//! Runtime settings: server binding, SQLite path, and the device→namespace policy.

use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;
use serde::Deserialize;
use tact_memory::RemoteRole;
use thiserror::Error;

use crate::auth::{Binding, Credential, CredentialTable, KeposPolicy, PolicyError};

const DEFAULT_BIND: &str = "127.0.0.1:8787";
const DEFAULT_DB: &str = "memory/kepos-tact-memory.sqlite3";

/// Local SQLite Tact remote memory, published as a Kepos HTTP service.
#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Args {
    /// Listen address for the Tact remote-memory protocol.
    #[arg(long, default_value = DEFAULT_BIND)]
    pub bind: SocketAddr,

    /// Path to the shared SQLite database.
    #[arg(long, default_value = DEFAULT_DB)]
    pub db: PathBuf,

    /// Bind one namespace to Kepos keys: NAMESPACE:KEY[,KEY...] (repeatable, writer role).
    #[arg(long, value_name = "NAMESPACE:KEY[,KEY...]")]
    pub binding: Vec<String>,

    /// Optional TOML configuration file supplying [server] and [auth.bindings].
    #[arg(long)]
    pub config: Option<PathBuf>,
}

/// TOML configuration file shape.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    #[serde(default)]
    pub server: Option<FileServer>,
    #[serde(default)]
    pub auth: Option<FileAuth>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileServer {
    pub bind: Option<String>,
    pub db: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileAuth {
    /// Device→namespace bindings; see `config.example.toml`.
    #[serde(default)]
    pub bindings: Vec<FileBinding>,
    /// Loopback-only bearer credentials; see `config.example.toml`.
    #[serde(default)]
    pub credentials: Vec<FileCredential>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileBinding {
    /// Human-readable namespace shared by the bound devices.
    pub namespace: String,
    /// `writer` (default) or `reader`.
    #[serde(default = "default_role")]
    pub role: RemoteRole,
    /// Kepos subscriber public keys (64 ASCII hex characters).
    pub keys: Vec<String>,
}

/// A loopback-only bearer credential declared in the TOML configuration file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileCredential {
    /// Human-readable namespace bound to this token.
    pub namespace: String,
    /// `writer` (default) or `reader`.
    #[serde(default = "default_role")]
    pub role: RemoteRole,
    /// Inline bearer token (prefer `token_file` so secrets stay out of managed configs).
    pub token: Option<String>,
    /// Path to a mode-0600 file whose first non-empty line is the bearer token.
    pub token_file: Option<PathBuf>,
}

const fn default_role() -> RemoteRole {
    RemoteRole::Writer
}

/// Effective runtime settings after merging the configuration file with command-line flags.
#[derive(Debug, Clone)]
pub struct Settings {
    pub bind: SocketAddr,
    pub db: PathBuf,
    pub bindings: Vec<Binding>,
    pub credentials: Vec<Credential>,
}

impl Settings {
    /// Builds effective settings from flags and an optional TOML file.
    pub fn resolve(args: &Args) -> Result<Self, ConfigError> {
        let file = match &args.config {
            Some(path) => {
                let raw = std::fs::read_to_string(path)
                    .map_err(|source| ConfigError::Read(path.clone(), source))?;
                Some(
                    toml::from_str::<FileConfig>(&raw)
                        .map_err(|error| ConfigError::Parse(path.clone(), error))?,
                )
            }
            None => None,
        };
        let file_server = file.as_ref().and_then(|file| file.server.as_ref());
        let file_auth = file.as_ref().and_then(|file| file.auth.as_ref());

        let bind = match file_server.and_then(|server| server.bind.as_ref()) {
            Some(value) if args.bind.to_string() == DEFAULT_BIND => value
                .parse()
                .map_err(|error| ConfigError::Bind(value.clone(), error))?,
            _ => args.bind,
        };
        let db = match file_server.and_then(|server| server.db.as_ref()) {
            Some(value) if args.db.as_path() == std::path::Path::new(DEFAULT_DB) => {
                PathBuf::from(value)
            }
            _ => args.db.clone(),
        };

        // The Kepos identity header is forgeable by any direct peer, so the listener must
        // stay loopback-only; bearer credentials are also enforced loopback-only.
        if !bind.ip().is_loopback() {
            return Err(ConfigError::NonLoopbackBind(bind));
        }

        let mut bindings = Vec::new();
        if let Some(auth) = file_auth {
            for binding in &auth.bindings {
                bindings.push(Binding::new(
                    binding.namespace.clone(),
                    binding.role,
                    binding.keys.clone(),
                )?);
            }
        }
        for raw in &args.binding {
            bindings.push(parse_cli_binding(raw)?);
        }
        let mut credentials = Vec::new();
        if let Some(auth) = file_auth {
            for credential in &auth.credentials {
                let token = match (&credential.token, &credential.token_file) {
                    (Some(token), None) => token.clone(),
                    (None, Some(path)) => read_token_file(path)?,
                    _ => {
                        return Err(ConfigError::CredentialField(
                            credential.namespace.clone(),
                        ))
                    }
                };
                credentials.push(Credential::new(
                    credential.namespace.clone(),
                    credential.role,
                    token,
                )?);
            }
        }
        Ok(Self {
            bind,
            db,
            bindings,
            credentials,
        })
    }

    /// Builds the Kepos device→namespace policy, rejecting ambiguous or invalid bindings.
    pub fn policy(&self) -> Result<KeposPolicy, PolicyError> {
        KeposPolicy::new(self.bindings.clone())
    }

    /// Returns whether any device is authorized.
    pub fn has_devices(&self) -> bool {
        self.bindings.iter().any(|binding| !binding.keys.is_empty())
    }

    /// Builds the loopback bearer-token table, rejecting duplicate tokens.
    pub fn credential_table(&self) -> Result<CredentialTable, PolicyError> {
        CredentialTable::new(self.credentials.clone())
    }
}

/// Upper bound on the raw bytes of a bearer token file.
const MAX_TOKEN_FILE_BYTES: usize = 64 * 1024;

/// Enforces that a bearer token file is a regular owner-only file (e.g. mode 0600).
#[cfg(unix)]
fn check_token_file_mode(path: &PathBuf) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata =
        std::fs::metadata(path).map_err(|source| ConfigError::TokenFile(path.clone(), source))?;
    if !metadata.is_file() {
        return Err(ConfigError::TokenFile(
            path.clone(),
            std::io::Error::new(std::io::ErrorKind::InvalidData, "token file is not a regular file"),
        ));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(ConfigError::TokenFilePermissions(path.clone(), mode));
    }
    Ok(())
}

/// Mode checks do not apply off Unix.
#[cfg(not(unix))]
fn check_token_file_mode(_path: &PathBuf) -> Result<(), ConfigError> {
    Ok(())
}

/// Reads the first non-empty line of a bearer token file.
fn read_token_file(path: &PathBuf) -> Result<String, ConfigError> {
    check_token_file_mode(path)?;
    let raw = std::fs::read_to_string(path)
        .map_err(|source| ConfigError::TokenFile(path.clone(), source))?;
    if raw.len() > MAX_TOKEN_FILE_BYTES {
        return Err(ConfigError::TokenFile(
            path.clone(),
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "token file exceeds 64 KiB",
            ),
        ));
    }
    raw.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            ConfigError::TokenFile(
                path.clone(),
                std::io::Error::new(std::io::ErrorKind::InvalidData, "token file is empty"),
            )
        })
}

/// Parses `NAMESPACE:KEY[,KEY...]` into a writer binding.
fn parse_cli_binding(raw: &str) -> Result<Binding, ConfigError> {
    let (namespace, keys) = raw
        .split_once(':')
        .ok_or_else(|| ConfigError::Binding(raw.to_owned()))?;
    if namespace.is_empty() || keys.is_empty() {
        return Err(ConfigError::Binding(raw.to_owned()));
    }
    let keys = keys
        .split(',')
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(str::to_owned)
        .collect();
    Ok(Binding::new(
        namespace.to_owned(),
        RemoteRole::Writer,
        keys,
    )?)
}

/// Failure while resolving runtime settings.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read configuration file {0}: {1}")]
    Read(PathBuf, std::io::Error),
    #[error("could not parse configuration file {0}: {1}")]
    Parse(PathBuf, toml::de::Error),
    #[error("invalid bind address {0:?}: {1}")]
    Bind(String, std::net::AddrParseError),
    #[error("bind address {0} is not loopback: the Kepos header is forgeable by any direct peer, so the listener must stay on 127.0.0.1 or ::1")]
    NonLoopbackBind(SocketAddr),
    #[error("invalid --binding {0:?}: expected NAMESPACE:KEY[,KEY...]")]
    Binding(String),
    #[error("credential for namespace {0:?} must set exactly one of token or token_file")]
    CredentialField(String),
    #[error("could not read bearer token file {0}: {1}")]
    TokenFile(PathBuf, std::io::Error),
    #[error("bearer token file {0} must be owner-only, e.g. mode 0600 (actual mode {1:o})")]
    TokenFilePermissions(PathBuf, u32),
    #[error(transparent)]
    Policy(#[from] PolicyError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tact_memory::server::protocol::is_valid_namespace;

    fn key(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    #[test]
    fn flags_default_when_config_file_absent() {
        let args = Args::parse_from(["kepos-tact-memory"]);
        let settings = Settings::resolve(&args).unwrap();
        assert_eq!(settings.bind.to_string(), DEFAULT_BIND);
        assert_eq!(settings.db, PathBuf::from(DEFAULT_DB));
        assert!(!settings.has_devices());
    }

    #[test]
    fn cli_binding_binds_devices_to_a_namespace() {
        let k1 = key(0x01);
        let k2 = key(0x02);
        let args = Args::parse_from([
            "kepos-tact-memory",
            "--binding",
            &format!("neil:{k1},{k2}"),
            "--binding",
            &format!("bob:{}", key(0x03)),
        ]);
        let settings = Settings::resolve(&args).unwrap();
        let policy = settings.policy().unwrap();
        assert_eq!(policy.resolve(&k1), Some(("neil", RemoteRole::Writer)));
        assert_eq!(policy.resolve(&k2), Some(("neil", RemoteRole::Writer)));
        assert_eq!(
            policy.resolve(&key(0x03)),
            Some(("bob", RemoteRole::Writer))
        );
    }

    #[test]
    fn file_bindings_supply_namespaces_and_roles() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let k1 = key(0x0a);
        let k2 = key(0x0b);
        let toml_text = format!(
            r#"[server]
bind = "127.0.0.1:9999"
db = "custom.sqlite3"

[[auth.bindings]]
namespace = "neil"
keys = ["{k1}"]

[[auth.bindings]]
namespace = "bob"
role = "reader"
keys = ["{k2}"]
"#
        );
        std::fs::write(&path, toml_text).unwrap();
        let args = Args::parse_from(["kepos-tact-memory", "--config", path.to_str().unwrap()]);
        let settings = Settings::resolve(&args).unwrap();
        assert_eq!(settings.bind.to_string(), "127.0.0.1:9999");
        assert_eq!(settings.db, PathBuf::from("custom.sqlite3"));
        let policy = settings.policy().unwrap();
        assert_eq!(policy.resolve(&k1), Some(("neil", RemoteRole::Writer)));
        assert_eq!(policy.resolve(&k2), Some(("bob", RemoteRole::Reader)));
    }

    #[test]
    fn duplicate_device_across_bindings_is_rejected() {
        let k = key(0x0c);
        let args = Args::parse_from([
            "kepos-tact-memory",
            "--binding",
            &format!("neil:{k}"),
            "--binding",
            &format!("bob:{k}"),
        ]);
        let settings = Settings::resolve(&args).unwrap();
        assert!(matches!(
            settings.policy(),
            Err(PolicyError::DuplicateKey(_))
        ));
    }

    #[test]
    fn explicit_flags_override_the_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"[server]
bind = "127.0.0.1:9999"
"#,
        )
        .unwrap();
        let args = Args::parse_from([
            "kepos-tact-memory",
            "--config",
            path.to_str().unwrap(),
            "--bind",
            "127.0.0.1:1234",
        ]);
        let settings = Settings::resolve(&args).unwrap();
        assert_eq!(settings.bind.to_string(), "127.0.0.1:1234");
    }

    #[test]
    fn bindings_must_be_protocol_namespaces() {
        let k = key(0x0d);
        let error = parse_cli_binding(&format!("bad namespace:{k}"));
        assert!(matches!(
            error,
            Err(ConfigError::Policy(PolicyError::InvalidNamespace(_)))
        ));
        assert!(is_valid_namespace("neil"));
    }

    #[test]
    fn file_credentials_parse_inline_tokens_and_token_files() {
        let dir = tempfile::tempdir().unwrap();
        let token_path = dir.path().join("loopback.token");
        std::fs::write(&token_path, "file-token-1\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let path = dir.path().join("config.toml");
        let toml_text = format!(
            r#"[server]
bind = "127.0.0.1:9999"

[[auth.bindings]]
namespace = "neil"
keys = ["{k}"]

[[auth.credentials]]
namespace = "neil"
token = "inline-token"

[[auth.credentials]]
namespace = "neil"
role = "reader"
token_file = "{tp}"
"#,
            k = key(0x0e),
            tp = token_path.display()
        );
        std::fs::write(&path, toml_text).unwrap();
        let args = Args::parse_from(["kepos-tact-memory", "--config", path.to_str().unwrap()]);
        let settings = Settings::resolve(&args).unwrap();
        let table = settings.credential_table().unwrap();
        assert_eq!(
            table.resolve("inline-token"),
            Some(("neil", RemoteRole::Writer))
        );
        assert_eq!(
            table.resolve("file-token-1"),
            Some(("neil", RemoteRole::Reader))
        );
    }

    #[test]
    fn credential_requires_exactly_one_token_source() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            format!(
                r#"[[auth.bindings]]
namespace = "neil"
keys = ["{k}"]

[[auth.credentials]]
namespace = "neil"
"#,
                k = key(0x0f)
            ),
        )
        .unwrap();
        let args = Args::parse_from(["kepos-tact-memory", "--config", path.to_str().unwrap()]);
        assert!(matches!(
            Settings::resolve(&args),
            Err(ConfigError::CredentialField(_))
        ));
    }

    #[test]
    fn non_loopback_bind_is_rejected_from_file_and_flags() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let toml_text = format!(
            r#"[server]
bind = "0.0.0.0:9999"

[[auth.bindings]]
namespace = "neil"
keys = ["{k}"]
"#,
            k = key(0x11)
        );
        std::fs::write(&path, toml_text).unwrap();
        let args = Args::parse_from(["kepos-tact-memory", "--config", path.to_str().unwrap()]);
        assert!(matches!(
            Settings::resolve(&args),
            Err(ConfigError::NonLoopbackBind(_))
        ));

        let args = Args::parse_from(["kepos-tact-memory", "--bind", "0.0.0.0:9999"]);
        assert!(matches!(
            Settings::resolve(&args),
            Err(ConfigError::NonLoopbackBind(_))
        ));
    }

    #[test]
    fn ipv6_loopback_bind_is_accepted() {
        let args = Args::parse_from(["kepos-tact-memory", "--bind", "[::1]:8787"]);
        let settings = Settings::resolve(&args).unwrap();
        assert_eq!(settings.bind.to_string(), "[::1]:8787");
    }

    #[cfg(unix)]
    #[test]
    fn token_file_mode_0600_is_enforced() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let token_path = dir.path().join("loopback.token");
        std::fs::write(&token_path, "secret-token\n").unwrap();
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let path = dir.path().join("config.toml");
        let toml_text = format!(
            r#"[[auth.bindings]]
namespace = "neil"
keys = ["{k}"]

[[auth.credentials]]
namespace = "neil"
token_file = "{tp}"
"#,
            k = key(0x12),
            tp = token_path.display()
        );
        std::fs::write(&path, toml_text).unwrap();
        let args = Args::parse_from(["kepos-tact-memory", "--config", path.to_str().unwrap()]);
        assert!(matches!(
            Settings::resolve(&args),
            Err(ConfigError::TokenFilePermissions(_, 0o644))
        ));

        // 0600 is accepted and the token resolves.
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let settings = Settings::resolve(&args).unwrap();
        assert_eq!(settings.credentials.len(), 1);
        assert_eq!(
            settings.credential_table().unwrap().resolve("secret-token"),
            Some(("neil", RemoteRole::Writer))
        );
    }

    #[cfg(unix)]
    #[test]
    fn any_owner_only_token_file_mode_is_accepted() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let token_path = dir.path().join("loopback.token");
        std::fs::write(&token_path, "secret-token\n").unwrap();
        let path = dir.path().join("config.toml");
        let toml_text = format!(
            r#"[[auth.bindings]]
namespace = "neil"
keys = ["{k}"]

[[auth.credentials]]
namespace = "neil"
token_file = "{tp}"
"#,
            k = key(0x13),
            tp = token_path.display()
        );
        std::fs::write(&path, toml_text).unwrap();
        let args = Args::parse_from(["kepos-tact-memory", "--config", path.to_str().unwrap()]);

        for mode in [0o400, 0o600, 0o700] {
            std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(mode)).unwrap();
            Settings::resolve(&args).unwrap();
        }
        // Group-readable (0440) is rejected even though owner retains full read.
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o440)).unwrap();
        assert!(matches!(
            Settings::resolve(&args),
            Err(ConfigError::TokenFilePermissions(_, 0o440))
        ));
    }

    #[test]
    fn oversized_token_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let token_path = dir.path().join("loopback.token");
        std::fs::write(&token_path, "x".repeat(65 * 1024)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let path = dir.path().join("config.toml");
        let toml_text = format!(
            r#"[[auth.bindings]]
namespace = "neil"
keys = ["{k}"]

[[auth.credentials]]
namespace = "neil"
token_file = "{tp}"
"#,
            k = key(0x10),
            tp = token_path.display()
        );
        std::fs::write(&path, toml_text).unwrap();
        let args = Args::parse_from(["kepos-tact-memory", "--config", path.to_str().unwrap()]);
        assert!(matches!(
            Settings::resolve(&args),
            Err(ConfigError::TokenFile(_, _))
        ));
    }
}
