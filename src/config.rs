//! Runtime settings: server binding, SQLite path, and the device→namespace policy.

use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;
use serde::Deserialize;
use tact_memory::RemoteRole;
use thiserror::Error;

use crate::auth::{Binding, KeposPolicy, PolicyError};

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

const fn default_role() -> RemoteRole {
    RemoteRole::Writer
}

/// Effective runtime settings after merging the configuration file with command-line flags.
#[derive(Debug, Clone)]
pub struct Settings {
    pub bind: SocketAddr,
    pub db: PathBuf,
    pub bindings: Vec<Binding>,
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
        Ok(Self { bind, db, bindings })
    }

    /// Builds the Kepos device→namespace policy, rejecting ambiguous or invalid bindings.
    pub fn policy(&self) -> Result<KeposPolicy, PolicyError> {
        KeposPolicy::new(self.bindings.clone())
    }

    /// Returns whether any device is authorized.
    pub fn has_devices(&self) -> bool {
        self.bindings.iter().any(|binding| !binding.keys.is_empty())
    }
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
    #[error("invalid --binding {0:?}: expected NAMESPACE:KEY[,KEY...]")]
    Binding(String),
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
}
