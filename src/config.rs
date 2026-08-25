//! Runtime settings: server binding, SQLite path, and the Kepos role policy.

use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;
use serde::Deserialize;
use thiserror::Error;

use crate::auth::{KeposPolicy, PUBLIC_KEY_HEX_LEN, is_public_key};

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

    /// Kepos subscriber public keys permitted to use the service (repeatable).
    #[arg(long)]
    pub allow: Vec<String>,

    /// Kepos subscriber public keys restricted to read-only (repeatable).
    #[arg(long)]
    pub readonly: Vec<String>,

    /// Authorize every valid Kepos key, trusting the Kepos publisher allowlist as the
    /// authorization boundary.
    #[arg(long)]
    pub allow_all: bool,

    /// Optional TOML configuration file supplying [server] and [auth] defaults.
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
    pub allow_all: Option<bool>,
    pub allow: Option<Vec<String>>,
    pub readonly: Option<Vec<String>>,
}

/// Effective runtime settings after merging the configuration file with command-line flags.
#[derive(Debug, Clone)]
pub struct Settings {
    pub bind: SocketAddr,
    pub db: PathBuf,
    pub allow_all: bool,
    pub allow: Vec<String>,
    pub readonly: Vec<String>,
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
        let allow_all =
            args.allow_all || file_auth.and_then(|auth| auth.allow_all).unwrap_or(false);
        let mut allow = args.allow.clone();
        if allow.is_empty() {
            allow = file_auth
                .and_then(|auth| auth.allow.clone())
                .unwrap_or_default();
        }
        let mut readonly = args.readonly.clone();
        if readonly.is_empty() {
            readonly = file_auth
                .and_then(|auth| auth.readonly.clone())
                .unwrap_or_default();
        }
        Ok(Self {
            bind,
            db,
            allow_all,
            allow,
            readonly,
        })
    }

    /// Builds the Kepos role policy, validating every configured public key.
    pub fn policy(&self) -> Result<KeposPolicy, ConfigError> {
        for key in self.allow.iter().chain(self.readonly.iter()) {
            if !is_public_key(key) {
                return Err(ConfigError::InvalidPublicKey(key.clone()));
            }
        }
        let allow: Vec<String> = self
            .allow
            .iter()
            .map(|key| key.to_ascii_lowercase())
            .collect();
        let readonly: Vec<String> = self
            .readonly
            .iter()
            .map(|key| key.to_ascii_lowercase())
            .collect();
        Ok(KeposPolicy::new(allow, readonly, self.allow_all))
    }
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
    #[error("invalid Kepos public key {0:?}: expected {PUBLIC_KEY_HEX_LEN} ASCII hex characters")]
    InvalidPublicKey(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn key(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    #[test]
    fn flags_default_when_config_file_absent() {
        let args = Args::parse_from(["kepos-tact-memory"]);
        let settings = Settings::resolve(&args).unwrap();
        assert_eq!(settings.bind.to_string(), DEFAULT_BIND);
        assert_eq!(settings.db, PathBuf::from(DEFAULT_DB));
        assert!(!settings.allow_all);
    }

    #[test]
    fn file_values_apply_when_flags_are_defaulted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let k1 = key(0x01);
        let k2 = key(0x02);
        let toml_text = format!(
            r#"[server]
bind = "127.0.0.1:9999"
db = "custom.sqlite3"
[auth]
allow_all = true
allow = ["{k1}"]
readonly = ["{k2}"]
"#
        );
        std::fs::write(&path, toml_text).unwrap();
        let args = Args::parse_from(["kepos-tact-memory", "--config", path.to_str().unwrap()]);
        let settings = Settings::resolve(&args).unwrap();
        assert_eq!(settings.bind.to_string(), "127.0.0.1:9999");
        assert_eq!(settings.db, PathBuf::from("custom.sqlite3"));
        assert!(settings.allow_all);
        assert_eq!(settings.allow, vec![k1]);
        assert_eq!(settings.readonly, vec![k2]);
    }

    #[test]
    fn explicit_flags_override_the_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"[server]
bind = "127.0.0.1:9999"
[auth]
allow = ["a"]
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
    fn policy_rejects_malformed_keys() {
        let args = Args::parse_from(["kepos-tact-memory", "--allow", "not-a-key"]);
        let settings = Settings::resolve(&args).unwrap();
        assert!(matches!(
            settings.policy(),
            Err(ConfigError::InvalidPublicKey(_))
        ));
    }
}
