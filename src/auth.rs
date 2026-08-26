//! Kepos device-identity authentication.
//!
//! A Kepos publisher with `kind = "http"` removes every caller-supplied `Authorization`
//! field and injects exactly one target-facing field:
//!
//! ```text
//! Authorization: Kepos <subscriber-public-key>
//! ```
//!
//! `<subscriber-public-key>` is the authenticated subscriber's canonical lowercase
//! 64-hex-character public key — a device identity, not a person or a secret. The operator
//! binds devices to human-readable Tact namespaces; one person's several devices share one
//! namespace:
//!
//! ```toml
//! [[auth.bindings]]
//! namespace = "neil"
//! keys = ["<pubkey1>", "<pubkey2>"]
//!
//! [[auth.bindings]]
//! namespace = "bob"
//! role = "reader"
//! keys = ["<pubkey3>"]
//! ```
//!
//! The header is trustworthy only at the intended private publisher ingress: anything that
//! can reach the target without passing through Kepos can forge it.
//!
//! A second, optional channel authenticates same-host Tact clients. A loopback-only bearer
//! credential (`Authorization: Bearer <token>`) resolves the token to a namespace and role
//! from `[[auth.credentials]]`; non-loopback sources can never use the bearer channel, so
//! the Kepos header remains the only network identity.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use tact_memory::{RemoteRole, server::protocol::is_valid_namespace};
use thiserror::Error;

/// Authorization scheme injected by the Kepos HTTP publisher adapter.
pub const AUTH_SCHEME: &str = "Kepos";
/// Length in ASCII hex characters of a Kepos subscriber public key.
pub const PUBLIC_KEY_HEX_LEN: usize = 64;
/// Optional loopback-only bearer scheme for same-host Tact clients.
pub const BEARER_SCHEME: &str = "Bearer";
/// Upper bound on bearer token length, mirroring the reference server.
const MAX_BEARER_TOKEN_BYTES: usize = 4096;

/// One namespace bound to one or more Kepos devices.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Binding {
    /// Human-readable Tact namespace shared by the bound devices.
    pub namespace: String,
    /// Role granted to every device in this binding.
    pub role: RemoteRole,
    /// Kepos subscriber public keys (64 ASCII hex characters).
    pub keys: Vec<String>,
}

impl Binding {
    /// Validates a namespace and its public keys.
    pub fn new(
        namespace: String,
        role: RemoteRole,
        keys: Vec<String>,
    ) -> Result<Self, PolicyError> {
        if !is_valid_namespace(&namespace) {
            return Err(PolicyError::InvalidNamespace(namespace));
        }
        for key in &keys {
            if !is_public_key(key) {
                return Err(PolicyError::InvalidPublicKey(key.clone()));
            }
        }
        Ok(Self {
            namespace,
            role,
            keys: keys
                .into_iter()
                .map(|key| key.to_ascii_lowercase())
                .collect(),
        })
    }
}

/// Failure while parsing the Kepos authorization header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthError {
    /// The header is not a valid `Kepos <64-hex>` value.
    Malformed,
}

/// How a request principal was authenticated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthSource {
    /// `Authorization: Kepos <subscriber-public-key>` injected by the publisher.
    Kepos,
    /// Loopback-only `Authorization: Bearer <token>` matching a configured credential.
    Bearer,
}

/// An authenticated principal and its resolved Tact memory namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Principal {
    /// Namespace bound to this principal by the configured policy.
    pub namespace: String,
    /// Role authorized for this principal by the configured policy.
    pub role: RemoteRole,
    /// Authentication path that produced this principal.
    pub source: AuthSource,
}

/// Returns whether `value` is a Kepos public key (64 ASCII hex characters).
pub fn is_public_key(value: &str) -> bool {
    value.len() == PUBLIC_KEY_HEX_LEN && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Returns whether `value` is a valid bearer token (RFC 6750 token68 charset).
pub fn is_bearer_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_BEARER_TOKEN_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
        })
}

/// Hashes a bearer token with SHA-256 so the runtime table retains no plaintext.
pub fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Parses an `Authorization` header value into a normalized lowercase public key.
pub fn parse_authorization(value: &str) -> Result<String, AuthError> {
    let (scheme, token) = value.split_once(' ').ok_or(AuthError::Malformed)?;
    if !scheme.eq_ignore_ascii_case(AUTH_SCHEME) || !is_public_key(token) {
        return Err(AuthError::Malformed);
    }
    Ok(token.to_ascii_lowercase())
}

/// Failure while assembling the device→namespace policy.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// A namespace violates the protocol grammar.
    #[error("invalid memory namespace {0:?}")]
    InvalidNamespace(String),
    /// A key is not 64 ASCII hex characters.
    #[error("invalid Kepos public key {0:?}: expected {PUBLIC_KEY_HEX_LEN} ASCII hex characters")]
    InvalidPublicKey(String),
    /// The same device appears in more than one binding.
    #[error("Kepos public key {0:?} is bound to more than one namespace")]
    DuplicateKey(String),
    /// A bearer token is empty, too large, or contains an unsupported byte.
    #[error("bearer token is invalid")]
    InvalidToken,
    /// The same bearer token appears in more than one credential.
    #[error("bearer token is used by more than one credential")]
    DuplicateToken,
    /// No bindings were configured.
    #[error("no Kepos device bindings are configured")]
    NoBindings,
}

/// Device→namespace resolution table.
#[derive(Clone, Debug, Default)]
pub struct KeposPolicy {
    devices: HashMap<String, (String, RemoteRole)>,
}

impl KeposPolicy {
    /// Builds the resolution table from validated bindings.
    ///
    /// Every key must appear in exactly one binding. Multiple keys may share a namespace, so
    /// one person's devices resolve to the same Tact memory namespace.
    pub fn new(bindings: impl IntoIterator<Item = Binding>) -> Result<Self, PolicyError> {
        let mut devices = HashMap::new();
        for binding in bindings {
            for key in binding.keys {
                if devices
                    .insert(key.clone(), (binding.namespace.clone(), binding.role))
                    .is_some()
                {
                    return Err(PolicyError::DuplicateKey(key));
                }
            }
        }
        if devices.is_empty() {
            return Err(PolicyError::NoBindings);
        }
        Ok(Self { devices })
    }

    /// Resolves a normalized public key to its namespace and role.
    pub fn resolve(&self, public_key: &str) -> Option<(&str, RemoteRole)> {
        self.devices
            .get(public_key)
            .map(|(namespace, role)| (namespace.as_str(), *role))
    }
}

/// A loopback-only bearer credential bound to one namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credential {
    /// Human-readable Tact namespace bound to this token.
    pub namespace: String,
    /// Role granted to this token.
    pub role: RemoteRole,
    /// Raw bearer token; hashed before retention by [CredentialTable].
    pub token: String,
}

impl Credential {
    /// Validates a namespace and bearer token.
    pub fn new(
        namespace: String,
        role: RemoteRole,
        token: String,
    ) -> Result<Self, PolicyError> {
        if !is_valid_namespace(&namespace) {
            return Err(PolicyError::InvalidNamespace(namespace));
        }
        if !is_bearer_token(&token) {
            return Err(PolicyError::InvalidToken);
        }
        Ok(Self {
            namespace,
            role,
            token,
        })
    }
}

/// Token-hash→namespace resolution table for the loopback bearer channel.
#[derive(Clone, Debug, Default)]
pub struct CredentialTable {
    tokens: HashMap<[u8; 32], (String, RemoteRole)>,
}

impl CredentialTable {
    /// Builds the resolution table, rejecting duplicate bearer tokens.
    pub fn new(
        credentials: impl IntoIterator<Item = Credential>,
    ) -> Result<Self, PolicyError> {
        let mut tokens = HashMap::new();
        for credential in credentials {
            let hash = hash_token(&credential.token);
            if tokens
                .insert(hash, (credential.namespace, credential.role))
                .is_some()
            {
                return Err(PolicyError::DuplicateToken);
            }
        }
        Ok(Self { tokens })
    }

    /// Resolves a raw bearer token to its namespace and role.
    pub fn resolve(&self, token: &str) -> Option<(&str, RemoteRole)> {
        self.tokens
            .get(&hash_token(token))
            .map(|(namespace, role)| (namespace.as_str(), *role))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn binding(namespace: &str, role: RemoteRole, keys: Vec<String>) -> Binding {
        Binding::new(namespace.to_owned(), role, keys).unwrap()
    }

    #[test]
    fn parses_the_kepos_scheme_and_normalizes_case() {
        let key = key(0xab);
        assert_eq!(
            parse_authorization(&format!("Kepos {}", key.to_uppercase())).unwrap(),
            key
        );
        assert_eq!(parse_authorization(&format!("kepos {key}")).unwrap(), key);
    }

    #[test]
    fn rejects_malformed_authorization() {
        assert_eq!(parse_authorization(""), Err(AuthError::Malformed));
        assert_eq!(parse_authorization("Kepos"), Err(AuthError::Malformed));
        assert_eq!(parse_authorization("Bearer abc"), Err(AuthError::Malformed));
        assert_eq!(
            parse_authorization("Kepos not-hex!"),
            Err(AuthError::Malformed)
        );
        assert_eq!(
            parse_authorization(&format!("Kepos {}", "a".repeat(63))),
            Err(AuthError::Malformed)
        );
    }

    #[test]
    fn multiple_devices_share_one_namespace() {
        let device_one = key(0x01);
        let device_two = key(0x02);
        let policy = KeposPolicy::new([binding(
            "neil",
            RemoteRole::Writer,
            vec![device_one.clone(), device_two.clone()],
        )])
        .unwrap();
        assert_eq!(
            policy.resolve(&device_one),
            Some(("neil", RemoteRole::Writer))
        );
        assert_eq!(
            policy.resolve(&device_two),
            Some(("neil", RemoteRole::Writer))
        );
        assert_eq!(policy.resolve(&key(0x03)), None);
        // Resolution is case-normalized.
        assert_eq!(
            policy.resolve(&device_one.to_uppercase()),
            Some(("neil", RemoteRole::Writer))
        );
    }

    #[test]
    fn distinct_namespaces_and_roles() {
        let neil_device = key(0x11);
        let bob_device = key(0x22);
        let policy = KeposPolicy::new([
            binding("neil", RemoteRole::Writer, vec![neil_device.clone()]),
            binding("bob", RemoteRole::Reader, vec![bob_device.clone()]),
        ])
        .unwrap();
        assert_eq!(
            policy.resolve(&neil_device),
            Some(("neil", RemoteRole::Writer))
        );
        assert_eq!(
            policy.resolve(&bob_device),
            Some(("bob", RemoteRole::Reader))
        );
    }

    #[test]
    fn a_device_cannot_be_bound_twice() {
        let device = key(0x33);
        let error = KeposPolicy::new([
            binding("neil", RemoteRole::Writer, vec![device.clone()]),
            binding("bob", RemoteRole::Writer, vec![device]),
        ]);
        assert!(matches!(error, Err(PolicyError::DuplicateKey(_))));
    }

    #[test]
    fn binding_validates_namespace_and_keys() {
        assert!(matches!(
            Binding::new(
                "has spaces!".to_owned(),
                RemoteRole::Writer,
                vec![key(0x01)]
            ),
            Err(PolicyError::InvalidNamespace(_))
        ));
        assert!(matches!(
            Binding::new(
                "neil".to_owned(),
                RemoteRole::Writer,
                vec!["not-a-key".to_owned()]
            ),
            Err(PolicyError::InvalidPublicKey(_))
        ));
        assert!(matches!(
            KeposPolicy::new(Vec::<Binding>::new()),
            Err(PolicyError::NoBindings)
        ));
    }

    #[test]
    fn bearer_token_grammar_caps_length() {
        assert!(is_bearer_token(&"a".repeat(4096)));
        assert!(!is_bearer_token(&"a".repeat(4097)));
        assert!(!is_bearer_token(""));
        assert!(!is_bearer_token("has space"));
        assert!(!is_bearer_token("has\ttab"));
    }

    #[test]
    fn credential_table_resolves_tokens_and_rejects_duplicates() {
        let table = CredentialTable::new([
            Credential::new(
                "neil".to_owned(),
                RemoteRole::Writer,
                "token-a".to_owned(),
            )
            .unwrap(),
            Credential::new("bob".to_owned(), RemoteRole::Reader, "token-b".to_owned())
                .unwrap(),
        ])
        .unwrap();
        assert_eq!(
            table.resolve("token-a"),
            Some(("neil", RemoteRole::Writer))
        );
        assert_eq!(
            table.resolve("token-b"),
            Some(("bob", RemoteRole::Reader))
        );
        assert_eq!(table.resolve("token-c"), None);
        assert!(matches!(
            CredentialTable::new([
                Credential::new(
                    "neil".to_owned(),
                    RemoteRole::Writer,
                    "same".to_owned()
                )
                .unwrap(),
                Credential::new("bob".to_owned(), RemoteRole::Reader, "same".to_owned())
                    .unwrap(),
            ]),
            Err(PolicyError::DuplicateToken)
        ));
    }

    #[test]
    fn credential_validates_namespace_and_token() {
        assert!(matches!(
            Credential::new(
                "bad ns".to_owned(),
                RemoteRole::Writer,
                "tok".to_owned()
            ),
            Err(PolicyError::InvalidNamespace(_))
        ));
        assert!(matches!(
            Credential::new("neil".to_owned(), RemoteRole::Writer, String::new()),
            Err(PolicyError::InvalidToken)
        ));
        assert!(matches!(
            Credential::new(
                "neil".to_owned(),
                RemoteRole::Writer,
                "bad token!".to_owned()
            ),
            Err(PolicyError::InvalidToken)
        ));
    }
}
