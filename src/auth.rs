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

use std::collections::HashMap;

use tact_memory::{RemoteRole, server::protocol::is_valid_namespace};
use thiserror::Error;

/// Authorization scheme injected by the Kepos HTTP publisher adapter.
pub const AUTH_SCHEME: &str = "Kepos";
/// Length in ASCII hex characters of a Kepos subscriber public key.
pub const PUBLIC_KEY_HEX_LEN: usize = 64;

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

/// An authenticated Kepos device and its resolved Tact memory principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeposPrincipal {
    /// Canonical lowercase 64-hex subscriber public key.
    pub public_key: String,
    /// Namespace bound to this device by the configured policy.
    pub namespace: String,
    /// Role authorized for this device by the configured policy.
    pub role: RemoteRole,
}

/// Returns whether `value` is a Kepos public key (64 ASCII hex characters).
pub fn is_public_key(value: &str) -> bool {
    value.len() == PUBLIC_KEY_HEX_LEN && value.bytes().all(|byte| byte.is_ascii_hexdigit())
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
}
