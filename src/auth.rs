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
//! 64-hex-character public key — a device identity, not a person or a secret. This module
//! parses that header, maps the device identity to a stable Tact memory namespace, and applies
//! the configured role policy. The header is trustworthy only at the intended private publisher
//! ingress: anything that can reach the target without passing through Kepos can forge it.

use std::collections::HashSet;

use tact_memory::RemoteRole;

/// Authorization scheme injected by the Kepos HTTP publisher adapter.
pub const AUTH_SCHEME: &str = "Kepos";
/// Length in ASCII hex characters of a Kepos subscriber public key.
pub const PUBLIC_KEY_HEX_LEN: usize = 64;
/// Prefix of the deterministic namespace derived from a Kepos identity.
pub const NAMESPACE_PREFIX: &str = "kepos-";

/// Failure while reading the Kepos authorization header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthError {
    /// The header is not a valid `Kepos <64-hex>` value.
    Malformed,
}

/// An authenticated Kepos device and its derived Tact memory principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeposPrincipal {
    /// Canonical lowercase 64-hex subscriber public key.
    pub public_key: String,
    /// Deterministic namespace bound to this device: `kepos-<public_key>`.
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

/// Returns the stable Tact memory namespace for a normalized public key.
///
/// The result satisfies the protocol namespace grammar (at most 128 ASCII alphanumerics,
/// periods, hyphens, or underscores), so it can travel in the `x-tact-memory-namespace`
/// assertion header and in returned memory keys.
pub fn namespace_for(public_key: &str) -> String {
    format!("{NAMESPACE_PREFIX}{public_key}")
}

/// Role policy applied to Kepos device identities.
#[derive(Clone, Debug, Default)]
pub struct KeposPolicy {
    allow: HashSet<String>,
    readonly: HashSet<String>,
    allow_all: bool,
}

impl KeposPolicy {
    /// Builds a policy from normalized public keys.
    ///
    /// `readonly` devices are authorized as observers even when omitted from `allow`;
    /// `allow_all` authorizes every valid Kepos key, trusting the Kepos publisher allowlist
    /// as the authorization boundary.
    pub fn new(
        allow: impl IntoIterator<Item = String>,
        readonly: impl IntoIterator<Item = String>,
        allow_all: bool,
    ) -> Self {
        Self {
            allow: allow.into_iter().collect(),
            readonly: readonly.into_iter().collect(),
            allow_all,
        }
    }

    /// Authorizes a normalized public key, returning its role or `None` when the device is
    /// unknown and not covered by `allow_all`.
    pub fn authorize(&self, public_key: &str) -> Option<RemoteRole> {
        let allowed =
            self.allow_all || self.allow.contains(public_key) || self.readonly.contains(public_key);
        if !allowed {
            return None;
        }
        if self.readonly.contains(public_key) {
            Some(RemoteRole::Reader)
        } else {
            Some(RemoteRole::Writer)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
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
    fn derives_a_protocol_valid_namespace() {
        let key = key(0x11);
        let namespace = namespace_for(&key);
        assert_eq!(namespace, format!("{NAMESPACE_PREFIX}{key}"));
        assert!(tact_memory::server::protocol::is_valid_namespace(
            &namespace
        ));
        assert!(namespace.len() <= tact_memory::server::protocol::MAX_NAMESPACE_BYTES);
    }

    #[test]
    fn policy_maps_roles() {
        let writer = key(0xab);
        let observer = key(0xac);
        let stranger = key(0xad);
        let policy = KeposPolicy::new([writer.clone()], [observer.clone()], false);
        assert_eq!(policy.authorize(&writer), Some(RemoteRole::Writer));
        assert_eq!(policy.authorize(&observer), Some(RemoteRole::Reader));
        assert_eq!(policy.authorize(&stranger), None);
        assert_eq!(policy.authorize(&writer.to_uppercase()), None);

        let open = KeposPolicy::new([], [], true);
        assert_eq!(open.authorize(&stranger), Some(RemoteRole::Writer));
        let observed = KeposPolicy::new([], [observer.clone()], true);
        assert_eq!(observed.authorize(&observer), Some(RemoteRole::Reader));
    }
}
