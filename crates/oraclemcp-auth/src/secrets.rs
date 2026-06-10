//! Secrets backends (plan §6.5; bead P2-5). Credentials are referenced by a
//! scheme-prefixed `credential_ref` (never stored in the profile or surfaced in
//! metadata) and resolved here to a zeroizing [`Secret`]:
//!
//! - `env:VAR` — an environment variable (dev / container injection).
//! - `vault:mount/path#field` — HashiCorp Vault / OpenBao KV v2 via AppRole
//!   (production; the HTTP client is feature-gated for deploy — see notes).
//! - `literal:...` — an inline value (**dev only**; default-denied under a
//!   `protected` production profile).
//!
//! End-to-end zeroize discipline: [`Secret`] wipes on drop and redacts in
//! `Debug`/logs.

use thiserror::Error;
use zeroize::Zeroizing;

/// A secret value that zeroes its memory on drop and never prints its contents.
#[derive(Clone)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wrap a secret string.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Secret(Zeroizing::new(value.into()))
    }

    /// Expose the secret for use at the FFI / connect boundary. Keep the borrow
    /// as short-lived as possible.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***redacted***)")
    }
}

/// Secret-resolution failures.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecretError {
    /// The `credential_ref` had no recognized `scheme:` prefix.
    #[error("malformed credential_ref (expected scheme:locator): {0}")]
    Malformed(String),
    /// The referenced secret could not be found / read.
    #[error("secret not found for credential_ref: {0}")]
    NotFound(String),
    /// A plaintext `literal:` ref was used under a production profile.
    #[error("plaintext literal credential is forbidden on a protected profile")]
    PlaintextForbidden,
    /// The scheme needs a backend not compiled into this build.
    #[error("secrets backend not available for scheme `{0}` (feature-gated)")]
    BackendUnavailable(String),
}

/// A parsed `credential_ref`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretRef {
    /// The scheme (`env` / `vault` / `literal`).
    pub scheme: String,
    /// The scheme-specific locator.
    pub locator: String,
}

impl SecretRef {
    /// Parse `scheme:locator`.
    pub fn parse(credential_ref: &str) -> Result<Self, SecretError> {
        match credential_ref.split_once(':') {
            Some((scheme, locator)) if !scheme.is_empty() && !locator.is_empty() => Ok(SecretRef {
                scheme: scheme.to_owned(),
                locator: locator.to_owned(),
            }),
            _ => Err(SecretError::Malformed(credential_ref.to_owned())),
        }
    }
}

/// Resolve a `credential_ref` to a [`Secret`]. `protected` = a production
/// profile, under which plaintext `literal:` refs are default-denied (§6.5).
///
/// `env_lookup` is injected so resolution is testable without touching the real
/// process environment (the production caller passes `std::env::var`).
pub fn resolve_secret(
    credential_ref: &str,
    protected: bool,
    env_lookup: impl Fn(&str) -> Option<String>,
) -> Result<Secret, SecretError> {
    let parsed = SecretRef::parse(credential_ref)?;
    match parsed.scheme.as_str() {
        "env" => env_lookup(&parsed.locator)
            .map(Secret::new)
            .ok_or_else(|| SecretError::NotFound(credential_ref.to_owned())),
        "literal" => {
            if protected {
                Err(SecretError::PlaintextForbidden)
            } else {
                Ok(Secret::new(parsed.locator))
            }
        }
        // Vault / OpenBao KV v2 via AppRole — the async HTTP client (vaultrs)
        // is wired at deploy behind the `vault` feature; absent it, this is an
        // explicit BackendUnavailable rather than a silent fallback to env.
        "vault" => Err(SecretError::BackendUnavailable("vault".to_owned())),
        other => Err(SecretError::BackendUnavailable(other.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env<'a>(
        map: &'a HashMap<&'static str, &'static str>,
    ) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| map.get(k).map(|v| (*v).to_owned())
    }

    #[test]
    fn parses_scheme_and_locator() {
        let r = SecretRef::parse("env:DB_PASSWORD").unwrap();
        assert_eq!(r.scheme, "env");
        assert_eq!(r.locator, "DB_PASSWORD");
        assert!(SecretRef::parse("noscheme").is_err());
        assert!(SecretRef::parse("env:").is_err());
    }

    #[test]
    fn env_scheme_resolves_from_injected_lookup() {
        let mut m = HashMap::new();
        m.insert("DB_PASSWORD", "tiger");
        let s = resolve_secret("env:DB_PASSWORD", true, env(&m)).expect("resolve");
        assert_eq!(s.expose(), "tiger");
        // Missing var -> NotFound.
        assert!(matches!(
            resolve_secret("env:NOPE", false, env(&m)),
            Err(SecretError::NotFound(_))
        ));
    }

    #[test]
    fn literal_is_denied_under_protected_profile() {
        let m = HashMap::new();
        assert!(matches!(
            resolve_secret("literal:hunter2", true, env(&m)),
            Err(SecretError::PlaintextForbidden)
        ));
        // Allowed in dev (non-protected).
        assert_eq!(
            resolve_secret("literal:hunter2", false, env(&m))
                .unwrap()
                .expose(),
            "hunter2"
        );
    }

    #[test]
    fn vault_scheme_is_explicit_backend_unavailable_without_the_feature() {
        let m = HashMap::new();
        assert!(matches!(
            resolve_secret("vault:secret/oracle#password", true, env(&m)),
            Err(SecretError::BackendUnavailable(_))
        ));
    }

    #[test]
    fn secret_debug_is_redacted() {
        let s = Secret::new("hunter2");
        assert_eq!(format!("{s:?}"), "Secret(***redacted***)");
        assert!(!format!("{s:?}").contains("hunter2"));
    }
}
