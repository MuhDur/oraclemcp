//! Secrets backends (plan §6.5; bead P2-5). Credentials are referenced by a
//! scheme-prefixed `credential_ref` (never stored in the profile or surfaced in
//! metadata) and resolved here to a zeroizing [`Secret`]:
//!
//! - `env:VAR` — an environment variable (dev / container injection).
//! - `file:/path/to/secret` — a local secret file (one trailing line ending is stripped).
//! - `keyring:account` or `keyring:service/account` — the OS keyring.
//! - `vault:mount/path#field` — HashiCorp Vault / OpenBao KV v2 via AppRole
//!   (production; the HTTP client is feature-gated for deploy — see notes).
//! - `literal:...` — an inline value (**dev only**; default-denied under a
//!   `protected` production profile).
//!
//! End-to-end zeroize discipline: [`Secret`] wipes on drop and redacts in
//! `Debug`/logs.

use std::fs;
use std::process::Command;

use thiserror::Error;
use zeroize::Zeroizing;

const DEFAULT_KEYRING_SERVICE: &str = "oraclemcp";
const KEYRING_COMMAND_ENV: &str = "ORACLEMCP_KEYRING_COMMAND";

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
    /// The secret reference had no recognized `scheme:` prefix.
    #[error("malformed secret reference (expected scheme:locator)")]
    Malformed(String),
    /// The referenced secret could not be found / read.
    #[error("secret not found for secret reference")]
    NotFound(String),
    /// A plaintext `literal:` ref was used under a production profile.
    #[error("plaintext literal credential is forbidden on a protected profile")]
    PlaintextForbidden,
    /// A backend returned bytes that were not UTF-8 text.
    #[error("secret backend `{0}` returned invalid utf-8")]
    InvalidUtf8(String),
    /// A backend command/service failed.
    #[error("secret backend `{0}` failed")]
    BackendFailure(String),
    /// The scheme needs a backend not compiled into this build.
    #[error("secrets backend not available for scheme `{0}` (feature-gated)")]
    BackendUnavailable(String),
}

/// A parsed secret reference.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretRef {
    /// The scheme (`env` / `file` / `keyring` / `vault` / `literal`).
    pub scheme: String,
    /// The scheme-specific locator.
    pub locator: String,
}

impl std::fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretRef")
            .field("scheme", &self.scheme)
            .field("locator", &"<redacted>")
            .finish()
    }
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

/// Pluggable secret-reference resolver. Production uses [`SystemSecretResolver`];
/// tests and embedders can inject an implementation that maps the same parsed
/// references to a different backend without changing config parsing.
pub trait SecretResolver: Send + Sync {
    /// Resolve a parsed, already-policy-checked reference to a secret value.
    fn resolve(&self, reference: &SecretRef) -> Result<Secret, SecretError>;
}

/// Production resolver for local process environment, local files, and OS
/// keyring access. `vault:` remains fail-closed until a production Vault client
/// is compiled in and injected behind this seam.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemSecretResolver;

impl SecretResolver for SystemSecretResolver {
    fn resolve(&self, reference: &SecretRef) -> Result<Secret, SecretError> {
        match reference.scheme.as_str() {
            "env" => std::env::var(&reference.locator)
                .ok()
                .map(Secret::new)
                .ok_or_else(|| SecretError::NotFound(reference.scheme.clone())),
            "file" => resolve_file_secret(&reference.locator),
            "keyring" => resolve_keyring_secret(&reference.locator),
            "literal" => Ok(Secret::new(reference.locator.clone())),
            // Vault / OpenBao KV v2 via AppRole — the async HTTP client (vaultrs)
            // is wired at deploy behind the `vault` feature; absent it, this is
            // explicit BackendUnavailable rather than a silent fallback to env.
            "vault" => Err(SecretError::BackendUnavailable("vault".to_owned())),
            other => Err(SecretError::BackendUnavailable(other.to_owned())),
        }
    }
}

/// Resolver with an injected environment lookup. File and keyring resolution are
/// still the system implementations; only `env:` is replaced. This preserves
/// deterministic tests without weakening the production resolver.
#[derive(Clone, Debug)]
pub struct EnvLookupSecretResolver<E> {
    env_lookup: E,
}

impl<E> EnvLookupSecretResolver<E> {
    /// Build a resolver whose `env:` scheme is backed by `env_lookup`.
    #[must_use]
    pub fn new(env_lookup: E) -> Self {
        EnvLookupSecretResolver { env_lookup }
    }
}

impl<E> SecretResolver for EnvLookupSecretResolver<E>
where
    E: for<'a> Fn(&'a str) -> Option<String> + Send + Sync,
{
    fn resolve(&self, reference: &SecretRef) -> Result<Secret, SecretError> {
        match reference.scheme.as_str() {
            "env" => (self.env_lookup)(&reference.locator)
                .map(Secret::new)
                .ok_or_else(|| SecretError::NotFound(reference.scheme.clone())),
            "file" => resolve_file_secret(&reference.locator),
            "keyring" => resolve_keyring_secret(&reference.locator),
            "literal" => Ok(Secret::new(reference.locator.clone())),
            "vault" => Err(SecretError::BackendUnavailable("vault".to_owned())),
            other => Err(SecretError::BackendUnavailable(other.to_owned())),
        }
    }
}

/// Resolve a `credential_ref` to a [`Secret`] with an injected resolver.
pub fn resolve_secret_with(
    credential_ref: &str,
    protected: bool,
    resolver: &dyn SecretResolver,
) -> Result<Secret, SecretError> {
    let parsed = SecretRef::parse(credential_ref)?;
    if parsed.scheme == "literal" && protected {
        return Err(SecretError::PlaintextForbidden);
    }
    resolver.resolve(&parsed)
}

/// Resolve a secret with an injected `env:` lookup and the system file/keyring
/// backends. This preserves the original helper shape for callers that only
/// need deterministic environment injection; use [`resolve_secret_with`] when
/// replacing the whole resolver.
pub fn resolve_secret(
    credential_ref: &str,
    protected: bool,
    env_lookup: impl Fn(&str) -> Option<String>,
) -> Result<Secret, SecretError> {
    let parsed = SecretRef::parse(credential_ref)?;
    if parsed.scheme == "literal" && protected {
        return Err(SecretError::PlaintextForbidden);
    }
    match parsed.scheme.as_str() {
        "env" => env_lookup(&parsed.locator)
            .map(Secret::new)
            .ok_or_else(|| SecretError::NotFound(parsed.scheme.clone())),
        "file" => resolve_file_secret(&parsed.locator),
        "keyring" => resolve_keyring_secret(&parsed.locator),
        "literal" => Ok(Secret::new(parsed.locator)),
        "vault" => Err(SecretError::BackendUnavailable("vault".to_owned())),
        other => Err(SecretError::BackendUnavailable(other.to_owned())),
    }
}

fn resolve_file_secret(locator: &str) -> Result<Secret, SecretError> {
    let contents =
        fs::read_to_string(locator).map_err(|_| SecretError::NotFound("file".to_owned()))?;
    Ok(Secret::new(strip_one_trailing_line_ending(contents)))
}

fn strip_one_trailing_line_ending(mut value: String) -> String {
    if value.ends_with("\r\n") {
        value.truncate(value.len() - 2);
    } else if value.ends_with('\n') || value.ends_with('\r') {
        value.truncate(value.len() - 1);
    }
    value
}

fn resolve_keyring_secret(locator: &str) -> Result<Secret, SecretError> {
    let (service, account) = parse_keyring_locator(locator)?;
    if let Ok(command) = std::env::var(KEYRING_COMMAND_ENV)
        && !command.trim().is_empty()
    {
        return run_keyring_command(&command, &[service, account]);
    }

    platform_keyring_secret(service, account)
}

fn parse_keyring_locator(locator: &str) -> Result<(&str, &str), SecretError> {
    let (service, account) = locator
        .split_once('/')
        .unwrap_or((DEFAULT_KEYRING_SERVICE, locator));
    if service.is_empty() || account.is_empty() {
        Err(SecretError::Malformed("keyring".to_owned()))
    } else {
        Ok((service, account))
    }
}

fn run_keyring_command(command: &str, args: &[&str]) -> Result<Secret, SecretError> {
    let output = Command::new(command).args(args).output().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            SecretError::BackendUnavailable("keyring".to_owned())
        } else {
            SecretError::BackendFailure("keyring".to_owned())
        }
    })?;
    if !output.status.success() {
        return Err(SecretError::NotFound("keyring".to_owned()));
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|_| SecretError::InvalidUtf8("keyring".to_owned()))?;
    let value = strip_one_trailing_line_ending(value);
    if value.is_empty() {
        Err(SecretError::NotFound("keyring".to_owned()))
    } else {
        Ok(Secret::new(value))
    }
}

#[cfg(target_os = "macos")]
fn platform_keyring_secret(service: &str, account: &str) -> Result<Secret, SecretError> {
    run_keyring_command(
        "/usr/bin/security",
        &["find-generic-password", "-w", "-s", service, "-a", account],
    )
}

#[cfg(target_os = "linux")]
fn platform_keyring_secret(service: &str, account: &str) -> Result<Secret, SecretError> {
    run_keyring_command(
        "secret-tool",
        &["lookup", "service", service, "account", account],
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform_keyring_secret(_service: &str, _account: &str) -> Result<Secret, SecretError> {
    Err(SecretError::BackendUnavailable("keyring".to_owned()))
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

    fn empty_env(_: &str) -> Option<String> {
        None
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
        let resolver = EnvLookupSecretResolver::new(env(&m));
        assert_eq!(
            resolve_secret_with("env:DB_PASSWORD", true, &resolver)
                .expect("resolve via seam")
                .expose(),
            "tiger"
        );
        // Missing var -> NotFound.
        assert!(matches!(
            resolve_secret_with("env:NOPE", false, &resolver),
            Err(SecretError::NotFound(_))
        ));
    }

    #[test]
    fn file_scheme_resolves_from_secret_file_and_strips_one_line_ending() {
        let path = std::env::temp_dir().join(format!(
            "oraclemcp-secret-test-{}-file.txt",
            std::process::id()
        ));
        std::fs::write(&path, "file-secret\n").expect("write secret fixture");
        let reference = format!("file:{}", path.display());
        let resolver = EnvLookupSecretResolver::new(empty_env);
        let s = resolve_secret_with(&reference, true, &resolver).expect("resolve file");
        assert_eq!(s.expose(), "file-secret");
    }

    #[test]
    fn keyring_scheme_is_available_through_the_resolver_seam() {
        struct MockResolver;
        impl SecretResolver for MockResolver {
            fn resolve(&self, reference: &SecretRef) -> Result<Secret, SecretError> {
                match reference.scheme.as_str() {
                    "keyring" => {
                        let (service, account) = parse_keyring_locator(&reference.locator)?;
                        Ok(Secret::new(format!("{service}/{account}-secret")))
                    }
                    other => Err(SecretError::BackendUnavailable(other.to_owned())),
                }
            }
        }

        let s = resolve_secret_with("keyring:prod/ro", true, &MockResolver).expect("keyring");
        assert_eq!(s.expose(), "prod/ro-secret");
        assert_eq!(
            parse_keyring_locator("solo").expect("default service"),
            (DEFAULT_KEYRING_SERVICE, "solo")
        );
    }

    #[test]
    fn literal_is_denied_under_protected_profile() {
        let m = HashMap::new();
        let resolver = EnvLookupSecretResolver::new(env(&m));
        assert!(matches!(
            resolve_secret_with("literal:hunter2", true, &resolver),
            Err(SecretError::PlaintextForbidden)
        ));
        // Allowed in dev (non-protected).
        assert_eq!(
            resolve_secret_with("literal:hunter2", false, &resolver)
                .unwrap()
                .expose(),
            "hunter2"
        );
    }

    #[test]
    fn vault_scheme_is_explicit_backend_unavailable_without_the_feature() {
        let m = HashMap::new();
        let resolver = EnvLookupSecretResolver::new(env(&m));
        assert!(matches!(
            resolve_secret_with("vault:secret/oracle#password", true, &resolver),
            Err(SecretError::BackendUnavailable(_))
        ));
    }

    #[test]
    fn secret_debug_is_redacted() {
        let s = Secret::new("hunter2");
        assert_eq!(format!("{s:?}"), "Secret(***redacted***)");
        assert!(!format!("{s:?}").contains("hunter2"));
    }

    #[test]
    fn secret_ref_debug_redacts_locator() {
        let r = SecretRef::parse("file:/private/path/secret.txt").expect("parse");
        let rendered = format!("{r:?}");
        assert!(rendered.contains("file"));
        assert!(!rendered.contains("/private/path/secret.txt"));
    }
}
