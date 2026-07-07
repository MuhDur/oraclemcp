//! Server-side OCI IAM database-token resolution (bead B2.2a): the two SIMPLE
//! token sources — an **environment variable** and a **token file** — that feed
//! a pre-fetched JWT database token into
//! [`OracleConnectOptions::iam_token`](oraclemcp_db::OracleConnectOptions), which
//! the B2 adapter then hands to the driver via `with_access_token` (TCPS-enforced;
//! a token on a plaintext transport is refused).
//!
//! Discipline (mirrors [`oraclemcp_auth::secrets`]): a token is an **external
//! ref**. This module holds only the *reference* (an env-var NAME or a file PATH)
//! on its types; the token **value** is resolved transiently at connect time and
//! is never persisted, rendered, logged, or placed in an error message. Both
//! sources **re-resolve on every [`ServerIamTokenSource::get_token`]** so a
//! rotated env/file is picked up without a restart. An empty or missing token is
//! a typed, fail-closed error — never a silent empty token.
//!
//! The richer proactive-refresh seam (`oraclemcp_db::IamTokenSource` /
//! `ensure_fresh_token`, for a future OCI-SDK source) is unchanged; these simple
//! sources use the static [`with_access_token`] path and re-read on each connect,
//! so a separate skew-based refresher is unnecessary for them.
//!
//! [`with_access_token`]: https://docs.rs/oracledb

use std::path::PathBuf;

use oraclemcp_config::{ConnectionProfile, OciConfig};
use oraclemcp_db::OracleConnectOptions;
use thiserror::Error;

/// The built-in environment variable checked for an IAM database token when a
/// profile enables `use_iam_token` without naming its own `token_env`.
pub const IAM_TOKEN_ENV: &str = "ORACLEMCP_IAM_TOKEN";

/// Seconds-before-expiry at which the JWT `exp` is considered "near expiry" for
/// the doctor diagnostic (5 minutes).
pub const IAM_TOKEN_EXPIRY_WARN_SECS: i64 = 300;

/// IAM database-token resolution failures. Fail-closed and **token-free**: no
/// variant carries the token value, so an error may be logged or surfaced
/// without leaking the credential.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum IamTokenError {
    /// The named environment variable is not set.
    #[error("IAM token environment variable `{0}` is not set")]
    EnvMissing(String),
    /// The token file could not be read (missing / unreadable).
    #[error("IAM token file `{0}` could not be read")]
    FileUnreadable(String),
    /// The resolved source produced an empty token (whitespace-only or empty).
    #[error("resolved IAM token from {0} is empty")]
    Empty(&'static str),
    /// A token is configured on a transport that is not provably TLS/TCPS. A
    /// database access token must never travel in clear text, so we fail closed
    /// before the token reaches the driver.
    #[error(
        "OCI IAM database-token auth requires a TLS (TCPS) transport; use a tcps:// connect \
         string, a PROTOCOL=TCPS descriptor, or a wallet-backed TLS profile"
    )]
    NonTcpsTransport,
}

/// A simple server-side IAM database-token source: an environment variable or a
/// token file. Each variant holds only the *reference* — never the token value —
/// and re-resolves on every [`Self::get_token`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerIamTokenSource {
    /// Read the token from an environment variable. `None` uses the built-in
    /// [`IAM_TOKEN_ENV`]; `Some(name)` uses the profile's `token_env` variable.
    Env {
        /// The environment-variable name, or `None` for [`IAM_TOKEN_ENV`].
        var: Option<String>,
    },
    /// Read the token from a file, re-read on every fetch.
    File {
        /// The token file path.
        path: PathBuf,
    },
}

impl ServerIamTokenSource {
    /// The source implied by a profile's `[profiles.oci]` config, when
    /// `use_iam_token` is set. Precedence: an explicit `token_file` wins, else a
    /// `token_env`-named variable, else the built-in [`IAM_TOKEN_ENV`]. Returns
    /// `None` when the profile does not use IAM-token auth.
    #[must_use]
    pub fn from_oci(oci: &OciConfig) -> Option<Self> {
        if !oci.use_iam_token {
            return None;
        }
        if let Some(path) = oci
            .token_file
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
        {
            return Some(ServerIamTokenSource::File {
                path: PathBuf::from(path),
            });
        }
        let var = oci
            .token_env
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(ToOwned::to_owned);
        Some(ServerIamTokenSource::Env { var })
    }

    /// Resolve the token now, reading the env/file **fresh** on every call so a
    /// rotated token is picked up without a restart. Trims surrounding
    /// whitespace/newlines; an empty or missing token is a typed, fail-closed
    /// error. The returned string is the raw token — keep the borrow short-lived
    /// and never log it.
    pub fn get_token(&self) -> Result<String, IamTokenError> {
        self.get_token_with(|name| std::env::var(name).ok())
    }

    /// [`Self::get_token`] with an injected environment lookup (deterministic
    /// tests). File resolution still reads the real filesystem.
    pub fn get_token_with(
        &self,
        env_lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<String, IamTokenError> {
        match self {
            ServerIamTokenSource::Env { var } => {
                let name = var.as_deref().unwrap_or(IAM_TOKEN_ENV);
                let raw =
                    env_lookup(name).ok_or_else(|| IamTokenError::EnvMissing(name.to_owned()))?;
                non_empty(raw.trim(), "env")
            }
            ServerIamTokenSource::File { path } => {
                // Re-read on every call: a rotated token file is picked up with
                // no caching across calls.
                let raw = std::fs::read_to_string(path)
                    .map_err(|_| IamTokenError::FileUnreadable(path.display().to_string()))?;
                non_empty(raw.trim(), "file")
            }
        }
    }
}

fn non_empty(trimmed: &str, source: &'static str) -> Result<String, IamTokenError> {
    if trimmed.is_empty() {
        Err(IamTokenError::Empty(source))
    } else {
        Ok(trimmed.to_owned())
    }
}

/// Whether a profile's transport is provably TLS/TCPS *before* opening the
/// socket — the same fail-closed signals the B2 adapter uses
/// (`transport_is_tcps`): a `tcps://` scheme, a `PROTOCOL=TCPS` descriptor, a
/// configured wallet directory, or an explicit server-cert DN. A bare TNS alias
/// backed by an OCI wallet is covered by `wallet_location`.
#[must_use]
pub fn profile_transport_is_tcps(profile: &ConnectionProfile) -> bool {
    let connect_string = profile.connect_string.as_deref().unwrap_or_default();
    let compact: String = connect_string
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let tls_connect_string = compact.starts_with("tcps://") || compact.contains("protocol=tcps");
    let wallet_or_cert = profile
        .oci
        .as_ref()
        .is_some_and(|oci| oci.wallet_location.is_some() || oci.ssl_server_cert_dn.is_some());
    tls_connect_string || wallet_or_cert
}

/// Resolve the server-side IAM database token for `profile` (env/file source)
/// and inject it into `options.iam_token`, so the B2 adapter wires it through
/// `with_access_token`. A **no-op** when the profile does not use IAM-token auth.
///
/// Fails closed if `use_iam_token` is set but (a) the transport is not provably
/// TCPS (a token must never travel in clear text — refused here as defense in
/// depth, and again by the driver at connect), or (b) the configured source
/// yields an empty/missing token. No error carries the token value.
pub fn inject_iam_token(
    profile: &ConnectionProfile,
    options: &mut OracleConnectOptions,
) -> Result<(), IamTokenError> {
    inject_iam_token_with(profile, options, |name| std::env::var(name).ok())
}

/// [`inject_iam_token`] with an injected environment lookup (deterministic
/// tests). File resolution still reads the real filesystem.
pub fn inject_iam_token_with(
    profile: &ConnectionProfile,
    options: &mut OracleConnectOptions,
    env_lookup: impl Fn(&str) -> Option<String>,
) -> Result<(), IamTokenError> {
    let Some(oci) = profile.oci.as_ref() else {
        return Ok(());
    };
    let Some(source) = ServerIamTokenSource::from_oci(oci) else {
        return Ok(());
    };
    // Refuse a token on a non-TCPS transport BEFORE reading it: a database access
    // token must never be exposed on a plaintext socket.
    if !profile_transport_is_tcps(profile) {
        return Err(IamTokenError::NonTcpsTransport);
    }
    let token = source.get_token_with(env_lookup)?;
    options.iam_token = Some(token);
    Ok(())
}

/// Read the `exp` (Unix seconds) claim from a JWT **without validating the
/// signature** — a diagnostic-only parse for the doctor near-expiry warning.
/// base64url-decodes the payload (second `.`-separated segment) and reads the
/// numeric `exp`. Returns `None` if the token is not a JWT-shaped string or has
/// no readable numeric `exp`. Never returns or logs the token itself.
#[must_use]
pub fn jwt_exp_unix(token: &str) -> Option<i64> {
    let payload_b64 = token.trim().split('.').nth(1)?;
    let payload = base64url_decode(payload_b64)?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    match claims.get("exp")? {
        serde_json::Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        _ => None,
    }
}

/// Minimal base64url (RFC 4648 §5, no padding) decoder. Pure, allocation-only,
/// no dependency — the workspace does not take a direct `base64` dep and this is
/// a tiny diagnostic decode. Tolerates optional `=` padding by stopping at it.
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    fn sextet(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &c in input.as_bytes() {
        if c == b'=' {
            break;
        }
        buffer = (buffer << 6) | sextet(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xFF).ok()?);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oraclemcp_config::OracleMcpConfig;

    /// Build a synthetic, unsigned JWT-shaped token: `header.payload.` where the
    /// payload is a base64url `{"exp": <exp>}`. NOT a real token; no signature.
    fn synthetic_jwt_with_exp(exp: i64) -> String {
        // base64url of `{"alg":"none"}` and the exp payload — computed by the
        // same decoder's inverse would be overkill; encode by hand.
        let header = base64url_encode(br#"{"alg":"none"}"#);
        let payload = base64url_encode(format!(r#"{{"exp":{exp}}}"#).as_bytes());
        format!("{header}.{payload}.")
    }

    fn base64url_encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        let mut buffer = 0u32;
        let mut bits = 0u32;
        for &b in bytes {
            buffer = (buffer << 8) | u32::from(b);
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                out.push(ALPHABET[((buffer >> bits) & 0x3F) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(ALPHABET[((buffer << (6 - bits)) & 0x3F) as usize] as char);
        }
        out
    }

    fn env_map(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        // Own the pairs so the returned closure does not borrow a temporary array.
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| {
            owned
                .iter()
                .find(|(name, _)| name == k)
                .map(|(_, v)| v.clone())
        }
    }

    fn tcps_profile() -> ConnectionProfile {
        OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "cloud"
            connect_string = "tcps://adb.example/svc"
            username = "app"
            [profiles.oci]
            use_iam_token = true
            "#,
        )
        .expect("config")
        .profiles
        .into_iter()
        .next()
        .expect("profile")
    }

    #[test]
    fn env_source_uses_builtin_when_no_token_env() {
        let src = ServerIamTokenSource::Env { var: None };
        let env = env_map(&[(IAM_TOKEN_ENV, "  header.payload.sig\n")]);
        assert_eq!(src.get_token_with(&env).unwrap(), "header.payload.sig");
    }

    #[test]
    fn env_source_uses_named_token_env() {
        let src = ServerIamTokenSource::Env {
            var: Some("MY_IAM_TOKEN".to_owned()),
        };
        let env = env_map(&[("MY_IAM_TOKEN", "tok-abc\n")]);
        assert_eq!(src.get_token_with(&env).unwrap(), "tok-abc");
        // A missing named var is a typed, fail-closed error (never empty token).
        let missing = ServerIamTokenSource::Env {
            var: Some("ABSENT_VAR".to_owned()),
        };
        assert_eq!(
            missing.get_token_with(env_map(&[])),
            Err(IamTokenError::EnvMissing("ABSENT_VAR".to_owned()))
        );
    }

    #[test]
    fn env_empty_token_is_fail_closed_not_silent() {
        let src = ServerIamTokenSource::Env { var: None };
        let env = env_map(&[(IAM_TOKEN_ENV, "   \n")]);
        assert_eq!(src.get_token_with(&env), Err(IamTokenError::Empty("env")));
    }

    #[test]
    fn file_source_reads_and_rereads_on_rotation() {
        let path = std::env::temp_dir().join(format!(
            "oraclemcp-iam-token-rotate-{}.jwt",
            std::process::id()
        ));
        std::fs::write(&path, "token-A\n").expect("write A");
        let src = ServerIamTokenSource::File { path: path.clone() };
        assert_eq!(src.get_token().unwrap(), "token-A");
        // Overwrite with B: the next get_token must observe B (no caching).
        std::fs::write(&path, "token-B\n").expect("write B");
        assert_eq!(src.get_token().unwrap(), "token-B");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn file_missing_is_fail_closed() {
        let src = ServerIamTokenSource::File {
            path: PathBuf::from("/no/such/oraclemcp/iam-token.jwt"),
        };
        assert!(matches!(
            src.get_token(),
            Err(IamTokenError::FileUnreadable(_))
        ));
    }

    #[test]
    fn from_oci_precedence_file_over_env_over_builtin() {
        let mut oci = OciConfig {
            use_iam_token: true,
            ..OciConfig::default()
        };
        // No refs -> built-in env.
        assert_eq!(
            ServerIamTokenSource::from_oci(&oci),
            Some(ServerIamTokenSource::Env { var: None })
        );
        // token_env named -> that var.
        oci.token_env = Some("NAMED".to_owned());
        assert_eq!(
            ServerIamTokenSource::from_oci(&oci),
            Some(ServerIamTokenSource::Env {
                var: Some("NAMED".to_owned())
            })
        );
        // token_file present -> file wins over env.
        oci.token_file = Some("/etc/iam.jwt".to_owned());
        assert_eq!(
            ServerIamTokenSource::from_oci(&oci),
            Some(ServerIamTokenSource::File {
                path: PathBuf::from("/etc/iam.jwt")
            })
        );
        // use_iam_token off -> no source.
        oci.use_iam_token = false;
        assert_eq!(ServerIamTokenSource::from_oci(&oci), None);
    }

    #[test]
    fn inject_sets_options_token_over_tcps() {
        let profile = tcps_profile();
        let mut opts = OracleConnectOptions {
            use_iam_token: true,
            ..Default::default()
        };
        let env = env_map(&[(IAM_TOKEN_ENV, "resolved.jwt.token")]);
        inject_iam_token_with(&profile, &mut opts, &env).expect("inject over tcps");
        assert_eq!(opts.iam_token.as_deref(), Some("resolved.jwt.token"));
    }

    #[test]
    fn inject_refuses_non_tcps_transport() {
        // Same profile but a plaintext EZConnect string (no wallet, no cert DN).
        let profile = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "plain"
            connect_string = "localhost:1521/FREEPDB1"
            username = "app"
            [profiles.oci]
            use_iam_token = true
            "#,
        )
        .expect("config")
        .profiles
        .into_iter()
        .next()
        .expect("profile");
        let mut opts = OracleConnectOptions::default();
        let env = env_map(&[(IAM_TOKEN_ENV, "SECRET_JWT_SENTINEL.payload.sig")]);
        let err = inject_iam_token_with(&profile, &mut opts, &env).expect_err("non-tcps refused");
        assert_eq!(err, IamTokenError::NonTcpsTransport);
        // Fail-closed: no token was injected.
        assert!(opts.iam_token.is_none());
        // The refusal must not echo the token.
        assert!(!err.to_string().contains("SECRET_JWT_SENTINEL"));
    }

    #[test]
    fn inject_is_noop_without_iam_token_auth() {
        let profile = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "pw"
            connect_string = "localhost:1521/FREEPDB1"
            username = "app"
            "#,
        )
        .expect("config")
        .profiles
        .into_iter()
        .next()
        .expect("profile");
        let mut opts = OracleConnectOptions::default();
        inject_iam_token_with(&profile, &mut opts, env_map(&[])).expect("noop");
        assert!(opts.iam_token.is_none());
    }

    #[test]
    fn jwt_exp_is_parsed_without_signature_validation() {
        let token = synthetic_jwt_with_exp(1_900_000_000);
        assert_eq!(jwt_exp_unix(&token), Some(1_900_000_000));
        // Non-JWT / no exp -> None (diagnostic only).
        assert_eq!(jwt_exp_unix("not-a-jwt"), None);
        assert_eq!(jwt_exp_unix("aaa.bbb.ccc"), None);
    }

    #[test]
    fn no_rendered_surface_leaks_the_token_sentinel() {
        // Adversarial non-leak: a sentinel token flows through resolution, the
        // source Debug, and an error; it must appear in NONE of them.
        const SENTINEL: &str = "SECRET_JWT_SENTINEL";
        let token = format!("{SENTINEL}.payload.sig");

        let env_src = ServerIamTokenSource::Env {
            var: Some("SENTINEL_VAR".to_owned()),
        };
        let file_src = ServerIamTokenSource::File {
            path: PathBuf::from("/etc/oracle/iam.jwt"),
        };
        let rendered_sources = format!("{env_src:?} {file_src:?}");
        assert!(
            !rendered_sources.contains(SENTINEL),
            "source Debug leaked: {rendered_sources}"
        );

        // A successful resolution returns the token but stores nothing on the
        // source; re-rendering the source still shows no token.
        let env = env_map(&[("SENTINEL_VAR", token.as_str())]);
        let resolved = env_src.get_token_with(&env).expect("resolve");
        assert!(resolved.contains(SENTINEL)); // the caller holds it transiently
        let rendered_after = format!("{env_src:?}");
        assert!(!rendered_after.contains(SENTINEL));

        // Every IamTokenError Display is token-free.
        for err in [
            IamTokenError::EnvMissing("SENTINEL_VAR".to_owned()),
            IamTokenError::FileUnreadable("/etc/oracle/iam.jwt".to_owned()),
            IamTokenError::Empty("env"),
            IamTokenError::NonTcpsTransport,
        ] {
            assert!(!err.to_string().contains(SENTINEL), "{err}");
        }
    }
}
