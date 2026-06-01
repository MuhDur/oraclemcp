//! The stdio transport init-token gate (plan §7.1).
//!
//! Over stdio the trust boundary is the OS process (the agent spawned the
//! server), hardened with a shared init token from `$ORACLEMCP_STDIO_TOKEN`,
//! checked on the first `initialize` before any other request. The server
//! refuses to start without a token unless `--allow-no-auth` is explicit.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The env var holding the expected stdio init token.
pub const STDIO_TOKEN_ENV: &str = "ORACLEMCP_STDIO_TOKEN";

/// The configured stdio auth policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StdioAuthPolicy {
    /// A token is required; the client must present it on `initialize`.
    Required {
        /// The expected token (loaded from `$ORACLEMCP_STDIO_TOKEN`).
        expected: String,
    },
    /// Auth is explicitly disabled (`--allow-no-auth`).
    Disabled,
}

/// Init-token validation failures.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum InitTokenError {
    /// No token was configured and `--allow-no-auth` was not set.
    #[error(
        "stdio init token required: set ${STDIO_TOKEN_ENV} or pass --allow-no-auth to run without it"
    )]
    NotConfigured,
    /// The client presented no token but one is required.
    #[error("stdio init token missing from initialize request")]
    Missing,
    /// The presented token did not match.
    #[error("stdio init token mismatch")]
    Mismatch,
}

impl StdioAuthPolicy {
    /// Resolve the policy from the environment and the `--allow-no-auth` flag.
    /// Returns [`InitTokenError::NotConfigured`] when neither a token nor the
    /// bypass is present (fail-closed: the server refuses to start).
    pub fn resolve(env_token: Option<String>, allow_no_auth: bool) -> Result<Self, InitTokenError> {
        match (env_token, allow_no_auth) {
            (Some(t), _) if !t.is_empty() => Ok(StdioAuthPolicy::Required { expected: t }),
            (_, true) => Ok(StdioAuthPolicy::Disabled),
            _ => Err(InitTokenError::NotConfigured),
        }
    }

    /// Validate the token presented on `initialize`. `Disabled` accepts any
    /// (including absent). `Required` demands a constant-time match.
    pub fn validate(&self, presented: Option<&str>) -> Result<(), InitTokenError> {
        match self {
            StdioAuthPolicy::Disabled => Ok(()),
            StdioAuthPolicy::Required { expected } => match presented {
                None => Err(InitTokenError::Missing),
                Some(p) if constant_time_eq(p.as_bytes(), expected.as_bytes()) => Ok(()),
                Some(_) => Err(InitTokenError::Mismatch),
            },
        }
    }
}

/// Constant-time byte comparison (no early return on first mismatch). The
/// length comparison can leak length, which is acceptable for a fixed-format
/// shared token.
#[must_use]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_requires_token_or_bypass() {
        assert!(matches!(
            StdioAuthPolicy::resolve(None, false),
            Err(InitTokenError::NotConfigured)
        ));
        assert!(matches!(
            StdioAuthPolicy::resolve(Some(String::new()), false),
            Err(InitTokenError::NotConfigured)
        ));
        assert_eq!(
            StdioAuthPolicy::resolve(None, true),
            Ok(StdioAuthPolicy::Disabled)
        );
        assert!(matches!(
            StdioAuthPolicy::resolve(Some("secret".to_owned()), false),
            Ok(StdioAuthPolicy::Required { .. })
        ));
    }

    #[test]
    fn required_policy_validates_token() {
        let policy = StdioAuthPolicy::Required {
            expected: "s3cr3t".to_owned(),
        };
        assert_eq!(policy.validate(Some("s3cr3t")), Ok(()));
        assert_eq!(
            policy.validate(Some("wrong")),
            Err(InitTokenError::Mismatch)
        );
        assert_eq!(policy.validate(None), Err(InitTokenError::Missing));
    }

    #[test]
    fn disabled_policy_accepts_anything() {
        let policy = StdioAuthPolicy::Disabled;
        assert_eq!(policy.validate(None), Ok(()));
        assert_eq!(policy.validate(Some("whatever")), Ok(()));
    }

    #[test]
    fn constant_time_eq_correctness() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }
}
