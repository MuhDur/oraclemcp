//! Operator-facing redaction helpers for secrets that must never appear in
//! doctor output, logs, or golden fixtures.

/// Placeholder substituted for scrubbed secret substrings in doctor detail/fix text.
pub const REDACTED: &str = "<redacted>";

/// A secret value that must not appear in `Debug`, `Display`, or serialized
/// operator surfaces. Use [`expose`](Self::expose) only at trust boundaries
/// (connect, signing) — never when building doctor or error envelopes.
#[derive(Clone, PartialEq, Eq)]
pub struct RedactedSecret(String);

impl RedactedSecret {
    /// Wrap a resolved secret for transient handling.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the secret for internal use (connect, HMAC, etc.).
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Consume and return the inner value.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Debug for RedactedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

impl std::fmt::Display for RedactedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

/// Replace every non-empty `secret` substring in `message` with [`REDACTED`].
/// Longest secrets first avoids partial leaks when one value is a prefix of another.
#[must_use]
pub fn redact_exact_substrings(message: &str, secrets: &[String]) -> String {
    let mut out = message.to_owned();
    let mut sorted: Vec<&str> = secrets
        .iter()
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .collect();
    sorted.sort_by_key(|value| std::cmp::Reverse(value.len()));
    for secret in sorted {
        out = out.replace(secret, REDACTED);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_secret_never_renders_plaintext() {
        let secret = RedactedSecret::new("plain-text-must-not-appear");
        assert_eq!(format!("{secret:?}"), REDACTED);
        assert_eq!(format!("{secret}"), REDACTED);
        assert_eq!(secret.expose(), "plain-text-must-not-appear");
    }

    #[test]
    fn redact_longest_first() {
        let message = "host=db.example secret=abc123xyz tail";
        let secrets = vec!["abc".to_owned(), "abc123xyz".to_owned()];
        let out = redact_exact_substrings(message, &secrets);
        assert_eq!(out, "host=db.example secret=<redacted> tail");
    }
}
