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

/// Redact an operator-facing message: first the exact known-secret substrings,
/// then any Oracle Cloud identifier (OCID) embedded in the surrounding prose.
///
/// This is the funnel for doctor detail/fix text and error envelopes. The two
/// passes are complementary — [`redact_exact_substrings`] scrubs values we
/// already hold (passwords, tokens), while [`redact_ocids`] catches a tenant or
/// resource identifier that an Oracle/OCI error message quoted back to us and
/// that we never had in `secrets` to match exactly.
#[must_use]
pub fn redact_operator_text(message: &str, secrets: &[String]) -> String {
    redact_ocids(&redact_exact_substrings(message, secrets))
}

/// Characters an OCID segment may carry. The documented shape is
/// `ocid1.<resource type>.<realm>[.<region>][.<future use>].<unique id>`, all
/// dot-separated ASCII alphanumerics with `-` and `_` appearing in practice.
fn is_ocid_body(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-' || byte == b'_'
}

/// Replace every OCID token embedded in free-text prose (error messages, log
/// lines) with [`REDACTED`], leaving the surrounding sentence intact.
///
/// Deliberately narrow, so it scrubs identifiers without mangling the messages
/// this surface exists to carry:
///
/// - A bare `ocid1` marker or a single-segment fragment (`ocid1.instance`) is
///   prose, not an identifier: the recognizer requires the documented minimum
///   of `ocid1.<type>.<realm>` — at least two non-empty segments past the
///   marker — before it redacts.
/// - The marker must sit on a token boundary, so a word that merely contains it
///   (`xocid1.instance.oc1`) is left alone.
/// - Approved digests (a `subject-sha256:<hex>` or a bare SHA-256) never begin
///   with `ocid1.` and contain no `ocid1.` substring, so they always survive.
#[must_use]
pub fn redact_ocids(message: &str) -> String {
    const MARKER: &str = "ocid1.";
    let lower = message.to_ascii_lowercase();
    let bytes = message.as_bytes();
    let mut out = String::with_capacity(message.len());
    let mut cursor = 0usize;

    while let Some(offset) = lower[cursor..].find(MARKER) {
        let start = cursor + offset;
        // Must start at a token boundary: the beginning, whitespace, or
        // punctuation. `xocid1.a.b` is not an OCID.
        let boundary = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let mut end = start + MARKER.len();
        while end < bytes.len() && is_ocid_body(bytes[end]) {
            end += 1;
        }
        // Trailing sentence punctuation belongs to the prose, not the id.
        while end > start && bytes[end - 1] == b'.' {
            end -= 1;
        }
        let token = &message[start..end];
        // ocid1 + type + realm at minimum: at least two non-empty segments
        // after the prefix marker.
        let segments = token.split('.').skip(1).filter(|s| !s.is_empty()).count();
        if boundary && segments >= 2 {
            out.push_str(&message[cursor..start]);
            out.push_str(REDACTED);
            cursor = end;
        } else {
            // Not an identifier: copy through up to the end of this candidate
            // so the scan always advances.
            let advance = end.max(start + MARKER.len());
            out.push_str(&message[cursor..advance]);
            cursor = advance;
        }
    }
    out.push_str(&message[cursor..]);
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

    /// Assemble a synthetic OCID at runtime. The literal five-segment shape must
    /// never appear in a tracked file: `scripts/secret_scan.sh` greps every
    /// tracked path for it so a real tenant identifier can never be committed.
    /// Building it from fragments keeps the fixture synthetic and the gate
    /// meaningful (mirrors the telemetry crate's `synthetic_ocid`).
    fn synthetic_ocid(resource: &str) -> String {
        format!("ocid{}.{resource}.oc1.phx.{}", 1, "aaaaexamplefake0000")
    }

    #[test]
    fn ocids_embedded_in_prose_are_redacted_at_every_boundary() {
        let ocid = synthetic_ocid("instance");
        for (label, value) in [
            ("prefix", format!("{ocid} could not be reached")),
            (
                "middle",
                format!("ORA-12514 while resolving {ocid} for tenant"),
            ),
            (
                "suffix",
                format!("listener refused the connection to {ocid}"),
            ),
            (
                "sentence punctuation",
                format!("target was {ocid}. Retrying."),
            ),
            ("parenthesised", format!("target ({ocid}) is unreachable")),
            ("comma", format!("targets {ocid}, then the standby")),
        ] {
            let redacted = redact_ocids(&value);
            assert!(
                !redacted.contains(&ocid),
                "{label}: the identifier survived redaction: {redacted}"
            );
            assert!(
                redacted.contains(REDACTED),
                "{label}: nothing was redacted: {redacted}"
            );
        }
    }

    #[test]
    fn ordinary_prose_and_near_misses_survive_ocid_scan() {
        for value in [
            "ORA-00942: table or view does not exist",
            "connection reset by peer while reading the response",
            // Near misses: a bare marker, a one-segment fragment, and a word
            // that merely contains the marker are prose, not identifiers.
            "the ocid1 prefix identifies an Oracle Cloud id",
            "ocid1.instance",
            "xocid1.instance.oc1 is not an identifier",
        ] {
            assert_eq!(
                redact_ocids(value),
                value,
                "ordinary prose must survive unchanged: {value}"
            );
        }
    }

    #[test]
    fn every_ocid_in_a_message_is_redacted_not_just_the_first() {
        let first = synthetic_ocid("instance");
        let second = synthetic_ocid("autonomousdatabase");
        let redacted = redact_ocids(&format!("failover from {first} to {second}"));
        assert!(
            !redacted.contains(&first) && !redacted.contains(&second),
            "both identifiers must be redacted: {redacted}"
        );
        assert_eq!(
            redacted.matches(REDACTED).count(),
            2,
            "each identifier gets its own marker: {redacted}"
        );
        assert!(
            redacted.starts_with("failover from ") && redacted.contains(" to "),
            "the surrounding message must survive: {redacted}"
        );
    }

    #[test]
    fn approved_hashes_are_never_masked_by_ocid_scan() {
        // A `subject-sha256:<hex>` digest and a bare SHA-256 must pass through
        // untouched — neither contains the `ocid1.` marker, so the narrow
        // recognizer never fires on them.
        let subject = format!("subject-sha256:{}", "0123456789abcdef".repeat(4));
        let bare = "a".repeat(64);
        for approved in [subject.clone(), bare.clone()] {
            let message = format!("audit subject {approved} accepted");
            assert_eq!(
                redact_ocids(&message),
                message,
                "approved hash must survive: {approved}"
            );
        }
    }

    #[test]
    fn operator_text_redacts_both_known_secrets_and_prose_ocids() {
        let ocid = synthetic_ocid("instance");
        let secrets = vec!["hunter2".to_owned()];
        let message = format!("connect to {ocid} with password hunter2 failed");
        let out = redact_operator_text(&message, &secrets);
        assert!(!out.contains(&ocid), "OCID must be redacted: {out}");
        assert!(
            !out.contains("hunter2"),
            "known secret must be redacted: {out}"
        );
        assert!(
            out.contains("connect to <redacted> with password <redacted> failed"),
            "surrounding prose must survive: {out}"
        );
    }
}
