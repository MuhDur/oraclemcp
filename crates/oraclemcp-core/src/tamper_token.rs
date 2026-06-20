//! Opaque, tamper-evident tokens (WP-E E2/E3).
//!
//! Several MCP surfaces hand the client an opaque string it later replays back:
//! a pagination `nextCursor` (E2) and an `oracle-export://{id}` resource id
//! (E3). A naive scheme (a raw offset, a guessable id) lets a client *forge* a
//! token to read outside the result/offset it was given, or to fetch an export
//! belonging to a different statement/profile. That is an authorization
//! boundary, so the tokens must be **unforgeable**.
//!
//! This module signs a small, structured payload with `HMAC-SHA256` over a
//! per-process random key (so a token from one server process cannot be
//! replayed against another) using the same audited primitive the rest of the
//! workspace uses (`oraclemcp_audit::hmac_sha256`, RFC 2104, constant-time
//! compare on verify). The payload is the bound context (`scope` + a list of
//! string fields, length-prefixed so fields cannot be ambiguously concatenated)
//! plus an 8-byte MAC tag rendered as hex. The verifier recomputes the MAC over
//! the *expected* context and constant-time-compares; any edit to the payload —
//! a bumped offset, a swapped statement hash, a different profile — fails.
//!
//! The key is intentionally process-local and never serialized: these tokens
//! are short-lived (a pagination handle, an export id valid until expiry), so
//! losing them on restart is correct, not a regression.

use std::sync::OnceLock;

use oraclemcp_audit::{ct_eq, hmac_sha256};

/// Length (in hex chars) of the appended MAC tag. 8 raw bytes => 16 hex chars
/// of second-preimage resistance, matching the existing confirmation-token
/// tag width in dispatch; ample for a non-secret, short-lived authz handle.
const TAG_HEX_LEN: usize = 16;
const TAG_BYTES: usize = TAG_HEX_LEN / 2;

/// The per-process tamper-evidence key. Random per process: a forged or stale
/// token minted elsewhere never verifies here. Generated lazily on first use.
fn token_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key)
            .expect("OS random source required for tamper-evident tokens");
        key
    })
}

/// Render the low [`TAG_BYTES`] of the MAC as lowercase hex.
fn tag_hex(mac: &[u8; 32]) -> String {
    let mut out = String::with_capacity(TAG_HEX_LEN);
    for byte in &mac[..TAG_BYTES] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Compute the MAC over a domain-separated, length-prefixed encoding of
/// `scope` + `payload` + `fields`. Length-prefixing each part means no choice
/// of values can collide with a different split (e.g. `["ab","c"]` vs
/// `["a","bc"]`), so the bound context is unambiguous. The `payload` is signed
/// too, so a client cannot keep a valid tag while editing the body (e.g.
/// bumping a pagination offset to read past its page).
fn token_mac(scope: &str, payload: &str, fields: &[&str]) -> [u8; 32] {
    let mut message = Vec::new();
    let push = |message: &mut Vec<u8>, part: &[u8]| {
        message.extend_from_slice(&(part.len() as u64).to_le_bytes());
        message.extend_from_slice(part);
    };
    push(&mut message, b"oraclemcp:tamper-token:v1");
    push(&mut message, scope.as_bytes());
    push(&mut message, payload.as_bytes());
    for field in fields {
        push(&mut message, field.as_bytes());
    }
    hmac_sha256(token_key(), &message)
}

/// Sign `payload` for `scope`, binding it to `fields`, and return
/// `"<payload>.<tag>"`. `payload` is the opaque, client-visible body (e.g. an
/// offset, an export id); `fields` is the context the client must NOT be able
/// to alter (e.g. the statement hash, the active profile). The client never
/// sees `fields`; it only replays the whole token, which the server re-binds on
/// verify.
#[must_use]
pub fn sign_token(scope: &str, payload: &str, fields: &[&str]) -> String {
    debug_assert!(
        !payload.contains('.'),
        "token payload must not contain '.' (the tag separator)"
    );
    let tag = tag_hex(&token_mac(scope, payload, fields));
    format!("{payload}.{tag}")
}

/// Verify `token` for `scope` against the expected `fields`, returning the
/// opaque payload body on success. Fails closed: a missing tag, a malformed
/// token, or a MAC mismatch (a forged/edited token, or one bound to a different
/// context) all return `None`. The compare is constant-time.
#[must_use]
pub fn verify_token(scope: &str, token: &str, fields: &[&str]) -> Option<String> {
    let (payload, tag) = token.rsplit_once('.')?;
    if tag.len() != TAG_HEX_LEN || !tag.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let expected = tag_hex(&token_mac(scope, payload, fields));
    // Constant-time compare over the lowercase-hex tags; reject before
    // surfacing any payload so a forged context never leaks an offset/id.
    if ct_eq(expected.as_bytes(), tag.to_ascii_lowercase().as_bytes()) {
        Some(payload.to_owned())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_the_payload_under_the_bound_context() {
        let token = sign_token("cursor:list:tools", "42", &["tools-v1"]);
        assert_eq!(
            verify_token("cursor:list:tools", &token, &["tools-v1"]).as_deref(),
            Some("42")
        );
    }

    #[test]
    fn a_forged_payload_is_rejected() {
        let token = sign_token("cursor:list:tools", "42", &["tools-v1"]);
        // The attacker keeps the real tag but bumps the offset to read past the
        // page boundary they were handed.
        let forged = token.replacen("42.", "9999.", 1);
        assert!(verify_token("cursor:list:tools", &forged, &["tools-v1"]).is_none());
    }

    #[test]
    fn a_token_bound_to_a_different_context_is_rejected() {
        // E3 shape: an export id bound to profile PROD must not verify when the
        // session is on profile DEV.
        let token = sign_token("export", "exp-abc", &["PROD"]);
        assert!(verify_token("export", &token, &["DEV"]).is_none());
        assert_eq!(
            verify_token("export", &token, &["PROD"]).as_deref(),
            Some("exp-abc")
        );
    }

    #[test]
    fn a_token_from_a_different_scope_is_rejected() {
        let token = sign_token("cursor:list:tools", "1", &["tools-v1"]);
        // Same payload + same fields but a different scope (a cross-endpoint
        // replay) must not verify.
        assert!(verify_token("cursor:list:resources", &token, &["tools-v1"]).is_none());
    }

    #[test]
    fn malformed_tokens_fail_closed() {
        assert!(verify_token("cursor", "no-tag", &[]).is_none());
        assert!(verify_token("cursor", "body.", &[]).is_none());
        assert!(verify_token("cursor", "body.zz", &[]).is_none());
        assert!(verify_token("cursor", "body.deadbeef", &[]).is_none());
        // A tag of the right length but not real hex-from-MAC fails.
        assert!(verify_token("cursor", "body.0000000000000000", &[]).is_none());
    }

    #[test]
    fn tags_are_stable_within_a_process() {
        let a = sign_token("scope", "p", &["x", "y"]);
        let b = sign_token("scope", "p", &["x", "y"]);
        assert_eq!(a, b, "same context mints the same token in one process");
    }
}
