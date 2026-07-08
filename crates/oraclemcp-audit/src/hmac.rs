//! HMAC-SHA256 over the in-tree `sha2` primitive (plan §5.13, §6.4; bead A8).
//!
//! The audit hash chain (`record.rs`) is bare SHA-256 — tamper-*evident* but
//! **forgeable**: an actor with write access to the append-only file can edit a
//! record and recompute the whole chain from genesis, and `hash_is_valid()`
//! will pass. A keyed MAC closes that hole: every record carries an
//! `HMAC-SHA256(key, entry_hash)` that a forger cannot reproduce without the
//! key, so a recompute-from-genesis forgery is detected at verify time.
//!
//! We implement HMAC-SHA256 directly over `sha2` (RFC 2104) rather than adding
//! the RustCrypto `hmac` crate: `sha2` is pinned at 0.11 in this workspace and
//! the matching `hmac`/`digest` 0.13 line is not yet released, so pulling it in
//! would risk a duplicate `digest`/`sha2` version. `forbid(unsafe_code)` is
//! upheld — this is pure safe Rust.

use sha2::{Digest, Sha256};

/// SHA-256 block size in bytes (RFC 2104 `B`).
const BLOCK_LEN: usize = 64;
/// SHA-256 output size in bytes (`L`).
const OUTPUT_LEN: usize = 32;
const HMAC_SHA256_PREFIX: &str = "hmac-sha256:";

/// Compute `HMAC-SHA256(key, message)` and return the 32 raw output bytes.
///
/// RFC 2104: `H((K0 ^ opad) || H((K0 ^ ipad) || message))`, where `K0` is the
/// key padded/condensed to the block length.
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; OUTPUT_LEN] {
    // K0: keys longer than the block are first hashed, then all keys are
    // right-padded with zeros to the block length.
    let mut block = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        let hashed = Sha256::digest(key);
        block[..OUTPUT_LEN].copy_from_slice(&hashed);
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_LEN];
    let mut opad = [0x5cu8; BLOCK_LEN];
    for i in 0..BLOCK_LEN {
        ipad[i] ^= block[i];
        opad[i] ^= block[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let outer_digest = outer.finalize();

    let mut out = [0u8; OUTPUT_LEN];
    out.copy_from_slice(&outer_digest);
    out
}

/// Compute `HMAC-SHA256` and render it as `hmac-sha256:<hex>` for storage in a
/// record's `signature` field. The `hmac-sha256:` prefix names the algorithm
/// so a future MAC upgrade is self-describing rather than ambiguous hex.
#[must_use]
pub fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    let mac = hmac_sha256(key, message);
    let mut out = String::with_capacity(HMAC_SHA256_PREFIX.len() + mac.len() * 2);
    out.push_str(HMAC_SHA256_PREFIX);
    for b in mac {
        push_hex_byte(&mut out, b);
    }
    out
}

/// Verify a stored `hmac-sha256:<lower-hex>` signature without allocating an
/// expected hex string.
#[must_use]
pub fn hmac_sha256_hex_is_valid(key: &[u8], message: &[u8], signature: &str) -> bool {
    let Some(hex) = signature.strip_prefix(HMAC_SHA256_PREFIX) else {
        return false;
    };
    if hex.len() != OUTPUT_LEN * 2 {
        return false;
    }

    let mut actual = [0_u8; OUTPUT_LEN];
    let bytes = hex.as_bytes();
    for i in 0..OUTPUT_LEN {
        let Some(hi) = decode_lower_hex_nibble(bytes[i * 2]) else {
            return false;
        };
        let Some(lo) = decode_lower_hex_nibble(bytes[i * 2 + 1]) else {
            return false;
        };
        actual[i] = (hi << 4) | lo;
    }

    let expected = hmac_sha256(key, message);
    ct_eq(&expected, &actual)
}

fn push_hex_byte(out: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
}

fn decode_lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Constant-time comparison of two byte slices (no early-out on first
/// mismatch), used when verifying a stored MAC against a recomputed one.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
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

    /// RFC 4231 Test Case 2: key="Jefe", data="what do ya want for nothing?".
    /// Known-answer test pins our HMAC-SHA256 to the standard.
    #[test]
    fn rfc4231_test_case_2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let expected =
            hex_to_bytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert_eq!(mac.as_slice(), expected.as_slice());
    }

    /// RFC 4231 Test Case 1: 20 bytes of 0x0b, data="Hi There".
    #[test]
    fn rfc4231_test_case_1() {
        let key = [0x0bu8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        let expected =
            hex_to_bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(mac.as_slice(), expected.as_slice());
    }

    /// A key longer than the 64-byte block must be hashed down first (RFC 4231
    /// Test Case 6 uses a 131-byte key).
    #[test]
    fn long_key_is_condensed() {
        let key = [0xaau8; 131];
        let mac = hmac_sha256(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        let expected =
            hex_to_bytes("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
        assert_eq!(mac.as_slice(), expected.as_slice());
    }

    #[test]
    fn exact_block_sized_key_is_not_condensed() {
        // RFC 2104 condenses only keys longer than the block. A 64-byte key is
        // used directly; hashing it first produces a different MAC.
        let key = [0xabu8; BLOCK_LEN];
        let msg = b"exact block length key";
        let actual = hmac_sha256(&key, msg);

        let hashed_key = Sha256::digest(key);
        let condensed = hmac_sha256(&hashed_key, msg);
        assert_ne!(
            actual, condensed,
            "a key exactly one SHA-256 block long must not be pre-hashed"
        );
    }

    #[test]
    fn hex_render_has_algorithm_prefix() {
        let s = hmac_sha256_hex(b"k", b"m");
        assert!(s.starts_with("hmac-sha256:"));
        assert_eq!(s.len(), HMAC_SHA256_PREFIX.len() + 64);
    }

    #[test]
    fn hex_verify_accepts_exact_canonical_signature() {
        let s = hmac_sha256_hex(b"k", b"m");
        assert!(hmac_sha256_hex_is_valid(b"k", b"m", &s));
    }

    #[test]
    fn hex_verify_rejects_malformed_or_noncanonical_signature() {
        let s = hmac_sha256_hex(b"k", b"m");
        assert!(!hmac_sha256_hex_is_valid(b"k2", b"m", &s));
        assert!(!hmac_sha256_hex_is_valid(b"k", b"m2", &s));
        assert!(!hmac_sha256_hex_is_valid(b"k", b"m", "sha256:abcd"));
        assert!(!hmac_sha256_hex_is_valid(b"k", b"m", "hmac-sha256:abcd"));
        assert!(!hmac_sha256_hex_is_valid(
            b"k",
            b"m",
            &s.to_ascii_uppercase()
        ));
    }

    #[test]
    fn ct_eq_matches_and_rejects() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
            .collect()
    }
}
