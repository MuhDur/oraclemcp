#![no_main]
//! Fuzz the audit-chain verify surface (bead H6 /
//! oraclemcp-eng-program-bp8ia.9.6). An audit JSONL file handed to
//! `verify_reader` / `parse_jsonl` + `verify_records` is an untrusted-input
//! parse surface: operators (and the standalone verifier) run it over files
//! that may be truncated, corrupted, tampered with, or adversarial. Arbitrary
//! bytes must never panic the parser or the chain verifier — every input must
//! come back as a clean `VerifyOutcome` verdict or a structured
//! `JsonlError`/`ParseError`.
//!
//! The target exercises BOTH verify paths against the same bytes: the
//! bounded-memory streaming `verify_reader` and the buffered
//! `parse_jsonl` + `verify_records` pair, which are documented to be
//! behaviourally identical. It does not assert which verdict is produced —
//! that behavior is covered by `oraclemcp-audit`'s own unit tests.
//!
//! Run: `cargo +nightly-2026-05-11 fuzz run chain_verify` (from
//! crates/oraclemcp-audit).

use libfuzzer_sys::fuzz_target;
use oraclemcp_audit::{parse_jsonl, verify_reader, verify_records, SigningKey};

fuzz_target!(|data: &[u8]| {
    // Keep standalone smoke/campaign runs resource-bounded even when a corpus
    // contains a pathological oversized record. Production `verify_reader`
    // has its own line bound; this cap also protects the buffered comparison.
    if data.len() > 1_048_576 {
        return;
    }
    let keys = [
        SigningKey::new("fuzz", b"0123456789abcdef0123456789abcdef".to_vec())
            .expect("fixed fuzz key is valid"),
    ];
    // Streaming path: bounded-memory chain verify straight over the bytes.
    let _ = verify_reader(data, &keys);
    // Buffered path: same behavior contract via parse_jsonl + verify_records.
    if let Ok(body) = std::str::from_utf8(data) {
        if let Ok(records) = parse_jsonl(body) {
            let _ = verify_records(&records, &keys);
        }
    }
});
