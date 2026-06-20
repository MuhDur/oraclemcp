//! Tamper-evidence verification for a persisted audit chain (plan §5.13, §6.4;
//! bead A8 deliverable (c)).
//!
//! Verification re-walks the JSONL records in order and checks three things per
//! record:
//!  1. the **hash link** — `prev_hash` equals the previous record's
//!     `entry_hash` (genesis for the first), and `entry_hash` recomputes from
//!     the record's content (catches an in-place edit);
//!  2. the **monotonic seq** — `seq` increases by one (catches reorder /
//!     insert / delete);
//!  3. the **keyed MAC** — `signature` verifies under the key named by
//!     `key_id` (catches a recompute-from-genesis forgery by an actor without
//!     the key).
//!
//! Multiple keys may be supplied so a rotated chain (old records under an old
//! `key_id`, new under a new one) verifies end to end.

use crate::record::{AuditRecord, GENESIS_HASH, SigningKey};

/// The result of verifying a chain: OK, or the first broken link with a reason.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyOutcome {
    /// Every record's hash link, sequence, and keyed MAC verified.
    Ok {
        /// Number of records walked.
        records: usize,
    },
    /// A record failed verification; `seq` is its sequence number and `reason`
    /// describes the first failing check.
    Broken {
        /// The sequence number of the offending record.
        seq: u64,
        /// Zero-based index of the offending record in the file.
        index: usize,
        /// Why verification failed.
        reason: BrokenReason,
    },
}

/// Why a chain failed verification.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BrokenReason {
    /// `entry_hash` does not recompute from the record content (in-place edit).
    HashMismatch,
    /// `prev_hash` does not match the previous record's `entry_hash`.
    PrevHashMismatch,
    /// `seq` did not increase by exactly one from the previous record.
    SeqNotMonotonic {
        /// The seq we expected.
        expected: u64,
        /// The seq we found.
        found: u64,
    },
    /// The record carried no `signature`/`key_id` (unsigned).
    Unsigned,
    /// The record names a `key_id` not in the supplied key set.
    UnknownKeyId(String),
    /// The keyed MAC did not verify — a recompute-from-genesis forgery, or a
    /// wrong key.
    SignatureMismatch,
}

impl std::fmt::Display for BrokenReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrokenReason::HashMismatch => {
                f.write_str("entry_hash does not match the record content (in-place edit)")
            }
            BrokenReason::PrevHashMismatch => {
                f.write_str("prev_hash does not link to the previous record's entry_hash")
            }
            BrokenReason::SeqNotMonotonic { expected, found } => {
                write!(
                    f,
                    "seq is not monotonic (expected {expected}, found {found})"
                )
            }
            BrokenReason::Unsigned => f.write_str("record carries no keyed MAC (unsigned)"),
            BrokenReason::UnknownKeyId(id) => {
                write!(f, "record names unknown key_id {id:?}")
            }
            BrokenReason::SignatureMismatch => f.write_str(
                "keyed MAC does not verify (recompute-from-genesis forgery or wrong key)",
            ),
        }
    }
}

/// Look up a signing key by id among the supplied keys.
fn key_for<'a>(keys: &'a [SigningKey], key_id: &str) -> Option<&'a SigningKey> {
    keys.iter().find(|k| k.key_id() == key_id)
}

/// Re-walk an ordered slice of records and verify hash links, monotonic seq,
/// and the keyed MAC under the supplied key set. Returns the first broken link,
/// or [`VerifyOutcome::Ok`].
#[must_use]
pub fn verify_records(records: &[AuditRecord], keys: &[SigningKey]) -> VerifyOutcome {
    let mut prev_hash = GENESIS_HASH.to_owned();
    let mut prev_seq: Option<u64> = None;
    for (index, record) in records.iter().enumerate() {
        // 1) hash recomputes from content (in-place edit).
        if !record.hash_is_valid() {
            return VerifyOutcome::Broken {
                seq: record.seq,
                index,
                reason: BrokenReason::HashMismatch,
            };
        }
        // 2) prev_hash links to the previous entry_hash.
        if record.prev_hash != prev_hash {
            return VerifyOutcome::Broken {
                seq: record.seq,
                index,
                reason: BrokenReason::PrevHashMismatch,
            };
        }
        // 3) seq increases by exactly one.
        let expected_seq = prev_seq.map_or(1, |s| s + 1);
        if record.seq != expected_seq {
            return VerifyOutcome::Broken {
                seq: record.seq,
                index,
                reason: BrokenReason::SeqNotMonotonic {
                    expected: expected_seq,
                    found: record.seq,
                },
            };
        }
        // 4) keyed MAC verifies under the record's key_id.
        let Some(key_id) = record.key_id.as_deref() else {
            return VerifyOutcome::Broken {
                seq: record.seq,
                index,
                reason: BrokenReason::Unsigned,
            };
        };
        let Some(key) = key_for(keys, key_id) else {
            return VerifyOutcome::Broken {
                seq: record.seq,
                index,
                reason: BrokenReason::UnknownKeyId(key_id.to_owned()),
            };
        };
        if !record.signature_is_valid(key) {
            return VerifyOutcome::Broken {
                seq: record.seq,
                index,
                reason: BrokenReason::SignatureMismatch,
            };
        }

        prev_hash = record.entry_hash.clone();
        prev_seq = Some(record.seq);
    }
    VerifyOutcome::Ok {
        records: records.len(),
    }
}

/// Parse a JSONL audit file body into records, surfacing the first malformed
/// line. Blank lines are skipped (trailing newline tolerance).
pub fn parse_jsonl(body: &str) -> Result<Vec<AuditRecord>, ParseError> {
    let mut records = Vec::new();
    for (line_no, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: AuditRecord = serde_json::from_str(line).map_err(|e| ParseError {
            line: line_no + 1,
            message: e.to_string(),
        })?;
        records.push(record);
    }
    Ok(records)
}

/// A malformed JSONL line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// One-based line number of the malformed record.
    pub line: usize,
    /// The serde error message.
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "malformed audit record at line {}: {}",
            self.line, self.message
        )
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{AuditDecision, AuditEntryDraft, AuditOutcome};
    use crate::sink::{Auditor, MemoryAuditSink};
    use std::sync::Arc;

    fn key() -> SigningKey {
        SigningKey::new("k1", b"verify-test-key".to_vec())
    }

    fn draft(sql: &str) -> AuditEntryDraft {
        AuditEntryDraft {
            agent_identity: "agent".to_owned(),
            tool: "oracle_execute".to_owned(),
            sql: sql.to_owned(),
            danger_level: "GUARDED".to_owned(),
            decision: AuditDecision::Allowed,
            rows_affected: None,
            outcome: AuditOutcome::Pending,
        }
    }

    struct Shared(Arc<MemoryAuditSink>);
    impl crate::sink::AuditSink for Shared {
        fn append(&self, r: &AuditRecord) -> Result<(), crate::sink::AuditError> {
            self.0.append(r)
        }
        fn flush(&self) -> Result<(), crate::sink::AuditError> {
            self.0.flush()
        }
    }

    fn signed_chain(n: usize) -> Vec<AuditRecord> {
        let sink = Arc::new(MemoryAuditSink::new());
        let auditor = Auditor::new(Box::new(Shared(sink.clone())), key());
        for i in 0..n {
            auditor
                .append(
                    &draft(&format!("DELETE FROM t WHERE id={i}")),
                    format!("t{i}"),
                    true,
                )
                .expect("append");
        }
        sink.records()
    }

    #[test]
    fn good_chain_verifies() {
        let records = signed_chain(3);
        assert_eq!(
            verify_records(&records, &[key()]),
            VerifyOutcome::Ok { records: 3 }
        );
    }

    #[test]
    fn in_place_edit_is_detected() {
        let mut records = signed_chain(3);
        records[1].sql_preview = "SELECT 1".to_owned(); // edit content, leave hash
        match verify_records(&records, &[key()]) {
            VerifyOutcome::Broken { seq, reason, .. } => {
                assert_eq!(seq, 2);
                assert_eq!(reason, BrokenReason::HashMismatch);
            }
            other => panic!("expected broken, got {other:?}"),
        }
    }

    #[test]
    fn recompute_from_genesis_without_key_is_detected() {
        // Forge record 2: edit the operator-legible preview AND recompute its
        // entry_hash so the bare hash chain would pass, exactly as an attacker
        // with the file but not the key would. (We rebuild a draft with the
        // forged preview as the SQL so sql_sha256/sql_preview both reflect it,
        // then copy the recomputed hash over the real record.)
        let mut records = signed_chain(3);
        let forged = AuditRecord::chained_unsigned(
            &draft("SELECT 1"),
            records[1].seq,
            &records[1].prev_hash,
            records[1].timestamp.clone(),
        );
        records[1].sql_sha256 = forged.sql_sha256.clone();
        records[1].sql_preview = forged.sql_preview.clone();
        records[1].entry_hash = forged.entry_hash.clone();
        // hash_is_valid now passes for record 2, but the MAC was computed over
        // the OLD entry_hash, so the keyed check fails.
        assert!(records[1].hash_is_valid());
        match verify_records(&records, &[key()]) {
            VerifyOutcome::Broken { seq, reason, .. } => {
                assert_eq!(seq, 2);
                assert_eq!(reason, BrokenReason::SignatureMismatch);
            }
            other => panic!("expected broken MAC, got {other:?}"),
        }
    }

    #[test]
    fn wrong_key_fails() {
        let records = signed_chain(2);
        let attacker = SigningKey::new("k1", b"wrong-key".to_vec());
        match verify_records(&records, &[attacker]) {
            VerifyOutcome::Broken { reason, .. } => {
                assert_eq!(reason, BrokenReason::SignatureMismatch);
            }
            other => panic!("expected broken, got {other:?}"),
        }
    }

    #[test]
    fn unknown_key_id_is_reported() {
        let records = signed_chain(1);
        let other = SigningKey::new("k2", b"verify-test-key".to_vec());
        match verify_records(&records, &[other]) {
            VerifyOutcome::Broken { reason, .. } => {
                assert_eq!(reason, BrokenReason::UnknownKeyId("k1".to_owned()));
            }
            other => panic!("expected unknown key id, got {other:?}"),
        }
    }

    #[test]
    fn jsonl_roundtrips_and_verifies() {
        let records = signed_chain(2);
        let body: String = records
            .iter()
            .map(|r| serde_json::to_string(r).expect("serialize") + "\n")
            .collect();
        let parsed = parse_jsonl(&body).expect("parse");
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            verify_records(&parsed, &[key()]),
            VerifyOutcome::Ok { records: 2 }
        );
    }

    #[test]
    fn rotated_keys_verify_end_to_end() {
        // Records 1..2 under k1, record 3 under k2 (simulated by signing a
        // tail record with a second key). Both keys supplied -> Ok.
        let k1 = key();
        let k2 = SigningKey::new("k2", b"rotated-key".to_vec());
        let sink = Arc::new(MemoryAuditSink::new());
        let auditor = Auditor::new(Box::new(Shared(sink.clone())), k1.clone());
        auditor
            .append(&draft("DELETE FROM t WHERE id=1"), "t1".to_owned(), true)
            .unwrap();
        auditor
            .append(&draft("DELETE FROM t WHERE id=2"), "t2".to_owned(), true)
            .unwrap();
        let mut records = sink.records();
        // Append a third record signed by k2, chained off record 2.
        let third = AuditRecord::chained_signed(
            &draft("DELETE FROM t WHERE id=3"),
            3,
            &records[1].entry_hash,
            "t3".to_owned(),
            &k2,
        );
        records.push(third);
        assert_eq!(
            verify_records(&records, &[k1, k2]),
            VerifyOutcome::Ok { records: 3 }
        );
    }
}
