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

use std::collections::BTreeSet;
use std::io::{self, BufRead};

use crate::record::{AuditRecord, GENESIS_HASH, SigningKey};

/// Maximum bytes permitted in one JSONL audit record line (excluding the
/// terminating newline).
///
/// Audit records carry only exact/normalized SQL **hashes** plus a fixed
/// redaction marker — never SQL text, bind values, or secrets — so a well-formed
/// record serializes to a few hundred bytes. A line beyond this generous cap is a
/// torn append or an adversarial oversized artifact on an operator-controlled
/// path; the streaming reader refuses it rather than buffering an unbounded line
/// into memory (bead oraclemcp-qa100 .29). 1 MiB leaves ample headroom for future
/// additive fields while keeping per-line memory bounded regardless of file size.
pub const MAX_AUDIT_LINE_LEN: usize = 1 << 20;

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
    /// A retired key id reappeared after a different signing epoch began.
    KeyIdReused(String),
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
            BrokenReason::KeyIdReused(id) => {
                write!(f, "retired audit key_id {id:?} reappears in a later epoch")
            }
        }
    }
}

/// Look up a signing key by id among the supplied keys.
fn key_for<'a>(keys: &'a [SigningKey], key_id: &str) -> Option<&'a SigningKey> {
    keys.iter().find(|k| k.key_id() == key_id)
}

/// Incremental hash-chain verifier: fed records one at a time in order, it
/// reproduces [`verify_records`] exactly while retaining only O(1) state (prior
/// hash + seq, the active key id, and the small set of retired key ids). This is
/// the shared core behind both the slice API and the streaming [`verify_reader`],
/// so a multi-gigabyte audit log verifies without ever materializing every
/// record in memory (bead oraclemcp-qa100 .29).
pub(crate) struct ChainVerifier<'a> {
    keys: &'a [SigningKey],
    prev_hash: String,
    prev_seq: Option<u64>,
    current_key_id: Option<String>,
    retired_key_ids: BTreeSet<String>,
    count: usize,
}

impl<'a> ChainVerifier<'a> {
    pub(crate) fn new(keys: &'a [SigningKey]) -> Self {
        Self {
            keys,
            prev_hash: GENESIS_HASH.to_owned(),
            prev_seq: None,
            current_key_id: None,
            retired_key_ids: BTreeSet::new(),
            count: 0,
        }
    }

    /// Number of records verified so far (== chain length once the stream ends
    /// with no break).
    pub(crate) fn count(&self) -> usize {
        self.count
    }

    /// Verify the next record at `index`. Returns the first [`VerifyOutcome::Broken`]
    /// on failure (leaving state unchanged so the caller stops), or `None` after
    /// advancing the chain state.
    pub(crate) fn observe(&mut self, index: usize, record: &AuditRecord) -> Option<VerifyOutcome> {
        let broken = |reason| {
            Some(VerifyOutcome::Broken {
                seq: record.seq,
                index,
                reason,
            })
        };
        // 1) hash recomputes from content (in-place edit).
        if !record.hash_is_valid() {
            return broken(BrokenReason::HashMismatch);
        }
        // 2) prev_hash links to the previous entry_hash.
        if record.prev_hash != self.prev_hash {
            return broken(BrokenReason::PrevHashMismatch);
        }
        // 3) seq increases by exactly one.
        let expected_seq = self.prev_seq.map_or(1, |s| s + 1);
        if record.seq != expected_seq {
            return broken(BrokenReason::SeqNotMonotonic {
                expected: expected_seq,
                found: record.seq,
            });
        }
        // 4) keyed MAC verifies under the record's key_id.
        let Some(key_id) = record.key_id.as_deref() else {
            return broken(BrokenReason::Unsigned);
        };
        let Some(key) = key_for(self.keys, key_id) else {
            return broken(BrokenReason::UnknownKeyId(key_id.to_owned()));
        };
        if !record.signature_is_valid(key) {
            return broken(BrokenReason::SignatureMismatch);
        }
        if self.current_key_id.as_deref() != Some(key_id) {
            if let Some(previous) = self.current_key_id.take() {
                self.retired_key_ids.insert(previous);
            }
            if self.retired_key_ids.contains(key_id) {
                return broken(BrokenReason::KeyIdReused(key_id.to_owned()));
            }
            self.current_key_id = Some(key_id.to_owned());
        }

        self.prev_hash = record.entry_hash.clone();
        self.prev_seq = Some(record.seq);
        self.count += 1;
        None
    }
}

/// Re-walk an ordered slice of records and verify hash links, monotonic seq,
/// and the keyed MAC under the supplied key set. Returns the first broken link,
/// or [`VerifyOutcome::Ok`].
#[must_use]
pub fn verify_records(records: &[AuditRecord], keys: &[SigningKey]) -> VerifyOutcome {
    let mut verifier = ChainVerifier::new(keys);
    for (index, record) in records.iter().enumerate() {
        if let Some(broken) = verifier.observe(index, record) {
            return broken;
        }
    }
    VerifyOutcome::Ok {
        records: verifier.count(),
    }
}

/// Stream an audit log from any [`BufRead`] source and verify the full chain
/// with **bounded memory** — only O(1) chain state plus one capped line buffer,
/// regardless of total file size (bead oraclemcp-qa100 .29). Behaviourally
/// identical to `parse_jsonl` followed by [`verify_records`]: a malformed or
/// oversized line surfaces as [`JsonlError::Malformed`] with the same one-based
/// physical line semantics, and the verify verdict is the same
/// [`VerifyOutcome`]. An I/O failure mid-stream surfaces as [`JsonlError::Io`].
pub fn verify_reader<R: BufRead>(
    reader: R,
    keys: &[SigningKey],
) -> Result<VerifyOutcome, JsonlError> {
    let mut records = JsonlReader::new(reader);
    let mut verifier = ChainVerifier::new(keys);
    let mut index = 0usize;
    while let Some(record) = records.next_record()? {
        if let Some(broken) = verifier.observe(index, &record) {
            return Ok(broken);
        }
        index += 1;
    }
    Ok(VerifyOutcome::Ok {
        records: verifier.count(),
    })
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

/// A failure while streaming JSONL records from a reader: either an I/O error
/// or a malformed/oversized line. Callers map both to their own fail-closed
/// diagnostics (bead oraclemcp-qa100 .29).
#[derive(Debug)]
pub enum JsonlError {
    /// The underlying reader returned an I/O error.
    Io(io::Error),
    /// A line was not a well-formed JSON record, or exceeded
    /// [`MAX_AUDIT_LINE_LEN`].
    Malformed(ParseError),
}

impl std::fmt::Display for JsonlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JsonlError::Io(e) => write!(f, "audit log read error: {e}"),
            JsonlError::Malformed(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for JsonlError {}

/// A streaming, memory-bounded reader over a newline-delimited audit log.
///
/// Yields one parsed [`AuditRecord`] per non-blank physical line, mirroring
/// [`parse_jsonl`] exactly (blank lines skipped, one-based physical line
/// numbers, trailing-newline tolerance) but reading through a capped buffer so a
/// single line can never grow beyond [`MAX_AUDIT_LINE_LEN`] in memory — an
/// unterminated or oversized line fails closed instead of allocating without
/// bound.
pub(crate) struct JsonlReader<R: BufRead> {
    reader: R,
    line_no: usize,
    line: Vec<u8>,
}

impl<R: BufRead> JsonlReader<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self {
            reader,
            line_no: 0,
            line: Vec::new(),
        }
    }

    /// The next non-blank record, `Ok(None)` at end of input, or an error for a
    /// malformed/oversized line or an I/O failure.
    pub(crate) fn next_record(&mut self) -> Result<Option<AuditRecord>, JsonlError> {
        loop {
            self.line.clear();
            if !self.read_physical_line()? {
                return Ok(None);
            }
            self.line_no += 1;
            // Mirror `str::lines`: a trailing "\r\n" drops the "\r" too.
            let mut slice: &[u8] = &self.line;
            if slice.last() == Some(&b'\r') {
                slice = &slice[..slice.len() - 1];
            }
            // Blank-line tolerance identical to `parse_jsonl` (which trims a
            // `&str`): a valid-UTF-8 whitespace-only line is skipped but still
            // counted; anything else is handed to the parser.
            if let Ok(text) = std::str::from_utf8(slice)
                && text.trim().is_empty()
            {
                continue;
            }
            let record: AuditRecord = serde_json::from_slice(slice).map_err(|e| {
                JsonlError::Malformed(ParseError {
                    line: self.line_no,
                    message: e.to_string(),
                })
            })?;
            return Ok(Some(record));
        }
    }

    /// Read one physical line (up to and excluding the next `\n`) into
    /// `self.line`, capped at [`MAX_AUDIT_LINE_LEN`]. Returns `Ok(false)` only at
    /// a clean end of input with no pending bytes.
    fn read_physical_line(&mut self) -> Result<bool, JsonlError> {
        let mut saw_bytes = false;
        loop {
            let available = match self.reader.fill_buf() {
                Ok(buf) => buf,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(JsonlError::Io(e)),
            };
            if available.is_empty() {
                return Ok(saw_bytes);
            }
            saw_bytes = true;
            let (chunk, found_newline) = match available.iter().position(|&b| b == b'\n') {
                Some(newline) => (&available[..newline], true),
                None => (available, false),
            };
            // Cap before buffering so an unterminated/oversized line can never
            // exhaust memory. Direct field access (not a `&mut self` method)
            // keeps `self.line` and the `self.reader` borrow disjoint.
            if self.line.len() + chunk.len() > MAX_AUDIT_LINE_LEN {
                return Err(JsonlError::Malformed(ParseError {
                    line: self.line_no + 1,
                    message: format!(
                        "audit record line exceeds the {MAX_AUDIT_LINE_LEN}-byte maximum"
                    ),
                }));
            }
            self.line.extend_from_slice(chunk);
            let consume = chunk.len() + usize::from(found_newline);
            self.reader.consume(consume);
            if found_newline {
                return Ok(true);
            }
        }
    }
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
    use crate::record::{
        AuditDecision, AuditEntryDraft, AuditOutcome, AuditSubject, compute_entry_hash_v1,
    };
    use crate::sink::{Auditor, MemoryAuditSink};
    use std::sync::Arc;

    fn key() -> SigningKey {
        SigningKey::new("k1", b"0123456789abcdef0123456789abcdef".to_vec()).expect("valid test key")
    }

    fn draft(sql: &str) -> AuditEntryDraft {
        AuditEntryDraft {
            subject: AuditSubject::new("agent", "agent"),
            db_evidence: None,
            cancel: None,
            result_masking: None,
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
        // Forge record 2: replace the exact/normalized SQL hashes and recompute
        // its entry_hash so the bare hash chain would pass, exactly as an
        // attacker with the file but not the key would. The v6 preview remains
        // the fixed redaction marker.
        let mut records = signed_chain(3);
        let forged = AuditRecord::chained_unsigned(
            &draft("SELECT 1"),
            records[1].seq,
            &records[1].prev_hash,
            records[1].timestamp.clone(),
        );
        records[1].sql_sha256 = forged.sql_sha256.clone();
        records[1].sql_normalized_sha256 = forged.sql_normalized_sha256.clone();
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
        let attacker = SigningKey::new("k1", b"fedcba9876543210fedcba9876543210".to_vec())
            .expect("valid test key");
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
        let other = SigningKey::new("k2", b"0123456789abcdef0123456789abcdef".to_vec())
            .expect("valid test key");
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
    fn legacy_v1_signed_record_still_verifies() {
        let sql = "DELETE FROM t WHERE id=1";
        let sql_sha256 = crate::sha256_hex(sql.as_bytes());
        let sql_preview = sql.to_owned();
        let entry_hash = compute_entry_hash_v1(
            1,
            "t1",
            "agent",
            "oracle_execute",
            &sql_sha256,
            &sql_preview,
            "GUARDED",
            AuditDecision::Allowed,
            None,
            AuditOutcome::Pending,
            GENESIS_HASH,
        );
        let legacy = AuditRecord {
            schema_version: 1,
            seq: 1,
            timestamp: "t1".to_owned(),
            agent_identity: "agent".to_owned(),
            subject: AuditSubject::default(),
            db_evidence: None,
            cancel: None,
            correlation: None,
            result_masking: None,
            observed_scn: None,
            verdict_certificate_core_hash: None,
            tool: "oracle_execute".to_owned(),
            sql_sha256,
            sql_normalized_sha256: String::new(),
            sql_preview,
            danger_level: "GUARDED".to_owned(),
            decision: AuditDecision::Allowed,
            rows_affected: None,
            outcome: AuditOutcome::Pending,
            prev_hash: GENESIS_HASH.to_owned(),
            entry_hash: entry_hash.clone(),
            key_id: Some("k1".to_owned()),
            signature: Some(key().sign(&entry_hash)),
        };
        assert_eq!(
            verify_records(&[legacy], &[key()]),
            VerifyOutcome::Ok { records: 1 }
        );
    }

    #[test]
    fn rotated_keys_verify_end_to_end() {
        // Records 1..2 under k1, record 3 under k2 (simulated by signing a
        // tail record with a second key). Both keys supplied -> Ok.
        let k1 = key();
        let k2 = SigningKey::new("k2", b"abcdef0123456789abcdef0123456789".to_vec())
            .expect("valid test key");
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

    #[test]
    fn retired_key_id_cannot_reappear_after_rotation() {
        let k1 = key();
        let k2 = SigningKey::new("k2", vec![0x72; 32]).expect("k2");
        let first = AuditRecord::chained_signed(
            &draft("DELETE FROM t WHERE id=1"),
            1,
            GENESIS_HASH,
            "t1".to_owned(),
            &k1,
        );
        let second = AuditRecord::chained_signed(
            &draft("DELETE FROM t WHERE id=2"),
            2,
            &first.entry_hash,
            "t2".to_owned(),
            &k2,
        );
        let rollback = AuditRecord::chained_signed(
            &draft("DELETE FROM t WHERE id=3"),
            3,
            &second.entry_hash,
            "t3".to_owned(),
            &k1,
        );
        assert_eq!(
            verify_records(&[first, second, rollback], &[k1, k2]),
            VerifyOutcome::Broken {
                seq: 3,
                index: 2,
                reason: BrokenReason::KeyIdReused("k1".to_owned()),
            }
        );
    }

    #[test]
    fn broken_reason_display_names_each_integrity_failure() {
        let cases = [
            (BrokenReason::HashMismatch.to_string(), "entry_hash"),
            (BrokenReason::PrevHashMismatch.to_string(), "prev_hash"),
            (
                BrokenReason::SeqNotMonotonic {
                    expected: 2,
                    found: 4,
                }
                .to_string(),
                "expected 2, found 4",
            ),
            (BrokenReason::Unsigned.to_string(), "no keyed MAC"),
            (
                BrokenReason::UnknownKeyId("k9".to_owned()).to_string(),
                "unknown key_id",
            ),
            (
                BrokenReason::SignatureMismatch.to_string(),
                "keyed MAC does not verify",
            ),
            (
                BrokenReason::KeyIdReused("k1".to_owned()).to_string(),
                "reappears",
            ),
        ];
        for (msg, needle) in cases {
            assert!(msg.contains(needle), "{msg}");
        }
    }

    #[test]
    fn parse_jsonl_reports_one_based_line_numbers_and_message() {
        let records = signed_chain(1);
        let good = serde_json::to_string(&records[0]).expect("serialize");
        let body = format!("\n{good}\n{{bad json}}\n");
        let err = parse_jsonl(&body).expect_err("third physical line is malformed");
        assert_eq!(err.line, 3);
        assert!(err.message.contains("key must be a string"), "{err:?}");
        let msg = err.to_string();
        assert!(msg.contains("line 3"), "{msg}");
        assert!(msg.contains(&err.message), "{msg}");
    }

    #[test]
    fn read_physical_line_advances_between_records_without_silently_skipping_bytes() {
        let records = signed_chain(2);
        let first = serde_json::to_string(&records[0]).expect("serialize first");
        let second = serde_json::to_string(&records[1]).expect("serialize second");
        let body = format!("{first}\n{second}\n");
        let mut reader = JsonlReader::new(io::BufReader::new(io::Cursor::new(&body)));

        assert!(reader.read_physical_line().expect("first raw line"));
        assert_eq!(reader.line, first.as_bytes());
        reader.line.clear();
        assert!(reader.read_physical_line().expect("second raw line"));
        assert_eq!(reader.line, second.as_bytes());
        assert!(!reader.read_physical_line().expect("eof"));
    }

    #[test]
    fn read_physical_line_rejects_truncated_or_malformed_lines_with_precise_offsets() {
        let good = serde_json::to_string(&signed_chain(1)[0]).expect("serialize");
        let malformed = format!("{good}\n{{bad-json}}\n");
        let mut malformed_reader =
            JsonlReader::new(io::BufReader::new(io::Cursor::new(&malformed)));
        assert!(
            malformed_reader
                .next_record()
                .expect("first record")
                .expect("first record")
                .seq
                > 0
        );
        match malformed_reader.next_record() {
            Err(JsonlError::Malformed(e)) => {
                assert_eq!(e.line, 2);
                assert!(e.message.contains("key must be a string"), "{e:?}");
            }
            other => panic!("malformed line must be rejected, got {other:?}"),
        }

        let truncated = format!("{good}\n{{\"seq\":");
        let mut truncated_reader =
            JsonlReader::new(io::BufReader::new(io::Cursor::new(&truncated)));
        assert!(
            truncated_reader
                .next_record()
                .expect("first record")
                .expect("first record")
                .seq
                > 0
        );
        match truncated_reader.next_record() {
            Err(JsonlError::Malformed(e)) => assert_eq!(e.line, 2),
            other => panic!("torn line must be rejected, got {other:?}"),
        }
    }

    #[test]
    fn read_physical_line_rejects_oversized_lines_without_unbounded_allocation() {
        let mut oversized_reader = JsonlReader::new(io::BufReader::new(InfiniteByte(b'a')));
        match oversized_reader.read_physical_line() {
            Err(JsonlError::Malformed(e)) => {
                assert_eq!(e.line, 1);
                assert!(e.message.contains("exceeds"), "{e}");
            }
            other => panic!("oversized line must be rejected, got {other:?}"),
        }

        let mut over_limit = String::with_capacity(MAX_AUDIT_LINE_LEN + 2);
        over_limit.push_str(&"a".repeat(MAX_AUDIT_LINE_LEN + 1));
        over_limit.push('\n');
        let mut reader = JsonlReader::new(io::BufReader::new(io::Cursor::new(over_limit)));
        match reader.read_physical_line() {
            Err(JsonlError::Malformed(_)) => {}
            other => panic!("bounded capped read must reject over-limit lines, got {other:?}"),
        }
    }

    // --- Streaming verification (bead oraclemcp-qa100 .29) ---

    fn body_of(records: &[AuditRecord]) -> String {
        records
            .iter()
            .map(|r| serde_json::to_string(r).expect("serialize") + "\n")
            .collect()
    }

    #[test]
    fn verify_reader_matches_the_slice_api_on_a_good_chain() {
        let records = signed_chain(5);
        let body = body_of(&records);
        assert_eq!(
            verify_reader(io::Cursor::new(&body), &[key()]).expect("no io/parse error"),
            VerifyOutcome::Ok { records: 5 }
        );
        // Blank-line and trailing-newline tolerance identical to parse_jsonl.
        let padded = format!("\n{body}\n");
        assert_eq!(
            verify_reader(io::Cursor::new(padded), &[key()]).expect("tolerant"),
            VerifyOutcome::Ok { records: 5 }
        );
    }

    #[test]
    fn verify_reader_preserves_first_error_line_and_seq_semantics() {
        // Every tamper/torn case reports the same first seq/line the whole-file
        // parse_jsonl + verify_records path did.
        let base = signed_chain(4);

        // In-place edit at seq 2 (hash mismatch).
        let mut edited = base.clone();
        edited[1].sql_preview = "SELECT 1".to_owned();
        match verify_reader(io::Cursor::new(body_of(&edited)), &[key()]).expect("stream") {
            VerifyOutcome::Broken { seq, index, reason } => {
                assert_eq!((seq, index, reason), (2, 1, BrokenReason::HashMismatch));
            }
            other => panic!("expected hash mismatch, got {other:?}"),
        }

        // Prev-hash break: drop the middle record (surviving tail relinks wrong).
        let deleted = format!(
            "{}\n{}\n",
            serde_json::to_string(&base[0]).unwrap(),
            serde_json::to_string(&base[2]).unwrap()
        );
        match verify_reader(io::Cursor::new(deleted), &[key()]).expect("stream") {
            VerifyOutcome::Broken { seq, reason, .. } => {
                assert_eq!((seq, reason), (3, BrokenReason::PrevHashMismatch));
            }
            other => panic!("expected prev-hash break, got {other:?}"),
        }

        // Unknown key id: verify with the wrong keyring.
        let other_key = SigningKey::new("k2", vec![0x5a; 32]).expect("k2");
        match verify_reader(io::Cursor::new(body_of(&base)), &[other_key]).expect("stream") {
            VerifyOutcome::Broken { seq, reason, .. } => {
                assert_eq!(
                    (seq, reason),
                    (1, BrokenReason::UnknownKeyId("k1".to_owned()))
                );
            }
            other => panic!("expected unknown key id, got {other:?}"),
        }

        // Malformed / torn tail: last line is partial JSON.
        let torn = format!("{}{{\"seq\":2,\"partial\":", body_of(&base[..1]));
        match verify_reader(io::Cursor::new(torn), &[key()]) {
            Err(JsonlError::Malformed(e)) => assert_eq!(e.line, 2),
            other => panic!("expected malformed line 2, got {other:?}"),
        }
    }

    /// A reader that yields `byte` forever and never a newline — models an
    /// unterminated/adversarial oversized line.
    struct InfiniteByte(u8);
    impl io::Read for InfiniteByte {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            buf.fill(self.0);
            Ok(buf.len())
        }
    }

    #[test]
    fn verify_reader_caps_an_oversized_line_with_bounded_memory() {
        // An unterminated line must fail closed at MAX_AUDIT_LINE_LEN rather than
        // buffer without bound. If the cap did not hold this would allocate
        // forever; instead it returns promptly with a Malformed(oversized) error.
        let reader = io::BufReader::new(InfiniteByte(b'a'));
        match verify_reader(reader, &[key()]) {
            Err(JsonlError::Malformed(e)) => {
                assert_eq!(e.line, 1);
                assert!(
                    e.message.contains("exceeds") && e.message.contains("maximum"),
                    "{e}"
                );
            }
            other => panic!("expected oversized-line refusal, got {other:?}"),
        }
        // A record padded to just over the cap is also refused.
        let mut giant = String::with_capacity(MAX_AUDIT_LINE_LEN + 16);
        giant.push_str(&"a".repeat(MAX_AUDIT_LINE_LEN + 1));
        giant.push('\n');
        match verify_reader(io::Cursor::new(giant), &[key()]) {
            Err(JsonlError::Malformed(_)) => {}
            other => panic!("expected oversized refusal, got {other:?}"),
        }
    }

    #[test]
    fn verify_reader_streams_a_large_chain_without_retaining_records() {
        // A large log verifies through the fixed-size line buffer. The chain is
        // long enough that a whole-file Vec of records would dwarf the reader's
        // O(1) working set — the point of the streaming path.
        let records = signed_chain(20_000);
        let body = body_of(&records);
        assert!(
            body.len() > 1_000_000,
            "fixture exercises a multi-block file"
        );
        assert_eq!(
            verify_reader(io::Cursor::new(&body), &[key()]).expect("stream large"),
            VerifyOutcome::Ok { records: 20_000 }
        );
        // A single tampered record deep in the large log is still caught.
        let mut tampered = records;
        tampered[12_345].sql_preview = "SELECT 1".to_owned();
        match verify_reader(io::Cursor::new(body_of(&tampered)), &[key()]).expect("stream") {
            VerifyOutcome::Broken { seq, .. } => assert_eq!(seq, 12_346),
            other => panic!("expected a broken record deep in the log, got {other:?}"),
        }
    }

    // === GATE-SEAL residue kills ===

    // L275: `JsonlError`'s `Display` must render its message; the FnValue
    // `Ok(Default::default())` mutant would print nothing.
    #[test]
    fn residue_jsonl_error_display_renders_message() {
        let e = JsonlError::Io(io::Error::other("diskfail"));
        assert!(
            e.to_string().contains("audit log read error"),
            "Display must render the error, got {:?}",
            e.to_string()
        );
    }

    // A `BufRead` that returns one error from `fill_buf`, then clean EOF. Lets the
    // Interrupted-retry branch be exercised deterministically without hanging.
    struct ErrThenEof {
        kind: io::ErrorKind,
        fired: bool,
    }
    impl io::Read for ErrThenEof {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }
    impl io::BufRead for ErrThenEof {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            if self.fired {
                Ok(&[])
            } else {
                self.fired = true;
                Err(io::Error::from(self.kind))
            }
        }
        fn consume(&mut self, _amt: usize) {}
    }

    // L347 (guard `== Interrupted` -> `true`, and `==` -> `!=`): a NON-interrupted
    // read error must surface as an I/O error, never be retried into a clean EOF.
    #[test]
    fn residue_read_physical_line_propagates_non_interrupted_io_error() {
        let mut reader = JsonlReader::new(ErrThenEof {
            kind: io::ErrorKind::Other,
            fired: false,
        });
        assert!(
            matches!(reader.next_record(), Err(JsonlError::Io(_))),
            "a non-interrupted read error must fail closed, not retry to EOF"
        );
    }

    // L347 (guard `== Interrupted` -> `false`, and `==` -> `!=`): an Interrupted
    // read error must be retried (transparently), yielding a clean EOF here.
    #[test]
    fn residue_read_physical_line_retries_interrupted_io_error() {
        let mut reader = JsonlReader::new(ErrThenEof {
            kind: io::ErrorKind::Interrupted,
            fired: false,
        });
        assert!(
            matches!(reader.next_record(), Ok(None)),
            "an EINTR must be retried and then reach a clean end of input"
        );
    }

    // L319 (`slice.len() - 1` -> `+ 1`): a CRLF line drops the trailing '\r'; the
    // `+ 1` mutant would index one past the slice and panic.
    #[test]
    fn residue_next_record_handles_crlf_line_ending() {
        let rec = &signed_chain(1)[0];
        let mut data = serde_json::to_string(rec).expect("serialize");
        data.push_str("\r\n");
        let mut reader = JsonlReader::new(io::Cursor::new(data.into_bytes()));
        let got = reader
            .next_record()
            .expect("a CRLF-terminated record parses")
            .expect("some record");
        assert_eq!(
            got.seq, rec.seq,
            "the CR must be stripped and the record parsed"
        );
    }

    // L361 (`>` -> `==`, and `+` -> `*`): a single oversized chunk (delivered
    // whole by `Cursor`, so `self.line.len()` is 0 at the check) must be capped
    // with the size-limit error. `==` never matches `MAX + 5`; `*` yields `0`.
    #[test]
    fn residue_read_physical_line_caps_a_single_oversized_chunk() {
        let mut data = "a".repeat(MAX_AUDIT_LINE_LEN + 5);
        data.push('\n');
        let mut reader = JsonlReader::new(io::Cursor::new(data.into_bytes()));
        match reader.next_record() {
            Err(JsonlError::Malformed(e)) => assert!(
                e.message.contains("exceeds"),
                "an oversized single chunk must be capped by the size limit, got {e}"
            ),
            other => panic!("expected an oversized-line size error, got {other:?}"),
        }
    }

    // L361 (`>` -> `>=`): a line of EXACTLY MAX bytes is within the limit and must
    // parse; the `>=` mutant would reject it at the boundary.
    #[test]
    fn residue_read_physical_line_accepts_a_line_exactly_at_the_limit() {
        let rec = &signed_chain(1)[0];
        let json = serde_json::to_string(rec).expect("serialize");
        assert!(
            json.len() < MAX_AUDIT_LINE_LEN,
            "fixture fits under the cap"
        );
        // Leading whitespace (serde-insignificant) pads the line to exactly MAX
        // bytes without changing the parsed record.
        let mut line = " ".repeat(MAX_AUDIT_LINE_LEN - json.len());
        line.push_str(&json);
        assert_eq!(line.len(), MAX_AUDIT_LINE_LEN, "line is exactly at the cap");
        line.push('\n');
        let mut reader = JsonlReader::new(io::Cursor::new(line.into_bytes()));
        let got = reader
            .next_record()
            .expect("a line exactly at the cap is within the limit")
            .expect("some record");
        assert_eq!(got.seq, rec.seq);
    }
}
