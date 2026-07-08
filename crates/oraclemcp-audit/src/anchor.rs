//! Head anchor: fail-closed tail-truncation detection for the audit chain
//! (bead oraclemcp-xb51).
//!
//! A prefix of a valid hash chain is itself a valid chain, so `verify_records`
//! alone cannot tell "the file is complete" from "the last N records were
//! deleted". The head anchor closes that gap **additively** — the JSONL record
//! format is untouched. A sidecar file (`<audit path>.anchor`, one JSON object)
//! attests the durable head of the chain: the last durably-fsynced record's
//! `seq` + `entry_hash`, bound by a domain-separated keyed MAC that a tamperer
//! without the signing key cannot recompute for a shorter chain.
//!
//! # Crash-consistency semantics (never anchor-ahead)
//!
//! The writer ([`crate::Auditor`]) orders every update as: **record fsync
//! FIRST, anchor update SECOND**. The anchor itself is replaced atomically
//! (write `<anchor>.tmp`, fsync it, `rename` over the anchor), so a reader
//! never observes a partial anchor. Consequences:
//!
//! - **Anchor behind the chain head** is an *explainable* state, not tamper
//!   evidence: a crash in the window between the record fsync and the anchor
//!   rename leaves the anchor one record behind, and non-durable (group-commit
//!   read) appends legitimately run ahead of the anchor until the next durable
//!   append or flush. Verification accepts it, provided the chain still passes
//!   through the anchored record.
//! - **Anchor ahead of the chain** can never be produced by a crash — the
//!   anchored record was durable before the anchor named it. A chain that ends
//!   *before* the anchor therefore means trailing records were removed:
//!   verification fails closed as **truncated**.
//! - The rename itself is *not* followed by a directory fsync: if the rename
//!   does not survive a crash the anchor is merely behind (explainable, above);
//!   durability of the anchor is not needed for the never-anchor-ahead
//!   invariant.
//!
//! # Residual limitations (documented, mitigated by shipping)
//!
//! An attacker who holds the signing key, or who replays an *old* anchor file
//! snapshotted together with the matching chain prefix (full-state rollback),
//! is not detectable locally — the same boundary the keyed MAC has always had.
//! The independent WORM/SIEM copy (`[audit.shipping]`, ADR 0003) remains the
//! mitigation for those. Likewise a log with **no** anchor sidecar (legacy log,
//! or the anchor deleted along with the tail) verifies with an explicit
//! advisory rather than failing, because pre-anchor logs are indistinguishable;
//! operators should treat an unexpectedly missing anchor as suspicious.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::hmac::ct_eq;
use crate::record::{AuditRecord, SigningKey};
use crate::sink::AuditError;

/// Current anchor document version.
pub const ANCHOR_VERSION: u16 = 1;

/// Domain-separation prefix for the anchor MAC. Distinct from the record
/// signature domain (which MACs a bare `sha256:<hex>` entry hash), so a record
/// signature can never be replayed as an anchor MAC or vice versa.
const ANCHOR_MAC_DOMAIN: &str = "oraclemcp-audit-anchor-v1";

/// The persisted head anchor: the durable head of the audit chain, keyed-MAC
/// bound so it cannot be rewritten to point at a truncated head without the
/// signing key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainAnchor {
    /// Anchor document version (additive evolution).
    pub anchor_version: u16,
    /// `seq` of the last durably-fsynced record.
    pub seq: u64,
    /// `entry_hash` of that record.
    pub entry_hash: String,
    /// The signing key id the MAC was computed under (rotation-aware).
    pub key_id: String,
    /// `hmac-sha256:<hex>` over the domain-separated `seq` + `entry_hash`.
    pub mac: String,
}

impl ChainAnchor {
    /// Build a MAC-signed anchor for the given chain head.
    #[must_use]
    pub fn signed(seq: u64, entry_hash: &str, key: &SigningKey) -> Self {
        ChainAnchor {
            anchor_version: ANCHOR_VERSION,
            seq,
            entry_hash: entry_hash.to_owned(),
            key_id: key.key_id().to_owned(),
            mac: key.sign(&mac_preimage(seq, entry_hash)),
        }
    }

    /// Whether the stored MAC verifies under `key` (constant-time compare).
    #[must_use]
    pub fn mac_is_valid(&self, key: &SigningKey) -> bool {
        let expected = key.sign(&mac_preimage(self.seq, &self.entry_hash));
        ct_eq(expected.as_bytes(), self.mac.as_bytes())
    }
}

fn mac_preimage(seq: u64, entry_hash: &str) -> String {
    format!("{ANCHOR_MAC_DOMAIN}\n{seq}\n{entry_hash}")
}

/// The sidecar anchor path for an audit log: `<audit path>.anchor`.
#[must_use]
pub fn anchor_path_for(audit_path: &Path) -> PathBuf {
    let mut path = audit_path.as_os_str().to_owned();
    path.push(".anchor");
    PathBuf::from(path)
}

/// Writer for the sidecar anchor file. Owned by the [`crate::Auditor`]; every
/// update is atomic (tmp + fsync + rename) and happens strictly *after* the
/// anchored record was fsynced, so the anchor can never run ahead of the
/// durable chain.
pub struct AnchorFile {
    path: PathBuf,
    key: SigningKey,
}

impl AnchorFile {
    /// An anchor writer at `path` signing with `key`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, key: SigningKey) -> Self {
        AnchorFile {
            path: path.into(),
            key,
        }
    }

    /// The sidecar path this writer maintains.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Atomically replace the anchor with the given durable chain head.
    ///
    /// The caller must have fsynced the record at `seq` before calling this
    /// (never anchor-ahead; see the module docs).
    pub fn record_head(&self, seq: u64, entry_hash: &str) -> Result<(), AuditError> {
        let anchor = ChainAnchor::signed(seq, entry_hash, &self.key);
        let mut body = serde_json::to_vec(&anchor).map_err(|e| AuditError::Io(e.to_string()))?;
        body.push(b'\n');
        let mut tmp = self.path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let io_err = |e: std::io::Error| AuditError::Io(e.to_string());
        {
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)
                .map_err(io_err)?;
            file.write_all(&body).map_err(io_err)?;
            // fsync the tmp content BEFORE the rename: a crash must never
            // surface a renamed-but-empty/partial anchor (that would look like
            // tampering instead of an explainable anchor-behind window).
            file.sync_all().map_err(io_err)?;
        }
        fs::rename(&tmp, &self.path).map_err(io_err)
    }
}

/// Why loading an anchor sidecar failed. Any error here is fail-closed at
/// verification time: a present-but-unreadable anchor is tamper-suspect, never
/// silently ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorLoadError {
    /// Human-readable reason.
    pub message: String,
}

impl std::fmt::Display for AnchorLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "audit head anchor unreadable: {}", self.message)
    }
}

impl std::error::Error for AnchorLoadError {}

/// Load the anchor sidecar at `path`. Absent file → `Ok(None)` (legacy log);
/// any other read/parse failure → `Err` (fail closed at verify time).
pub fn load_anchor(path: &Path) -> Result<Option<ChainAnchor>, AnchorLoadError> {
    let body = match fs::read_to_string(path) {
        Ok(body) => body,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(AnchorLoadError {
                message: format!("{}: {e}", path.display()),
            });
        }
    };
    let anchor: ChainAnchor = serde_json::from_str(body.trim()).map_err(|e| AnchorLoadError {
        message: format!("{}: {e}", path.display()),
    })?;
    Ok(Some(anchor))
}

/// The anchor cross-check verdict for an otherwise-valid chain.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnchorStatus {
    /// The chain head is exactly the anchored record.
    Match,
    /// The chain extends past the anchor by `behind_by` record(s) and still
    /// passes through the anchored record — the explainable crash/buffer
    /// window (see the module docs), not tamper evidence.
    Behind {
        /// How many records the chain head is ahead of the anchor.
        behind_by: u64,
    },
}

/// An anchor cross-check failure — always fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnchorViolation {
    /// The anchor names a `key_id` not in the supplied key set.
    UnknownKeyId(String),
    /// The anchor MAC does not verify — a rewritten/forged anchor.
    MacMismatch,
    /// The chain ends before the anchored head: trailing records were removed.
    Truncated {
        /// The durable head `seq` the anchor attests.
        anchor_seq: u64,
        /// How many records the chain actually holds.
        chain_records: usize,
    },
    /// The record at the anchored `seq` exists but its `entry_hash` differs —
    /// the chain diverged from the attested history.
    HeadHashMismatch {
        /// The anchored `seq` whose record does not match.
        anchor_seq: u64,
    },
}

impl std::fmt::Display for AnchorViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnchorViolation::UnknownKeyId(id) => {
                write!(f, "head anchor names unknown key_id {id:?}")
            }
            AnchorViolation::MacMismatch => {
                f.write_str("head anchor MAC does not verify (rewritten or forged anchor)")
            }
            AnchorViolation::Truncated {
                anchor_seq,
                chain_records,
            } => write!(
                f,
                "chain ends at {chain_records} record(s) but the head anchor attests seq \
                 {anchor_seq} — trailing records were removed (tail truncation)"
            ),
            AnchorViolation::HeadHashMismatch { anchor_seq } => write!(
                f,
                "record at anchored seq {anchor_seq} does not match the anchored entry_hash \
                 (chain diverged from the attested history)"
            ),
        }
    }
}

/// Cross-check an already-verified chain (see [`crate::verify_records`], which
/// guarantees `records[i].seq == i + 1`) against a head anchor.
///
/// Fail-closed: any MAC/key problem with the anchor, a chain shorter than the
/// anchored head, or a hash mismatch at the anchored seq is a violation. A
/// chain *longer* than the anchor that still passes through the anchored record
/// is [`AnchorStatus::Behind`] — the explainable crash/buffer window.
pub fn check_anchor(
    records: &[AuditRecord],
    anchor: &ChainAnchor,
    keys: &[SigningKey],
) -> Result<AnchorStatus, AnchorViolation> {
    let Some(key) = keys.iter().find(|k| k.key_id() == anchor.key_id) else {
        return Err(AnchorViolation::UnknownKeyId(anchor.key_id.clone()));
    };
    if !anchor.mac_is_valid(key) {
        return Err(AnchorViolation::MacMismatch);
    }
    let chain_records = records.len();
    if (chain_records as u64) < anchor.seq {
        return Err(AnchorViolation::Truncated {
            anchor_seq: anchor.seq,
            chain_records,
        });
    }
    // verify_records enforced seq == index + 1, so the anchored record (if the
    // chain is long enough) sits at index anchor.seq - 1.
    let index = usize::try_from(anchor.seq.saturating_sub(1)).unwrap_or(usize::MAX);
    let anchored = records.get(index);
    match anchored {
        Some(record) if record.entry_hash == anchor.entry_hash => {
            let behind_by = (chain_records as u64) - anchor.seq;
            if behind_by == 0 {
                Ok(AnchorStatus::Match)
            } else {
                Ok(AnchorStatus::Behind { behind_by })
            }
        }
        // seq 0 anchors are never written (the writer anchors only after an
        // append); treat any such artifact as a forged anchor.
        _ => Err(AnchorViolation::HeadHashMismatch {
            anchor_seq: anchor.seq,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{AuditDecision, AuditEntryDraft, AuditOutcome, AuditRecord, AuditSubject};

    fn key() -> SigningKey {
        SigningKey::new("k1", b"anchor-test-key".to_vec())
    }

    fn draft(sql: &str) -> AuditEntryDraft {
        AuditEntryDraft {
            subject: AuditSubject::new("agent", "agent"),
            db_evidence: None,
            cancel: None,
            tool: "oracle_execute".to_owned(),
            sql: sql.to_owned(),
            danger_level: "GUARDED".to_owned(),
            decision: AuditDecision::Allowed,
            rows_affected: None,
            outcome: AuditOutcome::Pending,
        }
    }

    fn signed_chain(n: usize) -> Vec<AuditRecord> {
        let k = key();
        let mut records: Vec<AuditRecord> = Vec::with_capacity(n);
        for i in 0..n {
            let prev = records
                .last()
                .map_or(crate::record::GENESIS_HASH, |r| r.entry_hash.as_str())
                .to_owned();
            records.push(AuditRecord::chained_signed(
                &draft(&format!("DELETE FROM t WHERE id={i}")),
                (i + 1) as u64,
                &prev,
                format!("t{i}"),
                &k,
            ));
        }
        records
    }

    fn anchor_at(records: &[AuditRecord], seq: u64) -> ChainAnchor {
        let record = &records[(seq - 1) as usize];
        ChainAnchor::signed(record.seq, &record.entry_hash, &key())
    }

    #[test]
    fn intact_chain_matches_its_anchor() {
        let records = signed_chain(3);
        let anchor = anchor_at(&records, 3);
        assert_eq!(
            check_anchor(&records, &anchor, &[key()]),
            Ok(AnchorStatus::Match)
        );
    }

    #[test]
    fn tail_truncation_is_detected() {
        let mut records = signed_chain(3);
        let anchor = anchor_at(&records, 3);
        records.pop(); // delete the last record: the chain prefix still verifies
        assert_eq!(
            check_anchor(&records, &anchor, &[key()]),
            Err(AnchorViolation::Truncated {
                anchor_seq: 3,
                chain_records: 2,
            })
        );
    }

    #[test]
    fn truncation_to_empty_is_detected() {
        let records = signed_chain(2);
        let anchor = anchor_at(&records, 2);
        assert_eq!(
            check_anchor(&[], &anchor, &[key()]),
            Err(AnchorViolation::Truncated {
                anchor_seq: 2,
                chain_records: 0,
            })
        );
    }

    #[test]
    fn anchor_behind_by_one_crash_window_is_explainable() {
        // Crash between the seq=3 record fsync and the anchor rename: the
        // anchor still names seq=2. The chain passes through the anchored
        // record, so this is Behind — never a violation.
        let records = signed_chain(3);
        let anchor = anchor_at(&records, 2);
        assert_eq!(
            check_anchor(&records, &anchor, &[key()]),
            Ok(AnchorStatus::Behind { behind_by: 1 })
        );
    }

    #[test]
    fn rewritten_anchor_without_key_fails_mac() {
        // The tail-truncation attack with anchor rewrite: point the anchor at
        // the shorter head. Without the signing key the MAC cannot be
        // recomputed; a copied record signature is domain-separated away.
        let mut records = signed_chain(3);
        records.pop();
        let head = records.last().unwrap().clone();
        let forged = ChainAnchor {
            anchor_version: ANCHOR_VERSION,
            seq: head.seq,
            entry_hash: head.entry_hash.clone(),
            key_id: "k1".to_owned(),
            // Best forgery available without the key: replay the record's own
            // keyed signature as the anchor MAC.
            mac: head.signature.clone().unwrap(),
        };
        assert_eq!(
            check_anchor(&records, &forged, &[key()]),
            Err(AnchorViolation::MacMismatch)
        );
    }

    #[test]
    fn anchor_under_unknown_key_id_is_reported() {
        let records = signed_chain(1);
        let other = SigningKey::new("k2", b"other-key".to_vec());
        let anchor = ChainAnchor::signed(1, &records[0].entry_hash, &other);
        assert_eq!(
            check_anchor(&records, &anchor, &[key()]),
            Err(AnchorViolation::UnknownKeyId("k2".to_owned()))
        );
    }

    #[test]
    fn diverged_history_at_anchored_seq_is_detected() {
        let records = signed_chain(2);
        let anchor = ChainAnchor::signed(2, "sha256:not-the-real-head", &key());
        assert_eq!(
            check_anchor(&records, &anchor, &[key()]),
            Err(AnchorViolation::HeadHashMismatch { anchor_seq: 2 })
        );
    }

    #[test]
    fn anchor_file_roundtrips_atomically() {
        let dir = tempfile::tempdir().expect("tempdir");
        let audit_path = dir.path().join("audit.jsonl");
        let anchor_path = anchor_path_for(&audit_path);
        assert_eq!(anchor_path, dir.path().join("audit.jsonl.anchor"));

        let writer = AnchorFile::new(&anchor_path, key());
        writer
            .record_head(7, "sha256:head-7")
            .expect("write anchor");
        let loaded = load_anchor(&anchor_path).expect("load").expect("present");
        assert_eq!(loaded.seq, 7);
        assert_eq!(loaded.entry_hash, "sha256:head-7");
        assert!(loaded.mac_is_valid(&key()));

        // Overwrite with a newer head; no stale tmp file remains.
        writer.record_head(8, "sha256:head-8").expect("rewrite");
        let loaded = load_anchor(&anchor_path).expect("load").expect("present");
        assert_eq!(loaded.seq, 8);
        assert!(!anchor_path.with_extension("anchor.tmp").exists());
    }

    #[test]
    fn anchor_mac_preimage_binds_domain_seq_and_hash() {
        let k = key();
        let anchor = ChainAnchor::signed(42, "sha256:head-42", &k);
        assert_eq!(
            anchor.mac,
            k.sign("oraclemcp-audit-anchor-v1\n42\nsha256:head-42"),
            "anchor MAC must bind the domain, sequence, and entry hash"
        );
        assert_ne!(
            anchor.mac,
            k.sign("42\nsha256:head-42"),
            "anchor MAC must stay domain-separated from record signatures"
        );
    }

    #[test]
    fn absent_anchor_loads_as_none_and_corrupt_anchor_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let anchor_path = dir.path().join("audit.jsonl.anchor");
        assert_eq!(load_anchor(&anchor_path), Ok(None));
        std::fs::write(&anchor_path, b"{not json").expect("write corrupt");
        assert!(
            load_anchor(&anchor_path).is_err(),
            "corrupt anchor fails closed"
        );
    }

    #[test]
    fn present_but_unreadable_anchor_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = load_anchor(dir.path()).expect_err("directory is present but unreadable as JSON");
        let msg = err.to_string();
        assert!(msg.contains("audit head anchor unreadable"), "{msg}");
        assert!(msg.contains(dir.path().to_string_lossy().as_ref()), "{msg}");
    }

    #[test]
    fn anchor_violation_messages_name_the_failure_mode() {
        let cases = [
            (
                AnchorViolation::UnknownKeyId("k2".to_owned()).to_string(),
                "unknown key_id",
            ),
            (
                AnchorViolation::MacMismatch.to_string(),
                "MAC does not verify",
            ),
            (
                AnchorViolation::Truncated {
                    anchor_seq: 9,
                    chain_records: 7,
                }
                .to_string(),
                "trailing records were removed",
            ),
            (
                AnchorViolation::HeadHashMismatch { anchor_seq: 3 }.to_string(),
                "does not match the anchored entry_hash",
            ),
        ];
        for (msg, needle) in cases {
            assert!(msg.contains(needle), "{msg}");
        }
    }
}
