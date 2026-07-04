//! Out-of-band durable audit sinks + the fsync-before-execute [`Auditor`]
//! (plan §5.13).
//!
//! **The sink is out-of-band on purpose** — an append-only local file, *never*
//! the Oracle session that runs the audited statement: an INSERT on that
//! connection would share the statement's transaction, so any ROLLBACK (the
//! savepoint preview, the cancel-rollback, an error) would erase the audit row,
//! violating "logged before it runs." For `Guarded`/`Destructive`/escalation
//! calls the record is fsynced *before* the statement executes (at-least-once
//! log, at-most-once execute); pure reads may use a batched group-commit flush.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

use parking_lot::Mutex;
use thiserror::Error;

use crate::anchor::{AnchorFile, load_anchor};
use crate::record::{AuditEntryDraft, AuditRecord, GENESIS_HASH, SigningKey};
use crate::verify::parse_jsonl;

/// Audit sink errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuditError {
    /// An I/O error writing or flushing the sink.
    #[error("audit io error: {0}")]
    Io(String),
    /// Chain verification failed at the given sequence number.
    #[error("audit chain broken at seq {0}")]
    ChainBroken(u64),
    /// A previous append/flush failed or panicked after the next record may have
    /// reached the byte stream. The auditor is poisoned: it refuses further
    /// appends rather than re-issue that sequence number and fork the hash chain.
    /// Operator action (inspect/repair the audit log) is required.
    #[error("audit sink poisoned after uncertain append")]
    Poisoned,
    /// Chain resume refused at startup: an existing audit log cannot seed a
    /// continuing hash chain without forking it or masking a truncation (a
    /// malformed tail, or a tail that contradicts the head anchor). The server
    /// must not start until an operator inspects/repairs the log — the message
    /// names the file and the repair path. See [`Auditor::resume_from`].
    #[error("audit chain resume refused: {0}")]
    ResumeRefused(String),
}

/// An append-only, durable audit sink.
pub trait AuditSink: Send + Sync {
    /// Append one record. Implementations must write the full record before
    /// returning.
    fn append(&self, record: &AuditRecord) -> Result<(), AuditError>;
    /// Flush + fsync any buffered data to durable storage.
    fn flush(&self) -> Result<(), AuditError>;
}

/// A durable append-only file sink. Each record is one JSON line; `flush`
/// performs an `fsync` (`File::sync_all`).
pub struct FileAuditSink {
    file: Mutex<File>,
}

impl FileAuditSink {
    /// Open (creating + appending) the audit file at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(FileAuditSink {
            file: Mutex::new(file),
        })
    }
}

impl AuditSink for FileAuditSink {
    fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
        let mut line = serde_json::to_vec(record).map_err(|e| AuditError::Io(e.to_string()))?;
        line.push(b'\n');
        let mut f = self.file.lock();
        f.write_all(&line)
            .map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(())
    }

    fn flush(&self) -> Result<(), AuditError> {
        let f = self.file.lock();
        // fsync: the bytes are durably on disk before we return.
        f.sync_all().map_err(|e| AuditError::Io(e.to_string()))
    }
}

/// An in-memory sink for tests: records every appended entry and counts flushes
/// so tests can assert fsync-before-execute ordering.
#[derive(Default)]
pub struct MemoryAuditSink {
    records: Mutex<Vec<AuditRecord>>,
    flushes: Mutex<usize>,
}

impl MemoryAuditSink {
    /// A new empty memory sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A snapshot of appended records.
    #[must_use]
    pub fn records(&self) -> Vec<AuditRecord> {
        self.records.lock().clone()
    }

    /// How many times `flush` was called.
    #[must_use]
    pub fn flush_count(&self) -> usize {
        *self.flushes.lock()
    }
}

impl AuditSink for MemoryAuditSink {
    fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.records.lock().push(record.clone());
        Ok(())
    }

    fn flush(&self) -> Result<(), AuditError> {
        *self.flushes.lock() += 1;
        Ok(())
    }
}

struct ChainState {
    seq: u64,
    last_hash: String,
    /// Set once an append or flush failed/panicked after the seq=N line may have
    /// reached the byte stream. The in-memory state was NOT advanced, so
    /// re-issuing seq=N from the un-advanced state would fork the tamper-evident
    /// hash chain. Once poisoned, every subsequent `append` fails closed.
    poisoned: bool,
}

/// The audit orchestrator: assigns monotonic sequence numbers, maintains the
/// hash chain, signs each record with a keyed MAC, and enforces
/// fsync-before-execute for durable records.
pub struct Auditor {
    sink: Box<dyn AuditSink>,
    /// The keyed MAC identity. Always present — a signed chain is the point of
    /// the auditor; construction is the place to fail closed if no key is
    /// configured (the binary does this before any operating level above
    /// ReadOnly is reachable).
    key: SigningKey,
    /// Optional sidecar head anchor (bead oraclemcp-xb51): after every durable
    /// fsync the anchor is atomically rewritten to name the durable chain head,
    /// so `audit verify` can detect tail truncation. Record fsync always comes
    /// FIRST — the anchor can be behind (explainable crash window) but never
    /// ahead of the durable chain. See `crate::anchor` for the semantics.
    anchor: Option<AnchorFile>,
    state: Mutex<ChainState>,
}

impl Auditor {
    /// A new signing auditor over the given sink and keyed MAC identity.
    #[must_use]
    pub fn new(sink: Box<dyn AuditSink>, key: SigningKey) -> Self {
        Auditor {
            sink,
            key,
            anchor: None,
            state: Mutex::new(ChainState {
                seq: 0,
                last_hash: GENESIS_HASH.to_owned(),
                poisoned: false,
            }),
        }
    }

    /// Maintain a sidecar head anchor at `path` (normally
    /// [`crate::anchor_path_for`] of the audit log), signed with this
    /// auditor's key. The anchor is updated after every durable append and
    /// every explicit flush; an anchor update failure fails the call closed
    /// (the record is already durably logged, so the chain state still
    /// advances and the chain never forks).
    #[must_use]
    pub fn with_head_anchor(mut self, path: impl Into<PathBuf>) -> Self {
        self.anchor = Some(AnchorFile::new(path.into(), self.key.clone()));
        self
    }

    /// Resume the hash chain from an existing on-disk audit log so a server
    /// **restart continues ONE verifiable chain** instead of re-issuing seq=1
    /// off genesis into the same file (bead oraclemcp-ow3v).
    ///
    /// Reads the audit log at `audit_path`. If it is absent or empty the chain
    /// starts fresh at genesis (state stays seq=0). Otherwise its LAST record
    /// seeds the chain state (`seq` + `entry_hash`), so the next append chains
    /// onto it and the head anchor **advances** rather than regressing below the
    /// prior run's head.
    ///
    /// Fails closed — the server must not start — when:
    ///  - the log exists but cannot be read, or any record is malformed: a torn
    ///    or tampered tail must be inspected/repaired by an operator, never
    ///    silently continued;
    ///  - a head anchor sidecar is present and the on-disk tail contradicts it,
    ///    i.e. the chain ends *before* the anchored durable head (tail
    ///    truncation) or the record at the anchored `seq` diverges from the
    ///    attested `entry_hash` (rewritten history).
    ///
    /// Call this AFTER [`with_head_anchor`](Self::with_head_anchor) so the
    /// anchor cross-check runs. It writes nothing, so the
    /// record-fsync-before-anchor ordering the writer maintains is untouched.
    pub fn resume_from(self, audit_path: &Path) -> Result<Self, AuditError> {
        let disp = audit_path.display();
        let body = match std::fs::read_to_string(audit_path) {
            Ok(body) => body,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => {
                return Err(AuditError::ResumeRefused(format!(
                    "cannot read audit log {disp} to resume the hash chain: {e}; inspect the file \
                     and its permissions, then restart"
                )));
            }
        };
        let records = parse_jsonl(&body).map_err(|e| {
            AuditError::ResumeRefused(format!(
                "audit log {disp} has a malformed record ({e}); a torn or tampered tail cannot \
                 seed a continuing chain — run `oraclemcp audit verify {disp}`, then repair or \
                 roll the file back to its last well-formed line before restarting"
            ))
        })?;
        let Some(tail) = records.last() else {
            // Empty log: nothing to resume; the fresh genesis state is correct.
            return Ok(self);
        };

        // Anchor cross-check: the sidecar attests the durable chain head. The
        // tail we are about to resume from must neither fall short of it
        // (truncation) nor diverge from it (rewritten history). A tail AHEAD of
        // the anchor is the explainable crash/group-commit window — accepted.
        if let Some(anchor_file) = &self.anchor
            && let Some(anchor) = load_anchor(anchor_file.path()).map_err(|e| {
                AuditError::ResumeRefused(format!(
                    "head anchor sidecar {} is present but unreadable ({e}); refusing to resume \
                     without confirming the durable chain head",
                    anchor_file.path().display()
                ))
            })?
        {
            if anchor.seq > tail.seq {
                return Err(AuditError::ResumeRefused(format!(
                    "head anchor attests durable seq {} but the audit log {disp} ends at seq {} — \
                     trailing records were removed (tail truncation); restore the missing tail, or \
                     only if the loss is understood reset the anchor, before restarting",
                    anchor.seq, tail.seq
                )));
            }
            if let Some(anchored) = records.iter().find(|r| r.seq == anchor.seq)
                && anchored.entry_hash != anchor.entry_hash
            {
                return Err(AuditError::ResumeRefused(format!(
                    "record at the anchored seq {} in {disp} does not match the head anchor's \
                     attested entry_hash — the chain diverged from the attested history; inspect \
                     with `oraclemcp audit verify {disp}` before restarting",
                    anchor.seq
                )));
            }
        }

        {
            let mut state = self.state.lock();
            state.seq = tail.seq;
            state.last_hash = tail.entry_hash.clone();
        }
        Ok(self)
    }

    /// Append a chained record. When `durable` is true the record is fsynced
    /// before this returns — use it for `Guarded`/`Destructive`/escalation calls
    /// so the statement is durably logged *before* it executes. Pure reads pass
    /// `durable=false` (group-commit; flush periodically).
    pub fn append(
        &self,
        draft: &AuditEntryDraft,
        timestamp: String,
        durable: bool,
    ) -> Result<AuditRecord, AuditError> {
        let mut state = self.state.lock();
        // Fail closed: once an append/flush failure or panic may have left a
        // record in the byte stream without advancing state, issuing any further
        // record would either reuse that seq or chain past an uncertain record.
        if state.poisoned {
            return Err(AuditError::Poisoned);
        }
        let seq = state.seq + 1;
        let record =
            AuditRecord::chained_signed(draft, seq, &state.last_hash, timestamp, &self.key);
        match catch_unwind(AssertUnwindSafe(|| self.sink.append(&record))) {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                state.poisoned = true;
                return Err(err);
            }
            Err(_) => {
                state.poisoned = true;
                return Err(AuditError::Poisoned);
            }
        }
        let mut anchor_outcome: Result<(), AuditError> = Ok(());
        if durable {
            // The seq=N line is now in the byte stream but not yet durable. If
            // the fsync fails or panics we must NOT advance state and must NOT
            // later re-issue seq=N off the same prev_hash.
            match catch_unwind(AssertUnwindSafe(|| self.sink.flush())) {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    state.poisoned = true;
                    return Err(err);
                }
                Err(_) => {
                    state.poisoned = true;
                    return Err(AuditError::Poisoned);
                }
            }
            // Head anchor, strictly AFTER the record fsync (never anchor-ahead;
            // see `crate::anchor`). An anchor failure does not fork the chain —
            // the record is durably on disk, so state advances below either
            // way — but it fails this call closed: privileged statements must
            // not run while truncation tamper-evidence cannot be maintained. A
            // later successful durable append re-anchors (self-healing), so
            // this does not poison.
            if let Some(anchor) = &self.anchor {
                anchor_outcome = catch_unwind(AssertUnwindSafe(|| {
                    anchor.record_head(seq, &record.entry_hash)
                }))
                .unwrap_or_else(|_| {
                    Err(AuditError::Io(
                        "audit head anchor update panicked".to_owned(),
                    ))
                });
            }
        }
        state.seq = seq;
        state.last_hash = record.entry_hash.clone();
        anchor_outcome?;
        Ok(record)
    }

    /// Force a flush (group-commit point for buffered reads). Holding the
    /// chain-state lock across the fsync keeps the subsequent anchor update
    /// consistent with the exact head that was flushed.
    pub fn flush(&self) -> Result<(), AuditError> {
        let state = self.state.lock();
        // Fail closed while poisoned: the byte stream may hold an uncertain
        // record past `state`, so neither a fresh fsync promise nor a
        // re-anchor of the stale head is trustworthy.
        if state.poisoned {
            return Err(AuditError::Poisoned);
        }
        self.sink.flush()?;
        if let Some(anchor) = &self.anchor
            && state.seq > 0
        {
            anchor.record_head(state.seq, &state.last_hash)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{AuditDecision, AuditOutcome, AuditSubject};
    use std::sync::Arc;
    use std::thread;

    fn test_key() -> SigningKey {
        SigningKey::new("test", b"sink-test-key".to_vec())
    }

    fn draft(sql: &str, danger: &str) -> AuditEntryDraft {
        AuditEntryDraft {
            subject: AuditSubject::new("agent", "agent"),
            db_evidence: None,
            cancel: None,
            tool: "oracle_query".to_owned(),
            sql: sql.to_owned(),
            danger_level: danger.to_owned(),
            decision: AuditDecision::Allowed,
            rows_affected: None,
            outcome: AuditOutcome::Pending,
        }
    }

    #[test]
    fn durable_append_fsyncs_before_returning() {
        // The fsync-before-execute contract (§5.13): a Guarded call's record is
        // flushed (fsynced) before append() returns, so a kill between this and
        // the (separate) execute leaves the log written and the DB untouched.
        let sink = Arc::new(MemoryAuditSink::new());
        let auditor = Auditor::new(Box::new(SharedSink(sink.clone())), test_key());
        auditor
            .append(
                &draft("DELETE FROM t WHERE id=1", "GUARDED"),
                "t0".to_owned(),
                true,
            )
            .expect("append");
        assert_eq!(sink.records().len(), 1, "record written");
        assert_eq!(sink.flush_count(), 1, "fsynced before returning");
    }

    #[test]
    fn read_append_is_not_fsynced_per_call() {
        let sink = Arc::new(MemoryAuditSink::new());
        let auditor = Auditor::new(Box::new(SharedSink(sink.clone())), test_key());
        auditor
            .append(&draft("SELECT 1 FROM dual", "SAFE"), "t0".to_owned(), false)
            .expect("append");
        assert_eq!(sink.records().len(), 1);
        assert_eq!(
            sink.flush_count(),
            0,
            "reads use group-commit, no per-call fsync"
        );
    }

    #[test]
    fn chain_links_and_increments_seq() {
        let sink = Arc::new(MemoryAuditSink::new());
        let auditor = Auditor::new(Box::new(SharedSink(sink.clone())), test_key());
        let r1 = auditor
            .append(&draft("SELECT 1 FROM dual", "SAFE"), "t0".to_owned(), false)
            .unwrap();
        let r2 = auditor
            .append(
                &draft("DELETE FROM t", "DESTRUCTIVE"),
                "t1".to_owned(),
                true,
            )
            .unwrap();
        assert_eq!(r1.seq, 1);
        assert_eq!(r2.seq, 2);
        assert_eq!(r1.prev_hash, GENESIS_HASH);
        assert_eq!(r2.prev_hash, r1.entry_hash, "chain links seq 2 to seq 1");
        assert!(r1.hash_is_valid() && r2.hash_is_valid());
    }

    #[test]
    fn file_sink_persists_and_chain_verifies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        {
            let auditor = Auditor::new(
                Box::new(FileAuditSink::open(&path).expect("open")),
                test_key(),
            );
            auditor
                .append(&draft("SELECT 1 FROM dual", "SAFE"), "t0".to_owned(), true)
                .unwrap();
            auditor
                .append(&draft("DROP TABLE t", "DESTRUCTIVE"), "t1".to_owned(), true)
                .unwrap();
        }
        let content = std::fs::read_to_string(&path).expect("read");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        let mut prev = GENESIS_HASH.to_owned();
        for (i, line) in lines.iter().enumerate() {
            let rec: AuditRecord = serde_json::from_str(line).expect("parse");
            assert!(rec.hash_is_valid(), "record {i} hash valid");
            assert_eq!(rec.prev_hash, prev, "record {i} links to previous");
            assert_eq!(rec.seq, (i + 1) as u64);
            prev = rec.entry_hash;
        }
    }

    #[test]
    fn durable_flush_failure_poisons_auditor_and_never_forks_chain() {
        // Regression for oracle-ajm2.9: on a transient fsync failure the seq=N
        // line may already be in the byte stream but state was not advanced. A
        // naive implementation re-issues seq=N off the same prev_hash on the
        // next durable append, forking the tamper-evident chain. The auditor
        // must poison instead.
        let sink = Arc::new(FlushFailsOnceSink::default());
        let auditor = Auditor::new(Box::new(SharedFlakySink(sink.clone())), test_key());

        // First durable append: the record is written, then flush() fails.
        let first = auditor.append(
            &draft("DELETE FROM t WHERE id=1", "GUARDED"),
            "t0".to_owned(),
            true,
        );
        assert!(
            matches!(first, Err(AuditError::Io(_))),
            "durable flush failure propagates the I/O error, got {first:?}"
        );
        assert_eq!(sink.records().len(), 1, "seq=1 line is already in the file");

        // Second durable append: must fail closed (poisoned), NOT re-issue seq=1.
        let second = auditor.append(
            &draft("DELETE FROM t WHERE id=2", "GUARDED"),
            "t1".to_owned(),
            true,
        );
        assert!(
            matches!(second, Err(AuditError::Poisoned)),
            "auditor is poisoned after a durable flush failure, got {second:?}"
        );

        // A non-durable read append must also fail closed once poisoned.
        let third = auditor.append(&draft("SELECT 1 FROM dual", "SAFE"), "t2".to_owned(), false);
        assert!(
            matches!(third, Err(AuditError::Poisoned)),
            "poisoning fails closed for non-durable appends too, got {third:?}"
        );

        // The on-disk stream never gained a second record, so it can never hold
        // two records sharing a seq / forking off the same prev_hash.
        let records = sink.records();
        assert_eq!(
            records.len(),
            1,
            "no further record appended after poisoning"
        );
        let mut seqs: Vec<u64> = records.iter().map(|r| r.seq).collect();
        let before = seqs.len();
        seqs.sort_unstable();
        seqs.dedup();
        assert_eq!(seqs.len(), before, "no duplicate seq in the audit stream");
    }

    #[test]
    fn durable_appends_maintain_the_head_anchor() {
        // Bead oraclemcp-xb51: every durable append fsyncs the record FIRST and
        // then re-anchors the durable head, so the anchor tracks the chain and
        // is never ahead of it.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let anchor_path = crate::anchor_path_for(&path);
        let auditor = Auditor::new(
            Box::new(FileAuditSink::open(&path).expect("open")),
            test_key(),
        )
        .with_head_anchor(&anchor_path);

        let r1 = auditor
            .append(
                &draft("DELETE FROM t WHERE id=1", "GUARDED"),
                "t0".to_owned(),
                true,
            )
            .expect("durable append 1");
        let anchor = crate::load_anchor(&anchor_path)
            .expect("load")
            .expect("present");
        assert_eq!(
            (anchor.seq, anchor.entry_hash.as_str()),
            (1, r1.entry_hash.as_str())
        );

        let r2 = auditor
            .append(
                &draft("DELETE FROM t WHERE id=2", "GUARDED"),
                "t1".to_owned(),
                true,
            )
            .expect("durable append 2");
        let anchor = crate::load_anchor(&anchor_path)
            .expect("load")
            .expect("present");
        assert_eq!(
            (anchor.seq, anchor.entry_hash.as_str()),
            (2, r2.entry_hash.as_str())
        );
        assert!(anchor.mac_is_valid(&test_key()));

        // The verified chain matches its anchor exactly.
        let records = crate::parse_jsonl(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            crate::verify_records(&records, &[test_key()]),
            crate::VerifyOutcome::Ok { records: 2 }
        );
        assert_eq!(
            crate::check_anchor(&records, &anchor, &[test_key()]),
            Ok(crate::AnchorStatus::Match)
        );
    }

    #[test]
    fn non_durable_appends_anchor_only_on_flush() {
        // Group-commit reads are not fsynced per call, so the anchor must NOT
        // run ahead of durability; it catches up at the explicit flush.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let anchor_path = crate::anchor_path_for(&path);
        let auditor = Auditor::new(
            Box::new(FileAuditSink::open(&path).expect("open")),
            test_key(),
        )
        .with_head_anchor(&anchor_path);

        auditor
            .append(&draft("SELECT 1 FROM dual", "SAFE"), "t0".to_owned(), false)
            .expect("read append");
        assert_eq!(
            crate::load_anchor(&anchor_path).expect("load"),
            None,
            "no anchor before the record is durable"
        );

        auditor.flush().expect("group-commit flush");
        let anchor = crate::load_anchor(&anchor_path)
            .expect("load")
            .expect("present");
        assert_eq!(anchor.seq, 1, "flush anchors the flushed head");
    }

    #[test]
    fn resume_on_absent_or_empty_log_starts_fresh_at_genesis() {
        // A first-ever run (FileAuditSink::open creates an empty file) resumes
        // to the fresh genesis state, so the first append is seq=1 off genesis.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let auditor = Auditor::new(
            Box::new(FileAuditSink::open(&path).expect("open")),
            test_key(),
        )
        .resume_from(&path)
        .expect("resume absent/empty log");
        let r1 = auditor
            .append(&draft("SELECT 1 FROM dual", "SAFE"), "t0".to_owned(), true)
            .expect("append");
        assert_eq!(r1.seq, 1);
        assert_eq!(r1.prev_hash, GENESIS_HASH);
    }

    #[test]
    fn restart_resumes_one_verifiable_chain_and_advances_the_anchor() {
        // Bead oraclemcp-ow3v: a restart must continue ONE verifiable chain
        // (not re-issue seq=1/genesis after the previous run), and the head
        // anchor must advance across the restart rather than regress.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let anchor_path = crate::anchor_path_for(&path);

        // First run: two durable records, then the auditor drops (server exits).
        {
            let auditor = Auditor::new(
                Box::new(FileAuditSink::open(&path).expect("open")),
                test_key(),
            )
            .with_head_anchor(&anchor_path)
            .resume_from(&path)
            .expect("resume empty log");
            auditor
                .append(
                    &draft("DELETE FROM t WHERE id=1", "GUARDED"),
                    "t0".to_owned(),
                    true,
                )
                .expect("run1 append 1");
            let r2 = auditor
                .append(
                    &draft("DELETE FROM t WHERE id=2", "GUARDED"),
                    "t1".to_owned(),
                    true,
                )
                .expect("run1 append 2");
            assert_eq!(r2.seq, 2);
        }
        let anchor_run1 = crate::load_anchor(&anchor_path)
            .expect("load")
            .expect("present");
        assert_eq!(anchor_run1.seq, 2);

        // Second run: reopen the SAME file (append mode) and resume.
        {
            let auditor = Auditor::new(
                Box::new(FileAuditSink::open(&path).expect("open")),
                test_key(),
            )
            .with_head_anchor(&anchor_path)
            .resume_from(&path)
            .expect("resume non-empty log");
            let r3 = auditor
                .append(
                    &draft("DELETE FROM t WHERE id=3", "GUARDED"),
                    "t2".to_owned(),
                    true,
                )
                .expect("run2 append 1");
            let r4 = auditor
                .append(
                    &draft("DELETE FROM t WHERE id=4", "GUARDED"),
                    "t3".to_owned(),
                    true,
                )
                .expect("run2 append 2");
            assert_eq!(r3.seq, 3, "second run continues the sequence, not seq=1");
            assert_eq!(r4.seq, 4);
        }

        // The whole file is ONE verifiable chain across the restart boundary.
        let records = crate::parse_jsonl(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(records.len(), 4);
        assert_eq!(
            crate::verify_records(&records, &[test_key()]),
            crate::VerifyOutcome::Ok { records: 4 }
        );

        // The anchor advanced across the restart (never regressed below seq=2).
        let anchor_run2 = crate::load_anchor(&anchor_path)
            .expect("load")
            .expect("present");
        assert!(
            anchor_run2.seq >= anchor_run1.seq,
            "anchor must not regress across a restart"
        );
        assert_eq!(anchor_run2.seq, 4);
        assert_eq!(
            crate::check_anchor(&records, &anchor_run2, &[test_key()]),
            Ok(crate::AnchorStatus::Match)
        );
    }

    #[test]
    fn resume_refuses_a_malformed_tail_with_a_repair_message() {
        // A torn final append (partial JSON) must refuse startup fail-closed,
        // with an operator-repair message — never silently continue.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let anchor_path = crate::anchor_path_for(&path);
        {
            let auditor = Auditor::new(
                Box::new(FileAuditSink::open(&path).expect("open")),
                test_key(),
            )
            .with_head_anchor(&anchor_path);
            auditor
                .append(
                    &draft("DELETE FROM t WHERE id=1", "GUARDED"),
                    "t0".to_owned(),
                    true,
                )
                .expect("good record");
        }
        {
            let mut f = OpenOptions::new().append(true).open(&path).expect("reopen");
            f.write_all(b"{\"seq\":2,\"partial\":")
                .expect("write torn tail");
        }
        let refused = Auditor::new(
            Box::new(FileAuditSink::open(&path).expect("open")),
            test_key(),
        )
        .with_head_anchor(&anchor_path)
        .resume_from(&path);
        match refused {
            Err(AuditError::ResumeRefused(msg)) => {
                assert!(
                    msg.contains("malformed") && msg.contains("audit verify"),
                    "operator-repair message expected, got: {msg}"
                );
            }
            Err(other) => panic!("expected ResumeRefused, got {other:?}"),
            Ok(_) => panic!("malformed tail must refuse startup"),
        }
    }

    #[test]
    fn resume_refuses_when_the_tail_is_behind_the_head_anchor() {
        // Tail truncation vs. a surviving anchor: the anchor attests seq=3 but
        // the log was cut back to two records. Resume must fail closed.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let anchor_path = crate::anchor_path_for(&path);
        {
            let auditor = Auditor::new(
                Box::new(FileAuditSink::open(&path).expect("open")),
                test_key(),
            )
            .with_head_anchor(&anchor_path);
            for i in 1..=3 {
                auditor
                    .append(
                        &draft(&format!("DELETE FROM t WHERE id={i}"), "GUARDED"),
                        format!("t{i}"),
                        true,
                    )
                    .expect("append");
            }
        }
        // Cut the log back to two records; the anchor still attests seq=3.
        let body = std::fs::read_to_string(&path).unwrap();
        let two: String = body.lines().take(2).map(|l| format!("{l}\n")).collect();
        std::fs::write(&path, two).unwrap();

        let refused = Auditor::new(
            Box::new(FileAuditSink::open(&path).expect("open")),
            test_key(),
        )
        .with_head_anchor(&anchor_path)
        .resume_from(&path);
        match refused {
            Err(AuditError::ResumeRefused(msg)) => {
                assert!(
                    msg.contains("truncation"),
                    "expected truncation message, got: {msg}"
                );
            }
            Err(other) => panic!("expected ResumeRefused, got {other:?}"),
            Ok(_) => panic!("tail truncation vs the anchor must refuse startup"),
        }
    }

    #[test]
    fn concurrent_appends_keep_one_valid_chain() {
        let sink = Arc::new(MemoryAuditSink::new());
        let auditor = Arc::new(Auditor::new(Box::new(SharedSink(sink.clone())), test_key()));
        let threads = 8;
        let per_thread = 16;
        let mut handles = Vec::new();
        for thread_id in 0..threads {
            let auditor = Arc::clone(&auditor);
            handles.push(thread::spawn(move || {
                for i in 0..per_thread {
                    auditor
                        .append(
                            &draft(
                                &format!("DELETE FROM t WHERE thread_id={thread_id} AND n={i}"),
                                "GUARDED",
                            ),
                            format!("t{thread_id}-{i}"),
                            true,
                        )
                        .expect("concurrent append");
                }
            }));
        }
        for handle in handles {
            handle.join().expect("append thread joins");
        }
        let records = sink.records();
        assert_eq!(records.len(), threads * per_thread);
        assert_eq!(
            crate::verify_records(&records, &[test_key()]),
            crate::VerifyOutcome::Ok {
                records: threads * per_thread
            }
        );
    }

    #[test]
    fn append_panic_poisons_auditor_without_forking_chain() {
        let sink = Arc::new(PanicAfterAppendSink::default());
        let auditor = Auditor::new(Box::new(SharedPanicSink(sink.clone())), test_key());

        let first = auditor.append(
            &draft("DELETE FROM t WHERE id=1", "GUARDED"),
            "t0".to_owned(),
            true,
        );
        assert!(
            matches!(first, Err(AuditError::Poisoned)),
            "append panic is contained as poisoned, got {first:?}"
        );

        let second = auditor.append(
            &draft("DELETE FROM t WHERE id=2", "GUARDED"),
            "t1".to_owned(),
            true,
        );
        assert!(
            matches!(second, Err(AuditError::Poisoned)),
            "auditor stays poisoned after append panic, got {second:?}"
        );

        let records = sink.records();
        assert_eq!(records.len(), 1, "no duplicate seq after append panic");
        assert_eq!(
            crate::verify_records(&records, &[test_key()]),
            crate::VerifyOutcome::Ok { records: 1 }
        );
    }

    // A sink that forwards to a shared Arc<MemoryAuditSink> (so the test keeps a
    // handle while the Auditor owns its Box<dyn AuditSink>).
    struct SharedSink(Arc<MemoryAuditSink>);
    impl AuditSink for SharedSink {
        fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.0.append(record)
        }
        fn flush(&self) -> Result<(), AuditError> {
            self.0.flush()
        }
    }

    // A sink that records every appended record but fails its FIRST flush()
    // (modelling a transient EIO/ENOSPC fsync error), succeeding thereafter.
    #[derive(Default)]
    struct FlushFailsOnceSink {
        records: Mutex<Vec<AuditRecord>>,
        flush_calls: Mutex<usize>,
    }
    impl FlushFailsOnceSink {
        fn records(&self) -> Vec<AuditRecord> {
            self.records.lock().clone()
        }
    }
    impl AuditSink for FlushFailsOnceSink {
        fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.records.lock().push(record.clone());
            Ok(())
        }
        fn flush(&self) -> Result<(), AuditError> {
            let mut calls = self.flush_calls.lock();
            *calls += 1;
            if *calls == 1 {
                Err(AuditError::Io("EIO: fsync failed".to_owned()))
            } else {
                Ok(())
            }
        }
    }

    struct SharedFlakySink(Arc<FlushFailsOnceSink>);
    impl AuditSink for SharedFlakySink {
        fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.0.append(record)
        }
        fn flush(&self) -> Result<(), AuditError> {
            self.0.flush()
        }
    }

    #[derive(Default)]
    struct PanicAfterAppendSink {
        records: Mutex<Vec<AuditRecord>>,
    }
    impl PanicAfterAppendSink {
        fn records(&self) -> Vec<AuditRecord> {
            self.records.lock().clone()
        }
    }
    impl AuditSink for PanicAfterAppendSink {
        fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.records.lock().push(record.clone());
            panic!("panic after writing audit record");
        }
        fn flush(&self) -> Result<(), AuditError> {
            Ok(())
        }
    }

    struct SharedPanicSink(Arc<PanicAfterAppendSink>);
    impl AuditSink for SharedPanicSink {
        fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.0.append(record)
        }
        fn flush(&self) -> Result<(), AuditError> {
            self.0.flush()
        }
    }
}
