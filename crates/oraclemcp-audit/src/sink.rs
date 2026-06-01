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
use std::path::Path;
use std::sync::Mutex;

use thiserror::Error;

use crate::record::{AuditEntryDraft, AuditRecord, GENESIS_HASH};

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
        let line = serde_json::to_string(record).map_err(|e| AuditError::Io(e.to_string()))?;
        let mut f = self.file.lock().expect("audit file mutex poisoned");
        f.write_all(line.as_bytes())
            .map_err(|e| AuditError::Io(e.to_string()))?;
        f.write_all(b"\n")
            .map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(())
    }

    fn flush(&self) -> Result<(), AuditError> {
        let f = self.file.lock().expect("audit file mutex poisoned");
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
        self.records.lock().expect("poisoned").clone()
    }

    /// How many times `flush` was called.
    #[must_use]
    pub fn flush_count(&self) -> usize {
        *self.flushes.lock().expect("poisoned")
    }
}

impl AuditSink for MemoryAuditSink {
    fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.records.lock().expect("poisoned").push(record.clone());
        Ok(())
    }

    fn flush(&self) -> Result<(), AuditError> {
        *self.flushes.lock().expect("poisoned") += 1;
        Ok(())
    }
}

struct ChainState {
    seq: u64,
    last_hash: String,
}

/// The audit orchestrator: assigns monotonic sequence numbers, maintains the
/// hash chain, and enforces fsync-before-execute for durable records.
pub struct Auditor {
    sink: Box<dyn AuditSink>,
    state: Mutex<ChainState>,
}

impl Auditor {
    /// A new auditor over the given sink.
    #[must_use]
    pub fn new(sink: Box<dyn AuditSink>) -> Self {
        Auditor {
            sink,
            state: Mutex::new(ChainState {
                seq: 0,
                last_hash: GENESIS_HASH.to_owned(),
            }),
        }
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
        let mut state = self.state.lock().expect("audit state poisoned");
        let seq = state.seq + 1;
        let record = AuditRecord::chained(draft, seq, &state.last_hash, timestamp);
        self.sink.append(&record)?;
        if durable {
            self.sink.flush()?;
        }
        state.seq = seq;
        state.last_hash = record.entry_hash.clone();
        Ok(record)
    }

    /// Force a flush (group-commit point for buffered reads).
    pub fn flush(&self) -> Result<(), AuditError> {
        self.sink.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{AuditDecision, AuditOutcome};
    use std::sync::Arc;

    fn draft(sql: &str, danger: &str) -> AuditEntryDraft {
        AuditEntryDraft {
            agent_identity: "agent".to_owned(),
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
        let auditor = Auditor::new(Box::new(SharedSink(sink.clone())));
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
        let auditor = Auditor::new(Box::new(SharedSink(sink.clone())));
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
        let auditor = Auditor::new(Box::new(SharedSink(sink.clone())));
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
            let auditor = Auditor::new(Box::new(FileAuditSink::open(&path).expect("open")));
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
}
