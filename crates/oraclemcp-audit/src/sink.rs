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
use std::path::Path;

use parking_lot::Mutex;
use thiserror::Error;

use crate::record::{AuditEntryDraft, AuditRecord, GENESIS_HASH, SigningKey};

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
    state: Mutex<ChainState>,
}

impl Auditor {
    /// A new signing auditor over the given sink and keyed MAC identity.
    #[must_use]
    pub fn new(sink: Box<dyn AuditSink>, key: SigningKey) -> Self {
        Auditor {
            sink,
            key,
            state: Mutex::new(ChainState {
                seq: 0,
                last_hash: GENESIS_HASH.to_owned(),
                poisoned: false,
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
