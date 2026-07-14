//! Bounded, durable, asynchronous delivery for audit-shipping destinations.
//!
//! [`DurableShippingForwarder`] turns a blocking [`ShippingForwarder`] into a
//! fast local enqueue operation. Each signed record is atomically persisted as
//! an individual spool file before `forward` returns; a dedicated worker then
//! performs destination I/O without holding the [`crate::Auditor`] chain lock.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use parking_lot::{Condvar, Mutex};
use serde::{Deserialize, Serialize};

use crate::{AuditRecord, ShippingError, ShippingForwarder};

/// Default maximum number of undelivered records retained per destination.
pub const DEFAULT_SPOOL_MAX_RECORDS: usize = 4_096;
/// Initial retry delay after a destination delivery failure.
pub const DEFAULT_SPOOL_RETRY_INITIAL: Duration = Duration::from_millis(250);
/// Maximum retry delay after repeated destination delivery failures.
pub const DEFAULT_SPOOL_RETRY_MAX: Duration = Duration::from_secs(30);

/// Configuration for one destination's durable delivery worker.
#[derive(Clone, Debug)]
pub struct DurableSpoolConfig {
    /// Private directory dedicated to this destination.
    pub directory: PathBuf,
    /// Stable, non-secret destination identity. A spool cannot be reopened for
    /// a different destination, preventing queued records from being rerouted.
    pub destination_id: String,
    /// Maximum number of undelivered record files retained on disk.
    pub max_records: usize,
    /// Initial retry delay.
    pub retry_initial: Duration,
    /// Maximum retry delay.
    pub retry_max: Duration,
}

impl DurableSpoolConfig {
    /// Build a production-default spool configuration.
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>, destination_id: impl Into<String>) -> Self {
        Self {
            directory: directory.into(),
            destination_id: destination_id.into(),
            max_records: DEFAULT_SPOOL_MAX_RECORDS,
            retry_initial: DEFAULT_SPOOL_RETRY_INITIAL,
            retry_max: DEFAULT_SPOOL_RETRY_MAX,
        }
    }

    /// Override the bounded record capacity.
    #[must_use]
    pub fn with_max_records(mut self, max_records: usize) -> Self {
        self.max_records = max_records;
        self
    }

    /// Override retry delays.
    #[must_use]
    pub fn with_retry(mut self, initial: Duration, max: Duration) -> Self {
        self.retry_initial = initial;
        self.retry_max = max;
        self
    }
}

/// Snapshot of one destination worker's observable delivery state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DurableShippingStatus {
    /// Records durably queued and not yet acknowledged by the destination.
    pub pending_records: u64,
    /// Records acknowledged and removed from the spool in this process.
    pub delivered_records: u64,
    /// Destination, parse, or spool-maintenance failures in this process.
    pub delivery_failures: u64,
    /// Records rejected because the bounded spool was full. Every rejection is
    /// also accumulated in the durable `overflow.json` indicator.
    pub overflowed_records: u64,
}

/// Cloneable observability handle that does not grant queue mutation.
#[derive(Clone)]
pub struct DurableShippingStatusHandle {
    shared: Arc<Shared>,
}

impl DurableShippingStatusHandle {
    /// Read a lock-free status snapshot.
    #[must_use]
    pub fn snapshot(&self) -> DurableShippingStatus {
        self.shared.status()
    }
}

/// A durable local spool plus a dedicated ordered delivery worker.
pub struct DurableShippingForwarder {
    shared: Arc<Shared>,
    worker: Mutex<Option<JoinHandle<()>>>,
    _lock: SpoolLock,
}

impl DurableShippingForwarder {
    /// Open/recover a destination spool and start its delivery worker.
    ///
    /// # Errors
    /// Returns a transport error for invalid configuration, an unreadable or
    /// corrupt spool, or a destination-identity mismatch. Existing queued data
    /// is never silently discarded.
    pub fn open(
        config: DurableSpoolConfig,
        destination: Box<dyn ShippingForwarder>,
    ) -> Result<Self, ShippingError> {
        validate_config(&config)?;
        std::fs::create_dir_all(&config.directory).map_err(transport)?;
        let lock = SpoolLock::acquire(&config.directory)?;
        bind_destination(&config.directory, &config.destination_id)?;
        let pending = recover_pending(&config.directory)?;
        if pending.len() > config.max_records {
            return Err(ShippingError::Transport(format!(
                "audit shipping spool contains {} records, exceeding configured capacity {}",
                pending.len(),
                config.max_records
            )));
        }
        sync_directory(&config.directory).map_err(transport)?;
        let overflowed = load_overflow(&config.directory)?.map_or(0, |state| state.count);
        let pending_len = u64::try_from(pending.len()).unwrap_or(u64::MAX);
        tracing::info!(
            spool_dir = %config.directory.display(),
            destination_id = %config.destination_id,
            pending_records = pending_len,
            overflowed_records = overflowed,
            max_records = config.max_records,
            "audit shipping spool recovered"
        );
        let shared = Arc::new(Shared {
            config,
            queue: Mutex::new(pending),
            wake: Condvar::new(),
            stopping: AtomicBool::new(false),
            pending: AtomicU64::new(pending_len),
            delivered: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            overflowed: AtomicU64::new(overflowed),
        });
        let worker_shared = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("audit-shipping".to_owned())
            .spawn(move || run_worker(worker_shared, destination))
            .map_err(transport)?;
        Ok(Self {
            shared,
            worker: Mutex::new(Some(worker)),
            _lock: lock,
        })
    }

    /// Obtain a cloneable status handle before moving this forwarder into a
    /// trait object.
    #[must_use]
    pub fn status_handle(&self) -> DurableShippingStatusHandle {
        DurableShippingStatusHandle {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Signal the worker to stop, wait for any in-flight destination call, and
    /// leave every unacknowledged record durably queued for restart replay.
    pub fn shutdown(&self) {
        self.shared.stopping.store(true, Ordering::Release);
        self.shared.wake.notify_all();
        if let Some(worker) = self.worker.lock().take()
            && worker.join().is_err()
        {
            self.shared.failures.fetch_add(1, Ordering::Relaxed);
            tracing::error!("audit shipping worker panicked during shutdown");
        }
    }

    fn enqueue(&self, record: &AuditRecord) -> Result<(), ShippingError> {
        if self.shared.stopping.load(Ordering::Acquire) {
            return Err(ShippingError::Transport(
                "audit shipping worker is stopped".to_owned(),
            ));
        }
        let bytes = serde_json::to_vec(record).map_err(transport)?;
        let mut queue = self.shared.queue.lock();
        if let Some(path) = queue.get(&record.seq) {
            let existing = std::fs::read(path).map_err(transport)?;
            if existing == bytes {
                return Ok(());
            }
            return Err(ShippingError::Transport(format!(
                "spool sequence {} already contains a different signed record",
                record.seq
            )));
        }
        if queue.len() >= self.shared.config.max_records {
            record_overflow(&self.shared.config.directory, record)?;
            self.shared.overflowed.fetch_add(1, Ordering::Relaxed);
            return Err(ShippingError::Transport(format!(
                "audit shipping spool is full at {} records; durable overflow indicator updated",
                self.shared.config.max_records
            )));
        }
        let final_path = record_path(&self.shared.config.directory, record.seq);
        let temp_path = temp_record_path(&self.shared.config.directory, record.seq);
        write_new_file(&temp_path, &bytes)?;
        std::fs::rename(&temp_path, &final_path).map_err(transport)?;
        let directory_sync = sync_directory(&self.shared.config.directory);
        queue.insert(record.seq, final_path);
        let pending = self.shared.pending.fetch_add(1, Ordering::Relaxed) + 1;
        drop(queue);
        tracing::debug!(
            seq = record.seq,
            pending_records = pending,
            destination_id = %self.shared.config.destination_id,
            "signed audit record durably queued for shipping"
        );
        self.shared.wake.notify_one();
        directory_sync.map_err(transport)
    }
}

impl ShippingForwarder for DurableShippingForwarder {
    fn forward(&self, record: &AuditRecord) -> Result<(), ShippingError> {
        self.enqueue(record)
    }

    fn flush(&self) -> Result<(), ShippingError> {
        self.shared.wake.notify_one();
        Ok(())
    }
}

impl Drop for DurableShippingForwarder {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct Shared {
    config: DurableSpoolConfig,
    queue: Mutex<BTreeMap<u64, PathBuf>>,
    wake: Condvar,
    stopping: AtomicBool,
    pending: AtomicU64,
    delivered: AtomicU64,
    failures: AtomicU64,
    overflowed: AtomicU64,
}

struct SpoolLock(File);

impl SpoolLock {
    fn acquire(directory: &Path) -> Result<Self, ShippingError> {
        let path = directory.join("spool.lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(transport)?;
        match file.try_lock() {
            Ok(()) => Ok(Self(file)),
            Err(TryLockError::WouldBlock) => Err(ShippingError::Transport(format!(
                "audit shipping spool {} is already owned by another worker",
                directory.display()
            ))),
            Err(TryLockError::Error(error)) => Err(transport(error)),
        }
    }
}

impl Drop for SpoolLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

impl Shared {
    fn status(&self) -> DurableShippingStatus {
        DurableShippingStatus {
            pending_records: self.pending.load(Ordering::Relaxed),
            delivered_records: self.delivered.load(Ordering::Relaxed),
            delivery_failures: self.failures.load(Ordering::Relaxed),
            overflowed_records: self.overflowed.load(Ordering::Relaxed),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct DestinationBinding {
    version: u8,
    destination_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct OverflowIndicator {
    version: u8,
    count: u64,
    first_seq: u64,
    last_seq: u64,
    last_entry_hash: String,
}

fn validate_config(config: &DurableSpoolConfig) -> Result<(), ShippingError> {
    if config.destination_id.trim().is_empty() {
        return Err(ShippingError::Transport(
            "audit shipping destination identity is empty".to_owned(),
        ));
    }
    if config.max_records == 0 {
        return Err(ShippingError::Transport(
            "audit shipping spool capacity must be non-zero".to_owned(),
        ));
    }
    if config.retry_initial.is_zero()
        || config.retry_max.is_zero()
        || config.retry_initial > config.retry_max
    {
        return Err(ShippingError::Transport(
            "audit shipping retry delays must be non-zero and initial <= max".to_owned(),
        ));
    }
    Ok(())
}

fn bind_destination(directory: &Path, destination_id: &str) -> Result<(), ShippingError> {
    let path = directory.join("destination.json");
    if path.exists() {
        let bytes = std::fs::read(&path).map_err(transport)?;
        let binding: DestinationBinding = serde_json::from_slice(&bytes).map_err(transport)?;
        if binding.version != 1 || binding.destination_id != destination_id {
            return Err(ShippingError::Transport(
                "audit shipping spool belongs to a different destination".to_owned(),
            ));
        }
        return Ok(());
    }
    let binding = DestinationBinding {
        version: 1,
        destination_id: destination_id.to_owned(),
    };
    let bytes = serde_json::to_vec(&binding).map_err(transport)?;
    write_new_file(&path, &bytes)?;
    sync_directory(directory).map_err(transport)
}

fn recover_pending(directory: &Path) -> Result<BTreeMap<u64, PathBuf>, ShippingError> {
    let mut pending = BTreeMap::new();
    for entry in std::fs::read_dir(directory).map_err(transport)? {
        let entry = entry.map_err(transport)?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if let Some(seq) = parse_record_name(name, ".acked") {
            std::fs::remove_file(&path).map_err(transport)?;
            tracing::debug!(seq, "removed acknowledged audit spool residue");
            continue;
        }
        if let Some(seq) = parse_record_name(name, ".tmp") {
            let record = read_spooled_record(&path)?;
            if record.seq != seq {
                return Err(ShippingError::Transport(format!(
                    "audit spool temporary filename sequence {seq} disagrees with record {}",
                    record.seq
                )));
            }
            let final_path = record_path(directory, seq);
            if final_path.exists() {
                let existing = std::fs::read(&final_path).map_err(transport)?;
                let temporary = std::fs::read(&path).map_err(transport)?;
                if existing != temporary {
                    return Err(ShippingError::Transport(format!(
                        "audit spool has conflicting temporary record at sequence {seq}"
                    )));
                }
                std::fs::remove_file(&path).map_err(transport)?;
            } else {
                std::fs::rename(&path, &final_path).map_err(transport)?;
            }
            continue;
        }
        let Some(seq) = parse_record_name(name, ".json") else {
            continue;
        };
        let record = read_spooled_record(&path)?;
        if record.seq != seq {
            return Err(ShippingError::Transport(format!(
                "audit spool filename sequence {seq} disagrees with record {}",
                record.seq
            )));
        }
        pending.insert(seq, path);
    }
    // A recovered temporary file may have been promoted after its final-name
    // entry was already visited by read_dir, so perform a second narrow scan.
    for entry in std::fs::read_dir(directory).map_err(transport)? {
        let path = entry.map_err(transport)?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if let Some(seq) = parse_record_name(name, ".json") {
            pending.entry(seq).or_insert(path);
        }
    }
    Ok(pending)
}

fn run_worker(shared: Arc<Shared>, destination: Box<dyn ShippingForwarder>) {
    let mut retry = shared.config.retry_initial;
    loop {
        let next = {
            let mut queue = shared.queue.lock();
            while queue.is_empty() && !shared.stopping.load(Ordering::Acquire) {
                shared.wake.wait(&mut queue);
            }
            if shared.stopping.load(Ordering::Acquire) {
                return;
            }
            queue
                .first_key_value()
                .map(|(&seq, path)| (seq, path.clone()))
        };
        let Some((seq, path)) = next else {
            continue;
        };
        let result = catch_unwind(AssertUnwindSafe(|| {
            read_spooled_record(&path)
                .and_then(|record| destination.forward(&record))
                .and_then(|()| destination.flush())
        }))
        .unwrap_or_else(|_| {
            Err(ShippingError::Transport(
                "audit shipping destination panicked".to_owned(),
            ))
        });
        match result {
            Ok(()) => {
                if acknowledge(&shared, seq, &path).is_ok() {
                    retry = shared.config.retry_initial;
                } else {
                    shared.failures.fetch_add(1, Ordering::Relaxed);
                    wait_retry(&shared, retry);
                    retry = retry.saturating_mul(2).min(shared.config.retry_max);
                }
            }
            Err(error) => {
                shared.failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(seq, error = %error, "audit shipping delivery failed; record remains durably queued");
                wait_retry(&shared, retry);
                retry = retry.saturating_mul(2).min(shared.config.retry_max);
            }
        }
    }
}

fn wait_retry(shared: &Shared, delay: Duration) {
    let mut queue = shared.queue.lock();
    if !shared.stopping.load(Ordering::Acquire) {
        shared.wake.wait_for(&mut queue, delay);
    }
}

fn acknowledge(shared: &Shared, seq: u64, path: &Path) -> Result<(), ShippingError> {
    let acknowledged = acknowledged_path(&shared.config.directory, seq);
    std::fs::rename(path, &acknowledged).map_err(transport)?;
    let directory_sync = sync_directory(&shared.config.directory);
    {
        let mut queue = shared.queue.lock();
        if queue.remove(&seq).is_some() {
            let pending = shared.pending.fetch_sub(1, Ordering::Relaxed) - 1;
            let delivered = shared.delivered.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::debug!(
                seq,
                pending_records = pending,
                delivered_records = delivered,
                destination_id = %shared.config.destination_id,
                "audit shipping destination acknowledged record"
            );
        }
    }
    if let Err(error) = std::fs::remove_file(&acknowledged) {
        tracing::debug!(seq, %error, "acknowledged audit spool residue retained for restart cleanup");
    } else if let Err(error) = sync_directory(&shared.config.directory) {
        tracing::debug!(seq, %error, "could not fsync audit spool directory after ack cleanup");
    }
    directory_sync.map_err(transport)
}

fn record_overflow(directory: &Path, record: &AuditRecord) -> Result<(), ShippingError> {
    let path = directory.join("overflow.json");
    let mut state = load_overflow(directory)?.unwrap_or(OverflowIndicator {
        version: 1,
        count: 0,
        first_seq: record.seq,
        last_seq: record.seq,
        last_entry_hash: record.entry_hash.clone(),
    });
    state.count = state.count.saturating_add(1);
    state.last_seq = record.seq;
    state.last_entry_hash.clone_from(&record.entry_hash);
    let bytes = serde_json::to_vec(&state).map_err(transport)?;
    let temporary = directory.join("overflow.tmp");
    write_replace_file(&temporary, &bytes)?;
    std::fs::rename(&temporary, &path).map_err(transport)?;
    sync_directory(directory).map_err(transport)
}

fn load_overflow(directory: &Path) -> Result<Option<OverflowIndicator>, ShippingError> {
    let path = directory.join("overflow.json");
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(transport),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(transport(error)),
    }
}

fn read_spooled_record(path: &Path) -> Result<AuditRecord, ShippingError> {
    let bytes = std::fs::read(path).map_err(transport)?;
    serde_json::from_slice(&bytes).map_err(transport)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), ShippingError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(transport)?;
    file.write_all(bytes).map_err(transport)?;
    file.sync_all().map_err(transport)
}

fn write_replace_file(path: &Path, bytes: &[u8]) -> Result<(), ShippingError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(transport)?;
    file.write_all(bytes).map_err(transport)?;
    file.sync_all().map_err(transport)
}

fn record_path(directory: &Path, seq: u64) -> PathBuf {
    directory.join(format!("record-{seq:020}.json"))
}

fn temp_record_path(directory: &Path, seq: u64) -> PathBuf {
    directory.join(format!("record-{seq:020}.tmp"))
}

fn acknowledged_path(directory: &Path, seq: u64) -> PathBuf {
    directory.join(format!("record-{seq:020}.acked"))
}

fn parse_record_name(name: &str, suffix: &str) -> Option<u64> {
    name.strip_prefix("record-")?
        .strip_suffix(suffix)?
        .parse()
        .ok()
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> std::io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> std::io::Result<()> {
    Ok(())
}

fn transport(error: impl std::fmt::Display) -> ShippingError {
    ShippingError::Transport(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuditDecision, AuditEntryDraft, AuditError, AuditOutcome, AuditSink, AuditSubject, Auditor,
        GENESIS_HASH, MemoryAuditSink, SigningKey,
    };
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    fn key() -> SigningKey {
        SigningKey::new("qa14", b"0123456789abcdef0123456789abcdef".to_vec())
            .expect("valid test key")
    }

    fn draft(seq: u64) -> AuditEntryDraft {
        AuditEntryDraft {
            subject: AuditSubject::new("agent", "qa14"),
            db_evidence: None,
            cancel: None,
            result_masking: None,
            tool: "oracle_execute".to_owned(),
            sql: format!("DELETE FROM qa14 WHERE id={seq}"),
            danger_level: "DESTRUCTIVE".to_owned(),
            decision: AuditDecision::Allowed,
            rows_affected: Some(1),
            outcome: AuditOutcome::Succeeded,
        }
    }

    fn record(seq: u64) -> AuditRecord {
        AuditRecord::chained_signed(&draft(seq), seq, GENESIS_HASH, format!("t{seq}"), &key())
    }

    fn config(directory: &Path, id: &str) -> DurableSpoolConfig {
        DurableSpoolConfig::new(directory, id)
            .with_max_records(32)
            .with_retry(Duration::from_millis(5), Duration::from_millis(20))
    }

    fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) {
        let deadline = Instant::now() + timeout;
        while !predicate() {
            assert!(Instant::now() < deadline, "condition timed out");
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[derive(Default)]
    struct Capture {
        seqs: Mutex<Vec<u64>>,
    }

    impl ShippingForwarder for Capture {
        fn forward(&self, record: &AuditRecord) -> Result<(), ShippingError> {
            self.seqs.lock().push(record.seq);
            Ok(())
        }
    }

    struct SharedCapture(Arc<Capture>);

    impl ShippingForwarder for SharedCapture {
        fn forward(&self, record: &AuditRecord) -> Result<(), ShippingError> {
            self.0.forward(record)
        }
    }

struct SleepForwarder(Duration);

impl ShippingForwarder for SleepForwarder {
        fn forward(&self, _record: &AuditRecord) -> Result<(), ShippingError> {
            thread::sleep(self.0);
            Ok(())
        }
    }

    struct FlakyForwarder {
        attempts: Arc<AtomicUsize>,
    }

    impl ShippingForwarder for FlakyForwarder {
        fn forward(&self, _record: &AuditRecord) -> Result<(), ShippingError> {
            if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(ShippingError::Transport("temporary enqueue failure".to_owned()))
            } else {
                Ok(())
            }
        }
    }

    struct SharedLocal(Arc<MemoryAuditSink>);

    impl AuditSink for SharedLocal {
        fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.0.append(record)
        }

        fn flush(&self) -> Result<(), AuditError> {
            self.0.flush()
        }
    }

    #[test]
    fn slow_destination_does_not_delay_durable_local_append() {
        let directory = tempfile::tempdir().expect("tempdir");
        let local = Arc::new(MemoryAuditSink::new());
        let delivery = DurableShippingForwarder::open(
            config(directory.path(), "slow"),
            Box::new(SleepForwarder(Duration::from_millis(300))),
        )
        .expect("open spool");
        let status = delivery.status_handle();
        let sink = crate::ShippingAuditSink::new(
            Box::new(SharedLocal(Arc::clone(&local))),
            Box::new(delivery),
        );
        let auditor = Auditor::new(Box::new(sink), key());

        let started = Instant::now();
        auditor
            .append(&draft(1), "t1".to_owned(), true)
            .expect("local durable append");
        assert!(
            started.elapsed() < Duration::from_millis(150),
            "the destination sleep leaked back onto the audit mutex: {:?}",
            started.elapsed()
        );
        assert_eq!(local.records().len(), 1);
        assert_eq!(status.snapshot().pending_records, 1);
        wait_until(Duration::from_secs(2), || {
            status.snapshot().delivered_records == 1
        });
    }

    #[test]
    fn concurrent_local_chain_stays_gap_free_while_shipping_is_stalled() {
        let directory = tempfile::tempdir().expect("tempdir");
        let local = Arc::new(MemoryAuditSink::new());
        let delivery = DurableShippingForwarder::open(
            config(directory.path(), "concurrent"),
            Box::new(SleepForwarder(Duration::from_millis(400))),
        )
        .expect("open spool");
        let sink = crate::ShippingAuditSink::new(
            Box::new(SharedLocal(Arc::clone(&local))),
            Box::new(delivery),
        );
        let auditor = Arc::new(Auditor::new(Box::new(sink), key()));
        let started = Instant::now();
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let auditor = Arc::clone(&auditor);
                thread::spawn(move || {
                    auditor
                        .append(&draft(i), format!("t{i}"), true)
                        .expect("append")
                })
            })
            .collect();
        for worker in threads {
            worker.join().expect("append thread");
        }
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "concurrent appends waited for the stalled destination"
        );
        let records = local.records();
        assert_eq!(records.len(), 8);
        assert_eq!(
            records.iter().map(|record| record.seq).collect::<Vec<_>>(),
            (1..=8).collect::<Vec<_>>()
        );
        drop(auditor);
    }

    struct GateForwarder {
        gate: Arc<(Mutex<bool>, Condvar)>,
    }

    impl ShippingForwarder for GateForwarder {
        fn forward(&self, _record: &AuditRecord) -> Result<(), ShippingError> {
            let (open, wake) = &*self.gate;
            let mut open = open.lock();
            while !*open {
                wake.wait(&mut open);
            }
            Ok(())
        }
    }

    fn open_gate(gate: &Arc<(Mutex<bool>, Condvar)>) {
        let (open, wake) = &**gate;
        *open.lock() = true;
        wake.notify_all();
    }

    struct GateRelease(Arc<(Mutex<bool>, Condvar)>);

    impl Drop for GateRelease {
        fn drop(&mut self) {
            open_gate(&self.0);
        }
    }

    fn release_gate_on_drop(gate: &Arc<(Mutex<bool>, Condvar)>) -> GateRelease {
        GateRelease(Arc::clone(gate))
    }

    #[test]
    fn bounded_spool_persists_an_overflow_indicator() {
        let directory = tempfile::tempdir().expect("tempdir");
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let delivery = DurableShippingForwarder::open(
            config(directory.path(), "bounded").with_max_records(2),
            Box::new(GateForwarder {
                gate: Arc::clone(&gate),
            }),
        )
        .expect("open spool");
        let _release = release_gate_on_drop(&gate);
        let status = delivery.status_handle();
        assert!(delivery.forward(&record(1)).is_ok());
        assert!(delivery.forward(&record(2)).is_ok());
        assert!(delivery.forward(&record(3)).is_err());
        assert!(delivery.forward(&record(4)).is_err());
        let snapshot = status.snapshot();
        assert_eq!(snapshot.pending_records, 2);
        assert_eq!(snapshot.overflowed_records, 2);
        let indicator: OverflowIndicator = serde_json::from_slice(
            &std::fs::read(directory.path().join("overflow.json")).expect("overflow indicator"),
        )
        .expect("valid overflow indicator");
        assert_eq!(indicator.count, 2);
        assert_eq!((indicator.first_seq, indicator.last_seq), (3, 4));
        open_gate(&gate);
        wait_until(Duration::from_secs(2), || {
            status.snapshot().delivered_records == 2
        });
    }

    struct AlwaysFails;

    impl ShippingForwarder for AlwaysFails {
        fn forward(&self, _record: &AuditRecord) -> Result<(), ShippingError> {
            Err(ShippingError::Transport("offline".to_owned()))
        }
    }

    #[test]
    fn restart_replays_pending_records_once_and_in_order() {
        let directory = tempfile::tempdir().expect("tempdir");
        let cfg = config(directory.path(), "restart");
        {
            let delivery = DurableShippingForwarder::open(cfg.clone(), Box::new(AlwaysFails))
                .expect("open first worker");
            for seq in 1..=3 {
                delivery.forward(&record(seq)).expect("durable enqueue");
            }
            assert_eq!(delivery.status_handle().snapshot().pending_records, 3);
            delivery.shutdown();
        }
        let capture = Arc::new(Capture::default());
        let delivery =
            DurableShippingForwarder::open(cfg, Box::new(SharedCapture(Arc::clone(&capture))))
                .expect("recover worker");
        let status = delivery.status_handle();
        wait_until(Duration::from_secs(2), || {
            status.snapshot().delivered_records == 3
        });
        assert_eq!(*capture.seqs.lock(), vec![1, 2, 3]);
        assert_eq!(status.snapshot().pending_records, 0);
    }

    struct PairForwarder {
        first: DurableShippingForwarder,
        second: DurableShippingForwarder,
    }

    impl ShippingForwarder for PairForwarder {
        fn forward(&self, record: &AuditRecord) -> Result<(), ShippingError> {
            let first = self.first.forward(record);
            let second = self.second.forward(record);
            first.and(second)
        }
    }

    #[test]
    fn slow_destination_cannot_block_a_second_destination() {
        let root = tempfile::tempdir().expect("tempdir");
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let slow = DurableShippingForwarder::open(
            config(&root.path().join("slow"), "slow-destination"),
            Box::new(GateForwarder {
                gate: Arc::clone(&gate),
            }),
        )
        .expect("slow spool");
        let capture = Arc::new(Capture::default());
        let fast = DurableShippingForwarder::open(
            config(&root.path().join("fast"), "fast-destination"),
            Box::new(SharedCapture(Arc::clone(&capture))),
        )
        .expect("fast spool");
        let fast_status = fast.status_handle();
        let pair = PairForwarder {
            first: slow,
            second: fast,
        };
        let _release = release_gate_on_drop(&gate);
        pair.forward(&record(1)).expect("enqueue both");
        pair.forward(&record(2)).expect("enqueue both");
        wait_until(Duration::from_secs(1), || {
            fast_status.snapshot().delivered_records == 2
        });
        assert_eq!(*capture.seqs.lock(), vec![1, 2]);
        open_gate(&gate);
    }

    #[test]
    fn destination_reconfiguration_cannot_hijack_a_spool() {
        let directory = tempfile::tempdir().expect("tempdir");
        let first = DurableShippingForwarder::open(
            config(directory.path(), "destination-a"),
            Box::new(AlwaysFails),
        )
        .expect("first destination");
        first.forward(&record(1)).expect("enqueue");
        first.shutdown();
        drop(first);
        let error = match DurableShippingForwarder::open(
            config(directory.path(), "destination-b"),
            Box::new(Capture::default()),
        ) {
            Ok(_) => panic!("destination mismatch must fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("different destination"));
        assert!(record_path(directory.path(), 1).exists());
    }

    #[test]
    fn a_spool_refuses_a_second_concurrent_worker() {
        let directory = tempfile::tempdir().expect("tempdir");
        let first = DurableShippingForwarder::open(
            config(directory.path(), "single-owner"),
            Box::new(Capture::default()),
        )
        .expect("first worker");
        let error = match DurableShippingForwarder::open(
            config(directory.path(), "single-owner"),
            Box::new(Capture::default()),
        ) {
            Ok(_) => panic!("second worker must not share one spool"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("already owned"));
        drop(first);
        DurableShippingForwarder::open(
            config(directory.path(), "single-owner"),
            Box::new(Capture::default()),
        )
        .expect("lock releases after shutdown");
    }

    struct PanicOnce {
        calls: Arc<AtomicUsize>,
    }

    impl ShippingForwarder for PanicOnce {
        fn forward(&self, _record: &AuditRecord) -> Result<(), ShippingError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("simulated destination panic");
            }
            Ok(())
        }
    }

    #[test]
    fn worker_supervises_a_panicking_destination_and_retries() {
        let directory = tempfile::tempdir().expect("tempdir");
        let calls = Arc::new(AtomicUsize::new(0));
        let delivery = DurableShippingForwarder::open(
            config(directory.path(), "panic"),
            Box::new(PanicOnce {
                calls: Arc::clone(&calls),
            }),
        )
        .expect("open spool");
        let status = delivery.status_handle();
        delivery.forward(&record(1)).expect("enqueue");
        wait_until(Duration::from_secs(1), || {
            status.snapshot().delivered_records == 1
        });
        assert!(calls.load(Ordering::SeqCst) >= 2);
        assert!(status.snapshot().delivery_failures >= 1);
    }

    #[test]
    fn local_flush_failure_never_enqueues_to_the_spool() {
        struct LocalFlushFails;
        impl AuditSink for LocalFlushFails {
            fn append(&self, _record: &AuditRecord) -> Result<(), AuditError> {
                Ok(())
            }
            fn flush(&self) -> Result<(), AuditError> {
                Err(AuditError::Io("local fsync failed".to_owned()))
            }
        }

        let directory = tempfile::tempdir().expect("tempdir");
        let delivery = DurableShippingForwarder::open(
            config(directory.path(), "local-failure"),
            Box::new(Capture::default()),
        )
        .expect("open spool");
        let status = delivery.status_handle();
        let sink = crate::ShippingAuditSink::new(Box::new(LocalFlushFails), Box::new(delivery));
        sink.append(&record(1)).expect("buffer local record");
        assert!(sink.flush().is_err());
        assert_eq!(status.snapshot().pending_records, 0);
        assert!(!record_path(directory.path(), 1).exists());
    }

    #[test]
    fn spool_config_rejects_invalid_retry_bounds_and_accepts_equal_bounds() {
        let directory = tempfile::tempdir().expect("tempdir");
        let valid = config(directory.path(), "valid-destination");
        let equal_retries = valid.clone().with_retry(Duration::from_millis(20), Duration::from_millis(20));
        validate_config(&equal_retries).expect("equal retry bounds must be accepted");
    }

    #[test]
    fn forwarder_enqueue_rejects_records_when_capacity_is_exact() {
        let directory = tempfile::tempdir().expect("tempdir");
        let delivery = DurableShippingForwarder::open(
            config(directory.path(), "capacity-boundary").with_max_records(1),
            Box::new(AlwaysFails),
        )
        .expect("open spool");
        let status = delivery.status_handle();

        delivery.forward(&record(1)).expect("initial record fills spool capacity");
        assert_eq!(status.snapshot().pending_records, 1);

        let error = delivery
            .forward(&record(2))
            .expect_err("second record must fail at exact capacity boundary");
        assert!(
            error.to_string().contains("spool is full"),
            "unexpected enqueue overflow error: {error}"
        );
        assert_eq!(status.snapshot().pending_records, 1);
        assert!(!record_path(directory.path(), 2).exists());
    }

    #[test]
    fn durable_forwarder_drop_leaves_state_for_replay() {
        let directory = tempfile::tempdir().expect("tempdir");
        let cfg = config(directory.path(), "drop-persists");
        let delivery = DurableShippingForwarder::open(cfg.clone(), Box::new(AlwaysFails))
            .expect("open spool");
        delivery.forward(&record(1)).expect("persist one record for replay");
        drop(delivery);

        let recovery = DurableShippingForwarder::open(cfg, Box::new(Capture::default()))
            .expect("drop must release lock");
        assert_eq!(recovery.status_handle().snapshot().pending_records, 1);
        assert!(record_path(directory.path(), 1).exists());
    }

    #[test]
    fn flush_wakes_worker_out_of_retry_backoff() {
        let directory = tempfile::tempdir().expect("tempdir");
        let attempts = Arc::new(AtomicUsize::new(0));
        let cfg = config(directory.path(), "flush-wakes")
            .with_retry(Duration::from_millis(800), Duration::from_millis(800));
        let delivery = DurableShippingForwarder::open(
            cfg,
            Box::new(FlakyForwarder {
                attempts: Arc::clone(&attempts),
            }),
        )
        .expect("open spool");
        let status = delivery.status_handle();

        delivery.forward(&record(1)).expect("enqueue for retry path");
        wait_until(Duration::from_secs(1), || {
            status.snapshot().delivery_failures >= 1
                && status.snapshot().pending_records == 1
        });

        delivery.flush().expect("flush can unblock retry");
        wait_until(Duration::from_millis(250), || status.snapshot().pending_records == 0);
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn spool_config_rejects_empty_capacity_and_invalid_retry_bounds() {
        let directory = tempfile::tempdir().expect("tempdir");
        let valid = config(directory.path(), "valid-destination");
        validate_config(&valid).expect("baseline config is valid");

        let invalid_destination = config(directory.path(), " \t ");
        assert!(
            validate_config(&invalid_destination)
                .expect_err("blank destination id must fail closed")
                .to_string()
                .contains("destination identity is empty")
        );

        let zero_capacity = valid.clone().with_max_records(0);
        assert!(
            validate_config(&zero_capacity)
                .expect_err("zero capacity must fail closed")
                .to_string()
                .contains("capacity must be non-zero")
        );

        for bad in [
            valid
                .clone()
                .with_retry(Duration::ZERO, Duration::from_millis(20)),
            valid
                .clone()
                .with_retry(Duration::from_millis(5), Duration::ZERO),
            valid
                .clone()
                .with_retry(Duration::from_millis(30), Duration::from_millis(20)),
        ] {
            assert!(
                validate_config(&bad)
                    .expect_err("invalid retry bounds must fail closed")
                    .to_string()
                    .contains("retry delays must be non-zero and initial <= max")
            );
        }
    }

    #[test]
    fn shutdown_stops_future_enqueue_attempts() {
        let directory = tempfile::tempdir().expect("tempdir");
        let delivery = DurableShippingForwarder::open(
            config(directory.path(), "shutdown"),
            Box::new(Capture::default()),
        )
        .expect("open spool");

        delivery.shutdown();
        let error = delivery
            .forward(&record(1))
            .expect_err("shutdown forwarder must fail closed to new records");
        assert!(
            error.to_string().contains("worker is stopped"),
            "unexpected shutdown error: {error}"
        );
    }

    #[test]
    fn recovered_spool_capacity_allows_exact_boundary_only() {
        let directory = tempfile::tempdir().expect("tempdir");
        for seq in 1..=2 {
            let bytes = serde_json::to_vec(&record(seq)).expect("serialize record");
            write_new_file(&record_path(directory.path(), seq), &bytes)
                .expect("seed pending record");
        }

        let cfg = config(directory.path(), "capacity").with_max_records(2);
        let delivery =
            DurableShippingForwarder::open(cfg.clone(), Box::new(AlwaysFails)).expect("at cap");
        assert_eq!(delivery.status_handle().snapshot().pending_records, 2);
        delivery.shutdown();
        drop(delivery);

        let error =
            match DurableShippingForwarder::open(cfg.with_max_records(1), Box::new(AlwaysFails)) {
                Err(error) => error,
                Ok(_) => panic!("over-capacity recovered spool must fail"),
            };
        assert!(
            error.to_string().contains("exceeding configured capacity"),
            "unexpected capacity error: {error}"
        );
    }

    #[test]
    fn duplicate_spool_sequence_must_be_byte_identical() {
        let directory = tempfile::tempdir().expect("tempdir");
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let delivery = DurableShippingForwarder::open(
            config(directory.path(), "duplicate"),
            Box::new(GateForwarder {
                gate: Arc::clone(&gate),
            }),
        )
        .expect("open spool");
        let _release = release_gate_on_drop(&gate);
        let original = record(1);
        let conflicting = AuditRecord::chained_signed(
            &draft(99),
            1,
            GENESIS_HASH,
            "different timestamp".to_owned(),
            &key(),
        );

        delivery.forward(&original).expect("initial enqueue");
        assert_eq!(delivery.status_handle().snapshot().pending_records, 1);
        delivery
            .forward(&original)
            .expect("byte-identical replay is idempotent");
        assert_eq!(
            delivery.status_handle().snapshot().pending_records,
            1,
            "idempotent replay must not double-count pending records"
        );
        let error = delivery
            .forward(&conflicting)
            .expect_err("same sequence with different bytes must fail closed");
        assert!(
            error
                .to_string()
                .contains("already contains a different signed record"),
            "unexpected duplicate error: {error}"
        );
        open_gate(&gate);
    }

    #[test]
    fn recovery_promotes_matching_temporary_record() {
        let directory = tempfile::tempdir().expect("tempdir");
        let rec = record(7);
        let tmp = temp_record_path(directory.path(), rec.seq);
        let bytes = serde_json::to_vec(&rec).expect("serialize record");
        write_new_file(&tmp, &bytes).expect("write temp record");

        let pending = recover_pending(directory.path()).expect("recover temp");
        let final_path = record_path(directory.path(), rec.seq);
        assert_eq!(pending.get(&rec.seq), Some(&final_path));
        assert!(final_path.exists(), "matching temporary record is promoted");
        assert!(!tmp.exists(), "temporary name is consumed during recovery");
    }

    #[test]
    fn recovery_rejects_temporary_record_sequence_mismatch() {
        let directory = tempfile::tempdir().expect("tempdir");
        let rec = record(8);
        let tmp = temp_record_path(directory.path(), 9);
        let bytes = serde_json::to_vec(&rec).expect("serialize record");
        write_new_file(&tmp, &bytes).expect("write mismatched temp record");

        let error = recover_pending(directory.path()).expect_err("mismatched temp sequence");
        assert!(
            error.to_string().contains("temporary filename sequence 9"),
            "unexpected recovery error: {error}"
        );
    }

    #[test]
    fn acknowledge_advances_delivery_counters_without_off_by_one() {
        let directory = tempfile::tempdir().expect("tempdir");
        let cfg = config(directory.path(), "ack-counters");
        let path_one = record_path(directory.path(), 1);
        let path_two = record_path(directory.path(), 2);
        write_new_file(
            &path_one,
            &serde_json::to_vec(&record(1)).expect("serialize record one"),
        )
        .expect("seed first queued record");
        write_new_file(
            &path_two,
            &serde_json::to_vec(&record(2)).expect("serialize record two"),
        )
        .expect("seed second queued record");

        let shared = Shared {
            config: cfg,
            queue: Mutex::new(BTreeMap::from_iter([
                (1, path_one.clone()),
                (2, path_two.clone()),
            ])),
            wake: Condvar::new(),
            stopping: AtomicBool::new(false),
            pending: AtomicU64::new(2),
            delivered: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            overflowed: AtomicU64::new(0),
        };

        assert_eq!(
            shared.status().pending_records,
            2,
            "setup confirms both records are queued"
        );
        acknowledge(&shared, 1, &path_one).expect("ack sequence 1");
        assert_eq!(
            shared.status().pending_records,
            1,
            "pending should decrement by one exactly once"
        );
        assert_eq!(
            shared.status().delivered_records,
            1,
            "delivered should increment by one exactly once"
        );

        acknowledge(&shared, 2, &path_two).expect("ack sequence 2");
        assert_eq!(
            shared.status().pending_records,
            0,
            "second ack should drain the queue"
        );
        assert_eq!(
            shared.status().delivered_records,
            2,
            "two successful acks should increment delivered twice"
        );
        assert!(
            !path_one.exists(),
            "acked record should be removed from durable queue path"
        );
        assert!(
            !path_two.exists(),
            "acked record should be removed from durable queue path"
        );
    }

    #[test]
    fn acknowledge_unknown_seq_is_rejected_or_noops_without_counter_corruption() {
        let directory = tempfile::tempdir().expect("tempdir");
        let cfg = config(directory.path(), "ack-unknown");
        let known_path = record_path(directory.path(), 1);
        let unknown_seq_path = record_path(directory.path(), 99);
        write_new_file(
            &known_path,
            &serde_json::to_vec(&record(1)).expect("serialize known record"),
        )
        .expect("seed known queued record");
        write_new_file(
            &unknown_seq_path,
            &serde_json::to_vec(&record(99)).expect("serialize unknown sequence"),
        )
        .expect("seed unknown sequence file");

        let shared = Shared {
            config: cfg,
            queue: Mutex::new(BTreeMap::from_iter([(1u64, known_path.clone())])),
            wake: Condvar::new(),
            stopping: AtomicBool::new(false),
            pending: AtomicU64::new(1),
            delivered: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            overflowed: AtomicU64::new(0),
        };
        let before = shared.status();

        assert!(acknowledge(&shared, 99, &unknown_seq_path).is_ok());
        let after = shared.status();
        assert_eq!(
            after.pending_records, before.pending_records,
            "unknown sequence must not reduce pending"
        );
        assert_eq!(
            after.delivered_records, before.delivered_records,
            "unknown sequence must not increase delivered"
        );
        assert!(
            !unknown_seq_path.exists(),
            "acknowledging an unknown sequence cannot silently keep a durable queue file"
        );
        assert!(
            known_path.exists(),
            "known queued records remain queued when unknown seq is acknowledged"
        );
    }

    #[derive(Clone, Default)]
    struct FieldCapture {
        fields: Arc<Mutex<std::collections::HashMap<String, u64>>>,
    }
    impl tracing::Subscriber for FieldCapture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct V<'a>(&'a mut std::collections::HashMap<String, u64>);
            impl tracing::field::Visit for V<'_> {
                fn record_u64(&mut self, f: &tracing::field::Field, v: u64) {
                    self.0.insert(f.name().to_owned(), v);
                }
                fn record_i64(&mut self, f: &tracing::field::Field, v: i64) {
                    if let Ok(v) = u64::try_from(v) {
                        self.0.insert(f.name().to_owned(), v);
                    }
                }
                fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
            }
            let mut g = self.fields.lock();
            event.record(&mut V(&mut g));
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(tracing::level_filters::LevelFilter::TRACE)
        }
    }

    // GATE-SEAL residue: `acknowledge` computes `pending`/`delivered` locals for
    // its debug log via `fetch_sub(1) - 1` / `fetch_add(1) + 1`. The atomics
    // (observable via `status()`) are correct regardless of the `- 1`/`+ 1`, so
    // only the LOGGED field values distinguish the mutants. `acknowledge` runs
    // here on the test thread, so a thread-local subscriber observes them.
    #[test]
    fn acknowledge_debug_log_reports_pending_zero_and_delivered_one() {
        let directory = tempfile::tempdir().expect("tempdir");
        let cfg = config(directory.path(), "ack-log");
        let known_path = record_path(directory.path(), 1);
        write_new_file(
            &known_path,
            &serde_json::to_vec(&record(1)).expect("serialize"),
        )
        .expect("seed");
        let shared = Shared {
            config: cfg,
            queue: Mutex::new(BTreeMap::from_iter([(1u64, known_path.clone())])),
            wake: Condvar::new(),
            stopping: AtomicBool::new(false),
            pending: AtomicU64::new(1),
            delivered: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            overflowed: AtomicU64::new(0),
        };
        let cap = FieldCapture::default();
        let fields = Arc::clone(&cap.fields);
        tracing::subscriber::with_default(cap, || {
            acknowledge(&shared, 1, &known_path).expect("ack ok");
        });
        let g = fields.lock();
        assert_eq!(
            g.get("pending_records").copied(),
            Some(0),
            "acknowledging the only queued record must log pending_records = 1 - 1 = 0"
        );
        assert_eq!(
            g.get("delivered_records").copied(),
            Some(1),
            "the first acknowledgement must log delivered_records = 0 + 1 = 1"
        );
    }

    // GATE-SEAL residue: `enqueue` logs `pending_records = fetch_add(1) + 1`.
    // Same observability shape as `acknowledge` above. Construct the forwarder
    // without a worker so nothing consumes the queue concurrently.
    #[test]
    fn enqueue_debug_log_reports_incremented_pending() {
        let directory = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(directory.path()).expect("dir");
        let cfg = config(directory.path(), "enqueue-log");
        let lock = SpoolLock::acquire(directory.path()).expect("spool lock");
        let forwarder = DurableShippingForwarder {
            shared: Arc::new(Shared {
                config: cfg,
                queue: Mutex::new(BTreeMap::new()),
                wake: Condvar::new(),
                stopping: AtomicBool::new(false),
                pending: AtomicU64::new(0),
                delivered: AtomicU64::new(0),
                failures: AtomicU64::new(0),
                overflowed: AtomicU64::new(0),
            }),
            worker: Mutex::new(None),
            _lock: lock,
        };
        let cap = FieldCapture::default();
        let fields = Arc::clone(&cap.fields);
        tracing::subscriber::with_default(cap, || {
            forwarder.enqueue(&record(1)).expect("enqueue ok");
        });
        let g = fields.lock();
        assert_eq!(
            g.get("pending_records").copied(),
            Some(1),
            "enqueuing the first record must log pending_records = 0 + 1 = 1"
        );
    }

    // GATE-SEAL residue: `recover_pending` compares a recovered `.tmp` against an
    // already-promoted final record. Identical content must dedupe (remove the
    // tmp and recover cleanly); the `!=` guard mutated to `==` would instead
    // REJECT identical content as a conflict.
    #[test]
    fn recover_pending_dedupes_a_temp_matching_its_promoted_final() {
        let directory = tempfile::tempdir().expect("tempdir");
        let bytes = serde_json::to_vec(&record(7)).expect("serialize");
        let final_path = record_path(directory.path(), 7);
        let tmp_path = temp_record_path(directory.path(), 7);
        std::fs::write(&final_path, &bytes).expect("seed final");
        std::fs::write(&tmp_path, &bytes).expect("seed identical tmp");
        let pending = recover_pending(directory.path())
            .expect("identical temp+final content must recover cleanly, not conflict");
        assert!(
            !tmp_path.exists(),
            "an identical temporary must be deduped away during recovery"
        );
        assert!(
            pending.contains_key(&7),
            "the promoted final record must be recovered as pending"
        );
    }

    // GATE-SEAL residue: `load_overflow` maps a NotFound read to `Ok(None)` but
    // must PROPAGATE any other read error. The guard mutated to `true` would
    // swallow a non-NotFound error as "no overflow".
    #[test]
    fn load_overflow_propagates_non_notfound_read_errors() {
        let directory = tempfile::tempdir().expect("tempdir");
        // Make `overflow.json` a directory: `std::fs::read` then fails with an
        // error whose kind is NOT NotFound.
        std::fs::create_dir(directory.path().join("overflow.json")).expect("mkdir overflow.json");
        assert!(
            load_overflow(directory.path()).is_err(),
            "a non-NotFound read error must propagate, not be treated as absent overflow"
        );
    }

    // GATE-SEAL residue: `sync_directory` fsyncs a directory handle; the FnValue
    // mutant replaces the body with `Ok(())`. The error path is reachable by
    // pointing it at a directory that cannot be opened.
    #[cfg(unix)]
    #[test]
    fn sync_directory_reports_failure_for_an_unopenable_directory() {
        let missing = std::path::Path::new("/proc/self/nonexistent-audit-dir-xyzzy");
        assert!(
            sync_directory(missing).is_err(),
            "fsync of an unopenable directory must surface the open error"
        );
    }

    // GATE-SEAL residue: `Drop for DurableShippingForwarder` calls `shutdown()`,
    // which signals and JOINS the worker; a no-op drop leaves the worker parked
    // forever. When the worker returns it drops the boxed destination, so an
    // observable destination `Drop` proves the join happened.
    #[test]
    fn drop_shuts_down_and_joins_the_worker() {
        struct DropSignal(Arc<AtomicBool>);
        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        impl ShippingForwarder for DropSignal {
            fn forward(&self, _record: &AuditRecord) -> Result<(), ShippingError> {
                Ok(())
            }
        }
        let directory = tempfile::tempdir().expect("tempdir");
        let dropped = Arc::new(AtomicBool::new(false));
        let forwarder = DurableShippingForwarder::open(
            config(directory.path(), "drop-join"),
            Box::new(DropSignal(Arc::clone(&dropped))),
        )
        .expect("open spool");
        drop(forwarder);
        assert!(
            dropped.load(Ordering::SeqCst),
            "dropping the forwarder must join the worker, which drops the destination"
        );
    }
}
