//! Bounded, durable, asynchronous delivery for audit-shipping destinations.
//!
//! [`DurableShippingForwarder`] turns a blocking [`ShippingForwarder`] into a
//! fast local enqueue operation. Each signed record is atomically persisted as
//! an individual spool file before `forward` returns; a dedicated worker then
//! performs destination I/O without holding the [`crate::Auditor`] chain lock.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, TryLockError};
use std::io::{Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};
use serde::{Deserialize, Serialize};

use crate::sink::{create_new_private_file, open_private_lock_file, open_private_read_file};
use crate::{AuditRecord, AuthenticatedAuditTail, ShippingError, ShippingForwarder, SigningKey};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

/// Default maximum number of undelivered records retained per destination.
pub const DEFAULT_SPOOL_MAX_RECORDS: usize = 4_096;
/// Absolute record-count ceiling accepted from any caller. Recovery retains
/// authenticated record metadata, so a public configuration value must not be
/// able to turn the count bound into an effectively unbounded allocation.
pub const MAX_SPOOL_RECORDS: usize = DEFAULT_SPOOL_MAX_RECORDS;
/// Absolute aggregate byte budget for all recognized recovery artifacts.
pub const MAX_SPOOL_RECOVERY_BYTES: usize = 64 * 1024 * 1024;
/// Initial retry delay after a destination delivery failure.
pub const DEFAULT_SPOOL_RETRY_INITIAL: Duration = Duration::from_millis(250);
/// Maximum retry delay after repeated destination delivery failures.
pub const DEFAULT_SPOOL_RETRY_MAX: Duration = Duration::from_secs(30);
/// Maximum wall time allowed for one synchronous destination call.
pub const DEFAULT_SPOOL_DESTINATION_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum time a shutdown caller waits for the delivery worker.
pub const DEFAULT_SPOOL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
/// Backstop for a stop notification that lands in the worker's atomic
/// check-to-park window while another thread exhausts its bounded mutex wait.
const WORKER_STOP_RECHECK_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Debug, PartialEq, Eq)]
struct ChainTail {
    seq: u64,
    entry_hash: String,
}

impl ChainTail {
    fn genesis() -> Self {
        Self {
            seq: 0,
            entry_hash: crate::GENESIS_HASH.to_owned(),
        }
    }

    fn from_optional(value: Option<(u64, String)>) -> Self {
        value.map_or_else(Self::genesis, |(seq, entry_hash)| Self { seq, entry_hash })
    }

    fn from_record(record: &AuditRecord) -> Self {
        Self {
            seq: record.seq,
            entry_hash: record.entry_hash.clone(),
        }
    }
}

/// Configuration for one destination's durable delivery worker.
#[derive(Clone)]
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
    /// Deadline enforced around one blocking destination call.
    pub destination_timeout: Duration,
    /// Budget for joining the owned worker during shutdown.
    pub shutdown_timeout: Duration,
    /// Audit keys accepted for recovered-record signature verification.
    verification_keys: Vec<SigningKey>,
    /// Tail of the already-verified authoritative primary ledger at startup.
    /// Production construction always supplies this; `None` is retained only
    /// for lower-level embedders that do not own a [`FileAuditSink`].
    authoritative_tail: Option<ChainTail>,
}

impl std::fmt::Debug for DurableSpoolConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurableSpoolConfig")
            .field("directory", &self.directory)
            .field("destination_id", &self.destination_id)
            .field("max_records", &self.max_records)
            .field("retry_initial", &self.retry_initial)
            .field("retry_max", &self.retry_max)
            .field("destination_timeout", &self.destination_timeout)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .field(
                "verification_key_ids",
                &self
                    .verification_keys
                    .iter()
                    .map(SigningKey::key_id)
                    .collect::<Vec<_>>(),
            )
            .field("authoritative_tail", &self.authoritative_tail)
            .finish()
    }
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
            destination_timeout: DEFAULT_SPOOL_DESTINATION_TIMEOUT,
            shutdown_timeout: DEFAULT_SPOOL_SHUTDOWN_TIMEOUT,
            verification_keys: Vec::new(),
            authoritative_tail: None,
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

    /// Supply the trusted audit keys used to authenticate recovered records.
    /// The first key is the active signer used for new delivery checkpoints;
    /// remaining keys are historical verification keys.
    #[must_use]
    pub fn with_verification_keys(mut self, keys: impl IntoIterator<Item = SigningKey>) -> Self {
        self.verification_keys = keys.into_iter().collect();
        self
    }

    /// Bind recovery to the exact cryptographically authenticated primary
    /// ledger tail. The opaque proof is produced before shipping recovery by
    /// [`crate::FileAuditSink::authenticate_existing_chain`].
    #[must_use]
    pub fn with_authenticated_primary(mut self, primary: &AuthenticatedAuditTail) -> Self {
        self.authoritative_tail = Some(ChainTail::from_optional(primary.chain_tail()));
        self
    }

    /// Override destination-call and shutdown deadlines.
    #[must_use]
    pub fn with_timeouts(mut self, destination: Duration, shutdown: Duration) -> Self {
        self.destination_timeout = destination;
        self.shutdown_timeout = shutdown;
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
    /// Destination calls that exceeded the configured deadline.
    pub destination_timeouts: u64,
    /// Shutdown calls that exhausted their bounded join budget.
    pub shutdown_timeouts: u64,
    /// Whether the delivery worker has not yet terminated.
    pub worker_running: bool,
}

/// Result of a bounded durable-shipping shutdown request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableShippingShutdownOutcome {
    /// The worker terminated and its owned handle was joined.
    Stopped,
    /// The shutdown budget expired. Unacknowledged records remain on disk.
    TimedOut,
}

/// Cloneable observability handle that does not grant queue mutation.
#[derive(Clone)]
pub struct DurableShippingStatusHandle {
    shared: Arc<SpoolShared>,
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
    shared: Arc<SpoolShared>,
    worker: Mutex<Option<JoinHandle<()>>>,
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
        secure_spool_directory(&config.directory)?;
        let lock = SpoolLock::acquire(&config.directory)?;
        bind_destination(&config.directory, &config.destination_id)?;
        let recovered = recover_for_open(&config, destination.as_ref())?;
        let overflowed = recovered.overflow.as_ref().map_or(0, |state| state.count);
        let pending_len = u64::try_from(recovered.queue.len()).unwrap_or(u64::MAX);
        tracing::info!(
            spool_dir = %config.directory.display(),
            destination_id = %config.destination_id,
            pending_records = pending_len,
            overflowed_records = overflowed,
            max_records = config.max_records,
            "audit shipping spool recovered"
        );
        let shared = Arc::new(SpoolShared {
            config,
            queue: Mutex::new(recovered.queue),
            checkpoint: Mutex::new(recovered.checkpoint),
            overflow_state: Mutex::new(recovered.overflow),
            admitted_tail: Mutex::new(recovered.admitted_tail),
            wake: Condvar::new(),
            enqueue_closed: AtomicBool::new(false),
            worker_stop: AtomicBool::new(false),
            pending: AtomicU64::new(pending_len),
            pending_bytes: AtomicU64::new(
                u64::try_from(recovered.pending_bytes).unwrap_or(u64::MAX),
            ),
            delivered: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            overflowed: AtomicU64::new(overflowed),
            overflow_poisoned: AtomicBool::new(false),
            destination_timeouts: AtomicU64::new(0),
            shutdown_timeouts: AtomicU64::new(0),
            worker_running: AtomicBool::new(true),
            completion: WorkerCompletion {
                done: Mutex::new(false),
                wake: Condvar::new(),
            },
        });
        let worker_shared = Arc::clone(&shared);
        let destination: Arc<dyn ShippingForwarder> = Arc::from(destination);
        let worker = thread::Builder::new()
            .name("audit-shipping".to_owned())
            .spawn(move || {
                // The worker, not the facade, owns the filesystem lease. A
                // bounded shutdown may return before an in-flight destination
                // call does, but no successor can touch this spool until the
                // old worker has permanently lost acknowledgement authority.
                let _lock = lock;
                let _completion = WorkerCompletionGuard(Arc::clone(&worker_shared));
                run_worker(worker_shared, destination);
            })
            .map_err(transport)?;
        Ok(Self {
            shared,
            worker: Mutex::new(Some(worker)),
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
    pub fn shutdown(&self) -> DurableShippingShutdownOutcome {
        let started = Instant::now();
        self.shared.enqueue_closed.store(true, Ordering::Release);
        self.shared.worker_stop.store(true, Ordering::Release);
        // Wake a worker that was already parked before attempting the mutex
        // bridge. The second notify below closes the check-to-park window.
        self.shared.wake.notify_all();
        // Bridge the store above and the notify below with the queue mutex:
        // the worker evaluates `worker_stop` under this mutex right before
        // parking in `wake.wait`, so without this lock both the store and the
        // notify can land inside that check-to-park window — the notify finds
        // no parked waiter, the worker parks forever, and the `join` below
        // hangs the caller (observed as a 75-minute Windows CI timeout in
        // a_spool_refuses_a_second_concurrent_worker). Acquiring the mutex
        // here waits only inside the configured shutdown budget. If acquired,
        // the worker has either parked (wait releases the lock) or re-checked
        // `worker_stop`, so the second notify always lands.
        let remaining = self
            .shared
            .config
            .shutdown_timeout
            .saturating_sub(started.elapsed());
        let Some(queue) = self.shared.queue.try_lock_for(remaining) else {
            self.shared
                .shutdown_timeouts
                .fetch_add(1, Ordering::Relaxed);
            self.shared.wake.notify_all();
            return DurableShippingShutdownOutcome::TimedOut;
        };
        drop(queue);
        self.shared.wake.notify_all();
        let mut done = self.shared.completion.done.lock();
        while !*done {
            let remaining = self
                .shared
                .config
                .shutdown_timeout
                .saturating_sub(started.elapsed());
            if remaining.is_zero() {
                self.shared
                    .shutdown_timeouts
                    .fetch_add(1, Ordering::Relaxed);
                return DurableShippingShutdownOutcome::TimedOut;
            }
            self.shared.completion.wake.wait_for(&mut done, remaining);
        }
        drop(done);
        let mut worker = self.worker.lock();
        while worker.as_ref().is_some_and(|worker| !worker.is_finished()) {
            if started.elapsed() >= self.shared.config.shutdown_timeout {
                self.shared
                    .shutdown_timeouts
                    .fetch_add(1, Ordering::Relaxed);
                return DurableShippingShutdownOutcome::TimedOut;
            }
            thread::yield_now();
        }
        if let Some(worker) = worker.take()
            && worker.join().is_err()
        {
            self.shared.failures.fetch_add(1, Ordering::Relaxed);
            tracing::error!("audit shipping worker panicked during shutdown");
        }
        DurableShippingShutdownOutcome::Stopped
    }

    fn enqueue(&self, record: &AuditRecord) -> Result<(), ShippingError> {
        if self.shared.enqueue_closed.load(Ordering::Acquire) {
            return Err(ShippingError::Transport(
                "audit shipping worker is stopped".to_owned(),
            ));
        }
        verify_record_signature(record, &self.shared.config.verification_keys)?;
        let bytes = serde_json::to_vec(record).map_err(transport)?;
        if bytes.len() > crate::MAX_AUDIT_LINE_LEN {
            return Err(ShippingError::Transport(format!(
                "audit shipping record {} is {} bytes, exceeding the {}-byte spool file limit",
                record.seq,
                bytes.len(),
                crate::MAX_AUDIT_LINE_LEN
            )));
        }
        let mut queue = self.shared.queue.lock();
        if self.shared.enqueue_closed.load(Ordering::Acquire) {
            return Err(ShippingError::Transport(
                "audit shipping worker is stopped".to_owned(),
            ));
        }
        if let Some(queued) = queue.get(&record.seq) {
            let existing = read_private_bytes(&queued.path)?;
            if existing == bytes {
                return Ok(());
            }
            return Err(ShippingError::Transport(format!(
                "spool sequence {} already contains a different signed record",
                record.seq
            )));
        }
        let mut admitted_tail = self.shared.admitted_tail.lock();
        if record.seq == admitted_tail.seq && record.entry_hash == admitted_tail.entry_hash {
            return Ok(());
        }
        if queue.len() >= self.shared.config.max_records {
            if record_overflow(&self.shared, record)? {
                self.shared.overflowed.fetch_add(1, Ordering::Relaxed);
            }
            return Err(ShippingError::Transport(format!(
                "audit shipping spool is full at {} records; durable overflow indicator updated",
                self.shared.config.max_records
            )));
        }
        let pending_bytes = self.shared.pending_bytes.load(Ordering::Relaxed);
        let Some(next_pending_bytes) = checked_pending_byte_total(pending_bytes, bytes.len())
        else {
            if record_overflow(&self.shared, record)? {
                self.shared.overflowed.fetch_add(1, Ordering::Relaxed);
            }
            return Err(ShippingError::Transport(format!(
                "audit shipping spool would exceed its {MAX_SPOOL_RECOVERY_BYTES}-byte recovery budget; durable overflow indicator updated"
            )));
        };
        if record.seq != admitted_tail.seq.saturating_add(1)
            || record.prev_hash != admitted_tail.entry_hash
        {
            return Err(spool_integrity(
                Some(record.seq),
                format!(
                    "record does not continue the admitted spool tail at sequence {}",
                    admitted_tail.seq
                ),
            ));
        }
        let final_path = record_path(&self.shared.config.directory, record.seq);
        let temp_path = random_temp_record_path(&self.shared.config.directory, record.seq)?;
        write_new_file(&temp_path, &bytes)?;
        std::fs::rename(&temp_path, &final_path).map_err(transport)?;
        let directory_sync = sync_directory(&self.shared.config.directory);
        queue.insert(
            record.seq,
            QueuedRecord {
                path: final_path,
                byte_len: bytes.len(),
                entry_hash: record.entry_hash.clone(),
            },
        );
        *admitted_tail = ChainTail::from_record(record);
        self.shared
            .pending_bytes
            .store(next_pending_bytes, Ordering::Relaxed);
        let pending = self.shared.pending.fetch_add(1, Ordering::Relaxed) + 1;
        drop(admitted_tail);
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

fn checked_pending_byte_total(current: u64, next_record: usize) -> Option<u64> {
    let next_record = u64::try_from(next_record).ok()?;
    current
        .checked_add(next_record)
        .filter(|total| *total <= MAX_SPOOL_RECOVERY_BYTES as u64)
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
        if !self.shared.enqueue_closed.load(Ordering::Acquire)
            || *self.shared.completion.done.lock()
        {
            let _ = self.shutdown();
        }
    }
}

struct SpoolShared {
    config: DurableSpoolConfig,
    queue: Mutex<BTreeMap<u64, QueuedRecord>>,
    checkpoint: Mutex<DeliveryCheckpoint>,
    overflow_state: Mutex<Option<OverflowIndicator>>,
    admitted_tail: Mutex<ChainTail>,
    wake: Condvar,
    /// Set only by an explicit facade shutdown; closes future durable enqueues.
    enqueue_closed: AtomicBool,
    /// Stops destination delivery without disabling durable enqueue/overflow.
    worker_stop: AtomicBool,
    pending: AtomicU64,
    pending_bytes: AtomicU64,
    delivered: AtomicU64,
    failures: AtomicU64,
    overflowed: AtomicU64,
    /// Set if updating the signed overflow file and its checkpoint commitment
    /// could not complete as one logical transition. Future overflow writes
    /// refuse rather than overwrite evidence whose on-disk state is uncertain.
    overflow_poisoned: AtomicBool,
    destination_timeouts: AtomicU64,
    shutdown_timeouts: AtomicU64,
    worker_running: AtomicBool,
    completion: WorkerCompletion,
}

struct WorkerCompletion {
    done: Mutex<bool>,
    wake: Condvar,
}

struct WorkerCompletionGuard(Arc<SpoolShared>);

impl Drop for WorkerCompletionGuard {
    fn drop(&mut self) {
        // This guard is declared after the worker-owned filesystem lease, so
        // it drops first. Revoke durable enqueue authority before a successor
        // can acquire that lease and write the same spool.
        self.0.enqueue_closed.store(true, Ordering::Release);
        self.0.worker_running.store(false, Ordering::Release);
        *self.0.completion.done.lock() = true;
        self.0.completion.wake.notify_all();
    }
}

struct SpoolLock(File);

impl SpoolLock {
    fn acquire(directory: &Path) -> Result<Self, ShippingError> {
        let path = directory.join("spool.lock");
        let file = open_private_lock_file(&path).map_err(transport)?;
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

impl SpoolShared {
    fn status(&self) -> DurableShippingStatus {
        DurableShippingStatus {
            pending_records: self.pending.load(Ordering::Relaxed),
            delivered_records: self.delivered.load(Ordering::Relaxed),
            delivery_failures: self.failures.load(Ordering::Relaxed),
            overflowed_records: self.overflowed.load(Ordering::Relaxed),
            destination_timeouts: self.destination_timeouts.load(Ordering::Relaxed),
            shutdown_timeouts: self.shutdown_timeouts.load(Ordering::Relaxed),
            worker_running: self.worker_running.load(Ordering::Acquire),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct DestinationBinding {
    version: u8,
    destination_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct OverflowIndicator {
    version: u8,
    destination_id: String,
    count: u64,
    first_seq: u64,
    first_prev_hash: String,
    last_seq: u64,
    last_entry_hash: String,
    checkpoint_seq: u64,
    checkpoint_entry_hash: String,
    key_id: String,
    signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct DeliveryCheckpoint {
    version: u8,
    destination_id: String,
    seq: u64,
    entry_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    record_key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    overflow_commitment: Option<String>,
    key_id: String,
    signature: String,
}

#[derive(Default)]
struct RecoveryCandidatePaths {
    final_path: Option<PathBuf>,
    temporary_path: Option<PathBuf>,
    acknowledged_path: Option<PathBuf>,
}

struct InspectedCandidate {
    record: AuditRecord,
    bytes: Vec<u8>,
    paths: RecoveryCandidatePaths,
}

struct RecoveryInspection {
    candidates: BTreeMap<u64, InspectedCandidate>,
}

struct PlannedPending {
    record: AuditRecord,
    bytes: Vec<u8>,
    final_path: PathBuf,
    source_path: PathBuf,
    redundant_paths: Vec<PathBuf>,
}

struct RecoveryPlan {
    checkpoint: DeliveryCheckpoint,
    overflow: Option<OverflowIndicator>,
    persist_initial_checkpoint: bool,
    pending: Vec<PlannedPending>,
    cleanup: Vec<(PathBuf, Vec<u8>)>,
}

#[derive(Debug)]
struct RecoveredPending {
    queue: BTreeMap<u64, QueuedRecord>,
    checkpoint: DeliveryCheckpoint,
    overflow: Option<OverflowIndicator>,
    admitted_tail: ChainTail,
    pending_bytes: usize,
}

#[derive(Clone, Debug)]
struct QueuedRecord {
    path: PathBuf,
    byte_len: usize,
    entry_hash: String,
}

#[derive(Clone, Copy)]
enum RecognizedSpoolState {
    Acknowledged,
    Temporary,
    Final,
}

fn validate_config(config: &DurableSpoolConfig) -> Result<(), ShippingError> {
    if config.destination_id.trim().is_empty() {
        return Err(ShippingError::Transport(
            "audit shipping destination identity is empty".to_owned(),
        ));
    }
    if config.max_records == 0 || config.max_records > MAX_SPOOL_RECORDS {
        return Err(ShippingError::Transport(format!(
            "audit shipping spool capacity must be between 1 and {MAX_SPOOL_RECORDS} records"
        )));
    }
    if config.retry_initial.is_zero()
        || config.retry_max.is_zero()
        || config.retry_initial > config.retry_max
    {
        return Err(ShippingError::Transport(
            "audit shipping retry delays must be non-zero and initial <= max".to_owned(),
        ));
    }
    if config.destination_timeout.is_zero() || config.shutdown_timeout.is_zero() {
        return Err(ShippingError::Transport(
            "audit shipping destination and shutdown timeouts must be non-zero".to_owned(),
        ));
    }
    if config.verification_keys.is_empty() {
        return Err(ShippingError::Transport(
            "audit shipping spool requires at least one verification key".to_owned(),
        ));
    }
    Ok(())
}

fn secure_spool_directory(directory: &Path) -> Result<(), ShippingError> {
    let metadata = std::fs::symlink_metadata(directory).map_err(transport)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(ShippingError::Transport(format!(
            "audit shipping spool {} must be a private directory, not a link or special object",
            directory.display()
        )));
    }
    #[cfg(unix)]
    {
        let expected_uid = rustix::process::geteuid().as_raw();
        if metadata.uid() != expected_uid {
            return Err(ShippingError::Transport(format!(
                "audit shipping spool {} is owned by uid {}, expected effective uid {expected_uid}",
                directory.display(),
                metadata.uid()
            )));
        }
        if metadata.permissions().mode() & 0o777 != 0o700 {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(directory, permissions).map_err(transport)?;
        }
    }
    #[cfg(windows)]
    crate::sink::harden_windows_private_directory(directory).map_err(transport)?;
    Ok(())
}

fn bind_destination(directory: &Path, destination_id: &str) -> Result<(), ShippingError> {
    let path = directory.join("destination.json");
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            let bytes = read_private_bytes(&path)?;
            let binding: DestinationBinding = serde_json::from_slice(&bytes).map_err(transport)?;
            if binding.version != 1 || binding.destination_id != destination_id {
                return Err(ShippingError::Transport(
                    "audit shipping spool belongs to a different destination".to_owned(),
                ));
            }
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(transport(error)),
    }
    let binding = DestinationBinding {
        version: 1,
        destination_id: destination_id.to_owned(),
    };
    let bytes = serde_json::to_vec(&binding).map_err(transport)?;
    write_new_file(&path, &bytes)?;
    sync_directory(directory).map_err(transport)
}

fn checkpoint_path(directory: &Path) -> PathBuf {
    directory.join("delivery-head.json")
}

fn canonical_hash(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn checkpoint_message(
    destination_id: &str,
    seq: u64,
    entry_hash: &str,
    record_key_id: Option<&str>,
    overflow_commitment: Option<&str>,
) -> String {
    const DOMAIN: &str = "oraclemcp:audit-shipping-checkpoint:v2\n";
    let record_key_id = record_key_id.unwrap_or_default();
    let overflow_commitment = overflow_commitment.unwrap_or_default();
    format!(
        "{DOMAIN}{}:{destination_id}\n{seq}\n{}:{entry_hash}\n{}:{record_key_id}\n{}:{overflow_commitment}",
        destination_id.len(),
        entry_hash.len(),
        record_key_id.len(),
        overflow_commitment.len()
    )
}

fn signed_checkpoint(
    config: &DurableSpoolConfig,
    tail: &ChainTail,
    record_key_id: Option<String>,
    overflow_commitment: Option<String>,
) -> DeliveryCheckpoint {
    let signer = config
        .verification_keys
        .first()
        .expect("validated spool config always has an active signing key");
    let message = checkpoint_message(
        &config.destination_id,
        tail.seq,
        &tail.entry_hash,
        record_key_id.as_deref(),
        overflow_commitment.as_deref(),
    );
    DeliveryCheckpoint {
        version: 2,
        destination_id: config.destination_id.clone(),
        seq: tail.seq,
        entry_hash: tail.entry_hash.clone(),
        record_key_id,
        overflow_commitment,
        key_id: signer.key_id().to_owned(),
        signature: signer.sign(&message),
    }
}

fn verify_checkpoint(
    checkpoint: &DeliveryCheckpoint,
    config: &DurableSpoolConfig,
) -> Result<(), ShippingError> {
    if checkpoint.version != 2 || checkpoint.destination_id != config.destination_id {
        return Err(spool_integrity(
            Some(checkpoint.seq),
            "delivery checkpoint belongs to another destination or version",
        ));
    }
    let valid_tail = if checkpoint.seq == 0 {
        checkpoint.entry_hash == crate::GENESIS_HASH && checkpoint.record_key_id.is_none()
    } else {
        canonical_hash(&checkpoint.entry_hash)
    };
    if !valid_tail {
        return Err(spool_integrity(
            Some(checkpoint.seq),
            "delivery checkpoint has an invalid chain tail",
        ));
    }
    if checkpoint
        .overflow_commitment
        .as_deref()
        .is_some_and(|commitment| !canonical_hash(commitment))
    {
        return Err(spool_integrity(
            Some(checkpoint.seq),
            "delivery checkpoint has an invalid overflow commitment",
        ));
    }
    let Some(key) = config
        .verification_keys
        .iter()
        .find(|candidate| candidate.key_id() == checkpoint.key_id)
    else {
        return Err(spool_integrity(
            Some(checkpoint.seq),
            format!(
                "delivery checkpoint names unknown signing key {}",
                checkpoint.key_id
            ),
        ));
    };
    let message = checkpoint_message(
        &checkpoint.destination_id,
        checkpoint.seq,
        &checkpoint.entry_hash,
        checkpoint.record_key_id.as_deref(),
        checkpoint.overflow_commitment.as_deref(),
    );
    if !key.verify(&message, &checkpoint.signature) {
        return Err(spool_integrity(
            Some(checkpoint.seq),
            "delivery checkpoint signature does not verify",
        ));
    }
    Ok(())
}

fn load_checkpoint(
    config: &DurableSpoolConfig,
) -> Result<Option<DeliveryCheckpoint>, ShippingError> {
    let path = checkpoint_path(&config.directory);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            let bytes = read_private_bytes(&path)?;
            let checkpoint: DeliveryCheckpoint =
                serde_json::from_slice(&bytes).map_err(|error| {
                    spool_integrity(
                        None,
                        format!("delivery checkpoint JSON is malformed: {error}"),
                    )
                })?;
            verify_checkpoint(&checkpoint, config)?;
            Ok(Some(checkpoint))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(transport(error)),
    }
}

fn persist_checkpoint(
    config: &DurableSpoolConfig,
    checkpoint: &DeliveryCheckpoint,
) -> Result<(), ShippingError> {
    verify_checkpoint(checkpoint, config)?;
    let bytes = serde_json::to_vec(checkpoint).map_err(transport)?;
    let temporary = random_temporary_path(&config.directory, "delivery-head")?;
    write_new_file(&temporary, &bytes)?;
    std::fs::rename(&temporary, checkpoint_path(&config.directory)).map_err(transport)?;
    sync_directory(&config.directory).map_err(transport)
}

fn inspect_recovery(config: &DurableSpoolConfig) -> Result<RecoveryInspection, ShippingError> {
    inspect_recovery_with_byte_limit(config, MAX_SPOOL_RECOVERY_BYTES)
}

fn inspect_recovery_with_byte_limit(
    config: &DurableSpoolConfig,
    byte_limit: usize,
) -> Result<RecoveryInspection, ShippingError> {
    let scan_limit = config.max_records.saturating_add(1);
    let mut recognized = Vec::new();
    for entry in std::fs::read_dir(&config.directory).map_err(transport)? {
        let entry = entry.map_err(transport)?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let parsed = if let Some(seq) = parse_record_name(name, ".acked") {
            Some((seq, RecognizedSpoolState::Acknowledged))
        } else if let Some(seq) = parse_temp_record_name(name) {
            Some((seq, RecognizedSpoolState::Temporary))
        } else {
            parse_record_name(name, ".json").map(|seq| (seq, RecognizedSpoolState::Final))
        };
        let Some((seq, state)) = parsed else {
            continue;
        };
        if recognized.len() >= scan_limit {
            return Err(ShippingError::Transport(format!(
                "audit shipping spool exceeds the bounded recognized-state limit of {scan_limit}; recovery stopped before opening or deleting sequence {seq}"
            )));
        }
        recognized.push((seq, state, path));
    }

    let distinct_non_acknowledged = recognized
        .iter()
        .filter(|(_, state, _)| !matches!(state, RecognizedSpoolState::Acknowledged))
        .map(|(seq, _, _)| *seq)
        .collect::<BTreeSet<_>>();
    if distinct_non_acknowledged.len() > config.max_records {
        return Err(ShippingError::Transport(format!(
            "audit shipping spool exceeds configured capacity {}; recovery stopped before opening any record body",
            config.max_records
        )));
    }

    let mut paths: BTreeMap<u64, RecoveryCandidatePaths> = BTreeMap::new();
    for (seq, state, path) in recognized {
        let candidate = paths.entry(seq).or_default();
        let slot = match state {
            RecognizedSpoolState::Acknowledged => &mut candidate.acknowledged_path,
            RecognizedSpoolState::Temporary => &mut candidate.temporary_path,
            RecognizedSpoolState::Final => &mut candidate.final_path,
        };
        if slot.replace(path).is_some() {
            return Err(spool_integrity(
                Some(seq),
                "multiple files claim the same spool sequence and state",
            ));
        }
    }

    let mut aggregate_bytes = 0_usize;
    let mut candidates = BTreeMap::new();
    for (seq, candidate_paths) in paths {
        let mut canonical: Option<(Vec<u8>, AuditRecord)> = None;
        for path in [
            candidate_paths.final_path.as_ref(),
            candidate_paths.temporary_path.as_ref(),
            candidate_paths.acknowledged_path.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            let bytes = read_private_bytes(path)?;
            aggregate_bytes = aggregate_bytes
                .checked_add(bytes.len())
                .ok_or_else(|| spool_integrity(None, "recovery byte accounting overflowed"))?;
            if aggregate_bytes > byte_limit {
                return Err(spool_integrity(
                    Some(seq),
                    format!(
                        "recognized spool state exceeds the {byte_limit}-byte aggregate recovery budget"
                    ),
                ));
            }
            let record: AuditRecord = serde_json::from_slice(&bytes).map_err(|error| {
                spool_integrity(Some(seq), format!("record JSON is malformed: {error}"))
            })?;
            if record.seq != seq {
                return Err(spool_integrity(
                    Some(seq),
                    format!("filename disagrees with record sequence {}", record.seq),
                ));
            }
            verify_record_signature(&record, &config.verification_keys)?;
            if let Some((existing, _)) = canonical.as_ref()
                && existing != &bytes
            {
                return Err(spool_integrity(
                    Some(seq),
                    "files for one spool sequence contain different authenticated bytes",
                ));
            }
            canonical.get_or_insert((bytes, record));
        }
        let (bytes, record) = canonical.expect("a recognized sequence always has a path");
        candidates.insert(
            seq,
            InspectedCandidate {
                record,
                bytes,
                paths: candidate_paths,
            },
        );
    }
    Ok(RecoveryInspection { candidates })
}

fn initial_checkpoint(
    config: &DurableSpoolConfig,
    trusted_destination_tail: Option<(u64, String)>,
) -> DeliveryCheckpoint {
    let tail = ChainTail::from_optional(trusted_destination_tail);
    signed_checkpoint(config, &tail, None, None)
}

fn plan_recovery(
    config: &DurableSpoolConfig,
    inspection: RecoveryInspection,
    checkpoint: Option<DeliveryCheckpoint>,
    overflow: Option<OverflowIndicator>,
    trusted_destination_tail: Option<(u64, String)>,
) -> Result<RecoveryPlan, ShippingError> {
    let persist_initial_checkpoint = checkpoint.is_none();
    let checkpoint =
        checkpoint.unwrap_or_else(|| initial_checkpoint(config, trusted_destination_tail));
    verify_checkpoint(&checkpoint, config)?;
    verify_overflow_checkpoint_binding(overflow.as_ref(), &checkpoint, config)?;
    let checkpoint_tail = ChainTail {
        seq: checkpoint.seq,
        entry_hash: checkpoint.entry_hash.clone(),
    };
    let mut cleanup = Vec::new();
    let mut pending = Vec::new();

    for (seq, candidate) in inspection.candidates {
        let mut paths = [
            candidate.paths.final_path,
            candidate.paths.temporary_path,
            candidate.paths.acknowledged_path,
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        if seq <= checkpoint.seq {
            if seq == checkpoint.seq && candidate.record.entry_hash != checkpoint.entry_hash {
                return Err(spool_integrity(
                    Some(seq),
                    "spool residue conflicts with the authenticated delivery checkpoint",
                ));
            }
            cleanup.extend(paths.drain(..).map(|path| (path, candidate.bytes.clone())));
            continue;
        }
        let final_path = record_path(&config.directory, seq);
        let source_index = paths
            .iter()
            .position(|path| path == &final_path)
            .unwrap_or(0);
        let source_path = paths.remove(source_index);
        pending.push(PlannedPending {
            record: candidate.record,
            bytes: candidate.bytes,
            final_path,
            source_path,
            redundant_paths: paths,
        });
    }
    if pending.len() > config.max_records {
        return Err(ShippingError::Transport(format!(
            "audit shipping spool contains {} pending records, exceeding configured capacity {}",
            pending.len(),
            config.max_records
        )));
    }

    let mut previous = checkpoint_tail.clone();
    let mut current_key_id = checkpoint.record_key_id.clone();
    let mut retired_key_ids = BTreeSet::new();
    for entry in &pending {
        let expected_seq = previous.seq.checked_add(1).ok_or_else(|| {
            spool_integrity(Some(entry.record.seq), "spool sequence exhausted u64")
        })?;
        if entry.record.seq != expected_seq || entry.record.prev_hash != previous.entry_hash {
            return Err(spool_integrity(
                Some(entry.record.seq),
                format!(
                    "recovered record does not continue authenticated checkpoint sequence {}",
                    previous.seq
                ),
            ));
        }
        let record_key_id = entry
            .record
            .key_id
            .as_deref()
            .expect("authenticated records always name a key");
        if current_key_id.as_deref() != Some(record_key_id) {
            if let Some(previous_key_id) = current_key_id.replace(record_key_id.to_owned()) {
                retired_key_ids.insert(previous_key_id);
            }
            if retired_key_ids.contains(record_key_id) {
                return Err(spool_integrity(
                    Some(entry.record.seq),
                    format!("retired signing key {record_key_id} reappears in recovered spool"),
                ));
            }
        }
        previous = ChainTail::from_record(&entry.record);
    }
    if let Some(authoritative_tail) = config.authoritative_tail.as_ref()
        && previous != *authoritative_tail
    {
        return Err(spool_integrity(
            Some(previous.seq),
            format!(
                "recovered spool tail does not match authoritative primary sequence {}",
                authoritative_tail.seq
            ),
        ));
    }
    Ok(RecoveryPlan {
        checkpoint,
        overflow,
        persist_initial_checkpoint,
        pending,
        cleanup,
    })
}

fn ensure_unchanged(path: &Path, expected: &[u8]) -> Result<(), ShippingError> {
    if read_private_bytes(path)? != expected {
        return Err(spool_integrity(
            None,
            format!("spool path {} changed during recovery", path.display()),
        ));
    }
    Ok(())
}

fn commit_recovery(
    config: &DurableSpoolConfig,
    plan: RecoveryPlan,
) -> Result<RecoveredPending, ShippingError> {
    if plan.persist_initial_checkpoint {
        persist_checkpoint(config, &plan.checkpoint)?;
    }
    for (path, bytes) in &plan.cleanup {
        ensure_unchanged(path, bytes)?;
        std::fs::remove_file(path).map_err(transport)?;
    }
    let mut queue = BTreeMap::new();
    let mut pending_bytes = 0_usize;
    let mut admitted_tail = ChainTail {
        seq: plan.checkpoint.seq,
        entry_hash: plan.checkpoint.entry_hash.clone(),
    };
    for entry in plan.pending {
        ensure_unchanged(&entry.source_path, &entry.bytes)?;
        for redundant in &entry.redundant_paths {
            ensure_unchanged(redundant, &entry.bytes)?;
        }
        if entry.source_path != entry.final_path {
            match std::fs::symlink_metadata(&entry.final_path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => {
                    return Err(spool_integrity(
                        Some(entry.record.seq),
                        "canonical record path appeared during recovery",
                    ));
                }
                Err(error) => return Err(transport(error)),
            }
            std::fs::rename(&entry.source_path, &entry.final_path).map_err(transport)?;
        }
        for redundant in entry.redundant_paths {
            std::fs::remove_file(redundant).map_err(transport)?;
        }
        pending_bytes = pending_bytes
            .checked_add(entry.bytes.len())
            .ok_or_else(|| spool_integrity(None, "recovered byte accounting overflowed"))?;
        admitted_tail = ChainTail::from_record(&entry.record);
        queue.insert(
            entry.record.seq,
            QueuedRecord {
                path: entry.final_path,
                byte_len: entry.bytes.len(),
                entry_hash: entry.record.entry_hash,
            },
        );
    }
    sync_directory(&config.directory).map_err(transport)?;
    Ok(RecoveredPending {
        queue,
        checkpoint: plan.checkpoint,
        overflow: plan.overflow,
        admitted_tail,
        pending_bytes,
    })
}

fn recover_for_open(
    config: &DurableSpoolConfig,
    destination: &dyn ShippingForwarder,
) -> Result<RecoveredPending, ShippingError> {
    let checkpoint = load_checkpoint(config)?;
    let overflow = load_overflow(config)?;
    let inspection = inspect_recovery(config)?;
    let plan = plan_recovery(
        config,
        inspection,
        checkpoint,
        overflow,
        destination.trusted_recovery_tail(),
    )?;
    let records = plan
        .pending
        .iter()
        .map(|entry| entry.record.clone())
        .collect::<Vec<_>>();
    destination.validate_recovered_spool(&records)?;
    commit_recovery(config, plan)
}

#[cfg(test)]
fn recover_pending(
    directory: &Path,
    max_records: usize,
    verification_keys: &[SigningKey],
) -> Result<RecoveredPending, ShippingError> {
    let config = DurableSpoolConfig::new(directory, "test-recovery")
        .with_max_records(max_records)
        .with_verification_keys(verification_keys.iter().cloned());
    let checkpoint = load_checkpoint(&config)?;
    let overflow = load_overflow(&config)?;
    let inspection = inspect_recovery(&config)?;
    let plan = plan_recovery(&config, inspection, checkpoint, overflow, None)?;
    commit_recovery(&config, plan)
}

fn run_worker(shared: Arc<SpoolShared>, destination: Arc<dyn ShippingForwarder>) {
    let mut retry = shared.config.retry_initial;
    loop {
        let next = {
            let mut queue = shared.queue.lock();
            while queue.is_empty() && !shared.worker_stop.load(Ordering::Acquire) {
                shared
                    .wake
                    .wait_for(&mut queue, WORKER_STOP_RECHECK_INTERVAL);
            }
            if shared.worker_stop.load(Ordering::Acquire) {
                return;
            }
            queue
                .first_key_value()
                .map(|(&seq, queued)| (seq, queued.clone()))
        };
        let Some((seq, queued)) = next else {
            continue;
        };
        let record = match read_spooled_record(&queued.path).and_then(|record| {
            verify_record_signature(&record, &shared.config.verification_keys)?;
            validate_delivery_candidate(&shared, seq, &queued.entry_hash, &record)?;
            Ok(record)
        }) {
            Ok(record) => record,
            Err(error) => {
                shared.failures.fetch_add(1, Ordering::Relaxed);
                tracing::error!(seq, error = %error, "audit shipping spool record became unreadable; worker stopped");
                shared.worker_stop.store(true, Ordering::Release);
                return;
            }
        };
        let attempt = deliver_with_deadline(&shared, Arc::clone(&destination), record.clone());
        match attempt {
            DeliveryAttempt::Completed(Ok(())) => {
                if acknowledge(&shared, &record, &queued.path).is_ok() {
                    retry = shared.config.retry_initial;
                } else {
                    shared.failures.fetch_add(1, Ordering::Relaxed);
                    wait_retry(&shared, retry);
                    retry = retry.saturating_mul(2).min(shared.config.retry_max);
                }
            }
            DeliveryAttempt::Completed(Err(error)) => {
                shared.failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(seq, error = %error, "audit shipping delivery failed; record remains durably queued");
                wait_retry(&shared, retry);
                retry = retry.saturating_mul(2).min(shared.config.retry_max);
            }
            DeliveryAttempt::TimedOut(call) => {
                shared.failures.fetch_add(1, Ordering::Relaxed);
                shared.worker_stop.store(true, Ordering::Release);
                tracing::warn!(
                    seq,
                    "audit shipping destination call timed out; delivery halted and spool lease retained until the call exits"
                );
                if call.join().is_err() {
                    shared.failures.fetch_add(1, Ordering::Relaxed);
                    tracing::error!(seq, "timed-out audit shipping call panicked while exiting");
                }
                return;
            }
        }
    }
}

fn validate_delivery_candidate(
    shared: &SpoolShared,
    queued_seq: u64,
    queued_entry_hash: &str,
    record: &AuditRecord,
) -> Result<(), ShippingError> {
    let checkpoint = shared.checkpoint.lock();
    let expected_seq = checkpoint.seq.checked_add(1).ok_or_else(|| {
        spool_integrity(
            Some(queued_seq),
            "delivery checkpoint sequence exhausted u64",
        )
    })?;
    if queued_seq != expected_seq
        || record.seq != queued_seq
        || record.prev_hash != checkpoint.entry_hash
        || record.entry_hash != queued_entry_hash
    {
        return Err(spool_integrity(
            Some(queued_seq),
            "queued record changed identity or does not continue the durable delivery checkpoint",
        ));
    }
    Ok(())
}

enum DeliveryAttempt {
    Completed(Result<(), ShippingError>),
    TimedOut(JoinHandle<()>),
}

fn deliver_with_deadline(
    shared: &SpoolShared,
    destination: Arc<dyn ShippingForwarder>,
    record: AuditRecord,
) -> DeliveryAttempt {
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let call = match thread::Builder::new()
        .name("audit-shipping-call".to_owned())
        .spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| {
                destination
                    .forward(&record)
                    .and_then(|()| destination.flush())
            }))
            .unwrap_or_else(|_| {
                Err(ShippingError::Transport(
                    "audit shipping destination panicked".to_owned(),
                ))
            });
            let _ = result_tx.send(result);
        }) {
        Ok(call) => call,
        Err(error) => return DeliveryAttempt::Completed(Err(transport(error))),
    };
    match result_rx.recv_timeout(shared.config.destination_timeout) {
        Ok(result) => match call.join() {
            Ok(()) => DeliveryAttempt::Completed(result),
            Err(_) => DeliveryAttempt::Completed(Err(ShippingError::Transport(
                "audit shipping destination call panicked".to_owned(),
            ))),
        },
        Err(mpsc::RecvTimeoutError::Timeout) => {
            shared.destination_timeouts.fetch_add(1, Ordering::Relaxed);
            DeliveryAttempt::TimedOut(call)
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = call.join();
            DeliveryAttempt::Completed(Err(ShippingError::Transport(
                "audit shipping destination worker disconnected".to_owned(),
            )))
        }
    }
}

fn wait_retry(shared: &SpoolShared, delay: Duration) {
    let mut queue = shared.queue.lock();
    if !shared.worker_stop.load(Ordering::Acquire) {
        shared.wake.wait_for(&mut queue, delay);
    }
}

fn acknowledge(
    shared: &SpoolShared,
    record: &AuditRecord,
    path: &Path,
) -> Result<(), ShippingError> {
    let seq = record.seq;
    let mut checkpoint = shared.checkpoint.lock();
    let expected_seq = checkpoint
        .seq
        .checked_add(1)
        .ok_or_else(|| spool_integrity(Some(seq), "delivery checkpoint sequence exhausted u64"))?;
    if seq != expected_seq || record.prev_hash != checkpoint.entry_hash {
        return Err(spool_integrity(
            Some(seq),
            "destination acknowledgement does not continue the durable delivery checkpoint",
        ));
    }
    let next_checkpoint = signed_checkpoint(
        &shared.config,
        &ChainTail::from_record(record),
        record.key_id.clone(),
        checkpoint.overflow_commitment.clone(),
    );
    persist_checkpoint(&shared.config, &next_checkpoint)?;
    *checkpoint = next_checkpoint;
    drop(checkpoint);

    let acknowledged = acknowledged_path(&shared.config.directory, seq);
    let renamed = match std::fs::symlink_metadata(&acknowledged) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::rename(path, &acknowledged) {
                Ok(()) => true,
                Err(error) => {
                    tracing::debug!(seq, %error, "delivery checkpoint advanced; spool residue retained for restart cleanup");
                    false
                }
            }
        }
        Ok(_) => false,
        Err(error) => {
            tracing::debug!(seq, %error, "could not inspect acknowledgement residue after durable checkpoint");
            false
        }
    };
    {
        let mut queue = shared.queue.lock();
        if let Some(queued) = queue.remove(&seq) {
            subtract_pending_bytes(shared, queued.byte_len)?;
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
    if renamed && let Err(error) = std::fs::remove_file(&acknowledged) {
        tracing::debug!(seq, %error, "acknowledged audit spool residue retained for restart cleanup");
    } else if let Err(error) = sync_directory(&shared.config.directory) {
        tracing::debug!(seq, %error, "could not fsync audit spool directory after ack cleanup");
    }
    Ok(())
}

fn subtract_pending_bytes(
    shared: &SpoolShared,
    acknowledged_bytes: usize,
) -> Result<(), ShippingError> {
    let acknowledged_bytes = u64::try_from(acknowledged_bytes).map_err(transport)?;
    shared
        .pending_bytes
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |pending_bytes| {
            pending_bytes.checked_sub(acknowledged_bytes)
        })
        .map_err(|_| spool_integrity(None, "audit shipping pending-byte accounting underflowed"))?;
    Ok(())
}

fn overflow_message(state: &OverflowIndicator) -> String {
    const DOMAIN: &str = "oraclemcp:audit-shipping-overflow:v2\n";
    format!(
        "{DOMAIN}{}:{}\n{}\n{}\n{}:{}\n{}\n{}:{}\n{}\n{}:{}",
        state.destination_id.len(),
        state.destination_id,
        state.count,
        state.first_seq,
        state.first_prev_hash.len(),
        state.first_prev_hash,
        state.last_seq,
        state.last_entry_hash.len(),
        state.last_entry_hash,
        state.checkpoint_seq,
        state.checkpoint_entry_hash.len(),
        state.checkpoint_entry_hash,
    )
}

fn verify_overflow(
    state: &OverflowIndicator,
    config: &DurableSpoolConfig,
) -> Result<(), ShippingError> {
    if state.version != 2 || state.destination_id != config.destination_id {
        return Err(spool_integrity(
            Some(state.last_seq),
            "overflow evidence belongs to another destination or version",
        ));
    }
    if state.count == 0 || state.first_seq == 0 || state.last_seq < state.first_seq {
        return Err(spool_integrity(
            Some(state.last_seq),
            "overflow evidence has impossible counters",
        ));
    }
    let span = state
        .last_seq
        .checked_sub(state.first_seq)
        .and_then(|span| span.checked_add(1))
        .ok_or_else(|| spool_integrity(Some(state.last_seq), "overflow span overflowed"))?;
    if state.count > span {
        return Err(spool_integrity(
            Some(state.last_seq),
            "overflow count exceeds its sequence span",
        ));
    }
    let valid_first_previous = if state.first_seq == 1 {
        state.first_prev_hash == crate::GENESIS_HASH
    } else {
        canonical_hash(&state.first_prev_hash)
    };
    if !valid_first_previous
        || !canonical_hash(&state.last_entry_hash)
        || (state.checkpoint_seq == 0 && state.checkpoint_entry_hash != crate::GENESIS_HASH)
        || (state.checkpoint_seq > 0 && !canonical_hash(&state.checkpoint_entry_hash))
        || state.first_seq <= state.checkpoint_seq
    {
        return Err(spool_integrity(
            Some(state.last_seq),
            "overflow evidence has an impossible chain/checkpoint binding",
        ));
    }
    let Some(key) = config
        .verification_keys
        .iter()
        .find(|candidate| candidate.key_id() == state.key_id)
    else {
        return Err(spool_integrity(
            Some(state.last_seq),
            format!(
                "overflow evidence names unknown signing key {}",
                state.key_id
            ),
        ));
    };
    if !key.verify(&overflow_message(state), &state.signature) {
        return Err(spool_integrity(
            Some(state.last_seq),
            "overflow evidence signature does not verify",
        ));
    }
    Ok(())
}

fn overflow_commitment(state: &OverflowIndicator) -> Result<String, ShippingError> {
    let bytes = serde_json::to_vec(state).map_err(transport)?;
    Ok(crate::sha256_hex(&bytes))
}

fn verify_overflow_checkpoint_binding(
    overflow: Option<&OverflowIndicator>,
    checkpoint: &DeliveryCheckpoint,
    config: &DurableSpoolConfig,
) -> Result<(), ShippingError> {
    let actual_commitment = overflow.map(overflow_commitment).transpose()?;
    if actual_commitment != checkpoint.overflow_commitment {
        return Err(spool_integrity(
            overflow.map(|state| state.last_seq),
            "overflow evidence is missing, rolled back, or does not match the authenticated delivery checkpoint",
        ));
    }
    let Some(state) = overflow else {
        return Ok(());
    };
    verify_overflow(state, config)?;
    if state.checkpoint_seq > checkpoint.seq
        || (state.checkpoint_seq == checkpoint.seq
            && state.checkpoint_entry_hash != checkpoint.entry_hash)
    {
        return Err(spool_integrity(
            Some(state.last_seq),
            "overflow evidence is bound to an impossible delivery checkpoint",
        ));
    }
    Ok(())
}

fn next_overflow(
    config: &DurableSpoolConfig,
    previous: Option<&OverflowIndicator>,
    checkpoint: &DeliveryCheckpoint,
    record: &AuditRecord,
) -> Result<Option<OverflowIndicator>, ShippingError> {
    if let Some(previous) = previous {
        verify_overflow(previous, config)?;
        if record.seq == previous.last_seq && record.entry_hash == previous.last_entry_hash {
            return Ok(None);
        }
        if record.seq <= previous.last_seq {
            return Err(spool_integrity(
                Some(record.seq),
                "overflow evidence sequence rolled back or forked",
            ));
        }
    }
    let count = previous
        .map_or(Some(1), |state| state.count.checked_add(1))
        .ok_or_else(|| spool_integrity(Some(record.seq), "overflow counter exhausted u64"))?;
    let signer = config
        .verification_keys
        .first()
        .expect("validated spool config always has an active signing key");
    let mut state = OverflowIndicator {
        version: 2,
        destination_id: config.destination_id.clone(),
        count,
        first_seq: previous.map_or(record.seq, |state| state.first_seq),
        first_prev_hash: previous.map_or_else(
            || record.prev_hash.clone(),
            |state| state.first_prev_hash.clone(),
        ),
        last_seq: record.seq,
        last_entry_hash: record.entry_hash.clone(),
        checkpoint_seq: checkpoint.seq,
        checkpoint_entry_hash: checkpoint.entry_hash.clone(),
        key_id: signer.key_id().to_owned(),
        signature: String::new(),
    };
    state.signature = signer.sign(&overflow_message(&state));
    verify_overflow(&state, config)?;
    Ok(Some(state))
}

fn persist_overflow(
    config: &DurableSpoolConfig,
    state: &OverflowIndicator,
) -> Result<(), ShippingError> {
    verify_overflow(state, config)?;
    let bytes = serde_json::to_vec(state).map_err(transport)?;
    let temporary = random_temporary_path(&config.directory, "overflow")?;
    write_new_file(&temporary, &bytes)?;
    std::fs::rename(&temporary, config.directory.join("overflow.json")).map_err(transport)?;
    sync_directory(&config.directory).map_err(transport)
}

fn record_overflow(shared: &SpoolShared, record: &AuditRecord) -> Result<bool, ShippingError> {
    if shared.overflow_poisoned.load(Ordering::Acquire) {
        return Err(spool_integrity(
            Some(record.seq),
            "overflow evidence transition is poisoned after an uncertain durable update",
        ));
    }
    let mut checkpoint = shared.checkpoint.lock();
    let mut state = shared.overflow_state.lock();
    let disk_state = load_overflow(&shared.config)?;
    verify_overflow_checkpoint_binding(disk_state.as_ref(), &checkpoint, &shared.config)?;
    if disk_state != *state {
        return Err(spool_integrity(
            Some(record.seq),
            "overflow evidence changed after startup",
        ));
    }
    let Some(next) = next_overflow(&shared.config, state.as_ref(), &checkpoint, record)? else {
        return Ok(false);
    };
    let commitment = overflow_commitment(&next)?;
    let next_checkpoint = signed_checkpoint(
        &shared.config,
        &ChainTail {
            seq: checkpoint.seq,
            entry_hash: checkpoint.entry_hash.clone(),
        },
        checkpoint.record_key_id.clone(),
        Some(commitment),
    );
    if let Err(error) = persist_overflow(&shared.config, &next)
        .and_then(|()| persist_checkpoint(&shared.config, &next_checkpoint))
    {
        shared.overflow_poisoned.store(true, Ordering::Release);
        return Err(error);
    }
    *checkpoint = next_checkpoint;
    *state = Some(next);
    Ok(true)
}

fn load_overflow(config: &DurableSpoolConfig) -> Result<Option<OverflowIndicator>, ShippingError> {
    let path = config.directory.join("overflow.json");
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            let state: OverflowIndicator = serde_json::from_slice(&read_private_bytes(&path)?)
                .map_err(|error| {
                    spool_integrity(
                        None,
                        format!("overflow evidence JSON is malformed: {error}"),
                    )
                })?;
            verify_overflow(&state, config)?;
            Ok(Some(state))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(transport(error)),
    }
}

fn read_spooled_record(path: &Path) -> Result<AuditRecord, ShippingError> {
    let bytes = read_private_bytes(path)?;
    let record: AuditRecord = serde_json::from_slice(&bytes)
        .map_err(|error| spool_integrity(None, format!("record JSON is malformed: {error}")))?;
    Ok(record)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), ShippingError> {
    let mut file = create_new_private_file(path).map_err(transport)?;
    file.write_all(bytes).map_err(transport)?;
    file.sync_all().map_err(transport)
}

fn read_private_bytes(path: &Path) -> Result<Vec<u8>, ShippingError> {
    let file = open_private_read_file(path).map_err(transport)?;
    let mut bytes = Vec::new();
    let limit = u64::try_from(crate::MAX_AUDIT_LINE_LEN)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(transport)?;
    if bytes.len() > crate::MAX_AUDIT_LINE_LEN {
        return Err(spool_integrity(
            None,
            format!(
                "spool file exceeds the {}-byte maximum",
                crate::MAX_AUDIT_LINE_LEN
            ),
        ));
    }
    Ok(bytes)
}

fn record_path(directory: &Path, seq: u64) -> PathBuf {
    directory.join(format!("record-{seq:020}.json"))
}

fn random_temp_record_path(directory: &Path, seq: u64) -> Result<PathBuf, ShippingError> {
    random_temporary_path(directory, &format!("record-{seq:020}"))
}

#[cfg(test)]
fn temp_record_path(directory: &Path, seq: u64) -> PathBuf {
    directory.join(format!("record-{seq:020}.tmp"))
}

fn acknowledged_path(directory: &Path, seq: u64) -> PathBuf {
    directory.join(format!("record-{seq:020}.acked"))
}

fn parse_record_name(name: &str, suffix: &str) -> Option<u64> {
    let sequence = name.strip_prefix("record-")?.strip_suffix(suffix)?;
    if sequence.len() != 20 || !sequence.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    sequence.parse().ok()
}

fn parse_temp_record_name(name: &str) -> Option<u64> {
    let body = name.strip_prefix("record-")?.strip_suffix(".tmp")?;
    let (seq, nonce) = body.split_once('.').unwrap_or((body, ""));
    if seq.len() != 20
        || !seq.bytes().all(|byte| byte.is_ascii_digit())
        || (!nonce.is_empty()
            && (nonce.len() != 32 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit())))
    {
        return None;
    }
    seq.parse().ok()
}

fn random_temporary_path(directory: &Path, prefix: &str) -> Result<PathBuf, ShippingError> {
    let mut nonce = [0_u8; 16];
    getrandom::getrandom(&mut nonce).map_err(transport)?;
    let mut encoded = String::with_capacity(nonce.len() * 2);
    for byte in nonce {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(directory.join(format!("{prefix}.{encoded}.tmp")))
}

fn verify_record_signature(
    record: &AuditRecord,
    verification_keys: &[SigningKey],
) -> Result<(), ShippingError> {
    if !record.hash_is_valid() {
        return Err(spool_integrity(
            Some(record.seq),
            "record hash does not authenticate its payload",
        ));
    }
    let Some(key_id) = record.key_id.as_deref() else {
        return Err(spool_integrity(
            Some(record.seq),
            "record does not name a signing key",
        ));
    };
    let Some(key) = verification_keys
        .iter()
        .find(|candidate| candidate.key_id() == key_id)
    else {
        return Err(spool_integrity(
            Some(record.seq),
            format!("record names unknown signing key {key_id}"),
        ));
    };
    if !record.signature_is_valid(key) {
        return Err(spool_integrity(
            Some(record.seq),
            "record signature does not verify",
        ));
    }
    Ok(())
}

fn spool_integrity(seq: Option<u64>, reason: impl Into<String>) -> ShippingError {
    ShippingError::SpoolIntegrity {
        seq,
        reason: reason.into(),
    }
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
        AuthenticatedAuditTail, FileAuditSink, GENESIS_HASH, MemoryAuditSink, SigningKey,
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
        let previous_hash = if seq == 1 {
            GENESIS_HASH.to_owned()
        } else {
            record(seq - 1).entry_hash
        };
        AuditRecord::chained_signed(&draft(seq), seq, &previous_hash, format!("t{seq}"), &key())
    }

    fn config(directory: &Path, id: &str) -> DurableSpoolConfig {
        DurableSpoolConfig::new(directory, id)
            .with_max_records(32)
            .with_retry(Duration::from_millis(5), Duration::from_millis(20))
            .with_verification_keys([key()])
    }

    fn queued(record: &AuditRecord, path: PathBuf) -> QueuedRecord {
        QueuedRecord {
            byte_len: serde_json::to_vec(record)
                .expect("serialize queued record")
                .len(),
            entry_hash: record.entry_hash.clone(),
            path,
        }
    }

    fn authenticate_primary(primary: &FileAuditSink, path: &Path) -> AuthenticatedAuditTail {
        primary
            .authenticate_existing_chain(path, &crate::anchor_path_for(path), &[key()])
            .expect("authenticate primary")
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

    struct FlakyForwarder {
        attempts: Arc<AtomicUsize>,
    }

    impl ShippingForwarder for FlakyForwarder {
        fn forward(&self, _record: &AuditRecord) -> Result<(), ShippingError> {
            if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(ShippingError::Transport(
                    "temporary enqueue failure".to_owned(),
                ))
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

    /// A durable local append must not wait for the destination.
    ///
    /// This used to prove that with a wall clock: a 300ms sleeping destination
    /// and an assertion that the append returned in under 150ms. That budget is
    /// a proxy, and it measures the wrong thing — the append itself performs a
    /// real `sync_all()` under the spool mutex, and one fsync costs far more on
    /// a virtualised Windows runner than on Linux, so the Windows lane failed
    /// while the property under test held perfectly (bead oraclemcp-mqmo9).
    ///
    /// The gate proves the property instead of timing it: the destination
    /// CANNOT have progressed, because it is blocked until this test opens the
    /// gate. An append that returns while `delivered_records` is still 0 did
    /// not wait for the destination, on any machine at any speed. Strictly
    /// stronger than the old threshold, which a fast machine could satisfy by
    /// luck.
    #[test]
    fn slow_destination_does_not_delay_durable_local_append() {
        let directory = tempfile::tempdir().expect("tempdir");
        let local = Arc::new(MemoryAuditSink::new());
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let delivery = DurableShippingForwarder::open(
            config(directory.path(), "slow"),
            Box::new(GateForwarder {
                gate: Arc::clone(&gate),
            }),
        )
        .expect("open spool");
        // Declared after `delivery` so it drops FIRST and releases the worker
        // before the spool's stop() waits on the in-flight destination call.
        let _release = release_gate_on_drop(&gate);
        let status = delivery.status_handle();
        let sink = crate::ShippingAuditSink::new(
            Box::new(SharedLocal(Arc::clone(&local))),
            Box::new(delivery),
        );
        let auditor = Auditor::new(Box::new(sink), key());

        // Liveness guard, NOT a latency budget: see the sibling test.
        let started = Instant::now();
        auditor
            .append(&draft(1), "t1".to_owned(), true)
            .expect("local durable append");
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the durable append blocked on the gated destination: {:?}",
            started.elapsed()
        );

        // The destination is provably still blocked, so the append cannot have
        // waited on it.
        assert_eq!(local.records().len(), 1);
        let snapshot = status.snapshot();
        assert_eq!(snapshot.pending_records, 1);
        assert_eq!(
            snapshot.delivered_records, 0,
            "the destination is gated shut; nothing can have been delivered yet"
        );

        open_gate(&gate);
        wait_until(Duration::from_secs(30), || {
            status.snapshot().delivered_records == 1
        });
    }

    #[test]
    fn concurrent_local_chain_stays_gap_free_while_shipping_is_stalled() {
        let directory = tempfile::tempdir().expect("tempdir");
        let local = Arc::new(MemoryAuditSink::new());
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        // A gate, not a sleep. The old version gave eight appends 1000ms while a
        // 2000ms sleeping destination ran, but each append performs a real
        // `sync_all()` under the spool mutex, so the budget measured serialised
        // fsync latency as much as blocking — and on a virtualised Windows
        // runner that alone exceeded it (bead oraclemcp-mqmo9). A gated
        // destination cannot progress at all, so "the chain stayed gap-free
        // while shipping was stalled" is proven rather than timed.
        let delivery = DurableShippingForwarder::open(
            config(directory.path(), "concurrent"),
            Box::new(GateForwarder {
                gate: Arc::clone(&gate),
            }),
        )
        .expect("open spool");
        // Declared after `delivery` so it drops FIRST and releases the worker
        // before the spool's stop() waits on the in-flight destination call.
        let _release = release_gate_on_drop(&gate);
        let status = delivery.status_handle();
        let sink = crate::ShippingAuditSink::new(
            Box::new(SharedLocal(Arc::clone(&local))),
            Box::new(delivery),
        );
        let auditor = Arc::new(Auditor::new(Box::new(sink), key()));
        // Liveness guard, NOT a latency budget. The gate proves the property;
        // this only distinguishes "returned" from "blocked forever", so it is
        // set far above any plausible fsync cost on any runner. The old 1000ms
        // budget tried to measure speed and failed on Windows fsync latency.
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
        // Every append returned while the destination was provably stalled.
        assert_eq!(
            status.snapshot().delivered_records,
            0,
            "the destination is gated shut; nothing can have been delivered yet"
        );
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "concurrent appends blocked on the stalled destination: {:?}",
            started.elapsed()
        );
        // Release the worker BEFORE dropping the auditor: it owns the spool, and
        // stop() waits for the in-flight destination call. `_release` cannot do
        // it — locals drop in reverse declaration order, so `auditor` goes first.
        open_gate(&gate);
        let records = local.records();
        assert_eq!(records.len(), 8);
        assert_eq!(
            records.iter().map(|record| record.seq).collect::<Vec<_>>(),
            (1..=8).collect::<Vec<_>>(),
            "the local chain must stay gap-free under concurrent appends"
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
        let equal_retries = valid
            .clone()
            .with_retry(Duration::from_millis(20), Duration::from_millis(20));
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

        delivery
            .forward(&record(1))
            .expect("initial record fills spool capacity");
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
        let delivery =
            DurableShippingForwarder::open(cfg.clone(), Box::new(AlwaysFails)).expect("open spool");
        delivery
            .forward(&record(1))
            .expect("persist one record for replay");
        drop(delivery);

        // Recover with a non-delivering backend: a delivering one (Capture) would
        // drain the recovered record on the worker thread — decrementing pending
        // and deleting the spool file — before these assertions run, which raced
        // under parallel load. AlwaysFails keeps the record durably queued so the
        // "left for replay" state is observed deterministically.
        let recovery = DurableShippingForwarder::open(cfg, Box::new(AlwaysFails))
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

        delivery
            .forward(&record(1))
            .expect("enqueue for retry path");
        wait_until(Duration::from_secs(1), || {
            status.snapshot().delivery_failures >= 1 && status.snapshot().pending_records == 1
        });

        delivery.flush().expect("flush can unblock retry");
        wait_until(Duration::from_millis(250), || {
            status.snapshot().pending_records == 0
        });
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
                .contains("capacity must be between 1 and")
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
            error.to_string().contains("exceeds configured capacity"),
            "unexpected capacity error: {error}"
        );
    }

    #[test]
    fn worm_restart_recovers_exact_signed_suffix_from_durable_spool() {
        let root = tempfile::tempdir().expect("tempdir");
        let primary_path = root.path().join("audit.jsonl");
        let mirror_path = root.path().join("worm.jsonl");
        let spool_path = root.path().join("spool");
        let primary = crate::FileAuditSink::open(&primary_path).expect("open primary");
        let first = record(1);
        let second = record(2);
        primary.append(&first).expect("append first primary record");
        primary
            .append(&second)
            .expect("append second primary record");
        primary.flush().expect("flush primary");
        std::fs::write(
            &mirror_path,
            format!(
                "{}\n",
                serde_json::to_string(&first).expect("serialize mirror prefix")
            ),
        )
        .expect("seed mirror prefix");
        std::fs::create_dir(&spool_path).expect("create spool");
        write_new_file(
            &record_path(&spool_path, second.seq),
            &serde_json::to_vec(&second).expect("serialize pending suffix"),
        )
        .expect("seed pending suffix");

        let worm =
            crate::WormFileForwarder::open_distinct_for_durable_recovery(&mirror_path, &primary)
                .expect("lagging mirror opens provisionally");
        let delivery = DurableShippingForwarder::open(
            config(&spool_path, "worm-crash-recovery"),
            Box::new(worm),
        )
        .expect("authenticated suffix bridges mirror to primary");
        let status = delivery.status_handle();
        wait_until(Duration::from_secs(1), || {
            status.snapshot().delivered_records == 1
        });
        assert_eq!(delivery.shutdown(), DurableShippingShutdownOutcome::Stopped);
        assert_eq!(
            std::fs::read(&mirror_path).expect("read recovered mirror"),
            std::fs::read(&primary_path).expect("read primary"),
            "replayed suffix must make the WORM mirror byte-identical to primary"
        );
    }

    #[test]
    fn worm_restart_rejects_a_gapped_recovered_suffix() {
        let root = tempfile::tempdir().expect("tempdir");
        let primary_path = root.path().join("audit.jsonl");
        let mirror_path = root.path().join("worm.jsonl");
        let spool_path = root.path().join("spool");
        let primary = crate::FileAuditSink::open(&primary_path).expect("open primary");
        let first = record(1);
        let second = record(2);
        let third = record(3);
        for record in [&first, &second, &third] {
            primary.append(record).expect("append primary record");
        }
        primary.flush().expect("flush primary");
        std::fs::write(
            &mirror_path,
            format!(
                "{}\n",
                serde_json::to_string(&first).expect("serialize mirror prefix")
            ),
        )
        .expect("seed mirror prefix");
        std::fs::create_dir(&spool_path).expect("create spool");
        write_new_file(
            &record_path(&spool_path, third.seq),
            &serde_json::to_vec(&third).expect("serialize gapped suffix"),
        )
        .expect("seed gapped suffix");

        let worm =
            crate::WormFileForwarder::open_distinct_for_durable_recovery(&mirror_path, &primary)
                .expect("lagging mirror opens provisionally");
        let error = match DurableShippingForwarder::open(
            config(&spool_path, "worm-gap-recovery"),
            Box::new(worm),
        ) {
            Err(error) => error,
            Ok(_) => panic!("gapped durable suffix must fail startup"),
        };
        assert!(
            error
                .to_string()
                .contains("does not continue authenticated checkpoint sequence 1"),
            "unexpected WORM recovery refusal: {error}"
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
        let rec = record(1);
        let tmp = temp_record_path(directory.path(), rec.seq);
        let bytes = serde_json::to_vec(&rec).expect("serialize record");
        write_new_file(&tmp, &bytes).expect("write temp record");

        let pending = recover_pending(directory.path(), 32, &[key()]).expect("recover temp");
        let final_path = record_path(directory.path(), rec.seq);
        assert_eq!(
            pending.queue.get(&rec.seq).map(|queued| &queued.path),
            Some(&final_path)
        );
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

        let error =
            recover_pending(directory.path(), 32, &[key()]).expect_err("mismatched temp sequence");
        assert!(
            error
                .to_string()
                .contains("filename disagrees with record sequence 8"),
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

        let checkpoint = signed_checkpoint(&cfg, &ChainTail::genesis(), None, None);
        let first = record(1);
        let second = record(2);
        let pending_bytes = serde_json::to_vec(&first).expect("serialize first").len()
            + serde_json::to_vec(&second).expect("serialize second").len();
        let shared = SpoolShared {
            config: cfg,
            queue: Mutex::new(BTreeMap::from_iter([
                (1, queued(&first, path_one.clone())),
                (2, queued(&second, path_two.clone())),
            ])),
            checkpoint: Mutex::new(checkpoint),
            overflow_state: Mutex::new(None),
            admitted_tail: Mutex::new(ChainTail::from_record(&record(2))),
            wake: Condvar::new(),
            enqueue_closed: AtomicBool::new(false),
            worker_stop: AtomicBool::new(false),
            pending: AtomicU64::new(2),
            pending_bytes: AtomicU64::new(pending_bytes as u64),
            delivered: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            overflowed: AtomicU64::new(0),
            overflow_poisoned: AtomicBool::new(false),
            destination_timeouts: AtomicU64::new(0),
            shutdown_timeouts: AtomicU64::new(0),
            worker_running: AtomicBool::new(true),
            completion: WorkerCompletion {
                done: Mutex::new(false),
                wake: Condvar::new(),
            },
        };

        assert_eq!(
            shared.status().pending_records,
            2,
            "setup confirms both records are queued"
        );
        acknowledge(&shared, &record(1), &path_one).expect("ack sequence 1");
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

        acknowledge(&shared, &record(2), &path_two).expect("ack sequence 2");
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

        let checkpoint = signed_checkpoint(&cfg, &ChainTail::genesis(), None, None);
        let first = record(1);
        let pending_bytes = serde_json::to_vec(&first).expect("serialize first").len();
        let shared = SpoolShared {
            config: cfg,
            queue: Mutex::new(BTreeMap::from_iter([(
                1u64,
                queued(&first, known_path.clone()),
            )])),
            checkpoint: Mutex::new(checkpoint),
            overflow_state: Mutex::new(None),
            admitted_tail: Mutex::new(ChainTail::from_record(&record(1))),
            wake: Condvar::new(),
            enqueue_closed: AtomicBool::new(false),
            worker_stop: AtomicBool::new(false),
            pending: AtomicU64::new(1),
            pending_bytes: AtomicU64::new(pending_bytes as u64),
            delivered: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            overflowed: AtomicU64::new(0),
            overflow_poisoned: AtomicBool::new(false),
            destination_timeouts: AtomicU64::new(0),
            shutdown_timeouts: AtomicU64::new(0),
            worker_running: AtomicBool::new(true),
            completion: WorkerCompletion {
                done: Mutex::new(false),
                wake: Condvar::new(),
            },
        };
        let before = shared.status();

        assert!(acknowledge(&shared, &record(99), &unknown_seq_path).is_err());
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
            unknown_seq_path.exists(),
            "a rejected unknown acknowledgement must preserve its durable queue file"
        );
        assert!(
            known_path.exists(),
            "known queued records remain queued when unknown seq is acknowledged"
        );
    }

    // GATE-SEAL residue: `recover_pending` compares a recovered `.tmp` against an
    // already-promoted final record. Identical content must dedupe (remove the
    // tmp and recover cleanly); the `!=` guard mutated to `==` would instead
    // REJECT identical content as a conflict.
    #[test]
    fn recover_pending_dedupes_a_temp_matching_its_promoted_final() {
        let directory = tempfile::tempdir().expect("tempdir");
        let bytes = serde_json::to_vec(&record(1)).expect("serialize");
        let final_path = record_path(directory.path(), 1);
        let tmp_path = temp_record_path(directory.path(), 1);
        std::fs::write(&final_path, &bytes).expect("seed final");
        std::fs::write(&tmp_path, &bytes).expect("seed identical tmp");
        let pending = recover_pending(directory.path(), 32, &[key()])
            .expect("identical temp+final content must recover cleanly, not conflict");
        assert!(
            !tmp_path.exists(),
            "an identical temporary must be deduped away during recovery"
        );
        assert!(
            pending.queue.contains_key(&1),
            "the promoted final record must be recovered as pending"
        );
    }

    struct RejectRecoveredSpool;

    impl ShippingForwarder for RejectRecoveredSpool {
        fn forward(&self, _record: &AuditRecord) -> Result<(), ShippingError> {
            panic!("recovery validation must finish before delivery starts")
        }

        fn validate_recovered_spool(&self, _records: &[AuditRecord]) -> Result<(), ShippingError> {
            Err(ShippingError::Transport(
                "destination rejected recovered spool".to_owned(),
            ))
        }
    }

    #[test]
    fn destination_recovery_validation_finishes_before_ack_cleanup_or_temp_promotion() {
        let directory = tempfile::tempdir().expect("tempdir");
        let acknowledged = acknowledged_path(directory.path(), 1);
        let temporary = temp_record_path(directory.path(), 2);
        write_new_file(
            &acknowledged,
            &serde_json::to_vec(&record(1)).expect("serialize acknowledged record"),
        )
        .expect("seed acknowledged residue");
        write_new_file(
            &temporary,
            &serde_json::to_vec(&record(2)).expect("serialize temporary record"),
        )
        .expect("seed temporary record");

        let error = match DurableShippingForwarder::open(
            config(directory.path(), "validate-before-mutate"),
            Box::new(RejectRecoveredSpool),
        ) {
            Err(error) => error,
            Ok(_) => panic!("destination validation failure must refuse startup"),
        };
        assert!(error.to_string().contains("destination rejected"));
        assert!(
            acknowledged.exists(),
            "recovery must not delete acknowledgement residue before validation"
        );
        assert!(
            temporary.exists(),
            "recovery must not promote temporary state before validation"
        );
        assert!(!record_path(directory.path(), 2).exists());
        assert!(
            !checkpoint_path(directory.path()).exists(),
            "a rejected recovery must not mint a delivery checkpoint"
        );
    }

    fn overflow_fixture(
        directory: &Path,
        id: &str,
        records: &[AuditRecord],
    ) -> (DurableSpoolConfig, DeliveryCheckpoint, OverflowIndicator) {
        let cfg = config(directory, id);
        let mut checkpoint = signed_checkpoint(&cfg, &ChainTail::genesis(), None, None);
        let mut overflow = None;
        for record in records {
            overflow = Some(
                next_overflow(&cfg, overflow.as_ref(), &checkpoint, record)
                    .expect("build signed overflow evidence")
                    .expect("new overflow sequence"),
            );
            checkpoint = signed_checkpoint(
                &cfg,
                &ChainTail {
                    seq: checkpoint.seq,
                    entry_hash: checkpoint.entry_hash.clone(),
                },
                checkpoint.record_key_id.clone(),
                Some(overflow_commitment(overflow.as_ref().unwrap()).expect("commitment")),
            );
        }
        (
            cfg,
            checkpoint,
            overflow.expect("at least one overflow record"),
        )
    }

    fn persist_overflow_fixture(
        config: &DurableSpoolConfig,
        checkpoint: &DeliveryCheckpoint,
        overflow: &OverflowIndicator,
    ) {
        persist_overflow(config, overflow).expect("persist overflow evidence");
        persist_checkpoint(config, checkpoint).expect("persist overflow checkpoint");
    }

    #[test]
    fn signed_overflow_evidence_recovers_exactly_and_is_checkpoint_bound() {
        let directory = tempfile::tempdir().expect("tempdir");
        let (cfg, checkpoint, overflow) =
            overflow_fixture(directory.path(), "overflow-valid", &[record(1), record(2)]);
        persist_overflow_fixture(&cfg, &checkpoint, &overflow);

        let recovered = recover_for_open(&cfg, &Capture::default()).expect("valid recovery");
        assert_eq!(recovered.overflow.as_ref(), Some(&overflow));
        assert_eq!(overflow.count, 2);
        assert_eq!(overflow.key_id, key().key_id());
        assert_eq!(overflow.destination_id, cfg.destination_id);
        assert_eq!(
            recovered.checkpoint.overflow_commitment,
            Some(overflow_commitment(&overflow).expect("commitment"))
        );
    }

    #[test]
    fn missing_or_rolled_back_overflow_evidence_refuses_before_forward_or_mutation() {
        let missing = tempfile::tempdir().expect("missing tempdir");
        let (missing_cfg, missing_checkpoint, _) =
            overflow_fixture(missing.path(), "overflow-missing", &[record(1)]);
        persist_checkpoint(&missing_cfg, &missing_checkpoint).expect("persist commitment only");
        let missing_checkpoint_before =
            std::fs::read(checkpoint_path(missing.path())).expect("read checkpoint");
        let missing_capture = Capture::default();
        let missing_error = recover_for_open(&missing_cfg, &missing_capture)
            .expect_err("committed overflow evidence cannot disappear");
        assert!(
            missing_error.to_string().contains("missing"),
            "{missing_error}"
        );
        assert!(missing_capture.seqs.lock().is_empty());
        assert_eq!(
            std::fs::read(checkpoint_path(missing.path())).expect("re-read checkpoint"),
            missing_checkpoint_before
        );

        let rollback = tempfile::tempdir().expect("rollback tempdir");
        let (rollback_cfg, latest_checkpoint, latest_overflow) = overflow_fixture(
            rollback.path(),
            "overflow-rollback",
            &[record(1), record(2)],
        );
        let (_, _, old_overflow) =
            overflow_fixture(rollback.path(), "overflow-rollback", &[record(1)]);
        persist_overflow_fixture(&rollback_cfg, &latest_checkpoint, &old_overflow);
        let checkpoint_before =
            std::fs::read(checkpoint_path(rollback.path())).expect("checkpoint before");
        let overflow_before =
            std::fs::read(rollback.path().join("overflow.json")).expect("overflow before");
        let rollback_capture = Capture::default();
        let rollback_error = recover_for_open(&rollback_cfg, &rollback_capture)
            .expect_err("older valid signed evidence must not replace the committed latest state");
        assert!(
            rollback_error.to_string().contains("rolled back"),
            "{rollback_error}"
        );
        assert!(rollback_capture.seqs.lock().is_empty());
        assert_eq!(
            std::fs::read(checkpoint_path(rollback.path())).expect("checkpoint after"),
            checkpoint_before
        );
        assert_eq!(
            std::fs::read(rollback.path().join("overflow.json")).expect("overflow after"),
            overflow_before
        );
        assert_ne!(old_overflow, latest_overflow);
    }

    #[test]
    fn overflow_payload_mac_key_and_counter_tampering_fail_closed() {
        #[derive(Clone, Copy)]
        enum Tamper {
            Payload,
            UnknownKey,
            ImpossibleCounter,
            Truncated,
        }
        for (name, tamper) in [
            ("payload", Tamper::Payload),
            ("unknown-key", Tamper::UnknownKey),
            ("counter", Tamper::ImpossibleCounter),
            ("truncated", Tamper::Truncated),
        ] {
            let directory = tempfile::tempdir().expect("tempdir");
            let (cfg, _checkpoint, mut overflow) =
                overflow_fixture(directory.path(), name, &[record(1)]);
            match tamper {
                Tamper::Payload => {
                    overflow.last_entry_hash = crate::sha256_hex(b"tampered-overflow-payload");
                }
                Tamper::UnknownKey => {
                    let unknown = SigningKey::new("unknown", vec![b'U'; 32]).expect("key");
                    overflow.key_id = unknown.key_id().to_owned();
                    overflow.signature = unknown.sign(&overflow_message(&overflow));
                }
                Tamper::ImpossibleCounter => {
                    overflow.count = 0;
                    overflow.signature = key().sign(&overflow_message(&overflow));
                }
                Tamper::Truncated => {}
            }
            let checkpoint = signed_checkpoint(
                &cfg,
                &ChainTail::genesis(),
                None,
                Some(overflow_commitment(&overflow).expect("tampered commitment")),
            );
            persist_checkpoint(&cfg, &checkpoint).expect("persist checkpoint");
            if matches!(tamper, Tamper::Truncated) {
                write_new_file(&cfg.directory.join("overflow.json"), b"{\"version\":2")
                    .expect("persist truncated evidence");
            } else {
                let bytes = serde_json::to_vec(&overflow).expect("serialize tampered evidence");
                write_new_file(&cfg.directory.join("overflow.json"), &bytes)
                    .expect("persist tampered evidence");
            }
            let checkpoint_before =
                std::fs::read(checkpoint_path(directory.path())).expect("checkpoint before");
            let overflow_before =
                std::fs::read(directory.path().join("overflow.json")).expect("overflow before");
            let capture = Capture::default();
            assert!(
                recover_for_open(&cfg, &capture).is_err(),
                "{name} overflow tamper must refuse recovery"
            );
            assert!(capture.seqs.lock().is_empty(), "{name} forwarded a record");
            assert_eq!(
                std::fs::read(checkpoint_path(directory.path())).expect("checkpoint after"),
                checkpoint_before
            );
            assert_eq!(
                std::fs::read(directory.path().join("overflow.json")).expect("overflow after"),
                overflow_before
            );
        }
    }

    #[test]
    fn signed_checkpoint_tampering_refuses_recovery_without_mutating_spool_state() {
        let directory = tempfile::tempdir().expect("tempdir");
        let cfg = config(directory.path(), "tampered-checkpoint");
        let checkpoint = signed_checkpoint(&cfg, &ChainTail::genesis(), None, None);
        persist_checkpoint(&cfg, &checkpoint).expect("seed signed checkpoint");
        let mut tampered = checkpoint;
        let first = record(1);
        tampered.seq = first.seq;
        tampered.entry_hash.clone_from(&first.entry_hash);
        tampered.record_key_id = first.key_id.clone();
        std::fs::write(
            checkpoint_path(directory.path()),
            serde_json::to_vec(&tampered).expect("serialize tampered checkpoint"),
        )
        .expect("tamper checkpoint");
        let temporary = temp_record_path(directory.path(), 1);
        write_new_file(
            &temporary,
            &serde_json::to_vec(&first).expect("serialize pending record"),
        )
        .expect("seed pending record");

        let error = match DurableShippingForwarder::open(cfg, Box::new(Capture::default())) {
            Err(error) => error,
            Ok(_) => panic!("tampered checkpoint must refuse startup"),
        };
        assert!(error.to_string().contains("signature does not verify"));
        assert!(temporary.exists(), "refusal must preserve temporary state");
        assert!(!record_path(directory.path(), 1).exists());
    }

    #[test]
    fn one_ack_residue_plus_a_full_pending_queue_recovers_at_exact_capacity() {
        let directory = tempfile::tempdir().expect("tempdir");
        let cfg = config(directory.path(), "ack-plus-capacity").with_max_records(2);
        let first = record(1);
        let checkpoint = signed_checkpoint(
            &cfg,
            &ChainTail::from_record(&first),
            first.key_id.clone(),
            None,
        );
        persist_checkpoint(&cfg, &checkpoint).expect("seed delivery checkpoint");
        write_new_file(
            &acknowledged_path(directory.path(), 1),
            &serde_json::to_vec(&first).expect("serialize ack residue"),
        )
        .expect("seed ack residue");
        for seq in 2..=3 {
            write_new_file(
                &record_path(directory.path(), seq),
                &serde_json::to_vec(&record(seq)).expect("serialize pending record"),
            )
            .expect("seed pending record");
        }

        let delivery = DurableShippingForwarder::open(cfg, Box::new(AlwaysFails))
            .expect("one ack residue must not consume pending capacity");
        assert_eq!(delivery.status_handle().snapshot().pending_records, 2);
        assert!(!acknowledged_path(directory.path(), 1).exists());
        assert_eq!(delivery.shutdown(), DurableShippingShutdownOutcome::Stopped);
    }

    #[test]
    fn signed_checkpoint_cleans_an_older_final_residue_after_ack_cleanup_failure() {
        let directory = tempfile::tempdir().expect("tempdir");
        let cfg = config(directory.path(), "checkpoint-final-residue");
        let second = record(2);
        let checkpoint = signed_checkpoint(
            &cfg,
            &ChainTail::from_record(&second),
            second.key_id.clone(),
            None,
        );
        persist_checkpoint(&cfg, &checkpoint).expect("seed advanced checkpoint");
        let residue = record_path(directory.path(), 1);
        write_new_file(
            &residue,
            &serde_json::to_vec(&record(1)).expect("serialize old residue"),
        )
        .expect("seed old final residue");

        let delivery = DurableShippingForwarder::open(cfg, Box::new(Capture::default()))
            .expect("checkpoint proves the older final record was already delivered");
        assert!(!residue.exists());
        assert_eq!(delivery.status_handle().snapshot().pending_records, 0);
        assert_eq!(delivery.shutdown(), DurableShippingShutdownOutcome::Stopped);
    }

    #[test]
    fn recovery_enforces_absolute_record_and_aggregate_byte_bounds() {
        let directory = tempfile::tempdir().expect("tempdir");
        let over_record_limit =
            config(directory.path(), "record-limit").with_max_records(MAX_SPOOL_RECORDS + 1);
        let error = validate_config(&over_record_limit)
            .expect_err("caller cannot configure an effectively unbounded recovery");
        assert!(error.to_string().contains(&MAX_SPOOL_RECORDS.to_string()));

        let cfg = config(directory.path(), "byte-limit");
        let path = record_path(directory.path(), 1);
        let bytes = serde_json::to_vec(&record(1)).expect("serialize record");
        write_new_file(&path, &bytes).expect("seed record");
        let error = match inspect_recovery_with_byte_limit(&cfg, bytes.len() - 1) {
            Err(error) => error,
            Ok(_) => panic!("aggregate recovery bytes must be bounded independently of count"),
        };
        assert!(error.to_string().contains("aggregate recovery budget"));
        assert!(
            path.exists(),
            "bounded inspection must not mutate spool state"
        );
    }

    #[test]
    fn authoritative_primary_rejects_a_missing_first_spool_record() {
        let root = tempfile::tempdir().expect("tempdir");
        let primary_path = root.path().join("audit.jsonl");
        let primary = FileAuditSink::open(&primary_path).expect("open primary");
        primary
            .append(&record(1))
            .expect("append primary record one");
        primary
            .append(&record(2))
            .expect("append primary record two");
        primary.flush().expect("flush primary");
        let spool = root.path().join("spool");
        std::fs::create_dir(&spool).expect("create spool");
        let second_path = record_path(&spool, 2);
        write_new_file(
            &second_path,
            &serde_json::to_vec(&record(2)).expect("serialize second record"),
        )
        .expect("seed incomplete spool");
        let authenticated = authenticate_primary(&primary, &primary_path);
        let cfg = config(&spool, "missing-first").with_authenticated_primary(&authenticated);

        let error = match DurableShippingForwarder::open(cfg, Box::new(Capture::default())) {
            Err(error) => error,
            Ok(_) => panic!("a surviving suffix cannot authenticate an omitted prefix"),
        };
        assert!(
            error
                .to_string()
                .contains("does not continue authenticated checkpoint sequence 0")
        );
        assert!(second_path.exists());
        assert!(!checkpoint_path(&spool).exists());
    }

    #[test]
    fn rejected_primary_or_anchor_authentication_precedes_spool_mutation_and_forwarding() {
        for reject_anchor in [false, true] {
            let root = tempfile::tempdir().expect("tempdir");
            let primary_path = root.path().join("audit.jsonl");
            let primary = FileAuditSink::open(&primary_path).expect("open primary");
            let record_key = if reject_anchor {
                key()
            } else {
                SigningKey::new("untrusted", vec![b'X'; 32]).expect("untrusted key")
            };
            let primary_record = AuditRecord::chained_signed(
                &draft(1),
                1,
                crate::GENESIS_HASH,
                "primary-t1".to_owned(),
                &record_key,
            );
            primary.append(&primary_record).expect("append primary");
            primary.flush().expect("flush primary");
            let anchor_path = crate::anchor_path_for(&primary_path);
            if reject_anchor {
                let attacker = SigningKey::new("attacker", vec![b'A'; 32]).expect("attacker key");
                crate::AnchorFile::new(&anchor_path, attacker)
                    .record_head(primary_record.seq, &primary_record.entry_hash)
                    .expect("write forged anchor");
            }

            let spool = root.path().join("spool");
            std::fs::create_dir(&spool).expect("create spool");
            let residue = temp_record_path(&spool, 1);
            write_new_file(&residue, b"unchanged-spool-residue").expect("seed residue");
            let residue_before = std::fs::read(&residue).expect("read residue");
            let capture = Capture::default();

            let error = primary
                .authenticate_existing_chain(&primary_path, &anchor_path, &[key()])
                .expect_err("primary/anchor authentication must fail closed");
            let message = error.to_string();
            if reject_anchor {
                assert!(message.contains("anchor"), "{message}");
            } else {
                assert!(message.contains("untrusted"), "{message}");
            }
            assert_eq!(
                std::fs::read(&residue).expect("re-read residue"),
                residue_before,
                "authentication refusal must not promote or clean spool state"
            );
            assert!(!checkpoint_path(&spool).exists());
            assert!(capture.seqs.lock().is_empty(), "refusal forwarded a record");
        }
    }

    #[test]
    fn authoritative_primary_rejects_a_missing_spool_tail() {
        let root = tempfile::tempdir().expect("tempdir");
        let primary_path = root.path().join("audit.jsonl");
        let primary = FileAuditSink::open(&primary_path).expect("open primary");
        primary
            .append(&record(1))
            .expect("append primary record one");
        primary
            .append(&record(2))
            .expect("append primary record two");
        primary.flush().expect("flush primary");
        let spool = root.path().join("spool");
        std::fs::create_dir(&spool).expect("create spool");
        let first_path = record_path(&spool, 1);
        write_new_file(
            &first_path,
            &serde_json::to_vec(&record(1)).expect("serialize first record"),
        )
        .expect("seed incomplete spool");
        let authenticated = authenticate_primary(&primary, &primary_path);
        let cfg = config(&spool, "missing-tail").with_authenticated_primary(&authenticated);

        let error = match DurableShippingForwarder::open(cfg, Box::new(Capture::default())) {
            Err(error) => error,
            Ok(_) => panic!("a surviving prefix cannot authenticate an omitted tail"),
        };
        assert!(
            error
                .to_string()
                .contains("authoritative primary sequence 2")
        );
        assert!(first_path.exists());
        assert!(!checkpoint_path(&spool).exists());
    }

    #[test]
    fn primary_fsync_without_spool_admission_is_detected_on_restart() {
        let root = tempfile::tempdir().expect("tempdir");
        let primary_path = root.path().join("audit.jsonl");
        let primary = FileAuditSink::open(&primary_path).expect("open primary");
        primary.append(&record(1)).expect("append primary record");
        primary.flush().expect("flush primary");
        let spool = root.path().join("spool");
        let authenticated = authenticate_primary(&primary, &primary_path);
        let cfg = config(&spool, "fsync-before-enqueue").with_authenticated_primary(&authenticated);

        let error = match DurableShippingForwarder::open(cfg, Box::new(Capture::default())) {
            Err(error) => error,
            Ok(_) => panic!("empty spool cannot silently skip a durable primary record"),
        };
        assert!(
            error
                .to_string()
                .contains("authoritative primary sequence 1")
        );
        assert!(!checkpoint_path(&spool).exists());
    }

    #[cfg(unix)]
    #[test]
    fn spool_refuses_link_and_fifo_control_files_without_touching_victims() {
        use std::os::unix::fs::symlink;

        let lock_dir = tempfile::tempdir().expect("lock tempdir");
        let lock_victim = lock_dir.path().join("lock-victim");
        std::fs::write(&lock_victim, b"lock-victim-bytes").expect("seed lock victim");
        symlink(&lock_victim, lock_dir.path().join("spool.lock")).expect("plant lock symlink");
        let lock_error = match DurableShippingForwarder::open(
            config(lock_dir.path(), "unsafe-lock"),
            Box::new(Capture::default()),
        ) {
            Err(error) => error,
            Ok(_) => panic!("symlinked spool lock must fail closed"),
        };
        assert!(lock_error.to_string().contains("symlink"));
        assert_eq!(
            std::fs::read(&lock_victim).expect("read lock victim"),
            b"lock-victim-bytes"
        );

        let binding_dir = tempfile::tempdir().expect("binding tempdir");
        let binding_victim = binding_dir.path().join("binding-victim");
        std::fs::write(&binding_victim, b"binding-victim-bytes").expect("seed binding victim");
        std::fs::hard_link(&binding_victim, binding_dir.path().join("destination.json"))
            .expect("plant destination hardlink");
        let binding_error = match DurableShippingForwarder::open(
            config(binding_dir.path(), "unsafe-binding"),
            Box::new(Capture::default()),
        ) {
            Err(error) => error,
            Ok(_) => panic!("hard-linked destination binding must fail closed"),
        };
        assert!(binding_error.to_string().contains("hard links"));
        assert_eq!(
            std::fs::read(&binding_victim).expect("read binding victim"),
            b"binding-victim-bytes"
        );

        let fifo_dir = tempfile::tempdir().expect("fifo tempdir");
        let fifo = fifo_dir.path().join("record-00000000000000000001.json");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo");
        assert!(status.success());
        let fifo_error = match DurableShippingForwarder::open(
            config(fifo_dir.path(), "unsafe-record"),
            Box::new(Capture::default()),
        ) {
            Err(error) => error,
            Ok(_) => panic!("FIFO spool record must fail closed"),
        };
        assert!(fifo_error.to_string().contains("non-regular"));
    }

    #[cfg(unix)]
    #[test]
    fn spool_uses_private_files_and_random_temps_leave_fixed_victims_untouched() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir().expect("tempdir");
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let delivery = DurableShippingForwarder::open(
            config(directory.path(), "private-files").with_max_records(1),
            Box::new(GateForwarder {
                gate: Arc::clone(&gate),
            }),
        )
        .expect("open spool");
        let _release = release_gate_on_drop(&gate);
        let temp_victim = directory.path().join("temp-victim");
        let overflow_victim = directory.path().join("overflow-victim");
        std::fs::write(&temp_victim, b"temp-victim-bytes").expect("seed temp victim");
        std::fs::write(&overflow_victim, b"overflow-victim-bytes").expect("seed overflow victim");
        symlink(&temp_victim, temp_record_path(directory.path(), 1))
            .expect("plant legacy fixed record temp");
        symlink(&overflow_victim, directory.path().join("overflow.tmp"))
            .expect("plant legacy fixed overflow temp");

        delivery.forward(&record(1)).expect("random-temp enqueue");
        delivery
            .forward(&record(2))
            .expect_err("second record overflows capacity");
        assert_eq!(
            std::fs::read(&temp_victim).expect("read temp victim"),
            b"temp-victim-bytes"
        );
        assert_eq!(
            std::fs::read(&overflow_victim).expect("read overflow victim"),
            b"overflow-victim-bytes"
        );
        assert_eq!(
            std::fs::metadata(record_path(directory.path(), 1))
                .expect("record metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        for name in ["spool.lock", "destination.json", "overflow.json"] {
            assert_eq!(
                std::fs::metadata(directory.path().join(name))
                    .expect("control metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600,
                "{name} must be private"
            );
        }
        assert_eq!(
            std::fs::metadata(directory.path())
                .expect("directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        open_gate(&gate);
    }

    #[cfg(unix)]
    #[test]
    fn oversized_recovery_stops_before_opening_any_record_body() {
        let directory = tempfile::tempdir().expect("tempdir");
        write_new_file(
            &record_path(directory.path(), 1),
            &serde_json::to_vec(&record(1)).expect("serialize first"),
        )
        .expect("seed first record");
        let tripwire = record_path(directory.path(), 2);
        let status = std::process::Command::new("mkfifo")
            .arg(&tripwire)
            .status()
            .expect("run mkfifo");
        assert!(status.success());

        let error = recover_pending(directory.path(), 1, &[key()])
            .expect_err("capacity+1 must fail before parsing record bodies");
        assert!(
            error.to_string().contains("exceeds configured capacity 1"),
            "the FIFO tripwire must not be opened before capacity refusal: {error}"
        );
    }

    #[test]
    fn acknowledged_residues_count_toward_recovery_scan_capacity() {
        let directory = tempfile::tempdir().expect("tempdir");
        for seq in 1..=3 {
            write_new_file(
                &acknowledged_path(directory.path(), seq),
                &serde_json::to_vec(&record(seq)).expect("serialize acknowledged residue"),
            )
            .expect("seed acknowledged residue");
        }

        let error = recover_pending(directory.path(), 1, &[key()])
            .expect_err("more than one acknowledgement residue beyond capacity must fail");
        assert!(
            error
                .to_string()
                .contains("exceeds the bounded recognized-state limit of 2"),
            "unexpected acknowledgement scan-cap refusal: {error}"
        );
        for seq in 1..=3 {
            assert!(
                acknowledged_path(directory.path(), seq).exists(),
                "over-capacity pre-scan must refuse before opening or deleting residue {seq}"
            );
        }
    }

    #[test]
    fn recovery_rejects_payload_hash_signature_and_link_tampering_before_forwarding() {
        for kind in ["payload", "hash", "signature", "link"] {
            let directory = tempfile::tempdir().expect("tempdir");
            let capture = Arc::new(Capture::default());
            let first = record(1);
            let mut tampered = first.clone();
            match kind {
                "payload" => tampered.tool.push_str("-tampered"),
                "hash" => tampered.entry_hash.push('0'),
                "signature" => tampered
                    .signature
                    .as_mut()
                    .expect("signed record has a signature")
                    .push('0'),
                "link" => {}
                _ => unreachable!(),
            }
            write_new_file(
                &record_path(directory.path(), 1),
                &serde_json::to_vec(&tampered).expect("serialize tampered record"),
            )
            .expect("seed tampered record");
            if kind == "link" {
                let bad_link = AuditRecord::chained_signed(
                    &draft(2),
                    2,
                    GENESIS_HASH,
                    "t2".to_owned(),
                    &key(),
                );
                write_new_file(
                    &record_path(directory.path(), 2),
                    &serde_json::to_vec(&bad_link).expect("serialize bad link"),
                )
                .expect("seed bad link");
            }

            let error = match DurableShippingForwarder::open(
                config(directory.path(), &format!("tamper-{kind}")),
                Box::new(SharedCapture(Arc::clone(&capture))),
            ) {
                Err(error) => error,
                Ok(_) => panic!("{kind} tampering must fail before worker startup"),
            };
            assert!(
                matches!(error, ShippingError::SpoolIntegrity { .. }),
                "{kind} tampering must return a typed integrity refusal: {error}"
            );
            assert!(
                capture.seqs.lock().is_empty(),
                "{kind} tampering must produce zero destination forwards"
            );
        }
    }

    #[derive(Default)]
    struct DestinationCallGateState {
        started: bool,
        open: bool,
        seqs: Vec<u64>,
    }

    struct DestinationCallGate {
        state: Arc<(Mutex<DestinationCallGateState>, Condvar)>,
    }

    impl ShippingForwarder for DestinationCallGate {
        fn forward(&self, record: &AuditRecord) -> Result<(), ShippingError> {
            let (state, wake) = &*self.state;
            let mut state = state.lock();
            state.seqs.push(record.seq);
            state.started = true;
            wake.notify_all();
            while !state.open {
                wake.wait(&mut state);
            }
            Ok(())
        }
    }

    fn wait_for_destination_call(state: &Arc<(Mutex<DestinationCallGateState>, Condvar)>) {
        let (state, wake) = &**state;
        let mut state = state.lock();
        let deadline = Instant::now() + Duration::from_secs(1);
        while !state.started {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "delivery worker must enter the destination call"
            );
            wake.wait_for(&mut state, remaining);
        }
    }

    fn release_destination_call(state: &Arc<(Mutex<DestinationCallGateState>, Condvar)>) {
        let (state, wake) = &**state;
        state.lock().open = true;
        wake.notify_all();
    }

    #[test]
    fn post_open_signed_record_replacement_is_refused_before_external_delivery() {
        let directory = tempfile::tempdir().expect("tempdir");
        let state = Arc::new((
            Mutex::new(DestinationCallGateState::default()),
            Condvar::new(),
        ));
        let delivery = DurableShippingForwarder::open(
            config(directory.path(), "post-open-replacement"),
            Box::new(DestinationCallGate {
                state: Arc::clone(&state),
            }),
        )
        .expect("open spool");
        let first = record(1);
        let second = record(2);
        delivery.forward(&first).expect("enqueue first record");
        wait_for_destination_call(&state);
        delivery.forward(&second).expect("enqueue second record");

        let mut alternate_draft = draft(2);
        alternate_draft.tool = "oracle_query".to_owned();
        alternate_draft.sql = "SELECT 2 FROM dual".to_owned();
        let alternate = AuditRecord::chained_signed(
            &alternate_draft,
            2,
            &first.entry_hash,
            "alternate-t2".to_owned(),
            &key(),
        );
        assert_ne!(alternate.entry_hash, second.entry_hash);
        std::fs::write(
            record_path(directory.path(), 2),
            serde_json::to_vec(&alternate).expect("serialize alternate signed record"),
        )
        .expect("replace queued record after startup");

        release_destination_call(&state);
        let status = delivery.status_handle();
        wait_until(Duration::from_secs(1), || !status.snapshot().worker_running);
        assert_eq!(
            state.0.lock().seqs,
            vec![1],
            "the substituted signed record must not cross the destination boundary"
        );
        assert!(record_path(directory.path(), 2).exists());
        assert_eq!(delivery.shutdown(), DurableShippingShutdownOutcome::Stopped);
    }

    #[test]
    fn shutdown_budget_includes_waiting_for_the_queue_mutex() {
        let directory = tempfile::tempdir().expect("tempdir");
        let delivery = Arc::new(
            DurableShippingForwarder::open(
                config(directory.path(), "queue-lock-timeout")
                    .with_timeouts(Duration::from_secs(1), Duration::from_millis(20)),
                Box::new(Capture::default()),
            )
            .expect("open spool"),
        );
        let queue = delivery.shared.queue.lock();
        let (finished_tx, finished_rx) = mpsc::sync_channel(1);
        let shutdown_delivery = Arc::clone(&delivery);
        let caller = thread::spawn(move || {
            finished_tx
                .send(shutdown_delivery.shutdown())
                .expect("report shutdown result");
        });
        assert_eq!(
            finished_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("shutdown must return while the queue remains locked"),
            DurableShippingShutdownOutcome::TimedOut
        );
        drop(queue);
        caller.join().expect("shutdown caller joins");
        assert_eq!(delivery.shutdown(), DurableShippingShutdownOutcome::Stopped);
    }

    #[test]
    fn worker_exit_revokes_old_facade_before_a_successor_acquires_the_spool() {
        let directory = tempfile::tempdir().expect("tempdir");
        let state = Arc::new((
            Mutex::new(DestinationCallGateState::default()),
            Condvar::new(),
        ));
        let cfg = config(directory.path(), "worker-exit-revocation")
            .with_timeouts(Duration::from_millis(20), Duration::from_secs(1));
        let delivery = DurableShippingForwarder::open(
            cfg.clone(),
            Box::new(DestinationCallGate {
                state: Arc::clone(&state),
            }),
        )
        .expect("open spool");
        let status = delivery.status_handle();
        delivery.forward(&record(1)).expect("enqueue record");
        wait_for_destination_call(&state);
        wait_until(Duration::from_secs(1), || {
            status.snapshot().destination_timeouts == 1
        });
        release_destination_call(&state);
        wait_until(Duration::from_secs(1), || !status.snapshot().worker_running);

        let successor = DurableShippingForwarder::open(cfg, Box::new(AlwaysFails))
            .expect("successor acquires the released spool lease");
        let error = delivery
            .forward(&record(2))
            .expect_err("old facade must lose enqueue authority before lease release");
        assert!(error.to_string().contains("worker is stopped"));
        assert_eq!(delivery.shutdown(), DurableShippingShutdownOutcome::Stopped);
        assert_eq!(
            successor.shutdown(),
            DurableShippingShutdownOutcome::Stopped
        );
    }

    #[test]
    fn enqueue_rejects_records_that_recovery_cannot_read() {
        let directory = tempfile::tempdir().expect("tempdir");
        let delivery = DurableShippingForwarder::open(
            config(directory.path(), "oversized-record"),
            Box::new(Capture::default()),
        )
        .expect("open spool");
        let mut oversized_draft = draft(1);
        oversized_draft.tool = "x".repeat(crate::MAX_AUDIT_LINE_LEN);
        let oversized = AuditRecord::chained_signed(
            &oversized_draft,
            1,
            GENESIS_HASH,
            "oversized".to_owned(),
            &key(),
        );
        let error = delivery
            .forward(&oversized)
            .expect_err("enqueue must reject a record recovery would refuse");
        assert!(error.to_string().contains("spool file limit"));
        assert!(!record_path(directory.path(), 1).exists());
        assert_eq!(delivery.status_handle().snapshot().pending_records, 0);
        assert_eq!(delivery.shutdown(), DurableShippingShutdownOutcome::Stopped);
    }

    #[test]
    fn pending_byte_budget_accepts_the_exact_boundary_only() {
        let record_bytes = serde_json::to_vec(&record(1))
            .expect("serialize record")
            .len();
        let exact = MAX_SPOOL_RECOVERY_BYTES as u64 - record_bytes as u64;
        assert_eq!(
            checked_pending_byte_total(exact, record_bytes),
            Some(MAX_SPOOL_RECOVERY_BYTES as u64)
        );
        assert_eq!(checked_pending_byte_total(exact + 1, record_bytes), None);
        assert_eq!(checked_pending_byte_total(u64::MAX, 1), None);
    }

    #[test]
    fn blocked_destination_cannot_exceed_shutdown_budget_and_record_stays_durable() {
        let directory = tempfile::tempdir().expect("tempdir");
        let state = Arc::new((
            Mutex::new(DestinationCallGateState::default()),
            Condvar::new(),
        ));
        let delivery = Arc::new(
            DurableShippingForwarder::open(
                config(directory.path(), "bounded-shutdown")
                    .with_timeouts(Duration::from_secs(30), Duration::from_millis(20)),
                Box::new(DestinationCallGate {
                    state: Arc::clone(&state),
                }),
            )
            .expect("open spool"),
        );
        delivery.forward(&record(1)).expect("enqueue record");
        wait_for_destination_call(&state);

        let (finished_tx, finished_rx) = mpsc::sync_channel(1);
        let shutdown_delivery = Arc::clone(&delivery);
        let caller = thread::spawn(move || {
            finished_tx
                .send(shutdown_delivery.shutdown())
                .expect("report shutdown result");
        });
        assert_eq!(
            finished_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("shutdown must honor its configured budget"),
            DurableShippingShutdownOutcome::TimedOut
        );
        caller.join().expect("shutdown caller joins");
        assert!(
            record_path(directory.path(), 1).exists(),
            "unacknowledged record must remain durable after timeout"
        );
        assert_eq!(delivery.status_handle().snapshot().shutdown_timeouts, 1);

        release_destination_call(&state);
        assert_eq!(delivery.shutdown(), DurableShippingShutdownOutcome::Stopped);
    }

    #[test]
    fn timed_out_owner_keeps_the_spool_lease_until_its_worker_exits() {
        let directory = tempfile::tempdir().expect("tempdir");
        let state = Arc::new((
            Mutex::new(DestinationCallGateState::default()),
            Condvar::new(),
        ));
        let delivery = DurableShippingForwarder::open(
            config(directory.path(), "lease-after-timeout")
                .with_timeouts(Duration::from_secs(30), Duration::from_millis(20)),
            Box::new(DestinationCallGate {
                state: Arc::clone(&state),
            }),
        )
        .expect("open spool");
        let status = delivery.status_handle();
        delivery.forward(&record(1)).expect("enqueue record");
        wait_for_destination_call(&state);

        assert_eq!(
            delivery.shutdown(),
            DurableShippingShutdownOutcome::TimedOut
        );
        drop(delivery);

        let overlap_error = match DurableShippingForwarder::open(
            config(directory.path(), "lease-after-timeout"),
            Box::new(Capture::default()),
        ) {
            Err(error) => error,
            Ok(_) => panic!("a successor must not overlap the timed-out worker"),
        };
        assert!(overlap_error.to_string().contains("already owned"));

        release_destination_call(&state);
        wait_until(Duration::from_secs(1), || !status.snapshot().worker_running);
        wait_until(Duration::from_secs(1), || {
            SpoolLock::acquire(directory.path()).is_ok()
        });

        let successor = DurableShippingForwarder::open(
            config(directory.path(), "lease-after-timeout"),
            Box::new(Capture::default()),
        )
        .expect("successor opens after the old worker releases its lease");
        assert_eq!(successor.status_handle().snapshot().pending_records, 0);
        assert_eq!(
            successor.shutdown(),
            DurableShippingShutdownOutcome::Stopped
        );
    }

    #[test]
    fn destination_timeout_halts_delivery_but_keeps_durable_enqueue_open_for_restart() {
        let directory = tempfile::tempdir().expect("tempdir");
        let state = Arc::new((
            Mutex::new(DestinationCallGateState::default()),
            Condvar::new(),
        ));
        let cfg = config(directory.path(), "destination-deadline")
            .with_max_records(2)
            .with_timeouts(Duration::from_millis(20), Duration::from_secs(1));
        let delivery = DurableShippingForwarder::open(
            cfg.clone(),
            Box::new(DestinationCallGate {
                state: Arc::clone(&state),
            }),
        )
        .expect("open spool");
        let status = delivery.status_handle();
        delivery.forward(&record(1)).expect("enqueue record");
        wait_for_destination_call(&state);
        wait_until(Duration::from_secs(1), || {
            let snapshot = status.snapshot();
            snapshot.destination_timeouts == 1
        });
        assert!(
            status.snapshot().worker_running,
            "the timed-out call must retain worker ownership until it actually exits"
        );

        delivery
            .forward(&record(2))
            .expect("delivery timeout must not close durable enqueue");
        let overflow = delivery
            .forward(&record(3))
            .expect_err("halted worker still enforces durable spool capacity");
        assert!(overflow.to_string().contains("spool is full"));
        let snapshot = status.snapshot();
        assert_eq!(snapshot.pending_records, 2);
        assert_eq!(snapshot.overflowed_records, 1);
        assert!(record_path(directory.path(), 1).exists());
        assert!(record_path(directory.path(), 2).exists());
        assert!(directory.path().join("overflow.json").exists());

        release_destination_call(&state);
        assert_eq!(delivery.shutdown(), DurableShippingShutdownOutcome::Stopped);
        drop(delivery);

        let capture = Arc::new(Capture::default());
        let recovery =
            DurableShippingForwarder::open(cfg, Box::new(SharedCapture(Arc::clone(&capture))))
                .expect("restart recovers records accepted after the old worker halted");
        let recovery_status = recovery.status_handle();
        wait_until(Duration::from_secs(1), || {
            recovery_status.snapshot().delivered_records == 2
        });
        assert_eq!(*capture.seqs.lock(), vec![1, 2]);
        assert_eq!(recovery.shutdown(), DurableShippingShutdownOutcome::Stopped);
    }

    #[test]
    fn destination_timeout_retains_the_spool_lease_until_the_call_returns() {
        let directory = tempfile::tempdir().expect("tempdir");
        let state = Arc::new((
            Mutex::new(DestinationCallGateState::default()),
            Condvar::new(),
        ));
        let cfg = config(directory.path(), "deadline-lease")
            .with_timeouts(Duration::from_millis(20), Duration::from_millis(20));
        let delivery = DurableShippingForwarder::open(
            cfg.clone(),
            Box::new(DestinationCallGate {
                state: Arc::clone(&state),
            }),
        )
        .expect("open spool");
        let status = delivery.status_handle();
        delivery.forward(&record(1)).expect("enqueue record");
        wait_for_destination_call(&state);
        wait_until(Duration::from_secs(1), || {
            status.snapshot().destination_timeouts == 1
        });
        assert_eq!(
            delivery.shutdown(),
            DurableShippingShutdownOutcome::TimedOut
        );
        drop(delivery);

        let overlap =
            match DurableShippingForwarder::open(cfg.clone(), Box::new(Capture::default())) {
                Err(error) => error,
                Ok(_) => panic!("a detached timed-out call must retain exclusive spool ownership"),
            };
        assert!(overlap.to_string().contains("already owned"));

        release_destination_call(&state);
        wait_until(Duration::from_secs(1), || !status.snapshot().worker_running);
        let successor = DurableShippingForwarder::open(cfg, Box::new(Capture::default()))
            .expect("successor opens only after the timed-out call exits");
        assert_eq!(
            successor.shutdown(),
            DurableShippingShutdownOutcome::Stopped
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
        let cfg = config(directory.path(), "overflow-read-error");
        assert!(
            load_overflow(&cfg).is_err(),
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
