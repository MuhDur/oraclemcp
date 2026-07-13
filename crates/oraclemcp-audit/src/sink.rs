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

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{BufReader, Seek, SeekFrom, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

use parking_lot::Mutex;
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::anchor::{AnchorFile, ChainAnchor, load_anchor};
use crate::keyring::AuditKeyring;
use crate::record::{AuditCorrelation, AuditEntryDraft, AuditRecord, GENESIS_HASH, SigningKey};
use crate::verify::{BrokenReason, ChainVerifier, JsonlError, JsonlReader, VerifyOutcome};

/// Stable identity of an already-open filesystem object. Comparing identities
/// from the open handles (rather than path strings) catches symlink, hard-link,
/// case-folding, and mount aliases without a check/open race.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OpenFileIdentity {
    volume: u64,
    file: u64,
}

#[cfg(unix)]
pub(crate) fn open_file_identity(file: &File) -> std::io::Result<OpenFileIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    Ok(OpenFileIdentity {
        volume: metadata.dev(),
        file: metadata.ino(),
    })
}

#[cfg(windows)]
pub(crate) fn open_file_identity(file: &File) -> std::io::Result<OpenFileIdentity> {
    use std::os::windows::fs::MetadataExt;

    let metadata = file.metadata()?;
    let volume = metadata.volume_serial_number().ok_or_else(|| {
        std::io::Error::other("filesystem did not provide a volume serial number")
    })?;
    let file_index = metadata
        .file_index()
        .ok_or_else(|| std::io::Error::other("filesystem did not provide a file index"))?;
    Ok(OpenFileIdentity {
        volume: u64::from(volume),
        file: file_index,
    })
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn open_file_identity(_file: &File) -> std::io::Result<OpenFileIdentity> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "open-file identity is unavailable on this platform",
    ))
}

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
    /// The verdict-certificate core hash is not canonical `sha256:<lowercase
    /// hex>`. Refuse it before an audit record can attest to an unverifiable
    /// certificate.
    #[error("invalid verdict certificate core hash")]
    InvalidVerdictCertificateCoreHash,
    /// Chain resume refused at startup: an existing audit log cannot seed a
    /// continuing hash chain without forking it or masking a truncation (a
    /// malformed tail, or a tail that contradicts the head anchor). The server
    /// must not start until an operator inspects/repairs the log — the message
    /// names the file and the repair path. See [`Auditor::resume_from`].
    #[error("audit chain resume refused: {0}")]
    ResumeRefused(String),
    /// A writable [`FileAuditSink`] could not take the exclusive advisory OS
    /// lock on the audit log because another oraclemcp instance already holds
    /// it (bead oraclemcp-mbu1). Two writers on one log would each resume from
    /// the same tail and both issue seq=N+1, FORKING the tamper-evident hash
    /// chain. The second instance fails closed at open time rather than forking.
    /// This is advisory `flock`/`LockFileEx`: a crashed holder releases the lock
    /// on process exit, so a clean restart re-acquires without operator action.
    #[error(
        "audit log {path} is locked by another oraclemcp instance{}; \
         refusing to fork the hash-chain",
        .holder_pid.map_or_else(String::new, |pid| format!(" (pid {pid})"))
    )]
    Locked {
        /// The audit log path whose lock is contended.
        path: String,
        /// The holding process id, if the lock sidecar recorded a readable one
        /// (best-effort operator hint; `None` when it could not be read).
        holder_pid: Option<u32>,
    },
}

fn is_canonical_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

/// An append-only, durable audit sink.
pub trait AuditSink: Send + Sync {
    /// Append one record. Implementations must write the full record before
    /// returning.
    fn append(&self, record: &AuditRecord) -> Result<(), AuditError>;
    /// Flush + fsync any buffered data to durable storage.
    fn flush(&self) -> Result<(), AuditError>;
}

/// The sidecar lock path for an audit log: `<audit path>.lock`. The advisory
/// OS lock is taken on this sibling file, never the data file itself, so the
/// lock is independent of the append fd and of the separate read fds that
/// `Auditor::resume_from` / `audit verify` open, and so the sidecar can carry
/// the holder pid as an operator hint on contention.
fn lock_path_for(audit_path: &Path) -> PathBuf {
    let mut path = audit_path.as_os_str().to_owned();
    path.push(".lock");
    PathBuf::from(path)
}

/// An exclusive advisory OS lock held for a writable audit sink's lifetime
/// (bead oraclemcp-mbu1). Acquired on the `<audit>.lock` sibling with
/// `File::try_lock` (`flock(LOCK_EX|LOCK_NB)` on Unix, `LockFileEx` on
/// Windows). A second oraclemcp opening the same log fails closed with
/// [`AuditError::Locked`] instead of silently forking the hash chain. The lock
/// releases on `Drop` (and, since it is an OS advisory lock tied to the open
/// file description, also on process exit — a crashed holder never permanently
/// wedges a restart).
struct AuditLogLock {
    file: File,
}

impl AuditLogLock {
    /// Take the exclusive advisory lock guarding writes to `audit_path`, or
    /// fail closed if another instance already holds it.
    fn acquire(audit_path: &Path) -> Result<Self, AuditError> {
        let lock_path = lock_path_for(audit_path);
        // Symlink-safe, private (0600), never-truncate-on-open sidecar: a
        // contender must not wipe the holder's recorded pid, and a pre-planted
        // symlink at the lock path must not redirect the truncate/pid write onto
        // another operator-writable file (bead oraclemcp-qa100 .15). The holder
        // truncates via `set_len(0)` only AFTER it owns the lock (below).
        let mut file = open_private_lock_file(&lock_path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(AuditError::Locked {
                    path: audit_path.display().to_string(),
                    holder_pid: read_holder_pid(&lock_path),
                });
            }
            Err(TryLockError::Error(e)) => {
                return Err(AuditError::Io(format!(
                    "cannot lock audit log {}: {e}",
                    audit_path.display()
                )));
            }
        }
        // We hold the lock. Record our pid so the NEXT contender can name us in
        // its fail-closed message. Best-effort: a failure here does not
        // surrender the lock (the lock is the fd's, not the file content's).
        let _ = file.set_len(0);
        let _ = file.seek(SeekFrom::Start(0));
        let _ = writeln!(file, "{}", std::process::id());
        Ok(AuditLogLock { file })
    }
}

impl Drop for AuditLogLock {
    fn drop(&mut self) {
        // The OS releases the advisory lock when this fd closes (and on process
        // exit), so this explicit unlock is belt-and-braces for a prompt,
        // well-documented release on clean shutdown.
        let _ = self.file.unlock();
    }
}

/// Read a pid previously written to the lock sidecar. Best-effort: any I/O or
/// parse failure yields `None` (the contention message just omits the pid).
fn read_holder_pid(lock_path: &Path) -> Option<u32> {
    std::fs::read_to_string(lock_path)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()
}

// Test-only observability for the parent-directory fsync (bead
// oraclemcp-g4xi). Thread-local so it is immune to other tests opening sinks
// in parallel: `fsync_parent_dir` runs synchronously on the caller's thread,
// so a test reads the count it caused and nothing else.
#[cfg(test)]
thread_local! {
    pub(crate) static PARENT_DIR_FSYNCS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Reject a pre-planted symlink or non-regular filesystem object at `path`
/// *before* creating/opening it (bead oraclemcp-qa100 .15). In a shared or
/// attacker-writable audit directory a symlink at the log/lock/anchor path would
/// otherwise redirect or truncate an operator-writable target; a FIFO/device
/// would block or corrupt. Audit files must be private *regular* files, so
/// anything else fails closed. An absent path is fine — the open creates it.
fn reject_unsafe_existing(path: &Path) -> Result<(), AuditError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() || !file_type.is_file() {
                Err(AuditError::Io(format!(
                    "refusing to open audit path {} — it is a symlink, directory, FIFO, device, or \
                     other non-regular object; audit files must be private regular files (inspect \
                     the path and its parent directory ownership/mode, then retry)",
                    path.display()
                )))
            } else {
                Ok(())
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(AuditError::Io(format!(
            "cannot inspect audit path {} before opening it: {e}",
            path.display()
        ))),
    }
}

/// After opening, confirm the OPEN handle is a regular file — catching a TOCTOU
/// swap between [`reject_unsafe_existing`] and the open — and, on Unix, harden
/// its mode to owner-only `0600` (bead oraclemcp-qa100 .15). `File::set_permissions`
/// acts on the descriptor (`fchmod`), so it hardens the exact opened inode with
/// no path race. This both tightens a create made under a permissive umask and
/// hardens an existing overly-broad audit/lock file down to `0600`.
fn harden_open_regular_file(file: &File, path: &Path) -> Result<(), AuditError> {
    let metadata = file.metadata().map_err(|e| {
        AuditError::Io(format!(
            "cannot stat opened audit file {} to confirm it is a private regular file: {e}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(AuditError::Io(format!(
            "audit path {} is not a regular file after opening (the path may have been swapped); \
             refusing to write audit records to it",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            file.set_permissions(permissions).map_err(|e| {
                AuditError::Io(format!(
                    "cannot set private 0600 mode on audit file {}: {e}",
                    path.display()
                ))
            })?;
        }
    }
    Ok(())
}

/// Open (creating when absent) a private, symlink-safe append handle for the
/// audit log at `path`: reject a pre-planted non-regular target, create with
/// mode `0600` on Unix, then confirm/harden the opened inode.
fn open_private_append_file(path: &Path) -> Result<File, AuditError> {
    reject_unsafe_existing(path)?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options
        .open(path)
        .map_err(|e| AuditError::Io(format!("failed to open audit log {}: {e}", path.display())))?;
    harden_open_regular_file(&file, path)?;
    Ok(file)
}

/// Open (creating when absent) a private, symlink-safe read/write handle for the
/// audit `<log>.lock` sidecar. Never truncates on open (a contender must not
/// wipe the holder's recorded pid); creates `0600` on Unix and confirms/hardens
/// the opened inode.
fn open_private_lock_file(path: &Path) -> Result<File, AuditError> {
    reject_unsafe_existing(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path).map_err(|e| {
        AuditError::Io(format!(
            "cannot open audit lock sidecar {}: {e}",
            path.display()
        ))
    })?;
    harden_open_regular_file(&file, path)?;
    Ok(file)
}

/// Create a brand-new private file at `path`, failing closed if it already
/// exists (`O_CREAT|O_EXCL`, which also refuses a pre-planted symlink). Used for
/// the anchor's unpredictable same-directory temporary (bead oraclemcp-qa100 .15).
pub(crate) fn create_new_private_file(path: &Path) -> Result<File, AuditError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path).map_err(|e| {
        AuditError::Io(format!(
            "cannot create private audit temporary {}: {e}",
            path.display()
        ))
    })?;
    harden_open_regular_file(&file, path)?;
    Ok(file)
}

/// fsync the parent directory of `path` so a *newly created* file's directory
/// entry is itself durable (bead oraclemcp-g4xi). Creating and even fsyncing a
/// file only guarantees its contents are on disk once the directory entry that
/// names it is also fsynced; without this a crash immediately after creating the
/// audit log (or its lock sidecar) could lose the file entirely, taking with it
/// the tamper-evidence for everything logged in that window. Fails closed: audit
/// durability is not best-effort.
#[cfg(unix)]
fn fsync_parent_dir(path: &Path) -> Result<(), AuditError> {
    #[cfg(test)]
    PARENT_DIR_FSYNCS.with(|c| c.set(c.get() + 1));
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let handle = File::open(dir).map_err(|e| {
        AuditError::Io(format!(
            "cannot open audit directory {} to fsync it: {e}",
            dir.display()
        ))
    })?;
    handle.sync_all().map_err(|e| {
        AuditError::Io(format!(
            "cannot fsync audit directory {}: {e}",
            dir.display()
        ))
    })
}

/// Non-Unix fallback: `fsync` of a directory handle is a POSIX primitive and
/// `File::open` on a directory is unsupported on Windows, whose create/rename
/// durability story differs. The append-fd fsync in [`FileAuditSink::flush`]
/// remains the durability guarantee there.
#[cfg(not(unix))]
fn fsync_parent_dir(_path: &Path) -> Result<(), AuditError> {
    #[cfg(test)]
    PARENT_DIR_FSYNCS.with(|c| c.set(c.get() + 1));
    Ok(())
}

/// A durable append-only file sink. Each record is one JSON line; `flush`
/// performs an `fsync` (`File::sync_all`).
///
/// Opening a writable sink takes an exclusive advisory OS lock on the log's
/// `<path>.lock` sidecar (bead oraclemcp-mbu1). A second oraclemcp instance
/// pointed at the same log fails closed at open time with
/// [`AuditError::Locked`] rather than both instances resuming from the same
/// tail and forking the tamper-evident hash chain. The lock is held for the
/// sink's lifetime and released on drop / process exit.
pub struct FileAuditSink {
    file: Mutex<File>,
    /// The advisory lock guarding this log against a concurrent writer. Held
    /// for the sink's lifetime; released when the sink drops. Never read after
    /// construction — its lifetime IS its purpose.
    _lock: AuditLogLock,
}

impl FileAuditSink {
    /// Open (creating + appending) the audit file at `path`, taking the
    /// exclusive advisory writer lock first so a concurrent oraclemcp instance
    /// on the same log fails closed instead of forking the hash chain.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let path = path.as_ref();
        // Whether the durable entries already exist decides whether opening will
        // *create* anything — and thus whether the parent directory entry needs
        // an fsync to be crash-durable (bead oraclemcp-g4xi).
        let audit_pre_existing = path.exists();
        let lock_pre_existing = lock_path_for(path).exists();
        // Lock BEFORE opening the append fd: fail fast on contention, and never
        // leave a half-armed writer if the lock is already held.
        let lock = AuditLogLock::acquire(path)?;
        // Symlink-safe, private (0600) append handle: reject a pre-planted
        // symlink/non-regular target and harden the opened inode to owner-only
        // (bead oraclemcp-qa100 .15).
        let file = open_private_append_file(path)?;
        // Directory durability: if we just created the audit log or its lock
        // sidecar, fsync the parent directory so the new file survives a crash
        // instead of vanishing with the tamper-evidence it was about to hold.
        if !audit_pre_existing || !lock_pre_existing {
            fsync_parent_dir(path)?;
        }
        Ok(FileAuditSink {
            file: Mutex::new(file),
            _lock: lock,
        })
    }

    /// Identity of the exact open primary-log handle. Used by the WORM
    /// forwarder constructor to prove the two destinations are independent.
    pub(crate) fn open_identity(&self) -> Result<OpenFileIdentity, AuditError> {
        open_file_identity(&self.file.lock()).map_err(|error| {
            AuditError::Io(format!(
                "cannot establish primary audit file identity: {error}"
            ))
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

/// Keyless structural walk of a persisted chain prefix: each record's own
/// `entry_hash` must recompute from its content, `prev_hash` must link to the
/// previous record's `entry_hash` (genesis for the first), and `seq` must
/// increase by exactly one. Returns a human description of the first break, or
/// `None` for a structurally intact prefix.
///
/// This is the subset of [`crate::verify_records`] that needs no signing key.
/// The production resume path now folds this walk into the single streaming
/// [`ChainVerifier`] pass (bead oraclemcp-qa100 .29); this standalone helper is
/// retained only so a test can assert a forgery is *structurally* intact.
#[cfg(test)]
fn structural_break(records: &[AuditRecord]) -> Option<String> {
    let mut prev_hash: &str = GENESIS_HASH;
    let mut prev_seq: Option<u64> = None;
    for (index, record) in records.iter().enumerate() {
        let pos = index + 1;
        if !record.hash_is_valid() {
            return Some(format!(
                "record #{pos} (seq {}) entry_hash does not recompute from its content \
                 (in-place edit)",
                record.seq
            ));
        }
        if record.prev_hash.as_str() != prev_hash {
            return Some(format!(
                "record #{pos} (seq {}) prev_hash does not link to the previous record's \
                 entry_hash (reordered, inserted, or deleted record)",
                record.seq
            ));
        }
        let expected = prev_seq.map_or(1, |s| s + 1);
        if record.seq != expected {
            return Some(format!(
                "record #{pos} has a non-monotonic seq (expected {expected}, found {})",
                record.seq
            ));
        }
        prev_hash = &record.entry_hash;
        prev_seq = Some(record.seq);
    }
    None
}

/// The resume seed captured from the last durable record of an existing audit
/// log: enough to continue the ONE hash chain without retaining every record.
struct ResumeTail {
    seq: u64,
    entry_hash: String,
    key_id: Option<String>,
}

/// Stream an existing audit log line by line with **bounded memory**, running the
/// same structural (keyless) + keyed verification the previous whole-file resume
/// path ran, and return the last record as the resume seed (bead
/// oraclemcp-qa100 .29). Absent or empty log → `Ok(None)` (fresh genesis).
fn analyze_resume_log(
    audit_path: &Path,
    keys: &[SigningKey],
) -> Result<Option<ResumeTail>, AuditError> {
    let disp = audit_path.display();
    let file = match File::open(audit_path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(AuditError::ResumeRefused(format!(
                "cannot read audit log {disp} to resume the hash chain: {e}; inspect the file and \
                 its permissions, then restart"
            )));
        }
    };
    let mut reader = JsonlReader::new(BufReader::new(file));
    let mut verifier = ChainVerifier::new(keys);
    let mut index = 0usize;
    let mut tail: Option<ResumeTail> = None;
    loop {
        let record = match reader.next_record() {
            Ok(Some(record)) => record,
            Ok(None) => break,
            Err(JsonlError::Io(e)) => {
                return Err(AuditError::ResumeRefused(format!(
                    "cannot read audit log {disp} to resume the hash chain: {e}; inspect the file \
                     and its permissions, then restart"
                )));
            }
            Err(JsonlError::Malformed(e)) => {
                return Err(AuditError::ResumeRefused(format!(
                    "audit log {disp} has a malformed record ({e}); a torn or tampered tail cannot \
                     seed a continuing chain — run `oraclemcp audit verify {disp}`, then repair or \
                     roll the file back to its last well-formed line before restarting"
                )));
            }
        };
        if let Some(VerifyOutcome::Broken { seq, reason, .. }) = verifier.observe(index, &record) {
            return Err(map_resume_break(audit_path, seq, &reason));
        }
        tail = Some(ResumeTail {
            seq: record.seq,
            entry_hash: record.entry_hash.clone(),
            key_id: record.key_id.clone(),
        });
        index += 1;
    }
    Ok(tail)
}

/// Render the whole-file resume refusal messages from a streamed
/// [`VerifyOutcome::Broken`], preserving the structural-vs-keyed wording the old
/// two-phase (`structural_break` then `verify_records`) path produced.
fn map_resume_break(audit_path: &Path, seq: u64, reason: &BrokenReason) -> AuditError {
    let disp = audit_path.display();
    match reason {
        BrokenReason::HashMismatch
        | BrokenReason::PrevHashMismatch
        | BrokenReason::SeqNotMonotonic { .. } => AuditError::ResumeRefused(format!(
            "audit log {disp} has a broken chain interior ({reason}); a tampered or torn interior \
             cannot seed a continuing chain — run `oraclemcp audit verify {disp}`, then repair \
             before restarting"
        )),
        BrokenReason::UnknownKeyId(key_id) => AuditError::ResumeRefused(format!(
            "audit log {disp} record at seq {seq} names audit key_id {key_id:?}, which is absent \
             from the configured active+historical keyring; run `oraclemcp audit verify {disp}` \
             with the complete keyring and restore the authentic records before restarting"
        )),
        BrokenReason::SignatureMismatch => AuditError::ResumeRefused(format!(
            "audit log {disp} record at seq {seq} has a keyed MAC that does not verify under its \
             configured audit key; run `oraclemcp audit verify {disp}` with the complete keyring \
             and restore the authentic records before restarting"
        )),
        BrokenReason::Unsigned => AuditError::ResumeRefused(format!(
            "audit log {disp} record at seq {seq} is unsigned and cannot seed a signed chain; run \
             `oraclemcp audit verify {disp}` with the complete keyring and restore the authentic \
             records before restarting"
        )),
        other => AuditError::ResumeRefused(format!(
            "audit log {disp} record at seq {seq} failed verification: {other}; run `oraclemcp \
             audit verify {disp}` with the complete keyring and restore the authentic records \
             before restarting"
        )),
    }
}

/// Second bounded streaming pass used only by the anchor divergence check:
/// return the `entry_hash` of the record at `target_seq`, or `None` if the log
/// is shorter (already handled as truncation by the caller). Never materializes
/// the whole chain.
fn find_entry_hash_at_seq(
    audit_path: &Path,
    target_seq: u64,
) -> Result<Option<String>, AuditError> {
    let disp = audit_path.display();
    let file = match File::open(audit_path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(AuditError::ResumeRefused(format!(
                "cannot re-read audit log {disp} to confirm the anchored record: {e}"
            )));
        }
    };
    let mut reader = JsonlReader::new(BufReader::new(file));
    loop {
        match reader.next_record() {
            Ok(Some(record)) => {
                if record.seq == target_seq {
                    return Ok(Some(record.entry_hash));
                }
            }
            Ok(None) => return Ok(None),
            Err(e) => {
                return Err(AuditError::ResumeRefused(format!(
                    "cannot re-read audit log {disp} to confirm the anchored record: {e}"
                )));
            }
        }
    }
}

struct ChainState {
    seq: u64,
    last_hash: String,
    /// An authenticated historical head was resumed, but no record under the
    /// active key exists yet. A plain flush must preserve the old anchor; only
    /// fsyncing the first active-key record authorizes the anchor transition.
    anchor_transition_pending: bool,
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
    keyring: AuditKeyring,
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
        Self::new_with_keyring(sink, AuditKeyring::single(key))
    }

    /// A new signing auditor with one active signer plus historical
    /// verification keys for authenticated rotation and mixed-key resume.
    #[must_use]
    pub fn new_with_keyring(sink: Box<dyn AuditSink>, keyring: AuditKeyring) -> Self {
        Auditor {
            sink,
            keyring,
            anchor: None,
            state: Mutex::new(ChainState {
                seq: 0,
                last_hash: GENESIS_HASH.to_owned(),
                anchor_transition_pending: false,
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
        self.anchor = Some(AnchorFile::new(path.into(), self.keyring.active().clone()));
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

        // Stream the whole on-disk prefix with BOUNDED MEMORY (bead
        // oraclemcp-qa100 .29): a permanent, never-pruned audit log can be
        // multi-gigabyte, so resume must NOT `read_to_string` + parse every
        // record into a `Vec`. `analyze_resume_log` walks the file line by line
        // through a capped buffer, keeping only O(1) chain state, and still runs
        // the identical checks the old whole-file path did:
        //  - each line must parse (a torn/tampered tail fails closed);
        //  - the keyless structural walk (hash link + monotonic seq) rejects a
        //    forked interior — a deleted/reordered middle record or an in-place
        //    edit — that a bare parse or the head-anchor check would miss (the
        //    anchor attests only the head seq/hash);
        //  - every record is authenticated under the configured active+historical
        //    keyring (an unknown key or bad MAC on any record fails closed;
        //    rotation is explicit only when the prior key is present).
        // It retains just the last record as the resume seed.
        let Some(tail) = analyze_resume_log(audit_path, self.keyring.verification_keys())? else {
            // Absent or empty log: nothing to resume; fresh genesis state is
            // correct.
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
            // The anchor's keyed MAC is what binds its plaintext seq/entry_hash
            // to the real durable head — verify it BEFORE trusting either, or a
            // forged/rewritten sidecar defeats the truncation/divergence checks
            // below (multi-pass 2026-07).
            self.verify_anchor_authenticity(&anchor)?;
            if anchor.seq > tail.seq {
                return Err(AuditError::ResumeRefused(format!(
                    "head anchor attests durable seq {} but the audit log {disp} ends at seq {} — \
                     trailing records were removed (tail truncation); restore the missing tail, or \
                     only if the loss is understood reset the anchor, before restarting",
                    anchor.seq, tail.seq
                )));
            }
            // Divergence at the anchored seq: a second bounded streaming pass
            // fetches only that one record's entry_hash (the verified chain is
            // contiguous, so it exists at or before the tail) — never the whole
            // Vec.
            if let Some(anchored_hash) = find_entry_hash_at_seq(audit_path, anchor.seq)?
                && anchored_hash != anchor.entry_hash
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
            state.anchor_transition_pending =
                tail.key_id.as_deref() != Some(self.keyring.active().key_id());
        }
        Ok(self)
    }

    /// Fail-closed MAC/keyring cross-check of a loaded head anchor at resume time,
    /// mirroring [`crate::anchor::check_anchor`]'s posture (the `oraclemcp audit
    /// verify` reference): an anchor under an unknown `key_id`, or whose keyed
    /// MAC does not verify under the active key, is refused BEFORE its plaintext
    /// `seq`/`entry_hash` are trusted.
    ///
    /// This closes the tail-truncation bypass (multi-pass 2026-07): the anchor's
    /// keyed MAC is the *only* thing binding its `seq`/`entry_hash` to the real
    /// durable head. Trusting the anchor's plaintext without verifying its MAC let
    /// a tamperer with file-write access (but no signing key) delete durable
    /// records, truncate the log, and rewrite the sidecar plaintext down to the
    /// truncated tail — the old cross-check compared only plaintext and passed. An
    /// unknown `key_id` (e.g. an attacker swapping it to dodge verification) is
    /// itself a refusal, exactly as `check_anchor` treats `UnknownKeyId`; a
    /// genuine cross-run key rotation is reconciled by an operator via `audit
    /// verify`, never by silently resuming past an unverifiable anchor.
    fn verify_anchor_authenticity(&self, anchor: &ChainAnchor) -> Result<(), AuditError> {
        let Some(key) = self.keyring.key(&anchor.key_id) else {
            return Err(AuditError::ResumeRefused(format!(
                "head anchor names audit key_id {:?}, which is absent from the configured \
                 active+historical keyring; add the authentic historical verification key and \
                 run `oraclemcp audit verify` before restarting",
                anchor.key_id
            )));
        };
        if !anchor.mac_is_valid(key) {
            return Err(AuditError::ResumeRefused(
                "head anchor MAC does not verify under its configured audit key — the sidecar \
                 was rewritten, forged, or the key bytes changed behind an existing key_id; \
                 inspect with `oraclemcp audit verify` and restore the authentic key/tail before \
                 restarting"
                    .to_owned(),
            ));
        }
        Ok(())
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
        self.append_correlated_with_observed_scn(draft, timestamp, durable, None, None)
    }

    /// Append a chained record carrying optional attempt/terminal correlation.
    /// Durability and poisoning semantics are identical to [`Self::append`].
    pub fn append_correlated(
        &self,
        draft: &AuditEntryDraft,
        timestamp: String,
        durable: bool,
        correlation: Option<AuditCorrelation>,
    ) -> Result<AuditRecord, AuditError> {
        self.append_correlated_with_observed_scn(draft, timestamp, durable, correlation, None)
    }

    /// Append a chained record carrying an optional observed read snapshot SCN.
    /// The SCN is stored in the current hash-covered record schema, so a caller
    /// can use it as a tamper-evident flashback replay target. Durability and
    /// poisoning semantics are identical to [`Self::append`].
    pub fn append_correlated_with_observed_scn(
        &self,
        draft: &AuditEntryDraft,
        timestamp: String,
        durable: bool,
        correlation: Option<AuditCorrelation>,
        observed_scn: Option<u64>,
    ) -> Result<AuditRecord, AuditError> {
        self.append_correlated_with_observed_scn_and_certificate_core_hash(
            draft,
            timestamp,
            durable,
            correlation,
            observed_scn,
            None,
        )
    }

    /// Append a record carrying an optional observed SCN and a certificate-core
    /// hash. The hash must be canonical SHA-256 before it becomes signed audit
    /// evidence; a malformed certificate therefore fails closed before append
    /// or execution can proceed.
    pub fn append_correlated_with_observed_scn_and_certificate_core_hash(
        &self,
        draft: &AuditEntryDraft,
        timestamp: String,
        durable: bool,
        correlation: Option<AuditCorrelation>,
        observed_scn: Option<u64>,
        verdict_certificate_core_hash: Option<&str>,
    ) -> Result<AuditRecord, AuditError> {
        if verdict_certificate_core_hash.is_some_and(|hash| !is_canonical_sha256(hash)) {
            return Err(AuditError::InvalidVerdictCertificateCoreHash);
        }
        let mut state = self.state.lock();
        // Fail closed: once an append/flush failure or panic may have left a
        // record in the byte stream without advancing state, issuing any further
        // record would either reuse that seq or chain past an uncertain record.
        if state.poisoned {
            return Err(AuditError::Poisoned);
        }
        let seq = state.seq + 1;
        let record =
            AuditRecord::chained_signed_correlated_with_observed_scn_and_certificate_core_hash(
                draft,
                seq,
                &state.last_hash,
                timestamp,
                self.keyring.active(),
                correlation,
                observed_scn,
                verdict_certificate_core_hash.map(str::to_owned),
            );
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
        // Every new record is signed under the active key. For a non-durable
        // append, a later flush fsyncs it before writing the active anchor; for
        // a durable append, fsync already preceded the anchor attempt above.
        state.anchor_transition_pending = false;
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
            && !state.anchor_transition_pending
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
    use crate::verify::{parse_jsonl, verify_records};
    use std::sync::Arc;
    use std::thread;

    fn test_key() -> SigningKey {
        SigningKey::new("test", b"0123456789abcdef0123456789abcdef".to_vec())
            .expect("valid test key")
    }

    fn draft(sql: &str, danger: &str) -> AuditEntryDraft {
        AuditEntryDraft {
            subject: AuditSubject::new("agent", "agent"),
            db_evidence: None,
            cancel: None,
            result_masking: None,
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
    fn certificate_core_hash_is_durable_and_malformed_evidence_refuses_before_append() {
        let sink = Arc::new(MemoryAuditSink::new());
        let auditor = Auditor::new(Box::new(SharedSink(sink.clone())), test_key());
        let certificate_core_hash = crate::sha256_hex(b"verdict certificate core");
        let record = auditor
            .append_correlated_with_observed_scn_and_certificate_core_hash(
                &draft("SELECT 1 FROM dual", "SAFE"),
                "t0".to_owned(),
                true,
                None,
                Some(42_000_001),
                Some(&certificate_core_hash),
            )
            .expect("canonical certificate evidence must append");
        assert_eq!(
            record.verdict_certificate_core_hash.as_deref(),
            Some(certificate_core_hash.as_str())
        );
        assert!(record.hash_is_valid());
        assert_eq!(sink.flush_count(), 1, "certificate evidence is fsynced");

        assert!(matches!(
            auditor.append_correlated_with_observed_scn_and_certificate_core_hash(
                &draft("SELECT 2 FROM dual", "SAFE"),
                "t1".to_owned(),
                true,
                None,
                None,
                Some("not-a-canonical-sha256"),
            ),
            Err(AuditError::InvalidVerdictCertificateCoreHash)
        ));
        assert_eq!(
            sink.records().len(),
            1,
            "invalid certificate evidence must not append an unauditable read"
        );
    }

    #[test]
    fn certificate_audit_write_failure_refuses_and_poisoned_auditor_stays_closed() {
        let sink = Arc::new(FlushFailsOnceSink::default());
        let auditor = Auditor::new(Box::new(SharedFlakySink(sink.clone())), test_key());
        let certificate_core_hash = crate::sha256_hex(b"verdict certificate core");

        let first = auditor.append_correlated_with_observed_scn_and_certificate_core_hash(
            &draft("SELECT 1 FROM dual", "SAFE"),
            "t0".to_owned(),
            true,
            None,
            Some(42_000_001),
            Some(&certificate_core_hash),
        );
        assert!(
            matches!(first, Err(AuditError::Io(_))),
            "certificate-bearing audit write failure must refuse before a read can proceed: {first:?}"
        );
        assert_eq!(
            sink.records().len(),
            1,
            "the uncertain record is never retried"
        );

        let retry = auditor.append_correlated_with_observed_scn_and_certificate_core_hash(
            &draft("SELECT 2 FROM dual", "SAFE"),
            "t1".to_owned(),
            true,
            None,
            Some(42_000_002),
            Some(&certificate_core_hash),
        );
        assert!(
            matches!(retry, Err(AuditError::Poisoned)),
            "a certificate write failure must leave the auditor fail-closed: {retry:?}"
        );
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
    fn second_writer_on_the_same_log_fails_closed_then_recovers_on_release() {
        // Bead oraclemcp-mbu1: two oraclemcp instances pointed at one audit log
        // must NOT both open a writable sink — each would resume from the same
        // tail and issue seq=N+1, forking the tamper-evident hash chain. The
        // exclusive advisory OS lock makes the SECOND open fail closed. Two
        // separate `File::open`s hold two distinct open file descriptions, so
        // `flock(LOCK_EX)` contends between them exactly as it does across two
        // processes — this in-process test drives the same OS primitive.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");

        // First writer holds the log.
        let first = FileAuditSink::open(&path).expect("first writer opens");

        // Second writer on the SAME path fails closed with the typed error,
        // naming the path and (best-effort) the holding pid.
        match FileAuditSink::open(&path) {
            Err(AuditError::Locked {
                path: p,
                holder_pid,
            }) => {
                assert!(
                    p.contains("audit.jsonl"),
                    "the fail-closed message names the log path, got {p}"
                );
                assert_eq!(
                    holder_pid,
                    Some(std::process::id()),
                    "the lock sidecar records the holder pid for the operator hint"
                );
            }
            Err(other) => panic!("expected AuditError::Locked, got {other:?}"),
            Ok(_) => panic!("a second writer on the same audit log must fail closed"),
        }

        // The sidecar lock file exists alongside the log.
        assert!(
            lock_path_for(&path).exists(),
            "the .lock sidecar guards the log"
        );

        // Release the first holder (server exits / clean shutdown → Drop).
        drop(first);

        // A THIRD open now succeeds — a clean restart after the holder is gone
        // re-acquires the lock. (Advisory flock also releases on process exit,
        // so a crashed holder does not permanently wedge a restart.)
        let third = FileAuditSink::open(&path).expect("open succeeds after the holder releases");
        // And it is a working writer: an appended record lands in the log.
        let auditor = Auditor::new(Box::new(third), test_key());
        auditor
            .append(&draft("SELECT 1 FROM dual", "SAFE"), "t0".to_owned(), true)
            .expect("append after re-acquire");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().lines().count(),
            1,
            "the re-acquired writer appends normally"
        );
    }

    #[test]
    fn writer_lock_message_is_actionable() {
        // The Display of the fail-closed error is the operator-facing message:
        // it must name the log and refuse-to-fork intent.
        let err = AuditError::Locked {
            path: "/var/lib/oraclemcp/audit.jsonl".to_owned(),
            holder_pid: Some(4242),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("/var/lib/oraclemcp/audit.jsonl"),
            "names path: {msg}"
        );
        assert!(
            msg.contains("locked by another oraclemcp instance"),
            "{msg}"
        );
        assert!(msg.contains("(pid 4242)"), "names holder pid: {msg}");
        assert!(msg.contains("refusing to fork the hash-chain"), "{msg}");

        // With no discoverable pid the message stays clean (no dangling "pid").
        let err = AuditError::Locked {
            path: "/tmp/a.jsonl".to_owned(),
            holder_pid: None,
        };
        let msg = err.to_string();
        assert!(!msg.contains("pid"), "no pid clause when unknown: {msg}");
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
    fn resume_refuses_a_forged_anchor_masking_a_tail_truncation() {
        // The tail-truncation bypass (multi-pass 2026-07): a tamperer with file
        // write access but NO signing key deletes durable records, truncates the
        // log, and rewrites the anchor sidecar's *plaintext* (seq + entry_hash)
        // down to the truncated tail so the plaintext cross-check passes. Only the
        // keyed MAC binds the anchor to the real head — resume MUST verify it.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let anchor_path = crate::anchor_path_for(&path);
        {
            let auditor = Auditor::new(
                Box::new(FileAuditSink::open(&path).expect("open")),
                test_key(),
            )
            .with_head_anchor(&anchor_path);
            for i in 1..=5 {
                auditor
                    .append(
                        &draft(&format!("DELETE FROM t WHERE id={i}"), "GUARDED"),
                        format!("t{i}"),
                        true,
                    )
                    .expect("append");
            }
        }
        // Truncate the log to its first 3 records; capture record 3's entry_hash.
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        let three: String = lines.iter().take(3).map(|l| format!("{l}\n")).collect();
        std::fs::write(&path, &three).unwrap();
        let rec3: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
        let entry_hash3 = rec3["entry_hash"].as_str().unwrap().to_owned();

        // Forge the sidecar: correct plaintext for the truncated head (seq 3),
        // correct active key_id, but a MAC the attacker could not compute.
        let forged = ChainAnchor {
            anchor_version: 1,
            seq: 3,
            entry_hash: entry_hash3,
            key_id: test_key().key_id().to_owned(),
            mac: "hmac-sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_owned(),
        };
        let mut buf = serde_json::to_vec(&forged).unwrap();
        buf.push(b'\n');
        std::fs::write(&anchor_path, buf).unwrap();

        let refused = Auditor::new(
            Box::new(FileAuditSink::open(&path).expect("open")),
            test_key(),
        )
        .with_head_anchor(&anchor_path)
        .resume_from(&path);
        match refused {
            Err(AuditError::ResumeRefused(msg)) => assert!(
                msg.contains("MAC does not verify"),
                "expected anchor-MAC refusal, got: {msg}"
            ),
            Err(other) => panic!("expected ResumeRefused, got {other:?}"),
            Ok(_) => panic!("forged anchor masking truncation must refuse startup"),
        }
    }

    #[test]
    fn resume_refuses_an_anchor_under_an_unknown_key_id() {
        // A tamperer cannot dodge the MAC check by swapping the anchor's key_id to
        // an unknown value: an anchor the active key cannot authenticate is itself
        // a refusal (mirrors check_anchor's UnknownKeyId), never a silent resume.
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
        // Rewrite the anchor's key_id to a value the active key does not match.
        let mut anchor = crate::load_anchor(&anchor_path).unwrap().unwrap();
        anchor.key_id = "attacker-swapped-key".to_owned();
        let mut buf = serde_json::to_vec(&anchor).unwrap();
        buf.push(b'\n');
        std::fs::write(&anchor_path, buf).unwrap();

        let refused = Auditor::new(
            Box::new(FileAuditSink::open(&path).expect("open")),
            test_key(),
        )
        .with_head_anchor(&anchor_path)
        .resume_from(&path);
        match refused {
            Err(AuditError::ResumeRefused(msg)) => assert!(
                msg.contains("key_id") && msg.contains("audit verify"),
                "expected unknown-key_id refusal, got: {msg}"
            ),
            Err(other) => panic!("expected ResumeRefused, got {other:?}"),
            Ok(_) => panic!("anchor under an unknown key_id must refuse startup"),
        }
    }

    #[test]
    fn resume_refuses_a_deleted_interior_even_with_a_matching_anchor() {
        // The head anchor attests only the HEAD seq/hash. A tamperer who deletes
        // an *interior* record but leaves the surviving tail (which still matches
        // the anchored head) would slip the anchor cross-check entirely: the
        // chain still ends at the anchored seq with the anchored entry_hash. The
        // keyless structural pre-check catches the forked interior (the surviving
        // tail's prev_hash no longer links to its new predecessor) and refuses.
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
        // Anchor attests seq=3; drop the MIDDLE record but keep the head line.
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 3);
        let kept = format!("{}\n{}\n", lines[0], lines[2]); // seq 1 then seq 3
        std::fs::write(&path, kept).unwrap();
        let anchor = crate::load_anchor(&anchor_path)
            .expect("load")
            .expect("present");
        assert_eq!(
            anchor.seq, 3,
            "anchor still attests the (surviving) head seq"
        );

        let refused = Auditor::new(
            Box::new(FileAuditSink::open(&path).expect("open")),
            test_key(),
        )
        .with_head_anchor(&anchor_path)
        .resume_from(&path);
        match refused {
            Err(AuditError::ResumeRefused(msg)) => {
                assert!(
                    msg.contains("broken chain interior") && msg.contains("audit verify"),
                    "expected structural-break message, got: {msg}"
                );
            }
            Err(other) => panic!("expected ResumeRefused, got {other:?}"),
            Ok(_) => panic!("a deleted interior record must refuse startup even with an anchor"),
        }
    }

    #[test]
    fn resume_refuses_a_reordered_interior_without_an_anchor() {
        // No anchor at all (legacy log): a reordered interior — the pure-JSONL
        // parse still succeeds — must still fail closed at startup rather than
        // seed a continuing chain onto a forked prefix.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        {
            let auditor = Auditor::new(
                Box::new(FileAuditSink::open(&path).expect("open")),
                test_key(),
            );
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
        // Swap the last two records: every line is still valid JSON.
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        let reordered = format!("{}\n{}\n{}\n", lines[0], lines[2], lines[1]);
        std::fs::write(&path, reordered).unwrap();

        let refused = Auditor::new(
            Box::new(FileAuditSink::open(&path).expect("open")),
            test_key(),
        )
        .resume_from(&path);
        match refused {
            Err(AuditError::ResumeRefused(msg)) => {
                assert!(
                    msg.contains("broken chain interior"),
                    "expected structural-break message, got: {msg}"
                );
            }
            Err(other) => panic!("expected ResumeRefused, got {other:?}"),
            Ok(_) => panic!("a reordered interior must refuse startup"),
        }
    }

    #[test]
    fn resume_accepts_a_structurally_intact_multi_record_log() {
        // Guard against over-tightening: a clean, structurally intact chain must
        // still resume (the structural pre-check is a no-op on a good prefix).
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        {
            let auditor = Auditor::new(
                Box::new(FileAuditSink::open(&path).expect("open")),
                test_key(),
            );
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
        let auditor = Auditor::new(
            Box::new(FileAuditSink::open(&path).expect("open")),
            test_key(),
        )
        .resume_from(&path)
        .expect("intact log resumes");
        let next = auditor
            .append(
                &draft("DELETE FROM t WHERE id=4", "GUARDED"),
                "t4".to_owned(),
                true,
            )
            .expect("append after resume");
        assert_eq!(next.seq, 4, "resume continues the sequence");
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

    #[test]
    fn resume_refuses_a_forged_interior_with_valid_structure_but_bad_mac() {
        // Bead oraclemcp-g4xi: a tamperer who rewrites an INTERIOR record and
        // repairs the hash chain (recompute entry_hash, relink prev_hash) passes
        // the keyless structural walk — but cannot re-sign without the key. The
        // keyed body check must catch the bad MAC at resume when the key is
        // present, and name the offending seq. Modelled by signing records 2..3
        // under the ACTIVE key_id but the WRONG key bytes (a forger who knows the
        // key_id label but not the secret).
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let forger = SigningKey::new(
            test_key().key_id(),
            b"fedcba9876543210fedcba9876543210".to_vec(),
        )
        .expect("valid test key");
        let r1 = AuditRecord::chained_signed(
            &draft("DELETE FROM t WHERE id=1", "GUARDED"),
            1,
            GENESIS_HASH,
            "t1".to_owned(),
            &test_key(),
        );
        let r2 = AuditRecord::chained_signed(
            &draft("SELECT secret FROM dual", "GUARDED"),
            2,
            &r1.entry_hash,
            "t2".to_owned(),
            &forger,
        );
        let r3 = AuditRecord::chained_signed(
            &draft("DELETE FROM t WHERE id=3", "GUARDED"),
            3,
            &r2.entry_hash,
            "t3".to_owned(),
            &forger,
        );
        let body: String = [&r1, &r2, &r3]
            .iter()
            .map(|r| serde_json::to_string(r).expect("serialize") + "\n")
            .collect();
        std::fs::write(&path, body).unwrap();

        // Sanity: the forged chain is structurally intact (hashes recompute and
        // link), so ONLY the keyed body check can catch it.
        let records = crate::parse_jsonl(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(
            structural_break(&records).is_none(),
            "forgery is structurally intact"
        );

        let refused = Auditor::new(
            Box::new(FileAuditSink::open(&path).expect("open")),
            test_key(),
        )
        .resume_from(&path);
        match refused {
            Err(AuditError::ResumeRefused(msg)) => {
                assert!(
                    msg.contains("keyed MAC that does not verify")
                        && msg.contains("seq 2")
                        && msg.contains("audit verify"),
                    "expected keyed-MAC refusal naming seq 2, got: {msg}"
                );
            }
            Err(other) => panic!("expected ResumeRefused, got {other:?}"),
            Ok(_) => {
                panic!("a forged interior with a bad MAC must refuse startup when key present")
            }
        }
    }

    #[test]
    fn resume_requires_the_historical_key_for_a_rotated_interior() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let old_key = SigningKey::new("old-key", b"abcdef0123456789abcdef0123456789".to_vec())
            .expect("valid test key");
        let r1 = AuditRecord::chained_signed(
            &draft("DELETE FROM t WHERE id=1", "GUARDED"),
            1,
            GENESIS_HASH,
            "t1".to_owned(),
            &old_key,
        );
        let r2 = AuditRecord::chained_signed(
            &draft("DELETE FROM t WHERE id=2", "GUARDED"),
            2,
            &r1.entry_hash,
            "t2".to_owned(),
            &test_key(),
        );
        let body: String = [&r1, &r2]
            .iter()
            .map(|r| serde_json::to_string(r).expect("serialize") + "\n")
            .collect();
        std::fs::write(&path, body).unwrap();

        let refused = Auditor::new(
            Box::new(FileAuditSink::open(&path).expect("open")),
            test_key(),
        )
        .resume_from(&path);
        assert!(
            matches!(refused, Err(AuditError::ResumeRefused(ref message)) if message.contains("old-key") && message.contains("absent")),
            "missing historical key must fail closed"
        );

        let keyring = AuditKeyring::new(test_key(), [old_key]).expect("valid rotation keyring");
        let auditor = Auditor::new_with_keyring(
            Box::new(FileAuditSink::open(&path).expect("reopen")),
            keyring,
        )
        .resume_from(&path)
        .expect("authenticated historical key permits mixed-key resume");
        // The chain seeded from the tail (seq 2): the next append is seq 3.
        let r3 = auditor
            .append(
                &draft("DELETE FROM t WHERE id=3", "GUARDED"),
                "t3".to_owned(),
                true,
            )
            .expect("append after rotated-interior resume");
        assert_eq!(r3.seq, 3);
        assert_eq!(
            r3.prev_hash, r2.entry_hash,
            "resume chained onto the active-key tail"
        );
    }

    #[test]
    fn authenticated_rotation_advances_anchor_only_after_first_new_durable_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let anchor_path = crate::anchor_path_for(&path);
        let old_key = SigningKey::new("old", vec![0x11; 32]).expect("old key");
        let new_key = SigningKey::new("new", vec![0x22; 32]).expect("new key");

        {
            let auditor = Auditor::new(
                Box::new(FileAuditSink::open(&path).expect("open old log")),
                old_key.clone(),
            )
            .with_head_anchor(&anchor_path);
            auditor
                .append(
                    &draft("DELETE FROM t WHERE id=1", "GUARDED"),
                    "t1".into(),
                    true,
                )
                .expect("old append");
        }
        let old_anchor = load_anchor(&anchor_path)
            .expect("load old anchor")
            .expect("old anchor");
        assert_eq!(old_anchor.key_id, "old");

        let rotation = AuditKeyring::new(new_key.clone(), [old_key.clone()])
            .expect("authenticated rotation keyring");
        {
            // Crash/stop before the first new-key record: resume authenticates
            // the old anchor but does not rewrite it merely by opening.
            let auditor = Auditor::new_with_keyring(
                Box::new(FileAuditSink::open(&path).expect("open rotation")),
                rotation.clone(),
            )
            .with_head_anchor(&anchor_path)
            .resume_from(&path)
            .expect("old anchor authenticated by historical key");
            auditor.flush().expect("flush old durable head");
            assert_eq!(
                load_anchor(&anchor_path).unwrap().unwrap(),
                old_anchor,
                "a flush without a new-key record must preserve the old anchor"
            );
        }
        assert_eq!(
            load_anchor(&anchor_path).unwrap().unwrap(),
            old_anchor,
            "rotation startup alone must not advance/re-sign the anchor"
        );

        {
            let auditor = Auditor::new_with_keyring(
                Box::new(FileAuditSink::open(&path).expect("open new signer")),
                rotation.clone(),
            )
            .with_head_anchor(&anchor_path)
            .resume_from(&path)
            .expect("resume for first new record");
            let record = auditor
                .append(
                    &draft("DELETE FROM t WHERE id=2", "GUARDED"),
                    "t2".into(),
                    true,
                )
                .expect("new-key durable append");
            assert_eq!(record.key_id.as_deref(), Some("new"));
        }
        let new_anchor = load_anchor(&anchor_path).unwrap().unwrap();
        assert_eq!(new_anchor.key_id, "new");
        assert!(new_anchor.mac_is_valid(&new_key));

        let records = parse_jsonl(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            verify_records(&records, rotation.verification_keys()),
            VerifyOutcome::Ok { records: 2 }
        );
        assert_eq!(
            crate::check_anchor(&records, &new_anchor, rotation.verification_keys()),
            Ok(crate::AnchorStatus::Match)
        );
    }

    #[test]
    fn crash_after_new_record_before_anchor_update_accepts_old_anchor_behind() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let anchor_path = crate::anchor_path_for(&path);
        let old_key = SigningKey::new("old", vec![0x31; 32]).expect("old key");
        let new_key = SigningKey::new("new", vec![0x32; 32]).expect("new key");
        {
            let auditor = Auditor::new(
                Box::new(FileAuditSink::open(&path).expect("old sink")),
                old_key.clone(),
            )
            .with_head_anchor(&anchor_path);
            auditor
                .append(
                    &draft("DELETE FROM t WHERE id=1", "GUARDED"),
                    "t1".into(),
                    true,
                )
                .expect("old append");
        }
        // Model the precise crash window: the first new-key record reached the
        // durable log, but the process died before replacing the old anchor.
        let rotation = AuditKeyring::new(new_key.clone(), [old_key.clone()]).unwrap();
        {
            let auditor = Auditor::new_with_keyring(
                Box::new(FileAuditSink::open(&path).expect("rotation sink")),
                rotation.clone(),
            )
            .resume_from(&path)
            .expect("resume without anchor writer");
            auditor
                .append(
                    &draft("DELETE FROM t WHERE id=2", "GUARDED"),
                    "t2".into(),
                    true,
                )
                .expect("durable new record");
        }
        assert_eq!(load_anchor(&anchor_path).unwrap().unwrap().key_id, "old");
        let auditor = Auditor::new_with_keyring(
            Box::new(FileAuditSink::open(&path).expect("recovery sink")),
            rotation,
        )
        .with_head_anchor(&anchor_path)
        .resume_from(&path)
        .expect("old authenticated anchor behind new-key tail is recoverable");
        let next = auditor
            .append(
                &draft("DELETE FROM t WHERE id=3", "GUARDED"),
                "t3".into(),
                true,
            )
            .expect("recovery append");
        assert_eq!(next.seq, 3);
        assert_eq!(load_anchor(&anchor_path).unwrap().unwrap().key_id, "new");
    }

    #[test]
    fn open_fsyncs_parent_dir_on_create_only() {
        // Bead oraclemcp-g4xi (b): creating the audit log fsyncs its parent
        // directory so the new file survives a crash; reopening an already-present
        // log (and lock sidecar) creates nothing and needs no directory fsync. The
        // counter is thread-local, so a parallel test opening its own sink cannot
        // perturb this one.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let before = PARENT_DIR_FSYNCS.with(std::cell::Cell::get);
        let sink = FileAuditSink::open(&path).expect("open new");
        let after_create = PARENT_DIR_FSYNCS.with(std::cell::Cell::get);
        assert_eq!(
            after_create,
            before + 1,
            "creating a new audit log fsyncs its parent directory exactly once"
        );
        drop(sink); // release the advisory writer lock before reopening

        let sink2 = FileAuditSink::open(&path).expect("reopen existing");
        let after_reopen = PARENT_DIR_FSYNCS.with(std::cell::Cell::get);
        assert_eq!(
            after_reopen, after_create,
            "reopening an existing log + lock sidecar creates nothing, so no dir fsync"
        );
        drop(sink2);
    }

    #[cfg(unix)]
    #[test]
    fn fsync_parent_dir_fails_closed_when_parent_cannot_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing_parent = dir.path().join("missing").join("audit.jsonl");
        let err = fsync_parent_dir(&missing_parent).expect_err("missing parent must fail closed");
        let msg = err.to_string();
        assert!(msg.contains("cannot open audit directory"), "{msg}");
        assert!(msg.contains("missing"), "{msg}");
    }

    #[test]
    fn resume_from_missing_log_starts_at_genesis() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("audit.jsonl");
        let sink = Arc::new(MemoryAuditSink::new());
        let auditor = Auditor::new(Box::new(SharedSink(sink.clone())), test_key())
            .resume_from(&missing)
            .expect("missing log is first-run genesis state");
        let record = auditor
            .append(&draft("SELECT 1 FROM dual", "SAFE"), "t0".to_owned(), false)
            .expect("append after missing-log resume");
        assert_eq!(record.seq, 1);
        assert_eq!(record.prev_hash, GENESIS_HASH);
    }

    #[test]
    fn flush_before_any_record_does_not_write_head_anchor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let anchor_path = dir.path().join("audit.jsonl.anchor");
        let auditor = Auditor::new(Box::new(MemoryAuditSink::new()), test_key())
            .with_head_anchor(&anchor_path);
        auditor.flush().expect("empty flush succeeds");
        assert_eq!(
            crate::load_anchor(&anchor_path).expect("load"),
            None,
            "an empty chain must not create a seq=0 head anchor"
        );
    }

    // --- Symlink / mode hardening (bead oraclemcp-qa100 .15) ---

    #[cfg(unix)]
    #[test]
    fn open_fails_closed_on_a_symlinked_audit_log_and_leaves_the_target_intact() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tempdir");
        let victim = dir.path().join("operator-writable");
        std::fs::write(&victim, b"operator-secret\n").expect("seed victim");
        let audit = dir.path().join("audit.jsonl");
        symlink(&victim, &audit).expect("preplant audit symlink");

        let err = FileAuditSink::open(&audit)
            .err()
            .expect("a symlinked audit path must fail closed");
        assert!(matches!(err, AuditError::Io(_)), "got {err:?}");
        assert_eq!(
            std::fs::read(&victim).expect("victim readable"),
            b"operator-secret\n",
            "the redirected target must be byte-unchanged"
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_fails_closed_on_a_symlinked_lock_sidecar_and_leaves_the_target_intact() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().expect("tempdir");
        let victim = dir.path().join("operator-writable");
        std::fs::write(&victim, b"keepme\n").expect("seed victim");
        let audit = dir.path().join("audit.jsonl");
        symlink(&victim, lock_path_for(&audit)).expect("preplant lock symlink");

        let err = FileAuditSink::open(&audit)
            .err()
            .expect("a symlinked lock sidecar must fail closed");
        assert!(matches!(err, AuditError::Io(_)), "got {err:?}");
        assert_eq!(
            std::fs::read(&victim).expect("victim readable"),
            b"keepme\n",
            "the lock-redirected target must not be truncated/overwritten"
        );
    }

    #[cfg(unix)]
    #[test]
    fn open_rejects_directory_and_fifo_targets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let as_dir = dir.path().join("audit-as-dir.jsonl");
        std::fs::create_dir(&as_dir).expect("create dir target");
        assert!(
            matches!(FileAuditSink::open(&as_dir), Err(AuditError::Io(_))),
            "a directory at the audit path must be rejected"
        );

        // FIFO rejection is best-effort: skip cleanly where mkfifo is absent.
        let fifo = dir.path().join("audit-fifo.jsonl");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if made {
            assert!(
                matches!(FileAuditSink::open(&fifo), Err(AuditError::Io(_))),
                "a FIFO at the audit path must be rejected"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn new_audit_files_are_0600_and_existing_broad_modes_are_hardened() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| {
            std::fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        {
            let _sink = FileAuditSink::open(&path).expect("open new");
            assert_eq!(mode(&path), 0o600, "new audit log is owner-only");
            assert_eq!(
                mode(&lock_path_for(&path)),
                0o600,
                "new lock sidecar is owner-only"
            );
        }
        // Overly-broad pre-existing files are hardened down to 0600 on reopen.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))
            .expect("loosen log");
        std::fs::set_permissions(lock_path_for(&path), std::fs::Permissions::from_mode(0o644))
            .expect("loosen lock");
        {
            let _sink = FileAuditSink::open(&path).expect("reopen existing");
            assert_eq!(mode(&path), 0o600, "broad audit mode hardened to 0600");
            assert_eq!(
                mode(&lock_path_for(&path)),
                0o600,
                "broad lock mode hardened to 0600"
            );
        }
    }

    // --- Bounded streaming resume (bead oraclemcp-qa100 .29) ---

    #[test]
    fn resume_streams_a_large_log_and_still_fails_closed_on_a_torn_tail() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        {
            let auditor = Auditor::new(
                Box::new(FileAuditSink::open(&path).expect("open")),
                test_key(),
            );
            for i in 0..6_000 {
                auditor
                    .append(
                        &draft(&format!("DELETE FROM t WHERE id={i}"), "GUARDED"),
                        format!("t{i}"),
                        false,
                    )
                    .expect("append");
            }
            auditor.flush().expect("group-commit flush");
        }
        assert!(
            std::fs::metadata(&path).expect("stat").len() > 1_000_000,
            "fixture must be a multi-block file so streaming actually matters"
        );

        // Bounded resume continues the ONE chain rather than loading every record.
        let auditor = Auditor::new(
            Box::new(FileAuditSink::open(&path).expect("open")),
            test_key(),
        )
        .resume_from(&path)
        .expect("resume large log with bounded memory");
        let next = auditor
            .append(
                &draft("DELETE FROM t WHERE id=next", "GUARDED"),
                "tn".to_owned(),
                true,
            )
            .expect("append after large resume");
        assert_eq!(next.seq, 6_001, "resume seeded from the streamed tail");
        drop(auditor);

        // A torn final line in the large log is still detected at resume.
        {
            let mut file = OpenOptions::new().append(true).open(&path).expect("reopen");
            file.write_all(b"{\"seq\":6002,\"partial\":")
                .expect("write torn tail");
        }
        let refused = Auditor::new(
            Box::new(FileAuditSink::open(&path).expect("open")),
            test_key(),
        )
        .resume_from(&path);
        match refused {
            Err(AuditError::ResumeRefused(message)) => assert!(
                message.contains("malformed"),
                "a torn tail in a large log must refuse with a repair message, got: {message}"
            ),
            Err(other) => panic!("expected ResumeRefused, got {other:?}"),
            Ok(_) => panic!("a torn tail in a large log must still refuse startup"),
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
