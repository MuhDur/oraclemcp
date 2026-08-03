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

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

use crate::anchor::{AnchorFile, ChainAnchor, load_anchor};
use crate::keyring::AuditKeyring;
use crate::record::{
    AuditCorrelation, AuditEntryDraft, AuditRecord, AuditVerdictCertificate,
    BoundAuditVerdictCertificate, GENESIS_HASH, SigningKey,
};
use crate::rekor::{AsyncRekorAnchor, AuditChainHead};
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

#[cfg(unix)]
fn metadata_identity(metadata: &std::fs::Metadata) -> std::io::Result<OpenFileIdentity> {
    use std::os::unix::fs::MetadataExt as _;

    Ok(OpenFileIdentity {
        volume: metadata.dev(),
        file: metadata.ino(),
    })
}

#[cfg(windows)]
fn metadata_identity(metadata: &std::fs::Metadata) -> std::io::Result<OpenFileIdentity> {
    use std::os::windows::fs::MetadataExt as _;

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
fn metadata_identity(_metadata: &std::fs::Metadata) -> std::io::Result<OpenFileIdentity> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "filesystem identity is unavailable on this platform",
    ))
}

/// Identity reached by a path lookup. This is used only for early alias
/// classification; callers must still perform a no-follow descriptor open
/// before any read or write.
pub(crate) fn path_identity(path: &Path) -> std::io::Result<OpenFileIdentity> {
    metadata_identity(&std::fs::metadata(path)?)
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
    /// The configured sink cannot durably persist a certificate beside its
    /// signed record. Refuse rather than emit an uninspectable proof.
    #[error("audit sink cannot persist verdict certificates")]
    VerdictCertificatePersistenceUnsupported,
    /// The supplied certificate does not match the signed record the auditor
    /// just constructed, so it cannot become audit evidence.
    #[error("invalid verdict certificate evidence: {0}")]
    InvalidVerdictCertificateEvidence(String),
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
    /// Append a record together with its already-bound, redacted verdict
    /// certificate. Implementations that cannot preserve the pair must refuse:
    /// silently dropping evidence would make the audit-tail proof dishonest.
    fn append_with_verdict_certificate(
        &self,
        _record: &AuditRecord,
        _certificate: &BoundAuditVerdictCertificate,
    ) -> Result<(), AuditError> {
        Err(AuditError::VerdictCertificatePersistenceUnsupported)
    }
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
/// parse failure yields `None` (the contention message just omits the pid). On
/// Windows the holder's exclusive `LockFileEx` lock is mandatory and blocks this
/// read, so a contender's pid hint is legitimately absent there; the fail-closed
/// refusal itself does not depend on it.
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

#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

#[cfg(windows)]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

#[cfg(windows)]
const FILE_SHARE_READ_WRITE_DELETE: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004;

#[cfg(windows)]
const FILE_SHARE_READ_WRITE: u32 = 0x0000_0001 | 0x0000_0002;

#[cfg(windows)]
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;

#[cfg(any(test, windows))]
fn windows_private_dacl_sddl(sid: &str, directory: bool) -> String {
    let inheritance = if directory { "OICI" } else { "" };
    format!("D:P(A;{inheritance};FA;;;{sid})")
}

fn configure_no_follow(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        let flags = i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits())
            .expect("O_NOFOLLOW fits OpenOptionsExt::custom_flags");
        options.custom_flags(flags);
    }
    #[cfg(windows)]
    {
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
}

#[cfg(windows)]
fn windows_security_handle(path: &Path, directory: bool) -> Result<File, AuditError> {
    use windows_permissions::constants::AccessRights;

    let access = (AccessRights::ReadControl | AccessRights::WriteDac | AccessRights::WriteOwner)
        .bits()
        | FILE_READ_ATTRIBUTES;
    let mut options = OpenOptions::new();
    options
        .access_mode(access)
        .share_mode(FILE_SHARE_READ_WRITE_DELETE)
        .custom_flags(
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
        );
    options.open(path).map_err(|error| {
        AuditError::Io(format!(
            "cannot open audit {} {} for Windows ACL validation: {error}",
            if directory { "directory" } else { "file" },
            path.display()
        ))
    })
}

/// Hold an authenticated, non-replaceable private parent directory across a
/// Windows file creation. Rust's `OpenOptions` cannot pass a security
/// descriptor to `CreateFileW`; requiring this exact inheritable DACL makes a
/// newly created child owner-only from its first observable instant. Omitting
/// `FILE_SHARE_DELETE` prevents the verified parent from being renamed while
/// the caller creates and authenticates the child.
#[cfg(windows)]
fn windows_private_creation_parent(path: &Path) -> Result<File, AuditError> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_permissions::constants::AccessRights;

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let access = AccessRights::ReadControl.bits() | FILE_READ_ATTRIBUTES;
    let mut options = OpenOptions::new();
    options
        .access_mode(access)
        .share_mode(FILE_SHARE_READ_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
    let directory = options.open(parent).map_err(|error| {
        AuditError::Io(format!(
            "cannot lock audit creation parent {} for Windows DACL validation: {error}",
            parent.display()
        ))
    })?;
    let metadata = directory.metadata().map_err(|error| {
        AuditError::Io(format!(
            "cannot stat audit creation parent {}: {error}",
            parent.display()
        ))
    })?;
    if !metadata.file_type().is_dir()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(AuditError::Io(format!(
            "audit creation parent {} is not a non-reparse directory",
            parent.display()
        )));
    }
    let path_metadata = std::fs::symlink_metadata(parent).map_err(|error| {
        AuditError::Io(format!(
            "cannot authenticate audit creation parent {}: {error}",
            parent.display()
        ))
    })?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_dir()
        || open_file_identity(&directory).map_err(|error| {
            AuditError::Io(format!(
                "cannot identify audit creation parent {}: {error}",
                parent.display()
            ))
        })? != metadata_identity(&path_metadata).map_err(|error| {
            AuditError::Io(format!(
                "cannot identify audit creation parent path {}: {error}",
                parent.display()
            ))
        })?
    {
        return Err(AuditError::Io(format!(
            "audit creation parent {} changed identity during validation",
            parent.display()
        )));
    }
    let current_sid = windows_permissions::utilities::current_process_sid().map_err(|error| {
        AuditError::Io(format!(
            "cannot resolve the current Windows process SID for audit creation parent {}: {error}",
            parent.display()
        ))
    })?;
    verify_windows_private_acl(&directory, parent, true, &current_sid).map_err(|error| {
        AuditError::Io(format!(
            "audit file creation requires an exact protected owner-only parent DACL at {}: {error}",
            parent.display()
        ))
    })?;
    Ok(directory)
}

#[cfg(windows)]
#[derive(Clone, Copy)]
enum WindowsPrivateOpenMode {
    Append,
    Lock,
}

#[cfg(windows)]
fn windows_private_open_options(mode: WindowsPrivateOpenMode) -> OpenOptions {
    let mut options = OpenOptions::new();
    match mode {
        WindowsPrivateOpenMode::Append => {
            options.read(true).append(true);
        }
        WindowsPrivateOpenMode::Lock => {
            options.read(true).write(true).truncate(false);
        }
    }
    configure_no_follow(&mut options);
    options
}

#[cfg(windows)]
fn open_or_create_private_windows_file(
    path: &Path,
    mode: WindowsPrivateOpenMode,
    description: &str,
) -> Result<File, AuditError> {
    match windows_private_open_options(mode).open(path) {
        Ok(file) => {
            harden_open_regular_file(&file, path)?;
            return Ok(file);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(AuditError::Io(format!(
                "cannot open {description} {}: {error}",
                path.display()
            )));
        }
    }

    let _creation_parent = windows_private_creation_parent(path)?;
    let mut create = windows_private_open_options(mode);
    create.create_new(true);
    let file = match create.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            windows_private_open_options(mode)
                .open(path)
                .map_err(|error| {
                    AuditError::Io(format!(
                        "cannot authenticate concurrently created {description} {}: {error}",
                        path.display()
                    ))
                })?
        }
        Err(error) => {
            return Err(AuditError::Io(format!(
                "cannot create {description} {} beneath its private Windows parent: {error}",
                path.display()
            )));
        }
    };
    harden_open_regular_file(&file, path)?;
    Ok(file)
}

#[cfg(windows)]
fn verify_windows_private_acl(
    handle: &File,
    path: &Path,
    directory: bool,
    current_sid: &windows_permissions::Sid,
) -> Result<(), AuditError> {
    use windows_permissions::constants::{
        AccessRights, AceFlags, AceType, SeObjectType, SecurityInformation,
    };

    let descriptor = windows_permissions::wrappers::GetSecurityInfo(
        handle,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl,
    )
    .map_err(|error| {
        AuditError::Io(format!(
            "cannot read the Windows owner/DACL for audit path {}: {error}",
            path.display()
        ))
    })?;
    if descriptor.owner() != Some(current_sid) {
        return Err(AuditError::Io(format!(
            "audit path {} is not owned by the current Windows process user",
            path.display()
        )));
    }
    let dacl = descriptor.dacl().ok_or_else(|| {
        AuditError::Io(format!(
            "audit path {} has no Windows DACL; refusing a null DACL",
            path.display()
        ))
    })?;
    if dacl.len() != 1 {
        return Err(AuditError::Io(format!(
            "audit path {} has {} Windows DACL entries, expected one owner-only entry",
            path.display(),
            dacl.len()
        )));
    }
    let ace = dacl.get_ace(0).ok_or_else(|| {
        AuditError::Io(format!(
            "audit path {} did not expose its sole Windows DACL entry",
            path.display()
        ))
    })?;
    let expected_flags = if directory {
        AceFlags::ObjectInherit | AceFlags::ContainerInherit
    } else {
        AceFlags::empty()
    };
    if ace.ace_type() != AceType::ACCESS_ALLOWED_ACE_TYPE
        || ace.flags() != expected_flags
        || ace.mask() != AccessRights::FileAllAccess
        || ace.sid() != Some(current_sid)
    {
        return Err(AuditError::Io(format!(
            "audit path {} Windows DACL is not the exact protected owner-only policy",
            path.display()
        )));
    }
    let dacl_sddl =
        windows_permissions::wrappers::ConvertSecurityDescriptorToStringSecurityDescriptor(
            &descriptor,
            SecurityInformation::Dacl,
        )
        .map_err(|error| {
            AuditError::Io(format!(
                "cannot render the Windows DACL control flags for audit path {}: {error}",
                path.display()
            ))
        })?;
    let dacl_sddl = dacl_sddl.to_string_lossy();
    let control_flags = dacl_sddl
        .strip_prefix("D:")
        .and_then(|value| value.split_once('(').map(|(flags, _)| flags))
        .ok_or_else(|| {
            AuditError::Io(format!(
                "audit path {} returned a malformed Windows DACL descriptor",
                path.display()
            ))
        })?;
    if !control_flags.contains('P') {
        return Err(AuditError::Io(format!(
            "audit path {} Windows DACL is inheritable instead of protected",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn harden_windows_private_acl(
    opened: &File,
    path: &Path,
    directory: bool,
) -> Result<(), AuditError> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::{LocalBox, SecurityDescriptor};

    let expected_identity = open_file_identity(opened).map_err(|error| {
        AuditError::Io(format!(
            "cannot identify opened audit path {} before Windows ACL hardening: {error}",
            path.display()
        ))
    })?;
    let mut security_handle = windows_security_handle(path, directory)?;
    let security_metadata = security_handle.metadata().map_err(|error| {
        AuditError::Io(format!(
            "cannot stat the Windows ACL handle for audit path {}: {error}",
            path.display()
        ))
    })?;
    if security_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || security_metadata.file_type().is_dir() != directory
        || security_metadata.file_type().is_file() == directory
    {
        return Err(AuditError::Io(format!(
            "audit path {} changed type or became a reparse point before Windows ACL hardening",
            path.display()
        )));
    }
    if !directory {
        match security_metadata.number_of_links() {
            Some(1) => {}
            Some(links) => {
                return Err(AuditError::Io(format!(
                    "audit path {} has {links} hard links; refusing Windows ACL hardening",
                    path.display()
                )));
            }
            None => {
                return Err(AuditError::Io(format!(
                    "audit path {} did not report a link count for Windows ACL hardening",
                    path.display()
                )));
            }
        }
    }
    let security_identity = open_file_identity(&security_handle).map_err(|error| {
        AuditError::Io(format!(
            "cannot identify the Windows ACL handle for audit path {}: {error}",
            path.display()
        ))
    })?;
    if security_identity != expected_identity {
        return Err(AuditError::Io(format!(
            "audit path {} changed identity before Windows ACL hardening",
            path.display()
        )));
    }

    let current_sid = windows_permissions::utilities::current_process_sid().map_err(|error| {
        AuditError::Io(format!(
            "cannot resolve the current Windows process SID for audit path {}: {error}",
            path.display()
        ))
    })?;
    let desired: LocalBox<SecurityDescriptor> =
        windows_private_dacl_sddl(&current_sid.to_string(), directory)
            .parse()
            .map_err(|error| {
                AuditError::Io(format!(
                    "cannot construct the private Windows DACL for audit path {}: {error}",
                    path.display()
                ))
            })?;
    let desired_dacl = desired.dacl().ok_or_else(|| {
        AuditError::Io("constructed private Windows audit descriptor has no DACL".to_owned())
    })?;
    // Windows can assign a new object the token's default owner (for example,
    // an Administrators group SID) instead of TokenUser. The no-follow,
    // identity-authenticated handle above is held with WRITE_OWNER + WRITE_DAC,
    // so normalize both owner and DACL in one transition, then read back the
    // exact TokenUser-only policy before admitting the path.
    windows_permissions::wrappers::SetSecurityInfo(
        &mut security_handle,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        Some(&current_sid),
        None,
        Some(desired_dacl),
        None,
    )
    .map_err(|error| {
        AuditError::Io(format!(
            "cannot set the protected owner-only Windows DACL on audit path {}: {error}",
            path.display()
        ))
    })?;
    verify_windows_private_acl(&security_handle, path, directory, &current_sid)?;

    let final_metadata = std::fs::symlink_metadata(path).map_err(|error| {
        AuditError::Io(format!(
            "cannot re-authenticate audit path {} after Windows ACL hardening: {error}",
            path.display()
        ))
    })?;
    if final_metadata.file_type().is_symlink()
        || final_metadata.file_type().is_dir() != directory
        || final_metadata.file_type().is_file() == directory
        || metadata_identity(&final_metadata).map_err(|error| {
            AuditError::Io(format!(
                "cannot identify audit path {} after Windows ACL hardening: {error}",
                path.display()
            ))
        })? != expected_identity
    {
        return Err(AuditError::Io(format!(
            "audit path {} changed after Windows ACL hardening",
            path.display()
        )));
    }
    Ok(())
}

/// Tighten and authenticate an existing Windows audit parent directory before
/// any control or record file is opened beneath it.
///
/// The helper requires `WRITE_OWNER` plus `WRITE_DAC`, normalizes the owner to
/// the current process user, then installs and reads back the exact protected,
/// inheritable owner-only DACL required for children to be created safely from
/// their first observable instant.
#[cfg(windows)]
pub fn harden_windows_private_directory(path: &Path) -> Result<(), AuditError> {
    let directory = windows_security_handle(path, true)?;
    harden_windows_private_acl(&directory, path, true)
}

/// After opening, confirm the OPEN handle is a regular file — catching a TOCTOU
/// swap between [`reject_unsafe_existing`] and the open — and harden it to its
/// platform's owner-only policy. Unix applies `0600` to the descriptor. Windows
/// authenticates a second no-follow handle to the same file, requires current-
/// user ownership, installs one protected full-control ACE for that SID, and
/// reads it back before returning.
pub(crate) fn harden_open_regular_file(file: &File, path: &Path) -> Result<(), AuditError> {
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
    let path_metadata = std::fs::symlink_metadata(path).map_err(|e| {
        AuditError::Io(format!(
            "cannot authenticate audit path {} after opening it: {e}",
            path.display()
        ))
    })?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(AuditError::Io(format!(
            "audit path {} changed to a link or non-regular object while it was opened",
            path.display()
        )));
    }
    let opened_identity = open_file_identity(file).map_err(|e| {
        AuditError::Io(format!(
            "cannot authenticate opened audit file {}: {e}",
            path.display()
        ))
    })?;
    let path_identity = metadata_identity(&path_metadata).map_err(|e| {
        AuditError::Io(format!(
            "cannot authenticate audit path {}: {e}",
            path.display()
        ))
    })?;
    if opened_identity != path_identity {
        return Err(AuditError::Io(format!(
            "audit path {} changed identity while it was opened",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if metadata.nlink() != 1 {
            return Err(AuditError::Io(format!(
                "audit path {} has {} hard links; refusing a file that can alias another path",
                path.display(),
                metadata.nlink()
            )));
        }
        let expected_uid = rustix::process::geteuid().as_raw();
        if metadata.uid() != expected_uid {
            return Err(AuditError::Io(format!(
                "audit path {} is owned by uid {}, expected the effective uid {expected_uid}",
                path.display(),
                metadata.uid()
            )));
        }
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
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;

        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(AuditError::Io(format!(
                "audit path {} is a reparse point; refusing to follow it",
                path.display()
            )));
        }
        match metadata.number_of_links() {
            Some(1) => {}
            Some(links) => {
                return Err(AuditError::Io(format!(
                    "audit path {} has {links} hard links; refusing a file that can alias another path",
                    path.display()
                )));
            }
            None => {
                return Err(AuditError::Io(format!(
                    "audit path {} did not report a link count",
                    path.display()
                )));
            }
        }
        harden_windows_private_acl(file, path, false)?;
    }
    Ok(())
}

/// Open (creating when absent) a private, symlink-safe append handle for the
/// audit log at `path`: reject a pre-planted non-regular target, create with
/// mode `0600` on Unix, then confirm/harden the opened inode.
pub(crate) fn open_private_append_file(path: &Path) -> Result<File, AuditError> {
    reject_unsafe_existing(path)?;
    #[cfg(windows)]
    {
        open_or_create_private_windows_file(path, WindowsPrivateOpenMode::Append, "audit log")
    }
    #[cfg(not(windows))]
    {
        let mut options = OpenOptions::new();
        options.create(true).read(true).append(true);
        #[cfg(unix)]
        options.mode(0o600);
        configure_no_follow(&mut options);
        let file = options.open(path).map_err(|e| {
            AuditError::Io(format!("failed to open audit log {}: {e}", path.display()))
        })?;
        harden_open_regular_file(&file, path)?;
        Ok(file)
    }
}

/// Open (creating when absent) a private, symlink-safe read/write handle for the
/// audit `<log>.lock` sidecar. Never truncates on open (a contender must not
/// wipe the holder's recorded pid); creates `0600` on Unix and confirms/hardens
/// the opened inode.
pub(crate) fn open_private_lock_file(path: &Path) -> Result<File, AuditError> {
    reject_unsafe_existing(path)?;
    #[cfg(windows)]
    {
        open_or_create_private_windows_file(
            path,
            WindowsPrivateOpenMode::Lock,
            "audit lock sidecar",
        )
    }
    #[cfg(not(windows))]
    {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        options.mode(0o600);
        configure_no_follow(&mut options);
        let file = options.open(path).map_err(|e| {
            AuditError::Io(format!(
                "cannot open audit lock sidecar {}: {e}",
                path.display()
            ))
        })?;
        harden_open_regular_file(&file, path)?;
        Ok(file)
    }
}

/// Create a brand-new private file at `path`, failing closed if it already
/// exists (`O_CREAT|O_EXCL`, which also refuses a pre-planted symlink). Used for
/// the anchor's unpredictable same-directory temporary (bead oraclemcp-qa100 .15).
pub(crate) fn create_new_private_file(path: &Path) -> Result<File, AuditError> {
    #[cfg(windows)]
    let _creation_parent = windows_private_creation_parent(path)?;
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

/// Open an existing private regular file for bounded reads without following a
/// symlink or accepting a hard-linked/special filesystem object.
pub(crate) fn open_private_read_file(path: &Path) -> Result<File, AuditError> {
    reject_unsafe_existing(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    configure_no_follow(&mut options);
    let file = options.open(path).map_err(|e| {
        AuditError::Io(format!(
            "cannot open private audit file {} for reading: {e}",
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

/// Opaque proof that one exact open primary audit ledger was fully
/// authenticated under a particular keyring and checked against its head
/// anchor. Shipping recovery and auditor resume share this token so neither can
/// trust a merely structural tail or re-read a path after a worker starts.
#[derive(Clone, Debug)]
pub struct AuthenticatedAuditTail {
    tail: Option<ResumeTail>,
    keyring_proof: Vec<(String, String)>,
}

impl AuthenticatedAuditTail {
    pub(crate) fn chain_tail(&self) -> Option<(u64, String)> {
        self.tail
            .as_ref()
            .map(|tail| (tail.seq, tail.entry_hash.clone()))
    }

    fn matches_keyring(&self, keys: &[SigningKey]) -> bool {
        self.keyring_proof == authenticated_tail_keyring_proof(keys)
    }
}

const AUTHENTICATED_TAIL_KEYRING_DOMAIN: &str = "oraclemcp:audit-authenticated-tail-keyring:v1";

fn authenticated_tail_keyring_proof(keys: &[SigningKey]) -> Vec<(String, String)> {
    keys.iter()
        .map(|key| {
            (
                key.key_id().to_owned(),
                key.sign(AUTHENTICATED_TAIL_KEYRING_DOMAIN),
            )
        })
        .collect()
}

fn verify_anchor_with_keys(anchor: &ChainAnchor, keys: &[SigningKey]) -> Result<(), AuditError> {
    let Some(key) = keys.iter().find(|key| key.key_id() == anchor.key_id) else {
        return Err(AuditError::ResumeRefused(format!(
            "head anchor names audit key_id {:?}, which is absent from the configured active+historical keyring; add the authentic historical verification key and run `oraclemcp audit verify` before restarting",
            anchor.key_id
        )));
    };
    if !anchor.mac_is_valid(key) {
        return Err(AuditError::ResumeRefused(
            "head anchor MAC does not verify under its configured audit key - the sidecar was rewritten, forged, or the key bytes changed behind an existing key_id; inspect with `oraclemcp audit verify` and restore the authentic key/tail before restarting"
                .to_owned(),
        ));
    }
    Ok(())
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

    /// Stream and structurally verify the exact open primary ledger, retaining
    /// only its tail. WORM startup uses this to reject a new or lagging mirror
    /// before the server can accept work.
    pub(crate) fn structural_tail(&self) -> Result<Option<(u64, String)>, AuditError> {
        let mut file = self.file.lock();
        file.seek(SeekFrom::Start(0)).map_err(|error| {
            AuditError::Io(format!(
                "cannot seek primary audit log for mirror verification: {error}"
            ))
        })?;
        let result = (|| {
            let mut reader = JsonlReader::new(BufReader::new(&mut *file));
            let mut expected_seq = 1_u64;
            let mut previous_hash = GENESIS_HASH.to_owned();
            let mut tail = None;
            while let Some(record) = reader.next_record().map_err(|error| {
                AuditError::Io(format!(
                    "cannot stream primary audit log for mirror verification: {error}"
                ))
            })? {
                if record.seq != expected_seq
                    || record.prev_hash != previous_hash
                    || !record.hash_is_valid()
                {
                    return Err(AuditError::ChainBroken(record.seq));
                }
                expected_seq = expected_seq.saturating_add(1);
                previous_hash.clone_from(&record.entry_hash);
                tail = Some((record.seq, record.entry_hash));
            }
            Ok(tail)
        })();
        file.seek(SeekFrom::End(0)).map_err(|error| {
            AuditError::Io(format!(
                "cannot restore primary audit log append position: {error}"
            ))
        })?;
        result
    }

    /// Authenticate the complete exact-open primary ledger before any shipping
    /// recovery can mutate state or start a worker. The walk verifies hashes,
    /// signatures, monotonic sequence, one-way key epochs, and the optional
    /// authenticated head anchor with bounded memory.
    pub fn authenticate_existing_chain(
        &self,
        audit_path: &Path,
        anchor_path: &Path,
        keys: &[SigningKey],
    ) -> Result<AuthenticatedAuditTail, AuditError> {
        let anchor = load_anchor(anchor_path).map_err(|error| {
            AuditError::ResumeRefused(format!(
                "head anchor sidecar {} is present but unreadable ({error}); refusing to arm audit shipping without confirming the durable chain head",
                anchor_path.display()
            ))
        })?;
        if let Some(anchor) = anchor.as_ref() {
            verify_anchor_with_keys(anchor, keys)?;
        }

        let mut file = self.file.lock();
        file.seek(SeekFrom::Start(0)).map_err(|error| {
            AuditError::Io(format!(
                "cannot seek primary audit log for authenticated shipping recovery: {error}"
            ))
        })?;
        let result = (|| {
            let mut reader = JsonlReader::new(BufReader::new(&mut *file));
            let mut verifier = ChainVerifier::new(keys);
            let mut tail = None;
            let mut anchored_hash = None;
            let mut index = 0_usize;
            loop {
                let record = match reader.next_record() {
                    Ok(Some(record)) => record,
                    Ok(None) => break,
                    Err(error) => {
                        return Err(AuditError::ResumeRefused(format!(
                            "cannot authenticate primary audit log {} before shipping recovery: {error}",
                            audit_path.display()
                        )));
                    }
                };
                if let Some(VerifyOutcome::Broken { seq, reason, .. }) =
                    verifier.observe(index, &record)
                {
                    return Err(map_resume_break(audit_path, seq, &reason));
                }
                if anchor
                    .as_ref()
                    .is_some_and(|anchor| anchor.seq == record.seq)
                {
                    anchored_hash = Some(record.entry_hash.clone());
                }
                tail = Some(ResumeTail {
                    seq: record.seq,
                    entry_hash: record.entry_hash.clone(),
                    key_id: record.key_id.clone(),
                });
                index = index.saturating_add(1);
            }

            if let Some(anchor) = anchor.as_ref() {
                let chain_seq = tail.as_ref().map_or(0, |tail| tail.seq);
                if anchor.seq > chain_seq {
                    return Err(AuditError::ResumeRefused(format!(
                        "head anchor attests durable seq {} but the audit log {} ends at seq {} - trailing records were removed",
                        anchor.seq,
                        audit_path.display(),
                        chain_seq
                    )));
                }
                if anchored_hash.as_deref() != Some(anchor.entry_hash.as_str()) {
                    return Err(AuditError::ResumeRefused(format!(
                        "record at the anchored seq {} in {} does not match the authenticated head anchor",
                        anchor.seq,
                        audit_path.display()
                    )));
                }
            }

            Ok(AuthenticatedAuditTail {
                tail,
                keyring_proof: authenticated_tail_keyring_proof(keys),
            })
        })();
        file.seek(SeekFrom::End(0)).map_err(|error| {
            AuditError::Io(format!(
                "cannot restore primary audit log append position after authentication: {error}"
            ))
        })?;
        result
    }

    fn write_record(
        &self,
        record: &AuditRecord,
        certificate: Option<&BoundAuditVerdictCertificate>,
    ) -> Result<(), AuditError> {
        let serialized = if let Some(certificate) = certificate {
            let mut value =
                serde_json::to_value(record).map_err(|e| AuditError::Io(e.to_string()))?;
            let object = value
                .as_object_mut()
                .expect("audit record always serializes as an object");
            object.insert(
                "verdict_certificate".to_owned(),
                serde_json::to_value(certificate).map_err(|e| AuditError::Io(e.to_string()))?,
            );
            serde_json::to_vec(&value).map_err(|e| AuditError::Io(e.to_string()))?
        } else {
            // Preserve the existing byte-exact JSONL representation for normal
            // records so WORM mirrors remain byte-identical.
            serde_json::to_vec(record).map_err(|e| AuditError::Io(e.to_string()))?
        };
        // Escape U+2028/U+2029 so a client-controlled field value cannot forge a
        // line boundary for a line-oriented downstream reader. The WORM mirror
        // applies the identical transform, so the two stay byte-identical.
        let mut line = crate::record::escape_json_line_separators(serialized);
        line.push(b'\n');
        let mut file = self.file.lock();
        file.write_all(&line)
            .map_err(|e| AuditError::Io(e.to_string()))
    }
}

impl AuditSink for FileAuditSink {
    fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.write_record(record, None)
    }

    fn append_with_verdict_certificate(
        &self,
        record: &AuditRecord,
        certificate: &BoundAuditVerdictCertificate,
    ) -> Result<(), AuditError> {
        self.write_record(record, Some(certificate))
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
    certificates: Mutex<Vec<Option<BoundAuditVerdictCertificate>>>,
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

    /// Redacted certificates aligned by index with [`Self::records`].
    #[must_use]
    pub fn certificates(&self) -> Vec<Option<BoundAuditVerdictCertificate>> {
        self.certificates.lock().clone()
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
        self.certificates.lock().push(None);
        Ok(())
    }

    fn append_with_verdict_certificate(
        &self,
        record: &AuditRecord,
        certificate: &BoundAuditVerdictCertificate,
    ) -> Result<(), AuditError> {
        self.records.lock().push(record.clone());
        self.certificates.lock().push(Some(certificate.clone()));
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
#[derive(Clone, Debug)]
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
    /// Best-effort external transparency anchoring. It only observes heads
    /// that already passed local fsync; an outage is never an admission gate.
    rekor_anchor: Option<AsyncRekorAnchor>,
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
            rekor_anchor: None,
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

    /// Attach a bounded asynchronous Rekor anchor worker. The worker observes
    /// durable audit heads after their local fsync; submission failure and queue
    /// pressure are visible through its status handle but never alter whether a
    /// guarded database operation may proceed.
    #[must_use]
    pub fn with_rekor_anchor(mut self, rekor_anchor: AsyncRekorAnchor) -> Self {
        self.rekor_anchor = Some(rekor_anchor);
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

    /// Resume from a token produced by
    /// [`FileAuditSink::authenticate_existing_chain`]. This is the startup path
    /// used when shipping is configured: the exact primary ledger and anchor
    /// are authenticated before any recovery worker is armed, and the auditor
    /// then consumes that same proof without a path-based re-read.
    pub fn resume_from_authenticated(
        self,
        authenticated: &AuthenticatedAuditTail,
    ) -> Result<Self, AuditError> {
        if !authenticated.matches_keyring(self.keyring.verification_keys()) {
            return Err(AuditError::ResumeRefused(
                "authenticated primary-tail proof was produced under a different audit keyring"
                    .to_owned(),
            ));
        }
        if let Some(tail) = authenticated.tail.as_ref() {
            let mut state = self.state.lock();
            state.seq = tail.seq;
            state.last_hash.clone_from(&tail.entry_hash);
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
        verify_anchor_with_keys(anchor, self.keyring.verification_keys())
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
        self.append_correlated_with_observed_scn_and_certificate_internal(
            draft,
            timestamp,
            durable,
            correlation,
            observed_scn,
            verdict_certificate_core_hash,
            None,
        )
    }

    /// Append a record with a typed, redaction-safe verdict certificate. The
    /// auditor computes the core hash itself, includes it in the signed record,
    /// then binds the persisted certificate to the resulting `entry_hash`
    /// before either object reaches the sink.
    pub fn append_correlated_with_observed_scn_and_verdict_certificate(
        &self,
        draft: &AuditEntryDraft,
        timestamp: String,
        durable: bool,
        correlation: Option<AuditCorrelation>,
        observed_scn: Option<u64>,
        verdict_certificate: Option<&AuditVerdictCertificate>,
    ) -> Result<AuditRecord, AuditError> {
        let core_hash = verdict_certificate.map(AuditVerdictCertificate::core_hash);
        self.append_correlated_with_observed_scn_and_certificate_internal(
            draft,
            timestamp,
            durable,
            correlation,
            observed_scn,
            core_hash.as_deref(),
            verdict_certificate,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn append_correlated_with_observed_scn_and_certificate_internal(
        &self,
        draft: &AuditEntryDraft,
        timestamp: String,
        durable: bool,
        correlation: Option<AuditCorrelation>,
        observed_scn: Option<u64>,
        verdict_certificate_core_hash: Option<&str>,
        verdict_certificate: Option<&AuditVerdictCertificate>,
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
        let bound_certificate = verdict_certificate
            .cloned()
            .map(|certificate| certificate.bind_to_record(&record))
            .transpose()
            .map_err(|error| AuditError::InvalidVerdictCertificateEvidence(error.to_string()))?;
        match catch_unwind(AssertUnwindSafe(|| match bound_certificate.as_ref() {
            Some(certificate) => self
                .sink
                .append_with_verdict_certificate(&record, certificate),
            None => self.sink.append(&record),
        })) {
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
        if durable && let Some(rekor_anchor) = &self.rekor_anchor {
            rekor_anchor.enqueue(AuditChainHead::from_record(&record));
        }
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
        if let Some(rekor_anchor) = &self.rekor_anchor
            && state.seq > 0
            && !state.anchor_transition_pending
        {
            rekor_anchor.enqueue(AuditChainHead {
                seq: state.seq,
                entry_hash: state.last_hash.clone(),
            });
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
    fn durable_jsonl_escapes_unicode_line_separators_and_still_verifies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        // A client-controlled field carrying the Unicode line separators: a
        // line-oriented downstream reader must not be tricked into seeing two
        // records where the log wrote one.
        let mut poisoned = draft("SELECT 1 FROM dual", "SAFE");
        poisoned.tool = "oracle\u{2028}query\u{2029}x".to_owned();
        {
            let auditor = Auditor::new(
                Box::new(FileAuditSink::open(&path).expect("open")),
                test_key(),
            );
            auditor
                .append(&poisoned, "t0".to_owned(), true)
                .expect("append");
        }

        let raw = std::fs::read(&path).expect("read durable log");
        // The durable bytes carry NO literal separator...
        assert!(
            !raw.windows(3)
                .any(|w| w == [0xE2, 0x80, 0xA8] || w == [0xE2, 0x80, 0xA9]),
            "no raw U+2028/U+2029 may reach the durable log"
        );
        let text = String::from_utf8(raw).expect("utf8");
        assert!(
            text.contains("\\u2028") && text.contains("\\u2029"),
            "the separators are present in escaped form"
        );
        // ...yet it decodes back to the identical record and the chain verifies,
        // so escaping does not disturb the hash-chain integrity.
        let records = parse_jsonl(&text).expect("parse escaped log");
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].tool, "oracle\u{2028}query\u{2029}x",
            "the field value round-trips exactly"
        );
        assert!(records[0].hash_is_valid());
        assert_eq!(
            verify_records(&records, &[test_key()]),
            VerifyOutcome::Ok { records: 1 }
        );
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
                // The pid hint is a best-effort operator convenience. On Unix
                // `flock` is advisory, so the contender can read the holder's
                // recorded pid. On Windows `File::try_lock` is a MANDATORY
                // `LockFileEx` lock that blocks the contender's read of the
                // sidecar, so `read_holder_pid` legitimately yields `None` while
                // the lock is held — the important guarantee (fail-closed with
                // the typed `Locked` error naming the path) is unchanged.
                #[cfg(unix)]
                assert_eq!(
                    holder_pid,
                    Some(std::process::id()),
                    "the lock sidecar records the holder pid for the operator hint"
                );
                #[cfg(not(unix))]
                let _ = holder_pid;
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
    fn flush_after_a_failed_fsync_refuses_due_to_poisoned_state() {
        let sink = Arc::new(FlushFailsOnceSink::default());
        let anchor_path = tempfile::tempdir()
            .expect("tempdir")
            .path()
            .join("audit.anchor");
        let sink = SharedFlakySink(sink);
        let auditor = Auditor::new(Box::new(sink), test_key()).with_head_anchor(&anchor_path);

        let first = auditor.append(
            &draft("DELETE FROM t WHERE id=1", "GUARDED"),
            "t0".to_owned(),
            true,
        );
        assert!(
            matches!(first, Err(AuditError::Io(_))),
            "durable fsync failure must be observable"
        );
        assert_eq!(
            load_anchor(&anchor_path).expect("load"),
            None,
            "anchor must stay absent after a failed durable flush"
        );

        let second = auditor.flush();
        assert!(
            matches!(second, Err(AuditError::Poisoned)),
            "poisoned flush must fail closed, not clear a failed fsync window"
        );
    }

    #[test]
    fn find_entry_hash_at_seq_handles_present_and_missing_sequences() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let missing_path = dir.path().join("missing.jsonl");
        let auditor = Auditor::new(
            Box::new(FileAuditSink::open(&path).expect("open durable audit log")),
            test_key(),
        );
        let first = auditor
            .append(&draft("SELECT 1 FROM dual", "SAFE"), "t0".to_owned(), true)
            .expect("append one");
        let second = auditor
            .append(&draft("SELECT 2 FROM dual", "SAFE"), "t1".to_owned(), true)
            .expect("append two");
        assert_eq!(
            find_entry_hash_at_seq(&missing_path, 1).expect("missing file"),
            None,
            "absent file should report no hash"
        );
        assert_eq!(
            find_entry_hash_at_seq(&path, 1).expect("seq one"),
            Some(first.entry_hash),
            "the matching sequence hash should be returned"
        );
        assert_eq!(
            find_entry_hash_at_seq(&path, 2).expect("seq two"),
            Some(second.entry_hash),
            "the second sequence hash should be returned"
        );
        assert_eq!(
            find_entry_hash_at_seq(&path, 3).expect("missing seq"),
            None,
            "absent sequence must return None"
        );
    }

    #[test]
    fn find_entry_hash_at_seq_refuses_malformed_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        std::fs::write(&path, "{bad json\n").expect("write malformed jsonl body");

        let err = match find_entry_hash_at_seq(&path, 1) {
            Ok(_) => panic!("malformed JSONL must fail this lookup"),
            Err(err) => err,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("cannot re-read audit log"),
            "malformed line must surface as a resume-style refusal: {msg}"
        );
        assert!(
            msg.contains("anchored") || msg.contains("malformed audit record"),
            "failure should describe malformed replay input: {msg}"
        );
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

    #[test]
    fn windows_private_dacl_policy_is_protected_and_owner_only() {
        let sid = "S-1-5-21-111-222-333-444";
        assert_eq!(
            windows_private_dacl_sddl(sid, false),
            "D:P(A;;FA;;;S-1-5-21-111-222-333-444)"
        );
        assert_eq!(
            windows_private_dacl_sddl(sid, true),
            "D:P(A;OICI;FA;;;S-1-5-21-111-222-333-444)"
        );
    }

    #[cfg(windows)]
    #[test]
    fn broad_windows_file_and_directory_dacls_are_tightened_and_read_back() {
        use windows_permissions::constants::{SeObjectType, SecurityInformation};
        use windows_permissions::{LocalBox, SecurityDescriptor};

        fn install_broad_dacl(path: &Path, directory: bool) {
            let current_sid = windows_permissions::utilities::current_process_sid()
                .expect("resolve current process SID");
            let inheritance = if directory { "OICI" } else { "" };
            let descriptor: LocalBox<SecurityDescriptor> = format!(
                "D:(A;{inheritance};FA;;;WD)(A;{inheritance};FA;;;{})",
                current_sid
            )
            .parse()
            .expect("parse broad test DACL");
            windows_permissions::wrappers::SetNamedSecurityInfo(
                path.as_os_str(),
                SeObjectType::SE_FILE_OBJECT,
                SecurityInformation::Dacl | SecurityInformation::UnprotectedDacl,
                None,
                None,
                descriptor.dacl(),
                None,
            )
            .expect("install broad test DACL");
            let broad = windows_permissions::wrappers::GetNamedSecurityInfo(
                path.as_os_str(),
                SeObjectType::SE_FILE_OBJECT,
                SecurityInformation::Dacl,
            )
            .expect("read broad test DACL");
            assert!(
                broad.dacl().expect("broad DACL exists").len() >= 2,
                "fixture must expose more than the private owner-only ACE"
            );
        }

        let root = tempfile::tempdir().expect("tempdir");
        let file_path = root.path().join("audit.jsonl");
        std::fs::write(&file_path, b"").expect("seed audit file");
        install_broad_dacl(&file_path, false);
        let file = open_private_append_file(&file_path).expect("harden broad file DACL");
        let current_sid = windows_permissions::utilities::current_process_sid()
            .expect("resolve current process SID");
        let file_acl_handle = windows_security_handle(&file_path, false).expect("file ACL handle");
        verify_windows_private_acl(&file_acl_handle, &file_path, false, &current_sid)
            .expect("file DACL must be exact after hardening");
        drop(file);

        let directory_path = root.path().join("spool");
        std::fs::create_dir(&directory_path).expect("create spool directory");
        install_broad_dacl(&directory_path, true);
        let refused_child = directory_path.join("refused-new.jsonl");
        let error = open_private_append_file(&refused_child)
            .expect_err("a broad parent DACL must fail before child creation");
        assert!(error.to_string().contains("owner-only parent DACL"));
        assert!(
            !refused_child.exists(),
            "fail-closed Windows creation must not leave a child behind"
        );
        harden_windows_private_directory(&directory_path).expect("harden broad directory DACL");
        let directory_acl_handle =
            windows_security_handle(&directory_path, true).expect("directory ACL handle");
        verify_windows_private_acl(&directory_acl_handle, &directory_path, true, &current_sid)
            .expect("directory DACL must be exact after hardening");

        let created_child = directory_path.join("created-private.jsonl");
        let child = open_private_append_file(&created_child)
            .expect("create beneath an authenticated private parent");
        let child_acl_handle =
            windows_security_handle(&created_child, false).expect("child ACL handle");
        verify_windows_private_acl(&child_acl_handle, &created_child, false, &current_sid)
            .expect("new child DACL must be exact after creation");
        drop(child);
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

    // === GATE-SEAL residue kills ===

    // Build a matching (signed record, bound verdict certificate) pair so the
    // certificate-persistence sinks can be exercised directly.
    fn record_with_bound_cert() -> (AuditRecord, BoundAuditVerdictCertificate) {
        let d = draft("SELECT 1 FROM dual", "GUARDED");
        let stmt_digest = crate::sha256_hex(d.sql.as_bytes());
        let step = crate::AuditVerdictDerivationStep::new(
            crate::AuditVerdictRuleId::R16,
            crate::AuditVerdictConstruct::FinalSafe,
        )
        .expect("registered derivation step");
        let cert = AuditVerdictCertificate::new(
            "audit-policy-v1".to_owned(),
            vec![step],
            Some(crate::AuditVerdictOperatingLevel::ReadOnly),
            None,
            stmt_digest,
            crate::AuditVerdict::Safe,
        )
        .expect("valid verdict certificate");
        let core_hash = cert.core_hash();
        let record =
            AuditRecord::chained_signed_correlated_with_observed_scn_and_certificate_core_hash(
                &d,
                1,
                GENESIS_HASH,
                "t0".to_owned(),
                &test_key(),
                None,
                None,
                Some(core_hash),
            );
        let bound = cert.bind_to_record(&record).expect("bind cert to record");
        (record, bound)
    }

    // L137: `is_canonical_sha256` must reject a `sha256:` value whose hex body is
    // not exactly 64 chars even when every char is lowercase hex (the `&&`
    // mutated to `||` would accept it).
    #[test]
    fn residue_verdict_core_hash_rejects_wrong_length_all_hex() {
        let auditor = Auditor::new(Box::new(MemoryAuditSink::new()), test_key());
        let bad = format!("sha256:{}", "a".repeat(63));
        let result = auditor.append_correlated_with_observed_scn_and_certificate_core_hash(
            &draft("SELECT 1", "GUARDED"),
            "t0".to_owned(),
            false,
            None,
            None,
            Some(bad.as_str()),
        );
        assert!(
            matches!(result, Err(AuditError::InvalidVerdictCertificateCoreHash)),
            "a 63-char all-hex body is not canonical sha256; got {result:?}"
        );
    }

    // L139: `is_canonical_sha256` must reject uppercase hex (the per-byte
    // `is_ascii_hexdigit() && !is_ascii_uppercase()` mutated to `||` would accept
    // uppercase, and would also accept non-hex chars).
    #[test]
    fn residue_verdict_core_hash_rejects_uppercase_hex() {
        let auditor = Auditor::new(Box::new(MemoryAuditSink::new()), test_key());
        let bad = format!("sha256:{}", "A".repeat(64));
        let result = auditor.append_correlated_with_observed_scn_and_certificate_core_hash(
            &draft("SELECT 1", "GUARDED"),
            "t0".to_owned(),
            false,
            None,
            None,
            Some(bad.as_str()),
        );
        assert!(
            matches!(result, Err(AuditError::InvalidVerdictCertificateCoreHash)),
            "uppercase hex is not canonical sha256; got {result:?}"
        );
    }

    // L156: the trait-default `append_with_verdict_certificate` must REFUSE
    // (persistence unsupported), never silently succeed. `SharedSink` inherits
    // the default.
    #[test]
    fn residue_default_verdict_persistence_is_refused() {
        let (record, bound) = record_with_bound_cert();
        let sink = SharedSink(Arc::new(MemoryAuditSink::new()));
        let result = sink.append_with_verdict_certificate(&record, &bound);
        assert!(
            matches!(
                result,
                Err(AuditError::VerdictCertificatePersistenceUnsupported)
            ),
            "a sink without certificate persistence must refuse; got {result:?}"
        );
    }

    // L270: `reject_unsafe_existing` must propagate a non-NotFound stat error
    // (the guard mutated to `true` would treat any error as "absent → ok").
    // Unix-only: the `file/child` probe below induces the non-NotFound error via
    // ENOTDIR; on Windows that same probe maps to `NotFound` (os error 3), so it
    // cannot exercise the non-NotFound branch there (matches the other
    // `#[cfg(unix)]` residue tests in this module).
    #[cfg(unix)]
    #[test]
    fn residue_reject_unsafe_existing_propagates_non_notfound() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"x").expect("seed regular file");
        let under_file = file.join("child"); // stat -> ENOTDIR (not NotFound)
        assert!(
            reject_unsafe_existing(&under_file).is_err(),
            "a non-NotFound inspection error must fail closed, not be treated as absent"
        );
    }

    // L381: `fsync_parent_dir` maps an empty parent to "." (a relative
    // single-component path has an empty-string parent); the guard mutated to
    // `true` would instead try to open the empty path and fail.
    #[cfg(unix)]
    #[test]
    fn residue_fsync_parent_dir_uses_dot_for_empty_parent() {
        assert!(
            fsync_parent_dir(Path::new("residue-single-component-name")).is_ok(),
            "an empty parent must resolve to \".\" and fsync successfully"
        );
    }

    // L447: `FileAuditSink::open` fsyncs the parent directory when EITHER the log
    // OR its lock sidecar is newly created (`||`). The `&&` mutant would skip the
    // fsync when only one of them is new.
    #[cfg(unix)]
    #[test]
    fn residue_open_fsyncs_parent_when_only_lock_is_new() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        // Pre-create the audit log (regular file) so `audit_pre_existing` is
        // true but the lock sidecar is still absent -> `false || true`.
        std::fs::write(&path, b"").expect("pre-create audit log");
        let before = PARENT_DIR_FSYNCS.with(std::cell::Cell::get);
        let _sink = FileAuditSink::open(&path).expect("open");
        let after = PARENT_DIR_FSYNCS.with(std::cell::Cell::get);
        assert_eq!(
            after - before,
            1,
            "creating only the lock sidecar must still fsync the parent directory"
        );
    }

    // L504: `FileAuditSink::append_with_verdict_certificate` must actually write
    // the cert-bearing record (the FnValue `Ok(())` mutant writes nothing).
    #[test]
    fn residue_file_sink_persists_verdict_certificate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let sink = FileAuditSink::open(&path).expect("open");
        let (record, bound) = record_with_bound_cert();
        sink.append_with_verdict_certificate(&record, &bound)
            .expect("append with cert");
        let contents = std::fs::read_to_string(&path).expect("read back");
        assert!(
            contents.contains("verdict_certificate"),
            "the certificate-bearing record must be durably written"
        );
    }

    // L539 + L561: `MemoryAuditSink::append_with_verdict_certificate` must record
    // the record AND its certificate, and `certificates()` must return them.
    #[test]
    fn residue_memory_sink_records_verdict_certificate() {
        let sink = MemoryAuditSink::new();
        let (record, bound) = record_with_bound_cert();
        sink.append_with_verdict_certificate(&record, &bound)
            .expect("append with cert");
        assert_eq!(sink.records().len(), 1, "the record must be recorded");
        assert_eq!(
            sink.certificates(),
            vec![Some(bound)],
            "the aligned certificate slot must hold the bound certificate"
        );
    }

    // L634: `analyze_resume_log` must propagate a non-NotFound open error (the
    // guard mutated to `true` would swallow it as "fresh genesis").
    // Unix-only: `file/child` induces ENOTDIR (a non-NotFound error) on Unix;
    // Windows maps it to `NotFound`, so the probe cannot exercise this branch.
    #[cfg(unix)]
    #[test]
    fn residue_analyze_resume_log_propagates_non_notfound() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"x").expect("seed regular file");
        let under_file = file.join("child");
        assert!(
            analyze_resume_log(&under_file, &[]).is_err(),
            "a non-NotFound open error must refuse resume, not seed a fresh chain"
        );
    }

    // Multi-record resume regression: a valid 2-record chain resumes to its last
    // record. (Note: the `index += 1` at sink.rs L672 is only fed to
    // `ChainVerifier::observe` as the discarded `Broken.index` diagnostic — the
    // chain itself verifies via the verifier's internal prev_hash/prev_seq state,
    // so `index`'s value is not observable here; the `*= 1` mutant is equivalent.)
    #[test]
    fn residue_analyze_resume_log_verifies_multiple_records() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        {
            let auditor = Auditor::new(
                Box::new(FileAuditSink::open(&path).expect("open")),
                test_key(),
            );
            auditor
                .append(&draft("SELECT 1", "GUARDED"), "t1".to_owned(), true)
                .expect("append 1");
            auditor
                .append(&draft("SELECT 2", "GUARDED"), "t2".to_owned(), true)
                .expect("append 2");
        }
        let tail = analyze_resume_log(&path, &[test_key()])
            .expect("a valid 2-record chain must resume")
            .expect("non-empty tail");
        assert_eq!(tail.seq, 2, "the resume tail must be the last record");
    }

    // L724: `find_entry_hash_at_seq` must propagate a non-NotFound open error.
    // Unix-only: `file/child` induces ENOTDIR (a non-NotFound error) on Unix;
    // Windows maps it to `NotFound`, so the probe cannot exercise this branch.
    #[cfg(unix)]
    #[test]
    fn residue_find_entry_hash_at_seq_propagates_non_notfound() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"x").expect("seed regular file");
        let under_file = file.join("child");
        assert!(
            find_entry_hash_at_seq(&under_file, 1).is_err(),
            "a non-NotFound open error must surface, not be reported as truncation"
        );
    }

    struct RejectingSubmitter;
    impl crate::RekorSubmitter for RejectingSubmitter {
        fn submit(
            &self,
            _head: &crate::AuditChainHead,
        ) -> Result<crate::RekorAnchorReceipt, crate::RekorSubmitError> {
            Err(crate::RekorSubmitError::Rejected)
        }
    }

    // L1183 (`> 0` -> `== 0` / `< 0`) and L1184 (drop `!`): a flush after at least
    // one record must enqueue the head to the Rekor anchor. A non-durable append
    // advances the seq without the durable-path enqueue, isolating the flush-path
    // enqueue.
    #[test]
    fn residue_flush_enqueues_rekor_head_after_a_record() {
        let anchor = crate::AsyncRekorAnchor::new(Box::new(RejectingSubmitter), 8).expect("anchor");
        let auditor = Auditor::new(Box::new(MemoryAuditSink::new()), test_key())
            .with_rekor_anchor(anchor.clone());
        auditor
            .append(&draft("SELECT 1", "GUARDED"), "t0".to_owned(), false)
            .expect("non-durable append");
        auditor.flush().expect("flush");
        assert_eq!(
            anchor.status().enqueued,
            1,
            "a flush after one record must enqueue exactly one Rekor head"
        );
    }

    // L1183 (`> 0` -> `>= 0`): a flush with NO records (seq == 0) must NOT enqueue
    // a Rekor head.
    #[test]
    fn residue_flush_before_any_record_does_not_enqueue_rekor() {
        let anchor = crate::AsyncRekorAnchor::new(Box::new(RejectingSubmitter), 8).expect("anchor");
        let auditor = Auditor::new(Box::new(MemoryAuditSink::new()), test_key())
            .with_rekor_anchor(anchor.clone());
        auditor.flush().expect("empty flush");
        assert_eq!(
            anchor.status().enqueued,
            0,
            "an empty chain (seq == 0) must not enqueue a Rekor head"
        );
    }
}
