//! Shared file-store primitives for service-owned state.
//!
//! This is deliberately files-first and SQLite-free. Mutations require a
//! process-wide service ownership capability, then use write-temp/fsync/rename/fsync-dir so
//! callers can build durable config, metrics, proposal, and idempotency stores
//! without inventing their own path handling.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use parking_lot::{ReentrantMutex, ReentrantMutexGuard};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

const APP_STATE_DIR: &str = "oraclemcp";
const SERVICE_LOCK_FILE: &str = ".service.lock";
const MAX_SEGMENT_LEN: usize = 64;

/// File-store operation errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FileStoreError {
    /// An I/O operation failed.
    #[error("file-store io error: {0}")]
    Io(String),
    /// A path segment was empty, too long, or contained traversal characters.
    #[error("invalid path segment for {kind}: {value:?}")]
    InvalidSegment { kind: &'static str, value: String },
    /// A path component that must be a directory is a symlink or non-directory.
    #[error("unsafe file-store path: {0}")]
    UnsafePath(String),
    /// Another service owner already holds the single-writer lock.
    #[error("file-store service lock is already held")]
    Locked,
    /// A mutation was attempted without the owner capability for this store root.
    #[error("file-store mutation requires the matching service owner")]
    LockRequired,
    /// Audit data is never pruned by retention.
    #[error("audit data is not prunable")]
    AuditNotPrunable,
    /// A JSONL append record must be one complete line without embedded line
    /// terminators.
    #[error("invalid jsonl record: embedded line terminator")]
    InvalidJsonlRecord,
}

type Result<T> = std::result::Result<T, FileStoreError>;

/// A sanitized, bounded ID safe to use as one path segment.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StoreId(String);

impl StoreId {
    /// Build an ID from trusted material that is already path-safe.
    pub fn from_safe_segment(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_segment("id", &value)?;
        Ok(Self(value))
    }

    /// Build a path-safe ID from untrusted material by combining a sanitized
    /// label with a SHA-256 content hash. Raw profile, author, principal, or
    /// proposal names should use this path, not direct interpolation.
    pub fn content_hashed(label: &str, parts: &[&str]) -> Result<Self> {
        let label = sanitize_label(label)?;
        let mut hasher = Sha256::new();
        for part in parts {
            hasher.update((part.len() as u64).to_le_bytes());
            hasher.update(part.as_bytes());
        }
        let digest = hex_lower(&hasher.finalize());
        Self::from_safe_segment(format!("{label}-{}", &digest[..40]))
    }

    /// The path-safe segment.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Cloneable capability proving this process owns the service state root.
///
/// Ownership is an advisory OS lock tied to the open descriptor. The
/// `.service.lock` sidecar persists as an operator hint and must not be
/// manually removed; process exit releases ownership automatically. Clones
/// share one in-process mutation gate and temporary-name sequence, so every
/// file-store domain composes under one process owner without weakening
/// cross-process exclusion.
#[derive(Clone)]
pub struct ServiceOwner {
    inner: Arc<ServiceOwnerInner>,
}

struct ServiceOwnerInner {
    root: PathBuf,
    file: File,
    mutation_gate: ReentrantMutex<()>,
    tmp_counter: AtomicU64,
}

impl ServiceOwner {
    fn assert_for(&self, store: &FileStore) -> Result<()> {
        if self.inner.root == store.root {
            Ok(())
        } else {
            Err(FileStoreError::LockRequired)
        }
    }

    /// The canonical state root owned by this process.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.inner.root
    }

    pub(crate) fn mutation_guard(&self) -> ReentrantMutexGuard<'_, ()> {
        self.inner.mutation_gate.lock()
    }
}

impl Drop for ServiceOwnerInner {
    fn drop(&mut self) {
        // SAFETY: ownership is the advisory OS lock on this exact open file,
        // never the mutable pathname. Closing the descriptor also releases it
        // after a crash. The sidecar is deliberately persistent: unlinking it
        // could let another process lock a replacement inode while this one is
        // still live, and an old holder must never delete a replacement lock.
        let _ = self.file.unlock();
    }
}

/// Classification for retention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionClass {
    /// Prunable service data such as metrics snapshots.
    Prunable,
    /// Audit data. This class is never pruned.
    Audit,
}

/// Report from JSONL tail repair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryReport {
    /// Bytes removed from an unterminated tail.
    pub repaired_tail_bytes: u64,
    /// Rebuilt line index.
    pub index: JsonlIndex,
}

/// A rebuilt byte-offset index for a JSONL file.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct JsonlIndex {
    /// Complete line spans in byte offsets.
    pub records: Vec<JsonlRecord>,
}

/// One complete JSONL record span.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonlRecord {
    /// Starting byte offset.
    pub offset: u64,
    /// Length including the trailing newline.
    pub len: u64,
}

/// Report from pruning a collection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PruneReport {
    /// Number of regular files removed.
    pub removed: usize,
    /// Number of regular files left in the collection.
    pub retained: usize,
}

/// Service-owned file store rooted under XDG state.
pub struct FileStore {
    root: PathBuf,
}

impl FileStore {
    /// Open a store rooted at `$XDG_STATE_HOME/oraclemcp`, or
    /// `$HOME/.local/state/oraclemcp` when XDG is not set.
    pub fn open_default() -> Result<Self> {
        Self::open(Self::default_state_dir()?)
    }

    /// The default state directory for oraclemcp.
    pub fn default_state_dir() -> Result<PathBuf> {
        if let Some(xdg) = std::env::var_os("XDG_STATE_HOME") {
            return Ok(PathBuf::from(xdg).join(APP_STATE_DIR));
        }
        if let Some(home) = std::env::var_os("HOME") {
            return Ok(PathBuf::from(home).join(".local/state").join(APP_STATE_DIR));
        }
        Err(FileStoreError::Io(
            "neither XDG_STATE_HOME nor HOME is set".to_owned(),
        ))
    }

    /// Open a store at `root`, creating it with private permissions when absent.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        ensure_private_dir(root)?;
        let root = root
            .canonicalize()
            .map_err(|e| FileStoreError::Io(e.to_string()))?;
        Ok(Self { root })
    }

    /// The canonical store root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Acquire the mandatory process-wide ownership capability for this store.
    pub fn acquire_service_owner(&self, owner: &str) -> Result<ServiceOwner> {
        self.acquire_service_owner_with_metadata(owner, write_service_lock_metadata)
    }

    fn acquire_service_owner_with_metadata(
        &self,
        owner: &str,
        write_metadata: impl FnOnce(&mut File, &str) -> std::io::Result<()>,
    ) -> Result<ServiceOwner> {
        let path = self.root.join(SERVICE_LOCK_FILE);
        let mut file = open_private_lock_file(&path)
            .map_err(|e| FileStoreError::Io(format!("cannot open {}: {e}", path.display())))?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(FileStoreError::Locked),
            Err(TryLockError::Error(error)) => {
                return Err(FileStoreError::Io(format!(
                    "cannot lock {}: {error}",
                    path.display()
                )));
            }
        }

        // The descriptor already owns the lock. All fallible initialization
        // below is therefore crash-safe: `?` drops the descriptor and releases
        // ownership, while the persistent (possibly partial) sidecar is never
        // interpreted as ownership by a future process.
        file.set_len(0)
            .and_then(|()| file.seek(SeekFrom::Start(0)).map(|_| ()))
            .and_then(|()| write_metadata(&mut file, owner))
            .map_err(|e| FileStoreError::Io(e.to_string()))?;
        file.sync_all()
            .map_err(|e| FileStoreError::Io(e.to_string()))?;
        fsync_dir(&self.root)?;
        Ok(ServiceOwner {
            inner: Arc::new(ServiceOwnerInner {
                root: self.root.clone(),
                file,
                mutation_gate: ReentrantMutex::new(()),
                tmp_counter: AtomicU64::new(0),
            }),
        })
    }

    /// Compute the path for a safe collection/id/extension tuple.
    pub fn path_for(&self, collection: &str, id: &StoreId, extension: &str) -> Result<PathBuf> {
        validate_segment("collection", collection)?;
        validate_segment("extension", extension)?;
        Ok(self
            .root
            .join(collection)
            .join(format!("{}.{}", id.as_str(), extension)))
    }

    /// Compute the path for a fixed root-level service file.
    ///
    /// This is for code-owned state files named by constants such as
    /// `clients.json`. Untrusted profile/principal/author material must still
    /// use [`StoreId::content_hashed`] under a collection.
    pub fn root_path_for(&self, id: &StoreId, extension: &str) -> Result<PathBuf> {
        validate_segment("extension", extension)?;
        Ok(self.root.join(format!("{}.{}", id.as_str(), extension)))
    }

    /// Atomically replace a file with `bytes`.
    pub fn write_atomic(
        &self,
        owner: &ServiceOwner,
        collection: &str,
        id: &StoreId,
        extension: &str,
        bytes: &[u8],
    ) -> Result<PathBuf> {
        owner.assert_for(self)?;
        let _guard = owner.inner.mutation_gate.lock();
        let dir = self.collection_dir(collection)?;
        let final_path = self.path_for(collection, id, extension)?;
        let tmp_path = self.tmp_path(owner, &dir, id, extension);

        let mut tmp =
            create_new_private_file(&tmp_path).map_err(|e| FileStoreError::Io(e.to_string()))?;
        tmp.write_all(bytes)
            .and_then(|()| tmp.sync_all())
            .map_err(|e| FileStoreError::Io(e.to_string()))?;
        drop(tmp);

        fs::rename(&tmp_path, &final_path).map_err(|e| FileStoreError::Io(e.to_string()))?;
        fsync_dir(&dir)?;
        Ok(final_path)
    }

    /// Atomically replace a fixed root-level service file with `bytes`.
    pub fn write_root_atomic(
        &self,
        owner: &ServiceOwner,
        id: &StoreId,
        extension: &str,
        bytes: &[u8],
    ) -> Result<PathBuf> {
        owner.assert_for(self)?;
        let _guard = owner.inner.mutation_gate.lock();
        let final_path = self.root_path_for(id, extension)?;
        let tmp_path = self.tmp_path(owner, &self.root, id, extension);

        let mut tmp =
            create_new_private_file(&tmp_path).map_err(|e| FileStoreError::Io(e.to_string()))?;
        tmp.write_all(bytes)
            .and_then(|()| tmp.sync_all())
            .map_err(|e| FileStoreError::Io(e.to_string()))?;
        drop(tmp);

        fs::rename(&tmp_path, &final_path).map_err(|e| FileStoreError::Io(e.to_string()))?;
        fsync_dir(&self.root)?;
        Ok(final_path)
    }

    /// Recover an append-style JSONL file by truncating any unterminated tail and
    /// rebuilding the byte-offset index from complete lines.
    pub fn recover_jsonl(
        &self,
        owner: &ServiceOwner,
        collection: &str,
        id: &StoreId,
    ) -> Result<RecoveryReport> {
        owner.assert_for(self)?;
        let _guard = owner.inner.mutation_gate.lock();
        let dir = self.collection_dir(collection)?;
        let path = self.path_for(collection, id, "jsonl")?;
        if !path.exists() {
            let file =
                create_new_private_file(&path).map_err(|e| FileStoreError::Io(e.to_string()))?;
            file.sync_all()
                .map_err(|e| FileStoreError::Io(e.to_string()))?;
            fsync_dir(&dir)?;
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| FileStoreError::Io(e.to_string()))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| FileStoreError::Io(e.to_string()))?;
        let valid_len = bytes
            .iter()
            .rposition(|b| *b == b'\n')
            .map_or(0usize, |pos| pos + 1);
        let repaired = bytes.len().saturating_sub(valid_len) as u64;
        if repaired > 0 {
            file.set_len(valid_len as u64)
                .and_then(|()| file.sync_all())
                .map_err(|e| FileStoreError::Io(e.to_string()))?;
            fsync_dir(&dir)?;
            bytes.truncate(valid_len);
        }
        Ok(RecoveryReport {
            repaired_tail_bytes: repaired,
            index: rebuild_jsonl_index(&bytes),
        })
    }

    /// Append one complete JSON record to a JSONL file and fsync before
    /// returning. `record` must not include the trailing newline; the store adds
    /// exactly one line terminator.
    pub fn append_jsonl(
        &self,
        owner: &ServiceOwner,
        collection: &str,
        id: &StoreId,
        record: &[u8],
    ) -> Result<PathBuf> {
        owner.assert_for(self)?;
        if record.iter().any(|b| *b == b'\n' || *b == b'\r') {
            return Err(FileStoreError::InvalidJsonlRecord);
        }
        let _guard = owner.inner.mutation_gate.lock();
        let dir = self.collection_dir(collection)?;
        let path = self.path_for(collection, id, "jsonl")?;
        let created = !path.exists();
        let mut file =
            open_append_private_file(&path).map_err(|e| FileStoreError::Io(e.to_string()))?;
        file.write_all(record)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|e| FileStoreError::Io(e.to_string()))?;
        if created {
            fsync_dir(&dir)?;
        }
        Ok(path)
    }

    /// Prune regular files from a collection, retaining the newest `keep_latest`
    /// by modified time. Audit-class data is refused.
    pub fn prune_collection(
        &self,
        owner: &ServiceOwner,
        collection: &str,
        keep_latest: usize,
        class: RetentionClass,
    ) -> Result<PruneReport> {
        owner.assert_for(self)?;
        if class == RetentionClass::Audit {
            return Err(FileStoreError::AuditNotPrunable);
        }
        let _guard = owner.inner.mutation_gate.lock();
        let dir = self.collection_dir(collection)?;
        let mut entries = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|e| FileStoreError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| FileStoreError::Io(e.to_string()))?;
            if !entry
                .file_type()
                .map_err(|e| FileStoreError::Io(e.to_string()))?
                .is_file()
            {
                continue;
            }
            let metadata = entry
                .metadata()
                .map_err(|e| FileStoreError::Io(e.to_string()))?;
            let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            entries.push((modified, entry.file_name(), entry.path()));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        let remove_count = entries.len().saturating_sub(keep_latest);
        for (_, _, path) in entries.iter().take(remove_count) {
            fs::remove_file(path).map_err(|e| FileStoreError::Io(e.to_string()))?;
        }
        if remove_count > 0 {
            fsync_dir(&dir)?;
        }
        Ok(PruneReport {
            removed: remove_count,
            retained: entries.len() - remove_count,
        })
    }

    fn collection_dir(&self, collection: &str) -> Result<PathBuf> {
        validate_segment("collection", collection)?;
        let dir = self.root.join(collection);
        ensure_private_dir(&dir)?;
        Ok(dir)
    }

    fn tmp_path(&self, owner: &ServiceOwner, dir: &Path, id: &StoreId, extension: &str) -> PathBuf {
        let counter = owner.inner.tmp_counter.fetch_add(1, Ordering::Relaxed);
        dir.join(format!(
            ".{}.{}.tmp.{}.{}",
            id.as_str(),
            extension,
            std::process::id(),
            counter
        ))
    }
}

fn rebuild_jsonl_index(bytes: &[u8]) -> JsonlIndex {
    let mut records = Vec::new();
    let mut offset = 0u64;
    for line in bytes.split_inclusive(|b| *b == b'\n') {
        if line.ends_with(b"\n") {
            records.push(JsonlRecord {
                offset,
                len: line.len() as u64,
            });
        }
        offset += line.len() as u64;
    }
    JsonlIndex { records }
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(FileStoreError::UnsafePath(path.display().to_string()));
        }
        harden_private_dir(path, meta)?;
        return Ok(());
    }

    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|e| FileStoreError::Io(e.to_string()))?;
    Ok(())
}

#[cfg(unix)]
fn harden_private_dir(path: &Path, meta: fs::Metadata) -> Result<()> {
    let mode = meta.permissions().mode() & 0o777;
    if mode == 0o700 {
        return Ok(());
    }
    let mut permissions = meta.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).map_err(|e| FileStoreError::Io(e.to_string()))
}

#[cfg(not(unix))]
fn harden_private_dir(_path: &Path, _meta: fs::Metadata) -> Result<()> {
    Ok(())
}

fn create_new_private_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path)
}

fn open_private_lock_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path)
}

fn write_service_lock_metadata(file: &mut File, owner: &str) -> std::io::Result<()> {
    writeln!(file, "pid={}", std::process::id())?;
    // Debug formatting escapes control characters so this operator hint stays
    // one physical line even if a caller supplied an unusual owner label.
    writeln!(file, "owner={owner:?}")
}

fn open_append_private_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path)
}

fn fsync_dir(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|e| FileStoreError::Io(e.to_string()))
}

fn validate_segment(kind: &'static str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_SEGMENT_LEN
        || value == "."
        || value == ".."
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(FileStoreError::InvalidSegment {
            kind,
            value: value.to_owned(),
        });
    }
    Ok(())
}

fn sanitize_label(label: &str) -> Result<String> {
    let mut out = String::with_capacity(label.len().min(24));
    for byte in label.bytes() {
        if byte.is_ascii_alphanumeric() {
            out.push((byte as char).to_ascii_lowercase());
        } else if (byte == b'-' || byte == b'_') && !out.ends_with('-') {
            out.push('-');
        }
        if out.len() == 24 {
            break;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        out.push_str("id");
    }
    validate_segment("label", &out)?;
    Ok(out)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant, UNIX_EPOCH};

    const LOCK_HELPER_ROOT_ENV: &str = "ORACLEMCP_FILE_STORE_LOCK_HELPER_ROOT";
    const LOCK_HELPER_READY_ENV: &str = "ORACLEMCP_FILE_STORE_LOCK_HELPER_READY";

    fn test_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/file-store-tests")
            .join(format!("{name}-{}-{stamp}", std::process::id()))
    }

    #[test]
    fn file_store_atomic_fsync_lock_path_safe() {
        let store = FileStore::open(test_root("atomic")).expect("store");
        let lock = store.acquire_service_owner("test").expect("lock");
        assert!(
            store.acquire_service_owner("other").is_err(),
            "second writer must not acquire the service lock"
        );

        let id =
            StoreId::content_hashed("proposal", &["../../prod", "author/../x"]).expect("hashed id");
        assert!(id.as_str().starts_with("proposal-"));
        assert!(!id.as_str().contains(".."));
        assert!(!id.as_str().contains('/'));
        assert!(id.as_str().len() <= MAX_SEGMENT_LEN);

        let path = store
            .write_atomic(&lock, "proposals", &id, "json", br#"{"ok":true}"#)
            .expect("atomic write");
        assert!(path.starts_with(store.root()));
        assert_eq!(
            fs::read_to_string(&path).expect("read atomically written file"),
            r#"{"ok":true}"#
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            assert_eq!(
                fs::metadata(store.root())
                    .expect("root metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&path)
                    .expect("file metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert!(
            store.path_for("../escape", &id, "json").is_err(),
            "collection traversal is rejected"
        );
        assert!(
            StoreId::from_safe_segment("../escape").is_err(),
            "id traversal is rejected"
        );

        let clients_id = StoreId::from_safe_segment("clients").expect("clients id");
        let clients_path = store
            .write_root_atomic(&lock, &clients_id, "json", br#"{"schema_version":1}"#)
            .expect("root atomic write");
        assert_eq!(clients_path, store.root().join("clients.json"));
        assert_eq!(
            fs::read_to_string(&clients_path).expect("read clients file"),
            r#"{"schema_version":1}"#
        );
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&clients_path)
                .expect("clients metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn all_file_store_domains_compose_under_one_process_owner() {
        use crate::change_proposal::{
            ChangeProposalAuthorKind, ChangeProposalDraftRequest, ChangeProposalStatementDraft,
        };
        use crate::client_credentials::ClientCredentialIssueRequest;
        use crate::source_history::{SourceHistoryStore, SourceSnapshotDraft};
        use crate::write_intent::{WriteIntent, WriteIntentDetails, WriteIntentOutcome};
        use oraclemcp_guard::{ExecGrantBinding, OperatingLevel};

        let root = test_root("process-composition");
        let store = FileStore::open(&root).expect("service store");
        let owner = store.acquire_service_owner("serve").expect("service owner");
        assert!(
            matches!(
                FileStore::open(&root)
                    .expect("competing store")
                    .acquire_service_owner("second-process"),
                Err(FileStoreError::Locked)
            ),
            "an independent owner must remain excluded"
        );

        let write_intents = crate::write_intent::WriteIntentLog::open_with_owner(owner.clone())
            .expect("write intents share owner");
        let clients =
            crate::client_credentials::ClientCredentialStore::open_with_owner(owner.clone())
                .expect("client credentials share owner");
        let config = crate::config_ops::ConfigOpsBackend::open_with_owner(owner.clone())
            .expect("config ops share owner");
        let proposals = crate::change_proposal::ChangeProposalStore::open_with_owner(owner.clone())
            .expect("change proposals share owner");
        let history = SourceHistoryStore::open_with_owner(owner.clone())
            .expect("source history shares owner");

        clients
            .issue(ClientCredentialIssueRequest::new(
                "operator",
                vec!["oracle:read".to_owned()],
            ))
            .expect("credential mutation");

        let binding = ExecGrantBinding::new("session", "lane", "principal", 1);
        let intent = WriteIntent::new(WriteIntentDetails {
            idempotency_key_material: "grant",
            subject: "profile:dev",
            active_profile: Some("dev"),
            tool: "oracle_execute",
            sql: "UPDATE employees SET name = name WHERE employee_id = 1",
            required_level: OperatingLevel::ReadWrite,
            binding: &binding,
        });
        let intent_id = write_intents
            .append_pending(intent)
            .expect("write-intent mutation");
        write_intents
            .resolve(&intent_id, WriteIntentOutcome::RolledBack)
            .expect("write-intent resolution");

        let config_path = store.root().join("profiles.toml");
        let plan = config
            .stage_config_draft(&config_path, "")
            .expect("config draft");
        config.apply_config_draft(&plan).expect("config mutation");

        proposals
            .draft(
                ChangeProposalDraftRequest {
                    profile: "dev".to_owned(),
                    author: ChangeProposalAuthorKind::Agent,
                    title: Some("No-op update".to_owned()),
                    statements: vec![ChangeProposalStatementDraft {
                        sql_template: "UPDATE employees SET name = name WHERE employee_id = 1"
                            .to_owned(),
                        binds: Vec::new(),
                        unit: None,
                        commit: Some(false),
                        capture_dbms_output: None,
                        stored_verdict: None,
                    }],
                    stored_verdict: None,
                },
                "subject-sha256:test".to_owned(),
            )
            .expect("proposal mutation");

        history
            .record_snapshot(SourceSnapshotDraft {
                profile: "dev".to_owned(),
                owner: "app".to_owned(),
                owner_quoted: false,
                name: "p".to_owned(),
                name_quoted: false,
                object_type: "procedure".to_owned(),
                target_identity_sha256: crate::source_history::source_identity_sha256(
                    "APP",
                    "P",
                    "PROCEDURE",
                ),
                source_kind: "all_source".to_owned(),
                source: "CREATE OR REPLACE PROCEDURE p IS BEGIN NULL; END;".to_owned(),
                proposal_id: "cp-1".to_owned(),
                statement_id: "stmt-1".to_owned(),
                statement_sql_sha256: "sha256:stmt".to_owned(),
                lane_id: Some("operator".to_owned()),
                subject_id_hash: "subject-sha256:test".to_owned(),
            })
            .expect("source-history mutation");
    }

    #[test]
    fn owner_serializes_concurrent_file_store_instances_without_temp_collisions() {
        let root = test_root("shared-owner-concurrency");
        let store = FileStore::open(&root).expect("service store");
        let owner = store.acquire_service_owner("serve").expect("service owner");
        let id = StoreId::from_safe_segment("shared").expect("safe id");

        let threads: Vec<_> = (0..16)
            .map(|index| {
                let root = root.clone();
                let owner = owner.clone();
                let id = id.clone();
                thread::spawn(move || {
                    let store = FileStore::open(root).expect("thread store");
                    store
                        .write_atomic(
                            &owner,
                            "concurrent",
                            &id,
                            "json",
                            format!("{{\"writer\":{index}}}").as_bytes(),
                        )
                        .expect("serialized write")
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("writer thread");
        }

        let final_path = store
            .path_for("concurrent", &id, "json")
            .expect("final path");
        let final_bytes = fs::read(&final_path).expect("final bytes");
        serde_json::from_slice::<serde_json::Value>(&final_bytes).expect("whole JSON write");
        let leftovers = fs::read_dir(final_path.parent().expect("collection dir"))
            .expect("read collection")
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(leftovers, 0, "atomic writes must not strand temp files");
    }

    #[test]
    fn service_lock_subprocess_holder() {
        let Some(root) = std::env::var_os(LOCK_HELPER_ROOT_ENV) else {
            return;
        };
        let ready = std::env::var_os(LOCK_HELPER_READY_ENV).expect("helper ready path");
        let store = FileStore::open(root).expect("helper store");
        let _lock = store
            .acquire_service_owner("subprocess-holder")
            .expect("helper service lock");
        let ready = PathBuf::from(ready);
        fs::write(&ready, b"ready\n").expect("publish helper readiness");
        File::open(ready.parent().expect("ready parent"))
            .and_then(|dir| dir.sync_all())
            .expect("fsync helper readiness");
        loop {
            thread::sleep(Duration::from_secs(60));
        }
    }

    #[test]
    fn service_lock_recovers_after_holder_process_is_killed() {
        let root = test_root("crash-recovery");
        let contender = FileStore::open(&root).expect("contender store");

        // Ten crash/restart cycles exercise the exact workload at 10x the
        // original reproducer, not merely a clean-drop happy path.
        for round in 0..10 {
            let ready = root.with_extension(format!("ready-{round}"));
            let mut child = Command::new(std::env::current_exe().expect("test executable"))
                .arg("--exact")
                .arg("file_store::tests::service_lock_subprocess_holder")
                .arg("--nocapture")
                .env(LOCK_HELPER_ROOT_ENV, &root)
                .env(LOCK_HELPER_READY_ENV, &ready)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn service-lock holder");

            let deadline = Instant::now() + Duration::from_secs(10);
            while !ready.exists() && Instant::now() < deadline {
                if let Some(status) = child.try_wait().expect("poll helper") {
                    panic!("service-lock helper exited before readiness: {status}");
                }
                thread::sleep(Duration::from_millis(10));
            }
            if !ready.exists() {
                let _ = child.kill();
                let _ = child.wait();
                panic!("service-lock helper did not become ready");
            }

            let live_contender_was_excluded = matches!(
                contender.acquire_service_owner("live-contender"),
                Err(FileStoreError::Locked)
            );

            child
                .kill()
                .expect("forcibly terminate service-lock holder");
            child.wait().expect("reap service-lock holder");
            assert!(
                live_contender_was_excluded,
                "a second process must not acquire while the holder is live"
            );
            let recovered = contender
                .acquire_service_owner("post-crash-owner")
                .expect("process death must release the service lock immediately");
            drop(recovered);
        }
    }

    #[test]
    fn service_lock_initialization_failure_releases_os_lock() {
        let store = FileStore::open(test_root("partial-lock-init")).expect("store");
        let error = match store
            .acquire_service_owner_with_metadata("failing-owner", |_file, _owner| {
                Err(std::io::Error::other("injected metadata failure"))
            }) {
            Ok(_) => panic!("metadata initialization must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, FileStoreError::Io(_)));

        let recovered = store
            .acquire_service_owner("recovered-owner")
            .expect("partial initialization must not leave a permanent lock");
        drop(recovered);
    }

    #[test]
    fn old_lock_drop_does_not_unlink_replacement_lock() {
        let store = FileStore::open(test_root("replacement-identity")).expect("store");
        let old_lock = store.acquire_service_owner("old-owner").expect("old lock");
        let lock_path = store.root().join(SERVICE_LOCK_FILE);
        let displaced_path = store.root().join(".service.lock.displaced");
        fs::rename(&lock_path, &displaced_path).expect("displace old lock pathname");

        let replacement = store
            .acquire_service_owner("replacement-owner")
            .expect("replacement lock");
        drop(old_lock);

        assert!(
            lock_path.exists(),
            "dropping an old handle must not unlink a replacement pathname"
        );
        assert!(
            matches!(
                store.acquire_service_owner("third-owner"),
                Err(FileStoreError::Locked)
            ),
            "the replacement must continue excluding a third writer"
        );
        drop(replacement);
    }

    #[test]
    fn jsonl_recovery_repairs_torn_tail_and_rebuilds_index() {
        let store = FileStore::open(test_root("jsonl")).expect("store");
        let lock = store.acquire_service_owner("test").expect("lock");
        let id = StoreId::from_safe_segment("metrics").expect("id");
        let path = store.path_for("metrics", &id, "jsonl").expect("path");
        ensure_private_dir(path.parent().expect("parent")).expect("metrics dir");
        fs::write(&path, b"{\"seq\":1}\n{\"seq\":2}").expect("write torn jsonl fixture");

        let recovered = store
            .recover_jsonl(&lock, "metrics", &id)
            .expect("recover jsonl");
        assert_eq!(recovered.repaired_tail_bytes, 9);
        assert_eq!(recovered.index.records.len(), 1);
        assert_eq!(
            recovered.index.records[0],
            JsonlRecord { offset: 0, len: 10 }
        );
        assert_eq!(
            fs::read_to_string(&path).expect("read repaired jsonl"),
            "{\"seq\":1}\n"
        );
    }

    #[test]
    fn jsonl_append_fsyncs_complete_single_line_records() {
        let store = FileStore::open(test_root("append-jsonl")).expect("store");
        let lock = store.acquire_service_owner("test").expect("lock");
        let id = StoreId::from_safe_segment("intents").expect("id");

        let path = store
            .append_jsonl(&lock, "write-intents", &id, br#"{"seq":1}"#)
            .expect("append first record");
        store
            .append_jsonl(&lock, "write-intents", &id, br#"{"seq":2}"#)
            .expect("append second record");
        assert_eq!(
            fs::read_to_string(&path).expect("read jsonl"),
            "{\"seq\":1}\n{\"seq\":2}\n"
        );
        assert!(matches!(
            store.append_jsonl(&lock, "write-intents", &id, b"{\"seq\":3}\n"),
            Err(FileStoreError::InvalidJsonlRecord)
        ));
    }

    #[test]
    fn retention_prunes_metrics_but_never_audit() {
        let store = FileStore::open(test_root("retention")).expect("store");
        let lock = store.acquire_service_owner("test").expect("lock");
        for i in 0..3 {
            let id = StoreId::from_safe_segment(format!("snap-{i}")).expect("id");
            store
                .write_atomic(&lock, "metrics", &id, "json", format!("{i}\n").as_bytes())
                .expect("write metric snapshot");
            thread::sleep(Duration::from_millis(2));
        }

        let report = store
            .prune_collection(&lock, "metrics", 1, RetentionClass::Prunable)
            .expect("prune metrics");
        assert_eq!(report.removed, 2);
        assert_eq!(report.retained, 1);

        let audit_id = StoreId::from_safe_segment("audit").expect("id");
        store
            .write_atomic(&lock, "audit", &audit_id, "jsonl", b"{}\n")
            .expect("write audit fixture");
        assert!(
            matches!(
                store.prune_collection(&lock, "audit", 0, RetentionClass::Audit),
                Err(FileStoreError::AuditNotPrunable)
            ),
            "audit retention must fail closed"
        );
        assert!(
            store
                .path_for("audit", &audit_id, "jsonl")
                .expect("audit path")
                .exists(),
            "audit file remains after refused prune"
        );
    }
}
