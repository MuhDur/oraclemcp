//! Shared file-store primitives for service-owned state.
//!
//! This is deliberately files-first and SQLite-free. Mutations require a
//! process-wide service lock token, then use write-temp/fsync/rename/fsync-dir so
//! callers can build durable config, metrics, proposal, and idempotency stores
//! without inventing their own path handling.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use parking_lot::Mutex;
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
    /// A mutation was attempted without the lock token for this store root.
    #[error("file-store mutation requires the matching service lock")]
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

/// Token proving this process holds the single-writer service lock.
pub struct ServiceLock {
    root: PathBuf,
    path: PathBuf,
    _file: File,
}

impl ServiceLock {
    fn assert_for(&self, store: &FileStore) -> Result<()> {
        if self.root == store.root {
            Ok(())
        } else {
            Err(FileStoreError::LockRequired)
        }
    }
}

impl Drop for ServiceLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        if let Some(parent) = self.path.parent() {
            let _ = fsync_dir(parent);
        }
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
    mutation_gate: Mutex<()>,
    tmp_counter: AtomicU64,
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
        Ok(Self {
            root,
            mutation_gate: Mutex::new(()),
            tmp_counter: AtomicU64::new(0),
        })
    }

    /// The canonical store root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Acquire the mandatory single-writer service lock for this store.
    pub fn acquire_service_lock(&self, owner: &str) -> Result<ServiceLock> {
        let path = self.root.join(SERVICE_LOCK_FILE);
        let mut file = create_new_private_file(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => FileStoreError::Locked,
            _ => FileStoreError::Io(e.to_string()),
        })?;
        writeln!(file, "pid={}", std::process::id())
            .and_then(|()| writeln!(file, "owner={owner}"))
            .map_err(|e| FileStoreError::Io(e.to_string()))?;
        file.sync_all()
            .map_err(|e| FileStoreError::Io(e.to_string()))?;
        fsync_dir(&self.root)?;
        Ok(ServiceLock {
            root: self.root.clone(),
            path,
            _file: file,
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
        lock: &ServiceLock,
        collection: &str,
        id: &StoreId,
        extension: &str,
        bytes: &[u8],
    ) -> Result<PathBuf> {
        lock.assert_for(self)?;
        let _guard = self.mutation_gate.lock();
        let dir = self.collection_dir(collection)?;
        let final_path = self.path_for(collection, id, extension)?;
        let tmp_path = self.tmp_path(&dir, id, extension);

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
        lock: &ServiceLock,
        id: &StoreId,
        extension: &str,
        bytes: &[u8],
    ) -> Result<PathBuf> {
        lock.assert_for(self)?;
        let _guard = self.mutation_gate.lock();
        let final_path = self.root_path_for(id, extension)?;
        let tmp_path = self.tmp_path(&self.root, id, extension);

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
        lock: &ServiceLock,
        collection: &str,
        id: &StoreId,
    ) -> Result<RecoveryReport> {
        lock.assert_for(self)?;
        let _guard = self.mutation_gate.lock();
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
        lock: &ServiceLock,
        collection: &str,
        id: &StoreId,
        record: &[u8],
    ) -> Result<PathBuf> {
        lock.assert_for(self)?;
        if record.iter().any(|b| *b == b'\n' || *b == b'\r') {
            return Err(FileStoreError::InvalidJsonlRecord);
        }
        let _guard = self.mutation_gate.lock();
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
        lock: &ServiceLock,
        collection: &str,
        keep_latest: usize,
        class: RetentionClass,
    ) -> Result<PruneReport> {
        lock.assert_for(self)?;
        if class == RetentionClass::Audit {
            return Err(FileStoreError::AuditNotPrunable);
        }
        let _guard = self.mutation_gate.lock();
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

    fn tmp_path(&self, dir: &Path, id: &StoreId, extension: &str) -> PathBuf {
        let counter = self.tmp_counter.fetch_add(1, Ordering::Relaxed);
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
    use std::thread;
    use std::time::{Duration, UNIX_EPOCH};

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
        let lock = store.acquire_service_lock("test").expect("lock");
        assert!(
            store.acquire_service_lock("other").is_err(),
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
    fn jsonl_recovery_repairs_torn_tail_and_rebuilds_index() {
        let store = FileStore::open(test_root("jsonl")).expect("store");
        let lock = store.acquire_service_lock("test").expect("lock");
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
        let lock = store.acquire_service_lock("test").expect("lock");
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
        let lock = store.acquire_service_lock("test").expect("lock");
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
