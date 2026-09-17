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

use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _};
#[cfg(not(unix))]
use cap_std::ambient_authority;
#[cfg(not(unix))]
use cap_std::fs::Dir as CapDir;
use cap_std::fs::OpenOptions as CapOpenOptions;
#[cfg(unix)]
use cap_std::fs::OpenOptionsExt as _;
use serde::{Deserialize, Serialize};

use crate::hmac::ct_eq;
use crate::record::{AuditRecord, SigningKey};
use crate::sink::AuditError;
#[cfg(windows)]
use crate::sink::open_windows_audit_directory_nofollow;
#[cfg(unix)]
use crate::sink::{
    AuditDirectoryOpenError, authenticate_held_audit_directory, create_new_private_file_at,
    open_existing_audit_directory_nofollow,
};
use crate::verify::JsonlReader;

#[cfg(not(unix))]
use std::fs;

/// Current anchor document version.
pub const ANCHOR_VERSION: u16 = 1;

/// A head anchor contains only a fixed-size version, sequence, hashes, key id,
/// and MAC. Keeping its reader below this cap prevents a replaced sidecar from
/// turning audit startup or verification into an unbounded allocation.
const MAX_ANCHOR_BYTES: usize = 16 * 1024;

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
        // Unpredictable, same-directory temporary opened with O_CREAT|O_EXCL
        // (bead oraclemcp-qa100 .15): the previous fixed `<anchor>.tmp` with
        // truncate-on-open could be a pre-planted symlink that every durable
        // append repeatedly truncates, diverting the write to another
        // operator-writable file. An exclusive create on an unpredictable name
        // refuses a symlink and cannot be pre-planted; the same-directory
        // location keeps the final `rename` atomic.
        let io_err = |e: std::io::Error| AuditError::Io(e.to_string());
        #[cfg(unix)]
        {
            let parent_path = self
                .path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let name = self
                .path
                .file_name()
                .filter(|name| !name.is_empty())
                .ok_or_else(|| {
                    AuditError::Io(format!(
                        "anchor path {} has no file name",
                        self.path.display()
                    ))
                })?;
            let directory =
                open_existing_audit_directory_nofollow(parent_path).map_err(AuditError::from)?;
            run_anchor_parent_open_hook();
            let tmp = anchor_tmp_path(&self.path);
            let tmp_name = tmp
                .file_name()
                .filter(|name| !name.is_empty())
                .ok_or_else(|| {
                    AuditError::Io(format!(
                        "anchor temporary {} has no file name",
                        tmp.display()
                    ))
                })?;
            {
                let mut file = create_new_private_file_at(&directory, Path::new(tmp_name), &tmp)?;
                file.write_all(&body).map_err(io_err)?;
                // fsync the tmp content BEFORE the rename: a crash must never
                // surface a renamed-but-empty/partial anchor (that would look like
                // tampering instead of an explainable anchor-behind window).
                file.sync_all().map_err(io_err)?;
            }
            directory
                .rename(tmp_name, &directory, name)
                .map_err(io_err)?;
            authenticate_held_audit_directory(&directory, parent_path)
        }
        #[cfg(not(unix))]
        {
            #[cfg(windows)]
            let held_parent = {
                let parent_path = self
                    .path
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."));
                open_windows_audit_directory_nofollow(parent_path)?
            };
            let tmp = anchor_tmp_path(&self.path);
            let mut file = crate::sink::create_new_private_file(&tmp)?;
            file.write_all(&body).map_err(io_err)?;
            // fsync the tmp content BEFORE the rename: a crash must never
            // surface a renamed-but-empty/partial anchor (that would look like
            // tampering instead of an explainable anchor-behind window).
            file.sync_all().map_err(io_err)?;
            drop(file);
            fs::rename(&tmp, &self.path).map_err(io_err)?;
            #[cfg(windows)]
            held_parent.authenticate_current_path()?;
            Ok(())
        }
    }
}

#[cfg(all(test, unix))]
thread_local! {
    static ANCHOR_PARENT_OPEN_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, unix))]
fn set_anchor_parent_open_hook(hook: impl FnOnce() + 'static) {
    ANCHOR_PARENT_OPEN_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(all(test, unix))]
fn run_anchor_parent_open_hook() {
    ANCHOR_PARENT_OPEN_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(all(test, unix)))]
fn run_anchor_parent_open_hook() {}

/// Process-wide counter feeding [`anchor_tmp_path`] for collision-free,
/// unpredictable temporary names.
static ANCHOR_TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// An unpredictable, hidden, same-directory temporary path for the atomic anchor
/// replacement (bead oraclemcp-qa100 .15). Same directory as the anchor so the
/// final `rename` is atomic; pid + process-wide counter + nanoseconds make it
/// unpredictable so it cannot be pre-planted as a symlink target.
fn anchor_tmp_path(anchor_path: &Path) -> PathBuf {
    let parent = anchor_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let stem = anchor_path.file_name().map_or_else(
        || "audit.anchor".to_owned(),
        |name| name.to_string_lossy().into_owned(),
    );
    let seq = ANCHOR_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    parent.join(format!(".{stem}.tmp.{}.{seq}.{nanos}", std::process::id()))
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

/// Load the anchor sidecar at `path`. An absent sidecar beneath an extant
/// parent yields `Ok(None)` for legacy logs; any other read/parse failure
/// yields `Err`.
pub fn load_anchor(path: &Path) -> Result<Option<ChainAnchor>, AnchorLoadError> {
    load_anchor_inner(path, false)
}

/// Load an anchor while authenticating an already-open primary ledger.
///
/// A legacy anchor sidecar may be absent, but the sidecar's parent must still
/// exist and resolve safely. Otherwise an attacker could move or redirect that
/// parent after the primary file was opened and make a real head anchor look
/// like a legacy absence, suppressing tail-truncation protection.
pub fn load_anchor_for_open_audit_ledger(
    path: &Path,
) -> Result<Option<ChainAnchor>, AnchorLoadError> {
    load_anchor_inner(path, true)
}

fn load_anchor_inner(
    path: &Path,
    require_existing_parent: bool,
) -> Result<Option<ChainAnchor>, AnchorLoadError> {
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| AnchorLoadError {
            message: format!("{}: anchor path has no file name", path.display()),
        })?;
    #[cfg(unix)]
    let directory = match open_existing_audit_directory_nofollow(parent_path) {
        Ok(directory) => directory,
        Err(AuditDirectoryOpenError::Missing) if !require_existing_parent => return Ok(None),
        Err(AuditDirectoryOpenError::Missing) => {
            return Err(AnchorLoadError {
                message: format!(
                    "{}: anchor parent is missing while an audit ledger is already open",
                    path.display()
                ),
            });
        }
        Err(AuditDirectoryOpenError::Rejected(error)) => {
            return Err(AnchorLoadError {
                message: format!("{}: {error}", path.display()),
            });
        }
    };
    #[cfg(windows)]
    let held_parent = match std::fs::symlink_metadata(parent_path) {
        // Preserve the legacy absence contract only when the parent was
        // genuinely absent before the no-reparse walk. Once it exists, the
        // walk below remains authoritative and rejects a final or
        // intermediate reparse point rather than following it.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !require_existing_parent => {
            return Ok(None);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(AnchorLoadError {
                message: format!(
                    "{}: anchor parent is missing while an audit ledger is already open",
                    path.display()
                ),
            });
        }
        Err(error) => {
            return Err(AnchorLoadError {
                message: format!("{}: {error}", path.display()),
            });
        }
        Ok(_) => {
            open_windows_audit_directory_nofollow(parent_path).map_err(|error| AnchorLoadError {
                message: format!("{}: {error}", path.display()),
            })?
        }
    };
    #[cfg(not(unix))]
    let directory = match CapDir::open_ambient_dir(parent_path, ambient_authority()) {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !require_existing_parent => {
            return Ok(None);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(AnchorLoadError {
                message: format!(
                    "{}: anchor parent is missing while an audit ledger is already open",
                    path.display()
                ),
            });
        }
        Err(error) => {
            return Err(AnchorLoadError {
                message: format!("{}: {error}", path.display()),
            });
        }
    };
    let mut options = CapOpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    // Opening a FIFO for reading blocks until a writer appears. Take a
    // non-blocking descriptor first, then reject every non-regular object
    // below; the no-follow descriptor is also the object we actually read.
    #[cfg(unix)]
    options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
    let file = match directory.open_with(name, &options) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(AnchorLoadError {
                message: format!("{}: {error}", path.display()),
            });
        }
    };
    let metadata = file.metadata().map_err(|error| AnchorLoadError {
        message: format!("{}: {error}", path.display()),
    })?;
    if !metadata.file_type().is_file() {
        return Err(AnchorLoadError {
            message: format!("{}: anchor sidecar is not a regular file", path.display()),
        });
    }
    let limit = u64::try_from(MAX_ANCHOR_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(MAX_ANCHOR_BYTES.saturating_add(1));
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| AnchorLoadError {
            message: format!("{}: {error}", path.display()),
        })?;
    if bytes.len() > MAX_ANCHOR_BYTES {
        return Err(AnchorLoadError {
            message: format!(
                "{}: anchor sidecar exceeds the {MAX_ANCHOR_BYTES}-byte maximum",
                path.display()
            ),
        });
    }
    let body = String::from_utf8(bytes).map_err(|error| AnchorLoadError {
        message: format!("{}: {error}", path.display()),
    })?;
    let anchor: ChainAnchor = serde_json::from_str(body.trim()).map_err(|e| AnchorLoadError {
        message: format!("{}: {e}", path.display()),
    })?;
    #[cfg(unix)]
    authenticate_held_audit_directory(&directory, parent_path).map_err(|error| {
        AnchorLoadError {
            message: format!("{}: {error}", path.display()),
        }
    })?;
    #[cfg(windows)]
    held_parent
        .authenticate_current_path()
        .map_err(|error| AnchorLoadError {
            message: format!("{}: {error}", path.display()),
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

/// A streaming [`check_anchor`] failure: either an anchor cross-check violation
/// or an error reading/parsing the streamed chain (bead oraclemcp-qa100 .29).
#[derive(Debug)]
pub enum AnchorReaderError {
    /// The anchor cross-check failed — always fail-closed (see [`AnchorViolation`]).
    Violation(AnchorViolation),
    /// The streamed audit log could not be read or parsed to complete the
    /// cross-check.
    Read(String),
}

impl std::fmt::Display for AnchorReaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnchorReaderError::Violation(v) => v.fmt(f),
            AnchorReaderError::Read(m) => write!(f, "audit chain unreadable for anchor check: {m}"),
        }
    }
}

impl std::error::Error for AnchorReaderError {}

/// Cross-check a head anchor against an audit chain streamed from any
/// [`BufRead`] source, with **bounded memory** — the streaming equivalent of
/// [`check_anchor`] (bead oraclemcp-qa100 .29).
///
/// The caller must have already verified the chain (e.g. via
/// [`crate::verify_reader`]) so that `seq == index + 1` holds; this pass then
/// retains only the running record count and the `entry_hash` of the anchored
/// `seq`, never the whole chain. Semantics match [`check_anchor`] exactly: an
/// unknown key id or MAC mismatch on the anchor, a chain shorter than the
/// anchored head, or a hash mismatch at the anchored seq is a violation; a
/// longer chain that still passes through the anchored record is
/// [`AnchorStatus::Behind`].
pub fn check_anchor_reader<R: BufRead>(
    reader: R,
    anchor: &ChainAnchor,
    keys: &[SigningKey],
) -> Result<AnchorStatus, AnchorReaderError> {
    // Authenticate the anchor before trusting its plaintext seq/entry_hash — no
    // records needed, so this fails fast exactly as `check_anchor` does.
    let Some(key) = keys.iter().find(|k| k.key_id() == anchor.key_id) else {
        return Err(AnchorReaderError::Violation(AnchorViolation::UnknownKeyId(
            anchor.key_id.clone(),
        )));
    };
    if !anchor.mac_is_valid(key) {
        return Err(AnchorReaderError::Violation(AnchorViolation::MacMismatch));
    }

    let mut records = JsonlReader::new(reader);
    let mut chain_records = 0usize;
    let mut anchored_hash: Option<String> = None;
    loop {
        match records.next_record() {
            Ok(Some(record)) => {
                chain_records += 1;
                if record.seq == anchor.seq {
                    anchored_hash = Some(record.entry_hash.clone());
                }
            }
            Ok(None) => break,
            Err(e) => return Err(AnchorReaderError::Read(e.to_string())),
        }
    }

    if (chain_records as u64) < anchor.seq {
        return Err(AnchorReaderError::Violation(AnchorViolation::Truncated {
            anchor_seq: anchor.seq,
            chain_records,
        }));
    }
    match anchored_hash {
        Some(hash) if hash == anchor.entry_hash => {
            let behind_by = (chain_records as u64) - anchor.seq;
            if behind_by == 0 {
                Ok(AnchorStatus::Match)
            } else {
                Ok(AnchorStatus::Behind { behind_by })
            }
        }
        _ => Err(AnchorReaderError::Violation(
            AnchorViolation::HeadHashMismatch {
                anchor_seq: anchor.seq,
            },
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{AuditDecision, AuditEntryDraft, AuditOutcome, AuditRecord, AuditSubject};

    fn key() -> SigningKey {
        SigningKey::new("k1", b"0123456789abcdef0123456789abcdef".to_vec()).expect("valid test key")
    }

    fn draft(sql: &str) -> AuditEntryDraft {
        AuditEntryDraft {
            subject: AuditSubject::new("agent", "agent"),
            db_evidence: None,
            cancel: None,
            result_masking: None,
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
        let other = SigningKey::new("k2", b"fedcba9876543210fedcba9876543210".to_vec())
            .expect("valid test key");
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

    #[cfg(unix)]
    #[test]
    fn anchor_file_is_private_0600_and_strands_no_fixed_temp() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let anchor_path = dir.path().join("audit.jsonl.anchor");
        let writer = AnchorFile::new(&anchor_path, key());
        writer.record_head(1, "sha256:h1").expect("first anchor");
        writer.record_head(2, "sha256:h2").expect("second anchor");
        let mode = std::fs::metadata(&anchor_path)
            .expect("anchor metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "anchor sidecar is owner-only");
        // The old fixed `<anchor>.tmp` is gone, and no unpredictable temp is left
        // stranded after a successful rename.
        let strays = std::fs::read_dir(dir.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp."))
            .count();
        assert_eq!(strays, 0, "no temporary anchor files remain");
    }

    #[test]
    fn anchor_tmp_path_is_hidden_unique_and_same_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let anchor = dir.path().join("head.anchor.json");
        let first = anchor_tmp_path(&anchor);
        let second = anchor_tmp_path(&anchor);

        assert_eq!(
            first.parent(),
            Some(dir.path()),
            "atomic anchor temp file must stay beside the anchor"
        );
        assert_ne!(first, second, "temp anchor names include a process counter");
        let filename = first
            .file_name()
            .and_then(|name| name.to_str())
            .expect("utf-8 temp filename");
        assert!(
            filename.starts_with(".head.anchor.json.tmp."),
            "temp anchor filename should be hidden and stem-derived: {filename}"
        );
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
    fn legacy_anchor_lookup_treats_a_genuinely_absent_parent_as_no_sidecar() {
        // The compatibility reader remains useful for callers that have not
        // opened a primary ledger. The stricter startup path is separate so a
        // parent removed after a primary open cannot exploit this legacy case.
        let dir = tempfile::tempdir().expect("tempdir");
        let anchor_path = dir
            .path()
            .join("parent-never-created")
            .join("audit.jsonl.anchor");
        assert_eq!(load_anchor(&anchor_path), Ok(None));
    }

    #[cfg(windows)]
    #[test]
    fn windows_legacy_anchor_lookup_treats_a_genuinely_absent_parent_as_no_sidecar() {
        let dir = tempfile::tempdir().expect("tempdir");
        let anchor_path = dir
            .path()
            .join("parent-never-created-on-windows")
            .join("audit.jsonl.anchor");

        assert_eq!(load_anchor(&anchor_path), Ok(None));
    }

    #[cfg(windows)]
    #[test]
    fn load_anchor_refuses_an_intermediate_reparse_parent() {
        use std::os::windows::fs::symlink_dir;

        // The final parent is an ordinary directory. Only its *intermediate*
        // predecessor is a reparse point, so a one-shot final-component open
        // would follow it and return the legacy absent-sidecar result.
        let root = tempfile::tempdir().expect("tempdir");
        let real_root = root.path().join("real-root");
        let real_parent = real_root.join("anchor-parent");
        let redirected_root = root.path().join("redirected-root");
        std::fs::create_dir(&real_root).expect("create real root");
        std::fs::create_dir(&real_parent).expect("create ordinary final parent");
        match symlink_dir(&real_root, &redirected_root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!(
                    "SKIP load_anchor_refuses_an_intermediate_reparse_parent: this Windows runner cannot create directory reparse-point fixtures"
                );
                return;
            }
            Err(error) => panic!("create intermediate directory reparse point: {error}"),
        }

        let configured = redirected_root
            .join("anchor-parent")
            .join("audit.jsonl.anchor");
        let error = load_anchor(&configured).expect_err(
            "an intermediate reparse point must not be followed while reading an anchor",
        );
        assert!(
            error.to_string().contains("reparse point"),
            "unexpected error: {error}"
        );
        assert_eq!(
            load_anchor(&real_parent.join("audit.jsonl.anchor")),
            Ok(None),
            "the fixture must leave the real final parent otherwise ordinary"
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

    #[cfg(unix)]
    #[test]
    fn load_anchor_refuses_a_symlink_without_reading_its_target() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("operator-controlled-anchor-target");
        let target_bytes = b"operator-controlled bytes";
        std::fs::write(&target, target_bytes).expect("seed anchor target");
        let anchor = dir.path().join("audit.jsonl.anchor");
        symlink(&target, &anchor).expect("plant anchor symlink");

        let error = load_anchor(&anchor).expect_err("symlinked anchor must fail closed");
        assert!(error.to_string().contains("audit head anchor unreadable"));
        assert_eq!(
            std::fs::read(&target).expect("read target"),
            target_bytes,
            "loading an anchor must not follow or alter its symlink target"
        );
    }

    #[cfg(unix)]
    #[test]
    fn anchor_reader_and_writer_refuse_a_symlinked_parent_without_touching_its_target() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("tempdir");
        let real_parent = root.path().join("real-parent");
        let configured_parent = root.path().join("configured-parent");
        std::fs::create_dir(&real_parent).expect("create real parent");
        symlink(&real_parent, &configured_parent).expect("plant parent symlink");
        let target = real_parent.join("audit.jsonl.anchor");
        AnchorFile::new(&target, key())
            .record_head(1, "sha256:target-head")
            .expect("write direct target anchor");
        let before = std::fs::read(&target).expect("read target before linked attempt");
        let configured = configured_parent.join("audit.jsonl.anchor");

        assert!(
            load_anchor(&configured).is_err(),
            "a configured parent symlink must never be followed while reading an anchor"
        );
        assert!(
            AnchorFile::new(&configured, key())
                .record_head(2, "sha256:redirected-head")
                .is_err(),
            "a configured parent symlink must never receive an anchor write"
        );
        assert_eq!(
            std::fs::read(&target).expect("read target after linked attempt"),
            before,
            "the symlink target must not be read as configured evidence or modified"
        );
    }

    #[cfg(unix)]
    #[test]
    fn anchor_writer_refuses_a_parent_replacement_after_its_capability_is_opened() {
        let root = tempfile::tempdir().expect("tempdir");
        let configured_parent = root.path().join("configured-parent");
        let parked_parent = root.path().join("parked-parent");
        std::fs::create_dir(&configured_parent).expect("create configured parent");
        let anchor = configured_parent.join("audit.jsonl.anchor");
        let moved_parent = configured_parent.clone();
        let moved_parked = parked_parent.clone();
        set_anchor_parent_open_hook(move || {
            std::fs::rename(&moved_parent, &moved_parked).expect("park held parent");
            std::fs::create_dir(&moved_parent).expect("create replacement parent");
        });

        let error = AnchorFile::new(&anchor, key())
            .record_head(1, "sha256:head")
            .expect_err("a replaced configured parent must fail closed");
        assert!(error.to_string().contains("changed identity"), "{error}");
        assert!(
            !anchor.exists(),
            "the replacement configured parent must not receive the anchor"
        );
        assert!(
            parked_parent.join("audit.jsonl.anchor").exists(),
            "the held capability may have written only to the parked original parent"
        );
    }

    #[test]
    fn load_anchor_refuses_an_oversized_sidecar_before_parsing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let anchor = dir.path().join("audit.jsonl.anchor");
        std::fs::write(&anchor, vec![b'x'; MAX_ANCHOR_BYTES + 1]).expect("seed oversized anchor");

        let error = load_anchor(&anchor).expect_err("oversized anchor must fail closed");
        assert!(
            error
                .to_string()
                .contains(&format!("{MAX_ANCHOR_BYTES}-byte maximum")),
            "unexpected error: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_anchor_rejects_a_fifo_without_waiting_for_a_writer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let anchor = dir.path().join("audit.jsonl.anchor");
        let made = std::process::Command::new("mkfifo")
            .arg(&anchor)
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if !made {
            return;
        }

        let (result_tx, result_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = result_tx.send(load_anchor(&anchor));
        });
        let result = result_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("FIFO anchor must be rejected without blocking for a writer");
        assert!(result.is_err(), "FIFO anchor must fail closed");
    }

    #[test]
    fn check_anchor_reader_matches_check_anchor_across_statuses() {
        // The streaming cross-check (bead oraclemcp-qa100 .29) reproduces
        // check_anchor exactly with bounded memory.
        let body_of = |records: &[AuditRecord]| -> String {
            records
                .iter()
                .map(|r| serde_json::to_string(r).expect("serialize") + "\n")
                .collect()
        };
        let stream = |records: &[AuditRecord], anchor: &ChainAnchor, keys: &[SigningKey]| {
            check_anchor_reader(std::io::Cursor::new(body_of(records)), anchor, keys)
        };

        // Match.
        let records = signed_chain(3);
        let anchor = anchor_at(&records, 3);
        assert_eq!(
            stream(&records, &anchor, &[key()]).unwrap(),
            AnchorStatus::Match
        );

        // Behind: anchor names seq 2 while the chain runs to 3.
        let behind = anchor_at(&records, 2);
        assert_eq!(
            stream(&records, &behind, &[key()]).unwrap(),
            AnchorStatus::Behind { behind_by: 1 }
        );

        // Truncated: anchor attests seq 3 but only two records survive.
        let anchor3 = anchor_at(&records, 3);
        match stream(&records[..2], &anchor3, &[key()]) {
            Err(AnchorReaderError::Violation(AnchorViolation::Truncated {
                anchor_seq,
                chain_records,
            })) => assert_eq!((anchor_seq, chain_records), (3, 2)),
            other => panic!("expected truncation, got {other:?}"),
        }

        // Head-hash mismatch at the anchored seq.
        let diverged = ChainAnchor::signed(2, "sha256:not-the-real-head", &key());
        match stream(&records, &diverged, &[key()]) {
            Err(AnchorReaderError::Violation(AnchorViolation::HeadHashMismatch { anchor_seq })) => {
                assert_eq!(anchor_seq, 2);
            }
            other => panic!("expected head-hash mismatch, got {other:?}"),
        }

        // Unknown key id — refused before any record is read.
        let other_key = SigningKey::new("k2", vec![0x5a; 32]).expect("k2");
        let foreign = ChainAnchor::signed(3, &records[2].entry_hash, &other_key);
        match stream(&records, &foreign, &[key()]) {
            Err(AnchorReaderError::Violation(AnchorViolation::UnknownKeyId(id))) => {
                assert_eq!(id, "k2");
            }
            other => panic!("expected unknown key id, got {other:?}"),
        }

        // MAC mismatch — forged sidecar without the key.
        let mut forged = anchor_at(&records, 3);
        forged.mac = "hmac-sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_owned();
        match stream(&records, &forged, &[key()]) {
            Err(AnchorReaderError::Violation(AnchorViolation::MacMismatch)) => {}
            other => panic!("expected MAC mismatch, got {other:?}"),
        }
    }

    #[test]
    fn anchor_reader_error_display_names_read_and_violation_modes() {
        let read = AnchorReaderError::Read("bad json at byte 7".to_owned()).to_string();
        assert!(
            read.contains("audit chain unreadable for anchor check"),
            "{read}"
        );
        assert!(read.contains("bad json at byte 7"), "{read}");

        let violation =
            AnchorReaderError::Violation(AnchorViolation::UnknownKeyId("missing".to_owned()))
                .to_string();
        assert!(violation.contains("unknown key_id"), "{violation}");
        assert!(violation.contains("missing"), "{violation}");
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
