//! Durable write-ahead idempotency intents for permanent database effects.
//!
//! This layer is intentionally smaller than the audit chain: it records only
//! non-secret idempotency and routing facts needed to fail closed after a crash.
//! The sequence is append `pending` + fsync before the database call, append a
//! terminal `resolved` record only after a safe terminal outcome, and rebuild the
//! unresolved set plus terminal idempotency index on restart.
//!
//! Growth is bounded on two axes. The in-memory `resolved` idempotency index is
//! capped ([`DEFAULT_MAX_RESOLVED_INTENTS`]) and evicts oldest-first, so resident
//! memory stays bounded regardless of write volume; unresolved intents are never
//! evicted. On disk, the log is compacted crash-safely at open (unresolved plus
//! the retained resolved window, written to a temp file, fsynced, atomically
//! renamed, dir fsynced) when it has grown well past its compact size.
//!
//! FOLLOW-UP (not implemented here): periodic/runtime compaction within a single
//! very-long-lived process is deliberately out of scope. Compaction only runs at
//! open, so a process that never restarts still grows its on-disk log unbounded
//! between restarts. A runtime trigger would need to hold the state lock across a
//! full-log rewrite (blocking appends) and was judged too risky for this change;
//! the fail-safe open-time compaction plus the hard in-memory cap were preferred.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use oraclemcp_guard::{ExecGrantBinding, OperatingLevel};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::file_store::{FileStore, FileStoreError, ServiceOwner, StoreId};

const WRITE_INTENT_COLLECTION: &str = "write-intents";
const WRITE_INTENT_ID: &str = "intents";
const WRITE_INTENT_SCHEMA_VERSION: u16 = 1;

/// Default cap on the in-memory resolved-intent idempotency index.
///
/// The `resolved` map exists only to reject same-grant/same-SQL replays within a
/// realistic retry lifetime; it is not a permanent history (the audit chain is
/// the permanent action history). Idempotency ids derive from single-use,
/// process-local grant material, and grants must be regenerated after restart,
/// so an unbounded window is never required for safety. Once this cap is
/// exceeded the oldest resolved entries are evicted; an evicted replay is simply
/// re-admitted as a fresh intent, which is safe because its grant material is
/// already spent. Unresolved intents are never subject to this cap — they must
/// survive forever so restart fails closed until an operator verifies them.
const DEFAULT_MAX_RESOLVED_INTENTS: usize = 8192;

/// Minimum on-disk record count before startup compaction is even considered.
/// Small ledgers are left untouched so ordinary operation never rewrites the log.
const COMPACTION_MIN_RECORDS: usize = 512;

/// Durable write-intent errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WriteIntentError {
    /// The underlying file store failed.
    #[error("write-intent store error: {0}")]
    Store(#[from] FileStoreError),
    /// Serialization failed before an append could be issued.
    #[error("write-intent serialization error: {0}")]
    Serialization(String),
    /// An existing JSONL record could not be parsed during recovery.
    #[error("write-intent parse error at line {line}: {message}")]
    Parse { line: usize, message: String },
    /// A pending intent with the same id is already unresolved.
    #[error("write intent is already unresolved: {0}")]
    Duplicate(String),
    /// A terminal outcome already exists for the same idempotency key and SQL.
    #[error("write intent is already resolved: {intent_id} ({outcome:?})")]
    AlreadyResolved {
        /// Stable intent id derived from the idempotency key material.
        intent_id: String,
        /// Previously recorded terminal outcome.
        outcome: WriteIntentOutcome,
    },
    /// The same idempotency key material was reused for different SQL.
    #[error("write intent idempotency key conflict: {intent_id}")]
    IdempotencyConflict {
        /// Stable intent id derived from the idempotency key material.
        intent_id: String,
    },
    /// A terminal outcome was requested for an unknown intent id.
    #[error("unknown write intent: {0}")]
    Unknown(String),
}

/// A terminal write-intent outcome that makes retry safe from the ledger's
/// perspective. In-doubt outcomes are deliberately not represented here; they
/// remain unresolved so restart fails closed until an operator verifies them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum WriteIntentOutcome {
    /// The permanent database action completed successfully, either through a
    /// commit or through a non-transactional effect such as sequence `NEXTVAL`.
    Succeeded,
    /// The action was rolled back or never committed.
    RolledBack,
    /// The action failed before a commit could be attempted.
    Failed,
    /// A pre-execute guard/audit step failed after the intent was written.
    AbortedBeforeExecute,
}

/// The durable pending fact for a committing or non-transactional tool.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WriteIntent {
    /// Stable path-safe id derived from the non-serialized idempotency key
    /// material.
    pub intent_id: String,
    /// SHA-256 digest of the idempotency key material; raw grant ids are never
    /// written.
    pub idempotency_key: String,
    /// Server-controlled subject identity.
    pub subject: String,
    /// Active profile, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_profile: Option<String>,
    /// Tool whose permanent-effect boundary this intent protects.
    pub tool: String,
    /// Streamable HTTP session id or process fallback.
    pub session_id: String,
    /// Server-assigned lane id.
    pub lane: String,
    /// Server-derived principal/subject key.
    pub principal: String,
    /// Lane/profile/level generation captured when the grant was consumed.
    pub lane_generation: u64,
    /// Guard-required operating level as a stable string.
    pub required_level: String,
    /// SHA-256 digest of the exact SQL bytes sent to the database.
    pub sql_sha256: String,
    /// Display timestamp. The append order is the authoritative recovery order.
    pub ts: String,
}

/// Constructor arguments for [`WriteIntent`].
pub struct WriteIntentDetails<'a> {
    /// Opaque idempotency material, normally the consumed execution-grant id.
    pub idempotency_key_material: &'a str,
    /// Server-controlled subject identity.
    pub subject: &'a str,
    /// Active profile, if any.
    pub active_profile: Option<&'a str>,
    /// Tool whose permanent-effect boundary this intent protects.
    pub tool: &'a str,
    /// Exact SQL bytes sent to the database.
    pub sql: &'a str,
    /// Required operating level.
    pub required_level: OperatingLevel,
    /// Lane/session/principal binding that authorized the write.
    pub binding: &'a ExecGrantBinding,
}

impl WriteIntent {
    /// Build a pending write intent from non-secret routing facts. The raw
    /// idempotency material is hashed before serialization.
    #[must_use]
    pub fn new(details: WriteIntentDetails<'_>) -> Self {
        let idempotency_key =
            oraclemcp_audit::sha256_hex(details.idempotency_key_material.as_bytes());
        let digest = idempotency_key
            .strip_prefix("sha256:")
            .unwrap_or(&idempotency_key);
        let intent_id = format!("intent-{}", digest.get(..40).unwrap_or(digest));
        Self {
            intent_id,
            idempotency_key,
            subject: details.subject.to_owned(),
            active_profile: details.active_profile.map(str::to_owned),
            tool: details.tool.to_owned(),
            session_id: details.binding.session_id.clone(),
            lane: details.binding.lane_id.clone(),
            principal: details.binding.subject_id.clone(),
            lane_generation: details.binding.generation,
            required_level: details.required_level.as_str().to_owned(),
            sql_sha256: oraclemcp_audit::sha256_hex(details.sql.as_bytes()),
            ts: unix_timestamp(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WriteIntentEvent {
    Pending,
    Resolved,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct WriteIntentRecord {
    schema_version: u16,
    event: WriteIntentEvent,
    intent_id: String,
    idempotency_key: String,
    subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_profile: Option<String>,
    tool: String,
    session_id: String,
    lane: String,
    principal: String,
    lane_generation: u64,
    required_level: String,
    sql_sha256: String,
    ts: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    outcome: Option<WriteIntentOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resolved_ts: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ResolvedWriteIntent {
    intent: WriteIntent,
    outcome: WriteIntentOutcome,
}

#[derive(Debug)]
struct WriteIntentState {
    /// Unresolved intents. Never evicted: these are the crash-safety poison that
    /// forces fail-closed restart until an operator verifies them.
    unresolved: HashMap<String, WriteIntent>,
    /// Bounded terminal idempotency index. Capped at `max_resolved`; the oldest
    /// entries are evicted first so resident memory stays bounded.
    resolved: HashMap<String, ResolvedWriteIntent>,
    /// Insertion order of `resolved` intent ids (oldest at the front) used to
    /// pick eviction victims. Stays 1:1 with `resolved`.
    resolved_order: VecDeque<String>,
    /// Maximum retained resolved entries.
    max_resolved: usize,
}

impl Default for WriteIntentState {
    fn default() -> Self {
        Self::with_max_resolved(DEFAULT_MAX_RESOLVED_INTENTS)
    }
}

impl WriteIntentState {
    fn with_max_resolved(max_resolved: usize) -> Self {
        Self {
            unresolved: HashMap::new(),
            resolved: HashMap::new(),
            resolved_order: VecDeque::new(),
            // A zero cap would evict everything and defeat idempotency; keep at
            // least one entry so the most recent resolution is always testable.
            max_resolved: max_resolved.max(1),
        }
    }

    fn ensure_appendable(&self, intent: &WriteIntent) -> Result<(), WriteIntentError> {
        if self.unresolved.contains_key(&intent.intent_id) {
            return Err(WriteIntentError::Duplicate(intent.intent_id.clone()));
        }
        if let Some(previous) = self.resolved.get(&intent.intent_id) {
            if previous.intent.sql_sha256 == intent.sql_sha256 {
                return Err(WriteIntentError::AlreadyResolved {
                    intent_id: intent.intent_id.clone(),
                    outcome: previous.outcome,
                });
            }
            return Err(WriteIntentError::IdempotencyConflict {
                intent_id: intent.intent_id.clone(),
            });
        }
        Ok(())
    }

    /// Record a terminal resolution and evict the oldest resolved entries beyond
    /// the retention cap. This only ever touches the bounded `resolved` index;
    /// `unresolved` intents are never dropped here.
    fn record_resolved(&mut self, intent_id: String, entry: ResolvedWriteIntent) {
        if self.resolved.insert(intent_id.clone(), entry).is_none() {
            self.resolved_order.push_back(intent_id);
        }
        while self.resolved.len() > self.max_resolved {
            match self.resolved_order.pop_front() {
                Some(oldest) => {
                    self.resolved.remove(&oldest);
                }
                None => break,
            }
        }
    }
}

impl WriteIntentRecord {
    fn pending(intent: &WriteIntent) -> Self {
        Self::from_intent(intent, WriteIntentEvent::Pending, None)
    }

    fn resolved(intent: &WriteIntent, outcome: WriteIntentOutcome) -> Self {
        let mut record = Self::from_intent(intent, WriteIntentEvent::Resolved, Some(outcome));
        record.resolved_ts = Some(unix_timestamp());
        record
    }

    fn into_intent(self) -> WriteIntent {
        WriteIntent {
            intent_id: self.intent_id,
            idempotency_key: self.idempotency_key,
            subject: self.subject,
            active_profile: self.active_profile,
            tool: self.tool,
            session_id: self.session_id,
            lane: self.lane,
            principal: self.principal,
            lane_generation: self.lane_generation,
            required_level: self.required_level,
            sql_sha256: self.sql_sha256,
            ts: self.ts,
        }
    }

    fn from_intent(
        intent: &WriteIntent,
        event: WriteIntentEvent,
        outcome: Option<WriteIntentOutcome>,
    ) -> Self {
        Self {
            schema_version: WRITE_INTENT_SCHEMA_VERSION,
            event,
            intent_id: intent.intent_id.clone(),
            idempotency_key: intent.idempotency_key.clone(),
            subject: intent.subject.clone(),
            active_profile: intent.active_profile.clone(),
            tool: intent.tool.clone(),
            session_id: intent.session_id.clone(),
            lane: intent.lane.clone(),
            principal: intent.principal.clone(),
            lane_generation: intent.lane_generation,
            required_level: intent.required_level.clone(),
            sql_sha256: intent.sql_sha256.clone(),
            ts: intent.ts.clone(),
            outcome,
            resolved_ts: None,
        }
    }
}

/// Append-only durable write-intent ledger.
pub struct WriteIntentLog {
    store: FileStore,
    owner: ServiceOwner,
    id: StoreId,
    state: Mutex<WriteIntentState>,
}

impl WriteIntentLog {
    /// Open the default service-owned write-intent log.
    pub fn open_default() -> Result<Self, WriteIntentError> {
        Self::open(FileStore::default_state_dir()?)
    }

    /// Open a write-intent log rooted at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, WriteIntentError> {
        let store = FileStore::open(root)?;
        let owner = store.acquire_service_owner("write-intents")?;
        Self::open_with_store_owner(store, owner)
    }

    /// Open the write-intent log under an existing process-wide service owner.
    pub fn open_with_owner(owner: ServiceOwner) -> Result<Self, WriteIntentError> {
        let store = FileStore::open(owner.root())?;
        Self::open_with_store_owner(store, owner)
    }

    fn open_with_store_owner(
        store: FileStore,
        owner: ServiceOwner,
    ) -> Result<Self, WriteIntentError> {
        Self::open_with_store_owner_capped(store, owner, DEFAULT_MAX_RESOLVED_INTENTS)
    }

    fn open_with_store_owner_capped(
        store: FileStore,
        owner: ServiceOwner,
        max_resolved: usize,
    ) -> Result<Self, WriteIntentError> {
        let id = StoreId::from_safe_segment(WRITE_INTENT_ID)?;
        // `recover_jsonl` truncates any torn tail (crash-safe) and returns a byte
        // index we do not need. `rebuild_state` then makes a single pass over the
        // repaired file to reconstruct the unresolved set plus the bounded
        // resolved index.
        store.recover_jsonl(&owner, WRITE_INTENT_COLLECTION, &id)?;
        let path = store.path_for(WRITE_INTENT_COLLECTION, &id, "jsonl")?;
        let (state, stats) = rebuild_state(&path, max_resolved)?;
        let log = Self {
            store,
            owner,
            id,
            state: Mutex::new(state),
        };
        // Bound on-disk growth across restarts. Best-effort and fail-safe: a
        // compaction problem never blocks startup and never corrupts the live log
        // (the new image is proven to rebuild before any atomic swap).
        log.compact_on_open_if_beneficial(stats.records_read);
        Ok(log)
    }

    /// Open with an explicit resolved-index cap. Test-only so bounded eviction and
    /// compaction can be exercised deterministically with small ledgers.
    #[cfg(test)]
    fn open_capped(root: impl AsRef<Path>, max_resolved: usize) -> Result<Self, WriteIntentError> {
        let store = FileStore::open(root)?;
        let owner = store.acquire_service_owner("write-intents")?;
        Self::open_with_store_owner_capped(store, owner, max_resolved)
    }

    /// The canonical path of the intent JSONL file.
    pub fn path(&self) -> Result<PathBuf, WriteIntentError> {
        Ok(self
            .store
            .path_for(WRITE_INTENT_COLLECTION, &self.id, "jsonl")?)
    }

    /// Return a snapshot of unresolved intents recovered or appended so far.
    pub fn unresolved(&self) -> Result<Vec<WriteIntent>, WriteIntentError> {
        let guard = self.state.lock();
        Ok(guard.unresolved.values().cloned().collect())
    }

    /// Append a pending intent and fsync before returning.
    pub fn append_pending(&self, intent: WriteIntent) -> Result<String, WriteIntentError> {
        let mut guard = self.state.lock();
        guard.ensure_appendable(&intent)?;
        let record = WriteIntentRecord::pending(&intent);
        self.append_record(&record)?;
        let intent_id = intent.intent_id.clone();
        guard.unresolved.insert(intent_id.clone(), intent);
        Ok(intent_id)
    }

    /// Append a terminal resolved outcome and remove the intent from the
    /// unresolved set. Do not call this for in-doubt outcomes.
    pub fn resolve(
        &self,
        intent_id: &str,
        outcome: WriteIntentOutcome,
    ) -> Result<(), WriteIntentError> {
        let mut guard = self.state.lock();
        let intent = guard
            .unresolved
            .get(intent_id)
            .cloned()
            .ok_or_else(|| WriteIntentError::Unknown(intent_id.to_owned()))?;
        let record = WriteIntentRecord::resolved(&intent, outcome);
        self.append_record(&record)?;
        guard.unresolved.remove(intent_id);
        guard.record_resolved(
            intent_id.to_owned(),
            ResolvedWriteIntent { intent, outcome },
        );
        Ok(())
    }

    fn append_record(&self, record: &WriteIntentRecord) -> Result<(), WriteIntentError> {
        let bytes = serde_json::to_vec(record)
            .map_err(|e| WriteIntentError::Serialization(e.to_string()))?;
        self.store
            .append_jsonl(&self.owner, WRITE_INTENT_COLLECTION, &self.id, &bytes)?;
        Ok(())
    }

    /// Rewrite the on-disk ledger down to every unresolved record plus the
    /// bounded window of retained resolved records, discarding resolved history
    /// that is already outside the in-memory idempotency window.
    ///
    /// Crash safety: the compacted image is written to a same-directory temp file,
    /// fsynced, atomically renamed over the live log, and the directory fsynced
    /// (all via [`FileStore::write_atomic`]). A crash therefore leaves either the
    /// old full log or the new compacted log — never a torn state, and never a
    /// lost unresolved intent. As an extra guard the compacted bytes are parsed
    /// back and proven to reproduce the exact unresolved + retained-resolved state
    /// before the swap; on any mismatch the live log is left untouched.
    ///
    /// Returns `true` if the log was rewritten, `false` if the self-check declined
    /// the swap. Runtime/periodic compaction within a single long-running process
    /// is intentionally not performed here (see the module-level follow-up note).
    fn compact(&self) -> Result<bool, WriteIntentError> {
        let guard = self.state.lock();
        let compacted = compact_bytes(&guard)?;
        // Prove the compacted image rebuilds to the identical logical state before
        // replacing the live log. Never risk swapping in a log that will not
        // reopen or that would drop an unresolved intent.
        let (verify, _) = rebuild_state_from_bytes(&compacted, guard.max_resolved)?;
        if verify.unresolved != guard.unresolved || verify.resolved != guard.resolved {
            return Ok(false);
        }
        self.store.write_atomic(
            &self.owner,
            WRITE_INTENT_COLLECTION,
            &self.id,
            "jsonl",
            &compacted,
        )?;
        Ok(true)
    }

    /// Compact at open when the on-disk log is meaningfully larger than its
    /// compacted form. Best-effort: any error leaves the (valid) live log in
    /// place and never blocks startup.
    fn compact_on_open_if_beneficial(&self, records_read: usize) {
        if records_read < COMPACTION_MIN_RECORDS {
            return;
        }
        let compacted_records = {
            let guard = self.state.lock();
            // Each retained resolved intent re-serializes as a pending + resolved
            // pair so the rebuild invariants hold; unresolved re-serialize as one
            // pending each.
            guard.unresolved.len() + guard.resolved.len().saturating_mul(2)
        };
        if records_read < compacted_records.saturating_mul(2) {
            return;
        }
        let _ = self.compact();
    }
}

/// Serialize a state snapshot into a compacted JSONL image: one `pending` record
/// per unresolved intent, then a `pending` + `resolved` pair per retained
/// resolved intent (oldest first). The pending-before-resolved pairing and
/// per-intent field matching preserve every rebuild invariant.
fn compact_bytes(state: &WriteIntentState) -> Result<Vec<u8>, WriteIntentError> {
    let mut buf = Vec::new();
    for intent in state.unresolved.values() {
        push_record(&mut buf, &WriteIntentRecord::pending(intent))?;
    }
    for id in &state.resolved_order {
        if let Some(resolved) = state.resolved.get(id) {
            push_record(&mut buf, &WriteIntentRecord::pending(&resolved.intent))?;
            push_record(
                &mut buf,
                &WriteIntentRecord::resolved(&resolved.intent, resolved.outcome),
            )?;
        }
    }
    Ok(buf)
}

fn push_record(buf: &mut Vec<u8>, record: &WriteIntentRecord) -> Result<(), WriteIntentError> {
    let bytes =
        serde_json::to_vec(record).map_err(|e| WriteIntentError::Serialization(e.to_string()))?;
    if bytes.iter().any(|b| *b == b'\n' || *b == b'\r') {
        return Err(WriteIntentError::Serialization(
            "compacted record contains an embedded newline".to_owned(),
        ));
    }
    buf.extend_from_slice(&bytes);
    buf.push(b'\n');
    Ok(())
}

/// Recovery accounting used to decide whether startup compaction is worthwhile.
struct RebuildStats {
    /// Number of complete records parsed from the on-disk log.
    records_read: usize,
}

/// Read and rebuild in a single pass over the (already torn-tail-repaired) file.
fn rebuild_state(
    path: &Path,
    max_resolved: usize,
) -> Result<(WriteIntentState, RebuildStats), WriteIntentError> {
    let bytes =
        fs::read(path).map_err(|e| WriteIntentError::Store(FileStoreError::Io(e.to_string())))?;
    rebuild_state_from_bytes(&bytes, max_resolved)
}

fn rebuild_state_from_bytes(
    bytes: &[u8],
    max_resolved: usize,
) -> Result<(WriteIntentState, RebuildStats), WriteIntentError> {
    let mut state = WriteIntentState::with_max_resolved(max_resolved);
    let mut records_read = 0usize;
    for (idx, line) in bytes.split_inclusive(|b| *b == b'\n').enumerate() {
        let line_no = idx + 1;
        let record_bytes = line.strip_suffix(b"\n").unwrap_or(line);
        if record_bytes.is_empty() {
            return Err(WriteIntentError::Parse {
                line: line_no,
                message: "empty jsonl record".to_owned(),
            });
        }
        let record: WriteIntentRecord =
            serde_json::from_slice(record_bytes).map_err(|e| WriteIntentError::Parse {
                line: line_no,
                message: e.to_string(),
            })?;
        if record.schema_version != WRITE_INTENT_SCHEMA_VERSION {
            return Err(WriteIntentError::Parse {
                line: line_no,
                message: format!("unsupported schema version {}", record.schema_version),
            });
        }
        records_read += 1;
        match record.event {
            WriteIntentEvent::Pending => {
                if record.outcome.is_some() || record.resolved_ts.is_some() {
                    return Err(WriteIntentError::Parse {
                        line: line_no,
                        message: "pending record carries terminal fields".to_owned(),
                    });
                }
                if state.resolved.contains_key(&record.intent_id) {
                    return Err(WriteIntentError::Parse {
                        line: line_no,
                        message: "pending record follows terminal resolution".to_owned(),
                    });
                }
                if state.unresolved.contains_key(&record.intent_id) {
                    return Err(WriteIntentError::Parse {
                        line: line_no,
                        message: "duplicate pending record".to_owned(),
                    });
                }
                state
                    .unresolved
                    .insert(record.intent_id.clone(), record.into_intent());
            }
            WriteIntentEvent::Resolved => {
                let outcome = record.outcome.ok_or_else(|| WriteIntentError::Parse {
                    line: line_no,
                    message: "resolved record is missing outcome".to_owned(),
                })?;
                if state.resolved.contains_key(&record.intent_id) {
                    return Err(WriteIntentError::Parse {
                        line: line_no,
                        message: "duplicate resolved record".to_owned(),
                    });
                }
                let intent = record.into_intent();
                let pending = state.unresolved.remove(&intent.intent_id).ok_or_else(|| {
                    WriteIntentError::Parse {
                        line: line_no,
                        message: "resolved record has no pending record".to_owned(),
                    }
                })?;
                if pending.idempotency_key != intent.idempotency_key
                    || pending.sql_sha256 != intent.sql_sha256
                {
                    return Err(WriteIntentError::Parse {
                        line: line_no,
                        message: "resolved record does not match pending record".to_owned(),
                    });
                }
                // Apply the same retention cap the live `resolve()` path uses so
                // the post-restart idempotency window matches steady-state exactly.
                let intent_id = intent.intent_id.clone();
                state.record_resolved(intent_id, ResolvedWriteIntent { intent, outcome });
            }
        }
    }
    Ok((state, RebuildStats { records_read }))
}

fn unix_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/write-intent-tests")
            .join(format!("{name}-{}-{stamp}", std::process::id()))
    }

    fn intent(key: &str) -> WriteIntent {
        intent_with_sql(
            key,
            "UPDATE employees SET name = name WHERE employee_id = 100",
        )
    }

    fn intent_with_sql(key: &str, sql: &str) -> WriteIntent {
        let binding = ExecGrantBinding::new("sess-1", "lane-1", "principal-1", 7);
        WriteIntent::new(WriteIntentDetails {
            idempotency_key_material: key,
            subject: "profile:dev",
            active_profile: Some("dev"),
            tool: "oracle_execute",
            sql,
            required_level: OperatingLevel::ReadWrite,
            binding: &binding,
        })
    }

    #[test]
    fn unresolved_intent_survives_reopen_until_terminal_resolution() {
        let root = test_root("survives-reopen");
        let first_intent = intent("grant-1");
        let intent_id = first_intent.intent_id.clone();
        {
            let log = WriteIntentLog::open(&root).expect("open first log");
            log.append_pending(first_intent).expect("append pending");
            assert_eq!(log.unresolved().expect("unresolved").len(), 1);
        }
        {
            let log = WriteIntentLog::open(&root).expect("reopen log");
            let unresolved = log.unresolved().expect("unresolved after reopen");
            assert_eq!(unresolved.len(), 1);
            assert_eq!(unresolved[0].intent_id, intent_id);
            log.resolve(&intent_id, WriteIntentOutcome::Succeeded)
                .expect("resolve intent");
        }
        {
            let log = WriteIntentLog::open(&root).expect("reopen resolved log");
            assert!(
                log.unresolved()
                    .expect("unresolved after resolve")
                    .is_empty(),
                "terminal resolution removes restart poison"
            );
        }
    }

    #[test]
    fn duplicate_pending_intent_is_rejected() {
        let log = WriteIntentLog::open(test_root("duplicate")).expect("open log");
        let first_intent = intent("grant-dup");
        let duplicate = first_intent.clone();
        log.append_pending(first_intent).expect("append first");
        assert!(matches!(
            log.append_pending(duplicate),
            Err(WriteIntentError::Duplicate(_))
        ));
    }

    #[test]
    fn resolved_intent_survives_reopen_and_rejects_same_grant_sql_replay() {
        let root = test_root("resolved-replay");
        let first_intent = intent("grant-resolved");
        let intent_id = first_intent.intent_id.clone();
        {
            let log = WriteIntentLog::open(&root).expect("open first log");
            log.append_pending(first_intent).expect("append pending");
            log.resolve(&intent_id, WriteIntentOutcome::Succeeded)
                .expect("resolve intent");
        }

        let log = WriteIntentLog::open(&root).expect("reopen resolved log");
        let replay = intent("grant-resolved");
        assert!(matches!(
            log.append_pending(replay),
            Err(WriteIntentError::AlreadyResolved {
                intent_id: replay_id,
                outcome: WriteIntentOutcome::Succeeded
            }) if replay_id == intent_id
        ));
        assert!(
            log.unresolved().expect("unresolved snapshot").is_empty(),
            "terminal replay rejection must not create an unresolved poison record"
        );
    }

    #[test]
    fn resolved_intent_rejects_same_grant_with_different_sql_as_conflict() {
        let root = test_root("resolved-conflict");
        let first_intent = intent_with_sql("grant-conflict", "UPDATE employees SET name = name");
        let intent_id = first_intent.intent_id.clone();
        {
            let log = WriteIntentLog::open(&root).expect("open first log");
            log.append_pending(first_intent).expect("append pending");
            log.resolve(&intent_id, WriteIntentOutcome::RolledBack)
                .expect("resolve intent");
        }

        let log = WriteIntentLog::open(&root).expect("reopen resolved log");
        let drift = intent_with_sql("grant-conflict", "UPDATE employees SET name = 'x'");
        assert!(matches!(
            log.append_pending(drift),
            Err(WriteIntentError::IdempotencyConflict { intent_id: drift_id }) if drift_id == intent_id
        ));
    }

    /// Resolve-and-record a distinct intent by idempotency key, returning its id.
    fn resolve_key(log: &WriteIntentLog, key: &str, outcome: WriteIntentOutcome) -> String {
        let id = log.append_pending(intent(key)).expect("append pending");
        log.resolve(&id, outcome).expect("resolve intent");
        id
    }

    fn resolved_len(log: &WriteIntentLog) -> usize {
        log.state.lock().resolved.len()
    }

    #[test]
    fn resolved_index_is_bounded_and_evicts_oldest() {
        // With a small cap the resident resolved index must never exceed it, and
        // the oldest resolved entries fall out of the idempotency window.
        let log = WriteIntentLog::open_capped(test_root("bounded-evict"), 4).expect("open capped");
        let mut ids = Vec::new();
        for i in 0..10 {
            ids.push(resolve_key(
                &log,
                &format!("evict-{i}"),
                WriteIntentOutcome::Succeeded,
            ));
        }
        assert!(
            resolved_len(&log) <= 4,
            "resident resolved index stays within the cap"
        );

        // A retained (most-recent) resolution still rejects same-grant/same-SQL
        // replay as AlreadyResolved.
        let retained = &ids[9];
        assert!(matches!(
            log.append_pending(intent("evict-9")),
            Err(WriteIntentError::AlreadyResolved { intent_id, .. }) if &intent_id == retained
        ));

        // An evicted (oldest) resolution has left the window and is re-admitted as
        // a fresh pending intent rather than being remembered forever.
        assert!(
            log.append_pending(intent("evict-0")).is_ok(),
            "evicted resolved entry is re-admitted, proving the window is bounded"
        );
    }

    #[test]
    fn unresolved_intents_are_never_evicted_by_resolved_cap() {
        // Even under heavy resolved churn against a tiny cap, every unresolved
        // intent must survive in memory and across restart: they are the
        // fail-closed crash poison and may never be dropped.
        let root = test_root("unresolved-preserved");
        {
            let log = WriteIntentLog::open_capped(&root, 2).expect("open capped");
            for i in 0..6 {
                log.append_pending(intent(&format!("keep-{i}")))
                    .expect("append unresolved");
            }
            for i in 0..30 {
                resolve_key(&log, &format!("churn-{i}"), WriteIntentOutcome::Succeeded);
            }
            assert_eq!(
                log.unresolved().expect("unresolved").len(),
                6,
                "resolved eviction never touches unresolved intents"
            );
            assert!(resolved_len(&log) <= 2, "resolved index stays bounded");
        }
        let log = WriteIntentLog::open_capped(&root, 2).expect("reopen capped");
        assert_eq!(
            log.unresolved().expect("unresolved after reopen").len(),
            6,
            "every unresolved intent survives restart"
        );
    }

    #[test]
    fn rebuild_applies_the_resolved_cap_and_keeps_the_newest_window() {
        // Recovery must reconstruct the same bounded window the live path would
        // hold: the newest `cap` resolutions, not the whole history.
        let root = test_root("rebuild-cap");
        {
            let log = WriteIntentLog::open_capped(&root, 3).expect("open capped");
            for i in 0..12 {
                resolve_key(&log, &format!("win-{i}"), WriteIntentOutcome::Succeeded);
            }
        }
        // Reopen with the same cap: rebuild reads all history but retains only the
        // newest three resolutions.
        let log = WriteIntentLog::open_capped(&root, 3).expect("reopen capped");
        assert!(resolved_len(&log) <= 3, "rebuild honours the resolved cap");
        // Newest is still in-window and rejects replay.
        assert!(matches!(
            log.append_pending(intent("win-11")),
            Err(WriteIntentError::AlreadyResolved { .. })
        ));
        // Oldest fell out of the window during rebuild and is re-admitted.
        assert!(
            log.append_pending(intent("win-0")).is_ok(),
            "rebuild evicts the oldest resolutions just like steady state"
        );
    }

    #[test]
    fn open_time_compaction_shrinks_log_and_preserves_all_state() {
        let root = test_root("compaction");
        let path;
        let size_before;
        {
            // Build a log well past the compaction floor: a handful of unresolved
            // intents plus a long resolved history that vastly exceeds the cap.
            let log = WriteIntentLog::open_capped(&root, 8).expect("open capped");
            for i in 0..5 {
                log.append_pending(intent(&format!("live-{i}")))
                    .expect("append unresolved");
            }
            for i in 0..260 {
                resolve_key(&log, &format!("hist-{i}"), WriteIntentOutcome::Succeeded);
            }
            path = log.path().expect("log path");
            size_before = fs::metadata(&path).expect("metadata").len();
            // Opening this log did not compact (it was empty at open); it grew to
            // > 512 records now.
        }

        // Reopening reads the oversized log and compacts it crash-safely.
        let size_after;
        {
            let log = WriteIntentLog::open_capped(&root, 8).expect("reopen + compact");
            size_after = fs::metadata(&path).expect("metadata after").len();
            assert!(
                size_after < size_before,
                "compaction shrinks the on-disk log ({size_after} !< {size_before})"
            );
            assert_eq!(
                log.unresolved().expect("unresolved").len(),
                5,
                "compaction preserves every unresolved intent"
            );
            // The newest resolutions survived compaction and still reject replay.
            assert!(matches!(
                log.append_pending(intent("hist-259")),
                Err(WriteIntentError::AlreadyResolved { .. })
            ));
        }

        // The compacted log rebuilds cleanly: unresolved intact, retained window
        // intact, never a parse failure.
        let log = WriteIntentLog::open_capped(&root, 8).expect("reopen compacted");
        assert_eq!(
            log.unresolved().expect("unresolved after compaction").len(),
            5,
            "unresolved intents survive across the compaction swap"
        );
        assert!(matches!(
            log.append_pending(intent("hist-259")),
            Err(WriteIntentError::AlreadyResolved { .. })
        ));
    }

    #[test]
    fn compact_self_check_is_a_no_op_faithful_rewrite() {
        // Directly exercising compaction on a small log must reproduce the exact
        // logical state and leave every intent recoverable.
        let root = test_root("compact-direct");
        let log = WriteIntentLog::open_capped(&root, 8).expect("open capped");
        let unresolved_id = log
            .append_pending(intent("stay-unresolved"))
            .expect("append unresolved");
        resolve_key(&log, "done-1", WriteIntentOutcome::Succeeded);
        resolve_key(&log, "done-2", WriteIntentOutcome::RolledBack);

        assert!(
            log.compact().expect("compact"),
            "compaction rewrote the log"
        );

        let before = {
            let guard = log.state.lock();
            (guard.unresolved.clone(), guard.resolved.clone())
        };
        drop(log);

        let reopened = WriteIntentLog::open_capped(&root, 8).expect("reopen after compact");
        let after = {
            let guard = reopened.state.lock();
            (guard.unresolved.clone(), guard.resolved.clone())
        };
        assert_eq!(before, after, "compaction is a faithful, lossless rewrite");
        assert_eq!(
            reopened.unresolved().expect("unresolved").len(),
            1,
            "the unresolved intent survives compaction"
        );
        assert!(
            reopened
                .unresolved()
                .expect("unresolved")
                .iter()
                .any(|i| i.intent_id == unresolved_id),
            "the exact unresolved intent id survives compaction"
        );
    }

    #[test]
    fn torn_tail_after_crash_is_repaired_without_losing_unresolved() {
        // A crash mid-append leaves an unterminated tail. Recovery must truncate
        // only that torn record and preserve every fully-committed unresolved
        // intent, failing closed on none of them.
        let root = test_root("torn-tail");
        let path;
        {
            let log = WriteIntentLog::open(&root).expect("open log");
            for i in 0..4 {
                log.append_pending(intent(&format!("committed-{i}")))
                    .expect("append committed");
            }
            path = log.path().expect("path");
        }
        // Simulate a torn write: append a partial record with no trailing newline.
        use std::io::Write as _;
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open for torn append");
        file.write_all(b"{\"schema_version\":1,\"event\":\"pending\",\"intent_id\":\"intent-torn")
            .expect("write torn tail");
        file.sync_all().expect("sync torn tail");
        drop(file);

        let log = WriteIntentLog::open(&root).expect("reopen after crash");
        let unresolved = log.unresolved().expect("unresolved after crash");
        assert_eq!(
            unresolved.len(),
            4,
            "all committed unresolved intents survive; only the torn tail is dropped"
        );
    }

    #[test]
    fn corrupt_record_fails_closed_with_typed_parse_error() {
        // A structurally complete but corrupt record must fail closed with a typed
        // diagnostic rather than panic or silently drop state.
        let root = test_root("corrupt-record");
        let path;
        {
            let log = WriteIntentLog::open(&root).expect("open log");
            log.append_pending(intent("ok-1")).expect("append ok");
            path = log.path().expect("path");
        }
        use std::io::Write as _;
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open for corrupt append");
        file.write_all(b"not-json\n").expect("write corrupt line");
        file.sync_all().expect("sync corrupt line");
        drop(file);

        assert!(matches!(
            WriteIntentLog::open(&root),
            Err(WriteIntentError::Parse { .. })
        ));
    }
}
