//! Durable write-ahead idempotency intents for permanent database effects.
//!
//! This layer is intentionally smaller than the audit chain: it records only
//! non-secret idempotency and routing facts needed to fail closed after a crash.
//! The sequence is append `pending` + fsync before the database call, append a
//! terminal `resolved` record only after a safe terminal outcome, and rebuild the
//! unresolved set plus terminal idempotency index on restart.

use std::collections::HashMap;
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

#[derive(Debug, Default)]
struct WriteIntentState {
    unresolved: HashMap<String, WriteIntent>,
    resolved: HashMap<String, ResolvedWriteIntent>,
}

impl WriteIntentState {
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
        let id = StoreId::from_safe_segment(WRITE_INTENT_ID)?;
        store.recover_jsonl(&owner, WRITE_INTENT_COLLECTION, &id)?;
        let path = store.path_for(WRITE_INTENT_COLLECTION, &id, "jsonl")?;
        let state = rebuild_state(&path)?;
        Ok(Self {
            store,
            owner,
            id,
            state: Mutex::new(state),
        })
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
        guard.resolved.insert(
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
}

fn rebuild_state(path: &Path) -> Result<WriteIntentState, WriteIntentError> {
    let bytes =
        fs::read(path).map_err(|e| WriteIntentError::Store(FileStoreError::Io(e.to_string())))?;
    let mut state = WriteIntentState::default();
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
                state.resolved.insert(
                    intent.intent_id.clone(),
                    ResolvedWriteIntent { intent, outcome },
                );
            }
        }
    }
    Ok(state)
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
}
