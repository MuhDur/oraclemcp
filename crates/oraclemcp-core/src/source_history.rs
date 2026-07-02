//! Durable source snapshots for governed source-replaceable DDL.
//!
//! The history store records the prior source for `CREATE OR REPLACE` objects
//! before a governed edit is applied. It stores full snapshot files under the
//! shared [`FileStore`] and keeps list views source-free; revert drafts are
//! created by the existing change-proposal path.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::file_store::{FileStore, FileStoreError, StoreId};

const SOURCE_SNAPSHOT_COLLECTION: &str = "source-snapshots";
const SOURCE_HISTORY_COLLECTION: &str = "source-history";
const SOURCE_HISTORY_EXTENSION: &str = "json";
const SOURCE_HISTORY_SCHEMA_VERSION: u8 = 1;

/// Persistent source-history store.
pub struct SourceHistoryStore {
    store: FileStore,
}

impl SourceHistoryStore {
    /// Open the default service-owned source-history store.
    pub fn open_default() -> Result<Self, SourceHistoryError> {
        Ok(Self::new(FileStore::open_default()?))
    }

    /// Build a source-history store from an existing file-store root.
    #[must_use]
    pub fn new(store: FileStore) -> Self {
        Self { store }
    }

    /// Record one complete prior-source snapshot and append its object history.
    pub fn record_snapshot(
        &self,
        draft: SourceSnapshotDraft,
    ) -> Result<SourceSnapshotView, SourceHistoryError> {
        let profile = normalize_non_empty(draft.profile, "profile")?;
        let owner = normalize_identifier(draft.owner, "owner")?;
        let name = normalize_identifier(draft.name, "name")?;
        let object_type = normalize_source_object_type(&draft.object_type).ok_or(
            SourceHistoryError::Invalid("unsupported source object type"),
        )?;
        let source = normalize_non_empty(draft.source, "source")?;
        let created_at = unix_timestamp();
        let source_sha256 = prefixed_sha256_hex(source.as_bytes());
        let source_lines = source.lines().count();
        let source_chars = source.chars().count();
        let id = StoreId::content_hashed(
            "srcsnap",
            &[
                profile.as_str(),
                owner.as_str(),
                name.as_str(),
                object_type.as_str(),
                source.as_str(),
            ],
        )?
        .as_str()
        .to_owned();

        let snapshot = SourceSnapshot {
            schema_version: SOURCE_HISTORY_SCHEMA_VERSION,
            id: id.clone(),
            created_at,
            profile,
            owner,
            name,
            object_type,
            source_kind: draft.source_kind,
            source_sha256,
            source_lines,
            source_chars,
            proposal_id: draft.proposal_id,
            statement_id: draft.statement_id,
            statement_sql_sha256: draft.statement_sql_sha256,
            lane_id: draft.lane_id,
            subject_id_hash: draft.subject_id_hash,
            source,
        };
        let view = snapshot.view();
        let mut snapshot_bytes = serde_json::to_vec_pretty(&snapshot)
            .map_err(|e| SourceHistoryError::Json(e.to_string()))?;
        snapshot_bytes.push(b'\n');
        let entry_bytes =
            serde_json::to_vec(&view).map_err(|e| SourceHistoryError::Json(e.to_string()))?;
        let history_id = object_history_id(
            &snapshot.profile,
            &snapshot.owner,
            &snapshot.name,
            &snapshot.object_type,
        )?;
        let snapshot_id = StoreId::from_safe_segment(id)?;
        let lock = self.store.acquire_service_lock("source-history")?;
        self.store.write_atomic(
            &lock,
            SOURCE_SNAPSHOT_COLLECTION,
            &snapshot_id,
            SOURCE_HISTORY_EXTENSION,
            &snapshot_bytes,
        )?;
        self.store
            .append_jsonl(&lock, SOURCE_HISTORY_COLLECTION, &history_id, &entry_bytes)?;
        Ok(view)
    }

    /// List source-history entries. Source text is never included.
    pub fn list(
        &self,
        filter: SourceHistoryFilter,
    ) -> Result<Vec<SourceSnapshotView>, SourceHistoryError> {
        let dir = self.store.root().join(SOURCE_HISTORY_COLLECTION);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|e| SourceHistoryError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| SourceHistoryError::Io(e.to_string()))?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
                continue;
            }
            let bytes = fs::read(&path).map_err(|e| SourceHistoryError::Io(e.to_string()))?;
            for line in bytes.split(|byte| *byte == b'\n') {
                if line.is_empty() {
                    continue;
                }
                let view: SourceSnapshotView = serde_json::from_slice(line)
                    .map_err(|e| SourceHistoryError::Json(e.to_string()))?;
                if filter.matches(&view) {
                    entries.push(view);
                }
            }
        }
        entries.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.profile.cmp(&b.profile))
                .then_with(|| a.owner.cmp(&b.owner))
                .then_with(|| a.name.cmp(&b.name))
                .then_with(|| a.object_type.cmp(&b.object_type))
                .then_with(|| a.id.cmp(&b.id))
        });
        if let Some(limit) = filter.max_rows {
            entries.truncate(limit);
        }
        Ok(entries)
    }

    /// Load a full snapshot by id for a revert draft.
    pub fn load_snapshot(&self, id: &str) -> Result<SourceSnapshot, SourceHistoryError> {
        let id = StoreId::from_safe_segment(id.trim().to_owned())?;
        let path =
            self.store
                .path_for(SOURCE_SNAPSHOT_COLLECTION, &id, SOURCE_HISTORY_EXTENSION)?;
        if !path.exists() {
            return Err(SourceHistoryError::UnknownSnapshot);
        }
        load_snapshot_from_path(&path)
    }
}

/// Request to create a revert change proposal from a stored source snapshot.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SourceHistoryRevertRequest {
    pub snapshot_id: String,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
}

/// List filter for source-history entries.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct SourceHistoryFilter {
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub object_type: Option<String>,
    #[serde(default)]
    pub max_rows: Option<usize>,
}

impl SourceHistoryFilter {
    fn matches(&self, view: &SourceSnapshotView) -> bool {
        matches_optional_case_insensitive(self.profile.as_deref(), &view.profile)
            && matches_optional_case_insensitive(self.owner.as_deref(), &view.owner)
            && matches_optional_case_insensitive(self.name.as_deref(), &view.name)
            && self
                .object_type
                .as_deref()
                .and_then(normalize_source_object_type)
                .is_none_or(|object_type| object_type == view.object_type)
    }
}

/// A parsed source-replaceable object target.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceObjectTarget {
    pub owner: Option<String>,
    pub name: String,
    pub object_type: String,
}

/// Full on-disk source snapshot.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceSnapshot {
    pub schema_version: u8,
    pub id: String,
    pub created_at: String,
    pub profile: String,
    pub owner: String,
    pub name: String,
    pub object_type: String,
    pub source_kind: String,
    pub source_sha256: String,
    pub source_lines: usize,
    pub source_chars: usize,
    pub proposal_id: String,
    pub statement_id: String,
    pub statement_sql_sha256: String,
    #[serde(default)]
    pub lane_id: Option<String>,
    pub subject_id_hash: String,
    pub source: String,
}

impl SourceSnapshot {
    /// Redacted operator-facing view. It intentionally excludes source text.
    #[must_use]
    pub fn view(&self) -> SourceSnapshotView {
        SourceSnapshotView {
            schema_version: self.schema_version,
            id: self.id.clone(),
            created_at: self.created_at.clone(),
            profile: self.profile.clone(),
            owner: self.owner.clone(),
            name: self.name.clone(),
            object_type: self.object_type.clone(),
            source_kind: self.source_kind.clone(),
            source_sha256: self.source_sha256.clone(),
            source_lines: self.source_lines,
            source_chars: self.source_chars,
            proposal_id: self.proposal_id.clone(),
            statement_id: self.statement_id.clone(),
            statement_sql_sha256: self.statement_sql_sha256.clone(),
            lane_id: self.lane_id.clone(),
            subject_id_hash: self.subject_id_hash.clone(),
        }
    }
}

/// Operator-facing source-history row.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceSnapshotView {
    pub schema_version: u8,
    pub id: String,
    pub created_at: String,
    pub profile: String,
    pub owner: String,
    pub name: String,
    pub object_type: String,
    pub source_kind: String,
    pub source_sha256: String,
    pub source_lines: usize,
    pub source_chars: usize,
    pub proposal_id: String,
    pub statement_id: String,
    pub statement_sql_sha256: String,
    #[serde(default)]
    pub lane_id: Option<String>,
    pub subject_id_hash: String,
}

/// Input for recording a snapshot fetched from the live dispatcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceSnapshotDraft {
    pub profile: String,
    pub owner: String,
    pub name: String,
    pub object_type: String,
    pub source_kind: String,
    pub source: String,
    pub proposal_id: String,
    pub statement_id: String,
    pub statement_sql_sha256: String,
    pub lane_id: Option<String>,
    pub subject_id_hash: String,
}

/// Source-history errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SourceHistoryError {
    /// File-store operation failed.
    #[error(transparent)]
    FileStore(#[from] FileStoreError),
    /// Plain I/O operation failed.
    #[error("source-history io error: {0}")]
    Io(String),
    /// JSON serialization or parsing failed.
    #[error("source-history json error: {0}")]
    Json(String),
    /// Invalid caller input.
    #[error("invalid source-history request: {0}")]
    Invalid(&'static str),
    /// The requested snapshot id does not exist.
    #[error("unknown source-history snapshot")]
    UnknownSnapshot,
}

/// Parse a plain `CREATE OR REPLACE` source-replaceable object target.
#[must_use]
pub fn source_object_from_create_or_replace_sql(sql: &str) -> Option<SourceObjectTarget> {
    let words: Vec<&str> = sql.split_whitespace().collect();
    if words.len() < 4
        || !words[0].eq_ignore_ascii_case("CREATE")
        || !words[1].eq_ignore_ascii_case("OR")
        || !words[2].eq_ignore_ascii_case("REPLACE")
    {
        return None;
    }
    let mut idx = 3;
    while matches!(
        words
            .get(idx)
            .map(|word| word.to_ascii_uppercase())
            .as_deref(),
        Some("EDITIONABLE" | "NONEDITIONABLE" | "FORCE" | "NOFORCE")
    ) {
        idx += 1;
    }
    let first = words.get(idx)?.to_ascii_uppercase();
    let (object_type, name_idx) = match first.as_str() {
        "PACKAGE"
            if words
                .get(idx + 1)
                .is_some_and(|word| word.eq_ignore_ascii_case("BODY")) =>
        {
            ("PACKAGE BODY".to_owned(), idx + 2)
        }
        "TYPE"
            if words
                .get(idx + 1)
                .is_some_and(|word| word.eq_ignore_ascii_case("BODY")) =>
        {
            ("TYPE BODY".to_owned(), idx + 2)
        }
        "PACKAGE" | "PROCEDURE" | "FUNCTION" | "TRIGGER" | "TYPE" | "VIEW" => (first, idx + 1),
        _ => return None,
    };
    let name = clean_source_name_token(words.get(name_idx)?)?;
    let mut parts = name.split('.');
    let first = parts.next()?.to_ascii_uppercase();
    let second = parts.next().map(str::to_ascii_uppercase);
    if parts.next().is_some() {
        return None;
    }
    let (owner, name) = match second {
        Some(name) => (Some(first), name),
        None => (None, first),
    };
    Some(SourceObjectTarget {
        owner,
        name,
        object_type,
    })
}

/// Normalize source-replaceable object types. VIEW is included because the
/// snapshot path fetches it through DBMS_METADATA instead of ALL_SOURCE.
#[must_use]
pub fn normalize_source_object_type(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_uppercase().replace('_', " ");
    match value.as_str() {
        "PACKAGE" | "PACKAGE BODY" | "PROCEDURE" | "FUNCTION" | "TRIGGER" | "TYPE"
        | "TYPE BODY" | "VIEW" => Some(value),
        _ => None,
    }
}

fn object_history_id(
    profile: &str,
    owner: &str,
    name: &str,
    object_type: &str,
) -> Result<StoreId, SourceHistoryError> {
    Ok(StoreId::content_hashed(
        "object",
        &[profile, owner, name, object_type],
    )?)
}

fn load_snapshot_from_path(path: &Path) -> Result<SourceSnapshot, SourceHistoryError> {
    let bytes = fs::read(path).map_err(|e| SourceHistoryError::Io(e.to_string()))?;
    let snapshot: SourceSnapshot =
        serde_json::from_slice(&bytes).map_err(|e| SourceHistoryError::Json(e.to_string()))?;
    if snapshot.schema_version != SOURCE_HISTORY_SCHEMA_VERSION {
        return Err(SourceHistoryError::Invalid(
            "unsupported source-history schema version",
        ));
    }
    Ok(snapshot)
}

fn clean_source_name_token(raw: &str) -> Option<String> {
    let token = raw
        .split('(')
        .next()
        .unwrap_or(raw)
        .trim()
        .trim_end_matches(';')
        .trim_matches('"');
    if is_simple_source_name(token) {
        Some(token.to_owned())
    } else {
        None
    }
}

fn is_simple_source_name(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    let second = parts.next();
    if parts.next().is_some() {
        return false;
    }
    let valid_part = |part: &str| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '#'))
    };
    valid_part(first) && second.is_none_or(valid_part)
}

fn normalize_non_empty(value: String, field: &'static str) -> Result<String, SourceHistoryError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(SourceHistoryError::Invalid(match field {
            "profile" => "profile is required",
            "source" => "source is required",
            _ => "required field is empty",
        }));
    }
    Ok(value.to_owned())
}

fn normalize_identifier(value: String, field: &'static str) -> Result<String, SourceHistoryError> {
    let value = normalize_non_empty(value, field)?.to_ascii_uppercase();
    if !is_simple_source_name(&value) || value.contains('.') {
        return Err(SourceHistoryError::Invalid(match field {
            "owner" => "owner must be one unquoted identifier",
            "name" => "name must be one unquoted identifier",
            _ => "invalid identifier",
        }));
    }
    Ok(value)
}

fn matches_optional_case_insensitive(expected: Option<&str>, actual: &str) -> bool {
    expected
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none_or(|value| value.eq_ignore_ascii_case(actual))
}

fn unix_timestamp() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!(
        "unix:{:020}.{:09}",
        duration.as_secs(),
        duration.subsec_nanos()
    )
}

fn prefixed_sha256_hex(bytes: &[u8]) -> String {
    format!("sha256:{}", oraclemcp_audit::sha256_hex(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_create_or_replace_targets() {
        let pkg = source_object_from_create_or_replace_sql(
            "CREATE OR REPLACE EDITIONABLE PACKAGE BODY app.emp_api AS END;",
        )
        .expect("package body target");
        assert_eq!(pkg.owner.as_deref(), Some("APP"));
        assert_eq!(pkg.name, "EMP_API");
        assert_eq!(pkg.object_type, "PACKAGE BODY");

        let view = source_object_from_create_or_replace_sql(
            "create or replace force view v as select 1 x from dual",
        )
        .expect("view target");
        assert_eq!(view.owner, None);
        assert_eq!(view.name, "V");
        assert_eq!(view.object_type, "VIEW");

        assert!(
            source_object_from_create_or_replace_sql("CREATE TABLE t (id NUMBER)").is_none(),
            "non-source DDL is not revert-snapshot eligible"
        );
    }

    #[test]
    fn list_views_exclude_source_text() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/source-history-tests")
            .join(format!("{}-{stamp}", std::process::id()));
        let store = SourceHistoryStore::new(FileStore::open(root).expect("file store"));
        let source = "CREATE OR REPLACE PROCEDURE p IS BEGIN NULL; END;".to_owned();
        let view = store
            .record_snapshot(SourceSnapshotDraft {
                profile: "prod".to_owned(),
                owner: "app".to_owned(),
                name: "p".to_owned(),
                object_type: "procedure".to_owned(),
                source_kind: "all_source".to_owned(),
                source,
                proposal_id: "cp-1".to_owned(),
                statement_id: "stmt-1".to_owned(),
                statement_sql_sha256: "sha256:stmt".to_owned(),
                lane_id: Some("operator".to_owned()),
                subject_id_hash: "subject-sha256:test".to_owned(),
            })
            .expect("snapshot recorded");
        let entries = store
            .list(SourceHistoryFilter {
                profile: Some("prod".to_owned()),
                owner: Some("APP".to_owned()),
                name: Some("P".to_owned()),
                object_type: Some("procedure".to_owned()),
                max_rows: None,
            })
            .expect("history listed");
        assert_eq!(entries, vec![view]);
        let rendered = serde_json::to_string(&entries).expect("history serializes");
        assert!(!rendered.contains("BEGIN NULL"));
        let full = store.load_snapshot(&entries[0].id).expect("snapshot loads");
        assert!(full.source.contains("BEGIN NULL"));
    }
}
