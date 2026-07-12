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

use crate::file_store::{FileStore, FileStoreError, ServiceOwner, StoreId};
use crate::pagination::{LIST_PAGE_SIZE, decode_cursor, encode_cursor};

const SOURCE_SNAPSHOT_COLLECTION: &str = "source-snapshots";
const SOURCE_HISTORY_COLLECTION: &str = "source-history";
const SOURCE_HISTORY_EXTENSION: &str = "json";
/// Tamper-token scope for source-history list cursors.
const SOURCE_HISTORY_CURSOR_KIND: &str = "source-history";
const SOURCE_HISTORY_SCHEMA_VERSION: u8 = 2;
const LEGACY_SOURCE_HISTORY_SCHEMA_VERSION: u8 = 1;

/// Persistent source-history store.
pub struct SourceHistoryStore {
    store: FileStore,
    owner: ServiceOwner,
}

impl SourceHistoryStore {
    /// Open the default service-owned source-history store.
    pub fn open_default() -> Result<Self, SourceHistoryError> {
        Self::open(FileStore::default_state_dir()?)
    }

    /// Open a standalone source-history store rooted at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, SourceHistoryError> {
        let store = FileStore::open(root)?;
        let owner = store.acquire_service_owner("source-history")?;
        Ok(Self { store, owner })
    }

    /// Open the source-history store under an existing process-wide service owner.
    pub fn open_with_owner(owner: ServiceOwner) -> Result<Self, SourceHistoryError> {
        let store = FileStore::open(owner.root())?;
        Ok(Self { store, owner })
    }

    /// Record one complete prior-source snapshot and append its object history.
    pub fn record_snapshot(
        &self,
        draft: SourceSnapshotDraft,
    ) -> Result<SourceSnapshotView, SourceHistoryError> {
        let profile = normalize_non_empty(draft.profile, "profile")?;
        let owner = normalize_identifier(draft.owner, draft.owner_quoted, "owner")?;
        let name = normalize_identifier(draft.name, draft.name_quoted, "name")?;
        let object_type = normalize_source_object_type(&draft.object_type).ok_or(
            SourceHistoryError::Invalid("unsupported source object type"),
        )?;
        let target_identity_sha256 = source_identity_sha256(&owner, &name, object_type.as_str());
        if target_identity_sha256 != draft.target_identity_sha256 {
            return Err(SourceHistoryError::Invalid(
                "source target identity changed before persistence",
            ));
        }
        let source = normalize_non_empty(draft.source, "source")?;
        let source_target = source_object_from_create_or_replace_sql(&source).ok_or(
            SourceHistoryError::Invalid("snapshot source target could not be parsed"),
        )?;
        if source_target.name != name
            || source_target.object_type != object_type
            || source_target
                .owner
                .as_deref()
                .is_some_and(|source_owner| source_owner != owner)
        {
            return Err(SourceHistoryError::Invalid(
                "snapshot source target does not match captured target",
            ));
        }
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
            owner_quoted: draft.owner_quoted,
            name,
            name_quoted: draft.name_quoted,
            object_type,
            target_identity_sha256,
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
        let _mutation = self.owner.mutation_guard();
        self.store.write_atomic(
            &self.owner,
            SOURCE_SNAPSHOT_COLLECTION,
            &snapshot_id,
            SOURCE_HISTORY_EXTENSION,
            &snapshot_bytes,
        )?;
        self.store.append_jsonl(
            &self.owner,
            SOURCE_HISTORY_COLLECTION,
            &history_id,
            &entry_bytes,
        )?;
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

    /// Conditional-request validator for the source-history board.
    ///
    /// Unchanged between two polls, it lets the caller answer `304 Not Modified`
    /// without re-reading the history files; it also doubles as the [`list_page`]
    /// cursor revision so a cursor minted before an append is rejected as stale.
    ///
    /// [`list_page`]: SourceHistoryStore::list_page
    pub fn etag(&self) -> Result<String, SourceHistoryError> {
        Ok(self.store.collection_etag(SOURCE_HISTORY_COLLECTION)?)
    }

    /// List one bounded, newest-first page of source-history entries. Source text
    /// is never included.
    ///
    /// Unlike [`list`], the page is capped at [`LIST_PAGE_SIZE`] with an opaque
    /// signed `next_cursor` when more entries remain, so a polled response stays
    /// bounded regardless of how large the history grows. A caller `max_rows`
    /// still caps the visible universe before paging. A single malformed JSONL
    /// record is skipped rather than failing the entire listing.
    ///
    /// [`list`]: SourceHistoryStore::list
    pub fn list_page(
        &self,
        filter: SourceHistoryFilter,
        cursor: Option<&str>,
    ) -> Result<SourceSnapshotPage, SourceHistoryError> {
        let etag = self.etag()?;
        let dir = self.store.root().join(SOURCE_HISTORY_COLLECTION);
        let mut entries = Vec::new();
        if dir.exists() {
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
                    // Skip a single corrupt record rather than hiding the board.
                    let Ok(view) = serde_json::from_slice::<SourceSnapshotView>(line) else {
                        continue;
                    };
                    if filter.matches(&view) {
                        entries.push(view);
                    }
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
        // A caller-supplied max_rows caps the visible universe; the structural
        // page cap below always applies on top of it.
        if let Some(limit) = filter.max_rows {
            entries.truncate(limit);
        }
        let offset = decode_cursor(SOURCE_HISTORY_CURSOR_KIND, &etag, cursor)
            .map_err(|_| SourceHistoryError::Invalid("invalid or stale pagination cursor"))?
            .min(entries.len());
        let end = offset.saturating_add(LIST_PAGE_SIZE).min(entries.len());
        let next_cursor =
            (end < entries.len()).then(|| encode_cursor(SOURCE_HISTORY_CURSOR_KIND, &etag, end));
        Ok(SourceSnapshotPage {
            snapshots: entries[offset..end].to_vec(),
            next_cursor,
            etag,
        })
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
            && matches_optional_identifier(self.owner.as_deref(), &view.owner)
            && matches_optional_identifier(self.name.as_deref(), &view.name)
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
    #[serde(default)]
    pub owner_quoted: bool,
    pub name: String,
    #[serde(default)]
    pub name_quoted: bool,
    pub object_type: String,
}

impl SourceObjectTarget {
    /// Render an identifier for tools whose identifier arguments retain Oracle
    /// quote syntax. Quoted spelling is never collapsed into an unquoted name.
    #[must_use]
    pub fn owner_lookup(&self) -> Option<String> {
        self.owner
            .as_deref()
            .map(|owner| render_identifier(owner, self.owner_quoted))
    }

    /// Render the object name without losing quoted-identifier identity.
    #[must_use]
    pub fn name_lookup(&self) -> String {
        render_identifier(&self.name, self.name_quoted)
    }

    /// Digest the concrete Oracle identity after an unqualified target's owner
    /// has been resolved by the source lookup.
    #[must_use]
    pub fn identity_sha256(&self, resolved_owner: &str) -> String {
        source_identity_sha256(
            self.owner.as_deref().unwrap_or(resolved_owner),
            &self.name,
            &self.object_type,
        )
    }
}

/// Full on-disk source snapshot.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceSnapshot {
    pub schema_version: u8,
    pub id: String,
    pub created_at: String,
    pub profile: String,
    pub owner: String,
    #[serde(default)]
    pub owner_quoted: bool,
    pub name: String,
    #[serde(default)]
    pub name_quoted: bool,
    pub object_type: String,
    #[serde(default)]
    pub target_identity_sha256: String,
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
            owner_quoted: self.owner_quoted,
            name: self.name.clone(),
            name_quoted: self.name_quoted,
            object_type: self.object_type.clone(),
            target_identity_sha256: self.target_identity_sha256.clone(),
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
    #[serde(default)]
    pub owner_quoted: bool,
    pub name: String,
    #[serde(default)]
    pub name_quoted: bool,
    pub object_type: String,
    #[serde(default)]
    pub target_identity_sha256: String,
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

/// One bounded page of source-history rows plus its conditional-request
/// validator. Source text is never included in a row.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SourceSnapshotPage {
    /// The newest-first history rows in this page.
    pub snapshots: Vec<SourceSnapshotView>,
    /// Opaque signed cursor for the next page, or `None` when exhausted.
    pub next_cursor: Option<String>,
    /// Validator matching [`SourceHistoryStore::etag`]; also the cursor
    /// revision, so a cursor is rejected once the store changes under it.
    pub etag: String,
}

/// Input for recording a snapshot fetched from the live dispatcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceSnapshotDraft {
    pub profile: String,
    pub owner: String,
    pub owner_quoted: bool,
    pub name: String,
    pub name_quoted: bool,
    pub object_type: String,
    pub target_identity_sha256: String,
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
    /// Invalid caller input, or a pagination cursor that was invalid, tampered,
    /// or stale.
    #[error("invalid source-history request: {0}")]
    Invalid(&'static str),
    /// The requested snapshot id does not exist.
    #[error("unknown source-history snapshot")]
    UnknownSnapshot,
}

/// Parse a plain `CREATE OR REPLACE` source-replaceable object target.
#[must_use]
pub fn source_object_from_create_or_replace_sql(sql: &str) -> Option<SourceObjectTarget> {
    let mut cursor = SourceHeaderCursor::new(sql);
    cursor.consume_keyword("CREATE")?;
    cursor.consume_keyword("OR")?;
    cursor.consume_keyword("REPLACE")?;

    loop {
        let checkpoint = cursor.position();
        let Some(modifier) = cursor.identifier() else {
            cursor.restore(checkpoint);
            break;
        };
        if modifier.quoted
            || !matches!(
                modifier.value.to_ascii_uppercase().as_str(),
                "EDITIONABLE" | "NONEDITIONABLE" | "FORCE" | "NOFORCE"
            )
        {
            cursor.restore(checkpoint);
            break;
        }
    }

    let first = cursor.identifier()?;
    if first.quoted {
        return None;
    }
    let first = first.value.to_ascii_uppercase();
    let object_type = match first.as_str() {
        "PACKAGE" | "TYPE" => {
            let checkpoint = cursor.position();
            let body = cursor.identifier();
            if body
                .as_ref()
                .is_some_and(|body| !body.quoted && body.value.eq_ignore_ascii_case("BODY"))
            {
                format!("{first} BODY")
            } else {
                cursor.restore(checkpoint);
                first
            }
        }
        "PROCEDURE" | "FUNCTION" | "TRIGGER" | "VIEW" => first,
        _ => return None,
    };

    let first = cursor.identifier()?;
    let (owner, owner_quoted, name) = if cursor.consume_dot()? {
        let name = cursor.identifier()?;
        let owner = if first.quoted {
            first.value
        } else {
            first.value.to_ascii_uppercase()
        };
        (Some(owner), first.quoted, name)
    } else {
        (None, false, first)
    };
    if cursor.consume_dot()? {
        return None;
    }
    Some(SourceObjectTarget {
        owner,
        owner_quoted,
        name: if name.quoted {
            name.value
        } else {
            name.value.to_ascii_uppercase()
        },
        name_quoted: name.quoted,
        object_type,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedSourceIdentifier {
    value: String,
    quoted: bool,
}

/// Header-only Oracle lexer for the small recovery eligibility grammar. It
/// deliberately stops before the object body, but handles comments and quoted
/// identifiers without using whitespace splitting or quote stripping.
struct SourceHeaderCursor<'a> {
    sql: &'a str,
    offset: usize,
}

impl<'a> SourceHeaderCursor<'a> {
    fn new(sql: &'a str) -> Self {
        Self { sql, offset: 0 }
    }

    fn position(&self) -> usize {
        self.offset
    }

    fn restore(&mut self, offset: usize) {
        self.offset = offset;
    }

    fn consume_keyword(&mut self, expected: &str) -> Option<()> {
        let identifier = self.identifier()?;
        (!identifier.quoted && identifier.value.eq_ignore_ascii_case(expected)).then_some(())
    }

    fn consume_dot(&mut self) -> Option<bool> {
        self.skip_trivia()?;
        if self.remaining().starts_with('.') {
            self.offset += 1;
            Some(true)
        } else {
            Some(false)
        }
    }

    fn identifier(&mut self) -> Option<ParsedSourceIdentifier> {
        self.skip_trivia()?;
        if self.remaining().starts_with('"') {
            return self.quoted_identifier();
        }
        let bytes = self.sql.as_bytes();
        let start = self.offset;
        if !bytes.get(start).is_some_and(u8::is_ascii_alphabetic) {
            return None;
        }
        self.offset += 1;
        while bytes
            .get(self.offset)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'$' | b'#'))
        {
            self.offset += 1;
        }
        Some(ParsedSourceIdentifier {
            value: self.sql[start..self.offset].to_owned(),
            quoted: false,
        })
    }

    fn quoted_identifier(&mut self) -> Option<ParsedSourceIdentifier> {
        self.offset += 1;
        let start = self.offset;
        let bytes = self.sql.as_bytes();
        while let Some(byte) = bytes.get(self.offset) {
            match *byte {
                b'\0' => return None,
                b'"' => {
                    if bytes.get(self.offset + 1) == Some(&b'"') {
                        // Oracle object names cannot contain a double quote.
                        // Treat doubled-quote syntax as unsupported, never as a
                        // lossy spelling of another object.
                        return None;
                    }
                    let value = self.sql[start..self.offset].to_owned();
                    if value.is_empty() {
                        return None;
                    }
                    self.offset += 1;
                    if bytes.get(self.offset).is_some_and(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'$' | b'#' | b'"')
                    }) {
                        return None;
                    }
                    return Some(ParsedSourceIdentifier {
                        value,
                        quoted: true,
                    });
                }
                _ => self.offset += 1,
            }
        }
        None
    }

    fn skip_trivia(&mut self) -> Option<()> {
        loop {
            while self
                .sql
                .as_bytes()
                .get(self.offset)
                .is_some_and(u8::is_ascii_whitespace)
            {
                self.offset += 1;
            }
            if self.remaining().starts_with("--") {
                self.offset += 2;
                while self
                    .sql
                    .as_bytes()
                    .get(self.offset)
                    .is_some_and(|byte| !matches!(*byte, b'\n' | b'\r'))
                {
                    self.offset += 1;
                }
                continue;
            }
            if self.remaining().starts_with("/*") {
                let end = self.remaining()[2..].find("*/")?;
                self.offset += 2 + end + 2;
                continue;
            }
            return Some(());
        }
    }

    fn remaining(&self) -> &str {
        &self.sql[self.offset..]
    }
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
    let mut snapshot: SourceSnapshot =
        serde_json::from_slice(&bytes).map_err(|e| SourceHistoryError::Json(e.to_string()))?;
    if !matches!(
        snapshot.schema_version,
        LEGACY_SOURCE_HISTORY_SCHEMA_VERSION | SOURCE_HISTORY_SCHEMA_VERSION
    ) {
        return Err(SourceHistoryError::Invalid(
            "unsupported source-history schema version",
        ));
    }
    if snapshot.schema_version == LEGACY_SOURCE_HISTORY_SCHEMA_VERSION
        && snapshot.target_identity_sha256.is_empty()
    {
        snapshot.target_identity_sha256 =
            source_identity_sha256(&snapshot.owner, &snapshot.name, &snapshot.object_type);
    } else if snapshot.target_identity_sha256.is_empty() {
        return Err(SourceHistoryError::Invalid(
            "source-history target identity digest is required",
        ));
    }
    Ok(snapshot)
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

fn normalize_identifier(
    value: String,
    quoted: bool,
    field: &'static str,
) -> Result<String, SourceHistoryError> {
    if quoted {
        if value.is_empty() {
            return Err(SourceHistoryError::Invalid(match field {
                "owner" => "owner is required",
                "name" => "name is required",
                _ => "required field is empty",
            }));
        }
        if value.contains('"') || value.contains('\0') || value.len() > 128 {
            return Err(SourceHistoryError::Invalid(match field {
                "owner" => "owner is not a supported quoted identifier",
                "name" => "name is not a supported quoted identifier",
                _ => "invalid quoted identifier",
            }));
        }
        return Ok(value);
    }
    let value = normalize_non_empty(value, field)?;
    let value = value.to_ascii_uppercase();
    if !is_simple_source_name(&value) || value.contains('.') {
        return Err(SourceHistoryError::Invalid(match field {
            "owner" => "owner must be one unquoted identifier",
            "name" => "name must be one unquoted identifier",
            _ => "invalid identifier",
        }));
    }
    Ok(value)
}

fn render_identifier(value: &str, quoted: bool) -> String {
    if quoted {
        format!("\"{value}\"")
    } else {
        value.to_owned()
    }
}

pub(crate) fn source_identity_sha256(owner: &str, name: &str, object_type: &str) -> String {
    let mut bytes = Vec::new();
    for part in [owner, name, object_type] {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part.as_bytes());
    }
    oraclemcp_audit::sha256_hex(&bytes)
}

fn matches_optional_case_insensitive(expected: Option<&str>, actual: &str) -> bool {
    expected
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none_or(|value| value.eq_ignore_ascii_case(actual))
}

fn matches_optional_identifier(expected: Option<&str>, actual: &str) -> bool {
    let Some(expected) = expected.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };
    if let Some(quoted) = expected
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .filter(|value| !value.is_empty() && !value.contains('"'))
    {
        quoted == actual
    } else {
        expected.to_ascii_uppercase() == actual
    }
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
        assert!(!pkg.owner_quoted);
        assert_eq!(pkg.name, "EMP_API");
        assert!(!pkg.name_quoted);
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
    fn quoted_targets_preserve_identity_through_comments_and_edition_modifiers() {
        let target = source_object_from_create_or_replace_sql(
            "CREATE /* header */ OR\n-- still header\nREPLACE NONEDITIONABLE PROCEDURE \"MiXeD Owner\" . \"foo\"(p NUMBER) IS BEGIN NULL; END;",
        )
        .expect("quoted procedure target");
        assert_eq!(target.owner.as_deref(), Some("MiXeD Owner"));
        assert!(target.owner_quoted);
        assert_eq!(target.name, "foo");
        assert!(target.name_quoted);
        assert_eq!(target.object_type, "PROCEDURE");
        assert_eq!(target.owner_lookup().as_deref(), Some("\"MiXeD Owner\""));
        assert_eq!(target.name_lookup(), "\"foo\"");

        let spaced = source_object_from_create_or_replace_sql(
            "CREATE OR REPLACE PROCEDURE \" owner \".\" name \" IS BEGIN NULL; END;",
        )
        .expect("space-sensitive quoted target");
        assert_eq!(spaced.owner.as_deref(), Some(" owner "));
        assert_eq!(spaced.name, " name ");
    }

    #[test]
    fn quoted_lowercase_and_unquoted_uppercase_have_distinct_identities() {
        let unquoted = source_object_from_create_or_replace_sql(
            "CREATE OR REPLACE PROCEDURE foo IS BEGIN NULL; END;",
        )
        .expect("unquoted target");
        let quoted = source_object_from_create_or_replace_sql(
            "CREATE OR REPLACE PROCEDURE \"foo\" IS BEGIN NULL; END;",
        )
        .expect("quoted target");
        assert_eq!(unquoted.name, "FOO");
        assert_eq!(quoted.name, "foo");
        assert_ne!(
            unquoted.identity_sha256("APP"),
            quoted.identity_sha256("APP")
        );

        let quoted_upper = source_object_from_create_or_replace_sql(
            "CREATE OR REPLACE PROCEDURE \"FOO\" IS BEGIN NULL; END;",
        )
        .expect("quoted uppercase target");
        assert_eq!(
            unquoted.identity_sha256("APP"),
            quoted_upper.identity_sha256("APP"),
            "quoted uppercase and unquoted uppercase are the same Oracle identity"
        );
    }

    #[test]
    fn ambiguous_or_unsupported_target_syntax_fails_closed() {
        for sql in [
            "CREATE OR REPLACE PROCEDURE \"fo\"\"o\" IS BEGIN NULL; END;",
            "CREATE OR REPLACE PROCEDURE \"foo\"bar IS BEGIN NULL; END;",
            "CREATE OR REPLACE PROCEDURE app.foo.extra IS BEGIN NULL; END;",
            "CREATE OR REPLACE PROCEDURE app.",
            "CREATE /* unterminated OR REPLACE PROCEDURE foo IS BEGIN NULL; END;",
            "CREATE OR REPLACE \"PROCEDURE\" foo IS BEGIN NULL; END;",
        ] {
            assert!(
                source_object_from_create_or_replace_sql(sql).is_none(),
                "unsupported header must not be rebound: {sql}"
            );
        }
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
        let store = SourceHistoryStore::open(root).expect("source history");
        let source = "CREATE OR REPLACE PROCEDURE p IS BEGIN NULL; END;".to_owned();
        let view = store
            .record_snapshot(SourceSnapshotDraft {
                profile: "prod".to_owned(),
                owner: "app".to_owned(),
                owner_quoted: false,
                name: "p".to_owned(),
                name_quoted: false,
                object_type: "procedure".to_owned(),
                target_identity_sha256: source_identity_sha256("APP", "P", "PROCEDURE"),
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

    #[test]
    fn quoted_snapshot_metadata_and_identity_digest_round_trip() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/source-history-tests")
            .join(format!("{}-{stamp}-quoted", std::process::id()));
        let store = SourceHistoryStore::open(root).expect("source history");
        let target_identity_sha256 = source_identity_sha256("MiXeD Owner", "foo", "PROCEDURE");
        let draft = SourceSnapshotDraft {
            profile: "prod".to_owned(),
            owner: "MiXeD Owner".to_owned(),
            owner_quoted: true,
            name: "foo".to_owned(),
            name_quoted: true,
            object_type: "procedure".to_owned(),
            target_identity_sha256: target_identity_sha256.clone(),
            source_kind: "all_source".to_owned(),
            source: "CREATE OR REPLACE PROCEDURE \"foo\" IS BEGIN NULL; END;".to_owned(),
            proposal_id: "cp-quoted".to_owned(),
            statement_id: "stmt-quoted".to_owned(),
            statement_sql_sha256: "sha256:stmt".to_owned(),
            lane_id: Some("operator".to_owned()),
            subject_id_hash: "subject-sha256:test".to_owned(),
        };
        let mut wrong_digest = draft.clone();
        wrong_digest.target_identity_sha256 =
            source_identity_sha256("MiXeD Owner", "FOO", "PROCEDURE");
        assert!(matches!(
            store.record_snapshot(wrong_digest),
            Err(SourceHistoryError::Invalid(
                "source target identity changed before persistence"
            ))
        ));
        let mut wrong_source = draft.clone();
        wrong_source.source = "CREATE OR REPLACE PROCEDURE FOO IS BEGIN NULL; END;".to_owned();
        assert!(matches!(
            store.record_snapshot(wrong_source),
            Err(SourceHistoryError::Invalid(
                "snapshot source target does not match captured target"
            ))
        ));
        let view = store
            .record_snapshot(draft)
            .expect("quoted snapshot recorded");
        assert_eq!(view.owner, "MiXeD Owner");
        assert!(view.owner_quoted);
        assert_eq!(view.name, "foo");
        assert!(view.name_quoted);
        assert_eq!(view.target_identity_sha256, target_identity_sha256);
        assert_eq!(
            store
                .list(SourceHistoryFilter {
                    owner: Some("\"MiXeD Owner\"".to_owned()),
                    name: Some("\"foo\"".to_owned()),
                    ..Default::default()
                })
                .expect("quoted identity filter"),
            vec![view.clone()]
        );
        assert!(
            store
                .list(SourceHistoryFilter {
                    name: Some("foo".to_owned()),
                    ..Default::default()
                })
                .expect("unquoted identity filter")
                .is_empty(),
            "an unquoted foo filter denotes FOO, not quoted lowercase foo"
        );
        let loaded = store
            .load_snapshot(&view.id)
            .expect("quoted snapshot loaded");
        assert_eq!(loaded.view(), view);
    }

    fn history_root(name: &str) -> std::path::PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/source-history-tests")
            .join(format!("page-{name}-{}-{stamp}", std::process::id()))
    }

    fn record_procedure(store: &SourceHistoryStore, name: &str) -> SourceSnapshotView {
        let upper = name.to_ascii_uppercase();
        store
            .record_snapshot(SourceSnapshotDraft {
                profile: "prod".to_owned(),
                owner: "app".to_owned(),
                owner_quoted: false,
                name: name.to_owned(),
                name_quoted: false,
                object_type: "procedure".to_owned(),
                target_identity_sha256: source_identity_sha256("APP", &upper, "PROCEDURE"),
                source_kind: "all_source".to_owned(),
                source: format!("CREATE OR REPLACE PROCEDURE {name} IS BEGIN NULL; END;"),
                proposal_id: format!("cp-{name}"),
                statement_id: format!("stmt-{name}"),
                statement_sql_sha256: "sha256:stmt".to_owned(),
                lane_id: Some("operator".to_owned()),
                subject_id_hash: "subject-sha256:test".to_owned(),
            })
            .expect("snapshot recorded")
    }

    #[test]
    fn list_page_bounds_and_paginates_without_leaking_source() {
        let store = SourceHistoryStore::open(history_root("bound")).expect("store");
        let total = LIST_PAGE_SIZE + 3;
        for i in 0..total {
            record_procedure(&store, &format!("p{i}"));
        }

        let first = store
            .list_page(SourceHistoryFilter::default(), None)
            .expect("first page");
        assert_eq!(first.snapshots.len(), LIST_PAGE_SIZE, "page is capped");
        assert!(!first.etag.is_empty());
        let rendered = serde_json::to_string(&first.snapshots).expect("serialize page");
        assert!(
            !rendered.contains("BEGIN NULL"),
            "history rows never carry source text"
        );

        let cursor = first.next_cursor.clone().expect("more pages remain");
        let second = store
            .list_page(SourceHistoryFilter::default(), Some(&cursor))
            .expect("second page");
        assert_eq!(second.snapshots.len(), total - LIST_PAGE_SIZE);
        assert!(second.next_cursor.is_none(), "last page has no cursor");

        let mut ids: Vec<String> = first.snapshots.iter().map(|s| s.id.clone()).collect();
        ids.extend(second.snapshots.iter().map(|s| s.id.clone()));
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), total, "every row appears exactly once");

        // A row appended after the cursor was minted changes the validator, so
        // the cursor is rejected as stale instead of skipping or duplicating.
        record_procedure(&store, "pnew");
        let stale = store
            .list_page(SourceHistoryFilter::default(), Some(&cursor))
            .expect_err("stale cursor rejected");
        assert!(matches!(stale, SourceHistoryError::Invalid(_)));
    }

    #[test]
    fn list_page_skips_a_malformed_record_line() {
        let root = history_root("malformed");
        let store = SourceHistoryStore::open(&root).expect("store");
        let good = record_procedure(&store, "good");

        let dir = root.join(SOURCE_HISTORY_COLLECTION);
        for entry in fs::read_dir(&dir).expect("read history dir") {
            let path = entry.expect("dir entry").path();
            if path.extension().and_then(|ext| ext.to_str()) == Some("jsonl") {
                use std::io::Write as _;
                let mut file = fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .expect("open jsonl");
                file.write_all(b"{ this is not valid json\n")
                    .expect("append corrupt line");
            }
        }

        let page = store
            .list_page(SourceHistoryFilter::default(), None)
            .expect("a single corrupt line must not fail the listing");
        assert_eq!(page.snapshots.len(), 1);
        assert_eq!(page.snapshots[0].id, good.id);
    }

    #[test]
    fn etag_tracks_appends_and_matches_the_page() {
        let store = SourceHistoryStore::open(history_root("etag")).expect("store");
        let empty = store.etag().expect("empty etag");
        assert_eq!(empty, store.etag().expect("empty etag again"));

        record_procedure(&store, "p1");
        let one = store.etag().expect("etag after append");
        assert_ne!(one, empty, "an append changes the validator");
        let page = store
            .list_page(SourceHistoryFilter::default(), None)
            .expect("page");
        assert_eq!(one, page.etag, "the page reports the current validator");
    }
}
