//! Durable operator change proposals for the dashboard review board.
//!
//! Proposals are service-owned files under the shared [`FileStore`]. They are
//! deliberately not lane-bound: a lane is selected only when an operator applies
//! the proposal through `/operator/v1/change-proposals/apply`.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use oraclemcp_guard::{
    Classifier, EditionLifecycleParse, EditionLifecycleSql, OperatingLevel,
    parse_edition_lifecycle_sql,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::file_store::{FileStore, FileStoreError, ServiceOwner, StoreId};
use crate::pagination::{LIST_PAGE_SIZE, decode_cursor, encode_cursor};

const CHANGE_PROPOSAL_COLLECTION: &str = "change-proposals";
const CHANGE_PROPOSAL_EXTENSION: &str = "json";
const CHANGE_PROPOSAL_SCHEMA_VERSION: u8 = 1;
const MAX_PROPOSAL_STATEMENTS: usize = 32;
const EDITION_PROPOSAL_COLLECTION: &str = "edition-proposals";
const EDITION_PROPOSAL_EXTENSION: &str = "json";
const EDITION_PROPOSAL_SCHEMA_VERSION: u8 = 1;
const MAX_EDITION_PROPOSAL_OBJECTS: usize = 64;
/// Tamper-token scope for change-proposal list cursors.
const CHANGE_PROPOSAL_CURSOR_KIND: &str = "change-proposals";

/// Persistent change-proposal store.
pub struct ChangeProposalStore {
    store: FileStore,
    owner: ServiceOwner,
}

impl ChangeProposalStore {
    /// Open the default service-owned proposal store.
    pub fn open_default() -> Result<Self, ChangeProposalError> {
        Self::open(FileStore::default_state_dir()?)
    }

    /// Open a standalone proposal store rooted at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ChangeProposalError> {
        let store = FileStore::open(root)?;
        let owner = store.acquire_service_owner("change-proposals")?;
        Ok(Self { store, owner })
    }

    /// Open the proposal store under an existing process-wide service owner.
    pub fn open_with_owner(owner: ServiceOwner) -> Result<Self, ChangeProposalError> {
        let store = FileStore::open(owner.root())?;
        Ok(Self { store, owner })
    }

    /// List proposal board entries. Bind values are never included in the view.
    pub fn list(&self) -> Result<Vec<ChangeProposalView>, ChangeProposalError> {
        let dir = self.store.root().join(CHANGE_PROPOSAL_COLLECTION);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut proposals = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|e| ChangeProposalError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| ChangeProposalError::Io(e.to_string()))?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some(CHANGE_PROPOSAL_EXTENSION) {
                continue;
            }
            let proposal = load_proposal_from_path(&path)?;
            proposals.push(proposal.view());
        }
        proposals.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then_with(|| a.profile.cmp(&b.profile))
                .then_with(|| a.title.cmp(&b.title))
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(proposals)
    }

    /// Conditional-request validator for the proposal board.
    ///
    /// Unchanged between two polls, it lets the caller answer `304 Not Modified`
    /// without rebuilding the board; it also doubles as the [`list_page`] cursor
    /// revision so a cursor minted against an older store is rejected as stale.
    ///
    /// [`list_page`]: ChangeProposalStore::list_page
    pub fn etag(&self) -> Result<String, ChangeProposalError> {
        Ok(self.store.collection_etag(CHANGE_PROPOSAL_COLLECTION)?)
    }

    /// List one bounded, newest-first page of proposal board entries.
    ///
    /// Unlike [`list`], the projection never carries `sql_template`: only
    /// lightweight metadata and the per-statement digest ride in the page, so the
    /// polled response stays small. Fetch the full SQL on selection through
    /// [`detail`]. A single malformed or oversized proposal file is skipped
    /// rather than failing the whole board, and the page is capped at
    /// [`LIST_PAGE_SIZE`] with an opaque signed `next_cursor` when more remain.
    ///
    /// [`list`]: ChangeProposalStore::list
    /// [`detail`]: ChangeProposalStore::detail
    pub fn list_page(
        &self,
        cursor: Option<&str>,
    ) -> Result<ChangeProposalPage, ChangeProposalError> {
        let etag = self.etag()?;
        let dir = self.store.root().join(CHANGE_PROPOSAL_COLLECTION);
        let mut proposals = Vec::new();
        if dir.exists() {
            for entry in fs::read_dir(&dir).map_err(|e| ChangeProposalError::Io(e.to_string()))? {
                let entry = entry.map_err(|e| ChangeProposalError::Io(e.to_string()))?;
                let path = entry.path();
                if path.extension().and_then(|ext| ext.to_str()) != Some(CHANGE_PROPOSAL_EXTENSION)
                {
                    continue;
                }
                // A single corrupt or oversized record must fail locally, never
                // hide the entire board from the operator.
                if let Ok(proposal) = load_proposal_from_path(&path) {
                    proposals.push(proposal.list_view());
                }
            }
        }
        proposals.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then_with(|| a.profile.cmp(&b.profile))
                .then_with(|| a.title.cmp(&b.title))
                .then_with(|| a.id.cmp(&b.id))
        });
        let offset = decode_cursor(CHANGE_PROPOSAL_CURSOR_KIND, &etag, cursor)
            .map_err(|_| ChangeProposalError::Invalid("invalid or stale pagination cursor"))?
            .min(proposals.len());
        let end = offset.saturating_add(LIST_PAGE_SIZE).min(proposals.len());
        let next_cursor =
            (end < proposals.len()).then(|| encode_cursor(CHANGE_PROPOSAL_CURSOR_KIND, &etag, end));
        Ok(ChangeProposalPage {
            proposals: proposals[offset..end].to_vec(),
            next_cursor,
            etag,
        })
    }

    /// Load one proposal's full review view, including the `sql_template` bodies
    /// that the list projection omits. Bind values remain redacted.
    pub fn detail(&self, id: &str) -> Result<ChangeProposalView, ChangeProposalError> {
        Ok(self.load(id)?.view())
    }

    /// Persist a new proposal draft and return the redacted board view.
    pub fn draft(
        &self,
        request: ChangeProposalDraftRequest,
        author_id_hash: String,
    ) -> Result<ChangeProposalDraftOutcome, ChangeProposalError> {
        let proposal = ChangeProposal::from_draft(request, author_id_hash)?;
        let id = StoreId::from_safe_segment(proposal.id.clone())?;
        let mut bytes = serde_json::to_vec_pretty(&proposal)
            .map_err(|e| ChangeProposalError::Json(e.to_string()))?;
        bytes.push(b'\n');
        let _mutation = self.owner.mutation_guard();
        let path = self.store.write_atomic(
            &self.owner,
            CHANGE_PROPOSAL_COLLECTION,
            &id,
            CHANGE_PROPOSAL_EXTENSION,
            &bytes,
        )?;
        Ok(ChangeProposalDraftOutcome {
            proposal: proposal.view(),
            path,
        })
    }

    /// Load one full proposal for apply.
    pub fn load(&self, id: &str) -> Result<ChangeProposal, ChangeProposalError> {
        let id = StoreId::from_safe_segment(id.trim().to_owned())?;
        let path =
            self.store
                .path_for(CHANGE_PROPOSAL_COLLECTION, &id, CHANGE_PROPOSAL_EXTENSION)?;
        if !path.exists() {
            return Err(ChangeProposalError::UnknownProposal);
        }
        load_proposal_from_path(&path)
    }

    /// List Edition-Based Redefinition requests shown beside ordinary change
    /// proposals on the Reviews board. These records are requests only: they
    /// contain no SQL, confirmation, verdict, or executable authority.
    pub fn list_edition_proposals(&self) -> Result<Vec<EditionProposalView>, ChangeProposalError> {
        let dir = self.store.root().join(EDITION_PROPOSAL_COLLECTION);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut proposals = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|e| ChangeProposalError::Io(e.to_string()))? {
            let entry = entry.map_err(|e| ChangeProposalError::Io(e.to_string()))?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some(EDITION_PROPOSAL_EXTENSION) {
                continue;
            }
            proposals.push(load_edition_proposal_from_path(&path)?.view());
        }
        proposals.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then_with(|| a.profile.cmp(&b.profile))
                .then_with(|| a.proposal_id.cmp(&b.proposal_id))
        });
        Ok(proposals)
    }

    /// Persist a new Edition-Based Redefinition request. Persisting this
    /// request does not create an edition, evaluate a statement, issue a grant,
    /// or otherwise authorize a guarded write.
    pub fn create_edition_proposal(
        &self,
        request: EditionProposalCreateRequest,
    ) -> Result<EditionProposalView, ChangeProposalError> {
        let proposal = EditionProposal::from_request(request)?;
        self.write_edition_proposal(&proposal)?;
        Ok(proposal.view())
    }

    /// Move an Edition-Based Redefinition request through its non-authorizing
    /// Reviews-board lifecycle. The only mutable field is the board status;
    /// this method cannot forward or synthesize a database action.
    pub fn transition_edition_proposal(
        &self,
        request: EditionProposalTransitionRequest,
    ) -> Result<EditionProposalView, ChangeProposalError> {
        let mut proposal = self.load_edition_proposal(&request.proposal_id)?;
        proposal.transition_to(request.status)?;
        self.write_edition_proposal(&proposal)?;
        Ok(proposal.view())
    }

    fn load_edition_proposal(
        &self,
        proposal_id: &str,
    ) -> Result<EditionProposal, ChangeProposalError> {
        let id = StoreId::from_safe_segment(proposal_id.trim().to_owned())?;
        let path =
            self.store
                .path_for(EDITION_PROPOSAL_COLLECTION, &id, EDITION_PROPOSAL_EXTENSION)?;
        if !path.exists() {
            return Err(ChangeProposalError::UnknownEditionProposal);
        }
        load_edition_proposal_from_path(&path)
    }

    fn write_edition_proposal(
        &self,
        proposal: &EditionProposal,
    ) -> Result<(), ChangeProposalError> {
        let id = StoreId::from_safe_segment(proposal.proposal_id.clone())?;
        let mut bytes = serde_json::to_vec_pretty(proposal)
            .map_err(|e| ChangeProposalError::Json(e.to_string()))?;
        bytes.push(b'\n');
        let _mutation = self.owner.mutation_guard();
        self.store.write_atomic(
            &self.owner,
            EDITION_PROPOSAL_COLLECTION,
            &id,
            EDITION_PROPOSAL_EXTENSION,
            &bytes,
        )?;
        Ok(())
    }
}

/// Operator-facing proposal-store errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ChangeProposalError {
    /// File-store operation failed.
    #[error(transparent)]
    FileStore(#[from] FileStoreError),
    /// Plain I/O operation failed.
    #[error("change proposal io error: {0}")]
    Io(String),
    /// JSON serialization or parsing failed.
    #[error("change proposal json error: {0}")]
    Json(String),
    /// The request body is malformed, or a pagination cursor was invalid,
    /// tampered, or stale.
    #[error("invalid change proposal: {0}")]
    Invalid(&'static str),
    /// The requested proposal id does not exist.
    #[error("unknown change proposal")]
    UnknownProposal,
    /// The requested edition proposal id does not exist.
    #[error("unknown edition proposal")]
    UnknownEditionProposal,
}

/// A non-authorizing request to stage editionable objects in one child edition.
///
/// This is intentionally separate from [`ChangeProposalDraftRequest`]: a
/// Reviews-board record must never smuggle SQL, bind values, stored verdicts,
/// confirmation tokens, or an `execute` switch into a later action path.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EditionProposalCreateRequest {
    pub profile: String,
    pub child_edition: String,
    pub base_edition: String,
    pub objects: Vec<String>,
}

/// The deliberately narrow lifecycle recorded by the Reviews board.
///
/// No status means an edition has been created, applied, merged, or otherwise
/// authorized. Those effects belong to later guarded actions, which must
/// classify at their point of execution.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EditionProposalStatus {
    Requested,
    Reviewing,
    Withdrawn,
}

/// A request to update one persisted Reviews-board status.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EditionProposalTransitionRequest {
    pub proposal_id: String,
    pub status: EditionProposalStatus,
}

/// Full on-disk edition-proposal record.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EditionProposal {
    pub schema_version: u8,
    pub proposal_id: String,
    pub profile: String,
    pub child_edition: String,
    pub base_edition: String,
    pub objects: Vec<String>,
    pub status: EditionProposalStatus,
    pub created_at: String,
    pub updated_at: String,
}

impl EditionProposal {
    fn from_request(request: EditionProposalCreateRequest) -> Result<Self, ChangeProposalError> {
        let profile = normalize_non_empty(request.profile, "profile")?;
        let child_edition = normalize_edition_identifier(request.child_edition)?;
        let base_edition = normalize_edition_identifier(request.base_edition)?;
        if child_edition == base_edition {
            return Err(ChangeProposalError::Invalid(
                "child_edition must differ from base_edition",
            ));
        }
        if request.objects.is_empty() {
            return Err(ChangeProposalError::Invalid(
                "edition proposal must name at least one object",
            ));
        }
        if request.objects.len() > MAX_EDITION_PROPOSAL_OBJECTS {
            return Err(ChangeProposalError::Invalid(
                "edition proposal has too many objects",
            ));
        }
        let mut objects = request
            .objects
            .into_iter()
            .map(normalize_edition_object)
            .collect::<Result<Vec<_>, _>>()?;
        objects.sort();
        objects.dedup();
        if objects.is_empty() {
            return Err(ChangeProposalError::Invalid(
                "edition proposal must name at least one object",
            ));
        }

        let now = unix_timestamp();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos().to_string())
            .unwrap_or_else(|_| "0".to_owned());
        let mut id_parts = vec![
            profile.as_str(),
            child_edition.as_str(),
            base_edition.as_str(),
            now.as_str(),
            nonce.as_str(),
        ];
        id_parts.extend(objects.iter().map(String::as_str));
        let proposal_id = StoreId::content_hashed("edition", &id_parts)?
            .as_str()
            .to_owned();

        Ok(Self {
            schema_version: EDITION_PROPOSAL_SCHEMA_VERSION,
            proposal_id,
            profile,
            child_edition,
            base_edition,
            objects,
            status: EditionProposalStatus::Requested,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    fn transition_to(&mut self, next: EditionProposalStatus) -> Result<(), ChangeProposalError> {
        let valid = matches!(
            (self.status, next),
            (
                EditionProposalStatus::Requested,
                EditionProposalStatus::Reviewing | EditionProposalStatus::Withdrawn
            ) | (
                EditionProposalStatus::Reviewing,
                EditionProposalStatus::Requested | EditionProposalStatus::Withdrawn
            )
        );
        if !valid {
            return Err(ChangeProposalError::Invalid(
                "edition proposal status transition is not allowed",
            ));
        }
        self.status = next;
        self.updated_at = unix_timestamp();
        Ok(())
    }

    fn view(&self) -> EditionProposalView {
        EditionProposalView {
            schema_version: self.schema_version,
            proposal_id: self.proposal_id.clone(),
            profile: self.profile.clone(),
            child_edition: self.child_edition.clone(),
            base_edition: self.base_edition.clone(),
            objects: self.objects.clone(),
            status: self.status,
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
        }
    }

    fn validate(&self) -> Result<(), ChangeProposalError> {
        if self.schema_version != EDITION_PROPOSAL_SCHEMA_VERSION {
            return Err(ChangeProposalError::Invalid(
                "unsupported edition proposal schema version",
            ));
        }
        if StoreId::from_safe_segment(self.proposal_id.clone()).is_err()
            || normalize_non_empty(self.profile.clone(), "profile")? != self.profile
            || normalize_edition_identifier(self.child_edition.clone())? != self.child_edition
            || normalize_edition_identifier(self.base_edition.clone())? != self.base_edition
            || self.child_edition == self.base_edition
            || self.objects.is_empty()
            || self.objects.len() > MAX_EDITION_PROPOSAL_OBJECTS
        {
            return Err(ChangeProposalError::Invalid(
                "invalid edition proposal record",
            ));
        }
        let mut canonical_objects = self
            .objects
            .iter()
            .cloned()
            .map(normalize_edition_object)
            .collect::<Result<Vec<_>, _>>()?;
        canonical_objects.sort();
        canonical_objects.dedup();
        if canonical_objects != self.objects {
            return Err(ChangeProposalError::Invalid(
                "invalid edition proposal objects",
            ));
        }
        Ok(())
    }
}

/// Redacted Reviews-board representation of an edition request.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct EditionProposalView {
    pub schema_version: u8,
    pub proposal_id: String,
    pub profile: String,
    pub child_edition: String,
    pub base_edition: String,
    pub objects: Vec<String>,
    pub status: EditionProposalStatus,
    pub created_at: String,
    pub updated_at: String,
}

/// New proposal request.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ChangeProposalDraftRequest {
    pub profile: String,
    pub author: ChangeProposalAuthorKind,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub statements: Vec<ChangeProposalStatementDraft>,
    #[serde(default)]
    pub stored_verdict: Option<Value>,
}

/// Apply request for one stored proposal.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ChangeProposalApplyRequest {
    pub proposal_id: String,
    #[serde(default)]
    pub lane_id: Option<String>,
    #[serde(default)]
    pub confirm: Option<String>,
    #[serde(default)]
    pub commit: Option<bool>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

/// Proposal author class.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeProposalAuthorKind {
    Agent,
    Human,
}

/// Draft statement. `sql_template` is the only SQL text field; bind values stay
/// out of list views and the classifier always evaluates the template.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ChangeProposalStatementDraft {
    pub sql_template: String,
    #[serde(default)]
    pub binds: Vec<Value>,
    #[serde(default)]
    pub unit: Option<ChangeProposalApplyUnit>,
    #[serde(default)]
    pub commit: Option<bool>,
    #[serde(default)]
    pub capture_dbms_output: Option<bool>,
    #[serde(default)]
    pub stored_verdict: Option<Value>,
}

/// Apply unit semantics. Multi-statement apply is sequential and stops at the
/// first failed unit; it does not claim all-or-nothing DDL atomicity.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeProposalApplyUnit {
    Read,
    Dml,
    Ddl,
}

/// Full on-disk proposal.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ChangeProposal {
    pub schema_version: u8,
    pub id: String,
    pub profile: String,
    pub author: ChangeProposalAuthorKind,
    pub author_id_hash: String,
    pub title: String,
    pub created_at: String,
    pub updated_at: String,
    pub statements: Vec<ChangeProposalStatement>,
    #[serde(default)]
    pub stored_verdict: Option<Value>,
}

impl ChangeProposal {
    fn from_draft(
        request: ChangeProposalDraftRequest,
        author_id_hash: String,
    ) -> Result<Self, ChangeProposalError> {
        let profile = normalize_non_empty(request.profile, "profile")?;
        let title = request
            .title
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("Change Proposal")
            .to_owned();
        if request.statements.is_empty() {
            return Err(ChangeProposalError::Invalid(
                "proposal must include at least one statement",
            ));
        }
        if request.statements.len() > MAX_PROPOSAL_STATEMENTS {
            return Err(ChangeProposalError::Invalid(
                "proposal has too many statements",
            ));
        }
        let now = unix_timestamp();
        let mut statements = Vec::with_capacity(request.statements.len());
        let mut id_parts = vec![
            profile.as_str(),
            title.as_str(),
            author_id_hash.as_str(),
            now.as_str(),
        ];
        let draft_statements = request.statements;
        for draft in &draft_statements {
            id_parts.push(draft.sql_template.as_str());
        }
        let proposal_id = StoreId::content_hashed("cp", &id_parts)?
            .as_str()
            .to_owned();
        for (index, draft) in draft_statements.into_iter().enumerate() {
            statements.push(ChangeProposalStatement::from_draft(
                index,
                &proposal_id,
                draft,
            )?);
        }
        Ok(Self {
            schema_version: CHANGE_PROPOSAL_SCHEMA_VERSION,
            id: proposal_id,
            profile,
            author: request.author,
            author_id_hash,
            title,
            created_at: now.clone(),
            updated_at: now,
            statements,
            stored_verdict: request.stored_verdict,
        })
    }

    /// Bounded list projection for the polled board endpoint. It carries the
    /// same metadata as [`ChangeProposal::view`] but omits every `sql_template`
    /// body (retained only in the detail view) so list responses stay small even
    /// as the proposal corpus grows. Bind values and stored verdicts remain
    /// redacted exactly as in [`ChangeProposal::view`].
    #[must_use]
    pub fn list_view(&self) -> ChangeProposalListView {
        ChangeProposalListView {
            schema_version: self.schema_version,
            id: self.id.clone(),
            profile: self.profile.clone(),
            author: self.author,
            author_id_hash: self.author_id_hash.clone(),
            title: self.title.clone(),
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
            statement_count: self.statements.len(),
            statements: self
                .statements
                .iter()
                .map(ChangeProposalStatement::list_view)
                .collect(),
            stored_verdict_present: self.stored_verdict.is_some(),
        }
    }

    /// Redacted board view. It keeps templates visible for review but omits
    /// captured bind values and any stored verdict payload.
    #[must_use]
    pub fn view(&self) -> ChangeProposalView {
        ChangeProposalView {
            schema_version: self.schema_version,
            id: self.id.clone(),
            profile: self.profile.clone(),
            author: self.author,
            author_id_hash: self.author_id_hash.clone(),
            title: self.title.clone(),
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
            statement_count: self.statements.len(),
            statements: self
                .statements
                .iter()
                .map(ChangeProposalStatement::view)
                .collect(),
            stored_verdict_present: self.stored_verdict.is_some(),
        }
    }
}

/// Full on-disk statement.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ChangeProposalStatement {
    pub id: String,
    pub unit: ChangeProposalApplyUnit,
    pub sql_template: String,
    #[serde(default)]
    pub binds: Vec<Value>,
    pub commit: bool,
    pub capture_dbms_output: bool,
    pub draft_verdict: ChangeProposalClassifierView,
    #[serde(default)]
    pub stored_verdict: Option<Value>,
}

impl ChangeProposalStatement {
    fn from_draft(
        index: usize,
        proposal_id: &str,
        draft: ChangeProposalStatementDraft,
    ) -> Result<Self, ChangeProposalError> {
        let sql_template = normalize_non_empty(draft.sql_template, "sql_template")?;
        let decision = Classifier::default().classify(&sql_template);
        let unit = draft
            .unit
            .unwrap_or_else(|| unit_for_required_level(decision.required_level));
        let commit = draft
            .commit
            .unwrap_or(matches!(unit, ChangeProposalApplyUnit::Ddl));
        let id = StoreId::content_hashed(
            "stmt",
            &[proposal_id, &index.to_string(), sql_template.as_str()],
        )?
        .as_str()
        .to_owned();
        Ok(Self {
            id,
            unit,
            sql_template,
            binds: draft.binds,
            commit,
            capture_dbms_output: draft.capture_dbms_output.unwrap_or(false),
            draft_verdict: ChangeProposalClassifierView::from_decision(decision),
            stored_verdict: draft.stored_verdict,
        })
    }

    /// Re-run the classifier for apply-time reporting. The dispatcher will
    /// classify again inside the MCP tool; this view is for the review result.
    #[must_use]
    pub fn reclassified_view(&self) -> ChangeProposalClassifierView {
        ChangeProposalClassifierView::from_decision(
            Classifier::default().classify(self.sql_template.as_str()),
        )
    }

    fn view(&self) -> ChangeProposalStatementView {
        ChangeProposalStatementView {
            id: self.id.clone(),
            unit: self.unit,
            sql_template: self.sql_template.clone(),
            sql_sha256: prefixed_sha256_hex(self.sql_template.as_bytes()),
            bind_count: self.binds.len(),
            commit: self.commit,
            capture_dbms_output: self.capture_dbms_output,
            draft_verdict: self.draft_verdict.clone(),
            stored_verdict_present: self.stored_verdict.is_some(),
        }
    }

    /// List projection that carries the SQL digest but not the `sql_template`
    /// body itself, so the polled board response stays bounded.
    fn list_view(&self) -> ChangeProposalStatementListView {
        ChangeProposalStatementListView {
            id: self.id.clone(),
            unit: self.unit,
            sql_sha256: prefixed_sha256_hex(self.sql_template.as_bytes()),
            bind_count: self.binds.len(),
            commit: self.commit,
            capture_dbms_output: self.capture_dbms_output,
            draft_verdict: self.draft_verdict.clone(),
            stored_verdict_present: self.stored_verdict.is_some(),
        }
    }
}

/// Redacted draft outcome.
#[derive(Clone, Debug, PartialEq)]
pub struct ChangeProposalDraftOutcome {
    pub proposal: ChangeProposalView,
    pub path: PathBuf,
}

/// Redacted proposal view for list/draft responses.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ChangeProposalView {
    pub schema_version: u8,
    pub id: String,
    pub profile: String,
    pub author: ChangeProposalAuthorKind,
    pub author_id_hash: String,
    pub title: String,
    pub created_at: String,
    pub updated_at: String,
    pub statement_count: usize,
    pub statements: Vec<ChangeProposalStatementView>,
    pub stored_verdict_present: bool,
}

/// Redacted statement view for the board.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ChangeProposalStatementView {
    pub id: String,
    pub unit: ChangeProposalApplyUnit,
    pub sql_template: String,
    pub sql_sha256: String,
    pub bind_count: usize,
    pub commit: bool,
    pub capture_dbms_output: bool,
    pub draft_verdict: ChangeProposalClassifierView,
    pub stored_verdict_present: bool,
}

/// One bounded page of proposal board entries plus its conditional-request
/// validator. Every entry omits `sql_template` (see [`ChangeProposalListView`]).
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct ChangeProposalPage {
    /// The newest-first list projections in this page.
    pub proposals: Vec<ChangeProposalListView>,
    /// Opaque signed cursor for the next page, or `None` when exhausted.
    pub next_cursor: Option<String>,
    /// Validator matching [`ChangeProposalStore::etag`]; also the cursor
    /// revision, so a cursor is rejected once the store changes under it.
    pub etag: String,
}

/// Redacted list projection for the polled board. It mirrors
/// [`ChangeProposalView`] but drops every `sql_template` body.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ChangeProposalListView {
    pub schema_version: u8,
    pub id: String,
    pub profile: String,
    pub author: ChangeProposalAuthorKind,
    pub author_id_hash: String,
    pub title: String,
    pub created_at: String,
    pub updated_at: String,
    pub statement_count: usize,
    pub statements: Vec<ChangeProposalStatementListView>,
    pub stored_verdict_present: bool,
}

/// Redacted statement list projection: the SQL digest without the SQL body.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ChangeProposalStatementListView {
    pub id: String,
    pub unit: ChangeProposalApplyUnit,
    pub sql_sha256: String,
    pub bind_count: usize,
    pub commit: bool,
    pub capture_dbms_output: bool,
    pub draft_verdict: ChangeProposalClassifierView,
    pub stored_verdict_present: bool,
}

/// Stable classifier summary for proposal review.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChangeProposalClassifierView {
    pub required_level: Option<String>,
    pub danger: String,
    pub reason: String,
}

impl ChangeProposalClassifierView {
    fn from_decision(decision: oraclemcp_guard::GuardDecision) -> Self {
        Self {
            required_level: decision
                .required_level
                .map(|level| level.as_str().to_owned()),
            danger: serde_json::to_value(decision.danger)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| format!("{:?}", decision.danger)),
            reason: decision.reason,
        }
    }
}

fn load_proposal_from_path(path: &Path) -> Result<ChangeProposal, ChangeProposalError> {
    let bytes = fs::read(path).map_err(|e| ChangeProposalError::Io(e.to_string()))?;
    let proposal: ChangeProposal =
        serde_json::from_slice(&bytes).map_err(|e| ChangeProposalError::Json(e.to_string()))?;
    if proposal.schema_version != CHANGE_PROPOSAL_SCHEMA_VERSION {
        return Err(ChangeProposalError::Invalid(
            "unsupported change proposal schema version",
        ));
    }
    Ok(proposal)
}

fn load_edition_proposal_from_path(path: &Path) -> Result<EditionProposal, ChangeProposalError> {
    let bytes = fs::read(path).map_err(|e| ChangeProposalError::Io(e.to_string()))?;
    let proposal: EditionProposal =
        serde_json::from_slice(&bytes).map_err(|e| ChangeProposalError::Json(e.to_string()))?;
    proposal.validate()?;
    Ok(proposal)
}

fn normalize_edition_identifier(value: String) -> Result<String, ChangeProposalError> {
    let value = normalize_non_empty(value, "edition")?;
    let candidate = format!("CREATE EDITION {value} AS CHILD OF ORACLEMCP_BASE");
    match parse_edition_lifecycle_sql(&candidate) {
        EditionLifecycleParse::Parsed(EditionLifecycleSql::CreateChild { child, .. }) => {
            Ok(child.as_str().to_owned())
        }
        _ => Err(ChangeProposalError::Invalid(
            "edition must be one Oracle identifier",
        )),
    }
}

fn normalize_edition_object(value: String) -> Result<String, ChangeProposalError> {
    let value = normalize_non_empty(value, "object")?;
    if value.len() > 512
        || value
            .chars()
            .any(|character| character.is_control() || character == ';')
    {
        return Err(ChangeProposalError::Invalid(
            "edition proposal object is not safe metadata",
        ));
    }
    Ok(value)
}

fn normalize_non_empty(value: String, field: &'static str) -> Result<String, ChangeProposalError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ChangeProposalError::Invalid(match field {
            "profile" => "profile is required",
            "sql_template" => "sql_template is required",
            _ => "required field is empty",
        }));
    }
    if value.len() > 256 * 1024 {
        return Err(ChangeProposalError::Invalid("field exceeds size limit"));
    }
    Ok(value.to_owned())
}

fn unit_for_required_level(required: Option<OperatingLevel>) -> ChangeProposalApplyUnit {
    match required {
        Some(OperatingLevel::ReadWrite) => ChangeProposalApplyUnit::Dml,
        Some(OperatingLevel::Ddl | OperatingLevel::Admin) => ChangeProposalApplyUnit::Ddl,
        Some(OperatingLevel::ReadOnly) | None => ChangeProposalApplyUnit::Read,
        Some(_) => ChangeProposalApplyUnit::Ddl,
    }
}

fn unix_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{secs:020}")
}

fn prefixed_sha256_hex(bytes: &[u8]) -> String {
    format!("sha256:{}", oraclemcp_audit::sha256_hex(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposal_view_omits_bind_values_and_stored_verdict_payloads() {
        let request = ChangeProposalDraftRequest {
            profile: "prod".to_owned(),
            author: ChangeProposalAuthorKind::Agent,
            title: Some("Hold account".to_owned()),
            statements: vec![ChangeProposalStatementDraft {
                sql_template: "UPDATE accounts SET status = :1 WHERE id = :2".to_owned(),
                binds: vec![Value::String("SECRET".to_owned()), Value::from(42)],
                unit: None,
                commit: Some(false),
                capture_dbms_output: None,
                stored_verdict: Some(serde_json::json!({ "required_level": "READ_ONLY" })),
            }],
            stored_verdict: Some(serde_json::json!({ "required_level": "READ_ONLY" })),
        };
        let proposal = ChangeProposal::from_draft(request, "subject-sha256:test".to_owned())
            .expect("proposal builds");
        let view = proposal.view();
        let rendered = serde_json::to_string(&view).expect("view serializes");
        assert!(!rendered.contains("SECRET"));
        assert!(!rendered.contains(r#""required_level":"READ_ONLY""#));
        assert!(rendered.contains("sql_template"));
        assert_eq!(
            view.statements[0].draft_verdict.required_level.as_deref(),
            Some("READ_WRITE")
        );
    }

    fn store_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/change-proposal-tests")
            .join(format!("{name}-{}-{stamp}", std::process::id()))
    }

    fn draft_one(store: &ChangeProposalStore, title: &str, sql: &str) -> ChangeProposalView {
        store
            .draft(
                ChangeProposalDraftRequest {
                    profile: "prod".to_owned(),
                    author: ChangeProposalAuthorKind::Agent,
                    title: Some(title.to_owned()),
                    statements: vec![ChangeProposalStatementDraft {
                        sql_template: sql.to_owned(),
                        binds: Vec::new(),
                        unit: None,
                        commit: None,
                        capture_dbms_output: None,
                        stored_verdict: None,
                    }],
                    stored_verdict: None,
                },
                "subject-sha256:test".to_owned(),
            )
            .expect("draft")
            .proposal
    }

    #[test]
    fn list_page_omits_sql_template_but_detail_retains_it() {
        let store = ChangeProposalStore::open(store_root("strip")).expect("store");
        let view = draft_one(
            &store,
            "Hold",
            "UPDATE accounts SET status = :1 WHERE id = :2",
        );

        let page = store.list_page(None).expect("page");
        assert_eq!(page.proposals.len(), 1);
        assert!(page.next_cursor.is_none());
        assert!(!page.etag.is_empty());
        let rendered = serde_json::to_string(&page.proposals).expect("serialize list page");
        assert!(
            !rendered.contains("UPDATE accounts"),
            "the list projection must not ship sql_template bodies"
        );
        assert!(
            rendered.contains("sql_sha256"),
            "the list projection keeps the SQL digest for review"
        );

        let detail = store.detail(&view.id).expect("detail");
        let detail_rendered = serde_json::to_string(&detail).expect("serialize detail");
        assert!(
            detail_rendered.contains("UPDATE accounts"),
            "the detail view retains the full sql_template"
        );
    }

    #[test]
    fn list_page_bounds_pages_and_rejects_a_stale_cursor() {
        let store = ChangeProposalStore::open(store_root("page")).expect("store");
        let total = LIST_PAGE_SIZE + 2;
        for i in 0..total {
            draft_one(&store, &format!("cp-{i}"), &format!("SELECT {i} FROM dual"));
        }

        let first = store.list_page(None).expect("first page");
        assert_eq!(first.proposals.len(), LIST_PAGE_SIZE, "page is capped");
        let cursor = first.next_cursor.clone().expect("more pages remain");
        let second = store.list_page(Some(&cursor)).expect("second page");
        assert_eq!(second.proposals.len(), total - LIST_PAGE_SIZE);
        assert!(second.next_cursor.is_none(), "last page has no cursor");

        let mut ids: Vec<String> = first.proposals.iter().map(|p| p.id.clone()).collect();
        ids.extend(second.proposals.iter().map(|p| p.id.clone()));
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), total, "every proposal appears exactly once");

        // Appending a proposal changes the store validator, so the in-flight
        // cursor is rejected as stale rather than paging an inconsistent board.
        draft_one(&store, "cp-new", "SELECT 9999 FROM dual");
        let stale = store
            .list_page(Some(&cursor))
            .expect_err("stale cursor rejected");
        assert!(matches!(stale, ChangeProposalError::Invalid(_)));
    }

    #[test]
    fn list_page_skips_a_malformed_proposal_file() {
        let root = store_root("malformed");
        let store = ChangeProposalStore::open(&root).expect("store");
        draft_one(&store, "good", "SELECT 1 FROM dual");

        let corrupt = root
            .join(CHANGE_PROPOSAL_COLLECTION)
            .join("cp-garbage.json");
        std::fs::write(&corrupt, b"{ this is not valid json").expect("write corrupt record");

        let page = store
            .list_page(None)
            .expect("a single corrupt record must not fail the whole board");
        assert_eq!(page.proposals.len(), 1);
        assert_eq!(page.proposals[0].title, "good");
    }

    #[test]
    fn etag_is_stable_until_the_board_changes() {
        let store = ChangeProposalStore::open(store_root("etag")).expect("store");
        let empty = store.etag().expect("empty etag");
        assert_eq!(empty, store.etag().expect("empty etag again"));

        draft_one(&store, "one", "SELECT 1 FROM dual");
        let one = store.etag().expect("etag after draft");
        assert_ne!(one, empty, "a new proposal changes the validator");
        assert_eq!(one, store.etag().expect("etag stable while unchanged"));
    }

    #[test]
    fn edition_proposal_is_durable_review_metadata_not_execution_authority() {
        let root = store_root("edition-proposal");
        let store = ChangeProposalStore::open(&root).expect("store");
        let proposal = store
            .create_edition_proposal(EditionProposalCreateRequest {
                profile: "stage".to_owned(),
                child_edition: "child_v2".to_owned(),
                base_edition: "ora$base".to_owned(),
                objects: vec!["SYNTHETIC_PACKAGE".to_owned(), "SYNTHETIC_VIEW".to_owned()],
            })
            .expect("create edition proposal");

        assert_eq!(proposal.status, EditionProposalStatus::Requested);
        assert_eq!(proposal.child_edition, "CHILD_V2");
        assert_eq!(proposal.base_edition, "ORA$BASE");
        let record_path = root
            .join(EDITION_PROPOSAL_COLLECTION)
            .join(format!("{}.json", proposal.proposal_id));
        let record = fs::read_to_string(&record_path).expect("persisted record");
        assert!(record.contains("\"status\": \"requested\""));
        for forbidden in ["sql", "bind", "confirm", "execute", "verdict", "grant"] {
            assert!(
                !record.contains(forbidden),
                "edition request must not persist {forbidden} authority"
            );
        }

        let listed = store
            .list_edition_proposals()
            .expect("list edition proposals");
        assert_eq!(listed, vec![proposal.clone()]);

        let transitioned = store
            .transition_edition_proposal(EditionProposalTransitionRequest {
                proposal_id: proposal.proposal_id.clone(),
                status: EditionProposalStatus::Reviewing,
            })
            .expect("transition to review");
        assert_eq!(transitioned.status, EditionProposalStatus::Reviewing);
        let replay = store
            .transition_edition_proposal(EditionProposalTransitionRequest {
                proposal_id: proposal.proposal_id,
                status: EditionProposalStatus::Reviewing,
            })
            .expect_err("replaying the same status must not reset a request");
        assert!(matches!(replay, ChangeProposalError::Invalid(_)));
    }
}
