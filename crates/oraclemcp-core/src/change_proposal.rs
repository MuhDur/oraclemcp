//! Durable operator change proposals for the dashboard review board.
//!
//! Proposals are service-owned files under the shared [`FileStore`]. They are
//! deliberately not lane-bound: a lane is selected only when an operator applies
//! the proposal through `/operator/v1/change-proposals/apply`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use oraclemcp_config::ConnectionProfile;
use oraclemcp_db::PdbIdentityScope;
use oraclemcp_guard::{
    Classifier, ClassifierConfig, EditionLifecycleParse, EditionLifecycleSql, OperatingLevel,
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
const EDITION_PROPOSAL_SCHEMA_VERSION: u8 = 3;
const MAX_EDITION_PROPOSAL_OBJECTS: usize = 64;
const DEFAULT_EDITION_TTL_SECONDS: u64 = 7 * 86400;
const MAX_TRANSITION_RECEIPTS: usize = 4096;
/// Tamper-token scope for change-proposal list cursors.
const CHANGE_PROPOSAL_CURSOR_KIND: &str = "change-proposals";

fn local_only_pdb_scope() -> PdbIdentityScope {
    PdbIdentityScope::LocalOnly {
        observation: oraclemcp_db::PdbIdentityObservation::Unreadable,
    }
}

fn same_identified_pdb(left: &PdbIdentityScope, right: &PdbIdentityScope) -> bool {
    matches!(
        (left, right),
        (
            PdbIdentityScope::ServiceStateStore { identity: left },
            PdbIdentityScope::ServiceStateStore { identity: right },
        ) if left == right
    )
}

fn same_service_local_branch_scope(
    left_scope: &PdbIdentityScope,
    left_profile: &str,
    right_scope: &PdbIdentityScope,
    right_profile: &str,
) -> bool {
    same_identified_pdb(left_scope, right_scope)
        || (matches!(
            (left_scope, right_scope),
            (
                PdbIdentityScope::LocalOnly { .. },
                PdbIdentityScope::LocalOnly { .. }
            )
        ) && left_profile == right_profile)
}

/// Proposal review is a text-only classification phase. Applying a proposal
/// always enters the dispatcher, which independently binds a live semantic
/// proof before an `oracle_query` can reach Oracle. Keep this deliberate
/// offline baseline distinct from the library's fail-closed default.
fn proposal_review_classifier() -> Classifier {
    Classifier::engine_free_baseline(ClassifierConfig::new())
}

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
        let result = Self { store, owner };
        result.list_edition_proposals()?;
        Ok(result)
    }

    /// Open the proposal store under an existing process-wide service owner.
    pub fn open_with_owner(owner: ServiceOwner) -> Result<Self, ChangeProposalError> {
        let store = FileStore::open(owner.root())?;
        let result = Self { store, owner };
        result.list_edition_proposals()?;
        Ok(result)
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
        let _mutation = self.owner.mutation_guard();
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
            proposals.push(
                self.read_edition_proposal_path(&path, current_seconds())?
                    .view(),
            );
        }
        proposals.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then_with(|| a.profile.cmp(&b.profile))
                .then_with(|| a.proposal_id.cmp(&b.proposal_id))
        });
        Ok(proposals)
    }

    /// Load one durable Edition-Based Redefinition review request.
    ///
    /// Callers receive metadata only.  This never returns a SQL statement,
    /// classifier verdict, confirmation grant, or any other executable
    /// authority; a later guarded operation must derive and classify its own
    /// statement from this request at its point of execution.
    pub fn edition_proposal(
        &self,
        proposal_id: &str,
    ) -> Result<EditionProposal, ChangeProposalError> {
        self.load_edition_proposal(proposal_id)
    }

    /// Find a still-active competing child request for the same parent edition.
    ///
    /// Oracle editions form a linear chain.  A review board that contains two
    /// different non-withdrawn children for one base is ambiguous evidence, so
    /// guarded lifecycle operations refuse it before they can reach Oracle's
    /// late ORA-38807 enforcement.  This deliberately treats an unreviewed
    /// competing request as blocking too: uncertainty tightens the operation.
    pub fn active_edition_branch_conflict(
        &self,
        proposal: &EditionProposal,
    ) -> Result<Option<EditionProposalView>, ChangeProposalError> {
        Ok(self
            .list_edition_proposals()?
            .into_iter()
            .find(|candidate| {
                candidate.proposal_id != proposal.proposal_id
                    && match (&candidate.database_identity, &proposal.database_identity) {
                        (Some(left), Some(right)) => left == right,
                        _ => same_service_local_branch_scope(
                            &candidate.coordination_scope,
                            &candidate.profile,
                            &proposal.coordination_scope,
                            &proposal.profile,
                        ),
                    }
                    && candidate.parent_edition == proposal.parent_edition
                    && candidate.child_edition != proposal.child_edition
                    && candidate.status.blocks_open_request()
            }))
    }

    /// Persist a new Edition-Based Redefinition request. Persisting this
    /// request does not create an edition, evaluate a statement, issue a grant,
    /// or otherwise authorize a guarded write.
    pub fn create_edition_proposal(
        &self,
        request: EditionProposalCreateRequest,
    ) -> Result<EditionProposalView, ChangeProposalError> {
        // All handles cloned from this service owner share the gate. The
        // conflict scan and atomic write must be one mutation, across profiles
        // and parent editions; locking only the final write admits two requests.
        let _mutation = self.owner.mutation_guard();
        let proposal = EditionProposal::from_request(request)?;
        if let Some(conflict) = self.active_pdb_request_conflict(&proposal)? {
            return Err(ChangeProposalError::OpenRequestConflict {
                rule: if conflict.parent_edition == proposal.parent_edition {
                    OpenRequestConflictRule::OracleOneChildPerParent
                } else {
                    OpenRequestConflictRule::OraclemcpOnePerPdbPolicy
                },
                proposal_id: conflict.proposal_id,
            });
        }
        self.write_edition_proposal(&proposal)?;
        Ok(proposal.view())
    }

    /// Open the opted-in lifecycle using evidence supplied by the server's
    /// catalog probe. Legacy draft metadata deliberately uses the method above.
    pub fn open_change_request(
        &self,
        mut request: EditionProposalCreateRequest,
        profile: &ConnectionProfile,
        identity: Option<DatabaseIdentity>,
        idempotency_key: &str,
    ) -> Result<EditionProposalView, ChangeProposalError> {
        let _mutation = self.owner.mutation_guard();
        if !profile.edition_change_requests()
            || profile.protected()
            || profile.max_level() < OperatingLevel::Ddl
        {
            return Err(ChangeProposalError::EditionChangeRequestsDisabled);
        }
        if profile.name != request.profile
            || !(1..=90).contains(&profile.edition_change_request_ttl_days())
        {
            return Err(ChangeProposalError::Invalid(
                "invalid lifecycle profile or TTL",
            ));
        }
        let identity = identity.ok_or(ChangeProposalError::DatabaseIdentityRequired)?;
        identity.validate()?;
        validate_idempotency_key(idempotency_key)?;
        request.coordination_scope = identity.coordination_scope();
        let mut proposal = EditionProposal::from_request(request)?;
        let request_bytes = serde_json::to_vec(&(
            &proposal.profile,
            &proposal.child_edition,
            &proposal.parent_edition,
            &proposal.objects,
            &identity,
            profile.edition_change_request_ttl_days(),
        ))
        .map_err(|e| ChangeProposalError::Json(e.to_string()))?;
        let request_hash = oraclemcp_audit::sha256_hex(&request_bytes);
        for candidate in self.list_edition_proposals()? {
            let full = self.load_edition_proposal(&candidate.proposal_id)?;
            if candidate.profile == profile.name
                && let Some(receipt) = &full.open_receipt
                && receipt.key == idempotency_key
            {
                if receipt.receipt.request_hash != request_hash {
                    return Err(ChangeProposalError::IdempotencyKeyReuse);
                }
                return Ok(receipt.receipt.result.clone());
            }
        }
        if let Some(conflict) = self.open_conflict(&identity, &proposal.parent_edition)? {
            return Err(ChangeProposalError::OpenRequestConflict {
                proposal_id: conflict.proposal_id,
                rule: conflict.rule,
            });
        }
        proposal.database_identity = Some(identity);
        proposal.expires_at = timestamp_seconds(&proposal.created_at)?
            .checked_add(u64::from(profile.edition_change_request_ttl_days()) * 86400)
            .ok_or(ChangeProposalError::Invalid("expiry overflow"))?;
        proposal.open_receipt = Some(OpenReceipt {
            key: idempotency_key.to_owned(),
            receipt: TransitionReceipt {
                request_hash,
                result: proposal.view(),
            },
        });
        self.write_edition_proposal(&proposal)?;
        Ok(proposal.view())
    }

    /// Both conflicts are scoped to this service state store, never to all
    /// deployments. Prefer the Oracle parent rule when both rules apply.
    pub fn open_conflict(
        &self,
        identity: &DatabaseIdentity,
        parent_edition: &str,
    ) -> Result<Option<OpenRequestConflict>, ChangeProposalError> {
        identity.validate()?;
        let active: Vec<_> = self
            .list_edition_proposals()?
            .into_iter()
            .filter(|candidate| {
                candidate.status.blocks_open_request()
                    && match &candidate.database_identity {
                        Some(observed) => observed == identity,
                        None => same_identified_pdb(
                            &candidate.coordination_scope,
                            &identity.coordination_scope(),
                        ),
                    }
            })
            .collect();
        Ok(active
            .iter()
            .find(|candidate| candidate.parent_edition == parent_edition)
            .or_else(|| active.first())
            .map(|candidate| OpenRequestConflict {
                proposal_id: candidate.proposal_id.clone(),
                rule: if candidate.parent_edition == parent_edition {
                    OpenRequestConflictRule::OracleOneChildPerParent
                } else {
                    OpenRequestConflictRule::OraclemcpOnePerPdbPolicy
                },
            }))
    }

    fn active_pdb_request_conflict(
        &self,
        proposal: &EditionProposal,
    ) -> Result<Option<EditionProposalView>, ChangeProposalError> {
        Ok(self
            .list_edition_proposals()?
            .into_iter()
            .find(|candidate| {
                candidate.proposal_id != proposal.proposal_id
                    && same_identified_pdb(
                        &candidate.coordination_scope,
                        &proposal.coordination_scope,
                    )
                    && candidate.status.blocks_open_request()
            }))
    }

    /// Move an Edition-Based Redefinition request through its non-authorizing
    /// Reviews-board lifecycle. The only mutable field is the board status;
    /// this method cannot forward or synthesize a database action.
    pub fn transition_edition_proposal(
        &self,
        request: EditionProposalTransitionRequest,
    ) -> Result<EditionProposalView, ChangeProposalError> {
        let _mutation = self.owner.mutation_guard();
        let mut proposal = self.load_edition_proposal(&request.proposal_id)?;
        validate_idempotency_key(&request.idempotency_key)?;
        let hash = request_hash(&request)?;
        if let Some(receipt) = proposal.transition_receipts.get(&request.idempotency_key) {
            if receipt.request_hash != hash {
                return Err(ChangeProposalError::IdempotencyKeyReuse);
            }
            return Ok(receipt.result.clone());
        }
        if request.expected_revision != proposal.proposal_revision {
            return Err(ChangeProposalError::RevisionConflict {
                expected: request.expected_revision,
                actual: proposal.proposal_revision,
            });
        }
        if proposal.transition_receipts.len() >= MAX_TRANSITION_RECEIPTS {
            return Err(ChangeProposalError::Invalid(
                "transition receipt capacity reached",
            ));
        }
        proposal.transition_to(&request)?;
        let result = proposal.view();
        proposal.transition_receipts.insert(
            request.idempotency_key,
            TransitionReceipt {
                request_hash: hash,
                result: result.clone(),
            },
        );
        self.write_edition_proposal(&proposal)?;
        Ok(result)
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
        let _mutation = self.owner.mutation_guard();
        self.read_edition_proposal_path(&path, current_seconds())
    }

    fn read_edition_proposal_path(
        &self,
        path: &Path,
        now: u64,
    ) -> Result<EditionProposal, ChangeProposalError> {
        let (mut proposal, migrated) = load_edition_proposal_from_path(path)?;
        let expired = proposal.status.blocks_open_request() && proposal.expires_at <= now;
        if expired {
            proposal.status = ChangeRequestState::Expired;
            proposal.proposal_revision = proposal
                .proposal_revision
                .checked_add(1)
                .ok_or(ChangeProposalError::Invalid("proposal revision exhausted"))?;
            proposal.verification_revision = None;
            proposal.review_revision = None;
            proposal.updated_at = format!("unix:{now:020}");
        }
        if migrated || expired {
            self.write_edition_proposal(&proposal)?;
        }
        Ok(proposal)
    }

    fn write_edition_proposal(
        &self,
        proposal: &EditionProposal,
    ) -> Result<(), ChangeProposalError> {
        proposal.validate()?;
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
    /// A service-state store already has an open request for this PDB.
    #[error("open edition request conflict ({rule:?}, service_state_store): {proposal_id}")]
    OpenRequestConflict {
        proposal_id: String,
        rule: OpenRequestConflictRule,
    },
    #[error("REVISION_CONFLICT: expected proposal revision {expected}, observed {actual}")]
    RevisionConflict { expected: u64, actual: u64 },
    #[error("idempotency key was already used for a different transition")]
    IdempotencyKeyReuse,
    #[error(
        "stable server-probed DB_UNIQUE_NAME, DBID and CON_UID evidence is required; permit the identity probe (including SELECT on SYS.V_$CONTAINERS), then retry Open; ordinary reads remain available"
    )]
    DatabaseIdentityRequired,
    #[error(
        "edition_change_requests must be explicitly enabled on an unprotected profile with max_level >= DDL"
    )]
    EditionChangeRequestsDisabled,
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
    /// Server-derived PDB coordination scope; local-only when identity is unreadable.
    #[serde(skip_deserializing, default = "local_only_pdb_scope")]
    pub coordination_scope: PdbIdentityScope,
}

/// Stable server-observed database and container identity. A container name
/// or its reusable CON_ID slot is never sufficient.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DatabaseIdentity {
    pub db_unique_name: String,
    pub dbid: String,
    pub container_uid: String,
}

impl DatabaseIdentity {
    #[must_use]
    pub fn coordination_scope(&self) -> PdbIdentityScope {
        PdbIdentityScope::ServiceStateStore {
            identity: oraclemcp_db::PdbIdentity {
                dbid: self.dbid.clone(),
                con_uid: self.container_uid.clone(),
            },
        }
    }

    pub fn validate(&self) -> Result<(), ChangeProposalError> {
        let stable_number = |value: &str| {
            value
                .parse::<u64>()
                .is_ok_and(|n| n > 0 && n.to_string() == value)
        };
        if self.db_unique_name.trim().is_empty()
            || self.db_unique_name.len() > 128
            || self.db_unique_name.chars().any(char::is_control)
            || !stable_number(&self.dbid)
            || !stable_number(&self.container_uid)
        {
            return Err(ChangeProposalError::DatabaseIdentityRequired);
        }
        Ok(())
    }
}

/// Edition change-request lifecycle; changing metadata never authorizes SQL.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeRequestState {
    Open,
    Staged,
    Verified,
    Reviewing,
    Promoted,
    RolledBack,
    Withdrawn,
    Expired,
    Failed,
    ChildRetired,
}

impl ChangeRequestState {
    pub const ALL: [Self; 10] = [
        Self::Open,
        Self::Staged,
        Self::Verified,
        Self::Reviewing,
        Self::Promoted,
        Self::RolledBack,
        Self::Withdrawn,
        Self::Expired,
        Self::Failed,
        Self::ChildRetired,
    ];

    pub const TRANSITIONS: &'static [(Self, Self)] = &[
        (Self::Open, Self::Staged),
        (Self::Staged, Self::Staged),
        (Self::Verified, Self::Staged),
        (Self::Reviewing, Self::Staged),
        (Self::Staged, Self::Verified),
        (Self::Verified, Self::Reviewing),
        (Self::Reviewing, Self::Promoted),
        (Self::Promoted, Self::RolledBack),
        (Self::RolledBack, Self::ChildRetired),
        (Self::Open, Self::Withdrawn),
        (Self::Staged, Self::Withdrawn),
        (Self::Verified, Self::Withdrawn),
        (Self::Reviewing, Self::Withdrawn),
        (Self::Open, Self::Expired),
        (Self::Staged, Self::Expired),
        (Self::Verified, Self::Expired),
        (Self::Reviewing, Self::Expired),
        (Self::Open, Self::Failed),
        (Self::Staged, Self::Failed),
        (Self::Verified, Self::Failed),
        (Self::Reviewing, Self::Failed),
        (Self::Withdrawn, Self::ChildRetired),
        (Self::Expired, Self::ChildRetired),
        (Self::Failed, Self::ChildRetired),
    ];

    #[must_use]
    pub fn permits(self, next: Self) -> bool {
        Self::TRANSITIONS.contains(&(self, next))
    }

    #[must_use]
    pub const fn blocks_open_request(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Staged | Self::Verified | Self::Reviewing
        )
    }
}

/// A request to update one persisted Reviews-board status.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EditionProposalTransitionRequest {
    pub proposal_id: String,
    pub status: ChangeRequestState,
    pub expected_revision: u64,
    pub idempotency_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objects: Option<Vec<String>>,
    /// Supplied by the verifier seam, never by an HTTP metadata client.
    #[serde(skip_deserializing, default)]
    pub verification_revision: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct TransitionReceipt {
    request_hash: String,
    result: EditionProposalView,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct OpenReceipt {
    key: String,
    receipt: TransitionReceipt,
}

/// The rule responsible for a service-state-store conflict.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpenRequestConflictRule {
    OracleOneChildPerParent,
    OraclemcpOnePerPdbPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenRequestConflict {
    pub proposal_id: String,
    pub rule: OpenRequestConflictRule,
}

fn current_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn timestamp_seconds(value: &str) -> Result<u64, ChangeProposalError> {
    let seconds = value
        .strip_prefix("unix:")
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(ChangeProposalError::Invalid("invalid creation timestamp"))?;
    if value != format!("unix:{seconds:020}") {
        return Err(ChangeProposalError::Invalid("noncanonical timestamp"));
    }
    Ok(seconds)
}

fn validate_idempotency_key(key: &str) -> Result<(), ChangeProposalError> {
    if key.is_empty() || key.len() > 128 || key.bytes().any(|c| !c.is_ascii_graphic()) {
        return Err(ChangeProposalError::Invalid(
            "idempotency key must contain 1..=128 printable ASCII characters",
        ));
    }
    Ok(())
}

fn request_hash(request: &EditionProposalTransitionRequest) -> Result<String, ChangeProposalError> {
    let bytes = serde_json::to_vec(request)
        .map_err(|error| ChangeProposalError::Json(error.to_string()))?;
    Ok(oraclemcp_audit::sha256_hex(&bytes))
}

/// Full on-disk edition-proposal record.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EditionProposal {
    pub schema_version: u8,
    pub proposal_id: String,
    pub profile: String,
    pub child_edition: String,
    pub parent_edition: String,
    pub objects: Vec<String>,
    /// Server-derived scope for this service state store's local control plane.
    #[serde(default = "local_only_pdb_scope")]
    pub coordination_scope: PdbIdentityScope,
    pub database_identity: Option<DatabaseIdentity>,
    pub status: ChangeRequestState,
    pub proposal_revision: u64,
    pub stage_revision: u64,
    pub verification_revision: Option<u64>,
    pub review_revision: Option<u64>,
    pub expires_at: u64,
    #[serde(default)]
    transition_receipts: BTreeMap<String, TransitionReceipt>,
    #[serde(default)]
    open_receipt: Option<OpenReceipt>,
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
            parent_edition: base_edition,
            objects,
            coordination_scope: request.coordination_scope,
            database_identity: None,
            status: ChangeRequestState::Open,
            proposal_revision: 0,
            stage_revision: 0,
            verification_revision: None,
            review_revision: None,
            expires_at: timestamp_seconds(&now)?
                .checked_add(DEFAULT_EDITION_TTL_SECONDS)
                .ok_or(ChangeProposalError::Invalid("expiry overflow"))?,
            transition_receipts: BTreeMap::new(),
            open_receipt: None,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    fn transition_to(
        &mut self,
        request: &EditionProposalTransitionRequest,
    ) -> Result<(), ChangeProposalError> {
        let next = request.status;
        if !self.status.permits(next) {
            return Err(ChangeProposalError::Invalid(
                "edition proposal status transition is not allowed",
            ));
        }
        if request.objects.is_some() && next != ChangeRequestState::Staged {
            return Err(ChangeProposalError::Invalid(
                "objects may change only while staging",
            ));
        }
        if !matches!(
            next,
            ChangeRequestState::Withdrawn
                | ChangeRequestState::Expired
                | ChangeRequestState::Failed
        ) && self.database_identity.is_none()
        {
            return Err(ChangeProposalError::DatabaseIdentityRequired);
        }
        match next {
            ChangeRequestState::Staged => {
                if let Some(objects) = &request.objects {
                    if objects.len() > MAX_EDITION_PROPOSAL_OBJECTS {
                        return Err(ChangeProposalError::Invalid("too many staged objects"));
                    }
                    self.objects = objects
                        .iter()
                        .cloned()
                        .map(normalize_edition_object)
                        .collect::<Result<Vec<_>, _>>()?;
                    self.objects.sort();
                    self.objects.dedup();
                }
                if self.objects.is_empty() {
                    return Err(ChangeProposalError::Invalid(
                        "a successful stage must contain an object",
                    ));
                }
                self.stage_revision = self
                    .stage_revision
                    .checked_add(1)
                    .ok_or(ChangeProposalError::Invalid("stage revision exhausted"))?;
                self.verification_revision = None;
                self.review_revision = None;
            }
            ChangeRequestState::Verified => {
                if self.stage_revision == 0
                    || request.verification_revision != Some(self.stage_revision)
                {
                    return Err(ChangeProposalError::Invalid(
                        "verification must bind the current stage revision",
                    ));
                }
                self.verification_revision = Some(self.stage_revision);
            }
            ChangeRequestState::Reviewing
            | ChangeRequestState::Promoted
            | ChangeRequestState::RolledBack => {
                if self.stage_revision == 0
                    || self.verification_revision != Some(self.stage_revision)
                {
                    return Err(ChangeProposalError::Invalid(
                        "current stage is not verified",
                    ));
                }
                if next == ChangeRequestState::Reviewing {
                    self.review_revision = Some(self.stage_revision);
                } else if self.review_revision != Some(self.stage_revision) {
                    return Err(ChangeProposalError::Invalid(
                        "current stage has no review bundle",
                    ));
                }
            }
            ChangeRequestState::Withdrawn
            | ChangeRequestState::Expired
            | ChangeRequestState::Failed
            | ChangeRequestState::ChildRetired => {
                self.verification_revision = None;
                self.review_revision = None;
            }
            ChangeRequestState::Open => unreachable!("transition table has no edge into Open"),
        }
        self.status = next;
        self.proposal_revision = self
            .proposal_revision
            .checked_add(1)
            .ok_or(ChangeProposalError::Invalid("proposal revision exhausted"))?;
        self.updated_at = unix_timestamp();
        Ok(())
    }

    /// Return the redacted Reviews-board projection for this request.
    ///
    /// The projection carries only the durable request metadata and cannot be
    /// converted into executable authority.
    #[must_use]
    pub fn view(&self) -> EditionProposalView {
        EditionProposalView {
            schema_version: self.schema_version,
            proposal_id: self.proposal_id.clone(),
            profile: self.profile.clone(),
            child_edition: self.child_edition.clone(),
            parent_edition: self.parent_edition.clone(),
            objects: self.objects.clone(),
            coordination_scope: self.coordination_scope.clone(),
            database_identity: self.database_identity.clone(),
            status: self.status,
            proposal_revision: self.proposal_revision,
            stage_revision: self.stage_revision,
            verification_revision: self.verification_revision,
            review_revision: self.review_revision,
            expires_at: self.expires_at,
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
        validate_dictionary_edition_identifier(&self.child_edition)?;
        validate_dictionary_edition_identifier(&self.parent_edition)?;
        if StoreId::from_safe_segment(self.proposal_id.clone()).is_err()
            || normalize_non_empty(self.profile.clone(), "profile")? != self.profile
            || self.child_edition == self.parent_edition
            || self.objects.len() > MAX_EDITION_PROPOSAL_OBJECTS
            || self.stage_revision > self.proposal_revision
            || self.transition_receipts.len() > MAX_TRANSITION_RECEIPTS
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
        if let Some(identity) = &self.database_identity {
            identity.validate()?;
            if self.coordination_scope != identity.coordination_scope() {
                return Err(ChangeProposalError::Invalid(
                    "database identity disagrees with coordination scope",
                ));
            }
        }
        if matches!(
            self.status,
            ChangeRequestState::Staged
                | ChangeRequestState::Verified
                | ChangeRequestState::Reviewing
                | ChangeRequestState::Promoted
                | ChangeRequestState::RolledBack
        ) && (self.objects.is_empty()
            || self.stage_revision == 0
            || self.database_identity.is_none())
        {
            return Err(ChangeProposalError::Invalid(
                "staged request lacks objects or database identity",
            ));
        }
        if matches!(
            self.status,
            ChangeRequestState::Verified
                | ChangeRequestState::Reviewing
                | ChangeRequestState::Promoted
                | ChangeRequestState::RolledBack
        ) && self.verification_revision != Some(self.stage_revision)
        {
            return Err(ChangeProposalError::Invalid(
                "verification revision is stale",
            ));
        }
        if matches!(
            self.status,
            ChangeRequestState::Reviewing
                | ChangeRequestState::Promoted
                | ChangeRequestState::RolledBack
        ) && self.review_revision != Some(self.stage_revision)
        {
            return Err(ChangeProposalError::Invalid("review revision is stale"));
        }
        let created = timestamp_seconds(&self.created_at)?;
        if self.expires_at <= created || self.expires_at - created > 90 * 86400 {
            return Err(ChangeProposalError::Invalid("invalid expiry timestamp"));
        }
        if self.database_identity.is_some() != self.open_receipt.is_some() {
            return Err(ChangeProposalError::Invalid(
                "lifecycle request lacks an Open receipt",
            ));
        }
        for (key, receipt) in self
            .transition_receipts
            .iter()
            .map(|(key, receipt)| (key.as_str(), receipt))
            .chain(
                self.open_receipt
                    .iter()
                    .map(|open| (open.key.as_str(), &open.receipt)),
            )
        {
            validate_idempotency_key(key)?;
            if receipt.request_hash.len() != 71
                || !receipt.request_hash.starts_with("sha256:")
                || !receipt.request_hash[7..]
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                || receipt.result.proposal_id != self.proposal_id
                || receipt.result.profile != self.profile
                || receipt.result.parent_edition != self.parent_edition
                || receipt.result.child_edition != self.child_edition
                || receipt.result.database_identity != self.database_identity
                || receipt.result.proposal_revision > self.proposal_revision
            {
                return Err(ChangeProposalError::Invalid("invalid idempotency receipt"));
            }
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
    pub parent_edition: String,
    pub objects: Vec<String>,
    /// Scope of the service-local coordination claim.
    pub coordination_scope: PdbIdentityScope,
    pub database_identity: Option<DatabaseIdentity>,
    pub status: ChangeRequestState,
    pub proposal_revision: u64,
    pub stage_revision: u64,
    pub verification_revision: Option<u64>,
    pub review_revision: Option<u64>,
    pub expires_at: u64,
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
    pub lane_generation: Option<u64>,
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
        let decision = proposal_review_classifier().classify(&sql_template);
        let unit = unit_for_required_level(decision.required_level);
        if draft.unit.is_some_and(|requested| requested != unit) {
            return Err(ChangeProposalError::Invalid(
                "statement unit does not match the classifier-required level",
            ));
        }
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

    /// Re-run the text-only review classifier for apply-time reporting. The
    /// dispatcher independently binds a live semantic proof inside the MCP
    /// tool; this view cannot authorize execution.
    #[must_use]
    pub fn reclassified_view(&self) -> ChangeProposalClassifierView {
        ChangeProposalClassifierView::from_decision(
            proposal_review_classifier().classify(self.sql_template.as_str()),
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

fn load_edition_proposal_from_path(
    path: &Path,
) -> Result<(EditionProposal, bool), ChangeProposalError> {
    let bytes = fs::read(path).map_err(|e| ChangeProposalError::Io(e.to_string()))?;
    let mut value: Value =
        serde_json::from_slice(&bytes).map_err(|e| ChangeProposalError::Json(e.to_string()))?;
    let version = value["schema_version"]
        .as_u64()
        .ok_or(ChangeProposalError::Invalid(
            "missing edition schema version",
        ))?;
    let migrated = matches!(version, 1 | 2);
    if migrated {
        let record = value
            .as_object_mut()
            .ok_or(ChangeProposalError::Invalid("invalid legacy request"))?;
        const LEGACY_FIELDS: &[&str] = &[
            "schema_version",
            "proposal_id",
            "profile",
            "child_edition",
            "base_edition",
            "objects",
            "coordination_scope",
            "status",
            "created_at",
            "updated_at",
        ];
        if record
            .keys()
            .any(|key| !LEGACY_FIELDS.contains(&key.as_str()))
        {
            return Err(ChangeProposalError::Invalid(
                "unexpected legacy request field",
            ));
        }
        let created = timestamp_seconds(
            record
                .get("created_at")
                .and_then(Value::as_str)
                .ok_or(ChangeProposalError::Invalid("invalid legacy timestamp"))?,
        )?;
        let status = match record.get("status").and_then(Value::as_str) {
            Some("requested" | "reviewing") => "open",
            Some("withdrawn") => "withdrawn",
            _ => return Err(ChangeProposalError::Invalid("invalid legacy state")),
        };
        let parent = record
            .remove("base_edition")
            .ok_or(ChangeProposalError::Invalid("legacy parent missing"))?;
        record.insert("parent_edition".into(), parent);
        record.insert("status".into(), Value::String(status.into()));
        record.insert(
            "schema_version".into(),
            Value::from(EDITION_PROPOSAL_SCHEMA_VERSION),
        );
        record.insert("database_identity".into(), Value::Null);
        record.insert("proposal_revision".into(), Value::from(0));
        record.insert("stage_revision".into(), Value::from(0));
        record.insert("verification_revision".into(), Value::Null);
        record.insert("review_revision".into(), Value::Null);
        record.insert("open_receipt".into(), Value::Null);
        record.insert("transition_receipts".into(), serde_json::json!({}));
        record.insert(
            "expires_at".into(),
            Value::from(
                created
                    .checked_add(DEFAULT_EDITION_TTL_SECONDS)
                    .ok_or(ChangeProposalError::Invalid("legacy expiry overflow"))?,
            ),
        );
        if version == 1 {
            // v1 mislabeled reusable CON_ID as CON_UID. Preserve the draft,
            // never that identity claim, and never any old review authority.
            record.insert(
                "coordination_scope".into(),
                serde_json::to_value(PdbIdentityScope::LocalOnly {
                    observation: oraclemcp_db::PdbIdentityObservation::LegacyContainerIdentity,
                })
                .map_err(|e| ChangeProposalError::Json(e.to_string()))?,
            );
        }
    }
    let proposal: EditionProposal =
        serde_json::from_value(value).map_err(|e| ChangeProposalError::Json(e.to_string()))?;
    proposal.validate()?;
    Ok((proposal, migrated))
}

pub(crate) fn normalize_edition_identifier(value: String) -> Result<String, ChangeProposalError> {
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

/// Validate a stored dictionary name without interpreting its spelling as a
/// fresh, unquoted SQL identifier. Raw request tokens are normalized once at
/// creation; persisted names retain the exact case and spaces Oracle uses.
pub(crate) fn validate_dictionary_edition_identifier(
    value: &str,
) -> Result<(), ChangeProposalError> {
    if value.is_empty()
        || value.len() > 128
        || value.contains('"')
        || value.chars().any(char::is_control)
    {
        return Err(ChangeProposalError::Invalid(
            "invalid dictionary edition identifier",
        ));
    }
    if normalize_edition_identifier(format!("\"{value}\""))? != value {
        return Err(ChangeProposalError::Invalid(
            "invalid dictionary edition identifier",
        ));
    }
    Ok(())
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
pub(crate) fn test_edition_transition(
    view: &EditionProposalView,
    status: ChangeRequestState,
    key: &str,
) -> EditionProposalTransitionRequest {
    EditionProposalTransitionRequest {
        proposal_id: view.proposal_id.clone(),
        status,
        expected_revision: view.proposal_revision,
        idempotency_key: key.to_owned(),
        objects: None,
        verification_revision: (status == ChangeRequestState::Verified)
            .then_some(view.stage_revision),
    }
}

#[cfg(test)]
pub(crate) fn test_verified_edition_request(
    store: &ChangeProposalStore,
    profile_name: &str,
    child: &str,
    parent: &str,
) -> EditionProposalView {
    let profile: ConnectionProfile = serde_json::from_value(serde_json::json!({
        "name": profile_name, "connect_string": "synthetic:1521/service",
        "max_level": "ADMIN", "edition_change_requests": true,
    }))
    .unwrap();
    let identity = DatabaseIdentity {
        db_unique_name: "SYNTHETIC_DB".into(),
        dbid: "42".into(),
        container_uid: "9001".into(),
    };
    let mut view = store
        .open_change_request(
            EditionProposalCreateRequest {
                profile: profile_name.into(),
                child_edition: child.into(),
                base_edition: parent.into(),
                objects: vec!["SYNTHETIC_VIEW".into()],
                coordination_scope: identity.coordination_scope(),
            },
            &profile,
            Some(identity),
            &format!("open-{}", oraclemcp_audit::sha256_hex(child.as_bytes())),
        )
        .unwrap();
    for state in [ChangeRequestState::Staged, ChangeRequestState::Verified] {
        let request = test_edition_transition(&view, state, &format!("state-{state:?}"));
        view = store.transition_edition_proposal(request).unwrap();
    }
    view
}

#[cfg(test)]
pub(crate) fn test_reviewed_edition_request(
    store: &ChangeProposalStore,
    profile_name: &str,
    child: &str,
    parent: &str,
) -> EditionProposalView {
    let view = test_verified_edition_request(store, profile_name, child, parent);
    store
        .transition_edition_proposal(test_edition_transition(
            &view,
            ChangeRequestState::Reviewing,
            "state-Reviewing",
        ))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lifecycle_profile() -> ConnectionProfile {
        serde_json::from_value(
            serde_json::json!({"name":"stage", "connect_string":"synthetic:1521/service",
            "max_level":"DDL", "edition_change_requests":true}),
        )
        .unwrap()
    }
    fn database_identity() -> DatabaseIdentity {
        DatabaseIdentity {
            db_unique_name: "SYNTHETIC_DB".into(),
            dbid: "42".into(),
            container_uid: "9001".into(),
        }
    }
    fn lifecycle_request(child: &str, parent: &str) -> EditionProposalCreateRequest {
        EditionProposalCreateRequest {
            profile: "stage".into(),
            child_edition: child.into(),
            base_edition: parent.into(),
            objects: Vec::new(),
            coordination_scope: local_only_pdb_scope(),
        }
    }
    fn open_empty(store: &ChangeProposalStore) -> EditionProposalView {
        store
            .open_change_request(
                lifecycle_request("CHILD_A", "ORA$BASE"),
                &lifecycle_profile(),
                Some(database_identity()),
                "open-a",
            )
            .unwrap()
    }
    fn stage(
        store: &ChangeProposalStore,
        view: &EditionProposalView,
        key: &str,
    ) -> EditionProposalView {
        let mut request = test_edition_transition(view, ChangeRequestState::Staged, key);
        request.objects = Some(vec!["SYNTHETIC_VIEW".into()]);
        store.transition_edition_proposal(request).unwrap()
    }

    #[test]
    fn change_request_transition_table_exhaustive() {
        use ChangeRequestState::*;
        for from in ChangeRequestState::ALL {
            for to in ChangeRequestState::ALL {
                let active = matches!(from, Open | Staged | Verified | Reviewing);
                let expected = (active && matches!(to, Withdrawn | Expired | Failed))
                    || (active && to == Staged)
                    || matches!(
                        (from, to),
                        (Staged, Verified)
                            | (Verified, Reviewing)
                            | (Reviewing, Promoted)
                            | (Promoted, RolledBack)
                            | (RolledBack | Withdrawn | Expired | Failed, ChildRetired)
                    );
                assert_eq!(from.permits(to), expected, "{from:?} -> {to:?}");
            }
        }
    }

    #[test]
    fn quoted_dictionary_edition_identifiers_round_trip_without_renormalization() {
        for (child_input, parent_input, child, parent) in [
            ("\"Child v2\"", "\"Base v1\"", "Child v2", "Base v1"),
            ("\"child_v2\"", "\"BaseV1\"", "child_v2", "BaseV1"),
        ] {
            let root = store_root("quoted-edition-roundtrip");
            let store = ChangeProposalStore::open(&root).unwrap();
            let request = lifecycle_request(child_input, parent_input);
            let created = store
                .open_change_request(
                    request.clone(),
                    &lifecycle_profile(),
                    Some(database_identity()),
                    "quoted-open",
                )
                .unwrap();
            assert_eq!(created.child_edition, child);
            assert_eq!(created.parent_edition, parent);
            let record = store.edition_proposal(&created.proposal_id).unwrap();
            record.validate().unwrap();
            let before = serde_json::to_value(&record).unwrap();
            drop(store);
            let reopened = ChangeProposalStore::open(&root).unwrap();
            let loaded = reopened.edition_proposal(&created.proposal_id).unwrap();
            loaded.validate().unwrap();
            assert_eq!(
                serde_json::to_value(&loaded).unwrap(),
                before,
                "persistent dictionary spelling must remain exact"
            );
            let replay = reopened
                .open_change_request(
                    request,
                    &lifecycle_profile(),
                    Some(database_identity()),
                    "quoted-open",
                )
                .unwrap();
            assert_eq!(replay.proposal_id, created.proposal_id);
            assert_eq!(replay.child_edition, child);
            assert_eq!(replay.parent_edition, parent);
        }
    }

    #[test]
    fn dictionary_edition_identifiers_refuse_unsafe_renderings() {
        let oversized = "X".repeat(129);
        for value in [
            "",
            "name\"escape",
            "name\0escape",
            "name\nescape",
            oversized.as_str(),
        ] {
            assert!(
                validate_dictionary_edition_identifier(value).is_err(),
                "{value:?}"
            );
        }
        for value in [
            "CHILD; DROP EDITION BASE",
            "CHILD EXTRA",
            "CHILD AS CHILD OF OTHER",
        ] {
            assert!(
                normalize_edition_identifier(value.to_owned()).is_err(),
                "raw SQL identifier grammar must remain strict"
            );
        }
    }

    #[test]
    fn unquoted_dictionary_edition_identifiers_still_fold_case() {
        let store = ChangeProposalStore::open(store_root("unquoted-edition-roundtrip")).unwrap();
        let created = store
            .open_change_request(
                lifecycle_request("child_v2", "base_v1"),
                &lifecycle_profile(),
                Some(database_identity()),
                "unquoted-open",
            )
            .unwrap();
        let loaded = store.edition_proposal(&created.proposal_id).unwrap();
        assert_eq!(loaded.child_edition, "CHILD_V2");
        assert_eq!(loaded.parent_edition, "BASE_V1");
    }

    #[test]
    fn open_allows_zero_objects() {
        let store = ChangeProposalStore::open(store_root("open-zero")).unwrap();
        let view = open_empty(&store);
        assert_eq!(view.status, ChangeRequestState::Open);
        assert!(view.objects.is_empty());
        assert_eq!(view.proposal_revision, 0);
        let mut view = stage(&store, &view, "stage");
        for state in [
            ChangeRequestState::Verified,
            ChangeRequestState::Reviewing,
            ChangeRequestState::Promoted,
            ChangeRequestState::RolledBack,
            ChangeRequestState::ChildRetired,
        ] {
            view = store
                .transition_edition_proposal(test_edition_transition(
                    &view,
                    state,
                    &format!("{state:?}"),
                ))
                .unwrap();
            assert_eq!(
                store.edition_proposal(&view.proposal_id).unwrap().status,
                state
            );
        }
    }

    #[test]
    fn stage_increments_revision_and_invalidates_verification() {
        let store = ChangeProposalStore::open(store_root("restage-verified")).unwrap();
        let first = stage(&store, &open_empty(&store), "stage-1");
        let verified = store
            .transition_edition_proposal(test_edition_transition(
                &first,
                ChangeRequestState::Verified,
                "verify",
            ))
            .unwrap();
        let second = stage(&store, &verified, "stage-2");
        assert_eq!(second.stage_revision, 2);
        assert_eq!(second.proposal_revision, verified.proposal_revision + 1);
        assert_eq!(second.verification_revision, None);
        assert_eq!(second.review_revision, None);
        let mut stale_verification =
            test_edition_transition(&second, ChangeRequestState::Verified, "old-verification");
        stale_verification.verification_revision = Some(1);
        assert!(matches!(
            store.transition_edition_proposal(stale_verification),
            Err(ChangeProposalError::Invalid(_))
        ));
    }

    #[test]
    fn stage_from_reviewing_withdraws_review_under_cas() {
        let store = ChangeProposalStore::open(store_root("restage-review")).unwrap();
        let reviewed = test_reviewed_edition_request(&store, "stage", "CHILD_A", "ORA$BASE");
        let next = stage(&store, &reviewed, "restage");
        assert_eq!(next.status, ChangeRequestState::Staged);
        assert_eq!(next.stage_revision, 2);
        assert_eq!(next.verification_revision, None);
        assert_eq!(next.review_revision, None);
        assert!(matches!(
            store.transition_edition_proposal(test_edition_transition(
                &reviewed,
                ChangeRequestState::Promoted,
                "stale-promote"
            )),
            Err(ChangeProposalError::RevisionConflict { .. })
        ));
        assert_eq!(
            store.edition_proposal(&next.proposal_id).unwrap().status,
            ChangeRequestState::Staged
        );
    }

    #[test]
    fn revision_cas_conflict_refused() {
        let store = ChangeProposalStore::open(store_root("revision-cas")).unwrap();
        let opened = open_empty(&store);
        let current = stage(&store, &opened, "first-stage");
        let mut stale = test_edition_transition(&opened, ChangeRequestState::Staged, "stale-stage");
        stale.objects = Some(vec!["OTHER_VIEW".into()]);
        assert!(matches!(
            store.transition_edition_proposal(stale),
            Err(ChangeProposalError::RevisionConflict {
                expected: 0,
                actual: 1
            })
        ));
        assert_eq!(
            store.edition_proposal(&current.proposal_id).unwrap().view(),
            current
        );
    }

    #[test]
    fn idempotent_retry_same_key_same_result() {
        let root = store_root("idempotent-transition");
        let store = ChangeProposalStore::open(&root).unwrap();
        let opened = open_empty(&store);
        assert_eq!(open_empty(&store), opened, "Open is idempotent too");
        let mut request =
            test_edition_transition(&opened, ChangeRequestState::Staged, "stage-once");
        request.objects = Some(vec!["SYNTHETIC_VIEW".into()]);
        let staged = store.transition_edition_proposal(request.clone()).unwrap();
        let verified = store
            .transition_edition_proposal(test_edition_transition(
                &staged,
                ChangeRequestState::Verified,
                "verify",
            ))
            .unwrap();
        drop(store);
        let store = ChangeProposalStore::open(&root).unwrap();
        assert_eq!(
            store.transition_edition_proposal(request).unwrap(),
            staged,
            "returns original durable receipt"
        );
        assert_eq!(
            store
                .edition_proposal(&verified.proposal_id)
                .unwrap()
                .view(),
            verified,
            "no mutation replayed"
        );
    }

    #[test]
    fn idempotency_key_reuse_with_different_request_refused() {
        let store = ChangeProposalStore::open(store_root("idempotency-reuse")).unwrap();
        let opened = open_empty(&store);
        let staged = stage(&store, &opened, "stage-once");
        assert!(matches!(
            store.transition_edition_proposal(test_edition_transition(
                &staged,
                ChangeRequestState::Withdrawn,
                "stage-once"
            )),
            Err(ChangeProposalError::IdempotencyKeyReuse)
        ));
        assert!(matches!(
            store.open_change_request(
                lifecycle_request("CHILD_B", "ORA$BASE"),
                &lifecycle_profile(),
                Some(database_identity()),
                "open-a"
            ),
            Err(ChangeProposalError::IdempotencyKeyReuse)
        ));
    }

    #[test]
    fn ttl_expiry_moves_to_expired() {
        let root = store_root("ttl-expiry");
        let store = ChangeProposalStore::open(&root).unwrap();
        let opened = open_empty(&store);
        let id = StoreId::from_safe_segment(opened.proposal_id.clone()).unwrap();
        let path = store
            .store
            .path_for(EDITION_PROPOSAL_COLLECTION, &id, EDITION_PROPOSAL_EXTENSION)
            .unwrap();
        let expired = store
            .read_edition_proposal_path(&path, opened.expires_at)
            .unwrap();
        assert_eq!(expired.status, ChangeRequestState::Expired);
        assert_eq!(expired.proposal_revision, 1);
        assert_eq!(expired.verification_revision, None);
        assert_eq!(
            store.edition_proposal(&opened.proposal_id).unwrap().status,
            ChangeRequestState::Expired
        );
        assert!(
            store
                .open_change_request(
                    lifecycle_request("CHILD_B", "ORA$BASE"),
                    &lifecycle_profile(),
                    Some(database_identity()),
                    "open-b"
                )
                .is_ok(),
            "expired metadata no longer claims the service-state-store slot"
        );
    }

    #[test]
    fn distinct_full_database_identities_do_not_share_a_request_slot_or_branch() {
        let store = ChangeProposalStore::open(store_root("different-full-identities")).unwrap();
        let left = open_empty(&store);
        let mut other_identity = database_identity();
        other_identity.db_unique_name = "OTHER_SYNTHETIC_DB".into();
        let mut profile = lifecycle_profile();
        profile.name = "stage_two".into();
        let mut request = lifecycle_request("CHILD_B", "ORA$BASE");
        request.profile = profile.name.clone();
        let right = store
            .open_change_request(request, &profile, Some(other_identity), "other-db")
            .unwrap();
        assert_eq!(store.list_edition_proposals().unwrap().len(), 2);
        let left = store.edition_proposal(&left.proposal_id).unwrap();
        let right = store.edition_proposal(&right.proposal_id).unwrap();
        assert!(
            store
                .active_edition_branch_conflict(&left)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .active_edition_branch_conflict(&right)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn legacy_status_records_migrate_once() {
        for version in [1, 2] {
            for old_status in ["requested", "reviewing", "withdrawn"] {
                let store = ChangeProposalStore::open(store_root(&format!(
                    "legacy-{version}-{old_status}"
                )))
                .unwrap();
                let view = store
                    .create_edition_proposal(lifecycle_request("LEGACY_CHILD", "ORA$BASE"))
                    .unwrap();
                let path = store
                    .store
                    .path_for(
                        EDITION_PROPOSAL_COLLECTION,
                        &StoreId::from_safe_segment(view.proposal_id.clone()).unwrap(),
                        EDITION_PROPOSAL_EXTENSION,
                    )
                    .unwrap();
                let legacy = serde_json::json!({"schema_version":version,"proposal_id":view.proposal_id,
                    "profile":view.profile,"child_edition":view.child_edition,"base_edition":view.parent_edition,
                    "objects":view.objects,"status":old_status,"coordination_scope":view.coordination_scope,
                    "created_at":view.created_at,"updated_at":view.updated_at});
                fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
                let canonical = store.edition_proposal(&view.proposal_id).unwrap();
                assert_eq!(canonical.schema_version, 3);
                assert_eq!(
                    canonical.status,
                    if old_status == "withdrawn" {
                        ChangeRequestState::Withdrawn
                    } else {
                        ChangeRequestState::Open
                    }
                );
                assert_eq!(canonical.database_identity, None);
                assert_eq!(canonical.stage_revision, 0);
                assert_eq!(canonical.verification_revision, None);
                assert_eq!(canonical.review_revision, None);
                let bytes = fs::read(&path).unwrap();
                let value: Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(value["schema_version"], 3, "migration is persisted on load");
                assert!(value.get("base_edition").is_none());
                assert_eq!(
                    store.edition_proposal(&view.proposal_id).unwrap(),
                    canonical
                );
                assert_eq!(
                    fs::read(&path).unwrap(),
                    bytes,
                    "canonical reload preserves the same state"
                );
            }
        }
    }

    #[test]
    fn ttl_sweeps_on_store_open_and_before_transition() {
        for on_open in [true, false] {
            let root = store_root(&format!("ttl-sweep-{on_open}"));
            let store = ChangeProposalStore::open(&root).unwrap();
            let view = open_empty(&store);
            let mut old = store.edition_proposal(&view.proposal_id).unwrap();
            let now = current_seconds();
            old.created_at = format!("unix:{:020}", now - 8 * 86400);
            old.updated_at = old.created_at.clone();
            old.expires_at = now - 86400;
            let receipt = &mut old.open_receipt.as_mut().unwrap().receipt.result;
            receipt.created_at = old.created_at.clone();
            receipt.updated_at = old.updated_at.clone();
            receipt.expires_at = old.expires_at;
            store.write_edition_proposal(&old).unwrap();
            let store = if on_open {
                drop(store);
                ChangeProposalStore::open(&root).unwrap()
            } else {
                store
            };
            if !on_open {
                assert!(matches!(
                    store.transition_edition_proposal(test_edition_transition(
                        &view,
                        ChangeRequestState::Withdrawn,
                        "before-transition"
                    )),
                    Err(ChangeProposalError::RevisionConflict {
                        expected: 0,
                        actual: 1
                    })
                ));
            }
            let expired = store.edition_proposal(&view.proposal_id).unwrap();
            assert_eq!(expired.status, ChangeRequestState::Expired);
            assert_eq!(expired.proposal_revision, 1);
        }
    }

    #[test]
    fn container_name_alone_is_not_identity() {
        let store = ChangeProposalStore::open(store_root("identity-required")).unwrap();
        let name_only = DatabaseIdentity {
            db_unique_name: "SYNTHETIC_DB".into(),
            dbid: String::new(),
            container_uid: "PDB_NAME".into(),
        };
        assert!(matches!(
            store.open_change_request(
                lifecycle_request("CHILD_A", "ORA$BASE"),
                &lifecycle_profile(),
                Some(name_only),
                "name-only"
            ),
            Err(ChangeProposalError::DatabaseIdentityRequired)
        ));
        let error = store
            .open_change_request(
                lifecycle_request("CHILD_A", "ORA$BASE"),
                &lifecycle_profile(),
                None,
                "missing",
            )
            .unwrap_err();
        assert!(error.to_string().contains("SYS.V_$CONTAINERS"));
        assert!(
            error
                .to_string()
                .contains("ordinary reads remain available")
        );
        assert!(store.list_edition_proposals().unwrap().is_empty());
        assert!(
            store
                .create_edition_proposal(lifecycle_request("LEGACY_CHILD", "ORA$BASE"))
                .is_ok(),
            "local-only draft metadata remains available"
        );
    }

    #[test]
    fn open_conflict_same_parent_edition_names_oracle_rule() {
        let store = ChangeProposalStore::open(store_root("oracle-parent-conflict")).unwrap();
        open_empty(&store);
        assert!(matches!(
            store.open_change_request(
                lifecycle_request("CHILD_B", "ORA$BASE"),
                &lifecycle_profile(),
                Some(database_identity()),
                "open-b"
            ),
            Err(ChangeProposalError::OpenRequestConflict {
                rule: OpenRequestConflictRule::OracleOneChildPerParent,
                ..
            })
        ));
    }

    #[test]
    fn open_conflict_same_pdb_names_oraclemcp_policy() {
        let store = ChangeProposalStore::open(store_root("product-pdb-conflict")).unwrap();
        open_empty(&store);
        assert!(matches!(
            store.open_change_request(
                lifecycle_request("CHILD_B", "OTHER_PARENT"),
                &lifecycle_profile(),
                Some(database_identity()),
                "open-b"
            ),
            Err(ChangeProposalError::OpenRequestConflict {
                rule: OpenRequestConflictRule::OraclemcpOnePerPdbPolicy,
                ..
            })
        ));
    }

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
    fn draft_rejects_a_caller_unit_that_disagrees_with_the_classifier() {
        let store = ChangeProposalStore::open(store_root("unit-mismatch")).expect("store");
        let error = store
            .draft(
                ChangeProposalDraftRequest {
                    profile: "prod".to_owned(),
                    author: ChangeProposalAuthorKind::Human,
                    title: Some("Mislabelled write".to_owned()),
                    statements: vec![ChangeProposalStatementDraft {
                        sql_template: "UPDATE accounts SET status = 'HOLD'".to_owned(),
                        binds: Vec::new(),
                        unit: Some(ChangeProposalApplyUnit::Read),
                        commit: None,
                        capture_dbms_output: None,
                        stored_verdict: None,
                    }],
                    stored_verdict: None,
                },
                "subject-sha256:test".to_owned(),
            )
            .expect_err("DML must not be saved as a read operation");

        assert!(
            error
                .to_string()
                .contains("unit does not match the classifier-required level")
        );
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
                coordination_scope: local_only_pdb_scope(),
            })
            .expect("create edition proposal");

        assert_eq!(proposal.status, ChangeRequestState::Open);
        assert_eq!(proposal.child_edition, "CHILD_V2");
        assert_eq!(proposal.parent_edition, "ORA$BASE");
        let record_path = root
            .join(EDITION_PROPOSAL_COLLECTION)
            .join(format!("{}.json", proposal.proposal_id));
        let record = fs::read_to_string(&record_path).expect("persisted record");
        assert!(record.contains("\"status\": \"open\""));
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
            .transition_edition_proposal(test_edition_transition(
                &proposal,
                ChangeRequestState::Withdrawn,
                "withdraw",
            ))
            .expect("withdraw draft metadata without database authority");
        assert_eq!(transitioned.status, ChangeRequestState::Withdrawn);
        let replay = store
            .transition_edition_proposal(test_edition_transition(
                &transitioned,
                ChangeRequestState::Withdrawn,
                "withdraw-again",
            ))
            .expect_err("replaying the same status must not reset a request");
        assert!(matches!(replay, ChangeProposalError::Invalid(_)));
    }

    fn identified_scope(dbid: &str, con_id: &str) -> PdbIdentityScope {
        PdbIdentityScope::ServiceStateStore {
            identity: oraclemcp_db::PdbIdentity {
                dbid: dbid.to_owned(),
                con_uid: con_id.to_owned(),
            },
        }
    }

    fn edition_request(scope: PdbIdentityScope, child: &str) -> EditionProposalCreateRequest {
        edition_request_for_profile("synthetic-profile", scope, child)
    }

    fn edition_request_for_profile(
        profile: &str,
        scope: PdbIdentityScope,
        child: &str,
    ) -> EditionProposalCreateRequest {
        EditionProposalCreateRequest {
            profile: profile.to_owned(),
            child_edition: child.to_owned(),
            base_edition: "ORA$BASE".to_owned(),
            objects: vec!["SYNTHETIC_VIEW".to_owned()],
            coordination_scope: scope,
        }
    }

    #[test]
    fn edition_proposals_conflict_only_for_the_same_identified_pdb() {
        let store = ChangeProposalStore::open(store_root("pdb-scope")).expect("store");
        store
            .create_edition_proposal(edition_request_for_profile(
                "profile_one",
                identified_scope("db-a", "pdb-1"),
                "CHILD_A",
            ))
            .expect("first PDB request");
        let conflict = store
            .create_edition_proposal(edition_request_for_profile(
                "profile_two",
                identified_scope("db-a", "pdb-1"),
                "CHILD_B",
            ))
            .expect_err("same PDB must serialize in one service state store");
        assert!(matches!(
            conflict,
            ChangeProposalError::OpenRequestConflict { .. }
        ));
        store
            .create_edition_proposal(edition_request(
                identified_scope("db-a", "pdb-2"),
                "CHILD_C",
            ))
            .expect("different PDB remains independent");
    }

    #[test]
    fn concurrent_profiles_share_one_pdb_request_slot_across_store_handles() {
        use std::sync::{Arc, Barrier};
        const CALLERS: usize = 16;
        for round in 0..4 {
            let store = ChangeProposalStore::open(store_root(&format!("pdb-concurrent-{round}")))
                .expect("store");
            let start = Arc::new(Barrier::new(CALLERS));
            let workers = (0..CALLERS)
                .map(|index| {
                    let handle = ChangeProposalStore::open_with_owner(store.owner.clone())
                        .expect("same service owner");
                    let start = Arc::clone(&start);
                    std::thread::spawn(move || {
                        let mut request = edition_request_for_profile(
                            &format!("profile_{index}"),
                            identified_scope("db-a", "pdb-1"),
                            &format!("CHILD_{index}"),
                        );
                        // The service policy is per PDB, not merely per parent.
                        request.base_edition = format!("PARENT_{index}");
                        start.wait();
                        handle.create_edition_proposal(request)
                    })
                })
                .collect::<Vec<_>>();
            let mut admitted = 0;
            for worker in workers {
                match worker.join().expect("request thread") {
                    Ok(_) => admitted += 1,
                    Err(error) => assert!(
                        matches!(error, ChangeProposalError::OpenRequestConflict { .. }),
                        "unexpected failure: {error}"
                    ),
                }
            }
            assert_eq!(
                admitted, 1,
                "exactly one positive request per PDB, round {round}"
            );
            assert_eq!(store.list_edition_proposals().unwrap().len(), 1);
        }
    }

    #[test]
    fn concurrent_review_cannot_resurrect_a_withdrawn_pdb_request() {
        use std::sync::{Arc, Barrier};
        for round in 0..16 {
            let store =
                ChangeProposalStore::open(store_root(&format!("pdb-transition-{round}"))).unwrap();
            let staged = stage(&store, &open_empty(&store), "initial-stage");
            let view = store
                .transition_edition_proposal(test_edition_transition(
                    &staged,
                    ChangeRequestState::Verified,
                    "initial-verify",
                ))
                .unwrap();
            let start = Arc::new(Barrier::new(2));
            let workers =
                [ChangeRequestState::Reviewing, ChangeRequestState::Withdrawn].map(|status| {
                    let handle = ChangeProposalStore::open_with_owner(store.owner.clone()).unwrap();
                    let start = Arc::clone(&start);
                    let view = view.clone();
                    std::thread::spawn(move || {
                        start.wait();
                        let mut result = handle.transition_edition_proposal(
                            test_edition_transition(&view, status, &format!("{status:?}")),
                        );
                        // CAS makes the losing request explicit. Withdrawal may
                        // retry once with the newly observed review revision.
                        if status == ChangeRequestState::Withdrawn
                            && matches!(result, Err(ChangeProposalError::RevisionConflict { .. }))
                        {
                            let current =
                                handle.edition_proposal(&view.proposal_id).unwrap().view();
                            result = handle.transition_edition_proposal(test_edition_transition(
                                &current,
                                status,
                                "withdraw-after-review",
                            ));
                        }
                        (status, result)
                    })
                });
            for worker in workers {
                let (status, result) = worker.join().unwrap();
                if status == ChangeRequestState::Withdrawn {
                    assert!(result.is_ok(), "withdrawal must complete: {result:?}");
                } else if let Err(error) = result {
                    assert!(matches!(
                        error,
                        ChangeProposalError::Invalid(_)
                            | ChangeProposalError::RevisionConflict { .. }
                    ));
                }
            }
            assert_eq!(
                store.edition_proposal(&view.proposal_id).unwrap().status,
                ChangeRequestState::Withdrawn
            );
            store
                .open_change_request(
                    lifecycle_request("NEW_CHILD", "ORA$BASE"),
                    &lifecycle_profile(),
                    Some(database_identity()),
                    "replacement",
                )
                .expect("withdrawal frees the PDB request slot");
        }
    }

    #[test]
    fn independent_service_stores_do_not_claim_pdb_global_exclusivity() {
        let left = ChangeProposalStore::open(store_root("pdb-service-left")).expect("left store");
        let right =
            ChangeProposalStore::open(store_root("pdb-service-right")).expect("right store");
        for (store, profile, child) in [
            (&left, "left_profile", "LEFT_CHILD"),
            (&right, "right_profile", "RIGHT_CHILD"),
        ] {
            let view = store
                .create_edition_proposal(edition_request_for_profile(
                    profile,
                    identified_scope("db-a", "pdb-1"),
                    child,
                ))
                .expect("each independent store admits its own request");
            let scope = serde_json::to_value(view.coordination_scope).unwrap();
            assert_eq!(scope["coordination_scope"], "service_state_store");
            assert!(!scope.to_string().contains("global"));
            assert_eq!(store.list_edition_proposals().unwrap().len(), 1);
        }
    }

    #[test]
    fn legacy_container_slot_is_migrated_to_explicit_local_only_identity() {
        let store = ChangeProposalStore::open(store_root("pdb-legacy-identity")).expect("store");
        let view = store
            .create_edition_proposal(edition_request(identified_scope("db-a", "3"), "OLD_CHILD"))
            .expect("request");
        let id = StoreId::from_safe_segment(view.proposal_id.clone()).unwrap();
        let path = store
            .store
            .path_for(EDITION_PROPOSAL_COLLECTION, &id, EDITION_PROPOSAL_EXTENSION)
            .unwrap();
        let legacy = serde_json::json!({
            "schema_version":1, "proposal_id":view.proposal_id, "profile":view.profile,
            "child_edition":view.child_edition, "base_edition":view.parent_edition,
            "objects":view.objects, "coordination_scope":view.coordination_scope,
            "status":"reviewing", "created_at":view.created_at, "updated_at":view.updated_at,
        });
        fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let canonical = store.edition_proposal(&view.proposal_id).unwrap();
        assert_eq!(canonical.schema_version, 3);
        assert_eq!(canonical.status, ChangeRequestState::Open);
        assert_eq!(canonical.verification_revision, None);
        assert_eq!(
            canonical.coordination_scope,
            PdbIdentityScope::LocalOnly {
                observation: oraclemcp_db::PdbIdentityObservation::LegacyContainerIdentity,
            }
        );
        assert_eq!(canonical.child_edition, view.child_edition);
        assert_eq!(canonical.objects, view.objects);
        let transitioned = store
            .transition_edition_proposal(test_edition_transition(
                &canonical.view(),
                ChangeRequestState::Withdrawn,
                "withdraw-migrated",
            ))
            .unwrap();
        assert_eq!(
            transitioned.coordination_scope,
            canonical.coordination_scope
        );
        let id = StoreId::from_safe_segment(view.proposal_id).unwrap();
        let bytes = fs::read(
            store
                .store
                .path_for(EDITION_PROPOSAL_COLLECTION, &id, EDITION_PROPOSAL_EXTENSION)
                .unwrap(),
        )
        .unwrap();
        let persisted: EditionProposal = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(persisted.schema_version, 3);
        assert_eq!(persisted.coordination_scope, canonical.coordination_scope);
    }

    #[test]
    fn edition_pdb_scope_conflict_survives_store_restart() {
        let root = store_root("pdb-scope-restart");
        ChangeProposalStore::open(&root)
            .expect("first store")
            .create_edition_proposal(edition_request(
                identified_scope("db-a", "pdb-1"),
                "CHILD_A",
            ))
            .expect("persist first PDB request");
        let restarted = ChangeProposalStore::open(&root).expect("restarted store");
        let conflict = restarted
            .create_edition_proposal(edition_request(
                identified_scope("db-a", "pdb-1"),
                "CHILD_B",
            ))
            .expect_err("persisted same-PDB request must survive restart");
        assert!(matches!(
            conflict,
            ChangeProposalError::OpenRequestConflict { .. }
        ));
    }
}
