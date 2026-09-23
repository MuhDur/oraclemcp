//! Operator-only default-edition execution. No agent SQL or MCP tool reaches
//! this path: its only input is an edition name loaded from a reviewed proposal.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use oraclemcp_guard::{OperatingLevel, OperatorStatementClass};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use crate::{
    DispatchContext, DispatchOutcome, OracleMcpServer,
    change_proposal::{EditionProposal, EditionProposalStatus, normalize_edition_identifier},
};

const CONFIRMATION_TTL: Duration = Duration::from_secs(120);
const MAX_PENDING_CONFIRMATIONS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditionFlipTarget {
    Merge,
    Rollback,
}

impl EditionFlipTarget {
    pub const fn action(self) -> &'static str {
        match self {
            Self::Merge => "merge",
            Self::Rollback => "rollback",
        }
    }

    fn edition(self, proposal: &EditionProposal) -> &str {
        match self {
            Self::Merge => &proposal.child_edition,
            Self::Rollback => &proposal.base_edition,
        }
    }
}

/// This key comes from the authenticated operator transport, never a request
/// field. A default value is deliberately unauthenticated for testability.
#[derive(Clone, Debug, Default)]
pub struct OperatorAuth {
    subject_key: Option<String>,
}

impl OperatorAuth {
    pub(crate) fn authenticated(subject_key: String) -> Self {
        Self {
            subject_key: Some(subject_key),
        }
    }

    fn key(&self) -> Result<&str, EditionExecutorRefusal> {
        self.subject_key
            .as_deref()
            .filter(|key| !key.is_empty())
            .ok_or(EditionExecutorRefusal::Unauthenticated)
    }
}

/// Current lane facts, obtained afresh from the dispatcher before preview and
/// again before apply. The dispatcher repeats the same checks at the DB call.
#[derive(Clone, Debug)]
pub struct OperatorLanePolicy {
    pub profile: String,
    pub max_level: OperatingLevel,
    pub effective_ceiling: OperatingLevel,
    pub current_level: OperatingLevel,
    pub protected: bool,
}

impl OperatorLanePolicy {
    fn require_admin(&self, proposal: &EditionProposal) -> Result<(), EditionExecutorRefusal> {
        if proposal.status != EditionProposalStatus::Reviewing {
            return Err(EditionExecutorRefusal::ProposalNotReviewed);
        }
        if self.protected {
            return Err(EditionExecutorRefusal::ProtectedProfile);
        }
        if self.max_level != OperatingLevel::Admin
            || self.effective_ceiling != OperatingLevel::Admin
            || self.current_level != OperatingLevel::Admin
        {
            return Err(EditionExecutorRefusal::AdminRequired);
        }
        if self.profile != proposal.profile {
            return Err(EditionExecutorRefusal::ProfileMismatch);
        }
        Ok(())
    }
}

/// A proposal-derived Oracle identifier. Callers cannot construct one from
/// arbitrary SQL, and the quoted rendering cannot escape the fixed template.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedEditionIdent(String);

impl ValidatedEditionIdent {
    fn from_proposal(
        proposal: &EditionProposal,
        target: EditionFlipTarget,
    ) -> Result<Self, EditionExecutorRefusal> {
        let value = target.edition(proposal);
        if value.is_empty()
            || value.len() > 128
            || value.contains(['"', '\0'])
            || value.chars().any(char::is_control)
            || normalize_edition_identifier(value.to_owned())
                .ok()
                .as_deref()
                != Some(value)
        {
            return Err(EditionExecutorRefusal::InvalidIdentifier);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn rendered_sql(&self) -> Result<String, EditionExecutorRefusal> {
        let sql = format!("ALTER DATABASE DEFAULT EDITION = \"{}\"", self.0);
        if OperatorStatementClass::from_exact_rendered_sql(&sql)
            != Some(OperatorStatementClass::DefaultEditionFlip)
        {
            return Err(EditionExecutorRefusal::TemplateMismatch);
        }
        Ok(sql)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EditionExecutorRefusal {
    Unauthenticated,
    ProtectedProfile,
    AdminRequired,
    ProfileMismatch,
    ProposalNotReviewed,
    InvalidIdentifier,
    TemplateMismatch,
    ConfirmationRequired,
    ConfirmationMismatch,
    ConfirmationCapacity,
    RandomUnavailable,
}

impl EditionExecutorRefusal {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Unauthenticated => "operator_auth_required",
            Self::ProtectedProfile => "protected_profile",
            Self::AdminRequired => "operator_admin_required",
            Self::ProfileMismatch => "edition_profile_mismatch",
            Self::ProposalNotReviewed => "edition_proposal_not_reviewed",
            Self::InvalidIdentifier => "invalid_edition_identifier",
            Self::TemplateMismatch => "operator_edition_template_mismatch",
            Self::ConfirmationRequired => "edition_default_confirmation_required",
            Self::ConfirmationMismatch => "edition_default_confirmation_mismatch",
            Self::ConfirmationCapacity => "edition_confirmation_capacity",
            Self::RandomUnavailable => "edition_confirmation_random_unavailable",
        }
    }
}

#[derive(Clone, Debug)]
pub struct OperatorConfirmation {
    pub token: String,
    pub sql_sha256: String,
}

#[derive(Clone, Debug)]
struct PendingConfirmation {
    subject_key: String,
    proposal_id: String,
    target: EditionFlipTarget,
    edition: ValidatedEditionIdent,
    lane_generation: Option<u64>,
    expires_at: Instant,
}

/// One-use confirmation store shared by all operator HTTP requests in this
/// transport. A consumed token is never restored after a database failure.
#[derive(Debug, Default)]
pub struct OperatorEditionExecutor {
    pending: Mutex<HashMap<String, PendingConfirmation>>,
}

/// The route supplies server-derived authority and a live lane context; no SQL
/// or caller-selected edition can enter the executor.
pub struct EditionApplyInput<'a> {
    pub auth: &'a OperatorAuth,
    pub confirmation: &'a str,
    pub proposal: &'a EditionProposal,
    pub target: EditionFlipTarget,
    pub lane_generation: Option<u64>,
    pub policy: &'a OperatorLanePolicy,
    pub server: &'a OracleMcpServer,
    pub context: DispatchContext<'a>,
}

impl OperatorEditionExecutor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn preview(
        &self,
        auth: &OperatorAuth,
        proposal: &EditionProposal,
        target: EditionFlipTarget,
        lane_generation: Option<u64>,
        policy: &OperatorLanePolicy,
    ) -> Result<OperatorConfirmation, EditionExecutorRefusal> {
        let subject_key = auth.key()?;
        policy.require_admin(proposal)?;
        let edition = ValidatedEditionIdent::from_proposal(proposal, target)?;
        let sql = edition.rendered_sql()?;
        let mut pending = self.pending.lock();
        let now = Instant::now();
        pending.retain(|_, entry| entry.expires_at > now);
        if pending.len() >= MAX_PENDING_CONFIRMATIONS {
            return Err(EditionExecutorRefusal::ConfirmationCapacity);
        }
        let mut random = [0u8; 32];
        getrandom::getrandom(&mut random).map_err(|_| EditionExecutorRefusal::RandomUnavailable)?;
        let token = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let digest = Sha256::digest(sql.as_bytes());
        let digest_hex = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        pending.insert(
            token.clone(),
            PendingConfirmation {
                subject_key: subject_key.to_owned(),
                proposal_id: proposal.proposal_id.clone(),
                target,
                edition,
                lane_generation,
                expires_at: now + CONFIRMATION_TTL,
            },
        );
        Ok(OperatorConfirmation {
            token,
            sql_sha256: format!("sha256:{digest_hex}"),
        })
    }

    pub fn apply(
        &self,
        input: EditionApplyInput<'_>,
    ) -> Result<DispatchOutcome, EditionExecutorRefusal> {
        let edition = self.consume_confirmation(
            input.auth,
            input.confirmation,
            input.proposal,
            input.target,
            input.lane_generation,
            input.policy,
        )?;
        Ok(input.server.run_operator_edition_blocking_with_context(
            input.context,
            edition,
            &input.proposal.profile,
        ))
    }

    fn consume_confirmation(
        &self,
        auth: &OperatorAuth,
        token: &str,
        proposal: &EditionProposal,
        target: EditionFlipTarget,
        lane_generation: Option<u64>,
        policy: &OperatorLanePolicy,
    ) -> Result<ValidatedEditionIdent, EditionExecutorRefusal> {
        let subject_key = auth.key()?;
        policy.require_admin(proposal)?;
        if token.is_empty() {
            return Err(EditionExecutorRefusal::ConfirmationRequired);
        }
        let edition = ValidatedEditionIdent::from_proposal(proposal, target)?;
        let _ = edition.rendered_sql()?;
        let mut pending = self.pending.lock();
        let now = Instant::now();
        pending.retain(|_, entry| entry.expires_at > now);
        let Some(entry) = pending.get(token) else {
            return Err(EditionExecutorRefusal::ConfirmationMismatch);
        };
        if entry.subject_key != subject_key
            || entry.proposal_id != proposal.proposal_id
            || entry.target != target
            || entry.edition != edition
            || entry.lane_generation != lane_generation
        {
            return Err(EditionExecutorRefusal::ConfirmationMismatch);
        }
        pending.remove(token);
        Ok(edition)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::change_proposal::EditionProposalStatus;

    fn proposal() -> EditionProposal {
        EditionProposal {
            schema_version: 1,
            proposal_id: "synthetic-proposal".to_owned(),
            profile: "synthetic-admin".to_owned(),
            child_edition: "CHILD_V2".to_owned(),
            base_edition: "ORA$BASE".to_owned(),
            objects: vec!["SYNTHETIC_VIEW".to_owned()],
            status: EditionProposalStatus::Reviewing,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    fn policy() -> OperatorLanePolicy {
        OperatorLanePolicy {
            profile: "synthetic-admin".to_owned(),
            max_level: OperatingLevel::Admin,
            effective_ceiling: OperatingLevel::Admin,
            current_level: OperatingLevel::Admin,
            protected: false,
        }
    }

    #[test]
    fn executor_refuses_max_level_below_admin() {
        let mut lane = policy();
        lane.max_level = OperatingLevel::Ddl;
        assert_eq!(
            OperatorEditionExecutor::new()
                .preview(
                    &OperatorAuth::authenticated("operator-a".to_owned()),
                    &proposal(),
                    EditionFlipTarget::Merge,
                    Some(7),
                    &lane,
                )
                .unwrap_err(),
            EditionExecutorRefusal::AdminRequired
        );
    }

    #[test]
    fn executor_refuses_protected_profile() {
        let mut lane = policy();
        lane.protected = true;
        assert_eq!(
            OperatorEditionExecutor::new()
                .preview(
                    &OperatorAuth::authenticated("operator-a".to_owned()),
                    &proposal(),
                    EditionFlipTarget::Merge,
                    Some(7),
                    &lane,
                )
                .unwrap_err(),
            EditionExecutorRefusal::ProtectedProfile
        );
    }

    #[test]
    fn executor_refuses_unauthenticated() {
        assert_eq!(
            OperatorEditionExecutor::new()
                .preview(
                    &OperatorAuth::default(),
                    &proposal(),
                    EditionFlipTarget::Merge,
                    Some(7),
                    &policy(),
                )
                .unwrap_err(),
            EditionExecutorRefusal::Unauthenticated
        );
    }

    #[test]
    fn executor_refuses_lane_generation_mismatch() {
        let executor = OperatorEditionExecutor::new();
        let auth = OperatorAuth::authenticated("operator-a".to_owned());
        let preview = executor
            .preview(
                &auth,
                &proposal(),
                EditionFlipTarget::Merge,
                Some(7),
                &policy(),
            )
            .expect("preview");
        assert_eq!(
            executor
                .consume_confirmation(
                    &auth,
                    &preview.token,
                    &proposal(),
                    EditionFlipTarget::Merge,
                    Some(8),
                    &policy()
                )
                .unwrap_err(),
            EditionExecutorRefusal::ConfirmationMismatch
        );
    }

    #[test]
    fn executor_confirmation_is_one_use() {
        let executor = OperatorEditionExecutor::new();
        let auth = OperatorAuth::authenticated("operator-a".to_owned());
        let preview = executor
            .preview(
                &auth,
                &proposal(),
                EditionFlipTarget::Merge,
                Some(7),
                &policy(),
            )
            .expect("preview");
        assert_eq!(
            executor
                .consume_confirmation(
                    &auth,
                    &preview.token,
                    &proposal(),
                    EditionFlipTarget::Merge,
                    Some(7),
                    &policy()
                )
                .expect("first use")
                .as_str(),
            "CHILD_V2"
        );
        assert_eq!(
            executor
                .consume_confirmation(
                    &auth,
                    &preview.token,
                    &proposal(),
                    EditionFlipTarget::Merge,
                    Some(7),
                    &policy()
                )
                .unwrap_err(),
            EditionExecutorRefusal::ConfirmationMismatch
        );
    }

    #[test]
    fn executor_rejects_identifier_with_quote_or_nul() {
        for identifier in ["CHILD\"V2", "CHILD\0V2"] {
            let mut proposal = proposal();
            proposal.child_edition = identifier.to_owned();
            assert_eq!(
                ValidatedEditionIdent::from_proposal(&proposal, EditionFlipTarget::Merge)
                    .unwrap_err(),
                EditionExecutorRefusal::InvalidIdentifier
            );
        }
    }

    #[test]
    fn executor_rendered_sql_is_exact_template() {
        let edition = ValidatedEditionIdent::from_proposal(&proposal(), EditionFlipTarget::Merge)
            .expect("validated identifier");
        assert_eq!(
            edition.rendered_sql().expect("fixed rendering"),
            "ALTER DATABASE DEFAULT EDITION = \"CHILD_V2\""
        );
    }
}
