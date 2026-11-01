//! Versioned impact facts for previews and later apply-time comparison.
//!
//! Only `decisive` enters the digest. Observations are display and audit data;
//! a changing SCN or cost estimate cannot silently invalidate a grant.

use std::{collections::BTreeMap, future::Future, time::Instant};

use oraclemcp_error::{ErrorClass, ErrorEnvelope, StatementOutcome};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    action_envelope::ActionKind,
    effective_dml_plan::{DML_REWRITE_ALGORITHM_VERSION, EffectiveDmlPlanV1},
};

const IMPACT_DOMAIN: &[u8] = b"omcp/impact-binding/decisive/v1";
pub const IMPACT_BINDING_VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    LevelBelowRequired,
    UntrustedTriggers,
    UnsupportedDmlShape,
    EngineNotWired,
    ReadOnlyTxn,
    HardParseCallbacks,
    Vpd,
    NoPrivilege,
    PlanTableUnverified,
    Timeout,
    Truncated,
    NotWired,
    CatalogUnavailable,
    UnresolvedDependency,
    EngineFailed,
    ObjectNotFound,
    SyntaxError,
    ConnectionFailed,
    RuntimeStateRequired,
    ChallengeRequired,
    RepreviewRequired,
    LeaseRequired,
    ForbiddenStatement,
    Busy,
    SessionBusy,
    AtCapacity,
    InvalidArguments,
    PolicyDenied,
    RequestCancelled,
    Transient,
    FlashbackRetentionExceeded,
    FlashbackDefinitionChanged,
    FlashbackNotFlashbackable,
    FlashbackCapabilityUnavailable,
    SnapshotTooOld,
    Internal,
    ImpactDecisiveUnavailable,
    ImpactDecisiveTruncated,
    /// This optional observation was not collected for the current action.
    NotCollected,
}

impl UnavailableReason {
    /// Keep an executor refusal's machine-readable cause in advisory fields.
    /// Unknown future classes remain unavailable rather than becoming a value.
    #[must_use]
    pub const fn from_error_class(class: ErrorClass) -> Self {
        match class {
            ErrorClass::InsufficientPrivilege => Self::NoPrivilege,
            ErrorClass::OperatingLevelTooLow => Self::LevelBelowRequired,
            ErrorClass::Timeout => Self::Timeout,
            ErrorClass::ObjectNotFound => Self::ObjectNotFound,
            ErrorClass::SyntaxError => Self::SyntaxError,
            ErrorClass::ConnectionFailed => Self::ConnectionFailed,
            ErrorClass::RuntimeStateRequired => Self::RuntimeStateRequired,
            ErrorClass::ChallengeRequired => Self::ChallengeRequired,
            ErrorClass::RepreviewRequired => Self::RepreviewRequired,
            ErrorClass::ImpactDecisiveUnavailable => Self::ImpactDecisiveUnavailable,
            ErrorClass::ImpactDecisiveTruncated => Self::ImpactDecisiveTruncated,
            ErrorClass::LeaseRequired => Self::LeaseRequired,
            ErrorClass::ForbiddenStatement => Self::ForbiddenStatement,
            ErrorClass::Busy => Self::Busy,
            ErrorClass::SessionBusy => Self::SessionBusy,
            ErrorClass::AtCapacity => Self::AtCapacity,
            ErrorClass::InvalidArguments => Self::InvalidArguments,
            ErrorClass::PolicyDenied => Self::PolicyDenied,
            ErrorClass::RequestCancelled => Self::RequestCancelled,
            ErrorClass::Transient => Self::Transient,
            ErrorClass::FlashbackRetentionExceeded => Self::FlashbackRetentionExceeded,
            ErrorClass::FlashbackDefinitionChanged => Self::FlashbackDefinitionChanged,
            ErrorClass::FlashbackNotFlashbackable => Self::FlashbackNotFlashbackable,
            ErrorClass::FlashbackCapabilityUnavailable => Self::FlashbackCapabilityUnavailable,
            ErrorClass::SnapshotTooOld => Self::SnapshotTooOld,
            ErrorClass::Internal => Self::Internal,
            _ => Self::CatalogUnavailable,
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::LevelBelowRequired => 1,
            Self::UntrustedTriggers => 2,
            Self::UnsupportedDmlShape => 3,
            Self::EngineNotWired => 4,
            Self::ReadOnlyTxn => 5,
            Self::HardParseCallbacks => 6,
            Self::Vpd => 7,
            Self::NoPrivilege => 8,
            Self::PlanTableUnverified => 9,
            Self::Timeout => 10,
            Self::Truncated => 11,
            Self::NotWired => 12,
            Self::CatalogUnavailable => 13,
            Self::UnresolvedDependency => 14,
            Self::EngineFailed => 15,
            Self::ObjectNotFound => 16,
            Self::SyntaxError => 17,
            Self::ConnectionFailed => 18,
            Self::RuntimeStateRequired => 19,
            Self::ChallengeRequired => 20,
            Self::RepreviewRequired => 21,
            Self::LeaseRequired => 22,
            Self::ForbiddenStatement => 23,
            Self::Busy => 24,
            Self::SessionBusy => 25,
            Self::AtCapacity => 26,
            Self::InvalidArguments => 27,
            Self::PolicyDenied => 28,
            Self::RequestCancelled => 29,
            Self::Transient => 30,
            Self::FlashbackRetentionExceeded => 31,
            Self::FlashbackDefinitionChanged => 32,
            Self::FlashbackNotFlashbackable => 33,
            Self::FlashbackCapabilityUnavailable => 34,
            Self::SnapshotTooOld => 35,
            Self::Internal => 36,
            Self::ImpactDecisiveUnavailable => 37,
            Self::ImpactDecisiveTruncated => 38,
            Self::NotCollected => 39,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotApplicableReason {
    NotDml,
    NoObject,
    NoSource,
    NoEffect,
    LevelBelowRequired,
    UntrustedTriggers,
}

impl NotApplicableReason {
    const fn tag(self) -> u8 {
        match self {
            Self::NotDml => 1,
            Self::NoObject => 2,
            Self::NoSource => 3,
            Self::NoEffect => 4,
            Self::LevelBelowRequired => 5,
            Self::UntrustedTriggers => 6,
        }
    }
}

/// A field is always present. Unavailable and inapplicable have closed,
/// machine-readable reasons rather than a missing or null value.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum FieldStatus<T> {
    Computed { value: T },
    Estimated { value: T },
    Unavailable { reason: UnavailableReason },
    NotApplicable { reason: NotApplicableReason },
}

impl<T> FieldStatus<T> {
    #[must_use]
    pub const fn not_collected() -> Self {
        Self::Unavailable {
            reason: UnavailableReason::NotCollected,
        }
    }

    #[must_use]
    pub const fn not_wired() -> Self {
        Self::Unavailable {
            reason: UnavailableReason::NotWired,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ObjectFact {
    pub identity: FieldStatus<String>,
    pub status: FieldStatus<String>,
    pub source_hash: FieldStatus<[u8; 32]>,
    pub dependency_hash: FieldStatus<[u8; 32]>,
    pub trigger_hash: FieldStatus<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DbIdentity {
    pub dbid: u64,
    pub con_uid: u64,
}

/// Closed identifiers shared by admission and the existing fact producers.
/// Producer-owned proofs are commitments, never raw source or bind values.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisiveField {
    Envelope,
    ObjectIdentities,
    ObjectStatus,
    MutationEffectClosure,
    Rows,
    Edition,
    CurrentSchema,
    ProfileGeneration,
    LaneGeneration,
    Dependents,
    PredictedInvalidSet,
    DdlEffectClosure,
    SourceEffects,
    Reversibility,
    ProfileCeiling,
    #[serde(rename = "oauth_ceiling")]
    OAuthCeiling,
    ClosureFactKey,
    RoutineEffects,
    MaskingProfileOutput,
    EditionManifest,
    ChangedEditionManifest,
    DbIdentity,
    DefaultEqualsBase,
    EditionParentage,
    EditionExposure,
    ServiceEditions,
    ScopeDigest,
    PolicyFloor,
}

/// Shape and scope come from server classification. Strict dependency impact
/// is server policy; none of these flags is client authority.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DecisiveMatrixContext {
    pub dml_rows_supported: bool,
    pub has_ddl_event: bool,
    pub statement_scoped: bool,
    pub require_impact: bool,
}

pub struct DecisiveFieldMatrixV1;

impl DecisiveFieldMatrixV1 {
    #[must_use]
    pub fn required(
        action: &ActionKind,
        context: DecisiveMatrixContext,
    ) -> &'static [DecisiveField] {
        use DecisiveField::*;
        const DML: &[DecisiveField] = &[
            Envelope,
            ObjectIdentities,
            ObjectStatus,
            MutationEffectClosure,
            Edition,
            CurrentSchema,
            ProfileGeneration,
            LaneGeneration,
        ];
        const DML_WITH_ROWS: &[DecisiveField] = &[
            Envelope,
            ObjectIdentities,
            ObjectStatus,
            MutationEffectClosure,
            Edition,
            CurrentSchema,
            ProfileGeneration,
            LaneGeneration,
            Rows,
        ];
        const DDL: &[DecisiveField] = &[
            Envelope,
            ObjectIdentities,
            ObjectStatus,
            Dependents,
            PredictedInvalidSet,
            DdlEffectClosure,
            SourceEffects,
            Reversibility,
            Edition,
            CurrentSchema,
            ProfileGeneration,
            LaneGeneration,
        ];
        const DDL_OBSERVATIONAL: &[DecisiveField] = &[
            Envelope,
            ObjectIdentities,
            ObjectStatus,
            DdlEffectClosure,
            SourceEffects,
            Reversibility,
            Edition,
            CurrentSchema,
            ProfileGeneration,
            LaneGeneration,
        ];
        const STATEMENT: &[DecisiveField] = &[Envelope, ProfileGeneration, LaneGeneration];
        const ELEVATION: &[DecisiveField] = &[
            Envelope,
            ProfileCeiling,
            OAuthCeiling,
            ProfileGeneration,
            LaneGeneration,
        ];
        const CUSTOM: &[DecisiveField] = &[
            Envelope,
            ClosureFactKey,
            RoutineEffects,
            MaskingProfileOutput,
            ProfileGeneration,
            LaneGeneration,
        ];
        const CUSTOM_DDL: &[DecisiveField] = &[
            Envelope,
            ClosureFactKey,
            RoutineEffects,
            MaskingProfileOutput,
            DdlEffectClosure,
            ProfileGeneration,
            LaneGeneration,
        ];
        const PROMOTION: &[DecisiveField] = &[
            Envelope,
            EditionManifest,
            ChangedEditionManifest,
            DbIdentity,
            DefaultEqualsBase,
            EditionParentage,
            EditionExposure,
            ServiceEditions,
            DdlEffectClosure,
            ProfileGeneration,
            LaneGeneration,
        ];
        const PROMOTION_WITHOUT_DDL_EVENT: &[DecisiveField] = &[
            Envelope,
            EditionManifest,
            ChangedEditionManifest,
            DbIdentity,
            DefaultEqualsBase,
            EditionParentage,
            EditionExposure,
            ServiceEditions,
            ProfileGeneration,
            LaneGeneration,
        ];
        const GRANT: &[DecisiveField] = &[
            Envelope,
            ScopeDigest,
            MutationEffectClosure,
            Rows,
            PolicyFloor,
            ProfileGeneration,
            LaneGeneration,
        ];
        // No wildcard: a new ActionKind must explicitly select its policy.
        match action {
            ActionKind::ExecuteDml | ActionKind::ExecuteDdlAdmin if context.statement_scoped => {
                STATEMENT
            }
            ActionKind::ExecuteDml | ActionKind::PreviewDmlSandbox => {
                if context.dml_rows_supported {
                    DML_WITH_ROWS
                } else {
                    DML
                }
            }
            ActionKind::ExecuteDdlAdmin
            | ActionKind::CompileObject
            | ActionKind::CreateOrReplace
            | ActionKind::PatchSource => {
                if context.require_impact {
                    DDL
                } else {
                    DDL_OBSERVATIONAL
                }
            }
            ActionKind::SetSessionLevel { .. } => ELEVATION,
            ActionKind::CustomToolCall => {
                if context.has_ddl_event {
                    CUSTOM_DDL
                } else {
                    CUSTOM
                }
            }
            ActionKind::ChangeRequestPromote => {
                if context.has_ddl_event {
                    PROMOTION
                } else {
                    PROMOTION_WITHOUT_DDL_EVENT
                }
            }
            ActionKind::GrantCreate | ActionKind::GrantUse => GRANT,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DecisiveRefusalReason {
    Unavailable { reason: UnavailableReason },
    Estimated,
    NotApplicable { reason: NotApplicableReason },
    Missing,
    UnsupportedVersion { found: u8 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, thiserror::Error)]
#[error("decisive field {field:?} is not computed: {reason:?}")]
pub struct DecisiveRefusal {
    pub field: DecisiveField,
    pub reason: DecisiveRefusalReason,
}

impl DecisiveRefusal {
    /// Convert only closed identifiers and causes to the public refusal.
    /// No field values, SQL source, or bind buffers cross this boundary.
    #[must_use]
    pub fn into_envelope(self) -> ErrorEnvelope {
        fn name(value: impl Serialize) -> String {
            serde_json::to_value(value)
                .expect("closed impact identifier serializes")
                .as_str()
                .expect("closed impact identifier is a string")
                .to_owned()
        }
        let (class, reason) = match self.reason {
            DecisiveRefusalReason::Unavailable {
                reason: UnavailableReason::Truncated | UnavailableReason::ImpactDecisiveTruncated,
            } => (ErrorClass::ImpactDecisiveTruncated, "truncated".to_owned()),
            DecisiveRefusalReason::Unavailable { reason } => {
                (ErrorClass::ImpactDecisiveUnavailable, name(reason))
            }
            DecisiveRefusalReason::Estimated => {
                (ErrorClass::ImpactDecisiveUnavailable, "estimated".into())
            }
            DecisiveRefusalReason::NotApplicable { reason } => (
                ErrorClass::ImpactDecisiveUnavailable,
                format!("not_applicable:{}", name(reason)),
            ),
            DecisiveRefusalReason::Missing => {
                (ErrorClass::ImpactDecisiveUnavailable, "missing".into())
            }
            DecisiveRefusalReason::UnsupportedVersion { found } => (
                ErrorClass::ImpactDecisiveUnavailable,
                format!("unsupported_version:{found}"),
            ),
        };
        ErrorEnvelope::new(
            class,
            "required impact facts are not complete; confirmation refused",
        )
        .with_impact_decisive(name(self.field), reason)
        .with_statement_outcome(StatementOutcome::NotStarted)
    }
}

fn require_computed<T>(
    field: DecisiveField,
    status: &FieldStatus<T>,
) -> Result<(), DecisiveRefusal> {
    let reason = match status {
        FieldStatus::Computed { .. } => return Ok(()),
        FieldStatus::Estimated { .. } => DecisiveRefusalReason::Estimated,
        FieldStatus::Unavailable { reason } => {
            DecisiveRefusalReason::Unavailable { reason: *reason }
        }
        FieldStatus::NotApplicable { reason } => {
            DecisiveRefusalReason::NotApplicable { reason: *reason }
        }
    };
    Err(DecisiveRefusal { field, reason })
}

/// Required facts cannot be waived by `require_impact` or by unavailable
/// advisory fields. Nested object identities must themselves be computed.
pub fn check_decisive(
    binding: &ImpactBindingV1,
    required: &[DecisiveField],
) -> Result<(), DecisiveRefusal> {
    if binding.version != IMPACT_BINDING_VERSION {
        return Err(DecisiveRefusal {
            field: DecisiveField::Envelope,
            reason: DecisiveRefusalReason::UnsupportedVersion {
                found: binding.version,
            },
        });
    }
    for &field in required {
        let facts = &binding.decisive;
        match field {
            DecisiveField::Envelope => require_computed(field, &facts.envelope_digest)?,
            DecisiveField::ObjectIdentities => {
                require_computed(field, &facts.objects)?;
                if let FieldStatus::Computed { value: objects } = &facts.objects {
                    for object in objects {
                        require_computed(field, &object.identity)?;
                    }
                }
            }
            DecisiveField::ObjectStatus => {
                require_computed(field, &facts.objects)?;
                if let FieldStatus::Computed { value: objects } = &facts.objects {
                    for object in objects {
                        require_computed(field, &object.status)?;
                    }
                }
            }
            DecisiveField::Edition => require_computed(field, &facts.edition)?,
            DecisiveField::CurrentSchema => require_computed(field, &facts.current_schema)?,
            DecisiveField::ProfileGeneration => require_computed(field, &facts.profile_generation)?,
            DecisiveField::LaneGeneration => require_computed(field, &facts.lane_generation)?,
            DecisiveField::DbIdentity => require_computed(field, &facts.db_identity)?,
            DecisiveField::ScopeDigest => {
                require_computed(field, &facts.scope_digest)?;
                if matches!(facts.scope_digest, FieldStatus::Computed { value: None }) {
                    return Err(DecisiveRefusal {
                        field,
                        reason: DecisiveRefusalReason::Missing,
                    });
                }
            }
            DecisiveField::MutationEffectClosure
            | DecisiveField::Rows
            | DecisiveField::Dependents
            | DecisiveField::PredictedInvalidSet
            | DecisiveField::DdlEffectClosure
            | DecisiveField::SourceEffects
            | DecisiveField::Reversibility
            | DecisiveField::ProfileCeiling
            | DecisiveField::OAuthCeiling
            | DecisiveField::ClosureFactKey
            | DecisiveField::RoutineEffects
            | DecisiveField::MaskingProfileOutput
            | DecisiveField::EditionManifest
            | DecisiveField::ChangedEditionManifest
            | DecisiveField::DefaultEqualsBase
            | DecisiveField::EditionParentage
            | DecisiveField::EditionExposure
            | DecisiveField::ServiceEditions
            | DecisiveField::PolicyFloor => {
                let status = facts.action_fields.get(&field).ok_or(DecisiveRefusal {
                    field,
                    reason: DecisiveRefusalReason::Missing,
                })?;
                require_computed(field, status)?;
            }
        }
    }
    Ok(())
}

/// A failed current computation and a changed approved value are distinct.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DecisiveRevalidationRefusal {
    #[error(transparent)]
    Unavailable(#[from] DecisiveRefusal),
    #[error("decisive field {field:?} changed")]
    Changed { field: DecisiveField },
}

impl DecisiveRevalidationRefusal {
    #[must_use]
    pub fn into_envelope(self) -> ErrorEnvelope {
        match self {
            Self::Unavailable(refusal) => refusal.into_envelope(),
            Self::Changed { field } => ErrorEnvelope::new(
                ErrorClass::RepreviewRequired,
                "REPREVIEW_REQUIRED: a decisive impact fact changed; preview again",
            )
            .with_impact_decisive(
                serde_json::to_value(field)
                    .expect("field identifier")
                    .as_str()
                    .expect("field string"),
                "changed",
            )
            .with_statement_outcome(StatementOutcome::NotStarted),
        }
    }
}

/// Compare exactly the fields selected by the matrix, including the bounded
/// catalog inputs used to revalidate a source/effect proof without reanalysis.
pub fn check_decisive_revalidation(
    approved: &ImpactBindingV1,
    current: &ImpactBindingV1,
    required: &[DecisiveField],
) -> Result<(), DecisiveRevalidationRefusal> {
    check_decisive(approved, required)?;
    for field in required
        .iter()
        .copied()
        .chain(computed_observations(approved))
    {
        if field_fingerprint(approved, field) != field_fingerprint(current, field) {
            return Err(DecisiveRevalidationRefusal::Changed { field });
        }
    }
    check_decisive(current, required)?;
    Ok(())
}

pub(crate) fn computed_observations(
    binding: &ImpactBindingV1,
) -> impl Iterator<Item = DecisiveField> + '_ {
    [
        DecisiveField::Dependents,
        DecisiveField::PredictedInvalidSet,
    ]
    .into_iter()
    .filter(|field| {
        matches!(
            binding.decisive.action_fields.get(field),
            Some(FieldStatus::Computed { .. })
        )
    })
}

#[derive(Clone, Copy)]
enum ObjectProjection {
    Identity,
    Status,
    ProofInputs,
}

fn object_projection(
    objects: &FieldStatus<Vec<ObjectFact>>,
    projection: ObjectProjection,
) -> Value {
    let mut status = serde_json::to_value(objects).expect("object proof serialization");
    if let Some(values) = status.get_mut("value").and_then(Value::as_array_mut) {
        for value in values.iter_mut() {
            *value = match projection {
                ObjectProjection::Identity => value["identity"].clone(),
                // Bind a status to its identity; a multiset of statuses alone
                // would miss two objects exchanging VALID and INVALID.
                ObjectProjection::Status => serde_json::json!([value["identity"], value["status"]]),
                ObjectProjection::ProofInputs => value.clone(),
            };
        }
        values.sort_by_cached_key(|value| serde_json::to_vec(value).expect("object projection"));
    }
    status
}

pub(crate) fn field_fingerprint(
    binding: &ImpactBindingV1,
    field: DecisiveField,
) -> Option<[u8; 32]> {
    let facts = &binding.decisive;
    let value = match field {
        DecisiveField::Envelope => serde_json::to_value(&facts.envelope_digest),
        DecisiveField::ObjectIdentities => Ok(object_projection(
            &facts.objects,
            ObjectProjection::Identity,
        )),
        DecisiveField::ObjectStatus => {
            Ok(object_projection(&facts.objects, ObjectProjection::Status))
        }
        DecisiveField::Edition => serde_json::to_value(&facts.edition),
        DecisiveField::CurrentSchema => serde_json::to_value(&facts.current_schema),
        DecisiveField::ProfileGeneration => serde_json::to_value(&facts.profile_generation),
        DecisiveField::LaneGeneration => serde_json::to_value(&facts.lane_generation),
        DecisiveField::DbIdentity => serde_json::to_value(&facts.db_identity),
        DecisiveField::ScopeDigest => serde_json::to_value(&facts.scope_digest),
        DecisiveField::MutationEffectClosure
        | DecisiveField::DdlEffectClosure
        | DecisiveField::Dependents => {
            let commitment = facts.action_fields.get(&field)?;
            Ok(serde_json::json!([
                commitment,
                object_projection(&facts.objects, ObjectProjection::ProofInputs)
            ]))
        }
        DecisiveField::SourceEffects => {
            let commitment = facts.action_fields.get(&field)?;
            Ok(serde_json::json!([
                commitment,
                facts.compiler_facts,
                facts.compile_parse_closure_digest,
                facts.engine_version,
                facts.ruleset_digest
            ]))
        }
        DecisiveField::Rows
        | DecisiveField::PredictedInvalidSet
        | DecisiveField::Reversibility
        | DecisiveField::ProfileCeiling
        | DecisiveField::OAuthCeiling
        | DecisiveField::ClosureFactKey
        | DecisiveField::RoutineEffects
        | DecisiveField::MaskingProfileOutput
        | DecisiveField::EditionManifest
        | DecisiveField::ChangedEditionManifest
        | DecisiveField::DefaultEqualsBase
        | DecisiveField::EditionParentage
        | DecisiveField::EditionExposure
        | DecisiveField::ServiceEditions
        | DecisiveField::PolicyFloor => serde_json::to_value(facts.action_fields.get(&field)?),
    }
    .expect("closed decisive fact serialization");
    let mut hash = Sha256::new();
    hash.update(b"omcp/impact-field/v1\0");
    hash.update(serde_json::to_vec(&(field, value)).expect("field commitment"));
    Some(hash.finalize().into())
}

pub(crate) fn field_fingerprints(binding: &ImpactBindingV1) -> BTreeMap<DecisiveField, [u8; 32]> {
    use DecisiveField::*;
    [
        Envelope,
        ObjectIdentities,
        ObjectStatus,
        Edition,
        CurrentSchema,
        ProfileGeneration,
        LaneGeneration,
        DbIdentity,
        ScopeDigest,
    ]
    .into_iter()
    .chain(binding.decisive.action_fields.keys().copied())
    .filter_map(|field| field_fingerprint(binding, field).map(|digest| (field, digest)))
    .collect()
}

pub(crate) fn authority_fingerprint(binding: &ImpactBindingV1) -> [u8; 32] {
    let facts = &binding.decisive;
    let data = serde_json::to_vec(&(
        &facts.envelope_digest,
        &facts.statement_digest,
        &facts.bind_hmac,
        &facts.policy_schema_digest,
        &facts.policy_ruleset_digest,
        &facts.matched_policy_rule_ids,
        &facts.rewrite_algorithm_version,
        &facts.effective_plan_digest,
        &facts.scope_digest,
    ))
    .expect("approval authority inputs");
    let mut hash = Sha256::new();
    hash.update(b"omcp/impact-authority/v1\0");
    hash.update(data);
    hash.finalize().into()
}

/// Facts that must be rechecked against the same identity before execution.
/// The envelope digest already includes the keyed bind HMAC; `bind_hmac`
/// remains explicit so a preview can show its status without exposing values.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DecisiveFacts {
    pub envelope_digest: FieldStatus<[u8; 32]>,
    pub statement_digest: FieldStatus<[u8; 32]>,
    pub bind_hmac: FieldStatus<[u8; 32]>,
    pub objects: FieldStatus<Vec<ObjectFact>>,
    pub edition: FieldStatus<String>,
    pub compiler_facts: FieldStatus<String>,
    /// Offline static SQL and fresh parse-time callback proof for candidate DDL.
    pub compile_parse_closure_digest: FieldStatus<[u8; 32]>,
    pub engine_version: FieldStatus<String>,
    pub ruleset_digest: FieldStatus<[u8; 32]>,
    /// The W13 plan that later preview/count/classification/apply consumers must share.
    pub effective_plan_digest: FieldStatus<[u8; 32]>,
    pub policy_schema_digest: FieldStatus<[u8; 32]>,
    pub policy_ruleset_digest: FieldStatus<[u8; 32]>,
    /// Ordered: removal, addition and reordering all require a new preview.
    pub matched_policy_rule_ids: FieldStatus<Vec<String>>,
    pub rewrite_algorithm_version: FieldStatus<u16>,
    pub db_identity: FieldStatus<DbIdentity>,
    pub current_schema: FieldStatus<String>,
    pub profile_generation: FieldStatus<u64>,
    pub lane_generation: FieldStatus<u64>,
    /// Opaque until W13 supplies its own typed scope fingerprint.
    pub scope_digest: FieldStatus<Option<[u8; 32]>>,
    /// Commitments supplied by action-specific producers. An absent entry is
    /// unavailable, never an implicit empty proof or a configuration waiver.
    pub action_fields: BTreeMap<DecisiveField, FieldStatus<[u8; 32]>>,
}

impl Default for DecisiveFacts {
    fn default() -> Self {
        Self {
            envelope_digest: FieldStatus::not_collected(),
            statement_digest: FieldStatus::not_collected(),
            bind_hmac: FieldStatus::not_collected(),
            objects: FieldStatus::not_collected(),
            edition: FieldStatus::not_collected(),
            compiler_facts: FieldStatus::not_collected(),
            compile_parse_closure_digest: FieldStatus::not_collected(),
            engine_version: FieldStatus::not_collected(),
            ruleset_digest: FieldStatus::not_collected(),
            effective_plan_digest: FieldStatus::not_collected(),
            policy_schema_digest: FieldStatus::not_collected(),
            policy_ruleset_digest: FieldStatus::not_collected(),
            matched_policy_rule_ids: FieldStatus::not_collected(),
            rewrite_algorithm_version: FieldStatus::not_collected(),
            db_identity: FieldStatus::not_collected(),
            current_schema: FieldStatus::not_collected(),
            profile_generation: FieldStatus::not_collected(),
            lane_generation: FieldStatus::not_collected(),
            scope_digest: FieldStatus::not_collected(),
            action_fields: BTreeMap::new(),
        }
    }
}

/// An AS OF observation has one SCN; an ordinary query has a before/after
/// window. The two shapes cannot serialize as one another.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScnBounds {
    AsOf { observed_at_scn: u64 },
    Window { scn_before: u64, scn_after: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowEstimateKind {
    Estimated,
    Observed,
    SnapshotEstimate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RowEstimate {
    pub kind: RowEstimateKind,
    pub value: u64,
    pub scn: ScnBounds,
    pub profile_generation: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Observations {
    pub rows: Option<RowEstimate>,
    pub cost: Option<Value>,
    pub timings: BTreeMap<String, u64>,
    pub statuses: BTreeMap<String, FieldStatus<()>>,
    pub scn_bounds: Option<ScnBounds>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ImpactBindingV1 {
    pub version: u8,
    pub decisive: DecisiveFacts,
    pub observations: Observations,
}

impl Default for ImpactBindingV1 {
    fn default() -> Self {
        Self {
            version: IMPACT_BINDING_VERSION,
            decisive: DecisiveFacts::default(),
            observations: Observations::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("unsupported impact binding version {found}")]
pub struct ImpactVersionError {
    pub found: u8,
}

impl ImpactBindingV1 {
    /// SHA-256 of the length-prefixed, domain-separated decisive facts only.
    /// All statuses and reasons are encoded, including unavailable fields.
    pub fn decisive_digest(&self) -> Result<[u8; 32], ImpactVersionError> {
        if self.version != IMPACT_BINDING_VERSION {
            return Err(ImpactVersionError {
                found: self.version,
            });
        }
        let mut out = Vec::new();
        put_bytes(&mut out, IMPACT_DOMAIN);
        out.push(self.version);
        self.decisive.encode(&mut out);
        Ok(Sha256::digest(out).into())
    }
}

/// User-visible impact. Every field is serialized even when no computation
/// is wired yet. T14.2-T14.5 replace the corresponding statuses.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ImpactV1 {
    pub binding: ImpactBindingV1,
    pub rows: FieldStatus<RowEstimate>,
    pub dependents: FieldStatus<Value>,
    pub effects: FieldStatus<Value>,
    pub sast: FieldStatus<Value>,
    pub cost: FieldStatus<Value>,
    pub locks: FieldStatus<Value>,
    pub reversibility: FieldStatus<Value>,
}

impl Default for ImpactV1 {
    fn default() -> Self {
        Self {
            binding: ImpactBindingV1::default(),
            rows: FieldStatus::not_collected(),
            dependents: FieldStatus::not_collected(),
            effects: FieldStatus::not_collected(),
            sast: FieldStatus::not_collected(),
            cost: FieldStatus::not_collected(),
            locks: FieldStatus::not_collected(),
            reversibility: FieldStatus::not_collected(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldCaps {
    pub max_depth: usize,
    pub max_count: usize,
}

pub struct FieldMeasure<T> {
    pub value: T,
    pub depth: usize,
    pub count: usize,
}

pub struct FieldBudget;

impl FieldBudget {
    /// Bound one asynchronous field computation. Its worker must also check
    /// caps while traversing; this final check prevents a computed status if
    /// it exceeded them. Expiry drops the future and returns a typed refusal.
    pub async fn run<T, F>(deadline: Instant, caps: FieldCaps, future: F) -> FieldStatus<T>
    where
        F: Future<Output = FieldMeasure<T>>,
    {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return FieldStatus::Unavailable {
                reason: UnavailableReason::Timeout,
            };
        }
        match asupersync::time::timeout(asupersync::time::wall_now(), remaining, future).await {
            Ok(measure) if measure.depth > caps.max_depth || measure.count > caps.max_count => {
                FieldStatus::Unavailable {
                    reason: UnavailableReason::Truncated,
                }
            }
            Ok(measure) => FieldStatus::Computed {
                value: measure.value,
            },
            Err(_) => FieldStatus::Unavailable {
                reason: UnavailableReason::Timeout,
            },
        }
    }
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn put_text(out: &mut Vec<u8>, value: &str) {
    put_bytes(out, value.as_bytes());
}

fn put_status<T>(out: &mut Vec<u8>, status: &FieldStatus<T>, encode: impl Fn(&mut Vec<u8>, &T)) {
    match status {
        FieldStatus::Computed { value } => {
            out.push(1);
            encode(out, value);
        }
        FieldStatus::Estimated { value } => {
            out.push(2);
            encode(out, value);
        }
        FieldStatus::Unavailable { reason } => out.extend_from_slice(&[3, reason.tag()]),
        FieldStatus::NotApplicable { reason } => out.extend_from_slice(&[4, reason.tag()]),
    }
}

impl DecisiveFacts {
    /// Bind one immutable plan for the later grant runtime to count and
    /// execute. Revalidation must compare all decisive facts.
    pub fn bind_effective_plan(&mut self, plan: &EffectiveDmlPlanV1) {
        self.effective_plan_digest = FieldStatus::Computed {
            value: plan.digest(),
        };
        self.policy_schema_digest = FieldStatus::Computed {
            value: plan.policy_schema_digest(),
        };
        self.policy_ruleset_digest = FieldStatus::Computed {
            value: plan.policy_ruleset_digest(),
        };
        self.matched_policy_rule_ids = FieldStatus::Computed {
            value: plan.matched_rule_ids().to_vec(),
        };
        self.rewrite_algorithm_version = FieldStatus::Computed {
            value: DML_REWRITE_ALGORITHM_VERSION,
        };
    }

    /// All W13-specific commitments must still match at apply. Unknown or
    /// estimated statuses never admit an apply.
    #[must_use]
    pub fn matches_effective_plan(&self, plan: &EffectiveDmlPlanV1) -> bool {
        matches!(&self.effective_plan_digest, FieldStatus::Computed { value } if value == &plan.digest())
            && matches!(&self.policy_schema_digest, FieldStatus::Computed { value } if value == &plan.policy_schema_digest())
            && matches!(&self.policy_ruleset_digest, FieldStatus::Computed { value } if value == &plan.policy_ruleset_digest())
            && matches!(&self.matched_policy_rule_ids, FieldStatus::Computed { value } if value == plan.matched_rule_ids())
            && matches!(&self.rewrite_algorithm_version, FieldStatus::Computed { value } if *value == DML_REWRITE_ALGORITHM_VERSION)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        put_status(out, &self.envelope_digest, |out, v| put_bytes(out, v));
        put_status(out, &self.statement_digest, |out, v| put_bytes(out, v));
        put_status(out, &self.bind_hmac, |out, v| put_bytes(out, v));
        put_status(out, &self.objects, |out, objects| {
            out.extend_from_slice(&(objects.len() as u64).to_be_bytes());
            let mut encoded_objects = Vec::with_capacity(objects.len());
            for object in objects {
                let mut encoded = Vec::new();
                put_status(&mut encoded, &object.identity, |out, v| put_text(out, v));
                put_status(&mut encoded, &object.status, |out, v| put_text(out, v));
                put_status(&mut encoded, &object.source_hash, |out, v| {
                    put_bytes(out, v)
                });
                put_status(&mut encoded, &object.dependency_hash, |out, v| {
                    put_bytes(out, v)
                });
                put_status(&mut encoded, &object.trigger_hash, |out, v| {
                    put_bytes(out, v)
                });
                encoded_objects.push(encoded);
            }
            encoded_objects.sort_unstable();
            for encoded in encoded_objects {
                put_bytes(out, &encoded);
            }
        });
        put_status(out, &self.edition, |out, v| put_text(out, v));
        put_status(out, &self.compiler_facts, |out, v| put_text(out, v));
        put_status(out, &self.compile_parse_closure_digest, |out, v| {
            put_bytes(out, v)
        });
        put_status(out, &self.engine_version, |out, v| put_text(out, v));
        put_status(out, &self.ruleset_digest, |out, v| put_bytes(out, v));
        put_status(out, &self.effective_plan_digest, |out, v| put_bytes(out, v));
        put_status(out, &self.policy_schema_digest, |out, v| put_bytes(out, v));
        put_status(out, &self.policy_ruleset_digest, |out, v| put_bytes(out, v));
        put_status(out, &self.matched_policy_rule_ids, |out, ids| {
            out.extend_from_slice(&(ids.len() as u64).to_be_bytes());
            for id in ids {
                put_text(out, id);
            }
        });
        put_status(out, &self.rewrite_algorithm_version, |out, v| {
            out.extend_from_slice(&v.to_be_bytes());
        });
        put_status(out, &self.db_identity, |out, v| {
            out.extend_from_slice(&v.dbid.to_be_bytes());
            out.extend_from_slice(&v.con_uid.to_be_bytes());
        });
        put_status(out, &self.current_schema, |out, v| put_text(out, v));
        put_status(out, &self.profile_generation, |out, v| {
            out.extend_from_slice(&v.to_be_bytes());
        });
        put_status(out, &self.lane_generation, |out, v| {
            out.extend_from_slice(&v.to_be_bytes());
        });
        put_status(out, &self.scope_digest, |out, v| match v {
            Some(digest) => {
                out.push(1);
                put_bytes(out, digest);
            }
            None => out.push(0),
        });
        out.extend_from_slice(&(self.action_fields.len() as u64).to_be_bytes());
        for (field, status) in &self.action_fields {
            put_bytes(
                out,
                &serde_json::to_vec(field).expect("closed field identifier"),
            );
            put_status(out, status, |out, digest| put_bytes(out, digest));
        }
    }
}
