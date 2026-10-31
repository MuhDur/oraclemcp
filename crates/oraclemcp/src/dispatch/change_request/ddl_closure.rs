//! W12 consumes the shared DDL-trigger collector. This proof authorizes no SQL;
//! the change-request owner retains classifier, level, token and audit checks.

use asupersync::Cx;
use oraclemcp_db::OracleConnection;
use oraclemcp_error::{
    ErrorClass, ErrorEnvelope, ReasonCategory, StatementOutcome, StructuredReason,
};
use oraclemcp_guard::{
    ImpactBindingV1, OperatorStatementClass,
    ddl_closure::{DdlClosureRefusal, DdlEffectClosureV1, DdlEvent, DdlObject},
    impact_binding::{DecisiveField, FieldStatus},
};
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum W12DdlEvent {
    CreateEdition,
    CreateOrReplace { kind: String },
    AlterCompile { kind: String },
    DropEdition,
}

impl W12DdlEvent {
    fn oracle_event(&self) -> DdlEvent {
        match self {
            Self::CreateEdition | Self::CreateOrReplace { .. } => DdlEvent::Create,
            Self::AlterCompile { .. } => DdlEvent::Alter,
            Self::DropEdition => DdlEvent::Drop,
        }
    }

    fn object_type(&self) -> Result<&str, W12DdlTriggerRefusal> {
        match self {
            Self::CreateEdition | Self::DropEdition => Ok("EDITION"),
            Self::CreateOrReplace { kind } | Self::AlterCompile { kind }
                if matches!(
                    kind.as_str(),
                    "PROCEDURE"
                        | "FUNCTION"
                        | "PACKAGE"
                        | "PACKAGE BODY"
                        | "TYPE"
                        | "TYPE BODY"
                        | "TRIGGER"
                        | "VIEW"
                        | "SYNONYM"
                ) =>
            {
                Ok(kind)
            }
            _ => Err(W12DdlTriggerRefusal::Unknown),
        }
    }
}

/// Server-owned dictionary spellings, captured on the actual W12 lane.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct W12DdlTriggerRequest {
    event: W12DdlEvent,
    object: DdlObject,
    container: String,
}

impl W12DdlTriggerRequest {
    pub fn new(
        event: W12DdlEvent,
        owner: &str,
        name: &str,
        container: &str,
    ) -> Result<Self, W12DdlTriggerRefusal> {
        let kind = event.object_type()?.to_owned();
        // Editions are non-schema objects represented under SYS in DBA_OBJECTS.
        let owner = if kind == "EDITION" { "SYS" } else { owner };
        if [owner, name, container]
            .iter()
            .any(|value| value.is_empty() || value.len() > 128 || value.contains('\0'))
        {
            return Err(W12DdlTriggerRefusal::Unknown);
        }
        Ok(Self {
            event,
            object: DdlObject {
                owner: owner.into(),
                name: name.into(),
                object_type: kind,
            },
            container: container.into(),
        })
    }

    pub fn event(&self) -> &W12DdlEvent {
        &self.event
    }
    pub fn object(&self) -> &DdlObject {
        &self.object
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum W12DdlTriggerRefusal {
    #[serde(rename = "DDL_TRIGGER_EFFECTFUL")]
    Effectful,
    #[serde(rename = "DDL_TRIGGER_UNKNOWN")]
    Unknown,
    RepreviewRequired,
}

impl W12DdlTriggerRefusal {
    pub fn into_envelope(self) -> ErrorEnvelope {
        let (class, reason) = match self {
            Self::Effectful => (
                ErrorClass::ForbiddenStatement,
                ReasonCategory::DdlTriggerEffectful,
            ),
            Self::Unknown => (
                ErrorClass::ForbiddenStatement,
                ReasonCategory::DdlTriggerUnknown,
            ),
            Self::RepreviewRequired => (ErrorClass::RepreviewRequired, ReasonCategory::Other),
        };
        ErrorEnvelope::new(
            class,
            format!(
                "{}: W12 DDL-trigger proof refused before execution",
                self.code()
            ),
        )
        .with_structured_reason(StructuredReason::new(reason))
        .with_statement_outcome(StatementOutcome::NotStarted)
        .with_suggested_tool("oracle_change_request")
        .with_next_step(if self == Self::RepreviewRequired {
            "obtain a new change-request preview; the bound DDL-trigger facts changed"
        } else {
            reason.next_action()
        })
    }

    pub const fn code(self) -> &'static str {
        match self {
            Self::Effectful => "DDL_TRIGGER_EFFECTFUL",
            Self::Unknown => "DDL_TRIGGER_UNKNOWN",
            Self::RepreviewRequired => "REPREVIEW_REQUIRED",
        }
    }
}

/// Constructible only after complete collection and shared W7 admission.
/// The full closure remains available for preview, audit and persistence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct W12DdlTriggerProof {
    request: W12DdlTriggerRequest,
    closure: DdlEffectClosureV1,
}

impl W12DdlTriggerProof {
    fn from_collected(
        request: W12DdlTriggerRequest,
        closure: DdlEffectClosureV1,
    ) -> Result<Self, W12DdlTriggerRefusal> {
        if closure.event != request.event.oracle_event()
            || closure.object != request.object
            || closure
                .database
                .as_ref()
                .is_none_or(|db| db.container != request.container)
        {
            return Err(W12DdlTriggerRefusal::Unknown);
        }
        closure.admit().map_err(|refusal| match refusal {
            DdlClosureRefusal::Unknown => W12DdlTriggerRefusal::Unknown,
            DdlClosureRefusal::Effect(_) => W12DdlTriggerRefusal::Effectful,
        })?;
        Ok(Self { request, closure })
    }

    pub fn closure(&self) -> &DdlEffectClosureV1 {
        &self.closure
    }
    pub fn request(&self) -> &W12DdlTriggerRequest {
        &self.request
    }

    /// The shared producer's complete closure commitment. The action envelope
    /// separately binds the W12 operation and exact statement.
    pub fn digest(&self) -> [u8; 32] {
        proof_digest(&self.closure)
    }

    /// Preview producer: the complete proof enters signed decisive material.
    pub fn bind_into(&self, binding: &mut ImpactBindingV1) {
        binding.decisive.action_fields.insert(
            DecisiveField::DdlEffectClosure,
            FieldStatus::Computed {
                value: self.digest(),
            },
        );
    }
}

fn proof_digest(closure: &DdlEffectClosureV1) -> [u8; 32] {
    let encoded = closure.fingerprint();
    std::array::from_fn(|index| {
        u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16)
            .expect("shared closure fingerprint is SHA-256 hex")
    })
}

/// The caller records both digests; even an equal proof cannot eliminate the
/// residual race with concurrent DDL after this recheck and before execution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct W12DdlTriggerRecheck {
    pub bound_digest: [u8; 32],
    pub observed_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct W12DdlTriggerRecheckFailure {
    pub refusal: W12DdlTriggerRefusal,
    pub bound_digest: [u8; 32],
    /// None means the supplied binding was already invalid before collection.
    pub observed_digest: Option<[u8; 32]>,
}

impl W12DdlTriggerRecheckFailure {
    pub fn into_envelope(self) -> ErrorEnvelope {
        self.refusal.into_envelope()
    }
}

fn binding_matches(binding: &ImpactBindingV1, proof: &W12DdlTriggerProof) -> bool {
    matches!(binding.decisive.action_fields.get(&DecisiveField::DdlEffectClosure),
        Some(FieldStatus::Computed { value }) if *value == proof.digest())
}

fn compare_recollected(
    binding: &ImpactBindingV1,
    preview: &W12DdlTriggerProof,
    current: DdlEffectClosureV1,
) -> Result<W12DdlTriggerRecheck, W12DdlTriggerRecheckFailure> {
    let bound_digest = preview.digest();
    let observed_digest = proof_digest(&current);
    if !binding_matches(binding, preview)
        || W12DdlTriggerProof::from_collected(preview.request.clone(), current).is_err()
        || observed_digest != bound_digest
    {
        return Err(W12DdlTriggerRecheckFailure {
            refusal: W12DdlTriggerRefusal::RepreviewRequired,
            bound_digest,
            observed_digest: Some(observed_digest),
        });
    }
    Ok(W12DdlTriggerRecheck {
        bound_digest,
        observed_digest,
    })
}

/// Call on the same W12 lane after consuming the confirmation token and
/// immediately before its separately guarded DDL. This executes catalog reads
/// only; it never authorizes SQL or substitutes for the caller's other checks.
pub async fn recheck_before_execute(
    cx: &Cx,
    conn: &dyn OracleConnection,
    binding: &ImpactBindingV1,
    preview: &W12DdlTriggerProof,
) -> Result<W12DdlTriggerRecheck, W12DdlTriggerRecheckFailure> {
    if !binding_matches(binding, preview) {
        return Err(W12DdlTriggerRecheckFailure {
            refusal: W12DdlTriggerRefusal::RepreviewRequired,
            bound_digest: preview.digest(),
            observed_digest: None,
        });
    }
    let request = &preview.request;
    let current = crate::ddl_closure::collect_ddl_effect_closure(
        cx,
        conn,
        request.event.oracle_event(),
        request.object.clone(),
        &request.container,
    )
    .await;
    compare_recollected(binding, preview, current)
}

pub async fn collect_ddl_trigger_proof(
    cx: &Cx,
    conn: &dyn OracleConnection,
    request: &W12DdlTriggerRequest,
) -> Result<W12DdlTriggerProof, W12DdlTriggerRefusal> {
    let closure = crate::ddl_closure::collect_ddl_effect_closure(
        cx,
        conn,
        request.event.oracle_event(),
        request.object.clone(),
        &request.container,
    )
    .await;
    W12DdlTriggerProof::from_collected(request.clone(), closure)
}

/// Only this exact operator rendering is exempt. This says nothing about SQL
/// authorization: the dedicated operator route and all its checks stay required.
/// Oracle's documented ALTER DATABASE exception:
/// https://docs.oracle.com/en/database/oracle/oracle-database/21/lnpls/CREATE-TRIGGER-statement.html
pub fn default_edition_flip_excluded(sql: &str) -> bool {
    OperatorStatementClass::from_exact_rendered_sql(sql)
        == Some(OperatorStatementClass::DefaultEditionFlip)
}

#[cfg(test)]
mod tests;
