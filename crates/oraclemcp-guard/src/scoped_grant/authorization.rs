//! Pure selection between session-level and scoped-grant write authority.
//!
//! A caller validates the signed reference and looks up its bound grant before
//! entering this seam. Selection never falls back to the session level after a
//! scoped reference was supplied.

use crate::levels::{LevelDecision, OperatingLevel, SessionLevelState};

use super::{ScopedGrant, hex};

/// Scope identity carried to the later statement-shape enforcement step.
/// The store's opaque entry id is checked before this value is constructed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedGrantId(String);

impl ScopedGrantId {
    /// The keyed scope digest of the validated grant.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The selected authority for one statement. Selection does not execute it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteAuthorization {
    /// Existing session-level gate and confirmation path.
    SessionLevel,
    /// An explicitly presented, validated scoped grant.
    ScopedGrant(ScopedGrantId),
}

/// A typed, terminal failure to select write authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteAuthRefusal {
    /// The ordinary session gate refused the statement.
    SessionGate(LevelDecision),
    /// A scoped grant cannot be used on a protected profile or under a
    /// READ_ONLY effective ceiling.
    GrantAboveCeiling,
    /// The policy's level floor must be held by the session itself.
    GrantPolicyFloorUnmet,
    /// Only exact READ_WRITE classifier requirements are grantable.
    GrantLevelNotGrantable,
    /// The validated grant's required level differs from READ_WRITE.
    GrantMismatch,
    /// The presented grant was never issued.
    GrantUnknown,
    /// The grant's TTL elapsed.
    GrantExpired,
    /// The grant was explicitly or generation-revoked.
    GrantRevoked,
    /// The grant was suspended after target or closure drift.
    GrantSuspendedDrift,
    /// A signed reference or lane binding did not match.
    GrantTokenKindMismatch,
    /// Scope enforcement is not installed yet; never execute on this seam.
    GrantEnforcementUnavailable,
}

impl WriteAuthRefusal {
    /// Stable machine-readable refusal code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::SessionGate(_) => "OPERATING_LEVEL_TOO_LOW",
            Self::GrantAboveCeiling => "GRANT_ABOVE_CEILING",
            Self::GrantPolicyFloorUnmet => "GRANT_POLICY_FLOOR_UNMET",
            Self::GrantLevelNotGrantable => "GRANT_LEVEL_NOT_GRANTABLE",
            Self::GrantMismatch => "GRANT_MISMATCH",
            Self::GrantUnknown => "GRANT_UNKNOWN",
            Self::GrantExpired => "GRANT_EXPIRED",
            Self::GrantRevoked => "GRANT_REVOKED",
            Self::GrantSuspendedDrift => "GRANT_SUSPENDED_DRIFT",
            Self::GrantTokenKindMismatch => "GRANT_TOKEN_KIND_MISMATCH",
            Self::GrantEnforcementUnavailable => "GRANT_ENFORCEMENT_UNAVAILABLE",
        }
    }
}

/// Select authority after classification, policy denial and grant lookup.
/// `policy_level_floor` is intentionally independent of `classifier_level`:
/// a scoped grant can satisfy only the latter's exact READ_WRITE requirement.
pub fn authorize_level(
    classifier_level: OperatingLevel,
    policy_level_floor: OperatingLevel,
    session: &SessionLevelState,
    ceiling: OperatingLevel,
    grant: Option<&ScopedGrant>,
) -> Result<WriteAuthorization, WriteAuthRefusal> {
    let Some(grant) = grant else {
        return match session.evaluate(Some(classifier_level.max(policy_level_floor))) {
            LevelDecision::Allow => Ok(WriteAuthorization::SessionLevel),
            refused => Err(WriteAuthRefusal::SessionGate(refused)),
        };
    };

    if session.is_protected()
        || ceiling.min(session.effective_ceiling()) < OperatingLevel::ReadWrite
    {
        return Err(WriteAuthRefusal::GrantAboveCeiling);
    }
    if session.effective_level() < policy_level_floor {
        return Err(WriteAuthRefusal::GrantPolicyFloorUnmet);
    }
    if classifier_level != OperatingLevel::ReadWrite {
        return Err(WriteAuthRefusal::GrantLevelNotGrantable);
    }
    if grant.required_level() != OperatingLevel::ReadWrite {
        return Err(WriteAuthRefusal::GrantMismatch);
    }
    Ok(WriteAuthorization::ScopedGrant(ScopedGrantId(hex(
        &grant.scope_digest()
    ))))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::time::Duration;

    use crate::exec_grant::ExecGrantBinding;
    use crate::resolver::CatalogGeneration;

    use super::*;
    use crate::scoped_grant::{
        ClosureFingerprints, ColumnIdent, EffectiveCeiling, GrantComparison, GrantContainer,
        GrantLimits, GrantOp, GrantOperand, GrantPredicateV1, GrantTargetIdentity, GrantValue,
        LastDdlTime, ScopedGrantRequest,
    };

    fn grant() -> ScopedGrant {
        let request = ScopedGrantRequest {
            profile: "dev".into(),
            binding: ExecGrantBinding::new("session", "lane", "subject", 1),
            verbs: vec!["UPDATE".into()],
            target: GrantTargetIdentity {
                owner: "OMCP_FX_T152".into(),
                object_name: "ORDERS".into(),
                object_id: 1,
                data_object_id: Some(1),
                container: GrantContainer {
                    con_id: 3,
                    con_uid: 7,
                },
                edition: None,
                catalog_generation: CatalogGeneration(1),
                resolved_via: None,
            },
            columns: BTreeSet::from([ColumnIdent::new("STATUS").unwrap()]),
            row_predicate: GrantPredicateV1::new(vec![GrantComparison {
                column: ColumnIdent::new("ID").unwrap(),
                op: GrantOp::Eq,
                operand: GrantOperand::Single(GrantValue::number("101").unwrap()),
            }]),
            limits: GrantLimits {
                max_rows_per_statement: 1,
                max_statements: 1,
                max_total_rows: 1,
            },
            ttl: Duration::from_secs(60),
            commit_allowed: false,
            closure: ClosureFingerprints::new(),
            last_ddl_time: LastDdlTime::new("2026-09-01T10:00:00").unwrap(),
        };
        ScopedGrant::new(
            request,
            EffectiveCeiling {
                profile_max_level: OperatingLevel::Admin,
                oauth_ceiling: None,
            },
            false,
            &[7; 32],
        )
        .unwrap()
    }

    #[test]
    fn authorize_level_table() {
        let levels = [
            OperatingLevel::ReadOnly,
            OperatingLevel::ReadWrite,
            OperatingLevel::Ddl,
            OperatingLevel::Admin,
        ];
        let grant = grant();
        for current in levels {
            let mut session = SessionLevelState::new(OperatingLevel::Admin, false);
            session.set_current_level(current).unwrap();
            for classifier in levels {
                for floor in levels {
                    let without =
                        authorize_level(classifier, floor, &session, OperatingLevel::Admin, None);
                    assert_eq!(
                        without.is_ok(),
                        current >= classifier && current >= floor,
                        "session current={current} classifier={classifier} floor={floor}"
                    );
                    let with = authorize_level(
                        classifier,
                        floor,
                        &session,
                        OperatingLevel::Admin,
                        Some(&grant),
                    );
                    assert_eq!(
                        with.is_ok(),
                        current >= floor && classifier == OperatingLevel::ReadWrite,
                        "grant current={current} classifier={classifier} floor={floor}"
                    );
                    if with.is_ok() {
                        assert!(matches!(with, Ok(WriteAuthorization::ScopedGrant(_))));
                    }
                }
            }
        }
        let protected = SessionLevelState::new(OperatingLevel::ReadOnly, true);
        assert_eq!(
            authorize_level(
                OperatingLevel::ReadWrite,
                OperatingLevel::ReadOnly,
                &protected,
                OperatingLevel::ReadOnly,
                Some(&grant)
            ),
            Err(WriteAuthRefusal::GrantAboveCeiling)
        );
    }
}
