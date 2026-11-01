use oraclemcp_guard::impact_binding::{
    DecisiveFieldMatrixV1, DecisiveMatrixContext, DecisiveRefusal, DecisiveRefusalReason,
    check_decisive,
};
use oraclemcp_guard::{ActionKind, OperatingLevel};
use std::time::{Duration, Instant};

use oraclemcp_guard::impact_binding::{
    DbIdentity, DecisiveFacts, DecisiveField, FieldBudget, FieldCaps, FieldMeasure, FieldStatus,
    ImpactBindingV1, ImpactV1, NotApplicableReason, ObjectFact, RowEstimate, RowEstimateKind,
    ScnBounds, UnavailableReason,
};
use proptest::prelude::*;
use serde_json::{Value, json};

fn computed<T>(value: T) -> FieldStatus<T> {
    FieldStatus::Computed { value }
}

fn sample() -> ImpactBindingV1 {
    ImpactBindingV1 {
        decisive: DecisiveFacts {
            envelope_digest: computed([0; 32]),
            statement_digest: computed([0; 32]),
            bind_hmac: computed([0; 32]),
            objects: computed(vec![ObjectFact {
                identity: computed("SCHEMA.T".into()),
                status: computed("VALID".into()),
                source_hash: computed([0; 32]),
                dependency_hash: computed([0; 32]),
                trigger_hash: computed([0; 32]),
            }]),
            edition: computed("EDITION_A".into()),
            compiler_facts: computed("PLSQL_OPTIMIZE_LEVEL=2".into()),
            compile_parse_closure_digest: computed([0; 32]),
            engine_version: computed("0.8.0".into()),
            ruleset_digest: computed([0; 32]),
            effective_plan_digest: computed([0; 32]),
            policy_schema_digest: computed([0; 32]),
            policy_ruleset_digest: computed([0; 32]),
            matched_policy_rule_ids: computed(vec!["P1".into(), "P2".into()]),
            rewrite_algorithm_version: computed(1),
            db_identity: computed(DbIdentity {
                dbid: 1,
                con_uid: 2,
            }),
            current_schema: computed("SCHEMA".into()),
            profile_generation: computed(1),
            lane_generation: computed(1),
            scope_digest: computed(None),
            action_fields: Default::default(),
        },
        ..ImpactBindingV1::default()
    }
}

#[test]
fn decisive_action_commitments_are_signed_facts() {
    let original = sample();
    let mut changed = original.clone();
    changed
        .decisive
        .action_fields
        .insert(DecisiveField::DdlEffectClosure, computed([2; 32]));
    assert_ne!(original.decisive_digest(), changed.decisive_digest());
    let committed = changed.decisive_digest();
    changed
        .decisive
        .action_fields
        .insert(DecisiveField::DdlEffectClosure, computed([3; 32]));
    assert_ne!(committed, changed.decisive_digest());
    changed.decisive.action_fields.insert(
        DecisiveField::DdlEffectClosure,
        FieldStatus::Estimated { value: [2; 32] },
    );
    assert_ne!(committed, changed.decisive_digest());
}

#[test]
fn decisive_action_commitment_field_identifier_enters_the_digest() {
    let mut ddl = sample();
    ddl.decisive
        .action_fields
        .insert(DecisiveField::DdlEffectClosure, computed([7; 32]));
    let mut routine = sample();
    routine
        .decisive
        .action_fields
        .insert(DecisiveField::RoutineEffects, computed([7; 32]));
    assert_ne!(ddl.decisive_digest(), routine.decisive_digest());
}

#[test]
fn decisive_action_commitments_preserve_unavailable_and_truncated_statuses() {
    for reason in [
        UnavailableReason::NoPrivilege,
        UnavailableReason::Truncated,
        UnavailableReason::Timeout,
    ] {
        let mut binding = sample();
        let original = binding.decisive_digest();
        binding.decisive.action_fields.insert(
            DecisiveField::DdlEffectClosure,
            FieldStatus::Unavailable { reason },
        );
        let encoded = serde_json::to_value(&binding).unwrap();
        assert_eq!(
            encoded["decisive"]["action_fields"]["ddl_effect_closure"]["status"],
            "unavailable"
        );
        assert_eq!(
            encoded["decisive"]["action_fields"]["ddl_effect_closure"]["reason"],
            serde_json::to_value(reason).unwrap()
        );
        let decoded: ImpactBindingV1 = serde_json::from_value(encoded).unwrap();
        assert_eq!(
            decoded
                .decisive
                .action_fields
                .get(&DecisiveField::DdlEffectClosure),
            Some(&FieldStatus::Unavailable { reason })
        );
        assert_ne!(original, decoded.decisive_digest());
    }
}

#[test]
fn decisive_action_map_cannot_override_typed_base_facts() {
    let mut binding = sample();
    binding
        .decisive
        .action_fields
        .insert(DecisiveField::Envelope, computed([9; 32]));
    binding
        .decisive
        .action_fields
        .insert(DecisiveField::ObjectIdentities, computed([9; 32]));
    let original = binding.decisive_digest();
    binding.decisive.envelope_digest = FieldStatus::Unavailable {
        reason: UnavailableReason::Timeout,
    };
    let FieldStatus::Computed { value: objects } = &mut binding.decisive.objects else {
        unreachable!()
    };
    objects[0].identity = FieldStatus::Unavailable {
        reason: UnavailableReason::NoPrivilege,
    };
    let decoded: ImpactBindingV1 =
        serde_json::from_value(serde_json::to_value(&binding).unwrap()).unwrap();
    assert_eq!(
        decoded.decisive.envelope_digest,
        FieldStatus::Unavailable {
            reason: UnavailableReason::Timeout
        }
    );
    let FieldStatus::Computed { value: objects } = &decoded.decisive.objects else {
        panic!("typed object facts disappeared")
    };
    assert_eq!(
        objects[0].identity,
        FieldStatus::Unavailable {
            reason: UnavailableReason::NoPrivilege
        }
    );
    assert_ne!(original, decoded.decisive_digest());
}

#[test]
fn decisive_action_map_encoding_is_independent_of_insertion_order() {
    let mut first = sample();
    first
        .decisive
        .action_fields
        .insert(DecisiveField::DdlEffectClosure, computed([3; 32]));
    first
        .decisive
        .action_fields
        .insert(DecisiveField::MutationEffectClosure, computed([4; 32]));
    let mut second = sample();
    second
        .decisive
        .action_fields
        .insert(DecisiveField::MutationEffectClosure, computed([4; 32]));
    second
        .decisive
        .action_fields
        .insert(DecisiveField::DdlEffectClosure, computed([3; 32]));
    assert_eq!(first.decisive_digest(), second.decisive_digest());
}

fn matrix_actions() -> Vec<ActionKind> {
    vec![
        ActionKind::ExecuteDml,
        ActionKind::ExecuteDdlAdmin,
        ActionKind::PreviewDmlSandbox,
        ActionKind::CompileObject,
        ActionKind::CreateOrReplace,
        ActionKind::PatchSource,
        ActionKind::SetSessionLevel {
            level: OperatingLevel::Admin,
            ttl: 60,
        },
        ActionKind::CustomToolCall,
        ActionKind::ChangeRequestPromote,
        ActionKind::GrantCreate,
        ActionKind::GrantUse,
    ]
}

fn complete_matrix_binding() -> ImpactBindingV1 {
    use DecisiveField::*;
    let mut binding = sample();
    binding.decisive.scope_digest = computed(Some([1; 32]));
    for field in [
        MutationEffectClosure,
        Rows,
        Dependents,
        PredictedInvalidSet,
        DdlEffectClosure,
        SourceEffects,
        Reversibility,
        ProfileCeiling,
        OAuthCeiling,
        ClosureFactKey,
        RoutineEffects,
        MaskingProfileOutput,
        EditionManifest,
        ChangedEditionManifest,
        DefaultEqualsBase,
        EditionParentage,
        EditionExposure,
        ServiceEditions,
        PolicyFloor,
    ] {
        binding
            .decisive
            .action_fields
            .insert(field, computed([1; 32]));
    }
    binding
}

#[derive(Clone, Copy)]
enum Noncomputed {
    Timeout,
    Truncated,
    Estimated,
    NotApplicable,
}

impl Noncomputed {
    fn reason(self) -> DecisiveRefusalReason {
        match self {
            Self::Timeout => DecisiveRefusalReason::Unavailable {
                reason: UnavailableReason::Timeout,
            },
            Self::Truncated => DecisiveRefusalReason::Unavailable {
                reason: UnavailableReason::Truncated,
            },
            Self::Estimated => DecisiveRefusalReason::Estimated,
            Self::NotApplicable => DecisiveRefusalReason::NotApplicable {
                reason: NotApplicableReason::NoEffect,
            },
        }
    }

    fn replace<T: Clone>(self, status: &mut FieldStatus<T>) {
        *status = match self {
            Self::Timeout => FieldStatus::Unavailable {
                reason: UnavailableReason::Timeout,
            },
            Self::Truncated => FieldStatus::Unavailable {
                reason: UnavailableReason::Truncated,
            },
            Self::Estimated => {
                let FieldStatus::Computed { value } = status else {
                    panic!("fixture must start computed")
                };
                FieldStatus::Estimated {
                    value: value.clone(),
                }
            }
            Self::NotApplicable => FieldStatus::NotApplicable {
                reason: NotApplicableReason::NoEffect,
            },
        };
    }
}

fn degrade_field(binding: &mut ImpactBindingV1, field: DecisiveField, status: Noncomputed) {
    let facts = &mut binding.decisive;
    match field {
        DecisiveField::Envelope => status.replace(&mut facts.envelope_digest),
        DecisiveField::ObjectIdentities => status.replace(&mut facts.objects),
        DecisiveField::ObjectStatus => {
            let FieldStatus::Computed { value: objects } = &mut facts.objects else {
                panic!("complete object fixture");
            };
            for object in objects {
                status.replace(&mut object.status);
            }
        }
        DecisiveField::Edition => status.replace(&mut facts.edition),
        DecisiveField::CurrentSchema => status.replace(&mut facts.current_schema),
        DecisiveField::ProfileGeneration => status.replace(&mut facts.profile_generation),
        DecisiveField::LaneGeneration => status.replace(&mut facts.lane_generation),
        DecisiveField::DbIdentity => status.replace(&mut facts.db_identity),
        DecisiveField::ScopeDigest => status.replace(&mut facts.scope_digest),
        _ => status.replace(
            facts
                .action_fields
                .get_mut(&field)
                .expect("complete field fixture"),
        ),
    }
}

#[test]
fn decisive_matrix_every_action_kind_has_row() {
    use DecisiveField::*;
    let context = DecisiveMatrixContext {
        dml_rows_supported: true,
        has_ddl_event: true,
        require_impact: true,
        ..Default::default()
    };
    for action in matrix_actions() {
        let required = DecisiveFieldMatrixV1::required(&action, context);
        assert_eq!(
            required.len(),
            required
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        );
        for common in [Envelope, ProfileGeneration, LaneGeneration] {
            assert!(required.contains(&common), "{action:?}: missing {common:?}");
        }
        let contract: &[DecisiveField] = match action {
            ActionKind::ExecuteDml | ActionKind::PreviewDmlSandbox => &[
                ObjectIdentities,
                ObjectStatus,
                MutationEffectClosure,
                Rows,
                Edition,
                CurrentSchema,
            ],
            ActionKind::ExecuteDdlAdmin
            | ActionKind::CompileObject
            | ActionKind::CreateOrReplace
            | ActionKind::PatchSource => &[
                ObjectIdentities,
                ObjectStatus,
                Dependents,
                PredictedInvalidSet,
                DdlEffectClosure,
                SourceEffects,
                Reversibility,
            ],
            ActionKind::SetSessionLevel { .. } => &[ProfileCeiling, OAuthCeiling],
            ActionKind::CustomToolCall => &[
                ClosureFactKey,
                RoutineEffects,
                DdlEffectClosure,
                MaskingProfileOutput,
            ],
            ActionKind::ChangeRequestPromote => &[
                EditionManifest,
                ChangedEditionManifest,
                DbIdentity,
                DefaultEqualsBase,
                EditionParentage,
                EditionExposure,
                ServiceEditions,
                DdlEffectClosure,
            ],
            ActionKind::GrantCreate | ActionKind::GrantUse => {
                &[ScopeDigest, MutationEffectClosure, Rows, PolicyFloor]
            }
        };
        for field in contract {
            assert!(required.contains(field), "{action:?}: missing {field:?}");
        }
        check_decisive(&complete_matrix_binding(), required).unwrap();
    }
}

#[test]
fn decisive_unavailable_refuses_for_each_row_field() {
    for has_ddl_event in [false, true] {
        for dml_rows_supported in [false, true] {
            let context = DecisiveMatrixContext {
                dml_rows_supported,
                has_ddl_event,
                ..Default::default()
            };
            for action in matrix_actions() {
                let required = DecisiveFieldMatrixV1::required(&action, context);
                for &field in required {
                    for status in [
                        Noncomputed::Timeout,
                        Noncomputed::Truncated,
                        Noncomputed::Estimated,
                        Noncomputed::NotApplicable,
                    ] {
                        let mut binding = complete_matrix_binding();
                        degrade_field(&mut binding, field, status);
                        assert_eq!(
                            check_decisive(&binding, required),
                            Err(DecisiveRefusal {
                                field,
                                reason: status.reason()
                            }),
                            "{action:?}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn require_impact_controls_partial_dependency_refusal_and_computed_drift_is_bound() {
    let action = ActionKind::CompileObject;
    let mut binding = complete_matrix_binding();
    binding.decisive.action_fields.insert(
        DecisiveField::Dependents,
        FieldStatus::Unavailable {
            reason: UnavailableReason::UnresolvedDependency,
        },
    );
    binding.decisive.action_fields.insert(
        DecisiveField::PredictedInvalidSet,
        FieldStatus::Unavailable {
            reason: UnavailableReason::Truncated,
        },
    );
    let mut context = DecisiveMatrixContext::default();
    check_decisive(&binding, DecisiveFieldMatrixV1::required(&action, context)).unwrap();
    context.require_impact = true;
    assert_eq!(
        check_decisive(&binding, DecisiveFieldMatrixV1::required(&action, context))
            .unwrap_err()
            .field,
        DecisiveField::Dependents
    );
    let original = complete_matrix_binding();
    let material =
        oraclemcp_guard::GrantMaterial::new("ALTER PROCEDURE APP.P COMPILE", &original).unwrap();
    let mut drifted = original.clone();
    drifted
        .decisive
        .action_fields
        .insert(DecisiveField::Dependents, computed([0xab; 32]));
    context.require_impact = false;
    assert_eq!(
        material
            .revalidate(&drifted, DecisiveFieldMatrixV1::required(&action, context))
            .unwrap_err()
            .into_envelope()
            .error_class,
        oraclemcp_error::ErrorClass::RepreviewRequired
    );
}

#[test]
fn decisive_missing_producer_commitment_refuses() {
    let context = DecisiveMatrixContext {
        dml_rows_supported: true,
        has_ddl_event: true,
        require_impact: true,
        ..Default::default()
    };
    for action in matrix_actions() {
        let required = DecisiveFieldMatrixV1::required(&action, context);
        for &field in required {
            let mut binding = complete_matrix_binding();
            if binding.decisive.action_fields.remove(&field).is_some() {
                assert_eq!(
                    check_decisive(&binding, required),
                    Err(DecisiveRefusal {
                        field,
                        reason: DecisiveRefusalReason::Missing
                    })
                );
            }
        }
    }
}

#[test]
fn decisive_truncated_dependents_refuses_ddl_when_required() {
    let context = DecisiveMatrixContext {
        dml_rows_supported: false,
        has_ddl_event: true,
        require_impact: true,
        ..Default::default()
    };
    let mut binding = complete_matrix_binding();
    degrade_field(
        &mut binding,
        DecisiveField::Dependents,
        Noncomputed::Truncated,
    );
    assert_eq!(
        check_decisive(
            &binding,
            DecisiveFieldMatrixV1::required(&ActionKind::ExecuteDdlAdmin, context)
        ),
        Err(DecisiveRefusal {
            field: DecisiveField::Dependents,
            reason: Noncomputed::Truncated.reason()
        })
    );
}

#[test]
fn generic_dml_unsupported_shape_rows_advisory_only() {
    let mut binding = complete_matrix_binding();
    degrade_field(&mut binding, DecisiveField::Rows, Noncomputed::Timeout);
    for action in [ActionKind::ExecuteDml, ActionKind::PreviewDmlSandbox] {
        let mut context = DecisiveMatrixContext {
            dml_rows_supported: false,
            has_ddl_event: false,
            ..Default::default()
        };
        check_decisive(&binding, DecisiveFieldMatrixV1::required(&action, context)).unwrap();
        context.dml_rows_supported = true;
        assert_eq!(
            check_decisive(&binding, DecisiveFieldMatrixV1::required(&action, context))
                .unwrap_err()
                .field,
            DecisiveField::Rows
        );
    }
}

#[test]
fn admin_action_unavailable_always_refuses() {
    let context = DecisiveMatrixContext {
        dml_rows_supported: false,
        has_ddl_event: true,
        ..Default::default()
    };
    for action in [
        ActionKind::ExecuteDdlAdmin,
        ActionKind::CustomToolCall,
        ActionKind::SetSessionLevel {
            level: OperatingLevel::Admin,
            ttl: 60,
        },
    ] {
        let required = DecisiveFieldMatrixV1::required(&action, context);
        for &field in required {
            let mut binding = complete_matrix_binding();
            degrade_field(&mut binding, field, Noncomputed::Timeout);
            assert!(check_decisive(&binding, required).is_err());
        }
    }
}

#[test]
fn decisive_computed_container_cannot_hide_unavailable_object_identity() {
    let mut binding = complete_matrix_binding();
    let FieldStatus::Computed { value: objects } = &mut binding.decisive.objects else {
        unreachable!()
    };
    objects[0].identity = FieldStatus::Unavailable {
        reason: UnavailableReason::Timeout,
    };
    binding
        .decisive
        .action_fields
        .insert(DecisiveField::ObjectIdentities, computed([2; 32]));
    assert_eq!(
        check_decisive(&binding, &[DecisiveField::ObjectIdentities]),
        Err(DecisiveRefusal {
            field: DecisiveField::ObjectIdentities,
            reason: Noncomputed::Timeout.reason()
        })
    );
}

#[test]
fn decisive_matrix_commitment_values_and_status_enter_digest() {
    let original = complete_matrix_binding();
    let mut changed = original.clone();
    changed
        .decisive
        .action_fields
        .insert(DecisiveField::MutationEffectClosure, computed([2; 32]));
    assert_ne!(original.decisive_digest(), changed.decisive_digest());
    changed = original.clone();
    degrade_field(
        &mut changed,
        DecisiveField::MutationEffectClosure,
        Noncomputed::Estimated,
    );
    assert_ne!(original.decisive_digest(), changed.decisive_digest());
}

#[test]
fn decisive_absent_scope_is_not_a_computed_grant_scope() {
    let mut binding = complete_matrix_binding();
    binding.decisive.scope_digest = computed(None);
    assert_eq!(
        check_decisive(&binding, &[DecisiveField::ScopeDigest]),
        Err(DecisiveRefusal {
            field: DecisiveField::ScopeDigest,
            reason: DecisiveRefusalReason::Missing
        })
    );
}

#[test]
fn decisive_wire_refusal_has_typed_class_field_and_cause_without_values() {
    use oraclemcp_error::{ErrorClass, StatementOutcome};
    for (reason, class, cause) in [
        (
            Noncomputed::Timeout.reason(),
            ErrorClass::ImpactDecisiveUnavailable,
            "timeout",
        ),
        (
            Noncomputed::Truncated.reason(),
            ErrorClass::ImpactDecisiveTruncated,
            "truncated",
        ),
    ] {
        let envelope = DecisiveRefusal {
            field: DecisiveField::Dependents,
            reason,
        }
        .into_envelope();
        assert_eq!(envelope.error_class, class);
        assert_eq!(
            envelope.statement_outcome,
            Some(StatementOutcome::NotStarted)
        );
        assert!(!envelope.error_class.is_retryable());
        assert!(!envelope.next_steps.is_empty());
        let wire = serde_json::to_value(envelope).unwrap();
        assert_eq!(
            wire["impact_decisive"],
            json!({"field":"dependents", "reason":cause})
        );
    }
}

#[test]
fn decisive_unknown_binding_version_refuses_even_with_computed_fields() {
    let mut binding = complete_matrix_binding();
    binding.version += 1;
    assert_eq!(
        check_decisive(&binding, &[DecisiveField::Envelope]),
        Err(DecisiveRefusal {
            field: DecisiveField::Envelope,
            reason: DecisiveRefusalReason::UnsupportedVersion {
                found: binding.version
            },
        })
    );
}

#[test]
fn decisive_revalidation_compares_each_required_value() {
    use oraclemcp_guard::impact_binding::check_decisive_revalidation;
    let approved = complete_matrix_binding();
    for action in matrix_actions() {
        let required = DecisiveFieldMatrixV1::required(
            &action,
            DecisiveMatrixContext {
                dml_rows_supported: true,
                has_ddl_event: true,
                require_impact: true,
                ..Default::default()
            },
        );
        check_decisive_revalidation(&approved, &approved, required).unwrap();
        for &field in required {
            let mut current = approved.clone();
            match field {
                DecisiveField::Envelope => current.decisive.envelope_digest = computed([9; 32]),
                DecisiveField::ObjectIdentities => {
                    let FieldStatus::Computed { value } = &mut current.decisive.objects else {
                        unreachable!()
                    };
                    value[0].identity = computed("different object".into());
                }
                DecisiveField::ObjectStatus => {
                    let FieldStatus::Computed { value } = &mut current.decisive.objects else {
                        unreachable!()
                    };
                    value[0].status = computed("INVALID".into());
                }
                DecisiveField::Edition => current.decisive.edition = computed("E2".into()),
                DecisiveField::CurrentSchema => {
                    current.decisive.current_schema = computed("OTHER".into())
                }
                DecisiveField::ProfileGeneration => {
                    current.decisive.profile_generation = computed(2)
                }
                DecisiveField::LaneGeneration => current.decisive.lane_generation = computed(2),
                DecisiveField::DbIdentity => {
                    current.decisive.db_identity = computed(DbIdentity {
                        dbid: 99,
                        con_uid: 99,
                    })
                }
                DecisiveField::ScopeDigest => {
                    current.decisive.scope_digest = computed(Some([9; 32]))
                }
                _ => {
                    current
                        .decisive
                        .action_fields
                        .insert(field, computed([9; 32]));
                }
            }
            let failure = check_decisive_revalidation(&approved, &current, required).unwrap_err();
            assert_eq!(
                failure.into_envelope().error_class,
                oraclemcp_error::ErrorClass::RepreviewRequired,
                "{action:?}/{field:?}"
            );
        }
    }
}

#[test]
fn require_impact_false_cannot_waive_decisive() {
    // Advisory configuration is deliberately absent from the admission API.
    let mut binding = complete_matrix_binding();
    degrade_field(
        &mut binding,
        DecisiveField::DdlEffectClosure,
        Noncomputed::Timeout,
    );
    let action = ActionKind::ExecuteDdlAdmin;
    let required = DecisiveFieldMatrixV1::required(
        &action,
        DecisiveMatrixContext {
            dml_rows_supported: false,
            has_ddl_event: true,
            ..Default::default()
        },
    );
    assert_eq!(
        check_decisive(&binding, required).unwrap_err().field,
        DecisiveField::DdlEffectClosure
    );
}

#[test]
fn decisive_optional_unavailable_and_row_drift_do_not_block_other_actions() {
    use oraclemcp_guard::impact_binding::check_decisive_revalidation;
    let approved = complete_matrix_binding();
    let mut current = approved.clone();
    degrade_field(&mut current, DecisiveField::Rows, Noncomputed::Timeout);
    for action in [
        ActionKind::ExecuteDdlAdmin,
        ActionKind::SetSessionLevel {
            level: OperatingLevel::Admin,
            ttl: 60,
        },
        ActionKind::CustomToolCall,
    ] {
        let required = DecisiveFieldMatrixV1::required(
            &action,
            DecisiveMatrixContext {
                dml_rows_supported: false,
                has_ddl_event: false,
                ..Default::default()
            },
        );
        check_decisive(&current, required).unwrap();
        check_decisive_revalidation(&approved, &current, required).unwrap();
    }
}

#[test]
fn decisive_ddl_trigger_requirement_comes_from_the_actual_event() {
    let mut binding = complete_matrix_binding();
    binding
        .decisive
        .action_fields
        .remove(&DecisiveField::DdlEffectClosure);
    for action in [ActionKind::CustomToolCall, ActionKind::ChangeRequestPromote] {
        let mut context = DecisiveMatrixContext {
            dml_rows_supported: false,
            has_ddl_event: false,
            ..Default::default()
        };
        check_decisive(&binding, DecisiveFieldMatrixV1::required(&action, context)).unwrap();
        context.has_ddl_event = true;
        assert_eq!(
            check_decisive(&binding, DecisiveFieldMatrixV1::required(&action, context))
                .unwrap_err()
                .field,
            DecisiveField::DdlEffectClosure
        );
    }
}

#[test]
fn decisive_wrapped_truncation_keeps_the_typed_refusal() {
    let envelope = DecisiveRefusal {
        field: DecisiveField::Dependents,
        reason: DecisiveRefusalReason::Unavailable {
            reason: UnavailableReason::ImpactDecisiveTruncated,
        },
    }
    .into_envelope();
    assert_eq!(
        envelope.error_class,
        oraclemcp_error::ErrorClass::ImpactDecisiveTruncated
    );
    assert_eq!(
        serde_json::to_value(envelope).unwrap()["impact_decisive"]["reason"],
        "truncated"
    );
}

#[test]
fn impact_every_field_serialized_with_status() {
    let value = serde_json::to_value(ImpactV1::default()).unwrap();
    for field in [
        "rows",
        "dependents",
        "effects",
        "sast",
        "cost",
        "locks",
        "reversibility",
    ] {
        assert_eq!(value[field]["status"], "unavailable", "{field}");
        assert_eq!(value[field]["reason"], "not_collected", "{field}");
    }
    for field in [
        "envelope_digest",
        "statement_digest",
        "bind_hmac",
        "objects",
        "edition",
        "compiler_facts",
        "compile_parse_closure_digest",
        "engine_version",
        "ruleset_digest",
        "effective_plan_digest",
        "policy_schema_digest",
        "policy_ruleset_digest",
        "matched_policy_rule_ids",
        "rewrite_algorithm_version",
        "db_identity",
        "current_schema",
        "profile_generation",
        "lane_generation",
        "scope_digest",
    ] {
        assert_eq!(
            value["binding"]["decisive"][field]["status"], "unavailable",
            "{field}"
        );
    }
    let decoded: ImpactV1 = serde_json::from_value(value).unwrap();
    assert_eq!(decoded, ImpactV1::default());
}

#[test]
fn impact_decisive_digest_ignores_observations() {
    let original = sample();
    let mut changed = original.clone();
    changed.observations.rows = Some(RowEstimate {
        kind: RowEstimateKind::Estimated,
        value: 42,
        scn: ScnBounds::Window {
            scn_before: 10,
            scn_after: 11,
        },
        profile_generation: 4,
    });
    changed.observations.cost = Some(json!({"estimate": 99}));
    changed.observations.timings.insert("query_ms".into(), 50);
    changed.observations.statuses.insert(
        "rows".into(),
        FieldStatus::NotApplicable {
            reason: NotApplicableReason::NotDml,
        },
    );
    changed.observations.scn_bounds = Some(ScnBounds::Window {
        scn_before: 10,
        scn_after: 11,
    });
    assert_ne!(changed.observations, original.observations);
    assert_eq!(original.decisive_digest(), changed.decisive_digest());
}

#[test]
fn impact_scn_advance_does_not_change_decisive_digest() {
    let mut binding = sample();
    binding.observations.scn_bounds = Some(ScnBounds::Window {
        scn_before: 10,
        scn_after: 11,
    });
    let original = binding.decisive_digest();
    binding.observations.scn_bounds = Some(ScnBounds::Window {
        scn_before: 20,
        scn_after: 21,
    });
    assert_eq!(binding.decisive_digest(), original);
}

#[test]
fn impact_object_order_does_not_change_decisive_digest() {
    let mut binding = sample();
    let FieldStatus::Computed { value: objects } = &mut binding.decisive.objects else {
        unreachable!()
    };
    let mut second = objects[0].clone();
    second.identity = computed("SCHEMA.U".into());
    objects.push(second);
    let original = binding.decisive_digest();
    let FieldStatus::Computed { value: objects } = &mut binding.decisive.objects else {
        unreachable!()
    };
    objects.reverse();
    assert_eq!(binding.decisive_digest(), original);
}

#[test]
fn impact_observed_at_scn_only_with_as_of() {
    let as_of = serde_json::to_value(ScnBounds::AsOf {
        observed_at_scn: 42,
    })
    .unwrap();
    let window = serde_json::to_value(ScnBounds::Window {
        scn_before: 41,
        scn_after: 43,
    })
    .unwrap();
    assert_eq!(as_of["observed_at_scn"], 42);
    assert!(as_of.get("scn_before").is_none());
    assert!(window.get("observed_at_scn").is_none());
    assert_eq!(window["scn_before"], 41);
    assert_eq!(window["scn_after"], 43);
}

#[test]
fn impact_binding_version_mismatch_refused() {
    let mut binding = sample();
    binding.version += 1;
    assert_eq!(binding.decisive_digest().unwrap_err().found, 2);
}

#[test]
fn field_budget_timeout_maps_to_unavailable_timeout() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap();
    let result = runtime.block_on(FieldBudget::run(
        Instant::now() + Duration::from_millis(10),
        FieldCaps {
            max_depth: 2,
            max_count: 2,
        },
        std::future::pending::<FieldMeasure<u8>>(),
    ));
    assert_eq!(
        result,
        FieldStatus::Unavailable {
            reason: UnavailableReason::Timeout
        }
    );
}

#[test]
fn field_budget_cap_maps_to_truncated() {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .unwrap();
    let caps = FieldCaps {
        max_depth: 2,
        max_count: 3,
    };
    for measure in [
        FieldMeasure {
            value: 7,
            depth: 3,
            count: 1,
        },
        FieldMeasure {
            value: 7,
            depth: 1,
            count: 4,
        },
    ] {
        let result = runtime.block_on(FieldBudget::run(
            Instant::now() + Duration::from_secs(1),
            caps,
            std::future::ready(measure),
        ));
        assert_eq!(
            result,
            FieldStatus::Unavailable {
                reason: UnavailableReason::Truncated
            }
        );
    }
}

fn change_dbid(facts: &mut DecisiveFacts, change: u8) {
    facts.db_identity = computed(DbIdentity {
        dbid: u64::from(change) + 1,
        con_uid: 2,
    });
}

#[test]
fn field_eight_change_one_changes_dbid_and_decisive_digest() {
    let original = sample();
    let mut changed = original.clone();
    change_dbid(&mut changed.decisive, 1);
    assert_ne!(original.decisive, changed.decisive);
    assert_ne!(original.decisive_digest(), changed.decisive_digest());
}

#[test]
fn policy_rule_order_and_identity_are_decisive_even_at_smallest_mutation() {
    let original = sample();
    let mut changed = original.clone();
    changed.decisive.matched_policy_rule_ids = computed(vec!["P3".into(), "P2".into()]);
    assert_ne!(original.decisive, changed.decisive);
    assert_ne!(original.decisive_digest(), changed.decisive_digest());
    changed.decisive.matched_policy_rule_ids = computed(vec!["P2".into(), "P1".into()]);
    assert_ne!(original.decisive_digest(), changed.decisive_digest());
}

proptest! {
    #[test]
    fn prop_decisive_digest_changes_on_each_decisive_field(field in 0usize..25, change in 1u8..=255) {
        let original = sample();
        let mut changed = original.clone();
        let facts = &mut changed.decisive;
        match field {
            0 => facts.envelope_digest = computed([change; 32]),
            1 => facts.statement_digest = computed([change; 32]),
            2 => facts.bind_hmac = computed([change; 32]),
            3 => facts.objects = computed(Vec::new()),
            4 => facts.edition = computed(format!("EDITION_{change}")),
            5 => facts.compiler_facts = computed(format!("COMPILER_{change}")),
            24 => facts.compile_parse_closure_digest = computed([change; 32]),
            6 => facts.engine_version = computed(format!("ENGINE_{change}")),
            7 => facts.ruleset_digest = computed([change; 32]),
            8 => change_dbid(facts, change),
            9 => facts.current_schema = computed(format!("SCHEMA_{change}")),
            10 => facts.profile_generation = computed(u64::from(change) + 1),
            11 => facts.lane_generation = computed(u64::from(change) + 1),
            12 => facts.scope_digest = computed(Some([change; 32])),
            18 => facts.db_identity = computed(DbIdentity { dbid: 1, con_uid: u64::from(change) + 2 }),
            19 => facts.effective_plan_digest = computed([change; 32]),
            20 => facts.policy_schema_digest = computed([change; 32]),
            21 => facts.policy_ruleset_digest = computed([change; 32]),
            22 => facts.matched_policy_rule_ids = computed(vec![format!("P{}", u16::from(change) + 2), "P2".into()]),
            23 => facts.rewrite_algorithm_version = computed(u16::from(change) + 1),
            13..=17 => {
                let FieldStatus::Computed { value: objects } = &mut facts.objects else { unreachable!() };
                let object = &mut objects[0];
                match field {
                    13 => object.identity = computed(format!("SCHEMA.T{change}")),
                    14 => object.status = computed(format!("STATUS_{change}")),
                    15 => object.source_hash = computed([change; 32]),
                    16 => object.dependency_hash = computed([change; 32]),
                    17 => object.trigger_hash = computed([change; 32]),
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
        prop_assert_ne!(&original.decisive, &changed.decisive);
        prop_assert_ne!(original.decisive_digest(), changed.decisive_digest());
    }
}

#[test]
fn status_encoding_changes_decisive_digest() {
    let original = sample();
    let mut estimated = original.clone();
    estimated.decisive.statement_digest = FieldStatus::Estimated { value: [0; 32] };
    assert_ne!(original.decisive_digest(), estimated.decisive_digest());
    let mut unavailable = original.clone();
    unavailable.decisive.statement_digest = FieldStatus::Unavailable {
        reason: UnavailableReason::NoPrivilege,
    };
    assert_ne!(original.decisive_digest(), unavailable.decisive_digest());
    assert_ne!(estimated.decisive_digest(), unavailable.decisive_digest());
    let serialized: Value = serde_json::to_value(unavailable).unwrap();
    assert_eq!(
        serialized["decisive"]["statement_digest"]["status"],
        "unavailable"
    );
}

#[test]
fn every_known_error_class_keeps_a_distinct_unavailable_reason() {
    let mut reasons = std::collections::BTreeSet::new();
    let mut digests = std::collections::BTreeSet::new();
    for class in oraclemcp_error::ErrorClass::ALL {
        let reason = UnavailableReason::from_error_class(class);
        assert_ne!(reason, UnavailableReason::CatalogUnavailable, "{class:?}");
        reasons.insert(serde_json::to_string(&reason).unwrap());
        let mut binding = sample();
        binding.decisive.statement_digest = FieldStatus::Unavailable { reason };
        digests.insert(binding.decisive_digest().unwrap());
    }
    assert_eq!(reasons.len(), oraclemcp_error::ErrorClass::ALL.len());
    assert_eq!(digests.len(), oraclemcp_error::ErrorClass::ALL.len());
    assert_eq!(
        serde_json::to_value(UnavailableReason::from_error_class(
            oraclemcp_error::ErrorClass::FlashbackDefinitionChanged
        ))
        .unwrap(),
        "flashback_definition_changed"
    );
}

#[test]
fn approved_material_ignores_optional_unavailability_and_requires_supported_rows() {
    let original = complete_matrix_binding();
    let material =
        oraclemcp_guard::GrantMaterial::new("UPDATE APP.T SET N=1 WHERE ID=1", &original).unwrap();
    let mut current = original.clone();
    current.decisive.db_identity = FieldStatus::Unavailable {
        reason: UnavailableReason::NoPrivilege,
    };
    current
        .decisive
        .action_fields
        .insert(DecisiveField::Rows, computed([9; 32]));
    assert_ne!(material.decisive_digest, current.decisive_digest().unwrap());
    let mut context = DecisiveMatrixContext {
        dml_rows_supported: false,
        has_ddl_event: false,
        ..Default::default()
    };
    let action = ActionKind::ExecuteDml;
    material
        .revalidate(&current, DecisiveFieldMatrixV1::required(&action, context))
        .unwrap();
    context.dml_rows_supported = true;
    assert_eq!(
        material.revalidate(&current, DecisiveFieldMatrixV1::required(&action, context)),
        Err(
            oraclemcp_guard::impact_binding::DecisiveRevalidationRefusal::Changed {
                field: DecisiveField::Rows
            }
        )
    );
    degrade_field(&mut current, DecisiveField::Rows, Noncomputed::Truncated);
    let error = material
        .revalidate(&current, DecisiveFieldMatrixV1::required(&action, context))
        .unwrap_err()
        .into_envelope();
    assert_eq!(
        error.error_class,
        oraclemcp_error::ErrorClass::RepreviewRequired
    );
    assert_eq!(
        check_decisive(&current, DecisiveFieldMatrixV1::required(&action, context))
            .unwrap_err()
            .into_envelope()
            .error_class,
        oraclemcp_error::ErrorClass::ImpactDecisiveTruncated
    );
}

#[test]
fn approved_material_keeps_policy_authority_decisive() {
    let original = complete_matrix_binding();
    let material =
        oraclemcp_guard::GrantMaterial::new("UPDATE APP.T SET N=1 WHERE ID=1", &original).unwrap();
    let mut current = original.clone();
    current.decisive.policy_ruleset_digest = computed([9; 32]);
    let required = DecisiveFieldMatrixV1::required(
        &ActionKind::ExecuteDml,
        DecisiveMatrixContext {
            dml_rows_supported: false,
            has_ddl_event: false,
            ..Default::default()
        },
    );
    assert_eq!(
        material.revalidate(&current, required),
        Err(
            oraclemcp_guard::impact_binding::DecisiveRevalidationRefusal::Changed {
                field: DecisiveField::Envelope
            }
        )
    );
}

#[test]
fn decisive_status_fingerprint_binds_the_object_identity() {
    let mut original = complete_matrix_binding();
    let FieldStatus::Computed { value: objects } = &mut original.decisive.objects else {
        unreachable!()
    };
    let mut second = objects[0].clone();
    second.identity = computed("OTHER_OBJECT".into());
    second.status = computed("INVALID".into());
    objects.push(second);
    let material = oraclemcp_guard::GrantMaterial::new("compile", &original).unwrap();
    let mut current = original.clone();
    let FieldStatus::Computed { value: objects } = &mut current.decisive.objects else {
        unreachable!()
    };
    objects[0].status = computed("INVALID".into());
    objects[1].status = computed("VALID".into());
    assert!(
        material
            .revalidate(&current, &[DecisiveField::ObjectStatus])
            .is_err()
    );
    let FieldStatus::Computed { value: objects } = &mut current.decisive.objects else {
        unreachable!()
    };
    objects.reverse();
    assert!(
        material
            .revalidate(&current, &[DecisiveField::ObjectStatus])
            .is_err()
    );
}
