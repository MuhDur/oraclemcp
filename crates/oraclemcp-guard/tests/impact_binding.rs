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
        assert_eq!(value[field]["reason"], "not_wired", "{field}");
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
