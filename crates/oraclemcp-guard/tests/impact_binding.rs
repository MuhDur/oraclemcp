use std::time::{Duration, Instant};

use oraclemcp_guard::impact_binding::{
    DbIdentity, DecisiveFacts, FieldBudget, FieldCaps, FieldMeasure, FieldStatus, ImpactBindingV1,
    ImpactV1, NotApplicableReason, ObjectFact, RowEstimate, RowEstimateKind, ScnBounds,
    UnavailableReason,
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
        },
        ..ImpactBindingV1::default()
    }
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
    fn prop_decisive_digest_changes_on_each_decisive_field(field in 0usize..24, change in 1u8..=255) {
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
