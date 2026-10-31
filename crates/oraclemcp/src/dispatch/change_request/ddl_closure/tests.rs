use super::*;
use oraclemcp_guard::{
    RoutineEffect, RoutineEffectsV1,
    ddl_closure::{DdlPredicate, DdlTriggerFact, DdlTriggerScope},
    mutation_closure::{MutationComputation, MutationDatabaseIdentity, MutationUnavailableReason},
};
use std::collections::BTreeSet;

fn request() -> W12DdlTriggerRequest {
    W12DdlTriggerRequest::new(
        W12DdlEvent::CreateOrReplace {
            kind: "PROCEDURE".into(),
        },
        "APP",
        "P",
        "FREEPDB1",
    )
    .unwrap()
}

fn collected(effects: impl IntoIterator<Item = RoutineEffect>) -> DdlEffectClosureV1 {
    let request = request();
    let mut closure = DdlEffectClosureV1::new(request.event.oracle_event(), request.object);
    closure.database = Some(MutationDatabaseIdentity {
        dbid: "1".into(),
        container: "FREEPDB1".into(),
        edition: "CHILD".into(),
    });
    closure.session_user = Some("APP".into());
    closure.current_schema = Some("APP".into());
    closure.catalog_sha256 = Some("a".repeat(64));
    closure.database_triggers_visible = true;
    closure.catalog_row_count = 1;
    closure.triggers.push(DdlTriggerFact {
        owner: "APP".into(),
        name: "DDL_READ".into(),
        object_id: 42,
        last_ddl_time: "2026-10-31T00:00:00".into(),
        scope: DdlTriggerScope::Schema,
        schema: Some("APP".into()),
        timing: "AFTER EVENT".into(),
        events: BTreeSet::from([DdlEvent::Create]),
        status: "ENABLED".into(),
        predicate: DdlPredicate::Unconditional,
        metadata_sha256: "b".repeat(64),
        source_sha256: Some("c".repeat(64)),
        routine_closure_fingerprint: Some("d".repeat(64)),
        effects: RoutineEffectsV1::new(effects),
        computation: MutationComputation::Computed,
    });
    closure
}

#[test]
fn w12_event_requests_use_exact_event_and_dictionary_object_type() {
    for (event, expected_event, kind, owner) in [
        (
            W12DdlEvent::CreateEdition,
            DdlEvent::Create,
            "EDITION",
            "SYS",
        ),
        (W12DdlEvent::DropEdition, DdlEvent::Drop, "EDITION", "SYS"),
        (
            W12DdlEvent::CreateOrReplace {
                kind: "PACKAGE BODY".into(),
            },
            DdlEvent::Create,
            "PACKAGE BODY",
            "APP",
        ),
        (
            W12DdlEvent::AlterCompile {
                kind: "PROCEDURE".into(),
            },
            DdlEvent::Alter,
            "PROCEDURE",
            "APP",
        ),
    ] {
        let request = W12DdlTriggerRequest::new(event, "APP", "X", "FREEPDB1").unwrap();
        assert_eq!(request.event.oracle_event(), expected_event);
        assert_eq!(request.object.object_type, kind);
        assert_eq!(request.object.owner, owner);
    }
    for kind in ["TABLE", "EDITION", "DATABASE", "UNKNOWN", ""] {
        assert!(
            W12DdlTriggerRequest::new(
                W12DdlEvent::AlterCompile { kind: kind.into() },
                "APP",
                "X",
                "FREEPDB1"
            )
            .is_err()
        );
    }
}

#[test]
fn w12_request_dictionary_names_are_bounded_and_reject_nul() {
    let event = W12DdlEvent::AlterCompile {
        kind: "PROCEDURE".into(),
    };
    let limit = "A".repeat(128);
    W12DdlTriggerRequest::new(event.clone(), &limit, &limit, &limit).unwrap();
    for invalid in [String::new(), "A".repeat(129), "A\0B".into()] {
        for (owner, name, container) in [
            (invalid.as_str(), "P", "FREEPDB1"),
            ("APP", invalid.as_str(), "FREEPDB1"),
            ("APP", "P", invalid.as_str()),
        ] {
            assert_eq!(
                W12DdlTriggerRequest::new(event.clone(), owner, name, container),
                Err(W12DdlTriggerRefusal::Unknown),
                "owner={owner:?}, name={name:?}, container={container:?}",
            );
        }
    }
}

#[test]
fn w12_ddl_trigger_missing_privilege_unknown_refuses() {
    let mut closure = collected([RoutineEffect::ReadDb]);
    closure.database_triggers_visible = false;
    closure
        .unavailable
        .insert(MutationUnavailableReason::CatalogUnreadable);
    assert_eq!(
        W12DdlTriggerProof::from_collected(request(), closure),
        Err(W12DdlTriggerRefusal::Unknown)
    );
}

#[test]
fn w12_ddl_trigger_admission_uses_the_shared_ddl_context() {
    for effect in [RoutineEffect::ReadDb, RoutineEffect::SessionState] {
        W12DdlTriggerProof::from_collected(request(), collected([effect])).unwrap();
    }
    for effect in [
        RoutineEffect::Dml,
        RoutineEffect::RowLock,
        RoutineEffect::Ddl,
        RoutineEffect::Admin,
        RoutineEffect::Autonomous,
        RoutineEffect::TxnControl,
    ] {
        assert_eq!(
            W12DdlTriggerProof::from_collected(request(), collected([effect])),
            Err(W12DdlTriggerRefusal::Effectful)
        );
    }
    assert_eq!(
        W12DdlTriggerProof::from_collected(request(), collected([RoutineEffect::Unknown])),
        Err(W12DdlTriggerRefusal::Unknown)
    );
}

#[test]
fn w12_ddl_trigger_proof_rejects_a_substituted_object_event_or_container() {
    for field in ["object", "event", "container"] {
        let mut closure = collected([RoutineEffect::ReadDb]);
        match field {
            "object" => closure.object.name = "OTHER".into(),
            "event" => closure.event = DdlEvent::Drop,
            _ => closure.database.as_mut().unwrap().container = "OTHERPDB".into(),
        }
        assert_eq!(
            W12DdlTriggerProof::from_collected(request(), closure),
            Err(W12DdlTriggerRefusal::Unknown)
        );
    }
}

#[test]
fn default_edition_flip_excluded_from_ddl_trigger_closure() {
    assert!(default_edition_flip_excluded(
        "ALTER DATABASE DEFAULT EDITION = \"REVIEWED_CHILD\""
    ));
    for sql in [
        "ALTER DATABASE OPEN",
        "ALTER SESSION SET EDITION = CHILD",
        "ALTER PROCEDURE P COMPILE",
        "DROP EDITION CHILD",
    ] {
        assert!(!default_edition_flip_excluded(sql), "{sql}");
    }
}

#[test]
fn w12_complete_trigger_proof_enters_the_decisive_binding() {
    let proof =
        W12DdlTriggerProof::from_collected(request(), collected([RoutineEffect::ReadDb])).unwrap();
    let mut binding = ImpactBindingV1::default();
    let before = binding.decisive_digest().unwrap();
    proof.bind_into(&mut binding);
    let fingerprint = proof
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(fingerprint, proof.closure.fingerprint());
    assert_eq!(
        binding
            .decisive
            .action_fields
            .get(&DecisiveField::DdlEffectClosure),
        Some(&FieldStatus::Computed {
            value: proof.digest()
        })
    );
    assert_ne!(before, binding.decisive_digest().unwrap());
    for field in ["source", "predicate", "identity", "effects", "catalog"] {
        let mut closure = proof.closure.clone();
        match field {
            "source" => closure.triggers[0].source_sha256 = Some("e".repeat(64)),
            "predicate" => {
                closure.triggers[0].predicate = DdlPredicate::DictionaryGuard {
                    text: "ORA_DICT_OBJ_TYPE = 'PROCEDURE'".into(),
                    value: true,
                }
            }
            "identity" => closure.triggers[0].object_id += 1,
            "effects" => {
                closure.triggers[0].effects = RoutineEffectsV1::new([RoutineEffect::SessionState])
            }
            _ => closure.catalog_sha256 = Some("f".repeat(64)),
        }
        let changed = W12DdlTriggerProof::from_collected(request(), closure).unwrap();
        assert_ne!(proof.digest(), changed.digest(), "{field}");
    }
}

#[test]
fn w12_recheck_refuses_clean_source_drift_and_retains_both_digests() {
    let preview =
        W12DdlTriggerProof::from_collected(request(), collected([RoutineEffect::ReadDb])).unwrap();
    let mut binding = ImpactBindingV1::default();
    preview.bind_into(&mut binding);
    let matched = compare_recollected(&binding, &preview, preview.closure.clone()).unwrap();
    assert_eq!(matched.bound_digest, preview.digest());
    assert_eq!(matched.observed_digest, preview.digest());
    let mut changed = preview.closure.clone();
    changed.triggers[0].source_sha256 = Some("e".repeat(64));
    let expected = proof_digest(&changed);
    let error = compare_recollected(&binding, &preview, changed).unwrap_err();
    assert_eq!(error.refusal, W12DdlTriggerRefusal::RepreviewRequired);
    assert_eq!(error.bound_digest, preview.digest());
    assert_eq!(error.observed_digest, Some(expected));
    assert_ne!(error.bound_digest, error.observed_digest.unwrap());
}

#[test]
fn w12_recheck_refuses_missing_or_noncomputed_binding_and_new_effects() {
    let preview =
        W12DdlTriggerProof::from_collected(request(), collected([RoutineEffect::ReadDb])).unwrap();
    let mut binding = ImpactBindingV1::default();
    assert!(compare_recollected(&binding, &preview, preview.closure.clone()).is_err());
    for status in [
        FieldStatus::Unavailable {
            reason: oraclemcp_guard::UnavailableReason::Truncated,
        },
        FieldStatus::Estimated {
            value: preview.digest(),
        },
        FieldStatus::Computed { value: [9; 32] },
    ] {
        binding
            .decisive
            .action_fields
            .insert(DecisiveField::DdlEffectClosure, status);
        assert!(compare_recollected(&binding, &preview, preview.closure.clone()).is_err());
    }
    preview.bind_into(&mut binding);
    for closure in [
        collected([RoutineEffect::Autonomous]),
        DdlEffectClosureV1::new(DdlEvent::Create, preview.request.object.clone()),
    ] {
        assert_eq!(
            compare_recollected(&binding, &preview, closure)
                .unwrap_err()
                .refusal,
            W12DdlTriggerRefusal::RepreviewRequired
        );
    }
}

#[test]
fn w12_refusals_keep_typed_categories_and_not_started_outcomes() {
    for (refusal, category) in [
        (W12DdlTriggerRefusal::Effectful, "DDL_TRIGGER_EFFECTFUL"),
        (W12DdlTriggerRefusal::Unknown, "DDL_TRIGGER_UNKNOWN"),
    ] {
        let value = serde_json::to_value(refusal.into_envelope()).unwrap();
        assert_eq!(value["error_class"], "FORBIDDEN_STATEMENT");
        assert_eq!(value["structured_reason"]["category"], category);
        assert_eq!(value["statement_outcome"], "not_started");
    }
    let value =
        serde_json::to_value(W12DdlTriggerRefusal::RepreviewRequired.into_envelope()).unwrap();
    assert_eq!(value["error_class"], "REPREVIEW_REQUIRED");
    assert_eq!(value["statement_outcome"], "not_started");
    assert_eq!(value["suggested_tool"], "oracle_change_request");
    assert!(value["next_steps"].as_array().unwrap().iter().any(|step| {
        step.as_str()
            == Some("obtain a new change-request preview; the bound DDL-trigger facts changed")
    }));
}
