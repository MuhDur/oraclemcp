//! Grant admission over constructed `MutationEffectClosureV1` values (T13.2a,
//! pvlqq.15.3). Unit/offline proof of the admission decision only; the live
//! collector facts are proven by `oraclemcp/tests/grant_admission_live.rs`.

use std::collections::BTreeSet;
use std::time::Duration;

use oraclemcp_guard::mutation_closure::{
    MutationCatalogObservation, MutationCatalogSource, MutationColumns, MutationComputation,
    MutationDatabaseIdentity, MutationEffectClosureV1, MutationForeignKeyAction, MutationMechanism,
    MutationMechanismFact, MutationRelationScope, MutationStatementKind, MutationTarget,
    MutationUnavailableReason,
};
use oraclemcp_guard::resolver::CatalogGeneration;
use oraclemcp_guard::scoped_grant::admission::{
    GrantAdmissionRefusal, GrantDrift, GrantTargetFacts, NonHeapKind, admit_grant_target,
    recheck_grant_closure,
};
use oraclemcp_guard::{
    ColumnIdent, EffectiveCeiling, ExecGrantBinding, GrantComparison, GrantContainer, GrantLimits,
    GrantOp, GrantOperand, GrantPredicateV1, GrantTargetIdentity, GrantValue, GrantVerbs,
    OperatingLevel, RoutineEffect, RoutineEffectsV1, ScopedGrant, ScopedGrantRequest,
};

const HASH: &str = "0000000000000000000000000000000000000000000000000000000000000001";

fn target() -> MutationTarget {
    MutationTarget {
        owner: "OMCP_FX_GA".into(),
        name: "ORDERS".into(),
        object_id: 74_001,
        object_edition: None,
        last_ddl_time: "2026-10-31T10:00:00".into(),
    }
}

fn facts() -> GrantTargetFacts {
    GrantTargetFacts {
        target: target(),
        partitioned: false,
        index_organized: false,
        clustered: false,
        temporary: false,
        external: false,
        remote: false,
    }
}

fn col(name: &str) -> ColumnIdent {
    ColumnIdent::new(name).unwrap()
}

fn status_column() -> BTreeSet<ColumnIdent> {
    BTreeSet::from([col("STATUS")])
}

fn scope(kind: MutationStatementKind) -> MutationRelationScope {
    MutationRelationScope {
        target: target(),
        statement_kind: kind,
        columns: match kind {
            MutationStatementKind::Update => {
                MutationColumns::Named(BTreeSet::from(["STATUS".into()]))
            }
            _ => MutationColumns::All,
        },
    }
}

/// A complete closure: every family observed, computed and hashed.
fn closure(
    kind: MutationStatementKind,
    mechanisms: Vec<MutationMechanismFact>,
) -> MutationEffectClosureV1 {
    let root = scope(kind);
    let mut closure = MutationEffectClosureV1::new(
        Some(MutationDatabaseIdentity {
            dbid: "1506701346".into(),
            container: "FREEPDB1".into(),
            edition: "ORA$BASE".into(),
        }),
        root.clone(),
    );
    for source in MutationCatalogSource::ALL {
        closure.observations.push(MutationCatalogObservation {
            scope: root.clone(),
            source,
            computation: MutationComputation::Computed,
            source_sha256: Some(HASH.into()),
            row_count: 0,
        });
    }
    closure.mechanisms = mechanisms;
    assert!(closure.is_complete(), "fixture closure must be complete");
    closure
}

fn fact(
    kind: MutationStatementKind,
    name: &str,
    mechanism: MutationMechanism,
    effects: &[RoutineEffect],
) -> MutationMechanismFact {
    MutationMechanismFact {
        scope: scope(kind),
        owner: "OMCP_FX_GA".into(),
        name: name.into(),
        object_id: Some(9),
        mechanism,
        metadata_sha256: HASH.into(),
        source_sha256: Some(HASH.into()),
        routine_closure_fingerprints: BTreeSet::from([HASH.to_owned()]),
        effects: RoutineEffectsV1::new(effects.iter().copied()),
        computation: MutationComputation::Computed,
    }
}

fn update() -> GrantVerbs {
    GrantVerbs::parse(&["UPDATE"]).unwrap()
}

fn admit_update(mechanisms: Vec<MutationMechanismFact>) -> Result<(), GrantAdmissionRefusal> {
    admit_grant_target(
        &facts(),
        &[closure(MutationStatementKind::Update, mechanisms)],
        &update(),
        &status_column(),
    )
    .map(|_| ())
}

fn trigger(timing: &str, level: &str, compound: bool, columns: &[&str]) -> MutationMechanism {
    MutationMechanism::DmlTrigger {
        timing: timing.into(),
        level: level.into(),
        compound,
        columns: columns.iter().map(|c| (*c).to_owned()).collect(),
    }
}

fn request(closure: oraclemcp_guard::ClosureFingerprints) -> ScopedGrantRequest {
    ScopedGrantRequest {
        profile: "dev".into(),
        binding: ExecGrantBinding::new("sess-1", "lane-1", "subject-1", 1),
        verbs: vec!["UPDATE".into()],
        target: GrantTargetIdentity {
            owner: "OMCP_FX_GA".into(),
            object_name: "ORDERS".into(),
            object_id: 74_001,
            data_object_id: Some(74_001),
            container: GrantContainer {
                con_id: 3,
                con_uid: 2_811_000_001,
            },
            edition: None,
            catalog_generation: CatalogGeneration(1),
            resolved_via: None,
        },
        columns: status_column(),
        row_predicate: GrantPredicateV1::new(vec![GrantComparison {
            column: col("ID"),
            op: GrantOp::In,
            operand: GrantOperand::List(vec![GrantValue::number("101").unwrap()]),
        }]),
        limits: GrantLimits {
            max_rows_per_statement: 5,
            max_statements: 20,
            max_total_rows: 20,
        },
        ttl: Duration::from_secs(600),
        commit_allowed: false,
        closure,
        last_ddl_time: oraclemcp_guard::LastDdlTime::new("2026-10-31T10:00:00").unwrap(),
    }
}

fn grant(closure: oraclemcp_guard::ClosureFingerprints) -> ScopedGrant {
    ScopedGrant::new(
        request(closure),
        EffectiveCeiling {
            profile_max_level: OperatingLevel::ReadWrite,
            oauth_ceiling: None,
        },
        false,
        &[7; 32],
    )
    .unwrap()
}

#[test]
fn grant_admission_ordinary_heap_table_admitted() {
    let verbs = GrantVerbs::parse(&["UPDATE", "DELETE"]).unwrap();
    // A plain FK (no delete action) and an ordinary index are not user code.
    let fk = fact(
        MutationStatementKind::Delete,
        "FK_LINES",
        MutationMechanism::ForeignKeyAction {
            on_delete: MutationForeignKeyAction::NoAction,
            child_owner: "OMCP_FX_GA".into(),
            child_table: "LINES".into(),
            child_columns: BTreeSet::from(["ORDER_ID".into()]),
        },
        &[RoutineEffect::ReadDb],
    );
    let index = fact(
        MutationStatementKind::Update,
        "ORDERS_PK",
        MutationMechanism::IndexCallback { domain: false },
        &[],
    );
    let admitted = admit_grant_target(
        &facts(),
        &[
            closure(MutationStatementKind::Update, vec![index]),
            closure(MutationStatementKind::Delete, vec![fk]),
        ],
        &verbs,
        &status_column(),
    )
    .expect("ordinary heap table is admitted");
    assert_eq!(admitted.required_level, OperatingLevel::ReadWrite);
    // Target facts plus one closure per verb.
    assert_eq!(admitted.closure.iter().count(), 3);
    // The fingerprints are bound into the grant's scope digest.
    let bound = grant(admitted.closure.clone());
    let unbound = grant(oraclemcp_guard::ClosureFingerprints::new());
    assert_ne!(bound.scope_digest(), unbound.scope_digest());
}

#[test]
fn grant_admission_refuses_partitioned_iot_external_clustered_temporary() {
    for (mutate, kind) in [
        (
            (|facts: &mut GrantTargetFacts| facts.partitioned = true) as fn(&mut GrantTargetFacts),
            NonHeapKind::Partitioned,
        ),
        (
            |facts| facts.index_organized = true,
            NonHeapKind::IndexOrganized,
        ),
        (|facts| facts.external = true, NonHeapKind::External),
        (|facts| facts.clustered = true, NonHeapKind::Clustered),
        (|facts| facts.temporary = true, NonHeapKind::Temporary),
        (|facts| facts.remote = true, NonHeapKind::Remote),
    ] {
        let mut target = facts();
        mutate(&mut target);
        assert_eq!(
            admit_grant_target(
                &target,
                &[closure(MutationStatementKind::Update, Vec::new())],
                &update(),
                &status_column()
            ),
            Err(GrantAdmissionRefusal::NotOrdinaryHeapTable { kind })
        );
    }
}

#[test]
fn grant_admission_refuses_any_enabled_user_dml_trigger() {
    for (name, mechanism, effects) in [
        // Purely transactional: only assigns :NEW.updated_at.
        (
            "TR_TOUCH",
            trigger("BEFORE EACH ROW", "ROW", false, &[]),
            vec![],
        ),
        // Updates a second large table.
        (
            "TR_FANOUT",
            trigger("AFTER STATEMENT", "STATEMENT", false, &[]),
            vec![RoutineEffect::Dml],
        ),
        (
            "TR_COMPOUND",
            trigger("COMPOUND", "COMPOUND", true, &[]),
            vec![RoutineEffect::ReadDb],
        ),
        (
            "TR_STATUS_ONLY",
            trigger("BEFORE EACH ROW", "ROW", false, &["STATUS"]),
            vec![],
        ),
    ] {
        let fact = fact(MutationStatementKind::Update, name, mechanism, &effects);
        assert_eq!(
            admit_update(vec![fact]),
            Err(GrantAdmissionRefusal::UserDmlTrigger {
                trigger: format!("OMCP_FX_GA.{name}")
            }),
            "{name}"
        );
    }
}

/// The trigger is refused for existing, even when its effects are unproven
/// and the closure is therefore incomplete.
#[test]
fn grant_admission_trigger_with_unproven_effects_is_named() {
    let mut unproven = fact(
        MutationStatementKind::Update,
        "TR_STAMP",
        trigger("BEFORE EACH ROW", "ROW", false, &[]),
        &[RoutineEffect::Unknown],
    );
    unproven.computation = MutationComputation::Unavailable {
        reason: MutationUnavailableReason::EffectProofUnavailable,
    };
    let mut closure = closure(MutationStatementKind::Update, Vec::new());
    closure.mechanisms.push(unproven);
    assert!(!closure.is_complete());
    assert_eq!(
        admit_grant_target(&facts(), &[closure], &update(), &status_column()),
        Err(GrantAdmissionRefusal::UserDmlTrigger {
            trigger: "OMCP_FX_GA.TR_STAMP".into()
        })
    );
}

#[test]
fn grant_admission_disabled_trigger_in_fingerprint() {
    // A disabled trigger is not a mechanism, but it is part of the hashed
    // trigger rows: enabling it later changes the bound fingerprint.
    let before = closure(MutationStatementKind::Update, Vec::new());
    let mut after = before.clone();
    for observation in &mut after.observations {
        if observation.source == MutationCatalogSource::Triggers {
            observation.source_sha256 =
                Some("00000000000000000000000000000000000000000000000000000000000000ff".into());
            observation.row_count = 1;
        }
    }
    let a = admit_grant_target(&facts(), &[before], &update(), &status_column()).unwrap();
    let b = admit_grant_target(&facts(), &[after], &update(), &status_column()).unwrap();
    assert_ne!(a.closure, b.closure);
}

#[test]
fn grant_admission_refuses_on_delete_cascade_and_set_null() {
    for rule in [
        MutationForeignKeyAction::Cascade,
        MutationForeignKeyAction::SetNull,
    ] {
        let fk = fact(
            MutationStatementKind::Update,
            "FK_CHILD",
            MutationMechanism::ForeignKeyAction {
                on_delete: rule,
                child_owner: "OMCP_FX_GA".into(),
                child_table: "CHILD".into(),
                child_columns: BTreeSet::from(["PARENT_ID".into()]),
            },
            &[RoutineEffect::ReadDb, RoutineEffect::Dml],
        );
        // Refused for an UPDATE grant too (tighten-only).
        assert_eq!(
            admit_update(vec![fk]),
            Err(GrantAdmissionRefusal::FkDeleteAction {
                constraint: "OMCP_FX_GA.FK_CHILD".into(),
                rule
            })
        );
    }
}

#[test]
fn grant_admission_refuses_domain_index() {
    let index = fact(
        MutationStatementKind::Update,
        "ORDERS_TEXT",
        MutationMechanism::IndexCallback { domain: true },
        &[RoutineEffect::ReadDb],
    );
    assert_eq!(
        admit_update(vec![index]),
        Err(GrantAdmissionRefusal::DomainIndex {
            index: "OMCP_FX_GA.ORDERS_TEXT".into()
        })
    );
}

#[test]
fn grant_admission_fbi_user_function_requires_clean() {
    let fbi = |effects: &[RoutineEffect]| {
        fact(
            MutationStatementKind::Update,
            "ORDERS_FBI",
            MutationMechanism::FunctionBasedIndex { position: 1 },
            effects,
        )
    };
    assert_eq!(admit_update(vec![fbi(&[])]), Ok(()));
    assert_eq!(admit_update(vec![fbi(&[RoutineEffect::ReadDb])]), Ok(()));
    for effects in [
        vec![RoutineEffect::Dml],
        vec![RoutineEffect::SessionState],
        vec![RoutineEffect::RowLock],
    ] {
        assert_eq!(
            admit_update(vec![fbi(&effects)]),
            Err(GrantAdmissionRefusal::UnprovenCallback {
                mechanism: "expression",
                identity: "OMCP_FX_GA.ORDERS_FBI".into()
            }),
            "{effects:?}"
        );
    }
    let virtual_column = fact(
        MutationStatementKind::Update,
        "TOTAL",
        MutationMechanism::VirtualColumnExpr {
            column: "TOTAL".into(),
        },
        &[RoutineEffect::Dml],
    );
    assert!(matches!(
        admit_update(vec![virtual_column]),
        Err(GrantAdmissionRefusal::UnprovenCallback { .. })
    ));
}

#[test]
fn grant_admission_refuses_fga_handler_autonomous() {
    let handler = fact(
        MutationStatementKind::Update,
        "P_AUDIT",
        MutationMechanism::FgaHandler,
        &[RoutineEffect::Autonomous],
    );
    assert_eq!(
        admit_update(vec![handler]),
        Err(GrantAdmissionRefusal::EffectRefused {
            effect: RoutineEffect::Autonomous
        })
    );
    // Its presence alone refuses, even when the handler proof is unavailable.
    let mut unproven = fact(
        MutationStatementKind::Update,
        "P_AUDIT",
        MutationMechanism::FgaHandler,
        &[RoutineEffect::Unknown],
    );
    unproven.computation = MutationComputation::Unavailable {
        reason: MutationUnavailableReason::EffectProofUnavailable,
    };
    let mut closure = closure(MutationStatementKind::Update, Vec::new());
    closure.mechanisms.push(unproven);
    assert_eq!(
        admit_grant_target(&facts(), &[closure], &update(), &status_column()),
        Err(GrantAdmissionRefusal::EffectRefused {
            effect: RoutineEffect::Autonomous
        })
    );
}

#[test]
fn grant_admission_refuses_vpd_unproven_policy_function() {
    // Any policy that applies to the granted verb refuses, even with a read-only
    // function: a mutation-time predicate changes the row set the pre-count saw.
    for effects in [
        vec![RoutineEffect::Unknown],
        vec![RoutineEffect::ReadDb],
        vec![],
    ] {
        let policy = fact(
            MutationStatementKind::Update,
            "P_TENANT",
            MutationMechanism::VpdPolicy {
                statement_types: BTreeSet::from([MutationStatementKind::Update]),
                check_option: true,
            },
            &effects,
        );
        let mut closure = closure(MutationStatementKind::Update, Vec::new());
        closure.mechanisms.push(policy);
        let result = admit_grant_target(&facts(), &[closure], &update(), &status_column());
        assert!(
            matches!(
                result,
                Err(GrantAdmissionRefusal::UnprovenCallback {
                    mechanism: "vpd_policy",
                    ..
                }) | Err(GrantAdmissionRefusal::ClosureUnknown { .. })
            ),
            "{effects:?}: {result:?}"
        );
    }
    for (mechanism, label) in [
        (MutationMechanism::OlsPolicy, "ols_policy"),
        (MutationMechanism::RasRealm, "ras_realm"),
        (MutationMechanism::RedactionPolicy, "redaction_policy"),
    ] {
        let fact = fact(MutationStatementKind::Update, "SEC", mechanism, &[]);
        assert!(matches!(
            admit_update(vec![fact]),
            Err(GrantAdmissionRefusal::UnprovenCallback { mechanism, .. }) if mechanism == label
        ));
    }
}

#[test]
fn grant_admission_mv_log_included_in_digest() {
    let with_log = closure(
        MutationStatementKind::Update,
        vec![fact(
            MutationStatementKind::Update,
            "MLOG$_ORDERS",
            MutationMechanism::MvLog {
                log_table: "MLOG$_ORDERS".into(),
            },
            &[RoutineEffect::Dml],
        )],
    );
    let without = closure(MutationStatementKind::Update, Vec::new());
    let logged = admit_grant_target(&facts(), &[with_log], &update(), &status_column())
        .expect("internal MV-log maintenance is admitted");
    let plain = admit_grant_target(&facts(), &[without], &update(), &status_column()).unwrap();
    assert_ne!(logged.closure, plain.closure);
    assert_ne!(
        grant(logged.closure).scope_digest(),
        grant(plain.closure).scope_digest()
    );
}

#[test]
fn grant_admission_unknown_source_refuses() {
    for source in MutationCatalogSource::ALL {
        let mut unavailable = closure(MutationStatementKind::Update, Vec::new());
        for observation in &mut unavailable.observations {
            if observation.source == source {
                observation.computation = MutationComputation::Unavailable {
                    reason: MutationUnavailableReason::CatalogUnreadable,
                };
            }
        }
        assert_eq!(
            admit_grant_target(&facts(), &[unavailable], &update(), &status_column()),
            Err(GrantAdmissionRefusal::ClosureUnknown {
                source,
                reason: MutationUnavailableReason::CatalogUnreadable
            }),
            "{source:?}"
        );
        // A missing family is uncertainty too, never absence.
        let mut missing = closure(MutationStatementKind::Update, Vec::new());
        missing
            .observations
            .retain(|observation| observation.source != source);
        assert!(
            matches!(
                admit_grant_target(&facts(), &[missing], &update(), &status_column()),
                Err(GrantAdmissionRefusal::ClosureUnknown { .. })
            ),
            "missing {source:?}"
        );
    }
    // A closure for another target, verb or column set never stands in.
    let mut other_target = closure(MutationStatementKind::Update, Vec::new());
    other_target.root.target.object_id = 1;
    let delete_only = closure(MutationStatementKind::Delete, Vec::new());
    let mut other_columns = closure(MutationStatementKind::Update, Vec::new());
    other_columns.root.columns = MutationColumns::Named(BTreeSet::from(["PRICE".into()]));
    for wrong in [other_target, delete_only, other_columns] {
        assert!(matches!(
            admit_grant_target(&facts(), &[wrong], &update(), &status_column()),
            Err(GrantAdmissionRefusal::ClosureUnknown { .. })
        ));
    }
    assert!(matches!(
        admit_grant_target(&facts(), &[], &update(), &status_column()),
        Err(GrantAdmissionRefusal::ClosureUnknown { .. })
    ));
    assert!(matches!(
        admit_grant_target(
            &facts(),
            &[
                closure(MutationStatementKind::Update, Vec::new()),
                closure(MutationStatementKind::Delete, Vec::new())
            ],
            &update(),
            &status_column()
        ),
        Err(GrantAdmissionRefusal::ClosureUnknown { .. })
    ));
}

#[test]
fn grant_admission_each_forbidden_effect_refuses() {
    for effect in [
        RoutineEffect::Autonomous,
        RoutineEffect::TxnControl,
        RoutineEffect::ExternalIo,
        RoutineEffect::DynamicSql,
        RoutineEffect::SequenceAdvance,
    ] {
        // An MV log fact is the only admitted code-free mechanism that reaches
        // the shared effect rule unconditionally.
        let log = fact(
            MutationStatementKind::Update,
            "MLOG$_ORDERS",
            MutationMechanism::MvLog {
                log_table: "MLOG$_ORDERS".into(),
            },
            &[RoutineEffect::Dml, effect],
        );
        assert_eq!(
            admit_update(vec![log]),
            Err(GrantAdmissionRefusal::EffectRefused { effect }),
            "{effect:?}"
        );
    }
    // Unknown effects make the closure incomplete before any rule runs.
    let unknown = fact(
        MutationStatementKind::Update,
        "MLOG$_ORDERS",
        MutationMechanism::MvLog {
            log_table: "MLOG$_ORDERS".into(),
        },
        &[RoutineEffect::Unknown],
    );
    let mut closure = closure(MutationStatementKind::Update, Vec::new());
    closure.mechanisms.push(unknown);
    assert!(matches!(
        admit_grant_target(&facts(), &[closure], &update(), &status_column()),
        Err(GrantAdmissionRefusal::ClosureUnknown { .. })
    ));
}

#[test]
fn grant_closure_recheck_detects_trigger_added_after_apply() {
    let applied = closure(MutationStatementKind::Update, Vec::new());
    let admitted = admit_grant_target(
        &facts(),
        std::slice::from_ref(&applied),
        &update(),
        &status_column(),
    )
    .unwrap();
    assert_eq!(
        recheck_grant_closure(
            &admitted,
            &facts(),
            std::slice::from_ref(&applied),
            &update(),
            &status_column()
        ),
        Ok(())
    );
    // A trigger enabled after apply refuses the next use.
    let mut triggered = applied.clone();
    triggered.mechanisms.push(fact(
        MutationStatementKind::Update,
        "TR_LATE",
        trigger("BEFORE EACH ROW", "ROW", false, &[]),
        &[],
    ));
    assert_eq!(
        recheck_grant_closure(
            &admitted,
            &facts(),
            &[triggered],
            &update(),
            &status_column()
        ),
        Err(GrantDrift::Refused(GrantAdmissionRefusal::UserDmlTrigger {
            trigger: "OMCP_FX_GA.TR_LATE".into()
        }))
    );
    // A disabled trigger created after apply changes only the hashed trigger
    // rows: still admissible, but drift.
    let mut disabled_added = applied.clone();
    for observation in &mut disabled_added.observations {
        if observation.source == MutationCatalogSource::Triggers {
            observation.source_sha256 =
                Some("00000000000000000000000000000000000000000000000000000000000000ee".into());
            observation.row_count = 1;
        }
    }
    assert!(
        admit_grant_target(
            &facts(),
            &[disabled_added.clone()],
            &update(),
            &status_column()
        )
        .is_ok()
    );
    assert_eq!(
        recheck_grant_closure(
            &admitted,
            &facts(),
            &[disabled_added],
            &update(),
            &status_column()
        ),
        Err(GrantDrift::FingerprintChanged)
    );
    // A recompiled target (new LAST_DDL_TIME) is drift even when admissible.
    let mut recompiled = facts();
    recompiled.target.last_ddl_time = "2026-10-31T11:00:00".into();
    let mut fresh = applied;
    fresh.root.target = recompiled.target.clone();
    for observation in &mut fresh.observations {
        observation.scope.target = recompiled.target.clone();
    }
    fresh.scopes = vec![fresh.root.clone()];
    assert_eq!(
        recheck_grant_closure(
            &admitted,
            &recompiled,
            &[fresh],
            &update(),
            &status_column()
        ),
        Err(GrantDrift::FingerprintChanged)
    );
}
