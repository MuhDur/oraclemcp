use std::collections::BTreeSet;
use std::time::Duration;

use oraclemcp_guard::action_envelope::{
    ActionEnvelopeV1, ActionKind, BindEnvelope, CanonicalBind, ExecLimits, OutputCapture,
};
use oraclemcp_guard::effective_dml_plan::{DmlCallerStatementV1, DmlPlanError, EffectiveDmlPlanV1};
use oraclemcp_guard::impact_binding::ImpactBindingV1;
use oraclemcp_guard::resolver::CatalogGeneration;
use oraclemcp_guard::scoped_grant::{
    ClosureFingerprints, ColumnIdent, EffectiveCeiling, GrantComparison, GrantContainer,
    GrantLimits, GrantOp, GrantOperand, GrantTargetIdentity, GrantValue, LastDdlTime, ScopedGrant,
    ScopedGrantRequest,
};
use oraclemcp_guard::{ExecGrantBinding, OperatingLevel};
use sqlparser::ast::{Expr, SetExpr, Statement};
use sqlparser::dialect::OracleDialect;
use sqlparser::parser::Parser;

fn target() -> GrantTargetIdentity {
    GrantTargetIdentity {
        owner: "APP".into(),
        object_name: "ORDERS".into(),
        object_id: 41,
        data_object_id: Some(42),
        container: GrantContainer {
            con_id: 3,
            con_uid: 20,
        },
        edition: None,
        catalog_generation: CatalogGeneration(7),
        resolved_via: None,
    }
}

fn columns() -> BTreeSet<ColumnIdent> {
    ["ID", "STATUS", "TENANT_ID", "CREATED_AT"]
        .into_iter()
        .map(|name| ColumnIdent::new(name).unwrap())
        .collect()
}

fn grant() -> ScopedGrant {
    let request = ScopedGrantRequest {
        profile: "test-profile".into(),
        binding: ExecGrantBinding::new("session", "lane", "subject", 3),
        verbs: vec!["UPDATE".into(), "DELETE".into()],
        target: target(),
        columns: BTreeSet::from([ColumnIdent::new("STATUS").unwrap()]),
        row_predicate: oraclemcp_guard::scoped_grant::GrantPredicateV1::new(vec![
            GrantComparison {
                column: ColumnIdent::new("ID").unwrap(),
                op: GrantOp::Eq,
                operand: GrantOperand::Single(GrantValue::number("11").unwrap()),
            },
        ]),
        limits: GrantLimits {
            max_rows_per_statement: 5,
            max_statements: 20,
            max_total_rows: 20,
        },
        ttl: Duration::from_secs(600),
        commit_allowed: false,
        closure: ClosureFingerprints::new(),
        last_ddl_time: LastDdlTime::new("2024-01-01T00:00:00").unwrap(),
    };
    ScopedGrant::new(
        request,
        EffectiveCeiling {
            profile_max_level: OperatingLevel::ReadWrite,
            oauth_ceiling: None,
        },
        false,
        &[9; 32],
    )
    .unwrap()
}

fn parse_expr(sql: &str) -> Expr {
    let mut parser = Parser::new(&OracleDialect {}).try_with_sql(sql).unwrap();
    let expression = parser.parse_expr().unwrap();
    parser
        .expect_token(&sqlparser::tokenizer::Token::EOF)
        .unwrap();
    expression
}

fn parse(sql: &str, binds: &[CanonicalBind<'_>]) -> Result<DmlCallerStatementV1, DmlPlanError> {
    DmlCallerStatementV1::parse(
        sql,
        target(),
        "APP",
        &columns(),
        &BindEnvelope::from_binds(&[7; 32], binds),
    )
}

#[test]
fn accepts_closed_update_and_delete_predicates() {
    let update = parse(
        "UPDATE APP.ORDERS SET STATUS = :1 WHERE ID IN (:2, :3) AND TENANT_ID = 8",
        &[
            CanonicalBind::String("ready"),
            CanonicalBind::I64(11),
            CanonicalBind::I64(12),
        ],
    )
    .unwrap();
    assert_eq!(update.assignments().len(), 1);
    assert_eq!(update.predicate().bind_positions().len(), 2);
    parse(
        "DELETE FROM APP.ORDERS WHERE CREATED_AT BETWEEN DATE '2024-01-01' AND DATE '2024-12-31' AND STATUS IS NOT NULL",
        &[],
    )
    .unwrap();
}

#[test]
fn refuses_functions_sequences_subqueries_relations_and_or() {
    for sql in [
        "UPDATE APP.ORDERS SET STATUS = 'x' WHERE USER_FUNC(ID) = 1",
        "UPDATE APP.ORDERS SET STATUS = 'x' WHERE ID = APP.SEQ.NEXTVAL",
        "DELETE FROM APP.ORDERS WHERE EXISTS (SELECT 1 FROM APP.OTHER)",
        "DELETE FROM APP.ORDERS WHERE ID IN (SELECT ID FROM APP.OTHER)",
        "DELETE FROM APP.ORDERS WHERE APP.OTHER.ID = 1",
        "DELETE FROM APP.ORDERS WHERE ID = 1 OR TENANT_ID = 2",
        "DELETE FROM APP.ORDERS WHERE ID = TENANT_ID",
        "DELETE FROM APP.ORDERS WHERE ID = 1 AND 1 = 1",
        "DELETE FROM APP.ORDERS WHERE ID = 1; DELETE FROM APP.ORDERS WHERE ID = 2",
        "UPDATE APP.ORDERS SET STATUS = USER_FUNC('x') WHERE ID = 1",
        "UPDATE APP.ORDERS SET STATUS = (SELECT 'x' FROM APP.OTHER) WHERE ID = 1",
        "UPDATE APP.ORDERS SET STATUS = 'x' WHERE ID = 1 RETURNING STATUS INTO :1",
        "UPDATE APP.ORDERS SET STATUS = 'x' WHERE ID = 1 FROM APP.OTHER",
    ] {
        assert!(parse(sql, &[]).is_err(), "admitted: {sql}");
    }
}

#[test]
fn bind_positions_must_match_envelope_exactly() {
    for (sql, binds) in [
        ("DELETE FROM APP.ORDERS WHERE ID = :1", vec![]),
        (
            "DELETE FROM APP.ORDERS WHERE ID = :2",
            vec![CanonicalBind::I64(1), CanonicalBind::I64(2)],
        ),
        (
            "DELETE FROM APP.ORDERS WHERE ID = :1",
            vec![CanonicalBind::I64(1), CanonicalBind::I64(2)],
        ),
        (
            "UPDATE APP.ORDERS SET STATUS = :1 WHERE ID = :1",
            vec![CanonicalBind::String("x")],
        ),
    ] {
        assert!(parse(sql, &binds).is_err(), "admitted: {sql}");
    }
    assert!(
        parse(
            "DELETE FROM APP.ORDERS WHERE ID = :1",
            &[CanonicalBind::Bool(true)]
        )
        .is_err()
    );
}

#[test]
fn target_must_be_the_catalog_resolved_local_table() {
    for sql in [
        "DELETE FROM OTHER.ORDERS WHERE ID = 1",
        "DELETE FROM APP.OTHER WHERE ID = 1",
        "DELETE FROM APP.ORDERS@LINK WHERE ID = 1",
        "DELETE FROM APP.ORDERS O WHERE ID = 1",
        "DELETE FROM APP.ORDERS WHERE UNKNOWN_COLUMN = 1",
    ] {
        assert!(parse(sql, &[]).is_err(), "admitted: {sql}");
    }
}

#[test]
fn predicate_bounds_refuse_oversized_in_list_and_boolean_widening() {
    let list = (0..=1000).map(|_| "1").collect::<Vec<_>>().join(", ");
    let sql = format!("DELETE FROM APP.ORDERS WHERE ID IN ({list})");
    assert_eq!(
        parse(&sql, &[]).unwrap_err(),
        DmlPlanError::UnsupportedPredicate
    );
    for sql in [
        "DELETE FROM APP.ORDERS WHERE ID NOT IN (1, 2)",
        "DELETE FROM APP.ORDERS WHERE ID NOT BETWEEN 1 AND 2",
        "DELETE FROM APP.ORDERS WHERE NOT (ID = 1)",
    ] {
        assert!(parse(sql, &[]).is_err(), "admitted: {sql}");
    }
}

fn plan_with(
    rules: Vec<String>,
    schema_digest: [u8; 32],
    ruleset_digest: [u8; 32],
    policy_where: &str,
    row_cap: u64,
) -> EffectiveDmlPlanV1 {
    let sql = "DELETE FROM APP.ORDERS WHERE ID = :1";
    let binds = BindEnvelope::from_binds(&[7; 32], &[CanonicalBind::I64(11)]);
    let caller = DmlCallerStatementV1::parse(sql, target(), "APP", &columns(), &binds).unwrap();
    let envelope = ActionEnvelopeV1 {
        version: 1,
        action_kind: ActionKind::ExecuteDml,
        statement_digest: ActionEnvelopeV1::statement_digest(sql),
        binds,
        commit: false,
        hold: false,
        output: OutputCapture {
            capture_dbms_output: false,
            max_lines: 0,
            max_chars: 0,
        },
        limits: ExecLimits {
            timeout_seconds: Some(5),
        },
        scoped_grant_ref: Some([4; 32]),
    };
    let grant = grant();
    EffectiveDmlPlanV1::from_verified_rewrite(
        caller,
        &envelope,
        schema_digest,
        ruleset_digest,
        rules,
        [9; 32],
        Some(parse_expr(policy_where)),
        &grant,
        row_cap,
    )
    .unwrap()
}

#[test]
fn plan_and_impact_bind_policy_identity_order_and_final_template() {
    let base = plan_with(
        vec!["P1".into(), "P2".into()],
        [1; 32],
        [2; 32],
        "TENANT_ID = 3",
        5,
    );
    let mut binding = ImpactBindingV1::default();
    assert!(!binding.decisive.matches_effective_plan(&base));
    binding.decisive.bind_effective_plan(&base);
    let debug = format!("{base:?}");
    assert!(!debug.contains("APP"));
    assert!(!debug.contains("ORDERS"));
    assert!(!debug.contains("P1"));
    assert!(!debug.contains("P2"));
    assert!(binding.decisive.matches_effective_plan(&base));
    let base_digest = binding.decisive_digest().unwrap();
    for changed in [
        plan_with(vec!["P1".into()], [1; 32], [2; 32], "TENANT_ID = 3", 5),
        plan_with(
            vec!["P2".into(), "P1".into()],
            [1; 32],
            [2; 32],
            "TENANT_ID = 3",
            5,
        ),
        plan_with(
            vec!["P1".into(), "P3".into()],
            [1; 32],
            [2; 32],
            "TENANT_ID = 3",
            5,
        ),
        plan_with(
            vec!["P1".into(), "P2".into()],
            [3; 32],
            [2; 32],
            "TENANT_ID = 3",
            5,
        ),
        plan_with(
            vec!["P1".into(), "P2".into()],
            [1; 32],
            [3; 32],
            "TENANT_ID = 3",
            5,
        ),
        plan_with(
            vec!["P1".into(), "P2".into()],
            [1; 32],
            [2; 32],
            "TENANT_ID = 4",
            5,
        ),
        plan_with(
            vec!["P1".into(), "P2".into()],
            [1; 32],
            [2; 32],
            "TENANT_ID = 3",
            4,
        ),
    ] {
        assert_ne!(base.digest(), changed.digest());
        assert!(!binding.decisive.matches_effective_plan(&changed));
        let mut rebound = binding.clone();
        rebound.decisive.bind_effective_plan(&changed);
        assert_ne!(base_digest, rebound.decisive_digest().unwrap());
    }
}

#[test]
fn impact_count_query_reuses_exact_effective_plan_predicate_and_binds() {
    let plan = plan_with(
        vec!["tenant-floor".into()],
        [1; 32],
        [2; 32],
        "TENANT_ID = 3",
        5,
    );
    let execution_statements = Parser::parse_sql(&OracleDialect {}, plan.effective_sql()).unwrap();
    assert_eq!(execution_statements.len(), 1);
    let Statement::Delete(execution) = &execution_statements[0] else {
        panic!("effective plan must render one DELETE");
    };
    let impact_statements = Parser::parse_sql(&OracleDialect {}, plan.impact_count_sql()).unwrap();
    assert_eq!(impact_statements.len(), 1);
    let Statement::Query(impact) = &impact_statements[0] else {
        panic!("impact plan must render one SELECT");
    };
    let SetExpr::Select(impact_select) = impact.body.as_ref() else {
        panic!("impact query must have one SELECT body");
    };
    assert_eq!(
        execution.selection.as_ref(),
        impact_select.selection.as_ref()
    );
    assert_eq!(
        execution.selection.as_ref(),
        Some(plan.effective_selection())
    );
    assert!(plan.effective_sql().contains(":omcp_g1"));
    assert!(plan.impact_count_sql().contains(":omcp_g1"));
    assert!(!plan.effective_sql().contains("11"));
    assert!(!plan.impact_count_sql().contains("11"));
    assert_eq!(plan.grant_binds().len(), 1);
    assert_eq!(plan.grant_binds()[0].name(), "omcp_g1");
}

#[test]
fn effective_plan_rejects_widening_policy_predicate_and_excess_grant_cap() {
    let sql = "DELETE FROM APP.ORDERS WHERE ID = :1";
    let binds = BindEnvelope::from_binds(&[7; 32], &[CanonicalBind::I64(11)]);
    let caller = DmlCallerStatementV1::parse(sql, target(), "APP", &columns(), &binds).unwrap();
    let grant = grant();
    let envelope = ActionEnvelopeV1 {
        version: 1,
        action_kind: ActionKind::ExecuteDml,
        statement_digest: ActionEnvelopeV1::statement_digest(sql),
        binds,
        commit: false,
        hold: false,
        output: OutputCapture {
            capture_dbms_output: false,
            max_lines: 0,
            max_chars: 0,
        },
        limits: ExecLimits {
            timeout_seconds: Some(5),
        },
        scoped_grant_ref: Some([4; 32]),
    };
    assert_eq!(
        EffectiveDmlPlanV1::from_verified_rewrite(
            caller.clone(),
            &envelope,
            [1; 32],
            [2; 32],
            vec!["P1".into()],
            [3; 32],
            Some(parse_expr("TENANT_ID = 3 OR ID = 2")),
            &grant,
            5,
        )
        .unwrap_err(),
        DmlPlanError::PolicyPredicateInvalid
    );
    assert_eq!(
        EffectiveDmlPlanV1::from_verified_rewrite(
            caller,
            &envelope,
            [1; 32],
            [2; 32],
            vec!["P1".into()],
            [3; 32],
            Some(parse_expr("TENANT_ID = 3")),
            &grant,
            6,
        )
        .unwrap_err(),
        DmlPlanError::GrantMismatch
    );
}

#[test]
fn plan_refuses_mismatched_original_envelope() {
    let sql = "DELETE FROM APP.ORDERS WHERE ID = :1";
    let binds = BindEnvelope::from_binds(&[7; 32], &[CanonicalBind::I64(11)]);
    let caller = DmlCallerStatementV1::parse(sql, target(), "APP", &columns(), &binds).unwrap();
    let grant = grant();
    let mut envelope = ActionEnvelopeV1 {
        version: 1,
        action_kind: ActionKind::ExecuteDml,
        statement_digest: ActionEnvelopeV1::statement_digest(sql),
        binds,
        commit: false,
        hold: false,
        output: OutputCapture {
            capture_dbms_output: false,
            max_lines: 0,
            max_chars: 0,
        },
        limits: ExecLimits {
            timeout_seconds: None,
        },
        scoped_grant_ref: None,
    };
    envelope.statement_digest = [8; 32];
    assert_eq!(
        EffectiveDmlPlanV1::from_verified_rewrite(
            caller.clone(),
            &envelope,
            [1; 32],
            [2; 32],
            vec![],
            [3; 32],
            Some(parse_expr("TENANT_ID = 3")),
            &grant,
            1,
        )
        .unwrap_err(),
        DmlPlanError::InvalidEffectivePlan
    );
    envelope.statement_digest = ActionEnvelopeV1::statement_digest(sql);
    envelope.binds.value_hmac = [8; 32];
    assert_eq!(
        EffectiveDmlPlanV1::from_verified_rewrite(
            caller,
            &envelope,
            [1; 32],
            [2; 32],
            vec![],
            [3; 32],
            Some(parse_expr("TENANT_ID = 3")),
            &grant,
            1,
        )
        .unwrap_err(),
        DmlPlanError::InvalidEffectivePlan
    );
}
