use std::collections::BTreeSet;
use std::time::Duration;

use oraclemcp_guard::action_envelope::{
    ActionEnvelopeV1, ActionKind, BindEnvelope, CanonicalBind, ExecLimits, OutputCapture,
};
use oraclemcp_guard::effective_dml_plan::{
    DML_REWRITE_ALGORITHM_VERSION, DmlCallerStatementV1, DmlPlanBindV1, DmlPlanError,
    EffectiveDmlPlanV1,
};
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
    let sqlparser::ast::FromTable::WithFromKeyword(execution_from) = &execution.from else {
        panic!("local DELETE target")
    };
    assert_eq!(&impact_select.from, execution_from);
    assert!(plan.effective_sql().contains(":omcp_g1"));
    assert!(plan.impact_count_sql().contains(":omcp_g1"));
    assert!(!plan.effective_sql().contains("11"));
    assert!(!plan.impact_count_sql().contains("11"));
    assert_eq!(plan.grant_binds().len(), 1);
    assert_eq!(plan.grant_binds()[0].name(), "omcp_g1");
}

fn bound_plan(sql: &str, values: &[CanonicalBind<'_>], cap: u64) -> EffectiveDmlPlanV1 {
    let binds = BindEnvelope::from_binds(&[7; 32], values);
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
    EffectiveDmlPlanV1::from_verified_rewrite(
        caller,
        &envelope,
        [1; 32],
        [2; 32],
        vec!["tenant".into()],
        [3; 32],
        Some(parse_expr("TENANT_ID = 3")),
        &grant(),
        cap,
    )
    .unwrap()
}

#[test]
fn immutable_update_plan_owns_check_option_cap_and_count_bind_subset() {
    use DmlPlanBindV1::{Caller, Grant};
    let plan = bound_plan(
        "UPDATE APP.ORDERS SET STATUS = :1 WHERE ID = :3 AND TENANT_ID = :2",
        &[
            CanonicalBind::String("ready"),
            CanonicalBind::I64(3),
            CanonicalBind::I64(11),
        ],
        2,
    );
    let rendered = oraclemcp_guard::scoped_grant::render_grant_update(&plan).unwrap();
    assert!(std::ptr::eq(rendered, plan.rewrite()));
    assert_eq!(rendered.executable_sql(), plan.effective_sql());
    assert!(plan.effective_sql().contains("WITH CHECK OPTION"));
    assert!(plan.effective_sql().contains("ROWNUM <= 2"));
    assert!(plan.impact_count_sql().contains("ROWNUM <= 2"));
    assert!(!plan.impact_count_sql().contains("STATUS"));
    assert!(!plan.impact_count_sql().contains(":1"));
    assert_eq!(
        plan.execution_bind_layout(),
        &[
            Grant { index: 0 },
            Caller { position: 1 },
            Caller { position: 3 },
            Caller { position: 2 }
        ]
    );
    assert_eq!(
        plan.impact_bind_layout(),
        &[
            Caller { position: 3 },
            Caller { position: 2 },
            Grant { index: 0 }
        ]
    );
    assert_eq!(DML_REWRITE_ALGORITHM_VERSION, 2);
    let statements = Parser::parse_sql(&OracleDialect {}, plan.impact_count_sql()).unwrap();
    let [Statement::Query(count)] = statements.as_slice() else {
        panic!("count SELECT")
    };
    let SetExpr::Select(count) = count.body.as_ref() else {
        panic!("simple count")
    };
    assert_eq!(count.selection.as_ref(), Some(plan.effective_selection()));
    assert_eq!(
        count.from[0].relation.to_string(),
        plan.rewrite().parts().target().to_string()
    );
}

#[test]
fn delete_plan_preserves_original_caller_positions_in_rendered_order() {
    use DmlPlanBindV1::{Caller, Grant};
    let plan = bound_plan(
        "DELETE FROM APP.ORDERS WHERE ID = :2 AND TENANT_ID = :1",
        &[CanonicalBind::I64(3), CanonicalBind::I64(11)],
        1,
    );
    let rendered = oraclemcp_guard::scoped_grant::render_grant_delete(&plan).unwrap();
    assert!(std::ptr::eq(rendered, plan.rewrite()));
    assert_eq!(
        plan.execution_bind_layout(),
        &[
            Caller { position: 2 },
            Caller { position: 1 },
            Grant { index: 0 }
        ]
    );
    assert_eq!(plan.impact_bind_layout(), plan.execution_bind_layout());
    assert!(plan.impact_count_sql().contains("ROWNUM <= 1"));
}

#[test]
fn bind_looking_literal_text_is_never_added_to_a_physical_bind_layout() {
    use DmlPlanBindV1::{Caller, Grant};
    let plan = bound_plan(
        "UPDATE APP.ORDERS SET STATUS='text:99' WHERE STATUS=':omcp_g1' AND ID=:1",
        &[CanonicalBind::I64(11)],
        1,
    );
    assert_eq!(
        plan.execution_bind_layout(),
        &[Grant { index: 0 }, Caller { position: 1 }]
    );
    assert_eq!(
        plan.impact_bind_layout(),
        &[Caller { position: 1 }, Grant { index: 0 }]
    );
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

fn impact_target() -> oraclemcp_guard::ResolvedObject {
    oraclemcp_guard::ResolvedObject {
        owner: "APP".into(),
        name: "ORDERS".into(),
        kind: oraclemcp_guard::CatalogObjectKind::Table,
        container: None,
        member: None,
        overloads: Vec::new(),
        quote_exact: true,
        synonym_chain: Vec::new(),
        db_link: None,
        identity: oraclemcp_guard::ResolvedIdentity {
            object_id: 41,
            edition: None,
        },
    }
}

fn impact_shape(
    sql: &str,
    resolved: &oraclemcp_guard::ResolvedObject,
) -> Result<
    oraclemcp_guard::effective_dml_plan::CountQueryPlan,
    oraclemcp_guard::effective_dml_plan::UnsupportedDmlShape,
> {
    use oraclemcp_guard::effective_dml_plan::{DmlImpactShapeV1, UnsupportedDmlShape};
    let statements = Parser::parse_sql(&OracleDialect {}, sql).map_err(|_| UnsupportedDmlShape)?;
    let [statement] = statements.as_slice() else {
        return Err(UnsupportedDmlShape);
    };
    DmlImpactShapeV1::prove(statement, resolved)
}

#[test]
fn dml_shape_update_single_table_supported() {
    let plan = impact_shape(
        "UPDATE APP.ORDERS SET STATUS=:1 WHERE ID BETWEEN :2 AND :3",
        &impact_target(),
    )
    .unwrap();
    assert_eq!(
        plan.sql(),
        "SELECT COUNT(*) FROM \"APP\".\"ORDERS\" WHERE ID BETWEEN :2 AND :3"
    );
    assert_eq!(
        plan.binds(),
        &[
            DmlPlanBindV1::Caller { position: 2 },
            DmlPlanBindV1::Caller { position: 3 }
        ]
    );
    assert_eq!(
        plan.positional_sql().unwrap(),
        "SELECT COUNT(*) FROM \"APP\".\"ORDERS\" WHERE ID BETWEEN :1 AND :2"
    );
}

#[test]
fn dml_shape_delete_supported() {
    let plan = impact_shape(
        "DELETE FROM ORDERS WHERE ID BETWEEN 1 AND 10",
        &impact_target(),
    )
    .unwrap();
    assert_eq!(
        plan.sql(),
        "SELECT COUNT(*) FROM \"APP\".\"ORDERS\" WHERE ID BETWEEN 1 AND 10"
    );
    assert!(plan.binds().is_empty());
}

#[test]
fn dml_shape_effective_plan_retains_policy_grant_and_bind_provenance() {
    use oraclemcp_guard::effective_dml_plan::CountQueryPlan;
    let effective = plan_with(
        vec!["tenant-floor".into()],
        [1; 32],
        [2; 32],
        "TENANT_ID = 3",
        5,
    );
    let count = CountQueryPlan::from_effective_plan(&effective);
    assert_eq!(count.sql(), effective.impact_count_sql());
    assert_eq!(count.binds(), effective.impact_bind_layout());
    assert!(count.sql().contains("TENANT_ID = 3"));
    assert!(count.sql().contains(":omcp_g1"));
    assert!(!count.positional_sql().unwrap().contains(":omcp_g1"));
}

macro_rules! unsupported_shape {
    ($name:ident, $sql:expr) => {
        #[test]
        fn $name() {
            assert_eq!(
                impact_shape($sql, &impact_target()).unwrap_err(),
                oraclemcp_guard::effective_dml_plan::UnsupportedDmlShape
            );
        }
    };
}

unsupported_shape!(
    dml_shape_unsupported_inline_view,
    "UPDATE (SELECT * FROM APP.ORDERS) SET STATUS='x' WHERE ID=1"
);
unsupported_shape!(
    dml_shape_unsupported_multi_table_view,
    "DELETE FROM APP.ORDERS, APP.OTHER WHERE ID=1"
);
unsupported_shape!(
    dml_shape_unsupported_partition_extended,
    "UPDATE APP.ORDERS PARTITION (P1) SET STATUS='x' WHERE ID=1"
);
unsupported_shape!(
    dml_shape_unsupported_remote,
    "DELETE FROM APP.ORDERS@REMOTE WHERE ID=1"
);
unsupported_shape!(
    dml_shape_unsupported_current_of,
    "DELETE FROM APP.ORDERS WHERE CURRENT OF cursor1"
);
unsupported_shape!(
    dml_shape_unsupported_table_collection,
    "DELETE FROM TABLE(APP.COLLECTION()) WHERE ID=1"
);
unsupported_shape!(
    dml_shape_unsupported_ambiguous,
    "UPDATE APP.ORDERS o SET STATUS='x' WHERE o.ID=1"
);
unsupported_shape!(
    dml_shape_unsupported_insert,
    "INSERT INTO APP.ORDERS (ID) VALUES (1)"
);
unsupported_shape!(
    dml_shape_unsupported_merge,
    "MERGE INTO APP.ORDERS t USING APP.OTHER s ON (t.ID=s.ID) WHEN MATCHED THEN UPDATE SET STATUS='x'"
);

#[test]
fn dml_shape_unsupported_instead_of_view() {
    let mut target = impact_target();
    target.kind = oraclemcp_guard::CatalogObjectKind::View;
    assert!(impact_shape("UPDATE APP.ORDERS SET STATUS='x' WHERE ID=1", &target).is_err());
}

#[test]
fn dml_shape_requires_the_exact_resolved_target() {
    let mut target = impact_target();
    target.name = "OTHER".into();
    assert!(impact_shape("DELETE FROM APP.ORDERS WHERE ID=1", &target).is_err());
    target = impact_target();
    target.identity.object_id = 0;
    assert!(impact_shape("DELETE FROM APP.ORDERS WHERE ID=1", &target).is_err());
}

#[test]
fn exec_grant_effective_plan_drift_is_non_consuming() {
    use oraclemcp_guard::{ExecGrantError, ExecGrantStore, GrantMaterial};
    let base = plan_with(
        vec!["P1".into(), "P2".into()],
        [1; 32],
        [2; 32],
        "TENANT_ID = 3",
        5,
    );
    let mut impact = ImpactBindingV1::default();
    impact.decisive.bind_effective_plan(&base);
    let approved = GrantMaterial::new("opaque-action-envelope", &impact).unwrap();
    for changed in [
        plan_with(
            vec!["P2".into(), "P1".into()],
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
            [4; 32],
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
        let mut drifted = impact.clone();
        drifted.decisive.bind_effective_plan(&changed);
        let drifted = GrantMaterial::new("opaque-action-envelope", &drifted).unwrap();
        let binding = ExecGrantBinding::new("session", "lane", "subject", 3);
        let grants = ExecGrantStore::new();
        let token = grants.issue(
            approved.clone(),
            binding.clone(),
            OperatingLevel::ReadWrite,
            Duration::from_secs(60),
        );
        assert_eq!(
            grants.consume(&token, &drifted, &binding, OperatingLevel::ReadWrite),
            Err(ExecGrantError::DecisiveMismatch)
        );
        assert_eq!(
            grants.consume(&token, &approved, &binding, OperatingLevel::ReadWrite),
            Ok(OperatingLevel::ReadWrite)
        );
    }
}
