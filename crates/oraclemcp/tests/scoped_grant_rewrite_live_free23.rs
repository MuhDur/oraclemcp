#![cfg(feature = "live-xe")]
#![forbid(unsafe_code)]

use oraclemcp_guard::action_envelope::{
    ActionEnvelopeV1, ActionKind, BindEnvelope, CanonicalBind, ExecLimits, OutputCapture,
};
use oraclemcp_guard::effective_dml_plan::{DmlCallerStatementV1, EffectiveDmlPlanV1};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use oraclemcp_db::{OracleBind, OracleConnectOptions, OracleConnection, RustOracleConnection};
use oraclemcp_guard::resolver::{
    CatalogGeneration, CatalogObjectKind, RawName, RawNamePart, SyntacticRole,
};
use oraclemcp_guard::scoped_grant::matcher::{ResolvedDmlTarget, match_sql};
use oraclemcp_guard::scoped_grant::rewrite::{render_grant_delete, render_grant_update};
use oraclemcp_guard::{
    ClosureFingerprints, ColumnIdent, EffectiveCeiling, ExecGrantBinding, GrantComparison,
    GrantContainer, GrantLimits, GrantOp, GrantOperand, GrantPredicateV1, GrantTargetIdentity,
    GrantValue, LastDdlTime, OperatingLevel, ScopedGrant, ScopedGrantRequest,
};

fn run<F, Fut>(body: F)
where
    F: FnOnce(Cx) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("runtime");
    runtime.block_on(async move {
        body(Cx::current().expect("current Cx")).await;
    });
}

fn options() -> OracleConnectOptions {
    OracleConnectOptions {
        connect_string: std::env::var("ORACLE_MATRIX_FREE23_DSN")
            .or_else(|_| std::env::var("ORACLEMCP_TEST_DSN"))
            .unwrap_or_else(|_| "localhost:1522/FREEPDB1".into()),
        username: Some(
            std::env::var("ORACLE_MATRIX_FREE23_USER")
                .or_else(|_| std::env::var("ORACLEMCP_TEST_USER"))
                .unwrap_or_else(|_| "system".into()),
        ),
        password: Some(
            std::env::var("ORACLE_MATRIX_FREE23_PASSWORD")
                .or_else(|_| std::env::var("ORACLEMCP_TEST_PASSWORD"))
                .unwrap_or_else(|_| "test_password".into()),
        ),
        call_timeout: Some(Duration::from_secs(20)),
        ..Default::default()
    }
}

async fn connect(cx: &Cx, name: &str) -> Option<RustOracleConnection> {
    if std::env::var("ORACLEMCP_LIVE_XE").as_deref() != Ok("1") {
        eprintln!("[live-free23] SKIP {name}: set ORACLEMCP_LIVE_XE=1 and FREE23 credentials");
        return None;
    }
    match RustOracleConnection::connect(cx, options()).await {
        Ok(conn) => Some(conn),
        Err(error) => panic!("live FREE23 connection failed: {error}"),
    }
}

async fn free23(conn: &RustOracleConnection, cx: &Cx) {
    let rows = conn
        .query_rows(
            cx,
            "SELECT version_full AS db_version FROM product_component_version WHERE ROWNUM = 1",
            &[] as &[OracleBind],
        )
        .await
        .expect("read database release");
    let version = rows
        .first()
        .and_then(|row| row.text("DB_VERSION"))
        .unwrap_or("");
    assert!(
        version.starts_with("23."),
        "expected FREE 23ai, got {version}"
    );
}

fn target(owner: &str, table: &str) -> GrantTargetIdentity {
    GrantTargetIdentity {
        owner: owner.to_owned(),
        object_name: table.to_owned(),
        object_id: 777,
        data_object_id: Some(777),
        container: GrantContainer {
            con_id: 3,
            con_uid: 9001,
        },
        edition: None,
        catalog_generation: CatalogGeneration(1),
        resolved_via: None,
    }
}

fn make_grant(
    target: GrantTargetIdentity,
    verb: &str,
    predicate_column: &str,
    predicate_value: &str,
) -> ScopedGrant {
    let columns = if verb == "UPDATE" {
        BTreeSet::from([ColumnIdent::new("STATUS").unwrap()])
    } else {
        BTreeSet::new()
    };
    ScopedGrant::new(
        ScopedGrantRequest {
            profile: "live-free23".into(),
            binding: ExecGrantBinding::new("session", "lane", "subject", 1),
            verbs: vec![verb.into()],
            target,
            columns,
            row_predicate: GrantPredicateV1::new(vec![GrantComparison {
                column: ColumnIdent::new(predicate_column).unwrap(),
                op: GrantOp::Eq,
                operand: GrantOperand::Single(GrantValue::number(predicate_value).unwrap()),
            }]),
            limits: GrantLimits {
                max_rows_per_statement: 5,
                max_statements: 3,
                max_total_rows: 5,
            },
            ttl: Duration::from_secs(60),
            commit_allowed: false,
            closure: ClosureFingerprints::new(),
            last_ddl_time: LastDdlTime::new("2026-09-01T00:00:00").unwrap(),
        },
        EffectiveCeiling {
            profile_max_level: OperatingLevel::ReadWrite,
            oauth_ceiling: None,
        },
        false,
        &[7; 32],
    )
    .unwrap()
}

async fn resolved(
    cx: &Cx,
    conn: &RustOracleConnection,
    identity: GrantTargetIdentity,
) -> ResolvedDmlTarget {
    let columns = conn.query_rows(cx,
        "SELECT column_name FROM SYS.all_tab_columns WHERE owner=:1 AND table_name=:2 ORDER BY column_id",
        &[OracleBind::from(identity.owner.clone()), OracleBind::from(identity.object_name.clone())])
        .await.expect("actual target columns").iter().map(|row|
            ColumnIdent::new(row.text("COLUMN_NAME").expect("native column name")).unwrap()).collect();
    ResolvedDmlTarget {
        raw_name: RawName::new(
            [
                RawNamePart::unquoted(&identity.owner),
                RawNamePart::unquoted(&identity.object_name),
            ],
            SyntacticRole::FromFactor,
        ),
        identity,
        object_kind: CatalogObjectKind::Table,
        columns,
        bind_types: BTreeMap::new(),
    }
}

fn build_plan(
    sql: &str,
    grant: &ScopedGrant,
    columns: &BTreeSet<ColumnIdent>,
    policy: sqlparser::ast::Expr,
    cap: u64,
    values: &[CanonicalBind<'_>],
) -> EffectiveDmlPlanV1 {
    let binds = BindEnvelope::from_binds(&[7; 32], values);
    let caller = DmlCallerStatementV1::parse(
        sql,
        grant.target().clone(),
        &grant.target().owner,
        columns,
        &binds,
    )
    .unwrap();
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
        vec!["synthetic-tenant".into()],
        [3; 32],
        Some(policy),
        grant,
        cap,
    )
    .unwrap()
}

fn bind_values(rewrite: &oraclemcp_guard::scoped_grant::GrantRewriteV1) -> Vec<OracleBind> {
    rewrite
        .binds()
        .iter()
        .map(|bind| OracleBind::I64(bind.value().expose_canonical().parse().unwrap()))
        .collect()
}

fn plan_bind_values(
    plan: &EffectiveDmlPlanV1,
    callers: &[OracleBind],
    count: bool,
) -> Vec<OracleBind> {
    use oraclemcp_guard::effective_dml_plan::DmlPlanBindV1;
    let grants = bind_values(plan.rewrite());
    let layout = if count {
        plan.impact_bind_layout()
    } else {
        plan.execution_bind_layout()
    };
    layout
        .iter()
        .map(|slot| match slot {
            DmlPlanBindV1::Caller { position } => callers[*position - 1].clone(),
            DmlPlanBindV1::Grant { index } => grants[*index].clone(),
        })
        .collect()
}

async fn native_count(
    conn: &RustOracleConnection,
    cx: &Cx,
    sql: &str,
    binds: &[OracleBind],
) -> i64 {
    let rows = conn
        .query_rows(cx, sql, binds)
        .await
        .expect("actual Oracle count");
    assert_eq!(rows.len(), 1);
    rows[0].columns[0]
        .1
        .value
        .as_deref()
        .unwrap()
        .parse()
        .unwrap()
}

async fn create_table(conn: &RustOracleConnection, cx: &Cx, name: &str) {
    let _ = conn
        .execute(
            cx,
            &format!("DROP TABLE {name} PURGE"),
            &[] as &[OracleBind],
        )
        .await;
    conn.execute(cx, &format!("CREATE TABLE {name} (ID NUMBER PRIMARY KEY, TENANT_ID NUMBER NOT NULL, STATUS VARCHAR2(20) NOT NULL)"), &[] as &[OracleBind]).await.expect("create synthetic table");
    conn.execute(
        cx,
        &format!("INSERT INTO {name} VALUES (1, 7, 'old')"),
        &[] as &[OracleBind],
    )
    .await
    .unwrap();
    conn.execute(
        cx,
        &format!("INSERT INTO {name} VALUES (2, 7, 'old')"),
        &[] as &[OracleBind],
    )
    .await
    .unwrap();
    conn.execute(
        cx,
        &format!("INSERT INTO {name} VALUES (3, 8, 'old')"),
        &[] as &[OracleBind],
    )
    .await
    .unwrap();
    conn.commit(cx).await.unwrap();
}

#[test]
fn grant_template_check_option_live_free23() {
    run(|cx| async move {
        let Some(conn) = connect(&cx, "grant_template_check_option_live_free23").await else {
            return;
        };
        free23(&conn, &cx).await;
        let owners = conn
            .query_rows(&cx, "SELECT USER AS OWNER FROM DUAL", &[] as &[OracleBind])
            .await
            .unwrap();
        let owner = owners
            .first()
            .and_then(|row| row.text("OWNER"))
            .expect("current owner")
            .to_owned();
        let table = format!("OMCP_FX_GRWU{}", std::process::id());
        let qualified = format!("{owner}.{table}");
        create_table(&conn, &cx, &qualified).await;
        let id = target(&owner, &table);
        let grant = make_grant(id.clone(), "UPDATE", "ID", "1");
        let sql = format!("UPDATE {qualified} SET STATUS = 'new' WHERE ID IN (1, 2)");
        let resolved = resolved(&cx, &conn, id.clone()).await;
        match_sql(&grant, &sql, &resolved).unwrap();
        let policy = sqlparser::ast::Expr::BinaryOp {
            left: Box::new(sqlparser::ast::Expr::Identifier(
                sqlparser::ast::Ident::new("TENANT_ID"),
            )),
            op: sqlparser::ast::BinaryOperator::Eq,
            right: Box::new(sqlparser::ast::Expr::Value(
                sqlparser::ast::Value::Number("7".into(), false).into(),
            )),
        };
        let plan = build_plan(&sql, &grant, &resolved.columns, policy.clone(), 5, &[]);
        let rewrite = render_grant_update(&plan).unwrap();
        conn.execute(&cx, rewrite.executable_sql(), &bind_values(rewrite))
            .await
            .expect("execute CHECK OPTION update");
        let rows = conn
            .query_rows(
                &cx,
                &format!("SELECT ID, STATUS FROM {qualified} ORDER BY ID"),
                &[] as &[OracleBind],
            )
            .await
            .unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| (
                    row.parse_i64("ID").unwrap(),
                    row.text("STATUS").unwrap().to_owned()
                ))
                .collect::<Vec<_>>(),
            vec![(1, "new".into()), (2, "old".into()), (3, "old".into())]
        );

        conn.execute(
            &cx,
            &format!("UPDATE {qualified} SET STATUS='old'"),
            &[] as &[OracleBind],
        )
        .await
        .unwrap();
        assert_eq!(
            native_count(
                &conn,
                &cx,
                &format!("SELECT COUNT(*) FROM {qualified} WHERE STATUS='old'"),
                &[]
            )
            .await,
            3
        );
        let capped_grant = make_grant(id.clone(), "UPDATE", "TENANT_ID", "7");
        let cap_sql = format!("UPDATE {qualified} SET STATUS=:1 WHERE ID BETWEEN :3 AND :2");
        let cap_plan = build_plan(
            &cap_sql,
            &capped_grant,
            &resolved.columns,
            policy,
            1,
            &[
                CanonicalBind::String("capped"),
                CanonicalBind::I64(3),
                CanonicalBind::I64(1),
            ],
        );
        let caller_values = [
            OracleBind::from("capped"),
            OracleBind::I64(3),
            OracleBind::I64(1),
        ];
        let counted = native_count(
            &conn,
            &cx,
            cap_plan.impact_count_sql(),
            &plan_bind_values(&cap_plan, &caller_values, true),
        )
        .await;
        assert_eq!(counted, 1, "two eligible rows must be capped to one");
        let affected = conn
            .execute(
                &cx,
                render_grant_update(&cap_plan).unwrap().executable_sql(),
                &plan_bind_values(&cap_plan, &caller_values, false),
            )
            .await
            .unwrap();
        assert_eq!(affected, counted as u64);
        assert_eq!(
            native_count(
                &conn,
                &cx,
                &format!("SELECT COUNT(*) FROM {qualified} WHERE STATUS='capped' AND TENANT_ID=7"),
                &[]
            )
            .await,
            1
        );
        assert_eq!(
            native_count(
                &conn,
                &cx,
                &format!("SELECT COUNT(*) FROM {qualified} WHERE ID=3 AND STATUS='old'"),
                &[]
            )
            .await,
            1
        );

        let leaving = format!(
            "UPDATE (SELECT * FROM \"{owner}\".\"{table}\" WHERE \"TENANT_ID\" = 7 WITH CHECK OPTION) SET \"TENANT_ID\" = 8 WHERE \"ID\" = 1"
        );
        let error = conn
            .execute(&cx, &leaving, &[] as &[OracleBind])
            .await
            .expect_err("scope-leaving write must fail");
        assert!(
            error.to_string().contains("ORA-01402"),
            "unexpected Oracle refusal: {error}"
        );
        let _ = conn
            .execute(
                &cx,
                &format!("DROP TABLE {qualified} PURGE"),
                &[] as &[OracleBind],
            )
            .await;
    });
}

#[test]
fn grant_rewrite_live_delete_touches_only_p_rows() {
    run(|cx| async move {
        let Some(conn) = connect(&cx, "grant_rewrite_live_delete_touches_only_p_rows").await else {
            return;
        };
        free23(&conn, &cx).await;
        let owners = conn
            .query_rows(&cx, "SELECT USER AS OWNER FROM DUAL", &[] as &[OracleBind])
            .await
            .unwrap();
        let owner = owners
            .first()
            .and_then(|row| row.text("OWNER"))
            .expect("current owner")
            .to_owned();
        let table = format!("OMCP_FX_GRWD{}", std::process::id());
        let qualified = format!("{owner}.{table}");
        create_table(&conn, &cx, &qualified).await;
        let id = target(&owner, &table);
        let grant = make_grant(id.clone(), "DELETE", "ID", "1");
        let sql = format!("DELETE FROM {qualified} WHERE ID IN (1, 2, 3)");
        let resolved = resolved(&cx, &conn, id.clone()).await;
        match_sql(&grant, &sql, &resolved).unwrap();
        let policy = sqlparser::ast::Expr::BinaryOp {
            left: Box::new(sqlparser::ast::Expr::Identifier(
                sqlparser::ast::Ident::new("TENANT_ID"),
            )),
            op: sqlparser::ast::BinaryOperator::Eq,
            right: Box::new(sqlparser::ast::Expr::Value(
                sqlparser::ast::Value::Number("7".into(), false).into(),
            )),
        };
        let plan = build_plan(&sql, &grant, &resolved.columns, policy.clone(), 5, &[]);
        let rewrite = render_grant_delete(&plan).unwrap();
        let affected = conn
            .execute(&cx, rewrite.executable_sql(), &bind_values(rewrite))
            .await
            .unwrap();
        assert_eq!(affected, 1);
        let rows = conn
            .query_rows(
                &cx,
                &format!("SELECT ID FROM {qualified} ORDER BY ID"),
                &[] as &[OracleBind],
            )
            .await
            .unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| row.parse_i64("ID").unwrap())
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        conn.execute(
            &cx,
            &format!("INSERT INTO {qualified} VALUES (4,7,'old')"),
            &[] as &[OracleBind],
        )
        .await
        .unwrap();
        assert_eq!(
            native_count(
                &conn,
                &cx,
                &format!("SELECT COUNT(*) FROM {qualified} WHERE TENANT_ID=7"),
                &[]
            )
            .await,
            2
        );
        let capped_grant = make_grant(id.clone(), "DELETE", "TENANT_ID", "7");
        let cap_sql = format!("DELETE FROM {qualified} WHERE ID BETWEEN :2 AND :1");
        let cap_plan = build_plan(
            &cap_sql,
            &capped_grant,
            &resolved.columns,
            policy,
            1,
            &[CanonicalBind::I64(4), CanonicalBind::I64(1)],
        );
        let caller_values = [OracleBind::I64(4), OracleBind::I64(1)];
        let counted = native_count(
            &conn,
            &cx,
            cap_plan.impact_count_sql(),
            &plan_bind_values(&cap_plan, &caller_values, true),
        )
        .await;
        assert_eq!(counted, 1);
        let affected = conn
            .execute(
                &cx,
                render_grant_delete(&cap_plan).unwrap().executable_sql(),
                &plan_bind_values(&cap_plan, &caller_values, false),
            )
            .await
            .unwrap();
        assert_eq!(affected, counted as u64);
        assert_eq!(
            native_count(
                &conn,
                &cx,
                &format!("SELECT COUNT(*) FROM {qualified} WHERE TENANT_ID=7"),
                &[]
            )
            .await,
            1
        );
        let _ = conn
            .execute(
                &cx,
                &format!("DROP TABLE {qualified} PURGE"),
                &[] as &[OracleBind],
            )
            .await;
    });
}
