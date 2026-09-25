#![cfg(feature = "live-xe")]
#![forbid(unsafe_code)]

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

fn grant(
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

fn resolved(identity: GrantTargetIdentity) -> ResolvedDmlTarget {
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
        bind_types: BTreeMap::new(),
    }
}

fn bind_values(rewrite: &oraclemcp_guard::scoped_grant::GrantRewriteV1) -> Vec<OracleBind> {
    rewrite
        .binds()
        .iter()
        .map(|bind| OracleBind::I64(bind.value().expose_canonical().parse().unwrap()))
        .collect()
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
        let grant = grant(id.clone(), "UPDATE", "ID", "1");
        let matched = match_sql(
            &grant,
            &format!("UPDATE {qualified} SET STATUS = 'new' WHERE ID IN (1, 2)"),
            &resolved(id.clone()),
        )
        .unwrap();
        let policy = sqlparser::ast::Expr::BinaryOp {
            left: Box::new(sqlparser::ast::Expr::Identifier(
                sqlparser::ast::Ident::new("TENANT_ID"),
            )),
            op: sqlparser::ast::BinaryOperator::Eq,
            right: Box::new(sqlparser::ast::Expr::Value(
                sqlparser::ast::Value::Number("7".into(), false).into(),
            )),
        };
        let rewrite =
            render_grant_update(&matched, grant.row_predicate(), Some(&policy), 5).unwrap();
        conn.execute(&cx, rewrite.executable_sql(), &bind_values(&rewrite))
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
        let grant = grant(id.clone(), "DELETE", "ID", "1");
        let matched = match_sql(
            &grant,
            &format!("DELETE FROM {qualified} WHERE ID IN (1, 2, 3)"),
            &resolved(id.clone()),
        )
        .unwrap();
        let policy = sqlparser::ast::Expr::BinaryOp {
            left: Box::new(sqlparser::ast::Expr::Identifier(
                sqlparser::ast::Ident::new("TENANT_ID"),
            )),
            op: sqlparser::ast::BinaryOperator::Eq,
            right: Box::new(sqlparser::ast::Expr::Value(
                sqlparser::ast::Value::Number("7".into(), false).into(),
            )),
        };
        let rewrite =
            render_grant_delete(&matched, grant.row_predicate(), Some(&policy), 5).unwrap();
        let affected = conn
            .execute(&cx, rewrite.executable_sql(), &bind_values(&rewrite))
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
        let _ = conn
            .execute(
                &cx,
                &format!("DROP TABLE {qualified} PURGE"),
                &[] as &[OracleBind],
            )
            .await;
    });
}
