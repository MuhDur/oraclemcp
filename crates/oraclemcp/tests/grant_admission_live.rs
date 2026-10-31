//! Grant admission over closures the real collector gathers from FREE 23ai
//! (T13.2a, pvlqq.15.3). Every case builds its own synthetic schema, collects
//! with the served engine binding, decides admission, then drops the schema.
#![cfg(feature = "plsql-intelligence")]

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use asupersync::{Cx, runtime::RuntimeBuilder};
use oraclemcp::mutation_closure::EngineMutationEffects;
use oraclemcp_db::mutation_closure::{
    MutationRequest, collect_mutation_effect_closure, read_grant_target_facts,
};
use oraclemcp_db::{OracleConnectOptions, OracleConnection, RustOracleConnection};
use oraclemcp_guard::mutation_closure::{
    MutationColumns, MutationEffectClosureV1, MutationForeignKeyAction, MutationStatementKind,
};
use oraclemcp_guard::scoped_grant::admission::{
    AdmittedGrantTarget, GrantAdmissionRefusal, admit_grant_target,
};
use oraclemcp_guard::{
    CatalogObjectKind, ColumnIdent, GrantVerbs, ResolvedIdentity, ResolvedObject,
};

async fn ddl(cx: &Cx, conn: &RustOracleConnection, sql: &str) {
    conn.execute(cx, sql, &[]).await.unwrap_or_else(|error| {
        let operation = sql
            .split_ascii_whitespace()
            .take(4)
            .collect::<Vec<_>>()
            .join(" ");
        panic!("synthetic fixture {operation}: {error}")
    });
}

/// SYS-owned catalog views the collector reads, granted through thin SYSDBA
/// exactly like the mutation fixture (the native driver has no SYSDBA mode).
fn catalog_grants(schema: &str) {
    let status = std::process::Command::new("python3")
        .args([
            "-c",
            r#"
import os, re, oracledb
schema = os.environ['ORACLEMCP_MUTATION_SCHEMA']
assert re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', schema)
dsn = os.environ['ORACLEMCP_TEST_DSN']
assert dsn.startswith('localhost:1523/')
with oracledb.connect(user='sys', password=os.environ['ORACLEMCP_TEST_PASSWORD'],
                      dsn=dsn, mode=oracledb.AUTH_MODE_SYSDBA,
                      tcp_connect_timeout=10, retry_count=0) as conn:
    conn.call_timeout = 10000
    cursor = conn.cursor()
    for view in ['V_$OPTION', 'DBA_CONSTRAINTS', 'DBA_CONS_COLUMNS',
                 'ALL_AUDIT_POLICIES', 'ALL_XS_APPLIED_POLICIES', 'REDACTION_POLICIES']:
        cursor.execute(f'GRANT SELECT ON SYS.{view} TO {schema}')
"#,
        ])
        .env("ORACLEMCP_MUTATION_SCHEMA", schema)
        .status()
        .expect("Python thin SYSDBA catalog setup");
    assert!(status.success(), "SYS-owned catalog setup failed");
}

struct Outcome {
    decision: Result<AdmittedGrantTarget, GrantAdmissionRefusal>,
    closures: Vec<MutationEffectClosureV1>,
    canary_rows: Option<i64>,
}

/// Build one synthetic schema, run `setup` as its owner's DDL, collect real
/// UPDATE(STATUS) and DELETE closures of `T`, and decide the grant.
fn run_case(case: &str, setup: &[&str], canary: bool) -> Outcome {
    let options = OracleConnectOptions {
        connect_string: std::env::var("ORACLEMCP_TEST_DSN").expect("FREE23 DSN"),
        username: Some(std::env::var("ORACLEMCP_TEST_USER").expect("lab admin user")),
        password: Some(std::env::var("ORACLEMCP_TEST_PASSWORD").expect("lab admin password")),
        call_timeout: Some(Duration::from_secs(20)),
        ..Default::default()
    };
    assert!(
        options.connect_string.starts_with("localhost:1523/"),
        "fixture is confined to the local FREE23 lane"
    );
    let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .unwrap();
    let case = case.to_owned();
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        let admin = RustOracleConnection::connect(&cx, options.clone()).await.expect("FREE23 admin connects");
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros();
        let schema = format!("OMCP_FX_GA_{nonce:X}");
        let password = format!("Grant{nonce:X}A");
        ddl(&cx, &admin, &format!("CREATE USER {schema} IDENTIFIED BY \"{password}\" DEFAULT TABLESPACE USERS QUOTA 8M ON USERS")).await;
        let outcome = async {
            ddl(&cx, &admin, &format!("GRANT CREATE SESSION, CREATE TABLE, CREATE TRIGGER, CREATE PROCEDURE TO {schema}")).await;
            catalog_grants(&schema);
            ddl(&cx, &admin, &format!("CREATE TABLE {schema}.T (ID NUMBER CONSTRAINT PK_T PRIMARY KEY, STATUS VARCHAR2(10), UPDATED_AT DATE)")).await;
            if canary {
                ddl(&cx, &admin, &format!("CREATE TABLE {schema}.CANARY (ID NUMBER)")).await;
            }
            for sql in setup {
                ddl(&cx, &admin, &sql.replace("{schema}", &schema)).await;
            }
            let mut reader_options = options.clone();
            reader_options.username = Some(schema.clone());
            reader_options.password = Some(password.clone());
            let reader = RustOracleConnection::connect(&cx, reader_options).await.expect("fixture owner connects");
            let facts = read_grant_target_facts(&cx, &reader, &schema, "T").await.expect("grant target facts");
            let request = |kind, columns| MutationRequest {
                target: ResolvedObject {
                    owner: schema.clone(),
                    name: "T".into(),
                    kind: CatalogObjectKind::Table,
                    container: None,
                    member: None,
                    overloads: Vec::new(),
                    quote_exact: true,
                    synonym_chain: Vec::new(),
                    db_link: None,
                    identity: ResolvedIdentity {
                        object_id: facts.target.object_id,
                        edition: facts.target.object_edition.clone(),
                    },
                },
                statement_kind: kind,
                columns,
            };
            let closures = vec![
                collect_mutation_effect_closure(&cx, &reader,
                    request(MutationStatementKind::Update, MutationColumns::Named(BTreeSet::from(["STATUS".into()]))),
                    &EngineMutationEffects).await,
                collect_mutation_effect_closure(&cx, &reader,
                    request(MutationStatementKind::Delete, MutationColumns::All), &EngineMutationEffects).await,
            ];
            let decision = admit_grant_target(
                &facts,
                &closures,
                &GrantVerbs::parse(&["UPDATE", "DELETE"]).unwrap(),
                &BTreeSet::from([ColumnIdent::new("STATUS").unwrap()]),
            );
            let canary_rows = if canary {
                let rows = admin.query_rows(&cx, &format!("SELECT COUNT(*) AS N FROM {schema}.CANARY"), &[]).await.unwrap();
                rows[0].parse_i64("N")
            } else {
                None
            };
            reader.close(&cx).await.unwrap();
            Outcome { decision, closures, canary_rows }
        }
        .await;
        ddl(&cx, &admin, &format!("DROP USER {schema} CASCADE")).await;
        admin.close(&cx).await.unwrap();
        eprintln!("{}", serde_json::json!({
            "case": case,
            "decision": format!("{:?}", outcome.decision),
            "closures_complete": outcome.closures.iter().map(MutationEffectClosureV1::is_complete).collect::<Vec<_>>(),
            "canary_rows": outcome.canary_rows,
        }));
        outcome
    })
}

#[test]
#[ignore = "requires an administrative connection to the local FREE23 lab"]
fn grant_admission_live_heap_table_admitted() {
    let outcome = run_case("grant_admission_live_heap_table_admitted", &[], false);
    assert!(
        outcome
            .closures
            .iter()
            .all(MutationEffectClosureV1::is_complete),
        "{:?}",
        outcome.closures
    );
    let admitted = outcome.decision.expect("a plain heap table is admitted");
    // Target facts plus one closure fingerprint per granted verb.
    assert_eq!(admitted.closure.iter().count(), 3);
}

#[test]
#[ignore = "requires an administrative connection to the local FREE23 lab"]
fn grant_admission_live_autonomous_trigger_refused() {
    let outcome = run_case(
        "grant_admission_live_autonomous_trigger_refused",
        &[
            "CREATE OR REPLACE TRIGGER {schema}.TR_AUTO AFTER UPDATE ON {schema}.T FOR EACH ROW DECLARE PRAGMA AUTONOMOUS_TRANSACTION; BEGIN INSERT INTO {schema}.CANARY (ID) VALUES (1); COMMIT; END;",
        ],
        true,
    );
    assert!(
        matches!(&outcome.decision, Err(GrantAdmissionRefusal::UserDmlTrigger { trigger }) if trigger.ends_with(".TR_AUTO")),
        "{:?}",
        outcome.decision
    );
    assert_eq!(
        outcome.canary_rows,
        Some(0),
        "admission must never run the trigger"
    );
}

#[test]
#[ignore = "requires an administrative connection to the local FREE23 lab"]
fn grant_admission_live_before_update_trigger_refused() {
    // Purely transactional: it only stamps :NEW.UPDATED_AT.
    let outcome = run_case(
        "grant_admission_live_before_update_trigger_refused",
        &[
            "CREATE OR REPLACE TRIGGER {schema}.TR_TOUCH BEFORE UPDATE ON {schema}.T FOR EACH ROW BEGIN :NEW.UPDATED_AT := SYSDATE; END;",
        ],
        false,
    );
    assert!(
        matches!(&outcome.decision, Err(GrantAdmissionRefusal::UserDmlTrigger { trigger }) if trigger.ends_with(".TR_TOUCH")),
        "{:?}",
        outcome.decision
    );
}

#[test]
#[ignore = "requires an administrative connection to the local FREE23 lab"]
fn grant_admission_live_cascade_fk_refused() {
    let outcome = run_case(
        "grant_admission_live_cascade_fk_refused",
        &[
            "CREATE TABLE {schema}.CHILD (ID NUMBER, T_ID NUMBER CONSTRAINT FK_CHILD_T REFERENCES {schema}.T(ID) ON DELETE CASCADE)",
        ],
        false,
    );
    assert!(
        matches!(
            &outcome.decision,
            Err(GrantAdmissionRefusal::FkDeleteAction { constraint, rule: MutationForeignKeyAction::Cascade })
                if constraint.ends_with(".FK_CHILD_T")
        ),
        "{:?}",
        outcome.decision
    );
}
