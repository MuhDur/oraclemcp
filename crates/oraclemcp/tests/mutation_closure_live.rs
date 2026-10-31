//! Collector engine binding and native Oracle fixture checks.
#![cfg(feature = "plsql-intelligence")]

fn engine_closure(source: &str, id: &str) -> plsql_engine::InvocationClosureV1 {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("trigger.sql"), source).unwrap();
    let run = plsql_engine::analyze_project(plsql_engine::AnalysisRequest {
        project_root: project.path().to_owned(),
        cache: plsql_engine::CacheConfig {
            enabled: false,
            ..Default::default()
        },
        ..Default::default()
    })
    .unwrap();
    eprintln!(
        "engine posture {:?}, units {:?}",
        run.completeness.posture,
        run.invocation_index.units.keys().collect::<Vec<_>>()
    );
    eprintln!(
        "diagnostic bare closure {:?}",
        run.invocation_index
            .closure(&plsql_engine::InvocationShapeV1 {
                routine_id: id.rsplit('.').next().unwrap().into(),
                ..Default::default()
            })
    );
    run.invocation_index
        .closure(&plsql_engine::InvocationShapeV1 {
            routine_id: id.into(),
            ..Default::default()
        })
}

#[test]
fn mutation_engine_compound_trigger_covers_every_timing_section() {
    let closure = engine_closure(
        "CREATE OR REPLACE TRIGGER APP.TR_COMPOUND FOR INSERT OR UPDATE OR DELETE ON APP.T COMPOUND TRIGGER\nBEFORE STATEMENT IS BEGIN NULL; END BEFORE STATEMENT;\nAFTER EACH ROW IS BEGIN INSERT INTO APP.AUDIT_T (ID) VALUES (1); END AFTER EACH ROW;\nEND;\n",
        "APP.TR_COMPOUND",
    );
    eprintln!("compound closure {closure:?}");
    assert!(
        closure.clean,
        "compound trigger needs complete engine effects"
    );
    assert!(
        closure
            .effects
            .iter()
            .any(|effect| effect == plsql_engine::RoutineEffect::Dml)
    );
}

#[test]
fn mutation_engine_autonomous_trigger_effect_is_preserved() {
    let closure = engine_closure(
        "CREATE OR REPLACE TRIGGER APP.TR_AUTO BEFORE INSERT ON APP.T FOR EACH ROW DECLARE PRAGMA AUTONOMOUS_TRANSACTION; BEGIN NULL; END;\n",
        "APP.TR_AUTO",
    );
    eprintln!("autonomous closure {closure:?}");
    assert!(
        closure
            .effects
            .iter()
            .any(|effect| effect == plsql_engine::RoutineEffect::Autonomous)
    );
}

#[test]
#[ignore = "requires an administrative connection to the local FREE23 lab"]
fn mutation_closure_live_fixture_matches_expected() {
    use asupersync::{Cx, runtime::RuntimeBuilder};
    use oraclemcp::mutation_closure::EngineMutationEffects;
    use oraclemcp_db::mutation_closure::{MutationRequest, collect_mutation_effect_closure};
    use oraclemcp_db::{OracleConnectOptions, OracleConnection, RustOracleConnection};
    use oraclemcp_guard::mutation_closure::*;
    use oraclemcp_guard::{
        CatalogObjectKind, EffectRefusal, OperatingLevel, ResolvedIdentity, ResolvedObject,
        RoutineEffect,
    };
    use std::collections::BTreeSet;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

    fn catalog_grants(schema: &str, granted: bool) {
        // The native driver does not expose SYSDBA authentication. Use the same
        // thin Python SYSDBA setup used by the W4 fixture for SYS-owned grants;
        // collection and engine analysis below stay inside this Rust process.
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
    if os.environ['ORACLEMCP_MUTATION_GRANT'] == '1':
        for view in ['V_$OPTION', 'DBA_CONSTRAINTS', 'DBA_CONS_COLUMNS',
                     'ALL_AUDIT_POLICIES', 'ALL_XS_APPLIED_POLICIES', 'REDACTION_POLICIES']:
            cursor.execute(f'GRANT SELECT ON SYS.{view} TO {schema}')
    else:
        cursor.execute(f'REVOKE SELECT ON SYS.DBA_CONSTRAINTS FROM {schema}')
"#,
            ])
            .env("ORACLEMCP_MUTATION_SCHEMA", schema)
            .env("ORACLEMCP_MUTATION_GRANT", if granted { "1" } else { "0" })
            .status()
            .expect("Python thin SYSDBA catalog setup");
        assert!(status.success(), "SYS-owned catalog setup failed");
    }

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
    runtime.block_on(async move {
        let cx = Cx::current().unwrap();
        let admin = RustOracleConnection::connect(&cx, options.clone()).await.expect("FREE23 admin connects");
        let version = admin.query_rows(&cx, "SELECT version_full AS version FROM SYS.product_component_version WHERE ROWNUM = 1", &[]).await.unwrap();
        assert!(version[0].text("VERSION").unwrap().starts_with("23."));
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_micros();
        let schema = format!("OM_MUT_{nonce:X}_{:X}", std::process::id());
        let password = format!("Mutation{nonce:X}A");
        ddl(&cx, &admin, &format!("CREATE USER {schema} IDENTIFIED BY \"{password}\" DEFAULT TABLESPACE USERS QUOTA 8M ON USERS")).await;
        ddl(&cx, &admin, &format!("GRANT CREATE SESSION, CREATE TABLE, CREATE TRIGGER, CREATE PROCEDURE TO {schema}")).await;
        catalog_grants(&schema, true);
        ddl(&cx, &admin, &format!("CREATE TABLE {schema}.ROOT (C1 NUMBER CONSTRAINT PK_ROOT PRIMARY KEY, C2 NUMBER)")).await;
        ddl(&cx, &admin, &format!("CREATE TABLE {schema}.CHILD (C1 NUMBER CONSTRAINT FK_CHILD REFERENCES {schema}.ROOT(C1) ON DELETE CASCADE, C2 NUMBER)")).await;
        ddl(&cx, &admin, &format!("CREATE MATERIALIZED VIEW LOG ON {schema}.ROOT WITH PRIMARY KEY INCLUDING NEW VALUES")).await;
        ddl(&cx, &admin, &format!("CREATE OR REPLACE TRIGGER {schema}.TR_ROW BEFORE UPDATE OF C2 ON {schema}.ROOT FOR EACH ROW BEGIN NULL; END;")).await;
        ddl(&cx, &admin, &format!("CREATE OR REPLACE TRIGGER {schema}.TR_COMPOUND FOR INSERT OR UPDATE OR DELETE ON {schema}.ROOT COMPOUND TRIGGER BEFORE STATEMENT IS BEGIN NULL; END BEFORE STATEMENT; AFTER EACH ROW IS BEGIN NULL; END AFTER EACH ROW; END;")).await;
        ddl(&cx, &admin, &format!("CREATE OR REPLACE TRIGGER {schema}.TR_CHILD BEFORE DELETE ON {schema}.CHILD FOR EACH ROW BEGIN NULL; END;")).await;
        ddl(&cx, &admin, &format!("CREATE OR REPLACE FUNCTION {schema}.POLICY_FN(S VARCHAR2, O VARCHAR2) RETURN VARCHAR2 AUTHID DEFINER IS BEGIN RETURN NULL; END;")).await;
        ddl(&cx, &admin, &format!("BEGIN SYS.DBMS_RLS.ADD_POLICY(object_schema => '{schema}', object_name => 'ROOT', policy_name => 'UPDATE_POLICY', function_schema => '{schema}', policy_function => 'POLICY_FN', statement_types => 'UPDATE', update_check => TRUE); END;")).await;

        let mut reader_options = options;
        reader_options.username = Some(schema.clone());
        reader_options.password = Some(password);
        let reader = RustOracleConnection::connect(&cx, reader_options).await.expect("fixture owner connects");
        let identity = reader.query_rows(&cx, "SELECT object_id, edition_name FROM SYS.ALL_OBJECTS WHERE owner=:1 AND object_name='ROOT' AND object_type='TABLE'", &[schema.as_str().into()]).await.unwrap();
        assert_eq!(identity.len(), 1);
        let request = |kind, columns| MutationRequest {
            target: ResolvedObject {
                owner: schema.clone(), name: "ROOT".into(), kind: CatalogObjectKind::Table,
                container: None, member: None, overloads: Vec::new(), quote_exact: true,
                synonym_chain: Vec::new(), db_link: None,
                identity: ResolvedIdentity {
                    object_id: identity[0].parse_i64("OBJECT_ID").unwrap().try_into().unwrap(),
                    edition: identity[0].text("EDITION_NAME").map(str::to_owned),
                },
            },
            statement_kind: kind, columns,
        };
        let closure = collect_mutation_effect_closure(&cx, &reader, request(MutationStatementKind::Merge, MutationColumns::All), &EngineMutationEffects).await;
        eprintln!("{}", serde_json::json!({"case":"mutation_closure_live_fixture_matches_expected", "phase":"collected", "closure":closure}));
        assert!(closure.is_complete(), "live fixture is incomplete: {closure:?}");
        assert_eq!(closure.admit(), Ok(OperatingLevel::ReadWrite));
        let observed: BTreeSet<_> = closure.mechanisms.iter().map(|fact| (fact.scope.target.name.as_str(), fact.name.as_str())).collect();
        assert_eq!(observed, BTreeSet::from([
            ("ROOT", "TR_ROW"), ("ROOT", "TR_COMPOUND"), ("ROOT", "FK_CHILD"),
            ("ROOT", "PK_ROOT"), ("ROOT", "MLOG$_ROOT"), ("ROOT", "UPDATE_POLICY"),
            ("CHILD", "TR_CHILD"),
        ]));
        for fact in &closure.mechanisms {
            assert_eq!(fact.metadata_sha256.len(), 64);
            if matches!(fact.mechanism, MutationMechanism::DmlTrigger {..} | MutationMechanism::VpdPolicy {..}) {
                assert_eq!(fact.source_sha256.as_ref().unwrap().len(), 64);
                assert!(!fact.routine_closure_fingerprints.is_empty());
            }
        }
        let policy = closure.mechanisms.iter().find(|fact| fact.name=="UPDATE_POLICY").unwrap();
        assert!(matches!(&policy.mechanism, MutationMechanism::VpdPolicy { statement_types, check_option: true } if *statement_types == BTreeSet::from([MutationStatementKind::Update])));
        let mut before_source_change = None;
        for (column, present) in [("C1", false), ("C2", true)] {
            let closure = collect_mutation_effect_closure(&cx, &reader, request(MutationStatementKind::Update, MutationColumns::Named(BTreeSet::from([column.into()]))), &EngineMutationEffects).await;
            assert!(closure.is_complete(), "UPDATE {column}: {closure:?}");
            assert_eq!(closure.mechanisms.iter().any(|fact| fact.name=="TR_ROW"), present);
            if column == "C2" {
                before_source_change = Some(closure.fingerprint());
            }
        }

        catalog_grants(&schema, false);
        let hidden = collect_mutation_effect_closure(&cx, &reader, request(MutationStatementKind::Merge, MutationColumns::All), &EngineMutationEffects).await;
        assert!(!hidden.is_complete(), "lost FK visibility cannot produce a smaller complete closure");
        assert!(hidden.observations.iter().any(|observation| observation.source == MutationCatalogSource::IncomingForeignKeys && matches!(observation.computation, MutationComputation::Unavailable {reason: MutationUnavailableReason::CatalogUnreadable})));
        catalog_grants(&schema, true);
        ddl(&cx, &admin, &format!("CREATE TABLE {schema}.AUTO_CANARY (ID NUMBER)")).await;
        ddl(&cx, &admin, &format!("INSERT INTO {schema}.ROOT (C1, C2) VALUES (1007, 0)")).await;
        admin.commit(&cx).await.unwrap();
        ddl(&cx, &admin, &format!("CREATE OR REPLACE TRIGGER {schema}.TR_ROW BEFORE UPDATE OF C2 ON {schema}.ROOT FOR EACH ROW DECLARE PRAGMA AUTONOMOUS_TRANSACTION; BEGIN INSERT INTO {schema}.AUTO_CANARY (ID) VALUES (1007); COMMIT; END;")).await;
        let autonomous = collect_mutation_effect_closure(&cx, &reader, request(MutationStatementKind::Update, MutationColumns::Named(BTreeSet::from(["C2".into()]))), &EngineMutationEffects).await;
        let canary = admin.query_rows(&cx, &format!("SELECT COUNT(*) AS N FROM {schema}.AUTO_CANARY"), &[]).await.unwrap();
        assert_eq!(canary[0].parse_i64("N"), Some(0), "collection must not run the autonomous INSERT/COMMIT");
        assert!(autonomous.is_complete(), "autonomous effects must be observed: {autonomous:?}");
        let trigger = autonomous.mechanisms.iter().find(|fact| fact.name == "TR_ROW").unwrap();
        assert!(trigger.effects.iter().any(|effect| effect == RoutineEffect::Autonomous));
        assert!(trigger.effects.iter().any(|effect| effect == RoutineEffect::TxnControl));
        assert_eq!(autonomous.admit(), Err(MutationClosureRefusal::Effect(EffectRefusal::AlwaysRefused(RoutineEffect::TxnControl))));
        assert_ne!(autonomous.fingerprint(), before_source_change.unwrap());
        // Positive fixture control: the real body fires and commits even when
        // the caller rolls its update back. The proof above must never do this.
        ddl(&cx, &admin, &format!("UPDATE {schema}.ROOT SET C2=1 WHERE C1=1007")).await;
        admin.rollback(&cx).await.unwrap();
        let fired = admin.query_rows(&cx, &format!("SELECT COUNT(*) AS N FROM {schema}.AUTO_CANARY"), &[]).await.unwrap();
        assert_eq!(fired[0].parse_i64("N"), Some(1), "autonomous fixture must really INSERT and COMMIT");
        eprintln!("{}", serde_json::json!({"case":"mutation_closure_live_fixture_matches_expected", "phase":"verified", "lane":"FREE23", "native_driver":true, "mechanisms":observed.len(), "column_cases":2, "visibility_refused":true, "autonomous_refused":true}));
        reader.close(&cx).await.unwrap();
        ddl(&cx, &admin, &format!("DROP USER {schema} CASCADE")).await;
        admin.close(&cx).await.unwrap();
    });
}
