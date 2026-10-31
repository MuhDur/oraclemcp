#![cfg(all(feature = "live-xe", feature = "plsql-intelligence"))]
#![forbid(unsafe_code)]

use asupersync::Cx;
use oraclemcp::dispatch::change_request::ddl_closure::{
    W12DdlEvent, W12DdlTriggerProof, W12DdlTriggerRefusal, W12DdlTriggerRequest,
    collect_ddl_trigger_proof, recheck_before_execute,
};
use oraclemcp_db::OracleConnection;
use oraclemcp_db::{OracleConnectOptions, OracleSessionIdentity, connect_oracle};
use oraclemcp_guard::{
    Classifier, DangerLevel, ExecGrantBinding, ExecGrantStore, GrantMaterial, LevelDecision,
    OperatingLevel, SessionLevelState,
};
use oraclemcp_guard::{ImpactBindingV1, RoutineEffect};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static FIXTURE: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    SchemaAutonomous,
    DatabaseCreate,
    Drift,
    Clean,
    Drop,
}

struct Names {
    table: String,
    procedure: String,
    trigger: String,
    control: String,
    edition: String,
}

struct Evidence {
    refusal: Option<W12DdlTriggerRefusal>,
    proof: Option<W12DdlTriggerProof>,
    before: usize,
    after: usize,
    control_after: usize,
    source_before: Vec<String>,
    source_after: Vec<String>,
    edition_after: bool,
    compile_refusal: Option<W12DdlTriggerRefusal>,
    consumed_once: bool,
}

async fn sql(cx: &Cx, conn: &dyn OracleConnection, statement: &str) -> Result<(), String> {
    conn.execute(cx, statement, &[])
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

async fn rows(cx: &Cx, conn: &dyn OracleConnection, table: &str) -> Result<usize, String> {
    conn.query_rows(cx, &format!("SELECT n FROM {table}"), &[])
        .await
        .map(|rows| rows.len())
        .map_err(|e| e.to_string())
}

async fn source(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
) -> Result<Vec<String>, String> {
    conn.query_rows(cx, "SELECT TEXT FROM SYS.ALL_SOURCE WHERE OWNER = :1 AND NAME = :2 AND TYPE = 'PROCEDURE' ORDER BY LINE", &[owner.into(), name.into()]).await
        .map(|rows| rows.iter().map(|row| row.text("TEXT").unwrap_or("").to_owned()).collect())
        .map_err(|e| e.to_string())
}

async fn edition_exists(cx: &Cx, conn: &dyn OracleConnection, name: &str) -> Result<bool, String> {
    conn.query_rows(
        cx,
        "SELECT EDITION_NAME FROM SYS.DBA_EDITIONS WHERE EDITION_NAME = :1",
        &[name.into()],
    )
    .await
    .map(|rows| !rows.is_empty())
    .map_err(|e| e.to_string())
}

// This is the in-process adapter consumer, not an MCP change-request tool.
// Its explicit grant consumption precedes the production recheck; requested
// DDL still passes the unchanged classifier and operating-level gate.
async fn boundary(
    cx: &Cx,
    conn: &dyn OracleConnection,
    request: &W12DdlTriggerRequest,
    statement: &str,
    drift: Option<&str>,
) -> Result<
    (
        Option<W12DdlTriggerRefusal>,
        Option<W12DdlTriggerProof>,
        bool,
    ),
    String,
> {
    let decision = Classifier::default().classify(statement);
    let mut level = SessionLevelState::new(OperatingLevel::Admin, false);
    level
        .set_current_level(OperatingLevel::Admin)
        .map_err(|e| e.to_string())?;
    if decision.danger == DangerLevel::Forbidden || decision.gate(&level) != LevelDecision::Allow {
        return Err(format!(
            "fixture request failed unchanged SQL guard: {decision:?}"
        ));
    }
    let preview = match collect_ddl_trigger_proof(cx, conn, request).await {
        Ok(proof) => proof,
        Err(refusal) => return Ok((Some(refusal), None, false)),
    };
    let mut binding = ImpactBindingV1::default();
    preview.bind_into(&mut binding);
    let material = GrantMaterial::new(statement, &binding).map_err(|e| e.to_string())?;
    let grants = ExecGrantStore::new();
    let owner = ExecGrantBinding::new("w12-live", "owned-child", "fixture", 1);
    let token = grants.issue(
        material.clone(),
        owner.clone(),
        OperatingLevel::Admin,
        Duration::from_secs(60),
    );
    if let Some(statement) = drift {
        sql(cx, conn, statement).await?;
    }
    grants
        .consume(&token, &material, &owner, OperatingLevel::Admin)
        .map_err(|e| format!("consume: {e:?}"))?;
    let consumed_once = grants
        .consume(&token, &material, &owner, OperatingLevel::Admin)
        .is_err();
    if let Err(error) = recheck_before_execute(cx, conn, &binding, &preview).await {
        return Ok((Some(error.refusal), Some(preview), consumed_once));
    }
    sql(cx, conn, statement).await?;
    Ok((None, Some(preview), consumed_once))
}

async fn exercise(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    base: &str,
    n: &Names,
    case: Case,
) -> Result<Evidence, String> {
    sql(cx, conn, &format!("CREATE TABLE {} (n NUMBER)", n.table)).await?;
    sql(cx, conn, &format!("CREATE TABLE {} (n NUMBER)", n.control)).await?;
    sql(
        cx,
        conn,
        &format!(
            "CREATE OR REPLACE PROCEDURE {} AS BEGIN NULL; END;",
            n.procedure
        ),
    )
    .await?;
    if case == Case::Drop {
        sql(
            cx,
            conn,
            &format!("CREATE EDITION \"{}\" AS CHILD OF \"{base}\"", n.edition),
        )
        .await?;
    }
    let scope = if matches!(case, Case::DatabaseCreate | Case::Drop) {
        "DATABASE"
    } else {
        "SCHEMA"
    };
    let event = if case == Case::Drop {
        "DROP"
    } else if case == Case::DatabaseCreate {
        "CREATE"
    } else {
        "CREATE OR ALTER"
    };
    let body = if matches!(case, Case::Clean | Case::Drift) {
        "DECLARE n NUMBER; BEGIN SELECT 1 INTO n FROM SYS.DUAL; END;".to_owned()
    } else {
        format!(
            "DECLARE PRAGMA AUTONOMOUS_TRANSACTION; BEGIN INSERT INTO {} (n) VALUES (1); COMMIT; END;",
            n.table
        )
    };
    sql(
        cx,
        conn,
        &format!(
            "CREATE OR REPLACE TRIGGER {} AFTER {event} ON {scope} {body}",
            n.trigger
        ),
    )
    .await?;
    let database = oraclemcp_db::read_closure_database_identity(cx, conn)
        .await
        .map_err(|e| format!("{e:?}"))?;
    if database.edition != base {
        return Err(format!("not the requested child edition: {database:?}"));
    }
    let before = rows(cx, conn, &n.table).await?;
    let source_before = source(cx, conn, owner, &n.procedure).await?;
    let (operation, target, statement) = match case {
        Case::DatabaseCreate => (
            W12DdlEvent::CreateEdition,
            n.edition.as_str(),
            format!("CREATE EDITION \"{}\" AS CHILD OF \"{base}\"", n.edition),
        ),
        Case::Drop => (
            W12DdlEvent::DropEdition,
            n.edition.as_str(),
            format!("DROP EDITION \"{}\"", n.edition),
        ),
        _ => (
            W12DdlEvent::CreateOrReplace {
                kind: "PROCEDURE".into(),
            },
            n.procedure.as_str(),
            format!(
                "CREATE OR REPLACE PROCEDURE {} AS BEGIN NULL; NULL; END;",
                n.procedure
            ),
        ),
    };
    let request = W12DdlTriggerRequest::new(operation, owner, target, &database.container)
        .map_err(|e| format!("request: {e:?}"))?;
    let drift = (case == Case::Drift).then(|| format!("CREATE OR REPLACE TRIGGER {} AFTER CREATE OR ALTER ON SCHEMA DECLARE n NUMBER; BEGIN SELECT 2 INTO n FROM SYS.DUAL; END;", n.trigger));
    let (refusal, proof, consumed_once) =
        boundary(cx, conn, &request, &statement, drift.as_deref()).await?;
    let compile_refusal = if matches!(case, Case::Clean | Case::SchemaAutonomous) {
        let request = W12DdlTriggerRequest::new(
            W12DdlEvent::AlterCompile {
                kind: "PROCEDURE".into(),
            },
            owner,
            &n.procedure,
            &database.container,
        )
        .map_err(|e| format!("compile request: {e:?}"))?;
        boundary(
            cx,
            conn,
            &request,
            &format!("ALTER PROCEDURE {} COMPILE", n.procedure),
            None,
        )
        .await?
        .0
    } else {
        None
    };
    let after = rows(cx, conn, &n.table).await?;
    let source_after = source(cx, conn, owner, &n.procedure).await?;
    let edition_after = edition_exists(cx, conn, &n.edition).await?;
    // Raw privileged fixture controls, after taking the refusal evidence,
    // prove the real INSERT+COMMIT body can fire. They are not agent paths.
    if matches!(case, Case::SchemaAutonomous | Case::DatabaseCreate) {
        sql(
            cx,
            conn,
            &format!(
                "CREATE OR REPLACE PROCEDURE {}_C AS BEGIN NULL; END;",
                n.procedure
            ),
        )
        .await?;
    } else if case == Case::Drop {
        sql(cx, conn, &format!("DROP TABLE {} PURGE", n.control)).await?;
    }
    let control_after = rows(cx, conn, &n.table).await?;
    Ok(Evidence {
        refusal,
        proof,
        before,
        after,
        control_after,
        source_before,
        source_after,
        edition_after,
        compile_refusal,
        consumed_once,
    })
}

async fn cleanup(cx: &Cx, conn: &dyn OracleConnection, n: &Names) -> Vec<String> {
    let mut errors = Vec::new();
    for (kind, name) in [
        ("TRIGGER", n.trigger.clone()),
        ("PROCEDURE", n.procedure.clone()),
        ("PROCEDURE", format!("{}_C", n.procedure)),
        ("TABLE", n.control.clone()),
        ("TABLE", n.table.clone()),
    ] {
        let found = conn.query_rows(cx, "SELECT OBJECT_NAME FROM SYS.USER_OBJECTS WHERE OBJECT_NAME = :1 AND OBJECT_TYPE = :2", &[name.as_str().into(), kind.into()]).await;
        match found {
            Ok(found) if !found.is_empty() => {
                let suffix = if kind == "TABLE" { " PURGE" } else { "" };
                if let Err(error) = sql(cx, conn, &format!("DROP {kind} {name}{suffix}")).await {
                    errors.push(error);
                }
            }
            Ok(_) => {}
            Err(error) => errors.push(error.to_string()),
        }
    }
    match edition_exists(cx, conn, &n.edition).await {
        Ok(true) => {
            if let Err(error) = sql(cx, conn, &format!("DROP EDITION \"{}\"", n.edition)).await {
                errors.push(error);
            }
        }
        Ok(false) => {}
        Err(error) => errors.push(error),
    }
    errors
}

fn run(case: Case) {
    let _fixture = FIXTURE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reactor = asupersync::runtime::reactor::create_reactor().unwrap();
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .unwrap();
    let (result, cleanup_errors, close) = runtime.block_on(async {
        let cx = Cx::current().unwrap();
        let owner =
            std::env::var("ORACLEMCP_TEST_USER").expect("dedicated privileged W12 fixture user");
        assert!(
            owner
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        );
        let base = std::env::var("ORACLEMCP_W12_TEST_EDITION").expect("run-owned child edition");
        let conn = connect_oracle(
            &cx,
            OracleConnectOptions {
                connect_string: std::env::var("ORACLEMCP_TEST_DSN").unwrap(),
                username: Some(owner.clone()),
                password: Some(std::env::var("ORACLEMCP_TEST_PASSWORD").unwrap()),
                session_identity: Some(OracleSessionIdentity {
                    edition: Some(base.clone()),
                    ..Default::default()
                }),
                call_timeout: Some(Duration::from_secs(20)),
                ..Default::default()
            },
        )
        .await
        .expect("native W12 connection");
        assert_eq!(conn.backend(), oraclemcp_db::OracleBackend::RustOracle);
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let prefix = format!("{owner}_{suffix:X}");
        let n = Names {
            table: format!("{prefix}_LOG"),
            procedure: format!("{prefix}_P"),
            trigger: format!("{prefix}_TR"),
            control: format!("{prefix}_CTRL"),
            edition: format!("{prefix}_ED"),
        };
        let result = exercise(&cx, conn.as_ref(), &owner, &base, &n, case).await;
        let cleanup_errors = cleanup(&cx, conn.as_ref(), &n).await;
        let close = conn.close(&cx).await;
        (result, cleanup_errors, close)
    });
    assert!(
        cleanup_errors.is_empty(),
        "cleanup failed: {cleanup_errors:?}"
    );
    close.expect("close native W12 connection");
    let evidence = result.expect("real W12 fixture");
    println!(
        "{}",
        serde_json::json!({"case":format!("{case:?}"),"before":evidence.before,"after":evidence.after,"control_after":evidence.control_after,"refusal":evidence.refusal,"consumed_once":evidence.consumed_once,"proof":evidence.proof})
    );
    assert_eq!(
        evidence.before, evidence.after,
        "guarded operations never run autonomous trigger DML"
    );
    match case {
        Case::Clean => {
            assert_eq!(evidence.refusal, None);
            assert_eq!(evidence.compile_refusal, None);
            assert!(evidence.consumed_once);
            assert_ne!(evidence.source_before, evidence.source_after);
            let proof = evidence.proof.unwrap();
            assert!(proof.closure().triggers.iter().any(|trigger| {
                trigger.owner == proof.closure().session_user.as_deref().unwrap()
                    && trigger.source_sha256.is_some()
                    && trigger.object_id > 0
                    && trigger
                        .effects
                        .iter()
                        .any(|effect| effect == RoutineEffect::ReadDb)
            }));
        }
        Case::Drift => {
            assert_eq!(
                evidence.refusal,
                Some(W12DdlTriggerRefusal::RepreviewRequired)
            );
            assert!(evidence.consumed_once);
            assert_eq!(evidence.source_before, evidence.source_after);
        }
        Case::SchemaAutonomous | Case::DatabaseCreate | Case::Drop => {
            if case == Case::Drop {
                assert!(matches!(
                    evidence.refusal,
                    Some(W12DdlTriggerRefusal::Effectful | W12DdlTriggerRefusal::Unknown)
                ));
                assert!(evidence.edition_after);
            } else {
                assert_eq!(evidence.refusal, Some(W12DdlTriggerRefusal::Effectful));
            }
            if case == Case::SchemaAutonomous {
                assert_eq!(
                    evidence.compile_refusal,
                    Some(W12DdlTriggerRefusal::Effectful)
                );
            }
            if case == Case::DatabaseCreate {
                assert!(!evidence.edition_after);
            }
            assert_eq!(evidence.source_before, evidence.source_after);
            assert!(
                evidence.control_after > evidence.after,
                "real autonomous body must INSERT and COMMIT in the raw control"
            );
        }
    }
}

#[test]
#[ignore = "requires dedicated privileged W12 user/child edition on FREE23 or XE21"]
fn w12_autonomous_schema_ddl_trigger_refuses_stage_live() {
    run(Case::SchemaAutonomous);
}
#[test]
#[ignore = "requires exclusive DATABASE-trigger fixture window on FREE23 or XE21"]
fn w12_create_edition_with_autonomous_database_ddl_trigger_refused_live() {
    run(Case::DatabaseCreate);
}
#[test]
#[ignore = "requires dedicated privileged W12 user/child edition on FREE23 or XE21"]
fn w12_ddl_trigger_drift_after_preview_refused_live() {
    run(Case::Drift);
}
#[test]
#[ignore = "requires dedicated privileged W12 user/child edition on FREE23 or XE21"]
fn w12_clean_readonly_ddl_trigger_admitted_live() {
    run(Case::Clean);
}
#[test]
#[ignore = "requires exclusive DATABASE-trigger fixture window on FREE23 or XE21"]
fn w12_drop_edition_ddl_trigger_checked_live() {
    run(Case::Drop);
}
