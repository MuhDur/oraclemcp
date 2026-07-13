//! Arc I — the reversible workspace, against a real Oracle
//! (bead `oraclemcp-epic-09x-alien-6sj8.11.1`).
//!
//! The deterministic half of this contract — the undo stack, the refusals, the
//! exact statements issued — is unit-tested in `dispatch::tests`. What only a
//! live database can prove is the part the whole arc rests on: that
//! `SAVEPOINT` / `ROLLBACK TO SAVEPOINT` really do restore the rows an agent
//! changed, that a held statement is genuinely visible in its own session and
//! genuinely absent everywhere else, and that discarding the workspace leaves
//! the table exactly as it was found.
//!
//! Gated behind the `live-xe` feature AND a runtime reachability probe: with no
//! Oracle reachable each test prints a SKIP banner and returns, matching the
//! repo's `live-xe` convention.
//!
//!   cargo test -p oraclemcp --features live-xe --test reversible_workspace -- --nocapture
//!
//! Override the target with ORACLEMCP_TEST_DSN / _USER / _PASSWORD.
#![cfg(feature = "live-xe")]
#![forbid(unsafe_code)]

use asupersync::runtime::RuntimeBuilder;
use asupersync::{Cx, Outcome};
use oraclemcp::dispatch::OracleDispatcher;
use oraclemcp_core::error::{ErrorClass, ErrorEnvelope};
use oraclemcp_core::{DispatchContext, ToolDispatch};
use oraclemcp_db::{OracleBind, OracleConnectOptions, OracleConnection, RustOracleConnection};
use oraclemcp_guard::{OperatingLevel, SessionLevelState};
use serde_json::{Value, json};
use std::time::Duration;

const TABLE: &str = "ORACLEMCP_I1_WORKSPACE";

fn run_with_cx<F, Fut, T>(body: F) -> T
where
    F: FnOnce(Cx) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    // Live tests do real socket I/O, so the runtime needs a reactor.
    let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("current-thread runtime");
    runtime.block_on(async move {
        let cx = Cx::current().expect("block_on installs a current Cx");
        body(cx).await
    })
}

fn test_opts() -> OracleConnectOptions {
    OracleConnectOptions {
        connect_string: std::env::var("ORACLEMCP_TEST_DSN")
            .unwrap_or_else(|_| "//localhost:1521/FREEPDB1".to_owned()),
        username: Some(
            std::env::var("ORACLEMCP_TEST_USER").unwrap_or_else(|_| "system".to_owned()),
        ),
        password: Some(
            std::env::var("ORACLEMCP_TEST_PASSWORD").unwrap_or_else(|_| "test_password".to_owned()),
        ),
        // Bound every round trip so a reachable-but-unauthable / stalled DB fails
        // fast and the test SKIPs cleanly rather than hanging the suite.
        call_timeout: Some(Duration::from_secs(15)),
        ..Default::default()
    }
}

async fn connect_or_skip(cx: &Cx, test_name: &str) -> Option<RustOracleConnection> {
    match RustOracleConnection::connect(cx, test_opts()).await {
        Ok(conn) => Some(conn),
        Err(e) => {
            eprintln!(
                "[live-xe] SKIP {test_name}: no reachable Oracle or prerequisite missing ({e}); \
                 set ORACLEMCP_TEST_DSN / _USER / _PASSWORD"
            );
            None
        }
    }
}

/// A session elevated to READ_WRITE — the floor the reversible workspace needs.
fn read_write() -> SessionLevelState {
    let mut level = SessionLevelState::new(OperatingLevel::ReadWrite, false);
    level
        .set_current_level(OperatingLevel::ReadWrite)
        .expect("READ_WRITE is within the ceiling");
    level
}

async fn call(dispatcher: &OracleDispatcher, cx: &Cx, tool: &str, args: Value) -> Value {
    match ToolDispatch::dispatch(dispatcher, cx, DispatchContext::default(), tool, args).await {
        Outcome::Ok(value) => value,
        other => panic!("{tool} was expected to succeed: {other:?}"),
    }
}

async fn call_err(
    dispatcher: &OracleDispatcher,
    cx: &Cx,
    tool: &str,
    args: Value,
) -> ErrorEnvelope {
    match ToolDispatch::dispatch(dispatcher, cx, DispatchContext::default(), tool, args).await {
        Outcome::Err(error) => error,
        other => panic!("{tool} was expected to be refused: {other:?}"),
    }
}

/// The single `V` value of the one seeded row, as this connection sees it.
async fn read_v(cx: &Cx, conn: &RustOracleConnection) -> Option<String> {
    let rows = conn
        .query_rows(
            cx,
            &format!("SELECT V FROM {TABLE} WHERE ID = 1"),
            &[] as &[OracleBind],
        )
        .await
        .expect("read the witness row");
    rows.first()
        .and_then(|row| row.text("V"))
        .map(str::to_owned)
}

async fn drop_table(cx: &Cx, conn: &RustOracleConnection) {
    let _ = conn
        .execute(
            cx,
            &format!("DROP TABLE {TABLE} PURGE"),
            &[] as &[OracleBind],
        )
        .await;
}

/// Seed one committed row: `ID = 1, V = 'baseline'`.
async fn seed(cx: &Cx, conn: &RustOracleConnection) {
    drop_table(cx, conn).await;
    conn.execute(
        cx,
        &format!("CREATE TABLE {TABLE} (ID NUMBER PRIMARY KEY, V VARCHAR2(30))"),
        &[] as &[OracleBind],
    )
    .await
    .expect("create the witness table");
    conn.execute(
        cx,
        &format!("INSERT INTO {TABLE} (ID, V) VALUES (1, 'baseline')"),
        &[] as &[OracleBind],
    )
    .await
    .expect("seed the witness row");
    conn.commit(cx).await.expect("commit the baseline");
}

/// The bead's acceptance path against a real Oracle: checkpoint → exploratory
/// DML → undo restores state. The held UPDATE must be visible inside the served
/// session (it is real, uncommitted work in that transaction) and invisible to
/// every other session; after the undo, the row is back to its baseline in both.
#[test]
fn checkpoint_then_exploratory_dml_then_undo_restores_state() {
    run_with_cx(|cx| async move {
        let Some(setup) = connect_or_skip(&cx, "checkpoint_undo/setup").await else {
            return;
        };
        seed(&cx, &setup).await;

        let Some(served) = connect_or_skip(&cx, "checkpoint_undo/served").await else {
            return;
        };
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(served),
            Some("live".to_owned()),
            read_write(),
        );

        let checkpoint = call(
            &dispatcher,
            &cx,
            "oracle_checkpoint",
            json!({ "name": "before_change" }),
        )
        .await;
        assert_eq!(checkpoint["checkpoint"], json!("BEFORE_CHANGE"));
        assert_eq!(checkpoint["workspace"]["open"], json!(true));

        let held = call(
            &dispatcher,
            &cx,
            "oracle_execute",
            json!({
                "sql": format!("UPDATE {TABLE} SET V = :1 WHERE ID = :2"),
                "binds": ["explored", 1],
                "hold": true,
            }),
        )
        .await;
        assert_eq!(held["rows_affected"], json!(1));
        assert_eq!(held["held"], json!(true));
        assert_eq!(held["committed"], json!(false));
        assert_eq!(held["rolled_back"], json!(false));
        assert_eq!(held["workspace"]["held_statements"], json!(1));

        // The held change is real, uncommitted work: the served session sees it…
        let inside = call(
            &dispatcher,
            &cx,
            "oracle_query",
            json!({ "sql": format!("SELECT V FROM {TABLE} WHERE ID = 1") }),
        )
        .await;
        assert_eq!(
            inside["rows"][0]["V"],
            json!("explored"),
            "the held UPDATE must be visible in its own transaction"
        );
        // …and no other session does.
        assert_eq!(
            read_v(&cx, &setup).await.as_deref(),
            Some("baseline"),
            "held work must be invisible outside the session — it is not committed"
        );

        // Undo: ROLLBACK TO SAVEPOINT restores the row inside the transaction.
        let undo = call(
            &dispatcher,
            &cx,
            "oracle_undo_to",
            json!({ "name": "before_change" }),
        )
        .await;
        assert_eq!(undo["undone_to"], json!("BEFORE_CHANGE"));
        assert_eq!(undo["discarded_statements"], json!(1));
        assert_eq!(undo["workspace"]["held_statements"], json!(0));

        let restored = call(
            &dispatcher,
            &cx,
            "oracle_query",
            json!({ "sql": format!("SELECT V FROM {TABLE} WHERE ID = 1") }),
        )
        .await;
        assert_eq!(
            restored["rows"][0]["V"],
            json!("baseline"),
            "undo to the checkpoint restored the row"
        );

        // Discard the workspace, then prove the database was never touched.
        let discarded = call(&dispatcher, &cx, "oracle_undo_to", json!({})).await;
        assert_eq!(discarded["workspace"]["open"], json!(false));
        drop(dispatcher);

        assert_eq!(
            read_v(&cx, &setup).await.as_deref(),
            Some("baseline"),
            "the whole exploration committed nothing"
        );
        drop_table(&cx, &setup).await;
    });
}

/// Live proof of the safety rule: while work is held, no statement may commit —
/// because `COMMIT` is transaction-wide and would carry the ungranted held
/// statement into permanence with it. After the workspace is discarded, the same
/// confirmed statement commits normally.
#[test]
fn an_open_workspace_refuses_to_commit_and_leaves_the_row_untouched() {
    run_with_cx(|cx| async move {
        let Some(setup) = connect_or_skip(&cx, "workspace_refuses_commit/setup").await else {
            return;
        };
        seed(&cx, &setup).await;

        let Some(served) = connect_or_skip(&cx, "workspace_refuses_commit/served").await else {
            return;
        };
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(served),
            Some("live".to_owned()),
            read_write(),
        );

        call(
            &dispatcher,
            &cx,
            "oracle_checkpoint",
            json!({ "name": "cp" }),
        )
        .await;
        call(
            &dispatcher,
            &cx,
            "oracle_execute",
            json!({
                "sql": format!("UPDATE {TABLE} SET V = 'held' WHERE ID = 1"),
                "hold": true,
            }),
        )
        .await;

        // A *different*, fully confirmed statement must not be able to commit:
        // its COMMIT would persist the held UPDATE too.
        let commit_sql = format!("UPDATE {TABLE} SET V = 'confirmed' WHERE ID = 1");
        let preview = call(
            &dispatcher,
            &cx,
            "oracle_preview_sql",
            json!({ "sql": commit_sql }),
        )
        .await;
        let confirm = preview["execute_confirmation"]["confirm"]
            .as_str()
            .expect("preview minted a confirmation")
            .to_owned();
        let refused = call_err(
            &dispatcher,
            &cx,
            "oracle_execute",
            json!({ "sql": commit_sql, "commit": true, "confirm": confirm.clone() }),
        )
        .await;
        assert_eq!(refused.error_class, ErrorClass::PolicyDenied);
        assert_eq!(
            read_v(&cx, &setup).await.as_deref(),
            Some("baseline"),
            "the refused commit left the committed row untouched"
        );

        // Discard the workspace; the unspent grant then commits as usual.
        call(&dispatcher, &cx, "oracle_undo_to", json!({})).await;
        let committed = call(
            &dispatcher,
            &cx,
            "oracle_execute",
            json!({ "sql": commit_sql, "commit": true, "confirm": confirm }),
        )
        .await;
        assert_eq!(committed["committed"], json!(true));
        drop(dispatcher);

        assert_eq!(
            read_v(&cx, &setup).await.as_deref(),
            Some("confirmed"),
            "only the confirmed statement was committed — never the held one"
        );
        drop_table(&cx, &setup).await;
    });
}

/// I2 (bead .11.2), live: the dry run really executes the DML, really shows the
/// rows it changed, and really takes it back — the committed table is untouched
/// and the served session is left with no pending change of its own.
#[test]
fn preview_dml_shows_before_and_after_then_leaves_nothing_behind() {
    run_with_cx(|cx| async move {
        let Some(setup) = connect_or_skip(&cx, "preview_dml/setup").await else {
            return;
        };
        seed(&cx, &setup).await;

        let Some(served) = connect_or_skip(&cx, "preview_dml/served").await else {
            return;
        };
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(served),
            Some("live".to_owned()),
            read_write(),
        );

        let preview = call(
            &dispatcher,
            &cx,
            "oracle_preview_dml",
            json!({
                "sql": format!("UPDATE {TABLE} SET V = :1 WHERE ID = :2"),
                "binds": ["previewed", 1],
                "witness": format!("SELECT ID, V FROM {TABLE} WHERE ID = :1"),
                "witness_binds": [1],
            }),
        )
        .await;
        assert_eq!(preview["previewed"], json!(true));
        assert_eq!(preview["reversible"], json!(true));
        assert_eq!(preview["rows_affected"], json!(1));
        assert_eq!(
            preview["before"]["rows"][0]["V"],
            json!("baseline"),
            "before: the row as it stood"
        );
        assert_eq!(
            preview["after"]["rows"][0]["V"],
            json!("previewed"),
            "after: the row as the DML would leave it — read inside the sandbox"
        );

        // The sandbox was rolled back: the served session sees the original row…
        let now = call(
            &dispatcher,
            &cx,
            "oracle_query",
            json!({ "sql": format!("SELECT V FROM {TABLE} WHERE ID = 1") }),
        )
        .await;
        assert_eq!(
            now["rows"][0]["V"],
            json!("baseline"),
            "the dry run left nothing pending in its own session"
        );
        drop(dispatcher);

        // …and so does every other session: nothing was committed.
        assert_eq!(
            read_v(&cx, &setup).await.as_deref(),
            Some("baseline"),
            "a dry run commits nothing"
        );
        drop_table(&cx, &setup).await;
    });
}

/// A dry run must not cause what it cannot undo: a sequence-touching statement is
/// refused and labeled, and the sequence is never advanced.
#[test]
fn preview_dml_will_not_advance_a_sequence_to_show_you_what_would_happen() {
    run_with_cx(|cx| async move {
        let Some(setup) = connect_or_skip(&cx, "preview_dml_sequence/setup").await else {
            return;
        };
        seed(&cx, &setup).await;
        let _ = setup
            .execute(&cx, "DROP SEQUENCE ORACLEMCP_I2_SEQ", &[] as &[OracleBind])
            .await;
        setup
            .execute(
                &cx,
                "CREATE SEQUENCE ORACLEMCP_I2_SEQ START WITH 1 INCREMENT BY 1",
                &[] as &[OracleBind],
            )
            .await
            .expect("create the witness sequence");

        let Some(served) = connect_or_skip(&cx, "preview_dml_sequence/served").await else {
            return;
        };
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(served),
            Some("live".to_owned()),
            read_write(),
        );

        let labeled = call(
            &dispatcher,
            &cx,
            "oracle_preview_dml",
            json!({
                "sql": format!(
                    "INSERT INTO {TABLE} (ID, V) VALUES (ORACLEMCP_I2_SEQ.NEXTVAL, 'seq')"
                ),
            }),
        )
        .await;
        assert_eq!(labeled["previewed"], json!(false));
        assert_eq!(labeled["reversible"], json!(false));
        assert!(
            !labeled["cannot_undo"]
                .as_array()
                .expect("cannot_undo list")
                .is_empty(),
            "the sequence effect must be labeled: {labeled}"
        );
        drop(dispatcher);

        // The sequence was never touched: its first value is still 1.
        let rows = setup
            .query_rows(
                &cx,
                "SELECT ORACLEMCP_I2_SEQ.NEXTVAL AS N FROM DUAL",
                &[] as &[OracleBind],
            )
            .await
            .expect("read the sequence");
        assert_eq!(
            rows.first().and_then(|row| row.parse_i64("N")),
            Some(1),
            "a refused dry run must not have advanced the sequence"
        );

        let _ = setup
            .execute(&cx, "DROP SEQUENCE ORACLEMCP_I2_SEQ", &[] as &[OracleBind])
            .await;
        drop_table(&cx, &setup).await;
    });
}

/// I3 (bead .11.3), live: committing re-classifies and re-gates the exact
/// statement rather than trusting the preview. A confirmation moved onto a
/// different statement is refused, the grant is single-use, and — the point of
/// the whole arc — the committed table only ever reflects the reviewed change.
#[test]
fn commit_re_classifies_the_exact_statement_and_spends_its_grant_once() {
    run_with_cx(|cx| async move {
        let Some(setup) = connect_or_skip(&cx, "commit_reclassify/setup").await else {
            return;
        };
        seed(&cx, &setup).await;

        let Some(served) = connect_or_skip(&cx, "commit_reclassify/served").await else {
            return;
        };
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(served),
            Some("live".to_owned()),
            read_write(),
        );

        let reviewed = format!("UPDATE {TABLE} SET V = 'reviewed' WHERE ID = 1");
        let preview = call(
            &dispatcher,
            &cx,
            "oracle_preview_sql",
            json!({ "sql": reviewed }),
        )
        .await;
        let confirm = preview["execute_confirmation"]["confirm"]
            .as_str()
            .expect("preview minted a confirmation")
            .to_owned();

        // The confirmation cannot be carried onto a different statement.
        let smuggled = call_err(
            &dispatcher,
            &cx,
            "oracle_execute",
            json!({
                "sql": format!("DELETE FROM {TABLE} WHERE ID = 1"),
                "commit": true,
                "confirm": confirm.clone(),
            }),
        )
        .await;
        assert_eq!(smuggled.error_class, ErrorClass::ChallengeRequired);
        assert_eq!(
            read_v(&cx, &setup).await.as_deref(),
            Some("baseline"),
            "the smuggled DELETE never ran"
        );

        // The reviewed statement commits, exactly once.
        let committed = call(
            &dispatcher,
            &cx,
            "oracle_execute",
            json!({ "sql": reviewed, "commit": true, "confirm": confirm.clone() }),
        )
        .await;
        assert_eq!(committed["committed"], json!(true));
        assert_eq!(committed["rows_affected"], json!(1));

        let replay = call_err(
            &dispatcher,
            &cx,
            "oracle_execute",
            json!({ "sql": reviewed, "commit": true, "confirm": confirm }),
        )
        .await;
        assert_eq!(
            replay.error_class,
            ErrorClass::ChallengeRequired,
            "the grant is single-use: a replay cannot commit the same change twice"
        );
        drop(dispatcher);

        assert_eq!(
            read_v(&cx, &setup).await.as_deref(),
            Some("reviewed"),
            "the committed table reflects exactly the reviewed statement"
        );
        drop_table(&cx, &setup).await;
    });
}
