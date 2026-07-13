//! D2: Edition-Based Redefinition against a live Oracle database.
//!
//! This test is deliberately feature-gated and prerequisite-aware: creating an
//! edition needs database-level EBR privileges and `ORA$BASE` must have no
//! existing child. When either condition is absent, it prints an honest SKIP
//! rather than pretending the ordinary XE lane proved a privileged lifecycle.
#![cfg(feature = "live-xe")]
#![forbid(unsafe_code)]

use std::time::Duration;

use asupersync::runtime::RuntimeBuilder;
use asupersync::{Cx, Outcome};
use oraclemcp::dispatch::OracleDispatcher;
use oraclemcp_core::{DispatchContext, ToolDispatch};
use oraclemcp_db::{OracleBind, OracleConnectOptions, OracleConnection, RustOracleConnection};
use oraclemcp_error::{ErrorClass, ErrorEnvelope, ReasonCategory};
use oraclemcp_guard::{OperatingLevel, SessionLevelState};
use serde_json::{Value, json};

const BASE_EDITION: &str = "ORA$BASE";
const FIXTURE_EDITION: &str = "ORACLEMCP_D2_LINEAR";

fn run_with_cx<F, Fut, T>(body: F) -> T
where
    F: FnOnce(Cx) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("live-XE runtime");
    runtime.block_on(async move {
        let cx = Cx::current().expect("live-XE runtime installs a request Cx");
        body(cx).await
    })
}

fn test_opts() -> OracleConnectOptions {
    OracleConnectOptions {
        connect_string: std::env::var("ORACLEMCP_TEST_DSN")
            .unwrap_or_else(|_| "//localhost:1522/FREEPDB1".to_owned()),
        username: Some(
            std::env::var("ORACLEMCP_TEST_USER").unwrap_or_else(|_| "system".to_owned()),
        ),
        password: Some(
            std::env::var("ORACLEMCP_TEST_PASSWORD").unwrap_or_else(|_| "test_password".to_owned()),
        ),
        call_timeout: Some(Duration::from_secs(20)),
        ..Default::default()
    }
}

async fn connect_or_skip(cx: &Cx, test_name: &str) -> Option<RustOracleConnection> {
    match RustOracleConnection::connect(cx, test_opts()).await {
        Ok(conn) => Some(conn),
        Err(error) => {
            eprintln!(
                "[live-xe] SKIP {test_name}: no reachable Oracle or prerequisite missing ({error}); \
                 set ORACLEMCP_TEST_DSN / _USER / _PASSWORD"
            );
            None
        }
    }
}

fn ddl_level() -> SessionLevelState {
    let mut level = SessionLevelState::new(OperatingLevel::Ddl, false);
    level
        .set_current_level(OperatingLevel::Ddl)
        .expect("DDL fits the test profile ceiling");
    level
}

async fn dispatch(
    dispatcher: &OracleDispatcher,
    cx: &Cx,
    tool: &str,
    args: Value,
) -> Result<Value, ErrorEnvelope> {
    match ToolDispatch::dispatch(dispatcher, cx, DispatchContext::default(), tool, args).await {
        Outcome::Ok(value) => Ok(value),
        Outcome::Err(error) => Err(error),
        other => panic!("{tool} returned an unexpected cancellation/outcome: {other:?}"),
    }
}

async fn confirmed_execute(
    dispatcher: &OracleDispatcher,
    cx: &Cx,
    sql: &str,
) -> Result<Value, ErrorEnvelope> {
    let preview = dispatch(dispatcher, cx, "oracle_preview_sql", json!({ "sql": sql })).await?;
    let confirm = preview
        .pointer("/execute_confirmation/confirm")
        .and_then(Value::as_str)
        .expect("DDL preview mints a confirmation");
    dispatch(
        dispatcher,
        cx,
        "oracle_execute",
        json!({ "sql": sql, "commit": true, "confirm": confirm }),
    )
    .await
}

async fn probe_child_slot(
    cx: &Cx,
    conn: &RustOracleConnection,
) -> Result<(bool, bool), oraclemcp_db::DbError> {
    let parent_rows = conn
        .query_rows(
            cx,
            "SELECT edition_name FROM all_editions WHERE parent_edition_name = :1",
            &[OracleBind::String(BASE_EDITION.to_owned())],
        )
        .await?;
    let fixture_rows = conn
        .query_rows(
            cx,
            "SELECT edition_name FROM all_editions WHERE edition_name = :1",
            &[OracleBind::String(FIXTURE_EDITION.to_owned())],
        )
        .await?;
    Ok((!parent_rows.is_empty(), !fixture_rows.is_empty()))
}

/// A real Oracle creates one child edition, then the server refuses a second
/// child before its CREATE reaches the driver. The test retires its exact
/// synthetic edition through the same governed DDL path.
#[test]
fn edition_lifecycle_is_linear_live_and_second_child_never_executes() {
    run_with_cx(|cx| async move {
        let test_name = "edition_lifecycle_is_linear_live_and_second_child_never_executes";
        let Some(probe) = connect_or_skip(&cx, test_name).await else {
            return;
        };
        let (base_has_child, fixture_exists) = match probe_child_slot(&cx, &probe).await {
            Ok(result) => result,
            Err(error) => {
                eprintln!(
                    "[live-xe] SKIP {test_name}: cannot inspect ALL_EDITIONS ({error}); \
                     the test user needs EBR dictionary visibility"
                );
                return;
            }
        };
        if base_has_child || fixture_exists {
            eprintln!(
                "[live-xe] SKIP {test_name}: ORA$BASE already has a child or the prior D2 fixture exists; \
                 this test never mutates a non-empty edition timeline"
            );
            return;
        }

        let Some(served) = connect_or_skip(&cx, &format!("{test_name}/served")).await else {
            return;
        };
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(served),
            Some("live-d2".to_owned()),
            ddl_level(),
        );
        let create = format!("CREATE EDITION {FIXTURE_EDITION} AS CHILD OF {BASE_EDITION}");
        let first = match confirmed_execute(&dispatcher, &cx, &create).await {
            Ok(value) => value,
            Err(error) if error.error_class == ErrorClass::InsufficientPrivilege => {
                eprintln!(
                    "[live-xe] SKIP {test_name}: test user cannot CREATE EDITION ({error:?})"
                );
                return;
            }
            Err(error) => panic!("first governed CREATE EDITION must succeed: {error:?}"),
        };
        assert_eq!(first["executed"], json!(true));
        assert_eq!(first["required_level"], json!("DDL"));

        let second = confirmed_execute(&dispatcher, &cx, &create)
            .await
            .expect_err("the second child must be refused before Oracle emits raw ORA-38807");
        assert_eq!(second.error_class, ErrorClass::ForbiddenStatement);
        assert_eq!(second.ora_code, Some(38_807));
        assert_eq!(
            second
                .structured_reason
                .as_ref()
                .map(|reason| reason.category),
            Some(ReasonCategory::OneChildEdition)
        );

        let retire = format!("DROP EDITION {FIXTURE_EDITION} CASCADE");
        let retired = confirmed_execute(&dispatcher, &cx, &retire)
            .await
            .expect("the synthetic child retires through the governed DDL path");
        assert_eq!(retired["executed"], json!(true));
        assert_eq!(retired["required_level"], json!("DDL"));
    });
}
