//! D5 — the live pinned-session idle-kill lane through the public dispatcher.
//!
//! This complements `oraclemcp-db`'s pooled idle-kill test. The pinned session is
//! the `DispatcherState.conn` owned by `OracleDispatcher`, so the proof belongs
//! at the served-tool boundary rather than in the DB crate.

#![cfg(feature = "live-xe")]
#![forbid(unsafe_code)]

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use oraclemcp::dispatch::OracleDispatcher;
use oraclemcp_db::{OracleBind, OracleConnectOptions, OracleConnection, RustOracleConnection};
use oraclemcp_guard::{OperatingLevel, SessionLevelState};
use serde_json::{Value, json};
use std::time::Duration;

fn run_with_cx<F, Fut, T>(body: F) -> T
where
    F: FnOnce(Cx) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("rt");
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct DispatcherSessionKey {
    sid: String,
    serial: String,
}

impl DispatcherSessionKey {
    fn checked(sid: String, serial: String) -> Self {
        assert!(
            sid.chars().all(|c| c.is_ascii_digit()) && !sid.is_empty(),
            "v$session.sid must be numeric, got {sid:?}"
        );
        assert!(
            serial.chars().all(|c| c.is_ascii_digit()) && !serial.is_empty(),
            "v$session.serial# must be numeric, got {serial:?}"
        );
        DispatcherSessionKey { sid, serial }
    }
}

const OWN_SESSION: &str = "SELECT sid AS s_id, serial# AS s_serial FROM v$session \
     WHERE sid = SYS_CONTEXT('USERENV', 'SID')";

fn read_session_key(value: &Value) -> DispatcherSessionKey {
    let row = value["rows"][0]
        .as_object()
        .expect("oracle_query returns one row object");
    DispatcherSessionKey::checked(
        row["S_ID"]
            .as_str()
            .expect("sid is a NUMBER string")
            .to_owned(),
        row["S_SERIAL"]
            .as_str()
            .expect("serial# is a NUMBER string")
            .to_owned(),
    )
}

async fn kill_session(cx: &Cx, admin: &RustOracleConnection, key: &DispatcherSessionKey) {
    let sql = format!(
        "ALTER SYSTEM KILL SESSION '{},{}' IMMEDIATE",
        key.sid, key.serial
    );
    admin
        .execute(cx, &sql, &[] as &[OracleBind])
        .await
        .expect("ALTER SYSTEM KILL SESSION requires the rig admin principal");
}

fn read_write_level() -> SessionLevelState {
    let mut level = SessionLevelState::new(OperatingLevel::ReadWrite, false);
    level
        .set_current_level(OperatingLevel::ReadWrite)
        .expect("READ_WRITE is within the test profile ceiling");
    level
}

#[test]
fn killed_dispatcher_pinned_session_is_refused_not_silently_rebound() {
    run_with_cx(|cx| async move {
        let test_name = "killed_dispatcher_pinned_session_is_refused_not_silently_rebound";
        let Some(admin) = connect_or_skip(&cx, test_name).await else {
            return;
        };
        let Some(pinned) = connect_or_skip(&cx, test_name).await else {
            return;
        };
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(pinned),
            Some("live_xe".to_owned()),
            read_write_level(),
        );

        let before = dispatcher
            .dispatch_with_cx(&cx, "oracle_query", json!({ "sql": OWN_SESSION }))
            .expect("dispatcher pinned session can identify itself before the kill");
        let victim = read_session_key(&before);

        if std::env::var("ORACLEMCP_D5_SKIP_KILL").is_err() {
            kill_session(&cx, &admin, &victim).await;
        }

        let after = dispatcher.dispatch_with_cx(&cx, "oracle_query", json!({ "sql": OWN_SESSION }));
        let error = match after {
            Ok(value) => {
                let current = read_session_key(&value);
                panic!(
                    "pinned: a killed dispatcher session must not be silently reused or rebound; \
                     victim={victim:?}, current={current:?}, value={value}"
                );
            }
            Err(error) => error,
        };

        assert!(
            error.message.contains("connection lost")
                || error.message.contains("quarantined")
                || error.message.contains("I/O error")
                || error.message.contains("not connected")
                || error.message.contains("closed"),
            "pinned: expected a typed dispatcher refusal for the killed session, got {error:?}"
        );
        assert!(
            error.next_steps.iter().any(|step| {
                step.contains("delete this MCP session")
                    || step.contains("restart")
                    || step.contains("new session")
                    || step.contains("profile")
            }),
            "pinned: refusal should guide the caller toward a new/restarted lane, got {error:?}"
        );
    });
}
