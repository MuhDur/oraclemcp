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
use oraclemcp_core::WriteIntentLog;
use oraclemcp_db::{OracleBind, OracleConnectOptions, OracleConnection, RustOracleConnection};
use oraclemcp_guard::{OperatingLevel, SessionLevelState};
use serde_json::json;
use std::sync::{Arc, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::tempdir;

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

fn read_session_key(rows: &[oraclemcp_db::OracleRow]) -> DispatcherSessionKey {
    let row = rows.first().expect("session query returns one row");
    DispatcherSessionKey::checked(
        row.text("S_ID").expect("sid is a NUMBER string").to_owned(),
        row.text("S_SERIAL")
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
        let before = pinned
            .query_rows(&cx, OWN_SESSION, &[] as &[OracleBind])
            .await
            .expect("pinned session can identify itself before the kill");
        let victim = read_session_key(&before);
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(pinned),
            Some("live_xe".to_owned()),
            read_write_level(),
        );

        if std::env::var("ORACLEMCP_D5_SKIP_KILL").is_err() {
            kill_session(&cx, &admin, &victim).await;
        }

        match dispatcher.dispatch_with_cx(&cx, "oracle_connection_info", json!({})) {
            Ok(value) => {
                assert_eq!(
                    value["connected"],
                    json!(false),
                    "pinned: a killed dispatcher session must not remain connected or be silently rebound; \
                     victim={victim:?}, value={value}"
                );
                let error = &value["connection_error"];
                assert_eq!(
                    error["error_class"],
                    json!("TRANSIENT"),
                    "pinned: connection_info must carry a typed connection_error after kill: {value}"
                );
                assert!(
                    error["message"]
                        .as_str()
                        .is_some_and(|message| message.contains("connection was lost")),
                    "pinned: connection_error must name the lost connection: {value}"
                );
            }
            Err(error) => {
                assert!(
                    error.message.contains("connection lost")
                        || error.message.contains("quarantined")
                        || error.message.contains("I/O error")
                        || error.message.contains("not connected")
                        || error.message.contains("closed"),
                    "pinned: expected a typed dispatcher refusal for the killed session, got {error:?}"
                );
            }
        }
    });
}
