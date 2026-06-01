//! Live Oracle integration tests for `oraclemcp-db` (bead P0-3; part of the
//! §12 real-Oracle matrix, T-INTEG).
//!
//! Gated behind the `live-xe` feature AND a runtime reachability probe: if no
//! Oracle is reachable (no Instant Client, no DB), each test prints a loud SKIP
//! banner and returns rather than failing — so CI without a database stays
//! green, matching the repo's `live-xe` / estate-absent convention.
//!
//! To run against the repo's containerized Oracle 23ai Free:
//!   LD_LIBRARY_PATH=/tmp/instantclient_23_7 \
//!     cargo test -p oraclemcp-db --features live-xe -- --nocapture
//! Override target with ORACLEMCP_TEST_DSN / _USER / _PASSWORD.
#![cfg(feature = "live-xe")]

use oraclemcp_db::{OracleBind, OracleConnectOptions, OracleConnection, RustOracleConnection};
use oraclemcp_db::{OraclePool, PoolSettings};

fn test_opts() -> OracleConnectOptions {
    OracleConnectOptions {
        connect_string: std::env::var("ORACLEMCP_TEST_DSN")
            .unwrap_or_else(|_| "//localhost:1521/FREEPDB1".to_owned()),
        username: Some(
            std::env::var("ORACLEMCP_TEST_USER").unwrap_or_else(|_| "system".to_owned()),
        ),
        password: Some(
            std::env::var("ORACLEMCP_TEST_PASSWORD")
                .unwrap_or_else(|_| "DemoPlsqlIntel#2026".to_owned()),
        ),
        ..Default::default()
    }
}

#[test]
fn live_connect_ping_query_bind_describe() {
    let conn = match RustOracleConnection::connect(test_opts()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "[live-xe] SKIP live_connect_ping_query_bind_describe: no reachable Oracle ({e}); \
                 set LD_LIBRARY_PATH + ORACLEMCP_TEST_*"
            );
            return;
        }
    };
    conn.ping().expect("ping");

    let rows = conn
        .query_rows("SELECT 1 AS one FROM dual", &[])
        .expect("scalar query");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].text("ONE"), Some("1"));

    // Bind values are bound, never interpolated.
    let rows = conn
        .query_rows("SELECT :1 AS v FROM dual", &[OracleBind::from("hello")])
        .expect("bind query");
    assert_eq!(rows[0].text("V"), Some("hello"));

    let rows = conn
        .query_rows("SELECT :1 AS n FROM dual", &[OracleBind::from(42i64)])
        .expect("int bind");
    assert_eq!(rows[0].parse_i64("N"), Some(42));

    let info = conn.describe().expect("describe");
    assert!(
        info.server_version.is_some(),
        "server_version should be populated"
    );
    eprintln!(
        "[live-xe] connected: version={:?} role={:?} open_mode={:?} schema={:?}",
        info.server_version, info.database_role, info.open_mode, info.current_schema
    );
}

#[tokio::test]
async fn live_pool_spawn_blocking_roundtrip() {
    let pool = match OraclePool::connect(test_opts(), PoolSettings::default()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[live-xe] SKIP live_pool_spawn_blocking_roundtrip: pool build failed ({e})");
            return;
        }
    };
    pool.ping().await.expect("pool ping");
    let rows = pool
        .query_rows("SELECT 7 AS n FROM dual", vec![])
        .await
        .expect("pool query");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].parse_i64("N"), Some(7));
    assert!(pool.state_connections() >= 1);
}
