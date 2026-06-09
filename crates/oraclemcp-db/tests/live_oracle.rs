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

use oraclemcp_db::{LeaseManager, OraclePool, PoolSettings, SerializeOptions, serialize_row};
use oraclemcp_db::{
    OracleBind, OracleConnectOptions, OracleConnection, OracleSessionIdentity, QueryCaps,
    RustOracleConnection,
};
use serde_json::json;
use std::time::Duration;

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
        session_identity: Some(OracleSessionIdentity {
            module: Some("oraclemcp-live-test".to_owned()),
            client_identifier: Some("oraclemcp-test-agent".to_owned()),
            ..Default::default()
        }),
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
    assert_eq!(info.module.as_deref(), Some("oraclemcp-live-test"));
    assert_eq!(
        info.client_identifier.as_deref(),
        Some("oraclemcp-test-agent")
    );
    assert!(
        info.session_user.is_some(),
        "session_user should be populated"
    );
    assert!(
        info.current_user.is_some(),
        "current_user should be populated"
    );
    eprintln!(
        "[live-xe] connected: version={:?} role={:?} open_mode={:?} schema={:?}",
        info.server_version, info.database_role, info.open_mode, info.current_schema
    );
}

#[test]
fn live_type_fidelity_number_string_and_iso_date() {
    let conn = match RustOracleConnection::connect(test_opts()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[live-xe] SKIP live_type_fidelity: {e}");
            return;
        }
    };
    // A 20-digit NUMBER (overflows f64), a DATE, and a BINARY_DOUBLE.
    let rows = conn
        .query_rows(
            "SELECT 12345678901234567890 AS big_num, \
             TO_DATE('2026-06-01 12:00:00','YYYY-MM-DD HH24:MI:SS') AS d, \
             CAST(3.5 AS BINARY_DOUBLE) AS bd FROM dual",
            &[],
        )
        .expect("query");
    let v = serialize_row(&rows[0], &SerializeOptions::default());
    eprintln!("[live-xe] type-fidelity row: {v}");
    // NUMBER serializes losslessly as a STRING (never f64-truncated).
    assert_eq!(v["BIG_NUM"], json!("12345678901234567890"));
    // DATE comes back ISO-8601 thanks to the canonical session NLS.
    assert_eq!(v["D"], json!("2026-06-01T12:00:00"));
    // BINARY_DOUBLE is a JSON number.
    assert_eq!(v["BD"], json!(3.5));
}

#[test]
fn live_lease_lifecycle_on_a_pinned_session() {
    let conn = match RustOracleConnection::connect(test_opts()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[live-xe] SKIP live_lease_lifecycle: {e}");
            return;
        }
    };
    let mgr = LeaseManager::new();
    // acquire applies the (empty) login script + stamps DBMS_APPLICATION_INFO.
    let id = mgr
        .acquire(
            "live",
            "agent-live",
            Duration::from_secs(900),
            &[],
            Box::new(conn),
        )
        .expect("acquire lease");
    assert_eq!(mgr.active_count(), 1);
    let info = mgr.info(&id).expect("info");
    assert_eq!(info.agent_identity, "agent-live");
    assert!(info.expires_in_ms > 0);

    // Side-effect-free transaction lifecycle on the pinned session.
    mgr.begin_transaction(&id).expect("begin");
    mgr.savepoint(&id, "oraclemcp_sp1").expect("savepoint");
    mgr.rollback(&id).expect("rollback");
    mgr.commit(&id).expect("commit (no-op)");
    let renewed = mgr.renew(&id).expect("renew");
    assert!(renewed.expires_in_ms > 0);

    mgr.release(&id);
    assert_eq!(mgr.active_count(), 0);
    assert!(mgr.info(&id).is_err(), "released lease is gone");
}

#[tokio::test]
async fn live_query_pagination_caps_and_cursor() {
    let pool = match OraclePool::connect(test_opts(), PoolSettings::default()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[live-xe] SKIP live_query_pagination: {e}");
            return;
        }
    };
    let caps = QueryCaps {
        max_rows: 5,
        max_result_bytes: 1_000_000,
    };
    // Deterministic source of >5 rows.
    let sql = "SELECT object_name FROM all_objects ORDER BY object_name";
    let page1 = pool
        .read_query(sql, vec![], caps, 0, SerializeOptions::default())
        .await
        .expect("page1");
    assert_eq!(page1.row_count, 5);
    assert!(page1.truncated, "all_objects has > 5 rows");
    let offset: usize = page1.next_cursor.as_deref().unwrap().parse().unwrap();
    assert_eq!(offset, 5);

    let page2 = pool
        .read_query(sql, vec![], caps, offset, SerializeOptions::default())
        .await
        .expect("page2");
    assert_eq!(page2.row_count, 5);
    // Page 2 is a disjoint window (OFFSET/FETCH wrapping is valid Oracle SQL).
    assert_ne!(page1.rows[0], page2.rows[0], "page 2 starts after page 1");
}

#[test]
fn live_savepoint_preview_is_ground_truth_and_rolls_back() {
    let setup = match RustOracleConnection::connect(test_opts()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[live-xe] SKIP live_savepoint_preview: {e}");
            return;
        }
    };
    let table = "ORACLEMCP_PREVIEW_T";
    // Best-effort clean slate, then create + seed 3 rows + commit.
    let _ = setup.execute(&format!("DROP TABLE {table}"), &[]);
    setup
        .execute(&format!("CREATE TABLE {table} (id NUMBER)"), &[])
        .expect("create");
    for i in 1..=3 {
        setup
            .execute(&format!("INSERT INTO {table} VALUES ({i})"), &[])
            .expect("insert");
    }
    setup.commit().expect("commit");

    // Preview a whole-table DELETE on a leased session.
    let conn = RustOracleConnection::connect(test_opts()).expect("lease conn");
    let mgr = LeaseManager::new();
    let id = mgr
        .acquire(
            "live",
            "agent",
            Duration::from_secs(300),
            &[],
            Box::new(conn),
        )
        .expect("lease");
    let impact = mgr
        .preview_dml(&id, &format!("DELETE FROM {table}"), &[])
        .expect("preview");
    assert_eq!(
        impact.rows_affected, 3,
        "ground-truth blast radius, not an estimate"
    );
    assert!(impact.rolled_back);
    mgr.release(&id);

    // The DB is unchanged — all 3 rows still present.
    let rows = setup
        .query_rows(&format!("SELECT COUNT(*) AS n FROM {table}"), &[])
        .expect("count");
    assert_eq!(
        rows[0].parse_i64("N"),
        Some(3),
        "preview rolled back; DB unchanged"
    );
    setup
        .execute(&format!("DROP TABLE {table}"), &[])
        .expect("drop");
    setup.commit().ok();
}

#[test]
fn live_tier1_intelligence_dictionary_tools() {
    let conn = match RustOracleConnection::connect(test_opts()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[live-xe] SKIP live_tier1_intelligence: {e}");
            return;
        }
    };
    // schema_inspect: DEMO packages (the synthetic lab ships PKG_AUTONOMOUS etc.).
    let pkgs =
        oraclemcp_db::list_objects(&conn, Some("demo"), Some("PACKAGE"), None, 500).expect("list");
    assert!(!pkgs.is_empty(), "DEMO should have packages");
    assert!(
        pkgs.iter()
            .any(|r| r.text("OBJECT_NAME") == Some("PKG_AUTONOMOUS"))
    );

    // get_ddl of a package returns DDL text.
    let ddl = oraclemcp_db::get_ddl(&conn, "PACKAGE", "demo", "PKG_AUTONOMOUS").expect("ddl");
    let ddl = ddl.expect("some ddl");
    assert!(
        ddl.to_uppercase().contains("PACKAGE"),
        "DDL: {}",
        &ddl[..ddl.len().min(60)]
    );

    // compile_errors runs (valid package -> empty is fine).
    let _ = oraclemcp_db::compile_errors(&conn, "demo", Some("PKG_AUTONOMOUS"))
        .expect("errors query runs");

    // search_source over ALL_SOURCE.
    let hits = oraclemcp_db::search_source(&conn, "demo", "AUTONOMOUS", 50).expect("search");
    assert!(
        !hits.is_empty(),
        "PKG_AUTONOMOUS source should mention AUTONOMOUS"
    );

    // get_ddl rejects an unsupported (injection-shaped) object type.
    assert!(oraclemcp_db::get_ddl(&conn, "TABLE; DROP", "demo", "x").is_err());
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
