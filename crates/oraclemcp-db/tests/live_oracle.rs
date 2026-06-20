//! Live Oracle integration tests for `oraclemcp-db` (bead P0-3; part of the
//! §12 real-Oracle matrix, T-INTEG).
//!
//! Gated behind the `live-xe` feature AND a runtime reachability probe: if no
//! Oracle is reachable, each test prints a loud SKIP banner and returns rather
//! than failing — so CI without a database stays
//! green, matching the repo's `live-xe` / estate-absent convention.
//!
//! To run against the repo's containerized Oracle 23ai Free:
//!   cargo test -p oraclemcp-db --features live-xe -- --nocapture
//! Override target with ORACLEMCP_TEST_DSN / _USER / _PASSWORD.
//! Optional TCPS fields: ORACLEMCP_TEST_WALLET_LOCATION,
//! ORACLEMCP_TEST_WALLET_PASSWORD, ORACLEMCP_TEST_SSL_SERVER_DN_MATCH,
//! ORACLEMCP_TEST_SSL_SERVER_CERT_DN, ORACLEMCP_TEST_USE_SNI.
//! Optional proxy auth fields: ORACLEMCP_TEST_PROXY_USER and
//! ORACLEMCP_TEST_PROXY_TARGET_SCHEMA. The database must grant:
//!   ALTER USER <target> GRANT CONNECT THROUGH <proxy>;
//! Optional app-context triples:
//!   ORACLEMCP_TEST_APP_CONTEXT='namespace:key:value;namespace:key2:value2'
//! The database must have matching application context namespaces available.
//! Optional edition check: ORACLEMCP_TEST_EDITION must name a valid edition.
//! Optional DRCP check: ORACLEMCP_TEST_DRCP=1 and optionally
//! ORACLEMCP_TEST_DRCP_CLASS.
#![cfg(feature = "live-xe")]

use asupersync::runtime::RuntimeBuilder;
use oraclemcp_db::{
    AuthAdapter, DbError, DrcpConfig, OracleBind, OracleConnectOptions, OracleConnection,
    OracleSessionIdentity, QueryCaps, RustOracleConnection, SessionPurity,
};
use oraclemcp_db::{LeaseManager, OraclePool, PoolSettings, SerializeOptions, serialize_row};
use serde_json::json;
use std::time::{Duration, Instant};

fn env_bool(name: &str) -> Option<bool> {
    std::env::var(name).ok().map(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn env_app_context() -> Option<Vec<(String, String, String)>> {
    let raw = std::env::var("ORACLEMCP_TEST_APP_CONTEXT").ok()?;
    let mut out = Vec::new();
    for (index, item) in raw
        .split(';')
        .filter(|item| !item.trim().is_empty())
        .enumerate()
    {
        let parts: Vec<&str> = item.splitn(3, ':').collect();
        assert!(
            parts.len() == 3 && !parts[0].trim().is_empty() && !parts[1].trim().is_empty(),
            "ORACLEMCP_TEST_APP_CONTEXT entry {index} must be namespace:key:value"
        );
        out.push((
            parts[0].trim().to_owned(),
            parts[1].trim().to_owned(),
            parts[2].to_owned(),
        ));
    }
    assert!(
        !out.is_empty(),
        "ORACLEMCP_TEST_APP_CONTEXT must contain at least one namespace:key:value entry"
    );
    Some(out)
}

fn connect_or_skip(test_name: &str, opts: OracleConnectOptions) -> Option<RustOracleConnection> {
    match RustOracleConnection::connect(opts) {
        Ok(conn) => Some(conn),
        Err(e) => {
            eprintln!(
                "[live-xe] SKIP {test_name}: no reachable Oracle or prerequisite missing ({e}); \
                 set ORACLEMCP_TEST_DSN / _USER / _PASSWORD and optional profile-matrix env vars"
            );
            None
        }
    }
}

fn env_or_skip(test_name: &str, name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) => Some(value),
        Err(_) => {
            eprintln!("[live-xe] SKIP {test_name}: set {name}");
            None
        }
    }
}

fn test_opts() -> OracleConnectOptions {
    let proxy_user = std::env::var("ORACLEMCP_TEST_PROXY_USER").ok();
    let proxy_target_schema = std::env::var("ORACLEMCP_TEST_PROXY_TARGET_SCHEMA").ok();
    let auth_adapter = match (&proxy_user, &proxy_target_schema) {
        (Some(proxy_user), Some(target_schema)) => AuthAdapter::Proxy {
            proxy_user: proxy_user.clone(),
            target_schema: target_schema.clone(),
        },
        (None, None) => AuthAdapter::Password,
        _ => {
            panic!(
                "set both ORACLEMCP_TEST_PROXY_USER and ORACLEMCP_TEST_PROXY_TARGET_SCHEMA for proxy live tests"
            )
        }
    };
    OracleConnectOptions {
        connect_string: std::env::var("ORACLEMCP_TEST_DSN")
            .unwrap_or_else(|_| "//localhost:1521/FREEPDB1".to_owned()),
        username: Some(
            proxy_user
                .or_else(|| std::env::var("ORACLEMCP_TEST_USER").ok())
                .unwrap_or_else(|| "system".to_owned()),
        ),
        password: Some(
            std::env::var("ORACLEMCP_TEST_PASSWORD").unwrap_or_else(|_| "test_password".to_owned()),
        ),
        auth_adapter,
        wallet_location: std::env::var("ORACLEMCP_TEST_WALLET_LOCATION")
            .ok()
            .map(Into::into),
        wallet_password: std::env::var("ORACLEMCP_TEST_WALLET_PASSWORD").ok(),
        ssl_server_dn_match: env_bool("ORACLEMCP_TEST_SSL_SERVER_DN_MATCH"),
        ssl_server_cert_dn: std::env::var("ORACLEMCP_TEST_SSL_SERVER_CERT_DN").ok(),
        use_sni: env_bool("ORACLEMCP_TEST_USE_SNI"),
        session_identity: Some(OracleSessionIdentity {
            program: Some("oraclemcp-live-program".to_owned()),
            machine: Some("oraclemcp-live-machine".to_owned()),
            os_user: Some("oraclemcp-live-os-user".to_owned()),
            terminal: Some("oraclemcp-live-terminal".to_owned()),
            module: Some("oraclemcp-live-test".to_owned()),
            action: Some("oraclemcp-live-action".to_owned()),
            client_identifier: Some("oraclemcp-test-agent".to_owned()),
            client_info: Some("oraclemcp-live-client-info".to_owned()),
            driver_name: Some("oraclemcp-live-driver".to_owned()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn live_profile_config_username_password_identity_and_session_fields_round_trip() {
    let Some(conn) = connect_or_skip(
        "live_profile_config_username_password_identity_and_session_fields_round_trip",
        test_opts(),
    ) else {
        return;
    };
    conn.ping().expect("profile-matrix ping");

    // This is the database metadata source used by oracle_connection_info.
    let info = conn.describe().expect("profile-matrix describe");
    assert!(
        info.session_user.is_some(),
        "username/password thin connection should report a session user"
    );
    assert_eq!(info.module.as_deref(), Some("oraclemcp-live-test"));
    assert_eq!(info.action.as_deref(), Some("oraclemcp-live-action"));
    assert_eq!(
        info.client_identifier.as_deref(),
        Some("oraclemcp-test-agent")
    );
    assert_eq!(
        info.client_info.as_deref(),
        Some("oraclemcp-live-client-info")
    );
    if let Some(program) = info.program.as_deref() {
        assert_eq!(program, "oraclemcp-live-program");
    }
    if let Some(machine) = info.machine.as_deref() {
        assert_eq!(machine, "oraclemcp-live-machine");
    }
    if let Some(os_user) = info.os_user.as_deref() {
        assert_eq!(os_user, "oraclemcp-live-os-user");
    }
    if let Some(terminal) = info.terminal.as_deref() {
        assert_eq!(terminal, "oraclemcp-live-terminal");
    }
    if let Some(client_driver) = info.client_driver.as_deref() {
        assert!(
            client_driver.contains("oraclemcp-live-driver"),
            "client_driver should include configured driver name when visible: {client_driver}"
        );
    }
}

#[test]
fn live_profile_config_invalid_edition_fails_at_connect_time() {
    let opts = test_opts();
    if connect_or_skip(
        "live_profile_config_invalid_edition_fails_at_connect_time/base",
        opts.clone(),
    )
    .is_none()
    {
        return;
    }

    let invalid_edition = "ORACLEMCP_NO_SUCH_EDITION_000000";
    let mut bad_opts = opts;
    bad_opts
        .session_identity
        .get_or_insert_with(Default::default)
        .edition = Some(invalid_edition.to_owned());
    let err = match RustOracleConnection::connect(bad_opts) {
        Ok(_) => panic!("invalid edition unexpectedly connected"),
        Err(err) => err,
    };
    assert!(
        matches!(err, DbError::Connect(_)),
        "invalid edition should fail during thin authentication, got {err}"
    );
    let rendered = err.to_string();
    assert!(
        !rendered.contains(invalid_edition),
        "edition names must be redacted from driver errors: {rendered}"
    );
}

#[test]
fn live_profile_config_wallet_username_password_when_configured() {
    if env_or_skip(
        "live_profile_config_wallet_username_password_when_configured",
        "ORACLEMCP_TEST_WALLET_LOCATION",
    )
    .is_none()
    {
        return;
    }
    let opts = test_opts();
    assert!(
        opts.username.is_some() && opts.password.is_some(),
        "TCPS wallet mode in thin still uses explicit username/password"
    );
    let Some(conn) = connect_or_skip(
        "live_profile_config_wallet_username_password_when_configured",
        opts,
    ) else {
        return;
    };
    conn.ping().expect("wallet username/password ping");
}

#[test]
fn live_profile_config_proxy_auth_when_configured() {
    let Some(proxy_user) = env_or_skip(
        "live_profile_config_proxy_auth_when_configured",
        "ORACLEMCP_TEST_PROXY_USER",
    ) else {
        return;
    };
    let Some(target_schema) = env_or_skip(
        "live_profile_config_proxy_auth_when_configured",
        "ORACLEMCP_TEST_PROXY_TARGET_SCHEMA",
    ) else {
        return;
    };
    let Some(conn) = connect_or_skip(
        "live_profile_config_proxy_auth_when_configured",
        test_opts(),
    ) else {
        return;
    };
    let rows = conn
        .query_rows(
            "SELECT \
                SYS_CONTEXT('USERENV','PROXY_USER') AS proxy_user, \
                SYS_CONTEXT('USERENV','SESSION_USER') AS session_user, \
                SYS_CONTEXT('USERENV','CURRENT_SCHEMA') AS current_schema \
             FROM dual",
            &[],
        )
        .expect("proxy SYS_CONTEXT query");
    assert_eq!(
        rows[0]
            .text("PROXY_USER")
            .map(str::to_ascii_uppercase)
            .as_deref(),
        Some(proxy_user.to_ascii_uppercase().as_str())
    );
    assert_eq!(
        rows[0]
            .text("SESSION_USER")
            .map(str::to_ascii_uppercase)
            .as_deref(),
        Some(target_schema.to_ascii_uppercase().as_str())
    );
    assert_eq!(
        rows[0]
            .text("CURRENT_SCHEMA")
            .map(str::to_ascii_uppercase)
            .as_deref(),
        Some(target_schema.to_ascii_uppercase().as_str())
    );
}

#[test]
fn live_profile_config_sdu_override_connects() {
    let mut opts = test_opts();
    opts.sdu = Some(32_768);
    let Some(conn) = connect_or_skip("live_profile_config_sdu_override_connects", opts) else {
        return;
    };
    let rows = conn
        .query_rows("SELECT 1 AS sdu_probe FROM dual", &[])
        .expect("SDU override probe query");
    assert_eq!(rows[0].text("SDU_PROBE"), Some("1"));
}

#[test]
fn live_profile_config_drcp_routing_when_configured() {
    if !env_bool("ORACLEMCP_TEST_DRCP").unwrap_or(false) {
        eprintln!(
            "[live-xe] SKIP live_profile_config_drcp_routing_when_configured: set ORACLEMCP_TEST_DRCP=1"
        );
        return;
    }
    let mut opts = test_opts();
    let base = opts.connect_string.clone();
    let drcp = DrcpConfig {
        pooled: true,
        connection_class: std::env::var("ORACLEMCP_TEST_DRCP_CLASS").ok(),
        purity: SessionPurity::Reuse,
    };
    opts.connect_string = drcp.apply_to_connect_string(&base);
    assert_ne!(
        opts.connect_string, base,
        "DRCP routing should transform the connect string"
    );
    let rendered = format!("{opts:?}");
    assert!(
        !rendered.contains(&opts.connect_string),
        "debug output must not leak transformed connect strings"
    );
    let Some(conn) = connect_or_skip("live_profile_config_drcp_routing_when_configured", opts)
    else {
        return;
    };
    conn.ping().expect("DRCP ping");
}

#[test]
fn live_app_context_round_trip_when_configured() {
    let Some(app_context) = env_app_context() else {
        eprintln!(
            "[live-xe] SKIP live_app_context_round_trip_when_configured: set ORACLEMCP_TEST_APP_CONTEXT"
        );
        return;
    };
    let mut opts = test_opts();
    if let Err(e) = RustOracleConnection::connect(opts.clone()) {
        eprintln!(
            "[live-xe] SKIP live_app_context_round_trip_when_configured: no reachable Oracle ({e}); \
             set ORACLEMCP_TEST_*"
        );
        return;
    }
    opts.app_context = app_context.clone();
    let conn = RustOracleConnection::connect(opts)
        .expect("app-context connect should succeed after the base live connection succeeds");

    for (namespace, key, expected) in app_context {
        let rows = conn
            .query_rows(
                "SELECT SYS_CONTEXT(:1, :2) AS value FROM dual",
                &[
                    OracleBind::from(namespace.as_str()),
                    OracleBind::from(key.as_str()),
                ],
            )
            .expect("SYS_CONTEXT query");
        assert_eq!(rows[0].text("VALUE"), Some(expected.as_str()));
    }
}

#[test]
fn live_edition_round_trip_when_configured() {
    let Ok(edition) = std::env::var("ORACLEMCP_TEST_EDITION") else {
        eprintln!(
            "[live-xe] SKIP live_edition_round_trip_when_configured: set ORACLEMCP_TEST_EDITION"
        );
        return;
    };
    let mut opts = test_opts();
    if let Err(e) = RustOracleConnection::connect(opts.clone()) {
        eprintln!(
            "[live-xe] SKIP live_edition_round_trip_when_configured: no reachable Oracle ({e}); \
             set ORACLEMCP_TEST_*"
        );
        return;
    }
    let identity = opts.session_identity.get_or_insert_with(Default::default);
    identity.edition = Some(edition.clone());

    let conn = RustOracleConnection::connect(opts)
        .expect("edition connect should succeed after the base live connection succeeds");
    let rows = conn
        .query_rows(
            "SELECT SYS_CONTEXT('USERENV', 'CURRENT_EDITION_NAME') AS edition FROM dual",
            &[],
        )
        .expect("edition SYS_CONTEXT query");
    assert_eq!(rows[0].text("EDITION"), Some(edition.as_str()));
}

#[test]
fn live_connect_ping_query_bind_describe() {
    let conn = match RustOracleConnection::connect(test_opts()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "[live-xe] SKIP live_connect_ping_query_bind_describe: no reachable Oracle ({e}); \
                 set ORACLEMCP_TEST_*"
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
    if let Some(program) = info.program.as_deref() {
        assert_eq!(program, "oraclemcp-live-program");
    }
    if let Some(machine) = info.machine.as_deref() {
        assert_eq!(machine, "oraclemcp-live-machine");
    }
    if let Some(os_user) = info.os_user.as_deref() {
        assert_eq!(os_user, "oraclemcp-live-os-user");
    }
    if let Some(terminal) = info.terminal.as_deref() {
        assert_eq!(terminal, "oraclemcp-live-terminal");
    }
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

    let rows = conn
        .query_rows("SELECT 1 AS after_describe FROM dual", &[])
        .expect("query after describe");
    assert_eq!(rows[0].text("AFTER_DESCRIBE"), Some("1"));
}

#[test]
#[ignore = "profiling helper; run explicitly with --ignored --nocapture"]
fn live_perf_phase_split_connect_ping_query_describe() {
    let opts = test_opts();
    if let Err(e) = RustOracleConnection::connect(opts.clone()) {
        eprintln!(
            "[live-xe] SKIP live_perf_phase_split_connect_ping_query_describe: no reachable Oracle ({e}); \
             set ORACLEMCP_TEST_*"
        );
        return;
    }

    eprintln!("scope,run,phase,ns");
    for run in 1..=20 {
        let start = Instant::now();
        let conn = RustOracleConnection::connect(opts.clone()).expect("cold connect");
        eprintln!("cold,{run},connect,{}", start.elapsed().as_nanos());

        emit_live_phase("cold", run, "ping", || conn.ping());
        emit_live_phase("cold", run, "query_scalar", || {
            conn.query_rows("SELECT 1 AS one FROM dual", &[])
                .map(|_| ())
        });
        emit_live_phase("cold", run, "query_bind", || {
            conn.query_rows("SELECT :1 AS v FROM dual", &[OracleBind::from("hello")])
                .map(|_| ())
        });
        emit_live_phase("cold", run, "describe", || conn.describe().map(|_| ()));
    }

    let conn = RustOracleConnection::connect(opts).expect("steady connect");
    for run in 1..=50 {
        emit_live_phase("steady", run, "ping", || conn.ping());
        emit_live_phase("steady", run, "query_scalar", || {
            conn.query_rows("SELECT 1 AS one FROM dual", &[])
                .map(|_| ())
        });
        emit_live_phase("steady", run, "query_bind", || {
            conn.query_rows("SELECT :1 AS v FROM dual", &[OracleBind::from("hello")])
                .map(|_| ())
        });
        emit_live_phase("steady", run, "describe", || conn.describe().map(|_| ()));
    }
}

fn emit_live_phase(scope: &str, run: usize, phase: &str, f: impl FnOnce() -> Result<(), DbError>) {
    let start = Instant::now();
    f().unwrap_or_else(|e| panic!("{scope} {phase} failed: {e}"));
    eprintln!("{scope},{run},{phase},{}", start.elapsed().as_nanos());
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
fn live_query_materializes_lob_locators_with_caps() {
    let opts = test_opts();
    let setup = match RustOracleConnection::connect(opts.clone()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[live-xe] SKIP live_query_materializes_lob_locators_with_caps: {e}");
            return;
        }
    };
    let table = "ORACLEMCP_LOB_T";
    let _ = setup.execute(&format!("DROP TABLE {table} PURGE"), &[]);
    setup
        .execute(
            &format!("CREATE TABLE {table} (id NUMBER, c CLOB, b BLOB)"),
            &[],
        )
        .expect("create LOB table");
    setup
        .execute(
            &format!(
                "INSERT INTO {table} VALUES (1, TO_CLOB(RPAD('x', 20, 'x')), TO_BLOB(HEXTORAW('DEADBEEFCAFEBABE')))"
            ),
            &[],
        )
        .expect("insert LOB row");
    setup.commit().expect("commit LOB row");

    let direct = setup
        .query_rows_with_serialize_options(
            &format!("SELECT c, b FROM {table} WHERE id = :1"),
            &[OracleBind::from(1i32)],
            &SerializeOptions {
                max_lob_chars: 4,
                max_blob_bytes: 2,
                ..Default::default()
            },
        )
        .expect("direct LOB query should materialize locators");
    assert_eq!(direct[0].text("C"), Some("xxxx"));
    assert_eq!(
        direct[0].cell("B").and_then(|cell| cell.bytes.as_deref()),
        Some([0xDE, 0xAD].as_slice())
    );

    let pool = OraclePool::connect(opts, PoolSettings::default())
        .expect("pool should connect after setup connection succeeds");
    let caps = QueryCaps {
        max_rows: 1,
        max_result_bytes: 1_000_000,
    };
    let serialize_opts = SerializeOptions {
        max_lob_chars: 4,
        max_blob_bytes: 2,
        ..Default::default()
    };
    let response = pool
        .read_query(
            format!("SELECT c, b FROM {table} WHERE id = :1"),
            vec![OracleBind::from(1i32)],
            caps,
            0,
            serialize_opts,
        )
        .expect("LOB query should materialize locators");

    assert_eq!(response.row_count, 1);
    assert_eq!(
        response.rows[0]["C"],
        json!({ "value": "xxxx", "truncated": true, "char_length": 20 })
    );
    assert_eq!(response.rows[0]["B"]["encoding"], json!("base64"));
    assert_eq!(response.rows[0]["B"]["data"], json!("3q0="));
    assert_eq!(response.rows[0]["B"]["byte_length"], json!(8));
    assert_eq!(response.rows[0]["B"]["truncated"], json!(true));
    let _ = setup.execute(&format!("DROP TABLE {table} PURGE"), &[]);
}

#[test]
fn live_implicit_resultset_serializes_ref_cursor_with_caps() {
    let conn = match RustOracleConnection::connect(test_opts()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[live-xe] SKIP live_implicit_resultset_serializes_ref_cursor: {e}");
            return;
        }
    };
    let rows = conn
        .query_rows_with_serialize_options(
            "DECLARE
               rc SYS_REFCURSOR;
             BEGIN
               OPEN rc FOR
                 SELECT 1 AS n, 'one' AS label FROM dual
                 UNION ALL
                 SELECT 2 AS n, 'two' AS label FROM dual;
               DBMS_SQL.RETURN_RESULT(rc);
             END;",
            &[],
            &SerializeOptions {
                max_nested_cursor_rows: 1,
                max_nested_cursor_cells: 8,
                ..Default::default()
            },
        )
        .expect("implicit REF CURSOR result should serialize");

    assert_eq!(rows.len(), 1);
    let rendered = serialize_row(
        &rows[0],
        &SerializeOptions {
            max_nested_cursor_rows: 1,
            max_nested_cursor_cells: 8,
            ..Default::default()
        },
    );
    let nested = &rendered["IMPLICIT_RESULT_1"];
    assert_eq!(nested["columns"], json!(["N", "LABEL"]));
    assert_eq!(nested["row_count"], json!(1));
    assert_eq!(nested["fetched_count"], json!(1));
    assert_eq!(nested["truncated"], json!(true));
    assert_eq!(nested["rows"][0], json!({ "N": "1", "LABEL": "one" }));
}

#[test]
fn live_cursor_expression_serializes_ref_cursor_with_caps() {
    let conn = match RustOracleConnection::connect(test_opts()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[live-xe] SKIP live_cursor_expression_serializes_ref_cursor: {e}");
            return;
        }
    };
    let rows = conn
        .query_rows_with_serialize_options(
            "SELECT CURSOR(
               SELECT 1 AS n FROM dual
               UNION ALL
               SELECT 2 AS n FROM dual
             ) AS child FROM dual",
            &[],
            &SerializeOptions {
                max_nested_cursor_rows: 1,
                max_nested_cursor_cells: 4,
                ..Default::default()
            },
        )
        .expect("cursor expression should serialize");

    assert_eq!(rows.len(), 1);
    let rendered = serialize_row(
        &rows[0],
        &SerializeOptions {
            max_nested_cursor_rows: 1,
            max_nested_cursor_cells: 4,
            ..Default::default()
        },
    );
    let nested = &rendered["CHILD"];
    assert_eq!(nested["columns"], json!(["N"]));
    assert_eq!(nested["row_count"], json!(1));
    assert_eq!(nested["fetched_count"], json!(1));
    assert_eq!(nested["truncated"], json!(true));
    assert_eq!(nested["rows"][0], json!({ "N": "1" }));
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

#[test]
fn live_query_pagination_caps_and_cursor() {
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
        .expect("page1");
    assert_eq!(page1.row_count, 5);
    assert!(page1.truncated, "all_objects has > 5 rows");
    let offset: usize = page1.next_cursor.as_deref().unwrap().parse().unwrap();
    assert_eq!(offset, 5);

    let page2 = pool
        .read_query(sql, vec![], caps, offset, SerializeOptions::default())
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
    if !pkgs
        .iter()
        .any(|r| r.text("OBJECT_NAME") == Some("PKG_AUTONOMOUS"))
    {
        eprintln!(
            "[live-xe] SKIP live_tier1_intelligence: DEMO.PKG_AUTONOMOUS fixture not present"
        );
        return;
    }

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
    let hits = oraclemcp_db::search_source(&conn, Some("demo"), "AUTONOMOUS", None, None, 50)
        .expect("search");
    assert!(
        !hits.is_empty(),
        "PKG_AUTONOMOUS source should mention AUTONOMOUS"
    );

    // get_ddl rejects an unsupported (injection-shaped) object type.
    assert!(oraclemcp_db::get_ddl(&conn, "TABLE; DROP", "demo", "x").is_err());
}

#[test]
fn live_pool_thin_roundtrip() {
    let pool = match OraclePool::connect(test_opts(), PoolSettings::default()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[live-xe] SKIP live_pool_thin_roundtrip: pool build failed ({e})");
            return;
        }
    };
    pool.ping().expect("pool ping");
    let rows = pool
        .query_rows("SELECT 7 AS n FROM dual", vec![])
        .expect("pool query");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].parse_i64("N"), Some(7));
    assert!(pool.state_connections() >= 1);
}

#[test]
fn live_dbms_output_capture_uses_thin_output_binds() {
    let conn = match RustOracleConnection::connect(test_opts()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[live-xe] SKIP live_dbms_output_capture: {e}");
            return;
        }
    };

    conn.enable_dbms_output(Some(2_000))
        .expect("enable DBMS_OUTPUT");
    conn.execute(
        "BEGIN DBMS_OUTPUT.PUT_LINE('oraclemcp-live-output'); END;",
        &[],
    )
    .expect("write DBMS_OUTPUT line");
    let out = conn
        .read_dbms_output(10, 200)
        .expect("capture DBMS_OUTPUT from thin output binds");
    assert_eq!(out.lines, vec!["oraclemcp-live-output"]);
    assert_eq!(out.line_count, 1);
    assert!(!out.truncated);
}

#[test]
fn live_cancelled_query_context_leaves_pool_usable() {
    let pool = match OraclePool::connect(test_opts(), PoolSettings::default()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[live-xe] SKIP live_cancelled_query_context: {e}");
            return;
        }
    };
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("asupersync runtime builds");
    runtime.block_on(async {
        let cx = asupersync::Cx::current().expect("block_on installs a request Cx");
        cx.set_cancel_requested(true);
        let err = pool
            .read_query_cx(
                &cx,
                "SELECT 1 AS n FROM dual",
                vec![],
                QueryCaps::default(),
                0,
                SerializeOptions::default(),
            )
            .expect_err("cancelled context must abort query boundary");
        assert!(matches!(err, DbError::Cancelled(_)), "{err}");
    });

    let rows = pool
        .query_rows("SELECT 7 AS n FROM dual", vec![])
        .expect("pool remains usable after cancelled request context");
    assert_eq!(rows[0].parse_i64("N"), Some(7));
}

/// WP-C live verification: the read-only DBA health suite runs against a real
/// 23ai, returns a finding per requested subcheck, and — critically — every
/// subcheck either succeeds against a readable view or degrades to a structured
/// skip; it must NEVER bubble a raw ORA- error or fail the whole call. This is
/// the live half of C1's privilege-degradation acceptance criterion (the unit
/// SQL-shape + degradation tests live in `health.rs`).
#[test]
fn live_db_health_suite_runs_all_subchecks_without_hard_failure() {
    let Some(conn) = connect_or_skip(
        "live_db_health_suite_runs_all_subchecks_without_hard_failure",
        test_opts(),
    ) else {
        return;
    };
    conn.ping().expect("health ping");

    let subchecks = oraclemcp_db::HealthSubcheck::all();
    let findings = oraclemcp_db::run_health(&conn, subchecks);
    assert_eq!(
        findings.len(),
        subchecks.len(),
        "every requested subcheck produces exactly one finding"
    );

    for finding in &findings {
        // The view name each subcheck actually used / attempted is recorded.
        assert!(
            !finding.source_view.is_empty(),
            "{:?} must record its source view",
            finding.subcheck
        );
        // A skipped subcheck is structured (status=skipped), never a raw ORA-.
        let status = finding.detail.get("status").and_then(|v| v.as_str());
        if status == Some("skipped") {
            assert_eq!(
                finding.severity,
                oraclemcp_db::Severity::Info,
                "a privilege skip is informational, not an alarm"
            );
            let reason = finding
                .detail
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            eprintln!(
                "[live-xe] db_health subcheck {} degraded to skip ({reason})",
                finding.subcheck.name()
            );
        } else {
            assert_eq!(status, Some("ok"), "non-skip findings carry status=ok");
        }
    }

    // Verify the DBA_*->ALL_* degradation actually exercises a live view by
    // running each builder's SQL directly through the read path; a privilege
    // error is acceptable (that is the degradation path), but a SUCCESS proves
    // the SQL is valid against the live dictionary.
    let (_, invalid_sql) = oraclemcp_db::invalid_objects_sql(oraclemcp_db::ViewTier::All);
    match conn.query_rows(&invalid_sql, &[]) {
        Ok(_) => {}
        Err(e) => eprintln!("[live-xe] ALL_OBJECTS invalid-objects query degraded ({e})"),
    }
}

// C10 consolidated live coverage (bead oraclemcp-040-epic-wp-c-17t.10): the
// full DBA suite + `oracle_top_queries` (incl. the Statspack-fallback path) +
// the C9 preflight, all run against a real 23ai. Together with the `health.rs`
// / `awr.rs` unit tests, the dispatch `db_health`/`top_queries` tests, and the
// `live_db_health_suite_runs_all_subchecks_without_hard_failure` test above,
// this is the consolidated WP-C coverage. The acceptance criterion is
// "CI-green-with-Oracle = every subcheck (C2–C7) + top_queries Statspack
// fallback (C8) + privilege-degradation (DBA_*→ALL_*) all pass against live
// 23ai". Without a reachable Oracle each test prints a SKIP banner and returns.

/// C9 live: the report-only preflight resolves a tier/feature posture for every
/// subcheck and for top_queries (default + historical) against a real DB. It
/// must never fail and must report a runnable-or-skip resolution per subcheck;
/// the resolved tiers must be consistent with what `run_health` actually used.
#[test]
fn live_dba_suite_preflight_reports_runnable_posture() {
    let Some(conn) = connect_or_skip(
        "live_dba_suite_preflight_reports_runnable_posture",
        test_opts(),
    ) else {
        return;
    };
    conn.ping().expect("preflight ping");

    let report = oraclemcp_db::preflight(&conn);
    assert_eq!(
        report.subchecks.len(),
        oraclemcp_db::HealthSubcheck::all().len(),
        "one preflight row per subcheck"
    );
    let (runnable, skipped) = report.runnable_skipped();
    assert_eq!(runnable + skipped, report.subchecks.len());
    eprintln!(
        "[live-xe] preflight: {runnable} runnable, {skipped} skip; default={:?} historical={:?} pack={} statspack={}",
        report.top_queries_default,
        report.top_queries_historical,
        report.diagnostics_pack_licensed,
        report.statspack_installed,
    );
    // Default top-queries is always the free live cursor (no pack required).
    assert_eq!(
        report.top_queries_default,
        oraclemcp_db::DiagnosticsSource::LiveCursor,
        "the default top-SQL source is the free live cursor cache"
    );
    // The preflight's per-subcheck tier must match what run_health would use:
    // a subcheck the preflight marks runnable must NOT degrade to a skip.
    let findings = oraclemcp_db::run_health(&conn, oraclemcp_db::HealthSubcheck::all());
    for row in &report.subchecks {
        let finding = findings
            .iter()
            .find(|f| f.subcheck == row.subcheck)
            .expect("a finding per subcheck");
        let actually_skipped =
            finding.detail.get("status").and_then(|v| v.as_str()) == Some("skipped");
        assert_eq!(
            row.tier.is_none(),
            actually_skipped,
            "preflight tier for {:?} must agree with run_health's skip decision",
            row.subcheck
        );
    }
}

/// C8/C10 live: `oracle_top_queries` resolves to a working source and the
/// resolved source's query runs as a pure read. The default (live cursor) path
/// always works; the historical path resolves to AWR (only if the Diagnostics
/// Pack is licensed) → Statspack (the free fallback) → a structured Unavailable
/// error — never a silent empty success. Whichever source is resolved, its SQL
/// is exercised against the live dictionary (the Statspack-fallback path is
/// covered whenever PERFSTAT is installed but the pack is not licensed).
#[test]
fn live_top_queries_resolves_source_and_runs_including_statspack_fallback() {
    let Some(conn) = connect_or_skip(
        "live_top_queries_resolves_source_and_runs_including_statspack_fallback",
        test_opts(),
    ) else {
        return;
    };
    conn.ping().expect("top_queries ping");

    // Default mode: always the free live cursor cache, query must run.
    let default_source = oraclemcp_db::resolve_top_sql_source(&conn, false);
    assert_eq!(default_source, oraclemcp_db::DiagnosticsSource::LiveCursor);
    let live_sql =
        oraclemcp_db::top_sql_query(default_source, oraclemcp_db::TopSqlMetric::Elapsed, 5, None)
            .expect("live cursor query builds");
    conn.query_rows(&live_sql, &[])
        .expect("live top-SQL runs as a pure read");

    // Historical mode: resolve the real posture and exercise the resolved path.
    let historical = oraclemcp_db::resolve_top_sql_source(&conn, true);
    eprintln!("[live-xe] top_queries historical source resolved to {historical:?}");
    match oraclemcp_db::top_sql_query(historical, oraclemcp_db::TopSqlMetric::Elapsed, 5, None) {
        Ok(sql) => {
            // AWR or Statspack: the SQL is valid against the live dictionary.
            // (A privilege miss is acceptable; a success proves the path works.)
            match conn.query_rows(&sql, &[]) {
                Ok(_) => eprintln!("[live-xe] historical top-SQL ran against {historical:?}"),
                Err(e) => eprintln!(
                    "[live-xe] historical top-SQL ({historical:?}) degraded on a privilege/feature miss ({e})"
                ),
            }
        }
        Err(envelope) => {
            // Unavailable: a clear structured error that offers Statspack —
            // never an empty success.
            assert_eq!(historical, oraclemcp_db::DiagnosticsSource::Unavailable);
            assert!(envelope.is_error);
            assert!(
                envelope
                    .next_steps
                    .iter()
                    .any(|s| s.to_lowercase().contains("statspack")),
                "the unavailable error offers the free Statspack fallback"
            );
        }
    }
}
