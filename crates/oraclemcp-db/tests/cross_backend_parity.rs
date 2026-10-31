//! Cross-backend OracleConnection parity evidence.
//!
//! Compiled only with both the official adapter (`oracledb`) and the live lane
//! (`live-xe`). Each live entry point runs when its rig environment is
//! complete; otherwise it prints a SKIP line, and with
//! `ORACLEMCP_REQUIRE_LIVE=1` (set by the tier-A FREE 23ai lane) an incomplete
//! environment is a test failure rather than a skip.
//!
//! Basic-auth parity reads the W4 rig variables: `ORACLEMCP_TEST_DSN`,
//! `ORACLEMCP_TEST_USER` and `ORACLEMCP_TEST_PASSWORD` for the owner of a
//! disposable, registered W4 fixture, plus `ORACLEMCP_PARITY_RUN_ID` naming
//! that fixture (tables are created in `W4O_<run-id>`; the error-taxonomy case
//! also needs `ORACLEMCP_PARITY_CROSS_PASSWORD` for `W4X_<run-id>`). Create the
//! fixture with `scripts/e2e/w4/fixture.py setup --lane free23 --run-id <id>`.
//!
//! TCPS/PEM parity reads `ORACLEMCP_TCPS_PEM_DSN`, `_USER`, `_PASSWORD` and
//! `_WALLET_LOCATION` (a directory with `ewallet.pem` and no `cwallet.sso`).
//!
//! ```text
//! ORACLEMCP_REQUIRE_LIVE=1 cargo test -p oraclemcp-db --features oracledb,live-xe \
//!   --test cross_backend_parity -- --nocapture --test-threads=1
//! ```
//!
//! The deterministic, feature-on VECTOR projection test remains next to the
//! official adapter. This target is the live proof for behaviour requiring a
//! real Oracle: independent backend connections, DATE/TIMESTAMP/TSLTZ/INTERVAL,
//! LOB/NULL, NUMBER/TSTZ/VECTOR, PL/SQL, DML, errors and TCPS/PEM.

#![cfg(all(feature = "oracledb", feature = "live-xe"))]
#![forbid(unsafe_code)]

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use oraclemcp_db::{
    DbError, OfficialOracleConnection, OracleBackend, OracleBind, OracleConnectOptions,
    OracleConnection, OracleRoutineArg, QueryRowStreamStart, RustOracleConnection,
    SerializeOptions, select_connection_backend, selected_endpoint_uses_tcps, serialize_row,
};
use oraclemcp_guard::{Classifier, DangerLevel, OperatingLevel};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const NUMBER_AND_TSTZ_SQL: &str = "SELECT \
    12345678901234567890123456789012345678 AS number_38, \
    TO_TIMESTAMP_TZ(\
        '2026-09-16 12:34:56.123456789 -05:30', \
        'YYYY-MM-DD HH24:MI:SS.FF9 TZH:TZM'\
    ) AS tstz \
    FROM dual";
const DATE_AND_PLAIN_TIMESTAMP_SQL: &str = "SELECT \
    TO_DATE('2026-06-01 12:00:00', 'YYYY-MM-DD HH24:MI:SS') AS plain_date, \
    TO_TIMESTAMP(\
        '2026-06-01 12:00:00.123456789', \
        'YYYY-MM-DD HH24:MI:SS.FF9'\
    ) AS plain_timestamp \
    FROM dual";
const SPARSE_VECTOR_SQL: &str = "SELECT VECTOR(\
    '[1000, [0, 500, 999], [1.5, 2.5, 3.5]]', \
    1000, FLOAT32, SPARSE\
) AS sparse_vector FROM dual";

/// Execute an async parity scenario on a current-thread runtime with a request
/// context. The official driver remains isolated on its own actor thread.
fn run_with_cx<F, Fut>(body: F)
where
    F: FnOnce(Cx) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("current-thread runtime");
    runtime.block_on(async move {
        let cx = Cx::current().expect("block_on installs a request Cx");
        body(cx).await;
    });
}

const LAB_ENV: [&str; 4] = [
    "ORACLEMCP_TEST_DSN",
    "ORACLEMCP_TEST_USER",
    "ORACLEMCP_TEST_PASSWORD",
    "ORACLEMCP_PARITY_RUN_ID",
];
const TCPS_PEM_ENV: [&str; 4] = [
    "ORACLEMCP_TCPS_PEM_DSN",
    "ORACLEMCP_TCPS_PEM_USER",
    "ORACLEMCP_TCPS_PEM_PASSWORD",
    "ORACLEMCP_TCPS_PEM_WALLET_LOCATION",
];

/// Decide whether a live parity entry point runs. A complete environment runs;
/// an incomplete one is a loud SKIP, or a failure when the lane requires live
/// proof (`ORACLEMCP_REQUIRE_LIVE=1`), so a required lane can never pass empty.
fn live_env_ready(lookup: &dyn Fn(&str) -> Option<String>, names: &[&str], test: &str) -> bool {
    let missing: Vec<&str> = names
        .iter()
        .copied()
        .filter(|name| lookup(name).is_none_or(|value| value.is_empty()))
        .collect();
    if missing.is_empty() {
        return true;
    }
    assert_ne!(
        lookup("ORACLEMCP_REQUIRE_LIVE").as_deref(),
        Some("1"),
        "{test}: ORACLEMCP_REQUIRE_LIVE=1 but {} is unset; a required live parity lane must not skip",
        missing.join(", ")
    );
    eprintln!(
        "[parity] SKIP {test}: set {} to run it (ORACLEMCP_REQUIRE_LIVE=1 makes this a failure)",
        missing.join(", ")
    );
    false
}

/// VECTOR exists from Oracle 23ai. The decision follows the server version the
/// driver reports; a version that cannot be parsed fails the test instead of
/// silently skipping the VECTOR scenarios.
fn server_supports_vector(server_version: Option<&str>) -> bool {
    let major = server_version
        .and_then(|version| version.split('.').next())
        .and_then(|major| major.parse::<u32>().ok())
        .unwrap_or_else(|| {
            panic!("cannot decide VECTOR support from server version {server_version:?}")
        });
    major >= 23
}

fn process_env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn lab_ready(test: &str, extra: &[&str]) -> bool {
    let names: Vec<&str> = LAB_ENV.iter().chain(extra).copied().collect();
    live_env_ready(&process_env, &names, test)
}

fn required_lab_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!(
            "cross-backend lab was explicitly selected but {name} is unset; \
             do not treat an unconfigured target as a parity result"
        )
    })
}

fn local_lab_options() -> OracleConnectOptions {
    OracleConnectOptions {
        connect_string: required_lab_env("ORACLEMCP_TEST_DSN"),
        username: Some(required_lab_env("ORACLEMCP_TEST_USER")),
        password: Some(required_lab_env("ORACLEMCP_TEST_PASSWORD")),
        ..Default::default()
    }
}

fn tcps_pem_lab_options() -> OracleConnectOptions {
    let wallet_location = PathBuf::from(required_lab_env("ORACLEMCP_TCPS_PEM_WALLET_LOCATION"));
    assert!(
        wallet_location.join("ewallet.pem").is_file(),
        "TCPS PEM parity requires an ewallet.pem wallet"
    );
    assert!(
        !wallet_location.join("cwallet.sso").is_file(),
        "TCPS PEM parity must not use an auto-login wallet; that remains driver-cx-only"
    );
    let options = OracleConnectOptions {
        connect_string: required_lab_env("ORACLEMCP_TCPS_PEM_DSN"),
        username: Some(required_lab_env("ORACLEMCP_TCPS_PEM_USER")),
        password: Some(required_lab_env("ORACLEMCP_TCPS_PEM_PASSWORD")),
        wallet_location: Some(wallet_location),
        wallet_password: std::env::var("ORACLEMCP_TCPS_PEM_WALLET_PASSWORD").ok(),
        ..Default::default()
    };
    assert!(
        selected_endpoint_uses_tcps(&options)
            .expect("TCPS PEM parity must parse its explicitly supplied endpoint"),
        "TCPS PEM parity refuses a non-TCPS endpoint"
    );
    options
}

fn serialized_single_row(rows: Vec<oraclemcp_db::OracleRow>, label: &str) -> Value {
    assert_eq!(rows.len(), 1, "{label} must return exactly one row");
    serialize_row(
        &rows.into_iter().next().expect("one row"),
        &SerializeOptions::default(),
    )
}

fn missing_object_facts(error: DbError) -> (oraclemcp_error::ErrorClass, Option<i32>, Option<u64>) {
    let envelope = error.into_envelope();
    (
        envelope.error_class,
        envelope.ora_code,
        envelope.retry_after_ms,
    )
}

fn assert_write_and_ddl_classification(create_sql: &str, insert_sql: &str) {
    let classifier = Classifier::default();
    let create = classifier.classify(create_sql);
    assert_eq!(create.danger, DangerLevel::Destructive);
    assert_eq!(create.required_level, Some(OperatingLevel::Ddl));

    let insert = classifier.classify(insert_sql);
    assert_eq!(insert.danger, DangerLevel::Guarded);
    assert_eq!(insert.required_level, Some(OperatingLevel::ReadWrite));
}

async fn run_transaction_scenario(
    cx: &Cx,
    connection: &dyn OracleConnection,
    table: &str,
) -> (u64, u64, String, String, u64, String) {
    let create_sql = format!("CREATE TABLE {table} (id NUMBER PRIMARY KEY, label VARCHAR2(32))");
    let insert_sql = format!("INSERT INTO {table} (id, label) VALUES (1, 'parity')");
    let count_sql = format!("SELECT COUNT(*) AS count_value FROM {table}");
    let drop_sql = format!("DROP TABLE {table} PURGE");
    assert_write_and_ddl_classification(&create_sql, &insert_sql);

    let mut table_created = false;
    let scenario: Result<(u64, u64, String, String, u64, String), String> = async {
        let create_count = connection
            .execute(cx, &create_sql, &[])
            .await
            .map_err(|error| format!("DDL create: {error}"))?;
        table_created = true;
        let first_insert_count = connection
            .execute(cx, &insert_sql, &[])
            .await
            .map_err(|error| format!("first DML insert: {error}"))?;
        let after_insert = transaction_count_value(
            connection
                .query_rows(cx, &count_sql, &[])
                .await
                .map_err(|error| format!("count after insert: {error}"))?,
            "count after insert",
        )?;

        connection
            .rollback(cx)
            .await
            .map_err(|error| format!("rollback: {error}"))?;
        let after_rollback = transaction_count_value(
            connection
                .query_rows(cx, &count_sql, &[])
                .await
                .map_err(|error| format!("count after rollback: {error}"))?,
            "count after rollback",
        )?;

        let committed_insert_count = connection
            .execute(cx, &insert_sql, &[])
            .await
            .map_err(|error| format!("committed DML insert: {error}"))?;
        connection
            .commit(cx)
            .await
            .map_err(|error| format!("commit: {error}"))?;
        let after_commit = transaction_count_value(
            connection
                .query_rows(cx, &count_sql, &[])
                .await
                .map_err(|error| format!("count after commit: {error}"))?,
            "count after commit",
        )?;

        Ok((
            create_count,
            first_insert_count,
            after_insert,
            after_rollback,
            committed_insert_count,
            after_commit,
        ))
    }
    .await;

    // The lab fixture is the sole deliberate DDL mutation in this test. Always
    // attempt cleanup before propagating the scenario result; this target never
    // treats a cleanup failure as a passing parity result.
    let cleanup: Result<(), String> = if table_created {
        async {
            connection
                .execute(cx, &drop_sql, &[])
                .await
                .map_err(|error| format!("drop local-lab parity table: {error}"))?;
            connection
                .commit(cx)
                .await
                .map_err(|error| format!("commit local-lab cleanup: {error}"))
        }
        .await
    } else {
        Ok(())
    };

    match (scenario, cleanup) {
        (Ok(observation), Ok(())) => observation,
        (Err(scenario), Ok(())) => panic!("transaction scenario failed after cleanup: {scenario}"),
        (Ok(_), Err(cleanup)) => panic!("transaction scenario cleanup failed: {cleanup}"),
        (Err(scenario), Err(cleanup)) => {
            panic!("transaction scenario failed ({scenario}) and cleanup failed ({cleanup})")
        }
    }
}

async fn run_dense_vector_scenario(
    cx: &Cx,
    connection: &dyn OracleConnection,
    table: &str,
) -> Value {
    let create_sql = format!(
        "CREATE TABLE {table} (id NUMBER PRIMARY KEY, embedding VECTOR(3, FLOAT32)) TABLESPACE USERS"
    );
    let insert_sql = format!("INSERT INTO {table} VALUES (1, '[1.25,-2.5,3.75]')");
    let query_sql = format!("SELECT embedding AS dense_vector FROM {table} WHERE id = 1");
    let drop_sql = format!("DROP TABLE {table} PURGE");
    let mut table_created = false;

    let scenario: Result<Value, String> = async {
        connection
            .execute(cx, &create_sql, &[])
            .await
            .map_err(|error| format!("create dense VECTOR table: {error}"))?;
        table_created = true;
        connection
            .execute(cx, &insert_sql, &[])
            .await
            .map_err(|error| format!("insert dense VECTOR row: {error}"))?;
        Ok(serialized_single_row(
            connection
                .query_rows(cx, &query_sql, &[])
                .await
                .map_err(|error| format!("query dense VECTOR row: {error}"))?,
            "dense VECTOR",
        ))
    }
    .await;

    let cleanup: Result<(), String> = if table_created {
        async {
            connection
                .execute(cx, &drop_sql, &[])
                .await
                .map_err(|error| format!("drop local-lab dense VECTOR table: {error}"))?;
            connection
                .commit(cx)
                .await
                .map_err(|error| format!("commit dense VECTOR cleanup: {error}"))
        }
        .await
    } else {
        Ok(())
    };

    match (scenario, cleanup) {
        (Ok(observation), Ok(())) => observation,
        (Err(scenario), Ok(())) => panic!("dense VECTOR scenario failed after cleanup: {scenario}"),
        (Ok(_), Err(cleanup)) => panic!("dense VECTOR cleanup failed: {cleanup}"),
        (Err(scenario), Err(cleanup)) => {
            panic!("dense VECTOR scenario failed ({scenario}) and cleanup failed ({cleanup})")
        }
    }
}

fn transaction_count_value(
    rows: Vec<oraclemcp_db::OracleRow>,
    label: &str,
) -> Result<String, String> {
    if rows.len() != 1 {
        return Err(format!(
            "{label} returned {} rows instead of one",
            rows.len()
        ));
    }
    Ok(serialize_row(&rows[0], &SerializeOptions::default()).to_string())
}

fn validate_parity_run_id(run_id: &str) {
    assert!(
        run_id.len() == 12
            && run_id.starts_with("W4")
            && run_id[2..6].bytes().all(|byte| byte.is_ascii_digit())
            && run_id[6..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase()),
        "parity needs the exact W4 run id of a registered, disposable fixture"
    );
}

fn parity_table(run_id: &str, family: &str) -> String {
    validate_parity_run_id(run_id);
    format!("W4O_{run_id}.ORACLEMCP_PARITY_{family}_{run_id}")
}

fn parity_error_facts(error: DbError, operation: &str) -> Value {
    let envelope = error.into_envelope();
    json!({
        "error_class": envelope.error_class,
        "ora_code": envelope.ora_code,
        "retry_after_ms": envelope.retry_after_ms,
        "operation": operation,
    })
}

fn compare_error_outcomes(
    case_id: &str,
    operation: &str,
    expected: Value,
    driver_result: Result<(), DbError>,
    official_result: Result<(), DbError>,
) {
    let driver_error = driver_result.expect_err(case_id);
    let official_error = official_result.expect_err(case_id);
    let driver_facts = parity_error_facts(driver_error, operation);
    let official_facts = parity_error_facts(official_error, operation);
    parity_record(
        case_id,
        "ErrorEnvelope",
        "driver-cx",
        &driver_facts,
        &driver_facts,
    );
    parity_record(
        case_id,
        "ErrorEnvelope",
        "official",
        &driver_facts,
        &official_facts,
    );
    assert_eq!(
        driver_facts, official_facts,
        "{case_id} error envelope parity"
    );
    assert_eq!(
        driver_facts, expected,
        "{case_id} independent expected envelope"
    );
}

async fn run_error_taxonomy_scenario(
    cx: &Cx,
    driver: &dyn OracleConnection,
    official: &dyn OracleConnection,
    low_driver: &dyn OracleConnection,
    low_official: &dyn OracleConnection,
    run_id: &str,
) {
    compare_error_outcomes(
        "parity_error_syntax",
        "query",
        json!({"error_class":"SYNTAX_ERROR","ora_code":900,"retry_after_ms":null,"operation":"query"}),
        driver
            .query_rows(cx, "SELEC 1 FROM dual", &[])
            .await
            .map(|_| ()),
        official
            .query_rows(cx, "SELEC 1 FROM dual", &[])
            .await
            .map(|_| ()),
    );

    let table = parity_table(run_id, "ERR");
    driver
        .execute(
            cx,
            &format!("CREATE TABLE {table} (ID NUMBER PRIMARY KEY)"),
            &[],
        )
        .await
        .expect("create run-owned unique-constraint table");
    driver
        .execute(cx, &format!("INSERT INTO {table} VALUES (1)"), &[])
        .await
        .expect("seed run-owned unique-constraint table");
    driver.commit(cx).await.expect("commit duplicate key seed");
    let duplicate_insert = format!("INSERT INTO {table} VALUES (1)");
    compare_error_outcomes(
        "parity_error_unique_constraint",
        "execute",
        json!({"error_class":"INTERNAL","ora_code":1,"retry_after_ms":null,"operation":"execute"}),
        driver.execute(cx, &duplicate_insert, &[]).await.map(|_| ()),
        official
            .execute(cx, &duplicate_insert, &[])
            .await
            .map(|_| ()),
    );

    let hidden = parity_table(run_id, "HIDDEN");
    driver
        .execute(cx, &format!("CREATE TABLE {hidden} (ID NUMBER)"), &[])
        .await
        .expect("create run-owned privilege table");
    driver.commit(cx).await.expect("commit privilege table");
    let hidden_sql = format!("SELECT ID FROM {hidden}");
    compare_error_outcomes(
        "parity_error_privilege",
        "query",
        json!({"error_class":"OBJECT_NOT_FOUND","ora_code":942,"retry_after_ms":null,"operation":"query"}),
        low_driver
            .query_rows(cx, &hidden_sql, &[])
            .await
            .map(|_| ()),
        low_official
            .query_rows(cx, &hidden_sql, &[])
            .await
            .map(|_| ()),
    );

    let timeout_options = OracleConnectOptions {
        call_timeout: Some(std::time::Duration::from_secs(1)),
        ..local_lab_options()
    };
    let timeout_driver = RustOracleConnection::connect(cx, timeout_options.clone())
        .await
        .expect("driver-cx timeout session");
    let timeout_official = OfficialOracleConnection::connect(cx, timeout_options)
        .await
        .expect("official timeout session");
    compare_error_outcomes(
        "parity_error_call_timeout",
        "execute",
        json!({"error_class":"TRANSIENT","ora_code":null,"retry_after_ms":null,"operation":"execute"}),
        timeout_driver
            .execute(cx, "BEGIN DBMS_SESSION.SLEEP(5); END;", &[])
            .await
            .map(|_| ()),
        timeout_official
            .execute(cx, "BEGIN DBMS_SESSION.SLEEP(5); END;", &[])
            .await
            .map(|_| ()),
    );
    timeout_driver
        .close(cx)
        .await
        .expect("close driver-cx timeout session");
    match timeout_official.close(cx).await {
        Ok(()) | Err(DbError::Quarantined { .. }) => {}
        Err(error) => panic!("close official timeout session: {error:?}"),
    }

    driver
        .execute(cx, &format!("DROP TABLE {hidden} PURGE"), &[])
        .await
        .expect("drop run-owned privilege table");
    driver
        .execute(cx, &format!("DROP TABLE {table} PURGE"), &[])
        .await
        .expect("drop run-owned error table");
    driver
        .commit(cx)
        .await
        .expect("commit parity error fixture cleanup");
}

async fn run_vector_variants_scenario(
    cx: &Cx,
    driver: &dyn OracleConnection,
    official: &dyn OracleConnection,
    run_id: &str,
) {
    let table = parity_table(run_id, "VECVAR");
    let create = format!(
        "CREATE TABLE {table} (ID NUMBER PRIMARY KEY, F64 VECTOR(3,FLOAT64), F64S VECTOR(1000,FLOAT64,SPARSE), I8 VECTOR(3,INT8), BIN VECTOR(16,BINARY))"
    );
    driver
        .execute(cx, &create, &[])
        .await
        .expect("create run-owned VECTOR variants table");
    driver.execute(cx, &format!("INSERT INTO {table} VALUES (1, '[1.25,-2.5,3.75]', VECTOR('[1000, [0, 500, 999], [1.5, 2.5, 3.5]]',1000,FLOAT64,SPARSE), '[1,-2,3]', '[85,170]')"), &[])
        .await.expect("insert FLOAT64, sparse FLOAT64, INT8, and BINARY vectors");
    driver
        .execute(cx, &format!("INSERT INTO {table} (ID) VALUES (2)"), &[])
        .await
        .expect("insert NULL VECTOR row");
    driver.commit(cx).await.expect("commit VECTOR fixture");

    for (case_id, column, expected) in [
        (
            "parity_vector_float64_dense",
            "F64",
            json!({"kind":"vector","storage":"dense","format":"float64","values":[1.25,-2.5,3.75]}),
        ),
        (
            "parity_vector_float64_sparse",
            "F64S",
            json!({"kind":"vector","storage":"sparse","format":"float64","num_dimensions":1000,"indices":[0,500,999],"values":[1.5,2.5,3.5]}),
        ),
        (
            "parity_vector_int8",
            "I8",
            json!({"kind":"vector","storage":"dense","format":"int8","values":[1,-2,3]}),
        ),
        (
            "parity_vector_binary",
            "BIN",
            json!({"kind":"vector","storage":"dense","format":"binary","values":[85,170]}),
        ),
    ] {
        assert_parity_cell(
            cx,
            driver,
            official,
            (case_id, "VECTOR"),
            &format!("SELECT {column} AS V FROM {table} WHERE ID=1"),
            expected,
            &SerializeOptions::default(),
        )
        .await;
    }
    assert_parity_cell(
        cx,
        driver,
        official,
        ("parity_vector_null", "VECTOR"),
        &format!("SELECT F64 AS V FROM {table} WHERE ID=2"),
        Value::Null,
        &SerializeOptions::default(),
    )
    .await;

    let non_finite = format!(
        "INSERT INTO {table} VALUES (3, VECTOR('[NaN,Infinity,-Infinity]',3,FLOAT64), NULL, NULL, NULL)"
    );
    let driver_outcome = driver.execute(cx, &non_finite, &[]).await;
    let official_outcome = official.execute(cx, &non_finite, &[]).await;
    match (driver_outcome, official_outcome) {
        (Err(driver_error), Err(official_error)) => {
            let driver_facts = parity_error_facts(driver_error, "execute");
            let official_facts = parity_error_facts(official_error, "execute");
            parity_record(
                "parity_vector_non_finite_components",
                "VECTOR(FLOAT64)",
                "driver-cx",
                &driver_facts,
                &driver_facts,
            );
            parity_record(
                "parity_vector_non_finite_components",
                "VECTOR(FLOAT64)",
                "official",
                &driver_facts,
                &official_facts,
            );
            assert_eq!(
                driver_facts, official_facts,
                "non-finite VECTOR refusal parity"
            );
        }
        (Ok(_), Ok(_)) => {
            let sql = format!("SELECT F64 AS V FROM {table} WHERE ID=3");
            let driver_row = serialized_single_row(
                driver
                    .query_rows(cx, &sql, &[])
                    .await
                    .expect("read driver-cx non-finite VECTOR"),
                "driver-cx non-finite VECTOR",
            );
            let official_row = serialized_single_row(
                official
                    .query_rows(cx, &sql, &[])
                    .await
                    .expect("read official non-finite VECTOR"),
                "official non-finite VECTOR",
            );
            assert!(
                driver_row["V"].is_object(),
                "non-finite VECTOR must retain structured serialization"
            );
            let expected = driver_row["V"].clone();
            parity_record(
                "parity_vector_non_finite_components",
                "VECTOR(FLOAT64)",
                "driver-cx",
                &expected,
                &driver_row["V"],
            );
            parity_record(
                "parity_vector_non_finite_components",
                "VECTOR(FLOAT64)",
                "official",
                &expected,
                &official_row["V"],
            );
            assert_eq!(
                driver_row["V"], official_row["V"],
                "non-finite VECTOR serialization parity"
            );
        }
        (driver, official) => panic!(
            "non-finite VECTOR result differs: driver-cx={:?}, official={:?}",
            driver
                .err()
                .map(|error| parity_error_facts(error, "execute")),
            official
                .err()
                .map(|error| parity_error_facts(error, "execute"))
        ),
    }
    driver
        .execute(cx, &format!("DROP TABLE {table} PURGE"), &[])
        .await
        .expect("drop run-owned VECTOR table");
    driver.commit(cx).await.expect("commit VECTOR cleanup");
}

#[test]
fn live_cross_backend_error_and_vector_parity() {
    if !lab_ready(
        "live_cross_backend_error_and_vector_parity",
        &["ORACLEMCP_PARITY_CROSS_PASSWORD"],
    ) {
        return;
    }
    run_with_cx(|cx| async move {
        let options = local_lab_options();
        let driver = RustOracleConnection::connect(&cx, options.clone())
            .await
            .expect("driver-cx lab connection");
        let official = OfficialOracleConnection::connect(&cx, options.clone())
            .await
            .expect("official lab connection");
        let run_id = required_lab_env("ORACLEMCP_PARITY_RUN_ID");
        validate_parity_run_id(&run_id);

        let low_options = OracleConnectOptions {
            username: Some(format!("W4X_{run_id}")),
            password: Some(required_lab_env("ORACLEMCP_PARITY_CROSS_PASSWORD")),
            ..options
        };
        let low_driver = RustOracleConnection::connect(&cx, low_options.clone())
            .await
            .expect("driver-cx W4 low-privilege connection");
        let low_official = OfficialOracleConnection::connect(&cx, low_options)
            .await
            .expect("official W4 low-privilege connection");

        let server_version = driver
            .describe(&cx)
            .await
            .expect("driver-cx describe")
            .server_version;
        if server_supports_vector(server_version.as_deref()) {
            run_vector_variants_scenario(&cx, &driver, &official, &run_id).await;
        } else {
            eprintln!(
                "[parity] SKIP VECTOR variants on {server_version:?}: VECTOR needs Oracle 23ai"
            );
        }
        run_error_taxonomy_scenario(&cx, &driver, &official, &low_driver, &low_official, &run_id)
            .await;

        low_driver
            .close(&cx)
            .await
            .expect("close driver-cx W4 low-privilege connection");
        low_official
            .close(&cx)
            .await
            .expect("close official W4 low-privilege connection");
        driver
            .close(&cx)
            .await
            .expect("close driver-cx parity connection");
        official
            .close(&cx)
            .await
            .expect("close official parity connection");
    });
}

fn parity_record(
    case_id: &str,
    column_type: &str,
    backend: &str,
    expected: &Value,
    actual: &Value,
) {
    println!(
        "{}",
        json!({
            "case_id": case_id, "column_type": column_type,
            "backend": backend, "expected": expected, "actual": actual,
        })
    );
}

fn assert_parity_value(case_id: &str, backend: &str, expected: &Value, actual: &Value) {
    assert_eq!(
        actual, expected,
        "{case_id}: {backend} independent expectation"
    );
}

#[test]
#[should_panic(expected = "parity_timestamp_no_utc_suffix: official independent expectation")]
fn parity_timestamp_no_utc_suffix_rejects_planted_utc_suffix() {
    assert_parity_value(
        "parity_timestamp_no_utc_suffix",
        "official",
        &json!("2020-02-29T12:34:56.123456789"),
        &json!("2020-02-29T12:34:56.123456789Z"),
    );
}

#[test]
#[should_panic(expected = "parity_typed_null_every_type: official independent expectation")]
fn parity_typed_null_every_type_rejects_planted_empty_string() {
    assert_parity_value(
        "parity_typed_null_every_type",
        "official",
        &Value::Null,
        &json!(""),
    );
}

async fn assert_parity_cell(
    cx: &Cx,
    driver: &dyn OracleConnection,
    official: &dyn OracleConnection,
    case: (&str, &str),
    sql: &str,
    expected: Value,
    serialize_opts: &SerializeOptions,
) {
    let (case_id, column_type) = case;
    let driver_row = serialized_single_row_with_options(
        driver
            .query_rows(cx, sql, &[])
            .await
            .unwrap_or_else(|error| panic!("{case_id} driver-cx query: {error}")),
        case_id,
        serialize_opts,
    );
    let official_row = serialized_single_row_with_options(
        official
            .query_rows(cx, sql, &[])
            .await
            .unwrap_or_else(|error| panic!("{case_id} official query: {error}")),
        case_id,
        serialize_opts,
    );
    let driver_value = &driver_row["V"];
    let official_value = &official_row["V"];
    parity_record(case_id, column_type, "driver-cx", &expected, driver_value);
    parity_record(case_id, column_type, "official", &expected, official_value);
    assert_parity_value(case_id, "driver-cx", &expected, driver_value);
    assert_parity_value(case_id, "official", &expected, official_value);
}

async fn number_value_and_oracle_text(
    cx: &Cx,
    connection: &dyn OracleConnection,
    sql: &str,
    label: &str,
) -> (Value, Value) {
    let rows = connection
        .query_rows(cx, sql, &[])
        .await
        .unwrap_or_else(|error| panic!("{label} NUMBER query: {error}"));
    let row = serialized_single_row(rows, label);
    (row["V"].clone(), row["EXPECTED"].clone())
}

fn canonicalize_oracle_number(text: &str) -> String {
    let (sign, unsigned) = match text.strip_prefix('-') {
        Some(unsigned) => ("-", unsigned),
        None => ("", text),
    };
    let (mantissa, exponent) = unsigned
        .split_once(['E', 'e'])
        .map(|(mantissa, exponent)| {
            (
                mantissa,
                exponent
                    .parse::<i32>()
                    .expect("Oracle TO_CHAR exponent is an integer"),
            )
        })
        .unwrap_or((unsigned, 0));
    let decimal_position = mantissa.find('.').unwrap_or(mantissa.len()) as i32 + exponent;
    let digits = mantissa.replace('.', "");
    let expanded = if decimal_position <= 0 {
        format!("0.{}{}", "0".repeat((-decimal_position) as usize), digits)
    } else if decimal_position as usize >= digits.len() {
        format!(
            "{}{}",
            digits,
            "0".repeat(decimal_position as usize - digits.len())
        )
    } else {
        let position = decimal_position as usize;
        format!("{}.{}", &digits[..position], &digits[position..])
    };
    format!("{sign}{expanded}")
}

async fn assert_number_parity(
    cx: &Cx,
    driver: &dyn OracleConnection,
    official: &dyn OracleConnection,
    case_id: &str,
    expression: &str,
) {
    let sql = format!(
        "SELECT {expression} AS V, \
         CASE WHEN TO_CHAR({expression}, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,''') LIKE '.%' \
              THEN '0' || TO_CHAR({expression}, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,''') \
              WHEN TO_CHAR({expression}, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,''') LIKE '-.%' \
              THEN '-0' || SUBSTR(TO_CHAR({expression}, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,'''), 2) \
              ELSE TO_CHAR({expression}, 'TM9', 'NLS_NUMERIC_CHARACTERS=''.,''') END AS EXPECTED \
         FROM dual"
    );
    let (driver_value, driver_expected) =
        number_value_and_oracle_text(cx, driver, &sql, case_id).await;
    let (official_value, official_expected) =
        number_value_and_oracle_text(cx, official, &sql, case_id).await;
    let expected = canonicalize_oracle_number(
        driver_expected
            .as_str()
            .expect("Oracle TO_CHAR must return JSON text"),
    );
    let official_canonical = canonicalize_oracle_number(
        official_expected
            .as_str()
            .expect("Oracle TO_CHAR must return JSON text"),
    );
    assert!(
        driver_value.is_string(),
        "{case_id}: driver-cx NUMBER must be JSON text"
    );
    assert!(
        official_value.is_string(),
        "{case_id}: official NUMBER must be JSON text"
    );
    assert!(
        driver_expected.is_string(),
        "{case_id}: Oracle TO_CHAR must be text"
    );
    assert!(
        official_expected.is_string(),
        "{case_id}: Oracle TO_CHAR must be text"
    );
    assert_eq!(
        expected, official_canonical,
        "{case_id}: canonical Oracle TO_CHAR parity"
    );
    let expected_value = json!(expected);
    parity_record(
        case_id,
        "NUMBER",
        "driver-cx",
        &expected_value,
        &driver_value,
    );
    parity_record(
        case_id,
        "NUMBER",
        "official",
        &expected_value,
        &official_value,
    );
    for (backend, expected, actual) in [
        ("driver-cx", &expected_value, &driver_value),
        ("official", &expected_value, &official_value),
    ] {
        assert_eq!(
            actual, expected,
            "{case_id}: {backend} NUMBER equals Oracle TO_CHAR"
        );
    }
}

/// Exercises NUMBER precision, scale, signed zero, and exponent boundaries
/// with typed Oracle expressions, leaving no lab objects behind.
async fn run_number_boundary_scenario(
    cx: &Cx,
    driver: &dyn OracleConnection,
    official: &dyn OracleConnection,
    run_id: &str,
) {
    validate_parity_run_id(run_id);
    assert_number_parity(
        cx,
        driver,
        official,
        "parity_number_pos_38_digits",
        "CAST(99999999999999999999999999999999999999 AS NUMBER(38,0))",
    )
    .await;
    assert_number_parity(
        cx,
        driver,
        official,
        "parity_number_neg_38_digits",
        "CAST(-99999999999999999999999999999999999999 AS NUMBER(38,0))",
    )
    .await;
    assert_number_parity(
        cx,
        driver,
        official,
        "parity_number_zero_and_neg_zero",
        "CAST(0 AS NUMBER)",
    )
    .await;
    assert_number_parity(
        cx,
        driver,
        official,
        "parity_number_zero_and_neg_zero",
        "CAST(-0 AS NUMBER)",
    )
    .await;
    assert_number_parity(
        cx,
        driver,
        official,
        "parity_number_scale_rounding",
        "CAST(0.0001 AS NUMBER)",
    )
    .await;
    assert_number_parity(
        cx,
        driver,
        official,
        "parity_number_scale_rounding",
        "CAST(123.4567 AS NUMBER)",
    )
    .await;
    assert_number_parity(
        cx,
        driver,
        official,
        "parity_number_scale_rounding",
        "CAST(1.23455 AS NUMBER(10,4))",
    )
    .await;
    assert_number_parity(
        cx,
        driver,
        official,
        "parity_number_extreme_exponents",
        "CAST(1E-130 AS NUMBER)",
    )
    .await;
    assert_number_parity(
        cx,
        driver,
        official,
        "parity_number_extreme_exponents",
        "CAST(9.999999999999999999999999999999999999E125 AS NUMBER)",
    )
    .await;
    assert_number_parity(
        cx,
        driver,
        official,
        "parity_number_is_exact_json_string",
        "CAST(12345678901234567890123456789012345678 AS NUMBER(38,0))",
    )
    .await;

    let sql = "SELECT CAST(1.5 AS BINARY_DOUBLE) AS V FROM dual";
    let driver_bd = serialized_single_row(
        driver
            .query_rows(cx, sql, &[])
            .await
            .expect("driver BINARY_DOUBLE query"),
        "driver BINARY_DOUBLE",
    );
    let official_bd = serialized_single_row(
        official
            .query_rows(cx, sql, &[])
            .await
            .expect("official BINARY_DOUBLE query"),
        "official BINARY_DOUBLE",
    );
    assert_eq!(
        driver_bd, official_bd,
        "BINARY_DOUBLE remains a separate floating type"
    );
}

async fn collect_streamed_values(
    cx: &Cx,
    connection: &dyn OracleConnection,
    sql: &str,
    label: &str,
) -> Vec<Value> {
    let start = connection
        .query_row_stream(cx, sql, &[], 32, &SerializeOptions::default())
        .await
        .unwrap_or_else(|error| panic!("{label} stream start: {error}"));
    let QueryRowStreamStart::Stream(mut stream) = start else {
        panic!("{label} unexpectedly fell back from row streaming");
    };
    let mut rows = Vec::new();
    while let Some(row) = stream
        .next_row(cx)
        .await
        .unwrap_or_else(|error| panic!("{label} stream fetch: {error}"))
    {
        rows.push(serialize_row(&row, &SerializeOptions::default()));
    }
    stream
        .recover(cx)
        .await
        .unwrap_or_else(|error| panic!("{label} stream recovery: {error}"));
    rows
}

async fn assert_stream_parity(
    cx: &Cx,
    driver: &dyn OracleConnection,
    official: &dyn OracleConnection,
    case_id: &str,
    sql: &str,
    expected: Vec<Value>,
) {
    let driver_rows = collect_streamed_values(cx, driver, sql, "driver-cx").await;
    let official_rows = collect_streamed_values(cx, official, sql, "official").await;
    for (backend, actual) in [("driver-cx", &driver_rows), ("official", &official_rows)] {
        let compact = |rows: &[Value]| {
            let encoded = serde_json::to_vec(rows).expect("serialize streamed rows");
            let digest = digest_bytes(&encoded);
            json!({
                "count": rows.len(),
                "first": rows.first(),
                "last": rows.last(),
                "sha256": digest["sha256"].clone(),
            })
        };
        parity_record(
            case_id,
            "stream rows",
            backend,
            &compact(&expected),
            &compact(actual),
        );
        assert_eq!(
            *actual, expected,
            "{case_id}: {backend} row count, order, and values"
        );
    }
}

async fn followup_after_abandoned_stream(
    cx: &Cx,
    connection: &dyn OracleConnection,
    options: &OracleConnectOptions,
    case_id: &str,
    cancel: bool,
) {
    let start = connection
        .query_row_stream(
            cx,
            "SELECT level AS V FROM dual CONNECT BY level <= 1000 ORDER BY level",
            &[],
            4,
            &SerializeOptions::default(),
        )
        .await
        .unwrap_or_else(|error| panic!("{case_id} stream start: {error}"));
    let QueryRowStreamStart::Stream(mut stream) = start else {
        panic!("{case_id} unexpectedly fell back from row streaming");
    };
    let prefix_rows = if cancel { 12 } else { 10 };
    for expected in 1..=prefix_rows {
        let row = stream
            .next_row(cx)
            .await
            .unwrap_or_else(|error| panic!("{case_id} prefix fetch: {error}"))
            .unwrap_or_else(|| panic!("{case_id} ended before row {expected}"));
        let value = serialize_row(&row, &SerializeOptions::default())["V"].clone();
        assert_eq!(
            value,
            json!(expected.to_string()),
            "{case_id}: streamed prefix"
        );
    }
    if cancel {
        cx.set_cancel_requested(true);
        let result = stream.next_row(cx).await;
        assert!(
            matches!(result, Err(DbError::Cancelled(_))),
            "{case_id}: Cx cancellation must stop the next stream fetch"
        );
        cx.set_cancel_requested(false);
    }
    drop(stream);

    let followup = match connection
        .query_rows(cx, "SELECT 42 AS V FROM dual", &[])
        .await
    {
        Ok(rows) => rows,
        Err(error) => {
            eprintln!(
                "{case_id}: abandoned stream made its connection unavailable ({error}); reconnecting the same backend"
            );
            let replacement = connect_backend(cx, options, connection.backend()).await;
            let rows = replacement
                .query_rows(cx, "SELECT 42 AS V FROM dual", &[])
                .await
                .expect("replacement follow-up query");
            replacement
                .close(cx)
                .await
                .expect("close replacement connection");
            rows
        }
    };
    let actual = serialized_single_row(followup, case_id)["V"].clone();
    let backend = match connection.backend() {
        OracleBackend::RustOracle => "driver-cx",
        OracleBackend::OfficialOracle => "official",
        _ => panic!("streaming connection backend is unsupported"),
    };
    parity_record(case_id, "NUMBER", backend, &json!("42"), &actual);
    assert_eq!(
        actual,
        json!("42"),
        "{case_id}: no leftover stream row may be reused"
    );
}

async fn connect_backend(
    cx: &Cx,
    options: &OracleConnectOptions,
    backend: OracleBackend,
) -> Box<dyn OracleConnection> {
    match backend {
        OracleBackend::RustOracle => Box::new(
            RustOracleConnection::connect(cx, options.clone())
                .await
                .expect("connect driver-cx backend"),
        ),
        OracleBackend::OfficialOracle => Box::new(
            OfficialOracleConnection::connect(cx, options.clone())
                .await
                .expect("connect official backend"),
        ),
        _ => panic!("unsupported row-stream backend"),
    }
}

async fn run_streaming_scenario(
    cx: &Cx,
    driver: &dyn OracleConnection,
    official: &dyn OracleConnection,
    options: &OracleConnectOptions,
) {
    // Only statements with a semantic read plan stream on driver-cx; an
    // unplanned hierarchical shape takes the cursor-chunked path (kogf0).
    match driver
        .query_row_stream(
            cx,
            "SELECT level AS V FROM dual START WITH 1=0 CONNECT BY level <= 1",
            &[],
            32,
            &SerializeOptions::default(),
        )
        .await
        .expect("driver-cx unplanned stream start")
    {
        QueryRowStreamStart::Fallback { reason } => assert_eq!(
            reason, "statement needs the uncached cursor-chunked path",
            "unplanned shape falls back for the documented reason"
        ),
        QueryRowStreamStart::Stream(_) => {
            panic!("driver-cx streamed a statement with no read plan")
        }
    }
    assert_stream_parity(
        cx,
        driver,
        official,
        "parity_stream_empty",
        "SELECT level AS V FROM dual WHERE 1 = 0 CONNECT BY level <= 1",
        Vec::new(),
    )
    .await;
    let expected = (1..=1000)
        .map(|value| json!({"V": value.to_string()}))
        .collect();
    assert_stream_parity(
        cx,
        driver,
        official,
        "parity_stream_ordered_1000_rows",
        "SELECT level AS V FROM dual CONNECT BY level <= 1000 ORDER BY level",
        expected,
    )
    .await;
    for (case_id, cancel) in [
        ("parity_stream_early_drop_no_stale_reuse", false),
        ("parity_stream_cancel_no_stale_reuse", true),
    ] {
        let abandoned_driver = connect_backend(cx, options, OracleBackend::RustOracle).await;
        followup_after_abandoned_stream(cx, &*abandoned_driver, options, case_id, cancel).await;
        drop(abandoned_driver);
        let abandoned_official = connect_backend(cx, options, OracleBackend::OfficialOracle).await;
        followup_after_abandoned_stream(cx, &*abandoned_official, options, case_id, cancel).await;
        drop(abandoned_official);
    }
}

fn serialized_single_row_with_options(
    rows: Vec<oraclemcp_db::OracleRow>,
    label: &str,
    options: &SerializeOptions,
) -> Value {
    assert_eq!(rows.len(), 1, "{label} must return one row");
    serialize_row(&rows[0], options)
}

async fn run_datetime_interval_scenario(
    cx: &Cx,
    driver: &dyn OracleConnection,
    official: &dyn OracleConnection,
    run_id: &str,
) {
    let table = parity_table(run_id, "DT");
    let create = format!(
        "CREATE TABLE {table} (ID NUMBER PRIMARY KEY, D_VAL DATE, TS_VAL TIMESTAMP(9), TSLTZ_VAL TIMESTAMP(9) WITH LOCAL TIME ZONE, IYM_VAL INTERVAL YEAR(4) TO MONTH, IDS_VAL INTERVAL DAY(4) TO SECOND(9))"
    );
    assert_write_and_ddl_classification(&create, &format!("INSERT INTO {table} (ID) VALUES (0)"));
    driver
        .execute(cx, &create, &[])
        .await
        .expect("create run-owned datetime parity table");
    let result = async {
        for connection in [driver, official] {
            connection.execute(cx, "ALTER SESSION SET TIME_ZONE = '+05:45'", &[]).await.expect("pin session zone");
            for statement in oraclemcp_db::canonical_nls_statements() {
                connection.execute(cx, statement, &[]).await.expect("pin parity NLS");
            }
        }
        let rows = [
            (1, "DATE '0001-01-01'", "TIMESTAMP '2026-01-01 00:00:00'", "INTERVAL '2-3' YEAR TO MONTH", "INTERVAL '3 04:05:06.123456789' DAY(4) TO SECOND(9)"),
            (2, "DATE '9999-12-31'", "TIMESTAMP '2020-02-29 12:34:56.123456789'", "INTERVAL '-2-3' YEAR TO MONTH", "INTERVAL '-3 04:05:06.123456789' DAY(4) TO SECOND(9)"),
        ];
        for (id, date, timestamp, ym, ds) in rows {
            let insert = format!("INSERT INTO {table} VALUES ({id}, {date}, {timestamp}, TO_TIMESTAMP_TZ('2026-01-01 00:00:00 +00:00','YYYY-MM-DD HH24:MI:SS TZH:TZM'), {ym}, {ds})");
            driver.execute(cx, &insert, &[]).await.expect("seed datetime parity row");
        }
        driver.execute(cx, &format!("INSERT INTO {table} (ID) VALUES (3)"), &[]).await.expect("seed typed NULL row");
        for digits in 0..=9 {
            let fraction = "123456789"[..digits].to_owned();
            let timestamp = if digits == 0 { "TIMESTAMP '2026-01-01 00:00:00'".to_owned() } else { format!("TIMESTAMP '2026-01-01 00:00:00.{fraction}'") };
            driver.execute(cx, &format!("INSERT INTO {table} (ID, TS_VAL) VALUES ({}, {timestamp})", digits + 10), &[]).await.expect("seed fractional TIMESTAMP");
        }
        driver.commit(cx).await.expect("commit datetime parity fixture");
        let defaults = SerializeOptions::default();
        for (id, expected) in [(1, "0001-01-01T00:00:00"), (2, "9999-12-31T00:00:00")] {
            assert_parity_cell(cx, driver, official, ("parity_date_min_max", "DATE"), &format!("SELECT D_VAL AS V FROM {table} WHERE ID={id}"), json!(expected), &defaults).await;
        }
        for digits in 0..=9 {
            let fraction = &"123456789"[..digits];
            let expected = if digits == 0 { "2026-01-01T00:00:00".to_owned() } else { format!("2026-01-01T00:00:00.{fraction:0<9}") };
            assert_parity_cell(cx, driver, official, ("parity_timestamp_fractional_0_to_9", "TIMESTAMP"), &format!("SELECT TS_VAL AS V FROM {table} WHERE ID={}", digits + 10), json!(expected), &defaults).await;
        }
        assert_parity_cell(cx, driver, official, ("parity_timestamp_no_utc_suffix", "TIMESTAMP"), &format!("SELECT TS_VAL AS V FROM {table} WHERE ID=2"), json!("2020-02-29T12:34:56.123456789"), &defaults).await;
        assert_parity_cell(cx, driver, official, ("parity_tsltz_session_zone", "SESSIONTIMEZONE"), "SELECT SESSIONTIMEZONE AS V FROM dual", json!("+05:45"), &defaults).await;
        assert_parity_cell(cx, driver, official, ("parity_tsltz_session_zone", "TO_CHAR(TSLTZ)"), &format!("SELECT TO_CHAR(TSLTZ_VAL,'YYYY-MM-DD HH24:MI:SS.FF9') AS V FROM {table} WHERE ID=1"), json!("2026-01-01 05:45:00.000000000"), &defaults).await;
        assert_parity_cell(cx, driver, official, ("parity_tsltz_session_zone", "TIMESTAMP WITH LOCAL TIME ZONE"), &format!("SELECT TSLTZ_VAL AS V FROM {table} WHERE ID=1"), json!("2026-01-01T05:45:00+05:45"), &defaults).await;
        for (id, expected) in [(1, "2-3"), (2, "-2--3")] {
            assert_parity_cell(cx, driver, official, ("parity_interval_ym_signed", "INTERVAL YEAR TO MONTH"), &format!("SELECT IYM_VAL AS V FROM {table} WHERE ID={id}"), json!(expected), &defaults).await;
        }
        for (id, expected) in [(1, "3 04:05:06.123456789"), (2, "-3 04:05:06.123456789")] {
            assert_parity_cell(cx, driver, official, ("parity_interval_ds_signed", "INTERVAL DAY TO SECOND"), &format!("SELECT IDS_VAL AS V FROM {table} WHERE ID={id}"), json!(expected), &defaults).await;
        }
        for (column, kind) in [("D_VAL", "DATE"), ("TS_VAL", "TIMESTAMP"), ("TSLTZ_VAL", "TIMESTAMP WITH LOCAL TIME ZONE"), ("IYM_VAL", "INTERVAL YEAR TO MONTH"), ("IDS_VAL", "INTERVAL DAY TO SECOND")] {
            assert_parity_cell(cx, driver, official, ("parity_typed_null_every_type", kind), &format!("SELECT {column} AS V FROM {table} WHERE ID=3"), Value::Null, &defaults).await;
        }
    }.await;
    driver
        .execute(cx, &format!("DROP TABLE {table} PURGE"), &[])
        .await
        .expect("drop run-owned datetime parity table");
    result
}

fn cell_digest(cell: &oraclemcp_db::OracleCell) -> Value {
    let bytes = cell
        .bytes
        .as_deref()
        .unwrap_or_else(|| cell.value.as_deref().unwrap_or("").as_bytes());
    digest_bytes(bytes)
}

fn digest_bytes(bytes: &[u8]) -> Value {
    let digest: String = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    json!({ "length": bytes.len(), "sha256": digest })
}

async fn run_lob_null_scenario(
    cx: &Cx,
    driver: &dyn OracleConnection,
    official: &dyn OracleConnection,
    run_id: &str,
) {
    let table = parity_table(run_id, "LOB");
    let source = format!("W4O_{run_id}.T_TYPES_{run_id}");
    let create = format!("CREATE TABLE {table} (ID NUMBER PRIMARY KEY, C_VAL CLOB, B_VAL BLOB)");
    driver
        .execute(cx, &create, &[])
        .await
        .expect("create run-owned LOB parity table");
    let result = async {
        for (id, clob, blob) in [
            (1, "EMPTY_CLOB()", "EMPTY_BLOB()"),
            (2, "TO_CLOB('ascii')", "TO_BLOB(HEXTORAW('00FF7F'))"),
            (3, "TO_CLOB(UNISTR('\\0646\\4EEE'))", "TO_BLOB(HEXTORAW('C3A9'))"),
        ] {
            driver.execute(cx, &format!("INSERT INTO {table} VALUES ({id}, {clob}, {blob})"), &[]).await.expect("seed LOB row");
        }
        driver.execute(cx, &format!("INSERT INTO {table} SELECT 4, C_VAL, B_VAL FROM {source} WHERE ID=1"), &[]).await.expect("copy run-owned large LOB seed");
        driver.execute(cx, &format!("INSERT INTO {table} (ID) VALUES (5)"), &[]).await.expect("seed LOB typed NULLs");
        driver.commit(cx).await.expect("commit LOB parity fixture");
        let opts = SerializeOptions { max_lob_chars: 1024, max_blob_bytes: 1024, ..Default::default() };
        let read_opts = SerializeOptions { max_lob_chars: 40_000, max_blob_bytes: 40_000, ..Default::default() };
        for (column, kind, id, expected) in [
            ("C_VAL", "CLOB", 1, json!("")),
            ("C_VAL", "CLOB", 2, json!("ascii")),
            ("C_VAL", "CLOB", 3, json!("ن仮")),
            ("C_VAL", "CLOB", 4, json!({"value": "c".repeat(1024), "truncated": true, "char_length": 33000})),
            ("B_VAL", "BLOB", 1, json!({"encoding":"base64","data":"","byte_length":0,"truncated":false})),
            ("B_VAL", "BLOB", 2, json!({"encoding":"base64","data":"AP9/","byte_length":3,"truncated":false})),
            ("B_VAL", "BLOB", 3, json!({"encoding":"base64","data":"w6k=","byte_length":2,"truncated":false})),
            ("B_VAL", "BLOB", 4, json!({"encoding":"base64","data":oraclemcp_db::base64_encode(&vec![b'b';1024]),"byte_length":33000,"truncated":true})),
        ] {
            let case_id = if kind == "CLOB" { "parity_clob_empty_ascii_multibyte_large" } else { "parity_blob_empty_small_large" };
            let sql = format!("SELECT {column} AS V FROM {table} WHERE ID={id}");
            let driver_rows = driver.query_rows_with_serialize_options(cx, &sql, &[], &read_opts).await.expect("driver LOB query");
            let official_rows = official.query_rows_with_serialize_options(cx, &sql, &[], &read_opts).await.expect("official LOB query");
            assert_eq!(driver_rows.len(), 1);
            assert_eq!(official_rows.len(), 1);
            let d_cell = &driver_rows[0].columns[0].1;
            let o_cell = &official_rows[0].columns[0].1;
            let d_digest = cell_digest(d_cell);
            let o_digest = cell_digest(o_cell);
            let expected_content = match (kind, id) {
                (_, 1) => Vec::new(),
                ("CLOB", 2) => b"ascii".to_vec(),
                ("CLOB", 3) => "ن仮".as_bytes().to_vec(),
                ("CLOB", 4) => vec![b'c'; 33_000],
                ("BLOB", 2) => vec![0, 255, 127],
                ("BLOB", 3) => vec![0xC3, 0xA9],
                ("BLOB", 4) => vec![b'b'; 33_000],
                _ => unreachable!("only seeded LOB cases are covered"),
            };
            let expected_digest = digest_bytes(&expected_content);
            parity_record(case_id, &format!("{kind} content digest"), "driver-cx", &expected_digest, &d_digest);
            parity_record(case_id, &format!("{kind} content digest"), "official", &expected_digest, &o_digest);
            assert_eq!(d_digest, expected_digest, "{case_id}: driver full content digest");
            assert_eq!(o_digest, expected_digest, "{case_id}: official full content digest");
            let d_value = serialize_row(&driver_rows[0], &opts)["V"].clone();
            let o_value = serialize_row(&official_rows[0], &opts)["V"].clone();
            parity_record(case_id, kind, "driver-cx", &expected, &d_value);
            parity_record(case_id, kind, "official", &expected, &o_value);
            assert_eq!(d_value, expected, "{case_id}: driver preview");
            assert_eq!(o_value, expected, "{case_id}: official preview");
        }
        for (column, kind) in [("C_VAL", "CLOB"), ("B_VAL", "BLOB")] {
            assert_parity_cell(cx, driver, official, ("parity_typed_null_every_type", kind), &format!("SELECT {column} AS V FROM {table} WHERE ID=5"), Value::Null, &opts).await;
        }
    }.await;
    driver
        .execute(cx, &format!("DROP TABLE {table} PURGE"), &[])
        .await
        .expect("drop run-owned LOB parity table");
    result
}

/// The live FREE 23ai proof for the shared `OracleConnection` observations.
#[test]
fn live_cross_backend_number_and_streaming_parity() {
    if !lab_ready("live_cross_backend_number_and_streaming_parity", &[]) {
        return;
    }
    run_with_cx(|cx| async move {
        let options = local_lab_options();
        let driver_cx = RustOracleConnection::connect(&cx, options.clone())
            .await
            .expect("driver-cx must connect to the explicit local lab");
        let official = OfficialOracleConnection::connect(&cx, options.clone())
            .await
            .expect("official adapter must connect to the explicit local lab");
        let run_id = required_lab_env("ORACLEMCP_PARITY_RUN_ID");

        assert_eq!(driver_cx.backend(), OracleBackend::RustOracle);
        assert_eq!(official.backend(), OracleBackend::OfficialOracle);
        run_number_boundary_scenario(&cx, &driver_cx, &official, &run_id).await;
        run_streaming_scenario(&cx, &driver_cx, &official, &options).await;

        driver_cx.close(&cx).await.expect("driver-cx close");
        official.close(&cx).await.expect("official close");
    });
}

#[test]
fn live_cross_backend_parity_for_supported_basic_auth() {
    if !lab_ready("live_cross_backend_parity_for_supported_basic_auth", &[]) {
        return;
    }
    run_with_cx(|cx| async move {
        let options = local_lab_options();
        let driver_cx = RustOracleConnection::connect(&cx, options.clone())
            .await
            .expect("driver-cx must connect to the explicit local lab");
        let official = OfficialOracleConnection::connect(&cx, options.clone())
            .await
            .expect("official adapter must connect to the explicit local lab");

        assert_eq!(driver_cx.backend(), OracleBackend::RustOracle);
        assert_eq!(official.backend(), OracleBackend::OfficialOracle);
        driver_cx.ping(&cx).await.expect("driver-cx ping");
        official.ping(&cx).await.expect("official ping");
        let driver_info = driver_cx.describe(&cx).await.expect("driver-cx describe");
        let official_info = official.describe(&cx).await.expect("official describe");
        assert_eq!(
            driver_info.server_version, official_info.server_version,
            "server version observed at connect"
        );
        assert_eq!(
            driver_info.session_user, official_info.session_user,
            "session user observed at connect"
        );
        assert_eq!(
            driver_info.current_schema, official_info.current_schema,
            "current schema observed at connect"
        );

        let driver_scalar = serialized_single_row(
            driver_cx
                .query_rows(&cx, NUMBER_AND_TSTZ_SQL, &[])
                .await
                .expect("driver-cx NUMBER/TSTZ query"),
            "driver-cx NUMBER/TSTZ",
        );
        let official_scalar = serialized_single_row(
            official
                .query_rows(&cx, NUMBER_AND_TSTZ_SQL, &[])
                .await
                .expect("official NUMBER/TSTZ query"),
            "official NUMBER/TSTZ",
        );
        assert_eq!(driver_scalar, official_scalar, "NUMBER/TSTZ serialization");
        assert_eq!(
            official_scalar["NUMBER_38"], "12345678901234567890123456789012345678",
            "NUMBER must remain the exact decimal string"
        );

        let driver_timezone_less = serialized_single_row(
            driver_cx
                .query_rows(&cx, DATE_AND_PLAIN_TIMESTAMP_SQL, &[])
                .await
                .expect("driver-cx DATE/plain-TIMESTAMP query"),
            "driver-cx DATE/plain-TIMESTAMP",
        );
        let official_timezone_less = serialized_single_row(
            official
                .query_rows(&cx, DATE_AND_PLAIN_TIMESTAMP_SQL, &[])
                .await
                .expect("official DATE/plain-TIMESTAMP query"),
            "official DATE/plain-TIMESTAMP",
        );
        assert_eq!(
            driver_timezone_less, official_timezone_less,
            "DATE/plain-TIMESTAMP serialization"
        );
        assert_eq!(
            official_timezone_less["PLAIN_DATE"], "2026-06-01T12:00:00",
            "DATE must not gain a UTC suffix"
        );
        assert_eq!(
            official_timezone_less["PLAIN_TIMESTAMP"], "2026-06-01T12:00:00.123456789",
            "plain TIMESTAMP must not gain a UTC suffix"
        );

        let run_id = required_lab_env("ORACLEMCP_PARITY_RUN_ID");
        run_number_boundary_scenario(&cx, &driver_cx, &official, &run_id).await;
        run_streaming_scenario(&cx, &driver_cx, &official, &options).await;
        run_datetime_interval_scenario(&cx, &driver_cx, &official, &run_id).await;
        run_lob_null_scenario(&cx, &driver_cx, &official, &run_id).await;
        let suffix = run_id;
        let vector_lab = server_supports_vector(driver_info.server_version.as_deref());
        if vector_lab {
            let driver_vector_table = format!("W4O_{suffix}.ORACLEMCP_PARITY_VEC_CX_{suffix}");
            let official_vector_table =
                format!("W4O_{suffix}.ORACLEMCP_PARITY_VEC_OFFICIAL_{suffix}");
            let driver_dense_vector =
                run_dense_vector_scenario(&cx, &driver_cx, &driver_vector_table).await;
            let official_dense_vector =
                run_dense_vector_scenario(&cx, &official, &official_vector_table).await;
            assert_eq!(
                driver_dense_vector, official_dense_vector,
                "dense VECTOR serialization"
            );
        } else {
            eprintln!(
                "[parity] SKIP dense and sparse VECTOR on {:?}: VECTOR needs Oracle 23ai",
                driver_info.server_version
            );
        }

        for (label, sql) in [("sparse VECTOR", SPARSE_VECTOR_SQL)]
            .into_iter()
            .filter(|_| vector_lab)
        {
            let driver_vector = serialized_single_row(
                driver_cx
                    .query_rows(&cx, sql, &[])
                    .await
                    .unwrap_or_else(|error| panic!("driver-cx {label} query: {error}")),
                &format!("driver-cx {label}"),
            );
            let official_vector = serialized_single_row(
                official
                    .query_rows(&cx, sql, &[])
                    .await
                    .unwrap_or_else(|error| panic!("official {label} query: {error}")),
                &format!("official {label}"),
            );
            assert_eq!(driver_vector, official_vector, "{label} serialization");
        }

        let missing_object_sql = "SELECT * FROM ORACLEMCP_PARITY_MISSING_OBJECT_7E1A";
        let driver_error = driver_cx
            .query_rows(&cx, missing_object_sql, &[])
            .await
            .expect_err("driver-cx missing-object query must fail");
        let official_error = official
            .query_rows(&cx, missing_object_sql, &[])
            .await
            .expect_err("official missing-object query must fail");
        assert_eq!(
            missing_object_facts(driver_error),
            missing_object_facts(official_error),
            "missing-object error envelope"
        );

        let driver_table = format!("W4O_{suffix}.ORACLEMCP_PARITY_CX_{suffix}");
        let official_table = format!("W4O_{suffix}.ORACLEMCP_PARITY_OFFICIAL_{suffix}");
        let driver_transaction = run_transaction_scenario(&cx, &driver_cx, &driver_table).await;
        let official_transaction = run_transaction_scenario(&cx, &official, &official_table).await;
        assert_eq!(
            driver_transaction, official_transaction,
            "DDL execution plus DML rollback/commit observations"
        );

        // Oracle's DATE lower boundary is BC, beyond driver-cx's current
        // 1..=9999 wire decoder. Keep this live assertion red until the
        // discovered driver bug rust-oracledb-dhgs is fixed and pinned.
        assert_parity_cell(
            &cx,
            &driver_cx,
            &official,
            ("parity_date_min_max", "DATE"),
            "SELECT TO_DATE('4712-01-01 BC','YYYY-MM-DD BC') AS V FROM dual",
            json!("-4712-01-01T00:00:00"),
            &SerializeOptions::default(),
        )
        .await;

        driver_cx.close(&cx).await.expect("driver-cx close");
        official.close(&cx).await.expect("official close");
    });
}

/// Establish only password-authenticated TCPS plus PEM-wallet sessions. This
/// intentionally does not exercise the cwallet.sso/IAM routes, which remain
/// driver-cx capabilities by contract.
#[test]
fn live_cross_backend_tcps_pem_connection_parity() {
    if !live_env_ready(
        &process_env,
        &TCPS_PEM_ENV,
        "live_cross_backend_tcps_pem_connection_parity",
    ) {
        return;
    }
    run_with_cx(|cx| async move {
        let options = tcps_pem_lab_options();
        assert_eq!(
            select_connection_backend(&options),
            OracleBackend::RustOracle,
            "mutable PEM wallet acquisition remains driver-cx-primary"
        );

        let driver_cx = RustOracleConnection::connect(&cx, options.clone())
            .await
            .expect("driver-cx must connect to the explicit TCPS PEM lab");
        let official = OfficialOracleConnection::connect(&cx, options)
            .await
            .expect("official adapter must connect to the explicit TCPS PEM lab");
        driver_cx.ping(&cx).await.expect("driver-cx TCPS PEM ping");
        official.ping(&cx).await.expect("official TCPS PEM ping");

        let driver_info = driver_cx
            .describe(&cx)
            .await
            .expect("driver-cx TCPS PEM identity");
        let official_info = official
            .describe(&cx)
            .await
            .expect("official TCPS PEM identity");
        assert_eq!(
            driver_info.server_version, official_info.server_version,
            "TCPS PEM server version"
        );
        assert_eq!(
            driver_info.session_user, official_info.session_user,
            "TCPS PEM session user"
        );
        assert_eq!(
            driver_info.current_schema, official_info.current_schema,
            "TCPS PEM current schema"
        );

        official.close(&cx).await.expect("official TCPS PEM close");
        driver_cx
            .close(&cx)
            .await
            .expect("driver-cx TCPS PEM close");
    });
}

/// Run-stamped PL/SQL objects in the disposable W4 owner schema: a function
/// and a procedure with NUMBER and VARCHAR2 OUT parameters.
fn plsql_parity_names(run_id: &str) -> (String, String) {
    validate_parity_run_id(run_id);
    (
        format!("W4O_{run_id}.ORACLEMCP_PARITY_FN_{run_id}"),
        format!("W4O_{run_id}.ORACLEMCP_PARITY_PROC_{run_id}"),
    )
}

async fn run_plsql_parity_scenario(
    cx: &Cx,
    driver_cx: &dyn OracleConnection,
    official: &dyn OracleConnection,
    run_id: &str,
) {
    let (function, procedure) = plsql_parity_names(run_id);
    driver_cx
        .execute(
            cx,
            &format!(
                "CREATE OR REPLACE FUNCTION {function}(n NUMBER) RETURN NUMBER AS \
                 BEGIN RETURN n * 2; END;"
            ),
            &[],
        )
        .await
        .expect("create the run-owned parity function");
    driver_cx
        .execute(
            cx,
            &format!(
                "CREATE OR REPLACE PROCEDURE {procedure}(n IN NUMBER, s IN VARCHAR2, \
                 r OUT NUMBER, t OUT VARCHAR2) AS BEGIN r := n * 2; t := s || '-ok'; END;"
            ),
            &[],
        )
        .await
        .expect("create the run-owned parity procedure");

    let outcome: Result<(), String> = async {
        let select_sql = format!("SELECT {function}(41) AS V FROM dual");
        let mut selected = Vec::new();
        for (backend, connection) in [("driver-cx", driver_cx), ("official", official)] {
            let rows = connection
                .query_rows(cx, &select_sql, &[])
                .await
                .map_err(|error| format!("{backend} SELECT fn(41): {error}"))?;
            let value = serialized_single_row(rows, backend);
            parity_record(
                "parity_plsql_function",
                "NUMBER",
                backend,
                &json!("82"),
                &value["V"],
            );
            selected.push(value);
        }
        if selected[0] != selected[1] || selected[0]["V"] != json!("82") {
            return Err(format!("SELECT fn(41) differs: {selected:?}"));
        }

        let block = format!("BEGIN {procedure}(:1, :2, :3, :4); END;");
        let mut outs = Vec::new();
        for (backend, connection) in [("driver-cx", driver_cx), ("official", official)] {
            let args = [
                OracleRoutineArg::input(OracleBind::I64(41)).expect("NUMBER input"),
                OracleRoutineArg::input(OracleBind::String("parity".to_owned()))
                    .expect("VARCHAR2 input"),
                OracleRoutineArg::output(2, 1, 22),
                OracleRoutineArg::output(1, 1, 64),
            ];
            let outcome = connection
                .call_routine(cx, &block, &args)
                .await
                .map_err(|error| format!("{backend} OUT-bind call: {error}"))?;
            let cells = serde_json::to_value(outcome.out_binds()).expect("serialize OUT cells");
            parity_record(
                "parity_plsql_out_bind",
                "NUMBER,VARCHAR2",
                backend,
                &json!(["82", "parity-ok"]),
                &cells,
            );
            outs.push(cells);
        }
        let values: Vec<Value> = outs[0]
            .as_array()
            .map(|cells| cells.iter().map(|cell| cell["value"].clone()).collect())
            .unwrap_or_default();
        if outs[0] != outs[1] || values != [json!("82"), json!("parity-ok")] {
            return Err(format!("OUT binds differ: {outs:?}"));
        }

        // An OUT kind the official adapter cannot decode exactly is a typed
        // refusal made before any round trip, never a guessed value.
        match official
            .call_routine(
                cx,
                "BEGIN :1 := SYSDATE; END;",
                &[OracleRoutineArg::output(12, 0, 7)],
            )
            .await
        {
            Err(DbError::UnsupportedFeature(message))
                if message.contains("NUMBER and VARCHAR2") => {}
            other => {
                return Err(format!(
                    "official DATE OUT bind was not refused typed: {:?}",
                    other.map(|outcome| outcome.out_binds().to_vec())
                ));
            }
        }
        Ok(())
    }
    .await;

    for object in [
        format!("FUNCTION {function}"),
        format!("PROCEDURE {procedure}"),
    ] {
        driver_cx
            .execute(cx, &format!("DROP {object}"), &[])
            .await
            .expect("drop the run-owned parity PL/SQL object");
    }
    outcome.unwrap_or_else(|failure| panic!("PL/SQL parity: {failure}"));
}

#[test]
fn parity_plsql_function_and_out_bind() {
    if !lab_ready("parity_plsql_function_and_out_bind", &[]) {
        return;
    }
    run_with_cx(|cx| async move {
        let options = local_lab_options();
        let driver_cx = RustOracleConnection::connect(&cx, options.clone())
            .await
            .expect("driver-cx must connect to the explicit local lab");
        let official = OfficialOracleConnection::connect(&cx, options)
            .await
            .expect("official adapter must connect to the explicit local lab");
        let run_id = required_lab_env("ORACLEMCP_PARITY_RUN_ID");
        run_plsql_parity_scenario(&cx, &driver_cx, &official, &run_id).await;
        driver_cx.close(&cx).await.expect("driver-cx close");
        official.close(&cx).await.expect("official close");
    });
}

#[test]
fn parity_suite_fails_when_required_env_missing() {
    let none = |_: &str| None;
    assert!(
        !live_env_ready(&none, &LAB_ENV, "probe"),
        "an incomplete environment without ORACLEMCP_REQUIRE_LIVE is a skip"
    );
    let required_only = |name: &str| (name == "ORACLEMCP_REQUIRE_LIVE").then(|| "1".to_owned());
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        live_env_ready(&required_only, &LAB_ENV, "probe")
    }))
    .expect_err("ORACLEMCP_REQUIRE_LIVE=1 with no DSN must fail, not skip");
    let message = failure
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_default();
    assert!(
        message.contains("ORACLEMCP_TEST_DSN"),
        "the failure names the missing variable: {message}"
    );
    let blank_dsn = |name: &str| match name {
        "ORACLEMCP_REQUIRE_LIVE" => Some("1".to_owned()),
        "ORACLEMCP_TEST_DSN" => Some(String::new()),
        _ => Some("set".to_owned()),
    };
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            live_env_ready(&blank_dsn, &LAB_ENV, "probe")
        }))
        .is_err(),
        "an empty value counts as missing"
    );
    let complete = |name: &str| Some(format!("value-for-{name}"));
    assert!(live_env_ready(&complete, &LAB_ENV, "probe"));
}

/// An endpoint nothing listens on: a refusal must come before any network use.
const UNREACHABLE_DSN: &str = "127.0.0.1:9/ORACLEMCP_PARITY_UNREACHABLE";

fn assert_official_refusal(options: OracleConnectOptions, expected: &'static str) {
    run_with_cx(|cx| async move {
        let error = match OfficialOracleConnection::connect(&cx, options).await {
            Ok(_) => panic!("official adapter accepted an unsupported auth form"),
            Err(error) => error,
        };
        match &error {
            DbError::UnsupportedAuth(message) => assert_eq!(message, expected),
            other => panic!("expected a typed UnsupportedAuth refusal, got {other:?}"),
        }
        assert_eq!(
            error.into_envelope().error_class,
            oraclemcp_error::ErrorClass::InvalidArguments
        );
    });
}

#[test]
fn official_adapter_refuses_sso_wallet_typed() {
    let sso = tempfile::tempdir().expect("temp wallet dir");
    std::fs::write(sso.path().join("cwallet.sso"), b"synthetic").expect("synthetic sso");
    let pem = tempfile::tempdir().expect("temp wallet dir");
    std::fs::write(pem.path().join("ewallet.pem"), b"synthetic").expect("synthetic pem");
    let options_for = |wallet: &std::path::Path| OracleConnectOptions {
        connect_string: UNREACHABLE_DSN.to_owned(),
        username: Some("parity".to_owned()),
        password: Some("synthetic".to_owned()),
        wallet_location: Some(wallet.to_path_buf()),
        ..Default::default()
    };
    for wallet in [sso.path(), pem.path()] {
        assert_eq!(
            select_connection_backend(&options_for(wallet)),
            OracleBackend::RustOracle,
            "wallet acquisition stays driver-cx-primary"
        );
    }
    assert_official_refusal(
        options_for(sso.path()),
        "official Oracle backend does not support cwallet.sso auto-login wallets",
    );
}

#[test]
fn official_adapter_refuses_iam_token_typed() {
    let options = OracleConnectOptions {
        connect_string: UNREACHABLE_DSN.to_owned(),
        use_iam_token: true,
        ..Default::default()
    };
    assert_eq!(
        select_connection_backend(&options),
        OracleBackend::RustOracle,
        "IAM token auth stays driver-cx-primary"
    );
    assert_official_refusal(
        options,
        "official Oracle backend does not support IAM or OAuth database tokens",
    );
}

#[test]
fn vector_gate_follows_the_server_major_version() {
    for version in ["23.26.2.0.0", "23.0.0.0.0", "26.1.0.0.0"] {
        assert!(server_supports_vector(Some(version)), "{version}");
    }
    for version in ["21.3.0.0.0", "18.4.0.0.0", "19.27.0.0.0"] {
        assert!(!server_supports_vector(Some(version)), "{version}");
    }
    for unknown in [None, Some(""), Some("unknown")] {
        assert!(
            std::panic::catch_unwind(|| server_supports_vector(unknown)).is_err(),
            "an unparsable version must fail, not skip: {unknown:?}"
        );
    }
}
