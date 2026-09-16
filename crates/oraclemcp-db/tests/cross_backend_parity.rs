//! Cross-backend OracleConnection parity evidence.
//!
//! This target is compiled only when both the feature-gated official adapter and
//! the local Oracle lab lane are requested. The test itself is ignored unless
//! explicitly selected because it connects to the local Free23 fixture and
//! creates short-lived, uniquely named tables. It is not a self-skipping live
//! claim: missing opt-in environment is an error when the ignored test is run.
//!
//! Run after `scripts/rig/oracle_l1.sh run --log` with:
//!
//! ```text
//! ORACLEMCP_DUAL_BACKEND_LAB=1 \
//! ORACLEMCP_TEST_DSN=//localhost:1522/FREEPDB1 \
//! ORACLEMCP_TEST_USER=pythontest \
//! ORACLEMCP_TEST_PASSWORD=<local-lab-password> \
//! cargo test -p oraclemcp-db --features oracledb,live-xe \
//!   --test cross_backend_parity -- --ignored --exact
//! ```
//!
//! The deterministic, feature-on VECTOR projection test remains next to the
//! official adapter. This target is the live proof for behavior requiring a
//! real Oracle: independent backend connections, NUMBER/TSTZ/VECTOR decoding,
//! DML rollback/commit, DDL execution after classifier admission, and Oracle
//! error-envelope equivalence.

#![cfg(all(feature = "oracledb", feature = "live-xe"))]
#![forbid(unsafe_code)]

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use oraclemcp_db::{
    DbError, OfficialOracleConnection, OracleBackend, OracleConnectOptions, OracleConnection,
    RustOracleConnection, SerializeOptions, serialize_row,
};
use oraclemcp_guard::{Classifier, DangerLevel, OperatingLevel};
use serde_json::Value;

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

fn required_lab_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!(
            "cross-backend lab was explicitly selected but {name} is unset; \
             do not treat an unconfigured target as a parity result"
        )
    })
}

fn local_lab_options() -> OracleConnectOptions {
    assert_eq!(
        required_lab_env("ORACLEMCP_DUAL_BACKEND_LAB"),
        "1",
        "set ORACLEMCP_DUAL_BACKEND_LAB=1 to acknowledge the local DDL/DML fixture"
    );
    OracleConnectOptions {
        connect_string: required_lab_env("ORACLEMCP_TEST_DSN"),
        username: Some(required_lab_env("ORACLEMCP_TEST_USER")),
        password: Some(required_lab_env("ORACLEMCP_TEST_PASSWORD")),
        ..Default::default()
    }
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

/// The feature-on, local-Free23 proof for the shared `OracleConnection`
/// observations. This is intentionally ignored in ordinary test lanes rather
/// than self-skipping: an operator must opt into the lab and capture its output.
#[test]
#[ignore = "requires explicit local Oracle Free23 lab credentials and DDL/DML acknowledgement"]
fn live_cross_backend_parity_for_supported_basic_auth() {
    run_with_cx(|cx| async move {
        let options = local_lab_options();
        let driver_cx = RustOracleConnection::connect(&cx, options.clone())
            .await
            .expect("driver-cx must connect to the explicit local lab");
        let official = OfficialOracleConnection::connect(&cx, options)
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

        let suffix = std::process::id();
        let driver_vector_table = format!("ORACLEMCP_PARITY_VEC_CX_{suffix}");
        let official_vector_table = format!("ORACLEMCP_PARITY_VEC_OFFICIAL_{suffix}");
        let driver_dense_vector =
            run_dense_vector_scenario(&cx, &driver_cx, &driver_vector_table).await;
        let official_dense_vector =
            run_dense_vector_scenario(&cx, &official, &official_vector_table).await;
        assert_eq!(
            driver_dense_vector, official_dense_vector,
            "dense VECTOR serialization"
        );

        for (label, sql) in [("sparse VECTOR", SPARSE_VECTOR_SQL)] {
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

        let driver_table = format!("ORACLEMCP_PARITY_CX_{suffix}");
        let official_table = format!("ORACLEMCP_PARITY_OFFICIAL_{suffix}");
        let driver_transaction = run_transaction_scenario(&cx, &driver_cx, &driver_table).await;
        let official_transaction = run_transaction_scenario(&cx, &official, &official_table).await;
        assert_eq!(
            driver_transaction, official_transaction,
            "DDL execution plus DML rollback/commit observations"
        );

        driver_cx.close(&cx).await.expect("driver-cx close");
        official.close(&cx).await.expect("official close");
    });
}
