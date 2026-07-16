//! Live Oracle XE coverage for the optional PL/SQL intelligence surface.
//!
//! Default builds compile only the gate assertion. The real scenario runs only
//! with both `live-xe` and `plsql-intelligence` enabled and follows the existing
//! live-suite convention: skip cleanly when no Oracle test database is reachable.

#![forbid(unsafe_code)]

#[cfg(not(all(feature = "live-xe", feature = "plsql-intelligence")))]
#[test]
fn plsql_live_xe_is_feature_gated() {
    let exe = std::env::current_exe().expect("current test binary path");
    let binary_name = exe
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    assert!(
        binary_name.contains("plsql_live_xe"),
        "the gate-off PL/SQL live-XE test binary should still run"
    );
}

#[cfg(all(feature = "live-xe", feature = "plsql-intelligence"))]
mod live {
    use std::collections::{BTreeMap, BTreeSet};
    use std::future::Future;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use asupersync::{Cx, runtime::RuntimeBuilder};
    use oraclemcp::dispatch::OracleDispatcher;
    use oraclemcp_db::{
        DbError, OracleBind, OracleConnectOptions, OracleConnection, OracleSessionIdentity,
        RustOracleConnection,
    };
    use serde_json::{Value, json};

    static SCRATCH_COUNTER: AtomicU32 = AtomicU32::new(0);

    const MODULE: &str = "oraclemcp-plsql-hero-live-xe-test";
    const DEFAULT_DSN: &str = "//localhost:1521/FREEPDB1";
    const DEFAULT_USER: &str = "system";
    const ORACLEMCP_SECRET_ENV: &str = concat!("ORACLEMCP_TEST_", "PASS", "WORD");
    const PLSQL_SECRET_ENV: &str = concat!("PLSQL_XE_SYSTEM_", "PASS", "WORD");

    #[test]
    fn hero_drop_column_runs_through_oraclemcp_live_plsql_tools() {
        let Some(admin) = connect_or_skip("hero_drop_column/admin") else {
            return;
        };
        let schema = hero_schema_name();
        if let Err(error) = create_scratch_schema(&admin, &schema) {
            eprintln!("[live-xe] SKIP hero_drop_column: {error}");
            return;
        }
        let guard = SchemaGuard {
            conn: admin,
            schema: schema.clone(),
        };

        provision_hero_corpus(&guard.conn, &schema);

        {
            let Some(read_conn) = connect_or_skip("hero_drop_column/before-tools") else {
                return;
            };
            let dispatcher = OracleDispatcher::new(Box::new(read_conn));
            assert_before_drop_tools(&dispatcher, &schema);
        }

        execute_sql(
            &guard.conn,
            &format!("ALTER TABLE {schema}.CUSTOMERS DROP COLUMN LEGACY_SEGMENT"),
        )
        .expect("hero DROP COLUMN DDL succeeds against the scratch schema");

        let Some(read_conn) = connect_or_skip("hero_drop_column/after-tools") else {
            return;
        };
        let dispatcher = OracleDispatcher::new(Box::new(read_conn));
        assert_after_drop_tools(&dispatcher, &schema);
    }

    #[test]
    fn oracle_lineage_live_catalog_marks_verified_missing_and_type_drift() {
        let Some(admin) = connect_or_skip("lineage_catalog_drift/admin") else {
            return;
        };
        let schema = hero_schema_name();
        if let Err(error) = create_scratch_schema(&admin, &schema) {
            eprintln!("[live-xe] SKIP lineage_catalog_drift: {error}");
            return;
        }
        let guard = SchemaGuard {
            conn: admin,
            schema: schema.clone(),
        };
        provision_lineage_catalog_drift_schema(&guard.conn, &schema);

        let project = tempfile::tempdir().expect("lineage source project");
        std::fs::write(
            project.path().join("lineage.sql"),
            format!(
                "CREATE TABLE {schema}.LINEAGE_OK (AMOUNT NUMBER);\n\
                 CREATE VIEW {schema}.V_LINEAGE_OK AS \
                 SELECT AMOUNT FROM {schema}.LINEAGE_OK;\n\
                 CREATE TABLE {schema}.LINEAGE_TYPE (AMOUNT NUMBER);\n\
                 CREATE VIEW {schema}.V_LINEAGE_TYPE AS \
                 SELECT AMOUNT FROM {schema}.LINEAGE_TYPE;\n\
                 CREATE TABLE {schema}.LINEAGE_GHOST (AMOUNT NUMBER);\n\
                 CREATE VIEW {schema}.V_LINEAGE_MISSING AS \
                 SELECT AMOUNT FROM {schema}.LINEAGE_GHOST;\n"
            ),
        )
        .expect("write source lineage fixture");

        let Some(read_conn) = connect_or_skip("lineage_catalog_drift/read") else {
            return;
        };
        let dispatcher = OracleDispatcher::new(Box::new(read_conn));
        let project_root = project.path().display().to_string();

        let verified = dispatch(
            &dispatcher,
            "oracle_lineage",
            json!({
                "project_root": project_root,
                "owner": schema,
                "object": "V_LINEAGE_OK",
                "column": "AMOUNT",
            }),
        );
        assert_eq!(verified["catalog_marker"]["status"], "verified");
        assert_lineage_edge_marker(&verified, "verified");

        let type_mismatch = dispatch(
            &dispatcher,
            "oracle_lineage",
            json!({
                "project_root": project.path().display().to_string(),
                "owner": schema,
                "object": "V_LINEAGE_TYPE",
                "column": "AMOUNT",
            }),
        );
        assert_eq!(
            type_mismatch["catalog_marker"]["status"], "drift:type_mismatch",
            "the source NUMBER must not be reported as verified against a live VARCHAR2 view: {type_mismatch}"
        );

        let missing = dispatch(
            &dispatcher,
            "oracle_lineage",
            json!({
                "project_root": project.path().display().to_string(),
                "owner": schema,
                "object": "V_LINEAGE_MISSING",
                "column": "AMOUNT",
            }),
        );
        assert_eq!(missing["catalog_marker"]["status"], "verified");
        assert_lineage_edge_marker(&missing, "drift:missing");
    }

    fn provision_lineage_catalog_drift_schema(conn: &RustOracleConnection, schema: &str) {
        for sql in [
            format!("CREATE TABLE {schema}.LINEAGE_OK (AMOUNT NUMBER)"),
            format!(
                "CREATE VIEW {schema}.V_LINEAGE_OK AS \
                 SELECT AMOUNT FROM {schema}.LINEAGE_OK"
            ),
            format!("CREATE TABLE {schema}.LINEAGE_TYPE (AMOUNT VARCHAR2(20))"),
            format!(
                "CREATE VIEW {schema}.V_LINEAGE_TYPE AS \
                 SELECT AMOUNT FROM {schema}.LINEAGE_TYPE"
            ),
            format!(
                "CREATE VIEW {schema}.V_LINEAGE_MISSING AS \
                 SELECT CAST(1 AS NUMBER) AS AMOUNT FROM DUAL"
            ),
        ] {
            execute_sql(conn, &sql).expect("provision live lineage catalog fixture");
        }
    }

    fn assert_lineage_edge_marker(value: &Value, expected_marker: &str) {
        let edges = value["upstream"]["edges"]
            .as_array()
            .expect("live lineage upstream edges");
        assert!(
            edges
                .iter()
                .any(|edge| { edge["catalog_marker"]["status"].as_str() == Some(expected_marker) }),
            "expected at least one upstream {expected_marker} marker: {value}"
        );
    }

    fn assert_before_drop_tools(dispatcher: &OracleDispatcher, schema: &str) {
        let statuses = object_statuses(dispatcher, schema);
        assert_eq!(
            statuses.get("CUSTOMERS::TABLE").map(String::as_str),
            Some("VALID")
        );
        assert_eq!(
            statuses
                .get("V_HIGH_VALUE_CUSTOMERS::VIEW")
                .map(String::as_str),
            Some("VALID")
        );
        assert_eq!(
            statuses
                .get("PKG_CUSTOMER_REPORT::PACKAGE")
                .map(String::as_str),
            Some("VALID")
        );
        assert_eq!(
            statuses
                .get("PKG_CUSTOMER_REPORT::PACKAGE BODY")
                .map(String::as_str),
            Some("VALID")
        );
        assert_eq!(
            statuses
                .get("PROC_SEGMENT_SUMMARY::PROCEDURE")
                .map(String::as_str),
            Some("VALID")
        );

        let columns = query(
            dispatcher,
            "SELECT column_name FROM all_tab_columns \
             WHERE owner = :1 AND table_name = 'CUSTOMERS' ORDER BY column_id",
            json!([schema]),
        );
        let column_names: BTreeSet<String> = rows(&columns)
            .iter()
            .filter_map(|row| string_cell(row, "COLUMN_NAME"))
            .map(str::to_owned)
            .collect();
        assert!(
            column_names.contains("LEGACY_SEGMENT"),
            "the hero corpus must expose the target column before DROP COLUMN: {column_names:?}"
        );

        let source = dispatch(
            dispatcher,
            "oracle_get_source",
            json!({
                "owner": schema,
                "name": "PKG_CUSTOMER_REPORT",
                "object_type": "PACKAGE BODY"
            }),
        );
        let body = source["source"]["source"]
            .as_str()
            .expect("oracle_get_source returns source text");
        assert!(
            body.to_ascii_uppercase().contains("LEGACY_SEGMENT"),
            "package body source must contain the target column reference"
        );

        let errors = dispatch(
            dispatcher,
            "oracle_compile_errors",
            json!({ "owner": schema, "name": "PKG_CUSTOMER_REPORT" }),
        );
        assert_eq!(
            errors["errors"]
                .as_array()
                .expect("compile errors array")
                .len(),
            0,
            "package compiles cleanly before the DROP COLUMN"
        );

        let snapshot = dispatch(
            dispatcher,
            "oracle_plsql_live_snapshot",
            json!({
                "schemas": [schema],
                "include_plscope": false,
                "include_snapshot": false
            }),
        );
        assert!(
            row_count(&snapshot, "objects") >= 4,
            "live snapshot sees the loaded PL/SQL hero objects: {snapshot}"
        );
        assert!(
            row_count(&snapshot, "columns") >= 7,
            "live snapshot sees the CUSTOMERS columns: {snapshot}"
        );
    }

    fn assert_after_drop_tools(dispatcher: &OracleDispatcher, schema: &str) {
        let statuses = object_statuses(dispatcher, schema);
        assert_eq!(
            statuses
                .get("V_HIGH_VALUE_CUSTOMERS::VIEW")
                .map(String::as_str),
            Some("INVALID"),
            "Oracle must invalidate the dependent view after DROP COLUMN"
        );
        assert_eq!(
            statuses
                .get("PKG_CUSTOMER_REPORT::PACKAGE")
                .map(String::as_str),
            Some("VALID"),
            "the package spec stays valid because it has no column reference"
        );
        assert_eq!(
            statuses
                .get("PKG_CUSTOMER_REPORT::PACKAGE BODY")
                .map(String::as_str),
            Some("INVALID"),
            "Oracle must invalidate the dependent package body after DROP COLUMN"
        );
        assert_eq!(
            statuses
                .get("PROC_SEGMENT_SUMMARY::PROCEDURE")
                .map(String::as_str),
            Some("INVALID"),
            "Oracle must invalidate the dependent procedure after DROP COLUMN"
        );

        let columns = query(
            dispatcher,
            "SELECT COUNT(*) AS col_count FROM all_tab_columns \
             WHERE owner = :1 AND table_name = 'CUSTOMERS' \
             AND column_name = 'LEGACY_SEGMENT'",
            json!([schema]),
        );
        assert_eq!(
            rows(&columns)
                .first()
                .and_then(|row| string_cell(row, "COL_COUNT")),
            Some("0"),
            "Oracle catalog must confirm LEGACY_SEGMENT is gone"
        );

        assert_matches_expected_dropcol_golden(&statuses);

        let blast = dispatch(
            dispatcher,
            "oracle_plsql_blast_radius",
            json!({
                "schemas": [schema],
                "include_plscope": false,
                "include_snapshot": false,
                "changeset": { "objects": [], "unclassified_files": [] },
                "mode": "live_snapshot"
            }),
        );
        assert_eq!(
            blast["prediction"]["schema_id"].as_str(),
            Some("plsql.cicd.change_impact"),
            "blast-radius response carries the plsql-cicd prediction envelope"
        );
        assert!(
            row_count(&blast["snapshot"], "objects") >= 4,
            "blast-radius response includes a live normalized snapshot: {blast}"
        );
    }

    fn object_statuses(dispatcher: &OracleDispatcher, schema: &str) -> BTreeMap<String, String> {
        let response = query(
            dispatcher,
            "SELECT object_name, object_type, status FROM all_objects \
             WHERE owner = :1 \
             AND object_name IN \
               ('CUSTOMERS', 'V_HIGH_VALUE_CUSTOMERS', \
                'PKG_CUSTOMER_REPORT', 'PROC_SEGMENT_SUMMARY') \
             ORDER BY object_type, object_name",
            json!([schema]),
        );
        let mut out = BTreeMap::new();
        for row in rows(&response) {
            let name = string_cell(row, "OBJECT_NAME")
                .expect("OBJECT_NAME")
                .to_ascii_uppercase();
            let object_type = string_cell(row, "OBJECT_TYPE")
                .expect("OBJECT_TYPE")
                .to_ascii_uppercase();
            let status = string_cell(row, "STATUS")
                .expect("STATUS")
                .to_ascii_uppercase();
            out.insert(format!("{name}::{object_type}"), status);
        }
        out
    }

    fn assert_matches_expected_dropcol_golden(statuses: &BTreeMap<String, String>) {
        let expected_json = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../plsql-intelligence/corpus/lab/hero_diff_dropcol/expected_what_breaks.json"
        ));
        let expected: Value =
            serde_json::from_str(expected_json).expect("expected what-breaks golden is valid JSON");
        let nodes = expected["what_breaks"]["nodes"]
            .as_array()
            .expect("golden nodes array");
        assert_eq!(
            nodes.len(),
            3,
            "the hero golden has exactly three broken nodes"
        );

        for node in nodes {
            let logical_id = node["logical_id"].as_str().expect("logical id");
            let oracle_status = node["oracle_status"]
                .as_str()
                .expect("oracle status")
                .to_ascii_uppercase();
            let object_key = match logical_id {
                "v_high_value_customers" => "V_HIGH_VALUE_CUSTOMERS::VIEW",
                "pkg_customer_report" => "PKG_CUSTOMER_REPORT::PACKAGE BODY",
                "proc_segment_summary" => "PROC_SEGMENT_SUMMARY::PROCEDURE",
                other => {
                    assert_eq!(other, "", "unexpected hero golden node {other}");
                    ""
                }
            };
            assert_eq!(
                statuses.get(object_key).map(String::as_str),
                Some(oracle_status.as_str()),
                "live Oracle status must match the committed hero golden for {logical_id}"
            );
        }
    }

    fn query(dispatcher: &OracleDispatcher, sql: &str, binds: Value) -> Value {
        dispatch(
            dispatcher,
            "oracle_query",
            json!({ "sql": sql, "binds": binds, "max_rows": 100 }),
        )
    }

    fn dispatch(dispatcher: &OracleDispatcher, tool: &str, args: Value) -> Value {
        dispatcher.dispatch(tool, args).unwrap_or_else(|error| {
            assert_eq!(tool, "", "{tool} failed: {error:?}");
            Value::Null
        })
    }

    fn rows(value: &Value) -> &[Value] {
        value["rows"].as_array().expect("query rows").as_slice()
    }

    fn string_cell<'a>(row: &'a Value, name: &str) -> Option<&'a str> {
        row.get(name).and_then(Value::as_str)
    }

    fn row_count(value: &Value, row_set: &str) -> u64 {
        value["row_counts"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|entry| entry["row_set"].as_str() == Some(row_set))
            .and_then(|entry| entry["row_count"].as_u64())
            .unwrap_or(0)
    }

    fn provision_hero_corpus(conn: &RustOracleConnection, schema: &str) {
        execute_sql(
            conn,
            &format!(
                "CREATE TABLE {schema}.CUSTOMERS ( \
                 CUSTOMER_ID NUMBER(10) NOT NULL, \
                 CUSTOMER_NAME VARCHAR2(200) NOT NULL, \
                 EMAIL VARCHAR2(320), \
                 PHONE VARCHAR2(40), \
                 REGION VARCHAR2(60), \
                 LEGACY_SEGMENT VARCHAR2(30), \
                 CREATED_AT DATE DEFAULT SYSDATE, \
                 CONSTRAINT {schema}_CUST_PK PRIMARY KEY (CUSTOMER_ID) \
                 )"
            ),
        )
        .expect("create hero CUSTOMERS table");

        execute_sql(
            conn,
            &format!(
                "CREATE OR REPLACE VIEW {schema}.V_HIGH_VALUE_CUSTOMERS AS \
                 SELECT CUSTOMER_ID, CUSTOMER_NAME, EMAIL, REGION, LEGACY_SEGMENT, CREATED_AT \
                 FROM {schema}.CUSTOMERS \
                 WHERE LEGACY_SEGMENT IS NOT NULL"
            ),
        )
        .expect("create hero dependent view");

        let spec = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../plsql-intelligence/corpus/lab/hero_diff_dropcol/before/pkg_customer_report.pks"
        ))
        .replace(
            "CREATE OR REPLACE PACKAGE pkg_customer_report",
            &format!("CREATE OR REPLACE PACKAGE {schema}.PKG_CUSTOMER_REPORT"),
        );
        execute_sql(conn, &spec).expect("create hero package spec");

        let body = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../plsql-intelligence/corpus/lab/hero_diff_dropcol/before/pkg_customer_report.pkb"
        ))
        .replace(
            "CREATE OR REPLACE PACKAGE BODY pkg_customer_report",
            &format!("CREATE OR REPLACE PACKAGE BODY {schema}.PKG_CUSTOMER_REPORT"),
        )
        .replace("FROM   customers", &format!("FROM   {schema}.CUSTOMERS"))
        .replace("FROM customers", &format!("FROM {schema}.CUSTOMERS"))
        .replace(
            "customers.legacy_segment%TYPE",
            &format!("{schema}.CUSTOMERS.LEGACY_SEGMENT%TYPE"),
        );
        execute_sql(conn, &body).expect("create hero package body");

        let proc_src = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../plsql-intelligence/corpus/lab/hero_diff_dropcol/before/proc_segment_summary.sql"
        ))
        .replace(
            "CREATE OR REPLACE PROCEDURE proc_segment_summary",
            &format!("CREATE OR REPLACE PROCEDURE {schema}.PROC_SEGMENT_SUMMARY"),
        )
        .replace("FROM   customers", &format!("FROM   {schema}.CUSTOMERS"))
        .replace(
            "customers.legacy_segment%TYPE",
            &format!("{schema}.CUSTOMERS.LEGACY_SEGMENT%TYPE"),
        );
        execute_sql(conn, &proc_src).expect("create hero dependent procedure");
    }

    fn create_scratch_schema(conn: &RustOracleConnection, schema: &str) -> Result<(), String> {
        drop_scratch_schema(conn, schema);
        let password = random_password("HeroColT");
        let create = format!(
            "CREATE USER {schema} IDENTIFIED BY {password} \
             DEFAULT TABLESPACE USERS QUOTA UNLIMITED ON USERS"
        );
        execute_sql(conn, &create).map_err(|error| {
            format!(
                "cannot create scratch schema {schema}; requires a privileged test user ({error})"
            )
        })?;

        for sql in [
            format!("GRANT CREATE SESSION TO {schema}"),
            format!("GRANT CREATE TABLE TO {schema}"),
            format!("GRANT CREATE VIEW TO {schema}"),
            format!("GRANT CREATE PROCEDURE TO {schema}"),
        ] {
            if let Err(error) = execute_sql(conn, &sql) {
                drop_scratch_schema(conn, schema);
                return Err(format!("cannot grant scratch-schema privilege: {error}"));
            }
        }
        Ok(())
    }

    struct SchemaGuard {
        conn: RustOracleConnection,
        schema: String,
    }

    impl Drop for SchemaGuard {
        fn drop(&mut self) {
            drop_scratch_schema(&self.conn, &self.schema);
        }
    }

    fn drop_scratch_schema(conn: &RustOracleConnection, schema: &str) {
        let sql = format!(
            "BEGIN \
             EXECUTE IMMEDIATE 'DROP USER {schema} CASCADE'; \
             EXCEPTION WHEN OTHERS THEN NULL; \
             END;"
        );
        let _ = execute_sql(conn, &sql);
    }

    fn execute_sql(conn: &RustOracleConnection, sql: &str) -> Result<u64, DbError> {
        run_live_future(async {
            let cx = Cx::current().expect("live-xe runtime installs a request Cx");
            conn.execute(&cx, sql, &[] as &[OracleBind]).await
        })
    }

    fn connect_or_skip(action: &str) -> Option<RustOracleConnection> {
        let opts = match connect_options(action) {
            Ok(opts) => opts,
            Err(error) => {
                eprintln!("[live-xe] SKIP {action}: {error}");
                return None;
            }
        };
        match run_live_future(async {
            let cx = Cx::current().expect("live-xe runtime installs a request Cx");
            RustOracleConnection::connect(&cx, opts).await
        }) {
            Ok(conn) => Some(conn),
            Err(error) => {
                eprintln!(
                    "[live-xe] SKIP {action}: no reachable Oracle or prerequisite missing ({error}); \
                     set ORACLEMCP_TEST_DSN / _USER / _PASSWORD"
                );
                None
            }
        }
    }

    fn connect_options(action: &str) -> Result<OracleConnectOptions, String> {
        let secret = std::env::var(ORACLEMCP_SECRET_ENV)
            .or_else(|_| std::env::var(PLSQL_SECRET_ENV))
            .map_err(|_| {
                format!(
                    "set {ORACLEMCP_SECRET_ENV} or {PLSQL_SECRET_ENV} for live Oracle PL/SQL tests"
                )
            })?;
        let mut opts = OracleConnectOptions {
            connect_string: std::env::var("ORACLEMCP_TEST_DSN")
                .unwrap_or_else(|_| DEFAULT_DSN.to_owned()),
            username: Some(
                std::env::var("ORACLEMCP_TEST_USER").unwrap_or_else(|_| DEFAULT_USER.to_owned()),
            ),
            session_identity: Some(OracleSessionIdentity {
                module: Some(MODULE.to_owned()),
                action: Some(action.to_owned()),
                ..OracleSessionIdentity::default()
            }),
            call_timeout: Some(Duration::from_secs(15)),
            ..OracleConnectOptions::default()
        };
        opts.password = Some(secret);
        Ok(opts)
    }

    fn run_live_future<F: Future>(future: F) -> F::Output {
        let reactor =
            asupersync::runtime::reactor::create_reactor().expect("live-xe native reactor");
        RuntimeBuilder::current_thread()
            .with_reactor(reactor)
            .build()
            .expect("live-xe asupersync runtime")
            .block_on(future)
    }

    fn hero_schema_name() -> String {
        format!("HEROCOL_T_{}", unique_suffix())
    }

    fn unique_suffix() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let counter = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed) % 1000;
        format!("{:015}{counter:03}", nanos % 1_000_000_000_000_000)
    }

    fn random_password(prefix: &str) -> String {
        format!("{prefix}{}#", random_hex(8))
    }

    fn random_hex(byte_count: usize) -> String {
        let mut bytes = vec![0_u8; byte_count];
        getrandom::getrandom(&mut bytes).expect("OS randomness must be available");
        let mut out = String::with_capacity(byte_count * 2);
        for byte in bytes {
            push_hex_byte(&mut out, byte);
        }
        out
    }

    fn push_hex_byte(output: &mut String, byte: u8) {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}
