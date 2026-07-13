//! Unit tests for the dispatcher, relocated verbatim from the former
//! single-file `dispatch.rs`. Body indentation is preserved as-is to keep
//! every raw-string fixture byte-identical.

use super::*;
use crate::registry::tool_names;
use asupersync::Cx;
use asupersync::channel::mpsc;
use asupersync::runtime::RuntimeBuilder;
use oraclemcp_core::{DispatchCloseReason, DispatchContext, ScopeGrant};
use oraclemcp_db::{OracleBackend, OracleCell, OracleRow, QueryRowStream, QueryRowStreamStart};
use std::path::{Path, PathBuf};
use std::sync::Barrier;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc as std_mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn run_with_current_cx(f: impl FnOnce(&Cx)) {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("asupersync test runtime builds");
    runtime.block_on(async {
        let cx = Cx::current().expect("block_on installs a current Cx");
        f(&cx);
    });
}

fn session_bundle(conn: impl OracleConnection + 'static) -> ProfileConnectionBundle {
    ProfileConnectionBundle::new(Box::new(conn), None)
}

#[derive(Default)]
struct SemanticGuardState {
    caller_queries: AtomicUsize,
}

struct SemanticGuardMock {
    state: Arc<SemanticGuardState>,
}

fn semantic_row(columns: &[(&str, Option<&str>)]) -> OracleRow {
    OracleRow {
        columns: columns
            .iter()
            .map(|(name, value)| {
                (
                    (*name).to_owned(),
                    OracleCell::new("VARCHAR2", value.map(str::to_owned)),
                )
            })
            .collect(),
    }
}

fn string_bind(binds: &[OracleBind], index: usize) -> Option<&str> {
    match binds.get(index) {
        Some(OracleBind::String(value)) => Some(value),
        _ => None,
    }
}

/// Shared live-catalog model for dispatcher mocks whose test concern is above
/// semantic resolution. Dedicated security tests use `SemanticGuardMock`
/// instead, so views, policies, and callables are never cleared by this model.
fn mock_plain_table_dictionary(sql: &str, binds: &[OracleBind]) -> Option<Vec<OracleRow>> {
    let normalized = sql.to_ascii_lowercase();
    if normalized.contains("sys_context('userenv', 'session_user')") {
        return Some(vec![semantic_row(&[
            ("SESSION_USER", Some("APP")),
            ("CURRENT_SCHEMA", Some("APP")),
            ("EDITION_NAME", Some("ORA$BASE")),
        ])]);
    }
    if normalized.contains("from session_roles") {
        return Some(Vec::new());
    }
    if normalized.contains("from all_objects")
        && normalized.contains("object_id, status, edition_name")
    {
        let owner = string_bind(binds, 0).unwrap_or("APP");
        let name = string_bind(binds, 1).unwrap_or("DUAL");
        return Some(vec![semantic_row(&[
            ("OWNER", Some(owner)),
            ("OBJECT_NAME", Some(name)),
            ("OBJECT_TYPE", Some("TABLE")),
            ("OBJECT_ID", Some("42")),
            ("STATUS", Some("VALID")),
            ("EDITION_NAME", None),
        ])]);
    }
    if normalized.contains("from all_synonyms")
        || normalized.contains("from all_arguments")
        || (normalized.contains("from all_tab_columns") && !normalized.contains("table_name = :2"))
    {
        return Some(Vec::new());
    }
    if normalized.contains("from all_tab_columns") && normalized.contains("table_name = :2") {
        let column = string_bind(binds, 2).unwrap_or("VALUE");
        return Some(vec![semantic_row(&[
            ("COLUMN_NAME", Some(column)),
            ("COLUMN_ID", Some("1")),
        ])]);
    }
    if normalized.contains("from all_policies") || normalized.contains("from all_tab_cols") {
        return Some(Vec::new());
    }
    None
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for SemanticGuardMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }

    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo {
            current_schema: Some("APP".to_owned()),
            session_user: Some("APP".to_owned()),
            current_edition: Some("ORA$BASE".to_owned()),
            ..Default::default()
        })
    }

    async fn query_rows(
        &self,
        _cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        let normalized = sql.to_ascii_lowercase();
        if normalized.contains("sys_context('userenv', 'session_user')") {
            return Ok(vec![semantic_row(&[
                ("SESSION_USER", Some("APP")),
                ("CURRENT_SCHEMA", Some("APP")),
                ("EDITION_NAME", Some("ORA$BASE")),
            ])]);
        }
        if normalized.contains("from session_roles") {
            return Ok(Vec::new());
        }
        if normalized.contains("from all_objects") {
            let name = string_bind(binds, 1).unwrap_or_default();
            let kind = match name {
                "ORDERS" | "POLICY_TABLE" => "TABLE",
                "SIDE_VIEW" => "VIEW",
                "DANGEROUS_FN" => "FUNCTION",
                _ => return Ok(Vec::new()),
            };
            return Ok(vec![semantic_row(&[
                ("OWNER", Some("APP")),
                ("OBJECT_NAME", Some(name)),
                ("OBJECT_TYPE", Some(kind)),
                ("OBJECT_ID", Some("42")),
                ("STATUS", Some("VALID")),
                ("EDITION_NAME", None),
            ])]);
        }
        if normalized.contains("from all_synonyms") {
            return Ok(Vec::new());
        }
        if normalized.contains("from all_arguments") {
            return Ok(vec![semantic_row(&[
                ("SUBPROGRAM_ID", Some("1")),
                ("OVERLOAD", None),
                ("POSITION", Some("0")),
                ("DATA_LEVEL", Some("0")),
                ("IN_OUT", Some("OUT")),
                ("DEFAULTED", Some("N")),
            ])]);
        }
        if normalized.contains("from all_tab_columns") && normalized.contains("table_name = :2") {
            let column = string_bind(binds, 2).unwrap_or_default();
            return Ok((column == "ID")
                .then(|| semantic_row(&[("COLUMN_NAME", Some("ID")), ("COLUMN_ID", Some("1"))]))
                .into_iter()
                .collect());
        }
        if normalized.contains("from all_tab_columns") {
            return Ok(Vec::new());
        }
        if normalized.contains("from all_policies") {
            return Ok((string_bind(binds, 1) == Some("POLICY_TABLE"))
                .then(|| semantic_row(&[("POLICY_NAME", Some("P"))]))
                .into_iter()
                .collect());
        }
        if normalized.contains("from all_tab_cols") {
            return Ok(Vec::new());
        }
        self.state.caller_queries.fetch_add(1, Ordering::SeqCst);
        Ok(vec![semantic_row(&[("ID", Some("1"))])])
    }

    async fn execute(&self, _cx: &Cx, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
        Ok(0)
    }

    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

fn semantic_dispatcher() -> (OracleDispatcher, Arc<SemanticGuardState>) {
    let state = Arc::new(SemanticGuardState::default());
    (
        OracleDispatcher::new(Box::new(SemanticGuardMock {
            state: Arc::clone(&state),
        })),
        state,
    )
}

#[test]
fn served_read_gate_executes_only_exact_plain_table_columns() {
    let (dispatcher, state) = semantic_dispatcher();
    dispatcher
        .dispatch(
            "oracle_query",
            json!({"sql": "SELECT o.id FROM app.orders o"}),
        )
        .expect("exact table column is proven read-only");
    assert_eq!(state.caller_queries.load(Ordering::SeqCst), 1);
}

#[test]
fn served_read_gate_refuses_view_policy_and_zero_arg_function_before_evaluation() {
    for sql in [
        "SELECT * FROM app.side_view",
        "SELECT * FROM app.policy_table",
        "SELECT dangerous_fn FROM app.orders",
    ] {
        let (dispatcher, state) = semantic_dispatcher();
        let error = dispatcher
            .dispatch("oracle_query", json!({"sql": sql}))
            .expect_err("hidden or executable dependency must fail closed");
        assert_eq!(error.error_class, ErrorClass::ForbiddenStatement, "{sql}");
        assert_eq!(state.caller_queries.load(Ordering::SeqCst), 0, "{sql}");
    }
}

#[test]
fn read_path_handler_work_runs_under_narrowed_read_cx() {
    // A9 (finding 7): the production read path narrows the handler context to
    // `ReadPathCaps` (TIME + IO; no SPAWN / REMOTE / RANDOM) and actually USES
    // it — the cancellation checkpoint that brackets every read dispatch runs
    // under the narrowed row. This is the same call the oracle_query /
    // oracle_schema_inspect / custom-read arms make. If `dispatch_checkpoint`
    // ever stopped accepting the narrowed `Cx<ReadPathCaps>`, this would fail to
    // compile — locking the narrowing onto the production path.
    run_with_current_cx(|cx| {
        let read_cx: Cx<oraclemcp_core::ReadPathCaps> = narrow_to_read_path(cx);
        dispatch_checkpoint(&read_cx, "test.read_path.narrowed").expect("checkpoint");
        // Type-level proof: the binding is the narrowed row, not the full one.
        fn assert_read_path(_: &Cx<oraclemcp_core::ReadPathCaps>) {}
        assert_read_path(&read_cx);
    });
}

#[test]
fn generated_read_gate_allows_known_metadata_sql_and_rejects_unknown_functions() {
    let ddl_sql =
        "SELECT DBMS_LOB.SUBSTR(DBMS_METADATA.GET_DDL('TABLE', :1, :2), 4000, 1) AS ddl FROM dual";
    assert_eq!(
        ensure_generated_read_sql_allowed(ddl_sql).expect("DBMS_METADATA read is allowed"),
        DangerLevel::Safe
    );

    let (_, health_sql) = oraclemcp_db::invalid_objects_sql(oraclemcp_db::ViewTier::All);
    assert_eq!(
        ensure_generated_read_sql_allowed(&health_sql).expect("health dictionary read is allowed"),
        DangerLevel::Safe
    );

    let err = ensure_generated_read_sql_allowed("SELECT billing.purge_old_rows() FROM dual")
        .expect_err("unknown qualified routine must not clear the generated-read gate");
    assert_eq!(err.error_class, ErrorClass::PolicyDenied);
}

fn read_write_level() -> SessionLevelState {
    let mut level = SessionLevelState::new(OperatingLevel::ReadWrite, false);
    level
        .set_current_level(OperatingLevel::ReadWrite)
        .expect("read/write is within ceiling");
    level
}

fn ddl_level() -> SessionLevelState {
    let mut level = SessionLevelState::new(OperatingLevel::Ddl, false);
    level
        .set_current_level(OperatingLevel::Ddl)
        .expect("ddl is within ceiling");
    level
}

fn preview_confirm(dispatcher: &OracleDispatcher, sql: &str) -> String {
    dispatcher
        .dispatch("oracle_preview_sql", json!({ "sql": sql }))
        .expect("preview")
        .pointer("/execute_confirmation/confirm")
        .and_then(Value::as_str)
        .expect("preview minted execute grant")
        .to_owned()
}

fn catalog_generation(dispatcher: &OracleDispatcher) -> u64 {
    RuntimeBuilder::current_thread()
        .build()
        .expect("asupersync test runtime builds")
        .block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            let state = dispatcher
                .state
                .lock(&cx)
                .await
                .unwrap_or_else(|_| panic!("dispatcher state lock failed"));
            state.catalog_cache.generation().0
        })
}

#[test]
fn catalog_invalidation_labels_cover_every_session_and_dictionary_mutation_class() {
    assert_eq!(
        catalog_invalidation_for_sql("DROP TABLE app.orders"),
        CatalogInvalidation::Ddl
    );
    assert_eq!(
        catalog_invalidation_for_sql("CREATE OR REPLACE SYNONYM orders FOR app.orders"),
        CatalogInvalidation::Synonym
    );
    assert_eq!(
        catalog_invalidation_for_sql("ALTER PACKAGE app.api COMPILE"),
        CatalogInvalidation::Package
    );
    assert_eq!(
        catalog_invalidation_for_sql("ALTER PROCEDURE app.run COMPILE"),
        CatalogInvalidation::Overload
    );
    assert_eq!(
        catalog_invalidation_for_sql("ALTER SESSION SET CURRENT_SCHEMA = APP"),
        CatalogInvalidation::CurrentSchema
    );
    assert_eq!(
        catalog_invalidation_for_sql("ALTER SESSION SET EDITION = blue"),
        CatalogInvalidation::Edition
    );
    assert_eq!(
        catalog_invalidation_for_sql("SET ROLE reporter"),
        CatalogInvalidation::Roles
    );
}

fn write_intent_root(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/dispatch-write-intent-tests")
        .join(format!("{name}-{}-{stamp}", std::process::id()))
}

fn write_intent_log(name: &str) -> Arc<WriteIntentLog> {
    Arc::new(WriteIntentLog::open(write_intent_root(name)).expect("write-intent log"))
}

fn scope_grant(scope: &str) -> ScopeGrant {
    ScopeGrant(vec![scope.to_owned()])
}

/// A driver-free mock that returns one synthetic row for any query — mirrors
/// `oraclemcp_db::query`'s `NRowMock` so the dispatch arms exercise offline.
struct OneRowMock;
#[async_trait::async_trait(?Send)]
impl OracleConnection for OneRowMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo {
            backend: Some(OracleBackend::RustOracle),
            connection_strategy: Some("single_session".to_owned()),
            pool_open_connections: None,
            server_version: Some("23.0.0".to_owned()),
            database_role: Some("PRIMARY".to_owned()),
            open_mode: Some("READ WRITE".to_owned()),
            db_unique_name: Some("ORCL23A".to_owned()),
            service_name: Some("freepdb1".to_owned()),
            instance_name: Some("free".to_owned()),
            read_only: false,
            read_only_reason: None,
            current_schema: Some("APP".to_owned()),
            current_edition: Some("ORA$BASE".to_owned()),
            session_user: Some("APP".to_owned()),
            current_user: Some("APP".to_owned()),
            proxy_user: None,
            sid: Some("101".to_owned()),
            serial_number: Some("202".to_owned()),
            module: Some("oraclemcp-test".to_owned()),
            action: None,
            client_identifier: Some("agent".to_owned()),
            client_info: None,
            os_user: Some("operator".to_owned()),
            host: Some("workstation".to_owned()),
            machine: Some("workstation".to_owned()),
            terminal: None,
            program: Some("oraclemcp".to_owned()),
            client_driver: Some("oraclemcp-driver".to_owned()),
            server_features: None,
        })
    }
    async fn query_rows(
        &self,
        _cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        if let Some(rows) = mock_plain_table_dictionary(sql, binds) {
            return Ok(rows);
        }
        let sql_lower = sql.to_ascii_lowercase();
        if sql_lower.contains("from all_users") {
            return Ok(vec![OracleRow {
                columns: vec![(
                    "USERNAME".to_owned(),
                    OracleCell::new("VARCHAR2", Some("APP".to_owned())),
                )],
            }]);
        }
        if catalog_extract_empty_rowset(&sql_lower) {
            return Ok(Vec::new());
        }
        Ok(vec![OracleRow {
                columns: vec![
                    (
                        "OWNER".to_owned(),
                        OracleCell::new("VARCHAR2", Some("APP".to_owned())),
                    ),
                    (
                        "OBJECT_NAME".to_owned(),
                        OracleCell::new("VARCHAR2", Some("EMPLOYEES".to_owned())),
                    ),
                    (
                        "INDEX_NAME".to_owned(),
                        OracleCell::new("VARCHAR2", Some("EMP_NAME_IX".to_owned())),
                    ),
                    (
                        "TABLE_OWNER".to_owned(),
                        OracleCell::new("VARCHAR2", Some("APP".to_owned())),
                    ),
                    (
                        "TABLE_NAME".to_owned(),
                        OracleCell::new("VARCHAR2", Some("EMPLOYEES".to_owned())),
                    ),
                    (
                        "IS_UNIQUE".to_owned(),
                        OracleCell::new("VARCHAR2", Some("NO".to_owned())),
                    ),
                    (
                        "INDEX_TYPE".to_owned(),
                        OracleCell::new("VARCHAR2", Some("NORMAL".to_owned())),
                    ),
                    (
                        "TRIGGER_NAME".to_owned(),
                        OracleCell::new("VARCHAR2", Some("EMP_BIU".to_owned())),
                    ),
                    (
                        "TRIGGER_TYPE".to_owned(),
                        OracleCell::new("VARCHAR2", Some("BEFORE EACH ROW".to_owned())),
                    ),
                    (
                        "TRIGGERING_EVENT".to_owned(),
                        OracleCell::new("VARCHAR2", Some("INSERT OR UPDATE".to_owned())),
                    ),
                    (
                        "VIEW_NAME".to_owned(),
                        OracleCell::new("VARCHAR2", Some("EMP_V".to_owned())),
                    ),
                    (
                        "TEXT_VC".to_owned(),
                        OracleCell::new("VARCHAR2", Some("SELECT 1 AS ID FROM dual".to_owned())),
                    ),
                    (
                        "READ_ONLY".to_owned(),
                        OracleCell::new("VARCHAR2", Some("N".to_owned())),
                    ),
                    (
                        "OBJECT_TYPE".to_owned(),
                        OracleCell::new("VARCHAR2", Some("TABLE".to_owned())),
                    ),
                    (
                        "STATUS".to_owned(),
                        OracleCell::new("VARCHAR2", Some("VALID".to_owned())),
                    ),
                    (
                        "SCHEMA_NAME".to_owned(),
                        OracleCell::new("VARCHAR2", Some("APP".to_owned())),
                    ),
                    (
                        "OBJECT_COUNT".to_owned(),
                        OracleCell::new("NUMBER", Some("42".to_owned())),
                    ),
                    (
                        "DDL".to_owned(),
                        OracleCell::new("CLOB", Some("CREATE TABLE ...".to_owned())),
                    ),
                    (
                        "LOB_VALUE".to_owned(),
                        OracleCell::new("CLOB", Some("large text".to_owned())),
                    ),
                    (
                        "TEXT".to_owned(),
                        OracleCell::new(
                            "VARCHAR2",
                            Some(
                                "PACKAGE BODY EMP_API AS\nPROCEDURE P IS BEGIN NULL; END;\nEND EMP_API;\n"
                                    .to_owned(),
                            ),
                        ),
                    ),
                ],
            }])
    }
    async fn query_rows_named(
        &self,
        cx: &Cx,
        sql: &str,
        b: &[(String, OracleBind)],
    ) -> Result<Vec<OracleRow>, DbError> {
        assert!(
            sql.contains(":id"),
            "custom SQL should preserve named bind references: {sql}"
        );
        assert_eq!(b, &[("id".to_owned(), OracleBind::I64(7))]);
        self.query_rows(cx, sql, &[]).await
    }
    async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
        Ok(0)
    }
    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

fn catalog_extract_empty_rowset(sql_lower: &str) -> bool {
    [
        "from all_tab_cols",
        "from all_constraints",
        "from all_synonyms",
        "from all_procedures",
        "from all_arguments",
        "from all_mviews",
        "from all_sequences",
        "from all_type_attrs",
        "from all_tab_privs",
        "from all_db_links",
        "from all_tab_comments",
        "from all_col_comments",
        "from all_editions",
        "from all_editioning_views",
        "from all_policies",
        "from all_dependencies",
        "from all_plsql_object_settings",
        "from all_identifiers",
    ]
    .iter()
    .any(|needle| sql_lower.contains(needle))
}

struct LabeledMock {
    label: &'static str,
    strategy: &'static str,
    counts: Arc<TouchCounts>,
}

impl LabeledMock {
    fn new(label: &'static str, strategy: &'static str, counts: Arc<TouchCounts>) -> Self {
        Self {
            label,
            strategy,
            counts,
        }
    }
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for LabeledMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }

    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        self.counts.ping.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        self.counts.describe.fetch_add(1, Ordering::SeqCst);
        Ok(OracleConnectionInfo {
            backend: Some(OracleBackend::RustOracle),
            connection_strategy: Some(self.strategy.to_owned()),
            pool_open_connections: (self.strategy == "stateless_metadata_pool").then_some(1),
            current_schema: Some("APP".to_owned()),
            ..Default::default()
        })
    }

    async fn query_rows(
        &self,
        _cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        if let Some(rows) = mock_plain_table_dictionary(sql, binds) {
            return Ok(rows);
        }
        self.counts.query.fetch_add(1, Ordering::SeqCst);
        let column = if sql.to_ascii_lowercase().contains("all_objects") {
            "SCHEMA_NAME"
        } else {
            "LABEL"
        };
        Ok(vec![OracleRow {
            columns: vec![(
                column.to_owned(),
                OracleCell::new("VARCHAR2", Some(self.label.to_owned())),
            )],
        }])
    }

    async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
        self.counts.execute.fetch_add(1, Ordering::SeqCst);
        Ok(1)
    }

    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        self.counts.commit.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        self.counts.rollback.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct SourceLookupMock;
#[async_trait::async_trait(?Send)]
impl OracleConnection for SourceLookupMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo {
            backend: Some(OracleBackend::RustOracle),
            database_role: Some("PRIMARY".to_owned()),
            open_mode: Some("READ WRITE".to_owned()),
            db_unique_name: Some("ORCL23A".to_owned()),
            service_name: Some("freepdb1".to_owned()),
            instance_name: Some("free".to_owned()),
            current_schema: Some("APP".to_owned()),
            session_user: Some("APP".to_owned()),
            current_user: Some("APP".to_owned()),
            proxy_user: Some("MCP_PROXY".to_owned()),
            sid: Some("101".to_owned()),
            serial_number: Some("202".to_owned()),
            module: Some("oraclemcp-test".to_owned()),
            action: Some("execute".to_owned()),
            client_identifier: Some("oauth-subject".to_owned()),
            ..Default::default()
        })
    }
    async fn query_rows(
        &self,
        _cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        if let Some(rows) = mock_plain_table_dictionary(sql, binds) {
            return Ok(rows);
        }
        if sql.contains("SELECT type") {
            return Ok(vec![
                OracleRow {
                    columns: vec![(
                        "TYPE".to_owned(),
                        OracleCell::new("VARCHAR2", Some("PACKAGE".to_owned())),
                    )],
                },
                OracleRow {
                    columns: vec![(
                        "TYPE".to_owned(),
                        OracleCell::new("VARCHAR2", Some("PACKAGE BODY".to_owned())),
                    )],
                },
            ]);
        }

        let is_type_body = binds
            .iter()
            .any(|bind| matches!(bind, OracleBind::String(value) if value == "TYPE BODY"));
        let source = if is_type_body {
            "TYPE BODY EMPLOYEE_T AS\nMEMBER PROCEDURE P IS BEGIN NULL; END P;\nEND EMPLOYEE_T;\n"
        } else {
            "PACKAGE BODY EMP_API AS\nPROCEDURE P IS BEGIN NULL; END;\nEND EMP_API;\n"
        };
        Ok(vec![OracleRow {
            columns: vec![(
                "TEXT".to_owned(),
                OracleCell::new("VARCHAR2", Some(source.to_owned())),
            )],
        }])
    }
    async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
        Ok(0)
    }
    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

/// A mock whose every query fails with a classifiable ORA- error, so we can
/// assert DbError -> ErrorEnvelope mapping end to end.
struct FailingMock;
#[async_trait::async_trait(?Send)]
impl OracleConnection for FailingMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo::default())
    }
    async fn query_rows(
        &self,
        _cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        if let Some(rows) = mock_plain_table_dictionary(sql, binds) {
            return Ok(rows);
        }
        Err(DbError::Query(
            "ORA-00942: table or view does not exist".to_owned(),
        ))
    }
    async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
        Err(DbError::Execute(
            "ORA-00942: table or view does not exist".to_owned(),
        ))
    }
    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

struct DescribeFailingMock;
#[async_trait::async_trait(?Send)]
impl OracleConnection for DescribeFailingMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Err(DbError::BackendNotCompiled {
            backend: OracleBackend::RustOracle,
        })
    }
    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Err(DbError::BackendNotCompiled {
            backend: OracleBackend::RustOracle,
        })
    }
    async fn query_rows(
        &self,
        _cx: &Cx,
        _sql: &str,
        _b: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        Err(DbError::BackendNotCompiled {
            backend: OracleBackend::RustOracle,
        })
    }
    async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
        Err(DbError::BackendNotCompiled {
            backend: OracleBackend::RustOracle,
        })
    }
    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Err(DbError::BackendNotCompiled {
            backend: OracleBackend::RustOracle,
        })
    }
    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Err(DbError::BackendNotCompiled {
            backend: OracleBackend::RustOracle,
        })
    }
}

#[derive(Default)]
struct ExecState {
    executed: Mutex<Vec<(String, Vec<OracleBind>)>>,
    execute_error: Mutex<Option<DbError>>,
    diagnostics: Mutex<Vec<OracleRow>>,
    dbms_output: Mutex<DbmsOutput>,
    describe_calls: AtomicUsize,
    cancel_on_describe: AtomicUsize,
    describe_error: Mutex<Option<DbError>>,
    describe_pending: AtomicUsize,
    dbms_output_enable_error: Mutex<Option<DbError>>,
    dbms_output_error: Mutex<Option<DbError>>,
    dbms_output_enabled: AtomicUsize,
    dbms_output_limits: Mutex<Vec<(usize, usize)>>,
    current_call_timeout: Mutex<Option<Duration>>,
    call_timeout_sets: Mutex<Vec<Option<Duration>>>,
    cancel_on_commit: AtomicUsize,
    cancel_on_rollback: AtomicUsize,
    commits: AtomicUsize,
    rollbacks: AtomicUsize,
}

struct ExecRecordingMock {
    state: Arc<ExecState>,
    rows_affected: u64,
}

struct CancelAfterExecuteMock {
    state: Arc<ExecState>,
}

struct CommitInDoubtMock {
    state: Arc<ExecState>,
}

struct IntentObservingExecMock {
    state: Arc<ExecState>,
    intents: Arc<WriteIntentLog>,
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for CancelAfterExecuteMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }

    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo {
            backend: Some(OracleBackend::RustOracle),
            database_role: Some("PRIMARY".to_owned()),
            open_mode: Some("READ WRITE".to_owned()),
            db_unique_name: Some("ORCL23A".to_owned()),
            service_name: Some("freepdb1".to_owned()),
            instance_name: Some("free".to_owned()),
            current_schema: Some("APP".to_owned()),
            session_user: Some("APP".to_owned()),
            current_user: Some("APP".to_owned()),
            proxy_user: Some("MCP_PROXY".to_owned()),
            sid: Some("101".to_owned()),
            serial_number: Some("202".to_owned()),
            module: Some("oraclemcp-test".to_owned()),
            action: Some("execute".to_owned()),
            client_identifier: Some("oauth-subject".to_owned()),
            ..Default::default()
        })
    }

    async fn query_rows(
        &self,
        _cx: &Cx,
        _sql: &str,
        _b: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        Ok(Vec::new())
    }

    async fn execute(&self, cx: &Cx, sql: &str, b: &[OracleBind]) -> Result<u64, DbError> {
        self.state
            .executed
            .lock()
            .expect("exec mutex")
            .push((sql.to_owned(), b.to_vec()));
        cx.set_cancel_requested(true);
        Err(DbError::Cancelled(
            "test cancellation after execute".to_owned(),
        ))
    }

    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        self.state.commits.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        self.state.rollbacks.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl ExecRecordingMock {
    fn new(state: Arc<ExecState>) -> Self {
        Self {
            state,
            rows_affected: 3,
        }
    }
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for IntentObservingExecMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }

    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo {
            backend: Some(OracleBackend::RustOracle),
            current_schema: Some("APP".to_owned()),
            ..Default::default()
        })
    }

    async fn query_rows(
        &self,
        _cx: &Cx,
        _sql: &str,
        _b: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        Ok(Vec::new())
    }

    async fn execute(&self, _cx: &Cx, sql: &str, b: &[OracleBind]) -> Result<u64, DbError> {
        let unresolved = self.intents.unresolved().expect("intent snapshot");
        assert_eq!(
            unresolved.len(),
            1,
            "pending write intent must be durable before DB execute"
        );
        assert_eq!(unresolved[0].tool, "oracle_execute");
        assert_eq!(unresolved[0].subject, "process:stdio");
        assert_eq!(unresolved[0].lane, "process");
        assert!(unresolved[0].sql_sha256.starts_with("sha256:"));
        self.state
            .executed
            .lock()
            .expect("exec mutex")
            .push((sql.to_owned(), b.to_vec()));
        Ok(3)
    }

    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        self.state.commits.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        self.state.rollbacks.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for CommitInDoubtMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }

    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo {
            backend: Some(OracleBackend::RustOracle),
            current_schema: Some("APP".to_owned()),
            ..Default::default()
        })
    }

    async fn query_rows(
        &self,
        _cx: &Cx,
        _sql: &str,
        _b: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        Ok(Vec::new())
    }

    async fn execute(&self, _cx: &Cx, sql: &str, b: &[OracleBind]) -> Result<u64, DbError> {
        self.state
            .executed
            .lock()
            .expect("exec mutex")
            .push((sql.to_owned(), b.to_vec()));
        Ok(3)
    }

    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        self.state.commits.fetch_add(1, Ordering::SeqCst);
        Err(DbError::Execute(
            "DPY-4011: commit response lost".to_owned(),
        ))
    }

    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        self.state.rollbacks.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for ExecRecordingMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }

    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn describe(&self, cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        self.state.describe_calls.fetch_add(1, Ordering::SeqCst);
        if self.state.describe_pending.load(Ordering::SeqCst) != 0 {
            return std::future::pending().await;
        }
        if let Some(err) = self
            .state
            .describe_error
            .lock()
            .expect("describe error mutex")
            .clone()
        {
            return Err(err);
        }
        if self.state.cancel_on_describe.load(Ordering::SeqCst) != 0 {
            cx.set_cancel_requested(true);
        }
        Ok(OracleConnectionInfo {
            backend: Some(OracleBackend::RustOracle),
            database_role: Some("PRIMARY".to_owned()),
            open_mode: Some("READ WRITE".to_owned()),
            db_unique_name: Some("ORCL23A".to_owned()),
            service_name: Some("freepdb1".to_owned()),
            instance_name: Some("free".to_owned()),
            current_schema: Some("APP".to_owned()),
            session_user: Some("APP".to_owned()),
            current_user: Some("APP".to_owned()),
            proxy_user: Some("MCP_PROXY".to_owned()),
            sid: Some("101".to_owned()),
            serial_number: Some("202".to_owned()),
            module: Some("oraclemcp-test".to_owned()),
            action: Some("execute".to_owned()),
            client_identifier: Some("oauth-subject".to_owned()),
            ..Default::default()
        })
    }

    async fn query_rows(
        &self,
        _cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        if let Some(rows) = mock_plain_table_dictionary(sql, binds) {
            return Ok(rows);
        }
        let sql_lc = sql.to_ascii_lowercase();
        if sql_lc.contains("from all_errors") {
            return Ok(self
                .state
                .diagnostics
                .lock()
                .expect("diagnostics mutex")
                .clone());
        }
        if sql_lc.contains("from all_source") {
            return Ok(vec![OracleRow {
                    columns: vec![(
                        "TEXT".to_owned(),
                        OracleCell::new(
                            "VARCHAR2",
                            Some(
                                "PACKAGE BODY EMP_API AS\nPROCEDURE P IS BEGIN NULL; END;\nEND EMP_API;\n"
                                    .to_owned(),
                            ),
                        ),
                    )],
                }]);
        }
        Ok(Vec::new())
    }

    async fn execute(&self, _cx: &Cx, sql: &str, b: &[OracleBind]) -> Result<u64, DbError> {
        self.state
            .executed
            .lock()
            .expect("exec mutex")
            .push((sql.to_owned(), b.to_vec()));
        if let Some(error) = self
            .state
            .execute_error
            .lock()
            .expect("execute error mutex")
            .clone()
        {
            return Err(error);
        }
        Ok(self.rows_affected)
    }

    fn call_timeout(&self) -> Result<Option<Duration>, DbError> {
        Ok(*self
            .state
            .current_call_timeout
            .lock()
            .expect("timeout mutex"))
    }

    fn set_call_timeout(&self, timeout: Option<Duration>) -> Result<(), DbError> {
        *self
            .state
            .current_call_timeout
            .lock()
            .expect("timeout mutex") = timeout;
        self.state
            .call_timeout_sets
            .lock()
            .expect("timeout sets mutex")
            .push(timeout);
        Ok(())
    }

    async fn enable_dbms_output(
        &self,
        _cx: &Cx,
        _buffer_bytes: Option<u32>,
    ) -> Result<(), DbError> {
        self.state
            .dbms_output_enabled
            .fetch_add(1, Ordering::SeqCst);
        if let Some(err) = self
            .state
            .dbms_output_enable_error
            .lock()
            .expect("DBMS_OUTPUT enable error mutex")
            .clone()
        {
            return Err(err);
        }
        Ok(())
    }

    async fn read_dbms_output(
        &self,
        _cx: &Cx,
        max_lines: usize,
        max_chars: usize,
    ) -> Result<DbmsOutput, DbError> {
        self.state
            .dbms_output_limits
            .lock()
            .expect("output limits mutex")
            .push((max_lines, max_chars));
        if let Some(err) = self
            .state
            .dbms_output_error
            .lock()
            .expect("output error mutex")
            .clone()
        {
            return Err(err);
        }
        Ok(self.state.dbms_output.lock().expect("output mutex").clone())
    }

    async fn commit(&self, cx: &Cx) -> Result<(), DbError> {
        self.state.commits.fetch_add(1, Ordering::SeqCst);
        if self.state.cancel_on_commit.load(Ordering::SeqCst) != 0 {
            cx.set_cancel_requested(true);
        }
        Ok(())
    }

    async fn rollback(&self, cx: &Cx) -> Result<(), DbError> {
        self.state.rollbacks.fetch_add(1, Ordering::SeqCst);
        if self.state.cancel_on_rollback.load(Ordering::SeqCst) != 0 {
            cx.set_cancel_requested(true);
        }
        Ok(())
    }
}

fn diagnostic_row(attribute: &str, text: &str) -> OracleRow {
    OracleRow {
        columns: vec![
            (
                "NAME".to_owned(),
                OracleCell::new("VARCHAR2", Some("EMP_API".to_owned())),
            ),
            (
                "TYPE".to_owned(),
                OracleCell::new("VARCHAR2", Some("PACKAGE".to_owned())),
            ),
            (
                "LINE".to_owned(),
                OracleCell::new("NUMBER", Some("7".to_owned())),
            ),
            (
                "POSITION".to_owned(),
                OracleCell::new("NUMBER", Some("3".to_owned())),
            ),
            (
                "TEXT".to_owned(),
                OracleCell::new("VARCHAR2", Some(text.to_owned())),
            ),
            (
                "ATTRIBUTE".to_owned(),
                OracleCell::new("VARCHAR2", Some(attribute.to_owned())),
            ),
        ],
    }
}

/// Minimal valid args for a given tool name (matches the registry schemas).
fn args_for(name: &str) -> Value {
    match name {
        "oracle_list_profiles" => json!({}),
        "oracle_connection_info" => json!({}),
        "oracle_switch_profile" => json!({ "profile": "other" }),
        "oracle_set_session_level" => json!({ "action": "status" }),
        "oracle_query" => json!({ "sql": "SELECT 1 FROM dual" }),
        "oracle_list_schemas" => json!({ "name_like": "APP%", "limit": 10 }),
        "oracle_schema_inspect" => json!({ "owner": "HR" }),
        "oracle_search_objects" => json!({ "owner": "HR", "detail_level": "names" }),
        "oracle_describe" => json!({ "owner": "HR", "table": "EMPLOYEES" }),
        "oracle_describe_index" => json!({ "owner": "HR", "name": "EMP_NAME_IX" }),
        "oracle_describe_trigger" => json!({ "owner": "HR", "name": "EMP_BIU" }),
        "oracle_describe_view" => json!({ "owner": "HR", "name": "EMP_DETAILS_VIEW" }),
        "oracle_get_ddl" => {
            json!({ "object_type": "TABLE", "owner": "HR", "name": "EMPLOYEES" })
        }
        "oracle_get_source" => {
            json!({ "object_type": "PACKAGE", "owner": "HR", "name": "EMP_API" })
        }
        "oracle_sample_rows" => json!({ "owner": "HR", "table": "EMPLOYEES" }),
        "oracle_read_clob" => {
            json!({ "owner": "HR", "table": "DOCS", "clob_column": "BODY", "pk_column": "ID", "pk_value": "42" })
        }
        "oracle_compile_errors" => json!({ "owner": "HR", "name": "PKG" }),
        "oracle_search_source" => json!({ "owner": "HR", "needle": "commit" }),
        "oracle_plscope_inspect" => json!({ "owner": "HR", "name": "PKG" }),
        "oracle_explain_plan" => {
            json!({ "sql": "SELECT 1 FROM dual", "allow_plan_table_write": true })
        }
        "oracle_top_queries" => json!({ "metric": "elapsed", "top_n": 5 }),
        "oracle_db_health" => json!({ "health_type": "all" }),
        "oracle_plsql_parse" => {
            json!({ "source": "CREATE OR REPLACE PACKAGE p AS PROCEDURE q; END;" })
        }
        "oracle_plsql_analyze" => json!({ "project_root": "" }),
        "oracle_plsql_what_breaks" => {
            json!({ "changeset": { "objects": [], "unclassified_files": [] } })
        }
        "oracle_plsql_lineage" => json!({ "project_root": "", "target": "APP.P" }),
        "oracle_plsql_sast" => json!({ "project_root": "" }),
        "oracle_plsql_doc" => {
            json!({ "source": "/** doc */\nCREATE PROCEDURE p IS BEGIN NULL; END;" })
        }
        "oracle_plsql_live_snapshot" => {
            json!({ "schemas": ["APP"], "include_plscope": false })
        }
        "oracle_plsql_blast_radius" => {
            json!({ "schemas": ["APP"], "include_plscope": false, "changeset": { "objects": [], "unclassified_files": [] } })
        }
        "oracle_preview_sql" => json!({ "sql": "SELECT 1 FROM dual" }),
        "oracle_execute" => {
            json!({ "sql": "UPDATE employees SET name = name WHERE employee_id = 100" })
        }
        "oracle_compile_object" => json!({ "object_type": "PACKAGE", "name": "EMP_API" }),
        "oracle_create_or_replace" => {
            json!({ "source_code": "CREATE OR REPLACE VIEW EMP_V AS SELECT 1 AS ID FROM dual" })
        }
        "oracle_patch_source" => {
            json!({ "object_type": "PACKAGE_BODY", "owner": "HR", "name": "EMP_API", "old_text": "NULL", "new_text": "1" })
        }
        "current_database" => json!({}),
        "switch_database" => json!({ "db": "other" }),
        "enable_writes" => json!({ "ttl_seconds": 60 }),
        "disable_writes" => json!({}),
        "query" => json!({ "sql": "SELECT 1 FROM dual" }),
        "execute_approved" => {
            let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
            json!({ "sql": sql, "token": "preview-issued-confirmation-placeholder" })
        }
        "compile_object" => json!({ "object_type": "PACKAGE", "object_name": "EMP_API" }),
        "compile_with_warnings" => {
            json!({ "object_type": "PACKAGE", "object_name": "EMP_API" })
        }
        "create_or_replace" => {
            json!({ "source_code": "CREATE OR REPLACE VIEW EMP_V AS SELECT 1 AS ID FROM dual" })
        }
        "patch_package" => {
            json!({ "owner": "HR", "object_name": "EMP_API", "search_text": "NULL", "replacement": "1" })
        }
        "patch_view" => {
            json!({ "owner": "HR", "object_name": "EMP_V", "old_text": "CREATE TABLE ...", "new_text": "CREATE OR REPLACE VIEW EMP_V AS SELECT 1 AS ID FROM dual" })
        }
        "read_patch_preview" => json!({}),
        "deploy_ddl" => {
            json!({ "ddl": "CREATE OR REPLACE VIEW EMP_V AS SELECT 1 AS ID FROM dual" })
        }
        "list_objects" => json!({ "owner": "HR" }),
        "list_schemas" => json!({ "name_like": "APP%" }),
        "get_schema" => json!({ "owner": "HR" }),
        "describe_table" => json!({ "owner": "HR", "table_name": "EMPLOYEES" }),
        "describe_index" => json!({ "owner": "HR", "index_name": "EMP_NAME_IX" }),
        "describe_trigger" => json!({ "owner": "HR", "trigger_name": "EMP_BIU" }),
        "describe_view" => json!({ "owner": "HR", "view_name": "EMP_DETAILS_VIEW" }),
        "get_ddl" => {
            json!({ "object_type": "TABLE", "owner": "HR", "object_name": "EMPLOYEES" })
        }
        "get_object_source" => {
            json!({ "object_type": "PACKAGE", "owner": "HR", "object_name": "EMP_API" })
        }
        "get_errors" => json!({ "owner": "HR", "object_name": "PKG" }),
        "get_clob" => {
            json!({ "owner": "HR", "table": "DOCS", "clob_col": "BODY", "pk_col": "ID", "pk_val": "42" })
        }
        "preview_sql" => json!({ "sql": "SELECT 1 FROM dual" }),
        other => panic!("no test args for {other}"),
    }
}

#[test]
fn every_registry_tool_routes_and_deserializes_offline() {
    for name in tool_names() {
        let dispatcher = OracleDispatcher::new_switchable(
            Box::new(OneRowMock),
            Some("dev".to_owned()),
            ddl_level(),
            Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
        );
        let args = if name == "execute_approved" {
            let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
            let token = preview_confirm(&dispatcher, sql);
            json!({ "token": token })
        } else {
            args_for(name)
        };
        let out = dispatcher
            .dispatch(name, args)
            .unwrap_or_else(|e| panic!("{name} should route + succeed offline: {e:?}"));
        assert!(out.is_object(), "{name} returns a JSON object");
    }
}

#[test]
fn compatibility_aliases_route_to_prefixed_tools() {
    let dispatcher = OracleDispatcher::new_switchable(
        Box::new(OneRowMock),
        Some("dev".to_owned()),
        default_read_only_level(),
        Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
    );
    for name in [
        "current_database",
        "switch_database",
        "query",
        "compile_object",
        "patch_package",
        "patch_view",
        "read_patch_preview",
        "list_objects",
        "list_schemas",
        "get_schema",
        "describe_table",
        "describe_index",
        "describe_trigger",
        "describe_view",
        "get_ddl",
        "get_object_source",
        "get_errors",
        "get_clob",
        "preview_sql",
    ] {
        let out = dispatcher
            .dispatch(name, args_for(name))
            .unwrap_or_else(|e| panic!("{name} alias should route: {e:?}"));
        assert!(out.is_object(), "{name} returns a JSON object");
    }
}

#[test]
fn connection_info_reports_the_active_profile() {
    let dispatcher =
        OracleDispatcher::new_with_profile(Box::new(OneRowMock), Some("dev".to_owned()));
    let out = dispatcher
        .dispatch("oracle_connection_info", json!({}))
        .expect("connection info");
    assert_eq!(out["active_profile"], json!("dev"));
    assert_eq!(out["connected"], json!(true));
    assert_eq!(out["metadata_cache_key"]["profile"], json!("dev"));
    assert!(
        out["metadata_cache_key"]["visible_schema"]
            .as_str()
            .is_some_and(|value| value.starts_with("schema-sha256:"))
    );
    assert_eq!(
        out["metadata_cache_key"]["serialization_contract_version"],
        json!(oraclemcp_db::ORACLE_CELL_STRUCTURED_CONTRACT_VERSION)
    );
    assert!(
        out["metadata_cache_key"]["db_fingerprint"]
            .as_str()
            .is_some_and(|value| value.starts_with("db-sha256:"))
    );
    assert!(
        out["metadata_cache_key"]["user"]
            .as_str()
            .is_some_and(|value| value.starts_with("user-sha256:"))
    );
    assert_eq!(out["connection"].get("module"), None);
    assert_eq!(out["connection"].get("client_identifier"), None);
    assert_eq!(out["connection"].get("program"), None);
    assert_eq!(out["connection"].get("client_driver"), None);
    let redacted_fields = out["connection"]["redacted_fields"]
        .as_array()
        .expect("redacted fields array");
    for field in ["module", "client_identifier", "program", "client_driver"] {
        assert!(
            redacted_fields.contains(&json!(field)),
            "{field} should be marked redacted in {out}"
        );
    }
    assert_eq!(out["connection"]["read_only"], json!(false));
    let serialized = out.to_string();
    for forbidden in [
        "oraclemcp-test",
        "agent",
        "operator",
        "workstation",
        "oraclemcp-driver",
        "ORCL23A",
        "freepdb1",
        "APP",
    ] {
        assert!(!serialized.contains(forbidden), "{forbidden} leaked: {out}");
    }
}

#[test]
fn connection_info_reports_stateless_read_strategy_when_configured() {
    let session_counts = Arc::new(TouchCounts::default());
    let stateless_counts = Arc::new(TouchCounts::default());
    let dispatcher = OracleDispatcher::new_switchable_with_custom_tools_and_stateless(
        Box::new(LabeledMock::new(
            "session",
            "single_session",
            session_counts.clone(),
        )),
        Some("dev".to_owned()),
        default_read_only_level(),
        Arc::new(|_cx, _profile| {
            Box::pin(async move { Err(DbError::Connect("unused".to_owned())) })
        }),
        StatelessReadStrategy::new(Some(Box::new(LabeledMock::new(
            "pool",
            "stateless_metadata_pool",
            stateless_counts.clone(),
        )))),
        CustomToolCatalog::default(),
        None,
    );

    let out = dispatcher
        .dispatch("oracle_connection_info", json!({}))
        .expect("connection info");

    assert_eq!(
        out["connection"]["connection_strategy"],
        json!("single_session")
    );
    assert_eq!(
        out["stateless_read_connection"]["strategy"],
        json!("stateless_metadata_pool")
    );
    assert_eq!(
        out["stateless_read_connection"]["pool_open_connections"],
        json!(1)
    );
    assert_eq!(session_counts.describe.load(Ordering::SeqCst), 1);
    assert_eq!(stateless_counts.describe.load(Ordering::SeqCst), 1);
}

#[test]
fn profile_switch_opens_one_connection_bundle() {
    let config = OracleMcpConfig::from_toml_str(
        r#"
        [[profiles]]
        name = "dev"
        connect_string = "dev:1521/svc"

        [[profiles]]
        name = "other"
        connect_string = "other:1521/svc"
        credential_ref = "env:ROTATING_PASSWORD"
        "#,
    )
    .expect("config");
    let state = ProfileDrainState::from_config(config);
    let bundle_calls = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&bundle_calls);
    let dispatcher = OracleDispatcher::new_switchable_with_custom_tools_and_stateless(
        Box::new(OneRowMock),
        Some("dev".to_owned()),
        default_read_only_level(),
        Arc::new(move |_cx, generation| {
            assert_eq!(generation.profile(), "other");
            assert_eq!(
                generation
                    .config()
                    .and_then(|config| config.profile("other"))
                    .and_then(|profile| profile.credential_ref.as_deref()),
                Some("env:ROTATING_PASSWORD")
            );
            calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                Ok(ProfileConnectionBundle::new(
                    Box::new(LabeledMock::new(
                        "bundle-session",
                        "single_session",
                        Arc::new(TouchCounts::default()),
                    )),
                    Some(Box::new(LabeledMock::new(
                        "bundle-pool",
                        "stateless_metadata_pool",
                        Arc::new(TouchCounts::default()),
                    ))),
                ))
            })
        }),
        StatelessReadStrategy::none(),
        CustomToolCatalog::default(),
        None,
    )
    .with_profile_drain_state(state);

    let before_generation = catalog_generation(&dispatcher);
    dispatcher
        .dispatch("oracle_switch_profile", json!({ "profile": "other" }))
        .expect("bundle switch succeeds");
    assert_eq!(catalog_generation(&dispatcher), before_generation + 1);
    assert_eq!(bundle_calls.load(Ordering::SeqCst), 1);
    let query = dispatcher
        .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
        .expect("primary bundle connection is active");
    assert_eq!(query["rows"][0]["LABEL"], json!("bundle-session"));
    let schemas = dispatcher
        .dispatch("oracle_list_schemas", json!({ "max_rows": 1 }))
        .expect("stateless bundle connection is active");
    assert_eq!(schemas["schemas"][0]["SCHEMA_NAME"], json!("bundle-pool"));
}

#[test]
fn reload_rejects_a_connection_prepared_from_the_stale_generation() {
    let before = OracleMcpConfig::from_toml_str(
        r#"
        [[profiles]]
        name = "dev"
        connect_string = "dev:1521/svc"

        [[profiles]]
        name = "prod"
        connect_string = "old-prod:1521/svc"
        "#,
    )
    .expect("before config");
    let after = OracleMcpConfig::from_toml_str(
        r#"
        [[profiles]]
        name = "dev"
        connect_string = "dev:1521/svc"

        [[profiles]]
        name = "prod"
        connect_string = "new-prod:1521/svc"
        "#,
    )
    .expect("after config");
    let drain = ProfileDrainState::from_config(before.clone());
    let (started_tx, started_rx) = std_mpsc::channel();
    let (release_tx, release_rx) = std_mpsc::channel();
    let first_release = Arc::new(Mutex::new(Some(release_rx)));
    let release_for_connector = Arc::clone(&first_release);
    let connector_calls = Arc::new(AtomicUsize::new(0));
    let calls_for_connector = Arc::clone(&connector_calls);
    let dispatcher = Arc::new(
        OracleDispatcher::new_switchable(
            Box::new(LabeledMock::new(
                "old-lane",
                "single_session",
                Arc::new(TouchCounts::default()),
            )),
            Some("dev".to_owned()),
            default_read_only_level(),
            Arc::new(move |_cx, generation| {
                let generation_number = generation.generation();
                let call = calls_for_connector.fetch_add(1, Ordering::SeqCst);
                let release = if call == 0 {
                    release_for_connector.lock().expect("release mutex").take()
                } else {
                    None
                };
                let started_tx = started_tx.clone();
                Box::pin(async move {
                    if let Some(release) = release {
                        started_tx.send(()).expect("announce blocked connector");
                        release.recv().expect("release blocked connector");
                    }
                    let label = match generation_number {
                        1 => "generation-1",
                        2 => "generation-2",
                        _ => "unexpected-generation",
                    };
                    Ok(session_bundle(LabeledMock::new(
                        label,
                        "single_session",
                        Arc::new(TouchCounts::default()),
                    )))
                })
            }),
        )
        .with_profile_drain_state(drain.clone()),
    );

    let switching = Arc::clone(&dispatcher);
    let stale_switch = std::thread::spawn(move || {
        switching.dispatch("oracle_switch_profile", json!({ "profile": "prod" }))
    });
    started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("generation-1 connector blocks after admission");
    drain
        .apply_config_reload_plan(&ConfigReloadPlan::between(&before, &after), &before, &after)
        .expect("generation-2 reload applies while connector is blocked");
    release_tx.send(()).expect("release generation-1 connector");

    let error = stale_switch
        .join()
        .expect("stale switch thread")
        .expect_err("generation-1 connection cannot bind after generation-2 reload");
    assert_eq!(error.error_class, ErrorClass::RuntimeStateRequired);
    assert!(error.message.contains("draining"));

    let current = dispatcher
        .dispatch("oracle_connection_info", json!({}))
        .expect("old lane remains active after stale switch rejection");
    assert_eq!(current["active_profile"], json!("dev"));
    let query = dispatcher
        .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
        .expect("old connection remains usable");
    assert_eq!(query["rows"][0]["LABEL"], json!("old-lane"));

    let switched = dispatcher
        .dispatch("oracle_switch_profile", json!({ "profile": "prod" }))
        .expect("the current generation can be opened after stale rejection");
    assert_eq!(switched["profile_generation"], json!(2));
    let query = dispatcher
        .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
        .expect("generation-2 connection is active");
    assert_eq!(query["rows"][0]["LABEL"], json!("generation-2"));
    assert_eq!(connector_calls.load(Ordering::SeqCst), 2);
}

#[test]
fn stateless_pool_is_used_only_for_metadata_tools() {
    let session_counts = Arc::new(TouchCounts::default());
    let stateless_counts = Arc::new(TouchCounts::default());
    let dispatcher = OracleDispatcher::new_switchable_with_custom_tools_and_stateless(
        Box::new(LabeledMock::new(
            "session",
            "single_session",
            session_counts.clone(),
        )),
        Some("dev".to_owned()),
        default_read_only_level(),
        Arc::new(|_cx, _profile| {
            Box::pin(async move { Err(DbError::Connect("unused".to_owned())) })
        }),
        StatelessReadStrategy::new(Some(Box::new(LabeledMock::new(
            "pool",
            "stateless_metadata_pool",
            stateless_counts.clone(),
        )))),
        CustomToolCatalog::default(),
        None,
    );

    let schemas = dispatcher
        .dispatch("oracle_list_schemas", json!({ "max_rows": 1 }))
        .expect("metadata uses stateless connection");
    assert_eq!(schemas["schemas"][0]["SCHEMA_NAME"], json!("pool"));
    assert_eq!(session_counts.query.load(Ordering::SeqCst), 0);
    assert_eq!(stateless_counts.query.load(Ordering::SeqCst), 1);

    let query = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT 1 AS label FROM dual" }),
        )
        .expect("read query stays on pinned session");
    assert_eq!(query["rows"][0]["LABEL"], json!("session"));
    assert_eq!(session_counts.query.load(Ordering::SeqCst), 1);
    assert_eq!(stateless_counts.query.load(Ordering::SeqCst), 1);

    let _sample = dispatcher
        .dispatch(
            "oracle_sample_rows",
            json!({ "owner": "APP", "table": "T", "max_rows": 1 }),
        )
        .expect("sample rows stays on pinned session");
    assert_eq!(session_counts.query.load(Ordering::SeqCst), 2);
    assert_eq!(stateless_counts.query.load(Ordering::SeqCst), 1);
}

#[test]
fn connection_info_degrades_when_describe_fails() {
    let dispatcher =
        OracleDispatcher::new_with_profile(Box::new(DescribeFailingMock), Some("dev".to_owned()));

    for tool in ["oracle_connection_info", "current_database"] {
        let out = dispatcher
            .dispatch(tool, json!({}))
            .unwrap_or_else(|e| panic!("{tool} should degrade without tool error: {e:?}"));
        assert_eq!(out["active_profile"], json!("dev"));
        assert_eq!(out["connected"], json!(false));
        assert_eq!(out["connection"], Value::Null);
        assert_eq!(
            out["connection_error"]["error_class"],
            json!("RUNTIME_STATE_REQUIRED")
        );
        assert_eq!(
            out["connection_error"]["suggested_tool"],
            json!("oracle_list_profiles")
        );
        assert_eq!(
            out["next_actions"][0]["tool"],
            json!("oracle_list_profiles")
        );
        assert_eq!(out["next_actions"][1]["command"], json!("oraclemcp"));
        assert_eq!(
            out["next_actions"][1]["args"],
            json!(["--json", "doctor", "--online", "--profile", "dev"])
        );
    }
}

#[test]
fn profile_response_omits_connection_and_secret_material() {
    let cfg = OracleMcpConfig::from_toml_str(
        r#"
            default_profile = "prod"

            [[profiles]]
            name = "prod"
            description = "Production profile"
            connect_string = "prod:1521/svc"
            username = "svc_acct"
            credential_ref = "env:ORACLE_PASSWORD"
            max_level = "READ_ONLY"
            default_level = "READ_ONLY"

            [profiles.proxy_auth]
            proxy_user = "svc_acct"
            target_schema = "APP_OWNER"
            "#,
    )
    .expect("valid config");

    let drain = ProfileDrainState::from_config(cfg);
    let out =
        profiles_response(&McpExposurePolicy::AllowAll, &drain).expect("accepted profile snapshot");
    assert_eq!(out["profiles"][0]["name"], json!("prod"));
    assert_eq!(out["profiles"][0]["is_default"], json!(true));

    let serialized = serde_json::to_string(&out).expect("json");
    for hidden in [
        "prod:1521/svc",
        "svc_acct",
        "APP_OWNER",
        "ORACLE_PASSWORD",
        "connect_string",
        "credential_ref",
        "proxy_auth",
        "target_schema",
        "username",
    ] {
        assert!(
            !serialized.contains(hidden),
            "{hidden} leaked into profile response"
        );
    }
}

#[test]
fn failed_profile_switch_does_not_replace_the_current_connection() {
    let dispatcher = OracleDispatcher::new_switchable(
        Box::new(OneRowMock),
        Some("dev".to_owned()),
        default_read_only_level(),
        Arc::new(|_cx, _profile| {
            Box::pin(async move { Err(DbError::Connect("connect failed".to_owned())) })
        }),
    );

    let err = dispatcher
        .dispatch("oracle_switch_profile", json!({ "db": "broken" }))
        .expect_err("canonical switch profile accepts db alias before switch errors");
    assert_eq!(err.error_class, ErrorClass::ConnectionFailed);

    let out = dispatcher
        .dispatch("oracle_connection_info", json!({}))
        .expect("current connection still usable");
    assert_eq!(out["active_profile"], json!("dev"));
}

#[test]
fn switch_profile_at_capacity_keeps_old_conn() {
    let old_counts = Arc::new(TouchCounts::default());
    let new_counts = Arc::new(TouchCounts::default());
    let connector_calls = Arc::new(AtomicUsize::new(0));
    let new_counts_for_connector = new_counts.clone();
    let connector_calls_for_connector = connector_calls.clone();
    let dispatcher = OracleDispatcher::new_switchable_with_custom_tools(
        Box::new(LabeledMock::new(
            "old",
            "single_session",
            old_counts.clone(),
        )),
        Some("dev".to_owned()),
        default_read_only_level(),
        Arc::new(move |_cx, profile| {
            assert_eq!(profile.profile(), "other");
            connector_calls_for_connector.fetch_add(1, Ordering::SeqCst);
            let counts = new_counts_for_connector.clone();
            Box::pin(async move {
                Ok(session_bundle(LabeledMock::new(
                    "new",
                    "single_session",
                    counts,
                )))
            })
        }),
        CustomToolCatalog::default(),
        Some(Arc::new(|profile, _level| {
            assert_eq!(profile.profile(), "other");
            Err(
                ErrorEnvelope::new(ErrorClass::AtCapacity, "profile capacity exhausted")
                    .with_retry_after_ms(250),
            )
        })),
    );

    let err = dispatcher
        .dispatch("oracle_switch_profile", json!({ "profile": "other" }))
        .expect_err("capacity refusal aborts the switch before commit");
    assert_eq!(err.error_class, ErrorClass::AtCapacity);
    assert_eq!(
        connector_calls.load(Ordering::SeqCst),
        1,
        "the replacement connection was acquired before the capacity refusal"
    );
    assert_eq!(
        new_counts.describe.load(Ordering::SeqCst),
        1,
        "the prepared replacement was described before the refusal"
    );

    let query = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT 1 AS label FROM dual" }),
        )
        .expect("old pinned connection remains usable");
    assert_eq!(query["rows"][0]["LABEL"], json!("old"));
    assert_eq!(old_counts.query.load(Ordering::SeqCst), 1);

    let out = dispatcher
        .dispatch("oracle_connection_info", json!({}))
        .expect("active profile remains the old profile");
    assert_eq!(out["active_profile"], json!("dev"));
}

#[test]
fn poisoned_quarantine_during_switch_returns_without_generation_deadlock() {
    let config = OracleMcpConfig::from_toml_str(
        r#"
        [[profiles]]
        name = "dev"
        connect_string = "dev:1521/svc"

        [[profiles]]
        name = "other"
        connect_string = "other:1521/svc"
        "#,
    )
    .expect("config");
    let drain = ProfileDrainState::from_config(config);
    let dispatcher = Arc::new(
        OracleDispatcher::new_switchable(
            Box::new(OneRowMock),
            Some("dev".to_owned()),
            default_read_only_level(),
            Arc::new(|_cx, _generation| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
        )
        .with_profile_drain_state(drain.clone()),
    );

    let poison_target = Arc::clone(&dispatcher);
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _guard = poison_target.quarantine.lock().expect("quarantine lock");
        panic!("poison quarantine for regression");
    }));
    assert!(poisoned.is_err());

    let worker = Arc::clone(&dispatcher);
    let (result_tx, result_rx) = std_mpsc::channel();
    let thread = std::thread::spawn(move || {
        result_tx
            .send(worker.dispatch("oracle_switch_profile", json!({ "profile": "other" })))
            .expect("send switch result");
    });
    let error = result_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("switch must not deadlock while dropping the pending lease")
        .expect_err("poisoned quarantine aborts switch");
    thread.join().expect("switch thread");
    assert_eq!(error.error_class, ErrorClass::Internal);
    assert!(error.message.contains("connection-quarantine mutex"));
    assert_eq!(
        dispatcher.request_timeout().expect("request timeout lock"),
        Some(DEFAULT_REQUEST_TIMEOUT),
        "fallible commit setup restores the old lane timeout"
    );

    let generations = drain.inner.lock().expect("generation lock");
    assert_eq!(
        generations.profiles["dev"].live_generations.get(&1),
        Some(&1),
        "the old lane keeps its generation lease"
    );
    assert!(
        generations.profiles["other"].live_generations.is_empty(),
        "the failed prepared lane releases its lease after the generation lock"
    );
}

#[test]
fn missing_profile_switch_target_is_actionable_invalid_arguments() {
    let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
    let err = dispatcher
        .dispatch("oracle_switch_profile", json!({}))
        .expect_err("missing profile target is rejected before reconnect");
    assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    assert!(err.message.contains("profile"));
    assert!(err.message.contains("db"));
    assert_eq!(err.suggested_tool.as_deref(), Some("oracle_list_profiles"));
    assert!(
        err.next_steps
            .iter()
            .any(|step| step.contains("oracle_list_profiles"))
    );

    let err = dispatcher
        .dispatch("switch_database", json!({ "db": " " }))
        .expect_err("blank db alias is rejected before reconnect");
    assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    assert!(err.message.contains("profile"));
    assert!(err.message.contains("db"));
    assert_eq!(err.suggested_tool.as_deref(), Some("oracle_list_profiles"));
}

#[test]
fn profile_switch_reports_metadata_errors_after_switching() {
    let dispatcher = OracleDispatcher::new_switchable(
        Box::new(OneRowMock),
        Some("dev".to_owned()),
        default_read_only_level(),
        Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(DescribeFailingMock)) })),
    );

    let out = dispatcher
        .dispatch("oracle_switch_profile", json!({ "profile": "offline" }))
        .expect("switch succeeds even if metadata is unavailable");
    assert_eq!(out["active_profile"], json!("offline"));
    assert_eq!(out["connected"], json!(false));
    assert_eq!(out["connection"], Value::Null);
    assert_eq!(out["custom_tool_count"], json!(0));
    assert_eq!(
        out["connection_error"]["error_class"],
        json!("RUNTIME_STATE_REQUIRED")
    );
    assert_eq!(
        out["connection_error"]["suggested_tool"],
        json!("oracle_list_profiles")
    );

    let current = dispatcher
        .dispatch("oracle_connection_info", json!({}))
        .expect("current profile uses the switched connection");
    assert_eq!(current["active_profile"], json!("offline"));
    assert_eq!(current["connected"], json!(false));
}

/// E5 connection-scope isolation: a switchable dispatcher with an explicit
/// allow-list containing only `agent_ro` (NOT `prod_admin`). Used by the
/// adversarial isolation tests below.
fn exposed_only_dispatcher() -> OracleDispatcher {
    OracleDispatcher::new_switchable(
        Box::new(OneRowMock),
        Some("agent_ro".to_owned()),
        default_read_only_level(),
        // The connector would happily connect to anything; the E5 gate must
        // refuse the non-exposed name BEFORE the connector is ever reached.
        Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
    )
    .with_mcp_exposure(McpExposurePolicy::AllowList(
        ["agent_ro".to_owned()].into_iter().collect(),
    ))
}

#[test]
fn e5_switch_to_an_exposed_profile_is_allowed() {
    let dispatcher = exposed_only_dispatcher();
    let out = dispatcher
        .dispatch("oracle_switch_profile", json!({ "profile": "agent_ro" }))
        .expect("switching to an mcp_exposed profile is permitted");
    assert_eq!(out["active_profile"], json!("agent_ro"));
}

#[test]
fn e5_adversarial_guessed_non_exposed_profile_is_rejected_by_switch() {
    // The load-bearing E5 adversarial test: an agent that GUESSES the name of a
    // profile the operator did not expose (`prod_admin`) must be refused by
    // oracle_switch_profile, and the refusal must not reveal that the name
    // happened to match a real-but-hidden profile (same envelope as a wholly
    // unknown name).
    let dispatcher = exposed_only_dispatcher();

    let hidden = dispatcher
        .dispatch("oracle_switch_profile", json!({ "profile": "prod_admin" }))
        .expect_err("a guessed non-exposed profile is refused by switch");
    let unknown = dispatcher
        .dispatch(
            "oracle_switch_profile",
            json!({ "profile": "totally_made_up" }),
        )
        .expect_err("a wholly unknown profile is refused by switch");

    assert_eq!(hidden.error_class, ErrorClass::InvalidArguments);
    assert_eq!(unknown.error_class, ErrorClass::InvalidArguments);
    // Indistinguishable: a hidden profile and an unknown one yield the identical
    // class and (modulo the echoed name) message, so the agent learns nothing.
    assert_eq!(
        hidden.message.replace("prod_admin", "X"),
        unknown.message.replace("totally_made_up", "X"),
        "a hidden profile must be indistinguishable from an unknown one"
    );
    assert_eq!(
        hidden.suggested_tool.as_deref(),
        Some("oracle_list_profiles")
    );

    // And the active connection is untouched — the failed switch never reached
    // the connector.
    let current = dispatcher
        .dispatch("oracle_connection_info", json!({}))
        .expect("current connection still usable");
    assert_eq!(current["active_profile"], json!("agent_ro"));

    // The `switch_database`/`db` compatibility alias is gated identically.
    let alias = dispatcher
        .dispatch("switch_database", json!({ "db": "prod_admin" }))
        .expect_err("the db alias is gated by E5 too");
    assert_eq!(alias.error_class, ErrorClass::InvalidArguments);
}

#[test]
fn e5_list_profiles_omits_non_exposed_profiles() {
    // The served oracle_list_profiles must filter to the exposure allow-list, so
    // a hidden profile never appears (and so can never be guessed FROM the list).
    let cfg = OracleMcpConfig::from_toml_str(
        r#"
            [[profiles]]
            name = "agent_ro"
            connect_string = "ro:1521/svc"
            mcp_exposed = true

            [[profiles]]
            name = "prod_admin"
            connect_string = "prod:1521/svc"
            "#,
    )
    .expect("valid config");

    let exposed = McpExposurePolicy::AllowList(["agent_ro".to_owned()].into_iter().collect());
    let drain = ProfileDrainState::from_config(cfg);
    let out = profiles_response(&exposed, &drain).expect("accepted profile snapshot");
    let names: Vec<&str> = out["profiles"]
        .as_array()
        .expect("profiles array")
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec!["agent_ro"],
        "only the exposed profile is listed"
    );
    let serialized = serde_json::to_string(&out).expect("json");
    assert!(
        !serialized.contains("prod_admin"),
        "a non-exposed profile name must never be surfaced"
    );
}

#[test]
fn s5_draining_profiles_are_not_listed_or_switchable() {
    let cfg = OracleMcpConfig::from_toml_str(
        r#"
            [[profiles]]
            name = "agent_ro"
            connect_string = "ro:1521/svc"

            [[profiles]]
            name = "rotated"
            connect_string = "rotated:1521/svc"
            "#,
    )
    .expect("valid config");
    let after = OracleMcpConfig::from_toml_str(
        r#"
            [[profiles]]
            name = "agent_ro"
            connect_string = "ro:1521/svc"
            "#,
    )
    .expect("valid reloaded config");
    let plan = ConfigReloadPlan::between(&cfg, &after);
    let drain = ProfileDrainState::from_config(cfg.clone());
    drain
        .apply_config_reload_plan(&plan, &cfg, &after)
        .expect("reload plan applies");

    let out =
        profiles_response(&McpExposurePolicy::AllowAll, &drain).expect("accepted profile snapshot");
    let names: Vec<&str> = out["profiles"]
        .as_array()
        .expect("profiles array")
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["agent_ro"]);

    let dispatcher = OracleDispatcher::new_switchable(
        Box::new(OneRowMock),
        Some("agent_ro".to_owned()),
        default_read_only_level(),
        Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
    )
    .with_profile_drain_state(drain);
    let err = dispatcher
        .dispatch("oracle_switch_profile", json!({ "profile": "rotated" }))
        .expect_err("removed profile is refused before reconnect");
    assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    assert!(
        err.message.contains("not available"),
        "removed, hidden, and unknown names remain indistinguishable"
    );

    let current = dispatcher
        .dispatch("oracle_connection_info", json!({}))
        .expect("failed switch does not replace active profile");
    assert_eq!(current["active_profile"], json!("agent_ro"));
}

#[test]
fn stale_lane_lease_cannot_bind_after_reload_advances_generation() {
    let before = OracleMcpConfig::from_toml_str(
        r#"
        [[profiles]]
        name = "prod"
        connect_string = "old:1521/svc"
        "#,
    )
    .expect("before config");
    let after = OracleMcpConfig::from_toml_str(
        r#"
        [[profiles]]
        name = "prod"
        connect_string = "new:1521/svc"
        "#,
    )
    .expect("after config");
    let state = ProfileDrainState::from_config(before.clone());
    let prepared = match state.admit_mcp_profile("prod", true) {
        ProfileGenerationAdmission::Ready(lease) => lease,
        other => panic!("old generation was not admitted: {other:?}"),
    };
    state
        .apply_config_reload_plan(&ConfigReloadPlan::between(&before, &after), &before, &after)
        .expect("reload applies before lane bind");

    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(OneRowMock),
        Some("prod".to_owned()),
        default_read_only_level(),
    );
    let error = match dispatcher.with_profile_generation_lease(state.clone(), prepared) {
        Ok(_) => panic!("stale connection preparation must not bind to the new generation"),
        Err(error) => error,
    };
    assert_eq!(error.error_class, ErrorClass::RuntimeStateRequired);
    assert!(error.message.contains("draining"));
    assert!(
        state.draining_profiles().is_empty(),
        "failed bind releases the final old-generation lease"
    );
}

#[test]
fn connection_diagnostics_report_exact_generation_without_config_secrets() {
    let before = OracleMcpConfig::from_toml_str(
        r#"
        [[profiles]]
        name = "prod"
        connect_string = "secret-old-host:1521/svc"
        credential_ref = "env:SECRET_PASSWORD"
        "#,
    )
    .expect("before config");
    let after = OracleMcpConfig::from_toml_str(
        r#"
        [[profiles]]
        name = "prod"
        connect_string = "secret-new-host:1521/svc"
        credential_ref = "env:ROTATED_SECRET_PASSWORD"
        "#,
    )
    .expect("after config");
    let state = ProfileDrainState::from_config(before.clone());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(OneRowMock),
        Some("prod".to_owned()),
        default_read_only_level(),
    )
    .with_profile_drain_state(state.clone());

    let current = dispatcher
        .dispatch("oracle_connection_info", json!({}))
        .expect("current generation diagnostics");
    assert_eq!(current["active_profile"], json!("prod"));
    assert_eq!(current["profile_generation_active"], json!(true));
    assert_eq!(current["profile_generation"], json!(1));
    assert_eq!(current["profile_generation_draining"], json!(false));

    state
        .apply_config_reload_plan(&ConfigReloadPlan::between(&before, &after), &before, &after)
        .expect("reload applies");
    let stale = dispatcher
        .dispatch("oracle_connection_info", json!({}))
        .expect("stale generation remains diagnosable");
    assert_eq!(stale["profile_generation"], json!(1));
    assert_eq!(stale["profile_generation_draining"], json!(true));
    let rendered = serde_json::to_string(&stale).expect("diagnostics json");
    for secret in [
        "secret-old-host",
        "secret-new-host",
        "SECRET_PASSWORD",
        "ROTATED_SECRET_PASSWORD",
    ] {
        assert!(!rendered.contains(secret), "diagnostics leaked {secret}");
    }
}

#[test]
fn s5_active_drained_profile_refuses_non_diagnostic_work() {
    let drain = ProfileDrainState::default();
    drain.replace_draining_profiles(["old_profile"]);
    let dispatcher =
        OracleDispatcher::new_with_profile(Box::new(OneRowMock), Some("old_profile".to_owned()))
            .with_profile_drain_state(drain);

    let info = dispatcher
        .dispatch("oracle_connection_info", json!({}))
        .expect("diagnostic connection info remains available during drain");
    assert_eq!(info["active_profile"], json!("old_profile"));

    let err = dispatcher
        .dispatch("oracle_query", json!({ "sql": "select 1 from dual" }))
        .expect_err("drained profile refuses new work");
    assert_eq!(err.error_class, ErrorClass::RuntimeStateRequired);
    assert!(err.message.contains("draining"));
}

#[test]
fn e5_from_config_opt_out_hides_only_explicit_false() {
    // Per-profile opt-out: a zero-config / single-profile setup (no mcp_exposed
    // anywhere) yields AllowAll so every profile is reachable out of the box.
    let zero = OracleMcpConfig::from_toml_str(
        r#"
            [[profiles]]
            name = "only"
            connect_string = "db:1521/svc"
            "#,
    )
    .expect("valid config");
    let policy = McpExposurePolicy::from_config(&zero);
    assert!(
        matches!(policy, McpExposurePolicy::AllowAll),
        "nothing hidden -> expose all (usable out of the box)"
    );
    assert!(policy.is_exposed("only"));

    // Two profiles, neither hidden -> still AllowAll (`mcp_exposed = true` is a
    // no-op confirmation of the default; it does not segment).
    let both_default = OracleMcpConfig::from_toml_str(
        r#"
            [[profiles]]
            name = "agent_ro"
            connect_string = "ro:1521/svc"
            mcp_exposed = true

            [[profiles]]
            name = "dev"
            connect_string = "dev:1521/svc"
            "#,
    )
    .expect("valid config");
    let policy = McpExposurePolicy::from_config(&both_default);
    assert!(
        matches!(policy, McpExposurePolicy::AllowAll),
        "no profile hidden -> AllowAll regardless of an explicit = true"
    );
    assert!(policy.is_exposed("agent_ro"));
    assert!(policy.is_exposed("dev"));

    // The moment one profile sets `mcp_exposed = false`, ONLY that one is hidden;
    // the others stay reachable (no global flip).
    let one_hidden = OracleMcpConfig::from_toml_str(
        r#"
            [[profiles]]
            name = "agent_ro"
            connect_string = "ro:1521/svc"

            [[profiles]]
            name = "prod_admin"
            connect_string = "prod:1521/svc"
            mcp_exposed = false
            "#,
    )
    .expect("valid config");
    let policy = McpExposurePolicy::from_config(&one_hidden);
    assert!(matches!(policy, McpExposurePolicy::AllowList(_)));
    assert!(
        policy.is_exposed("agent_ro"),
        "an unflagged profile stays exposed even when another is hidden"
    );
    assert!(
        !policy.is_exposed("prod_admin"),
        "the explicitly hidden profile is unreachable"
    );
}

#[test]
fn compile_errors_can_default_to_current_schema() {
    let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
    let out = dispatcher
        .dispatch("oracle_compile_errors", json!({}))
        .expect("compile errors defaults owner");
    assert!(out["errors"].is_array());
}

#[test]
fn schema_inspect_can_default_to_current_schema() {
    let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
    let out = dispatcher
        .dispatch("oracle_schema_inspect", json!({}))
        .expect("schema inspect defaults owner");
    assert_eq!(out["owner"], json!("APP"));
    assert_eq!(out["max_rows"], json!(DEFAULT_SCHEMA_INSPECT_MAX_ROWS));
    assert!(out["objects"].is_array());
}

/// E4: a scripted mock that drives `oracle_search_objects` through dispatch,
/// returning SQL-shape-dependent rows so the detail levels and the
/// ALL_TABLES.NUM_ROWS path are exercised end-to-end.
struct SearchObjectsDispatchMock;

#[async_trait::async_trait(?Send)]
impl OracleConnection for SearchObjectsDispatchMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo {
            current_schema: Some("APP".to_owned()),
            ..Default::default()
        })
    }
    async fn query_rows(
        &self,
        _cx: &Cx,
        sql: &str,
        _b: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        let row = |pairs: &[(&str, &str)]| OracleRow {
            columns: pairs
                .iter()
                .map(|(n, v)| {
                    (
                        (*n).to_owned(),
                        OracleCell::new("VARCHAR2", Some((*v).to_owned())),
                    )
                })
                .collect(),
        };
        if sql.contains("FROM all_objects") {
            return Ok(vec![row(&[
                ("OWNER", "APP"),
                ("OBJECT_NAME", "EMPLOYEES"),
                ("OBJECT_TYPE", "TABLE"),
                ("STATUS", "VALID"),
            ])]);
        }
        if sql.contains("all_col_comments") {
            return Ok(vec![row(&[
                ("COLUMN_NAME", "ID"),
                ("DATA_TYPE", "NUMBER"),
                ("NULLABLE", "N"),
            ])]);
        }
        if sql.contains("FROM all_indexes") {
            return Ok(vec![row(&[
                ("INDEX_NAME", "EMP_PK"),
                ("UNIQUENESS", "UNIQUE"),
            ])]);
        }
        if sql.contains("all_ind_columns") {
            return Ok(vec![row(&[("COLUMN_NAME", "ID")])]);
        }
        Ok(Vec::new())
    }
    async fn query_optional_row(
        &self,
        _cx: &Cx,
        sql: &str,
        _b: &[OracleBind],
    ) -> Result<Option<OracleRow>, DbError> {
        let row = |pairs: &[(&str, &str)]| {
            Some(OracleRow {
                columns: pairs
                    .iter()
                    .map(|(n, v)| {
                        (
                            (*n).to_owned(),
                            OracleCell::new("VARCHAR2", Some((*v).to_owned())),
                        )
                    })
                    .collect(),
            })
        };
        if sql.contains("FROM all_tables") {
            return Ok(row(&[
                ("NUM_ROWS", "999"),
                ("LAST_ANALYZED", "2026-06-01T00:00:00"),
            ]));
        }
        if sql.contains("COUNT(*) AS column_count") {
            return Ok(row(&[("COLUMN_COUNT", "1")]));
        }
        if sql.contains("all_tab_comments") {
            return Ok(row(&[("COMMENTS", "emp table")]));
        }
        Ok(None)
    }
    async fn execute(&self, _cx: &Cx, s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
        // Generated dictionary reads may assert the transaction-level read-only
        // backstop. Any other execute remains a bug.
        if s == oraclemcp_guard::SET_TRANSACTION_READ_ONLY {
            return Ok(0);
        }
        panic!("oracle_search_objects must not execute non-backstop SQL: {s}");
    }
    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        panic!("oracle_search_objects must be read-only and never commit()");
    }
    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

#[test]
fn search_objects_detail_levels_and_truncation_through_dispatch() {
    let dispatcher = OracleDispatcher::new(Box::new(SearchObjectsDispatchMock));

    // names: identifiers only.
    let names = dispatcher
        .dispatch(
            "oracle_search_objects",
            json!({ "owner": "APP", "detail_level": "names" }),
        )
        .expect("names search");
    assert_eq!(names["detail_level"], json!("names"));
    assert_eq!(names["count"], json!(1));
    assert_eq!(names["results"][0]["object_name"], json!("EMPLOYEES"));
    assert!(names["results"][0].get("num_rows").is_none());
    assert!(names["results"][0].get("columns").is_none());

    // summary: ALL_TABLES.NUM_ROWS estimate + column count + comment, no columns.
    let summary = dispatcher
        .dispatch(
            "oracle_search_objects",
            json!({ "owner": "APP", "detail": "summary" }),
        )
        .expect("summary search");
    assert_eq!(summary["detail_level"], json!("summary"));
    assert_eq!(summary["results"][0]["num_rows"], json!(999));
    assert_eq!(summary["results"][0]["row_count_is_estimate"], json!(true));
    assert_eq!(summary["results"][0]["column_count"], json!(1));
    assert_eq!(summary["results"][0]["comment"], json!("emp table"));
    assert!(summary["results"][0].get("columns").is_none());

    // standard (default): + columns.
    let standard = dispatcher
        .dispatch("oracle_search_objects", json!({ "owner": "APP" }))
        .expect("standard search");
    assert_eq!(standard["detail_level"], json!("standard"));
    assert_eq!(standard["results"][0]["columns"][0]["name"], json!("ID"));
    assert!(standard["results"][0].get("indexes").is_none());

    // full: + indexes.
    let full = dispatcher
        .dispatch(
            "oracle_search_objects",
            json!({ "owner": "APP", "detail_level": "full" }),
        )
        .expect("full search");
    assert_eq!(full["results"][0]["indexes"][0]["name"], json!("EMP_PK"));

    // truncation: max_rows=1 with one returned row flags truncated=true.
    let capped = dispatcher
        .dispatch(
            "oracle_search_objects",
            json!({ "owner": "APP", "detail_level": "names", "max_rows": 1 }),
        )
        .expect("capped search");
    assert_eq!(capped["max_rows"], json!(1));
    assert_eq!(capped["truncated"], json!(true));

    // an unknown detail level is a structured invalid-arguments error.
    let bad = dispatcher
        .dispatch(
            "oracle_search_objects",
            json!({ "owner": "APP", "detail_level": "everything" }),
        )
        .expect_err("unknown detail level rejected");
    assert_eq!(bad.error_class, ErrorClass::InvalidArguments);
}

#[test]
fn list_schemas_accepts_filter_and_limit_alias() {
    let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
    let out = dispatcher
        .dispatch("list_schemas", json!({ "name_like": "app%", "limit": 10 }))
        .expect("schema listing accepts filter and limit alias");
    assert_eq!(out["name_like"], json!("app%"));
    assert_eq!(out["max_rows"], json!(10));
    assert!(out["schemas"].is_array());
    assert_eq!(out["schemas"][0]["SCHEMA_NAME"], json!("APP"));
    assert_eq!(out["schemas"][0]["OBJECT_COUNT"], json!("42"));
}

#[test]
fn schema_inspect_accepts_all_owners_and_limit_alias() {
    let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
    let out = dispatcher
        .dispatch(
            "oracle_schema_inspect",
            json!({ "owner": "*", "object_type": "package", "name_like": "emp%", "limit": 5 }),
        )
        .expect("schema inspect accepts all-owner filters");
    assert_eq!(out["owner"], json!("*"));
    assert_eq!(out["object_type"], json!("package"));
    assert_eq!(out["name_like"], json!("emp%"));
    assert_eq!(out["max_rows"], json!(5));
}

#[test]
fn describe_object_helpers_default_owner_and_accept_legacy_aliases() {
    let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
    let index = dispatcher
        .dispatch("oracle_describe_index", json!({ "index_name": "EMP_IX" }))
        .expect("index description defaults owner");
    assert_eq!(index["owner"], json!("APP"));
    assert!(index["index"].is_object());
    assert!(index["columns"].is_array());
    assert!(index["expressions"].is_array());

    let trigger = dispatcher
        .dispatch(
            "oracle_describe_trigger",
            json!({ "trigger_name": "EMP_BIU" }),
        )
        .expect("trigger description defaults owner");
    assert_eq!(trigger["owner"], json!("APP"));
    assert!(trigger["trigger"].is_object());

    let view = dispatcher
        .dispatch("oracle_describe_view", json!({ "view_name": "EMP_V" }))
        .expect("view description defaults owner");
    assert_eq!(view["owner"], json!("APP"));
    assert!(view["view"].is_object());
    assert!(view["columns"].is_array());
}

#[test]
fn dictionary_tools_accept_default_owner_qualified_names_and_aliases() {
    let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));

    let described = dispatcher
        .dispatch("oracle_describe", json!({ "table_name": "APP.EMPLOYEES" }))
        .expect("describe accepts table_name alias and qualified table");
    assert_eq!(described["owner"], json!("APP"));
    assert_eq!(described["table"], json!("EMPLOYEES"));
    assert!(described["columns"].is_array());
    assert!(described["constraints"].is_array());

    let ddl = dispatcher
        .dispatch(
            "oracle_get_ddl",
            json!({ "object_type": "TABLE", "object_name": "APP.EMPLOYEES" }),
        )
        .expect("ddl accepts object_name alias and qualified name");
    assert_eq!(ddl["owner"], json!("APP"));
    assert_eq!(ddl["name"], json!("EMPLOYEES"));
    assert_eq!(ddl["ddl"], json!("CREATE TABLE ..."));

    let source = dispatcher
        .dispatch(
            "oracle_get_source",
            json!({ "object_type": "PACKAGE", "object_name": "APP.EMP_API" }),
        )
        .expect("source accepts object_name alias and qualified name");
    assert_eq!(source["source"]["owner"], json!("APP"));
    assert_eq!(source["source"]["name"], json!("EMP_API"));

    let sample = dispatcher
        .dispatch(
            "oracle_sample_rows",
            json!({ "table_name": "APP.EMPLOYEES", "limit": 2 }),
        )
        .expect("sample accepts table_name/limit aliases and qualified table");
    assert_eq!(sample["owner"], json!("APP"));
    assert_eq!(sample["table"], json!("EMPLOYEES"));
    assert_eq!(sample["row_count"], json!(1));

    let clob = dispatcher
        .dispatch(
            "oracle_read_clob",
            json!({ "table": "APP.DOCS", "clob_col": "BODY", "pk_col": "ID", "pk_val": "42" }),
        )
        .expect("read_clob accepts old argument aliases");
    assert_eq!(clob["clob"]["owner"], json!("APP"));
    assert_eq!(clob["clob"]["table"], json!("DOCS"));

    let errors = dispatcher
        .dispatch("oracle_compile_errors", json!({ "object_name": "APP.PKG" }))
        .expect("compile errors accepts object_name alias and qualified name");
    assert_eq!(errors["owner"], json!("APP"));
    assert_eq!(errors["name"], json!("PKG"));
    assert!(errors["errors"].is_array());

    let matches = dispatcher
        .dispatch("oracle_search_source", json!({ "needle": "commit" }))
        .expect("search source defaults owner");
    assert_eq!(matches["owner"], json!("APP"));
    assert!(matches["matches"].is_array());

    let all_matches = dispatcher
        .dispatch(
            "oracle_search_source",
            json!({
                "owner": "*",
                "needle": "commit",
                "object_type": "package_body",
                "name_like": "emp%",
                "limit": 999999
            }),
        )
        .expect("search source accepts all-owner, scope filters, and limit alias");
    assert_eq!(all_matches["owner"], json!("*"));
    assert_eq!(all_matches["object_type"], json!("package_body"));
    assert_eq!(all_matches["name_like"], json!("emp%"));
    assert_eq!(all_matches["max_rows"], json!(5000));

    let plscope = dispatcher
        .dispatch(
            "oracle_plscope_inspect",
            json!({ "object_name": "APP.PKG" }),
        )
        .expect("plscope inspect accepts object_name alias and qualified name");
    assert_eq!(plscope["owner"], json!("APP"));
    assert_eq!(plscope["name"], json!("PKG"));
    assert!(plscope["identifiers"].is_array());
    assert!(plscope["statements"].is_array());
}

#[test]
fn get_source_without_object_type_returns_all_visible_sources() {
    let dispatcher = OracleDispatcher::new(Box::new(SourceLookupMock));
    let out = dispatcher
        .dispatch("oracle_get_source", json!({ "name": "EMP_API" }))
        .expect("source lookup can infer visible source types");
    assert_eq!(out["owner"], json!("APP"));
    assert_eq!(out["name"], json!("EMP_API"));
    assert_eq!(out["source_count"], json!(2));
    assert_eq!(out["sources"][0]["object_type"], json!("PACKAGE"));
    assert_eq!(out["sources"][1]["object_type"], json!("PACKAGE BODY"));
}

#[test]
fn patch_source_preview_requires_unique_match_and_returns_confirmation() {
    let dispatcher = OracleDispatcher::new_switchable(
        Box::new(SourceLookupMock),
        Some("dev".to_owned()),
        ddl_level(),
        Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(SourceLookupMock)) })),
    );
    let out = dispatcher
        .dispatch(
            "oracle_patch_source",
            json!({
                "owner": "APP",
                "name": "EMP_API",
                "object_type": "PACKAGE_BODY",
                "old_text": "NULL",
                "new_text": "1",
            }),
        )
        .expect("patch preview succeeds");
    assert_eq!(out["applied"], json!(false));
    assert_eq!(out["preview"], json!(true));
    assert_eq!(out["source_kind"], json!("all_source"));
    assert_eq!(out["object_type"], json!("PACKAGE BODY"));
    assert_eq!(out["match_count"], json!(1));
    assert_eq!(out["diff"]["start_line"], json!(2));
    assert!(
        out["patched_ddl_preview"]["text"]
            .as_str()
            .expect("preview text")
            .contains("CREATE OR REPLACE PACKAGE BODY EMP_API")
    );
    assert_eq!(out["confirmation"]["tool"], json!("oracle_patch_source"));
    assert_eq!(out["next_actions"][0]["tool"], json!("oracle_patch_source"));
    assert!(
        out.get("patch_guard_note").is_none(),
        "package/type bodies use the central classifier, not a patch-only balance override"
    );

    let patched_ddl = out["patched_ddl_preview"]["text"]
        .as_str()
        .expect("complete patched DDL preview");
    let direct = dispatcher
        .dispatch(
            "oracle_create_or_replace",
            json!({ "source_code": patched_ddl }),
        )
        .expect("the same stored body previews through create-or-replace");
    for field in ["danger", "required_level", "gate_decision", "reason"] {
        assert_eq!(
            out[field], direct[field],
            "patch and create-or-replace must share the {field} decision"
        );
    }

    let err = dispatcher
        .dispatch(
            "oracle_patch_source",
            json!({
                "owner": "APP",
                "name": "EMP_API",
                "object_type": "PACKAGE_BODY",
                "old_text": "EMP_API",
                "new_text": "EMP_API2",
            }),
        )
        .expect_err("duplicate exact match is rejected");
    assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    assert!(err.message.contains("matches more than once"));

    let blocked = dispatcher
        .dispatch(
            "oracle_patch_source",
            json!({
                "owner": "APP",
                "name": "EMP_API",
                "object_type": "PACKAGE_BODY",
                "old_text": "NULL",
                "new_text": "EXECUTE/**/IMMEDIATE 'DROP TABLE T'",
            }),
        )
        .expect("unsafe patch previews but does not mint confirmation");
    assert_eq!(blocked["gate_decision"], json!("blocked"));
    assert_eq!(blocked["confirmation"], Value::Null);
}

#[test]
fn patch_type_body_and_create_or_replace_share_guard_decision() {
    let dispatcher = OracleDispatcher::new_switchable(
        Box::new(SourceLookupMock),
        Some("dev".to_owned()),
        ddl_level(),
        Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(SourceLookupMock)) })),
    );
    let patch = dispatcher
        .dispatch(
            "oracle_patch_source",
            json!({
                "owner": "APP",
                "name": "EMPLOYEE_T",
                "object_type": "TYPE_BODY",
                "old_text": "NULL",
                "new_text": "SELF.id := SELF.id",
            }),
        )
        .expect("valid type-body patch previews");
    assert_eq!(patch["object_type"], json!("TYPE BODY"));
    let patched_ddl = patch["patched_ddl_preview"]["text"]
        .as_str()
        .expect("complete patched type-body DDL");
    let direct = dispatcher
        .dispatch(
            "oracle_create_or_replace",
            json!({ "source_code": patched_ddl }),
        )
        .expect("the same type body previews directly");
    for field in ["danger", "required_level", "gate_decision", "reason"] {
        assert_eq!(
            patch[field], direct[field],
            "TYPE BODY patch/create parity drifted for {field}"
        );
    }
}

#[test]
fn patch_source_execute_refetches_and_uses_create_or_replace_gate() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_switchable(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        ddl_level(),
        Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
    );
    let preview_args = json!({
        "owner": "APP",
        "name": "EMP_API",
        "object_type": "PACKAGE_BODY",
        "old_text": "NULL",
        "new_text": "1",
    });
    let preview = dispatcher
        .dispatch("oracle_patch_source", preview_args.clone())
        .expect("patch preview succeeds");
    let confirm = preview["confirmation"]["confirm"]
        .as_str()
        .expect("confirm grant")
        .to_owned();
    let mut execute_args = preview_args;
    execute_args["execute"] = json!(true);
    execute_args["confirm"] = json!(confirm);

    let out = dispatcher
        .dispatch("oracle_patch_source", execute_args)
        .expect("patch execute succeeds");
    assert_eq!(out["applied"], json!(true));
    assert_eq!(out["patch_tool"], json!("oracle_patch_source"));
    let executed = state.executed.lock().expect("executed SQL");
    assert_eq!(executed.len(), 1);
    assert!(
        executed[0]
            .0
            .contains("CREATE OR REPLACE PACKAGE BODY EMP_API")
    );
    assert!(executed[0].0.contains("BEGIN 1; END;"));
    assert_eq!(state.commits.load(Ordering::SeqCst), 1);
}

#[test]
fn patch_view_alias_defaults_to_view_ddl() {
    let dispatcher = OracleDispatcher::new_switchable(
        Box::new(OneRowMock),
        Some("dev".to_owned()),
        ddl_level(),
        Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
    );
    let out = dispatcher
        .dispatch("patch_view", args_for("patch_view"))
        .expect("patch_view defaults object_type");
    assert_eq!(out["preview"], json!(true));
    assert_eq!(out["object_type"], json!("VIEW"));
    assert_eq!(out["source_kind"], json!("dbms_metadata"));
    assert_eq!(out["confirmation"]["tool"], json!("patch_view"));
}

#[test]
fn read_patch_preview_lists_and_reads_last_preview() {
    let dispatcher = OracleDispatcher::new_switchable(
        Box::new(SourceLookupMock),
        Some("dev".to_owned()),
        ddl_level(),
        Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(SourceLookupMock)) })),
    );

    let empty = dispatcher
        .dispatch("read_patch_preview", json!({}))
        .expect("empty preview cache is readable");
    assert_eq!(empty["preview_available"], json!(false));
    assert_eq!(empty["preview_count"], json!(0));

    dispatcher
        .dispatch(
            "patch_package",
            json!({
                "owner": "APP",
                "object_name": "EMP_API",
                "search_text": "NULL",
                "replacement": "1",
            }),
        )
        .expect("patch preview is remembered");

    let listed = dispatcher
        .dispatch("read_patch_preview", json!({}))
        .expect("preview list is readable");
    assert_eq!(listed["preview_available"], json!(true));
    assert_eq!(listed["preview_count"], json!(1));
    assert_eq!(listed["previews"][0]["name"], json!("EMP_API"));

    let read = dispatcher
        .dispatch(
            "read_patch_preview",
            json!({ "name": "EMP_API", "max_chars": 50 }),
        )
        .expect("remembered preview is readable");
    assert_eq!(read["preview_available"], json!(true));
    assert_eq!(read["patch_tool"], json!("patch_package"));
    assert_eq!(read["ddl_preview"]["truncated"], json!(true));
    assert!(
        read["ddl_preview"]["text"]
            .as_str()
            .expect("preview text")
            .starts_with("CREATE OR REPLACE PACKAGE BODY EMP_API")
    );
}

#[test]
fn conflicting_owner_and_qualified_name_is_invalid_arguments() {
    let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
    let err = dispatcher
        .dispatch(
            "oracle_get_ddl",
            json!({ "object_type": "TABLE", "owner": "HR", "name": "APP.EMPLOYEES" }),
        )
        .expect_err("conflicting owners rejected");
    assert_eq!(err.error_class, ErrorClass::InvalidArguments);
}

#[test]
fn unknown_tool_is_invalid_arguments() {
    let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
    let err = dispatcher
        .dispatch("oracle_nonexistent", json!({}))
        .expect_err("unknown tool errors");
    assert_eq!(err.error_class, ErrorClass::InvalidArguments);
}

#[test]
fn custom_read_only_tool_dispatches_with_named_binds() {
    let defs = oraclemcp_core::parse_tools_file(
        r#"
            [[tool]]
            name = "app_customer_lookup"
            description = "Lookup a customer row by id"
            sql = "SELECT id, name FROM app_customers WHERE id = :id"
            output_mode = "rows"

            [[tool.params]]
            name = "id"
            type = "integer"
            required = true
            description = "Customer id"
            "#,
    )
    .expect("custom tool parses");
    let loaded = oraclemcp_core::load_tools(
        &defs,
        &Classifier::new(ClassifierConfig::new()),
        OperatingLevel::ReadOnly,
    )
    .expect("custom tool loads");
    let dispatcher = OracleDispatcher::new_switchable_with_custom_tools(
        Box::new(OneRowMock),
        Some("dev".to_owned()),
        default_read_only_level(),
        Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
        CustomToolCatalog::new(loaded),
        None,
    );

    let out = dispatcher
        .dispatch("app_customer_lookup", json!({ "id": 7 }))
        .expect("custom tool dispatches");
    assert_eq!(out["row_count"], json!(1));
    assert_eq!(out["rows"][0]["OBJECT_NAME"], json!("EMPLOYEES"));
}

#[test]
fn qa45_profile_switch_refreshes_every_discovery_surface_and_execution() {
    fn catalog(name: &str) -> CustomToolCatalog {
        let source = format!(
            r#"
                [[tool]]
                name = "{name}"
                description = "Profile-scoped {name}"
                sql = "SELECT :id AS value FROM dual"
                output_mode = "rows"

                [[tool.params]]
                name = "id"
                type = "integer"
                required = true
            "#,
        );
        let defs = oraclemcp_core::parse_tools_file(&source).expect("custom tool parses");
        CustomToolCatalog::new(
            oraclemcp_core::load_tools(
                &defs,
                &Classifier::new(ClassifierConfig::new()),
                OperatingLevel::ReadOnly,
            )
            .expect("custom tool loads"),
        )
    }

    let catalog_a = catalog("custom_a");
    let loader: Arc<CustomToolLoader> = Arc::new(move |profile, _level| match profile.profile() {
        "profile_b" => Ok(catalog("custom_b")),
        "broken" => Err(ErrorEnvelope::new(
            ErrorClass::AtCapacity,
            "injected catalog-load refusal",
        )),
        other => panic!("unexpected profile {other}"),
    });
    let notifications = Arc::new(oraclemcp_core::NotificationHub::new());
    let dispatcher = Arc::new(OracleDispatcher::new_switchable_with_custom_tools(
        Box::new(OneRowMock),
        Some("profile_a".to_owned()),
        default_read_only_level(),
        Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
        catalog_a.clone(),
        Some(loader),
    ));
    let registry = crate::registry::tool_registry();
    let capabilities = oraclemcp_core::CapabilitiesReport::new(
        "test",
        registry.tools.clone(),
        OperatingLevel::ReadOnly,
        oraclemcp_core::FeatureTiers {
            live_db: true,
            engine: false,
            http_transport: false,
        },
    );
    let server =
        oraclemcp_core::OracleMcpServer::new("test", registry, capabilities, dispatcher.clone())
            .with_notifications(Arc::clone(&notifications));

    run_with_current_cx(|_| {
        let before = server
            .handle_jsonrpc_request(
                json!({"jsonrpc":"2.0", "id":1, "method":"tools/list"}),
                None,
            )
            .expect("tools/list response");
        let before_names: Vec<&str> = before["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        assert!(before_names.contains(&"custom_a"));
        assert!(!before_names.contains(&"custom_b"));

        let switch = server
            .handle_jsonrpc_request(
                json!({
                    "jsonrpc":"2.0",
                    "id":10,
                    "method":"tools/call",
                    "params":{
                        "name":"oracle_switch_profile",
                        "arguments":{"profile":"profile_b"}
                    }
                }),
                None,
            )
            .expect("profile switch response");
        assert_eq!(
            switch["result"]["structuredContent"]["custom_catalog_generation"],
            json!(2)
        );
        let changed = server
            .drain_server_notifications(oraclemcp_core::notifications::STDIO_NOTIFICATION_OWNER);
        assert_eq!(changed.len(), 1);
        assert_eq!(
            changed[0]["method"],
            json!("notifications/tools/list_changed")
        );

        let after = server
            .handle_jsonrpc_request(
                json!({"jsonrpc":"2.0", "id":2, "method":"tools/list"}),
                None,
            )
            .expect("tools/list response");
        let after_names: Vec<&str> = after["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        assert!(!after_names.contains(&"custom_a"));
        assert!(after_names.contains(&"custom_b"));

        let capabilities = server
            .handle_jsonrpc_request(
                json!({
                    "jsonrpc":"2.0",
                    "id":3,
                    "method":"tools/call",
                    "params":{"name":"oracle_capabilities", "arguments":{}}
                }),
                None,
            )
            .expect("capabilities response");
        let capabilities = &capabilities["result"]["structuredContent"];
        let capability_names: Vec<&str> = capabilities["tools"]
            .as_array()
            .expect("capabilities tools")
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        assert!(!capability_names.contains(&"custom_a"));
        assert!(capability_names.contains(&"custom_b"));

        let resource = server
            .handle_jsonrpc_request(
                json!({
                    "jsonrpc":"2.0",
                    "id":4,
                    "method":"resources/read",
                    "params":{"uri":"oracle://tools"}
                }),
                None,
            )
            .expect("tools resource response");
        let resource: Value = serde_json::from_str(
            resource["result"]["contents"][0]["text"]
                .as_str()
                .expect("resource text"),
        )
        .expect("tools resource JSON");
        let resource_names: Vec<&str> = resource["tools"]
            .as_array()
            .expect("resource tools")
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        assert_eq!(resource_names, after_names);

        dispatcher
            .dispatch("custom_b", json!({"id":7}))
            .expect("newly advertised custom tool executes");
        let stale = dispatcher
            .dispatch("custom_a", json!({}))
            .expect_err("removed custom tool refuses");
        assert_eq!(stale.error_class, ErrorClass::InvalidArguments);

        let failed = server
            .handle_jsonrpc_request(
                json!({
                    "jsonrpc":"2.0",
                    "id":11,
                    "method":"tools/call",
                    "params":{
                        "name":"oracle_switch_profile",
                        "arguments":{"profile":"broken"}
                    }
                }),
                None,
            )
            .expect("catalog refusal response");
        assert_eq!(
            failed["result"]["structuredContent"]["error_class"],
            json!("AT_CAPACITY")
        );
        assert!(
            server
                .drain_server_notifications(
                    oraclemcp_core::notifications::STDIO_NOTIFICATION_OWNER,
                )
                .is_empty()
        );
        let after_failed = server
            .handle_jsonrpc_request(
                json!({"jsonrpc":"2.0", "id":5, "method":"tools/list"}),
                None,
            )
            .expect("tools/list after failed switch");
        let after_failed_names: Vec<&str> = after_failed["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        assert_eq!(after_failed_names, after_names);
        dispatcher
            .dispatch("custom_b", json!({"id":7}))
            .expect("failed switch preserves executable catalog");
    });
}

#[test]
fn qa99_level_changes_and_ttl_expiry_emit_list_changed_only_when_visibility_changes() {
    let dispatcher = Arc::new(OracleDispatcher::new_with_profile_level(
        Box::new(NoExecMock),
        Some("dev".to_owned()),
        SessionLevelState::new(OperatingLevel::ReadWrite, false),
    ));
    let registry = crate::registry::tool_registry();
    let capabilities = oraclemcp_core::CapabilitiesReport::new(
        "test",
        registry.tools.clone(),
        OperatingLevel::ReadOnly,
        oraclemcp_core::FeatureTiers {
            live_db: true,
            engine: false,
            http_transport: false,
        },
    );
    let server = oraclemcp_core::OracleMcpServer::new("test", registry, capabilities, dispatcher);
    let owner = oraclemcp_core::notifications::STDIO_NOTIFICATION_OWNER;
    let call = |id: u64, name: &str, arguments: Value| {
        server
            .handle_jsonrpc_request(
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/call",
                    "params": { "name": name, "arguments": arguments }
                }),
                None,
            )
            .expect("tool response")
    };
    let listed_names = |id: u64| {
        server
            .handle_jsonrpc_request(
                json!({"jsonrpc":"2.0", "id":id, "method":"tools/list"}),
                None,
            )
            .expect("tools/list response")["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
            .collect::<Vec<_>>()
    };

    let read_only = listed_names(1);
    assert!(!read_only.iter().any(|name| name == "oracle_execute"));
    assert!(server.drain_server_notifications(owner).is_empty());

    let preview = call(
        2,
        "oracle_set_session_level",
        json!({"level":"READ_WRITE", "ttl_seconds":60}),
    );
    let confirm = preview["result"]["structuredContent"]["confirmation"]["confirm"]
        .as_str()
        .expect("preview confirmation")
        .to_owned();
    assert!(
        server.drain_server_notifications(owner).is_empty(),
        "preview does not change the served catalog"
    );
    call(
        3,
        "oracle_set_session_level",
        json!({
            "level":"READ_WRITE",
            "ttl_seconds":60,
            "execute":true,
            "confirm":confirm
        }),
    );
    let elevated = server.drain_server_notifications(owner);
    assert_eq!(elevated.len(), 1);
    assert_eq!(
        elevated[0]["method"],
        json!("notifications/tools/list_changed")
    );
    assert!(listed_names(4).iter().any(|name| name == "oracle_execute"));

    call(5, "oracle_set_session_level", json!({"action":"status"}));
    assert!(
        server.drain_server_notifications(owner).is_empty(),
        "status at an unchanged level is silent"
    );
    call(6, "oracle_set_session_level", json!({"action":"drop"}));
    assert_eq!(server.drain_server_notifications(owner).len(), 1);
    assert!(!listed_names(7).iter().any(|name| name == "oracle_execute"));

    let preview = call(
        8,
        "oracle_set_session_level",
        json!({"level":"READ_WRITE", "ttl_seconds":1}),
    );
    let confirm = preview["result"]["structuredContent"]["confirmation"]["confirm"]
        .as_str()
        .expect("second preview confirmation")
        .to_owned();
    call(
        9,
        "oracle_set_session_level",
        json!({
            "level":"READ_WRITE",
            "ttl_seconds":1,
            "execute":true,
            "confirm":confirm
        }),
    );
    assert_eq!(server.drain_server_notifications(owner).len(), 1);
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    server
        .handle_jsonrpc_request(json!({"jsonrpc":"2.0", "id":10, "method":"ping"}), None)
        .expect("ping response after expiry");
    assert_eq!(
        server.drain_server_notifications(owner).len(),
        1,
        "the first request after monotonic TTL expiry reports catalog shrinkage"
    );
    assert!(!listed_names(11).iter().any(|name| name == "oracle_execute"));
}

#[test]
fn malformed_args_are_invalid_arguments_not_a_panic() {
    let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
    // Missing required `table`.
    let err = dispatcher
        .dispatch("oracle_describe", json!({ "owner": "HR" }))
        .expect_err("missing required arg errors");
    assert_eq!(err.error_class, ErrorClass::InvalidArguments);

    let err = dispatcher
        .dispatch("oracle_plscope_inspect", json!({ "owner": "HR" }))
        .expect_err("missing PL/Scope object name errors");
    assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    assert!(err.message.contains("missing required `name`"));
}

#[test]
fn null_args_behave_like_empty_object_args() {
    for name in tool_names() {
        let d_empty = OracleDispatcher::new_switchable(
            Box::new(OneRowMock),
            Some("dev".to_owned()),
            ddl_level(),
            Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
        );
        let d_null = OracleDispatcher::new_switchable(
            Box::new(OneRowMock),
            Some("dev".to_owned()),
            ddl_level(),
            Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
        );
        let empty = d_empty.dispatch(name, json!({}));
        let null = d_null.dispatch(name, Value::Null);
        match (&empty, &null) {
            (Ok(_), Ok(_)) => {}
            (Err(e1), Err(e2)) => assert_eq!(
                e1.error_class, e2.error_class,
                "{name}: omitted-args (null) classified differently from empty object"
            ),
            _ => panic!("{name}: null args and empty-object args disagree (one Ok, one Err)"),
        }
    }
}

#[test]
fn db_error_maps_to_a_classified_envelope() {
    let dispatcher = OracleDispatcher::new(Box::new(FailingMock));
    let err = dispatcher
        .dispatch("oracle_schema_inspect", json!({ "owner": "HR" }))
        .expect_err("ORA-00942 propagates as an envelope");
    assert_eq!(err.error_class, ErrorClass::ObjectNotFound);
    assert_eq!(err.ora_code, Some(942));
}

#[test]
fn oversized_first_query_row_propagates_without_cursor_or_result_entry() {
    let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
    let args = json!({
        "sql": "SELECT object_name, lob_value FROM user_objects",
        "max_result_bytes": 1,
    });

    for attempt in 1..=2 {
        let error = dispatcher
            .dispatch("oracle_query", args.clone())
            .expect_err("an oversized first row must remain a typed dispatch error");
        assert_eq!(error.error_class, ErrorClass::InvalidArguments);
        assert!(error.message.contains("row at offset 0"));
        assert!(error.message.contains("row-payload cap"));

        let wire_error = error.to_json();
        assert!(
            wire_error.get("next_cursor").is_none()
                && wire_error.get("rows").is_none()
                && wire_error.get("result").is_none(),
            "attempt {attempt} emitted a resumable/result entry for a refused row: {wire_error}"
        );
        assert!(
            wire_error.to_string().len() < 1_024,
            "dispatch error must stay bounded independently of row contents"
        );
    }
}

#[test]
fn query_export_is_minted_for_the_dispatch_principal_and_exact_scopes() {
    let exports = Arc::new(oraclemcp_core::ExportRegistry::new());
    let dispatcher =
        OracleDispatcher::new_with_profile(Box::new(OneRowMock), Some("dev".to_owned()))
            .with_exports(Arc::clone(&exports));
    let read = scope_grant("oracle:read");
    let principal_a = "oauth:principal-a";
    let output = dispatcher
        .dispatch_with_context(
            "oracle_query",
            json!({
                "sql": "SELECT object_name FROM user_objects",
                "export": true,
                "export_format": "csv",
            }),
            DispatchContext::with_scope_grant(&read).with_principal_key(principal_a),
        )
        .expect("principal A materializes an export");
    let uri = output["export"]["uri"].as_str().expect("export URI");
    let id = uri
        .strip_prefix("oracle-export://")
        .expect("export URI scheme");

    let owner = oraclemcp_core::ExportAccess::new(
        Some("different-advisory-profile"),
        principal_a,
        Some(&read.0),
    );
    assert!(
        exports.read(id, &owner).is_ok(),
        "same principal and scopes can resume independently of profile"
    );
    let cross_principal =
        oraclemcp_core::ExportAccess::new(Some("dev"), "oauth:principal-b", Some(&read.0));
    let error = exports
        .read(id, &cross_principal)
        .expect_err("same scopes do not transfer export ownership");
    assert_eq!(error.error_class, ErrorClass::ObjectNotFound);
    let public = format!("{uri}{}", error.to_json());
    assert!(!public.contains(principal_a));
    assert!(!public.contains("principal-b"));
}

#[test]
fn query_binds_are_accepted_and_typed() {
    let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
    let out = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT * FROM t WHERE id = :1 AND active = :2", "binds": [42, true] }),
        )
        .expect("binds accepted");
    assert!(out["columns"].is_array() || out.is_object());
}

#[test]
fn query_bind_values_do_not_echo_to_protocol_output() {
    let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
    let out = dispatcher
        .dispatch(
            "oracle_query",
            json!({
                "sql": "SELECT * FROM t WHERE payload = :1 AND id = :2",
                "binds": ["n-s6-bind-secret-not-in-rendered-surfaces", 42424242],
            }),
        )
        .expect("binds accepted");
    let serialized = out.to_string();
    for forbidden in ["n-s6-bind-secret-not-in-rendered-surfaces", "42424242"] {
        assert!(
            !serialized.contains(forbidden),
            "{forbidden} leaked in query output: {out}"
        );
    }
}

#[test]
fn query_accepts_page_and_width_compatibility_args() {
    let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
    let out = dispatcher
        .dispatch(
            "query",
            json!({
                "sql": "SELECT object_name, lob_value FROM user_objects",
                "limit": 25,
                "max_col_width": 3,
                "max_lob_chars": 4,
                "max_result_bytes": 4096,
                "deep_decode": true,
                "max_structured_rows": 2000,
                "max_structured_cells": 20000,
                "max_structured_bytes": 2097152,
                "max_structured_depth": 12,
                "numbers_as_float": false
            }),
        )
        .expect("query args accepted");
    assert_eq!(out["row_count"], json!(1));
    assert_eq!(out["rows"][0]["OBJECT_NAME"]["value"], json!("EMP"));
    assert_eq!(out["rows"][0]["OBJECT_NAME"]["truncated"], json!(true));
    assert_eq!(out["rows"][0]["LOB_VALUE"]["value"], json!("larg"));
    assert_eq!(out["rows"][0]["LOB_VALUE"]["truncated"], json!(true));
}

#[test]
fn query_structured_decode_caps_require_deep_decode_for_larger_limits() {
    let safe_args: QueryArgs = serde_json::from_value(json!({
        "sql": "SELECT json_col FROM t",
        "max_structured_rows": StructuredDecodeCaps::DEEP.max_rows,
        "max_structured_cells": StructuredDecodeCaps::DEEP.max_cells,
        "max_structured_bytes": StructuredDecodeCaps::DEEP.max_bytes,
        "max_structured_depth": StructuredDecodeCaps::DEEP.max_depth
    }))
    .expect("query args parse");
    assert_eq!(
        query_serialize_options_from_args(&safe_args).structured_decode_caps,
        StructuredDecodeCaps::default(),
        "larger structured caps require deep_decode=true"
    );

    let deep_args: QueryArgs = serde_json::from_value(json!({
        "sql": "SELECT json_col FROM t",
        "deep_decode": true
    }))
    .expect("query args parse");
    assert_eq!(
        query_serialize_options_from_args(&deep_args).structured_decode_caps,
        StructuredDecodeCaps::deep()
    );

    let lowered_args: QueryArgs = serde_json::from_value(json!({
        "sql": "SELECT json_col FROM t",
        "deep_decode": true,
        "max_structured_rows": 2,
        "max_structured_cells": 3,
        "max_structured_bytes": 128,
        "max_structured_depth": 4
    }))
    .expect("query args parse");
    assert_eq!(
        query_serialize_options_from_args(&lowered_args).structured_decode_caps,
        StructuredDecodeCaps::new(2, 3, 128, 4)
    );
}

#[test]
fn invalid_bind_type_is_invalid_arguments() {
    let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
    let err = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT 1", "binds": [ {"nested": "object"} ] }),
        )
        .expect_err("object bind rejected");
    assert_eq!(err.error_class, ErrorClass::InvalidArguments);
}

/// A connection that MUST never be touched: any query/execute panics. Proves
/// the read-only gate refuses a statement *before* it can reach Oracle.
struct NoExecMock;
#[async_trait::async_trait(?Send)]
impl OracleConnection for NoExecMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo::default())
    }
    async fn query_rows(
        &self,
        _cx: &Cx,
        _sql: &str,
        _b: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        panic!("a refused statement must never reach the database (query_rows)")
    }
    async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
        panic!("a refused statement must never reach the database (execute)")
    }
    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

#[derive(Default)]
struct TouchCounts {
    ping: AtomicUsize,
    describe: AtomicUsize,
    query: AtomicUsize,
    execute: AtomicUsize,
    commit: AtomicUsize,
    rollback: AtomicUsize,
}

impl TouchCounts {
    fn total(&self) -> usize {
        self.ping.load(Ordering::SeqCst)
            + self.describe.load(Ordering::SeqCst)
            + self.query.load(Ordering::SeqCst)
            + self.execute.load(Ordering::SeqCst)
            + self.commit.load(Ordering::SeqCst)
            + self.rollback.load(Ordering::SeqCst)
    }
}

struct TouchCountingMock {
    counts: Arc<TouchCounts>,
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for TouchCountingMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }

    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        self.counts.ping.fetch_add(1, Ordering::SeqCst);
        panic!("guard-before-I/O test must not ping the database")
    }

    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        self.counts.describe.fetch_add(1, Ordering::SeqCst);
        panic!("guard-before-I/O test must not describe the database")
    }

    async fn query_rows(
        &self,
        _cx: &Cx,
        _sql: &str,
        _b: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        self.counts.query.fetch_add(1, Ordering::SeqCst);
        panic!("guard-before-I/O test must not query the database")
    }

    async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
        self.counts.execute.fetch_add(1, Ordering::SeqCst);
        panic!("guard-before-I/O test must not execute against the database")
    }

    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        self.counts.commit.fetch_add(1, Ordering::SeqCst);
        panic!("guard-before-I/O test must not commit")
    }

    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        self.counts.rollback.fetch_add(1, Ordering::SeqCst);
        panic!("guard-before-I/O test must not roll back")
    }
}

struct LifecycleCleanupMock {
    rollbacks: Arc<AtomicUsize>,
    executes: Arc<AtomicUsize>,
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for LifecycleCleanupMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }

    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo {
            backend: Some(OracleBackend::RustOracle),
            connection_strategy: Some("single_session".to_owned()),
            pool_open_connections: None,
            server_version: None,
            database_role: None,
            open_mode: None,
            db_unique_name: None,
            service_name: None,
            instance_name: None,
            read_only: false,
            read_only_reason: None,
            current_schema: Some("APP".to_owned()),
            current_edition: None,
            session_user: Some("APP".to_owned()),
            current_user: Some("APP".to_owned()),
            proxy_user: None,
            sid: None,
            serial_number: None,
            module: None,
            action: None,
            client_identifier: None,
            client_info: None,
            os_user: None,
            host: None,
            machine: None,
            terminal: None,
            program: None,
            client_driver: None,
            server_features: None,
        })
    }

    async fn query_rows(
        &self,
        _cx: &Cx,
        _sql: &str,
        _b: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        Ok(Vec::new())
    }

    async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
        self.executes.fetch_add(1, Ordering::SeqCst);
        panic!("stale lifecycle grant must fail before database execute")
    }

    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        panic!("stale lifecycle grant must fail before commit")
    }

    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        self.rollbacks.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn close_dispatcher_for_test(
    dispatcher: &OracleDispatcher,
    reason: DispatchCloseReason,
) -> Result<(), ErrorEnvelope> {
    RuntimeBuilder::current_thread()
        .build()
        .expect("asupersync test runtime builds")
        .block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            ToolDispatch::close(dispatcher, &cx, reason).await
        })
}

#[test]
fn lifecycle_close_rolls_back_and_revokes_execution_grants() {
    use oraclemcp_audit::{AuditError, AuditRecord, AuditSink, MemoryAuditSink, SigningKey};

    struct SharedSink(Arc<MemoryAuditSink>);
    impl AuditSink for SharedSink {
        fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.0.append(record)
        }

        fn flush(&self) -> Result<(), AuditError> {
            self.0.flush()
        }
    }

    let rollbacks = Arc::new(AtomicUsize::new(0));
    let executes = Arc::new(AtomicUsize::new(0));
    let sink = Arc::new(MemoryAuditSink::new());
    let auditor = Arc::new(oraclemcp_audit::Auditor::new(
        Box::new(SharedSink(sink.clone())),
        SigningKey::new("test-key", b"lifecycle-close-test-key-12345678".to_vec())
            .expect("valid test key"),
    ));
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(LifecycleCleanupMock {
            rollbacks: Arc::clone(&rollbacks),
            executes: Arc::clone(&executes),
        }),
        Some("dev".to_owned()),
        read_write_level(),
    )
    .with_auditor(auditor);
    let sql = "UPDATE employees SET salary = salary WHERE employee_id = 1";
    let confirm = preview_confirm(&dispatcher, sql);

    close_dispatcher_for_test(&dispatcher, DispatchCloseReason::SessionDelete)
        .expect("lifecycle cleanup succeeds");

    assert_eq!(rollbacks.load(Ordering::SeqCst), 1);
    let records = sink.records();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.tool, "lane_lifecycle");
    assert_eq!(record.sql_preview, "<sql text redacted; see sql_sha256>");
    assert_eq!(
        record.sql_sha256,
        oraclemcp_audit::sha256_hex(b"LANE_CLOSE")
    );
    assert_eq!(
        record.cancel.as_ref().map(|c| c.kind.as_str()),
        Some("User")
    );
    assert_eq!(
        record.cancel.as_ref().map(|c| c.reason.as_str()),
        Some("session_delete")
    );
    assert!(record.hash_is_valid());
    let err = dispatcher
        .dispatch(
            "oracle_execute",
            json!({ "sql": sql, "commit": true, "confirm": confirm }),
        )
        .expect_err("old grant must be rejected after lifecycle close");
    assert_eq!(err.error_class, ErrorClass::RuntimeStateRequired);
    assert!(
        err.message
            .contains("no longer owns an active profile generation"),
        "a closed lane must fail before it can evaluate a stale grant: {}",
        err.message
    );
    assert_eq!(
        executes.load(Ordering::SeqCst),
        0,
        "revoked grant must fail before database execute"
    );
}

#[test]
fn dispatch_reload_and_close_race_releases_only_the_bound_generation() {
    let before = OracleMcpConfig::from_toml_str(
        r#"
        [[profiles]]
        name = "prod"
        connect_string = "old:1521/svc"
        "#,
    )
    .expect("before config");
    let after = OracleMcpConfig::from_toml_str(
        r#"
        [[profiles]]
        name = "prod"
        connect_string = "new:1521/svc"
        "#,
    )
    .expect("after config");
    let plan = ConfigReloadPlan::between(&before, &after);
    let drain = ProfileDrainState::from_config(before.clone());
    let dispatcher = Arc::new(
        OracleDispatcher::new_with_profile_level(
            Box::new(OneRowMock),
            Some("prod".to_owned()),
            default_read_only_level(),
        )
        .with_profile_drain_state(drain.clone()),
    );
    let start = Arc::new(Barrier::new(4));

    let query_dispatcher = Arc::clone(&dispatcher);
    let query_start = Arc::clone(&start);
    let (query_tx, query_rx) = std_mpsc::channel();
    let query = std::thread::spawn(move || {
        query_start.wait();
        query_tx
            .send(query_dispatcher.dispatch(
                "oracle_query",
                json!({ "sql": "SELECT 1 AS label FROM dual" }),
            ))
            .expect("send query result");
    });

    let reload_state = drain.clone();
    let reload_start = Arc::clone(&start);
    let (reload_tx, reload_rx) = std_mpsc::channel();
    let reload_before = before.clone();
    let reload_after = after.clone();
    let reload = std::thread::spawn(move || {
        reload_start.wait();
        reload_tx
            .send(reload_state.apply_config_reload_plan(&plan, &reload_before, &reload_after))
            .expect("send reload result");
    });

    let close_dispatcher = Arc::clone(&dispatcher);
    let close_start = Arc::clone(&start);
    let (close_tx, close_rx) = std_mpsc::channel();
    let close = std::thread::spawn(move || {
        close_start.wait();
        close_tx
            .send(close_dispatcher_for_test(
                close_dispatcher.as_ref(),
                DispatchCloseReason::SessionDelete,
            ))
            .expect("send close result");
    });

    start.wait();
    let query_result = query_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("query completes without lock inversion");
    if let Err(error) = query_result {
        assert_eq!(error.error_class, ErrorClass::RuntimeStateRequired);
    }
    reload_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("reload completes without lock inversion")
        .expect("reload applies");
    close_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("close completes without lock inversion")
        .expect("close succeeds");
    query.join().expect("query thread");
    reload.join().expect("reload thread");
    close.join().expect("close thread");

    let post_close = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT 1 AS label FROM dual" }),
        )
        .expect_err("closed old lane cannot dispatch on the replacement generation");
    assert_eq!(post_close.error_class, ErrorClass::RuntimeStateRequired);
    assert!(drain.draining_profiles().is_empty());
    assert_eq!(
        drain
            .accepted_config()
            .expect("replacement accepted")
            .profile("prod")
            .and_then(|profile| profile.connect_string.as_deref()),
        Some("new:1521/svc")
    );
}

#[test]
fn lifecycle_timeout_close_audits_timeout_reason() {
    use oraclemcp_audit::{AuditError, AuditRecord, AuditSink, MemoryAuditSink, SigningKey};

    struct SharedSink(Arc<MemoryAuditSink>);
    impl AuditSink for SharedSink {
        fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.0.append(record)
        }

        fn flush(&self) -> Result<(), AuditError> {
            self.0.flush()
        }
    }

    let rollbacks = Arc::new(AtomicUsize::new(0));
    let executes = Arc::new(AtomicUsize::new(0));
    let sink = Arc::new(MemoryAuditSink::new());
    let auditor = Arc::new(oraclemcp_audit::Auditor::new(
        Box::new(SharedSink(sink.clone())),
        SigningKey::new("test-key", b"lifecycle-timeout-test-key-12345".to_vec())
            .expect("valid test key"),
    ));
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(LifecycleCleanupMock {
            rollbacks: Arc::clone(&rollbacks),
            executes,
        }),
        Some("dev".to_owned()),
        read_write_level(),
    )
    .with_auditor(auditor);

    close_dispatcher_for_test(&dispatcher, DispatchCloseReason::Timeout)
        .expect("timeout lifecycle cleanup succeeds");

    assert_eq!(rollbacks.load(Ordering::SeqCst), 1);
    let records = sink.records();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.tool, "lane_lifecycle");
    assert_eq!(record.sql_preview, "<sql text redacted; see sql_sha256>");
    assert_eq!(
        record.sql_sha256,
        oraclemcp_audit::sha256_hex(b"LANE_CLOSE")
    );
    assert_eq!(
        record.cancel.as_ref().map(|c| c.kind.as_str()),
        Some("Timeout")
    );
    assert_eq!(
        record.cancel.as_ref().map(|c| c.reason.as_str()),
        Some("idle_timeout")
    );
    assert!(record.hash_is_valid());
}

#[test]
fn finalization_timeout_audits_unknown_before_best_effort_cleanup() {
    use oraclemcp_audit::{
        AuditError, AuditOutcome, AuditRecord, AuditSink, Auditor, MemoryAuditSink, SigningKey,
    };

    struct SharedSink(Arc<MemoryAuditSink>);
    impl AuditSink for SharedSink {
        fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.0.append(record)
        }

        fn flush(&self) -> Result<(), AuditError> {
            self.0.flush()
        }
    }

    struct FinalizationTimeoutMock {
        sink: Arc<MemoryAuditSink>,
        rollbacks: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for FinalizationTimeoutMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            panic!("a known-unknown finalization timeout must audit without awaiting DB evidence")
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            Ok(Vec::new())
        }

        async fn execute(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            Ok(0)
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            let records = self.sink.records();
            assert_eq!(
                records.len(),
                1,
                "durable terminal lifecycle audit must precede best-effort rollback"
            );
            assert_eq!(records[0].outcome, AuditOutcome::UnknownDiscarded);
            self.rollbacks.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    let sink = Arc::new(MemoryAuditSink::new());
    let rollbacks = Arc::new(AtomicUsize::new(0));
    let auditor = Arc::new(Auditor::new(
        Box::new(SharedSink(Arc::clone(&sink))),
        SigningKey::new(
            "test-key",
            b"request-finalization-timeout-test-key".to_vec(),
        )
        .expect("valid test key"),
    ));
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(FinalizationTimeoutMock {
            sink: Arc::clone(&sink),
            rollbacks: Arc::clone(&rollbacks),
        }),
        Some("dev".to_owned()),
        read_write_level(),
    )
    .with_auditor(auditor);

    close_dispatcher_for_test(&dispatcher, DispatchCloseReason::RequestFinalizationTimeout)
        .expect("known-unknown lifecycle record survives best-effort cleanup");

    assert_eq!(rollbacks.load(Ordering::SeqCst), 1);
    let records = sink.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].tool, "lane_lifecycle");
    assert_eq!(records[0].outcome, AuditOutcome::UnknownDiscarded);
    assert_eq!(
        records[0]
            .cancel
            .as_ref()
            .map(|cancel| cancel.reason.as_str()),
        Some("request_finalization_timeout")
    );
    assert!(records[0].hash_is_valid());
    assert_eq!(
        dispatcher
            .connection_quarantine()
            .expect("quarantine lock")
            .expect("finalization timeout quarantines")
            .outcome,
        AuditOutcome::UnknownDiscarded
    );
}

#[test]
fn partial_request_limit_install_failure_quarantines_failed_rollback() {
    #[derive(Default)]
    struct LimitState {
        call_timeout: Mutex<Option<Duration>>,
        request_deadline: Mutex<Option<Time>>,
        deadline_restore_attempts: AtomicUsize,
        timeout_restore_attempts: AtomicUsize,
    }

    struct LimitInstallFailureMock {
        state: Arc<LimitState>,
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for LimitInstallFailureMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            Ok(Vec::new())
        }

        async fn execute(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            Ok(0)
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        fn call_timeout(&self) -> Result<Option<Duration>, DbError> {
            Ok(*self.state.call_timeout.lock().expect("call timeout mutex"))
        }

        fn set_call_timeout(&self, timeout: Option<Duration>) -> Result<(), DbError> {
            if timeout.is_none()
                && self
                    .state
                    .call_timeout
                    .lock()
                    .expect("call timeout mutex")
                    .is_some()
            {
                self.state
                    .timeout_restore_attempts
                    .fetch_add(1, Ordering::SeqCst);
                return Err(DbError::Internal(
                    "injected call-timeout rollback failure".to_owned(),
                ));
            }
            *self.state.call_timeout.lock().expect("call timeout mutex") = timeout;
            Ok(())
        }

        fn request_deadline(&self, _cx: &Cx) -> Result<Option<Time>, DbError> {
            Ok(*self
                .state
                .request_deadline
                .lock()
                .expect("request deadline mutex"))
        }

        fn set_request_deadline(&self, _cx: &Cx, deadline: Option<Time>) -> Result<(), DbError> {
            if deadline.is_none()
                && self
                    .state
                    .request_deadline
                    .lock()
                    .expect("request deadline mutex")
                    .is_some()
            {
                self.state
                    .deadline_restore_attempts
                    .fetch_add(1, Ordering::SeqCst);
                return Err(DbError::Internal(
                    "injected request-deadline rollback failure".to_owned(),
                ));
            }
            *self
                .state
                .request_deadline
                .lock()
                .expect("request deadline mutex") = deadline;
            Ok(())
        }

        fn set_request_quota(
            &self,
            _cx: &Cx,
            quota: Option<DbRequestQuota>,
        ) -> Result<(), DbError> {
            if quota.is_some() {
                return Err(DbError::Internal(
                    "injected request-quota installation failure".to_owned(),
                ));
            }
            Ok(())
        }
    }

    let state = Arc::new(LimitState::default());
    let conn = LimitInstallFailureMock {
        state: Arc::clone(&state),
    };
    let quarantine = SyncMutex::new(None);
    RuntimeBuilder::current_thread()
        .build()
        .expect("asupersync test runtime builds")
        .block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            let deadline = cx.now() + Duration::from_secs(30);
            let quota = DbRequestQuota::new(asupersync::Budget::new().with_poll_quota(10));
            let error = match ConnectionLimitGuard::install(
                &cx,
                &conn,
                Some(&quarantine),
                Some(Duration::from_secs(5)),
                Some(deadline),
                Some(quota),
            ) {
                Ok(_) => panic!("request-quota installation should fail"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("limit rollback also failed"));
        });

    assert_eq!(state.deadline_restore_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(state.timeout_restore_attempts.load(Ordering::SeqCst), 1);
    let quarantine = quarantine
        .lock()
        .expect("quarantine mutex")
        .clone()
        .expect("failed limit rollback quarantines");
    assert_eq!(
        quarantine.outcome,
        oraclemcp_audit::AuditOutcome::UnknownDiscarded
    );
    assert!(
        quarantine
            .message
            .contains("prior limits could not be restored"),
        "{}",
        quarantine.message
    );
}

#[test]
fn writes_ddl_and_dcl_are_refused_before_touching_the_db() {
    let dispatcher = OracleDispatcher::new(Box::new(NoExecMock));
    // Each must be refused fail-closed — and NoExecMock panics if any of
    // them reaches the connection, so a pass here also proves non-execution.
    for sql in [
        "INSERT INTO hr.employees (id) VALUES (1)",
        "UPDATE hr.employees SET salary = 0",
        "DELETE FROM hr.employees",
        "DROP TABLE hr.employees",
        "TRUNCATE TABLE hr.employees",
        "CREATE OR REPLACE PROCEDURE p AS BEGIN NULL; END;",
        "GRANT DBA TO scott",
        "ALTER SYSTEM FLUSH SHARED_POOL",
    ] {
        let err = dispatcher
            .dispatch("oracle_query", json!({ "sql": sql }))
            .expect_err(&format!("expected a fail-closed refusal for: {sql}"));
        assert!(
            matches!(
                err.error_class,
                ErrorClass::OperatingLevelTooLow | ErrorClass::ForbiddenStatement
            ),
            "{sql} -> unexpected class {:?}",
            err.error_class
        );
    }
}

#[test]
fn malformed_and_unauthorized_sql_are_refused_before_any_db_io() {
    let counts = Arc::new(TouchCounts::default());
    let dispatcher = OracleDispatcher::new(Box::new(TouchCountingMock {
        counts: counts.clone(),
    }));

    for sql in [
        "SELECT * FROM",
        "DELETE FROM important_table",
        "SELECT 1 FROM dual; GRANT DBA TO scott",
    ] {
        let err = match dispatcher.dispatch("oracle_query", json!({ "sql": sql })) {
            Ok(value) => panic!("expected fail-closed refusal for {sql}, got {value}"),
            Err(err) => err,
        };
        assert!(
            matches!(
                err.error_class,
                ErrorClass::SyntaxError
                    | ErrorClass::ForbiddenStatement
                    | ErrorClass::OperatingLevelTooLow
            ),
            "{sql} -> unexpected class {:?}",
            err.error_class
        );
    }

    assert_eq!(
        counts.total(),
        0,
        "malformed or unauthorized SQL must be classified before any DB I/O or transaction state"
    );
}

#[test]
fn sequence_nextval_is_refused_by_oracle_query_before_any_db_io() {
    let counts = Arc::new(TouchCounts::default());
    let dispatcher = OracleDispatcher::new(Box::new(TouchCountingMock {
        counts: Arc::clone(&counts),
    }));

    for sql in [
        "SELECT app_seq.NEXTVAL FROM dual",
        "SELECT app.app_seq.nextval FROM dual",
        "SELECT \"App\".\"App Seq\".NEXTVAL FROM dual",
        "SELECT (app_seq . NEXTVAL) AS generated_id FROM dual",
        "SELECT app_seq /* split */ . /* split */ NEXTVAL FROM dual",
        "SELECT app.app_seq.NEXTVAL@prod.example FROM dual",
    ] {
        let err = dispatcher
            .dispatch("oracle_query", json!({ "sql": sql }))
            .expect_err("NEXTVAL must not enter the read-only query path");
        assert_eq!(err.error_class, ErrorClass::OperatingLevelTooLow, "{sql:?}");
    }

    assert_eq!(
        counts.total(),
        0,
        "sequence mutation must be rejected by the guard before any database I/O"
    );
}

#[test]
fn sequence_nextval_dml_execution_warns_that_rollback_cannot_restore_it() {
    let state = Arc::new(ExecState::default());
    let intents = write_intent_log("sequence-nextval");
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(IntentObservingExecMock {
            state: Arc::clone(&state),
            intents: Arc::clone(&intents),
        }),
        Some("dev".to_owned()),
        read_write_level(),
    )
    .with_write_intent_log(Arc::clone(&intents));
    let sql = "INSERT INTO orders (id) VALUES (app_seq.NEXTVAL)";

    let preview = dispatcher
        .dispatch("oracle_preview_sql", json!({ "sql": sql }))
        .expect("NEXTVAL has a governed READ_WRITE preview path");
    assert_eq!(preview["allowed_on_read_only"], json!(false));
    assert_eq!(preview["required_level"], json!("READ_WRITE"));
    assert!(
        preview["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("independently of transaction rollback")),
        "preview must disclose that sequence advancement is permanent"
    );
    let confirm = preview
        .pointer("/execute_confirmation/confirm")
        .and_then(Value::as_str)
        .expect("preview minted a confirmation")
        .to_owned();
    assert_eq!(preview["execute_confirmation"]["commit"], json!(false));
    assert_eq!(
        preview["next_actions"][0]["intent"],
        json!("execute_non_transactional_effect")
    );
    assert_eq!(
        preview["next_actions"][0]["args"]["confirm"],
        json!(confirm.clone())
    );

    let out = dispatcher
        .dispatch("oracle_execute", json!({ "sql": sql, "confirm": confirm }))
        .expect("confirmed NEXTVAL executes only on the governed path");
    assert_eq!(out["committed"], json!(false));
    assert_eq!(out["rolled_back"], json!(true));
    assert!(
        out["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("independently of transaction rollback"))
    );
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 1);
    assert!(
        intents.unresolved().expect("intent snapshot").is_empty(),
        "the confirmed permanent effect must resolve its durable intent after execution"
    );

    let replay = dispatcher
        .dispatch("oracle_execute", json!({ "sql": sql, "confirm": confirm }))
        .expect_err("the confirmation for a permanent effect must be single-use");
    assert_eq!(replay.error_class, ErrorClass::ChallengeRequired);
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 1);
}

#[test]
fn sequence_nextval_rollback_default_requires_confirmation_before_database_io() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(Arc::clone(&state))),
        Some("dev".to_owned()),
        read_write_level(),
    );

    for sql in [
        "INSERT INTO orders (id) VALUES (app_seq.NEXTVAL)",
        "UPDATE orders SET id = app_seq.NEXTVAL WHERE id = 1",
    ] {
        let err = dispatcher
            .dispatch("oracle_execute", json!({ "sql": sql }))
            .expect_err("rollback cannot undo NEXTVAL, so omission of confirm must fail closed");
        assert_eq!(err.error_class, ErrorClass::ChallengeRequired, "{sql:?}");
    }
    let wrapped = dispatcher
        .dispatch(
            "oracle_execute",
            json!({ "sql": "BEGIN x := app_seq.NEXTVAL; END;" }),
        )
        .expect_err("engine-free caller PL/SQL must use direct static DML instead");
    assert_eq!(wrapped.error_class, ErrorClass::ForbiddenStatement);
    assert!(state.executed.lock().expect("exec mutex").is_empty());
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 0);
}

#[test]
fn sequence_nextval_rollback_default_rejects_wrong_confirmation_before_database_io() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(Arc::clone(&state))),
        Some("dev".to_owned()),
        read_write_level(),
    );
    let wrong_confirm = preview_confirm(
        &dispatcher,
        "UPDATE employees SET name = name WHERE employee_id = 100",
    );

    let err = dispatcher
        .dispatch(
            "oracle_execute",
            json!({
                "sql": "INSERT INTO orders (id) VALUES (app_seq.NEXTVAL)",
                "confirm": wrong_confirm,
            }),
        )
        .expect_err("a confirmation for different SQL must not authorize NEXTVAL");
    assert_eq!(err.error_class, ErrorClass::ChallengeRequired);
    assert!(state.executed.lock().expect("exec mutex").is_empty());
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 0);
}

#[test]
fn sequence_nextval_query_is_never_offered_to_execute_without_fetching() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(Arc::clone(&state))),
        Some("dev".to_owned()),
        read_write_level(),
    );
    let sql = "SELECT app_seq.NEXTVAL FROM dual";
    let preview = dispatcher
        .dispatch("oracle_preview_sql", json!({ "sql": sql }))
        .expect("query-shaped NEXTVAL can be explained safely");

    assert_eq!(preview["required_level"], json!("READ_WRITE"));
    assert_eq!(preview["execute_confirmation"], Value::Null);
    assert_eq!(preview["next_actions"][0]["intent"], json!("rewrite_sql"));
    assert!(
        preview["next_actions"][0]["message"]
            .as_str()
            .is_some_and(|message| message.contains("does not fetch query rows"))
    );

    let err = dispatcher
        .dispatch(
            "oracle_execute",
            json!({ "sql": sql, "confirm": "must-not-be-consumed" }),
        )
        .expect_err("execute-with-rowcount cannot prove a SELECT NEXTVAL was fetched");
    assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    assert!(state.executed.lock().expect("exec mutex").is_empty());
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 0);
}

#[test]
fn sequence_nextval_ddl_batch_preview_keeps_aggregate_class_but_offers_no_execution() {
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(NoExecMock),
        Some("dev".to_owned()),
        ddl_level(),
    );
    let preview = dispatcher
        .dispatch(
            "oracle_preview_sql",
            json!({
                "sql": "SELECT app_seq.NEXTVAL FROM dual; DROP TABLE audit_log"
            }),
        )
        .expect("DDL-capable profile can preview the aggregate batch");

    assert_eq!(preview["danger"], json!("DESTRUCTIVE"));
    assert_eq!(preview["required_level"], json!("DDL"));
    assert!(
        preview["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("Destructive/DDL"))
    );
    assert_eq!(preview["execute_confirmation"], Value::Null);
    assert_eq!(preview["next_actions"][0]["intent"], json!("rewrite_sql"));
}

#[test]
fn read_only_select_passes_the_gate() {
    // A plain SELECT (no unproven function call) is proven read-only and runs.
    let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
    let out = dispatcher
            .dispatch(
                "oracle_query",
                json!({ "sql": "SELECT object_name FROM all_objects WHERE owner = :1", "binds": ["HR"] }),
            )
            .expect("a read-only SELECT must pass the gate");
    assert!(out.is_object());
}

// =======================================================================
// K9 — flashback / AS-OF read mode (STRUCTURED `as_of`)
//
// Safety contract: the base SELECT is proven read-only by the UNCHANGED
// classifier FIRST; only then is the proven query bounded in a DBMS_FLASHBACK
// window. `as_of` never enters the classifier input or the SQL text.
// =======================================================================

#[test]
fn as_of_never_enters_the_classifier_input_so_the_base_decision_is_byte_identical() {
    // `as_of` deserializes into its OWN field; it never touches `sql`. So the
    // exact text the dispatcher marks + classifies is the SAME base SELECT with
    // or without `as_of`, and therefore so is the GuardDecision (byte-identical).
    let base = "SELECT count(*) AS c FROM app.t WHERE id = :1";
    let args_without: QueryArgs = serde_json::from_value(json!({ "sql": base })).expect("args");
    let args_with: QueryArgs =
        serde_json::from_value(json!({ "sql": base, "as_of": { "scn": 42 } })).expect("args");
    assert!(args_without.as_of.is_none());
    assert!(args_with.as_of.is_some(), "as_of parses into its own field");
    assert_eq!(
        args_without.sql, args_with.sql,
        "the SELECT text is untouched by as_of"
    );

    let marked_without = with_audit_marker(&args_without.sql, None, "oracle_query");
    let marked_with = with_audit_marker(&args_with.sql, None, "oracle_query");
    assert_eq!(
        marked_without, marked_with,
        "the classifier input is identical with and without as_of"
    );
    let decision_without: GuardDecision = DEFAULT_CLASSIFIER.classify(&marked_without);
    let decision_with: GuardDecision = DEFAULT_CLASSIFIER.classify(&marked_with);
    assert_eq!(
        decision_without, decision_with,
        "the base SELECT classifies to a byte-identical GuardDecision"
    );
    assert_eq!(
        decision_without.required_level,
        Some(OperatingLevel::ReadOnly),
        "the base SELECT is proven read-only"
    );
}

#[test]
fn non_read_base_is_refused_before_any_flashback_or_db_io() {
    // NoExecMock panics on any query/execute — so reaching the assertions proves
    // the refusal happened BEFORE any DBMS_FLASHBACK ENABLE or DB round trip.
    // The refusal is DERIVED from the GuardDecision on the classified text; a
    // byte-identical refusal with and without `as_of` proves the classifier saw
    // the SAME base SELECT (the flashback target is applied AFTER, never fused
    // into the classified SQL).
    let dispatcher = OracleDispatcher::new(Box::new(NoExecMock));
    for base in [
        "UPDATE app.t SET x = 1",
        "SELECT * FROM app.t FOR UPDATE",
        "DELETE FROM app.t",
    ] {
        let without = dispatcher
            .dispatch("oracle_query", json!({ "sql": base }))
            .expect_err("non-read base is refused");
        let with_as_of = dispatcher
            .dispatch(
                "oracle_query",
                json!({ "sql": base, "as_of": { "scn": 9_000_000 } }),
            )
            .expect_err("non-read base is refused even with a valid as_of");
        assert_eq!(
            without.error_class, with_as_of.error_class,
            "{base}: refusal class identical with/without as_of"
        );
        assert_eq!(
            without.message, with_as_of.message,
            "{base}: byte-identical refusal message with/without as_of"
        );
        assert!(
            matches!(
                without.error_class,
                ErrorClass::ForbiddenStatement | ErrorClass::OperatingLevelTooLow
            ),
            "{base} -> unexpected class {:?}",
            without.error_class
        );
    }
}

#[test]
fn as_of_with_both_scn_and_timestamp_is_rejected_before_db_io() {
    // NoExecMock never runs; a both-set / empty as_of is a structural refusal
    // returned before classification even completes.
    let dispatcher = OracleDispatcher::new(Box::new(NoExecMock));
    let both = dispatcher
        .dispatch(
            "oracle_query",
            json!({
                "sql": "SELECT 1 FROM dual",
                "as_of": { "scn": 100, "timestamp": "2026-07-08 10:00:00" }
            }),
        )
        .expect_err("both scn and timestamp set is invalid");
    assert_eq!(both.error_class, ErrorClass::InvalidArguments);

    let empty = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT 1 FROM dual", "as_of": {} }),
        )
        .expect_err("an empty as_of (neither scn nor timestamp) is invalid");
    assert_eq!(empty.error_class, ErrorClass::InvalidArguments);
}

#[test]
fn read_base_with_as_of_dispatches_through_the_flashback_wrapper() {
    // A proven read + as_of runs end-to-end through `read_query_as_of` against a
    // mock that accepts the DBMS_FLASHBACK enable/disable executes and returns
    // rows — the happy path is wired and returns a normal query response.
    let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
    let out = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT count(*) AS c FROM app.t", "as_of": { "scn": 9_000_000 } }),
        )
        .expect("a proven read with as_of runs inside the flashback window");
    assert!(out.is_object());
    assert!(
        out.get("rows").is_some(),
        "returns a normal, inline query response"
    );
}

#[test]
fn preview_sql_reports_read_only_gate_decision_without_running_sql() {
    let dispatcher = OracleDispatcher::new(Box::new(NoExecMock));
    let select = dispatcher
        .dispatch("oracle_preview_sql", json!({ "sql": "SELECT 1 FROM dual" }))
        .expect("preview select");
    assert_eq!(select["allowed_on_read_only"], json!(true));
    assert_eq!(select["gate_decision"], json!("allow"));
    assert_eq!(select["required_level"], json!("READ_ONLY"));
    assert_eq!(select["session_level"], json!("READ_ONLY"));
    assert_eq!(select["profile_ceiling"], json!("READ_ONLY"));
    assert_eq!(select["next_actions"][0]["tool"], json!("oracle_query"));
    assert_eq!(select["next_actions"][0]["intent"], json!("run_read"));

    let write = dispatcher
        .dispatch("preview_sql", json!({ "sql": "DELETE FROM t" }))
        .expect("preview write alias");
    assert_eq!(write["allowed_on_read_only"], json!(false));
    assert_ne!(write["gate_decision"], json!("allow"));
    assert_eq!(
        write["next_actions"][0]["tool"],
        json!("oracle_list_profiles")
    );
}

#[test]
fn preview_sql_uses_configured_profile_ceiling() {
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(NoExecMock),
        Some("dev".to_owned()),
        SessionLevelState::new(OperatingLevel::Ddl, false),
    );

    let write = dispatcher
        .dispatch(
            "oracle_preview_sql",
            json!({ "sql": "DELETE FROM t WHERE id = 1" }),
        )
        .expect("preview write");
    assert_eq!(write["allowed_on_read_only"], json!(false));
    assert_eq!(write["gate_decision"], json!("require_step_up"));
    assert_eq!(write["step_up_target"], json!("READ_WRITE"));
    assert_eq!(write["profile_ceiling"], json!("DDL"));
    assert_eq!(write["protected"], json!(false));
    assert_eq!(
        write["next_actions"][0]["tool"],
        json!("oracle_set_session_level")
    );

    let ddl = dispatcher
        .dispatch(
            "oracle_preview_sql",
            json!({ "sql": "CREATE TABLE t (id NUMBER)" }),
        )
        .expect("preview ddl");
    assert_eq!(ddl["gate_decision"], json!("require_step_up"));
    assert_eq!(ddl["step_up_target"], json!("DDL"));
}

#[test]
fn create_or_replace_preview_is_default_and_does_not_execute() {
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(OneRowMock),
        Some("dev".to_owned()),
        ddl_level(),
    );

    let out = dispatcher
        .dispatch(
            "oracle_create_or_replace",
            json!({ "source_code": "CREATE OR REPLACE VIEW emp_v AS SELECT 1 AS id FROM dual" }),
        )
        .expect("create-or-replace preview");
    assert_eq!(out["preview"], json!(true));
    assert_eq!(out["applied"], json!(false));
    assert_eq!(out["required_level"], json!("DDL"));
    assert_eq!(out["gate_decision"], json!("allow"));
    assert_eq!(out["detected_object"]["owner"], json!("APP"));
    assert_eq!(out["detected_object"]["name"], json!("EMP_V"));
    assert_eq!(out["detected_object"]["object_type"], json!("VIEW"));
    assert_eq!(
        out["confirmation"]["tool"],
        json!("oracle_create_or_replace")
    );
    assert_eq!(
        out["next_actions"][0]["tool"],
        json!("oracle_create_or_replace")
    );
}

#[test]
fn create_or_replace_plsql_procedure_floors_at_ddl_and_mints_own_grant() {
    // oracle-p0d6: a PL/SQL-bearing CREATE OR REPLACE PROCEDURE now floors at
    // DDL (was READ_WRITE), consistent with CREATE OR REPLACE VIEW and
    // oracle_patch_source. At a DDL-level session the preview therefore Allows,
    // mints its OWN single-use confirmation grant, and attributes the apply to
    // oracle_create_or_replace (no delegation to oracle_execute).
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(OneRowMock),
        Some("dev".to_owned()),
        ddl_level(),
    );
    let source = "CREATE OR REPLACE PROCEDURE p IS BEGIN NULL; END;";
    let out = dispatcher
        .dispatch("oracle_create_or_replace", json!({ "source_code": source }))
        .expect("plsql create-or-replace preview");
    assert_eq!(out["preview"], json!(true));
    assert_eq!(
        out["required_level"],
        json!("DDL"),
        "PL/SQL CREATE OR REPLACE must require DDL, not READ_WRITE"
    );
    assert_eq!(out["gate_decision"], json!("allow"));
    assert_eq!(
        out["confirmation"]["tool"],
        json!("oracle_create_or_replace")
    );
    assert!(
        out["confirmation"]["confirm"].is_string(),
        "a DDL-level PL/SQL CoR must mint its own single-use grant (not confirmation=None): {out:#}"
    );
    assert_eq!(
        out["next_actions"][0]["tool"],
        json!("oracle_create_or_replace"),
        "the apply action must stay on oracle_create_or_replace, not delegate to oracle_execute"
    );

    // At READ_WRITE the same statement now requires a step-up to DDL (a DML
    // principal must NOT be able to replace stored code — definer-rights escalation).
    let rw = OracleDispatcher::new_with_profile_level(
        Box::new(OneRowMock),
        Some("dev".to_owned()),
        SessionLevelState::new(OperatingLevel::Ddl, false),
    );
    let preview = rw
        .dispatch("oracle_create_or_replace", json!({ "source_code": source }))
        .expect("preview inspectable below current level");
    assert_eq!(preview["gate_decision"], json!("require_step_up"));
    assert_eq!(preview["step_up_target"], json!("DDL"));
}

#[test]
fn create_or_replace_package_spec_preview_is_ddl_and_mints_confirmation() {
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(OneRowMock),
        Some("dev".to_owned()),
        ddl_level(),
    );
    let source = "CREATE OR REPLACE PACKAGE emp_api AS PROCEDURE run(p_value NUMBER); END emp_api;";

    let preview = dispatcher
        .dispatch("oracle_create_or_replace", json!({ "source_code": source }))
        .expect("valid package specification previews");

    assert_eq!(preview["preview"], json!(true));
    assert_eq!(preview["applied"], json!(false));
    assert_eq!(preview["danger"], json!("DESTRUCTIVE"));
    assert_eq!(preview["required_level"], json!("DDL"));
    assert_eq!(preview["gate_decision"], json!("allow"));
    assert_eq!(preview["detected_object"]["owner"], json!("APP"));
    assert_eq!(preview["detected_object"]["name"], json!("EMP_API"));
    assert_eq!(preview["detected_object"]["object_type"], json!("PACKAGE"));
    assert_eq!(
        preview["confirmation"]["tool"],
        json!("oracle_create_or_replace")
    );
    assert!(preview["confirmation"]["confirm"].is_string());
}

#[test]
fn create_or_replace_package_spec_apply_uses_preview_grant_once() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        ddl_level(),
    );
    let source = "CREATE OR REPLACE PACKAGE emp_api AS PROCEDURE run(p_value NUMBER); END emp_api;";
    let preview = dispatcher
        .dispatch("oracle_create_or_replace", json!({ "source_code": source }))
        .expect("valid package specification previews");
    let confirm = preview["confirmation"]["confirm"]
        .as_str()
        .expect("package preview confirmation");

    let applied = dispatcher
        .dispatch(
            "oracle_create_or_replace",
            json!({ "source_code": source, "execute": true, "confirm": confirm }),
        )
        .expect("confirmed package specification applies");

    assert_eq!(applied["applied"], json!(true));
    assert_eq!(applied["committed"], json!(true));
    assert_eq!(applied["detected_object"]["object_type"], json!("PACKAGE"));
    let executed = state.executed.lock().expect("exec mutex");
    assert_eq!(executed.len(), 1);
    assert!(executed[0].0.ends_with(source));
    drop(executed);

    let replay = dispatcher
        .dispatch(
            "oracle_create_or_replace",
            json!({ "source_code": source, "execute": true, "confirm": confirm }),
        )
        .expect_err("package preview grant is single-use");
    assert_eq!(replay.error_class, ErrorClass::ChallengeRequired);
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);
}

#[test]
fn create_or_replace_stored_bodies_preview_and_apply_exactly_once() {
    for (source, object_type) in [
        (
            "CREATE OR REPLACE PACKAGE BODY emp_api AS PROCEDURE run IS BEGIN NULL; END run; END emp_api;",
            "PACKAGE BODY",
        ),
        (
            "CREATE OR REPLACE TYPE BODY employee_t AS MEMBER FUNCTION label RETURN VARCHAR2 IS BEGIN RETURN 'ok'; END label; END employee_t;",
            "TYPE BODY",
        ),
    ] {
        let state = Arc::new(ExecState::default());
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(state.clone())),
            Some("dev".to_owned()),
            ddl_level(),
        );

        let preview = dispatcher
            .dispatch("oracle_create_or_replace", json!({ "source_code": source }))
            .expect("valid stored body previews");
        assert_eq!(preview["preview"], json!(true), "{source}");
        assert_eq!(preview["applied"], json!(false), "{source}");
        assert_eq!(preview["danger"], json!("DESTRUCTIVE"), "{source}");
        assert_eq!(preview["required_level"], json!("DDL"), "{source}");
        assert_eq!(preview["gate_decision"], json!("allow"), "{source}");
        assert_eq!(
            preview["detected_object"]["object_type"],
            json!(object_type),
            "{source}"
        );
        let confirm = preview["confirmation"]["confirm"]
            .as_str()
            .expect("stored-body preview mints DDL confirmation");
        assert!(
            state.executed.lock().expect("exec mutex").is_empty(),
            "preview must not execute the stored body"
        );
        assert_eq!(state.commits.load(Ordering::SeqCst), 0);

        let applied = dispatcher
            .dispatch(
                "oracle_create_or_replace",
                json!({
                    "source_code": source,
                    "execute": true,
                    "confirm": confirm,
                    "include_errors": false,
                }),
            )
            .expect("confirmed stored body applies");
        assert_eq!(applied["applied"], json!(true), "{source}");
        assert_eq!(applied["committed"], json!(true), "{source}");
        let executed = state.executed.lock().expect("exec mutex");
        assert_eq!(
            executed.len(),
            1,
            "stored body executes exactly once: {source}"
        );
        assert!(executed[0].0.ends_with(source), "{source}");
        drop(executed);
        assert_eq!(state.commits.load(Ordering::SeqCst), 1, "{source}");
    }
}

#[test]
fn create_or_replace_stored_call_specs_preview_and_apply_exactly_once() {
    for (source, object_type) in [
        (
            "CREATE OR REPLACE PACKAGE BODY emp_api AS PROCEDURE run AS LANGUAGE JAVA NAME 'EmployeeApi.run()'; END emp_api;",
            "PACKAGE BODY",
        ),
        (
            "CREATE OR REPLACE TYPE BODY employee_t AS STATIC FUNCTION label RETURN VARCHAR2 AS LANGUAGE C NAME \"employee_label\" LIBRARY employee_lib; END employee_t;",
            "TYPE BODY",
        ),
    ] {
        let state = Arc::new(ExecState::default());
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(state.clone())),
            Some("dev".to_owned()),
            ddl_level(),
        );

        let preview = dispatcher
            .dispatch("oracle_create_or_replace", json!({ "source_code": source }))
            .expect("valid stored call specification previews");
        assert_eq!(preview["danger"], json!("DESTRUCTIVE"), "{source}");
        assert_eq!(preview["required_level"], json!("DDL"), "{source}");
        assert_eq!(preview["gate_decision"], json!("allow"), "{source}");
        assert_eq!(
            preview["detected_object"]["object_type"],
            json!(object_type),
            "{source}"
        );
        let confirm = preview["confirmation"]["confirm"]
            .as_str()
            .expect("call-spec preview mints DDL confirmation");
        assert!(state.executed.lock().expect("exec mutex").is_empty());

        let applied = dispatcher
            .dispatch(
                "oracle_create_or_replace",
                json!({
                    "source_code": source,
                    "execute": true,
                    "confirm": confirm,
                    "include_errors": false,
                }),
            )
            .expect("confirmed stored call specification applies");
        assert_eq!(applied["applied"], json!(true), "{source}");
        let executed = state.executed.lock().expect("exec mutex");
        assert_eq!(executed.len(), 1, "{source}");
        assert!(executed[0].0.ends_with(source), "{source}");
        drop(executed);
        assert_eq!(state.commits.load(Ordering::SeqCst), 1, "{source}");
    }
}

#[test]
fn create_or_replace_stored_body_refusals_never_execute() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        ddl_level(),
    );

    for source in [
        "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE q IS BEGIN NULL; END q; END p; DROP TABLE t",
        "CREATE OR REPLACE TYPE BODY t AS MEMBER PROCEDURE q IS BEGIN EXECUTE/**/IMMEDIATE 'DROP TABLE t'; END q; END t;",
        "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE q IS BEGIN NULL; END q;",
    ] {
        let preview = dispatcher
            .dispatch("oracle_create_or_replace", json!({ "source_code": source }))
            .expect("forbidden source remains inspectable as a preview");
        assert_eq!(preview["gate_decision"], json!("blocked"), "{source}");
        assert_eq!(preview["required_level"], Value::Null, "{source}");
        assert_eq!(preview["confirmation"], Value::Null, "{source}");
    }
    assert!(state.executed.lock().expect("exec mutex").is_empty());
    assert_eq!(state.commits.load(Ordering::SeqCst), 0);
}

#[test]
fn create_or_replace_package_spec_trailing_sql_stays_fail_closed() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        ddl_level(),
    );
    let source = "CREATE OR REPLACE PACKAGE p AS PROCEDURE q; END; DROP TABLE t";

    let preview = dispatcher
        .dispatch("oracle_create_or_replace", json!({ "source_code": source }))
        .expect("forbidden source remains inspectable as a preview");

    assert_eq!(preview["gate_decision"], json!("blocked"));
    assert_eq!(preview["blocked_reason"]["type"], json!("forbidden"));
    assert_eq!(preview["required_level"], Value::Null);
    assert_eq!(preview["confirmation"], Value::Null);
    assert!(state.executed.lock().expect("exec mutex").is_empty());
}

#[test]
fn create_or_replace_requires_ddl_level_without_executing() {
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(NoExecMock),
        Some("dev".to_owned()),
        SessionLevelState::new(OperatingLevel::Ddl, false),
    );

    let preview = dispatcher
        .dispatch(
            "oracle_create_or_replace",
            json!({ "source_code": "CREATE OR REPLACE VIEW emp_v AS SELECT 1 AS id FROM dual" }),
        )
        .expect("preview is inspectable below current level");
    assert_eq!(preview["gate_decision"], json!("require_step_up"));
    assert_eq!(preview["step_up_target"], json!("DDL"));
    assert_eq!(
        preview["next_actions"][0]["tool"],
        json!("oracle_set_session_level")
    );

    let err = dispatcher
        .dispatch(
            "oracle_create_or_replace",
            json!({
                "source_code": "CREATE OR REPLACE VIEW emp_v AS SELECT 1 AS id FROM dual",
                "execute": true,
                "confirm": "wrong"
            }),
        )
        .expect_err("execute is blocked before touching DB");
    assert_eq!(err.error_class, ErrorClass::OperatingLevelTooLow);
}

#[test]
fn create_or_replace_execute_requires_confirmation() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        ddl_level(),
    );

    let err = dispatcher
        .dispatch(
            "oracle_create_or_replace",
            json!({
                "source_code": "CREATE OR REPLACE VIEW emp_v AS SELECT 1 AS id FROM dual",
                "execute": true
            }),
        )
        .expect_err("apply requires preview token");
    assert_eq!(err.error_class, ErrorClass::ChallengeRequired);
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
}

#[test]
fn create_or_replace_execute_applies_and_reports_compile_errors() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        ddl_level(),
    );
    let source = "CREATE OR REPLACE VIEW emp_v AS SELECT 1 AS id FROM dual";
    let preview = dispatcher
        .dispatch("create_or_replace", json!({ "source_code": source }))
        .expect("alias previews");
    let confirm = preview["confirmation"]["confirm"]
        .as_str()
        .expect("confirm grant");

    let before_generation = catalog_generation(&dispatcher);
    let out = dispatcher
        .dispatch(
            "create_or_replace",
            json!({ "source_code": source, "execute": true, "token": confirm }),
        )
        .expect("confirmed apply");
    assert_eq!(catalog_generation(&dispatcher), before_generation + 1);
    assert_eq!(out["applied"], json!(true));
    assert_eq!(out["committed"], json!(true));
    assert_eq!(out["detected_object"]["owner"], json!("APP"));
    assert_eq!(out["detected_object"]["name"], json!("EMP_V"));
    assert_eq!(out["errors"], json!([]));
    assert_eq!(out["error_count"], json!(0));
    assert_eq!(state.commits.load(Ordering::SeqCst), 1);
    let executed = state.executed.lock().expect("exec mutex");
    assert_eq!(executed.len(), 1);
    // A3: the executed text carries the per-statement audit marker (a leading,
    // verdict-preserving comment) followed by the exact source.
    assert!(
        executed[0].0.starts_with("/* oraclemcp llm="),
        "executed SQL should carry the A3 audit marker: {}",
        executed[0].0
    );
    // oracle-p0d6: the audit marker (and the persisted audit record it mirrors)
    // must attribute the CREATE OR REPLACE to `oracle_create_or_replace`, NOT the
    // delegated `oracle_execute`. The apply path threads the canonical tool name
    // into execute_sql so V$SQL / the audit chain / write-intents all carry it.
    assert!(
        executed[0].0.contains("tool=oracle_create_or_replace"),
        "executed SQL marker must attribute tool=oracle_create_or_replace: {}",
        executed[0].0
    );
    assert!(executed[0].0.ends_with(source));
}

#[test]
fn create_or_replace_rejects_other_sql_shapes() {
    let dispatcher = OracleDispatcher::new(Box::new(NoExecMock));
    let err = dispatcher
        .dispatch(
            "oracle_create_or_replace",
            json!({ "source_code": "CREATE TABLE t (id NUMBER)" }),
        )
        .expect_err("non create-or-replace is rejected");
    assert_eq!(err.error_class, ErrorClass::InvalidArguments);
}

#[test]
fn deploy_ddl_preview_uses_create_or_replace_path() {
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(OneRowMock),
        Some("dev".to_owned()),
        ddl_level(),
    );

    let out = dispatcher
        .dispatch(
            "deploy_ddl",
            json!({
                "name": "emp_v",
                "ddl": "CREATE OR REPLACE VIEW emp_v AS SELECT 1 AS id FROM dual",
                "wait_seconds": 3
            }),
        )
        .expect("deploy preview");
    assert_eq!(out["preview"], json!(true));
    assert_eq!(out["applied"], json!(false));
    assert_eq!(out["deploy_name"], json!("emp_v"));
    assert_eq!(out["wait_seconds"], json!(3));
    assert_eq!(out["compatibility_tool"], json!("deploy_ddl"));
    assert_eq!(out["detected_object"]["name"], json!("EMP_V"));
    assert_eq!(
        out["confirmation"]["tool"],
        json!("oracle_create_or_replace")
    );
}

#[test]
fn deploy_ddl_execute_requires_confirmation_without_executing() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        ddl_level(),
    );

    let err = dispatcher
        .dispatch(
            "deploy_ddl",
            json!({
                "ddl": "CREATE TABLE emp_stage (id NUMBER)",
                "execute": true
            }),
        )
        .expect_err("deploy ddl needs confirmation");
    assert_eq!(err.error_class, ErrorClass::ChallengeRequired);
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
}

#[test]
fn deploy_ddl_rejects_dml_without_executing() {
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(NoExecMock),
        Some("dev".to_owned()),
        ddl_level(),
    );

    let err = dispatcher
        .dispatch(
            "deploy_ddl",
            json!({ "ddl": "UPDATE employees SET name = name WHERE employee_id = 100" }),
        )
        .expect_err("dml is not ddl deploy");
    assert_eq!(err.error_class, ErrorClass::InvalidArguments);
}

#[test]
fn set_session_level_previews_before_elevating() {
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(NoExecMock),
        Some("dev".to_owned()),
        SessionLevelState::new(OperatingLevel::ReadWrite, false),
    );

    let out = dispatcher
        .dispatch(
            "oracle_set_session_level",
            json!({ "level": "READ_WRITE", "ttl_seconds": 60 }),
        )
        .expect("session level preview");
    assert_eq!(out["preview"], json!(true));
    assert_eq!(out["changed"], json!(false));
    assert_eq!(out["target_level"], json!("READ_WRITE"));
    assert_eq!(out["session"]["current_level"], json!("READ_ONLY"));
    assert_eq!(out["session"]["profile_ceiling"], json!("READ_WRITE"));
    assert_eq!(out["gate"]["decision"], json!("require_step_up"));
    assert_eq!(
        out["confirmation"]["tool"],
        json!("oracle_set_session_level")
    );
    assert!(out["confirmation"]["confirm"].as_str().is_some());

    let write = dispatcher
        .dispatch(
            "oracle_preview_sql",
            json!({ "sql": "DELETE FROM t WHERE id = 1" }),
        )
        .expect("preview write after level preview only");
    assert_eq!(write["gate_decision"], json!("require_step_up"));
}

#[test]
fn set_session_level_requires_confirmation_to_apply() {
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(NoExecMock),
        Some("dev".to_owned()),
        SessionLevelState::new(OperatingLevel::ReadWrite, false),
    );

    let err = dispatcher
        .dispatch(
            "oracle_set_session_level",
            json!({ "level": "READ_WRITE", "ttl_seconds": 60, "execute": true }),
        )
        .expect_err("elevation requires preview token");
    assert_eq!(err.error_class, ErrorClass::ChallengeRequired);

    let preview = dispatcher
        .dispatch(
            "oracle_set_session_level",
            json!({ "level": "READ_WRITE", "ttl_seconds": 60 }),
        )
        .expect("preview supplies token");
    let confirm = preview["confirmation"]["confirm"]
        .as_str()
        .expect("confirm grant");
    let applied = dispatcher
        .dispatch(
            "oracle_set_session_level",
            json!({ "level": "READ_WRITE", "ttl_seconds": 60, "execute": true, "token": confirm }),
        )
        .expect("confirmed elevation applies");
    assert_eq!(applied["changed"], json!(true));
    assert_eq!(applied["session"]["current_level"], json!("READ_WRITE"));
    assert_eq!(applied["session"]["has_active_elevation"], json!(true));

    let write = dispatcher
        .dispatch(
            "oracle_preview_sql",
            json!({ "sql": "DELETE FROM t WHERE id = 1" }),
        )
        .expect("write is now within current session level");
    assert_eq!(write["gate_decision"], json!("allow"));
    assert!(write["execute_confirmation"]["confirm"].as_str().is_some());
}

#[test]
fn set_session_level_can_lower_without_confirmation() {
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(NoExecMock),
        Some("dev".to_owned()),
        ddl_level(),
    );

    let preview = dispatcher
        .dispatch("oracle_set_session_level", json!({ "level": "READ_WRITE" }))
        .expect("lowering preview");
    assert_eq!(preview["preview"], json!(true));
    assert_eq!(preview["gate"]["decision"], json!("allow_lowering"));
    assert_eq!(preview["confirmation"], Value::Null);

    let lowered = dispatcher
        .dispatch(
            "oracle_set_session_level",
            json!({ "level": "READ_WRITE", "action": "apply" }),
        )
        .expect("lowering applies without confirmation");
    assert_eq!(lowered["changed"], json!(true));
    assert_eq!(lowered["session"]["current_level"], json!("READ_WRITE"));

    let ddl = dispatcher
        .dispatch(
            "oracle_preview_sql",
            json!({ "sql": "CREATE TABLE t (id NUMBER)" }),
        )
        .expect("ddl now requires step-up again");
    assert_eq!(ddl["gate_decision"], json!("require_step_up"));
}

#[test]
fn set_session_level_cannot_exceed_profile_ceiling() {
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(NoExecMock),
        Some("ro".to_owned()),
        SessionLevelState::new(OperatingLevel::ReadOnly, true),
    );

    let preview = dispatcher
        .dispatch(
            "oracle_set_session_level",
            json!({ "level": "READ_WRITE", "ttl_seconds": 60 }),
        )
        .expect("blocked preview is still inspectable");
    assert_eq!(preview["preview"], json!(true));
    assert_eq!(preview["gate"]["decision"], json!("blocked"));
    assert_eq!(preview["confirmation"], Value::Null);
    assert_eq!(
        preview["next_actions"][0]["tool"],
        json!("oracle_list_profiles")
    );

    let err = dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({ "level": "READ_WRITE", "ttl_seconds": 60, "execute": true, "confirm": "wrong" }),
            )
            .expect_err("ceiling blocks even with execute=true");
    assert_eq!(err.error_class, ErrorClass::OperatingLevelTooLow);
}

#[test]
fn oauth_read_scope_blocks_write_tool_even_when_session_is_elevated() {
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(NoExecMock),
        Some("dev".to_owned()),
        read_write_level(),
    );
    let read = scope_grant("oracle:read");
    let sql = "UPDATE employees SET salary = salary WHERE employee_id = 100";
    let err = dispatcher
        .dispatch_with_context(
            "oracle_execute",
            json!({
                "sql": sql,
                "commit": true,
                "confirm": "wrong"
            }),
            DispatchContext::with_scope_grant(&read),
        )
        .expect_err("read-scoped HTTP token must block write tools before DB access");

    assert_eq!(err.error_class, ErrorClass::OperatingLevelTooLow);
    assert!(
        err.message.contains("READ_WRITE"),
        "message should name the blocked required level: {}",
        err.message
    );
    assert!(
        err.message.contains("READ_ONLY"),
        "message should name the scoped ceiling: {}",
        err.message
    );
}

#[test]
fn oauth_read_scope_does_not_persistently_lower_session_level() {
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(NoExecMock),
        Some("dev".to_owned()),
        SessionLevelState::new(OperatingLevel::ReadWrite, false),
    );
    let read = scope_grant("oracle:read");

    let scoped = dispatcher
        .dispatch_with_context(
            "oracle_set_session_level",
            json!({ "level": "READ_WRITE", "ttl_seconds": 60 }),
            DispatchContext::with_scope_grant(&read),
        )
        .expect("scoped blocked preview is inspectable");
    assert_eq!(scoped["gate"]["decision"], json!("blocked"));
    assert_eq!(scoped["session"]["profile_ceiling"], json!("READ_ONLY"));
    assert_eq!(scoped["confirmation"], Value::Null);

    let unscoped = dispatcher
        .dispatch(
            "oracle_set_session_level",
            json!({ "level": "READ_WRITE", "ttl_seconds": 60 }),
        )
        .expect("later unscoped request still sees the profile ceiling");
    assert_eq!(unscoped["gate"]["decision"], json!("require_step_up"));
    assert_eq!(unscoped["session"]["profile_ceiling"], json!("READ_WRITE"));
    assert!(unscoped["confirmation"]["confirm"].as_str().is_some());
}

#[test]
fn oauth_admin_scope_cannot_exceed_profile_max_level() {
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(NoExecMock),
        Some("dev".to_owned()),
        read_write_level(),
    );
    let admin = scope_grant("oracle:admin");

    let preview = dispatcher
        .dispatch_with_context(
            "oracle_preview_sql",
            json!({ "sql": "CREATE TABLE scoped_test (id NUMBER)" }),
            DispatchContext::with_scope_grant(&admin),
        )
        .expect("DDL preview is inspectable");
    assert_eq!(preview["gate_decision"], json!("blocked"));
    assert_eq!(preview["blocked_reason"]["type"], json!("exceeds_ceiling"));
    assert_eq!(preview["blocked_reason"]["required"], json!("DDL"));
    assert_eq!(preview["blocked_reason"]["ceiling"], json!("READ_WRITE"));
    assert_eq!(preview["profile_ceiling"], json!("READ_WRITE"));
}

#[test]
fn oauth_admin_scope_keeps_protected_profile_read_only() {
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(NoExecMock),
        Some("prod".to_owned()),
        SessionLevelState::new(OperatingLevel::ReadOnly, true),
    );
    let admin = scope_grant("oracle:admin");

    let preview = dispatcher
        .dispatch_with_context(
            "oracle_preview_sql",
            json!({ "sql": "DELETE FROM important_table" }),
            DispatchContext::with_scope_grant(&admin),
        )
        .expect("blocked preview is inspectable");
    assert_eq!(preview["gate_decision"], json!("blocked"));
    assert_eq!(preview["blocked_reason"]["type"], json!("exceeds_ceiling"));
    assert_eq!(preview["blocked_reason"]["required"], json!("READ_WRITE"));
    assert_eq!(preview["blocked_reason"]["ceiling"], json!("READ_ONLY"));
    assert_eq!(preview["profile_ceiling"], json!("READ_ONLY"));
    assert_eq!(preview["protected"], json!(true));
}

#[test]
fn write_compatibility_aliases_share_session_level_gate() {
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(NoExecMock),
        Some("dev".to_owned()),
        SessionLevelState::new(OperatingLevel::ReadWrite, false),
    );

    let preview = dispatcher
        .dispatch(
            "enable_writes",
            json!({ "ttl_seconds": 60, "db": "ignored" }),
        )
        .expect("enable_writes previews READ_WRITE elevation");
    assert_eq!(preview["preview"], json!(true));
    assert_eq!(preview["target_level"], json!("READ_WRITE"));
    assert_eq!(preview["confirmation"]["tool"], json!("enable_writes"));
    let confirm = preview["confirmation"]["confirm"]
        .as_str()
        .expect("confirm grant");

    let applied = dispatcher
        .dispatch(
            "enable_writes",
            json!({ "ttl_seconds": 60, "execute": true, "confirm": confirm }),
        )
        .expect("enable_writes applies with confirmation");
    assert_eq!(applied["session"]["current_level"], json!("READ_WRITE"));

    let dropped = dispatcher
        .dispatch("disable_writes", json!({}))
        .expect("disable_writes drops immediately");
    assert_eq!(dropped["changed"], json!(true));
    assert_eq!(dropped["session"]["current_level"], json!("READ_ONLY"));

    let write = dispatcher
        .dispatch(
            "oracle_preview_sql",
            json!({ "sql": "DELETE FROM t WHERE id = 1" }),
        )
        .expect("write requires step-up again");
    assert_eq!(write["gate_decision"], json!("require_step_up"));
}

#[test]
fn preview_sql_includes_execute_confirmation_for_allowed_write() {
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(NoExecMock),
        Some("dev".to_owned()),
        read_write_level(),
    );

    let preview = dispatcher
        .dispatch(
            "oracle_preview_sql",
            json!({ "sql": "UPDATE employees SET name = name WHERE employee_id = 100" }),
        )
        .expect("preview write");
    assert_eq!(preview["gate_decision"], json!("allow"));
    assert_eq!(
        preview["execute_confirmation"]["tool"],
        json!("oracle_execute")
    );
    assert_eq!(preview["execute_confirmation"]["commit"], json!(true));
    assert_eq!(
        preview["execute_confirmation"]["required_level"],
        json!("READ_WRITE")
    );
    let confirm = preview["execute_confirmation"]["confirm"]
        .as_str()
        .expect("token");
    assert!(
        confirm.starts_with("xgrant-") && confirm.contains('.'),
        "confirm should be an opaque signed grant reference: {confirm}"
    );
    assert_eq!(
        preview["next_actions"][0]["intent"],
        json!("rollback_preview")
    );
    assert_eq!(preview["next_actions"][0]["tool"], json!("oracle_execute"));
    assert_eq!(preview["next_actions"][0]["args"]["commit"], json!(false));
    assert_eq!(preview["next_actions"][1]["intent"], json!("commit"));
    assert_eq!(
        preview["next_actions"][1]["args"]["confirm"],
        preview["execute_confirmation"]["confirm"]
    );
}

#[test]
fn confirmation_grants_are_opaque_non_deterministic_references() {
    let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(Arc::new(ExecState::default()))),
        Some("dev".to_owned()),
        read_write_level(),
    );
    let first = preview_confirm(&dispatcher, sql);
    let second = preview_confirm(&dispatcher, sql);
    assert_ne!(
        first, second,
        "same statement previews mint distinct single-use grant references"
    );
    for confirm in [&first, &second] {
        assert!(
            confirm.starts_with("xgrant-") && confirm.contains('.'),
            "confirm should be an opaque signed grant reference: {confirm}"
        );
        assert_ne!(
            confirm.len(),
            16,
            "legacy deterministic 16-hex confirmation MAC must stay retired"
        );
    }
}

#[test]
fn execute_confirmation_preserves_semantic_whitespace_before_database_io() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        read_write_level(),
    );
    let approved = "UPDATE \"A  B\" SET x = 1";
    let different_object = "UPDATE \"A B\" SET x = 1";
    let confirm = preview_confirm(&dispatcher, approved);

    let err = dispatcher
        .dispatch(
            "oracle_execute",
            json!({
                "sql": different_object,
                "commit": true,
                "confirm": confirm,
            }),
        )
        .expect_err("grant for a two-space identifier cannot authorize a one-space identifier");
    assert_eq!(err.error_class, ErrorClass::ChallengeRequired);
    assert!(err.message.contains("different statement"));
    assert!(
        state.executed.lock().expect("exec mutex").is_empty(),
        "digest mismatch must fail before Oracle execution"
    );
    assert_eq!(state.commits.load(Ordering::SeqCst), 0);
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 0);

    let out = dispatcher
        .dispatch(
            "oracle_execute",
            json!({
                "sql": approved,
                "commit": true,
                "confirm": confirm,
            }),
        )
        .expect("a non-consuming mismatch leaves the exact grant usable");
    assert_eq!(out["committed"], json!(true));
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);
    assert_eq!(state.commits.load(Ordering::SeqCst), 1);
}

#[test]
fn session_level_grant_is_lane_bound_and_not_recomputable() {
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(NoExecMock),
        Some("dev".to_owned()),
        SessionLevelState::new(OperatingLevel::ReadWrite, false),
    );
    let lane_a = DispatchContext::default()
        .with_http_session_id("sess-a")
        .with_principal_key("oauth:user-a")
        .with_lane_identity("lane-a", 1);
    let lane_b = DispatchContext::default()
        .with_http_session_id("sess-a")
        .with_principal_key("oauth:user-a")
        .with_lane_identity("lane-b", 1);

    let preview = dispatcher
        .dispatch_with_context(
            "oracle_set_session_level",
            json!({ "level": "READ_WRITE", "ttl_seconds": 60 }),
            lane_a,
        )
        .expect("lane a previews elevation");
    let confirm = preview["confirmation"]["confirm"]
        .as_str()
        .expect("session-level grant")
        .to_owned();
    assert!(
        confirm.starts_with("xgrant-") && confirm.contains('.'),
        "session-level confirm should be an opaque signed grant reference: {confirm}"
    );

    let err = dispatcher
        .dispatch_with_context(
            "oracle_set_session_level",
            json!({
                "level": "READ_WRITE",
                "ttl_seconds": 60,
                "execute": true,
                "confirm": confirm.clone(),
            }),
            lane_b,
        )
        .expect_err("a different lane cannot consume lane a's grant");
    assert_eq!(err.error_class, ErrorClass::ChallengeRequired);

    let applied = dispatcher
        .dispatch_with_context(
            "oracle_set_session_level",
            json!({
                "level": "READ_WRITE",
                "ttl_seconds": 60,
                "execute": true,
                "confirm": confirm,
            }),
            lane_a,
        )
        .expect("lane a can still consume its grant");
    assert_eq!(applied["changed"], json!(true));
    assert_eq!(applied["session"]["current_level"], json!("READ_WRITE"));
}

#[test]
fn execute_rolls_back_dml_by_default() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        read_write_level(),
    );

    let out = dispatcher
        .dispatch(
            "oracle_execute",
            json!({
                "sql": "UPDATE employees SET name = name WHERE employee_id = :1",
                "binds": [100]
            }),
        )
        .expect("execute rollback");
    assert_eq!(out["executed"], json!(true));
    assert_eq!(out["committed"], json!(false));
    assert_eq!(out["rolled_back"], json!(true));
    assert_eq!(out["rows_affected"], json!(3));
    assert_eq!(state.commits.load(Ordering::SeqCst), 0);
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 1);
    let executed = state.executed.lock().expect("exec mutex");
    assert_eq!(executed.len(), 1);
    assert_eq!(executed[0].1, vec![OracleBind::I64(100)]);
}

#[test]
fn caller_transaction_control_is_refused_before_database_io() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(Arc::clone(&state))),
        Some("dev".to_owned()),
        read_write_level(),
    );

    for (sql, commit) in [
        ("COMMIT", false),
        ("ROLLBACK TO SAVEPOINT before_change", false),
        ("SAVEPOINT before_change", false),
        ("SET TRANSACTION READ WRITE", false),
        (
            "BEGIN UPDATE employees SET name = name WHERE employee_id = 100; COMMIT; END;",
            false,
        ),
        (
            "BEGIN UPDATE employees SET name = name WHERE employee_id = 100; COMMIT; END;",
            true,
        ),
    ] {
        let err = dispatcher
            .dispatch(
                "oracle_execute",
                json!({ "sql": sql, "commit": commit, "confirm": "irrelevant" }),
            )
            .expect_err("caller transaction boundaries are never executable");
        assert_eq!(err.error_class, ErrorClass::ForbiddenStatement, "{sql:?}");
        assert!(
            err.message.contains("server owns"),
            "refusal must explain transaction ownership: {err:?}"
        );
    }

    assert!(state.executed.lock().expect("exec mutex").is_empty());
    assert_eq!(state.commits.load(Ordering::SeqCst), 0);
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 0);
}

#[test]
fn opaque_plsql_calls_are_refused_before_database_io() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(Arc::clone(&state))),
        Some("dev".to_owned()),
        read_write_level(),
    );

    for sql in [
        "BEGIN DBMS_UTILITY.EXEC_DDL_STATEMENT('DROP TABLE protected_target'); END;",
        "BEGIN dbms_utility /* gap */ . execute_ddl_statement('DROP ' || 'TABLE protected_target'); END;",
        "BEGIN :embedding := DBMS_VECTOR.UTL_TO_EMBEDDING(:txt); END;",
        "CALL app_admin.run_ddl('protected_target')",
        "BEGIN app_admin.run_ddl; END;",
    ] {
        let err = dispatcher
            .dispatch("oracle_execute", json!({ "sql": sql }))
            .expect_err("an unproven routine cannot inherit READ_WRITE authority");
        assert_eq!(err.error_class, ErrorClass::ForbiddenStatement, "{sql:?}");
    }

    assert!(state.executed.lock().expect("exec mutex").is_empty());
    assert_eq!(state.commits.load(Ordering::SeqCst), 0);
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 0);
}

#[test]
fn non_allowlisted_alter_session_is_refused_before_database_io() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(Arc::clone(&state))),
        Some("dev".to_owned()),
        read_write_level(),
    );

    for sql in [
        "ALTER SESSION SET CONTAINER = CDB$ROOT",
        "ALTER SESSION SET SQL_TRACE = TRUE",
        "ALTER SESSION SET EVENTS = '10046 trace name context forever, level 12'",
        "ALTER SESSION SET \"_PRIVATE_PARAMETER\" = TRUE",
        "ALTER SESSION DISABLE GUARD",
        "ALTER SESSION SET CURRENT_SCHEMA=HR/**/SQL_TRACE=TRUE",
        "/* oraclemcp audit */ ALTER/**/SESSION SET CONTAINER = CDB$ROOT",
    ] {
        let preview = dispatcher
            .dispatch("oracle_preview_sql", json!({ "sql": sql }))
            .expect("a forbidden preview remains inspectable");
        assert_eq!(preview["gate_decision"], json!("blocked"), "{sql:?}");
        assert_eq!(
            preview["blocked_reason"]["type"],
            json!("forbidden"),
            "{sql:?}"
        );
        assert!(preview["execute_confirmation"].is_null(), "{sql:?}");

        let err = dispatcher
            .dispatch(
                "oracle_execute",
                json!({ "sql": sql, "commit": true, "confirm": "irrelevant" }),
            )
            .expect_err("non-allowlisted session state is never executable");
        assert_eq!(err.error_class, ErrorClass::ForbiddenStatement, "{sql:?}");
    }

    assert!(state.executed.lock().expect("exec mutex").is_empty());
    assert_eq!(state.commits.load(Ordering::SeqCst), 0);
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 0);
}

#[test]
fn allowlisted_alter_session_requires_confirmation_even_with_rollback_default() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(Arc::clone(&state))),
        Some("dev".to_owned()),
        read_write_level(),
    );
    let sql = "ALTER SESSION SET CURRENT_SCHEMA = APP";

    let err = dispatcher
        .dispatch("oracle_execute", json!({ "sql": sql }))
        .expect_err("persistent session state requires exact-statement review");
    assert_eq!(err.error_class, ErrorClass::ChallengeRequired);
    assert!(err.message.contains("non-transactional effect"), "{err:?}");
    assert!(state.executed.lock().expect("exec mutex").is_empty());

    let confirm = preview_confirm(&dispatcher, sql);
    let before_generation = catalog_generation(&dispatcher);
    let out = dispatcher
        .dispatch("oracle_execute", json!({ "sql": sql, "confirm": confirm }))
        .expect("reviewed allowlisted setting executes");
    assert_eq!(catalog_generation(&dispatcher), before_generation + 1);
    assert_eq!(out["committed"], json!(false));
    assert_eq!(out["rolled_back"], json!(true));
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);
    assert_eq!(state.commits.load(Ordering::SeqCst), 0);
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 1);
}

#[test]
fn query_timeout_override_is_restored_after_call() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        default_read_only_level(),
    );

    let out = dispatcher
        .dispatch(
            "oracle_query",
            json!({
                "sql": "SELECT 1 AS id FROM dual",
                "timeout_seconds": 17
            }),
        )
        .expect("query with timeout");
    assert_eq!(out["row_count"], json!(0));
    let timeouts = state.call_timeout_sets.lock().expect("timeout sets mutex");
    assert_eq!(timeouts.as_slice(), &[Some(Duration::from_secs(17)), None]);
}

#[test]
fn query_timeout_override_cannot_widen_profile_timeout() {
    let state = Arc::new(ExecState::default());
    *state.current_call_timeout.lock().expect("timeout mutex") = Some(Duration::from_secs(10));
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        default_read_only_level(),
    )
    .with_request_timeout(Some(Duration::from_secs(10)));

    let out = dispatcher
        .dispatch(
            "oracle_query",
            json!({
                "sql": "SELECT 1 AS id FROM dual",
                "timeout_seconds": 17
            }),
        )
        .expect("query with timeout");
    assert_eq!(out["row_count"], json!(0));
    let timeouts = state.call_timeout_sets.lock().expect("timeout sets mutex");
    assert!(
        timeouts.is_empty(),
        "an equal-or-looser override must not churn the existing profile limit"
    );
    drop(timeouts);
    assert_eq!(
        *state.current_call_timeout.lock().expect("timeout mutex"),
        Some(Duration::from_secs(10)),
        "the profile's tighter timeout remains installed"
    );
}

#[test]
fn execute_timeout_override_is_restored_after_call() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        read_write_level(),
    );

    let out = dispatcher
        .dispatch(
            "oracle_execute",
            json!({
                "sql": "UPDATE employees SET name = name WHERE employee_id = 100",
                "timeout_seconds": 11
            }),
        )
        .expect("execute with timeout");
    assert_eq!(out["executed"], json!(true));
    assert_eq!(out["rolled_back"], json!(true));
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 1);
    let timeouts = state.call_timeout_sets.lock().expect("timeout sets mutex");
    assert_eq!(timeouts.as_slice(), &[Some(Duration::from_secs(11)), None]);
}

#[test]
fn execute_can_capture_bounded_dbms_output() {
    let state = Arc::new(ExecState::default());
    *state.dbms_output.lock().expect("output mutex") = DbmsOutput {
        lines: vec!["first".to_owned(), "second".to_owned()],
        line_count: 2,
        char_count: 11,
        truncated: false,
    };
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        read_write_level(),
    );

    let out = dispatcher
        .dispatch(
            "oracle_execute",
            json!({
                "sql": "BEGIN SYS.DBMS_OUTPUT.PUT_LINE('first'); SYS.DBMS_OUTPUT.PUT_LINE('second'); END;",
                "dbms_output": true,
                "max_dbms_output_lines": 10,
                "max_dbms_output_chars": 100
            }),
        )
        .expect("execute with dbms output");

    assert_eq!(out["executed"], json!(true));
    assert_eq!(out["rolled_back"], json!(true));
    assert_eq!(out["dbms_output"]["enabled"], json!(true));
    assert_eq!(out["dbms_output"]["lines"], json!(["first", "second"]));
    assert_eq!(out["dbms_output"]["line_count"], json!(2));
    assert_eq!(out["dbms_output"]["char_count"], json!(11));
    assert_eq!(out["dbms_output"]["truncated"], json!(false));
    assert_eq!(out["dbms_output"]["max_lines"], json!(10));
    assert_eq!(out["dbms_output"]["max_chars"], json!(100));
    assert_eq!(state.dbms_output_enabled.load(Ordering::SeqCst), 1);
    assert_eq!(
        state
            .dbms_output_limits
            .lock()
            .expect("output limits mutex")
            .as_slice(),
        &[(10, 100)]
    );
}

#[test]
fn execute_dbms_output_limits_are_clamped() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        read_write_level(),
    );

    let out = dispatcher
        .dispatch(
            "oracle_execute",
            json!({
                "sql": "BEGIN SYS.DBMS_OUTPUT.PUT_LINE('x'); END;",
                "capture_dbms_output": true,
                "dbms_output_max_lines": 999999,
                "dbms_output_max_chars": 999999999
            }),
        )
        .expect("execute with clamped dbms output");

    assert_eq!(
        out["dbms_output"]["max_lines"],
        json!(MAX_DBMS_OUTPUT_MAX_LINES)
    );
    assert_eq!(
        out["dbms_output"]["max_chars"],
        json!(MAX_DBMS_OUTPUT_MAX_CHARS)
    );
    assert_eq!(
        state
            .dbms_output_limits
            .lock()
            .expect("output limits mutex")
            .as_slice(),
        &[(MAX_DBMS_OUTPUT_MAX_LINES, MAX_DBMS_OUTPUT_MAX_CHARS)]
    );
}

#[test]
fn execute_commit_requires_preview_confirmation_without_executing() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        read_write_level(),
    );

    let err = dispatcher
        .dispatch(
            "oracle_execute",
            json!({
                "sql": "UPDATE employees SET name = name WHERE employee_id = 100",
                "commit": true
            }),
        )
        .expect_err("commit needs confirmation");
    assert_eq!(err.error_class, ErrorClass::ChallengeRequired);
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
    assert_eq!(state.commits.load(Ordering::SeqCst), 0);
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 0);
}

#[test]
fn execute_commit_with_preview_confirmation_commits() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        read_write_level(),
    );
    let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
    let preview = dispatcher
        .dispatch("oracle_preview_sql", json!({ "sql": sql }))
        .expect("preview");
    let confirm = preview["execute_confirmation"]["confirm"]
        .as_str()
        .expect("confirm");

    let out = dispatcher
        .dispatch(
            "oracle_execute",
            json!({ "sql": sql, "commit": true, "confirmation_token": confirm }),
        )
        .expect("execute commit");
    assert_eq!(out["committed"], json!(true));
    assert_eq!(out["rolled_back"], json!(false));
    assert_eq!(state.commits.load(Ordering::SeqCst), 1);
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 0);
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);
}

#[test]
fn execute_commit_writes_intent_before_db_execute_and_resolves_after_commit() {
    let state = Arc::new(ExecState::default());
    let intents = write_intent_log("execute-before-db");
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(IntentObservingExecMock {
            state: state.clone(),
            intents: intents.clone(),
        }),
        Some("dev".to_owned()),
        read_write_level(),
    )
    .with_write_intent_log(intents.clone());
    let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
    let confirm = preview_confirm(&dispatcher, sql);

    let out = dispatcher
        .dispatch(
            "oracle_execute",
            json!({ "sql": sql, "commit": true, "confirm": confirm }),
        )
        .expect("execute commit");
    assert_eq!(out["committed"], json!(true));
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);
    assert_eq!(state.commits.load(Ordering::SeqCst), 1);
    assert!(
        intents.unresolved().expect("intent snapshot").is_empty(),
        "successful commit resolves the durable intent"
    );
}

#[test]
fn write_intent_replay_error_is_runtime_state_required() {
    let err = write_intent_error_to_envelope(WriteIntentError::AlreadyResolved {
        intent_id: "intent-test".to_owned(),
        outcome: WriteIntentOutcome::Succeeded,
    });
    assert_eq!(err.error_class, ErrorClass::RuntimeStateRequired);
    assert!(
        err.message.contains("already resolved"),
        "message should expose the replay reason: {}",
        err.message
    );
    assert!(
        err.next_steps
            .iter()
            .any(|step| step.contains("do not replay this confirmation grant")),
        "next step should steer away from duplicate execution: {:?}",
        err.next_steps
    );
}

#[test]
fn execute_grant_is_lane_bound_and_not_consumed_by_wrong_lane() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        read_write_level(),
    );
    let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
    let lane_a = DispatchContext::default()
        .with_http_session_id("sess-a")
        .with_principal_key("oauth:user-a")
        .with_lane_identity("lane-a", 1);
    let lane_b = DispatchContext::default()
        .with_http_session_id("sess-a")
        .with_principal_key("oauth:user-a")
        .with_lane_identity("lane-b", 1);
    let preview = dispatcher
        .dispatch_with_context("oracle_preview_sql", json!({ "sql": sql }), lane_a)
        .expect("preview on lane a");
    let confirm = preview["execute_confirmation"]["confirm"]
        .as_str()
        .expect("grant")
        .to_owned();

    let err = dispatcher
        .dispatch_with_context(
            "oracle_execute",
            json!({ "sql": sql, "commit": true, "confirm": confirm.clone() }),
            lane_b,
        )
        .expect_err("lane b cannot consume lane a grant");
    assert_eq!(err.error_class, ErrorClass::ChallengeRequired);
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);

    let out = dispatcher
        .dispatch_with_context(
            "oracle_execute",
            json!({ "sql": sql, "commit": true, "confirm": confirm }),
            lane_a,
        )
        .expect("lane a still consumes the grant");
    assert_eq!(out["committed"], json!(true));
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);
}

#[test]
fn execute_grant_is_invalid_after_session_level_generation_change() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        read_write_level(),
    );
    let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
    let stale_confirm = preview_confirm(&dispatcher, sql);

    dispatcher
        .dispatch("oracle_set_session_level", json!({ "action": "drop" }))
        .expect("drop to read-only");
    let preview = dispatcher
        .dispatch(
            "oracle_set_session_level",
            json!({ "level": "READ_WRITE", "ttl_seconds": 60 }),
        )
        .expect("preview re-elevation");
    let level_confirm = preview["confirmation"]["confirm"]
        .as_str()
        .expect("level confirmation");
    dispatcher
        .dispatch(
            "oracle_set_session_level",
            json!({ "level": "READ_WRITE", "ttl_seconds": 60, "execute": true, "confirm": level_confirm }),
        )
        .expect("re-elevate to read/write");

    let err = dispatcher
        .dispatch(
            "oracle_execute",
            json!({ "sql": sql, "commit": true, "confirm": stale_confirm }),
        )
        .expect_err("old grant was minted for an earlier generation");
    assert_eq!(err.error_class, ErrorClass::ChallengeRequired);
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
}

#[test]
fn execute_commit_in_doubt_audits_and_quarantines_dispatcher() {
    use oraclemcp_audit::{AuditError, AuditRecord, AuditSink, MemoryAuditSink, SigningKey};

    struct SharedSink(Arc<MemoryAuditSink>);
    impl AuditSink for SharedSink {
        fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.0.append(record)
        }

        fn flush(&self) -> Result<(), AuditError> {
            self.0.flush()
        }
    }

    let state = Arc::new(ExecState::default());
    let sink = Arc::new(MemoryAuditSink::new());
    let auditor = Arc::new(oraclemcp_audit::Auditor::new(
        Box::new(SharedSink(sink.clone())),
        SigningKey::new("test-key", b"commit-in-doubt-test-key-1234567".to_vec())
            .expect("valid test key"),
    ));
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(CommitInDoubtMock {
            state: state.clone(),
        }),
        Some("dev".to_owned()),
        read_write_level(),
    )
    .with_auditor(auditor);
    let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
    let confirm = preview_confirm(&dispatcher, sql);

    let err = dispatcher
        .dispatch(
            "oracle_execute",
            json!({ "sql": sql, "commit": true, "confirmation_token": confirm }),
        )
        .expect_err("lost commit response is in doubt");
    assert_eq!(err.error_class, ErrorClass::ConnectionFailed);
    assert!(err.message.contains("commit_in_doubt"), "{}", err.message);
    assert_eq!(state.commits.load(Ordering::SeqCst), 1);
    assert_eq!(
        state.rollbacks.load(Ordering::SeqCst),
        0,
        "commit-in-doubt must not pretend rollback resolved the outcome"
    );

    let records = sink.records();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].outcome, AuditOutcome::Pending);
    assert_eq!(records[1].outcome, AuditOutcome::CommitInDoubt);

    let later = dispatcher
        .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
        .expect_err("quarantined dispatcher refuses later calls");
    assert_eq!(later.error_class, ErrorClass::RuntimeStateRequired);
    assert!(later.message.contains("quarantined"), "{}", later.message);
}

#[test]
fn execute_commit_in_doubt_leaves_durable_intent_unresolved() {
    let state = Arc::new(ExecState::default());
    let intents = write_intent_log("commit-in-doubt");
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(CommitInDoubtMock {
            state: state.clone(),
        }),
        Some("dev".to_owned()),
        read_write_level(),
    )
    .with_write_intent_log(intents.clone());
    let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
    let confirm = preview_confirm(&dispatcher, sql);

    let err = dispatcher
        .dispatch(
            "oracle_execute",
            json!({ "sql": sql, "commit": true, "confirm": confirm }),
        )
        .expect_err("commit response loss is in doubt");
    assert_eq!(err.error_class, ErrorClass::ConnectionFailed);
    assert_eq!(state.commits.load(Ordering::SeqCst), 1);

    let unresolved = intents.unresolved().expect("intent snapshot");
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].tool, "oracle_execute");
    assert_eq!(unresolved[0].subject, "process:stdio");
}

#[test]
fn execute_approved_token_only_rolls_back_by_default_and_replays_token_once() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        read_write_level(),
    );
    let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
    let preview = dispatcher
        .dispatch("preview_sql", json!({ "sql": sql }))
        .expect("preview stores token");
    let token = preview["execute_confirmation"]["confirm"]
        .as_str()
        .expect("token");

    let out = dispatcher
        .dispatch("execute_approved", json!({ "token": token }))
        .expect("execute approved");
    assert_eq!(out["committed"], json!(false));
    assert_eq!(out["rolled_back"], json!(true));
    assert_eq!(state.commits.load(Ordering::SeqCst), 0);
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 1);
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);

    let err = dispatcher
        .dispatch("execute_approved", json!({ "token": token }))
        .expect_err("token is one shot");
    assert_eq!(err.error_class, ErrorClass::ChallengeRequired);
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);
}

#[test]
fn execute_approved_explicit_commit_token_race_allows_exactly_one_success() {
    let state = Arc::new(ExecState::default());
    let dispatcher = Arc::new(OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        read_write_level(),
    ));
    let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
    let preview = dispatcher
        .dispatch("preview_sql", json!({ "sql": sql }))
        .expect("preview stores one-shot token");
    let token = preview["execute_confirmation"]["confirm"]
        .as_str()
        .expect("token")
        .to_owned();
    let barrier = Arc::new(Barrier::new(3));
    let results = Arc::new(Mutex::new(Vec::new()));

    std::thread::scope(|scope| {
        for _ in 0..2 {
            let dispatcher = dispatcher.clone();
            let barrier = barrier.clone();
            let results = results.clone();
            let token = token.clone();
            scope.spawn(move || {
                barrier.wait();
                let result = dispatcher
                    .dispatch(
                        "execute_approved",
                        json!({ "token": token, "commit": true }),
                    )
                    .map(|value| value["committed"] == json!(true))
                    .map_err(|err| err.error_class);
                results.lock().expect("results mutex").push(result);
            });
        }
        barrier.wait();
    });

    let results = results.lock().expect("results mutex");
    let successes = results
        .iter()
        .filter(|result| matches!(result, Ok(true)))
        .count();
    let one_shot_refusals = results
        .iter()
        .filter(|result| matches!(result, Err(ErrorClass::ChallengeRequired)))
        .count();
    assert_eq!(successes, 1, "exactly one racing region may redeem token");
    assert_eq!(
        one_shot_refusals, 1,
        "the losing region must get a structured one-shot refusal"
    );
    assert_eq!(
        state.commits.load(Ordering::SeqCst),
        1,
        "only the winning region commits"
    );
    assert_eq!(
        state.executed.lock().expect("exec mutex").len(),
        1,
        "only the winning region reaches the database"
    );
}

#[test]
fn execute_approved_with_sql_rolls_back_by_default() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        read_write_level(),
    );
    let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
    let token = preview_confirm(&dispatcher, sql);

    let out = dispatcher
        .dispatch("execute_approved", json!({ "sql": sql, "token": token }))
        .expect("execute approved with sql");
    assert_eq!(out["committed"], json!(false));
    assert_eq!(out["rolled_back"], json!(true));
    assert_eq!(state.commits.load(Ordering::SeqCst), 0);
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 1);
}

#[test]
fn execute_approved_ddl_requires_explicit_commit_without_executing() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        ddl_level(),
    );
    let sql = "CREATE TABLE app_smoke_execute_approved (id NUMBER)";
    let token = preview_confirm(&dispatcher, sql);

    let err = dispatcher
        .dispatch("execute_approved", json!({ "token": token }))
        .expect_err("DDL cannot use the rollback default");
    assert_eq!(err.error_class, ErrorClass::ChallengeRequired);
    assert!(state.executed.lock().expect("exec mutex").is_empty());
    assert_eq!(state.commits.load(Ordering::SeqCst), 0);
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 0);
}

#[test]
fn execute_approved_rejects_file_output_without_executing() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        read_write_level(),
    );
    let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
    let token = "unused-before-save-output-validation";

    let err = dispatcher
        .dispatch(
            "execute_approved",
            json!({ "sql": sql, "token": token, "save_output": "out.json" }),
        )
        .expect_err("file output is not generic core behavior");
    assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
}

#[test]
fn execute_rejects_write_below_current_level_without_executing() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        SessionLevelState::new(OperatingLevel::ReadWrite, false),
    );

    let err = dispatcher
        .dispatch(
            "oracle_execute",
            json!({ "sql": "UPDATE employees SET name = name WHERE employee_id = 100" }),
        )
        .expect_err("write needs elevated/default read-write level");
    assert_eq!(err.error_class, ErrorClass::OperatingLevelTooLow);
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
}

#[test]
fn execute_requires_commit_confirmation_for_ddl_without_executing() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        ddl_level(),
    );

    let err = dispatcher
        .dispatch(
            "oracle_execute",
            json!({ "sql": "CREATE TABLE app_smoke_execute (id NUMBER)" }),
        )
        .expect_err("ddl cannot rollback-preview");
    assert_eq!(err.error_class, ErrorClass::ChallengeRequired);
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
}

#[test]
fn parsed_and_unparsed_ddl_admin_floors_refuse_read_write_before_database_io() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(Arc::clone(&state))),
        Some("dev".to_owned()),
        read_write_level(),
    );

    for (sql, required_level) in [
        ("COMMENT ON TABLE app.t IS 'x'", "DDL"),
        ("ANALYZE TABLE app.t COMPUTE STATISTICS", "DDL"),
        ("CREATE SEQUENCE app.s START WITH 1", "DDL"),
        ("ALTER INDEX app.i REBUILD", "DDL"),
        ("CREATE PROFILE prof LIMIT SESSIONS_PER_USER 1", "ADMIN"),
        ("DROP PROFILE prof CASCADE", "ADMIN"),
        (
            "CREATE SCHEMA AUTHORIZATION app GRANT SELECT ON app.t TO reader",
            "ADMIN",
        ),
        ("DROP DATABASE", "ADMIN"),
        (
            "DROP PLUGGABLE DATABASE apppdb INCLUDING DATAFILES",
            "ADMIN",
        ),
    ] {
        let preview = dispatcher
            .dispatch("oracle_preview_sql", json!({ "sql": sql }))
            .expect("a level-gated preview remains inspectable");
        assert_eq!(preview["required_level"], json!(required_level), "{sql:?}");
        assert_ne!(preview["gate_decision"], json!("allow"), "{sql:?}");
        assert!(preview["execute_confirmation"].is_null(), "{sql:?}");

        let err = dispatcher
            .dispatch(
                "oracle_execute",
                json!({ "sql": sql, "commit": true, "confirm": "irrelevant" }),
            )
            .expect_err("READ_WRITE must not authorize DDL/Admin");
        assert_eq!(err.error_class, ErrorClass::OperatingLevelTooLow, "{sql:?}");
    }

    assert!(state.executed.lock().expect("exec mutex").is_empty());
    assert_eq!(state.commits.load(Ordering::SeqCst), 0);
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 0);
}

#[test]
fn compile_object_preview_is_default_and_does_not_execute() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        ddl_level(),
    );

    let preview = dispatcher
        .dispatch(
            "oracle_compile_object",
            json!({
                "object_type": "PACKAGE_BODY",
                "owner": "APP",
                "name": "EMP_API",
                "plscope": true,
                "enable_warnings": true
            }),
        )
        .expect("compile preview");
    assert_eq!(preview["compiled"], json!(false));
    assert_eq!(preview["preview"], json!(true));
    assert_eq!(preview["warnings"], json!(true));
    assert_eq!(preview["required_level"], json!("DDL"));
    assert_eq!(preview["gate_decision"], json!("allow"));
    assert_eq!(preview["statements"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        preview["statements"][0],
        json!(
            "ALTER PACKAGE APP.EMP_API COMPILE BODY PLSQL_WARNINGS = 'ENABLE:ALL' PLSCOPE_SETTINGS = 'IDENTIFIERS:ALL, STATEMENTS:ALL' REUSE SETTINGS"
        )
    );
    assert!(
        !preview["statements"][0]
            .as_str()
            .expect("compile statement")
            .contains("ALTER SESSION")
    );
    assert_eq!(
        preview["confirmation"]["tool"],
        json!("oracle_compile_object")
    );
    assert_eq!(preview["next_actions"][0]["intent"], json!("compile"));
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
}

#[test]
fn compile_object_requires_ddl_level_without_executing() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        read_write_level(),
    );

    let err = dispatcher
        .dispatch(
            "oracle_compile_object",
            json!({
                "object_type": "PACKAGE",
                "name": "EMP_API",
                "execute": true,
                "confirm": "bad"
            }),
        )
        .expect_err("read/write is not enough for compile");
    assert_eq!(err.error_class, ErrorClass::OperatingLevelTooLow);
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
}

#[test]
fn compile_view_rejects_plsql_only_options_before_execute() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        ddl_level(),
    );

    let err = dispatcher
        .dispatch(
            "oracle_compile_object",
            json!({
                "object_type": "VIEW",
                "owner": "APP",
                "name": "EMP_V",
                "warnings": true
            }),
        )
        .expect_err("PL/SQL compiler options do not apply to views");

    assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    assert!(err.message.contains("not VIEW"));
    assert!(state.executed.lock().expect("exec mutex").is_empty());
}

#[test]
fn compile_object_execute_requires_preview_confirmation() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        ddl_level(),
    );

    let err = dispatcher
        .dispatch(
            "compile_object",
            json!({
                "object_type": "PACKAGE",
                "object_name": "EMP_API",
                "execute": true
            }),
        )
        .expect_err("confirmation required");
    assert_eq!(err.error_class, ErrorClass::ChallengeRequired);
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
}

#[test]
fn compile_object_execute_runs_statements_and_returns_compile_errors() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        ddl_level(),
    );
    let preview = dispatcher
        .dispatch(
            "oracle_compile_object",
            json!({ "object_type": "PACKAGE", "name": "EMP_API" }),
        )
        .expect("preview");
    let confirm = preview["confirmation"]["confirm"]
        .as_str()
        .expect("confirm");

    let before_generation = catalog_generation(&dispatcher);
    let out = dispatcher
        .dispatch(
            "oracle_compile_object",
            json!({
                "object_type": "PACKAGE",
                "name": "EMP_API",
                "execute": true,
                "confirmation_token": confirm
            }),
        )
        .expect("compile executes");
    assert_eq!(catalog_generation(&dispatcher), before_generation + 1);
    assert_eq!(out["compiled"], json!(true));
    assert_eq!(out["object_type"], json!("PACKAGE"));
    assert_eq!(
        out["statements_executed"][0],
        json!("ALTER PACKAGE APP.EMP_API COMPILE")
    );
    assert!(out["errors"].is_array());
    let executed = state.executed.lock().expect("exec mutex");
    assert_eq!(executed.len(), 1);
    assert_eq!(executed[0].0, "ALTER PACKAGE APP.EMP_API COMPILE");
}

#[test]
fn compile_with_warnings_enables_warnings_and_counts_diagnostics() {
    let state = Arc::new(ExecState::default());
    state
        .diagnostics
        .lock()
        .expect("diagnostics mutex")
        .extend([
            diagnostic_row("ERROR", "PLS-00103: encountered symbol"),
            diagnostic_row("WARNING", "PLW-06009: procedure may be removed"),
        ]);
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        ddl_level(),
    );

    let preview = dispatcher
        .dispatch(
            "compile_with_warnings",
            json!({ "object_type": "PACKAGE", "object_name": "EMP_API" }),
        )
        .expect("compile-with-warnings preview");
    assert_eq!(preview["warnings"], json!(true));
    assert_eq!(preview["statements"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        preview["statements"][0],
        json!("ALTER PACKAGE APP.EMP_API COMPILE PLSQL_WARNINGS = 'ENABLE:ALL' REUSE SETTINGS")
    );
    assert_eq!(
        preview["confirmation"]["tool"],
        json!("compile_with_warnings")
    );
    let confirm = preview["confirmation"]["confirm"]
        .as_str()
        .expect("confirm");

    let out = dispatcher
        .dispatch(
            "compile_with_warnings",
            json!({
                "object_type": "PACKAGE",
                "object_name": "EMP_API",
                "execute": true,
                "token": confirm
            }),
        )
        .expect("compile with warnings executes");
    assert_eq!(out["compiled"], json!(true));
    assert_eq!(out["warnings"], json!(true));
    assert_eq!(out["diagnostic_count"], json!(2));
    assert_eq!(out["error_count"], json!(1));
    assert_eq!(out["warning_count"], json!(1));

    let executed = state.executed.lock().expect("exec mutex");
    assert_eq!(executed.len(), 1);
    assert_eq!(
        executed[0].0,
        "ALTER PACKAGE APP.EMP_API COMPILE PLSQL_WARNINGS = 'ENABLE:ALL' REUSE SETTINGS"
    );
}

#[test]
fn explain_plan_refuses_a_non_read_only_statement() {
    let dispatcher = OracleDispatcher::new(Box::new(NoExecMock));
    let err = dispatcher
        .dispatch(
            "oracle_explain_plan",
            json!({ "sql": "DELETE FROM hr.employees" }),
        )
        .expect_err("explain of a write is refused fail-closed");
    assert!(matches!(
        err.error_class,
        ErrorClass::OperatingLevelTooLow | ErrorClass::ForbiddenStatement
    ));
}

#[test]
fn explain_plan_refuses_plan_table_write_by_default_before_db() {
    let dispatcher = OracleDispatcher::new(Box::new(NoExecMock));
    let err = dispatcher
        .dispatch(
            "oracle_explain_plan",
            json!({ "sql": "SELECT 1 FROM dual" }),
        )
        .expect_err("PLAN_TABLE write needs explicit opt-in");
    assert_eq!(err.error_class, ErrorClass::PolicyDenied);
    assert!(err.message.contains("PLAN_TABLE"));
    assert!(
        err.next_steps
            .iter()
            .any(|step| step.contains("allow_plan_table_write=true"))
    );
}

#[test]
fn explain_plan_refuses_read_only_standby_before_db() {
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(NoExecMock),
        Some("dev".to_owned()),
        read_write_level(),
    );
    let err = dispatcher
        .dispatch(
            "oracle_explain_plan",
            json!({
                "sql": "SELECT 1 FROM dual",
                "read_only_standby": true,
                "allow_plan_table_write": true
            }),
        )
        .expect_err("read-only standby must refuse PLAN_TABLE writes");
    assert_eq!(err.error_class, ErrorClass::PolicyDenied);
    assert!(err.message.contains("read-only standby"));
}

#[test]
fn explain_plan_requires_read_write_session_when_allowed() {
    let dispatcher = OracleDispatcher::new(Box::new(NoExecMock));
    let err = dispatcher
        .dispatch(
            "oracle_explain_plan",
            json!({
                "sql": "SELECT 1 FROM dual",
                "allow_plan_table_write": true
            }),
        )
        .expect_err("explicit PLAN_TABLE write still needs READ_WRITE");
    assert_eq!(err.error_class, ErrorClass::OperatingLevelTooLow);
    assert!(err.message.contains("READ_WRITE"));
}

#[test]
fn explain_plan_executes_only_with_read_write_and_explicit_allow() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        read_write_level(),
    );

    let out = dispatcher
        .dispatch(
            "oracle_explain_plan",
            json!({
                "sql": "SELECT 1 FROM dual",
                "allow_plan_table_write": true
            }),
        )
        .expect("READ_WRITE + explicit diagnostic write runs explain plan");
    assert_eq!(out["diagnostic_write"]["statement"], json!("EXPLAIN PLAN"));
    assert_eq!(out["diagnostic_write"]["writes"], json!("PLAN_TABLE"));
    assert_eq!(
        out["diagnostic_write"]["required_level"],
        json!("READ_WRITE")
    );
    assert_eq!(out["diagnostic_write"]["explicitly_allowed"], json!(true));
    assert_eq!(out["diagnostic_write"]["rolled_back"], json!(true));
    assert_eq!(
        state.rollbacks.load(Ordering::SeqCst),
        1,
        "PLAN_TABLE diagnostic rows are always rolled back after capture"
    );

    let executed = state.executed.lock().expect("exec mutex");
    assert_eq!(executed.len(), 1);
    assert_eq!(executed[0].0, "EXPLAIN PLAN FOR SELECT 1 FROM dual");
    assert_eq!(executed[0].1, Vec::<OracleBind>::new());
}

#[test]
fn multi_statement_batch_with_a_write_is_refused() {
    // A `;`-joined batch carrying a DROP is refused fail-closed (its danger
    // is the max over statements; a desynced batch would be ForbiddenStatement).
    let dispatcher = OracleDispatcher::new(Box::new(NoExecMock));
    let err = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT 1 FROM dual; DROP TABLE hr.employees" }),
        )
        .expect_err("a multi-statement batch containing a write is refused");
    assert!(matches!(
        err.error_class,
        ErrorClass::ForbiddenStatement | ErrorClass::OperatingLevelTooLow
    ));
}

#[test]
fn cancelled_query_never_reaches_database() {
    let dispatcher = OracleDispatcher::new(Box::new(NoExecMock));
    run_with_current_cx(|cx| {
        cx.set_cancel_requested(true);
        let err = dispatcher
            .dispatch_with_cx(cx, "oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
            .expect_err("cancelled context must stop before DB query");
        assert_eq!(err.error_class, ErrorClass::Timeout);
    });
}

#[test]
fn cancellation_after_mutating_execute_rolls_back_dirty_session() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(CancelAfterExecuteMock {
            state: state.clone(),
        }),
        Some("dev".to_owned()),
        read_write_level(),
    );
    let sql = "UPDATE employees SET salary = salary WHERE employee_id = 100";
    let confirm = preview_confirm(&dispatcher, sql);

    run_with_current_cx(|cx| {
        let err = dispatcher
            .dispatch_with_cx(
                cx,
                "oracle_execute",
                json!({
                    "sql": sql,
                    "commit": true,
                    "confirm": confirm
                }),
            )
            .expect_err("post-execute cancellation must be surfaced");
        assert_eq!(err.error_class, ErrorClass::Timeout);
    });

    assert_eq!(
        state.executed.lock().expect("exec mutex").len(),
        1,
        "the mock simulates an Oracle-side execute before cancellation"
    );
    assert_eq!(
        state.rollbacks.load(Ordering::SeqCst),
        1,
        "dirty session must be rolled back after cancellation"
    );
    assert_eq!(
        state.commits.load(Ordering::SeqCst),
        0,
        "cancelled dirty session must not commit"
    );
}

/// QA85: cancellation and secondary-finalization failures at a mutation's
/// terminal boundary must never invite an unsafe retry or let a preview escape
/// its request cancellation.
mod qa85_terminal_boundaries {
    use super::*;
    use oraclemcp_audit::{
        AuditError, AuditOutcome, AuditRecord, AuditSink, Auditor, MemoryAuditSink, SigningKey,
    };
    use std::task::Poll;

    struct SharedSink(Arc<MemoryAuditSink>);

    impl AuditSink for SharedSink {
        fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.0.append(record)
        }

        fn flush(&self) -> Result<(), AuditError> {
            self.0.flush()
        }
    }

    fn auditor_with_sink() -> (Arc<Auditor>, Arc<MemoryAuditSink>) {
        let sink = Arc::new(MemoryAuditSink::new());
        let auditor = Arc::new(Auditor::new(
            Box::new(SharedSink(Arc::clone(&sink))),
            SigningKey::new(
                "qa85-test-key",
                b"qa85-terminal-boundary-key-12345".to_vec(),
            )
            .expect("valid test key"),
        ));
        (auditor, sink)
    }

    struct FailAfterFirstAppendSink {
        inner: Arc<MemoryAuditSink>,
        appends: Arc<AtomicUsize>,
    }

    impl AuditSink for FailAfterFirstAppendSink {
        fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
            let append_index = self.appends.fetch_add(1, Ordering::SeqCst);
            if append_index > 0 {
                return Err(AuditError::Io(
                    "injected terminal audit sink failure".to_owned(),
                ));
            }
            self.inner.append(record)
        }

        fn flush(&self) -> Result<(), AuditError> {
            self.inner.flush()
        }
    }

    struct CancelOnAppendSink {
        inner: Arc<MemoryAuditSink>,
        cx: Cx,
    }

    impl AuditSink for CancelOnAppendSink {
        fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.inner.append(record)?;
            self.cx.set_cancel_requested(true);
            Ok(())
        }

        fn flush(&self) -> Result<(), AuditError> {
            self.inner.flush()
        }
    }

    fn level_and_generation(dispatcher: &OracleDispatcher) -> (OperatingLevel, u64) {
        RuntimeBuilder::current_thread()
            .build()
            .expect("asupersync test runtime builds")
            .block_on(async {
                let cx = Cx::current().expect("block_on installs a current Cx");
                let state = dispatcher
                    .state
                    .lock(&cx)
                    .await
                    .expect("dispatcher state lock");
                (state.level.effective_level(), state.grant_generation)
            })
    }

    fn assert_uncertain_ddl_preflight_aborts(case: &str, tool: &str, mut args: Value) {
        let state = Arc::new(ExecState::default());
        let intents = write_intent_log(case);
        let (auditor, sink) = auditor_with_sink();
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            ddl_level(),
        )
        .with_auditor(auditor)
        .with_write_intent_log(Arc::clone(&intents));

        let preview = dispatcher
            .dispatch(tool, args.clone())
            .unwrap_or_else(|error| panic!("{case}: preview failed: {error:?}"));
        let confirm = preview["confirmation"]["confirm"]
            .as_str()
            .unwrap_or_else(|| panic!("{case}: preview did not mint confirmation"))
            .to_owned();
        *state.describe_error.lock().expect("describe error mutex") = Some(DbError::Cancelled(
            format!("{case}: injected evidence cancellation"),
        ));
        args["execute"] = json!(true);
        args["confirm"] = json!(confirm);

        let error = match dispatcher.dispatch(tool, args) {
            Ok(value) => panic!("{case}: uncertain evidence unexpectedly applied: {value}"),
            Err(error) => error,
        };
        assert_eq!(error.error_class, ErrorClass::ConnectionFailed, "{case}");
        assert!(
            error.message.contains("unknown_discarded"),
            "{case}: {error:?}"
        );
        assert!(
            state.executed.lock().expect("exec mutex").is_empty(),
            "{case}: evidence uncertainty must stop before DDL execution"
        );
        assert!(
            sink.records().is_empty(),
            "{case}: Pending audit must not be written"
        );
        assert!(
            intents.unresolved().expect("intent snapshot").is_empty(),
            "{case}: pre-execute failure must resolve the durable intent"
        );
        let ledger = std::fs::read_to_string(intents.path().expect("intent path"))
            .expect("intent ledger is readable");
        assert!(
            ledger.contains("ABORTED_BEFORE_EXECUTE"),
            "{case}: terminal intent resolution must distinguish pre-execute abort: {ledger}"
        );
        let quarantine = dispatcher
            .connection_quarantine()
            .expect("quarantine lock")
            .expect("uncertain preflight quarantines");
        assert_eq!(quarantine.outcome, AuditOutcome::UnknownDiscarded, "{case}");
    }

    #[test]
    fn cancelled_profile_prepare_cannot_cross_switch_commit_point() {
        let candidate = Arc::new(ExecState::default());
        candidate.cancel_on_describe.store(1, Ordering::SeqCst);
        let connector_state = Arc::clone(&candidate);
        let dispatcher = OracleDispatcher::new_switchable(
            Box::new(OneRowMock),
            Some("dev".to_owned()),
            default_read_only_level(),
            Arc::new(move |_cx, _profile| {
                let state = Arc::clone(&connector_state);
                Box::pin(async move { Ok(session_bundle(ExecRecordingMock::new(state))) })
            }),
        );
        let before = level_and_generation(&dispatcher);

        let error = dispatcher
            .dispatch("oracle_switch_profile", json!({ "profile": "other" }))
            .expect_err("cancellation during candidate metadata aborts before switch commit");
        assert_eq!(error.error_class, ErrorClass::Timeout);
        assert_eq!(level_and_generation(&dispatcher), before);
        assert_eq!(candidate.describe_calls.load(Ordering::SeqCst), 1);

        let active = dispatcher
            .dispatch("oracle_connection_info", json!({}))
            .expect("old profile remains usable after aborted switch");
        assert_eq!(active["active_profile"], json!("dev"));
    }

    #[test]
    fn dropped_elevation_evidence_future_cannot_mutate_live_authority() {
        let state = Arc::new(ExecState::default());
        let (auditor, sink) = auditor_with_sink();
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            SessionLevelState::new(OperatingLevel::ReadWrite, false),
        )
        .with_auditor(auditor);
        let preview = dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({ "level": "READ_WRITE", "ttl_seconds": 60 }),
            )
            .expect("preview elevation");
        let confirm = preview["confirmation"]["confirm"]
            .as_str()
            .expect("elevation grant")
            .to_owned();
        let before = level_and_generation(&dispatcher);
        state.describe_pending.store(1, Ordering::SeqCst);

        RuntimeBuilder::current_thread()
            .build()
            .expect("asupersync test runtime builds")
            .block_on(async {
                let cx = Cx::current().expect("block_on installs a current Cx");
                let mut apply = ToolDispatch::dispatch(
                    &dispatcher,
                    &cx,
                    DispatchContext::default(),
                    "oracle_set_session_level",
                    json!({
                        "level": "READ_WRITE",
                        "ttl_seconds": 60,
                        "execute": true,
                        "confirm": confirm,
                    }),
                );
                std::future::poll_fn(|task_cx| match apply.as_mut().poll(task_cx) {
                    Poll::Ready(outcome) => {
                        panic!("pending evidence dispatch unexpectedly completed: {outcome:?}")
                    }
                    Poll::Pending if state.describe_calls.load(Ordering::SeqCst) > 0 => {
                        Poll::Ready(())
                    }
                    Poll::Pending => {
                        task_cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                })
                .await;
                drop(apply);
            });

        state.describe_pending.store(0, Ordering::SeqCst);
        assert_eq!(level_and_generation(&dispatcher), before);
        assert!(
            sink.records().is_empty(),
            "no successful elevation audit exists, so live authority must stay unchanged"
        );
        let retry = dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({
                    "level": "READ_WRITE",
                    "ttl_seconds": 60,
                    "execute": true,
                    "confirm": confirm,
                }),
            )
            .expect_err("a staged transition still consumes its single-use confirmation");
        assert_eq!(retry.error_class, ErrorClass::ChallengeRequired);
    }

    #[test]
    fn uncertain_elevation_evidence_cannot_mutate_level_or_generation() {
        let state = Arc::new(ExecState::default());
        let (auditor, sink) = auditor_with_sink();
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            SessionLevelState::new(OperatingLevel::ReadWrite, false),
        )
        .with_auditor(auditor);
        let preview = dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({ "level": "READ_WRITE", "ttl_seconds": 60 }),
            )
            .expect("preview elevation");
        let confirm = preview["confirmation"]["confirm"]
            .as_str()
            .expect("elevation grant")
            .to_owned();
        let before = level_and_generation(&dispatcher);
        *state.describe_error.lock().expect("describe error mutex") = Some(DbError::Cancelled(
            "injected elevation evidence cancellation".to_owned(),
        ));

        let error = dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({
                    "level": "READ_WRITE",
                    "ttl_seconds": 60,
                    "execute": true,
                    "confirm": confirm,
                }),
            )
            .expect_err("uncertain evidence refuses elevation");
        assert_eq!(error.error_class, ErrorClass::ConnectionFailed);
        assert!(error.message.contains("unknown_discarded"), "{error:?}");
        assert_eq!(level_and_generation(&dispatcher), before);
        assert!(sink.records().is_empty());
        assert_eq!(
            dispatcher
                .connection_quarantine()
                .expect("quarantine lock")
                .expect("uncertain evidence quarantines")
                .outcome,
            AuditOutcome::UnknownDiscarded
        );
    }

    #[test]
    fn streaming_dispatch_preserves_durably_audited_elevation_after_late_cancellation() {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("asupersync test runtime builds");
        runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            let sink = Arc::new(MemoryAuditSink::new());
            let auditor = Arc::new(Auditor::new(
                Box::new(CancelOnAppendSink {
                    inner: Arc::clone(&sink),
                    cx: cx.clone(),
                }),
                SigningKey::new(
                    "qa85-test-key",
                    b"qa85-cancel-after-elevation-audit".to_vec(),
                )
                .expect("valid test key"),
            ));
            let dispatcher = OracleDispatcher::new_with_profile_level(
                Box::new(ExecRecordingMock::new(Arc::new(ExecState::default()))),
                Some("dev".to_owned()),
                SessionLevelState::new(OperatingLevel::ReadWrite, false),
            )
            .with_auditor(auditor);
            let preview = match ToolDispatch::dispatch(
                &dispatcher,
                &cx,
                DispatchContext::default(),
                "oracle_set_session_level",
                json!({ "level": "READ_WRITE", "ttl_seconds": 60 }),
            )
            .await
            {
                Outcome::Ok(value) => value,
                other => panic!("elevation preview failed: {other:?}"),
            };
            let confirm = preview["confirmation"]["confirm"]
                .as_str()
                .expect("elevation grant")
                .to_owned();
            let before_generation = dispatcher
                .state
                .lock(&cx)
                .await
                .expect("dispatcher state lock")
                .grant_generation;
            let (frames_tx, _frames_rx) = mpsc::channel(1);
            let outcome = ToolDispatch::dispatch_stream(
                &dispatcher,
                &cx,
                DispatchContext::default(),
                "oracle_set_session_level",
                json!({
                    "level": "READ_WRITE",
                    "ttl_seconds": 60,
                    "execute": true,
                    "confirm": confirm,
                }),
                frames_tx,
            )
            .await;
            let value = match outcome {
                Outcome::Ok(value) => value,
                other => panic!("terminal elevation must win late cancellation: {other:?}"),
            };
            assert_eq!(value["changed"], json!(true));
            assert_eq!(value["session"]["current_level"], json!("READ_WRITE"));
            assert_eq!(value["deadline_observed_after_effect"], json!(true));
            let records = sink.records();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].outcome, AuditOutcome::Succeeded);

            cx.set_cancel_requested(false);
            let state = dispatcher
                .state
                .lock(&cx)
                .await
                .expect("dispatcher state lock after clearing test cancellation");
            assert_eq!(state.level.effective_level(), OperatingLevel::ReadWrite);
            assert!(state.grant_generation > before_generation);
        });
    }

    #[test]
    fn ddl_mutators_resolve_uncertain_evidence_as_aborted_before_execute() {
        assert_uncertain_ddl_preflight_aborts(
            "qa85-compile-evidence-cancel",
            "oracle_compile_object",
            json!({ "owner": "APP", "object_type": "PACKAGE", "name": "EMP_API" }),
        );
        assert_uncertain_ddl_preflight_aborts(
            "qa85-create-evidence-cancel",
            "oracle_create_or_replace",
            json!({
                "source_code": "CREATE OR REPLACE VIEW EMP_V AS SELECT 1 AS ID FROM dual"
            }),
        );
        assert_uncertain_ddl_preflight_aborts(
            "qa85-patch-evidence-cancel",
            "oracle_patch_source",
            json!({
                "owner": "APP",
                "name": "EMP_API",
                "object_type": "PACKAGE_BODY",
                "old_text": "NULL",
                "new_text": "1"
            }),
        );
    }

    #[test]
    fn uncertain_dbms_output_setup_aborts_before_main_execute() {
        let state = Arc::new(ExecState::default());
        *state
            .dbms_output_enable_error
            .lock()
            .expect("DBMS_OUTPUT enable error mutex") = Some(DbError::Cancelled(
            "injected DBMS_OUTPUT setup cancellation".to_owned(),
        ));
        let intents = write_intent_log("qa85-dbms-output-enable-cancel");
        let (auditor, sink) = auditor_with_sink();
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            read_write_level(),
        )
        .with_auditor(auditor)
        .with_write_intent_log(Arc::clone(&intents));
        let sql = "BEGIN SYS.DBMS_OUTPUT.PUT_LINE('never-ran'); END;";
        let confirm = preview_confirm(&dispatcher, sql);

        let error = dispatcher
            .dispatch(
                "oracle_execute",
                json!({
                    "sql": sql,
                    "commit": true,
                    "confirm": confirm,
                    "dbms_output": true,
                }),
            )
            .expect_err("uncertain DBMS_OUTPUT setup must fail closed");
        assert_eq!(error.error_class, ErrorClass::ConnectionFailed);
        assert!(error.message.contains("unknown_discarded"), "{error:?}");
        assert_eq!(state.dbms_output_enabled.load(Ordering::SeqCst), 1);
        assert!(
            state.executed.lock().expect("exec mutex").is_empty(),
            "the approved statement must not run after DBMS_OUTPUT setup uncertainty"
        );
        assert_eq!(state.commits.load(Ordering::SeqCst), 0);
        assert_eq!(state.rollbacks.load(Ordering::SeqCst), 0);
        let records = sink.records();
        assert_eq!(records.len(), 2, "Pending plus terminal uncertainty");
        assert_eq!(records[0].outcome, AuditOutcome::Pending);
        assert_eq!(records[1].outcome, AuditOutcome::UnknownDiscarded);
        assert!(intents.unresolved().expect("intent snapshot").is_empty());
        let ledger = std::fs::read_to_string(intents.path().expect("intent path"))
            .expect("intent ledger is readable");
        assert!(ledger.contains("ABORTED_BEFORE_EXECUTE"), "{ledger}");
    }

    #[test]
    fn confirmed_commit_survives_late_cancellation_and_finalizes_durable_records() {
        let state = Arc::new(ExecState::default());
        state.cancel_on_commit.store(1, Ordering::SeqCst);
        let intents = write_intent_log("qa85-late-cancel-after-commit");
        let (auditor, sink) = auditor_with_sink();
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            read_write_level(),
        )
        .with_auditor(auditor)
        .with_write_intent_log(Arc::clone(&intents));
        let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
        let confirm = preview_confirm(&dispatcher, sql);

        run_with_current_cx(|cx| {
            let out = dispatcher
                .dispatch_with_cx(
                    cx,
                    "oracle_execute",
                    json!({ "sql": sql, "commit": true, "confirm": confirm }),
                )
                .expect("a confirmed commit remains successful after late cancellation");
            assert_eq!(out["executed"], json!(true));
            assert_eq!(out["committed"], json!(true));
            assert_eq!(out["deadline_observed_after_effect"], json!(true));
        });

        assert_eq!(state.commits.load(Ordering::SeqCst), 1);
        assert!(
            intents.unresolved().expect("intent snapshot").is_empty(),
            "known commit success resolves the durable write intent"
        );
        let records = sink.records();
        assert_eq!(records.len(), 2, "pending plus terminal audit record");
        assert_eq!(records[0].outcome, AuditOutcome::Pending);
        assert_eq!(records[1].outcome, AuditOutcome::Succeeded);
    }

    #[test]
    fn rollback_preview_with_late_cancellation_is_not_reported_as_success() {
        let state = Arc::new(ExecState::default());
        state.cancel_on_rollback.store(1, Ordering::SeqCst);
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            read_write_level(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("asupersync test runtime builds");
        let outcome = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            ToolDispatch::dispatch(
                &dispatcher,
                &cx,
                DispatchContext::default(),
                "oracle_execute",
                json!({
                    "sql": "UPDATE employees SET name = name WHERE employee_id = 100",
                    "commit": false,
                }),
            )
            .await
        });

        assert!(
            matches!(outcome, Outcome::Cancelled(_)),
            "rollback-only execution is a cancellable preview, got {outcome:?}"
        );
        assert_eq!(state.commits.load(Ordering::SeqCst), 0);
        assert_eq!(state.rollbacks.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn commit_in_doubt_remains_primary_when_terminal_audit_also_fails() {
        let state = Arc::new(ExecState::default());
        let intents = write_intent_log("qa85-commit-in-doubt-audit-failure");
        let memory_sink = Arc::new(MemoryAuditSink::new());
        let append_count = Arc::new(AtomicUsize::new(0));
        let auditor = Arc::new(Auditor::new(
            Box::new(FailAfterFirstAppendSink {
                inner: Arc::clone(&memory_sink),
                appends: Arc::clone(&append_count),
            }),
            SigningKey::new(
                "qa85-test-key",
                b"qa85-terminal-audit-failure-1234".to_vec(),
            )
            .expect("valid test key"),
        ));
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(CommitInDoubtMock {
                state: Arc::clone(&state),
            }),
            Some("dev".to_owned()),
            read_write_level(),
        )
        .with_auditor(auditor)
        .with_write_intent_log(Arc::clone(&intents));
        let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
        let confirm = preview_confirm(&dispatcher, sql);

        let err = dispatcher
            .dispatch(
                "oracle_execute",
                json!({ "sql": sql, "commit": true, "confirm": confirm }),
            )
            .expect_err("lost commit response remains commit-in-doubt");
        assert_eq!(err.error_class, ErrorClass::ConnectionFailed);
        assert!(err.message.contains("commit_in_doubt"), "{}", err.message);
        assert_eq!(append_count.load(Ordering::SeqCst), 2);
        assert_eq!(memory_sink.records().len(), 1, "only Pending was durable");
        assert_eq!(state.commits.load(Ordering::SeqCst), 1);
        assert_eq!(state.rollbacks.load(Ordering::SeqCst), 0);
        assert_eq!(
            intents.unresolved().expect("intent snapshot").len(),
            1,
            "an in-doubt commit must leave its durable intent unresolved"
        );

        let later = dispatcher
            .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
            .expect_err("commit-in-doubt quarantines the connection");
        assert_eq!(later.error_class, ErrorClass::RuntimeStateRequired);
    }

    #[test]
    fn cancelled_audit_evidence_preflight_quarantines_before_execute() {
        let state = Arc::new(ExecState::default());
        *state.describe_error.lock().expect("describe error mutex") = Some(DbError::Cancelled(
            "injected audit-evidence cancellation".to_owned(),
        ));
        let (auditor, sink) = auditor_with_sink();
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            read_write_level(),
        )
        .with_auditor(auditor);
        let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
        let confirm = preview_confirm(&dispatcher, sql);

        let err = dispatcher
            .dispatch(
                "oracle_execute",
                json!({ "sql": sql, "commit": true, "confirm": confirm }),
            )
            .expect_err("uncertain audit evidence must stop before execute");
        assert_eq!(err.error_class, ErrorClass::ConnectionFailed);
        assert!(err.message.contains("unknown_discarded"), "{}", err.message);
        assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
        assert_eq!(state.commits.load(Ordering::SeqCst), 0);
        assert!(
            sink.records().is_empty(),
            "Pending is not written preflight"
        );

        let later = dispatcher
            .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
            .expect_err("uncertain preflight quarantines the connection");
        assert_eq!(later.error_class, ErrorClass::RuntimeStateRequired);
    }

    #[test]
    fn uncertain_dbms_output_after_commit_is_in_band_and_quarantines_reuse() {
        let state = Arc::new(ExecState::default());
        *state.dbms_output_error.lock().expect("output error mutex") = Some(DbError::Cancelled(
            "injected DBMS_OUTPUT drain cancellation".to_owned(),
        ));
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            read_write_level(),
        );
        let sql = "BEGIN SYS.DBMS_OUTPUT.PUT_LINE('done'); END;";
        let confirm = preview_confirm(&dispatcher, sql);

        let out = dispatcher
            .dispatch(
                "oracle_execute",
                json!({
                    "sql": sql,
                    "commit": true,
                    "confirm": confirm,
                    "dbms_output": true,
                }),
            )
            .expect("known commit survives optional diagnostic uncertainty");
        assert_eq!(out["executed"], json!(true));
        assert_eq!(out["committed"], json!(true));
        assert!(out.get("dbms_output").is_none());
        assert!(
            out["dbms_output_unavailable"]
                .as_str()
                .is_some_and(|reason| reason.contains("terminal database outcome")),
            "optional diagnostic loss is reported in-band: {out}"
        );
        assert_eq!(state.commits.load(Ordering::SeqCst), 1);

        let later = dispatcher
            .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
            .expect_err("uncertain optional diagnostic quarantines later reuse");
        assert_eq!(later.error_class, ErrorClass::RuntimeStateRequired);
        assert!(later.message.contains("quarantined"), "{}", later.message);
    }
}

/// K7: the read-only gate attaches a "parameterize inline literals" next step
/// when a refused statement carries bind-safe literals, and omits it when there
/// is nothing to suggest. Purely additive — the class and refusal are unchanged.
mod parameterization_hint {
    use super::*;

    #[test]
    fn refused_write_with_inline_literal_gets_a_parameterization_hint() {
        let err = ensure_read_only("UPDATE orders SET status = 'X' WHERE id = 42")
            .expect_err("a write is refused by the read-only gate");
        assert_eq!(err.error_class, ErrorClass::OperatingLevelTooLow);
        let hint = err
            .next_steps
            .iter()
            .find(|s| s.contains("parameterize inline literals"))
            .expect("a parameterization hint is attached");
        assert!(
            hint.contains(":id"),
            "the hint suggests binding the literal named after its column: {hint}"
        );
    }

    #[test]
    fn refused_statement_without_bindable_literal_has_no_hint() {
        // A DDL refusal with no bind-safe literal must not fabricate a hint.
        let err = ensure_read_only("DROP TABLE orders")
            .expect_err("DDL is refused by the read-only gate");
        assert!(
            !err.next_steps.iter().any(|s| s.contains("parameterize")),
            "no parameterization hint when there is nothing bind-safe to suggest"
        );
    }
}

/// Bead .102: the served read-only gate refuses a **paren-less** qualified
/// function invocation. Oracle runs a zero-arg function with no `()`, so
/// `SELECT app_admin.run_ddl FROM dual` *calls* `run_ddl` — the classifier's
/// `ident(`-only UDF scan used to read it as a column reference and clear it to
/// Safe. The `DEFAULT_CLASSIFIER` opts into the qualified-callable guard so the
/// gate now fails closed, while genuine in-scope column references still pass.
mod parenless_qualified_callable_gate {
    use super::*;

    #[test]
    fn served_gate_refuses_parenless_qualified_callable() {
        for sql in [
            "SELECT app_admin.run_ddl FROM dual",
            "SELECT id, app_admin.run_ddl FROM orders",
            "SELECT s.nextval FROM dual",
            "SELECT hr.dangerous_fn FROM hr.employees",
            "SELECT app_admin.run_ddl FROM dual WHERE EXISTS (SELECT 1 FROM audit_log app_admin)",
            "SELECT employees.dangerous_fn FROM hr.employees e",
            "WITH c AS (SELECT dbms_random.value v FROM dual) SELECT c.v FROM dual dbms_random, c",
            "SELECT dbms_random.v FROM (SELECT dbms_random.value v FROM dual) dbms_random",
            "SELECT 1 FROM dual d JOIN dual x ON dbms_random.value > 0 JOIN dual dbms_random ON 1=1",
            "SELECT emp.dummy FROM dual \"emp\"",
            "SELECT run_ddl@oraclemcp_missing_link FROM dual",
            "SELECT dbms_random.value@oraclemcp_missing_link FROM dual dbms_random",
            "SELECT sys.dbms_random.value@oraclemcp_missing_link FROM dual sys",
            "SELECT dbms_random.value@prod.example.com FROM dual dbms_random",
        ] {
            let err = ensure_read_only(sql)
                .expect_err("a paren-less qualified callable must be refused by the served gate");
            assert!(
                matches!(
                    err.error_class,
                    ErrorClass::ForbiddenStatement | ErrorClass::OperatingLevelTooLow
                ),
                "refusal should be a guard block, got {:?} for {sql:?}",
                err.error_class
            );
        }
    }

    #[test]
    fn served_gate_still_admits_genuine_qualified_column_reads() {
        for sql in [
            "SELECT e.id, e.name FROM employees e WHERE e.id = 42",
            "SELECT hr.employees.salary FROM hr.employees",
            "SELECT id, name FROM employees WHERE dept = 10",
            "SELECT c.id FROM customers c WHERE EXISTS (SELECT 1 FROM orders o WHERE o.customer_id = c.id)",
            "SELECT \"Emp\".\"Name\" FROM employees \"Emp\"",
            "SELECT EMP.dummy FROM dual \"EMP\"",
            "SELECT \"EMP\".dummy FROM dual EMP",
            "SELECT d.dummy, q.v FROM dual d, LATERAL (SELECT d.dummy v FROM dual) q",
            "SELECT d.dummy, q.v FROM dual d CROSS APPLY (SELECT d.dummy v FROM dual) q",
            "SELECT j.doc.a FROM (SELECT json_col doc FROM json_docs) j",
            "SELECT e.address.city.name FROM employees e",
            "SELECT t.x FROM nested_docs d, TABLE(d.vals) t",
            "SELECT jt.a FROM json_docs d, JSON_TABLE(d.doc, '$' COLUMNS(a NUMBER PATH '$.a')) jt",
            "SELECT xt.a FROM xml_docs d, XMLTABLE('/r' PASSING d.doc COLUMNS a NUMBER PATH '.') xt",
            "SELECT employees.name FROM hr.employees@prod",
            "SELECT employees.name FROM employees@prod",
            "SELECT employees.name FROM hr.employees@prod.example.com",
            "SELECT employees.name FROM employees@prod.example.com",
            "SELECT \"run@ddl\" FROM (SELECT 1 \"run@ddl\" FROM dual)",
        ] {
            ensure_read_only(sql).unwrap_or_else(|e| {
                panic!("a genuine in-scope read must pass the gate: {sql:?} -> {e:?}")
            });
        }
    }
}

/// K8: the read-only gate attaches a structured "why blocked + minimal safe
/// rewrite" reason. Each refusal class returns a valid category, and a minimal
/// rewrite where one exists (or none, deferring to `suggested_tool`).
mod structured_reason {
    use super::*;
    use oraclemcp_error::ReasonCategory;

    fn reason_for(sql: &str) -> oraclemcp_error::StructuredReason {
        ensure_read_only(sql)
            .expect_err("statement is refused")
            .structured_reason
            .expect("a structured reason is attached to a guard refusal")
    }

    #[test]
    fn write_needs_higher_level_with_minimal_rewrite() {
        let reason = reason_for("UPDATE orders SET status = 'X' WHERE id = 42");
        assert_eq!(reason.category, ReasonCategory::RequiresHigherLevel);
        assert_eq!(reason.required_level.as_deref(), Some("READ_WRITE"));
        assert!(
            reason
                .minimal_rewrite
                .as_deref()
                .is_some_and(|r| r.contains("READ_WRITE")),
            "a level-gated write suggests running at the required level"
        );
    }

    #[test]
    fn multi_statement_batch_suggests_splitting() {
        // Trailing top-level SQL after a PL/SQL block rebalances the depth
        // counter — a stacking evasion the guard refuses fail-closed.
        let reason = reason_for("BEGIN NULL; END; DROP TABLE orders");
        assert_eq!(reason.category, ReasonCategory::MultiStatementBatch);
        assert!(
            reason
                .minimal_rewrite
                .as_deref()
                .is_some_and(|r| r.contains("its own")),
            "a stacked batch suggests submitting statements separately"
        );
    }

    #[test]
    fn dynamic_sql_has_category_but_no_minimal_rewrite() {
        let reason = reason_for("BEGIN EXECUTE IMMEDIATE 'DROP TABLE orders'; END;");
        assert_eq!(reason.category, ReasonCategory::DynamicSql);
        assert!(
            reason.minimal_rewrite.is_none(),
            "dynamic SQL has no single safe rewrite; defer to suggested_tool"
        );
        assert!(reason.offending_construct.is_some());
    }
}

/// A8: the hash-chained, keyed-MAC auditor is wired into the SERVED dispatch
/// path (not just the standalone `oracle_query_execute` helper). These prove the
/// wiring end to end: writes/DDL and escalations are chained; pure reads are not.
mod audit_wiring {
    use super::*;
    use oraclemcp_audit::{
        AuditError, AuditOutcome, AuditRecord, AuditSink, AuditSubject, MemoryAuditSink, SigningKey,
    };
    use std::sync::Arc;

    /// Share one `MemoryAuditSink` between the `Auditor` (which owns a
    /// `Box<dyn AuditSink>`) and the test (which inspects the records).
    struct SharedSink(Arc<MemoryAuditSink>);
    impl AuditSink for SharedSink {
        fn append(&self, r: &AuditRecord) -> Result<(), AuditError> {
            self.0.append(r)
        }
        fn flush(&self) -> Result<(), AuditError> {
            self.0.flush()
        }
    }

    fn auditor_with_sink() -> (Arc<Auditor>, Arc<MemoryAuditSink>) {
        let sink = Arc::new(MemoryAuditSink::new());
        let key = SigningKey::new("test-key", b"0123456789abcdef0123456789abcdef".to_vec())
            .expect("valid test key");
        let auditor = Arc::new(Auditor::new(Box::new(SharedSink(sink.clone())), key));
        (auditor, sink)
    }

    /// Ceiling permits DDL but the session starts read-only, so a level increase
    /// is gated by step-up (the path that A8 must audit).
    fn escalatable_read_only() -> SessionLevelState {
        SessionLevelState::new(OperatingLevel::Ddl, false)
    }

    fn dispatcher_with(level: SessionLevelState, auditor: Arc<Auditor>) -> OracleDispatcher {
        dispatcher_with_conn(Box::new(OneRowMock), level, auditor)
    }

    fn dispatcher_with_conn(
        conn: Box<dyn OracleConnection>,
        level: SessionLevelState,
        auditor: Arc<Auditor>,
    ) -> OracleDispatcher {
        OracleDispatcher::new_switchable(
            conn,
            Some("dev".to_owned()),
            level,
            Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
        )
        .with_auditor(auditor)
    }

    struct FailingSink;
    impl AuditSink for FailingSink {
        fn append(&self, _r: &AuditRecord) -> Result<(), AuditError> {
            Err(AuditError::Io("test audit sink failure".to_owned()))
        }
        fn flush(&self) -> Result<(), AuditError> {
            Ok(())
        }
    }

    fn failing_auditor() -> Arc<Auditor> {
        let key = SigningKey::new("test-key", b"0123456789abcdef0123456789abcdef".to_vec())
            .expect("valid test key");
        Arc::new(Auditor::new(Box::new(FailingSink), key))
    }

    fn preview_confirm_with_context(
        dispatcher: &OracleDispatcher,
        context: DispatchContext<'_>,
        sql: &str,
    ) -> String {
        dispatcher
            .dispatch_with_context(
                "oracle_preview_sql",
                json!({
                    "sql": sql,
                    "agent_identity": "attacker",
                    "operator_name": "HumanOperator",
                    "label": "spoofed",
                }),
                context,
            )
            .expect("preview")
            .pointer("/execute_confirmation/confirm")
            .and_then(Value::as_str)
            .expect("preview minted execute grant")
            .to_owned()
    }

    #[test]
    fn served_write_appends_pending_then_signed_outcome() {
        let (auditor, sink) = auditor_with_sink();
        let dispatcher = dispatcher_with(ddl_level(), auditor);
        let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
        let confirm = preview_confirm(&dispatcher, sql);
        let out = dispatcher
            .dispatch(
                "execute_approved",
                json!({ "sql": sql, "token": confirm, "commit": true }),
            )
            .expect("write dispatches");
        assert!(out.is_object());

        let recs = sink.records();
        assert_eq!(
            recs.len(),
            2,
            "a served write logs Pending then its outcome"
        );
        assert_eq!(recs[0].outcome, AuditOutcome::Pending);
        assert_eq!(recs[1].outcome, AuditOutcome::Succeeded);
        // Hash chain links pre -> post.
        assert_eq!(recs[1].prev_hash, recs[0].entry_hash);
        // Every served record is signed by the keyed MAC (not forgeable by a
        // bare recompute-from-genesis).
        assert!(recs[0].signature.is_some(), "pre record is signed");
        assert!(recs[1].signature.is_some(), "post record is signed");
        assert_eq!(recs[1].key_id.as_deref(), Some("test-key"));
        // The SQL bytes are never stored verbatim — only the digest + preview.
        assert!(recs[1].sql_sha256.starts_with("sha256:"));
    }

    #[test]
    fn caller_supplied_identity_cannot_change_audit_subject_or_db_evidence() {
        let (auditor, sink) = auditor_with_sink();
        let state = Arc::new(ExecState::default());
        let dispatcher = dispatcher_with_conn(
            Box::new(ExecRecordingMock::new(state.clone())),
            ddl_level(),
            auditor,
        );
        let context = DispatchContext::default()
            .with_http_session_id("mcp-session-1")
            .with_principal_key("oauth:subject-hash")
            .with_lane_identity("lane-1", 7);
        let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
        let confirm = preview_confirm_with_context(&dispatcher, context, sql);

        dispatcher
            .dispatch_with_context(
                "execute_approved",
                json!({
                    "token": confirm,
                    "commit": true,
                    "agent_identity": "attacker",
                    "operator_name": "HumanOperator",
                    "label": "spoofed",
                }),
                context,
            )
            .expect("write dispatches");

        let recs = sink.records();
        assert_eq!(recs.len(), 2);
        let expected_subject =
            AuditSubject::new("oauth", "subject-hash").with_authn_method("oauth");
        for rec in &recs {
            assert_eq!(rec.subject, expected_subject);
            assert_eq!(rec.agent_identity, "oauth:subject-hash");
            assert!(
                !rec.agent_identity.contains("attacker")
                    && !rec.agent_identity.contains("HumanOperator")
                    && !rec.agent_identity.contains("spoofed")
            );
            let evidence = rec.db_evidence.as_ref().expect("DB evidence captured");
            assert_eq!(evidence.availability.as_deref(), Some("captured"));
            assert_eq!(evidence.db_unique_name.as_deref(), Some("ORCL23A"));
            assert_eq!(evidence.service_name.as_deref(), Some("freepdb1"));
            assert_eq!(evidence.instance_name.as_deref(), Some("free"));
            assert_eq!(evidence.session_user.as_deref(), Some("APP"));
            assert_eq!(evidence.proxy_user.as_deref(), Some("MCP_PROXY"));
            assert_eq!(evidence.sid.as_deref(), Some("101"));
            assert_eq!(evidence.serial_number.as_deref(), Some("202"));
            assert_eq!(evidence.client_identifier.as_deref(), Some("oauth-subject"));
            assert_eq!(evidence.module.as_deref(), Some("oraclemcp-test"));
            assert_eq!(evidence.action.as_deref(), Some("execute"));
        }
    }

    #[test]
    fn served_read_is_not_audited() {
        let (auditor, sink) = auditor_with_sink();
        let dispatcher = dispatcher_with(ddl_level(), auditor);
        let _ = dispatcher
            .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
            .expect("read dispatches");
        assert!(
            sink.records().is_empty(),
            "pure reads must not touch the audit chain"
        );
    }

    #[test]
    fn session_level_escalation_is_audited() {
        let (auditor, sink) = auditor_with_sink();
        let dispatcher = dispatcher_with(escalatable_read_only(), auditor);
        // A preview mints the single-use confirmation grant; apply escalates.
        let preview = dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({ "level": "READ_WRITE", "ttl_seconds": 60 }),
            )
            .expect("preview elevation");
        let confirm = preview["confirmation"]["confirm"]
            .as_str()
            .expect("confirm grant");
        let out = dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({
                    "level": "READ_WRITE",
                    "ttl_seconds": 60,
                    "execute": true,
                    "confirm": confirm,
                }),
            )
            .expect("escalation dispatches");
        assert_eq!(out["changed"], json!(true), "escalation applied");

        let recs = sink.records();
        assert_eq!(recs.len(), 1, "a level increase logs exactly one record");
        assert_eq!(recs[0].tool, "oracle_set_session_level");
        assert_eq!(recs[0].outcome, AuditOutcome::Succeeded);
        assert!(recs[0].signature.is_some(), "escalation record is signed");
    }

    #[test]
    fn compile_object_execute_is_audited_pending_then_signed_outcome() {
        let (auditor, sink) = auditor_with_sink();
        let state = Arc::new(ExecState::default());
        let dispatcher = dispatcher_with_conn(
            Box::new(ExecRecordingMock::new(state.clone())),
            ddl_level(),
            auditor,
        );
        let preview = dispatcher
            .dispatch(
                "oracle_compile_object",
                json!({ "object_type": "PACKAGE", "name": "EMP_API" }),
            )
            .expect("compile preview");
        let confirm = preview["confirmation"]["confirm"]
            .as_str()
            .expect("confirm grant");

        let out = dispatcher
            .dispatch(
                "oracle_compile_object",
                json!({
                    "object_type": "PACKAGE",
                    "name": "EMP_API",
                    "execute": true,
                    "confirm": confirm,
                }),
            )
            .expect("compile executes");
        assert_eq!(out["compiled"], json!(true));

        let recs = sink.records();
        assert_eq!(recs.len(), 2, "compile logs Pending then outcome");
        assert_eq!(recs[0].tool, "oracle_compile_object");
        assert_eq!(recs[0].outcome, AuditOutcome::Pending);
        assert_eq!(recs[1].outcome, AuditOutcome::Succeeded);
        assert_eq!(recs[1].prev_hash, recs[0].entry_hash);
        assert!(recs[0].signature.is_some());
        assert_eq!(recs[0].sql_preview, "<sql text redacted; see sql_sha256>");
        assert!(recs[0].sql_sha256.starts_with("sha256:"));
        assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);
    }

    #[test]
    fn definite_compile_failure_has_no_prior_session_effect_and_resolves_intent() {
        let (auditor, sink) = auditor_with_sink();
        let state = Arc::new(ExecState::default());
        *state.execute_error.lock().expect("execute error mutex") = Some(DbError::Execute(
            "ORA-04043: object APP.EMP_API does not exist".to_owned(),
        ));
        let intents = write_intent_log("qa110-definite-compile-failure");
        let dispatcher = dispatcher_with_conn(
            Box::new(ExecRecordingMock::new(state.clone())),
            ddl_level(),
            auditor,
        )
        .with_write_intent_log(intents.clone());
        let preview = dispatcher
            .dispatch(
                "oracle_compile_object",
                json!({
                    "object_type": "PACKAGE",
                    "name": "EMP_API",
                    "plscope": true,
                    "warnings": true
                }),
            )
            .expect("compile preview");
        let confirm = preview["confirmation"]["confirm"]
            .as_str()
            .expect("confirm grant");

        let error = dispatcher
            .dispatch(
                "oracle_compile_object",
                json!({
                    "object_type": "PACKAGE",
                    "name": "EMP_API",
                    "plscope": true,
                    "warnings": true,
                    "execute": true,
                    "confirm": confirm,
                }),
            )
            .expect_err("definite compile failure surfaces");
        assert_eq!(error.error_class, ErrorClass::ObjectNotFound);

        let executed = state.executed.lock().expect("exec mutex");
        assert_eq!(executed.len(), 1, "compile performs one database effect");
        assert_eq!(
            executed[0].0,
            "ALTER PACKAGE APP.EMP_API COMPILE PLSQL_WARNINGS = 'ENABLE:ALL' PLSCOPE_SETTINGS = 'IDENTIFIERS:ALL, STATEMENTS:ALL' REUSE SETTINGS"
        );
        assert!(!executed[0].0.contains("ALTER SESSION"));
        drop(executed);

        let recs = sink.records();
        assert_eq!(recs.len(), 2, "compile logs Pending then Failed");
        assert_eq!(recs[0].outcome, AuditOutcome::Pending);
        assert_eq!(recs[1].outcome, AuditOutcome::Failed);
        assert_eq!(recs[1].prev_hash, recs[0].entry_hash);
        assert!(
            intents.unresolved().expect("intent snapshot").is_empty(),
            "a definite one-statement failure is safe to resolve"
        );
        let ledger = std::fs::read_to_string(intents.path().expect("intent path"))
            .expect("intent ledger is readable");
        assert!(ledger.contains("\"outcome\":\"FAILED\""), "{ledger}");
        assert!(
            dispatcher
                .connection_quarantine()
                .expect("quarantine lock")
                .is_none(),
            "a definite failure with no earlier session effect remains reusable"
        );
        dispatcher
            .dispatch("oracle_connection_info", json!({}))
            .expect("connection remains usable after the definite failure");
    }

    #[test]
    fn patch_source_execute_is_audited_pending_then_signed_outcome() {
        let (auditor, sink) = auditor_with_sink();
        let state = Arc::new(ExecState::default());
        let dispatcher = dispatcher_with_conn(
            Box::new(ExecRecordingMock::new(state.clone())),
            ddl_level(),
            auditor,
        );
        let preview_args = json!({
            "owner": "APP",
            "name": "EMP_API",
            "object_type": "PACKAGE_BODY",
            "old_text": "NULL",
            "new_text": "1",
        });
        let preview = dispatcher
            .dispatch("oracle_patch_source", preview_args.clone())
            .expect("patch preview");
        let confirm = preview["confirmation"]["confirm"]
            .as_str()
            .expect("confirm grant")
            .to_owned();
        let mut execute_args = preview_args;
        execute_args["execute"] = json!(true);
        execute_args["confirm"] = json!(confirm);

        let out = dispatcher
            .dispatch("oracle_patch_source", execute_args)
            .expect("patch executes");
        assert_eq!(out["applied"], json!(true));

        let recs = sink.records();
        assert_eq!(recs.len(), 2, "patch logs Pending then outcome");
        assert_eq!(recs[0].tool, "oracle_patch_source");
        assert_eq!(recs[0].outcome, AuditOutcome::Pending);
        assert_eq!(recs[1].outcome, AuditOutcome::Succeeded);
        assert_eq!(recs[1].prev_hash, recs[0].entry_hash);
        assert!(recs[0].signature.is_some());
        assert_eq!(recs[0].sql_preview, "<sql text redacted; see sql_sha256>");
        assert!(recs[0].sql_sha256.starts_with("sha256:"));
        assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);
    }

    #[test]
    fn audit_write_failure_refuses_compile_before_db_execute() {
        let state = Arc::new(ExecState::default());
        let dispatcher = dispatcher_with_conn(
            Box::new(ExecRecordingMock::new(state.clone())),
            ddl_level(),
            failing_auditor(),
        );
        let preview = dispatcher
            .dispatch(
                "oracle_compile_object",
                json!({ "object_type": "PACKAGE", "name": "EMP_API" }),
            )
            .expect("compile preview");
        let confirm = preview["confirmation"]["confirm"]
            .as_str()
            .expect("confirm grant");

        let err = dispatcher
            .dispatch(
                "oracle_compile_object",
                json!({
                    "object_type": "PACKAGE",
                    "name": "EMP_API",
                    "execute": true,
                    "confirm": confirm,
                }),
            )
            .expect_err("audit failure refuses compile");
        assert_eq!(err.error_class, ErrorClass::Internal);
        assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
    }

    #[test]
    fn audit_write_failure_refuses_patch_before_db_execute() {
        let state = Arc::new(ExecState::default());
        let dispatcher = dispatcher_with_conn(
            Box::new(ExecRecordingMock::new(state.clone())),
            ddl_level(),
            failing_auditor(),
        );
        let preview_args = json!({
            "owner": "APP",
            "name": "EMP_API",
            "object_type": "PACKAGE_BODY",
            "old_text": "NULL",
            "new_text": "1",
        });
        let preview = dispatcher
            .dispatch("oracle_patch_source", preview_args.clone())
            .expect("patch preview");
        let confirm = preview["confirmation"]["confirm"]
            .as_str()
            .expect("confirm grant")
            .to_owned();
        let mut execute_args = preview_args;
        execute_args["execute"] = json!(true);
        execute_args["confirm"] = json!(confirm);

        let err = dispatcher
            .dispatch("oracle_patch_source", execute_args)
            .expect_err("audit failure refuses patch");
        assert_eq!(err.error_class, ErrorClass::Internal);
        assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
    }
}

/// C8: `oracle_top_queries` surfaces the existing awr.rs builder as a served,
/// read-only tool. The free live cursor cache (V$SQLSTATS) is the default; the
/// licensed AWR path is opt-in and gated (proven in awr.rs unit tests).
mod top_queries {
    use super::*;
    use std::sync::Arc;

    struct CancelledLicenseProbeMock {
        queries: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for CancelledLicenseProbeMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo {
                current_schema: Some("APP".to_owned()),
                ..Default::default()
            })
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.queries.fetch_add(1, Ordering::SeqCst);
            Err(DbError::Cancelled(
                "injected Diagnostics Pack probe cancellation".to_owned(),
            ))
        }

        async fn execute(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            Ok(0)
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    fn dispatcher() -> OracleDispatcher {
        OracleDispatcher::new_switchable(
            Box::new(OneRowMock),
            Some("dev".to_owned()),
            read_write_level(),
            Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
        )
    }

    #[test]
    fn live_source_is_the_default_and_returns_ranked_rows() {
        let out = dispatcher()
            .dispatch("oracle_top_queries", json!({ "metric": "cpu", "top_n": 3 }))
            .expect("top_queries dispatches");
        // Free live cursor cache, no Diagnostics Pack needed.
        assert_eq!(out["source"], json!("live_cursor"));
        assert_eq!(out["metric"], json!("cpu"));
        assert!(out["rows"].is_array(), "returns ranked rows");
    }

    #[test]
    fn unknown_metric_is_rejected_with_a_clear_error() {
        let err = dispatcher()
            .dispatch("oracle_top_queries", json!({ "metric": "bogus" }))
            .expect_err("unknown metric is rejected");
        assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    }

    #[test]
    fn five_pct_of_total_mode_is_accepted_on_the_live_source() {
        let out = dispatcher()
            .dispatch("oracle_top_queries", json!({ "min_pct_of_total": 5 }))
            .expect("5%-of-total dispatches");
        assert_eq!(out["source"], json!("live_cursor"));
        assert!(out["rows"].is_array());
    }

    #[test]
    fn uncertain_historical_probe_stops_fallback_and_quarantines_pinned_session() {
        let queries = Arc::new(AtomicUsize::new(0));
        let dispatcher = OracleDispatcher::new_with_profile(
            Box::new(CancelledLicenseProbeMock {
                queries: Arc::clone(&queries),
            }),
            Some("dev".to_owned()),
        );

        let error = dispatcher
            .dispatch("oracle_top_queries", json!({ "historical": true }))
            .expect_err("uncertain license probe must stop source resolution");
        assert_eq!(error.error_class, ErrorClass::Timeout);
        assert_eq!(
            queries.load(Ordering::SeqCst),
            1,
            "Statspack must not be probed after connection uncertainty"
        );
        assert_eq!(
            dispatcher
                .connection_quarantine()
                .expect("quarantine lock")
                .expect("uncertain pinned probe quarantines")
                .outcome,
            AuditOutcome::UnknownDiscarded
        );

        let retry = dispatcher
            .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
            .expect_err("quarantined pinned session cannot be reused");
        assert_eq!(retry.error_class, ErrorClass::RuntimeStateRequired);
        assert_eq!(queries.load(Ordering::SeqCst), 1);
    }
}

/// C1–C7: the read-only `oracle_db_health` suite. The framework dispatches the
/// requested subchecks, aggregates findings tagged with severity + source view,
/// and — per C1's load-bearing AC — never lets a missing privilege become a raw
/// ORA-/hard failure: it degrades DBA_*→ALL_*, then yields a structured skip.
mod db_health {
    use super::*;
    use std::sync::Arc;

    /// A mock that fails every query (no DBA_* and no ALL_* access) so every
    /// subcheck must degrade to a structured skip.
    struct NoPrivilegeMock;
    #[async_trait::async_trait(?Send)]
    impl OracleConnection for NoPrivilegeMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo {
                current_schema: Some("APP".to_owned()),
                ..Default::default()
            })
        }
        async fn query_rows(
            &self,
            _cx: &Cx,
            _sql: &str,
            _b: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            Err(DbError::Query(
                "ORA-00942: table or view does not exist".to_owned(),
            ))
        }
        async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
            Ok(0)
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    fn dispatcher_with(conn: impl OracleConnection + 'static) -> OracleDispatcher {
        OracleDispatcher::new_switchable(
            Box::new(conn),
            Some("dev".to_owned()),
            read_write_level(),
            Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
        )
    }

    #[test]
    fn all_runs_every_subcheck_and_returns_findings() {
        // OneRowMock answers any query, so every probe + subcheck succeeds.
        let out = dispatcher_with(OneRowMock)
            .dispatch("oracle_db_health", json!({ "health_type": "all" }))
            .expect("db_health dispatches");
        let findings = out["findings"].as_array().expect("findings array");
        assert_eq!(findings.len(), 6, "all six subchecks produce a finding");
        // Every finding carries a subcheck, severity, and source_view.
        for f in findings {
            assert!(f["subcheck"].is_string());
            assert!(f["severity"].is_string());
            assert!(f["source_view"].is_string());
        }
        assert_eq!(
            out["checks_run"].as_array().expect("checks_run").len(),
            6,
            "nothing skipped when the views are readable"
        );
        assert!(
            out["checks_skipped"]
                .as_array()
                .expect("checks_skipped")
                .is_empty()
        );
        assert!(
            out["unknown_checks"]
                .as_array()
                .expect("unknown")
                .is_empty()
        );
    }

    #[test]
    fn comma_list_runs_only_the_requested_subchecks() {
        let out = dispatcher_with(OneRowMock)
            .dispatch(
                "oracle_db_health",
                json!({ "health_type": "invalid_objects, sequence_ceiling" }),
            )
            .expect("db_health dispatches");
        let run: Vec<&str> = out["checks_run"]
            .as_array()
            .expect("checks_run")
            .iter()
            .map(|v| v.as_str().expect("name"))
            .collect();
        assert_eq!(run, vec!["invalid_objects", "sequence_ceiling"]);
    }

    #[test]
    fn unknown_subcheck_is_reported_not_fatal() {
        let out = dispatcher_with(OneRowMock)
            .dispatch(
                "oracle_db_health",
                json!({ "health_type": "invalid_objects, not_a_real_check" }),
            )
            .expect("db_health tolerates an unknown subcheck");
        assert_eq!(out["checks_run"], json!(["invalid_objects"]));
        assert_eq!(out["unknown_checks"], json!(["not_a_real_check"]));
    }

    #[test]
    fn missing_privilege_yields_a_structured_skip_never_an_error() {
        // No DBA_* and no ALL_* access: the whole suite must still succeed,
        // every subcheck reported as a structured skip (never a raw ORA-).
        let out = dispatcher_with(NoPrivilegeMock)
            .dispatch("oracle_db_health", json!({ "health_type": "all" }))
            .expect("db_health never hard-fails on privilege");
        assert!(
            out["checks_run"].as_array().expect("checks_run").is_empty(),
            "no subcheck could read its view"
        );
        assert_eq!(
            out["checks_skipped"]
                .as_array()
                .expect("checks_skipped")
                .len(),
            6,
            "every subcheck degraded to a skip"
        );
        let findings = out["findings"].as_array().expect("findings");
        for f in findings {
            assert_eq!(f["detail"]["status"], json!("skipped"));
            assert_eq!(f["severity"], json!("info"));
            // Structured skip carries the views it tried, not a raw ORA- bubble.
            assert!(f["detail"]["attempted_views"].is_array());
            assert!(
                !f["summary"].as_str().unwrap_or("").contains("ORA-"),
                "skip summary must not surface a raw ORA- error"
            );
        }
    }
}

/// A1 (oraclemcp-040-epic-wp-a-ia1.1): the lazy read-only backstop, exercised
/// END TO END through the real dispatch path (not just the unit-tested
/// `ReadOnlyBackstop` primitive). These prove the backstop is WIRED into
/// `oracle_query`/`oracle_execute` on the pinned session: armed lazily on the
/// read path, disarmed by a gated write so an authorized write is never blocked,
/// and re-asserted on the next read transaction.
mod read_only_backstop_wiring {
    use super::*;
    use oraclemcp_guard::SET_TRANSACTION_READ_ONLY;

    /// Records every `execute` (so the backstop statement is observable) and
    /// returns rows for `query_rows` (so a `oracle_query` succeeds). The execute
    /// log lets a test assert the backstop is issued lazily and at the right
    /// transaction boundaries through the real dispatcher.
    #[derive(Default)]
    struct BackstopRecordingState {
        executed: Mutex<Vec<String>>,
        events: Mutex<Vec<String>>,
        read_only_transaction: AtomicBool,
        fail_next_rollback: AtomicBool,
    }

    struct BackstopRecordingMock {
        state: Arc<BackstopRecordingState>,
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for BackstopRecordingMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo {
                current_schema: Some("APP".to_owned()),
                ..Default::default()
            })
        }
        async fn query_rows(
            &self,
            _cx: &Cx,
            sql: &str,
            binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            if let Some(rows) = mock_plain_table_dictionary(sql, binds) {
                return Ok(rows);
            }
            Ok(vec![OracleRow {
                columns: vec![(
                    "N".to_owned(),
                    OracleCell::new("NUMBER", Some("1".to_owned())),
                )],
            }])
        }
        async fn query_rows_with_serialize_options(
            &self,
            cx: &Cx,
            sql: &str,
            b: &[OracleBind],
            _opts: &SerializeOptions,
        ) -> Result<Vec<OracleRow>, DbError> {
            self.query_rows(cx, sql, b).await
        }
        async fn execute(&self, _cx: &Cx, sql: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
            self.state
                .executed
                .lock()
                .expect("exec mutex")
                .push(sql.to_owned());
            self.state
                .events
                .lock()
                .expect("events mutex")
                .push(sql.to_owned());
            if sql == SET_TRANSACTION_READ_ONLY {
                self.state
                    .read_only_transaction
                    .store(true, Ordering::SeqCst);
            } else if self.state.read_only_transaction.load(Ordering::SeqCst)
                && DEFAULT_CLASSIFIER
                    .classify(sql)
                    .required_level
                    .is_some_and(|level| level >= OperatingLevel::ReadWrite)
            {
                return Err(DbError::Execute(
                    "ORA-01456: may not perform insert/delete/update operation inside a READ ONLY transaction"
                        .to_owned(),
                ));
            }
            Ok(0)
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            self.state
                .events
                .lock()
                .expect("events mutex")
                .push("ROLLBACK".to_owned());
            if self.state.fail_next_rollback.swap(false, Ordering::SeqCst) {
                return Err(DbError::Cancelled(
                    "injected read-only transition rollback failure".to_owned(),
                ));
            }
            self.state
                .read_only_transaction
                .store(false, Ordering::SeqCst);
            Ok(())
        }
    }

    fn elevate_session(dispatcher: &OracleDispatcher, level: &str) {
        let preview = dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({ "level": level, "ttl_seconds": 60 }),
            )
            .expect("elevation preview");
        let confirm = preview["confirmation"]["confirm"]
            .as_str()
            .expect("elevation confirmation")
            .to_owned();
        dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({
                    "level": level,
                    "ttl_seconds": 60,
                    "execute": true,
                    "confirm": confirm,
                }),
            )
            .expect("confirmed elevation");
    }

    fn backstop_statements(state: &Arc<BackstopRecordingState>) -> usize {
        state
            .executed
            .lock()
            .expect("exec mutex")
            .iter()
            .filter(|sql| sql.as_str() == SET_TRANSACTION_READ_ONLY)
            .count()
    }

    #[test]
    fn generated_dictionary_reads_arm_backstop_and_audit_as_system() {
        use oraclemcp_audit::{
            AuditError, AuditOutcome, AuditRecord, AuditSink, AuditSubject, MemoryAuditSink,
            SigningKey,
        };

        struct SharedSink(Arc<MemoryAuditSink>);
        impl AuditSink for SharedSink {
            fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
                self.0.append(record)
            }

            fn flush(&self) -> Result<(), AuditError> {
                self.0.flush()
            }
        }

        let state = Arc::new(BackstopRecordingState::default());
        let sink = Arc::new(MemoryAuditSink::new());
        let auditor = Arc::new(Auditor::new(
            Box::new(SharedSink(sink.clone())),
            SigningKey::new("test-key", b"generated-read-audit-test-key-123".to_vec())
                .expect("valid test key"),
        ));
        let dispatcher = OracleDispatcher::new_with_profile(
            Box::new(BackstopRecordingMock {
                state: state.clone(),
            }),
            Some("dev".to_owned()),
        )
        .with_auditor(auditor);

        dispatcher
            .dispatch("oracle_list_schemas", json!({ "limit": 5 }))
            .expect("generated dictionary read succeeds");

        assert_eq!(
            backstop_statements(&state),
            1,
            "generated reads on the pinned session assert SET TRANSACTION READ ONLY"
        );
        let records = sink.records();
        assert_eq!(records.len(), 2, "pending + succeeded audit records");
        let subject = AuditSubject::new("system", "generated-read").with_authn_method("server");
        assert_eq!(records[0].subject, subject);
        assert_eq!(records[1].subject, subject);
        assert_eq!(records[0].tool, "oracle_list_schemas");
        assert_eq!(records[1].tool, "oracle_list_schemas");
        assert_eq!(records[0].danger_level, "SAFE");
        assert_eq!(records[1].danger_level, "SAFE");
        assert_eq!(records[0].outcome, AuditOutcome::Pending);
        assert_eq!(records[1].outcome, AuditOutcome::Succeeded);
        assert_eq!(
            records[0].sql_preview,
            "<sql text redacted; see sql_sha256>"
        );
        assert!(records[0].sql_sha256.starts_with("sha256:"));
        assert!(records[0].hash_is_valid());
        assert!(records[1].hash_is_valid());
    }

    #[test]
    fn read_path_arms_set_transaction_read_only_lazily_once() {
        // Three oracle_query calls on a READ_ONLY session: the backstop is
        // asserted exactly once (lazy), not once per read.
        let state = Arc::new(BackstopRecordingState::default());
        let dispatcher = OracleDispatcher::new_with_profile(
            Box::new(BackstopRecordingMock {
                state: state.clone(),
            }),
            Some("dev".to_owned()),
        );
        for _ in 0..3 {
            dispatcher
                .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
                .expect("read succeeds under the backstop");
        }
        assert_eq!(
            backstop_statements(&state),
            1,
            "SET TRANSACTION READ ONLY is issued exactly once across many reads (lazy)"
        );
    }

    #[test]
    fn gated_write_disarms_then_next_read_re_asserts() {
        // READ_WRITE session. A read arms the backstop; a gated UPDATE
        // (commit=true) disarms it BEFORE it runs so the write is not blocked;
        // the next read re-asserts the backstop on the fresh transaction.
        let state = Arc::new(BackstopRecordingState::default());
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(BackstopRecordingMock {
                state: state.clone(),
            }),
            Some("dev".to_owned()),
            read_write_level(),
        );
        // A read at READ_WRITE does NOT arm the backstop (a write may be
        // authorized); prove the read path is a no-op above READ_ONLY.
        dispatcher
            .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
            .expect("read at read/write");
        assert_eq!(
            backstop_statements(&state),
            0,
            "no SET TRANSACTION READ ONLY at READ_WRITE — a legitimate write must not be blocked"
        );

        // A gated write that commits — must succeed (not refused by the backstop)
        // and the executed log must NOT contain a SET TRANSACTION READ ONLY
        // immediately gating it.
        let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
        let confirm = preview_confirm(&dispatcher, sql);
        let out = dispatcher
            .dispatch(
                "oracle_execute",
                json!({ "sql": sql, "commit": true, "confirm": confirm }),
            )
            .expect("gated write is not blocked by the read-only backstop");
        assert_eq!(out["executed"], json!(true));
        assert_eq!(out["committed"], json!(true));
        assert_eq!(
            backstop_statements(&state),
            0,
            "the authorized write path never issues SET TRANSACTION READ ONLY"
        );
    }

    #[test]
    fn read_then_elevate_then_governed_dml_rolls_back_read_only_transaction_first() {
        let state = Arc::new(BackstopRecordingState::default());
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(BackstopRecordingMock {
                state: state.clone(),
            }),
            Some("dev".to_owned()),
            SessionLevelState::new(OperatingLevel::ReadWrite, false),
        );

        dispatcher
            .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
            .expect("read arms a real read-only transaction");
        assert!(state.read_only_transaction.load(Ordering::SeqCst));

        elevate_session(&dispatcher, "READ_WRITE");
        let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
        let out = dispatcher
            .dispatch("oracle_execute", json!({ "sql": sql }))
            .expect("rollback-by-default DML runs after ending the read-only transaction");
        assert_eq!(out["executed"], json!(true));
        assert_eq!(out["committed"], json!(false));
        assert!(!state.read_only_transaction.load(Ordering::SeqCst));

        let events = state.events.lock().expect("events mutex").clone();
        let write = events
            .iter()
            .position(|event| event.contains("UPDATE employees"))
            .expect("governed DML reached the mock");
        assert_eq!(
            events.get(write.wrapping_sub(1)).map(String::as_str),
            Some("ROLLBACK"),
            "the real Oracle transaction boundary must precede the governed DML"
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.as_str() == "ROLLBACK")
                .count(),
            3,
            "one reset arms the backstop, one clears it before DML, and rollback-by-default cleans up the DML"
        );
    }

    #[test]
    fn failed_transition_rollback_prevents_write_and_quarantines_session() {
        let state = Arc::new(BackstopRecordingState::default());
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(BackstopRecordingMock {
                state: state.clone(),
            }),
            Some("dev".to_owned()),
            SessionLevelState::new(OperatingLevel::ReadWrite, false),
        );
        dispatcher
            .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
            .expect("read arms a real read-only transaction");
        elevate_session(&dispatcher, "READ_WRITE");
        state.fail_next_rollback.store(true, Ordering::SeqCst);

        let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
        let error = dispatcher
            .dispatch("oracle_execute", json!({ "sql": sql }))
            .expect_err("an uncertain transition rollback must fail before execute");
        assert_eq!(error.error_class, ErrorClass::ConnectionFailed);
        assert!(
            error
                .message
                .contains("approved statement was not executed"),
            "{error:?}"
        );
        assert!(
            state
                .executed
                .lock()
                .expect("exec mutex")
                .iter()
                .all(|statement| !statement.contains("UPDATE employees")),
            "governed DML must not reach Oracle after transition rollback failure"
        );
        assert!(
            state.read_only_transaction.load(Ordering::SeqCst),
            "a failed rollback must not claim the read-only transaction was cleared"
        );
        let quarantine = dispatcher
            .connection_quarantine()
            .expect("quarantine lock")
            .expect("rollback failure quarantines");
        assert_eq!(quarantine.outcome, AuditOutcome::UnknownDiscarded);

        let retry = dispatcher
            .dispatch("oracle_execute", json!({ "sql": sql }))
            .expect_err("the quarantined pinned session must not be reused");
        assert_eq!(retry.error_class, ErrorClass::RuntimeStateRequired);
    }

    #[test]
    fn ddl_preview_preserves_backstop_and_confirmed_compile_clears_it_before_effect() {
        let state = Arc::new(BackstopRecordingState::default());
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(BackstopRecordingMock {
                state: state.clone(),
            }),
            Some("dev".to_owned()),
            SessionLevelState::new(OperatingLevel::Ddl, false),
        );
        dispatcher
            .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
            .expect("read arms a real read-only transaction");
        elevate_session(&dispatcher, "DDL");

        let preview = dispatcher
            .dispatch(
                "oracle_compile_object",
                json!({ "object_type": "PACKAGE", "name": "EMP_API" }),
            )
            .expect("compile preview");
        assert!(state.read_only_transaction.load(Ordering::SeqCst));
        assert_eq!(
            state
                .events
                .lock()
                .expect("events mutex")
                .iter()
                .filter(|event| event.as_str() == "ROLLBACK")
                .count(),
            1,
            "preview-only work must preserve the armed transaction"
        );
        let confirm = preview["confirmation"]["confirm"]
            .as_str()
            .expect("compile confirmation")
            .to_owned();
        dispatcher
            .dispatch(
                "oracle_compile_object",
                json!({
                    "object_type": "PACKAGE",
                    "name": "EMP_API",
                    "execute": true,
                    "confirm": confirm,
                }),
            )
            .expect("confirmed compile runs after the transaction transition");

        let events = state.events.lock().expect("events mutex").clone();
        let ddl = events
            .iter()
            .position(|event| event.contains("ALTER PACKAGE"))
            .expect("compile DDL reached the mock");
        assert_eq!(
            events.get(ddl.wrapping_sub(1)).map(String::as_str),
            Some("ROLLBACK"),
            "the real transaction boundary must precede confirmed DDL"
        );
    }

    #[test]
    fn read_only_session_write_attempt_is_classifier_blocked_with_backstop_set() {
        // Defense-in-depth contract: on a READ_ONLY session a read arms the
        // backstop; an attempted write via oracle_execute is refused by the
        // CLASSIFIER (layer C) before it reaches the DB, while the backstop
        // (layer B) is already set so even a misclassified write would raise
        // ORA-01456 at the engine. (A real ORA-01456 is asserted by the live-xe
        // test; offline we assert the layered posture deterministically.)
        let state = Arc::new(BackstopRecordingState::default());
        let dispatcher = OracleDispatcher::new_with_profile(
            Box::new(BackstopRecordingMock {
                state: state.clone(),
            }),
            Some("dev".to_owned()),
        );
        dispatcher
            .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
            .expect("read arms the backstop");
        assert_eq!(
            backstop_statements(&state),
            1,
            "backstop set on the read path"
        );

        let err = dispatcher
            .dispatch(
                "oracle_execute",
                json!({ "sql": "UPDATE employees SET name = name WHERE employee_id = 100" }),
            )
            .expect_err("a write on a READ_ONLY session is refused");
        assert!(
            matches!(
                err.error_class,
                ErrorClass::OperatingLevelTooLow | ErrorClass::ForbiddenStatement
            ),
            "write refused by the operating-level gate, not silently run: {:?}",
            err.error_class
        );
        assert!(state.read_only_transaction.load(Ordering::SeqCst));
        assert_eq!(
            state
                .events
                .lock()
                .expect("events mutex")
                .iter()
                .filter(|event| event.as_str() == "ROLLBACK")
                .count(),
            1,
            "a refused write must not end the armed read-only transaction"
        );
    }

    #[test]
    fn profile_switch_resets_the_backstop_so_the_new_session_re_asserts() {
        // After a profile switch the pinned session is replaced; the new
        // session's first read must re-assert the backstop on its own
        // transaction.
        let first = Arc::new(BackstopRecordingState::default());
        let second = Arc::new(BackstopRecordingState::default());
        let second_for_connector = second.clone();
        let dispatcher = OracleDispatcher::new_switchable(
            Box::new(BackstopRecordingMock {
                state: first.clone(),
            }),
            Some("dev".to_owned()),
            default_read_only_level(),
            Arc::new(move |_cx, _profile| {
                let state = second_for_connector.clone();
                Box::pin(async move { Ok(session_bundle(BackstopRecordingMock { state })) })
            }),
        );
        // Arm on the first session.
        dispatcher
            .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
            .expect("read on first session");
        assert_eq!(backstop_statements(&first), 1);

        // Switch profiles (replaces the pinned session, resets the backstop).
        dispatcher
            .dispatch("oracle_switch_profile", json!({ "profile": "other" }))
            .expect("switch profile");

        // The new session's first read re-asserts on its own transaction.
        dispatcher
            .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
            .expect("read on second session");
        assert_eq!(
            backstop_statements(&second),
            1,
            "the new pinned session re-asserts SET TRANSACTION READ ONLY on its first read"
        );
    }
}

// ===================================================================
// K10 — streaming query results (incremental fetch + chunked delivery)
// ===================================================================

/// A read mock that HONORS the `OFFSET n ROWS FETCH NEXT m ROWS ONLY` envelope
/// the server wraps around a proven SELECT, so a streamed/resumed page returns
/// the true next window of a fixed dataset. This lets the dispatcher's streaming
/// path be proven byte-identical to a single full read.
struct StreamOffsetMock {
    total: usize,
}

impl StreamOffsetMock {
    fn window(sql: &str) -> (usize, usize) {
        let after = |marker: &str| -> Option<usize> {
            let idx = sql.find(marker)? + marker.len();
            sql[idx..]
                .split_whitespace()
                .next()
                .and_then(|tok| tok.parse::<usize>().ok())
        };
        (
            after("OFFSET ").unwrap_or(0),
            after("FETCH NEXT ").unwrap_or(usize::MAX),
        )
    }
}

fn stream_offset_row(i: usize) -> OracleRow {
    OracleRow {
        columns: vec![
            (
                "ID".to_owned(),
                OracleCell::new("NUMBER", Some(format!("{}", i * 11 + 3))),
            ),
            (
                "NAME".to_owned(),
                OracleCell::new("VARCHAR2", Some(format!("row-{i}"))),
            ),
        ],
    }
}

struct RowStreamMock {
    total: usize,
    stream_opens: Arc<AtomicUsize>,
    stream_recovers: Arc<AtomicUsize>,
}

impl RowStreamMock {
    fn rows(&self, sql: &str) -> Vec<OracleRow> {
        let (offset, fetch) = StreamOffsetMock::window(sql);
        let end = offset.saturating_add(fetch).min(self.total);
        let start = offset.min(self.total);
        (start..end).map(stream_offset_row).collect()
    }
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for RowStreamMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo {
            current_schema: Some("APP".to_owned()),
            ..Default::default()
        })
    }
    async fn query_rows(
        &self,
        _cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        if let Some(rows) = mock_plain_table_dictionary(sql, binds) {
            return Ok(rows);
        }
        Ok(self.rows(sql))
    }
    async fn query_row_stream(
        &self,
        _cx: &Cx,
        sql: &str,
        _binds: &[OracleBind],
        _arraysize: usize,
        _serialize_opts: &SerializeOptions,
    ) -> Result<QueryRowStreamStart, DbError> {
        self.stream_opens.fetch_add(1, Ordering::SeqCst);
        Ok(QueryRowStreamStart::Stream(
            QueryRowStream::from_static_rows_for_testing(
                vec!["ID".to_owned(), "NAME".to_owned()],
                self.rows(sql),
                Some(Arc::clone(&self.stream_recovers)),
            ),
        ))
    }
    async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
        Ok(0)
    }
    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for StreamOffsetMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo {
            current_schema: Some("APP".to_owned()),
            ..Default::default()
        })
    }
    async fn query_rows(
        &self,
        _cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        if let Some(rows) = mock_plain_table_dictionary(sql, binds) {
            return Ok(rows);
        }
        let (offset, fetch) = Self::window(sql);
        let end = offset.saturating_add(fetch).min(self.total);
        let start = offset.min(self.total);
        Ok((start..end).map(stream_offset_row).collect())
    }
    async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
        Ok(0)
    }
    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

#[test]
fn row_streaming_dispatch_emits_one_sse_frame_per_row_byte_identically() {
    let stream_opens = Arc::new(AtomicUsize::new(0));
    let stream_recovers = Arc::new(AtomicUsize::new(0));
    let dispatcher = OracleDispatcher::new_with_profile(
        Box::new(RowStreamMock {
            total: 4,
            stream_opens: Arc::clone(&stream_opens),
            stream_recovers: Arc::clone(&stream_recovers),
        }),
        Some("dev".to_owned()),
    );
    let full = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT id, name FROM t", "max_rows": 1000 }),
        )
        .expect("full read");
    let full_rows = full["rows"].as_array().expect("rows").clone();

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("asupersync test runtime builds");
    let (outcome, frames) = runtime.block_on(async {
        let cx = Cx::current().expect("block_on installs a current Cx");
        let (frames_tx, mut frames_rx) = mpsc::channel(8);
        let outcome = dispatcher
            .dispatch_stream(
                &cx,
                DispatchContext::default(),
                "oracle_query",
                json!({ "sql": "SELECT id, name FROM t", "streaming": true, "max_rows": 2 }),
                frames_tx,
            )
            .await;
        let mut frames = Vec::new();
        while let Ok(frame) = frames_rx.recv(&cx).await {
            frames.push(frame);
        }
        (outcome, frames)
    });
    let final_value = match outcome {
        Outcome::Ok(value) => value,
        other => panic!("streaming dispatch should succeed, got {other:?}"),
    };
    assert_eq!(final_value["streaming"], json!(true));
    assert_eq!(final_value["streaming_mode"], json!("rows"));
    assert_eq!(final_value["row_count"], json!(4));
    assert_eq!(stream_opens.load(Ordering::SeqCst), 1);
    assert_eq!(stream_recovers.load(Ordering::SeqCst), 1);

    let mut streamed_rows = Vec::new();
    for (idx, frame) in frames.into_iter().enumerate() {
        match frame {
            ToolStreamFrame::Row { seq, row } => {
                assert_eq!(seq, idx as u64);
                streamed_rows.push(row);
            }
            other => panic!("row streaming emitted unexpected frame: {other:?}"),
        }
    }
    assert_eq!(
        streamed_rows, full_rows,
        "row frames concatenate byte-identically to a full eager read"
    );
}

#[test]
fn streaming_write_refusal_opens_zero_row_streams() {
    let stream_opens = Arc::new(AtomicUsize::new(0));
    let dispatcher = OracleDispatcher::new_with_profile(
        Box::new(RowStreamMock {
            total: 4,
            stream_opens: Arc::clone(&stream_opens),
            stream_recovers: Arc::new(AtomicUsize::new(0)),
        }),
        Some("dev".to_owned()),
    );
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("asupersync test runtime builds");
    let outcome = runtime.block_on(async {
        let cx = Cx::current().expect("block_on installs a current Cx");
        let (frames_tx, _frames_rx) = mpsc::channel(4);
        dispatcher
            .dispatch_stream(
                &cx,
                DispatchContext::default(),
                "oracle_query",
                json!({ "sql": "DELETE FROM t", "streaming": true }),
                frames_tx,
            )
            .await
    });
    match outcome {
        Outcome::Err(err) => assert_eq!(err.error_class, ErrorClass::OperatingLevelTooLow),
        other => panic!("streaming write should be refused, got {other:?}"),
    }
    assert_eq!(
        stream_opens.load(Ordering::SeqCst),
        0,
        "the read-only guard must refuse DELETE before opening a row stream"
    );
}

#[test]
fn row_streaming_recovers_when_receiver_disconnects_under_backpressure() {
    let stream_opens = Arc::new(AtomicUsize::new(0));
    let stream_recovers = Arc::new(AtomicUsize::new(0));
    let dispatcher = OracleDispatcher::new_with_profile(
        Box::new(RowStreamMock {
            total: 3,
            stream_opens: Arc::clone(&stream_opens),
            stream_recovers: Arc::clone(&stream_recovers),
        }),
        Some("dev".to_owned()),
    );
    let (frames_tx, mut frames_rx) = mpsc::channel(1);
    let (done_tx, done_rx) = std_mpsc::channel();
    let join = std::thread::spawn(move || {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("asupersync test runtime builds");
        let outcome = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            dispatcher
                .dispatch_stream(
                    &cx,
                    DispatchContext::default(),
                    "oracle_query",
                    json!({ "sql": "SELECT id, name FROM t", "streaming": true, "max_rows": 2 }),
                    frames_tx,
                )
                .await
        });
        let _ = done_tx.send(outcome);
    });

    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("asupersync test runtime builds");
    runtime.block_on(async {
        let cx = Cx::current().expect("block_on installs a current Cx");
        let first = frames_rx.recv(&cx).await.expect("first row frame");
        assert!(matches!(first, ToolStreamFrame::Row { seq: 0, .. }));
    });
    drop(frames_rx);

    let outcome = done_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("bounded sender should unblock when receiver disconnects");
    join.join().expect("streaming dispatch thread joined");
    match outcome {
        Outcome::Err(err) => assert_eq!(err.error_class, ErrorClass::Timeout),
        other => panic!("disconnect should end with a timeout-class tool error, got {other:?}"),
    }
    assert_eq!(stream_opens.load(Ordering::SeqCst), 1);
    assert_eq!(
        stream_recovers.load(Ordering::SeqCst),
        1,
        "disconnect must recover the owned row stream before returning"
    );
}

#[test]
fn streaming_query_delivers_chunks_byte_identical_to_a_full_read() {
    // Full (non-streaming) read of all 23 rows in one page.
    let full_dispatcher = OracleDispatcher::new_with_profile(
        Box::new(StreamOffsetMock { total: 23 }),
        Some("dev".to_owned()),
    );
    let full = full_dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT id, name FROM t", "max_rows": 1000 }),
        )
        .expect("full read");
    let full_rows = full["rows"].as_array().expect("rows array").clone();
    assert_eq!(full_rows.len(), 23);
    assert_eq!(full["truncated"], json!(false));

    // Streaming read: 5-row pages -> 5 chunks (5,5,5,5,3).
    let dispatcher = OracleDispatcher::new_with_profile(
        Box::new(StreamOffsetMock { total: 23 }),
        Some("dev".to_owned()),
    );
    let streamed = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT id, name FROM t", "streaming": true, "max_rows": 5 }),
        )
        .expect("streaming read");
    assert_eq!(streamed["streaming"], json!(true));
    assert_eq!(streamed["columns"], json!(["ID", "NAME"]));
    assert_eq!(streamed["row_count"], json!(23));
    assert_eq!(streamed["truncated"], json!(false));
    assert_eq!(streamed["next_cursor"], Value::Null);

    let chunks = streamed["chunks"].as_array().expect("chunks array");
    assert_eq!(chunks.len(), 5, "ceil(23/5) = 5 chunks");

    // Concatenate every chunk's rows and prove BYTE-IDENTITY with the full read.
    let mut streamed_rows: Vec<Value> = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        assert_eq!(chunk["seq"], json!(i));
        let last = i + 1 == chunks.len();
        assert_eq!(chunk["last"], json!(last));
        if last {
            assert_eq!(chunk["row_count"], json!(3));
            assert_eq!(
                chunk["next_cursor"],
                Value::Null,
                "final chunk has no cursor"
            );
        } else {
            assert_eq!(chunk["row_count"], json!(5));
            let cursor = chunk["next_cursor"].as_str().expect("sealed cursor");
            assert!(
                cursor.parse::<usize>().is_err(),
                "next_cursor is a sealed, tamper-evident token, not a raw offset"
            );
        }
        streamed_rows.extend(chunk["rows"].as_array().expect("chunk rows").clone());
    }
    assert_eq!(
        streamed_rows, full_rows,
        "streamed chunks concatenate byte-identically to the full read"
    );
}

#[test]
fn streaming_resume_cursor_matches_a_manual_incremental_fetch() {
    // A streamed chunk's sealed next_cursor must be usable to resume a plain
    // (non-streaming) oracle_query and land on exactly the next window — proving
    // streaming and incremental cursor fetch share one cursor contract.
    let dispatcher = OracleDispatcher::new_with_profile(
        Box::new(StreamOffsetMock { total: 12 }),
        Some("dev".to_owned()),
    );
    let streamed = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT id, name FROM t", "streaming": true, "max_rows": 4 }),
        )
        .expect("streaming read");
    let chunks = streamed["chunks"].as_array().expect("chunks");
    let first_cursor = chunks[0]["next_cursor"]
        .as_str()
        .expect("cursor")
        .to_owned();

    // Resume a NON-streaming read with the streamed cursor.
    let resumed = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT id, name FROM t", "cursor": first_cursor, "max_rows": 4 }),
        )
        .expect("cursor resume");
    // The resumed page equals the SECOND streamed chunk's rows.
    assert_eq!(
        resumed["rows"], chunks[1]["rows"],
        "resuming with a streamed cursor yields the next chunk byte-identically"
    );
}

#[test]
fn streaming_never_bypasses_the_read_only_classifier() {
    // Streaming only changes DELIVERY: a non-read statement is refused BEFORE
    // any I/O exactly as it is on the inline path — the guard is untouched.
    let dispatcher = OracleDispatcher::new_with_profile(
        Box::new(StreamOffsetMock { total: 5 }),
        Some("dev".to_owned()),
    );
    let err = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "DELETE FROM t", "streaming": true }),
        )
        .expect_err("a write is refused even with streaming=true");
    // The classifier/level gate refuses the write (a DELETE exceeds the default
    // READ_ONLY level) before any I/O — streaming did not weaken the guard.
    assert_eq!(err.error_class, ErrorClass::OperatingLevelTooLow);
}

#[test]
fn streaming_is_mutually_exclusive_with_export_and_as_of() {
    let dispatcher = OracleDispatcher::new_with_profile(
        Box::new(StreamOffsetMock { total: 5 }),
        Some("dev".to_owned()),
    );
    let export_err = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT id FROM t", "streaming": true, "export": true }),
        )
        .expect_err("streaming + export refused");
    assert_eq!(export_err.error_class, ErrorClass::InvalidArguments);
    assert!(export_err.message.contains("mutually exclusive"));

    let as_of_err = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT id FROM t", "streaming": true, "as_of": { "scn": 42 } }),
        )
        .expect_err("streaming + as_of refused");
    assert_eq!(as_of_err.error_class, ErrorClass::InvalidArguments);
}

/// SEC-1 (plan §4-RS security-audit): a *stored* execute-grant is NEVER an
/// authorization input at apply. Once the session ceiling is lowered by ANY
/// path, a grant minted before the change must not run — the guard re-derives
/// authority from the LIVE lane state (the monotonic `grant_generation` + a
/// classifier re-gate against the current level), never from the stored verdict.
///
/// Bead `oraclemcp-release-073-iec3.2.10` (sec1). These are adversarial,
/// two-lane PROOFS: Lane A mints a grant, a lowering happens, and Lane A's
/// redemption is refused fail-closed. There are exactly three dispatch sites
/// that `grant_generation.saturating_add(1)` + `execute_grants.clear()`, namely
/// `close_with_cx` (lifecycle drop_elevation, already proven by
/// `lifecycle_close_rolls_back_and_revokes_execution_grants`), the profile-switch
/// commit block, and the `changed==true` `oracle_set_session_level` arm (which
/// covers both the explicit `action=drop` de-escalation AND a
/// `set_session_level` to a lower level).
///
/// AC2 exercises the switch plus both `set_session_level` lowerings here. The
/// TTL-expiry test documents the one lowering that does NOT invalidate the
/// grant (and why the served path is still safe).
#[cfg(test)]
mod sec1_stored_verdict_never_authorizes {
    use super::*;

    // A synthetic READ_WRITE write and a synthetic DDL statement (no live
    // identifiers). The UPDATE is used where we want the *lowered* ceiling to
    // still permit the statement (so grant-invalidation is the only thing that
    // can refuse it); the DDL is used for the AC1 "formerly-permitted DDL no
    // longer runs" narrative.
    const UPDATE_SQL: &str = "UPDATE hr.employees SET salary = salary WHERE employee_id = 1";
    const DDL_SQL: &str = "CREATE TABLE sec1_probe (id NUMBER)";

    /// A single-connection dispatcher whose mock RECORDS every executed
    /// statement (so we can prove nothing ran) and never panics.
    fn recording_dispatcher(level: SessionLevelState) -> (OracleDispatcher, Arc<ExecState>) {
        let state = Arc::new(ExecState::default());
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(state.clone())),
            Some("dev".to_owned()),
            level,
        );
        (dispatcher, state)
    }

    /// A switchable dispatcher whose connector hands back a recording mock that
    /// shares the SAME `ExecState`, so an execute on either the pre- or
    /// post-switch session is observable through one handle.
    fn switchable_recording_dispatcher(
        level: SessionLevelState,
    ) -> (OracleDispatcher, Arc<ExecState>) {
        let state = Arc::new(ExecState::default());
        let connector_state = state.clone();
        let dispatcher = OracleDispatcher::new_switchable(
            Box::new(ExecRecordingMock::new(state.clone())),
            Some("dev".to_owned()),
            level,
            Arc::new(move |_cx, _profile| {
                let state = connector_state.clone();
                Box::pin(async move { Ok(session_bundle(ExecRecordingMock::new(state))) })
            }),
        );
        (dispatcher, state)
    }

    /// The statements the mock actually executed against the database.
    fn executed(state: &Arc<ExecState>) -> Vec<String> {
        state
            .executed
            .lock()
            .expect("exec mutex")
            .iter()
            .map(|(sql, _)| sql.clone())
            .collect()
    }

    /// Read/mutate the private dispatcher state directly (legal from this child
    /// module) so we can assert the generation counter and simulate a passive
    /// TTL expiry deterministically.
    fn with_state<R>(
        dispatcher: &OracleDispatcher,
        f: impl FnOnce(&mut DispatcherState) -> R,
    ) -> R {
        RuntimeBuilder::current_thread()
            .build()
            .expect("asupersync test runtime builds")
            .block_on(async {
                let cx = Cx::current().expect("block_on installs a current Cx");
                let mut guard = match dispatcher.state.lock(&cx).await {
                    Ok(guard) => guard,
                    Err(_) => panic!("state mutex lock failed"),
                };
                f(&mut guard)
            })
    }

    /// AC1 — the two-lane proof, DDL flavor. Lane A mints an execute-grant for a
    /// DDL while the session permits DDL; Lane B (same shared state) drops the
    /// elevation to READ_ONLY; Lane A's redemption is REFUSED and the DDL never
    /// runs. The signed-reference redemption is refused by the live re-gate
    /// (OperatingLevelTooLow), and the remembered-token redemption is refused as
    /// UNKNOWN (the store was cleared) — proving the stored grant is dead, not
    /// merely gated.
    #[test]
    fn ac1_two_lane_pre_minted_ddl_grant_never_runs_after_elevation_dropped() {
        let (dispatcher, state) = recording_dispatcher(ddl_level());

        // Lane A: mint a DDL execute-grant.
        let lane_a = DispatchContext::default()
            .with_http_session_id("sess-a")
            .with_principal_key("oauth:subj-a")
            .with_lane_identity("lane-a", 1);
        let confirm = dispatcher
            .dispatch_with_context("oracle_preview_sql", json!({ "sql": DDL_SQL }), lane_a)
            .expect("preview")
            .pointer("/execute_confirmation/confirm")
            .and_then(Value::as_str)
            .expect("preview minted a DDL execute grant")
            .to_owned();

        // Lane B: lower the shared ceiling (drop the elevation to READ_ONLY).
        let lane_b = DispatchContext::default()
            .with_http_session_id("sess-b")
            .with_principal_key("oauth:subj-b")
            .with_lane_identity("lane-b", 1);
        dispatcher
            .dispatch_with_context(
                "oracle_set_session_level",
                json!({ "action": "drop" }),
                lane_b,
            )
            .expect("lane B drops the elevation");

        // Lane A: the stored DDL grant must not authorize anything now.
        let exec_err = dispatcher
            .dispatch_with_context(
                "oracle_execute",
                json!({ "sql": DDL_SQL, "confirm": confirm.clone(), "commit": true }),
                lane_a,
            )
            .expect_err("a DDL grant minted before the drop must be refused");
        assert!(
            matches!(
                exec_err.error_class,
                ErrorClass::OperatingLevelTooLow | ErrorClass::ChallengeRequired
            ),
            "fail-closed refusal, got {:?}: {}",
            exec_err.error_class,
            exec_err.message
        );
        assert!(
            executed(&state).is_empty(),
            "the DDL must NOT have reached the database"
        );

        // The grant is genuinely invalidated (the store was cleared), not just
        // gated: the remembered-token redemption is UNKNOWN — a grant-
        // invalidation refusal, independent of the current level.
        let token_err = dispatcher
            .dispatch_with_context("execute_approved", json!({ "token": confirm }), lane_a)
            .expect_err("the cleared grant is unknown");
        assert_eq!(token_err.error_class, ErrorClass::ChallengeRequired);
        assert!(
            token_err.message.contains("unknown or expired"),
            "grant-invalidation refusal expected: {}",
            token_err.message
        );
        assert!(executed(&state).is_empty(), "still nothing ran");
    }

    /// AC2 — EACH distinct level-lowering dispatch path invalidates a
    /// pre-minted grant. Table-driven over the three sites that clear+bump.
    /// For every path we assert, uniformly:
    ///   1. `grant_generation` advanced (the monotonic invalidation stamp), and
    ///   2. the signed-reference redemption is refused fail-closed and never
    ///      touches the database, and
    ///   3. the remembered-token redemption is refused as UNKNOWN (the store was
    ///      cleared) — a level-INDEPENDENT proof that the grant itself is dead,
    ///      isolating grant-invalidation from the belt-and-suspenders re-gate.
    #[test]
    fn ac2_every_lowering_path_refuses_and_never_executes() {
        struct LoweringPath {
            name: &'static str,
            build: fn() -> (OracleDispatcher, Arc<ExecState>),
            lower: fn(&OracleDispatcher),
        }

        let paths = [
            LoweringPath {
                name: "set_session_level action=drop (explicit drop_elevation)",
                build: || recording_dispatcher(ddl_level()),
                lower: |dispatcher| {
                    dispatcher
                        .dispatch("oracle_set_session_level", json!({ "action": "drop" }))
                        .expect("drop elevation");
                },
            },
            LoweringPath {
                name: "set_session_level to a lower level (DDL -> READ_WRITE)",
                build: || recording_dispatcher(ddl_level()),
                lower: |dispatcher| {
                    dispatcher
                        .dispatch(
                            "oracle_set_session_level",
                            json!({ "level": "READ_WRITE", "action": "apply" }),
                        )
                        .expect("lower to READ_WRITE");
                },
            },
            LoweringPath {
                name: "profile switch",
                build: || switchable_recording_dispatcher(ddl_level()),
                lower: |dispatcher| {
                    dispatcher
                        .dispatch("oracle_switch_profile", json!({ "profile": "other" }))
                        .expect("switch profile");
                },
            },
        ];

        for path in paths {
            let (dispatcher, state) = (path.build)();
            let confirm = preview_confirm(&dispatcher, UPDATE_SQL);
            let gen_before = with_state(&dispatcher, |s| s.grant_generation);

            (path.lower)(&dispatcher);

            // sec1/AC3: a mutant that DELETED `grant_generation.saturating_add(1)`
            // at this path's dispatch site would leave `gen_after == gen_before`
            // and fail this assert. A mutant that deleted `execute_grants.clear()`
            // / `execute_approved_tokens.clear()` would leave the token redeemable
            // and fail the "unknown or expired" assert below. (Mutation coverage
            // itself is bead D6.4; these asserts name the invariant it must kill.)
            let gen_after = with_state(&dispatcher, |s| s.grant_generation);
            assert!(
                gen_after > gen_before,
                "{}: grant_generation must advance ({gen_before} -> {gen_after})",
                path.name
            );

            // Signed-reference redemption is refused fail-closed and never runs.
            let exec_err = dispatcher
                .dispatch(
                    "oracle_execute",
                    json!({ "sql": UPDATE_SQL, "confirm": confirm.clone(), "commit": true }),
                )
                .expect_err(&format!(
                    "{}: a grant minted before the lowering must be refused",
                    path.name
                ));
            assert!(
                matches!(
                    exec_err.error_class,
                    ErrorClass::ChallengeRequired | ErrorClass::OperatingLevelTooLow
                ),
                "{}: fail-closed refusal, got {:?}: {}",
                path.name,
                exec_err.error_class,
                exec_err.message
            );
            assert!(
                executed(&state).is_empty(),
                "{}: the write must NOT reach the database",
                path.name
            );

            // Remembered-token redemption proves the store was CLEARED. This
            // refusal fires before any level re-gate, so it isolates
            // grant-invalidation from the classifier re-gate.
            let token_err = dispatcher
                .dispatch("execute_approved", json!({ "token": confirm }))
                .expect_err(&format!("{}: the cleared grant is unknown", path.name));
            assert_eq!(
                token_err.error_class,
                ErrorClass::ChallengeRequired,
                "{}",
                path.name
            );
            assert!(
                token_err.message.contains("unknown or expired"),
                "{}: grant-invalidation refusal expected: {}",
                path.name,
                token_err.message
            );
            assert!(
                executed(&state).is_empty(),
                "{}: still nothing ran",
                path.name
            );
        }
    }

    /// The precise SEC-1 statement: the stored verdict is never an authorization
    /// input EVEN WHEN the live gate would still allow the statement. Mint a
    /// READ_WRITE grant at DDL, then lower to READ_WRITE — the UPDATE is still
    /// within the (lowered) ceiling, so the classifier re-gate ALLOWS it; the
    /// ONLY thing that can refuse the redeem is the stale lane generation. This
    /// isolates grant-invalidation from the belt-and-suspenders re-gate.
    #[test]
    fn set_session_level_lower_refuses_stale_grant_even_when_live_gate_allows() {
        let (dispatcher, state) = recording_dispatcher(ddl_level());
        let confirm = preview_confirm(&dispatcher, UPDATE_SQL);

        dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({ "level": "READ_WRITE", "action": "apply" }),
            )
            .expect("lower DDL -> READ_WRITE");

        let err = dispatcher
            .dispatch(
                "oracle_execute",
                json!({ "sql": UPDATE_SQL, "confirm": confirm, "commit": true }),
            )
            .expect_err("stale grant refused although the live gate permits READ_WRITE");
        // Not a level gate (READ_WRITE is permitted) — a grant-invalidation
        // refusal that cites the lane generation.
        assert_eq!(
            err.error_class,
            ErrorClass::ChallengeRequired,
            "grant-invalidation (not a level gate) must refuse: {}",
            err.message
        );
        assert!(
            err.message.contains("generation"),
            "the refusal cites the lane generation: {}",
            err.message
        );
        assert!(executed(&state).is_empty(), "the UPDATE must NOT run");
    }

    /// Positive control: with NO lowering, the very same mint→redeem flow runs
    /// the statement exactly once. This proves the refusals above are caused by
    /// the lowering, not by an inert harness that never executes anything.
    #[test]
    fn control_valid_grant_runs_once_when_ceiling_is_not_lowered() {
        let (dispatcher, state) = recording_dispatcher(ddl_level());
        let confirm = preview_confirm(&dispatcher, UPDATE_SQL);
        let out = dispatcher
            .dispatch(
                "oracle_execute",
                json!({ "sql": UPDATE_SQL, "confirm": confirm, "commit": true }),
            )
            .expect("a fresh, un-lowered grant runs");
        assert_eq!(out["executed"], json!(true));
        let ran = executed(&state);
        assert_eq!(ran.len(), 1, "exactly one statement ran");
        assert!(
            ran[0].contains("UPDATE hr.employees"),
            "the previewed UPDATE ran: {}",
            ran[0]
        );
    }

    /// FINDING (honest verdict): the ONE level-lowering path that does NOT go
    /// through a clear+bump dispatch site is the PASSIVE elevation-window TTL
    /// expiry. When an `escalate_window` deadline lapses, the effective level
    /// drops back to the base with NO dispatch call, so `grant_generation` is
    /// unchanged and `execute_grants` is not cleared — the grant is NOT
    /// invalidated. This is safe on the SERVED path because the write apply path
    /// (`execute_sql_inner`) RE-CLASSIFIES and RE-GATES against the live level
    /// BEFORE consuming the grant, so a now-forbidden DDL is refused anyway.
    /// (The standalone `oraclemcp-core::oracle_query_execute` helper now performs
    /// the same re-classify + re-gate at apply-time — SEC-1, bead iec3.2.34 — so it
    /// is safe-by-construction if ever wired; it remains unwired on this surface.)
    #[test]
    fn ttl_elevation_expiry_is_caught_by_reclassify_not_by_grant_invalidation() {
        // Ceiling DDL, base current READ_ONLY: a *temporary* elevation to DDL.
        let (dispatcher, state) =
            recording_dispatcher(SessionLevelState::new(OperatingLevel::Ddl, false));

        // Real step-up elevation to DDL (this bumps the generation once).
        let preview = dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({ "level": "DDL", "ttl_seconds": 3600 }),
            )
            .expect("preview elevation");
        let confirm = preview["confirmation"]["confirm"]
            .as_str()
            .expect("elevation grant")
            .to_owned();
        dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({ "level": "DDL", "ttl_seconds": 3600, "execute": true, "confirm": confirm }),
            )
            .expect("elevate to DDL");

        // Mint a DDL grant while elevated.
        let ddl_confirm = preview_confirm(&dispatcher, DDL_SQL);
        let gen_at_mint = with_state(&dispatcher, |s| s.grant_generation);

        // Simulate the elevation TTL lapsing: re-arm an ALREADY-expired window,
        // exactly the post-expiry state (levels.rs auto-drops an expired window
        // in `effective_level`). This is a passive state transition — it does
        // NOT run through any dispatch site, so it neither bumps the generation
        // nor clears the grant store.
        with_state(&dispatcher, |s| {
            s.level
                .escalate_window(OperatingLevel::Ddl, std::time::Duration::from_secs(0))
                .expect("re-arm an already-expired elevation window");
        });
        let gen_after_expiry = with_state(&dispatcher, |s| s.grant_generation);

        // FINDING: TTL expiry does NOT invalidate the grant.
        assert_eq!(
            gen_after_expiry, gen_at_mint,
            "TTL expiry must not bump grant_generation (it is a passive drop)"
        );

        // Yet the pre-minted DDL grant STILL does not run: the served apply path
        // re-classifies + re-gates against the LIVE (post-expiry, READ_ONLY)
        // level and refuses the now-forbidden DDL BEFORE the grant is consumed.
        let err = dispatcher
            .dispatch(
                "oracle_execute",
                json!({ "sql": DDL_SQL, "confirm": ddl_confirm, "commit": true }),
            )
            .expect_err("expired-elevation DDL grant must be refused");
        assert_eq!(
            err.error_class,
            ErrorClass::OperatingLevelTooLow,
            "the live re-gate (not invalidation) refuses the now-forbidden DDL: {}",
            err.message
        );
        assert!(
            executed(&state).is_empty(),
            "the DDL must NOT run after the elevation window expired"
        );
    }
}

/// Offline unit tests for the additive DDL blast-radius (dependents) block
/// assembled into the create_or_replace / patch_source previews (bead K11).
mod dependents_preview {
    use super::*;

    fn dep(owner: &str, name: &str, ty: &str) -> DependentObject {
        DependentObject {
            owner: owner.to_owned(),
            name: name.to_owned(),
            object_type: ty.to_owned(),
        }
    }

    #[test]
    fn available_block_lists_objects_and_flags_invalidatable_subset() {
        let probe = DependentsProbe::Available {
            direct: vec![
                dep("APP", "V_ORDERS", "VIEW"),
                dep("APP", "P_REPORT", "PROCEDURE"),
                dep("APP", "T_AUDIT", "TABLE"),
            ],
        };
        let (key, block) = dependents_preview_entry(&probe);
        assert_eq!(key, "dependents");
        assert_eq!(block["count"], json!(3));
        assert_eq!(block["objects"].as_array().unwrap().len(), 3);
        // TABLE is not invalidatable; the view + proc are.
        let at_risk = block["at_risk_of_invalid"].as_array().unwrap();
        assert_eq!(at_risk.len(), 2);
        let names: Vec<&str> = at_risk
            .iter()
            .map(|o| o["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"V_ORDERS") && names.contains(&"P_REPORT"));
        assert!(!names.contains(&"T_AUDIT"));
        // Object shape uses the "type" key.
        assert_eq!(block["objects"][0]["type"], json!("VIEW"));
        assert!(
            block["note"]
                .as_str()
                .unwrap()
                .contains("direct dependents only")
        );
    }

    #[test]
    fn unavailable_block_carries_reason_and_omits_dependents() {
        let probe = DependentsProbe::Unavailable {
            reason: "ALL_DEPENDENCIES not accessible: ORA-00942".to_owned(),
        };
        let (key, block) = dependents_preview_entry(&probe);
        assert_eq!(key, "dependents_unavailable");
        assert!(block["reason"].as_str().unwrap().contains("ORA-00942"));
    }

    #[test]
    fn merge_splices_block_into_preview_without_disturbing_existing_keys() {
        let mut preview = json!({ "applied": false, "preview": true });
        let probe = DependentsProbe::Available {
            direct: vec![dep("APP", "PKG_BODY", "PACKAGE BODY")],
        };
        merge_dependents_preview(&mut preview, &probe);
        assert_eq!(preview["applied"], json!(false));
        assert_eq!(preview["preview"], json!(true));
        assert_eq!(preview["dependents"]["count"], json!(1));
        assert_eq!(
            preview["dependents"]["at_risk_of_invalid"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn empty_available_block_has_zero_count() {
        let probe = DependentsProbe::Available { direct: vec![] };
        let (_key, block) = dependents_preview_entry(&probe);
        assert_eq!(block["count"], json!(0));
        assert_eq!(block["objects"].as_array().unwrap().len(), 0);
        assert_eq!(block["at_risk_of_invalid"].as_array().unwrap().len(), 0);
    }
}

/// QA85: a multi-round-trip health request inherits one absolute deadline and
/// one shared quota handle. Later subchecks cannot get a fresh allowance merely
/// because they issue a separate database call.
mod qa85_shared_health_budget {
    use super::*;

    #[derive(Default)]
    struct BudgetTrackingState {
        request_deadline: Mutex<Option<Time>>,
        request_quota: Mutex<Option<DbRequestQuota>>,
        observed_deadlines: Mutex<Vec<Time>>,
        observed_quotas: Mutex<Vec<DbRequestQuota>>,
        remaining_before_query: Mutex<Vec<u32>>,
        query_attempts: AtomicUsize,
        query_completions: AtomicUsize,
    }

    struct BudgetTrackingHealthMock {
        state: Arc<BudgetTrackingState>,
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for BudgetTrackingHealthMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.state.query_attempts.fetch_add(1, Ordering::SeqCst);
            let deadline = self
                .state
                .request_deadline
                .lock()
                .expect("request deadline mutex")
                .expect("dispatch installed an absolute request deadline");
            let quota = self
                .state
                .request_quota
                .lock()
                .expect("request quota mutex")
                .clone()
                .expect("dispatch installed a shared request quota");
            self.state
                .observed_deadlines
                .lock()
                .expect("observed deadlines mutex")
                .push(deadline);
            self.state
                .remaining_before_query
                .lock()
                .expect("remaining quota mutex")
                .push(quota.polls_remaining());
            self.state
                .observed_quotas
                .lock()
                .expect("observed quotas mutex")
                .push(quota.clone());
            quota.consume_checkpoint("qa85 health database round trip")?;
            self.state.query_completions.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        }

        async fn execute(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            Ok(0)
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        fn request_deadline(&self, _cx: &Cx) -> Result<Option<Time>, DbError> {
            Ok(*self
                .state
                .request_deadline
                .lock()
                .expect("request deadline mutex"))
        }

        fn set_request_deadline(&self, _cx: &Cx, deadline: Option<Time>) -> Result<(), DbError> {
            *self
                .state
                .request_deadline
                .lock()
                .expect("request deadline mutex") = deadline;
            Ok(())
        }

        fn request_quota(&self, _cx: &Cx) -> Result<Option<DbRequestQuota>, DbError> {
            Ok(self
                .state
                .request_quota
                .lock()
                .expect("request quota mutex")
                .clone())
        }

        fn set_request_quota(
            &self,
            _cx: &Cx,
            quota: Option<DbRequestQuota>,
        ) -> Result<(), DbError> {
            *self
                .state
                .request_quota
                .lock()
                .expect("request quota mutex") = quota;
            Ok(())
        }
    }

    #[test]
    fn health_subchecks_share_one_installed_deadline_and_exhaust_one_quota() {
        let state = Arc::new(BudgetTrackingState::default());
        let dispatcher = OracleDispatcher::new_with_profile(
            Box::new(BudgetTrackingHealthMock {
                state: Arc::clone(&state),
            }),
            Some("dev".to_owned()),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("asupersync test runtime builds");
        let outcome = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            let admitted_at = cx.now();
            let caller_budget = asupersync::Budget::new()
                .with_timeout(admitted_at, Duration::from_secs(30))
                .with_poll_quota(8);
            let request_budget = RequestBudget::from_budget_at(admitted_at, caller_budget);
            let context = DispatchContext::default()
                .with_admitted_at(admitted_at)
                .with_caller_budget(caller_budget)
                .with_request_budget(&request_budget);
            ToolDispatch::dispatch(
                &dispatcher,
                &cx,
                context,
                "oracle_db_health",
                json!({ "health_type": "all" }),
            )
            .await
        });

        match outcome {
            Outcome::Err(error) => assert_eq!(error.error_class, ErrorClass::Timeout),
            other => panic!("shared quota exhaustion must stop health dispatch: {other:?}"),
        }
        assert_eq!(
            state.query_attempts.load(Ordering::SeqCst),
            4,
            "remaining quota observations: {:?}",
            *state
                .remaining_before_query
                .lock()
                .expect("remaining quota mutex")
        );
        assert_eq!(state.query_completions.load(Ordering::SeqCst), 3);
        assert_eq!(
            state
                .remaining_before_query
                .lock()
                .expect("remaining quota mutex")
                .as_slice(),
            &[3, 2, 1, 0],
            "each database round trip consumes the same request allowance"
        );
        let deadlines = state
            .observed_deadlines
            .lock()
            .expect("observed deadlines mutex");
        assert_eq!(deadlines.len(), 4);
        assert!(deadlines.windows(2).all(|pair| pair[0] == pair[1]));
        drop(deadlines);
        let quotas = state.observed_quotas.lock().expect("observed quotas mutex");
        assert_eq!(quotas.len(), 4);
        assert!(quotas.windows(2).all(|pair| pair[0].ptr_eq(&pair[1])));
        drop(quotas);
        assert_eq!(
            *state
                .request_deadline
                .lock()
                .expect("request deadline mutex"),
            None,
            "dispatch restores the connection-scoped deadline"
        );
        assert!(
            state
                .request_quota
                .lock()
                .expect("request quota mutex")
                .is_none(),
            "dispatch restores the connection-scoped quota"
        );
    }
}

/// QA97: health-query failures remain truthful at the served dispatcher
/// boundary. This module is intentionally isolated so concurrent QA85 timeout
/// tests do not share fixtures or edit the same production paths.
mod qa97_health_failure_boundaries {
    use super::*;
    use std::sync::Arc;

    #[derive(Clone, Copy)]
    enum FailureMode {
        Ordinary,
        Uncertain,
    }

    struct HealthFailureMock {
        mode: FailureMode,
        query_count: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for HealthFailureMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo {
                current_schema: Some("APP".to_owned()),
                ..Default::default()
            })
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.query_count.fetch_add(1, Ordering::SeqCst);
            match self.mode {
                FailureMode::Ordinary => Err(DbError::Query(
                    "ORA-00904: invalid identifier; password=never-render-this".to_owned(),
                )),
                FailureMode::Uncertain => Err(DbError::Cancelled(
                    "health query cancelled at the database boundary".to_owned(),
                )),
            }
        }

        async fn execute(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            Ok(0)
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    fn dispatcher(mode: FailureMode, query_count: Arc<AtomicUsize>) -> OracleDispatcher {
        OracleDispatcher::new_switchable(
            Box::new(HealthFailureMock { mode, query_count }),
            Some("dev".to_owned()),
            read_write_level(),
            Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
        )
    }

    #[test]
    fn ordinary_health_failure_is_reported_failed_and_secret_safe() {
        let query_count = Arc::new(AtomicUsize::new(0));
        let out = dispatcher(FailureMode::Ordinary, Arc::clone(&query_count))
            .dispatch(
                "oracle_db_health",
                json!({ "health_type": "invalid_objects" }),
            )
            .expect("ordinary diagnostic failure remains an in-band health report");

        assert_eq!(out["checks_run"], json!([]));
        assert_eq!(out["checks_skipped"], json!([]));
        assert_eq!(out["checks_failed"], json!(["invalid_objects"]));
        assert_eq!(out["findings"][0]["detail"]["status"], json!("failed"));
        assert_eq!(
            out["findings"][0]["detail"]["error_class"],
            json!("SYNTAX_ERROR")
        );
        assert_eq!(out["findings"][0]["detail"]["ora_code"], json!(904));
        let rendered = out.to_string();
        assert!(!rendered.contains("never-render-this"), "{rendered}");
        assert!(!rendered.contains("password="), "{rendered}");
        assert_eq!(
            query_count.load(Ordering::SeqCst),
            1,
            "an ordinary SQL regression must not trigger an ALL_* fallback"
        );
    }

    #[test]
    fn uncertain_health_failure_quarantines_and_refuses_subsequent_dispatch() {
        let query_count = Arc::new(AtomicUsize::new(0));
        let dispatcher = dispatcher(FailureMode::Uncertain, Arc::clone(&query_count));

        let first = dispatcher
            .dispatch(
                "oracle_db_health",
                json!({ "health_type": "invalid_objects" }),
            )
            .expect_err("uncertain health failure must propagate");
        assert_eq!(first.error_class, ErrorClass::Timeout);
        assert_eq!(query_count.load(Ordering::SeqCst), 1);

        let second = dispatcher
            .dispatch(
                "oracle_db_health",
                json!({ "health_type": "invalid_objects" }),
            )
            .expect_err("quarantined connection must refuse later work");
        assert_eq!(second.error_class, ErrorClass::RuntimeStateRequired);
        assert!(second.message.contains("quarantined"), "{}", second.message);
        assert_eq!(
            query_count.load(Ordering::SeqCst),
            1,
            "subsequent refusal must happen before another Oracle query"
        );
    }
}

/// QA106: uncertain read failures obey physical-session ownership. Retained
/// primary sessions are quarantined before they can be reused; stateless read
/// workers own their checkout lifecycle and therefore do not poison the
/// dispatcher's unrelated primary session.
mod qa106_uncertain_read_ownership {
    use super::*;
    use std::sync::Arc;

    #[derive(Clone, Copy)]
    enum FirstFailure {
        Cancelled,
        Ordinary,
    }

    struct FailFirstReadMock {
        calls: Arc<AtomicUsize>,
        failure: FirstFailure,
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for FailFirstReadMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo {
                current_schema: Some("APP".to_owned()),
                ..Default::default()
            })
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            sql: &str,
            binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            if let Some(rows) = mock_plain_table_dictionary(sql, binds) {
                return Ok(rows);
            }
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return match self.failure {
                    FirstFailure::Cancelled => Err(DbError::Cancelled(
                        "injected uncertain read boundary".to_owned(),
                    )),
                    FirstFailure::Ordinary => Err(DbError::Query(
                        "ORA-00942: table or view does not exist".to_owned(),
                    )),
                };
            }
            Ok(vec![OracleRow {
                columns: vec![(
                    "SCHEMA_NAME".to_owned(),
                    OracleCell::new("VARCHAR2", Some("APP".to_owned())),
                )],
            }])
        }

        async fn execute(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            Ok(0)
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    fn assert_pinned_retry_is_refused(
        dispatcher: &OracleDispatcher,
        calls: &AtomicUsize,
        tool: &str,
        args: Value,
    ) {
        let first = dispatcher
            .dispatch(tool, args.clone())
            .expect_err("uncertain pinned read must fail");
        assert_eq!(first.error_class, ErrorClass::Timeout);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let retry = dispatcher
            .dispatch(tool, args)
            .expect_err("quarantined pinned session must not be reused");
        assert_eq!(retry.error_class, ErrorClass::RuntimeStateRequired);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "retry must be refused before another database round trip"
        );
        let quarantine = dispatcher
            .connection_quarantine()
            .expect("quarantine lock")
            .expect("uncertain read records quarantine");
        assert_eq!(quarantine.outcome, AuditOutcome::UnknownDiscarded);
    }

    #[test]
    fn raw_query_uncertainty_quarantines_the_retained_primary_session() {
        let calls = Arc::new(AtomicUsize::new(0));
        let dispatcher = OracleDispatcher::new_with_profile(
            Box::new(FailFirstReadMock {
                calls: Arc::clone(&calls),
                failure: FirstFailure::Cancelled,
            }),
            Some("dev".to_owned()),
        );
        assert_pinned_retry_is_refused(
            &dispatcher,
            &calls,
            "oracle_query",
            json!({ "sql": "SELECT schema_name FROM app_table" }),
        );
    }

    #[test]
    fn generated_read_uncertainty_quarantines_the_retained_primary_session() {
        let calls = Arc::new(AtomicUsize::new(0));
        let dispatcher = OracleDispatcher::new_with_profile(
            Box::new(FailFirstReadMock {
                calls: Arc::clone(&calls),
                failure: FirstFailure::Cancelled,
            }),
            Some("dev".to_owned()),
        );
        assert_pinned_retry_is_refused(
            &dispatcher,
            &calls,
            "oracle_sample_rows",
            json!({ "owner": "APP", "table": "T", "max_rows": 1 }),
        );
    }

    #[test]
    fn ordinary_sql_error_keeps_the_pinned_session_usable() {
        let calls = Arc::new(AtomicUsize::new(0));
        let dispatcher = OracleDispatcher::new_with_profile(
            Box::new(FailFirstReadMock {
                calls: Arc::clone(&calls),
                failure: FirstFailure::Ordinary,
            }),
            Some("dev".to_owned()),
        );

        let first = dispatcher
            .dispatch(
                "oracle_query",
                json!({ "sql": "SELECT schema_name FROM app_table" }),
            )
            .expect_err("deterministic ORA-00942 propagates");
        assert_eq!(first.error_class, ErrorClass::ObjectNotFound);
        let second = dispatcher
            .dispatch(
                "oracle_query",
                json!({ "sql": "SELECT schema_name FROM app_table" }),
            )
            .expect("deterministic SQL error must not quarantine the session");
        assert_eq!(second["rows"][0]["SCHEMA_NAME"], json!("APP"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(
            dispatcher
                .connection_quarantine()
                .expect("quarantine lock")
                .is_none()
        );
    }

    #[test]
    fn stateless_read_failure_does_not_poison_the_primary_session() {
        let calls = Arc::new(AtomicUsize::new(0));
        let dispatcher = OracleDispatcher::new_switchable_with_custom_tools_and_stateless(
            Box::new(OneRowMock),
            Some("dev".to_owned()),
            default_read_only_level(),
            Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
            StatelessReadStrategy::new(Some(Box::new(FailFirstReadMock {
                calls: Arc::clone(&calls),
                failure: FirstFailure::Cancelled,
            }))),
            CustomToolCatalog::default(),
            None,
        );

        let first = dispatcher
            .dispatch("oracle_list_schemas", json!({ "max_rows": 1 }))
            .expect_err("failed stateless checkout propagates");
        assert_eq!(first.error_class, ErrorClass::Timeout);
        assert!(
            dispatcher
                .connection_quarantine()
                .expect("quarantine lock")
                .is_none(),
            "the stateless worker must not quarantine the unrelated primary session"
        );
        let second = dispatcher
            .dispatch("oracle_list_schemas", json!({ "max_rows": 1 }))
            .expect("a fresh stateless read can proceed");
        assert_eq!(second["schemas"][0]["SCHEMA_NAME"], json!("APP"));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}

/// QA107: best-effort connection metadata may degrade ordinary adapter or
/// privilege failures, but it must never hide cancellation/connection loss on
/// a retained session or install an uncertain switch candidate.
mod qa107_describe_uncertainty {
    use super::*;
    use std::sync::Arc;

    struct UncertainDescribeMock {
        describe_calls: Arc<AtomicUsize>,
        query_calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for UncertainDescribeMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            self.describe_calls.fetch_add(1, Ordering::SeqCst);
            Err(DbError::Cancelled(
                "injected uncertain describe boundary".to_owned(),
            ))
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.query_calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![OracleRow {
                columns: vec![(
                    "VALUE".to_owned(),
                    OracleCell::new("NUMBER", Some("1".to_owned())),
                )],
            }])
        }

        async fn execute(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            Ok(0)
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    #[test]
    fn uncertain_connection_info_quarantines_retained_primary_before_reuse() {
        let describe_calls = Arc::new(AtomicUsize::new(0));
        let query_calls = Arc::new(AtomicUsize::new(0));
        let dispatcher = OracleDispatcher::new_with_profile(
            Box::new(UncertainDescribeMock {
                describe_calls: Arc::clone(&describe_calls),
                query_calls: Arc::clone(&query_calls),
            }),
            Some("dev".to_owned()),
        );

        let first = dispatcher
            .dispatch("oracle_connection_info", json!({}))
            .expect_err("uncertain describe must not become disconnected metadata");
        assert_eq!(first.error_class, ErrorClass::Timeout);
        assert_eq!(describe_calls.load(Ordering::SeqCst), 1);
        let quarantine = dispatcher
            .connection_quarantine()
            .expect("quarantine lock")
            .expect("retained primary describe quarantines uncertainty");
        assert_eq!(quarantine.outcome, AuditOutcome::UnknownDiscarded);

        let retry = dispatcher
            .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
            .expect_err("quarantined primary must refuse later work");
        assert_eq!(retry.error_class, ErrorClass::RuntimeStateRequired);
        assert_eq!(
            query_calls.load(Ordering::SeqCst),
            0,
            "retry refusal must precede database I/O"
        );
    }

    #[test]
    fn uncertain_switch_candidate_is_dropped_without_poisoning_active_session() {
        let candidate_describes = Arc::new(AtomicUsize::new(0));
        let candidate_queries = Arc::new(AtomicUsize::new(0));
        let connector_describes = Arc::clone(&candidate_describes);
        let connector_queries = Arc::clone(&candidate_queries);
        let dispatcher = OracleDispatcher::new_switchable(
            Box::new(OneRowMock),
            Some("dev".to_owned()),
            default_read_only_level(),
            Arc::new(move |_cx, _profile| {
                let describe_calls = Arc::clone(&connector_describes);
                let query_calls = Arc::clone(&connector_queries);
                Box::pin(async move {
                    Ok(session_bundle(UncertainDescribeMock {
                        describe_calls,
                        query_calls,
                    }))
                })
            }),
        );

        let error = dispatcher
            .dispatch("oracle_switch_profile", json!({ "profile": "uncertain" }))
            .expect_err("uncertain candidate metadata must abort the switch");
        assert_eq!(error.error_class, ErrorClass::Timeout);
        assert_eq!(candidate_describes.load(Ordering::SeqCst), 1);
        assert_eq!(candidate_queries.load(Ordering::SeqCst), 0);
        assert!(
            dispatcher
                .connection_quarantine()
                .expect("quarantine lock")
                .is_none(),
            "candidate uncertainty must not poison the unrelated active primary"
        );

        let current = dispatcher
            .dispatch("oracle_connection_info", json!({}))
            .expect("active session remains usable after candidate rejection");
        assert_eq!(current["active_profile"], json!("dev"));
        assert_eq!(current["connected"], json!(true));
        dispatcher
            .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
            .expect("active primary still serves reads");
    }
}
