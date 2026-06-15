//! Unit tests for the dispatcher, relocated verbatim from the former
//! single-file `dispatch.rs`. Body indentation is preserved as-is to keep
//! every raw-string fixture byte-identical.

use super::*;
use crate::registry::TOOL_NAMES;
use asupersync::runtime::RuntimeBuilder;
use oraclemcp_core::{DispatchContext, ScopeGrant};
use oraclemcp_db::{OracleBackend, OracleCell, OracleRow};
use std::sync::atomic::{AtomicUsize, Ordering};

fn run_with_current_cx(f: impl FnOnce(&Cx)) {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("asupersync test runtime builds");
    runtime.block_on(async {
        let cx = Cx::current().expect("block_on installs a current Cx");
        f(&cx);
    });
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

fn scope_grant(scope: &str) -> ScopeGrant {
    ScopeGrant(vec![scope.to_owned()])
}

/// A driver-free mock that returns one synthetic row for any query — mirrors
/// `oraclemcp_db::query`'s `NRowMock` so the dispatch arms exercise offline.
struct OneRowMock;
impl OracleConnection for OneRowMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    fn ping(&self) -> Result<(), DbError> {
        Ok(())
    }
    fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo {
            backend: Some(OracleBackend::RustOracle),
            server_version: Some("23.0.0".to_owned()),
            database_role: Some("PRIMARY".to_owned()),
            open_mode: Some("READ WRITE".to_owned()),
            read_only: false,
            read_only_reason: None,
            current_schema: Some("APP".to_owned()),
            current_edition: Some("ORA$BASE".to_owned()),
            session_user: Some("APP".to_owned()),
            current_user: Some("APP".to_owned()),
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
        })
    }
    fn query_rows(&self, _sql: &str, _b: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
        Ok(vec![OracleRow {
                columns: vec![
                    (
                        "OBJECT_NAME".to_owned(),
                        OracleCell::new("VARCHAR2", Some("EMPLOYEES".to_owned())),
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
    fn query_rows_named(
        &self,
        sql: &str,
        b: &[(String, OracleBind)],
    ) -> Result<Vec<OracleRow>, DbError> {
        assert!(
            sql.contains(":id"),
            "custom SQL should preserve named bind references: {sql}"
        );
        assert_eq!(b, &[("id".to_owned(), OracleBind::I64(7))]);
        self.query_rows(sql, &[])
    }
    fn execute(&self, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
        Ok(0)
    }
    fn commit(&self) -> Result<(), DbError> {
        Ok(())
    }
    fn rollback(&self) -> Result<(), DbError> {
        Ok(())
    }
}

struct SourceLookupMock;
impl OracleConnection for SourceLookupMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    fn ping(&self) -> Result<(), DbError> {
        Ok(())
    }
    fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo {
            backend: Some(OracleBackend::RustOracle),
            current_schema: Some("APP".to_owned()),
            ..Default::default()
        })
    }
    fn query_rows(&self, sql: &str, _b: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
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

        Ok(vec![OracleRow {
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
        }])
    }
    fn execute(&self, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
        Ok(0)
    }
    fn commit(&self) -> Result<(), DbError> {
        Ok(())
    }
    fn rollback(&self) -> Result<(), DbError> {
        Ok(())
    }
}

/// A mock whose every query fails with a classifiable ORA- error, so we can
/// assert DbError -> ErrorEnvelope mapping end to end.
struct FailingMock;
impl OracleConnection for FailingMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    fn ping(&self) -> Result<(), DbError> {
        Ok(())
    }
    fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo::default())
    }
    fn query_rows(&self, _sql: &str, _b: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
        Err(DbError::Query(
            "ORA-00942: table or view does not exist".to_owned(),
        ))
    }
    fn execute(&self, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
        Err(DbError::Execute(
            "ORA-00942: table or view does not exist".to_owned(),
        ))
    }
    fn commit(&self) -> Result<(), DbError> {
        Ok(())
    }
    fn rollback(&self) -> Result<(), DbError> {
        Ok(())
    }
}

struct DescribeFailingMock;
impl OracleConnection for DescribeFailingMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    fn ping(&self) -> Result<(), DbError> {
        Err(DbError::BackendNotCompiled {
            backend: OracleBackend::RustOracle,
        })
    }
    fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
        Err(DbError::BackendNotCompiled {
            backend: OracleBackend::RustOracle,
        })
    }
    fn query_rows(&self, _sql: &str, _b: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
        Err(DbError::BackendNotCompiled {
            backend: OracleBackend::RustOracle,
        })
    }
    fn execute(&self, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
        Err(DbError::BackendNotCompiled {
            backend: OracleBackend::RustOracle,
        })
    }
    fn commit(&self) -> Result<(), DbError> {
        Err(DbError::BackendNotCompiled {
            backend: OracleBackend::RustOracle,
        })
    }
    fn rollback(&self) -> Result<(), DbError> {
        Err(DbError::BackendNotCompiled {
            backend: OracleBackend::RustOracle,
        })
    }
}

#[derive(Default)]
struct ExecState {
    executed: Mutex<Vec<(String, Vec<OracleBind>)>>,
    diagnostics: Mutex<Vec<OracleRow>>,
    dbms_output: Mutex<DbmsOutput>,
    dbms_output_enabled: AtomicUsize,
    dbms_output_limits: Mutex<Vec<(usize, usize)>>,
    current_call_timeout: Mutex<Option<Duration>>,
    call_timeout_sets: Mutex<Vec<Option<Duration>>>,
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

impl OracleConnection for CancelAfterExecuteMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }

    fn ping(&self) -> Result<(), DbError> {
        Ok(())
    }

    fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo {
            backend: Some(OracleBackend::RustOracle),
            current_schema: Some("APP".to_owned()),
            ..Default::default()
        })
    }

    fn query_rows(&self, _sql: &str, _b: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
        Ok(Vec::new())
    }

    fn execute(&self, sql: &str, b: &[OracleBind]) -> Result<u64, DbError> {
        self.state
            .executed
            .lock()
            .expect("exec mutex")
            .push((sql.to_owned(), b.to_vec()));
        Ok(1)
    }

    fn execute_cx(&self, cx: &Cx, sql: &str, b: &[OracleBind]) -> Result<u64, DbError> {
        let _ = self.execute(sql, b)?;
        cx.set_cancel_requested(true);
        Err(DbError::Cancelled(
            "test cancellation after execute".to_owned(),
        ))
    }

    fn commit(&self) -> Result<(), DbError> {
        self.state.commits.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn rollback(&self) -> Result<(), DbError> {
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

impl OracleConnection for ExecRecordingMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }

    fn ping(&self) -> Result<(), DbError> {
        Ok(())
    }

    fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo {
            backend: Some(OracleBackend::RustOracle),
            current_schema: Some("APP".to_owned()),
            ..Default::default()
        })
    }

    fn query_rows(&self, sql: &str, _b: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
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

    fn execute(&self, sql: &str, b: &[OracleBind]) -> Result<u64, DbError> {
        self.state
            .executed
            .lock()
            .expect("exec mutex")
            .push((sql.to_owned(), b.to_vec()));
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

    fn enable_dbms_output(&self, _buffer_bytes: Option<u32>) -> Result<(), DbError> {
        self.state
            .dbms_output_enabled
            .fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn read_dbms_output(&self, max_lines: usize, max_chars: usize) -> Result<DbmsOutput, DbError> {
        self.state
            .dbms_output_limits
            .lock()
            .expect("output limits mutex")
            .push((max_lines, max_chars));
        Ok(self.state.dbms_output.lock().expect("output mutex").clone())
    }

    fn commit(&self) -> Result<(), DbError> {
        self.state.commits.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn rollback(&self) -> Result<(), DbError> {
        self.state.rollbacks.fetch_add(1, Ordering::SeqCst);
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
            let confirm = execute_confirmation_token(sql, OperatingLevel::ReadWrite, Some("dev"))
                .expect("confirm");
            json!({ "sql": sql, "token": confirm })
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
    for name in TOOL_NAMES {
        let dispatcher = OracleDispatcher::new_switchable(
            Box::new(OneRowMock),
            Some("dev".to_owned()),
            ddl_level(),
            Arc::new(|_| Ok(Box::new(OneRowMock))),
        );
        let out = dispatcher
            .dispatch(name, args_for(name))
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
        Arc::new(|_| Ok(Box::new(OneRowMock))),
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
    assert_eq!(out["connection"]["module"], json!("oraclemcp-test"));
    assert_eq!(out["connection"]["client_identifier"], json!("agent"));
    assert_eq!(out["connection"]["program"], json!("oraclemcp"));
    assert_eq!(
        out["connection"]["client_driver"],
        json!("oraclemcp-driver")
    );
    assert_eq!(out["connection"]["read_only"], json!(false));
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
            json!(["--json", "doctor", "--profile", "dev"])
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
            "#,
    )
    .expect("valid config");

    let out = profiles_response(&cfg);
    assert_eq!(out["profiles"][0]["name"], json!("prod"));
    assert_eq!(out["profiles"][0]["is_default"], json!(true));

    let serialized = serde_json::to_string(&out).expect("json");
    for hidden in [
        "prod:1521/svc",
        "svc_acct",
        "ORACLE_PASSWORD",
        "connect_string",
        "credential_ref",
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
        Arc::new(|_| Err(DbError::Connect("connect failed".to_owned()))),
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
        Arc::new(|_| Ok(Box::new(DescribeFailingMock))),
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
        Arc::new(|_| Ok(Box::new(SourceLookupMock))),
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
                "new_text": "EXECUTE IMMEDIATE 'DROP TABLE T'",
            }),
        )
        .expect("unsafe patch previews but does not mint confirmation");
    assert_eq!(blocked["gate_decision"], json!("blocked"));
    assert_eq!(blocked["confirmation"], Value::Null);
}

#[test]
fn patch_source_execute_refetches_and_uses_create_or_replace_gate() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_switchable(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        ddl_level(),
        Arc::new(|_| Ok(Box::new(OneRowMock))),
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
        .expect("confirm token")
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
        Arc::new(|_| Ok(Box::new(OneRowMock))),
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
        Arc::new(|_| Ok(Box::new(SourceLookupMock))),
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
        Arc::new(|_| Ok(Box::new(OneRowMock))),
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
    for name in TOOL_NAMES {
        let d_empty = OracleDispatcher::new_switchable(
            Box::new(OneRowMock),
            Some("dev".to_owned()),
            ddl_level(),
            Arc::new(|_| Ok(Box::new(OneRowMock))),
        );
        let d_null = OracleDispatcher::new_switchable(
            Box::new(OneRowMock),
            Some("dev".to_owned()),
            ddl_level(),
            Arc::new(|_| Ok(Box::new(OneRowMock))),
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
fn patch_side_effect_marker_catches_comment_wedged_dynamic_sql() {
    let wedged = "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE x IS BEGIN \
                      EXECUTE/**/IMMEDIATE 'DROP TABLE t'; END; END;";
    assert!(
        contains_patch_side_effect_marker(wedged),
        "comment-wedged EXECUTE IMMEDIATE must be detected"
    );
    let plain = "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE x IS BEGIN \
                     EXECUTE IMMEDIATE 'DROP TABLE t'; END; END;";
    assert!(contains_patch_side_effect_marker(plain));
    let pragma = "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE x IS \
                      PRAGMA/**/AUTONOMOUS_TRANSACTION; BEGIN NULL; END; END;";
    assert!(contains_patch_side_effect_marker(pragma));
    let clean = "CREATE OR REPLACE PACKAGE BODY p AS PROCEDURE x IS BEGIN NULL; END; END;";
    assert!(
        !contains_patch_side_effect_marker(clean),
        "a body with no side-effect marker must not be flagged"
    );
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
impl OracleConnection for NoExecMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    fn ping(&self) -> Result<(), DbError> {
        Ok(())
    }
    fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo::default())
    }
    fn query_rows(&self, _sql: &str, _b: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
        panic!("a refused statement must never reach the database (query_rows)")
    }
    fn execute(&self, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
        panic!("a refused statement must never reach the database (execute)")
    }
    fn commit(&self) -> Result<(), DbError> {
        Ok(())
    }
    fn rollback(&self) -> Result<(), DbError> {
        Ok(())
    }
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
        .expect("confirm token");

    let out = dispatcher
        .dispatch(
            "create_or_replace",
            json!({ "source_code": source, "execute": true, "token": confirm }),
        )
        .expect("confirmed apply");
    assert_eq!(out["applied"], json!(true));
    assert_eq!(out["committed"], json!(true));
    assert_eq!(out["detected_object"]["owner"], json!("APP"));
    assert_eq!(out["detected_object"]["name"], json!("EMP_V"));
    assert_eq!(out["errors"], json!([]));
    assert_eq!(out["error_count"], json!(0));
    assert_eq!(state.commits.load(Ordering::SeqCst), 1);
    let executed = state.executed.lock().expect("exec mutex");
    assert_eq!(executed.len(), 1);
    assert_eq!(executed[0].0, source);
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
        .expect("confirm token");
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
        .expect("confirm token");

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
    assert_eq!(
        preview["execute_confirmation"]["confirm"]
            .as_str()
            .expect("token")
            .len(),
        16
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
fn confirmation_tokens_are_stable_hex_and_domain_separated() {
    let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
    let execute = execute_confirmation_token(sql, OperatingLevel::ReadWrite, Some("dev"))
        .expect("write token");
    let execute_normalized = execute_confirmation_token(
        "  UPDATE   employees SET name = name WHERE employee_id = 100; ",
        OperatingLevel::ReadWrite,
        Some("dev"),
    )
    .expect("write token");
    assert_eq!(execute, execute_normalized);

    let other_profile = execute_confirmation_token(sql, OperatingLevel::ReadWrite, Some("prod"))
        .expect("write token");
    let session = session_level_confirmation_token(Some("dev"), OperatingLevel::ReadWrite, 60);
    let compile = compile_confirmation_token(
        &["ALTER PACKAGE APP.EMP_API COMPILE".to_owned()],
        Some("dev"),
        "APP",
        "EMP_API",
        "PACKAGE",
        false,
    );

    for token in [&execute, &other_profile, &session, &compile] {
        assert_eq!(token.len(), 16);
        assert!(token.chars().all(|ch| ch.is_ascii_hexdigit()));
    }
    assert_ne!(execute, other_profile);
    assert_ne!(execute, session);
    assert_ne!(execute, compile);
    assert_ne!(session, compile);
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
                "sql": "BEGIN DBMS_OUTPUT.PUT_LINE('first'); DBMS_OUTPUT.PUT_LINE('second'); END;",
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
                "sql": "BEGIN DBMS_OUTPUT.PUT_LINE('x'); END;",
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
fn execute_approved_replays_preview_token_once() {
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
    assert_eq!(out["committed"], json!(true));
    assert_eq!(out["rolled_back"], json!(false));
    assert_eq!(state.commits.load(Ordering::SeqCst), 1);
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 0);
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);

    let err = dispatcher
        .dispatch("execute_approved", json!({ "token": token }))
        .expect_err("token is one shot");
    assert_eq!(err.error_class, ErrorClass::ChallengeRequired);
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);
}

#[test]
fn execute_approved_accepts_stateless_sql_and_token() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        read_write_level(),
    );
    let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
    let token =
        execute_confirmation_token(sql, OperatingLevel::ReadWrite, Some("dev")).expect("confirm");

    let out = dispatcher
        .dispatch(
            "execute_approved",
            json!({ "sql": sql, "token": token, "commit": false }),
        )
        .expect("execute approved with sql");
    assert_eq!(out["committed"], json!(false));
    assert_eq!(out["rolled_back"], json!(true));
    assert_eq!(state.commits.load(Ordering::SeqCst), 0);
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 1);
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
    let token =
        execute_confirmation_token(sql, OperatingLevel::ReadWrite, Some("dev")).expect("confirm");

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
    assert_eq!(
        preview["statements"][0],
        json!("ALTER SESSION SET PLSQL_WARNINGS = 'ENABLE:ALL'")
    );
    assert_eq!(
        preview["statements"][1],
        json!("ALTER SESSION SET PLSCOPE_SETTINGS = 'IDENTIFIERS:ALL, STATEMENTS:ALL'")
    );
    assert_eq!(
        preview["statements"][2],
        json!("ALTER PACKAGE APP.EMP_API COMPILE BODY")
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
    assert_eq!(
        preview["statements"][0],
        json!("ALTER SESSION SET PLSQL_WARNINGS = 'ENABLE:ALL'")
    );
    assert_eq!(
        preview["statements"][1],
        json!("ALTER PACKAGE APP.EMP_API COMPILE")
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
    assert_eq!(executed.len(), 2);
    assert_eq!(
        executed[0].0,
        "ALTER SESSION SET PLSQL_WARNINGS = 'ENABLE:ALL'"
    );
    assert_eq!(executed[1].0, "ALTER PACKAGE APP.EMP_API COMPILE");
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
    let confirm =
        execute_confirmation_token(sql, OperatingLevel::ReadWrite, Some("dev")).expect("confirm");

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
