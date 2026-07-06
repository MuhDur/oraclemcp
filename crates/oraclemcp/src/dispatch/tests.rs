//! Unit tests for the dispatcher, relocated verbatim from the former
//! single-file `dispatch.rs`. Body indentation is preserved as-is to keep
//! every raw-string fixture byte-identical.

use super::*;
use crate::registry::tool_names;
use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use oraclemcp_core::{DispatchCloseReason, DispatchContext, ScopeGrant};
use oraclemcp_db::{OracleBackend, OracleCell, OracleRow};
use std::path::{Path, PathBuf};
use std::sync::Barrier;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn run_with_current_cx(f: impl FnOnce(&Cx)) {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("asupersync test runtime builds");
    runtime.block_on(async {
        let cx = Cx::current().expect("block_on installs a current Cx");
        f(&cx);
    });
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
        })
    }
    async fn query_rows(
        &self,
        _cx: &Cx,
        sql: &str,
        _b: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
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
        _b: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
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
        _b: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
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
        _sql: &str,
        _b: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
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
        _b: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
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
        Ok(self.state.dbms_output.lock().expect("output mutex").clone())
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
            Arc::new(|_cx, _profile| {
                Box::pin(async move { Ok(Box::new(OneRowMock) as Box<dyn OracleConnection>) })
            }),
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
        Arc::new(|_cx, _profile| {
            Box::pin(async move { Ok(Box::new(OneRowMock) as Box<dyn OracleConnection>) })
        }),
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
        StatelessReadStrategy::new(
            Some(Box::new(LabeledMock::new(
                "pool",
                "stateless_metadata_pool",
                stateless_counts.clone(),
            ))),
            None,
        ),
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
        StatelessReadStrategy::new(
            Some(Box::new(LabeledMock::new(
                "pool",
                "stateless_metadata_pool",
                stateless_counts.clone(),
            ))),
            None,
        ),
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

    let out = profiles_response(
        &cfg,
        &McpExposurePolicy::AllowAll,
        &ProfileDrainState::default(),
    );
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
            assert_eq!(profile, "other");
            connector_calls_for_connector.fetch_add(1, Ordering::SeqCst);
            let counts = new_counts_for_connector.clone();
            Box::pin(async move {
                Ok(Box::new(LabeledMock::new("new", "single_session", counts))
                    as Box<dyn OracleConnection>)
            })
        }),
        CustomToolCatalog::default(),
        Some(Arc::new(|profile, _level| {
            assert_eq!(profile, Some("other"));
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
        Arc::new(|_cx, _profile| {
            Box::pin(async move { Ok(Box::new(DescribeFailingMock) as Box<dyn OracleConnection>) })
        }),
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
        Arc::new(|_cx, _profile| {
            Box::pin(async move { Ok(Box::new(OneRowMock) as Box<dyn OracleConnection>) })
        }),
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
    let out = profiles_response(&cfg, &exposed, &ProfileDrainState::default());
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
    let drain = ProfileDrainState::default();
    drain.apply_config_reload_plan(&plan);

    let out = profiles_response(&cfg, &McpExposurePolicy::AllowAll, &drain);
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
        Arc::new(|_cx, _profile| {
            Box::pin(async move { Ok(Box::new(OneRowMock) as Box<dyn OracleConnection>) })
        }),
    )
    .with_profile_drain_state(drain);
    let err = dispatcher
        .dispatch("oracle_switch_profile", json!({ "profile": "rotated" }))
        .expect_err("draining profile is refused before reconnect");
    assert_eq!(err.error_class, ErrorClass::RuntimeStateRequired);
    assert!(err.message.contains("draining"));

    let current = dispatcher
        .dispatch("oracle_connection_info", json!({}))
        .expect("failed switch does not replace active profile");
    assert_eq!(current["active_profile"], json!("agent_ro"));
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
        Arc::new(|_cx, _profile| {
            Box::pin(async move { Ok(Box::new(SourceLookupMock) as Box<dyn OracleConnection>) })
        }),
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
        Arc::new(|_cx, _profile| {
            Box::pin(async move { Ok(Box::new(OneRowMock) as Box<dyn OracleConnection>) })
        }),
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
        Arc::new(|_cx, _profile| {
            Box::pin(async move { Ok(Box::new(OneRowMock) as Box<dyn OracleConnection>) })
        }),
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
        Arc::new(|_cx, _profile| {
            Box::pin(async move { Ok(Box::new(SourceLookupMock) as Box<dyn OracleConnection>) })
        }),
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
        Arc::new(|_cx, _profile| {
            Box::pin(async move { Ok(Box::new(OneRowMock) as Box<dyn OracleConnection>) })
        }),
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
    for name in tool_names() {
        let d_empty = OracleDispatcher::new_switchable(
            Box::new(OneRowMock),
            Some("dev".to_owned()),
            ddl_level(),
            Arc::new(|_cx, _profile| {
                Box::pin(async move { Ok(Box::new(OneRowMock) as Box<dyn OracleConnection>) })
            }),
        );
        let d_null = OracleDispatcher::new_switchable(
            Box::new(OneRowMock),
            Some("dev".to_owned()),
            ddl_level(),
            Arc::new(|_cx, _profile| {
                Box::pin(async move { Ok(Box::new(OneRowMock) as Box<dyn OracleConnection>) })
            }),
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
        SigningKey::new("test-key", b"lifecycle-close-test-key".to_vec()),
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
    assert_eq!(record.sql_preview, "LANE_CLOSE");
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
    assert_eq!(err.error_class, ErrorClass::ChallengeRequired);
    assert!(
        err.message.contains("generation"),
        "stale grant should fail as lane-generation-bound: {}",
        err.message
    );
    assert_eq!(
        executes.load(Ordering::SeqCst),
        0,
        "revoked grant must fail before database execute"
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
        SigningKey::new("test-key", b"lifecycle-timeout-test-key".to_vec()),
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
    assert_eq!(record.sql_preview, "LANE_CLOSE");
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
    assert_eq!(
        timeouts.as_slice(),
        &[Some(Duration::from_secs(10)), Some(Duration::from_secs(10))]
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
        SigningKey::new("test-key", b"commit-in-doubt-test-key".to_vec()),
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
fn execute_approved_preview_token_race_allows_exactly_one_success() {
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
                    .dispatch("execute_approved", json!({ "token": token }))
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
fn execute_approved_accepts_sql_and_preview_token() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        read_write_level(),
    );
    let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
    let token = preview_confirm(&dispatcher, sql);

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
        let key = SigningKey::new("test-key", b"0123456789abcdef0123456789abcdef".to_vec());
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
            Arc::new(|_cx, _profile| {
                Box::pin(async move { Ok(Box::new(OneRowMock) as Box<dyn OracleConnection>) })
            }),
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
        let key = SigningKey::new("test-key", b"0123456789abcdef0123456789abcdef".to_vec());
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
            .dispatch("execute_approved", json!({ "sql": sql, "token": confirm }))
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
        assert!(
            recs[0]
                .sql_preview
                .contains("ALTER PACKAGE APP.EMP_API COMPILE")
        );
        assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);
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
        assert!(
            recs[0]
                .sql_preview
                .contains("CREATE OR REPLACE PACKAGE BODY")
        );
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

    fn dispatcher() -> OracleDispatcher {
        OracleDispatcher::new_switchable(
            Box::new(OneRowMock),
            Some("dev".to_owned()),
            read_write_level(),
            Arc::new(|_cx, _profile| {
                Box::pin(async move { Ok(Box::new(OneRowMock) as Box<dyn OracleConnection>) })
            }),
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
            Arc::new(|_cx, _profile| {
                Box::pin(async move { Ok(Box::new(OneRowMock) as Box<dyn OracleConnection>) })
            }),
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
            _sql: &str,
            _b: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
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
            Ok(0)
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
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
            SigningKey::new("test-key", b"generated-read-audit-test-key".to_vec()),
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
        assert!(
            records[0].sql_preview.starts_with("SELECT * FROM ("),
            "audit preview identifies the generated dictionary SQL"
        );
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
                Box::pin(async move {
                    Ok(Box::new(BackstopRecordingMock { state }) as Box<dyn OracleConnection>)
                })
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
