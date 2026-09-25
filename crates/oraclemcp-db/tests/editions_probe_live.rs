//! Mock-free EBR catalog checks against the three disposable Oracle lanes.

#![cfg(feature = "live-xe")]
#![forbid(unsafe_code)]

use std::{
    any::Any,
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    pin::Pin,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use asupersync::{Cx, runtime::RuntimeBuilder};
use oraclemcp_db::{
    AuthAdapter, DbError, EditionsProofStatus, OracleBackend, OracleConnectOptions,
    OracleConnection, OracleConnectionInfo, OracleRow, RustOracleConnection,
    probe_editions_catalog, probe_editions_enabled,
};
use oraclemcp_error::{ErrorClass, ReasonCategory, StatementOutcome};

const LANES: &[(&str, &str, &str)] = &[
    ("XE18", "localhost:1518/XEPDB1", "18."),
    ("XE21", "localhost:1520/XEPDB1", "21."),
    ("FREE23", "localhost:1523/FREEPDB1", "23."),
];

fn enabled() -> bool {
    std::env::var("ORACLEMCP_EDITIONS_LIVE").as_deref() == Ok("1")
}

fn run_with_cx<F, Fut, T>(body: F) -> T
where
    F: FnOnce(Cx) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("runtime");
    runtime.block_on(async move {
        let cx = Cx::current().expect("runtime installs Cx");
        body(cx).await
    })
}

async fn connect(cx: &Cx, lane: &str, default_dsn: &str) -> RustOracleConnection {
    let user = std::env::var(format!("ORACLE_MATRIX_{lane}_USER"))
        .unwrap_or_else(|_| panic!("{lane} live editions user missing"));
    let password = std::env::var(format!("ORACLE_MATRIX_{lane}_PASSWORD"))
        .unwrap_or_else(|_| panic!("{lane} live editions password missing"));
    let dsn = std::env::var(format!("ORACLE_MATRIX_{lane}_DSN"))
        .unwrap_or_else(|_| default_dsn.to_owned());
    assert!(
        dsn.starts_with("localhost:") || dsn.starts_with("127.0.0.1:"),
        "editions matrix runs only against local lab lanes"
    );
    RustOracleConnection::connect(
        cx,
        OracleConnectOptions {
            connect_string: dsn,
            username: Some(user),
            password: Some(password),
            auth_adapter: AuthAdapter::Password,
            ..Default::default()
        },
    )
    .await
    .unwrap_or_else(|error| panic!("{lane} live editions connection failed: {error}"))
}

fn synthetic_owner(lane: &str, marker: &str) -> String {
    let lane = match lane {
        "XE18" => "18",
        "XE21" => "21",
        "FREE23" => "23",
        _ => unreachable!("closed lane list"),
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    format!(
        "OMCP_E{marker}_{lane}_{:X}{:X}",
        std::process::id(),
        stamp & 0xFFFF
    )
}

async fn create_user(cx: &Cx, conn: &RustOracleConnection, owner: &str, password: &str) {
    conn.execute(
        cx,
        &format!("CREATE USER {owner} IDENTIFIED BY \"{password}\""),
        &[],
    )
    .await
    .unwrap_or_else(|error| panic!("synthetic owner creation failed: {error}"));
    conn.execute(cx, &format!("GRANT CREATE SESSION TO {owner}"), &[])
        .await
        .unwrap_or_else(|error| panic!("synthetic owner grant failed: {error}"));
}

async fn drop_user(cx: &Cx, conn: &dyn OracleConnection, owner: &str) -> Result<u64, DbError> {
    conn.execute(cx, &format!("DROP USER {owner} CASCADE"), &[])
        .await
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ObservedStatement {
    Query(String),
    Execute(String),
}

/// Records SQL at the OracleConnection boundary, around a real driver session.
/// An ALTER USER attempt is recorded and refused before it reaches Oracle.
struct EditionsProbeRecordingConnection<'a> {
    inner: &'a dyn OracleConnection,
    statements: Mutex<Vec<ObservedStatement>>,
}

impl<'a> EditionsProbeRecordingConnection<'a> {
    fn new(inner: &'a dyn OracleConnection) -> Self {
        Self {
            inner,
            statements: Mutex::new(Vec::new()),
        }
    }

    fn statements(&self) -> Vec<ObservedStatement> {
        self.statements.lock().expect("statement log lock").clone()
    }
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for EditionsProbeRecordingConnection<'_> {
    fn backend(&self) -> OracleBackend {
        self.inner.backend()
    }

    async fn ping(&self, cx: &Cx) -> Result<(), DbError> {
        self.inner.ping(cx).await
    }

    async fn describe(&self, cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        self.inner.describe(cx).await
    }

    async fn query_rows(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[oraclemcp_db::OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        self.statements
            .lock()
            .expect("statement log lock")
            .push(ObservedStatement::Query(sql.to_owned()));
        self.inner.query_rows(cx, sql, binds).await
    }

    async fn execute(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[oraclemcp_db::OracleBind],
    ) -> Result<u64, DbError> {
        self.statements
            .lock()
            .expect("statement log lock")
            .push(ObservedStatement::Execute(sql.to_owned()));
        if sql.to_ascii_uppercase().contains("ALTER USER") {
            return Err(DbError::Internal(
                "recording connection blocked ALTER USER before Oracle".to_owned(),
            ));
        }
        self.inner.execute(cx, sql, binds).await
    }

    async fn commit(&self, cx: &Cx) -> Result<(), DbError> {
        self.inner.commit(cx).await
    }

    async fn rollback(&self, cx: &Cx) -> Result<(), DbError> {
        self.inner.rollback(cx).await
    }

    async fn close(&self, cx: &Cx) -> Result<(), DbError> {
        self.inner.close(cx).await
    }
}

fn assert_probe_sent_no_alter_user(statements: &[ObservedStatement], lane: &str) {
    assert!(
        statements.iter().all(|statement| match statement {
            ObservedStatement::Query(sql) | ObservedStatement::Execute(sql) => {
                !sql.to_ascii_uppercase().contains("ALTER USER")
            }
        }),
        "{lane} probe sent ALTER USER: {statements:?}"
    );
}

fn assert_probe_sent_only_catalog_reads(statements: &[ObservedStatement], lane: &str) {
    assert_probe_sent_no_alter_user(statements, lane);
    assert!(
        !statements.is_empty()
            && statements.iter().all(|statement| matches!(
                statement,
                ObservedStatement::Query(sql)
                    if sql.trim_start().to_ascii_uppercase().starts_with("SELECT ")
            )),
        "{lane} probe sent a non-query statement: {statements:?}"
    );
}

struct CatchUnwindFuture<F> {
    future: Pin<Box<F>>,
}

impl<F: Future> Future for CatchUnwindFuture<F> {
    type Output = Result<F::Output, Box<dyn Any + Send>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match catch_unwind(AssertUnwindSafe(|| this.future.as_mut().poll(cx))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(output)) => Poll::Ready(Ok(output)),
            Err(payload) => Poll::Ready(Err(payload)),
        }
    }
}

async fn with_synthetic_user_cleanup<T, F>(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owners: &[String],
    body: F,
) -> T
where
    F: Future<Output = T>,
{
    let outcome = CatchUnwindFuture {
        future: Box::pin(body),
    }
    .await;
    let mut cleanup_errors = Vec::new();
    for owner in owners.iter().rev() {
        if let Err(error) = drop_user(cx, conn, owner).await {
            cleanup_errors.push(format!("{owner}: {error}"));
        }
    }
    match outcome {
        Ok(value) => {
            assert!(
                cleanup_errors.is_empty(),
                "synthetic-user cleanup failed: {cleanup_errors:?}"
            );
            value
        }
        Err(payload) => {
            if !cleanup_errors.is_empty() {
                eprintln!("[editions-live] cleanup errors while unwinding: {cleanup_errors:?}");
            }
            resume_unwind(payload)
        }
    }
}

#[derive(Default)]
struct NoopConnection {
    executed: AtomicUsize,
}

#[async_trait::async_trait(?Send)]
impl OracleConnection for NoopConnection {
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
        _binds: &[oraclemcp_db::OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        Ok(Vec::new())
    }

    async fn execute(
        &self,
        _cx: &Cx,
        _sql: &str,
        _binds: &[oraclemcp_db::OracleBind],
    ) -> Result<u64, DbError> {
        self.executed.fetch_add(1, Ordering::SeqCst);
        Ok(0)
    }

    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn close(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

#[test]
fn editions_probe_connection_audit_rejects_planted_alter_user() {
    run_with_cx(|cx| async move {
        let inner = NoopConnection::default();
        let recorder = EditionsProbeRecordingConnection::new(&inner);
        assert!(
            recorder
                .execute(
                    &cx,
                    "ALTER USER SYNTHETIC_PLANTED ENABLE EDITIONS FOR VIEW",
                    &[],
                )
                .await
                .is_err(),
            "recording adapter must block ALTER USER before forwarding"
        );
        let observed = recorder.statements();
        assert!(matches!(
            observed.as_slice(),
            [ObservedStatement::Execute(sql)] if sql.contains("ALTER USER")
        ));
        assert_eq!(inner.executed.load(Ordering::SeqCst), 0);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                assert_probe_sent_only_catalog_reads(&observed, "planted-negative")
            }))
            .is_err(),
            "connection-level assertion must fail on planted ALTER USER"
        );
    });
}

#[test]
fn editions_probe_synthetic_owner_cleanup_runs_while_unwinding() {
    run_with_cx(|cx| async move {
        let inner = NoopConnection::default();
        let owners = vec!["SYNTHETIC_PANIC".to_owned()];
        let caught = CatchUnwindFuture {
            future: Box::pin(with_synthetic_user_cleanup(&cx, &inner, &owners, async {
                panic!("planted assertion panic")
            })),
        }
        .await;
        assert!(
            caught.is_err(),
            "the planted assertion panic must propagate"
        );
        assert_eq!(
            inner.executed.load(Ordering::SeqCst),
            1,
            "the registered synthetic user must be dropped during unwind"
        );
    });
}

fn assert_live_enabled(proof: &oraclemcp_db::EditionsEnabledProof, lane: &str) {
    assert_eq!(proof.owner_enabled, EditionsProofStatus::Proven, "{lane}");
    assert_eq!(proof.type_enabled, EditionsProofStatus::Proven, "{lane}");
    assert!(proof.is_proven(), "{lane}");
    assert_probe_audit(proof, lane);
}

fn assert_refused_before_statement(proof: &oraclemcp_db::EditionsEnabledProof, lane: &str) {
    let refusal = proof.refusal_envelope();
    assert_eq!(refusal.error_class, ErrorClass::PolicyDenied, "{lane}");
    assert_eq!(
        refusal.statement_outcome,
        Some(StatementOutcome::NotStarted),
        "{lane} refusal must stop before a statement starts"
    );
    assert_eq!(
        refusal.structured_reason.unwrap().category,
        ReasonCategory::EditionsNotEnabled,
        "{lane}"
    );
    assert_probe_audit(proof, lane);
}

fn assert_probe_audit(proof: &oraclemcp_db::EditionsEnabledProof, lane: &str) {
    assert!(
        proof.audit_contains_only_catalog_reads(),
        "{lane} editions probe audit contains a non-catalog statement attempt: {:?}",
        proof.audit_records
    );
    for record in &proof.audit_records {
        println!(
            "{}",
            serde_json::json!({
                "case_id":"editions_probe_audit_contains_only_catalog_reads_live",
                "lane":lane,
                "audit_record":record,
                "verdict":"pass"
            })
        );
    }
}

#[test]
fn editions_probe_owner_enabled_live() {
    if !enabled() {
        eprintln!(
            "[editions-live] SKIP; set ORACLEMCP_EDITIONS_LIVE=1 and XE18/XE21/FREE23 credentials"
        );
        return;
    }
    run_with_cx(|cx| async move {
        for (lane, dsn, version_prefix) in LANES {
            let conn = connect(&cx, lane, dsn).await;
            let info = conn.describe(&cx).await.expect("server identity");
            assert!(
                info.server_version
                    .as_deref()
                    .is_some_and(|version| version.starts_with(version_prefix)),
                "{lane} server version did not match the requested lane"
            );
            let owner = synthetic_owner(lane, "PV");
            let password = format!("Ep{}_{:X}", lane, std::process::id());
            with_synthetic_user_cleanup(&cx, &conn, std::slice::from_ref(&owner), async {
                create_user(&cx, &conn, &owner, &password).await;
                conn.execute(
                    &cx,
                    &format!("ALTER USER {owner} ENABLE EDITIONS FOR VIEW"),
                    &[],
                )
                .await
                .unwrap_or_else(|error| panic!("{lane} synthetic EBR setup failed: {error}"));
                let capabilities = probe_editions_catalog(&cx, &conn).await;
                let proof = probe_editions_enabled(&cx, &conn, &capabilities, &owner, "VIEW").await;
                let owner_conn = RustOracleConnection::connect(
                    &cx,
                    OracleConnectOptions {
                        connect_string: (*dsn).to_owned(),
                        username: Some(owner.clone()),
                        password: Some(password.clone()),
                        auth_adapter: AuthAdapter::Password,
                        ..Default::default()
                    },
                )
                .await
                .unwrap_or_else(|error| panic!("{lane} synthetic owner connect failed: {error}"));
                let self_capabilities = probe_editions_catalog(&cx, &owner_conn).await;
                let self_proof =
                    probe_editions_enabled(&cx, &owner_conn, &self_capabilities, &owner, "VIEW")
                        .await;
                assert_live_enabled(&proof, lane);
                assert_live_enabled(&self_proof, lane);
                println!(
                    "{}",
                    serde_json::json!({
                        "case_id":"editions_probe_owner_enabled_live",
                        "lane":lane,
                        "version":info.server_version,
                        "dba_owner_view":proof.owner_evidence_view,
                        "dba_type_view":proof.type_evidence_view,
                        "self_owner_view":self_proof.owner_evidence_view,
                        "self_type_view":self_proof.type_evidence_view,
                        "verdict":"pass"
                    })
                );
            })
            .await;
        }
    });
}

#[test]
fn editions_probe_owner_disabled_refuses_live() {
    if !enabled() {
        return;
    }
    run_with_cx(|cx| async move {
        for (lane, dsn, _) in LANES {
            let conn = connect(&cx, lane, dsn).await;
            let owner = synthetic_owner(lane, "OFF");
            let password = format!("Of{}_{:X}", lane, std::process::id());
            with_synthetic_user_cleanup(&cx, &conn, std::slice::from_ref(&owner), async {
                create_user(&cx, &conn, &owner, &password).await;
                let capabilities = probe_editions_catalog(&cx, &conn).await;
                let proof = probe_editions_enabled(&cx, &conn, &capabilities, &owner, "VIEW").await;
                assert_eq!(proof.owner_enabled, EditionsProofStatus::Disabled, "{lane}");
                assert_eq!(proof.type_enabled, EditionsProofStatus::Disabled, "{lane}");
                assert_refused_before_statement(&proof, lane);
                println!(
                    "{}",
                    serde_json::json!({"case_id":"editions_probe_owner_disabled_refuses_live","lane":lane,"statement_outcome":"NOT_STARTED","verdict":"pass"})
                );
            })
            .await;
        }
    });
}

#[test]
fn editions_probe_type_omitted_refuses_live() {
    if !enabled() {
        return;
    }
    run_with_cx(|cx| async move {
        for (lane, dsn, _) in LANES {
            let conn = connect(&cx, lane, dsn).await;
            let owner = synthetic_owner(lane, "PR");
            let password = format!("Pr{}_{:X}", lane, std::process::id());
            with_synthetic_user_cleanup(&cx, &conn, std::slice::from_ref(&owner), async {
                create_user(&cx, &conn, &owner, &password).await;
                conn.execute(
                    &cx,
                    &format!("ALTER USER {owner} ENABLE EDITIONS FOR PROCEDURE"),
                    &[],
                )
                .await
                .unwrap_or_else(|error| panic!("{lane} procedure-only setup failed: {error}"));
                let capabilities = probe_editions_catalog(&cx, &conn).await;
                let proof = probe_editions_enabled(&cx, &conn, &capabilities, &owner, "VIEW").await;
                assert_eq!(proof.owner_enabled, EditionsProofStatus::Proven, "{lane}");
                assert_eq!(proof.type_enabled, EditionsProofStatus::Disabled, "{lane}");
                assert_refused_before_statement(&proof, lane);
                println!(
                    "{}",
                    serde_json::json!({"case_id":"editions_probe_type_omitted_refuses_live","lane":lane,"object_type":"VIEW","statement_outcome":"NOT_STARTED","verdict":"pass"})
                );
            })
            .await;
        }
    });
}

#[test]
fn editions_probe_other_owner_without_dba_privilege_unknown_live() {
    if !enabled() {
        return;
    }
    run_with_cx(|cx| async move {
        for (lane, dsn, _) in LANES {
            let admin = connect(&cx, lane, dsn).await;
            let low_owner = synthetic_owner(lane, "LOW");
            let target_owner = synthetic_owner(lane, "TG");
            let password = format!("Lo{}_{:X}", lane, std::process::id());
            let cleanup_owners = vec![low_owner.clone(), target_owner.clone()];
            with_synthetic_user_cleanup(&cx, &admin, &cleanup_owners, async {
                create_user(&cx, &admin, &low_owner, &password).await;
                create_user(&cx, &admin, &target_owner, &password).await;
                let low_conn = RustOracleConnection::connect(
                    &cx,
                    OracleConnectOptions {
                        connect_string: (*dsn).to_owned(),
                        username: Some(low_owner.clone()),
                        password: Some(password.clone()),
                        auth_adapter: AuthAdapter::Password,
                        ..Default::default()
                    },
                )
                .await
                .unwrap_or_else(|error| panic!("{lane} low-privilege connect failed: {error}"));
                let capabilities = probe_editions_catalog(&cx, &low_conn).await;
                let proof = probe_editions_enabled(
                    &cx,
                    &low_conn,
                    &capabilities,
                    &target_owner,
                    "VIEW",
                )
                .await;
                drop(low_conn);
                assert_eq!(proof.owner_enabled, EditionsProofStatus::Unknown, "{lane}");
                assert_eq!(proof.type_enabled, EditionsProofStatus::Unknown, "{lane}");
                assert!(!proof.is_proven(), "{lane}");
                assert_refused_before_statement(&proof, lane);
                println!(
                    "{}",
                    serde_json::json!({"case_id":"editions_probe_other_owner_without_dba_privilege_unknown_live","lane":lane,"verdict":"pass"})
                );
            })
            .await;
        }
    });
}

#[test]
fn editions_probe_columns_present_per_version_live() {
    if !enabled() {
        return;
    }
    run_with_cx(|cx| async move {
        for (lane, dsn, version_prefix) in LANES {
            let conn = connect(&cx, lane, dsn).await;
            let capabilities = probe_editions_catalog(&cx, &conn).await;
            assert!(
                capabilities.metadata_visible,
                "{lane} ALL_TAB_COLUMNS unavailable"
            );
            assert!(
                capabilities
                    .server_version
                    .as_deref()
                    .is_some_and(|version| version.starts_with(version_prefix)),
                "{lane} version mismatch"
            );
            assert!(
                !capabilities.audit_records.is_empty()
                    && capabilities.audit_records.iter().all(|record| matches!(
                        record,
                        oraclemcp_db::EditionsProbeAuditRecord::CatalogRead { .. }
                    )),
                "{lane} catalog capability audit must contain the metadata catalog read"
            );
            for column in &capabilities.columns {
                println!(
                    "{}",
                    serde_json::json!({
                        "case_id":"editions_probe_columns_present_per_version_live",
                        "version":capabilities.server_version,
                        "lane":lane,
                        "view":column.view,
                        "column":column.column,
                        "present":column.present,
                        "verdict":"pass"
                    })
                );
            }
        }
    });
}

#[test]
fn editions_probe_audit_contains_only_catalog_reads_live() {
    if !enabled() {
        return;
    }
    run_with_cx(|cx| async move {
        for (lane, dsn, _) in LANES {
            let conn = connect(&cx, lane, dsn).await;
            let recorder = EditionsProbeRecordingConnection::new(&conn);
            let capabilities = probe_editions_catalog(&cx, &recorder).await;
            let session_user = capabilities
                .session_user
                .as_deref()
                .expect("session user in editions capability snapshot");
            let proof =
                probe_editions_enabled(&cx, &recorder, &capabilities, session_user, "VIEW").await;
            assert_probe_audit(&proof, lane);
            let sent = recorder.statements();
            assert_probe_sent_only_catalog_reads(&sent, lane);
            for statement in &sent {
                println!(
                    "{}",
                    serde_json::json!({
                        "case_id":"editions_probe_audit_contains_only_catalog_reads_live",
                        "lane":lane,
                        "connection_statement":format!("{statement:?}"),
                        "verdict":"pass"
                    })
                );
            }

            // Planted negative: exercise the same real-connection wrapper's
            // execute boundary. It records and blocks ALTER USER before the
            // backend sees it; the audit assertion must reject that transcript.
            let planted = EditionsProbeRecordingConnection::new(&conn);
            assert!(
                planted
                    .execute(
                        &cx,
                        "ALTER USER SYNTHETIC_PLANTED ENABLE EDITIONS FOR VIEW",
                        &[],
                    )
                    .await
                    .is_err(),
                "planted ALTER USER must be stopped before Oracle"
            );
            let planted_statements = planted.statements();
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    assert_probe_sent_only_catalog_reads(&planted_statements, lane)
                }))
                .is_err(),
                "connection-level audit must reject a planted ALTER USER"
            );
            println!(
                "{}",
                serde_json::json!({
                    "case_id":"editions_probe_audit_contains_only_catalog_reads_live",
                    "lane":lane,
                    "catalog_read_count":proof.audit_records.len(),
                    "connection_statement_count":sent.len(),
                    "planted_alter_user_rejected":true,
                    "verdict":"pass"
                })
            );
        }
    });
}
