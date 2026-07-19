use super::*;
use crate::capabilities::{CapabilitiesReport, FeatureTiers};
use crate::server::{DispatchContext, DispatchFuture, ToolDispatch, ToolStreamFrame};
use crate::tools::ToolRegistry;
use asupersync::channel::{mpsc, oneshot};
use asupersync::{CancelReason, Cx, Outcome, PanicPayload};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use oraclemcp_guard::{Classifier, OperatingLevel};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

struct NoopDispatch;
impl ToolDispatch for NoopDispatch {
    fn dispatch<'a>(
        &'a self,
        _cx: &'a Cx,
        _context: DispatchContext<'a>,
        _name: &'a str,
        _args: Value,
    ) -> DispatchFuture<'a> {
        Box::pin(async { Outcome::Ok(serde_json::json!({})) })
    }
}

struct BusyDispatch;
impl ToolDispatch for BusyDispatch {
    fn dispatch<'a>(
        &'a self,
        _cx: &'a Cx,
        _context: DispatchContext<'a>,
        _name: &'a str,
        _args: Value,
    ) -> DispatchFuture<'a> {
        Box::pin(async {
            Outcome::Err(
                ErrorEnvelope::new(ErrorClass::Busy, "test lane mailbox is full")
                    .with_retry_after_ms(250),
            )
        })
    }
}

struct AtCapacityDispatch;
impl ToolDispatch for AtCapacityDispatch {
    fn dispatch<'a>(
        &'a self,
        _cx: &'a Cx,
        _context: DispatchContext<'a>,
        _name: &'a str,
        _args: Value,
    ) -> DispatchFuture<'a> {
        Box::pin(async {
            Outcome::Err(
                ErrorEnvelope::new(ErrorClass::AtCapacity, "stateful lane capacity exhausted")
                    .with_retry_after_ms(250),
            )
        })
    }
}

struct PolicyDeniedDispatch;
impl ToolDispatch for PolicyDeniedDispatch {
    fn dispatch<'a>(
        &'a self,
        _cx: &'a Cx,
        _context: DispatchContext<'a>,
        _name: &'a str,
        _args: Value,
    ) -> DispatchFuture<'a> {
        Box::pin(async {
            Outcome::Err(ErrorEnvelope::new(
                ErrorClass::PolicyDenied,
                "test policy denied the operator action",
            ))
        })
    }
}

struct CancelledDispatch;
impl ToolDispatch for CancelledDispatch {
    fn dispatch<'a>(
        &'a self,
        _cx: &'a Cx,
        _context: DispatchContext<'a>,
        _name: &'a str,
        _args: Value,
    ) -> DispatchFuture<'a> {
        Box::pin(async { Outcome::Cancelled(CancelReason::timeout()) })
    }
}

struct PanickedDispatch;
impl ToolDispatch for PanickedDispatch {
    fn dispatch<'a>(
        &'a self,
        _cx: &'a Cx,
        _context: DispatchContext<'a>,
        _name: &'a str,
        _args: Value,
    ) -> DispatchFuture<'a> {
        Box::pin(async { Outcome::Panicked(PanicPayload::new("test panic")) })
    }
}

struct ScopeEchoDispatch;
impl ToolDispatch for ScopeEchoDispatch {
    fn dispatch<'a>(
        &'a self,
        _cx: &'a Cx,
        context: DispatchContext<'a>,
        name: &'a str,
        _args: Value,
    ) -> DispatchFuture<'a> {
        let scopes = context
            .scope_grant()
            .map(|grant| grant.0.clone())
            .unwrap_or_default();
        let session_id = context.http_session_id().map(str::to_owned);
        let principal_key = context.principal_key().map(str::to_owned);
        Box::pin(async move {
            Outcome::Ok(serde_json::json!({
                "tool": name,
                "scopes": scopes,
                "session_id": session_id,
                "principal_key": principal_key,
            }))
        })
    }
}

/// QA100 `.116`: a dispatcher whose structured result is far larger than a
/// small whole-response budget, used to prove oversized responses are refused
/// before they reach the wire or the stateful replay store.
struct BigResultDispatch {
    payload_bytes: usize,
}
impl ToolDispatch for BigResultDispatch {
    fn dispatch<'a>(
        &'a self,
        _cx: &'a Cx,
        _context: DispatchContext<'a>,
        _name: &'a str,
        _args: Value,
    ) -> DispatchFuture<'a> {
        let blob = "Q".repeat(self.payload_bytes);
        Box::pin(async move { Outcome::Ok(serde_json::json!({ "blob": blob })) })
    }
}

struct LaneThreadDispatch;
impl ToolDispatch for LaneThreadDispatch {
    fn dispatch<'a>(
        &'a self,
        _cx: &'a Cx,
        _context: DispatchContext<'a>,
        name: &'a str,
        _args: Value,
    ) -> DispatchFuture<'a> {
        let tool = name.to_owned();
        Box::pin(async move {
            Outcome::Ok(serde_json::json!({
                "tool": tool,
                "thread": format!("{:?}", std::thread::current().id()),
            }))
        })
    }
}

struct CountingDispatch {
    calls: Arc<AtomicUsize>,
}

impl ToolDispatch for CountingDispatch {
    fn dispatch<'a>(
        &'a self,
        _cx: &'a Cx,
        _context: DispatchContext<'a>,
        name: &'a str,
        args: Value,
    ) -> DispatchFuture<'a> {
        let call = self.calls.fetch_add(1, AtomicOrdering::SeqCst) + 1;
        let tool = name.to_owned();
        Box::pin(async move {
            Outcome::Ok(serde_json::json!({
                "tool": tool,
                "call": call,
                "args": args,
            }))
        })
    }
}

struct WorkbenchDispatch {
    calls: Arc<AtomicUsize>,
}

impl ToolDispatch for WorkbenchDispatch {
    fn dispatch<'a>(
        &'a self,
        _cx: &'a Cx,
        _context: DispatchContext<'a>,
        name: &'a str,
        args: Value,
    ) -> DispatchFuture<'a> {
        let call = self.calls.fetch_add(1, AtomicOrdering::SeqCst) + 1;
        let tool = name.to_owned();
        Box::pin(async move {
            let classification = args.get("sql").and_then(Value::as_str).map(|sql| {
                let decision = Classifier::default().classify(sql);
                serde_json::json!({
                    "required_level": decision.required_level,
                    "danger": decision.danger,
                    "reason": decision.reason,
                })
            });
            Outcome::Ok(serde_json::json!({
                "tool": tool,
                "call": call,
                "args": args,
                "classification": classification,
            }))
        })
    }
}

struct SourceHistoryDispatch {
    calls: Arc<Mutex<Vec<(String, Value)>>>,
}

impl ToolDispatch for SourceHistoryDispatch {
    fn dispatch<'a>(
        &'a self,
        _cx: &'a Cx,
        _context: DispatchContext<'a>,
        name: &'a str,
        args: Value,
    ) -> DispatchFuture<'a> {
        self.calls.lock().push((name.to_owned(), args.clone()));
        let tool = name.to_owned();
        Box::pin(async move {
            if tool == "oracle_get_source" {
                return Outcome::Ok(serde_json::json!({
                    "source": {
                        "owner": "APP",
                        "name": "EMP_API",
                        "object_type": "PACKAGE BODY",
                        "source": "PACKAGE BODY emp_api AS BEGIN NULL; END;",
                        "line_count": 1,
                        "char_count": 39,
                        "truncated": false
                    }
                }));
            }
            let classification = args.get("sql").and_then(Value::as_str).map(|sql| {
                let decision = Classifier::default().classify(sql);
                serde_json::json!({
                    "required_level": decision.required_level,
                    "danger": decision.danger,
                    "reason": decision.reason,
                })
            });
            Outcome::Ok(serde_json::json!({
                "tool": tool,
                "args": args,
                "classification": classification,
            }))
        })
    }
}

struct QuotedSourceHistoryDispatch {
    calls: Arc<Mutex<Vec<(String, Value)>>>,
    return_wrong_unquoted_object: bool,
}

impl ToolDispatch for QuotedSourceHistoryDispatch {
    fn dispatch<'a>(
        &'a self,
        _cx: &'a Cx,
        _context: DispatchContext<'a>,
        name: &'a str,
        args: Value,
    ) -> DispatchFuture<'a> {
        self.calls.lock().push((name.to_owned(), args.clone()));
        let tool = name.to_owned();
        let wrong = self.return_wrong_unquoted_object;
        Box::pin(async move {
            if tool == "oracle_get_source" {
                let (owner, name, source) = if wrong {
                    ("APP", "FOO", "PROCEDURE FOO IS BEGIN NULL; END;")
                } else {
                    ("App", "foo", "PROCEDURE \"foo\" IS BEGIN NULL; END;")
                };
                return Outcome::Ok(serde_json::json!({
                    "source": {
                        "owner": owner,
                        "name": name,
                        "object_type": "PROCEDURE",
                        "source": source,
                        "line_count": 1,
                        "char_count": source.len(),
                        "truncated": false
                    }
                }));
            }
            Outcome::Ok(serde_json::json!({
                "tool": tool,
                "args": args,
            }))
        })
    }
}

fn server_with_dispatch(dispatcher: Arc<dyn ToolDispatch>) -> OracleMcpServer {
    let report = CapabilitiesReport::new(
        "0.1.0",
        vec![],
        OperatingLevel::ReadOnly,
        FeatureTiers {
            live_db: false,
            engine: true,
            http_transport: true,
        },
    );
    OracleMcpServer::new("0.1.0", ToolRegistry::new(), report, dispatcher)
}

fn test_server() -> OracleMcpServer {
    server_with_dispatch(Arc::new(NoopDispatch))
}

fn scope_echo_server() -> OracleMcpServer {
    let report = CapabilitiesReport::new(
        "0.1.0",
        vec![],
        OperatingLevel::ReadOnly,
        FeatureTiers {
            live_db: false,
            engine: true,
            http_transport: true,
        },
    );
    OracleMcpServer::new(
        "0.1.0",
        ToolRegistry::new(),
        report,
        Arc::new(ScopeEchoDispatch),
    )
}

fn busy_server() -> OracleMcpServer {
    let report = CapabilitiesReport::new(
        "0.1.0",
        vec![],
        OperatingLevel::ReadOnly,
        FeatureTiers {
            live_db: false,
            engine: true,
            http_transport: true,
        },
    );
    OracleMcpServer::new("0.1.0", ToolRegistry::new(), report, Arc::new(BusyDispatch))
}

fn at_capacity_server() -> OracleMcpServer {
    let report = CapabilitiesReport::new(
        "0.1.0",
        vec![],
        OperatingLevel::ReadOnly,
        FeatureTiers {
            live_db: false,
            engine: true,
            http_transport: true,
        },
    );
    OracleMcpServer::new(
        "0.1.0",
        ToolRegistry::new(),
        report,
        Arc::new(AtCapacityDispatch),
    )
}

fn cancelled_server() -> OracleMcpServer {
    server_with_dispatch(Arc::new(CancelledDispatch))
}

fn panicked_server() -> OracleMcpServer {
    server_with_dispatch(Arc::new(PanickedDispatch))
}

fn init_body() -> Value {
    serde_json::json!({
        "jsonrpc":"2.0",
        "id":1,
        "method":"initialize",
        "params":{
            "protocolVersion":"2025-11-25",
            "capabilities":{},
            "clientInfo":{"name":"t","version":"1.0"}
        }
    })
}

fn post(body: &Value) -> HttpRequest {
    HttpRequest::new(
        "POST",
        MCP_PATH,
        [
            ("host", "127.0.0.1"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
        ],
        body.to_string().into_bytes(),
    )
}

include!("tests_config.rs");
fn response_json(response: &HttpResponse) -> Value {
    serde_json::from_slice(&response.body).expect("response body is JSON")
}

fn operator_auditor() -> (Arc<Auditor>, Arc<oraclemcp_audit::MemoryAuditSink>) {
    struct SharedSink(Arc<oraclemcp_audit::MemoryAuditSink>);
    impl oraclemcp_audit::AuditSink for SharedSink {
        fn append(
            &self,
            record: &oraclemcp_audit::AuditRecord,
        ) -> Result<(), oraclemcp_audit::AuditError> {
            self.0.append(record)
        }

        fn flush(&self) -> Result<(), oraclemcp_audit::AuditError> {
            self.0.flush()
        }
    }

    let sink = Arc::new(oraclemcp_audit::MemoryAuditSink::default());
    let key = oraclemcp_audit::SigningKey::new(
        "operator-test",
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .expect("valid test key");
    let auditor = Arc::new(Auditor::new(Box::new(SharedSink(Arc::clone(&sink))), key));
    (auditor, sink)
}

fn assert_operator_audit_pair(
    records: &[AuditRecord],
    expected_decision: AuditDecision,
    expected_outcome: AuditOutcome,
) {
    assert_eq!(records.len(), 2, "one request emits attempt + terminal");
    let attempt = &records[0];
    let terminal = &records[1];
    assert_eq!(attempt.tool, "operator_api");
    assert_eq!(terminal.tool, "operator_api");
    assert_eq!(attempt.outcome, AuditOutcome::Pending);
    assert_eq!(attempt.decision, AuditDecision::Allowed);
    assert_eq!(terminal.decision, expected_decision);
    assert_eq!(terminal.outcome, expected_outcome);
    assert_eq!(attempt.sql_sha256, terminal.sql_sha256);
    let attempt_correlation = attempt.correlation.as_ref().expect("attempt correlation");
    let terminal_correlation = terminal.correlation.as_ref().expect("terminal correlation");
    assert_eq!(attempt_correlation.parent_seq, None);
    assert_eq!(terminal_correlation.parent_seq, Some(attempt.seq));
    assert_eq!(
        terminal_correlation.request_sha256,
        attempt_correlation.request_sha256
    );
    assert!(attempt.hash_is_valid());
    assert!(terminal.hash_is_valid());
}

#[derive(Default)]
struct FailTerminalAuditSink {
    appends: AtomicUsize,
    records: Mutex<Vec<AuditRecord>>,
}

impl oraclemcp_audit::AuditSink for FailTerminalAuditSink {
    fn append(&self, record: &AuditRecord) -> Result<(), oraclemcp_audit::AuditError> {
        if self.appends.fetch_add(1, AtomicOrdering::SeqCst) == 0 {
            self.records.lock().push(record.clone());
            Ok(())
        } else {
            Err(oraclemcp_audit::AuditError::Io(
                "forced terminal append failure".to_owned(),
            ))
        }
    }

    fn flush(&self) -> Result<(), oraclemcp_audit::AuditError> {
        Ok(())
    }
}

fn terminal_failing_operator_auditor() -> (Arc<Auditor>, Arc<FailTerminalAuditSink>) {
    struct SharedSink(Arc<FailTerminalAuditSink>);
    impl oraclemcp_audit::AuditSink for SharedSink {
        fn append(&self, record: &AuditRecord) -> Result<(), oraclemcp_audit::AuditError> {
            self.0.append(record)
        }

        fn flush(&self) -> Result<(), oraclemcp_audit::AuditError> {
            self.0.flush()
        }
    }

    let sink = Arc::new(FailTerminalAuditSink::default());
    let key = oraclemcp_audit::SigningKey::new(
        "operator-terminal-failure-test",
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .expect("valid test key");
    (
        Arc::new(Auditor::new(Box::new(SharedSink(Arc::clone(&sink))), key)),
        sink,
    )
}

fn audit_tail_fixture_path(name: &str) -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("../../target/tmp/operator-audit-tail-tests");
    std::fs::create_dir_all(&dir).expect("create audit tail fixture dir");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos();
    dir.push(format!("{name}-{}-{nanos}.jsonl", std::process::id()));
    dir
}

fn client_credential_fixture_path(name: &str) -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("../../target/tmp/client-credential-http-tests");
    std::fs::create_dir_all(&dir).expect("create client credential fixture dir");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos();
    dir.push(format!("{name}-{}-{nanos}", std::process::id()));
    dir
}

fn audit_tail_draft(
    subject_id: &str,
    tool: &str,
    sql: &str,
    danger_level: &str,
    outcome: AuditOutcome,
    db_evidence: Option<DbEvidence>,
) -> AuditEntryDraft {
    AuditEntryDraft {
        subject: AuditSubject::new("operator", subject_id).with_authn_method("loopback"),
        db_evidence,
        cancel: None,
        result_masking: None,
        tool: tool.to_owned(),
        sql: sql.to_owned(),
        danger_level: danger_level.to_owned(),
        decision: AuditDecision::Allowed,
        rows_affected: Some(3),
        outcome,
    }
}

fn write_audit_tail_fixture(name: &str, break_second_hash: bool) -> PathBuf {
    let key =
        oraclemcp_audit::SigningKey::new("tail-test", b"0123456789abcdef0123456789abcdef".to_vec())
            .expect("valid test key");
    let db_evidence = DbEvidence {
        availability: Some("captured".to_owned()),
        db_unique_name: Some("ORCLPDB1".to_owned()),
        service_name: Some("orclpdb1".to_owned()),
        instance_name: Some("orcl".to_owned()),
        session_user: Some("APP_USER".to_owned()),
        current_user: Some("APP_USER".to_owned()),
        current_schema: Some("APP".to_owned()),
        sid: Some("123".to_owned()),
        serial_number: Some("456".to_owned()),
        client_identifier: Some("operator-dashboard".to_owned()),
        module: Some("oraclemcp".to_owned()),
        action: Some("oracle_execute".to_owned()),
        database_role: Some("PRIMARY".to_owned()),
        open_mode: Some("READ WRITE".to_owned()),
        ..Default::default()
    };
    let drafts = [
        audit_tail_draft(
            "human@example.test",
            "oracle_execute",
            "UPDATE accounts SET flag=:1 WHERE id=:2",
            "GUARDED",
            AuditOutcome::Succeeded,
            Some(db_evidence),
        ),
        audit_tail_draft(
            "other@example.test",
            "oracle_query",
            "SELECT * FROM accounts WHERE id=:1",
            "SAFE",
            AuditOutcome::Succeeded,
            None,
        ),
    ];
    let mut previous_hash = GENESIS_HASH.to_owned();
    let records: Vec<AuditRecord> = drafts
        .iter()
        .enumerate()
        .map(|(index, draft)| {
            let record = AuditRecord::chained_signed(
                draft,
                u64::try_from(index + 1).expect("fixture index fits u64"),
                &previous_hash,
                format!("2026-06-30T12:00:0{index}Z"),
                &key,
            );
            previous_hash = record.entry_hash.clone();
            record
        })
        .collect();
    let path = audit_tail_fixture_path(name);
    let mut file = std::fs::File::create(&path).expect("create audit tail fixture");
    for (index, record) in records.iter().enumerate() {
        let mut value = serde_json::to_value(record).expect("serialize audit fixture");
        if index == 0 {
            value["bind_values"] = serde_json::json!(["sensitive-bind-value"]);
        }
        if break_second_hash && index == 1 {
            value["entry_hash"] = serde_json::json!("sha256:broken");
        }
        writeln!(file, "{value}").expect("write audit fixture line");
    }
    path
}

fn write_certificate_audit_tail_fixture(name: &str) -> PathBuf {
    let key = oraclemcp_audit::SigningKey::new(
        "certificate-tail-test",
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .expect("valid test key");
    let path = audit_tail_fixture_path(name);
    let certificate = Classifier::default()
        .classify("SELECT payroll.secret_bonus FROM payroll WHERE employee_id = :secret_employee")
        .verdict_certificate()
        .clone()
        .with_observed_scn(Some(42_000_001))
        .audit_certificate()
        .expect("the guard's registered certificate must project to audit evidence");
    let auditor = Auditor::new(
        Box::new(
            oraclemcp_audit::FileAuditSink::open(&path).expect("open private audit-tail fixture"),
        ),
        key,
    );
    let record = auditor
        .append_correlated_with_observed_scn_and_verdict_certificate(
            &audit_tail_draft(
                "human@example.test",
                "oracle_query",
                "SELECT payroll.secret_bonus FROM payroll WHERE employee_id = :secret_employee",
                "SAFE",
                AuditOutcome::Succeeded,
                None,
            ),
            "2026-07-13T09:00:00Z".to_owned(),
            true,
            None,
            Some(42_000_001),
            Some(&certificate),
        )
        .expect("certificate-bearing record must fsync before returning");
    assert!(record.hash_is_valid());
    assert!(record.verdict_certificate_core_hash.is_some());
    drop(auditor);
    path
}

#[test]
fn request_target_preserves_and_decodes_query_string() {
    let request = HttpRequest::new(
        "GET",
        "/mcp?cursor=1%2F0&status=active+lane&status=blocked",
        [("host", "127.0.0.1")],
        Vec::new(),
    );

    assert_eq!(request.path, MCP_PATH);
    assert_eq!(
        request.query_string.as_deref(),
        Some("cursor=1%2F0&status=active+lane&status=blocked")
    );
    assert_eq!(request.query_param("cursor"), Some("1/0"));
    let statuses: Vec<&str> = request.query_values("status").collect();
    assert_eq!(statuses, vec!["active lane", "blocked"]);
}

include!("tests_operator.rs");
include!("tests_ci_lanes.rs");
fn dashboard_test_dir(name: &str) -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("../../target/tmp/dashboard-http-tests");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    dir.push(format!("{}-{nanos}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dashboard test dir");
    dir
}

#[derive(Clone)]
struct TestConfigReloadApplier {
    applied: Arc<Mutex<Vec<Vec<String>>>>,
}

impl crate::config_ops::ConfigReloadApplier for TestConfigReloadApplier {
    fn apply_config_reload_plan(
        &self,
        plan: &oraclemcp_config::ConfigReloadPlan,
        _expected: &oraclemcp_config::OracleMcpConfig,
        _next: &oraclemcp_config::OracleMcpConfig,
    ) -> crate::config_ops::ConfigReloadApplyReport {
        let draining = plan.draining_profiles();
        self.applied.lock().push(draining.clone());
        crate::config_ops::ConfigReloadApplyReport {
            status: "applied".to_owned(),
            hot_reloadable: true,
            restart_required: Vec::new(),
            draining_profiles: draining,
            message: "test reload applied".to_owned(),
        }
    }
}

type TestConfigOps = (
    Arc<crate::config_ops::ConfigOpsService>,
    PathBuf,
    Arc<Mutex<Vec<Vec<String>>>>,
);

fn config_ops_for_test(name: &str, current_toml: &str) -> TestConfigOps {
    let dir = dashboard_test_dir(name);
    let target = dir.join("profiles.toml");
    std::fs::write(&target, current_toml).expect("write current config");
    let applied = Arc::new(Mutex::new(Vec::new()));
    let service = crate::config_ops::ConfigOpsService::new(
        crate::config_ops::ConfigOpsBackend::open(dir.join("state")).expect("config ops backend"),
        target.clone(),
        Some(Arc::new(TestConfigReloadApplier {
            applied: Arc::clone(&applied),
        })),
    );
    (Arc::new(service), target, applied)
}

fn operator_json_post(path: &'static str, body: &Value) -> HttpRequest {
    HttpRequest::new(
        "POST",
        path,
        [
            ("host", "127.0.0.1"),
            ("content-type", "application/json"),
            ("accept", "application/json"),
        ],
        body.to_string().into_bytes(),
    )
    .with_peer_loopback(true)
}

fn operator_json_get(path: &'static str) -> HttpRequest {
    HttpRequest::new(
        "GET",
        path,
        [("host", "127.0.0.1"), ("accept", "application/json")],
        Vec::new(),
    )
    .with_peer_loopback(true)
}

/// GET with a runtime-owned path and an optional `If-None-Match` validator, for
/// the by-id detail route and conditional-request assertions.
fn operator_get_owned(path: String, if_none_match: Option<&str>) -> HttpRequest {
    let mut headers: Vec<(String, String)> = vec![
        ("host".to_owned(), "127.0.0.1".to_owned()),
        ("accept".to_owned(), "application/json".to_owned()),
    ];
    if let Some(validator) = if_none_match {
        headers.push(("if-none-match".to_owned(), validator.to_owned()));
    }
    HttpRequest::new("GET", path, headers, Vec::new()).with_peer_loopback(true)
}

/// A same-origin submission of the pairing form: the one-time code travels in
/// the body, never the request target (bead oraclemcp-l6xn).
fn pairing_post(code: &str) -> HttpRequest {
    HttpRequest::new(
        "POST",
        DASHBOARD_PAIR_PATH,
        [
            ("host", "127.0.0.1"),
            ("origin", "http://127.0.0.1"),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        format!("{DASHBOARD_PAIRING_CODE_FIELD}={code}").into_bytes(),
    )
    .with_peer_loopback(true)
}

include!("tests_dashboard.rs");
fn sse_json_events(response: &HttpResponse) -> Vec<Value> {
    String::from_utf8(response.body.clone())
        .expect("SSE body is UTF-8")
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .map(|json| serde_json::from_str(json).expect("SSE data is JSON"))
        .collect()
}

include!("tests_stores.rs");
fn oauth_enforcement() -> Arc<OAuthEnforcement> {
    Arc::new(OAuthEnforcement {
        config: ResourceServerConfig {
            resource: "https://oraclemcp.example/mcp".to_owned(),
            allowed_issuers: vec!["https://idp.example".to_owned()],
            authorization_servers: vec!["https://idp.example".to_owned()],
            required_scopes: vec![],
        },
        verifier: Arc::new(
            oraclemcp_auth::Hs256Verifier::new(b"0123456789abcdef0123456789abcdef".to_vec())
                .expect("valid test key"),
        ),
        metadata_url: "https://oraclemcp.example/.well-known/oauth-protected-resource".to_owned(),
    })
}

include!("tests_serve.rs");
include!("tests_serve_tls.rs");
include!("tests_auth.rs");
include!("tests_sse.rs");
