use super::*;
use crate::capabilities::{CapabilitiesReport, FeatureTiers};
use crate::server::{DispatchContext, DispatchFuture, ToolDispatch};
use crate::tools::ToolRegistry;
use asupersync::{CancelReason, Cx, PanicPayload};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use oraclemcp_guard::{Classifier, OperatingLevel};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
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

#[test]
fn request_rate_limiter_uses_bounded_redacted_principal_buckets() {
    let limiters = HttpRequestRateLimiters::new(HttpRequestRateLimitConfig {
        rate_per_second: 1,
        burst: 1,
        max_buckets: 2,
    });
    let now = Time::from_millis(1_000);
    let subject_a = "oauth:alice@example.invalid";
    let subject_b = "oauth:bob@example.invalid";
    let subject_c = "oauth:carol@example.invalid";

    assert!(
        limiters
            .try_admit_at(HTTP_RATE_LIMIT_SCOPE_MCP, subject_a, now)
            .is_ok()
    );
    let rejected = limiters
        .try_admit_at(HTTP_RATE_LIMIT_SCOPE_MCP, subject_a, now)
        .expect_err("second same-scope request is throttled");
    assert_eq!(rejected.scope, HTTP_RATE_LIMIT_SCOPE_MCP);
    assert_eq!(
        rejected.subject_id_hash,
        operator_subject_id_hash(subject_a)
    );
    assert!(rejected.retry_after_ms > 0);

    assert!(
        limiters
            .try_admit_at(HTTP_RATE_LIMIT_SCOPE_OPERATOR, subject_a, now)
            .is_ok(),
        "operator traffic has a separate bucket from MCP traffic for the same subject"
    );
    assert!(
        limiters
            .try_admit_at(HTTP_RATE_LIMIT_SCOPE_MCP, subject_b, now)
            .is_ok()
    );
    assert!(
        limiters
            .try_admit_at(HTTP_RATE_LIMIT_SCOPE_MCP, subject_c, now)
            .is_ok()
    );
    assert_eq!(
        limiters.bucket_count(),
        2,
        "resident limiter buckets stay bounded"
    );

    let metric_bucket_names = limiters.metric_bucket_names();
    assert_eq!(metric_bucket_names.len(), 2);
    for name in metric_bucket_names {
        assert!(name.starts_with("http-rate:"));
        assert!(!name.contains("alice"));
        assert!(!name.contains("bob"));
        assert!(!name.contains("carol"));
        assert!(!name.contains("example.invalid"));
        assert!(!name.contains("oauth:"));
    }
}

#[test]
fn mcp_post_rate_limit_returns_429_retry_after_and_redacts_principal() {
    let limiters = Arc::new(HttpRequestRateLimiters::new(HttpRequestRateLimitConfig {
        rate_per_second: 1,
        burst: 1,
        max_buckets: 8,
    }));
    let cfg = HttpTransportConfig {
        json_response: true,
        request_rate_limits: Arc::clone(&limiters),
        ..Default::default()
    };
    let request = post(&init_body());
    let principal_key = "oauth:alice@example.invalid";

    let first = handle_mcp_post(&test_server(), &cfg, &request, None, Some(principal_key));
    assert_eq!(first.status, 200);
    let second = handle_mcp_post(&test_server(), &cfg, &request, None, Some(principal_key));

    assert_eq!(second.status, 429);
    assert!(
        second
            .headers
            .iter()
            .any(|(name, value)| name == "retry-after" && value == "1")
    );
    let body = String::from_utf8(second.body).expect("rate limit body is UTF-8 JSON");
    assert!(body.contains("\"error_class\":\"AT_CAPACITY\""));
    assert!(body.contains("rate_limit_snapshot"));
    assert!(body.contains("subject-sha256:"));
    assert!(!body.contains(principal_key));
    assert!(!body.contains("alice@example.invalid"));
}

#[test]
fn request_rate_limiter_does_not_throttle_observability_routes() {
    let limiters = Arc::new(HttpRequestRateLimiters::new(HttpRequestRateLimitConfig {
        rate_per_second: 1,
        burst: 1,
        max_buckets: 8,
    }));
    let health = HealthState::new("0.1.0");
    let cfg = HttpTransportConfig {
        json_response: true,
        request_rate_limits: Arc::clone(&limiters),
        observability: ObservabilityState {
            health: Some(health),
            metrics: None,
            readiness_probe: None,
        },
        ..Default::default()
    };
    let request = post(&init_body());
    let principal_key = "oauth:alice@example.invalid";

    let first = handle_mcp_post(&test_server(), &cfg, &request, None, Some(principal_key));
    assert_eq!(first.status, 200);
    let second = handle_mcp_post(&test_server(), &cfg, &request, None, Some(principal_key));
    assert_eq!(second.status, 429);

    let healthz = handle_http_request(&test_server(), &cfg, get(HEALTHZ_PATH));
    assert_eq!(
        healthz.status, 200,
        "health/doctor-style observability probes are not charged to MCP request-rate buckets"
    );
}

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
    let key = oraclemcp_audit::SigningKey::new("operator-test", b"operator-key".to_vec());
    let auditor = Arc::new(Auditor::new(Box::new(SharedSink(Arc::clone(&sink))), key));
    (auditor, sink)
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
        tool: tool.to_owned(),
        sql: sql.to_owned(),
        danger_level: danger_level.to_owned(),
        decision: AuditDecision::Allowed,
        rows_affected: Some(3),
        outcome,
    }
}

fn write_audit_tail_fixture(name: &str, break_second_hash: bool) -> PathBuf {
    let key = oraclemcp_audit::SigningKey::new("tail-test", b"tail-test-key".to_vec());
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

#[test]
fn operator_api_routes_are_typed_json_404_and_parse_query() {
    let (auditor, sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        ..Default::default()
    };
    let response = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            "/operator/v1/sessions?cursor=4%2F0&status=active&profile=prod",
            [("host", "127.0.0.1"), ("accept", "application/json")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );

    assert_eq!(response.status, 404);
    assert_eq!(response.header("content-type"), Some("application/json"));
    let body = response_json(&response);
    assert_eq!(body["protocol_version"], serde_json::json!("operator.v1"));
    assert_eq!(body["schema_version"], serde_json::json!(1));
    assert_eq!(
        body["data"]["error"],
        serde_json::json!("operator_route_not_found")
    );
    assert_eq!(body["data"]["query"]["cursor"], serde_json::json!("4/0"));
    assert_eq!(
        body["data"]["query"]["filters"]["status"],
        serde_json::json!("active")
    );
    assert_eq!(
        body["data"]["query"]["filters"]["profile"],
        serde_json::json!("prod")
    );
    let records = sink.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].tool, "operator_api");
    assert_eq!(records[0].sql_preview, "GET /operator/v1/sessions");
    assert_eq!(
        records[0].subject,
        AuditSubject::new("local-owner", "process-owner").with_authn_method("loopback")
    );

    let bad_host = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            "/operator/v1/sessions",
            [("host", "attacker.example"), ("accept", "application/json")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(bad_host.status, 403);
}

#[test]
fn mcp_protocol_version_header_is_enforced_before_dispatch() {
    let mut request = post(&init_body());
    request
        .headers
        .push(("mcp-protocol-version".to_owned(), "1900-01-01".to_owned()));

    let response = handle_http_request(&test_server(), &HttpTransportConfig::default(), request);

    assert_eq!(response.status, 400);
    assert_eq!(response.header("mcp-protocol-version"), Some("2025-11-25"));
    let body = response_json(&response);
    assert_eq!(
        body["error"],
        serde_json::json!("unsupported_protocol_version")
    );
    assert_eq!(
        body["supported"],
        serde_json::json!(["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"])
    );

    // Field-test regression: every negotiable protocol revision is accepted in
    // the header, so a client that negotiated an older version during
    // initialize is not rejected on subsequent requests.
    for supported in crate::capabilities::SUPPORTED_PROTOCOL_VERSIONS {
        let mut ok_request = post(&init_body());
        ok_request
            .headers
            .push(("mcp-protocol-version".to_owned(), (*supported).to_owned()));
        let ok_response =
            handle_http_request(&test_server(), &HttpTransportConfig::default(), ok_request);
        assert_ne!(
            ok_response.status, 400,
            "supported protocol version {supported} must not be rejected"
        );
    }
}

/// Bead oraclemcp-s693 — per-session protocol-revision hygiene over HTTP:
/// the negotiated version is stored per session; sessions that negotiated
/// 2025-06-18 or later must send MCP-Protocol-Version on every post-init
/// POST; older-negotiated sessions keep the historical leniency; and a
/// second initialize on a live session is rejected with a structured error.
#[test]
fn post_init_requests_require_the_protocol_version_header_per_negotiated_revision() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: true,
        session_store: Some(Arc::new(HttpSessionStore::default())),
        ..Default::default()
    };

    let session_for = |requested: &str| -> String {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": requested,
                "capabilities": {},
                "clientInfo": { "name": "t", "version": "1.0" }
            }
        });
        handle_http_request(&test_server(), &cfg, post(&body))
            .header("mcp-session-id")
            .expect("initialize returns a session id")
            .to_owned()
    };

    let call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": { "name": "oracle_preview_sql", "arguments": { "sql": "SELECT 1 FROM dual" } }
    });
    let call_request = |session_id: &str, header: Option<&str>| {
        let mut headers = vec![
            ("host".to_owned(), "127.0.0.1".to_owned()),
            ("content-type".to_owned(), "application/json".to_owned()),
            (
                "accept".to_owned(),
                "application/json, text/event-stream".to_owned(),
            ),
            ("mcp-session-id".to_owned(), session_id.to_owned()),
        ];
        if let Some(header) = header {
            headers.push(("mcp-protocol-version".to_owned(), header.to_owned()));
        }
        HttpRequest::new("POST", MCP_PATH, headers, call.to_string().into_bytes())
    };

    // A 2025-11-25 session: the header is REQUIRED after initialize.
    let modern = session_for("2025-11-25");
    let missing = handle_http_request(&scope_echo_server(), &cfg, call_request(&modern, None));
    assert_eq!(missing.status, 400);
    let body = response_json(&missing);
    assert_eq!(
        body["error"],
        serde_json::json!("missing_protocol_version_header")
    );
    assert_eq!(body["negotiated"], serde_json::json!("2025-11-25"));
    let with_header = handle_http_request(
        &scope_echo_server(),
        &cfg,
        call_request(&modern, Some("2025-11-25")),
    );
    assert_eq!(with_header.status, 200, "header satisfies the requirement");

    // A 2025-03-26 session keeps the pre-2025-06-18 leniency.
    let legacy = session_for("2025-03-26");
    let lenient = handle_http_request(&scope_echo_server(), &cfg, call_request(&legacy, None));
    assert_eq!(
        lenient.status, 200,
        "older-negotiated sessions are not retroactively held to the header requirement"
    );

    // Re-initialize on a live session is a lifecycle violation.
    let reinit = HttpRequest::new(
        "POST",
        MCP_PATH,
        [
            ("host", "127.0.0.1"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
            ("mcp-session-id", modern.as_str()),
        ],
        init_body().to_string().into_bytes(),
    );
    let rejected = handle_http_request(&test_server(), &cfg, reinit);
    assert_eq!(rejected.status, 400);
    assert_eq!(
        response_json(&rejected)["error"],
        serde_json::json!("session_already_initialized")
    );

    // An initialize with a STALE/unknown session id still starts fresh.
    let fresh = HttpRequest::new(
        "POST",
        MCP_PATH,
        [
            ("host", "127.0.0.1"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
            ("mcp-session-id", "00000000-0000-4000-8000-deadbeefdead"),
        ],
        init_body().to_string().into_bytes(),
    );
    let fresh = handle_http_request(&test_server(), &cfg, fresh);
    assert_eq!(
        fresh.status, 200,
        "stale session id does not block a new initialize"
    );
    assert!(fresh.header("mcp-session-id").is_some());
}

struct StaticReadinessProbe(bool);

impl ReadinessProbe for StaticReadinessProbe {
    fn is_db_reachable(&self) -> bool {
        self.0
    }
}

#[derive(Debug)]
struct StaticLaneLifecycle {
    lanes: Vec<HttpLaneSnapshot>,
}

impl StaticLaneLifecycle {
    fn one_lane() -> Self {
        Self {
            lanes: vec![HttpLaneSnapshot {
                lane_id: "lane-a".to_owned(),
                generation: 7,
                status: "active",
                subject_id_hash: "subject-sha256:abc".to_owned(),
            }],
        }
    }
}

impl HttpSessionLifecycle for StaticLaneLifecycle {
    fn close_session(&self, _session_id: &str, _principal_key: &str) -> bool {
        false
    }

    fn active_lanes(&self) -> Vec<HttpLaneSnapshot> {
        self.lanes.clone()
    }

    fn lane_binding(&self, lane_id: &str) -> Option<HttpLaneBinding> {
        self.lanes
            .iter()
            .find(|lane| lane.lane_id == lane_id)
            .map(|lane| HttpLaneBinding {
                lane_id: lane.lane_id.clone(),
                mcp_session_id: format!("mcp-session:{}", lane.lane_id),
                principal_key: format!("principal:{}", lane.subject_id_hash),
                generation: lane.generation,
            })
    }

    fn capacity_snapshot(&self, scope: &str, subject: &str) -> Option<CapacitySnapshot> {
        Some(crate::admission::AdmissionController::n4_stateful_defaults().snapshot(scope, subject))
    }
}

/// Lane registry that records every close call so a test can prove the operator
/// cancel route terminated the right lane with the right reason.
#[derive(Debug, Default)]
struct CancelRecordingLifecycle {
    closed: std::sync::Mutex<Vec<(String, String, DispatchCloseReason)>>,
}

impl HttpSessionLifecycle for CancelRecordingLifecycle {
    fn close_session(&self, session_id: &str, principal_key: &str) -> bool {
        self.close_session_with_reason(
            session_id,
            principal_key,
            DispatchCloseReason::SessionDelete,
        )
    }

    fn close_session_with_reason(
        &self,
        session_id: &str,
        principal_key: &str,
        reason: DispatchCloseReason,
    ) -> bool {
        self.closed.lock().expect("cancel lock").push((
            session_id.to_owned(),
            principal_key.to_owned(),
            reason,
        ));
        true
    }

    fn active_lanes(&self) -> Vec<HttpLaneSnapshot> {
        vec![HttpLaneSnapshot {
            lane_id: "lane-a".to_owned(),
            generation: 7,
            status: "active",
            subject_id_hash: "subject-sha256:abc".to_owned(),
        }]
    }

    fn lane_binding(&self, lane_id: &str) -> Option<HttpLaneBinding> {
        (lane_id == "lane-a").then(|| HttpLaneBinding {
            lane_id: "lane-a".to_owned(),
            mcp_session_id: "mcp-session:lane-a".to_owned(),
            principal_key: "principal:subject-sha256:abc".to_owned(),
            generation: 7,
        })
    }
}

#[test]
fn operator_lane_cancel_is_operator_gated_and_audited() {
    let (auditor, sink) = operator_auditor();
    let lifecycle = Arc::new(CancelRecordingLifecycle::default());
    let cfg = HttpTransportConfig {
        stateful: true,
        operator_auditor: Some(auditor),
        session_lifecycle: Some(Arc::clone(&lifecycle) as Arc<dyn HttpSessionLifecycle>),
        ..Default::default()
    };
    let cancel_request = |peer_loopback: bool, lane_id: &str| {
        HttpRequest::new(
            "POST",
            "/operator/v1/lanes/cancel",
            [
                ("host", "127.0.0.1"),
                ("content-type", "application/json"),
                ("accept", "application/json"),
            ],
            serde_json::json!({ "lane_id": lane_id })
                .to_string()
                .into_bytes(),
        )
        .with_peer_loopback(peer_loopback)
    };

    // Unauthorized: not the loopback owner and no operator principal. The
    // request is refused by OperatorAuthorityPolicy::authorize before dispatch,
    // so no lane is terminated and nothing is audited as an allowed action.
    let refused = handle_http_request(&test_server(), &cfg, cancel_request(false, "lane-a"));
    assert_eq!(refused.status, 403);
    assert_eq!(
        response_json(&refused)["error"],
        serde_json::json!("operator_authority_required")
    );
    assert!(
        lifecycle.closed.lock().expect("cancel lock").is_empty(),
        "unauthorized cancel must not terminate any lane"
    );
    assert!(
        sink.records().is_empty(),
        "unauthorized cancel must not append an allowed operator audit entry"
    );

    // Authorized loopback operator: terminates the resolved lane, fail-closed,
    // recorded in the operator audit hash-chain.
    let ok = handle_http_request(&test_server(), &cfg, cancel_request(true, "lane-a"));
    assert_eq!(ok.status, 200);
    let body = response_json(&ok);
    assert_eq!(body["data"]["status"], serde_json::json!("terminated"));
    assert_eq!(body["data"]["terminated"], serde_json::json!(true));
    assert_eq!(body["data"]["lane_id"], serde_json::json!("lane-a"));
    assert_eq!(body["data"]["lane_generation"], serde_json::json!(7));
    assert_eq!(body["data"]["reason"], serde_json::json!("operator_cancel"));

    {
        let closed = lifecycle.closed.lock().expect("cancel lock");
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].0, "mcp-session:lane-a");
        assert_eq!(closed[0].1, "principal:subject-sha256:abc");
        assert_eq!(closed[0].2, DispatchCloseReason::OperatorCancel);
    }

    let records = sink.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].tool, "operator_api");
    assert_eq!(records[0].sql_preview, "POST /operator/v1/lanes/cancel");

    // Unknown lane id: 404, no termination.
    let unknown = handle_http_request(&test_server(), &cfg, cancel_request(true, "lane-z"));
    assert_eq!(unknown.status, 404);
    assert_eq!(
        response_json(&unknown)["data"]["error"],
        serde_json::json!("operator_lane_not_found")
    );
    assert_eq!(
        lifecycle.closed.lock().expect("cancel lock").len(),
        1,
        "unknown lane must not terminate anything"
    );
}

fn classifier_ladder_draft(
    tool: &str,
    sql: &str,
    danger: &str,
    decision: AuditDecision,
    outcome: AuditOutcome,
) -> AuditEntryDraft {
    AuditEntryDraft {
        subject: AuditSubject::new("operator", "human@example.test").with_authn_method("loopback"),
        db_evidence: None,
        cancel: None,
        tool: tool.to_owned(),
        sql: sql.to_owned(),
        danger_level: danger.to_owned(),
        decision,
        rows_affected: None,
        outcome,
    }
}

/// Write a self-lane audit fixture that carries one statement per ladder verdict
/// plus an `operator_api` meta entry (which the ladder must skip).
fn write_classifier_ladder_fixture(name: &str) -> PathBuf {
    let key = oraclemcp_audit::SigningKey::new("ladder-test", b"ladder-test-key".to_vec());
    let drafts = [
        classifier_ladder_draft(
            "oracle_query",
            "SELECT * FROM dual",
            "READ_ONLY",
            AuditDecision::Allowed,
            AuditOutcome::Succeeded,
        ),
        classifier_ladder_draft(
            "oracle_execute",
            "UPDATE accounts SET flag=:1 WHERE id=:2",
            "READ_WRITE",
            AuditDecision::StepUpRequired,
            AuditOutcome::Pending,
        ),
        classifier_ladder_draft(
            "oracle_execute",
            "DROP TABLE accounts",
            "DDL",
            AuditDecision::Blocked,
            AuditOutcome::Failed,
        ),
        classifier_ladder_draft(
            "operator_api",
            "GET /operator/v1/health",
            "OPERATOR",
            AuditDecision::Allowed,
            AuditOutcome::Succeeded,
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
    let mut file = std::fs::File::create(&path).expect("create classifier ladder fixture");
    for record in &records {
        let value = serde_json::to_value(record).expect("serialize ladder fixture");
        writeln!(file, "{value}").expect("write ladder fixture line");
    }
    path
}

#[test]
fn operator_events_stream_classifier_verdicts_for_ladder() {
    let path = write_classifier_ladder_fixture("verdicts");
    let (auditor, _sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        operator_audit_tail_path: Some(path),
        session_lifecycle: Some(Arc::new(StaticLaneLifecycle::one_lane())),
        ..Default::default()
    };

    let events = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            "/operator/v1/events",
            [("host", "127.0.0.1"), ("accept", "text/event-stream")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(events.status, 200);

    let snapshot = sse_json_events(&events)[0].clone();
    let classifier = &snapshot["data"]["classifier"];
    assert_eq!(classifier["source"], serde_json::json!("self_lane"));
    let verdicts = classifier["verdicts"]
        .as_array()
        .expect("classifier verdicts array");
    // Three classified statements are surfaced; the operator_api meta entry is
    // not a classified statement, so the ladder skips it.
    assert_eq!(verdicts.len(), 3);

    let mapped: Vec<(String, String, String)> = verdicts
        .iter()
        .map(|verdict| {
            (
                verdict["decision"].as_str().expect("decision").to_owned(),
                verdict["verdict"].as_str().expect("verdict").to_owned(),
                verdict["ladder"].as_str().expect("ladder").to_owned(),
            )
        })
        .collect();
    assert!(mapped.contains(&("ALLOWED".to_owned(), "PASS".to_owned(), "PASS".to_owned())));
    assert!(mapped.contains(&(
        "STEP_UP_REQUIRED".to_owned(),
        "HOLD".to_owned(),
        "HOLD-FOR-GO".to_owned()
    )));
    assert!(mapped.contains(&(
        "BLOCKED".to_owned(),
        "REFUSED".to_owned(),
        "REFUSED-exceeds-ceiling".to_owned()
    )));
    assert!(
        verdicts
            .iter()
            .all(|verdict| verdict["tool"] != serde_json::json!("operator_api")),
        "operator_api meta entries must not appear on the classifier ladder"
    );

    // The ladder is derived from the redacted tail: no SQL text leaks onto the
    // stream, only the sha256 fingerprint.
    let rendered = classifier.to_string();
    assert!(
        !rendered.contains("DROP TABLE") && !rendered.contains("SELECT"),
        "classifier verdict stream must not carry SQL text"
    );
    assert!(
        verdicts[0]["sql_sha256"]
            .as_str()
            .expect("sql fingerprint")
            .starts_with("sha256:")
    );
}

#[test]
fn operator_v1_serves_schema_health_events_and_action_mapping() {
    let (auditor, sink) = operator_auditor();
    let health = oraclemcp_telemetry::HealthState::new(env!("CARGO_PKG_VERSION"));
    health.set_ready(true);
    let metrics = Arc::new(oraclemcp_telemetry::Metrics::new());
    metrics.record_request("oracle_query", "ok");
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        session_lifecycle: Some(Arc::new(StaticLaneLifecycle::one_lane())),
        observability: ObservabilityState {
            health: Some(health),
            metrics: Some(metrics),
            readiness_probe: Some(Arc::new(StaticReadinessProbe(true))),
        },
        ..Default::default()
    };

    let schema = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            "/operator/v1/schema",
            [("host", "127.0.0.1"), ("accept", "application/json")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(schema.status, 200);
    let schema_body = response_json(&schema);
    assert_eq!(
        schema_body["x-oraclemcp-protocol-version"],
        serde_json::json!("operator.v1")
    );
    assert!(
        schema_body["routes"]
            .as_array()
            .expect("routes")
            .iter()
            .any(|route| route["path"] == "/operator/v1/actions/preview")
    );

    let health_response = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            "/operator/v1/health",
            [("host", "127.0.0.1"), ("accept", "application/json")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(health_response.status, 200);
    let health_body = response_json(&health_response);
    assert_eq!(
        health_body["data"]["readiness"]["status"],
        serde_json::json!("ok")
    );
    assert_eq!(
        health_body["data"]["readiness"]["db_reachable"],
        serde_json::json!(true)
    );

    let metrics_response = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            "/operator/v1/metrics",
            [("host", "127.0.0.1"), ("accept", "application/json")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(metrics_response.status, 200);
    let metrics_body = response_json(&metrics_response);
    assert_eq!(
        metrics_body["data"]["snapshot"]["active_lanes"],
        serde_json::json!(1)
    );
    assert_eq!(
        metrics_body["data"]["snapshot"]["active_lane_gauges"][0]["lane_id"],
        serde_json::json!("lane-a")
    );
    assert_eq!(
        metrics_body["data"]["snapshot"]["active_lane_gauges"][0]["subject_id_hash"],
        serde_json::json!("subject-sha256:abc")
    );
    assert_eq!(
        metrics_body["data"]["capacity"]["read_pool"]["configured_per_profile"],
        serde_json::json!(16)
    );
    assert_eq!(
        metrics_body["data"]["capacity"]["stateful_lanes"]["configured"]["global"],
        serde_json::json!(64)
    );
    assert_eq!(
        metrics_body["data"]["capacity"]["stateful_lanes"]["effective"]["regular_global_cap"],
        serde_json::json!(62)
    );
    assert_eq!(
        metrics_body["data"]["capacity"]["stateful_lanes"]["reserve"]["operator"],
        serde_json::json!(1)
    );
    assert_eq!(
        metrics_body["data"]["capacity"]["stateful_lanes"]["retry_after_ms"],
        serde_json::json!(250)
    );
    assert_eq!(
        metrics_body["data"]["capacity"]["transport"]["accepted_connection_workers"]["regular_global_cap"],
        serde_json::json!(62)
    );
    assert_eq!(
        metrics_body["data"]["capacity"]["transport"]["sse_subscribers"]["per_subject_cap"],
        serde_json::json!(8)
    );
    assert_eq!(
        metrics_body["data"]["capacity"]["idle_reaping"]["ttl_seconds"],
        serde_json::json!(900)
    );

    let events = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            "/operator/v1/events",
            [("host", "127.0.0.1"), ("accept", "text/event-stream")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(events.status, 200);
    assert_eq!(events.header("content-type"), Some("text/event-stream"));
    let event = sse_json_events(&events)[0].clone();
    assert_eq!(event["schema_version"], serde_json::json!(1));
    assert_eq!(event["lane_id"], serde_json::json!("operator"));
    assert!(
        event["subject_id_hash"]
            .as_str()
            .expect("subject hash")
            .starts_with("subject-sha256:")
    );

    let action_body = serde_json::json!({
        "tool": "oracle_preview_sql",
        "arguments": { "sql": "SELECT 1 FROM dual" }
    });
    let action = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "POST",
            "/operator/v1/actions/preview",
            [
                ("host", "127.0.0.1"),
                ("content-type", "application/json"),
                ("accept", "application/json"),
            ],
            action_body.to_string().into_bytes(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(action.status, 200);
    let action_body = response_json(&action);
    assert_eq!(
        action_body["data"]["mcp_tool"],
        serde_json::json!("oracle_preview_sql")
    );
    assert_eq!(
        action_body["data"]["status"],
        serde_json::json!("forwarded")
    );

    let records = sink.records();
    assert!(
        records.len() >= 5,
        "schema, health, metrics, events, and action routes are audited"
    );
    assert_eq!(records[0].sql_preview, "GET /operator/v1/schema");
    assert_eq!(records[1].sql_preview, "GET /operator/v1/health");
    assert_eq!(records[2].sql_preview, "GET /operator/v1/metrics");
    assert_eq!(records[3].sql_preview, "GET /operator/v1/events");
    assert_eq!(records[4].sql_preview, "POST /operator/v1/actions/preview");
}

#[test]
fn audit_tail_filters_exports_redacted_proof_bundle() {
    let path = write_audit_tail_fixture("filters", false);
    let (auditor, _sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        operator_audit_tail_path: Some(path.clone()),
        ..Default::default()
    };

    let response = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            "/operator/v1/audit-tail?limit=5&tool=oracle_execute&level=GUARDED&export=proof-bundle",
            [("host", "127.0.0.1"), ("accept", "application/json")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );

    assert_eq!(response.status, 200);
    let body = response_json(&response);
    let data = &body["data"];
    assert_eq!(data["source"], serde_json::json!("self_lane"));
    assert_eq!(data["scanned_records"], serde_json::json!(2));
    assert_eq!(data["selected_records"], serde_json::json!(1));
    assert_eq!(
        data["proof"]["verification"]["hash_chain"]["status"],
        serde_json::json!("ok")
    );
    assert_eq!(
        data["proof"]["verification"]["keyed_mac"]["status"],
        serde_json::json!("not_checked")
    );
    assert_eq!(
        data["export"]["format"],
        serde_json::json!("oraclemcp.audit.proof-bundle.v1")
    );

    let record = &data["records"][0];
    assert_eq!(record["tool"], serde_json::json!("oracle_execute"));
    assert_eq!(record["danger_level"], serde_json::json!("GUARDED"));
    assert_eq!(
        record["db_evidence"]["current_user"],
        serde_json::json!("APP_USER")
    );
    assert_eq!(
        record["bind_values"]["stored"],
        serde_json::json!(false),
        "bind values are never exported from the audit tail"
    );
    assert_eq!(
        record["proof"]["prev_hash"],
        serde_json::json!(GENESIS_HASH)
    );
    assert!(
        record["proof"]["signature"]
            .as_str()
            .expect("signature")
            .starts_with("hmac-sha256:")
    );

    let rendered = data.to_string();
    assert!(
        !rendered.contains("human@example.test"),
        "raw subject stable ids must not be serialized"
    );
    assert!(
        !rendered.contains("sensitive-bind-value"),
        "unknown/raw bind fields in JSONL must be dropped by the allow-list"
    );
    assert!(
        !rendered.contains("UPDATE accounts"),
        "timeline and proof bundle must not export sql_preview/inlined SQL text"
    );

    let subject_id_hash = record["subject_id_hash"].as_str().expect("subject hash");
    let subject_filter_response = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            format!("/operator/v1/audit-tail?subject_id_hash={subject_id_hash}"),
            [("host", "127.0.0.1"), ("accept", "application/json")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(subject_filter_response.status, 200);
    let subject_filter_body = response_json(&subject_filter_response);
    assert_eq!(
        subject_filter_body["data"]["selected_records"],
        serde_json::json!(1)
    );
    assert_eq!(
        subject_filter_body["data"]["records"][0]["subject_id_hash"],
        serde_json::json!(subject_id_hash)
    );
}

#[test]
fn audit_tail_reports_broken_hash_chain_without_exposing_raw_json_fields() {
    let path = write_audit_tail_fixture("broken", true);
    let (auditor, _sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        operator_audit_tail_path: Some(path),
        ..Default::default()
    };

    let response = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            "/operator/v1/audit-tail?limit=10",
            [("host", "127.0.0.1"), ("accept", "application/json")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );

    assert_eq!(response.status, 200);
    let body = response_json(&response);
    assert_eq!(
        body["data"]["proof"]["verification"]["hash_chain"]["status"],
        serde_json::json!("broken")
    );
    assert_eq!(
        body["data"]["proof"]["verification"]["hash_chain"]["broken"]["check"],
        serde_json::json!("entry_hash")
    );
    assert_eq!(
        body["data"]["records"][1]["proof"]["hash_valid"],
        serde_json::json!(false)
    );
    assert!(
        !body["data"].to_string().contains("sensitive-bind-value"),
        "proof export path must stay allow-list-only even on broken chains"
    );
}

#[test]
fn operator_events_resume_is_lane_scoped() {
    let (auditor, _sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        operator_events: Arc::new(OperatorEventStore::new()),
        ..Default::default()
    };
    let event_request = |target: &'static str, last_event_id: Option<&'static str>| {
        let mut headers = vec![
            ("host".to_owned(), "127.0.0.1".to_owned()),
            ("accept".to_owned(), "text/event-stream".to_owned()),
        ];
        if let Some(last_event_id) = last_event_id {
            headers.push(("last-event-id".to_owned(), last_event_id.to_owned()));
        }
        HttpRequest::new("GET", target, headers, Vec::new()).with_peer_loopback(true)
    };

    let first_a = handle_http_request(
        &test_server(),
        &cfg,
        event_request("/operator/v1/events?lane_id=lane-a", None),
    );
    assert_eq!(first_a.status, 200);
    let first_a_body = String::from_utf8(first_a.body).expect("operator SSE utf-8");
    assert!(first_a_body.contains("id: lane-a/1"));

    let first_b = handle_http_request(
        &test_server(),
        &cfg,
        event_request("/operator/v1/events?lane_id=lane-b", None),
    );
    assert_eq!(first_b.status, 200);
    let first_b_body = String::from_utf8(first_b.body).expect("operator SSE utf-8");
    assert!(first_b_body.contains("id: lane-b/1"));

    let replay_a = handle_http_request(
        &test_server(),
        &cfg,
        event_request("/operator/v1/events?lane_id=lane-a", Some("lane-a/1")),
    );
    assert_eq!(replay_a.status, 200);
    let replay_a_body = String::from_utf8(replay_a.body.clone()).expect("operator SSE utf-8");
    assert!(replay_a_body.contains("id: lane-a/2"));
    assert!(
        !replay_a_body.contains("lane-b"),
        "lane-a resume must not replay lane-b events"
    );
    let replayed = sse_json_events(&replay_a);
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed[0]["event_id"], serde_json::json!("lane-a/2"));
    assert_eq!(replayed[0]["lane_id"], serde_json::json!("lane-a"));
    assert_eq!(
        replayed[0]["redaction_level"],
        serde_json::json!("operator_redacted")
    );

    let mismatch = handle_http_request(
        &test_server(),
        &cfg,
        event_request("/operator/v1/events?lane_id=lane-a", Some("lane-b/1")),
    );
    assert_eq!(mismatch.status, 400);
    assert_eq!(
        response_json(&mismatch)["data"]["error"],
        serde_json::json!("operator_event_cursor_lane_mismatch")
    );

    let subject_a = "operator:subject-a";
    let subject_b = "operator:subject-b";
    let subject_b_hash = operator_subject_id_hash(subject_b);
    cfg.operator_events
        .append_snapshot_and_resume(
            subject_a,
            "shared-lane",
            None,
            None,
            false,
            serde_json::json!({ "source": "subject-a-1" }),
        )
        .expect("append subject-a event");
    cfg.operator_events
        .append_snapshot_and_resume(
            subject_b,
            "shared-lane",
            None,
            None,
            false,
            serde_json::json!({ "source": "subject-b-1" }),
        )
        .expect("append subject-b event");
    let subject_a_resume = cfg
        .operator_events
        .append_snapshot_and_resume(
            subject_a,
            "shared-lane",
            Some("shared-lane/1"),
            Some(1),
            false,
            serde_json::json!({ "source": "subject-a-2" }),
        )
        .expect("resume subject-a stream");
    assert_eq!(subject_a_resume.len(), 1);
    assert_eq!(subject_a_resume[0].id, "shared-lane/2");
    assert_eq!(
        subject_a_resume[0].data["subject_id_hash"],
        serde_json::json!(operator_subject_id_hash(subject_a))
    );
    assert_ne!(
        subject_a_resume[0].data["subject_id_hash"],
        serde_json::json!(subject_b_hash),
        "subject-a resume must not replay subject-b events on the same lane id"
    );
}

#[test]
fn operator_events_last_event_id_reports_gap_for_slow_consumer() {
    let (auditor, _sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        operator_events: Arc::new(OperatorEventStore::new()),
        ..Default::default()
    };
    let event_request = |target: &'static str, last_event_id: Option<&'static str>| {
        let mut headers = vec![
            ("host".to_owned(), "127.0.0.1".to_owned()),
            ("accept".to_owned(), "text/event-stream".to_owned()),
        ];
        if let Some(last_event_id) = last_event_id {
            headers.push(("last-event-id".to_owned(), last_event_id.to_owned()));
        }
        HttpRequest::new("GET", target, headers, Vec::new()).with_peer_loopback(true)
    };

    for _ in 0..=MAX_OPERATOR_EVENTS_PER_STREAM {
        let response = handle_http_request(
            &test_server(),
            &cfg,
            event_request("/operator/v1/events?lane_id=lane-a", None),
        );
        assert_eq!(response.status, 200);
    }

    let gap = handle_http_request(
        &test_server(),
        &cfg,
        event_request("/operator/v1/events?lane_id=lane-a", Some("lane-a/1")),
    );
    assert_eq!(gap.status, 200);
    let body = String::from_utf8(gap.body.clone()).expect("operator SSE utf-8");
    assert!(body.contains("event: operator.stream_gap"));
    assert!(body.contains("id: lane-a/2"));
    assert!(body.contains("\"type\":\"stream_gap\""));
    assert!(body.contains("\"oldest_event_id\":\"lane-a/3\""));
    assert!(
        !body.contains("lane-b"),
        "slow-consumer replay must stay within the requested lane"
    );
    let events = sse_json_events(&gap);
    assert_eq!(
        events[0]["event_type"],
        serde_json::json!("operator.stream_gap")
    );
    assert_eq!(events[0]["lane_id"], serde_json::json!("lane-a"));

    let expired_cursor = handle_http_request(
        &test_server(),
        &cfg,
        event_request("/operator/v1/events?lane_id=lane-a&cursor=lane-a/1", None),
    );
    assert_eq!(expired_cursor.status, 410);
    assert_eq!(
        response_json(&expired_cursor)["data"]["error"],
        serde_json::json!("operator_stream_cursor_expired")
    );
}

#[test]
fn operator_action_idempotency_replays_same_response_and_conflicts_on_drift() {
    let (auditor, _sink) = operator_auditor();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server_with_dispatch(Arc::new(CountingDispatch {
        calls: Arc::clone(&calls),
    }));
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        ..Default::default()
    };
    let first_body = serde_json::json!({
        "idempotency_key": "operator-request-1",
        "tool": "oracle_preview_sql",
        "arguments": { "sql": "UPDATE t SET x = 1 WHERE id = 42" }
    });
    let action_request = |body: &Value| {
        HttpRequest::new(
            "POST",
            "/operator/v1/actions/preview",
            [
                ("host", "127.0.0.1"),
                ("content-type", "application/json"),
                ("accept", "application/json"),
            ],
            body.to_string().into_bytes(),
        )
        .with_peer_loopback(true)
    };

    let first = handle_http_request(&server, &cfg, action_request(&first_body));
    assert_eq!(first.status, 200);
    let second = handle_http_request(&server, &cfg, action_request(&first_body));
    assert_eq!(second.status, 200);
    assert_eq!(
        response_json(&second),
        response_json(&first),
        "same idempotency key and request material replays the original response"
    );
    assert_eq!(
        calls.load(AtomicOrdering::SeqCst),
        1,
        "retry must not re-enter guarded dispatch"
    );
    let first_json = response_json(&first);
    assert_eq!(
        first_json["data"]["idempotency"]["request_id"],
        serde_json::json!("operator-request-1")
    );
    assert!(
        first_json["data"]["idempotency"]["grant_sha256"].is_null(),
        "preview has no consumed confirmation grant"
    );
    assert!(
        first_json["data"]["idempotency"]["sql_sha256"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:"))
    );

    let drifted = serde_json::json!({
        "idempotency_key": "operator-request-1",
        "tool": "oracle_preview_sql",
        "arguments": { "sql": "UPDATE t SET x = 2 WHERE id = 42" }
    });
    let conflict = handle_http_request(&server, &cfg, action_request(&drifted));
    assert_eq!(conflict.status, 409);
    let conflict_json = response_json(&conflict);
    assert_eq!(
        conflict_json["data"]["error"],
        serde_json::json!("operator_idempotency_key_conflict")
    );
    assert_eq!(
        calls.load(AtomicOrdering::SeqCst),
        1,
        "conflicting replay must not re-enter guarded dispatch"
    );
}

#[test]
fn operator_session_set_level_is_lane_bound_preview_apply_drop() {
    let (auditor, _sink) = operator_auditor();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server_with_dispatch(Arc::new(CountingDispatch {
        calls: Arc::clone(&calls),
    }));
    let cfg = HttpTransportConfig {
        stateful: true,
        operator_auditor: Some(auditor),
        session_lifecycle: Some(Arc::new(StaticLaneLifecycle::one_lane())),
        ..Default::default()
    };
    let action_request = |body: &Value| {
        HttpRequest::new(
            "POST",
            "/operator/v1/session/set-level",
            [
                ("host", "127.0.0.1"),
                ("content-type", "application/json"),
                ("accept", "application/json"),
            ],
            body.to_string().into_bytes(),
        )
        .with_peer_loopback(true)
    };

    let missing_lane = handle_http_request(
        &server,
        &cfg,
        action_request(&serde_json::json!({
            "idempotency_key": "level-missing-lane",
            "arguments": { "level": "READ_WRITE", "action": "preview" }
        })),
    );
    assert_eq!(missing_lane.status, 400);
    assert_eq!(
        response_json(&missing_lane)["data"]["error"],
        serde_json::json!("operator_lane_required")
    );

    let preview = handle_http_request(
        &server,
        &cfg,
        action_request(&serde_json::json!({
            "idempotency_key": "level-preview",
            "lane_id": "lane-a",
            "arguments": {
                "level": "READ_WRITE",
                "ttl_seconds": 120,
                "action": "preview",
                "execute": false
            }
        })),
    );
    assert_eq!(preview.status, 200);
    let preview_json = response_json(&preview);
    let preview_result = &preview_json["data"]["mcp_response"]["result"]["structuredContent"];
    assert_eq!(
        preview_json["data"]["mcp_tool"],
        serde_json::json!("oracle_set_session_level")
    );
    assert_eq!(
        preview_json["data"]["idempotency"]["lane_id"],
        serde_json::json!("lane-a")
    );
    assert_eq!(
        preview_json["data"]["idempotency"]["lane_generation"],
        serde_json::json!(7)
    );
    assert_eq!(
        preview_result["tool"],
        serde_json::json!("oracle_set_session_level")
    );
    assert_eq!(
        preview_result["args"]["level"],
        serde_json::json!("READ_WRITE")
    );
    assert_eq!(
        preview_result["args"]["ttl_seconds"],
        serde_json::json!(120)
    );
    assert_eq!(preview_result["args"]["execute"], serde_json::json!(false));

    let apply = handle_http_request(
        &server,
        &cfg,
        action_request(&serde_json::json!({
            "idempotency_key": "level-apply",
            "lane_id": "lane-a",
            "arguments": {
                "level": "READ_WRITE",
                "ttl_seconds": 120,
                "action": "apply",
                "execute": true,
                "confirm": "opaque-session-level-grant"
            }
        })),
    );
    assert_eq!(apply.status, 200);
    let apply_json = response_json(&apply);
    let apply_result = &apply_json["data"]["mcp_response"]["result"]["structuredContent"];
    assert_eq!(apply_result["args"]["execute"], serde_json::json!(true));
    assert_eq!(
        apply_result["args"]["confirm"],
        serde_json::json!("opaque-session-level-grant")
    );

    let drop = handle_http_request(
        &server,
        &cfg,
        action_request(&serde_json::json!({
            "idempotency_key": "level-drop",
            "lane_id": "lane-a",
            "arguments": { "action": "drop" }
        })),
    );
    assert_eq!(drop.status, 200);
    let drop_json = response_json(&drop);
    let drop_result = &drop_json["data"]["mcp_response"]["result"]["structuredContent"];
    assert_eq!(drop_result["args"]["action"], serde_json::json!("drop"));
    assert_eq!(
        calls.load(AtomicOrdering::SeqCst),
        3,
        "missing-lane request must fail before dispatch; preview/apply/drop must dispatch"
    );
}

#[test]
fn operator_idempotency_ledger_reports_in_progress_before_completion() {
    let ledger = OperatorIdempotencyLedger::new();
    let subject = AuditSubject::new("local-owner", "fixture");
    let request = HttpRequest::new(
        "POST",
        "/operator/v1/actions/execute",
        [
            ("host", "127.0.0.1"),
            ("content-type", "application/json"),
            ("accept", "application/json"),
            ("idempotency-key", "execute-once"),
        ],
        Vec::new(),
    )
    .with_peer_loopback(true);
    let payload = serde_json::json!({
        "tool": "oracle_execute",
        "arguments": {
            "sql": "UPDATE t SET x = 1 WHERE id = 7",
            "confirm": "grant-ref"
        }
    });
    let payload = payload.as_object().expect("payload object");
    let arguments = payload.get("arguments").cloned().expect("arguments");
    let facts = operator_idempotency_facts(OperatorIdempotencyInput {
        request: &request,
        payload,
        operator_subject: &subject,
        route: OperatorRouteKind::ActionExecute,
        tool: "oracle_execute",
        arguments: &arguments,
        binding: None,
        operator_audit_seq: 9,
    });

    let lease = match ledger.begin(&request.path, facts.clone()) {
        OperatorIdempotencyBegin::Fresh(lease) => lease,
        _ => panic!("first reservation must be fresh"),
    };
    let in_progress = match ledger.begin(&request.path, facts.clone()) {
        OperatorIdempotencyBegin::InProgress(response) => response,
        _ => panic!("duplicate before completion must be typed in-progress"),
    };
    assert_eq!(in_progress.status, 409);
    let in_progress_json = response_json(&in_progress);
    assert_eq!(
        in_progress_json["data"]["error"],
        serde_json::json!("operator_idempotency_in_progress")
    );
    assert!(
        in_progress_json["data"]["idempotency"]["grant_sha256"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:"))
    );

    let completed = facts.completed("unix:42".to_owned());
    let original = operator_json_response(
        200,
        &request.path,
        json!({ "status": "forwarded", "idempotency": completed.as_json("forwarded") }),
    );
    ledger.complete(lease, completed, original.clone());
    let replay = match ledger.begin(&request.path, facts) {
        OperatorIdempotencyBegin::Replay(response) => response,
        _ => panic!("duplicate after completion must replay"),
    };
    assert_eq!(replay, original);
}

#[test]
fn workbench_no_bypass_guard_is_the_feature() {
    let (auditor, _sink) = operator_auditor();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server_with_dispatch(Arc::new(WorkbenchDispatch {
        calls: Arc::clone(&calls),
    }));
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        ..Default::default()
    };
    let action_request = |path: &'static str, body: &Value| {
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
    };

    let write_sql = "UPDATE accounts SET status = 'HOLD' WHERE id = :1";
    let direct_decision = Classifier::default().classify(write_sql);
    let preview = handle_http_request(
        &server,
        &cfg,
        action_request(
            "/operator/v1/actions/preview",
            &serde_json::json!({
                "idempotency_key": "workbench-preview",
                "tool": "oracle_preview_sql",
                "arguments": { "sql": write_sql }
            }),
        ),
    );
    assert_eq!(preview.status, 200);
    let preview_result =
        response_json(&preview)["data"]["mcp_response"]["result"]["structuredContent"].clone();
    assert_eq!(
        preview_result["tool"],
        serde_json::json!("oracle_preview_sql")
    );
    assert_eq!(preview_result["args"]["sql"], serde_json::json!(write_sql));
    assert_eq!(
        preview_result["classification"]["required_level"],
        serde_json::to_value(direct_decision.required_level).expect("level serializes"),
        "workbench classify must be the same MCP classifier decision agents get"
    );

    let read_sql = "SELECT * FROM dual";
    let read = handle_http_request(
        &server,
        &cfg,
        action_request(
            "/operator/v1/actions/execute",
            &serde_json::json!({
                "idempotency_key": "workbench-read",
                "tool": "oracle_query",
                "arguments": { "sql": read_sql, "max_rows": 100 }
            }),
        ),
    );
    assert_eq!(read.status, 200);
    let read_result =
        response_json(&read)["data"]["mcp_response"]["result"]["structuredContent"].clone();
    assert_eq!(read_result["tool"], serde_json::json!("oracle_query"));
    assert_eq!(read_result["args"]["sql"], serde_json::json!(read_sql));

    let execute = handle_http_request(
        &server,
        &cfg,
        action_request(
            "/operator/v1/actions/execute",
            &serde_json::json!({
                "idempotency_key": "workbench-commit",
                "tool": "oracle_execute",
                "arguments": {
                    "sql": write_sql,
                    "binds": [42],
                    "commit": true,
                    "confirm": "opaque-preview-grant"
                }
            }),
        ),
    );
    assert_eq!(execute.status, 200);
    let execute_result =
        response_json(&execute)["data"]["mcp_response"]["result"]["structuredContent"].clone();
    assert_eq!(execute_result["tool"], serde_json::json!("oracle_execute"));
    assert_eq!(execute_result["args"]["sql"], serde_json::json!(write_sql));
    assert_eq!(execute_result["args"]["commit"], serde_json::json!(true));
    assert_eq!(
        execute_result["args"]["confirm"],
        serde_json::json!("opaque-preview-grant")
    );

    let preview_bypass = handle_http_request(
        &server,
        &cfg,
        action_request(
            "/operator/v1/actions/preview",
            &serde_json::json!({
                "tool": "oracle_execute",
                "arguments": { "sql": write_sql, "commit": true, "confirm": "grant" }
            }),
        ),
    );
    assert_eq!(preview_bypass.status, 400);
    assert_eq!(
        response_json(&preview_bypass)["data"]["error"],
        serde_json::json!("operator_action_tool_not_allowed")
    );

    let compatibility_bypass = handle_http_request(
        &server,
        &cfg,
        action_request(
            "/operator/v1/actions/execute",
            &serde_json::json!({
                "tool": "execute_approved",
                "arguments": { "sql": write_sql, "token": "legacy-token" }
            }),
        ),
    );
    assert_eq!(compatibility_bypass.status, 400);
    assert_eq!(
        response_json(&compatibility_bypass)["data"]["error"],
        serde_json::json!("operator_action_tool_not_allowed")
    );
    assert_eq!(
        calls.load(AtomicOrdering::SeqCst),
        3,
        "blocked workbench bypass attempts must not enter dispatch"
    );
}

#[test]
fn operator_execute_allows_read_only_metadata_tools_for_explorer() {
    let (auditor, _sink) = operator_auditor();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server_with_dispatch(Arc::new(WorkbenchDispatch {
        calls: Arc::clone(&calls),
    }));
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        ..Default::default()
    };
    let action_request = |path: &'static str, body: &Value| {
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
    };
    let metadata_tools = [
        ("oracle_connection_info", serde_json::json!({})),
        (
            "oracle_list_schemas",
            serde_json::json!({ "name_like": "APP%", "max_rows": 10 }),
        ),
        (
            "oracle_search_objects",
            serde_json::json!({
                "owner": "APP",
                "object_type": "TABLE",
                "name_like": "CUSTOMER%",
                "detail_level": "names",
                "max_rows": 10
            }),
        ),
        (
            "oracle_get_ddl",
            serde_json::json!({ "owner": "APP", "name": "CUSTOMERS", "object_type": "TABLE" }),
        ),
        (
            "oracle_get_source",
            serde_json::json!({
                "owner": "APP",
                "name": "PKG_CUSTOMERS",
                "object_type": "PACKAGE",
                "max_chars": 4000
            }),
        ),
        (
            "oracle_plsql_parse",
            serde_json::json!({ "source": "CREATE OR REPLACE PROCEDURE p IS BEGIN NULL; END;" }),
        ),
        (
            "oracle_plsql_analyze",
            serde_json::json!({ "project_root": "." }),
        ),
        (
            "oracle_plsql_lineage",
            serde_json::json!({
                "project_root": ".",
                "target": "APP.PKG_CUSTOMERS",
                "direction": "bidirectional",
                "max_depth": 2
            }),
        ),
        (
            "oracle_plsql_sast",
            serde_json::json!({ "project_root": ".", "format": "json" }),
        ),
        (
            "oracle_plsql_doc",
            serde_json::json!({
                "source": "/** customer package */\nCREATE PACKAGE pkg_customers AS END;",
                "query": "customer"
            }),
        ),
        (
            "oracle_plsql_what_breaks",
            serde_json::json!({
                "changeset": { "objects": [], "unclassified_files": [] },
                "mode": "source_only"
            }),
        ),
    ];
    let expected_count = metadata_tools.len();

    for (tool, arguments) in metadata_tools {
        let response = handle_http_request(
            &server,
            &cfg,
            action_request(
                "/operator/v1/actions/execute",
                &serde_json::json!({
                    "idempotency_key": format!("explorer:{tool}"),
                    "tool": tool,
                    "arguments": arguments
                }),
            ),
        );
        assert_eq!(response.status, 200, "{tool} should be forwarded");
        let result =
            response_json(&response)["data"]["mcp_response"]["result"]["structuredContent"].clone();
        assert_eq!(result["tool"], serde_json::json!(tool));
    }

    let preview_response = handle_http_request(
        &server,
        &cfg,
        action_request(
            "/operator/v1/actions/preview",
            &serde_json::json!({
                "tool": "oracle_search_objects",
                "arguments": { "owner": "APP", "detail_level": "names" }
            }),
        ),
    );
    assert_eq!(preview_response.status, 400);
    assert_eq!(
        response_json(&preview_response)["data"]["error"],
        serde_json::json!("operator_action_tool_not_allowed")
    );
    assert_eq!(
        calls.load(AtomicOrdering::SeqCst),
        expected_count,
        "rejected preview metadata action must not enter dispatch"
    );
}

#[test]
fn dashboard_workbench_ddl_apply_is_release_gated() {
    let (auditor, _sink) = operator_auditor();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server_with_dispatch(Arc::new(WorkbenchDispatch {
        calls: Arc::clone(&calls),
    }));
    let dir = dashboard_test_dir("ddl-gate");
    let auth = Arc::new(DashboardAuth::new(dir.clone()));
    let cfg = HttpTransportConfig {
        dashboard_auth: Some(Arc::clone(&auth)),
        operator_auditor: Some(auditor),
        ..Default::default()
    };
    let ticket = crate::dashboard_auth::mint_dashboard_pairing_ticket(&dir, "http://127.0.0.1")
        .expect("ticket mints");
    let login = auth
        .exchange_ticket(ticket_from_pairing_url(&ticket.url))
        .expect("login works");
    let cookie_pair = login.session_cookie.split(';').next().expect("cookie pair");
    let view = auth
        .session_view(Some(cookie_pair))
        .expect("session view works");
    let execute_ticket = view
        .action_tickets
        .iter()
        .find(|ticket| ticket.path == "/operator/v1/actions/execute")
        .expect("execute action ticket")
        .ticket
        .clone();

    let response = handle_http_request(
        &server,
        &cfg,
        HttpRequest::new(
            "POST",
            "/operator/v1/actions/execute",
            [
                ("host", "127.0.0.1"),
                ("origin", "http://127.0.0.1"),
                ("sec-fetch-site", "same-origin"),
                ("content-type", "application/json"),
                ("accept", "application/json"),
                ("cookie", cookie_pair),
                (DASHBOARD_CSRF_HEADER, view.csrf_token.as_str()),
                (DASHBOARD_ACTION_TICKET_HEADER, execute_ticket.as_str()),
            ],
            serde_json::json!({
                "tool": "oracle_execute",
                "arguments": {
                    "sql": "CREATE TABLE dashboard_apply_blocked (id NUMBER)",
                    "commit": true,
                    "confirm": "opaque-preview-grant"
                }
            })
            .to_string()
            .into_bytes(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(response.status, 403);
    assert_eq!(
        response_json(&response)["data"]["error"],
        serde_json::json!("dashboard_ddl_workbench_disabled")
    );
    assert_eq!(
        calls.load(AtomicOrdering::SeqCst),
        0,
        "browser DDL apply must fail before MCP dispatch"
    );
}

#[test]
fn cp_apply_reclassifies_never_trusts_stored_verdict() {
    let (auditor, _sink) = operator_auditor();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server_with_dispatch(Arc::new(WorkbenchDispatch {
        calls: Arc::clone(&calls),
    }));
    let dir = dashboard_test_dir("cp-reclassify");
    let store = Arc::new(crate::change_proposal::ChangeProposalStore::new(
        crate::file_store::FileStore::open(dir.join("state")).expect("file store"),
    ));
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        change_proposals: Some(store),
        ..Default::default()
    };
    let write_sql = "UPDATE accounts SET status = :1 WHERE id = :2";
    let read_sql = "SELECT status FROM accounts WHERE id = :1";
    let draft = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/change-proposals/draft",
            &serde_json::json!({
                "profile": "prod",
                "author": "agent",
                "title": "Hold account",
                "stored_verdict": { "marker": "never-serialize-stored-verdict" },
                "statements": [{
                    "sql_template": write_sql,
                    "binds": ["HOLD", 42],
                    "stored_verdict": { "marker": "never-serialize-stored-verdict" }
                }, {
                    "sql_template": read_sql,
                    "binds": [42],
                    "unit": "read",
                    "stored_verdict": { "marker": "never-serialize-stored-verdict" }
                }]
            }),
        ),
    );
    assert_eq!(draft.status, 200);
    let draft_json = response_json(&draft);
    let proposal_id = draft_json["data"]["proposal"]["id"]
        .as_str()
        .expect("proposal id");
    assert_eq!(
        draft_json["data"]["proposal"]["statements"][0]["draft_verdict"]["required_level"],
        serde_json::json!("READ_WRITE")
    );
    assert!(
        !draft_json
            .to_string()
            .contains("never-serialize-stored-verdict"),
        "proposal views must not serialize stored verdict payloads"
    );
    assert!(
        !draft_json.to_string().contains("HOLD"),
        "proposal views must not serialize captured bind values"
    );

    let apply = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/change-proposals/apply",
            &serde_json::json!({
                "proposal_id": proposal_id,
                "confirm": "opaque-preview-grant",
                "commit": true,
                "idempotency_key": "cp-apply"
            }),
        ),
    );
    assert_eq!(apply.status, 200);
    let apply_json = response_json(&apply);
    let write_result = &apply_json["data"]["results"][0];
    let read_result = &apply_json["data"]["results"][1];
    assert_eq!(apply_json["data"]["status"], serde_json::json!("applied"));
    assert_eq!(
        write_result["reclassified"]["required_level"],
        serde_json::json!("READ_WRITE"),
        "apply must classify the current SQL template, not trust stored verdicts"
    );
    assert_eq!(
        read_result["reclassified"]["required_level"],
        serde_json::json!("READ_ONLY"),
        "read proposal apply must also classify the current SQL template"
    );
    assert_eq!(
        write_result["stored_verdict_ignored"],
        serde_json::json!(true)
    );
    let dispatched_write =
        &write_result["action_response"]["data"]["mcp_response"]["result"]["structuredContent"];
    let dispatched_read =
        &read_result["action_response"]["data"]["mcp_response"]["result"]["structuredContent"];
    assert_eq!(
        dispatched_write["tool"],
        serde_json::json!("oracle_execute")
    );
    assert_eq!(
        dispatched_write["classification"]["required_level"],
        serde_json::json!("READ_WRITE")
    );
    assert_eq!(
        dispatched_write["args"]["sql"],
        serde_json::json!(write_sql)
    );
    assert_eq!(
        dispatched_write["args"]["binds"],
        serde_json::json!(["HOLD", 42])
    );
    assert_eq!(dispatched_read["tool"], serde_json::json!("oracle_query"));
    assert_eq!(dispatched_read["args"]["sql"], serde_json::json!(read_sql));
    assert_eq!(dispatched_read["args"]["binds"], serde_json::json!([42]));
    assert_eq!(
        calls.load(AtomicOrdering::SeqCst),
        2,
        "proposal apply should enter dispatch once per statement after reclassification"
    );
}

#[test]
fn schema_diff_export_is_redacted_and_review_gated() {
    let (auditor, _sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        ..Default::default()
    };

    let response = handle_http_request(
        &test_server(),
        &cfg,
        operator_json_post(
            "/operator/v1/schema-diff",
            &serde_json::json!({
                "title": "App migration",
                "before": {
                    "objects": [
                        {
                            "object_type": "TABLE",
                            "name": "T_OLD",
                            "ddl": "create table t_old (id number)"
                        },
                        {
                            "object_type": "TABLE",
                            "name": "T_CHANGED",
                            "ddl": "create table t_changed (id number)"
                        }
                    ]
                },
                "after": {
                    "objects": [
                        {
                            "object_type": "TABLE",
                            "name": "T_CHANGED",
                            "ddl": "create table t_changed (id number, name varchar2(30))"
                        },
                        {
                            "object_type": "VIEW",
                            "name": "V_NEW",
                            "ddl": "create or replace view v_new as select id from t_changed"
                        }
                    ]
                }
            }),
        ),
    );

    assert_eq!(response.status, 200);
    let body = response_json(&response);
    assert_eq!(body["data"]["source"], serde_json::json!("schema_diff"));
    assert_eq!(body["data"]["summary"]["added"], serde_json::json!(1));
    assert_eq!(body["data"]["summary"]["dropped"], serde_json::json!(1));
    assert_eq!(body["data"]["summary"]["changed"], serde_json::json!(1));
    assert_eq!(
        body["data"]["diff"]["changed"][0].get("ddl"),
        None,
        "redacted diff view must not expose object DDL"
    );
    assert!(
        body["data"]["diff"]["changed"][0]["ddl_sha256"]
            .as_str()
            .expect("ddl hash")
            .starts_with("sha256:")
    );
    let script = body["data"]["migration_script"]
        .as_str()
        .expect("migration script");
    assert!(script.contains("review artifact only"));
    assert!(script.contains("Oracle DDL commits independently"));
    assert!(script.contains("create or replace view v_new"));
    assert!(script.contains("DROP TABLE T_OLD"));
    assert_eq!(
        body["data"]["proposal_statements"][0]["unit"],
        serde_json::json!("ddl"),
        "apply is via a normal Change Proposal statement"
    );
    assert_eq!(
        body["data"]["proposal_statements"][0]["binds"],
        serde_json::json!([])
    );
}

#[test]
fn source_history_snapshots_prior_source_and_revert_drafts_review_proposal() {
    let (auditor, _sink) = operator_auditor();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let server = server_with_dispatch(Arc::new(SourceHistoryDispatch {
        calls: Arc::clone(&calls),
    }));
    let dir = dashboard_test_dir("source-history");
    let state = dir.join("state");
    let change_proposals = Arc::new(crate::change_proposal::ChangeProposalStore::new(
        crate::file_store::FileStore::open(&state).expect("proposal store"),
    ));
    let source_history = Arc::new(crate::source_history::SourceHistoryStore::new(
        crate::file_store::FileStore::open(&state).expect("source-history store"),
    ));
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        change_proposals: Some(change_proposals),
        source_history: Some(source_history),
        ..Default::default()
    };
    let ddl = "CREATE OR REPLACE PACKAGE BODY app.emp_api AS BEGIN NULL; END;";

    let draft = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/change-proposals/draft",
            &serde_json::json!({
                "profile": "prod",
                "author": "agent",
                "title": "Patch package body",
                "statements": [{
                    "sql_template": ddl,
                    "unit": "ddl",
                    "commit": true
                }]
            }),
        ),
    );
    assert_eq!(draft.status, 200);
    let proposal_id = response_json(&draft)["data"]["proposal"]["id"]
        .as_str()
        .expect("proposal id")
        .to_owned();

    let apply = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/change-proposals/apply",
            &serde_json::json!({
                "proposal_id": proposal_id,
                "confirm": "opaque-preview-grant",
                "commit": true,
                "idempotency_key": "source-history-apply"
            }),
        ),
    );
    assert_eq!(apply.status, 200);
    let apply_json = response_json(&apply);
    let snapshot = &apply_json["data"]["results"][0]["source_snapshot"]["snapshot"];
    assert_eq!(
        apply_json["data"]["results"][0]["source_snapshot"]["status"],
        serde_json::json!("captured")
    );
    assert_eq!(snapshot["owner"], serde_json::json!("APP"));
    assert_eq!(snapshot["name"], serde_json::json!("EMP_API"));
    assert_eq!(snapshot["object_type"], serde_json::json!("PACKAGE BODY"));
    let snapshot_id = snapshot["id"].as_str().expect("snapshot id").to_owned();

    let history = handle_http_request(
        &server,
        &cfg,
        operator_json_get("/operator/v1/source-history"),
    );
    assert_eq!(history.status, 200);
    let history_body = String::from_utf8(history.body.clone()).expect("history utf8");
    assert!(
        !history_body.contains("BEGIN NULL"),
        "source-history list must not serialize source text"
    );
    let history_json = response_json(&history);
    assert_eq!(
        history_json["data"]["snapshots"][0]["id"],
        serde_json::json!(snapshot_id)
    );

    let revert = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/source-history/revert",
            &serde_json::json!({ "snapshot_id": snapshot_id }),
        ),
    );
    assert_eq!(revert.status, 200);
    let revert_json = response_json(&revert);
    assert_eq!(
        revert_json["data"]["status"],
        serde_json::json!("revert_drafted")
    );
    assert_eq!(
        revert_json["data"]["proposal"]["statements"][0]["unit"],
        serde_json::json!("ddl")
    );
    assert!(
        revert_json["data"]["proposal"]["statements"][0]["sql_template"]
            .as_str()
            .expect("revert SQL")
            .starts_with("CREATE OR REPLACE PACKAGE BODY")
    );

    let call_names = calls
        .lock()
        .iter()
        .map(|(tool, _)| tool.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        call_names,
        vec!["oracle_get_source".to_owned(), "oracle_execute".to_owned()]
    );
}

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
    let store = crate::file_store::FileStore::open(dir.join("state")).expect("file store");
    let applied = Arc::new(Mutex::new(Vec::new()));
    let service = crate::config_ops::ConfigOpsService::new(
        crate::config_ops::ConfigOpsBackend::new(store),
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

fn ticket_from_pairing_url(url: &str) -> &str {
    url.split_once("ticket=")
        .map(|(_, token)| token)
        .expect("pairing URL has ticket query")
}

#[test]
fn dashboard_pairing_sets_strict_cookie_and_session_view() {
    let (auditor, _sink) = operator_auditor();
    let dir = dashboard_test_dir("pairing");
    let auth = Arc::new(DashboardAuth::new(dir.clone()));
    let cfg = HttpTransportConfig {
        dashboard_auth: Some(Arc::clone(&auth)),
        operator_auditor: Some(auditor),
        ..Default::default()
    };
    let ticket = crate::dashboard_auth::mint_dashboard_pairing_ticket(&dir, "http://127.0.0.1")
        .expect("ticket mints");
    let token = ticket_from_pairing_url(&ticket.url);

    let pair = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            format!("{DASHBOARD_PAIR_PATH}?ticket={token}"),
            [("host", "127.0.0.1"), ("accept", "text/html")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(pair.status, 303);
    assert_eq!(pair.header("location"), Some("/"));
    assert_eq!(pair.header("referrer-policy"), Some("no-referrer"));
    assert!(
        pair.header("content-security-policy")
            .is_some_and(|csp| csp.contains("frame-ancestors 'none'"))
    );
    let cookie = pair.header("set-cookie").expect("dashboard cookie");
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));
    let cookie_pair = cookie.split(';').next().expect("cookie pair");

    let replay = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            format!("{DASHBOARD_PAIR_PATH}?ticket={token}"),
            [("host", "127.0.0.1"), ("accept", "text/html")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(replay.status, 401, "pairing ticket is single-use");

    let unauth_shell = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            "/",
            [("host", "127.0.0.1"), ("accept", "text/html")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(unauth_shell.status, 401);

    let session = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            DASHBOARD_SESSION_PATH,
            [
                ("host", "127.0.0.1"),
                ("accept", "application/json"),
                ("cookie", cookie_pair),
                ("sec-fetch-site", "same-origin"),
            ],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(session.status, 200);
    assert_eq!(session.header("cache-control"), Some("no-store"));
    let session_json = response_json(&session);
    assert_eq!(
        session_json["csrf_header"],
        serde_json::json!(DASHBOARD_CSRF_HEADER)
    );
    assert_eq!(
        session_json["action_ticket_header"],
        serde_json::json!(DASHBOARD_ACTION_TICKET_HEADER)
    );
    assert!(
        session_json["action_tickets"]
            .as_array()
            .expect("action tickets")
            .iter()
            .any(|ticket| ticket["path"] == "/operator/v1/actions/preview")
    );
    assert!(
        session_json["action_tickets"]
            .as_array()
            .expect("action tickets")
            .iter()
            .any(|ticket| ticket["path"] == "/operator/v1/config/apply")
    );
}

#[test]
fn operator_config_draft_apply_and_rollback_are_redacted_and_audited() {
    let current = r#"
            [[profiles]]
            name = "prod"
            description = "old safe label"
            connect_string = "prod-old:1521/svc"
            credential_ref = "env:OLD_SECRET"
            "#;
    let draft = r#"
            [[profiles]]
            name = "prod"
            description = "new safe label"
            connect_string = "prod-new:1521/svc"
            credential_ref = "env:NEW_SECRET"
            "#;
    let (config_ops, target, applied_plans) = config_ops_for_test("config-ops", current);
    let (auditor, sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        config_ops: Some(config_ops),
        ..Default::default()
    };

    let status = handle_http_request(
        &test_server(),
        &cfg,
        operator_json_get("/operator/v1/config"),
    );
    assert_eq!(status.status, 200);
    let status_json = response_json(&status);
    let current_sha = status_json["data"]["status"]["current_sha256"]
        .as_str()
        .expect("current hash")
        .to_owned();

    let preview = handle_http_request(
        &test_server(),
        &cfg,
        operator_json_post(
            "/operator/v1/config/draft",
            &serde_json::json!({ "draft_toml": draft }),
        ),
    );
    assert_eq!(preview.status, 200);
    let preview_body = String::from_utf8(preview.body.clone()).expect("preview utf8");
    for forbidden in [
        "prod-old:1521/svc",
        "prod-new:1521/svc",
        "env:OLD_SECRET",
        "env:NEW_SECRET",
    ] {
        assert!(
            !preview_body.contains(forbidden),
            "config preview leaked {forbidden}: {preview_body}"
        );
    }
    let preview_json = response_json(&preview);
    assert_eq!(
        preview_json["data"]["preview"]["current_sha256"],
        serde_json::json!(current_sha)
    );

    let apply = handle_http_request(
        &test_server(),
        &cfg,
        operator_json_post(
            "/operator/v1/config/apply",
            &serde_json::json!({
                "draft_toml": draft,
                "expected_current_sha256": current_sha,
            }),
        ),
    );
    assert_eq!(apply.status, 200);
    assert_eq!(std::fs::read_to_string(&target).expect("target"), draft);
    let apply_body = String::from_utf8(apply.body.clone()).expect("apply utf8");
    assert!(!apply_body.contains("env:NEW_SECRET"));
    let apply_json = response_json(&apply);
    assert_eq!(
        apply_json["data"]["outcome"]["reload"]["status"],
        serde_json::json!("applied")
    );
    assert_eq!(
        applied_plans.lock().last().cloned(),
        Some(vec!["prod".to_owned()])
    );
    let rollback_id = apply_json["data"]["outcome"]["rollback_id"]
        .as_str()
        .expect("rollback id")
        .to_owned();

    let rollback = handle_http_request(
        &test_server(),
        &cfg,
        operator_json_post(
            "/operator/v1/config/rollback",
            &serde_json::json!({ "rollback_id": rollback_id }),
        ),
    );
    assert_eq!(rollback.status, 200);
    assert_eq!(std::fs::read_to_string(&target).expect("target"), current);
    assert!(
        sink.records().len() >= 4,
        "status, preview, apply, and rollback should all be operator-audited"
    );
}

#[test]
fn malicious_page_cannot_trigger_dashboard_gated_action() {
    let (auditor, _sink) = operator_auditor();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server_with_dispatch(Arc::new(CountingDispatch {
        calls: Arc::clone(&calls),
    }));
    let dir = dashboard_test_dir("csrf");
    let auth = Arc::new(DashboardAuth::new(dir.clone()));
    let cfg = HttpTransportConfig {
        dashboard_auth: Some(Arc::clone(&auth)),
        operator_auditor: Some(auditor),
        ..Default::default()
    };
    let ticket = crate::dashboard_auth::mint_dashboard_pairing_ticket(&dir, "http://127.0.0.1")
        .expect("ticket mints");
    let login = auth
        .exchange_ticket(ticket_from_pairing_url(&ticket.url))
        .expect("login works");
    let cookie_pair = login.session_cookie.split(';').next().expect("cookie pair");
    let view = auth
        .session_view(Some(cookie_pair))
        .expect("session view works");
    let preview_ticket = view
        .action_tickets
        .iter()
        .find(|ticket| ticket.path == "/operator/v1/actions/preview")
        .expect("preview action ticket")
        .ticket
        .clone();
    let action_body = serde_json::json!({
        "tool": "oracle_preview_sql",
        "arguments": { "sql": "SELECT 1 FROM dual" }
    });

    let malicious = handle_http_request(
        &server,
        &cfg,
        HttpRequest::new(
            "POST",
            "/operator/v1/actions/preview",
            [
                ("host", "127.0.0.1"),
                ("origin", "http://127.0.0.1:3000"),
                ("content-type", "application/json"),
                ("accept", "application/json"),
                ("cookie", cookie_pair),
                (DASHBOARD_CSRF_HEADER, view.csrf_token.as_str()),
                (DASHBOARD_ACTION_TICKET_HEADER, preview_ticket.as_str()),
            ],
            action_body.to_string().into_bytes(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(malicious.status, 403);
    assert_eq!(
        response_json(&malicious)["error"],
        serde_json::json!("dashboard_same_origin_required")
    );
    assert_eq!(
        calls.load(AtomicOrdering::SeqCst),
        0,
        "cross-origin dashboard POST must not reach dispatch"
    );

    let missing_csrf = handle_http_request(
        &server,
        &cfg,
        HttpRequest::new(
            "POST",
            "/operator/v1/actions/preview",
            [
                ("host", "127.0.0.1"),
                ("origin", "http://127.0.0.1"),
                ("content-type", "application/json"),
                ("accept", "application/json"),
                ("cookie", cookie_pair),
                (DASHBOARD_ACTION_TICKET_HEADER, preview_ticket.as_str()),
            ],
            action_body.to_string().into_bytes(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(missing_csrf.status, 401);
    assert_eq!(
        response_json(&missing_csrf)["error"],
        serde_json::json!("dashboard_auth_required")
    );
    assert_eq!(calls.load(AtomicOrdering::SeqCst), 0);

    let valid = handle_http_request(
        &server,
        &cfg,
        HttpRequest::new(
            "POST",
            "/operator/v1/actions/preview",
            [
                ("host", "127.0.0.1"),
                ("origin", "http://127.0.0.1"),
                ("sec-fetch-site", "same-origin"),
                ("content-type", "application/json"),
                ("accept", "application/json"),
                ("cookie", cookie_pair),
                (DASHBOARD_CSRF_HEADER, view.csrf_token.as_str()),
                (DASHBOARD_ACTION_TICKET_HEADER, preview_ticket.as_str()),
            ],
            action_body.to_string().into_bytes(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(valid.status, 200);
    assert_eq!(calls.load(AtomicOrdering::SeqCst), 1);
}

fn sse_json_events(response: &HttpResponse) -> Vec<Value> {
    String::from_utf8(response.body.clone())
        .expect("SSE body is UTF-8")
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .map(|json| serde_json::from_str(json).expect("SSE data is JSON"))
        .collect()
}

#[cfg(not(feature = "dashboard-bundle"))]
#[test]
fn dashboard_bundle_is_absent_from_default_build() {
    let response = handle_http_request(
        &test_server(),
        &HttpTransportConfig::default(),
        HttpRequest::new(
            "GET",
            "/",
            [("host", "127.0.0.1"), ("accept", "text/html")],
            Vec::new(),
        ),
    );

    assert_eq!(response.status, 404);
}

#[cfg(feature = "dashboard-bundle")]
#[test]
fn dashboard_bundle_serves_html_without_api_fallback() {
    let response = handle_http_request(
        &test_server(),
        &HttpTransportConfig::default(),
        HttpRequest::new(
            "GET",
            "/",
            [("host", "127.0.0.1"), ("accept", "text/html")],
            Vec::new(),
        ),
    );

    assert_eq!(response.status, 200);
    assert_eq!(
        response.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(response.header("x-content-type-options"), Some("nosniff"));
    let html = String::from_utf8(response.body).expect("dashboard html is UTF-8");
    assert!(html.contains("oraclemcp"));

    let api = handle_http_request(
        &test_server(),
        &HttpTransportConfig::default(),
        HttpRequest::new(
            "GET",
            "/operator/v1/sessions",
            [("host", "127.0.0.1"), ("accept", "text/html")],
            Vec::new(),
        ),
    );
    assert_eq!(api.status, 406);
}

#[test]
fn mcp_post_enforces_accept_and_content_type_negotiation() {
    let cfg = HttpTransportConfig {
        json_response: true,
        ..Default::default()
    };
    let unacceptable = HttpRequest::new(
        "POST",
        MCP_PATH,
        [
            ("host", "127.0.0.1"),
            ("content-type", "application/json"),
            ("accept", "text/html"),
        ],
        init_body().to_string().into_bytes(),
    );
    let unacceptable = handle_http_request(&test_server(), &cfg, unacceptable);
    assert_eq!(unacceptable.status, 406);

    let wrong_content_type = HttpRequest::new(
        "POST",
        MCP_PATH,
        [
            ("host", "127.0.0.1"),
            ("content-type", "text/plain"),
            ("accept", "application/json"),
        ],
        init_body().to_string().into_bytes(),
    );
    let wrong_content_type = handle_http_request(&test_server(), &cfg, wrong_content_type);
    assert_eq!(wrong_content_type.status, 415);
}

#[test]
fn stateless_delete_is_method_not_allowed_not_false_accepted() {
    let response = handle_http_request(
        &test_server(),
        &HttpTransportConfig::default(),
        HttpRequest::new("DELETE", MCP_PATH, [("host", "127.0.0.1")], Vec::new()),
    );

    assert_eq!(response.status, 405);
    assert_eq!(response.header("allow"), Some("POST"));
}

#[test]
fn stateful_get_replays_buffered_lane_results_by_cursor() {
    let result_store = Arc::new(HttpResultStore::new());
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: true,
        session_store: Some(Arc::new(HttpSessionStore::default())),
        result_store: Some(Arc::clone(&result_store)),
        ..Default::default()
    };
    let lane: Arc<dyn ToolDispatch> = Arc::new(crate::lane::LaneRuntime::spawn(
        "http-buffer-test",
        Arc::new(LaneThreadDispatch),
        4,
    ));
    let server = OracleMcpServer::new(
        "0.1.0",
        ToolRegistry::new(),
        CapabilitiesReport::new(
            "0.1.0",
            vec![],
            OperatingLevel::ReadOnly,
            FeatureTiers {
                live_db: false,
                engine: true,
                http_transport: true,
            },
        ),
        lane,
    );

    let caller_thread = format!("{:?}", std::thread::current().id());
    let init = handle_http_request(&server, &cfg, post(&init_body()));
    let session_id = init
        .header("mcp-session-id")
        .expect("stateful init session id");
    let call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": { "name": "oracle_query", "arguments": { "sql": "SELECT 1 FROM dual" } }
    });
    let post = HttpRequest::new(
        "POST",
        MCP_PATH,
        [
            ("host", "127.0.0.1"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
            ("mcp-session-id", session_id),
            // Session negotiated 2025-11-25 → post-init POSTs carry the header.
            ("mcp-protocol-version", "2025-11-25"),
        ],
        call.to_string().into_bytes(),
    );
    let post = handle_http_request(&server, &cfg, post);
    assert_eq!(post.status, 200);
    let post_body = String::from_utf8(post.body).expect("SSE utf-8");
    assert!(post_body.contains("id: 1/0"));
    assert!(
        !post_body.contains(&caller_thread),
        "tool body must run on the lane thread, not the HTTP caller thread"
    );

    let replay = HttpRequest::new(
        "GET",
        "/mcp?cursor=0",
        [
            ("host", "127.0.0.1"),
            ("accept", "text/event-stream"),
            ("mcp-session-id", session_id),
        ],
        Vec::new(),
    );
    let replay = handle_http_request(&server, &cfg, replay);
    assert_eq!(replay.status, 200);
    assert_eq!(replay.header("content-type"), Some("text/event-stream"));
    let replay_body = String::from_utf8(replay.body).expect("SSE utf-8");
    assert!(replay_body.contains("id: 1/0"));
    assert!(replay_body.contains("\"id\":9"));
    assert!(replay_body.contains("\"tool\":\"oracle_query\""));

    let after = HttpRequest::new(
        "GET",
        "/mcp?cursor=1/0",
        [
            ("host", "127.0.0.1"),
            ("accept", "text/event-stream"),
            ("mcp-session-id", session_id),
        ],
        Vec::new(),
    );
    let after = handle_http_request(&server, &cfg, after);
    let after_body = String::from_utf8(after.body).expect("SSE utf-8");
    assert!(
        !after_body.contains("\"id\":9"),
        "cursor after the buffered event must not replay it again"
    );
}

#[test]
fn stateful_get_reports_typed_expiry_when_cursor_falls_out_of_ring() {
    let session_store = Arc::new(HttpSessionStore::default());
    let result_store = Arc::new(HttpResultStore::new());
    let session_id = "expired-cursor-session";
    // Seeded session pins the pre-2025-06-18 revision: these tests exercise
    // session/cursor semantics, not the post-init protocol-version header
    // requirement (covered by its own tests).
    session_store.insert(
        session_id.to_owned(),
        "anonymous-http".to_owned(),
        "2025-03-26".to_owned(),
    );
    for i in 0..=MAX_BUFFERED_MCP_EVENTS_PER_SESSION {
        result_store.append_response(session_id, serde_json::json!({ "seq": i }));
    }
    let cfg = HttpTransportConfig {
        stateful: true,
        session_store: Some(session_store),
        result_store: Some(result_store),
        ..Default::default()
    };

    let response = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            "/mcp?cursor=0",
            [
                ("host", "127.0.0.1"),
                ("accept", "text/event-stream"),
                ("mcp-session-id", session_id),
            ],
            Vec::new(),
        ),
    );

    assert_eq!(response.status, 410);
    let body: Value = serde_json::from_slice(&response.body).expect("json expiry body");
    assert_eq!(body["error"], serde_json::json!("stream_cursor_expired"));
    assert_eq!(body["oldest_event_id"], serde_json::json!("2/0"));
    assert!(
        body["next_step"]
            .as_str()
            .is_some_and(|message| message.contains("restart the MCP session"))
    );
}

#[test]
fn stateful_get_last_event_id_reports_gap_marker_for_slow_consumer() {
    let session_store = Arc::new(HttpSessionStore::default());
    let result_store = Arc::new(HttpResultStore::new());
    let session_id = "slow-consumer-session";
    // Seeded session pins the pre-2025-06-18 revision: these tests exercise
    // session/cursor semantics, not the post-init protocol-version header
    // requirement (covered by its own tests).
    session_store.insert(
        session_id.to_owned(),
        "anonymous-http".to_owned(),
        "2025-03-26".to_owned(),
    );
    for i in 0..=MAX_BUFFERED_MCP_EVENTS_PER_SESSION {
        result_store.append_response(session_id, serde_json::json!({ "seq": i }));
    }
    let cfg = HttpTransportConfig {
        stateful: true,
        session_store: Some(session_store),
        result_store: Some(result_store),
        ..Default::default()
    };

    let response = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            MCP_PATH,
            [
                ("host", "127.0.0.1"),
                ("accept", "text/event-stream"),
                ("mcp-session-id", session_id),
                ("last-event-id", "0/0"),
            ],
            Vec::new(),
        ),
    );

    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-type"), Some("text/event-stream"));
    let body = String::from_utf8(response.body).expect("SSE utf-8");
    assert!(body.contains("event: stream-gap"));
    assert!(body.contains("id: 1/gap"));
    assert!(body.contains("\"type\":\"stream_gap\""));
    assert!(body.contains("\"oldest_event_id\":\"2/0\""));
    assert!(body.contains("\"seq\":128"));
}

#[test]
fn served_stateful_get_streams_chunked_sse_until_session_closes() {
    fn read_until(stream: &mut TcpStream, raw: &mut Vec<u8>, needle: &[u8]) {
        let mut buf = [0_u8; 512];
        while !raw.windows(needle.len()).any(|window| window == needle) {
            let n = stream
                .read(&mut buf)
                .expect("streaming SSE response remains readable");
            assert_ne!(n, 0, "streaming SSE response ended before expected data");
            raw.extend_from_slice(&buf[..n]);
        }
    }

    let session_store = Arc::new(HttpSessionStore::default());
    let result_store = Arc::new(HttpResultStore::new());
    let session_id = "served-stream-session";
    // Seeded session pins the pre-2025-06-18 revision: these tests exercise
    // session/cursor semantics, not the post-init protocol-version header
    // requirement (covered by its own tests).
    session_store.insert(
        session_id.to_owned(),
        "anonymous-http".to_owned(),
        "2025-03-26".to_owned(),
    );
    result_store.ensure_session(session_id);
    let config = HttpTransportConfig {
        stateful: true,
        session_store: Some(Arc::clone(&session_store)),
        result_store: Some(Arc::clone(&result_store)),
        ..Default::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind streaming test listener");
    let addr = listener.local_addr().expect("streaming listener address");
    let shutdown = Arc::new(AtomicBool::new(false));
    let thread_shutdown = Arc::clone(&shutdown);
    let handle = std::thread::spawn(move || {
        serve_http_until(listener, test_server(), &config, thread_shutdown)
            .expect("streaming HTTP listener exits cleanly");
    });

    let mut stream = TcpStream::connect(addr).expect("connect to streaming listener");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set streaming read timeout");
    let request = format!(
        "GET {MCP_PATH} HTTP/1.1\r\nhost: 127.0.0.1\r\naccept: text/event-stream\r\nmcp-session-id: {session_id}\r\ncontent-length: 0\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .expect("write streaming GET");

    let mut raw = Vec::new();
    read_until(&mut stream, &mut raw, b"\r\n\r\n");
    let text = String::from_utf8_lossy(&raw);
    let head = text
        .split_once("\r\n\r\n")
        .map(|(head, _)| head)
        .expect("streaming HTTP response head");
    assert!(head.contains("transfer-encoding: chunked"));
    assert!(!head.contains("content-length:"));

    result_store.append_response(session_id, serde_json::json!({ "seq": 1 }));
    read_until(&mut stream, &mut raw, b"\"seq\":1");
    let text = String::from_utf8_lossy(&raw);
    assert!(text.contains("content-type: text/event-stream"));
    assert!(text.contains("id: 1/0"));

    result_store.remove_session(session_id);
    shutdown.store(true, Ordering::SeqCst);
    drop(stream);
    handle.join().expect("streaming listener thread joins");
}

#[test]
fn stateful_idle_reaper_closes_by_timeout_and_clears_buffers() {
    #[derive(Debug, Default)]
    struct RecordingLifecycle {
        closed: std::sync::Mutex<Vec<(String, String, DispatchCloseReason)>>,
    }

    impl HttpSessionLifecycle for RecordingLifecycle {
        fn close_session(&self, session_id: &str, principal_key: &str) -> bool {
            self.close_session_with_reason(
                session_id,
                principal_key,
                DispatchCloseReason::SessionDelete,
            )
        }

        fn close_session_with_reason(
            &self,
            session_id: &str,
            principal_key: &str,
            reason: DispatchCloseReason,
        ) -> bool {
            self.closed.lock().expect("test lifecycle mutex").push((
                session_id.to_owned(),
                principal_key.to_owned(),
                reason,
            ));
            true
        }
    }

    let session_store = Arc::new(HttpSessionStore::default());
    let result_store = Arc::new(HttpResultStore::new());
    let lifecycle = Arc::new(RecordingLifecycle::default());
    let session_id = "idle-session";
    session_store.insert(
        session_id.to_owned(),
        "principal-a".to_owned(),
        "2025-03-26".to_owned(),
    );
    result_store.append_response(session_id, serde_json::json!({ "stale": true }));
    session_store.force_idle_for_test(session_id, Duration::from_secs(901));
    let cfg = HttpTransportConfig {
        stateful: true,
        stateful_idle_ttl: Duration::from_secs(900),
        session_store: Some(Arc::clone(&session_store)),
        result_store: Some(Arc::clone(&result_store)),
        session_lifecycle: Some(lifecycle.clone()),
        ..Default::default()
    };

    assert_eq!(reap_idle_stateful_sessions(&cfg), 1);
    assert!(session_store.principal_for(session_id).is_none());
    assert!(
        result_store
            .events_after(session_id, None, false)
            .expect("removed session has no buffered events")
            .is_empty()
    );
    assert_eq!(
        lifecycle
            .closed
            .lock()
            .expect("test lifecycle mutex")
            .as_slice(),
        &[(
            session_id.to_owned(),
            "principal-a".to_owned(),
            DispatchCloseReason::Timeout
        )]
    );
    assert_eq!(
        reap_idle_stateful_sessions(&cfg),
        0,
        "reaping the same idle session is idempotent"
    );
}

#[test]
fn principal_session_close_clears_sessions_buffers_and_lanes() {
    #[derive(Debug, Default)]
    struct RecordingLifecycle {
        closed: std::sync::Mutex<Vec<(String, DispatchCloseReason)>>,
    }

    impl HttpSessionLifecycle for RecordingLifecycle {
        fn close_session(&self, _session_id: &str, _principal_key: &str) -> bool {
            false
        }

        fn close_principal_sessions(
            &self,
            principal_key: &str,
            reason: DispatchCloseReason,
        ) -> usize {
            self.closed
                .lock()
                .expect("test lifecycle mutex")
                .push((principal_key.to_owned(), reason));
            2
        }
    }

    let session_store = Arc::new(HttpSessionStore::default());
    let result_store = Arc::new(HttpResultStore::new());
    let lifecycle = Arc::new(RecordingLifecycle::default());
    session_store.insert(
        "sess-a".to_owned(),
        "client:sha256:aaa".to_owned(),
        "2025-03-26".to_owned(),
    );
    session_store.insert(
        "sess-b".to_owned(),
        "client:sha256:aaa".to_owned(),
        "2025-03-26".to_owned(),
    );
    session_store.insert(
        "sess-c".to_owned(),
        "client:sha256:bbb".to_owned(),
        "2025-03-26".to_owned(),
    );
    result_store.append_response("sess-a", serde_json::json!({ "a": true }));
    result_store.append_response("sess-b", serde_json::json!({ "b": true }));
    result_store.append_response("sess-c", serde_json::json!({ "c": true }));
    let cfg = HttpTransportConfig {
        stateful: true,
        session_store: Some(Arc::clone(&session_store)),
        result_store: Some(Arc::clone(&result_store)),
        session_lifecycle: Some(lifecycle.clone()),
        ..Default::default()
    };

    assert_eq!(
        close_http_principal_sessions(
            &cfg,
            "client:sha256:aaa",
            DispatchCloseReason::SessionDelete,
        ),
        2
    );
    assert!(session_store.principal_for("sess-a").is_none());
    assert!(session_store.principal_for("sess-b").is_none());
    assert_eq!(
        session_store.principal_for("sess-c").as_deref(),
        Some("client:sha256:bbb")
    );
    assert!(
        result_store
            .events_after("sess-a", None, false)
            .expect("removed principal session has no buffered events")
            .is_empty()
    );
    assert!(
        result_store
            .events_after("sess-b", None, false)
            .expect("removed principal session has no buffered events")
            .is_empty()
    );
    assert_eq!(
        lifecycle
            .closed
            .lock()
            .expect("test lifecycle mutex")
            .as_slice(),
        &[(
            "client:sha256:aaa".to_owned(),
            DispatchCloseReason::SessionDelete
        )]
    );
}

#[test]
fn busy_tool_result_is_http_429_backpressure() {
    let cfg = HttpTransportConfig {
        json_response: true,
        ..Default::default()
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "oracle_query",
            "arguments": { "sql": "SELECT 1 FROM dual" }
        }
    });
    let response = handle_http_request(&busy_server(), &cfg, post(&body));

    assert_eq!(response.status, 429);
    assert_eq!(response.header("retry-after"), Some("1"));
    let body = response_json(&response);
    assert_eq!(
        body["result"]["structuredContent"]["error_class"],
        serde_json::json!("BUSY")
    );
    assert_eq!(
        body["result"]["structuredContent"]["retry_after_ms"],
        serde_json::json!(250)
    );
}

#[test]
fn at_capacity_tool_result_is_http_429_backpressure() {
    let cfg = HttpTransportConfig {
        json_response: true,
        ..Default::default()
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "oracle_query",
            "arguments": { "sql": "SELECT 1 FROM dual" }
        }
    });
    let response = handle_http_request(&at_capacity_server(), &cfg, post(&body));

    assert_eq!(response.status, 429);
    assert_eq!(response.header("retry-after"), Some("1"));
    let body = response_json(&response);
    assert_eq!(
        body["result"]["structuredContent"]["error_class"],
        serde_json::json!("AT_CAPACITY")
    );
    assert_eq!(
        body["result"]["structuredContent"]["retry_after_ms"],
        serde_json::json!(250)
    );
}

#[test]
fn cancelled_dispatch_outcome_is_http_499() {
    let cfg = HttpTransportConfig {
        json_response: true,
        ..Default::default()
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "oracle_query",
            "arguments": { "sql": "SELECT 1 FROM dual" }
        }
    });
    let response = handle_http_request(&cancelled_server(), &cfg, post(&body));

    assert_eq!(response.status, 499);
    let body = response_json(&response);
    assert_eq!(body["outcome"], serde_json::json!("cancelled"));
    assert_eq!(body["cancel_kind"], serde_json::json!("Timeout"));
    assert!(body.get("result").is_none());
}

#[test]
fn panicked_dispatch_outcome_is_http_500() {
    let cfg = HttpTransportConfig {
        json_response: true,
        ..Default::default()
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "oracle_query",
            "arguments": { "sql": "SELECT 1 FROM dual" }
        }
    });
    let response = handle_http_request(&panicked_server(), &cfg, post(&body));

    assert_eq!(response.status, 500);
    let body = response_json(&response);
    assert_eq!(body["outcome"], serde_json::json!("panicked"));
    assert_eq!(body["error"], serde_json::json!("request_panicked"));
    assert!(body.get("result").is_none());
}

// ---- D1-health: /healthz, /readyz, /metrics ----------------------------

struct StaticProbe(std::sync::atomic::AtomicBool);
impl ReadinessProbe for StaticProbe {
    fn is_db_reachable(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

fn obs_config(
    health: HealthState,
    metrics: Option<Arc<Metrics>>,
    probe: Option<Arc<dyn ReadinessProbe>>,
) -> HttpTransportConfig {
    HttpTransportConfig {
        observability: ObservabilityState {
            health: Some(health),
            metrics,
            readiness_probe: probe,
        },
        ..Default::default()
    }
}

fn get(path: &str) -> HttpRequest {
    HttpRequest::new("GET", path, [("host", "127.0.0.1")], Vec::new())
}

#[test]
fn healthz_is_ok_even_while_db_is_down() {
    // Liveness is process-up only: a never-reachable DB probe + not-ready
    // health must NOT take /healthz down.
    let health = HealthState::new("0.1.0");
    let probe: Arc<dyn ReadinessProbe> =
        Arc::new(StaticProbe(std::sync::atomic::AtomicBool::new(false)));
    let cfg = obs_config(health, None, Some(probe));
    let resp = handle_http_request(&test_server(), &cfg, get(HEALTHZ_PATH));
    assert_eq!(resp.status, 200, "healthz is OK while DB is unreachable");
    assert_eq!(response_json(&resp)["live"], serde_json::json!(true));
}

#[test]
fn readyz_is_503_when_db_unreachable_and_200_when_reachable() {
    let health = HealthState::new("0.1.0");
    health.set_ready(true); // pool established
    let flag = Arc::new(StaticProbe(std::sync::atomic::AtomicBool::new(false)));
    let probe: Arc<dyn ReadinessProbe> = flag.clone();
    let cfg = obs_config(health.clone(), None, Some(probe));

    // DB unreachable -> 503 even though the process is live + health ready.
    let down = handle_http_request(&test_server(), &cfg, get(READYZ_PATH));
    assert_eq!(down.status, 503, "readyz 503 when DB unreachable");
    assert_eq!(
        response_json(&down)["db_reachable"],
        serde_json::json!(false)
    );

    // DB becomes reachable -> 200.
    flag.0.store(true, std::sync::atomic::Ordering::SeqCst);
    let up = handle_http_request(&test_server(), &cfg, get(READYZ_PATH));
    assert_eq!(up.status, 200, "readyz 200 when DB reachable + ready");
    assert_eq!(response_json(&up)["ready"], serde_json::json!(true));
}

#[test]
fn readyz_is_503_on_shutdown_even_if_db_reachable() {
    let health = HealthState::new("0.1.0");
    health.set_ready(true);
    let probe: Arc<dyn ReadinessProbe> =
        Arc::new(StaticProbe(std::sync::atomic::AtomicBool::new(true)));
    let cfg = obs_config(health.clone(), None, Some(probe));
    assert_eq!(
        handle_http_request(&test_server(), &cfg, get(READYZ_PATH)).status,
        200
    );
    // Begin draining: readyz must flip to 503 even though the DB is up.
    health.begin_shutdown();
    let draining = handle_http_request(&test_server(), &cfg, get(READYZ_PATH));
    assert_eq!(draining.status, 503, "readyz drains on shutdown");
    assert_eq!(
        response_json(&draining)["draining"],
        serde_json::json!(true)
    );
}

#[test]
fn readyz_without_probe_tracks_health_only() {
    // No DB probe configured: readiness == health readiness.
    let health = HealthState::new("0.1.0");
    let cfg = obs_config(health.clone(), None, None);
    assert_eq!(
        handle_http_request(&test_server(), &cfg, get(READYZ_PATH)).status,
        503,
        "not ready until pool up"
    );
    health.set_ready(true);
    assert_eq!(
        handle_http_request(&test_server(), &cfg, get(READYZ_PATH)).status,
        200
    );
}

#[test]
fn metrics_endpoint_serves_prometheus_text() {
    let metrics = Arc::new(Metrics::new());
    metrics.record_request("oracle_query", "ok");
    metrics.set_pool_active(2);
    let mut cfg = obs_config(HealthState::new("0.1.0"), Some(metrics), None);
    cfg.session_lifecycle = Some(Arc::new(StaticLaneLifecycle::one_lane()));
    let resp = handle_http_request(&test_server(), &cfg, get(METRICS_PATH));
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.header("content-type"),
        Some("text/plain; version=0.0.4; charset=utf-8")
    );
    let body = String::from_utf8(resp.body).expect("utf-8");
    assert!(body.contains("mcp_requests_total{tool=\"oracle_query\",status=\"ok\"} 1"));
    assert!(body.contains("mcp_active_lanes 1"));
    assert!(
        body.contains(
            "mcp_active_lane{lane_id=\"lane-a\",subject_id_hash=\"subject-sha256:abc\"} 1"
        )
    );
    assert!(body.contains("db_pool_active_connections 2"));
}

#[test]
fn observability_routes_are_404_when_unconfigured() {
    // Default config has no observability state -> routes fall through to
    // the normal 404 (not advertised). This also proves the routes don't
    // collide with /mcp routing when off.
    let cfg = HttpTransportConfig::default();
    for path in [HEALTHZ_PATH, READYZ_PATH, METRICS_PATH] {
        assert_eq!(
            handle_http_request(&test_server(), &cfg, get(path)).status,
            404,
            "{path} is 404 when observability is off"
        );
    }
}

#[test]
fn health_routes_bypass_oauth_and_host_guard() {
    // /healthz must answer even when OAuth enforcement is configured (infra
    // probes carry no bearer) and regardless of Host/Origin allowlists.
    let health = HealthState::new("0.1.0");
    let mut cfg = obs_config(health, None, None);
    cfg.oauth = Some(oauth_enforcement());
    cfg.allowed_origins = vec!["https://only-this.example".to_owned()];
    let resp = handle_http_request(&test_server(), &cfg, get(HEALTHZ_PATH));
    assert_eq!(resp.status, 200, "healthz bypasses OAuth + guards");
}

#[test]
fn surface_inventory_authn_no_leak() {
    let server = test_server();

    let oauth_cfg = HttpTransportConfig {
        json_response: true,
        stateful: true,
        resource_metadata: Some(serde_json::json!({"resource": "https://oraclemcp.example/mcp"})),
        oauth: Some(oauth_enforcement()),
        ..Default::default()
    };
    let mcp_post = handle_http_request(&server, &oauth_cfg, post(&init_body()));
    let mcp_sse_get = handle_http_request(
        &server,
        &oauth_cfg,
        HttpRequest::new(
            "GET",
            MCP_PATH,
            [("host", "127.0.0.1"), ("accept", "text/event-stream")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );
    let metadata = handle_http_request(
        &server,
        &oauth_cfg,
        HttpRequest::new(
            "GET",
            PROTECTED_RESOURCE_METADATA_PATH,
            [("host", "127.0.0.1"), ("accept", "application/json")],
            Vec::new(),
        ),
    );

    let (auditor, _sink) = operator_auditor();
    let operator_cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        ..Default::default()
    };
    let operator_remote = handle_http_request(
        &server,
        &operator_cfg,
        HttpRequest::new(
            "GET",
            "/operator/v1/health",
            [("host", "127.0.0.1"), ("accept", "application/json")],
            Vec::new(),
        )
        .with_peer_loopback(false),
    );
    let operator_no_audit = handle_http_request(
        &server,
        &HttpTransportConfig::default(),
        operator_json_get("/operator/v1/health"),
    );

    let dir = dashboard_test_dir("surface-inventory");
    let dashboard_cfg = HttpTransportConfig {
        dashboard_auth: Some(Arc::new(DashboardAuth::new(dir))),
        operator_auditor: operator_cfg.operator_auditor.clone(),
        ..Default::default()
    };
    let dashboard_post = handle_http_request(
        &server,
        &dashboard_cfg,
        HttpRequest::new(
            "POST",
            "/operator/v1/actions/preview",
            [
                ("host", "127.0.0.1"),
                ("origin", "http://127.0.0.1"),
                ("sec-fetch-site", "same-origin"),
                ("content-type", "application/json"),
                ("accept", "application/json"),
            ],
            serde_json::json!({
                "tool": "oracle_preview_sql",
                "arguments": { "sql": "SELECT 1 FROM dual" }
            })
            .to_string()
            .into_bytes(),
        )
        .with_peer_loopback(true),
    );
    let dashboard_pairing_remote = handle_http_request(
        &server,
        &dashboard_cfg,
        HttpRequest::new(
            "GET",
            format!("{DASHBOARD_PAIR_PATH}?ticket=opaque"),
            [("host", "127.0.0.1"), ("accept", "text/html")],
            Vec::new(),
        )
        .with_peer_loopback(false),
    );
    let config_apply_remote = handle_http_request(
        &server,
        &operator_cfg,
        HttpRequest::new(
            "POST",
            "/operator/v1/config/apply",
            [
                ("host", "127.0.0.1"),
                ("content-type", "application/json"),
                ("accept", "application/json"),
            ],
            serde_json::json!({"draft_toml": ""})
                .to_string()
                .into_bytes(),
        )
        .with_peer_loopback(false),
    );

    let health = HealthState::new("0.1.0");
    health.set_ready(true);
    let metrics = Arc::new(Metrics::new());
    metrics.record_request("oracle_query", "ok");
    let mut observability_cfg = obs_config(
        health,
        Some(metrics),
        Some(Arc::new(StaticProbe(std::sync::atomic::AtomicBool::new(
            true,
        )))),
    );
    observability_cfg.oauth = Some(oauth_enforcement());
    observability_cfg.allowed_hosts = vec!["only-this.example".to_owned()];
    observability_cfg.allowed_origins = vec!["https://only-this.example".to_owned()];
    let readyz = handle_http_request(
        &server,
        &observability_cfg,
        HttpRequest::new(
            "GET",
            READYZ_PATH,
            [
                ("host", "attacker.example"),
                ("origin", "https://evil.example"),
                ("accept", "application/json"),
            ],
            Vec::new(),
        ),
    );
    let metrics_response = handle_http_request(
        &server,
        &observability_cfg,
        HttpRequest::new(
            "GET",
            METRICS_PATH,
            [
                ("host", "attacker.example"),
                ("origin", "https://evil.example"),
                ("accept", "text/plain"),
            ],
            Vec::new(),
        ),
    );

    let inventory = [
        ("mcp POST", mcp_post.status, 401, "oauth bearer required"),
        (
            "mcp SSE GET",
            mcp_sse_get.status,
            401,
            "oauth bearer required",
        ),
        (
            "oauth metadata",
            metadata.status,
            200,
            "public discovery only",
        ),
        (
            "operator remote",
            operator_remote.status,
            403,
            "operator authority required",
        ),
        (
            "operator no audit",
            operator_no_audit.status,
            503,
            "audit required before operator action",
        ),
        (
            "dashboard POST",
            dashboard_post.status,
            401,
            "dashboard session required",
        ),
        (
            "dashboard pairing remote",
            dashboard_pairing_remote.status,
            403,
            "loopback pairing required",
        ),
        (
            "config apply remote",
            config_apply_remote.status,
            403,
            "operator authority required",
        ),
        ("readyz", readyz.status, 200, "unauth infra no-leak"),
        (
            "metrics",
            metrics_response.status,
            200,
            "unauth infra no-leak",
        ),
    ];
    for (surface, actual, expected, gate) in inventory {
        assert_eq!(
            actual, expected,
            "{surface} should enforce {gate}, got HTTP {actual}"
        );
    }

    assert_observability_no_db_or_secret_leak("readyz", &readyz);
    assert_observability_no_db_or_secret_leak("metrics", &metrics_response);
    assert_eq!(
        metrics_response.header("content-type"),
        Some("text/plain; version=0.0.4; charset=utf-8")
    );
}

fn assert_observability_no_db_or_secret_leak(surface: &str, response: &HttpResponse) {
    let body = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    for forbidden in [
        "v$session",
        "app_user",
        "orcl",
        "freepdb",
        "connect_string",
        "credential_ref",
        "wallet",
        "password",
        "sql_text",
        "bind_values",
        "session_user",
        "serial_number",
        "client_identifier",
    ] {
        assert!(
            !body.contains(forbidden),
            "{surface} leaked forbidden marker {forbidden}: {body}"
        );
    }
}

fn oauth_enforcement() -> Arc<OAuthEnforcement> {
    Arc::new(OAuthEnforcement {
        config: ResourceServerConfig {
            resource: "https://oraclemcp.example/mcp".to_owned(),
            allowed_issuers: vec!["https://idp.example".to_owned()],
            authorization_servers: vec!["https://idp.example".to_owned()],
            required_scopes: vec![],
        },
        verifier: Arc::new(oraclemcp_auth::Hs256Verifier {
            secret: b"k".to_vec(),
        }),
        metadata_url: "https://oraclemcp.example/.well-known/oauth-protected-resource".to_owned(),
    })
}

#[test]
fn metadata_route_serves_rfc9728_document() {
    let meta = serde_json::json!({
        "resource": "https://oraclemcp.example/mcp",
        "authorization_servers": ["https://idp.example"],
    });
    let cfg = HttpTransportConfig {
        resource_metadata: Some(meta),
        ..Default::default()
    };
    let response = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            PROTECTED_RESOURCE_METADATA_PATH,
            [("host", "127.0.0.1")],
            Vec::new(),
        ),
    );
    assert_eq!(response.status, 200);
    assert_eq!(
        response_json(&response)["resource"],
        serde_json::json!("https://oraclemcp.example/mcp")
    );
}

#[test]
fn initialize_over_streamable_http_returns_json() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: false,
        ..Default::default()
    };
    let response = handle_http_request(&test_server(), &cfg, post(&init_body()));
    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-type"), Some("application/json"));
    let body = response_json(&response);
    assert!(body.get("result").is_some(), "JSON-RPC initialize result");
    assert_eq!(body["result"]["serverInfo"]["name"], "oraclemcp");
}

#[test]
fn stateful_initialize_uses_sse_and_session_header() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: true,
        ..Default::default()
    };
    let response = handle_http_request(&test_server(), &cfg, post(&init_body()));
    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-type"), Some("text/event-stream"));
    assert_eq!(response.header("cache-control"), Some("no-cache"));
    assert!(response.header("mcp-session-id").is_some());
    let body = String::from_utf8(response.body).expect("SSE is UTF-8");
    assert!(body.contains("id: 0\nretry: 3000\ndata:\n\n"));
    assert!(!body.contains("\"method\""));
    assert!(body.contains("\"result\""));
}

#[test]
fn stateful_initialize_sets_strict_session_cookie() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: true,
        session_store: Some(Arc::new(HttpSessionStore::default())),
        result_store: Some(Arc::new(HttpResultStore::new())),
        ..Default::default()
    };
    let response = handle_http_request(&test_server(), &cfg, post(&init_body()));
    let session_id = response
        .header("mcp-session-id")
        .expect("initialize returns mcp-session-id");
    let cookie = response
        .header("set-cookie")
        .expect("initialize returns EventSource session cookie");
    assert!(cookie.starts_with(&format!("{STATEFUL_SESSION_COOKIE}={session_id};")));
    assert!(cookie.contains("Path=/mcp"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));
}

#[test]
fn oauth_stateful_get_accepts_strict_cookie_with_origin_only() {
    let session_store = Arc::new(HttpSessionStore::default());
    let result_store = Arc::new(HttpResultStore::new());
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: true,
        allowed_origins: vec!["https://app.example".to_owned()],
        oauth: Some(Arc::new(OAuthEnforcement {
            config: ResourceServerConfig {
                resource: "https://oraclemcp.example/mcp".to_owned(),
                allowed_issuers: vec!["https://idp.example".to_owned()],
                authorization_servers: vec!["https://idp.example".to_owned()],
                required_scopes: vec![],
            },
            verifier: Arc::new(AcceptHs256),
            metadata_url: "https://oraclemcp.example/.well-known/oauth-protected-resource"
                .to_owned(),
        })),
        session_store: Some(Arc::clone(&session_store)),
        result_store: Some(Arc::clone(&result_store)),
        ..Default::default()
    };
    let token = format!("Bearer {}", jwt_with_scope("oracle:read"));
    let init = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "POST",
            MCP_PATH,
            [
                ("host", "127.0.0.1"),
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
                ("origin", "https://app.example"),
                ("authorization", token.as_str()),
            ],
            init_body().to_string().into_bytes(),
        ),
    );
    assert_eq!(init.status, 200);
    let session_id = init
        .header("mcp-session-id")
        .expect("initialize returns mcp-session-id");
    let cookie_pair = init
        .header("set-cookie")
        .and_then(|cookie| cookie.split(';').next())
        .expect("initialize returns cookie pair")
        .to_owned();
    result_store.append_response(session_id, serde_json::json!({ "seq": 1 }));

    let cookie_get = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            MCP_PATH,
            [
                ("host", "127.0.0.1"),
                ("accept", "text/event-stream"),
                ("origin", "https://app.example"),
                ("cookie", cookie_pair.as_str()),
                ("last-event-id", "0/0"),
            ],
            Vec::new(),
        ),
    );
    assert_eq!(cookie_get.status, 200);
    let body = String::from_utf8(cookie_get.body).expect("SSE utf-8");
    assert!(body.contains("id: 1/0"));
    assert!(body.contains("\"seq\":1"));

    let missing_origin = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            MCP_PATH,
            [
                ("host", "127.0.0.1"),
                ("accept", "text/event-stream"),
                ("cookie", cookie_pair.as_str()),
            ],
            Vec::new(),
        ),
    );
    assert_eq!(missing_origin.status, 403);
    assert_eq!(
        String::from_utf8_lossy(&missing_origin.body),
        "Missing Origin header for cookie-authenticated SSE"
    );

    let header_only_without_bearer = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            MCP_PATH,
            [
                ("host", "127.0.0.1"),
                ("accept", "text/event-stream"),
                ("origin", "https://app.example"),
                ("mcp-session-id", session_id),
            ],
            Vec::new(),
        ),
    );
    assert_eq!(header_only_without_bearer.status, 401);
    assert!(
        header_only_without_bearer
            .header("www-authenticate")
            .is_some()
    );
}

#[test]
fn stateful_requests_require_a_known_session_id_after_initialize() {
    #[derive(Debug, Default)]
    struct RecordingLifecycle {
        closed: std::sync::Mutex<Vec<(String, String)>>,
    }

    impl HttpSessionLifecycle for RecordingLifecycle {
        fn close_session(&self, session_id: &str, principal_key: &str) -> bool {
            self.closed
                .lock()
                .expect("test lifecycle mutex")
                .push((session_id.to_owned(), principal_key.to_owned()));
            true
        }
    }

    let lifecycle = Arc::new(RecordingLifecycle::default());
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: true,
        session_store: Some(Arc::new(HttpSessionStore::default())),
        session_lifecycle: Some(lifecycle.clone()),
        ..Default::default()
    };
    let init = handle_http_request(&test_server(), &cfg, post(&init_body()));
    let session_id = init
        .header("mcp-session-id")
        .expect("initialize returns a session id")
        .to_owned();

    let call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "oracle_preview_sql",
            "arguments": { "sql": "SELECT 1 FROM dual" }
        }
    });
    let missing = handle_http_request(&scope_echo_server(), &cfg, post(&call));
    assert_eq!(missing.status, 400);
    assert_eq!(
        String::from_utf8_lossy(&missing.body),
        "Missing mcp-session-id"
    );

    let forged = HttpRequest::new(
        "POST",
        MCP_PATH,
        [
            ("host", "127.0.0.1"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
            ("mcp-session-id", "00000000-0000-4000-8000-deadbeefdead"),
        ],
        call.to_string().into_bytes(),
    );
    let forged = handle_http_request(&scope_echo_server(), &cfg, forged);
    assert_eq!(forged.status, 404);
    assert_eq!(
        String::from_utf8_lossy(&forged.body),
        "Invalid mcp-session-id"
    );

    let valid = HttpRequest::new(
        "POST",
        MCP_PATH,
        [
            ("host", "127.0.0.1"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
            ("mcp-session-id", session_id.as_str()),
            // The session negotiated 2025-11-25, so post-init POSTs must carry
            // the MCP-Protocol-Version header (2025-06-18 requirement).
            ("mcp-protocol-version", "2025-11-25"),
        ],
        call.to_string().into_bytes(),
    );
    let valid = handle_http_request(&scope_echo_server(), &cfg, valid);
    assert_eq!(valid.status, 200);
    let valid_body = String::from_utf8_lossy(&valid.body);
    assert!(
        valid_body.contains("\"tool\":\"oracle_preview_sql\""),
        "valid session id reaches dispatch"
    );
    assert!(
        valid_body.contains(&format!("\"session_id\":\"{session_id}\"")),
        "valid stateful request carries its MCP session id into dispatch: {valid_body}"
    );

    let delete = HttpRequest::new(
        "DELETE",
        MCP_PATH,
        [
            ("host", "127.0.0.1"),
            ("mcp-session-id", session_id.as_str()),
        ],
        Vec::new(),
    );
    let deleted = handle_http_request(&test_server(), &cfg, delete);
    assert_eq!(deleted.status, 202);
    assert_eq!(
        lifecycle
            .closed
            .lock()
            .expect("test lifecycle mutex")
            .as_slice(),
        &[(session_id.clone(), "anonymous-http".to_owned())],
        "DELETE must close the lane/resource bound to the session"
    );

    let stale = HttpRequest::new(
        "POST",
        MCP_PATH,
        [
            ("host", "127.0.0.1"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
            ("mcp-session-id", session_id.as_str()),
        ],
        call.to_string().into_bytes(),
    );
    let stale = handle_http_request(&scope_echo_server(), &cfg, stale);
    assert_eq!(stale.status, 404);
    assert_eq!(
        String::from_utf8_lossy(&stale.body),
        "Invalid mcp-session-id"
    );
}

#[test]
fn session_ids_are_unpredictable_and_high_entropy() {
    // Mint a batch and assert they are all distinct, never sequentially
    // predictable (the old monotonic counter would make id N+1 trivially
    // derivable from id N), and carry the canonical UUIDv4 shape.
    let ids: Vec<String> = (0..256).map(|_| new_session_id()).collect();
    let unique: std::collections::HashSet<&String> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len(), "session ids must be unique");

    for id in &ids {
        assert_eq!(id.len(), 36, "UUIDv4 shape: {id}");
        // 8-4-4-4-12 hyphen layout, hex elsewhere, version nibble `4`.
        let hyphens: Vec<usize> = id.match_indices('-').map(|(i, _)| i).collect();
        assert_eq!(hyphens, vec![8, 13, 18, 23], "hyphen layout: {id}");
        assert!(
            id.chars().all(|c| c == '-' || c.is_ascii_hexdigit()),
            "hex digits only: {id}"
        );
        assert_eq!(id.as_bytes()[14], b'4', "version nibble must be 4: {id}");
    }

    // No two consecutive ids share their leading random bytes (counter would).
    let mut consecutive_prefix_collisions = 0;
    for pair in ids.windows(2) {
        if pair[0][..8] == pair[1][..8] {
            consecutive_prefix_collisions += 1;
        }
    }
    assert_eq!(
        consecutive_prefix_collisions, 0,
        "consecutive ids must not share a 32-bit prefix"
    );
}

#[test]
fn dns_rebinding_host_is_rejected_by_the_transport() {
    let request = HttpRequest::new(
        "POST",
        MCP_PATH,
        [
            ("host", "attacker.example"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
        ],
        init_body().to_string().into_bytes(),
    );
    let response = handle_http_request(&test_server(), &HttpTransportConfig::default(), request);
    assert_eq!(response.status, 403);
    assert_eq!(
        String::from_utf8_lossy(&response.body),
        "Forbidden: Host header is not allowed"
    );
}

#[test]
fn forbidden_browser_origin_is_rejected_by_the_transport() {
    let cfg = HttpTransportConfig {
        allowed_origins: vec!["https://app.example".to_owned()],
        ..Default::default()
    };
    let request = HttpRequest::new(
        "POST",
        MCP_PATH,
        [
            ("host", "127.0.0.1"),
            ("origin", "https://evil.example"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
        ],
        init_body().to_string().into_bytes(),
    );
    let response = handle_http_request(&test_server(), &cfg, request);
    assert_eq!(response.status, 403);
    assert_eq!(
        String::from_utf8_lossy(&response.body),
        "Forbidden: Origin header is not allowed"
    );
}

#[test]
fn oauth_enabled_rejects_missing_token_with_www_authenticate() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: false,
        oauth: Some(oauth_enforcement()),
        ..Default::default()
    };
    let response = handle_http_request(&test_server(), &cfg, post(&init_body()));
    assert_eq!(response.status, 401);
    assert_eq!(
        response.header("www-authenticate"),
        Some(
            "Bearer resource_metadata=\"https://oraclemcp.example/.well-known/oauth-protected-resource\""
        )
    );
}

#[test]
fn oauth_enabled_rejects_bad_token_but_keeps_metadata_open() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: false,
        resource_metadata: Some(serde_json::json!({"resource": "https://oraclemcp.example/mcp"})),
        oauth: Some(oauth_enforcement()),
        ..Default::default()
    };
    let bad = HttpRequest::new(
        "POST",
        MCP_PATH,
        [
            ("host", "127.0.0.1"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
            ("authorization", "Bearer not.a.jwt"),
        ],
        init_body().to_string().into_bytes(),
    );
    let response = handle_http_request(&test_server(), &cfg, bad);
    assert_eq!(response.status, 401);
    assert!(
        response
            .header("www-authenticate")
            .is_some_and(|value| value.contains("error=\"invalid_token\""))
    );
    let body = String::from_utf8_lossy(&response.body);
    assert_eq!(body, "unauthorized");
    assert!(
        !body.contains("not.a.jwt"),
        "bad bearer token must not be echoed in the response body"
    );
    for (name, value) in &response.headers {
        assert!(
            !value.contains("not.a.jwt"),
            "bad bearer token leaked in response header {name}: {value}"
        );
    }

    let metadata = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            PROTECTED_RESOURCE_METADATA_PATH,
            [("host", "127.0.0.1")],
            Vec::new(),
        ),
    );
    assert_eq!(metadata.status, 200);
}

#[test]
fn oversized_request_is_rejected_before_oauth() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: false,
        oauth: Some(oauth_enforcement()),
        ..Default::default()
    };
    let response = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "POST",
            MCP_PATH,
            [
                ("host", "127.0.0.1"),
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
            ],
            vec![b'x'; MAX_BODY_BYTES + 1],
        ),
    );
    assert_eq!(response.status, 413);
    assert!(response.header("www-authenticate").is_none());
}

#[test]
fn serve_http_until_stops_accepting_and_drains_worker() {
    #[derive(Debug)]
    struct ShutdownLifecycle {
        closed_all: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl HttpSessionLifecycle for ShutdownLifecycle {
        fn close_session(&self, _session_id: &str, _principal_key: &str) -> bool {
            false
        }

        fn close_all_sessions(&self) {
            self.closed_all
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback test listener");
    let addr = listener.local_addr().expect("listener has local addr");
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let closed_all = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let server_closed_all = Arc::clone(&closed_all);
    let handle = std::thread::spawn(move || {
        serve_http_until(
            listener,
            test_server(),
            &HttpTransportConfig {
                json_response: true,
                stateful: true,
                session_lifecycle: Some(Arc::new(ShutdownLifecycle {
                    closed_all: server_closed_all,
                })),
                ..Default::default()
            },
            server_shutdown,
        )
        .expect("native HTTP server exits cleanly")
    });

    let body = init_body().to_string();
    let mut stream = TcpStream::connect(addr).expect("connect to test listener");
    write!(
            stream,
            "POST {MCP_PATH} HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            body.len()
        )
        .expect("write partial request");
    std::thread::sleep(Duration::from_millis(30));
    shutdown.store(true, Ordering::SeqCst);
    stream
        .write_all(body.as_bytes())
        .expect("finish request body");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    handle.join().expect("server thread joins after draining");
    assert_eq!(
        closed_all.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "stateful listener shutdown closes all lane sessions after worker drain"
    );
}

#[test]
fn serve_http_until_bounds_connection_workers_before_request_parse() {
    let transport_admission = Arc::new(AdmissionController::new(1, 1));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback test listener");
    let addr = listener.local_addr().expect("listener has local addr");
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let config = HttpTransportConfig {
        json_response: true,
        transport_admission: Arc::clone(&transport_admission),
        ..Default::default()
    };
    let handle = std::thread::spawn(move || {
        serve_http_until(listener, test_server(), &config, server_shutdown)
            .expect("bounded native HTTP server exits cleanly")
    });

    let stalled = TcpStream::connect(addr).expect("connect stalled reader");
    for _ in 0..100 {
        if transport_admission.available_global() == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        transport_admission.available_global(),
        0,
        "first accepted socket must hold the only transport worker permit"
    );

    let mut rejected = TcpStream::connect(addr).expect("connect rejected reader");
    rejected
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set rejected read timeout");
    let mut response = String::new();
    rejected
        .read_to_string(&mut response)
        .expect("read transport capacity rejection");
    assert!(response.starts_with("HTTP/1.1 429 Too Many Requests"));
    assert!(response.contains("retry-after: 1"));
    assert!(response.contains("\"error_class\":\"AT_CAPACITY\""));
    assert!(response.contains("http_transport_connection"));
    assert!(response.contains("capacity_snapshot"));

    drop(stalled);
    shutdown.store(true, Ordering::SeqCst);
    handle.join().expect("bounded server thread joins");
}

#[test]
fn served_stateful_get_sse_subscribers_are_capped() {
    fn read_until(stream: &mut TcpStream, raw: &mut Vec<u8>, needle: &[u8]) {
        let mut buf = [0_u8; 512];
        while !raw.windows(needle.len()).any(|window| window == needle) {
            let n = stream.read(&mut buf).expect("SSE response is readable");
            assert_ne!(n, 0, "SSE response ended before expected data");
            raw.extend_from_slice(&buf[..n]);
        }
    }

    let sse_admission = Arc::new(AdmissionController::new(1, 1));
    let session_store = Arc::new(HttpSessionStore::default());
    let result_store = Arc::new(HttpResultStore::new());
    let session_id = "subscriber-cap-session";
    // Seeded session pins the pre-2025-06-18 revision: these tests exercise
    // session/cursor semantics, not the post-init protocol-version header
    // requirement (covered by its own tests).
    session_store.insert(
        session_id.to_owned(),
        "anonymous-http".to_owned(),
        "2025-03-26".to_owned(),
    );
    result_store.ensure_session(session_id);
    let config = HttpTransportConfig {
        stateful: true,
        session_store: Some(Arc::clone(&session_store)),
        result_store: Some(Arc::clone(&result_store)),
        sse_admission: Arc::clone(&sse_admission),
        ..Default::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind SSE cap listener");
    let addr = listener.local_addr().expect("SSE cap listener address");
    let shutdown = Arc::new(AtomicBool::new(false));
    let thread_shutdown = Arc::clone(&shutdown);
    let handle = std::thread::spawn(move || {
        serve_http_until(listener, test_server(), &config, thread_shutdown)
            .expect("SSE cap HTTP listener exits cleanly");
    });

    let request = format!(
        "GET {MCP_PATH} HTTP/1.1\r\nhost: 127.0.0.1\r\naccept: text/event-stream\r\nmcp-session-id: {session_id}\r\ncontent-length: 0\r\n\r\n"
    );
    let mut first = TcpStream::connect(addr).expect("connect first SSE subscriber");
    first
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set first SSE read timeout");
    first
        .write_all(request.as_bytes())
        .expect("write first SSE GET");
    let mut first_raw = Vec::new();
    read_until(&mut first, &mut first_raw, b"\r\n\r\n");
    assert_eq!(
        sse_admission.available_global(),
        0,
        "streaming GET must hold the only SSE subscriber permit"
    );

    let mut second = TcpStream::connect(addr).expect("connect second SSE subscriber");
    second
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set second SSE read timeout");
    second
        .write_all(request.as_bytes())
        .expect("write second SSE GET");
    let mut response = String::new();
    second
        .read_to_string(&mut response)
        .expect("read SSE capacity rejection");
    assert!(response.starts_with("HTTP/1.1 429 Too Many Requests"));
    assert!(response.contains("retry-after: 1"));
    assert!(response.contains("\"error_class\":\"AT_CAPACITY\""));
    assert!(response.contains("http_sse_subscriber"));
    assert!(response.contains("capacity_snapshot"));

    result_store.remove_session(session_id);
    shutdown.store(true, Ordering::SeqCst);
    drop(first);
    handle.join().expect("SSE cap listener thread joins");
}

fn self_signed_cert() -> (Vec<u8>, Vec<u8>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    (
        cert.cert.pem().into_bytes(),
        cert.key_pair.serialize_pem().into_bytes(),
    )
}

fn ca_cert() -> (rcgen::Certificate, rcgen::KeyPair) {
    let mut params =
        rcgen::CertificateParams::new(vec!["oraclemcp-test-ca".to_owned()]).expect("CA params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let key = rcgen::KeyPair::generate().expect("CA key");
    let cert = params.self_signed(&key).expect("self-signed CA");
    (cert, key)
}

fn cert_signed_by(
    name: &str,
    ca_cert: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
) -> (Vec<u8>, Vec<u8>) {
    let params = rcgen::CertificateParams::new(vec![name.to_owned()]).expect("cert params");
    let key = rcgen::KeyPair::generate().expect("cert key");
    let cert = params
        .signed_by(&key, ca_cert, ca_key)
        .expect("certificate signed by test CA");
    (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
}

fn pem_certs(pem: &[u8]) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .expect("certificate PEM parses")
}

fn pem_key(pem: &[u8]) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_slice(pem).expect("private-key PEM parses")
}

fn tls_client_config(
    server_cert_pem: &[u8],
    client_cert_and_key: Option<(&[u8], &[u8])>,
) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in pem_certs(server_cert_pem) {
        roots.add(cert).expect("server cert added to roots");
    }
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("default TLS versions")
    .with_root_certificates(roots);
    match client_cert_and_key {
        Some((cert_pem, key_pem)) => builder
            .with_client_auth_cert(pem_certs(cert_pem), pem_key(key_pem))
            .expect("client auth cert config"),
        None => builder.with_no_client_auth(),
    }
    .into()
}

fn spawn_https_with(
    tls: Arc<TlsServerConfig>,
    server: OracleMcpServer,
    config: HttpTransportConfig,
) -> (
    std::net::SocketAddr,
    Arc<AtomicBool>,
    std::thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback HTTPS listener");
    let addr = listener.local_addr().expect("listener has local addr");
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let handle = std::thread::spawn(move || {
        serve_https_until(listener, server, &config, tls, server_shutdown)
            .expect("native HTTPS server exits cleanly")
    });
    (addr, shutdown, handle)
}

fn spawn_https(
    tls: Arc<TlsServerConfig>,
) -> (
    std::net::SocketAddr,
    Arc<AtomicBool>,
    std::thread::JoinHandle<()>,
) {
    spawn_https_with(
        tls,
        test_server(),
        HttpTransportConfig {
            json_response: true,
            stateful: false,
            ..Default::default()
        },
    )
}

fn https_get(
    addr: std::net::SocketAddr,
    config: Arc<rustls::ClientConfig>,
) -> std::io::Result<String> {
    let stream = TcpStream::connect(addr)?;
    let connection =
        rustls::ClientConnection::new(config, ServerName::try_from("localhost").unwrap())
            .map_err(|e| std::io::Error::other(format!("TLS client setup: {e}")))?;
    let mut stream = rustls::StreamOwned::new(connection, stream);
    write!(
        stream,
        "GET {MCP_PATH} HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 0\r\n\r\n"
    )?;
    stream.flush()?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn https_post(
    addr: std::net::SocketAddr,
    config: Arc<rustls::ClientConfig>,
    body: &str,
) -> std::io::Result<String> {
    let stream = TcpStream::connect(addr)?;
    let connection =
        rustls::ClientConnection::new(config, ServerName::try_from("localhost").unwrap())
            .map_err(|e| std::io::Error::other(format!("TLS client setup: {e}")))?;
    let mut stream = rustls::StreamOwned::new(connection, stream);
    write!(
        stream,
        "POST {MCP_PATH} HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/json\r\naccept: application/json, text/event-stream\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    )?;
    stream.flush()?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

fn http_body(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("HTTP response has body separator")
}

#[test]
fn serve_https_accepts_tls_handshake() {
    let (cert, key) = self_signed_cert();
    let tls = crate::tls::build_server_config(&crate::tls::TlsMaterial {
        cert_chain_pem: cert.clone(),
        private_key_pem: key,
        client_ca_pem: None,
    })
    .expect("server-only TLS config builds");
    let (addr, shutdown, handle) = spawn_https(tls);

    let response = https_get(addr, tls_client_config(&cert, None)).expect("HTTPS request");
    assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed"));

    shutdown.store(true, Ordering::SeqCst);
    handle.join().expect("HTTPS server thread joins");
}

#[test]
fn serve_https_requires_client_certificate_when_mtls_is_configured() {
    let (server_cert, server_key) = self_signed_cert();
    let (client_ca, client_ca_key) = ca_cert();
    let (client_cert, client_key) =
        cert_signed_by("oraclemcp-test-client", &client_ca, &client_ca_key);
    let tls = crate::tls::build_server_config(&crate::tls::TlsMaterial {
        cert_chain_pem: server_cert.clone(),
        private_key_pem: server_key,
        client_ca_pem: Some(client_ca.pem().into_bytes()),
    })
    .expect("mTLS config builds");
    let (addr, shutdown, handle) = spawn_https(tls);

    let without_client_cert = https_get(addr, tls_client_config(&server_cert, None));
    assert!(
        without_client_cert.is_err(),
        "mTLS listener must reject clients without a certificate"
    );

    let response = https_get(
        addr,
        tls_client_config(&server_cert, Some((&client_cert, &client_key))),
    )
    .expect("mTLS request with client certificate");
    assert!(response.starts_with("HTTP/1.1 403 Forbidden"));
    assert!(
        response.contains("mtls_client_not_registered"),
        "CA-valid but unregistered mTLS client must fail closed: {response}"
    );

    shutdown.store(true, Ordering::SeqCst);
    handle.join().expect("mTLS server thread joins");
}

#[test]
fn registered_mtls_client_certificate_becomes_dispatch_principal() {
    let (server_cert, server_key) = self_signed_cert();
    let (client_ca, client_ca_key) = ca_cert();
    let (client_cert, client_key) =
        cert_signed_by("oraclemcp-test-client", &client_ca, &client_ca_key);
    let fingerprint = cert_fingerprint_sha256(pem_certs(&client_cert)[0].as_ref());
    let tls = crate::tls::build_server_config(&crate::tls::TlsMaterial {
        cert_chain_pem: server_cert.clone(),
        private_key_pem: server_key,
        client_ca_pem: Some(client_ca.pem().into_bytes()),
    })
    .expect("mTLS config builds");
    let (addr, shutdown, handle) = spawn_https_with(
        tls,
        scope_echo_server(),
        HttpTransportConfig {
            json_response: true,
            stateful: false,
            mtls_clients: MtlsClientRegistry::from_fingerprints([fingerprint.clone()]),
            ..Default::default()
        },
    );

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {
            "name": "oracle_preview_sql",
            "arguments": { "sql": "SELECT 1 FROM dual" }
        }
    })
    .to_string();
    let response = https_post(
        addr,
        tls_client_config(&server_cert, Some((&client_cert, &client_key))),
        &body,
    )
    .expect("mTLS request with registered client certificate");
    assert!(
        response.starts_with("HTTP/1.1 200 OK"),
        "registered mTLS client should dispatch successfully: {response}"
    );
    let json: Value = serde_json::from_str(http_body(&response)).expect("JSON response body");
    assert_eq!(
        json["result"]["structuredContent"]["principal_key"],
        serde_json::json!(format!("mtls:{fingerprint}"))
    );
    assert_eq!(
        json["result"]["structuredContent"]["scopes"],
        serde_json::json!([])
    );

    shutdown.store(true, Ordering::SeqCst);
    handle.join().expect("mTLS server thread joins");
}

fn b64url(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(T[((n >> 18) & 0x3f) as usize] as char);
        out.push(T[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(T[((n >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(T[(n & 0x3f) as usize] as char);
        }
    }
    out
}

struct AcceptHs256;
impl oraclemcp_auth::SignatureVerifier for AcceptHs256 {
    fn verify(&self, alg: &str, _signing_input: &[u8], _signature: &[u8]) -> bool {
        alg == "HS256"
    }
}

fn jwt_with_scope(scope: &str) -> String {
    let header = b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let claims = serde_json::json!({
        "iss": "https://idp.example",
        "aud": "https://oraclemcp.example/mcp",
        "exp": 9_999_999_999i64,
        "scope": scope,
    });
    let payload = b64url(serde_json::to_string(&claims).unwrap().as_bytes());
    format!("{header}.{payload}.{}", b64url(b"sig"))
}

fn accepting_oauth_enforcement(required_scopes: Vec<String>) -> Arc<OAuthEnforcement> {
    Arc::new(OAuthEnforcement {
        config: ResourceServerConfig {
            resource: "https://oraclemcp.example/mcp".to_owned(),
            allowed_issuers: vec!["https://idp.example".to_owned()],
            authorization_servers: vec!["https://idp.example".to_owned()],
            required_scopes,
        },
        verifier: Arc::new(AcceptHs256),
        metadata_url: "https://oraclemcp.example/.well-known/oauth-protected-resource".to_owned(),
    })
}

#[test]
fn oauth_scope_is_captured_for_dispatch_enforcement() {
    let enforcement = OAuthEnforcement {
        config: ResourceServerConfig {
            resource: "https://oraclemcp.example/mcp".to_owned(),
            allowed_issuers: vec!["https://idp.example".to_owned()],
            authorization_servers: vec!["https://idp.example".to_owned()],
            required_scopes: vec![],
        },
        verifier: Arc::new(AcceptHs256),
        metadata_url: "https://oraclemcp.example/.well-known/oauth-protected-resource".to_owned(),
    };
    let request = HttpRequest::new(
        "POST",
        MCP_PATH,
        [
            ("host", "127.0.0.1"),
            (
                "authorization",
                &format!("Bearer {}", jwt_with_scope("oracle:read")),
            ),
        ],
        Vec::new(),
    );
    let grant = validate_oauth_request(&request, &enforcement)
        .expect("valid narrowly-scoped bearer is admitted");
    assert_eq!(
        grant.scope_grant,
        ScopeGrant(vec!["oracle:read".to_owned()])
    );
}

#[test]
fn oauth_insufficient_scope_is_forbidden() {
    let enforcement = OAuthEnforcement {
        config: ResourceServerConfig {
            resource: "https://oraclemcp.example/mcp".to_owned(),
            allowed_issuers: vec!["https://idp.example".to_owned()],
            authorization_servers: vec!["https://idp.example".to_owned()],
            required_scopes: vec!["oracle:write".to_owned()],
        },
        verifier: Arc::new(AcceptHs256),
        metadata_url: "https://oraclemcp.example/.well-known/oauth-protected-resource".to_owned(),
    };
    let request = HttpRequest::new(
        "POST",
        MCP_PATH,
        [
            ("host", "127.0.0.1"),
            (
                "authorization",
                &format!("Bearer {}", jwt_with_scope("oracle:read")),
            ),
        ],
        Vec::new(),
    );
    let response = validate_oauth_request(&request, &enforcement)
        .expect_err("valid token without required scope is forbidden");
    assert_eq!(response.status, 403);
    assert_eq!(String::from_utf8_lossy(&response.body), "forbidden");
    assert!(
        response
            .header("www-authenticate")
            .is_some_and(|value| value.contains("error=\"insufficient_scope\""))
    );
}

#[test]
fn oauth_scope_is_forwarded_to_tool_dispatch() {
    let enforcement = OAuthEnforcement {
        config: ResourceServerConfig {
            resource: "https://oraclemcp.example/mcp".to_owned(),
            allowed_issuers: vec!["https://idp.example".to_owned()],
            authorization_servers: vec!["https://idp.example".to_owned()],
            required_scopes: vec![],
        },
        verifier: Arc::new(AcceptHs256),
        metadata_url: "https://oraclemcp.example/.well-known/oauth-protected-resource".to_owned(),
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "oracle_preview_sql",
            "arguments": { "sql": "SELECT 1 FROM dual" }
        }
    });
    let request = HttpRequest::new(
        "POST",
        MCP_PATH,
        [
            ("host", "127.0.0.1"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
            (
                "authorization",
                &format!("Bearer {}", jwt_with_scope("oracle:read")),
            ),
        ],
        body.to_string().into_bytes(),
    );
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: false,
        oauth: Some(Arc::new(enforcement)),
        ..Default::default()
    };

    let response = handle_http_request(&scope_echo_server(), &cfg, request);
    assert_eq!(response.status, 200);
    let body = response_json(&response);
    assert_eq!(
        body["result"]["structuredContent"]["scopes"],
        serde_json::json!(["oracle:read"])
    );
    let principal_key = body["result"]["structuredContent"]["principal_key"]
        .as_str()
        .expect("OAuth dispatch context carries a redacted principal key");
    assert!(principal_key.starts_with("oauth:"));
    assert!(
        !principal_key.contains("oracle:read"),
        "principal key must be derived/redacted, not a raw claim or bearer token"
    );
}

#[test]
fn client_credentials_are_scoped_principals_and_rotate_independently() {
    let store = Arc::new(
        ClientCredentialStore::open(client_credential_fixture_path("http-scope"))
            .expect("credential store opens"),
    );
    let read = store
        .issue(
            crate::client_credentials::ClientCredentialIssueRequest::new(
                "Claude Desktop",
                vec!["oracle:read".to_owned()],
            ),
        )
        .expect("issue read client");
    let execute = store
        .issue(
            crate::client_credentials::ClientCredentialIssueRequest::new(
                "Codex CLI",
                vec!["oracle:execute".to_owned()],
            ),
        )
        .expect("issue execute client");
    let read_bearer = read.bearer.expose().to_owned();
    let execute_bearer = execute.bearer.expose().to_owned();
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: false,
        client_credentials: Some(Arc::clone(&store)),
        ..Default::default()
    };
    let call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "oracle_preview_sql",
            "arguments": { "sql": "SELECT 1 FROM dual" }
        }
    });
    let request_with_bearer = |bearer: &str| {
        HttpRequest::new(
            "POST",
            MCP_PATH,
            [
                ("host", "127.0.0.1"),
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
                ("authorization", &format!("Bearer {bearer}")),
            ],
            call.to_string().into_bytes(),
        )
        .with_peer_addr(Some("127.0.0.1:49152".to_owned()))
    };

    let read_response = handle_http_request(
        &scope_echo_server(),
        &cfg,
        request_with_bearer(&read_bearer),
    );
    assert_eq!(read_response.status, 200);
    let read_body = response_json(&read_response);
    assert_eq!(
        read_body["result"]["structuredContent"]["scopes"],
        serde_json::json!(["oracle:read"])
    );
    assert_eq!(
        read_body["result"]["structuredContent"]["principal_key"],
        serde_json::json!(read.principal_key)
    );
    assert!(
        !String::from_utf8_lossy(&read_response.body).contains(&read_bearer),
        "dispatch response must not echo the bearer"
    );

    let execute_response = handle_http_request(
        &scope_echo_server(),
        &cfg,
        request_with_bearer(&execute_bearer),
    );
    assert_eq!(execute_response.status, 200);
    let execute_body = response_json(&execute_response);
    assert_eq!(
        execute_body["result"]["structuredContent"]["scopes"],
        serde_json::json!(["oracle:execute"])
    );
    assert_eq!(
        execute_body["result"]["structuredContent"]["principal_key"],
        serde_json::json!(execute.principal_key)
    );

    let (rotated_read, lifecycle) = store.rotate(&read.client_id).expect("rotate read client");
    assert_eq!(lifecycle.principal_key, read.principal_key);
    assert_eq!(
        handle_http_request(
            &scope_echo_server(),
            &cfg,
            request_with_bearer(&read_bearer)
        )
        .status,
        401,
        "rotating one client invalidates only its old bearer"
    );
    assert_eq!(
        handle_http_request(
            &scope_echo_server(),
            &cfg,
            request_with_bearer(&execute_bearer)
        )
        .status,
        200,
        "another client's bearer remains valid after the rotation"
    );
    assert_eq!(
        handle_http_request(
            &scope_echo_server(),
            &cfg,
            request_with_bearer(rotated_read.bearer.expose())
        )
        .status,
        200,
        "the rotated one-time bearer is admitted"
    );

    let revoked = store
        .revoke(&execute.client_id)
        .expect("revoke execute client");
    assert_eq!(revoked.principal_key, execute.principal_key);
    assert_eq!(
        handle_http_request(
            &scope_echo_server(),
            &cfg,
            request_with_bearer(&execute_bearer)
        )
        .status,
        401,
        "revoking one client blocks that client"
    );
    assert_eq!(
        handle_http_request(
            &scope_echo_server(),
            &cfg,
            request_with_bearer(rotated_read.bearer.expose())
        )
        .status,
        200,
        "revoking a different client leaves the rotated client valid"
    );
}

#[test]
fn operator_client_credentials_screen_lists_rotates_revokes_without_token_leak() {
    #[derive(Debug, Default)]
    struct RecordingLifecycle {
        closed: std::sync::Mutex<Vec<(String, DispatchCloseReason)>>,
    }

    impl HttpSessionLifecycle for RecordingLifecycle {
        fn close_session(&self, _session_id: &str, _principal_key: &str) -> bool {
            false
        }

        fn close_principal_sessions(
            &self,
            principal_key: &str,
            reason: DispatchCloseReason,
        ) -> usize {
            self.closed
                .lock()
                .expect("test lifecycle mutex")
                .push((principal_key.to_owned(), reason));
            1
        }
    }

    let (auditor, _sink) = operator_auditor();
    let store = Arc::new(
        ClientCredentialStore::open(client_credential_fixture_path("operator-screen"))
            .expect("credential store opens"),
    );
    let read = store
        .issue(
            crate::client_credentials::ClientCredentialIssueRequest::new(
                "Claude Desktop",
                vec!["oracle:read".to_owned()],
            ),
        )
        .expect("issue read client");
    let execute = store
        .issue(
            crate::client_credentials::ClientCredentialIssueRequest::new(
                "Codex CLI",
                vec!["oracle:execute".to_owned()],
            ),
        )
        .expect("issue execute client");
    let read_client_id = read.client_id.clone();
    let read_principal = read.principal_key.clone();
    let read_bearer = read.bearer.expose().to_owned();
    let execute_client_id = execute.client_id.clone();
    let execute_principal = execute.principal_key.clone();
    let execute_bearer = execute.bearer.expose().to_owned();
    store
        .authenticate_bearer(&read_bearer, Some("127.0.0.1:49152"))
        .expect("last-use metadata records");

    let session_store = Arc::new(HttpSessionStore::default());
    let result_store = Arc::new(HttpResultStore::new());
    let lifecycle = Arc::new(RecordingLifecycle::default());
    session_store.insert(
        "read-session".to_owned(),
        read_principal.clone(),
        "2025-03-26".to_owned(),
    );
    session_store.insert(
        "execute-session".to_owned(),
        execute_principal.clone(),
        "2025-03-26".to_owned(),
    );
    result_store.append_response("read-session", serde_json::json!({ "stale": "read" }));
    result_store.append_response("execute-session", serde_json::json!({ "stale": "execute" }));

    let dir = dashboard_test_dir("operator-client-credentials");
    let auth = Arc::new(DashboardAuth::new(dir.clone()));
    let cfg = HttpTransportConfig {
        dashboard_auth: Some(Arc::clone(&auth)),
        operator_auditor: Some(auditor),
        client_credentials: Some(Arc::clone(&store)),
        session_store: Some(Arc::clone(&session_store)),
        result_store: Some(Arc::clone(&result_store)),
        session_lifecycle: Some(lifecycle.clone()),
        ..Default::default()
    };
    let ticket = crate::dashboard_auth::mint_dashboard_pairing_ticket(&dir, "http://127.0.0.1")
        .expect("ticket mints");
    let login = auth
        .exchange_ticket(ticket_from_pairing_url(&ticket.url))
        .expect("login works");
    let cookie_pair = login.session_cookie.split(';').next().expect("cookie pair");
    let view = auth
        .session_view(Some(cookie_pair))
        .expect("session view works");
    let route_ticket = |path: &str| {
        view.action_tickets
            .iter()
            .find(|ticket| ticket.path == path)
            .unwrap_or_else(|| panic!("missing dashboard action ticket for {path}"))
            .ticket
            .clone()
    };
    let rotate_ticket = route_ticket("/operator/v1/client-credentials/rotate");
    let revoke_ticket = route_ticket("/operator/v1/client-credentials/revoke");
    let dashboard_post = |path: &'static str, ticket: &str, body: Value| -> HttpRequest {
        HttpRequest::new(
            "POST",
            path,
            [
                ("host", "127.0.0.1"),
                ("origin", "http://127.0.0.1"),
                ("sec-fetch-site", "same-origin"),
                ("content-type", "application/json"),
                ("accept", "application/json"),
                ("cookie", cookie_pair),
                (DASHBOARD_CSRF_HEADER, view.csrf_token.as_str()),
                (DASHBOARD_ACTION_TICKET_HEADER, ticket),
            ],
            body.to_string().into_bytes(),
        )
        .with_peer_loopback(true)
    };

    let list = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            "/operator/v1/client-credentials",
            [
                ("host", "127.0.0.1"),
                ("accept", "application/json"),
                ("cookie", cookie_pair),
                ("sec-fetch-site", "same-origin"),
            ],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(list.status, 200);
    let list_text = String::from_utf8(list.body.clone()).expect("list body UTF-8");
    assert!(list_text.contains(&read_client_id));
    assert!(list_text.contains("127.0.0.1:49152"));
    assert!(!list_text.contains(&read_bearer));
    assert!(!list_text.contains(&execute_bearer));
    assert!(!list_text.contains("credential_hash"));
    assert!(!list_text.contains("credential_salt"));

    let rotate = handle_http_request(
        &test_server(),
        &cfg,
        dashboard_post(
            "/operator/v1/client-credentials/rotate",
            &rotate_ticket,
            serde_json::json!({ "client_id": read_client_id }),
        ),
    );
    assert_eq!(rotate.status, 200);
    let rotate_body = response_json(&rotate);
    let rotated_bearer = rotate_body["data"]["bearer"]
        .as_str()
        .expect("rotated bearer is shown once");
    assert!(rotated_bearer.starts_with("ocmcp_"));
    assert_eq!(
        rotate_body["data"]["bearer_shown_once"],
        serde_json::json!(true)
    );
    let rotate_text = String::from_utf8(rotate.body.clone()).expect("rotate body UTF-8");
    assert!(!rotate_text.contains(&read_bearer));
    assert!(!rotate_text.contains(&execute_bearer));
    assert!(session_store.principal_for("read-session").is_none());
    assert_eq!(
        session_store.principal_for("execute-session").as_deref(),
        Some(execute_principal.as_str())
    );
    assert!(
        result_store
            .events_after("read-session", None, false)
            .expect("rotated principal buffer removed")
            .is_empty()
    );

    let revoke = handle_http_request(
        &test_server(),
        &cfg,
        dashboard_post(
            "/operator/v1/client-credentials/revoke",
            &revoke_ticket,
            serde_json::json!({ "client_id": execute_client_id }),
        ),
    );
    assert_eq!(revoke.status, 200);
    let revoke_body = response_json(&revoke);
    assert_eq!(revoke_body["data"]["status"], serde_json::json!("revoked"));
    assert!(revoke_body["data"].get("bearer").is_none());
    let revoke_text = String::from_utf8(revoke.body.clone()).expect("revoke body UTF-8");
    assert!(!revoke_text.contains(&execute_bearer));
    assert!(session_store.principal_for("execute-session").is_none());
    assert!(
        result_store
            .events_after("execute-session", None, false)
            .expect("revoked principal buffer removed")
            .is_empty()
    );
    assert_eq!(
        lifecycle
            .closed
            .lock()
            .expect("test lifecycle mutex")
            .as_slice(),
        &[
            (read_principal, DispatchCloseReason::SessionDelete),
            (execute_principal, DispatchCloseReason::SessionDelete),
        ]
    );
}

#[test]
fn uniform_auth_errors_no_enumeration_oracle() {
    let auth_fingerprint = |response: &HttpResponse| {
        (
            response.status,
            response.header("cache-control").map(str::to_owned),
            String::from_utf8_lossy(&response.body).into_owned(),
        )
    };

    let store = Arc::new(
        ClientCredentialStore::open(client_credential_fixture_path("uniform-auth"))
            .expect("credential store opens"),
    );
    let issued = store
        .issue(
            crate::client_credentials::ClientCredentialIssueRequest::new(
                "Codex CLI",
                vec!["oracle:read".to_owned()],
            ),
        )
        .expect("issue client");
    let bearer = issued.bearer.expose().to_owned();
    let unknown_bearer = concat!(
        "ocmcp_client-11111111111111111111111111111111_",
        "2222222222222222222222222222222222222222222222222222222222222222"
    );
    let cfg = HttpTransportConfig {
        json_response: true,
        client_credentials: Some(Arc::clone(&store)),
        ..Default::default()
    };
    let call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "oracle_preview_sql",
            "arguments": { "sql": "SELECT 1 FROM dual" }
        }
    });
    let client_request = |authorization: Option<&str>| {
        let mut request = post(&call);
        if let Some(value) = authorization {
            request
                .headers
                .push(("authorization".to_owned(), format!("Bearer {value}")));
        }
        request
    };
    let missing_client = handle_http_request(&test_server(), &cfg, client_request(None));
    let unknown_client =
        handle_http_request(&test_server(), &cfg, client_request(Some(unknown_bearer)));
    store.revoke(&issued.client_id).expect("revoke client");
    let revoked_client = handle_http_request(&test_server(), &cfg, client_request(Some(&bearer)));
    assert_eq!(
        auth_fingerprint(&unknown_client),
        auth_fingerprint(&missing_client)
    );
    assert_eq!(
        auth_fingerprint(&revoked_client),
        auth_fingerprint(&missing_client)
    );
    assert_eq!(
        response_json(&missing_client)["error"],
        serde_json::json!("client_credential_required")
    );

    let dir = dashboard_test_dir("uniform-auth");
    let auth = Arc::new(DashboardAuth::new(dir.clone()));
    let dashboard_cfg = HttpTransportConfig {
        dashboard_auth: Some(Arc::clone(&auth)),
        ..Default::default()
    };
    let missing_pairing = handle_http_request(
        &test_server(),
        &dashboard_cfg,
        HttpRequest::new(
            "GET",
            DASHBOARD_PAIR_PATH,
            [("host", "127.0.0.1"), ("accept", "text/html")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );
    let invalid_pairing = handle_http_request(
        &test_server(),
        &dashboard_cfg,
        HttpRequest::new(
            "GET",
            format!("{DASHBOARD_PAIR_PATH}?ticket=invalid-bootstrap-secret"),
            [("host", "127.0.0.1"), ("accept", "text/html")],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(
        auth_fingerprint(&invalid_pairing),
        auth_fingerprint(&missing_pairing)
    );
    assert_eq!(
        response_json(&missing_pairing)["error"],
        serde_json::json!("dashboard_pairing_required")
    );

    let ticket = crate::dashboard_auth::mint_dashboard_pairing_ticket(&dir, "http://127.0.0.1")
        .expect("ticket mints");
    let login = auth
        .exchange_ticket(ticket_from_pairing_url(&ticket.url))
        .expect("login works");
    let cookie_pair = login.session_cookie.split(';').next().expect("cookie pair");
    let view = auth
        .session_view(Some(cookie_pair))
        .expect("session view works");
    let dashboard_body = serde_json::json!({
        "tool": "oracle_preview_sql",
        "arguments": { "sql": "SELECT 1 FROM dual" }
    });
    let missing_session = handle_http_request(
        &test_server(),
        &dashboard_cfg,
        HttpRequest::new(
            "POST",
            "/operator/v1/actions/preview",
            [
                ("host", "127.0.0.1"),
                ("origin", "http://127.0.0.1"),
                ("sec-fetch-site", "same-origin"),
                ("content-type", "application/json"),
                ("accept", "application/json"),
            ],
            dashboard_body.to_string().into_bytes(),
        )
        .with_peer_loopback(true),
    );
    let missing_csrf = handle_http_request(
        &test_server(),
        &dashboard_cfg,
        HttpRequest::new(
            "POST",
            "/operator/v1/actions/preview",
            [
                ("host", "127.0.0.1"),
                ("origin", "http://127.0.0.1"),
                ("sec-fetch-site", "same-origin"),
                ("content-type", "application/json"),
                ("accept", "application/json"),
                ("cookie", cookie_pair),
            ],
            dashboard_body.to_string().into_bytes(),
        )
        .with_peer_loopback(true),
    );
    let missing_action_ticket = handle_http_request(
        &test_server(),
        &dashboard_cfg,
        HttpRequest::new(
            "POST",
            "/operator/v1/actions/preview",
            [
                ("host", "127.0.0.1"),
                ("origin", "http://127.0.0.1"),
                ("sec-fetch-site", "same-origin"),
                ("content-type", "application/json"),
                ("accept", "application/json"),
                ("cookie", cookie_pair),
                (DASHBOARD_CSRF_HEADER, view.csrf_token.as_str()),
            ],
            dashboard_body.to_string().into_bytes(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(
        auth_fingerprint(&missing_csrf),
        auth_fingerprint(&missing_session)
    );
    assert_eq!(
        auth_fingerprint(&missing_action_ticket),
        auth_fingerprint(&missing_session)
    );
    assert_eq!(
        response_json(&missing_session)["error"],
        serde_json::json!("dashboard_auth_required")
    );

    let session_store = Arc::new(HttpSessionStore::default());
    session_store.insert(
        "known-session".to_owned(),
        "oauth:owner".to_owned(),
        "2025-03-26".to_owned(),
    );
    let stateful_cfg = HttpTransportConfig {
        stateful: true,
        session_store: Some(session_store),
        ..Default::default()
    };
    let unknown_session = HttpRequest::new(
        "POST",
        MCP_PATH,
        [("host", "127.0.0.1"), ("mcp-session-id", "unknown-session")],
        Vec::new(),
    );
    let cross_principal_session = HttpRequest::new(
        "POST",
        MCP_PATH,
        [("host", "127.0.0.1"), ("mcp-session-id", "known-session")],
        Vec::new(),
    );
    let unknown =
        validate_stateful_session(&stateful_cfg, &unknown_session, Some("oauth:other"), false)
            .err()
            .expect("unknown session rejected");
    let cross_principal = validate_stateful_session(
        &stateful_cfg,
        &cross_principal_session,
        Some("oauth:other"),
        false,
    )
    .err()
    .expect("cross-principal session rejected");
    assert_eq!(
        auth_fingerprint(&cross_principal),
        auth_fingerprint(&unknown)
    );
}

#[test]
fn scoped_principal_cannot_act_as_operator_without_allowlist_and_operator_action_is_audited() {
    let token = jwt_with_scope("oracle:read");
    let principal_key = oauth_principal_key_from_validated_token(&token);
    let (auditor, sink) = operator_auditor();
    let denied_cfg = HttpTransportConfig {
        oauth: Some(accepting_oauth_enforcement(Vec::new())),
        operator_auditor: Some(Arc::clone(&auditor)),
        operator_authority: OperatorAuthorityPolicy {
            allow_loopback_owner: true,
            local_owner_stable_id: "process-owner".to_owned(),
            allowed_subjects: Vec::new(),
        },
        ..Default::default()
    };
    let request = || {
        HttpRequest::new(
            "GET",
            "/operator/v1/sessions?force=true",
            [
                ("host", "127.0.0.1"),
                ("accept", "application/json"),
                ("authorization", &format!("Bearer {token}")),
            ],
            Vec::new(),
        )
        .with_peer_loopback(true)
    };

    let denied = handle_http_request(&test_server(), &denied_cfg, request());
    assert_eq!(denied.status, 403);
    let denied_body = response_json(&denied);
    assert_eq!(
        denied_body["error"],
        serde_json::json!("operator_authority_required")
    );
    assert!(
        sink.records().is_empty(),
        "denied scoped-principal attempt is not an operator action"
    );

    let allowed_cfg = HttpTransportConfig {
        operator_authority: OperatorAuthorityPolicy {
            allow_loopback_owner: false,
            local_owner_stable_id: "process-owner".to_owned(),
            allowed_subjects: vec![principal_key.clone()],
        },
        ..denied_cfg
    };
    let allowed = handle_http_request(&test_server(), &allowed_cfg, request());
    assert_eq!(allowed.status, 404);
    let records = sink.records();
    assert_eq!(records.len(), 1);
    let (_, stable_id) = principal_key.split_once(':').expect("principal key");
    assert_eq!(
        records[0].subject,
        AuditSubject::new("oauth", stable_id).with_authn_method("oauth")
    );
    assert_eq!(records[0].tool, "operator_api");
    assert_eq!(records[0].sql_preview, "GET /operator/v1/sessions");
    assert!(!records[0].sql_preview.contains("force=true"));
}

// ===================================================================
// K10 — streaming query results over SSE (the streaming assembly)
// ===================================================================

fn streaming_query_response() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 7,
        "result": {
            "structuredContent": {
                "streaming": true,
                "columns": ["ID", "NAME"],
                "chunk_count": 2,
                "row_count": 3,
                "truncated": false,
                "next_cursor": Value::Null,
                "chunks": [
                    { "seq": 0, "rows": [{"ID": "1", "NAME": "a"}, {"ID": "2", "NAME": "b"}],
                      "row_count": 2, "total_bytes": 40, "next_cursor": "sealed-cursor-0", "last": false },
                    { "seq": 1, "rows": [{"ID": "3", "NAME": "c"}],
                      "row_count": 1, "total_bytes": 20, "next_cursor": Value::Null, "last": true }
                ]
            }
        }
    })
}

#[test]
fn streaming_query_chunks_detects_only_streaming_results() {
    // A streaming oracle_query result exposes its ordered chunks.
    let streaming = streaming_query_response();
    let chunks = streaming_query_chunks(&streaming).expect("streaming result has chunks");
    assert_eq!(chunks.len(), 2);
    assert_eq!(chunks[0]["seq"], json!(0));

    // A plain (non-streaming) tool result is never treated as streaming.
    let inline = json!({
        "jsonrpc": "2.0", "id": 1,
        "result": { "structuredContent": { "columns": ["ID"], "rows": [], "row_count": 0 } }
    });
    assert!(streaming_query_chunks(&inline).is_none());

    // A streaming flag without a chunks array degrades to None (no framing).
    let no_chunks = json!({
        "jsonrpc": "2.0", "id": 1,
        "result": { "structuredContent": { "streaming": true } }
    });
    assert!(streaming_query_chunks(&no_chunks).is_none());

    // An error response (no result) is never streaming.
    let err = json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32000, "message": "x" } });
    assert!(streaming_query_chunks(&err).is_none());
}

#[test]
fn write_query_stream_chunks_frames_each_chunk_as_an_sse_event() {
    let streaming = streaming_query_response();
    let chunks = streaming_query_chunks(&streaming).expect("chunks");
    let mut body = Vec::new();
    let framed = write_query_stream_chunks(&mut body, chunks);
    assert_eq!(framed, 2, "one SSE frame per chunk");
    let text = String::from_utf8(body).expect("utf8 SSE body");
    // Each chunk is its own `event: chunk` frame with a monotonic, resumable id.
    assert_eq!(text.matches("event: chunk\n").count(), 2);
    assert!(text.contains("id: chunk/0\n"));
    assert!(text.contains("id: chunk/1\n"));
    // The chunk rows ride in the frame data (progressive delivery).
    assert!(text.contains("\"NAME\":\"a\""));
    assert!(text.contains("\"NAME\":\"c\""));
    // The re-sealed cursor of a non-final chunk is carried for resume.
    assert!(text.contains("sealed-cursor-0"));
}

#[test]
fn sse_response_emits_chunk_frames_before_the_authoritative_result() {
    // End-to-end SSE assembly: a streaming query response frames each page as
    // its own `event: chunk` SSE event, THEN the authoritative response frame —
    // a plain client still reads the final result; a streaming-aware client
    // renders chunks progressively.
    let cfg = HttpTransportConfig::default();
    let response = sse_response(
        &cfg,
        Some("tools/call"),
        streaming_query_response(),
        None,
        "principal-test",
        Some("1/0"),
    );
    assert_eq!(response.status, 200);
    let text = String::from_utf8(response.body).expect("utf8 SSE body");
    assert_eq!(
        text.matches("event: chunk\n").count(),
        2,
        "two page chunks framed as SSE events"
    );
    // The chunk frames precede the authoritative response frame (id 1/0).
    let first_chunk = text.find("event: chunk\n").expect("chunk frame present");
    let response_frame = text
        .find("id: 1/0\n")
        .expect("authoritative response frame");
    assert!(
        first_chunk < response_frame,
        "chunks stream before the final result"
    );

    // A NON-streaming response is unchanged: no chunk frames, just the result.
    let inline = json!({
        "jsonrpc": "2.0", "id": 1,
        "result": { "structuredContent": { "columns": ["ID"], "rows": [], "row_count": 0 } }
    });
    let plain = sse_response(
        &cfg,
        Some("tools/call"),
        inline,
        None,
        "principal-test",
        Some("1/0"),
    );
    let plain_text = String::from_utf8(plain.body).expect("utf8");
    assert!(
        !plain_text.contains("event: chunk\n"),
        "no chunk frames for inline reads"
    );
}
