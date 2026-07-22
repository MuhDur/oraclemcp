use super::operator::config_error_value;

#[test]
fn config_preview_errors_keep_their_distinct_operator_codes() {
    for (error, status, expected_code) in [
        (ConfigOpsError::PreviewRequired, 400, "config_preview_required"),
        (
            ConfigOpsError::InvalidPreviewToken,
            409,
            "config_preview_token_invalid",
        ),
        (
            ConfigOpsError::PreviewExpired,
            409,
            "config_preview_expired",
        ),
        (
            ConfigOpsError::PreviewDraftChanged,
            409,
            "config_preview_draft_changed",
        ),
        (
            ConfigOpsError::PreviewConfirmationRequired,
            409,
            "config_preview_confirmation_required",
        ),
    ] {
        let (actual_status, body) = config_error_value(error);
        assert_eq!(actual_status, status);
        assert_eq!(body["error"], serde_json::json!(expected_code));
        assert!(body["message"].as_str().is_some_and(|message| !message.is_empty()));
    }
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
    assert_operator_audit_pair(&records, AuditDecision::Blocked, AuditOutcome::Failed);
    assert_eq!(
        records[0].sql_preview,
        "<sql text redacted; see sql_sha256>"
    );
    assert_eq!(
        records[0].sql_sha256,
        oraclemcp_audit::sha256_hex(b"GET /operator/v1/sessions")
    );
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
fn operator_malformed_body_and_rate_limit_emit_blocked_terminal_records() {
    let (auditor, sink) = operator_auditor();
    let limiters = Arc::new(HttpRequestRateLimiters::new(HttpRequestRateLimitConfig {
        rate_per_second: 1,
        burst: 2,
        max_buckets: 8,
    }));
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        request_rate_limits: Arc::clone(&limiters),
        ..Default::default()
    };

    let malformed = handle_http_request(
        &test_server(),
        &cfg,
        operator_json_post(
            "/operator/v1/lanes/cancel",
            &serde_json::json!(["not", "an", "object"]),
        ),
    );
    assert_eq!(malformed.status, 400);

    let first_health = handle_http_request(
        &test_server(),
        &cfg,
        operator_json_get("/operator/v1/health"),
    );
    assert_eq!(first_health.status, 200);
    let throttled = handle_http_request(
        &test_server(),
        &cfg,
        operator_json_get("/operator/v1/health"),
    );
    assert_eq!(throttled.status, 429);

    let records = sink.records();
    assert_eq!(records.len(), 6);
    assert_operator_audit_pair(&records[0..2], AuditDecision::Blocked, AuditOutcome::Failed);
    assert_operator_audit_pair(
        &records[2..4],
        AuditDecision::Allowed,
        AuditOutcome::Succeeded,
    );
    assert_operator_audit_pair(&records[4..6], AuditDecision::Blocked, AuditOutcome::Failed);
    assert_ne!(
        records[2].correlation.as_ref().unwrap().request_sha256,
        records[4].correlation.as_ref().unwrap().request_sha256,
        "identical repeated routes must still have unique correlation ids"
    );
}

#[test]
fn operator_conflict_and_provider_failure_never_emit_success_terminals() {
    let (auditor, sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        ..Default::default()
    };

    let conflict = handle_http_request(
        &test_server(),
        &cfg,
        operator_json_post(
            "/operator/v1/lanes/cancel",
            &serde_json::json!({ "lane_id": "lane-a" }),
        ),
    );
    assert_eq!(conflict.status, 409);
    let unavailable = handle_http_request(
        &test_server(),
        &cfg,
        operator_json_get("/operator/v1/config"),
    );
    assert_eq!(unavailable.status, 503);

    let records = sink.records();
    assert_eq!(records.len(), 4);
    assert_operator_audit_pair(&records[0..2], AuditDecision::Blocked, AuditOutcome::Failed);
    assert_operator_audit_pair(&records[2..4], AuditDecision::Allowed, AuditOutcome::Failed);
}

#[test]
fn interrupted_operator_request_leaves_only_an_honest_pending_attempt() {
    let (auditor, sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        ..Default::default()
    };
    let request = operator_json_post(
        "/operator/v1/actions/execute",
        &serde_json::json!({ "tool": "oracle_query" }),
    );
    let subject = AuditSubject::new("local-owner", "process-owner").with_authn_method("loopback");

    let attempt = begin_operator_audit(&cfg, &subject, &request).expect("durable attempt");
    let records = sink.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].seq, attempt.seq);
    assert_eq!(records[0].outcome, AuditOutcome::Pending);
    assert_eq!(records[0].correlation.as_ref().unwrap().parent_seq, None);
    assert_eq!(
        records[0].correlation.as_ref().unwrap().request_sha256,
        attempt.request_sha256
    );
    assert!(records[0].hash_is_valid());
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

#[test]
fn rejected_initialize_does_not_allocate_stateful_session_state() {
    let sessions = Arc::new(HttpSessionStore::default());
    let results = Arc::new(HttpResultStore::new());
    let cfg = HttpTransportConfig {
        stateful: true,
        session_store: Some(Arc::clone(&sessions)),
        result_store: Some(Arc::clone(&results)),
        ..Default::default()
    };
    for rejected in [
        serde_json::json!({
            "jsonrpc": "1.0",
            "id": 1,
            "method": "initialize",
            "params": { "protocolVersion": "2025-11-25" }
        }),
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": []
        }),
    ] {
        let response = handle_http_request(&test_server(), &cfg, post(&rejected));

        assert!(
            String::from_utf8_lossy(&response.body).contains("\"error\""),
            "rejected initialize response must retain its JSON-RPC error"
        );
        assert_eq!(response.header("mcp-session-id"), None);
        assert_eq!(response.header("set-cookie"), None);
        assert_eq!(sessions.len(), 0);
        assert_eq!(results.session_count(), 0);
    }

    let parse_error = HttpRequest::new(
        "POST",
        MCP_PATH,
        [
            ("host", "127.0.0.1"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
        ],
        b"{".to_vec(),
    );
    let response = handle_http_request(&test_server(), &cfg, parse_error);
    assert_eq!(response.header("mcp-session-id"), None);
    assert_eq!(response.header("set-cookie"), None);
    assert_eq!(sessions.len(), 0);
    assert_eq!(results.session_count(), 0);
}

#[test]
fn stateful_session_caps_are_atomic_per_principal_and_global_and_release_on_delete() {
    let sessions = Arc::new(HttpSessionStore::with_limits_for_test(2, 1));
    let results = Arc::new(HttpResultStore::new());
    let cfg = HttpTransportConfig {
        stateful: true,
        session_store: Some(Arc::clone(&sessions)),
        result_store: Some(Arc::clone(&results)),
        ..Default::default()
    };
    let initialize = |principal: &str| {
        handle_mcp_post(
            &test_server(),
            &cfg,
            &post(&init_body()),
            None,
            Some(principal),
        )
    };

    let alice = initialize("oauth:alice@example.invalid");
    let alice_session = alice
        .header("mcp-session-id")
        .expect("first principal admitted")
        .to_owned();
    assert_eq!(sessions.len(), 1);
    assert_eq!(results.session_count(), 1);

    let same_principal = initialize("oauth:alice@example.invalid");
    assert_eq!(same_principal.status, 429);
    assert_eq!(same_principal.header("mcp-session-id"), None);
    assert_eq!(same_principal.header("set-cookie"), None);
    let same_body = String::from_utf8_lossy(&same_principal.body);
    assert!(same_body.contains("AT_CAPACITY"));
    assert!(same_body.contains("stateful_sessions_principal"));
    assert!(!same_body.contains("alice@example.invalid"));
    assert_eq!(sessions.len(), 1);
    assert_eq!(results.session_count(), 1);

    let bob = initialize("oauth:bob@example.invalid");
    assert!(bob.header("mcp-session-id").is_some());
    let global = initialize("oauth:carol@example.invalid");
    assert_eq!(global.status, 429);
    assert!(String::from_utf8_lossy(&global.body).contains("stateful_sessions_global"));
    assert_eq!(sessions.len(), 2);
    assert_eq!(results.session_count(), 2);

    let delete = HttpRequest::new(
        "DELETE",
        MCP_PATH,
        [
            ("host", "127.0.0.1"),
            ("mcp-session-id", alice_session.as_str()),
        ],
        Vec::new(),
    );
    assert_eq!(
        handle_mcp_delete(&test_server(), &cfg, &delete, "oauth:alice@example.invalid",).status,
        202
    );
    assert_eq!(sessions.len(), 1);
    assert_eq!(results.session_count(), 1);
    assert!(
        initialize("oauth:alice@example.invalid")
            .header("mcp-session-id")
            .is_some(),
        "DELETE releases both per-principal and global capacity"
    );
    assert_eq!(sessions.len(), 2);
    assert_eq!(results.session_count(), 2);
}

#[test]
fn stateful_initialize_storm_cannot_exceed_registry_cardinality() {
    let sessions = Arc::new(HttpSessionStore::with_limits_for_test(4, 2));
    let results = Arc::new(HttpResultStore::new());
    let cfg = HttpTransportConfig {
        stateful: true,
        session_store: Some(Arc::clone(&sessions)),
        result_store: Some(Arc::clone(&results)),
        ..Default::default()
    };

    for index in 0..100 {
        let principal = format!("oauth:storm-{index}@example.invalid");
        let _ = handle_mcp_post(
            &test_server(),
            &cfg,
            &post(&init_body()),
            None,
            Some(&principal),
        );
    }

    assert_eq!(sessions.len(), 4);
    assert_eq!(results.session_count(), 4);
}

fn big_result_http_server(payload_bytes: usize, ceiling: usize) -> OracleMcpServer {
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
        Arc::new(BigResultDispatch { payload_bytes }),
    )
    .with_response_byte_budget(crate::response_budget::ResponseByteBudget::new(ceiling, 0))
}

// QA100 `.116`: an oversized tool response on the stateless JSON HTTP path is
// refused with the bounded typed error, and the serialized wire body stays
// within the ceiling.
#[test]
fn stateless_json_oversized_tool_response_is_refused_with_bounded_error() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: false,
        ..Default::default()
    };
    let server = big_result_http_server(16_384, 4_096);
    let call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": { "name": "big_tool", "arguments": {} }
    });
    let response = handle_http_request(&server, &cfg, post(&call));
    assert_eq!(response.status, 200);
    let body = response_json(&response);
    assert!(
        body.get("result").is_none(),
        "the oversized payload is not delivered"
    );
    assert_eq!(body["id"], serde_json::json!(7), "id is preserved");
    assert_eq!(
        body["error"]["data"]["reason"],
        serde_json::json!("response_too_large")
    );
    assert!(
        response.body.len() <= 4_096,
        "the refused response body ({} bytes) stays within the whole-response ceiling",
        response.body.len()
    );
    assert!(
        !String::from_utf8_lossy(&response.body).contains(&"Q".repeat(64)),
        "the oversized blob never reaches the wire"
    );
}

// QA100 `.116`: on the stateful SSE path, an oversized tool response is refused
// with the bounded typed error BEFORE replay insertion — the replay store never
// retains the oversized payload, only the small bounded error.
#[test]
fn stateful_sse_oversized_tool_response_is_refused_before_replay_insertion() {
    let result_store = Arc::new(HttpResultStore::new());
    let cfg = HttpTransportConfig {
        stateful: true,
        session_store: Some(Arc::new(HttpSessionStore::default())),
        result_store: Some(Arc::clone(&result_store)),
        ..Default::default()
    };
    let server = big_result_http_server(64_000, 4_096);
    let init = handle_http_request(&server, &cfg, post(&init_body()));
    let session_id = init
        .header("mcp-session-id")
        .expect("stateful init session id")
        .to_owned();

    let call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": { "name": "big_tool", "arguments": {} }
    });
    let call_request = HttpRequest::new(
        "POST",
        MCP_PATH,
        [
            ("host", "127.0.0.1"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
            ("mcp-session-id", session_id.as_str()),
            ("mcp-protocol-version", "2025-11-25"),
        ],
        call.to_string().into_bytes(),
    );
    let response = handle_http_request(&server, &cfg, call_request);
    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-type"), Some("text/event-stream"));

    let events = sse_json_events(&response);
    let refused = events
        .iter()
        .find(|event| event["id"] == serde_json::json!(11))
        .expect("the SSE stream carries the tool response frame");
    assert!(refused.get("result").is_none());
    assert_eq!(
        refused["error"]["data"]["reason"],
        serde_json::json!("response_too_large")
    );
    assert!(
        !String::from_utf8_lossy(&response.body).contains(&"Q".repeat(64)),
        "the oversized blob is not framed onto the SSE wire"
    );

    // The replay store retained only the bounded error, never the oversized
    // payload: total retained bytes are far below the oversized payload size.
    let (retained_total, sessions) = result_store.retained_bytes_for_test();
    assert!(
        retained_total < 4_096,
        "replay retained only the bounded error ({retained_total} bytes), not the oversized payload"
    );
    assert!(
        sessions.iter().all(|(_, bytes)| *bytes < 4_096),
        "no session retained the oversized payload"
    );

    // Replaying the buffered result serves the bounded error, not the payload.
    let replay = handle_http_request(
        &server,
        &cfg,
        HttpRequest::new(
            "GET",
            "/mcp?cursor=0",
            [
                ("host", "127.0.0.1"),
                ("accept", "text/event-stream"),
                ("mcp-session-id", session_id.as_str()),
            ],
            Vec::new(),
        ),
    );
    assert_eq!(replay.status, 200);
    let replay_body = String::from_utf8_lossy(&replay.body);
    assert!(replay_body.contains("response_too_large"));
    assert!(!replay_body.contains(&"Q".repeat(64)));
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

    fn with_lanes(lane_ids: &[&str]) -> Self {
        Self {
            lanes: lane_ids
                .iter()
                .enumerate()
                .map(|(i, lane_id)| HttpLaneSnapshot {
                    lane_id: (*lane_id).to_owned(),
                    generation: 7,
                    status: "active",
                    subject_id_hash: format!("subject-sha256:{i}"),
                })
                .collect(),
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
    closed: parking_lot::Mutex<Vec<(String, String, DispatchCloseReason)>>,
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
        self.closed.lock().push((
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
fn operator_lane_cancel_invalidates_the_mcp_session_and_replay_buffer() {
    // QA100 .91: an operator lane kill must invalidate the WHOLE MCP session,
    // not just close the lane. Before this fix the session id stayed resolvable
    // in the session store and its buffered stream results remained replayable
    // after an operator "kill".
    let session_id = "mcp-session:lane-a";
    let sessions = Arc::new(HttpSessionStore::default());
    sessions.insert(
        session_id.to_owned(),
        "principal:subject-sha256:abc".to_owned(),
        "2025-06-18".to_owned(),
    );
    let results = Arc::new(HttpResultStore::new());
    results.ensure_session(session_id);
    results.append_response(session_id, serde_json::json!({ "ok": true }));
    assert_eq!(results.session_count(), 1);

    let (auditor, _sink) = operator_auditor();
    let lifecycle = Arc::new(CancelRecordingLifecycle::default());
    let cfg = HttpTransportConfig {
        stateful: true,
        operator_auditor: Some(auditor),
        session_store: Some(Arc::clone(&sessions)),
        result_store: Some(Arc::clone(&results)),
        session_lifecycle: Some(Arc::clone(&lifecycle) as Arc<dyn HttpSessionLifecycle>),
        ..Default::default()
    };
    let cancel = HttpRequest::new(
        "POST",
        "/operator/v1/lanes/cancel",
        [
            ("host", "127.0.0.1"),
            ("content-type", "application/json"),
            ("accept", "application/json"),
        ],
        serde_json::json!({ "lane_id": "lane-a" })
            .to_string()
            .into_bytes(),
    )
    .with_peer_loopback(true);

    let ok = handle_http_request(&test_server(), &cfg, cancel);
    assert_eq!(ok.status, 200);
    assert_eq!(
        response_json(&ok)["data"]["terminated"],
        serde_json::json!(true)
    );

    // The lane close still happened, and the MCP session is now fully invalid:
    // the session store dropped it and its replay buffer is gone.
    assert_eq!(lifecycle.closed.lock().len(), 1);
    assert!(
        !sessions.remove(session_id),
        "operator cancel must have already removed the HTTP session"
    );
    assert_eq!(
        results.session_count(),
        0,
        "operator cancel must drop the session's stream replay buffer"
    );
    assert!(
        results
            .append_response_if_session(session_id, serde_json::json!({ "late": true }))
            .is_none(),
        "no stream result can be appended to a cancelled session"
    );
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
        lifecycle.closed.lock().is_empty(),
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
        let closed = lifecycle.closed.lock();
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].0, "mcp-session:lane-a");
        assert_eq!(closed[0].1, "principal:subject-sha256:abc");
        assert_eq!(closed[0].2, DispatchCloseReason::OperatorCancel);
    }

    let records = sink.records();
    assert_operator_audit_pair(&records, AuditDecision::Allowed, AuditOutcome::Succeeded);
    assert_eq!(
        records[0].sql_preview,
        "<sql text redacted; see sql_sha256>"
    );
    assert_eq!(
        records[0].sql_sha256,
        oraclemcp_audit::sha256_hex(b"POST /operator/v1/lanes/cancel")
    );

    // Unknown lane id: 404, no termination.
    let unknown = handle_http_request(&test_server(), &cfg, cancel_request(true, "lane-z"));
    assert_eq!(unknown.status, 404);
    assert_eq!(
        response_json(&unknown)["data"]["error"],
        serde_json::json!("operator_lane_not_found")
    );
    assert_eq!(
        lifecycle.closed.lock().len(),
        1,
        "unknown lane must not terminate anything"
    );
    let records = sink.records();
    assert_eq!(records.len(), 4);
    assert_operator_audit_pair(&records[2..], AuditDecision::Blocked, AuditOutcome::Failed);
}

#[test]
fn operator_dispatch_cancellation_is_terminal_failure_with_cancel_evidence() {
    let (auditor, sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        ..Default::default()
    };
    let response = handle_http_request(
        &cancelled_server(),
        &cfg,
        operator_json_post(
            "/operator/v1/actions/execute",
            &serde_json::json!({
                "idempotency_key": "cancelled-operator-action",
                "tool": "oracle_query",
                "arguments": { "sql": "SELECT 1 FROM dual" }
            }),
        ),
    );

    assert_eq!(response.status, 499);
    assert_eq!(
        response_json(&response)["outcome"],
        serde_json::json!("cancelled")
    );
    let records = sink.records();
    assert_operator_audit_pair(&records, AuditDecision::Allowed, AuditOutcome::Failed);
    assert_eq!(
        records[1].cancel,
        Some(AuditCancel::new(
            "Transport",
            "operator_request_cancelled_before_terminal_result"
        ))
    );

    let panicked = handle_http_request(
        &panicked_server(),
        &cfg,
        operator_json_post(
            "/operator/v1/actions/execute",
            &serde_json::json!({
                "idempotency_key": "panicked-operator-action",
                "tool": "oracle_query",
                "arguments": { "sql": "SELECT 1 FROM dual" }
            }),
        ),
    );
    assert_eq!(panicked.status, 500);
    assert_eq!(
        response_json(&panicked)["outcome"],
        serde_json::json!("panicked")
    );
    let records = sink.records();
    assert_eq!(records.len(), 4);
    assert_operator_audit_pair(&records[2..], AuditDecision::Allowed, AuditOutcome::Failed);
    assert_eq!(records[3].cancel, None);
}

#[test]
fn terminal_audit_failure_surfaces_indeterminate_after_control_side_effect() {
    let (auditor, sink) = terminal_failing_operator_auditor();
    let lifecycle = Arc::new(CancelRecordingLifecycle::default());
    let cfg = HttpTransportConfig {
        stateful: true,
        operator_auditor: Some(auditor),
        session_lifecycle: Some(Arc::clone(&lifecycle) as Arc<dyn HttpSessionLifecycle>),
        ..Default::default()
    };
    let response = handle_http_request(
        &test_server(),
        &cfg,
        operator_json_post(
            "/operator/v1/lanes/cancel",
            &serde_json::json!({ "lane_id": "lane-a" }),
        ),
    );

    assert_eq!(response.status, 500);
    let body = response_json(&response);
    assert_eq!(
        body["error"],
        serde_json::json!("operator_terminal_audit_failed")
    );
    assert_eq!(body["outcome"], serde_json::json!("indeterminate"));
    assert_eq!(body["side_effects"], serde_json::json!("may_have_occurred"));
    assert_eq!(body["original_http_status"], serde_json::json!(200));
    assert!(body["request_sha256"].as_str().is_some_and(|value| {
        value.starts_with("sha256:") && value.len() == "sha256:".len() + 64
    }));
    assert_eq!(
        lifecycle.closed.lock().len(),
        1,
        "the response must not falsely claim rollback after the side effect"
    );
    let records = sink.records.lock().clone();
    assert_eq!(records.len(), 1, "only the durable Pending record exists");
    assert_eq!(records[0].outcome, AuditOutcome::Pending);
    assert_eq!(body["pending_audit_seq"], serde_json::json!(records[0].seq));
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
        result_masking: None,
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
    let key = oraclemcp_audit::SigningKey::new(
        "ladder-test",
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .expect("valid test key");
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

// E4 (bead oraclemcp-eng-program-bp8ia.6.4): "no green-for-blocked rendering
// anywhere". `classifier_verdict_from_record` is the map from a raw audit
// `decision` string to the CLASSIFIER-LIVE ladder the dashboard renders. Its
// match arm falls through to `_ => return None` for anything it does not
// recognize, which drops the record from the ladder entirely rather than
// defaulting it to a verdict. This test pins that default: an unrecognized,
// empty, or case-mismatched decision NEVER becomes `"PASS"` (or any verdict) —
// it is silently absent, exactly like the `operator_api` meta-entry filter
// just above it, not silently affirmed.
#[test]
fn classifier_verdict_never_defaults_an_unrecognized_decision_to_pass() {
    for decision in [
        "",
        "UNKNOWN",
        "allowed",  // lowercase: the real field is emitted upper-case; a
        // case mismatch must not be treated as a match.
        "ALLOWED ", // trailing whitespace: not an exact match either.
        "PENDING",
        "ERROR",
    ] {
        let record = serde_json::json!({
            "tool": "oracle_query",
            "decision": decision,
            "seq": 1,
        });
        assert_eq!(
            classifier_verdict_from_record(&record),
            None,
            "decision {decision:?} must never be surfaced as a verdict, let alone PASS"
        );
    }

    // Sanity check on the same helper: the one decision that legitimately
    // means "admitted" really does map to PASS, so the assertions above are
    // proving an absence, not a helper that always returns None.
    let allowed = serde_json::json!({
        "tool": "oracle_query",
        "decision": "ALLOWED",
        "seq": 2,
    });
    let verdict = classifier_verdict_from_record(&allowed).expect("ALLOWED must produce a verdict");
    assert_eq!(verdict["verdict"], serde_json::json!("PASS"));

    // A record with no `decision` field at all (defaults to "" via
    // `unwrap_or_default`) must take the same fail-closed path as an
    // explicitly empty string, never PASS.
    let no_decision = serde_json::json!({ "tool": "oracle_query", "seq": 3 });
    assert_eq!(classifier_verdict_from_record(&no_decision), None);
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
    assert!(
        schema_body["routes"]
            .as_array()
            .expect("routes")
            .iter()
            .any(|route| route["path"] == "/operator/v1/ci-lanes")
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
        serde_json::json!(64)
    );
    assert_eq!(
        metrics_body["data"]["capacity"]["stateful_lanes"]["reserve"]["operator"],
        serde_json::json!(0)
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
        records.len() >= 10,
        "schema, health, metrics, events, and action routes are audited"
    );
    for record in records.iter().take(10) {
        assert_eq!(record.sql_preview, "<sql text redacted; see sql_sha256>");
    }
    for (pair, action) in records.chunks_exact(2).zip([
        "GET /operator/v1/schema",
        "GET /operator/v1/health",
        "GET /operator/v1/metrics",
        "GET /operator/v1/events",
        "POST /operator/v1/actions/preview",
    ]) {
        assert_operator_audit_pair(pair, AuditDecision::Allowed, AuditOutcome::Succeeded);
        assert_eq!(
            pair[0].sql_sha256,
            oraclemcp_audit::sha256_hex(action.as_bytes())
        );
    }
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
fn audit_tail_projects_hash_covered_operator_correlation() {
    let key = oraclemcp_audit::SigningKey::new(
        "tail-correlation",
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .expect("valid key");
    let draft = audit_tail_draft(
        "operator",
        "operator_api",
        "POST /operator/v1/actions/execute",
        "OPERATOR",
        AuditOutcome::Failed,
        None,
    );
    let record = AuditRecord::chained_signed_correlated(
        &draft,
        9,
        GENESIS_HASH,
        "unix:1".to_owned(),
        &key,
        Some(AuditCorrelation::terminal("sha256:request-9", 8)),
    );

    let redacted = redacted_audit_record(&record, None);
    assert_eq!(
        redacted["correlation"]["request_sha256"],
        serde_json::json!("sha256:request-9")
    );
    assert_eq!(redacted["correlation"]["parent_seq"], serde_json::json!(8));
    assert_eq!(redacted["outcome"], serde_json::json!("FAILED"));
    assert!(record.hash_is_valid());
}

#[test]
fn audit_tail_projects_a_bound_redacted_verdict_certificate() {
    let path = write_certificate_audit_tail_fixture("verdict-certificate");
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
    let record = &body["data"]["records"][0];
    let certificate = &record["verdict_certificate"];
    assert_eq!(
        record["observed_scn"],
        serde_json::json!(42_000_001_u64),
        "the audit tail exposes the exact SCN recorded for replay"
    );
    // The four client-side checks from the verdict-proof inspector all hold.
    assert_eq!(
        certificate["bound_audit_hash"], record["proof"]["entry_hash"],
        "certificate is bound to this exact signed audit record"
    );
    assert_eq!(certificate["stmt_digest"], record["sql_sha256"]);
    assert_eq!(
        certificate["derivation"][0]["rule_id"],
        serde_json::json!("R16")
    );
    assert_eq!(
        certificate["derivation"][0]["construct"],
        serde_json::json!("final_verdict:SAFE")
    );
    assert_eq!(record["proof"]["hash_valid"], serde_json::json!(true));
    assert!(
        record["verdict_certificate_core_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:")),
        "the signed record exposes the certificate core hash"
    );

    let rendered = body.to_string();
    for forbidden in [
        "payroll",
        "secret_bonus",
        "secret_employee",
        "SELECT payroll",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "audit-tail certificate must not expose SQL, binds, or identifiers: {forbidden}"
        );
    }
}

#[test]
fn audit_tail_omits_a_certificate_forged_after_the_signed_append() {
    let path = write_certificate_audit_tail_fixture("forged-verdict-certificate");
    let persisted = std::fs::read_to_string(&path).expect("read certificate fixture");
    let forged = persisted.replacen("final_verdict:SAFE", "final_verdict:FORBIDDEN", 1);
    assert_ne!(
        persisted, forged,
        "fixture must contain the registered label"
    );
    std::fs::write(&path, forged).expect("rewrite only the unauthenticated sidecar envelope");

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
    let record = &response_json(&response)["data"]["records"][0];
    assert_eq!(record["proof"]["hash_valid"], serde_json::json!(true));
    assert!(
        record["verdict_certificate"].is_null()
            && record["verdict_certificate_core_hash"].is_null(),
        "the HTTP surface must not promote a certificate whose core no longer matches the signed record"
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
fn operator_events_reject_an_inactive_lane_id() {
    // QA100 .24: a specific lane_id must name an active lane; the default
    // aggregate stream is always valid; a bogus lane is refused so a caller
    // cannot mint unbounded distinct streams from attacker-chosen lane ids.
    let (auditor, _sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        operator_events: Arc::new(OperatorEventStore::new()),
        session_lifecycle: Some(Arc::new(StaticLaneLifecycle::with_lanes(&["lane-a"]))),
        ..Default::default()
    };
    let get = |target: &'static str| {
        HttpRequest::new(
            "GET",
            target,
            [("host", "127.0.0.1"), ("accept", "text/event-stream")],
            Vec::new(),
        )
        .with_peer_loopback(true)
    };
    assert_eq!(
        handle_http_request(
            &test_server(),
            &cfg,
            get("/operator/v1/events?lane_id=lane-a")
        )
        .status,
        200,
        "an active lane is served"
    );
    assert_eq!(
        handle_http_request(&test_server(), &cfg, get("/operator/v1/events")).status,
        200,
        "the default aggregate stream is always served"
    );
    let refused = handle_http_request(
        &test_server(),
        &cfg,
        get("/operator/v1/events?lane_id=lane-nope"),
    );
    assert_eq!(refused.status, 404);
    assert_eq!(
        response_json(&refused)["data"]["error"],
        serde_json::json!("operator_lane_not_active")
    );
}

#[test]
fn operator_event_store_caps_the_number_of_streams() {
    // QA100 .24: the store bounds the number of distinct streams; excess ones are
    // LRU-evicted so many lane ids cannot grow memory without limit.
    let store = OperatorEventStore::new();
    for i in 0..(MAX_OPERATOR_EVENT_STREAMS + 50) {
        let _ = store.append_snapshot_and_resume(
            "subject",
            &format!("lane-{i}"),
            None,
            None,
            false,
            serde_json::json!({ "n": i }),
        );
    }
    assert!(
        store.streams.lock().len() <= MAX_OPERATOR_EVENT_STREAMS,
        "operator event stream count must stay bounded"
    );
}

#[test]
fn operator_events_resume_is_lane_scoped() {
    let (auditor, _sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        operator_events: Arc::new(OperatorEventStore::new()),
        session_lifecycle: Some(Arc::new(StaticLaneLifecycle::with_lanes(&[
            "lane-a", "lane-b",
        ]))),
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
        session_lifecycle: Some(Arc::new(StaticLaneLifecycle::with_lanes(&["lane-a"]))),
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

fn idempotency_fact(key: &str) -> OperatorIdempotencyFacts {
    OperatorIdempotencyFacts {
        storage_key: key.to_owned(),
        request_id: key.to_owned(),
        idempotency_key_sha256: "k".to_owned(),
        fingerprint_sha256: "f".to_owned(),
        lane_id: None,
        lane_generation: None,
        subject_id_hash: "s".to_owned(),
        grant_sha256: None,
        sql_sha256: None,
        operator_audit_seq: 0,
        started_at: "t".to_owned(),
        completed_at: None,
    }
}

#[test]
fn idempotency_capacity_eviction_spares_in_progress_and_drops_completed() {
    // QA100 .23: capacity eviction must never drop an in-progress entry
    // (response is None) — doing so would discard the marker a retry relies on
    // and let the operator action double-execute. Only completed entries are
    // evictable.
    let mut entries = std::collections::HashMap::new();
    // Oldest entry is in-progress; it must survive.
    entries.insert(
        "in-progress".to_owned(),
        OperatorIdempotencyEntry {
            facts: idempotency_fact("in-progress"),
            response: None,
            created_at: std::time::Instant::now(),
            generation: 1,
        },
    );
    // Fill past the cap with newer, completed entries.
    for i in 0..OPERATOR_IDEMPOTENCY_MAX_ENTRIES {
        let key = format!("done-{i}");
        entries.insert(
            key.clone(),
            OperatorIdempotencyEntry {
                facts: idempotency_fact(&key),
                response: Some(empty_response(200)),
                created_at: std::time::Instant::now(),
                generation: (i + 2) as u64,
            },
        );
    }
    assert!(entries.len() > OPERATOR_IDEMPOTENCY_MAX_ENTRIES);

    evict_completed_operator_idempotency_entries_to_capacity(&mut entries);

    assert!(entries.len() < OPERATOR_IDEMPOTENCY_MAX_ENTRIES);
    assert!(
        entries.contains_key("in-progress"),
        "an in-progress idempotency entry must never be evicted for capacity"
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
fn operator_idempotency_fresh_lease_drop_releases_panic_stranded_marker() {
    let ledger = OperatorIdempotencyLedger::new();
    let facts = idempotency_fact("panic-safe");

    let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _lease = match ledger.begin("/operator/v1/actions/execute", facts.clone()) {
            OperatorIdempotencyBegin::Fresh(lease) => lease,
            _ => panic!("first reservation must be fresh"),
        };
        panic!("synthetic operator unwind before completion");
    }));
    assert!(panic_result.is_err());

    match ledger.begin("/operator/v1/actions/execute", facts) {
        OperatorIdempotencyBegin::Fresh(_lease) => {}
        other => panic!(
            "panic-dropped lease must immediately permit a fresh retry, got {}",
            operator_idempotency_begin_kind(&other)
        ),
    }
}

#[test]
fn operator_idempotency_stale_lease_drop_cannot_remove_newer_generation() {
    let ledger = OperatorIdempotencyLedger::new();
    let facts = idempotency_fact("same-key");
    let stale_lease = match ledger.begin("/operator/v1/actions/execute", facts.clone()) {
        OperatorIdempotencyBegin::Fresh(lease) => lease,
        _ => panic!("first reservation must be fresh"),
    };
    let newer_generation = stale_lease.generation_for_test().saturating_add(1);
    ledger.insert_for_test(
        facts.storage_key.clone(),
        OperatorIdempotencyEntry {
            facts: facts.clone(),
            response: None,
            created_at: std::time::Instant::now(),
            generation: newer_generation,
        },
    );

    drop(stale_lease);

    match ledger.begin("/operator/v1/actions/execute", facts) {
        OperatorIdempotencyBegin::InProgress(response) => {
            assert_eq!(response.status, 409);
            assert_eq!(
                response_json(&response)["data"]["error"],
                serde_json::json!("operator_idempotency_in_progress")
            );
        }
        other => panic!(
            "stale lease drop must leave the newer in-progress generation intact, got {}",
            operator_idempotency_begin_kind(&other)
        ),
    }
}

fn operator_idempotency_begin_kind(begin: &OperatorIdempotencyBegin) -> &'static str {
    match begin {
        OperatorIdempotencyBegin::Fresh(_) => "fresh",
        OperatorIdempotencyBegin::Replay(_) => "replay",
        OperatorIdempotencyBegin::InProgress(_) => "in_progress",
        OperatorIdempotencyBegin::Conflict(_) => "conflict",
    }
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
fn operator_http_200_preserves_mcp_failure_and_partial_apply_contract() {
    let (auditor, sink) = operator_auditor();
    let dir = dashboard_test_dir("operator-semantic-outcome");
    let proposals = Arc::new(
        crate::change_proposal::ChangeProposalStore::open(dir.join("state"))
            .expect("proposal store"),
    );
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        change_proposals: Some(proposals),
        ..Default::default()
    };
    let server = busy_server();

    let forwarded = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/actions/execute",
            &serde_json::json!({
                "idempotency_key": "semantic-outcome-workbench",
                "tool": "oracle_query",
                "arguments": { "sql": "SELECT 1 FROM dual", "max_rows": 1 }
            }),
        ),
    );
    assert_eq!(
        forwarded.status, 200,
        "JSON-RPC/MCP semantic failures intentionally keep a successful HTTP envelope"
    );
    let forwarded_json = response_json(&forwarded);
    assert_eq!(
        forwarded_json["data"]["status"],
        serde_json::json!("forwarded")
    );
    assert_eq!(
        forwarded_json["data"]["mcp_response"]["result"]["isError"],
        serde_json::json!(true)
    );
    assert_eq!(
        forwarded_json["data"]["mcp_response"]["result"]["structuredContent"]["error_class"],
        serde_json::json!("BUSY")
    );

    let draft = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/change-proposals/draft",
            &serde_json::json!({
                "profile": "prod",
                "author": "human",
                "title": "Semantic outcome fixture",
                "statements": [{
                    "sql_template": "SELECT 1 FROM dual",
                    "unit": "read"
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
                "idempotency_key": "semantic-outcome-proposal"
            }),
        ),
    );
    assert_eq!(
        apply.status, 200,
        "the proposal route reports a terminal domain outcome inside operator.v1"
    );
    let apply_json = response_json(&apply);
    assert_eq!(
        apply_json["data"]["status"],
        serde_json::json!("stopped_on_failure")
    );
    assert_eq!(
        apply_json["data"]["results"][0]["action_response"]["data"]["mcp_response"]["result"]["isError"],
        serde_json::json!(true),
        "the client decoder must inspect the nested failed statement, not HTTP 200"
    );

    let records = sink.records();
    assert_eq!(records.len(), 6);
    assert_operator_audit_pair(&records[0..2], AuditDecision::Allowed, AuditOutcome::Failed);
    assert_operator_audit_pair(
        &records[2..4],
        AuditDecision::Allowed,
        AuditOutcome::Succeeded,
    );
    assert_operator_audit_pair(&records[4..6], AuditDecision::Allowed, AuditOutcome::Failed);
}

#[test]
fn operator_http_200_mcp_policy_refusal_is_a_blocked_terminal() {
    let (auditor, sink) = operator_auditor();
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        ..Default::default()
    };
    let server = server_with_dispatch(Arc::new(PolicyDeniedDispatch));
    let response = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/actions/execute",
            &serde_json::json!({
                "idempotency_key": "semantic-policy-refusal",
                "tool": "oracle_query",
                "arguments": { "sql": "SELECT 1 FROM dual" }
            }),
        ),
    );

    assert_eq!(response.status, 200);
    assert_eq!(
        response_json(&response)["data"]["mcp_response"]["result"]["structuredContent"]["error_class"],
        serde_json::json!("POLICY_DENIED")
    );
    assert_operator_audit_pair(
        &sink.records(),
        AuditDecision::Blocked,
        AuditOutcome::Failed,
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
fn dashboard_operator_auth_enforces_origin_even_for_authenticated_principals() {
    // QA100 .87: an authenticated principal (e.g. an ambient mTLS client cert the
    // browser attaches automatically) must NOT bypass the browser origin /
    // Sec-Fetch CSRF check — otherwise a hostile page could drive the dashboard
    // with the victim's ambient credential.
    let dir = dashboard_test_dir("origin-csrf-87");
    let auth = Arc::new(
        DashboardAuth::new(dir.clone(), "http://127.0.0.1").expect("dashboard auth builds"),
    );
    let cfg = HttpTransportConfig {
        dashboard_auth: Some(Arc::clone(&auth)),
        ..Default::default()
    };
    let request = |origin: Option<&'static str>, sec_fetch: Option<&'static str>| {
        let mut headers = vec![
            ("host".to_owned(), "127.0.0.1".to_owned()),
            ("content-type".to_owned(), "application/json".to_owned()),
        ];
        if let Some(origin) = origin {
            headers.push(("origin".to_owned(), origin.to_owned()));
        }
        if let Some(sec_fetch) = sec_fetch {
            headers.push(("sec-fetch-site".to_owned(), sec_fetch.to_owned()));
        }
        HttpRequest::new("POST", "/dashboard/api/action", headers, Vec::new())
    };

    // Authenticated + cross-origin => refused (the fix).
    let refused = enforce_dashboard_operator_auth(
        &cfg,
        &request(Some("http://evil.example"), Some("cross-site")),
        true,
    )
    .expect("a cross-origin authenticated request must be refused");
    assert_eq!(refused.status, 403);

    // Authenticated + same-origin => allowed.
    assert!(
        enforce_dashboard_operator_auth(
            &cfg,
            &request(Some("http://127.0.0.1"), Some("same-origin")),
            true,
        )
        .is_none(),
        "a same-origin authenticated request passes"
    );

    // Authenticated non-browser (no Origin / Sec-Fetch headers) => allowed, so
    // bearer/mTLS API clients are unaffected.
    assert!(
        enforce_dashboard_operator_auth(&cfg, &request(None, None), true).is_none(),
        "a non-browser authenticated request (no browser headers) passes"
    );
}

#[test]
fn dashboard_workbench_ddl_apply_is_release_gated() {
    let (auditor, sink) = operator_auditor();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server_with_dispatch(Arc::new(WorkbenchDispatch {
        calls: Arc::clone(&calls),
    }));
    let dir = dashboard_test_dir("ddl-gate");
    let auth = Arc::new(
        DashboardAuth::new(dir.clone(), "http://127.0.0.1").expect("dashboard auth builds"),
    );
    let cfg = HttpTransportConfig {
        dashboard_auth: Some(Arc::clone(&auth)),
        operator_auditor: Some(auditor),
        ..Default::default()
    };
    let cases = [
        (
            "oracle_execute",
            serde_json::json!({
                "sql": "CREATE TABLE dashboard_apply_blocked (id NUMBER)",
                "commit": true,
                "confirm": "opaque-preview-grant"
            }),
        ),
        (
            "oracle_compile_object",
            serde_json::json!({
                "owner": "APP",
                "object_type": "PACKAGE",
                "name": "P",
                "execute": true,
                "confirm": "opaque-preview-grant"
            }),
        ),
        (
            "oracle_create_or_replace",
            serde_json::json!({
                "source_code": "CREATE OR REPLACE VIEW v AS SELECT 1 x FROM dual",
                "execute": true,
                "confirm": "opaque-preview-grant"
            }),
        ),
        (
            "oracle_patch_source",
            serde_json::json!({
                "owner": "APP",
                "object_type": "PACKAGE BODY",
                "name": "P",
                "patch": "@@ -1 +1 @@",
                "execute": true,
                "confirm": "opaque-preview-grant"
            }),
        ),
    ];
    let routes = [
        "/operator/v1/actions/confirm",
        "/operator/v1/actions/execute",
    ];
    for (case_index, (tool, arguments)) in cases.iter().enumerate() {
        for (route_index, path) in routes.iter().enumerate() {
            let ticket =
                crate::dashboard_auth::mint_dashboard_pairing_ticket_for_test(auth.as_ref())
                    .expect("ticket mints");
            let login = auth
                .exchange_ticket(&ticket.code, auth.audience(), false)
                .expect("login works");
            let cookie_pair = login.session_cookie.split(';').next().expect("cookie pair");
            let view = auth
                .session_view(Some(cookie_pair))
                .expect("session view works");
            let action_ticket = view
                .action_tickets
                .iter()
                .find(|ticket| ticket.path == *path)
                .expect("route action ticket")
                .ticket
                .clone();
            let response = handle_http_request(
                &server,
                &cfg,
                HttpRequest::new(
                    "POST",
                    *path,
                    [
                        ("host", "127.0.0.1"),
                        ("origin", "http://127.0.0.1"),
                        ("sec-fetch-site", "same-origin"),
                        ("content-type", "application/json"),
                        ("accept", "application/json"),
                        ("cookie", cookie_pair),
                        (DASHBOARD_CSRF_HEADER, view.csrf_token.as_str()),
                        (DASHBOARD_ACTION_TICKET_HEADER, action_ticket.as_str()),
                    ],
                    serde_json::json!({
                        "idempotency_key": format!("ddl-gate-{case_index}-{route_index}"),
                        "tool": tool,
                        "arguments": arguments,
                    })
                    .to_string()
                    .into_bytes(),
                )
                .with_peer_loopback(true),
            );
            assert_eq!(response.status, 403, "{path} must release-gate {tool}");
            assert_eq!(
                response_json(&response)["data"]["error"],
                serde_json::json!("dashboard_ddl_workbench_disabled"),
                "{path} must release-gate {tool}"
            );
        }
    }
    assert_eq!(
        calls.load(AtomicOrdering::SeqCst),
        0,
        "every browser DDL apply target must fail before MCP dispatch"
    );
    let records = sink.records();
    assert_eq!(records.len(), cases.len() * routes.len() * 2);
    for pair in records.chunks_exact(2) {
        assert_operator_audit_pair(pair, AuditDecision::Blocked, AuditOutcome::Failed);
    }
}

#[test]
fn dashboard_structured_ddl_preview_remains_available() {
    let (auditor, sink) = operator_auditor();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server_with_dispatch(Arc::new(WorkbenchDispatch {
        calls: Arc::clone(&calls),
    }));
    let dir = dashboard_test_dir("ddl-preview");
    let auth = Arc::new(
        DashboardAuth::new(dir.clone(), "http://127.0.0.1").expect("dashboard auth builds"),
    );
    let cfg = HttpTransportConfig {
        dashboard_auth: Some(Arc::clone(&auth)),
        operator_auditor: Some(auditor),
        ..Default::default()
    };
    let ticket = crate::dashboard_auth::mint_dashboard_pairing_ticket_for_test(auth.as_ref())
        .expect("ticket mints");
    let login = auth
        .exchange_ticket(&ticket.code, auth.audience(), false)
        .expect("login works");
    let cookie_pair = login.session_cookie.split(';').next().expect("cookie pair");
    let view = auth
        .session_view(Some(cookie_pair))
        .expect("session view works");
    let preview_ticket = view
        .action_tickets
        .iter()
        .find(|ticket| ticket.path == "/operator/v1/actions/preview")
        .expect("preview action ticket");
    let response = handle_http_request(
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
                (
                    DASHBOARD_ACTION_TICKET_HEADER,
                    preview_ticket.ticket.as_str(),
                ),
            ],
            serde_json::json!({
                "idempotency_key": "ddl-preview-compile",
                "tool": "oracle_compile_object",
                "arguments": {
                    "owner": "APP",
                    "object_type": "PACKAGE",
                    "name": "P",
                    "execute": true
                }
            })
            .to_string()
            .into_bytes(),
        )
        .with_peer_loopback(true),
    );
    assert_eq!(response.status, 200);
    assert_eq!(calls.load(AtomicOrdering::SeqCst), 1);
    assert_eq!(
        response_json(&response)["data"]["mcp_response"]["result"]["structuredContent"]["args"]["execute"],
        serde_json::json!(false),
        "preview route must force the structured tool into non-executing mode"
    );
    assert_operator_audit_pair(
        &sink.records(),
        AuditDecision::Allowed,
        AuditOutcome::Succeeded,
    );
}

#[test]
fn non_browser_operator_keeps_structured_ddl_dispatch_path() {
    let (auditor, sink) = operator_auditor();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server_with_dispatch(Arc::new(WorkbenchDispatch {
        calls: Arc::clone(&calls),
    }));
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        ..Default::default()
    };
    let response = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/actions/execute",
            &serde_json::json!({
                "idempotency_key": "non-browser-create-or-replace",
                "tool": "oracle_create_or_replace",
                "arguments": {
                    "source_code": "CREATE OR REPLACE VIEW v AS SELECT 1 x FROM dual",
                    "execute": true,
                    "confirm": "opaque-preview-grant"
                }
            }),
        ),
    );

    assert_eq!(response.status, 200);
    assert_eq!(calls.load(AtomicOrdering::SeqCst), 1);
    assert_operator_audit_pair(
        &sink.records(),
        AuditDecision::Allowed,
        AuditOutcome::Succeeded,
    );
}

#[test]
fn streaming_dispatch_requires_a_valid_jsonrpc_request() {
    // QA100 .61: the streaming path is selected only from a well-formed JSON-RPC
    // 2.0 tools/call request. An invalid envelope must fall through to the main
    // dispatcher (which returns a proper JSON-RPC error) rather than being
    // streamed unvalidated.
    assert!(
        streaming_oracle_query_call(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "oracle_query", "arguments": { "sql": "SELECT 1 FROM dual", "streaming": true } },
        }))
        .is_some(),
        "a well-formed JSON-RPC 2.0 streaming request selects streaming"
    );

    let rejected = [
        // missing jsonrpc
        serde_json::json!({ "id": 1, "method": "tools/call", "params": { "name": "oracle_query", "arguments": { "streaming": true } } }),
        // wrong jsonrpc version
        serde_json::json!({ "jsonrpc": "1.0", "id": 1, "method": "tools/call", "params": { "name": "oracle_query", "arguments": { "streaming": true } } }),
        // structured id (not a valid request id)
        serde_json::json!({ "jsonrpc": "2.0", "id": { "x": 1 }, "method": "tools/call", "params": { "name": "oracle_query", "arguments": { "streaming": true } } }),
        // null id
        serde_json::json!({ "jsonrpc": "2.0", "id": null, "method": "tools/call", "params": { "name": "oracle_query", "arguments": { "streaming": true } } }),
        // notification (no id)
        serde_json::json!({ "jsonrpc": "2.0", "method": "tools/call", "params": { "name": "oracle_query", "arguments": { "streaming": true } } }),
        // streaming not requested (existing behavior preserved)
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": "oracle_query", "arguments": { "streaming": false } } }),
    ];
    for req in &rejected {
        assert!(
            streaming_oracle_query_call(req).is_none(),
            "invalid/non-streaming request must not select streaming: {req}"
        );
    }
}

#[test]
fn restored_dashboard_read_only_actions_are_allowed_on_execute() {
    // QA100 .22: the dashboard's capabilities view and global source search were
    // dropped from the operator allowlist, so those read-only actions failed
    // closed. Both are now explicitly allowed on the execute route (and only
    // there), while default-deny still holds for tools never exposed.
    for tool in ["oracle_capabilities", "oracle_search_source"] {
        let policy = operator_action_tool_policy(tool)
            .unwrap_or_else(|| panic!("{tool} must be an allowed operator action"));
        assert_eq!(policy.browser_apply, BrowserApplyPolicy::Allow, "{tool}");
        assert!(
            policy.allows(OperatorRouteKind::ActionExecute),
            "{tool} must be allowed on the execute route"
        );
        assert!(
            !policy.allows(OperatorRouteKind::ActionConfirm),
            "{tool} is read-only and must not be a mutating confirm action"
        );
    }
    assert!(
        operator_action_tool_policy("oracle_totally_unlisted_tool").is_none(),
        "default-deny still holds for tools not deliberately exposed"
    );
}

#[test]
fn every_browser_action_tool_has_an_explicit_release_policy() {
    let mut names = std::collections::BTreeSet::new();
    for policy in OPERATOR_ACTION_TOOL_POLICIES {
        assert!(
            names.insert(policy.tool),
            "duplicate policy for {}",
            policy.tool
        );
        assert_ne!(policy.routes, 0, "{} has no allowed route", policy.tool);
    }
    for tool in [
        "oracle_compile_object",
        "oracle_create_or_replace",
        "oracle_patch_source",
    ] {
        assert_eq!(
            operator_action_tool_policy(tool).map(|policy| policy.browser_apply),
            Some(BrowserApplyPolicy::DdlMutation),
            "structured mutation tool must be explicitly release-gated: {tool}"
        );
    }
    assert_eq!(
        operator_action_tool_policy("oracle_execute").map(|policy| policy.browser_apply),
        Some(BrowserApplyPolicy::ClassifySql)
    );
    let admin = dashboard_workbench_release_gate(
        OperatorRouteKind::ActionConfirm,
        "oracle_execute",
        &serde_json::json!({"sql": "GRANT SELECT ON app.orders TO reporting"}),
    )
    .expect("browser Admin SQL must be release-gated");
    assert_eq!(
        admin["required_level"],
        serde_json::json!(oraclemcp_guard::OperatingLevel::Admin)
    );
    assert!(
        dashboard_workbench_release_gate(
            OperatorRouteKind::ActionExecute,
            "oracle_execute",
            &serde_json::json!({"sql": "UPDATE t SET x = 1 WHERE id = 2"}),
        )
        .is_none(),
        "ordinary DML behavior must not be changed by the DDL release gate"
    );
    assert!(
        dashboard_workbench_release_gate(
            OperatorRouteKind::ActionExecute,
            "oracle_query",
            &serde_json::json!({"sql": "SELECT 1 FROM dual"}),
        )
        .is_none(),
        "read tools remain browser-allowed"
    );
    let unresolved = dashboard_workbench_release_gate(
        OperatorRouteKind::ActionExecute,
        "oracle_execute",
        &serde_json::json!({}),
    )
    .expect("unclassifiable browser SQL must fail closed");
    assert_eq!(
        unresolved["error"],
        serde_json::json!("dashboard_action_policy_unresolved")
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
    let store = Arc::new(
        crate::change_proposal::ChangeProposalStore::open(dir.join("state"))
            .expect("proposal store"),
    );
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
fn edition_proposals_are_persisted_review_requests_not_replayable_authority() {
    let (auditor, sink) = operator_auditor();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server_with_dispatch(Arc::new(WorkbenchDispatch {
        calls: Arc::clone(&calls),
    }));
    let dir = dashboard_test_dir("edition-proposals");
    let store = Arc::new(
        crate::change_proposal::ChangeProposalStore::open(dir.join("state"))
            .expect("proposal store"),
    );
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        change_proposals: Some(Arc::clone(&store)),
        ..Default::default()
    };

    let draft = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/edition-proposals/draft",
            &serde_json::json!({
                "profile": "stage",
                "child_edition": "synthetic_child",
                "base_edition": "ora$base",
                "objects": ["SYNTHETIC_PACKAGE", "SYNTHETIC_VIEW"]
            }),
        ),
    );
    assert_eq!(draft.status, 200);
    let draft_json = response_json(&draft);
    assert_eq!(draft_json["data"]["authority"], serde_json::json!("request_only"));
    assert_eq!(
        draft_json["data"]["proposal"]["status"],
        serde_json::json!("requested")
    );
    let proposal_id = draft_json["data"]["proposal"]["proposal_id"]
        .as_str()
        .expect("proposal id")
        .to_owned();

    let list = handle_http_request(
        &server,
        &cfg,
        operator_json_get("/operator/v1/edition-proposals"),
    );
    assert_eq!(list.status, 200);
    assert_eq!(
        response_json(&list)["data"]["proposals"][0]["proposal_id"],
        serde_json::json!(proposal_id)
    );

    let transition = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/edition-proposals/transition",
            &serde_json::json!({
                "proposal_id": proposal_id,
                "status": "reviewing"
            }),
        ),
    );
    assert_eq!(transition.status, 200);
    assert_eq!(
        response_json(&transition)["data"]["proposal"]["status"],
        serde_json::json!("reviewing")
    );

    // A stored request has no apply route and cannot smuggle SQL, a stored
    // verdict, or confirmation into the normal guard/dispatch path. This is
    // the negative SEC-1 proof: review state is never replay authority.
    let attempted_apply = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/edition-proposals/apply",
            &serde_json::json!({
                "proposal_id": proposal_id,
                "sql": "DROP TABLE synthetic_edition_target",
                "stored_verdict": { "danger": "SAFE" },
                "confirm": "forged"
            }),
        ),
    );
    assert_eq!(attempted_apply.status, 404);
    assert_eq!(
        calls.load(AtomicOrdering::SeqCst),
        0,
        "edition request records must never reach dispatch; later guarded apply re-classifies independently"
    );

    let records = sink.records();
    assert_eq!(records.len(), 8, "every board read/write attempt is audited");
    assert_operator_audit_pair(&records[0..2], AuditDecision::Allowed, AuditOutcome::Succeeded);
    assert_operator_audit_pair(&records[2..4], AuditDecision::Allowed, AuditOutcome::Succeeded);
    assert_operator_audit_pair(&records[4..6], AuditDecision::Allowed, AuditOutcome::Succeeded);
    assert_operator_audit_pair(&records[6..8], AuditDecision::Blocked, AuditOutcome::Failed);
}

#[test]
fn edition_default_flip_requires_admin_confirmation_reclassification_and_audit() {
    let (auditor, sink) = operator_auditor();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server_with_dispatch(Arc::new(WorkbenchDispatch {
        calls: Arc::clone(&calls),
    }));
    let dir = dashboard_test_dir("edition-default-flip");
    let store = Arc::new(
        crate::change_proposal::ChangeProposalStore::open(dir.join("state"))
            .expect("proposal store"),
    );
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        change_proposals: Some(store),
        ..Default::default()
    };

    let draft = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/edition-proposals/draft",
            &serde_json::json!({
                "profile": "synthetic_stage",
                "child_edition": "synthetic_child",
                "base_edition": "synthetic_base",
                "objects": ["SYNTHETIC_EDITIONABLE_VIEW"]
            }),
        ),
    );
    assert_eq!(draft.status, 200);
    let proposal_id = response_json(&draft)["data"]["proposal"]["proposal_id"]
        .as_str()
        .expect("proposal id")
        .to_owned();
    let reviewing = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/edition-proposals/transition",
            &serde_json::json!({ "proposal_id": proposal_id, "status": "reviewing" }),
        ),
    );
    assert_eq!(reviewing.status, 200);

    // A merge is never a convenience bare tool call.  The token is transient
    // input; the durable record contains no token and cannot execute by itself.
    let without_confirmation = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/edition-proposals/merge",
            &serde_json::json!({ "proposal_id": proposal_id }),
        ),
    );
    assert_eq!(without_confirmation.status, 409);
    assert_eq!(
        response_json(&without_confirmation)["data"]["error"],
        serde_json::json!("edition_default_confirmation_required")
    );
    assert_eq!(
        calls.load(AtomicOrdering::SeqCst),
        0,
        "missing confirmation must fail before guarded dispatch"
    );

    let merge = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/edition-proposals/merge",
            &serde_json::json!({
                "proposal_id": proposal_id,
                "confirm": "synthetic-admin-preview-grant",
                "idempotency_key": "synthetic-edition-merge"
            }),
        ),
    );
    assert_eq!(merge.status, 200);
    let merge_json = response_json(&merge);
    assert_eq!(merge_json["data"]["action"], serde_json::json!("merge"));
    assert_eq!(
        merge_json["data"]["reclassified"]["required_level"],
        serde_json::json!("ADMIN"),
        "apply must freshly classify the generated default-edition SQL at ADMIN"
    );
    assert_eq!(
        merge_json["data"]["reclassified"]["stored_proposal_is_authority"],
        serde_json::json!(false)
    );
    let merged_action = &merge_json["data"]["mcp_response"]["result"]["structuredContent"];
    assert_eq!(merged_action["tool"], serde_json::json!("oracle_execute"));
    assert_eq!(
        merged_action["classification"]["required_level"],
        serde_json::json!("ADMIN"),
        "the guarded execution seam must receive the same fresh ADMIN classification"
    );
    assert_eq!(
        merged_action["args"]["sql"],
        serde_json::json!("ALTER DATABASE DEFAULT EDITION = SYNTHETIC_CHILD")
    );
    assert_eq!(merged_action["args"]["commit"], serde_json::json!(true));
    assert_eq!(
        merged_action["args"]["confirm"],
        serde_json::json!("synthetic-admin-preview-grant")
    );

    let rollback = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/edition-proposals/rollback",
            &serde_json::json!({
                "proposal_id": proposal_id,
                "confirm": "synthetic-rollback-preview-grant",
                "idempotency_key": "synthetic-edition-rollback"
            }),
        ),
    );
    assert_eq!(rollback.status, 200);
    let rollback_json = response_json(&rollback);
    assert_eq!(rollback_json["data"]["action"], serde_json::json!("rollback"));
    assert_eq!(
        rollback_json["data"]["target_edition"],
        serde_json::json!("SYNTHETIC_BASE")
    );
    assert_eq!(
        rollback_json["data"]["rollback_scope"]["changes_default_edition_for"],
        serde_json::json!("new_sessions_only")
    );
    assert_eq!(
        rollback_json["data"]["rollback_scope"]["cannot_restore"],
        serde_json::json!([
            "autonomous transaction effects",
            "sequence increments",
            "trigger side effects"
        ]),
        "rollback must not claim to undo effects that Oracle does not roll back"
    );

    assert_eq!(calls.load(AtomicOrdering::SeqCst), 2);
    let records = sink.records();
    assert_eq!(records.len(), 10, "every default-edition attempt is hash-chain audited");
    assert_operator_audit_pair(&records[0..2], AuditDecision::Allowed, AuditOutcome::Succeeded);
    assert_operator_audit_pair(&records[2..4], AuditDecision::Allowed, AuditOutcome::Succeeded);
    assert_operator_audit_pair(&records[4..6], AuditDecision::Blocked, AuditOutcome::Failed);
    assert_operator_audit_pair(&records[6..8], AuditDecision::Allowed, AuditOutcome::Succeeded);
    assert_operator_audit_pair(&records[8..10], AuditDecision::Allowed, AuditOutcome::Succeeded);
}

#[test]
fn edition_default_flip_refuses_forked_or_replayed_review_state() {
    let (auditor, sink) = operator_auditor();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server_with_dispatch(Arc::new(WorkbenchDispatch {
        calls: Arc::clone(&calls),
    }));
    let dir = dashboard_test_dir("edition-default-fork");
    let store = Arc::new(
        crate::change_proposal::ChangeProposalStore::open(dir.join("state"))
            .expect("proposal store"),
    );
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        change_proposals: Some(store),
        ..Default::default()
    };
    let draft = |child: &str| {
        handle_http_request(
            &server,
            &cfg,
            operator_json_post(
                "/operator/v1/edition-proposals/draft",
                &serde_json::json!({
                    "profile": "synthetic_stage",
                    "child_edition": child,
                    "base_edition": "synthetic_base",
                    "objects": ["SYNTHETIC_EDITIONABLE_VIEW"]
                }),
            ),
        )
    };
    let first = draft("synthetic_child_a");
    let first_id = response_json(&first)["data"]["proposal"]["proposal_id"]
        .as_str()
        .expect("first proposal id")
        .to_owned();
    assert_eq!(
        handle_http_request(
            &server,
            &cfg,
            operator_json_post(
                "/operator/v1/edition-proposals/transition",
                &serde_json::json!({ "proposal_id": first_id, "status": "reviewing" }),
            ),
        )
        .status,
        200
    );
    let second = draft("synthetic_child_b");
    assert_eq!(second.status, 200);

    // The second non-withdrawn child is ambiguous board state.  Refuse before
    // the confirmation is consumed or a database can report ORA-38807 late.
    let forked = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/edition-proposals/merge",
            &serde_json::json!({
                "proposal_id": first_id,
                "confirm": "synthetic-admin-preview-grant"
            }),
        ),
    );
    assert_eq!(forked.status, 409);
    assert_eq!(
        response_json(&forked)["data"]["error"],
        serde_json::json!("edition_linear_chain_required")
    );

    let forked_rollback = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/edition-proposals/rollback",
            &serde_json::json!({
                "proposal_id": first_id,
                "confirm": "synthetic-rollback-preview-grant"
            }),
        ),
    );
    assert_eq!(forked_rollback.status, 409);
    assert_eq!(
        response_json(&forked_rollback)["data"]["error"],
        serde_json::json!("edition_linear_chain_required"),
        "rollback uses the same no-fork preflight before it can redirect new sessions"
    );
    assert_eq!(calls.load(AtomicOrdering::SeqCst), 0);

    // A caller cannot replay a manufactured verdict or substitute SQL through
    // an otherwise valid request.  Unknown fields are rejected before dispatch,
    // so only the canonical, freshly classified ALTER DATABASE statement exists.
    let replay = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/edition-proposals/merge",
            &serde_json::json!({
                "proposal_id": first_id,
                "confirm": "synthetic-admin-preview-grant",
                "sql": "SELECT 1 FROM dual",
                "stored_verdict": { "required_level": "READ_ONLY" }
            }),
        ),
    );
    assert_eq!(replay.status, 400);
    assert_eq!(calls.load(AtomicOrdering::SeqCst), 0);

    let records = sink.records();
    assert_eq!(records.len(), 12);
    assert_operator_audit_pair(&records[0..2], AuditDecision::Allowed, AuditOutcome::Succeeded);
    assert_operator_audit_pair(&records[2..4], AuditDecision::Allowed, AuditOutcome::Succeeded);
    assert_operator_audit_pair(&records[4..6], AuditDecision::Allowed, AuditOutcome::Succeeded);
    assert_operator_audit_pair(&records[6..8], AuditDecision::Blocked, AuditOutcome::Failed);
    assert_operator_audit_pair(&records[8..10], AuditDecision::Blocked, AuditOutcome::Failed);
    assert_operator_audit_pair(&records[10..12], AuditDecision::Blocked, AuditOutcome::Failed);
}

#[test]
fn edition_default_flip_surfaces_a_live_policy_refusal_as_an_audited_block() {
    let (auditor, sink) = operator_auditor();
    let server = server_with_dispatch(Arc::new(PolicyDeniedDispatch));
    let dir = dashboard_test_dir("edition-default-reclassified-refusal");
    let store = Arc::new(
        crate::change_proposal::ChangeProposalStore::open(dir.join("state"))
            .expect("proposal store"),
    );
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        change_proposals: Some(store),
        ..Default::default()
    };
    let draft = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/edition-proposals/draft",
            &serde_json::json!({
                "profile": "synthetic_stage",
                "child_edition": "synthetic_child",
                "base_edition": "synthetic_base",
                "objects": ["SYNTHETIC_EDITIONABLE_VIEW"]
            }),
        ),
    );
    let proposal_id = response_json(&draft)["data"]["proposal"]["proposal_id"]
        .as_str()
        .expect("proposal id")
        .to_owned();
    assert_eq!(
        handle_http_request(
            &server,
            &cfg,
            operator_json_post(
                "/operator/v1/edition-proposals/transition",
                &serde_json::json!({ "proposal_id": proposal_id, "status": "reviewing" }),
            ),
        )
        .status,
        200
    );

    let refused = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/edition-proposals/merge",
            &serde_json::json!({
                "proposal_id": proposal_id,
                "confirm": "synthetic-admin-preview-grant"
            }),
        ),
    );
    assert_eq!(refused.status, 200);
    let refused_json = response_json(&refused);
    assert_eq!(refused_json["data"]["status"], serde_json::json!("refused"));
    assert_eq!(
        refused_json["data"]["mcp_response"]["result"]["structuredContent"]["error_class"],
        serde_json::json!("POLICY_DENIED"),
        "a current dispatcher denial wins over any prior review-board state"
    );
    let records = sink.records();
    assert_eq!(records.len(), 6);
    assert_operator_audit_pair(&records[0..2], AuditDecision::Allowed, AuditOutcome::Succeeded);
    assert_operator_audit_pair(&records[2..4], AuditDecision::Allowed, AuditOutcome::Succeeded);
    assert_operator_audit_pair(&records[4..6], AuditDecision::Blocked, AuditOutcome::Failed);
}

fn change_proposals_test_config() -> (OracleMcpServer, HttpTransportConfig, String) {
    let (auditor, _sink) = operator_auditor();
    let dir = dashboard_test_dir("change-proposals-list");
    let store = Arc::new(
        crate::change_proposal::ChangeProposalStore::open(dir.join("state"))
            .expect("proposal store"),
    );
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        change_proposals: Some(store),
        ..Default::default()
    };
    let server = test_server();
    let write_sql = "UPDATE accounts SET status = :1 WHERE id = :2";
    let draft = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/change-proposals/draft",
            &serde_json::json!({
                "profile": "prod",
                "author": "agent",
                "title": "Hold account",
                "statements": [{
                    "sql_template": write_sql,
                    "binds": ["HOLD", 42]
                }]
            }),
        ),
    );
    assert_eq!(draft.status, 200);
    let proposal_id = response_json(&draft)["data"]["proposal"]["id"]
        .as_str()
        .expect("proposal id")
        .to_owned();
    (server, cfg, proposal_id)
}

#[test]
fn change_proposals_list_returns_stripped_projection_with_etag_and_next_cursor() {
    let (server, cfg, _proposal_id) = change_proposals_test_config();

    let list = handle_http_request(
        &server,
        &cfg,
        operator_json_get("/operator/v1/change-proposals"),
    );
    assert_eq!(list.status, 200);
    let etag = list.header("etag").expect("list carries an ETag validator");
    assert!(!etag.is_empty(), "ETag must be a non-empty validator");

    let body = String::from_utf8(list.body.clone()).expect("list body utf8");
    assert!(
        !body.contains("UPDATE accounts"),
        "list projection must not serialize sql_template bodies"
    );

    let list_json = response_json(&list);
    let statement = &list_json["data"]["proposals"][0]["statements"][0];
    assert!(
        statement["sql_sha256"]
            .as_str()
            .expect("sql digest present")
            .starts_with("sha256:"),
        "list statement keeps the SQL digest"
    );
    assert_eq!(
        statement.get("sql_template"),
        None,
        "list statement omits the sql_template body"
    );
    assert_eq!(statement["unit"], serde_json::json!("dml"));
    assert_eq!(
        list_json["data"]["nextCursor"],
        Value::Null,
        "a single-page board reports no next cursor"
    );
    assert_eq!(
        list_json["data"]["source"],
        serde_json::json!("change_proposals")
    );
}

#[test]
fn change_proposals_list_answers_304_on_matching_if_none_match() {
    let (server, cfg, _proposal_id) = change_proposals_test_config();

    let first = handle_http_request(
        &server,
        &cfg,
        operator_json_get("/operator/v1/change-proposals"),
    );
    assert_eq!(first.status, 200);
    let etag = first
        .header("etag")
        .expect("first list carries an ETag")
        .to_owned();

    let revalidated = handle_http_request(
        &server,
        &cfg,
        operator_get_owned("/operator/v1/change-proposals".to_owned(), Some(&etag)),
    );
    assert_eq!(
        revalidated.status, 304,
        "an unchanged board revalidates to 304 Not Modified"
    );
    assert!(
        revalidated.body.is_empty(),
        "a 304 response carries no body"
    );
    assert_eq!(
        revalidated.header("etag"),
        Some(etag.as_str()),
        "the 304 response echoes the ETag validator"
    );
}

#[test]
fn change_proposal_detail_route_returns_full_sql_template() {
    let (server, cfg, proposal_id) = change_proposals_test_config();

    let detail = handle_http_request(
        &server,
        &cfg,
        operator_get_owned(format!("/operator/v1/change-proposals/{proposal_id}"), None),
    );
    assert_eq!(detail.status, 200);
    let detail_json = response_json(&detail);
    assert_eq!(
        detail_json["data"]["source"],
        serde_json::json!("change_proposals")
    );
    assert_eq!(
        detail_json["data"]["proposal"]["statements"][0]["sql_template"],
        serde_json::json!("UPDATE accounts SET status = :1 WHERE id = :2"),
        "the detail view restores the sql_template the list projection omits"
    );

    let missing = handle_http_request(
        &server,
        &cfg,
        operator_get_owned(
            "/operator/v1/change-proposals/cp-does-not-exist".to_owned(),
            None,
        ),
    );
    assert_eq!(missing.status, 404);
    assert_eq!(
        response_json(&missing)["data"]["error"],
        serde_json::json!("unknown_change_proposal")
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
                            "owner": null,
                            "name": {"text": "T_OLD", "quoted": false},
                            "ddl": "create table t_old (id number)"
                        },
                        {
                            "object_type": "TABLE",
                            "owner": null,
                            "name": {"text": "T_CHANGED", "quoted": false},
                            "ddl": "create table t_changed (id number)"
                        }
                    ]
                },
                "after": {
                    "objects": [
                        {
                            "object_type": "TABLE",
                            "owner": null,
                            "name": {"text": "T_CHANGED", "quoted": false},
                            "ddl": "create table t_changed (id number, name varchar2(30))"
                        },
                        {
                            "object_type": "VIEW",
                            "owner": null,
                            "name": {"text": "V_NEW", "quoted": false},
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
        body["data"]["diff"]["changed"][0]["name"],
        serde_json::json!({"text": "T_CHANGED", "quoted": false})
    );
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
    let service_store = crate::file_store::FileStore::open(&state).expect("service store");
    let owner = service_store
        .acquire_service_owner("http-test")
        .expect("service owner");
    let change_proposals = Arc::new(
        crate::change_proposal::ChangeProposalStore::open_with_owner(owner.clone())
            .expect("proposal store"),
    );
    let source_history = Arc::new(
        crate::source_history::SourceHistoryStore::open_with_owner(owner)
            .expect("source-history store"),
    );
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
    assert_eq!(
        history_json["data"]["nextCursor"],
        Value::Null,
        "a single-page history reports no next cursor"
    );
    let history_etag = history
        .header("etag")
        .expect("source-history list carries an ETag")
        .to_owned();
    assert!(!history_etag.is_empty());

    let history_revalidated = handle_http_request(
        &server,
        &cfg,
        operator_get_owned(
            "/operator/v1/source-history".to_owned(),
            Some(&history_etag),
        ),
    );
    assert_eq!(
        history_revalidated.status, 304,
        "an unchanged source-history board revalidates to 304"
    );
    assert!(history_revalidated.body.is_empty());
    assert_eq!(
        history_revalidated.header("etag"),
        Some(history_etag.as_str())
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

type QuotedSourceApplyFixture = (
    OracleMcpServer,
    HttpTransportConfig,
    Arc<Mutex<Vec<(String, Value)>>>,
    Value,
);

fn apply_quoted_source_change(return_wrong_unquoted_object: bool) -> QuotedSourceApplyFixture {
    let (auditor, _sink) = operator_auditor();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let server = server_with_dispatch(Arc::new(QuotedSourceHistoryDispatch {
        calls: Arc::clone(&calls),
        return_wrong_unquoted_object,
    }));
    let dir = dashboard_test_dir(if return_wrong_unquoted_object {
        "source-history-quoted-mismatch"
    } else {
        "source-history-quoted-exact"
    });
    let state = dir.join("state");
    let service_store = crate::file_store::FileStore::open(&state).expect("service store");
    let owner = service_store
        .acquire_service_owner("http-test")
        .expect("service owner");
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        change_proposals: Some(Arc::new(
            crate::change_proposal::ChangeProposalStore::open_with_owner(owner.clone())
                .expect("proposal store"),
        )),
        source_history: Some(Arc::new(
            crate::source_history::SourceHistoryStore::open_with_owner(owner)
                .expect("source-history store"),
        )),
        ..Default::default()
    };
    let ddl = "CREATE /* identity */ OR\n-- quote guard\nREPLACE EDITIONABLE PROCEDURE \"App\".\"foo\" IS BEGIN NULL; END;";
    let draft = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/change-proposals/draft",
            &serde_json::json!({
                "profile": "prod",
                "author": "agent",
                "title": "Patch quoted procedure",
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
                "idempotency_key": "source-history-quoted-apply"
            }),
        ),
    );
    assert_eq!(apply.status, 200);
    let apply_json = response_json(&apply);
    (server, cfg, calls, apply_json)
}

#[test]
fn quoted_source_snapshot_fetch_capture_and_revert_keep_exact_identity() {
    let (server, cfg, calls, apply_json) = apply_quoted_source_change(false);
    let source_snapshot = &apply_json["data"]["results"][0]["source_snapshot"];
    assert_eq!(source_snapshot["status"], serde_json::json!("captured"));
    let snapshot = &source_snapshot["snapshot"];
    assert_eq!(snapshot["owner"], serde_json::json!("App"));
    assert_eq!(snapshot["owner_quoted"], serde_json::json!(true));
    assert_eq!(snapshot["name"], serde_json::json!("foo"));
    assert_eq!(snapshot["name_quoted"], serde_json::json!(true));
    assert!(
        snapshot["target_identity_sha256"]
            .as_str()
            .is_some_and(|digest| digest.starts_with("sha256:"))
    );

    let snapshot_id = snapshot["id"].as_str().expect("snapshot id");
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
    let revert_sql = revert_json["data"]["proposal"]["statements"][0]["sql_template"]
        .as_str()
        .expect("revert SQL");
    assert!(revert_sql.starts_with("CREATE OR REPLACE PROCEDURE \"foo\""));

    let calls = calls.lock();
    assert_eq!(calls[0].0, "oracle_get_source");
    assert_eq!(calls[0].1["owner"], serde_json::json!("\"App\""));
    assert_eq!(calls[0].1["name"], serde_json::json!("\"foo\""));
    assert_eq!(calls[0].1["owner_quoted"], serde_json::json!(true));
    assert_eq!(calls[0].1["name_quoted"], serde_json::json!(true));
    assert_eq!(calls[1].0, "oracle_execute");
}

#[test]
fn coexisting_unquoted_object_cannot_satisfy_quoted_snapshot_identity() {
    let (server, cfg, calls, apply_json) = apply_quoted_source_change(true);
    let source_snapshot = &apply_json["data"]["results"][0]["source_snapshot"];
    assert_eq!(source_snapshot["status"], serde_json::json!("skipped"));
    assert_eq!(
        source_snapshot["reason"],
        serde_json::json!("source fetch target identity did not match apply target")
    );
    assert_eq!(source_snapshot["expected_object"]["name"], "foo");
    assert_eq!(source_snapshot["actual_object"]["name"], "FOO");
    assert_ne!(
        source_snapshot["expected_identity_sha256"],
        source_snapshot["actual_identity_sha256"]
    );

    let history = handle_http_request(
        &server,
        &cfg,
        operator_json_get("/operator/v1/source-history"),
    );
    assert_eq!(
        response_json(&history)["data"]["snapshots"],
        serde_json::json!([])
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

#[test]
fn fetched_source_text_cannot_disagree_with_exact_quoted_metadata() {
    let target = source_object_from_create_or_replace_sql(
        "CREATE OR REPLACE PROCEDURE \"App\".\"foo\" IS BEGIN NULL; END;",
    )
    .expect("quoted target");
    let outcome = current_source_document(
        &target,
        "PROCEDURE",
        "App",
        "foo",
        "PROCEDURE",
        "all_source",
        "CREATE OR REPLACE PROCEDURE FOO IS BEGIN NULL; END;",
    );
    let SourceSnapshotFetchOutcome::Skipped(skipped) = outcome else {
        panic!("mismatched source text must not become a captured document");
    };
    assert_eq!(skipped["status"], serde_json::json!("skipped"));
    assert_eq!(
        skipped["reason"],
        serde_json::json!("source fetch target identity did not match apply target")
    );
}

#[test]
fn unsupported_quoted_source_header_skips_snapshot_without_fetching() {
    let (auditor, _sink) = operator_auditor();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let server = server_with_dispatch(Arc::new(SourceHistoryDispatch {
        calls: Arc::clone(&calls),
    }));
    let state = dashboard_test_dir("source-history-unsupported-quote").join("state");
    let service_store = crate::file_store::FileStore::open(&state).expect("service store");
    let owner = service_store
        .acquire_service_owner("http-test")
        .expect("service owner");
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        change_proposals: Some(Arc::new(
            crate::change_proposal::ChangeProposalStore::open_with_owner(owner.clone())
                .expect("proposal store"),
        )),
        source_history: Some(Arc::new(
            crate::source_history::SourceHistoryStore::open_with_owner(owner)
                .expect("source-history store"),
        )),
        ..Default::default()
    };
    let draft = handle_http_request(
        &server,
        &cfg,
        operator_json_post(
            "/operator/v1/change-proposals/draft",
            &serde_json::json!({
                "profile": "prod",
                "author": "agent",
                "statements": [{
                    "sql_template": "CREATE OR REPLACE PROCEDURE \"fo\"\"o\" IS BEGIN NULL; END;",
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
                "idempotency_key": "source-history-unsupported-quote"
            }),
        ),
    );
    assert_eq!(apply.status, 200);
    let apply_json = response_json(&apply);
    assert_eq!(
        apply_json["data"]["results"][0]["source_snapshot"]["status"],
        serde_json::json!("skipped")
    );
    assert_eq!(
        apply_json["data"]["results"][0]["source_snapshot"]["reason"],
        serde_json::json!(
            "statement is not a supported source-replaceable CREATE OR REPLACE shape"
        )
    );
    let call_names = calls
        .lock()
        .iter()
        .map(|(tool, _)| tool.clone())
        .collect::<Vec<_>>();
    assert_eq!(call_names, vec!["oracle_execute".to_owned()]);
}
