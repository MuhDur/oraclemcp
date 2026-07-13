#[test]
fn stateless_unauthenticated_http_has_an_explicit_anonymous_principal() {
    let call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "oracle_preview_sql",
            "arguments": { "sql": "SELECT 1 FROM dual" }
        }
    });
    let response = handle_http_request(
        &scope_echo_server(),
        &HttpTransportConfig {
            json_response: true,
            stateful: false,
            ..Default::default()
        },
        post(&call),
    );
    assert_eq!(response.status, 200);
    let body = response_json(&response);
    assert_eq!(
        body["result"]["structuredContent"]["principal_key"],
        serde_json::json!("anonymous-http"),
        "HTTP must never overload missing principal, which is reserved for process:stdio"
    );
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
