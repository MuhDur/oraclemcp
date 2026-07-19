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
    let response_event_id = post_body
        .lines()
        .find_map(|line| line.strip_prefix("id: 1/"))
        .map(|binding| format!("1/{binding}"))
        .expect("stateful response carries a session-bound event id");
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
    assert!(replay_body.contains(&format!("id: {response_event_id}")));
    assert!(replay_body.contains("\"id\":9"));
    assert!(replay_body.contains("\"tool\":\"oracle_query\""));

    let after = HttpRequest::new(
        "GET",
        format!("/mcp?cursor={response_event_id}"),
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
fn replay_store_replaces_oversized_responses_with_a_bounded_honest_gap() {
    let limits = HttpResultStoreLimits {
        max_events_per_session: 8,
        max_event_bytes: 256,
        max_session_bytes: 2_048,
        max_global_bytes: 4_096,
    };
    let result_store = HttpResultStore::with_limits_for_test(limits);
    let session_id = "oversized-replay-session";
    result_store.ensure_session(session_id);

    let secret_payload = "not-retained-".repeat(128);
    let id =
        result_store.append_response(session_id, serde_json::json!({ "payload": secret_payload }));
    assert!(id.starts_with("1/"), "{id}");
    assert_ne!(id, "1/0");
    let (total_bytes, sessions) = result_store.retained_bytes_for_test();
    assert!(total_bytes <= limits.max_global_bytes, "{total_bytes}");
    assert_eq!(sessions.len(), 1);
    assert!(sessions[0].1 <= limits.max_session_bytes);

    let events = result_store
        .events_after(session_id, Some("0"), true)
        .expect("bounded replay marker");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, id);
    assert_eq!(events[0].event, Some("stream-gap"));
    assert_eq!(
        events[0].data["reason"],
        serde_json::json!("response_too_large_for_replay")
    );
    assert_eq!(events[0].data["max_replay_event_bytes"], 256);
    assert!(
        !events[0].data.to_string().contains("not-retained-"),
        "the replay marker must not retain the oversized response body"
    );
}

#[test]
fn replay_store_notifies_only_waiters_for_the_changed_session() {
    let result_store = HttpResultStore::new();
    result_store.ensure_session("session-a");
    result_store.ensure_session("session-b");
    assert_eq!(
        result_store.session_notification_count_for_test("session-a"),
        0
    );
    assert_eq!(
        result_store.session_notification_count_for_test("session-b"),
        0
    );

    result_store.append_response("session-a", serde_json::json!({ "row": 1 }));

    assert_eq!(
        result_store.session_notification_count_for_test("session-a"),
        1,
        "the changed session wakes its own SSE waiters"
    );
    assert_eq!(
        result_store.session_notification_count_for_test("session-b"),
        0,
        "an unrelated session must not receive the wakeup"
    );
}

#[test]
fn replay_store_enforces_session_and_global_byte_caps_with_oldest_eviction() {
    let limits = HttpResultStoreLimits {
        max_events_per_session: 128,
        max_event_bytes: 512,
        max_session_bytes: 500,
        max_global_bytes: 700,
    };
    let result_store = Arc::new(HttpResultStore::with_limits_for_test(limits));
    for sequence in 0..4 {
        result_store.append_response(
            "session-a",
            serde_json::json!({ "sequence": sequence, "payload": "a".repeat(180) }),
        );
    }
    for sequence in 0..3 {
        result_store.append_response(
            "session-b",
            serde_json::json!({ "sequence": sequence, "payload": "b".repeat(180) }),
        );
    }

    let (total_bytes, sessions) = result_store.retained_bytes_for_test();
    assert!(total_bytes <= limits.max_global_bytes, "{total_bytes}");
    assert_eq!(
        total_bytes,
        sessions.iter().map(|(_, bytes)| *bytes).sum::<usize>(),
        "global accounting equals the exact sum of resident sessions"
    );
    assert!(
        sessions
            .iter()
            .all(|(_, bytes)| *bytes <= limits.max_session_bytes),
        "per-session byte ceiling violated: {sessions:?}"
    );
    let expired = result_store
        .events_after("session-a", Some("0"), false)
        .expect_err("the oldest globally evicted cursor must be explicit");
    assert_eq!(expired.status, 410);
    let gap = result_store
        .events_after("session-a", Some("0"), true)
        .expect("last-event-id resume gets a typed gap");
    assert_eq!(gap[0].event, Some("stream-gap"));

    let concurrent = Arc::clone(&result_store);
    let workers = (0..8)
        .map(|worker| {
            let store = Arc::clone(&concurrent);
            std::thread::spawn(move || {
                let session = format!("concurrent-{worker}");
                for sequence in 0..20 {
                    store.append_response(
                        &session,
                        serde_json::json!({ "sequence": sequence, "payload": "c".repeat(80) }),
                    );
                }
                if worker % 2 == 0 {
                    store.remove_session(&session);
                }
            })
        })
        .collect::<Vec<_>>();
    for worker in workers {
        worker.join().expect("concurrent replay worker");
    }
    let (total_bytes, sessions) = result_store.retained_bytes_for_test();
    assert!(total_bytes <= limits.max_global_bytes, "{total_bytes}");
    assert_eq!(
        total_bytes,
        sessions.iter().map(|(_, bytes)| *bytes).sum::<usize>()
    );
    assert!(
        sessions
            .iter()
            .all(|(_, bytes)| *bytes <= limits.max_session_bytes)
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
    assert!(
        body["oldest_event_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("2/"))
    );
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
    assert!(body.contains("id: 1/"));
    assert!(body.contains("\"type\":\"stream_gap\""));
    assert!(body.contains("\"oldest_event_id\":\"2/"));
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
    assert!(text.contains("id: 1/"));

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

    let session_store = Arc::new(HttpSessionStore::with_limits_for_test(1, 1));
    let result_store = Arc::new(HttpResultStore::new());
    let lifecycle = Arc::new(RecordingLifecycle::default());
    let session_id = "idle-session";
    session_store
        .insert_with_result_store(
            session_id.to_owned(),
            "principal-a".to_owned(),
            "2025-03-26".to_owned(),
            Duration::from_secs(900),
            Some(result_store.as_ref()),
        )
        .expect("seed bounded session");
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

    let server = test_server();
    assert_eq!(reap_idle_stateful_sessions(&server, &cfg), 1);
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
        reap_idle_stateful_sessions(&server, &cfg),
        0,
        "reaping the same idle session is idempotent"
    );
    session_store
        .insert_with_result_store(
            "replacement-session".to_owned(),
            "principal-a".to_owned(),
            "2025-03-26".to_owned(),
            Duration::from_secs(900),
            Some(result_store.as_ref()),
        )
        .expect("idle expiry releases global and per-principal capacity");
    assert_eq!(session_store.len(), 1);
    assert_eq!(result_store.session_count(), 1);
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
            _min_generation: Option<u64>,
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
            &test_server(),
            &cfg,
            "client:sha256:aaa",
            DispatchCloseReason::SessionDelete,
            None,
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
fn principal_session_close_forwards_the_revocation_generation_floor() {
    // QA100 .92: the HTTP revoke/rotate bridge must forward the bumped credential
    // generation to the lane lifecycle so it can install a per-principal admission
    // floor. This proves the wiring between close_http_principal_sessions and the
    // lifecycle carries the generation, not merely the principal/reason.
    #[derive(Debug, Default)]
    struct RecordingLifecycle {
        installed: std::sync::Mutex<Vec<(String, Option<u64>)>>,
    }

    impl HttpSessionLifecycle for RecordingLifecycle {
        fn close_session(&self, _session_id: &str, _principal_key: &str) -> bool {
            false
        }

        fn close_principal_sessions(
            &self,
            principal_key: &str,
            _reason: DispatchCloseReason,
            min_generation: Option<u64>,
        ) -> usize {
            self.installed
                .lock()
                .expect("test lifecycle mutex")
                .push((principal_key.to_owned(), min_generation));
            1
        }
    }

    let lifecycle = Arc::new(RecordingLifecycle::default());
    let cfg = HttpTransportConfig {
        stateful: true,
        session_lifecycle: Some(lifecycle.clone()),
        ..Default::default()
    };

    close_http_principal_sessions(
        &test_server(),
        &cfg,
        "client:sha256:aaa",
        DispatchCloseReason::SessionDelete,
        Some(7),
    );

    assert_eq!(
        lifecycle
            .installed
            .lock()
            .expect("test lifecycle mutex")
            .as_slice(),
        &[("client:sha256:aaa".to_owned(), Some(7))],
        "the bumped credential generation must reach the lane lifecycle floor",
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
    let mut wire = Vec::new();
    write_http_response(&mut wire, &response).expect("serialize cancellation response");
    let wire = String::from_utf8(wire).expect("HTTP response is UTF-8");
    assert!(
        wire.starts_with("HTTP/1.1 499 Client Closed Request\r\n"),
        "unexpected cancellation status line: {wire}"
    );
    let body = response_json(&response);
    assert_eq!(body["outcome"], serde_json::json!("cancelled"));
    assert_eq!(body["cancel_kind"], serde_json::json!("Timeout"));
    assert!(body.get("result").is_none());
}

#[test]
fn every_emitted_http_status_has_an_explicit_non_success_reason_phrase() {
    for status in [
        200, 202, 303, 400, 401, 403, 404, 405, 406, 409, 410, 413, 415, 429, 499, 500, 503,
    ] {
        assert_ne!(
            reason_phrase(status),
            "Unknown Status",
            "emitted status {status} must have an explicit reason phrase"
        );
    }

    let response = HttpResponse {
        status: 599,
        headers: Vec::new(),
        body: Vec::new(),
    };
    let mut wire = Vec::new();
    write_http_response(&mut wire, &response).expect("serialize unknown status");
    let wire = String::from_utf8(wire).expect("HTTP response is UTF-8");
    assert!(
        wire.starts_with("HTTP/1.1 599 Unknown Status\r\n"),
        "{wire}"
    );
    assert!(!wire.starts_with("HTTP/1.1 599 OK"), "{wire}");
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
fn healthz_pairing_probe_is_bound_to_listener_token_and_audience() {
    let dir = dashboard_test_dir("listener-proof");
    let auth =
        Arc::new(DashboardAuth::new(dir, "http://127.0.0.1:7070").expect("dashboard auth builds"));
    let mut cfg = obs_config(HealthState::new("0.1.0"), None, None);
    cfg.dashboard_auth = Some(Arc::clone(&auth));
    let challenge = "a".repeat(64);
    let token_sha256 = "b".repeat(64);
    let request = HttpRequest::new(
        "GET",
        HEALTHZ_PATH,
        [
            ("host", "127.0.0.1"),
            (DASHBOARD_PROBE_CHALLENGE_HEADER, challenge.as_str()),
            (DASHBOARD_PROBE_TOKEN_HASH_HEADER, token_sha256.as_str()),
        ],
        Vec::new(),
    );
    let response = handle_http_request(&test_server(), &cfg, request);
    assert_eq!(response.status, 200);
    assert_eq!(
        response.header(DASHBOARD_INSTANCE_HEADER),
        Some(auth.instance_id())
    );
    assert_eq!(
        response.header(DASHBOARD_AUDIENCE_HEADER),
        Some(auth.audience())
    );
    let expected = auth
        .pairing_probe_proof(&challenge, &token_sha256)
        .expect("well-formed proof");
    assert_eq!(
        response.header(DASHBOARD_PROOF_HEADER),
        Some(expected.as_str())
    );
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
        dashboard_auth: Some(Arc::new(
            DashboardAuth::new(dir, "http://127.0.0.1").expect("dashboard auth builds"),
        )),
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
            "POST",
            DASHBOARD_PAIR_PATH,
            [
                ("host", "127.0.0.1"),
                ("origin", "http://127.0.0.1"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            format!("{DASHBOARD_PAIRING_CODE_FIELD}=opaque").into_bytes(),
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
