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
    let response = handle_http_request(
        &test_server(),
        &cfg,
        post(&init_body()).with_peer_loopback(true),
    );
    assert_eq!(response.status, 200);
    assert_eq!(response.header("content-type"), Some("application/json"));
    let body = response_json(&response);
    assert!(body.get("result").is_some(), "JSON-RPC initialize result");
    assert_eq!(body["result"]["serverInfo"]["name"], "oraclemcp");
    assert_eq!(
        body["result"]["capabilities"]["tools"]["listChanged"],
        serde_json::json!(false),
        "stateless JSON has no compliant server-notification channel"
    );
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
    let initialize = sse_json_events(&HttpResponse {
        status: 200,
        headers: Vec::new(),
        body: body.into_bytes(),
    });
    assert_eq!(
        initialize[0]["result"]["capabilities"]["tools"]["listChanged"],
        serde_json::json!(true),
        "stateful SSE advertises the notification channel it implements"
    );
}

#[test]
fn stateful_progress_notifications_stay_on_the_originating_session_stream() {
    let sessions = Arc::new(HttpSessionStore::default());
    let results = Arc::new(HttpResultStore::new());
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: true,
        session_store: Some(Arc::clone(&sessions)),
        result_store: Some(Arc::clone(&results)),
        ..Default::default()
    };
    let server = test_server();
    let initialize = || {
        handle_http_request(&server, &cfg, post(&init_body()))
            .header("mcp-session-id")
            .expect("initialize returns session id")
            .to_owned()
    };
    let session_a = initialize();
    let session_b = initialize();

    let call = |session_id: &str, id: u64, token: &str| {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": "test_tool",
                "arguments": {},
                "_meta": { "progressToken": token }
            }
        });
        handle_http_request(
            &server,
            &cfg,
            HttpRequest::new(
                "POST",
                MCP_PATH,
                [
                    ("host", "127.0.0.1"),
                    ("content-type", "application/json"),
                    ("accept", "application/json, text/event-stream"),
                    ("mcp-session-id", session_id),
                    ("mcp-protocol-version", "2025-11-25"),
                ],
                body.to_string().into_bytes(),
            ),
        )
    };

    let response_a = call(&session_a, 10, "token-a");
    let response_b = call(&session_b, 20, "token-b");
    for (response, expected, forbidden) in [
        (&response_a, "token-a", "token-b"),
        (&response_b, "token-b", "token-a"),
    ] {
        let progress = sse_json_events(response)
            .into_iter()
            .filter(|event| event["method"] == "notifications/progress")
            .collect::<Vec<_>>();
        assert_eq!(progress.len(), 2, "start and finish are delivered");
        assert!(
            progress
                .iter()
                .all(|event| event["params"]["progressToken"] == expected)
        );
        assert!(
            progress
                .iter()
                .all(|event| event["params"]["progressToken"] != forbidden)
        );
    }

    for (session_id, expected, forbidden) in [
        (&session_a, "token-a", "token-b"),
        (&session_b, "token-b", "token-a"),
    ] {
        let replay = results
            .events_after(session_id, None, false)
            .expect("session replay remains available");
        let progress = replay
            .iter()
            .filter(|event| event.data["method"] == "notifications/progress")
            .collect::<Vec<_>>();
        assert_eq!(progress.len(), 2);
        assert!(
            progress
                .iter()
                .all(|event| event.data["params"]["progressToken"] == expected)
        );
        assert!(
            progress
                .iter()
                .all(|event| event.data["params"]["progressToken"] != forbidden)
        );
    }
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
    let response = handle_http_request(
        &test_server(),
        &cfg,
        post(&init_body()).with_peer_loopback(true),
    );
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
    assert!(
        !cookie.contains("Secure"),
        "explicit loopback HTTP compatibility stays available"
    );
}

#[test]
fn remote_plaintext_initialize_suppresses_cookie_despite_forwarding_headers() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: true,
        session_store: Some(Arc::new(HttpSessionStore::default())),
        result_store: Some(Arc::new(HttpResultStore::new())),
        ..Default::default()
    };
    let request = HttpRequest::new(
        "POST",
        MCP_PATH,
        [
            ("host", "mcp.example.com"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
            ("forwarded", "for=192.0.2.10;proto=https"),
            ("x-forwarded-proto", "https"),
        ],
        init_body().to_string().into_bytes(),
    );
    let cfg = HttpTransportConfig {
        allowed_hosts: vec!["mcp.example.com".to_owned()],
        ..cfg
    };

    let response = handle_http_request(&test_server(), &cfg, request);
    assert_eq!(response.status, 200);
    assert!(
        response.header("mcp-session-id").is_some(),
        "non-browser MCP clients retain the explicit session header"
    );
    assert_eq!(
        response.header("set-cookie"),
        None,
        "remote plaintext must not mint a privileged browser cookie, and spoofed forwarding headers cannot override the server-observed scheme"
    );
}

#[test]
fn explicit_effective_https_sets_secure_cookie_and_ignores_forwarded_http() {
    let cfg = HttpTransportConfig {
        allowed_hosts: vec!["mcp.example.com".to_owned()],
        json_response: true,
        stateful: true,
        effective_scheme: EffectiveHttpScheme::Https,
        session_store: Some(Arc::new(HttpSessionStore::default())),
        result_store: Some(Arc::new(HttpResultStore::new())),
        ..Default::default()
    };
    let request = HttpRequest::new(
        "POST",
        MCP_PATH,
        [
            ("host", "mcp.example.com"),
            ("content-type", "application/json"),
            ("accept", "application/json, text/event-stream"),
            ("forwarded", "for=192.0.2.10;proto=http"),
            ("x-forwarded-proto", "http"),
        ],
        init_body().to_string().into_bytes(),
    );

    let response = handle_http_request(&test_server(), &cfg, request);
    let cookie = response
        .header("set-cookie")
        .expect("explicit effective HTTPS mints a browser cookie");
    assert!(cookie.contains("Secure"));
}

#[test]
fn stateful_cookie_expiry_matches_transport_and_scope_attributes() {
    let secure = expired_stateful_session_cookie_header(true);
    for attribute in ["Path=/mcp", "Max-Age=0", "HttpOnly", "SameSite=Strict"] {
        assert!(secure.contains(attribute), "missing {attribute}: {secure}");
    }
    assert!(secure.contains("Secure"));

    let loopback_http = expired_stateful_session_cookie_header(false);
    assert!(loopback_http.contains("Max-Age=0"));
    assert!(!loopback_http.contains("Secure"));
}

#[test]
fn effective_https_delete_expires_cookie_with_secure_matching_attributes() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: true,
        effective_scheme: EffectiveHttpScheme::Https,
        session_store: Some(Arc::new(HttpSessionStore::default())),
        result_store: Some(Arc::new(HttpResultStore::new())),
        ..Default::default()
    };
    let init = handle_http_request(&test_server(), &cfg, post(&init_body()));
    let session_id = init
        .header("mcp-session-id")
        .expect("HTTPS initialize returns session id");
    assert!(
        init.header("set-cookie")
            .is_some_and(|cookie| cookie.contains("Secure")),
        "HTTPS initialize cookie is Secure"
    );
    let delete = HttpRequest::new(
        "DELETE",
        MCP_PATH,
        [("host", "127.0.0.1"), ("mcp-session-id", session_id)],
        Vec::new(),
    );
    let response = handle_http_request(&test_server(), &cfg, delete);
    assert_eq!(response.status, 202);
    let expired = response
        .header("set-cookie")
        .expect("HTTPS DELETE expires the cookie");
    for attribute in [
        "Path=/mcp",
        "Max-Age=0",
        "HttpOnly",
        "SameSite=Strict",
        "Secure",
    ] {
        assert!(
            expired.contains(attribute),
            "missing {attribute}: {expired}"
        );
    }
}

#[test]
fn oauth_stateful_get_accepts_strict_cookie_with_origin_only() {
    let session_store = Arc::new(HttpSessionStore::default());
    let result_store = Arc::new(HttpResultStore::new());
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: true,
        effective_scheme: EffectiveHttpScheme::Https,
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
    assert!(
        init.header("set-cookie")
            .is_some_and(|cookie| cookie.contains("Secure")),
        "effective HTTPS must secure the OAuth session cookie"
    );
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
    assert!(body.contains("id: 1/"));
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
    )
    .with_peer_loopback(true);
    let deleted = handle_http_request(&test_server(), &cfg, delete);
    assert_eq!(deleted.status, 202);
    let expired_cookie = deleted
        .header("set-cookie")
        .expect("successful loopback DELETE clears the browser session cookie");
    assert!(expired_cookie.starts_with(&format!("{STATEFUL_SESSION_COOKIE}=;")));
    assert!(expired_cookie.contains("Path=/mcp"));
    assert!(expired_cookie.contains("Max-Age=0"));
    assert!(expired_cookie.contains("HttpOnly"));
    assert!(expired_cookie.contains("SameSite=Strict"));
    assert!(!expired_cookie.contains("Secure"));
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

    for token in [
        jwt_with_type_and_claims(Some("JWT"), oauth_claims("oracle:read")),
        {
            let mut claims = oauth_claims("oracle:read");
            claims.as_object_mut().unwrap().remove("sub");
            jwt_with_type_and_claims(Some("at+jwt"), claims)
        },
    ] {
        let rejected = handle_http_request(
            &test_server(),
            &cfg,
            HttpRequest::new(
                "POST",
                MCP_PATH,
                [
                    ("host", "127.0.0.1"),
                    ("content-type", "application/json"),
                    ("accept", "application/json, text/event-stream"),
                    ("authorization", &format!("Bearer {token}")),
                ],
                init_body().to_string().into_bytes(),
            ),
        );
        assert_eq!(rejected.status, 401);
        assert_eq!(String::from_utf8_lossy(&rejected.body), "unauthorized");
        assert!(
            rejected
                .header("www-authenticate")
                .is_some_and(|value| value.ends_with("error=\"invalid_token\"")),
            "token-class and claim-shape failures must share the opaque invalid_token surface"
        );
        assert!(
            !String::from_utf8_lossy(&rejected.body).contains(&token),
            "rejected bearer must not be echoed"
        );
        for (name, value) in &rejected.headers {
            assert!(
                !value.contains(&token),
                "rejected bearer leaked in response header {name}: {value}"
            );
        }
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
fn oauth_rejections_keep_one_challenge_and_audit_the_fixed_reason() {
    let (auditor, sink) = operator_auditor();
    let bad_signature_cfg = HttpTransportConfig {
        json_response: true,
        stateful: false,
        oauth: Some(oauth_enforcement()),
        operator_auditor: Some(Arc::clone(&auditor)),
        ..Default::default()
    };
    let bad_signature = jwt_with_scope("oracle:read");
    let bad_signature_response = handle_http_request(
        &test_server(),
        &bad_signature_cfg,
        HttpRequest::new(
            "POST",
            MCP_PATH,
            [
                ("host", "127.0.0.1"),
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
                ("authorization", &format!("Bearer {bad_signature}")),
            ],
            init_body().to_string().into_bytes(),
        ),
    );

    let mut expired_claims = oauth_claims("oracle:read");
    expired_claims["exp"] = serde_json::json!(0);
    let expired = jwt_with_type_and_claims(Some("at+jwt"), expired_claims);
    let expired_cfg = HttpTransportConfig {
        json_response: true,
        stateful: false,
        oauth: Some(accepting_oauth_enforcement(Vec::new())),
        operator_auditor: Some(auditor),
        ..Default::default()
    };
    let expired_response = handle_http_request(
        &test_server(),
        &expired_cfg,
        HttpRequest::new(
            "POST",
            MCP_PATH,
            [
                ("host", "127.0.0.1"),
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
                ("authorization", &format!("Bearer {expired}")),
            ],
            init_body().to_string().into_bytes(),
        ),
    );

    let challenge = bad_signature_response
        .header("www-authenticate")
        .expect("bad signature has a challenge");
    assert_eq!(bad_signature_response.status, 401);
    assert_eq!(expired_response.status, 401);
    assert_eq!(expired_response.header("www-authenticate"), Some(challenge));
    assert_eq!(
        challenge,
        "Bearer resource_metadata=\"https://oraclemcp.example/.well-known/oauth-protected-resource\", error=\"invalid_token\""
    );
    assert!(
        !challenge.contains("error_description="),
        "anonymous callers must not receive a token-validation oracle"
    );

    let records = sink.records();
    assert_eq!(records.len(), 2, "each rejected bearer is an audit event");
    let reasons: Vec<_> = records
        .iter()
        .map(|record| {
            assert_eq!(record.tool, "oauth_bearer_authentication");
            assert_eq!(record.decision, AuditDecision::Blocked);
            assert_eq!(record.outcome, AuditOutcome::Failed);
            assert_eq!(
                record.cancel.as_ref().map(|cancel| cancel.kind.as_str()),
                Some("Authentication")
            );
            record
                .cancel
                .as_ref()
                .map(|cancel| cancel.reason.as_str())
                .expect("OAuth rejection keeps its fixed reason in the audit trail")
        })
        .collect();
    assert_eq!(reasons, ["oauth_bad_signature", "oauth_expired"]);
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
fn native_parser_preserves_413_431_and_400_statuses() {
    fn exchange(addr: std::net::SocketAddr, request: &[u8]) -> String {
        let mut stream = TcpStream::connect(addr).expect("connect native parser listener");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set response timeout");
        stream.write_all(request).expect("write raw request");
        stream
            .shutdown(std::net::Shutdown::Write)
            .expect("finish raw request");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("read raw response");
        response
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind native parser listener");
    let addr = listener.local_addr().expect("native parser address");
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let handle = std::thread::spawn(move || {
        serve_http_until(
            listener,
            test_server(),
            &obs_config(HealthState::new("0.1.0"), None, None),
            server_shutdown,
        )
        .expect("native parser listener exits cleanly")
    });

    let oversized_body = format!(
        "POST /mcp HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: {}\r\n\r\n",
        MAX_BODY_BYTES + 1
    );
    let response = exchange(addr, oversized_body.as_bytes());
    assert!(response.starts_with("HTTP/1.1 413 Payload Too Large\r\n"));
    assert!(response.contains("cache-control: no-store\r\n"));

    let mut oversized_header = b"GET /healthz HTTP/1.1\r\nhost: 127.0.0.1\r\nx-fill: ".to_vec();
    oversized_header.resize(MAX_HEADER_BYTES - 3, b'x');
    oversized_header.extend_from_slice(b"\r\n\r\n");
    assert_eq!(oversized_header.len(), MAX_HEADER_BYTES + 1);
    let response = exchange(addr, &oversized_header);
    assert!(response.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n"));

    let malformed = b"POST /mcp HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: nope\r\n\r\n";
    let response = exchange(addr, malformed);
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));

    let mut exact_header = b"GET /healthz HTTP/1.1\r\nhost: 127.0.0.1\r\nx-fill: ".to_vec();
    exact_header.resize(MAX_HEADER_BYTES - 4, b'x');
    exact_header.extend_from_slice(b"\r\n\r\n");
    assert_eq!(exact_header.len(), MAX_HEADER_BYTES);
    let response = exchange(addr, &exact_header);
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));

    shutdown.store(true, Ordering::SeqCst);
    handle.join().expect("native parser listener joins");
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
fn stateful_shutdown_clears_both_registries_and_releases_capacity() {
    let sessions = Arc::new(HttpSessionStore::with_limits_for_test(1, 1));
    let results = Arc::new(HttpResultStore::new());
    sessions
        .insert_with_result_store(
            "before-shutdown".to_owned(),
            "principal-a".to_owned(),
            "2025-03-26".to_owned(),
            Duration::from_secs(900),
            Some(results.as_ref()),
        )
        .expect("initial session");
    let cfg = HttpTransportConfig {
        stateful: true,
        session_store: Some(Arc::clone(&sessions)),
        result_store: Some(Arc::clone(&results)),
        ..Default::default()
    };

    close_stateful_sessions_for_shutdown(&test_server(), &cfg);

    assert_eq!(sessions.len(), 0);
    assert_eq!(results.session_count(), 0);
    assert!(
        results
            .append_response_if_session(
                "before-shutdown",
                serde_json::json!({ "late": "completion" }),
            )
            .is_none(),
        "a late completion must not recreate an orphan replay session"
    );
    assert_eq!(results.session_count(), 0);
    sessions
        .insert_with_result_store(
            "after-shutdown".to_owned(),
            "principal-a".to_owned(),
            "2025-03-26".to_owned(),
            Duration::from_secs(900),
            Some(results.as_ref()),
        )
        .expect("shutdown releases global and per-principal capacity");
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
fn local_doctor_and_authorized_operator_use_transport_reserve_under_saturation() {
    fn request(addr: std::net::SocketAddr, raw: &str) -> String {
        let mut stream = TcpStream::connect(addr).expect("connect control request");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set control response timeout");
        stream
            .write_all(raw.as_bytes())
            .expect("write control request");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("read control response");
        response
    }

    let cx = detached_admission_cx();
    let lane_admission = AdmissionController::n4_stateful_defaults();
    let mut lane_permits = Vec::new();
    for index in 0..DEFAULT_GLOBAL_HOST_CAP {
        lane_permits.push(
            lane_admission
                .try_admit(&cx, &format!("lane-subject-{}", index / 8))
                .expect("all measured Oracle lane capacity remains usable"),
        );
    }
    assert!(
        lane_admission.try_admit(&cx, "lane-overflow").is_err(),
        "data-plane lane capacity is genuinely saturated"
    );

    let transport_admission = Arc::new(AdmissionController::with_reserved(3, 3, 1, 1));
    let lifecycle = Arc::new(CancelRecordingLifecycle::default());
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback reserve listener");
    let addr = listener.local_addr().expect("reserve listener address");
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let (auditor, _audit_sink) = operator_auditor();
    let config = HttpTransportConfig {
        json_response: true,
        transport_admission: Arc::clone(&transport_admission),
        operator_auditor: Some(auditor),
        session_lifecycle: Some(Arc::clone(&lifecycle) as Arc<dyn HttpSessionLifecycle>),
        observability: ObservabilityState {
            health: Some(HealthState::new("0.1.0")),
            metrics: None,
            readiness_probe: None,
        },
        ..Default::default()
    };
    let handle = std::thread::spawn(move || {
        serve_http_until(listener, test_server(), &config, server_shutdown)
            .expect("reserved native HTTP server exits cleanly")
    });

    let stalled_regular = TcpStream::connect(addr).expect("connect regular capacity holder");
    for _ in 0..100 {
        if transport_admission
            .snapshot(
                HTTP_TRANSPORT_CAPACITY_SCOPE,
                HTTP_TRANSPORT_CAPACITY_SUBJECT,
            )
            .regular_global_available
            == 0
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        transport_admission
            .snapshot(
                HTTP_TRANSPORT_CAPACITY_SCOPE,
                HTTP_TRANSPORT_CAPACITY_SUBJECT
            )
            .regular_global_available,
        0,
        "regular transport capacity saturates"
    );

    let stalled_probe = TcpStream::connect(addr).expect("connect stalled reserve probe");
    for _ in 0..100 {
        if transport_admission
            .snapshot(
                HTTP_TRANSPORT_CAPACITY_SCOPE,
                HTTP_TRANSPORT_CAPACITY_SUBJECT,
            )
            .control_probes_in_use
            == 1
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let probe_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < probe_deadline
        && transport_admission
            .snapshot(
                HTTP_TRANSPORT_CAPACITY_SCOPE,
                HTTP_TRANSPORT_CAPACITY_SUBJECT,
            )
            .control_probes_in_use
            != 0
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        transport_admission
            .snapshot(
                HTTP_TRANSPORT_CAPACITY_SCOPE,
                HTTP_TRANSPORT_CAPACITY_SUBJECT,
            )
            .control_probes_in_use,
        0,
        "an unclassified reserve worker must be released by its one-second ingress deadline"
    );
    drop(stalled_probe);

    let spoofed = request(
        addr,
        "GET /ordinary HTTP/1.1\r\nhost: 127.0.0.1\r\nx-admission-class: operator\r\ncontent-length: 0\r\n\r\n",
    );
    assert!(spoofed.starts_with("HTTP/1.1 429 Too Many Requests"));
    assert!(spoofed.contains("AT_CAPACITY"));

    let health = request(
        addr,
        "GET /healthz HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 0\r\n\r\n",
    );
    assert!(health.starts_with("HTTP/1.1 200 OK"), "{health}");

    let operator = request(
        addr,
        "GET /operator/v1/health HTTP/1.1\r\nhost: 127.0.0.1\r\naccept: application/json\r\ncontent-length: 0\r\n\r\n",
    );
    assert!(operator.starts_with("HTTP/1.1 200 OK"), "{operator}");

    let cancel_body = serde_json::json!({ "lane_id": "lane-a" }).to_string();
    let cancel_request = format!(
        "POST /operator/v1/lanes/cancel HTTP/1.1\r\nhost: 127.0.0.1\r\naccept: application/json\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
        cancel_body.len(),
        cancel_body
    );
    let cancel = request(addr, &cancel_request);
    assert!(cancel.starts_with("HTTP/1.1 200 OK"), "{cancel}");
    assert_eq!(
        lifecycle.closed.lock().as_slice(),
        &[(
            "mcp-session:lane-a".to_owned(),
            "principal:subject-sha256:abc".to_owned(),
            DispatchCloseReason::OperatorCancel,
        )],
        "operator cancellation remains reachable while both lane and regular transport caps are saturated"
    );

    let snapshot = transport_admission.snapshot(
        HTTP_TRANSPORT_CAPACITY_SCOPE,
        HTTP_TRANSPORT_CAPACITY_SUBJECT,
    );
    assert_eq!(
        snapshot.global_in_use, 1,
        "only the stalled regular remains"
    );
    assert_eq!(snapshot.control_probes_in_use, 0);
    assert_eq!(snapshot.operator_in_use, 0);
    assert_eq!(snapshot.doctor_in_use, 0);
    assert!(snapshot.global_in_use <= snapshot.global_cap);

    drop(stalled_regular);
    drop(lane_permits);
    shutdown.store(true, Ordering::SeqCst);
    handle.join().expect("reserved server thread joins");
}

#[test]
fn remote_or_unclassified_callers_cannot_enter_transport_reserve() {
    let cx = detached_admission_cx();
    let controller = AdmissionController::with_reserved(3, 3, 1, 1);
    let _regular = controller
        .try_admit(&cx, HTTP_TRANSPORT_CAPACITY_SUBJECT)
        .expect("regular slot");

    let remote = try_admit_http_transport(&controller, false)
        .expect_err("remote pre-auth caller cannot consume local control reserve");
    assert_eq!(remote.status, 429);
    let snapshot = controller.snapshot(
        HTTP_TRANSPORT_CAPACITY_SCOPE,
        HTTP_TRANSPORT_CAPACITY_SUBJECT,
    );
    assert_eq!(snapshot.global_in_use, 1);
    assert_eq!(snapshot.control_probes_in_use, 0);

    let probe = try_admit_http_transport(&controller, true)
        .expect("one local unclassified probe is bounded");
    assert!(probe.is_control_probe());
    assert!(
        try_admit_http_transport(&controller, true).is_err(),
        "only one unclassified control worker may exist at a time"
    );
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
