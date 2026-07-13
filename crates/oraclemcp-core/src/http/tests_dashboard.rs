#[test]
fn dashboard_pairing_sets_strict_cookie_and_session_view() {
    let (auditor, _sink) = operator_auditor();
    let dir = dashboard_test_dir("pairing");
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
    assert!(!cookie.contains("Secure"), "loopback HTTP remains usable");
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
fn dashboard_pairing_uses_secure_cookie_on_effective_https() {
    let dir = dashboard_test_dir("pairing-secure");
    let auth = Arc::new(
        DashboardAuth::new(dir.clone(), "https://127.0.0.1").expect("dashboard auth builds"),
    );
    let cfg = HttpTransportConfig {
        effective_scheme: EffectiveHttpScheme::Https,
        dashboard_auth: Some(Arc::clone(&auth)),
        ..Default::default()
    };
    let ticket = crate::dashboard_auth::mint_dashboard_pairing_ticket_for_test(auth.as_ref())
        .expect("ticket mints");
    let token = ticket_from_pairing_url(&ticket.url);
    let pair = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "GET",
            format!("{DASHBOARD_PAIR_PATH}?ticket={token}"),
            [
                ("host", "127.0.0.1"),
                ("accept", "text/html"),
                ("x-forwarded-proto", "http"),
            ],
            Vec::new(),
        )
        .with_peer_loopback(true),
    );

    assert_eq!(pair.status, 303);
    let cookie = pair.header("set-cookie").expect("dashboard cookie");
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));
    assert!(cookie.contains("Secure"));
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

    let direct_apply = handle_http_request(
        &test_server(),
        &cfg,
        operator_json_post(
            "/operator/v1/config/apply",
            &serde_json::json!({ "draft_toml": draft }),
        ),
    );
    assert_eq!(direct_apply.status, 400);
    assert_eq!(
        response_json(&direct_apply)["data"]["error"],
        serde_json::json!("invalid_config_request")
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("target preserved"),
        current,
        "dashboard apply cannot bypass preview"
    );

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
    let preview_token = preview_json["data"]["preview"]["preview_token"]
        .as_str()
        .expect("preview token")
        .to_owned();
    let draft_sha = preview_json["data"]["preview"]["draft_sha256"]
        .as_str()
        .expect("draft hash")
        .to_owned();

    let apply = handle_http_request(
        &test_server(),
        &cfg,
        operator_json_post(
            "/operator/v1/config/apply",
            &serde_json::json!({
                "draft_toml": draft,
                "preview_token": preview_token,
                "expected_draft_sha256": draft_sha,
                "confirm_preview": true,
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
        apply_json["data"]["outcome"]["review"]["draft_sha256"],
        preview_json["data"]["preview"]["draft_sha256"]
    );
    assert_eq!(
        apply_json["data"]["outcome"]["review"]["redacted_diff_sha256"],
        preview_json["data"]["preview"]["redacted_diff_sha256"]
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
        .exchange_ticket(ticket_from_pairing_url(&ticket.url), auth.audience(), false)
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
