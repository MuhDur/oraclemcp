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
    let token = &ticket.code;
    assert!(
        !ticket.url.contains(token.as_str()) && !ticket.url.contains('?') && !ticket.url.contains('#'),
        "the pairing URL carries no bootstrap secret: {}",
        ticket.url
    );

    let pair = handle_http_request(&test_server(), &cfg, pairing_post(token));
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

    let replay = handle_http_request(&test_server(), &cfg, pairing_post(token));
    assert_eq!(replay.status, 401, "pairing ticket is single-use");
    assert!(
        replay.header("set-cookie").is_none(),
        "a replayed code mints no second session"
    );

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
    let token = &ticket.code;
    let pair = handle_http_request(
        &test_server(),
        &cfg,
        HttpRequest::new(
            "POST",
            DASHBOARD_PAIR_PATH,
            [
                ("host", "127.0.0.1"),
                ("origin", "https://127.0.0.1"),
                ("content-type", "application/x-www-form-urlencoded"),
                ("x-forwarded-proto", "http"),
            ],
            format!("{DASHBOARD_PAIRING_CODE_FIELD}={token}").into_bytes(),
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
    let malicious_json = response_json(&malicious);
    assert_eq!(
        malicious_json["error_class"],
        serde_json::json!("POLICY_DENIED")
    );
    assert_eq!(
        malicious_json["message"],
        serde_json::json!("dashboard request was refused")
    );
    assert!(
        malicious_json["next_steps"].as_array().is_some_and(|steps| !steps.is_empty()),
        "dashboard 403 envelope should keep the actionable ErrorEnvelope shape"
    );
    let malicious_body =
        String::from_utf8(malicious.body.clone()).expect("dashboard 403 body is UTF-8");
    for leaked_reason in [
        "dashboard_same_origin_required",
        "Origin header",
        "Host header",
        "csrf",
        "action_ticket",
    ] {
        assert!(
            !malicious_body.contains(leaked_reason),
            "dashboard 403 must not reveal refusal cause {leaked_reason}: {malicious_body}"
        );
    }
    assert!(
        malicious_json.get("error").is_none(),
        "dashboard 403 uses ErrorEnvelope fields, not cause-specific error labels"
    );
    assert_eq!(
        calls.load(AtomicOrdering::SeqCst),
        0,
        "cross-origin dashboard POST must not reach dispatch"
    );

    let null_origin = handle_http_request(
        &server,
        &cfg,
        HttpRequest::new(
            "POST",
            "/operator/v1/actions/preview",
            [
                ("host", "127.0.0.1"),
                ("origin", "null"),
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
    assert_eq!(null_origin.status, 403);
    let null_origin_json = response_json(&null_origin);
    assert_eq!(
        null_origin_json["error_class"],
        serde_json::json!("POLICY_DENIED")
    );
    assert_eq!(null_origin_json, malicious_json);
    assert_eq!(
        calls.load(AtomicOrdering::SeqCst),
        0,
        "literal Origin:null must not reach dispatch"
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

/// Bead oraclemcp-l6xn acceptance, proven on the **real served loopback path**
/// (native parser, real sockets) rather than only through `handle_http_request`.
///
/// The bootstrap secret never appears in a request target, so it cannot be
/// recovered from browser history, an extension's `tabs`/`webNavigation` events,
/// `Referer`, or an access log. The secret-free form page deliberately uses
/// `same-origin` so Chromium serializes the real Origin on the form POST; ticket
/// use remains body-only, single-use, `no-store`, CSP-guarded, and backed by the
/// HttpOnly/SameSite=Strict cookie.
#[test]
fn served_dashboard_pairing_keeps_the_bootstrap_secret_out_of_the_request_target() {
    use std::io::Write as _;
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::AtomicBool;

    let dir = dashboard_test_dir("served-pairing");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind pairing listener");
    let addr = listener.local_addr().expect("pairing listener address");
    let host = format!("127.0.0.1:{}", addr.port());
    let audience = format!("http://{host}");
    let auth = Arc::new(DashboardAuth::new(dir, &audience).expect("dashboard auth builds"));
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let server_auth = Arc::clone(&auth);
    let handle = std::thread::spawn(move || {
        serve_http_until(
            listener,
            test_server(),
            &HttpTransportConfig {
                dashboard_auth: Some(server_auth),
                ..Default::default()
            },
            server_shutdown,
        )
        .expect("pairing listener exits cleanly")
    });

    // Every request target this flow sends, exactly as an access log records it.
    let mut access_log: Vec<String> = Vec::new();
    let mut send = |method: &str, target: &str, extra: &str, body: &str| -> String {
        access_log.push(format!("{method} {target} HTTP/1.1"));
        let request = format!(
            "{method} {target} HTTP/1.1\r\nhost: {host}\r\nconnection: close\r\n{extra}content-length: {}\r\n\r\n{body}",
            body.len()
        );
        let mut stream = TcpStream::connect(addr).expect("connect to pairing listener");
        stream
            .write_all(request.as_bytes())
            .expect("write pairing request");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("read pairing response");
        response
    };

    let ticket = crate::dashboard_auth::mint_dashboard_pairing_ticket_for_test(auth.as_ref())
        .expect("ticket mints");
    let code = ticket.code.clone();
    assert_eq!(ticket.url, format!("{audience}{DASHBOARD_PAIR_PATH}"));
    assert!(
        !ticket.url.contains(&code) && !ticket.url.contains('?') && !ticket.url.contains('#'),
        "the URL the operator opens carries no secret: {}",
        ticket.url
    );

    // The bootstrap page is served with no secret in it and none supplied.
    let form = send("GET", DASHBOARD_PAIR_PATH, "accept: text/html\r\n", "");
    assert!(form.starts_with("HTTP/1.1 200 "), "served form: {form}");
    assert!(!form.contains(&code), "the served form never carries the code");
    assert!(form.contains(&format!("name=\"{DASHBOARD_PAIRING_CODE_FIELD}\"")));
    assert!(form.contains("referrer-policy: same-origin"));
    assert!(form.contains(r#"<meta name="referrer" content="same-origin">"#));
    assert!(form.contains("frame-ancestors 'none'"));
    assert!(form.contains("cache-control: no-store"));

    // The code is accepted from the body and mints exactly one session.
    let form_headers = format!(
        "origin: {audience}\r\nsec-fetch-site: same-origin\r\ncontent-type: application/x-www-form-urlencoded\r\n"
    );
    let submit = format!("{DASHBOARD_PAIRING_CODE_FIELD}={code}");
    let paired = send("POST", DASHBOARD_PAIR_PATH, &form_headers, &submit);
    assert!(paired.starts_with("HTTP/1.1 303 "), "pairing: {paired}");
    assert!(paired.contains("location: /"));
    assert!(paired.contains("cache-control: no-store"));
    assert!(
        paired.contains("referrer-policy: no-referrer"),
        "the POST/redirect response keeps the dashboard-wide no-referrer default; \
         only the secret-free form page relaxes to same-origin"
    );
    assert!(paired.contains("HttpOnly"));
    assert!(paired.contains("SameSite=Strict"));
    assert!(
        !paired.contains(&code),
        "no response — redirect Location included — echoes the code"
    );

    // Replay fails closed and mints no second session.
    let replay = send("POST", DASHBOARD_PAIR_PATH, &form_headers, &submit);
    assert!(replay.starts_with("HTTP/1.1 401 "), "replay: {replay}");
    assert!(
        !replay.to_ascii_lowercase().contains("set-cookie"),
        "exactly one session mint: {replay}"
    );
    assert!(
        !replay.contains(&code),
        "the error text never echoes the code"
    );

    // The access log of the whole successful flow is secret-free.
    assert!(
        access_log.iter().all(|line| !line.contains(&code)),
        "no request target carries the bootstrap secret: {access_log:?}"
    );

    shutdown.store(true, AtomicOrdering::SeqCst);
    let _ = TcpStream::connect(addr);
    handle.join().expect("pairing listener thread joins");
}

/// A pre-l6xn `?ticket=` URL replayed from history must not pair — and must not
/// consume the live ticket it names, so the real body exchange still succeeds.
#[test]
fn served_dashboard_pairing_refuses_a_secret_in_the_query_without_consuming_it() {
    use std::io::Write as _;
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::AtomicBool;

    let dir = dashboard_test_dir("served-pairing-query");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind pairing listener");
    let addr = listener.local_addr().expect("pairing listener address");
    let host = format!("127.0.0.1:{}", addr.port());
    let audience = format!("http://{host}");
    let auth = Arc::new(DashboardAuth::new(dir, &audience).expect("dashboard auth builds"));
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let server_auth = Arc::clone(&auth);
    let handle = std::thread::spawn(move || {
        serve_http_until(
            listener,
            test_server(),
            &HttpTransportConfig {
                dashboard_auth: Some(server_auth),
                ..Default::default()
            },
            server_shutdown,
        )
        .expect("pairing listener exits cleanly")
    });

    let send = |method: &str, target: &str, extra: &str, body: &str| -> String {
        let request = format!(
            "{method} {target} HTTP/1.1\r\nhost: {host}\r\nconnection: close\r\n{extra}content-length: {}\r\n\r\n{body}",
            body.len()
        );
        let mut stream = TcpStream::connect(addr).expect("connect to pairing listener");
        stream
            .write_all(request.as_bytes())
            .expect("write pairing request");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("read pairing response");
        response
    };

    let ticket = crate::dashboard_auth::mint_dashboard_pairing_ticket_for_test(auth.as_ref())
        .expect("ticket mints");
    let code = ticket.code.clone();

    let refused = send(
        "GET",
        &format!("{DASHBOARD_PAIR_PATH}?ticket={code}"),
        "accept: text/html\r\n",
        "",
    );
    assert!(refused.starts_with("HTTP/1.1 400 "), "refused: {refused}");
    assert!(
        !refused.to_ascii_lowercase().contains("set-cookie"),
        "a secret in the query never pairs: {refused}"
    );
    assert!(
        !refused.contains(&code),
        "the refusal never echoes the code back"
    );

    // Refusing the URL did not burn the ticket: the body exchange still pairs.
    let paired = send(
        "POST",
        DASHBOARD_PAIR_PATH,
        &format!(
            "origin: {audience}\r\ncontent-type: application/x-www-form-urlencoded\r\n"
        ),
        &format!("{DASHBOARD_PAIRING_CODE_FIELD}={code}"),
    );
    assert!(
        paired.starts_with("HTTP/1.1 303 "),
        "the refused URL must not consume the ticket: {paired}"
    );

    shutdown.store(true, AtomicOrdering::SeqCst);
    let _ = TcpStream::connect(addr);
    handle.join().expect("pairing listener thread joins");
}

/// Literal `Origin: null` is never a workaround for the browser pairing issue:
/// the server must refuse it before reading/exchanging the body code, so a
/// subsequent same-origin POST still consumes the ticket exactly once.
#[test]
fn served_dashboard_pairing_refuses_origin_null_without_consuming_ticket() {
    use std::io::Write as _;
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::AtomicBool;

    let dir = dashboard_test_dir("served-pairing-null-origin");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind pairing listener");
    let addr = listener.local_addr().expect("pairing listener address");
    let host = format!("127.0.0.1:{}", addr.port());
    let audience = format!("http://{host}");
    let auth = Arc::new(DashboardAuth::new(dir, &audience).expect("dashboard auth builds"));
    let shutdown = Arc::new(AtomicBool::new(false));
    let server_shutdown = Arc::clone(&shutdown);
    let server_auth = Arc::clone(&auth);
    let handle = std::thread::spawn(move || {
        serve_http_until(
            listener,
            test_server(),
            &HttpTransportConfig {
                dashboard_auth: Some(server_auth),
                ..Default::default()
            },
            server_shutdown,
        )
        .expect("pairing listener exits cleanly")
    });

    let send = |method: &str, target: &str, extra: &str, body: &str| -> String {
        let request = format!(
            "{method} {target} HTTP/1.1\r\nhost: {host}\r\nconnection: close\r\n{extra}content-length: {}\r\n\r\n{body}",
            body.len()
        );
        let mut stream = TcpStream::connect(addr).expect("connect pairing listener");
        stream
            .write_all(request.as_bytes())
            .expect("write pairing request");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("read pairing response");
        response
    };

    let ticket = crate::dashboard_auth::mint_dashboard_pairing_ticket_for_test(auth.as_ref())
        .expect("ticket mints");
    let code = ticket.code.clone();
    let body = format!("{DASHBOARD_PAIRING_CODE_FIELD}={code}");
    let null_origin = send(
        "POST",
        DASHBOARD_PAIR_PATH,
        "origin: null\r\nsec-fetch-site: same-origin\r\ncontent-type: application/x-www-form-urlencoded\r\n",
        &body,
    );
    assert!(
        null_origin.starts_with("HTTP/1.1 403 "),
        "literal Origin:null must be refused: {null_origin}"
    );
    assert!(
        !null_origin.to_ascii_lowercase().contains("set-cookie"),
        "literal Origin:null never mints a session: {null_origin}"
    );
    assert!(
        !null_origin.contains(&code),
        "the refusal never echoes the body code"
    );

    let paired = send(
        "POST",
        DASHBOARD_PAIR_PATH,
        &format!(
            "origin: {audience}\r\nsec-fetch-site: same-origin\r\ncontent-type: application/x-www-form-urlencoded\r\n"
        ),
        &body,
    );
    assert!(
        paired.starts_with("HTTP/1.1 303 "),
        "refusing literal Origin:null must not consume the ticket: {paired}"
    );

    shutdown.store(true, AtomicOrdering::SeqCst);
    let _ = TcpStream::connect(addr);
    handle.join().expect("pairing listener thread joins");
}
