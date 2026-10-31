fn paired_dashboard_json_post(auth: &DashboardAuth, path: &str, body: &Value) -> HttpRequest {
    let ticket = crate::dashboard_auth::mint_dashboard_pairing_ticket_for_test(auth)
        .expect("pairing ticket mints");
    let login = auth
        .exchange_ticket(&ticket.code, auth.audience(), false)
        .expect("dashboard login works");
    let cookie_pair = login
        .session_cookie
        .split(';')
        .next()
        .expect("session cookie pair")
        .to_owned();
    let view = auth
        .session_view(Some(&cookie_pair))
        .expect("dashboard session view works");
    let action_ticket = view
        .action_tickets
        .iter()
        .find(|ticket| ticket.path == path)
        .unwrap_or_else(|| panic!("action ticket exists for {path}"))
        .ticket
        .clone();
    HttpRequest::new(
        "POST",
        path,
        [
            ("host", "127.0.0.1"),
            ("origin", "http://127.0.0.1"),
            ("sec-fetch-site", "same-origin"),
            ("content-type", "application/json"),
            ("accept", "application/json"),
            ("cookie", cookie_pair.as_str()),
            (DASHBOARD_CSRF_HEADER, view.csrf_token.as_str()),
            (DASHBOARD_ACTION_TICKET_HEADER, action_ticket.as_str()),
        ],
        body.to_string().into_bytes(),
    )
    .with_peer_loopback(true)
}
#[test]
fn dashboard_workbench_defaults_disabled_and_is_browser_only_and_tool_scoped() {
    let (auditor, _sink) = operator_auditor();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server_with_dispatch(Arc::new(WorkbenchDispatch {
        calls: Arc::clone(&calls),
    }));
    let dir = dashboard_test_dir("workbench-config-gate");
    let auth =
        Arc::new(DashboardAuth::new(dir, "http://127.0.0.1").expect("dashboard auth builds"));
    let cfg = HttpTransportConfig {
        dashboard_auth: Some(Arc::clone(&auth)),
        operator_auditor: Some(auditor),
        ..Default::default()
    };
    assert!(!cfg.dashboard_workbench, "browser SQL defaults disabled");

    let write_sql = "UPDATE accounts SET status = 'HOLD' WHERE id = 42";
    for (index, (path, tool, arguments)) in [
        (
            "/operator/v1/actions/preview",
            "oracle_preview_sql",
            serde_json::json!({ "sql": write_sql }),
        ),
        (
            "/operator/v1/actions/execute",
            "oracle_query",
            serde_json::json!({ "sql": "SELECT 1 FROM dual", "max_rows": 1 }),
        ),
        (
            "/operator/v1/actions/confirm",
            "oracle_execute",
            serde_json::json!({ "sql": write_sql, "commit": false }),
        ),
        (
            "/operator/v1/actions/execute",
            "oracle_execute",
            serde_json::json!({
                "sql": write_sql,
                "commit": false,
                "confirm": "opaque-preview-grant"
            }),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let response = handle_http_request(
            &server,
            &cfg,
            paired_dashboard_json_post(
                auth.as_ref(),
                path,
                &serde_json::json!({
                    "idempotency_key": format!("disabled-workbench-{index}"),
                    "tool": tool,
                    "arguments": arguments,
                }),
            ),
        );
        assert_eq!(response.status, 403, "browser {tool} must be disabled");
        let body = response_json(&response);
        assert_eq!(
            body["data"]["error"],
            serde_json::json!("dashboard_workbench_disabled")
        );
        assert_eq!(
            body["data"]["configuration"],
            serde_json::json!("http.dashboard_workbench")
        );
        assert_eq!(body["data"]["enabled"], serde_json::json!(false));
    }
    assert_eq!(
        calls.load(AtomicOrdering::SeqCst),
        0,
        "disabled browser workbench requests stop before dispatch"
    );

    for (index, tool) in ["oracle_connection_info", "oracle_list_schemas"]
        .into_iter()
        .enumerate()
    {
        let response = handle_http_request(
            &server,
            &cfg,
            paired_dashboard_json_post(
                auth.as_ref(),
                "/operator/v1/actions/execute",
                &serde_json::json!({
                    "idempotency_key": format!("explorer-unaffected-{index}"),
                    "tool": tool,
                    "arguments": {},
                }),
            ),
        );
        assert_eq!(
            response.status, 200,
            "browser Explorer tool {tool} remains available"
        );
    }

    let non_browser_cfg = HttpTransportConfig {
        operator_auditor: cfg.operator_auditor.clone(),
        ..Default::default()
    };
    let non_browser = handle_http_request(
        &server,
        &non_browser_cfg,
        operator_json_post(
            "/operator/v1/actions/execute",
            &serde_json::json!({
                "idempotency_key": "non-browser-workbench-unaffected",
                "tool": "oracle_query",
                "arguments": { "sql": "SELECT 1 FROM dual", "max_rows": 1 },
            }),
        ),
    );
    assert_eq!(
        non_browser.status, 200,
        "the browser-only switch must not alter non-browser operator clients"
    );
    assert_eq!(calls.load(AtomicOrdering::SeqCst), 3);
}

#[test]
fn enabled_dashboard_workbench_allows_non_ddl_sql_actions() {
    let (auditor, _sink) = operator_auditor();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server_with_dispatch(Arc::new(WorkbenchDispatch {
        calls: Arc::clone(&calls),
    }));
    let dir = dashboard_test_dir("workbench-config-enabled");
    let auth =
        Arc::new(DashboardAuth::new(dir, "http://127.0.0.1").expect("dashboard auth builds"));
    let cfg = HttpTransportConfig {
        dashboard_auth: Some(Arc::clone(&auth)),
        dashboard_workbench: true,
        operator_auditor: Some(auditor),
        ..Default::default()
    };
    let write_sql = "UPDATE accounts SET status = 'HOLD' WHERE id = 42";
    for (index, (path, tool, arguments)) in [
        (
            "/operator/v1/actions/preview",
            "oracle_preview_sql",
            serde_json::json!({ "sql": write_sql }),
        ),
        (
            "/operator/v1/actions/execute",
            "oracle_query",
            serde_json::json!({ "sql": "SELECT 1 FROM dual", "max_rows": 1 }),
        ),
        (
            "/operator/v1/actions/execute",
            "oracle_execute",
            serde_json::json!({
                "sql": write_sql,
                "commit": false,
                "confirm": "opaque-preview-grant"
            }),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let response = handle_http_request(
            &server,
            &cfg,
            paired_dashboard_json_post(
                auth.as_ref(),
                path,
                &serde_json::json!({
                    "idempotency_key": format!("enabled-workbench-{index}"),
                    "tool": tool,
                    "arguments": arguments,
                }),
            ),
        );
        assert_eq!(response.status, 200, "enabled browser {tool} forwards");
    }
    assert_eq!(calls.load(AtomicOrdering::SeqCst), 3);
}

#[test]
fn disabled_dashboard_workbench_blocks_change_proposal_forwarding() {
    let (auditor, _sink) = operator_auditor();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server_with_dispatch(Arc::new(WorkbenchDispatch {
        calls: Arc::clone(&calls),
    }));
    let dir = dashboard_test_dir("workbench-proposal-gate");
    let auth = Arc::new(
        DashboardAuth::new(dir.clone(), "http://127.0.0.1").expect("dashboard auth builds"),
    );
    let proposals = Arc::new(
        crate::change_proposal::ChangeProposalStore::open(dir.join("state"))
            .expect("proposal store"),
    );
    let cfg = HttpTransportConfig {
        dashboard_auth: Some(Arc::clone(&auth)),
        operator_auditor: Some(auditor),
        change_proposals: Some(proposals),
        ..Default::default()
    };
    let draft = handle_http_request(
        &server,
        &cfg,
        paired_dashboard_json_post(
            auth.as_ref(),
            "/operator/v1/change-proposals/draft",
            &serde_json::json!({
                "profile": "prod",
                "author": "human",
                "title": "Read current database time",
                "statements": [{
                    "sql_template": "SELECT CURRENT_TIMESTAMP FROM dual",
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
        paired_dashboard_json_post(
            auth.as_ref(),
            "/operator/v1/change-proposals/apply",
            &serde_json::json!({
                "proposal_id": proposal_id,
                "idempotency_key": "disabled-proposal-apply"
            }),
        ),
    );
    assert_eq!(
        apply.status, 200,
        "proposal route returns its domain envelope"
    );
    let body = response_json(&apply);
    assert_eq!(
        body["data"]["status"],
        serde_json::json!("stopped_on_failure")
    );
    assert_eq!(body["data"]["results"][0]["action_status"], 403);
    assert_eq!(
        body["data"]["results"][0]["action_response"]["data"]["error"],
        serde_json::json!("dashboard_workbench_disabled")
    );
    assert_eq!(
        calls.load(AtomicOrdering::SeqCst),
        0,
        "proposal forwarding must hit the same browser workbench gate"
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
        dashboard_workbench: true,
        operator_auditor: Some(auditor),
        ..Default::default()
    };
    let cases = [
        (
            "oracle_execute",
            serde_json::json!({
                "sql": "ALTER DATABASE DEFAULT EDITION = synthetic_child",
                "confirm": "opaque-preview-grant"
            }),
        ),
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
                serde_json::json!(if arguments
                    .get("sql")
                    .and_then(Value::as_str)
                    .is_some_and(|sql| sql.starts_with("ALTER DATABASE"))
                {
                    "dashboard_operator_only_statement"
                } else {
                    "dashboard_ddl_workbench_disabled"
                }),
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
fn dashboard_edition_flip_requires_decisive_binding_and_current_opt_in() {
    let (auditor, _sink) = operator_auditor();
    let calls = Arc::new(AtomicUsize::new(0));
    let enabled = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let server = server_with_dispatch(Arc::new(EditionDispatch {
        calls: Arc::clone(&calls),
        profile: "synthetic_stage",
        deny: false,
        edition_change_requests: Arc::clone(&enabled),
    }));
    let dir = dashboard_test_dir("browser-edition-flip");
    let store =
        Arc::new(crate::change_proposal::ChangeProposalStore::open(dir.join("state")).unwrap());
    let reviewed = crate::change_proposal::test_reviewed_edition_request(
        &store,
        "synthetic_stage",
        "SYNTHETIC_CHILD",
        "SYNTHETIC_BASE",
    );
    let auth = Arc::new(DashboardAuth::new(dir, "http://127.0.0.1").unwrap());
    let cfg = HttpTransportConfig {
        dashboard_auth: Some(Arc::clone(&auth)),
        operator_auditor: Some(auditor),
        change_proposals: Some(Arc::clone(&store)),
        // Edition flips have their own policy; the general SQL workbench is off.
        dashboard_workbench: false,
        ..Default::default()
    };
    let operator_cfg = HttpTransportConfig {
        dashboard_auth: None,
        ..cfg.clone()
    };
    for path in [
        "/operator/v1/edition-proposals/merge",
        "/operator/v1/edition-proposals/rollback",
    ] {
        for field in ["sql", "ddl", "source_code", "edition", "stored_verdict"] {
            let mut body = serde_json::json!({"proposal_id": reviewed.proposal_id});
            body[field] = serde_json::json!("ALTER DATABASE DEFAULT EDITION = other");
            let response = handle_http_request(
                &server,
                &cfg,
                paired_dashboard_json_post(&auth, path, &body),
            );
            assert_eq!(response.status, 400, "{path} rejects {field}");
        }
        let preview = handle_http_request(
            &server,
            &operator_cfg,
            operator_json_post(
                path,
                &serde_json::json!({"proposal_id": reviewed.proposal_id}),
            ),
        );
        assert_eq!(preview.status, 200, "{}", response_json(&preview));
        let token = response_json(&preview)["data"]["confirmation"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(response_json(&preview)["data"]["required_level"], "ADMIN");
        let body = serde_json::json!({"proposal_id": reviewed.proposal_id, "confirm": token});
        let before = calls.load(AtomicOrdering::SeqCst);
        for browser_body in [
            &serde_json::json!({"proposal_id": reviewed.proposal_id}),
            &body,
        ] {
            let refused = handle_http_request(
                &server,
                &cfg,
                paired_dashboard_json_post(&auth, path, browser_body),
            );
            assert_eq!(refused.status, 409);
            assert_eq!(
                response_json(&refused)["data"]["error"],
                "edition_decisive_binding_required"
            );
            assert_eq!(calls.load(AtomicOrdering::SeqCst), before);
        }
        enabled.store(false, AtomicOrdering::SeqCst);
        let refused = handle_http_request(
            &server,
            &cfg,
            paired_dashboard_json_post(&auth, path, &body),
        );
        assert_eq!(refused.status, 409);
        assert_eq!(
            response_json(&refused)["data"]["error"],
            "edition_change_requests_disabled"
        );
        assert_eq!(calls.load(AtomicOrdering::SeqCst), before);
        let refused_operator =
            handle_http_request(&server, &operator_cfg, operator_json_post(path, &body));
        assert_eq!(refused_operator.status, 409);
        assert_eq!(
            response_json(&refused_operator)["data"]["error"],
            "edition_change_requests_disabled"
        );
        assert_eq!(calls.load(AtomicOrdering::SeqCst), before);
        // The same persisted request is retained. A fresh current opt-in allows
        // its still-unconsumed, revision-bound ADMIN confirmation.
        enabled.store(true, AtomicOrdering::SeqCst);
        let applied = handle_http_request(&server, &operator_cfg, operator_json_post(path, &body));
        assert_eq!(applied.status, 200, "{}", response_json(&applied));
        assert_eq!(response_json(&applied)["data"]["status"], "applied");
        let replay = handle_http_request(&server, &operator_cfg, operator_json_post(path, &body));
        assert_eq!(replay.status, 409);
        assert_eq!(
            response_json(&replay)["data"]["error"],
            "edition_default_confirmation_mismatch"
        );
        assert_eq!(calls.load(AtomicOrdering::SeqCst), before + 1);
    }
    assert_eq!(calls.load(AtomicOrdering::SeqCst), 2);
    assert_eq!(
        store
            .edition_proposal(&reviewed.proposal_id)
            .unwrap()
            .proposal_revision,
        reviewed.proposal_revision
    );
}

#[test]
fn operator_edition_flip_refuses_confirmation_after_review_revision_changes() {
    let (auditor, _sink) = operator_auditor();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = server_with_dispatch(Arc::new(EditionDispatch {
        edition_change_requests: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        calls: Arc::clone(&calls),
        profile: "synthetic_stage",
        deny: false,
    }));
    let dir = dashboard_test_dir("browser-edition-review-drift");
    let store =
        Arc::new(crate::change_proposal::ChangeProposalStore::open(dir.join("state")).unwrap());
    let mut reviewed = crate::change_proposal::test_reviewed_edition_request(
        &store,
        "synthetic_stage",
        "SYNTHETIC_CHILD",
        "SYNTHETIC_BASE",
    );
    let cfg = HttpTransportConfig {
        operator_auditor: Some(auditor),
        change_proposals: Some(Arc::clone(&store)),
        ..Default::default()
    };
    for path in [
        "/operator/v1/edition-proposals/merge",
        "/operator/v1/edition-proposals/rollback",
    ] {
        let preview = handle_http_request(
            &server,
            &cfg,
            operator_json_post(
                path,
                &serde_json::json!({"proposal_id": reviewed.proposal_id}),
            ),
        );
        assert_eq!(preview.status, 200);
        let token = response_json(&preview)["data"]["confirmation"]
            .as_str()
            .unwrap()
            .to_owned();
        for state in [
            crate::change_proposal::ChangeRequestState::Staged,
            crate::change_proposal::ChangeRequestState::Verified,
            crate::change_proposal::ChangeRequestState::Reviewing,
        ] {
            reviewed = store
                .transition_edition_proposal(crate::change_proposal::test_edition_transition(
                    &reviewed,
                    state,
                    &format!("{path}-{state:?}"),
                ))
                .unwrap();
        }
        let response = handle_http_request(
            &server,
            &cfg,
            operator_json_post(
                path,
                &serde_json::json!({"proposal_id": reviewed.proposal_id, "confirm": token}),
            ),
        );
        assert_eq!(response.status, 409);
        assert_eq!(
            response_json(&response)["data"]["error"],
            "edition_default_confirmation_mismatch"
        );
        assert_eq!(calls.load(AtomicOrdering::SeqCst), 0);
    }
}
