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

fn oauth_claims(scope: &str) -> Value {
    serde_json::json!({
        "iss": "https://idp.example",
        "aud": "https://oraclemcp.example/mcp",
        "exp": 9_999_999_999i64,
        "sub": "test-subject",
        "client_id": "test-client",
        "iat": 1_000_000_000i64,
        "jti": "test-token",
        "scope": scope,
    })
}

fn jwt_with_type_and_claims(typ: Option<&str>, claims: Value) -> String {
    let mut header = serde_json::json!({ "alg": "HS256" });
    if let Some(typ) = typ {
        header["typ"] = serde_json::json!(typ);
    }
    let header = b64url(serde_json::to_string(&header).unwrap().as_bytes());
    let payload = b64url(serde_json::to_string(&claims).unwrap().as_bytes());
    format!("{header}.{payload}.{}", b64url(b"sig"))
}

fn jwt_with_scope(scope: &str) -> String {
    jwt_with_type_and_claims(Some("at+jwt"), oauth_claims(scope))
}

#[test]
fn oauth_principal_distinguishes_clients_that_share_a_subject() {
    // QA100 .56: the principal key must compose the issuer with EVERY present
    // identity claim, not just the first. Two different OAuth clients (distinct
    // client_id/azp) acting for the same subject must map to distinct principals,
    // or one client's session/revocation would leak onto the other.
    let token = |sub: &str, client_id: Option<&str>, azp: Option<&str>| {
        let header = b64url(br#"{"alg":"HS256","typ":"at+jwt"}"#);
        let mut claims = serde_json::json!({
            "iss": "https://idp.example",
            "aud": "https://oraclemcp.example/mcp",
            "exp": 9_999_999_999i64,
            "sub": sub,
        });
        if let Some(client_id) = client_id {
            claims["client_id"] = serde_json::json!(client_id);
        }
        if let Some(azp) = azp {
            claims["azp"] = serde_json::json!(azp);
        }
        let payload = b64url(serde_json::to_string(&claims).unwrap().as_bytes());
        format!("{header}.{payload}.{}", b64url(b"sig"))
    };
    let key = |t: &str| oauth_principal_key_from_validated_token(t);

    assert_ne!(
        key(&token("user-1", Some("client-a"), None)),
        key(&token("user-1", Some("client-b"), None)),
        "same subject via different client_id must not collapse to one principal"
    );
    assert_ne!(
        key(&token("user-1", None, Some("app-a"))),
        key(&token("user-1", None, Some("app-b"))),
        "same subject via different azp must not collapse to one principal"
    );
    assert_eq!(
        key(&token("user-1", Some("client-a"), Some("app-a"))),
        key(&token("user-1", Some("client-a"), Some("app-a"))),
        "identical issuer + subject + client + azp is one stable principal"
    );
    assert_ne!(
        key(&token("user-1", Some("client-a"), None)),
        key(&token("user-2", Some("client-a"), None)),
        "different subjects on the same client stay distinct"
    );
}

#[test]
fn oauth_principal_is_stable_across_refresh_only_with_a_canonical_subject() {
    let token = |subject: Option<&str>, generation: u64| {
        let header = b64url(br#"{"alg":"HS256","typ":"at+jwt"}"#);
        let mut claims = serde_json::json!({
            "iss": "https://idp.example",
            "aud": "https://oraclemcp.example/mcp",
            "exp": 9_999_999_999i64,
            "scope": "oracle:read",
            "jti": format!("refresh-{generation}"),
        });
        if let Some(subject) = subject {
            claims["sub"] = serde_json::json!(subject);
        }
        let payload = b64url(serde_json::to_string(&claims).unwrap().as_bytes());
        format!(
            "{header}.{payload}.{}",
            b64url(format!("sig-{generation}").as_bytes())
        )
    };

    let first = token(Some("subject-a"), 1);
    let refreshed = token(Some("subject-a"), 2);
    assert_ne!(first, refreshed);
    assert_eq!(
        oauth_principal_key_from_validated_token(&first),
        oauth_principal_key_from_validated_token(&refreshed),
        "refresh changes token material, not canonical issuer+subject ownership"
    );
    assert_ne!(
        oauth_principal_key_from_validated_token(&first),
        oauth_principal_key_from_validated_token(&token(Some("subject-b"), 3)),
        "different subjects must never share export ownership"
    );
    assert_ne!(
        oauth_principal_key_from_validated_token(&token(None, 4)),
        oauth_principal_key_from_validated_token(&token(None, 5)),
        "tokens without a stable subject fail safely as token-local principals"
    );
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
            _min_generation: Option<u64>,
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
    let auth = Arc::new(
        DashboardAuth::new(dir.clone(), "http://127.0.0.1").expect("dashboard auth builds"),
    );
    let cfg = HttpTransportConfig {
        dashboard_auth: Some(Arc::clone(&auth)),
        operator_auditor: Some(auditor),
        client_credentials: Some(Arc::clone(&store)),
        session_store: Some(Arc::clone(&session_store)),
        result_store: Some(Arc::clone(&result_store)),
        session_lifecycle: Some(lifecycle.clone()),
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

    store.fail_next_persist(crate::client_credentials::CredentialPersistFault::BeforeCommit);
    let failed_rotate = handle_http_request(
        &test_server(),
        &cfg,
        dashboard_post(
            "/operator/v1/client-credentials/rotate",
            &rotate_ticket,
            serde_json::json!({ "client_id": read_client_id }),
        ),
    );
    assert_eq!(failed_rotate.status, 500);
    assert!(
        lifecycle
            .closed
            .lock()
            .expect("test lifecycle mutex")
            .is_empty(),
        "a failed durable mutation must not close sessions for an unpublished generation"
    );
    assert_eq!(
        session_store.principal_for("read-session").as_deref(),
        Some(read_principal.as_str())
    );
    assert!(
        store.authenticate_bearer(&read_bearer, None).is_ok(),
        "the old bearer remains authoritative after a pre-write failure"
    );

    store.fail_next_persist(crate::client_credentials::CredentialPersistFault::AfterVisibleCommit);
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
    assert_eq!(
        rotate_body["data"]["durability"],
        serde_json::json!("reconciled_after_write_error")
    );
    assert_eq!(
        rotate_body["data"]["closed_principal"]["durability"],
        serde_json::json!("reconciled_after_write_error")
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
    assert_eq!(
        revoke_body["data"]["closed_principal"]["durability"],
        serde_json::json!("durable")
    );
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
    let auth = Arc::new(
        DashboardAuth::new(dir.clone(), "http://127.0.0.1").expect("dashboard auth builds"),
    );
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

    let ticket = crate::dashboard_auth::mint_dashboard_pairing_ticket_for_test(auth.as_ref())
        .expect("ticket mints");
    let login = auth
        .exchange_ticket(ticket_from_pairing_url(&ticket.url), auth.audience(), false)
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
    assert_operator_audit_pair(&records, AuditDecision::Blocked, AuditOutcome::Failed);
    let (_, stable_id) = principal_key.split_once(':').expect("principal key");
    assert_eq!(
        records[0].subject,
        AuditSubject::new("oauth", stable_id).with_authn_method("oauth")
    );
    assert_eq!(records[0].tool, "operator_api");
    assert_eq!(
        records[0].sql_preview,
        "<sql text redacted; see sql_sha256>"
    );
    assert_eq!(
        records[0].sql_sha256,
        oraclemcp_audit::sha256_hex(b"GET /operator/v1/sessions")
    );
}

// ===================================================================
// K10 — streaming query results over SSE (the streaming assembly)
// ===================================================================
