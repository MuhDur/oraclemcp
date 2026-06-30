use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::thread;
use std::time::Duration;

use asupersync::Cx;
use oraclemcp::dispatch::OracleDispatcher;
use oraclemcp::registry::{capabilities, tool_registry};
use oraclemcp_auth::{ResourceServerConfig, SignatureVerifier};
use oraclemcp_core::http::{
    HEALTHZ_PATH, PROTECTED_RESOURCE_METADATA_PATH, SinglePrincipalGuard, serve_http_until,
};
use oraclemcp_core::{
    DispatchContext, DispatchFuture, HttpTransportConfig, LaneDispatchFactory, LaneRuntime,
    MCP_PATH, OAuthEnforcement, ObservabilityState, OracleMcpServer, StatefulLaneDispatch,
    ToolDispatch,
};
use oraclemcp_db::{
    DbError, OracleBackend, OracleBind, OracleConnection, OracleConnectionInfo, OracleRow,
};
use oraclemcp_guard::{OperatingLevel, SessionLevelState};
use oraclemcp_telemetry::HealthState;
use serde_json::{Value, json};

struct NoExecMock;

#[async_trait::async_trait(?Send)]
impl OracleConnection for NoExecMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }

    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo::default())
    }

    async fn query_rows(
        &self,
        _cx: &Cx,
        _sql: &str,
        _b: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        Ok(Vec::new())
    }

    async fn execute(&self, _cx: &Cx, _sql: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
        panic!("read-scoped HTTP test must not reach DB execution")
    }

    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }

    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

struct AcceptHs256;

impl SignatureVerifier for AcceptHs256 {
    fn verify(&self, alg: &str, _signing_input: &[u8], _signature: &[u8]) -> bool {
        alg == "HS256"
    }
}

struct BlockingToolDispatch {
    entered: std_mpsc::Sender<()>,
    release: std::sync::Mutex<std_mpsc::Receiver<()>>,
}

impl ToolDispatch for BlockingToolDispatch {
    fn dispatch<'a>(
        &'a self,
        _cx: &'a Cx,
        _context: DispatchContext<'a>,
        _name: &'a str,
        _args: Value,
    ) -> DispatchFuture<'a> {
        Box::pin(async move {
            self.entered
                .send(())
                .expect("test waits until lane dispatch is entered");
            self.release
                .lock()
                .expect("release mutex not poisoned")
                .recv()
                .expect("test releases blocked lane dispatch");
            Ok(json!({ "ok": true }))
        })
    }
}

struct HttpHarness {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for HttpHarness {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            handle.join().expect("HTTP test server joins cleanly");
        }
    }
}

fn b64url(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
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

fn jwt_with_scope(scope: &str) -> String {
    jwt_with_scope_and_subject(scope, None)
}

fn jwt_with_scope_and_subject(scope: &str, subject: Option<&str>) -> String {
    let header = b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
    let mut claims = json!({
        "iss": "https://idp.example",
        "aud": "https://oraclemcp.example/mcp",
        "exp": 9_999_999_999i64,
        "scope": scope,
    });
    if let Some(subject) = subject {
        claims["sub"] = json!(subject);
    }
    let payload = b64url(serde_json::to_string(&claims).unwrap().as_bytes());
    format!("{header}.{payload}.{}", b64url(b"sig"))
}

fn server() -> OracleMcpServer {
    server_with_max_level(OperatingLevel::ReadWrite)
}

fn server_with_max_level(max_level: OperatingLevel) -> OracleMcpServer {
    let registry = tool_registry();
    OracleMcpServer::new(
        env!("CARGO_PKG_VERSION"),
        registry,
        capabilities(env!("CARGO_PKG_VERSION"), true, false),
        Arc::new(OracleDispatcher::new_with_profile_level(
            Box::new(NoExecMock),
            Some("http-oauth-e2e".to_owned()),
            SessionLevelState::new(max_level, false),
        )),
    )
}

fn lane_backed_blocking_server(
    entered: std_mpsc::Sender<()>,
    release: std_mpsc::Receiver<()>,
) -> OracleMcpServer {
    let registry = tool_registry();
    let lane = LaneRuntime::spawn(
        "http-responsive-test",
        Arc::new(BlockingToolDispatch {
            entered,
            release: std::sync::Mutex::new(release),
        }),
        1,
    );
    OracleMcpServer::new(
        env!("CARGO_PKG_VERSION"),
        registry,
        capabilities(env!("CARGO_PKG_VERSION"), true, false),
        Arc::new(lane),
    )
}

fn per_lane_dispatcher_server(max_level: OperatingLevel) -> OracleMcpServer {
    let registry = tool_registry();
    let factory: Arc<LaneDispatchFactory> = Arc::new(move |_cx, _lane_context| {
        Box::pin(async move {
            Ok(Arc::new(OracleDispatcher::new_with_profile_level(
                Box::new(NoExecMock),
                Some("http-lane-e2e".to_owned()),
                SessionLevelState::new(max_level, false),
            )) as Arc<dyn ToolDispatch>)
        })
    });
    OracleMcpServer::new(
        env!("CARGO_PKG_VERSION"),
        registry,
        capabilities(env!("CARGO_PKG_VERSION"), true, false),
        Arc::new(StatefulLaneDispatch::with_dispatch_factory(factory, None)),
    )
}

fn oauth_config(required_scopes: Vec<String>) -> HttpTransportConfig {
    let resource = "https://oraclemcp.example/mcp".to_owned();
    let rs = ResourceServerConfig {
        resource,
        allowed_issuers: vec!["https://idp.example".to_owned()],
        authorization_servers: vec!["https://idp.example".to_owned()],
        required_scopes,
    };
    HttpTransportConfig {
        json_response: true,
        resource_metadata: Some(rs.protected_resource_metadata()),
        oauth: Some(Arc::new(OAuthEnforcement {
            config: rs,
            verifier: Arc::new(AcceptHs256),
            metadata_url: "https://oraclemcp.example/.well-known/oauth-protected-resource"
                .to_owned(),
        })),
        ..Default::default()
    }
}

fn spawn_http(config: HttpTransportConfig) -> HttpHarness {
    spawn_http_with_server(config, server())
}

fn spawn_http_with_max_level(
    config: HttpTransportConfig,
    max_level: OperatingLevel,
) -> HttpHarness {
    spawn_http_with_server(config, server_with_max_level(max_level))
}

fn spawn_http_with_server(config: HttpTransportConfig, server: OracleMcpServer) -> HttpHarness {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback test listener");
    let addr = listener.local_addr().expect("local addr");
    let shutdown = Arc::new(AtomicBool::new(false));
    let thread_shutdown = Arc::clone(&shutdown);
    let handle = thread::spawn(move || {
        serve_http_until(listener, server, &config, thread_shutdown)
            .expect("HTTP server exits cleanly");
    });
    HttpHarness {
        addr,
        shutdown,
        handle: Some(handle),
    }
}

fn post_tool(body: &Value, token: Option<&str>) -> (u16, Vec<(String, String)>, Value) {
    let harness = spawn_http(oauth_config(Vec::new()));
    request_json(
        harness.addr,
        "POST",
        MCP_PATH,
        token,
        Some(body.to_string().as_bytes()),
    )
}

fn request_json(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&[u8]>,
) -> (u16, Vec<(String, String)>, Value) {
    request_json_with_extra_headers(addr, method, path, token, &[], body)
}

fn request_json_with_extra_headers(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
    extra_headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> (u16, Vec<(String, String)>, Value) {
    let body = body.unwrap_or_default();
    let auth = token
        .map(|token| format!("authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    let extra_headers = extra_headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect::<String>();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-type: application/json\r\naccept: application/json, text/event-stream\r\n{auth}{extra_headers}content-length: {}\r\n\r\n",
        body.len()
    );
    let mut stream = TcpStream::connect(addr).expect("connect to HTTP test server");
    stream.write_all(request.as_bytes()).expect("write headers");
    stream.write_all(body).expect("write body");
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("finish request");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).expect("read response");
    let raw = String::from_utf8(raw).expect("HTTP response is UTF-8");
    let (head, body) = raw.split_once("\r\n\r\n").expect("HTTP response shape");
    let mut lines = head.lines();
    let status_line = lines.next().expect("status line");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse::<u16>()
        .expect("numeric status");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    let body = if body.is_empty() {
        Value::Null
    } else if body.starts_with('{') {
        serde_json::from_str(body).expect("JSON response body")
    } else {
        json!(body)
    };
    (status, headers, body)
}

fn tool_call(name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments
        }
    })
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.as_str())
}

fn sse_last_json(body: &Value) -> Value {
    let body = body.as_str().expect("stateful response is SSE text");
    body.lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .filter(|data| *data != "null")
        .filter_map(|data| serde_json::from_str::<Value>(data).ok())
        .next_back()
        .expect("SSE response carries a JSON event")
}

fn stateful_initialize(addr: SocketAddr, token: &str, client_name: &str) -> String {
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": client_name, "version": "1.0" }
        }
    });
    let (status, headers, _body) = request_json(
        addr,
        "POST",
        MCP_PATH,
        Some(token),
        Some(initialize.to_string().as_bytes()),
    );
    assert_eq!(status, 200);
    header(&headers, "mcp-session-id")
        .expect("stateful initialize returns mcp-session-id")
        .to_owned()
}

fn stateful_tool_call(
    addr: SocketAddr,
    token: &str,
    session_id: &str,
    name: &str,
    arguments: Value,
) -> Value {
    let (status, _headers, body) = request_json_with_extra_headers(
        addr,
        "POST",
        MCP_PATH,
        Some(token),
        &[
            ("mcp-session-id", session_id),
            ("mcp-protocol-version", "2025-11-25"),
        ],
        Some(tool_call(name, arguments).to_string().as_bytes()),
    );
    assert_eq!(status, 200);
    sse_last_json(&body)
}

#[test]
fn binary_http_oauth_rejects_missing_invalid_and_insufficient_tokens() {
    let harness = spawn_http(oauth_config(Vec::new()));
    let (status, headers, body) = request_json(harness.addr, "POST", MCP_PATH, None, Some(b"{}"));
    assert_eq!(status, 401);
    assert_eq!(body, json!("unauthorized"));
    assert_eq!(
        header(&headers, "www-authenticate"),
        Some(
            "Bearer resource_metadata=\"https://oraclemcp.example/.well-known/oauth-protected-resource\""
        )
    );

    let (status, headers, body) = request_json(
        harness.addr,
        "POST",
        MCP_PATH,
        Some("not.a.jwt"),
        Some(b"{}"),
    );
    assert_eq!(status, 401);
    assert_eq!(body, json!("unauthorized"));
    assert_eq!(
        header(&headers, "www-authenticate"),
        Some(
            "Bearer resource_metadata=\"https://oraclemcp.example/.well-known/oauth-protected-resource\", error=\"invalid_token\""
        )
    );
    assert!(
        !headers.iter().any(|(_, value)| value.contains("not.a.jwt")),
        "bad bearer token must not be echoed in headers"
    );

    let harness = spawn_http(oauth_config(vec!["oracle:write".to_owned()]));
    let (status, headers, body) = request_json(
        harness.addr,
        "POST",
        MCP_PATH,
        Some(&jwt_with_scope("oracle:read")),
        Some(b"{}"),
    );
    assert_eq!(status, 403);
    assert_eq!(body, json!("forbidden"));
    assert_eq!(
        header(&headers, "www-authenticate"),
        Some(
            "Bearer resource_metadata=\"https://oraclemcp.example/.well-known/oauth-protected-resource\", error=\"insufficient_scope\""
        )
    );
}

#[test]
fn binary_http_oauth_serves_metadata_and_applies_scope_ceilings() {
    let harness = spawn_http(oauth_config(Vec::new()));
    let (status, _headers, metadata) = request_json(
        harness.addr,
        "GET",
        PROTECTED_RESOURCE_METADATA_PATH,
        None,
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(metadata["resource"], json!("https://oraclemcp.example/mcp"));
    assert_eq!(
        metadata["authorization_servers"],
        json!(["https://idp.example"])
    );
    assert_eq!(metadata["bearer_methods_supported"], json!(["header"]));
    assert_eq!(
        metadata["scopes_supported"],
        json!(["oracle:read", "oracle:write", "oracle:ddl", "oracle:admin"])
    );

    let update = tool_call(
        "oracle_preview_sql",
        json!({ "sql": "UPDATE employees SET salary = salary" }),
    );
    let (status, _headers, read_scoped) = post_tool(&update, Some(&jwt_with_scope("oracle:read")));
    assert_eq!(status, 200);
    let blocked = &read_scoped["result"]["structuredContent"];
    assert_eq!(blocked["gate_decision"], json!("blocked"));
    assert_eq!(blocked["blocked_reason"]["required"], json!("READ_WRITE"));
    assert_eq!(blocked["blocked_reason"]["ceiling"], json!("READ_ONLY"));

    let (status, _headers, write_scoped) =
        post_tool(&update, Some(&jwt_with_scope("oracle:admin")));
    assert_eq!(status, 200);
    let write_gate = &write_scoped["result"]["structuredContent"];
    assert_eq!(write_gate["gate_decision"], json!("require_step_up"));
    assert_eq!(write_gate["profile_ceiling"], json!("READ_WRITE"));

    let ddl = tool_call(
        "oracle_preview_sql",
        json!({ "sql": "CREATE TABLE scoped_test (id NUMBER)" }),
    );
    let (status, _headers, admin_scoped) = post_tool(&ddl, Some(&jwt_with_scope("oracle:admin")));
    assert_eq!(status, 200);
    let ddl_gate = &admin_scoped["result"]["structuredContent"];
    assert_eq!(ddl_gate["gate_decision"], json!("blocked"));
    assert_eq!(ddl_gate["blocked_reason"]["required"], json!("DDL"));
    assert_eq!(ddl_gate["blocked_reason"]["ceiling"], json!("READ_WRITE"));

    let protected = spawn_http_with_max_level(oauth_config(Vec::new()), OperatingLevel::ReadOnly);
    let (status, _headers, protected_scoped) = request_json(
        protected.addr,
        "POST",
        MCP_PATH,
        Some(&jwt_with_scope("oracle:admin")),
        Some(update.to_string().as_bytes()),
    );
    assert_eq!(status, 200);
    let protected_gate = &protected_scoped["result"]["structuredContent"];
    assert_eq!(protected_gate["gate_decision"], json!("blocked"));
    assert_eq!(
        protected_gate["blocked_reason"]["required"],
        json!("READ_WRITE")
    );
    assert_eq!(
        protected_gate["blocked_reason"]["ceiling"],
        json!("READ_ONLY")
    );
}

#[test]
fn binary_http_single_principal_guard_rejects_second_oauth_subject_pre_lane() {
    let mut config = oauth_config(Vec::new());
    config.single_principal_guard = Some(SinglePrincipalGuard::new());
    let harness = spawn_http(config);
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "n8-pre-lane", "version": "1.0" }
        }
    });

    let agent_a_read = jwt_with_scope_and_subject("oracle:read", Some("agent-a"));
    let (status, _headers, _body) = request_json(
        harness.addr,
        "POST",
        MCP_PATH,
        Some(&agent_a_read),
        Some(initialize.to_string().as_bytes()),
    );
    assert_eq!(status, 200);

    let agent_a_admin = jwt_with_scope_and_subject("oracle:admin", Some("agent-a"));
    let (status, _headers, _body) = request_json(
        harness.addr,
        "POST",
        MCP_PATH,
        Some(&agent_a_admin),
        Some(initialize.to_string().as_bytes()),
    );
    assert_eq!(
        status, 200,
        "the same principal may refresh/change scopes without opening a second lane"
    );

    let agent_b = jwt_with_scope_and_subject("oracle:read", Some("agent-b"));
    let (status, headers, body) = request_json(
        harness.addr,
        "POST",
        MCP_PATH,
        Some(&agent_b),
        Some(initialize.to_string().as_bytes()),
    );
    assert_eq!(status, 409);
    assert_eq!(body["error"], json!("single_principal_active"));
    assert!(
        !headers
            .iter()
            .any(|(_, value)| value.contains(&agent_b) || value.contains("agent-b")),
        "rejection headers must not leak the second token or subject"
    );
    assert!(
        !body.to_string().contains("agent-b"),
        "rejection body must not leak the second subject"
    );
}

#[test]
fn stateful_http_lanes_keep_operating_level_isolated_per_session_and_subject() {
    let mut config = oauth_config(Vec::new());
    config.stateful = true;
    config.single_principal_guard = None;
    let harness = spawn_http_with_server(
        config,
        per_lane_dispatcher_server(OperatingLevel::ReadWrite),
    );
    let agent_a_admin = jwt_with_scope_and_subject("oracle:admin", Some("agent-a"));
    let agent_a_read = jwt_with_scope_and_subject("oracle:read", Some("agent-a"));
    let agent_b_admin = jwt_with_scope_and_subject("oracle:admin", Some("agent-b"));
    let session_a = stateful_initialize(harness.addr, &agent_a_admin, "n2-agent-a");
    let session_b = stateful_initialize(harness.addr, &agent_b_admin, "n2-agent-b");

    let preview = stateful_tool_call(
        harness.addr,
        &agent_a_admin,
        &session_a,
        "oracle_set_session_level",
        json!({ "level": "READ_WRITE", "ttl_seconds": 60 }),
    );
    let confirm = preview["result"]["structuredContent"]["confirmation"]["confirm"]
        .as_str()
        .expect("preview returns an elevation confirmation token")
        .to_owned();
    let applied = stateful_tool_call(
        harness.addr,
        &agent_a_admin,
        &session_a,
        "oracle_set_session_level",
        json!({
            "level": "READ_WRITE",
            "ttl_seconds": 60,
            "execute": true,
            "token": confirm,
        }),
    );
    assert_eq!(
        applied["result"]["structuredContent"]["session"]["current_level"],
        json!("READ_WRITE")
    );

    let sibling = stateful_tool_call(
        harness.addr,
        &agent_b_admin,
        &session_b,
        "oracle_set_session_level",
        json!({ "action": "status" }),
    );
    assert_eq!(
        sibling["result"]["structuredContent"]["session"]["current_level"],
        json!("READ_ONLY"),
        "agent B's lane must not inherit agent A's elevation"
    );

    let narrowed = stateful_tool_call(
        harness.addr,
        &agent_a_read,
        &session_a,
        "oracle_set_session_level",
        json!({ "action": "status" }),
    );
    assert_eq!(
        narrowed["result"]["structuredContent"]["session"]["current_level"],
        json!("READ_ONLY"),
        "a read-scoped request sees a lowered effective level"
    );

    let restored = stateful_tool_call(
        harness.addr,
        &agent_a_admin,
        &session_a,
        "oracle_set_session_level",
        json!({ "action": "status" }),
    );
    assert_eq!(
        restored["result"]["structuredContent"]["session"]["current_level"],
        json!("READ_WRITE"),
        "OAuth scope narrowing must not permanently lower the lane state"
    );
}

#[test]
fn binary_http_transport_responsive_while_lane_blocked_in_db() {
    let (entered_tx, entered_rx) = std_mpsc::channel();
    let (release_tx, release_rx) = std_mpsc::channel();
    let config = HttpTransportConfig {
        json_response: true,
        observability: ObservabilityState {
            health: Some(HealthState::new(env!("CARGO_PKG_VERSION"))),
            ..Default::default()
        },
        ..Default::default()
    };
    let harness =
        spawn_http_with_server(config, lane_backed_blocking_server(entered_tx, release_rx));

    let blocked_addr = harness.addr;
    let blocked_call = thread::spawn(move || {
        request_json(
            blocked_addr,
            "POST",
            MCP_PATH,
            None,
            Some(
                tool_call("oracle_connection_info", json!({}))
                    .to_string()
                    .as_bytes(),
            ),
        )
    });
    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("lane-backed tool call reached the blocked dispatcher");

    let health = request_json(harness.addr, "GET", HEALTHZ_PATH, None, None);
    release_tx.send(()).expect("release blocked tool call");
    let blocked = blocked_call
        .join()
        .expect("blocked HTTP request thread joined");

    assert_eq!(health.0, 200, "healthz responds while the lane is blocked");
    assert_eq!(health.2["live"], json!(true));
    assert_eq!(blocked.0, 200);
    assert_eq!(
        blocked.2["result"]["structuredContent"],
        json!({ "ok": true })
    );
}

#[test]
fn binary_http_rejects_bad_origin_and_forged_stateful_sessions() {
    let mut config = oauth_config(Vec::new());
    config.stateful = true;
    config.allowed_origins = vec!["https://app.example".to_owned()];
    let harness = spawn_http(config);
    let token = jwt_with_scope_and_subject("oracle:read", Some("agent-a"));
    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "http-origin-session-e2e", "version": "1.0" }
        }
    });

    let (status, _headers, body) = request_json_with_extra_headers(
        harness.addr,
        "POST",
        MCP_PATH,
        Some(&token),
        &[("origin", "https://evil.example")],
        Some(initialize.to_string().as_bytes()),
    );
    assert_eq!(status, 403);
    assert_eq!(body, json!("Forbidden: Origin header is not allowed"));

    let (status, headers, body) = request_json_with_extra_headers(
        harness.addr,
        "POST",
        MCP_PATH,
        Some(&token),
        &[("origin", "https://app.example")],
        Some(initialize.to_string().as_bytes()),
    );
    assert_eq!(status, 200);
    let session_id = header(&headers, "mcp-session-id")
        .expect("stateful initialize returns mcp-session-id")
        .to_owned();
    assert!(
        body.as_str()
            .is_some_and(|body| body.contains("\"protocolVersion\":\"2025-11-25\"")),
        "stateful initialize returns an SSE JSON-RPC response: {body}"
    );

    let tools_list = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    });
    let (status, _headers, body) = request_json_with_extra_headers(
        harness.addr,
        "POST",
        MCP_PATH,
        Some(&token),
        &[
            ("origin", "https://app.example"),
            ("mcp-session-id", &session_id),
            ("mcp-protocol-version", "2025-11-25"),
        ],
        Some(tools_list.to_string().as_bytes()),
    );
    assert_eq!(status, 200);
    assert!(
        body.as_str().is_some_and(|body| body.contains("\"tools\"")),
        "stateful tools/list request is admitted and streamed: {body}"
    );

    let agent_b = jwt_with_scope_and_subject("oracle:read", Some("agent-b"));
    let (status, _headers, body) = request_json_with_extra_headers(
        harness.addr,
        "POST",
        MCP_PATH,
        Some(&agent_b),
        &[
            ("origin", "https://app.example"),
            ("mcp-session-id", &session_id),
            ("mcp-protocol-version", "2025-11-25"),
        ],
        Some(tools_list.to_string().as_bytes()),
    );
    assert_eq!(status, 403);
    assert_eq!(body, json!("mcp-session-id is bound to another principal"));
    assert!(
        !body.to_string().contains("agent-b"),
        "session owner rejection must not leak the replaying subject"
    );

    let (status, _headers, body) = request_json_with_extra_headers(
        harness.addr,
        "POST",
        MCP_PATH,
        Some(&token),
        &[
            ("origin", "https://app.example"),
            ("mcp-session-id", "00000000-0000-4000-8000-999999999999"),
            ("mcp-protocol-version", "2025-11-25"),
        ],
        Some(tools_list.to_string().as_bytes()),
    );
    assert_eq!(status, 404);
    assert_eq!(body, json!("Unknown mcp-session-id"));
}
