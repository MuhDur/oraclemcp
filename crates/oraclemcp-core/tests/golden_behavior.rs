//! Golden behavior harness for the native HTTP and stdio transport surface.
//!
//! These tests intentionally compare observable protocol responses against
//! reviewed fixtures under `tests/golden/`. The fixtures are synthetic and
//! contain no real credentials or business data.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use asupersync::{Cx, Outcome};
use oraclemcp_auth::{ResourceServerConfig, SignatureVerifier};
use oraclemcp_core::OracleMcpServer;
use oraclemcp_core::capabilities::{CapabilitiesReport, FeatureTiers};
use oraclemcp_core::http::{
    HttpRequest, HttpResponse, HttpSessionStore, HttpTransportConfig, MCP_PATH, OAuthEnforcement,
    PROTECTED_RESOURCE_METADATA_PATH, handle_http_request, serve_http_until,
};
use oraclemcp_core::server::{DispatchContext, DispatchFuture, ToolDispatch};
use oraclemcp_core::tools::{ToolDescriptor, ToolRegistry, ToolTier};
use oraclemcp_guard::OperatingLevel;
use serde_json::{Value, json};

#[path = "../../../tests/golden/support.rs"]
mod golden_support;

struct EchoDispatch;
impl ToolDispatch for EchoDispatch {
    fn dispatch<'a>(
        &'a self,
        _cx: &'a Cx,
        context: DispatchContext<'a>,
        name: &'a str,
        args: Value,
    ) -> DispatchFuture<'a> {
        Box::pin(async move {
            let mut result = json!({ "tool": name, "args": args, "ok": true });
            if let Some(grant) = context.scope_grant() {
                result["scopes"] = json!(grant.0);
            }
            Outcome::Ok(result)
        })
    }
}

struct AcceptHs256;
impl SignatureVerifier for AcceptHs256 {
    fn verify(&self, alg: &str, _signing_input: &[u8], _signature: &[u8]) -> bool {
        alg == "HS256"
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
            handle.join().expect("golden HTTP server joins cleanly");
        }
    }
}

fn harness_server() -> OracleMcpServer {
    let mut registry = ToolRegistry::new();
    registry.register(
        ToolDescriptor::new(
            "oracle_schema_inspect",
            ToolTier::FoundationLiveDb,
            "inspect a schema",
        )
        .with_input_schema(json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string" },
                "name_like": { "type": "string" }
            },
            "required": [],
            "additionalProperties": false
        })),
    );
    let report = CapabilitiesReport::new(
        "0.3.0",
        registry.tools.clone(),
        OperatingLevel::ReadOnly,
        FeatureTiers {
            live_db: false,
            engine: false,
            http_transport: true,
        },
    );
    OracleMcpServer::new("0.3.0", registry, report, Arc::new(EchoDispatch))
}

fn initialize_body(id: i64, client: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": client, "version": "1.0" }
        }
    })
}

fn json_post(path: &str, body: &Value) -> HttpRequest {
    request(
        "POST",
        path,
        default_post_headers(),
        body.to_string().into_bytes(),
    )
}

fn request(
    method: &str,
    path: &str,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
) -> HttpRequest {
    HttpRequest::new(method, path, headers, body)
}

fn default_post_headers() -> Vec<(&'static str, String)> {
    vec![
        ("host", "127.0.0.1".to_owned()),
        ("content-type", "application/json".to_owned()),
        ("accept", "application/json, text/event-stream".to_owned()),
    ]
}

fn headers_with(extra: &[(&'static str, &str)]) -> Vec<(&'static str, String)> {
    let mut headers = default_post_headers();
    headers.extend(
        extra
            .iter()
            .map(|(name, value)| (*name, (*value).to_owned())),
    );
    headers
}

fn capture_response(response: HttpResponse) -> Value {
    let content_type = response.header("content-type").map(str::to_owned);
    let headers = selected_headers(&response.headers);
    json!({
        "status": response.status,
        "headers": headers,
        "body": golden_support::body_value(content_type.as_deref(), &response.body),
    })
}

fn selected_headers(headers: &[(String, String)]) -> Value {
    let names = [
        "content-type",
        "cache-control",
        "www-authenticate",
        "allow",
        "mcp-session-id",
    ];
    let mut out = serde_json::Map::new();
    for name in names {
        if let Some((_, value)) = headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        {
            out.insert(name.to_owned(), Value::String(value.clone()));
        }
    }
    Value::Object(out)
}

fn session_id(response: &HttpResponse) -> String {
    response
        .header("mcp-session-id")
        .expect("stateful initialize returns Mcp-Session-Id")
        .to_owned()
}

fn b64url(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 0x3f) as usize] as char);
        }
    }
    out
}

fn jwt_with_scope(scope: &str) -> String {
    let header = b64url(br#"{"alg":"HS256","typ":"at+jwt"}"#);
    let claims = json!({
        "iss": "https://idp.example",
        "aud": "https://oraclemcp.example/mcp",
        "exp": 9_999_999_999i64,
        "sub": "golden-subject",
        "client_id": "golden-client",
        "iat": 1_000_000_000i64,
        "jti": "golden-token",
        "scope": scope,
    });
    let payload = b64url(serde_json::to_string(&claims).unwrap().as_bytes());
    format!("{header}.{payload}.{}", b64url(b"sig"))
}

fn oauth_enforcement() -> Arc<OAuthEnforcement> {
    Arc::new(OAuthEnforcement {
        config: ResourceServerConfig {
            resource: "https://oraclemcp.example/mcp".to_owned(),
            allowed_issuers: vec!["https://idp.example".to_owned()],
            authorization_servers: vec!["https://idp.example".to_owned()],
            required_scopes: vec![],
        },
        verifier: Arc::new(
            oraclemcp_auth::Hs256Verifier::new(b"0123456789abcdef0123456789abcdef".to_vec())
                .expect("valid test key"),
        ),
        metadata_url: "https://oraclemcp.example/.well-known/oauth-protected-resource".to_owned(),
    })
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

fn spawn_served_http(config: HttpTransportConfig) -> HttpHarness {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback golden HTTP listener");
    let addr = listener.local_addr().expect("listener has local address");
    let shutdown = Arc::new(AtomicBool::new(false));
    let thread_shutdown = Arc::clone(&shutdown);
    let handle = thread::spawn(move || {
        serve_http_until(listener, harness_server(), &config, thread_shutdown)
            .expect("served golden HTTP exits cleanly");
    });
    HttpHarness {
        addr,
        shutdown,
        handle: Some(handle),
    }
}

fn served_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> HttpResponse {
    let mut request = format!("{method} {path} HTTP/1.1\r\n");
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str(&format!("content-length: {}\r\n\r\n", body.len()));

    let mut stream = TcpStream::connect(addr).expect("connect to served golden HTTP");
    stream
        .write_all(request.as_bytes())
        .expect("write HTTP request headers");
    stream.write_all(body).expect("write HTTP request body");
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("finish HTTP request");

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .expect("read served HTTP response");
    parse_served_response(&raw)
}

fn parse_served_response(raw: &[u8]) -> HttpResponse {
    let raw = String::from_utf8(raw.to_vec()).expect("served HTTP response is UTF-8");
    let (head, body) = raw.split_once("\r\n\r\n").expect("HTTP response shape");
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .expect("HTTP status code")
        .parse::<u16>()
        .expect("numeric HTTP status");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    HttpResponse {
        status,
        headers,
        body: body.as_bytes().to_vec(),
    }
}

fn served_post_headers(token_scope: Option<&str>, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut headers = default_post_headers()
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect::<Vec<_>>();
    if let Some(scope) = token_scope {
        headers.push((
            "authorization".to_owned(),
            format!("Bearer {}", jwt_with_scope(scope)),
        ));
    }
    headers.extend(
        extra
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    headers
}

#[test]
fn golden_http_stateless_initialize_json_response() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: false,
        ..Default::default()
    };
    let server = harness_server();
    let body = initialize_body(1, "golden-http-json");

    let response = handle_http_request(&server, &cfg, json_post(MCP_PATH, &body));
    let actual = json!({
        "case": "stateless /mcp initialize returns direct JSON",
        "request": {
            "method": "POST",
            "path": MCP_PATH,
            "headers": default_post_headers(),
            "body": body,
        },
        "response": capture_response(response),
    });
    golden_support::assert_golden("http/stateless_initialize_json_response", &actual);
}

#[test]
fn golden_http_protected_resource_metadata() {
    let metadata = json!({
        "resource": "https://oraclemcp.example/mcp",
        "authorization_servers": ["https://idp.example"],
        "scopes_supported": ["oracle:read"],
    });
    let cfg = HttpTransportConfig {
        resource_metadata: Some(metadata.clone()),
        ..Default::default()
    };
    let req = request(
        "GET",
        PROTECTED_RESOURCE_METADATA_PATH,
        vec![("host", "127.0.0.1".to_owned())],
        Vec::new(),
    );

    let server = harness_server();
    let response = handle_http_request(&server, &cfg, req);
    let actual = json!({
        "case": "RFC 9728 protected-resource metadata stays publicly discoverable",
        "request": {
            "method": "GET",
            "path": PROTECTED_RESOURCE_METADATA_PATH,
            "headers": [["host", "127.0.0.1"]],
            "body": "",
        },
        "configured_metadata": metadata,
        "response": capture_response(response),
    });
    golden_support::assert_golden("http/protected_resource_metadata", &actual);
}

#[test]
fn golden_http_unauthorized_www_authenticate() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: false,
        oauth: Some(oauth_enforcement()),
        ..Default::default()
    };
    let server = harness_server();
    let body = initialize_body(1, "golden-http-unauthorized");

    let response = handle_http_request(&server, &cfg, json_post(MCP_PATH, &body));
    let actual = json!({
        "case": "OAuth-protected /mcp refuses missing bearer with WWW-Authenticate",
        "request": {
            "method": "POST",
            "path": MCP_PATH,
            "headers": default_post_headers(),
            "body": body,
        },
        "response": capture_response(response),
    });
    golden_support::assert_golden("http/unauthorized_www_authenticate", &actual);
}

#[test]
fn golden_http_host_and_origin_guards() {
    let init = initialize_body(1, "golden-http-guard");
    let server = harness_server();
    let host_response = handle_http_request(
        &server,
        &HttpTransportConfig::default(),
        request(
            "POST",
            MCP_PATH,
            vec![
                ("host", "attacker.example".to_owned()),
                ("content-type", "application/json".to_owned()),
                ("accept", "application/json, text/event-stream".to_owned()),
            ],
            init.to_string().into_bytes(),
        ),
    );

    let origin_cfg = HttpTransportConfig {
        allowed_origins: vec!["https://app.example".to_owned()],
        ..Default::default()
    };
    let origin_response = handle_http_request(
        &server,
        &origin_cfg,
        request(
            "POST",
            MCP_PATH,
            headers_with(&[("origin", "https://evil.example")]),
            init.to_string().into_bytes(),
        ),
    );

    let actual = json!({
        "case": "native DNS-rebinding Host guard and browser Origin allowlist",
        "requests": [
            {
                "name": "untrusted host",
                "method": "POST",
                "path": MCP_PATH,
                "headers": [
                    ["host", "attacker.example"],
                    ["content-type", "application/json"],
                    ["accept", "application/json, text/event-stream"]
                ],
                "body": init,
                "response": capture_response(host_response),
            },
            {
                "name": "forbidden origin",
                "method": "POST",
                "path": MCP_PATH,
                "headers": headers_with(&[("origin", "https://evil.example")]),
                "body": init,
                "response": capture_response(origin_response),
            }
        ]
    });
    golden_support::assert_golden("http/host_origin_guards", &actual);
}

#[test]
fn golden_http_stateful_streamable_session() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: true,
        session_store: Some(Arc::new(HttpSessionStore::default())),
        ..Default::default()
    };
    let server = harness_server();

    let init = initialize_body(1, "golden-http-stateful");
    let init_response = handle_http_request(&server, &cfg, json_post(MCP_PATH, &init));
    assert_eq!(init_response.status, 200);
    let session_id = session_id(&init_response);
    let init_exchange = capture_response(init_response);

    let initialized = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    });
    let initialized_headers = headers_with(&[
        ("mcp-session-id", &session_id),
        ("mcp-protocol-version", "2025-11-25"),
    ]);
    let initialized_response = handle_http_request(
        &server,
        &cfg,
        request(
            "POST",
            MCP_PATH,
            initialized_headers.clone(),
            initialized.to_string().into_bytes(),
        ),
    );
    let initialized_exchange = capture_response(initialized_response);

    let list = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
    });
    let list_headers = headers_with(&[
        ("mcp-session-id", &session_id),
        ("mcp-protocol-version", "2025-11-25"),
    ]);
    let list_response = handle_http_request(
        &server,
        &cfg,
        request(
            "POST",
            MCP_PATH,
            list_headers.clone(),
            list.to_string().into_bytes(),
        ),
    );
    let list_exchange = capture_response(list_response);
    assert!(
        list_exchange["body"]
            .as_array()
            .is_some_and(|events| events.iter().any(|event| event["data"]["id"] == json!(2))),
        "stateful tools/list SSE response must include the JSON-RPC response event: {list_exchange}"
    );

    let delete_response = handle_http_request(
        &server,
        &cfg,
        request(
            "DELETE",
            MCP_PATH,
            vec![
                ("host", "127.0.0.1".to_owned()),
                ("mcp-session-id", session_id),
                ("mcp-protocol-version", "2025-11-25".to_owned()),
            ],
            Vec::new(),
        ),
    );

    let actual = json!({
        "case": "stateful Streamable HTTP session uses SSE, session header, initialized notification, and session-bound request",
        "exchanges": [
            {
                "name": "initialize",
                "request": {
                    "method": "POST",
                    "path": MCP_PATH,
                    "headers": default_post_headers(),
                    "body": init,
                },
                "response": init_exchange,
            },
            {
                "name": "notifications/initialized",
                "request": {
                    "method": "POST",
                    "path": MCP_PATH,
                    "headers": initialized_headers,
                    "body": initialized,
                },
                "response": initialized_exchange,
            },
            {
                "name": "tools/list",
                "request": {
                    "method": "POST",
                    "path": MCP_PATH,
                    "headers": list_headers,
                    "body": list,
                },
                "response": list_exchange,
            },
            {
                "name": "delete session",
                "request": {
                    "method": "DELETE",
                    "path": MCP_PATH,
                    "headers": [
                        ["host", "127.0.0.1"],
                        ["mcp-session-id", "[SESSION_ID]"],
                        ["mcp-protocol-version", "2025-11-25"]
                    ],
                    "body": "",
                },
                "response": capture_response(delete_response),
            }
        ]
    });
    golden_support::assert_golden("http/stateful_streamable_session", &actual);
}

#[test]
fn golden_http_served_auth_scope_and_session_matrix() {
    let cfg = HttpTransportConfig {
        json_response: true,
        stateful: true,
        allowed_origins: vec!["https://app.example".to_owned()],
        oauth: Some(accepting_oauth_enforcement(Vec::new())),
        session_store: Some(Arc::new(HttpSessionStore::default())),
        ..Default::default()
    };
    let harness = spawn_served_http(cfg);
    let init = initialize_body(1, "golden-served-http");

    let anonymous_headers = served_post_headers(None, &[]);
    let anonymous = served_request(
        harness.addr,
        "POST",
        MCP_PATH,
        &anonymous_headers,
        init.to_string().as_bytes(),
    );

    let bad_origin_headers =
        served_post_headers(Some("oracle:read"), &[("origin", "https://evil.example")]);
    let bad_origin = served_request(
        harness.addr,
        "POST",
        MCP_PATH,
        &bad_origin_headers,
        init.to_string().as_bytes(),
    );

    let allowed_init_headers =
        served_post_headers(Some("oracle:read"), &[("origin", "https://app.example")]);
    let allowed_init = served_request(
        harness.addr,
        "POST",
        MCP_PATH,
        &allowed_init_headers,
        init.to_string().as_bytes(),
    );
    assert_eq!(allowed_init.status, 200);
    let issued_session_id = session_id(&allowed_init);

    let call = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "oracle_schema_inspect",
            "arguments": { "owner": "HR" }
        }
    });
    let allowed_call_headers = served_post_headers(
        Some("oracle:read"),
        &[
            ("origin", "https://app.example"),
            ("mcp-session-id", &issued_session_id),
            ("mcp-protocol-version", "2025-11-25"),
        ],
    );
    let allowed_call = served_request(
        harness.addr,
        "POST",
        MCP_PATH,
        &allowed_call_headers,
        call.to_string().as_bytes(),
    );
    assert_eq!(allowed_call.status, 200);

    let forged_session_headers = served_post_headers(
        Some("oracle:read"),
        &[
            ("origin", "https://app.example"),
            ("mcp-session-id", "00000000-0000-4000-8000-999999999999"),
            ("mcp-protocol-version", "2025-11-25"),
        ],
    );
    let forged_session = served_request(
        harness.addr,
        "POST",
        MCP_PATH,
        &forged_session_headers,
        call.to_string().as_bytes(),
    );

    let actual = json!({
        "case": "served native HTTP enforces OAuth, Origin, scope forwarding, and stateful session ids",
        "transport": "TcpListener -> serve_http_until -> request parser -> MCP dispatcher",
        "exchanges": [
            {
                "name": "anonymous initialize refused",
                "request": {
                    "method": "POST",
                    "path": MCP_PATH,
                    "headers": default_post_headers(),
                    "body": init,
                },
                "response": capture_response(anonymous),
            },
            {
                "name": "bad Origin refused before dispatch",
                "request": {
                    "method": "POST",
                    "path": MCP_PATH,
                    "headers": headers_with(&[("origin", "https://evil.example")]),
                    "authorization": "[TOKEN: oracle:read]",
                    "body": init,
                },
                "response": capture_response(bad_origin),
            },
            {
                "name": "valid bearer creates stateful session",
                "request": {
                    "method": "POST",
                    "path": MCP_PATH,
                    "headers": headers_with(&[("origin", "https://app.example")]),
                    "authorization": "[TOKEN: oracle:read]",
                    "body": init,
                },
                "response": capture_response(allowed_init),
            },
            {
                "name": "valid bearer scope reaches tool dispatch",
                "request": {
                    "method": "POST",
                    "path": MCP_PATH,
                    "headers": [
                        ["host", "127.0.0.1"],
                        ["content-type", "application/json"],
                        ["accept", "application/json, text/event-stream"],
                        ["origin", "https://app.example"],
                        ["mcp-session-id", "[SESSION_ID]"],
                        ["mcp-protocol-version", "2025-11-25"]
                    ],
                    "authorization": "[TOKEN: oracle:read]",
                    "body": call,
                },
                "response": capture_response(allowed_call),
            },
            {
                "name": "forged stateful session id refused",
                "request": {
                    "method": "POST",
                    "path": MCP_PATH,
                    "headers": [
                        ["host", "127.0.0.1"],
                        ["content-type", "application/json"],
                        ["accept", "application/json, text/event-stream"],
                        ["origin", "https://app.example"],
                        ["mcp-session-id", "00000000-0000-4000-8000-999999999999"],
                        ["mcp-protocol-version", "2025-11-25"]
                    ],
                    "authorization": "[TOKEN: oracle:read]",
                    "body": call,
                },
                "response": capture_response(forged_session),
            }
        ]
    });
    golden_support::assert_golden("http/served_auth_scope_session_matrix", &actual);
}
