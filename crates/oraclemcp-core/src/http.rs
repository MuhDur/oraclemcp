//! Native Streamable HTTP(S) transport (plan §7.1, §2.5; bead P1-9a /
//! oracle-qmwz.2.9.1).
//!
//! This module owns the small HTTP/1.1 surface oraclemcp actually needs: the
//! `/mcp` Streamable HTTP endpoint, RFC 9728 protected-resource metadata, the
//! DNS-rebinding `Host` guard, the browser `Origin` allowlist, and OAuth bearer
//! validation. It deliberately does not depend on a web framework or ambient
//! async runtime.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oraclemcp_auth::{
    HttpGuardError, HttpGuardPolicy, ResourceServerConfig, SignatureVerifier, TokenError,
    extract_bearer,
};
use serde_json::{Value, json};

use crate::server::{DispatchContext, OracleMcpServer};

/// The MCP endpoint path the Streamable HTTP transport is mounted at.
pub const MCP_PATH: &str = "/mcp";
/// The RFC 9728 protected-resource-metadata well-known path.
pub const PROTECTED_RESOURCE_METADATA_PATH: &str = "/.well-known/oauth-protected-resource";

/// Operator configuration for the HTTP transport.
#[derive(Clone, Debug, Default)]
pub struct HttpTransportConfig {
    /// Allowed `Host` authorities beyond loopback (DNS-rebinding guard). Empty
    /// keeps the default loopback-only policy.
    pub allowed_hosts: Vec<String>,
    /// Allowed browser `Origin`s (empty allows only loopback origins).
    pub allowed_origins: Vec<String>,
    /// Stateless `application/json` responses instead of SSE framing when
    /// `stateful` is false.
    pub json_response: bool,
    /// Stateful session mode (SSE priming + session-bound requests).
    pub stateful: bool,
    /// The RFC 9728 protected-resource metadata document to serve, if OAuth is
    /// enabled (from [`oraclemcp_auth::oauth_rs::ResourceServerConfig`]).
    pub resource_metadata: Option<Value>,
    /// OAuth 2.1 resource-server enforcement (P1-9b). When set, every `/mcp`
    /// request must carry a valid bearer token; the metadata route stays open so
    /// clients can discover the authorization server.
    pub oauth: Option<Arc<OAuthEnforcement>>,
}

/// OAuth 2.1 resource-server enforcement wiring for the HTTP transport (P1-9b).
pub struct OAuthEnforcement {
    /// Issuer allowlist + RFC 8707 audience + required scopes.
    pub config: ResourceServerConfig,
    /// The signature verifier (HS256 here; RS256/ES256 via a JWKS-backed impl).
    pub verifier: Arc<dyn SignatureVerifier + Send + Sync>,
    /// The RFC 9728 metadata URL advertised in `WWW-Authenticate` on a 401.
    pub metadata_url: String,
}

impl std::fmt::Debug for OAuthEnforcement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The verifier may hold a secret; never print it.
        f.debug_struct("OAuthEnforcement")
            .field("config", &self.config)
            .field("verifier", &"<SignatureVerifier>")
            .field("metadata_url", &self.metadata_url)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::{CapabilitiesReport, FeatureTiers};
    use crate::server::{DispatchContext, DispatchFuture, ToolDispatch};
    use crate::tools::ToolRegistry;
    use asupersync::Cx;
    use oraclemcp_guard::OperatingLevel;

    struct NoopDispatch;
    impl ToolDispatch for NoopDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            _name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async { Ok(serde_json::json!({})) })
        }
    }

    struct ScopeEchoDispatch;
    impl ToolDispatch for ScopeEchoDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            context: DispatchContext<'a>,
            name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            let scopes = context
                .scope_grant()
                .map(|grant| grant.0.clone())
                .unwrap_or_default();
            Box::pin(async move { Ok(serde_json::json!({ "tool": name, "scopes": scopes })) })
        }
    }

    fn test_server() -> OracleMcpServer {
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
        OracleMcpServer::new("0.1.0", ToolRegistry::new(), report, Arc::new(NoopDispatch))
    }

    fn scope_echo_server() -> OracleMcpServer {
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
            Arc::new(ScopeEchoDispatch),
        )
    }

    fn init_body() -> Value {
        serde_json::json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"initialize",
            "params":{
                "protocolVersion":"2025-11-25",
                "capabilities":{},
                "clientInfo":{"name":"t","version":"1.0"}
            }
        })
    }

    fn post(body: &Value) -> HttpRequest {
        HttpRequest::new(
            "POST",
            MCP_PATH,
            [
                ("host", "127.0.0.1"),
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
            ],
            body.to_string().into_bytes(),
        )
    }

    fn response_json(response: &HttpResponse) -> Value {
        serde_json::from_slice(&response.body).expect("response body is JSON")
    }

    fn oauth_enforcement() -> Arc<OAuthEnforcement> {
        Arc::new(OAuthEnforcement {
            config: ResourceServerConfig {
                resource: "https://oraclemcp.example/mcp".to_owned(),
                allowed_issuers: vec!["https://idp.example".to_owned()],
                authorization_servers: vec!["https://idp.example".to_owned()],
                required_scopes: vec![],
            },
            verifier: Arc::new(oraclemcp_auth::Hs256Verifier {
                secret: b"k".to_vec(),
            }),
            metadata_url: "https://oraclemcp.example/.well-known/oauth-protected-resource"
                .to_owned(),
        })
    }

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
        let response = handle_http_request(&test_server(), &cfg, post(&init_body()));
        assert_eq!(response.status, 200);
        assert_eq!(response.header("content-type"), Some("application/json"));
        let body = response_json(&response);
        assert!(body.get("result").is_some(), "JSON-RPC initialize result");
        assert_eq!(body["result"]["serverInfo"]["name"], "oraclemcp");
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
        let response =
            handle_http_request(&test_server(), &HttpTransportConfig::default(), request);
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
            resource_metadata: Some(
                serde_json::json!({"resource": "https://oraclemcp.example/mcp"}),
            ),
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
    fn serve_http_until_stops_accepting_and_drains_worker() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback test listener");
        let addr = listener.local_addr().expect("listener has local addr");
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_shutdown = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            serve_http_until(
                listener,
                test_server(),
                &HttpTransportConfig {
                    json_response: true,
                    stateful: false,
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
    }

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

    fn jwt_with_scope(scope: &str) -> String {
        let header = b64url(br#"{"alg":"HS256","typ":"JWT"}"#);
        let claims = serde_json::json!({
            "iss": "https://idp.example",
            "aud": "https://oraclemcp.example/mcp",
            "exp": 9_999_999_999i64,
            "scope": scope,
        });
        let payload = b64url(serde_json::to_string(&claims).unwrap().as_bytes());
        format!("{header}.{payload}.{}", b64url(b"sig"))
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
            metadata_url: "https://oraclemcp.example/.well-known/oauth-protected-resource"
                .to_owned(),
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
        assert_eq!(grant, ScopeGrant(vec!["oracle:read".to_owned()]));
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
            metadata_url: "https://oraclemcp.example/.well-known/oauth-protected-resource"
                .to_owned(),
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
            metadata_url: "https://oraclemcp.example/.well-known/oauth-protected-resource"
                .to_owned(),
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
    }
}

/// The OAuth scopes a validated request carries.
///
/// The HTTP transport passes this grant into `ToolDispatch`, where it lowers
/// the request's effective session ceiling through
/// `oraclemcp_auth::apply_oauth_scopes`. A scope can only lower the profile
/// ceiling for the current request; it never raises a profile and it never
/// permanently narrows later requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeGrant(pub Vec<String>);

/// A parsed native HTTP request. Header names are stored lowercase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    #[must_use]
    pub fn new<I, K, V, B>(
        method: impl Into<String>,
        path: impl Into<String>,
        headers: I,
        body: B,
    ) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
        B: Into<Vec<u8>>,
    {
        let headers = headers
            .into_iter()
            .map(|(name, value)| (name.into().to_ascii_lowercase(), value.into()))
            .collect();
        Self {
            method: method.into().to_ascii_uppercase(),
            path: path.into(),
            headers,
            body: body.into(),
        }
    }

    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(candidate, _)| candidate == &name)
            .map(|(_, value)| value.as_str())
    }
}

/// A native HTTP response used by the listener and by protocol tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(candidate, _)| candidate == &name)
            .map(|(_, value)| value.as_str())
    }
}

fn token_error_code(e: &TokenError) -> &'static str {
    match e {
        TokenError::InsufficientScope => "insufficient_scope",
        // RFC 6750: every other validation failure is `invalid_token`.
        _ => "invalid_token",
    }
}

fn token_error_status(e: Option<&TokenError>) -> u16 {
    match e {
        Some(TokenError::InsufficientScope) => 403,
        _ => 401,
    }
}

fn validate_oauth_request(
    request: &HttpRequest,
    enforcement: &OAuthEnforcement,
) -> Result<ScopeGrant, HttpResponse> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let decision = match extract_bearer(request.header("authorization")) {
        Ok(token) => enforcement
            .config
            .validate(token, enforcement.verifier.as_ref(), now_unix)
            .map_err(Some),
        Err(_) => Err(None),
    };
    decision.map(ScopeGrant).map_err(|err| {
        let challenge = enforcement.config.www_authenticate(
            &enforcement.metadata_url,
            err.as_ref().map(token_error_code),
        );
        let status = token_error_status(err.as_ref());
        HttpResponse {
            status,
            headers: vec![
                (
                    "content-type".to_owned(),
                    "text/plain; charset=utf-8".to_owned(),
                ),
                ("www-authenticate".to_owned(), challenge),
            ],
            body: if status == 403 {
                b"forbidden".to_vec()
            } else {
                b"unauthorized".to_vec()
            },
        }
    })
}

fn guard_http_request(config: &HttpTransportConfig, request: &HttpRequest) -> Option<HttpResponse> {
    let policy = HttpGuardPolicy {
        allowed_origins: config.allowed_origins.clone(),
        allowed_hosts: config.allowed_hosts.clone(),
        // The CLI's listen guard owns the plaintext remote-bind policy. This
        // per-request guard preserves the previous Streamable HTTP behavior:
        // loopback hosts pass by default, explicit allowed_hosts pass when set.
        allow_non_loopback_http: true,
    };
    match policy.check("http", request.header("host"), request.header("origin")) {
        Ok(()) => None,
        Err(HttpGuardError::ForbiddenOrigin(_)) => Some(HttpResponse {
            status: 403,
            headers: vec![],
            body: b"Forbidden: Origin header is not allowed".to_vec(),
        }),
        Err(_) => Some(HttpResponse {
            status: 403,
            headers: vec![],
            body: b"Forbidden: Host header is not allowed".to_vec(),
        }),
    }
}

/// Handle one parsed native HTTP request.
#[must_use]
pub fn handle_http_request(
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    request: HttpRequest,
) -> HttpResponse {
    if request.path == PROTECTED_RESOURCE_METADATA_PATH && request.method == "GET" {
        return match &config.resource_metadata {
            Some(meta) => json_response(200, meta),
            None => empty_response(404),
        };
    }
    if request.path != MCP_PATH {
        return empty_response(404);
    }
    if let Some(response) = guard_http_request(config, &request) {
        return response;
    }
    if request.body.len() > MAX_BODY_BYTES {
        return empty_response(413);
    }
    let scope_grant = match &config.oauth {
        Some(enforcement) => match validate_oauth_request(&request, enforcement) {
            Ok(grant) => Some(grant),
            Err(response) => return response,
        },
        None => None,
    };
    match request.method.as_str() {
        "DELETE" => empty_response(202),
        "POST" => handle_mcp_post(server, config, &request, scope_grant.as_ref()),
        "GET" => empty_response(405).with_header("allow", "POST, DELETE"),
        _ => empty_response(405).with_header("allow", "GET, POST, DELETE"),
    }
}

fn handle_mcp_post(
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    request: &HttpRequest,
    scope_grant: Option<&ScopeGrant>,
) -> HttpResponse {
    let parsed = match serde_json::from_slice::<Value>(&request.body) {
        Ok(value) => value,
        Err(_) => {
            return json_response(200, &jsonrpc_error(Value::Null, -32700, "Parse error"));
        }
    };
    let method = parsed
        .get("method")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let context = scope_grant
        .map(DispatchContext::with_scope_grant)
        .unwrap_or_default();
    let response = server.handle_jsonrpc_request_with_context(parsed, None, context);
    let Some(response) = response else {
        return empty_response(202);
    };
    if config.stateful {
        return sse_response(method.as_deref(), response);
    }
    json_response(200, &response)
}

fn jsonrpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        },
    })
}

fn json_response(status: u16, value: &Value) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body: serde_json::to_vec(value).expect("JSON response serializes"),
    }
}

fn empty_response(status: u16) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![],
        body: Vec::new(),
    }
}

impl HttpResponse {
    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

fn sse_response(method: Option<&str>, response: Value) -> HttpResponse {
    let mut body = Vec::new();
    let session_id = if method == Some("initialize") {
        write_sse_event(&mut body, Some("0"), Some(3000), Some(&Value::Null));
        write_sse_event(&mut body, None, None, Some(&response));
        Some(new_session_id())
    } else {
        write_sse_event(&mut body, Some("0/0"), Some(3000), Some(&Value::Null));
        write_sse_event(&mut body, Some("1/0"), None, Some(&response));
        None
    };
    let mut headers = vec![
        ("content-type".to_owned(), "text/event-stream".to_owned()),
        ("cache-control".to_owned(), "no-cache".to_owned()),
    ];
    if let Some(session_id) = session_id {
        headers.push(("mcp-session-id".to_owned(), session_id));
    }
    HttpResponse {
        status: 200,
        headers,
        body,
    }
}

fn write_sse_event(body: &mut Vec<u8>, id: Option<&str>, retry: Option<u64>, data: Option<&Value>) {
    if let Some(id) = id {
        body.extend_from_slice(format!("id: {id}\n").as_bytes());
    }
    if let Some(retry) = retry {
        body.extend_from_slice(format!("retry: {retry}\n").as_bytes());
    }
    if let Some(data) = data {
        if data.is_null() {
            body.extend_from_slice(b"data:\n");
        } else {
            body.extend_from_slice(b"data: ");
            body.extend_from_slice(
                serde_json::to_string(data)
                    .expect("SSE event data serializes")
                    .as_bytes(),
            );
            body.push(b'\n');
        }
    }
    body.push(b'\n');
}

fn new_session_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("00000000-0000-4000-8000-{n:012x}")
}

/// Serve the MCP server over plaintext Streamable HTTP on `listener`.
///
/// # Errors
/// Returns fatal listener or connection write errors. Individual malformed
/// client requests are answered with HTTP errors and the listener continues.
pub fn serve_http(
    listener: TcpListener,
    server: OracleMcpServer,
    config: &HttpTransportConfig,
) -> std::io::Result<()> {
    serve_http_until(listener, server, config, Arc::new(AtomicBool::new(false)))
}

/// Serve HTTP until `shutdown` becomes true, then stop accepting new
/// connections and join active request workers before returning.
///
/// This is primarily used by tests and future signal wiring; the production
/// `serve_http` wrapper passes a never-set flag and therefore runs until the
/// listener itself fails or the process exits.
pub fn serve_http_until(
    listener: TcpListener,
    server: OracleMcpServer,
    config: &HttpTransportConfig,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    let config = Arc::new(config.clone());
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let server = server.clone();
                let config = Arc::clone(&config);
                workers.push(std::thread::spawn(move || {
                    if let Err(e) = handle_connection(stream, &server, &config) {
                        tracing::debug!(error = %e, "native HTTP connection failed");
                    }
                }));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
    for worker in workers {
        let _ = worker.join();
    }
    Ok(())
}

fn handle_connection(
    mut stream: TcpStream,
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(CONNECTION_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_IO_TIMEOUT))?;
    let response = match read_http_request(&mut stream) {
        Ok(Some(request)) => handle_http_request(server, config, request),
        Ok(None) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => HttpResponse {
            status: 400,
            headers: vec![],
            body: e.to_string().into_bytes(),
        },
        Err(e) => return Err(e),
    };
    write_http_response(&mut stream, &response)
}

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const CONNECTION_IO_TIMEOUT: Duration = Duration::from_secs(30);

fn read_http_request(stream: &mut TcpStream) -> std::io::Result<Option<HttpRequest>> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 8192];
    let header_end = loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err(invalid_data("incomplete HTTP request"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_header_end(&buf) {
            break end;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(invalid_data("HTTP headers exceed native transport limit"));
        }
    };

    let header_text = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| invalid_data("HTTP headers are not UTF-8"))?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| invalid_data("missing HTTP request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP method"))?;
    let target = request_parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP target"))?;
    let version = request_parts
        .next()
        .ok_or_else(|| invalid_data("missing HTTP version"))?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(invalid_data("unsupported HTTP version"));
    }

    let mut headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err(invalid_data("malformed HTTP header"));
        };
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }
    let mut request = HttpRequest::new(
        method,
        target.split('?').next().unwrap_or(target),
        headers,
        Vec::new(),
    );
    let content_length = request
        .header("content-length")
        .map(str::parse::<usize>)
        .transpose()
        .map_err(|_| invalid_data("invalid Content-Length"))?
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err(invalid_data("HTTP body exceeds native transport limit"));
    }
    let body_start = header_end + 4;
    request.body.extend_from_slice(&buf[body_start..]);
    while request.body.len() < content_length {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(invalid_data("incomplete HTTP body"));
        }
        request.body.extend_from_slice(&chunk[..n]);
    }
    request.body.truncate(content_length);
    Ok(Some(request))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn invalid_data(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

fn write_http_response(stream: &mut TcpStream, response: &HttpResponse) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {} {}\r\n",
        response.status,
        reason_phrase(response.status)
    )?;
    let mut has_content_length = false;
    let mut has_connection = false;
    for (name, value) in &response.headers {
        if name.eq_ignore_ascii_case("content-length") {
            has_content_length = true;
        }
        if name.eq_ignore_ascii_case("connection") {
            has_connection = true;
        }
        write!(stream, "{name}: {value}\r\n")?;
    }
    if !has_content_length {
        write!(stream, "content-length: {}\r\n", response.body.len())?;
    }
    if !has_connection {
        write!(stream, "connection: close\r\n")?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(&response.body)?;
    stream.flush()
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        _ => "OK",
    }
}
