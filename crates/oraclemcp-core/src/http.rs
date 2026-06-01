//! Streamable HTTP(S) transport (plan §7.1, §2.5; bead P1-9a / oracle-qmwz.2.9.1).
//!
//! Mounts the [`OracleMcpServer`] as an `rmcp` [`StreamableHttpService`] on an
//! axum router — the modern **Streamable HTTP** transport (MCP spec 2025-06-18+),
//! **NO legacy HTTP+SSE**. The DNS-rebinding `Host` guard and `Origin` allowlist
//! are enforced natively by `rmcp` (configured from [`HttpTransportConfig`],
//! mirroring `oraclemcp_auth::http_guard`'s policy intent); OAuth 2.1 resource-server
//! validation (P1-9b, [`oraclemcp_auth::oauth_rs`]) is advertised via the RFC
//! 9728 protected-resource-metadata route mounted here; TLS/mTLS (P1-9c) wraps
//! the listener with rustls.
//!
//! The engine stays synchronous behind `spawn_blocking` inside the server's tool
//! dispatch — this transport is purely the HTTP front.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use oraclemcp_auth::{ResourceServerConfig, SignatureVerifier, TokenError, extract_bearer};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use serde_json::Value;

use crate::server::OracleMcpServer;

/// The MCP endpoint path the Streamable HTTP transport is mounted at.
pub const MCP_PATH: &str = "/mcp";
/// The RFC 9728 protected-resource-metadata well-known path.
pub const PROTECTED_RESOURCE_METADATA_PATH: &str = "/.well-known/oauth-protected-resource";

/// Operator configuration for the HTTP transport.
#[derive(Clone, Debug, Default)]
pub struct HttpTransportConfig {
    /// Allowed `Host` authorities beyond loopback (DNS-rebinding guard). Empty
    /// keeps the rmcp default (loopback-only).
    pub allowed_hosts: Vec<String>,
    /// Allowed browser `Origin`s (empty disables Origin validation per rmcp).
    pub allowed_origins: Vec<String>,
    /// Stateless `application/json` responses instead of SSE framing (simpler
    /// request/response; `false` = stateful SSE, the rmcp default).
    pub json_response: bool,
    /// Stateful session mode (SSE priming + reconnect). `true` is the rmcp default.
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

/// The OAuth scopes a validated request carries, attached to the request
/// extensions by [`oauth_guard`]. The session-setup layer reads this and lowers
/// the operating-level ceiling via `oraclemcp_auth::apply_oauth_scopes` — a scope
/// can only LOWER the ceiling, never raise it (P1-9e), so e.g. an `oracle:read`
/// token cannot reach a write tool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeGrant(pub Vec<String>);

fn token_error_code(e: &TokenError) -> &'static str {
    match e {
        TokenError::InsufficientScope => "insufficient_scope",
        // RFC 6750: every other validation failure is `invalid_token`.
        _ => "invalid_token",
    }
}

/// Axum middleware enforcing OAuth 2.1 resource-server validation on `/mcp`.
async fn oauth_guard(
    State(enforcement): State<Arc<OAuthEnforcement>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // Decide while borrowing the request headers; release the borrow before
    // handing the request on (so the body can be consumed downstream).
    let decision: Result<Vec<String>, Option<TokenError>> = {
        let header = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        match extract_bearer(header) {
            Ok(token) => enforcement
                .config
                .validate(token, enforcement.verifier.as_ref(), now_unix)
                .map_err(Some),
            Err(_) => Err(None), // missing/blank bearer
        }
    };
    match decision {
        Ok(scopes) => {
            // Attach the granted scopes so the session-setup layer can lower the
            // operating-level ceiling (scope can only LOWER it — P1-9e).
            let mut request = request;
            request.extensions_mut().insert(ScopeGrant(scopes));
            next.run(request).await
        }
        Err(err) => {
            let challenge = enforcement.config.www_authenticate(
                &enforcement.metadata_url,
                err.as_ref().map(token_error_code),
            );
            (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, challenge)],
                "unauthorized",
            )
                .into_response()
        }
    }
}

impl HttpTransportConfig {
    fn to_rmcp(&self) -> StreamableHttpServerConfig {
        let mut cfg = StreamableHttpServerConfig::default()
            .with_json_response(self.json_response)
            .with_stateful_mode(self.stateful);
        if !self.allowed_hosts.is_empty() {
            cfg = cfg.with_allowed_hosts(self.allowed_hosts.clone());
        }
        if !self.allowed_origins.is_empty() {
            cfg = cfg.with_allowed_origins(self.allowed_origins.clone());
        }
        cfg
    }
}

/// Build the axum [`Router`] that serves the MCP server over Streamable HTTP at
/// [`MCP_PATH`], plus (when configured) the RFC 9728 metadata route. The
/// `server` is cloned per session by the service factory.
pub fn build_router(server: OracleMcpServer, config: &HttpTransportConfig) -> Router {
    let factory_server = server.clone();
    let service: StreamableHttpService<OracleMcpServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(factory_server.clone()),
            Arc::new(LocalSessionManager::default()),
            config.to_rmcp(),
        );

    let mut router = Router::new().nest_service(MCP_PATH, service);

    // Enforce OAuth on /mcp (the layer applies to routes added BEFORE it, so the
    // metadata route added afterwards stays open for authorization discovery).
    if let Some(enforcement) = &config.oauth {
        router = router.layer(axum::middleware::from_fn_with_state(
            Arc::clone(enforcement),
            oauth_guard,
        ));
    }

    if let Some(meta) = &config.resource_metadata {
        let meta = meta.clone();
        router = router.route(
            PROTECTED_RESOURCE_METADATA_PATH,
            axum::routing::get(move || {
                let meta = meta.clone();
                async move { axum::Json(meta) }
            }),
        );
    }
    router
}

/// Serve the MCP server over plaintext Streamable HTTP on `listener` until
/// `shutdown` completes. TLS/mTLS (P1-9c) wraps the accept loop separately.
///
/// # Errors
/// Returns any fatal I/O error from the axum accept loop.
pub async fn serve_http(
    listener: tokio::net::TcpListener,
    server: OracleMcpServer,
    config: &HttpTransportConfig,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let router = build_router(server, config);
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::{CapabilitiesReport, FeatureTiers};
    use crate::server::ToolDispatch;
    use crate::tools::ToolRegistry;
    use oraclemcp_error::ErrorEnvelope;
    use oraclemcp_guard::OperatingLevel;

    struct NoopDispatch;
    impl ToolDispatch for NoopDispatch {
        fn dispatch(&self, _name: &str, _args: Value) -> Result<Value, ErrorEnvelope> {
            Ok(serde_json::json!({}))
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

    #[test]
    fn config_maps_guards_to_rmcp() {
        let cfg = HttpTransportConfig {
            allowed_hosts: vec!["mcp.example:8443".to_owned()],
            allowed_origins: vec!["https://app.example".to_owned()],
            json_response: true,
            stateful: false,
            resource_metadata: None,
            oauth: None,
        };
        let rmcp = cfg.to_rmcp();
        assert!(rmcp.allowed_hosts.contains(&"mcp.example:8443".to_owned()));
        assert!(
            rmcp.allowed_origins
                .contains(&"https://app.example".to_owned())
        );
        assert!(rmcp.json_response);
        assert!(!rmcp.stateful_mode);
    }

    #[tokio::test]
    async fn metadata_route_serves_rfc9728_document() {
        use tower::ServiceExt;
        let meta = serde_json::json!({
            "resource": "https://oraclemcp.example/mcp",
            "authorization_servers": ["https://idp.example"],
        });
        let cfg = HttpTransportConfig {
            resource_metadata: Some(meta),
            ..Default::default()
        };
        let router = build_router(test_server(), &cfg);

        let req = axum::http::Request::builder()
            .uri(PROTECTED_RESOURCE_METADATA_PATH)
            .header("host", "127.0.0.1")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .unwrap();
        let doc: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            doc["resource"],
            serde_json::json!("https://oraclemcp.example/mcp")
        );
    }

    #[tokio::test]
    async fn initialize_over_streamable_http_returns_json() {
        use tower::ServiceExt;
        // Stateless + json_response -> initialize returns application/json directly.
        let cfg = HttpTransportConfig {
            json_response: true,
            stateful: false,
            ..Default::default()
        };
        let router = build_router(test_server(), &cfg);

        const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1.0"}}}"#;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(MCP_PATH)
            .header("host", "127.0.0.1")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(axum::body::Body::from(INIT))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "initialize handshake succeeds over HTTP"
        );
        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        assert!(
            ct.contains("application/json"),
            "stateless json mode -> application/json, got {ct}"
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 256 * 1024)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        // A well-formed JSON-RPC initialize result that advertises the server.
        assert!(
            body.get("result").is_some(),
            "initialize returns a JSON-RPC result: {body}"
        );
        assert!(
            String::from_utf8_lossy(&bytes).contains("oraclemcp"),
            "the initialize result advertises the oraclemcp server"
        );
    }

    #[tokio::test]
    async fn dns_rebinding_host_is_rejected_by_the_transport() {
        use tower::ServiceExt;
        // Default config = loopback-only Host allowlist; an attacker Host is refused.
        let router = build_router(test_server(), &HttpTransportConfig::default());
        const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1.0"}}}"#;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(MCP_PATH)
            .header("host", "attacker.example")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(axum::body::Body::from(INIT))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            axum::http::StatusCode::OK,
            "non-loopback Host is refused (DNS-rebinding guard)"
        );
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

    #[tokio::test]
    async fn oauth_enabled_rejects_missing_token_with_www_authenticate() {
        use tower::ServiceExt;
        let cfg = HttpTransportConfig {
            json_response: true,
            stateful: false,
            oauth: Some(oauth_enforcement()),
            ..Default::default()
        };
        let router = build_router(test_server(), &cfg);
        const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1.0"}}}"#;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(MCP_PATH)
            .header("host", "127.0.0.1")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            // No Authorization header.
            .body(axum::body::Body::from(INIT))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "no token -> 401"
        );
        let chal = resp
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            chal.contains("Bearer resource_metadata="),
            "401 carries the RFC 9728 challenge: {chal}"
        );
    }

    #[tokio::test]
    async fn oauth_enabled_rejects_bad_token_but_keeps_metadata_open() {
        use tower::ServiceExt;
        let cfg = HttpTransportConfig {
            json_response: true,
            stateful: false,
            resource_metadata: Some(
                serde_json::json!({"resource": "https://oraclemcp.example/mcp"}),
            ),
            oauth: Some(oauth_enforcement()),
            ..Default::default()
        };
        // A garbage bearer token -> 401.
        const INIT: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(MCP_PATH)
            .header("host", "127.0.0.1")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("authorization", "Bearer not.a.jwt")
            .body(axum::body::Body::from(INIT))
            .unwrap();
        let resp = build_router(test_server(), &cfg)
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "bad token -> 401"
        );

        // The metadata route is NOT behind auth (authorization-server discovery).
        let req = axum::http::Request::builder()
            .uri(PROTECTED_RESOURCE_METADATA_PATH)
            .header("host", "127.0.0.1")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = build_router(test_server(), &cfg)
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::OK,
            "metadata route stays open for discovery"
        );
    }
}
