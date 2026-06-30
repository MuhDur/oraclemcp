//! Native Streamable HTTP(S) transport (plan §7.1, §2.5; bead P1-9a /
//! oracle-qmwz.2.9.1).
//!
//! This module owns the small HTTP/1.1 surface oraclemcp actually needs: the
//! `/mcp` Streamable HTTP endpoint, RFC 9728 protected-resource metadata, the
//! DNS-rebinding `Host` guard, the browser `Origin` allowlist, and OAuth bearer
//! validation. It deliberately does not depend on a web framework or ambient
//! async runtime.

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oraclemcp_auth::{
    HttpGuardError, HttpGuardPolicy, ResourceServerConfig, SignatureVerifier, TokenError,
    extract_bearer,
};
use oraclemcp_telemetry::{HealthState, Metrics};
use rustls::{ServerConnection, StreamOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::server::{DispatchContext, OracleMcpServer};
use crate::tls::TlsServerConfig;

/// The MCP endpoint path the Streamable HTTP transport is mounted at.
pub const MCP_PATH: &str = "/mcp";
/// The RFC 9728 protected-resource-metadata well-known path.
pub const PROTECTED_RESOURCE_METADATA_PATH: &str = "/.well-known/oauth-protected-resource";
/// Kubernetes-style liveness probe path (D1-health). Process-up only.
pub const HEALTHZ_PATH: &str = "/healthz";
/// Kubernetes-style readiness probe path (D1-health). DB-reachable + not draining.
pub const READYZ_PATH: &str = "/readyz";
/// Prometheus metrics-scrape path (D1-health / D1-metrics).
pub const METRICS_PATH: &str = "/metrics";

/// A cheap, synchronous DB-reachability check for the `/readyz` probe.
///
/// The served HTTP path is synchronous, so the readiness handler cannot itself
/// `await` an Oracle `ping`. An implementation therefore reads a cached result
/// maintained out of band (a background pinger that holds its own connection +
/// `Cx`, calls `OracleConnection::ping`, and updates an atomic). `/readyz`
/// returns 200 only when this is `true` AND the server is not shutting down.
pub trait ReadinessProbe: Send + Sync {
    /// `true` if the database is currently reachable (last probe succeeded).
    fn is_db_reachable(&self) -> bool;
}

/// Observability surface mounted on the HTTP transport (D1; off by default).
///
/// All fields are optional: when `None`, the corresponding endpoint returns 404
/// (the route is not advertised). `HealthState` drives `/healthz` + `/readyz`,
/// `Metrics` backs `/metrics` (Prometheus text), and `readiness_probe` is the
/// DB-reachability gate for `/readyz`.
#[derive(Clone, Default)]
pub struct ObservabilityState {
    /// Liveness/readiness state (shared with the shutdown coordinator).
    pub health: Option<HealthState>,
    /// In-process metrics registry exposed at `/metrics`.
    pub metrics: Option<Arc<Metrics>>,
    /// DB-reachability gate for `/readyz`.
    pub readiness_probe: Option<Arc<dyn ReadinessProbe>>,
}

impl std::fmt::Debug for ObservabilityState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObservabilityState")
            .field("health", &self.health.is_some())
            .field("metrics", &self.metrics.is_some())
            .field("readiness_probe", &self.readiness_probe.is_some())
            .finish()
    }
}

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
    /// Issued stateful Streamable HTTP session ids. Listener wrappers install a
    /// store automatically when `stateful` is true.
    pub session_store: Option<Arc<HttpSessionStore>>,
    /// N8 interim guard: until per-principal lanes exist, a served HTTP process
    /// may bind to one authenticated principal only. A second principal is
    /// refused before it can touch the shared dispatcher/session state.
    pub single_principal_guard: Option<SinglePrincipalGuard>,
    /// Health/metrics observability endpoints (D1; off by default — `None`
    /// fields make the corresponding route return 404 / not be advertised).
    pub observability: ObservabilityState,
}

/// OAuth 2.1 resource-server enforcement wiring for the HTTP transport (P1-9b).
pub struct OAuthEnforcement {
    /// Issuer allowlist + RFC 8707 audience + required scopes.
    pub config: ResourceServerConfig,
    /// The JWT signature verifier. Only symmetric HS256 is wired in production;
    /// asymmetric algs (RS256/ES256 via JWKS) are a fail-closed seam pending a
    /// JWKS-backed verifier — such tokens are rejected (`BadSignature`) today.
    pub verifier: Arc<dyn SignatureVerifier + Send + Sync>,
    /// The RFC 9728 metadata URL advertised in `WWW-Authenticate` on a 401.
    pub metadata_url: String,
}

/// Interim single-principal admission guard for the pre-lane HTTP server.
///
/// The guard stores only a derived, redacted key. It never stores a bearer token
/// or raw JWT claim value.
#[derive(Clone, Debug, Default)]
pub struct SinglePrincipalGuard {
    active_principal_key: Arc<Mutex<Option<String>>>,
}

impl SinglePrincipalGuard {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn admit(&self, candidate_key: &str) -> Result<(), ()> {
        let Ok(mut active) = self.active_principal_key.lock() else {
            return Err(());
        };
        match active.as_deref() {
            None => {
                *active = Some(candidate_key.to_owned());
                Ok(())
            }
            Some(current) if current == candidate_key => Ok(()),
            Some(_) => Err(()),
        }
    }
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

/// Shared stateful Streamable HTTP session-id registry.
#[derive(Debug, Default)]
pub struct HttpSessionStore {
    owners: Mutex<HashMap<String, String>>,
}

impl HttpSessionStore {
    fn insert(&self, id: String, principal_key: String) {
        if let Ok(mut owners) = self.owners.lock() {
            owners.insert(id, principal_key);
        }
    }

    fn principal_for(&self, id: &str) -> Option<String> {
        self.owners
            .lock()
            .ok()
            .and_then(|owners| owners.get(id).cloned())
    }

    fn remove(&self, id: &str) -> bool {
        self.owners
            .lock()
            .is_ok_and(|mut owners| owners.remove(id).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::{CapabilitiesReport, FeatureTiers};
    use crate::server::{DispatchContext, DispatchFuture, ToolDispatch};
    use crate::tools::ToolRegistry;
    use asupersync::Cx;
    use oraclemcp_error::{ErrorClass, ErrorEnvelope};
    use oraclemcp_guard::OperatingLevel;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};

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

    struct BusyDispatch;
    impl ToolDispatch for BusyDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            _name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async {
                Err(
                    ErrorEnvelope::new(ErrorClass::Busy, "test lane mailbox is full")
                        .with_retry_after_ms(250),
                )
            })
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
            let session_id = context.http_session_id().map(str::to_owned);
            let principal_key = context.principal_key().map(str::to_owned);
            Box::pin(async move {
                Ok(serde_json::json!({
                    "tool": name,
                    "scopes": scopes,
                    "session_id": session_id,
                    "principal_key": principal_key,
                }))
            })
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

    fn busy_server() -> OracleMcpServer {
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
        OracleMcpServer::new("0.1.0", ToolRegistry::new(), report, Arc::new(BusyDispatch))
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
        let cfg = obs_config(HealthState::new("0.1.0"), Some(metrics), None);
        let resp = handle_http_request(&test_server(), &cfg, get(METRICS_PATH));
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.header("content-type"),
            Some("text/plain; version=0.0.4; charset=utf-8")
        );
        let body = String::from_utf8(resp.body).expect("utf-8");
        assert!(body.contains("mcp_requests_total{tool=\"oracle_query\",status=\"ok\"} 1"));
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
    fn stateful_requests_require_a_known_session_id_after_initialize() {
        let cfg = HttpTransportConfig {
            json_response: true,
            stateful: true,
            session_store: Some(Arc::new(HttpSessionStore::default())),
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
            "Unknown mcp-session-id"
        );

        let valid = HttpRequest::new(
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
        );
        let deleted = handle_http_request(&test_server(), &cfg, delete);
        assert_eq!(deleted.status, 202);

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

    fn self_signed_cert() -> (Vec<u8>, Vec<u8>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        (
            cert.cert.pem().into_bytes(),
            cert.key_pair.serialize_pem().into_bytes(),
        )
    }

    fn ca_cert() -> (rcgen::Certificate, rcgen::KeyPair) {
        let mut params =
            rcgen::CertificateParams::new(vec!["oraclemcp-test-ca".to_owned()]).expect("CA params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().expect("CA key");
        let cert = params.self_signed(&key).expect("self-signed CA");
        (cert, key)
    }

    fn cert_signed_by(
        name: &str,
        ca_cert: &rcgen::Certificate,
        ca_key: &rcgen::KeyPair,
    ) -> (Vec<u8>, Vec<u8>) {
        let params = rcgen::CertificateParams::new(vec![name.to_owned()]).expect("cert params");
        let key = rcgen::KeyPair::generate().expect("cert key");
        let cert = params
            .signed_by(&key, ca_cert, ca_key)
            .expect("certificate signed by test CA");
        (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
    }

    fn pem_certs(pem: &[u8]) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .expect("certificate PEM parses")
    }

    fn pem_key(pem: &[u8]) -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_slice(pem).expect("private-key PEM parses")
    }

    fn tls_client_config(
        server_cert_pem: &[u8],
        client_cert_and_key: Option<(&[u8], &[u8])>,
    ) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in pem_certs(server_cert_pem) {
            roots.add(cert).expect("server cert added to roots");
        }
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("default TLS versions")
        .with_root_certificates(roots);
        match client_cert_and_key {
            Some((cert_pem, key_pem)) => builder
                .with_client_auth_cert(pem_certs(cert_pem), pem_key(key_pem))
                .expect("client auth cert config"),
            None => builder.with_no_client_auth(),
        }
        .into()
    }

    fn spawn_https(
        tls: Arc<TlsServerConfig>,
    ) -> (
        std::net::SocketAddr,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback HTTPS listener");
        let addr = listener.local_addr().expect("listener has local addr");
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_shutdown = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            serve_https_until(
                listener,
                test_server(),
                &HttpTransportConfig {
                    json_response: true,
                    stateful: false,
                    ..Default::default()
                },
                tls,
                server_shutdown,
            )
            .expect("native HTTPS server exits cleanly")
        });
        (addr, shutdown, handle)
    }

    fn https_get(
        addr: std::net::SocketAddr,
        config: Arc<rustls::ClientConfig>,
    ) -> std::io::Result<String> {
        let stream = TcpStream::connect(addr)?;
        let connection =
            rustls::ClientConnection::new(config, ServerName::try_from("localhost").unwrap())
                .map_err(|e| std::io::Error::other(format!("TLS client setup: {e}")))?;
        let mut stream = rustls::StreamOwned::new(connection, stream);
        write!(
            stream,
            "GET {MCP_PATH} HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 0\r\n\r\n"
        )?;
        stream.flush()?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    }

    #[test]
    fn serve_https_accepts_tls_handshake() {
        let (cert, key) = self_signed_cert();
        let tls = crate::tls::build_server_config(&crate::tls::TlsMaterial {
            cert_chain_pem: cert.clone(),
            private_key_pem: key,
            client_ca_pem: None,
        })
        .expect("server-only TLS config builds");
        let (addr, shutdown, handle) = spawn_https(tls);

        let response = https_get(addr, tls_client_config(&cert, None)).expect("HTTPS request");
        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed"));

        shutdown.store(true, Ordering::SeqCst);
        handle.join().expect("HTTPS server thread joins");
    }

    #[test]
    fn serve_https_requires_client_certificate_when_mtls_is_configured() {
        let (server_cert, server_key) = self_signed_cert();
        let (client_ca, client_ca_key) = ca_cert();
        let (client_cert, client_key) =
            cert_signed_by("oraclemcp-test-client", &client_ca, &client_ca_key);
        let tls = crate::tls::build_server_config(&crate::tls::TlsMaterial {
            cert_chain_pem: server_cert.clone(),
            private_key_pem: server_key,
            client_ca_pem: Some(client_ca.pem().into_bytes()),
        })
        .expect("mTLS config builds");
        let (addr, shutdown, handle) = spawn_https(tls);

        let without_client_cert = https_get(addr, tls_client_config(&server_cert, None));
        assert!(
            without_client_cert.is_err(),
            "mTLS listener must reject clients without a certificate"
        );

        let response = https_get(
            addr,
            tls_client_config(&server_cert, Some((&client_cert, &client_key))),
        )
        .expect("mTLS request with client certificate");
        assert!(response.starts_with("HTTP/1.1 405 Method Not Allowed"));

        shutdown.store(true, Ordering::SeqCst);
        handle.join().expect("mTLS server thread joins");
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
        let principal_key = body["result"]["structuredContent"]["principal_key"]
            .as_str()
            .expect("OAuth dispatch context carries a redacted principal key");
        assert!(principal_key.starts_with("oauth:"));
        assert!(
            !principal_key.contains("oracle:read"),
            "principal key must be derived/redacted, not a raw claim or bearer token"
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidatedOAuthRequest {
    scope_grant: ScopeGrant,
    principal_key: String,
}

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
) -> Result<ValidatedOAuthRequest, HttpResponse> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let token = match extract_bearer(request.header("authorization")) {
        Ok(token) => token,
        Err(_) => return Err(oauth_error_response(enforcement, None)),
    };
    enforcement
        .config
        .validate(token, enforcement.verifier.as_ref(), now_unix)
        .map(|scopes| ValidatedOAuthRequest {
            scope_grant: ScopeGrant(scopes),
            principal_key: oauth_principal_key_from_validated_token(token),
        })
        .map_err(|err| oauth_error_response(enforcement, Some(err)))
}

fn oauth_error_response(enforcement: &OAuthEnforcement, err: Option<TokenError>) -> HttpResponse {
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
}

fn oauth_principal_key_from_validated_token(token: &str) -> String {
    let stable_material = jwt_claims_unverified(token)
        .and_then(|claims| {
            let issuer = claims.get("iss").and_then(Value::as_str)?;
            ["sub", "client_id", "azp"].iter().find_map(|claim| {
                claims
                    .get(*claim)
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .map(|value| format!("iss={issuer}\n{claim}={value}"))
            })
        })
        .unwrap_or_else(|| format!("token={}", sha256_hex(token.as_bytes())));
    format!("oauth:{}", sha256_hex(stable_material.as_bytes()))
}

fn jwt_claims_unverified(token: &str) -> Option<Value> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let _signature = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    serde_json::from_slice(&base64url_decode(payload)?).ok()
}

fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0_u32;
    let mut bits = 0_u32;
    for &c in input.as_bytes() {
        if c == b'=' {
            continue;
        }
        let v = u32::from(val(c)?);
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn stateful_principal_key(principal_key: Option<&str>) -> &str {
    principal_key.unwrap_or("anonymous-http")
}

fn enforce_single_principal(
    config: &HttpTransportConfig,
    validated_oauth: Option<&ValidatedOAuthRequest>,
) -> Option<HttpResponse> {
    let guard = config.single_principal_guard.as_ref()?;
    let key =
        stateful_principal_key(validated_oauth.map(|validated| validated.principal_key.as_str()));
    guard
        .admit(key)
        .err()
        .map(|()| single_principal_conflict_response())
}

fn single_principal_conflict_response() -> HttpResponse {
    json_response(
        409,
        &json!({
            "error": "single_principal_active",
            "message": "this pre-lane HTTP server is already bound to another principal",
            "next_step": "start a separate oraclemcp process for the second principal, or wait for the per-principal LaneRuntime release",
        }),
    )
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
    // D1-health: liveness / readiness / metrics probes. Served before OAuth and
    // the Host/Origin guard — these are infra endpoints for load balancers and
    // Prometheus, not the MCP surface, and must answer even while the DB is down
    // or the bearer config is absent. They carry no secrets and no DB data.
    if let Some(response) = handle_observability_route(&config.observability, &request) {
        return response;
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
    let validated_oauth = match &config.oauth {
        Some(enforcement) => match validate_oauth_request(&request, enforcement) {
            Ok(validated) => Some(validated),
            Err(response) => return response,
        },
        None => None,
    };
    if let Some(response) = enforce_single_principal(config, validated_oauth.as_ref()) {
        return response;
    }
    let scope_grant = validated_oauth
        .as_ref()
        .map(|validated| &validated.scope_grant);
    let principal_key = validated_oauth
        .as_ref()
        .map(|validated| validated.principal_key.as_str());
    match request.method.as_str() {
        "DELETE" => handle_mcp_delete(config, &request, stateful_principal_key(principal_key)),
        "POST" => handle_mcp_post(server, config, &request, scope_grant, principal_key),
        "GET" => empty_response(405).with_header("allow", "POST, DELETE"),
        _ => empty_response(405).with_header("allow", "GET, POST, DELETE"),
    }
}

/// Route the D1 observability endpoints. Returns `None` when the path is not an
/// observability path (so normal MCP routing proceeds), or a response otherwise.
///
/// - `/healthz` (liveness): 200 while the process is up — **even if the DB is
///   down**. Reflects only [`HealthState::is_live`].
/// - `/readyz` (readiness): 200 only when the DB-reachability probe succeeds AND
///   the server is not draining; **503 when the DB is unreachable or on
///   shutdown** (the R4 acceptance criterion).
/// - `/metrics`: Prometheus text exposition (no labels carry secrets/binds).
fn handle_observability_route(
    obs: &ObservabilityState,
    request: &HttpRequest,
) -> Option<HttpResponse> {
    match request.path.as_str() {
        HEALTHZ_PATH => {
            let health = obs.health.as_ref()?;
            if request.method != "GET" {
                return Some(empty_response(405).with_header("allow", "GET"));
            }
            let (status, report) = health.liveness();
            Some(json_response(
                status,
                &serde_json::to_value(&report).unwrap_or(Value::Null),
            ))
        }
        READYZ_PATH => {
            let health = obs.health.as_ref()?;
            if request.method != "GET" {
                return Some(empty_response(405).with_header("allow", "GET"));
            }
            // Readiness gates on BOTH the HealthState (drains on shutdown) AND a
            // live DB-reachability probe. The DB gate makes /readyz 503 when the
            // database is unreachable even though the process is still live.
            let health_ready = health.is_ready();
            let db_reachable = obs
                .readiness_probe
                .as_ref()
                .is_none_or(|probe| probe.is_db_reachable());
            let ready = health_ready && db_reachable;
            let status = if ready { 200 } else { 503 };
            let body = json!({
                "status": if ready { "ok" } else { "unavailable" },
                "ready": ready,
                "db_reachable": db_reachable,
                "draining": !health_ready,
            });
            Some(json_response(status, &body))
        }
        METRICS_PATH => {
            let metrics = obs.metrics.as_ref()?;
            if request.method != "GET" {
                return Some(empty_response(405).with_header("allow", "GET"));
            }
            Some(HttpResponse {
                status: 200,
                headers: vec![(
                    "content-type".to_owned(),
                    "text/plain; version=0.0.4; charset=utf-8".to_owned(),
                )],
                body: metrics.prometheus_text().into_bytes(),
            })
        }
        _ => None,
    }
}

fn handle_mcp_delete(
    config: &HttpTransportConfig,
    request: &HttpRequest,
    principal_key: &str,
) -> HttpResponse {
    if config.stateful {
        return match validate_stateful_session(config, request, principal_key) {
            Ok(session_id) => {
                if let Some(store) = &config.session_store {
                    store.remove(session_id);
                }
                empty_response(202)
            }
            Err(response) => response,
        };
    }
    empty_response(202)
}

fn handle_mcp_post(
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    request: &HttpRequest,
    scope_grant: Option<&ScopeGrant>,
    principal_key: Option<&str>,
) -> HttpResponse {
    let session_principal_key = stateful_principal_key(principal_key);
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
    let http_session_id = if config.stateful {
        if method.as_deref() == Some("initialize") {
            Some(new_session_id())
        } else {
            match validate_stateful_session(config, request, session_principal_key) {
                Ok(session_id) => Some(session_id.to_owned()),
                Err(response) => return response,
            }
        }
    } else {
        None
    };
    let mut context = scope_grant
        .map(DispatchContext::with_scope_grant)
        .unwrap_or_default();
    if let Some(session_id) = http_session_id.as_deref() {
        context = context.with_http_session_id(session_id);
    }
    if let Some(principal_key) = principal_key {
        context = context.with_principal_key(principal_key);
    }
    let response = server.handle_jsonrpc_request_with_context(parsed, None, context);
    let Some(response) = response else {
        return empty_response(202);
    };
    if let Some(retry_after_ms) = jsonrpc_busy_retry_after_ms(&response) {
        let retry_after = retry_after_header_seconds(retry_after_ms);
        return json_response(429, &response).with_header("retry-after", &retry_after);
    }
    if config.stateful {
        return sse_response(
            config,
            method.as_deref(),
            response,
            http_session_id,
            session_principal_key,
        );
    }
    json_response(200, &response)
}

fn jsonrpc_busy_retry_after_ms(response: &Value) -> Option<u64> {
    let result = response.get("result")?;
    if !result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return None;
    }
    let structured = result.get("structuredContent")?;
    if structured.get("error_class").and_then(Value::as_str) != Some("BUSY") {
        return None;
    }
    Some(
        structured
            .get("retry_after_ms")
            .and_then(Value::as_u64)
            .unwrap_or(crate::admission::DEFAULT_RETRY_AFTER_MS),
    )
}

fn retry_after_header_seconds(ms: u64) -> String {
    (ms.saturating_add(999) / 1000).max(1).to_string()
}

fn validate_stateful_session<'a>(
    config: &HttpTransportConfig,
    request: &'a HttpRequest,
    principal_key: &str,
) -> Result<&'a str, HttpResponse> {
    let Some(session_id) = request.header("mcp-session-id") else {
        return Err(HttpResponse {
            status: 400,
            headers: vec![],
            body: b"Missing mcp-session-id".to_vec(),
        });
    };
    let owner = config
        .session_store
        .as_ref()
        .and_then(|store| store.principal_for(session_id));
    match owner.as_deref() {
        Some(owner) if owner == principal_key => Ok(session_id),
        Some(_) => Err(HttpResponse {
            status: 403,
            headers: vec![],
            body: b"mcp-session-id is bound to another principal".to_vec(),
        }),
        None => Err(HttpResponse {
            status: 404,
            headers: vec![],
            body: b"Unknown mcp-session-id".to_vec(),
        }),
    }
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

fn sse_response(
    config: &HttpTransportConfig,
    method: Option<&str>,
    response: Value,
    initialized_session_id: Option<String>,
    principal_key: &str,
) -> HttpResponse {
    let mut body = Vec::new();
    let session_id = if method == Some("initialize") {
        write_sse_event(&mut body, Some("0"), Some(3000), Some(&Value::Null));
        write_sse_event(&mut body, None, None, Some(&response));
        initialized_session_id.or_else(|| Some(new_session_id()))
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
        if let Some(store) = &config.session_store {
            store.insert(session_id.clone(), principal_key.to_owned());
        }
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
    // Mint an unpredictable UUIDv4-shaped id from the OS CSPRNG. A monotonic
    // counter would let a client guess other sessions' ids; the session-id is a
    // bearer credential for the stateful Streamable HTTP transport, so it must
    // carry full entropy. Validation is pure membership (no format parsing), so
    // the shape is cosmetic — but we keep the canonical UUIDv4 layout (version
    // nibble `4`, variant bits `10`).
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("OS random source required for HTTP session ids");
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10xx
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
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
    let config = Arc::new(listener_config(config));
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

/// Serve the MCP server over TLS-terminating Streamable HTTPS on `listener`.
///
/// # Errors
/// Returns fatal listener or connection write errors. Individual malformed
/// client requests are answered with HTTP errors and the listener continues.
pub fn serve_https(
    listener: TcpListener,
    server: OracleMcpServer,
    config: &HttpTransportConfig,
    tls: Arc<TlsServerConfig>,
) -> std::io::Result<()> {
    serve_https_until(
        listener,
        server,
        config,
        tls,
        Arc::new(AtomicBool::new(false)),
    )
}

/// Serve HTTPS until `shutdown` becomes true, then stop accepting new
/// connections and join active request workers before returning.
pub fn serve_https_until(
    listener: TcpListener,
    server: OracleMcpServer,
    config: &HttpTransportConfig,
    tls: Arc<TlsServerConfig>,
    shutdown: Arc<AtomicBool>,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    let config = Arc::new(listener_config(config));
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let server = server.clone();
                let config = Arc::clone(&config);
                let tls = Arc::clone(&tls);
                workers.push(std::thread::spawn(move || {
                    if let Err(e) = handle_tls_connection(stream, &server, &config, tls) {
                        tracing::debug!(error = %e, "native HTTPS connection failed");
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

fn listener_config(config: &HttpTransportConfig) -> HttpTransportConfig {
    let mut config = config.clone();
    if config.stateful && config.session_store.is_none() {
        config.session_store = Some(Arc::new(HttpSessionStore::default()));
    }
    config
}

fn handle_connection(
    mut stream: TcpStream,
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(CONNECTION_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_IO_TIMEOUT))?;
    handle_stream(&mut stream, server, config)
}

fn handle_tls_connection(
    stream: TcpStream,
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    tls: Arc<TlsServerConfig>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(CONNECTION_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_IO_TIMEOUT))?;
    let connection = ServerConnection::new(tls).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("TLS setup: {e}"))
    })?;
    let mut stream = StreamOwned::new(connection, stream);
    let result = handle_stream(&mut stream, server, config);
    stream.conn.send_close_notify();
    let _ = stream.flush();
    result
}

fn handle_stream(
    stream: &mut (impl Read + Write),
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
) -> std::io::Result<()> {
    let response = match read_http_request(stream) {
        Ok(Some(request)) => handle_http_request(server, config, request),
        Ok(None) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => HttpResponse {
            status: 400,
            headers: vec![],
            body: e.to_string().into_bytes(),
        },
        Err(e) => return Err(e),
    };
    write_http_response(stream, &response)
}

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const CONNECTION_IO_TIMEOUT: Duration = Duration::from_secs(30);

fn read_http_request(stream: &mut impl Read) -> std::io::Result<Option<HttpRequest>> {
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

fn write_http_response(stream: &mut impl Write, response: &HttpResponse) -> std::io::Result<()> {
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
