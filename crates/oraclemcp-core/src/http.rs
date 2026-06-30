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
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use oraclemcp_auth::{
    HttpGuardError, HttpGuardPolicy, ResourceServerConfig, SignatureVerifier, TokenError,
    extract_bearer,
};
use oraclemcp_telemetry::{HealthState, Metrics};
use parking_lot::{Condvar, Mutex};
use rustls::{ServerConnection, StreamOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::server::{DispatchCloseReason, DispatchContext, OracleMcpServer};
use crate::tls::TlsServerConfig;

/// The MCP endpoint path the Streamable HTTP transport is mounted at.
pub const MCP_PATH: &str = "/mcp";
/// The versioned operator API prefix. FN0 only installs routing and query
/// parsing; later WP-P beads fill in the schema-first API under this prefix.
pub const OPERATOR_API_PREFIX: &str = "/operator/v1";
/// The RFC 9728 protected-resource-metadata well-known path.
pub const PROTECTED_RESOURCE_METADATA_PATH: &str = "/.well-known/oauth-protected-resource";
/// Kubernetes-style liveness probe path (D1-health). Process-up only.
pub const HEALTHZ_PATH: &str = "/healthz";
/// Kubernetes-style readiness probe path (D1-health). DB-reachable + not draining.
pub const READYZ_PATH: &str = "/readyz";
/// Prometheus metrics-scrape path (D1-health / D1-metrics).
pub const METRICS_PATH: &str = "/metrics";
/// Default idle TTL for stateful Streamable HTTP sessions.
pub const DEFAULT_STATEFUL_IDLE_TTL_SECONDS: u64 = 900;

const STATEFUL_IDLE_REAP_INTERVAL: Duration = Duration::from_secs(1);
const SSE_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const STATEFUL_SESSION_COOKIE: &str = "oraclemcp_mcp_session";

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
#[derive(Clone, Debug)]
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
    /// Idle timeout for stateful sessions. A zero duration disables the
    /// watchdog. The watchdog closes stale lanes through [`HttpSessionLifecycle`]
    /// and never touches dispatcher/connection state directly.
    pub stateful_idle_ttl: Duration,
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
    /// Buffered stateful Streamable HTTP responses. Listener wrappers install a
    /// store automatically when `stateful` is true so GET can replay results by
    /// cursor / Last-Event-ID.
    pub result_store: Option<Arc<HttpResultStore>>,
    /// Stateful session lifecycle hook. In served stateful mode this points at
    /// the lane registry so HTTP DELETE can terminate the owning lane instead
    /// of only forgetting the session id.
    pub session_lifecycle: Option<Arc<dyn HttpSessionLifecycle>>,
    /// N8 interim guard: until per-principal lanes exist, a served HTTP process
    /// may bind to one authenticated principal only. A second principal is
    /// refused before it can touch the shared dispatcher/session state.
    pub single_principal_guard: Option<SinglePrincipalGuard>,
    /// Health/metrics observability endpoints (D1; off by default — `None`
    /// fields make the corresponding route return 404 / not be advertised).
    pub observability: ObservabilityState,
}

impl Default for HttpTransportConfig {
    fn default() -> Self {
        Self {
            allowed_hosts: Vec::new(),
            allowed_origins: Vec::new(),
            json_response: false,
            stateful: false,
            stateful_idle_ttl: Duration::from_secs(DEFAULT_STATEFUL_IDLE_TTL_SECONDS),
            resource_metadata: None,
            oauth: None,
            session_store: None,
            result_store: None,
            session_lifecycle: None,
            single_principal_guard: None,
            observability: ObservabilityState::default(),
        }
    }
}

/// Lifecycle hook for stateful Streamable HTTP sessions.
pub trait HttpSessionLifecycle: std::fmt::Debug + Send + Sync {
    /// Close the lane/resources bound to `session_id` and `principal_key`.
    ///
    /// Returns `true` when a live resource was found and closed.
    fn close_session(&self, session_id: &str, principal_key: &str) -> bool;

    /// Close the lane/resources bound to a session for a specific lifecycle
    /// reason. Implementations that do not distinguish reasons can rely on the
    /// default adapter.
    fn close_session_with_reason(
        &self,
        session_id: &str,
        principal_key: &str,
        _reason: DispatchCloseReason,
    ) -> bool {
        self.close_session(session_id, principal_key)
    }

    /// Close every live stateful session during listener shutdown.
    fn close_all_sessions(&self) {}
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
        let mut active = self.active_principal_key.lock();
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
    owners: Mutex<HashMap<String, HttpSessionEntry>>,
}

#[derive(Debug)]
struct HttpSessionEntry {
    principal_key: String,
    last_seen: Instant,
}

impl HttpSessionStore {
    fn insert(&self, id: String, principal_key: String) {
        self.owners.lock().insert(
            id,
            HttpSessionEntry {
                principal_key,
                last_seen: Instant::now(),
            },
        );
    }

    fn principal_for(&self, id: &str) -> Option<String> {
        let mut owners = self.owners.lock();
        let entry = owners.get_mut(id)?;
        entry.last_seen = Instant::now();
        Some(entry.principal_key.clone())
    }

    fn remove(&self, id: &str) -> bool {
        self.owners.lock().remove(id).is_some()
    }

    fn reap_idle(&self, idle_ttl: Duration) -> Vec<(String, String)> {
        if idle_ttl.is_zero() {
            return Vec::new();
        }
        self.reap_idle_at(idle_ttl, Instant::now())
    }

    fn reap_idle_at(&self, idle_ttl: Duration, now: Instant) -> Vec<(String, String)> {
        let mut owners = self.owners.lock();
        let expired: Vec<String> = owners
            .iter()
            .filter(|(_, entry)| now.duration_since(entry.last_seen) >= idle_ttl)
            .map(|(session_id, _)| session_id.clone())
            .collect();
        expired
            .into_iter()
            .filter_map(|session_id| {
                owners
                    .remove(&session_id)
                    .map(|entry| (session_id, entry.principal_key))
            })
            .collect()
    }

    #[cfg(test)]
    fn force_idle_for_test(&self, id: &str, idle_for: Duration) {
        let mut owners = self.owners.lock();
        if let Some(entry) = owners.get_mut(id) {
            let now = Instant::now();
            entry.last_seen = now.checked_sub(idle_for).unwrap_or(now);
        }
    }
}

const MAX_BUFFERED_MCP_EVENTS_PER_SESSION: usize = 128;

/// Stateful Streamable HTTP result buffer.
///
/// POST still returns a response for compatible clients, but every stateful
/// JSON-RPC response is also retained here under the MCP session id. GET can
/// then replay responses after a cursor, which is the substrate later streaming
/// and disconnect/resume work builds on.
#[derive(Debug, Default)]
pub struct HttpResultStore {
    state: Mutex<HttpResultStoreState>,
    changed: Condvar,
}

#[derive(Debug, Default)]
struct HttpResultStoreState {
    sessions: HashMap<String, Vec<HttpBufferedEvent>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HttpBufferedEvent {
    id: String,
    event: Option<&'static str>,
    data: Value,
}

impl HttpBufferedEvent {
    fn data(id: String, data: Value) -> Self {
        Self {
            id,
            event: None,
            data,
        }
    }

    fn gap(id: String, requested_cursor: Option<&str>, oldest_event_id: &str) -> Self {
        Self {
            id,
            event: Some("stream-gap"),
            data: json!({
                "type": "stream_gap",
                "message": "one or more Streamable HTTP events were dropped before this resume point",
                "requested_last_event_id": requested_cursor.unwrap_or(""),
                "oldest_event_id": oldest_event_id,
                "next_step": "continue from the retained events in this stream; restart the MCP session if the missing range is required",
            }),
        }
    }
}

impl HttpResultStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn ensure_session(&self, session_id: &str) {
        self.state
            .lock()
            .sessions
            .entry(session_id.to_owned())
            .or_default();
    }

    fn append_response(&self, session_id: &str, data: Value) -> String {
        let mut state = self.state.lock();
        let events = state.sessions.entry(session_id.to_owned()).or_default();
        let next_seq = events
            .last()
            .and_then(|event| stream_event_sequence(&event.id))
            .unwrap_or(0)
            .saturating_add(1);
        let id = format!("{next_seq}/0");
        events.push(HttpBufferedEvent::data(id.clone(), data));
        if events.len() > MAX_BUFFERED_MCP_EVENTS_PER_SESSION {
            let overflow = events.len() - MAX_BUFFERED_MCP_EVENTS_PER_SESSION;
            events.drain(..overflow);
        }
        drop(state);
        self.changed.notify_all();
        id
    }

    fn events_after(
        &self,
        session_id: &str,
        cursor: Option<&str>,
        gap_on_expired_cursor: bool,
    ) -> Result<Vec<HttpBufferedEvent>, HttpResponse> {
        let after_seq = parse_stream_cursor(cursor)?;
        let state = self.state.lock();
        let Some(events) = state.sessions.get(session_id) else {
            return Ok(Vec::new());
        };
        events_after_sequence(events, after_seq, cursor, gap_on_expired_cursor)
    }

    fn wait_events_after(
        &self,
        session_id: &str,
        after_seq: u64,
        timeout: Duration,
    ) -> HttpResultWait {
        let mut state = self.state.lock();
        loop {
            let Some(events) = state.sessions.get(session_id) else {
                return HttpResultWait::Closed;
            };
            let cursor = format!("{after_seq}/0");
            match events_after_sequence(events, after_seq, Some(&cursor), true) {
                Ok(events) if !events.is_empty() => return HttpResultWait::Events(events),
                Ok(_) => {}
                Err(_) => return HttpResultWait::Closed,
            }
            let wait = self.changed.wait_for(&mut state, timeout);
            if wait.timed_out() {
                return HttpResultWait::Timeout;
            }
        }
    }

    fn remove_session(&self, session_id: &str) {
        let mut state = self.state.lock();
        let removed = state.sessions.remove(session_id).is_some();
        drop(state);
        if removed {
            self.changed.notify_all();
        }
    }

    fn close_all(&self) {
        let mut state = self.state.lock();
        if !state.sessions.is_empty() {
            state.sessions.clear();
            drop(state);
            self.changed.notify_all();
        }
    }
}

enum HttpResultWait {
    Events(Vec<HttpBufferedEvent>),
    Closed,
    Timeout,
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

    struct AtCapacityDispatch;
    impl ToolDispatch for AtCapacityDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            _name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async {
                Err(
                    ErrorEnvelope::new(ErrorClass::AtCapacity, "stateful lane capacity exhausted")
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

    struct LaneThreadDispatch;
    impl ToolDispatch for LaneThreadDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            let tool = name.to_owned();
            Box::pin(async move {
                Ok(serde_json::json!({
                    "tool": tool,
                    "thread": format!("{:?}", std::thread::current().id()),
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

    fn at_capacity_server() -> OracleMcpServer {
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
            Arc::new(AtCapacityDispatch),
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

    #[test]
    fn request_target_preserves_and_decodes_query_string() {
        let request = HttpRequest::new(
            "GET",
            "/mcp?cursor=1%2F0&status=active+lane&status=blocked",
            [("host", "127.0.0.1")],
            Vec::new(),
        );

        assert_eq!(request.path, MCP_PATH);
        assert_eq!(
            request.query_string.as_deref(),
            Some("cursor=1%2F0&status=active+lane&status=blocked")
        );
        assert_eq!(request.query_param("cursor"), Some("1/0"));
        let statuses: Vec<&str> = request.query_values("status").collect();
        assert_eq!(statuses, vec!["active lane", "blocked"]);
    }

    #[test]
    fn operator_api_routes_are_typed_json_404_and_parse_query() {
        let response = handle_http_request(
            &test_server(),
            &HttpTransportConfig::default(),
            HttpRequest::new(
                "GET",
                "/operator/v1/sessions?cursor=4%2F0&status=active&profile=prod",
                [("host", "127.0.0.1"), ("accept", "application/json")],
                Vec::new(),
            ),
        );

        assert_eq!(response.status, 404);
        assert_eq!(response.header("content-type"), Some("application/json"));
        let body = response_json(&response);
        assert_eq!(body["error"], serde_json::json!("operator_route_not_found"));
        assert_eq!(body["query"]["cursor"], serde_json::json!("4/0"));
        assert_eq!(
            body["query"]["filters"]["status"],
            serde_json::json!("active")
        );
        assert_eq!(
            body["query"]["filters"]["profile"],
            serde_json::json!("prod")
        );

        let bad_host = handle_http_request(
            &test_server(),
            &HttpTransportConfig::default(),
            HttpRequest::new(
                "GET",
                "/operator/v1/sessions",
                [("host", "attacker.example"), ("accept", "application/json")],
                Vec::new(),
            ),
        );
        assert_eq!(bad_host.status, 403);
    }

    #[cfg(not(feature = "dashboard-bundle"))]
    #[test]
    fn dashboard_bundle_is_absent_from_default_build() {
        let response = handle_http_request(
            &test_server(),
            &HttpTransportConfig::default(),
            HttpRequest::new(
                "GET",
                "/",
                [("host", "127.0.0.1"), ("accept", "text/html")],
                Vec::new(),
            ),
        );

        assert_eq!(response.status, 404);
    }

    #[cfg(feature = "dashboard-bundle")]
    #[test]
    fn dashboard_bundle_serves_html_without_api_fallback() {
        let response = handle_http_request(
            &test_server(),
            &HttpTransportConfig::default(),
            HttpRequest::new(
                "GET",
                "/",
                [("host", "127.0.0.1"), ("accept", "text/html")],
                Vec::new(),
            ),
        );

        assert_eq!(response.status, 200);
        assert_eq!(
            response.header("content-type"),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(response.header("x-content-type-options"), Some("nosniff"));
        let html = String::from_utf8(response.body).expect("dashboard html is UTF-8");
        assert!(html.contains("oraclemcp"));

        let api = handle_http_request(
            &test_server(),
            &HttpTransportConfig::default(),
            HttpRequest::new(
                "GET",
                "/operator/v1/sessions",
                [("host", "127.0.0.1"), ("accept", "text/html")],
                Vec::new(),
            ),
        );
        assert_eq!(api.status, 406);
    }

    #[test]
    fn mcp_post_enforces_accept_and_content_type_negotiation() {
        let cfg = HttpTransportConfig {
            json_response: true,
            ..Default::default()
        };
        let unacceptable = HttpRequest::new(
            "POST",
            MCP_PATH,
            [
                ("host", "127.0.0.1"),
                ("content-type", "application/json"),
                ("accept", "text/html"),
            ],
            init_body().to_string().into_bytes(),
        );
        let unacceptable = handle_http_request(&test_server(), &cfg, unacceptable);
        assert_eq!(unacceptable.status, 406);

        let wrong_content_type = HttpRequest::new(
            "POST",
            MCP_PATH,
            [
                ("host", "127.0.0.1"),
                ("content-type", "text/plain"),
                ("accept", "application/json"),
            ],
            init_body().to_string().into_bytes(),
        );
        let wrong_content_type = handle_http_request(&test_server(), &cfg, wrong_content_type);
        assert_eq!(wrong_content_type.status, 415);
    }

    #[test]
    fn stateless_delete_is_method_not_allowed_not_false_accepted() {
        let response = handle_http_request(
            &test_server(),
            &HttpTransportConfig::default(),
            HttpRequest::new("DELETE", MCP_PATH, [("host", "127.0.0.1")], Vec::new()),
        );

        assert_eq!(response.status, 405);
        assert_eq!(response.header("allow"), Some("POST"));
    }

    #[test]
    fn stateful_get_replays_buffered_lane_results_by_cursor() {
        let result_store = Arc::new(HttpResultStore::new());
        let cfg = HttpTransportConfig {
            json_response: true,
            stateful: true,
            session_store: Some(Arc::new(HttpSessionStore::default())),
            result_store: Some(Arc::clone(&result_store)),
            ..Default::default()
        };
        let lane: Arc<dyn ToolDispatch> = Arc::new(crate::lane::LaneRuntime::spawn(
            "http-buffer-test",
            Arc::new(LaneThreadDispatch),
            4,
        ));
        let server = OracleMcpServer::new(
            "0.1.0",
            ToolRegistry::new(),
            CapabilitiesReport::new(
                "0.1.0",
                vec![],
                OperatingLevel::ReadOnly,
                FeatureTiers {
                    live_db: false,
                    engine: true,
                    http_transport: true,
                },
            ),
            lane,
        );

        let caller_thread = format!("{:?}", std::thread::current().id());
        let init = handle_http_request(&server, &cfg, post(&init_body()));
        let session_id = init
            .header("mcp-session-id")
            .expect("stateful init session id");
        let call = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": { "name": "oracle_query", "arguments": { "sql": "SELECT 1 FROM dual" } }
        });
        let post = HttpRequest::new(
            "POST",
            MCP_PATH,
            [
                ("host", "127.0.0.1"),
                ("content-type", "application/json"),
                ("accept", "application/json, text/event-stream"),
                ("mcp-session-id", session_id),
            ],
            call.to_string().into_bytes(),
        );
        let post = handle_http_request(&server, &cfg, post);
        assert_eq!(post.status, 200);
        let post_body = String::from_utf8(post.body).expect("SSE utf-8");
        assert!(post_body.contains("id: 1/0"));
        assert!(
            !post_body.contains(&caller_thread),
            "tool body must run on the lane thread, not the HTTP caller thread"
        );

        let replay = HttpRequest::new(
            "GET",
            "/mcp?cursor=0",
            [
                ("host", "127.0.0.1"),
                ("accept", "text/event-stream"),
                ("mcp-session-id", session_id),
            ],
            Vec::new(),
        );
        let replay = handle_http_request(&server, &cfg, replay);
        assert_eq!(replay.status, 200);
        assert_eq!(replay.header("content-type"), Some("text/event-stream"));
        let replay_body = String::from_utf8(replay.body).expect("SSE utf-8");
        assert!(replay_body.contains("id: 1/0"));
        assert!(replay_body.contains("\"id\":9"));
        assert!(replay_body.contains("\"tool\":\"oracle_query\""));

        let after = HttpRequest::new(
            "GET",
            "/mcp?cursor=1/0",
            [
                ("host", "127.0.0.1"),
                ("accept", "text/event-stream"),
                ("mcp-session-id", session_id),
            ],
            Vec::new(),
        );
        let after = handle_http_request(&server, &cfg, after);
        let after_body = String::from_utf8(after.body).expect("SSE utf-8");
        assert!(
            !after_body.contains("\"id\":9"),
            "cursor after the buffered event must not replay it again"
        );
    }

    #[test]
    fn stateful_get_reports_typed_expiry_when_cursor_falls_out_of_ring() {
        let session_store = Arc::new(HttpSessionStore::default());
        let result_store = Arc::new(HttpResultStore::new());
        let session_id = "expired-cursor-session";
        session_store.insert(session_id.to_owned(), "anonymous-http".to_owned());
        for i in 0..=MAX_BUFFERED_MCP_EVENTS_PER_SESSION {
            result_store.append_response(session_id, serde_json::json!({ "seq": i }));
        }
        let cfg = HttpTransportConfig {
            stateful: true,
            session_store: Some(session_store),
            result_store: Some(result_store),
            ..Default::default()
        };

        let response = handle_http_request(
            &test_server(),
            &cfg,
            HttpRequest::new(
                "GET",
                "/mcp?cursor=0",
                [
                    ("host", "127.0.0.1"),
                    ("accept", "text/event-stream"),
                    ("mcp-session-id", session_id),
                ],
                Vec::new(),
            ),
        );

        assert_eq!(response.status, 410);
        let body: Value = serde_json::from_slice(&response.body).expect("json expiry body");
        assert_eq!(body["error"], serde_json::json!("stream_cursor_expired"));
        assert_eq!(body["oldest_event_id"], serde_json::json!("2/0"));
        assert!(
            body["next_step"]
                .as_str()
                .is_some_and(|message| message.contains("restart the MCP session"))
        );
    }

    #[test]
    fn stateful_get_last_event_id_reports_gap_marker_for_slow_consumer() {
        let session_store = Arc::new(HttpSessionStore::default());
        let result_store = Arc::new(HttpResultStore::new());
        let session_id = "slow-consumer-session";
        session_store.insert(session_id.to_owned(), "anonymous-http".to_owned());
        for i in 0..=MAX_BUFFERED_MCP_EVENTS_PER_SESSION {
            result_store.append_response(session_id, serde_json::json!({ "seq": i }));
        }
        let cfg = HttpTransportConfig {
            stateful: true,
            session_store: Some(session_store),
            result_store: Some(result_store),
            ..Default::default()
        };

        let response = handle_http_request(
            &test_server(),
            &cfg,
            HttpRequest::new(
                "GET",
                MCP_PATH,
                [
                    ("host", "127.0.0.1"),
                    ("accept", "text/event-stream"),
                    ("mcp-session-id", session_id),
                    ("last-event-id", "0/0"),
                ],
                Vec::new(),
            ),
        );

        assert_eq!(response.status, 200);
        assert_eq!(response.header("content-type"), Some("text/event-stream"));
        let body = String::from_utf8(response.body).expect("SSE utf-8");
        assert!(body.contains("event: stream-gap"));
        assert!(body.contains("id: 1/gap"));
        assert!(body.contains("\"type\":\"stream_gap\""));
        assert!(body.contains("\"oldest_event_id\":\"2/0\""));
        assert!(body.contains("\"seq\":128"));
    }

    #[test]
    fn served_stateful_get_streams_chunked_sse_until_session_closes() {
        fn read_until(stream: &mut TcpStream, raw: &mut Vec<u8>, needle: &[u8]) {
            let mut buf = [0_u8; 512];
            while !raw.windows(needle.len()).any(|window| window == needle) {
                let n = stream
                    .read(&mut buf)
                    .expect("streaming SSE response remains readable");
                assert_ne!(n, 0, "streaming SSE response ended before expected data");
                raw.extend_from_slice(&buf[..n]);
            }
        }

        let session_store = Arc::new(HttpSessionStore::default());
        let result_store = Arc::new(HttpResultStore::new());
        let session_id = "served-stream-session";
        session_store.insert(session_id.to_owned(), "anonymous-http".to_owned());
        result_store.ensure_session(session_id);
        let config = HttpTransportConfig {
            stateful: true,
            session_store: Some(Arc::clone(&session_store)),
            result_store: Some(Arc::clone(&result_store)),
            ..Default::default()
        };
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind streaming test listener");
        let addr = listener.local_addr().expect("streaming listener address");
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread_shutdown = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            serve_http_until(listener, test_server(), &config, thread_shutdown)
                .expect("streaming HTTP listener exits cleanly");
        });

        let mut stream = TcpStream::connect(addr).expect("connect to streaming listener");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set streaming read timeout");
        let request = format!(
            "GET {MCP_PATH} HTTP/1.1\r\nhost: 127.0.0.1\r\naccept: text/event-stream\r\nmcp-session-id: {session_id}\r\ncontent-length: 0\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .expect("write streaming GET");

        let mut raw = Vec::new();
        read_until(&mut stream, &mut raw, b"\r\n\r\n");
        let text = String::from_utf8_lossy(&raw);
        let head = text
            .split_once("\r\n\r\n")
            .map(|(head, _)| head)
            .expect("streaming HTTP response head");
        assert!(head.contains("transfer-encoding: chunked"));
        assert!(!head.contains("content-length:"));

        result_store.append_response(session_id, serde_json::json!({ "seq": 1 }));
        read_until(&mut stream, &mut raw, b"\"seq\":1");
        let text = String::from_utf8_lossy(&raw);
        assert!(text.contains("content-type: text/event-stream"));
        assert!(text.contains("id: 1/0"));

        result_store.remove_session(session_id);
        shutdown.store(true, Ordering::SeqCst);
        drop(stream);
        handle.join().expect("streaming listener thread joins");
    }

    #[test]
    fn stateful_idle_reaper_closes_by_timeout_and_clears_buffers() {
        #[derive(Debug, Default)]
        struct RecordingLifecycle {
            closed: std::sync::Mutex<Vec<(String, String, DispatchCloseReason)>>,
        }

        impl HttpSessionLifecycle for RecordingLifecycle {
            fn close_session(&self, session_id: &str, principal_key: &str) -> bool {
                self.close_session_with_reason(
                    session_id,
                    principal_key,
                    DispatchCloseReason::SessionDelete,
                )
            }

            fn close_session_with_reason(
                &self,
                session_id: &str,
                principal_key: &str,
                reason: DispatchCloseReason,
            ) -> bool {
                self.closed.lock().expect("test lifecycle mutex").push((
                    session_id.to_owned(),
                    principal_key.to_owned(),
                    reason,
                ));
                true
            }
        }

        let session_store = Arc::new(HttpSessionStore::default());
        let result_store = Arc::new(HttpResultStore::new());
        let lifecycle = Arc::new(RecordingLifecycle::default());
        let session_id = "idle-session";
        session_store.insert(session_id.to_owned(), "principal-a".to_owned());
        result_store.append_response(session_id, serde_json::json!({ "stale": true }));
        session_store.force_idle_for_test(session_id, Duration::from_secs(901));
        let cfg = HttpTransportConfig {
            stateful: true,
            stateful_idle_ttl: Duration::from_secs(900),
            session_store: Some(Arc::clone(&session_store)),
            result_store: Some(Arc::clone(&result_store)),
            session_lifecycle: Some(lifecycle.clone()),
            ..Default::default()
        };

        assert_eq!(reap_idle_stateful_sessions(&cfg), 1);
        assert!(session_store.principal_for(session_id).is_none());
        assert!(
            result_store
                .events_after(session_id, None, false)
                .expect("removed session has no buffered events")
                .is_empty()
        );
        assert_eq!(
            lifecycle
                .closed
                .lock()
                .expect("test lifecycle mutex")
                .as_slice(),
            &[(
                session_id.to_owned(),
                "principal-a".to_owned(),
                DispatchCloseReason::Timeout
            )]
        );
        assert_eq!(
            reap_idle_stateful_sessions(&cfg),
            0,
            "reaping the same idle session is idempotent"
        );
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

    #[test]
    fn at_capacity_tool_result_is_http_429_backpressure() {
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
        let response = handle_http_request(&at_capacity_server(), &cfg, post(&body));

        assert_eq!(response.status, 429);
        assert_eq!(response.header("retry-after"), Some("1"));
        let body = response_json(&response);
        assert_eq!(
            body["result"]["structuredContent"]["error_class"],
            serde_json::json!("AT_CAPACITY")
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
    fn stateful_initialize_sets_strict_session_cookie() {
        let cfg = HttpTransportConfig {
            json_response: true,
            stateful: true,
            session_store: Some(Arc::new(HttpSessionStore::default())),
            result_store: Some(Arc::new(HttpResultStore::new())),
            ..Default::default()
        };
        let response = handle_http_request(&test_server(), &cfg, post(&init_body()));
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
    }

    #[test]
    fn oauth_stateful_get_accepts_strict_cookie_with_origin_only() {
        let session_store = Arc::new(HttpSessionStore::default());
        let result_store = Arc::new(HttpResultStore::new());
        let cfg = HttpTransportConfig {
            json_response: true,
            stateful: true,
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
        assert!(body.contains("id: 1/0"));
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
    pub query_string: Option<String>,
    pub query: Vec<(String, String)>,
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
        let (path, query_string, query) = split_request_target(&path.into());
        let headers = headers
            .into_iter()
            .map(|(name, value)| (name.into().to_ascii_lowercase(), value.into()))
            .collect();
        Self {
            method: method.into().to_ascii_uppercase(),
            path,
            query_string,
            query,
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

    #[must_use]
    pub fn query_param(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
    }

    pub fn query_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.query.iter().filter_map(move |(candidate, value)| {
            if candidate == name {
                Some(value.as_str())
            } else {
                None
            }
        })
    }
}

fn split_request_target(target: &str) -> (String, Option<String>, Vec<(String, String)>) {
    let (path, query_string) = target
        .split_once('?')
        .map_or((target, None), |(path, query)| {
            (path, Some(query.to_owned()))
        });
    let query = query_string
        .as_deref()
        .map(parse_query_string)
        .unwrap_or_default();
    (path.to_owned(), query_string, query)
}

fn parse_query_string(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (name, value) = part.split_once('=').unwrap_or((part, ""));
            (percent_decode_query(name), percent_decode_query(value))
        })
        .collect()
}

fn percent_decode_query(input: &str) -> String {
    fn hex(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            b'A'..=b'F' => Some(value - b'A' + 10),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                    out.push((hi << 4) | lo);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
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

fn stateful_session_cookie(request: &HttpRequest) -> Option<&str> {
    request
        .header("cookie")
        .and_then(|cookie| cookie_value(cookie, STATEFUL_SESSION_COOKIE))
}

fn cookie_value<'a>(cookie: &'a str, name: &str) -> Option<&'a str> {
    cookie.split(';').find_map(|part| {
        let (candidate, value) = part.trim().split_once('=')?;
        (candidate == name && !value.is_empty()).then_some(value)
    })
}

fn stateful_session_id(request: &HttpRequest, allow_cookie: bool) -> Option<&str> {
    request.header("mcp-session-id").or_else(|| {
        allow_cookie
            .then(|| stateful_session_cookie(request))
            .flatten()
    })
}

fn stateful_session_cookie_header(session_id: &str) -> String {
    format!("{STATEFUL_SESSION_COOKIE}={session_id}; Path={MCP_PATH}; HttpOnly; SameSite=Strict")
}

fn cookie_get_requires_origin(request: &HttpRequest) -> Option<HttpResponse> {
    if request.method == "GET"
        && request.path == MCP_PATH
        && stateful_session_cookie(request).is_some()
        && request.header("origin").is_none()
    {
        return Some(HttpResponse {
            status: 403,
            headers: vec![],
            body: b"Missing Origin header for cookie-authenticated SSE".to_vec(),
        });
    }
    None
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HttpRoute {
    ProtectedResourceMetadata,
    Observability,
    Mcp,
    OperatorApi,
    NotFound,
}

fn route_for(path: &str) -> HttpRoute {
    match path {
        PROTECTED_RESOURCE_METADATA_PATH => HttpRoute::ProtectedResourceMetadata,
        HEALTHZ_PATH | READYZ_PATH | METRICS_PATH => HttpRoute::Observability,
        MCP_PATH => HttpRoute::Mcp,
        OPERATOR_API_PREFIX => HttpRoute::OperatorApi,
        _ if path
            .strip_prefix(OPERATOR_API_PREFIX)
            .is_some_and(|suffix| suffix.starts_with('/')) =>
        {
            HttpRoute::OperatorApi
        }
        _ => HttpRoute::NotFound,
    }
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

enum HttpExchange {
    Buffered(HttpResponse),
    SseStream(HttpSseStream),
}

impl HttpExchange {
    fn into_buffered_response(self) -> HttpResponse {
        match self {
            Self::Buffered(response) => response,
            Self::SseStream(stream) => stream.into_buffered_response(),
        }
    }
}

/// Handle one parsed native HTTP request.
#[must_use]
pub fn handle_http_request(
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    request: HttpRequest,
) -> HttpResponse {
    handle_http_exchange(server, config, request, false).into_buffered_response()
}

fn handle_http_exchange(
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    request: HttpRequest,
    allow_streaming_get: bool,
) -> HttpExchange {
    match route_for(&request.path) {
        HttpRoute::ProtectedResourceMetadata => {
            if request.method != "GET" {
                return HttpExchange::Buffered(empty_response(405).with_header("allow", "GET"));
            }
            return HttpExchange::Buffered(match &config.resource_metadata {
                Some(meta) => json_response(200, meta),
                None => empty_response(404),
            });
        }
        // D1-health: liveness / readiness / metrics probes. Served before OAuth
        // and the Host/Origin guard — these are infra endpoints for load
        // balancers and Prometheus, not the MCP surface, and must answer even
        // while the DB is down or the bearer config is absent. They carry no
        // secrets and no DB data.
        HttpRoute::Observability => {
            return HttpExchange::Buffered(
                handle_observability_route(&config.observability, &request)
                    .unwrap_or_else(|| empty_response(404)),
            );
        }
        HttpRoute::OperatorApi => {
            if let Some(response) = guard_http_request(config, &request) {
                return HttpExchange::Buffered(response);
            }
            if !accepts_media(request.header("accept"), "application/json") {
                return HttpExchange::Buffered(empty_response(406));
            }
            if let Some(enforcement) = &config.oauth
                && let Err(response) = validate_oauth_request(&request, enforcement)
            {
                return HttpExchange::Buffered(response);
            }
            return HttpExchange::Buffered(handle_operator_api_route(&request));
        }
        HttpRoute::NotFound => {
            return HttpExchange::Buffered(
                handle_dashboard_route(config, &request).unwrap_or_else(|| empty_response(404)),
            );
        }
        HttpRoute::Mcp => {}
    }
    if let Some(response) = guard_http_request(config, &request) {
        return HttpExchange::Buffered(response);
    }
    if request.body.len() > MAX_BODY_BYTES {
        return HttpExchange::Buffered(empty_response(413));
    }
    if let Some(response) = cookie_get_requires_origin(&request) {
        return HttpExchange::Buffered(response);
    }
    let cookie_authenticated_get = request.method == "GET"
        && config.stateful
        && request.header("authorization").is_none()
        && stateful_session_cookie(&request).is_some();
    let validated_oauth = match &config.oauth {
        Some(enforcement) => match validate_oauth_request(&request, enforcement) {
            Ok(validated) => Some(validated),
            Err(_) if cookie_authenticated_get => None,
            Err(response) => return HttpExchange::Buffered(response),
        },
        None => None,
    };
    if let Some(response) = enforce_single_principal(config, validated_oauth.as_ref()) {
        return HttpExchange::Buffered(response);
    }
    let scope_grant = validated_oauth
        .as_ref()
        .map(|validated| &validated.scope_grant);
    let principal_key = validated_oauth
        .as_ref()
        .map(|validated| validated.principal_key.as_str());
    match request.method.as_str() {
        "GET" => handle_mcp_get(config, &request, principal_key, allow_streaming_get),
        "DELETE" => HttpExchange::Buffered(handle_mcp_delete(
            config,
            &request,
            stateful_principal_key(principal_key),
        )),
        "POST" => HttpExchange::Buffered(handle_mcp_post(
            server,
            config,
            &request,
            scope_grant,
            principal_key,
        )),
        _ => HttpExchange::Buffered(empty_response(405).with_header(
            "allow",
            if config.stateful {
                "GET, POST, DELETE"
            } else {
                "POST"
            },
        )),
    }
}

fn handle_operator_api_route(request: &HttpRequest) -> HttpResponse {
    if request.method != "GET" {
        return empty_response(405).with_header("allow", "GET");
    }
    let filters: serde_json::Map<String, Value> = request
        .query
        .iter()
        .filter(|(name, _)| name != "cursor")
        .map(|(name, value)| (name.clone(), Value::String(value.clone())))
        .collect();
    json_response(
        404,
        &json!({
            "error": "operator_route_not_found",
            "message": "operator API route is not served yet",
            "path": request.path,
            "query": {
                "cursor": request.query_param("cursor"),
                "filters": filters,
            },
        }),
    )
}

fn handle_dashboard_route(
    config: &HttpTransportConfig,
    request: &HttpRequest,
) -> Option<HttpResponse> {
    if !matches!(request.method.as_str(), "GET" | "HEAD") {
        return None;
    }
    if dashboard_html_fallback_path(&request.path)
        && !accepts_media(request.header("accept"), "text/html")
    {
        return None;
    }
    if let Some(response) = guard_http_request(config, request) {
        return Some(response);
    }
    let asset = crate::dashboard_bundle::dashboard_asset_for(&request.path)?;
    let body = if request.method == "HEAD" {
        Vec::new()
    } else {
        asset.body
    };
    Some(HttpResponse {
        status: 200,
        headers: vec![
            ("content-type".to_owned(), asset.content_type.to_owned()),
            ("cache-control".to_owned(), asset.cache_control.to_owned()),
            ("x-content-type-options".to_owned(), "nosniff".to_owned()),
        ],
        body,
    })
}

fn dashboard_html_fallback_path(path: &str) -> bool {
    let path = path.trim_start_matches('/');
    path.is_empty()
        || path == "index.html"
        || !path
            .rsplit('/')
            .next()
            .is_some_and(|part| part.contains('.'))
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

fn handle_mcp_get(
    config: &HttpTransportConfig,
    request: &HttpRequest,
    principal_key: Option<&str>,
    allow_streaming: bool,
) -> HttpExchange {
    if !config.stateful {
        return HttpExchange::Buffered(empty_response(405).with_header("allow", "POST"));
    }
    if !accepts_media(request.header("accept"), "text/event-stream") {
        return HttpExchange::Buffered(empty_response(406));
    }
    let session = match validate_stateful_session(config, request, principal_key, true) {
        Ok(session) => session,
        Err(response) => return HttpExchange::Buffered(response),
    };
    let session_id = session.session_id;
    let cursor = request
        .query_param("cursor")
        .or_else(|| request.header("last-event-id"));
    let gap_on_expired_cursor =
        request.query_param("cursor").is_none() && request.header("last-event-id").is_some();
    let Some(store) = config.result_store.as_ref() else {
        return HttpExchange::Buffered(buffered_sse_response(&[]));
    };
    store.ensure_session(session_id);
    let events = match store.events_after(session_id, cursor, gap_on_expired_cursor) {
        Ok(events) => events,
        Err(response) => return HttpExchange::Buffered(response),
    };
    if allow_streaming {
        return HttpExchange::SseStream(HttpSseStream::new(
            Arc::clone(store),
            session_id.to_owned(),
            parse_stream_cursor(cursor).unwrap_or(0),
            events,
        ));
    }
    HttpExchange::Buffered(buffered_sse_response(&events))
}

fn handle_mcp_delete(
    config: &HttpTransportConfig,
    request: &HttpRequest,
    principal_key: &str,
) -> HttpResponse {
    if config.stateful {
        return match validate_stateful_session(config, request, Some(principal_key), false) {
            Ok(session) => {
                let session_id = session.session_id;
                if let Some(store) = &config.session_store {
                    store.remove(session_id);
                }
                if let Some(store) = &config.result_store {
                    store.remove_session(session_id);
                }
                if let Some(lifecycle) = &config.session_lifecycle {
                    lifecycle.close_session(session_id, &session.principal_key);
                }
                empty_response(202)
            }
            Err(response) => response,
        };
    }
    empty_response(405).with_header("allow", "POST")
}

fn handle_mcp_post(
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    request: &HttpRequest,
    scope_grant: Option<&ScopeGrant>,
    principal_key: Option<&str>,
) -> HttpResponse {
    if !content_type_is_json(request) {
        return empty_response(415);
    }
    if !accepts_media(
        request.header("accept"),
        if config.stateful {
            "text/event-stream"
        } else {
            "application/json"
        },
    ) {
        return empty_response(406);
    }
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
            match validate_stateful_session(config, request, Some(session_principal_key), false) {
                Ok(session) => Some(session.session_id.to_owned()),
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
        let response_event_id = if method.as_deref() == Some("initialize") {
            None
        } else {
            http_session_id.as_deref().and_then(|session_id| {
                config
                    .result_store
                    .as_ref()
                    .map(|store| store.append_response(session_id, response.clone()))
            })
        };
        return sse_response(
            config,
            method.as_deref(),
            response,
            http_session_id,
            session_principal_key,
            response_event_id.as_deref(),
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
    let error_class = structured.get("error_class").and_then(Value::as_str);
    if !matches!(error_class, Some("BUSY" | "AT_CAPACITY")) {
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

fn content_type_is_json(request: &HttpRequest) -> bool {
    request.header("content-type").is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
    })
}

fn accepts_media(header: Option<&str>, required: &str) -> bool {
    let Some(header) = header else {
        return true;
    };
    let Some((required_type, required_subtype)) = required.split_once('/') else {
        return false;
    };
    header.split(',').any(|range| {
        let media = range.split(';').next().unwrap_or("").trim();
        if media == "*/*" {
            return true;
        }
        let Some((media_type, media_subtype)) = media.split_once('/') else {
            return false;
        };
        (media_type == "*" || media_type.eq_ignore_ascii_case(required_type))
            && (media_subtype == "*" || media_subtype.eq_ignore_ascii_case(required_subtype))
    })
}

struct ValidatedStatefulSession<'a> {
    session_id: &'a str,
    principal_key: String,
}

fn validate_stateful_session<'a>(
    config: &HttpTransportConfig,
    request: &'a HttpRequest,
    expected_principal_key: Option<&str>,
    allow_cookie: bool,
) -> Result<ValidatedStatefulSession<'a>, HttpResponse> {
    let Some(session_id) = stateful_session_id(request, allow_cookie) else {
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
        Some(owner) if expected_principal_key.is_none_or(|expected| owner == expected) => {
            Ok(ValidatedStatefulSession {
                session_id,
                principal_key: owner.to_owned(),
            })
        }
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

fn stream_event_sequence(id: &str) -> Option<u64> {
    id.split('/').next()?.parse().ok()
}

fn parse_stream_cursor(cursor: Option<&str>) -> Result<u64, HttpResponse> {
    match cursor {
        Some(cursor) if !cursor.trim().is_empty() => {
            stream_event_sequence(cursor).ok_or_else(|| {
                json_response(
                    400,
                    &json!({
                        "error": "invalid_stream_cursor",
                        "message": "cursor must be a Streamable HTTP event id such as 1 or 1/0",
                    }),
                )
            })
        }
        _ => Ok(0),
    }
}

fn events_after_sequence(
    events: &[HttpBufferedEvent],
    after_seq: u64,
    cursor: Option<&str>,
    gap_on_expired_cursor: bool,
) -> Result<Vec<HttpBufferedEvent>, HttpResponse> {
    if let Some(oldest_event) = events.first()
        && let Some(oldest_seq) = stream_event_sequence(&oldest_event.id)
        && after_seq < oldest_seq.saturating_sub(1)
    {
        if !gap_on_expired_cursor {
            return Err(json_response(
                410,
                &json!({
                    "error": "stream_cursor_expired",
                    "message": "requested Streamable HTTP cursor is older than the retained event buffer",
                    "cursor": cursor.unwrap_or(""),
                    "oldest_event_id": oldest_event.id,
                    "next_step": "restart the MCP session; the missing event range is no longer available for replay",
                }),
            ));
        }
        let mut resumed = Vec::with_capacity(events.len().saturating_add(1));
        resumed.push(HttpBufferedEvent::gap(
            format!("{}/gap", oldest_seq.saturating_sub(1)),
            cursor,
            &oldest_event.id,
        ));
        resumed.extend(events.iter().cloned());
        return Ok(resumed);
    }
    Ok(events
        .iter()
        .filter(|event| stream_event_sequence(&event.id).is_some_and(|seq| seq > after_seq))
        .cloned()
        .collect())
}

struct HttpSseStream {
    store: Arc<HttpResultStore>,
    session_id: String,
    after_seq: u64,
    initial_events: Vec<HttpBufferedEvent>,
}

impl HttpSseStream {
    fn new(
        store: Arc<HttpResultStore>,
        session_id: String,
        after_seq: u64,
        initial_events: Vec<HttpBufferedEvent>,
    ) -> Self {
        Self {
            store,
            session_id,
            after_seq,
            initial_events,
        }
    }

    fn into_buffered_response(self) -> HttpResponse {
        buffered_sse_response(&self.initial_events)
    }

    fn write_to(mut self, stream: &mut impl Write) -> std::io::Result<()> {
        write_streaming_sse_headers(stream)?;
        write_chunked_sse_event(stream, None, Some("0/0"), Some(3000), Some(&Value::Null))?;
        let initial_events = std::mem::take(&mut self.initial_events);
        for event in initial_events {
            self.write_buffered_event(stream, &event)?;
        }
        loop {
            match self.store.wait_events_after(
                &self.session_id,
                self.after_seq,
                SSE_KEEPALIVE_INTERVAL,
            ) {
                HttpResultWait::Events(events) => {
                    for event in events {
                        self.write_buffered_event(stream, &event)?;
                    }
                }
                HttpResultWait::Timeout => write_chunked_sse_comment(stream, "keepalive")?,
                HttpResultWait::Closed => break,
            }
        }
        write_final_chunk(stream)
    }

    fn write_buffered_event(
        &mut self,
        stream: &mut impl Write,
        event: &HttpBufferedEvent,
    ) -> std::io::Result<()> {
        write_chunked_sse_event(
            stream,
            event.event,
            Some(&event.id),
            None,
            Some(&event.data),
        )?;
        if let Some(seq) = stream_event_sequence(&event.id) {
            self.after_seq = self.after_seq.max(seq);
        }
        Ok(())
    }
}

fn buffered_sse_response(events: &[HttpBufferedEvent]) -> HttpResponse {
    let mut body = Vec::new();
    write_sse_event(&mut body, None, Some("0/0"), Some(3000), Some(&Value::Null));
    for event in events {
        write_sse_event(
            &mut body,
            event.event,
            Some(&event.id),
            None,
            Some(&event.data),
        );
    }
    HttpResponse {
        status: 200,
        headers: vec![
            ("content-type".to_owned(), "text/event-stream".to_owned()),
            ("cache-control".to_owned(), "no-cache".to_owned()),
        ],
        body,
    }
}

fn sse_response(
    config: &HttpTransportConfig,
    method: Option<&str>,
    response: Value,
    initialized_session_id: Option<String>,
    principal_key: &str,
    response_event_id: Option<&str>,
) -> HttpResponse {
    let mut body = Vec::new();
    let session_id = if method == Some("initialize") {
        write_sse_event(&mut body, None, Some("0"), Some(3000), Some(&Value::Null));
        write_sse_event(&mut body, None, None, None, Some(&response));
        initialized_session_id.or_else(|| Some(new_session_id()))
    } else {
        write_sse_event(&mut body, None, Some("0/0"), Some(3000), Some(&Value::Null));
        write_sse_event(
            &mut body,
            None,
            Some(response_event_id.unwrap_or("1/0")),
            None,
            Some(&response),
        );
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
        if let Some(store) = &config.result_store {
            store.ensure_session(&session_id);
        }
        headers.push(("mcp-session-id".to_owned(), session_id.clone()));
        headers.push((
            "set-cookie".to_owned(),
            stateful_session_cookie_header(&session_id),
        ));
    }
    HttpResponse {
        status: 200,
        headers,
        body,
    }
}

fn write_sse_event(
    body: &mut Vec<u8>,
    event: Option<&str>,
    id: Option<&str>,
    retry: Option<u64>,
    data: Option<&Value>,
) {
    if let Some(event) = event {
        body.extend_from_slice(format!("event: {event}\n").as_bytes());
    }
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

fn write_streaming_sse_headers(stream: &mut impl Write) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 200 {}\r\ncontent-type: text/event-stream\r\ncache-control: no-cache\r\ntransfer-encoding: chunked\r\nconnection: close\r\nx-accel-buffering: no\r\n\r\n",
        reason_phrase(200)
    )?;
    stream.flush()
}

fn write_chunked_sse_event(
    stream: &mut impl Write,
    event: Option<&str>,
    id: Option<&str>,
    retry: Option<u64>,
    data: Option<&Value>,
) -> std::io::Result<()> {
    let mut body = Vec::new();
    write_sse_event(&mut body, event, id, retry, data);
    write_chunked_bytes(stream, &body)
}

fn write_chunked_sse_comment(stream: &mut impl Write, comment: &str) -> std::io::Result<()> {
    let mut body = Vec::with_capacity(comment.len().saturating_add(4));
    body.extend_from_slice(b": ");
    body.extend_from_slice(comment.as_bytes());
    body.extend_from_slice(b"\n\n");
    write_chunked_bytes(stream, &body)
}

fn write_chunked_bytes(stream: &mut impl Write, bytes: &[u8]) -> std::io::Result<()> {
    write!(stream, "{:x}\r\n", bytes.len())?;
    stream.write_all(bytes)?;
    stream.write_all(b"\r\n")?;
    stream.flush()
}

fn write_final_chunk(stream: &mut impl Write) -> std::io::Result<()> {
    stream.write_all(b"0\r\n\r\n")?;
    stream.flush()
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
    let mut last_idle_reap = Instant::now();
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while !shutdown.load(Ordering::SeqCst) {
        if last_idle_reap.elapsed() >= STATEFUL_IDLE_REAP_INTERVAL {
            reap_idle_stateful_sessions(&config);
            last_idle_reap = Instant::now();
        }
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
    close_stateful_sessions_for_shutdown(&config);
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
    let mut last_idle_reap = Instant::now();
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while !shutdown.load(Ordering::SeqCst) {
        if last_idle_reap.elapsed() >= STATEFUL_IDLE_REAP_INTERVAL {
            reap_idle_stateful_sessions(&config);
            last_idle_reap = Instant::now();
        }
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
    close_stateful_sessions_for_shutdown(&config);
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
    if config.stateful && config.result_store.is_none() {
        config.result_store = Some(Arc::new(HttpResultStore::new()));
    }
    config
}

fn close_stateful_sessions_for_shutdown(config: &HttpTransportConfig) {
    if let Some(lifecycle) = &config.session_lifecycle {
        lifecycle.close_all_sessions();
    }
    if let Some(result_store) = &config.result_store {
        result_store.close_all();
    }
}

fn reap_idle_stateful_sessions(config: &HttpTransportConfig) -> usize {
    if !config.stateful || config.stateful_idle_ttl.is_zero() {
        return 0;
    }
    let Some(session_store) = &config.session_store else {
        return 0;
    };
    let expired = session_store.reap_idle(config.stateful_idle_ttl);
    let count = expired.len();
    for (session_id, principal_key) in expired {
        if let Some(result_store) = &config.result_store {
            result_store.remove_session(&session_id);
        }
        if let Some(lifecycle) = &config.session_lifecycle {
            lifecycle.close_session_with_reason(
                &session_id,
                &principal_key,
                DispatchCloseReason::Timeout,
            );
        }
    }
    count
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
    let exchange = match read_http_request(stream) {
        Ok(Some(request)) => handle_http_exchange(server, config, request, true),
        Ok(None) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            HttpExchange::Buffered(HttpResponse {
                status: 400,
                headers: vec![],
                body: e.to_string().into_bytes(),
            })
        }
        Err(e) => return Err(e),
    };
    match exchange {
        HttpExchange::Buffered(response) => write_http_response(stream, &response),
        HttpExchange::SseStream(response) => response.write_to(stream),
    }
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
    let mut request = HttpRequest::new(method, target, headers, Vec::new());
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
        406 => "Not Acceptable",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        _ => "OK",
    }
}
