//! Native Streamable HTTP(S) transport (plan §7.1, §2.5; bead P1-9a /
//! oracle-qmwz.2.9.1).
//!
//! This module owns the small HTTP/1.1 surface oraclemcp actually needs: the
//! `/mcp` Streamable HTTP endpoint, RFC 9728 protected-resource metadata, the
//! DNS-rebinding `Host` guard, the browser `Origin` allowlist, and OAuth bearer
//! validation. It deliberately does not depend on a web framework or ambient
//! async runtime.

use std::collections::{HashMap, VecDeque};
use std::fmt::Write as FmtWrite;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use asupersync::Outcome;
use oraclemcp_audit::{
    AuditDecision, AuditEntryDraft, AuditOutcome, AuditRecord, AuditSubject, Auditor, DbEvidence,
    GENESIS_HASH,
};
use oraclemcp_auth::{
    HttpGuardError, HttpGuardPolicy, ResourceServerConfig, SignatureVerifier, TokenError,
    extract_bearer,
};
use oraclemcp_telemetry::{HealthState, Metrics};
use parking_lot::{Condvar, Mutex};
use rustls::{ServerConnection, StreamOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::admin_auth::OperatorAuthorityPolicy;
use crate::capabilities::PROTOCOL_VERSION;
use crate::dashboard_auth::{
    DASHBOARD_ACTION_TICKET_HEADER, DASHBOARD_CSRF_HEADER, DASHBOARD_PAIR_PATH,
    DASHBOARD_SESSION_PATH, DashboardAuth, DashboardAuthError,
};
use crate::operator_protocol::{
    OPERATOR_PROTOCOL_VERSION, operator_event, operator_response, operator_route_index,
    operator_schema_bundle, operator_subject_id_hash, validate_operator_event,
    validate_operator_response,
};
use crate::server::{DispatchCloseReason, DispatchContext, OracleMcpServer};
use crate::tls::TlsServerConfig;

/// The MCP endpoint path the Streamable HTTP transport is mounted at.
pub const MCP_PATH: &str = "/mcp";
/// The versioned, schema-first operator API prefix.
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
#[derive(Clone)]
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
    /// D17 operator-authority policy for `/operator/v1`. Ordinary authenticated
    /// subjects are not operators unless this policy authorizes them.
    pub operator_authority: OperatorAuthorityPolicy,
    /// Browser dashboard local pairing/session guard. When configured, the
    /// embedded SPA and unauthenticated loopback `/operator/v1` calls require a
    /// same-origin dashboard session in addition to per-request operator
    /// authority.
    pub dashboard_auth: Option<Arc<DashboardAuth>>,
    /// Audit sink for authorized operator API actions. If unset, operator API
    /// actions fail closed rather than running unaudited.
    pub operator_auditor: Option<Arc<Auditor>>,
    /// Optional audit JSONL path used by `/operator/v1/audit-tail`. The route
    /// summarizes records and never exposes bind values or raw identities.
    pub operator_audit_tail_path: Option<PathBuf>,
    /// In-memory idempotency ledger for `/operator/v1` gated-action routes.
    /// It caches only redacted operator envelopes and never bypasses the
    /// dispatcher's grant or write-intent checks.
    pub operator_idempotency: Arc<OperatorIdempotencyLedger>,
    /// Bounded replay buffer for `/operator/v1/events`, partitioned by
    /// server-derived subject hash and lane id so a resume cannot cross streams.
    pub operator_events: Arc<OperatorEventStore>,
    /// Health/metrics observability endpoints (D1; off by default — `None`
    /// fields make the corresponding route return 404 / not be advertised).
    pub observability: ObservabilityState,
}

impl std::fmt::Debug for HttpTransportConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTransportConfig")
            .field("allowed_hosts", &self.allowed_hosts)
            .field("allowed_origins", &self.allowed_origins)
            .field("json_response", &self.json_response)
            .field("stateful", &self.stateful)
            .field("stateful_idle_ttl", &self.stateful_idle_ttl)
            .field("resource_metadata", &self.resource_metadata.is_some())
            .field("oauth", &self.oauth.is_some())
            .field("session_store", &self.session_store.is_some())
            .field("result_store", &self.result_store.is_some())
            .field("session_lifecycle", &self.session_lifecycle.is_some())
            .field(
                "single_principal_guard",
                &self.single_principal_guard.is_some(),
            )
            .field("operator_authority", &self.operator_authority)
            .field("dashboard_auth", &self.dashboard_auth.is_some())
            .field("operator_auditor", &self.operator_auditor.is_some())
            .field(
                "operator_audit_tail_path",
                &self
                    .operator_audit_tail_path
                    .as_ref()
                    .map(|_| "<configured>"),
            )
            .field("operator_idempotency", &true)
            .field("operator_events", &true)
            .field("observability", &self.observability)
            .finish()
    }
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
            operator_authority: OperatorAuthorityPolicy::default(),
            dashboard_auth: None,
            operator_auditor: None,
            operator_audit_tail_path: None,
            operator_idempotency: Arc::new(OperatorIdempotencyLedger::new()),
            operator_events: Arc::new(OperatorEventStore::new()),
            observability: ObservabilityState::default(),
        }
    }
}

/// Redacted stateful lane summary exposed to the operator API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpLaneSnapshot {
    pub lane_id: String,
    pub generation: u64,
    pub status: &'static str,
    pub subject_id_hash: String,
}

/// Internal binding for routing operator actions back onto an existing lane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpLaneBinding {
    pub lane_id: String,
    pub mcp_session_id: String,
    pub principal_key: String,
    pub generation: u64,
}

const MAX_OPERATOR_EVENTS_PER_STREAM: usize = 128;

/// Bounded `/operator/v1/events` replay buffer.
///
/// Events are keyed by the redacted subject hash plus lane id. That makes resume
/// isolation structural: even identical cursor numbers on two lanes or two
/// operators consult different rings.
#[derive(Debug, Default)]
pub struct OperatorEventStore {
    streams: Mutex<HashMap<OperatorEventStreamKey, Vec<HttpBufferedEvent>>>,
}

impl OperatorEventStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn append_snapshot_and_resume(
        &self,
        subject_key: &str,
        lane_id: &str,
        cursor: Option<&str>,
        after_seq: Option<u64>,
        gap_on_expired_cursor: bool,
        data: Value,
    ) -> Result<Vec<HttpBufferedEvent>, OperatorEventReplayError> {
        let subject_id_hash = operator_subject_id_hash(subject_key);
        let key = OperatorEventStreamKey {
            subject_id_hash,
            lane_id: lane_id.to_owned(),
        };
        let mut streams = self.streams.lock();
        let stream = streams.entry(key).or_default();
        let previous_seq = stream
            .last()
            .and_then(|event| operator_event_sequence(&event.id))
            .unwrap_or(0);
        let next_seq = previous_seq.saturating_add(1);
        let event = operator_event(next_seq, lane_id, subject_key, "operator.snapshot", data);
        debug_assert!(
            validate_operator_event(&event).is_ok(),
            "operator SSE event must match the Rust contract"
        );
        let event_id = event
            .get("event_id")
            .and_then(Value::as_str)
            .unwrap_or("operator/0")
            .to_owned();
        stream.push(HttpBufferedEvent {
            id: event_id,
            event: Some("operator.snapshot"),
            data: event,
        });
        if stream.len() > MAX_OPERATOR_EVENTS_PER_STREAM {
            let overflow = stream.len() - MAX_OPERATOR_EVENTS_PER_STREAM;
            stream.drain(..overflow);
        }
        operator_events_after_sequence(
            stream,
            after_seq.unwrap_or(previous_seq),
            cursor,
            gap_on_expired_cursor,
            lane_id,
            subject_key,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct OperatorEventStreamKey {
    subject_id_hash: String,
    lane_id: String,
}

#[derive(Debug)]
enum OperatorEventReplayError {
    Expired {
        cursor: String,
        oldest_event_id: String,
    },
}

const OPERATOR_IDEMPOTENCY_TTL: Duration = Duration::from_secs(15 * 60);
const OPERATOR_IDEMPOTENCY_MAX_ENTRIES: usize = 1024;

/// In-memory idempotency ledger for `/operator/v1` gated actions.
///
/// The ledger protects the operator HTTP edge from duplicate action retries by
/// caching the exact redacted operator response for a request key. It is not a
/// persistence mechanism and does not replace dispatcher-side single-use
/// grants or durable write-ahead intents.
#[derive(Debug, Default)]
pub struct OperatorIdempotencyLedger {
    entries: Mutex<HashMap<String, OperatorIdempotencyEntry>>,
}

impl OperatorIdempotencyLedger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn begin(&self, route: &str, facts: OperatorIdempotencyFacts) -> OperatorIdempotencyBegin {
        let mut entries = self.entries.lock();
        prune_operator_idempotency_entries(&mut entries);
        match entries.get(&facts.storage_key) {
            Some(entry) if entry.facts.fingerprint_sha256 != facts.fingerprint_sha256 => {
                OperatorIdempotencyBegin::Conflict(operator_json_response(
                    409,
                    route,
                    json!({
                        "error": "operator_idempotency_key_conflict",
                        "message": "idempotency key was already used with different operator action material",
                        "idempotency": entry.facts.as_json("conflict"),
                    }),
                ))
            }
            Some(entry) => match &entry.response {
                Some(response) => OperatorIdempotencyBegin::Replay(response.clone()),
                None => OperatorIdempotencyBegin::InProgress(operator_json_response(
                    409,
                    route,
                    json!({
                        "error": "operator_idempotency_in_progress",
                        "message": "idempotency key is already in progress",
                        "idempotency": entry.facts.as_json("in_progress"),
                    }),
                )),
            },
            None => {
                let storage_key = facts.storage_key.clone();
                entries.insert(
                    storage_key.clone(),
                    OperatorIdempotencyEntry {
                        facts,
                        response: None,
                        created_at: Instant::now(),
                    },
                );
                OperatorIdempotencyBegin::Fresh(OperatorIdempotencyLease { storage_key })
            }
        }
    }

    fn complete(
        &self,
        lease: OperatorIdempotencyLease,
        completed_facts: OperatorIdempotencyFacts,
        response: HttpResponse,
    ) -> HttpResponse {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.get_mut(&lease.storage_key) {
            entry.facts = completed_facts;
            entry.response = Some(response.clone());
        }
        response
    }
}

#[derive(Clone, Debug)]
struct OperatorIdempotencyFacts {
    storage_key: String,
    request_id: String,
    idempotency_key_sha256: String,
    fingerprint_sha256: String,
    lane_id: Option<String>,
    lane_generation: Option<u64>,
    subject_id_hash: String,
    grant_sha256: Option<String>,
    sql_sha256: Option<String>,
    operator_audit_seq: u64,
    started_at: String,
    completed_at: Option<String>,
}

impl OperatorIdempotencyFacts {
    fn as_json(&self, outcome: &str) -> Value {
        json!({
            "request_id": self.request_id,
            "idempotency_key_sha256": self.idempotency_key_sha256,
            "fingerprint_sha256": self.fingerprint_sha256,
            "lane_id": self.lane_id,
            "lane_generation": self.lane_generation,
            "subject_id_hash": self.subject_id_hash,
            "grant_sha256": self.grant_sha256,
            "sql_sha256": self.sql_sha256,
            "operator_audit_seq": self.operator_audit_seq,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "outcome": outcome,
        })
    }

    fn completed(&self, completed_at: String) -> Self {
        let mut facts = self.clone();
        facts.completed_at = Some(completed_at);
        facts
    }
}

#[derive(Clone, Debug)]
struct OperatorIdempotencyEntry {
    facts: OperatorIdempotencyFacts,
    response: Option<HttpResponse>,
    created_at: Instant,
}

#[derive(Clone, Debug)]
struct OperatorIdempotencyLease {
    storage_key: String,
}

enum OperatorIdempotencyBegin {
    Fresh(OperatorIdempotencyLease),
    Replay(HttpResponse),
    InProgress(HttpResponse),
    Conflict(HttpResponse),
}

fn prune_operator_idempotency_entries(entries: &mut HashMap<String, OperatorIdempotencyEntry>) {
    let now = Instant::now();
    entries.retain(|_, entry| now.duration_since(entry.created_at) <= OPERATOR_IDEMPOTENCY_TTL);
    while entries.len() >= OPERATOR_IDEMPOTENCY_MAX_ENTRIES {
        let Some(oldest) = entries
            .iter()
            .min_by_key(|(_, entry)| entry.created_at)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        entries.remove(&oldest);
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

    /// Redacted lane summaries for `/operator/v1/active-lanes`.
    fn active_lanes(&self) -> Vec<HttpLaneSnapshot> {
        Vec::new()
    }

    /// Resolve a lane id for an operator-triggered action. Implementations
    /// return internal session/principal keys only to the HTTP router; these
    /// values are never serialized.
    fn lane_binding(&self, _lane_id: &str) -> Option<HttpLaneBinding> {
        None
    }
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
    use asupersync::{CancelReason, Cx, PanicPayload};
    use oraclemcp_error::{ErrorClass, ErrorEnvelope};
    use oraclemcp_guard::{Classifier, OperatingLevel};
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    struct NoopDispatch;
    impl ToolDispatch for NoopDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            _name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async { Outcome::Ok(serde_json::json!({})) })
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
                Outcome::Err(
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
                Outcome::Err(
                    ErrorEnvelope::new(ErrorClass::AtCapacity, "stateful lane capacity exhausted")
                        .with_retry_after_ms(250),
                )
            })
        }
    }

    struct CancelledDispatch;
    impl ToolDispatch for CancelledDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            _name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async { Outcome::Cancelled(CancelReason::timeout()) })
        }
    }

    struct PanickedDispatch;
    impl ToolDispatch for PanickedDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            _name: &'a str,
            _args: Value,
        ) -> DispatchFuture<'a> {
            Box::pin(async { Outcome::Panicked(PanicPayload::new("test panic")) })
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
                Outcome::Ok(serde_json::json!({
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
                Outcome::Ok(serde_json::json!({
                    "tool": tool,
                    "thread": format!("{:?}", std::thread::current().id()),
                }))
            })
        }
    }

    struct CountingDispatch {
        calls: Arc<AtomicUsize>,
    }

    impl ToolDispatch for CountingDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            name: &'a str,
            args: Value,
        ) -> DispatchFuture<'a> {
            let call = self.calls.fetch_add(1, AtomicOrdering::SeqCst) + 1;
            let tool = name.to_owned();
            Box::pin(async move {
                Outcome::Ok(serde_json::json!({
                    "tool": tool,
                    "call": call,
                    "args": args,
                }))
            })
        }
    }

    struct WorkbenchDispatch {
        calls: Arc<AtomicUsize>,
    }

    impl ToolDispatch for WorkbenchDispatch {
        fn dispatch<'a>(
            &'a self,
            _cx: &'a Cx,
            _context: DispatchContext<'a>,
            name: &'a str,
            args: Value,
        ) -> DispatchFuture<'a> {
            let call = self.calls.fetch_add(1, AtomicOrdering::SeqCst) + 1;
            let tool = name.to_owned();
            Box::pin(async move {
                let classification = args.get("sql").and_then(Value::as_str).map(|sql| {
                    let decision = Classifier::default().classify(sql);
                    serde_json::json!({
                        "required_level": decision.required_level,
                        "danger": decision.danger,
                        "reason": decision.reason,
                    })
                });
                Outcome::Ok(serde_json::json!({
                    "tool": tool,
                    "call": call,
                    "args": args,
                    "classification": classification,
                }))
            })
        }
    }

    fn server_with_dispatch(dispatcher: Arc<dyn ToolDispatch>) -> OracleMcpServer {
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
        OracleMcpServer::new("0.1.0", ToolRegistry::new(), report, dispatcher)
    }

    fn test_server() -> OracleMcpServer {
        server_with_dispatch(Arc::new(NoopDispatch))
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

    fn cancelled_server() -> OracleMcpServer {
        server_with_dispatch(Arc::new(CancelledDispatch))
    }

    fn panicked_server() -> OracleMcpServer {
        server_with_dispatch(Arc::new(PanickedDispatch))
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

    fn operator_auditor() -> (Arc<Auditor>, Arc<oraclemcp_audit::MemoryAuditSink>) {
        struct SharedSink(Arc<oraclemcp_audit::MemoryAuditSink>);
        impl oraclemcp_audit::AuditSink for SharedSink {
            fn append(
                &self,
                record: &oraclemcp_audit::AuditRecord,
            ) -> Result<(), oraclemcp_audit::AuditError> {
                self.0.append(record)
            }

            fn flush(&self) -> Result<(), oraclemcp_audit::AuditError> {
                self.0.flush()
            }
        }

        let sink = Arc::new(oraclemcp_audit::MemoryAuditSink::default());
        let key = oraclemcp_audit::SigningKey::new("operator-test", b"operator-key".to_vec());
        let auditor = Arc::new(Auditor::new(Box::new(SharedSink(Arc::clone(&sink))), key));
        (auditor, sink)
    }

    fn audit_tail_fixture_path(name: &str) -> PathBuf {
        let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        dir.push("../../target/tmp/operator-audit-tail-tests");
        std::fs::create_dir_all(&dir).expect("create audit tail fixture dir");
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        dir.push(format!("{name}-{}-{nanos}.jsonl", std::process::id()));
        dir
    }

    fn audit_tail_draft(
        subject_id: &str,
        tool: &str,
        sql: &str,
        danger_level: &str,
        outcome: AuditOutcome,
        db_evidence: Option<DbEvidence>,
    ) -> AuditEntryDraft {
        AuditEntryDraft {
            subject: AuditSubject::new("operator", subject_id).with_authn_method("loopback"),
            db_evidence,
            cancel: None,
            tool: tool.to_owned(),
            sql: sql.to_owned(),
            danger_level: danger_level.to_owned(),
            decision: AuditDecision::Allowed,
            rows_affected: Some(3),
            outcome,
        }
    }

    fn write_audit_tail_fixture(name: &str, break_second_hash: bool) -> PathBuf {
        let key = oraclemcp_audit::SigningKey::new("tail-test", b"tail-test-key".to_vec());
        let db_evidence = DbEvidence {
            availability: Some("captured".to_owned()),
            db_unique_name: Some("ORCLPDB1".to_owned()),
            service_name: Some("orclpdb1".to_owned()),
            instance_name: Some("orcl".to_owned()),
            session_user: Some("APP_USER".to_owned()),
            current_user: Some("APP_USER".to_owned()),
            current_schema: Some("APP".to_owned()),
            sid: Some("123".to_owned()),
            serial_number: Some("456".to_owned()),
            client_identifier: Some("operator-dashboard".to_owned()),
            module: Some("oraclemcp".to_owned()),
            action: Some("oracle_execute".to_owned()),
            database_role: Some("PRIMARY".to_owned()),
            open_mode: Some("READ WRITE".to_owned()),
            ..Default::default()
        };
        let drafts = [
            audit_tail_draft(
                "human@example.test",
                "oracle_execute",
                "UPDATE accounts SET flag=:1 WHERE id=:2",
                "GUARDED",
                AuditOutcome::Succeeded,
                Some(db_evidence),
            ),
            audit_tail_draft(
                "other@example.test",
                "oracle_query",
                "SELECT * FROM accounts WHERE id=:1",
                "SAFE",
                AuditOutcome::Succeeded,
                None,
            ),
        ];
        let mut previous_hash = GENESIS_HASH.to_owned();
        let records: Vec<AuditRecord> = drafts
            .iter()
            .enumerate()
            .map(|(index, draft)| {
                let record = AuditRecord::chained_signed(
                    draft,
                    u64::try_from(index + 1).expect("fixture index fits u64"),
                    &previous_hash,
                    format!("2026-06-30T12:00:0{index}Z"),
                    &key,
                );
                previous_hash = record.entry_hash.clone();
                record
            })
            .collect();
        let path = audit_tail_fixture_path(name);
        let mut file = std::fs::File::create(&path).expect("create audit tail fixture");
        for (index, record) in records.iter().enumerate() {
            let mut value = serde_json::to_value(record).expect("serialize audit fixture");
            if index == 0 {
                value["bind_values"] = serde_json::json!(["sensitive-bind-value"]);
            }
            if break_second_hash && index == 1 {
                value["entry_hash"] = serde_json::json!("sha256:broken");
            }
            writeln!(file, "{value}").expect("write audit fixture line");
        }
        path
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
        let (auditor, sink) = operator_auditor();
        let cfg = HttpTransportConfig {
            operator_auditor: Some(auditor),
            ..Default::default()
        };
        let response = handle_http_request(
            &test_server(),
            &cfg,
            HttpRequest::new(
                "GET",
                "/operator/v1/sessions?cursor=4%2F0&status=active&profile=prod",
                [("host", "127.0.0.1"), ("accept", "application/json")],
                Vec::new(),
            )
            .with_peer_loopback(true),
        );

        assert_eq!(response.status, 404);
        assert_eq!(response.header("content-type"), Some("application/json"));
        let body = response_json(&response);
        assert_eq!(body["protocol_version"], serde_json::json!("operator.v1"));
        assert_eq!(body["schema_version"], serde_json::json!(1));
        assert_eq!(
            body["data"]["error"],
            serde_json::json!("operator_route_not_found")
        );
        assert_eq!(body["data"]["query"]["cursor"], serde_json::json!("4/0"));
        assert_eq!(
            body["data"]["query"]["filters"]["status"],
            serde_json::json!("active")
        );
        assert_eq!(
            body["data"]["query"]["filters"]["profile"],
            serde_json::json!("prod")
        );
        let records = sink.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tool, "operator_api");
        assert_eq!(records[0].sql_preview, "GET /operator/v1/sessions");
        assert_eq!(
            records[0].subject,
            AuditSubject::new("local-owner", "process-owner").with_authn_method("loopback")
        );

        let bad_host = handle_http_request(
            &test_server(),
            &cfg,
            HttpRequest::new(
                "GET",
                "/operator/v1/sessions",
                [("host", "attacker.example"), ("accept", "application/json")],
                Vec::new(),
            )
            .with_peer_loopback(true),
        );
        assert_eq!(bad_host.status, 403);
    }

    #[test]
    fn mcp_protocol_version_header_is_enforced_before_dispatch() {
        let mut request = post(&init_body());
        request
            .headers
            .push(("mcp-protocol-version".to_owned(), "1900-01-01".to_owned()));

        let response =
            handle_http_request(&test_server(), &HttpTransportConfig::default(), request);

        assert_eq!(response.status, 400);
        assert_eq!(response.header("mcp-protocol-version"), Some("2025-11-25"));
        let body = response_json(&response);
        assert_eq!(
            body["error"],
            serde_json::json!("unsupported_protocol_version")
        );
        assert_eq!(body["supported"], serde_json::json!(["2025-11-25"]));
    }

    struct StaticReadinessProbe(bool);

    impl ReadinessProbe for StaticReadinessProbe {
        fn is_db_reachable(&self) -> bool {
            self.0
        }
    }

    #[derive(Debug)]
    struct StaticLaneLifecycle {
        lanes: Vec<HttpLaneSnapshot>,
    }

    impl StaticLaneLifecycle {
        fn one_lane() -> Self {
            Self {
                lanes: vec![HttpLaneSnapshot {
                    lane_id: "lane-a".to_owned(),
                    generation: 7,
                    status: "active",
                    subject_id_hash: "subject-sha256:abc".to_owned(),
                }],
            }
        }
    }

    impl HttpSessionLifecycle for StaticLaneLifecycle {
        fn close_session(&self, _session_id: &str, _principal_key: &str) -> bool {
            false
        }

        fn active_lanes(&self) -> Vec<HttpLaneSnapshot> {
            self.lanes.clone()
        }
    }

    #[test]
    fn operator_v1_serves_schema_health_events_and_action_mapping() {
        let (auditor, sink) = operator_auditor();
        let health = oraclemcp_telemetry::HealthState::new("0.4.1");
        health.set_ready(true);
        let metrics = Arc::new(oraclemcp_telemetry::Metrics::new());
        metrics.record_request("oracle_query", "ok");
        let cfg = HttpTransportConfig {
            operator_auditor: Some(auditor),
            session_lifecycle: Some(Arc::new(StaticLaneLifecycle::one_lane())),
            observability: ObservabilityState {
                health: Some(health),
                metrics: Some(metrics),
                readiness_probe: Some(Arc::new(StaticReadinessProbe(true))),
            },
            ..Default::default()
        };

        let schema = handle_http_request(
            &test_server(),
            &cfg,
            HttpRequest::new(
                "GET",
                "/operator/v1/schema",
                [("host", "127.0.0.1"), ("accept", "application/json")],
                Vec::new(),
            )
            .with_peer_loopback(true),
        );
        assert_eq!(schema.status, 200);
        let schema_body = response_json(&schema);
        assert_eq!(
            schema_body["x-oraclemcp-protocol-version"],
            serde_json::json!("operator.v1")
        );
        assert!(
            schema_body["routes"]
                .as_array()
                .expect("routes")
                .iter()
                .any(|route| route["path"] == "/operator/v1/actions/preview")
        );

        let health_response = handle_http_request(
            &test_server(),
            &cfg,
            HttpRequest::new(
                "GET",
                "/operator/v1/health",
                [("host", "127.0.0.1"), ("accept", "application/json")],
                Vec::new(),
            )
            .with_peer_loopback(true),
        );
        assert_eq!(health_response.status, 200);
        let health_body = response_json(&health_response);
        assert_eq!(
            health_body["data"]["readiness"]["status"],
            serde_json::json!("ok")
        );
        assert_eq!(
            health_body["data"]["readiness"]["db_reachable"],
            serde_json::json!(true)
        );

        let metrics_response = handle_http_request(
            &test_server(),
            &cfg,
            HttpRequest::new(
                "GET",
                "/operator/v1/metrics",
                [("host", "127.0.0.1"), ("accept", "application/json")],
                Vec::new(),
            )
            .with_peer_loopback(true),
        );
        assert_eq!(metrics_response.status, 200);
        let metrics_body = response_json(&metrics_response);
        assert_eq!(
            metrics_body["data"]["snapshot"]["active_lanes"],
            serde_json::json!(1)
        );
        assert_eq!(
            metrics_body["data"]["snapshot"]["active_lane_gauges"][0]["lane_id"],
            serde_json::json!("lane-a")
        );
        assert_eq!(
            metrics_body["data"]["snapshot"]["active_lane_gauges"][0]["subject_id_hash"],
            serde_json::json!("subject-sha256:abc")
        );

        let events = handle_http_request(
            &test_server(),
            &cfg,
            HttpRequest::new(
                "GET",
                "/operator/v1/events",
                [("host", "127.0.0.1"), ("accept", "text/event-stream")],
                Vec::new(),
            )
            .with_peer_loopback(true),
        );
        assert_eq!(events.status, 200);
        assert_eq!(events.header("content-type"), Some("text/event-stream"));
        let event = sse_json_events(&events)[0].clone();
        assert_eq!(event["schema_version"], serde_json::json!(1));
        assert_eq!(event["lane_id"], serde_json::json!("operator"));
        assert!(
            event["subject_id_hash"]
                .as_str()
                .expect("subject hash")
                .starts_with("subject-sha256:")
        );

        let action_body = serde_json::json!({
            "tool": "oracle_preview_sql",
            "arguments": { "sql": "SELECT 1 FROM dual" }
        });
        let action = handle_http_request(
            &test_server(),
            &cfg,
            HttpRequest::new(
                "POST",
                "/operator/v1/actions/preview",
                [
                    ("host", "127.0.0.1"),
                    ("content-type", "application/json"),
                    ("accept", "application/json"),
                ],
                action_body.to_string().into_bytes(),
            )
            .with_peer_loopback(true),
        );
        assert_eq!(action.status, 200);
        let action_body = response_json(&action);
        assert_eq!(
            action_body["data"]["mcp_tool"],
            serde_json::json!("oracle_preview_sql")
        );
        assert_eq!(
            action_body["data"]["status"],
            serde_json::json!("forwarded")
        );

        let records = sink.records();
        assert!(
            records.len() >= 5,
            "schema, health, metrics, events, and action routes are audited"
        );
        assert_eq!(records[0].sql_preview, "GET /operator/v1/schema");
        assert_eq!(records[1].sql_preview, "GET /operator/v1/health");
        assert_eq!(records[2].sql_preview, "GET /operator/v1/metrics");
        assert_eq!(records[3].sql_preview, "GET /operator/v1/events");
        assert_eq!(records[4].sql_preview, "POST /operator/v1/actions/preview");
    }

    #[test]
    fn audit_tail_filters_exports_redacted_proof_bundle() {
        let path = write_audit_tail_fixture("filters", false);
        let (auditor, _sink) = operator_auditor();
        let cfg = HttpTransportConfig {
            operator_auditor: Some(auditor),
            operator_audit_tail_path: Some(path.clone()),
            ..Default::default()
        };

        let response = handle_http_request(
            &test_server(),
            &cfg,
            HttpRequest::new(
                "GET",
                "/operator/v1/audit-tail?limit=5&tool=oracle_execute&level=GUARDED&export=proof-bundle",
                [("host", "127.0.0.1"), ("accept", "application/json")],
                Vec::new(),
            )
            .with_peer_loopback(true),
        );

        assert_eq!(response.status, 200);
        let body = response_json(&response);
        let data = &body["data"];
        assert_eq!(data["source"], serde_json::json!("self_lane"));
        assert_eq!(data["scanned_records"], serde_json::json!(2));
        assert_eq!(data["selected_records"], serde_json::json!(1));
        assert_eq!(
            data["proof"]["verification"]["hash_chain"]["status"],
            serde_json::json!("ok")
        );
        assert_eq!(
            data["proof"]["verification"]["keyed_mac"]["status"],
            serde_json::json!("not_checked")
        );
        assert_eq!(
            data["export"]["format"],
            serde_json::json!("oraclemcp.audit.proof-bundle.v1")
        );

        let record = &data["records"][0];
        assert_eq!(record["tool"], serde_json::json!("oracle_execute"));
        assert_eq!(record["danger_level"], serde_json::json!("GUARDED"));
        assert_eq!(
            record["db_evidence"]["current_user"],
            serde_json::json!("APP_USER")
        );
        assert_eq!(
            record["bind_values"]["stored"],
            serde_json::json!(false),
            "bind values are never exported from the audit tail"
        );
        assert_eq!(
            record["proof"]["prev_hash"],
            serde_json::json!(GENESIS_HASH)
        );
        assert!(
            record["proof"]["signature"]
                .as_str()
                .expect("signature")
                .starts_with("hmac-sha256:")
        );

        let rendered = data.to_string();
        assert!(
            !rendered.contains("human@example.test"),
            "raw subject stable ids must not be serialized"
        );
        assert!(
            !rendered.contains("sensitive-bind-value"),
            "unknown/raw bind fields in JSONL must be dropped by the allow-list"
        );
        assert!(
            !rendered.contains("UPDATE accounts"),
            "timeline and proof bundle must not export sql_preview/inlined SQL text"
        );

        let subject_id_hash = record["subject_id_hash"].as_str().expect("subject hash");
        let subject_filter_response = handle_http_request(
            &test_server(),
            &cfg,
            HttpRequest::new(
                "GET",
                format!("/operator/v1/audit-tail?subject_id_hash={subject_id_hash}"),
                [("host", "127.0.0.1"), ("accept", "application/json")],
                Vec::new(),
            )
            .with_peer_loopback(true),
        );
        assert_eq!(subject_filter_response.status, 200);
        let subject_filter_body = response_json(&subject_filter_response);
        assert_eq!(
            subject_filter_body["data"]["selected_records"],
            serde_json::json!(1)
        );
        assert_eq!(
            subject_filter_body["data"]["records"][0]["subject_id_hash"],
            serde_json::json!(subject_id_hash)
        );
    }

    #[test]
    fn audit_tail_reports_broken_hash_chain_without_exposing_raw_json_fields() {
        let path = write_audit_tail_fixture("broken", true);
        let (auditor, _sink) = operator_auditor();
        let cfg = HttpTransportConfig {
            operator_auditor: Some(auditor),
            operator_audit_tail_path: Some(path),
            ..Default::default()
        };

        let response = handle_http_request(
            &test_server(),
            &cfg,
            HttpRequest::new(
                "GET",
                "/operator/v1/audit-tail?limit=10",
                [("host", "127.0.0.1"), ("accept", "application/json")],
                Vec::new(),
            )
            .with_peer_loopback(true),
        );

        assert_eq!(response.status, 200);
        let body = response_json(&response);
        assert_eq!(
            body["data"]["proof"]["verification"]["hash_chain"]["status"],
            serde_json::json!("broken")
        );
        assert_eq!(
            body["data"]["proof"]["verification"]["hash_chain"]["broken"]["check"],
            serde_json::json!("entry_hash")
        );
        assert_eq!(
            body["data"]["records"][1]["proof"]["hash_valid"],
            serde_json::json!(false)
        );
        assert!(
            !body["data"].to_string().contains("sensitive-bind-value"),
            "proof export path must stay allow-list-only even on broken chains"
        );
    }

    #[test]
    fn operator_events_resume_is_lane_scoped() {
        let (auditor, _sink) = operator_auditor();
        let cfg = HttpTransportConfig {
            operator_auditor: Some(auditor),
            operator_events: Arc::new(OperatorEventStore::new()),
            ..Default::default()
        };
        let event_request = |target: &'static str, last_event_id: Option<&'static str>| {
            let mut headers = vec![
                ("host".to_owned(), "127.0.0.1".to_owned()),
                ("accept".to_owned(), "text/event-stream".to_owned()),
            ];
            if let Some(last_event_id) = last_event_id {
                headers.push(("last-event-id".to_owned(), last_event_id.to_owned()));
            }
            HttpRequest::new("GET", target, headers, Vec::new()).with_peer_loopback(true)
        };

        let first_a = handle_http_request(
            &test_server(),
            &cfg,
            event_request("/operator/v1/events?lane_id=lane-a", None),
        );
        assert_eq!(first_a.status, 200);
        let first_a_body = String::from_utf8(first_a.body).expect("operator SSE utf-8");
        assert!(first_a_body.contains("id: lane-a/1"));

        let first_b = handle_http_request(
            &test_server(),
            &cfg,
            event_request("/operator/v1/events?lane_id=lane-b", None),
        );
        assert_eq!(first_b.status, 200);
        let first_b_body = String::from_utf8(first_b.body).expect("operator SSE utf-8");
        assert!(first_b_body.contains("id: lane-b/1"));

        let replay_a = handle_http_request(
            &test_server(),
            &cfg,
            event_request("/operator/v1/events?lane_id=lane-a", Some("lane-a/1")),
        );
        assert_eq!(replay_a.status, 200);
        let replay_a_body = String::from_utf8(replay_a.body.clone()).expect("operator SSE utf-8");
        assert!(replay_a_body.contains("id: lane-a/2"));
        assert!(
            !replay_a_body.contains("lane-b"),
            "lane-a resume must not replay lane-b events"
        );
        let replayed = sse_json_events(&replay_a);
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0]["event_id"], serde_json::json!("lane-a/2"));
        assert_eq!(replayed[0]["lane_id"], serde_json::json!("lane-a"));
        assert_eq!(
            replayed[0]["redaction_level"],
            serde_json::json!("operator_redacted")
        );

        let mismatch = handle_http_request(
            &test_server(),
            &cfg,
            event_request("/operator/v1/events?lane_id=lane-a", Some("lane-b/1")),
        );
        assert_eq!(mismatch.status, 400);
        assert_eq!(
            response_json(&mismatch)["data"]["error"],
            serde_json::json!("operator_event_cursor_lane_mismatch")
        );

        let subject_a = "operator:subject-a";
        let subject_b = "operator:subject-b";
        let subject_b_hash = operator_subject_id_hash(subject_b);
        cfg.operator_events
            .append_snapshot_and_resume(
                subject_a,
                "shared-lane",
                None,
                None,
                false,
                serde_json::json!({ "source": "subject-a-1" }),
            )
            .expect("append subject-a event");
        cfg.operator_events
            .append_snapshot_and_resume(
                subject_b,
                "shared-lane",
                None,
                None,
                false,
                serde_json::json!({ "source": "subject-b-1" }),
            )
            .expect("append subject-b event");
        let subject_a_resume = cfg
            .operator_events
            .append_snapshot_and_resume(
                subject_a,
                "shared-lane",
                Some("shared-lane/1"),
                Some(1),
                false,
                serde_json::json!({ "source": "subject-a-2" }),
            )
            .expect("resume subject-a stream");
        assert_eq!(subject_a_resume.len(), 1);
        assert_eq!(subject_a_resume[0].id, "shared-lane/2");
        assert_eq!(
            subject_a_resume[0].data["subject_id_hash"],
            serde_json::json!(operator_subject_id_hash(subject_a))
        );
        assert_ne!(
            subject_a_resume[0].data["subject_id_hash"],
            serde_json::json!(subject_b_hash),
            "subject-a resume must not replay subject-b events on the same lane id"
        );
    }

    #[test]
    fn operator_events_last_event_id_reports_gap_for_slow_consumer() {
        let (auditor, _sink) = operator_auditor();
        let cfg = HttpTransportConfig {
            operator_auditor: Some(auditor),
            operator_events: Arc::new(OperatorEventStore::new()),
            ..Default::default()
        };
        let event_request = |target: &'static str, last_event_id: Option<&'static str>| {
            let mut headers = vec![
                ("host".to_owned(), "127.0.0.1".to_owned()),
                ("accept".to_owned(), "text/event-stream".to_owned()),
            ];
            if let Some(last_event_id) = last_event_id {
                headers.push(("last-event-id".to_owned(), last_event_id.to_owned()));
            }
            HttpRequest::new("GET", target, headers, Vec::new()).with_peer_loopback(true)
        };

        for _ in 0..=MAX_OPERATOR_EVENTS_PER_STREAM {
            let response = handle_http_request(
                &test_server(),
                &cfg,
                event_request("/operator/v1/events?lane_id=lane-a", None),
            );
            assert_eq!(response.status, 200);
        }

        let gap = handle_http_request(
            &test_server(),
            &cfg,
            event_request("/operator/v1/events?lane_id=lane-a", Some("lane-a/1")),
        );
        assert_eq!(gap.status, 200);
        let body = String::from_utf8(gap.body.clone()).expect("operator SSE utf-8");
        assert!(body.contains("event: operator.stream_gap"));
        assert!(body.contains("id: lane-a/2"));
        assert!(body.contains("\"type\":\"stream_gap\""));
        assert!(body.contains("\"oldest_event_id\":\"lane-a/3\""));
        assert!(
            !body.contains("lane-b"),
            "slow-consumer replay must stay within the requested lane"
        );
        let events = sse_json_events(&gap);
        assert_eq!(
            events[0]["event_type"],
            serde_json::json!("operator.stream_gap")
        );
        assert_eq!(events[0]["lane_id"], serde_json::json!("lane-a"));

        let expired_cursor = handle_http_request(
            &test_server(),
            &cfg,
            event_request("/operator/v1/events?lane_id=lane-a&cursor=lane-a/1", None),
        );
        assert_eq!(expired_cursor.status, 410);
        assert_eq!(
            response_json(&expired_cursor)["data"]["error"],
            serde_json::json!("operator_stream_cursor_expired")
        );
    }

    #[test]
    fn operator_action_idempotency_replays_same_response_and_conflicts_on_drift() {
        let (auditor, _sink) = operator_auditor();
        let calls = Arc::new(AtomicUsize::new(0));
        let server = server_with_dispatch(Arc::new(CountingDispatch {
            calls: Arc::clone(&calls),
        }));
        let cfg = HttpTransportConfig {
            operator_auditor: Some(auditor),
            ..Default::default()
        };
        let first_body = serde_json::json!({
            "idempotency_key": "operator-request-1",
            "tool": "oracle_preview_sql",
            "arguments": { "sql": "UPDATE t SET x = 1 WHERE id = 42" }
        });
        let action_request = |body: &Value| {
            HttpRequest::new(
                "POST",
                "/operator/v1/actions/preview",
                [
                    ("host", "127.0.0.1"),
                    ("content-type", "application/json"),
                    ("accept", "application/json"),
                ],
                body.to_string().into_bytes(),
            )
            .with_peer_loopback(true)
        };

        let first = handle_http_request(&server, &cfg, action_request(&first_body));
        assert_eq!(first.status, 200);
        let second = handle_http_request(&server, &cfg, action_request(&first_body));
        assert_eq!(second.status, 200);
        assert_eq!(
            response_json(&second),
            response_json(&first),
            "same idempotency key and request material replays the original response"
        );
        assert_eq!(
            calls.load(AtomicOrdering::SeqCst),
            1,
            "retry must not re-enter guarded dispatch"
        );
        let first_json = response_json(&first);
        assert_eq!(
            first_json["data"]["idempotency"]["request_id"],
            serde_json::json!("operator-request-1")
        );
        assert!(
            first_json["data"]["idempotency"]["grant_sha256"].is_null(),
            "preview has no consumed confirmation grant"
        );
        assert!(
            first_json["data"]["idempotency"]["sql_sha256"]
                .as_str()
                .is_some_and(|hash| hash.starts_with("sha256:"))
        );

        let drifted = serde_json::json!({
            "idempotency_key": "operator-request-1",
            "tool": "oracle_preview_sql",
            "arguments": { "sql": "UPDATE t SET x = 2 WHERE id = 42" }
        });
        let conflict = handle_http_request(&server, &cfg, action_request(&drifted));
        assert_eq!(conflict.status, 409);
        let conflict_json = response_json(&conflict);
        assert_eq!(
            conflict_json["data"]["error"],
            serde_json::json!("operator_idempotency_key_conflict")
        );
        assert_eq!(
            calls.load(AtomicOrdering::SeqCst),
            1,
            "conflicting replay must not re-enter guarded dispatch"
        );
    }

    #[test]
    fn operator_idempotency_ledger_reports_in_progress_before_completion() {
        let ledger = OperatorIdempotencyLedger::new();
        let subject = AuditSubject::new("local-owner", "fixture");
        let request = HttpRequest::new(
            "POST",
            "/operator/v1/actions/execute",
            [
                ("host", "127.0.0.1"),
                ("content-type", "application/json"),
                ("accept", "application/json"),
                ("idempotency-key", "execute-once"),
            ],
            Vec::new(),
        )
        .with_peer_loopback(true);
        let payload = serde_json::json!({
            "tool": "oracle_execute",
            "arguments": {
                "sql": "UPDATE t SET x = 1 WHERE id = 7",
                "confirm": "grant-ref"
            }
        });
        let payload = payload.as_object().expect("payload object");
        let arguments = payload.get("arguments").cloned().expect("arguments");
        let facts = operator_idempotency_facts(OperatorIdempotencyInput {
            request: &request,
            payload,
            operator_subject: &subject,
            route: OperatorRouteKind::ActionExecute,
            tool: "oracle_execute",
            arguments: &arguments,
            binding: None,
            operator_audit_seq: 9,
        });

        let lease = match ledger.begin(&request.path, facts.clone()) {
            OperatorIdempotencyBegin::Fresh(lease) => lease,
            _ => panic!("first reservation must be fresh"),
        };
        let in_progress = match ledger.begin(&request.path, facts.clone()) {
            OperatorIdempotencyBegin::InProgress(response) => response,
            _ => panic!("duplicate before completion must be typed in-progress"),
        };
        assert_eq!(in_progress.status, 409);
        let in_progress_json = response_json(&in_progress);
        assert_eq!(
            in_progress_json["data"]["error"],
            serde_json::json!("operator_idempotency_in_progress")
        );
        assert!(
            in_progress_json["data"]["idempotency"]["grant_sha256"]
                .as_str()
                .is_some_and(|hash| hash.starts_with("sha256:"))
        );

        let completed = facts.completed("unix:42".to_owned());
        let original = operator_json_response(
            200,
            &request.path,
            json!({ "status": "forwarded", "idempotency": completed.as_json("forwarded") }),
        );
        ledger.complete(lease, completed, original.clone());
        let replay = match ledger.begin(&request.path, facts) {
            OperatorIdempotencyBegin::Replay(response) => response,
            _ => panic!("duplicate after completion must replay"),
        };
        assert_eq!(replay, original);
    }

    #[test]
    fn workbench_no_bypass_guard_is_the_feature() {
        let (auditor, _sink) = operator_auditor();
        let calls = Arc::new(AtomicUsize::new(0));
        let server = server_with_dispatch(Arc::new(WorkbenchDispatch {
            calls: Arc::clone(&calls),
        }));
        let cfg = HttpTransportConfig {
            operator_auditor: Some(auditor),
            ..Default::default()
        };
        let action_request = |path: &'static str, body: &Value| {
            HttpRequest::new(
                "POST",
                path,
                [
                    ("host", "127.0.0.1"),
                    ("content-type", "application/json"),
                    ("accept", "application/json"),
                ],
                body.to_string().into_bytes(),
            )
            .with_peer_loopback(true)
        };

        let write_sql = "UPDATE accounts SET status = 'HOLD' WHERE id = :1";
        let direct_decision = Classifier::default().classify(write_sql);
        let preview = handle_http_request(
            &server,
            &cfg,
            action_request(
                "/operator/v1/actions/preview",
                &serde_json::json!({
                    "idempotency_key": "workbench-preview",
                    "tool": "oracle_preview_sql",
                    "arguments": { "sql": write_sql }
                }),
            ),
        );
        assert_eq!(preview.status, 200);
        let preview_result =
            response_json(&preview)["data"]["mcp_response"]["result"]["structuredContent"].clone();
        assert_eq!(
            preview_result["tool"],
            serde_json::json!("oracle_preview_sql")
        );
        assert_eq!(preview_result["args"]["sql"], serde_json::json!(write_sql));
        assert_eq!(
            preview_result["classification"]["required_level"],
            serde_json::to_value(direct_decision.required_level).expect("level serializes"),
            "workbench classify must be the same MCP classifier decision agents get"
        );

        let read_sql = "SELECT * FROM dual";
        let read = handle_http_request(
            &server,
            &cfg,
            action_request(
                "/operator/v1/actions/execute",
                &serde_json::json!({
                    "idempotency_key": "workbench-read",
                    "tool": "oracle_query",
                    "arguments": { "sql": read_sql, "max_rows": 100 }
                }),
            ),
        );
        assert_eq!(read.status, 200);
        let read_result =
            response_json(&read)["data"]["mcp_response"]["result"]["structuredContent"].clone();
        assert_eq!(read_result["tool"], serde_json::json!("oracle_query"));
        assert_eq!(read_result["args"]["sql"], serde_json::json!(read_sql));

        let execute = handle_http_request(
            &server,
            &cfg,
            action_request(
                "/operator/v1/actions/execute",
                &serde_json::json!({
                    "idempotency_key": "workbench-commit",
                    "tool": "oracle_execute",
                    "arguments": {
                        "sql": write_sql,
                        "binds": [42],
                        "commit": true,
                        "confirm": "opaque-preview-grant"
                    }
                }),
            ),
        );
        assert_eq!(execute.status, 200);
        let execute_result =
            response_json(&execute)["data"]["mcp_response"]["result"]["structuredContent"].clone();
        assert_eq!(execute_result["tool"], serde_json::json!("oracle_execute"));
        assert_eq!(execute_result["args"]["sql"], serde_json::json!(write_sql));
        assert_eq!(execute_result["args"]["commit"], serde_json::json!(true));
        assert_eq!(
            execute_result["args"]["confirm"],
            serde_json::json!("opaque-preview-grant")
        );

        let preview_bypass = handle_http_request(
            &server,
            &cfg,
            action_request(
                "/operator/v1/actions/preview",
                &serde_json::json!({
                    "tool": "oracle_execute",
                    "arguments": { "sql": write_sql, "commit": true, "confirm": "grant" }
                }),
            ),
        );
        assert_eq!(preview_bypass.status, 400);
        assert_eq!(
            response_json(&preview_bypass)["data"]["error"],
            serde_json::json!("operator_action_tool_not_allowed")
        );

        let compatibility_bypass = handle_http_request(
            &server,
            &cfg,
            action_request(
                "/operator/v1/actions/execute",
                &serde_json::json!({
                    "tool": "execute_approved",
                    "arguments": { "sql": write_sql, "token": "legacy-token" }
                }),
            ),
        );
        assert_eq!(compatibility_bypass.status, 400);
        assert_eq!(
            response_json(&compatibility_bypass)["data"]["error"],
            serde_json::json!("operator_action_tool_not_allowed")
        );
        assert_eq!(
            calls.load(AtomicOrdering::SeqCst),
            3,
            "blocked workbench bypass attempts must not enter dispatch"
        );
    }

    #[test]
    fn dashboard_workbench_ddl_apply_is_release_gated() {
        let (auditor, _sink) = operator_auditor();
        let calls = Arc::new(AtomicUsize::new(0));
        let server = server_with_dispatch(Arc::new(WorkbenchDispatch {
            calls: Arc::clone(&calls),
        }));
        let dir = dashboard_test_dir("ddl-gate");
        let auth = Arc::new(DashboardAuth::new(dir.clone()));
        let cfg = HttpTransportConfig {
            dashboard_auth: Some(Arc::clone(&auth)),
            operator_auditor: Some(auditor),
            ..Default::default()
        };
        let ticket = crate::dashboard_auth::mint_dashboard_pairing_ticket(&dir, "http://127.0.0.1")
            .expect("ticket mints");
        let login = auth
            .exchange_ticket(ticket_from_pairing_url(&ticket.url))
            .expect("login works");
        let cookie_pair = login.session_cookie.split(';').next().expect("cookie pair");
        let view = auth
            .session_view(Some(cookie_pair))
            .expect("session view works");
        let execute_ticket = view
            .action_tickets
            .iter()
            .find(|ticket| ticket.path == "/operator/v1/actions/execute")
            .expect("execute action ticket")
            .ticket
            .clone();

        let response = handle_http_request(
            &server,
            &cfg,
            HttpRequest::new(
                "POST",
                "/operator/v1/actions/execute",
                [
                    ("host", "127.0.0.1"),
                    ("origin", "http://127.0.0.1"),
                    ("sec-fetch-site", "same-origin"),
                    ("content-type", "application/json"),
                    ("accept", "application/json"),
                    ("cookie", cookie_pair),
                    (DASHBOARD_CSRF_HEADER, view.csrf_token.as_str()),
                    (DASHBOARD_ACTION_TICKET_HEADER, execute_ticket.as_str()),
                ],
                serde_json::json!({
                    "tool": "oracle_execute",
                    "arguments": {
                        "sql": "CREATE TABLE dashboard_apply_blocked (id NUMBER)",
                        "commit": true,
                        "confirm": "opaque-preview-grant"
                    }
                })
                .to_string()
                .into_bytes(),
            )
            .with_peer_loopback(true),
        );
        assert_eq!(response.status, 403);
        assert_eq!(
            response_json(&response)["data"]["error"],
            serde_json::json!("dashboard_ddl_workbench_disabled")
        );
        assert_eq!(
            calls.load(AtomicOrdering::SeqCst),
            0,
            "browser DDL apply must fail before MCP dispatch"
        );
    }

    fn dashboard_test_dir(name: &str) -> PathBuf {
        let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        dir.push("../../target/tmp/dashboard-http-tests");
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        dir.push(format!("{}-{nanos}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dashboard test dir");
        dir
    }

    fn ticket_from_pairing_url(url: &str) -> &str {
        url.split_once("ticket=")
            .map(|(_, token)| token)
            .expect("pairing URL has ticket query")
    }

    #[test]
    fn dashboard_pairing_sets_strict_cookie_and_session_view() {
        let (auditor, _sink) = operator_auditor();
        let dir = dashboard_test_dir("pairing");
        let auth = Arc::new(DashboardAuth::new(dir.clone()));
        let cfg = HttpTransportConfig {
            dashboard_auth: Some(Arc::clone(&auth)),
            operator_auditor: Some(auditor),
            ..Default::default()
        };
        let ticket = crate::dashboard_auth::mint_dashboard_pairing_ticket(&dir, "http://127.0.0.1")
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
    }

    #[test]
    fn malicious_page_cannot_trigger_dashboard_gated_action() {
        let (auditor, _sink) = operator_auditor();
        let calls = Arc::new(AtomicUsize::new(0));
        let server = server_with_dispatch(Arc::new(CountingDispatch {
            calls: Arc::clone(&calls),
        }));
        let dir = dashboard_test_dir("csrf");
        let auth = Arc::new(DashboardAuth::new(dir.clone()));
        let cfg = HttpTransportConfig {
            dashboard_auth: Some(Arc::clone(&auth)),
            operator_auditor: Some(auditor),
            ..Default::default()
        };
        let ticket = crate::dashboard_auth::mint_dashboard_pairing_ticket(&dir, "http://127.0.0.1")
            .expect("ticket mints");
        let login = auth
            .exchange_ticket(ticket_from_pairing_url(&ticket.url))
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
        assert_eq!(missing_csrf.status, 403);
        assert_eq!(
            response_json(&missing_csrf)["error"],
            serde_json::json!("dashboard_csrf_required")
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

    fn sse_json_events(response: &HttpResponse) -> Vec<Value> {
        String::from_utf8(response.body.clone())
            .expect("SSE body is UTF-8")
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .map(|json| serde_json::from_str(json).expect("SSE data is JSON"))
            .collect()
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

    #[test]
    fn cancelled_dispatch_outcome_is_http_499() {
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
        let response = handle_http_request(&cancelled_server(), &cfg, post(&body));

        assert_eq!(response.status, 499);
        let body = response_json(&response);
        assert_eq!(body["outcome"], serde_json::json!("cancelled"));
        assert_eq!(body["cancel_kind"], serde_json::json!("Timeout"));
        assert!(body.get("result").is_none());
    }

    #[test]
    fn panicked_dispatch_outcome_is_http_500() {
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
        let response = handle_http_request(&panicked_server(), &cfg, post(&body));

        assert_eq!(response.status, 500);
        let body = response_json(&response);
        assert_eq!(body["outcome"], serde_json::json!("panicked"));
        assert_eq!(body["error"], serde_json::json!("request_panicked"));
        assert!(body.get("result").is_none());
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
        let mut cfg = obs_config(HealthState::new("0.1.0"), Some(metrics), None);
        cfg.session_lifecycle = Some(Arc::new(StaticLaneLifecycle::one_lane()));
        let resp = handle_http_request(&test_server(), &cfg, get(METRICS_PATH));
        assert_eq!(resp.status, 200);
        assert_eq!(
            resp.header("content-type"),
            Some("text/plain; version=0.0.4; charset=utf-8")
        );
        let body = String::from_utf8(resp.body).expect("utf-8");
        assert!(body.contains("mcp_requests_total{tool=\"oracle_query\",status=\"ok\"} 1"));
        assert!(body.contains("mcp_active_lanes 1"));
        assert!(body.contains(
            "mcp_active_lane{lane_id=\"lane-a\",subject_id_hash=\"subject-sha256:abc\"} 1"
        ));
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

    fn accepting_oauth_enforcement(required_scopes: Vec<String>) -> Arc<OAuthEnforcement> {
        Arc::new(OAuthEnforcement {
            config: ResourceServerConfig {
                resource: "https://oraclemcp.example/mcp".to_owned(),
                allowed_issuers: vec!["https://idp.example".to_owned()],
                authorization_servers: vec!["https://idp.example".to_owned()],
                required_scopes,
            },
            verifier: Arc::new(AcceptHs256),
            metadata_url: "https://oraclemcp.example/.well-known/oauth-protected-resource"
                .to_owned(),
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
        assert_eq!(records.len(), 1);
        let (_, stable_id) = principal_key.split_once(':').expect("principal key");
        assert_eq!(
            records[0].subject,
            AuditSubject::new("oauth", stable_id).with_authn_method("oauth")
        );
        assert_eq!(records[0].tool, "operator_api");
        assert_eq!(records[0].sql_preview, "GET /operator/v1/sessions");
        assert!(!records[0].sql_preview.contains("force=true"));
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
    pub peer_is_loopback: bool,
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
            peer_is_loopback: false,
        }
    }

    /// Attach server-observed peer locality. Tests and embedders that construct
    /// requests directly must set this explicitly when modeling loopback.
    #[must_use]
    pub fn with_peer_loopback(mut self, peer_is_loopback: bool) -> Self {
        self.peer_is_loopback = peer_is_loopback;
        self
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
    DashboardPairing,
    DashboardSession,
    Mcp,
    OperatorApi,
    NotFound,
}

fn route_for(path: &str) -> HttpRoute {
    match path {
        PROTECTED_RESOURCE_METADATA_PATH => HttpRoute::ProtectedResourceMetadata,
        HEALTHZ_PATH | READYZ_PATH | METRICS_PATH => HttpRoute::Observability,
        DASHBOARD_PAIR_PATH => HttpRoute::DashboardPairing,
        DASHBOARD_SESSION_PATH => HttpRoute::DashboardSession,
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
                handle_observability_route(config, &request).unwrap_or_else(|| empty_response(404)),
            );
        }
        HttpRoute::DashboardPairing => {
            return HttpExchange::Buffered(handle_dashboard_pairing_route(config, &request));
        }
        HttpRoute::DashboardSession => {
            return HttpExchange::Buffered(handle_dashboard_session_route(config, &request));
        }
        HttpRoute::OperatorApi => {
            if let Some(response) = guard_http_request(config, &request) {
                return HttpExchange::Buffered(response);
            }
            let operator_route = operator_route_kind(&request.path);
            let required_media = if operator_route == OperatorRouteKind::Events {
                "text/event-stream"
            } else {
                "application/json"
            };
            if !accepts_media(request.header("accept"), required_media) {
                return HttpExchange::Buffered(empty_response(406));
            }
            let validated_oauth = match &config.oauth {
                Some(enforcement) => match validate_oauth_request(&request, enforcement) {
                    Ok(validated) => Some(validated),
                    Err(response) => return HttpExchange::Buffered(response),
                },
                None => None,
            };
            let principal_key = validated_oauth
                .as_ref()
                .map(|validated| validated.principal_key.as_str());
            if let Some(response) =
                enforce_dashboard_operator_auth(config, &request, principal_key.is_some())
            {
                return HttpExchange::Buffered(response);
            }
            let Some(operator_subject) = config
                .operator_authority
                .authorize(principal_key, request.peer_is_loopback)
            else {
                return HttpExchange::Buffered(operator_authority_required_response());
            };
            let operator_audit_seq =
                match append_operator_audit(config, &operator_subject, &request) {
                    Ok(seq) => seq,
                    Err(response) => return HttpExchange::Buffered(response),
                };
            let dashboard_browser = config.dashboard_auth.is_some() && principal_key.is_none();
            let response = handle_operator_api_route(
                server,
                config,
                &request,
                &operator_subject,
                operator_route,
                operator_audit_seq,
                dashboard_browser,
            );
            return HttpExchange::Buffered(if dashboard_browser {
                with_dashboard_security_headers(response)
            } else {
                response
            });
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
    if let Some(response) = enforce_mcp_protocol_version(&request) {
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

fn handle_dashboard_pairing_route(
    config: &HttpTransportConfig,
    request: &HttpRequest,
) -> HttpResponse {
    if request.method != "GET" {
        return with_dashboard_security_headers(empty_response(405).with_header("allow", "GET"));
    }
    if let Some(response) = guard_http_request(config, request) {
        return with_dashboard_security_headers(response);
    }
    let Some(auth) = &config.dashboard_auth else {
        return with_dashboard_security_headers(empty_response(404));
    };
    if !request.peer_is_loopback {
        return dashboard_auth_error_response(403, "dashboard_pairing_requires_loopback");
    }
    let Some(ticket) = request
        .query_param("ticket")
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return dashboard_auth_error_response(401, "dashboard_pairing_ticket_missing");
    };
    match auth.exchange_ticket(ticket) {
        Ok(login) => with_dashboard_security_headers(
            empty_response(303)
                .with_header("location", "/")
                .with_header("set-cookie", &login.session_cookie)
                .with_header("cache-control", "no-store"),
        ),
        Err(DashboardAuthError::ExpiredTicket) => {
            dashboard_auth_error_response(401, "dashboard_pairing_ticket_expired")
        }
        Err(_) => dashboard_auth_error_response(401, "dashboard_pairing_ticket_invalid"),
    }
}

fn handle_dashboard_session_route(
    config: &HttpTransportConfig,
    request: &HttpRequest,
) -> HttpResponse {
    if request.method != "GET" {
        return with_dashboard_security_headers(empty_response(405).with_header("allow", "GET"));
    }
    if let Some(response) = guard_http_request(config, request) {
        return with_dashboard_security_headers(response);
    }
    if let Some(response) = enforce_dashboard_get_headers(request) {
        return response;
    }
    let Some(auth) = &config.dashboard_auth else {
        return with_dashboard_security_headers(empty_response(404));
    };
    if config
        .operator_authority
        .authorize(None, request.peer_is_loopback)
        .is_none()
    {
        return dashboard_auth_error_response(403, "dashboard_operator_authority_required");
    }
    match auth.session_view(request.header("cookie")) {
        Ok(view) => with_dashboard_security_headers(json_response(
            200,
            &serde_json::to_value(view).unwrap_or(Value::Null),
        ))
        .with_header("cache-control", "no-store"),
        Err(_) => dashboard_auth_error_response(401, "dashboard_session_required"),
    }
}

fn enforce_dashboard_operator_auth(
    config: &HttpTransportConfig,
    request: &HttpRequest,
    has_authenticated_principal: bool,
) -> Option<HttpResponse> {
    let auth = config.dashboard_auth.as_ref()?;
    if has_authenticated_principal {
        return None;
    }
    if request.method == "POST" {
        if let Some(response) = enforce_dashboard_post_headers(request) {
            return Some(response);
        }
        return match auth.validate_action(
            request.header("cookie"),
            request.header(DASHBOARD_CSRF_HEADER),
            request.header(DASHBOARD_ACTION_TICKET_HEADER),
            &request.method,
            &request.path,
        ) {
            Ok(()) => None,
            Err(DashboardAuthError::MissingSession | DashboardAuthError::InvalidSession) => Some(
                dashboard_auth_error_response(401, "dashboard_session_required"),
            ),
            Err(DashboardAuthError::MissingCsrf | DashboardAuthError::InvalidCsrf) => Some(
                dashboard_auth_error_response(403, "dashboard_csrf_required"),
            ),
            Err(
                DashboardAuthError::MissingActionTicket | DashboardAuthError::InvalidActionTicket,
            ) => Some(dashboard_auth_error_response(
                403,
                "dashboard_action_ticket_required",
            )),
            Err(_) => Some(dashboard_auth_error_response(403, "dashboard_auth_failed")),
        };
    }
    if let Some(response) = enforce_dashboard_get_headers(request) {
        return Some(response);
    }
    match auth.session_view(request.header("cookie")) {
        Ok(_) => None,
        Err(_) => Some(dashboard_auth_error_response(
            401,
            "dashboard_session_required",
        )),
    }
}

fn enforce_dashboard_post_headers(request: &HttpRequest) -> Option<HttpResponse> {
    let origin = request.header("origin").map(str::trim).unwrap_or_default();
    if origin.is_empty() || !origin_matches_host(origin, request.header("host")) {
        return Some(dashboard_auth_error_response(
            403,
            "dashboard_same_origin_required",
        ));
    }
    if let Some(sec_fetch_site) = request.header("sec-fetch-site") {
        let sec_fetch_site = sec_fetch_site.trim();
        if !matches!(sec_fetch_site, "same-origin" | "none") {
            return Some(dashboard_auth_error_response(
                403,
                "dashboard_same_origin_required",
            ));
        }
    }
    None
}

fn enforce_dashboard_get_headers(request: &HttpRequest) -> Option<HttpResponse> {
    if let Some(origin) = request.header("origin")
        && !origin_matches_host(origin, request.header("host"))
    {
        return Some(dashboard_auth_error_response(
            403,
            "dashboard_same_origin_required",
        ));
    }
    if let Some(sec_fetch_site) = request.header("sec-fetch-site") {
        let sec_fetch_site = sec_fetch_site.trim();
        if !matches!(sec_fetch_site, "same-origin" | "none") {
            return Some(dashboard_auth_error_response(
                403,
                "dashboard_same_origin_required",
            ));
        }
    }
    None
}

fn origin_matches_host(origin: &str, host: Option<&str>) -> bool {
    let Some(host) = host.map(str::trim).filter(|host| !host.is_empty()) else {
        return false;
    };
    let origin = origin.trim().trim_end_matches('/');
    let Some((scheme, authority)) = origin.split_once("://") else {
        return false;
    };
    matches!(scheme, "http" | "https") && authority.eq_ignore_ascii_case(host)
}

fn dashboard_auth_error_response(status: u16, error: &'static str) -> HttpResponse {
    with_dashboard_security_headers(json_response(
        status,
        &json!({
            "error": error,
            "message": "dashboard authentication is required for this browser surface",
        }),
    ))
    .with_header("cache-control", "no-store")
}

fn with_dashboard_security_headers(response: HttpResponse) -> HttpResponse {
    response
        .with_header("content-security-policy", dashboard_csp())
        .with_header("x-content-type-options", "nosniff")
        .with_header("referrer-policy", "no-referrer")
        .with_header("x-frame-options", "DENY")
}

fn dashboard_csp() -> &'static str {
    "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
}

fn operator_authority_required_response() -> HttpResponse {
    json_response(
        403,
        &json!({
            "error": "operator_authority_required",
            "message": "operator API requires server-derived operator authority",
            "next_step": "use the local loopback owner path or configure http.operator.allowed_subjects",
        }),
    )
}

fn operator_audit_required_response() -> HttpResponse {
    json_response(
        503,
        &json!({
            "error": "operator_audit_required",
            "message": "operator API actions require a configured audit chain",
            "next_step": "set [audit].key_ref or keep /operator/v1 disabled",
        }),
    )
}

fn operator_audit_failed_response() -> HttpResponse {
    json_response(
        500,
        &json!({
            "error": "operator_audit_failed",
            "message": "operator API audit append failed; action refused",
        }),
    )
}

fn enforce_mcp_protocol_version(request: &HttpRequest) -> Option<HttpResponse> {
    let presented = request.header("mcp-protocol-version")?;
    if presented.trim() == PROTOCOL_VERSION {
        return None;
    }
    Some(
        json_response(
            400,
            &json!({
                "error": "unsupported_protocol_version",
                "message": "unsupported MCP-Protocol-Version header",
                "presented": presented,
                "supported": [PROTOCOL_VERSION],
            }),
        )
        .with_header("mcp-protocol-version", PROTOCOL_VERSION),
    )
}

fn audit_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{secs}")
}

fn append_operator_audit(
    config: &HttpTransportConfig,
    subject: &AuditSubject,
    request: &HttpRequest,
) -> Result<u64, HttpResponse> {
    let Some(auditor) = &config.operator_auditor else {
        return Err(operator_audit_required_response());
    };
    let draft = AuditEntryDraft {
        subject: subject.clone(),
        db_evidence: None,
        cancel: None,
        tool: "operator_api".to_owned(),
        sql: format!("{} {}", request.method, request.path),
        danger_level: "OPERATOR".to_owned(),
        decision: AuditDecision::Allowed,
        rows_affected: None,
        outcome: AuditOutcome::Succeeded,
    };
    auditor
        .append(&draft, audit_timestamp(), true)
        .map(|record| record.seq)
        .map_err(|_| operator_audit_failed_response())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OperatorRouteKind {
    Index,
    Schema,
    Health,
    Metrics,
    AuditTail,
    ActiveLanes,
    Vsession,
    Events,
    ActionPreview,
    ActionConfirm,
    ActionExecute,
    SetLevel,
    SwitchProfile,
    NotFound,
}

fn operator_route_kind(path: &str) -> OperatorRouteKind {
    match path {
        OPERATOR_API_PREFIX => OperatorRouteKind::Index,
        "/operator/v1/schema" => OperatorRouteKind::Schema,
        "/operator/v1/health" => OperatorRouteKind::Health,
        "/operator/v1/metrics" => OperatorRouteKind::Metrics,
        "/operator/v1/audit-tail" => OperatorRouteKind::AuditTail,
        "/operator/v1/active-lanes" => OperatorRouteKind::ActiveLanes,
        "/operator/v1/vsession" => OperatorRouteKind::Vsession,
        "/operator/v1/events" => OperatorRouteKind::Events,
        "/operator/v1/actions/preview" => OperatorRouteKind::ActionPreview,
        "/operator/v1/actions/confirm" => OperatorRouteKind::ActionConfirm,
        "/operator/v1/actions/execute" => OperatorRouteKind::ActionExecute,
        "/operator/v1/session/set-level" => OperatorRouteKind::SetLevel,
        "/operator/v1/session/switch-profile" => OperatorRouteKind::SwitchProfile,
        _ => OperatorRouteKind::NotFound,
    }
}

impl OperatorRouteKind {
    fn allowed_method(self) -> &'static str {
        match self {
            Self::ActionPreview
            | Self::ActionConfirm
            | Self::ActionExecute
            | Self::SetLevel
            | Self::SwitchProfile => "POST",
            _ => "GET",
        }
    }
}

fn handle_operator_api_route(
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    request: &HttpRequest,
    operator_subject: &AuditSubject,
    route: OperatorRouteKind,
    operator_audit_seq: u64,
    dashboard_browser: bool,
) -> HttpResponse {
    if route == OperatorRouteKind::NotFound {
        return operator_not_found_response(request);
    }
    let allowed = route.allowed_method();
    if request.method != allowed {
        return empty_response(405).with_header("allow", allowed);
    }
    match route {
        OperatorRouteKind::Index => json_response(200, &operator_route_index()),
        OperatorRouteKind::Schema => json_response(200, &operator_schema_bundle()),
        OperatorRouteKind::Health => operator_json_response(
            200,
            &request.path,
            operator_health_data(&config.observability),
        ),
        OperatorRouteKind::Metrics => {
            operator_json_response(200, &request.path, operator_metrics_data(config))
        }
        OperatorRouteKind::AuditTail => operator_json_response(
            200,
            &request.path,
            operator_audit_tail_data(config, request),
        ),
        OperatorRouteKind::ActiveLanes => {
            operator_json_response(200, &request.path, operator_active_lanes_data(config))
        }
        OperatorRouteKind::Vsession => {
            operator_json_response(200, &request.path, operator_vsession_data())
        }
        OperatorRouteKind::Events => operator_events_response(config, request, operator_subject),
        OperatorRouteKind::ActionPreview
        | OperatorRouteKind::ActionConfirm
        | OperatorRouteKind::ActionExecute
        | OperatorRouteKind::SetLevel
        | OperatorRouteKind::SwitchProfile => handle_operator_action_route(
            server,
            config,
            request,
            operator_subject,
            route,
            operator_audit_seq,
            dashboard_browser,
        ),
        OperatorRouteKind::NotFound => unreachable!("handled above"),
    }
}

fn operator_json_response(status: u16, route: &str, data: Value) -> HttpResponse {
    let body = operator_response(route, data);
    debug_assert!(
        validate_operator_response(&body).is_ok(),
        "operator REST response must match the Rust contract"
    );
    json_response(status, &body)
}

fn operator_not_found_response(request: &HttpRequest) -> HttpResponse {
    let filters: serde_json::Map<String, Value> = request
        .query
        .iter()
        .filter(|(name, _)| name != "cursor")
        .map(|(name, value)| (name.clone(), Value::String(value.clone())))
        .collect();
    operator_json_response(
        404,
        &request.path,
        json!({
            "error": "operator_route_not_found",
            "message": "operator API route is not served",
            "path": request.path,
            "query": {
                "cursor": request.query_param("cursor"),
                "filters": filters,
            },
        }),
    )
}

fn operator_health_data(obs: &ObservabilityState) -> Value {
    let liveness = obs
        .health
        .as_ref()
        .map(|health| serde_json::to_value(health.liveness().1).unwrap_or(Value::Null))
        .unwrap_or_else(|| {
            json!({
                "status": "unavailable",
                "live": false,
                "ready": false,
                "version": null,
            })
        });
    let (ready, health_ready) = obs
        .health
        .as_ref()
        .map(|health| (health.is_ready(), health.is_ready()))
        .unwrap_or((false, false));
    let db_reachable = obs
        .readiness_probe
        .as_ref()
        .is_some_and(|probe| probe.is_db_reachable());
    json!({
        "source": if obs.health.is_some() { "self_lane" } else { "unavailable" },
        "liveness": liveness,
        "readiness": {
            "status": if ready && db_reachable { "ok" } else { "unavailable" },
            "ready": ready && db_reachable,
            "db_reachable": db_reachable,
            "draining": !health_ready,
        }
    })
}

fn operator_metrics_data(config: &HttpTransportConfig) -> Value {
    refresh_active_lane_metrics(config);
    match &config.observability.metrics {
        Some(metrics) => json!({
            "source": "self_lane",
            "snapshot": metrics.snapshot(),
        }),
        None => json!({
            "source": "unavailable",
            "reason": "metrics provider is not configured",
            "snapshot": null,
        }),
    }
}

fn active_lane_snapshots(config: &HttpTransportConfig) -> Vec<HttpLaneSnapshot> {
    config
        .session_lifecycle
        .as_ref()
        .map(|lifecycle| lifecycle.active_lanes())
        .unwrap_or_default()
}

fn refresh_active_lane_metrics(config: &HttpTransportConfig) {
    let lanes = active_lane_snapshots(config);
    set_active_lane_metrics_from_snapshots(config, &lanes);
}

fn set_active_lane_metrics_from_snapshots(
    config: &HttpTransportConfig,
    lanes: &[HttpLaneSnapshot],
) {
    if let Some(metrics) = &config.observability.metrics {
        let labels = lanes
            .iter()
            .map(|lane| (lane.lane_id.clone(), lane.subject_id_hash.clone()))
            .collect::<Vec<_>>();
        metrics.set_active_lanes(&labels);
    }
}

fn operator_active_lanes_data(config: &HttpTransportConfig) -> Value {
    let lane_snapshots = active_lane_snapshots(config);
    set_active_lane_metrics_from_snapshots(config, &lane_snapshots);
    let lanes = lane_snapshots
        .into_iter()
        .map(|lane| {
            json!({
                "lane_id": lane.lane_id,
                "generation": lane.generation,
                "status": lane.status,
                "subject_id_hash": lane.subject_id_hash,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "source": if config.session_lifecycle.is_some() { "self_lane" } else { "unavailable" },
        "lanes": lanes,
    })
}

fn operator_vsession_data() -> Value {
    json!({
        "source": "unavailable",
        "reason": "v$session summary requires a configured monitor profile; this provider is not configured",
        "sessions": [],
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuditTailQuery {
    limit: usize,
    subject_id_hash: Option<String>,
    danger_level: Option<String>,
    tool: Option<String>,
    decision: Option<String>,
    outcome: Option<String>,
    export_proof_bundle: bool,
}

impl AuditTailQuery {
    fn from_request(request: &HttpRequest) -> Self {
        Self {
            limit: request
                .query_param("limit")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(50)
                .clamp(1, 200),
            subject_id_hash: query_param_trimmed(request, "subject_id_hash")
                .or_else(|| query_param_trimmed(request, "subject")),
            danger_level: query_param_trimmed(request, "danger_level")
                .or_else(|| query_param_trimmed(request, "level")),
            tool: query_param_trimmed(request, "tool"),
            decision: query_param_trimmed(request, "decision"),
            outcome: query_param_trimmed(request, "outcome"),
            export_proof_bundle: request
                .query_param("export")
                .or_else(|| request.query_param("format"))
                .is_some_and(|value| {
                    value.eq_ignore_ascii_case("proof-bundle")
                        || value.eq_ignore_ascii_case("proof_bundle")
                }),
        }
    }

    fn matches(&self, record: &AuditRecord) -> bool {
        if let Some(expected) = self.subject_id_hash.as_deref()
            && operator_subject_id_hash(&audit_subject_key(record)) != expected
        {
            return false;
        }
        if let Some(expected) = self.tool.as_deref()
            && !record.tool.eq_ignore_ascii_case(expected)
        {
            return false;
        }
        if let Some(expected) = self.danger_level.as_deref()
            && !record.danger_level.eq_ignore_ascii_case(expected)
        {
            return false;
        }
        if let Some(expected) = self.decision.as_deref()
            && !audit_enum_label(&record.decision).eq_ignore_ascii_case(expected)
        {
            return false;
        }
        if let Some(expected) = self.outcome.as_deref()
            && !audit_enum_label(&record.outcome).eq_ignore_ascii_case(expected)
        {
            return false;
        }
        true
    }

    fn filters_json(&self) -> Value {
        json!({
            "subject_id_hash": self.subject_id_hash,
            "danger_level": self.danger_level,
            "tool": self.tool,
            "decision": self.decision,
            "outcome": self.outcome,
        })
    }
}

struct AuditTailRead {
    records: Vec<Value>,
    scanned_records: usize,
    selected_records: usize,
    proof: Value,
}

#[derive(Debug)]
struct AuditTailProofBuilder {
    previous_hash: String,
    previous_seq: Option<u64>,
    broken: Option<Value>,
}

impl AuditTailProofBuilder {
    fn new() -> Self {
        Self {
            previous_hash: GENESIS_HASH.to_owned(),
            previous_seq: None,
            broken: None,
        }
    }

    fn observe(&mut self, record: &AuditRecord, index: usize) {
        if self.broken.is_some() {
            return;
        }
        if !record.hash_is_valid() {
            self.broken = Some(json!({
                "seq": record.seq,
                "index": index,
                "check": "entry_hash",
                "reason": "entry_hash does not match the record content",
            }));
            return;
        }
        if record.prev_hash != self.previous_hash {
            self.broken = Some(json!({
                "seq": record.seq,
                "index": index,
                "check": "prev_hash",
                "reason": "prev_hash does not link to the previous record",
                "expected": self.previous_hash,
                "found": record.prev_hash,
            }));
            return;
        }
        let expected_seq = self.previous_seq.map_or(1, |seq| seq + 1);
        if record.seq != expected_seq {
            self.broken = Some(json!({
                "seq": record.seq,
                "index": index,
                "check": "seq",
                "reason": "seq is not monotonic",
                "expected": expected_seq,
                "found": record.seq,
            }));
            return;
        }
        self.previous_hash = record.entry_hash.clone();
        self.previous_seq = Some(record.seq);
    }

    fn finish(self, scanned_records: usize, selected_records: usize) -> Value {
        let hash_chain = match self.broken {
            Some(broken) => json!({
                "status": "broken",
                "records": scanned_records,
                "selected_records": selected_records,
                "broken": broken,
            }),
            None => json!({
                "status": "ok",
                "records": scanned_records,
                "selected_records": selected_records,
                "last_seq": self.previous_seq,
                "last_entry_hash": if scanned_records == 0 {
                    Value::Null
                } else {
                    Value::String(self.previous_hash)
                },
            }),
        };
        json!({
            "verification": {
                "hash_chain": hash_chain,
                "keyed_mac": {
                    "status": "not_checked",
                    "reason": "operator audit tail does not load signing keys; run `oraclemcp audit verify` with the audit signing key for keyed MAC verification"
                }
            },
            "redaction": audit_tail_redaction_policy(),
        })
    }
}

fn operator_audit_tail_data(config: &HttpTransportConfig, request: &HttpRequest) -> Value {
    let query = AuditTailQuery::from_request(request);
    let Some(path) = config.operator_audit_tail_path.as_ref() else {
        return json!({
            "source": "unavailable",
            "reason": "audit tail provider is not configured",
            "limit": query.limit,
            "filters": query.filters_json(),
            "records": [],
        });
    };
    match read_redacted_audit_tail(path, &query) {
        Ok(view) => {
            let export = query
                .export_proof_bundle
                .then(|| audit_tail_proof_bundle(path, &query, &view));
            json!({
                "source": "self_lane",
                "limit": query.limit,
                "filters": query.filters_json(),
                "scanned_records": view.scanned_records,
                "selected_records": view.selected_records,
                "records": view.records,
                "proof": view.proof,
                "export": export,
            })
        }
        Err(reason) => json!({
            "source": "unavailable",
            "reason": reason,
            "limit": query.limit,
            "filters": query.filters_json(),
            "records": [],
        }),
    }
}

fn read_redacted_audit_tail(path: &Path, query: &AuditTailQuery) -> Result<AuditTailRead, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("audit tail unavailable: {e}"))?;
    let reader = BufReader::new(file);
    let mut tail = VecDeque::with_capacity(query.limit);
    let mut proof = AuditTailProofBuilder::new();
    let mut scanned_records = 0usize;
    let mut selected_records = 0usize;
    for (line_index, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("audit tail read failed: {e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let record: AuditRecord =
            serde_json::from_str(&line).map_err(|e| format!("audit tail parse failed: {e}"))?;
        proof.observe(&record, line_index);
        scanned_records += 1;
        if !query.matches(&record) {
            continue;
        }
        selected_records += 1;
        if tail.len() == query.limit {
            tail.pop_front();
        }
        tail.push_back(redacted_audit_record(&record));
    }
    Ok(AuditTailRead {
        records: tail.into_iter().collect(),
        scanned_records,
        selected_records,
        proof: proof.finish(scanned_records, selected_records),
    })
}

fn query_param_trimmed(request: &HttpRequest, key: &str) -> Option<String> {
    request
        .query_param(key)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn audit_enum_label<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "UNKNOWN".to_owned())
}

fn audit_subject_key(record: &AuditRecord) -> String {
    if record.subject != AuditSubject::default() {
        return record.subject.legacy_agent_identity();
    }
    if !record.agent_identity.is_empty() {
        return record.agent_identity.clone();
    }
    "unknown:unknown".to_owned()
}

fn redacted_audit_record(record: &AuditRecord) -> Value {
    let subject_key = audit_subject_key(record);
    json!({
        "schema_version": record.schema_version,
        "seq": record.seq,
        "timestamp": record.timestamp,
        "subject_id_hash": operator_subject_id_hash(&subject_key),
        "tool": record.tool,
        "danger_level": record.danger_level,
        "decision": record.decision,
        "outcome": record.outcome,
        "rows_affected": record.rows_affected,
        "sql_sha256": record.sql_sha256,
        "sql_text": {
            "availability": "not_exported",
            "reason": "timeline and proof bundle expose sql_sha256 only; SQL text may contain inlined literals"
        },
        "bind_values": {
            "status": "redacted",
            "stored": false,
            "reveal": "unavailable_no_bind_values_stored"
        },
        "db_evidence": db_evidence_json(record.db_evidence.as_ref()),
        "proof": {
            "prev_hash": record.prev_hash,
            "entry_hash": record.entry_hash,
            "hash_valid": record.hash_is_valid(),
            "key_id": record.key_id,
            "signature": record.signature,
        },
    })
}

fn db_evidence_json(evidence: Option<&DbEvidence>) -> Value {
    let Some(evidence) = evidence else {
        return Value::Null;
    };
    json!({
        "availability": evidence.availability,
        "db_unique_name": evidence.db_unique_name,
        "service_name": evidence.service_name,
        "instance_name": evidence.instance_name,
        "session_user": evidence.session_user,
        "current_user": evidence.current_user,
        "proxy_user": evidence.proxy_user,
        "current_schema": evidence.current_schema,
        "sid": evidence.sid,
        "serial_number": evidence.serial_number,
        "client_identifier": evidence.client_identifier,
        "module": evidence.module,
        "action": evidence.action,
        "database_role": evidence.database_role,
        "open_mode": evidence.open_mode,
    })
}

fn audit_tail_redaction_policy() -> Value {
    json!({
        "subject": "subject_id_hash_only",
        "sql": "sql_sha256_only",
        "bind_values": "not_stored_redacted_by_default",
        "secrets": "never_serialized",
    })
}

fn audit_tail_proof_bundle(path: &Path, query: &AuditTailQuery, view: &AuditTailRead) -> Value {
    json!({
        "format": "oraclemcp.audit.proof-bundle.v1",
        "source": "audit_tail",
        "file": path.display().to_string(),
        "limit": query.limit,
        "filters": query.filters_json(),
        "scanned_records": view.scanned_records,
        "selected_records": view.selected_records,
        "records": view.records,
        "proof": view.proof,
    })
}

fn operator_events_response(
    config: &HttpTransportConfig,
    request: &HttpRequest,
    operator_subject: &AuditSubject,
) -> HttpResponse {
    let lane_id = match operator_event_lane_id(request) {
        Ok(lane_id) => lane_id,
        Err(data) => return operator_json_response(400, &request.path, data),
    };
    let cursor = request
        .query_param("cursor")
        .or_else(|| request.header("last-event-id"));
    let cursor_seq = match parse_operator_event_cursor(cursor, &lane_id) {
        Ok(cursor_seq) => cursor_seq,
        Err(data) => return operator_json_response(400, &request.path, data),
    };
    let gap_on_expired_cursor =
        request.query_param("cursor").is_none() && request.header("last-event-id").is_some();
    let active_lanes = operator_active_lanes_data(config);
    let lane_count = active_lanes["lanes"].as_array().map_or(0, Vec::len);
    let subject_key = operator_subject.legacy_agent_identity();
    let events = match config.operator_events.append_snapshot_and_resume(
        &subject_key,
        &lane_id,
        cursor,
        cursor_seq,
        gap_on_expired_cursor,
        json!({
            "protocol_version": OPERATOR_PROTOCOL_VERSION,
            "active_lanes": lane_count,
            "health": operator_health_data(&config.observability),
            "metrics": operator_metrics_data(config),
        }),
    ) {
        Ok(events) => events,
        Err(OperatorEventReplayError::Expired {
            cursor,
            oldest_event_id,
        }) => {
            return operator_json_response(
                410,
                &request.path,
                json!({
                    "error": "operator_stream_cursor_expired",
                    "message": "requested operator event cursor is older than the retained event buffer",
                    "cursor": cursor,
                    "oldest_event_id": oldest_event_id,
                    "lane_id": lane_id,
                    "next_step": "restart the operator event stream; the missing event range is no longer available for replay",
                }),
            );
        }
    };
    operator_sse_response(&events)
}

fn operator_event_lane_id(request: &HttpRequest) -> Result<String, Value> {
    let lane_id = request
        .query_param("lane_id")
        .or_else(|| request.query_param("lane"))
        .unwrap_or("operator")
        .trim();
    if lane_id.is_empty() || lane_id.contains('/') || lane_id.len() > 128 {
        return Err(json!({
            "error": "invalid_operator_event_lane",
            "message": "operator event lane_id must be non-empty, at most 128 bytes, and must not contain /",
        }));
    }
    Ok(lane_id.to_owned())
}

fn parse_operator_event_cursor(
    cursor: Option<&str>,
    expected_lane_id: &str,
) -> Result<Option<u64>, Value> {
    let Some(cursor) = cursor.map(str::trim).filter(|cursor| !cursor.is_empty()) else {
        return Ok(None);
    };
    if let Ok(seq) = cursor.parse::<u64>() {
        return Ok(Some(seq));
    }
    let Some((lane_id, seq)) = cursor.rsplit_once('/') else {
        return Err(json!({
            "error": "invalid_operator_event_cursor",
            "message": "cursor must be an operator event id such as operator/1 or a sequence number",
        }));
    };
    if lane_id != expected_lane_id {
        return Err(json!({
            "error": "operator_event_cursor_lane_mismatch",
            "message": "cursor lane_id does not match the requested operator event stream",
            "cursor_lane_id": lane_id,
            "lane_id": expected_lane_id,
        }));
    }
    seq.parse::<u64>().map(Some).map_err(|_| {
        json!({
            "error": "invalid_operator_event_cursor",
            "message": "cursor must be an operator event id such as operator/1 or a sequence number",
        })
    })
}

fn operator_event_sequence(id: &str) -> Option<u64> {
    id.rsplit('/').next()?.parse().ok()
}

fn operator_events_after_sequence(
    events: &[HttpBufferedEvent],
    after_seq: u64,
    cursor: Option<&str>,
    gap_on_expired_cursor: bool,
    lane_id: &str,
    subject_key: &str,
) -> Result<Vec<HttpBufferedEvent>, OperatorEventReplayError> {
    if let Some(oldest_event) = events.first()
        && let Some(oldest_seq) = operator_event_sequence(&oldest_event.id)
        && after_seq < oldest_seq.saturating_sub(1)
    {
        if !gap_on_expired_cursor {
            return Err(OperatorEventReplayError::Expired {
                cursor: cursor.unwrap_or("").to_owned(),
                oldest_event_id: oldest_event.id.clone(),
            });
        }
        let gap_seq = oldest_seq.saturating_sub(1);
        let gap_event = operator_event(
            gap_seq,
            lane_id,
            subject_key,
            "operator.stream_gap",
            json!({
                "type": "stream_gap",
                "message": "one or more operator events were dropped before this resume point",
                "requested_last_event_id": cursor.unwrap_or(""),
                "oldest_event_id": oldest_event.id.as_str(),
                "next_step": "continue from the retained events in this stream; restart the operator event stream if the missing range is required",
            }),
        );
        debug_assert!(
            validate_operator_event(&gap_event).is_ok(),
            "operator stream gap event must match the Rust contract"
        );
        let mut resumed = Vec::with_capacity(events.len().saturating_add(1));
        resumed.push(HttpBufferedEvent {
            id: gap_event
                .get("event_id")
                .and_then(Value::as_str)
                .unwrap_or("operator/0")
                .to_owned(),
            event: Some("operator.stream_gap"),
            data: gap_event,
        });
        resumed.extend(events.iter().cloned());
        return Ok(resumed);
    }
    Ok(events
        .iter()
        .filter(|event| operator_event_sequence(&event.id).is_some_and(|seq| seq > after_seq))
        .cloned()
        .collect())
}

fn operator_sse_response(events: &[HttpBufferedEvent]) -> HttpResponse {
    let mut body = Vec::new();
    for (idx, event) in events.iter().enumerate() {
        write_sse_event(
            &mut body,
            event.event,
            Some(&event.id),
            (idx == 0).then_some(3000),
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

fn handle_operator_action_route(
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    request: &HttpRequest,
    operator_subject: &AuditSubject,
    route: OperatorRouteKind,
    operator_audit_seq: u64,
    dashboard_browser: bool,
) -> HttpResponse {
    if !content_type_is_json(request) {
        return empty_response(415);
    }
    let payload = match serde_json::from_slice::<Value>(&request.body) {
        Ok(Value::Object(payload)) => payload,
        Ok(_) | Err(_) => {
            return operator_json_response(
                400,
                &request.path,
                json!({
                    "error": "invalid_operator_action",
                    "message": "operator action body must be a JSON object",
                }),
            );
        }
    };
    let lane_id = payload
        .get("lane_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let (tool, mut arguments) = match operator_action_target(route, &payload) {
        Ok(target) => target,
        Err(response) => return operator_json_response(400, &request.path, response),
    };
    if route == OperatorRouteKind::ActionPreview {
        force_preview_mode(tool, &mut arguments);
    }
    if dashboard_browser
        && let Some(data) = dashboard_workbench_release_gate(route, tool, &arguments)
    {
        return operator_json_response(403, &request.path, data);
    }

    let binding = match operator_action_lane_binding(config, lane_id.as_deref()) {
        Ok(binding) => binding,
        Err(response) => return operator_json_response(response.0, &request.path, response.1),
    };
    let idempotency_facts = operator_idempotency_facts(OperatorIdempotencyInput {
        request,
        payload: &payload,
        operator_subject,
        route,
        tool,
        arguments: &arguments,
        binding: binding.as_ref(),
        operator_audit_seq,
    });
    let idempotency_lease = match config
        .operator_idempotency
        .begin(&request.path, idempotency_facts.clone())
    {
        OperatorIdempotencyBegin::Fresh(lease) => lease,
        OperatorIdempotencyBegin::Replay(response)
        | OperatorIdempotencyBegin::InProgress(response)
        | OperatorIdempotencyBegin::Conflict(response) => return response,
    };
    let operator_key;
    let mut context = DispatchContext::default();
    if let Some(binding) = binding.as_ref() {
        context = context
            .with_http_session_id(&binding.mcp_session_id)
            .with_principal_key(&binding.principal_key);
    } else {
        operator_key = operator_subject.legacy_agent_identity();
        context = context.with_principal_key(&operator_key);
    }

    let rpc = json!({
        "jsonrpc": "2.0",
        "id": "operator-v1",
        "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": arguments,
        }
    });
    let response = server.handle_jsonrpc_request_with_context(rpc, None, context);
    let status = if response.is_some() {
        "forwarded"
    } else {
        "accepted"
    };
    let mut data = json!({
        "status": if response.is_some() { "forwarded" } else { "accepted" },
        "lane_id": binding
            .as_ref()
            .map(|binding| binding.lane_id.as_str())
            .or(lane_id.as_deref()),
        "mcp_tool": tool,
        "mcp_response": response,
    });
    let completed_facts = idempotency_facts.completed(audit_timestamp());
    if let Value::Object(data) = &mut data {
        data.insert("idempotency".to_owned(), completed_facts.as_json(status));
    }
    let response = operator_json_response(
        if status == "accepted" { 202 } else { 200 },
        &request.path,
        data,
    );
    config
        .operator_idempotency
        .complete(idempotency_lease, completed_facts, response)
}

fn operator_action_target(
    route: OperatorRouteKind,
    payload: &serde_json::Map<String, Value>,
) -> Result<(&'static str, Value), Value> {
    match route {
        OperatorRouteKind::SetLevel => Ok((
            "oracle_set_session_level",
            operator_arguments_from_payload(payload),
        )),
        OperatorRouteKind::SwitchProfile => Ok((
            "oracle_switch_profile",
            operator_arguments_from_payload(payload),
        )),
        OperatorRouteKind::ActionPreview
        | OperatorRouteKind::ActionConfirm
        | OperatorRouteKind::ActionExecute => {
            let Some(tool) = payload.get("tool").and_then(Value::as_str) else {
                return Err(json!({
                    "error": "invalid_operator_action",
                    "message": "action body must include tool",
                }));
            };
            let Some(tool) = allowed_operator_action_tool(route, tool) else {
                return Err(json!({
                    "error": "operator_action_tool_not_allowed",
                    "message": "tool is not allowed for this operator action route",
                    "tool": tool,
                }));
            };
            Ok((tool, operator_arguments_from_payload(payload)))
        }
        _ => unreachable!("non-action route"),
    }
}

fn dashboard_workbench_release_gate(
    route: OperatorRouteKind,
    tool: &str,
    arguments: &Value,
) -> Option<Value> {
    if !matches!(
        route,
        OperatorRouteKind::ActionConfirm | OperatorRouteKind::ActionExecute
    ) || tool != "oracle_execute"
    {
        return None;
    }
    let sql = arguments.get("sql").and_then(Value::as_str)?;
    let decision = oraclemcp_guard::Classifier::default().classify(sql);
    if decision
        .required_level
        .is_some_and(|level| level >= oraclemcp_guard::OperatingLevel::Ddl)
    {
        return Some(json!({
            "error": "dashboard_ddl_workbench_disabled",
            "message": "browser dashboard DDL/Admin apply is release-gated; preview remains available",
            "required_level": decision.required_level,
            "next_step": "use /operator/v1/actions/preview to inspect the statement, or use a non-browser operator path with the normal profile ceiling",
        }));
    }
    None
}

fn operator_arguments_from_payload(payload: &serde_json::Map<String, Value>) -> Value {
    payload.get("arguments").cloned().unwrap_or_else(|| {
        let mut args = payload.clone();
        args.remove("lane_id");
        args.remove("tool");
        args.remove("idempotency_key");
        args.remove("request_id");
        args.remove("idempotency_sequence");
        Value::Object(args)
    })
}

struct OperatorIdempotencyInput<'a> {
    request: &'a HttpRequest,
    payload: &'a serde_json::Map<String, Value>,
    operator_subject: &'a AuditSubject,
    route: OperatorRouteKind,
    tool: &'a str,
    arguments: &'a Value,
    binding: Option<&'a HttpLaneBinding>,
    operator_audit_seq: u64,
}

fn operator_idempotency_facts(input: OperatorIdempotencyInput<'_>) -> OperatorIdempotencyFacts {
    let lane_id = input
        .binding
        .map(|binding| binding.lane_id.clone())
        .or_else(|| {
            input
                .payload
                .get("lane_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
    let lane_generation = input.binding.map(|binding| binding.generation).or_else(|| {
        input
            .payload
            .get("idempotency_sequence")
            .and_then(Value::as_u64)
    });
    let subject_key = input.operator_subject.legacy_agent_identity();
    let subject_id_hash = operator_subject_id_hash(&subject_key);
    let explicit_key = input
        .request
        .header("idempotency-key")
        .or_else(|| input.payload.get("idempotency_key").and_then(Value::as_str))
        .or_else(|| input.payload.get("request_id").and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let derivation = json!({
        "protocol": OPERATOR_PROTOCOL_VERSION,
        "route": input.request.path,
        "route_kind": format!("{:?}", input.route),
        "tool": input.tool,
        "lane_id": lane_id,
        "lane_generation": lane_generation.unwrap_or(0),
        "subject_id_hash": subject_id_hash,
        "arguments": input.arguments,
    });
    let derived_key = format!("derived:{}", prefixed_sha256_hex(&json_bytes(&derivation)));
    let request_id = explicit_key.unwrap_or(&derived_key).to_owned();
    let idempotency_key_sha256 = prefixed_sha256_hex(request_id.as_bytes());
    let fingerprint_sha256 = prefixed_sha256_hex(&json_bytes(&derivation));
    let storage_key = prefixed_sha256_hex(
        format!("{subject_key}\0{}\0{request_id}", input.request.path).as_bytes(),
    );
    OperatorIdempotencyFacts {
        storage_key,
        request_id,
        idempotency_key_sha256,
        fingerprint_sha256,
        lane_id,
        lane_generation,
        subject_id_hash,
        grant_sha256: operator_grant_sha256(input.arguments),
        sql_sha256: operator_sql_sha256(input.arguments),
        operator_audit_seq: input.operator_audit_seq,
        started_at: audit_timestamp(),
        completed_at: None,
    }
}

fn json_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap_or_else(|_| b"<json-serialization-failed>".to_vec())
}

fn prefixed_sha256_hex(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

fn operator_grant_sha256(arguments: &Value) -> Option<String> {
    ["confirm", "token", "confirmation_token"]
        .into_iter()
        .find_map(|name| arguments.get(name).and_then(Value::as_str))
        .map(|grant| prefixed_sha256_hex(grant.as_bytes()))
}

fn operator_sql_sha256(arguments: &Value) -> Option<String> {
    ["sql", "source_code", "ddl"]
        .into_iter()
        .find_map(|name| arguments.get(name).and_then(Value::as_str))
        .map(|sql| prefixed_sha256_hex(sql.as_bytes()))
}

fn allowed_operator_action_tool(route: OperatorRouteKind, tool: &str) -> Option<&'static str> {
    const PREVIEW: &[&str] = &[
        "oracle_preview_sql",
        "oracle_set_session_level",
        "oracle_compile_object",
        "oracle_create_or_replace",
        "oracle_patch_source",
    ];
    const CONFIRM: &[&str] = &[
        "oracle_execute",
        "oracle_set_session_level",
        "oracle_compile_object",
        "oracle_create_or_replace",
        "oracle_patch_source",
    ];
    const EXECUTE: &[&str] = &[
        "oracle_query",
        "oracle_execute",
        "oracle_set_session_level",
        "oracle_compile_object",
        "oracle_create_or_replace",
        "oracle_patch_source",
    ];
    let allowed = match route {
        OperatorRouteKind::ActionPreview => PREVIEW,
        OperatorRouteKind::ActionConfirm => CONFIRM,
        OperatorRouteKind::ActionExecute => EXECUTE,
        _ => &[],
    };
    allowed.iter().copied().find(|candidate| *candidate == tool)
}

fn force_preview_mode(tool: &str, arguments: &mut Value) {
    if tool == "oracle_preview_sql" {
        return;
    }
    if let Value::Object(args) = arguments {
        args.insert("execute".to_owned(), Value::Bool(false));
    }
}

fn operator_action_lane_binding(
    config: &HttpTransportConfig,
    lane_id: Option<&str>,
) -> Result<Option<HttpLaneBinding>, (u16, Value)> {
    if !config.stateful {
        return Ok(None);
    }
    let Some(lane_id) = lane_id else {
        return Err((
            400,
            json!({
                "error": "operator_lane_required",
                "message": "stateful operator actions require lane_id",
            }),
        ));
    };
    let Some(lifecycle) = config.session_lifecycle.as_ref() else {
        return Err((
            409,
            json!({
                "error": "operator_lane_registry_unavailable",
                "message": "stateful operator action route has no lane registry provider",
            }),
        ));
    };
    lifecycle.lane_binding(lane_id).map(Some).ok_or_else(|| {
        (
            404,
            json!({
                "error": "operator_lane_not_found",
                "message": "requested lane_id is not active",
                "lane_id": lane_id,
            }),
        )
    })
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
    if config.dashboard_auth.is_some() {
        if let Some(response) = enforce_dashboard_get_headers(request) {
            return Some(response);
        }
        if config
            .operator_authority
            .authorize(None, request.peer_is_loopback)
            .is_none()
        {
            return Some(dashboard_auth_error_response(
                403,
                "dashboard_operator_authority_required",
            ));
        }
        if let Some(auth) = &config.dashboard_auth
            && auth.session_view(request.header("cookie")).is_err()
        {
            return Some(dashboard_auth_error_response(
                401,
                "dashboard_session_required",
            ));
        }
    }
    let asset = crate::dashboard_bundle::dashboard_asset_for(&request.path)?;
    let body = if request.method == "HEAD" {
        Vec::new()
    } else {
        asset.body
    };
    Some(with_dashboard_security_headers(HttpResponse {
        status: 200,
        headers: vec![
            ("content-type".to_owned(), asset.content_type.to_owned()),
            ("cache-control".to_owned(), asset.cache_control.to_owned()),
        ],
        body,
    }))
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
    config: &HttpTransportConfig,
    request: &HttpRequest,
) -> Option<HttpResponse> {
    let obs = &config.observability;
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
            refresh_active_lane_metrics(config);
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
    let dispatch_principal_key = if config.stateful {
        Some(session_principal_key)
    } else {
        principal_key
    };
    if let Some(principal_key) = dispatch_principal_key {
        context = context.with_principal_key(principal_key);
    }
    let outcome = server.handle_jsonrpc_request_with_context_outcome(parsed, None, context);
    let response = match outcome {
        Outcome::Ok(Some(response)) => response,
        Outcome::Ok(None) => return empty_response(202),
        Outcome::Err(error) => error.into_response(),
        Outcome::Cancelled(reason) => return dispatch_cancelled_response(&reason),
        Outcome::Panicked(payload) => return dispatch_panicked_response(&payload),
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

fn dispatch_cancelled_response(reason: &asupersync::CancelReason) -> HttpResponse {
    tracing::info!(
        outcome = "cancelled",
        cancel_kind = reason.kind.as_str(),
        "MCP request cancelled before dispatch completion"
    );
    json_response(
        499,
        &json!({
            "error": "request_cancelled",
            "outcome": "cancelled",
            "cancel_kind": reason.kind.as_str(),
            "message": reason.to_string(),
        }),
    )
}

fn dispatch_panicked_response(_payload: &asupersync::PanicPayload) -> HttpResponse {
    tracing::error!(
        outcome = "panicked",
        "MCP request dispatch panicked; lane supervision has quarantined any affected lane"
    );
    json_response(
        500,
        &json!({
            "error": "request_panicked",
            "outcome": "panicked",
            "message": "tool dispatch panicked; the owning lane must be inspected before retry",
        }),
    )
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
    let peer_is_loopback = stream
        .peer_addr()
        .map(|addr| addr.ip().is_loopback())
        .unwrap_or(false);
    handle_stream(&mut stream, server, config, peer_is_loopback)
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
    let peer_is_loopback = stream
        .peer_addr()
        .map(|addr| addr.ip().is_loopback())
        .unwrap_or(false);
    let mut stream = StreamOwned::new(connection, stream);
    let result = handle_stream(&mut stream, server, config, peer_is_loopback);
    stream.conn.send_close_notify();
    let _ = stream.flush();
    result
}

fn handle_stream(
    stream: &mut (impl Read + Write),
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    peer_is_loopback: bool,
) -> std::io::Result<()> {
    let exchange = match read_http_request(stream) {
        Ok(Some(request)) => handle_http_exchange(
            server,
            config,
            request.with_peer_loopback(peer_is_loopback),
            true,
        ),
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
        303 => "See Other",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        409 => "Conflict",
        410 => "Gone",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "OK",
    }
}
