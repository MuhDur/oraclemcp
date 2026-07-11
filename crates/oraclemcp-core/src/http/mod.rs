//! Native Streamable HTTP(S) transport (plan §7.1, §2.5; bead P1-9a /
//! oracle-qmwz.2.9.1).
//!
//! This module owns the small HTTP/1.1 surface oraclemcp actually needs: the
//! `/mcp` Streamable HTTP endpoint, RFC 9728 protected-resource metadata, the
//! DNS-rebinding `Host` guard, the browser `Origin` allowlist, and OAuth bearer
//! validation. It deliberately does not depend on a web framework or ambient
//! async runtime.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as FmtWrite;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use asupersync::channel::mpsc;
use asupersync::combinator::{
    RateLimitAlgorithm, RateLimitPolicy, RateLimiter, RateLimiterRegistry, WaitStrategy,
};
use asupersync::cx::NoCaps;
use asupersync::time::wall_now;
use asupersync::types::Time;
use asupersync::{Cx, Outcome};
use oraclemcp_audit::{
    AuditDecision, AuditEntryDraft, AuditOutcome, AuditRecord, AuditSubject, Auditor, DbEvidence,
    GENESIS_HASH,
};
use oraclemcp_auth::{
    HttpGuardError, HttpGuardPolicy, ResourceServerConfig, SignatureVerifier, TokenError,
    extract_bearer,
};
use oraclemcp_db::PoolSettings;
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use oraclemcp_telemetry::{HealthState, Metrics, MetricsSnapshot};
use parking_lot::{Condvar, Mutex};
use rustls::{ServerConnection, StreamOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::admin_auth::OperatorAuthorityPolicy;
use crate::admission::{
    AdmissionController, AdmissionPermit, CapacitySnapshot, DEFAULT_DOCTOR_RESERVED_LANES,
    DEFAULT_GLOBAL_HOST_CAP, DEFAULT_OPERATOR_RESERVED_LANES, DEFAULT_READ_PER_PROFILE_CAP,
    DEFAULT_RETRY_AFTER_MS, DEFAULT_STATEFUL_PER_PROFILE_CAP,
};
use crate::capabilities::PROTOCOL_VERSION;
use crate::change_proposal::{
    ChangeProposalApplyRequest, ChangeProposalApplyUnit, ChangeProposalError,
    ChangeProposalStatement, ChangeProposalStore,
};
use crate::client_credentials::{
    ClientCredentialError, ClientCredentialStore, looks_like_client_bearer,
};
use crate::config_ops::{ConfigOpsError, ConfigOpsService};
use crate::dashboard_auth::{
    DASHBOARD_ACTION_TICKET_HEADER, DASHBOARD_CSRF_HEADER, DASHBOARD_PAIR_PATH,
    DASHBOARD_SESSION_PATH, DashboardAuth,
};
use crate::file_store::FileStoreError;
use crate::operator_protocol::{
    OPERATOR_PROTOCOL_VERSION, operator_event, operator_response, operator_route_index,
    operator_schema_bundle, operator_subject_id_hash, validate_operator_event,
    validate_operator_response,
};
use crate::schema_diff_export::{
    SchemaDiffExportRequest, schema_diff_error_data, schema_diff_export_data,
};
use crate::server::{
    DispatchCloseReason, DispatchContext, DispatchReplyReceiver, OracleMcpServer, ToolStreamFrame,
};
use crate::source_history::{
    SourceHistoryError, SourceHistoryFilter, SourceHistoryRevertRequest, SourceHistoryStore,
    SourceObjectTarget, SourceSnapshotDraft, normalize_source_object_type,
    source_object_from_create_or_replace_sql,
};
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
const QUERY_ROW_STREAM_CHANNEL_CAPACITY: usize = 16;
const STATEFUL_SESSION_COOKIE: &str = "oraclemcp_mcp_session";
const CONFIG_DRAFT_MAX_BYTES: usize = 256 * 1024;
const HTTP_TRANSPORT_CAPACITY_SCOPE: &str = "http_transport_connection";
const HTTP_TRANSPORT_CAPACITY_SUBJECT: &str = "accepted-connections";
const HTTP_SSE_CAPACITY_SCOPE: &str = "http_sse_subscriber";
const HTTP_RATE_LIMIT_SCOPE_MCP: &str = "http_mcp_request_rate";
const HTTP_RATE_LIMIT_SCOPE_OPERATOR: &str = "http_operator_request_rate";
const HTTP_REQUEST_RATE_POLICY_NAME: &str = "http_principal_request_rate";
const HTTP_REQUEST_RATE_COST: u32 = 1;

/// Default per-principal HTTP request-rate limit.
///
/// This is intentionally independent from N4/N4+ concurrency admission. It
/// protects authenticated request surfaces from hot-loop callers without
/// constraining normal tool latency, SSE subscriber counts, or listener-worker
/// capacity.
pub const DEFAULT_HTTP_REQUEST_RATE_PER_SECOND: u32 = 600;
/// Default per-principal burst for the HTTP request-rate limiter.
pub const DEFAULT_HTTP_REQUEST_RATE_BURST: u32 = 1200;
/// Maximum resident rate-limit buckets retained by the HTTP transport.
pub const DEFAULT_HTTP_REQUEST_RATE_BUCKETS: usize = 1024;

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

/// Registered mTLS clients for the native HTTP transport.
///
/// rustls verifies the certificate chain against the configured client CA. This
/// registry is the application-identity step: only a listed leaf fingerprint is
/// converted into an `mtls:sha256:<hex>` principal key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MtlsClientRegistry {
    fingerprints: Vec<String>,
}

impl MtlsClientRegistry {
    /// Build a registry from SHA-256 leaf-certificate fingerprints. Invalid
    /// entries are ignored because config validation owns operator-facing
    /// errors; direct embedders can use [`Self::is_empty`] to detect no entries.
    #[must_use]
    pub fn from_fingerprints<I, S>(fingerprints: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut fingerprints = fingerprints
            .into_iter()
            .filter_map(|fingerprint| normalize_cert_fingerprint(fingerprint.as_ref()))
            .collect::<Vec<_>>();
        fingerprints.sort();
        fingerprints.dedup();
        Self { fingerprints }
    }

    /// `true` when no client certificate can be mapped to an application
    /// principal.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    fn principal_key_for_fingerprint(&self, fingerprint: &str) -> Option<String> {
        let fingerprint = normalize_cert_fingerprint(fingerprint)?;
        self.fingerprints
            .binary_search(&fingerprint)
            .ok()
            .map(|_| mtls_principal_key(&fingerprint))
    }
}

/// Per-principal HTTP request-rate limiter policy.
///
/// The limiter key is always derived by the server from an authenticated
/// principal/session subject plus a fixed traffic scope. Raw bearer tokens,
/// OAuth subject strings, request ids, and caller-supplied identity values are
/// never used as registry names or rendered in responses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequestRateLimitConfig {
    pub rate_per_second: u32,
    pub burst: u32,
    pub max_buckets: usize,
}

impl Default for HttpRequestRateLimitConfig {
    fn default() -> Self {
        Self {
            rate_per_second: DEFAULT_HTTP_REQUEST_RATE_PER_SECOND,
            burst: DEFAULT_HTTP_REQUEST_RATE_BURST,
            max_buckets: DEFAULT_HTTP_REQUEST_RATE_BUCKETS,
        }
    }
}

impl HttpRequestRateLimitConfig {
    #[must_use]
    fn normalized(self) -> Self {
        Self {
            rate_per_second: self.rate_per_second.max(1),
            burst: self.burst.max(1),
            max_buckets: self.max_buckets.max(1),
        }
    }
}

#[derive(Default)]
struct HttpRequestRateBuckets {
    known: HashSet<String>,
    order: VecDeque<String>,
}

/// Bounded registry of asupersync request-rate limiters for HTTP principals.
pub struct HttpRequestRateLimiters {
    registry: RateLimiterRegistry,
    buckets: Mutex<HttpRequestRateBuckets>,
    config: HttpRequestRateLimitConfig,
}

impl std::fmt::Debug for HttpRequestRateLimiters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRequestRateLimiters")
            .field("rate_per_second", &self.config.rate_per_second)
            .field("burst", &self.config.burst)
            .field("max_buckets", &self.config.max_buckets)
            .field("bucket_count", &self.bucket_count())
            .finish()
    }
}

impl Default for HttpRequestRateLimiters {
    fn default() -> Self {
        Self::new(HttpRequestRateLimitConfig::default())
    }
}

impl HttpRequestRateLimiters {
    #[must_use]
    pub fn new(config: HttpRequestRateLimitConfig) -> Self {
        let config = config.normalized();
        let policy = RateLimitPolicy {
            name: HTTP_REQUEST_RATE_POLICY_NAME.to_owned(),
            rate: config.rate_per_second,
            period: Duration::from_secs(1),
            burst: config.burst,
            wait_strategy: WaitStrategy::Reject,
            default_cost: HTTP_REQUEST_RATE_COST,
            algorithm: RateLimitAlgorithm::TokenBucket,
        };
        Self {
            registry: RateLimiterRegistry::new(policy),
            buckets: Mutex::new(HttpRequestRateBuckets::default()),
            config,
        }
    }

    fn try_admit_at(
        &self,
        scope: &str,
        principal_key: &str,
        now: Time,
    ) -> Result<(), HttpRequestRateLimitRejection> {
        let bucket_key = http_request_rate_bucket_key(scope, principal_key);
        let limiter = self.limiter_for_bucket(&bucket_key);
        if limiter.try_acquire(HTTP_REQUEST_RATE_COST, now) {
            return Ok(());
        }
        let retry_after = limiter.retry_after(HTTP_REQUEST_RATE_COST, now);
        let retry_after_ms = duration_to_millis_saturating(retry_after).max(1);
        Err(HttpRequestRateLimitRejection {
            scope: scope.to_owned(),
            subject_id_hash: operator_subject_id_hash(principal_key),
            retry_after_ms,
            rate_per_second: self.config.rate_per_second,
            burst: self.config.burst,
            max_buckets: self.config.max_buckets,
            bucket_count: self.bucket_count(),
        })
    }

    fn limiter_for_bucket(&self, bucket_key: &str) -> Arc<RateLimiter> {
        let mut buckets = self.buckets.lock();
        if buckets.known.insert(bucket_key.to_owned()) {
            buckets.order.push_back(bucket_key.to_owned());
            while buckets.known.len() > self.config.max_buckets {
                let Some(evicted) = buckets.order.pop_front() else {
                    break;
                };
                if buckets.known.remove(&evicted) {
                    let _ = self.registry.remove(&evicted);
                }
            }
        }
        drop(buckets);
        self.registry.get_or_create(bucket_key)
    }

    fn bucket_count(&self) -> usize {
        self.buckets.lock().known.len()
    }

    #[cfg(test)]
    fn metric_bucket_names(&self) -> Vec<String> {
        self.registry.all_metrics().keys().cloned().collect()
    }
}

struct HttpRequestRateLimitRejection {
    scope: String,
    subject_id_hash: String,
    retry_after_ms: u64,
    rate_per_second: u32,
    burst: u32,
    max_buckets: usize,
    bucket_count: usize,
}

/// Server-observed effective scheme for security-sensitive response behavior.
/// Native rustls listeners force [`Https`](Self::Https); plaintext listeners
/// remain [`Http`](Self::Http) unless startup config explicitly asserts trusted
/// external HTTPS termination. Request forwarding headers never influence it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EffectiveHttpScheme {
    #[default]
    Http,
    Https,
}

impl EffectiveHttpScheme {
    fn is_https(self) -> bool {
        self == Self::Https
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
    /// Effective external request scheme, derived only from the native listener
    /// or explicit trusted-termination config. Never derived from request
    /// headers.
    pub effective_scheme: EffectiveHttpScheme,
    /// Idle timeout for stateful sessions. A zero duration disables the
    /// watchdog. The watchdog closes stale lanes through [`HttpSessionLifecycle`]
    /// and never touches dispatcher/connection state directly.
    pub stateful_idle_ttl: Duration,
    /// Transport-layer admission for accepted HTTP(S) connection workers. This
    /// runs before the listener spawns a per-connection thread, so slow readers
    /// cannot create unbounded workers before Oracle/session admission exists.
    pub transport_admission: Arc<AdmissionController>,
    /// Admission for long-lived Streamable HTTP GET/SSE subscribers. These are
    /// transport consumers, not Oracle lanes, so they are capped separately from
    /// lane/session admission.
    pub sse_admission: Arc<AdmissionController>,
    /// Per-principal request-rate limiter for authenticated MCP and operator
    /// HTTP calls. Buckets are hashed server-derived principal/scope keys and
    /// are bounded independently from concurrency admission.
    pub request_rate_limits: Arc<HttpRequestRateLimiters>,
    /// The RFC 9728 protected-resource metadata document to serve, if OAuth is
    /// enabled (from [`oraclemcp_auth::oauth_rs::ResourceServerConfig`]).
    pub resource_metadata: Option<Value>,
    /// OAuth 2.1 resource-server enforcement (P1-9b). When set, `/mcp`
    /// requests may authenticate with a valid bearer token, or with a
    /// registered mTLS leaf fingerprint when mTLS is configured; the metadata
    /// route stays open so clients can discover the authorization server.
    pub oauth: Option<Arc<OAuthEnforcement>>,
    /// Registered mTLS clients. A CA-verified client certificate becomes an
    /// authenticated principal only when its leaf fingerprint appears here.
    pub mtls_clients: MtlsClientRegistry,
    /// Service-owned per-client bearer credentials. When set, `ocmcp_*`
    /// Authorization bearers authenticate as isolated HTTP principals and their
    /// stored scopes flow through the existing scope-grant lowering path.
    pub client_credentials: Option<Arc<ClientCredentialStore>>,
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
    /// Safe config draft/apply backend for `/operator/v1/config/*`.
    pub config_ops: Option<Arc<ConfigOpsService>>,
    /// Durable change proposal board for `/operator/v1/change-proposals/*`.
    /// Draft/list are lane-free; apply acquires a lane only by forwarding to the
    /// existing gated action route.
    pub change_proposals: Option<Arc<ChangeProposalStore>>,
    /// Durable source snapshots captured before governed source-replaceable DDL
    /// applies. Revert uses the change-proposal path; this store never writes
    /// directly to Oracle.
    pub source_history: Option<Arc<SourceHistoryStore>>,
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
            .field("effective_scheme", &self.effective_scheme)
            .field("stateful_idle_ttl", &self.stateful_idle_ttl)
            .field(
                "transport_regular_global_cap",
                &self.transport_admission.regular_global_cap(),
            )
            .field(
                "sse_regular_global_cap",
                &self.sse_admission.regular_global_cap(),
            )
            .field("request_rate_limits", &self.request_rate_limits)
            .field("resource_metadata", &self.resource_metadata.is_some())
            .field("oauth", &self.oauth.is_some())
            .field("mtls_client_count", &self.mtls_clients.fingerprints.len())
            .field("client_credentials", &self.client_credentials.is_some())
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
            .field("config_ops", &self.config_ops.is_some())
            .field("change_proposals", &self.change_proposals.is_some())
            .field("source_history", &self.source_history.is_some())
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
            effective_scheme: EffectiveHttpScheme::Http,
            stateful_idle_ttl: Duration::from_secs(DEFAULT_STATEFUL_IDLE_TTL_SECONDS),
            transport_admission: default_transport_admission(),
            sse_admission: default_sse_admission(),
            request_rate_limits: Arc::new(HttpRequestRateLimiters::default()),
            resource_metadata: None,
            oauth: None,
            mtls_clients: MtlsClientRegistry::default(),
            client_credentials: None,
            session_store: None,
            result_store: None,
            session_lifecycle: None,
            single_principal_guard: None,
            operator_authority: OperatorAuthorityPolicy::default(),
            dashboard_auth: None,
            operator_auditor: None,
            operator_audit_tail_path: None,
            config_ops: None,
            change_proposals: None,
            source_history: None,
            operator_idempotency: Arc::new(OperatorIdempotencyLedger::new()),
            operator_events: Arc::new(OperatorEventStore::new()),
            observability: ObservabilityState::default(),
        }
    }
}

fn default_transport_admission() -> Arc<AdmissionController> {
    Arc::new(AdmissionController::with_reserved(
        DEFAULT_GLOBAL_HOST_CAP,
        DEFAULT_GLOBAL_HOST_CAP,
        DEFAULT_OPERATOR_RESERVED_LANES,
        DEFAULT_DOCTOR_RESERVED_LANES,
    ))
}

fn default_sse_admission() -> Arc<AdmissionController> {
    Arc::new(AdmissionController::with_reserved(
        DEFAULT_GLOBAL_HOST_CAP,
        DEFAULT_STATEFUL_PER_PROFILE_CAP,
        DEFAULT_OPERATOR_RESERVED_LANES,
        DEFAULT_DOCTOR_RESERVED_LANES,
    ))
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

    /// Close every live session/lane owned by one principal. Credential
    /// revoke/rotate uses this to force grant revocation without needing the
    /// client's individual MCP session ids.
    fn close_principal_sessions(
        &self,
        _principal_key: &str,
        _reason: DispatchCloseReason,
    ) -> usize {
        0
    }

    /// Redacted lane summaries for `/operator/v1/active-lanes`.
    fn active_lanes(&self) -> Vec<HttpLaneSnapshot> {
        Vec::new()
    }

    /// Redaction-safe capacity facts for operator diagnostics.
    fn capacity_snapshot(&self, _scope: &str, _subject: &str) -> Option<CapacitySnapshot> {
        None
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
    /// The protocol revision negotiated by this session's `initialize` (bead
    /// oraclemcp-s693). Drives the post-init `MCP-Protocol-Version` header
    /// requirement for sessions that negotiated >= 2025-06-18.
    protocol_version: String,
}

impl HttpSessionStore {
    fn insert(&self, id: String, principal_key: String, protocol_version: String) {
        self.owners.lock().insert(
            id,
            HttpSessionEntry {
                principal_key,
                last_seen: Instant::now(),
                protocol_version,
            },
        );
    }

    fn principal_for(&self, id: &str) -> Option<String> {
        let mut owners = self.owners.lock();
        let entry = owners.get_mut(id)?;
        entry.last_seen = Instant::now();
        Some(entry.principal_key.clone())
    }

    /// The protocol revision the session negotiated at `initialize`.
    fn protocol_version_for(&self, id: &str) -> Option<String> {
        self.owners
            .lock()
            .get(id)
            .map(|entry| entry.protocol_version.clone())
    }

    fn remove(&self, id: &str) -> bool {
        self.owners.lock().remove(id).is_some()
    }

    fn remove_principal(&self, principal_key: &str) -> Vec<String> {
        let mut owners = self.owners.lock();
        let session_ids = owners
            .iter()
            .filter(|(_, entry)| entry.principal_key == principal_key)
            .map(|(session_id, _)| session_id.clone())
            .collect::<Vec<_>>();
        for session_id in &session_ids {
            owners.remove(session_id);
        }
        session_ids
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

mod request_target;
mod sse_writer;
mod wire;
use request_target::split_request_target;
use sse_writer::{
    write_chunked_sse_comment, write_chunked_sse_event, write_final_chunk,
    write_query_stream_chunks, write_sse_event, write_streaming_sse_headers,
};
use wire::{read_http_request, write_http_response};

#[cfg(test)]
mod tests;

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

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuthenticatedHttpRequest {
    scope_grant: Option<ScopeGrant>,
    principal_key: String,
}

fn authenticate_client_credential_request(
    request: &HttpRequest,
    store: &ClientCredentialStore,
) -> Result<Option<AuthenticatedHttpRequest>, HttpResponse> {
    let Some(header) = request.header("authorization") else {
        return Ok(None);
    };
    let bearer = match extract_bearer(Some(header)) {
        Ok(bearer) => bearer,
        Err(_) => return Ok(None),
    };
    if !looks_like_client_bearer(bearer) {
        return Ok(None);
    }
    match store.authenticate_bearer(bearer, request.peer_addr.as_deref()) {
        Ok(authenticated) => Ok(Some(AuthenticatedHttpRequest {
            scope_grant: Some(ScopeGrant(authenticated.scopes)),
            principal_key: authenticated.principal_key,
        })),
        Err(ClientCredentialError::AuthenticationFailed | ClientCredentialError::Revoked(_)) => {
            Err(client_credential_unauthorized_response())
        }
        Err(_) => Err(client_credential_unavailable_response()),
    }
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
    pub peer_addr: Option<String>,
    pub peer_cert_fingerprint_sha256: Option<String>,
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
            peer_addr: None,
            peer_cert_fingerprint_sha256: None,
        }
    }

    /// Attach server-observed peer locality. Tests and embedders that construct
    /// requests directly must set this explicitly when modeling loopback.
    #[must_use]
    pub fn with_peer_loopback(mut self, peer_is_loopback: bool) -> Self {
        self.peer_is_loopback = peer_is_loopback;
        self
    }

    /// Attach server-observed peer address. The value is informational and is
    /// never accepted from HTTP headers.
    #[must_use]
    pub fn with_peer_addr(mut self, peer_addr: Option<String>) -> Self {
        self.peer_addr = peer_addr;
        self
    }

    /// Attach the rustls-verified mTLS leaf-certificate fingerprint.
    #[must_use]
    pub fn with_peer_cert_fingerprint_sha256(mut self, fingerprint: Option<String>) -> Self {
        self.peer_cert_fingerprint_sha256 = fingerprint;
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

fn authenticate_http_request(
    config: &HttpTransportConfig,
    request: &HttpRequest,
    allow_unauthenticated_cookie_get: bool,
) -> Result<Option<AuthenticatedHttpRequest>, HttpResponse> {
    if let Some(store) = &config.client_credentials
        && let Some(authenticated) = authenticate_client_credential_request(request, store)?
    {
        return Ok(Some(authenticated));
    }

    if let Some(enforcement) = &config.oauth
        && request.header("authorization").is_some()
    {
        let validated = validate_oauth_request(request, enforcement)?;
        return Ok(Some(AuthenticatedHttpRequest {
            scope_grant: Some(validated.scope_grant),
            principal_key: validated.principal_key,
        }));
    }

    if let Some(fingerprint) = request.peer_cert_fingerprint_sha256.as_deref() {
        let Some(principal_key) = config
            .mtls_clients
            .principal_key_for_fingerprint(fingerprint)
        else {
            return Err(mtls_forbidden_response());
        };
        return Ok(Some(AuthenticatedHttpRequest {
            scope_grant: None,
            principal_key,
        }));
    }

    if allow_unauthenticated_cookie_get {
        return Ok(None);
    }

    if let Some(enforcement) = &config.oauth {
        return Err(oauth_error_response(enforcement, None));
    }

    if config.client_credentials.is_some() {
        return Err(client_credential_unauthorized_response());
    }

    Ok(None)
}

fn client_credential_unauthorized_response() -> HttpResponse {
    json_response(
        401,
        &json!({
            "error": "client_credential_required",
            "message": "valid per-client bearer credential required",
        }),
    )
    .with_header("cache-control", "no-store")
}

fn client_credential_unavailable_response() -> HttpResponse {
    json_response(
        503,
        &json!({
            "error": "client_credential_store_unavailable",
            "message": "client credential store is unavailable",
        }),
    )
    .with_header("cache-control", "no-store")
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

fn cert_fingerprint_sha256(cert_der: &[u8]) -> String {
    prefixed_sha256_hex(cert_der)
}

fn normalize_cert_fingerprint(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    let hex = value.strip_prefix("sha256:").unwrap_or(&value);
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then(|| format!("sha256:{hex}"))
}

fn mtls_principal_key(fingerprint_sha256: &str) -> String {
    format!("mtls:{fingerprint_sha256}")
}

fn mtls_forbidden_response() -> HttpResponse {
    json_response(
        403,
        &json!({
            "error": "mtls_client_not_registered",
            "message": "mTLS client certificate is verified but not registered for this service",
        }),
    )
    .with_header("cache-control", "no-store")
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

fn http_request_rate_bucket_key(scope: &str, principal_key: &str) -> String {
    let mut material = Vec::with_capacity(scope.len() + principal_key.len() + 1);
    material.extend_from_slice(scope.as_bytes());
    material.push(0);
    material.extend_from_slice(principal_key.as_bytes());
    format!("http-rate:{}", sha256_hex(&material))
}

fn duration_to_millis_saturating(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
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

fn stateful_session_cookie_header(session_id: &str, secure: bool) -> String {
    stateful_session_cookie_header_with_max_age(session_id, None, secure)
}

fn stateful_session_cookie_header_with_max_age(
    session_id: &str,
    max_age: Option<u64>,
    secure: bool,
) -> String {
    let mut header = format!("{STATEFUL_SESSION_COOKIE}={session_id}; Path={MCP_PATH}");
    if let Some(max_age) = max_age {
        header.push_str(&format!("; Max-Age={max_age}"));
    }
    header.push_str("; HttpOnly; SameSite=Strict");
    if secure {
        header.push_str("; Secure");
    }
    header
}

fn expired_stateful_session_cookie_header(secure: bool) -> String {
    stateful_session_cookie_header_with_max_age("", Some(0), secure)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrivilegedCookiePolicy {
    Secure,
    LoopbackHttp,
    Suppress,
}

impl PrivilegedCookiePolicy {
    fn for_request(config: &HttpTransportConfig, request: &HttpRequest) -> Self {
        if config.effective_scheme.is_https() {
            Self::Secure
        } else if request.peer_is_loopback {
            Self::LoopbackHttp
        } else {
            Self::Suppress
        }
    }

    fn secure(self) -> bool {
        self == Self::Secure
    }
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
    authenticated: Option<&AuthenticatedHttpRequest>,
) -> Option<HttpResponse> {
    let guard = config.single_principal_guard.as_ref()?;
    let key = stateful_principal_key(authenticated.map(|auth| auth.principal_key.as_str()));
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
    ToolStream(HttpToolStream),
}

impl HttpExchange {
    fn into_buffered_response(self) -> HttpResponse {
        match self {
            Self::Buffered(response) => response,
            Self::SseStream(stream) => stream.into_buffered_response(),
            Self::ToolStream(stream) => stream.into_buffered_response(),
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
            let allow_dashboard_session = config.dashboard_auth.is_some()
                && request.peer_is_loopback
                && request.header("authorization").is_none();
            let authenticated =
                match authenticate_http_request(config, &request, allow_dashboard_session) {
                    Ok(authenticated) => authenticated,
                    Err(response) => return HttpExchange::Buffered(response),
                };
            let principal_key = authenticated
                .as_ref()
                .map(|auth| auth.principal_key.as_str());
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
            if let Err(response) = try_admit_http_request_rate(
                &config.request_rate_limits,
                HTTP_RATE_LIMIT_SCOPE_OPERATOR,
                &operator_subject.legacy_agent_identity(),
                "retry after retry_after_ms, or reduce operator API request rate for this subject",
            ) {
                return HttpExchange::Buffered(response);
            }
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
    let authenticated = match authenticate_http_request(config, &request, cookie_authenticated_get)
    {
        Ok(authenticated) => authenticated,
        Err(response) => return HttpExchange::Buffered(response),
    };
    if let Some(response) = enforce_single_principal(config, authenticated.as_ref()) {
        return HttpExchange::Buffered(response);
    }
    let scope_grant = authenticated
        .as_ref()
        .and_then(|auth| auth.scope_grant.as_ref());
    let principal_key = authenticated
        .as_ref()
        .map(|auth| auth.principal_key.as_str());
    match request.method.as_str() {
        "GET" => handle_mcp_get(config, &request, principal_key, allow_streaming_get),
        "DELETE" => HttpExchange::Buffered(handle_mcp_delete(
            config,
            &request,
            stateful_principal_key(principal_key),
        )),
        "POST" => handle_mcp_post_exchange(server, config, &request, scope_grant, principal_key),
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
        return dashboard_pairing_auth_required_response();
    };
    let cookie_policy = PrivilegedCookiePolicy::for_request(config, request);
    if cookie_policy == PrivilegedCookiePolicy::Suppress {
        return dashboard_auth_error_response(403, "dashboard_pairing_requires_secure_transport");
    }
    match auth.exchange_ticket(ticket, cookie_policy.secure()) {
        Ok(login) => with_dashboard_security_headers(
            empty_response(303)
                .with_header("location", "/")
                .with_header("set-cookie", &login.session_cookie)
                .with_header("cache-control", "no-store"),
        ),
        Err(_) => dashboard_pairing_auth_required_response(),
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
        Err(_) => dashboard_auth_required_response(),
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
            Err(_) => Some(dashboard_auth_required_response()),
        };
    }
    if let Some(response) = enforce_dashboard_get_headers(request) {
        return Some(response);
    }
    match auth.session_view(request.header("cookie")) {
        Ok(_) => None,
        Err(_) => Some(dashboard_auth_required_response()),
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

fn dashboard_auth_required_response() -> HttpResponse {
    dashboard_auth_error_response(401, "dashboard_auth_required")
}

fn dashboard_pairing_auth_required_response() -> HttpResponse {
    dashboard_auth_error_response(401, "dashboard_pairing_required")
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

/// Post-initialize `MCP-Protocol-Version` header requirement (bead
/// oraclemcp-s693). The 2025-06-18 Streamable HTTP spec makes the header
/// mandatory on every request after `initialize`; sessions that negotiated an
/// OLDER revision keep the historical leniency (header validated only when
/// present, by [`enforce_mcp_protocol_version`]).
///
/// Enforced on POST (the JSON-RPC request channel) only: the GET SSE resume
/// path deliberately supports browser `EventSource` clients (cookie + Origin
/// auth), and `EventSource` cannot set custom request headers — requiring the
/// header there would break the documented dashboard flow, not tighten
/// anything (GET carries no JSON-RPC request). DELETE follows GET's leniency.
fn require_negotiated_protocol_version_header(
    config: &HttpTransportConfig,
    request: &HttpRequest,
    session: &ValidatedStatefulSession<'_>,
) -> Option<HttpResponse> {
    let store = config.session_store.as_ref()?;
    let negotiated = store.protocol_version_for(session.session_id)?;
    if !crate::capabilities::revision_at_least(
        &negotiated,
        crate::capabilities::HTTP_PROTOCOL_VERSION_HEADER_REQUIRED_SINCE,
    ) {
        return None;
    }
    if request.header("mcp-protocol-version").is_some() {
        // Presence is required here; supported-ness (and the 400 for junk
        // values) is already enforced globally by enforce_mcp_protocol_version.
        return None;
    }
    Some(
        json_response(
            400,
            &json!({
                "error": "missing_protocol_version_header",
                "message": format!(
                    "MCP-Protocol-Version header is required on every request after \
                     initialize for sessions that negotiated {negotiated} (spec revision \
                     2025-06-18 and later)"
                ),
                "negotiated": negotiated,
                "next_step": "send MCP-Protocol-Version with the negotiated revision on \
                              every post-initialize request",
            }),
        )
        .with_header("mcp-protocol-version", PROTOCOL_VERSION),
    )
}

fn enforce_mcp_protocol_version(request: &HttpRequest) -> Option<HttpResponse> {
    let presented = request.header("mcp-protocol-version")?;
    if crate::capabilities::SUPPORTED_PROTOCOL_VERSIONS.contains(&presented.trim()) {
        return None;
    }
    Some(
        json_response(
            400,
            &json!({
                "error": "unsupported_protocol_version",
                "message": "unsupported MCP-Protocol-Version header",
                "presented": presented,
                "supported": crate::capabilities::SUPPORTED_PROTOCOL_VERSIONS,
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
    LaneCancel,
    Vsession,
    Events,
    ConfigStatus,
    ConfigDraft,
    ConfigApply,
    ConfigRollback,
    ChangeProposalsList,
    ChangeProposalsDraft,
    ChangeProposalsApply,
    SchemaDiff,
    SourceHistoryList,
    SourceHistoryRevert,
    ClientCredentials,
    ClientCredentialRotate,
    ClientCredentialRevoke,
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
        "/operator/v1/lanes/cancel" => OperatorRouteKind::LaneCancel,
        "/operator/v1/vsession" => OperatorRouteKind::Vsession,
        "/operator/v1/events" => OperatorRouteKind::Events,
        "/operator/v1/config" => OperatorRouteKind::ConfigStatus,
        "/operator/v1/config/draft" => OperatorRouteKind::ConfigDraft,
        "/operator/v1/config/apply" => OperatorRouteKind::ConfigApply,
        "/operator/v1/config/rollback" => OperatorRouteKind::ConfigRollback,
        "/operator/v1/change-proposals" => OperatorRouteKind::ChangeProposalsList,
        "/operator/v1/change-proposals/draft" => OperatorRouteKind::ChangeProposalsDraft,
        "/operator/v1/change-proposals/apply" => OperatorRouteKind::ChangeProposalsApply,
        "/operator/v1/schema-diff" => OperatorRouteKind::SchemaDiff,
        "/operator/v1/source-history" => OperatorRouteKind::SourceHistoryList,
        "/operator/v1/source-history/revert" => OperatorRouteKind::SourceHistoryRevert,
        "/operator/v1/client-credentials" => OperatorRouteKind::ClientCredentials,
        "/operator/v1/client-credentials/rotate" => OperatorRouteKind::ClientCredentialRotate,
        "/operator/v1/client-credentials/revoke" => OperatorRouteKind::ClientCredentialRevoke,
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
            | Self::ConfigDraft
            | Self::ConfigApply
            | Self::ConfigRollback
            | Self::ChangeProposalsDraft
            | Self::ChangeProposalsApply
            | Self::SchemaDiff
            | Self::SourceHistoryRevert
            | Self::ClientCredentialRotate
            | Self::ClientCredentialRevoke
            | Self::SetLevel
            | Self::SwitchProfile
            | Self::LaneCancel => "POST",
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
        OperatorRouteKind::LaneCancel => handle_operator_lane_cancel_route(config, request),
        OperatorRouteKind::Vsession => {
            operator_json_response(200, &request.path, operator_vsession_data())
        }
        OperatorRouteKind::Events => operator_events_response(config, request, operator_subject),
        OperatorRouteKind::ConfigStatus
        | OperatorRouteKind::ConfigDraft
        | OperatorRouteKind::ConfigApply
        | OperatorRouteKind::ConfigRollback => handle_operator_config_route(config, request, route),
        OperatorRouteKind::ChangeProposalsList
        | OperatorRouteKind::ChangeProposalsDraft
        | OperatorRouteKind::ChangeProposalsApply => handle_operator_change_proposal_route(
            server,
            config,
            request,
            operator_subject,
            route,
            operator_audit_seq,
            dashboard_browser,
        ),
        OperatorRouteKind::SchemaDiff => handle_operator_schema_diff_route(request),
        OperatorRouteKind::SourceHistoryList | OperatorRouteKind::SourceHistoryRevert => {
            handle_operator_source_history_route(config, request, operator_subject, route)
        }
        OperatorRouteKind::ClientCredentials
        | OperatorRouteKind::ClientCredentialRotate
        | OperatorRouteKind::ClientCredentialRevoke => {
            handle_operator_client_credentials_route(config, request, route)
        }
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
        Some(metrics) => {
            let snapshot = metrics.snapshot();
            let capacity = operator_capacity_data(config, Some(&snapshot));
            json!({
                "source": "self_lane",
                "snapshot": snapshot,
                "capacity": capacity,
            })
        }
        None => json!({
            "source": "unavailable",
            "reason": "metrics provider is not configured",
            "snapshot": null,
            "capacity": operator_capacity_data(config, None),
        }),
    }
}

fn operator_capacity_data(
    config: &HttpTransportConfig,
    metrics_snapshot: Option<&MetricsSnapshot>,
) -> Value {
    let stateful_snapshot = config
        .session_lifecycle
        .as_ref()
        .and_then(|lifecycle| lifecycle.capacity_snapshot("stateful_lane", "operator"));
    let transport_snapshot = config.transport_admission.snapshot(
        HTTP_TRANSPORT_CAPACITY_SCOPE,
        HTTP_TRANSPORT_CAPACITY_SUBJECT,
    );
    let sse_snapshot = config
        .sse_admission
        .snapshot(HTTP_SSE_CAPACITY_SCOPE, "operator");
    let read_pool_effective = PoolSettings::default().resolved().max_size;
    let active_lanes = metrics_snapshot
        .and_then(|snapshot| usize::try_from(snapshot.active_lanes).ok())
        .unwrap_or_else(|| active_lane_snapshots(config).len());
    let pool_active = metrics_snapshot
        .map(|snapshot| snapshot.pool_active_connections)
        .unwrap_or(0);
    let at_capacity_events = at_capacity_events(metrics_snapshot);
    let (regular_in_use, retry_after_ms, reserve) = match stateful_snapshot.as_ref() {
        Some(snapshot) => (
            snapshot
                .regular_global_cap
                .saturating_sub(snapshot.regular_global_available),
            snapshot.retry_after_ms,
            json!({
                "operator": snapshot.operator_reserved,
                "doctor": snapshot.doctor_reserved,
                "regular_global_cap": snapshot.regular_global_cap,
            }),
        ),
        None => (
            0,
            DEFAULT_RETRY_AFTER_MS,
            json!({
                "operator": DEFAULT_OPERATOR_RESERVED_LANES,
                "doctor": DEFAULT_DOCTOR_RESERVED_LANES,
                "regular_global_cap": DEFAULT_GLOBAL_HOST_CAP
                    .saturating_sub(DEFAULT_OPERATOR_RESERVED_LANES)
                    .saturating_sub(DEFAULT_DOCTOR_RESERVED_LANES),
            }),
        ),
    };
    let stateful_source = if stateful_snapshot.is_some() {
        "admission"
    } else {
        "monitoring_unavailable"
    };
    let metrics_source = if metrics_snapshot.is_some() {
        "metrics"
    } else {
        "monitoring_unavailable"
    };

    json!({
        "source": if stateful_snapshot.is_some() || metrics_snapshot.is_some() {
            "self_lane"
        } else {
            "monitoring_unavailable"
        },
        "read_pool": {
            "source": metrics_source,
            "configured_per_profile": DEFAULT_READ_PER_PROFILE_CAP,
            "effective_per_profile": read_pool_effective,
            "active": pool_active,
            "limit_sources": [
                {
                    "name": "configured_max_size",
                    "status": "applied",
                    "configured": DEFAULT_READ_PER_PROFILE_CAP,
                    "effective": DEFAULT_READ_PER_PROFILE_CAP,
                },
                {
                    "name": "cpu_parallelism",
                    "status": "applied",
                    "effective": read_pool_effective,
                },
                {
                    "name": "profile_override",
                    "status": "monitoring_unavailable",
                    "reason": "selected profile pool settings are not carried on the HTTP transport",
                },
                {
                    "name": "db_session_limit",
                    "status": "monitoring_unavailable",
                },
            ],
        },
        "stateful_lanes": {
            "source": stateful_source,
            "configured": {
                "global": DEFAULT_GLOBAL_HOST_CAP,
                "per_subject": DEFAULT_STATEFUL_PER_PROFILE_CAP,
                "operator_reserved": DEFAULT_OPERATOR_RESERVED_LANES,
                "doctor_reserved": DEFAULT_DOCTOR_RESERVED_LANES,
            },
            "effective": stateful_snapshot,
            "active": active_lanes,
            "regular_in_use": regular_in_use,
            "reserve": reserve,
            "at_capacity_events": at_capacity_events,
            "retry_after_ms": retry_after_ms,
            "limit_sources": [
                {
                    "name": "configured_stateful_caps",
                    "status": "applied",
                },
                {
                    "name": "operator_doctor_reserve",
                    "status": "applied",
                },
                {
                    "name": "db_session_limit",
                    "status": "monitoring_unavailable",
                },
                {
                    "name": "fd_limit",
                    "status": "monitoring_unavailable",
                },
                {
                    "name": "memory_budget",
                    "status": "monitoring_unavailable",
                },
            ],
        },
        "transport": {
            "source": "admission",
            "accepted_connection_workers": transport_snapshot,
            "sse_subscribers": sse_snapshot,
            "limit_sources": [
                {
                    "name": "configured_transport_worker_caps",
                    "status": "applied",
                },
                {
                    "name": "configured_sse_subscriber_caps",
                    "status": "applied",
                },
                {
                    "name": "operator_doctor_reserve",
                    "status": "applied",
                },
            ],
        },
        "idle_reaping": {
            "enabled": !config.stateful_idle_ttl.is_zero(),
            "ttl_seconds": config.stateful_idle_ttl.as_secs(),
        },
    })
}

fn at_capacity_events(metrics_snapshot: Option<&MetricsSnapshot>) -> u64 {
    metrics_snapshot
        .map(|snapshot| {
            snapshot
                .requests
                .iter()
                .filter(|request| request.status == "at_capacity")
                .map(|request| request.count)
                .sum()
        })
        .unwrap_or(0)
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

/// Terminate one principal's stateful lane on an authorized operator request.
///
/// Fail-closed control action, not a data path: the caller has already cleared
/// [`OperatorAuthorityPolicy::authorize`] (Subject is server-derived from the
/// transport, never browser-supplied) and the request is already recorded in
/// the operator audit hash-chain by [`append_operator_audit`] before dispatch.
/// This route only resolves the lane id to its server-internal binding and
/// drops the lane through the lifecycle hook — the lane's connection, elevation
/// window, and single-use grants go away. It never runs SQL, so it cannot
/// bypass the classifier; the closed lane's own lifecycle audit entry records
/// the `operator_cancel` reason.
fn handle_operator_lane_cancel_route(
    config: &HttpTransportConfig,
    request: &HttpRequest,
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
                    "error": "invalid_operator_lane_cancel",
                    "message": "lane cancel body must be a JSON object",
                }),
            );
        }
    };
    let Some(lane_id) = payload
        .get("lane_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|lane_id| !lane_id.is_empty())
    else {
        return operator_json_response(
            400,
            &request.path,
            json!({
                "error": "operator_lane_required",
                "message": "lane cancel requires a non-empty lane_id",
            }),
        );
    };
    let Some(lifecycle) = config.session_lifecycle.as_ref() else {
        return operator_json_response(
            409,
            &request.path,
            json!({
                "error": "operator_lane_registry_unavailable",
                "message": "lane cancel requires a stateful lane registry provider",
            }),
        );
    };
    let Some(binding) = lifecycle.lane_binding(lane_id) else {
        return operator_json_response(
            404,
            &request.path,
            json!({
                "error": "operator_lane_not_found",
                "message": "requested lane_id is not active",
                "lane_id": lane_id,
            }),
        );
    };
    let terminated = lifecycle.close_session_with_reason(
        &binding.mcp_session_id,
        &binding.principal_key,
        DispatchCloseReason::OperatorCancel,
    );
    operator_json_response(
        200,
        &request.path,
        json!({
            "status": if terminated { "terminated" } else { "already_closed" },
            "lane_id": binding.lane_id,
            "lane_generation": binding.generation,
            "reason": DispatchCloseReason::OperatorCancel.as_str(),
            "terminated": terminated,
        }),
    )
}

fn operator_vsession_data() -> Value {
    json!({
        "source": "unavailable",
        "reason": "v$session summary requires a configured monitor profile; this provider is not configured",
        "sessions": [],
    })
}

fn handle_operator_config_route(
    config: &HttpTransportConfig,
    request: &HttpRequest,
    route: OperatorRouteKind,
) -> HttpResponse {
    let Some(config_ops) = config.config_ops.as_ref() else {
        return operator_json_response(
            503,
            &request.path,
            json!({
                "source": "unavailable",
                "error": "config_ops_unavailable",
                "message": "operator config workflow is not configured for this transport",
            }),
        );
    };

    match route {
        OperatorRouteKind::ConfigStatus => match config_ops.status() {
            Ok(status) => operator_json_response(
                200,
                &request.path,
                json!({
                    "source": "config_ops",
                    "status": status,
                }),
            ),
            Err(error) => operator_config_error_response(&request.path, error),
        },
        OperatorRouteKind::ConfigDraft => match config_draft_toml_from_request(request)
            .and_then(|draft| config_ops.stage(&draft).map_err(config_error_value))
        {
            Ok(preview) => operator_json_response(
                200,
                &request.path,
                json!({
                    "source": "config_ops",
                    "preview": preview,
                    "redaction": "draft TOML and secret references are not echoed",
                }),
            ),
            Err((status, data)) => operator_json_response(status, &request.path, data),
        },
        OperatorRouteKind::ConfigApply => {
            let payload = match operator_config_json_payload(request) {
                Ok(payload) => payload,
                Err((status, data)) => {
                    return operator_json_response(status, &request.path, data);
                }
            };
            let Some(draft) = payload.get("draft_toml").and_then(Value::as_str) else {
                return operator_json_response(
                    400,
                    &request.path,
                    missing_config_field("draft_toml"),
                );
            };
            if draft.len() > CONFIG_DRAFT_MAX_BYTES {
                return operator_json_response(413, &request.path, config_draft_too_large());
            }
            let expected = payload
                .get("expected_current_sha256")
                .and_then(Value::as_str);
            match config_ops.apply(draft, expected) {
                Ok(outcome) => operator_json_response(
                    200,
                    &request.path,
                    json!({
                        "source": "config_ops",
                        "outcome": outcome,
                        "redaction": "draft TOML and secret references are not echoed",
                    }),
                ),
                Err(error) => operator_config_error_response(&request.path, error),
            }
        }
        OperatorRouteKind::ConfigRollback => {
            let payload = match operator_config_json_payload(request) {
                Ok(payload) => payload,
                Err((status, data)) => {
                    return operator_json_response(status, &request.path, data);
                }
            };
            let Some(rollback_id) = payload.get("rollback_id").and_then(Value::as_str) else {
                return operator_json_response(
                    400,
                    &request.path,
                    missing_config_field("rollback_id"),
                );
            };
            match config_ops.rollback(rollback_id) {
                Ok(outcome) => operator_json_response(
                    200,
                    &request.path,
                    json!({
                        "source": "config_ops",
                        "outcome": outcome,
                    }),
                ),
                Err(error) => operator_config_error_response(&request.path, error),
            }
        }
        _ => unreachable!("non-config route"),
    }
}

fn handle_operator_change_proposal_route(
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    request: &HttpRequest,
    operator_subject: &AuditSubject,
    route: OperatorRouteKind,
    operator_audit_seq: u64,
    dashboard_browser: bool,
) -> HttpResponse {
    let Some(store) = config.change_proposals.as_ref() else {
        return operator_json_response(
            503,
            &request.path,
            json!({
                "source": "change_proposals",
                "error": "change_proposals_unavailable",
                "message": "change proposal store is not configured for this transport",
            }),
        );
    };

    match route {
        OperatorRouteKind::ChangeProposalsList => match store.list() {
            Ok(proposals) => operator_json_response(
                200,
                &request.path,
                json!({
                    "source": "change_proposals",
                    "proposals": proposals,
                }),
            ),
            Err(error) => operator_change_proposal_error_response(&request.path, error),
        },
        OperatorRouteKind::ChangeProposalsDraft => {
            if !content_type_is_json(request) {
                return empty_response(415);
            }
            let payload = match serde_json::from_slice(&request.body) {
                Ok(payload) => payload,
                Err(_) => {
                    return operator_json_response(
                        400,
                        &request.path,
                        json!({
                            "source": "change_proposals",
                            "error": "invalid_change_proposal",
                            "message": "change proposal draft body must be valid JSON",
                        }),
                    );
                }
            };
            let author_id_hash =
                operator_subject_id_hash(&operator_subject.legacy_agent_identity());
            match store.draft(payload, author_id_hash) {
                Ok(outcome) => operator_json_response(
                    200,
                    &request.path,
                    json!({
                        "source": "change_proposals",
                        "status": "drafted",
                        "proposal": outcome.proposal,
                    }),
                ),
                Err(error) => operator_change_proposal_error_response(&request.path, error),
            }
        }
        OperatorRouteKind::ChangeProposalsApply => {
            if !content_type_is_json(request) {
                return empty_response(415);
            }
            let apply = match serde_json::from_slice::<ChangeProposalApplyRequest>(&request.body) {
                Ok(apply) => apply,
                Err(_) => {
                    return operator_json_response(
                        400,
                        &request.path,
                        json!({
                            "source": "change_proposals",
                            "error": "invalid_change_proposal_apply",
                            "message": "change proposal apply body must include a valid proposal_id",
                        }),
                    );
                }
            };
            let proposal = match store.load(&apply.proposal_id) {
                Ok(proposal) => proposal,
                Err(error) => return operator_change_proposal_error_response(&request.path, error),
            };
            let context = ChangeProposalApplyContext {
                server,
                config,
                original_request: request,
                operator_subject,
                operator_audit_seq,
                dashboard_browser,
            };
            operator_json_response(
                200,
                &request.path,
                apply_change_proposal(&context, &proposal, &apply),
            )
        }
        _ => unreachable!("non-change-proposal route"),
    }
}

fn handle_operator_schema_diff_route(request: &HttpRequest) -> HttpResponse {
    if !content_type_is_json(request) {
        return empty_response(415);
    }
    let payload = match serde_json::from_slice::<SchemaDiffExportRequest>(&request.body) {
        Ok(payload) => payload,
        Err(_) => {
            return operator_json_response(
                400,
                &request.path,
                json!({
                    "source": "schema_diff",
                    "error": "invalid_schema_diff_request",
                    "message": "schema diff body must include before and after schema snapshots",
                }),
            );
        }
    };
    match schema_diff_export_data(payload) {
        Ok(data) => operator_json_response(200, &request.path, data),
        Err(error) => operator_json_response(400, &request.path, schema_diff_error_data(error)),
    }
}

struct ChangeProposalApplyContext<'a> {
    server: &'a OracleMcpServer,
    config: &'a HttpTransportConfig,
    original_request: &'a HttpRequest,
    operator_subject: &'a AuditSubject,
    operator_audit_seq: u64,
    dashboard_browser: bool,
}

fn apply_change_proposal(
    context: &ChangeProposalApplyContext<'_>,
    proposal: &crate::change_proposal::ChangeProposal,
    apply: &ChangeProposalApplyRequest,
) -> Value {
    let mut results = Vec::new();
    let mut failed = false;
    for (index, statement) in proposal.statements.iter().enumerate() {
        let source_snapshot =
            capture_source_snapshot_for_statement(context, proposal, apply, statement);
        let response = if source_snapshot_blocks_apply(&source_snapshot) {
            source_snapshot_blocked_response(context, &source_snapshot)
        } else {
            apply_change_proposal_statement(context, proposal, apply, statement)
        };
        let response_body: Value = serde_json::from_slice(&response.body).unwrap_or_else(|_| {
            json!({
                "error": "invalid_operator_action_response",
                "message": "operator action response was not valid JSON",
            })
        });
        let statement_failed = operator_action_response_failed(response.status, &response_body);
        failed |= statement_failed;
        results.push(json!({
            "statement_index": index,
            "statement_id": statement.id,
            "unit": statement.unit,
            "sql_sha256": prefixed_sha256_hex(statement.sql_template.as_bytes()),
            "bind_count": statement.binds.len(),
            "reclassified": statement.reclassified_view(),
            "stored_verdict_ignored": statement.stored_verdict.is_some() || proposal.stored_verdict.is_some(),
            "source_snapshot": source_snapshot,
            "action_status": response.status,
            "action_response": response_body,
        }));
        if statement_failed {
            break;
        }
    }
    let status = if failed {
        "stopped_on_failure"
    } else if results.len() == proposal.statements.len() {
        "applied"
    } else {
        "not_started"
    };
    json!({
        "source": "change_proposals",
        "status": status,
        "proposal": proposal.view(),
        "lane_id": apply.lane_id.as_deref().map(str::trim).filter(|value| !value.is_empty()),
        "atomicity": {
            "unit": "per_statement_or_object",
            "mode": "sequential_stop_on_failure",
            "all_or_nothing": false,
        },
        "results": results,
    })
}

fn source_snapshot_blocks_apply(snapshot: &Value) -> bool {
    snapshot
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| status == "failed")
}

fn source_snapshot_blocked_response(
    context: &ChangeProposalApplyContext<'_>,
    snapshot: &Value,
) -> HttpResponse {
    operator_json_response(
        500,
        &context.original_request.path,
        json!({
            "source": "change_proposals",
            "error": "source_snapshot_failed",
            "message": "source snapshot persistence failed before DDL apply; statement was not dispatched",
            "source_snapshot": snapshot,
        }),
    )
}

fn apply_change_proposal_statement(
    context: &ChangeProposalApplyContext<'_>,
    proposal: &crate::change_proposal::ChangeProposal,
    apply: &ChangeProposalApplyRequest,
    statement: &ChangeProposalStatement,
) -> HttpResponse {
    let (tool, arguments) = change_proposal_action_arguments(statement, apply);
    let key_prefix = apply
        .idempotency_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("change-proposal-apply");
    forward_operator_action(
        context,
        OperatorActionForward {
            idempotency_key: format!("{key_prefix}:{}:{}", proposal.id, statement.id),
            lane_id: apply.lane_id.as_deref(),
            tool,
            arguments,
        },
    )
}

struct OperatorActionForward<'a> {
    idempotency_key: String,
    lane_id: Option<&'a str>,
    tool: &'a str,
    arguments: Value,
}

fn forward_operator_action(
    context: &ChangeProposalApplyContext<'_>,
    action: OperatorActionForward<'_>,
) -> HttpResponse {
    let body = json!({
        "idempotency_key": action.idempotency_key,
        "lane_id": action.lane_id.map(str::trim).filter(|value| !value.is_empty()),
        "tool": action.tool,
        "arguments": action.arguments,
    });
    let host = context
        .original_request
        .header("host")
        .unwrap_or("127.0.0.1");
    let action_request = HttpRequest::new(
        "POST",
        "/operator/v1/actions/execute",
        [
            ("host", host),
            ("content-type", "application/json"),
            ("accept", "application/json"),
        ],
        body.to_string().into_bytes(),
    )
    .with_peer_loopback(context.original_request.peer_is_loopback)
    .with_peer_addr(context.original_request.peer_addr.clone())
    .with_peer_cert_fingerprint_sha256(
        context
            .original_request
            .peer_cert_fingerprint_sha256
            .clone(),
    );
    handle_operator_action_route(
        context.server,
        context.config,
        &action_request,
        context.operator_subject,
        OperatorRouteKind::ActionExecute,
        context.operator_audit_seq,
        context.dashboard_browser,
    )
}

struct CurrentSourceDocument {
    owner: String,
    name: String,
    object_type: String,
    source_kind: String,
    source: String,
}

enum SourceSnapshotFetchOutcome {
    Document(CurrentSourceDocument),
    Skipped(Value),
}

fn capture_source_snapshot_for_statement(
    context: &ChangeProposalApplyContext<'_>,
    proposal: &crate::change_proposal::ChangeProposal,
    apply: &ChangeProposalApplyRequest,
    statement: &ChangeProposalStatement,
) -> Value {
    if statement.unit != ChangeProposalApplyUnit::Ddl {
        return json!({
            "status": "not_applicable",
            "reason": "statement unit is not DDL",
        });
    }
    let Some(store) = context.config.source_history.as_ref() else {
        return json!({
            "status": "unavailable",
            "reason": "source history store is not configured",
        });
    };
    let Some(target) = source_object_from_create_or_replace_sql(&statement.sql_template) else {
        return json!({
            "status": "skipped",
            "reason": "statement is not a supported source-replaceable CREATE OR REPLACE shape",
        });
    };
    let document = match fetch_current_source_document(context, proposal, apply, statement, &target)
    {
        Ok(SourceSnapshotFetchOutcome::Document(document)) => document,
        Ok(SourceSnapshotFetchOutcome::Skipped(data)) | Err(data) => return data,
    };
    match store.record_snapshot(SourceSnapshotDraft {
        profile: proposal.profile.clone(),
        owner: document.owner,
        name: document.name,
        object_type: document.object_type,
        source_kind: document.source_kind,
        source: document.source,
        proposal_id: proposal.id.clone(),
        statement_id: statement.id.clone(),
        statement_sql_sha256: prefixed_sha256_hex(statement.sql_template.as_bytes()),
        lane_id: apply
            .lane_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
        subject_id_hash: operator_subject_id_hash(
            &context.operator_subject.legacy_agent_identity(),
        ),
    }) {
        Ok(view) => json!({
            "status": "captured",
            "snapshot": view,
        }),
        Err(error) => json!({
            "status": "failed",
            "reason": "source snapshot could not be persisted",
            "error": error.to_string(),
        }),
    }
}

fn fetch_current_source_document(
    context: &ChangeProposalApplyContext<'_>,
    proposal: &crate::change_proposal::ChangeProposal,
    apply: &ChangeProposalApplyRequest,
    statement: &ChangeProposalStatement,
    target: &SourceObjectTarget,
) -> Result<SourceSnapshotFetchOutcome, Value> {
    let object_type = normalize_source_object_type(&target.object_type).ok_or_else(|| {
        json!({
            "status": "skipped",
            "reason": "unsupported source object type",
            "object_type": target.object_type,
        })
    })?;
    let (tool, arguments) = source_snapshot_fetch_action(target, &object_type);
    let response = forward_operator_action(
        context,
        OperatorActionForward {
            idempotency_key: format!(
                "source-history-snapshot:{}:{}:{}",
                context.operator_audit_seq, proposal.id, statement.id
            ),
            lane_id: apply.lane_id.as_deref(),
            tool,
            arguments,
        },
    );
    let body: Value = serde_json::from_slice(&response.body).unwrap_or_else(|_| {
        json!({
            "error": "invalid_operator_action_response",
            "message": "source snapshot fetch response was not valid JSON",
        })
    });
    if operator_action_response_failed(response.status, &body) {
        return Ok(SourceSnapshotFetchOutcome::Skipped(json!({
            "status": "skipped",
            "reason": "prior source was not visible before apply",
            "object": source_target_json(target, &object_type),
            "fetch_status": response.status,
            "fetch_error": body.pointer("/data/mcp_response/error/message")
                .or_else(|| body.pointer("/data/mcp_response/error"))
                .or_else(|| body.pointer("/data/error"))
                .cloned()
                .unwrap_or(Value::Null),
        })));
    }
    let structured = body
        .pointer("/data/mcp_response/result/structuredContent")
        .ok_or_else(|| {
            json!({
                "status": "skipped",
                "reason": "source fetch response did not include structured content",
                "object": source_target_json(target, &object_type),
            })
        })?;
    if object_type == "VIEW" {
        return Ok(source_snapshot_document_from_ddl(structured, target));
    }
    Ok(source_snapshot_document_from_all_source(
        structured,
        target,
        &object_type,
    ))
}

fn source_snapshot_fetch_action(
    target: &SourceObjectTarget,
    object_type: &str,
) -> (&'static str, Value) {
    let mut arguments = serde_json::Map::new();
    if let Some(owner) = target.owner.as_ref() {
        arguments.insert("owner".to_owned(), json!(owner));
    }
    arguments.insert("name".to_owned(), json!(target.name.as_str()));
    arguments.insert("object_type".to_owned(), json!(object_type));
    if object_type == "VIEW" {
        ("oracle_get_ddl", Value::Object(arguments))
    } else {
        arguments.insert("max_chars".to_owned(), json!(1_000_000));
        ("oracle_get_source", Value::Object(arguments))
    }
}

fn source_snapshot_document_from_ddl(
    structured: &Value,
    target: &SourceObjectTarget,
) -> SourceSnapshotFetchOutcome {
    let Some(source) = structured.get("ddl").and_then(Value::as_str) else {
        return SourceSnapshotFetchOutcome::Skipped(json!({
            "status": "skipped",
            "reason": "no prior view DDL was visible before apply",
            "object": source_target_json(target, "VIEW"),
        }));
    };
    let source = source.trim();
    if source.is_empty() {
        return SourceSnapshotFetchOutcome::Skipped(json!({
            "status": "skipped",
            "reason": "no prior view DDL was visible before apply",
            "object": source_target_json(target, "VIEW"),
        }));
    }
    SourceSnapshotFetchOutcome::Document(CurrentSourceDocument {
        owner: structured
            .get("owner")
            .and_then(Value::as_str)
            .or(target.owner.as_deref())
            .unwrap_or_default()
            .to_ascii_uppercase(),
        name: structured
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(&target.name)
            .to_ascii_uppercase(),
        object_type: "VIEW".to_owned(),
        source_kind: "dbms_metadata".to_owned(),
        source: source.to_owned(),
    })
}

fn source_snapshot_document_from_all_source(
    structured: &Value,
    target: &SourceObjectTarget,
    object_type: &str,
) -> SourceSnapshotFetchOutcome {
    let source = structured.get("source").unwrap_or(&Value::Null);
    if source
        .get("truncated")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return SourceSnapshotFetchOutcome::Skipped(json!({
            "status": "skipped",
            "reason": "prior source was truncated before apply",
            "object": source_target_json(target, object_type),
        }));
    }
    if source
        .get("line_count")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        == 0
    {
        return SourceSnapshotFetchOutcome::Skipped(json!({
            "status": "skipped",
            "reason": "no prior source was visible before apply",
            "object": source_target_json(target, object_type),
        }));
    }
    let Some(text) = source.get("source").and_then(Value::as_str) else {
        return SourceSnapshotFetchOutcome::Skipped(json!({
            "status": "skipped",
            "reason": "source fetch response did not include source text",
            "object": source_target_json(target, object_type),
        }));
    };
    if text.trim().is_empty() {
        return SourceSnapshotFetchOutcome::Skipped(json!({
            "status": "skipped",
            "reason": "no prior source was visible before apply",
            "object": source_target_json(target, object_type),
        }));
    }
    SourceSnapshotFetchOutcome::Document(CurrentSourceDocument {
        owner: source
            .get("owner")
            .and_then(Value::as_str)
            .or(target.owner.as_deref())
            .unwrap_or_default()
            .to_ascii_uppercase(),
        name: source
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(&target.name)
            .to_ascii_uppercase(),
        object_type: source
            .get("object_type")
            .and_then(Value::as_str)
            .and_then(normalize_source_object_type)
            .unwrap_or_else(|| object_type.to_owned()),
        source_kind: "all_source".to_owned(),
        source: create_or_replace_ddl_for_source(text),
    })
}

fn create_or_replace_ddl_for_source(source: &str) -> String {
    let trimmed = source.trim_start();
    if trimmed
        .to_ascii_uppercase()
        .starts_with("CREATE OR REPLACE ")
    {
        source.to_owned()
    } else {
        format!("CREATE OR REPLACE {trimmed}")
    }
}

fn source_target_json(target: &SourceObjectTarget, object_type: &str) -> Value {
    json!({
        "owner": target.owner.as_deref(),
        "name": target.name.as_str(),
        "object_type": object_type,
    })
}

fn change_proposal_action_arguments(
    statement: &ChangeProposalStatement,
    apply: &ChangeProposalApplyRequest,
) -> (&'static str, Value) {
    match statement.unit {
        ChangeProposalApplyUnit::Read => (
            "oracle_query",
            json!({
                "sql": statement.sql_template.as_str(),
                "binds": &statement.binds,
                "max_rows": 100,
            }),
        ),
        ChangeProposalApplyUnit::Dml | ChangeProposalApplyUnit::Ddl => {
            let confirm = apply
                .confirm
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            (
                "oracle_execute",
                json!({
                    "sql": statement.sql_template.as_str(),
                    "binds": &statement.binds,
                    "commit": apply.commit.unwrap_or(statement.commit),
                    "confirm": confirm,
                    "capture_dbms_output": statement.capture_dbms_output,
                }),
            )
        }
    }
}

fn operator_action_response_failed(status: u16, body: &Value) -> bool {
    if status >= 400 {
        return true;
    }
    let Some(mcp_response) = body.pointer("/data/mcp_response") else {
        return false;
    };
    mcp_response.get("error").is_some()
        || mcp_response
            .pointer("/result/isError")
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

fn operator_change_proposal_error_response(
    route: &str,
    error: ChangeProposalError,
) -> HttpResponse {
    let (status, code) = match &error {
        ChangeProposalError::Invalid(_) => (400, "invalid_change_proposal"),
        ChangeProposalError::UnknownProposal => (404, "unknown_change_proposal"),
        ChangeProposalError::FileStore(FileStoreError::InvalidSegment { .. }) => {
            (400, "invalid_change_proposal")
        }
        ChangeProposalError::FileStore(FileStoreError::Locked) => {
            (409, "change_proposal_store_locked")
        }
        ChangeProposalError::FileStore(_)
        | ChangeProposalError::Io(_)
        | ChangeProposalError::Json(_) => (500, "change_proposal_store_failed"),
    };
    operator_json_response(
        status,
        route,
        json!({
            "source": "change_proposals",
            "error": code,
            "message": error.to_string(),
        }),
    )
}

fn handle_operator_source_history_route(
    config: &HttpTransportConfig,
    request: &HttpRequest,
    operator_subject: &AuditSubject,
    route: OperatorRouteKind,
) -> HttpResponse {
    let Some(history) = config.source_history.as_ref() else {
        return operator_json_response(
            503,
            &request.path,
            json!({
                "source": "source_history",
                "error": "source_history_unavailable",
                "message": "source history store is not configured for this transport",
            }),
        );
    };

    match route {
        OperatorRouteKind::SourceHistoryList => {
            match history.list(source_history_filter_from_request(request)) {
                Ok(snapshots) => operator_json_response(
                    200,
                    &request.path,
                    json!({
                        "source": "source_history",
                        "snapshots": snapshots,
                        "redaction": "source text is omitted from history list responses",
                    }),
                ),
                Err(error) => operator_source_history_error_response(&request.path, error),
            }
        }
        OperatorRouteKind::SourceHistoryRevert => {
            if !content_type_is_json(request) {
                return empty_response(415);
            }
            let Some(change_proposals) = config.change_proposals.as_ref() else {
                return operator_json_response(
                    503,
                    &request.path,
                    json!({
                        "source": "source_history",
                        "error": "change_proposals_unavailable",
                        "message": "source-history revert requires the change proposal store",
                    }),
                );
            };
            let revert = match serde_json::from_slice::<SourceHistoryRevertRequest>(&request.body) {
                Ok(revert) => revert,
                Err(_) => {
                    return operator_json_response(
                        400,
                        &request.path,
                        json!({
                            "source": "source_history",
                            "error": "invalid_source_history_revert",
                            "message": "source-history revert body must include a valid snapshot_id",
                        }),
                    );
                }
            };
            let snapshot = match history.load_snapshot(&revert.snapshot_id) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    return operator_source_history_error_response(&request.path, error);
                }
            };
            let profile = revert
                .profile
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| snapshot.profile.clone());
            let title = revert
                .title
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    format!(
                        "Revert {}.{} {} to {}",
                        snapshot.owner, snapshot.name, snapshot.object_type, snapshot.source_sha256
                    )
                });
            let author_id_hash =
                operator_subject_id_hash(&operator_subject.legacy_agent_identity());
            let draft_request = crate::change_proposal::ChangeProposalDraftRequest {
                profile,
                author: crate::change_proposal::ChangeProposalAuthorKind::Agent,
                title: Some(title),
                statements: vec![crate::change_proposal::ChangeProposalStatementDraft {
                    sql_template: snapshot.source.clone(),
                    binds: Vec::new(),
                    unit: Some(ChangeProposalApplyUnit::Ddl),
                    commit: Some(true),
                    capture_dbms_output: Some(false),
                    stored_verdict: None,
                }],
                stored_verdict: None,
            };
            match change_proposals.draft(draft_request, author_id_hash) {
                Ok(outcome) => operator_json_response(
                    200,
                    &request.path,
                    json!({
                        "source": "source_history",
                        "status": "revert_drafted",
                        "snapshot": snapshot.view(),
                        "proposal": outcome.proposal,
                    }),
                ),
                Err(error) => operator_change_proposal_error_response(&request.path, error),
            }
        }
        _ => unreachable!("non-source-history route"),
    }
}

fn source_history_filter_from_request(request: &HttpRequest) -> SourceHistoryFilter {
    let max_rows = request
        .query_param("max_rows")
        .or_else(|| request.query_param("limit"))
        .and_then(|value| value.parse::<usize>().ok())
        .map(|value| value.clamp(1, 500))
        .or(Some(100));
    SourceHistoryFilter {
        profile: request.query_param("profile").map(str::to_owned),
        owner: request.query_param("owner").map(str::to_owned),
        name: request.query_param("name").map(str::to_owned),
        object_type: request.query_param("object_type").map(str::to_owned),
        max_rows,
    }
}

fn operator_source_history_error_response(route: &str, error: SourceHistoryError) -> HttpResponse {
    let (status, code) = match &error {
        SourceHistoryError::Invalid(_) => (400, "invalid_source_history_request"),
        SourceHistoryError::UnknownSnapshot => (404, "unknown_source_history_snapshot"),
        SourceHistoryError::FileStore(FileStoreError::InvalidSegment { .. }) => {
            (400, "invalid_source_history_request")
        }
        SourceHistoryError::FileStore(FileStoreError::Locked) => (409, "source_history_locked"),
        SourceHistoryError::FileStore(_)
        | SourceHistoryError::Io(_)
        | SourceHistoryError::Json(_) => (500, "source_history_store_failed"),
    };
    operator_json_response(
        status,
        route,
        json!({
            "source": "source_history",
            "error": code,
            "message": error.to_string(),
        }),
    )
}

fn handle_operator_client_credentials_route(
    config: &HttpTransportConfig,
    request: &HttpRequest,
    route: OperatorRouteKind,
) -> HttpResponse {
    let Some(store) = config.client_credentials.as_ref() else {
        return operator_json_response(
            503,
            &request.path,
            json!({
                "source": "client_credentials",
                "error": "client_credentials_unavailable",
                "message": "client credential store is not configured for this transport",
            }),
        );
    };

    match route {
        OperatorRouteKind::ClientCredentials => operator_json_response(
            200,
            &request.path,
            json!({
                "source": "client_credentials",
                "clients": store.list(),
                "redaction": "bearer tokens are never returned by list",
            }),
        ),
        OperatorRouteKind::ClientCredentialRotate => {
            let client_id = match operator_client_credential_client_id(request) {
                Ok(client_id) => client_id,
                Err((status, data)) => return operator_json_response(status, &request.path, data),
            };
            match store.rotate(&client_id) {
                Ok((issued, lifecycle)) => {
                    let closed_sessions = close_http_principal_sessions(
                        config,
                        &lifecycle.principal_key,
                        DispatchCloseReason::SessionDelete,
                    );
                    operator_json_response(
                        200,
                        &request.path,
                        json!({
                            "source": "client_credentials",
                            "status": "rotated",
                            "client": issued.view,
                            "bearer": issued.bearer.expose(),
                            "bearer_shown_once": true,
                            "closed_principal": client_credential_lifecycle_json(&lifecycle),
                            "closed_sessions": closed_sessions,
                            "redaction": "stored credential metadata is redacted; the rotated bearer is returned once",
                        }),
                    )
                }
                Err(error) => operator_client_credential_error_response(&request.path, error),
            }
        }
        OperatorRouteKind::ClientCredentialRevoke => {
            let client_id = match operator_client_credential_client_id(request) {
                Ok(client_id) => client_id,
                Err((status, data)) => return operator_json_response(status, &request.path, data),
            };
            match store.revoke(&client_id) {
                Ok(lifecycle) => {
                    let closed_sessions = close_http_principal_sessions(
                        config,
                        &lifecycle.principal_key,
                        DispatchCloseReason::SessionDelete,
                    );
                    let client = store
                        .list()
                        .into_iter()
                        .find(|client| client.client_id == lifecycle.client_id);
                    operator_json_response(
                        200,
                        &request.path,
                        json!({
                            "source": "client_credentials",
                            "status": "revoked",
                            "client": client,
                            "closed_principal": client_credential_lifecycle_json(&lifecycle),
                            "closed_sessions": closed_sessions,
                            "redaction": "bearer tokens are never returned by revoke",
                        }),
                    )
                }
                Err(error) => operator_client_credential_error_response(&request.path, error),
            }
        }
        _ => unreachable!("non-client-credentials route"),
    }
}

fn operator_client_credential_client_id(request: &HttpRequest) -> Result<String, (u16, Value)> {
    let payload = operator_client_credential_json_payload(request)?;
    let Some(client_id) = payload
        .get("client_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|client_id| !client_id.is_empty())
    else {
        return Err((
            400,
            json!({
                "source": "client_credentials",
                "error": "invalid_client_credential_request",
                "message": "client credential requests must include client_id",
            }),
        ));
    };
    Ok(client_id.to_owned())
}

fn operator_client_credential_json_payload(
    request: &HttpRequest,
) -> Result<serde_json::Map<String, Value>, (u16, Value)> {
    if !content_type_is_json(request) {
        return Err((
            415,
            json!({
                "source": "client_credentials",
                "error": "invalid_client_credential_request",
                "message": "client credential requests must use application/json",
            }),
        ));
    }
    match serde_json::from_slice::<Value>(&request.body) {
        Ok(Value::Object(payload)) => Ok(payload),
        Ok(_) | Err(_) => Err((
            400,
            json!({
                "source": "client_credentials",
                "error": "invalid_client_credential_request",
                "message": "client credential request body must be a JSON object",
            }),
        )),
    }
}

fn client_credential_lifecycle_json(
    lifecycle: &crate::client_credentials::ClientCredentialLifecycle,
) -> Value {
    json!({
        "client_id": &lifecycle.client_id,
        "subject_id_hash": operator_subject_id_hash(&lifecycle.principal_key),
        "generation": lifecycle.generation,
    })
}

fn operator_client_credential_error_response(
    route: &str,
    error: ClientCredentialError,
) -> HttpResponse {
    let (status, code) = match &error {
        ClientCredentialError::InvalidRequest(_) => (400, "invalid_client_credential_request"),
        ClientCredentialError::AuthenticationFailed => (401, "client_credential_auth_failed"),
        ClientCredentialError::UnknownClient(_) => (404, "unknown_client_credential"),
        ClientCredentialError::Revoked(_) => (409, "client_credential_revoked"),
        ClientCredentialError::Store(FileStoreError::Locked) => {
            (409, "client_credential_store_locked")
        }
        ClientCredentialError::Store(_)
        | ClientCredentialError::Serialization(_)
        | ClientCredentialError::Parse(_)
        | ClientCredentialError::Random(_) => (500, "client_credential_store_failed"),
    };
    operator_json_response(
        status,
        route,
        json!({
            "source": "client_credentials",
            "error": code,
            "message": error.to_string(),
        }),
    )
}

fn config_draft_toml_from_request(request: &HttpRequest) -> Result<String, (u16, Value)> {
    let payload = operator_config_json_payload(request)?;
    let Some(draft) = payload.get("draft_toml").and_then(Value::as_str) else {
        return Err((400, missing_config_field("draft_toml")));
    };
    if draft.len() > CONFIG_DRAFT_MAX_BYTES {
        return Err((413, config_draft_too_large()));
    }
    Ok(draft.to_owned())
}

fn operator_config_json_payload(
    request: &HttpRequest,
) -> Result<serde_json::Map<String, Value>, (u16, Value)> {
    if !content_type_is_json(request) {
        return Err((
            415,
            json!({
                "error": "invalid_config_request",
                "message": "config workflow requests must use application/json",
            }),
        ));
    }
    match serde_json::from_slice::<Value>(&request.body) {
        Ok(Value::Object(payload)) => Ok(payload),
        Ok(_) | Err(_) => Err((
            400,
            json!({
                "error": "invalid_config_request",
                "message": "config workflow body must be a JSON object",
            }),
        )),
    }
}

fn missing_config_field(field: &str) -> Value {
    json!({
        "error": "invalid_config_request",
        "message": format!("config workflow body must include {field}"),
    })
}

fn config_draft_too_large() -> Value {
    json!({
        "error": "config_draft_too_large",
        "message": "config draft exceeds the operator API size limit",
        "max_bytes": CONFIG_DRAFT_MAX_BYTES,
    })
}

fn operator_config_error_response(route: &str, error: ConfigOpsError) -> HttpResponse {
    let (status, data) = config_error_value(error);
    operator_json_response(status, route, data)
}

fn config_error_value(error: ConfigOpsError) -> (u16, Value) {
    match error {
        ConfigOpsError::CurrentChanged {
            expected_sha256,
            actual_sha256,
        } => (
            409,
            json!({
                "error": "config_current_changed",
                "message": "config target changed after the draft was previewed",
                "expected_sha256": expected_sha256,
                "actual_sha256": actual_sha256,
            }),
        ),
        ConfigOpsError::InvalidTargetPath(reason) => (
            400,
            json!({
                "error": "config_target_invalid",
                "message": reason,
            }),
        ),
        ConfigOpsError::InvalidUtf8 { .. } => (
            400,
            json!({
                "error": "config_invalid_utf8",
                "message": "config file is not valid UTF-8",
            }),
        ),
        ConfigOpsError::Config(_) => (
            400,
            json!({
                "error": "config_validation_failed",
                "message": "draft failed strict config validation",
            }),
        ),
        ConfigOpsError::UnknownRollbackId => (
            404,
            json!({
                "error": "config_rollback_unknown",
                "message": "rollback id is unknown or already consumed",
            }),
        ),
        ConfigOpsError::FileStore(_) | ConfigOpsError::Io(_) => (
            500,
            json!({
                "error": "config_ops_failed",
                "message": "config workflow failed before completion",
            }),
        ),
    }
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
        "sql_normalized_sha256": record.sql_normalized_sha256,
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

/// How many recent audit-tail records the CLASSIFIER-LIVE ladder streams.
const OPERATOR_CLASSIFIER_LADDER_LIMIT: usize = 24;

/// Surface recent classifier verdicts for the CLASSIFIER-LIVE ladder.
///
/// The verdicts are derived from the redacted self-lane audit tail (the same
/// hash-chained source `/operator/v1/audit-tail` reads), so the stream never
/// carries anything the audit tail would not already expose: no SQL text, no
/// bind values, only the redaction-safe `danger_level`/`decision`/`outcome`
/// plus the derived ladder verdict. When no audit tail is configured the field
/// is present but empty, so the UI can distinguish "no verdicts yet" from
/// "provider unavailable".
fn operator_classifier_verdicts(config: &HttpTransportConfig) -> Value {
    let Some(path) = config.operator_audit_tail_path.as_ref() else {
        return json!({
            "source": "unavailable",
            "reason": "audit tail provider is not configured",
            "verdicts": [],
        });
    };
    let query = AuditTailQuery {
        limit: OPERATOR_CLASSIFIER_LADDER_LIMIT,
        subject_id_hash: None,
        danger_level: None,
        tool: None,
        decision: None,
        outcome: None,
        export_proof_bundle: false,
    };
    match read_redacted_audit_tail(path, &query) {
        Ok(view) => {
            let verdicts = view
                .records
                .iter()
                .filter_map(classifier_verdict_from_record)
                .collect::<Vec<_>>();
            json!({ "source": "self_lane", "verdicts": verdicts })
        }
        Err(reason) => json!({
            "source": "unavailable",
            "reason": reason,
            "verdicts": [],
        }),
    }
}

/// Map one redacted audit record onto the CLASSIFIER-LIVE ladder verdict.
///
/// `PASS` = allowed at the active level, `HOLD-FOR-GO` = a step-up confirmation
/// is required before it can run, `REFUSED-exceeds-ceiling` = the guard blocked
/// the statement. Operator API meta-entries (`operator_api`) are HTTP calls, not
/// classified SQL, so they are skipped rather than shown as spurious passes.
fn classifier_verdict_from_record(record: &Value) -> Option<Value> {
    let tool = record
        .get("tool")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if tool == "operator_api" {
        return None;
    }
    let decision = record
        .get("decision")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let (verdict, ladder) = match decision {
        "BLOCKED" => ("REFUSED", "REFUSED-exceeds-ceiling"),
        "STEP_UP_REQUIRED" => ("HOLD", "HOLD-FOR-GO"),
        "ALLOWED" => ("PASS", "PASS"),
        _ => return None,
    };
    Some(json!({
        "seq": record.get("seq"),
        "timestamp": record.get("timestamp"),
        "subject_id_hash": record.get("subject_id_hash"),
        "tool": tool,
        "danger_level": record.get("danger_level"),
        "decision": decision,
        "outcome": record.get("outcome"),
        "verdict": verdict,
        "ladder": ladder,
        "sql_sha256": record.get("sql_sha256"),
    }))
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
            "classifier": operator_classifier_verdicts(config),
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
        "oracle_connection_info",
        "oracle_list_schemas",
        "oracle_search_objects",
        "oracle_get_ddl",
        "oracle_get_source",
        "oracle_query",
        "oracle_execute",
        "oracle_set_session_level",
        "oracle_compile_object",
        "oracle_create_or_replace",
        "oracle_patch_source",
        "oracle_plsql_parse",
        "oracle_plsql_analyze",
        "oracle_plsql_what_breaks",
        "oracle_plsql_lineage",
        "oracle_plsql_sast",
        "oracle_plsql_doc",
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
            return Some(dashboard_auth_required_response());
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
    let session_principal_key = session.principal_key;
    if let Err(response) = try_admit_http_request_rate(
        &config.request_rate_limits,
        HTTP_RATE_LIMIT_SCOPE_MCP,
        &session_principal_key,
        "retry after retry_after_ms, or reduce MCP GET/SSE request rate for this principal",
    ) {
        return HttpExchange::Buffered(response);
    }
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
        let sse_permit = match try_admit_http_capacity(
            &config.sse_admission,
            &session_principal_key,
            HTTP_SSE_CAPACITY_SCOPE,
            "retry after retry_after_ms, or close an existing SSE subscriber",
        ) {
            Ok(permit) => permit,
            Err(response) => return HttpExchange::Buffered(response),
        };
        return HttpExchange::SseStream(HttpSseStream::new(
            Arc::clone(store),
            session_id.to_owned(),
            parse_stream_cursor(cursor).unwrap_or(0),
            events,
            sse_permit,
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
                if let Err(response) = try_admit_http_request_rate(
                    &config.request_rate_limits,
                    HTTP_RATE_LIMIT_SCOPE_MCP,
                    &session.principal_key,
                    "retry after retry_after_ms, or reduce MCP DELETE request rate for this principal",
                ) {
                    return response;
                }
                if let Some(store) = &config.session_store {
                    store.remove(session_id);
                }
                if let Some(store) = &config.result_store {
                    store.remove_session(session_id);
                }
                if let Some(lifecycle) = &config.session_lifecycle {
                    lifecycle.close_session(session_id, &session.principal_key);
                }
                let cookie_policy = PrivilegedCookiePolicy::for_request(config, request);
                let response = empty_response(202);
                if cookie_policy == PrivilegedCookiePolicy::Suppress {
                    response
                } else {
                    response.with_header(
                        "set-cookie",
                        &expired_stateful_session_cookie_header(cookie_policy.secure()),
                    )
                }
            }
            Err(response) => response,
        };
    }
    empty_response(405).with_header("allow", "POST")
}

fn streaming_oracle_query_call(parsed: &Value) -> Option<(Value, String, Value)> {
    let object = parsed.as_object()?;
    if object.get("method").and_then(Value::as_str) != Some("tools/call") {
        return None;
    }
    let id = object.get("id")?.clone();
    let params = object.get("params")?.as_object()?;
    let name = params.get("name")?.as_str()?;
    if name != "oracle_query" {
        return None;
    }
    let args = match params.get("arguments") {
        Some(Value::Object(arguments)) => Value::Object(arguments.clone()),
        Some(Value::Null) | None => Value::Null,
        Some(_) => return None,
    };
    let streaming = args
        .get("streaming")
        .or_else(|| args.get("stream"))
        .and_then(Value::as_bool)
        == Some(true);
    streaming.then(|| (id, name.to_owned(), args))
}

fn handle_mcp_post_exchange(
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    request: &HttpRequest,
    scope_grant: Option<&ScopeGrant>,
    principal_key: Option<&str>,
) -> HttpExchange {
    if !content_type_is_json(request) {
        return HttpExchange::Buffered(empty_response(415));
    }
    if !accepts_media(
        request.header("accept"),
        if config.stateful {
            "text/event-stream"
        } else {
            "application/json"
        },
    ) {
        return HttpExchange::Buffered(empty_response(406));
    }
    let session_principal_key = stateful_principal_key(principal_key);
    let parsed = match serde_json::from_slice::<Value>(&request.body) {
        Ok(value) => value,
        Err(_) => {
            return HttpExchange::Buffered(json_response(
                200,
                &jsonrpc_error(Value::Null, -32700, "Parse error"),
            ));
        }
    };
    let method = parsed
        .get("method")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let http_session_id = if config.stateful {
        if method.as_deref() == Some("initialize") {
            // MCP lifecycle (bead oraclemcp-s693): a session initializes
            // exactly once. An initialize that PRESENTS a live session id is a
            // re-initialize on that session — reject it with a structured
            // error instead of silently minting a replacement session.
            if let Some(presented) = stateful_session_id(request, false)
                && config
                    .session_store
                    .as_ref()
                    .is_some_and(|store| store.principal_for(presented).is_some())
            {
                return HttpExchange::Buffered(json_response(
                    400,
                    &json!({
                        "error": "session_already_initialized",
                        "message": "initialize was already completed for this MCP session; \
                                    the lifecycle negotiates the protocol version exactly \
                                    once per session",
                        "next_step": "omit mcp-session-id on initialize to open a new \
                                      session, or keep using the existing session without \
                                      re-initializing",
                    }),
                ));
            }
            Some(new_session_id())
        } else {
            match validate_stateful_session(config, request, Some(session_principal_key), false) {
                Ok(session) => {
                    if let Some(response) =
                        require_negotiated_protocol_version_header(config, request, &session)
                    {
                        return HttpExchange::Buffered(response);
                    }
                    Some(session.session_id.to_owned())
                }
                Err(response) => return HttpExchange::Buffered(response),
            }
        }
    } else {
        None
    };
    let rate_limit_principal_key = if config.stateful {
        session_principal_key
    } else {
        stateful_principal_key(principal_key)
    };
    if let Err(response) = try_admit_http_request_rate(
        &config.request_rate_limits,
        HTTP_RATE_LIMIT_SCOPE_MCP,
        rate_limit_principal_key,
        "retry after retry_after_ms, or reduce MCP request rate for this principal",
    ) {
        return HttpExchange::Buffered(response);
    }
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
    if config.stateful
        && let Some((request_id, name, args)) = streaming_oracle_query_call(&parsed)
        && let Some(session_id) = http_session_id.clone()
    {
        let (frames_tx, frames_rx) = mpsc::channel(QUERY_ROW_STREAM_CHANNEL_CAPACITY);
        match server.start_tool_stream_blocking_with_context(context, name, args, frames_tx) {
            Outcome::Ok(reply_rx) => {
                return HttpExchange::ToolStream(HttpToolStream::new(
                    server.clone(),
                    config.result_store.clone(),
                    session_id,
                    session_principal_key.to_owned(),
                    request_id,
                    frames_rx,
                    reply_rx,
                ));
            }
            Outcome::Err(envelope) => {
                let response =
                    server.jsonrpc_tool_response_from_outcome(request_id, Outcome::Err(envelope));
                let response_event_id = config
                    .result_store
                    .as_ref()
                    .map(|store| store.append_response(&session_id, response.clone()));
                return HttpExchange::Buffered(sse_response(
                    config,
                    request,
                    method.as_deref(),
                    response,
                    http_session_id,
                    session_principal_key,
                    response_event_id.as_deref(),
                ));
            }
            Outcome::Cancelled(reason) => {
                return HttpExchange::Buffered(dispatch_cancelled_response(&reason));
            }
            Outcome::Panicked(payload) => {
                return HttpExchange::Buffered(dispatch_panicked_response(&payload));
            }
        }
    }
    let outcome = server.handle_jsonrpc_request_with_context_outcome(parsed, None, context);
    let response = match outcome {
        Outcome::Ok(Some(response)) => response,
        Outcome::Ok(None) => return HttpExchange::Buffered(empty_response(202)),
        Outcome::Err(error) => error.into_response(),
        Outcome::Cancelled(reason) => {
            return HttpExchange::Buffered(dispatch_cancelled_response(&reason));
        }
        Outcome::Panicked(payload) => {
            return HttpExchange::Buffered(dispatch_panicked_response(&payload));
        }
    };
    if let Some(retry_after_ms) = jsonrpc_busy_retry_after_ms(&response) {
        let retry_after = retry_after_header_seconds(retry_after_ms);
        return HttpExchange::Buffered(
            json_response(429, &response).with_header("retry-after", &retry_after),
        );
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
        return HttpExchange::Buffered(sse_response(
            config,
            request,
            method.as_deref(),
            response,
            http_session_id,
            session_principal_key,
            response_event_id.as_deref(),
        ));
    }
    HttpExchange::Buffered(json_response(200, &response))
}

#[cfg(test)]
fn handle_mcp_post(
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    request: &HttpRequest,
    scope_grant: Option<&ScopeGrant>,
    principal_key: Option<&str>,
) -> HttpResponse {
    handle_mcp_post_exchange(server, config, request, scope_grant, principal_key)
        .into_buffered_response()
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

fn detached_admission_cx() -> Cx<NoCaps> {
    Cx::<NoCaps>::detached_cancel_context()
}

fn try_admit_http_capacity(
    controller: &AdmissionController,
    subject: &str,
    scope: &str,
    next_step: &str,
) -> Result<AdmissionPermit, HttpResponse> {
    let cx = detached_admission_cx();
    controller.try_admit(&cx, subject).map_err(|_| {
        let envelope = controller
            .at_capacity_envelope(scope, subject)
            .with_next_step(next_step);
        let retry_after =
            retry_after_header_seconds(envelope.retry_after_ms.unwrap_or(DEFAULT_RETRY_AFTER_MS));
        json_response(429, &envelope.to_json()).with_header("retry-after", &retry_after)
    })
}

fn try_admit_http_request_rate(
    limiters: &HttpRequestRateLimiters,
    scope: &str,
    principal_key: &str,
    next_step: &str,
) -> Result<(), HttpResponse> {
    limiters
        .try_admit_at(scope, principal_key, wall_now())
        .map_err(|rejection| http_request_rate_limit_response(rejection, next_step))
}

fn http_request_rate_limit_response(
    rejection: HttpRequestRateLimitRejection,
    next_step: &str,
) -> HttpResponse {
    let snapshot = json!({
        "scope": rejection.scope,
        "subject_id_hash": rejection.subject_id_hash,
        "retry_after_ms": rejection.retry_after_ms,
        "rate_per_second": rejection.rate_per_second,
        "burst": rejection.burst,
        "bucket_count": rejection.bucket_count,
        "max_buckets": rejection.max_buckets,
    });
    let envelope = ErrorEnvelope::new(
        ErrorClass::AtCapacity,
        format!(
            "request rate limit exceeded for {}; rate_limit_snapshot={}",
            snapshot["scope"].as_str().unwrap_or("http_request_rate"),
            serde_json::to_string(&snapshot).unwrap_or_else(|_| {
                json!({
                    "scope": "http_request_rate",
                    "subject": "redacted",
                    "retry_after_ms": rejection.retry_after_ms
                })
                .to_string()
            })
        ),
    )
    .with_retry_after_ms(rejection.retry_after_ms)
    .with_next_step(next_step);
    let retry_after = retry_after_header_seconds(rejection.retry_after_ms);
    json_response(429, &envelope.to_json()).with_header("retry-after", &retry_after)
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
        Some(_) | None => Err(invalid_stateful_session_response()),
    }
}

fn invalid_stateful_session_response() -> HttpResponse {
    HttpResponse {
        status: 404,
        headers: vec![],
        body: b"Invalid mcp-session-id".to_vec(),
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
    _permit: AdmissionPermit,
}

impl HttpSseStream {
    fn new(
        store: Arc<HttpResultStore>,
        session_id: String,
        after_seq: u64,
        initial_events: Vec<HttpBufferedEvent>,
        permit: AdmissionPermit,
    ) -> Self {
        Self {
            store,
            session_id,
            after_seq,
            initial_events,
            _permit: permit,
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

struct HttpToolStream {
    server: OracleMcpServer,
    result_store: Option<Arc<HttpResultStore>>,
    session_id: String,
    _principal_key: String,
    request_id: Value,
    frames_rx: mpsc::Receiver<ToolStreamFrame>,
    reply_rx: DispatchReplyReceiver,
}

impl HttpToolStream {
    fn new(
        server: OracleMcpServer,
        result_store: Option<Arc<HttpResultStore>>,
        session_id: String,
        principal_key: String,
        request_id: Value,
        frames_rx: mpsc::Receiver<ToolStreamFrame>,
        reply_rx: DispatchReplyReceiver,
    ) -> Self {
        Self {
            server,
            result_store,
            session_id,
            _principal_key: principal_key,
            request_id,
            frames_rx,
            reply_rx,
        }
    }

    fn into_buffered_response(mut self) -> HttpResponse {
        let mut body = Vec::new();
        write_sse_event(&mut body, None, Some("0/0"), Some(3000), Some(&Value::Null));
        let response = crate::lane::block_on_lane_bridge(async {
            let cx = Cx::current().expect("block_on installs a request Cx");
            while let Ok(frame) = self.frames_rx.recv(&cx).await {
                write_tool_stream_frame_buffered(&mut body, frame);
            }
            self.final_response(&cx).await
        });
        let response_event_id = self.append_final_response(&response);
        write_sse_event(
            &mut body,
            None,
            Some(response_event_id.as_deref().unwrap_or("1/0")),
            None,
            Some(&response),
        );
        HttpResponse {
            status: 200,
            headers: vec![
                ("content-type".to_owned(), "text/event-stream".to_owned()),
                ("cache-control".to_owned(), "no-cache".to_owned()),
            ],
            body,
        }
    }

    fn write_to(mut self, stream: &mut impl Write) -> std::io::Result<()> {
        write_streaming_sse_headers(stream)?;
        write_chunked_sse_event(stream, None, Some("0/0"), Some(3000), Some(&Value::Null))?;
        let response = crate::lane::block_on_lane_bridge(async {
            let cx = Cx::current().expect("block_on installs a request Cx");
            loop {
                match self.frames_rx.recv(&cx).await {
                    Ok(frame) => write_tool_stream_frame_chunked(stream, frame)?,
                    Err(mpsc::RecvError::Disconnected) => break,
                    Err(mpsc::RecvError::Cancelled) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "stream frame receive cancelled",
                        ));
                    }
                    Err(mpsc::RecvError::Empty) => continue,
                }
            }
            Ok::<Value, std::io::Error>(self.final_response(&cx).await)
        })?;
        let response_event_id = self.append_final_response(&response);
        write_chunked_sse_event(
            stream,
            None,
            Some(response_event_id.as_deref().unwrap_or("1/0")),
            None,
            Some(&response),
        )?;
        write_final_chunk(stream)
    }

    async fn final_response(&mut self, cx: &Cx) -> Value {
        match self.reply_rx.recv(cx).await {
            Ok(outcome) => self
                .server
                .jsonrpc_tool_response_from_outcome(self.request_id.clone(), outcome),
            Err(_) => self.server.jsonrpc_tool_response_from_outcome(
                self.request_id.clone(),
                Outcome::Err(ErrorEnvelope::new(
                    ErrorClass::RuntimeStateRequired,
                    "streaming dispatch lane stopped before final reply",
                )),
            ),
        }
    }

    fn append_final_response(&self, response: &Value) -> Option<String> {
        self.result_store
            .as_ref()
            .map(|store| store.append_response(&self.session_id, response.clone()))
    }
}

fn write_tool_stream_frame_buffered(body: &mut Vec<u8>, frame: ToolStreamFrame) {
    match frame {
        ToolStreamFrame::Row { seq, row } => {
            let id = format!("row/{seq}");
            write_sse_event(
                body,
                Some("row"),
                Some(&id),
                None,
                Some(&json!({ "seq": seq, "row": row })),
            );
        }
        ToolStreamFrame::Chunk { seq, chunk } => {
            let id = format!("chunk/{seq}");
            write_sse_event(body, Some("chunk"), Some(&id), None, Some(&chunk));
        }
    }
}

fn write_tool_stream_frame_chunked(
    stream: &mut impl Write,
    frame: ToolStreamFrame,
) -> std::io::Result<()> {
    match frame {
        ToolStreamFrame::Row { seq, row } => {
            let id = format!("row/{seq}");
            write_chunked_sse_event(
                stream,
                Some("row"),
                Some(&id),
                None,
                Some(&json!({ "seq": seq, "row": row })),
            )
        }
        ToolStreamFrame::Chunk { seq, chunk } => {
            let id = format!("chunk/{seq}");
            write_chunked_sse_event(stream, Some("chunk"), Some(&id), None, Some(&chunk))
        }
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

/// K10: if `response` is a streaming `oracle_query` tool result, borrow its
/// ordered page `chunks` for SSE chunk-frame emission. `None` for every other
/// response, so the standard single-frame SSE path is untouched.
fn streaming_query_chunks(response: &Value) -> Option<&Vec<Value>> {
    let structured = response.get("result")?.get("structuredContent")?;
    if structured.get("streaming").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    structured.get("chunks").and_then(Value::as_array)
}

fn sse_response(
    config: &HttpTransportConfig,
    request: &HttpRequest,
    method: Option<&str>,
    response: Value,
    initialized_session_id: Option<String>,
    principal_key: &str,
    response_event_id: Option<&str>,
) -> HttpResponse {
    let mut body = Vec::new();
    // The negotiated revision rides in the initialize result; store it with the
    // session (bead oraclemcp-s693) so post-init requests can be held to the
    // 2025-06-18 MCP-Protocol-Version header requirement when applicable.
    let negotiated_version = response
        .get("result")
        .and_then(|result| result.get("protocolVersion"))
        .and_then(Value::as_str)
        .unwrap_or(PROTOCOL_VERSION)
        .to_owned();
    let session_id = if method == Some("initialize") {
        write_sse_event(&mut body, None, Some("0"), Some(3000), Some(&Value::Null));
        write_sse_event(&mut body, None, None, None, Some(&response));
        initialized_session_id.or_else(|| Some(new_session_id()))
    } else {
        write_sse_event(&mut body, None, Some("0/0"), Some(3000), Some(&Value::Null));
        // K10: a streaming `oracle_query` result carries an ordered page
        // `chunks` array. Emit each chunk as its own `event: chunk` SSE frame
        // BEFORE the authoritative response frame, so a streaming-aware client
        // renders pages progressively while a plain client still reads the final
        // result. Purely additive — every non-streaming response is unchanged.
        if let Some(chunks) = streaming_query_chunks(&response) {
            write_query_stream_chunks(&mut body, chunks);
        }
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
            store.insert(
                session_id.clone(),
                principal_key.to_owned(),
                negotiated_version,
            );
        }
        if let Some(store) = &config.result_store {
            store.ensure_session(&session_id);
        }
        headers.push(("mcp-session-id".to_owned(), session_id.clone()));
        let cookie_policy = PrivilegedCookiePolicy::for_request(config, request);
        if cookie_policy != PrivilegedCookiePolicy::Suppress {
            headers.push((
                "set-cookie".to_owned(),
                stateful_session_cookie_header(&session_id, cookie_policy.secure()),
            ));
        }
    }
    HttpResponse {
        status: 200,
        headers,
        body,
    }
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
    let config = Arc::new(listener_config(config, EffectiveHttpScheme::Http));
    let mut last_idle_reap = Instant::now();
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while !shutdown.load(Ordering::SeqCst) {
        reap_finished_workers(&mut workers);
        if last_idle_reap.elapsed() >= STATEFUL_IDLE_REAP_INTERVAL {
            reap_idle_stateful_sessions(&config);
            last_idle_reap = Instant::now();
        }
        match listener.accept() {
            Ok((mut stream, _addr)) => {
                let transport_permit = match try_admit_http_capacity(
                    &config.transport_admission,
                    HTTP_TRANSPORT_CAPACITY_SUBJECT,
                    HTTP_TRANSPORT_CAPACITY_SCOPE,
                    "retry after retry_after_ms; accepted connection workers are bounded to preserve operator and doctor reserve",
                ) {
                    Ok(permit) => permit,
                    Err(response) => {
                        let _ = stream.set_write_timeout(Some(CONNECTION_IO_TIMEOUT));
                        if let Err(e) = write_http_response(&mut stream, &response) {
                            tracing::debug!(
                                error = %e,
                                "native HTTP capacity rejection failed"
                            );
                        }
                        continue;
                    }
                };
                let server = server.clone();
                let config = Arc::clone(&config);
                workers.push(std::thread::spawn(move || {
                    let _transport_permit = transport_permit;
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
    let config = Arc::new(listener_config(config, EffectiveHttpScheme::Https));
    let mut last_idle_reap = Instant::now();
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while !shutdown.load(Ordering::SeqCst) {
        reap_finished_workers(&mut workers);
        if last_idle_reap.elapsed() >= STATEFUL_IDLE_REAP_INTERVAL {
            reap_idle_stateful_sessions(&config);
            last_idle_reap = Instant::now();
        }
        match listener.accept() {
            Ok((stream, _addr)) => {
                let transport_permit = match try_admit_http_capacity(
                    &config.transport_admission,
                    HTTP_TRANSPORT_CAPACITY_SUBJECT,
                    HTTP_TRANSPORT_CAPACITY_SCOPE,
                    "retry after retry_after_ms; accepted TLS connection workers are bounded to preserve operator and doctor reserve",
                ) {
                    Ok(permit) => permit,
                    Err(_) => {
                        tracing::debug!("native HTTPS connection rejected at transport capacity");
                        continue;
                    }
                };
                let server = server.clone();
                let config = Arc::clone(&config);
                let tls = Arc::clone(&tls);
                workers.push(std::thread::spawn(move || {
                    let _transport_permit = transport_permit;
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

fn reap_finished_workers(workers: &mut Vec<JoinHandle<()>>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            let _ = worker.join();
        } else {
            index += 1;
        }
    }
}

fn listener_config(
    config: &HttpTransportConfig,
    native_scheme: EffectiveHttpScheme,
) -> HttpTransportConfig {
    let mut config = config.clone();
    if native_scheme.is_https() {
        config.effective_scheme = EffectiveHttpScheme::Https;
    }
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

/// Close all stateful HTTP sessions and dispatch lanes for one principal.
///
/// Per-client credential rotate/revoke calls this after mutating
/// `clients.json`: the transport-facing session ids are removed, buffered SSE
/// results are closed, and the lane dispatch cleanup path revokes any in-memory
/// grants.
pub fn close_http_principal_sessions(
    config: &HttpTransportConfig,
    principal_key: &str,
    reason: DispatchCloseReason,
) -> usize {
    let session_ids = config
        .session_store
        .as_ref()
        .map(|store| store.remove_principal(principal_key))
        .unwrap_or_default();
    if let Some(result_store) = &config.result_store {
        for session_id in &session_ids {
            result_store.remove_session(session_id);
        }
    }
    let closed_lanes = config
        .session_lifecycle
        .as_ref()
        .map(|lifecycle| lifecycle.close_principal_sessions(principal_key, reason))
        .unwrap_or(0);
    closed_lanes.max(session_ids.len())
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
    let peer_addr = stream.peer_addr().ok();
    let peer_is_loopback = peer_addr.is_some_and(|addr| addr.ip().is_loopback());
    handle_stream(
        &mut stream,
        server,
        config,
        peer_is_loopback,
        peer_addr.map(|addr| addr.to_string()),
        None,
    )
}

fn handle_tls_connection(
    mut stream: TcpStream,
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    tls: Arc<TlsServerConfig>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(CONNECTION_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(CONNECTION_IO_TIMEOUT))?;
    let mut connection = ServerConnection::new(tls).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("TLS setup: {e}"))
    })?;
    let peer_addr = stream.peer_addr().ok();
    let peer_is_loopback = peer_addr.is_some_and(|addr| addr.ip().is_loopback());
    while connection.is_handshaking() {
        let (read, written) = connection.complete_io(&mut stream)?;
        if read == 0 && written == 0 && connection.is_handshaking() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "TLS handshake did not complete",
            ));
        }
    }
    let peer_cert_fingerprint_sha256 = connection
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| cert_fingerprint_sha256(cert.as_ref()));
    let mut stream = StreamOwned::new(connection, stream);
    let result = handle_stream(
        &mut stream,
        server,
        config,
        peer_is_loopback,
        peer_addr.map(|addr| addr.to_string()),
        peer_cert_fingerprint_sha256,
    );
    stream.conn.send_close_notify();
    let _ = stream.flush();
    result
}

fn handle_stream(
    stream: &mut (impl Read + Write),
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    peer_is_loopback: bool,
    peer_addr: Option<String>,
    peer_cert_fingerprint_sha256: Option<String>,
) -> std::io::Result<()> {
    let exchange = match read_http_request(stream) {
        Ok(Some(request)) => handle_http_exchange(
            server,
            config,
            request
                .with_peer_loopback(peer_is_loopback)
                .with_peer_addr(peer_addr)
                .with_peer_cert_fingerprint_sha256(peer_cert_fingerprint_sha256),
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
        HttpExchange::ToolStream(response) => response.write_to(stream),
    }
}

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const CONNECTION_IO_TIMEOUT: Duration = Duration::from_secs(30);

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
