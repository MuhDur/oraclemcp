//! Transport configuration for the native HTTP surface: [`HttpTransportConfig`]
//! and everything it is assembled from — the TLS/mTLS client registry, the OAuth
//! and dashboard-pairing wiring, the observability/readiness surface, the
//! request-rate limiter and its defaults, and the admission controllers.
//!
//! Extracted verbatim from `http/mod.rs` (behavior-identical). This module is
//! the *shape* of the transport; the request path that reads it stays in the
//! parent.
//!
//! Every fail-closed default is unchanged and lives here: `stateful` off,
//! `allow_remote` off, OAuth enforcement absent unless configured, an empty
//! mTLS fingerprint registry (an unregistered client certificate never becomes a
//! principal), and the rate limiter's bounded resident-bucket cap.
//!
//! The glob import is deliberate and mirrors the inline test module: this code
//! moved out of `mod.rs` and must resolve every name in exactly the environment
//! it was written in, so the extraction cannot silently rebind a type.
use super::*;

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

    pub(super) fn principal_key_for_fingerprint(&self, fingerprint: &str) -> Option<String> {
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

    pub(super) fn try_admit_at(
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

    pub(super) fn bucket_count(&self) -> usize {
        self.buckets.lock().known.len()
    }

    #[cfg(test)]
    pub(super) fn metric_bucket_names(&self) -> Vec<String> {
        self.registry.all_metrics().keys().cloned().collect()
    }
}

pub(super) struct HttpRequestRateLimitRejection {
    pub(super) scope: String,
    pub(super) subject_id_hash: String,
    pub(super) retry_after_ms: u64,
    pub(super) rate_per_second: u32,
    pub(super) burst: u32,
    pub(super) max_buckets: usize,
    pub(super) bucket_count: usize,
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
    pub(super) fn is_https(self) -> bool {
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
    /// Optional path to a durably stored `/operator/v1/ci-lanes` snapshot:
    /// either the native `ci-lane-snapshot/v1` format or the CI heartbeat
    /// notifier's `ci-heartbeat/v1` output (`scripts/ci_heartbeat.sh`, default
    /// `$XDG_STATE_HOME/oraclemcp/ci-heartbeat.json` — `oraclemcp serve` wires
    /// that default). Unset, missing, malformed, or stale renders the tile as
    /// an honest `"unavailable"`/`unknown` catalog listing rather than a
    /// fabricated green — nothing polls GitHub automatically from this
    /// transport.
    pub ci_lane_snapshot_path: Option<PathBuf>,
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
            .field(
                "ci_lane_snapshot_path",
                &self.ci_lane_snapshot_path.as_ref().map(|_| "<configured>"),
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
            ci_lane_snapshot_path: None,
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
    // Operator and readiness control work never opens an MCP SSE subscriber;
    // reserving subscriber slots would only create unreachable dead capacity.
    Arc::new(AdmissionController::new(
        DEFAULT_GLOBAL_HOST_CAP,
        DEFAULT_STATEFUL_PER_PROFILE_CAP,
    ))
}
