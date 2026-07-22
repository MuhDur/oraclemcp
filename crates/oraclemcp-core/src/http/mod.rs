//! Native Streamable HTTP(S) transport (plan §7.1, §2.5; bead P1-9a /
//! oracle-qmwz.2.9.1).
//!
//! This module owns the small HTTP/1.1 surface oraclemcp actually needs: the
//! `/mcp` Streamable HTTP endpoint, RFC 9728 protected-resource metadata, the
//! DNS-rebinding `Host` guard, the browser `Origin` allowlist, and OAuth bearer
//! validation. It deliberately does not depend on a web framework or ambient
//! async runtime.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt::Write as FmtWrite;
use std::io::{BufRead, BufReader, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// The inline `tests` module reaches these through `use super::*`. Their
// production users moved to `serve`, so scope them to the test cfg here instead
// of touching the test module, which is the behavioral contract.
#[cfg(test)]
use crate::tls::TlsServerConfig;
#[cfg(test)]
use rustls::ServerConnection;
#[cfg(test)]
use std::net::{TcpListener, TcpStream};
#[cfg(test)]
use std::sync::atomic::AtomicBool;

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
    AuditCancel, AuditCorrelation, AuditDecision, AuditEntryDraft, AuditOutcome, AuditRecord,
    AuditSubject, Auditor, DbEvidence, GENESIS_HASH,
};
use oraclemcp_auth::{
    HttpGuardError, HttpGuardPolicy, ResourceServerConfig, SignatureVerifier, TokenError,
    extract_bearer,
};
use oraclemcp_db::PoolSettings;
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use oraclemcp_telemetry::{HealthState, Metrics, MetricsSnapshot};
use parking_lot::{Condvar, Mutex};
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
    DASHBOARD_ACTION_TICKET_HEADER, DASHBOARD_AUDIENCE_HEADER, DASHBOARD_CSRF_HEADER,
    DASHBOARD_INSTANCE_HEADER, DASHBOARD_PAIR_PATH, DASHBOARD_PAIRING_CODE_FIELD,
    DASHBOARD_PAIRING_TTL_SECONDS, DASHBOARD_PROBE_CHALLENGE_HEADER,
    DASHBOARD_PROBE_TOKEN_HASH_HEADER, DASHBOARD_PROOF_HEADER, DASHBOARD_SESSION_PATH,
    DashboardAuth,
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
    SourceObjectTarget, SourceSnapshotDraft, normalize_source_object_type, source_identity_sha256,
    source_object_from_create_or_replace_sql,
};

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
static NEXT_OPERATOR_AUDIT_REQUEST: AtomicU64 = AtomicU64::new(1);

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
    ///
    /// `min_generation`, when present, is the credential-store generation the
    /// revoke/rotate installed. Implementations bind it as a per-principal
    /// admission floor so an in-flight request that authenticated under an
    /// earlier generation cannot resolve a fresh lane after this call becomes
    /// authoritative (QA100 .92).
    fn close_principal_sessions(
        &self,
        _principal_key: &str,
        _reason: DispatchCloseReason,
        _min_generation: Option<u64>,
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

mod ci_lanes;
mod config;
mod operator;
mod request_target;
mod serve;
mod sse;
mod sse_writer;
mod stores;
mod wire;
// Façade: the listener lifecycle moved to `serve`, but every existing path
// (`oraclemcp_core::http::serve_http`, the `lib.rs` re-exports, and this
// module's own calls into `close_http_principal_sessions`) resolves unchanged.
use request_target::{parse_form_urlencoded, split_request_target};
// Façade: the transport configuration moved to `config`, but every existing
// path (`oraclemcp_core::http::HttpTransportConfig`, the `lib.rs` re-exports)
// resolves unchanged.
use config::HttpRequestRateLimitRejection;
pub use config::{
    DEFAULT_HTTP_REQUEST_RATE_BUCKETS, DEFAULT_HTTP_REQUEST_RATE_BURST,
    DEFAULT_HTTP_REQUEST_RATE_PER_SECOND, EffectiveHttpScheme, HttpRequestRateLimitConfig,
    HttpRequestRateLimiters, HttpTransportConfig, MtlsClientRegistry, ObservabilityState,
    ReadinessProbe,
};
// Façade: the session/result stores moved to `stores`; `http::HttpResultStore`
// and the lib.rs re-exports resolve unchanged.
use stores::{
    HttpBufferedEvent, HttpResultWait, HttpSessionCapacityRejection,
    STATEFUL_SESSION_RETRY_AFTER_MS,
};
// Façade: the CI-lane-health tile and its out-of-request-path refresh worker
// live in `ci_lanes`.
use ci_lanes::{operator_ci_lane_health_data, start_ci_lane_poller};
// The rest of `ci_lanes`' internals are exercised directly by the inline test
// module (through `use super::*`).
#[cfg(test)]
use ci_lanes::{
    CI_LANE_MAX_RESPONSE_BYTES, CiLaneCatalogEntry, CiLaneObservation, CiLanePoller,
    CiLaneSnapshot, ci_lane_health_from_observations, ci_lane_health_json,
    ci_lane_snapshot_from_heartbeat, fetch_ci_lane_snapshot, load_ci_lane_snapshot,
    parse_ci_heartbeat_generated_at, parse_ci_lane_catalog, render_ci_lane_health_data,
    write_ci_lane_snapshot,
};
// Reached by the inline test module through `use super::*`.
use operator::{
    OperatorRequestContext, OperatorRouteKind, begin_operator_audit, complete_operator_audit,
    handle_operator_api_route, operator_authority_required_response, operator_route_kind,
    operator_route_panicked_response, prefixed_sha256_hex, refresh_active_lane_metrics,
};
pub use serve::{
    close_http_principal_sessions, serve_control_https_until, serve_http, serve_http_until,
    serve_https, serve_https_until,
};
#[cfg(test)]
use serve::{
    close_stateful_sessions_for_shutdown, complete_tls_handshake, reap_idle_stateful_sessions,
};
// Façade: the SSE/streaming surface moved to `sse`; `mod.rs`, the sibling
// `stores` module (through its own `use super::*`), `serve`'s stream writer, and
// the inline test module all resolve the same names they resolved before.
use sse::{
    HttpSseStream, HttpToolStream, HttpToolStreamBinding, HttpToolStreamNotifications,
    SseResponseEvents, append_nonstreaming_response_if_session, buffered_sse_response,
    events_after_sequence, parse_stream_cursor, retain_server_notifications, sse_response,
    stream_event_sequence, validate_stream_cursor_binding,
};
// Reached by the inline test module through `use super::*`.
#[cfg(test)]
use sse::streaming_query_chunks;
#[cfg(test)]
use sse_writer::write_query_stream_chunks;
use sse_writer::{
    write_chunked_sse_comment, write_chunked_sse_event, write_final_chunk, write_sse_event,
    write_streaming_sse_headers,
};
// Reached by the inline test module through `use super::*`.
#[cfg(test)]
use operator::{
    BrowserApplyPolicy, MAX_OPERATOR_EVENT_STREAMS, MAX_OPERATOR_EVENTS_PER_STREAM,
    OPERATOR_ACTION_TOOL_POLICIES, OPERATOR_IDEMPOTENCY_MAX_ENTRIES, OperatorIdempotencyBegin,
    OperatorIdempotencyEntry, OperatorIdempotencyFacts, OperatorIdempotencyInput,
    SourceSnapshotFetchOutcome, classifier_verdict_from_record, current_source_document,
    dashboard_workbench_release_gate, evict_completed_operator_idempotency_entries_to_capacity,
    operator_action_tool_policy, operator_idempotency_facts, operator_json_response,
    redacted_audit_record,
};
// Façade: the /operator/v1 surface moved to `operator`; `http::OperatorEventStore`
// and the lib.rs re-exports resolve unchanged.
pub use operator::{OperatorEventStore, OperatorIdempotencyLedger};
pub use stores::{HttpResultStore, HttpSessionStore};
#[cfg(test)]
use stores::{HttpResultStoreLimits, MAX_BUFFERED_MCP_EVENTS_PER_SESSION};
#[cfg(test)]
use wire::write_http_response;

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
    /// Credential-store generation observed at authentication, for callers that
    /// authenticated against a per-client bearer credential (QA100 .92). `None`
    /// for OAuth/mTLS principals, which are not governed by the credential store.
    credential_generation: Option<u64>,
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
            credential_generation: Some(authenticated.generation),
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
        TokenError::Missing => "invalid_request",
        TokenError::InsufficientScope => "insufficient_scope",
        // RFC 6750: every other validation failure is `invalid_token`.
        _ => "invalid_token",
    }
}

/// Fixed, token-free OAuth rejection category for the operator audit trail.
///
/// These labels intentionally retain the typed validation outcome without
/// recording a bearer token, signature bytes, untrusted issuer, or algorithm.
/// They must never reach an unauthenticated HTTP response.
fn token_error_audit_reason(e: &TokenError) -> &'static str {
    match e {
        TokenError::Missing => "oauth_missing_bearer",
        TokenError::Malformed => "oauth_malformed",
        TokenError::MissingRequiredClaim(claim) => match *claim {
            "iss" => "oauth_missing_required_claim_iss",
            "sub" => "oauth_missing_required_claim_sub",
            "client_id" => "oauth_missing_required_claim_client_id",
            "jti" => "oauth_missing_required_claim_jti",
            "iat" => "oauth_missing_required_claim_iat",
            "exp" => "oauth_missing_required_claim_exp",
            _ => "oauth_missing_required_claim",
        },
        TokenError::UnexpectedTokenType => "oauth_unexpected_token_type",
        TokenError::UnsupportedAlg(_) => "oauth_unsupported_algorithm",
        TokenError::BadSignature => "oauth_bad_signature",
        // Keep the verified expiry timestamp local to `doctor oauth`; the
        // HTTP audit label and public challenge remain token-free and uniform.
        TokenError::Expired { .. } => "oauth_expired",
        TokenError::NotYetValid => "oauth_not_yet_valid",
        TokenError::UntrustedIssuer(_) => "oauth_untrusted_issuer",
        TokenError::AudienceMismatch => "oauth_audience_mismatch",
        TokenError::InsufficientScope => "oauth_insufficient_scope",
        _ => "oauth_validation_failed",
    }
}

/// Persist a token-free authentication failure for the operator.
///
/// OAuth has already failed closed before this observer runs. An unavailable
/// auditor must therefore never turn a rejection into an allow or change its
/// public response; the fixed reason remains visible in the security log until
/// the signed audit sink is restored.
fn record_oauth_rejection(auditor: Option<&Arc<Auditor>>, error: &TokenError) {
    let reason = token_error_audit_reason(error);
    let Some(auditor) = auditor else {
        tracing::warn!(
            oauth_rejection_reason = reason,
            "OAuth bearer token rejected without a signed audit sink"
        );
        return;
    };
    let draft = AuditEntryDraft {
        subject: AuditSubject::new("anonymous-http", "oauth-token-rejected")
            .with_authn_method("oauth"),
        db_evidence: None,
        cancel: Some(AuditCancel::new("Authentication", reason)),
        result_masking: None,
        tool: "oauth_bearer_authentication".to_owned(),
        sql: "oauth_token_rejected".to_owned(),
        danger_level: "AUTHENTICATION".to_owned(),
        decision: AuditDecision::Blocked,
        rows_affected: None,
        outcome: AuditOutcome::Failed,
    };
    if auditor.append(&draft, audit_timestamp(), true).is_err() {
        tracing::error!(
            oauth_rejection_reason = reason,
            "failed to append OAuth rejection audit record"
        );
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
    auditor: Option<&Arc<Auditor>>,
) -> Result<ValidatedOAuthRequest, HttpResponse> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let token = match extract_bearer(request.header("authorization")) {
        Ok(token) => token,
        Err(error) => {
            record_oauth_rejection(auditor, &error);
            return Err(oauth_error_response(enforcement, None));
        }
    };
    enforcement
        .config
        .validate(token, enforcement.verifier.as_ref(), now_unix)
        .map(|scopes| ValidatedOAuthRequest {
            scope_grant: ScopeGrant(scopes),
            principal_key: oauth_principal_key_from_validated_token(token),
        })
        .map_err(|error| {
            record_oauth_rejection(auditor, &error);
            oauth_error_response(enforcement, Some(&error))
        })
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
        let validated =
            validate_oauth_request(request, enforcement, config.operator_auditor.as_ref())?;
        return Ok(Some(AuthenticatedHttpRequest {
            scope_grant: Some(validated.scope_grant),
            principal_key: validated.principal_key,
            credential_generation: None,
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
            credential_generation: None,
        }));
    }

    if allow_unauthenticated_cookie_get {
        return Ok(None);
    }

    if let Some(enforcement) = &config.oauth {
        record_oauth_rejection(config.operator_auditor.as_ref(), &TokenError::Missing);
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

fn oauth_error_response(enforcement: &OAuthEnforcement, err: Option<&TokenError>) -> HttpResponse {
    let challenge = enforcement
        .config
        .www_authenticate(&enforcement.metadata_url, err.map(token_error_code));
    let status = token_error_status(err);
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
            // Compose the issuer with EVERY present identity claim, not just the
            // first. Two different OAuth clients (distinct client_id/azp) acting
            // for the same subject must not collapse to one principal — otherwise
            // one client's session/revocation would apply to the other. Claims
            // are added in a fixed order so the key is deterministic; at least
            // one of sub/client_id/azp must be present for a structured key.
            let mut parts = vec![format!("iss={issuer}")];
            for claim in ["sub", "client_id", "azp"] {
                if let Some(value) = claims
                    .get(claim)
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    parts.push(format!("{claim}={value}"));
                }
            }
            // Only the issuer means no identity claim was present: fall back.
            (parts.len() > 1).then(|| parts.join("\n"))
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
    ToolStream(Box<HttpToolStream>),
}

impl HttpExchange {
    fn into_buffered_response(self) -> HttpResponse {
        match self {
            Self::Buffered(response) => response,
            Self::SseStream(stream) => stream.into_buffered_response(),
            Self::ToolStream(stream) => (*stream).into_buffered_response(),
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
    handle_http_exchange(server, config, request, false, None).into_buffered_response()
}

fn handle_http_exchange(
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    request: HttpRequest,
    allow_streaming_get: bool,
    mut transport_permit: Option<&mut AdmissionPermit>,
) -> HttpExchange {
    let route = route_for(&request.path);
    if transport_permit
        .as_deref()
        .is_some_and(AdmissionPermit::is_control_probe)
    {
        let is_doctor_request = route == HttpRoute::Observability
            && request.method == "GET"
            && matches!(request.path.as_str(), HEALTHZ_PATH | READYZ_PATH);
        if is_doctor_request {
            let permit = transport_permit
                .as_deref_mut()
                .expect("control probe was present above");
            if permit.promote_to_doctor().is_err() {
                return HttpExchange::Buffered(control_reserve_rejection(config));
            }
        } else if route != HttpRoute::OperatorApi {
            // A fallback permit may parse only enough request data for trusted
            // route/auth classification. Ordinary callers cannot retain it by
            // naming an admission class, spoofing a header, or choosing a
            // non-control route.
            return HttpExchange::Buffered(control_reserve_rejection(config));
        }
    }

    match route {
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
            // OAuth scopes are an upper bound on every dispatch that this
            // request can reach.  The operator API eventually forwards tool
            // actions through the same dispatcher as /mcp, so preserve the
            // validated grant through that forwarding boundary as well.
            let scope_grant = authenticated
                .as_ref()
                .and_then(|auth| auth.scope_grant.as_ref());
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
            if let Some(permit) = transport_permit
                .as_mut()
                .filter(|permit| permit.is_control_probe())
                && permit.promote_to_operator().is_err()
            {
                return HttpExchange::Buffered(control_reserve_rejection(config));
            }
            let operator_audit = match begin_operator_audit(config, &operator_subject, &request) {
                Ok(attempt) => attempt,
                Err(response) => return HttpExchange::Buffered(response),
            };
            if let Err(response) = try_admit_http_request_rate(
                &config.request_rate_limits,
                HTTP_RATE_LIMIT_SCOPE_OPERATOR,
                &operator_subject.legacy_agent_identity(),
                "retry after retry_after_ms, or reduce operator API request rate for this subject",
            ) {
                return HttpExchange::Buffered(complete_operator_audit(
                    config,
                    &operator_subject,
                    &request,
                    &operator_audit,
                    response,
                ));
            }
            let dashboard_browser = config.dashboard_auth.is_some() && principal_key.is_none();
            let response = catch_unwind(AssertUnwindSafe(|| {
                handle_operator_api_route(
                    server,
                    config,
                    &request,
                    &operator_subject,
                    operator_route,
                    operator_audit.seq,
                    OperatorRequestContext {
                        dashboard_browser,
                        scope_grant,
                    },
                )
            }))
            .unwrap_or_else(|_| operator_route_panicked_response());
            let response = complete_operator_audit(
                config,
                &operator_subject,
                &request,
                &operator_audit,
                response,
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
    let credential_generation = authenticated
        .as_ref()
        .and_then(|auth| auth.credential_generation);
    match request.method.as_str() {
        "GET" => handle_mcp_get(config, &request, principal_key, allow_streaming_get),
        "DELETE" => HttpExchange::Buffered(handle_mcp_delete(
            server,
            config,
            &request,
            stateful_principal_key(principal_key),
        )),
        "POST" => handle_mcp_post_exchange(
            server,
            config,
            &request,
            scope_grant,
            principal_key,
            credential_generation,
        ),
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

/// Local dashboard bootstrap (bead oraclemcp-l6xn).
///
/// `GET` serves a script-free pairing form; `POST` exchanges the pasted code for
/// a session cookie. The bootstrap secret is accepted **only** from the POST
/// body: it is never read from the request target, so it cannot be recovered
/// from browser history, an extension's tab/navigation events, `Referer`, or an
/// access log. A stale `?ticket=` URL is refused without consuming anything.
fn handle_dashboard_pairing_route(
    config: &HttpTransportConfig,
    request: &HttpRequest,
) -> HttpResponse {
    if !matches!(request.method.as_str(), "GET" | "POST") {
        return with_dashboard_security_headers(
            empty_response(405).with_header("allow", "GET, POST"),
        );
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
    // A secret in the request target is refused outright rather than honored:
    // replaying a pre-l6xn URL must not pair, and must not burn a live ticket.
    if request.query_param("ticket").is_some() {
        return dashboard_auth_error_response(400, "dashboard_pairing_query_secret_refused");
    }
    let cookie_policy = PrivilegedCookiePolicy::for_request(config, request);
    if cookie_policy == PrivilegedCookiePolicy::Suppress {
        return dashboard_auth_error_response(403, "dashboard_pairing_requires_secure_transport");
    }
    if request.method == "GET" {
        if let Some(response) = enforce_dashboard_get_headers(request) {
            return response;
        }
        return dashboard_pairing_form_response();
    }
    if let Some(response) = enforce_dashboard_post_headers(request) {
        return response;
    }
    if request.body.len() > MAX_PAIRING_BODY_BYTES {
        return with_dashboard_security_headers(empty_response(413));
    }
    let Some(code) = dashboard_pairing_code_from_body(request) else {
        return dashboard_pairing_auth_required_response();
    };
    match auth.exchange_ticket(&code, auth.audience(), cookie_policy.secure()) {
        Ok(login) => with_dashboard_security_headers(
            empty_response(303)
                .with_header("location", "/")
                .with_header("set-cookie", &login.session_cookie)
                .with_header("cache-control", "no-store"),
        ),
        Err(_) => dashboard_pairing_auth_required_response(),
    }
}

/// Read the one-time code from a same-origin form submission. Only an exact
/// `application/x-www-form-urlencoded` body is read; nothing else is inspected.
fn dashboard_pairing_code_from_body(request: &HttpRequest) -> Option<String> {
    let content_type = request.header("content-type")?;
    let media_type = content_type.split(';').next()?.trim();
    if !media_type.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        return None;
    }
    let body = std::str::from_utf8(&request.body).ok()?;
    parse_form_urlencoded(body)
        .into_iter()
        .find(|(name, _)| name == DASHBOARD_PAIRING_CODE_FIELD)
        .map(|(_, value)| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

/// The bootstrap form. Script-free by design: keeping JS out of the pairing
/// boundary means no page script ever handles the code, and the page needs no
/// CSP relaxation. The page is secret-free, so it can use `same-origin`
/// referrer policy: that lets browsers serialize the real same-origin `Origin`
/// on the form POST while still refusing literal `Origin: null`.
/// Inline `style-src` is already permitted by [`dashboard_csp`].
fn dashboard_pairing_form_response() -> HttpResponse {
    let body = format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin">
<title>Pair the oraclemcp dashboard</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ margin: 0; min-height: 100vh; display: grid; place-items: center;
         font: 16px/1.5 ui-sans-serif, system-ui, sans-serif; }}
  main {{ width: min(28rem, 90vw); }}
  h1 {{ font-size: 1.25rem; margin: 0 0 .5rem; }}
  p {{ margin: 0 0 1.25rem; opacity: .8; }}
  label {{ display: block; font-weight: 600; margin-bottom: .375rem; }}
  input, button {{ font: inherit; width: 100%; box-sizing: border-box;
                   padding: .625rem .75rem; border-radius: .5rem; }}
  input {{ border: 1px solid currentColor; letter-spacing: .05em; }}
  button {{ margin-top: .75rem; border: 0; font-weight: 600; cursor: pointer;
            background: currentColor; }}
  button span {{ mix-blend-mode: difference; filter: invert(1); }}
</style>
</head>
<body>
<main>
  <h1>Pair the oraclemcp dashboard</h1>
  <p>Paste the one-time code printed by <code>oraclemcp dashboard</code>. It expires
     {ttl} seconds after it was issued and works once.</p>
  <form method="post" action="{path}">
    <label for="{field}">One-time pairing code</label>
    <input id="{field}" name="{field}" type="password" autocomplete="off"
           autocapitalize="off" autocorrect="off" spellcheck="false" autofocus
           required>
    <button type="submit"><span>Pair this browser</span></button>
  </form>
</main>
</body>
</html>
"##,
        ttl = DASHBOARD_PAIRING_TTL_SECONDS,
        path = DASHBOARD_PAIR_PATH,
        field = DASHBOARD_PAIRING_CODE_FIELD,
    );
    with_dashboard_pairing_form_security_headers(HttpResponse {
        status: 200,
        headers: vec![
            (
                "content-type".to_owned(),
                "text/html; charset=utf-8".to_owned(),
            ),
            ("cache-control".to_owned(), "no-store".to_owned()),
        ],
        body: body.into_bytes(),
    })
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
    // Browser CSRF defense applied to EVERY request, even an already
    // authenticated one: if a browser Origin / Sec-Fetch-Site header is present
    // it MUST be same-origin, regardless of the authentication mechanism. An
    // ambient credential — a pairing cookie OR an ambient mTLS client
    // certificate the browser attaches automatically — is CSRF-able, so a valid
    // principal does not exempt the origin check. Non-browser clients (CLI,
    // bearer/mTLS API callers) send neither header and pass this check, so they
    // are unaffected.
    if let Some(response) = enforce_dashboard_get_headers(request) {
        return Some(response);
    }
    if has_authenticated_principal {
        return None;
    }
    if request.method == "POST" {
        // Unauthenticated browser POST (the pairing flow): additionally require a
        // matching Origin (fail closed on absent) and a valid CSRF ticket.
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
    with_dashboard_security_headers_referrer(response, "no-referrer")
}

fn with_dashboard_pairing_form_security_headers(response: HttpResponse) -> HttpResponse {
    with_dashboard_security_headers_referrer(response, "same-origin")
}

fn with_dashboard_security_headers_referrer(
    response: HttpResponse,
    referrer_policy: &'static str,
) -> HttpResponse {
    response
        .with_header("content-security-policy", dashboard_csp())
        .with_header("x-content-type-options", "nosniff")
        .with_header("referrer-policy", referrer_policy)
        .with_header("x-frame-options", "DENY")
}

fn dashboard_csp() -> &'static str {
    "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
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
            let mut response = json_response(
                status,
                &serde_json::to_value(&report).unwrap_or(Value::Null),
            );
            if let (Some(auth), Some(challenge), Some(token_sha256)) = (
                config.dashboard_auth.as_ref(),
                request.header(DASHBOARD_PROBE_CHALLENGE_HEADER),
                request.header(DASHBOARD_PROBE_TOKEN_HASH_HEADER),
            ) && let Some(proof) = auth.pairing_probe_proof(challenge, token_sha256)
            {
                response = response
                    .with_header(DASHBOARD_INSTANCE_HEADER, auth.instance_id())
                    .with_header(DASHBOARD_AUDIENCE_HEADER, auth.audience())
                    .with_header(DASHBOARD_PROOF_HEADER, &proof);
            }
            Some(response)
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
    server: &OracleMcpServer,
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
                server.notifications().forget_session(session_id);
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
    // Only select the streaming path for a well-formed JSON-RPC 2.0 request. An
    // invalid envelope (wrong/missing `jsonrpc`, or an id that is not a JSON-RPC
    // request id) must fall through to the main dispatcher, which validates it
    // and returns a proper JSON-RPC error instead of being silently streamed.
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return None;
    }
    if object.get("method").and_then(Value::as_str) != Some("tools/call") {
        return None;
    }
    // A request that expects a response must carry an id that is a string or a
    // number; a missing id (a notification), a null id, or a structured id is
    // not a streamable request.
    let id = object.get("id")?;
    if !id.is_string() && !id.is_number() {
        return None;
    }
    let id = id.clone();
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
    credential_generation: Option<u64>,
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
            // Pre-generate the opaque id so discovery observation and queued
            // notifications are scoped to the same future MCP session. It is
            // not inserted or exposed until initialize succeeds and both
            // bounded registries admit it atomically.
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
    context = context.with_local_transport(request.peer_is_loopback);
    if let Some(session_id) = http_session_id.as_deref() {
        context = context.with_http_session_id(session_id);
    }
    // Every HTTP dispatch has a canonical transport principal. In particular,
    // stateless unauthenticated HTTP must carry `anonymous-http` explicitly so
    // a missing principal remains unambiguous for the stdio transport.
    context = context.with_principal_key(session_principal_key);
    let notification_request_owner = config.stateful.then(new_session_id);
    if let (Some(session_id), Some(request_owner)) = (
        http_session_id.as_deref(),
        notification_request_owner.as_deref(),
    ) {
        context = context.with_notification_owners(session_id, request_owner);
    } else {
        context = context.without_server_notifications();
    }
    // QA100 .92: carry the credential generation observed at admission so lane
    // resolution can refuse a stale (pre-revoke/rotate) context fail-closed.
    if let Some(generation) = credential_generation {
        context = context.with_credential_generation(generation);
    }
    if config.stateful
        && let Some((request_id, name, args)) = streaming_oracle_query_call(&parsed)
        && let Some(session_id) = http_session_id.clone()
    {
        server.observe_tool_catalog(context);
        let progress_token = parsed
            .get("params")
            .and_then(|params| crate::notifications::progress_token_from_params(Some(params)));
        if let (Some(request_owner), Some(progress_token)) = (
            notification_request_owner.as_deref(),
            progress_token.as_ref(),
        ) {
            server.notifications().enqueue_progress(
                request_owner,
                progress_token,
                0.0,
                Some(1.0),
                Some(&format!("{name} started")),
            );
        }
        let initial_notifications = notification_request_owner
            .as_deref()
            .map(|request_owner| server.drain_server_notifications(request_owner))
            .map(|notifications| {
                retain_server_notifications(
                    config.result_store.as_deref(),
                    Some(&session_id),
                    notifications,
                )
            })
            .unwrap_or_default();
        let (frames_tx, frames_rx) = mpsc::channel(QUERY_ROW_STREAM_CHANNEL_CAPACITY);
        match server.start_tool_stream_blocking_with_context(context, name, args, frames_tx) {
            Outcome::Ok(reply_rx) => {
                return HttpExchange::ToolStream(Box::new(HttpToolStream::new(
                    server.clone(),
                    config.result_store.clone(),
                    HttpToolStreamBinding {
                        session_id,
                        principal_key: session_principal_key.to_owned(),
                    },
                    request_id,
                    frames_rx,
                    reply_rx,
                    HttpToolStreamNotifications {
                        initial: initial_notifications,
                        request_owner: notification_request_owner,
                        progress_token,
                    },
                )));
            }
            Outcome::Err(envelope) => {
                if let (Some(request_owner), Some(progress_token)) = (
                    notification_request_owner.as_deref(),
                    progress_token.as_ref(),
                ) {
                    server.notifications().enqueue_progress(
                        request_owner,
                        progress_token,
                        1.0,
                        Some(1.0),
                        Some("oracle_query completed"),
                    );
                }
                let mut notifications = initial_notifications;
                if let Some(request_owner) = notification_request_owner.as_deref() {
                    notifications.extend(retain_server_notifications(
                        config.result_store.as_deref(),
                        Some(&session_id),
                        server.drain_server_notifications(request_owner),
                    ));
                }
                let response =
                    server.jsonrpc_tool_response_from_outcome(request_id, Outcome::Err(envelope));
                let response_event_id = config.result_store.as_ref().and_then(|store| {
                    append_nonstreaming_response_if_session(store, &session_id, &response)
                });
                return HttpExchange::Buffered(sse_response(
                    config,
                    request,
                    method.as_deref(),
                    response,
                    http_session_id,
                    session_principal_key,
                    SseResponseEvents {
                        response_event_id: response_event_id.as_deref(),
                        notifications: &notifications,
                    },
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
    let notification_events = notification_request_owner
        .as_deref()
        .map(|request_owner| server.drain_server_notifications(request_owner))
        .map(|notifications| {
            retain_server_notifications(
                config.result_store.as_deref(),
                http_session_id.as_deref(),
                notifications,
            )
        })
        .unwrap_or_default();
    // QA100 `.116`: the stateful/stateless buffered HTTP paths build their
    // response here from the `_outcome` variant (bypassing the stdio wrapper),
    // so enforce the whole-response byte budget before the value is framed for
    // the wire and, on the stateful path, inserted into the replay store.
    let response = match outcome {
        Outcome::Ok(Some(response)) => server.enforce_response_byte_budget(response),
        Outcome::Ok(None) => return HttpExchange::Buffered(empty_response(202)),
        Outcome::Err(error) => server.enforce_response_byte_budget(error.into_response()),
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
                config.result_store.as_ref().and_then(|store| {
                    append_nonstreaming_response_if_session(store, session_id, &response)
                })
            })
        };
        return HttpExchange::Buffered(sse_response(
            config,
            request,
            method.as_deref(),
            response,
            http_session_id,
            session_principal_key,
            SseResponseEvents {
                response_event_id: response_event_id.as_deref(),
                notifications: &notification_events,
            },
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
    handle_mcp_post_exchange(server, config, request, scope_grant, principal_key, None)
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

fn try_admit_http_transport(
    controller: &AdmissionController,
    peer_is_loopback: bool,
) -> Result<AdmissionPermit, HttpResponse> {
    let cx = detached_admission_cx();
    if let Ok(permit) = controller.try_admit(&cx, HTTP_TRANSPORT_CAPACITY_SUBJECT) {
        return Ok(permit);
    }
    // The default operator authority is the local process owner and readiness
    // is normally scraped locally. Do not expose the pre-auth reserve to remote
    // peers: a remote caller has not yet presented server-verifiable authority
    // and could otherwise occupy the incident-response slots with slow ingress.
    if peer_is_loopback && let Ok(permit) = controller.try_admit_control_probe(&cx) {
        return Ok(permit);
    }
    Err(control_reserve_rejection_for(controller))
}

fn control_reserve_rejection(config: &HttpTransportConfig) -> HttpResponse {
    control_reserve_rejection_for(&config.transport_admission)
}

fn control_reserve_rejection_for(controller: &AdmissionController) -> HttpResponse {
    let envelope = controller
        .at_capacity_envelope(
            HTTP_TRANSPORT_CAPACITY_SCOPE,
            HTTP_TRANSPORT_CAPACITY_SUBJECT,
        )
        .with_next_step(
            "retry after retry_after_ms; control reserve requires an exact local readiness route or server-authorized operator request",
        );
    let retry_after =
        retry_after_header_seconds(envelope.retry_after_ms.unwrap_or(DEFAULT_RETRY_AFTER_MS));
    json_response(429, &envelope.to_json()).with_header("retry-after", &retry_after)
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

fn stateful_session_capacity_response(
    rejection: HttpSessionCapacityRejection,
    principal_key: &str,
) -> HttpResponse {
    let snapshot = json!({
        "scope": rejection.scope,
        "subject_id_hash": operator_subject_id_hash(principal_key),
        "active_global": rejection.active_global,
        "active_for_principal": rejection.active_for_principal,
        "max_global": rejection.limits.max_global,
        "max_per_principal": rejection.limits.max_per_principal,
        "retry_after_ms": STATEFUL_SESSION_RETRY_AFTER_MS,
    });
    let envelope = ErrorEnvelope::new(
        ErrorClass::AtCapacity,
        format!(
            "stateful session capacity exhausted; session_capacity_snapshot={}",
            serde_json::to_string(&snapshot).unwrap_or_else(|_| {
                json!({
                    "scope": "stateful_sessions",
                    "subject": "redacted",
                    "retry_after_ms": STATEFUL_SESSION_RETRY_AFTER_MS,
                })
                .to_string()
            })
        ),
    )
    .with_retry_after_ms(STATEFUL_SESSION_RETRY_AFTER_MS)
    .with_next_step(
        "close an existing MCP session with DELETE or wait for idle expiry, then retry initialize",
    );
    json_response(429, &envelope.to_json()).with_header(
        "retry-after",
        &retry_after_header_seconds(STATEFUL_SESSION_RETRY_AFTER_MS),
    )
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

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
/// The pairing route returns before the MCP body cap, so it carries its own.
/// One hex code in a form body is ~80 bytes; 1 KiB is generous and bounded.
const MAX_PAIRING_BODY_BYTES: usize = 1024;

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
        431 => "Request Header Fields Too Large",
        499 => "Client Closed Request",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown Status",
    }
}
