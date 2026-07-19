//! The `/operator/v1` API: its route table, every route handler, the
//! hash-chained audit that brackets each one, the idempotency ledger, and the
//! per-subject/per-lane event replay stream behind `/operator/v1/events`.
//!
//! Extracted verbatim from `http/mod.rs` (behavior-identical). The transport
//! itself — routing, authentication, the dashboard and observability routes —
//! stays in the parent; this module is what happens *after* a request has been
//! classified as an operator route and authorized.
//!
//! Security properties preserved exactly, none of them relaxed by the move:
//!
//! - **Subject is server-derived, never browser-supplied.** Every handler acts on
//!   the principal the transport authenticated (mTLS fingerprint, OAuth subject,
//!   or client credential); no route takes an identity from the request body or a
//!   caller-set header.
//! - **Operator authority is a config allow-list above the subject**, checked
//!   before a route runs; a route that is not on the exact allow-list fails closed
//!   rather than falling through.
//! - **Audit brackets every route, and a broken audit sink fails the request
//!   closed**: the attempt is durably logged before the effect and the terminal
//!   record after it; failing to write either is an error, never a silently
//!   unaudited operator action.
//! - **Guarded actions forward through MCP `tools/call`**, so they meet the same
//!   fail-closed classifier and operating-level gate as any agent request — the
//!   operator API is not a side door around the guard.
//! - The idempotency ledger's leases/TTL and the bounded event-replay ring keep
//!   their caps.
//!
//! This is a flat module rather than an `operator/` directory on purpose: the
//! dashboard security-substring scanner (`dashboard_e2e::read_http_source`) does
//! a NON-recursive `read_dir` over `crates/oraclemcp-core/src/http/*.rs`, so a
//! subdirectory would silently escape the very contract this extraction must
//! preserve.
//!
//! The glob import mirrors the inline test module: the moved code resolves every
//! name in exactly the environment it was written in.
use super::*;
use crate::change_proposal::{
    EditionProposal, EditionProposalCreateRequest, EditionProposalStatus,
    EditionProposalTransitionRequest,
};
use oraclemcp_guard::{Classifier, OperatingLevel};
use serde::Deserialize;

pub(super) const MAX_OPERATOR_EVENTS_PER_STREAM: usize = 128;

/// Hard cap on the number of distinct `/operator/v1/events` replay streams. Keys
/// are already bounded to active lanes per authenticated operator (a specific
/// `lane_id` is validated against the active lane set at the call site); this cap
/// additionally bounds accumulation from closed lanes and many operators over
/// time, evicting the least-recently-updated stream when exceeded.
pub(super) const MAX_OPERATOR_EVENT_STREAMS: usize = 256;

/// The default aggregate operator event stream. Always a valid `lane_id`; any
/// other `lane_id` must name a currently active lane.
const OPERATOR_AGGREGATE_LANE: &str = "operator";

/// One operator event stream: its bounded event ring plus the last time it was
/// touched (for least-recently-updated eviction).
#[derive(Debug)]
pub(super) struct OperatorEventStream {
    events: Vec<HttpBufferedEvent>,
    last_updated: Instant,
}

/// Bounded `/operator/v1/events` replay buffer.
///
/// Events are keyed by the redacted subject hash plus lane id. That makes resume
/// isolation structural: even identical cursor numbers on two lanes or two
/// operators consult different rings.
#[derive(Debug, Default)]
pub struct OperatorEventStore {
    pub(super) streams: Mutex<HashMap<OperatorEventStreamKey, OperatorEventStream>>,
}

impl OperatorEventStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub(super) fn append_snapshot_and_resume(
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
        // Bound the number of live streams: when a NEW key would exceed the cap,
        // evict the least-recently-updated stream first (defense in depth on top
        // of the call-site lane_id validation).
        if !streams.contains_key(&key)
            && streams.len() >= MAX_OPERATOR_EVENT_STREAMS
            && let Some(evict) = streams
                .iter()
                .min_by_key(|(_, entry)| entry.last_updated)
                .map(|(evict_key, _)| evict_key.clone())
        {
            streams.remove(&evict);
        }
        let entry = streams.entry(key).or_insert_with(|| OperatorEventStream {
            events: Vec::new(),
            last_updated: Instant::now(),
        });
        entry.last_updated = Instant::now();
        let stream = &mut entry.events;
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
            data: Arc::new(event),
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
pub(super) struct OperatorEventStreamKey {
    subject_id_hash: String,
    lane_id: String,
}

#[derive(Debug)]
pub(super) enum OperatorEventReplayError {
    Expired {
        cursor: String,
        oldest_event_id: String,
    },
}

const OPERATOR_IDEMPOTENCY_TTL: Duration = Duration::from_secs(15 * 60);
pub(super) const OPERATOR_IDEMPOTENCY_MAX_ENTRIES: usize = 1024;

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

    pub(super) fn begin(
        &self,
        route: &str,
        facts: OperatorIdempotencyFacts,
    ) -> OperatorIdempotencyBegin {
        let mut entries = self.entries.lock();
        // Drop only genuinely TTL-expired entries before the lookup (an expired
        // key must read as absent). Capacity eviction happens AFTER the lookup,
        // on the fresh-insert path, so it can never evict the key being served.
        prune_expired_operator_idempotency_entries(&mut entries);
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
                // A genuinely new key: enforce the capacity cap now, evicting
                // only completed entries — never an in-progress one, whose retry
                // would otherwise lose its marker and double-execute. Runs after
                // the lookup, so it can never evict the entry for this key.
                evict_completed_operator_idempotency_entries_to_capacity(&mut entries);
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

    pub(super) fn complete(
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
pub(super) struct OperatorIdempotencyFacts {
    pub(super) storage_key: String,
    pub(super) request_id: String,
    pub(super) idempotency_key_sha256: String,
    pub(super) fingerprint_sha256: String,
    pub(super) lane_id: Option<String>,
    pub(super) lane_generation: Option<u64>,
    pub(super) subject_id_hash: String,
    pub(super) grant_sha256: Option<String>,
    pub(super) sql_sha256: Option<String>,
    pub(super) operator_audit_seq: u64,
    pub(super) started_at: String,
    pub(super) completed_at: Option<String>,
}

impl OperatorIdempotencyFacts {
    pub(super) fn as_json(&self, outcome: &str) -> Value {
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

    pub(super) fn completed(&self, completed_at: String) -> Self {
        let mut facts = self.clone();
        facts.completed_at = Some(completed_at);
        facts
    }
}

#[derive(Clone, Debug)]
pub(super) struct OperatorIdempotencyEntry {
    pub(super) facts: OperatorIdempotencyFacts,
    pub(super) response: Option<HttpResponse>,
    pub(super) created_at: Instant,
}

#[derive(Clone, Debug)]
pub(super) struct OperatorIdempotencyLease {
    storage_key: String,
}

pub(super) enum OperatorIdempotencyBegin {
    Fresh(OperatorIdempotencyLease),
    Replay(HttpResponse),
    InProgress(HttpResponse),
    Conflict(HttpResponse),
}

/// Drop TTL-expired idempotency entries. Safe to run before a key lookup: an
/// expired entry must read as absent so the action can proceed afresh.
fn prune_expired_operator_idempotency_entries(
    entries: &mut HashMap<String, OperatorIdempotencyEntry>,
) {
    let now = Instant::now();
    entries.retain(|_, entry| now.duration_since(entry.created_at) <= OPERATOR_IDEMPOTENCY_TTL);
}

/// Enforce the capacity bound by evicting the oldest COMPLETED entries. An
/// in-progress entry (`response` is `None`) is never evicted — dropping it would
/// discard the marker a concurrent retry relies on and let the operator action
/// double-execute. If every entry is in-progress the cap may be briefly
/// exceeded; the in-progress count is separately bounded by request-concurrency
/// limits and drains as operations complete. Called only on a fresh insert,
/// after the key lookup, so it can never evict the key being served.
pub(super) fn evict_completed_operator_idempotency_entries_to_capacity(
    entries: &mut HashMap<String, OperatorIdempotencyEntry>,
) {
    while entries.len() >= OPERATOR_IDEMPOTENCY_MAX_ENTRIES {
        let Some(oldest_completed) = entries
            .iter()
            .filter(|(_, entry)| entry.response.is_some())
            .min_by_key(|(_, entry)| entry.created_at)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        entries.remove(&oldest_completed);
    }
}

pub(super) fn operator_authority_required_response() -> HttpResponse {
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

pub(super) fn operator_route_panicked_response() -> HttpResponse {
    json_response(
        500,
        &json!({
            "error": "operator_route_panicked",
            "message": "operator route panicked; the owning lane was contained and the request failed",
            "outcome": "failed",
            "next_step": "inspect the audit correlation and service logs before retrying",
        }),
    )
}

fn operator_terminal_audit_failed_response(
    attempt: &OperatorAuditAttempt,
    original_http_status: u16,
) -> HttpResponse {
    json_response(
        500,
        &json!({
            "error": "operator_terminal_audit_failed",
            "message": "operator request returned but its terminal audit record could not be durably appended",
            "outcome": "indeterminate",
            "pending_audit_seq": attempt.seq,
            "request_sha256": attempt.request_sha256,
            "original_http_status": original_http_status,
            "side_effects": "may_have_occurred",
            "next_step": "do not retry blindly; verify target state and repair the audit sink using the pending record correlation",
        }),
    )
}

#[derive(Clone, Debug)]
pub(super) struct OperatorAuditAttempt {
    pub(super) seq: u64,
    pub(super) request_sha256: String,
}

pub(super) fn begin_operator_audit(
    config: &HttpTransportConfig,
    subject: &AuditSubject,
    request: &HttpRequest,
) -> Result<OperatorAuditAttempt, HttpResponse> {
    let Some(auditor) = &config.operator_auditor else {
        return Err(operator_audit_required_response());
    };
    let request_sha256 = operator_audit_request_sha256(subject, request);
    let draft = AuditEntryDraft {
        subject: subject.clone(),
        db_evidence: None,
        cancel: None,
        result_masking: None,
        tool: "operator_api".to_owned(),
        sql: format!("{} {}", request.method, request.path),
        danger_level: "OPERATOR".to_owned(),
        decision: AuditDecision::Allowed,
        rows_affected: None,
        outcome: AuditOutcome::Pending,
    };
    auditor
        .append_correlated(
            &draft,
            audit_timestamp(),
            true,
            Some(AuditCorrelation::attempt(request_sha256.clone())),
        )
        .map(|record| OperatorAuditAttempt {
            seq: record.seq,
            request_sha256,
        })
        .map_err(|_| operator_audit_failed_response())
}

fn operator_audit_request_sha256(subject: &AuditSubject, request: &HttpRequest) -> String {
    let nonce = NEXT_OPERATOR_AUDIT_REQUEST.fetch_add(1, Ordering::Relaxed);
    let observed_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let material = format!(
        "oraclemcp-operator-audit-request-v1\0{}\0{}\0{}\0{observed_nanos}\0{nonce}",
        subject.legacy_agent_identity(),
        request.method,
        request.path,
    );
    oraclemcp_audit::sha256_hex(material.as_bytes())
}

#[derive(Clone, Debug)]
struct OperatorAuditTerminal {
    decision: AuditDecision,
    outcome: AuditOutcome,
    cancel: Option<AuditCancel>,
}

pub(super) fn complete_operator_audit(
    config: &HttpTransportConfig,
    subject: &AuditSubject,
    request: &HttpRequest,
    attempt: &OperatorAuditAttempt,
    response: HttpResponse,
) -> HttpResponse {
    let terminal = operator_audit_terminal(&response);
    let draft = AuditEntryDraft {
        subject: subject.clone(),
        db_evidence: None,
        cancel: terminal.cancel,
        result_masking: None,
        tool: "operator_api".to_owned(),
        sql: format!("{} {}", request.method, request.path),
        danger_level: "OPERATOR".to_owned(),
        decision: terminal.decision,
        rows_affected: None,
        outcome: terminal.outcome,
    };
    let appended = config.operator_auditor.as_ref().is_some_and(|auditor| {
        auditor
            .append_correlated(
                &draft,
                audit_timestamp(),
                true,
                Some(AuditCorrelation::terminal(
                    attempt.request_sha256.clone(),
                    attempt.seq,
                )),
            )
            .is_ok()
    });
    if appended {
        response
    } else {
        operator_terminal_audit_failed_response(attempt, response.status)
    }
}

fn operator_audit_terminal(response: &HttpResponse) -> OperatorAuditTerminal {
    if response.status == 499 {
        return OperatorAuditTerminal {
            decision: AuditDecision::Allowed,
            outcome: AuditOutcome::Failed,
            cancel: Some(AuditCancel::new(
                "Transport",
                "operator_request_cancelled_before_terminal_result",
            )),
        };
    }
    if (400..500).contains(&response.status) {
        return OperatorAuditTerminal {
            decision: AuditDecision::Blocked,
            outcome: AuditOutcome::Failed,
            cancel: None,
        };
    }
    if response.status >= 500 {
        return OperatorAuditTerminal {
            decision: AuditDecision::Allowed,
            outcome: AuditOutcome::Failed,
            cancel: None,
        };
    }
    if let Ok(body) = serde_json::from_slice::<Value>(&response.body)
        && let Some(refused) = operator_semantic_failure(&body)
    {
        return OperatorAuditTerminal {
            decision: if refused {
                AuditDecision::Blocked
            } else {
                AuditDecision::Allowed
            },
            outcome: AuditOutcome::Failed,
            cancel: None,
        };
    }
    OperatorAuditTerminal {
        decision: AuditDecision::Allowed,
        outcome: AuditOutcome::Succeeded,
        cancel: None,
    }
}

/// Return `Some(refused)` for a terminal semantic failure carried inside a 2xx
/// operator response. MCP/JSON-RPC errors deliberately use HTTP 200, so status
/// alone cannot decide the audit outcome.
fn operator_semantic_failure(body: &Value) -> Option<bool> {
    let data = body.get("data").unwrap_or(body);
    if data.get("error").is_some_and(|error| !error.is_null()) {
        return Some(operator_error_class(data).is_some_and(operator_error_class_is_refusal));
    }
    if data
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| {
            matches!(
                status,
                "accepted" | "stopped_on_failure" | "not_started" | "partial"
            )
        })
    {
        return Some(false);
    }
    let mcp_response = data.get("mcp_response")?;
    let Some(mcp_response) = mcp_response.as_object() else {
        return Some(false);
    };
    if let Some(error) = mcp_response.get("error") {
        return Some(
            operator_error_class(error)
                .or_else(|| operator_error_class(data))
                .is_some_and(operator_error_class_is_refusal),
        );
    }
    let Some(result) = mcp_response.get("result").and_then(Value::as_object) else {
        return Some(false);
    };
    if result.get("isError").and_then(Value::as_bool) == Some(true) {
        let structured = result.get("structuredContent").unwrap_or(&Value::Null);
        return Some(operator_error_class(structured).is_some_and(operator_error_class_is_refusal));
    }
    None
}

fn operator_error_class(value: &Value) -> Option<&str> {
    value
        .get("error_class")
        .and_then(Value::as_str)
        .or_else(|| value.pointer("/data/error_class").and_then(Value::as_str))
}

fn operator_error_class_is_refusal(error_class: &str) -> bool {
    matches!(
        error_class,
        "CHALLENGE_REQUIRED"
            | "FORBIDDEN_STATEMENT"
            | "INSUFFICIENT_PRIVILEGE"
            | "LEASE_REQUIRED"
            | "OPERATING_LEVEL_TOO_LOW"
            | "POLICY_DENIED"
            | "RUNTIME_STATE_REQUIRED"
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OperatorRouteKind {
    Index,
    Schema,
    Health,
    Metrics,
    AuditTail,
    ActiveLanes,
    CiLanes,
    LaneCancel,
    Vsession,
    Events,
    ConfigStatus,
    ConfigDraft,
    ConfigApply,
    ConfigRollback,
    ChangeProposalsList,
    ChangeProposalsDetail,
    ChangeProposalsDraft,
    ChangeProposalsApply,
    EditionProposalsList,
    EditionProposalsDraft,
    EditionProposalsTransition,
    EditionProposalsMerge,
    EditionProposalsRollback,
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

/// Request-level constraints which must survive every operator forwarding path.
#[derive(Clone, Copy)]
pub(super) struct OperatorRequestContext<'a> {
    pub(super) dashboard_browser: bool,
    pub(super) scope_grant: Option<&'a ScopeGrant>,
}

pub(super) fn operator_route_kind(path: &str) -> OperatorRouteKind {
    match path {
        OPERATOR_API_PREFIX => OperatorRouteKind::Index,
        "/operator/v1/schema" => OperatorRouteKind::Schema,
        "/operator/v1/health" => OperatorRouteKind::Health,
        "/operator/v1/metrics" => OperatorRouteKind::Metrics,
        "/operator/v1/audit-tail" => OperatorRouteKind::AuditTail,
        "/operator/v1/active-lanes" => OperatorRouteKind::ActiveLanes,
        "/operator/v1/ci-lanes" => OperatorRouteKind::CiLanes,
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
        "/operator/v1/edition-proposals" => OperatorRouteKind::EditionProposalsList,
        "/operator/v1/edition-proposals/draft" => OperatorRouteKind::EditionProposalsDraft,
        "/operator/v1/edition-proposals/transition" => {
            OperatorRouteKind::EditionProposalsTransition
        }
        "/operator/v1/edition-proposals/merge" => OperatorRouteKind::EditionProposalsMerge,
        "/operator/v1/edition-proposals/rollback" => OperatorRouteKind::EditionProposalsRollback,
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
        // Single-segment proposal ids resolve to the by-id detail route. The
        // `draft`/`apply` sub-routes are matched exactly above, so they never
        // reach this guard.
        path if change_proposal_detail_id(path).is_some() => {
            OperatorRouteKind::ChangeProposalsDetail
        }
        _ => OperatorRouteKind::NotFound,
    }
}

const CHANGE_PROPOSAL_DETAIL_PREFIX: &str = "/operator/v1/change-proposals/";

/// Extract the proposal id from a `/operator/v1/change-proposals/{id}` detail
/// path, or `None` when `path` is not a single-segment detail route. The
/// `draft` and `apply` sub-routes own exact matches and are never ids, and a
/// value with an embedded `/` is rejected so the store never sees a multi-part
/// segment.
fn change_proposal_detail_id(path: &str) -> Option<&str> {
    let id = path.strip_prefix(CHANGE_PROPOSAL_DETAIL_PREFIX)?;
    if id.is_empty() || id.contains('/') || id == "draft" || id == "apply" {
        return None;
    }
    Some(id)
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
            | Self::EditionProposalsDraft
            | Self::EditionProposalsTransition
            | Self::EditionProposalsMerge
            | Self::EditionProposalsRollback
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

pub(super) fn handle_operator_api_route(
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    request: &HttpRequest,
    operator_subject: &AuditSubject,
    route: OperatorRouteKind,
    operator_audit_seq: u64,
    request_context: OperatorRequestContext<'_>,
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
        OperatorRouteKind::CiLanes => {
            operator_json_response(200, &request.path, operator_ci_lane_health_data(config))
        }
        OperatorRouteKind::LaneCancel => handle_operator_lane_cancel_route(config, request),
        OperatorRouteKind::Vsession => {
            operator_json_response(200, &request.path, operator_vsession_data())
        }
        OperatorRouteKind::Events => operator_events_response(config, request, operator_subject),
        OperatorRouteKind::ConfigStatus
        | OperatorRouteKind::ConfigDraft
        | OperatorRouteKind::ConfigApply
        | OperatorRouteKind::ConfigRollback => handle_operator_config_route(
            config,
            request,
            operator_subject,
            route,
            request_context.dashboard_browser,
        ),
        OperatorRouteKind::ChangeProposalsList
        | OperatorRouteKind::ChangeProposalsDetail
        | OperatorRouteKind::ChangeProposalsDraft
        | OperatorRouteKind::ChangeProposalsApply => handle_operator_change_proposal_route(
            server,
            config,
            request,
            operator_subject,
            route,
            operator_audit_seq,
            request_context,
        ),
        OperatorRouteKind::EditionProposalsList
        | OperatorRouteKind::EditionProposalsDraft
        | OperatorRouteKind::EditionProposalsTransition
        | OperatorRouteKind::EditionProposalsMerge
        | OperatorRouteKind::EditionProposalsRollback => handle_operator_edition_proposal_route(
            server,
            config,
            request,
            operator_subject,
            route,
            operator_audit_seq,
            request_context,
        ),
        OperatorRouteKind::SchemaDiff => handle_operator_schema_diff_route(request),
        OperatorRouteKind::SourceHistoryList | OperatorRouteKind::SourceHistoryRevert => {
            handle_operator_source_history_route(config, request, operator_subject, route)
        }
        OperatorRouteKind::ClientCredentials
        | OperatorRouteKind::ClientCredentialRotate
        | OperatorRouteKind::ClientCredentialRevoke => {
            handle_operator_client_credentials_route(server, config, request, route)
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
            request_context,
        ),
        OperatorRouteKind::NotFound => unreachable!("handled above"),
    }
}

pub(super) fn operator_json_response(status: u16, route: &str, data: Value) -> HttpResponse {
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
                "operator": 0,
                "doctor": 0,
                "regular_global_cap": DEFAULT_GLOBAL_HOST_CAP,
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
                "operator_reserved": 0,
                "doctor_reserved": 0,
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
                    "status": "not_applicable",
                    "reason": "control-plane work is admitted out of band and does not allocate Oracle lanes",
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
                    "name": "operator_doctor_worker_reserve",
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

pub(super) fn refresh_active_lane_metrics(config: &HttpTransportConfig) {
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
/// transport, never browser-supplied) and the request has a durable Pending
/// record from [`begin_operator_audit`] before dispatch; the caller appends the
/// correlated terminal outcome after this route returns.
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
    // Invalidate the whole MCP session, not just the lane. Remove the HTTP
    // session first (lane.rs requires the caller to drop the HTTP session before
    // the lane is closed), then its streaming replay buffer, then close the
    // dispatch session. Without this an operator "kill" left the MCP session id
    // and its buffered results usable — mirrors handle_mcp_delete's teardown.
    if let Some(store) = &config.session_store {
        store.remove(&binding.mcp_session_id);
    }
    if let Some(store) = &config.result_store {
        store.remove_session(&binding.mcp_session_id);
    }
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
    operator_subject: &AuditSubject,
    route: OperatorRouteKind,
    dashboard_browser: bool,
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

    let review_binding = if dashboard_browser {
        let Some(auth) = config.dashboard_auth.as_ref() else {
            return dashboard_auth_required_response();
        };
        match auth.session_binding(request.header("cookie")) {
            Ok(binding) => binding,
            Err(_) => return dashboard_auth_required_response(),
        }
    } else {
        format!(
            "operator:{}",
            operator_subject_id_hash(&operator_subject.legacy_agent_identity())
        )
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
        OperatorRouteKind::ConfigDraft => {
            match config_draft_toml_from_request(request).and_then(|draft| {
                config_ops
                    .stage_reviewed(&draft, &review_binding)
                    .map_err(config_error_value)
            }) {
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
            }
        }
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
            let Some(preview_token) = payload.get("preview_token").and_then(Value::as_str) else {
                return operator_json_response(
                    400,
                    &request.path,
                    missing_config_field("preview_token"),
                );
            };
            let Some(expected_draft_sha256) =
                payload.get("expected_draft_sha256").and_then(Value::as_str)
            else {
                return operator_json_response(
                    400,
                    &request.path,
                    missing_config_field("expected_draft_sha256"),
                );
            };
            let confirmed = payload
                .get("confirm_preview")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            match config_ops.apply_reviewed(
                draft,
                expected_draft_sha256,
                preview_token,
                &review_binding,
                confirmed,
            ) {
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
    request_context: OperatorRequestContext<'_>,
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
        OperatorRouteKind::ChangeProposalsList => {
            let etag = match store.etag() {
                Ok(etag) => etag,
                Err(error) => {
                    return operator_change_proposal_error_response(&request.path, error);
                }
            };
            // A polling board revalidates with the last-seen validator; an
            // unchanged store answers 304 with the ETag and no body.
            if request.header("if-none-match") == Some(etag.as_str()) {
                return empty_response(304).with_header("etag", &etag);
            }
            match store.list_page(request.query_param("cursor")) {
                Ok(page) => operator_json_response(
                    200,
                    &request.path,
                    json!({
                        "source": "change_proposals",
                        "proposals": page.proposals,
                        "nextCursor": page.next_cursor,
                    }),
                )
                .with_header("etag", &page.etag),
                Err(error) => operator_change_proposal_error_response(&request.path, error),
            }
        }
        OperatorRouteKind::ChangeProposalsDetail => {
            let Some(id) = change_proposal_detail_id(&request.path) else {
                return operator_not_found_response(request);
            };
            // The detail view carries the full sql_template bodies the list
            // projection omits; the board fetches it on selection.
            match store.detail(id) {
                Ok(proposal) => operator_json_response(
                    200,
                    &request.path,
                    json!({
                        "source": "change_proposals",
                        "proposal": proposal,
                    }),
                ),
                Err(error) => operator_change_proposal_error_response(&request.path, error),
            }
        }
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
                dashboard_browser: request_context.dashboard_browser,
                scope_grant: request_context.scope_grant,
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

/// Handle the Edition-Based Redefinition request board.
///
/// The stored proposal remains review metadata, never executable authority.
/// The two lifecycle endpoints below derive a fixed statement from validated
/// metadata, classify it again at the moment of the request, and forward it
/// only through the normal guarded `oracle_execute` confirmation path.
fn handle_operator_edition_proposal_route(
    server: &OracleMcpServer,
    config: &HttpTransportConfig,
    request: &HttpRequest,
    operator_subject: &AuditSubject,
    route: OperatorRouteKind,
    operator_audit_seq: u64,
    request_context: OperatorRequestContext<'_>,
) -> HttpResponse {
    let Some(store) = config.change_proposals.as_ref() else {
        return operator_json_response(
            503,
            &request.path,
            json!({
                "source": "edition_proposals",
                "error": "edition_proposals_unavailable",
                "message": "edition proposal store is not configured for this transport",
            }),
        );
    };

    match route {
        OperatorRouteKind::EditionProposalsList => match store.list_edition_proposals() {
            Ok(proposals) => operator_json_response(
                200,
                &request.path,
                json!({
                    "source": "edition_proposals",
                    "proposals": proposals,
                }),
            ),
            Err(error) => operator_edition_proposal_error_response(&request.path, error),
        },
        OperatorRouteKind::EditionProposalsDraft => {
            if !content_type_is_json(request) {
                return empty_response(415);
            }
            let draft = match serde_json::from_slice::<EditionProposalCreateRequest>(&request.body)
            {
                Ok(draft) => draft,
                Err(_) => {
                    return operator_json_response(
                        400,
                        &request.path,
                        json!({
                            "source": "edition_proposals",
                            "error": "invalid_edition_proposal",
                            "message": "edition proposal draft body must be a request without SQL or execution fields",
                        }),
                    );
                }
            };
            match store.create_edition_proposal(draft) {
                Ok(proposal) => operator_json_response(
                    200,
                    &request.path,
                    json!({
                        "source": "edition_proposals",
                        "status": "requested",
                        "proposal": proposal,
                        "authority": "request_only",
                    }),
                ),
                Err(error) => operator_edition_proposal_error_response(&request.path, error),
            }
        }
        OperatorRouteKind::EditionProposalsTransition => {
            if !content_type_is_json(request) {
                return empty_response(415);
            }
            let transition = match serde_json::from_slice::<EditionProposalTransitionRequest>(
                &request.body,
            ) {
                Ok(transition) => transition,
                Err(_) => {
                    return operator_json_response(
                        400,
                        &request.path,
                        json!({
                            "source": "edition_proposals",
                            "error": "invalid_edition_proposal_transition",
                            "message": "edition proposal transition body must contain only proposal_id and a non-authorizing status",
                        }),
                    );
                }
            };
            match store.transition_edition_proposal(transition) {
                Ok(proposal) => operator_json_response(
                    200,
                    &request.path,
                    json!({
                        "source": "edition_proposals",
                        "status": "transitioned",
                        "proposal": proposal,
                        "authority": "request_only",
                    }),
                ),
                Err(error) => operator_edition_proposal_error_response(&request.path, error),
            }
        }
        OperatorRouteKind::EditionProposalsMerge | OperatorRouteKind::EditionProposalsRollback => {
            let context = ChangeProposalApplyContext {
                server,
                config,
                original_request: request,
                operator_subject,
                operator_audit_seq,
                dashboard_browser: request_context.dashboard_browser,
                scope_grant: request_context.scope_grant,
            };
            let flip = if route == OperatorRouteKind::EditionProposalsMerge {
                EditionDefaultFlip::Merge
            } else {
                EditionDefaultFlip::Rollback
            };
            handle_operator_edition_default_flip(&context, store, flip)
        }
        _ => unreachable!("non-edition-proposal route"),
    }
}

/// The only two database-wide default-edition operations exposed by the board.
/// The target is selected from persisted, validated metadata; callers cannot
/// supply arbitrary SQL or an alternative edition identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EditionDefaultFlip {
    Merge,
    Rollback,
}

impl EditionDefaultFlip {
    fn action(self) -> &'static str {
        match self {
            Self::Merge => "merge",
            Self::Rollback => "rollback",
        }
    }

    fn target_edition(self, proposal: &EditionProposal) -> &str {
        match self {
            Self::Merge => &proposal.child_edition,
            Self::Rollback => &proposal.base_edition,
        }
    }
}

/// Transient, caller-supplied input for an ADMIN default-edition flip.
///
/// `deny_unknown_fields` is deliberate: SQL, a stored verdict, a replacement
/// target, and an execution switch are all rejected rather than becoming an
/// alternate authorization path around the persisted review request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EditionProposalFlipRequest {
    proposal_id: String,
    #[serde(default)]
    lane_id: Option<String>,
    #[serde(default)]
    confirm: Option<String>,
    #[serde(default)]
    idempotency_key: Option<String>,
}

/// Merge to a proposal child, or re-flip to its base edition.
///
/// This handler is intentionally not an executor.  It refuses unsafe review
/// state locally, reclassifies the canonical SQL from scratch, then delegates
/// profile ceilings, protected/read-only profiles, the ADMIN elevation window,
/// and one-use confirmation-token validation to the same `oracle_execute`
/// dispatch path used by every other privileged operation.
fn handle_operator_edition_default_flip(
    context: &ChangeProposalApplyContext<'_>,
    store: &crate::change_proposal::ChangeProposalStore,
    flip: EditionDefaultFlip,
) -> HttpResponse {
    if !content_type_is_json(context.original_request) {
        return empty_response(415);
    }
    let apply = match serde_json::from_slice::<EditionProposalFlipRequest>(
        &context.original_request.body,
    ) {
        Ok(apply) => apply,
        Err(_) => {
            return operator_json_response(
                400,
                &context.original_request.path,
                json!({
                    "source": "edition_proposals",
                    "error": "invalid_edition_default_flip",
                    "message": "edition merge or rollback accepts only proposal_id, lane_id, confirmation, and idempotency_key",
                }),
            );
        }
    };
    let proposal = match store.edition_proposal(&apply.proposal_id) {
        Ok(proposal) => proposal,
        Err(error) => {
            return operator_edition_proposal_error_response(&context.original_request.path, error);
        }
    };
    if proposal.status != EditionProposalStatus::Reviewing {
        return operator_json_response(
            409,
            &context.original_request.path,
            json!({
                "source": "edition_proposals",
                "error": "edition_proposal_not_reviewed",
                "message": "default-edition changes require a separately reviewed proposal",
                "proposal_id": proposal.proposal_id,
            }),
        );
    }
    let conflict = match store.active_edition_branch_conflict(&proposal) {
        Ok(conflict) => conflict,
        Err(error) => {
            return operator_edition_proposal_error_response(&context.original_request.path, error);
        }
    };
    if conflict.is_some() {
        return operator_json_response(
            409,
            &context.original_request.path,
            json!({
                "source": "edition_proposals",
                "error": "edition_linear_chain_required",
                "message": "edition default change refused: the reviewed board has a competing active child for this base; Oracle editions are a linear chain, not a branch graph (ORA-38807)",
                "proposal_id": proposal.proposal_id,
            }),
        );
    }

    // SEC-1: the review record has no verdict and is never treated as one.  A
    // new classifier decision is required for the exact canonical statement on
    // every merge and rollback request.  The live dispatch repeats this with
    // the active lane policy before Oracle can see the statement.
    let target_edition = flip.target_edition(&proposal);
    let sql = format!("ALTER DATABASE DEFAULT EDITION = {target_edition}");
    let decision = Classifier::default().classify(&sql);
    if decision.required_level != Some(OperatingLevel::Admin) {
        return operator_json_response(
            409,
            &context.original_request.path,
            json!({
                "source": "edition_proposals",
                "error": "edition_default_classifier_refused",
                "message": "default-edition change was not proven to require ADMIN by the current classifier; refusing rather than falling through",
                "proposal_id": proposal.proposal_id,
            }),
        );
    }
    let Some(confirm) = apply
        .confirm
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return operator_json_response(
            409,
            &context.original_request.path,
            json!({
                "source": "edition_proposals",
                "error": "edition_default_confirmation_required",
                "message": "database-wide default-edition changes require an ADMIN preview confirmation; this endpoint never performs a bare execution",
                "proposal_id": proposal.proposal_id,
                "required_level": OperatingLevel::Admin,
                "next_step": "obtain an oracle_preview_sql confirmation for this proposal's canonical ALTER DATABASE DEFAULT EDITION statement, then resubmit it here",
            }),
        );
    };

    let key_prefix = apply
        .idempotency_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("edition-default-flip");
    let response = forward_operator_action(
        context,
        OperatorActionForward {
            idempotency_key: format!("{key_prefix}:{}:{}", flip.action(), proposal.proposal_id),
            lane_id: apply.lane_id.as_deref(),
            tool: "oracle_execute",
            arguments: json!({
                "sql": sql.as_str(),
                "binds": [],
                "commit": true,
                "confirm": confirm,
                "capture_dbms_output": false,
            }),
        },
    );
    let action_body: Value = serde_json::from_slice(&response.body).unwrap_or_else(|_| {
        json!({
            "error": "invalid_operator_action_response",
            "message": "guarded default-edition action response was not valid JSON",
        })
    });
    let mcp_response = action_body
        .pointer("/data/mcp_response")
        .cloned()
        .unwrap_or(action_body);
    let action_failed = operator_action_response_failed(
        response.status,
        &json!({
            "data": { "mcp_response": &mcp_response }
        }),
    );
    let rollback_scope = (flip == EditionDefaultFlip::Rollback).then(|| {
        json!({
            "changes_default_edition_for": "new_sessions_only",
            "not_a_global_instant_undo": true,
            "cannot_restore": [
                "autonomous transaction effects",
                "sequence increments",
                "trigger side effects"
            ],
        })
    });
    operator_json_response(
        response.status,
        &context.original_request.path,
        json!({
            "source": "edition_proposals",
            "status": if action_failed { "refused" } else { "forwarded" },
            "action": flip.action(),
            "proposal": proposal.view(),
            "target_edition": target_edition,
            "sql_sha256": prefixed_sha256_hex(sql.as_bytes()),
            "reclassified": {
                "required_level": decision.required_level,
                "danger": decision.danger,
                "stored_proposal_is_authority": false,
                "live_dispatch_reclassifies": true,
            },
            "mcp_response": mcp_response,
            "rollback_scope": rollback_scope,
        }),
    )
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
    scope_grant: Option<&'a ScopeGrant>,
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
        OperatorRequestContext {
            dashboard_browser: context.dashboard_browser,
            scope_grant: context.scope_grant,
        },
    )
}

pub(super) struct CurrentSourceDocument {
    owner: String,
    owner_quoted: bool,
    name: String,
    name_quoted: bool,
    object_type: String,
    target_identity_sha256: String,
    source_kind: String,
    source: String,
}

pub(super) enum SourceSnapshotFetchOutcome {
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
        owner_quoted: document.owner_quoted,
        name: document.name,
        name_quoted: document.name_quoted,
        object_type: document.object_type,
        target_identity_sha256: document.target_identity_sha256,
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
    if let Some(owner) = target.owner_lookup() {
        arguments.insert("owner".to_owned(), json!(owner));
    }
    arguments.insert("name".to_owned(), json!(target.name_lookup()));
    arguments.insert("owner_quoted".to_owned(), json!(target.owner_quoted));
    arguments.insert("name_quoted".to_owned(), json!(target.name_quoted));
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
    current_source_document(
        target,
        "VIEW",
        structured
            .get("owner")
            .and_then(Value::as_str)
            .or(target.owner.as_deref())
            .unwrap_or_default(),
        structured
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(&target.name),
        "VIEW",
        "dbms_metadata",
        source,
    )
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
    current_source_document(
        target,
        object_type,
        source
            .get("owner")
            .and_then(Value::as_str)
            .or(target.owner.as_deref())
            .unwrap_or_default(),
        source
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or(&target.name),
        source
            .get("object_type")
            .and_then(Value::as_str)
            .unwrap_or(object_type),
        "all_source",
        &create_or_replace_ddl_for_source(text),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn current_source_document(
    target: &SourceObjectTarget,
    expected_object_type: &str,
    owner: &str,
    name: &str,
    object_type: &str,
    source_kind: &str,
    source: &str,
) -> SourceSnapshotFetchOutcome {
    let Some(object_type) = normalize_source_object_type(object_type) else {
        return source_identity_mismatch(target, expected_object_type, owner, name, object_type);
    };
    let source_target = source_object_from_create_or_replace_sql(source);
    let expected_identity_sha256 = target.identity_sha256(owner);
    let actual_identity_sha256 = source_identity_sha256(owner, name, &object_type);
    let metadata_matches = !owner.is_empty()
        && !name.is_empty()
        && object_type == expected_object_type
        && target
            .owner
            .as_deref()
            .is_none_or(|expected_owner| expected_owner == owner)
        && target.name == name
        && expected_identity_sha256 == actual_identity_sha256;
    let source_matches = source_target.as_ref().is_some_and(|source_target| {
        source_target.object_type == target.object_type
            && source_target.name == target.name
            && match (source_target.owner.as_deref(), target.owner.as_deref()) {
                (Some(source_owner), Some(target_owner)) => source_owner == target_owner,
                (None, _) => true,
                (Some(_), None) => false,
            }
    });
    if !metadata_matches || !source_matches {
        return source_identity_mismatch(target, expected_object_type, owner, name, &object_type);
    }
    SourceSnapshotFetchOutcome::Document(CurrentSourceDocument {
        owner: owner.to_owned(),
        owner_quoted: target.owner_quoted,
        name: name.to_owned(),
        name_quoted: target.name_quoted,
        object_type,
        target_identity_sha256: actual_identity_sha256,
        source_kind: source_kind.to_owned(),
        source: source.to_owned(),
    })
}

fn source_identity_mismatch(
    target: &SourceObjectTarget,
    object_type: &str,
    owner: &str,
    name: &str,
    actual_object_type: &str,
) -> SourceSnapshotFetchOutcome {
    SourceSnapshotFetchOutcome::Skipped(json!({
        "status": "skipped",
        "reason": "source fetch target identity did not match apply target",
        "expected_object": source_target_json(target, object_type),
        "expected_identity_sha256": target.identity_sha256(owner),
        "actual_object": {
            "owner": owner,
            "name": name,
            "object_type": actual_object_type,
        },
        "actual_identity_sha256": source_identity_sha256(owner, name, actual_object_type),
    }))
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
        "owner_quoted": target.owner_quoted,
        "name": target.name.as_str(),
        "name_quoted": target.name_quoted,
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
        ChangeProposalError::UnknownEditionProposal => (404, "unknown_edition_proposal"),
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

fn operator_edition_proposal_error_response(
    route: &str,
    error: ChangeProposalError,
) -> HttpResponse {
    let (status, code) = match &error {
        ChangeProposalError::Invalid(_) => (400, "invalid_edition_proposal"),
        ChangeProposalError::UnknownEditionProposal => (404, "unknown_edition_proposal"),
        ChangeProposalError::UnknownProposal => (404, "unknown_edition_proposal"),
        ChangeProposalError::FileStore(FileStoreError::InvalidSegment { .. }) => {
            (400, "invalid_edition_proposal")
        }
        ChangeProposalError::FileStore(FileStoreError::Locked) => {
            (409, "edition_proposal_store_locked")
        }
        ChangeProposalError::FileStore(_)
        | ChangeProposalError::Io(_)
        | ChangeProposalError::Json(_) => (500, "edition_proposal_store_failed"),
    };
    operator_json_response(
        status,
        route,
        json!({
            "source": "edition_proposals",
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
            let etag = match history.etag() {
                Ok(etag) => etag,
                Err(error) => {
                    return operator_source_history_error_response(&request.path, error);
                }
            };
            if request.header("if-none-match") == Some(etag.as_str()) {
                return empty_response(304).with_header("etag", &etag);
            }
            match history.list_page(
                source_history_filter_from_request(request),
                request.query_param("cursor"),
            ) {
                Ok(page) => operator_json_response(
                    200,
                    &request.path,
                    json!({
                        "source": "source_history",
                        "snapshots": page.snapshots,
                        "nextCursor": page.next_cursor,
                        "redaction": "source text is omitted from history list responses",
                    }),
                )
                .with_header("etag", &page.etag),
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
    server: &OracleMcpServer,
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
                        server,
                        config,
                        &lifecycle.principal_key,
                        DispatchCloseReason::SessionDelete,
                        Some(lifecycle.generation),
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
                            "durability": issued.durability.as_str(),
                            "durability_warning": issued.durability.warning(),
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
                        server,
                        config,
                        &lifecycle.principal_key,
                        DispatchCloseReason::SessionDelete,
                        Some(lifecycle.generation),
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
                            "durability": lifecycle.durability.as_str(),
                            "durability_warning": lifecycle.durability.warning(),
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
        "durability": lifecycle.durability.as_str(),
        "durability_warning": lifecycle.durability.warning(),
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
        | ClientCredentialError::PersistenceUncertain
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
        ConfigOpsError::PreviewRequired => (
            400,
            json!({
                "error": "config_preview_required",
                "message": "apply requires a live reviewed config preview",
            }),
        ),
        ConfigOpsError::InvalidPreviewToken
        | ConfigOpsError::PreviewExpired
        | ConfigOpsError::PreviewDraftChanged => (
            409,
            json!({
                "error": "config_preview_invalid",
                "message": "the reviewed config preview is invalid, expired, consumed, or no longer matches",
                "next_step": "preview the current draft again before applying",
            }),
        ),
        ConfigOpsError::PreviewConfirmationRequired => (
            409,
            json!({
                "error": "config_preview_confirmation_required",
                "message": "this reviewed config change requires explicit confirmation",
                "next_step": "review the redacted reasons and resubmit with confirm_preview=true",
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
        let persisted: Value =
            serde_json::from_str(&line).map_err(|e| format!("audit tail parse failed: {e}"))?;
        let record: AuditRecord = serde_json::from_value(persisted.clone())
            .map_err(|e| format!("audit tail parse failed: {e}"))?;
        // A certificate is evidence only when the persisted, response-side
        // binding and the signed record's core hash both agree. A forged or
        // malformed sidecar is omitted rather than projected as a proof.
        let certificate = persisted
            .get("verdict_certificate")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
            .filter(
                |certificate: &oraclemcp_audit::BoundAuditVerdictCertificate| {
                    certificate.matches_record(&record)
                },
            );
        proof.observe(&record, line_index);
        scanned_records += 1;
        if !query.matches(&record) {
            continue;
        }
        selected_records += 1;
        if tail.len() == query.limit {
            tail.pop_front();
        }
        tail.push_back(redacted_audit_record(&record, certificate.as_ref()));
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

pub(super) fn redacted_audit_record(
    record: &AuditRecord,
    certificate: Option<&oraclemcp_audit::BoundAuditVerdictCertificate>,
) -> Value {
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
        "correlation": record.correlation,
        "rows_affected": record.rows_affected,
        "observed_scn": record.observed_scn,
        "sql_sha256": record.sql_sha256,
        "sql_normalized_sha256": record.sql_normalized_sha256,
        "verdict_certificate": certificate,
        "verdict_certificate_core_hash": certificate
            .and(record.verdict_certificate_core_hash.as_deref()),
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
    // A specific lane_id must name a currently active lane; only the default
    // aggregate stream is always valid. This bounds the event-stream key space to
    // the active lanes so a caller cannot mint unbounded distinct streams from
    // attacker-chosen lane ids.
    if lane_id != OPERATOR_AGGREGATE_LANE
        && !active_lanes["lanes"].as_array().is_some_and(|lanes| {
            lanes
                .iter()
                .any(|lane| lane.get("lane_id").and_then(Value::as_str) == Some(lane_id.as_str()))
        })
    {
        return operator_json_response(
            404,
            &request.path,
            json!({
                "error": "operator_lane_not_active",
                "message": "requested lane_id is not an active lane",
                "lane_id": lane_id,
            }),
        );
    }
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
        .unwrap_or(OPERATOR_AGGREGATE_LANE)
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
            data: Arc::new(gap_event),
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
    request_context: OperatorRequestContext<'_>,
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
    if request_context.dashboard_browser
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
    let mut context = request_context
        .scope_grant
        .map(DispatchContext::with_scope_grant)
        .unwrap_or_default();
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
    let response = match server.handle_jsonrpc_request_with_context_outcome(rpc, None, context) {
        Outcome::Ok(response) => response,
        Outcome::Err(error) => Some(error.into_response()),
        Outcome::Cancelled(reason) => {
            let response = dispatch_cancelled_response(&reason);
            let completed_facts = idempotency_facts.completed(audit_timestamp());
            return config.operator_idempotency.complete(
                idempotency_lease,
                completed_facts,
                response,
            );
        }
        Outcome::Panicked(payload) => {
            let response = dispatch_panicked_response(&payload);
            let completed_facts = idempotency_facts.completed(audit_timestamp());
            return config.operator_idempotency.complete(
                idempotency_lease,
                completed_facts,
                response,
            );
        }
    };
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

pub(super) fn dashboard_workbench_release_gate(
    route: OperatorRouteKind,
    tool: &str,
    arguments: &Value,
) -> Option<Value> {
    if !matches!(
        route,
        OperatorRouteKind::ActionConfirm | OperatorRouteKind::ActionExecute
    ) {
        return None;
    }
    let Some(policy) = operator_action_tool_policy(tool) else {
        return Some(json!({
            "error": "dashboard_action_policy_missing",
            "message": "browser action has no explicit release policy and was refused before dispatch",
            "tool": tool,
        }));
    };
    let required_level = match policy.browser_apply {
        BrowserApplyPolicy::Allow => return None,
        BrowserApplyPolicy::DdlMutation => Some(oraclemcp_guard::OperatingLevel::Ddl),
        BrowserApplyPolicy::ClassifySql => {
            let Some(sql) = ["sql", "ddl", "source_code"]
                .into_iter()
                .find_map(|key| arguments.get(key).and_then(Value::as_str))
            else {
                return Some(json!({
                    "error": "dashboard_action_policy_unresolved",
                    "message": "browser SQL action could not be classified and was refused before dispatch",
                    "tool": tool,
                }));
            };
            oraclemcp_guard::Classifier::default()
                .classify(sql)
                .required_level
        }
    };
    if required_level.is_some_and(|level| level >= oraclemcp_guard::OperatingLevel::Ddl) {
        Some(json!({
            "error": "dashboard_ddl_workbench_disabled",
            "message": "browser dashboard DDL/Admin apply is release-gated; preview remains available",
            "tool": tool,
            "required_level": required_level,
            "next_step": "use /operator/v1/actions/preview to inspect the action, or use a non-browser operator path with the normal profile ceiling",
        }))
    } else {
        None
    }
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

pub(super) struct OperatorIdempotencyInput<'a> {
    pub(super) request: &'a HttpRequest,
    pub(super) payload: &'a serde_json::Map<String, Value>,
    pub(super) operator_subject: &'a AuditSubject,
    pub(super) route: OperatorRouteKind,
    pub(super) tool: &'a str,
    pub(super) arguments: &'a Value,
    pub(super) binding: Option<&'a HttpLaneBinding>,
    pub(super) operator_audit_seq: u64,
}

pub(super) fn operator_idempotency_facts(
    input: OperatorIdempotencyInput<'_>,
) -> OperatorIdempotencyFacts {
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

pub(super) fn prefixed_sha256_hex(bytes: &[u8]) -> String {
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

const ACTION_PREVIEW_POLICY: u8 = 1;
const ACTION_CONFIRM_POLICY: u8 = 2;
const ACTION_EXECUTE_POLICY: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BrowserApplyPolicy {
    Allow,
    ClassifySql,
    DdlMutation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct OperatorActionToolPolicy {
    pub(super) tool: &'static str,
    pub(super) routes: u8,
    pub(super) browser_apply: BrowserApplyPolicy,
}

impl OperatorActionToolPolicy {
    pub(super) fn allows(self, route: OperatorRouteKind) -> bool {
        let flag = match route {
            OperatorRouteKind::ActionPreview => ACTION_PREVIEW_POLICY,
            OperatorRouteKind::ActionConfirm => ACTION_CONFIRM_POLICY,
            OperatorRouteKind::ActionExecute => ACTION_EXECUTE_POLICY,
            _ => return false,
        };
        self.routes & flag != 0
    }
}

pub(super) const OPERATOR_ACTION_TOOL_POLICIES: &[OperatorActionToolPolicy] = &[
    OperatorActionToolPolicy {
        tool: "oracle_preview_sql",
        routes: ACTION_PREVIEW_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_execute",
        routes: ACTION_CONFIRM_POLICY | ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::ClassifySql,
    },
    OperatorActionToolPolicy {
        tool: "oracle_set_session_level",
        routes: ACTION_PREVIEW_POLICY | ACTION_CONFIRM_POLICY | ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_compile_object",
        routes: ACTION_PREVIEW_POLICY | ACTION_CONFIRM_POLICY | ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::DdlMutation,
    },
    OperatorActionToolPolicy {
        tool: "oracle_create_or_replace",
        routes: ACTION_PREVIEW_POLICY | ACTION_CONFIRM_POLICY | ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::DdlMutation,
    },
    OperatorActionToolPolicy {
        tool: "oracle_patch_source",
        routes: ACTION_PREVIEW_POLICY | ACTION_CONFIRM_POLICY | ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::DdlMutation,
    },
    OperatorActionToolPolicy {
        tool: "oracle_connection_info",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_list_schemas",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_search_objects",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_search_source",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_capabilities",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_get_ddl",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_get_source",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_query",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_plsql_parse",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_plsql_analyze",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_plsql_what_breaks",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_plsql_lineage",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_plsql_sast",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
    OperatorActionToolPolicy {
        tool: "oracle_plsql_doc",
        routes: ACTION_EXECUTE_POLICY,
        browser_apply: BrowserApplyPolicy::Allow,
    },
];

pub(super) fn operator_action_tool_policy(tool: &str) -> Option<OperatorActionToolPolicy> {
    OPERATOR_ACTION_TOOL_POLICIES
        .iter()
        .copied()
        .find(|policy| policy.tool == tool)
}

fn allowed_operator_action_tool(route: OperatorRouteKind, tool: &str) -> Option<&'static str> {
    operator_action_tool_policy(tool)
        .filter(|policy| policy.allows(route))
        .map(|policy| policy.tool)
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
