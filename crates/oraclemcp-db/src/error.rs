//! The DB-layer error type, distinct from the engine's `CatalogError`.
//!
//! Kept independent so `oraclemcp-db` never depends on a `plsql-*` engine crate
//! (the one-way boundary, §0). [`DbError::into_envelope`] renders the
//! agent-facing [`ErrorEnvelope`] via the shared `oraclemcp-error` classifier.

use std::time::Duration;

pub use oraclemcp_error::StatementOutcome;
use oraclemcp_error::{
    ErrorClass, ErrorEnvelope, OracleRetryAction, envelope_from_oracle_message,
    oracle_retry_action_from_message, parse_ora_code,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::OracleBackend;

/// Whether an Oracle error message has a driver-aligned retry action.
///
/// This compatibility helper keeps the core retry API stable while routing its
/// decision through the one shared taxonomy rather than a second code list.
#[must_use]
pub fn is_transient_error(message: &str) -> bool {
    !matches!(
        oracle_retry_action_from_message(message),
        OracleRetryAction::Never
    )
}

/// Retry policy for idempotent read operations.
///
/// The policy chooses whether another attempt is permitted; the caller still
/// owns the connection action from [`OracleRetryAction`] and must never replay
/// a mutation automatically.
#[derive(Clone, Copy, Debug)]
pub struct RetryPolicy {
    /// Maximum attempts, including the initial call.
    pub max_attempts: u32,
    /// Base backoff; attempt `n` waits `base * 2^(n-1)`.
    pub base_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
        }
    }
}

impl RetryPolicy {
    /// One immediate retry after the initial failed read.
    ///
    /// The stateless pool runs on a timer-less cooperative runtime, so this
    /// purpose-built policy yields once instead of waiting on a timer that
    /// could never wake. It is intentionally distinct from [`Self::default`]
    /// so callers that need exponential backoff retain that option.
    #[must_use]
    pub const fn one_immediate_retry() -> Self {
        Self {
            max_attempts: 2,
            base_delay: Duration::ZERO,
        }
    }

    /// The delay before the next attempt, or `None` when the request must not
    /// be retried.
    #[must_use]
    pub fn next_delay(
        &self,
        attempt: u32,
        mutating: bool,
        error_message: &str,
    ) -> Option<Duration> {
        self.next_delay_for_action(
            attempt,
            mutating,
            oracle_retry_action_from_message(error_message),
        )
    }

    /// The action-aware form used at the driver seam, where raw I/O failures
    /// have no `ORA-` code but the driver still proves a lost connection.
    #[must_use]
    pub fn next_delay_for_action(
        &self,
        attempt: u32,
        mutating: bool,
        action: OracleRetryAction,
    ) -> Option<Duration> {
        if mutating || attempt >= self.max_attempts || action == OracleRetryAction::Never {
            return None;
        }
        Some(self.base_delay * 2u32.pow(attempt.saturating_sub(1)))
    }
}

/// The known outcome class when a DB session is deliberately quarantined.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum QuarantineOutcome {
    /// Cleanup completed and the transactional work was rolled back.
    RolledBack,
    /// The session was discarded while uncommitted work may have existed.
    DiscardedUncommitted,
    /// A commit was sent but the client could not prove whether Oracle accepted it.
    CommitInDoubt,
    /// The session state is unknown; it was discarded and must not be reused.
    UnknownDiscarded,
}

impl From<QuarantineOutcome> for StatementOutcome {
    fn from(outcome: QuarantineOutcome) -> Self {
        match outcome {
            QuarantineOutcome::RolledBack => StatementOutcome::RolledBack,
            // No commit was sent, and Oracle rolls back a terminated session's
            // uncommitted work.
            QuarantineOutcome::DiscardedUncommitted => StatementOutcome::RolledBack,
            QuarantineOutcome::CommitInDoubt => StatementOutcome::CommitUnknown,
            QuarantineOutcome::UnknownDiscarded => StatementOutcome::ProtocolUnsynchronized,
        }
    }
}

/// What kind of statement an outcome belongs to, for the replay decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StatementClass {
    /// A read the guarded read executor admitted as provably read-only.
    /// Only that executor may produce this class; every other call site
    /// classifies as `Unknown` at best.
    ProvenIdempotentRead,
    /// DML or anything else that may change data.
    Mutation,
    /// DDL (auto-commits).
    Ddl,
    /// Session or transaction control (`ALTER SESSION`, `SET ROLE`, …).
    SessionControl,
    /// Not proven to be any of the above.
    Unknown,
}

/// Whether a failed statement may be retried automatically.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryDecision {
    /// Safe to run again automatically, on a fresh lease.
    AutoRetry,
    /// Never replay: return the typed outcome to the client.
    ReturnTyped,
}

/// The one place that decides automatic replay.
///
/// `NotStarted` is retried for every class because nothing reached Oracle.
/// Beyond that, only a proven idempotent read whose session desynchronised or
/// which already completed may run again (on a fresh lease). Every mutation,
/// DDL, session-control or unknown statement that may have reached Oracle
/// returns its typed outcome and is never replayed. Both matches are
/// exhaustive without a wildcard arm, so a new outcome or class does not
/// compile until it is classified here.
#[must_use]
pub fn retry_decision(outcome: StatementOutcome, class: StatementClass) -> RetryDecision {
    match outcome {
        StatementOutcome::NotStarted => RetryDecision::AutoRetry,
        StatementOutcome::CompletedRead | StatementOutcome::ProtocolUnsynchronized => match class {
            StatementClass::ProvenIdempotentRead => RetryDecision::AutoRetry,
            StatementClass::Mutation
            | StatementClass::Ddl
            | StatementClass::SessionControl
            | StatementClass::Unknown => RetryDecision::ReturnTyped,
        },
        StatementOutcome::RolledBack
        | StatementOutcome::Committed
        | StatementOutcome::CommitUnknown
        | StatementOutcome::DdlOutcomeUnknown => RetryDecision::ReturnTyped,
        // A future outcome must not silently become an automatic mutation retry.
        _ => RetryDecision::ReturnTyped,
    }
}

/// Machine-stable category for a flashback/AS-OF read refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FlashbackRefusalKind {
    /// The selected database/version does not expose `DBMS_FLASHBACK` to this
    /// profile (`PLS-00201`). Time-travel and SCN-diff requests must refuse;
    /// they must never silently become current reads.
    CapabilityUnavailable,
    /// Oracle no longer has enough undo/SCN mapping data for the requested
    /// target (`ORA-01555`, `ORA-08180`, `ORA-08186`).
    RetentionExceeded,
    /// The table/index definition changed after the requested target
    /// (`ORA-01466`).
    DefinitionChanged,
    /// Oracle cannot serve this object or route through flashback query.
    NotFlashbackable,
}

impl FlashbackRefusalKind {
    /// Stable, lower-case wire/log label for this refusal kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            FlashbackRefusalKind::CapabilityUnavailable => "capability_unavailable",
            FlashbackRefusalKind::RetentionExceeded => "retention_exceeded",
            FlashbackRefusalKind::DefinitionChanged => "definition_changed",
            FlashbackRefusalKind::NotFlashbackable => "not_flashbackable",
        }
    }

    /// Agent-facing error class paired with this flashback refusal kind.
    #[must_use]
    pub(crate) const fn error_class(self) -> ErrorClass {
        match self {
            FlashbackRefusalKind::CapabilityUnavailable => {
                ErrorClass::FlashbackCapabilityUnavailable
            }
            FlashbackRefusalKind::RetentionExceeded => ErrorClass::FlashbackRetentionExceeded,
            FlashbackRefusalKind::DefinitionChanged => ErrorClass::FlashbackDefinitionChanged,
            FlashbackRefusalKind::NotFlashbackable => ErrorClass::FlashbackNotFlashbackable,
        }
    }

    /// Short operator-facing explanation of the refusal.
    #[must_use]
    pub(crate) const fn summary(self) -> &'static str {
        match self {
            FlashbackRefusalKind::CapabilityUnavailable => {
                "the selected Oracle server version/profile does not expose the required DBMS_FLASHBACK capability"
            }
            FlashbackRefusalKind::RetentionExceeded => {
                "the requested flashback target is outside available retention"
            }
            FlashbackRefusalKind::DefinitionChanged => {
                "the object definition changed after the requested flashback target"
            }
            FlashbackRefusalKind::NotFlashbackable => {
                "the query references an object Oracle cannot serve through flashback"
            }
        }
    }

    /// Concrete recovery hints exposed in the error envelope.
    #[must_use]
    pub(crate) const fn next_steps(self) -> &'static [&'static str] {
        match self {
            FlashbackRefusalKind::CapabilityUnavailable => &[
                "use a profile whose Oracle server version exposes DBMS_FLASHBACK before retrying this time-travel or SCN-diff request",
                "retry without as_of/oracle_diff only if a current read is explicitly acceptable; this request was not silently degraded",
            ],
            FlashbackRefusalKind::RetentionExceeded => &[
                "retry with a newer SCN/timestamp inside the database undo/flashback retention window",
                "for future comparisons, record the current SCN before the change and use that observed_scn",
            ],
            FlashbackRefusalKind::DefinitionChanged => &[
                "retry with an SCN after the table or index DDL change",
                "split the comparison at the DDL boundary or compare against current metadata instead",
            ],
            FlashbackRefusalKind::NotFlashbackable => &[
                "remove the non-flashbackable object from the query or run the read directly on the source database",
                "retry without as_of/oracle_diff only if a current read is acceptable",
            ],
        }
    }
}

impl std::fmt::Display for FlashbackRefusalKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl QuarantineOutcome {
    /// Stable, lower-case wire/log label for this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            QuarantineOutcome::RolledBack => "rolled_back",
            QuarantineOutcome::DiscardedUncommitted => "discarded_uncommitted",
            QuarantineOutcome::CommitInDoubt => "commit_in_doubt",
            QuarantineOutcome::UnknownDiscarded => "unknown_discarded",
        }
    }
}

impl std::fmt::Display for QuarantineOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Structured classification of a driver connect/handshake failure.
///
/// Built **only** inside the driver-seam adapter (`connection.rs`), which is
/// the single place allowed to inspect the driver's error variants. Each kind
/// carries enough context to render a plain-language message plus concrete
/// `next_steps` — no raw driver string is ever surfaced without guidance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
#[non_exhaustive]
pub enum ConnectFailureKind {
    /// The server replied with an unexpected low-level TNS packet during the
    /// connect handshake (network layer, before any SQL).
    UnexpectedTnsPacket {
        /// The raw TNS packet type byte the server sent.
        packet_type: u8,
    },
    /// The listener kept demanding CONNECT resends and the driver gave up.
    ConnectResendLoop {
        /// How many resend rounds were attempted before giving up.
        rounds: u8,
    },
    /// Token/IAM authentication was requested but the server never advertised
    /// fast authentication (pre-23ai servers do not).
    FastAuthNotAdvertised,
    /// The server requires or negotiated a wire feature this pure-Rust thin
    /// build does not support (e.g. Native Network Encryption, pipelining).
    UnsupportedWireFeature {
        /// The feature named by the driver.
        feature: String,
    },
    /// The listener actively refused the connection with a TNS refuse packet.
    ListenerRefused {
        /// The `ERR=` code extracted from the refuse payload, when present.
        err_code: Option<u32>,
    },
    /// The listener redirected the connection; the thin driver does not
    /// follow TNS redirects.
    ListenerRedirectUnsupported,
    /// The server negotiated a TNS protocol generation below the thin
    /// driver's supported floor.
    ServerGenerationUnsupported {
        /// The TNS version the server offered, when known.
        tns_version: Option<u16>,
    },
    /// A connect-phase protocol failure with no more specific classification
    /// (framing/decode errors on the TNS/TTC layer during handshake).
    HandshakeProtocol,
}

impl ConnectFailureKind {
    /// Stable, grep-able class token, rendered as `[label]` in messages so
    /// operators, doctor, and log pipelines can match it without parsing
    /// free-form prose.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            ConnectFailureKind::UnexpectedTnsPacket { .. } => "unexpected-tns-packet",
            ConnectFailureKind::ConnectResendLoop { .. } => "connect-resend-loop",
            ConnectFailureKind::FastAuthNotAdvertised => "fast-auth-not-advertised",
            ConnectFailureKind::UnsupportedWireFeature { .. } => "unsupported-wire-feature",
            ConnectFailureKind::ListenerRefused { .. } => "listener-refused",
            ConnectFailureKind::ListenerRedirectUnsupported => "listener-redirect-unsupported",
            ConnectFailureKind::ServerGenerationUnsupported { .. } => {
                "server-generation-unsupported"
            }
            ConnectFailureKind::HandshakeProtocol => "handshake-protocol-error",
        }
    }

    /// Plain-language interpretation of the failure, naming the protocol
    /// phase honestly (the field bug this fixes: a network-layer TNS packet
    /// was misreported under an application-layer TTC name).
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            ConnectFailureKind::UnexpectedTnsPacket { packet_type } => format!(
                "the server replied with unexpected low-level TNS packet type {packet_type} \
                 during the connect handshake (network layer, before authentication) — the \
                 endpoint is not an Oracle listener, or speaks a protocol generation this \
                 driver does not recognise"
            ),
            ConnectFailureKind::ConnectResendLoop { rounds } => format!(
                "the listener kept demanding CONNECT resends ({rounds} rounds) and the driver \
                 gave up — usually a listener redirect loop or connect-data size problem"
            ),
            ConnectFailureKind::FastAuthNotAdvertised => "token/IAM authentication needs a \
                 server that advertises fast authentication, and this server does not \
                 (pre-23ai servers never do)"
                .to_owned(),
            ConnectFailureKind::UnsupportedWireFeature { feature } => format!(
                "the server requires `{feature}`, which this pure-Rust thin build does not \
                 support"
            ),
            ConnectFailureKind::ListenerRefused { err_code } => match err_code {
                Some(12514) => "the listener refused the connection (ERR=12514): it does not \
                     currently know the service name in the connect string — the service name \
                     is wrong, or the database has not (yet) registered it"
                    .to_owned(),
                Some(12505) => "the listener refused the connection (ERR=12505): it does not \
                     currently know the SID in the connect string"
                    .to_owned(),
                Some(code) => {
                    format!("the listener actively refused the connection (ERR={code})")
                }
                None => "the listener actively refused the connection".to_owned(),
            },
            ConnectFailureKind::ListenerRedirectUnsupported => "the listener redirected the \
                 connection to another endpoint; this thin driver does not follow TNS \
                 redirects"
                .to_owned(),
            ConnectFailureKind::ServerGenerationUnsupported { tns_version } => match tns_version {
                Some(version) => format!(
                    "the server negotiated TNS protocol version {version}, below the minimum \
                     this thin driver supports (300 = Oracle 12.1)"
                ),
                None => "the server's TNS protocol generation is below the minimum this thin \
                     driver supports (Oracle 12.1)"
                    .to_owned(),
            },
            ConnectFailureKind::HandshakeProtocol => "the TNS/TTC connect handshake failed at \
                 the protocol layer (wire framing/decode, not SQL)"
                .to_owned(),
        }
    }

    /// The `ORA-` code implied by this failure, when one is well-defined.
    #[must_use]
    pub const fn ora_code(&self) -> Option<i32> {
        match self {
            ConnectFailureKind::ListenerRefused {
                err_code: Some(code),
            } => Some(*code as i32),
            _ => None,
        }
    }
}

/// The standing next-step for protocol-level connect triage: how to capture a
/// driver handshake trace.
pub const CONNECT_TRACE_NEXT_STEP: &str = "capture a driver handshake trace for protocol-level \
     triage: set ORACLEDB_TRACE_CONNECT=1 in the server environment and reconnect (the trace \
     prints to stderr); attach it when reporting the issue";

/// An error from the Oracle connectivity layer.
#[derive(Clone, Debug, Error)]
#[non_exhaustive]
pub enum DbError {
    /// The requested backend was not compiled in.
    #[error("oracle backend `{backend}` not compiled")]
    BackendNotCompiled {
        /// The backend that was requested.
        backend: OracleBackend,
    },
    /// Opening the connection failed.
    #[error("oracle connect failed: {0}")]
    Connect(String),
    /// Opening the connection failed during the TNS/TTC handshake, with a
    /// structured classification from the driver-seam adapter.
    #[error("connect handshake failed [{}]: {}: {message}", kind.label(), kind.describe())]
    ConnectHandshake {
        /// The structured failure classification.
        kind: ConnectFailureKind,
        /// The sanitized driver detail (secrets redacted).
        message: String,
    },
    /// A query failed.
    #[error("oracle query failed: {0}")]
    Query(String),
    /// A server-composed query failed. Its SQL text is not caller input, so a
    /// parse error must not be attributed to the request arguments.
    #[error("server-owned Oracle query failed: {0}")]
    ServerQuery(String),
    /// A server-composed execute failed (for example an internal probe).
    #[error("server-owned Oracle execute failed: {0}")]
    ServerExecute(String),
    /// Request validation failed before SQL reached Oracle.
    #[error("invalid Oracle request argument: {0}")]
    InvalidArgument(String),
    /// The SQL guard refused a generated read. Preserve its structured
    /// envelope without flattening it into an internal database error.
    #[error("generated read refused: {}", .0.message)]
    Refused(Box<ErrorEnvelope>),
    /// Named bind names did not exactly match the SQL placeholders, so the
    /// driver was not called with values that could be positionally misbound.
    #[error("named bind mismatch: missing {missing:?}; unexpected {unexpected:?}")]
    NamedBindMismatch {
        /// Placeholders present in SQL but absent from the supplied bind list.
        missing: Vec<String>,
        /// Supplied bind names with no remaining matching placeholder.
        unexpected: Vec<String>,
    },
    /// The driver proved that the Oracle session/socket was lost. The pool must
    /// discard this connection before an idempotent read can be retried.
    #[error("Oracle connection lost: {0}")]
    ConnectionLost(String),
    /// The first row of a query page cannot fit within the configured compact
    /// row-payload byte budget. The row is not returned or skipped; callers may
    /// retry the same query/cursor after narrowing the selected payload.
    #[error(
        "query row at offset {row_offset} serializes to {row_bytes} bytes, exceeding the max_result_bytes row-payload cap of {max_result_bytes} bytes"
    )]
    QueryRowTooLarge {
        /// Zero-based query offset of the row that could not be represented.
        row_offset: usize,
        /// Compact JSON bytes required by the serialized row object.
        row_bytes: usize,
        /// Configured compact row-payload byte budget for this page.
        max_result_bytes: usize,
    },
    /// A DML/DDL execute failed.
    #[error("oracle execute failed: {0}")]
    Execute(String),
    /// A flashback/AS-OF read failed for a known, typed Oracle flashback
    /// limitation. This variant is constructed only by flashback read paths, so
    /// ordinary `ORA-01555` on a non-flashback long query is not mislabeled as a
    /// flashback retention refusal.
    #[error("oracle flashback refused ({kind}): {message}")]
    FlashbackRefusal {
        /// Machine-stable refusal kind.
        kind: FlashbackRefusalKind,
        /// Sanitized Oracle detail.
        message: String,
        /// Parsed originating ORA code, when present.
        ora_code: Option<i32>,
    },
    /// A pool operation failed (acquire timeout, build failure, …).
    #[error("connection pool error: {0}")]
    Pool(String),
    /// The request context was cancelled before or after a DB boundary.
    #[error("database call cancelled: {0}")]
    Cancelled(String),
    /// A database call exceeded its per-call timeout. The retry disposition is
    /// retained separately because one backend may drain and reuse its session
    /// while another must discard a session whose timeout recovery failed.
    #[error("Oracle {operation} call timed out")]
    CallTimeout {
        /// The connection operation that timed out (`query` or `execute`).
        operation: String,
        /// Backend-specific safe disposition after timeout recovery.
        retry_action: OracleRetryAction,
    },
    /// An auth mode is configured that this build cannot satisfy yet.
    #[error("unsupported auth mode: {0}")]
    UnsupportedAuth(String),
    /// A database feature is configured or requested that this backend cannot
    /// satisfy yet.
    #[error("unsupported database feature: {0}")]
    UnsupportedFeature(String),
    /// A session reached an uncertain lifecycle boundary and was quarantined.
    #[error("database session quarantined ({outcome}): {message}")]
    Quarantined {
        /// The safest known outcome class.
        outcome: QuarantineOutcome,
        /// Redacted operator-facing detail.
        message: String,
    },
    /// An internal error (e.g. a blocking task join failure).
    #[error("internal db error: {0}")]
    Internal(String),
}

impl DbError {
    /// Mark a query/execute failure as originating in SQL composed by this
    /// server. Other typed failures retain their existing classification.
    #[must_use]
    pub fn server_sql_origin(self) -> Self {
        match self {
            DbError::Query(message) => DbError::ServerQuery(message),
            DbError::Execute(message) => DbError::ServerExecute(message),
            other => other,
        }
    }

    /// Whether this error means the session state cannot be trusted for reuse.
    #[must_use]
    pub fn is_uncertain_session_state(&self) -> bool {
        match self {
            DbError::Cancelled(_)
            | DbError::Connect(_)
            | DbError::ConnectHandshake { .. }
            | DbError::ConnectionLost(_)
            | DbError::Pool(_)
            | DbError::Quarantined { .. } => true,
            DbError::CallTimeout { retry_action, .. } => {
                *retry_action == OracleRetryAction::ReconnectThenRetry
            }
            DbError::Query(message) | DbError::Execute(message) => {
                message_is_uncertain_connection_state(message)
            }
            DbError::ServerQuery(message) | DbError::ServerExecute(message) => {
                message_is_uncertain_connection_state(message)
            }
            _ => false,
        }
    }

    /// Whether this error requires a fresh Oracle connection before an
    /// idempotent read can be retried.
    #[must_use]
    pub fn is_connection_lost(&self) -> bool {
        self.retry_action() == OracleRetryAction::ReconnectThenRetry
    }

    /// The retry action the caller may consider for an idempotent read.
    #[must_use]
    pub fn retry_action(&self) -> OracleRetryAction {
        match self {
            DbError::ConnectionLost(_) => OracleRetryAction::ReconnectThenRetry,
            DbError::CallTimeout { retry_action, .. } => *retry_action,
            DbError::Query(message)
            | DbError::Execute(message)
            | DbError::ServerQuery(message)
            | DbError::ServerExecute(message) => {
                let action = oracle_retry_action_from_message(message);
                if action == OracleRetryAction::Never && raw_connection_lost_marker(message) {
                    OracleRetryAction::ReconnectThenRetry
                } else {
                    action
                }
            }
            _ => OracleRetryAction::Never,
        }
    }

    /// Render the agent-facing [`ErrorEnvelope`]. Oracle-originated errors are
    /// classified by their `ORA-` code via the shared classifier.
    #[must_use]
    pub fn into_envelope(self) -> ErrorEnvelope {
        match self {
            DbError::Connect(msg) => {
                // Classify via the embedded ORA- code where present.
                let env = oracle_error_envelope(&msg);
                if env.error_class == ErrorClass::Internal {
                    // No ORA- code recognised: keep it as a connection-class
                    // failure rather than a bare Internal. Driver transport
                    // detail is not an operator contract and may disclose
                    // socket internals, so never render it on a tool surface.
                    ErrorEnvelope::new(
                        ErrorClass::ConnectionFailed,
                        "Oracle connection failed; driver detail suppressed",
                    )
                        .with_next_step(
                            "verify the connect string (host, port, service name), credentials, \
                             and listener reachability",
                        )
                        .with_next_step(CONNECT_TRACE_NEXT_STEP)
                } else {
                    env
                }
            }
            DbError::ConnectHandshake { kind, message } => {
                connect_handshake_envelope(&kind, &message)
            }
            DbError::ServerQuery(msg) | DbError::ServerExecute(msg) => {
                server_sql_error_envelope(&msg)
            }
            DbError::Refused(envelope) => *envelope,
            DbError::InvalidArgument(msg) => {
                let mut envelope = ErrorEnvelope::new(ErrorClass::InvalidArguments, &msg);
                let lower = msg.to_ascii_lowercase();
                if lower.contains("unsupported ddl object type") {
                    envelope = envelope
                        .with_suggested_tool("oracle_get_ddl")
                        .with_next_step("use one of the object types supported by oracle_get_ddl");
                } else if lower.contains("unsupported source object type") {
                    envelope = envelope
                        .with_suggested_tool("oracle_get_source")
                        .with_next_step("use a supported source object type");
                } else if lower.contains("owner is required because current_schema") {
                    envelope = envelope
                        .with_suggested_tool("oracle_connection_info")
                        .with_next_step("supply an owner because the current schema could not be detected");
                }
                envelope
            }
            DbError::Query(msg) | DbError::Execute(msg) => {
                if raw_connection_lost_marker(&msg) {
                    return transport_lost_envelope(&msg);
                }
                // Classify via the embedded ORA- code where present.
                oracle_error_envelope(&msg)
            }
            DbError::NamedBindMismatch {
                missing,
                unexpected,
            } => ErrorEnvelope::new(
                ErrorClass::InvalidArguments,
                format!(
                    "named bind names must exactly match SQL placeholders; missing {missing:?}; unexpected {unexpected:?}"
                ),
            )
            .with_next_step("supply each named placeholder exactly once and remove unused bind names"),
            DbError::ConnectionLost(msg) => {
                let mut env = transport_lost_envelope(&msg);
                if let Some(code) = parse_ora_code(&msg) {
                    env = env.with_ora_code(code);
                }
                env
            }
            DbError::FlashbackRefusal {
                kind,
                message,
                ora_code,
            } => {
                let mut env = ErrorEnvelope::new(
                    kind.error_class(),
                    format!("flashback refused: {}; {message}", kind.summary()),
                );
                if let Some(code) = ora_code {
                    env = env.with_ora_code(code);
                }
                for step in kind.next_steps() {
                    env = env.with_next_step(*step);
                }
                env
            }
            DbError::QueryRowTooLarge {
                row_offset,
                row_bytes,
                max_result_bytes,
            } => ErrorEnvelope::new(
                ErrorClass::InvalidArguments,
                format!(
                    "query row at offset {row_offset} requires {row_bytes} compact JSON bytes, exceeding the max_result_bytes row-payload cap of {max_result_bytes} bytes"
                ),
            )
            .with_next_step(
                "retry the same query and cursor after selecting fewer columns or filtering out unneeded wide values",
            )
            .with_next_step(
                "lower max_col_width, max_lob_chars, or max_blob_bytes so each serialized row fits; use an export for larger bounded result delivery",
            ),
            DbError::BackendNotCompiled { backend } => ErrorEnvelope::new(
                ErrorClass::RuntimeStateRequired,
                format!("oracle backend `{backend}` not compiled into this build"),
            ),
            DbError::Pool(msg) => {
                ErrorEnvelope::new(ErrorClass::Busy, msg).with_retry_after_ms(250)
            }
            DbError::Cancelled(msg) => ErrorEnvelope::new(ErrorClass::Timeout, msg),
            DbError::CallTimeout { operation, .. } => ErrorEnvelope::new(
                ErrorClass::Transient,
                format!("Oracle {operation} call timed out"),
            ),
            DbError::UnsupportedAuth(msg) | DbError::UnsupportedFeature(msg) => {
                ErrorEnvelope::new(ErrorClass::InvalidArguments, msg)
            }
            DbError::Quarantined { outcome, message } => ErrorEnvelope::new(
                ErrorClass::ConnectionFailed,
                format!("database session quarantined ({outcome}): {message}"),
            )
            .with_next_step("discard this lease/session and acquire a fresh connection")
            .with_next_step(match outcome {
                QuarantineOutcome::CommitInDoubt => {
                    "verify the transaction outcome in Oracle before retrying any non-idempotent work"
                }
                _ => "do not reuse the quarantined session",
            }),
            DbError::Internal(msg) => ErrorEnvelope::new(ErrorClass::Internal, msg),
        }
    }
}

/// Map an Oracle error message that arose inside a flashback/AS-OF read path to
/// a typed refusal. The mapping is intentionally contextual: the same ORA code
/// can have broader meanings outside flashback and should remain a normal
/// Oracle error there.
#[must_use]
pub(crate) fn classify_flashback_refusal_message(
    message: &str,
) -> Option<(FlashbackRefusalKind, Option<i32>)> {
    let ora_code = parse_ora_code(message);
    let lower = message.to_ascii_lowercase();
    // PLS-00201 is reported beneath an ORA-06550 wrapper, so presenting that
    // wrapper as the root cause would be misleading. The missing
    // DBMS_FLASHBACK capability is the useful, version/profile-specific fact.
    if lower.contains("pls-00201") && lower.contains("dbms_flashback") {
        return Some((FlashbackRefusalKind::CapabilityUnavailable, None));
    }
    match ora_code {
        // Oracle returns ORA-08186 when `TIMESTAMP_TO_SCN` cannot map an
        // otherwise valid AS OF timestamp into retained history. This only
        // becomes a retention refusal on this contextual flashback path.
        Some(1555 | 8180 | 8186) => Some((FlashbackRefusalKind::RetentionExceeded, ora_code)),
        Some(1466) => Some((FlashbackRefusalKind::DefinitionChanged, ora_code)),
        Some(8182 | 8185 | 8187 | 8189..=8199) => {
            Some((FlashbackRefusalKind::NotFlashbackable, ora_code))
        }
        Some(2070) if message.to_ascii_lowercase().contains("flashback") => {
            Some((FlashbackRefusalKind::NotFlashbackable, ora_code))
        }
        _ => {
            if lower.contains("cannot perform a flashback query")
                || lower.contains("not flashbackable")
                || lower.contains("non-flashbackable")
            {
                Some((FlashbackRefusalKind::NotFlashbackable, ora_code))
            } else {
                None
            }
        }
    }
}

/// Render the agent-facing envelope for a classified connect/handshake
/// failure: a plain-language message headed by the stable `[label]` token,
/// the implied `ORA-` code when well-defined, and concrete `next_steps` for
/// every class — a raw driver string never travels without guidance.
fn connect_handshake_envelope(kind: &ConnectFailureKind, detail: &str) -> ErrorEnvelope {
    let class = match kind {
        // Server/config capability mismatches: retrying cannot help, the
        // profile or the server has to change.
        ConnectFailureKind::FastAuthNotAdvertised
        | ConnectFailureKind::UnsupportedWireFeature { .. }
        | ConnectFailureKind::ServerGenerationUnsupported { .. } => ErrorClass::InvalidArguments,
        _ => ErrorClass::ConnectionFailed,
    };
    let message = format!(
        "connect handshake failed [{}]: {}: {detail}",
        kind.label(),
        kind.describe()
    );
    let mut env = ErrorEnvelope::new(class, message);
    if let Some(code) = kind.ora_code() {
        env = env.with_ora_code(code);
    }
    match kind {
        ConnectFailureKind::UnexpectedTnsPacket { .. } => env
            .with_next_step(
                "verify the host:port in the connect string points at an Oracle listener and \
                 not another service",
            )
            .with_next_step(CONNECT_TRACE_NEXT_STEP),
        ConnectFailureKind::ConnectResendLoop { .. } => env
            .with_next_step(
                "check the listener log for redirect loops and retry; shorten the connect data \
                 (long service names / descriptors) if the loop persists",
            )
            .with_next_step(CONNECT_TRACE_NEXT_STEP),
        ConnectFailureKind::FastAuthNotAdvertised => env.with_next_step(
            "use username/password authentication (profile credential_ref) for this server, or \
             point token/IAM auth at an Oracle 23ai or newer service",
        ),
        ConnectFailureKind::UnsupportedWireFeature { feature } => {
            let mut env = env.with_next_step(
                "connect to a server/service that does not require this wire feature, or \
                 disable the requirement on the server",
            );
            if feature
                .to_ascii_lowercase()
                .contains("native network encryption")
            {
                env = env.with_next_step(
                    "Native Network Encryption is required by the server's sqlnet.ora \
                     (SQLNET.ENCRYPTION_SERVER / SQLNET.CRYPTO_CHECKSUM_SERVER = required); \
                     set them to `accepted` or use TCPS/TLS transport instead",
                );
            }
            env
        }
        ConnectFailureKind::ListenerRefused { err_code } => {
            let mut env = env.with_next_step(
                "verify the service name in the connect string against the services the \
                 listener actually knows (`lsnrctl services` on the database host)",
            );
            if *err_code == Some(12514) {
                env = env.with_next_step(
                    "if the service name is right, the database may still be starting or has \
                     not registered with the listener yet — retry once it is open",
                );
            }
            env.with_next_step(
                "verify host and port reach the intended listener (a wrong port can hit a \
                 different listener that refuses the service)",
            )
        }
        ConnectFailureKind::ListenerRedirectUnsupported => env
            .with_next_step(
                "connect directly to the redirect target (the dedicated server's host:port) \
                 instead of an endpoint that issues TNS redirects (e.g. CMAN or a \
                 shared-server dispatcher)",
            )
            .with_next_step(CONNECT_TRACE_NEXT_STEP),
        ConnectFailureKind::ServerGenerationUnsupported { .. } => env.with_next_step(
            "this thin driver supports Oracle 12.1 and newer; connect to a supported database \
             generation",
        ),
        ConnectFailureKind::HandshakeProtocol => env
            .with_next_step(
                "verify the endpoint is an Oracle listener of a supported generation (12.1+)",
            )
            .with_next_step(CONNECT_TRACE_NEXT_STEP),
    }
}

/// Render a parsed Oracle error and attach the retry remedy that follows from
/// the shared driver-aligned taxonomy. `ErrorClass::Transient` deliberately
/// does not distinguish reconnect from retry-in-place on the wire, so the
/// ordered operator steps make that safety-relevant distinction explicit.
fn oracle_error_envelope(message: &str) -> ErrorEnvelope {
    let env = envelope_from_oracle_message(message);
    if env.error_class == ErrorClass::SnapshotTooOld {
        return env.with_retry_after_ms(1_000).with_next_step(
            "retry with a narrower read; if the error repeats, ask the DBA about UNDO_RETENTION",
        );
    }
    match oracle_retry_action_from_message(message) {
        OracleRetryAction::Never => env,
        OracleRetryAction::RetrySameConnection => env.with_next_step(
            "the Oracle session remains usable; retry this idempotent read once on the same connection",
        ),
        OracleRetryAction::ReconnectThenRetry => env.with_next_step(
            "the Oracle connection was lost; discard it and retry this idempotent read once on a fresh connection",
        ),
    }
}

/// Keep parser failures of SQL composed by the server on the server side of
/// the boundary, retaining Oracle's numeric code without exposing generated
/// SQL text as though the caller could fix it.
fn server_sql_error_envelope(message: &str) -> ErrorEnvelope {
    let oracle = oracle_error_envelope(message);
    if oracle.error_class == ErrorClass::SyntaxError {
        let mut envelope = ErrorEnvelope::new(
            ErrorClass::Internal,
            format!(
                "a server-owned query failed (ORA-{}); your input did not cause this",
                oracle.ora_code.unwrap_or_default()
            ),
        );
        if let Some(code) = oracle.ora_code {
            envelope = envelope.with_ora_code(code);
        }
        return envelope;
    }
    oracle
}

/// Defense-in-depth fallback for **driver-originated** `Query`/`Execute` errors
/// whose only signal is an `ORA-`/`DPY-` code (a stable structural identifier)
/// or a driver connection-state phrase we do not model as a typed variant.
///
/// oraclemcp's *own* uncertain-state paths (mid-cancel, fetch-loop call timeout)
/// never rely on this text match — they return a structural variant
/// ([`DbError::Cancelled`] / [`DbError::ConnectHandshake`] / …) that
/// [`DbError::is_uncertain_session_state`] flags from the kind. This list only
/// catches strings we cannot restructure because they arrive from the driver.
fn message_is_uncertain_connection_state(message: &str) -> bool {
    const MARKERS: &[&str] = &["dpy-4011", "call timeout", "ora-01013"];
    let message = message.to_ascii_lowercase();
    matches!(
        oracle_retry_action_from_message(&message),
        OracleRetryAction::ReconnectThenRetry
    ) || raw_connection_lost_marker(&message)
        || MARKERS.iter().any(|marker| message.contains(marker))
}

/// Raw I/O errors do not carry an ORA code. The driver adapter preserves them
/// as [`DbError::ConnectionLost`], while these markers keep mocks and legacy
/// string-only call sites fail-closed until they reach that seam.
fn raw_connection_lost_marker(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    [
        "dpy-4011",
        "connection closed",
        "connection is closed",
        "broken pipe",
        "connection reset",
    ]
    .iter()
    .any(|marker| message.contains(marker))
}

/// Raw socket/driver text is not a stable operator contract and can include
/// transport internals. Preserve retryability without rendering the driver's
/// display text on an MCP tool surface.
fn transport_lost_envelope(message: &str) -> ErrorEnvelope {
    let mut env = ErrorEnvelope::new(
        ErrorClass::Transient,
        "Oracle transport connection was lost; driver detail suppressed",
    )
    .with_next_step(
        "discard the connection and retry this idempotent read once on a fresh connection",
    );
    if let Some(code) = parse_ora_code(message) {
        env = env.with_ora_code(code);
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_OUTCOMES: [StatementOutcome; 7] = [
        StatementOutcome::NotStarted,
        StatementOutcome::CompletedRead,
        StatementOutcome::RolledBack,
        StatementOutcome::Committed,
        StatementOutcome::CommitUnknown,
        StatementOutcome::DdlOutcomeUnknown,
        StatementOutcome::ProtocolUnsynchronized,
    ];

    const ALL_CLASSES: [StatementClass; 5] = [
        StatementClass::ProvenIdempotentRead,
        StatementClass::Mutation,
        StatementClass::Ddl,
        StatementClass::SessionControl,
        StatementClass::Unknown,
    ];

    /// Compile-time completeness: adding a variant breaks these matches, so the
    /// `ALL_*` tables above must be extended with it.
    fn outcome_index(outcome: StatementOutcome) -> usize {
        match outcome {
            StatementOutcome::NotStarted => 0,
            StatementOutcome::CompletedRead => 1,
            StatementOutcome::RolledBack => 2,
            StatementOutcome::Committed => 3,
            StatementOutcome::CommitUnknown => 4,
            StatementOutcome::DdlOutcomeUnknown => 5,
            StatementOutcome::ProtocolUnsynchronized => 6,
            _ => panic!("new statement outcome needs an explicit matrix case"),
        }
    }

    fn class_index(class: StatementClass) -> usize {
        match class {
            StatementClass::ProvenIdempotentRead => 0,
            StatementClass::Mutation => 1,
            StatementClass::Ddl => 2,
            StatementClass::SessionControl => 3,
            StatementClass::Unknown => 4,
        }
    }

    #[test]
    fn statement_outcome_serializes_to_plan_names() {
        let expected = [
            "not_started",
            "completed_read",
            "rolled_back",
            "committed",
            "commit_unknown",
            "ddl_outcome_unknown",
            "protocol_unsynchronized",
        ];
        for (outcome, name) in ALL_OUTCOMES.iter().zip(expected) {
            assert_eq!(
                outcome_index(*outcome),
                ALL_OUTCOMES.iter().position(|o| o == outcome).unwrap()
            );
            let wire = serde_json::to_string(outcome).unwrap();
            assert_eq!(wire, format!("\"{name}\""));
            let back: StatementOutcome = serde_json::from_str(&wire).unwrap();
            assert_eq!(back, *outcome);
        }
    }

    /// The expected policy, written as an explicit table (not derived from the
    /// implementation): AutoRetry only for NotStarted (any class) and for a
    /// proven idempotent read after CompletedRead / ProtocolUnsynchronized.
    fn expected_matrix(outcome: StatementOutcome, class: StatementClass) -> RetryDecision {
        let auto = RetryDecision::AutoRetry;
        let typed = RetryDecision::ReturnTyped;
        //                         read   mut    ddl    sess   unknown
        const T: [[bool; 5]; 7] = [
            /* not_started      */ [true, true, true, true, true],
            /* completed_read   */ [true, false, false, false, false],
            /* rolled_back      */ [false, false, false, false, false],
            /* committed        */ [false, false, false, false, false],
            /* commit_unknown   */ [false, false, false, false, false],
            /* ddl_unknown      */ [false, false, false, false, false],
            /* protocol_unsync  */ [true, false, false, false, false],
        ];
        if T[outcome_index(outcome)][class_index(class)] {
            auto
        } else {
            typed
        }
    }

    fn assert_policy_matrix(policy: impl Fn(StatementOutcome, StatementClass) -> RetryDecision) {
        for outcome in ALL_OUTCOMES {
            for class in ALL_CLASSES {
                assert_eq!(
                    policy(outcome, class),
                    expected_matrix(outcome, class),
                    "{outcome:?} x {class:?}"
                );
                if class == StatementClass::Mutation && outcome != StatementOutcome::NotStarted {
                    assert_eq!(
                        policy(outcome, class),
                        RetryDecision::ReturnTyped,
                        "a mutation that may have reached Oracle is never replayed: {outcome:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn retry_decision_matrix_is_exhaustive_and_never_retries_mutation() {
        assert_eq!(ALL_OUTCOMES.len() * ALL_CLASSES.len(), 35);
        assert_policy_matrix(retry_decision);
        for (i, outcome) in ALL_OUTCOMES.iter().enumerate() {
            assert_eq!(outcome_index(*outcome), i);
        }
        for (i, class) in ALL_CLASSES.iter().enumerate() {
            assert_eq!(class_index(*class), i);
        }
    }

    #[test]
    fn planted_mutant_retrying_commit_unknown_mutation_fails_the_matrix() {
        let mutant = |outcome: StatementOutcome, class: StatementClass| {
            if outcome == StatementOutcome::CommitUnknown && class == StatementClass::Mutation {
                RetryDecision::AutoRetry
            } else {
                retry_decision(outcome, class)
            }
        };
        let caught = std::panic::catch_unwind(|| assert_policy_matrix(mutant));
        assert!(
            caught.is_err(),
            "the matrix test must reject the planted mutant"
        );
    }

    #[test]
    fn quarantine_outcome_maps_totally() {
        let cases = [
            (QuarantineOutcome::RolledBack, StatementOutcome::RolledBack),
            (
                QuarantineOutcome::DiscardedUncommitted,
                StatementOutcome::RolledBack,
            ),
            (
                QuarantineOutcome::CommitInDoubt,
                StatementOutcome::CommitUnknown,
            ),
            (
                QuarantineOutcome::UnknownDiscarded,
                StatementOutcome::ProtocolUnsynchronized,
            ),
        ];
        for (quarantine, expected) in cases {
            // Exhaustive: a new QuarantineOutcome variant fails to compile here.
            match quarantine {
                QuarantineOutcome::RolledBack
                | QuarantineOutcome::DiscardedUncommitted
                | QuarantineOutcome::CommitInDoubt
                | QuarantineOutcome::UnknownDiscarded => {}
            }
            assert_eq!(StatementOutcome::from(quarantine), expected);
        }
        // An in-doubt commit is never reported as a definite outcome.
        assert_ne!(
            StatementOutcome::from(QuarantineOutcome::CommitInDoubt),
            StatementOutcome::Committed
        );
    }

    #[test]
    fn unknown_class_never_auto_retries_after_start() {
        for outcome in ALL_OUTCOMES {
            let decision = retry_decision(outcome, StatementClass::Unknown);
            if outcome == StatementOutcome::NotStarted {
                assert_eq!(decision, RetryDecision::AutoRetry);
            } else {
                assert_eq!(decision, RetryDecision::ReturnTyped, "{outcome:?}");
            }
        }
    }

    #[test]
    fn query_error_with_ora_code_classifies() {
        let env =
            DbError::Query("ORA-00942: table or view does not exist".to_owned()).into_envelope();
        assert_eq!(env.error_class, ErrorClass::ObjectNotFound);
        assert_eq!(env.ora_code, Some(942));
    }

    #[test]
    fn error_class_table() {
        let refused = ErrorEnvelope::new(ErrorClass::ForbiddenStatement, "generated read refused")
            .with_next_step("inspect the policy decision");
        let cases = [
            (
                "unsupported ddl type",
                DbError::InvalidArgument("unsupported DDL object type: TABLESPACE".to_owned()),
                ErrorClass::InvalidArguments,
                None,
                Some("oracle_get_ddl"),
            ),
            (
                "unsupported source type",
                DbError::InvalidArgument("unsupported source object type: TABLE".to_owned()),
                ErrorClass::InvalidArguments,
                None,
                Some("oracle_get_source"),
            ),
            (
                "snapshot too old",
                DbError::Query("ORA-01555: snapshot too old".to_owned()),
                ErrorClass::SnapshotTooOld,
                Some(1555),
                None,
            ),
            (
                "table definition changed during read",
                DbError::Query(
                    "ORA-01466: unable to read data - table definition has changed".to_owned(),
                ),
                ErrorClass::Transient,
                Some(1466),
                None,
            ),
            (
                "caller syntax error",
                DbError::Query("ORA-00904: invalid identifier".to_owned()),
                ErrorClass::SyntaxError,
                Some(904),
                None,
            ),
            (
                "server syntax error",
                DbError::ServerQuery("ORA-00904: invalid identifier".to_owned()),
                ErrorClass::Internal,
                Some(904),
                None,
            ),
            (
                "object missing",
                DbError::Query("ORA-00942: table or view does not exist".to_owned()),
                ErrorClass::ObjectNotFound,
                Some(942),
                Some("oracle_schema_inspect"),
            ),
            (
                "insufficient privilege",
                DbError::Execute("ORA-01031: insufficient privileges".to_owned()),
                ErrorClass::InsufficientPrivilege,
                Some(1031),
                None,
            ),
            (
                "generated read refusal",
                DbError::Refused(Box::new(refused)),
                ErrorClass::ForbiddenStatement,
                None,
                None,
            ),
            (
                "connection loss",
                DbError::ConnectionLost("Broken pipe".to_owned()),
                ErrorClass::Transient,
                None,
                None,
            ),
        ];

        for (source, error, expected_class, expected_code, expected_tool) in cases {
            let envelope = error.into_envelope();
            assert_eq!(envelope.error_class, expected_class, "{source}");
            assert_eq!(envelope.ora_code, expected_code, "{source}");
            assert_eq!(
                envelope.suggested_tool.as_deref(),
                expected_tool,
                "{source}"
            );
            if source == "generated read refusal" {
                assert_eq!(
                    envelope.next_steps,
                    ["inspect the policy decision".to_owned()],
                    "{source}"
                );
            }
        }
    }

    #[test]
    fn dbms_metadata_missing_object_does_not_fall_back_to_connection_failed() {
        let env = DbError::Query(
            "ORA-31603: object \"MISSING_TABLE\" of type TABLE not found in schema \"APP\""
                .to_owned(),
        )
        .into_envelope();
        assert_eq!(env.error_class, ErrorClass::ObjectNotFound);
        assert_eq!(env.ora_code, Some(31603));
        assert_eq!(env.suggested_tool.as_deref(), Some("oracle_schema_inspect"));
    }

    #[test]
    fn unclassified_oracle_error_keeps_internal_class_and_code() {
        let env =
            DbError::Execute("ORA-20000: server detail suppressed".to_owned()).into_envelope();
        assert_eq!(env.error_class, ErrorClass::Internal);
        assert_eq!(env.ora_code, Some(20_000));
    }

    #[test]
    fn ora_01555_is_snapshot_too_old_not_connection_failed() {
        let env = DbError::Query("ORA-01555: snapshot too old".to_owned()).into_envelope();
        assert_eq!(env.error_class, ErrorClass::SnapshotTooOld);
        assert_eq!(env.ora_code, Some(1555));
        assert!(env.error_class.is_retryable());
        assert_eq!(env.retry_after_ms, Some(1_000));
        assert!(
            env.next_steps
                .iter()
                .any(|step| step.contains("UNDO_RETENTION"))
        );
    }

    #[test]
    fn ora_01466_plain_query_is_transient_with_same_session_retry_guidance() {
        let envelope = DbError::Query(
            "ORA-01466: unable to read data - table definition has changed".to_owned(),
        )
        .into_envelope();

        assert_eq!(envelope.error_class, ErrorClass::Transient);
        assert_eq!(envelope.ora_code, Some(1466));
        assert_ne!(
            envelope.suggested_tool.as_deref(),
            Some("oracle_connection_info")
        );
        assert!(
            envelope
                .next_steps
                .iter()
                .any(|step| step.contains("same connection")),
            "{}",
            envelope.next_steps.join("; ")
        );
    }

    #[test]
    fn server_origin_ora_00904_is_not_syntax_error() {
        let caller = DbError::Query("ORA-00904: invalid identifier".to_owned()).into_envelope();
        assert_eq!(caller.error_class, ErrorClass::SyntaxError);
        assert_eq!(caller.ora_code, Some(904));

        let server =
            DbError::ServerQuery("ORA-00904: invalid identifier".to_owned()).into_envelope();
        assert_eq!(server.error_class, ErrorClass::Internal);
        assert_eq!(server.ora_code, Some(904));
        assert!(server.message.contains("your input did not cause this"));
        assert!(!server.message.contains("invalid identifier"));
    }

    #[test]
    fn invalid_argument_has_type_specific_suggestion() {
        let env =
            DbError::InvalidArgument("unsupported DDL object type: \"DATABASE LINK\"".to_owned())
                .into_envelope();
        assert_eq!(env.error_class, ErrorClass::InvalidArguments);
        assert_eq!(env.suggested_tool.as_deref(), Some("oracle_get_ddl"));
    }

    #[test]
    fn flashback_retention_refusal_has_typed_class_and_next_steps() {
        let env = DbError::FlashbackRefusal {
            kind: FlashbackRefusalKind::RetentionExceeded,
            message: "ORA-08180: no snapshot found based on specified time".to_owned(),
            ora_code: Some(8180),
        }
        .into_envelope();

        assert_eq!(env.error_class, ErrorClass::FlashbackRetentionExceeded);
        assert_eq!(env.ora_code, Some(8180));
        assert!(env.message.contains("outside available retention"));
        assert!(
            env.next_steps.iter().any(|step| step.contains("newer SCN")),
            "{:?}",
            env.next_steps
        );
    }

    #[test]
    fn missing_dbms_flashback_is_a_typed_non_degrading_capability_refusal() {
        let env = DbError::FlashbackRefusal {
            kind: FlashbackRefusalKind::CapabilityUnavailable,
            message: "ORA-06550: line 1, column 7:\nPLS-00201: identifier 'DBMS_FLASHBACK' must be declared; database version 18.4.0.0.0"
                .to_owned(),
            ora_code: None,
        }
        .into_envelope();

        assert_eq!(env.error_class, ErrorClass::FlashbackCapabilityUnavailable);
        assert_eq!(env.ora_code, None, "ORA-06550 is only the PLS wrapper");
        assert!(env.message.contains("DBMS_FLASHBACK"), "{}", env.message);
        assert!(
            env.message.contains("18.4.0.0.0"),
            "the envelope retains the detected database version: {}",
            env.message
        );
        assert!(
            env.next_steps
                .iter()
                .any(|step| step.contains("not silently degraded")),
            "{:?}",
            env.next_steps
        );
    }

    #[test]
    fn flashback_definition_change_refusal_has_typed_class_and_next_steps() {
        let env = DbError::FlashbackRefusal {
            kind: FlashbackRefusalKind::DefinitionChanged,
            message: "ORA-01466: unable to read data - table definition has changed".to_owned(),
            ora_code: Some(1466),
        }
        .into_envelope();

        assert_eq!(env.error_class, ErrorClass::FlashbackDefinitionChanged);
        assert_eq!(env.ora_code, Some(1466));
        assert!(env.message.contains("definition changed"));
        assert!(
            env.next_steps
                .iter()
                .any(|step| step.contains("DDL boundary")),
            "{:?}",
            env.next_steps
        );
    }

    #[test]
    fn flashback_non_flashbackable_refusal_has_typed_class_and_next_steps() {
        let env = DbError::FlashbackRefusal {
            kind: FlashbackRefusalKind::NotFlashbackable,
            message: "ORA-02070: database REMOTE does not support flashback in this context"
                .to_owned(),
            ora_code: Some(2070),
        }
        .into_envelope();

        assert_eq!(env.error_class, ErrorClass::FlashbackNotFlashbackable);
        assert_eq!(env.ora_code, Some(2070));
        assert!(env.message.contains("cannot serve through flashback"));
        assert!(
            env.next_steps
                .iter()
                .any(|step| step.contains("source database")),
            "{:?}",
            env.next_steps
        );
    }

    #[test]
    fn flashback_refusal_classifier_is_contextual_and_conservative() {
        assert_eq!(
            classify_flashback_refusal_message(
                "ORA-06550: line 1, column 7:\nPLS-00201: identifier 'DBMS_FLASHBACK' must be declared"
            ),
            Some((FlashbackRefusalKind::CapabilityUnavailable, None)),
            "the PLS wrapper must not erase the missing DBMS_FLASHBACK capability"
        );
        assert_eq!(
            classify_flashback_refusal_message("ORA-01555: snapshot too old"),
            Some((FlashbackRefusalKind::RetentionExceeded, Some(1555)))
        );
        assert_eq!(
            classify_flashback_refusal_message("ORA-08186: invalid timestamp specified"),
            Some((FlashbackRefusalKind::RetentionExceeded, Some(8186)))
        );
        assert_eq!(
            classify_flashback_refusal_message(
                "ORA-01466: unable to read data - table definition has changed"
            ),
            Some((FlashbackRefusalKind::DefinitionChanged, Some(1466)))
        );
        assert_eq!(
            classify_flashback_refusal_message(
                "ORA-02070: database REMOTE does not support flashback in this context"
            ),
            Some((FlashbackRefusalKind::NotFlashbackable, Some(2070)))
        );
        assert_eq!(
            classify_flashback_refusal_message("ORA-08185: flashback not supported for user SYS"),
            Some((FlashbackRefusalKind::NotFlashbackable, Some(8185)))
        );
        assert_eq!(
            classify_flashback_refusal_message(
                "ORA-02070: database REMOTE does not support DECODE in this context"
            ),
            None,
            "generic ORA-02070 must not be mislabeled as a flashback refusal"
        );
    }

    #[test]
    fn connect_error_without_code_is_connection_failed() {
        let env = DbError::Connect("listener refused the connection".to_owned()).into_envelope();
        assert_eq!(env.error_class, ErrorClass::ConnectionFailed);
    }

    #[test]
    fn pool_error_is_busy_with_retry() {
        let env = DbError::Pool("timed out waiting for connection".to_owned()).into_envelope();
        assert_eq!(env.error_class, ErrorClass::Busy);
        assert_eq!(env.retry_after_ms, Some(250));
    }

    #[test]
    fn generic_connect_error_always_carries_next_actions() {
        // A raw driver string with no ORA- code must never surface without
        // concrete next steps (field-test bead bhw6.2).
        let env = DbError::Connect("socket closed mid-handshake".to_owned()).into_envelope();
        assert_eq!(env.error_class, ErrorClass::ConnectionFailed);
        assert!(!env.next_steps.is_empty());
        assert!(
            env.next_steps
                .iter()
                .any(|step| step.contains("ORACLEDB_TRACE_CONNECT=1")),
            "generic connect failures must point at the handshake trace: {:?}",
            env.next_steps
        );
    }

    #[test]
    fn unexpected_tns_packet_names_the_network_layer_with_trace_guidance() {
        let env = DbError::ConnectHandshake {
            kind: ConnectFailureKind::UnexpectedTnsPacket { packet_type: 11 },
            message: "unexpected TNS packet type 11 (Resend)".to_owned(),
        }
        .into_envelope();
        assert_eq!(env.error_class, ErrorClass::ConnectionFailed);
        assert!(env.message.contains("[unexpected-tns-packet]"));
        assert!(env.message.contains("TNS packet type 11"));
        // Honest layering: this is the network-layer handshake, not TTC/SQL.
        assert!(env.message.contains("network layer"));
        assert!(
            env.next_steps
                .iter()
                .any(|step| step.contains("ORACLEDB_TRACE_CONNECT=1"))
        );
    }

    #[test]
    fn connect_resend_loop_reports_rounds_and_trace_guidance() {
        let env = DbError::ConnectHandshake {
            kind: ConnectFailureKind::ConnectResendLoop { rounds: 5 },
            message: "server kept requesting CONNECT resend (5 rounds); giving up".to_owned(),
        }
        .into_envelope();
        assert_eq!(env.error_class, ErrorClass::ConnectionFailed);
        assert!(env.message.contains("[connect-resend-loop]"));
        assert!(env.message.contains("5 rounds"));
        assert!(
            env.next_steps
                .iter()
                .any(|step| step.contains("ORACLEDB_TRACE_CONNECT=1"))
        );
    }

    #[test]
    fn fast_auth_not_advertised_points_at_password_auth_or_23ai() {
        let env = DbError::ConnectHandshake {
            kind: ConnectFailureKind::FastAuthNotAdvertised,
            message: "server did not advertise fast authentication".to_owned(),
        }
        .into_envelope();
        assert_eq!(env.error_class, ErrorClass::InvalidArguments);
        assert!(env.message.contains("[fast-auth-not-advertised]"));
        assert!(env.message.contains("pre-23ai"));
        assert!(
            env.next_steps
                .iter()
                .any(|step| step.contains("credential_ref"))
        );
    }

    #[test]
    fn unsupported_wire_feature_names_the_feature_and_na_encryption_remedy() {
        let env = DbError::ConnectHandshake {
            kind: ConnectFailureKind::UnsupportedWireFeature {
                feature: "Native Network Encryption and Data Integrity".to_owned(),
            },
            message: "unsupported feature: Native Network Encryption and Data Integrity".to_owned(),
        }
        .into_envelope();
        assert_eq!(env.error_class, ErrorClass::InvalidArguments);
        assert!(env.message.contains("[unsupported-wire-feature]"));
        assert!(env.message.contains("Native Network Encryption"));
        assert!(
            env.next_steps
                .iter()
                .any(|step| step.contains("SQLNET.ENCRYPTION_SERVER"))
        );
    }

    #[test]
    fn listener_refused_extracts_err_code_and_names_invalid_service() {
        let env = DbError::ConnectHandshake {
            kind: ConnectFailureKind::ListenerRefused {
                err_code: Some(12514),
            },
            message: "(DESCRIPTION=(ERR=12514))".to_owned(),
        }
        .into_envelope();
        assert_eq!(env.error_class, ErrorClass::ConnectionFailed);
        assert_eq!(env.ora_code, Some(12514));
        assert!(env.message.contains("[listener-refused]"));
        assert!(env.message.contains("service name"));
        assert!(
            env.next_steps
                .iter()
                .any(|step| step.contains("lsnrctl services"))
        );
    }

    #[test]
    fn listener_redirect_unsupported_suggests_direct_connect() {
        let env = DbError::ConnectHandshake {
            kind: ConnectFailureKind::ListenerRedirectUnsupported,
            message: "listener redirected this connection".to_owned(),
        }
        .into_envelope();
        assert_eq!(env.error_class, ErrorClass::ConnectionFailed);
        assert!(env.message.contains("[listener-redirect-unsupported]"));
        assert!(
            env.next_steps
                .iter()
                .any(|step| step.contains("connect directly"))
        );
    }

    #[test]
    fn server_generation_unsupported_names_the_version_floor() {
        let env = DbError::ConnectHandshake {
            kind: ConnectFailureKind::ServerGenerationUnsupported {
                tns_version: Some(298),
            },
            message: "unsupported TNS version 298".to_owned(),
        }
        .into_envelope();
        assert_eq!(env.error_class, ErrorClass::InvalidArguments);
        assert!(env.message.contains("[server-generation-unsupported]"));
        assert!(env.message.contains("298"));
        assert!(env.message.contains("Oracle 12.1"));
        assert!(!env.next_steps.is_empty());
    }

    #[test]
    fn handshake_protocol_error_names_the_phase_and_trace() {
        let env = DbError::ConnectHandshake {
            kind: ConnectFailureKind::HandshakeProtocol,
            message: "unknown TTC message type 11 at position 4".to_owned(),
        }
        .into_envelope();
        assert_eq!(env.error_class, ErrorClass::ConnectionFailed);
        assert!(env.message.contains("[handshake-protocol-error]"));
        assert!(env.message.contains("connect handshake"));
        // The sanitized driver detail is preserved for triage…
        assert!(env.message.contains("unknown TTC message type 11"));
        // …but never without next actions.
        assert!(
            env.next_steps
                .iter()
                .any(|step| step.contains("ORACLEDB_TRACE_CONNECT=1"))
        );
    }

    #[test]
    fn connect_handshake_is_uncertain_session_state() {
        let err = DbError::ConnectHandshake {
            kind: ConnectFailureKind::HandshakeProtocol,
            message: "boom".to_owned(),
        };
        assert!(err.is_uncertain_session_state());
    }

    #[test]
    fn cancelled_error_is_timeout_envelope() {
        let env =
            DbError::Cancelled("oracle_query.serialize.rows: cancelled".to_owned()).into_envelope();
        assert_eq!(env.error_class, ErrorClass::Timeout);
        assert!(env.message.contains("oracle_query.serialize.rows"));
        assert!(env.retry_after_ms.is_none());
    }

    #[test]
    fn typed_call_timeout_preserves_transient_envelope_and_connection_disposition() {
        let reusable = DbError::CallTimeout {
            operation: "execute".to_owned(),
            retry_action: OracleRetryAction::RetrySameConnection,
        };
        let envelope = reusable.clone().into_envelope();
        assert_eq!(envelope.error_class, ErrorClass::Transient);
        assert_eq!(envelope.ora_code, None);
        assert_eq!(envelope.retry_after_ms, None);
        assert_eq!(
            reusable.retry_action(),
            OracleRetryAction::RetrySameConnection
        );
        assert!(!reusable.is_connection_lost());
        assert!(!reusable.is_uncertain_session_state());

        let dead = DbError::CallTimeout {
            operation: "execute".to_owned(),
            retry_action: OracleRetryAction::ReconnectThenRetry,
        };
        assert_eq!(dead.retry_action(), OracleRetryAction::ReconnectThenRetry);
        assert!(dead.is_connection_lost());
        assert!(dead.is_uncertain_session_state());
    }

    // --- into_envelope coverage for the remaining DbError variants (H5) -----
    //
    // Each of these constructs and classifies without an ORA- code to parse, so
    // they were previously exercised only at their *construction* sites
    // (`matches!(err, DbError::Foo(_))`) and never through `into_envelope()` —
    // the actual agent-facing rendering. A regression that mapped one of these
    // to the wrong `ErrorClass` (for example, `Quarantined` losing its
    // `ConnectionFailed` class) would have passed every existing test.

    #[test]
    fn backend_not_compiled_is_runtime_state_required() {
        let env = DbError::BackendNotCompiled {
            backend: OracleBackend::RustOracle,
        }
        .into_envelope();
        assert_eq!(env.error_class, ErrorClass::RuntimeStateRequired);
        assert!(env.message.contains("not compiled"));
        assert!(env.message.contains("oracledb-thin"));
    }

    #[test]
    fn unsupported_auth_is_invalid_arguments() {
        let env = DbError::UnsupportedAuth("mTLS client cert auth not implemented".to_owned())
            .into_envelope();
        assert_eq!(env.error_class, ErrorClass::InvalidArguments);
        assert!(env.message.contains("mTLS client cert"));
    }

    #[test]
    fn unsupported_feature_is_invalid_arguments() {
        let env = DbError::UnsupportedFeature("CQN registration".to_owned()).into_envelope();
        assert_eq!(env.error_class, ErrorClass::InvalidArguments);
        assert!(env.message.contains("CQN registration"));
    }

    #[test]
    fn quarantined_envelope_carries_outcome_in_message_and_discard_next_step() {
        for outcome in [
            QuarantineOutcome::RolledBack,
            QuarantineOutcome::DiscardedUncommitted,
            QuarantineOutcome::UnknownDiscarded,
        ] {
            let env = DbError::Quarantined {
                outcome,
                message: "cleanup failed".to_owned(),
            }
            .into_envelope();
            assert_eq!(env.error_class, ErrorClass::ConnectionFailed, "{outcome}");
            assert!(
                env.message.contains(outcome.as_str()),
                "envelope must name the quarantine outcome: {}",
                env.message
            );
            assert!(
                env.next_steps
                    .iter()
                    .any(|step| step.contains("do not reuse")),
                "{outcome}: {:?}",
                env.next_steps
            );
        }
    }

    #[test]
    fn quarantined_commit_in_doubt_gets_a_distinct_verification_next_step() {
        // CommitInDoubt is the one outcome where the transaction may actually
        // have landed — "do not reuse the session" is not enough; the agent
        // must be told to verify the outcome before retrying non-idempotent
        // work (never assume the commit silently failed).
        let env = DbError::Quarantined {
            outcome: QuarantineOutcome::CommitInDoubt,
            message: "fsync failed after commit".to_owned(),
        }
        .into_envelope();
        assert_eq!(env.error_class, ErrorClass::ConnectionFailed);
        assert!(env.message.contains("commit_in_doubt"));
        assert!(
            env.next_steps
                .iter()
                .any(|step| step.contains("verify the transaction outcome")),
            "{:?}",
            env.next_steps
        );
        assert!(
            !env.next_steps
                .iter()
                .any(|step| step.contains("do not reuse")),
            "CommitInDoubt must not carry the generic 'do not reuse' step in place \
             of the verification step: {:?}",
            env.next_steps
        );
    }

    #[test]
    fn internal_error_is_internal_class_and_preserves_detail() {
        let env = DbError::Internal("pool lock poisoned: some thread panicked".to_owned())
            .into_envelope();
        assert_eq!(env.error_class, ErrorClass::Internal);
        assert!(env.message.contains("pool lock poisoned"));
    }

    // --- is_uncertain_session_state marker coverage (H5) --------------------
    //
    // `message_is_uncertain_connection_state` is the defense-in-depth fallback
    // for driver-originated Query/Execute errors that carry no structural
    // variant. Its marker list gates whether a lease is quarantined after a
    // failure — get it wrong and either a genuinely uncertain session gets
    // reused (data risk) or a certain one gets needlessly discarded. Every
    // marker had zero direct test before this: the only prior coverage was
    // indirect, through `ConnectHandshake` (a structural variant that never
    // touches this text-matching path at all).

    #[test]
    fn query_and_execute_uncertain_state_markers_are_each_detected() {
        const MARKERS: &[&str] = &[
            "DPY-4011: no more data to read from socket",
            "call timeout exceeded",
            "ORA-01013: user requested cancel of current operation",
            "connection closed by peer",
            "the connection is closed",
            "Broken pipe (os error 32)",
            "connection reset by peer",
        ];
        for marker in MARKERS {
            assert!(
                DbError::Query((*marker).to_owned()).is_uncertain_session_state(),
                "Query variant must flag as uncertain for marker: {marker}"
            );
            assert!(
                DbError::Execute((*marker).to_owned()).is_uncertain_session_state(),
                "Execute variant must flag as uncertain for marker: {marker}"
            );
        }

        for code in oraclemcp_error::CONNECTION_LOST_ORA_CODES {
            let marker = format!("ORA-{code:05}: connection lost");
            assert!(
                DbError::Query(marker.clone()).is_uncertain_session_state(),
                "Query must quarantine every driver connection-lost ORA code: {marker}"
            );
            assert!(
                DbError::Execute(marker.clone()).is_connection_lost(),
                "Execute must reconnect before retrying every connection-lost ORA code: {marker}"
            );
        }
    }

    #[test]
    fn retry_envelopes_distinguish_fresh_connection_from_same_session() {
        let lost = DbError::ConnectionLost("ORA-02396: exceeded maximum idle time".to_owned());
        assert!(lost.is_connection_lost());
        let lost_envelope = lost.into_envelope();
        assert_eq!(lost_envelope.error_class, ErrorClass::Transient);
        assert_eq!(lost_envelope.ora_code, Some(2396));
        assert!(
            lost_envelope
                .next_steps
                .iter()
                .any(|step| step.contains("fresh connection"))
        );

        let reset =
            DbError::Query("ORA-04068: existing state of packages has been discarded".to_owned());
        assert!(!reset.is_uncertain_session_state());
        assert!(!reset.is_connection_lost());
        let reset_envelope = reset.into_envelope();
        assert_eq!(reset_envelope.error_class, ErrorClass::Transient);
        assert!(
            reset_envelope
                .next_steps
                .iter()
                .any(|step| step.contains("same connection"))
        );
    }

    #[test]
    fn raw_transport_display_never_reaches_an_agent_envelope() {
        for error in [
            DbError::Connect("Broken pipe (os error 32)".to_owned()),
            DbError::ConnectionLost("Broken pipe (os error 32)".to_owned()),
            DbError::Query("connection reset by peer (os error 104)".to_owned()),
            DbError::Execute("the connection is closed".to_owned()),
        ] {
            let envelope = error.into_envelope();
            assert!(
                matches!(
                    envelope.error_class,
                    ErrorClass::ConnectionFailed | ErrorClass::Transient
                ),
                "unexpected class: {:?}",
                envelope.error_class
            );
            assert!(!envelope.next_steps.is_empty());
            let rendered = envelope.to_json().to_string();
            assert!(!rendered.contains("Broken pipe"));
            assert!(!rendered.contains("connection reset by peer"));
            assert!(!rendered.contains("the connection is closed"));
        }
    }

    #[test]
    fn query_marker_match_is_case_insensitive() {
        assert!(
            DbError::Query("ora-03113: end-of-file on communication channel".to_owned())
                .is_uncertain_session_state(),
            "a lower-cased ORA code must still match the marker"
        );
    }

    #[test]
    fn ordinary_query_error_without_a_marker_is_not_uncertain_state() {
        let err = DbError::Query("ORA-00942: table or view does not exist".to_owned());
        assert!(
            !err.is_uncertain_session_state(),
            "an ordinary object-not-found error must not trigger a session quarantine"
        );
    }

    #[test]
    fn connect_pool_and_cancelled_are_always_uncertain_session_state() {
        // Unlike Query/Execute (marker-gated), these variants are unconditionally
        // uncertain regardless of message content.
        assert!(DbError::Connect("anything".to_owned()).is_uncertain_session_state());
        assert!(DbError::Pool("anything".to_owned()).is_uncertain_session_state());
        assert!(DbError::Cancelled("anything".to_owned()).is_uncertain_session_state());
    }
}
