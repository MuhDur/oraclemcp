//! The DB-layer error type, distinct from the engine's `CatalogError`.
//!
//! Kept independent so `oraclemcp-db` never depends on a `plsql-*` engine crate
//! (the one-way boundary, §0). [`DbError::into_envelope`] renders the
//! agent-facing [`ErrorEnvelope`] via the shared `oraclemcp-error` classifier.

use oraclemcp_error::{ErrorClass, ErrorEnvelope, envelope_from_oracle_message, parse_ora_code};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::types::OracleBackend;

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

/// Machine-stable category for a flashback/AS-OF read refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FlashbackRefusalKind {
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
            FlashbackRefusalKind::RetentionExceeded => "retention_exceeded",
            FlashbackRefusalKind::DefinitionChanged => "definition_changed",
            FlashbackRefusalKind::NotFlashbackable => "not_flashbackable",
        }
    }

    /// Agent-facing error class paired with this flashback refusal kind.
    #[must_use]
    pub(crate) const fn error_class(self) -> ErrorClass {
        match self {
            FlashbackRefusalKind::RetentionExceeded => ErrorClass::FlashbackRetentionExceeded,
            FlashbackRefusalKind::DefinitionChanged => ErrorClass::FlashbackDefinitionChanged,
            FlashbackRefusalKind::NotFlashbackable => ErrorClass::FlashbackNotFlashbackable,
        }
    }

    /// Short operator-facing explanation of the refusal.
    #[must_use]
    pub(crate) const fn summary(self) -> &'static str {
        match self {
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
    /// An auth mode is configured that this build cannot satisfy yet.
    #[error("unsupported auth mode: {0}")]
    UnsupportedAuth(String),
    /// A database feature is configured or requested that this backend cannot
    /// satisfy yet.
    #[error("unsupported database feature: {0}")]
    UnsupportedFeature(String),
    /// A stateful operation (transaction / savepoint) was attempted without a
    /// session lease (§5.1) — never a silent best-effort.
    #[error("session lease required: {0}")]
    LeaseRequired(String),
    /// The referenced lease does not exist or has expired.
    #[error("lease not found or expired: {0}")]
    LeaseNotFound(String),
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
    /// Whether this error means the session state cannot be trusted for reuse.
    #[must_use]
    pub fn is_uncertain_session_state(&self) -> bool {
        match self {
            DbError::Cancelled(_)
            | DbError::Connect(_)
            | DbError::ConnectHandshake { .. }
            | DbError::Pool(_)
            | DbError::Quarantined { .. } => true,
            DbError::Query(message) | DbError::Execute(message) => {
                message_is_uncertain_connection_state(message)
            }
            _ => false,
        }
    }

    /// Render the agent-facing [`ErrorEnvelope`]. Oracle-originated errors are
    /// classified by their `ORA-` code via the shared classifier.
    #[must_use]
    pub fn into_envelope(self) -> ErrorEnvelope {
        match self {
            DbError::Connect(msg) => {
                // Classify via the embedded ORA- code where present.
                let env = envelope_from_oracle_message(&msg);
                if env.error_class == ErrorClass::Internal {
                    // No ORA- code recognised: keep it as a connection-class
                    // failure rather than a bare Internal — and never surface
                    // a raw driver string without concrete next actions.
                    ErrorEnvelope::new(ErrorClass::ConnectionFailed, msg)
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
            DbError::Query(msg) | DbError::Execute(msg) => {
                // Classify via the embedded ORA- code where present.
                let env = envelope_from_oracle_message(&msg);
                if env.error_class == ErrorClass::Internal {
                    // An absent or as-yet-unclassified ORA code remains a
                    // connection-class failure rather than a bare Internal.
                    // Preserve a parsed code: rebuilding the fallback envelope
                    // must not erase useful structured diagnostics such as
                    // application-error ORA-20000.
                    let mut fallback = ErrorEnvelope::new(ErrorClass::ConnectionFailed, msg);
                    if let Some(code) = env.ora_code {
                        fallback = fallback.with_ora_code(code);
                    }
                    fallback
                } else {
                    env
                }
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
            DbError::UnsupportedAuth(msg) | DbError::UnsupportedFeature(msg) => {
                ErrorEnvelope::new(ErrorClass::InvalidArguments, msg)
            }
            DbError::LeaseRequired(msg) => ErrorEnvelope::new(ErrorClass::LeaseRequired, msg)
                .with_next_step("call oracle_session(acquire_lease) and pass the lease_id"),
            DbError::LeaseNotFound(msg) => ErrorEnvelope::new(ErrorClass::LeaseRequired, msg)
                .with_next_step("acquire a fresh lease via oracle_session(acquire_lease)"),
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
            let lower = message.to_ascii_lowercase();
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
    const MARKERS: &[&str] = &[
        "dpy-4011",
        "call timeout",
        "ora-01013",
        "ora-01012",
        "ora-03113",
        "ora-03114",
        "ora-03135",
        "ora-12170",
        "connection closed",
        "connection is closed",
    ];
    let message = message.to_ascii_lowercase();
    MARKERS.iter().any(|marker| message.contains(marker))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_error_with_ora_code_classifies() {
        let env =
            DbError::Query("ORA-00942: table or view does not exist".to_owned()).into_envelope();
        assert_eq!(env.error_class, ErrorClass::ObjectNotFound);
        assert_eq!(env.ora_code, Some(942));
    }

    #[test]
    fn unclassified_oracle_error_keeps_code_in_connection_fallback() {
        let env =
            DbError::Execute("ORA-20000: server detail suppressed".to_owned()).into_envelope();
        assert_eq!(env.error_class, ErrorClass::ConnectionFailed);
        assert_eq!(env.ora_code, Some(20_000));
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
}
