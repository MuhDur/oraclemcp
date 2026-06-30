//! The DB-layer error type, distinct from the engine's `CatalogError`.
//!
//! Kept independent so `oraclemcp-db` never depends on a `plsql-*` engine crate
//! (the one-way boundary, §0). [`DbError::into_envelope`] renders the
//! agent-facing [`ErrorEnvelope`] via the shared `oraclemcp-error` classifier.

use oraclemcp_error::{ErrorClass, ErrorEnvelope, envelope_from_oracle_message};
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
    /// A query failed.
    #[error("oracle query failed: {0}")]
    Query(String),
    /// A DML/DDL execute failed.
    #[error("oracle execute failed: {0}")]
    Execute(String),
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
            DbError::Connect(msg) | DbError::Query(msg) | DbError::Execute(msg) => {
                // Classify via the embedded ORA- code where present.
                let env = envelope_from_oracle_message(&msg);
                if env.error_class == ErrorClass::Internal {
                    // No ORA- code recognised: keep it as a connection-class
                    // failure rather than a bare Internal.
                    ErrorEnvelope::new(ErrorClass::ConnectionFailed, msg)
                } else {
                    env
                }
            }
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
    fn cancelled_error_is_timeout_envelope() {
        let env =
            DbError::Cancelled("oracle_query.serialize.rows: cancelled".to_owned()).into_envelope();
        assert_eq!(env.error_class, ErrorClass::Timeout);
        assert!(env.message.contains("oracle_query.serialize.rows"));
        assert!(env.retry_after_ms.is_none());
    }
}
