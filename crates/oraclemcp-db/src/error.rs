//! The DB-layer error type, distinct from the engine's `CatalogError`.
//!
//! Kept independent so `oraclemcp-db` never depends on a `plsql-*` engine crate
//! (the one-way boundary, §0). [`DbError::into_envelope`] renders the
//! agent-facing [`ErrorEnvelope`] via the shared `oraclemcp-error` classifier.

use oraclemcp_error::{ErrorClass, ErrorEnvelope, envelope_from_oracle_message};
use thiserror::Error;

use crate::types::OracleBackend;

/// An error from the Oracle connectivity layer.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DbError {
    /// The requested backend was not compiled in (the `oracle-driver` feature
    /// is off — the offline build).
    #[error("oracle backend `{backend}` not compiled (build with the `oracle-driver` feature)")]
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
    /// An auth mode is configured that this build cannot satisfy yet.
    #[error("unsupported auth mode: {0}")]
    UnsupportedAuth(String),
    /// A stateful operation (transaction / savepoint) was attempted without a
    /// session lease (§5.1) — never a silent best-effort.
    #[error("session lease required: {0}")]
    LeaseRequired(String),
    /// The referenced lease does not exist or has expired.
    #[error("lease not found or expired: {0}")]
    LeaseNotFound(String),
    /// An internal error (e.g. a blocking task join failure).
    #[error("internal db error: {0}")]
    Internal(String),
}

impl DbError {
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
            DbError::UnsupportedAuth(msg) => ErrorEnvelope::new(ErrorClass::InvalidArguments, msg),
            DbError::LeaseRequired(msg) => ErrorEnvelope::new(ErrorClass::LeaseRequired, msg)
                .with_next_step("call oracle_session(acquire_lease) and pass the lease_id"),
            DbError::LeaseNotFound(msg) => ErrorEnvelope::new(ErrorClass::LeaseRequired, msg)
                .with_next_step("acquire a fresh lease via oracle_session(acquire_lease)"),
            DbError::Internal(msg) => ErrorEnvelope::new(ErrorClass::Internal, msg),
        }
    }
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
}
