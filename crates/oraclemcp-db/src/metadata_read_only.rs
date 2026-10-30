//! Transaction control for an explicitly opted-in metadata pool checkout.
//! The classifier remains the primary control; autonomous transactions are
//! outside Oracle's transaction-scoped READ ONLY enforcement.

use std::future::Future;
use std::time::Duration;

use asupersync::{Cx, combinator::try_commit_section};
use oraclemcp_guard::{OperatingLevel, SET_TRANSACTION_READ_ONLY, SessionLevelState};

use crate::{DbError, OracleConnection};

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const CLEANUP_MASKED_POLLS: u32 = 100;

/// A control failure must never be retried as if it were a query failure.
/// The pool owner discards this checkout before returning the error.
pub(crate) struct MetadataReadAttempt<T> {
    pub(crate) result: Result<T, DbError>,
    pub(crate) control_failed: bool,
    /// An invalidated read snapshot leaves a healthy session reusable only
    /// after the READ ONLY transaction has been rolled back successfully.
    pub(crate) reusable_snapshot_error: bool,
}

pub(crate) async fn metadata_read_attempt<T, F, Fut>(
    cx: &Cx,
    conn: &dyn OracleConnection,
    level: Option<&SessionLevelState>,
    operation: F,
) -> MetadataReadAttempt<T>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<T, DbError>>,
{
    // Evaluate the live TTL-bearing state at checkout, not at pool creation.
    // None means the profile option is disabled: no extra database operation.
    let armed = level.is_some_and(|level| level.effective_level() == OperatingLevel::ReadOnly);
    if armed {
        let arm = async {
            // End any connect-time or previous transaction before choosing a
            // fresh snapshot. SET TRANSACTION must be its first statement.
            conn.rollback(cx).await?;
            conn.execute(cx, SET_TRANSACTION_READ_ONLY, &[]).await?;
            Ok::<_, DbError>(())
        }
        .await;
        if let Err(error) = arm {
            return MetadataReadAttempt {
                result: Err(error),
                control_failed: true,
                reusable_snapshot_error: false,
            };
        }
    }
    let result = operation().await;
    if !armed {
        return MetadataReadAttempt {
            result,
            control_failed: false,
            reusable_snapshot_error: false,
        };
    }
    // Ignore the exhausted primary cancellation while driving cleanup, with
    // its own finite deadline/poll allowance. The native adapter also applies
    // its independent five-second cleanup wire ceiling. A dropped future is
    // still owned by the pool's dirty-discard checkout guard.
    let cleanup = asupersync::time::timeout(
        cx.now(),
        CLEANUP_TIMEOUT,
        try_commit_section(cx, CLEANUP_MASKED_POLLS, conn.rollback(cx)),
    )
    .await
    .unwrap_or_else(|_| {
        Err(DbError::Cancelled(
            "metadata READ ONLY rollback exceeded its cleanup deadline".to_owned(),
        ))
    });
    match cleanup {
        Ok(()) => {
            let reusable_snapshot_error = matches!(
                &result,
                Err(error @ (DbError::Query(message) | DbError::ServerQuery(message)))
                    if oraclemcp_error::parse_ora_code(message) == Some(1466)
                        && !error.is_uncertain_session_state()
            );
            MetadataReadAttempt {
                result,
                control_failed: false,
                reusable_snapshot_error,
            }
        }
        Err(cleanup_error) => MetadataReadAttempt {
            // Never turn an original query refusal into an apparently
            // successful read because its cleanup also failed.
            result: result.and_then(|_| Err(cleanup_error)),
            control_failed: true,
            reusable_snapshot_error: false,
        },
    }
}

#[cfg(test)]
pub(crate) use tests::RecordingMetadataConnection;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OracleBackend, OracleBind, OracleConnectionInfo, OracleRow};
    use std::sync::{Arc, Mutex};

    #[derive(Default, Clone)]
    pub(crate) struct RecordingMetadataConnection {
        pub(crate) calls: Arc<Mutex<Vec<&'static str>>>,
        pub(crate) fail_arm: bool,
        pub(crate) fail_cleanup: bool,
        pub(crate) stall_cleanup: bool,
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for RecordingMetadataConnection {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        async fn ping(&self, _: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn close(&self, _: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn describe(&self, _: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Err(DbError::Internal(
                "describe is outside this unit test".into(),
            ))
        }
        async fn query_rows(
            &self,
            _: &Cx,
            _: &str,
            _: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.calls.lock().unwrap().push("read");
            Ok(Vec::new())
        }
        async fn execute(&self, _: &Cx, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError> {
            assert_eq!(sql, SET_TRANSACTION_READ_ONLY);
            assert!(binds.is_empty());
            self.calls.lock().unwrap().push("arm");
            if self.fail_arm {
                Err(DbError::Query(
                    "ORA-04068: synthetic transaction arm failure".into(),
                ))
            } else {
                Ok(0)
            }
        }
        async fn commit(&self, _: &Cx) -> Result<(), DbError> {
            panic!("metadata reads never commit")
        }
        async fn rollback(&self, cx: &Cx) -> Result<(), DbError> {
            cx.checkpoint()
                .map_err(|error| DbError::Cancelled(error.to_string()))?;
            let cleanup = {
                let mut calls = self.calls.lock().unwrap();
                calls.push("rollback");
                calls.iter().filter(|call| **call == "rollback").count() > 1
            };
            if cleanup && self.stall_cleanup {
                return std::future::pending().await;
            }
            if self.fail_cleanup && cleanup {
                Err(DbError::Query(
                    "ORA-03113: synthetic rollback failure".into(),
                ))
            } else {
                Ok(())
            }
        }
    }

    fn run(
        conn: &RecordingMetadataConnection,
        level: Option<&SessionLevelState>,
    ) -> MetadataReadAttempt<Vec<OracleRow>> {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                metadata_read_attempt(&cx, conn, level, || {
                    conn.query_rows(&cx, "SELECT 1 FROM dual", &[])
                })
                .await
            })
    }

    #[test]
    fn metadata_pool_arms_read_only_when_enabled_at_read_only_transaction_hook() {
        let conn = RecordingMetadataConnection::default();
        let result = run(
            &conn,
            Some(&SessionLevelState::new(OperatingLevel::Admin, false)),
        );
        assert!(result.result.is_ok());
        assert!(!result.control_failed);
        assert_eq!(
            *conn.calls.lock().unwrap(),
            ["rollback", "arm", "read", "rollback"]
        );
    }

    #[test]
    fn metadata_pool_untouched_when_disabled_transaction_hook() {
        let conn = RecordingMetadataConnection::default();
        let result = run(&conn, None);
        assert!(result.result.is_ok());
        assert!(!result.control_failed);
        assert_eq!(*conn.calls.lock().unwrap(), ["read"]);
    }

    #[test]
    fn metadata_pool_not_armed_above_read_only_transaction_hook() {
        for level in [
            OperatingLevel::ReadWrite,
            OperatingLevel::Ddl,
            OperatingLevel::Admin,
        ] {
            let conn = RecordingMetadataConnection::default();
            let mut state = SessionLevelState::new(OperatingLevel::Admin, false);
            state
                .escalate_window(level, Duration::from_secs(60))
                .unwrap();
            let result = run(&conn, Some(&state));
            assert!(result.result.is_ok());
            assert_eq!(*conn.calls.lock().unwrap(), ["read"]);
        }
    }

    #[test]
    fn metadata_pool_arm_failure_refuses_and_requires_discard() {
        let conn = RecordingMetadataConnection {
            fail_arm: true,
            ..Default::default()
        };
        let result = run(
            &conn,
            Some(&SessionLevelState::new(OperatingLevel::Admin, false)),
        );
        assert!(result.result.is_err());
        assert!(
            result.control_failed,
            "pool must discard, never retry or return idle"
        );
        assert_eq!(*conn.calls.lock().unwrap(), ["rollback", "arm"]);
    }

    #[test]
    fn metadata_pool_rollback_failure_requires_discard() {
        let conn = RecordingMetadataConnection {
            fail_cleanup: true,
            ..Default::default()
        };
        let result = run(
            &conn,
            Some(&SessionLevelState::new(OperatingLevel::Admin, false)),
        );
        assert!(result.result.is_err());
        assert!(result.control_failed);
        assert_eq!(
            *conn.calls.lock().unwrap(),
            ["rollback", "arm", "read", "rollback"]
        );
    }

    fn run_error(
        conn: &RecordingMetadataConnection,
        level: Option<&SessionLevelState>,
        error: DbError,
    ) -> MetadataReadAttempt<Vec<OracleRow>> {
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                metadata_read_attempt(&cx, conn, level, || async {
                    conn.query_rows(&cx, "SELECT 1 FROM dual", &[]).await?;
                    Err(error)
                })
                .await
            })
    }

    #[test]
    fn metadata_snapshot_error_is_reusable_only_after_successful_read_only_cleanup() {
        let level = SessionLevelState::new(OperatingLevel::ReadOnly, false);
        for fail_cleanup in [false, true] {
            let conn = RecordingMetadataConnection {
                fail_cleanup,
                ..Default::default()
            };
            let attempt = run_error(
                &conn,
                Some(&level),
                DbError::ServerQuery("ORA-01466: table definition has changed".into()),
            );
            assert!(attempt.result.is_err(), "the read error must be returned");
            assert_eq!(attempt.control_failed, fail_cleanup);
            assert_eq!(attempt.reusable_snapshot_error, !fail_cleanup);
            assert_eq!(
                *conn.calls.lock().unwrap(),
                ["rollback", "arm", "read", "rollback"]
            );
        }
    }

    #[test]
    fn metadata_snapshot_error_without_read_only_cleanup_is_not_reusable() {
        let mut elevated = SessionLevelState::new(OperatingLevel::Admin, false);
        elevated
            .escalate_window(OperatingLevel::ReadWrite, Duration::from_secs(60))
            .unwrap();
        for level in [None, Some(&elevated)] {
            let conn = RecordingMetadataConnection::default();
            let attempt = run_error(
                &conn,
                level,
                DbError::Query("ORA-01466: table definition has changed".into()),
            );
            assert!(!attempt.reusable_snapshot_error);
            assert_eq!(*conn.calls.lock().unwrap(), ["read"]);
        }
    }

    #[test]
    fn metadata_cleanup_does_not_make_other_errors_reusable() {
        let level = SessionLevelState::new(OperatingLevel::ReadOnly, false);
        for error in [
            DbError::Query("ORA-01456: cannot perform insert/delete/update".into()),
            DbError::Query("ORA-03113: end-of-file on communication channel".into()),
            DbError::Query("ORA-01466: snapshot changed; ORA-03113: lost connection".into()),
            DbError::Internal("ORA-01466: untrusted internal detail".into()),
        ] {
            let conn = RecordingMetadataConnection::default();
            let attempt = run_error(&conn, Some(&level), error);
            assert!(!attempt.control_failed);
            assert!(!attempt.reusable_snapshot_error);
        }
    }

    #[test]
    fn metadata_pool_cancelled_query_still_rolls_back_with_a_fresh_cleanup_allowance() {
        let conn = RecordingMetadataConnection::default();
        let level = SessionLevelState::new(OperatingLevel::Admin, false);
        let result = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .unwrap()
            .block_on(async {
                let cx = Cx::current().unwrap();
                metadata_read_attempt(&cx, &conn, Some(&level), || async {
                    conn.query_rows(&cx, "SELECT 1 FROM dual", &[]).await?;
                    cx.set_cancel_requested(true);
                    Err::<Vec<OracleRow>, _>(DbError::Cancelled(
                        "synthetic primary cancellation".into(),
                    ))
                })
                .await
            });
        assert!(matches!(result.result, Err(DbError::Cancelled(_))));
        assert!(
            !result.control_failed,
            "masked cleanup must succeed despite dead primary cancellation"
        );
        assert_eq!(
            *conn.calls.lock().unwrap(),
            ["rollback", "arm", "read", "rollback"]
        );
    }

    #[test]
    fn metadata_pool_rechecks_expired_elevation_and_oauth_ceiling() {
        let mut expired = SessionLevelState::new(OperatingLevel::Admin, false);
        expired
            .escalate_window(OperatingLevel::Admin, Duration::ZERO)
            .unwrap();
        let mut oauth = SessionLevelState::new(OperatingLevel::Admin, false);
        oauth
            .escalate_window(OperatingLevel::Admin, Duration::from_secs(60))
            .unwrap();
        oauth.apply_scope_ceiling(OperatingLevel::ReadOnly);
        for level in [expired, oauth] {
            let conn = RecordingMetadataConnection::default();
            assert!(run(&conn, Some(&level)).result.is_ok());
            assert_eq!(
                *conn.calls.lock().unwrap(),
                ["rollback", "arm", "read", "rollback"]
            );
        }
    }

    #[test]
    fn metadata_pool_stalled_rollback_hits_the_independent_cleanup_deadline() {
        let conn = RecordingMetadataConnection {
            stall_cleanup: true,
            ..Default::default()
        };
        let result = run(
            &conn,
            Some(&SessionLevelState::new(OperatingLevel::Admin, false)),
        );
        assert!(matches!(result.result, Err(DbError::Cancelled(ref message))
            if message == "metadata READ ONLY rollback exceeded its cleanup deadline"));
        assert!(
            result.control_failed,
            "a stalled finalizer must force discard"
        );
        assert_eq!(
            *conn.calls.lock().unwrap(),
            ["rollback", "arm", "read", "rollback"]
        );
    }
}
