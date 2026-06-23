//! Lazy per-statement read-only backstop (bead A1 / oraclemcp-040-epic-wp-a-ia1.1).
//!
//! Defense-in-depth layer **B** of the read-only enforcement stack (the layers
//! are documented in `oraclemcp_guard::enforcement`): even if the fail-closed
//! classifier (layer C) ever *mis-judged* a statement as read-only, the
//! DATABASE itself must still refuse a write on the read path. Oracle enforces
//! exactly that when the current transaction was opened with
//! [`SET TRANSACTION READ ONLY`](oraclemcp_guard::SET_TRANSACTION_READ_ONLY):
//! any subsequent INSERT/UPDATE/DELETE/DDL raises `ORA-01456`
//! ("may not perform insert/delete/update operation inside a READ ONLY
//! transaction").
//!
//! ## Why this is NOT the connect-time backstop
//!
//! `oraclemcp_core::connect` already issues `SET TRANSACTION READ ONLY` once, at
//! connect, as a profile login statement for a `READ_ONLY`-ceilinged profile.
//! That one-shot is necessary but NOT sufficient: a read-only transaction in
//! Oracle is *transaction-scoped* — it ends at the next `COMMIT`/`ROLLBACK`, and
//! the session silently returns to a normal read-write transaction afterwards.
//! A plain `SELECT` does not end the transaction, but a legitimately-gated
//! `oracle_execute` write does (it commits or rolls back), and a session whose
//! TTL elevation window expires drops back to `READ_ONLY` *silently*. After
//! either event the connect-time one-shot is gone and a misclassified write
//! would no longer hit `ORA-01456`. This backstop re-asserts the property at the
//! **start of every read transaction** so the guarantee is continuous.
//!
//! ## Where the boundary sits (the senior call)
//!
//! The boundary is the **dispatcher's pinned/primary session read context**, one
//! [`ReadOnlyBackstop`] per [`DispatcherState`](super::DispatcherState). It is
//! scoped to that single pinned session only — NOT the stateless metadata-read
//! pool, whose connections are checked out per call, never carry a caller
//! transaction, and rely on the least-privilege DB user (layer A / bead A2)
//! instead. The dispatcher serializes the pinned session behind one async mutex,
//! so the backstop's `armed` flag needs no interior synchronization beyond that
//! `&mut` borrow.
//!
//! ## Lazy / reset / fail-closed behavior
//!
//! - **Lazy.** [`ReadOnlyBackstop::ensure_armed`] issues
//!   `SET TRANSACTION READ ONLY` only when the backstop is not already `armed`.
//!   Once armed, repeated reads in the SAME read-only transaction pay no extra
//!   round trip — the property persists until a transaction boundary. The
//!   deterministic test asserts the statement is issued exactly once across many
//!   reads.
//! - **Reset on a transaction boundary.** Anything that ends the transaction
//!   disarms the backstop so the next read re-asserts it: a committed/rolled-back
//!   write ([`ReadOnlyBackstop::disarm`], called by the write path before it runs
//!   so the gated write is never refused by `ORA-01456`), and a profile switch
//!   that swaps the underlying session ([`ReadOnlyBackstop::reset`]).
//! - **Re-assert on a silent drop back to `READ_ONLY`.** The read path always
//!   consults the live [`effective_level`](oraclemcp_guard::SessionLevelState::effective_level):
//!   when it is `READ_ONLY` and the backstop is disarmed (e.g. after a TTL
//!   elevation window expired silently following a write), `ensure_armed`
//!   re-issues the statement. When the level is above `READ_ONLY` the read path
//!   does not arm it (a write may be legitimately authorized).
//! - **Fail-closed.** This is a SECURITY control: if `SET TRANSACTION READ ONLY`
//!   fails to apply on a read context, [`ReadOnlyBackstop::ensure_armed`]
//!   propagates the error (the read is refused) rather than letting an
//!   un-backstopped read proceed. It does NOT mark itself armed on failure, so a
//!   later retry re-attempts the assertion. It composes with B1's async DB seam
//!   (it `.await`s the `OracleConnection::execute` round trip), the lease
//!   dirty-discard, and A9 read-path capability narrowing (it runs on the same
//!   pinned `&dyn OracleConnection`, no extra effect capability required).
//!
//! ## Known limitation (carried from layer B everywhere)
//!
//! `SET TRANSACTION READ ONLY` does not stop `PRAGMA AUTONOMOUS_TRANSACTION`
//! side effects fired by a trigger/VPD function — those commit independently and
//! raise no `ORA-01456`. The classifier's trigger/VPD walk is the defense there;
//! on a `protected` profile the least-privilege DB user (layer A) is the real
//! boundary. This backstop is ADDITIONAL to, never a replacement for, the
//! classifier and the operating-level gate.

use asupersync::Cx;
use oraclemcp_db::{OracleBind, OracleConnection};
use oraclemcp_error::ErrorEnvelope;
use oraclemcp_guard::{OperatingLevel, SET_TRANSACTION_READ_ONLY, SessionLevelState};

use super::DbError;

/// Per-pinned-session tracker for the lazy read-only transaction backstop (A1).
///
/// `armed == true` means this read context believes the pinned session's
/// current transaction was opened `READ ONLY` and no transaction boundary has
/// happened since. It is a best-effort *belief* derived from what the dispatcher
/// itself issued on the serialized session; the real guarantee lives in Oracle
/// (the engine raises `ORA-01456` regardless of this flag).
#[derive(Debug, Default)]
pub(crate) struct ReadOnlyBackstop {
    armed: bool,
}

impl ReadOnlyBackstop {
    /// A fresh, disarmed backstop (the next read at `READ_ONLY` will assert it).
    pub(crate) fn new() -> Self {
        Self { armed: false }
    }

    /// Whether the read-only transaction is currently believed to be in force.
    #[cfg(test)]
    pub(crate) fn is_armed(&self) -> bool {
        self.armed
    }

    /// Read-path entry point. When the live effective level is `READ_ONLY` and
    /// the backstop is not already armed, issue `SET TRANSACTION READ ONLY` on
    /// the pinned session so Oracle enforces read-only at the transaction level.
    ///
    /// Lazy: a no-op when already armed (no per-read round trip). When the
    /// effective level is above `READ_ONLY`, this does nothing — a write may be
    /// legitimately authorized and must not be blocked by the backstop.
    ///
    /// Fail-closed: a failure to apply the statement is propagated (the read is
    /// refused) and the backstop is left disarmed so a retry re-attempts it.
    pub(crate) async fn ensure_armed(
        &mut self,
        cx: &Cx,
        conn: &dyn OracleConnection,
        session: &SessionLevelState,
    ) -> Result<(), ErrorEnvelope> {
        // A silent TTL-window expiry drops the effective level back to
        // READ_ONLY; we read it live on every call so the backstop re-asserts
        // exactly when the session is (again) read-only.
        if session.effective_level() != OperatingLevel::ReadOnly {
            return Ok(());
        }
        if self.armed {
            return Ok(());
        }
        self.assert_read_only(cx, conn).await
    }

    /// Issue `SET TRANSACTION READ ONLY` and, only on success, mark armed.
    async fn assert_read_only(
        &mut self,
        cx: &Cx,
        conn: &dyn OracleConnection,
    ) -> Result<(), ErrorEnvelope> {
        conn.execute(cx, SET_TRANSACTION_READ_ONLY, &[] as &[OracleBind])
            .await
            .map_err(DbError::into_envelope)?;
        self.armed = true;
        Ok(())
    }

    /// Disarm the backstop because the current transaction is about to end (a
    /// gated write commits or rolls back). Called by the write path BEFORE the
    /// write runs so the authorized write is never refused with `ORA-01456`, and
    /// so the NEXT read re-asserts the backstop on the fresh transaction.
    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }

    /// Reset because the underlying pinned session was replaced (profile switch).
    /// The new session has its own transaction; the backstop must re-assert on
    /// its first read.
    pub(crate) fn reset(&mut self) {
        self.armed = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::DbError;
    use asupersync::runtime::RuntimeBuilder;
    use oraclemcp_db::{OracleBackend, OracleConnectionInfo, OracleRow};
    use std::sync::Mutex;

    /// Records every `execute` (so the backstop statement is observable) and
    /// every `query_rows` so a test can interleave reads and assert the backstop
    /// is issued lazily (once), not per read.
    #[derive(Default)]
    struct RecordingConn {
        executed: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for RecordingConn {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }
        async fn query_rows(
            &self,
            _cx: &Cx,
            _sql: &str,
            _b: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            Ok(Vec::new())
        }
        async fn execute(&self, _cx: &Cx, sql: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
            self.executed
                .lock()
                .expect("exec mutex")
                .push(sql.to_owned());
            Ok(0)
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    /// An `execute` that always fails, to prove the fail-closed path.
    struct FailingExecConn;
    #[async_trait::async_trait(?Send)]
    impl OracleConnection for FailingExecConn {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }
        async fn query_rows(
            &self,
            _cx: &Cx,
            _sql: &str,
            _b: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            Ok(Vec::new())
        }
        async fn execute(&self, _cx: &Cx, _sql: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
            Err(DbError::Execute("ORA-01456 surrogate".to_owned()))
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    fn run<F, Fut, T>(body: F) -> T
    where
        F: FnOnce(Cx) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        runtime.block_on(async move {
            let cx = Cx::current().expect("block_on installs a current Cx");
            body(cx).await
        })
    }

    fn read_only() -> SessionLevelState {
        SessionLevelState::new(OperatingLevel::ReadOnly, false)
    }

    fn read_write() -> SessionLevelState {
        let mut level = SessionLevelState::new(OperatingLevel::ReadWrite, false);
        level
            .set_current_level(OperatingLevel::ReadWrite)
            .expect("read/write within ceiling");
        level
    }

    #[test]
    fn arms_lazily_once_across_many_reads() {
        run(|cx| async move {
            let conn = RecordingConn::default();
            let session = read_only();
            let mut backstop = ReadOnlyBackstop::new();
            // Three reads in the same read-only transaction.
            for _ in 0..3 {
                backstop
                    .ensure_armed(&cx, &conn, &session)
                    .await
                    .expect("backstop arms");
            }
            let executed = conn.executed.lock().expect("exec mutex").clone();
            assert_eq!(
                executed,
                vec![SET_TRANSACTION_READ_ONLY.to_owned()],
                "SET TRANSACTION READ ONLY issued exactly once (lazy), not per read"
            );
            assert!(backstop.is_armed());
        });
    }

    #[test]
    fn re_asserts_after_a_transaction_boundary() {
        run(|cx| async move {
            let conn = RecordingConn::default();
            let session = read_only();
            let mut backstop = ReadOnlyBackstop::new();
            backstop.ensure_armed(&cx, &conn, &session).await.unwrap();
            // A write commits/rolls back the transaction; the write path disarms.
            backstop.disarm();
            assert!(!backstop.is_armed());
            // The next read re-asserts on the fresh transaction.
            backstop.ensure_armed(&cx, &conn, &session).await.unwrap();
            let executed = conn.executed.lock().expect("exec mutex").clone();
            assert_eq!(
                executed,
                vec![
                    SET_TRANSACTION_READ_ONLY.to_owned(),
                    SET_TRANSACTION_READ_ONLY.to_owned(),
                ],
                "the backstop is re-asserted on the new read transaction after a commit/rollback"
            );
        });
    }

    #[test]
    fn does_not_arm_above_read_only_so_a_gated_write_is_not_blocked() {
        run(|cx| async move {
            let conn = RecordingConn::default();
            let session = read_write();
            let mut backstop = ReadOnlyBackstop::new();
            backstop.ensure_armed(&cx, &conn, &session).await.unwrap();
            assert!(
                conn.executed.lock().expect("exec mutex").is_empty(),
                "no SET TRANSACTION READ ONLY at READ_WRITE — a legitimate write must not be blocked"
            );
            assert!(!backstop.is_armed());
        });
    }

    #[test]
    fn re_asserts_after_silent_drop_back_to_read_only() {
        run(|cx| async move {
            let conn = RecordingConn::default();
            let mut backstop = ReadOnlyBackstop::new();
            // Read-only: armed once.
            backstop
                .ensure_armed(&cx, &conn, &read_only())
                .await
                .unwrap();
            // Elevation to READ_WRITE; a gated write happened (disarm), level was
            // raised, the read path is a no-op while elevated.
            backstop.disarm();
            backstop
                .ensure_armed(&cx, &conn, &read_write())
                .await
                .unwrap();
            // TTL window expires silently -> back to READ_ONLY. The next read
            // re-asserts because the live effective level is read-only again.
            backstop
                .ensure_armed(&cx, &conn, &read_only())
                .await
                .unwrap();
            let executed = conn.executed.lock().expect("exec mutex").clone();
            assert_eq!(
                executed,
                vec![
                    SET_TRANSACTION_READ_ONLY.to_owned(),
                    SET_TRANSACTION_READ_ONLY.to_owned(),
                ],
                "re-asserted on return to READ_ONLY; not issued while elevated"
            );
        });
    }

    #[test]
    fn fail_closed_when_set_transaction_read_only_cannot_apply() {
        run(|cx| async move {
            let conn = FailingExecConn;
            let session = read_only();
            let mut backstop = ReadOnlyBackstop::new();
            let err = backstop
                .ensure_armed(&cx, &conn, &session)
                .await
                .expect_err("a failed backstop assertion must be an error, never a silent pass");
            // Surfaced as a structured envelope; the read does not proceed.
            assert!(format!("{err:?}").contains("ORA-01456"));
            assert!(
                !backstop.is_armed(),
                "not marked armed on failure, so a retry re-attempts the assertion"
            );
        });
    }
}
