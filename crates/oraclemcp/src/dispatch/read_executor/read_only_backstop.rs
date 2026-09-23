//! Fresh-per-request read-only backstop (bead A1 / oraclemcp-040-epic-wp-a-ia1.1).
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
//! ## Freshness / reset / fail-closed behavior
//!
//! - **Fresh per request.** [`ReadOnlyBackstop::ensure_armed`] resets the prior
//!   transaction with `ROLLBACK`, then issues `SET TRANSACTION READ ONLY` before
//!   every `READ_ONLY` request. Oracle gives read-only transactions
//!   transaction-level consistency: keeping one armed across requests would pin
//!   the lane to the first request's snapshot indefinitely. Ending the previous
//!   read-only transaction immediately before the next guarded read keeps the
//!   engine backstop armed while giving each request a fresh committed snapshot.
//! - **Clear before a governed write.** Flipping the in-memory belief is not a
//!   transaction boundary. When an armed session is about to run an authorized
//!   write, [`ReadOnlyBackstop::clear_before_write`] first performs a bounded,
//!   cancellation-masked `ROLLBACK`; only a successful rollback disarms the
//!   tracker. This ends the real Oracle read-only transaction so the write is
//!   not refused by `ORA-01456`. A failed rollback leaves the tracker armed and
//!   the dispatcher quarantines the uncertain session.
//! - **Reset on an external transaction boundary.** Flashback cleanup and a
//!   profile switch can replace/reset the underlying transaction or session;
//!   those paths disarm/reset the belief so the next read re-asserts it.
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
use std::cell::Cell;

use super::DbError;

/// Per-pinned-session tracker for the read-only transaction backstop (A1).
///
/// `armed == true` means this read context believes the pinned session's
/// current transaction was opened `READ ONLY` and no transaction boundary has
/// happened since. It is a best-effort *belief* derived from what the dispatcher
/// itself issued on the serialized session; the real guarantee lives in Oracle
/// (the engine raises `ORA-01456` regardless of this flag).
#[derive(Debug, Default)]
pub(crate) struct ReadOnlyBackstop {
    armed: Cell<bool>,
}

impl ReadOnlyBackstop {
    /// A fresh, disarmed backstop (the next read at `READ_ONLY` will assert it).
    pub(crate) fn new() -> Self {
        Self {
            armed: Cell::new(false),
        }
    }

    /// Whether the read-only transaction is currently believed to be in force.
    #[cfg(test)]
    pub(crate) fn is_armed(&self) -> bool {
        self.armed.get()
    }

    /// Read-path entry point. When the live effective level is `READ_ONLY`, end
    /// the prior transaction and issue `SET TRANSACTION READ ONLY` on the pinned
    /// session so Oracle enforces read-only at the transaction level for this
    /// request's fresh snapshot.
    ///
    /// The transaction boundary occurs before the next request rather than in a
    /// post-read finalizer: the dispatch mutex serializes this pinned session,
    /// so no next read can start before the prior request completed, and a
    /// cancelled response cannot skip the transaction cleanup. When the
    /// effective level is above `READ_ONLY`, this does nothing — a write may be
    /// legitimately authorized and must not be blocked by the backstop.
    ///
    /// Fail-closed: a failure to apply the statement is propagated (the read is
    /// refused) and the backstop is left disarmed so a retry re-attempts it.
    ///
    /// Returns whether it actually asserted the statement. Every `READ_ONLY`
    /// call returns `true` after it creates its fresh backstopped transaction.
    /// Asserting rolls the prior transaction back, which erases every Oracle
    /// savepoint, so the caller must drop the reversible workspace's belief when
    /// this returns `true` (Arc I). This is also the path a silently-expired
    /// elevation window takes: the level falls back to `READ_ONLY`, the next
    /// read re-arms, and any uncommitted held work is discarded — the existing,
    /// correct fail-closed behavior.
    pub(crate) async fn ensure_armed(
        &mut self,
        cx: &Cx,
        conn: &dyn OracleConnection,
        session: &SessionLevelState,
    ) -> Result<bool, ErrorEnvelope> {
        // A silent TTL-window expiry drops the effective level back to
        // READ_ONLY; we read it live on every call so the backstop re-asserts
        // exactly when the session is (again) read-only.
        if session.effective_level() != OperatingLevel::ReadOnly {
            return Ok(false);
        }
        self.assert_read_only(cx, conn).await?;
        Ok(true)
    }

    /// Reset the prior transaction, issue `SET TRANSACTION READ ONLY`, and only
    /// on success mark armed for the upcoming guarded read.
    async fn assert_read_only(
        &mut self,
        cx: &Cx,
        conn: &dyn OracleConnection,
    ) -> Result<(), ErrorEnvelope> {
        // Oracle requires SET TRANSACTION to be the first statement in a
        // transaction. More importantly, an already-armed transaction has
        // transaction-level read consistency, so it must end before this
        // request can see a newly committed snapshot. Clear our belief before
        // the boundary: a failed rollback or SET leaves this request refused and
        // must never be treated as an armed backstop on a retry.
        self.armed.set(false);
        conn.rollback(cx).await.map_err(DbError::into_envelope)?;
        conn.execute(cx, SET_TRANSACTION_READ_ONLY, &[] as &[OracleBind])
            .await
            .map_err(DbError::into_envelope)?;
        self.armed.set(true);
        Ok(())
    }

    /// End an armed Oracle read-only transaction before a governed write.
    ///
    /// The rollback is a fresh bounded cleanup finalizer, independent of the
    /// spent request budget. Only a successful rollback clears the belief. On
    /// failure the caller must quarantine the session because whether Oracle
    /// crossed the transaction boundary is unknown.
    ///
    /// Returns whether it actually rolled back. A disarmed backstop is a no-op —
    /// it crosses no transaction boundary — so callers that key other
    /// transaction-scoped state off this (the Arc I savepoint stack) must not
    /// treat `Ok(false)` as a boundary.
    pub(crate) async fn clear_before_write(
        &self,
        cx: &Cx,
        conn: &dyn OracleConnection,
    ) -> Result<bool, DbError> {
        if !self.armed.get() {
            return Ok(false);
        }
        super::rollback_conn_cleanup(cx, conn).await?;
        self.armed.set(false);
        Ok(true)
    }

    /// Disarm after another path has already established a real transaction
    /// boundary (for example, flashback teardown). This must never be used as a
    /// substitute for [`Self::clear_before_write`] on a governed write path.
    pub(crate) fn disarm(&self) {
        self.armed.set(false);
    }

    /// Reset because the underlying pinned session was replaced (profile switch).
    /// The new session has its own transaction; the backstop must re-assert on
    /// its first read.
    pub(crate) fn reset(&self) {
        self.armed.set(false);
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
        rollbacks: Mutex<usize>,
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for RecordingConn {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        async fn close(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
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
            *self.rollbacks.lock().expect("rollback mutex") += 1;
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
        async fn close(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
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
    fn arms_a_fresh_read_only_transaction_for_every_read() {
        run(|cx| async move {
            let conn = RecordingConn::default();
            let session = read_only();
            let mut backstop = ReadOnlyBackstop::new();
            // Each next read ends the prior read-only transaction and begins a
            // fresh one, so Oracle cannot retain the first read's snapshot.
            for _ in 0..3 {
                backstop
                    .ensure_armed(&cx, &conn, &session)
                    .await
                    .expect("backstop arms");
            }
            let executed = conn.executed.lock().expect("exec mutex").clone();
            assert_eq!(
                executed,
                vec![
                    SET_TRANSACTION_READ_ONLY.to_owned(),
                    SET_TRANSACTION_READ_ONLY.to_owned(),
                    SET_TRANSACTION_READ_ONLY.to_owned(),
                ],
                "SET TRANSACTION READ ONLY is re-issued for every fresh read transaction"
            );
            assert_eq!(
                *conn.rollbacks.lock().expect("rollback mutex"),
                3,
                "each read transaction is reset before its read-only backstop is armed"
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
            assert_eq!(
                *conn.rollbacks.lock().expect("rollback mutex"),
                2,
                "each arming pass resets the transaction before SET TRANSACTION"
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
