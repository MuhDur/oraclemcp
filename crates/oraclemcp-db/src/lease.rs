//! The session-lease primitive (plan §5.1) — the #1 production blocker.
//!
//! A **lease** pins one physical Oracle session to one agent for a unit of
//! work, so transactions, savepoints, `DBMS_OUTPUT`, temp tables and
//! login-script session settings all land on the *same* session (a pool would
//! otherwise hand out a different session per checkout — silent corruption
//! under concurrency). Leases have a **monotonic** TTL; on expiry the manager
//! force-rolls-back the open transaction and drops the session (clearing all
//! session state). Any transaction/savepoint attempt **without** a lease is a
//! structured [`DbError::LeaseRequired`], never a silent best-effort.
//!
//! The lifecycle logic is driver-free (it operates over the
//! [`OracleConnection`] trait), so it is fully unit-testable with a mock.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asupersync::Cx;
use asupersync::sync::Mutex as AsyncMutex;
use oraclemcp_guard::{MonotonicDeadline, is_allowed_alter_session};
use serde::{Deserialize, Serialize};

// Cancellation checkpoints route through the single crate-wide
// `connection::db_checkpoint`.
use crate::connection::{OracleConnection, db_checkpoint};
use crate::error::{DbError, QuarantineOutcome};

/// Oracle limits: MODULE ≤ 48 chars, ACTION ≤ 32 chars (`DBMS_APPLICATION_INFO`).
const MODULE_NAME: &str = "oraclemcp";
const ACTION_MAX: usize = 32;
/// Oracle limit: CLIENT_INFO ≤ 64 chars (`DBMS_APPLICATION_INFO.SET_CLIENT_INFO`).
const CLIENT_INFO_MAX: usize = 64;
/// Oracle limit: CLIENT_IDENTIFIER ≤ 64 chars (`DBMS_SESSION.SET_IDENTIFIER`).
const CLIENT_IDENTIFIER_MAX: usize = 64;

/// Environment variable an operator/host may set to label the driving agent
/// model in `V$SESSION`. Best-effort, non-secret; absent → `oraclemcp`.
const AGENT_MODEL_ENV: &str = "ORACLEMCP_AGENT_MODEL";

/// One DBMS call in the session-tagging sequence: a PL/SQL block and its binds.
type TagStatement = (&'static str, Vec<crate::types::OracleBind>);

/// Truncate a tag value to a char-bounded, control-free, single-line string.
/// `DBMS_APPLICATION_INFO`/`DBMS_SESSION` silently truncate over-long values and
/// reject embedded NULs; we additionally drop control chars so a tag cannot
/// smuggle newlines into `V$SESSION` columns.
fn tag_value(raw: &str, max: usize) -> String {
    raw.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// Build the per-checkout **clear-and-reset** session-tagging sequence (bead A4).
///
/// CLIENT_IDENTIFIER (and MODULE/ACTION/CLIENT_INFO) persist on a physical
/// session across pooled reuse unless explicitly cleared. To prevent a prior
/// request's identity from leaking into the next checkout, this ALWAYS clears
/// every tag first, then sets MODULE/ACTION/CLIENT_INFO/CLIENT_IDENTIFIER to the
/// live agent + model for this lease. The sequence is pure and order-stable so
/// it can be unit-tested without a live database.
///
/// - MODULE      = `oraclemcp` (the server)
/// - ACTION      = the agent identity (≤ 32 chars; e.g. `profile:dev`)
/// - CLIENT_INFO = `agent=<identity> model=<model>` (≤ 64 chars)
/// - CLIENT_IDENTIFIER = the agent identity (≤ 64 chars)
fn session_tag_statements(agent_identity: &str, model: &str) -> Vec<TagStatement> {
    use crate::types::OracleBind;

    let action = tag_value(agent_identity, ACTION_MAX);
    let client_info = tag_value(
        &format!("agent={agent_identity} model={model}"),
        CLIENT_INFO_MAX,
    );
    let client_identifier = tag_value(agent_identity, CLIENT_IDENTIFIER_MAX);

    vec![
        // 1) Clear-and-reset: wipe any tags left by a prior pooled reuse. NULL
        //    MODULE also clears ACTION; CLEAR_IDENTIFIER drops CLIENT_IDENTIFIER;
        //    SET_CLIENT_INFO(NULL) clears CLIENT_INFO.
        (
            "BEGIN DBMS_APPLICATION_INFO.SET_MODULE(NULL, NULL); \
             DBMS_APPLICATION_INFO.SET_CLIENT_INFO(NULL); \
             DBMS_SESSION.CLEAR_IDENTIFIER; END;",
            vec![],
        ),
        // 2) Set the live identity for this checkout.
        (
            "BEGIN DBMS_APPLICATION_INFO.SET_MODULE(:1, :2); END;",
            vec![OracleBind::from(MODULE_NAME), OracleBind::from(action)],
        ),
        (
            "BEGIN DBMS_APPLICATION_INFO.SET_CLIENT_INFO(:1); END;",
            vec![OracleBind::from(client_info)],
        ),
        (
            "BEGIN DBMS_SESSION.SET_IDENTIFIER(:1); END;",
            vec![OracleBind::from(client_identifier)],
        ),
    ]
}

/// The best-effort agent-model label for session tagging: the operator-supplied
/// `ORACLEMCP_AGENT_MODEL`, else `oraclemcp`.
fn agent_model_label() -> String {
    std::env::var(AGENT_MODEL_ENV).unwrap_or_else(|_| MODULE_NAME.to_owned())
}

/// An opaque, in-process lease handle.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LeaseId(pub String);

impl std::fmt::Display for LeaseId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A non-secret snapshot of a lease's state (for `oracle_session` / capabilities).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseInfo {
    /// The lease handle.
    pub lease_id: String,
    /// The connection profile the session is pinned to.
    pub profile: String,
    /// The agent identity stamped into `DBMS_APPLICATION_INFO`.
    pub agent_identity: String,
    /// The configured TTL in seconds.
    pub ttl_seconds: u64,
    /// Milliseconds until expiry (0 if expired).
    pub expires_in_ms: u128,
    /// Whether an explicit transaction is open on the session.
    pub in_transaction: bool,
    /// Monotonic lease generation assigned when this physical session is pinned.
    pub generation: u64,
}

/// The ground-truth impact of a previewed (and rolled-back) DML.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviewImpact {
    /// Rows the statement would actually affect (`SQL%ROWCOUNT`).
    pub rows_affected: u64,
    /// Always `true` — the preview rolled back; the DB is unchanged.
    pub rolled_back: bool,
}

struct Lease {
    profile: String,
    agent_identity: String,
    generation: u64,
    conn: Box<dyn OracleConnection>,
    deadline: MonotonicDeadline,
    ttl: Duration,
    in_transaction: bool,
    lifecycle: LeaseLifecycle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LeaseLifecycle {
    Active,
    Revoking,
    Revoked,
}

impl Lease {
    fn info(&self, id: &str) -> LeaseInfo {
        LeaseInfo {
            lease_id: id.to_owned(),
            profile: self.profile.clone(),
            agent_identity: self.agent_identity.clone(),
            ttl_seconds: self.ttl.as_secs(),
            expires_in_ms: self.deadline.remaining().as_millis(),
            in_transaction: self.in_transaction,
            generation: self.generation,
        }
    }

    /// Force-clean on expiry/release: roll back any open transaction. Dropping
    /// the `Lease` afterwards closes the physical session (clearing all session
    /// state). Callers that are already tearing the lease down may ignore the
    /// error; callers deciding whether the lease remains reusable must inspect
    /// it and quarantine on failure.
    async fn force_rollback(&mut self, cx: &Cx) -> Result<(), DbError> {
        if self.in_transaction {
            let result = self.conn.rollback(cx).await;
            self.in_transaction = false;
            result?;
        }
        Ok(())
    }
}

fn quarantine_error(outcome: QuarantineOutcome, message: impl Into<String>) -> DbError {
    DbError::Quarantined {
        outcome,
        message: message.into(),
    }
}

/// Manages session leases. Cheap to clone-share via `Arc`. Each lease's
/// physical session is serialized behind its own async [`AsyncMutex`] so a DB
/// round trip (which is now `.await`-ed) can hold the guard across the await
/// without the deadlock/cancellation hazard a `std::sync::Mutex` would create.
/// The lease MAP itself is a plain `std::sync::Mutex`, only ever locked and
/// dropped synchronously for map operations (never across an `.await`).
#[derive(Default)]
pub struct LeaseManager {
    leases: Mutex<HashMap<String, Arc<AsyncMutex<Lease>>>>,
    counter: AtomicU64,
    generation: AtomicU64,
}

impl LeaseManager {
    /// A new, empty manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn next_id(&self) -> LeaseId {
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        LeaseId(format!("lease-{}-{n}", std::process::id()))
    }

    fn next_generation(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Acquire a lease over an already-opened connection: apply the profile's
    /// login statements, stamp the agent identity into `DBMS_APPLICATION_INFO`,
    /// and pin the session under a monotonic TTL. Returns the lease handle.
    pub async fn acquire(
        &self,
        cx: &Cx,
        profile: impl Into<String>,
        agent_identity: impl Into<String>,
        ttl: Duration,
        login_statements: &[String],
        conn: Box<dyn OracleConnection>,
    ) -> Result<LeaseId, DbError> {
        let profile = profile.into();
        let agent_identity = agent_identity.into();

        // Login script (operator house convention) — applied once on this
        // pinned session (§6.5). Each statement is the operator's responsibility
        // to allowlist; the guard validates them upstream.
        for stmt in login_statements {
            conn.execute(cx, stmt, &[]).await?;
        }

        // A4: clear-and-reset DBMS_APPLICATION_INFO / DBMS_SESSION on every
        // checkout, then stamp the live agent + model for Unified Auditing /
        // V$SESSION visibility. The clear step prevents a prior request's tag
        // (notably CLIENT_IDENTIFIER, which persists across pooled reuse) from
        // leaking into this lease.
        let model = agent_model_label();
        for (sql, binds) in session_tag_statements(&agent_identity, &model) {
            conn.execute(cx, sql, &binds).await?;
        }

        let id = self.next_id();
        let lease = Lease {
            profile,
            agent_identity,
            generation: self.next_generation(),
            conn,
            deadline: MonotonicDeadline::after(ttl),
            ttl,
            in_transaction: false,
            lifecycle: LeaseLifecycle::Active,
        };
        self.leases
            .lock()
            .expect("lease map mutex poisoned")
            .insert(id.0.clone(), Arc::new(AsyncMutex::new(lease)));
        Ok(id)
    }

    fn get(&self, id: &str) -> Option<Arc<AsyncMutex<Lease>>> {
        self.leases
            .lock()
            .expect("lease map mutex poisoned")
            .get(id)
            .cloned()
    }

    fn remove(&self, id: &str) -> Option<Arc<AsyncMutex<Lease>>> {
        self.leases
            .lock()
            .expect("lease map mutex poisoned")
            .remove(id)
    }

    fn lease_arc(&self, id: &str) -> Result<Arc<AsyncMutex<Lease>>, DbError> {
        self.get(id)
            .ok_or_else(|| DbError::LeaseNotFound(id.to_owned()))
    }

    fn remove_if_same(&self, id: &str, expected: &Arc<AsyncMutex<Lease>>) -> bool {
        let mut leases = self.leases.lock().expect("lease map mutex poisoned");
        let is_same = leases
            .get(id)
            .is_some_and(|current| Arc::ptr_eq(current, expected));
        if is_same {
            leases.remove(id);
        }
        is_same
    }

    /// Re-check lifecycle, map membership, and expiry while holding the exact
    /// same per-lease lock that protects the following DB operation. A handle
    /// cloned before release/reap cannot pass this point after revocation.
    async fn validate_locked(
        &self,
        cx: &Cx,
        id: &str,
        arc: &Arc<AsyncMutex<Lease>>,
        lease: &mut Lease,
    ) -> Result<(), DbError> {
        let current = self
            .leases
            .lock()
            .expect("lease map mutex poisoned")
            .get(id)
            .is_some_and(|candidate| Arc::ptr_eq(candidate, arc));
        if lease.lifecycle != LeaseLifecycle::Active || !current {
            return Err(DbError::LeaseNotFound(id.to_owned()));
        }
        if lease.deadline.is_expired() {
            lease.lifecycle = LeaseLifecycle::Revoking;
            self.remove_if_same(id, arc);
            let _ = lease.force_rollback(cx).await;
            lease.lifecycle = LeaseLifecycle::Revoked;
            return Err(DbError::LeaseNotFound(format!("{id} (expired)")));
        }
        Ok(())
    }

    /// Revoke a lease after a DB call crossed an uncertain boundary. Removal
    /// happens while the operation still owns the per-lease lock, so no later
    /// handle can reuse the session. Any possibly-open transaction is rolled
    /// back best-effort before the physical connection is dropped.
    async fn quarantine_uncertain_locked(
        &self,
        cx: &Cx,
        id: &str,
        arc: &Arc<AsyncMutex<Lease>>,
        lease: &mut Lease,
        operation: &str,
        error: DbError,
    ) -> DbError {
        debug_assert!(error.is_uncertain_session_state());
        lease.lifecycle = LeaseLifecycle::Revoking;
        self.remove_if_same(id, arc);
        let outcome = match lease.force_rollback(cx).await {
            Ok(()) => QuarantineOutcome::RolledBack,
            Err(_) => QuarantineOutcome::UnknownDiscarded,
        };
        lease.lifecycle = LeaseLifecycle::Revoked;
        quarantine_error(
            outcome,
            format!("{operation} crossed an uncertain DB boundary; lease discarded: {error}"),
        )
    }

    /// Renew a lease's TTL (clients renew at ~75% of the TTL). Errors if the
    /// lease is gone/expired.
    pub async fn renew(&self, cx: &Cx, id: &LeaseId) -> Result<LeaseInfo, DbError> {
        let arc = self.lease_arc(&id.0)?;
        let mut lease = arc.lock(cx).await.map_err(lock_err)?;
        self.validate_locked(cx, &id.0, &arc, &mut lease).await?;
        lease.deadline = MonotonicDeadline::after(lease.ttl);
        Ok(lease.info(&id.0))
    }

    /// Release a lease: force-rollback any open transaction and drop the
    /// session. Idempotent.
    pub async fn release(&self, cx: &Cx, id: &LeaseId) {
        if let Some(arc) = self.remove(&id.0)
            && let Ok(mut lease) = arc.lock(cx).await
        {
            lease.lifecycle = LeaseLifecycle::Revoking;
            let _ = lease.force_rollback(cx).await;
            lease.lifecycle = LeaseLifecycle::Revoked;
            // Dropping the Arc/Lease closes the physical session.
        }
    }

    /// Begin an explicit transaction on the leased session.
    pub async fn begin_transaction(&self, cx: &Cx, id: &LeaseId) -> Result<(), DbError> {
        let arc = self.lease_arc(&id.0)?;
        let mut lease = arc.lock(cx).await.map_err(lock_err)?;
        self.validate_locked(cx, &id.0, &arc, &mut lease).await?;
        lease.in_transaction = true;
        Ok(())
    }

    /// Commit the leased session's transaction.
    pub async fn commit(&self, cx: &Cx, id: &LeaseId) -> Result<(), DbError> {
        let arc = self.lease_arc(&id.0)?;
        let mut lease = arc.lock(cx).await.map_err(lock_err)?;
        self.validate_locked(cx, &id.0, &arc, &mut lease).await?;
        match lease.conn.commit(cx).await {
            Ok(()) => {
                lease.in_transaction = false;
                Ok(())
            }
            Err(err) => {
                lease.lifecycle = LeaseLifecycle::Revoking;
                self.remove_if_same(&id.0, &arc);
                lease.lifecycle = LeaseLifecycle::Revoked;
                Err(quarantine_error(
                    QuarantineOutcome::CommitInDoubt,
                    format!("commit failed; lease discarded: {err}"),
                ))
            }
        }
    }

    /// Roll back the leased session's transaction.
    pub async fn rollback(&self, cx: &Cx, id: &LeaseId) -> Result<(), DbError> {
        let arc = self.lease_arc(&id.0)?;
        let mut lease = arc.lock(cx).await.map_err(lock_err)?;
        self.validate_locked(cx, &id.0, &arc, &mut lease).await?;
        match lease.conn.rollback(cx).await {
            Ok(()) => {
                lease.in_transaction = false;
                Ok(())
            }
            Err(err) => {
                lease.lifecycle = LeaseLifecycle::Revoking;
                self.remove_if_same(&id.0, &arc);
                lease.lifecycle = LeaseLifecycle::Revoked;
                Err(quarantine_error(
                    QuarantineOutcome::UnknownDiscarded,
                    format!("rollback failed; lease discarded: {err}"),
                ))
            }
        }
    }

    /// Create a savepoint on the leased session. `name` must be a simple
    /// unquoted identifier (validated to prevent injection).
    pub async fn savepoint(&self, cx: &Cx, id: &LeaseId, name: &str) -> Result<(), DbError> {
        if !is_simple_identifier(name) {
            return Err(DbError::Execute(format!(
                "invalid savepoint name: {name:?}"
            )));
        }
        let arc = self.lease_arc(&id.0)?;
        let mut lease = arc.lock(cx).await.map_err(lock_err)?;
        self.validate_locked(cx, &id.0, &arc, &mut lease).await?;
        let was_in_transaction = lease.in_transaction;
        // SAVEPOINT may have succeeded even when the response is cancelled or
        // lost. Mark transaction state before crossing that boundary so
        // quarantine cleanup never skips the rollback.
        lease.in_transaction = true;
        match lease
            .conn
            .execute(cx, &format!("SAVEPOINT {name}"), &[])
            .await
        {
            Ok(_) => Ok(()),
            Err(error) if error.is_uncertain_session_state() => Err(self
                .quarantine_uncertain_locked(cx, &id.0, &arc, &mut lease, "savepoint", error)
                .await),
            Err(error) => {
                lease.in_transaction = was_in_transaction;
                Err(error)
            }
        }
    }

    /// Execute-in-savepoint **preview** (plan §5.4, bead P2-3): inside an
    /// autonomous savepoint on the leased session, actually run `sql`, capture
    /// `SQL%ROWCOUNT` (ground-truth blast radius — not optimizer cardinality),
    /// then **unconditionally `ROLLBACK TO SAVEPOINT`** so the DB is left
    /// unchanged. The rollback runs even if the statement errored.
    ///
    /// Cancellation may be observed before the savepoint or before/after the
    /// preview DML. Once a savepoint exists, rollback-to-savepoint is always
    /// attempted without a cancellation checkpoint. If rollback-to-savepoint
    /// fails, the lease is force-rolled-back and removed so an uncertain session
    /// cannot be reused.
    pub async fn preview_dml(
        &self,
        cx: &Cx,
        id: &LeaseId,
        sql: &str,
        binds: &[crate::types::OracleBind],
    ) -> Result<PreviewImpact, DbError> {
        const SP: &str = "oraclemcp_preview";
        let arc = self.lease_arc(&id.0)?;
        let mut discard_lease = None;
        {
            let mut lease = arc.lock(cx).await.map_err(lock_err)?;
            self.validate_locked(cx, &id.0, &arc, &mut lease).await?;
            let savepoint_sql = format!("SAVEPOINT {SP}");
            let rollback_sql = format!("ROLLBACK TO SAVEPOINT {SP}");
            db_checkpoint(cx, "oracle_lease.preview.savepoint.before")?;
            let was_in_transaction = lease.in_transaction;
            lease.in_transaction = true;
            match lease.conn.execute(cx, &savepoint_sql, &[]).await {
                Ok(_) => {}
                Err(error) if error.is_uncertain_session_state() => {
                    return Err(self
                        .quarantine_uncertain_locked(
                            cx,
                            &id.0,
                            &arc,
                            &mut lease,
                            "preview savepoint",
                            error,
                        )
                        .await);
                }
                Err(error) => {
                    lease.in_transaction = was_in_transaction;
                    return Err(error);
                }
            }
            let preview_result = match db_checkpoint(cx, "oracle_lease.preview.execute.before") {
                Ok(()) => lease.conn.execute(cx, sql, binds).await,
                Err(err) => Err(err),
            };
            let rollback_result = lease.conn.execute(cx, &rollback_sql, &[]).await;
            let result = match (preview_result, rollback_result) {
                (Ok(rows_affected), Ok(_)) => {
                    db_checkpoint(cx, "oracle_lease.preview.rollback.after")?;
                    Ok(PreviewImpact {
                        rows_affected,
                        rolled_back: true,
                    })
                }
                (Err(err), Ok(_)) if err.is_uncertain_session_state() => Err(self
                    .quarantine_uncertain_locked(
                        cx,
                        &id.0,
                        &arc,
                        &mut lease,
                        "preview execute",
                        err,
                    )
                    .await),
                (Err(err), Ok(_)) => Err(err),
                (Ok(_), Err(cleanup_err)) | (Err(_), Err(cleanup_err)) => {
                    let outcome = match lease.force_rollback(cx).await {
                        Ok(()) => QuarantineOutcome::RolledBack,
                        Err(_) => QuarantineOutcome::UnknownDiscarded,
                    };
                    discard_lease = Some(outcome);
                    Err(quarantine_error(
                        outcome,
                        format!("preview rollback failed; lease discarded: {cleanup_err}"),
                    ))
                }
            };
            if discard_lease.is_some() {
                lease.lifecycle = LeaseLifecycle::Revoking;
                self.remove_if_same(&id.0, &arc);
                lease.lifecycle = LeaseLifecycle::Revoked;
            }
            result
        }
    }

    /// Enable `DBMS_OUTPUT` on the leased session (full line capture is the
    /// `oracle_session` tool's job, P1-SESS).
    pub async fn enable_dbms_output(&self, cx: &Cx, id: &LeaseId) -> Result<(), DbError> {
        let arc = self.lease_arc(&id.0)?;
        let mut lease = arc.lock(cx).await.map_err(lock_err)?;
        self.validate_locked(cx, &id.0, &arc, &mut lease).await?;
        match lease
            .conn
            .execute(cx, "BEGIN DBMS_OUTPUT.ENABLE(NULL); END;", &[])
            .await
        {
            Ok(_) => Ok(()),
            Err(error) if error.is_uncertain_session_state() => Err(self
                .quarantine_uncertain_locked(
                    cx,
                    &id.0,
                    &arc,
                    &mut lease,
                    "DBMS_OUTPUT enablement",
                    error,
                )
                .await),
            Err(error) => Err(error),
        }
    }

    /// Apply an `ALTER SESSION` statement on the leased session (the
    /// `oracle_session` `set_session` action body, P1-SESS). This layer
    /// re-checks the guard allowlist so no caller can bypass the router and run
    /// arbitrary session state changes on a pinned lease.
    pub async fn apply_session_statement(
        &self,
        cx: &Cx,
        id: &LeaseId,
        statement: &str,
    ) -> Result<(), DbError> {
        if !is_allowed_alter_session(statement) {
            return Err(DbError::UnsupportedFeature(format!(
                "ALTER SESSION not on the allowlist: {statement:?}"
            )));
        }
        let arc = self.lease_arc(&id.0)?;
        let mut lease = arc.lock(cx).await.map_err(lock_err)?;
        self.validate_locked(cx, &id.0, &arc, &mut lease).await?;
        match lease.conn.execute(cx, statement, &[]).await {
            Ok(_) => Ok(()),
            Err(error) if error.is_uncertain_session_state() => Err(self
                .quarantine_uncertain_locked(cx, &id.0, &arc, &mut lease, "ALTER SESSION", error)
                .await),
            Err(error) => Err(error),
        }
    }

    /// A snapshot of a lease's state.
    pub async fn info(&self, cx: &Cx, id: &LeaseId) -> Result<LeaseInfo, DbError> {
        let arc = self.lease_arc(&id.0)?;
        let mut lease = arc.lock(cx).await.map_err(lock_err)?;
        self.validate_locked(cx, &id.0, &arc, &mut lease).await?;
        Ok(lease.info(&id.0))
    }

    /// Reap every expired lease (force-rollback + drop). Returns the count.
    pub async fn reap_expired(&self, cx: &Cx) -> usize {
        // Snapshot every lease handle, then check each one's deadline behind
        // its own async lock (the map mutex is only held for the snapshot).
        let candidates: Vec<(String, Arc<AsyncMutex<Lease>>)> = {
            let map = self.leases.lock().expect("lease map mutex poisoned");
            map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        let mut expired = 0;
        for (id, arc) in candidates {
            let Ok(mut lease) = arc.lock(cx).await else {
                continue;
            };
            if lease.lifecycle == LeaseLifecycle::Active
                && lease.deadline.is_expired()
                && self.remove_if_same(&id, &arc)
            {
                lease.lifecycle = LeaseLifecycle::Revoking;
                let _ = lease.force_rollback(cx).await;
                lease.lifecycle = LeaseLifecycle::Revoked;
                expired += 1;
            }
        }
        expired
    }

    /// Number of active leases.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.leases.lock().expect("lease map mutex poisoned").len()
    }

    /// Force-roll-back and drop every lease (graceful shutdown / crash cleanup,
    /// §5.7). Returns the number released. Idempotent.
    pub async fn release_all(&self, cx: &Cx) -> usize {
        let drained: Vec<Arc<AsyncMutex<Lease>>> = {
            let mut map = self.leases.lock().expect("lease map mutex poisoned");
            map.drain().map(|(_, v)| v).collect()
        };
        let count = drained.len();
        for arc in &drained {
            if let Ok(mut lease) = arc.lock(cx).await {
                lease.lifecycle = LeaseLifecycle::Revoking;
                let _ = lease.force_rollback(cx).await;
                lease.lifecycle = LeaseLifecycle::Revoked;
            }
        }
        count
    }
}

/// Map an async-mutex lock failure to a structured internal error.
fn lock_err(err: asupersync::sync::LockError) -> DbError {
    DbError::Internal(format!("lease mutex lock failed: {err}"))
}

/// Require a `lease_id` for a stateful (transaction/savepoint) operation —
/// returns [`DbError::LeaseRequired`] when absent (plan §5.1, P0-4d). This is
/// the law that a stateful op never silently runs in a best-effort autocommit
/// mode.
pub fn require_lease_id(lease_id: Option<&str>) -> Result<&str, DbError> {
    match lease_id {
        Some(id) if !id.is_empty() => Ok(id),
        _ => Err(DbError::LeaseRequired(
            "this operation opens a transaction/savepoint and requires an active lease".to_owned(),
        )),
    }
}

/// Whether `s` is a simple unquoted SQL identifier (letter, then
/// letters/digits/`_`/`$`/`#`).
fn is_simple_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '#'))
        && s.len() <= 30
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{OracleBind, OracleConnectionInfo, OracleRow};
    use asupersync::runtime::RuntimeBuilder;

    #[derive(Default)]
    struct MockLog {
        executed: Vec<String>,
        /// (sql, binds) for assertions on the values bound per statement.
        executed_binds: Vec<(String, Vec<OracleBind>)>,
        commits: u32,
        rollbacks: u32,
    }

    struct MockConn {
        log: Arc<Mutex<MockLog>>,
    }

    struct CancelAfterPreviewExecuteConn {
        log: Arc<Mutex<MockLog>>,
    }

    struct RollbackToSavepointFailsConn {
        log: Arc<Mutex<MockLog>>,
    }

    struct CommitFailsConn {
        log: Arc<Mutex<MockLog>>,
    }

    struct RollbackFailsConn {
        log: Arc<Mutex<MockLog>>,
    }

    struct FailAfterEffectConn {
        log: Arc<Mutex<MockLog>>,
        fail_sql: &'static str,
        error: DbError,
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for MockConn {
        fn backend(&self) -> crate::types::OracleBackend {
            crate::types::OracleBackend::RustOracle
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
            sql: &str,
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.log.lock().unwrap().executed.push(sql.to_owned());
            Ok(vec![])
        }
        async fn execute(&self, _cx: &Cx, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError> {
            let mut log = self.log.lock().unwrap();
            log.executed.push(sql.to_owned());
            log.executed_binds.push((sql.to_owned(), binds.to_vec()));
            Ok(0)
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            self.log.lock().unwrap().commits += 1;
            Ok(())
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            self.log.lock().unwrap().rollbacks += 1;
            Ok(())
        }
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for FailAfterEffectConn {
        fn backend(&self) -> crate::types::OracleBackend {
            crate::types::OracleBackend::RustOracle
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
            sql: &str,
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.log.lock().unwrap().executed.push(sql.to_owned());
            Ok(vec![])
        }
        async fn execute(&self, _cx: &Cx, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError> {
            let mut log = self.log.lock().unwrap();
            log.executed.push(sql.to_owned());
            log.executed_binds.push((sql.to_owned(), binds.to_vec()));
            if sql == self.fail_sql {
                Err(self.error.clone())
            } else {
                Ok(0)
            }
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            self.log.lock().unwrap().commits += 1;
            Ok(())
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            self.log.lock().unwrap().rollbacks += 1;
            Ok(())
        }
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for CancelAfterPreviewExecuteConn {
        fn backend(&self) -> crate::types::OracleBackend {
            crate::types::OracleBackend::RustOracle
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
            sql: &str,
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.log.lock().unwrap().executed.push(sql.to_owned());
            Ok(vec![])
        }
        async fn execute(&self, cx: &Cx, sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
            // First call (SAVEPOINT) succeeds; the preview UPDATE then trips a
            // cancellation request, modelling a cancel observed mid-preview.
            self.log.lock().unwrap().executed.push(sql.to_owned());
            if sql.starts_with("UPDATE") {
                cx.set_cancel_requested(true);
                return Err(DbError::Cancelled(
                    "test cancellation after preview execute".to_owned(),
                ));
            }
            Ok(7)
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            self.log.lock().unwrap().commits += 1;
            Ok(())
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            self.log.lock().unwrap().rollbacks += 1;
            Ok(())
        }
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for RollbackToSavepointFailsConn {
        fn backend(&self) -> crate::types::OracleBackend {
            crate::types::OracleBackend::RustOracle
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
            sql: &str,
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.log.lock().unwrap().executed.push(sql.to_owned());
            Ok(vec![])
        }
        async fn execute(
            &self,
            _cx: &Cx,
            sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            self.log.lock().unwrap().executed.push(sql.to_owned());
            if sql.starts_with("ROLLBACK TO SAVEPOINT") {
                Err(DbError::Execute("rollback to savepoint failed".to_owned()))
            } else {
                Ok(3)
            }
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            self.log.lock().unwrap().commits += 1;
            Ok(())
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            self.log.lock().unwrap().rollbacks += 1;
            Ok(())
        }
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for CommitFailsConn {
        fn backend(&self) -> crate::types::OracleBackend {
            crate::types::OracleBackend::RustOracle
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
            sql: &str,
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.log.lock().unwrap().executed.push(sql.to_owned());
            Ok(vec![])
        }
        async fn execute(&self, _cx: &Cx, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError> {
            let mut log = self.log.lock().unwrap();
            log.executed.push(sql.to_owned());
            log.executed_binds.push((sql.to_owned(), binds.to_vec()));
            Ok(0)
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            self.log.lock().unwrap().commits += 1;
            Err(DbError::Execute(
                "DPY-4011: commit response lost".to_owned(),
            ))
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            self.log.lock().unwrap().rollbacks += 1;
            Ok(())
        }
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for RollbackFailsConn {
        fn backend(&self) -> crate::types::OracleBackend {
            crate::types::OracleBackend::RustOracle
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
            sql: &str,
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.log.lock().unwrap().executed.push(sql.to_owned());
            Ok(vec![])
        }
        async fn execute(&self, _cx: &Cx, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError> {
            let mut log = self.log.lock().unwrap();
            log.executed.push(sql.to_owned());
            log.executed_binds.push((sql.to_owned(), binds.to_vec()));
            Ok(0)
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            self.log.lock().unwrap().commits += 1;
            Ok(())
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            self.log.lock().unwrap().rollbacks += 1;
            Err(DbError::Execute("rollback socket closed".to_owned()))
        }
    }

    fn mock() -> (Box<dyn OracleConnection>, Arc<Mutex<MockLog>>) {
        let log = Arc::new(Mutex::new(MockLog::default()));
        (Box::new(MockConn { log: log.clone() }), log)
    }

    async fn acquire_fail_after_effect(
        mgr: &LeaseManager,
        cx: &Cx,
        fail_sql: &'static str,
        error: DbError,
    ) -> (LeaseId, Arc<Mutex<MockLog>>) {
        let log = Arc::new(Mutex::new(MockLog::default()));
        let id = mgr
            .acquire(
                cx,
                "dev",
                "a",
                Duration::from_secs(900),
                &[],
                Box::new(FailAfterEffectConn {
                    log: log.clone(),
                    fail_sql,
                    error,
                }),
            )
            .await
            .expect("acquire");
        (id, log)
    }

    fn assert_quarantined_rolled_back(error: &DbError) {
        assert!(
            matches!(
                error,
                DbError::Quarantined {
                    outcome: QuarantineOutcome::RolledBack,
                    ..
                }
            ),
            "{error:?}"
        );
    }

    /// Run an async test body on a fresh current-thread runtime, handing it the
    /// installed request `Cx`.
    fn run_with_cx<F, Fut, T>(body: F) -> T
    where
        F: FnOnce(Cx) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("asupersync test runtime builds");
        runtime.block_on(async move {
            let cx = Cx::current().expect("block_on installs a current Cx");
            body(cx).await
        })
    }

    #[test]
    fn acquire_applies_login_and_stamps_identity() {
        run_with_cx(|cx| async move {
            let mgr = LeaseManager::new();
            let (conn, log) = mock();
            let id = mgr
                .acquire(
                    &cx,
                    "dev",
                    "agent-claude",
                    Duration::from_secs(900),
                    &["ALTER SESSION SET CURRENT_SCHEMA = HR".to_owned()],
                    conn,
                )
                .await
                .expect("acquire");
            {
                let executed = &log.lock().unwrap().executed;
                assert!(
                    executed.iter().any(|s| s.contains("CURRENT_SCHEMA = HR")),
                    "login script applied"
                );
                assert!(
                    executed.iter().any(|s| s.contains("SET_MODULE")),
                    "identity stamped"
                );
            }
            assert_eq!(mgr.active_count(), 1);
            let info = mgr.info(&cx, &id).await.expect("info");
            assert_eq!(info.agent_identity, "agent-claude");
            assert!(!info.in_transaction);
        });
    }

    #[test]
    fn acquire_assigns_monotonic_lease_generation() {
        run_with_cx(|cx| async move {
            let mgr = LeaseManager::new();
            let (conn1, _log1) = mock();
            let first = mgr
                .acquire(&cx, "dev", "agent-a", Duration::from_secs(900), &[], conn1)
                .await
                .expect("first acquire");
            let (conn2, _log2) = mock();
            let second = mgr
                .acquire(&cx, "dev", "agent-b", Duration::from_secs(900), &[], conn2)
                .await
                .expect("second acquire");

            let first_info = mgr.info(&cx, &first).await.expect("first info");
            let second_info = mgr.info(&cx, &second).await.expect("second info");
            assert_eq!(first_info.generation, 1);
            assert_eq!(second_info.generation, 2);
            assert!(second_info.generation > first_info.generation);
        });
    }

    #[test]
    fn session_tag_statements_clear_then_set_live_identity() {
        // A4: the builder always clears first, then sets MODULE/ACTION/
        // CLIENT_INFO/CLIENT_IDENTIFIER to the live agent + model.
        let stmts = session_tag_statements("profile:dev", "claude-opus");
        assert_eq!(stmts.len(), 4, "clear + three sets");

        // 1) The clear step has no binds and resets every tag (incl. identifier).
        assert!(stmts[0].0.contains("SET_MODULE(NULL, NULL)"));
        assert!(stmts[0].0.contains("SET_CLIENT_INFO(NULL)"));
        assert!(stmts[0].0.contains("CLEAR_IDENTIFIER"));
        assert!(stmts[0].1.is_empty());

        // 2) MODULE = oraclemcp, ACTION = agent identity.
        assert!(stmts[1].0.contains("SET_MODULE"));
        assert_eq!(
            stmts[1].1,
            vec![
                OracleBind::from("oraclemcp"),
                OracleBind::from("profile:dev"),
            ]
        );
        // 3) CLIENT_INFO carries both agent and model.
        assert!(stmts[2].0.contains("SET_CLIENT_INFO"));
        assert_eq!(
            stmts[2].1,
            vec![OracleBind::from("agent=profile:dev model=claude-opus")]
        );
        // 4) CLIENT_IDENTIFIER = agent identity.
        assert!(stmts[3].0.contains("SET_IDENTIFIER"));
        assert_eq!(stmts[3].1, vec![OracleBind::from("profile:dev")]);
    }

    #[test]
    fn session_tag_values_are_bounded_and_control_free() {
        // Over-long, newline-bearing identity is truncated and stripped so a tag
        // cannot smuggle newlines into V$SESSION or overflow the Oracle limits.
        let long = format!("agent\n{}", "x".repeat(200));
        let stmts = session_tag_statements(&long, "m");
        let OracleBind::String(action) = &stmts[1].1[1] else {
            panic!("action bind is a string");
        };
        assert!(action.len() <= ACTION_MAX);
        assert!(!action.contains('\n'));
        let OracleBind::String(client_info) = &stmts[2].1[0] else {
            panic!("client_info bind is a string");
        };
        assert!(client_info.chars().count() <= CLIENT_INFO_MAX);
        assert!(!client_info.contains('\n'));
    }

    #[test]
    fn acquire_clears_tags_before_setting_no_cross_request_leak() {
        // A4: on checkout, the clear-and-reset runs BEFORE the live set, so a
        // prior request's CLIENT_IDENTIFIER cannot leak into the next lease.
        run_with_cx(|cx| async move {
            let mgr = LeaseManager::new();
            let (conn, log) = mock();
            let _id = mgr
                .acquire(
                    &cx,
                    "dev",
                    "agent-claude",
                    Duration::from_secs(900),
                    &[],
                    conn,
                )
                .await
                .expect("acquire");
            let executed = &log.lock().unwrap().executed;
            let clear_idx = executed
                .iter()
                .position(|s| s.contains("CLEAR_IDENTIFIER"))
                .expect("clear step present");
            let set_idx = executed
                .iter()
                .position(|s| s.contains("SET_IDENTIFIER"))
                .expect("set step present");
            assert!(
                clear_idx < set_idx,
                "clear ({clear_idx}) must precede set ({set_idx}): {executed:?}"
            );
        });
    }

    #[test]
    fn acquire_binds_live_agent_into_module_action_and_client_info() {
        let (log, _mgr_alive) = run_with_cx(|cx| async move {
            let mgr = LeaseManager::new();
            let (conn, log) = mock();
            let _id = mgr
                .acquire(
                    &cx,
                    "dev",
                    "agent-claude",
                    Duration::from_secs(900),
                    &[],
                    conn,
                )
                .await
                .expect("acquire");
            (log, mgr)
        });
        let binds = log.lock().unwrap().executed_binds.clone();
        // ACTION bind carries the agent identity.
        assert!(
            binds.iter().any(|(sql, b)| sql.contains("SET_MODULE")
                && b == &vec![
                    OracleBind::from("oraclemcp"),
                    OracleBind::from("agent-claude"),
                ]),
            "MODULE/ACTION bound to oraclemcp/agent-claude: {binds:?}"
        );
        // CLIENT_INFO bind carries the agent (and a model label).
        assert!(
            binds.iter().any(|(sql, b)| sql.contains("SET_CLIENT_INFO")
                && matches!(b.first(), Some(OracleBind::String(s)) if s.contains("agent=agent-claude"))),
            "CLIENT_INFO carries the agent identity: {binds:?}"
        );
    }

    #[test]
    fn no_lease_transaction_is_a_structured_error() {
        // P0-4d: a stateful op without a lease must be a structured error.
        let err = require_lease_id(None).unwrap_err();
        assert!(matches!(err, DbError::LeaseRequired(_)));
        assert!(require_lease_id(Some("lease-1-1")).is_ok());
        assert!(matches!(
            require_lease_id(Some("")),
            Err(DbError::LeaseRequired(_))
        ));
    }

    #[test]
    fn commit_and_rollback_route_to_the_pinned_session() {
        run_with_cx(|cx| async move {
            let mgr = LeaseManager::new();
            let (conn, log) = mock();
            let id = mgr
                .acquire(&cx, "dev", "a", Duration::from_secs(900), &[], conn)
                .await
                .expect("acquire");
            mgr.begin_transaction(&cx, &id).await.expect("begin");
            assert!(mgr.info(&cx, &id).await.unwrap().in_transaction);
            mgr.commit(&cx, &id).await.expect("commit");
            assert!(!mgr.info(&cx, &id).await.unwrap().in_transaction);
            mgr.begin_transaction(&cx, &id).await.expect("begin2");
            mgr.rollback(&cx, &id).await.expect("rollback");
            let log = log.lock().unwrap();
            assert_eq!(log.commits, 1);
            assert_eq!(log.rollbacks, 1);
        });
    }

    #[test]
    fn commit_failure_discards_lease_as_commit_in_doubt() {
        run_with_cx(|cx| async move {
            let mgr = LeaseManager::new();
            let log = Arc::new(Mutex::new(MockLog::default()));
            let id = mgr
                .acquire(
                    &cx,
                    "dev",
                    "a",
                    Duration::from_secs(900),
                    &[],
                    Box::new(CommitFailsConn { log: log.clone() }),
                )
                .await
                .expect("acquire");
            mgr.begin_transaction(&cx, &id).await.expect("begin");
            let err = mgr
                .commit(&cx, &id)
                .await
                .expect_err("lost commit response is in doubt");
            assert!(
                matches!(
                    err,
                    DbError::Quarantined {
                        outcome: QuarantineOutcome::CommitInDoubt,
                        ..
                    }
                ),
                "{err:?}"
            );
            assert_eq!(log.lock().unwrap().commits, 1);
            assert_eq!(mgr.active_count(), 0, "in-doubt commit quarantines lease");
            assert!(
                mgr.info(&cx, &id).await.is_err(),
                "quarantined lease is never reused"
            );
        });
    }

    #[test]
    fn rollback_failure_discards_lease_as_unknown() {
        run_with_cx(|cx| async move {
            let mgr = LeaseManager::new();
            let log = Arc::new(Mutex::new(MockLog::default()));
            let id = mgr
                .acquire(
                    &cx,
                    "dev",
                    "a",
                    Duration::from_secs(900),
                    &[],
                    Box::new(RollbackFailsConn { log: log.clone() }),
                )
                .await
                .expect("acquire");
            mgr.begin_transaction(&cx, &id).await.expect("begin");
            let err = mgr
                .rollback(&cx, &id)
                .await
                .expect_err("rollback failure quarantines");
            assert!(
                matches!(
                    err,
                    DbError::Quarantined {
                        outcome: QuarantineOutcome::UnknownDiscarded,
                        ..
                    }
                ),
                "{err:?}"
            );
            assert_eq!(log.lock().unwrap().rollbacks, 1);
            assert_eq!(mgr.active_count(), 0, "rollback failure drops lease");
        });
    }

    #[test]
    fn expired_lease_forces_rollback_and_is_unusable() {
        // P0-4b: monotonic TTL; on expiry, force rollback + return.
        run_with_cx(|cx| async move {
            let mgr = LeaseManager::new();
            let (conn, log) = mock();
            // Zero TTL => already expired on the monotonic clock.
            let id = mgr
                .acquire(&cx, "dev", "a", Duration::from_secs(0), &[], conn)
                .await
                .expect("acquire");
            // begin_transaction should reap the already-expired lease.
            let err = mgr.begin_transaction(&cx, &id).await.unwrap_err();
            assert!(matches!(err, DbError::LeaseNotFound(_)));
            assert_eq!(mgr.active_count(), 0, "expired lease was reaped");
            assert_eq!(log.lock().unwrap().commits, 0);
        });
    }

    #[test]
    fn reap_expired_cleans_open_transactions() {
        run_with_cx(|cx| async move {
            let mgr = LeaseManager::new();
            let (conn, log) = mock();
            let id = mgr
                .acquire(&cx, "dev", "a", Duration::from_secs(900), &[], conn)
                .await
                .expect("acquire");
            mgr.begin_transaction(&cx, &id).await.expect("begin");
            let (conn2, log2) = mock();
            let id2 = mgr
                .acquire(&cx, "dev", "b", Duration::from_secs(0), &[], conn2)
                .await
                .expect("acquire2");
            let reaped = mgr.reap_expired(&cx).await;
            assert!(reaped >= 1);
            assert!(mgr.info(&cx, &id).await.is_ok());
            assert!(mgr.info(&cx, &id2).await.is_err());
            let _ = (log, log2);
        });
    }

    #[test]
    fn cloned_handle_cannot_cross_release_linearization_point() {
        run_with_cx(|cx| async move {
            let mgr = LeaseManager::new();
            let (conn, log) = mock();
            let id = mgr
                .acquire(&cx, "dev", "a", Duration::from_secs(900), &[], conn)
                .await
                .expect("acquire");
            mgr.begin_transaction(&cx, &id).await.expect("begin");
            let stale = mgr.lease_arc(&id.0).expect("prevalidated handle");

            mgr.release(&cx, &id).await;
            let mut stale_lease = stale.lock(&cx).await.expect("stale handle lock");
            let error = mgr
                .validate_locked(&cx, &id.0, &stale, &mut stale_lease)
                .await
                .expect_err("released handle must stay revoked");
            assert!(matches!(error, DbError::LeaseNotFound(_)));
            drop(stale_lease);

            assert_eq!(log.lock().unwrap().rollbacks, 1, "release rolls back once");
            assert!(mgr.savepoint(&cx, &id, "late").await.is_err());
            assert_eq!(
                log.lock().unwrap().rollbacks,
                1,
                "stale work cannot clean twice"
            );
            assert_eq!(
                mgr.release_all(&cx).await,
                0,
                "revoked lease is not redrained"
            );
        });
    }

    #[test]
    fn savepoint_name_is_validated() {
        run_with_cx(|cx| async move {
            let mgr = LeaseManager::new();
            let (conn, _log) = mock();
            let id = mgr
                .acquire(&cx, "dev", "a", Duration::from_secs(900), &[], conn)
                .await
                .expect("acquire");
            assert!(mgr.savepoint(&cx, &id, "sp1").await.is_ok());
            assert!(mgr.savepoint(&cx, &id, "sp1; DROP TABLE t").await.is_err());
            assert!(mgr.savepoint(&cx, &id, "1bad").await.is_err());
        });
    }

    #[test]
    fn apply_session_statement_rechecks_alter_session_allowlist() {
        run_with_cx(|cx| async move {
            let mgr = LeaseManager::new();
            let (conn, log) = mock();
            let id = mgr
                .acquire(&cx, "dev", "a", Duration::from_secs(900), &[], conn)
                .await
                .expect("acquire");

            let err = mgr
                .apply_session_statement(&cx, &id, "ALTER SESSION SET CONTAINER = CDB$ROOT")
                .await
                .expect_err("forbidden alter session must be rejected in lease layer");
            assert!(matches!(err, DbError::UnsupportedFeature(_)), "{err:?}");
            assert!(
                !log.lock()
                    .unwrap()
                    .executed
                    .iter()
                    .any(|sql| sql.contains("CONTAINER = CDB$ROOT")),
                "forbidden statement must not reach the database"
            );

            mgr.apply_session_statement(&cx, &id, "ALTER SESSION SET CURRENT_SCHEMA = HR")
                .await
                .expect("allowlisted alter session");
            assert!(
                log.lock()
                    .unwrap()
                    .executed
                    .iter()
                    .any(|sql| sql.contains("CURRENT_SCHEMA = HR")),
                "allowlisted statement reaches the pinned session"
            );
        });
    }

    #[test]
    fn uncertain_savepoint_response_revokes_and_rolls_back_lease() {
        run_with_cx(|cx| async move {
            let mgr = LeaseManager::new();
            let (id, log) = acquire_fail_after_effect(
                &mgr,
                &cx,
                "SAVEPOINT SP_CANCEL",
                DbError::Cancelled("response lost after savepoint effect".to_owned()),
            )
            .await;

            let error = mgr
                .savepoint(&cx, &id, "SP_CANCEL")
                .await
                .expect_err("uncertain savepoint is quarantined");
            assert_quarantined_rolled_back(&error);
            assert_eq!(mgr.active_count(), 0);
            assert_eq!(log.lock().unwrap().rollbacks, 1);
            let calls = log.lock().unwrap().executed.len();
            assert!(mgr.savepoint(&cx, &id, "LATE").await.is_err());
            assert_eq!(log.lock().unwrap().executed.len(), calls);
        });
    }

    #[test]
    fn uncertain_dbms_output_response_revokes_open_transaction() {
        run_with_cx(|cx| async move {
            let mgr = LeaseManager::new();
            let (id, log) = acquire_fail_after_effect(
                &mgr,
                &cx,
                "BEGIN DBMS_OUTPUT.ENABLE(NULL); END;",
                DbError::Cancelled("response lost after DBMS_OUTPUT effect".to_owned()),
            )
            .await;
            mgr.begin_transaction(&cx, &id).await.expect("begin");

            let error = mgr
                .enable_dbms_output(&cx, &id)
                .await
                .expect_err("uncertain enablement is quarantined");
            assert_quarantined_rolled_back(&error);
            assert_eq!(mgr.active_count(), 0);
            assert_eq!(log.lock().unwrap().rollbacks, 1);
            assert!(mgr.info(&cx, &id).await.is_err());
        });
    }

    #[test]
    fn uncertain_alter_session_response_revokes_open_transaction() {
        const ALTER: &str = "ALTER SESSION SET CURRENT_SCHEMA = HR";
        run_with_cx(|cx| async move {
            let mgr = LeaseManager::new();
            let (id, log) = acquire_fail_after_effect(
                &mgr,
                &cx,
                ALTER,
                DbError::Cancelled("response lost after ALTER SESSION effect".to_owned()),
            )
            .await;
            mgr.begin_transaction(&cx, &id).await.expect("begin");

            let error = mgr
                .apply_session_statement(&cx, &id, ALTER)
                .await
                .expect_err("uncertain ALTER SESSION is quarantined");
            assert_quarantined_rolled_back(&error);
            assert_eq!(mgr.active_count(), 0);
            assert_eq!(log.lock().unwrap().rollbacks, 1);
            assert!(mgr.info(&cx, &id).await.is_err());
        });
    }

    #[test]
    fn uncertain_preview_savepoint_response_revokes_and_rolls_back() {
        run_with_cx(|cx| async move {
            let mgr = LeaseManager::new();
            let (id, log) = acquire_fail_after_effect(
                &mgr,
                &cx,
                "SAVEPOINT oraclemcp_preview",
                DbError::Cancelled("response lost after preview savepoint".to_owned()),
            )
            .await;

            let error = mgr
                .preview_dml(&cx, &id, "UPDATE employees SET name = name", &[])
                .await
                .expect_err("uncertain preview savepoint is quarantined");
            assert_quarantined_rolled_back(&error);
            assert_eq!(mgr.active_count(), 0);
            assert_eq!(log.lock().unwrap().rollbacks, 1);
            assert!(
                !log.lock()
                    .unwrap()
                    .executed
                    .iter()
                    .any(|sql| sql.starts_with("UPDATE")),
                "preview DML never runs after an uncertain savepoint"
            );
        });
    }

    #[test]
    fn deterministic_session_error_keeps_lease_reusable() {
        const ALTER: &str = "ALTER SESSION SET CURRENT_SCHEMA = HR";
        run_with_cx(|cx| async move {
            let mgr = LeaseManager::new();
            let (id, log) = acquire_fail_after_effect(
                &mgr,
                &cx,
                ALTER,
                DbError::Execute("ORA-00922: missing or invalid option".to_owned()),
            )
            .await;

            let error = mgr
                .apply_session_statement(&cx, &id, ALTER)
                .await
                .expect_err("deterministic Oracle error is returned");
            assert!(matches!(error, DbError::Execute(_)));
            assert!(!error.is_uncertain_session_state());
            assert_eq!(mgr.active_count(), 1);
            mgr.savepoint(&cx, &id, "AFTER_ERROR")
                .await
                .expect("known-safe failure leaves lease reusable");
            assert_eq!(log.lock().unwrap().rollbacks, 0);
        });
    }

    #[test]
    fn renew_resets_the_deadline() {
        run_with_cx(|cx| async move {
            let mgr = LeaseManager::new();
            let (conn, _log) = mock();
            let id = mgr
                .acquire(&cx, "dev", "a", Duration::from_secs(900), &[], conn)
                .await
                .expect("acquire");
            let before = mgr.info(&cx, &id).await.unwrap().expires_in_ms;
            let renewed = mgr.renew(&cx, &id).await.expect("renew");
            assert!(renewed.expires_in_ms > 0);
            // Roughly the full TTL again.
            assert!(renewed.expires_in_ms >= before.saturating_sub(1000));
        });
    }

    #[test]
    fn preview_dml_rolls_back_to_savepoint_after_cancellation() {
        run_with_cx(|cx| async move {
            let mgr = LeaseManager::new();
            let log = Arc::new(Mutex::new(MockLog::default()));
            let id = mgr
                .acquire(
                    &cx,
                    "dev",
                    "a",
                    Duration::from_secs(900),
                    &[],
                    Box::new(CancelAfterPreviewExecuteConn { log: log.clone() }),
                )
                .await
                .expect("acquire");
            let err = mgr
                .preview_dml(
                    &cx,
                    &id,
                    "UPDATE employees SET name = name WHERE employee_id = :1",
                    &[OracleBind::I64(100)],
                )
                .await
                .expect_err("preview cancellation is surfaced");
            assert!(
                matches!(
                    err,
                    DbError::Quarantined {
                        outcome: QuarantineOutcome::RolledBack,
                        ..
                    }
                ),
                "{err:?}"
            );

            let executed = log.lock().unwrap().executed.clone();
            assert!(
                executed
                    .iter()
                    .any(|sql| sql == "UPDATE employees SET name = name WHERE employee_id = :1"),
                "preview DML reached the mocked database"
            );
            assert!(
                executed
                    .iter()
                    .any(|sql| sql == "ROLLBACK TO SAVEPOINT oraclemcp_preview"),
                "rollback-to-savepoint runs even after cancellation"
            );
            assert_eq!(
                mgr.active_count(),
                0,
                "B1c: a cancelled preview discards the lease even when savepoint cleanup succeeds"
            );
        });
    }

    #[test]
    fn preview_dml_discards_lease_when_savepoint_cleanup_fails() {
        run_with_cx(|cx| async move {
            let mgr = LeaseManager::new();
            let log = Arc::new(Mutex::new(MockLog::default()));
            let id = mgr
                .acquire(
                    &cx,
                    "dev",
                    "a",
                    Duration::from_secs(900),
                    &[],
                    Box::new(RollbackToSavepointFailsConn { log: log.clone() }),
                )
                .await
                .expect("acquire");
            let err = mgr
                .preview_dml(
                    &cx,
                    &id,
                    "DELETE FROM employees WHERE employee_id = :1",
                    &[OracleBind::I64(100)],
                )
                .await
                .expect_err("cleanup failure is surfaced");
            assert!(
                matches!(
                    err,
                    DbError::Quarantined {
                        outcome: QuarantineOutcome::RolledBack,
                        ..
                    }
                ),
                "{err:?}"
            );
            assert_eq!(
                log.lock().unwrap().rollbacks,
                1,
                "cleanup failure falls back to a full rollback before dropping the lease"
            );
            assert_eq!(
                mgr.active_count(),
                0,
                "uncertain preview cleanup removes the lease from reuse"
            );
            assert!(
                mgr.info(&cx, &id).await.is_err(),
                "discarded lease is no longer usable"
            );
        });
    }
}
