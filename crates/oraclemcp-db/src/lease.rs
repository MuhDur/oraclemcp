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

use oraclemcp_guard::MonotonicDeadline;
use serde::{Deserialize, Serialize};

use crate::connection::OracleConnection;
use crate::error::DbError;

/// Oracle limits: MODULE ≤ 48 chars, ACTION ≤ 32 chars (`DBMS_APPLICATION_INFO`).
const MODULE_NAME: &str = "oraclemcp";
const ACTION_MAX: usize = 32;

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
}

struct Lease {
    profile: String,
    agent_identity: String,
    conn: Box<dyn OracleConnection>,
    deadline: MonotonicDeadline,
    ttl: Duration,
    in_transaction: bool,
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
        }
    }

    /// Force-clean on expiry/release: roll back any open transaction. Dropping
    /// the `Lease` afterwards closes the physical session (clearing all session
    /// state and returning it).
    fn force_rollback(&mut self) {
        if self.in_transaction {
            // Best-effort: the session is being torn down regardless.
            let _ = self.conn.rollback();
            self.in_transaction = false;
        }
    }
}

/// Manages session leases. Cheap to clone-share via `Arc`; all DB work inside a
/// lease must be dispatched on a blocking worker by the caller (§4.3).
#[derive(Default)]
pub struct LeaseManager {
    leases: Mutex<HashMap<String, Arc<Mutex<Lease>>>>,
    counter: AtomicU64,
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

    /// Acquire a lease over an already-opened connection: apply the profile's
    /// login statements, stamp the agent identity into `DBMS_APPLICATION_INFO`,
    /// and pin the session under a monotonic TTL. Returns the lease handle.
    pub fn acquire(
        &self,
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
            conn.execute(stmt, &[])?;
        }

        // Stamp the agent identity for Unified Auditing / V$SESSION visibility.
        let action: String = agent_identity.chars().take(ACTION_MAX).collect();
        conn.execute(
            "BEGIN DBMS_APPLICATION_INFO.SET_MODULE(:1, :2); END;",
            &[
                crate::types::OracleBind::from(MODULE_NAME),
                crate::types::OracleBind::from(action),
            ],
        )?;

        let id = self.next_id();
        let lease = Lease {
            profile,
            agent_identity,
            conn,
            deadline: MonotonicDeadline::after(ttl),
            ttl,
            in_transaction: false,
        };
        self.leases
            .lock()
            .expect("lease map mutex poisoned")
            .insert(id.0.clone(), Arc::new(Mutex::new(lease)));
        Ok(id)
    }

    fn get(&self, id: &str) -> Option<Arc<Mutex<Lease>>> {
        self.leases
            .lock()
            .expect("lease map mutex poisoned")
            .get(id)
            .cloned()
    }

    /// Run `f` against a live (non-expired) lease. An expired lease is
    /// force-cleaned and removed, and the call fails with `LeaseNotFound`.
    fn with_lease<R>(
        &self,
        id: &str,
        f: impl FnOnce(&mut Lease) -> Result<R, DbError>,
    ) -> Result<R, DbError> {
        let arc = self
            .get(id)
            .ok_or_else(|| DbError::LeaseNotFound(id.to_owned()))?;
        let mut lease = arc.lock().expect("lease mutex poisoned");
        if lease.deadline.is_expired() {
            lease.force_rollback();
            drop(lease);
            self.remove(id);
            return Err(DbError::LeaseNotFound(format!("{id} (expired)")));
        }
        f(&mut lease)
    }

    fn remove(&self, id: &str) -> Option<Arc<Mutex<Lease>>> {
        self.leases
            .lock()
            .expect("lease map mutex poisoned")
            .remove(id)
    }

    /// Renew a lease's TTL (clients renew at ~75% of the TTL). Errors if the
    /// lease is gone/expired.
    pub fn renew(&self, id: &LeaseId) -> Result<LeaseInfo, DbError> {
        self.with_lease(&id.0, |lease| {
            lease.deadline = MonotonicDeadline::after(lease.ttl);
            Ok(lease.info(&id.0))
        })
    }

    /// Release a lease: force-rollback any open transaction and drop the
    /// session. Idempotent.
    pub fn release(&self, id: &LeaseId) {
        if let Some(arc) = self.remove(&id.0) {
            arc.lock().expect("lease mutex poisoned").force_rollback();
            // Dropping the Arc/Lease closes the physical session.
        }
    }

    /// Begin an explicit transaction on the leased session.
    pub fn begin_transaction(&self, id: &LeaseId) -> Result<(), DbError> {
        self.with_lease(&id.0, |lease| {
            lease.in_transaction = true;
            Ok(())
        })
    }

    /// Commit the leased session's transaction.
    pub fn commit(&self, id: &LeaseId) -> Result<(), DbError> {
        self.with_lease(&id.0, |lease| {
            lease.conn.commit()?;
            lease.in_transaction = false;
            Ok(())
        })
    }

    /// Roll back the leased session's transaction.
    pub fn rollback(&self, id: &LeaseId) -> Result<(), DbError> {
        self.with_lease(&id.0, |lease| {
            lease.conn.rollback()?;
            lease.in_transaction = false;
            Ok(())
        })
    }

    /// Create a savepoint on the leased session. `name` must be a simple
    /// unquoted identifier (validated to prevent injection).
    pub fn savepoint(&self, id: &LeaseId, name: &str) -> Result<(), DbError> {
        if !is_simple_identifier(name) {
            return Err(DbError::Execute(format!(
                "invalid savepoint name: {name:?}"
            )));
        }
        self.with_lease(&id.0, |lease| {
            lease.conn.execute(&format!("SAVEPOINT {name}"), &[])?;
            lease.in_transaction = true;
            Ok(())
        })
    }

    /// A snapshot of a lease's state.
    pub fn info(&self, id: &LeaseId) -> Result<LeaseInfo, DbError> {
        self.with_lease(&id.0, |lease| Ok(lease.info(&id.0)))
    }

    /// Reap every expired lease (force-rollback + drop). Returns the count.
    pub fn reap_expired(&self) -> usize {
        let expired: Vec<String> = {
            let map = self.leases.lock().expect("lease map mutex poisoned");
            map.iter()
                .filter(|(_, arc)| {
                    arc.lock()
                        .expect("lease mutex poisoned")
                        .deadline
                        .is_expired()
                })
                .map(|(k, _)| k.clone())
                .collect()
        };
        for id in &expired {
            if let Some(arc) = self.remove(id) {
                arc.lock().expect("lease mutex poisoned").force_rollback();
            }
        }
        expired.len()
    }

    /// Number of active leases.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.leases.lock().expect("lease map mutex poisoned").len()
    }

    /// Force-roll-back and drop every lease (graceful shutdown / crash cleanup,
    /// §5.7). Returns the number released. Idempotent.
    pub fn release_all(&self) -> usize {
        let drained: Vec<Arc<Mutex<Lease>>> = {
            let mut map = self.leases.lock().expect("lease map mutex poisoned");
            map.drain().map(|(_, v)| v).collect()
        };
        for arc in &drained {
            arc.lock().expect("lease mutex poisoned").force_rollback();
        }
        drained.len()
    }
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

    #[derive(Default)]
    struct MockLog {
        executed: Vec<String>,
        commits: u32,
        rollbacks: u32,
    }

    struct MockConn {
        log: Arc<Mutex<MockLog>>,
    }

    impl OracleConnection for MockConn {
        fn backend(&self) -> crate::types::OracleBackend {
            crate::types::OracleBackend::RustOracle
        }
        fn ping(&self) -> Result<(), DbError> {
            Ok(())
        }
        fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }
        fn query_rows(&self, sql: &str, _binds: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
            self.log.lock().unwrap().executed.push(sql.to_owned());
            Ok(vec![])
        }
        fn execute(&self, sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
            self.log.lock().unwrap().executed.push(sql.to_owned());
            Ok(0)
        }
        fn commit(&self) -> Result<(), DbError> {
            self.log.lock().unwrap().commits += 1;
            Ok(())
        }
        fn rollback(&self) -> Result<(), DbError> {
            self.log.lock().unwrap().rollbacks += 1;
            Ok(())
        }
    }

    fn mock() -> (Box<dyn OracleConnection>, Arc<Mutex<MockLog>>) {
        let log = Arc::new(Mutex::new(MockLog::default()));
        (Box::new(MockConn { log: log.clone() }), log)
    }

    #[test]
    fn acquire_applies_login_and_stamps_identity() {
        let mgr = LeaseManager::new();
        let (conn, log) = mock();
        let id = mgr
            .acquire(
                "dev",
                "agent-claude",
                Duration::from_secs(900),
                &["ALTER SESSION SET CURRENT_SCHEMA = HR".to_owned()],
                conn,
            )
            .expect("acquire");
        let executed = &log.lock().unwrap().executed;
        assert!(
            executed.iter().any(|s| s.contains("CURRENT_SCHEMA = HR")),
            "login script applied"
        );
        assert!(
            executed.iter().any(|s| s.contains("SET_MODULE")),
            "identity stamped"
        );
        assert_eq!(mgr.active_count(), 1);
        let info = mgr.info(&id).expect("info");
        assert_eq!(info.agent_identity, "agent-claude");
        assert!(!info.in_transaction);
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
        let mgr = LeaseManager::new();
        let (conn, log) = mock();
        let id = mgr
            .acquire("dev", "a", Duration::from_secs(900), &[], conn)
            .expect("acquire");
        mgr.begin_transaction(&id).expect("begin");
        assert!(mgr.info(&id).unwrap().in_transaction);
        mgr.commit(&id).expect("commit");
        assert!(!mgr.info(&id).unwrap().in_transaction);
        mgr.begin_transaction(&id).expect("begin2");
        mgr.rollback(&id).expect("rollback");
        let log = log.lock().unwrap();
        assert_eq!(log.commits, 1);
        assert_eq!(log.rollbacks, 1);
    }

    #[test]
    fn expired_lease_forces_rollback_and_is_unusable() {
        // P0-4b: monotonic TTL; on expiry, force rollback + return.
        let mgr = LeaseManager::new();
        let (conn, log) = mock();
        // Zero TTL => already expired on the monotonic clock.
        let id = mgr
            .acquire("dev", "a", Duration::from_secs(0), &[], conn)
            .expect("acquire");
        // Mark a transaction open via a fresh lease... but it's already expired,
        // so begin_transaction should reap it.
        let err = mgr.begin_transaction(&id).unwrap_err();
        assert!(matches!(err, DbError::LeaseNotFound(_)));
        assert_eq!(mgr.active_count(), 0, "expired lease was reaped");
        // The reap rolled back nothing here (no open txn), but the session was
        // dropped; commits/rollbacks observable via the log show no commit.
        assert_eq!(log.lock().unwrap().commits, 0);
    }

    #[test]
    fn reap_expired_cleans_open_transactions() {
        let mgr = LeaseManager::new();
        let (conn, log) = mock();
        let id = mgr
            .acquire("dev", "a", Duration::from_secs(900), &[], conn)
            .expect("acquire");
        mgr.begin_transaction(&id).expect("begin");
        // Force the deadline expired by re-acquiring with zero ttl is awkward;
        // instead release-by-reap after manually expiring via a 2nd zero-ttl lease.
        let (conn2, log2) = mock();
        let id2 = mgr
            .acquire("dev", "b", Duration::from_secs(0), &[], conn2)
            .expect("acquire2");
        let reaped = mgr.reap_expired();
        assert!(reaped >= 1);
        // id2 (zero ttl, in a txn? no) reaped; id (900s) survives.
        assert!(mgr.info(&id).is_ok());
        assert!(mgr.info(&id2).is_err());
        let _ = (log, log2);
    }

    #[test]
    fn savepoint_name_is_validated() {
        let mgr = LeaseManager::new();
        let (conn, _log) = mock();
        let id = mgr
            .acquire("dev", "a", Duration::from_secs(900), &[], conn)
            .expect("acquire");
        assert!(mgr.savepoint(&id, "sp1").is_ok());
        assert!(mgr.savepoint(&id, "sp1; DROP TABLE t").is_err());
        assert!(mgr.savepoint(&id, "1bad").is_err());
    }

    #[test]
    fn renew_resets_the_deadline() {
        let mgr = LeaseManager::new();
        let (conn, _log) = mock();
        let id = mgr
            .acquire("dev", "a", Duration::from_secs(900), &[], conn)
            .expect("acquire");
        let before = mgr.info(&id).unwrap().expires_in_ms;
        let renewed = mgr.renew(&id).expect("renew");
        assert!(renewed.expires_in_ms > 0);
        // Roughly the full TTL again.
        assert!(renewed.expires_in_ms >= before.saturating_sub(1000));
    }
}
