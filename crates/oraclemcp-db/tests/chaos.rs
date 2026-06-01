//! Chaos tests — DB-side scenarios (bead T-CHAOS / oracle-qmwz.6.3): lease-TTL
//! expiry/teardown with an open transaction (ASSERT rollback) and credential
//! rotation mid-flight (ASSERT refresh, not failure). Each scenario asserts the
//! safe-degradation behavior in-process; the genuinely-live scenarios (real
//! listener drop, RAC/standby failover) run in the live tagged job, but their
//! safety primitives are exercised here and in the core chaos suite.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use oraclemcp_db::{
    IamToken, IamTokenSource, LeaseManager, OciError, OracleBackend, OracleBind, OracleConnection,
    OracleConnectionInfo, OracleRow, ensure_fresh_token,
};

/// A connection that counts rollbacks — to prove forced rollback on teardown.
struct CountingConn {
    rollbacks: Arc<AtomicUsize>,
}

impl OracleConnection for CountingConn {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    fn ping(&self) -> Result<(), oraclemcp_db::DbError> {
        Ok(())
    }
    fn describe(&self) -> Result<OracleConnectionInfo, oraclemcp_db::DbError> {
        Ok(OracleConnectionInfo::default())
    }
    fn query_rows(
        &self,
        _sql: &str,
        _binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, oraclemcp_db::DbError> {
        Ok(vec![])
    }
    fn execute(&self, _sql: &str, _binds: &[OracleBind]) -> Result<u64, oraclemcp_db::DbError> {
        Ok(0)
    }
    fn commit(&self) -> Result<(), oraclemcp_db::DbError> {
        Ok(())
    }
    fn rollback(&self) -> Result<(), oraclemcp_db::DbError> {
        self.rollbacks.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[test]
fn lease_teardown_with_open_transaction_forces_rollback() {
    // Lease-TTL expiry and explicit release share the same force_rollback path
    // (lease.rs): an open transaction is ALWAYS rolled back when the lease is
    // torn down — a kill/expiry never leaves an in-flight write committed.
    let rollbacks = Arc::new(AtomicUsize::new(0));
    let mgr = LeaseManager::new();
    let conn = Box::new(CountingConn {
        rollbacks: Arc::clone(&rollbacks),
    });
    let id = mgr
        .acquire("dev", "agent-a", Duration::from_secs(900), &[], conn)
        .expect("acquire");
    mgr.begin_transaction(&id).expect("begin txn");
    assert_eq!(mgr.active_count(), 1);

    // Teardown (same path expiry-reaping uses) must force a rollback.
    mgr.release(&id);
    assert_eq!(
        rollbacks.load(Ordering::SeqCst),
        1,
        "open transaction was rolled back on teardown"
    );
    assert_eq!(mgr.active_count(), 0, "lease dropped");
}

#[test]
fn expired_lease_is_reaped() {
    // The reaping mechanic: a zero-TTL lease is expired immediately and reaped.
    let mgr = LeaseManager::new();
    let conn = Box::new(CountingConn {
        rollbacks: Arc::new(AtomicUsize::new(0)),
    });
    let id = mgr
        .acquire("dev", "b", Duration::from_secs(0), &[], conn)
        .expect("acquire");
    assert!(mgr.reap_expired() >= 1, "expired lease reaped");
    assert!(mgr.info(&id).is_err(), "reaped lease is gone");
}

struct OneShotTokenSource {
    calls: Arc<AtomicUsize>,
}
impl IamTokenSource for OneShotTokenSource {
    fn fetch(&self) -> Result<IamToken, OciError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(IamToken {
            token: "rotated".to_owned(),
            expires_at_unix: 10_000,
        })
    }
}

#[test]
fn credential_rotation_mid_flight_refreshes_without_failure() {
    // An IAM database token nearing expiry mid-session is proactively refreshed
    // (not allowed to fail an in-flight call).
    let calls = Arc::new(AtomicUsize::new(0));
    let src = OneShotTokenSource {
        calls: Arc::clone(&calls),
    };
    let stale = IamToken {
        token: "old".to_owned(),
        expires_at_unix: 1000,
    };

    // now is within the 60s skew of expiry -> rotate.
    let fresh = ensure_fresh_token(Some(&stale), &src, 950, 60).expect("rotation succeeds");
    assert_eq!(fresh.token, "rotated");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "rotated exactly once mid-flight"
    );

    // A token with ample headroom is reused (no needless rotation).
    let reused = ensure_fresh_token(Some(&fresh), &src, 1000, 60).expect("reuse");
    assert_eq!(reused.token, "rotated");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "no extra fetch when fresh");
}
