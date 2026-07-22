//! D5 — the idle-kill lane: prove the server survives a session killed out from
//! under its stateless pool.
//!
//! The pooled and pinned surfaces are not the same code path and must not be
//! proven by the same test (plan §A.6.9 settles the architecture: **the pinned
//! session is NOT pooled** — it is a single long-lived connection whose only
//! recovery today is an explicit profile switch, and the field's P0-5 symptom
//! ran on that path):
//!
//! - **pooled** (A4a, validate-on-checkout): a dead session must be replaced
//!   transparently. The caller holds no session state, so silence is correct.
//! - **pinned** (A4e, audited recycle): covered at the dispatcher surface in
//!   `crates/oraclemcp/tests/live_dispatcher_idle_kill.rs`, because the
//!   production pinned session is `DispatcherState.conn`, not the deleted test
//!   lease subsystem.
//!
//! Run against the rig: `bash scripts/rig/oracle_l1.sh up` then
//! `cargo test -p oraclemcp-db --features live-xe --test live_idle_kill`,
//! with ORACLEMCP_TEST_DSN / _USER / _PASSWORD pointed at the lane.
//!
//! Killing requires ALTER SYSTEM, which the rig's admin principal holds.
//!
//! # The lane can fail on purpose
//!
//! `ORACLEMCP_D5_SKIP_KILL=1` runs everything EXCEPT the kill. The pooled lane
//! must then FAIL because the same `(sid, serial#)` comes back. A lane whose
//! kill silently stopped landing would otherwise go green forever while proving
//! nothing.
//!
//! # What this lane found on first run (XE21, 2026-07-21)
//!
//! The predicted pre-fix failure DID NOT REPRODUCE. Both surfaces already
//! behave correctly, for reasons that are deliberate rather than lucky:
//!
//! - pooled: `OraclePool::with_conn` already carries
//!   `RetryPolicy::one_immediate_retry` with `ReconnectThenRetry`, and discards
//!   a session whose error `is_uncertain_session_state`. The caller saw
//!   sid 313 serial 7915 replaced by sid 313 serial 42101 and no error. Note
//!   this is reconnect-THEN-REPLAY, not validate-on-checkout: the recovery runs
//!   after the caller's statement has already failed once, which is only safe
//!   for a replayable statement. A4a moves the check earlier; it does not
//!   introduce recovery that was missing.
//! A prior version of this lane asserted the pinned half through the removed
//! `LeaseManager` subsystem. That was vacuous because no production tool used
//! that subsystem; keep pinned-session assertions on the real dispatcher state.

#![cfg(feature = "live-xe")]
#![forbid(unsafe_code)]

use asupersync::Cx;
use asupersync::runtime::RuntimeBuilder;
use oraclemcp_db::{
    OracleConnectOptions, OracleConnection, OraclePool, PoolSettings, RustOracleConnection,
};

/// Run an async body on a fresh current-thread runtime with a reactor, handing
/// it the installed request `Cx`. The only `block_on` in this file.
fn run_with_cx<F, Fut, T>(body: F) -> T
where
    F: FnOnce(Cx) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
    let runtime = RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("rt");
    runtime.block_on(async move {
        let cx = Cx::current().expect("block_on installs a current Cx");
        body(cx).await
    })
}

fn test_opts() -> OracleConnectOptions {
    OracleConnectOptions {
        connect_string: std::env::var("ORACLEMCP_TEST_DSN")
            .unwrap_or_else(|_| "//localhost:1521/FREEPDB1".to_owned()),
        username: Some(
            std::env::var("ORACLEMCP_TEST_USER").unwrap_or_else(|_| "system".to_owned()),
        ),
        password: Some(
            std::env::var("ORACLEMCP_TEST_PASSWORD").unwrap_or_else(|_| "test_password".to_owned()),
        ),
        ..Default::default()
    }
}

/// A session's `(sid, serial#)`, the pair `ALTER SYSTEM KILL SESSION` needs.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SessionKey {
    sid: String,
    serial: String,
}

impl SessionKey {
    /// Both halves come back from `v$session` as NUMBER-as-string (the
    /// NUMBER->string invariant). Refuse anything else rather than interpolate
    /// unvalidated text into an ALTER SYSTEM statement, which takes no binds.
    fn checked(sid: String, serial: String) -> Self {
        assert!(
            sid.chars().all(|c| c.is_ascii_digit()) && !sid.is_empty(),
            "v$session.sid must be numeric, got {sid:?}"
        );
        assert!(
            serial.chars().all(|c| c.is_ascii_digit()) && !serial.is_empty(),
            "v$session.serial# must be numeric, got {serial:?}"
        );
        SessionKey { sid, serial }
    }
}

const OWN_SESSION: &str = "SELECT sid AS s_id, serial# AS s_serial FROM v$session \
     WHERE sid = SYS_CONTEXT('USERENV', 'SID')";

/// Kill a session from a SECOND connection, the way an DBA or a resource
/// manager policy would. IMMEDIATE so the victim learns on its next use rather
/// than at PMON's convenience.
async fn kill_session(cx: &Cx, admin: &RustOracleConnection, key: &SessionKey) {
    let sql = format!(
        "ALTER SYSTEM KILL SESSION '{},{}' IMMEDIATE",
        key.sid, key.serial
    );
    admin
        .execute(cx, &sql, &[])
        .await
        .expect("ALTER SYSTEM KILL SESSION requires the rig admin principal");
}

/// POOLED SURFACE (A4a). A caller that checks a connection out of the pool holds
/// no session state, so a dead session must be replaced without the caller ever
/// seeing it.
///
/// ANTI-VACUITY: the pool is pinned to exactly one connection. With the default
/// sizing the next checkout could hand back a DIFFERENT, still-live connection
/// and the test would pass while validate-on-checkout did nothing at all.
#[test]
fn a_killed_pooled_session_is_replaced_without_the_caller_seeing_it() {
    run_with_cx(|cx| async move {
        let admin = RustOracleConnection::connect(&cx, test_opts())
            .await
            .expect("admin connection for the kill");
        let pool = OraclePool::connect(
            &cx,
            test_opts(),
            PoolSettings {
                max_size: 1,
                min_idle: 1,
                ..PoolSettings::default()
            },
        )
        .await
        .expect("pool connect");

        let rows = pool
            .query_rows(&cx, OWN_SESSION, Vec::new())
            .await
            .expect("the pooled session can identify itself before the kill");
        let victim = SessionKey::checked(
            rows[0].text("S_ID").expect("sid").to_owned(),
            rows[0].text("S_SERIAL").expect("serial#").to_owned(),
        );

        if std::env::var("ORACLEMCP_D5_SKIP_KILL").is_err() {
            kill_session(&cx, &admin, &victim).await;
        }

        // The caller's next use. Post-fix this succeeds on a replacement
        // session; pre-fix it surfaces the raw transport error (the recorded
        // failing half of the two-sided proof).
        let after = pool.query_rows(&cx, OWN_SESSION, Vec::new()).await;
        let after = match after {
            Ok(rows) => rows,
            Err(err) => panic!(
                "pooled: validate-on-checkout must replace a session killed while idle, \
                 but the caller saw the death directly: {err:?}"
            ),
        };
        let replacement = SessionKey::checked(
            after[0].text("S_ID").expect("sid").to_owned(),
            after[0].text("S_SERIAL").expect("serial#").to_owned(),
        );
        eprintln!("D5 pooled: victim={victim:?} replacement={replacement:?}");

        // The detector: a pool that handed back the SAME (sid, serial#) did not
        // replace anything, so the kill did not land and this test proves
        // nothing. Assert the precondition rather than trusting it.
        assert_ne!(
            replacement, victim,
            "pooled: the post-kill session is the pre-kill session, so the kill never took \
             effect and this lane is not exercising recovery at all"
        );
    });
}
