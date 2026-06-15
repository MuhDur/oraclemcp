//! Chaos tests — core-side scenarios (bead T-CHAOS / oracle-qmwz.6.3): pool
//! exhaustion → structured `BUSY` (never a raw `ORA-12519`), cancel mid-DML →
//! never double-executes, and listener-drop / timeout → classified transient
//! with a circuit breaker that opens to protect a struggling target.

use std::time::Duration;

use asupersync::Cx;
use asupersync::cx::NoCaps;
use oraclemcp_core::error::{ErrorClass, OracleMcpError};
use oraclemcp_core::{
    AdmissionController, CancelOutcome, CircuitBreaker, CircuitState, is_transient_error,
};

#[test]
fn pool_exhaustion_returns_structured_busy_not_raw_ora() {
    // global cap 1, per-agent cap 1: the first call admits, the second is
    // refused with a structured BUSY + retry-after — the agent never sees a raw
    // ORA-12519 "no appropriate service handler".
    let cx = Cx::<NoCaps>::detached_cancel_context();
    let ac = AdmissionController::new(1, 1);
    let _permit = ac.try_admit(&cx, "agent-a").expect("first admitted");
    let err = ac.try_admit(&cx, "agent-a").expect_err("pool exhausted");
    assert!(
        matches!(err, OracleMcpError::Busy { .. }),
        "exhaustion is BUSY, not a raw error"
    );

    let envelope = ac.busy_envelope();
    assert_eq!(envelope.error_class, ErrorClass::Busy);
    assert!(
        envelope.retry_after_ms.is_some(),
        "BUSY carries a retry-after hint"
    );
    // Releasing the permit frees capacity again.
    drop(_permit);
    assert!(
        ac.try_admit(&cx, "agent-a").is_ok(),
        "capacity restored after release"
    );
}

#[test]
fn cancel_mid_dml_never_double_executes() {
    // A mutating statement interrupted mid-flight is NEVER auto-retried (the
    // double-execute guard); only an idempotent read may retry.
    assert!(
        !CancelOutcome::mutating().can_retry,
        "DML must not auto-retry"
    );
    assert!(
        CancelOutcome::read().can_retry,
        "an idempotent read may retry"
    );
}

#[test]
fn listener_drop_and_timeout_are_classified_transient() {
    // The reconnect classifier recognizes the listener/network failure modes.
    for msg in [
        "ORA-03113: end-of-file on communication channel", // listener/conn drop
        "ORA-12541: TNS:no listener",
        "ORA-12170: TNS:Connect timeout occurred",
        "ORA-12514: TNS:listener does not currently know of service",
    ] {
        assert!(
            is_transient_error(msg),
            "{msg} should be transient/retryable"
        );
    }
    // A privilege / object error is NOT transient (must not be retried blindly).
    assert!(!is_transient_error(
        "ORA-00942: table or view does not exist"
    ));
    assert!(!is_transient_error("ORA-01031: insufficient privileges"));
}

#[test]
fn circuit_breaker_opens_after_repeated_failures() {
    // After repeated connection failures the breaker opens, shedding load from a
    // struggling target instead of hammering it (failover/overload protection).
    let cb = CircuitBreaker::new(2, Duration::from_secs(60));
    assert!(cb.allow_request(), "starts closed");
    cb.on_failure();
    cb.on_failure();
    assert_eq!(cb.state(), CircuitState::Open);
    assert!(
        !cb.allow_request(),
        "open breaker sheds load within the cooldown"
    );
}
