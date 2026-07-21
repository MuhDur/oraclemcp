//! Resilience primitives (plan §10; bead P2-RESIL): a circuit breaker, a
//! transient-only retry policy, and a call-timeout helper.
//!
//! Retry law: only the DB adapter's driver-aligned transient taxonomy is
//! retryable, and **DML is never auto-retried** (double-execute risk, §5.7).
//! A misclassification here is fail-safe — when in doubt, do not retry.

use std::time::{Duration, Instant};

use asupersync::time::{timeout as asupersync_timeout, wall_now};
use parking_lot::Mutex;

/// Driver-aligned retry policy re-exported from the DB boundary.
pub use oraclemcp_db::RetryPolicy;

/// Per-round-trip call timeout (§10).
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Whether an Oracle error message is retryable by the driver-aligned DB
/// taxonomy. The reconnect-vs-same-session distinction remains inside the DB
/// layer, which retains the driver's structural signal for raw I/O failures.
pub use oraclemcp_db::is_transient_error;

/// Circuit-breaker state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitState {
    /// Requests flow normally.
    Closed,
    /// Tripped: requests are rejected until the cooldown elapses.
    Open,
    /// A single trial request is allowed through to probe recovery; concurrent
    /// callers are rejected until that probe resolves (success closes the
    /// circuit, failure re-opens it).
    HalfOpen,
}

struct Inner {
    consecutive_failures: u32,
    state: CircuitState,
    opened_at: Option<Instant>,
    /// True while exactly one HalfOpen trial request is outstanding. Set when a
    /// caller is admitted as the probe (the Open→HalfOpen flip); cleared by the
    /// next `on_success`/`on_failure`. While set, further HalfOpen callers are
    /// rejected so a single probe — not a stampede — tests a fragile target.
    probe_in_flight: bool,
}

/// A circuit breaker: opens after `failure_threshold` consecutive failures and
/// stays open for `cooldown`, then half-opens to admit a single trial request
/// that probes recovery — concurrent callers are shed while that probe is in
/// flight, so a struggling target is not stampeded (§10).
pub struct CircuitBreaker {
    failure_threshold: u32,
    cooldown: Duration,
    inner: Mutex<Inner>,
}

impl CircuitBreaker {
    /// A breaker that opens after `failure_threshold` consecutive failures.
    #[must_use]
    pub fn new(failure_threshold: u32, cooldown: Duration) -> Self {
        CircuitBreaker {
            failure_threshold: failure_threshold.max(1),
            cooldown,
            inner: Mutex::new(Inner {
                consecutive_failures: 0,
                state: CircuitState::Closed,
                opened_at: None,
                probe_in_flight: false,
            }),
        }
    }

    /// Whether a request may proceed now. In `Closed` it always admits. In
    /// `Open` it shed-loads until the cooldown elapses, then flips to
    /// `HalfOpen` and admits exactly one trial request (the probe). While that
    /// probe is in flight, further `HalfOpen` callers are rejected; the probe
    /// resolves via the next `on_success` (closes) or `on_failure` (re-opens).
    #[must_use]
    pub fn allow_request(&self) -> bool {
        let mut inner = self.inner.lock();
        match inner.state {
            CircuitState::Closed => true,
            // Already half-open: admit only if no probe is outstanding. The
            // first admitted caller becomes the probe; the rest are shed.
            CircuitState::HalfOpen => {
                if inner.probe_in_flight {
                    false
                } else {
                    inner.probe_in_flight = true;
                    true
                }
            }
            CircuitState::Open => {
                let elapsed = inner
                    .opened_at
                    .map(|t| t.elapsed())
                    .unwrap_or(self.cooldown);
                if elapsed >= self.cooldown {
                    // Flip to half-open and admit this caller as the single probe.
                    inner.state = CircuitState::HalfOpen;
                    inner.probe_in_flight = true;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Record a success: resets the failure count and closes the circuit. A
    /// HalfOpen probe that succeeds resolves here, clearing the probe flag.
    pub fn on_success(&self) {
        let mut inner = self.inner.lock();
        inner.consecutive_failures = 0;
        inner.state = CircuitState::Closed;
        inner.opened_at = None;
        inner.probe_in_flight = false;
    }

    /// Record a failure: trips the circuit at the threshold (or immediately if
    /// probing in HalfOpen). A HalfOpen probe that fails resolves here, clearing
    /// the probe flag and re-opening the circuit (the cooldown must elapse again
    /// before the next single probe is admitted).
    pub fn on_failure(&self) {
        let mut inner = self.inner.lock();
        inner.consecutive_failures += 1;
        let trip = inner.state == CircuitState::HalfOpen
            || inner.consecutive_failures >= self.failure_threshold;
        inner.probe_in_flight = false;
        if trip {
            inner.state = CircuitState::Open;
            inner.opened_at = Some(Instant::now());
        }
    }

    /// The current state (for metrics / tests).
    #[must_use]
    pub fn state(&self) -> CircuitState {
        self.inner.lock().state
    }
}

/// Run `fut` with a deadline; `Err(())` on timeout. The caller maps the timeout
/// to a structured error and (for the DB path) `conn.break_execution()`.
///
/// # Errors
/// Returns `Err(())` if `fut` does not complete within `timeout`.
pub async fn run_with_timeout<F, T>(timeout: Duration, fut: F) -> Result<T, ()>
where
    F: std::future::Future<Output = T>,
{
    asupersync_timeout(wall_now(), timeout, fut)
        .await
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::runtime::RuntimeBuilder;
    use std::future::Future;
    use std::panic::AssertUnwindSafe;
    use std::sync::mpsc;

    fn run_asupersync_test<F>(future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                let runtime = RuntimeBuilder::current_thread()
                    .build()
                    .expect("asupersync current-thread test runtime builds");
                runtime.block_on(future);
            }));
            let _ = tx.send(result.map_err(|_| "asupersync test future panicked"));
        });
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => handle.join().expect("asupersync test thread joins"),
            Ok(Err(message)) => panic!("{message}"),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("asupersync test future did not complete within 5s")
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("asupersync test thread disconnected")
            }
        }
    }

    #[test]
    fn transient_classification() {
        assert!(is_transient_error(
            "ORA-03113: end-of-file on communication channel"
        ));
        assert!(is_transient_error(
            "ORA-00028: your session has been killed"
        ));
        assert!(is_transient_error(
            "ORA-04068: existing state of packages has been discarded"
        ));
        assert!(!is_transient_error(
            "ORA-00942: table or view does not exist"
        ));
        assert!(
            !is_transient_error("ORA-12541: TNS:no listener"),
            "listener reachability is not a lost in-session connection"
        );
        assert!(!is_transient_error("ORA-01403: no data found"));
        assert!(!is_transient_error("not an oracle error"));
    }

    #[test]
    fn retry_policy_only_retries_transient_reads() {
        let p = RetryPolicy::default();
        // Transient read, attempt 1 -> retry with base delay.
        assert_eq!(
            p.next_delay(1, false, "ORA-03113"),
            Some(Duration::from_millis(100))
        );
        // Attempt 2 -> doubled.
        assert_eq!(
            p.next_delay(2, false, "ORA-03113"),
            Some(Duration::from_millis(200))
        );
        // Mutating -> never retry, even if transient.
        assert_eq!(p.next_delay(1, true, "ORA-03113"), None);
        // Non-transient -> never retry.
        assert_eq!(p.next_delay(1, false, "ORA-00942"), None);
        // Final attempt -> no further retry.
        assert_eq!(p.next_delay(3, false, "ORA-03113"), None);
    }

    #[test]
    fn circuit_opens_after_threshold_and_half_opens_after_cooldown() {
        let cb = CircuitBreaker::new(3, Duration::from_millis(0));
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.on_failure();
        cb.on_failure();
        assert!(cb.allow_request()); // still closed (2 < 3)
        cb.on_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        // Zero cooldown -> immediately half-opens on the next allow.
        assert!(cb.allow_request());
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        // A failure in half-open re-opens immediately.
        cb.on_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn half_open_admits_a_single_probe_and_sheds_concurrent_callers() {
        // Open the breaker with a zero cooldown so the next allow flips to
        // HalfOpen and admits the trial request.
        let cb = CircuitBreaker::new(1, Duration::from_millis(0));
        cb.on_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // First allow_request: Open -> HalfOpen, admitted as the single probe.
        assert!(cb.allow_request(), "first half-open caller is the probe");
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // A second and third concurrent caller are shed while the probe is in
        // flight — the breaker must NOT admit a stampede against a fragile
        // target, matching the "single trial request" contract.
        assert!(
            !cb.allow_request(),
            "second half-open caller is rejected while a probe is outstanding"
        );
        assert!(
            !cb.allow_request(),
            "third half-open caller is rejected while a probe is outstanding"
        );
        // State stays HalfOpen — the rejected callers do not resolve the probe.
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // The outstanding probe succeeds: circuit closes and the next caller is
        // admitted normally (probe flag cleared).
        cb.on_success();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request(), "closed circuit admits");
    }

    #[test]
    fn half_open_probe_failure_re_arms_a_fresh_single_probe() {
        // A failed probe re-opens; after cooldown the NEXT single probe is
        // admitted again (the probe flag is cleared on failure, not leaked).
        let cb = CircuitBreaker::new(1, Duration::from_millis(0));
        cb.on_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Admit the first probe, then it fails -> re-open.
        assert!(cb.allow_request(), "first probe admitted");
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.on_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // After (zero) cooldown a fresh single probe is admitted again — the
        // probe slot was not left stuck set by the previous failure.
        assert!(
            cb.allow_request(),
            "a fresh probe is admitted after re-open"
        );
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        assert!(!cb.allow_request(), "still single-probe after re-arming");
    }

    #[test]
    fn circuit_closes_on_success() {
        let cb = CircuitBreaker::new(2, Duration::from_secs(60));
        cb.on_failure();
        cb.on_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.allow_request(), "open with a long cooldown rejects");
        cb.on_success();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());
    }

    #[test]
    fn timeout_helper_completes_fast_future_and_trips_elapsed_deadline() {
        run_asupersync_test(async move {
            let fast = run_with_timeout(Duration::from_secs(5), async { 7 }).await;
            assert_eq!(fast, Ok(7));
            let slow = run_with_timeout(Duration::ZERO, std::future::pending::<u8>()).await;
            assert_eq!(slow, Err(()));
        });
    }
}
