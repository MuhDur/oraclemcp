//! Resilience primitives (plan §10; bead P2-RESIL): a circuit breaker, a
//! transient-only retry policy, and a call-timeout helper.
//!
//! Retry law: only **transient** connection errors (ORA-03113/03114/12170/
//! 12541/12537) are retryable, and **DML is never auto-retried** (double-execute
//! risk, §5.7). A misclassification here is fail-safe — when in doubt, do not
//! retry.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Transient, retryable Oracle/network error codes (§10). Anything else
/// (ORA-00942 object-not-found, ORA-01403 no-data, syntax, privilege) is NOT
/// retried.
const TRANSIENT_ORA_CODES: &[i32] = &[3113, 3114, 12170, 12541, 12537, 12543, 12514];

/// Per-round-trip call timeout (§10).
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Whether an Oracle error message names a transient, retryable condition.
#[must_use]
pub fn is_transient_error(message: &str) -> bool {
    oraclemcp_error::parse_ora_code(message).is_some_and(|c| TRANSIENT_ORA_CODES.contains(&c))
}

/// The retry policy for read operations.
#[derive(Clone, Copy, Debug)]
pub struct RetryPolicy {
    /// Maximum attempts (including the first).
    pub max_attempts: u32,
    /// Base backoff; attempt `n` waits `base * 2^(n-1)`.
    pub base_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
        }
    }
}

impl RetryPolicy {
    /// The delay before the next attempt, or `None` if the call must not be
    /// retried: a mutating op is never retried; only a transient error on a
    /// non-final attempt is.
    #[must_use]
    pub fn next_delay(
        &self,
        attempt: u32,
        mutating: bool,
        error_message: &str,
    ) -> Option<Duration> {
        if mutating || attempt >= self.max_attempts {
            return None;
        }
        if !is_transient_error(error_message) {
            return None;
        }
        Some(self.base_delay * 2u32.pow(attempt.saturating_sub(1)))
    }
}

/// Circuit-breaker state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitState {
    /// Requests flow normally.
    Closed,
    /// Tripped: requests are rejected until the cooldown elapses.
    Open,
    /// One trial request is allowed to test recovery.
    HalfOpen,
}

struct Inner {
    consecutive_failures: u32,
    state: CircuitState,
    opened_at: Option<Instant>,
}

/// A circuit breaker: opens after `failure_threshold` consecutive failures and
/// stays open for `cooldown`, then half-opens to probe recovery (§10).
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
            }),
        }
    }

    /// Whether a request may proceed now (transitions Open→HalfOpen after the
    /// cooldown).
    #[must_use]
    pub fn allow_request(&self) -> bool {
        let mut inner = self.inner.lock().expect("circuit mutex poisoned");
        match inner.state {
            CircuitState::Closed | CircuitState::HalfOpen => true,
            CircuitState::Open => {
                let elapsed = inner
                    .opened_at
                    .map(|t| t.elapsed())
                    .unwrap_or(self.cooldown);
                if elapsed >= self.cooldown {
                    inner.state = CircuitState::HalfOpen;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Record a success: resets the failure count and closes the circuit.
    pub fn on_success(&self) {
        let mut inner = self.inner.lock().expect("circuit mutex poisoned");
        inner.consecutive_failures = 0;
        inner.state = CircuitState::Closed;
        inner.opened_at = None;
    }

    /// Record a failure: trips the circuit at the threshold (or immediately if
    /// probing in HalfOpen).
    pub fn on_failure(&self) {
        let mut inner = self.inner.lock().expect("circuit mutex poisoned");
        inner.consecutive_failures += 1;
        let trip = inner.state == CircuitState::HalfOpen
            || inner.consecutive_failures >= self.failure_threshold;
        if trip {
            inner.state = CircuitState::Open;
            inner.opened_at = Some(Instant::now());
        }
    }

    /// The current state (for metrics / tests).
    #[must_use]
    pub fn state(&self) -> CircuitState {
        self.inner.lock().expect("circuit mutex poisoned").state
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
    tokio::time::timeout(timeout, fut).await.map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_classification() {
        assert!(is_transient_error(
            "ORA-03113: end-of-file on communication channel"
        ));
        assert!(is_transient_error("ORA-12541: TNS:no listener"));
        assert!(!is_transient_error(
            "ORA-00942: table or view does not exist"
        ));
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

    #[tokio::test]
    async fn timeout_helper_trips_on_slow_future() {
        let fast = run_with_timeout(Duration::from_secs(5), async { 7 }).await;
        assert_eq!(fast, Ok(7));
        let slow = run_with_timeout(Duration::from_millis(10), async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            7
        })
        .await;
        assert_eq!(slow, Err(()));
    }
}
