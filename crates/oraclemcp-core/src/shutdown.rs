//! Cancellation & graceful shutdown (plan §5.7; bead P2-2).
//!
//! On MCP cancel (`notifications/cancelled` / `tasks/cancel`): break the OCI
//! call, roll back any open transaction on the leased session, close cursors,
//! and return a deterministic [`CancelOutcome`] — **DML is never auto-retried**
//! (only transient connection errors are). On SIGTERM: flip `/readyz` to
//! draining, stop accepting work, roll back in-flight transactions, revoke
//! leases, drain the pool, flush exporters, then exit. Crash safety is
//! `panic = "abort"` (workspace `[profile.release]`) + a panic hook that logs
//! through `tracing` first.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use oraclemcp_telemetry::HealthState;
use tokio::sync::Notify;

/// The deterministic result of cancelling an in-flight call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CancelOutcome {
    /// Whether the agent may retry the *same* request. Always `false` for a
    /// mutating statement (double-execute risk); `true` only for an idempotent
    /// read interrupted by a transient condition.
    pub can_retry: bool,
}

impl CancelOutcome {
    /// Cancellation of a mutating statement: never auto-retry.
    #[must_use]
    pub fn mutating() -> Self {
        CancelOutcome { can_retry: false }
    }

    /// Cancellation of an idempotent read: safe to retry.
    #[must_use]
    pub fn read() -> Self {
        CancelOutcome { can_retry: true }
    }
}

struct Inner {
    shutting_down: AtomicBool,
    notify: Notify,
}

/// Coordinates graceful shutdown across the server: flips readiness, signals
/// in-flight work, and is awaited by the serve loop.
#[derive(Clone)]
pub struct ShutdownCoordinator {
    inner: Arc<Inner>,
    health: HealthState,
}

impl ShutdownCoordinator {
    /// A coordinator wired to the health state (so `/readyz` drains on shutdown).
    #[must_use]
    pub fn new(health: HealthState) -> Self {
        ShutdownCoordinator {
            inner: Arc::new(Inner {
                shutting_down: AtomicBool::new(false),
                notify: Notify::new(),
            }),
            health,
        }
    }

    /// Begin graceful shutdown: `/readyz` fails immediately (drain), new work is
    /// refused, and any awaiters of [`wait_for_shutdown`](Self::wait_for_shutdown)
    /// are woken. Idempotent.
    pub fn begin_shutdown(&self) {
        if !self.inner.shutting_down.swap(true, Ordering::SeqCst) {
            self.health.begin_shutdown();
            self.inner.notify.notify_waiters();
        }
    }

    /// Whether shutdown has begun (the admission layer refuses new work).
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.inner.shutting_down.load(Ordering::SeqCst)
    }

    /// Await the shutdown signal (returns immediately if already shutting down).
    ///
    /// Registers the [`Notify`] waiter *before* the flag check (and re-checks
    /// after) so a `begin_shutdown` that races between the check and the await
    /// cannot be lost. `notify_waiters` (used by `begin_shutdown`) stores no
    /// permit for future waiters, so a naive "check flag, then `notified().await`"
    /// has a TOCTOU window: shutdown fires after the flag reads `false` but
    /// before the waiter registers, and the task then parks forever. Enabling
    /// the `Notified` future first closes that window (tokio >= 1.52).
    pub async fn wait_for_shutdown(&self) {
        let notified = self.inner.notify.notified();
        tokio::pin!(notified);
        // Register this waiter now, so a concurrent `begin_shutdown` after the
        // flag check below still wakes us.
        notified.as_mut().enable();
        if self.is_shutting_down() {
            return;
        }
        notified.await;
    }
}

/// Install a panic hook that logs through `tracing` before the `panic = "abort"`
/// runtime aborts the process (crash safety, §5.7). Call once at startup.
pub fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(panic = %info, "oraclemcp panic — aborting");
        prev(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_outcome_never_retries_dml() {
        assert!(!CancelOutcome::mutating().can_retry);
        assert!(CancelOutcome::read().can_retry);
    }

    #[test]
    fn shutdown_flips_readiness_and_is_idempotent() {
        let health = HealthState::new("0.1.0");
        health.set_ready(true);
        assert!(health.is_ready());
        let coord = ShutdownCoordinator::new(health.clone());
        assert!(!coord.is_shutting_down());
        coord.begin_shutdown();
        assert!(coord.is_shutting_down());
        assert!(!health.is_ready(), "readyz drains on shutdown");
        assert!(health.is_live(), "still live while draining");
        coord.begin_shutdown(); // idempotent
        assert!(coord.is_shutting_down());
    }

    #[tokio::test]
    async fn wait_returns_after_begin_shutdown() {
        let coord = ShutdownCoordinator::new(HealthState::new("0.1.0"));
        let c2 = coord.clone();
        let waiter = tokio::spawn(async move { c2.wait_for_shutdown().await });
        // Give the waiter a moment to register, then signal.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        coord.begin_shutdown();
        waiter.await.expect("waiter joins");
        // Already shutting down -> immediate return.
        coord.wait_for_shutdown().await;
    }

    // Regression for oracle-qm3q.15 (lost-wakeup TOCTOU): signal shutdown
    // *before* the waiter ever polls — no pre-sleep to let it register first
    // (the old test at the call site masked the race with a 20ms sleep). The
    // waiter must still return promptly rather than park on a notification that
    // already fired. `begin_shutdown` here completes before the poll, so the
    // post-`enable()` flag re-check is what guarantees the prompt return.
    #[tokio::test]
    async fn wait_returns_promptly_when_signalled_before_waiting() {
        let coord = ShutdownCoordinator::new(HealthState::new("0.1.0"));
        coord.begin_shutdown();
        tokio::time::timeout(std::time::Duration::from_secs(5), coord.wait_for_shutdown())
            .await
            .expect("wait_for_shutdown returns promptly after a prior begin_shutdown");
    }

    // Regression for oracle-qm3q.15: stress the check-then-register window by
    // racing `begin_shutdown` against a freshly spawned waiter across many
    // iterations on a multi-thread runtime. The fix (enable the `Notified`
    // future before the flag check) makes the wakeup race-free; a gross
    // regression that re-opened the window would eventually trip the per-waiter
    // timeout here. NOTE: the genuine lost-wakeup window is sub-poll (between
    // the flag read and the waiter registration inside a single `poll`), so a
    // *deterministic* repro is not expressible through the public future — this
    // guards the invariant rather than pinning the exact interleaving.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn wait_does_not_lose_wakeup_under_signal_race() {
        for _ in 0..1_000 {
            let coord = ShutdownCoordinator::new(HealthState::new("0.1.0"));
            let waiter = {
                let c = coord.clone();
                tokio::spawn(async move { c.wait_for_shutdown().await })
            };
            // Yield once so the waiter has a chance to begin its first poll,
            // then fire the signal to interleave with registration.
            tokio::task::yield_now().await;
            coord.begin_shutdown();
            tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
                .await
                .expect("waiter must not lose the shutdown wakeup")
                .expect("waiter task joins");
        }
    }
}
