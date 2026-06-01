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
    pub async fn wait_for_shutdown(&self) {
        if self.is_shutting_down() {
            return;
        }
        self.inner.notify.notified().await;
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
}
