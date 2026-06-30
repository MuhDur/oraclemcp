//! Cancellation & graceful shutdown (plan §5.7; bead P2-2).
//!
//! On MCP cancel (`notifications/cancelled` / `tasks/cancel`): break the OCI
//! call, roll back any open transaction on the leased session, close cursors,
//! and return a deterministic [`CancelOutcome`] — **DML is never auto-retried**
//! (only transient connection errors are). On SIGTERM: flip `/readyz` to
//! draining, stop accepting work, roll back in-flight transactions, revoke
//! leases, drain the pool, flush exporters, then exit. Crash safety is
//! `panic = "unwind"` (workspace `[profile.release]`) plus lane-level panic
//! containment for DB work; the process-wide panic hook logs through `tracing`
//! before the unwind continues.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use asupersync::sync::Notify;
use oraclemcp_telemetry::HealthState;

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
    /// Uses Asupersync `wait_until`, which evaluates the shutdown predicate
    /// before parking and re-checks it after every wake. That keeps the
    /// `notify_waiters` signal edge-triggered without reopening the historical
    /// check-then-park lost-wakeup window.
    pub async fn wait_for_shutdown(&self) {
        self.inner
            .notify
            .wait_until(|| self.is_shutting_down())
            .await;
    }
}

/// Install a panic hook that logs through `tracing` before unwind/containment
/// proceeds (crash safety, §5.7). Call once at startup.
pub fn install_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(panic = %info, "oraclemcp panic observed");
        prev(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::runtime::{Runtime, RuntimeBuilder, yield_now};
    use std::future::Future;
    use std::panic::AssertUnwindSafe;
    use std::sync::mpsc;
    use std::time::Duration;

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

    #[test]
    fn wait_returns_after_begin_shutdown() {
        run_asupersync_test(async move {
            let coord = ShutdownCoordinator::new(HealthState::new("0.1.0"));
            let c2 = coord.clone();
            let waiter = Runtime::current_handle()
                .expect("asupersync test runtime installed")
                .try_spawn(async move { c2.wait_for_shutdown().await })
                .expect("waiter spawned");
            // Give the waiter a moment to register, then signal.
            yield_now().await;
            coord.begin_shutdown();
            waiter.await;
            // Already shutting down -> immediate return.
            coord.wait_for_shutdown().await;
        });
    }

    // Regression for oracle-qm3q.15 (lost-wakeup TOCTOU): signal shutdown
    // *before* the waiter ever polls — no pre-sleep to let it register first
    // (the old test at the call site masked the race with a 20ms sleep). The
    // waiter must still return promptly rather than park on a notification that
    // already fired. `begin_shutdown` here completes before the poll, so the
    // post-`enable()` flag re-check is what guarantees the prompt return.
    #[test]
    fn wait_returns_promptly_when_signalled_before_waiting() {
        run_asupersync_test(async move {
            let coord = ShutdownCoordinator::new(HealthState::new("0.1.0"));
            coord.begin_shutdown();
            coord.wait_for_shutdown().await;
        });
    }

    // Regression for oracle-qm3q.15: a waiter that races shutdown must not park
    // forever if shutdown fires around the first poll. Asupersync `wait_until`
    // owns the predicate-check loop, so this test guards our integration with
    // that primitive rather than reimplementing waiter registration by hand.
    #[test]
    fn wait_does_not_lose_wakeup_under_signal_race() {
        run_asupersync_test(async move {
            for _ in 0..1_000 {
                let coord = ShutdownCoordinator::new(HealthState::new("0.1.0"));
                let waiter = {
                    let c = coord.clone();
                    Runtime::current_handle()
                        .expect("asupersync test runtime installed")
                        .try_spawn(async move { c.wait_for_shutdown().await })
                        .expect("waiter spawned")
                };
                // Yield once so the waiter has a chance to begin its first poll,
                // then fire the signal to interleave with registration.
                yield_now().await;
                coord.begin_shutdown();
                waiter.await;
            }
        });
    }
}
