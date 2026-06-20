//! Background DB-reachability pinger for the `/readyz` probe (D1-health `.4`).
//!
//! The served HTTP path is synchronous, so the `/readyz` handler cannot itself
//! `await` an Oracle `ping`. This module runs a background thread that owns its
//! own current-thread asupersync runtime, periodically calls
//! [`OracleConnection::ping`] on a dedicated probe connection, and publishes the
//! result into an atomic. The HTTP handler reads that atomic via the
//! [`ReadinessProbe`] trait — fast, lock-free, and accurate to within one probe
//! interval.
//!
//! The probe connection is separate from the dispatch connection so a slow probe
//! never contends with live tool dispatch. When no live DB is configured (the
//! stub connection), every `ping` fails and `/readyz` correctly reports 503.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use asupersync::Cx;
use oraclemcp_core::ReadinessProbe;
use oraclemcp_db::OracleConnection;

/// How often the background pinger re-checks DB reachability.
const PROBE_INTERVAL: Duration = Duration::from_secs(5);
/// Per-probe ping timeout budget (the ping itself is cancellation-aware).
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Shared, lock-free DB-reachability flag the `/readyz` handler reads.
#[derive(Debug, Default)]
struct ProbeState {
    reachable: AtomicBool,
}

impl ReadinessProbe for ProbeState {
    fn is_db_reachable(&self) -> bool {
        self.reachable.load(Ordering::Relaxed)
    }
}

/// Owns the background pinger thread. Dropping it stops the pinger.
pub struct DbReadinessPinger {
    state: Arc<ProbeState>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl DbReadinessPinger {
    /// Start a pinger that probes `connection` every [`PROBE_INTERVAL`].
    ///
    /// The connection is moved onto the pinger thread (it is `Send`; only its
    /// `ping` future is `!Send`, and that future never leaves the thread).
    #[must_use]
    pub fn start(connection: Box<dyn OracleConnection>) -> Self {
        let state = Arc::new(ProbeState::default());
        let stop = Arc::new(AtomicBool::new(false));
        let worker_state = Arc::clone(&state);
        let worker_stop = Arc::clone(&stop);
        let worker = std::thread::Builder::new()
            .name("oraclemcp-readyz-probe".to_owned())
            .spawn(move || run_pinger(&*connection, &worker_state, &worker_stop))
            .ok();
        Self {
            state,
            stop,
            worker,
        }
    }

    /// A `ReadinessProbe` handle for [`oraclemcp_core::ObservabilityState`].
    #[must_use]
    pub fn probe(&self) -> Arc<dyn ReadinessProbe> {
        Arc::clone(&self.state) as Arc<dyn ReadinessProbe>
    }

    /// Signal the pinger to stop and join its thread.
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for DbReadinessPinger {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn run_pinger(connection: &dyn OracleConnection, state: &Arc<ProbeState>, stop: &Arc<AtomicBool>) {
    // Each probe is its own short-lived `block_on`, and the inter-probe wait is a
    // sequence of small `std::thread::sleep`s that re-check `stop`. This keeps
    // shutdown PROMPT (≤ SHUTDOWN_POLL) and avoids relying on the runtime's timer
    // surviving an infinite in-runtime loop (which could otherwise wedge the
    // worker join on shutdown).
    const SHUTDOWN_POLL: Duration = Duration::from_millis(100);

    while !stop.load(Ordering::Relaxed) {
        let reachable = probe_once(connection);
        state.reachable.store(reachable, Ordering::Relaxed);

        // Sleep the probe interval in small increments, bailing out fast on stop.
        let mut waited = Duration::ZERO;
        while waited < PROBE_INTERVAL {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(SHUTDOWN_POLL);
            waited += SHUTDOWN_POLL;
        }
    }
}

/// Run a single cancellation-aware ping on a one-shot current-thread runtime.
/// Returns `true` only if the ping succeeds within [`PROBE_TIMEOUT`].
fn probe_once(connection: &dyn OracleConnection) -> bool {
    let Ok(runtime) = asupersync::runtime::RuntimeBuilder::current_thread().build() else {
        tracing::warn!("oraclemcp-readyz: could not build probe runtime; /readyz stays not-ready");
        return false;
    };
    runtime.block_on(async {
        let cx = Cx::current().expect("block_on installs a probe Cx");
        match asupersync::time::timeout(cx.now(), PROBE_TIMEOUT, connection.ping(&cx)).await {
            Ok(Ok(())) => true,
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "oraclemcp-readyz: DB ping failed");
                false
            }
            Err(_) => {
                tracing::debug!("oraclemcp-readyz: DB ping timed out");
                false
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stub::StubConnection;
    use oraclemcp_db::DbError;

    #[test]
    fn stub_connection_is_never_reachable() {
        // A stub connection's ping always errors -> /readyz reports not reachable.
        let conn: Box<dyn OracleConnection> = Box::new(StubConnection::new(DbError::Connect(
            "no driver".to_owned(),
        )));
        let mut pinger = DbReadinessPinger::start(conn);
        let probe = pinger.probe();
        // Give the background pinger a moment to run its first probe.
        std::thread::sleep(Duration::from_millis(200));
        assert!(!probe.is_db_reachable(), "stub DB never reachable");
        pinger.shutdown();
    }
}
