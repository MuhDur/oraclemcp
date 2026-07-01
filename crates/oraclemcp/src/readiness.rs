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

use std::ffi::OsStr;
use std::io;
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
const SYSTEMD_READY_MESSAGE: &[u8] = b"READY=1\nSTATUS=oraclemcp service ready\n";

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
    // The DB ping runs the async `oracledb` driver, so the probe runtime needs a
    // reactor to drive socket I/O — without one the ping hangs (release-gre.16).
    let Ok(reactor) = asupersync::runtime::reactor::create_reactor() else {
        tracing::warn!("oraclemcp-readyz: could not build probe reactor; /readyz stays not-ready");
        return false;
    };
    let Ok(runtime) = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
    else {
        tracing::warn!("oraclemcp-readyz: could not build probe runtime; /readyz stays not-ready");
        return false;
    };
    // block-on-boundary: one-shot readiness probe runtime on the pinger thread.
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

/// Notify systemd that the HTTP service is accepting work, when launched under
/// a `Type=notify` unit. The stronger DB health gate remains `/readyz`.
pub fn notify_systemd_ready() {
    match notify_systemd_ready_from_env() {
        Ok(true) => tracing::debug!("oraclemcp-readyz: sent systemd READY=1 notification"),
        Ok(false) => {}
        Err(e) => {
            tracing::warn!(error = %e, "oraclemcp-readyz: failed to send systemd READY=1");
        }
    }
}

fn notify_systemd_ready_from_env() -> io::Result<bool> {
    let Some(socket) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(false);
    };
    if socket.is_empty() {
        return Ok(false);
    }
    notify_systemd_ready_to(&socket)?;
    Ok(true)
}

#[cfg(all(unix, target_os = "linux"))]
fn notify_systemd_ready_to(socket: &OsStr) -> io::Result<()> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    use std::path::Path;

    let socket_bytes = socket.as_bytes();
    let datagram = UnixDatagram::unbound()?;
    if let Some(abstract_name) = socket_bytes.strip_prefix(b"@") {
        let addr = SocketAddr::from_abstract_name(abstract_name)?;
        datagram.connect_addr(&addr)?;
    } else {
        datagram.connect(Path::new(socket))?;
    }
    let sent = datagram.send(SYSTEMD_READY_MESSAGE)?;
    if sent == SYSTEMD_READY_MESSAGE.len() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short write to NOTIFY_SOCKET",
        ))
    }
}

#[cfg(not(all(unix, target_os = "linux")))]
fn notify_systemd_ready_to(_socket: &OsStr) -> io::Result<()> {
    Ok(())
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

    #[cfg(all(unix, target_os = "linux"))]
    #[test]
    fn systemd_ready_notify_sends_ready_datagram_to_path_socket() {
        use std::os::unix::net::UnixDatagram;

        let mut path = std::env::temp_dir();
        path.push(format!(
            "omcp-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock after epoch")
                .as_nanos()
        ));
        let receiver = UnixDatagram::bind(&path).expect("bind notify socket");
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("set notify socket timeout");

        notify_systemd_ready_to(path.as_os_str()).expect("notify ready");

        let mut buf = [0u8; 128];
        let len = receiver.recv(&mut buf).expect("receive READY=1");
        let payload = std::str::from_utf8(&buf[..len]).expect("utf8 notify payload");
        assert!(payload.contains("READY=1"), "{payload}");
        assert!(
            payload.contains("STATUS=oraclemcp service ready"),
            "{payload}"
        );
    }
}
