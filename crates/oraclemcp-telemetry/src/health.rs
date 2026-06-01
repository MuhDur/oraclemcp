//! Liveness / readiness health state (plan §10).
//!
//! Separate from request handling: `/healthz` (liveness — the process is up) and
//! `/readyz` (readiness — a pool connection pings + not shutting down). The HTTP
//! mounting lives in the transport layer (P1-9); this crate owns the state +
//! the report shape so it is testable without a server, and `/readyz` flips to
//! not-ready immediately on shutdown so load balancers drain in flight.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

/// Shared health state. Cheap to clone (`Arc` inside).
#[derive(Clone)]
pub struct HealthState {
    inner: Arc<Inner>,
}

struct Inner {
    live: AtomicBool,
    ready: AtomicBool,
    version: String,
}

impl HealthState {
    /// A new state: live, not-yet-ready (readiness flips true once the pool is up).
    #[must_use]
    pub fn new(version: impl Into<String>) -> Self {
        HealthState {
            inner: Arc::new(Inner {
                live: AtomicBool::new(true),
                ready: AtomicBool::new(false),
                version: version.into(),
            }),
        }
    }

    /// Mark the server ready (pool established, accepting work).
    pub fn set_ready(&self, ready: bool) {
        self.inner.ready.store(ready, Ordering::SeqCst);
    }

    /// Begin shutdown: not ready (drain) but still live until the process exits.
    pub fn begin_shutdown(&self) {
        self.inner.ready.store(false, Ordering::SeqCst);
    }

    /// Liveness.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.inner.live.load(Ordering::SeqCst)
    }

    /// Readiness.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.inner.ready.load(Ordering::SeqCst)
    }

    /// The `/healthz` (liveness) report + HTTP status (200 live / 503 down).
    #[must_use]
    pub fn liveness(&self) -> (u16, HealthReport) {
        let live = self.is_live();
        (if live { 200 } else { 503 }, self.report(live))
    }

    /// The `/readyz` (readiness) report + HTTP status (200 ready / 503 draining).
    #[must_use]
    pub fn readiness(&self) -> (u16, HealthReport) {
        let ready = self.is_ready();
        (if ready { 200 } else { 503 }, self.report(ready))
    }

    fn report(&self, ok: bool) -> HealthReport {
        HealthReport {
            status: if ok { "ok" } else { "unavailable" }.to_owned(),
            live: self.is_live(),
            ready: self.is_ready(),
            version: self.inner.version.clone(),
        }
    }
}

/// The JSON body returned by the health endpoints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthReport {
    /// `"ok"` or `"unavailable"`.
    pub status: String,
    /// Liveness.
    pub live: bool,
    /// Readiness.
    pub ready: bool,
    /// Server version.
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_live_but_not_ready() {
        let h = HealthState::new("0.1.0");
        assert!(h.is_live());
        assert!(!h.is_ready());
        assert_eq!(h.liveness().0, 200);
        assert_eq!(h.readiness().0, 503, "not ready until the pool is up");
    }

    #[test]
    fn ready_then_shutdown_drains() {
        let h = HealthState::new("0.1.0");
        h.set_ready(true);
        assert_eq!(h.readiness().0, 200);
        h.begin_shutdown();
        assert_eq!(h.readiness().0, 503, "readyz fails immediately on shutdown");
        assert!(h.is_live(), "still live while draining");
    }

    #[test]
    fn report_serializes() {
        let h = HealthState::new("1.2.3");
        h.set_ready(true);
        let (_status, report) = h.readiness();
        let json = serde_json::to_value(&report).expect("serialize");
        assert_eq!(json["status"], serde_json::json!("ok"));
        assert_eq!(json["ready"], serde_json::json!(true));
        assert_eq!(json["version"], serde_json::json!("1.2.3"));
    }
}
