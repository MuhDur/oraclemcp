//! Structured `tracing` JSON logging + OTLP telemetry wiring (plan §10; WP-D D1).
//!
//! Logs go to stderr as JSON, filtered by `RUST_LOG` (default `info`).
//!
//! **Redaction scope (§31.2 correction — read this before adding a log site):**
//! [`crate::otlp::Redactor`] is wired into the **OTLP export path only**
//! (`OtlpLogLayer`/`OtlpTraceLayer`, see [`crate::otlp::logs`]/[`crate::otlp::traces`]).
//! The local stderr JSON layer installed below has **no structural redaction
//! backstop** — it is the raw `tracing_subscriber` JSON formatter, unfiltered.
//! Bind values and secrets are never logged only because callers are
//! disciplined about it (SQL is logged as SHA-256 + preview, never binds — see
//! `oraclemcp-audit`); nothing in this module enforces that on the stderr path.
//! If a log call ever interpolates a raw error message that could carry a
//! secret (a connect string, a bearer token), it reaches stderr unredacted.
//! See [`crate::otlp::redact`] for the policy enforced on the OTLP path only.
//!
//! **Correlation:** there is no per-request span created anywhere in this
//! crate or wired automatically by [`init_telemetry`] — that would be a
//! decision for the request-dispatch path, which lives outside
//! `oraclemcp-telemetry`. What *is* real: when a caller does create a span
//! (`#[instrument]` / `info_span!`) while the OTLP traces layer is installed,
//! [`crate::otlp::logs::OtlpLogLayer`] correlates any log event emitted inside
//! it by attaching that span's `trace_id`/`span_id` (see
//! `crate::otlp::traces::current_span_trace_context`, crate-private). Today
//! only test code and one trace-level span (`catalog_extract.rs`, in
//! `oraclemcp-db`) create spans, so this plumbing is real but mostly dormant —
//! it activates automatically wherever a span gets created, without another
//! change to this crate.
//!
//! [`init_telemetry`] is the wired entry point: it installs the JSON stderr
//! layer and, when an [`OtlpConfig`](crate::otlp::OtlpConfig) is supplied, also
//! the OTLP logs + traces layers (feeding the background export pump). It returns
//! a [`TelemetryGuard`] the server keeps alive; dropping it flushes + joins the
//! export pump with a bounded budget.

use std::sync::OnceLock;

use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::otlp::config::OtlpConfig;
use crate::otlp::logs::OtlpLogLayer;
use crate::otlp::pump::PumpHandle;
use crate::otlp::traces::OtlpTraceLayer;
use crate::otlp::{ExportPump, Redactor};

static INIT: OnceLock<()> = OnceLock::new();

/// Build the local JSON layer at the one spot both entry points (and the
/// redaction-scope test below) share, so the test exercises the exact
/// production construction rather than a hand copy that could drift.
///
/// **No redaction runs here.** This is the raw `tracing_subscriber` JSON
/// formatter over `writer` — see the module docs' "Redaction scope" note.
fn json_fmt_layer<S, W>(writer: W) -> impl tracing_subscriber::Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    W: for<'writer> tracing_subscriber::fmt::MakeWriter<'writer> + 'static,
{
    tracing_subscriber::fmt::layer()
        .json()
        .with_current_span(true)
        .with_span_list(false)
        .with_target(true)
        .with_writer(writer)
}

/// Initialize JSON logging to stderr, filtered by `RUST_LOG` (default `level`).
/// Idempotent: returns `true` on the first call that installs the subscriber,
/// `false` if logging was already initialized (so tests / repeated `serve`
/// invocations do not panic on a double-install).
///
/// This installs **only** the local JSON layer (no OTLP). For the wired OTLP
/// path, call [`init_telemetry`] instead.
pub fn init_json_logging(default_level: &str) -> bool {
    let mut installed = false;
    INIT.get_or_init(|| {
        let filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
        // `try_init` returns Err if a global subscriber is already set; we treat
        // that as "already initialized" rather than a hard error.
        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(json_fmt_layer(std::io::stderr))
            .try_init();
        installed = true;
    });
    installed
}

/// Keeps the OTLP export pump alive for the server's lifetime. Dropping it
/// performs the bounded shutdown drain + worker join. Holds `None` when OTLP
/// export is off (no endpoint configured) — telemetry is then local-only.
#[must_use = "drop the guard at shutdown to flush + join the OTLP export pump"]
pub struct TelemetryGuard {
    pump: Option<ExportPump>,
}

impl TelemetryGuard {
    /// A cloneable handle for submitting telemetry to the pump, when OTLP export
    /// is enabled. `None` when export is off.
    #[must_use]
    pub fn pump_handle(&self) -> Option<PumpHandle> {
        self.pump.as_ref().map(ExportPump::handle)
    }

    /// Register the provider the pump polls for the live metrics snapshot.
    pub fn set_metrics_provider(&self, provider: crate::otlp::pump::MetricsProvider) {
        if let Some(handle) = self.pump_handle() {
            handle.set_metrics_provider(provider);
        }
    }

    /// Whether OTLP export is enabled (an endpoint was configured).
    #[must_use]
    pub fn otlp_enabled(&self) -> bool {
        self.pump.is_some()
    }
}

/// Initialize the full telemetry stack: JSON stderr logging plus — when `otlp`
/// is `Some` — OTLP logs + traces layers wired to a background export pump.
///
/// Returns a [`TelemetryGuard`]. When `otlp` is `None` (the default: no
/// `OTEL_EXPORTER_OTLP_*` endpoint configured), only the local JSON layer is
/// installed and the guard holds no pump — **nothing is exported**.
///
/// Idempotent w.r.t. the global subscriber: a second call (e.g. in a test that
/// already installed one) is a no-op for the subscriber but still returns a
/// guard owning a fresh pump if `otlp` is `Some`.
pub fn init_telemetry(default_level: &str, otlp: Option<OtlpConfig>) -> TelemetryGuard {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));

    let json_layer = json_fmt_layer(std::io::stderr);

    match otlp {
        Some(config) => {
            let pump = ExportPump::start(config.clone());
            let handle = pump.handle();
            let log_layer = OtlpLogLayer::new(handle.clone());
            let trace_layer = OtlpTraceLayer::new(
                std::sync::Arc::new(handle),
                Redactor::new(),
                config.trace_sample_ratio,
            );

            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(json_layer)
                .with(log_layer)
                .with(trace_layer)
                .try_init();

            // Mark the legacy OnceLock so a later init_json_logging is a no-op.
            let _ = INIT.set(());
            TelemetryGuard { pump: Some(pump) }
        }
        None => {
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(json_layer)
                .try_init();
            let _ = INIT.set(());
            TelemetryGuard { pump: None }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_is_idempotent() {
        // First call installs (or coexists with a test harness subscriber);
        // subsequent calls must not panic and must report not-installed.
        let _first = init_json_logging("info");
        assert!(!init_json_logging("debug"), "second init must be a no-op");
    }

    #[test]
    fn env_filter_parses_default_level() {
        // A bad default would panic in EnvFilter::new; assert common levels work.
        for level in ["error", "warn", "info", "debug", "trace"] {
            let _ = EnvFilter::new(level);
        }
    }

    #[test]
    fn init_telemetry_off_when_no_otlp() {
        let guard = init_telemetry("info", None);
        assert!(!guard.otlp_enabled(), "no endpoint -> no export pump");
        assert!(guard.pump_handle().is_none());
    }

    #[test]
    fn init_telemetry_on_when_otlp_configured() {
        let cfg = OtlpConfig::from_lookup(|k| {
            (k == "OTEL_EXPORTER_OTLP_ENDPOINT").then(|| "http://127.0.0.1:9/".to_owned())
        });
        assert!(cfg.is_some());
        let guard = init_telemetry("info", cfg);
        assert!(guard.otlp_enabled(), "endpoint -> export pump started");
        assert!(guard.pump_handle().is_some());
        // Dropping the guard must perform a bounded drain + join without hanging.
    }

    /// An in-memory [`tracing_subscriber::fmt::MakeWriter`] so the redaction
    /// scope test below can inspect what the local JSON layer actually wrote,
    /// without touching the process's real stderr.
    #[derive(Clone, Default)]
    struct CapturingWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl CapturingWriter {
        fn contents(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    impl std::io::Write for CapturingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturingWriter {
        type Writer = CapturingWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn local_stderr_layer_has_no_redaction_backstop_matching_the_doc() {
        // Proves the module doc's "Redaction scope" claim: `json_fmt_layer`
        // (the exact construction both init_json_logging and init_telemetry
        // use for the local stderr path) runs no Redactor pass, so a
        // secret-shaped field reaches the formatted line verbatim.
        //
        // Contrast with the OTLP path, which DOES redact the same shape of
        // value before export — see otlp/logs.rs's
        // `secret_attributes_are_dropped_and_bodies_redacted` and
        // otlp/redact.rs's redaction tests. Together these two tests are the
        // executable proof that the doc's scope claim matches reality.
        let writer = CapturingWriter::default();
        let subscriber = tracing_subscriber::registry().with(json_fmt_layer(writer.clone()));
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(password = "QA_H8_SECRET_SENTINEL", "auth failed");
        });
        let out = writer.contents();
        assert!(
            out.contains("QA_H8_SECRET_SENTINEL"),
            "local stderr JSON layer has no redaction backstop (matches the \
             module doc's 'Redaction scope' note); captured: {out}"
        );
    }
}
