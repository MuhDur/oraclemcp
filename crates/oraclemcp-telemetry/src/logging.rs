//! Structured `tracing` JSON logging + OTLP telemetry wiring (plan §10; WP-D D1).
//!
//! Logs go to stderr as JSON, filtered by `RUST_LOG` (default `info`).
//!
//! **Redaction:** local stderr JSON and the OTLP export path use the same
//! [`crate::otlp::Redactor`] policy. The local writer parses each JSON event,
//! drops sensitive-key fields, and scrubs secret-shaped values before writing.
//!
//! **Correlation:** the request-dispatch path creates an `mcp.request` span
//! carrying request/session/lane IDs and explicit W3C trace/span IDs. The local
//! JSON formatter renders its current-span fields, and the OTLP traces layer
//! adopts those same IDs; [`crate::otlp::logs::OtlpLogLayer`] also correlates
//! events with the enclosing span.
//!
//! [`init_telemetry`] is the wired entry point: it installs the JSON stderr
//! layer and, when an [`OtlpConfig`](crate::otlp::OtlpConfig) is supplied, also
//! the OTLP logs + traces layers (feeding the background export pump). It returns
//! a [`TelemetryGuard`] the server keeps alive; dropping it flushes + joins the
//! export pump with a bounded budget.

use std::io::{self, Write};
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

/// Build the local JSON layer at the one spot both entry points and the
/// redaction test share, so the test exercises the production construction.
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
        .with_writer(RedactingMakeWriter {
            inner: writer,
            redactor: Redactor::new(),
        })
}

struct RedactingMakeWriter<W> {
    inner: W,
    redactor: Redactor,
}

struct RedactingWriter<W: Write> {
    inner: W,
    redactor: Redactor,
    pending: Vec<u8>,
}

impl<W> Write for RedactingWriter<W>
where
    W: Write,
{
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.pending.is_empty() {
            return self.inner.flush();
        }
        let mut safe = Vec::new();
        for line in self.pending.split_inclusive(|byte| *byte == b'\n') {
            match serde_json::from_slice::<serde_json::Value>(line) {
                Ok(mut value) => {
                    redact_json_value(&mut value, None, &self.redactor);
                    serde_json::to_writer(&mut safe, &value).map_err(io::Error::other)?;
                    if line.last() == Some(&b'\n') {
                        safe.push(b'\n');
                    }
                }
                Err(_) => safe.extend_from_slice(b"[REDACTED LOG EVENT]\n"),
            }
        }
        self.pending.clear();
        self.inner.write_all(&safe)?;
        self.inner.flush()
    }
}

impl<W: Write> Drop for RedactingWriter<W> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

impl<'a, W> tracing_subscriber::fmt::MakeWriter<'a> for RedactingMakeWriter<W>
where
    W: tracing_subscriber::fmt::MakeWriter<'a> + 'static,
{
    type Writer = RedactingWriter<<W as tracing_subscriber::fmt::MakeWriter<'a>>::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter {
            inner: self.inner.make_writer(),
            redactor: self.redactor,
            pending: Vec::new(),
        }
    }
}

fn redact_json_value(
    value: &mut serde_json::Value,
    parent_key: Option<&str>,
    redactor: &Redactor,
) -> bool {
    match value {
        serde_json::Value::Object(object) => {
            object.retain(|key, value| {
                if redactor.should_drop_key(key) {
                    return false;
                }
                redact_json_value(value, Some(key), redactor)
            });
            true
        }
        serde_json::Value::Array(items) => {
            items.retain_mut(|item| redact_json_value(item, parent_key, redactor));
            true
        }
        serde_json::Value::String(text) => {
            let key = parent_key.unwrap_or("message");
            match redactor.filter(key, text) {
                Some((_, safe)) => {
                    *text = safe;
                    true
                }
                None => false,
            }
        }
        _ => true,
    }
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
    use crate::otlp::traces::{FinishedSpan, OtlpTraceLayer, SpanSink};

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

    /// An in-memory [`tracing_subscriber::fmt::MakeWriter`] for local JSON tests.
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
    fn stderr_redactor_scrubs_secrets_and_keeps_useful_error_context() {
        let writer = CapturingWriter::default();
        let subscriber = tracing_subscriber::registry().with(json_fmt_layer(writer.clone()));
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(
                tool = "oracle_query",
                error_class = "ConnectionFailed",
                ora_code = 1017,
                password = "synthetic-password-canary",
                token = "synthetic-token-canary",
                dsn = "user/synthetic-dsn-canary@db.example/service",
                bind = "synthetic-bind-canary",
                credential_ref = "env:SYNTHETIC_REFERENCE_CANARY",
                "auth failed for ocid1.instance.oc1.synthetic-canary"
            );
        });
        let out = writer.contents();
        for canary in [
            "synthetic-password-canary",
            "synthetic-token-canary",
            "synthetic-dsn-canary",
            "synthetic-bind-canary",
            "SYNTHETIC_REFERENCE_CANARY",
            "ocid1.instance.oc1.synthetic-canary",
        ] {
            assert!(!out.contains(canary), "stderr leaked {canary}: {out}");
        }
        for safe in ["oracle_query", "ConnectionFailed", "1017"] {
            assert!(out.contains(safe), "stderr lost {safe}: {out}");
        }
    }

    #[derive(Default)]
    struct SpanCapture(std::sync::Mutex<Vec<FinishedSpan>>);

    impl SpanSink for SpanCapture {
        fn submit(&self, span: FinishedSpan) {
            self.0.lock().unwrap().push(span);
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn request_span_ids_match_local_log_and_otlp() {
        let writer = CapturingWriter::default();
        let sink = std::sync::Arc::new(SpanCapture::default());
        let subscriber = tracing_subscriber::registry()
            .with(json_fmt_layer(writer.clone()))
            .with(OtlpTraceLayer::new(sink.clone(), Redactor::new(), 1.0));
        let (trace_id, span_id) = crate::otlp::new_request_trace_ids();
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                "mcp.request",
                request_id = "request-73",
                session_id = "session-1",
                lane_id = "lane-1",
                subject_id = "subject-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                tool = "oracle_query",
                trace_id = %trace_id,
                span_id = %span_id,
            );
            span.in_scope(|| {
                tracing::error!(
                    error_class = "ConnectionFailed",
                    ora_code = 1017,
                    "connect failed"
                )
            });
        });

        let local = writer.contents();
        assert!(
            local.contains(&format!("\"trace_id\":\"{trace_id}\"")),
            "missing trace id in local line: {local}"
        );
        assert!(
            local.contains(&format!("\"span_id\":\"{span_id}\"")),
            "missing span id in local line: {local}"
        );
        let spans = sink.0.lock().unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(hex(&spans[0].trace_id), trace_id);
        assert_eq!(hex(&spans[0].span_id), span_id);
        assert!(
            spans[0]
                .attributes
                .iter()
                .any(|(key, value)| key == "request_id" && value == "request-73")
        );
    }

    #[test]
    fn concurrent_requests_separable_by_request_id() {
        let writer = CapturingWriter::default();
        let sink = std::sync::Arc::new(SpanCapture::default());
        let mut threads = Vec::new();
        for number in 0..8 {
            let writer = writer.clone();
            let sink = sink.clone();
            threads.push(std::thread::spawn(move || {
                let subscriber = tracing_subscriber::registry()
                    .with(json_fmt_layer(writer))
                    .with(OtlpTraceLayer::new(sink, Redactor::new(), 1.0));
                let (trace_id, span_id) = crate::otlp::new_request_trace_ids();
                tracing::subscriber::with_default(subscriber, || {
                    let request_id = format!("request-{number}");
                    let span = tracing::info_span!(
                        "mcp.request",
                        request_id = %request_id,
                        session_id = "session-1",
                        lane_id = "lane-1",
                        subject_id = "subject-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        tool = "oracle_query",
                        trace_id = %trace_id,
                        span_id = %span_id,
                    );
                    span.in_scope(|| tracing::info!("request completed"));
                });
            }));
        }
        for thread in threads {
            thread.join().expect("request span thread");
        }
        let spans = sink.0.lock().unwrap();
        assert_eq!(spans.len(), 8);
        for number in 0..8 {
            let request_id = format!("request-{number}");
            assert_eq!(
                spans
                    .iter()
                    .filter(|span| span
                        .attributes
                        .iter()
                        .any(|(key, value)| key == "request_id" && value == &request_id))
                    .count(),
                1,
                "request ID must select exactly one OTLP span"
            );
        }
        let local = writer.contents();
        for number in 0..8 {
            assert!(
                local.contains(&format!("request-{number}")),
                "missing request ID in local logs"
            );
        }
    }
}
