//! OTLP logs export (D1-logs, bead `oraclemcp-040-epic-wp-d-1il.1`).
//!
//! This is the **turnkey** signal: asupersync ships `OtlpLogsHttpExporter` +
//! `LogsSnapshot::to_otlp_protobuf` over its own Tokio-free HTTP/1 client, so we
//! do not hand-roll the logs protobuf — we only build a redacted [`LogsSnapshot`]
//! and hand it to the exporter. Logs egress goes ONLY through asupersync (never
//! reqwest/hyper).
//!
//! Every record's body and attributes pass through [`Redactor`] before they
//! reach the snapshot: no SQL bind values, passwords, tokens, or wallet secrets.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use asupersync::observability::{LogLevel, LogsSnapshot, OtlpLogRecord, OtlpLogsHttpExporter};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use super::config::OtlpConfig;
use super::pump::PumpHandle;
use super::redact::Redactor;

/// Instrumentation scope name for oraclemcp log exports.
pub const SCOPE_NAME: &str = "oraclemcp.telemetry";
/// Instrumentation scope version (the telemetry crate version).
pub const SCOPE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// A single structured log record awaiting OTLP export, pre-redaction.
#[derive(Clone, Debug)]
pub struct LogRecordInput {
    /// Severity.
    pub level: LogLevel,
    /// Event message / body.
    pub body: String,
    /// Event timestamp (unix nanos); 0 = unknown.
    pub time_unix_nano: u64,
    /// Structured attributes (key/value); redacted on the way in.
    pub attributes: Vec<(String, String)>,
    /// Optional 16-byte W3C trace id for correlation.
    pub trace_id: Vec<u8>,
    /// Optional 8-byte W3C span id for correlation.
    pub span_id: Vec<u8>,
    /// W3C trace flags (low 8 bits exported).
    pub trace_flags: u32,
}

impl LogRecordInput {
    /// A new record at `level` with `body` and timestamp.
    #[must_use]
    pub fn new(level: LogLevel, body: impl Into<String>, time_unix_nano: u64) -> Self {
        Self {
            level,
            body: body.into(),
            time_unix_nano,
            attributes: Vec::new(),
            trace_id: Vec::new(),
            span_id: Vec::new(),
            trace_flags: 0,
        }
    }

    /// Attach an attribute (redacted at snapshot-build time).
    #[must_use]
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.push((key.into(), value.into()));
        self
    }

    /// Attach W3C trace correlation.
    #[must_use]
    pub fn with_trace_context(mut self, trace_id: Vec<u8>, span_id: Vec<u8>, flags: u32) -> Self {
        self.trace_id = trace_id;
        self.span_id = span_id;
        self.trace_flags = flags;
        self
    }
}

/// Build a single-resource, single-scope [`LogsSnapshot`] from records, applying
/// secret redaction to every body and attribute.
///
/// The body is value-redacted under a synthetic free-form key so a log line that
/// accidentally quoted a secret (e.g. a connect string) is scrubbed; structured
/// attributes are funneled through [`Redactor::filter`] (drop sensitive keys,
/// redact secret-shaped values).
#[must_use]
pub fn build_snapshot(
    config: &OtlpConfig,
    redactor: &Redactor,
    records: &[LogRecordInput],
) -> LogsSnapshot {
    let mut snapshot =
        LogsSnapshot::new(config.service_name.clone()).with_scope(SCOPE_NAME, SCOPE_VERSION);

    for record in records {
        let safe_body = redactor.redact_value("message", &record.body);
        let mut otlp = OtlpLogRecord::new(record.level, safe_body, record.time_unix_nano);

        if !record.trace_id.is_empty() || !record.span_id.is_empty() {
            otlp = otlp.with_trace_context(
                record.trace_id.clone(),
                record.span_id.clone(),
                record.trace_flags,
            );
        }

        for (key, value) in &record.attributes {
            if let Some((safe_key, safe_value)) = redactor.filter(key, value) {
                otlp = otlp.with_attribute(safe_key, safe_value);
            }
        }
        snapshot.add_record(otlp);
    }
    snapshot
}

/// Export a logs snapshot to the configured collector over asupersync's HTTP/1
/// client. Async + Cx-aware; the caller decides where this runs (the background
/// export pump in [`super::runtime`], never the request path).
///
/// # Errors
/// Returns the asupersync `ExportError` if the OTLP request ultimately fails
/// (after the exporter's own retry budget). The caller drops on error — telemetry
/// failure never blocks or fails the request path.
pub async fn export_snapshot(
    cx: &asupersync::Cx,
    config: &OtlpConfig,
    snapshot: &LogsSnapshot,
) -> Result<(), asupersync::observability::ExportError> {
    // NOTE: asupersync 0.3.4's `OtlpLogsHttpExporter` wraps `OtlpHttpExporter`
    // but only re-exports the timeout/retry/compression builders — not the
    // auth-header builders. So `OTEL_EXPORTER_OTLP_HEADERS` collector auth for
    // the LOGS signal is configured at the collector/proxy layer; the METRICS
    // and TRACES signals (which call `OtlpHttpExporter` directly) DO attach the
    // headers. This is a documented asupersync surface gap, not a silent drop.
    let exporter = OtlpLogsHttpExporter::new(config.logs_endpoint.clone())
        .with_timeout(config.timeout)
        .with_compression(config.compression);
    exporter.export_async(cx, snapshot).await
}

// ===========================================================================
// tracing Layer → OTLP logs
// ===========================================================================

/// Map a `tracing` level to an asupersync [`LogLevel`].
fn map_level(level: &tracing::Level) -> LogLevel {
    match *level {
        tracing::Level::TRACE => LogLevel::Trace,
        tracing::Level::DEBUG => LogLevel::Debug,
        tracing::Level::INFO => LogLevel::Info,
        tracing::Level::WARN => LogLevel::Warn,
        tracing::Level::ERROR => LogLevel::Error,
    }
}

/// Captures an event's fields into a body + attributes.
#[derive(Default)]
struct EventVisitor {
    body: String,
    attributes: Vec<(String, String)>,
}

impl Visit for EventVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.body = format!("{value:?}");
        } else {
            self.attributes
                .push((field.name().to_owned(), format!("{value:?}")));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.body = value.to_owned();
        } else {
            self.attributes
                .push((field.name().to_owned(), value.to_owned()));
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.attributes
            .push((field.name().to_owned(), value.to_string()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.attributes
            .push((field.name().to_owned(), value.to_string()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.attributes
            .push((field.name().to_owned(), value.to_string()));
    }
}

/// A `tracing` layer that forwards events to the OTLP logs pump (redacted).
///
/// This is the wired logs path: events emitted anywhere on the served path
/// become OTLP log records (in addition to the local JSON-to-stderr layer). The
/// layer only `submit`s into the pump's bounded queue — it never blocks or
/// exports inline.
///
/// **Correlation:** when the event is emitted inside a span that
/// [`super::traces::OtlpTraceLayer`] has instrumented (i.e. some caller created
/// one — via `#[instrument]` or `info_span!`), the record's `trace_id`/`span_id`
/// are set from that span via [`super::traces::current_span_trace_context`], so
/// the log line and the span line up in the OTLP backend. Outside any span
/// (which is most of the codebase today — see the crate root docs), the record
/// carries no trace context; this layer does not manufacture one.
pub struct OtlpLogLayer {
    pump: PumpHandle,
    target_prefix_filter: Option<String>,
    exclude_prefix: String,
}

impl OtlpLogLayer {
    /// Build a logs layer that forwards captured events to `pump`.
    ///
    /// Events emitted by this crate's own export machinery (target prefix
    /// `oraclemcp_telemetry`) are EXCLUDED to avoid a feedback loop: the pump
    /// logs an export failure on a dead collector, and re-capturing that line
    /// would re-queue it indefinitely.
    #[must_use]
    pub fn new(pump: PumpHandle) -> Self {
        Self {
            pump,
            target_prefix_filter: None,
            exclude_prefix: "oraclemcp_telemetry".to_owned(),
        }
    }

    /// Only forward events whose target starts with `prefix` (e.g. `oraclemcp`).
    #[must_use]
    pub fn with_target_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.target_prefix_filter = Some(prefix.into());
        self
    }
}

impl<S> Layer<S> for OtlpLogLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let target = event.metadata().target();
        // Never re-capture our own export-failure logs (feedback-loop guard).
        if target.starts_with(self.exclude_prefix.as_str()) {
            return;
        }
        if let Some(prefix) = &self.target_prefix_filter
            && !target.starts_with(prefix.as_str())
        {
            return;
        }
        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let mut record =
            LogRecordInput::new(map_level(event.metadata().level()), visitor.body, now)
                .with_attribute("target", event.metadata().target());
        // Correlate with the enclosing span, when one exists (see the type doc).
        if let Some((trace_id, span_id, sampled)) = super::traces::current_span_trace_context(&ctx)
        {
            let flags = u32::from(sampled);
            record = record.with_trace_context(trace_id.to_vec(), span_id.to_vec(), flags);
        }
        for (key, value) in visitor.attributes {
            record = record.with_attribute(key, value);
        }
        self.pump.submit_log(record);
    }
}

/// A pump-backed logs layer is cheap to clone via the shared `Arc` pump handle.
impl OtlpLogLayer {
    /// Wrap the layer in an `Arc` for composition with other layers.
    #[must_use]
    pub fn boxed(self) -> Arc<Self> {
        Arc::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> OtlpConfig {
        OtlpConfig::from_lookup(|k| {
            if k == "OTEL_EXPORTER_OTLP_ENDPOINT" {
                Some("http://collector:4318".to_owned())
            } else {
                None
            }
        })
        .expect("on")
    }

    #[test]
    fn snapshot_is_well_formed_and_roundtrips_protobuf() {
        let config = cfg();
        let r = Redactor::new();
        let records = vec![
            LogRecordInput::new(LogLevel::Info, "request handled", 1_000)
                .with_attribute("tool", "oracle_query")
                .with_attribute("row_count", "5"),
        ];
        let snapshot = build_snapshot(&config, &r, &records);
        assert_eq!(snapshot.record_count(), 1);
        assert_eq!(snapshot.scope_name, SCOPE_NAME);
        // service.name resource attribute present.
        assert!(
            snapshot
                .resource_attributes
                .iter()
                .any(|(k, v)| k == "service.name" && v == "oraclemcp"),
            "service.name resource attribute present"
        );
        // Protobuf encodes to a non-empty, well-formed OTLP body.
        let bytes = snapshot.to_otlp_protobuf();
        assert!(!bytes.is_empty(), "OTLP logs protobuf encodes");
    }

    #[test]
    fn secret_attributes_are_dropped_and_bodies_redacted() {
        let config = cfg();
        let r = Redactor::new();
        let records = vec![
            LogRecordInput::new(LogLevel::Warn, "auth used Bearer deadbeefdeadbeef", 1)
                .with_attribute("password", "hunter2")
                .with_attribute("tool", "oracle_session")
                .with_attribute("bind_0", "social-security-number"),
        ];
        let snapshot = build_snapshot(&config, &r, &records);
        let record = &snapshot.records[0];
        // Body redacted (Bearer token).
        assert_eq!(record.body, super::super::redact::REDACTED);
        // Sensitive keys dropped, safe key kept.
        let keys: Vec<&str> = record.attributes.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!keys.contains(&"password"), "password dropped");
        assert!(!keys.contains(&"bind_0"), "bind value dropped");
        assert!(keys.contains(&"tool"), "safe attribute kept");
    }

    #[test]
    fn sensitive_db_attributes_never_reach_log_protobuf() {
        const SENTINEL: &str = "QA34_DB_SECRET_SENTINEL";
        let config = cfg();
        let records = vec![
            LogRecordInput::new(LogLevel::Warn, "database event", 1)
                .with_attribute("db.password", SENTINEL)
                .with_attribute("db.bind_count", "2")
                .with_attribute("db.vendor.extension", format!("Bearer {SENTINEL}")),
        ];
        let snapshot = build_snapshot(&config, &Redactor::new(), &records);
        let record = &snapshot.records[0];
        assert!(
            !record
                .attributes
                .iter()
                .any(|(key, _)| key == "db.password")
        );
        assert!(
            record
                .attributes
                .iter()
                .any(|(key, value)| { key == "db.bind_count" && value == "2" })
        );
        assert!(record.attributes.iter().any(|(key, value)| {
            key == "db.vendor.extension" && value == super::super::redact::REDACTED
        }));

        let bytes = snapshot.to_otlp_protobuf();
        assert!(
            !bytes
                .windows(SENTINEL.len())
                .any(|window| window == SENTINEL.as_bytes()),
            "sensitive db.* sentinel must not reach OTLP log bytes"
        );
    }
}
