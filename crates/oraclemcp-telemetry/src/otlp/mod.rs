//! OTLP/OpenTelemetry export for oraclemcp (D1 / WP-D observability stack,
//! bead `oraclemcp-040-epic-wp-d-1il` `.1`–`.4`).
//!
//! Telemetry export is **OFF BY DEFAULT**: nothing here is wired unless an OTLP
//! endpoint is configured via the standard `OTEL_EXPORTER_OTLP_*` environment
//! variables (see [`config::OtlpConfig`]). Egress goes ONLY through asupersync's
//! Tokio-free exporters — there is no reqwest/hyper/tonic/tokio anywhere in this
//! module (the engine-free boundary lint enforces that).
//!
//! Submodules:
//! - [`config`] — `OtlpConfig` from env + the off-by-default toggle.
//! - [`redact`] — load-bearing secret redaction (no binds/passwords/tokens).
//! - [`proto`] — hand-rolled OTLP protobuf wire types for metrics + traces.
//! - [`logs`] — turnkey logs export via `OtlpLogsHttpExporter` (`.1`).
//! - [`metrics`] — hand-rolled `ExportMetricsServiceRequest` (`.2`).
//! - [`traces`] — `tracing` `Layer` → `Span` bridge + `ExportTraceServiceRequest` (`.3`).
//! - [`pump`] — region-owned background export pump (no detached spawn; bounded
//!   shutdown budget; telemetry failure DROPS, never blocks the request path).

pub mod config;
pub mod logs;
pub mod metrics;
pub mod proto;
pub mod pump;
pub mod redact;
pub mod traces;

pub use config::OtlpConfig;
pub use pump::{ExportPump, PumpHandle};
pub use redact::Redactor;

use asupersync::observability::otel::OtlpHttpExporter;

/// Build an `OtlpHttpExporter` for `endpoint` with the config's timeout,
/// compression, and `OTEL_EXPORTER_OTLP_HEADERS` auth headers applied.
///
/// Auth headers flow ONLY into the outbound request (`Authorization` / API-key);
/// they are never exported as telemetry. A header literally named
/// `authorization` is sent as the `Authorization` header; any other header is a
/// custom header.
#[must_use]
pub(crate) fn build_http_exporter(endpoint: &str, config: &OtlpConfig) -> OtlpHttpExporter {
    let mut exporter = OtlpHttpExporter::new(endpoint.to_owned())
        .with_timeout(config.timeout)
        .with_compression(config.compression);
    for (name, value) in &config.headers {
        exporter = exporter.with_auth_header(name.clone(), value.clone());
    }
    exporter
}
