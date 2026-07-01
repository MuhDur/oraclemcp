#![forbid(unsafe_code)]

//! Observability for the `oraclemcp` server (plan §10; beads P1-8 + WP-D `D1`):
//! structured `tracing` JSON logging, liveness/readiness health state, an
//! in-process metrics registry, and — when configured — OpenTelemetry **OTLP**
//! export of logs, metrics, and traces over asupersync's Tokio-free HTTP/1
//! client.
//!
//! OTLP export is **OFF BY DEFAULT**: it is wired only when an OTLP endpoint is
//! configured via the standard `OTEL_EXPORTER_OTLP_*` environment variables (see
//! [`otlp::OtlpConfig`]). With no endpoint set, logs stay local (JSON to stderr),
//! metrics stay Prometheus-text/JSON-snapshot only, and traces stay `tracing`-only.
//!
//! **Secrets are never emitted**: SQL bind values, passwords, tokens, and wallet
//! secrets are stripped by [`otlp::Redactor`] before any log/metric/span leaves
//! the process.

mod health;
mod logging;
mod metrics;
pub mod otlp;

pub use health::{HealthReport, HealthState};
pub use logging::{TelemetryGuard, init_json_logging, init_telemetry};
pub use metrics::{
    ActiveLaneGauge, ErrorCount, HistogramSnapshot, LaneBlockedCount, LaneRequestCount,
    LaneRequestDuration, Metrics, MetricsSnapshot, RequestCount,
};
pub use otlp::{ExportPump, OtlpConfig, PumpHandle, Redactor};

/// Re-export the shared agent-facing error envelope.
pub use oraclemcp_error as error;
