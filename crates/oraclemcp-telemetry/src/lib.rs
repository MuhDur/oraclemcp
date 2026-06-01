#![forbid(unsafe_code)]

//! Observability for the `oraclemcp` server (plan §10; bead P1-8): structured
//! `tracing` JSON logging and liveness/readiness health state. OpenTelemetry
//! metrics/traces (P2-6) build on this; logs never carry bind values or secrets.

mod health;
mod logging;
mod metrics;

pub use health::{HealthReport, HealthState};
pub use logging::init_json_logging;
pub use metrics::{ErrorCount, HistogramSnapshot, Metrics, MetricsSnapshot, RequestCount};

/// Re-export the shared agent-facing error envelope.
pub use oraclemcp_error as error;
