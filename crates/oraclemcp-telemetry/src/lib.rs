#![forbid(unsafe_code)]

//! Observability for the `oraclemcp` Oracle MCP server: structured `tracing`
//! JSON logs, an OpenTelemetry metrics/traces bridge, and the `/healthz`
//! `/readyz` health endpoint (plan §10; beads P0-1 scaffold, P1-8, P2-6).
//!
//! Phase-A skeleton. Logs never carry bind values or secrets.

/// Re-export the shared agent-facing error envelope.
pub use oraclemcp_error as error;
