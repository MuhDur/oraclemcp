//! OTLP exporter configuration (D1 / WP-D bead `oraclemcp-040-epic-wp-d-1il`).
//!
//! Telemetry export is **OFF BY DEFAULT**. It is enabled only when an OTLP
//! endpoint is configured — via the standard `OTEL_EXPORTER_OTLP_*` environment
//! variables (matching the OpenTelemetry spec) plus an explicit operator toggle
//! threaded from the CLI. With no endpoint configured, [`OtlpConfig::from_env`]
//! returns `None` and **no exporter is ever wired** (logs stay local-stderr-only,
//! metrics stay Prometheus-text-only, traces stay `tracing`-only).
//!
//! ## Config surface (standard OTEL env vars)
//!
//! | Variable | Meaning | Default |
//! |----------|---------|---------|
//! | `OTEL_EXPORTER_OTLP_ENDPOINT` | base collector URL (`http://host:4318`) | unset → export OFF |
//! | `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` | per-signal override for logs | base + `/v1/logs` |
//! | `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` | per-signal override for metrics | base + `/v1/metrics` |
//! | `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | per-signal override for traces | base + `/v1/traces` |
//! | `OTEL_EXPORTER_OTLP_HEADERS` | `k1=v1,k2=v2` auth headers (e.g. an API key) | none |
//! | `OTEL_EXPORTER_OTLP_TIMEOUT` | per-request timeout (ms) | 10000 |
//! | `OTEL_EXPORTER_OTLP_COMPRESSION` | `gzip` to enable request gzip | off |
//! | `OTEL_SERVICE_NAME` | `service.name` resource attribute | `oraclemcp` |
//! | `OTEL_TRACES_SAMPLER_ARG` | head-sampling ratio in `[0.0, 1.0]` | 1.0 |
//! | `OTEL_METRICS_SAMPLER_ARG` | metric-export sampling ratio (oraclemcp ext.) | 1.0 |
//!
//! Only the HTTP/protobuf OTLP transport is supported — gRPC is deliberately
//! absent (tonic would pull Tokio and break the engine-free boundary, plan §0).
//!
//! ## Secret redaction (load-bearing)
//!
//! Telemetry MUST NEVER emit SQL bind values, passwords, tokens, or wallet
//! secrets. [`Redactor`] enforces this on every attribute/field/log body before
//! it reaches a `LogsSnapshot`, a metric label, or a span attribute. The header
//! map ([`OtlpConfig::headers`]) holds the collector auth secret and is never
//! itself exported — it only flows into the outbound HTTP `Authorization` /
//! API-key headers via asupersync's exporter.

use std::collections::BTreeMap;
use std::time::Duration;

/// The default `service.name` when `OTEL_SERVICE_NAME` is unset.
pub const DEFAULT_SERVICE_NAME: &str = "oraclemcp";
/// Default OTLP per-request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// OTLP HTTP/protobuf logs path appended to a base endpoint.
pub const LOGS_PATH: &str = "/v1/logs";
/// OTLP HTTP/protobuf metrics path appended to a base endpoint.
pub const METRICS_PATH: &str = "/v1/metrics";
/// OTLP HTTP/protobuf traces path appended to a base endpoint.
pub const TRACES_PATH: &str = "/v1/traces";

/// Resolved OTLP exporter configuration. Constructed only when an endpoint is
/// configured; its mere existence is the "telemetry is on" signal.
#[derive(Clone, Debug, PartialEq)]
pub struct OtlpConfig {
    /// Fully-qualified logs endpoint (e.g. `http://collector:4318/v1/logs`).
    pub logs_endpoint: String,
    /// Fully-qualified metrics endpoint.
    pub metrics_endpoint: String,
    /// Fully-qualified traces endpoint.
    pub traces_endpoint: String,
    /// Outbound auth headers (collector API key / bearer). NEVER exported as
    /// telemetry — only attached to the OTLP HTTP request.
    pub headers: Vec<(String, String)>,
    /// Per-request timeout.
    pub timeout: Duration,
    /// Whether to gzip request bodies (requires asupersync `compression`).
    pub compression: bool,
    /// `service.name` resource attribute.
    pub service_name: String,
    /// Head-sampling ratio for traces, clamped to `[0.0, 1.0]`.
    pub trace_sample_ratio: f64,
    /// Export sampling ratio for metrics batches, clamped to `[0.0, 1.0]`.
    pub metrics_sample_ratio: f64,
}

impl OtlpConfig {
    /// Build configuration from the process environment.
    ///
    /// Returns `None` (export OFF) unless an endpoint is configured via
    /// `OTEL_EXPORTER_OTLP_ENDPOINT` or any per-signal `*_ENDPOINT` override.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Build configuration from an arbitrary key→value lookup (testable).
    ///
    /// Returns `None` if no base or per-signal endpoint is present.
    #[must_use]
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let trimmed = |key: &str| {
            lookup(key)
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        };

        let base = trimmed("OTEL_EXPORTER_OTLP_ENDPOINT");
        let logs_override = trimmed("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT");
        let metrics_override = trimmed("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT");
        let traces_override = trimmed("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT");

        // Off-by-default: with no endpoint anywhere, return None — nothing wired.
        if base.is_none()
            && logs_override.is_none()
            && metrics_override.is_none()
            && traces_override.is_none()
        {
            return None;
        }

        let logs_endpoint = logs_override.unwrap_or_else(|| join_path(base.as_deref(), LOGS_PATH));
        let metrics_endpoint =
            metrics_override.unwrap_or_else(|| join_path(base.as_deref(), METRICS_PATH));
        let traces_endpoint =
            traces_override.unwrap_or_else(|| join_path(base.as_deref(), TRACES_PATH));

        let headers = trimmed("OTEL_EXPORTER_OTLP_HEADERS")
            .map(|raw| parse_headers(&raw))
            .unwrap_or_default();

        let timeout = trimmed("OTEL_EXPORTER_OTLP_TIMEOUT")
            .and_then(|ms| ms.parse::<u64>().ok())
            .map_or(DEFAULT_TIMEOUT, Duration::from_millis);

        let compression = trimmed("OTEL_EXPORTER_OTLP_COMPRESSION")
            .is_some_and(|v| v.eq_ignore_ascii_case("gzip"));

        let service_name =
            trimmed("OTEL_SERVICE_NAME").unwrap_or_else(|| DEFAULT_SERVICE_NAME.to_owned());

        let trace_sample_ratio = trimmed("OTEL_TRACES_SAMPLER_ARG")
            .and_then(|v| v.parse::<f64>().ok())
            .map_or(1.0, clamp_ratio);
        let metrics_sample_ratio = trimmed("OTEL_METRICS_SAMPLER_ARG")
            .and_then(|v| v.parse::<f64>().ok())
            .map_or(1.0, clamp_ratio);

        Some(Self {
            logs_endpoint,
            metrics_endpoint,
            traces_endpoint,
            headers,
            timeout,
            compression,
            service_name,
            trace_sample_ratio,
            metrics_sample_ratio,
        })
    }
}

fn clamp_ratio(r: f64) -> f64 {
    if r.is_nan() { 1.0 } else { r.clamp(0.0, 1.0) }
}

/// Join a base endpoint with a per-signal path, tolerating a trailing slash.
/// When `base` is `None` (only per-signal overrides were set elsewhere) the path
/// is returned as-is; callers always pass a concrete override in that case.
fn join_path(base: Option<&str>, path: &str) -> String {
    match base {
        Some(base) => {
            let base = base.trim_end_matches('/');
            format!("{base}{path}")
        }
        None => path.to_owned(),
    }
}

/// Parse an `OTEL_EXPORTER_OTLP_HEADERS` value (`k1=v1,k2=v2`) into pairs.
///
/// De-duplicated on key (last write wins) and ordered for determinism. Empty
/// keys are skipped. Values may contain `=`; only the first `=` splits.
fn parse_headers(raw: &str) -> Vec<(String, String)> {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for pair in raw.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        if let Some((key, value)) = pair.split_once('=') {
            let key = key.trim();
            if !key.is_empty() {
                map.insert(key.to_owned(), value.trim().to_owned());
            }
        }
    }
    map.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup_from(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |key: &str| map.get(key).cloned()
    }

    #[test]
    fn off_by_default_with_no_endpoint() {
        let cfg = OtlpConfig::from_lookup(lookup_from(&[]));
        assert!(cfg.is_none(), "no endpoint -> export OFF");
        // Even with sampler/service set, no endpoint means OFF.
        let cfg = OtlpConfig::from_lookup(lookup_from(&[
            ("OTEL_SERVICE_NAME", "x"),
            ("OTEL_TRACES_SAMPLER_ARG", "0.5"),
        ]));
        assert!(cfg.is_none(), "endpoint is the only enable switch");
    }

    #[test]
    fn base_endpoint_derives_per_signal_paths() {
        let cfg = OtlpConfig::from_lookup(lookup_from(&[(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "http://collector:4318/",
        )]))
        .expect("endpoint present -> on");
        assert_eq!(cfg.logs_endpoint, "http://collector:4318/v1/logs");
        assert_eq!(cfg.metrics_endpoint, "http://collector:4318/v1/metrics");
        assert_eq!(cfg.traces_endpoint, "http://collector:4318/v1/traces");
        assert_eq!(cfg.service_name, DEFAULT_SERVICE_NAME);
        assert!((cfg.trace_sample_ratio - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn per_signal_override_wins() {
        let cfg = OtlpConfig::from_lookup(lookup_from(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://base:4318"),
            (
                "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                "http://traces:9999/custom",
            ),
        ]))
        .expect("on");
        assert_eq!(cfg.traces_endpoint, "http://traces:9999/custom");
        assert_eq!(cfg.logs_endpoint, "http://base:4318/v1/logs");
    }

    #[test]
    fn only_per_signal_override_enables() {
        let cfg = OtlpConfig::from_lookup(lookup_from(&[(
            "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
            "http://m:4318/v1/metrics",
        )]))
        .expect("a per-signal endpoint also enables");
        assert_eq!(cfg.metrics_endpoint, "http://m:4318/v1/metrics");
    }

    #[test]
    fn headers_parsed_and_deduped() {
        let cfg = OtlpConfig::from_lookup(lookup_from(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://c:4318"),
            (
                "OTEL_EXPORTER_OTLP_HEADERS",
                "api-key=secret123, x-tenant = acme , api-key=override",
            ),
        ]))
        .expect("on");
        // last write wins, sorted by key
        assert_eq!(
            cfg.headers,
            vec![
                ("api-key".to_owned(), "override".to_owned()),
                ("x-tenant".to_owned(), "acme".to_owned()),
            ]
        );
    }

    #[test]
    fn timeout_and_compression_and_sampling() {
        let cfg = OtlpConfig::from_lookup(lookup_from(&[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://c:4318"),
            ("OTEL_EXPORTER_OTLP_TIMEOUT", "2500"),
            ("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip"),
            ("OTEL_TRACES_SAMPLER_ARG", "0.25"),
            ("OTEL_METRICS_SAMPLER_ARG", "1.5"),
        ]))
        .expect("on");
        assert_eq!(cfg.timeout, Duration::from_millis(2500));
        assert!(cfg.compression);
        assert!((cfg.trace_sample_ratio - 0.25).abs() < f64::EPSILON);
        assert!(
            (cfg.metrics_sample_ratio - 1.0).abs() < f64::EPSILON,
            "out-of-range ratio clamps to 1.0"
        );
    }
}
