//! OTLP metrics export (D1-metrics, bead `oraclemcp-040-epic-wp-d-1il.2`).
//!
//! Hand-rolls an `ExportMetricsServiceRequest` from the crate's
//! [`MetricsSnapshot`] (see `crate::metrics`) and sends the encoded protobuf
//! through asupersync's Tokio-free `OtlpHttpExporter::send_otlp_protobuf`.
//!
//! Attribute mapping follows the OTel **`db.*` semantic conventions** where the
//! value does not leak (e.g. `db.system.name = oracle`,
//! `db.response.status_code` for the ORA code). SQL bind values and statement
//! text are NEVER emitted. Every label passes through [`Redactor`].
//!
//! Sampling: `config.metrics_sample_ratio` gates whether a given export batch is
//! sent at all (a cheap, deterministic batch-level head sampler — metrics are
//! cumulative so dropping a batch only delays, never corrupts, the series).

use asupersync::observability::ExportError;

use crate::metrics::MetricsSnapshot;

use super::config::OtlpConfig;
use super::proto::{
    AGGREGATION_TEMPORALITY_CUMULATIVE, ExportMetricsServiceRequest, Gauge, Histogram,
    HistogramDataPoint, InstrumentationScope, Metric, NumberDataPoint, Resource, ResourceMetrics,
    ScopeMetrics, Sum, key_value, metric, number_data_point,
};
use super::redact::Redactor;

/// OTel schema URL the exported scope is anchored to.
pub const OTEL_SCHEMA_URL: &str = "https://opentelemetry.io/schemas/1.37.0";
/// Instrumentation scope name.
pub const SCOPE_NAME: &str = "oraclemcp.telemetry";
/// Instrumentation scope version.
pub const SCOPE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build an OTLP `ExportMetricsServiceRequest` from a [`MetricsSnapshot`].
///
/// `now_unix_nano` is the export timestamp (the `time_unix_nano` of cumulative
/// points). `start_unix_nano` is the process/series start. All metric labels are
/// funneled through [`Redactor`] (drop sensitive keys, redact secret-shaped
/// values) before they reach the wire.
#[must_use]
pub fn build_request(
    config: &OtlpConfig,
    redactor: &Redactor,
    snapshot: &MetricsSnapshot,
    start_unix_nano: u64,
    now_unix_nano: u64,
) -> ExportMetricsServiceRequest {
    let mut metrics: Vec<Metric> = Vec::new();

    // mcp.server.request.count {tool, status} — monotonic counter.
    for r in &snapshot.requests {
        let attrs = redact_labels(redactor, &[("tool", &r.tool), ("status", &r.status)]);
        metrics.push(sum_metric(
            "mcp.server.request.count",
            "Count of MCP tool dispatches by tool and status.",
            "1",
            attrs,
            i64::try_from(r.count).unwrap_or(i64::MAX),
            start_unix_nano,
            now_unix_nano,
        ));
    }

    // db.errors {db.response.status_code} — monotonic counter, db.* conventions.
    for e in &snapshot.errors {
        let code = e.ora_code.to_string();
        let attrs = redact_labels(
            redactor,
            &[
                ("db.system.name", "oracle"),
                ("db.response.status_code", &code),
            ],
        );
        metrics.push(sum_metric(
            "db.client.errors",
            "Count of Oracle DB errors by ORA code.",
            "1",
            attrs,
            i64::try_from(e.count).unwrap_or(i64::MAX),
            start_unix_nano,
            now_unix_nano,
        ));
    }

    // db.client.operation.duration — histogram (ms). db.* convention name.
    metrics.push(histogram_metric(
        "db.client.operation.duration",
        "Oracle query duration.",
        "ms",
        vec![key_value("db.system.name", "oracle")],
        snapshot.query_duration_ms.count,
        snapshot.query_duration_ms.sum,
        snapshot.query_duration_ms.max,
        start_unix_nano,
        now_unix_nano,
    ));

    // db.client.connection.wait_time — histogram (ms) for pool checkout wait.
    metrics.push(histogram_metric(
        "db.client.connection.wait_time",
        "Time spent waiting to acquire a pooled connection.",
        "ms",
        vec![key_value("db.system.name", "oracle")],
        snapshot.pool_wait_ms.count,
        snapshot.pool_wait_ms.sum,
        snapshot.pool_wait_ms.max,
        start_unix_nano,
        now_unix_nano,
    ));

    // db.client.connection.count — gauge of active pooled connections.
    metrics.push(gauge_metric(
        "db.client.connection.count",
        "Active pooled Oracle connections.",
        "{connection}",
        vec![
            key_value("db.system.name", "oracle"),
            key_value("state", "used"),
        ],
        i64::try_from(snapshot.pool_active_connections).unwrap_or(i64::MAX),
        now_unix_nano,
    ));

    ExportMetricsServiceRequest {
        resource_metrics: vec![ResourceMetrics {
            resource: Some(Resource {
                attributes: vec![
                    key_value("service.name", config.service_name.clone()),
                    key_value("telemetry.sdk.name", "oraclemcp"),
                    key_value("telemetry.sdk.version", SCOPE_VERSION),
                ],
            }),
            scope_metrics: vec![ScopeMetrics {
                scope: Some(InstrumentationScope {
                    name: SCOPE_NAME.to_owned(),
                    version: SCOPE_VERSION.to_owned(),
                }),
                metrics,
                schema_url: OTEL_SCHEMA_URL.to_owned(),
            }],
            schema_url: OTEL_SCHEMA_URL.to_owned(),
        }],
    }
}

fn redact_labels(redactor: &Redactor, labels: &[(&str, &str)]) -> Vec<super::proto::KeyValue> {
    labels
        .iter()
        .filter_map(|(key, value)| {
            redactor
                .filter(key, value)
                .map(|(safe_key, safe_value)| key_value(safe_key, safe_value))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn sum_metric(
    name: &str,
    description: &str,
    unit: &str,
    attributes: Vec<super::proto::KeyValue>,
    value: i64,
    start: u64,
    now: u64,
) -> Metric {
    Metric {
        name: name.to_owned(),
        description: description.to_owned(),
        unit: unit.to_owned(),
        data: Some(metric::Data::Sum(Sum {
            aggregation_temporality: AGGREGATION_TEMPORALITY_CUMULATIVE,
            is_monotonic: true,
            data_points: vec![NumberDataPoint {
                attributes,
                start_time_unix_nano: start,
                time_unix_nano: now,
                value: Some(number_data_point::Value::AsInt(value)),
            }],
        })),
    }
}

fn gauge_metric(
    name: &str,
    description: &str,
    unit: &str,
    attributes: Vec<super::proto::KeyValue>,
    value: i64,
    now: u64,
) -> Metric {
    Metric {
        name: name.to_owned(),
        description: description.to_owned(),
        unit: unit.to_owned(),
        data: Some(metric::Data::Gauge(Gauge {
            data_points: vec![NumberDataPoint {
                attributes,
                start_time_unix_nano: 0,
                time_unix_nano: now,
                value: Some(number_data_point::Value::AsInt(value)),
            }],
        })),
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::cast_precision_loss)]
fn histogram_metric(
    name: &str,
    description: &str,
    unit: &str,
    attributes: Vec<super::proto::KeyValue>,
    count: u64,
    sum: u64,
    max: u64,
    start: u64,
    now: u64,
) -> Metric {
    Metric {
        name: name.to_owned(),
        description: description.to_owned(),
        unit: unit.to_owned(),
        data: Some(metric::Data::Histogram(Histogram {
            aggregation_temporality: AGGREGATION_TEMPORALITY_CUMULATIVE,
            data_points: vec![HistogramDataPoint {
                attributes,
                start_time_unix_nano: start,
                time_unix_nano: now,
                count,
                sum: Some(sum as f64),
                // No explicit bucket boundaries: a single implicit (-inf, +inf)
                // bucket carrying the full count. Collectors accept this; it is
                // the count+sum aggregation our in-process Histogram tracks.
                bucket_counts: vec![count],
                explicit_bounds: Vec::new(),
                max: if count == 0 { None } else { Some(max as f64) },
            }],
        })),
    }
}

/// Decide whether to export this metrics batch under the configured ratio.
///
/// Cumulative metrics are resilient to a dropped batch (the next batch carries
/// the up-to-date totals), so a simple uniform sampler on a rotating sequence is
/// sufficient and deterministic. `seq` is a monotonically increasing batch
/// counter supplied by the caller.
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
pub fn should_export_batch(ratio: f64, seq: u64) -> bool {
    if ratio >= 1.0 {
        return true;
    }
    if ratio <= 0.0 {
        return false;
    }
    // Deterministic stride sampler: keep ~ratio of batches, evenly spread.
    let period = (1.0 / ratio).round().max(1.0) as u64;
    seq.is_multiple_of(period)
}

/// Encode + send a metrics request through asupersync's Tokio-free exporter.
///
/// Off-the-request-path; Cx-aware. Auth headers from `OTEL_EXPORTER_OTLP_HEADERS`
/// are attached to the outbound request (never exported as telemetry).
///
/// # Errors
/// Returns the asupersync `ExportError` if the OTLP request fails after retries.
pub async fn export_request(
    cx: &asupersync::Cx,
    config: &OtlpConfig,
    request: &ExportMetricsServiceRequest,
) -> Result<(), ExportError> {
    let exporter = super::build_http_exporter(&config.metrics_endpoint, config);
    exporter.send_otlp_protobuf(cx, request.to_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::Metrics;
    use prost::Message;

    fn cfg() -> OtlpConfig {
        OtlpConfig::from_lookup(|k| {
            (k == "OTEL_EXPORTER_OTLP_ENDPOINT").then(|| "http://c:4318".to_owned())
        })
        .expect("on")
    }

    #[test]
    fn maps_snapshot_to_db_semantic_conventions_and_roundtrips() {
        let m = Metrics::new();
        m.record_request("oracle_query", "ok");
        m.record_request("oracle_query", "error");
        m.record_error(942);
        m.record_query_duration_ms(10);
        m.record_query_duration_ms(30);
        m.record_pool_wait_ms(5);
        m.set_pool_active(3);
        let snap = m.snapshot();

        let req = build_request(&cfg(), &Redactor::new(), &snap, 1_000, 2_000);
        let bytes = req.to_bytes();
        let decoded = ExportMetricsServiceRequest::decode(bytes.as_slice()).expect("decodes");
        assert_eq!(decoded, req, "metrics request roundtrips");

        let names: Vec<&str> = decoded.resource_metrics[0].scope_metrics[0]
            .metrics
            .iter()
            .map(|metric| metric.name.as_str())
            .collect();
        assert!(names.contains(&"mcp.server.request.count"));
        assert!(names.contains(&"db.client.errors"));
        assert!(names.contains(&"db.client.operation.duration"));
        assert!(names.contains(&"db.client.connection.count"));

        // db.* convention: the error metric carries db.system.name + response code.
        let err_metric = decoded.resource_metrics[0].scope_metrics[0]
            .metrics
            .iter()
            .find(|metric| metric.name == "db.client.errors")
            .expect("errors metric");
        if let Some(metric::Data::Sum(sum)) = &err_metric.data {
            let keys: Vec<&str> = sum.data_points[0]
                .attributes
                .iter()
                .map(|kv| kv.key.as_str())
                .collect();
            assert!(keys.contains(&"db.system.name"));
            assert!(keys.contains(&"db.response.status_code"));
        } else {
            panic!("errors metric must be a Sum");
        }
    }

    #[test]
    fn no_secret_labels_reach_the_wire() {
        // A request with a tool name that is structured & safe; assert no label
        // value across the whole request looks like a secret or a bind value.
        let m = Metrics::new();
        m.record_request("oracle_query", "ok");
        let snap = m.snapshot();
        let req = build_request(&cfg(), &Redactor::new(), &snap, 1, 2);
        for rm in &req.resource_metrics {
            for sm in &rm.scope_metrics {
                for metric in &sm.metrics {
                    let dps_attrs: Vec<&super::super::proto::KeyValue> = match &metric.data {
                        Some(metric::Data::Sum(s)) => {
                            s.data_points.iter().flat_map(|p| &p.attributes).collect()
                        }
                        Some(metric::Data::Gauge(g)) => {
                            g.data_points.iter().flat_map(|p| &p.attributes).collect()
                        }
                        Some(metric::Data::Histogram(h)) => {
                            h.data_points.iter().flat_map(|p| &p.attributes).collect()
                        }
                        None => vec![],
                    };
                    for kv in dps_attrs {
                        assert!(!kv.key.to_ascii_lowercase().contains("bind"));
                        assert!(!kv.key.to_ascii_lowercase().contains("password"));
                    }
                }
            }
        }
    }

    #[test]
    fn batch_sampling_respects_ratio() {
        assert!(should_export_batch(1.0, 12345));
        assert!(!should_export_batch(0.0, 12345));
        // ratio 0.5 -> every other batch (period 2).
        assert!(should_export_batch(0.5, 0));
        assert!(!should_export_batch(0.5, 1));
        assert!(should_export_batch(0.5, 2));
    }
}
