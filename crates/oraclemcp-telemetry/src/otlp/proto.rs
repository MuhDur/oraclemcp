//! Hand-rolled OTLP protobuf wire types (D1-metrics `.2` + D1-traces `.3`).
//!
//! asupersync's own metrics/trace proto encoders are `cfg(fuzz)`/test-gated and
//! pull `opentelemetry-proto` (→ tonic → Tokio), so they are NOT reachable from
//! a `metrics`-only production build. The bead therefore says to hand-roll our
//! own `ExportMetricsServiceRequest` / `ExportTraceServiceRequest`, mirroring
//! the field numbers and structure asupersync's vendored encoder uses (which in
//! turn mirror the upstream `opentelemetry-proto` `.proto` definitions). Encoded
//! bodies are sent through `OtlpHttpExporter::send_otlp_protobuf` (Tokio-free).
//!
//! Only the field subset oraclemcp emits is modeled; `prost` skips defaulted
//! fields, so a partial-but-correct message is still valid OTLP. The field
//! numbers below are load-bearing — they MUST match the OTLP proto contract
//! (collectors decode by tag number, not name).

#![allow(clippy::doc_markdown)]

use prost::Message;

// ===========================================================================
// common/v1 — shared by metrics and traces
// ===========================================================================

/// `opentelemetry.proto.common.v1.AnyValue` (string variant only — every
/// oraclemcp attribute is a string).
#[derive(Clone, PartialEq, Message)]
pub struct AnyValue {
    #[prost(oneof = "any_value::Value", tags = "1")]
    pub value: Option<any_value::Value>,
}

/// Oneof for [`AnyValue`].
pub mod any_value {
    /// The value variants we emit.
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Value {
        /// UTF-8 string value.
        #[prost(string, tag = "1")]
        StringValue(String),
    }
}

/// `opentelemetry.proto.common.v1.KeyValue`.
#[derive(Clone, PartialEq, Message)]
pub struct KeyValue {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(message, optional, tag = "2")]
    pub value: Option<AnyValue>,
}

/// `opentelemetry.proto.common.v1.InstrumentationScope`.
#[derive(Clone, PartialEq, Message)]
pub struct InstrumentationScope {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub version: String,
}

/// `opentelemetry.proto.resource.v1.Resource`.
#[derive(Clone, PartialEq, Message)]
pub struct Resource {
    #[prost(message, repeated, tag = "1")]
    pub attributes: Vec<KeyValue>,
}

/// Build a string-valued [`KeyValue`].
#[must_use]
pub fn key_value(key: impl Into<String>, value: impl Into<String>) -> KeyValue {
    KeyValue {
        key: key.into(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.into())),
        }),
    }
}

// ===========================================================================
// metrics/v1
// ===========================================================================

/// `opentelemetry.proto.collector.metrics.v1.ExportMetricsServiceRequest`.
#[derive(Clone, PartialEq, Message)]
pub struct ExportMetricsServiceRequest {
    #[prost(message, repeated, tag = "1")]
    pub resource_metrics: Vec<ResourceMetrics>,
}

impl ExportMetricsServiceRequest {
    /// Encode to the OTLP protobuf wire body.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

/// `metrics.v1.ResourceMetrics`.
#[derive(Clone, PartialEq, Message)]
pub struct ResourceMetrics {
    #[prost(message, optional, tag = "1")]
    pub resource: Option<Resource>,
    #[prost(message, repeated, tag = "2")]
    pub scope_metrics: Vec<ScopeMetrics>,
    #[prost(string, tag = "3")]
    pub schema_url: String,
}

/// `metrics.v1.ScopeMetrics`.
#[derive(Clone, PartialEq, Message)]
pub struct ScopeMetrics {
    #[prost(message, optional, tag = "1")]
    pub scope: Option<InstrumentationScope>,
    #[prost(message, repeated, tag = "2")]
    pub metrics: Vec<Metric>,
    #[prost(string, tag = "3")]
    pub schema_url: String,
}

/// `metrics.v1.Metric`.
#[derive(Clone, PartialEq, Message)]
pub struct Metric {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub description: String,
    #[prost(string, tag = "3")]
    pub unit: String,
    #[prost(oneof = "metric::Data", tags = "5, 7, 9")]
    pub data: Option<metric::Data>,
}

/// Oneof for [`Metric`] (matching upstream field numbers: Gauge=5, Sum=7,
/// Histogram=9).
pub mod metric {
    use super::{Gauge, Histogram, Sum};

    /// The metric-data variants we emit.
    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Data {
        /// A gauge (last-value).
        #[prost(message, tag = "5")]
        Gauge(Gauge),
        /// A monotonic cumulative sum (counter).
        #[prost(message, tag = "7")]
        Sum(Sum),
        /// A cumulative histogram.
        #[prost(message, tag = "9")]
        Histogram(Histogram),
    }
}

/// `metrics.v1.Gauge`.
#[derive(Clone, PartialEq, Message)]
pub struct Gauge {
    #[prost(message, repeated, tag = "1")]
    pub data_points: Vec<NumberDataPoint>,
}

/// `metrics.v1.Sum`.
#[derive(Clone, PartialEq, Message)]
pub struct Sum {
    #[prost(message, repeated, tag = "1")]
    pub data_points: Vec<NumberDataPoint>,
    #[prost(int32, tag = "2")]
    pub aggregation_temporality: i32,
    #[prost(bool, tag = "3")]
    pub is_monotonic: bool,
}

/// `metrics.v1.Histogram`.
#[derive(Clone, PartialEq, Message)]
pub struct Histogram {
    #[prost(message, repeated, tag = "1")]
    pub data_points: Vec<HistogramDataPoint>,
    #[prost(int32, tag = "2")]
    pub aggregation_temporality: i32,
}

/// `metrics.v1.NumberDataPoint`.
#[derive(Clone, PartialEq, Message)]
pub struct NumberDataPoint {
    #[prost(message, repeated, tag = "7")]
    pub attributes: Vec<KeyValue>,
    #[prost(fixed64, tag = "2")]
    pub start_time_unix_nano: u64,
    #[prost(fixed64, tag = "3")]
    pub time_unix_nano: u64,
    #[prost(oneof = "number_data_point::Value", tags = "4, 6")]
    pub value: Option<number_data_point::Value>,
}

/// Oneof for [`NumberDataPoint`] (AsDouble=4, AsInt=6 per upstream).
pub mod number_data_point {
    /// Numeric value variants.
    #[derive(Clone, Copy, PartialEq, prost::Oneof)]
    pub enum Value {
        /// Double value.
        #[prost(double, tag = "4")]
        AsDouble(f64),
        /// Signed-integer value.
        #[prost(sfixed64, tag = "6")]
        AsInt(i64),
    }
}

/// `metrics.v1.HistogramDataPoint`.
#[derive(Clone, PartialEq, Message)]
pub struct HistogramDataPoint {
    #[prost(message, repeated, tag = "9")]
    pub attributes: Vec<KeyValue>,
    #[prost(fixed64, tag = "2")]
    pub start_time_unix_nano: u64,
    #[prost(fixed64, tag = "3")]
    pub time_unix_nano: u64,
    #[prost(fixed64, tag = "4")]
    pub count: u64,
    #[prost(double, optional, tag = "5")]
    pub sum: Option<f64>,
    #[prost(fixed64, repeated, tag = "6")]
    pub bucket_counts: Vec<u64>,
    #[prost(double, repeated, tag = "7")]
    pub explicit_bounds: Vec<f64>,
    #[prost(double, optional, tag = "11")]
    pub max: Option<f64>,
}

/// OTLP `AggregationTemporality::Cumulative`.
pub const AGGREGATION_TEMPORALITY_CUMULATIVE: i32 = 2;

// ===========================================================================
// trace/v1
// ===========================================================================

/// `opentelemetry.proto.collector.trace.v1.ExportTraceServiceRequest`.
#[derive(Clone, PartialEq, Message)]
pub struct ExportTraceServiceRequest {
    #[prost(message, repeated, tag = "1")]
    pub resource_spans: Vec<ResourceSpans>,
}

impl ExportTraceServiceRequest {
    /// Encode to the OTLP protobuf wire body.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encode_to_vec()
    }
}

/// `trace.v1.ResourceSpans`.
#[derive(Clone, PartialEq, Message)]
pub struct ResourceSpans {
    #[prost(message, optional, tag = "1")]
    pub resource: Option<Resource>,
    #[prost(message, repeated, tag = "2")]
    pub scope_spans: Vec<ScopeSpans>,
    #[prost(string, tag = "3")]
    pub schema_url: String,
}

/// `trace.v1.ScopeSpans`.
#[derive(Clone, PartialEq, Message)]
pub struct ScopeSpans {
    #[prost(message, optional, tag = "1")]
    pub scope: Option<InstrumentationScope>,
    #[prost(message, repeated, tag = "2")]
    pub spans: Vec<Span>,
    #[prost(string, tag = "3")]
    pub schema_url: String,
}

/// `trace.v1.Span`.
#[derive(Clone, PartialEq, Message)]
pub struct Span {
    #[prost(bytes = "vec", tag = "1")]
    pub trace_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub span_id: Vec<u8>,
    #[prost(string, tag = "3")]
    pub trace_state: String,
    #[prost(bytes = "vec", tag = "4")]
    pub parent_span_id: Vec<u8>,
    #[prost(string, tag = "5")]
    pub name: String,
    #[prost(int32, tag = "6")]
    pub kind: i32,
    #[prost(fixed64, tag = "7")]
    pub start_time_unix_nano: u64,
    #[prost(fixed64, tag = "8")]
    pub end_time_unix_nano: u64,
    #[prost(message, repeated, tag = "9")]
    pub attributes: Vec<KeyValue>,
    #[prost(uint32, tag = "10")]
    pub dropped_attributes_count: u32,
    #[prost(message, optional, tag = "15")]
    pub status: Option<Status>,
}

/// `trace.v1.Status`.
#[derive(Clone, PartialEq, Message)]
pub struct Status {
    #[prost(string, tag = "2")]
    pub message: String,
    #[prost(int32, tag = "3")]
    pub code: i32,
}

/// OTLP `SpanKind::Internal`.
pub const SPAN_KIND_INTERNAL: i32 = 1;
/// OTLP `SpanKind::Server`.
pub const SPAN_KIND_SERVER: i32 = 2;
/// OTLP `SpanKind::Client`.
pub const SPAN_KIND_CLIENT: i32 = 3;

/// OTLP `StatusCode::Unset`.
pub const STATUS_CODE_UNSET: i32 = 0;
/// OTLP `StatusCode::Ok`.
pub const STATUS_CODE_OK: i32 = 1;
/// OTLP `StatusCode::Error`.
pub const STATUS_CODE_ERROR: i32 = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_request_roundtrips() {
        let req = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(Resource {
                    attributes: vec![key_value("service.name", "oraclemcp")],
                }),
                scope_metrics: vec![ScopeMetrics {
                    scope: Some(InstrumentationScope {
                        name: "oraclemcp.telemetry".to_owned(),
                        version: "0.3.0".to_owned(),
                    }),
                    metrics: vec![Metric {
                        name: "mcp.requests".to_owned(),
                        description: String::new(),
                        unit: "1".to_owned(),
                        data: Some(metric::Data::Sum(Sum {
                            aggregation_temporality: AGGREGATION_TEMPORALITY_CUMULATIVE,
                            is_monotonic: true,
                            data_points: vec![NumberDataPoint {
                                attributes: vec![key_value("tool", "oracle_query")],
                                start_time_unix_nano: 1,
                                time_unix_nano: 2,
                                value: Some(number_data_point::Value::AsInt(7)),
                            }],
                        })),
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };
        let bytes = req.to_bytes();
        assert!(!bytes.is_empty());
        let decoded = ExportMetricsServiceRequest::decode(bytes.as_slice()).expect("decodes");
        assert_eq!(decoded, req, "metrics request roundtrips through prost");
    }

    #[test]
    fn trace_request_roundtrips() {
        let req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![key_value("service.name", "oraclemcp")],
                }),
                scope_spans: vec![ScopeSpans {
                    scope: Some(InstrumentationScope {
                        name: "oraclemcp.telemetry".to_owned(),
                        version: "0.3.0".to_owned(),
                    }),
                    spans: vec![Span {
                        trace_id: vec![1u8; 16],
                        span_id: vec![2u8; 8],
                        trace_state: String::new(),
                        parent_span_id: Vec::new(),
                        name: "request".to_owned(),
                        kind: SPAN_KIND_SERVER,
                        start_time_unix_nano: 100,
                        end_time_unix_nano: 200,
                        attributes: vec![key_value("tool", "oracle_query")],
                        dropped_attributes_count: 0,
                        status: Some(Status {
                            message: String::new(),
                            code: STATUS_CODE_OK,
                        }),
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };
        let bytes = req.to_bytes();
        let decoded = ExportTraceServiceRequest::decode(bytes.as_slice()).expect("decodes");
        assert_eq!(decoded, req, "trace request roundtrips through prost");
        // 16-byte trace id / 8-byte span id preserved on the wire.
        assert_eq!(
            decoded.resource_spans[0].scope_spans[0].spans[0]
                .trace_id
                .len(),
            16
        );
        assert_eq!(
            decoded.resource_spans[0].scope_spans[0].spans[0]
                .span_id
                .len(),
            8
        );
    }
}
