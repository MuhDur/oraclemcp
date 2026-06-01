//! Metrics instruments (plan §10; bead P2-6). The instrument set §10 lists —
//! `mcp.requests.total{tool,status}`, `db.query.duration_ms`,
//! `db.pool.active_connections`, `db.pool.wait_ms`, `db.errors.total{ora_code}`
//! — recorded in-process with atomics, exposed as a serializable snapshot and
//! a Prometheus exposition. An OTLP/OpenTelemetry exporter maps the same
//! snapshot at deploy time; traces flow via the `tracing` layer (P1-8).

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

/// A minimal count+sum+max histogram (enough for averages and a max).
#[derive(Debug, Default)]
struct Histogram {
    count: AtomicU64,
    sum: AtomicU64,
    max: AtomicU64,
}

impl Histogram {
    fn observe(&self, value: u64) {
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(value, Ordering::Relaxed);
        self.max.fetch_max(value, Ordering::Relaxed);
    }

    fn snapshot(&self) -> HistogramSnapshot {
        let count = self.count.load(Ordering::Relaxed);
        let sum = self.sum.load(Ordering::Relaxed);
        HistogramSnapshot {
            count,
            sum,
            max: self.max.load(Ordering::Relaxed),
            mean: if count == 0 {
                0.0
            } else {
                sum as f64 / count as f64
            },
        }
    }
}

/// A serializable histogram snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct HistogramSnapshot {
    /// Number of observations.
    pub count: u64,
    /// Sum of observed values.
    pub sum: u64,
    /// Maximum observed value.
    pub max: u64,
    /// Mean (0 if no observations).
    pub mean: f64,
}

/// The server's metrics registry.
#[derive(Debug, Default)]
pub struct Metrics {
    requests: Mutex<BTreeMap<(String, String), u64>>, // (tool, status) -> count
    errors: Mutex<BTreeMap<i32, u64>>,                // ora_code -> count
    query_duration_ms: Histogram,
    pool_wait_ms: Histogram,
    pool_active: AtomicU64,
}

impl Metrics {
    /// A new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an MCP request outcome (`status` = `ok` / `error` / `busy` / …).
    pub fn record_request(&self, tool: &str, status: &str) {
        *self
            .requests
            .lock()
            .expect("metrics mutex poisoned")
            .entry((tool.to_owned(), status.to_owned()))
            .or_insert(0) += 1;
    }

    /// Record a DB query duration (ms).
    pub fn record_query_duration_ms(&self, ms: u64) {
        self.query_duration_ms.observe(ms);
    }

    /// Record a pool-acquire wait (ms).
    pub fn record_pool_wait_ms(&self, ms: u64) {
        self.pool_wait_ms.observe(ms);
    }

    /// Set the current active pooled-connection gauge.
    pub fn set_pool_active(&self, n: u64) {
        self.pool_active.store(n, Ordering::Relaxed);
    }

    /// Record a DB error by `ORA-` code.
    pub fn record_error(&self, ora_code: i32) {
        *self
            .errors
            .lock()
            .expect("metrics mutex poisoned")
            .entry(ora_code)
            .or_insert(0) += 1;
    }

    /// A serializable snapshot (OTLP/JSON export source).
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            requests: self
                .requests
                .lock()
                .expect("poisoned")
                .iter()
                .map(|((tool, status), c)| RequestCount {
                    tool: tool.clone(),
                    status: status.clone(),
                    count: *c,
                })
                .collect(),
            errors: self
                .errors
                .lock()
                .expect("poisoned")
                .iter()
                .map(|(code, c)| ErrorCount {
                    ora_code: *code,
                    count: *c,
                })
                .collect(),
            query_duration_ms: self.query_duration_ms.snapshot(),
            pool_wait_ms: self.pool_wait_ms.snapshot(),
            pool_active_connections: self.pool_active.load(Ordering::Relaxed),
        }
    }

    /// Prometheus text exposition of the current metrics.
    #[must_use]
    pub fn prometheus_text(&self) -> String {
        let s = self.snapshot();
        let mut out = String::new();
        out.push_str("# TYPE mcp_requests_total counter\n");
        for r in &s.requests {
            out.push_str(&format!(
                "mcp_requests_total{{tool=\"{}\",status=\"{}\"}} {}\n",
                r.tool, r.status, r.count
            ));
        }
        out.push_str("# TYPE db_errors_total counter\n");
        for e in &s.errors {
            out.push_str(&format!(
                "db_errors_total{{ora_code=\"{}\"}} {}\n",
                e.ora_code, e.count
            ));
        }
        out.push_str("# TYPE db_query_duration_ms summary\n");
        out.push_str(&format!(
            "db_query_duration_ms_count {}\n",
            s.query_duration_ms.count
        ));
        out.push_str(&format!(
            "db_query_duration_ms_sum {}\n",
            s.query_duration_ms.sum
        ));
        out.push_str("# TYPE db_pool_active_connections gauge\n");
        out.push_str(&format!(
            "db_pool_active_connections {}\n",
            s.pool_active_connections
        ));
        out
    }
}

/// A labeled request count.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestCount {
    /// Tool name.
    pub tool: String,
    /// Status label.
    pub status: String,
    /// Count.
    pub count: u64,
}

/// A labeled error count.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorCount {
    /// The `ORA-` code.
    pub ora_code: i32,
    /// Count.
    pub count: u64,
}

/// A serializable metrics snapshot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// Per-(tool,status) request counts.
    pub requests: Vec<RequestCount>,
    /// Per-ORA-code error counts.
    pub errors: Vec<ErrorCount>,
    /// Query-duration histogram.
    pub query_duration_ms: HistogramSnapshot,
    /// Pool-acquire-wait histogram.
    pub pool_wait_ms: HistogramSnapshot,
    /// Active pooled connections.
    pub pool_active_connections: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_snapshots_requests_and_errors() {
        let m = Metrics::new();
        m.record_request("oracle_query", "ok");
        m.record_request("oracle_query", "ok");
        m.record_request("oracle_query", "error");
        m.record_error(942);
        m.record_error(942);
        m.record_error(1031);
        let s = m.snapshot();
        let ok = s.requests.iter().find(|r| r.status == "ok").unwrap();
        assert_eq!(ok.count, 2);
        assert_eq!(
            s.errors.iter().find(|e| e.ora_code == 942).unwrap().count,
            2
        );
    }

    #[test]
    fn histogram_tracks_count_sum_max_mean() {
        let m = Metrics::new();
        for ms in [10u64, 20, 60] {
            m.record_query_duration_ms(ms);
        }
        let h = m.snapshot().query_duration_ms;
        assert_eq!(h.count, 3);
        assert_eq!(h.sum, 90);
        assert_eq!(h.max, 60);
        assert!((h.mean - 30.0).abs() < 1e-9);
    }

    #[test]
    fn pool_gauge_is_last_write() {
        let m = Metrics::new();
        m.set_pool_active(5);
        m.set_pool_active(3);
        assert_eq!(m.snapshot().pool_active_connections, 3);
    }

    #[test]
    fn prometheus_text_exposes_instruments() {
        let m = Metrics::new();
        m.record_request("oracle_query", "ok");
        m.record_error(942);
        m.set_pool_active(2);
        let text = m.prometheus_text();
        assert!(text.contains("mcp_requests_total{tool=\"oracle_query\",status=\"ok\"} 1"));
        assert!(text.contains("db_errors_total{ora_code=\"942\"} 1"));
        assert!(text.contains("db_pool_active_connections 2"));
    }

    #[test]
    fn snapshot_roundtrips() {
        let m = Metrics::new();
        m.record_request("t", "ok");
        let s = m.snapshot();
        let json = serde_json::to_string(&s).unwrap();
        let back: MetricsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}
