//! Metrics instruments (plan §10; bead P2-6). The instrument set §10 lists —
//! `mcp.requests.total{tool,status}`, lane-scoped request counters and
//! histograms, `db.query.duration_ms`, `db.pool.active_connections`,
//! `db.pool.wait_ms`, `db.errors.total{ora_code}` — recorded in-process with
//! atomics, exposed as a serializable snapshot and a Prometheus exposition. An
//! OTLP/OpenTelemetry exporter maps the same snapshot at deploy time; traces
//! flow via the `tracing` layer (P1-8).

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

/// Hard ceiling on the number of distinct label combinations any single
/// metric instrument tracks. Set comfortably above the server's entire
/// legitimate tool/status/reason-class surface (a few dozen combinations at
/// most — see `oraclemcp::registry::TOOL_NAMES` plus the bounded operator
/// custom-tool budget), so ordinary traffic never collides with it, while
/// staying finite: a caller that feeds an unvalidated label per request (for
/// example the MCP `tools/call` name, which reaches metrics before any
/// tool-registry check) cannot grow a metric map without bound.
const MAX_SERIES_PER_INSTRUMENT: usize = 512;

/// Substituted for every label of a metric key once its instrument has
/// reached [`MAX_SERIES_PER_INSTRUMENT`] distinct combinations, so continued
/// attacker-driven cardinality growth collapses into one visible, bounded
/// bucket instead of either growing the process's memory unboundedly or being
/// silently dropped.
const CARDINALITY_OVERFLOW_LABEL: &str = "__cardinality_limit__";

/// Return `key` unless recording it under `map` would create a new series
/// beyond [`MAX_SERIES_PER_INSTRUMENT`] distinct existing combinations, in
/// which case return the bounded overflow key from `overflow` instead. An
/// already-tracked key is always preserved verbatim (that's not new growth).
/// Must be called while holding `map`'s lock so the size check is atomic with
/// the subsequent insert.
fn bounded_key<K: Ord, V>(map: &BTreeMap<K, V>, key: K, overflow: impl FnOnce() -> K) -> K {
    if map.contains_key(&key) || map.len() < MAX_SERIES_PER_INSTRUMENT {
        key
    } else {
        overflow()
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
    lane_requests: Mutex<BTreeMap<LaneRequestKey, u64>>,
    lane_blocked: Mutex<BTreeMap<LaneBlockedKey, u64>>,
    lane_request_duration_ms: Mutex<BTreeMap<LaneRequestDurationKey, Histogram>>,
    active_lane_labels: Mutex<BTreeMap<LaneSubjectKey, u64>>,
    query_duration_ms: Histogram,
    pool_wait_ms: Histogram,
    pool_active: AtomicU64,
    active_lanes: AtomicU64,
}

impl Metrics {
    /// A new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an MCP request outcome (`status` = `ok` / `error` / `busy` / …).
    ///
    /// `tool` reaches this call before any tool-registry validation (an MCP
    /// `tools/call` name is caller-supplied), so it is not itself a bounded
    /// label; cardinality is capped here rather than trusted upstream.
    pub fn record_request(&self, tool: &str, status: &str) {
        let mut requests = self.requests.lock().expect("metrics mutex poisoned");
        let key = bounded_key(&requests, (tool.to_owned(), status.to_owned()), || {
            (
                CARDINALITY_OVERFLOW_LABEL.to_owned(),
                CARDINALITY_OVERFLOW_LABEL.to_owned(),
            )
        });
        *requests.entry(key).or_insert(0) += 1;
    }

    /// Record an MCP request outcome scoped to the server-derived lane and
    /// redacted subject hash.
    pub fn record_lane_request(
        &self,
        lane_id: &str,
        subject_id_hash: &str,
        tool: &str,
        status: &str,
    ) {
        self.record_request(tool, status);
        let mut lane_requests = self.lane_requests.lock().expect("metrics mutex poisoned");
        let key = bounded_key(
            &lane_requests,
            LaneRequestKey::new(lane_id, subject_id_hash, tool, status),
            LaneRequestKey::overflow,
        );
        *lane_requests.entry(key).or_insert(0) += 1;
    }

    /// Record a per-lane MCP request latency (ms).
    pub fn record_lane_request_duration_ms(
        &self,
        lane_id: &str,
        subject_id_hash: &str,
        tool: &str,
        ms: u64,
    ) {
        let mut histograms = self
            .lane_request_duration_ms
            .lock()
            .expect("metrics mutex poisoned");
        let key = bounded_key(
            &histograms,
            LaneRequestDurationKey::new(lane_id, subject_id_hash, tool),
            LaneRequestDurationKey::overflow,
        );
        histograms.entry(key).or_default().observe(ms);
    }

    /// Record a request that was blocked before useful DB work could happen,
    /// labeled (K4) with *why* — `reason_class` (`capacity` / `policy` /
    /// `classifier` / `operating_level` / `other`) — and the operating level the
    /// statement required (`READ_ONLY` / `READ_WRITE` / `DDL` / `ADMIN` / `n/a`).
    /// Both labels are drawn from bounded sets so cardinality stays fixed: a
    /// broken meter can never weaken the guard, and operators see what agents
    /// *attempt*, not just what runs.
    pub fn record_lane_blocked(
        &self,
        lane_id: &str,
        subject_id_hash: &str,
        reason_class: &str,
        operating_level: &str,
    ) {
        let mut lane_blocked = self.lane_blocked.lock().expect("metrics mutex poisoned");
        let key = bounded_key(
            &lane_blocked,
            LaneBlockedKey::new(lane_id, subject_id_hash, reason_class, operating_level),
            LaneBlockedKey::overflow,
        );
        *lane_blocked.entry(key).or_insert(0) += 1;
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

    /// Set the current active-lane gauge. Labels must already be redacted:
    /// `subject_id_hash`, never a raw principal key.
    pub fn set_active_lanes(&self, lanes: &[(String, String)]) {
        self.active_lanes.store(
            u64::try_from(lanes.len()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        let mut labels = self
            .active_lane_labels
            .lock()
            .expect("metrics mutex poisoned");
        labels.clear();
        for (lane_id, subject_id_hash) in lanes {
            labels.insert(LaneSubjectKey::new(lane_id, subject_id_hash), 1);
        }
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
            lane_requests: self
                .lane_requests
                .lock()
                .expect("poisoned")
                .iter()
                .map(|(key, c)| LaneRequestCount {
                    lane_id: key.lane_id.clone(),
                    subject_id_hash: key.subject_id_hash.clone(),
                    tool: key.tool.clone(),
                    status: key.status.clone(),
                    count: *c,
                })
                .collect(),
            lane_blocked: self
                .lane_blocked
                .lock()
                .expect("poisoned")
                .iter()
                .map(|(key, c)| LaneBlockedCount {
                    lane_id: key.lane_id.clone(),
                    subject_id_hash: key.subject_id_hash.clone(),
                    reason_class: key.reason_class.clone(),
                    operating_level: key.operating_level.clone(),
                    count: *c,
                })
                .collect(),
            lane_request_duration_ms: self
                .lane_request_duration_ms
                .lock()
                .expect("poisoned")
                .iter()
                .map(|(key, histogram)| LaneRequestDuration {
                    lane_id: key.lane_id.clone(),
                    subject_id_hash: key.subject_id_hash.clone(),
                    tool: key.tool.clone(),
                    histogram: histogram.snapshot(),
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
            active_lanes: self.active_lanes.load(Ordering::Relaxed),
            active_lane_gauges: self
                .active_lane_labels
                .lock()
                .expect("poisoned")
                .iter()
                .map(|(key, active)| ActiveLaneGauge {
                    lane_id: key.lane_id.clone(),
                    subject_id_hash: key.subject_id_hash.clone(),
                    active: *active,
                })
                .collect(),
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
                escape_label(&r.tool),
                escape_label(&r.status),
                r.count
            ));
        }
        out.push_str("# TYPE mcp_lane_requests_total counter\n");
        for r in &s.lane_requests {
            out.push_str(&format!(
                "mcp_lane_requests_total{{lane_id=\"{}\",subject_id_hash=\"{}\",tool=\"{}\",status=\"{}\"}} {}\n",
                escape_label(&r.lane_id),
                escape_label(&r.subject_id_hash),
                escape_label(&r.tool),
                escape_label(&r.status),
                r.count
            ));
        }
        out.push_str("# TYPE mcp_lane_blocked_total counter\n");
        for r in &s.lane_blocked {
            out.push_str(&format!(
                "mcp_lane_blocked_total{{lane_id=\"{}\",subject_id_hash=\"{}\",reason_class=\"{}\",operating_level=\"{}\"}} {}\n",
                escape_label(&r.lane_id),
                escape_label(&r.subject_id_hash),
                escape_label(&r.reason_class),
                escape_label(&r.operating_level),
                r.count
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
        out.push_str("# TYPE mcp_lane_request_duration_ms summary\n");
        for r in &s.lane_request_duration_ms {
            out.push_str(&format!(
                "mcp_lane_request_duration_ms_count{{lane_id=\"{}\",subject_id_hash=\"{}\",tool=\"{}\"}} {}\n",
                escape_label(&r.lane_id),
                escape_label(&r.subject_id_hash),
                escape_label(&r.tool),
                r.histogram.count
            ));
            out.push_str(&format!(
                "mcp_lane_request_duration_ms_sum{{lane_id=\"{}\",subject_id_hash=\"{}\",tool=\"{}\"}} {}\n",
                escape_label(&r.lane_id),
                escape_label(&r.subject_id_hash),
                escape_label(&r.tool),
                r.histogram.sum
            ));
        }
        out.push_str("# TYPE db_pool_active_connections gauge\n");
        out.push_str(&format!(
            "db_pool_active_connections {}\n",
            s.pool_active_connections
        ));
        out.push_str("# TYPE mcp_active_lanes gauge\n");
        out.push_str(&format!("mcp_active_lanes {}\n", s.active_lanes));
        for lane in &s.active_lane_gauges {
            out.push_str(&format!(
                "mcp_active_lane{{lane_id=\"{}\",subject_id_hash=\"{}\"}} {}\n",
                escape_label(&lane.lane_id),
                escape_label(&lane.subject_id_hash),
                lane.active
            ));
        }
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct LaneSubjectKey {
    lane_id: String,
    subject_id_hash: String,
}

impl LaneSubjectKey {
    fn new(lane_id: &str, subject_id_hash: &str) -> Self {
        Self {
            lane_id: lane_id.to_owned(),
            subject_id_hash: subject_id_hash.to_owned(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct LaneBlockedKey {
    lane_id: String,
    subject_id_hash: String,
    reason_class: String,
    operating_level: String,
}

impl LaneBlockedKey {
    fn new(
        lane_id: &str,
        subject_id_hash: &str,
        reason_class: &str,
        operating_level: &str,
    ) -> Self {
        Self {
            lane_id: lane_id.to_owned(),
            subject_id_hash: subject_id_hash.to_owned(),
            reason_class: reason_class.to_owned(),
            operating_level: operating_level.to_owned(),
        }
    }

    fn overflow() -> Self {
        Self::new(
            CARDINALITY_OVERFLOW_LABEL,
            CARDINALITY_OVERFLOW_LABEL,
            CARDINALITY_OVERFLOW_LABEL,
            CARDINALITY_OVERFLOW_LABEL,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct LaneRequestKey {
    lane_id: String,
    subject_id_hash: String,
    tool: String,
    status: String,
}

impl LaneRequestKey {
    fn new(lane_id: &str, subject_id_hash: &str, tool: &str, status: &str) -> Self {
        Self {
            lane_id: lane_id.to_owned(),
            subject_id_hash: subject_id_hash.to_owned(),
            tool: tool.to_owned(),
            status: status.to_owned(),
        }
    }

    fn overflow() -> Self {
        Self::new(
            CARDINALITY_OVERFLOW_LABEL,
            CARDINALITY_OVERFLOW_LABEL,
            CARDINALITY_OVERFLOW_LABEL,
            CARDINALITY_OVERFLOW_LABEL,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct LaneRequestDurationKey {
    lane_id: String,
    subject_id_hash: String,
    tool: String,
}

impl LaneRequestDurationKey {
    fn new(lane_id: &str, subject_id_hash: &str, tool: &str) -> Self {
        Self {
            lane_id: lane_id.to_owned(),
            subject_id_hash: subject_id_hash.to_owned(),
            tool: tool.to_owned(),
        }
    }

    fn overflow() -> Self {
        Self::new(
            CARDINALITY_OVERFLOW_LABEL,
            CARDINALITY_OVERFLOW_LABEL,
            CARDINALITY_OVERFLOW_LABEL,
        )
    }
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
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

/// A per-lane/per-subject request counter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneRequestCount {
    /// Stable lane id.
    pub lane_id: String,
    /// Redacted subject id hash.
    pub subject_id_hash: String,
    /// Tool name.
    pub tool: String,
    /// Status label.
    pub status: String,
    /// Count.
    pub count: u64,
}

/// A per-lane/per-subject blocked counter, labeled by the bounded reason class
/// and required operating level (K4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneBlockedCount {
    /// Stable lane id.
    pub lane_id: String,
    /// Redacted subject id hash.
    pub subject_id_hash: String,
    /// Bounded reason class: `capacity` / `policy` / `classifier` /
    /// `operating_level` / `other`. Defaults empty for legacy snapshots.
    #[serde(default)]
    pub reason_class: String,
    /// Bounded required operating level: `READ_ONLY` / `READ_WRITE` / `DDL` /
    /// `ADMIN` / `n/a`. Defaults empty for legacy snapshots.
    #[serde(default)]
    pub operating_level: String,
    /// Count.
    pub count: u64,
}

/// A per-lane/per-subject/tool request latency histogram.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LaneRequestDuration {
    /// Stable lane id.
    pub lane_id: String,
    /// Redacted subject id hash.
    pub subject_id_hash: String,
    /// Tool name.
    pub tool: String,
    /// Histogram snapshot.
    pub histogram: HistogramSnapshot,
}

/// A per-lane active gauge label.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveLaneGauge {
    /// Stable lane id.
    pub lane_id: String,
    /// Redacted subject id hash.
    pub subject_id_hash: String,
    /// `1` when active in the current snapshot.
    pub active: u64,
}

/// A serializable metrics snapshot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// Per-(tool,status) request counts.
    pub requests: Vec<RequestCount>,
    /// Per-lane/per-subject request counts.
    #[serde(default)]
    pub lane_requests: Vec<LaneRequestCount>,
    /// Per-lane/per-subject blocked counts.
    #[serde(default)]
    pub lane_blocked: Vec<LaneBlockedCount>,
    /// Per-lane/per-subject/tool request latency histograms.
    #[serde(default)]
    pub lane_request_duration_ms: Vec<LaneRequestDuration>,
    /// Per-ORA-code error counts.
    pub errors: Vec<ErrorCount>,
    /// Query-duration histogram.
    pub query_duration_ms: HistogramSnapshot,
    /// Pool-acquire-wait histogram.
    pub pool_wait_ms: HistogramSnapshot,
    /// Active pooled connections.
    pub pool_active_connections: u64,
    /// Current active stateful lanes.
    #[serde(default)]
    pub active_lanes: u64,
    /// Active stateful lanes by lane and redacted subject hash.
    #[serde(default)]
    pub active_lane_gauges: Vec<ActiveLaneGauge>,
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
        m.record_lane_request("lane-a", "subject-sha256:abc", "oracle_query", "ok");
        m.record_lane_request_duration_ms("lane-a", "subject-sha256:abc", "oracle_query", 37);
        m.record_lane_blocked(
            "lane-a",
            "subject-sha256:abc",
            "operating_level",
            "READ_WRITE",
        );
        m.set_active_lanes(&[("lane-a".to_owned(), "subject-sha256:abc".to_owned())]);
        m.record_error(942);
        m.record_error(942);
        m.record_error(1031);
        let s = m.snapshot();
        let ok = s.requests.iter().find(|r| r.status == "ok").unwrap();
        assert_eq!(ok.count, 3);
        let lane_ok = s
            .lane_requests
            .iter()
            .find(|r| r.lane_id == "lane-a" && r.status == "ok")
            .unwrap();
        assert_eq!(lane_ok.subject_id_hash, "subject-sha256:abc");
        assert_eq!(lane_ok.count, 1);
        assert_eq!(s.lane_blocked[0].count, 1);
        assert_eq!(s.lane_blocked[0].reason_class, "operating_level");
        assert_eq!(s.lane_blocked[0].operating_level, "READ_WRITE");
        assert_eq!(s.lane_request_duration_ms[0].histogram.count, 1);
        assert_eq!(s.lane_request_duration_ms[0].histogram.sum, 37);
        assert_eq!(s.active_lanes, 1);
        assert_eq!(s.active_lane_gauges[0].active, 1);
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
        m.record_lane_request("lane-a", "subject-sha256:abc", "oracle_query", "ok");
        m.record_lane_request_duration_ms("lane-a", "subject-sha256:abc", "oracle_query", 12);
        m.record_lane_blocked("lane-a", "subject-sha256:abc", "classifier", "n/a");
        m.set_active_lanes(&[("lane-a".to_owned(), "subject-sha256:abc".to_owned())]);
        m.record_error(942);
        m.set_pool_active(2);
        let text = m.prometheus_text();
        assert!(text.contains("mcp_requests_total{tool=\"oracle_query\",status=\"ok\"} 2"));
        assert!(text.contains("mcp_lane_requests_total{lane_id=\"lane-a\",subject_id_hash=\"subject-sha256:abc\",tool=\"oracle_query\",status=\"ok\"} 1"));
        assert!(
            text.contains(
                "mcp_lane_request_duration_ms_count{lane_id=\"lane-a\",subject_id_hash=\"subject-sha256:abc\",tool=\"oracle_query\"} 1"
            )
        );
        assert!(text.contains(
            "mcp_lane_blocked_total{lane_id=\"lane-a\",subject_id_hash=\"subject-sha256:abc\",reason_class=\"classifier\",operating_level=\"n/a\"} 1"
        ));
        assert!(text.contains("mcp_active_lanes 1"));
        assert!(text.contains("db_errors_total{ora_code=\"942\"} 1"));
        assert!(text.contains("db_pool_active_connections 2"));
    }

    #[test]
    fn tool_label_cardinality_is_bounded_against_attacker_controlled_names() {
        // The MCP `tools/call` name reaches `record_request`/`record_lane_request`
        // before any tool-registry validation, so it is effectively
        // attacker-controlled free text. Without a cap, a request per unique
        // name would grow every label-keyed map without bound (a DoS via
        // unbounded process memory / Prometheus exposition size). Prove that
        // many thousands of distinct inputs still leave every instrument
        // capped at `MAX_SERIES_PER_INSTRUMENT` (+1 for the overflow bucket).
        let m = Metrics::new();
        let attempted = MAX_SERIES_PER_INSTRUMENT * 4;
        for i in 0..attempted {
            let tool = format!("attacker-tool-{i}");
            m.record_lane_request("lane-a", "subject-sha256:abc", &tool, "error");
            m.record_lane_request_duration_ms("lane-a", "subject-sha256:abc", &tool, 1);
            m.record_lane_blocked("lane-a", "subject-sha256:abc", &tool, &tool);
        }
        let s = m.snapshot();
        assert!(
            s.requests.len() <= MAX_SERIES_PER_INSTRUMENT + 1,
            "requests grew to {} distinct series",
            s.requests.len()
        );
        assert!(
            s.lane_requests.len() <= MAX_SERIES_PER_INSTRUMENT + 1,
            "lane_requests grew to {} distinct series",
            s.lane_requests.len()
        );
        assert!(
            s.lane_request_duration_ms.len() <= MAX_SERIES_PER_INSTRUMENT + 1,
            "lane_request_duration_ms grew to {} distinct series",
            s.lane_request_duration_ms.len()
        );
        assert!(
            s.lane_blocked.len() <= MAX_SERIES_PER_INSTRUMENT + 1,
            "lane_blocked grew to {} distinct series",
            s.lane_blocked.len()
        );
        // The overflow bucket itself must have absorbed the excess, not
        // dropped it: total observations across all lane_requests series
        // still equals every attempted call.
        let total: u64 = s.lane_requests.iter().map(|r| r.count).sum();
        assert_eq!(total, attempted as u64);
        assert!(
            s.lane_requests
                .iter()
                .any(|r| r.tool == CARDINALITY_OVERFLOW_LABEL),
            "overflow bucket must be visible once the cap is exceeded"
        );
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
