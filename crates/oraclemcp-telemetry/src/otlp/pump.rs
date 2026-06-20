//! Background OTLP export pump (D1; bead `.3` backpressure requirement).
//!
//! The exporter batch/flush loop is **region-owned with a bounded shutdown
//! budget** — NOT a detached spawn. Telemetry failure DROPS, never blocks the
//! request path:
//!
//! - The request path (and the `tracing` trace layer) only ever `submit(...)`
//!   into a bounded, lock-free-ish queue. When the queue is full, the newest
//!   item is dropped (load shedding) — `submit` is non-blocking and infallible.
//! - A dedicated OS thread owns a single-purpose asupersync current-thread
//!   runtime. Inside that runtime, a region drains the queues on an interval and
//!   exports each batch via the Tokio-free asupersync exporter, honoring the Cx.
//! - On [`PumpHandle::shutdown`], the pump drains what it can within a bounded
//!   time budget, then the thread joins. An export error during drain is logged
//!   and dropped — shutdown never wedges on an unreachable collector.
//!
//! This keeps the engine-free core's request path free of any async-runtime or
//! network work for telemetry: the only thing on the hot path is a queue push.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bounded::BoundedQueue;

use crate::metrics::MetricsSnapshot;

use super::config::OtlpConfig;
use super::logs::{self, LogRecordInput};
use super::metrics as otlp_metrics;
use super::redact::Redactor;
use super::traces::{self, FinishedSpan, SpanSink};

/// Bounded queue capacities. Generous enough for bursts, small enough to bound
/// memory; overflow drops the newest item (telemetry is best-effort).
const LOGS_QUEUE_CAP: usize = 4096;
const SPANS_QUEUE_CAP: usize = 8192;

/// How often the pump wakes to drain queues + emit a metrics snapshot.
const DRAIN_INTERVAL: Duration = Duration::from_millis(500);

/// Bounded budget for the shutdown drain.
const SHUTDOWN_DRAIN_BUDGET: Duration = Duration::from_secs(3);

/// A minimal bounded MPSC-ish queue: a `Mutex<VecDeque>` with newest-drop on
/// overflow. Kept local (no extra dep) — the contention is trivial (a push per
/// log/span, a drain every 500ms).
mod bounded {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Bounded queue with newest-drop load shedding.
    #[derive(Debug)]
    pub struct BoundedQueue<T> {
        inner: Mutex<VecDeque<T>>,
        cap: usize,
        dropped: AtomicU64,
    }

    impl<T> BoundedQueue<T> {
        pub fn new(cap: usize) -> Self {
            Self {
                inner: Mutex::new(VecDeque::with_capacity(cap.min(1024))),
                cap,
                dropped: AtomicU64::new(0),
            }
        }

        /// Push, dropping the new item if at capacity. Non-blocking, infallible.
        pub fn push(&self, item: T) {
            let mut q = match self.inner.lock() {
                Ok(q) => q,
                Err(poisoned) => poisoned.into_inner(),
            };
            if q.len() >= self.cap {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            q.push_back(item);
        }

        /// Drain up to `max` items.
        pub fn drain(&self, max: usize) -> Vec<T> {
            let mut q = match self.inner.lock() {
                Ok(q) => q,
                Err(poisoned) => poisoned.into_inner(),
            };
            let n = q.len().min(max);
            q.drain(..n).collect()
        }

        pub fn dropped_count(&self) -> u64 {
            self.dropped.load(Ordering::Relaxed)
        }
    }
}

/// A snapshot provider the pump polls each interval for the live metrics.
pub type MetricsProvider = Arc<dyn Fn() -> MetricsSnapshot + Send + Sync>;

/// Shared queues + config the pump thread drains.
struct Shared {
    config: OtlpConfig,
    redactor: Redactor,
    logs: BoundedQueue<LogRecordInput>,
    spans: BoundedQueue<FinishedSpan>,
    metrics_provider: Mutex<Option<MetricsProvider>>,
    metrics_seq: AtomicU64,
    shutting_down: AtomicBool,
    start_unix_nano: u64,
}

/// Handle to a running export pump. Cloneable (shares the queues).
#[derive(Clone)]
pub struct PumpHandle {
    shared: Arc<Shared>,
}

impl PumpHandle {
    /// Submit a log record for export (non-blocking; drops on overflow).
    pub fn submit_log(&self, record: LogRecordInput) {
        if self.shared.shutting_down.load(Ordering::Relaxed) {
            return;
        }
        self.shared.logs.push(record);
    }

    /// Register the provider the pump polls each interval for live metrics.
    pub fn set_metrics_provider(&self, provider: MetricsProvider) {
        if let Ok(mut slot) = self.shared.metrics_provider.lock() {
            *slot = Some(provider);
        }
    }

    /// Begin shutdown: stop accepting new submissions. The owning [`ExportPump`]
    /// performs the bounded drain + join when dropped.
    pub fn begin_shutdown(&self) {
        self.shared.shutting_down.store(true, Ordering::Relaxed);
    }

    /// Count of telemetry items dropped due to queue overflow (logs + spans).
    #[must_use]
    pub fn dropped_count(&self) -> u64 {
        self.shared.logs.dropped_count() + self.shared.spans.dropped_count()
    }
}

impl SpanSink for PumpHandle {
    fn submit(&self, span: FinishedSpan) {
        if self.shared.shutting_down.load(Ordering::Relaxed) {
            return;
        }
        self.shared.spans.push(span);
    }
}

/// The owning pump: holds the worker thread. Dropping it performs the bounded
/// shutdown drain and joins the thread (RAII region ownership — no leak, no
/// detached spawn).
pub struct ExportPump {
    handle: PumpHandle,
    worker: Option<JoinHandle<()>>,
}

impl ExportPump {
    /// Start the pump for `config`. Returns the pump (owns the thread) — keep it
    /// alive for the server's lifetime, then drop it (or call [`Self::shutdown`])
    /// to flush + join.
    #[must_use]
    pub fn start(config: OtlpConfig) -> Self {
        let start_unix_nano = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let shared = Arc::new(Shared {
            config,
            redactor: Redactor::new(),
            logs: BoundedQueue::new(LOGS_QUEUE_CAP),
            spans: BoundedQueue::new(SPANS_QUEUE_CAP),
            metrics_provider: Mutex::new(None),
            metrics_seq: AtomicU64::new(0),
            shutting_down: AtomicBool::new(false),
            start_unix_nano,
        });
        let worker_shared = Arc::clone(&shared);
        let worker = std::thread::Builder::new()
            .name("oraclemcp-otlp-pump".to_owned())
            .spawn(move || run_pump(&worker_shared))
            .ok();
        Self {
            handle: PumpHandle { shared },
            worker,
        }
    }

    /// A cloneable handle for submitting telemetry.
    #[must_use]
    pub fn handle(&self) -> PumpHandle {
        self.handle.clone()
    }

    /// Begin shutdown, drain within the bounded budget, and join the worker.
    /// Idempotent; also performed on `Drop`.
    pub fn shutdown(&mut self) {
        self.handle.begin_shutdown();
        if let Some(worker) = self.worker.take() {
            // The worker observes `shutting_down`, does a final bounded drain,
            // and returns. Join is bounded by the worker's own budget.
            let _ = worker.join();
        }
    }
}

impl Drop for ExportPump {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The pump body: builds a current-thread asupersync runtime, opens a region,
/// and drains the queues on an interval until shutdown, then does a final
/// bounded drain. All export work is Cx-aware and inside the region.
fn run_pump(shared: &Arc<Shared>) {
    use asupersync::runtime::RuntimeBuilder;

    let Ok(runtime) = RuntimeBuilder::current_thread().build() else {
        tracing::warn!("oraclemcp-otlp: could not build export runtime; telemetry export disabled");
        return;
    };

    runtime.block_on(async {
        let cx = asupersync::Cx::current()
            .expect("asupersync block_on installs a Cx for the pump region");
        let deadline = loop {
            // Drain steady-state batches.
            drain_once(&cx, shared).await;

            if shared.shutting_down.load(Ordering::Relaxed) {
                break Instant::now() + SHUTDOWN_DRAIN_BUDGET;
            }
            asupersync::time::sleep(cx.now(), DRAIN_INTERVAL).await;
        };

        // Bounded shutdown drain: flush remaining queued telemetry until the
        // queues are empty or the budget expires. Errors are dropped.
        while Instant::now() < deadline {
            let drained = drain_once(&cx, shared).await;
            if drained == 0 {
                break;
            }
        }
    });
}

/// Drain one pass of logs + spans + a metrics snapshot. Returns the number of
/// telemetry items exported (logs records + spans) this pass.
async fn drain_once(cx: &asupersync::Cx, shared: &Arc<Shared>) -> usize {
    let mut exported = 0usize;

    // ---- logs ----
    let log_records = shared.logs.drain(LOGS_QUEUE_CAP);
    if !log_records.is_empty() {
        exported += log_records.len();
        let snapshot = logs::build_snapshot(&shared.config, &shared.redactor, &log_records);
        if let Err(e) = logs::export_snapshot(cx, &shared.config, &snapshot).await {
            tracing::debug!(error = %e, "oraclemcp-otlp: logs export dropped");
        }
    }

    // ---- spans ----
    let spans = shared.spans.drain(SPANS_QUEUE_CAP);
    if !spans.is_empty() {
        exported += spans.len();
        let request = traces::build_request(&shared.config, &spans);
        if let Err(e) = traces::export_request(cx, &shared.config, &request).await {
            tracing::debug!(error = %e, "oraclemcp-otlp: trace export dropped");
        }
    }

    // ---- metrics (poll the live snapshot; batch-level sampling) ----
    let provider = shared
        .metrics_provider
        .lock()
        .ok()
        .and_then(|slot| slot.clone());
    if let Some(provider) = provider {
        let seq = shared.metrics_seq.fetch_add(1, Ordering::Relaxed);
        if otlp_metrics::should_export_batch(shared.config.metrics_sample_ratio, seq) {
            let snapshot = provider();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            let request = otlp_metrics::build_request(
                &shared.config,
                &shared.redactor,
                &snapshot,
                shared.start_unix_nano,
                now,
            );
            if let Err(e) = otlp_metrics::export_request(cx, &shared.config, &request).await {
                tracing::debug!(error = %e, "oraclemcp-otlp: metrics export dropped");
            }
        }
    }

    exported
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> OtlpConfig {
        // Point at a black-hole endpoint: exports will fail fast and be dropped,
        // which is exactly the "telemetry failure never blocks" behaviour we
        // assert. No live collector is required.
        OtlpConfig::from_lookup(|k| {
            (k == "OTEL_EXPORTER_OTLP_ENDPOINT").then(|| "http://127.0.0.1:9/".to_owned())
        })
        .map(|mut c| {
            c.timeout = Duration::from_millis(50);
            c
        })
        .expect("on")
    }

    #[test]
    fn submit_is_non_blocking_and_shutdown_is_bounded() {
        let mut pump = ExportPump::start(cfg());
        let handle = pump.handle();
        // Submit a burst of logs + spans; never blocks even with no collector.
        for i in 0..100 {
            handle.submit_log(LogRecordInput::new(
                asupersync::observability::LogLevel::Info,
                format!("event {i}"),
                i,
            ));
            handle.submit(FinishedSpan {
                trace_id: [1u8; 16],
                span_id: [2u8; 8],
                parent_span_id: [0u8; 8],
                name: "request".to_owned(),
                kind: super::super::proto::SPAN_KIND_SERVER,
                start_time_unix_nano: i,
                end_time_unix_nano: i + 1,
                attributes: vec![("tool".to_owned(), "oracle_query".to_owned())],
                status_code: super::super::proto::STATUS_CODE_OK,
                trace_state: String::new(),
            });
        }
        // Bounded shutdown: must return quickly (well under the test timeout)
        // even though the collector is unreachable.
        let start = Instant::now();
        pump.shutdown();
        assert!(
            start.elapsed() < SHUTDOWN_DRAIN_BUDGET + Duration::from_secs(2),
            "shutdown drain is bounded"
        );
    }

    #[test]
    fn overflow_drops_newest_and_counts() {
        let q: BoundedQueue<u32> = BoundedQueue::new(2);
        q.push(1);
        q.push(2);
        q.push(3); // dropped
        assert_eq!(q.dropped_count(), 1);
        assert_eq!(q.drain(10), vec![1, 2]);
    }
}
