#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use asupersync::{Cx, Outcome};
use oraclemcp_core::error::{ErrorClass, ErrorEnvelope};
use oraclemcp_core::{
    DispatchContext, DispatchFuture, LaneContext, LaneDispatchFactory, StatefulLaneDispatch,
    ToolDispatch, block_on_lane_bridge,
};
use oraclemcp_db::{OracleConnectOptions, OraclePool, PoolSettings};
use parking_lot::Mutex;
use serde_json::{Value, json};

const DEFAULT_LANES: usize = 16;
const DEFAULT_PROBES_PER_LANE: usize = 4;
const DEFAULT_P99_BUDGET_US: u128 = 1_000_000;
const GLOBAL_CAP_CANDIDATE: usize = 64;
const READ_CAP_CANDIDATE: usize = 16;
const STATEFUL_CAP_CANDIDATE: usize = 8;
const THREADS_PER_LANE_BUDGET: u64 = 2;
const RESERVED_TASKS_FOR_OPERATOR_AND_SERVICE: u64 = 16;
const RESERVED_FDS_FOR_OPERATOR_AND_SERVICE: u64 = 128;

type DispatchFactoryFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Arc<dyn ToolDispatch>, ErrorEnvelope>> + 'a>>;

struct DbProbeDispatch {
    lane_id: String,
    pool: OraclePool,
    latencies_us: Arc<Mutex<Vec<u128>>>,
    lane_threads: Arc<Mutex<BTreeSet<String>>>,
}

impl ToolDispatch for DbProbeDispatch {
    fn dispatch<'a>(
        &'a self,
        cx: &'a Cx,
        _context: DispatchContext<'a>,
        _name: &'a str,
        _args: Value,
    ) -> DispatchFuture<'a> {
        Box::pin(async move {
            let lane_thread = format!("{:?}", std::thread::current().id());
            let started = Instant::now();
            let rows = self
                .pool
                .query_rows(cx, "SELECT 1 AS lane_ok FROM dual", Vec::new())
                .await
                .map_err(|err| db_error(&self.lane_id, "query", err))?;
            let elapsed_us = started.elapsed().as_micros();
            let observed = rows
                .first()
                .and_then(|row| row.parse_i64("LANE_OK"))
                .unwrap_or_default();
            if observed != 1 {
                return Outcome::Err(ErrorEnvelope::new(
                    ErrorClass::RuntimeStateRequired,
                    format!("lane {} returned an unexpected probe value", self.lane_id),
                ));
            }
            self.latencies_us.lock().push(elapsed_us);
            self.lane_threads.lock().insert(lane_thread.clone());
            Outcome::Ok(json!({
                "lane_id": self.lane_id,
                "lane_thread": lane_thread,
                "latency_us": elapsed_us
            }))
        })
    }
}

#[test]
#[ignore = "live-xe: set ORACLEMCP_LIVE_XE=1 and ORACLEMCP_TEST_* to run CX-I6 capacity spike"]
fn phase0_capacity_spike() {
    if std::env::var("ORACLEMCP_LIVE_XE").is_err() {
        eprintln!(
            "phase0_capacity_spike: skipped - set ORACLEMCP_LIVE_XE=1 plus \
             ORACLEMCP_TEST_DSN/_USER/_PASSWORD to measure real lane capacity"
        );
        return;
    }
    let (Ok(dsn), Ok(user), Ok(password)) = (
        std::env::var("ORACLEMCP_TEST_DSN"),
        std::env::var("ORACLEMCP_TEST_USER"),
        std::env::var("ORACLEMCP_TEST_PASSWORD"),
    ) else {
        eprintln!(
            "phase0_capacity_spike: skipped - ORACLEMCP_LIVE_XE is set but \
             ORACLEMCP_TEST_DSN/_USER/_PASSWORD are not complete"
        );
        return;
    };

    let lanes = read_env_usize("ORACLEMCP_PHASE0_LANES")
        .unwrap_or(DEFAULT_LANES)
        .clamp(1, GLOBAL_CAP_CANDIDATE);
    let probes_per_lane = read_env_usize("ORACLEMCP_PHASE0_PROBES_PER_LANE")
        .unwrap_or(DEFAULT_PROBES_PER_LANE)
        .clamp(1, 128);
    let p99_budget_us = read_env_u128("ORACLEMCP_PHASE0_P99_BUDGET_US")
        .unwrap_or(DEFAULT_P99_BUDGET_US)
        .max(1);

    let opts = Arc::new(OracleConnectOptions {
        connect_string: dsn,
        username: Some(user),
        password: Some(password),
        call_timeout: Some(Duration::from_secs(10)),
        ..Default::default()
    });
    let latencies_us = Arc::new(Mutex::new(Vec::with_capacity(lanes * probes_per_lane)));
    let lane_threads = Arc::new(Mutex::new(BTreeSet::new()));
    let factory = probe_factory(
        Arc::clone(&opts),
        Arc::clone(&latencies_us),
        Arc::clone(&lane_threads),
    );
    let registry = Arc::new(StatefulLaneDispatch::with_dispatch_factory(factory, None));

    let before = HostSnapshot::capture();
    let started = Instant::now();
    warm_all_lanes(&registry, lanes);
    latencies_us.lock().clear();
    lane_threads.lock().clear();
    let after_warm = HostSnapshot::capture();
    run_probe_waves(&registry, lanes, probes_per_lane);
    let after_probe = HostSnapshot::capture();
    let elapsed_ms = started.elapsed().as_millis();

    let mut samples = latencies_us.lock().clone();
    samples.sort_unstable();
    let p50 = percentile(&samples, 0.50);
    let p95 = percentile(&samples, 0.95);
    let p99 = percentile(&samples, 0.99);
    let max = samples.last().copied().unwrap_or_default();
    let observed_lane_threads = lane_threads.lock().len();
    let limits = HostLimits::capture();
    let derivation = CapacityDerivation::from_measurement(&before, &after_warm, &limits, lanes);

    assert_eq!(
        samples.len(),
        lanes * probes_per_lane,
        "every lane/probe pair must complete against real Oracle"
    );
    assert_eq!(
        observed_lane_threads, lanes,
        "each measured lane should own one dispatch thread"
    );
    assert!(
        p99 <= p99_budget_us,
        "phase0 lane p99 {p99}us exceeded budget {p99_budget_us}us"
    );
    if let Some(safe_lanes) = derivation.safe_global_lanes {
        assert!(
            safe_lanes >= u64::try_from(lanes).unwrap_or(u64::MAX),
            "host resource derivation supports only {safe_lanes} lanes, below measured {lanes}"
        );
    }

    eprintln!(
        "{}",
        json!({
            "event": "phase0_capacity_spike",
            "bead": "oraclemcp-epic-060-f4xo.5.27",
            "lanes_requested": lanes,
            "oracle_sessions_opened": lanes,
            "probes_per_lane": probes_per_lane,
            "samples": samples.len(),
            "elapsed_ms": elapsed_ms,
            "latency_us": {
                "p50": p50,
                "p95": p95,
                "p99": p99,
                "max": max,
                "budget_p99": p99_budget_us
            },
            "thread_model": {
                "appendix": "A.11",
                "budgeted_threads_per_lane": THREADS_PER_LANE_BUDGET,
                "observed_lane_dispatch_threads": observed_lane_threads,
                "observed_process_threads_before": before.threads,
                "observed_process_threads_after_warm": after_warm.threads,
                "observed_process_threads_after_probe": after_probe.threads,
                "observed_process_thread_delta_after_warm": after_warm.delta_threads(&before)
            },
            "fd_model": {
                "observed_fds_before": before.fds,
                "observed_fds_after_warm": after_warm.fds,
                "observed_fds_after_probe": after_probe.fds,
                "observed_fd_delta_after_warm": after_warm.delta_fds(&before)
            },
            "host_limits": limits.to_json(),
            "derived_capacity": derivation.to_json(),
            "candidate_caps_under_review_by_n4b": {
                "read_per_profile": READ_CAP_CANDIDATE,
                "stateful_per_profile": STATEFUL_CAP_CANDIDATE,
                "global": GLOBAL_CAP_CANDIDATE
            },
            "verdict": "measurement_captured_for_n4b_default_finalization"
        })
    );
}

fn probe_factory(
    opts: Arc<OracleConnectOptions>,
    latencies_us: Arc<Mutex<Vec<u128>>>,
    lane_threads: Arc<Mutex<BTreeSet<String>>>,
) -> Arc<LaneDispatchFactory> {
    Arc::new(move |cx: &Cx, lane_context: &LaneContext| {
        let opts = Arc::clone(&opts);
        let latencies_us = Arc::clone(&latencies_us);
        let lane_threads = Arc::clone(&lane_threads);
        let lane_id = lane_context.lane_id().to_owned();
        let future: DispatchFactoryFuture<'_> = Box::pin(async move {
            let settings = PoolSettings {
                max_size: 1,
                min_idle: 1,
                acquire_timeout_secs: 5,
                statement_cache_size: 20,
            };
            let pool = OraclePool::connect(cx, (*opts).clone(), settings)
                .await
                .map_err(|err| db_error(&lane_id, "connect", err))?;
            Ok(Arc::new(DbProbeDispatch {
                lane_id,
                pool,
                latencies_us,
                lane_threads,
            }) as Arc<dyn ToolDispatch>)
        });
        future
    })
}

fn warm_all_lanes(registry: &Arc<StatefulLaneDispatch>, lanes: usize) {
    for lane in 0..lanes {
        dispatch_probe(registry, lane, "warm");
    }
}

fn run_probe_waves(registry: &Arc<StatefulLaneDispatch>, lanes: usize, probes_per_lane: usize) {
    for probe in 0..probes_per_lane {
        let mut handles = Vec::with_capacity(lanes);
        for lane in 0..lanes {
            let registry = Arc::clone(registry);
            handles.push(std::thread::spawn(move || {
                dispatch_probe(&registry, lane, &format!("probe-{probe}"));
            }));
        }
        for handle in handles {
            handle
                .join()
                .expect("phase0 probe coordinator thread joins");
        }
    }
}

fn dispatch_probe(registry: &Arc<StatefulLaneDispatch>, lane: usize, probe: &str) {
    block_on_lane_bridge(async {
        let cx = Cx::current().expect("lane bridge installs Cx");
        let session = format!("phase0-session-{lane}");
        let principal = format!("phase0-principal-{lane}");
        registry
            .dispatch(
                &cx,
                DispatchContext::default()
                    .with_http_session_id(&session)
                    .with_principal_key(&principal),
                probe,
                Value::Null,
            )
            .await
            .expect("phase0 lane probe dispatch succeeds");
    });
}

fn db_error(lane_id: &str, phase: &str, err: oraclemcp_db::DbError) -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorClass::ConnectionFailed,
        format!("phase0 capacity lane {lane_id} failed during {phase}: {err}"),
    )
}

fn read_env_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok()?.parse().ok()
}

fn read_env_u128(name: &str) -> Option<u128> {
    std::env::var(name).ok()?.parse().ok()
}

fn percentile(sorted: &[u128], p: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (((sorted.len() - 1) as f64) * p).round() as usize;
    sorted[idx]
}

#[derive(Clone, Copy, Debug)]
struct HostSnapshot {
    threads: Option<u64>,
    fds: Option<u64>,
}

impl HostSnapshot {
    fn capture() -> Self {
        Self {
            threads: count_dir("/proc/self/task"),
            fds: count_dir("/proc/self/fd"),
        }
    }

    fn delta_threads(&self, before: &Self) -> Option<i64> {
        delta(self.threads, before.threads)
    }

    fn delta_fds(&self, before: &Self) -> Option<i64> {
        delta(self.fds, before.fds)
    }
}

#[derive(Clone, Copy, Debug)]
struct HostLimits {
    open_files_soft: Option<u64>,
    max_processes_soft: Option<u64>,
    stack_soft_bytes: Option<u64>,
    cgroup_pids_max: Option<u64>,
    cgroup_memory_max_bytes: Option<u64>,
}

impl HostLimits {
    fn capture() -> Self {
        Self {
            open_files_soft: proc_limit_soft("Max open files"),
            max_processes_soft: proc_limit_soft("Max processes"),
            stack_soft_bytes: proc_limit_soft("Max stack size"),
            cgroup_pids_max: read_cgroup_limit("/sys/fs/cgroup/pids.max"),
            cgroup_memory_max_bytes: read_cgroup_limit("/sys/fs/cgroup/memory.max"),
        }
    }

    fn task_limit(&self) -> Option<u64> {
        finite_min([self.max_processes_soft, self.cgroup_pids_max])
    }

    fn to_json(self) -> Value {
        json!({
            "open_files_soft": self.open_files_soft,
            "max_processes_soft": self.max_processes_soft,
            "stack_soft_bytes": self.stack_soft_bytes,
            "cgroup_pids_max": self.cgroup_pids_max,
            "cgroup_memory_max_bytes": self.cgroup_memory_max_bytes
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct CapacityDerivation {
    observed_threads_per_lane_x100: Option<u64>,
    observed_fds_per_lane_x100: Option<u64>,
    lanes_by_tasks: Option<u64>,
    lanes_by_fds: Option<u64>,
    lanes_by_memory: Option<u64>,
    safe_global_lanes: Option<u64>,
}

impl CapacityDerivation {
    fn from_measurement(
        before: &HostSnapshot,
        after: &HostSnapshot,
        limits: &HostLimits,
        lanes: usize,
    ) -> Self {
        let lanes_u64 = u64::try_from(lanes).unwrap_or(u64::MAX).max(1);
        let thread_delta = after
            .delta_threads(before)
            .and_then(|n| u64::try_from(n.max(0)).ok());
        let fd_delta = after
            .delta_fds(before)
            .and_then(|n| u64::try_from(n.max(0)).ok());
        let observed_threads_per_lane_x100 =
            thread_delta.map(|n| n.saturating_mul(100) / lanes_u64);
        let observed_fds_per_lane_x100 = fd_delta.map(|n| n.saturating_mul(100) / lanes_u64);
        let per_lane_tasks = observed_threads_per_lane_x100
            .map(ceil_x100)
            .unwrap_or(THREADS_PER_LANE_BUDGET)
            .max(THREADS_PER_LANE_BUDGET);
        let per_lane_fds = observed_fds_per_lane_x100
            .map(ceil_x100)
            .unwrap_or(1)
            .max(1);

        let lanes_by_tasks = limits
            .task_limit()
            .zip(before.threads)
            .map(|(limit, base)| {
                limit
                    .saturating_sub(base)
                    .saturating_sub(RESERVED_TASKS_FOR_OPERATOR_AND_SERVICE)
                    / per_lane_tasks
            });
        let lanes_by_fds = limits.open_files_soft.zip(before.fds).map(|(limit, base)| {
            limit
                .saturating_sub(base)
                .saturating_sub(RESERVED_FDS_FOR_OPERATOR_AND_SERVICE)
                / per_lane_fds
        });
        let lanes_by_memory = limits
            .cgroup_memory_max_bytes
            .zip(limits.stack_soft_bytes)
            .map(|(memory, stack)| {
                let per_lane_stack = stack.saturating_mul(THREADS_PER_LANE_BUDGET).max(1);
                memory / per_lane_stack
            });
        let safe_global_lanes = finite_min([lanes_by_tasks, lanes_by_fds, lanes_by_memory]);

        Self {
            observed_threads_per_lane_x100,
            observed_fds_per_lane_x100,
            lanes_by_tasks,
            lanes_by_fds,
            lanes_by_memory,
            safe_global_lanes,
        }
    }

    fn to_json(self) -> Value {
        json!({
            "observed_threads_per_lane": format_x100(self.observed_threads_per_lane_x100),
            "observed_fds_per_lane": format_x100(self.observed_fds_per_lane_x100),
            "lanes_by_tasks": self.lanes_by_tasks,
            "lanes_by_fds": self.lanes_by_fds,
            "lanes_by_memory": self.lanes_by_memory,
            "safe_global_lanes": self.safe_global_lanes,
            "supports_global_64_candidate": self
                .safe_global_lanes
                .map(|n| n >= GLOBAL_CAP_CANDIDATE as u64)
        })
    }
}

fn count_dir(path: &str) -> Option<u64> {
    let count = std::fs::read_dir(path).ok()?.filter_map(Result::ok).count();
    u64::try_from(count).ok()
}

fn delta(after: Option<u64>, before: Option<u64>) -> Option<i64> {
    Some(i64::try_from(after?).ok()? - i64::try_from(before?).ok()?)
}

fn proc_limit_soft(label: &str) -> Option<u64> {
    let limits = std::fs::read_to_string("/proc/self/limits").ok()?;
    for line in limits.lines() {
        if let Some(rest) = line.strip_prefix(label) {
            return parse_limit_value(rest.split_whitespace().next()?);
        }
    }
    None
}

fn read_cgroup_limit(path: &str) -> Option<u64> {
    let raw = std::fs::read_to_string(path).ok()?;
    parse_limit_value(raw.trim())
}

fn parse_limit_value(raw: &str) -> Option<u64> {
    if raw.eq_ignore_ascii_case("unlimited") || raw == "max" {
        None
    } else {
        raw.parse().ok()
    }
}

fn finite_min(values: impl IntoIterator<Item = Option<u64>>) -> Option<u64> {
    values.into_iter().flatten().min()
}

fn ceil_x100(value: u64) -> u64 {
    value.saturating_add(99) / 100
}

fn format_x100(value: Option<u64>) -> Option<String> {
    let value = value?;
    Some(format!("{}.{:02}", value / 100, value % 100))
}
