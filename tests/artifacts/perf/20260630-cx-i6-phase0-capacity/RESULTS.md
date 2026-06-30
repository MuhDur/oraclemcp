# CX-I6 Phase-0 Capacity Spike

- Run id: `20260630-cx-i6-phase0-capacity`
- Bead: `oraclemcp-epic-060-f4xo.5.27`
- Git SHA: `122c0e1` with local release-train changes in progress
- Host: Linux 7.0.0-27-generic x86_64 GNU/Linux, 128 logical CPUs
- Database: local Oracle FREE 23ai container (`gvenzl/oracle-free:23-slim`, FREEPDB1)
- Toolchain: pinned workspace nightly from `rust-toolchain.toml`

## Command

Secrets were supplied through the environment and were not printed.

```text
ORACLEMCP_LIVE_XE=1 \
ORACLEMCP_TEST_DSN=localhost:1521/FREEPDB1 \
ORACLEMCP_TEST_USER=system \
ORACLEMCP_TEST_PASSWORD=<redacted> \
ORACLEMCP_PHASE0_LANES=16 \
ORACLEMCP_PHASE0_PROBES_PER_LANE=4 \
CARGO_TARGET_DIR="$PWD/target" \
cargo test -p oraclemcp-core --test phase0_capacity -- --ignored --nocapture
```

## Result

```json
{
  "bead": "oraclemcp-epic-060-f4xo.5.27",
  "candidate_caps_under_review_by_n4b": {
    "global": 64,
    "read_per_profile": 16,
    "stateful_per_profile": 8
  },
  "derived_capacity": {
    "lanes_by_fds": 262111,
    "lanes_by_memory": null,
    "lanes_by_tasks": 16375,
    "observed_fds_per_lane": "4.00",
    "observed_threads_per_lane": "2.00",
    "safe_global_lanes": 16375,
    "supports_global_64_candidate": true
  },
  "elapsed_ms": 2397,
  "event": "phase0_capacity_spike",
  "fd_model": {
    "observed_fd_delta_after_warm": 64,
    "observed_fds_after_probe": 68,
    "observed_fds_after_warm": 68,
    "observed_fds_before": 4
  },
  "host_limits": {
    "cgroup_memory_max_bytes": null,
    "cgroup_pids_max": null,
    "max_processes_soft": 32768,
    "open_files_soft": 1048576,
    "stack_soft_bytes": 8388608
  },
  "lanes_requested": 16,
  "latency_us": {
    "budget_p99": 1000000,
    "max": 2090,
    "p50": 1203,
    "p95": 1427,
    "p99": 1464
  },
  "oracle_sessions_opened": 16,
  "probes_per_lane": 4,
  "samples": 64,
  "thread_model": {
    "appendix": "A.11",
    "budgeted_threads_per_lane": 2,
    "observed_lane_dispatch_threads": 16,
    "observed_process_thread_delta_after_warm": 32,
    "observed_process_threads_after_probe": 34,
    "observed_process_threads_after_warm": 34,
    "observed_process_threads_before": 2
  },
  "verdict": "measurement_captured_for_n4b_default_finalization"
}
```

The test passed: one ignored live test, zero failures.

## Interpretation

This spike measured the WP-N lane shape that exists in `oraclemcp-core`: each
stateful lane owns a dedicated OS thread plus an asupersync current-thread
runtime, and constructs a real Oracle pool on that lane. Sixteen lane-owned
Oracle sessions completed 64 `SELECT 1` probes.

The observed process-thread delta was exactly 32 for 16 warmed lanes, matching
the Appendix A.11 budget of roughly two OS threads per lane. The observed file
descriptor delta was 64, or 4.00 fds per lane, including Oracle sockets and the
runtime/reactor footprint visible through `/proc/self/fd`.

On this host, finite process and fd limits both support the candidate global
cap of 64 lanes with headroom. cgroup pids and memory limits were unavailable,
so memory-derived capacity is intentionally recorded as `null` rather than
invented. N4b owns the final shipped defaults and must cite this measurement.
