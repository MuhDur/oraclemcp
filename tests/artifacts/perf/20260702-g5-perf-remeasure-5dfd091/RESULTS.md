# Performance re-measurement - G5

- Run id: `20260702-g5-perf-remeasure-5dfd091`
- Git SHA: `5dfd09192e2dce3cc90dbcbb72e2d9eb7862eee1`
- Bead: `oraclemcp-epic-060-f4xo.11.5`
- Host: AMD EPYC 7713 (64c/128t), 247 GiB RAM, Ubuntu 26.04 LTS, Linux 7.0.0, ext4
- Toolchain: `nightly-2026-05-11` (`rustc 1.97.0-nightly 2026-05-10`)
- Database: local `gvenzl/oracle-free:23-slim` FREEPDB1 container on `localhost:1521`
- Tuning: no kernel/CPU tuning; governor `schedutil`, boost enabled
- See `fingerprint.json` for the full environment header.

## Scope

This is the G5 post-lane-work re-measurement. It uses the repository's existing
load/soak and lane-capacity harnesses; no performance code changes were made.
The numbers are developer-host validation evidence, not a frozen release-RC
qualification run.

## Live load/soak against Oracle 23ai FREE

Workload: 8 thread-per-connection clients, 200 iterations/client, deterministic
80% `SELECT 1 FROM dual` / 20% `describe` mix through `OraclePool`.

Command:

```text
ORACLEMCP_LIVE_XE=1 \
ORACLEMCP_TEST_DSN=localhost:1521/FREEPDB1 \
ORACLEMCP_TEST_USER=system ORACLEMCP_TEST_PASSWORD=<redacted> \
CARGO_TARGET_DIR=/home/durakovic/.cache/oraclemcp-gap2-target \
TMPDIR=/home/durakovic/.cache/oraclemcp-gap2-tmp \
cargo test -p oraclemcp-db --test load_soak \
  live_xe_load_soak_pool_accounting_and_latency -- --ignored --nocapture
```

Output:

```text
live_xe_load_soak: 1600 ops across 8 clients (ITERATIONS=200) - p50=898us p95=3525us p99=5248us; all per-client pools balanced
test live_xe_load_soak_pool_accounting_and_latency ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.71s
elapsed_sec=0.93 max_rss_kb=81508
```

| Metric | Value |
|---|---:|
| Total operations | 1,600 |
| Clients | 8 |
| p50 | 898 us |
| p95 | 3,525 us |
| p99 | 5,248 us |
| Throughput, test-harness wall | ~2,254 ops/sec |
| Throughput, command wall including Cargo wrapper | ~1,720 ops/sec |
| Pool accounting | balanced |
| Leaked sessions | 0 |

The p50/p95/p99 remain well under the documented soft live thresholds
(25 ms / 75 ms / 150 ms). Pool accounting balance and zero leaked sessions are
hard pass/fail invariants and passed.

## Offline drain/leak harness

Command:

```text
CARGO_TARGET_DIR=/home/durakovic/.cache/oraclemcp-gap2-target \
TMPDIR=/home/durakovic/.cache/oraclemcp-gap2-tmp \
cargo test -p oraclemcp-db --test load_soak \
  load_soak_zero_leaked_sessions_clean_drain_bounded -- --nocapture
```

Output:

```text
test load_soak_zero_leaked_sessions_clean_drain_bounded ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.05s
elapsed_sec=0.25 max_rss_kb=81532
```

Assertions covered by the harness: `acquired == released + discarded`, live
count returns to zero, `LeaseManager::active_count() == 0` after drain, no
commits on drained/preview sessions, and live high-water mark stays at or below
the 8-client ceiling.

## Phase-0 lane capacity spike

Workload: 16 stateful lanes, one lane-owned Oracle session per lane, 4 probes
per lane after warm-up.

Command:

```text
ORACLEMCP_LIVE_XE=1 \
ORACLEMCP_TEST_DSN=localhost:1521/FREEPDB1 \
ORACLEMCP_TEST_USER=system ORACLEMCP_TEST_PASSWORD=<redacted> \
ORACLEMCP_PHASE0_LANES=16 \
ORACLEMCP_PHASE0_PROBES_PER_LANE=4 \
CARGO_TARGET_DIR=/home/durakovic/.cache/oraclemcp-gap2-target \
TMPDIR=/home/durakovic/.cache/oraclemcp-gap2-tmp \
cargo test -p oraclemcp-core --test phase0_capacity \
  phase0_capacity_spike -- --ignored --nocapture
```

Output summary:

```text
lanes_requested=16 oracle_sessions_opened=16 probes_per_lane=4 samples=64 elapsed_ms=2403
latency_us: p50=1173 p95=1613 p99=1723 max=1729 budget_p99=1000000
threads: before=2 after_warm=34 delta=32 observed_lane_dispatch_threads=16
fds: before=4 after_warm=68 delta=64
derived_capacity: observed_threads_per_lane=2.00 observed_fds_per_lane=4.00 safe_global_lanes=16375 supports_global_64_candidate=true
test phase0_capacity_spike ... ok
elapsed_sec=2.62 max_rss_kb=80620
```

| Metric | Value |
|---|---:|
| Lane-owned Oracle sessions opened | 16 |
| Probe samples | 64 |
| p50 / p95 / p99 / max | 1,173 us / 1,613 us / 1,723 us / 1,729 us |
| Process threads before -> warmed | 2 -> 34 |
| Observed thread delta | 32 = 2.00 per lane |
| File descriptors before -> warmed | 4 -> 68 |
| Observed fd delta | 64 = 4.00 per lane |
| Soft max processes | 32,768 |
| Soft open files | 1,048,576 |
| Derived safe global lanes | 16,375 |
| Supports global 64-lane candidate | yes |

## Interpretation

Compared with the prior dev-host validation run
`20260623-v0.4.0-oracledb0.5.0-473f9a8`, load/soak p50 is flat, p95 is within
same-host noise, and p99 is higher but still far below the documented live
threshold. The lane-capacity spike remains resource-bounded by the explicit
2-thread / 4-fd per-lane model and still supports the reviewed global 64-lane
candidate with wide host headroom.

No ranked performance hotspot or regression candidate is supported by this
measurement, so G5 does not justify optimization work.
