# Rejected Optimization Targets

Run ID: `2026-06-15-campaign-p3`

These targets should not be optimized now. Revisit only if new profiling
evidence changes the ranking.

## Fail-Closed SQL Classifier

Reason: P2 measured the classifier at p95 14.36 us per statement, roughly three
orders below the live Oracle first-work path. It is also the central safety
boundary, so correctness and fail-closed behavior dominate any micro-optimization
interest.

Evidence:
- `tests/artifacts/perf/2026-06-15-campaign-p2/raw/s2-perf-classifier.csv`
- `tests/artifacts/perf/2026-06-15-campaign-p2/raw/s2-perf-classifier-cargo.log`

## Oracle Type Classification

Reason: P2 measured this in the nanosecond range. Existing page serialization
already caches column classifications across a result page, so optimizing this
again would be noise unless a later flamegraph says otherwise.

Evidence:
- `tests/artifacts/perf/2026-06-15-campaign-p2/raw/s4-classify-type-bench.log`
- `crates/oraclemcp-db/src/serialize.rs`

## Offline CLI Startup

Reason: `oraclemcp info` and `oraclemcp capabilities` are already 8-10 ms p95
and mostly represent process startup. This is lower priority than live DB
latency and repeated server hot paths.

Evidence:
- `tests/artifacts/perf/2026-06-15-campaign-p2/raw/s0-cli-startup-ns.csv`

## Connection Optimization From First-Connect Numbers Alone

Reason: P2 proves first live work is the largest measured path, but it does not
separate physical connection setup, pooled reuse, query execution, dictionary
SQL cost, `describe`, and test-process overhead. Changing connection behavior
before that split would be attribution error.

Evidence:
- `tests/artifacts/perf/2026-06-15-campaign-p2/raw/s5-live-connect-smoke-release.csv`
- `tests/artifacts/perf/2026-06-15-campaign-p2/raw/s5-live-connect-direct-release.log`

## OS Or Kernel Tuning

Reason: `perf_event_paranoid=4` blocks unprivileged CPU sampling, but changing
kernel profiling knobs is global state and was not approved. This campaign can
request approval later; it should not silently tune the host.

Evidence:
- `tests/artifacts/perf/2026-06-15-campaign-p1/risk-notes.md`
- `tests/artifacts/perf/2026-06-15-campaign-p2/BASELINE.md`

## Broad Runtime Or Transport Rewrites

Reason: P2 has no evidence that Asupersync runtime dispatch, stdio parsing, HTTP
transport, or cancellation machinery dominates. Rewriting these now would be a
scope expansion without ranked proof.

Evidence:
- P2 hotspot table ranks live DB, startup/tool listing, and serialization above
  any runtime/concurrency target.

## DDL Or Dictionary Query Shape Changes

Reason: dictionary workflows were listed as S6 but not measured in P2. Do not
change `DBMS_METADATA`, `ROWNUM`, or dictionary SQL shapes for performance until
S6 has its own live evidence.

Evidence:
- `tests/artifacts/perf/2026-06-15-campaign-p1/scenario-map.md`
- `tests/artifacts/perf/2026-06-15-campaign-p2/hypothesis.md`
