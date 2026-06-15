# DEFINE - Thin-Native Performance Footprint

## Scenario

Measure current thin-native `oraclemcp` footprint and offline performance
surfaces after the Asupersync/thin-driver migration: release binary size,
Docker image size, startup for offline discovery commands, synthetic read-query
page serialization, and fail-closed SQL classifier cost.

## Metric

Binary/image/package bytes, command wall-clock p50/p95/max, command max RSS,
Criterion estimates for synthetic read serialization, and classifier
nanoseconds per statement.

## Budget

No long-lived budget existed before W13. This run establishes the first baseline
for future regression gates. Same-host p95 drift over 10 percent should be
investigated before claiming a regression or improvement.

## Golden Output

Smoke checks:

- `/tmp/cargo-target/release/oraclemcp info` exits successfully and reports
  `engine=false`, `live_db=true`, `transports=["stdio","http"]`, version
  `0.2.1`.
- `docker run --rm --entrypoint /bin/sh oraclemcp:w13-7dd4a60 -c '... oraclemcp info'`
  exits successfully and reports `runtime_gcc=absent`.
- `/tmp/cargo-target/release/oraclemcp capabilities | head -c 1200 >/dev/null`
  exits successfully under `pipefail`.
- `cargo test -p oraclemcp-guard --release --test perf_classifier -- --ignored --nocapture`
  passes its sanity assertion.

## Scope Boundary

Out of scope:

- Live Oracle connection/query latency. No live database credentials or
  connect strings were used.
- Historical thick-mode binary/image timing. Existing stale `0.2.0` packages in
  the local target directory were not treated as a fair rebuilt baseline.
- Kernel or CPU tuning. The run records current host state only.

## Variance Envelope

- Less than or equal to 10 percent p95 drift vs a same-host run: treat as noise.
- More than 10 percent p95 drift: investigate.
- More than 20 percent p95 drift, or three consecutive drifts above 10 percent:
  escalate to profiling.

## Stakeholder / Requester

W13 from the thin-native Asupersync migration plan. The decision hinging on
this run is whether release/readme claims have measured support and whether any
release artifact still fails basic build/smoke checks.
