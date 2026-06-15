# P3 Profiling Interpretation

Run ID: `2026-06-15-campaign-p3`
Completed: `2026-06-15T21:09:21Z`

This pass interprets the P1/P2 profiling artifacts only. It did not run
benchmarks, optimize code, refactor code, tune the OS, install tools, or touch
production Rust code.

## Evidence Base

- P1 scenario and environment definition:
  `tests/artifacts/perf/2026-06-15-campaign-p1/`
- P2 baseline, hotspot table, hypothesis ledger, and raw samples:
  `tests/artifacts/perf/2026-06-15-campaign-p2/`
- P2 sampling limitation: no CPU flamegraph or allocation profile was captured
  because `perf_event_paranoid=4` blocks unprivileged sampling and no kernel
  tuning was approved.

## Ranked Interpretation

| Rank | Target | Interpretation | Real Hotspot? | Evidence |
| ---: | --- | --- | --- | --- |
| 1 | Live Oracle first-connect smoke | The largest measured user-visible path is first live DB work: connect, ping/query/bind, and describe around Oracle 23ai. It is real latency, but the P2 measurement bundles physical connection setup, session initialization, test-process overhead, and database round trips. | Yes for user-visible latency; not yet isolated enough for a connection optimization. | P2 `raw/s5-live-connect-smoke-release.csv`: p50 50 ms, p95 54.55 ms, p99 56.42 ms; `raw/s5-live-smoke-cargo-release.log` confirms Oracle `23.26.1.0.0`. |
| 2 | Native stdio startup plus initialize and `tools/list` | The first MCP contact path is stable at low double-digit milliseconds and emits a 44,095 byte tool-list response. The code builds the `tools/list` JSON from a fixed registry on each request, while the registry and capabilities are assembled once at server construction. | Yes, but smaller than live DB. Strong local optimization candidate if custom-tool correctness is preserved. | P2 `raw/s1-stdio-handshake-tools-list.csv`: p50 13 ms, p95 14 ms; `raw/s1-stdio-smoke-output.bytes`: 44,095 bytes; `crates/oraclemcp-core/src/server.rs` maps `tools/list` to `tools_list_result_json()`. |
| 3 | Offline `capabilities` startup | CLI startup and JSON rendering are visible but already small. The measurement mostly captures process startup rather than reusable server hot-path work. | Real but not worth optimizing first. | P2 `raw/s0-cli-startup-ns.csv`: p95 10 ms for `capabilities`; `raw/s0-capabilities-output.json` parses as JSON. |
| 4 | Page serialization for 1000 rows | Large-page JSON construction is a real local CPU/allocation path. Its absolute cost is lower than the live DB path, but it can compound on dictionary/source workflows that return large result sets. Existing code already caches per-column type classification across a page, so the next lever must target row/value construction or byte accounting, not type-name reclassification. | Yes, medium priority. | P2 `raw/s3-page-serialization-bench.log`: 1000 rows 1.7955 ms, 200 rows 357.76 us, 10 rows 13.426 us; `crates/oraclemcp-db/src/query.rs`; `crates/oraclemcp-db/src/serialize.rs`. |
| 5 | BLOB base64 cap path | BLOB serialization is the highest isolated cell-level cost, but the measured absolute cost is 116.82 us for a capped 1 MiB input. It is worth revisiting only for BLOB-heavy workflows or if a cheap, proven encoder swap scores well. | Yes, low priority. | P2 `raw/s4-lob-capping-bench.log`: `blob_base64_over_cap` 116.82 us. |
| 6 | Fail-closed SQL classifier | The classifier is mandatory for safety and currently cheap relative to DB and startup paths. It should stay correctness-first. | Not a current hotspot. | P2 `raw/s2-perf-classifier.csv`: p95 14.36 us/statement, about 71k classifications/sec. |
| 7 | Oracle type classification | Type classification is already in the nanosecond range and is not a meaningful user-visible cost. | Not a hotspot. | P2 `raw/s4-classify-type-bench.log`: 285.05 ns per classify benchmark loop, 454.91 ns for row classification benchmark. |

## What Is Missing

- A steady-state pooled Oracle measurement. P2 measured first live work by
  repeatedly launching a release test binary; it did not separate first-connect
  from pooled query and dictionary-tool latency.
- A pure `tools/list` construction benchmark. P2 measured process startup plus
  initialize plus `tools/list`, so O1 should prove the cached response improves
  either a focused construction benchmark or the same S1 wall-clock transcript.
- CPU flamegraph and allocation attribution. These remain blocked until the
  operator approves kernel/profiler setup or an unprivileged sampler is
  installed.

## Optimizer Entry Recommendation

The first optimizer pass should score `tools/list` response reuse first. It is a
local, low-risk, measurable candidate with clear correctness tests and no
database state. The live DB path should stay measurement-first until steady-state
pool and dictionary timings are captured.
