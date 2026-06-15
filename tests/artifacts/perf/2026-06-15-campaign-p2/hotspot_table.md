# P2 Hotspot Table

Ranked by measured scenario cost and optimization relevance from P2 artifacts.
No CPU flamegraph was captured because unprivileged `perf` is blocked by
`perf_event_paranoid=4` and no kernel tuning was approved.

| Rank | Location | Metric | Value | Category | Evidence |
| ---: | --- | --- | ---: | --- | --- |
| 1 | Live Oracle 23ai connect + ping + bind queries + describe | p95 wall | 54.55 ms | DB round-trip / connection path | `raw/s5-live-connect-smoke-release.csv`, `raw/s5-live-smoke-cargo-release.log` |
| 2 | Native stdio process startup + initialize + `tools/list` | p95 wall, output size | 14 ms, 44,095 bytes | Process startup / JSON response construction | `raw/s1-stdio-handshake-tools-list.csv`, `raw/s1-stdio-smoke-output.bytes` |
| 3 | Offline `capabilities` process startup | p95 wall | 10 ms | Process startup / JSON serialization | `raw/s0-cli-startup-ns.csv`, `raw/s0-capabilities-output.json` |
| 4 | `read_query` page serialization for 1000 mock rows | Criterion estimate | 1.7955 ms | CPU / allocation / JSON construction | `raw/s3-page-serialization-bench.log` |
| 5 | `read_query` page serialization for 200 mock rows | Criterion estimate | 357.76 us | CPU / allocation / JSON construction | `raw/s3-page-serialization-bench.log` |
| 6 | BLOB base64 cap path for 1 MiB input capped at 64 KiB | Criterion estimate | 116.82 us | CPU / allocation / encoding | `raw/s4-lob-capping-bench.log` |
| 7 | Fail-closed SQL classifier | p95 per statement | 14.36 us | CPU / parser-classifier | `raw/s2-perf-classifier.csv`, `raw/s2-perf-classifier-cargo.log` |
| 8 | Oracle type classification | Criterion estimate | 285.05 ns per 10-name loop | CPU / string classification | `raw/s4-classify-type-bench.log` |

## P3 Interpretation Targets

- Separate connection setup cost from steady-state pooled query cost before
  choosing a DB optimization lever.
- Inspect whether `tools/list` output construction can be cached or reused
  safely without weakening dynamic capability correctness.
- Treat classifier optimization as low priority unless a later profile shows it
  repeats many times per user-visible request.
- Keep page serialization and LOB paths as medium-priority candidates for
  large-result workflows, especially S6 dictionary and source-reading paths.
