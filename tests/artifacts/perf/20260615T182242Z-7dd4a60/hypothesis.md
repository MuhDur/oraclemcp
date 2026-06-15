# Hypothesis Ledger - 20260615T182242Z-7dd4a60

| Hypothesis | Verdict | Evidence |
|---|---|---|
| Thin-native release artifacts no longer require Oracle Instant Client or ODPI-C. | supports | Boundary gate and dependency graph are clean from W12; runtime Docker image contains no Oracle Instant Client install step and no `gcc`; `oraclemcp info` reports `live_db=true`. |
| Docker release path is currently healthy. | supports after fix | First build failed with missing `cc`; adding builder-only `gcc` made `docker build -t oraclemcp:w13-7dd4a60 .` pass and container smoke succeed. |
| Offline CLI discovery is a startup bottleneck. | rejects | `info` p95 8.053 ms; `capabilities` p95 9.398 ms on this host. |
| Local read-query serialization is likely to dominate live query latency. | rejects for normal DB use | Synthetic 1000-row serialization estimate is 1.7810 ms; live Oracle network/execute/fetch latency was not measured but is expected to dominate many real workloads. |
| SQL classification is a meaningful performance risk. | rejects for normal DB use | Classifier baseline is 14,290 ns/statement over the mixed corpus, far below typical DB round-trip scale. |
| W13 can claim a fair thick-vs-thin speedup. | rejects | No same-host historical thick binary/image was rebuilt under the same measurement contract. This run must not claim a speedup ratio. |
| W13 can claim current thin-native footprint. | supports | Release binary, Docker image, package sizes, startup RSS, and command timings are recorded in `BASELINE.md`. |
| Large CLI output behaves correctly in Unix pipelines. | supports after fix | `oraclemcp capabilities | head -c 1200 >/dev/null` exits 0 under `pipefail` locally and in the final Docker runtime image. |

## Follow-Up Candidates

- Add a live Oracle benchmark profile when sanitized credentials and an approved test schema are available.
- Add a release CI Docker smoke job in W14 so the builder dependency regression cannot return.
