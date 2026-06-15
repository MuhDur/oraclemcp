# O2 Results

Optimization/fix landed: keep fully consumed query cursors reusable by calling
the thin driver's `release_cursor` instead of `close_cursor`.

Live Oracle 23ai phase split after the fix:

| Scope | Phase | n | p50 | p95 | p99 | Min | Max |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| cold | connect | 20 | 144.346 ms | 154.685 ms | 160.083 ms | 131.403 ms | 160.083 ms |
| cold | describe | 20 | 3.506 ms | 4.013 ms | 4.471 ms | 3.078 ms | 4.471 ms |
| cold | ping | 20 | 0.154 ms | 0.176 ms | 0.179 ms | 0.140 ms | 0.179 ms |
| cold | query_bind | 20 | 0.299 ms | 0.346 ms | 0.357 ms | 0.272 ms | 0.357 ms |
| cold | query_scalar | 20 | 0.328 ms | 0.409 ms | 0.415 ms | 0.296 ms | 0.415 ms |
| steady | describe | 50 | 1.310 ms | 1.559 ms | 3.034 ms | 1.212 ms | 3.034 ms |
| steady | ping | 50 | 0.147 ms | 0.177 ms | 0.185 ms | 0.138 ms | 0.185 ms |
| steady | query_bind | 50 | 0.207 ms | 0.248 ms | 0.280 ms | 0.198 ms | 0.280 ms |
| steady | query_scalar | 50 | 0.195 ms | 0.233 ms | 0.319 ms | 0.185 ms | 0.319 ms |

Interpretation:

- Cold physical connect dominates live DB startup by two orders of magnitude.
- Once connected, scalar/bind query and ping are already sub-millisecond.
- `describe()` is the only steady-state phase above 1 ms p50, but it is metadata
  with correctness-sensitive invalidation semantics, so no cache is landed in
  this pass.
- The first attempted steady-state phase split exposed the cursor lifecycle bug;
  after the fix the same harness completed 50 steady iterations.

Raw evidence:

- `raw/live-phase-split.log`
- `raw/live-phase-split.csv`
- `raw/live-phase-summary.csv`
- `raw/live-oracle-full.log`
- `raw/secret-scan.txt`

Next optimization direction:

O3 should be a convergence pass. The remaining largest latency is cold physical
connect, which is not a safe or high-confidence optimization target inside
oraclemcp without driver-level work or explicit product changes such as
connection warmup policy.
