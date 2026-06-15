# P2 Hypothesis Ledger

| Hypothesis | Verdict | Evidence |
| --- | --- | --- |
| Live Oracle round-trip and connection setup dominate first real database work. | supports | S5 release smoke p95 is 54.55 ms, far above local serialization and classifier costs. See `raw/s5-live-connect-smoke-release.csv`. |
| Native stdio startup/tool listing is acceptable but visible in first-contact latency. | supports | S1 p95 is 14 ms and emits 44,095 bytes. It is not worse than the live DB path, but it is large enough to consider response reuse. |
| The fail-closed SQL classifier is not a current bottleneck. | supports | S2 classifier p95 is 14.36 us per statement, roughly three orders below S5 live wall time. |
| Page serialization scales roughly linearly and becomes relevant on large pages. | supports | Criterion measured 13.426 us for 10 rows, 357.76 us for 200 rows, and 1.7955 ms for 1000 rows. |
| BLOB capping is the highest measured cell-level serialization cost. | supports | `blob_base64_over_cap` measured 116.82 us, above CLOB cap paths at 10.68-13.67 us. |
| Type classification is worth optimizing now. | rejects | Type classification measured 285.05 ns per benchmark loop and row serialization classification measured 454.91 ns. It is below page-building, LOB, stdio, and DB costs. |
| CPU flamegraph evidence is required before changing low-level parser or serializer internals. | supports | P2 has wall/Criterion evidence only; `perf record` is unavailable without approved kernel tuning. |

## Hand-Off To P3

P3 should interpret whether the first optimization pass should target:

1. Steady-state live DB path measurement: pooled connection query and dictionary
   tools, not just first connect.
2. `tools/list` response construction or caching, if dynamic custom tools do not
   require rebuilding the response every request.
3. Large page serialization and BLOB cap behavior, if S6 dictionary/source paths
   show large local payload cost.

No optimization should be applied until P3 turns this ledger into an
Opportunity Matrix for `extreme-software-optimization`.
