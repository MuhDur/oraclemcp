# O2 Opportunity Matrix

Scope: second `extreme-software-optimization` pass for bead
`oraclemcp-8fc.2`, focused on live Oracle 23ai after O1.

| Candidate | Evidence | User benefit | Risk | Score | Decision |
| --- | --- | --- | --- | ---: | --- |
| Preserve reusable thin-driver cursors with `release_cursor` after fully fetched query results | First O2 phase-split run failed on a reused connection with `ORA-01001` after `describe()`, showing the wrapper closed a cursor id still eligible for driver statement-cache reuse. After the fix, the live regression and 300 phase measurements completed. | Long-running agents can reuse one Oracle session across `describe`, query, and bind-query calls without cursor invalidation; steady-state calls stay sub-millisecond. | Low: this uses the driver's public lifecycle API for cached cursors. Copied cursors are still closed by the driver when released. | 4.2 | Land |
| Optimize cold physical connect | O2 shows cold connect dominates at 144.346 ms p50 and 154.685 ms p95. | Could reduce first live DB use after process start. | High inside oraclemcp: physical connect is primarily driver/network/database work, and the server already keeps pooled/session state for normal use. | 1.6 | Defer |
| Cache `describe()` result | Steady describe is 1.310 ms p50 and 1.559 ms p95. | Speeds repeated connection-info calls. | Medium: connection/session metadata can change after profile switch, identity changes, or role/open-mode changes. Needs invalidation design. | 1.7 | Defer |
| Optimize steady query path | Steady scalar query is 0.195 ms p50 and 0.233 ms p95 after cursor fix. | Low latency win potential is small. | Medium: query path is shared with safety, pagination, and type fidelity. | 0.9 | Reject for now |

The landed change fixes a correctness issue that also protects performance:
cursor reuse remains valid on long-lived sessions instead of degrading into
`ORA-01001` failures after discovery/describe cycles.
