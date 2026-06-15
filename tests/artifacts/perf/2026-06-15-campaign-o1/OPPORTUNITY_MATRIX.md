# O1 Opportunity Matrix

Scope: first `extreme-software-optimization` pass for bead `oraclemcp-8fc.2`.
Baseline source is commit `6251dd45180f35872ba2e1c25a5437e5d228050b`.

| Candidate | Evidence | User benefit | Risk | Score | Decision |
| --- | --- | --- | --- | ---: | --- |
| Lazy cache the static `tools/list` descriptor/result JSON inside `OracleMcpServer` | P2 ranked native stdio initialize + `tools/list` as the second visible first-contact path. P3 identified descriptor rebuild as local and behavior-preserving. O1 repeated-session measurement improves p50 and p95. | Agents that probe tools repeatedly in one MCP session spend less time rebuilding the same descriptor payload. | Low: registry is fixed at server construction; the cache does not affect tool dispatch, auth, SQL guard, or DB connection behavior. | 3.1 | Land |
| Eager cache at server construction | O1 one-shot process measurement became worse because work moved into startup. | None for startup-heavy clients. | Medium: penalizes sessions that never call `tools/list`. | 0.8 | Reject |
| Optimize Oracle connection setup | P2 live first-connect smoke is largest path, but it bundles process/test harness, physical connect, session init, ping, query, and describe. | Could reduce first live DB latency. | High until split into first-connect vs steady-state measurements. | 1.4 | Defer |
| Optimize classifier | P2 classifier p95 is about 14.36 us per statement. | Low current impact. | Medium: classifier is the fail-closed safety core. | 0.7 | Reject for now |
| Optimize BLOB/base64 capping | P2 BLOB base64-over-cap benchmark is 116.82 us. | Helps large BLOB pages. | Medium: serialization semantics must remain exact. | 1.5 | Defer |

The landed candidate is deliberately limited to server-owned MCP discovery data.
It does not alter the fail-closed SQL guard, operating level enforcement,
transport authentication, or Oracle thin driver behavior.
