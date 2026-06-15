# Scenario Map

Run ID: `2026-06-15-campaign-p1`

This pass defines what should be measured after the thin-native/asupersync
migration. No benchmark loop was run in P1.

## P2 Measurement Scenarios

| ID | Scenario | Why It Matters | Primary Metric | Golden / Correctness Gate |
| --- | --- | --- | --- | --- |
| S0 | Offline CLI startup: `oraclemcp info`, `oraclemcp capabilities` | First agent contact must stay fast and low-RSS when no profile is configured. | p50/p95/p99 wall time, peak RSS, binary size | Command exits 0; output remains valid JSON/text per existing tests. |
| S1 | Stdio MCP handshake and tool listing | Agent clients usually start with initialize/tools/list before any DB call. | p50/p95 wall time, output bytes, peak RSS | Existing stdio golden transcripts still match. |
| S2 | Fail-closed SQL classifier throughput | Every raw `oracle_query` and `oracle_explain_plan` goes through this gate before Oracle. | ns/statement, classifications/sec | Classifier tests and adversarial corpus remain green. |
| S3 | Offline row/page serialization | Thin driver returns rows; local JSON serialization can dominate large pages. | Criterion estimates for 10/200/1000 rows, alloc/RSS if available | Existing `oraclemcp-db` serialization tests remain green. |
| S4 | LOB and type classification paths | CLOB/BLOB caps and Oracle type handling are high-risk for both latency and payload size. | Criterion estimate, output byte caps, p95 over repeated samples | Type-fidelity tests remain green. |
| S5 | Live Oracle 23ai connect, ping, describe, and simple bound read | Confirms thin driver round-trip cost and connection setup cost on the local 23ai path. | p50/p95 wall time, Oracle round-trip count if instrumented, peak RSS | `live_connect_ping_query_bind_describe` passes with credentials kept out of artifacts. |
| S6 | Live dictionary workflows: schema/table/source/DDL/compile errors | These are the agent-facing productivity paths most likely to hit Oracle dictionary cost. | p50/p95 wall time per tool, rows returned, serialized bytes | Existing `live_oracle` cases pass; no write tools are exercised. |
| S7 | Native transport concurrency and cancellation | Replaced rmcp/Axum/Hyper/Tokio with native/asupersync paths; concurrency behavior needs measurement. | p95 under concurrent requests, cancellation latency, failure rate | MCP conformance and chaos tests remain green. |
| S8 | Safety refusal paths | Refusing writes must be cheap and must not touch Oracle when blocked by policy. | p50/p95 refusal latency, backend touch count | `NoExecMock`/fail-closed tests prove no DB execution. |

## Prioritization For P2

Measure S0-S5 first. They have existing commands or tests and can produce a
ranked hotspot table without new production code. S6-S8 should follow once the
baseline harness is stable, because they may need additional measurement-only
wrapping or scripted transcripts.

## Non-Goals For P2

- No thick-mode comparison. Thick mode has been removed from this repo.
- No OS/kernel tuning unless explicitly approved.
- No optimization or refactor before a ranked hotspot table exists.
- No credential values, connect strings beyond localhost test endpoints, wallet
  paths, or schema data in artifacts.
