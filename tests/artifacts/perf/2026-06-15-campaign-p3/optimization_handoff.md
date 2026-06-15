# Optimization Handoff

Run ID: `2026-06-15-campaign-p3`

This is the handoff from `profiling-software-performance` to
`extreme-software-optimization`. Each candidate lists the objective, proof
commands, guardrails, likely files, and whether current evidence is strong
enough to enter the optimizer Opportunity Matrix.

## Candidate 1: Cache Or Reuse `tools/list` Result JSON

Objective: reduce native first-contact and repeated `tools/list` JSON
construction cost without changing the advertised tool names, order, schemas,
or `oracle_capabilities` behavior.

Evidence:
- P2 S1: stdio initialize plus `tools/list` p95 is 14 ms over 50 runs.
- P2 S1: `tools/list` response contributes a 44,095 byte transcript.
- Current code builds the list through `OracleMcpServer::tools_list_result_json`
  and `OracleMcpServer::tools_json`; `build_server` constructs the registry and
  capabilities once before serving.

Likely files to inspect:
- `crates/oraclemcp-core/src/server.rs`
- `crates/oraclemcp/src/main.rs`
- `crates/oraclemcp-core/src/tools.rs`
- `crates/oraclemcp-core/tests/mcp_conformance.rs`
- `crates/oraclemcp/tests/e2e_stdio.rs`
- `crates/oraclemcp/tests/golden_behavior.rs`

Proof commands:
```bash
cargo test -p oraclemcp-core --test mcp_conformance tools_list_returns_input_schema_objects_and_echoes_string_ids -- --exact
cargo test -p oraclemcp --test e2e_stdio tools_list_advertises_registry_tools_plus_capabilities -- --exact
cargo test -p oraclemcp --test golden_behavior -- --nocapture
```

Performance proof:
```bash
cargo build --release -p oraclemcp
for i in $(seq 1 50); do printf '%b' "$payload" | ORACLEMCP_LOG=error /tmp/cargo-target/release/oraclemcp serve --allow-no-auth >/dev/null; done
```

Guardrails:
- Preserve `oracle_capabilities` first in `tools/list`.
- Preserve deduplication if a registry ever contains `oracle_capabilities`.
- Preserve every descriptor `inputSchema`.
- Do not cache across a server rebuild with a different custom-tool catalog.
- Do not weaken auth, init-token handling, scope checks, or dispatch behavior.

Opportunity Matrix eligibility: yes. This is the recommended first O1 target,
with one extra focused before/after measurement if the optimizer needs cleaner
attribution than the P2 process-level S1 transcript.

## Candidate 2: Separate First Connect From Steady-State Oracle Work

Objective: establish whether optimization should target physical connection
setup, pooled checkout, query execution, dictionary SQL shape, or result
serialization for real Oracle 23ai use.

Evidence:
- P2 S5: live first-connect smoke p95 is 54.55 ms over 30 release-test runs.
- The live smoke validates the local Oracle 23ai path but mixes process/test
  harness overhead, physical connect, ping/query/bind calls, and `describe`.

Likely files to inspect:
- `crates/oraclemcp-db/src/connection.rs`
- `crates/oraclemcp-db/src/pool.rs`
- `crates/oraclemcp-db/src/intelligence.rs`
- `crates/oraclemcp-db/tests/live_oracle.rs`
- `crates/oraclemcp/src/dispatch/mod.rs`

Proof commands:
```bash
cargo test -p oraclemcp-db --features live-xe --test live_oracle live_connect_ping_query_bind_describe -- --exact --nocapture
cargo test -p oraclemcp-db --features live-xe --test live_oracle live_pool_reuses_connection_for_query -- --exact --nocapture
```

Guardrails:
- Keep credentials in shell variables; do not print or artifact values.
- Do not relax the read-only guard or standby/read-only posture.
- Do not optimize connection behavior from first-connect numbers alone.
- Keep rollback/lease cleanup behavior intact.

Opportunity Matrix eligibility: not yet for a code optimization. It is eligible
only as a measurement-first optimizer setup task.

## Candidate 3: Large Page Serialization And Byte Accounting

Objective: reduce large-page `read_query` serialization cost while preserving
byte caps, row caps, cursor semantics, JSON shapes, type fidelity, and
cancellation checkpoints.

Evidence:
- P2 S3: 1000-row page serialization is 1.7955 ms; 200 rows is 357.76 us.
- Existing code already uses `PageColumnCache`, so further work should not
  re-target per-cell type classification unless new evidence contradicts P2.

Likely files to inspect:
- `crates/oraclemcp-db/src/query.rs`
- `crates/oraclemcp-db/src/serialize.rs`
- `crates/oraclemcp-db/benches/page_serialization.rs`
- `crates/oraclemcp-db/tests/type_fidelity.rs`
- `crates/oraclemcp-db/tests/live_oracle.rs`

Proof commands:
```bash
cargo bench -p oraclemcp-db --bench page_serialization -- --sample-size 30
cargo test -p oraclemcp-db type_fidelity -- --nocapture
cargo test -p oraclemcp-db query -- --nocapture
```

Guardrails:
- Preserve `QueryResponse` fields and `next_cursor` behavior.
- Preserve `max_result_bytes`, `max_rows`, and "include at least one row" logic.
- Preserve cancellation checkpoints before, during, and after serialization.
- Preserve lossless `NUMBER` behavior and LOB truncation metadata.

Opportunity Matrix eligibility: yes, but lower priority than Candidate 1 unless
the next live dictionary/profile measurement shows large local payload cost.

## Candidate 4: BLOB Base64 Encoding

Objective: reduce capped BLOB serialization cost only if an isolated, proven
encoder improvement is available without changing JSON output or adding
unwanted dependency risk.

Evidence:
- P2 S4: capped 1 MiB BLOB serialization is 116.82 us.
- This is the largest isolated cell-level measurement, but it is small in
  absolute user-visible terms.

Likely files to inspect:
- `crates/oraclemcp-db/src/serialize.rs`
- `crates/oraclemcp-db/benches/lob_capping.rs`
- `crates/oraclemcp-db/tests/type_fidelity.rs`

Proof commands:
```bash
cargo bench -p oraclemcp-db --bench lob_capping -- --sample-size 30
cargo test -p oraclemcp-db blob -- --nocapture
```

Guardrails:
- Preserve standard base64 alphabet and padding.
- Preserve `byte_length`, `truncated`, and cap semantics.
- Avoid adding a dependency unless the measured gain clears the optimizer score.

Opportunity Matrix eligibility: maybe. It has isolated evidence, but likely
scores below Candidate 1 and Candidate 3 because the absolute cost is low.

## Recommended O1 Order

1. Score and attempt Candidate 1 if the Opportunity Matrix is >= 2.0.
2. If Candidate 1 does not clear the score gate, add the missing steady-state
   Oracle measurement before touching connection/pool behavior.
3. Consider Candidate 3 only after the tool-list path converges or live
   dictionary workloads show serialization dominates local time.
