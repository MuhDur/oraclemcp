# D1 De-Monolithization Census

Scope: local, confirmation-gated `de-monolithize-your-codebase-isomorphically`
pass for bead `oraclemcp-8fc.4`.

This pass did not create the sibling de-monolithization workspace and did not
execute file splits. The skill requires explicit operator confirmation for the
sibling workspace, mode, tool inventory/install posture, offload choice, and
execution scope before a full split campaign.

## Census

Rust soft threshold: 5,000 code LOC. Hard trigger: 10,000 code LOC.

| File | LOC | Churn, last 180 days | Buckets | Severity prior | Verdict |
| --- | ---: | ---: | --- | --- | --- |
| `crates/oraclemcp/src/dispatch/mod.rs` | 3,520 | 6 | B3, B6-ish | borderline | Leave in place for now |
| `crates/oraclemcp/src/dispatch/tests.rs` | 2,899 | not scored | B9 | test-only | Leave in place |
| `crates/oraclemcp-guard/src/classifier.rs` | 2,313 | 12 | B11 | leave-alone | Cohesive safety-critical guard |
| `crates/oraclemcp/src/registry.rs` | 1,584 | 40 | B3, B4-ish data surface | borderline | Defer to schema-golden design |
| `crates/oraclemcp/src/main.rs` | 1,559 | 35 | B3 | borderline | Already has `robot_docs.rs` extracted |
| `crates/oraclemcp-core/src/custom_tools.rs` | 1,341 | 14 | B11 | leave-alone | Cohesive custom-tool pipeline |
| `crates/oraclemcp-db/src/intelligence.rs` | 1,060 | 12 | B11 | leave-alone | Cohesive dictionary/introspection module |
| `crates/oraclemcp-core/src/http.rs` | 1,049 | 8 | B11 | leave-alone | Cohesive native streamable HTTP transport |

No production Rust file exceeds the Rust soft threshold.

## Candidate Analysis

### `dispatch/mod.rs`

Existing decomposition:

- `dispatch/args.rs` holds the tool-call argument DTOs.
- `dispatch/tests.rs` holds the large dispatcher unit suite.
- `dispatch/mod.rs` contains constants, dispatcher state, safety gates, preview
  caches, tool handlers, and the `ToolDispatch` implementation.

Potential seam:

- Write-preview tools (`oracle_execute`, `oracle_compile_object`,
  `oracle_create_or_replace`, `oracle_patch_source`, `deploy_ddl`) form the
  largest visible cluster.

Why not split now:

- The cluster shares `DispatcherState`, confirmation-token helpers,
  `PatchPreviewEntry`, scoped session-level gates, the single connection lock,
  and fail-closed classifier helpers.
- A mechanical extraction would either widen many helpers to `pub(super)` or
  introduce a new context object around the connection/session/cache state.
- The current file is below the Rust soft threshold and not high churn.
- No compile-resource or runtime profile currently identifies this file as a
  bottleneck.

Required proof before any future extraction:

- Full dispatcher golden output for every affected tool alias.
- Public/internal API snapshot proving no exposed tool surface drift.
- Concurrency audit first, because the dispatcher intentionally serializes the
  live connection through one mutex.

### `registry.rs`

Potential seam:

- Schema fragments and per-tool registration blocks could move into a registry
  submodule.

Why not split now:

- This is public MCP schema data. A visually small edit can change an
  agent-facing JSON schema.
- The file is only 1,584 LOC and its helper extraction already reduced repeated
  fragments.

Required proof before any future extraction:

- Byte-stable `tools/list` and `oracle_capabilities` golden artifacts.
- Per-tool schema hash comparison before and after the move.

### `classifier.rs`

Verdict: leave alone.

The classifier is cohesive and safety-critical. It has one job: fail-closed SQL
classification. Splitting it without a direct safety or compile-resource reason
would add movement risk to the project's core invariant.

## Decision

No de-monolithization split should be executed in this campaign pass.

The repository is currently under the Rust monolith thresholds, the only
plausible split candidate is safety/concurrency sensitive, and a full
de-monolithization campaign requires explicit confirmation before creating the
sibling workspace or running extraction experiments. The next productive work is
the deadlock/concurrency audit.
