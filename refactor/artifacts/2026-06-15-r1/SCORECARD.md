# R1 Simplification Scorecard

Scope: first `simplify-and-refactor-code-isomorphically` pass for bead
`oraclemcp-8fc.3`.

Inventory:

- Largest production files: `dispatch/mod.rs` (3520 LOC), guard classifier
  (2313 LOC), `registry.rs` (1584 LOC), `main.rs` (1559 LOC),
  `custom_tools.rs` (1341 LOC), DB intelligence (1060 LOC), core HTTP
  transport (1049 LOC), server (990 LOC), DB connection (884 LOC).
- High-risk public surfaces: SQL classifier, registry schemas, dispatch tool
  contracts, DB serialization/type fidelity, native transports.
- Recent high-value context: O2 changed DB cursor lifecycle and added live 23ai
  query-after-describe coverage.

Candidates:

| Candidate | LOC saved | Confidence | Risk | Score | Decision |
| --- | ---: | ---: | ---: | ---: | --- |
| Extract `RustOracleConnection::describe()` best-effort first-row helper | 16 | 0.90 | 2 | 7.2 | Land in R2 |
| Normalize registry alias schema fragments further | 80+ | 0.55 | 6 | 7.3 | Defer: public schema output is large and golden-sensitive; needs dedicated schema golden proof. |
| Split `dispatch/mod.rs` tool families | 300+ | 0.45 | 8 | 16.9 | Defer to de-monolithization pass; file movement needs a separate isomorphism contract. |
| Collapse repeated dispatch JSON response builders | 40 | 0.60 | 5 | 4.8 | Defer: touches many tool outputs and could affect agent-facing shape. |
| Simplify live phase profiling helper | 4 | 0.95 | 1 | 3.8 | Already acceptable; no standalone user benefit. |

R2 target:

Refactor `describe()` only. Preserve its current best-effort semantics: each
metadata query may fail independently, and `describe()` still returns available
fields instead of failing the whole connection-info path.
