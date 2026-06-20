# ADR 0006 — `oraclemcp-db` is the canonical shared driver foundation; converge `plsql-mcp` onto it

## Status

Accepted (0.4.0).

## Context

`oraclemcp` is the lean half of a two-binary family; the PL/SQL intelligence
superset `plsql-mcp` lives in the sibling `plsql-intelligence` repo. Both need
the same things: thin Oracle connectivity, the NLS-stable serializer with
NUMBER→string fidelity, dictionary operations, the fail-closed classifier, and
the operating-level gate. Maintaining two divergent copies of that
correctness-critical core would double the surface for bugs and split the
hardening, fuzzing, and audit work.

## Decision

Treat **`oraclemcp-db`** (and its sibling engine-free crates: `-guard`,
`-audit`, `-error`, `-config`, `-auth`, `-telemetry`, `-core`) as the
**canonical shared foundation**. `plsql-mcp` converges onto these crates rather
than carrying its own driver/classifier/serializer; its added value (offline
PL/SQL parse/analyze, dependency graph, lineage, SAST, impact analysis) layers
on top. The engine-free core imports **no** PL/SQL analysis engine — a one-way
dependency boundary the CI enforces.

## Consequences

- The correctness-critical core (driver seam, serializer, classifier, audit) is
  written, tested, fuzzed, and hardened **once** and shared by both binaries.
- `oraclemcp` stays lean — it ships the database MCP surface without dragging in
  an analysis engine.
- The convergence is a migration cost: `plsql-mcp` must drop its own copies and
  depend on the shared crates, and the CI boundary must keep the engine out of
  the core.
- Changes to the shared crates must consider both consumers, so the core's API
  is governed more conservatively than a single-consumer library would be.

## Review trigger

Revisit if the two binaries' needs **diverge** enough that a shared abstraction
forces awkward compromises on one side, if the engine-free boundary is breached
(CI catches a PL/SQL-engine import creeping into a core crate), or if `plsql-mcp`
has not in fact converged onto `oraclemcp-db` by its next release — at which
point either complete the convergence or formally split the foundations.
