# ADR 0002 — Driver-adapter seam isolates `oracledb` churn to one file

## Status

Accepted (0.4.0; bead B2).

## Context

The thin `oracledb` driver is pre-1.0 and its API moves between releases. If
driver calls were scattered across the codebase, every driver bump would touch
many files and risk subtle behavior drift in the parts of the system that must
stay correct (NLS-stable serialization, NUMBER→string fidelity, LOB/REF CURSOR
materialization, cancellation/rollback semantics).

## Decision

Isolate **all** `oracledb` driver calls behind a single adapter seam in
`crates/oraclemcp-db/connection.rs`. The rest of the workspace depends on
oraclemcp's own types and the `oraclemcp-db` surface, never on `oracledb`
directly. The dependency DAG is one-way and the seam is the only place that
imports the driver.

## Consequences

- A driver upgrade is a localized edit to one file plus its tests, not a
  workspace-wide change.
- The serializer, classifier, and tool layer are insulated from driver API
  drift; their correctness tests do not depend on the driver version.
- New driver features (e.g. a complete IAM token source/refresh flow) are added
  at the seam, keeping the rest of the code stable.
- There is a small indirection cost: driver capabilities are exposed to the rest
  of the system only through the adapter's surface, so genuinely new
  capabilities require a deliberate seam extension.

## Review trigger

Revisit if driver calls begin appearing **outside `oraclemcp-db/connection.rs`**
(grep for direct `oracledb::` use elsewhere), or if a driver upgrade requires
edits in more than that one file plus its tests — either signals the seam has
eroded and needs re-establishing.
