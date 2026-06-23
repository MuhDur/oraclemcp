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

## Addendum (B5) — Public-API lock on the shared surface

The seam keeps driver churn *in*; a complementary gate keeps the public surface
*stable* for the two consumers of the canonical foundation (ADR-0006:
`oraclemcp-db`, plus the engine-free spine `oraclemcp-error` / `oraclemcp-guard`
that `plsql-mcp` converges onto). An unintended breaking change to that surface
must be caught before it reaches `plsql-mcp`.

**Decision.** Adopt two API-lock tools (mirroring `oracledb`'s own ADR-0002):

- **`cargo public-api`** — renders the exact public API and diffs it against a
  committed baseline at `crates/<crate>/api/<crate>.txt`. This is the hard,
  deterministic, offline gate (`scripts/oraclemcp_api_lock.sh`). An intentional
  change is landed by refreshing the baseline in the same PR, so the surface
  delta is reviewable in the diff.
- **`cargo semver-checks`** — the SemVer *contract*: it compares the working
  tree against the last published release and fails when the diff is not allowed
  by the version bump. This catches a breaking change that a baseline refresh
  alone would silently bless.

Both render rustdoc JSON, so they run on the pinned nightly (ADR-0001). They are
installed as standalone CI binaries (`taiki-e/install-action`), **not** added to
the workspace dependency graph, so they do not affect `cargo deny`.

**Locked crates.** The published spine `plsql-mcp` consumes
(`oraclemcp-error`, `oraclemcp-guard`) and the canonical foundation
(`oraclemcp-db`). The binary-facing aggregation crate `oraclemcp-core` is
deliberately **not** locked — it is an internal consumer, not a shared product
API. The accepted spine dependency `oraclemcp-error` is part of the locked
`oraclemcp-db` surface (re-exported as `error_envelope`; `ErrorEnvelope` appears
in return positions), not pretended away.

**Baseline-refresh procedure.** See `crates/oraclemcp-db/README.md` and the
header of `scripts/oraclemcp_api_lock.sh`:
`cargo public-api -p <crate> > crates/<crate>/api/<crate>.txt` under the pinned
nightly.

**Review trigger (addendum).** Revisit the locked-crate set if `plsql-mcp`'s
convergence (ADR-0006) lands and a fourth shared crate joins the spine, or if
`cargo public-api` / `cargo semver-checks` rustdoc-JSON output stops being
stable under a re-pinned nightly (regenerate the baselines as part of the
re-pin).
