# ADR 0002 — Driver-adapter seam isolates backend churn

## Status

Accepted (0.4.0; bead B2).

## Context

The Cx-native thin driver is pre-1.0 and its API moves between releases. If
driver calls were scattered across the codebase, every driver bump would touch
many files and risk subtle behavior drift in the parts of the system that must
stay correct (NLS-stable serialization, NUMBER→string fidelity, LOB/REF CURSOR
materialization, cancellation/rollback semantics). Oracle also intends to
publish its own Rust driver, which may have a different runtime and capability
model. That must not leak into policy or create implicit cross-driver retry.

## Decision

Isolate all network/session driver calls behind the `OracleConnection` adapter
seam in `crates/oraclemcp-db/src/connection.rs`. The rest of the workspace
depends on oraclemcp's own types and the `oraclemcp-db` surface, never on a
driver directly. The dependency DAG is one-way and the seam is the only place
that imports a connection implementation.

The retained `oraclemcp-driver-cx` backend is the default: pure-Rust thin mode,
Asupersync `Cx` deadlines, and structured cancellation without Tokio. Oracle's
driver may become a second backend only after its API, runtime, licensing, and
failure semantics are qualified. Backend selection is explicit in build and
configuration state. A failed operation is never retried through another
backend, and there is no automatic fallback between drivers.

Each physical connection belongs to one backend for its entire lifetime. The
adapter maps backend errors and capabilities into shared oraclemcp types. A
timeout or cancellation must either prove the session reusable or discard or
quarantine it; an uncertain session is never returned to a pool. Transaction
cleanup remains rollback-by-default. If Oracle's backend requires Tokio, it
uses one bounded, long-lived runtime boundary rather than creating or blocking
on a runtime per operation.

The fail-closed classifier, operating-level ceiling, protected-profile clamp,
OAuth scope reduction, confirmation/TTL elevation, rollback default, and audit
chain remain above every backend and cannot be weakened by backend capability
differences. Unsupported capabilities return an explicit typed result; they do
not trigger a policy bypass or a cross-driver fallback.

The direct sans-I/O protocol utilities are narrower exceptions, not connection
backends: wallet inspection in `oraclemcp-core/src/doctor.rs`, wallet handling
at the connection seam, and TNS parsing in `oraclemcp-db/src/tns.rs` use the
protocol crate pinned with driver-cx. These paths parse local configuration and
fixtures; they do not own sessions or dispatch SQL.

## Consequences

- A connection-driver upgrade is localized to the adapter plus its tests and
  dependency/provenance surfaces, not the policy or tool layers.
- The serializer, classifier, and tool layer are insulated from driver API
  drift; their correctness tests do not depend on the driver version.
- New driver features (e.g. a complete IAM token source/refresh flow) are added
  at the seam, keeping the rest of the code stable.
- Operators can see and choose a qualified backend; failures remain attributable
  to that backend because execution never silently crosses implementations.
- There is a small indirection cost: driver capabilities are exposed to the rest
  of the system only through the adapter's surface, so genuinely new
  capabilities require a deliberate seam extension.

## Review trigger

Revisit if connection-driver calls begin appearing outside
`oraclemcp-db/src/connection.rs`, if a backend type reaches policy/tool layers,
if runtime management appears per operation, or if any retry can cross backend
boundaries. Extending the explicit wallet/TNS parser inventory requires an ADR
update and a dependency-boundary test.

## Addendum (B5) — Public-API lock on the shared surface

The seam keeps driver churn *in*; a complementary gate keeps the published
canonical foundation stable (`oraclemcp-db`, plus its public
`oraclemcp-error` / `oraclemcp-guard` dependencies). An unintended breaking
change to that surface must be caught before release. ADR-0006's separate
`plsql-mcp` convergence story is superseded: the server's supported optional
engine is embedded through `plsql-intelligence`.

**Decision.** Adopt two API-lock tools (mirroring driver-cx's own ADR-0002):

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

**Locked crates.** The canonical foundation (`oraclemcp-db`) and its public
dependencies (`oraclemcp-error`, `oraclemcp-guard`) are snapshot-locked. The
binary-facing aggregation crate `oraclemcp-core` is deliberately **not** locked
— it is an internal consumer, not a shared product API. The accepted dependency
on `oraclemcp-error` is part of the locked `oraclemcp-db` surface (re-exported
as `error_envelope`; `ErrorEnvelope` appears in return positions), not
pretended away.

**Baseline-refresh procedure.** See `crates/oraclemcp-db/README.md` and the
header of `scripts/oraclemcp_api_lock.sh`:
`cargo public-api -p <crate> > crates/<crate>/api/<crate>.txt` under the pinned
nightly.

**Review trigger (addendum).** Revisit the locked-crate set if another public
crate joins the canonical foundation, or if `cargo public-api` /
`cargo semver-checks` rustdoc-JSON output stops being stable under a re-pinned
nightly (regenerate the baselines as part of the re-pin).
