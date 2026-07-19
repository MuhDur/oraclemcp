# Test-organization tiers

`oraclemcp` runs many kinds of checks — a `cargo test` on every push, a nightly
mutation sweep, a dispatch-only real-OCI signoff — with different costs and
different jobs. This document is the **manifest**: which real lane runs when,
what it proves, and which of four cost/latency tiers it belongs to. It exists
because a tier assignment stated only in prose drifts from the workflow YAML
that actually runs; this doc is reconciled against the tracked CI config
(`.github/workflows/*.yml`, `docs/ci_taxonomy.json`) as of this writing, and
says so explicitly where the two disagree (§4).

Source: `docs/plan/PLAN_ENGINEERING_PROGRAM.md` §30.6 ("Local vs CI vs nightly
vs live — the testing organization"), written in response to §30.5's
self-fulfilling-fixture class (see `scripts/oraclemcp_fixture_lint.sh` and its
header comment for that half of the same hardening pass).

## 1. Two orthogonal axes — do not conflate them

- **Tier (this doc)** — *when* a lane runs and how expensive it is: Tier 0
  (local, seconds) through Tier 3 (live/real-cloud, deliberate dispatch).
  Cost-and-latency staging.
- **required / advisory / release / scheduled / manual (`docs/ci-taxonomy.md`,
  `scripts/ci_taxonomy.py`)** — *whether a red result blocks anything*, derived
  mechanically from each job's trigger and `continue-on-error`. Blocking-ness.

A lane's tier does not determine its blocking-ness and vice versa: the live
version-matrix is a Tier 2 **producer** of exact-SHA evidence that a Tier 3
release-qualification step then hard-**consumes** (plan §30.6's
producer/consumer nuance) — advisory-as-a-lane and hard-gate-at-release are two
roles of the same artifact, not a contradiction. The table in §3 gives both
columns per lane so neither axis has to be inferred from the other.

## 2. The four tiers

**Tier 0 — Local pre-push (seconds → ~2 min).** `fmt` + `clippy` +
`cargo test -p <touched-crate>` (scoped) + the fast static lints. No live DB,
no fuzz, no coverage measurement. This is where an agent or developer catches
a mistake before it costs a CI round trip.

**Tier 1 — Required CI (per-PR, target <15 min).** The full offline suite:
workspace `cargo test`, golden/conformance suites, feature-powerset,
architecture/honesty/seam lints, `cargo deny`, the API/semver locks. Must be
green to merge.

**Tier 2 — Nightly / scheduled (advisory-but-watched, no per-PR cost).** The
heavy and the slow: mutation testing, fuzz campaigns, a full live-version
matrix, coverage baselines. Chronically-red scheduled lanes go explicitly
advisory with an auto-reblocking rule once they recover (plan §27.6 item 4).

**Tier 3 — Live / real-cloud (deliberate dispatch, never per-PR).** Real
provisioning or a release gate: the OCI Always-Free ADB e2e (agent-runnable
within its cost guardrails — provably $0, no per-run approval needed), the
release rehearsal, and exact-SHA release-qualification (operator-authorized;
gates a tag push, not a merge).

## 3. Manifest — real lanes mapped to tiers

| Lane | Where it runs | Trigger | Tier | `ci_taxonomy` class |
|---|---|---|---|---|
| `cargo fmt --all -- --check` | local / `ci.yml:fmt` | pre-push, every push+PR | 0 → 1 | required |
| `cargo clippy --workspace --all-targets -- -D warnings` | local / `ci.yml:clippy` | pre-push, every push+PR | 0 → 1 | required |
| `cargo test --workspace` (no `live-xe`) | local / `ci.yml:test` | pre-push, every push+PR | 0 → 1 | required |
| `scripts/verify_required_local.py`, `scripts/local_release_gate_check.sh` | local | on demand, mirrors `_quality.yml`'s Required graph | 0 | n/a (local proof, not a CI job) |
| `scripts/oraclemcp_fixture_lint.sh` (H7, this pass) | local / not yet wired into CI | on demand | 0 | n/a — **recommended for the `boundary` job (Tier 1)**, not added by this pass; see §5 |
| `scripts/oraclemcp_concurrency_lint.sh`, `_boundary_lint.sh`, `_arch_fitness_lint.sh`, `_agent_surface_lint.sh`, `_driver_seam_lint.sh`, `oraclemcp_honesty_grep.sh` | local / `ci.yml:boundary` | pre-push + every push+PR | 0 → 1 | required |
| `scripts/gen_coverage_report.sh --check` (conformance **clause** coverage, MUST/SHOULD vs `tests/conformance/clauses.tsv` — *not* code coverage) | `ci.yml:boundary` | every push+PR | 1 | required |
| feature-powerset (`cargo hack`) | `ci.yml:feature-powerset` | every push+PR | 1 | required |
| `cargo deny check` (supply-chain) | local / `ci.yml:supply-chain` | pre-push + every push+PR | 0 → 1 | required |
| public-API lock (`cargo public-api` + `cargo semver-checks`) | `ci.yml:api-lock` | every push+PR | 1 | required |
| installer lint + built-artifact smoke, Windows installer/Rust | `ci.yml:installer`, `windows-installer`, `windows-rust` | every push+PR | 1 | required |
| PL/SQL intelligence feature matrix, thin-driver build | `ci.yml:plsql-intelligence`, `thin-db` | every push+PR | 1 | required |
| `sensitive-data` / `secret_scan.sh` structural + denylist scan | `ci.yml:sensitive-data` | every push+PR | 1 | required |
| BMC formal proofs (Kani/CBMC) over guard + audit | `kani-safety.yml:kani-safety` | every push+PR (no schedule despite the filename) | 1 | required |
| release-acceptance suite (B.12) | `ci.yml:release-acceptance` **and** `release.yml:release-acceptance` | every push+PR, **and again** at tag push | 1 and 3 | required (PR copy) / release (tag copy) |
| `mutation-safety.yml` — `cargo-mutants` over guard + audit | `mutation-safety.yml` | cron `17 2 * * *` (nightly) | 2 | scheduled |
| `multi-nightly` floating-toolchain early warning | `ci.yml:multi-nightly` | every push+PR (not a schedule — see §4.3) | 1-shaped but advisory | advisory |
| fuzz targets **compile** check (`oraclemcp-guard`'s 2 targets — `alter_session_parse`, `classify_fuzz`; `cargo fuzz build`) | `ci.yml:fuzz-build` | every push+PR | 1-shaped but advisory | advisory |
| fuzz targets **run** (actual corpus execution) | none automated — `cargo +nightly-2026-05-11 fuzz run <target>` locally only | manual | — (gap; see §4.4) | n/a |
| gvenzl 23ai matrix + VECTOR smoke (real live DB) | `ci.yml:oracle-free23` (`scripts/e2e/oracle_version_matrix.sh --log --lane free23`) | every push+PR | 1 (should be 2; see §4.1) | required |
| gvenzl full ladder (XE 18 / XE 21 / FREE 23ai) | `scripts/e2e/oracle_version_matrix.sh --log` | operator/agent-run, no schedule | 2-shaped, executed as 3 | manual |
| code-coverage baseline / ratchet (`cargo llvm-cov`) | not implemented | — | 1 (ratchet) / 2 (baseline) — **not built yet** | n/a (gap; see §4.5) |
| loom model-checks | not implemented — no `loom` dependency in the workspace | — | 2 — **not built yet** | n/a (gap; see §4.6) |
| `scripts/e2e/oci_adb_terraform.sh`, `real_adb_tcps_signoff.sh`, `oci_adb_iam_bootstrap/` (real OCI Always-Free ADB) | `oci-adb.yml:acceptance` | `workflow_dispatch` only | 3 | manual |
| `scripts/local_release_gate.sh` (D3.2: synthetic TCPS proof, optional real-ADB delegation) | local, pre-tag | on demand before a release tag | 3 | n/a (local, not a CI job) |
| full release pipeline (cross-platform build, sign, publish crates.io/GHCR/MCP registry) | `release.yml` | push tag `v*` | 3 | release |
| `docker.yml`, `publish-mcp.yml`, `publish-npm.yml` | manual recovery/repair auxiliaries (AGENTS.md "Release flow") | `workflow_dispatch` only | 3 | manual |

Live-Oracle Rust test suites (`crates/*/tests/live_*`, `oci_tcps_e2e.rs`) are
gated behind the `live-xe` Cargo feature **and** a runtime reachability probe:
`cargo test --workspace` (Tier 0/1, no feature flags) never compiles or runs
them, so the required per-PR gate stays live-DB-free by construction except
for `oracle-free23`'s own dedicated container (§4.1). Reaching them requires
`--features live-xe` plus a target DSN — that is what `scripts/e2e/*.sh`
(owned separately from this doc; see AGENTS.md) orchestrates for Tier 2/3 runs.

## 4. Known reality-vs-manifest gaps (honest accounting)

Per plan §30.6's own "reality-reconciliation" note, the four-tier model is
**not** yet how the repo fully runs. Restating it as fully realized would be
exactly the stale-CONFIRMED failure mode the retro (§27.6, V5/V12) exists to
prevent. As of this writing:

1. **`oracle-free23` is a real live database wired as a required per-PR gate**
   (Tier 1), not the Tier 2 nightly producer + lightweight Tier 1 smoke the
   model calls for. It is the single biggest tier/reality gap in the table
   above and the one plan §30.6 names explicitly. Not fixed by this pass — CI
   workflow restructuring is out of scope for H4/H7 (test-integrity hardening
   only); tracked as follow-up work, not silently dropped.
2. **`multi-nightly` and `fuzz-build` are named "nightly" but trigger on every
   push/PR**, not on a schedule; they earn their advisory status from
   `continue-on-error`, not from running off the per-PR path. The floating
   Rust nightly and the fuzz-compile check both execute every time, they just
   never fail the merge.
3. **No automated fuzz-campaign lane exists.** `fuzz-build` only proves
   `oraclemcp-guard`'s 2 current targets still *compile*; running them against
   a corpus (`cargo fuzz run <target>`) is a local-only, manual action today.
   Plan §30.6 describes a Tier 2 aspiration of "22 protocol targets + the new
   guard/config/sql targets" — the target count itself is aspirational too,
   not just the scheduled-run lane; today there are 2, both in
   `oraclemcp-guard`.
4. **No code-coverage measurement exists at all** (`cargo llvm-cov` or
   equivalent) — confirmed by grep across `scripts/*.sh`, `scripts/*.py`, and
   `.github/workflows/*.yml`. `scripts/gen_coverage_report.sh` is a different,
   already-real thing: **conformance clause coverage** (MUST/SHOULD vs
   `tests/conformance/clauses.tsv`), wired into the required `boundary` job.
   Do not conflate the two when reading this doc or the plan: "coverage
   ratchet" (Tier 1) and "coverage baseline" (Tier 2) in plan §30.6 both refer
   to *code* coverage and remain unbuilt.
5. **No loom model-checking exists** — no `loom` dependency appears anywhere
   in the workspace. The plan's Tier 2 loom line item is aspirational.
6. **`.github/workflows/_quality.yml`'s "Live matrix" step references a
   nonexistent script.** Line 24 runs `bash scripts/version_matrix.sh full
   all`; no such file exists (`scripts/version_matrix.sh` is not in the repo).
   The real live-matrix entry point is `scripts/e2e/oracle_version_matrix.sh
   --log --lane <name>`, a different path and a different argument
   convention. This step only executes when a caller passes
   `profile: release-qualification` to the reusable workflow, so the dead
   reference has never actually run in CI and nothing has caught it — a live
   instance of exactly the "aspirational text vs. reality" pattern this whole
   hardening pass targets. **Not fixed by this doc** (`_quality.yml` is CI
   wiring, outside this pass's file scope); flagged here so it is not
   silently rediscovered later.
7. **The full 3-version gvenzl ladder (XE 18 / XE 21 / FREE 23ai,
   `scripts/e2e/oracle_version_matrix.sh --log`) is operator/agent-run, not on
   any schedule** (`docs/release-checklist.md`, `docs/operations.md` both
   describe it as a "lab lane"). Only the 23ai slice is automated, and that
   slice runs at Tier 1 (§4.1), not Tier 2. The plan's Tier 2
   producer / Tier 3 consumer split for the live matrix is not yet automated
   end-to-end.
8. **Several required (Tier 1) jobs are budgeted well past the "<15 min"
   target**: `kani-safety` and `oracle-free23` both carry 45-minute timeouts.
   A timeout is a ceiling, not an observed duration — confirming actual
   wall-clock latency needs `gh run list`/`gh run view` against recent runs,
   which this pass did not do. Flagged as a thing to check before treating
   "Tier 1 is <15 min" as true today.

None of the above are fixed by this pass. H4/H7 is test-**integrity**
hardening (value-blind assertions, self-fulfilling fixtures, and this
manifest); CI retiming/rewiring is separate work already named in plan §25/§27
and is out of scope for the files this pass touches.

## 5. What this pass (H7) added

- **`scripts/oraclemcp_fixture_lint.sh`** — the no-self-fulfilling-fixture
  static lint (plan §30.5). Run it locally (Tier 0):
  ```bash
  bash scripts/oraclemcp_fixture_lint.sh            # scan the tracked tree
  bash scripts/oraclemcp_fixture_lint.sh --self-test # prove it actually trips
  ```
  It is not yet wired into any CI job. The natural home is the `boundary` job
  in `ci.yml` (Tier 1, required) alongside the other static lints listed in
  §3 — adding that step is a one-line CI change left for a follow-up, since
  editing `.github/workflows/*.yml` is outside this pass's file scope.
- **This document.**

Both are process controls in the same family as `tests/golden/PROVENANCE.md`'s
"fixture changes are protocol behavior changes; read the diff before
re-approving" rule — a human (or reviewing agent) reading a regenerated golden
diff is still the backstop the static lint cannot replace; see the lint
script's own header comment for exactly what it does and does not prove.
