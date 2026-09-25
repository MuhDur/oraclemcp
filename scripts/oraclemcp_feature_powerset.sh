#!/usr/bin/env bash
# Curated feature-powerset gate: a COMPILE + LINT gate, not a test gate.
#
# Scope: only the three crates that actually define optional features
#   - oraclemcp        (default plsql-intelligence, dashboard-bundle, mimalloc, live-xe)
#   - oraclemcp-core   (dashboard-bundle)
#   - oraclemcp-db     (live-xe, test-utils)
# `--workspace` re-iterated every featureless crate under every combination for
# no added coverage. `cargo clippy` already type-checks + compiles, so the prior
# separate `cargo hack check` and `cargo hack test` passes were redundant here:
# runtime behaviour is covered by the default `cargo test` job (which explicitly
# adds the dashboard-bundle and dashboard-bundle,mimalloc interactions).
#
# Excluded deliberately:
#   - live-xe: requires external Oracle credentials, covered by live gates
#   - plsql-intelligence/default: the default engine-enabled build and its full
#     tests run in the required `plsql-intelligence` CI job. This powerset keeps
#     its compile matrix bounded and covers the remaining optional combinations.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "oraclemcp-feature-powerset: missing required command: $1" >&2
    exit 2
  }
}

need cargo
need cargo-hack

# Powerset fanout is a heavy build by definition: it must hold the machine-wide
# build lease (scripts/build_lease.sh) on a shared dev box, and must never run
# against a shared or RAM-backed target dir. CI runners are waived inside.
"$ROOT/scripts/check_build_lease.sh" --require-lease

common=(
  -p oraclemcp-db
  -p oraclemcp-core
  -p oraclemcp
  --feature-powerset
  --exclude-features
  live-xe,plsql-intelligence,default
  --all-targets
)

# clippy compiles + type-checks every target under every feature combination,
# so a single clippy pass subsumes the old `cargo hack check`. Runtime behaviour
# is covered by the default `cargo test` job, not re-run per combo here.
echo "oraclemcp-feature-powerset: cargo hack clippy"
cargo hack clippy "${common[@]}" -- -D warnings

echo "oraclemcp-feature-powerset: OK — curated feature powerset is green."
