#!/usr/bin/env bash
# Curated feature-powerset gate: a COMPILE + LINT gate, not a test gate.
#
# Scope: only the three crates that actually define optional features
#   - oraclemcp        (dashboard-bundle, mimalloc, live-xe, plsql-intelligence)
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
#   - plsql-intelligence: optional engine variant, built by distribution jobs
#   - default: currently empty for these crates; excluding it avoids redundant
#     with/without-default combinations. Re-add it here if `default` ever gains
#     members.
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
