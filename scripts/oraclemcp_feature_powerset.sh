#!/usr/bin/env bash
# Curated feature-powerset gate for release CI.
#
# Current Cargo features that belong in the always-on PR matrix:
#   - default/no features
#   - dashboard-bundle (dashboard API is always compiled; the bundle feature
#     embeds the web/dist artifact that CI builds first)
#
# Excluded deliberately:
#   - live-xe: requires external Oracle credentials and is covered by live gates
#   - plsql-intelligence: optional engine variant, built by distribution jobs
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
  --workspace
  --feature-powerset
  --exclude-features
  live-xe,plsql-intelligence
  --all-targets
)

echo "oraclemcp-feature-powerset: cargo hack check"
cargo hack check "${common[@]}"

echo "oraclemcp-feature-powerset: cargo hack clippy"
cargo hack clippy "${common[@]}" -- -D warnings

echo "oraclemcp-feature-powerset: cargo hack test"
cargo hack test "${common[@]}"

echo "oraclemcp-feature-powerset: OK — curated feature powerset is green."
