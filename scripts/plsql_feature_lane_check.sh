#!/usr/bin/env bash
# Arc K1 — the PL/SQL-intelligence feature lane, runnable offline.
#
# The optional `plsql-intelligence` distribution pulls the published PL/SQL
# engine crates and advertises the eight offline `oracle_plsql_*` tools. This
# script is the single source of truth for that lane: it builds the binary with
# the feature and then proves the advertised tool surface from the binary's own
# `--json info`, rather than merely compiling the optional dependency graph.
#
# CI (.github/workflows/ci.yml `plsql-intelligence` job) calls this after the
# `cargo test --workspace --features plsql-intelligence` run, so the assertion
# has one home an agent can also run locally:
#
#   bash scripts/plsql_feature_lane_check.sh
#
# It uses no database and no network beyond the crate build. It is engine-free
# by default: the feature is opt-in and this is the only path that turns it on.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# The exact tools the feature must advertise. Kept sorted; the binary's report
# is sorted before comparison so ordering never causes a false mismatch.
EXPECTED_TOOLS=(
  oracle_plsql_analyze
  oracle_plsql_blast_radius
  oracle_plsql_doc
  oracle_plsql_lineage
  oracle_plsql_live_snapshot
  oracle_plsql_parse
  oracle_plsql_sast
  oracle_plsql_what_breaks
)

# Allow CI/agents to substitute the cargo wrapper (e.g. the swarm's `omcpb`).
CARGO="${CARGO:-cargo}"

echo "plsql-feature-lane: building oraclemcp --features plsql-intelligence"
$CARGO build -p oraclemcp --features plsql-intelligence

# Locate the freshly built binary. CARGO_TARGET_DIR wins; otherwise the default.
target_dir="${CARGO_TARGET_DIR:-target}"
bin="$target_dir/debug/oraclemcp"
if [ ! -x "$bin" ]; then
  echo "plsql-feature-lane: FAIL — built binary not found at $bin" >&2
  exit 1
fi

echo "plsql-feature-lane: asserting the advertised tool surface from --json info"
info="$("$bin" --json info)"

# `engine` must be true under the feature, and the oracle_plsql_* set must be
# EXACTLY the eight tools — no missing tool, and no extra one that slipped in
# unreviewed. jq -e exits non-zero on a false result, which fails the script.
printf '%s' "$info" | jq -e --argjson expected "$(printf '%s\n' "${EXPECTED_TOOLS[@]}" | jq -R . | jq -s 'sort')" '
  .engine == true
  and ([.tools[] | select(startswith("oracle_plsql_"))] | sort) == $expected
' >/dev/null || {
  echo "plsql-feature-lane: FAIL — engine flag or oracle_plsql_* tool set did not match" >&2
  echo "  engine    = $(printf '%s' "$info" | jq -c '.engine')" >&2
  echo "  advertised= $(printf '%s' "$info" | jq -c '[.tools[] | select(startswith("oracle_plsql_"))] | sort')" >&2
  echo "  expected  = $(printf '%s\n' "${EXPECTED_TOOLS[@]}" | jq -R . | jq -sc 'sort')" >&2
  exit 1
}

echo "plsql-feature-lane: OK — engine=true and all ${#EXPECTED_TOOLS[@]} oracle_plsql_* tools registered"
