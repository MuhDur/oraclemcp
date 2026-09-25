#!/usr/bin/env bash
# Validate the default PL/SQL-intelligence distribution from the binary.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EXPECTED_TOOLS=(
  oracle_lineage
  oracle_plsql_analyze
  oracle_plsql_blast_radius
  oracle_plsql_doc
  oracle_plsql_lineage
  oracle_plsql_live_snapshot
  oracle_plsql_parse
  oracle_plsql_sast
  oracle_plsql_what_breaks
)
expected="$(printf '%s\n' "${EXPECTED_TOOLS[@]}" | jq -R . | jq -s 'sort')"
CARGO="${CARGO:-cargo}"

echo "plsql-feature-lane: building oraclemcp with default features"
$CARGO build -p oraclemcp

target_dir="${CARGO_TARGET_DIR:-target}"
bin="$target_dir/debug/oraclemcp"
if [ ! -x "$bin" ]; then
  echo "plsql-feature-lane: FAIL — built binary not found at $bin" >&2
  exit 1
fi

info="$("$bin" --json info)"
check_info() {
  jq -e --argjson expected "$expected" '
    .engine == true
    and ([.tools[] | select(. as $tool | $expected | index($tool))] | sort) == $expected
  ' >/dev/null
}

if ! printf '%s' "$info" | check_info; then
  echo "plsql-feature-lane: FAIL — engine flag or complete PL/SQL tool registry did not match" >&2
  echo "  engine    = $(printf '%s' "$info" | jq -c '.engine')" >&2
  echo "  advertised= $(printf '%s' "$info" | jq -c '.tools | sort')" >&2
  echo "  expected  = $expected" >&2
  exit 1
fi

if [ "${1:-}" = "--selftest" ]; then
  mutated="$(printf '%s' "$info" | jq 'del(.tools[] | select(. == "oracle_lineage"))')"
  if printf '%s' "$mutated" | check_info; then
    echo "plsql-feature-lane: FAIL — missing oracle_lineage unexpectedly passed the negative case" >&2
    exit 1
  fi
  echo "plsql-feature-lane: selftest OK — missing oracle_lineage is refused"
  exit 0
fi

echo "plsql-feature-lane: OK — engine=true and all ${#EXPECTED_TOOLS[@]} PL/SQL tools registered"
