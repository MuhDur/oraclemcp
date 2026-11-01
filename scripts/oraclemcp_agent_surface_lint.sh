#!/usr/bin/env bash
# Agent-facing surface lint (R3 / B.4).
#
# `call_routine` is adapter-internal routine plumbing in oraclemcp-db. It must
# never appear in the binary-facing or MCP-core surfaces that build tools/list,
# capabilities, CLI commands, resources, or operator endpoints.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SURFACE_PATHS=(
  crates/oraclemcp/Cargo.toml
  crates/oraclemcp/src
  crates/oraclemcp-core/Cargo.toml
  crates/oraclemcp-core/src
)

mapfile -t FILES < <(
  git ls-files "${SURFACE_PATHS[@]}" |
    grep -E '\.(rs|toml)$' |
    grep -vE '/tests?/|tests\.rs$'
)

# Temporary exception, mirroring tests/honesty_grep.rs: exactly one
# `.call_routine(` inside the module-level `async fn run_package_wire(` of the
# signed-plan runner, up to its column-zero closing brace. oraclemcp-wbbn6
# moves verification into the adapter and removes this exception.
RUNNER_FILE=crates/oraclemcp/src/dispatch/custom_tool.rs
runner_range() {
  awk '/^async fn run_package_wire\(/ { if (s) { print "DUP"; exit } s = NR }
       s && !e && /^}$/ { e = NR }
       END { if (s && e) print s, e }' "$RUNNER_FILE"
}

violations=0
allowed=0
read -r runner_start runner_end < <(runner_range || true) || true
if [ "${runner_start:-}" = "DUP" ]; then
  echo "FORBIDDEN agent routine surface  $RUNNER_FILE: more than one run_package_wire definition"
  violations=$((violations + 1))
  runner_start=""
fi
for f in "${FILES[@]}"; do
  [ -n "$f" ] || continue
  while IFS=: read -r line text; do
    if [ "$f" = "$RUNNER_FILE" ] && [ -n "${runner_start:-}" ] &&
      [ "$line" -gt "$runner_start" ] && [ "$line" -lt "$runner_end" ] &&
      [ "$(grep -o 'call_routine' <<<"$text" | wc -l)" -eq 1 ] &&
      [[ "$text" == *".call_routine("* ]]; then
      allowed=$((allowed + 1))
      continue
    fi
    printf 'FORBIDDEN agent routine surface  %s:%s:%s\n' \
      "$f" "$line" "${text#"${text%%[![:space:]]*}"}"
    violations=$((violations + 1))
  done < <(grep -nF 'call_routine' "$f" 2>/dev/null || true)
done
if [ "$allowed" -ne 1 ]; then
  echo "FORBIDDEN agent routine surface  $RUNNER_FILE: expected exactly one signed-plan runner call_routine, found $allowed (oraclemcp-wbbn6 removes this exception)"
  violations=$((violations + 1))
fi

if [ "$violations" -gt 0 ]; then
  echo "oraclemcp-agent-surface-lint: FAIL — call_routine reached an agent-facing surface."
  echo "Keep routine execution adapter-internal in oraclemcp-db; do not add an arbitrary routine MCP tool."
  exit 1
fi

echo "oraclemcp-agent-surface-lint: OK — call_routine only at the bounded signed-plan runner (until oraclemcp-wbbn6)."
