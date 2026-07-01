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

violations=0
for f in "${FILES[@]}"; do
  [ -n "$f" ] || continue
  while IFS=: read -r line text; do
    printf 'FORBIDDEN agent routine surface  %s:%s:%s\n' \
      "$f" "$line" "${text#"${text%%[![:space:]]*}"}"
    violations=$((violations + 1))
  done < <(grep -nF 'call_routine' "$f" 2>/dev/null || true)
done

if [ "$violations" -gt 0 ]; then
  echo "oraclemcp-agent-surface-lint: FAIL — call_routine reached an agent-facing surface."
  echo "Keep routine execution adapter-internal in oraclemcp-db; do not add an arbitrary routine MCP tool."
  exit 1
fi

echo "oraclemcp-agent-surface-lint: OK — call_routine absent from agent-facing surfaces."
