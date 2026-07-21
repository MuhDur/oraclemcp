#!/usr/bin/env bash
# Drift guard for the agent-facing CLI contract.
#
# Pins the top-level help footer, capabilities JSON contract, exit-code
# dictionary, and MCP/CLI/dashboard parity matrix through focused Rust tests.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() {
  cat <<'USAGE'
Validate the oraclemcp agent-ergonomics contract.

Usage:
  scripts/oraclemcp_ergonomics_lint.sh

Checks:
  - om/oraclemcp --help agent footer
  - oraclemcp --json capabilities schema keys
  - stable exit-code dictionary
  - MCP/CLI/dashboard parity matrix

Exit codes:
  0  contract is pinned and tests pass
  2  required local tool is missing or arguments are invalid
  1  cargo test reported a contract failure
USAGE
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi
if [ "$#" -ne 0 ]; then
  echo "oraclemcp-ergonomics-lint: unknown argument: $1" >&2
  usage >&2
  exit 2
fi

command -v cargo >/dev/null 2>&1 || {
  echo "oraclemcp-ergonomics-lint: missing required command: cargo" >&2
  exit 2
}

echo "oraclemcp-ergonomics-lint: cargo test -p oraclemcp agent_ergonomics_drift_guard"
# `cargo test <filter>` exits 0 when the filter matches NOTHING — libtest prints
# "test result: ok. 0 passed" and reports success. Trusting the exit status alone
# meant this gate would keep passing, in CI, while asserting nothing about the
# agent-facing CLI contract the moment either drift-guard test was renamed.
# Deliberately inlined rather than sourced from scripts/e2e/lib.sh: this lint has
# its own documented exit codes and no e2e-harness dependency.
# `set -e` aborts at a failing assignment, so capture inside an `if` — otherwise
# a failing cargo run kills the script before its own output is ever printed.
if ! ergonomics_output="$(cargo test -p oraclemcp agent_ergonomics_drift_guard 2>&1)"; then
  printf '%s\n' "$ergonomics_output"
  echo "oraclemcp-ergonomics-lint: cargo test reported a contract failure" >&2
  exit 1
fi
printf '%s\n' "$ergonomics_output"
ergonomics_ran="$(printf '%s\n' "$ergonomics_output" \
  | sed -n 's/^test result: [a-zA-Z]*\. \([0-9][0-9]*\) passed.*/\1/p' \
  | awk '{total += $1} END {print total + 0}')"
if [ "$ergonomics_ran" -lt 2 ]; then
  echo "oraclemcp-ergonomics-lint: the agent_ergonomics_drift_guard filter matched ${ergonomics_ran} test(s), expected at least 2; the CLI contract is NOT pinned (renamed or deleted test?)" >&2
  exit 1
fi
echo "oraclemcp-ergonomics-lint: OK - agent-facing CLI contract is pinned (${ergonomics_ran} drift-guard tests ran)."
