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
cargo test -p oraclemcp agent_ergonomics_drift_guard
echo "oraclemcp-ergonomics-lint: OK - agent-facing CLI contract is pinned."
