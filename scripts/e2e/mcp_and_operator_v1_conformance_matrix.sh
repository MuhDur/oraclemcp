#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="mcp_and_operator_v1_conformance_matrix"
E2E_LANE="operator-v1"
E2E_PROFILE="offline"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

for arg in "$@"; do
  set +e
  e2e_parse_common_arg "$arg"
  parsed=$?
  set -e
  case "$parsed" in
    0) continue ;;
    3)
      echo "Validate B.6 MCP + operator v1 conformance accounting and schema fixtures."
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "mcp_and_operator_v1_conformance_matrix: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "B.6 MCP + operator v1 conformance"

required=(
  tests/conformance/COVERAGE.md
  schemas/operator.schema.json
  ui/generated/operator-v1.ts
  scripts/ui_fixtures_validate_against_rust_schema.sh
  tests/fixtures/ui/operator-v1/route-index.json
  tests/fixtures/ui/operator-v1/event-snapshot.json
)
missing=0
for path in "${required[@]}"; do
  if [ ! -f "$path" ]; then
    echo "missing required B.6 file: $path" >&2
    missing=$((missing + 1))
  fi
done
if [ "$missing" -ne 0 ]; then
  e2e_finish_fail "$missing required B.6 file(s) missing"
fi

if ! grep -F "| Operator v1 | 8 | 0 | 8 | 8 | 0 | 100% |" tests/conformance/COVERAGE.md >/dev/null; then
  e2e_finish_fail "Operator v1 MUST coverage must be 8/8 score=1.00"
fi
if ! grep -F "| HTTP negotiation | 2 | 0 | 2 | 2 | 0 | 100% |" tests/conformance/COVERAGE.md >/dev/null; then
  e2e_finish_fail "HTTP negotiation coverage must include MCP-Protocol-Version"
fi
if ! grep -F "Total tracked requirements: 49 MUST, 2 SHOULD, 51 tested." tests/conformance/COVERAGE.md >/dev/null; then
  e2e_finish_fail "B.6 coverage totals are stale"
fi
if grep -RInE '(^|[^A-Z])SKIP([^A-Z]|$)' tests/conformance/COVERAGE.md >/dev/null; then
  e2e_finish_fail "B.6 conformance docs must use XFAIL terminology, not SKIP"
fi

e2e_run_command "assert" scripts/ui_fixtures_validate_against_rust_schema.sh
e2e_run_command "assert" env CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/target/tmp" \
  cargo test -p oraclemcp-core --lib mcp_protocol_version_header_is_enforced_before_dispatch

e2e_log_event "coverage_summary" "assert" "pass" 0 "B.6 MUST coverage 49/49 score=1.00"
e2e_finish_pass
