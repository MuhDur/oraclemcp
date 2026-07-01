#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="conformance_coverage"
E2E_LANE="harness"
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
      echo "Validate the e2e harness conformance accounting files."
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "conformance_coverage: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "e2e harness conformance accounting"

required=(
  scripts/e2e/lib.sh
  scripts/e2e/run_all.sh
  scripts/e2e/offline_stdio.sh
  scripts/e2e/mcp_and_operator_v1_conformance_matrix.sh
  scripts/e2e/http_oauth_lanes.sh
  scripts/e2e/audit_append.sh
  scripts/e2e/live_oracle.sh
  scripts/e2e/load_soak.sh
  scripts/e2e/COVERAGE.md
  scripts/e2e/PROVENANCE.md
  scripts/e2e/DISCREPANCIES.md
  tests/conformance/COVERAGE.md
  scripts/ui_fixtures_validate_against_rust_schema.sh
)
missing=0
for path in "${required[@]}"; do
  if [ ! -f "$path" ]; then
    echo "missing required harness file: $path" >&2
    missing=$((missing + 1))
  fi
done
if [ "$missing" -ne 0 ]; then
  e2e_finish_fail "$missing required harness file(s) missing"
fi

if ! grep -F "| MUST coverage | 6 | 6 | 6 | 0 | 1.00 |" scripts/e2e/COVERAGE.md >/dev/null; then
  e2e_finish_fail "COVERAGE.md must record 1.00 MUST coverage for the harness standard"
fi
if ! grep -F "| Operator v1 | 8 | 0 | 8 | 8 | 0 | 100% |" tests/conformance/COVERAGE.md >/dev/null; then
  e2e_finish_fail "tests/conformance/COVERAGE.md must record 1.00 MUST coverage for operator v1"
fi
if grep -RInE '(^|[^A-Z])SKIP([^A-Z]|$)' scripts/e2e/COVERAGE.md scripts/e2e/DISCREPANCIES.md >/dev/null; then
  e2e_finish_fail "coverage/discrepancy docs must use XFAIL terminology, not SKIP"
fi
if ! grep -F "No accepted divergences." scripts/e2e/DISCREPANCIES.md >/dev/null; then
  e2e_finish_fail "DISCREPANCIES.md must explicitly state current divergence posture"
fi

e2e_log_event "coverage_summary" "assert" "pass" 0 "MUST coverage 6/6 score=1.00 xfail=0"
e2e_finish_pass
