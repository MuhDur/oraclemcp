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
  scripts/e2e/doctor_fixtures.sh
  scripts/e2e/http_oauth_lanes.sh
  scripts/e2e/dashboard_readonly.sh
  scripts/e2e/audit_append.sh
  scripts/e2e/live_oracle.sh
  scripts/e2e/load_soak.sh
  scripts/e2e/live_xe_headline.sh
  scripts/e2e/COVERAGE.md
  scripts/e2e/PROVENANCE.md
  scripts/e2e/DISCREPANCIES.md
  tests/conformance/COVERAGE.md
  tests/conformance/DISCREPANCIES.md
  tests/golden/PROVENANCE.md
  scripts/ui_fixtures_validate_against_rust_schema.sh
  scripts/oraclemcp_arch_fitness_lint.sh
  scripts/oraclemcp_feature_powerset.sh
  scripts/oraclemcp_ergonomics_lint.sh
  scripts/release_acceptance_ci_suite.sh
  crates/oraclemcp-core/tests/concurrency_contract.rs
  crates/oraclemcp-core/tests/lane_state_machine.rs
  crates/oraclemcp-db/tests/multi_lane_live_xe.rs
  crates/oraclemcp/tests/live_xe_service_attach.rs
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
if ! grep -F "| Operator v1 | 9 | 0 | 9 | 9 | 0 | 100% |" tests/conformance/COVERAGE.md >/dev/null; then
  e2e_finish_fail "tests/conformance/COVERAGE.md must record 1.00 MUST coverage for operator v1"
fi
if ! grep -F "| WP-N concurrency/session | 11 | 0 | 11 | 11 | 0 | 100% |" tests/conformance/COVERAGE.md >/dev/null; then
  e2e_finish_fail "tests/conformance/COVERAGE.md must record 1.00 MUST coverage for WP-N"
fi
if ! grep -F "Total tracked requirements: 70 MUST, 2 SHOULD, 72 tested." tests/conformance/COVERAGE.md >/dev/null; then
  e2e_finish_fail "tests/conformance/COVERAGE.md totals are stale"
fi
if ! grep -F "| JSON-RPC errors | 3 | 2 | 5 | 5 | 1 | 100% |" tests/conformance/COVERAGE.md >/dev/null; then
  e2e_finish_fail "accepted JSON-RPC divergences must be XFAIL-accounted while preserving 100% coverage"
fi
if grep -RInE '(^|[^A-Z])SKIP([^A-Z]|$)' scripts/e2e/COVERAGE.md scripts/e2e/DISCREPANCIES.md tests/conformance/COVERAGE.md tests/conformance/DISCREPANCIES.md >/dev/null; then
  e2e_finish_fail "coverage/discrepancy docs must use XFAIL terminology, not SKIP"
fi
if ! grep -F "No accepted divergences." scripts/e2e/DISCREPANCIES.md >/dev/null; then
  e2e_finish_fail "DISCREPANCIES.md must explicitly state current divergence posture"
fi
if ! grep -F "XFAIL-ACCEPTED" tests/conformance/DISCREPANCIES.md >/dev/null; then
  e2e_finish_fail "tests/conformance/DISCREPANCIES.md must label intentional divergences as XFAIL-ACCEPTED"
fi
if ! grep -F "UPDATE_GOLDENS=1 cargo test -p oraclemcp-core --test golden_behavior" tests/golden/PROVENANCE.md >/dev/null; then
  e2e_finish_fail "golden provenance must document the core HTTP golden rebless command"
fi
if ! grep -F "UPDATE_GOLDENS=1 cargo test -p oraclemcp --test golden_behavior" tests/golden/PROVENANCE.md >/dev/null; then
  e2e_finish_fail "golden provenance must document the binary stdio golden rebless command"
fi
if ! grep -F "UPDATE_GOLDENS=1 cargo test -p oraclemcp-db --test structured_schema_golden" tests/golden/PROVENANCE.md >/dev/null; then
  e2e_finish_fail "golden provenance must document the structured schema golden rebless command"
fi
if ! grep -F "Agent ergonomics drift guard" scripts/e2e/COVERAGE.md >/dev/null; then
  e2e_finish_fail "COVERAGE.md must account for the ERG-10 drift guard"
fi
if ! grep -F "scripts/oraclemcp_ergonomics_lint.sh" scripts/e2e/PROVENANCE.md >/dev/null; then
  e2e_finish_fail "PROVENANCE.md must document the ERG-10 drift guard command"
fi
if ! grep -F "Release acceptance CI suite" scripts/e2e/COVERAGE.md >/dev/null; then
  e2e_finish_fail "COVERAGE.md must account for the HCI release acceptance suite"
fi
if ! grep -F "scripts/release_acceptance_ci_suite.sh" scripts/e2e/PROVENANCE.md >/dev/null; then
  e2e_finish_fail "PROVENANCE.md must document the HCI release acceptance suite command"
fi
if ! grep -F "G6 live-XE headline" scripts/e2e/COVERAGE.md >/dev/null; then
  e2e_finish_fail "COVERAGE.md must account for the G6 live-XE headline suite"
fi
if ! grep -F "scripts/e2e/live_xe_headline.sh" scripts/e2e/PROVENANCE.md >/dev/null; then
  e2e_finish_fail "PROVENANCE.md must document the G6 live-XE headline command"
fi

e2e_log_event "coverage_summary" "assert" "pass" 0 "MUST coverage 6/6 score=1.00 xfail=0"
e2e_finish_pass
