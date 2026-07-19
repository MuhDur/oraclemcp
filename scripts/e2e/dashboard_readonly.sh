#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="dashboard_readonly"
E2E_LANE="dashboard"
E2E_PROFILE="operator"
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
      echo "Run the 0.6.0 read-only dashboard acceptance gate."
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "dashboard_readonly: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "0.6.0 read-only dashboard acceptance gate"

if ! e2e_run_command "act" bash scripts/dashboard_skin_lint.sh; then
  e2e_finish_fail "dashboard skin boundary failed"
fi
if ! e2e_run_command "act" bash scripts/sensitive_data_lint.sh; then
  e2e_finish_fail "dashboard browser storage or sensitive-data lint failed"
fi
if ! e2e_run_command "act" bash scripts/dashboard_bundle_check.sh; then
  e2e_finish_fail "dashboard bundle reproducibility check failed"
fi
if ! e2e_run_command "act" npm --prefix web exec -- tsc -p web/tsconfig.json --noEmit; then
  e2e_finish_fail "dashboard TypeScript check failed"
fi
if ! e2e_run_command "act" npm --prefix web exec -- vite build web --outDir ../target/e2e-dashboard-readonly --emptyOutDir=false; then
  e2e_finish_fail "dashboard Vite build failed"
fi

e2e_log_event "scenario_assert" "assert" "pass" 0 "read-only views, browser auth, skin fallback, and bundle checks completed"
e2e_finish_pass
