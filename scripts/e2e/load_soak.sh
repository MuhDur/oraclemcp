#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="load_soak"
E2E_LANE="live-db-load"
E2E_PROFILE="live-xe"
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
      echo "Run the opt-in live Oracle load/soak e2e suite."
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "load_soak: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "live Oracle load/soak safety gate"
e2e_require_live_oracle_env
if ! e2e_run_command "act" cargo test -p oraclemcp-db --test load_soak live_xe_load_soak_pool_accounting_and_latency -- --ignored --nocapture; then
  e2e_finish_fail "live Oracle load/soak suite failed"
fi
e2e_log_event "scenario_assert" "assert" "pass" 0 "live Oracle load/soak suite completed"
e2e_finish_pass
