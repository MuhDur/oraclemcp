#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="http_oauth_lanes"
E2E_LANE="http-stateful"
E2E_PROFILE="offline"
E2E_LEVEL="READ_WRITE"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

for arg in "$@"; do
  set +e
  e2e_parse_common_arg "$arg"
  parsed=$?
  set -e
  case "$parsed" in
    0) continue ;;
    3)
      echo "Run the offline HTTP OAuth/stateful-lane e2e suite."
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "http_oauth_lanes: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "offline HTTP OAuth and lane isolation suite"
if ! e2e_run_command "act" cargo test -p oraclemcp --test e2e_http_oauth -- --nocapture; then
  e2e_finish_fail "HTTP OAuth/stateful-lane suite failed"
fi
e2e_log_event "scenario_assert" "assert" "pass" 0 "HTTP OAuth/stateful-lane suite completed"
e2e_finish_pass
