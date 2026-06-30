#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="offline_stdio"
E2E_LANE="stdio"
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
      echo "Run the offline stdio MCP e2e suite."
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "offline_stdio: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "offline stdio MCP suite"
if ! e2e_run_command "act" cargo test -p oraclemcp --test e2e_stdio -- --nocapture; then
  e2e_finish_fail "offline stdio MCP suite failed"
fi
e2e_log_event "scenario_assert" "assert" "pass" 0 "stdio suite completed"
e2e_finish_pass
