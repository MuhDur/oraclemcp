#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="live_xe_headline"
E2E_LANE="live-xe-headline"
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
      echo "Run the full G6 live-XE headline suite: live DB, multi-lane, load/soak, service attach."
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "live_xe_headline: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

e2e_require_g6_headline_env() {
  e2e_require_live_oracle_env
  if [ "${ORACLEMCP_MULTI_DB_LIVE_XE:-}" != "1" ]; then
    e2e_finish_skip "set ORACLEMCP_MULTI_DB_LIVE_XE=1 and ORACLEMCP_TEST_*_A/B for G6 multi-DB proof"
  fi
  for name in \
    ORACLEMCP_TEST_DSN_A ORACLEMCP_TEST_USER_A ORACLEMCP_TEST_PASSWORD_A \
    ORACLEMCP_TEST_DSN_B ORACLEMCP_TEST_USER_B ORACLEMCP_TEST_PASSWORD_B
  do
    if [ -z "${!name:-}" ]; then
      e2e_finish_skip "set $name for G6 multi-DB proof"
    fi
  done
  if [ "${ORACLEMCP_LIVE_XE_CONTENTION:-}" != "1" ]; then
    e2e_finish_skip "set ORACLEMCP_LIVE_XE_CONTENTION=1 for G6 same-DB contention proof"
  fi
}

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "G6 live-XE headline suite safety gate"
e2e_require_g6_headline_env

if ! e2e_run_command "act" cargo test -p oraclemcp-db --features live-xe --test live_oracle -- --nocapture; then
  e2e_finish_fail "live Oracle suite failed"
fi
if ! e2e_run_command "act" cargo test -p oraclemcp-db --features live-xe --test multi_lane_live_xe -- --ignored --nocapture; then
  e2e_finish_fail "live multi-lane DB suite failed"
fi
if ! e2e_run_command "act" cargo test -p oraclemcp-db --test load_soak live_xe_load_soak_pool_accounting_and_latency -- --ignored --nocapture; then
  e2e_finish_fail "live load/soak suite failed"
fi
if ! e2e_run_command "act" cargo test -p oraclemcp --features live-xe --test live_xe_service_attach -- --ignored --nocapture; then
  e2e_finish_fail "live service attach suite failed"
fi

e2e_log_event "scenario_assert" "assert" "pass" 0 "G6 live-XE headline suite completed"
e2e_finish_pass
