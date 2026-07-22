#!/usr/bin/env bash
# Rig D10: real idle-kill failure-injection lane.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="rig_idle_kill"
E2E_LANE="oracle-free23-idle-kill"
E2E_PROFILE="container-lab"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

CONTAINER="${ORACLEMCP_RIG_D10_CONTAINER:-rust-oracledb-free}"
PDB="${ORACLEMCP_RIG_D10_PDB:-FREEPDB1}"
HOST_PORT="${ORACLEMCP_RIG_D10_HOST_PORT:-1522}"
READY_TIMEOUT_SECS="${ORACLEMCP_RIG_D10_READY_TIMEOUT_SECS:-300}"
TEST_TIMEOUT_SECS="${ORACLEMCP_RIG_D10_TEST_TIMEOUT_SECS:-900}"
CARGO_TARGET_DIR="${ORACLEMCP_RIG_CARGO_TARGET_DIR:-$ROOT/target}"
export CARGO_TARGET_DIR

usage() {
  cat <<'USAGE'
Rig D10 real idle-kill lane.

Usage:
  bash scripts/rig/rig_idle_kill.sh [run|failure-probe] [--log|--dry-run]

`run` starts the existing Free23 lab container if needed, then runs the real
pooled checkout and pinned OracleDispatcher idle-kill tests. Skips and raw
Broken pipe output are hard failures.

`failure-probe` disables the kill in both tests and requires the rig to catch
that vacuous lane. This is the D10 failure path.
USAGE
  e2e_usage_common
}

parse_args() {
  command="run"
  while [ "$#" -gt 0 ]; do
    case "$1" in
      run|failure-probe) command="$1"; shift ;;
      --help|-h) usage; exit 0 ;;
      *)
        if e2e_parse_common_arg "$1"; then shift; continue; fi
        case $? in
          3) usage; exit 0 ;;
          *) e2e_finish_fail "unknown argument: $1" ;;
        esac
        ;;
    esac
  done
}

require_runtime_tools() {
  command -v timeout >/dev/null 2>&1 || e2e_finish_fail "timeout is required for bounded D10 idle-kill"
  [[ "$READY_TIMEOUT_SECS" =~ ^[1-9][0-9]*$ ]] || e2e_finish_fail "ORACLEMCP_RIG_D10_READY_TIMEOUT_SECS must be a positive integer"
  [[ "$TEST_TIMEOUT_SECS" =~ ^[1-9][0-9]*$ ]] || e2e_finish_fail "ORACLEMCP_RIG_D10_TEST_TIMEOUT_SECS must be a positive integer"
  if [ "$E2E_DRY_RUN" = "1" ]; then
    return 0
  fi
  command -v docker >/dev/null 2>&1 || e2e_finish_fail "docker is required for D10 idle-kill"
  command -v cargo >/dev/null 2>&1 || e2e_finish_fail "cargo is required for D10 idle-kill"
}

container_running() {
  [ "$(docker inspect --format '{{.State.Running}}' "$CONTAINER" 2>/dev/null || true)" = "true" ]
}

admin_password() {
  local explicit_password configured_password
  explicit_password="${ORACLEMCP_RIG_D10_ADMIN_PASSWORD:-${ORACLEMCP_RIG_L1_FREE23_ADMIN_PASSWORD:-${ORACLEMCP_RIG_L1_ADMIN_PASSWORD:-}}}"
  if [ -n "$explicit_password" ]; then
    printf '%s\n' "$explicit_password"
    return 0
  fi
  configured_password="$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$CONTAINER" 2>/dev/null \
    | awk -F= '$1 == "ORACLE_PASSWORD" { print substr($0, index($0, "=") + 1); exit }')"
  printf '%s\n' "$configured_password"
}

start_and_wait_container() {
  local started deadline
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "idle_kill_container" "setup" "skipped" 0 "container=$CONTAINER dry-run"
    return 0
  fi
  docker container inspect "$CONTAINER" >/dev/null 2>&1 \
    || e2e_finish_fail "D10 expected existing container $CONTAINER; rig refuses to create lab containers"
  if ! container_running; then
    started="$(e2e_epoch_ms)"
    e2e_log_event "idle_kill_container" "setup" "running" 0 "container=$CONTAINER start"
    timeout -k 5 60 docker start "$CONTAINER" >/dev/null
    e2e_log_event "idle_kill_container" "setup" "pass" "$(( $(e2e_epoch_ms) - started ))" "container=$CONTAINER started"
  fi

  started="$(e2e_epoch_ms)"
  deadline=$((SECONDS + READY_TIMEOUT_SECS))
  e2e_log_event "idle_kill_ready" "setup" "running" 0 "container=$CONTAINER sentinel=DATABASE IS READY TO USE"
  while ! docker logs "$CONTAINER" 2>&1 | grep -F "DATABASE IS READY TO USE" >/dev/null; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      e2e_log_event "idle_kill_ready" "assert" "fail" "$(( $(e2e_epoch_ms) - started ))" "container=$CONTAINER readiness timed out"
      e2e_finish_fail "D10 container readiness timed out after ${READY_TIMEOUT_SECS}s"
    fi
    sleep 2
  done
  e2e_log_event "idle_kill_ready" "assert" "pass" "$(( $(e2e_epoch_ms) - started ))" "container=$CONTAINER ready"
}

passed_test_count() {
  sed -n 's/^test result: [a-zA-Z]*\. \([0-9][0-9]*\) passed.*/\1/p' \
    | awk '{total += $1} END {print total + 0}'
}

run_cargo_test() {
  local label="$1"
  shift
  local password="$1"
  shift
  local started output status ran
  started="$(e2e_epoch_ms)"
  e2e_log_event "command_start" "assert" "running" 0 "$label"
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "command_dry_run" "assert" "skipped" 0 "$label"
    return 0
  fi
  set +e
  output="$(ORACLEMCP_TEST_DSN="//localhost:${HOST_PORT}/${PDB}" \
    ORACLEMCP_TEST_USER="system" \
    ORACLEMCP_TEST_PASSWORD="$password" \
    timeout -k 20 "$TEST_TIMEOUT_SECS" cargo test "$@" 2>&1)"
  status=$?
  set -e
  printf '%s\n' "$output"
  if [ "$status" -ne 0 ]; then
    e2e_finish_fail "$label: cargo test failed (exit $status)"
  fi
  ran="$(printf '%s\n' "$output" | passed_test_count)"
  if [ "$ran" -lt 1 ]; then
    e2e_finish_fail "$label: filter matched no tests"
  fi
  if printf '%s\n' "$output" | grep -F "[live-xe] SKIP" >/dev/null; then
    e2e_finish_fail "$label: live test skipped instead of exercising the rig"
  fi
  if printf '%s\n' "$output" | grep -F "Broken pipe" >/dev/null; then
    e2e_finish_fail "$label: raw Broken pipe reached the test output"
  fi
  e2e_log_event "idle_kill_test" "assert" "pass" "$(( $(e2e_epoch_ms) - started ))" "$label: $ran test(s)"
}

expect_cargo_test_failure() {
  local label="$1"
  local signature="$2"
  shift 2
  local password="$1"
  shift
  local started output status ran
  started="$(e2e_epoch_ms)"
  e2e_log_event "command_start" "assert" "running" 0 "$label expected failure"
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "command_dry_run" "assert" "skipped" 0 "$label expected failure"
    return 0
  fi
  set +e
  output="$(ORACLEMCP_D5_SKIP_KILL=1 \
    ORACLEMCP_TEST_DSN="//localhost:${HOST_PORT}/${PDB}" \
    ORACLEMCP_TEST_USER="system" \
    ORACLEMCP_TEST_PASSWORD="$password" \
    timeout -k 20 "$TEST_TIMEOUT_SECS" cargo test "$@" 2>&1)"
  status=$?
  set -e
  printf '%s\n' "$output"
  ran="$(printf '%s\n' "$output" | passed_test_count)"
  if [ "$ran" -gt 0 ] || [ "$status" -eq 0 ]; then
    e2e_finish_fail "$label: failure probe unexpectedly passed"
  fi
  if printf '%s\n' "$output" | grep -F "[live-xe] SKIP" >/dev/null; then
    e2e_finish_fail "$label: failure probe skipped instead of proving the rig"
  fi
  if printf '%s\n' "$output" | grep -F "Broken pipe" >/dev/null; then
    e2e_finish_fail "$label: failure probe exposed raw Broken pipe"
  fi
  if ! printf '%s\n' "$output" | grep -F "$signature" >/dev/null; then
    e2e_finish_fail "$label: failure signature changed; expected '$signature'"
  fi
  e2e_log_event "idle_kill_failure_probe" "assert" "pass" "$(( $(e2e_epoch_ms) - started ))" "$label failed for the expected reason"
}

run_positive_lane() {
  local password
  password="${ORACLEMCP_RIG_DRY_RUN_PASSWORD:-dry-run-password}"
  if [ "$E2E_DRY_RUN" != "1" ]; then
    password="$(admin_password)"
  fi
  [ -n "$password" ] || e2e_finish_fail "D10 has no Docker-configured ORACLE_PASSWORD; set ORACLEMCP_RIG_D10_ADMIN_PASSWORD"
  run_cargo_test "D10 pooled real checkout idle-kill" "$password" \
    -p oraclemcp-db --features live-xe --test live_idle_kill \
    a_killed_pooled_session_is_replaced_without_the_caller_seeing_it -- --exact --nocapture
  run_cargo_test "D10 pinned dispatcher idle-kill" "$password" \
    -p oraclemcp --features live-xe --test live_dispatcher_idle_kill \
    killed_dispatcher_pinned_session_is_refused_not_silently_rebound -- --exact --nocapture
}

run_failure_probe() {
  local password
  password="${ORACLEMCP_RIG_DRY_RUN_PASSWORD:-dry-run-password}"
  if [ "$E2E_DRY_RUN" != "1" ]; then
    password="$(admin_password)"
  fi
  [ -n "$password" ] || e2e_finish_fail "D10 has no Docker-configured ORACLE_PASSWORD; set ORACLEMCP_RIG_D10_ADMIN_PASSWORD"
  expect_cargo_test_failure "D10 pooled no-kill failure path" "the kill never took effect" "$password" \
    -p oraclemcp-db --features live-xe --test live_idle_kill \
    a_killed_pooled_session_is_replaced_without_the_caller_seeing_it -- --exact --nocapture
  expect_cargo_test_failure "D10 pinned no-kill failure path" "must not remain connected or be silently rebound" "$password" \
    -p oraclemcp --features live-xe --test live_dispatcher_idle_kill \
    killed_dispatcher_pinned_session_is_refused_not_silently_rebound -- --exact --nocapture
}

parse_args "$@"
require_runtime_tools
start_and_wait_container
case "$command" in
  run) run_positive_lane ;;
  failure-probe) run_failure_probe ;;
esac
e2e_finish_pass
