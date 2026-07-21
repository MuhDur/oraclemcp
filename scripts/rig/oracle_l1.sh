#!/usr/bin/env bash
# Rig L1: reuse the local XE 18 / XE 21 / Free 23ai lab containers.
#
# The command intentionally never creates or removes a container. `run` starts
# only stopped, pre-existing lanes; waits for the driver's readiness sentinel;
# invokes the driver's idempotent schema bootstrap; smoke-queries every lane;
# and stops only lanes started by this process. That makes a repeated `run`
# deterministic without taking down a container another operator already had up.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="rig_l1"
E2E_LANE="oracle-l1"
E2E_PROFILE="container-lab"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

DRIVER_ROOT="${ORACLEMCP_DRIVER_ROOT:-$ROOT/../rust-oracledb}"
DRIVER_CONTAINER="$DRIVER_ROOT/scripts/container.sh"
DRIVER_BOOTSTRAP="$DRIVER_ROOT/scripts/bootstrap_live_schema.sh"
READY_TIMEOUT_SECS="${ORACLEMCP_RIG_L1_READY_TIMEOUT_SECS:-300}"
BOOTSTRAP_TIMEOUT_SECS="${ORACLEMCP_RIG_L1_BOOTSTRAP_TIMEOUT_SECS:-300}"
# Keep runtime-only credentials lane-specific: the reused XE and Free images
# may deliberately have different SYS passwords. The shared variable remains a
# convenience fallback for lab images that use one password everywhere.
COMMON_ADMIN_PASSWORD="${ORACLEMCP_RIG_L1_ADMIN_PASSWORD:-}"
OWNED_STATE_DIR="${ORACLEMCP_RIG_L1_STATE_DIR:-$ROOT/target/e2e/rig_l1}"
OWNED_STATE_FILE="$OWNED_STATE_DIR/owned-containers.tsv"

lanes=(xe18 xe21 free23)

usage() {
  cat <<'USAGE'
Rig L1 Oracle container harness.

Usage:
  bash scripts/rig/oracle_l1.sh run --log
  bash scripts/rig/oracle_l1.sh <up|wait|bootstrap|smoke|down|run> [--log|--dry-run]

`run` is the one-command L1 cycle: start stopped existing containers, wait for
the Oracle readiness sentinel, seed the reusable driver schema, smoke-query
each lane, then stop only containers this process started. It never creates or
removes a container and leaves pre-existing running lanes untouched.

Environment:
  ORACLEMCP_DRIVER_ROOT                 rust-oracledb checkout (default sibling)
  ORACLEMCP_RIG_L1_READY_TIMEOUT_SECS   per-lane bounded readiness wait (default 300)
  ORACLEMCP_RIG_L1_BOOTSTRAP_TIMEOUT_SECS  per-lane bootstrap ceiling (default 300)
  ORACLEMCP_RIG_L1_<LANE>_ADMIN_PASSWORD  lane SYS password (XE18, XE21, FREE23; not logged)
  ORACLEMCP_RIG_L1_ADMIN_PASSWORD         shared fallback SYS password (not logged)
USAGE
  e2e_usage_common
}

lane_container() {
  case "$1" in
    xe18) printf '%s\n' 'oracle-xe18-1518' ;;
    xe21) printf '%s\n' 'oracle-xe21-1520' ;;
    free23) printf '%s\n' 'rust-oracledb-free' ;;
    *) return 1 ;;
  esac
}

lane_pdb() {
  case "$1" in
    xe18 | xe21) printf '%s\n' 'XEPDB1' ;;
    free23) printf '%s\n' 'FREEPDB1' ;;
    *) return 1 ;;
  esac
}

lane_admin_password() {
  case "$1" in
    xe18) printf '%s\n' "${ORACLEMCP_RIG_L1_XE18_ADMIN_PASSWORD:-$COMMON_ADMIN_PASSWORD}" ;;
    xe21) printf '%s\n' "${ORACLEMCP_RIG_L1_XE21_ADMIN_PASSWORD:-$COMMON_ADMIN_PASSWORD}" ;;
    free23) printf '%s\n' "${ORACLEMCP_RIG_L1_FREE23_ADMIN_PASSWORD:-$COMMON_ADMIN_PASSWORD}" ;;
    *) return 1 ;;
  esac
}

require_runtime_tools() {
  command -v docker >/dev/null 2>&1 || e2e_finish_fail 'docker is required for rig L1'
  command -v timeout >/dev/null 2>&1 || e2e_finish_fail 'timeout is required for bounded rig L1 commands'
  [[ "$READY_TIMEOUT_SECS" =~ ^[1-9][0-9]*$ ]] || e2e_finish_fail 'ORACLEMCP_RIG_L1_READY_TIMEOUT_SECS must be a positive integer'
  [[ "$BOOTSTRAP_TIMEOUT_SECS" =~ ^[1-9][0-9]*$ ]] || e2e_finish_fail 'ORACLEMCP_RIG_L1_BOOTSTRAP_TIMEOUT_SECS must be a positive integer'
  [ -x "$DRIVER_CONTAINER" ] || e2e_finish_fail "driver container helper is not executable: $DRIVER_CONTAINER"
  [ -x "$DRIVER_BOOTSTRAP" ] || e2e_finish_fail "driver bootstrap hook is not executable: $DRIVER_BOOTSTRAP"
}

require_lane_admin_password() {
  local lane="$1"
  [ -n "$(lane_admin_password "$lane")" ] || e2e_finish_fail "set ORACLEMCP_RIG_L1_$(printf '%s' "$lane" | tr '[:lower:]' '[:upper:]')_ADMIN_PASSWORD (or the shared ORACLEMCP_RIG_L1_ADMIN_PASSWORD) for fixture bootstrap or SQL smoke"
}

container_exists() {
  docker container inspect "$1" >/dev/null 2>&1
}

container_running() {
  [ "$(docker inspect --format '{{.State.Running}}' "$1" 2>/dev/null || true)" = 'true' ]
}

record_owned_state() {
  local container="$1"
  local state="$2"
  mkdir -p "$OWNED_STATE_DIR"
  printf '%s\t%s\t%s\n' "$container" "$state" "$E2E_SID" >>"$OWNED_STATE_FILE"
}

owned_state() {
  local container="$1"
  if [ ! -f "$OWNED_STATE_FILE" ]; then
    return 0
  fi
  awk -F '\t' -v container="$container" -v sid="$E2E_SID" \
    '$1 == container && $3 == sid { state = $2 } END { print state }' "$OWNED_STATE_FILE"
}

start_lane() {
  local lane="$1"
  local container
  container="$(lane_container "$lane")"
  if [ "$E2E_DRY_RUN" = '1' ]; then
    e2e_log_event 'container_start' 'setup' 'skipped' 0 "lane=$lane dry-run"
    return 0
  fi
  container_exists "$container" || e2e_finish_fail "lane=$lane expected existing container $container; rig L1 refuses to create lab containers"
  if container_running "$container"; then
    e2e_log_event 'container_start' 'setup' 'pass' 0 "lane=$lane container already running"
    return 0
  fi
  local started
  started="$(e2e_epoch_ms)"
  e2e_log_event 'container_start' 'setup' 'running' 0 "lane=$lane"
  timeout -k 5 60 docker start "$container" >/dev/null
  record_owned_state "$container" 'started'
  e2e_log_event 'container_start' 'setup' 'pass' "$(( $(e2e_epoch_ms) - started ))" "lane=$lane started owned container"
}

wait_lane() {
  local lane="$1"
  local container deadline started
  container="$(lane_container "$lane")"
  if [ "$E2E_DRY_RUN" = '1' ]; then
    e2e_log_event 'container_ready' 'assert' 'skipped' 0 "lane=$lane dry-run"
    return 0
  fi
  container_running "$container" || e2e_finish_fail "lane=$lane container is not running: $container"
  started="$(e2e_epoch_ms)"
  deadline=$((SECONDS + READY_TIMEOUT_SECS))
  e2e_log_event 'container_ready' 'act' 'running' 0 "lane=$lane sentinel=DATABASE IS READY TO USE"
  while ! docker logs "$container" 2>&1 | grep -Fq 'DATABASE IS READY TO USE'; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      e2e_log_event 'container_ready' 'assert' 'fail' "$(( $(e2e_epoch_ms) - started ))" "lane=$lane readiness timed out after ${READY_TIMEOUT_SECS}s"
      e2e_finish_fail "lane=$lane readiness timed out after ${READY_TIMEOUT_SECS}s"
    fi
    sleep 2
  done
  e2e_log_event 'container_ready' 'assert' 'pass' "$(( $(e2e_epoch_ms) - started ))" "lane=$lane readiness sentinel observed"
}

bootstrap_lane() {
  local lane="$1"
  local container pdb password started
  container="$(lane_container "$lane")"
  pdb="$(lane_pdb "$lane")"
  if [ "$E2E_DRY_RUN" = '1' ]; then
    e2e_log_event 'fixture_bootstrap' 'act' 'skipped' 0 "lane=$lane dry-run"
    return 0
  fi
  require_lane_admin_password "$lane"
  password="$(lane_admin_password "$lane")"
  container_running "$container" || e2e_finish_fail "lane=$lane container is not running: $container"
  started="$(e2e_epoch_ms)"
  e2e_log_event 'fixture_bootstrap' 'act' 'running' 0 "lane=$lane driver bootstrap hook"
  # Do not use e2e_run_command: its command artifact would include the secret
  # environment assignment. The hook's normal success line contains no secret.
  if ! ORACLEDB_CONTAINER_NAME="$container" ORACLEDB_PDB="$pdb" ORACLE_PASSWORD="$password" \
    timeout -k 10 "$BOOTSTRAP_TIMEOUT_SECS" "$DRIVER_BOOTSTRAP" >/dev/null; then
    e2e_log_event 'fixture_bootstrap' 'assert' 'fail' "$(( $(e2e_epoch_ms) - started ))" "lane=$lane driver bootstrap failed"
    e2e_finish_fail "lane=$lane driver bootstrap failed"
  fi
  e2e_log_event 'fixture_bootstrap' 'assert' 'pass' "$(( $(e2e_epoch_ms) - started ))" "lane=$lane driver bootstrap completed"
}

smoke_lane() {
  local lane="$1"
  local container pdb password started output query_exit
  container="$(lane_container "$lane")"
  pdb="$(lane_pdb "$lane")"
  if [ "$E2E_DRY_RUN" = '1' ]; then
    e2e_log_event 'smoke_query' 'assert' 'skipped' 0 "lane=$lane dry-run"
    return 0
  fi
  require_lane_admin_password "$lane"
  password="$(lane_admin_password "$lane")"
  container_running "$container" || e2e_finish_fail "lane=$lane container is not running: $container"
  started="$(e2e_epoch_ms)"
  e2e_log_event 'smoke_query' 'act' 'running' 0 "lane=$lane SELECT 1 FROM dual"
  set +e
  output="$(timeout -k 5 60 docker exec -i "$container" \
    sqlplus -S -L "sys/${password}@localhost:1521/${pdb} as sysdba" <<'SQL'
whenever sqlerror exit failure
set echo off feedback off heading off verify off pagesize 0
select 1 from dual;
exit
SQL
  )"
  query_exit=$?
  set -e
  if [ "$query_exit" -ne 0 ] || ! printf '%s\n' "$output" | awk 'NF == 1 && $1 == 1 { found = 1 } END { exit !found }'; then
    e2e_log_event 'smoke_query' 'assert' 'fail' "$(( $(e2e_epoch_ms) - started ))" "lane=$lane SELECT 1 FROM dual failed"
    e2e_finish_fail "lane=$lane SELECT 1 FROM dual failed"
  fi
  e2e_log_event 'smoke_query' 'assert' 'pass' "$(( $(e2e_epoch_ms) - started ))" "lane=$lane SELECT 1 FROM dual returned 1"
}

teardown_owned_lanes() {
  local lane container started state
  if [ "$E2E_DRY_RUN" = '1' ]; then
    e2e_log_event 'container_teardown' 'teardown' 'skipped' 0 'dry-run'
    return 0
  fi
  for lane in "${lanes[@]}"; do
    container="$(lane_container "$lane")"
    state="$(owned_state "$container")"
    if [ "$state" != 'started' ]; then
      continue
    fi
    if ! container_running "$container"; then
      record_owned_state "$container" 'stopped'
      continue
    fi
    started="$(e2e_epoch_ms)"
    e2e_log_event 'container_teardown' 'teardown' 'running' 0 "container=$container owned-by-this-run"
    timeout -k 5 60 docker stop "$container" >/dev/null
    record_owned_state "$container" 'stopped'
    e2e_log_event 'container_teardown' 'teardown' 'pass' "$(( $(e2e_epoch_ms) - started ))" "container=$container stopped"
  done
}

run_all_lanes() {
  local lane
  for lane in "${lanes[@]}"; do
    start_lane "$lane"
    wait_lane "$lane"
  done
  for lane in "${lanes[@]}"; do
    bootstrap_lane "$lane"
    smoke_lane "$lane"
  done
}

command='run'
if [ "$#" -gt 0 ]; then
  case "$1" in
    up | wait | bootstrap | smoke | down | run)
      command="$1"
      shift
      ;;
  esac
fi
for arg in "$@"; do
  set +e
  e2e_parse_common_arg "$arg"
  parsed=$?
  set -e
  case "$parsed" in
    0) continue ;;
    3) usage; exit 0 ;;
    1) e2e_finish_fail "unknown argument: $arg" ;;
  esac
done

require_runtime_tools
e2e_log_event 'scenario_start' 'setup' 'running' 0 "Rig L1 command=$command lanes=${lanes[*]}"

case "$command" in
  up)
    for lane in "${lanes[@]}"; do start_lane "$lane"; done
    ;;
  wait)
    for lane in "${lanes[@]}"; do wait_lane "$lane"; done
    ;;
  bootstrap)
    for lane in "${lanes[@]}"; do bootstrap_lane "$lane"; done
    ;;
  smoke)
    for lane in "${lanes[@]}"; do smoke_lane "$lane"; done
    ;;
  down)
    teardown_owned_lanes
    ;;
  run)
    trap teardown_owned_lanes EXIT
    run_all_lanes
    trap - EXIT
    teardown_owned_lanes
    ;;
esac

e2e_log_event 'scenario_assert' 'assert' 'pass' 0 "Rig L1 command=$command completed"
e2e_finish_pass
