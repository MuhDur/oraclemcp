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
CAPABILITY_FIXTURES_SQL="$ROOT/scripts/rig/oracle_l1_capabilities.sql"
READY_TIMEOUT_SECS="${ORACLEMCP_RIG_L1_READY_TIMEOUT_SECS:-300}"
BOOTSTRAP_TIMEOUT_SECS="${ORACLEMCP_RIG_L1_BOOTSTRAP_TIMEOUT_SECS:-300}"
# The driver bootstrap owns this throwaway principal. Keep the D2 fixture
# credentials aligned with it while permitting an operator to override a
# rotated lab password without printing it.
FIXTURE_USER="${PYO_TEST_MAIN_USER:-pythontest}"
FIXTURE_PASSWORD="${ORACLEMCP_RIG_L1_FIXTURE_PASSWORD:-${PYO_TEST_MAIN_PASSWORD:-testpw}}"
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
  bash scripts/rig/oracle_l1.sh <up|wait|bootstrap|fixtures|smoke|drcp-identity|down|run> [--log|--dry-run]

`run` is the one-command L1 cycle: start stopped existing containers, wait for
the Oracle readiness sentinel, seed the reusable driver schema, smoke-query
and verify D2 capability fixtures in each lane, then stop only containers this
process started. It never creates or removes a container and leaves pre-existing
running lanes untouched.

`drcp-identity` runs the two-profile DRCP reuse assertion against FREE 23ai.
It intentionally fails until B14a clears identity before setting it; that red
result is the fixture's proof that it can catch the cross-profile bleed.

Environment:
  ORACLEMCP_DRIVER_ROOT                 rust-oracledb checkout (default sibling)
  ORACLEMCP_RIG_L1_READY_TIMEOUT_SECS   per-lane bounded readiness wait (default 300)
  ORACLEMCP_RIG_L1_BOOTSTRAP_TIMEOUT_SECS  per-lane bootstrap ceiling (default 300)
  ORACLEMCP_RIG_L1_<LANE>_ADMIN_PASSWORD  lane SYS password (XE18, XE21, FREE23; not logged)
  ORACLEMCP_RIG_L1_ADMIN_PASSWORD         shared fallback SYS password (not logged)
  ORACLEMCP_RIG_L1_FIXTURE_PASSWORD       PYO_TEST_MAIN_USER password after bootstrap (default: testpw; not logged)
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
  local explicit_password container configured_password
  case "$1" in
    xe18) explicit_password="${ORACLEMCP_RIG_L1_XE18_ADMIN_PASSWORD:-$COMMON_ADMIN_PASSWORD}" ;;
    xe21) explicit_password="${ORACLEMCP_RIG_L1_XE21_ADMIN_PASSWORD:-$COMMON_ADMIN_PASSWORD}" ;;
    free23) explicit_password="${ORACLEMCP_RIG_L1_FREE23_ADMIN_PASSWORD:-$COMMON_ADMIN_PASSWORD}" ;;
    *) return 1 ;;
  esac
  if [ -n "$explicit_password" ]; then
    printf '%s\n' "$explicit_password"
    return 0
  fi

  # The local lab containers were created with gvenzl's ORACLE_PASSWORD
  # contract. Reading that Docker config makes the ordinary L1 invocation a
  # single command without printing or persisting the credential. An explicit
  # lane value above still wins when an operator rotated the database password
  # after container creation.
  container="$(lane_container "$1")"
  configured_password="$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$container" 2>/dev/null \
    | awk -F= '$1 == "ORACLE_PASSWORD" { print substr($0, index($0, "=") + 1); exit }')"
  printf '%s\n' "$configured_password"
}

require_runtime_tools() {
  command -v docker >/dev/null 2>&1 || e2e_finish_fail 'docker is required for rig L1'
  command -v timeout >/dev/null 2>&1 || e2e_finish_fail 'timeout is required for bounded rig L1 commands'
  [[ "$READY_TIMEOUT_SECS" =~ ^[1-9][0-9]*$ ]] || e2e_finish_fail 'ORACLEMCP_RIG_L1_READY_TIMEOUT_SECS must be a positive integer'
  [[ "$BOOTSTRAP_TIMEOUT_SECS" =~ ^[1-9][0-9]*$ ]] || e2e_finish_fail 'ORACLEMCP_RIG_L1_BOOTSTRAP_TIMEOUT_SECS must be a positive integer'
  [ -x "$DRIVER_CONTAINER" ] || e2e_finish_fail "driver container helper is not executable: $DRIVER_CONTAINER"
  [ -x "$DRIVER_BOOTSTRAP" ] || e2e_finish_fail "driver bootstrap hook is not executable: $DRIVER_BOOTSTRAP"
  [ -r "$CAPABILITY_FIXTURES_SQL" ] || e2e_finish_fail "D2 capability fixture SQL is not readable: $CAPABILITY_FIXTURES_SQL"
}

require_lane_admin_password() {
  local lane="$1"
  [ -n "$(lane_admin_password "$lane")" ] || e2e_finish_fail "lane=$lane has no Docker-configured ORACLE_PASSWORD; set ORACLEMCP_RIG_L1_$(printf '%s' "$lane" | tr '[:lower:]' '[:upper:]')_ADMIN_PASSWORD (or ORACLEMCP_RIG_L1_ADMIN_PASSWORD) for fixture bootstrap or SQL smoke"
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
  # Do not use grep -q here: with pipefail it closes Docker's log stream early,
  # turning a successful sentinel match into Docker's SIGPIPE status. Consume
  # the bounded log output before deciding whether the sentinel was present.
  while ! docker logs "$container" 2>&1 | grep -F 'DATABASE IS READY TO USE' >/dev/null; do
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

seed_capability_lane() {
  local lane="$1"
  local container pdb started output fixture_exit
  container="$(lane_container "$lane")"
  pdb="$(lane_pdb "$lane")"
  if [ "$E2E_DRY_RUN" = '1' ]; then
    e2e_log_event 'capability_fixture_seed' 'act' 'skipped' 0 "lane=$lane dry-run"
    return 0
  fi
  [ -n "$FIXTURE_USER" ] || e2e_finish_fail 'PYO_TEST_MAIN_USER must not be empty for D2 fixtures'
  [ -n "$FIXTURE_PASSWORD" ] || e2e_finish_fail 'ORACLEMCP_RIG_L1_FIXTURE_PASSWORD must not be empty for D2 fixtures'
  container_running "$container" || e2e_finish_fail "lane=$lane container is not running: $container"
  started="$(e2e_epoch_ms)"
  e2e_log_event 'capability_fixture_seed' 'act' 'running' "0" "lane=$lane schema=ORACLEMCP_CAP_*"
  set +e
  output="$(timeout -k 10 "$BOOTSTRAP_TIMEOUT_SECS" docker exec -i "$container" \
    sqlplus -S -L "${FIXTURE_USER}/${FIXTURE_PASSWORD}@localhost:1521/${pdb}" \
    <"$CAPABILITY_FIXTURES_SQL")"
  fixture_exit=$?
  set -e
  if [ "$fixture_exit" -ne 0 ]; then
    e2e_log_event 'capability_fixture_seed' 'assert' 'fail' "$(( $(e2e_epoch_ms) - started ))" "lane=$lane D2 schema seed failed"
    e2e_finish_fail "lane=$lane D2 capability schema seed failed"
  fi
  e2e_log_event 'capability_fixture_seed' 'assert' 'pass' "$(( $(e2e_epoch_ms) - started ))" "lane=$lane schema=ORACLEMCP_CAP_* seeded"
}

verify_capability_lane() {
  local lane="$1"
  local container pdb started output fixture_exit
  container="$(lane_container "$lane")"
  pdb="$(lane_pdb "$lane")"
  if [ "$E2E_DRY_RUN" = '1' ]; then
    e2e_log_event 'capability_fixture_assert' 'assert' 'skipped' 0 "lane=$lane dry-run"
    return 0
  fi
  container_running "$container" || e2e_finish_fail "lane=$lane container is not running: $container"
  started="$(e2e_epoch_ms)"
  e2e_log_event 'capability_fixture_assert' 'act' 'running' 0 "lane=$lane typed,lob,refcursor,soda,vector,tpc,output,edition,statement-cache"
  set +e
  output="$(timeout -k 10 "$BOOTSTRAP_TIMEOUT_SECS" docker exec -i "$container" \
    sqlplus -S -L "${FIXTURE_USER}/${FIXTURE_PASSWORD}@localhost:1521/${pdb}" <<'SQL'
whenever sqlerror exit failure
set echo off feedback off heading off verify off serveroutput on size 1000000
declare
  l_major pls_integer;
  l_count pls_integer;
  l_number number;
  l_text varchar2(64);
  l_raw raw(4);
  l_lob_chars pls_integer;
  l_lob_bytes pls_integer;
  l_cache_value varchar2(32);
  l_tpc_state varchar2(16);
  l_ref sys_refcursor;
  l_ref_id number;
  l_ref_number number;
  l_ref_text varchar2(64);
  l_collection soda_collection_t;
begin
  select to_number(regexp_substr(version, '^[0-9]+')) into l_major from v$instance;
  select number_value, text_value, raw_value
    into l_number, l_text, l_raw
    from ORACLEMCP_CAP_TYPED where id = 1;
  if l_number != 42.125 or l_text != 'd2 typed row' or rawtohex(l_raw) != 'DEADBEEF' then
    raise_application_error(-20001, 'typed fixture drift');
  end if;
  select dbms_lob.getlength(text_value), dbms_lob.getlength(blob_value)
    into l_lob_chars, l_lob_bytes
    from ORACLEMCP_CAP_LOB where id = 1;
  if l_lob_chars != 96 or l_lob_bytes != 8 then
    raise_application_error(-20002, 'LOB fixture drift');
  end if;
  ORACLEMCP_CAP_REFCURSOR.open_typed_rows(l_ref);
  fetch l_ref into l_ref_id, l_ref_number, l_ref_text;
  close l_ref;
  if l_ref_id != 1 or l_ref_number != 42.125 or l_ref_text != 'd2 typed row' then
    raise_application_error(-20003, 'REF CURSOR fixture drift');
  end if;
  select cache_value into l_cache_value from ORACLEMCP_CAP_STMT_CACHE where cache_key = 2;
  select state into l_tpc_state from ORACLEMCP_CAP_TPC where branch_id = 'd2-local-only';
  if l_cache_value != 'second cached row' or l_tpc_state != 'unprepared' then
    raise_application_error(-20004, 'statement-cache or TPC fixture drift');
  end if;
  select count(*) into l_count from all_editions where edition_name = 'E_TEST';
  if l_count != 1 then
    raise_application_error(-20005, 'edition fixture missing E_TEST');
  end if;
  if l_major >= 23 then
    select count(*) into l_count from user_tables where table_name = 'ORACLEMCP_CAP_VECTOR';
    if l_count != 1 then
      raise_application_error(-20006, '23ai vector fixture missing');
    end if;
    l_collection := dbms_soda.open_collection('ORACLEMCP_CAP_SODA');
    if l_collection is null then
      raise_application_error(-20007, '23ai SODA fixture missing');
    end if;
  else
    -- This is a negative fixture, not an omission: an XE lane must reject the
    -- 23ai VECTOR DDL. A mistaken broad generation gate makes this fail.
    begin
      execute immediate 'create table ORACLEMCP_CAP_VECTOR_NEG (v vector(3, float32))';
      execute immediate 'drop table ORACLEMCP_CAP_VECTOR_NEG purge';
      raise_application_error(-20008, 'pre-23 lane unexpectedly accepted VECTOR');
    exception
      when others then
        if sqlcode = -20008 then
          raise;
        end if;
    end;
    select count(*) into l_count from user_tables where table_name = 'ORACLEMCP_CAP_VECTOR';
    if l_count != 0 then
      raise_application_error(-20009, 'pre-23 lane has a vector fixture');
    end if;
  end if;
  ORACLEMCP_CAP_OUTPUT.emit_fixture_line;
  dbms_output.put_line('oraclemcp-d2-capabilities-pass');
end;
/
exit
SQL
  )"
  fixture_exit=$?
  set -e
  if [ "$fixture_exit" -ne 0 ] || ! printf '%s\n' "$output" | grep -Fx 'oraclemcp-d2-capabilities-pass' >/dev/null; then
    e2e_log_event 'capability_fixture_assert' 'assert' 'fail' "$(( $(e2e_epoch_ms) - started ))" "lane=$lane D2 live capability assertion failed"
    e2e_finish_fail "lane=$lane D2 live capability assertion failed"
  fi
  if ! printf '%s\n' "$output" | grep -Fx 'oraclemcp-d2-output' >/dev/null; then
    e2e_log_event 'capability_fixture_assert' 'assert' 'fail' "$(( $(e2e_epoch_ms) - started ))" "lane=$lane DBMS_OUTPUT fixture did not emit"
    e2e_finish_fail "lane=$lane DBMS_OUTPUT fixture did not emit"
  fi
  e2e_log_event 'capability_fixture_assert' 'assert' 'pass' "$(( $(e2e_epoch_ms) - started ))" "lane=$lane live capability fixtures asserted"
}

drcp_identity_fixture() {
  local lane='free23'
  local container pdb started test_exit
  container="$(lane_container "$lane")"
  pdb="$(lane_pdb "$lane")"
  if [ "$E2E_DRY_RUN" = '1' ]; then
    e2e_log_event 'drcp_identity_fixture' 'assert' 'skipped' 0 'lane=free23 dry-run'
    return 0
  fi
  container_running "$container" || e2e_finish_fail "lane=$lane container is not running: $container"
  started="$(e2e_epoch_ms)"
  e2e_log_event 'drcp_identity_fixture' 'act' 'running' 0 'lane=free23 two profiles, same DRCP class'
  # This is intentionally a focused crate test. It uses the actual adapter
  # connection path, not a SQLPlus approximation, and so is expected to be red
  # before B14a's clear-before-set fix lands.
  set +e
  ORACLEMCP_TEST_DSN="//localhost:1521/${pdb}" \
    ORACLEMCP_TEST_USER="$FIXTURE_USER" \
    ORACLEMCP_TEST_PASSWORD="$FIXTURE_PASSWORD" \
    ORACLEMCP_TEST_DRCP=1 \
    ORACLEMCP_TEST_DRCP_IDENTITY=1 \
    ORACLEMCP_TEST_DRCP_CLASS='oraclemcp-d2-identity' \
    timeout -k 20 "$BOOTSTRAP_TIMEOUT_SECS" \
    cargo test -p oraclemcp-db --features live-xe live_drcp_reuse_clears_prior_profile_identity -- --exact --nocapture
  test_exit=$?
  set -e
  if [ "$test_exit" -ne 0 ]; then
    e2e_log_event 'drcp_identity_fixture' 'assert' 'fail' "$(( $(e2e_epoch_ms) - started ))" 'lane=free23 DRCP profile isolation failed (expected before B14a)'
    return "$test_exit"
  fi
  e2e_log_event 'drcp_identity_fixture' 'assert' 'pass' "$(( $(e2e_epoch_ms) - started ))" 'lane=free23 DRCP profile isolation held'
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
    seed_capability_lane "$lane"
    verify_capability_lane "$lane"
    smoke_lane "$lane"
  done
}

command='run'
if [ "$#" -gt 0 ]; then
  case "$1" in
    up | wait | bootstrap | fixtures | smoke | drcp-identity | down | run)
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
  fixtures)
    for lane in "${lanes[@]}"; do
      bootstrap_lane "$lane"
      seed_capability_lane "$lane"
      verify_capability_lane "$lane"
    done
    ;;
  smoke)
    for lane in "${lanes[@]}"; do smoke_lane "$lane"; done
    ;;
  drcp-identity)
    drcp_identity_fixture
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
