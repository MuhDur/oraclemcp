#!/usr/bin/env bash
# Rig L1: the oraclemcp-owned XE 18 / XE 21 / FREE 23ai lab lanes (bead .9.2).
#
# scripts/rig/lanes.toml is the lane inventory: container name, image pinned by
# digest, host port and PDB. `up` creates a missing lane from its pinned image
# (labelled oraclemcp.rig=1), starts a stopped one and adopts a running one;
# the bootstrap SQL lives in scripts/rig/bootstrap/. `down` stops only lanes
# that carry the oraclemcp.rig=1 label and removes them only with the explicit
# operator flag --remove. Nothing here calls into another repository.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="rig_l1"
E2E_LANE="oracle-l1"
E2E_PROFILE="container-lab"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

LANES_TOML="${ORACLEMCP_RIG_L1_LANES_TOML:-$ROOT/scripts/rig/lanes.toml}"
BOOTSTRAP_SQL="$ROOT/scripts/rig/bootstrap/01_fixture_principals.sql"
RIG_LABEL='oraclemcp.rig=1'
CAPABILITY_FIXTURES_SQL="$ROOT/scripts/rig/oracle_l1_capabilities.sql"
PRIVILEGE_MATRIX_SQL="$ROOT/scripts/rig/oracle_l1_privilege_matrix.sql"
READY_TIMEOUT_SECS="${ORACLEMCP_RIG_L1_READY_TIMEOUT_SECS:-300}"
BOOTSTRAP_TIMEOUT_SECS="${ORACLEMCP_RIG_L1_BOOTSTRAP_TIMEOUT_SECS:-300}"
# Synthetic fixture principals created by scripts/rig/bootstrap. The names stay
# the ones the D2 fixtures, rig doctor and tool sweep already connect as; an
# operator may override a rotated lab password without printing it.
FIXTURE_USER="${PYO_TEST_MAIN_USER:-pythontest}"
FIXTURE_PASSWORD="${ORACLEMCP_RIG_L1_FIXTURE_PASSWORD:-${PYO_TEST_MAIN_PASSWORD:-testpw}}"
PROXY_USER="${PYO_TEST_PROXY_USER:-pythontestproxy}"
PROXY_PASSWORD="${PYO_TEST_PROXY_PASSWORD:-proxypw}"
REMOVE_LANES=0
# Keep runtime-only credentials lane-specific: the reused XE and Free images
# may deliberately have different SYS passwords. The shared variable remains a
# convenience fallback for lab images that use one password everywhere.
COMMON_ADMIN_PASSWORD="${ORACLEMCP_RIG_L1_ADMIN_PASSWORD:-}"
OWNED_STATE_DIR="${ORACLEMCP_RIG_L1_STATE_DIR:-$ROOT/target/e2e/rig_l1}"
OWNED_STATE_FILE="$OWNED_STATE_DIR/owned-containers.tsv"

lanes=(xe18 xe21 free23)

# One field of one lane from lanes.toml (the single lane inventory).
lane_field() {
  python3 - "$LANES_TOML" "$1" "$2" <<'PY'
import sys, tomllib
with open(sys.argv[1], "rb") as handle:
    lane = tomllib.load(handle)["lanes"].get(sys.argv[2])
if lane is None or sys.argv[3] not in lane:
    sys.exit(1)
print(lane[sys.argv[3]])
PY
}

lane_container() { lane_field "$1" container; }
lane_pdb() { lane_field "$1" pdb; }
lane_image() { lane_field "$1" image; }

lane_host_port() {
  if [ "$1" = 'free23' ] && [ -n "${ORACLEMCP_RIG_FREE23_PORT:-}" ]; then
    printf '%s\n' "$ORACLEMCP_RIG_FREE23_PORT"
    return 0
  fi
  lane_field "$1" host_port
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
  command -v python3 >/dev/null 2>&1 || e2e_finish_fail 'python3 is required to read scripts/rig/lanes.toml'
  [ -r "$LANES_TOML" ] || e2e_finish_fail "lane inventory is not readable: $LANES_TOML"
  [ -r "$BOOTSTRAP_SQL" ] || e2e_finish_fail "lane bootstrap SQL is not readable: $BOOTSTRAP_SQL"
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
  if ! container_exists "$container"; then
    create_lane "$lane"
    return 0
  fi
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

# Create a missing lane from its pinned image. The admin password reaches the
# container through the environment (never argv): an explicit lane password, or
# a fresh random one that `lane_admin_password` later reads back from Docker.
create_lane() {
  local lane="$1"
  local container image port started password
  container="$(lane_container "$lane")"
  image="$(lane_image "$lane")"
  port="$(lane_host_port "$lane")"
  password="$(lane_admin_password "$lane")"
  if [ -z "$password" ]; then
    password="Rig$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')x9"
  fi
  started="$(e2e_epoch_ms)"
  e2e_log_event 'container_create' 'setup' 'running' 0 "lane=$lane container=$container image=$image port=$port"
  if ! ORACLE_PASSWORD="$password" timeout -k 5 900 docker run -d --name "$container" \
    --label "$RIG_LABEL" --label "oraclemcp.rig.lane=$lane" \
    -p "$port:1521" -e ORACLE_PASSWORD "$image" >/dev/null; then
    e2e_log_event 'container_create' 'setup' 'fail' "$(( $(e2e_epoch_ms) - started ))" "lane=$lane docker run failed"
    e2e_finish_fail "lane=$lane could not create $container from $image"
  fi
  record_owned_state "$container" 'started'
  e2e_log_event 'container_create' 'setup' 'pass' "$(( $(e2e_epoch_ms) - started ))" "lane=$lane created owned container $container"
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
  e2e_log_event 'fixture_bootstrap' 'act' 'running' 0 "lane=$lane scripts/rig/bootstrap"
  # Every secret travels by environment-variable NAME (`-e VAR`): never on the
  # host argv, never in a log line. Inside the container they become SQL*Plus
  # substitution values for the bootstrap script.
  if ! ORACLE_PASSWORD="$password" PDB="$pdb" RIG_FU="$FIXTURE_USER" RIG_FP="$FIXTURE_PASSWORD" \
    RIG_PU="$PROXY_USER" RIG_PP="$PROXY_PASSWORD" \
    timeout -k 10 "$BOOTSTRAP_TIMEOUT_SECS" docker exec -i -e ORACLE_PASSWORD -e PDB \
    -e RIG_FU -e RIG_FP -e RIG_PU -e RIG_PP "$container" bash -c \
    'sqlplus -S -L "sys/\"$ORACLE_PASSWORD\"@localhost:1521/$PDB as sysdba" @/dev/stdin "$RIG_FU" "$RIG_FP" "$RIG_PU" "$RIG_PP"' \
    <"$BOOTSTRAP_SQL" >/dev/null; then
    e2e_log_event 'fixture_bootstrap' 'assert' 'fail' "$(( $(e2e_epoch_ms) - started ))" "lane=$lane bootstrap failed"
    e2e_finish_fail "lane=$lane bootstrap failed"
  fi
  e2e_log_event 'fixture_bootstrap' 'assert' 'pass' "$(( $(e2e_epoch_ms) - started ))" "lane=$lane bootstrap completed"
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

# D4 — provision the privilege-matrix fixture (no-flashback + catalog-blind
# principals) and emit the environment the live Rust test consumes.
#
# The fixture SQL runs as SYSDBA inside the PDB: it recreates the three
# ORACLEMCP_D4_* principals, proves from the catalog that the guarded table has
# exactly one enabled SELECT VPD policy and one virtual column, and prints
# `oraclemcp-d4-catalog-object-id=<id>`. This command surfaces that verified
# object id plus the restricted-principal DSN/credentials so the live test
# (crates/oraclemcp-db/tests/privilege_matrix_live.rs) can run against the exact
# identity the rig proved — never against an accidentally privileged account.
#
# The two test cases are #[ignore]d expected-red until A3a/A3b and A1a land; this
# command provisions the fixture and records the failing half, it does not flip
# them green.
privilege_matrix_fixture() {
  local lane='free23'
  local container pdb host_port started output fixture_exit object_id
  container="$(lane_container "$lane")"
  pdb="$(lane_pdb "$lane")"
  host_port="$(lane_host_port "$lane")"
  if [ "$E2E_DRY_RUN" = '1' ]; then
    e2e_log_event 'privilege_matrix_fixture' 'assert' 'skipped' 0 "lane=$lane dry-run"
    return 0
  fi
  [ -r "$PRIVILEGE_MATRIX_SQL" ] || e2e_finish_fail "D4 privilege-matrix fixture SQL is not readable: $PRIVILEGE_MATRIX_SQL"
  container_running "$container" || e2e_finish_fail "lane=$lane container is not running: $container"
  started="$(e2e_epoch_ms)"
  e2e_log_event 'privilege_matrix_fixture' 'act' 'running' 0 "lane=$lane schema=ORACLEMCP_D4_*"
  set +e
  output="$( { printf 'alter session set container=%s;\n' "$pdb"; cat "$PRIVILEGE_MATRIX_SQL"; } \
    | timeout -k 10 "$BOOTSTRAP_TIMEOUT_SECS" docker exec -i "$container" sqlplus -S -L "/ as sysdba" 2>&1 )"
  fixture_exit=$?
  set -e
  if [ "$fixture_exit" -ne 0 ]; then
    e2e_log_event 'privilege_matrix_fixture' 'assert' 'fail' "$(( $(e2e_epoch_ms) - started ))" "lane=$lane D4 fixture load failed"
    printf '%s\n' "$output" >&2
    e2e_finish_fail "lane=$lane D4 privilege-matrix fixture load failed"
  fi
  object_id="$(printf '%s\n' "$output" | grep -oE 'oraclemcp-d4-catalog-object-id=[0-9]+' | head -1 | cut -d= -f2)"
  if [ -z "$object_id" ]; then
    e2e_log_event 'privilege_matrix_fixture' 'assert' 'fail' "$(( $(e2e_epoch_ms) - started ))" "lane=$lane fixture did not report a verified object id"
    printf '%s\n' "$output" >&2
    e2e_finish_fail "lane=$lane D4 fixture did not emit oraclemcp-d4-catalog-object-id"
  fi
  e2e_log_event 'privilege_matrix_fixture' 'assert' 'pass' "$(( $(e2e_epoch_ms) - started ))" "lane=$lane D4 fixture ready object_id=$object_id"
  # The restricted-principal password is a synthetic fixture value baked into the
  # fixture SQL; it is not a secret and the live test needs it to connect.
  cat <<ENV
ORACLEMCP_D4_DSN=//localhost:${host_port}/${pdb}
ORACLEMCP_D4_NO_FLASHBACK_USER=ORACLEMCP_D4_NO_FLASHBACK
ORACLEMCP_D4_NO_FLASHBACK_PASSWORD=D4_Privilege_Test_42
ORACLEMCP_D4_CATALOG_BLIND_USER=ORACLEMCP_D4_CATALOG_BLIND
ORACLEMCP_D4_CATALOG_BLIND_PASSWORD=D4_Privilege_Test_42
ORACLEMCP_D4_CATALOG_OBJECT_ID=${object_id}
ENV
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
  output="$(ORACLE_PASSWORD="$password" PDB="$pdb" timeout -k 5 60 docker exec -i \
    -e ORACLE_PASSWORD -e PDB "$container" bash -c \
    'sqlplus -S -L "sys/\"$ORACLE_PASSWORD\"@localhost:1521/$PDB as sysdba"' <<'SQL'
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

# `run` cleanup: stop only lanes this process started.
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

container_is_owned() {
  [ "$(docker inspect --format '{{index .Config.Labels "oraclemcp.rig"}}' "$1" 2>/dev/null || true)" = '1' ]
}

# `down`: stop (and, only with --remove, remove) lanes that carry the
# oraclemcp.rig=1 label. An unlabelled container is never touched, even under
# a lane's name: it was not created by this rig.
down_lanes() {
  local lane container
  for lane in "${lanes[@]}"; do
    container="$(lane_container "$lane")"
    if [ "$E2E_DRY_RUN" = '1' ]; then
      e2e_log_event 'container_down' 'teardown' 'skipped' 0 "lane=$lane container=$container dry-run"
      continue
    fi
    if ! container_exists "$container"; then
      e2e_log_event 'container_down' 'teardown' 'skipped' 0 "lane=$lane container=$container absent"
      continue
    fi
    if ! container_is_owned "$container"; then
      e2e_log_event 'container_down' 'teardown' 'skipped' 0 "lane=$lane container=$container not labelled $RIG_LABEL; left untouched"
      continue
    fi
    if container_running "$container"; then
      timeout -k 5 60 docker stop "$container" >/dev/null
    fi
    if [ "$REMOVE_LANES" = '1' ]; then
      timeout -k 5 60 docker rm "$container" >/dev/null
      e2e_log_event 'container_down' 'teardown' 'pass' 0 "lane=$lane container=$container stopped and removed (--remove)"
    else
      e2e_log_event 'container_down' 'teardown' 'pass' 0 "lane=$lane container=$container stopped"
    fi
  done
}

# One JSON line per lane (rig.sh doctor consumes this).
status_lanes() {
  local lane container image port present running owned digest version
  for lane in "${lanes[@]}"; do
    container="$(lane_container "$lane")"
    image="$(lane_image "$lane")"
    port="$(lane_host_port "$lane")"
    present=false running=false owned=false digest='' version=''
    if [ "$E2E_DRY_RUN" != '1' ] && container_exists "$container"; then
      present=true
      container_running "$container" && running=true
      container_is_owned "$container" && owned=true
      digest="$(docker image inspect --format '{{join .RepoDigests ","}}' \
        "$(docker inspect --format '{{.Image}}' "$container")" 2>/dev/null || true)"
      version="$(docker inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$container" 2>/dev/null || true)"
    fi
    python3 -c 'import json, sys; keys = ["lane", "container", "pinned_image", "port", "present", "healthy", "owned", "image_digests", "version"]; vals = sys.argv[1:]; row = dict(zip(keys, vals)); [row.__setitem__(k, row[k] == "true") for k in ("present", "healthy", "owned")]; row["port"] = int(row["port"]); print(json.dumps(row, sort_keys=True))' \
      "$lane" "$container" "$image" "$port" "$present" "$running" "$owned" "$digest" "$version"
  done
}

# Offline selftest: the inventory is complete and pinned, the free23 pin equals
# CI's, no rig file references another repository's checkout (proved against a
# planted reference), and a planted admin password never reaches a log line.
selftest() {
  local failures=0 lane field file planted canary logdir
  for lane in "${lanes[@]}"; do
    for field in container image host_port pdb; do
      lane_field "$lane" "$field" >/dev/null || { echo "selftest: lane $lane lacks $field" >&2; failures=1; }
    done
    [[ "$(lane_image "$lane")" == *@sha256:* ]] || { echo "selftest: lane $lane image is not pinned by digest" >&2; failures=1; }
  done
  grep -F "image: $(lane_image free23)" "$ROOT/.github/workflows/ci.yml" >/dev/null ||
    { echo "selftest: free23 image differs from the ci.yml oracle-free23 pin" >&2; failures=1; }
  rig_files=("$ROOT/scripts/rig/oracle_l1.sh" "$LANES_TOML" "$BOOTSTRAP_SQL" "$ROOT/scripts/e2e/lib.sh")
  # The pattern is assembled from pieces so this file never matches itself.
  local driver_repo='rust''-oracledb' driver_root='ORACLEMCP_''DRIVER_ROOT' driver_hook='bootstrap_''live_schema'
  local foreign_pattern="$driver_repo|$driver_root|$driver_hook"
  scan_foreign() { grep -nE "$foreign_pattern" "$@"; }
  for file in "${rig_files[@]}"; do
    if scan_foreign "$file" >/dev/null; then
      echo "selftest: $file references another repository's checkout" >&2
      failures=1
    fi
  done
  planted="$(mktemp)"
  printf 'bash "$ROOT/../%s/scripts/%s.sh"\n' "$driver_repo" "$driver_hook" >"$planted"
  scan_foreign "$planted" >/dev/null || { echo "selftest: the foreign-reference scan missed a planted reference" >&2; failures=1; }
  canary="RigCanary$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
  logdir="$(mktemp -d)"
  ORACLEMCP_RIG_L1_ADMIN_PASSWORD="$canary" E2E_ARTIFACT_DIR="$logdir" ORACLEMCP_E2E_ARTIFACT_DIR="$logdir" \
    bash "$ROOT/scripts/rig/oracle_l1.sh" run --log --dry-run >"$logdir/stdout" 2>"$logdir/stderr" ||
    { echo "selftest: dry-run failed" >&2; failures=1; }
  if grep -rF "$canary" "$logdir" >/dev/null; then
    echo "selftest: the planted admin password reached a log line" >&2
    failures=1
  fi
  [ "$failures" = '0' ] || return 1
  echo "oracle_l1 selftest: OK (3 pinned lanes, free23 pin = ci.yml, no foreign checkout reference, password canary absent)"
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
    up | wait | bootstrap | fixtures | smoke | status | drcp-identity | privilege-matrix | down | run)
      command="$1"
      shift
      ;;
    --selftest)
      selftest
      exit $?
      ;;
  esac
fi
only_lane=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --lane)
      [ "$#" -ge 2 ] || e2e_finish_fail '--lane requires xe18, xe21 or free23'
      only_lane="$2"
      shift 2
      continue
      ;;
    --remove)
      REMOVE_LANES=1
      shift
      continue
      ;;
  esac
  set +e
  e2e_parse_common_arg "$1"
  parsed=$?
  set -e
  case "$parsed" in
    0) shift; continue ;;
    3) usage; exit 0 ;;
    1) e2e_finish_fail "unknown argument: $1" ;;
  esac
done
if [ -n "$only_lane" ]; then
  case "$only_lane" in
    xe18 | xe21 | free23) lanes=("$only_lane") ;;
    *) e2e_finish_fail "unknown lane: $only_lane" ;;
  esac
fi
[ "$REMOVE_LANES" = '0' ] || [ "$command" = 'down' ] || e2e_finish_fail '--remove is only valid with down'

require_runtime_tools
e2e_log_event 'scenario_start' 'setup' 'running' 0 "Rig L1 command=$command lanes=${lanes[*]}"
for lane in "${lanes[@]}"; do
  e2e_log_event 'lane_plan' 'setup' 'pass' 0 "lane=$lane container=$(lane_container "$lane") image=$(lane_image "$lane") port=$(lane_host_port "$lane") pdb=$(lane_pdb "$lane")"
done

case "$command" in
  up)
    # Sequential per lane: create/start, readiness, bootstrap, smoke.
    for lane in "${lanes[@]}"; do
      start_lane "$lane"
      wait_lane "$lane"
      bootstrap_lane "$lane"
      smoke_lane "$lane"
    done
    ;;
  status)
    status_lanes
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
  privilege-matrix)
    privilege_matrix_fixture
    ;;
  down)
    down_lanes
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
