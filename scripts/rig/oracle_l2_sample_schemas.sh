#!/usr/bin/env bash
# Rig L2: load the vendored MIT sample schemas plus the synthetic governance
# overlay into local lab containers.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="rig_l2_sample_schemas"
E2E_LANE="oracle-l2"
E2E_PROFILE="container-lab"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

SAMPLE_ROOT="$ROOT/tests/fixtures/sample_schemas"
UPSTREAM_DIR="$SAMPLE_ROOT/upstream"
GOVERNANCE_SQL="$SAMPLE_ROOT/governance/governance_overlay.sql"
VERIFY_VENDOR="$ROOT/scripts/rig/verify_sample_schemas.sh"
D4_SQL="$ROOT/scripts/rig/oracle_l1_privilege_matrix.sql"
RUN_ID="${ORACLEMCP_RIG_L2_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
REMOTE_ROOT="/tmp/oraclemcp-d9-$RUN_ID"
LANES="${ORACLEMCP_RIG_L2_LANES:-free23 xe21}"
BOOTSTRAP_TIMEOUT_SECS="${ORACLEMCP_RIG_L2_BOOTSTRAP_TIMEOUT_SECS:-420}"
SAMPLE_PASSWORD="${ORACLEMCP_RIG_L2_SAMPLE_PASSWORD:-D9_Sample_Test_42}"
COMMON_ADMIN_PASSWORD="${ORACLEMCP_RIG_L1_ADMIN_PASSWORD:-}"

usage() {
  cat <<'USAGE'
Rig L2 sample-schema loader.

Usage:
  bash scripts/rig/oracle_l2_sample_schemas.sh run [--log|--dry-run]
  bash scripts/rig/oracle_l2_sample_schemas.sh verify [--log|--dry-run]

Loads HR and CO with upstream install scripts, SH as structure-only from
sh_create.sql (the large SH CSVs are deliberately not vendored), then applies
the synthetic governance overlay.

Environment:
  ORACLEMCP_RIG_L2_LANES                  lanes to run, default: "free23 xe21"
  ORACLEMCP_RIG_L2_BOOTSTRAP_TIMEOUT_SECS per SQL step ceiling, default: 420
  ORACLEMCP_RIG_L2_SAMPLE_PASSWORD        synthetic HR/CO/SH password
USAGE
  e2e_usage_common
}

parse_common_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --help|-h) usage; exit 0 ;;
      *)
        if e2e_parse_common_arg "$1"; then shift; continue; fi
        case $? in
          3) usage; exit 0 ;;
          *) e2e_finish_fail "unknown argument: $1" ;;
        esac
        ;;
    esac
    shift
  done
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
  local lane="$1" explicit_password container configured_password
  case "$lane" in
    xe18) explicit_password="${ORACLEMCP_RIG_L1_XE18_ADMIN_PASSWORD:-$COMMON_ADMIN_PASSWORD}" ;;
    xe21) explicit_password="${ORACLEMCP_RIG_L1_XE21_ADMIN_PASSWORD:-$COMMON_ADMIN_PASSWORD}" ;;
    free23) explicit_password="${ORACLEMCP_RIG_L1_FREE23_ADMIN_PASSWORD:-$COMMON_ADMIN_PASSWORD}" ;;
    *) return 1 ;;
  esac
  if [ -n "$explicit_password" ]; then
    printf '%s\n' "$explicit_password"
    return 0
  fi
  container="$(lane_container "$lane")"
  configured_password="$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$container" 2>/dev/null \
    | awk -F= '$1 == "ORACLE_PASSWORD" { print substr($0, index($0, "=") + 1); exit }')"
  printf '%s\n' "$configured_password"
}

require_tools() {
  command -v docker >/dev/null 2>&1 || e2e_finish_fail 'docker is required for rig L2'
  command -v timeout >/dev/null 2>&1 || e2e_finish_fail 'timeout is required for bounded rig L2 commands'
  [ -x "$VERIFY_VENDOR" ] || e2e_finish_fail "sample-schema verifier is not executable: $VERIFY_VENDOR"
  [ -r "$GOVERNANCE_SQL" ] || e2e_finish_fail "governance overlay is not readable: $GOVERNANCE_SQL"
  [ -r "$D4_SQL" ] || e2e_finish_fail "D4 privilege fixture is not readable: $D4_SQL"
  [[ "$BOOTSTRAP_TIMEOUT_SECS" =~ ^[1-9][0-9]*$ ]] || e2e_finish_fail 'ORACLEMCP_RIG_L2_BOOTSTRAP_TIMEOUT_SECS must be a positive integer'
}

container_running() {
  [ "$(docker inspect --format '{{.State.Running}}' "$1" 2>/dev/null || true)" = 'true' ]
}

require_lane() {
  local lane="$1" container
  container="$(lane_container "$lane")" || e2e_finish_fail "unknown rig L2 lane: $lane"
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "l2_lane_preflight" "assert" "skipped" 0 "lane=$lane dry-run"
    return 0
  fi
  container_running "$container" || e2e_finish_fail "lane=$lane container is not running: $container"
  [ -n "$(lane_admin_password "$lane")" ] || e2e_finish_fail "lane=$lane has no Docker-configured ORACLE_PASSWORD; set ORACLEMCP_RIG_L1_$(printf '%s' "$lane" | tr '[:lower:]' '[:upper:]')_ADMIN_PASSWORD"
  docker exec "$container" command -v sqlplus >/dev/null 2>&1 || e2e_finish_fail "lane=$lane has no sqlplus inside $container"
  e2e_log_event "l2_lane_preflight" "assert" "pass" 0 "lane=$lane container=$container"
}

copy_fixture_tree() {
  local lane="$1" container
  container="$(lane_container "$lane")"
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "l2_fixture_copy" "setup" "skipped" 0 "lane=$lane remote=$REMOTE_ROOT dry-run"
    return 0
  fi
  timeout -k 5 60 docker exec "$container" mkdir -p "$REMOTE_ROOT/upstream" "$REMOTE_ROOT/governance"
  timeout -k 5 120 docker cp "$UPSTREAM_DIR/." "$container:$REMOTE_ROOT/upstream/"
  timeout -k 5 60 docker cp "$GOVERNANCE_SQL" "$container:$REMOTE_ROOT/governance/governance_overlay.sql"
  timeout -k 5 60 docker cp "$D4_SQL" "$container:$REMOTE_ROOT/governance/oracle_l1_privilege_matrix.sql"
  timeout -k 5 60 docker exec --user root "$container" chmod -R ugo+rwX "$REMOTE_ROOT"
  e2e_log_event "l2_fixture_copy" "setup" "pass" 0 "lane=$lane remote=$REMOTE_ROOT"
}

sqlplus_system() {
  local lane="$1" cwd="$2" sql="$3" container pdb password
  container="$(lane_container "$lane")"
  pdb="$(lane_pdb "$lane")"
  password="$(lane_admin_password "$lane")"
  timeout -k 10 "$BOOTSTRAP_TIMEOUT_SECS" docker exec -i \
    --env "ORA_PW=$password" \
    --env "ORA_PDB=$pdb" \
    --env "SAMPLE_PASSWORD=$SAMPLE_PASSWORD" \
    "$container" bash -lc "cd '$cwd' && sqlplus -S -L \"system/\${ORA_PW}@localhost:1521/\${ORA_PDB}\"" <<<"$sql"
}

load_hr_schema() {
  local lane="$1" started status=0 output
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "l2_schema_load" "act" "skipped" 0 "lane=$lane schema=HR dry-run"
    return 0
  fi
  started="$(e2e_epoch_ms)"
  e2e_log_event "l2_schema_load" "act" "running" 0 "lane=$lane schema=HR"
  set +e
  output="$(sqlplus_system "$lane" "$REMOTE_ROOT/upstream/human_resources" "
whenever sqlerror exit failure
set echo off feedback off heading off verify off
column default_tbs new_value default_tbs noprint
select property_value default_tbs
  from database_properties
 where property_name = 'DEFAULT_PERMANENT_TABLESPACE';
begin
  execute immediate 'drop user HR cascade';
exception
  when others then
    if sqlcode != -1918 then
      raise;
    end if;
end;
/
create user hr identified by \"$SAMPLE_PASSWORD\"
  default tablespace &default_tbs
  quota unlimited on &default_tbs
/
grant create materialized view,
      create procedure,
      create sequence,
      create session,
      create synonym,
      create table,
      create trigger,
      create type,
      create view
  to hr
/
alter session set current_schema=HR
/
alter session set nls_language=American
/
alter session set nls_territory=America
/
@hr_create.sql
@hr_populate.sql
@hr_code.sql
exit
" 2>&1)"
  status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    printf '%s\n' "$output"
    e2e_log_event "l2_schema_load" "assert" "fail" "$(( $(e2e_epoch_ms) - started ))" "lane=$lane schema=HR"
    e2e_finish_fail "lane=$lane schema=HR install failed"
  fi
  e2e_log_event "l2_schema_load" "assert" "pass" "$(( $(e2e_epoch_ms) - started ))" "lane=$lane schema=HR"
}

load_co_schema() {
  local lane="$1" started status=0 output
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "l2_schema_load" "act" "skipped" 0 "lane=$lane schema=CO dry-run"
    return 0
  fi
  started="$(e2e_epoch_ms)"
  e2e_log_event "l2_schema_load" "act" "running" 0 "lane=$lane schema=CO"
  set +e
  output="$(sqlplus_system "$lane" "$REMOTE_ROOT/upstream/customer_orders" "
whenever sqlerror exit failure
set echo off feedback off heading off verify off
column default_tbs new_value default_tbs noprint
select property_value default_tbs
  from database_properties
 where property_name = 'DEFAULT_PERMANENT_TABLESPACE';
begin
  execute immediate 'drop user CO cascade';
exception
  when others then
    if sqlcode != -1918 then
      raise;
    end if;
end;
/
create user co identified by \"$SAMPLE_PASSWORD\"
  default tablespace &default_tbs
  quota unlimited on &default_tbs
/
grant create materialized view,
      create procedure,
      create sequence,
      create session,
      create synonym,
      create table,
      create trigger,
      create type,
      create view
  to co
/
alter session set current_schema=CO
/
alter session set nls_language=American
/
alter session set nls_territory=America
/
@co_create.sql
@co_populate.sql
exit
" 2>&1)"
  status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    printf '%s\n' "$output"
    e2e_log_event "l2_schema_load" "assert" "fail" "$(( $(e2e_epoch_ms) - started ))" "lane=$lane schema=CO"
    e2e_finish_fail "lane=$lane schema=CO install failed"
  fi
  e2e_log_event "l2_schema_load" "assert" "pass" "$(( $(e2e_epoch_ms) - started ))" "lane=$lane schema=CO"
}

load_sh_structure_only() {
  local lane="$1" started status=0 output
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "l2_schema_load" "act" "skipped" 0 "lane=$lane schema=SH structure-only dry-run"
    return 0
  fi
  started="$(e2e_epoch_ms)"
  e2e_log_event "l2_schema_load" "act" "running" 0 "lane=$lane schema=SH structure-only"
  set +e
  output="$(sqlplus_system "$lane" "$REMOTE_ROOT/upstream/sales_history" '
whenever sqlerror exit failure
set echo off feedback off heading off verify off
column default_tbs new_value default_tbs noprint
select property_value default_tbs
  from database_properties
 where property_name = '"'DEFAULT_PERMANENT_TABLESPACE'"';
begin
  execute immediate '"'drop user SH cascade'"';
exception
  when others then
    if sqlcode != -1918 then
      raise;
    end if;
end;
/
create user sh identified by "'"${SAMPLE_PASSWORD}"'"
  default tablespace &default_tbs
  quota unlimited on &default_tbs
/
grant create materialized view,
      create dimension,
      create procedure,
      create sequence,
      create session,
      create synonym,
      create table,
      create trigger,
      create type,
      create view
  to sh
/
alter session set current_schema=SH
/
alter session set nls_language=American
/
alter session set nls_territory=America
/
@sh_create.sql
exit
' 2>&1)"
  status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    printf '%s\n' "$output"
    e2e_log_event "l2_schema_load" "assert" "fail" "$(( $(e2e_epoch_ms) - started ))" "lane=$lane schema=SH structure-only"
    e2e_finish_fail "lane=$lane schema=SH structure-only install failed"
  fi
  e2e_log_event "l2_schema_load" "assert" "pass" "$(( $(e2e_epoch_ms) - started ))" "lane=$lane schema=SH structure-only"
}

load_governance_overlay() {
  local lane="$1" started status=0 output
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "l2_governance_load" "act" "skipped" 0 "lane=$lane dry-run"
    return 0
  fi
  started="$(e2e_epoch_ms)"
  e2e_log_event "l2_governance_load" "act" "running" 0 "lane=$lane"
  set +e
  output="$(sqlplus_system "$lane" "$REMOTE_ROOT/governance" '@oracle_l1_privilege_matrix.sql
' 2>&1)"
  status=$?
  if [ "$status" -eq 0 ]; then
    output="$output
$(sqlplus_system "$lane" "$REMOTE_ROOT/governance" '@governance_overlay.sql
exit
' 2>&1)"
    status=$?
  fi
  set -e
  if [ "$status" -ne 0 ]; then
    printf '%s\n' "$output"
    e2e_log_event "l2_governance_load" "assert" "fail" "$(( $(e2e_epoch_ms) - started ))" "lane=$lane"
    e2e_finish_fail "lane=$lane governance overlay failed"
  fi
  e2e_log_event "l2_governance_load" "assert" "pass" "$(( $(e2e_epoch_ms) - started ))" "lane=$lane"
}

assert_l2_objects() {
  local lane="$1" started status=0 output
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "l2_object_assert" "assert" "skipped" 0 "lane=$lane dry-run"
    return 0
  fi
  started="$(e2e_epoch_ms)"
  set +e
  output="$(sqlplus_system "$lane" "$REMOTE_ROOT" '
whenever sqlerror exit failure
set echo off feedback off heading off verify off
declare
  n pls_integer;
begin
  select count(*) into n from dba_tables where owner = '"'HR'"';
  if n < 7 then raise_application_error(-20910, '"'HR table shape missing'"'); end if;
  select count(*) into n from hr.employees;
  if n != 107 then raise_application_error(-20911, '"'HR row fixture drift'"'); end if;

  select count(*) into n from dba_tables where owner = '"'CO'"';
  if n < 7 then raise_application_error(-20912, '"'CO table shape missing'"'); end if;
  select count(*) into n from co.orders;
  if n != 1950 then raise_application_error(-20913, '"'CO row fixture drift'"'); end if;

  select count(*) into n
    from dba_tables
   where owner = '"'SH'"'
     and table_name in (
       '"'CHANNELS'"','"'COSTS'"','"'COUNTRIES'"','"'CUSTOMERS'"','"'PRODUCTS'"',
       '"'PROMOTIONS'"','"'SALES'"','"'TIMES'"','"'SUPPLEMENTARY_DEMOGRAPHICS'"'
     );
  if n != 9 then raise_application_error(-20914, '"'SH structure-only tables missing'"'); end if;
  select count(*) into n from dba_mviews where owner = '"'SH'"';
  if n < 2 then raise_application_error(-20915, '"'SH materialized views missing'"'); end if;

  select count(*) into n
    from dba_synonyms
   where owner = '"'ORACLEMCP_D4_OWNER'"'
     and synonym_name = '"'ORACLEMCP_D9_GUARDED_SYN'"';
  if n != 1 then raise_application_error(-20916, '"'D9 guarded synonym missing'"'); end if;
  select count(*) into n
    from dba_triggers
   where owner = '"'ORACLEMCP_D9_TARGET'"'
     and trigger_name = '"'ORACLEMCP_D9_AFTER_LOGOFF'"';
  if n != 1 then raise_application_error(-20917, '"'D9 logoff trigger missing'"'); end if;
  select count(*) into n
    from dba_tables
   where owner = '"'ORACLEMCP_D9_TARGET'"'
     and table_name in ('"'ORACLEMCP_D9_OWNED_ROWS'"','"'ORACLEMCP_D9_LOGOFF_LOG'"');
  if n != 2 then raise_application_error(-20918, '"'D9 proxy/logoff tables missing'"'); end if;
end;
/
prompt oraclemcp-d9-sample-schemas-ready
exit
' 2>&1)"
  status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    printf '%s\n' "$output"
    e2e_log_event "l2_object_assert" "assert" "fail" "$(( $(e2e_epoch_ms) - started ))" "lane=$lane"
    e2e_finish_fail "lane=$lane L2 object assertions failed"
  fi
  printf '%s\n' "$output" | grep -F 'oraclemcp-d9-sample-schemas-ready' >/dev/null \
    || e2e_finish_fail "lane=$lane L2 assertion sentinel missing"
  e2e_log_event "l2_object_assert" "assert" "pass" "$(( $(e2e_epoch_ms) - started ))" "lane=$lane HR/CO/SH/governance objects verified"
}

run_lane() {
  local lane="$1"
  require_lane "$lane"
  copy_fixture_tree "$lane"
  load_hr_schema "$lane"
  load_co_schema "$lane"
  load_sh_structure_only "$lane"
  load_governance_overlay "$lane"
  assert_l2_objects "$lane"
}

cmd="${1:-run}"
if [ "$#" -gt 0 ]; then
  shift
fi
parse_common_args "$@"
require_tools

case "$cmd" in
  verify)
    bash "$VERIFY_VENDOR"
    e2e_finish_pass
    ;;
  run)
    bash "$VERIFY_VENDOR"
    for lane in $LANES; do
      run_lane "$lane"
    done
    e2e_finish_pass
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
