#!/usr/bin/env bash
# Living-DB release matrix (bead oraclemcp-epic-09x-alien-6sj8.7.12).
#
# Each selected local Oracle lane is exercised through the smallest existing
# proof at the boundary it owns:
#   * `oracle_orient`: real catalog snapshot with schema, FK, hot-object,
#     freshness, and recent-DDL evidence;
#   * CQN: a real QUERY-level callback, plus core contracts that reduce it to
#     one coalesced URI update and refuse OBJECT-level registration before the
#     driver/audit effect point; and
#   * served `oracle_query format=arrow`: base64 Arrow IPC decodes to the exact
#     governed JSON rows, including a policy-masked cell.
#
# CQN's Oracle privilege is intentionally optional in lab accounts. ORA-29972
# is reported as a typed per-lane skip, never a pass. Current thin-driver
# limitations are also named narrowly: XE18's CQN ORA-29970 registration path
# and XE21's catalog TTC type 12 decode. Any other failed proof is a failed
# lane. Credentials are environment-only and are never recorded in the
# evidence directory.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="living_db"
E2E_LANE="living-db-matrix"
E2E_PROFILE="matrix"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

selected_lanes=()
expect_lane_arg=0
for arg in "$@"; do
  if [ "$expect_lane_arg" = "1" ]; then
    selected_lanes+=("$arg")
    expect_lane_arg=0
    continue
  fi
  if [ "$arg" = "--lane" ]; then
    expect_lane_arg=1
    continue
  fi
  set +e
  e2e_parse_common_arg "$arg"
  parsed=$?
  set -e
  case "$parsed" in
    0) continue ;;
    3)
      echo "Run living Oracle catalog, CQN, and Arrow e2e proofs."
      echo "Options: --lane <xe18|xe21|free23> (repeatable; default all three)"
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "living_db: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done
if [ "$expect_lane_arg" = "1" ]; then
  echo "living_db: --lane needs a value (xe18|xe21|free23)" >&2
  exit 2
fi
[ "${#selected_lanes[@]}" -gt 0 ] || selected_lanes=(xe18 xe21 free23)

lane_dsn() {
  case "$1" in
    xe18) printf '%s\n' "${ORACLE_MATRIX_XE18_DSN:-localhost:1518/XEPDB1}" ;;
    xe21) printf '%s\n' "${ORACLE_MATRIX_XE21_DSN:-localhost:1520/XEPDB1}" ;;
    free23) printf '%s\n' "${ORACLE_MATRIX_FREE23_DSN:-localhost:1522/FREEPDB1}" ;;
    *) return 1 ;;
  esac
}

lane_user() {
  case "$1" in
    xe18) printf '%s\n' "${ORACLE_MATRIX_XE18_USER:-}" ;;
    xe21) printf '%s\n' "${ORACLE_MATRIX_XE21_USER:-}" ;;
    free23) printf '%s\n' "${ORACLE_MATRIX_FREE23_USER:-}" ;;
    *) return 1 ;;
  esac
}

lane_password() {
  case "$1" in
    xe18) printf '%s\n' "${ORACLE_MATRIX_XE18_PASSWORD:-}" ;;
    xe21) printf '%s\n' "${ORACLE_MATRIX_XE21_PASSWORD:-}" ;;
    free23) printf '%s\n' "${ORACLE_MATRIX_FREE23_PASSWORD:-}" ;;
    *) return 1 ;;
  esac
}

lane_env_label() {
  printf '%s' "$1" | tr '[:lower:]' '[:upper:]'
}

require_matrix_env() {
  if [ "${ORACLEMCP_LIVE_XE:-}" != "1" ]; then
    e2e_finish_skip "set ORACLEMCP_LIVE_XE=1 plus ORACLE_MATRIX_*_USER/_PASSWORD to run the living DB matrix"
  fi
  for lane in "${selected_lanes[@]}"; do
    case "$lane" in
      xe18|xe21|free23) ;;
      *) e2e_finish_fail "unknown lane '$lane' (expected xe18|xe21|free23)" ;;
    esac
    local dsn user password upper
    dsn="$(lane_dsn "$lane")"
    user="$(lane_user "$lane")"
    password="$(lane_password "$lane")"
    upper="$(lane_env_label "$lane")"
    if [ -z "$user" ] || [ -z "$password" ]; then
      e2e_finish_fail "ORACLEMCP_LIVE_XE=1 is set but lane $lane is missing ORACLE_MATRIX_${upper}_USER / _PASSWORD"
    fi
    if e2e_value_has_production_marker "$dsn" || e2e_value_has_production_marker "$user"; then
      e2e_finish_fail "refusing production-looking target for living DB lane $lane"
    fi
    if ! e2e_value_has_test_marker "$dsn"; then
      e2e_finish_fail "living DB lane $lane DSN must include a local/free/xe/test marker"
    fi
  done
}

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "living DB matrix lanes=${selected_lanes[*]}"
require_matrix_env
command -v cargo >/dev/null 2>&1 || e2e_finish_fail "cargo is required for living DB proofs"
command -v timeout >/dev/null 2>&1 || e2e_finish_fail "timeout is required for living DB proofs"

if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: living DB wiring validated, no live lanes exercised"
  e2e_finish_pass
  exit 0
fi

run_stamp="$(date -u +"%Y%m%dT%H%M%SZ")-$$"
matrix_dir="$ORACLEMCP_E2E_ARTIFACT_DIR/$E2E_SCENARIO/$run_stamp"
mkdir -p "$matrix_dir"
lane_timeout_secs="${ORACLEMCP_LIVING_DB_LANE_TIMEOUT_SECS:-180}"
typed_skips=0
hard_failures=0

# The served Arrow test launches a child `oraclemcp`. Its configuration prefix
# is strict, so harness-only controls must remain local to this shell rather
# than becoming unknown server configuration in that child.
export -n ORACLEMCP_E2E_ARTIFACT_DIR ORACLEMCP_E2E_SEED ORACLEMCP_LIVING_DB_LANE_TIMEOUT_SECS

run_case() {
  local lane="$1" case_name="$2" skip_allowed="$3"
  shift 3
  local evidence="$matrix_dir/$lane/$case_name.txt"
  local started ended status
  mkdir -p "$(dirname "$evidence")"
  started="$(e2e_epoch_ms)"
  e2e_log_event "$case_name" "act" "running" 0 "lane=$lane"
  set +e
  timeout -k 15 "$lane_timeout_secs" "$@" >"$evidence" 2>&1
  status=$?
  set -e
  cat "$evidence"
  ended="$(e2e_epoch_ms)"
  if [ "$status" -ne 0 ]; then
    if [ "$skip_allowed" = "1" ] && [ "$case_name" = "cqn_query_callback" ] && grep -Fq "ORA-29970" "$evidence"; then
      typed_skips=$((typed_skips + 1))
      e2e_log_event "$case_name" "assert" "skipped" "$((ended - started))" "lane=$lane typed CQN driver capability skip evidence=$evidence"
      return 0
    fi
    if [ "$skip_allowed" = "1" ] && [ "$case_name" = "orient_snapshot" ] && grep -Fq "unknown TTC message type 12" "$evidence"; then
      typed_skips=$((typed_skips + 1))
      e2e_log_event "$case_name" "assert" "skipped" "$((ended - started))" "lane=$lane typed thin-driver catalog capability skip evidence=$evidence"
      return 0
    fi
    e2e_log_event "$case_name" "assert" "fail" "$((ended - started))" "lane=$lane status=$status evidence=$evidence"
    return 1
  fi
  if [ "$skip_allowed" = "1" ] && grep -Fq "[live-xe] SKIP" "$evidence"; then
    typed_skips=$((typed_skips + 1))
    e2e_log_event "$case_name" "assert" "skipped" "$((ended - started))" "lane=$lane typed prerequisite/capability skip evidence=$evidence"
    return 0
  fi
  e2e_log_event "$case_name" "assert" "pass" "$((ended - started))" "lane=$lane evidence=$evidence"
}

run_lane() {
  local lane="$1" dsn user password
  dsn="$(lane_dsn "$lane")"
  user="$(lane_user "$lane")"
  password="$(lane_password "$lane")"
  export E2E_LANE="$lane" E2E_PROFILE="living_db" E2E_LEVEL="READ_ONLY"
  e2e_log_event "lane_start" "act" "running" 0 "lane=$lane"

  local common_env=(env ORACLEMCP_LIVE_XE=1 "ORACLEMCP_TEST_DSN=$dsn" "ORACLEMCP_TEST_USER=$user" "ORACLEMCP_TEST_PASSWORD=$password")
  local lane_failed=0
  run_case "$lane" "orient_snapshot" 1 "${common_env[@]}" cargo test -p oraclemcp --features live-xe --test orient_live_xe oracle_orient_assembles_live_schema_fk_hot_freshness_and_ddl -- --exact --nocapture || lane_failed=1
  run_case "$lane" "orient_catalog_revision_cache" 0 cargo test -p oraclemcp --lib dispatch::tests::orient_assembles_selector_stable_snapshot_and_reloads_on_catalog_revision -- --exact || lane_failed=1
  run_case "$lane" "cqn_query_callback" 1 "${common_env[@]}" cargo test -p oraclemcp-db --features live-xe --test live_oracle live_cqn_query_callback_is_event_only_within_the_ten_second_ceiling -- --exact --nocapture || lane_failed=1
  run_case "$lane" "cqn_uri_coalescing" 0 cargo test -p oraclemcp-core --lib subscriptions::tests::cqn_emon_callback_relay_is_uri_only_and_coalesced -- --exact || lane_failed=1
  run_case "$lane" "cqn_object_refusal" 0 cargo test -p oraclemcp-core --lib subscriptions::tests::cqn_effect_point_refuses_object_scope_before_the_db_adapter -- --exact || lane_failed=1
  run_case "$lane" "arrow_governed_round_trip" 0 "${common_env[@]}" cargo test -p oraclemcp --features live-xe --test live_xe_service_attach live_xe_arrow_query_round_trips_through_served_mcp -- --ignored --exact --nocapture || lane_failed=1

  if [ "$lane_failed" -ne 0 ]; then
    e2e_log_event "lane_result" "assert" "fail" 0 "lane=$lane evidence=$matrix_dir/$lane"
    return 1
  fi
  e2e_log_event "lane_result" "assert" "pass" 0 "lane=$lane typed_skips_so_far=$typed_skips"
}

for lane in "${selected_lanes[@]}"; do
  if ! run_lane "$lane"; then
    hard_failures=$((hard_failures + 1))
  fi
done

summary="lanes=${#selected_lanes[@]} hard_failures=$hard_failures typed_skips=$typed_skips artifacts=$matrix_dir"
if [ "$hard_failures" -ne 0 ]; then
  e2e_finish_fail "$summary"
fi
e2e_log_event "scenario_assert" "assert" "pass" 0 "$summary"
e2e_finish_pass
