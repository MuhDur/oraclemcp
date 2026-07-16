#!/usr/bin/env bash
# Live lineage feature lane (bead oraclemcp-epic-09x-alien-6sj8.9.5).
#
# Each selected local Oracle lane runs the real `oracle_lineage` catalog proof:
# a source-derived view edge is verified against the catalog, then the same
# fixture proves type and missing-object drift markers. The wrapped-body case is
# deliberately source-only: its typed `WrappedSource` marker proves partial
# lineage without inventing an edge or making a database utility call.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="live_lineage"
E2E_LANE="lineage-matrix"
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
      echo "Run live Oracle lineage markers over XE 18, XE 21, and FREE 23ai."
      echo "Options: --lane <xe18|xe21|free23> (repeatable; default all three)"
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "live_lineage: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done
if [ "$expect_lane_arg" = "1" ]; then
  echo "live_lineage: --lane needs a value (xe18|xe21|free23)" >&2
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
    e2e_finish_skip "set ORACLEMCP_LIVE_XE=1 plus ORACLE_MATRIX_*_USER/_PASSWORD to run live lineage"
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
      e2e_finish_fail "refusing production-looking target for live lineage lane $lane"
    fi
    if ! e2e_value_has_test_marker "$dsn"; then
      e2e_finish_fail "live lineage lane $lane DSN must include a local/free/xe/test marker"
    fi
  done
}

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "live lineage lanes=${selected_lanes[*]}"
require_matrix_env
command -v cargo >/dev/null 2>&1 || e2e_finish_fail "cargo is required for live lineage proofs"
command -v timeout >/dev/null 2>&1 || e2e_finish_fail "timeout is required for live lineage proofs"

if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: live lineage wiring validated, no lanes exercised"
  e2e_finish_pass
  exit 0
fi

run_stamp="$(date -u +"%Y%m%dT%H%M%SZ")-$$"
matrix_dir="$ORACLEMCP_E2E_ARTIFACT_DIR/$E2E_SCENARIO/$run_stamp"
mkdir -p "$matrix_dir"
lane_timeout_secs="${ORACLEMCP_LIVE_LINEAGE_LANE_TIMEOUT_SECS:-180}"
typed_skips=0
hard_failures=0

run_case() {
  local lane="$1" case_name="$2"
  shift 2
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
    e2e_log_event "$case_name" "assert" "fail" "$((ended - started))" "lane=$lane status=$status evidence=$evidence"
    return 1
  fi
  if grep -Fq "[live-xe] SKIP" "$evidence"; then
    typed_skips=$((typed_skips + 1))
    e2e_log_event "$case_name" "assert" "skipped" "$((ended - started))" "lane=$lane typed live prerequisite skip evidence=$evidence"
    return 2
  fi
  e2e_log_event "$case_name" "assert" "pass" "$((ended - started))" "lane=$lane evidence=$evidence"
}

run_wrapped_source_proof() {
  if run_case "source" "wrapped_partial_marker" \
    cargo test -p oraclemcp --features plsql-intelligence --lib \
      plsql_tools::tests::lineage_marks_wrapped_body_as_partial_without_inventing_dependencies \
      -- --exact; then
    :
  else
    local status=$?
    if [ "$status" -eq 2 ]; then
      e2e_finish_fail "wrapped-source lineage proof unexpectedly skipped"
    fi
    e2e_finish_fail "wrapped-source partial lineage proof failed"
  fi
  e2e_log_event "catalog_marker_partial_wrapped_source" "assert" "pass" 0 "source-only wrapped body is marked WrappedSource without a fabricated edge"
}

run_lane() {
  local lane="$1" dsn user password
  dsn="$(lane_dsn "$lane")"
  user="$(lane_user "$lane")"
  password="$(lane_password "$lane")"
  export E2E_LANE="$lane" E2E_PROFILE="live_lineage" E2E_LEVEL="READ_ONLY"
  e2e_log_event "lane_start" "act" "running" 0 "lane=$lane"

  local common_env=(env ORACLEMCP_LIVE_XE=1 "ORACLEMCP_TEST_DSN=$dsn" "ORACLEMCP_TEST_USER=$user" "ORACLEMCP_TEST_PASSWORD=$password")
  if run_case "$lane" "catalog_markers" \
    "${common_env[@]}" cargo test -p oraclemcp --features live-xe,plsql-intelligence \
      --test plsql_live_xe oracle_lineage_live_catalog_marks_verified_missing_and_type_drift \
      -- --nocapture; then
    :
  else
    local status=$?
    if [ "$status" -eq 2 ]; then
      e2e_log_event "lane_result" "assert" "skipped" 0 "lane=$lane typed_skips_so_far=$typed_skips"
      return 0
    fi
    e2e_log_event "lane_result" "assert" "fail" 0 "lane=$lane evidence=$matrix_dir/$lane"
    return 1
  fi

  e2e_log_event "catalog_marker_verified" "assert" "pass" 0 "lane=$lane asserted by catalog_markers"
  e2e_log_event "catalog_marker_drift_type_mismatch" "assert" "pass" 0 "lane=$lane asserted by catalog_markers"
  e2e_log_event "catalog_marker_drift_missing" "assert" "pass" 0 "lane=$lane asserted by catalog_markers"
  e2e_log_event "lane_result" "assert" "pass" 0 "lane=$lane"
}

run_wrapped_source_proof
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
