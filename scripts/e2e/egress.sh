#!/usr/bin/env bash
# Governed-egress live matrix (bead oraclemcp-epic-09x-alien-6sj8.4.6).
#
# The egress seam is the last thing between a live Oracle row and the model, so
# a missing test here is a data-exfiltration hole, not a regression. This drives
# `crates/oraclemcp-db/tests/live_egress.rs` across the lab lanes and logs one
# event per case per lane:
#
#   1. tokenization                — a configured sensitive column egresses as a
#                                    stable token, never plaintext
#   2. mask-unknown-default        — an unconfigured column is masked anyway
#                                    (fail-closed)
#   3. no-plaintext-through-self-join — a self-join over a tokenized column keeps
#                                    the join relation (equal plaintext => equal
#                                    token) while leaking no plaintext
#   4. certificate re-derivation   — the per-result mask certificate re-derives
#                                    to the same decisions and agrees with the row
#
# Lab containers ONLY (lib.sh refuses production-looking targets).
#
# Required env (opt-in gate + per-lane credentials):
#   ORACLEMCP_LIVE_XE=1
#   ORACLE_MATRIX_<LANE>_USER / _PASSWORD     (LANE = XE18 | XE21 | FREE23)
# Optional:
#   ORACLE_MATRIX_<LANE>_DSN   (defaults: localhost:1518/XEPDB1,
#                                         localhost:1520/XEPDB1,
#                                         localhost:1522/FREEPDB1)
#   ORACLE_EGRESS_LANE_TIMEOUT_SECS (default 600, per case)
#
# Options:
#   --lane xe18|xe21|free23   (repeatable; default: all three)
#   plus the common --log / --dry-run / --help.
#
# A configured lane whose case SKIPs (unreachable DB) is a FAILURE, not a pass:
# a security gate that silently tests nothing is the failure mode this suite
# exists to prevent.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="egress"
E2E_LANE="governed-egress"
E2E_PROFILE="live-matrix"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

CASES=(
  live_egress_tokenizes_a_configured_sensitive_column
  live_egress_masks_an_unconfigured_column_by_default
  live_egress_self_join_over_a_tokenized_column_leaks_no_plaintext
  live_egress_mask_certificate_re_derives_the_decision
)

selected_lanes=()
expect_lane_arg=0
for arg in "$@"; do
  if [ "$expect_lane_arg" = "1" ]; then
    selected_lanes+=("$arg")
    expect_lane_arg=0
    continue
  fi
  case "$arg" in
    --lane)
      expect_lane_arg=1
      continue
      ;;
  esac
  set +e
  e2e_parse_common_arg "$arg"
  parsed=$?
  set -e
  case "$parsed" in
    0) continue ;;
    3)
      echo "Run the governed-egress live matrix (masking, tokenization, inference, certificate)."
      echo "  --lane xe18|xe21|free23   restrict to one lane (repeatable)"
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "egress: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done
if [ "$expect_lane_arg" = "1" ]; then
  echo "egress: --lane requires a value" >&2
  exit 2
fi
if [ "${#selected_lanes[@]}" -eq 0 ]; then
  selected_lanes=(xe18 xe21 free23)
fi

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

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "governed-egress matrix lanes=${selected_lanes[*]}"

if [ "${ORACLEMCP_LIVE_XE:-}" != "1" ]; then
  e2e_finish_skip "set ORACLEMCP_LIVE_XE=1 plus ORACLE_MATRIX_*_USER/_PASSWORD to run the governed-egress matrix"
fi

for lane in "${selected_lanes[@]}"; do
  if ! lane_dsn "$lane" >/dev/null 2>&1; then
    e2e_finish_fail "unknown lane: $lane (expected xe18, xe21, or free23)"
  fi
  dsn="$(lane_dsn "$lane")"
  user="$(lane_user "$lane")"
  upper="$(printf '%s' "$lane" | tr '[:lower:]' '[:upper:]')"
  if [ -z "$user" ] || [ -z "$(lane_password "$lane")" ]; then
    e2e_finish_fail "lane $lane is missing ORACLE_MATRIX_${upper}_USER / _PASSWORD"
  fi
  if e2e_value_has_production_marker "$dsn" || e2e_value_has_production_marker "$user"; then
    e2e_finish_fail "refusing production-looking Oracle target for lane $lane"
  fi
  if ! e2e_value_has_test_marker "$dsn"; then
    e2e_finish_fail "lane $lane DSN must include a local/free/xe/test marker"
  fi
done

timeout_secs="${ORACLE_EGRESS_LANE_TIMEOUT_SECS:-600}"
artifact_dir="$(e2e_artifact_dir)"
failures=0

for lane in "${selected_lanes[@]}"; do
  ORACLEMCP_TEST_DSN="$(lane_dsn "$lane")"
  ORACLEMCP_TEST_USER="$(lane_user "$lane")"
  ORACLEMCP_TEST_PASSWORD="$(lane_password "$lane")"
  export ORACLEMCP_TEST_DSN ORACLEMCP_TEST_USER ORACLEMCP_TEST_PASSWORD
  e2e_log_event "lane_start" "setup" "running" 0 "lane=$lane dsn=$ORACLEMCP_TEST_DSN"

  for case_name in "${CASES[@]}"; do
    start="$(e2e_epoch_ms)"
    e2e_log_event "egress_case_start" "act" "running" 0 "lane=$lane case=$case_name"

    set +e
    e2e_run_command "act" timeout "$timeout_secs" \
      cargo test -p oraclemcp-db --features live-xe --test live_egress \
      -- --exact --nocapture "$case_name"
    status=$?
    set -e
    end="$(e2e_epoch_ms)"

    if [ "$status" -ne 0 ]; then
      failures=$((failures + 1))
      e2e_log_event "egress_case" "assert" "fail" "$((end - start))" "lane=$lane case=$case_name"
      continue
    fi

    # A skipped case exits 0. On a lane the operator explicitly configured, that
    # means the DB was unreachable and the security assertion never ran — which
    # must not be reported as a pass.
    if grep -q '\[live-xe\] SKIP' "$artifact_dir/output.txt" 2>/dev/null; then
      failures=$((failures + 1))
      e2e_log_event "egress_case" "assert" "fail" "$((end - start))" \
        "lane=$lane case=$case_name skipped-on-a-configured-lane (unreachable Oracle: the egress assertion never ran)"
      continue
    fi

    e2e_log_event "egress_case" "assert" "pass" "$((end - start))" "lane=$lane case=$case_name"
  done

  e2e_log_event "lane_complete" "assert" "pass" 0 "lane=$lane"
done

if [ "$failures" -ne 0 ]; then
  e2e_finish_fail "governed-egress matrix: $failures case(s) failed"
fi
e2e_log_event "scenario_assert" "assert" "pass" 0 \
  "governed-egress matrix green: ${#CASES[@]} cases x ${#selected_lanes[@]} lane(s)"
e2e_finish_pass
