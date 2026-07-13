#!/usr/bin/env bash
# Live Edition-Based Redefinition lifecycle matrix (Arc D / bead .12.6).
#
# Each selected local lab lane proves the real served surface can:
#   * persist and review a synthetic edition proposal;
#   * create exactly one child edition, then refuse a competing child before
#     Oracle can see it, with the typed ONE_CHILD_EDITION / ORA-38807 contract;
#   * replace a synthetic editionable VIEW while its session is in that child;
#   * merge the reviewed child with an ADMIN confirmation, then prove a NEW
#     session observes it; and
#   * roll back by re-flipping the default, honestly proving a new session is
#     redirected back while never claiming a global instant undo.
#
# Runtime profiles, keys, audit records, and evidence remain under target/e2e.
# No endpoint, account, password, or identifier is committed here.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="editions"
E2E_LANE="editions"
E2E_PROFILE="editions"
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
      echo "Run the governed editions lifecycle E2E matrix (XE 18 / XE 21 / FREE 23ai)."
      echo "Options: --lane <xe18|xe21|free23> (repeatable; default all three)"
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "editions: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done
if [ "$expect_lane_arg" = "1" ]; then
  echo "editions: --lane needs a value (xe18|xe21|free23)" >&2
  exit 2
fi
[ "${#selected_lanes[@]}" -gt 0 ] || selected_lanes=(xe18 xe21 free23)
# Python emits the same structured stage events as the shell harness.  lib.sh
# owns the value, while this export makes a --log request visible to its child.
export E2E_LOG

lane_dsn() {
  case "$1" in
    xe18) printf '%s\n' "${ORACLE_MATRIX_XE18_DSN:-}" ;;
    xe21) printf '%s\n' "${ORACLE_MATRIX_XE21_DSN:-}" ;;
    # The single-lane live-suite input is intentionally a FREE 23ai fallback.
    # Endpoints remain runtime-only: this committed harness names no database.
    free23) printf '%s\n' "${ORACLE_MATRIX_FREE23_DSN:-${ORACLEMCP_TEST_DSN:-}}" ;;
    *) return 1 ;;
  esac
}

lane_user() {
  case "$1" in
    xe18) printf '%s\n' "${ORACLE_MATRIX_XE18_USER:-}" ;;
    xe21) printf '%s\n' "${ORACLE_MATRIX_XE21_USER:-}" ;;
    free23) printf '%s\n' "${ORACLE_MATRIX_FREE23_USER:-${ORACLEMCP_TEST_USER:-}}" ;;
  esac
}

lane_password() {
  case "$1" in
    xe18) printf '%s\n' "${ORACLE_MATRIX_XE18_PASSWORD:-}" ;;
    xe21) printf '%s\n' "${ORACLE_MATRIX_XE21_PASSWORD:-}" ;;
    free23) printf '%s\n' "${ORACLE_MATRIX_FREE23_PASSWORD:-${ORACLEMCP_TEST_PASSWORD:-}}" ;;
  esac
}

# An isolated CI lab may provide a known leaf edition, allowing this harness to
# create its synthetic two-edition branch without touching the shared default
# timeline. It is runtime input only; when omitted the current default is the
# base and an existing child produces the typed connect_or_skip outcome.
lane_base_edition() {
  case "$1" in
    xe18) printf '%s\n' "${ORACLE_MATRIX_XE18_EDITION_BASE:-}" ;;
    xe21) printf '%s\n' "${ORACLE_MATRIX_XE21_EDITION_BASE:-}" ;;
    free23) printf '%s\n' "${ORACLE_MATRIX_FREE23_EDITION_BASE:-${ORACLEMCP_EDITION_BASE:-}}" ;;
  esac
}

require_editions_env() {
  if [ "${ORACLEMCP_LIVE_XE:-}" != "1" ]; then
    e2e_finish_skip "set ORACLEMCP_LIVE_XE=1 plus local lab credentials to run the editions lifecycle matrix"
  fi
  for lane in "${selected_lanes[@]}"; do
    case "$lane" in
      xe18 | xe21 | free23) ;;
      *) e2e_finish_fail "unknown lane '$lane' (expected xe18|xe21|free23)" ;;
    esac
    local dsn user password
    dsn="$(lane_dsn "$lane")"
    user="$(lane_user "$lane")"
    password="$(lane_password "$lane")"
    if [ -z "$dsn" ] || [ -z "$user" ] || [ -z "$password" ]; then
      e2e_finish_fail "ORACLEMCP_LIVE_XE=1 is set but lane $lane is missing its configured DSN, user, or password"
    fi
    if e2e_value_has_production_marker "$dsn" || e2e_value_has_production_marker "$user"; then
      e2e_finish_fail "refusing production-looking target for lane $lane"
    fi
    if ! e2e_value_has_test_marker "$dsn"; then
      e2e_finish_fail "lane $lane DSN must include a local/free/xe/test marker"
    fi
  done
}

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "Arc D editions lifecycle matrix: lanes=${selected_lanes[*]}"
require_editions_env
command -v python3 >/dev/null 2>&1 || e2e_finish_fail "python3 is required for the editions lifecycle harness"
command -v timeout >/dev/null 2>&1 || e2e_finish_fail "timeout is required for the editions lifecycle harness"

if [ -n "${ORACLEMCP_EDITIONS_BINARY:-}" ]; then
  BINARY="$ORACLEMCP_EDITIONS_BINARY"
  e2e_log_event "prebuilt_binary" "setup" "pass" 0 "using explicit prebuilt editions binary"
else
  command -v omcpb >/dev/null 2>&1 || e2e_finish_fail "omcpb is required to build the editions MCP binary"
  if ! e2e_run_command "setup" omcpb build -p oraclemcp --bin oraclemcp; then
    e2e_finish_fail "building the oraclemcp binary through omcpb failed"
  fi
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: editions wiring validated, no live lanes exercised"
    e2e_finish_pass
    exit 0
  fi
  build_output="$(e2e_artifact_dir)/output.txt"
  build_target="$(sed -n 's/^omcpb: lane [0-9][0-9]*  target=\([^ ]*\)  jobs=.*/\1/p' "$build_output" | tail -n 1)"
  [ -n "$build_target" ] || e2e_finish_fail "omcpb completed without reporting its selected target directory"
  BINARY="$build_target/debug/oraclemcp"
fi

if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: editions wiring validated, no live lanes exercised"
  e2e_finish_pass
  exit 0
fi

[ -x "$BINARY" ] || e2e_finish_fail "configured editions binary not found at $BINARY"

run_stamp="$(date -u +"%Y%m%dT%H%M%SZ")-$$"
matrix_dir="$ORACLEMCP_E2E_ARTIFACT_DIR/$E2E_SCENARIO/$run_stamp"
mkdir -p "$matrix_dir"
lane_timeout_secs="${ORACLEMCP_EDITIONS_LANE_TIMEOUT_SECS:-420}"

run_lane() {
  set -e
  local lane="$1"
  local dsn user password base_edition lane_dir audit_file evidence
  dsn="$(lane_dsn "$lane")"
  user="$(lane_user "$lane")"
  password="$(lane_password "$lane")"
  base_edition="$(lane_base_edition "$lane")"
  lane_dir="$matrix_dir/$lane"
  audit_file="$lane_dir/audit.jsonl"
  evidence="$lane_dir/editions_evidence.jsonl"
  mkdir -p "$lane_dir"
  chmod 700 "$lane_dir"

  export E2E_LANE="$lane" E2E_PROFILE="editions_$lane" E2E_LEVEL="READ_ONLY"
  export E2E_EDITIONS_DSN="$dsn" E2E_EDITIONS_USER="$user" E2E_EDITIONS_PASSWORD="$password"
  if [ -n "$base_edition" ]; then
    export E2E_EDITIONS_BASE_EDITION="$base_edition"
  else
    unset E2E_EDITIONS_BASE_EDITION
  fi
  e2e_log_event "editions_lane" "act" "running" 0 "lane $lane: proposal, child stage, test, ADMIN merge, and re-flip rollback"

  set +e
  timeout -k 15 "$lane_timeout_secs" python3 "$ROOT/scripts/e2e/editions_session.py" \
    --binary "$BINARY" \
    --lane "$lane" \
    --run-dir "$lane_dir" \
    --audit-file "$audit_file" \
    --evidence "$evidence"
  local status=$?
  set -e
  unset E2E_EDITIONS_DSN E2E_EDITIONS_USER E2E_EDITIONS_PASSWORD E2E_EDITIONS_BASE_EDITION
  if [ "$status" -eq 77 ]; then
    e2e_log_event "editions_lane" "assert" "skipped" 0 "lane $lane: connect_or_skip (the current default edition already has a child)"
    return 0
  fi
  if [ "$status" -ne 0 ]; then
    e2e_log_event "editions_lane" "assert" "fail" 0 "lane $lane: lifecycle session failed; inspect private artifacts under $lane_dir"
    return 1
  fi

  if ! "$BINARY" --json audit verify "$audit_file" >"$lane_dir/audit_verify.json" 2>"$lane_dir/audit_verify.stderr"; then
    e2e_log_event "audit_verify" "assert" "fail" 0 "lane $lane: audit verify failed"
    return 1
  fi
  if ! python3 - "$lane_dir/audit_verify.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
if report.get("ok") is not True or int(report.get("records", 0)) < 12:
    raise SystemExit(1)
PY
  then
    e2e_log_event "audit_verify" "assert" "fail" 0 "lane $lane: audit chain is invalid or too short"
    return 1
  fi
  e2e_log_event "audit_verify" "assert" "pass" 0 "lane $lane: signed audit chain covers ADMIN elevation, default flip, and re-flip"
  e2e_log_event "editions_lane" "assert" "pass" 0 "lane $lane: propose/test/merge/rollback plus typed one-child and not-editionable refusals passed"
}

overall_fail=0
for lane in "${selected_lanes[@]}"; do
  if ! (run_lane "$lane"); then
    overall_fail=1
  fi
done

if [ "$overall_fail" -ne 0 ]; then
  e2e_finish_fail "one or more editions lifecycle lanes failed (private artifacts: $matrix_dir)"
fi
e2e_finish_pass
