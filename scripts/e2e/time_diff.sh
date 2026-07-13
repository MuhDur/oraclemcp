#!/usr/bin/env bash
# Live flashback/time-diff E2E matrix. Each disposable lab lane proves:
#   * keyed add/remove/change versus two SCNs;
#   * keyless add/remove-only fallback;
#   * typed ORA-01466 and flashback-retention refusals; and
#   * replay of committed oracle_query rows at the hash-covered observed_scn.
#
# Required lab-only opt-in:
#   ORACLEMCP_LIVE_XE=1
#   ORACLE_MATRIX_XE18_USER / ORACLE_MATRIX_XE18_PASSWORD
#   ORACLE_MATRIX_XE21_USER / ORACLE_MATRIX_XE21_PASSWORD
#   ORACLE_MATRIX_FREE23_USER / ORACLE_MATRIX_FREE23_PASSWORD
# Optional: ORACLE_MATRIX_<LANE>_DSN and --lane xe18|xe21|free23.
#
# Oracle can raise ORA-01466 for flashback queries immediately after a table is
# created. The live fixture therefore waits a bounded period after its setup
# DDL before taking either comparison snapshot. Override only in a lab that
# has already aged the fixture deliberately.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="time_diff"
E2E_LANE="time-diff"
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
      echo "Run the Oracle time-diff and SCN replay E2E matrix (XE 18 / XE 21 / FREE 23ai)."
      echo "Options: --lane <xe18|xe21|free23> (repeatable; default all three)"
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "time_diff: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done
if [ "$expect_lane_arg" = "1" ]; then
  echo "time_diff: --lane needs a value (xe18|xe21|free23)" >&2
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
  esac
}

lane_password() {
  case "$1" in
    xe18) printf '%s\n' "${ORACLE_MATRIX_XE18_PASSWORD:-}" ;;
    xe21) printf '%s\n' "${ORACLE_MATRIX_XE21_PASSWORD:-}" ;;
    free23) printf '%s\n' "${ORACLE_MATRIX_FREE23_PASSWORD:-}" ;;
  esac
}

require_time_diff_env() {
  if [ "${ORACLEMCP_LIVE_XE:-}" != "1" ]; then
    e2e_finish_skip "set ORACLEMCP_LIVE_XE=1 plus ORACLE_MATRIX_*_USER/_PASSWORD to run the time-diff matrix"
  fi
  for lane in "${selected_lanes[@]}"; do
    case "$lane" in
      xe18 | xe21 | free23) ;;
      *) e2e_finish_fail "unknown lane '$lane' (expected xe18|xe21|free23)" ;;
    esac
    local dsn user password upper_lane
    dsn="$(lane_dsn "$lane")"
    user="$(lane_user "$lane")"
    password="$(lane_password "$lane")"
    upper_lane="$(printf '%s' "$lane" | tr '[:lower:]' '[:upper:]')"
    if [ -z "$user" ] || [ -z "$password" ]; then
      e2e_finish_fail "ORACLEMCP_LIVE_XE=1 is set but lane $lane is missing ORACLE_MATRIX_${upper_lane}_USER / _PASSWORD"
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
e2e_log_event "scenario_start" "setup" "running" 0 "Oracle time-diff E2E: lanes=${selected_lanes[*]}"
require_time_diff_env
command -v python3 >/dev/null 2>&1 || e2e_finish_fail "python3 is required for the time-diff MCP harness"
command -v omcpb >/dev/null 2>&1 || e2e_finish_fail "omcpb is required to build the time-diff MCP binary"

if [ -n "${ORACLEMCP_TIME_DIFF_BINARY:-}" ]; then
  # A caller can supply an already omcpb-built binary when an unrelated shared
  # worktree edit is mid-compile. This never changes the normal path below and
  # cannot introduce a bare-cargo build into the harness.
  BINARY="$ORACLEMCP_TIME_DIFF_BINARY"
  e2e_log_event "prebuilt_binary" "setup" "pass" 0 "using explicit prebuilt time-diff binary"
else
  # This scenario intentionally builds only its owned package through the swarm
  # wrapper. The wrapper owns lane selection, memory caps, and the pinned nightly;
  # no e2e path invokes cargo directly.
  if ! e2e_run_command "setup" omcpb build -p oraclemcp --bin oraclemcp; then
    e2e_finish_fail "building the oraclemcp binary through omcpb failed"
  fi

  build_output="$(e2e_artifact_dir)/output.txt"
  build_target="$(sed -n 's/^omcpb: lane [0-9][0-9]*  target=\([^ ]*\)  jobs=.*/\1/p' "$build_output" | tail -n 1)"
  [ -n "$build_target" ] || e2e_finish_fail "omcpb completed without reporting its selected target directory"
  BINARY="$build_target/debug/oraclemcp"
fi

if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: time-diff wiring validated, no live lanes exercised"
  e2e_finish_pass
  exit 0
fi

[ -x "$BINARY" ] || e2e_finish_fail "configured time-diff binary not found at $BINARY"
command -v timeout >/dev/null 2>&1 || e2e_finish_fail "timeout is required for live time-diff lanes"

run_stamp="$(date -u +"%Y%m%dT%H%M%SZ")-$$"
matrix_dir="$ORACLEMCP_E2E_ARTIFACT_DIR/$E2E_SCENARIO/$run_stamp"
mkdir -p "$matrix_dir"
audit_key="$(openssl rand -hex 32 2>/dev/null || date +%s%N | sha256sum | cut -d' ' -f1)"
lane_timeout_secs="${ORACLEMCP_TIME_DIFF_LANE_TIMEOUT_SECS:-600}"
ddl_settle_secs="${ORACLEMCP_TIME_DIFF_DDL_SETTLE_SECONDS:-180}"
if ! [[ "$ddl_settle_secs" =~ ^[0-9]+$ ]] || [ "$ddl_settle_secs" -gt 600 ]; then
  e2e_finish_fail "ORACLEMCP_TIME_DIFF_DDL_SETTLE_SECONDS must be an integer from 0 to 600"
fi

run_lane() {
  set -e
  local lane="$1"
  local dsn user password lane_dir state_dir profiles_file table evidence audit_file audit_json
  dsn="$(lane_dsn "$lane")"
  user="$(lane_user "$lane")"
  password="$(lane_password "$lane")"
  lane_dir="$matrix_dir/$lane"
  state_dir="$lane_dir/state"
  mkdir -p "$lane_dir" "$state_dir"
  profiles_file="$lane_dir/profiles.toml"
  table="E2E_TD_${lane^^}_$$"
  evidence="$lane_dir/time_diff_evidence.jsonl"
  audit_file="$state_dir/oraclemcp/audit/audit.jsonl"
  audit_json="$lane_dir/audit_verify.json"

  # The table is per-run in an explicit lab-only profile. Writes are still
  # previewed, confirmation-token-gated, audited, and committed one by one by
  # the driver; this configuration merely permits those governed test setup
  # mutations and the deliberate DDL boundary.
  cat >"$profiles_file" <<PROFILES
schema_version = 2
default_profile = "$lane"

[[profiles]]
name = "$lane"
description = "time-diff lab lane $lane (throwaway container)"
connect_string = "$dsn"
username = "$user"
credential_ref = "env:ORACLE_MATRIX_ACTIVE_PASSWORD"
max_level = "DDL"
default_level = "READ_ONLY"
PROFILES

  export ORACLEMCP_CONFIG="$profiles_file"
  export ORACLE_MATRIX_ACTIVE_PASSWORD="$password"
  export ORACLEMCP_AUDIT_KEY="$audit_key"
  export XDG_STATE_HOME="$state_dir"
  export E2E_LANE="$lane" E2E_PROFILE="$lane" E2E_LEVEL="READ_ONLY"

  e2e_log_event "time_diff_lane" "act" "running" 0 "lane $lane: SCN diff/replay session"
  set +e
  timeout -k 15 "$lane_timeout_secs" python3 "$ROOT/scripts/e2e/time_diff_session.py" \
    --binary "$BINARY" \
    --profile "$lane" \
    --table "$table" \
    --audit-file "$audit_file" \
    --evidence "$evidence" \
    --server-stderr "$lane_dir/server.stderr" \
    --ddl-settle-seconds "$ddl_settle_secs"
  local status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    e2e_log_event "time_diff_lane" "assert" "fail" 0 "lane $lane: session failed status=$status evidence=$evidence"
    return 1
  fi

  # The CLI shares the server's `ORACLEMCP_*` config parser. Harness-only
  # switches must not be interpreted as unknown server configuration while the
  # audit verifier reopens the file; keep only its explicit audit key/config.
  if ! env \
    -u ORACLEMCP_TIME_DIFF_BINARY \
    -u ORACLEMCP_TIME_DIFF_DDL_SETTLE_SECONDS \
    -u ORACLEMCP_TIME_DIFF_LANE_TIMEOUT_SECS \
    -u ORACLEMCP_LIVE_XE \
    -u ORACLEMCP_E2E_ARTIFACT_DIR \
    -u ORACLEMCP_E2E_SEED \
    timeout -k 10 60 "$BINARY" --json audit verify "$audit_file" >"$audit_json" 2>"$lane_dir/audit_verify.stderr"; then
    e2e_log_event "audit_verify" "assert" "fail" 0 "lane $lane: audit verify failed (see $audit_json)"
    return 1
  fi
  if ! python3 - "$audit_json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
if report.get("ok") is not True or int(report.get("records", 0)) < 12:
    raise SystemExit(1)
PY
  then
    e2e_log_event "audit_verify" "assert" "fail" 0 "lane $lane: audit chain is not valid or too short (see $audit_json)"
    return 1
  fi
  e2e_log_event "audit_verify" "assert" "pass" 0 "lane $lane: signed audit chain verifies after SCN replay"
  e2e_log_event "time_diff_lane" "assert" "pass" 0 "lane $lane: keyed/keyless diff, typed refusals, and replay green"
}

overall_fail=0
for lane in "${selected_lanes[@]}"; do
  if ! (run_lane "$lane"); then
    overall_fail=1
  fi
done

if [ "$overall_fail" -ne 0 ]; then
  e2e_finish_fail "one or more time-diff live lanes failed (artifacts: $matrix_dir)"
fi
e2e_finish_pass
