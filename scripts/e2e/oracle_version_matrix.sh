#!/usr/bin/env bash
# Pre-production Oracle version matrix: full operating-level ladder e2e over
# MCP stdio against three live lab lanes (XE 18, XE 21, FREE 23ai) — bead
# oraclemcp-field-test-0607-bhw6.9.
#
# Per lane, against the REAL binary:
#   1. --json doctor --online --profile <lane>   (connectivity green)
#   2. READ_ONLY   : row-VALUE assertions (v$version banner, arithmetic) and
#                    a structured OPERATING_LEVEL_TOO_LOW refusal for INSERT
#   3. READ_WRITE  : preview verdict -> session-level grant -> elevation;
#                    DML rollback-by-default proven, then governed commit,
#                    row counts asserted via oracle_query
#   4. DDL         : governed CREATE TABLE / DROP TABLE through the
#                    preview -> confirmation-grant -> execute gate
#   5. drop back to READ_ONLY and prove writes refuse again
#   6. audit hash-chain: per-step records present, chain re-verified with
#                    `oraclemcp audit verify` (isolated XDG_STATE_HOME per run)
#
# Lab containers ONLY. The lane endpoints must look like local test targets
# (lib.sh refuses production-looking DSNs/users). Suggested lab compose:
#   docker run -d --name oracle-xe18 -p 1518:1521 -e ORACLE_PASSWORD=... gvenzl/oracle-xe:18-slim
#   docker run -d --name oracle-xe21 -p 1520:1521 -e ORACLE_PASSWORD=... gvenzl/oracle-xe:21-slim
#   docker run -d --name oracle-free -p 1522:1521 -e ORACLE_PASSWORD=... gvenzl/oracle-free:23-slim
#
# Required env (opt-in gate + per-lane credentials; the DB user needs CREATE
# TABLE in its own schema, e.g. gvenzl APP_USER):
#   ORACLEMCP_LIVE_XE=1
#   ORACLE_MATRIX_XE18_USER / ORACLE_MATRIX_XE18_PASSWORD
#   ORACLE_MATRIX_XE21_USER / ORACLE_MATRIX_XE21_PASSWORD
#   ORACLE_MATRIX_FREE23_USER / ORACLE_MATRIX_FREE23_PASSWORD
# Optional overrides:
#   ORACLE_MATRIX_<LANE>_DSN          (defaults: localhost:1518/XEPDB1,
#                                         localhost:1520/XEPDB1, localhost:1522/FREEPDB1)
#   ORACLE_MATRIX_<LANE>_BANNER_REGEX (defaults pin the lane's Oracle release)
#   ORACLE_MATRIX_LANE_TIMEOUT_SECS   (default 900: per-lane wall-clock ceiling
#                                         on the ladder session — a hung lane
#                                         fails the lane instead of hanging
#                                         run_all)
#   ORACLE_MATRIX_DOCTOR_TIMEOUT_SECS (default 120: ceiling on doctor --online)
#   --lane xe18|xe21|free23              (repeatable; default: all three — the
#                                         release gate requires all three green)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="oracle_version_matrix"
E2E_LANE="version-matrix"
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
      echo "Run the Oracle version-matrix operating-level ladder e2e (XE 18 / XE 21 / FREE 23ai)."
      echo "Options: --lane <xe18|xe21|free23> (repeatable; default all three)"
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "oracle_version_matrix: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done
if [ "$expect_lane_arg" = "1" ]; then
  echo "oracle_version_matrix: --lane needs a value (xe18|xe21|free23)" >&2
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

lane_banner_regex() {
  case "$1" in
    xe18) printf '%s\n' "${ORACLE_MATRIX_XE18_BANNER_REGEX:-Oracle Database 18c Express Edition}" ;;
    xe21) printf '%s\n' "${ORACLE_MATRIX_XE21_BANNER_REGEX:-Oracle Database 21c Express Edition}" ;;
    # gvenzl/oracle-free:23 images report "Oracle Database 23ai Free Release 23…"
    # (newer builds re-brand as "Oracle AI Database 26ai Free Release 23.26…");
    # both pin release 23 — the regression bar for the 23ai lane.
    free23) printf '%s\n' "${ORACLE_MATRIX_FREE23_BANNER_REGEX:-Free Release 23\\.}" ;;
  esac
}

require_matrix_env() {
  if [ "${ORACLEMCP_LIVE_XE:-}" != "1" ]; then
    e2e_finish_skip "set ORACLEMCP_LIVE_XE=1 plus ORACLE_MATRIX_*_USER/_PASSWORD to run the version matrix"
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
    if [ -z "$user" ] || [ -z "$password" ]; then
      # ORACLEMCP_LIVE_XE=1 is an EXPLICIT live opt-in: a selected lane with
      # missing credentials is a misconfigured request and must hard-fail, not
      # silently skip (skip-accounting green-wash). The whole-suite skip when
      # ORACLEMCP_LIVE_XE is unset (above) stays a skip.
      e2e_finish_fail "ORACLEMCP_LIVE_XE=1 is set but lane $lane is missing ORACLE_MATRIX_$(printf '%s' "$lane" | tr '[:lower:]' '[:upper:]')_USER / _PASSWORD"
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
e2e_log_event "scenario_start" "setup" "running" 0 "Oracle version-matrix ladder e2e: lanes=${selected_lanes[*]}"
require_matrix_env

if ! e2e_run_command "setup" cargo build -p oraclemcp --bin oraclemcp; then
  e2e_finish_fail "building the oraclemcp binary failed"
fi

if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: wiring validated, no live lanes exercised"
  e2e_finish_pass
  exit 0
fi

target_dir="$(cargo metadata --format-version 1 --no-deps | jq -r '.target_directory')"
BINARY="$target_dir/debug/oraclemcp"
[ -x "$BINARY" ] || e2e_finish_fail "built binary not found at $BINARY"

run_stamp="$(date -u +"%Y%m%dT%H%M%SZ")-$$"
matrix_dir="$ORACLEMCP_E2E_ARTIFACT_DIR/$E2E_SCENARIO/$run_stamp"
mkdir -p "$matrix_dir"

audit_key="$(openssl rand -hex 32 2>/dev/null || date +%s%N | sha256sum | cut -d' ' -f1)"

# Per-lane wall-clock ceilings: a hung lane (stuck DB, wedged stdio session)
# must fail THAT lane, never hang the whole matrix / run_all. GNU coreutils
# `timeout` exits 124 on expiry; -k adds a SIGKILL grace window.
lane_timeout_secs="${ORACLE_MATRIX_LANE_TIMEOUT_SECS:-900}"
doctor_timeout_secs="${ORACLE_MATRIX_DOCTOR_TIMEOUT_SECS:-120}"

overall_fail=0
lane_summaries=()

run_lane() {
  # The caller invokes run_lane in a `set +e` subshell, which turns errexit OFF
  # in here; re-enable it so an unchecked setup failure (mkdir/heredoc/export)
  # aborts the lane instead of running the ladder against broken state. The
  # local `set +e` / `set -e` pairs around doctor/ladder still toggle correctly.
  set -e
  local lane="$1"
  local dsn user password banner_regex
  dsn="$(lane_dsn "$lane")"
  user="$(lane_user "$lane")"
  password="$(lane_password "$lane")"
  banner_regex="$(lane_banner_regex "$lane")"

  local lane_dir="$matrix_dir/$lane"
  local state_dir="$lane_dir/state"
  mkdir -p "$lane_dir" "$state_dir"

  # Lane-scoped profile config: writable lab profile with max_level = DDL for
  # the ladder tests; READ_ONLY stays the default level (the ladder proves the
  # step-ups). Secrets go through credential_ref, never into the file.
  local profiles_file="$lane_dir/profiles.toml"
  cat >"$profiles_file" <<PROFILES
schema_version = 2
default_profile = "$lane"

[[profiles]]
name = "$lane"
description = "version-matrix lab lane $lane (throwaway container)"
connect_string = "$dsn"
username = "$user"
credential_ref = "env:ORACLE_MATRIX_ACTIVE_PASSWORD"
max_level = "DDL"
default_level = "READ_ONLY"
PROFILES

  export ORACLEMCP_CONFIG="$profiles_file"
  export ORACLE_MATRIX_ACTIVE_PASSWORD="$password"
  export XDG_STATE_HOME="$state_dir"
  export ORACLEMCP_AUDIT_KEY="$audit_key"
  export E2E_LANE="$lane" E2E_PROFILE="$lane"

  # Step 1: doctor --online connectivity gate.
  e2e_log_event "doctor_online" "act" "running" 0 "lane $lane: --json doctor --online --profile $lane"
  local doctor_json="$lane_dir/doctor_online.json"
  set +e
  timeout -k 10 "$doctor_timeout_secs" \
    "$BINARY" --json doctor --online --profile "$lane" >"$doctor_json" 2>"$lane_dir/doctor_online.stderr"
  local doctor_status=$?
  set -e
  if [ "$doctor_status" -eq 124 ]; then
    e2e_log_event "doctor_online" "assert" "fail" 0 "lane $lane: doctor --online timed out after ${doctor_timeout_secs}s (hung lane failed, not hung)"
    return 1
  fi
  if [ "$doctor_status" -ne 0 ]; then
    e2e_log_event "doctor_online" "assert" "fail" 0 "lane $lane: doctor exit=$doctor_status (see $doctor_json)"
    return 1
  fi
  if ! jq -e '.ok == true and ([.checks[] | select(.name == "Connectivity") | .status] == ["pass"])' \
    "$doctor_json" >/dev/null; then
    e2e_log_event "doctor_online" "assert" "fail" 0 "lane $lane: connectivity check not green (see $doctor_json)"
    return 1
  fi
  e2e_log_event "doctor_online" "assert" "pass" 0 "lane $lane: doctor --online green, connectivity pass"

  # Steps 2-5 + per-step audit records: one long-lived MCP stdio session
  # walking the full operating-level ladder against the real binary. Run it
  # directly (not via e2e_run_command) so its harness-schema JSON-line step
  # events flow to this script's stderr stream; its stdout is evidence.
  local evidence="$lane_dir/ladder_evidence.jsonl"
  local table="E2E_LADDER_$$"
  e2e_log_event "ladder_session" "act" "running" 0 "lane $lane: MCP stdio ladder session (table $table)"
  set +e
  timeout -k 15 "$lane_timeout_secs" \
    python3 "$ROOT/scripts/e2e/oracle_ladder_session.py" \
    --binary "$BINARY" --profile "$lane" --banner-regex "$banner_regex" \
    --table "$table" --evidence "$evidence" >"$lane_dir/ladder_stdout.txt"
  local ladder_status=$?
  set -e
  cat "$lane_dir/ladder_stdout.txt"
  if [ "$ladder_status" -eq 124 ]; then
    e2e_log_event "ladder_session" "assert" "fail" 0 "lane $lane: ladder session exceeded the ${lane_timeout_secs}s wall-clock ceiling (hung lane failed, not hung; evidence: $evidence)"
    return 1
  fi
  if [ "$ladder_status" -ne 0 ]; then
    e2e_log_event "ladder_session" "assert" "fail" 0 "lane $lane: ladder session failed (evidence: $evidence)"
    return 1
  fi
  e2e_log_event "ladder_session" "assert" "pass" 0 "lane $lane: full ladder green (evidence: $evidence)"

  # Step 6: re-verify the signed audit hash-chain with the binary's own
  # verifier (recomputes every link + keyed MAC with the run's key).
  local audit_file="$state_dir/oraclemcp/audit/audit.jsonl"
  local audit_json="$lane_dir/audit_verify.json"
  if ! timeout -k 10 60 "$BINARY" --json audit verify "$audit_file" >"$audit_json" 2>"$lane_dir/audit_verify.stderr"; then
    e2e_log_event "audit_verify" "assert" "fail" 0 "lane $lane: audit verify failed (see $audit_json)"
    return 1
  fi
  if ! jq -e '.ok == true and .records >= 10' "$audit_json" >/dev/null; then
    e2e_log_event "audit_verify" "assert" "fail" 0 "lane $lane: audit chain not ok or too few records (see $audit_json)"
    return 1
  fi
  # The server maintains the head anchor sidecar; a fresh single-run log must
  # verify with the anchor matching (or explainably behind) the chain head.
  if ! jq -e '.anchor.status == "match" or .anchor.status == "behind"' "$audit_json" >/dev/null; then
    e2e_log_event "audit_verify" "assert" "fail" 0 "lane $lane: head anchor missing or not tracking the chain (see $audit_json)"
    return 1
  fi
  local audit_records
  audit_records="$(jq -r '.records' "$audit_json")"
  e2e_log_event "audit_verify" "assert" "pass" 0 "lane $lane: signed hash-chain verified ($audit_records records, anchor $(jq -r '.anchor.status' "$audit_json"))"

  # Step 6b (bead oraclemcp-xb51): tail-truncation tamper evidence. Cut the
  # copied chain to just below the anchored head and expect verify to report
  # TRUNCATED (exit non-zero) — a valid prefix must NOT verify clean once the
  # anchor attests a longer durable chain.
  local anchor_seq
  anchor_seq="$(jq -r '.anchor.seq' "$audit_json")"
  local truncated_file="$lane_dir/audit_truncated.jsonl"
  local truncated_json="$lane_dir/audit_truncated_verify.json"
  head -n "$((anchor_seq - 1))" "$audit_file" >"$truncated_file"
  cp "$audit_file.anchor" "$truncated_file.anchor"
  set +e
  timeout -k 10 60 "$BINARY" --json audit verify "$truncated_file" >"$truncated_json" 2>"$lane_dir/audit_truncated_verify.stderr"
  local truncated_status=$?
  set -e
  if [ "$truncated_status" -eq 0 ]; then
    e2e_log_event "audit_truncation_detect" "assert" "fail" 0 "lane $lane: truncated chain verified CLEAN — tail truncation undetected (see $truncated_json)"
    return 1
  fi
  if ! jq -e '.ok == false and .truncated == true' "$truncated_json" >/dev/null; then
    e2e_log_event "audit_truncation_detect" "assert" "fail" 0 "lane $lane: truncated chain refused for the wrong reason (see $truncated_json)"
    return 1
  fi
  e2e_log_event "audit_truncation_detect" "assert" "pass" 0 "lane $lane: tail truncation detected (anchor seq $anchor_seq, exit $truncated_status)"
  return 0
}

for lane in "${selected_lanes[@]}"; do
  lane_started="$(e2e_epoch_ms)"
  e2e_log_event "lane_start" "act" "running" 0 "lane $lane starting"
  set +e
  (run_lane "$lane")
  lane_status=$?
  set -e
  lane_ended="$(e2e_epoch_ms)"
  if [ "$lane_status" -eq 0 ]; then
    e2e_log_event "lane_result" "assert" "pass" "$((lane_ended - lane_started))" "lane $lane passed"
    lane_summaries+=("$lane=pass")
  else
    e2e_log_event "lane_result" "assert" "fail" "$((lane_ended - lane_started))" "lane $lane FAILED"
    lane_summaries+=("$lane=fail")
    overall_fail=1
  fi
done

summary="lanes: ${lane_summaries[*]} (artifacts: $matrix_dir)"
if [ "$overall_fail" -ne 0 ]; then
  e2e_finish_fail "$summary"
fi
e2e_log_event "scenario_assert" "assert" "pass" 0 "$summary"
echo "oracle_version_matrix: $summary"
e2e_finish_pass
