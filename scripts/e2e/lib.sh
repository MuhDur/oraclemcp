#!/usr/bin/env bash
# Shared helpers for oraclemcp end-to-end scripts.
#
# The contract for scripts in this directory:
#   - accept --log and emit structured JSON lines to stderr;
#   - keep command stdout/stderr on stdout so stderr stays machine-readable;
#   - write failure artifacts under target/e2e/ and print CRASHPACK + SEED.
set -euo pipefail

e2e_repo_root() {
  local src="${BASH_SOURCE[0]}"
  local dir
  dir="$(cd "$(dirname "$src")/../.." && pwd)"
  printf '%s\n' "$dir"
}

ROOT="${ROOT:-$(e2e_repo_root)}"
E2E_LOG="${E2E_LOG:-0}"
E2E_DRY_RUN="${E2E_DRY_RUN:-0}"
E2E_SCENARIO="${E2E_SCENARIO:-unknown}"
E2E_LANE="${E2E_LANE:-$E2E_SCENARIO}"
E2E_SUBJECT="${E2E_SUBJECT:-test-harness}"
E2E_SID="${E2E_SID:-$$}"
E2E_PROFILE="${E2E_PROFILE:-offline}"
E2E_LEVEL="${E2E_LEVEL:-READ_ONLY}"
E2E_GRANT="${E2E_GRANT:-none}"
ORACLEMCP_E2E_SEED="${ORACLEMCP_E2E_SEED:-0}"
ORACLEMCP_E2E_ARTIFACT_DIR="${ORACLEMCP_E2E_ARTIFACT_DIR:-$ROOT/target/e2e}"

e2e_epoch_ms() {
  local ns
  ns="$(date +%s%N 2>/dev/null || true)"
  if [[ "$ns" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$((ns / 1000000))"
  else
    printf '%s000\n' "$(date +%s)"
  fi
}

e2e_ts() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

e2e_json_escape() {
  local value="${1-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "$value"
}

e2e_validate_phase() {
  case "$1" in
    setup|act|assert|teardown) return 0 ;;
    *) echo "e2e: invalid phase '$1'" >&2; return 2 ;;
  esac
}

e2e_log_event() {
  local event="$1"
  local phase="$2"
  local outcome="$3"
  local duration_ms="${4:-0}"
  local message="${5:-}"
  [ "$E2E_LOG" = "1" ] || return 0
  e2e_validate_phase "$phase"
  printf '{"event":"%s","phase":"%s","ts":"%s","duration_ms":%s,"lane":"%s","subject":"%s","sid":"%s","profile":"%s","level":"%s","grant":"%s","outcome":"%s","scenario":"%s","seed":"%s","message":"%s"}\n' \
    "$(e2e_json_escape "$event")" \
    "$(e2e_json_escape "$phase")" \
    "$(e2e_json_escape "$(e2e_ts)")" \
    "$duration_ms" \
    "$(e2e_json_escape "$E2E_LANE")" \
    "$(e2e_json_escape "$E2E_SUBJECT")" \
    "$(e2e_json_escape "$E2E_SID")" \
    "$(e2e_json_escape "$E2E_PROFILE")" \
    "$(e2e_json_escape "$E2E_LEVEL")" \
    "$(e2e_json_escape "$E2E_GRANT")" \
    "$(e2e_json_escape "$outcome")" \
    "$(e2e_json_escape "$E2E_SCENARIO")" \
    "$(e2e_json_escape "$ORACLEMCP_E2E_SEED")" \
    "$(e2e_json_escape "$message")" >&2
}

e2e_usage_common() {
  cat <<'USAGE'
Common options:
  --log       emit structured JSON-line events to stderr
  --dry-run   validate wiring and safety checks without running cargo
  --help      show script usage
USAGE
}

e2e_parse_common_arg() {
  case "${1:-}" in
    --log) E2E_LOG=1; return 0 ;;
    --dry-run) E2E_DRY_RUN=1; return 0 ;;
    --help|-h) return 3 ;;
    *) return 1 ;;
  esac
}

e2e_artifact_dir() {
  local dir="$ORACLEMCP_E2E_ARTIFACT_DIR/$E2E_SCENARIO"
  mkdir -p "$dir"
  printf '%s\n' "$dir"
}

e2e_command_file() {
  local dir="$1"
  shift
  printf '%q ' "$@" >"$dir/command.txt"
  printf '\n' >>"$dir/command.txt"
}

e2e_emit_crashpack() {
  local output_file="$1"
  shift
  local stamp
  stamp="$(date -u +"%Y%m%dT%H%M%SZ")"
  local base="$ORACLEMCP_E2E_ARTIFACT_DIR/crashpacks"
  local crashpack="$base/$E2E_SCENARIO-$stamp-seed-$ORACLEMCP_E2E_SEED"
  mkdir -p "$crashpack"
  cp "$output_file" "$crashpack/output.txt"
  e2e_command_file "$crashpack" "$@"
  {
    printf 'ORACLEMCP_E2E_SEED=%q\n' "$ORACLEMCP_E2E_SEED"
    printf 'ORACLEMCP_E2E_SCENARIO=%q\n' "$E2E_SCENARIO"
  } >"$crashpack/replay.env"
  e2e_log_event "crashpack" "teardown" "fail" 0 "CRASHPACK=$crashpack SEED=$ORACLEMCP_E2E_SEED"
  if [ "$E2E_LOG" = "1" ]; then
    echo "CRASHPACK=$crashpack SEED=$ORACLEMCP_E2E_SEED"
  else
    echo "CRASHPACK=$crashpack SEED=$ORACLEMCP_E2E_SEED" >&2
  fi
}

e2e_run_command() {
  local phase="$1"
  shift
  local start
  start="$(e2e_epoch_ms)"
  e2e_log_event "command_start" "$phase" "running" 0 "$*"

  if [ "$E2E_DRY_RUN" = "1" ]; then
    local end
    end="$(e2e_epoch_ms)"
    e2e_log_event "command_dry_run" "$phase" "skipped" "$((end - start))" "$*"
    return 0
  fi

  local dir
  dir="$(e2e_artifact_dir)"
  local output="$dir/output.txt"
  e2e_command_file "$dir" "$@"

  set +e
  "$@" >"$output" 2>&1
  local status=$?
  set -e
  cat "$output"

  local end
  end="$(e2e_epoch_ms)"
  if [ "$status" -eq 0 ]; then
    e2e_log_event "command_complete" "$phase" "pass" "$((end - start))" "$*"
    return 0
  fi

  e2e_log_event "command_complete" "$phase" "fail" "$((end - start))" "$*"
  e2e_emit_crashpack "$output" "$@"
  return "$status"
}

e2e_finish_pass() {
  e2e_log_event "scenario_complete" "teardown" "pass" 0 "$E2E_SCENARIO passed"
}

e2e_finish_skip() {
  local reason="$1"
  e2e_log_event "scenario_complete" "teardown" "skipped" 0 "$reason"
  [ "$E2E_LOG" = "1" ] || echo "SKIP $E2E_SCENARIO: $reason" >&2
  exit 0
}

e2e_finish_fail() {
  local reason="$1"
  e2e_log_event "scenario_complete" "teardown" "fail" 0 "$reason"
  if [ "$E2E_LOG" = "1" ]; then
    echo "FAIL $E2E_SCENARIO: $reason"
  else
    echo "FAIL $E2E_SCENARIO: $reason" >&2
  fi
  exit 1
}

e2e_lower() {
  printf '%s\n' "$1" | tr '[:upper:]' '[:lower:]'
}

e2e_value_has_production_marker() {
  local value
  value="$(e2e_lower "${1:-}")"
  [[ "$value" =~ (^|[^a-z0-9])(prod|production|prd|primary|customer|corp|live)([^a-z0-9]|$) ]]
}

e2e_value_has_test_marker() {
  local value
  value="$(e2e_lower "${1:-}")"
  [[ "$value" =~ (localhost|127\.0\.0\.1|\[::1\]|::1|test|testing|xe|free|freepdb) ]]
}

e2e_require_live_oracle_env() {
  if [ "${ORACLEMCP_LIVE_XE:-}" != "1" ]; then
    e2e_finish_skip "set ORACLEMCP_LIVE_XE=1 to run live Oracle scenarios"
  fi
  for name in ORACLEMCP_TEST_DSN ORACLEMCP_TEST_USER ORACLEMCP_TEST_PASSWORD; do
    if [ -z "${!name:-}" ]; then
      e2e_finish_skip "set $name for live Oracle scenarios"
    fi
  done

  local dsn="${ORACLEMCP_TEST_DSN:-}"
  local user="${ORACLEMCP_TEST_USER:-}"
  if e2e_value_has_production_marker "$dsn" || e2e_value_has_production_marker "$user"; then
    e2e_finish_fail "refusing production-looking Oracle test target"
  fi
  if ! e2e_value_has_test_marker "$dsn"; then
    e2e_finish_fail "ORACLEMCP_TEST_DSN must include a local/free/xe/test marker"
  fi
}
