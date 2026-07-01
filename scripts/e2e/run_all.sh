#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="run_all"
E2E_LANE="orchestrator"
E2E_PROFILE="mixed"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

for arg in "$@"; do
  set +e
  e2e_parse_common_arg "$arg"
  parsed=$?
  set -e
  case "$parsed" in
    0) continue ;;
    3)
      echo "Run all oraclemcp e2e scenarios and aggregate pass/fail/skipped status."
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "run_all: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"
scenarios=(
  scripts/e2e/conformance_coverage.sh
  scripts/e2e/mcp_and_operator_v1_conformance_matrix.sh
  scripts/e2e/doctor_fixtures.sh
  scripts/e2e/offline_stdio.sh
  scripts/e2e/http_oauth_lanes.sh
  scripts/e2e/dashboard_readonly.sh
  scripts/e2e/audit_append.sh
  scripts/e2e/live_oracle.sh
  scripts/e2e/load_soak.sh
  scripts/e2e/live_xe_headline.sh
)

run_dir="$ORACLEMCP_E2E_ARTIFACT_DIR/run_all"
mkdir -p "$run_dir"

started="$(e2e_epoch_ms)"
e2e_log_event "orchestrator_start" "setup" "running" 0 "scenarios=${#scenarios[@]}"

passed=0
failed=0
skipped=0

for script in "${scenarios[@]}"; do
  name="$(basename "$script" .sh)"
  out="$run_dir/$name.stdout"
  err="$run_dir/$name.stderr"
  args=()
  [ "$E2E_LOG" = "1" ] && args+=(--log)
  [ "$E2E_DRY_RUN" = "1" ] && args+=(--dry-run)

  e2e_log_event "scenario_dispatch" "act" "running" 0 "$script"
  set +e
  bash "$script" "${args[@]}" > >(tee "$out") 2> >(tee "$err" >&2)
  status=$?
  set -e

  if [ "$status" -ne 0 ]; then
    failed=$((failed + 1))
    e2e_log_event "scenario_result" "assert" "fail" 0 "$name status=$status"
  elif grep -F '"event":"scenario_complete"' "$err" | grep -F '"outcome":"skipped"' >/dev/null 2>&1; then
    skipped=$((skipped + 1))
    e2e_log_event "scenario_result" "assert" "skipped" 0 "$name skipped"
  else
    passed=$((passed + 1))
    e2e_log_event "scenario_result" "assert" "pass" 0 "$name passed"
  fi
done

ended="$(e2e_epoch_ms)"
total="${#scenarios[@]}"
summary="pass=$passed fail=$failed skipped=$skipped total=$total"
if [ "$failed" -eq 0 ]; then
  e2e_log_event "orchestrator_summary" "teardown" "pass" "$((ended - started))" "$summary"
  echo "e2e summary: $summary"
  exit 0
fi

e2e_log_event "orchestrator_summary" "teardown" "fail" "$((ended - started))" "$summary"
echo "e2e summary: $summary" >&2
exit 1
