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
  scripts/e2e/served_console.sh
  scripts/e2e/audit_append.sh
  scripts/e2e/verdict_certificate.sh
  scripts/e2e/live_oracle.sh
  scripts/e2e/egress.sh
  scripts/e2e/served_egress.sh
  scripts/e2e/load_soak.sh
  scripts/e2e/live_xe_headline.sh
  scripts/e2e/oracle_version_matrix.sh
  scripts/e2e/living_db.sh
  scripts/e2e/editions.sh
  scripts/e2e/governed_rag.sh
  scripts/e2e/time_diff.sh
  scripts/e2e/sql_policy.sh
  scripts/e2e/refusal_corpus.sh
  scripts/e2e/incident.sh
  scripts/e2e/seeded_fault_injection.sh
  scripts/e2e/fleet.sh
  scripts/e2e/reversible.sh
  scripts/e2e/cost_gate.sh
  scripts/e2e/clean_machine_e2e.sh
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
  # Plain redirects (not `tee` via process substitution): bash does not wait for
  # a process-substitution child before the grep below, so a `> >(tee …)` skip
  # line could still be unflushed and miscounted as a pass. Capture to files,
  # then replay to the terminal after the exit code is known.
  # Served-egress credentials are deliberately environment-only. They are
  # `ORACLEMCP_*` names for the harness, while child servers reject unknown
  # `ORACLEMCP_*` configuration keys. Scope them to their one scenario so they
  # cannot leak into another served process or change an unrelated result.
  set +e
  if [ "$name" = "served_egress" ]; then
    bash "$script" "${args[@]}" >"$out" 2>"$err"
  else
    env \
      -u ORACLEMCP_SERVED_EGRESS_DSN \
      -u ORACLEMCP_SERVED_EGRESS_USER \
      -u ORACLEMCP_SERVED_EGRESS_PASSWORD \
      bash "$script" "${args[@]}" >"$out" 2>"$err"
  fi
  status=$?
  set -e
  cat "$out"
  cat "$err" >&2

  # Skip detection must be independent of E2E_LOG. `e2e_finish_skip` emits the
  # `scenario_complete`/`skipped` JSON event ONLY under --log, and a plain
  # `SKIP <scenario>: …` stderr sentinel ONLY without --log — so check both, or
  # a skip run without --log (e.g. the version matrix with no live creds) is
  # silently counted as a pass and green-washes the release gate. The
  # `scenario_complete` filter on the JSON path avoids matching the unrelated
  # `command_dry_run`/`skipped` events emitted in --dry-run mode.
  if [ "$status" -ne 0 ]; then
    failed=$((failed + 1))
    e2e_log_event "scenario_result" "assert" "fail" 0 "$name status=$status"
  elif { grep -F '"event":"scenario_complete"' "$err" | grep -Fq '"outcome":"skipped"'; } ||
    grep -Eq '^SKIP ' "$err"; then
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
