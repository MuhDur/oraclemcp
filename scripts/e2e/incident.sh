#!/usr/bin/env bash
# Arc E served command proof. This deliberately needs no Oracle connection:
# capture/replay must be honest and fail closed even when the only available
# runtime is the deterministic offline LabRuntime.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="incident"
E2E_LANE="offline-lab-runtime"
E2E_PROFILE="offline"
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
      echo "Exercise real om incident capture/replay with synthetic-only inputs."
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "incident: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

export E2E_LOG ORACLEMCP_E2E_SEED
cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "real incident capture and deterministic replay"
command -v python3 >/dev/null 2>&1 || e2e_finish_fail "python3 is required for the incident harness"

if [ -n "${ORACLEMCP_INCIDENT_BINARY:-}" ]; then
  BINARY="$ORACLEMCP_INCIDENT_BINARY"
  e2e_log_event "prebuilt_binary" "setup" "pass" 0 "using explicit prebuilt incident binary"
else
  command -v omcpb >/dev/null 2>&1 || e2e_finish_fail "omcpb is required to build the incident binary"
  if ! e2e_run_command "setup" omcpb build -p oraclemcp --bin oraclemcp; then
    e2e_finish_fail "building the oraclemcp binary through omcpb failed"
  fi
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "scenario_assert" "assert" "pass" 0 "dry-run: incident wiring validated; no artifact was created"
    e2e_finish_pass
    exit 0
  fi
  build_output="$(e2e_artifact_dir)/output.txt"
  build_target="$(sed -n 's/^omcpb: lane [0-9][0-9]*  target=\([^ ]*\)  jobs=.*/\1/p' "$build_output" | tail -n 1)"
  [ -n "$build_target" ] || e2e_finish_fail "omcpb completed without reporting its selected target directory"
  BINARY="$build_target/debug/oraclemcp"
fi

if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "scenario_assert" "assert" "pass" 0 "dry-run: incident wiring validated; no artifact was created"
  e2e_finish_pass
  exit 0
fi

[ -x "$BINARY" ] || e2e_finish_fail "configured incident binary not found at $BINARY"
run_dir="$(e2e_artifact_dir)/lab-${ORACLEMCP_E2E_SEED}-$$"
mkdir -p "$run_dir"
evidence="$run_dir/evidence.jsonl"

set +e
python3 "$ROOT/scripts/e2e/incident_session.py" \
  --binary "$BINARY" \
  --run-dir "$run_dir" \
  --evidence "$evidence" \
  --seed "$ORACLEMCP_E2E_SEED"
status=$?
set -e
if [ "$status" -ne 0 ]; then
  e2e_log_event "incident_replay" "assert" "fail" 0 "incident scenario failed; inspect bounded evidence"
  e2e_finish_fail "real incident capture/replay scenario failed"
fi

e2e_log_event "incident_replay" "assert" "pass" 0 "bundle redaction gate and deterministic replay passed"
e2e_finish_pass
