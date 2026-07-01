#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="doctor_fixtures"
E2E_LANE="doctor"
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
      echo "Run the doctor --fix fixture/accounting gate."
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "doctor_fixtures: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "doctor --fix fixture/accounting gate"

required=(
  crates/oraclemcp-core/src/doctor.rs
  crates/oraclemcp/src/main.rs
)
missing=0
for path in "${required[@]}"; do
  if [ ! -f "$path" ]; then
    echo "missing required doctor fixture gate file: $path" >&2
    missing=$((missing + 1))
  fi
done
if [ "$missing" -ne 0 ]; then
  e2e_finish_fail "$missing required doctor fixture gate file(s) missing"
fi

mkdir -p "$ROOT/target/tmp"
if ! e2e_run_command "assert" env CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/target/tmp" \
  cargo test -p oraclemcp-core doctor_fix_fixture_gate_current_repairs_are_fixture_accounted; then
  e2e_finish_fail "doctor --fix fixture/accounting gate failed"
fi
if ! e2e_run_command "assert" env CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/target/tmp" \
  cargo test -p oraclemcp doctor_process_exit_code_matches_cli_contract; then
  e2e_finish_fail "doctor CLI exit-code contract failed"
fi

e2e_log_event "fixture_summary" "assert" "pass" 0 "current doctor repairs are no-op/refusal accounted; future mutations require round-trip fixtures"
e2e_finish_pass
