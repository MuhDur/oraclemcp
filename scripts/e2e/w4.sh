#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"
E2E_SCENARIO=w4
E2E_LANE=free23
E2E_PROFILE=w4
E2E_LEVEL=READ_ONLY
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

args=()
lane=free23
binary=""
binary_source_sha=""
contract_only=0
coverage_report=0
cargo_test_logs=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --lane)
      [ "$#" -ge 2 ] || e2e_finish_fail "--lane requires a value"
      lane="$2"; shift 2 ;;
    --binary)
      [ "$#" -ge 2 ] || e2e_finish_fail "--binary requires a path"
      binary="$2"; shift 2 ;;
    --binary-source-sha)
      [ "$#" -ge 2 ] || e2e_finish_fail "--binary-source-sha requires a SHA"
      binary_source_sha="$2"; shift 2 ;;
    --contract-only) contract_only=1; shift ;;
    --coverage-report) coverage_report=1; shift ;;
    --cargo-test-log)
      [ "$#" -ge 2 ] || e2e_finish_fail "--cargo-test-log requires a path"
      cargo_test_logs+=("$2"); shift 2 ;;
    --log|--dry-run) e2e_parse_common_arg "$1"; shift ;;
    --help|-h)
      echo "Usage: scripts/e2e/w4.sh [--lane free23|xe18|xe21] [--binary PATH] [--binary-source-sha SHA] [--contract-only] [--coverage-report] [--cargo-test-log PATH] [--log] [--dry-run]"
      exit 0 ;;
    *) e2e_finish_fail "unknown argument $1" ;;
  esac
done
case "$lane" in free23|xe18|xe21) ;; *) e2e_finish_fail "unknown lab lane $lane" ;; esac
E2E_LANE="$lane"
export E2E_LANE

python="${W4_PYTHON:-python3}"
args=("$ROOT/scripts/e2e/w4/driver.py" --lane "$lane")
[ -z "$binary" ] || args+=(--binary "$binary")
[ -z "$binary_source_sha" ] || args+=(--binary-source-sha "$binary_source_sha")
[ "$contract_only" = 0 ] || args+=(--contract-only)
[ "$coverage_report" = 0 ] || args+=(--coverage-report)
for path in "${cargo_test_logs[@]}"; do args+=(--cargo-test-log "$path"); done

if [ "$E2E_DRY_RUN" = 1 ]; then
  e2e_run_command assert "$python" "$ROOT/scripts/e2e/w4/driver.py" --selftest
  e2e_run_command act "$python" "${args[@]}"
  e2e_finish_pass
  exit 0
fi
if [ "${ORACLEMCP_LIVE_XE:-}" != 1 ]; then
  e2e_finish_skip "set ORACLEMCP_LIVE_XE=1 for live W4 lab"
fi
e2e_run_command act "$python" "${args[@]}"
e2e_finish_pass
