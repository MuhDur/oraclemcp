#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="audit_append"
E2E_LANE="audit"
E2E_PROFILE="file-audit"
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
      echo "Run the audit append/hash-chain e2e contract."
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "audit_append: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "audit append/hash-chain contract"
if ! e2e_run_command "act" cargo test -p oraclemcp-audit concurrent_appends_keep_one_valid_chain -- --nocapture; then
  e2e_finish_fail "audit append/hash-chain contract failed"
fi
e2e_log_event "scenario_assert" "assert" "pass" 0 "audit append/hash-chain contract completed"
e2e_finish_pass
