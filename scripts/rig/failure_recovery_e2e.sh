#!/usr/bin/env bash
# Rig E5: failure/recovery e2e over an installed oraclemcp artifact.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="failure_recovery_e2e"
E2E_LANE="e5-failure-recovery"
E2E_PROFILE="e5_synthetic"
E2E_LEVEL="READ_WRITE"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

usage() {
  cat <<'USAGE'
Rig E5 failure/recovery lane.

Usage:
  bash scripts/rig/failure_recovery_e2e.sh [run] [--log|--dry-run]

`run` installs the committed oraclemcp artifact from a git archive, starts it as
a real stateful HTTP service, and drives MCP/operator requests on the wire. The
database profile is synthetic/local only and stores credentials as env refs.
USAGE
  e2e_usage_common
}

command="run"
while [ "$#" -gt 0 ]; do
  case "$1" in
    run) command="$1"; shift ;;
    --help|-h) usage; exit 0 ;;
    *)
      if e2e_parse_common_arg "$1"; then shift; continue; fi
      case $? in
        3) usage; exit 0 ;;
        *) e2e_finish_fail "unknown argument: $1" ;;
      esac
      ;;
  esac
done

case "$command" in
  run)
    args=()
    if [ "$E2E_DRY_RUN" = "1" ]; then
      args+=(--dry-run)
    fi
    if [ "$E2E_LOG" = "1" ]; then
      args+=(--log)
    fi
    python3 "$ROOT/scripts/rig/failure_recovery_e2e.py" "${args[@]}"
    ;;
esac

e2e_finish_pass
