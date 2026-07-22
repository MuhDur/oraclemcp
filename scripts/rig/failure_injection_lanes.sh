#!/usr/bin/env bash
# Rig R-fail: deterministic failure-injection lanes over installed oraclemcp.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="failure_injection_lanes"
E2E_LANE="rfail-wire-faults"
E2E_PROFILE="rfail_synthetic"
E2E_LEVEL="READ_WRITE"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

usage() {
  cat <<'USAGE'
Rig R-fail failure-injection lanes.

Usage:
  bash scripts/rig/failure_injection_lanes.sh [run] [--log|--dry-run]

`run` installs the committed oraclemcp artifact from a git archive, starts it as
a real stateful HTTP service, and drives deterministic fault assertions on the
wire: killed Oracle session, client revoke, client rotate, server restart, and
OAuth access-token expiry. The database profile is synthetic/local only and
stores credentials as env refs.
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
    [ "$E2E_DRY_RUN" = "1" ] && args+=(--dry-run)
    [ "$E2E_LOG" = "1" ] && args+=(--log)
    python3 "$ROOT/scripts/rig/failure_injection_lanes.py" "${args[@]}"
    ;;
esac

e2e_finish_pass
