#!/usr/bin/env bash
# C9 onboarding snippet truth lane: execute setup-printed client snippets verbatim.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="onboarding_snippet_truth"
E2E_LANE="snippet-truth"
E2E_PROFILE="c9_ro"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

cmd="${1:-run}"
if [ "$#" -gt 0 ]; then
  shift
fi

usage() {
  cat <<'USAGE'
C9 onboarding snippet truth lane.

Usage:
  bash scripts/rig/onboarding_snippet_truth.sh run [--log|--dry-run]
  bash scripts/rig/onboarding_snippet_truth.sh xfail [--log|--dry-run]

`run` is the future regression gate: every setup-printed client snippet must
complete MCP initialize. `xfail` runs the same snippets but requires the current
C9 known failures, producing close evidence without weakening the future gate.
USAGE
  e2e_usage_common
}

for arg in "$@"; do
  set +e
  e2e_parse_common_arg "$arg"
  parsed=$?
  set -e
  case "$parsed" in
    0) continue ;;
    3) usage; exit 0 ;;
    *) e2e_finish_fail "unknown argument: $arg" ;;
  esac
done

case "$cmd" in
  run|xfail) ;;
  --help|-h) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "C9 setup-printed snippet truth"

command -v python3 >/dev/null 2>&1 || e2e_finish_fail "python3 is required"
command -v cargo >/dev/null 2>&1 || e2e_finish_fail "cargo is required"
command -v git >/dev/null 2>&1 || e2e_finish_fail "git is required"
command -v tar >/dev/null 2>&1 || e2e_finish_fail "tar is required"

if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "installed_artifact" "setup" "skipped" 0 "dry-run"
  e2e_log_event "snippet_truth" "assert" "skipped" 0 "dry-run"
  e2e_finish_pass
  exit 0
fi

artifact_dir="${ORACLEMCP_C9_ARTIFACT_DIR:-$ROOT/target/e2e/c9-snippet-truth-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
mkdir -p "$artifact_dir"

set +e
PYTHONDONTWRITEBYTECODE=1 python3 "$ROOT/scripts/rig/onboarding_snippet_truth.py" \
  --mode "$cmd" \
  --artifact-dir "$artifact_dir"
status=$?
set -e

case "$status" in
  0)
    e2e_log_event "snippet_truth" "assert" "pass" 0 "artifact=$artifact_dir/summary.json"
    e2e_finish_pass
    ;;
  10)
    e2e_log_event "snippet_truth" "assert" "fail" 0 "artifact=$artifact_dir/summary.json"
    e2e_finish_fail "one or more setup-printed snippets failed verbatim; artifact=$artifact_dir/summary.json"
    ;;
  *)
    e2e_log_event "snippet_truth" "assert" "fail" 0 "artifact=$artifact_dir/summary.json status=$status"
    e2e_finish_fail "C9 snippet truth harness failed; artifact=$artifact_dir/summary.json status=$status"
    ;;
esac
