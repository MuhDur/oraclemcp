#!/usr/bin/env bash
# R3 browser lane: drive the real `oraclemcp serve` listener from Chromium.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="browser_lane"
E2E_LANE="browser-lane"
E2E_PROFILE="operator"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

cmd="${1:-run}"
if [ "$#" -gt 0 ]; then
  shift
fi

usage() {
  cat <<'USAGE'
Browser lane against the live Rust HTTP listener.

Usage:
  bash scripts/rig/rig_browser_lane.sh run [--log|--dry-run]
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
  run) ;;
  --help|-h) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "browser lane live-serve proof"

command -v omcpb >/dev/null 2>&1 || e2e_finish_fail "omcpb is required to build the browser-lane binary"
if [ "$E2E_DRY_RUN" != "1" ] && [ ! -d "$ROOT/web/node_modules/@playwright/test" ]; then
  e2e_finish_skip "web/node_modules is not installed (run npm --prefix web ci)"
fi

if ! e2e_run_command "setup" omcpb build -p oraclemcp --bin oraclemcp; then
  e2e_finish_fail "building the browser-lane binary through omcpb failed"
fi

if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: browser lane wiring validated, no listener started"
  e2e_finish_pass
  exit 0
fi

build_output="$(e2e_artifact_dir)/output.txt"
build_target="$(sed -n 's/^omcpb: lane [0-9][0-9]*  target=\([^ ]*\)  jobs=.*/\1/p' "$build_output" | tail -n 1)"
[ -n "$build_target" ] || e2e_finish_fail "omcpb completed without reporting its selected target directory"
OMCP_BIN="$build_target/debug/oraclemcp"
[ -x "$OMCP_BIN" ] || e2e_finish_fail "could not locate the omcpb-built browser-lane binary"
export OMCP_BIN
export OMCP_BROWSER_LANE=1
export OMCP_BROWSER_LANE_ARTIFACT_DIR="${OMCP_BROWSER_LANE_ARTIFACT_DIR:-$ORACLEMCP_E2E_ARTIFACT_DIR/browser-lane}"

if ! e2e_run_command "act" npm --prefix web exec -- playwright test --config web/playwright.live-serve.config.ts; then
  e2e_finish_fail "browser lane failed"
fi

e2e_log_event "scenario_assert" "assert" "pass" 0 "Chromium paired via 303 redirect, browser action POST returned 200, and EventSource resumed with Last-Event-ID"
e2e_finish_pass
