#!/usr/bin/env bash
# Served-console E2E (Arc L / oraclemcp-rxf6): prove the shipped Carved Light
# affordances consume REAL data from a REAL served backend — no mocks.
#
# Builds the `oraclemcp` binary, then runs web/src/app/served-console.e2e.test.ts,
# which spawns `oraclemcp serve` over Streamable HTTP, pairs with its operator
# surface the way the browser does, drives real MCP + operator API calls, and
# feeds every response through the console's own parsers. The assertions are the
# console's honesty bar: real cost ceiling, real refusal, no-proof is not a proof,
# no mask certificate is not proof of no masking, an unreachable fleet lane is a
# visible drift-unknown node, and a missing policy verdict is reported as such.
#
# This registered release scenario requires a local lab Oracle. The no-DB
# honesty negatives remain useful in focused UI tests, but they cannot satisfy
# this scenario's proof obligation: a passing run must contain a completed,
# governed read and its real server evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="served_console"
E2E_LANE="served-console"
E2E_PROFILE="operator"
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
      echo "Prove the shipped console affordances against a real served backend (no mocks)."
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "served_console: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "served-console affordance proof"

require_live_console_env() {
  local value
  for value in OMCP_LIVE_DSN OMCP_LIVE_USER OMCP_LIVE_CRED; do
    if [ -z "${!value:-}" ]; then
      e2e_finish_fail "served-console requires $value for its mandatory live-Oracle proof"
    fi
  done
  if e2e_value_has_production_marker "$OMCP_LIVE_DSN" || e2e_value_has_production_marker "$OMCP_LIVE_USER"; then
    e2e_finish_fail "refusing production-looking served-console Oracle target"
  fi
  if ! e2e_value_has_test_marker "$OMCP_LIVE_DSN"; then
    e2e_finish_fail "OMCP_LIVE_DSN must include a local/free/xe/test marker"
  fi
  for value in "$OMCP_LIVE_DSN" "$OMCP_LIVE_USER" "$OMCP_LIVE_CRED"; do
    case "$value" in
      *$'\n'*|*$'\r'*|*'"'*|*'\\'*)
        e2e_finish_fail "served-console live input contains unsupported TOML characters"
        ;;
    esac
  done
}

# Dry-run checks only the registered wiring. It deliberately starts no server
# and is the sole posture permitted without live inputs.
if [ "$E2E_DRY_RUN" != "1" ]; then
  require_live_console_env
fi

# The web client's node modules are a prerequisite for the live Vitest phase,
# not for dry-run. Dry-run must still schedule the server build so the harness
# can prove its registered wiring on a host without web assets.
if [ "$E2E_DRY_RUN" != "1" ] && [ ! -d "$ROOT/web/node_modules/vitest" ]; then
  e2e_finish_skip "web/node_modules is not installed (run npm --prefix web ci)"
fi

command -v omcpb >/dev/null 2>&1 || e2e_finish_fail "omcpb is required to build the served-console binary"
if ! e2e_run_command "setup" omcpb build -p oraclemcp --bin oraclemcp; then
  e2e_finish_fail "building the served-console binary through omcpb failed"
fi

if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: served-console live wiring validated, no server started"
  e2e_finish_pass
  exit 0
fi

build_output="$(e2e_artifact_dir)/output.txt"
build_target="$(sed -n 's/^omcpb: lane [0-9][0-9]*  target=\([^ ]*\)  jobs=.*/\1/p' "$build_output" | tail -n 1)"
[ -n "$build_target" ] || e2e_finish_fail "omcpb completed without reporting its selected target directory"
OMCP_BIN="$build_target/debug/oraclemcp"
[ -x "$OMCP_BIN" ] || e2e_finish_fail "could not locate the omcpb-built served-console binary"
export OMCP_BIN
export OMCP_SERVED_E2E=1
export OMCP_SERVED_PORT="${OMCP_SERVED_PORT:-7393}"

e2e_log_event "scenario_note" "act" "running" 0 "validated local live Oracle inputs; positive-path proofs required"

if ! e2e_run_command "act" npm --prefix web exec -- vitest run src/app/served-console.e2e.test.ts; then
  e2e_finish_fail "served-console affordance proof failed"
fi

e2e_log_event "scenario_assert" "assert" "pass" 0 "console consumed a real governed row, SCN, audit-bound verdict proof, egress mask, cost/policy data, and reachable-plus-unreachable fleet map"
e2e_finish_pass
