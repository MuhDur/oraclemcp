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
# No live Oracle is required: the affordance-honesty postures are exactly the
# ones that hold when the server has NOT completed a governed statement, which is
# what a fresh read-only lane without a reachable DB produces.
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

# The web client's node modules are a prerequisite; skip cleanly if absent rather
# than fail the aggregate suite on a machine that never installed them.
if [ ! -d "$ROOT/web/node_modules/vitest" ]; then
  e2e_finish_skip "web/node_modules is not installed (run npm --prefix web ci)"
fi

if ! e2e_run_command "act" cargo build -p oraclemcp --bin oraclemcp; then
  e2e_finish_fail "building the oraclemcp binary failed"
fi

OMCP_BIN="$ROOT/target/debug/oraclemcp"
if [ ! -x "$OMCP_BIN" ]; then
  # Swarm builds land under a lane-specific target dir; fall back to the newest.
  OMCP_BIN="$(ls -t "$ROOT"/target*/debug/oraclemcp /home/*/.cache/omcp-swarm/target-*/debug/oraclemcp 2>/dev/null | head -1 || true)"
fi
if [ -z "${OMCP_BIN:-}" ] || [ ! -x "$OMCP_BIN" ]; then
  e2e_finish_fail "could not locate the built oraclemcp binary"
fi
export OMCP_BIN
export OMCP_SERVED_E2E=1
export OMCP_SERVED_PORT="${OMCP_SERVED_PORT:-7393}"

# When a live Oracle is offered (OMCP_LIVE_DSN + creds), the suite drives a real
# governed SELECT and proves the REAL proof-carrying record, observed_scn, and
# federated fleet map. Without it, the suite proves the honesty negatives only.
# Both postures are green; the live variables simply widen coverage.
if [ -n "${OMCP_LIVE_DSN:-}" ]; then
  e2e_log_event "scenario_note" "act" "running" 0 "live DB offered; positive-path proofs enabled"
else
  e2e_log_event "scenario_note" "act" "running" 0 "no live DB; proving honesty negatives"
fi

if ! e2e_run_command "act" npm --prefix web exec -- vitest run src/app/served-console.e2e.test.ts; then
  e2e_finish_fail "served-console affordance proof failed"
fi

e2e_log_event "scenario_assert" "assert" "pass" 0 "console affordances consumed real served responses; honesty negatives held"
e2e_finish_pass
