#!/usr/bin/env bash
# Arc E3 deterministic fault-injection acceptance runner.  It is intentionally
# offline: LabRuntime and the real admission ledger must run, not skip, when no
# Oracle database is configured.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="seeded_fault_injection"
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
      echo "Run the seeded LabRuntime lane fault-injection harness (no Oracle required)."
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "seeded_fault_injection: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "offline seeded LabRuntime fault harness"
command -v omcpb >/dev/null 2>&1 || e2e_finish_fail "omcpb is required for the fault harness"

e2e_log_event "fault_harness_seed" "act" "running" 0 "fixed seed and bounded DPOR search"
if ! e2e_run_command "act" omcpb test -p oraclemcp-core --test seeded_fault_injection -- --nocapture; then
  e2e_finish_fail "offline seeded fault harness failed; this must never skip for a missing database"
fi
if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "fault_harness_wiring" "assert" "pass" 0 "dry-run scheduled the offline LabRuntime harness"
fi
e2e_log_event "fault_harness_seed" "assert" "pass" 0 "seed-reproduced permit leak and lost wakeup were detected"
e2e_log_event "fault_harness_dpor" "assert" "pass" 0 "bounded lane-switch-at-cap interleavings recorded"
e2e_finish_pass
