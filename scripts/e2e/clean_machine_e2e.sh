#!/usr/bin/env bash
# H5 clean-machine acceptance harness.
#
# This script intentionally does not install or uninstall a service by default.
# The real acceptance proof is collected after an operator/sandbox has rebooted
# with an oraclemcp user service already installed and configured for two live
# test database profiles.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="clean_machine_e2e"
E2E_LANE="clean-machine"
E2E_PROFILE="multi-db"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

print_reboot_marker=false

usage() {
  cat <<'USAGE'
Run the H5 clean-machine e2e:
  reboot -> user service already running -> dashboard -> two agents/two DBs.

Required for the real run:
  ORACLEMCP_CLEAN_MACHINE_E2E=1
  ORACLEMCP_CLEAN_MACHINE_BOOT_ID_BEFORE=<boot id captured before reboot>
  ORACLEMCP_CLEAN_MACHINE_URL=http://127.0.0.1:7070
  ORACLEMCP_CLEAN_MACHINE_SERVICE_NAME=oraclemcp
  ORACLEMCP_CLEAN_MACHINE_PROFILE_A=<test/free/xe/local profile>
  ORACLEMCP_CLEAN_MACHINE_PROFILE_B=<test/free/xe/local profile>

For authenticated HTTP services, also set:
  ORACLEMCP_CLEAN_MACHINE_BEARER_A=<agent A bearer>
  ORACLEMCP_CLEAN_MACHINE_BEARER_B=<agent B bearer>

For local allow-no-auth test services only:
  ORACLEMCP_CLEAN_MACHINE_ALLOW_NO_AUTH=1

Options:
  --print-reboot-marker  print an export line for the current boot id, to save
                         before rebooting the clean-machine test sandbox
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
    3)
      usage
      exit 0
      ;;
    1)
      case "$arg" in
        --print-reboot-marker)
          print_reboot_marker=true
          ;;
        *)
          echo "clean_machine_e2e: unknown argument: $arg" >&2
          exit 2
          ;;
      esac
      ;;
  esac
done

current_boot_id() {
  if [ -r /proc/sys/kernel/random/boot_id ]; then
    tr -d '\n' </proc/sys/kernel/random/boot_id
  fi
}

require_loopback_url() {
  local url="$1"
  case "$url" in
    http://127.0.0.1:*|http://localhost:*|http://[::1]:*) ;;
    *)
      e2e_finish_fail "ORACLEMCP_CLEAN_MACHINE_URL must be a loopback http URL"
      ;;
  esac
  if e2e_value_has_production_marker "$url"; then
    e2e_finish_fail "refusing production-looking clean-machine URL"
  fi
}

require_test_profile_name() {
  local name="$1"
  local value="${!name:-}"
  if [ -z "$value" ]; then
    e2e_finish_skip "set $name for H5 clean-machine proof"
  fi
  if e2e_value_has_production_marker "$value"; then
    e2e_finish_fail "refusing production-looking clean-machine profile $name"
  fi
  if ! e2e_value_has_test_marker "$value"; then
    e2e_finish_fail "$name must include a local/free/xe/test marker"
  fi
}

require_clean_machine_env() {
  if [ "${ORACLEMCP_CLEAN_MACHINE_E2E:-}" != "1" ]; then
    e2e_finish_skip "set ORACLEMCP_CLEAN_MACHINE_E2E=1 to run H5 clean-machine proof"
  fi

  local url="${ORACLEMCP_CLEAN_MACHINE_URL:-http://127.0.0.1:7070}"
  require_loopback_url "$url"

  local service_name="${ORACLEMCP_CLEAN_MACHINE_SERVICE_NAME:-oraclemcp}"
  if e2e_value_has_production_marker "$service_name"; then
    e2e_finish_fail "refusing production-looking clean-machine service name"
  fi

  require_test_profile_name ORACLEMCP_CLEAN_MACHINE_PROFILE_A
  require_test_profile_name ORACLEMCP_CLEAN_MACHINE_PROFILE_B

  if [ -z "${ORACLEMCP_CLEAN_MACHINE_BOOT_ID_BEFORE:-}" ]; then
    e2e_finish_skip "save ORACLEMCP_CLEAN_MACHINE_BOOT_ID_BEFORE from --print-reboot-marker before reboot"
  fi

  if [ "${ORACLEMCP_CLEAN_MACHINE_ALLOW_NO_AUTH:-}" != "1" ]; then
    for name in ORACLEMCP_CLEAN_MACHINE_BEARER_A ORACLEMCP_CLEAN_MACHINE_BEARER_B; do
      if [ -z "${!name:-}" ]; then
        e2e_finish_skip "set $name, or ORACLEMCP_CLEAN_MACHINE_ALLOW_NO_AUTH=1 for local test services"
      fi
    done
  fi
}

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "H5 clean-machine proof safety gate"

if [ "$print_reboot_marker" = true ]; then
  boot_id="$(current_boot_id)"
  if [ -z "$boot_id" ]; then
    e2e_finish_fail "this platform cannot report a boot id; set ORACLEMCP_CLEAN_MACHINE_BOOT_ID_BEFORE manually"
  fi
  printf 'export ORACLEMCP_CLEAN_MACHINE_BOOT_ID_BEFORE=%q\n' "$boot_id"
  e2e_log_event "reboot_marker" "setup" "pass" 0 "captured current boot id for pre-reboot marker"
  e2e_finish_pass
fi

require_clean_machine_env

if ! e2e_run_command "act" cargo test -p oraclemcp --features live-xe --test clean_machine_e2e -- --ignored --nocapture; then
  e2e_finish_fail "H5 clean-machine proof failed"
fi

e2e_log_event "scenario_assert" "assert" "pass" 0 "H5 rebooted service dashboard two-agent two-DB proof completed"
e2e_finish_pass
