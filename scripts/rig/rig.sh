#!/usr/bin/env bash
# Local Integrator Rig entrypoint.
#
# R0 owns the shell around the live lanes: one command namespace, disposable
# Tier A pseudo-home, report skeleton, and host-hygiene assertions. The live DB
# lane remains scripts/rig/oracle_l1.sh; this wrapper supplies isolation and a
# single place for R1-R5 lanes to plug in.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="rig"
E2E_LANE="integrator"
E2E_PROFILE="tier-a"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

RUN_ID="${ORACLEMCP_RIG_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
RIG_ROOT="${ORACLEMCP_RIG_ROOT:-$ROOT/target/rig-home-$RUN_ID}"
RIG_STATE_DIR="${ORACLEMCP_RIG_STATE_DIR:-$ROOT/target/e2e/rig}"
RIG_STATE_FILE="$RIG_STATE_DIR/active-run.env"
RIG_REPORT_DIR="$RIG_STATE_DIR/$RUN_ID"
RIG_L1="$ROOT/scripts/rig/oracle_l1.sh"
RIG_DOCTOR="$ROOT/scripts/rig/rig_doctor.sh"
RIG_BOUNDARY_LINT="$ROOT/scripts/rig/rig_boundary_lint.sh"
RIG_IDLE_KILL="$ROOT/scripts/rig/rig_idle_kill.sh"
RIG_FAILURE_INJECTION="$ROOT/scripts/rig/failure_injection_lanes.sh"
RIG_BROWSER_LANE="$ROOT/scripts/rig/rig_browser_lane.sh"
RIG_REPORT="$ROOT/scripts/rig/rig_report.sh"

usage() {
  cat <<'USAGE'
Local Integrator Rig.

Usage:
  bash scripts/rig/rig.sh doctor [--log]
  bash scripts/rig/rig.sh up [--log|--dry-run]
  bash scripts/rig/rig.sh run [--log|--dry-run]
  bash scripts/rig/rig.sh idle-kill [--log|--dry-run]
  bash scripts/rig/rig.sh idle-kill-failure-probe [--log|--dry-run]
  bash scripts/rig/rig.sh failure-injection [--log|--dry-run]
  bash scripts/rig/rig.sh browser-lane [--log|--dry-run]
  bash scripts/rig/rig.sh report [--log|--dry-run]
  bash scripts/rig/rig.sh down [--log|--dry-run]

Default isolation is Tier A: a throwaway pseudo-home under target/rig-home-<runid>
with HOME, XDG_*, PATH, config, state, cache, and runtime redirected into it.
Host service-manager mutations are not run by this tier.
USAGE
  e2e_usage_common
}

parse_common_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --help|-h) usage; exit 0 ;;
      *)
        if e2e_parse_common_arg "$1"; then shift; continue; fi
        case $? in
          3) usage; exit 0 ;;
          *) e2e_finish_fail "unknown argument: $1" ;;
        esac
        ;;
    esac
    shift
  done
}

require_scaffold_tools() {
  [ -x "$RIG_DOCTOR" ] || e2e_finish_fail "rig doctor is not executable: $RIG_DOCTOR"
  [ -x "$RIG_L1" ] || e2e_finish_fail "rig L1 is not executable: $RIG_L1"
  [ -x "$RIG_BOUNDARY_LINT" ] || e2e_finish_fail "rig boundary lint is not executable: $RIG_BOUNDARY_LINT"
  [ -x "$RIG_IDLE_KILL" ] || e2e_finish_fail "rig idle-kill lane is not executable: $RIG_IDLE_KILL"
  [ -x "$RIG_FAILURE_INJECTION" ] || e2e_finish_fail "rig failure-injection lane is not executable: $RIG_FAILURE_INJECTION"
  [ -x "$RIG_BROWSER_LANE" ] || e2e_finish_fail "rig browser lane is not executable: $RIG_BROWSER_LANE"
  [ -x "$RIG_REPORT" ] || e2e_finish_fail "rig report lane is not executable: $RIG_REPORT"
  command -v git >/dev/null 2>&1 || e2e_finish_fail "git is required for host-hygiene snapshots"
  command -v find >/dev/null 2>&1 || e2e_finish_fail "find is required for host-hygiene snapshots"
}

tier_a_env_file() {
  printf '%s\n' "$RIG_REPORT_DIR/tier-a.env"
}

prepare_tier_a() {
  mkdir -p \
    "$RIG_ROOT/bin" \
    "$RIG_ROOT/home" \
    "$RIG_ROOT/config" \
    "$RIG_ROOT/state" \
    "$RIG_ROOT/cache" \
    "$RIG_ROOT/runtime" \
    "$RIG_REPORT_DIR"
  {
    printf 'ORACLEMCP_RIG_RUN_ID=%q\n' "$RUN_ID"
    printf 'ORACLEMCP_RIG_ROOT=%q\n' "$RIG_ROOT"
    printf 'HOME=%q\n' "$RIG_ROOT/home"
    printf 'XDG_CONFIG_HOME=%q\n' "$RIG_ROOT/config"
    printf 'XDG_STATE_HOME=%q\n' "$RIG_ROOT/state"
    printf 'XDG_CACHE_HOME=%q\n' "$RIG_ROOT/cache"
    printf 'XDG_RUNTIME_DIR=%q\n' "$RIG_ROOT/runtime"
    printf 'PATH=%q\n' "$RIG_ROOT/bin:$PATH"
    printf 'ORACLEMCP_CONFIG=%q\n' "$RIG_ROOT/config/oraclemcp/oraclemcp.toml"
    printf 'ORACLEMCP_E2E_ARTIFACT_DIR=%q\n' "$RIG_REPORT_DIR/artifacts"
  } >"$(tier_a_env_file)"
  mkdir -p "$RIG_STATE_DIR"
  cp "$(tier_a_env_file)" "$RIG_STATE_FILE"
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "tier_a_prepare" "setup" "skipped" 0 "root=$RIG_ROOT dry-run"
    return 0
  fi
  e2e_log_event "tier_a_prepare" "setup" "pass" 0 "root=$RIG_ROOT"
}

run_tier_a() {
  local env_file
  env_file="$(tier_a_env_file)"
  [ -f "$env_file" ] || prepare_tier_a
  set -a
  # shellcheck source=/dev/null
  . "$env_file"
  set +a
  "$@"
}

snapshot_host() {
  local label="$1"
  mkdir -p "$RIG_REPORT_DIR"
  git status --short >"$RIG_REPORT_DIR/git-status-$label.txt"
  if [ -d "$HOME/.config/oraclemcp" ]; then
    find "$HOME/.config/oraclemcp" -xdev -type f -printf '%P\t%s\t%T@\n' \
      | sort >"$RIG_REPORT_DIR/home-config-$label.txt"
  else
    : >"$RIG_REPORT_DIR/home-config-$label.txt"
  fi
  if command -v systemctl >/dev/null 2>&1; then
    systemctl --user list-unit-files 'oraclemcp*.service' --no-legend 2>/dev/null \
      | sort >"$RIG_REPORT_DIR/user-units-$label.txt" || : >"$RIG_REPORT_DIR/user-units-$label.txt"
  else
    : >"$RIG_REPORT_DIR/user-units-$label.txt"
  fi
}

assert_host_hygiene() {
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "host_hygiene" "assert" "skipped" 0 "dry-run"
    return 0
  fi
  snapshot_host after
  local failed=0
  for subject in git-status home-config user-units; do
    if ! cmp -s "$RIG_REPORT_DIR/$subject-before.txt" "$RIG_REPORT_DIR/$subject-after.txt"; then
      e2e_log_event "host_hygiene" "assert" "fail" 0 "$subject changed"
      failed=1
    fi
  done
  [ "$failed" -eq 0 ] || e2e_finish_fail "host hygiene changed; inspect $RIG_REPORT_DIR"
  e2e_log_event "host_hygiene" "assert" "pass" 0 "host config, user units, and git status unchanged"
}

write_report() {
  local report_args=(run --out-dir "$RIG_REPORT_DIR")
  [ "$E2E_LOG" = "1" ] && report_args+=(--log)
  [ "$E2E_DRY_RUN" = "1" ] && report_args+=(--dry-run)
  bash "$RIG_REPORT" "${report_args[@]}"
  [ "$E2E_LOG" = "1" ] || printf 'rig report: %s\n' "$RIG_REPORT_DIR/findings.md"
}

safe_down() {
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "tier_a_down" "teardown" "skipped" 0 "root=$RIG_ROOT dry-run"
    return 0
  fi
  case "$RIG_ROOT" in
    "$ROOT"/target/rig-home-*) ;;
    *) e2e_finish_fail "refusing to remove non-rig root: $RIG_ROOT" ;;
  esac
  [ -d "$RIG_ROOT" ] || {
    e2e_log_event "tier_a_down" "teardown" "pass" 0 "root=$RIG_ROOT already absent"
    return 0
  }
  rm -rf "$RIG_ROOT"
  e2e_log_event "tier_a_down" "teardown" "pass" 0 "root=$RIG_ROOT removed"
}

cmd="${1:-run}"
if [ "$#" -gt 0 ]; then
  shift
fi
parse_common_args "$@"
require_scaffold_tools

case "$cmd" in
  doctor)
    bash "$RIG_DOCTOR" "$@"
    ;;
  up)
    snapshot_host before
    bash "$RIG_DOCTOR" "$@"
    prepare_tier_a
    run_tier_a bash "$RIG_L1" up "$@"
    assert_host_hygiene
    e2e_finish_pass
    ;;
  run)
    snapshot_host before
    bash "$RIG_DOCTOR" "$@"
    bash "$RIG_BOUNDARY_LINT"
    prepare_tier_a
    run_tier_a bash "$RIG_L1" run "$@"
    run_tier_a bash "$RIG_BROWSER_LANE" run "$@"
    write_report
    assert_host_hygiene
    e2e_finish_pass
    ;;
  idle-kill)
    snapshot_host before
    bash "$RIG_DOCTOR" "$@"
    prepare_tier_a
    run_tier_a bash "$RIG_IDLE_KILL" run "$@"
    assert_host_hygiene
    e2e_finish_pass
    ;;
  idle-kill-failure-probe)
    snapshot_host before
    bash "$RIG_DOCTOR" "$@"
    prepare_tier_a
    run_tier_a bash "$RIG_IDLE_KILL" failure-probe "$@"
    assert_host_hygiene
    e2e_finish_pass
    ;;
  failure-injection)
    snapshot_host before
    bash "$RIG_DOCTOR" "$@"
    prepare_tier_a
    run_tier_a bash "$RIG_FAILURE_INJECTION" run "$@"
    assert_host_hygiene
    e2e_finish_pass
    ;;
  browser-lane)
    snapshot_host before
    bash "$RIG_DOCTOR" "$@"
    prepare_tier_a
    run_tier_a bash "$RIG_BROWSER_LANE" run "$@"
    assert_host_hygiene
    e2e_finish_pass
    ;;
  report)
    write_report
    e2e_finish_pass
    ;;
  down)
    safe_down
    e2e_finish_pass
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
