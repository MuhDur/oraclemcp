#!/usr/bin/env bash
# R2: full MCP tool-surface sweep through an installed artifact and raw wire client.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="rig_tool_surface_sweep"
E2E_LANE="tool-surface"
E2E_PROFILE="matrix"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

usage() {
  cat <<'USAGE'
R2 tool-surface sweep.

Usage:
  bash scripts/rig/tool_surface_sweep.sh [run] [--log|--dry-run]

Builds and installs oraclemcp from a git-archive copy of HEAD into a rig prefix,
then drives the installed binary with an independent line-delimited JSON-RPC
stdio client. The sweep counts the running server's tool surface and invokes
every advertised tool across read_only, protected, proxy_auth, pooled, and drcp
synthetic local profiles.
USAGE
  e2e_usage_common
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      run) shift ;;
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
}

parse_args "$@"

command -v python3 >/dev/null 2>&1 || e2e_finish_fail "python3 is required for R2 wire sweep"
command -v cargo >/dev/null 2>&1 || e2e_finish_fail "cargo is required to install the R2 artifact"
command -v git >/dev/null 2>&1 || e2e_finish_fail "git is required to archive HEAD for R2"
command -v tar >/dev/null 2>&1 || e2e_finish_fail "tar is required to unpack the R2 source archive"

if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "install_artifact" "setup" "skipped" 0 "dry-run"
  e2e_log_event "wire_sweep" "assert" "skipped" 0 "dry-run"
  e2e_finish_pass
  exit 0
fi

e2e_run_command "assert" python3 "$ROOT/scripts/rig/tool_surface_sweep.py" "$@"
e2e_finish_pass
