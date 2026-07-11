#!/usr/bin/env bash
# Dry-run the v0.6.0 rollback command plan. This script never performs outward
# rollback actions; it only emits the exact commands an operator would review.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="rollback_runbook_dry_run"
E2E_LANE="release"
E2E_PROFILE="release"
E2E_LEVEL="ADMIN"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

VERSION="${ORACLEMCP_ROLLBACK_VERSION:-0.6.0}"
PREVIOUS_VERSION="${ORACLEMCP_ROLLBACK_PREVIOUS_VERSION:-0.4.1}"
TAG="v$VERSION"
PREVIOUS_TAG="v$PREVIOUS_VERSION"

usage() {
  cat <<'USAGE'
Dry-run the release rollback runbook command plan.

Environment:
  ORACLEMCP_ROLLBACK_VERSION           Broken release version (default: 0.6.0)
  ORACLEMCP_ROLLBACK_PREVIOUS_VERSION  Version to restore as latest (default: 0.4.1)
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
      echo "release_rollback_dry_run: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

if [ "$E2E_DRY_RUN" != "1" ]; then
  e2e_finish_fail "rollback runbook is dry-run-only; copy reviewed commands manually after explicit operator approval"
fi

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "Appendix B.12 rollback runbook dry-run"

crates=(
  oraclemcp-error
  oraclemcp-telemetry
  oraclemcp-audit
  oraclemcp-guard
  oraclemcp-config
  oraclemcp-db
  oraclemcp-auth
  oraclemcp-core
  oraclemcp
)

for crate in "${crates[@]}"; do
  e2e_run_command "act" cargo yank -p "$crate" --vers "$VERSION"
done

e2e_run_command "act" gh release edit "$TAG" --prerelease
e2e_run_command "act" gh release delete "$TAG" --yes --cleanup-tag

e2e_run_command "act" gh workflow run docker.yml -f "version=$PREVIOUS_VERSION" -f "variant=core" -f "operation=rollback"
e2e_run_command "act" gh workflow run docker.yml -f "version=$PREVIOUS_VERSION" -f "variant=plsql-intelligence" -f "operation=rollback"

e2e_run_command "act" git restore --source="$PREVIOUS_TAG" -- server.json
e2e_run_command "act" git commit -m "chore: revert MCP registry listing to $PREVIOUS_TAG" server.json
e2e_run_command "act" gh workflow run publish-mcp.yml --ref main

e2e_run_command "act" npm deprecate "oraclemcp@$VERSION" "Broken release; use $PREVIOUS_VERSION while rollback is active."
e2e_run_command "act" npm dist-tag add "oraclemcp@$PREVIOUS_VERSION" latest

e2e_log_event "manual_lag" "assert" "pass" 0 "Homebrew and winget are pull-based; submit rollback PRs and document propagation lag."
e2e_log_event "scenario_assert" "assert" "pass" 0 "rollback plan covers crates.io, GitHub release, GHCR latest, server.json, npm, Homebrew, and winget"
e2e_finish_pass
