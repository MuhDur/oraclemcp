#!/usr/bin/env bash
# Emit a reviewable rollback plan for an explicitly named broken release and
# previous-good release. This script is dry-run-only and never mutates local or
# public state.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="rollback_runbook_dry_run"
E2E_LANE="release"
E2E_PROFILE="release"
E2E_LEVEL="ADMIN"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

BROKEN_VERSION=""
PREVIOUS_VERSION=""

usage() {
  cat <<'USAGE'
Dry-run the release rollback runbook command plan.

Required options:
  --broken-version VERSION        Broken release version, without leading v
  --previous-good VERSION         Previous-good release to restore as latest

The versions are deliberately required. There is no implicit rollback target.
USAGE
  e2e_usage_common
}

while [ "$#" -gt 0 ]; do
  arg="$1"
  shift
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
        --broken-version)
          [ "$#" -gt 0 ] || e2e_finish_fail "--broken-version requires a value"
          BROKEN_VERSION="$1"
          shift
          ;;
        --broken-version=*)
          BROKEN_VERSION="${arg#*=}"
          ;;
        --previous-good)
          [ "$#" -gt 0 ] || e2e_finish_fail "--previous-good requires a value"
          PREVIOUS_VERSION="$1"
          shift
          ;;
        --previous-good=*)
          PREVIOUS_VERSION="${arg#*=}"
          ;;
        *)
          echo "release_rollback_dry_run: unknown argument: $arg" >&2
          exit 2
          ;;
      esac
      ;;
  esac
done

if [ "$E2E_DRY_RUN" != "1" ]; then
  e2e_finish_fail "rollback runbook is dry-run-only; copy reviewed commands manually after explicit operator approval"
fi
if [ -z "$BROKEN_VERSION" ] || [ -z "$PREVIOUS_VERSION" ]; then
  e2e_finish_fail "both --broken-version and --previous-good are required; refusing an implicit rollback target"
fi
semver_re='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z][0-9A-Za-z.-]*)?$'
if [[ ! "$BROKEN_VERSION" =~ $semver_re ]]; then
  e2e_finish_fail "invalid broken release version: $BROKEN_VERSION"
fi
if [[ ! "$PREVIOUS_VERSION" =~ $semver_re ]]; then
  e2e_finish_fail "invalid previous-good release version: $PREVIOUS_VERSION"
fi
if [ "$BROKEN_VERSION" = "$PREVIOUS_VERSION" ]; then
  e2e_finish_fail "broken and previous-good releases must differ"
fi

TAG="v$BROKEN_VERSION"

require_literal() {
  local file="$1"
  local literal="$2"
  grep -F -- "$literal" "$ROOT/$file" >/dev/null ||
    e2e_finish_fail "$file no longer satisfies rollback topology contract: missing $literal"
}

# Tag publication belongs to release.yml. The two smaller workflows are
# dispatch-only recovery tools and must never become competing tag publishers.
require_literal .github/workflows/release.yml 'tags: ["v*"]'
require_literal .github/workflows/release.yml 'ROLLBACK_COVERAGE: crates.io=publish-crates github-release=release signed-artifacts=release ghcr=docker mcp-registry=publish-mcp-registry'
require_literal .github/workflows/release.yml '  publish-crates:'
require_literal .github/workflows/release.yml '  release:'
require_literal .github/workflows/release.yml '  docker:'
require_literal .github/workflows/release.yml '  publish-mcp-registry:'
# Tranche-1 scheduling contract: expensive artifact builds overlap acceptance,
# but crates.io publication remains gated by both. Acceptance may skip only the
# powerset already proved by the same-SHA `checks` prerequisite.
require_literal .github/workflows/release.yml '    needs: [checks, pinned-nightly, web-build]'
require_literal .github/workflows/release.yml '    needs: [build, release-acceptance]'
require_literal .github/workflows/release.yml 'scripts/release_acceptance_ci_suite.sh --skip-feature-powerset'
for auxiliary in .github/workflows/docker.yml .github/workflows/publish-mcp.yml; do
  require_literal "$auxiliary" '  workflow_dispatch:'
  if grep -Eq '^  push:' "$ROOT/$auxiliary"; then
    e2e_finish_fail "$auxiliary must remain a manual recovery workflow, not a tag publisher"
  fi
done

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 \
  "rollback dry-run for broken=$TAG previous_good=v$PREVIOUS_VERSION"
e2e_log_event "channel_inventory" "assert" "pass" 0 \
  "tag pipeline channels: crates.io, GitHub release, signed artifacts, GHCR, MCP registry; pending registry promotion: Homebrew, winget"
e2e_log_event "workflow_topology" "assert" "pass" 0 \
  "release.yml owns tag publication; docker.yml and publish-mcp.yml are manual recovery auxiliaries"

metadata="$(cargo metadata --locked --offline --no-deps --format-version 1)" ||
  e2e_finish_fail "cargo metadata could not enumerate workspace crates"
mapfile -t crates < <(jq -r '.packages[] | select(.publish != []) | .name' <<<"$metadata")
if [ "${#crates[@]}" -eq 0 ]; then
  e2e_finish_fail "cargo metadata found no publishable workspace crates"
fi

plan_check() {
  local channel="$1"
  shift
  e2e_log_event "publication_check" "assert" "pass" 0 "channel=$channel command=$*"
  e2e_run_command "assert" "$@"
}

plan_action() {
  local channel="$1"
  local approval="$2"
  local condition="$3"
  shift 3
  e2e_log_event "approval_required" "assert" "pass" 0 \
    "channel=$channel approval=$approval condition=$condition command=$*"
  e2e_run_command "act" "$@"
}

# First reconcile what the authoritative tag workflow actually published.
plan_check tag-pipeline gh run list --workflow=release.yml --branch "$TAG" --limit 20
for crate in "${crates[@]}"; do
  plan_check crates.io cargo info "$crate@$BROKEN_VERSION"
done
plan_check github-release gh release view "$TAG" --json tagName,isDraft,isPrerelease,assets,url
plan_check ghcr docker buildx imagetools inspect "ghcr.io/muhdur/oraclemcp:$BROKEN_VERSION"
plan_check ghcr docker buildx imagetools inspect ghcr.io/muhdur/oraclemcp:latest
plan_check mcp-registry bash -c \
  "curl -fsS 'https://registry.modelcontextprotocol.io/v0/servers?search=oraclemcp&limit=20' | jq -e --arg version '$BROKEN_VERSION' '.servers[] | select(.server.name == \"io.github.MuhDur/oraclemcp\" and .server.version == \$version)'"
plan_check homebrew brew info MuhDur/oraclemcp/oraclemcp
plan_check winget winget show --id MuhDur.oraclemcp --exact

# Every public mutation is conditional on the checks above and separately
# approval-gated. The script still skips every command because it is dry-run-only.
for crate in "${crates[@]}"; do
  plan_action crates.io irreversible "exact $crate@$BROKEN_VERSION is published and operator approved yank" \
    cargo yank -p "$crate" --vers "$BROKEN_VERSION"
done
plan_action github-release reversible "GitHub release exists and operator approved incident marking" \
  gh release edit "$TAG" --prerelease
plan_action github-release destructive-optional "artifacts must be hidden and operator separately approved release plus tag deletion" \
  gh release delete "$TAG" --yes --cleanup-tag
plan_action ghcr outward "versioned previous-good image exists, is signed, and rolling latest needs repair" \
  gh workflow run docker.yml -f "version=$PREVIOUS_VERSION" -f variant=core -f operation=rollback
e2e_log_event "manual_channel" "assert" "pass" 0 \
  "MCP registry: published versions are immutable and cannot be unpublished; record $BROKEN_VERSION and cut a fixed higher version through release.yml because republishing $PREVIOUS_VERSION cannot become latest"
e2e_log_event "manual_channel" "assert" "pass" 0 \
  "Homebrew: only submit a rollback formula update if brew info resolves $BROKEN_VERSION; record PR and propagation state"
e2e_log_event "manual_channel" "assert" "pass" 0 \
  "winget: only submit a rollback manifest update if winget show resolves $BROKEN_VERSION; record PR and propagation state"
e2e_log_event "scenario_assert" "assert" "pass" 0 \
  "rollback plan is non-mutating and covers the current tag pipeline, published channels, signed release evidence, and pending registry promotions"
e2e_finish_pass
