#!/usr/bin/env bash
# Static contract test for the manual Docker provenance-recovery workflow.
# shellcheck disable=SC2016 # Fixed strings intentionally contain shell/GHA syntax.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="${ORACLEMCP_DOCKER_WORKFLOW:-$ROOT/.github/workflows/docker.yml}"

fail() {
  echo "docker-provenance-workflow: $*" >&2
  exit 1
}

require() {
  local needle="$1"
  grep -F -- "$needle" "$WORKFLOW" >/dev/null ||
    fail "missing required contract: $needle"
}

line_of() {
  local needle="$1"
  local line
  line="$(grep -nF -- "$needle" "$WORKFLOW" | head -n 1 | cut -d: -f1)"
  [ -n "$line" ] || fail "cannot order missing contract: $needle"
  printf '%s\n' "$line"
}

before() {
  local first="$1"
  local second="$2"
  [ "$(line_of "$first")" -lt "$(line_of "$second")" ] ||
    fail "expected '$first' before '$second'"
}

[ -f "$WORKFLOW" ] || fail "missing $WORKFLOW"

# Dispatch is explicit and serialized per immutable release/variant pair.
require 'description: "Existing release version whose immutable image should be promoted."'
require 'default: "rollback"'
require 'group: docker-provenance-${{ inputs.version }}-${{ inputs.variant }}'
require 'cancel-in-progress: false'

# The read-only job validates syntax, resolves the exact tag, and proves all
# release metadata before the registry-writing job can begin.
require 'verify-release:'
require 'needs: verify-release'
require 'ref: refs/tags/v${{ steps.release.outputs.version }}'
require 'ref: refs/tags/v${{ needs.verify-release.outputs.version }}'
require 'tag_sha="$(git rev-parse "$tag^{commit}")"'
require '[ "$source_sha" = "$tag_sha" ]'
require '[ "$cargo_version" = "$VERSION" ]'
require '[ "$server_version" = "$VERSION" ]'
require 'RELEASE_TAG="v$VERSION" bash scripts/release_preflight.sh'
before 'verify-release:' 'packages: write'
before 'Verify tag commit and release metadata' 'Log in to GHCR'

# Recovery never writes the immutable version tag. It resolves and verifies its
# digest, and only imagetools-creates the rolling tag from that digest.
require 'digest="$(docker buildx imagetools inspect "$VERSION_IMAGE" --format'
require 'rollback never rebuilds or creates a version tag'
require 'cosign verify'
require "if: needs.verify-release.outputs.operation == 'rollback' && steps.existing.outputs.exists == 'true'"
require 'release.yml@refs/tags/v$VERSION'
if grep -F '[ "$VARIANT" = "core" ] && cosign verify' "$WORKFLOW" >/dev/null; then
  fail "tag-workflow provenance must be accepted for every published variant"
fi
require '-a "oraclemcp.source_sha=$SOURCE_SHA"'
require 'outputs: type=image,name=${{ env.IMAGE_REPOSITORY }},push-by-digest=true,name-canonical=true,push=true'
require '[ "$REBUILT_DIGEST" != "$EXPECTED_DIGEST" ]'
require 'refusing to replace immutable release image'
require 'Publish missing immutable version tag'
require 'refusing to race or replace newly-created version tag'
require '--tag "$ROLLING_IMAGE"'
require '"$IMAGE_REPOSITORY@$DIGEST"'
require 'Existing version tag rewritten: \`false\`'
before 'Resolve immutable version digest' 'Rebuild exact tag source by digest'
before 'Refuse a non-identical rebuild' 'Sign source-bound rebuild'
before 'Refuse a non-identical rebuild' 'Promote verified digest to rolling tag'

if grep -F 'tags: ${{ steps.' "$WORKFLOW" >/dev/null; then
  fail "manual recovery must not pass version and rolling tags to build-push-action"
fi
before 'refusing to race or replace newly-created version tag' '--tag "$VERSION_IMAGE"'
if [ "$(grep -c 'packages: write' "$WORKFLOW")" -ne 1 ]; then
  fail "packages:write must appear only in the gated promotion job"
fi

echo "docker-provenance-workflow: immutable tag, digest comparison, and rollback contracts verified"
