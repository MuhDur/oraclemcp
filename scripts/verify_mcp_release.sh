#!/usr/bin/env bash
# Bind MCP registry publication to an existing immutable, signed release image.
set -euo pipefail

ROOT="${ORACLEMCP_RELEASE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

fail() {
  echo "verify-mcp-release: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

mode="${1:-}"
case "$mode" in
  validate | revalidate) ;;
  *) fail "usage: scripts/verify_mcp_release.sh validate|revalidate" ;;
esac

git_bin="${ORACLEMCP_GIT_BIN:-git}"
gh_bin="${ORACLEMCP_GH_BIN:-gh}"
docker_bin="${ORACLEMCP_DOCKER_BIN:-docker}"
cosign_bin="${ORACLEMCP_COSIGN_BIN:-cosign}"
version="${VERSION:-}"
repository="${GITHUB_REPOSITORY:-}"
expected_source_sha="${EXPECTED_SOURCE_SHA:-}"
expected_image_digest="${EXPECTED_IMAGE_DIGEST:-}"
oidc_issuer="${EXPECTED_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  fail "VERSION must be stable SemVer (got '$version')"
[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
  fail "GITHUB_REPOSITORY must be owner/repository"
if [ "$mode" = "revalidate" ]; then
  [[ "$expected_source_sha" =~ ^[0-9a-f]{40}$ ]] || fail "EXPECTED_SOURCE_SHA is required"
  [[ "$expected_image_digest" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    fail "EXPECTED_IMAGE_DIGEST is required"
fi
need "$git_bin"
need "$gh_bin"
need "$docker_bin"
need "$cosign_bin"
need jq
need python3

cd "$ROOT"
tag="refs/tags/v$version"
"$git_bin" show-ref --verify --quiet "$tag" || fail "release tag does not exist: $tag"
source_sha="$("$git_bin" rev-parse HEAD)"
tag_sha="$("$git_bin" rev-parse "$tag^{commit}")"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || fail "current checkout did not resolve to a commit SHA"
[ "$source_sha" = "$tag_sha" ] || fail "checkout $source_sha does not match $tag at $tag_sha"
if [ -n "$expected_source_sha" ]; then
  [ "$source_sha" = "$expected_source_sha" ] ||
    fail "checkout source $source_sha changed after validation ($expected_source_sha)"
fi

"$git_bin" fetch --no-tags origin main >/dev/null 2>&1 || fail "could not fetch origin/main"
"$git_bin" merge-base --is-ancestor "$source_sha" origin/main ||
  fail "$tag commit $source_sha is not contained in origin/main"

cargo_version="$(python3 "$ROOT/scripts/release_surface_manifest.py" --value server_version)" ||
  fail "could not structurally resolve workspace version"
server_version="$(jq -er '.version | select(type == "string")' "$ROOT/server.json")" ||
  fail "server.json has no string version"
[ "$cargo_version" = "$version" ] ||
  fail "workspace version $cargo_version does not match requested release $version"
[ "$server_version" = "$version" ] ||
  fail "server.json version $server_version does not match requested release $version"

image="$(jq -er '[.packages[] | select(.registryType == "oci") | .identifier] | if length == 1 then .[0] else error("expected one OCI package") end' "$ROOT/server.json")" ||
  fail "server.json must contain exactly one OCI package"
expected_image="ghcr.io/muhdur/oraclemcp:$version"
[ "$image" = "$expected_image" ] ||
  fail "server.json image $image does not match immutable release image $expected_image"

release_json="$("$gh_bin" release view "v$version" --repo "$repository" --json tagName,isDraft,isPrerelease)" ||
  fail "GitHub release v$version does not exist"
jq -e --arg tag "v$version" \
  '.tagName == $tag and .isDraft == false and .isPrerelease == false' \
  <<<"$release_json" >/dev/null ||
  fail "GitHub release v$version is missing, draft, prerelease, or names a different tag"

image_digest="$("$docker_bin" buildx imagetools inspect "$image" --format '{{.Manifest.Digest}}')" ||
  fail "could not resolve GHCR digest for $image"
[[ "$image_digest" =~ ^sha256:[0-9a-f]{64}$ ]] ||
  fail "GHCR returned an invalid digest for $image: $image_digest"
if [ -n "$expected_image_digest" ]; then
  [ "$image_digest" = "$expected_image_digest" ] ||
    fail "GHCR digest changed after validation ($image_digest != $expected_image_digest)"
fi

subject="ghcr.io/muhdur/oraclemcp@$image_digest"
release_identity="https://github.com/$repository/.github/workflows/release.yml@$tag"
recovery_identity="https://github.com/$repository/.github/workflows/docker.yml@refs/heads/main"
if "$cosign_bin" verify \
  --certificate-identity "$release_identity" \
  --certificate-oidc-issuer "$oidc_issuer" \
  "$subject" >/dev/null; then
  signature_source="release"
elif "$cosign_bin" verify \
  --certificate-identity "$recovery_identity" \
  --certificate-oidc-issuer "$oidc_issuer" \
  -a "oraclemcp.source_sha=$source_sha" \
  -a "oraclemcp.version=$version" \
  -a "oraclemcp.variant=core" \
  "$subject" >/dev/null; then
  signature_source="recovery"
else
  fail "no exact release or source-bound recovery signature verified for $image_digest"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "version=$version"
    echo "source_sha=$source_sha"
    echo "image=$image"
    echo "image_digest=$image_digest"
  } >>"$GITHUB_OUTPUT"
fi

echo "verify-mcp-release: OK mode=$mode tag=v$version source=$source_sha digest=$image_digest signature=$signature_source"
