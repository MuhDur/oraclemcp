#!/usr/bin/env bash
# Verify and smoke an untagged release digest before creating immutable/rolling tags.
set -euo pipefail

fail() {
  echo "promote-release-image: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

docker_bin="${ORACLEMCP_DOCKER_BIN:-docker}"
cosign_bin="${ORACLEMCP_COSIGN_BIN:-cosign}"
image_repository="${IMAGE_REPOSITORY:-ghcr.io/muhdur/oraclemcp}"
version="${VERSION:-}"
digest="${DIGEST:-}"
publish_latest="${PUBLISH_LATEST:-false}"
certificate_identity="${EXPECTED_CERTIFICATE_IDENTITY:-}"
oidc_issuer="${EXPECTED_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] ||
  fail "VERSION must be stable or prerelease SemVer (got '$version')"
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "DIGEST is not sha256:HEX"
case "$publish_latest" in
  true | false) ;;
  *) fail "PUBLISH_LATEST must be true or false" ;;
esac
[ -n "$certificate_identity" ] || fail "EXPECTED_CERTIFICATE_IDENTITY is required"
need "$docker_bin"
need "$cosign_bin"

version_image="$image_repository:$version"
subject="$image_repository@$digest"

inspect_digest() {
  local image="$1"
  local result
  if result="$("$docker_bin" buildx imagetools inspect "$image" --format '{{.Manifest.Digest}}' 2>&1)"; then
    if [[ ! "$result" =~ ^sha256:[0-9a-f]{64}$ ]]; then
      echo "promote-release-image: registry returned an invalid digest for $image: $result" >&2
      return 2
    fi
    printf '%s\n' "$result"
    return 0
  fi
  if [[ "$result" =~ [Mm]anifest[[:space:]]+[Uu]nknown ]] ||
    [[ "$result" =~ ^ERROR:.*:[[:space:]]not[[:space:]]found$ ]]; then
    return 1
  fi
  echo "promote-release-image: registry lookup failed for $image: $result" >&2
  return 2
}

# The candidate was pushed by digest only. A version tag is read before any
# signature, smoke, or tag operation; an existing different digest is terminal.
if existing_digest="$(inspect_digest "$version_image")"; then
  [ "$existing_digest" = "$digest" ] ||
    fail "refusing to replace immutable release image $version_image ($existing_digest != $digest)"
else
  inspect_status=$?
  [ "$inspect_status" -eq 1 ] || fail "could not safely resolve $version_image"
fi

"$cosign_bin" verify \
  --certificate-identity "$certificate_identity" \
  --certificate-oidc-issuer "$oidc_issuer" \
  "$subject" >/dev/null || fail "cosign verification failed for $subject"

# Smoke the immutable subject itself. No mutable tag exists or moves before
# this succeeds.
"$docker_bin" pull "$subject" >/dev/null || fail "could not pull candidate digest $subject"
# shellcheck disable=SC2016 # The command expands EXPECTED_VERSION inside the container.
"$docker_bin" run --rm --entrypoint /bin/bash \
  -e EXPECTED_VERSION="$version" \
  "$subject" -lc '
    set -euo pipefail
    if command -v gcc >/dev/null 2>&1; then
      echo "runtime image unexpectedly contains gcc" >&2
      exit 1
    fi
    oraclemcp info >/tmp/oraclemcp-info.json
    grep -q "\"version\": \"$EXPECTED_VERSION\"" /tmp/oraclemcp-info.json
    oraclemcp capabilities | head -c 1200 >/dev/null
  ' || fail "candidate digest smoke failed for $subject"

# Recheck immediately before creating the version tag. If another run won the
# race with the same digest, no write is needed; a different digest is refused.
if current_digest="$(inspect_digest "$version_image")"; then
  [ "$current_digest" = "$digest" ] ||
    fail "refusing to race or replace immutable release image $version_image"
else
  inspect_status=$?
  [ "$inspect_status" -eq 1 ] || fail "could not safely re-resolve $version_image"
  "$docker_bin" buildx imagetools create --tag "$version_image" "$subject"
  published_digest="$(inspect_digest "$version_image")" ||
    fail "new immutable version tag did not resolve: $version_image"
  [ "$published_digest" = "$digest" ] ||
    fail "version tag resolved to $published_digest, expected $digest"
fi

if [ "$publish_latest" = "true" ]; then
  latest_image="$image_repository:latest"
  "$docker_bin" buildx imagetools create --tag "$latest_image" "$subject"
  latest_digest="$(inspect_digest "$latest_image")" ||
    fail "rolling tag did not resolve after promotion: $latest_image"
  [ "$latest_digest" = "$digest" ] ||
    fail "rolling tag resolved to $latest_digest, expected $digest"
fi

echo "promote-release-image: OK subject=$subject version_tag=$version_image latest=$publish_latest"
