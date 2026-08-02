#!/usr/bin/env bash
# Validate release metadata before a tag can publish crates, binaries, images,
# or MCP registry state.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "release-preflight: missing required command: $1" >&2
    exit 2
  }
}

fail() {
  echo "release-preflight: $*" >&2
  exit 1
}

bounded_integer() {
  local name="$1"
  local value="$2"
  local minimum="$3"
  local maximum="$4"
  [[ "$value" =~ ^[0-9]+$ ]] || fail "$name must be an integer between $minimum and $maximum"
  [ "$value" -ge "$minimum" ] && [ "$value" -le "$maximum" ] ||
    fail "$name must be between $minimum and $maximum (got $value)"
}

curl_bin="${ORACLEMCP_CURL_BIN:-curl}"
registry_api_base="${ORACLEMCP_CRATES_IO_API_BASE:-https://crates.io/api/v1/crates}"
registry_connect_timeout="${ORACLEMCP_CRATES_IO_CONNECT_TIMEOUT_SECONDS:-5}"
registry_max_time="${ORACLEMCP_CRATES_IO_MAX_TIME_SECONDS:-15}"
registry_retries="${ORACLEMCP_CRATES_IO_RETRIES:-2}"
registry_retry_delay="${ORACLEMCP_CRATES_IO_RETRY_DELAY_SECONDS:-1}"
registry_retry_max_time="${ORACLEMCP_CRATES_IO_RETRY_MAX_TIME_SECONDS:-45}"
crates_ua="oraclemcp-release-preflight (https://github.com/MuhDur/oraclemcp; release@oraclemcp.local)"
registry_response_file=""

validate_registry_limits() {
  bounded_integer ORACLEMCP_CRATES_IO_CONNECT_TIMEOUT_SECONDS "$registry_connect_timeout" 1 30
  bounded_integer ORACLEMCP_CRATES_IO_MAX_TIME_SECONDS "$registry_max_time" 1 60
  bounded_integer ORACLEMCP_CRATES_IO_RETRIES "$registry_retries" 0 5
  bounded_integer ORACLEMCP_CRATES_IO_RETRY_DELAY_SECONDS "$registry_retry_delay" 0 10
  bounded_integer ORACLEMCP_CRATES_IO_RETRY_MAX_TIME_SECONDS "$registry_retry_max_time" 1 120
}

registry_get() {
  local url="$1"
  local output="$2"
  "$curl_bin" --silent --show-error \
    --connect-timeout "$registry_connect_timeout" \
    --max-time "$registry_max_time" \
    --retry "$registry_retries" \
    --retry-delay "$registry_retry_delay" \
    --retry-max-time "$registry_retry_max_time" \
    --retry-connrefused \
    -H "User-Agent: $crates_ua" \
    -H "Accept: application/json" \
    --output "$output" \
    --write-out '%{http_code}' \
    "$url"
}

check_driver_registry() {
  local driver_version driver_api http_status validation
  driver_version="$(
    python3 "$ROOT/scripts/release_surface_manifest.py" --value driver_version
  )" || fail "Cargo.toml must structurally pin oraclemcp-driver-cx at an exact =X.Y.Z version"
  driver_api="${registry_api_base%/}/oraclemcp-driver-cx/${driver_version}"
  registry_response_file="$(mktemp)"
  trap 'rm -f "$registry_response_file"' EXIT

  if ! http_status="$(registry_get "$driver_api" "$registry_response_file")"; then
    fail "could not verify oraclemcp-driver-cx =${driver_version} on crates.io within the bounded retry window"
  fi
  case "$http_status" in
    200) ;;
    404)
      fail "oraclemcp-driver-cx =${driver_version} is not published on crates.io; publish the driver first"
      ;;
    *)
      fail "crates.io returned HTTP $http_status for oraclemcp-driver-cx =${driver_version}"
      ;;
  esac
  if ! validation="$(
    python3 "$ROOT/scripts/release_surface_manifest.py" \
      --validate-registry-response "$registry_response_file" \
      --crate oraclemcp-driver-cx \
      --expected-version "$driver_version" 2>&1
  )"; then
    fail "invalid crates.io response for oraclemcp-driver-cx =${driver_version}: $validation"
  fi
}

need python3
validate_registry_limits

mode="${1:-}"
[ "$#" -le 1 ] || fail "usage: scripts/release_preflight.sh [--check-driver-registry]"
case "$mode" in
  --check-driver-registry)
    need "$curl_bin"
    check_driver_registry
    echo "release-preflight: driver registry contract OK"
    exit 0
    ;;
  "") ;;
  *) fail "unknown argument: $mode" ;;
esac

need cargo
need jq
need "$curl_bin"

bash "$ROOT/scripts/release_surface_sync_check.sh"
env -u ORACLEMCP_RELEASE_FAKE_CURL_MODE -u ORACLEMCP_FAKE_YANKED_CRATE \
  bash "$ROOT/tests/release_contract_test.sh"

bash "$ROOT/scripts/oraclemcp_boundary_lint.sh"
bash "$ROOT/scripts/oraclemcp_arch_fitness_lint.sh"
bash "$ROOT/scripts/oraclemcp_agent_surface_lint.sh"
bash "$ROOT/scripts/oraclemcp_ergonomics_lint.sh"
bash "$ROOT/scripts/oraclemcp_concurrency_lint.sh"
bash "$ROOT/scripts/dashboard_bundle_check.sh"
bash "$ROOT/scripts/release_sbom_check.sh" --source
bash "$ROOT/scripts/dashboard_skin_lint.sh"
bash "$ROOT/scripts/installer_lint_and_offline_smoke.sh"
bash "$ROOT/scripts/secret_scan.sh"
bash "$ROOT/scripts/mutation_safety_gate.sh" check-report
bash "$ROOT/scripts/local_release_gate_check.sh"

metadata="$(cargo metadata --no-deps --format-version 1)"

mapfile -t package_lines < <(jq -r '.packages[] | [.name, .version] | @tsv' <<<"$metadata")
[ "${#package_lines[@]}" -gt 0 ] || fail "no workspace packages found"

versions="$(
  printf '%s\n' "${package_lines[@]}" |
    awk -F '\t' '{print $2}' |
    sort -u
)"
version_count="$(printf '%s\n' "$versions" | sed '/^$/d' | wc -l | tr -d ' ')"
[ "$version_count" = "1" ] || {
  printf 'release-preflight: workspace packages must share one version:\n%s\n' "$versions" >&2
  exit 1
}
version="$versions"

publish_lines="$(
  printf '%s\n' "$metadata" |
    python3 "$ROOT/scripts/release_surface_manifest.py" --publish-order -
)" || fail "could not derive crates.io publish order from cargo metadata"
mapfile -t publish_lines <<<"$publish_lines"
[ "${#publish_lines[@]}" -gt 0 ] || fail "no crates.io-publishable workspace packages found"
for package_line in "${publish_lines[@]}"; do
  package="${package_line%%$'\t'*}"
  package_version="${package_line#*$'\t'}"
  [ "$package" != "$package_line" ] || fail "malformed publish-order entry: $package_line"
  [ "$package_version" = "$version" ] ||
    fail "$package metadata version '$package_version' does not match workspace version '$version'"
done

tag="${RELEASE_TAG:-}"
if [ -z "$tag" ] && [ "${GITHUB_REF_TYPE:-}" = "tag" ]; then
  tag="${GITHUB_REF_NAME:-}"
fi
if [ -z "$tag" ] && [[ "${GITHUB_REF:-}" == refs/tags/* ]]; then
  tag="${GITHUB_REF#refs/tags/}"
fi

if [ -n "$tag" ]; then
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] ||
    fail "tag '$tag' is not a supported semver tag (expected vX.Y.Z or vX.Y.Z-prerelease)"
  [ "$tag" = "v$version" ] ||
    fail "tag '$tag' does not match workspace version '$version' (expected v$version)"
fi

server_version="$(jq -r '.version' server.json)"
[ "$server_version" = "$version" ] ||
  fail "server.json version '$server_version' does not match workspace version '$version'"

dashboard_version="$(jq -r '.version' web/package.json)"
[ "$dashboard_version" = "$version" ] ||
  fail "web/package.json version '$dashboard_version' does not match workspace version '$version'"

dashboard_lock_version="$(jq -r '.version' web/package-lock.json)"
[ "$dashboard_lock_version" = "$version" ] ||
  fail "web/package-lock.json version '$dashboard_lock_version' does not match workspace version '$version'"

dashboard_lock_package_version="$(jq -r '.packages[""].version' web/package-lock.json)"
[ "$dashboard_lock_package_version" = "$version" ] ||
  fail "web/package-lock.json root package version '$dashboard_lock_package_version' does not match workspace version '$version'"

if ! grep -F "## [$version]" CHANGELOG.md >/dev/null; then
  fail "CHANGELOG.md does not contain an entry for $version"
fi

server_name="$(jq -r '.name' server.json)"
[ "$server_name" = "io.github.MuhDur/oraclemcp" ] ||
  fail "server.json name changed unexpectedly: $server_name"

image_identifier="$(jq -r '.packages[] | select(.registryType == "oci") | .identifier' server.json)"
[ "$image_identifier" = "ghcr.io/muhdur/oraclemcp:$version" ] ||
  fail "server.json OCI image '$image_identifier' does not match ghcr.io/muhdur/oraclemcp:$version"

# Install-EXAMPLE surfaces (README curl/docker/self-update one-liners, install.sh
# `--version` help text, docs/*.md docker pins) are version-AGNOSTIC (`latest`) by
# design, so they are NOT pinned to the workspace $version. The stale-numeric-tag
# guard below therefore scans only source / workflow / manifest surfaces — where a
# hardcoded numeric image tag would be a genuine bug. See docs/release-surfaces.md.
stale_image_refs="$(
  grep -RInE 'ghcr\.io/muhdur/oraclemcp:[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?' \
    server.json crates/oraclemcp/src .github/workflows Dockerfile 2>/dev/null |
    grep -Fv "ghcr.io/muhdur/oraclemcp:$version" || true
)"
if [ -n "$stale_image_refs" ]; then
  printf 'release-preflight: stale Docker image version reference(s):\n%s\n' "$stale_image_refs" >&2
  exit 1
fi

# Honesty gate (F1a / §8 item 8): no over-claiming framing in release-visible
# text (README/docs/package metadata/source docs). oraclemcp is governed +
# least-privilege, never "safe-by-default" / a "read-only binary".
bash "$ROOT/scripts/oraclemcp_honesty_grep.sh"

# D10 — driver-first release ordering: the pinned `oraclemcp-driver-cx` crate must already
# be on crates.io at its exact pinned version before this server release can
# tag/publish. The driver versions independently of the server (e.g.
# driver 0.7.4 while the server is 0.8.0), so this validates the pinned driver
# version structurally parsed from Cargo.toml — NOT the server's own $version.
# The exact-version API response must also name the requested version and carry
# an explicit yanked=false; existing yanked versions cannot be republished.
check_driver_registry

if [ "${RELEASE_REQUIRE_MAIN:-false}" = "true" ]; then
  need git
  git fetch --no-tags origin main >/dev/null 2>&1 || fail "could not fetch origin/main for tag ancestry check"
  git merge-base --is-ancestor HEAD origin/main ||
    fail "release tag commit is not contained in origin/main"
fi

echo "release-preflight: OK version=$version tag=${tag:-none}"
