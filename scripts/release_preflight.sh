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

need cargo
need jq
need curl

bash "$ROOT/scripts/release_surface_sync_check.sh"

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

expected_packages=(
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

for package in "${expected_packages[@]}"; do
  if ! printf '%s\n' "${package_lines[@]}" | awk -F '\t' '{print $1}' | grep -Fx "$package" >/dev/null; then
    fail "expected workspace package missing: $package"
  fi
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

# D10 — driver-first release ordering: the pinned `oracledb` crate must already
# be on crates.io at its exact pinned version before this server release can
# tag/publish. The oracledb driver versions INDEPENDENTLY of the server (e.g.
# driver 0.7.4 while the server is 0.8.0), so this validates the pinned driver
# version parsed from Cargo.toml — NOT the server's own $version.
driver_version="$(
  grep -E '^oracledb = \{ version = "=[0-9]' "$ROOT/Cargo.toml" |
    head -1 | sed -E 's/.*version = "=([0-9][0-9.]*)".*/\1/'
)"
[ -n "$driver_version" ] || fail "Cargo.toml must pin oracledb at an exact =X.Y.Z version"
driver_api="https://crates.io/api/v1/crates/oracledb/${driver_version}"
driver_json="$(mktemp)"
trap 'rm -f "$driver_json"' EXIT
crates_ua="oraclemcp-release-preflight (https://github.com/MuhDur/oraclemcp; release@oraclemcp.local)"
if ! curl -fsS \
  -H "User-Agent: $crates_ua" \
  -H "Accept: application/json" \
  "$driver_api" -o "$driver_json"; then
  fail "oracledb =${driver_version} is not published on crates.io; publish rust-oracledb first (GET $driver_api failed)"
fi
published_oracledb="$(jq -r '.version.num // empty' <"$driver_json")"
[ -n "$published_oracledb" ] || fail "crates.io response for oracledb missing version.num"
[ "$published_oracledb" = "$driver_version" ] ||
  fail "crates.io oracledb version '$published_oracledb' does not match pinned driver =$driver_version"

if [ "${RELEASE_REQUIRE_MAIN:-false}" = "true" ]; then
  need git
  git fetch --no-tags origin main >/dev/null 2>&1 || fail "could not fetch origin/main for tag ancestry check"
  git merge-base --is-ancestor HEAD origin/main ||
    fail "release tag commit is not contained in origin/main"
fi

echo "release-preflight: OK version=$version tag=${tag:-none}"
