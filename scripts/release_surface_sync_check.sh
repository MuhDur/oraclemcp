#!/usr/bin/env bash
# D3.1 — release version-surface sync check.
#
# Verifies every release-visible version pin matches the single workspace version
# from `cargo metadata`. Inventory: docs/release-surfaces.md
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "release-surface-sync: $*" >&2
  exit 1
}

require_contains() {
  local file="$1"
  local needle="$2"
  local description="$3"
  grep -Fq "$needle" "$file" ||
    fail "$file must contain current $description: $needle"
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

need cargo
need jq
need grep

metadata="$(cargo metadata --no-deps --format-version 1)"

mapfile -t package_lines < <(jq -r '.packages[] | [.name, .version] | @tsv' <<<"$metadata")
[ "${#package_lines[@]}" -gt 0 ] || fail "no workspace packages found"

versions="$(
  printf '%s\n' "${package_lines[@]}" |
    awk -F '\t' '{print $2}' |
    sort -u
)"
version_count="$(printf '%s\n' "$versions" | sed '/^$/d' | wc -l | tr -d ' ')"
[ "$version_count" = "1" ] || fail "workspace packages must share one version: $versions"
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
  pkg_version="$(
    printf '%s\n' "${package_lines[@]}" |
      awk -F '\t' -v p="$package" '$1 == p { print $2; exit }'
  )"
  [ -n "$pkg_version" ] || fail "expected workspace package missing from metadata: $package"
  [ "$pkg_version" = "$version" ] || fail "$package metadata version '$pkg_version' != workspace '$version'"
done

for manifest in crates/oraclemcp-*/Cargo.toml; do
  [ -f "$manifest" ] || continue
  case "$manifest" in
    */fuzz/Cargo.toml) continue ;;
  esac
  manifest_version="$(grep -E '^version = ' "$manifest" | head -1 | sed -E 's/^version = "(.*)"/\1/')"
  [ "$manifest_version" = "$version" ] ||
    fail "$manifest version '$manifest_version' != workspace '$version'"
done

workspace_toml="$ROOT/Cargo.toml"
# The oracledb / oracledb-protocol driver crates version INDEPENDENTLY of the
# server workspace version (a separate upstream release train — e.g. driver
# 0.7.4 while the server is 0.8.0). Parse the pinned driver version from the
# manifest and verify every driver-facing surface agrees on that SAME version
# (internal consistency), decoupled from the server's own $version.
driver_version="$(
  grep -E '^oracledb = \{ version = "=[0-9]' "$workspace_toml" |
    head -1 | sed -E 's/.*version = "=([0-9][0-9.]*)".*/\1/'
)"
[ -n "$driver_version" ] || fail "Cargo.toml must pin oracledb at an exact =X.Y.Z version"

asupersync_version="$(
  grep -E '^asupersync = \{ version = "[0-9]' "$workspace_toml" |
    head -1 | sed -E 's/.*version = "([0-9][0-9.]*)".*/\1/'
)"
[ -n "$asupersync_version" ] || fail "Cargo.toml must pin asupersync at X.Y.Z"

grep -Fq "oracledb = { version = \"=$driver_version\", default-features = false }" "$workspace_toml" ||
  fail "Cargo.toml must pin oracledb exactly at =$driver_version"
grep -Fq "oracledb-protocol = { version = \"=$driver_version\", default-features = false }" "$workspace_toml" ||
  fail "Cargo.toml must pin oracledb-protocol exactly at =$driver_version (must match the oracledb pin)"

lock="$ROOT/Cargo.lock"
for pkg in oracledb oracledb-protocol; do
  lock_versions="$(
    awk -v pkg="$pkg" '
      $0 ~ /^name = / { cur = $0; sub(/^name = "/, "", cur); sub(/"$/, "", cur) }
      cur == pkg && $0 ~ /^version = / {
        v = $0; sub(/^version = "/, "", v); sub(/"$/, "", v); print v
      }
    ' "$lock" | sort -u
  )"
  [ "$(printf '%s\n' "$lock_versions" | sed '/^$/d' | wc -l | tr -d ' ')" = "1" ] ||
    fail "Cargo.lock must resolve exactly one $pkg version (got: $lock_versions)"
  [ "$lock_versions" = "$driver_version" ] ||
    fail "Cargo.lock $pkg version '$lock_versions' != pinned driver '$driver_version'"
done

connection_rs="$ROOT/crates/oraclemcp-db/src/connection.rs"
grep -Fq "oracledb = { version = \"=$driver_version\", default-features = false }" "$connection_rs" ||
  fail "connection.rs pin_is seam test must assert oracledb =$driver_version pin"
driver_seam_fn="pin_is_$(printf '%s' "$driver_version" | tr '.' '_')_and_seam_intact"
if ! grep -Fq "fn $driver_seam_fn" "$connection_rs"; then
  fail "connection.rs must define fn $driver_seam_fn driver seam regression test"
fi

require_contains \
  "AGENTS.md" \
  "$driver_version driver is stable-clean" \
  "driver provenance"
require_contains \
  "README.md" \
  "$driver_version driver itself is stable-clean" \
  "driver provenance"
require_contains \
  "docs/operations.md" \
  "pinned \`oracledb\` $driver_version driver is stable-clean" \
  "driver provenance"
require_contains \
  "docs/operations.md" \
  "pinned \`oracledb\` $driver_version stack parses" \
  "EXPIRE_TIME driver provenance"
require_contains \
  "docs/TOOLCHAIN.md" \
  "pinned \`oracledb\` $driver_version driver is **stable-clean**" \
  "toolchain driver provenance"
require_contains \
  "docs/adr/0001-pinned-nightly-toolchain.md" \
  "pinned \`oracledb\`"$'\n'"$driver_version driver itself is **stable-clean**" \
  "ADR driver provenance"
require_contains \
  "docs/behavior-inventory.md" \
  "driver/protocol pins are exact at $driver_version" \
  "behavior-inventory driver provenance"
require_contains \
  "docs/behavior-inventory.md" \
  "\`oracledb = $driver_version\` and" \
  "behavior-inventory oracledb pin"
require_contains \
  "docs/behavior-inventory.md" \
  "\`oracledb-protocol = $driver_version\` crates from crates.io" \
  "behavior-inventory protocol pin"
require_contains \
  "Cargo.toml" \
  "The oracledb $driver_version driver is stable-clean" \
  "workspace driver provenance"
require_contains \
  "Cargo.toml" \
  "version \`oracledb $driver_version\`" \
  "workspace protocol provenance"
require_contains \
  ".github/workflows/ci.yml" \
  "oracledb $driver_version is stable-clean" \
  "CI driver provenance"
require_contains \
  ".github/workflows/ci.yml" \
  "Asupersync depends on specific nightly-only language features" \
  "CI nightly provenance"
require_contains \
  "AGENTS.md" \
  "asupersync $asupersync_version" \
  "asupersync provenance"
require_contains \
  "README.md" \
  "asupersync $asupersync_version" \
  "asupersync provenance"
require_contains \
  "docs/operations.md" \
  "asupersync $asupersync_version" \
  "operations asupersync provenance"
require_contains \
  "docs/TOOLCHAIN.md" \
  "asupersync $asupersync_version" \
  "toolchain asupersync provenance"
require_contains \
  "docs/adr/0001-pinned-nightly-toolchain.md" \
  "asupersync $asupersync_version" \
  "ADR asupersync provenance"
require_contains \
  "crates/oraclemcp-core/src/capability.rs" \
  "pinned asupersync $asupersync_version" \
  "capability asupersync provenance"
require_contains \
  "crates/oraclemcp-db/src/tns.rs" \
  "\`oracledb-protocol\` is pinned to \`=$driver_version\`, the exact version \`oracledb $driver_version\`" \
  "TNS adapter driver provenance"
require_contains \
  "crates/oraclemcp-core/tests/fixtures/wallet/PROVENANCE.md" \
  "Driver API exercised (from the pinned \`oracledb-protocol\` API)" \
  "wallet fixture driver provenance"

server_version="$(jq -r '.version' server.json)"
[ "$server_version" = "$version" ] ||
  fail "server.json version '$server_version' != workspace '$version'"

image_identifier="$(jq -r '.packages[] | select(.registryType == "oci") | .identifier' server.json)"
[ "$image_identifier" = "ghcr.io/muhdur/oraclemcp:$version" ] ||
  fail "server.json OCI image '$image_identifier' != ghcr.io/muhdur/oraclemcp:$version"

dashboard_version="$(jq -r '.version' web/package.json)"
[ "$dashboard_version" = "$version" ] ||
  fail "web/package.json version '$dashboard_version' != workspace '$version'"

dashboard_lock_version="$(jq -r '.version' web/package-lock.json)"
[ "$dashboard_lock_version" = "$version" ] ||
  fail "web/package-lock.json version '$dashboard_lock_version' != workspace '$version'"

dashboard_lock_root="$(jq -r '.packages[""].version' web/package-lock.json)"
[ "$dashboard_lock_root" = "$version" ] ||
  fail "web/package-lock.json root package version '$dashboard_lock_root' != workspace '$version'"

npm_version="$(jq -r '.version' npm/oraclemcp/package.json)"
[ "$npm_version" = "$version" ] ||
  fail "npm/oraclemcp/package.json version '$npm_version' != workspace '$version'"

if ! grep -F "## [$version]" CHANGELOG.md >/dev/null; then
  fail "CHANGELOG.md missing ## [$version] entry"
fi

if ! grep -F "e.g. $version or v$version" install.sh >/dev/null; then
  fail "install.sh help must show e.g. $version or v$version"
fi

if ! grep -F "ghcr.io/muhdur/oraclemcp:$version" README.md >/dev/null; then
  fail "README.md must mention ghcr.io/muhdur/oraclemcp:$version"
fi

health_fixture="${ORACLEMCP_RELEASE_SURFACE_SYNC_HEALTH_PATH:-$ROOT/tests/fixtures/ui/operator-v1/health.json}"
health_version="$(jq -r '.data.liveness.version' "$health_fixture")"
[ "$health_version" = "$version" ] ||
  fail "$health_fixture liveness.version '$health_version' != workspace '$version'"

for golden in tests/golden/stdio/*.json; do
  [ -f "$golden" ] || continue
  while IFS= read -r golden_version; do
    [ -n "$golden_version" ] || continue
    [ "$golden_version" = "$version" ] ||
      fail "$golden serverInfo.version '$golden_version' != workspace '$version'"
  done < <(
    jq -r '.. | objects | select(has("serverInfo")) | .serverInfo.version? // empty' "$golden" |
      sort -u
  )
done

dashboard_sbom="$ROOT/web/dist/oraclemcp-dashboard.cyclonedx.json"
if [ -f "$dashboard_sbom" ]; then
  package_name="$(jq -r '.name' web/package.json)"
  jq -e '
    .bomFormat == "CycloneDX" and
    .metadata.component["bom-ref"] == ($name + "@" + $version) and
    .metadata.component.purl == ("pkg:npm/%40oraclemcp/dashboard@" + $version)
  ' --arg name "$package_name" --arg version "$version" "$dashboard_sbom" >/dev/null ||
    fail "dashboard SBOM is not current for $package_name@$version"
else
  fail "missing dashboard SBOM (run dashboard build): $dashboard_sbom"
fi

echo "release-surface-sync: OK version=$version surfaces=$(wc -l < docs/release-surfaces.md | tr -d ' ') inventory lines"
