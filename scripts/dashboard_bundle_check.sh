#!/usr/bin/env bash
# Validate the reproducible dashboard bundle inputs and generated dist.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB="$ROOT/web"
DIST="$WEB/dist"
HASH_FILE="$DIST/oraclemcp-dashboard.sha256"
SBOM_FILE="$DIST/oraclemcp-dashboard.cyclonedx.json"
MAX_CRATE_BYTES="${ORACLEMCP_MAX_CRATE_BYTES:-1000000}"

write_hash=false
check_crates=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    --write-hash)
      write_hash=true
      ;;
    --check-crates)
      check_crates=true
      ;;
    *)
      echo "dashboard-bundle-check: unknown argument: $1" >&2
      exit 2
      ;;
  esac
  shift
done

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "dashboard-bundle-check: missing required command: $1" >&2
    exit 2
  }
}

fail() {
  echo "dashboard-bundle-check: $*" >&2
  exit 1
}

need npm
need jq
need sha256sum

[ -f "$WEB/package.json" ] || fail "missing web/package.json"
[ -f "$WEB/package-lock.json" ] || fail "missing web/package-lock.json; run npm install --package-lock-only in web/"
package_name="$(jq -r '.name' "$WEB/package.json")"
package_version="$(jq -r '.version' "$WEB/package.json")"

if jq -e '
  [
    .. | objects
    | select(
        (.resolved? | type == "string" and (startswith("git:") or startswith("git+") or startswith("file:"))) or
        (.version? | type == "string" and (startswith("git:") or startswith("git+") or startswith("file:")))
      )
  ] | length > 0
' "$WEB/package-lock.json" >/dev/null; then
  fail "package-lock.json contains git:/git+/file: dependency sources"
fi

(cd "$WEB" && npm audit --audit-level=high)

[ -d "$DIST" ] || fail "missing web/dist; run npm run build in web/"
[ -f "$DIST/index.html" ] || fail "missing web/dist/index.html"
[ -f "$SBOM_FILE" ] || fail "missing $SBOM_FILE; run npm run build in web/"

jq -e '
  .bomFormat == "CycloneDX" and
  (.components | type == "array") and
  (.metadata.component["bom-ref"] == ($name + "@" + $version))
' --arg name "$package_name" --arg version "$package_version" "$SBOM_FILE" >/dev/null ||
  fail "dashboard SBOM is not a CycloneDX document for $package_name@$package_version"

tmp_hash="$(mktemp)"
trap 'rm -f "$tmp_hash"' EXIT
(
  cd "$DIST"
  find . -type f ! -name "$(basename "$HASH_FILE")" -print0 |
    LC_ALL=C sort -z |
    xargs -0 -r sha256sum
) >"$tmp_hash"

[ -s "$tmp_hash" ] || fail "web/dist is empty"

if [ "$write_hash" = true ]; then
  cp "$tmp_hash" "$HASH_FILE"
fi

[ -f "$HASH_FILE" ] || fail "missing $HASH_FILE; rebuild with npm run build"
cmp -s "$tmp_hash" "$HASH_FILE" || fail "web/dist content hash is stale; rerun npm run build"

if [ "$check_crates" = true ]; then
  shopt -s nullglob
  crates=("$ROOT"/target/package/*.crate)
  [ "${#crates[@]}" -gt 0 ] || fail "no packaged .crate files found under target/package"
  for crate in "${crates[@]}"; do
    size="$(wc -c < "$crate" | tr -d '[:space:]')"
    if [ "$size" -gt "$MAX_CRATE_BYTES" ]; then
      fail "$(basename "$crate") exceeds crate size budget: $size > $MAX_CRATE_BYTES bytes"
    fi
  done
fi

echo "dashboard-bundle-check: OK"
