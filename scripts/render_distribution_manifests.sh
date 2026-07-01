#!/usr/bin/env bash
# Render Homebrew and winget metadata from tag-time release artifact checksums.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-${1:-$ROOT/artifacts}}"
OUT_DIR="${OUT_DIR:-${2:-$ARTIFACT_DIR/distribution-manifests}}"
VERSION="${VERSION:-}"

if [ -z "$VERSION" ] && [ -n "${GITHUB_REF_NAME:-}" ]; then
  VERSION="${GITHUB_REF_NAME#v}"
fi
if [ -z "$VERSION" ]; then
  printf 'render_distribution_manifests: VERSION or GITHUB_REF_NAME is required\n' >&2
  exit 2
fi

fail() {
  printf 'render_distribution_manifests: %s\n' "$*" >&2
  exit 1
}

sha256_from_file() {
  local asset="$1" checksum_file digest
  checksum_file="$ARTIFACT_DIR/$asset.sha256"
  [ -f "$checksum_file" ] || fail "missing checksum file: $checksum_file"
  digest="$(
    awk '
      match($0, /[A-Fa-f0-9]{64}/) {
        print substr($0, RSTART, RLENGTH)
        exit
      }
    ' "$checksum_file"
  )"
  [ -n "$digest" ] || fail "checksum file does not contain a SHA-256 digest: $checksum_file"
  printf '%s\n' "$digest" | tr '[:upper:]' '[:lower:]'
}

render_template() {
  local input="$1" output="$2"
  mkdir -p "$(dirname "$output")"
  sed \
    -e "s/__VERSION__/$VERSION/g" \
    -e "s/__SHA256_DARWIN_X64__/$sha_darwin_x64/g" \
    -e "s/__SHA256_DARWIN_ARM64__/$sha_darwin_arm64/g" \
    -e "s/__SHA256_WINDOWS_X64__/$sha_windows_x64_upper/g" \
    "$input" > "$output"
}

sha_darwin_x64="$(sha256_from_file "oraclemcp-x86_64-apple-darwin.tar.gz")"
sha_darwin_arm64="$(sha256_from_file "oraclemcp-aarch64-apple-darwin.tar.gz")"
sha_windows_x64="$(sha256_from_file "oraclemcp-x86_64-pc-windows-msvc.zip")"
sha_windows_x64_upper="$(printf '%s\n' "$sha_windows_x64" | tr '[:lower:]' '[:upper:]')"

homebrew_out="$OUT_DIR/homebrew/Formula/oraclemcp.rb"
winget_out="$OUT_DIR/winget/manifests/m/MuhDur/oraclemcp/$VERSION"

render_template \
  "$ROOT/packaging/homebrew/Formula/oraclemcp.rb.in" \
  "$homebrew_out"
render_template \
  "$ROOT/packaging/winget/MuhDur.oraclemcp.yaml.in" \
  "$winget_out/MuhDur.oraclemcp.yaml"
render_template \
  "$ROOT/packaging/winget/MuhDur.oraclemcp.locale.en-US.yaml.in" \
  "$winget_out/MuhDur.oraclemcp.locale.en-US.yaml"
render_template \
  "$ROOT/packaging/winget/MuhDur.oraclemcp.installer.yaml.in" \
  "$winget_out/MuhDur.oraclemcp.installer.yaml"

printf 'render_distribution_manifests: wrote %s\n' "$homebrew_out"
printf 'render_distribution_manifests: wrote %s\n' "$winget_out/MuhDur.oraclemcp.yaml"
printf 'render_distribution_manifests: wrote %s\n' "$winget_out/MuhDur.oraclemcp.locale.en-US.yaml"
printf 'render_distribution_manifests: wrote %s\n' "$winget_out/MuhDur.oraclemcp.installer.yaml"
