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

sha256_of_archive() {
  local archive="$1" output digest
  [ -f "$archive" ] || fail "missing release archive: $archive"

  if command -v sha256sum >/dev/null 2>&1; then
    output="$(sha256sum -- "$archive")"
  elif command -v shasum >/dev/null 2>&1; then
    output="$(shasum -a 256 -- "$archive")"
  else
    fail "sha256sum or shasum is required to verify release archives"
  fi

  digest="${output%% *}"
  [[ "$digest" =~ ^[A-Fa-f0-9]{64}$ ]] ||
    fail "checksum tool returned an invalid SHA-256 digest for: $archive"
  printf '%s\n' "$digest" | tr '[:upper:]' '[:lower:]'
}

sha256_from_file() {
  local asset="$1" archive checksum_file line parsed_digest actual_digest
  local gnu_pattern bsd_pattern
  local -a lines=()

  archive="$ARTIFACT_DIR/$asset"
  checksum_file="$ARTIFACT_DIR/$asset.sha256"
  [ -f "$checksum_file" ] || fail "missing checksum file: $checksum_file"

  while IFS= read -r line || [ -n "$line" ]; do
    lines+=("${line%$'\r'}")
  done < "$checksum_file"

  gnu_pattern='^([A-Fa-f0-9]{64}) ([ *])(.+)$'
  bsd_pattern='^SHA256 \((.+)\) = ([A-Fa-f0-9]{64})$'
  parsed_digest=""
  if [ "${#lines[@]}" -eq 1 ] && [[ "${lines[0]}" =~ $gnu_pattern ]]; then
    [ "${BASH_REMATCH[3]}" = "$asset" ] ||
      fail "checksum record names '${BASH_REMATCH[3]}', expected '$asset': $checksum_file"
    parsed_digest="${BASH_REMATCH[1]}"
  elif [ "${#lines[@]}" -eq 1 ] && [[ "${lines[0]}" =~ $bsd_pattern ]]; then
    [ "${BASH_REMATCH[1]}" = "$asset" ] ||
      fail "checksum record names '${BASH_REMATCH[1]}', expected '$asset': $checksum_file"
    parsed_digest="${BASH_REMATCH[2]}"
  elif [ "${#lines[@]}" -eq 3 ] &&
    [ "${lines[0]}" = "SHA256 hash of $asset:" ] &&
    [[ "${lines[1]}" =~ ^[A-Fa-f0-9]{64}$ ]] &&
    [ "${lines[2]}" = "CertUtil: -hashfile command completed successfully." ]; then
    parsed_digest="${lines[1]}"
  else
    fail "checksum file must contain exactly one basename-bound GNU, BSD, or certutil SHA-256 record: $checksum_file"
  fi

  parsed_digest="$(printf '%s\n' "$parsed_digest" | tr '[:upper:]' '[:lower:]')"
  actual_digest="$(sha256_of_archive "$archive")"
  [ "$parsed_digest" = "$actual_digest" ] ||
    fail "checksum mismatch for release archive: $archive"

  printf '%s\n' "$actual_digest"
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
