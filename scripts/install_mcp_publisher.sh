#!/usr/bin/env bash
set -euo pipefail

# Update this version and every digest together from the signed upstream
# registry_<version>_checksums.txt release asset. The workflow policy check
# rejects releases/latest so publication can never silently move to new code.
readonly MCP_PUBLISHER_VERSION="v1.7.9"

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print tolower($1)}'
  else
    echo "neither sha256sum nor shasum is available" >&2
    return 1
  fi
}

verify_sha256() {
  local file="$1"
  local expected
  local actual
  expected="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || {
    echo "invalid pinned SHA-256 for $(basename "$file")" >&2
    return 1
  }
  actual="$(sha256_file "$file")"
  if [[ "$actual" != "$expected" ]]; then
    echo "SHA-256 mismatch for $(basename "$file"): expected $expected, got $actual" >&2
    return 1
  fi
}

mcp_publisher_platform() {
  local os="$1"
  local arch="$2"
  case "${os}_${arch}" in
    darwin_amd64)
      printf '%s\t%s\t%s\n' \
        "mcp-publisher_darwin_amd64.tar.gz" \
        "8250b61c7530960fbb54f99daa91001004e365c604cb305b13fc072ea3f5cca9" \
        "mcp-publisher"
      ;;
    darwin_arm64)
      printf '%s\t%s\t%s\n' \
        "mcp-publisher_darwin_arm64.tar.gz" \
        "5925c8d2c942b2a0330b979530b5d70284c3bdb03850a3cd1032685b80ddc2e3" \
        "mcp-publisher"
      ;;
    linux_amd64)
      printf '%s\t%s\t%s\n' \
        "mcp-publisher_linux_amd64.tar.gz" \
        "ab128162b0616090b47cf245afe0a23f3ef08936fdce19074f5ba0a4469281ac" \
        "mcp-publisher"
      ;;
    linux_arm64)
      printf '%s\t%s\t%s\n' \
        "mcp-publisher_linux_arm64.tar.gz" \
        "04f5199b3deef8e6fc4d6ed98c56a74f799def53edca3fe6d4862ecd4397c172" \
        "mcp-publisher"
      ;;
    windows_amd64)
      printf '%s\t%s\t%s\n' \
        "mcp-publisher_windows_amd64.tar.gz" \
        "aa7c3e014a38b427171b5c6d2c034551daa6fd822ce4a00d1dee2dbf7a21c118" \
        "mcp-publisher.exe"
      ;;
    windows_arm64)
      printf '%s\t%s\t%s\n' \
        "mcp-publisher_windows_arm64.tar.gz" \
        "10cc090b0727ea088dd5543ae6736f885fb9705176cd2d14314c3fcaa2acbe7e" \
        "mcp-publisher.exe"
      ;;
    *)
      echo "unsupported mcp-publisher platform: ${os}_${arch}" >&2
      return 1
      ;;
  esac
}

normalize_os() {
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    darwin) echo darwin ;;
    linux) echo linux ;;
    mingw* | msys* | cygwin* | windows*) echo windows ;;
    *) echo "unsupported operating system: $1" >&2; return 1 ;;
  esac
}

normalize_arch() {
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    x86_64 | amd64) echo amd64 ;;
    aarch64 | arm64) echo arm64 ;;
    *) echo "unsupported architecture: $1" >&2; return 1 ;;
  esac
}

install_mcp_publisher() {
  local destination="${1:-./mcp-publisher}"
  local os arch artifact expected executable metadata work_dir archive url
  os="$(normalize_os "$(uname -s)")"
  arch="$(normalize_arch "$(uname -m)")"
  metadata="$(mcp_publisher_platform "$os" "$arch")"
  IFS=$'\t' read -r artifact expected executable <<<"$metadata"

  work_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/mcp-publisher.XXXXXX")"
  archive="$work_dir/$artifact"
  url="https://github.com/modelcontextprotocol/registry/releases/download/${MCP_PUBLISHER_VERSION}/${artifact}"

  curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
    --output "$archive" "$url"
  # Authentication is checked before tar sees any bytes from the archive.
  verify_sha256 "$archive" "$expected"
  tar -xzf "$archive" -C "$work_dir" "$executable"
  install -m 0755 "$work_dir/$executable" "$destination"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  install_mcp_publisher "${1:-./mcp-publisher}"
fi
