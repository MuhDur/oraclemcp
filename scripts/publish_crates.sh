#!/usr/bin/env bash
# Publish the workspace to crates.io in dependency order. The script is
# idempotent for release retries: an already-published exact version is skipped.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "publish-crates: $*" >&2
  exit 1
}

command -v cargo >/dev/null 2>&1 || fail "missing cargo"
command -v python3 >/dev/null 2>&1 || fail "missing python3"

mode="${1:-}"
[ "$#" -le 1 ] || fail "usage: scripts/publish_crates.sh [--print-order]"
case "$mode" in
  "" | --print-order) ;;
  *) fail "unknown argument: $mode" ;;
esac

metadata="$(cargo metadata --no-deps --format-version 1)" ||
  fail "cargo metadata failed"
publish_lines="$(
  printf '%s\n' "$metadata" |
    python3 "$ROOT/scripts/release_surface_manifest.py" --publish-order -
)" || fail "could not derive crates.io publish order from cargo metadata"
mapfile -t publish_lines <<<"$publish_lines"
[ "${#publish_lines[@]}" -gt 0 ] || fail "no crates.io-publishable workspace packages found"

order=()
versions=()
for package_line in "${publish_lines[@]}"; do
  crate="${package_line%%$'\t'*}"
  crate_version="${package_line#*$'\t'}"
  [ "$crate" != "$package_line" ] || fail "malformed publish-order entry: $package_line"
  order+=("$crate")
  versions+=("$crate_version")
done

version="$(printf '%s\n' "${versions[@]}" | sort -u)"
version_count="$(printf '%s\n' "$version" | sed '/^$/d' | wc -l | tr -d ' ')"
[ "$version_count" = "1" ] || fail "publishable workspace packages must share one version: $version"

if [ "$mode" = "--print-order" ]; then
  printf '%s\n' "${order[@]}"
  exit 0
fi

curl_bin="${ORACLEMCP_CURL_BIN:-curl}"
command -v "$curl_bin" >/dev/null 2>&1 || fail "missing curl command: $curl_bin"

bounded_integer() {
  local name="$1"
  local value="$2"
  local minimum="$3"
  local maximum="$4"
  [[ "$value" =~ ^[0-9]+$ ]] || fail "$name must be an integer between $minimum and $maximum"
  [ "$value" -ge "$minimum" ] && [ "$value" -le "$maximum" ] ||
    fail "$name must be between $minimum and $maximum (got $value)"
}

registry_api_base="${ORACLEMCP_CRATES_IO_API_BASE:-https://crates.io/api/v1/crates}"
registry_connect_timeout="${ORACLEMCP_CRATES_IO_CONNECT_TIMEOUT_SECONDS:-5}"
registry_max_time="${ORACLEMCP_CRATES_IO_MAX_TIME_SECONDS:-15}"
registry_retries="${ORACLEMCP_CRATES_IO_RETRIES:-2}"
registry_retry_delay="${ORACLEMCP_CRATES_IO_RETRY_DELAY_SECONDS:-1}"
registry_retry_max_time="${ORACLEMCP_CRATES_IO_RETRY_MAX_TIME_SECONDS:-45}"
bounded_integer ORACLEMCP_CRATES_IO_CONNECT_TIMEOUT_SECONDS "$registry_connect_timeout" 1 30
bounded_integer ORACLEMCP_CRATES_IO_MAX_TIME_SECONDS "$registry_max_time" 1 60
bounded_integer ORACLEMCP_CRATES_IO_RETRIES "$registry_retries" 0 5
bounded_integer ORACLEMCP_CRATES_IO_RETRY_DELAY_SECONDS "$registry_retry_delay" 0 10
bounded_integer ORACLEMCP_CRATES_IO_RETRY_MAX_TIME_SECONDS "$registry_retry_max_time" 1 120

user_agent="oraclemcp-release-workflow (https://github.com/MuhDur/oraclemcp)"
registry_response_file="$(mktemp)"
trap 'rm -f "$registry_response_file"' EXIT

crate_version_exists() {
  local crate="$1"
  local http_status validation
  if ! http_status="$(
    "$curl_bin" --silent --show-error \
      --connect-timeout "$registry_connect_timeout" \
      --max-time "$registry_max_time" \
      --retry "$registry_retries" \
      --retry-delay "$registry_retry_delay" \
      --retry-max-time "$registry_retry_max_time" \
      --retry-connrefused \
      -H "User-Agent: $user_agent" \
      -H "Accept: application/json" \
      --output "$registry_response_file" \
      --write-out '%{http_code}' \
      "${registry_api_base%/}/$crate/$version"
  )"; then
    echo "publish-crates: registry request for $crate $version exceeded or exhausted the bounded retry window" >&2
    return 2
  fi
  case "$http_status" in
    200) ;;
    404) return 1 ;;
    *)
      echo "publish-crates: crates.io returned HTTP $http_status for $crate $version" >&2
      return 2
      ;;
  esac
  if ! validation="$(
    python3 "$ROOT/scripts/release_surface_manifest.py" \
      --validate-registry-response "$registry_response_file" \
      --crate "$crate" \
      --expected-version "$version" 2>&1
  )"; then
    echo "publish-crates: invalid crates.io response for $crate $version: $validation" >&2
    return 2
  fi
  return 0
}

wait_for_index() {
  local crate="$1"
  for _ in $(seq 1 30); do
    if cargo info "$crate@$version" --registry crates-io >/dev/null 2>&1; then
      return 0
    fi
    sleep 10
  done
  fail "$crate $version did not appear on crates.io after publish"
}

missing=()
for crate in "${order[@]}"; do
  if crate_version_exists "$crate"; then
    continue
  else
    probe_status=$?
  fi
  case "$probe_status" in
    1) missing+=("$crate") ;;
    *) fail "could not safely determine whether $crate $version is already published" ;;
  esac
done

if [ "${#missing[@]}" -eq 0 ]; then
  echo "publish-crates: all workspace crates already exist on crates.io at $version; nothing to publish"
  exit 0
fi

[ -n "${CARGO_REGISTRY_TOKEN:-}" ] ||
  fail "CARGO_REGISTRY_TOKEN is required to publish missing crate(s): ${missing[*]}"

for crate in "${order[@]}"; do
  if crate_version_exists "$crate"; then
    echo "publish-crates: $crate $version already exists on crates.io; skipping"
    continue
  else
    probe_status=$?
  fi
  case "$probe_status" in
    1) ;;
    *) fail "could not safely determine whether $crate $version is already published" ;;
  esac

  echo "publish-crates: publishing $crate $version"
  cargo publish -p "$crate" --locked --dry-run
  cargo publish -p "$crate" --locked
  wait_for_index "$crate"
done

echo "publish-crates: OK version=$version"
