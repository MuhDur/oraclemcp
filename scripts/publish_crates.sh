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
command -v curl >/dev/null 2>&1 || fail "missing curl"
command -v jq >/dev/null 2>&1 || fail "missing jq"

version="$(
  cargo metadata --no-deps --format-version 1 |
    jq -r '.packages[] | select(.name == "oraclemcp") | .version'
)"
if [ -z "$version" ] || [ "$version" = "null" ]; then
  fail "could not resolve oraclemcp package version"
fi

order=(
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

user_agent="oraclemcp-release-workflow (https://github.com/MuhDur/oraclemcp)"

crate_version_exists() {
  local crate="$1"
  curl -fsS \
    -H "User-Agent: $user_agent" \
    "https://crates.io/api/v1/crates/$crate/$version" \
    >/dev/null
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
  if ! crate_version_exists "$crate"; then
    missing+=("$crate")
  fi
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
  fi

  echo "publish-crates: publishing $crate $version"
  cargo publish -p "$crate" --locked
  wait_for_index "$crate"
done

echo "publish-crates: OK version=$version"
