#!/usr/bin/env bash
# Run cargo metadata and fail closed when Cargo reports an unused patch.
set -euo pipefail

[ "$#" -gt 0 ] || {
  echo "cargo-patch-warning-guard: usage: cargo_patch_warning_guard.sh <cargo metadata options...>" >&2
  exit 2
}

output=""
status=0
if output="$(cargo metadata "$@" 2>&1)"; then
  status=0
else
  status=$?
fi

metadata_json="$(grep -E '^\{"packages":' <<<"$output" || true)"
diagnostics="$(grep -vE '^\{"packages":' <<<"$output" || true)"
if [ -n "$diagnostics" ]; then
  printf '%s\n' "$diagnostics" >&2
fi
if [ -n "$metadata_json" ]; then
  printf '%s\n' "$metadata_json"
fi

if grep -Eq '^warning: patch .+ was not used in the crate graph$' <<<"$diagnostics"; then
  echo "cargo-patch-warning-guard: refusing Cargo output with an unused patch" >&2
  exit 1
fi

if [ "$status" -ne 0 ]; then
  exit "$status"
fi
