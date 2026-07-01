#!/usr/bin/env bash
# Architecture-fitness lint for the oraclemcp workspace.
#
# D15 rule 1: domain/security crates point inward only. The classifier,
# operating-level ladder, audit model, and server-derived Subject must never
# grow a dependency on transport, frontend, storage, or adapter crates.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "oraclemcp-arch-fitness-lint: missing required command: $1" >&2
    exit 2
  }
}

indent_text() {
  local line
  while IFS= read -r line; do
    printf '  %s\n' "$line"
  done
}

need cargo
need jq

metadata="$(cargo metadata --locked --no-deps --format-version 1)"
violations=0

expected_packages=(
  oraclemcp-error
  oraclemcp-audit
  oraclemcp-guard
  oraclemcp-config
  oraclemcp-db
  oraclemcp-auth
  oraclemcp-telemetry
  oraclemcp-core
  oraclemcp
)

declare -A expected_seen=()
for package in "${expected_packages[@]}"; do
  expected_seen["$package"]=0
done

while IFS= read -r package; do
  if [ -v "expected_seen[$package]" ]; then
    expected_seen["$package"]=1
  else
    echo "ARCH-FITNESS VIOLATION: unexpected workspace package: $package" >&2
    violations=$((violations + 1))
  fi
done < <(jq -r '.packages[] | select(.source == null) | .name' <<<"$metadata" | sort)

for package in "${expected_packages[@]}"; do
  if [ "${expected_seen[$package]}" != "1" ]; then
    echo "ARCH-FITNESS VIOLATION: expected workspace package missing: $package" >&2
    violations=$((violations + 1))
  fi
done

declare -A allowed_deps=(
  [oraclemcp-error]=""
  [oraclemcp-audit]="oraclemcp-error"
  [oraclemcp-guard]="oraclemcp-audit oraclemcp-error"
  [oraclemcp-config]="oraclemcp-error oraclemcp-guard"
  [oraclemcp-db]="oraclemcp-error oraclemcp-guard"
  [oraclemcp-auth]="oraclemcp-audit oraclemcp-error oraclemcp-guard"
  [oraclemcp-telemetry]="oraclemcp-error"
  [oraclemcp-core]="oraclemcp-audit oraclemcp-auth oraclemcp-config oraclemcp-db oraclemcp-error oraclemcp-guard oraclemcp-telemetry"
  [oraclemcp]="oraclemcp-audit oraclemcp-auth oraclemcp-config oraclemcp-core oraclemcp-db oraclemcp-error oraclemcp-guard oraclemcp-telemetry"
)

while IFS=$'\t' read -r package dep kind; do
  [ -n "$package" ] || continue
  [ "$kind" = "normal" ] || continue
  [[ "$dep" == oraclemcp* ]] || continue

  allowed=" ${allowed_deps[$package]-} "
  if [[ "$allowed" != *" $dep "* ]]; then
    echo "ARCH-FITNESS VIOLATION: $package has forbidden normal dependency on $dep" >&2
    echo "Allowed internal deps for $package:" >&2
    if [ -n "${allowed_deps[$package]-}" ]; then
      tr ' ' '\n' <<<"${allowed_deps[$package]}" | sed '/^$/d' | indent_text >&2
    else
      echo "  <none>" >&2
    fi
    violations=$((violations + 1))
  fi
done < <(
  jq -r '
    .packages[]
    | select(.source == null)
    | .name as $package
    | .dependencies[]
    | [$package, .name, (.kind // "normal")]
    | @tsv
  ' <<<"$metadata"
)

domain_crates=(oraclemcp-error oraclemcp-audit oraclemcp-guard)
for crate in "${domain_crates[@]}"; do
  forbidden="${allowed_deps[$crate]-}"
  echo "OK[domain]: $crate normal internal deps are inward only: ${forbidden:-<none>}"
done

if [ "$violations" -ne 0 ]; then
  echo "" >&2
  echo "oraclemcp-arch-fitness-lint: $violations violation(s)." >&2
  echo "Domain/security crates must stay independent of transport/frontend/storage adapters." >&2
  exit 1
fi

echo "oraclemcp-arch-fitness-lint: OK — workspace dependency graph points inward."
