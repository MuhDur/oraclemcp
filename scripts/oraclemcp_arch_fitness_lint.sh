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

count_lines() {
  local path="$1"
  wc -l <"$path" | tr -d ' '
}

check_max_file_size_ratchet() {
  local global_limit=15829
  local path line_count
  declare -A path_limits=(
    [crates/oraclemcp/src/dispatch/tests.rs]=15676
    [crates/oraclemcp/src/dispatch/mod.rs]=15688
    [web/src/app/App.tsx]=9892
    [crates/oraclemcp-db/src/connection.rs]=8812
    [crates/oraclemcp-guard/src/classifier.rs]=7678
    [crates/oraclemcp/src/main.rs]=7722
    [crates/oraclemcp-core/src/doctor.rs]=5569
    [crates/oraclemcp/src/service_lifecycle.rs]=5538
    [crates/oraclemcp-core/src/lane.rs]=5510
    [crates/oraclemcp/src/main_tests.rs]=4690
    [crates/oraclemcp-core/src/http/tests_operator.rs]=4452
    [crates/oraclemcp-db/src/intelligence.rs]=4425
    [crates/oraclemcp-audit/src/record.rs]=4334
    [crates/oraclemcp-core/src/http/operator.rs]=4290
    [crates/oraclemcp-core/src/server.rs]=4145
    [crates/oraclemcp-config/src/lib.rs]=3756
    [web/src/app/operator-client.ts]=3278
    [crates/oraclemcp/src/plsql_tools.rs]=3228
    [crates/oraclemcp-audit/src/sink.rs]=3115
  )

  while IFS= read -r path; do
    [ -n "$path" ] || continue
    [ -f "$path" ] || continue
    line_count="$(count_lines "$path")"
    if [ "$line_count" -gt "$global_limit" ]; then
      echo "ARCH-FITNESS VIOLATION: $path has $line_count lines, above global tracked-source limit $global_limit" >&2
      violations=$((violations + 1))
    fi
  done < <(git ls-files 'crates/**/*.rs' 'web/src/**/*.ts' 'web/src/**/*.tsx')

  for path in "${!path_limits[@]}"; do
    [ -f "$path" ] || continue
    line_count="$(count_lines "$path")"
    if [ "$line_count" -gt "${path_limits[$path]}" ]; then
      echo "ARCH-FITNESS VIOLATION: $path has $line_count lines, above measured ratchet ${path_limits[$path]}" >&2
      echo "Split or move code behind an isomorphic seam, or lower the ratchet in the same reviewed split commit." >&2
      violations=$((violations + 1))
    fi
  done

  echo "OK[file-size]: tracked Rust/TS source files are within measured max-file-size ratchets."
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
  oraclemcp-verifier
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
  # Standalone certificate verifier: re-runs the guard Classifier and re-checks
  # the audit binding, so it depends on the two domain crates by design. It is a
  # leaf consumer (no adapter deps), NOT itself a domain crate.
  [oraclemcp-verifier]="oraclemcp-audit oraclemcp-guard"
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

check_max_file_size_ratchet

if [ "$violations" -ne 0 ]; then
  echo "" >&2
  echo "oraclemcp-arch-fitness-lint: $violations violation(s)." >&2
  echo "Domain/security crates must stay independent of transport/frontend/storage adapters, and monolith files must not regrow past their measured ratchets." >&2
  exit 1
fi

echo "oraclemcp-arch-fitness-lint: OK — workspace dependency graph points inward and file-size ratchets hold."
