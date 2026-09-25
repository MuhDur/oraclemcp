#!/usr/bin/env bash
# Release distributions must use the checked-in generated parser tables.
set -euo pipefail

if [[ -n "${PLSQL_ANTLR_REGEN+x}" ]]; then
  echo "antlr-codegen-release-gate: refusing PLSQL_ANTLR_REGEN=${PLSQL_ANTLR_REGEN}" >&2
  exit 1
fi

tree="$(cargo tree --locked --edges build,features -p oraclemcp --features dashboard-bundle,oracledb)"
if grep -F 'feature "antlr-codegen"' <<<"$tree" >/dev/null; then
  echo "antlr-codegen-release-gate: build-time antlr-codegen feature is enabled" >&2
  exit 1
fi

echo "antlr-codegen-release-gate: OK — no parser generator is in the build-dependency graph"
