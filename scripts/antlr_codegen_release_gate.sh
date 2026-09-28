#!/usr/bin/env bash
# Release distributions must use the checked-in generated parser tables.
#
# `antlr-codegen` is permitted in the resolved dependency graph: it supplies
# the engine's checked-in parser support.  Only an explicit regeneration
# request may invoke Java/ANTLR, and release builds must reject that request.
set -euo pipefail

if [[ -n "${PLSQL_ANTLR_REGEN+x}" ]]; then
  echo "antlr-codegen-release-gate: refusing PLSQL_ANTLR_REGEN=${PLSQL_ANTLR_REGEN}" >&2
  exit 1
fi

echo "antlr-codegen-release-gate: OK — parser regeneration is not requested"
