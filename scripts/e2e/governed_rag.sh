#!/usr/bin/env bash
# Live 23ai proof for governed hybrid retrieval. The underlying version-matrix
# ladder provisions an isolated VECTOR fixture and drives the served MCP
# binary; this wrapper makes the Arc-F contract an explicit run_all scenario.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="governed_rag"
E2E_LANE="free23"
E2E_PROFILE="governed-rag"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

for arg in "$@"; do
  set +e
  e2e_parse_common_arg "$arg"
  parsed=$?
  set -e
  case "$parsed" in
    0) continue ;;
    3)
      echo "Run the served governed-RAG hybrid retrieval proof on local FREE 23ai."
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "governed_rag: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "governed hybrid retrieval requires a live FREE 23ai lane"

# Unlike optional general live scenarios, this bead's acceptance criterion IS a
# served 23ai proof. A missing opt-in or credential is therefore a hard failure,
# never a green skip in run_all.
if [ "${ORACLEMCP_LIVE_XE:-}" != "1" ]; then
  e2e_finish_fail "governed-RAG requires ORACLEMCP_LIVE_XE=1 and the local FREE 23ai lab"
fi
for name in ORACLE_MATRIX_FREE23_USER ORACLE_MATRIX_FREE23_PASSWORD; do
  if [ -z "${!name:-}" ]; then
    e2e_finish_fail "governed-RAG requires $name for localhost:1522/FREEPDB1"
  fi
done

if ! e2e_value_has_test_marker "${ORACLE_MATRIX_FREE23_DSN:-localhost:1522/FREEPDB1}"; then
  e2e_finish_fail "governed-RAG FREE 23ai DSN must name a local/free/xe/test target"
fi

if ! bash "$ROOT/scripts/e2e/oracle_version_matrix.sh" --lane free23 "$@"; then
  e2e_finish_fail "governed-RAG served FREE 23ai proof failed"
fi

e2e_log_event "scenario_assert" "assert" "pass" 0 "hybrid filter, masking, and direct-read equivalence passed"
e2e_finish_pass
