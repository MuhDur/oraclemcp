#!/usr/bin/env bash
# Live governed-RAG proof. The underlying version-matrix ladder provisions an
# isolated VECTOR fixture and drives the served MCP binary; this wrapper makes
# the Arc-F contract explicit across the real capability boundary: FREE 23ai
# proves vector/hybrid egress, while XE 18 and XE 21 prove the same served
# `query_text` request fails with the typed `requires_23ai` refusal.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="governed_rag"
E2E_LANE="governed-rag-matrix"
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
      echo "Run served governed-RAG proof on local XE 18, XE 21, and FREE 23ai lab lanes."
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
e2e_log_event "scenario_start" "setup" "running" 0 "governed hybrid retrieval requires local XE 18, XE 21, and FREE 23ai lanes"

# A dry run exercises no lane, so it needs no lane credentials: it validates
# wiring and returns, exactly as sql_policy.sh and time_diff.sh do. This must
# stay ABOVE the hard-failure checks below — without it a --dry-run demands a
# live opt-in it will never use, which fails run_all --dry-run on any machine
# without the labs (CI included). It does not soften the contract below: a real
# governed-RAG run still hard-fails when the labs are absent.
if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: governed-RAG wiring validated, no live lanes exercised"
  e2e_finish_pass
  exit 0
fi

# Unlike optional general live scenarios, this bead's acceptance criterion IS a
# served capability-boundary proof. A missing opt-in or any lane credential is
# therefore a hard failure, never a green skip in run_all.
if [ "${ORACLEMCP_LIVE_XE:-}" != "1" ]; then
  e2e_finish_fail "governed-RAG requires ORACLEMCP_LIVE_XE=1 and the local XE 18, XE 21, and FREE 23ai labs"
fi
for lane in XE18 XE21 FREE23; do
  for suffix in USER PASSWORD; do
    name="ORACLE_MATRIX_${lane}_${suffix}"
    if [ -z "${!name:-}" ]; then
      e2e_finish_fail "governed-RAG requires $name for the live capability-boundary matrix"
    fi
  done
done

for lane in XE18 XE21 FREE23; do
  dsn_name="ORACLE_MATRIX_${lane}_DSN"
  case "$lane" in
    XE18) default_dsn="localhost:1518/XEPDB1" ;;
    XE21) default_dsn="localhost:1520/XEPDB1" ;;
    FREE23) default_dsn="localhost:1522/FREEPDB1" ;;
  esac
  if ! e2e_value_has_test_marker "${!dsn_name:-$default_dsn}"; then
    e2e_finish_fail "governed-RAG $lane DSN must name a local/free/xe/test target"
  fi
done

if ! bash "$ROOT/scripts/e2e/oracle_version_matrix.sh" \
  --lane xe18 --lane xe21 --lane free23 "$@"; then
  e2e_finish_fail "governed-RAG served capability-boundary proof failed"
fi

e2e_log_event "scenario_assert" "assert" "pass" 0 "FREE 23ai hybrid filter/masking/direct-read proof and XE 18/XE 21 typed-degrade proof passed"
e2e_finish_pass
