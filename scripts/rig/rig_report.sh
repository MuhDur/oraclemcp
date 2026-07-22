#!/usr/bin/env bash
# R4 report lane: emit punch-list findings and run the refusal-corpus diff gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="rig_report"
E2E_LANE="r4-report"
E2E_PROFILE="offline"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

cmd="${1:-run}"
if [ "$#" -gt 0 ]; then
  shift
fi

out_dir="${ORACLEMCP_R4_REPORT_DIR:-$ROOT/target/e2e/r4-report-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
baseline="$ROOT/tests/fixtures/rig/refusal_corpus_baseline.jsonl"
candidate="$ROOT/tests/fixtures/rig/refusal_corpus_seeded_flip.jsonl"
expect_findings=2

usage() {
  cat <<'USAGE'
R4 rig report and refusal-corpus regression gate.

Usage:
  bash scripts/rig/rig_report.sh run [--log|--dry-run] [--out-dir DIR] [--candidate FILE]

The default candidate is a seeded drift fixture. It proves the report catches a
category flip and a newly allowed construct, while real rig runs can pass
--candidate to compare an exported refusal corpus against the committed baseline.
USAGE
  e2e_usage_common
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out-dir)
      [ "$#" -ge 2 ] || e2e_finish_fail "--out-dir requires a value"
      out_dir="$2"
      shift 2
      ;;
    --candidate)
      [ "$#" -ge 2 ] || e2e_finish_fail "--candidate requires a value"
      candidate="$2"
      expect_findings=""
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      if e2e_parse_common_arg "$1"; then
        shift
        continue
      fi
      case $? in
        3) usage; exit 0 ;;
        *) e2e_finish_fail "unknown argument: $1" ;;
      esac
      ;;
  esac
done

case "$cmd" in
  run) ;;
  --help|-h) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "R4 report and refusal-corpus diff"
command -v python3 >/dev/null 2>&1 || e2e_finish_fail "python3 is required"

if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "refusal_corpus_gate" "assert" "skipped" 0 "dry-run baseline=$baseline candidate=$candidate"
  e2e_log_event "rig_report" "teardown" "skipped" 0 "dry-run out_dir=$out_dir"
  e2e_finish_pass
  exit 0
fi

mkdir -p "$out_dir"
args=(
  "$ROOT/scripts/rig/refusal_corpus_gate.py"
  --baseline "$baseline"
  --candidate "$candidate"
  --out-dir "$out_dir"
  --scan-output
)
if [ -n "$expect_findings" ]; then
  args+=(--expect-findings "$expect_findings")
fi

if ! e2e_run_command "assert" python3 "${args[@]}"; then
  e2e_finish_fail "R4 refusal-corpus gate failed"
fi

e2e_log_event "rig_report" "teardown" "pass" 0 "findings=$out_dir/findings.jsonl markdown=$out_dir/findings.md summary=$out_dir/summary.json"
e2e_finish_pass
