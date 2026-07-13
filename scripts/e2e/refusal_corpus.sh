#!/usr/bin/env bash
# Served Arc-J refusal-corpus E2E. This is intentionally offline: the real
# stdio server rejects the synthetic dynamic SQL before a connection can be
# used, while still exercising the default served dispatcher's corpus writer.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="refusal_corpus"
E2E_LANE="served-stdio"
E2E_PROFILE="offline"
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
      echo "Exercise the served MCP refusal corpus with synthetic-only inputs."
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "refusal_corpus: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "served MCP refusal corpus"
command -v python3 >/dev/null 2>&1 || e2e_finish_fail "python3 is required for the refusal-corpus MCP harness"

if [ -n "${ORACLEMCP_REFUSAL_CORPUS_BINARY:-}" ]; then
  BINARY="$ORACLEMCP_REFUSAL_CORPUS_BINARY"
  e2e_log_event "prebuilt_binary" "setup" "pass" 0 "using explicit prebuilt refusal-corpus binary"
else
  command -v omcpb >/dev/null 2>&1 || e2e_finish_fail "omcpb is required to build the refusal-corpus MCP binary"
  if ! e2e_run_command "setup" omcpb build -p oraclemcp --bin oraclemcp; then
    e2e_finish_fail "building the oraclemcp binary through omcpb failed"
  fi
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: refusal-corpus wiring validated, no server started"
    e2e_finish_pass
    exit 0
  fi
  build_output="$(e2e_artifact_dir)/output.txt"
  build_target="$(sed -n 's/^omcpb: lane [0-9][0-9]*  target=\([^ ]*\)  jobs=.*/\1/p' "$build_output" | tail -n 1)"
  [ -n "$build_target" ] || e2e_finish_fail "omcpb completed without reporting its selected target directory"
  BINARY="$build_target/debug/oraclemcp"
fi

if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: refusal-corpus wiring validated, no server started"
  e2e_finish_pass
  exit 0
fi

[ -x "$BINARY" ] || e2e_finish_fail "configured refusal-corpus binary not found at $BINARY"
command -v timeout >/dev/null 2>&1 || e2e_finish_fail "timeout is required for the refusal-corpus MCP harness"

run_dir="$(e2e_artifact_dir)/served-stdio-$(date -u +"%Y%m%dT%H%M%SZ")-$$"
mkdir -p "$run_dir"
evidence="$run_dir/refusal_corpus_evidence.jsonl"
state_home="$run_dir/state"

set +e
timeout -k 10 60 python3 "$ROOT/scripts/e2e/refusal_corpus_session.py" \
  --binary "$BINARY" \
  --state-home "$state_home" \
  --evidence "$evidence" \
  --server-stderr "$run_dir/server.stderr"
status=$?
set -e
if [ "$status" -ne 0 ]; then
  e2e_log_event "refusal_corpus" "assert" "fail" 0 "served refusal corpus scenario failed; inspect $evidence"
  e2e_finish_fail "served refusal-corpus MCP scenario failed"
fi

e2e_log_event "refusal_corpus" "assert" "pass" 0 "one validated redacted record persisted; forbidden rewrite absent"
e2e_finish_pass
