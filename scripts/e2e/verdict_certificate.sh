#!/usr/bin/env bash
# Real served Arc-B verdict-certificate proof. This scenario starts the actual
# HTTP MCP server against a live local Oracle, obtains the certificate from the
# served operator audit-tail, and delegates independent verification to the
# standalone verifier crate. It never uses a mock database or dispatcher.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="verdict_certificate"
E2E_LANE="free23"
E2E_PROFILE="verdict-certificate"
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
      echo "Prove served verdict certificates against a live local Oracle and the standalone verifier."
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "verdict_certificate: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "served MCP verdict-certificate proof against a live local Oracle"
e2e_require_live_oracle_env
command -v python3 >/dev/null 2>&1 || e2e_finish_fail "python3 is required for the served verdict-certificate harness"

if [ -n "${ORACLEMCP_VERDICT_CERTIFICATE_BINARY:-}" ]; then
  BINARY="$ORACLEMCP_VERDICT_CERTIFICATE_BINARY"
  e2e_log_event "prebuilt_binary" "setup" "pass" 0 "using explicit prebuilt verdict-certificate binary"
else
  command -v omcpb >/dev/null 2>&1 || e2e_finish_fail "omcpb is required to build the verdict-certificate MCP binary"
  if ! e2e_run_command "setup" omcpb build -p oraclemcp --bin oraclemcp; then
    e2e_finish_fail "building the oraclemcp binary through omcpb failed"
  fi
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: verdict-certificate wiring validated, no server started"
    e2e_finish_pass
    exit 0
  fi
  build_output="$(e2e_artifact_dir)/output.txt"
  build_target="$(sed -n 's/^omcpb: lane [0-9][0-9]*  target=\([^ ]*\)  jobs=.*/\1/p' "$build_output" | tail -n 1)"
  [ -n "$build_target" ] || e2e_finish_fail "omcpb completed without reporting its selected target directory"
  BINARY="$build_target/debug/oraclemcp"
fi

if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: verdict-certificate wiring validated, no server started"
  e2e_finish_pass
  exit 0
fi

[ -x "$BINARY" ] || e2e_finish_fail "configured verdict-certificate binary not found at $BINARY"

run_dir="$(e2e_artifact_dir)/free23-$(date -u +"%Y%m%dT%H%M%SZ")-$$"
mkdir -p "$run_dir"
chmod 700 "$run_dir"
evidence="$run_dir/wire_evidence.json"
events="$run_dir/events.jsonl"
audit_key="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export E2E_VERDICT_CERTIFICATE_AUDIT_KEY="$audit_key"

set +e
timeout -k 20 180 python3 "$ROOT/scripts/e2e/verdict_certificate_session.py" \
  --binary "$BINARY" \
  --run-dir "$run_dir" \
  --evidence "$evidence" \
  --events "$events" \
  --audit-key-id "verdict-certificate-e2e"
status=$?
set -e
if [ "$status" -ne 0 ]; then
  e2e_log_event "served_verdict_certificate" "assert" "fail" 0 "served verdict-certificate scenario failed; inspect private artifacts under $run_dir"
  e2e_finish_fail "served verdict-certificate MCP scenario failed"
fi

export E2E_VERDICT_CERTIFICATE_EVIDENCE="$evidence"
if ! e2e_run_command "assert" omcpb test -p oraclemcp-verifier --test served_verdict_certificate -- --nocapture; then
  e2e_finish_fail "standalone verifier rejected the served verdict-certificate evidence"
fi

e2e_log_event "served_verdict_certificate" "assert" "pass" 0 "served certificate binding, redaction, tamper rejection, SEC-1 replay resistance, and audit-append fail-closed proof passed"
e2e_finish_pass
