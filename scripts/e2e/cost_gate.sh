#!/usr/bin/env bash
# Live MCP stdio cost-gate matrix: proves oracle_query refuses over-budget
# optimizer estimates before execution and fails closed when cost is unavailable.
#
# Required env (same lab-lane convention as oracle_version_matrix.sh):
#   ORACLEMCP_LIVE_XE=1
#   ORACLE_MATRIX_XE18_USER / ORACLE_MATRIX_XE18_PASSWORD
#   ORACLE_MATRIX_XE21_USER / ORACLE_MATRIX_XE21_PASSWORD
#   ORACLE_MATRIX_FREE23_USER / ORACLE_MATRIX_FREE23_PASSWORD
# Optional:
#   ORACLE_MATRIX_<LANE>_DSN (defaults below)
#   ORACLEMCP_COST_GATE_CHEAP_SQL
#   ORACLEMCP_COST_GATE_HIGH_SQL
#   ORACLEMCP_COST_GATE_NULL_SQL
#   --lane xe18|xe21|free23 (repeatable; default all three)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="cost_gate"
E2E_LANE="cost-gate"
E2E_PROFILE="matrix"
E2E_LEVEL="READ_WRITE"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

selected_lanes=()
expect_lane_arg=0
for arg in "$@"; do
  if [ "$expect_lane_arg" = "1" ]; then
    selected_lanes+=("$arg")
    expect_lane_arg=0
    continue
  fi
  if [ "$arg" = "--lane" ]; then
    expect_lane_arg=1
    continue
  fi
  set +e
  e2e_parse_common_arg "$arg"
  parsed=$?
  set -e
  case "$parsed" in
    0) continue ;;
    3)
      echo "Run the live oracle_query cost-gate MCP stdio matrix (XE 18 / XE 21 / FREE 23ai)."
      echo "Options: --lane <xe18|xe21|free23> (repeatable; default all three)"
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "cost_gate: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done
if [ "$expect_lane_arg" = "1" ]; then
  echo "cost_gate: --lane needs a value (xe18|xe21|free23)" >&2
  exit 2
fi
[ "${#selected_lanes[@]}" -gt 0 ] || selected_lanes=(xe18 xe21 free23)

lane_dsn() {
  case "$1" in
    xe18) printf '%s\n' "${ORACLE_MATRIX_XE18_DSN:-localhost:1518/XEPDB1}" ;;
    xe21) printf '%s\n' "${ORACLE_MATRIX_XE21_DSN:-localhost:1520/XEPDB1}" ;;
    free23) printf '%s\n' "${ORACLE_MATRIX_FREE23_DSN:-localhost:1522/FREEPDB1}" ;;
    *) return 1 ;;
  esac
}

lane_user() {
  case "$1" in
    xe18) printf '%s\n' "${ORACLE_MATRIX_XE18_USER:-}" ;;
    xe21) printf '%s\n' "${ORACLE_MATRIX_XE21_USER:-}" ;;
    free23) printf '%s\n' "${ORACLE_MATRIX_FREE23_USER:-}" ;;
  esac
}

lane_password() {
  case "$1" in
    xe18) printf '%s\n' "${ORACLE_MATRIX_XE18_PASSWORD:-}" ;;
    xe21) printf '%s\n' "${ORACLE_MATRIX_XE21_PASSWORD:-}" ;;
    free23) printf '%s\n' "${ORACLE_MATRIX_FREE23_PASSWORD:-}" ;;
  esac
}

require_cost_gate_env() {
  if [ "${ORACLEMCP_LIVE_XE:-}" != "1" ]; then
    e2e_finish_skip "set ORACLEMCP_LIVE_XE=1 plus ORACLE_MATRIX_*_USER/_PASSWORD to run the cost-gate matrix"
  fi
  for lane in "${selected_lanes[@]}"; do
    case "$lane" in
      xe18 | xe21 | free23) ;;
      *) e2e_finish_fail "unknown lane '$lane' (expected xe18|xe21|free23)" ;;
    esac
    local dsn user password
    dsn="$(lane_dsn "$lane")"
    user="$(lane_user "$lane")"
    password="$(lane_password "$lane")"
    if [ -z "$user" ] || [ -z "$password" ]; then
      e2e_finish_fail "ORACLEMCP_LIVE_XE=1 is set but lane $lane is missing ORACLE_MATRIX_$(printf '%s' "$lane" | tr '[:lower:]' '[:upper:]')_USER / _PASSWORD"
    fi
    if e2e_value_has_production_marker "$dsn" || e2e_value_has_production_marker "$user"; then
      e2e_finish_fail "refusing production-looking target for lane $lane"
    fi
    if ! e2e_value_has_test_marker "$dsn"; then
      e2e_finish_fail "lane $lane DSN must include a local/free/xe/test marker"
    fi
  done
}

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "oracle_query cost-gate MCP stdio e2e: lanes=${selected_lanes[*]}"
require_cost_gate_env
command -v python3 >/dev/null 2>&1 || e2e_finish_fail "python3 is required for the MCP stdio cost-gate harness"

if ! e2e_run_command "setup" cargo build -p oraclemcp --bin oraclemcp; then
  e2e_finish_fail "building the oraclemcp binary failed"
fi

if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: wiring validated, no live lanes exercised"
  e2e_finish_pass
  exit 0
fi

target_dir="$(cargo metadata --format-version 1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
BINARY="$target_dir/debug/oraclemcp"
[ -x "$BINARY" ] || e2e_finish_fail "built binary not found at $BINARY"

run_stamp="$(date -u +"%Y%m%dT%H%M%SZ")-$$"
matrix_dir="$ORACLEMCP_E2E_ARTIFACT_DIR/$E2E_SCENARIO/$run_stamp"
mkdir -p "$matrix_dir"

overall_fail=0
lane_summaries=()

run_lane() {
  set -e
  local lane="$1"
  local dsn user password
  dsn="$(lane_dsn "$lane")"
  user="$(lane_user "$lane")"
  password="$(lane_password "$lane")"

  local lane_dir="$matrix_dir/$lane"
  local state_dir="$lane_dir/state"
  mkdir -p "$lane_dir" "$state_dir"

  # Cost estimation writes PLAN_TABLE, so this throwaway profile starts at
  # READ_WRITE while still restricting the served operation to oracle_query's
  # read classifier plus max_query_cost fail-closed gate.
  local profiles_file="$lane_dir/profiles.toml"
  cat >"$profiles_file" <<PROFILES
schema_version = 2
default_profile = "$lane"

[[profiles]]
name = "$lane"
description = "cost-gate lab lane $lane (throwaway container)"
connect_string = "$dsn"
username = "$user"
credential_ref = "env:ORACLE_MATRIX_ACTIVE_PASSWORD"
max_level = "READ_WRITE"
default_level = "READ_WRITE"
max_query_cost = 1000000
PROFILES

  export ORACLEMCP_CONFIG="$profiles_file"
  export ORACLE_MATRIX_ACTIVE_PASSWORD="$password"
  export XDG_STATE_HOME="$state_dir"
  export E2E_LANE="$lane" E2E_PROFILE="$lane" E2E_LEVEL="READ_WRITE"

  local evidence="$lane_dir/cost_gate_evidence.jsonl"
  e2e_log_event "cost_gate_lane" "act" "running" 0 "lane $lane: MCP stdio cost-gate session"
  set +e
  python3 - "$BINARY" "$lane" "$lane_dir" "$evidence" <<'PY'
import datetime as _dt
import json
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path


class Failure(Exception):
    pass


def now():
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def emit(event, phase, outcome, duration_ms, message):
    if os.environ.get("E2E_LOG") != "1":
        return
    payload = {
        "event": event,
        "phase": phase,
        "ts": now(),
        "duration_ms": duration_ms,
        "lane": os.environ.get("E2E_LANE", "cost-gate"),
        "subject": os.environ.get("E2E_SUBJECT", "test-harness"),
        "sid": os.environ.get("E2E_SID", str(os.getpid())),
        "profile": os.environ.get("E2E_PROFILE", "matrix"),
        "level": os.environ.get("E2E_LEVEL", "READ_WRITE"),
        "grant": os.environ.get("E2E_GRANT", "none"),
        "outcome": outcome,
        "scenario": os.environ.get("E2E_SCENARIO", "cost_gate"),
        "seed": os.environ.get("ORACLEMCP_E2E_SEED", "0"),
        "message": message,
    }
    print(json.dumps(payload, separators=(",", ":")), file=sys.stderr, flush=True)


class Evidence:
    def __init__(self, path):
        self.file = open(path, "a", encoding="utf-8")

    def line(self, case, outcome, detail):
        self.file.write(
            json.dumps(
                {
                    "case": case,
                    "outcome": outcome,
                    "ts": now(),
                    "detail": detail,
                },
                sort_keys=True,
            )
            + "\n"
        )
        self.file.flush()

    def close(self):
        self.file.close()


class McpSession:
    def __init__(self, binary, profile, lane_dir):
        self.stderr = open(Path(lane_dir) / "server.stderr", "a", encoding="utf-8")
        self.proc = subprocess.Popen(
            [binary, "serve", "--profile", profile, "--allow-no-auth"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.queue = queue.Queue()
        self.request_id = 0
        threading.Thread(target=self._reader, daemon=True).start()
        threading.Thread(target=self._drain_stderr, daemon=True).start()

    def _reader(self):
        for line in self.proc.stdout:
            line = line.strip()
            if line:
                self.queue.put(line)

    def _drain_stderr(self):
        for line in self.proc.stderr:
            self.stderr.write(line)
            self.stderr.flush()

    def rpc(self, method, params=None, timeout=120):
        self.request_id += 1
        request = {"jsonrpc": "2.0", "id": self.request_id, "method": method}
        if params is not None:
            request["params"] = params
        self.proc.stdin.write(json.dumps(request) + "\n")
        self.proc.stdin.flush()
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Failure(f"timeout waiting for reply to {method}")
            try:
                line = self.queue.get(timeout=remaining)
            except queue.Empty:
                raise Failure(f"timeout waiting for reply to {method}") from None
            message = json.loads(line)
            if message.get("id") == self.request_id:
                return message

    def notify(self, method):
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
        self.proc.stdin.flush()

    def call(self, tool, arguments):
        reply = self.rpc("tools/call", {"name": tool, "arguments": arguments})
        if "error" in reply:
            raise Failure(f"{tool}: JSON-RPC error: {reply['error']}")
        return reply["result"]

    def close(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=15)
        self.stderr.close()


def require(condition, description, context):
    if not condition:
        raise Failure(f"{description}; context={json.dumps(context, sort_keys=True)[:4000]}")


def structured(result):
    content = result.get("structuredContent")
    if content is None:
        raise Failure(f"tool result has no structuredContent: {result}")
    return content


def run_case(evidence, name, fn):
    start = time.monotonic()
    emit(name, "act", "running", 0, f"{name} started")
    try:
        detail = fn()
    except Exception as exc:
        duration = int((time.monotonic() - start) * 1000)
        emit(name, "assert", "fail", duration, str(exc))
        evidence.line(name, "fail", {"error": str(exc)})
        raise
    duration = int((time.monotonic() - start) * 1000)
    emit(name, "assert", "pass", duration, f"{name} passed")
    evidence.line(name, "pass", detail)


def main():
    binary, profile, lane_dir, evidence_path = sys.argv[1:5]
    evidence = Evidence(evidence_path)
    session = McpSession(binary, profile, lane_dir)
    cheap_sql = os.environ.get("ORACLEMCP_COST_GATE_CHEAP_SQL", "SELECT 1 AS ok FROM dual")
    high_sql = os.environ.get(
        "ORACLEMCP_COST_GATE_HIGH_SQL",
        "SELECT * FROM all_objects a CROSS JOIN all_objects b "
        "WHERE a.object_name LIKE 'ORACLEMCP_COST_GATE_%'",
    )
    null_sql = os.environ.get(
        "ORACLEMCP_COST_GATE_NULL_SQL",
        "SELECT /*+ RULE */ * FROM all_objects "
        "WHERE object_name LIKE 'ORACLEMCP_COST_GATE_%'",
    )
    try:
        def initialize():
            init = session.rpc(
                "initialize",
                {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "cost-gate-e2e", "version": "1"},
                },
            )
            server = init.get("result", {}).get("serverInfo", {})
            require(server.get("name") == "oraclemcp", "server identifies itself", init)
            session.notify("notifications/initialized")
            return {"server_version": server.get("version")}

        def cheap_query_passes():
            result = session.call(
                "oracle_query",
                {"sql": cheap_sql, "allow_plan_table_write": True, "max_rows": 1},
            )
            content = structured(result)
            require(result.get("isError") is not True, "cheap query passes", content)
            rows = content.get("rows") or []
            require(rows, "cheap query returns at least one row", content)
            return {"row_count": content.get("row_count"), "sql": "cheap_sql"}

        def over_ceiling_refuses_pre_execution():
            result = session.call(
                "oracle_query",
                {
                    "sql": high_sql,
                    "allow_plan_table_write": True,
                    "max_query_cost": 100,
                    "max_rows": 1,
                },
            )
            content = structured(result)
            require(result.get("isError") is True, "over-ceiling query is refused", content)
            require(content.get("error_class") == "POLICY_DENIED", "refusal is policy-denied", content)
            require("query_cost_exceeded" in content.get("message", ""), "refusal names query_cost_exceeded", content)
            reason = content.get("structured_reason") or {}
            require(reason.get("category") == "COST_BUDGET_EXCEEDED", "structured reason categorizes cost budget", content)
            detail = reason.get("query_cost_refusal") or {}
            require(detail.get("estimated_cost", 0) > detail.get("max_query_cost", 0), "estimated cost exceeds ceiling in payload", detail)
            require(detail.get("plan_rows"), "payload includes plan rows", detail)
            require(detail.get("predicate_hints"), "payload includes predicate-derived hints", detail)
            require("rows" not in content, "refusal returns no result rows, proving no scan result was served", content)
            return {
                "estimated_cost": detail.get("estimated_cost"),
                "max_query_cost": detail.get("max_query_cost"),
                "plan_rows": len(detail.get("plan_rows") or []),
                "predicate_hints": len(detail.get("predicate_hints") or []),
            }

        def null_cost_fails_closed():
            result = session.call(
                "oracle_query",
                {
                    "sql": null_sql,
                    "allow_plan_table_write": True,
                    "max_query_cost": 1000000,
                    "max_rows": 1,
                },
            )
            content = structured(result)
            require(result.get("isError") is True, "NULL/unavailable cost query is refused", content)
            require(content.get("error_class") == "POLICY_DENIED", "NULL/unavailable cost refusal is policy-denied", content)
            require("cost_unavailable" in content.get("message", ""), "refusal names cost_unavailable", content)
            return {"error_class": content.get("error_class"), "sql": "null_sql"}

        for name, fn in [
            ("initialize", initialize),
            ("cheap_query_passes", cheap_query_passes),
            ("over_ceiling_refuses_pre_execution", over_ceiling_refuses_pre_execution),
            ("null_cost_fails_closed", null_cost_fails_closed),
        ]:
            run_case(evidence, name, fn)
    finally:
        session.close()
        evidence.close()


if __name__ == "__main__":
    try:
        main()
    except Failure as exc:
        print(f"COST_GATE_FAILURE: {exc}", file=sys.stderr)
        sys.exit(1)
PY
  local status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    e2e_log_event "cost_gate_lane" "assert" "fail" 0 "lane $lane failed (see $evidence)"
    return "$status"
  fi
  e2e_log_event "cost_gate_lane" "assert" "pass" 0 "lane $lane passed (evidence: $evidence)"
  return 0
}

for lane in "${selected_lanes[@]}"; do
  lane_started="$(e2e_epoch_ms)"
  e2e_log_event "lane_start" "act" "running" 0 "lane $lane starting"
  set +e
  (run_lane "$lane")
  lane_status=$?
  set -e
  lane_ended="$(e2e_epoch_ms)"
  if [ "$lane_status" -eq 0 ]; then
    e2e_log_event "lane_result" "assert" "pass" "$((lane_ended - lane_started))" "lane $lane passed"
    lane_summaries+=("$lane=pass")
  else
    e2e_log_event "lane_result" "assert" "fail" "$((lane_ended - lane_started))" "lane $lane FAILED"
    lane_summaries+=("$lane=fail")
    overall_fail=1
  fi
done

summary="lanes: ${lane_summaries[*]} (artifacts: $matrix_dir)"
if [ "$overall_fail" -ne 0 ]; then
  e2e_finish_fail "$summary"
fi
e2e_log_event "scenario_assert" "assert" "pass" 0 "$summary"
echo "cost_gate: $summary"
e2e_finish_pass
