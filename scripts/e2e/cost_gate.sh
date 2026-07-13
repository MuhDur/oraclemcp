#!/usr/bin/env bash
# Live MCP stdio cost-gate matrix. It proves that oracle_query refuses an
# over-ceiling optimizer estimate before target execution, fails closed when
# the estimate is unavailable, and durably exhausts a server-owned
# per-principal cumulative budget across a served-process restart.
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
#   ORACLEMCP_COST_GATE_METERED_SQL
#   ORACLEMCP_COST_GATE_BINARY
#   --lane xe18|xe21|free23 (repeatable; default all three)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="cost_gate"
E2E_LANE="cost-gate"
E2E_PROFILE="matrix"
E2E_LEVEL="DDL"
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

if [ -n "${ORACLEMCP_COST_GATE_BINARY:-}" ]; then
  BINARY="$ORACLEMCP_COST_GATE_BINARY"
  e2e_log_event "prebuilt_binary" "setup" "pass" 0 "using explicit prebuilt cost-gate binary"
else
  command -v omcpb >/dev/null 2>&1 || e2e_finish_fail "omcpb is required to build the cost-gate MCP binary"
  if ! e2e_run_command "setup" omcpb build -p oraclemcp --bin oraclemcp; then
    e2e_finish_fail "building the oraclemcp binary through omcpb failed"
  fi
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: wiring validated, no live lanes exercised"
    e2e_finish_pass
    exit 0
  fi
  build_output="$(e2e_artifact_dir)/output.txt"
  build_target="$(sed -n 's/^omcpb: lane [0-9][0-9]*  target=\([^ ]*\)  jobs=.*/\1/p' "$build_output" | tail -n 1)"
  [ -n "$build_target" ] || e2e_finish_fail "omcpb completed without reporting its selected target directory"
  BINARY="$build_target/debug/oraclemcp"
fi

if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: wiring validated, no live lanes exercised"
  e2e_finish_pass
  exit 0
fi

[ -x "$BINARY" ] || e2e_finish_fail "configured cost-gate binary not found at $BINARY"

run_stamp="$(date -u +"%Y%m%dT%H%M%SZ")-$$"
matrix_dir="$ORACLEMCP_E2E_ARTIFACT_DIR/$E2E_SCENARIO/$run_stamp"
mkdir -p "$matrix_dir"
matrix_dir="$(cd "$matrix_dir" && pwd)"

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
  local table="E2E_COST_${$}"
  local schema
  schema="$(printf '%s' "$user" | tr '[:lower:]' '[:upper:]')"
  if ! [[ "$schema" =~ ^[A-Z][A-Z0-9_\$#]{0,29}$ ]]; then
    e2e_finish_fail "lane $lane user must be an unquoted Oracle identifier for the synthetic cost fixture"
  fi

  # Cost estimation writes PLAN_TABLE, and this disposable fixture is created
  # and dropped through the governed served MCP surface. The throwaway profile
  # starts at DDL; oracle_query remains classifier-bound and cost-gated.
  local profiles_file="$lane_dir/profiles.toml"
  local budget_profiles_file="$lane_dir/budget-profiles.toml"
  cat >"$profiles_file" <<PROFILES
schema_version = 2
default_profile = "$lane"

[[profiles]]
name = "$lane"
description = "cost-gate lab lane $lane (throwaway container)"
connect_string = "$dsn"
username = "$user"
credential_ref = "env:ORACLE_MATRIX_ACTIVE_PASSWORD"
max_level = "DDL"
default_level = "DDL"
max_query_cost = 1000000
PROFILES

  export ORACLEMCP_CONFIG="$profiles_file"
  export ORACLE_MATRIX_ACTIVE_PASSWORD="$password"
  # Keep the disposable DDL path on the ordinary signed-audit startup guard
  # with a per-run, ignored key. Query classification and cost enforcement are
  # still evaluated at application time for every oracle_query request.
  export ORACLEMCP_AUDIT_KEY="$(openssl rand -hex 32 2>/dev/null || date +%s%N | sha256sum | cut -d' ' -f1)"
  export XDG_STATE_HOME="$state_dir"
  export E2E_LANE="$lane" E2E_PROFILE="$lane" E2E_LEVEL="DDL"
  export E2E_COST_GATE_TABLE="$table" E2E_COST_GATE_SCHEMA="$schema"

  local evidence="$lane_dir/cost_gate_evidence.jsonl"
  e2e_log_event "cost_gate_lane" "act" "running" 0 "lane $lane: MCP stdio cost-gate session"
  set +e
  python3 - "$BINARY" "$lane" "$lane_dir" "$evidence" "$budget_profiles_file" <<'PY'
import datetime as _dt
import json
import os
import queue
import re
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
        "level": os.environ.get("E2E_LEVEL", "DDL"),
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
    def __init__(self, binary, profile, lane_dir, config_path, state_dir):
        self.stderr = open(Path(lane_dir) / "server.stderr", "a", encoding="utf-8")
        # The parent harness uses ORACLEMCP_* controls for logging and
        # artifacts. The served binary treats that prefix as config overrides,
        # so forward only the generated config and the non-prefixed credential.
        server_env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("ORACLEMCP_")
        }
        server_env["ORACLEMCP_CONFIG"] = str(config_path)
        if os.environ.get("ORACLEMCP_AUDIT_KEY"):
            server_env["ORACLEMCP_AUDIT_KEY"] = os.environ["ORACLEMCP_AUDIT_KEY"]
        server_env["XDG_STATE_HOME"] = str(state_dir)
        self.proc = subprocess.Popen(
            [binary, "serve", "--profile", profile, "--allow-no-auth"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=server_env,
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
        except (OSError, ValueError):
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
    binary, profile, lane_dir, evidence_path, budget_profiles_path = sys.argv[1:6]
    evidence = Evidence(evidence_path)
    base_config_path = os.environ["ORACLEMCP_CONFIG"]
    state_dir = os.environ["XDG_STATE_HOME"]
    session = McpSession(binary, profile, lane_dir, base_config_path, state_dir)
    table = os.environ["E2E_COST_GATE_TABLE"]
    schema = os.environ["E2E_COST_GATE_SCHEMA"]
    require(re.fullmatch(r"[A-Z][A-Z0-9_]{0,29}", table), "fixture table identifier is safe", table)
    require(re.fullmatch(r"[A-Z][A-Z0-9_$#]{0,29}", schema), "fixture schema identifier is safe", schema)
    qualified_table = f"{schema}.{table}"
    fixture_created = False
    cheap_sql = os.environ.get(
        "ORACLEMCP_COST_GATE_CHEAP_SQL",
        f"SELECT id FROM {qualified_table} WHERE id = 1",
    )
    high_sql = os.environ.get(
        "ORACLEMCP_COST_GATE_HIGH_SQL",
        f"SELECT a.id FROM {qualified_table} a CROSS JOIN {qualified_table} b "
        f"CROSS JOIN {qualified_table} c CROSS JOIN {qualified_table} d",
    )
    null_sql = os.environ.get(
        "ORACLEMCP_COST_GATE_NULL_SQL",
        f"SELECT /*+ RULE */ id FROM {qualified_table} WHERE id = 1",
    )
    metered_sql = os.environ.get(
        "ORACLEMCP_COST_GATE_METERED_SQL",
        high_sql,
    )
    try:
        def initialize(target):
            init = target.rpc(
                "initialize",
                {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "cost-gate-e2e", "version": "1"},
                },
            )
            server = init.get("result", {}).get("serverInfo", {})
            require(server.get("name") == "oraclemcp", "server identifies itself", init)
            target.notify("notifications/initialized")
            return {"server_version": server.get("version")}

        def execute_governed(target, sql):
            preview = structured(target.call("oracle_preview_sql", {"sql": sql}))
            require(preview.get("gate_decision") == "allow", "fixture mutation preview is allowed", preview)
            confirm = (preview.get("execute_confirmation") or {}).get("confirm")
            require(confirm, "fixture mutation receives an execution confirmation", preview)
            result = target.call(
                "oracle_execute",
                {"sql": sql, "commit": True, "confirm": confirm},
            )
            content = structured(result)
            require(result.get("isError") is not True, "fixture mutation succeeds through served MCP", content)
            require(content.get("executed") is True, "fixture mutation actually executes", content)
            return content

        def bootstrap_synthetic_fixture():
            nonlocal fixture_created
            execute_governed(
                session,
                f"CREATE TABLE {table} (id NUMBER PRIMARY KEY, label VARCHAR2(32) NOT NULL)",
            )
            fixture_created = True
            execute_governed(
                session,
                f"INSERT INTO {table} (id, label) VALUES (1, 'cheap')",
            )
            execute_governed(
                session,
                f"INSERT INTO {table} (id, label) VALUES (2, 'metered')",
            )
            execute_governed(
                session,
                f"INSERT INTO {table} (id, label) "
                "SELECT LEVEL + 2, 'bulk' FROM dual CONNECT BY LEVEL <= 16384",
            )
            return {"fixture": "throwaway-table-created-through-served-mcp", "inserted_rows": 16386}

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

        def calibrate_metered_cost():
            result = session.call(
                "oracle_query",
                {
                    "sql": metered_sql,
                    "allow_plan_table_write": True,
                    "max_query_cost": 100,
                    "max_rows": 1,
                },
            )
            content = structured(result)
            require(result.get("isError") is True, "calibration query is refused at its one-unit ceiling", content)
            require(content.get("error_class") == "POLICY_DENIED", "calibration refusal is typed policy-denied", content)
            require("query_cost_exceeded" in content.get("message", ""), "calibration reports query_cost_exceeded", content)
            detail = (content.get("structured_reason") or {}).get("query_cost_refusal") or {}
            observed_cost = detail.get("estimated_cost")
            require(isinstance(observed_cost, int) and observed_cost > 100, "calibration exposes a metered cost above one hundred", detail)
            return {"estimated_cost": observed_cost, "max_query_cost": detail.get("max_query_cost")}

        def cumulative_budget_is_durable_and_not_client_resettable():
            calibration = calibrate_metered_cost()
            observed_cost = calibration["estimated_cost"]
            base_config = Path(base_config_path).read_text(encoding="utf-8")
            baseline_ceiling = "max_query_cost = 1000000"
            require(
                base_config.count(baseline_ceiling) == 1,
                "budget profile derives from one known baseline ceiling",
                {"occurrences": base_config.count(baseline_ceiling)},
            )
            # The calibrated query must pass the per-statement gate exactly
            # once so the next server-owned refusal is attributable to the
            # cumulative policy, not an independently tighter profile ceiling.
            budget_config = base_config.replace(
                baseline_ceiling,
                f"max_query_cost = {observed_cost}",
            )
            Path(budget_profiles_path).write_text(
                budget_config
                + "\n[profiles.cumulative_query_cost_budget]\n"
                + f"max_cost = {observed_cost}\n"
                + "window_seconds = 3600\n",
                encoding="utf-8",
            )

            # A fresh served process starts the budget window. Its first query
            # exactly consumes the optimizer cost calibrated from the real
            # Oracle response, and its replacement process must still refuse.
            session.close()
            budget_session = McpSession(
                binary,
                profile,
                lane_dir,
                budget_profiles_path,
                state_dir,
            )
            try:
                initialize(budget_session)
                first = budget_session.call(
                    "oracle_query",
                    {
                        "sql": metered_sql,
                        "allow_plan_table_write": True,
                        "max_rows": 1,
                    },
                )
                first_content = structured(first)
                require(first.get("isError") is not True, "first metered query is admitted", first_content)
                require(first_content.get("rows"), "admitted metered query returns a real Oracle row", first_content)
            finally:
                budget_session.close()

            restarted = McpSession(
                binary,
                profile,
                lane_dir,
                budget_profiles_path,
                state_dir,
            )
            try:
                initialize(restarted)
                result = restarted.call(
                    "oracle_query",
                    {
                        "sql": metered_sql,
                        "allow_plan_table_write": True,
                        "max_rows": 1,
                        # These are deliberately client-supplied forgeries. The
                        # accepted schema has no accounting-key or reset knob.
                        "principal": "forged-principal",
                        "reset_budget": True,
                    },
                )
                content = structured(result)
                require(result.get("isError") is True, "exhausted cumulative budget is refused", content)
                require(content.get("error_class") == "POLICY_DENIED", "cumulative refusal is typed policy-denied", content)
                message = content.get("message", "")
                require("cumulative_query_cost_budget_exhausted" in message, "cumulative refusal names its enforced gate", content)
                reason = content.get("structured_reason") or {}
                require(reason.get("category") == "COST_BUDGET_EXCEEDED", "cumulative refusal has typed cost category", content)
                expected_wire_cost = f"estimated cost {observed_cost}; window consumed {observed_cost} of {observed_cost}"
                require(expected_wire_cost in message, "wire cost matches the calibrated and enforced budget", content)
                require("rows" not in content, "exhausted budget returns no target-query rows", content)
                return {
                    "calibrated_cost": observed_cost,
                    "wire_cost": expected_wire_cost,
                    "client_reset_fields_ignored": True,
                    "survived_server_restart": True,
                }
            finally:
                restarted.close()

        for name, fn in [
            ("initialize", lambda: initialize(session)),
            ("bootstrap_synthetic_fixture_through_served_mcp", bootstrap_synthetic_fixture),
            ("cheap_query_passes", cheap_query_passes),
            ("over_ceiling_refuses_pre_execution", over_ceiling_refuses_pre_execution),
            ("null_cost_fails_closed", null_cost_fails_closed),
            ("cumulative_budget_is_durable_and_not_client_resettable", cumulative_budget_is_durable_and_not_client_resettable),
        ]:
            run_case(evidence, name, fn)
    finally:
        session.close()
        if fixture_created:
            cleanup_session = McpSession(binary, profile, lane_dir, base_config_path, state_dir)
            try:
                initialize(cleanup_session)
                execute_governed(cleanup_session, f"DROP TABLE {table} PURGE")
                evidence.line("cleanup_drop_synthetic_fixture", "pass", {"fixture": "dropped"})
                emit("cleanup_drop_synthetic_fixture", "teardown", "pass", 0, "dropped throwaway cost fixture")
            except Exception as exc:
                evidence.line("cleanup_drop_synthetic_fixture", "fail", {"error": str(exc)})
                emit("cleanup_drop_synthetic_fixture", "teardown", "fail", 0, str(exc))
                raise
            finally:
                cleanup_session.close()
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
