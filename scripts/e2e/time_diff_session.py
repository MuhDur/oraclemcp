#!/usr/bin/env python3
"""Live MCP driver for scripts/e2e/time_diff.sh.

The wrapper supplies one isolated lab profile. This driver creates a disposable
table, obtains the two comparison SCNs exclusively from successful,
hash-chained oracle_query audit records, then proves time-diff semantics and
SCN replay through the real MCP stdio surface.
"""

import argparse
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


class StepFailure(Exception):
    """A scenario assertion that should fail the selected live lane."""


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def require(condition, description, context):
    if not condition:
        raise StepFailure(f"assertion failed: {description}; context: {context}")


def structured(result):
    content = result.get("structuredContent")
    if content is None:
        raise StepFailure(f"tool result has no structuredContent: {result}")
    return content


def normalized_row(row):
    return {str(key).upper(): str(value) for key, value in row.items()}


class Harness:
    """Emit the shared JSON-line schema and durable per-step evidence."""

    def __init__(self, evidence_path):
        self.log_enabled = os.environ.get("E2E_LOG", "0") == "1"
        self.evidence = open(evidence_path, "a", encoding="utf-8")
        self.level = "READ_ONLY"
        self.grant = "none"

    def emit(self, event, phase, outcome, duration_ms, message):
        if not self.log_enabled:
            return
        print(
            json.dumps(
                {
                    "event": event,
                    "phase": phase,
                    "ts": now_iso(),
                    "duration_ms": duration_ms,
                    "lane": os.environ.get("E2E_LANE", "time-diff"),
                    "subject": os.environ.get("E2E_SUBJECT", "test-harness"),
                    "sid": os.environ.get("E2E_SID", str(os.getpid())),
                    "profile": os.environ.get("E2E_PROFILE", "matrix"),
                    "level": self.level,
                    "grant": self.grant,
                    "outcome": outcome,
                    "scenario": os.environ.get("E2E_SCENARIO", "time_diff"),
                    "seed": os.environ.get("ORACLEMCP_E2E_SEED", "0"),
                    "message": message,
                },
                separators=(",", ":"),
            ),
            file=sys.stderr,
            flush=True,
        )

    def evidence_line(self, step, outcome, detail):
        self.evidence.write(
            json.dumps(
                {
                    "ts": now_iso(),
                    "step": step,
                    "lane": os.environ.get("E2E_LANE", "time-diff"),
                    "level": self.level,
                    "grant": self.grant,
                    "outcome": outcome,
                    "detail": detail,
                },
                sort_keys=True,
            )
            + "\n"
        )
        self.evidence.flush()

    def close(self):
        self.evidence.close()


class McpSession:
    """One real, long-lived MCP stdio connection to the selected lab lane."""

    def __init__(self, binary, profile, server_stderr):
        self.stderr = open(server_stderr, "a", encoding="utf-8")
        self.server_stderr = server_stderr
        # The server treats ORACLEMCP_* as configuration overrides. E2E control
        # variables (for example ORACLEMCP_E2E_ARTIFACT_DIR and
        # ORACLEMCP_LIVE_XE) are not server configuration and must never leak
        # into that parser. Keep only the two server inputs this lab driver
        # deliberately supplies; database credentials retain their separate
        # ORACLE_MATRIX_ACTIVE_PASSWORD name.
        child_env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("ORACLEMCP_")
            or key in {"ORACLEMCP_CONFIG", "ORACLEMCP_AUDIT_KEY"}
        }
        self.proc = subprocess.Popen(
            [binary, "serve", "--profile", profile, "--allow-no-auth"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=child_env,
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
            if self.proc.poll() is not None:
                raise StepFailure(
                    f"server exited before replying to {method}; inspect {self.server_stderr}"
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise StepFailure(f"timeout waiting for reply to {method}")
            try:
                line = self.queue.get(timeout=min(remaining, 0.5))
            except queue.Empty:
                continue
            message = json.loads(line)
            if message.get("id") == self.request_id:
                return message

    def notify(self, method):
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
        self.proc.stdin.flush()

    def call(self, tool, arguments):
        reply = self.rpc("tools/call", {"name": tool, "arguments": arguments})
        if "error" in reply:
            raise StepFailure(f"{tool}: JSON-RPC error: {reply['error']}")
        return reply["result"]

    def close(self):
        try:
            self.proc.stdin.close()
        except (AttributeError, OSError):
            pass
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=15)
        self.stderr.close()


class TimeDiff:
    def __init__(self, args, harness):
        self.args = args
        self.harness = harness
        self.session = McpSession(args.binary, args.profile, args.server_stderr)
        self.table = args.table
        self.created = False

    def step(self, name, fn):
        started = time.monotonic()
        self.harness.emit(name, "act", "running", 0, f"step {name} started")
        try:
            detail = fn()
        except StepFailure as exc:
            duration = int((time.monotonic() - started) * 1000)
            self.harness.emit(name, "assert", "fail", duration, str(exc))
            self.harness.evidence_line(name, "fail", {"error": str(exc)})
            raise
        duration = int((time.monotonic() - started) * 1000)
        self.harness.emit(name, "assert", "pass", duration, f"step {name} passed")
        self.harness.evidence_line(name, "pass", detail)
        return detail

    def query(self, sql, as_of=None):
        args = {"sql": sql}
        if as_of is not None:
            args["as_of"] = as_of
        result = self.session.call("oracle_query", args)
        content = structured(result)
        require(result.get("isError") is not True, "oracle_query succeeds", content)
        return content

    def query_refused(self, sql, as_of, expected_class, expected_oras):
        result = self.session.call("oracle_query", {"sql": sql, "as_of": as_of})
        content = structured(result)
        require(result.get("isError") is True, "flashback query is refused", content)
        require(
            content.get("error_class") == expected_class,
            f"refusal error_class is {expected_class}",
            content,
        )
        require(
            content.get("ora_code") in expected_oras,
            f"refusal ora_code is one of {sorted(expected_oras)}",
            content,
        )
        return content

    def diff(self, sql, scn_a, scn_b, key=None):
        args = {"sql": sql, "scn_a": scn_a, "scn_b": scn_b}
        if key is not None:
            args["key"] = key
        result = self.session.call("oracle_diff", args)
        content = structured(result)
        require(result.get("isError") is not True, "oracle_diff succeeds", content)
        return content

    def elevate(self):
        preview = structured(self.session.call("oracle_set_session_level", {"level": "DDL"}))
        token = (preview.get("confirmation") or {}).get("confirm")
        require(token, "DDL elevation preview returns a confirmation grant", preview)
        self.harness.grant = "session-level"
        applied = structured(
            self.session.call(
                "oracle_set_session_level",
                {"level": "DDL", "execute": True, "confirm": token},
            )
        )
        self.harness.grant = "none"
        session = applied.get("session") or {}
        require(
            session.get("current_level") == "DDL",
            "confirmed elevation reaches DDL",
            applied,
        )
        self.harness.level = "DDL"
        return {"preview": preview, "applied": applied}

    def execute(self, sql):
        preview = structured(self.session.call("oracle_preview_sql", {"sql": sql}))
        require(
            preview.get("gate_decision") == "allow",
            "preview allows governed lab mutation",
            preview,
        )
        token = (preview.get("execute_confirmation") or {}).get("confirm")
        require(token, "preview returns an execution confirmation grant", preview)
        self.harness.grant = "execute"
        result = self.session.call(
            "oracle_execute", {"sql": sql, "commit": True, "confirm": token}
        )
        self.harness.grant = "none"
        content = structured(result)
        require(result.get("isError") is not True, "governed mutation succeeds", content)
        require(content.get("executed") is True, "governed mutation was executed", content)
        return content

    def observed_scn(self):
        audit_path = Path(self.args.audit_file)
        require(audit_path.exists(), "audit chain file exists", str(audit_path))
        records = []
        for line in audit_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(json.loads(line))
        for record in reversed(records):
            if (
                record.get("tool") == "oracle_query"
                and record.get("outcome") == "SUCCEEDED"
                and isinstance(record.get("observed_scn"), int)
                and record["observed_scn"] >= 1
            ):
                return record["observed_scn"]
        raise StepFailure("no successful oracle_query audit record carried observed_scn")

    def run(self):
        def initialize():
            reply = self.session.rpc(
                "initialize",
                {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "oraclemcp-time-diff-e2e", "version": "1"},
                },
            )
            server = reply.get("result", {}).get("serverInfo", {})
            require(server.get("name") == "oraclemcp", "server identifies itself", reply)
            self.session.notify("notifications/initialized")
            return {"server_version": server.get("version")}

        self.step("initialize", initialize)
        self.step("elevate_ddl", self.elevate)

        def create_table():
            self.execute(
                f"CREATE TABLE {self.table} (id NUMBER PRIMARY KEY, val VARCHAR2(30))"
            )
            self.created = True
            return {"table": self.table}

        self.step("create_table", create_table)

        def settle_after_ddl():
            seconds = self.args.ddl_settle_seconds
            if seconds:
                time.sleep(seconds)
            return {"seconds": seconds}

        self.step("ddl_settle", settle_after_ddl)

        def baseline():
            self.execute(f"INSERT INTO {self.table} (id, val) VALUES (1, 'before')")
            self.execute(f"INSERT INTO {self.table} (id, val) VALUES (2, 'removed')")
            rows = self.query(f"SELECT id, val FROM {self.table} ORDER BY id").get("rows", [])
            require(
                [normalized_row(row) for row in rows]
                == [{"ID": "1", "VAL": "before"}, {"ID": "2", "VAL": "removed"}],
                "baseline rows are committed",
                rows,
            )
            scn = self.observed_scn()
            return {"rows": rows, "observed_scn": scn}

        baseline_result = self.step("baseline_observed_scn", baseline)
        scn_a = baseline_result["observed_scn"]

        def mutate():
            self.execute(f"UPDATE {self.table} SET val = 'changed' WHERE id = 1")
            self.execute(f"DELETE FROM {self.table} WHERE id = 2")
            self.execute(f"INSERT INTO {self.table} (id, val) VALUES (3, 'added')")
            rows = self.query(f"SELECT id, val FROM {self.table} ORDER BY id").get("rows", [])
            require(
                [normalized_row(row) for row in rows]
                == [{"ID": "1", "VAL": "changed"}, {"ID": "3", "VAL": "added"}],
                "mutated rows are committed",
                rows,
            )
            scn = self.observed_scn()
            require(scn > scn_a, "post-mutation observed SCN advances", {"before": scn_a, "after": scn})
            return {"rows": rows, "observed_scn": scn}

        mutated_result = self.step("mutation_observed_scn", mutate)
        scn_b = mutated_result["observed_scn"]
        row_sql = f"SELECT id, val FROM {self.table} ORDER BY id"

        def keyed_diff():
            diff = self.diff(row_sql, scn_a, scn_b, ["ID"])
            require(diff.get("keyed") is True, "explicit key produces keyed diff", diff)
            require(diff.get("key_columns") == ["ID"], "keyed diff preserves key column", diff)
            require(len(diff.get("added") or []) == 1, "keyed diff has one add", diff)
            require(len(diff.get("removed") or []) == 1, "keyed diff has one remove", diff)
            changed = diff.get("changed") or []
            require(len(changed) == 1, "keyed diff has one changed row", diff)
            require(
                normalized_row(changed[0].get("key") or {}) == {"ID": "1"}
                and normalized_row(changed[0].get("before") or {}) == {"ID": "1", "VAL": "before"}
                and normalized_row(changed[0].get("after") or {}) == {"ID": "1", "VAL": "changed"},
                "keyed diff aligns the changed row by ID",
                changed,
            )
            require(
                normalized_row((diff.get("added") or [])[0]) == {"ID": "3", "VAL": "added"}
                and normalized_row((diff.get("removed") or [])[0]) == {"ID": "2", "VAL": "removed"},
                "keyed diff reports correct add and remove rows",
                diff,
            )
            return {"scn_a": scn_a, "scn_b": scn_b, "changed": changed}

        self.step("keyed_time_diff", keyed_diff)

        def keyless_diff():
            # Joining DUAL deliberately makes this a multi-relation query: primary-key
            # inference must not silently key it, so row changes are add/remove only.
            sql = f"SELECT t.id, t.val FROM {self.table} t JOIN dual d ON 1 = 1 ORDER BY t.id"
            diff = self.diff(sql, scn_a, scn_b)
            require(diff.get("keyed") is False, "multi-relation diff falls back to keyless mode", diff)
            require(not (diff.get("key_columns") or []), "keyless diff exposes no inferred key", diff)
            require(not (diff.get("changed") or []), "keyless diff has no changed rows", diff)
            require(
                len(diff.get("added") or []) == 2 and len(diff.get("removed") or []) == 2,
                "keyless diff represents changed row as add/remove",
                diff,
            )
            return {"added": diff.get("added"), "removed": diff.get("removed")}

        self.step("keyless_time_diff", keyless_diff)

        def audited_replay():
            before_rows = self.query(row_sql).get("rows", [])
            replay_scn = self.observed_scn()
            self.execute(f"UPDATE {self.table} SET val = 'after-replay-snapshot' WHERE id = 1")
            replayed_rows = self.query(row_sql, {"scn": replay_scn}).get("rows", [])
            require(
                [normalized_row(row) for row in replayed_rows]
                == [normalized_row(row) for row in before_rows],
                "as_of observed_scn reproduces the committed served rows",
                {"observed_scn": replay_scn, "before": before_rows, "replayed": replayed_rows},
            )
            return {"observed_scn": replay_scn, "rows": replayed_rows}

        self.step("audited_read_replay", audited_replay)

        def retention_refusal():
            refusal = self.query_refused(
                row_sql,
                {"timestamp": "1900-01-01 00:00:00"},
                "FLASHBACK_RETENTION_EXCEEDED",
                # Timestamp conversion has version-specific retention errors:
                # ORA-08186 is common on XE 18, while other supported Oracle
                # versions can surface ORA-08180 or ORA-01555.
                (8180, 8186, 1555),
            )
            return {"error_class": refusal.get("error_class"), "ora_code": refusal.get("ora_code")}

        self.step("flashback_retention_refusal", retention_refusal)

        def definition_refusal():
            # Oracle documents a column MODIFY as invalidating the prior undo
            # image; widening this synthetic column preserves every fixture
            # value while making a pre-DDL SCN deterministically unreplayable.
            self.execute(f"ALTER TABLE {self.table} MODIFY (val VARCHAR2(31))")
            refusal = self.query_refused(
                row_sql,
                {"scn": scn_b},
                "FLASHBACK_DEFINITION_CHANGED",
                (1466,),
            )
            return {"error_class": refusal.get("error_class"), "ora_code": refusal.get("ora_code")}

        self.step("flashback_definition_refusal", definition_refusal)

    def cleanup(self):
        try:
            if self.created:
                self.execute(f"DROP TABLE {self.table} PURGE")
                self.harness.emit(
                    "cleanup_drop_table",
                    "teardown",
                    "pass",
                    0,
                    "dropped throwaway time-diff table",
                )
        except (StepFailure, OSError, ValueError) as exc:
            self.harness.emit(
                "cleanup_drop_table",
                "teardown",
                "fail",
                0,
                f"governed teardown failed; throwaway table may remain: {exc}",
            )
        finally:
            self.session.close()


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--table", required=True)
    parser.add_argument("--audit-file", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--server-stderr", required=True)
    parser.add_argument("--ddl-settle-seconds", type=int, default=180)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,29}", args.table):
        parser.error("--table must be a safe unquoted Oracle identifier")
    if not 0 <= args.ddl_settle_seconds <= 600:
        parser.error("--ddl-settle-seconds must be from 0 to 600")
    return args


def main():
    args = parse_args()
    harness = Harness(args.evidence)
    scenario = TimeDiff(args, harness)
    try:
        scenario.run()
    except StepFailure as exc:
        harness.emit("time_diff_session", "assert", "fail", 0, str(exc))
        harness.evidence_line("time_diff_session", "fail", {"error": str(exc)})
        return 1
    finally:
        scenario.cleanup()
        harness.close()
    harness.emit("time_diff_session", "assert", "pass", 0, "time-diff matrix assertions passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
