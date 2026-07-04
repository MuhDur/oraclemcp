#!/usr/bin/env python3
"""Operating-level ladder e2e session driver for oracle_version_matrix.sh.

Drives the REAL oraclemcp binary over MCP stdio (newline-delimited JSON-RPC:
initialize -> notifications/initialized -> tools/call ...) and walks the full
operating-level ladder READ_ONLY -> DDL -> READ_ONLY -> READ_WRITE -> DDL ->
READ_ONLY against one live lab lane, asserting row VALUES, refusal envelopes,
preview verdicts, confirmation grants, rollback-by-default, governed DDL, and
the on-disk audit hash-chain records for every privileged step.

Contract with the wrapping bash script (scripts/e2e/lib.sh conventions):
  - JSON-line step events go to stderr when E2E_LOG=1, in the harness schema
    (event/phase/ts/duration_ms/lane/subject/sid/profile/level/grant/outcome/
    scenario/seed/message);
  - per-step evidence is ALWAYS appended to --evidence as JSON lines;
  - exit 0 only when every step passed.

Sanitization: this driver only ever talks to the profile the wrapper generated
(local lab containers); it never embeds hostnames, services, or credentials.
"""

import argparse
import json
import os
import queue
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class StepFailure(Exception):
    pass


class Harness:
    """JSON-line logging in the scripts/e2e/lib.sh schema + evidence file."""

    def __init__(self, evidence_path):
        self.log_enabled = os.environ.get("E2E_LOG", "0") == "1"
        self.evidence = open(evidence_path, "a", encoding="utf-8")
        self.level = "READ_ONLY"
        self.grant = "none"

    def emit(self, event, phase, outcome, duration_ms, message):
        record = {
            "event": event,
            "phase": phase,
            "ts": now_iso(),
            "duration_ms": duration_ms,
            "lane": os.environ.get("E2E_LANE", "unknown"),
            "subject": os.environ.get("E2E_SUBJECT", "test-harness"),
            "sid": os.environ.get("E2E_SID", str(os.getpid())),
            "profile": os.environ.get("E2E_PROFILE", "unknown"),
            "level": self.level,
            "grant": self.grant,
            "outcome": outcome,
            "scenario": os.environ.get("E2E_SCENARIO", "oracle_version_matrix"),
            "seed": os.environ.get("ORACLEMCP_E2E_SEED", "0"),
            "message": message,
        }
        if self.log_enabled:
            print(json.dumps(record), file=sys.stderr, flush=True)

    def evidence_line(self, step, outcome, detail):
        self.evidence.write(
            json.dumps(
                {
                    "ts": now_iso(),
                    "step": step,
                    "lane": os.environ.get("E2E_LANE", "unknown"),
                    "level": self.level,
                    "grant": self.grant,
                    "outcome": outcome,
                    "detail": detail,
                }
            )
            + "\n"
        )
        self.evidence.flush()


class McpSession:
    """One long-lived stdio MCP session against the real binary."""

    def __init__(self, binary, profile):
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
        for _ in self.proc.stderr:
            pass

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
                raise StepFailure(f"timeout waiting for reply to {method}")
            try:
                line = self.queue.get(timeout=remaining)
            except queue.Empty:
                raise StepFailure(f"timeout waiting for reply to {method}") from None
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
        except OSError:
            pass
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=15)


def structured(result):
    content = result.get("structuredContent")
    if content is None:
        raise StepFailure(f"tool result has no structuredContent: {result}")
    return content


def require(condition, description, context):
    if not condition:
        raise StepFailure(f"assertion failed: {description}; context: {context}")


class Ladder:
    def __init__(self, args, harness):
        self.args = args
        self.harness = harness
        self.session = McpSession(args.binary, args.profile)
        self.table = args.table
        self.table_created = False
        self.table_dropped = False
        self.failures = 0

    # -- step plumbing ------------------------------------------------------

    def step(self, name, fn):
        start = time.monotonic()
        self.harness.emit(name, "act", "running", 0, f"step {name} started")
        try:
            detail = fn()
        except StepFailure as exc:
            duration = int((time.monotonic() - start) * 1000)
            self.harness.emit(name, "assert", "fail", duration, str(exc))
            self.harness.evidence_line(name, "fail", {"error": str(exc)})
            raise
        duration = int((time.monotonic() - start) * 1000)
        self.harness.emit(name, "assert", "pass", duration, f"step {name} passed")
        self.harness.evidence_line(name, "pass", detail)

    # -- tool helpers -------------------------------------------------------

    def query_rows(self, sql):
        content = structured(self.session.call("oracle_query", {"sql": sql}))
        require(
            content.get("isError") is not True,
            "read-only query succeeds",
            content,
        )
        return content.get("rows", [])

    def query_refused(self, sql):
        result = self.session.call("oracle_query", {"sql": sql})
        content = structured(result)
        require(result.get("isError") is True, "write via oracle_query is refused", content)
        require(
            content.get("error_class") == "OPERATING_LEVEL_TOO_LOW",
            "refusal is the structured operating-level error",
            content,
        )
        return content

    def preview(self, sql):
        return structured(self.session.call("oracle_preview_sql", {"sql": sql}))

    def elevate(self, level):
        preview = structured(
            self.session.call("oracle_set_session_level", {"level": level})
        )
        confirmation = preview.get("confirmation") or {}
        token = confirmation.get("confirm")
        require(token, f"elevation preview to {level} returns a confirmation grant", preview)
        self.harness.grant = "session-level"
        applied = structured(
            self.session.call(
                "oracle_set_session_level",
                {"level": level, "execute": True, "confirm": token},
            )
        )
        session = applied.get("session") or {}
        require(
            session.get("current_level") == level,
            f"session level is {level} after grant-confirmed apply",
            applied,
        )
        self.harness.level = level
        self.harness.grant = "none"
        return {"preview": preview, "applied": applied}

    def drop_level(self):
        dropped = structured(
            self.session.call("oracle_set_session_level", {"action": "drop"})
        )
        session = dropped.get("session") or {}
        require(
            session.get("current_level") == "READ_ONLY",
            "drop returns the session to READ_ONLY",
            dropped,
        )
        self.harness.level = "READ_ONLY"
        return dropped

    def governed_execute(self, sql, commit, expect):
        """preview -> single-use confirmation grant -> oracle_execute."""
        preview = self.preview(sql)
        require(
            preview.get("gate_decision") == "allow",
            "preview allows execution at the current level",
            preview,
        )
        confirmation = preview.get("execute_confirmation") or {}
        token = confirmation.get("confirm")
        require(token, "preview returns a single-use execution grant", preview)
        self.harness.grant = "execute"
        outcome = structured(
            self.session.call(
                "oracle_execute", {"sql": sql, "commit": commit, "confirm": token}
            )
        )
        self.harness.grant = "none"
        require(outcome.get("executed") is True, "statement executed", outcome)
        for key, expected in expect.items():
            require(
                outcome.get(key) == expected,
                f"execute outcome {key} == {expected!r}",
                outcome,
            )
        return {"preview": preview, "outcome": outcome}

    def count_rows(self, sql):
        rows = self.query_rows(sql)
        require(len(rows) == 1, "count query returns one row", rows)
        return int(next(iter(rows[0].values())))

    # -- the ladder ---------------------------------------------------------

    def run(self):
        table = self.table

        def session_initialize():
            init = self.session.rpc(
                "initialize",
                {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "oracle-version-matrix-e2e", "version": "1"},
                },
            )
            server = init.get("result", {}).get("serverInfo", {})
            require(server.get("name") == "oraclemcp", "server identifies itself", init)
            self.session.notify("notifications/initialized")
            return {"server_version": server.get("version")}

        def read_only_banner():
            import re

            rows = self.query_rows("SELECT banner FROM v$version")
            require(rows, "v$version returns at least one row", rows)
            banner = str(rows[0].get("BANNER", ""))
            require(
                re.search(self.args.banner_regex, banner),
                f"banner matches /{self.args.banner_regex}/",
                banner,
            )
            return {"banner": banner}

        def read_only_arithmetic():
            rows = self.query_rows("SELECT 6*7 AS answer, 'ladder' AS tag FROM dual")
            require(rows and rows[0].get("ANSWER") == "42", "6*7 = 42 as string", rows)
            require(rows[0].get("TAG") == "ladder", "string literal round-trips", rows)
            return {"rows": rows}

        def read_only_write_refused():
            return self.query_refused(
                f"INSERT INTO {table} (id, note) VALUES (1, 'refused')"
            )

        def preview_insert_requires_step_up():
            verdict = self.preview(
                f"INSERT INTO {table} (id, note) VALUES (1, 'preview')"
            )
            require(
                verdict.get("gate_decision") == "require_step_up",
                "preview at READ_ONLY demands step-up",
                verdict,
            )
            require(
                verdict.get("required_level") == "READ_WRITE",
                "INSERT requires READ_WRITE",
                verdict,
            )
            require(
                verdict.get("execute_confirmation") is None,
                "no execution grant is minted below the required level",
                verdict,
            )
            return verdict

        def elevate_ddl():
            return self.elevate("DDL")

        def ddl_create_table():
            result = self.governed_execute(
                f"CREATE TABLE {table} (id NUMBER PRIMARY KEY, note VARCHAR2(40))",
                commit=True,
                expect={"committed": True},
            )
            self.table_created = True
            return result

        def verify_table_exists():
            describe = structured(
                self.session.call("oracle_describe", {"table": table})
            )
            columns = json.dumps(describe).upper()
            require("NOTE" in columns, "described table lists the NOTE column", describe)
            count = self.count_rows(f"SELECT COUNT(*) AS n FROM {table}")
            require(count == 0, "fresh table is empty", count)
            return {"describe_ok": True, "row_count": count}

        def drop_to_read_only_mid():
            dropped = self.drop_level()
            refusal = self.query_refused(
                f"INSERT INTO {table} (id, note) VALUES (1, 'refused-again')"
            )
            return {"dropped": dropped, "refusal": refusal}

        def elevate_read_write():
            return self.elevate("READ_WRITE")

        def dml_rollback_by_default():
            result = self.governed_execute(
                f"INSERT INTO {table} (id, note) VALUES (1, 'rollback-me')",
                commit=False,
                expect={"committed": False, "rolled_back": True, "rows_affected": 1},
            )
            count = self.count_rows(f"SELECT COUNT(*) AS n FROM {table}")
            require(count == 0, "uncommitted DML rolled back: row absent", count)
            result["row_count_after"] = count
            return result

        def dml_commit():
            result = self.governed_execute(
                f"INSERT INTO {table} (id, note) VALUES (2, 'commit-me')",
                commit=True,
                expect={"committed": True, "rolled_back": False, "rows_affected": 1},
            )
            count = self.count_rows(f"SELECT COUNT(*) AS n FROM {table}")
            require(count == 1, "committed DML persisted: exactly one row", count)
            rows = self.query_rows(f"SELECT note FROM {table} WHERE id = 2")
            require(
                rows and rows[0].get("NOTE") == "commit-me",
                "committed value round-trips",
                rows,
            )
            result["row_count_after"] = count
            return result

        def ddl_requires_step_up_at_read_write():
            verdict = self.preview(f"DROP TABLE {table} PURGE")
            require(
                verdict.get("gate_decision") == "require_step_up",
                "DDL at READ_WRITE demands step-up",
                verdict,
            )
            require(
                verdict.get("required_level") == "DDL",
                "DROP TABLE requires the DDL level",
                verdict,
            )
            return verdict

        def elevate_ddl_again():
            return self.elevate("DDL")

        def ddl_drop_table():
            result = self.governed_execute(
                f"DROP TABLE {table} PURGE",
                commit=True,
                expect={"committed": True},
            )
            self.table_dropped = True
            remaining = self.count_rows(
                f"SELECT COUNT(*) AS n FROM user_tables WHERE table_name = '{table}'"
            )
            require(remaining == 0, "table is gone from user_tables", remaining)
            return result

        def drop_to_read_only_final():
            dropped = self.drop_level()
            refusal = self.query_refused(
                f"INSERT INTO {table} (id, note) VALUES (3, 'refused-final')"
            )
            return {"dropped": dropped, "refusal": refusal}

        steps = [
            ("session_initialize", session_initialize),
            ("read_only_banner", read_only_banner),
            ("read_only_arithmetic", read_only_arithmetic),
            ("read_only_write_refused", read_only_write_refused),
            ("preview_insert_requires_step_up", preview_insert_requires_step_up),
            ("elevate_ddl", elevate_ddl),
            ("ddl_create_table", ddl_create_table),
            ("verify_table_exists", verify_table_exists),
            ("drop_to_read_only_mid", drop_to_read_only_mid),
            ("elevate_read_write", elevate_read_write),
            ("dml_rollback_by_default", dml_rollback_by_default),
            ("dml_commit", dml_commit),
            ("ddl_requires_step_up_at_read_write", ddl_requires_step_up_at_read_write),
            ("elevate_ddl_again", elevate_ddl_again),
            ("ddl_drop_table", ddl_drop_table),
            ("drop_to_read_only_final", drop_to_read_only_final),
        ]
        try:
            for name, fn in steps:
                self.step(name, fn)
        finally:
            self.cleanup()

    def cleanup(self):
        """Best-effort governed teardown of the throwaway table, then exit."""
        if self.table_created and not self.table_dropped:
            try:
                self.elevate("DDL")
                self.governed_execute(
                    f"DROP TABLE {self.table} PURGE", commit=True, expect={}
                )
                self.harness.emit(
                    "cleanup_drop_table", "teardown", "pass", 0,
                    "governed teardown dropped the throwaway table",
                )
            except (StepFailure, OSError, ValueError) as exc:
                self.harness.emit(
                    "cleanup_drop_table", "teardown", "fail", 0,
                    f"governed teardown failed; throwaway table may remain: {exc}",
                )
        self.session.close()


def verify_audit_records(args, harness):
    """Assert the audit hash-chain records the privileged ladder steps."""
    audit_path = os.path.join(
        os.environ["XDG_STATE_HOME"], "oraclemcp", "audit", "audit.jsonl"
    )
    if not os.path.exists(audit_path):
        raise StepFailure(f"audit chain file missing: {audit_path}")
    records = []
    with open(audit_path, encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                records.append(json.loads(line))
    require(records, "audit chain has records", audit_path)

    chain_fields = ("seq", "prev_hash", "entry_hash", "signature", "key_id", "tool")
    previous_hash = None
    for index, record in enumerate(records):
        for field in chain_fields:
            require(
                field in record,
                f"audit record {index} carries chain field `{field}`",
                sorted(record.keys()),
            )
        expected_prev = previous_hash if previous_hash is not None else "genesis"
        require(
            record["prev_hash"] == expected_prev,
            f"audit record {index} links to its predecessor",
            {"prev_hash": record["prev_hash"], "expected": expected_prev},
        )
        previous_hash = record["entry_hash"]

    def has(tool, **fields):
        return any(
            record.get("tool") == tool
            and all(record.get(key) == value for key, value in fields.items())
            for record in records
        )

    require(
        has("oracle_set_session_level"),
        "audit chain records the session-level step-ups",
        len(records),
    )
    require(
        has("oracle_execute", outcome="ROLLED_BACK"),
        "audit chain records the rollback-by-default DML",
        len(records),
    )
    require(
        has("oracle_execute", outcome="SUCCEEDED", decision="ALLOWED"),
        "audit chain records the committed governed executes",
        len(records),
    )
    harness.evidence_line(
        "audit_chain_records",
        "pass",
        {
            "audit_path": audit_path,
            "records": len(records),
            "tools": sorted({record.get("tool") for record in records}),
        },
    )
    return len(records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--banner-regex", required=True)
    parser.add_argument("--table", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()

    harness = Harness(args.evidence)
    ladder = Ladder(args, harness)
    try:
        ladder.run()
        harness.emit(
            "audit_chain_records", "assert", "running", 0, "verifying audit records"
        )
        record_count = verify_audit_records(args, harness)
        harness.emit(
            "audit_chain_records", "assert", "pass", 0,
            f"audit chain holds {record_count} linked, signed records",
        )
    except StepFailure as exc:
        # Failure detail goes to stdout: the wrapper keeps stderr reserved for
        # machine-readable JSON-line events (scripts/e2e/lib.sh contract).
        print(f"LADDER FAIL ({args.profile}): {exc}")
        return 1
    print(f"LADDER PASS ({args.profile})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
