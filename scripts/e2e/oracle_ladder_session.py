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
        self.primary_profile = args.profile
        self.ro_profile = getattr(args, "ro_profile", None)
        self.semantic_masked_profile = getattr(args, "semantic_masked_profile", None)
        self.custom_tool = getattr(args, "custom_tool", None)
        self.vector_smoke = getattr(args, "vector_smoke", False)
        self.table_created = False
        self.table_dropped = False
        self.vector_table = f"{args.table}_VEC"
        self.vector_table_created = False
        self.vector_table_dropped = False
        # Throwaway source objects for the create_or_replace / compile_object /
        # patch_source governed-DDL sub-ladder. Both a VIEW and a PL/SQL
        # PROCEDURE exercise oracle_create_or_replace's own DDL grant flow
        # (oracle-p0d6: PL/SQL CREATE OR REPLACE floors at DDL, no longer
        # delegating to the general execute path); the PROCEDURE additionally
        # exercises compile_object + patch_source (both DDL-gated).
        self.view = f"{args.table}_V"
        self.proc = f"{args.table}_P"
        self.proc_owner = None
        self.view_created = False
        self.view_dropped = False
        self.proc_created = False
        self.proc_dropped = False
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
        # Read isError from the TOP-LEVEL tool result (the MCP-authoritative
        # field), matching query_refused — not from structuredContent's
        # embedded copy, which is a server convenience that could drift.
        result = self.session.call("oracle_query", {"sql": sql})
        content = structured(result)
        require(
            result.get("isError") is not True,
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

    def query_governed_refusal(self, sql, allowed_classes):
        """oracle_query on a governed statement must be REFUSED before execution
        with a structured error_class in `allowed_classes` (asserts the value, not
        an exit code). Used for the always-forbidden and smuggled-DML paths."""
        result = self.session.call("oracle_query", {"sql": sql})
        content = structured(result)
        require(
            result.get("isError") is True,
            "governed statement via oracle_query is refused before execution",
            content,
        )
        cls = content.get("error_class")
        require(
            cls in allowed_classes,
            f"refusal carries a governed error_class in {sorted(allowed_classes)} (got {cls!r})",
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

    # -- additional governed-surface helpers (bead oraclemcp-rsya) ----------

    def explain_plan_refused(self, arguments, expect_class):
        """oracle_explain_plan must be REFUSED (structured error_class) before it
        writes PLAN_TABLE. Asserts the VALUE of error_class, not an exit code."""
        result = self.session.call("oracle_explain_plan", arguments)
        content = structured(result)
        require(
            result.get("isError") is True,
            "explain_plan is refused before the PLAN_TABLE diagnostic write",
            content,
        )
        require(
            content.get("error_class") == expect_class,
            f"explain_plan refusal carries error_class {expect_class} (got {content.get('error_class')!r})",
            content,
        )
        return content

    def sample_rows(self, arguments):
        result = self.session.call("oracle_sample_rows", arguments)
        content = structured(result)
        require(
            result.get("isError") is not True, "oracle_sample_rows succeeds", content
        )
        return content

    def read_clob(self, arguments):
        result = self.session.call("oracle_read_clob", arguments)
        content = structured(result)
        require(
            result.get("isError") is not True, "oracle_read_clob succeeds", content
        )
        clob = content.get("clob") or {}
        require(clob, "read_clob returns a clob structure", content)
        return clob

    def governed_execute_capture(self, sql, dbms_output_max_lines):
        """preview -> single-use grant -> oracle_execute with DBMS_OUTPUT capture.
        Returns the dbms_output object so the caller can assert the line/char caps."""
        preview = self.preview(sql)
        require(
            preview.get("gate_decision") == "allow",
            "DBMS_OUTPUT block preview allows at the current level",
            preview,
        )
        token = (preview.get("execute_confirmation") or {}).get("confirm")
        require(token, "DBMS_OUTPUT block preview mints a single-use grant", preview)
        self.harness.grant = "execute"
        outcome = structured(
            self.session.call(
                "oracle_execute",
                {
                    "sql": sql,
                    "commit": False,
                    "confirm": token,
                    "capture_dbms_output": True,
                    "dbms_output_max_lines": dbms_output_max_lines,
                },
            )
        )
        self.harness.grant = "none"
        require(outcome.get("executed") is True, "DBMS_OUTPUT block executed", outcome)
        dbms = outcome.get("dbms_output") or {}
        require(dbms.get("enabled") is True, "DBMS_OUTPUT capture is enabled", outcome)
        return dbms

    def switch_profile(self, profile):
        result = self.session.call("oracle_switch_profile", {"profile": profile})
        content = structured(result)
        require(
            result.get("isError") is not True,
            f"oracle_switch_profile to {profile} succeeds",
            content,
        )
        return content

    def preview_elevation(self, level):
        """Preview-only oracle_set_session_level (no execute); returns the raw
        structured response so the caller can assert gate posture."""
        return structured(
            self.session.call("oracle_set_session_level", {"level": level})
        )

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

        def read_only_server_version():
            import re

            connection = structured(self.session.call("oracle_connection_info", {}))
            require(
                connection.get("connected") is True,
                "connection metadata confirms the served profile is live",
                connection,
            )
            version = str((connection.get("connection") or {}).get("server_version") or "")
            require(
                re.search(self.args.server_version_regex, version),
                f"server version matches /{self.args.server_version_regex}/",
                version,
            )
            return {"server_version": version}

        def semantic_text_capability_is_typed_and_fail_closed():
            # This is deliberately a served MCP call, not a unit-level probe.
            # On the pre-23.4 lanes it must stop at the COMPATIBLE gate with the
            # machine-readable `requires_23ai` token; it must never fall back to
            # client embedding or a table scan. FREE 23ai may instead reach the
            # second gate and report that no local ONNX model is installed.
            result = self.session.call(
                "oracle_semantic_search",
                {
                    "over": {"table": "DUAL", "column": "DUMMY"},
                    "query_text": "synthetic governed-rag capability probe",
                    "k": 1,
                },
            )
            content = structured(result)
            require(
                result.get("isError") is True
                and content.get("error_class") == "RUNTIME_STATE_REQUIRED",
                "query_text capability gap returns a typed refusal, never a silent fallback",
                content,
            )
            token = ((content.get("structured_reason") or {}).get("offending_construct"))
            is_23ai_lane = self.args.server_version_regex.lstrip("^").startswith("23")
            expected = {"requires_23ai", "no_in_db_model"} if is_23ai_lane else {"requires_23ai"}
            require(
                token in expected,
                "semantic text refusal identifies the exact missing capability",
                {"token": token, "expected": sorted(expected), "content": content},
            )
            return {"capability_refusal": token}

        def read_only_arithmetic():
            rows = self.query_rows("SELECT 42 AS answer, 'ladder' AS tag FROM dual")
            require(rows and rows[0].get("ANSWER") == "42", "numeric literal round-trips", rows)
            require(rows[0].get("TAG") == "ladder", "string literal round-trips", rows)
            return {"rows": rows}

        def read_only_write_refused():
            return self.query_refused(
                f"INSERT INTO {table} (id, note) VALUES (1, 'refused')"
            )

        def read_only_forbidden_statement_refused():
            # A statement the fail-closed classifier marks Forbidden (a dynamic-SQL
            # PL/SQL block) is NEVER dispatchable at ANY level, so oracle_query must
            # refuse it with the FORBIDDEN_STATEMENT class — distinct from the
            # level-gated OPERATING_LEVEL_TOO_LOW. Identical on every lane/version.
            content = self.query_governed_refusal(
                "BEGIN EXECUTE IMMEDIATE 'DROP TABLE x'; END;",
                {"FORBIDDEN_STATEMENT"},
            )
            return {"error_class": content.get("error_class")}

        def read_only_smuggled_dml_not_served_as_read():
            # Regression for the derived-subquery-smuggled-DML classifier fix
            # (oracle-derived-dml-body): a write hidden in a FROM-derived subquery
            # must NOT be served as a READ_ONLY read. At READ_ONLY the guard sees a
            # write classification and refuses (OPERATING_LEVEL_TOO_LOW), or marks
            # it FORBIDDEN — either way it is refused, never executed as a read.
            content = self.query_governed_refusal(
                f"SELECT * FROM (UPDATE {table} SET note = 'x')",
                {"OPERATING_LEVEL_TOO_LOW", "FORBIDDEN_STATEMENT"},
            )
            return {"error_class": content.get("error_class")}

        def explain_plan_refused_at_read_only():
            # oracle_explain_plan writes PLAN_TABLE. Without an explicit
            # allow_plan_table_write it is refused (POLICY_DENIED) regardless of
            # level — a diagnostic write is never implicit. Identical every lane.
            content = self.explain_plan_refused(
                {"sql": "SELECT 1 FROM dual"}, "POLICY_DENIED"
            )
            return {"error_class": content.get("error_class")}

        def explain_plan_refused_on_standby():
            # Even with allow_plan_table_write=true, a read-only standby refuses
            # the PLAN_TABLE write fail-closed (POLICY_DENIED). We assert the
            # server honours a caller-declared standby; a live standby is not
            # required to prove the gate.
            content = self.explain_plan_refused(
                {
                    "sql": "SELECT 1 FROM dual",
                    "allow_plan_table_write": True,
                    "read_only_standby": True,
                },
                "POLICY_DENIED",
            )
            return {"error_class": content.get("error_class")}

        def explain_plan_allow_requires_read_write_at_read_only():
            # With allow_plan_table_write=true but the session at READ_ONLY, the
            # PLAN_TABLE write is gated up to READ_WRITE (OPERATING_LEVEL_TOO_LOW).
            content = self.explain_plan_refused(
                {"sql": "SELECT 1 FROM dual", "allow_plan_table_write": True},
                "OPERATING_LEVEL_TOO_LOW",
            )
            return {"error_class": content.get("error_class")}

        def custom_read_only_tool_callable():
            # An operator-defined READ_ONLY custom tool (from ORACLEMCP_TOOLS_DIR)
            # is served and returns its computed VALUE. A write/DDL custom tool is
            # refused at LOAD (fail closed) — that half is asserted by the wrapper
            # (custom_tool_write_refused), since a refused tool never reaches a
            # live MCP session.
            if not self.custom_tool:
                return {"skipped": "no --custom-tool provided"}
            tools = self.session.rpc("tools/list").get("result", {}).get("tools", [])
            names = {t.get("name") for t in tools}
            require(
                self.custom_tool in names,
                f"the READ_ONLY custom tool {self.custom_tool!r} is served",
                sorted(n for n in names if n and not n.startswith("oracle_")),
            )
            content = structured(self.session.call(self.custom_tool, {}))
            rows = content.get("rows") or []
            require(
                rows and rows[0].get("ANSWER") == "42",
                "custom READ_ONLY tool returns its numeric value",
                content,
            )
            require(
                rows[0].get("TAG") == "matrix",
                "custom tool string literal round-trips",
                content,
            )
            return {"rows": rows}

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
            # A CLOB column (`body`) is carried so the READ_WRITE phase can prove
            # oracle_read_clob's value + byte/char caps against a real LOB.
            result = self.governed_execute(
                f"CREATE TABLE {table} (id NUMBER PRIMARY KEY, note VARCHAR2(40), body CLOB)",
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

        def vector_distance_smoke():
            """Prove governed vector retrieval and its egress boundary end-to-end."""
            if not self.vector_smoke:
                return {"skipped": "VECTOR smoke is specific to the FREE 23ai lane"}
            require(
                self.semantic_masked_profile,
                "FREE 23ai vector proof has a READ_ONLY masking sibling profile",
                self.semantic_masked_profile,
            )

            vector_table = self.vector_table
            # The local FREE 23ai system account defaults to SYSTEM, whose
            # segment-space management is MANUAL. VECTOR columns require an
            # automatic tablespace; USERS is the standard automatic lab
            # tablespace and keeps this synthetic fixture out of SYSTEM.
            self.governed_execute(
                f"CREATE TABLE {vector_table} "
                "(id NUMBER PRIMARY KEY, label VARCHAR2(40), secret VARCHAR2(80), "
                "embedding VECTOR(3, FLOAT32)) TABLESPACE USERS",
                commit=True,
                expect={"committed": True},
            )
            self.vector_table_created = True
            for row_id, label, secret, embedding in [
                (1, "nearest", "do-not-return-vector-secret", "[1,0,0]"),
                (2, "second", "do-not-return-vector-secret", "[0.8,0.2,0]"),
                (3, "far", "do-not-return-vector-secret", "[0,1,0]"),
            ]:
                self.governed_execute(
                    f"INSERT INTO {vector_table} (id, label, secret, embedding) "
                    f"VALUES ({row_id}, '{label}', '{secret}', '{embedding}')",
                    commit=True,
                    expect={"committed": True, "rolled_back": False, "rows_affected": 1},
                )
            rows = self.query_rows(
                f"SELECT VECTOR_DISTANCE(v.embedding, '[1,0,0]', COSINE) AS distance "
                f"FROM {vector_table} v WHERE v.id = 1"
            )
            require(len(rows) == 1, "VECTOR_DISTANCE returns one synthetic row", rows)
            try:
                distance = float(rows[0].get("DISTANCE"))
            except (TypeError, ValueError) as exc:
                raise StepFailure(
                    f"VECTOR_DISTANCE result is not numeric: {rows!r} ({exc})"
                ) from exc
            require(
                abs(distance) < 0.000001,
                "VECTOR_DISTANCE of identical vectors is zero",
                {"distance": distance, "rows": rows},
            )

            search_args = {
                "over": {"table": vector_table, "column": "embedding"},
                "query_vector": [1.0, 0.0, 0.0],
                "k": 2,
                "metric": "COSINE",
            }
            semantic_result = self.session.call("oracle_semantic_search", search_args)
            semantic = structured(semantic_result)
            require(
                semantic_result.get("isError") is not True,
                "oracle_semantic_search succeeds through the served MCP surface",
                semantic,
            )
            semantic_rows = semantic.get("rows") or []
            require(
                semantic.get("metric") == "COSINE" and semantic.get("k") == 2,
                "semantic search reports the bound metric and k",
                semantic,
            )
            require(
                semantic.get("used_index") is None,
                "semantic search does not claim an unproven index decision",
                semantic,
            )
            require(
                len(semantic_rows) == 2 and semantic_rows[0].get("ID") == "1",
                "semantic search returns the synthetic nearest row first",
                semantic_rows,
            )

            filter_result = self.session.call(
                "oracle_semantic_search", {**search_args, "filter": "id = 1"}
            )
            filter_refusal = structured(filter_result)
            require(
                filter_result.get("isError") is True
                and filter_refusal.get("error_class") == "INVALID_ARGUMENTS",
                "an unproven caller filter is refused before it can become SQL",
                filter_refusal,
            )

            hybrid_args = {
                **search_args,
                "filter": {"column": "label", "value": "nearest"},
            }
            hybrid_result = self.session.call("oracle_semantic_search", hybrid_args)
            hybrid = structured(hybrid_result)
            require(
                hybrid_result.get("isError") is not True,
                "a server-owned equality filter produces a governed hybrid search",
                hybrid,
            )
            hybrid_rows = hybrid.get("rows") or []
            require(
                [row.get("ID") for row in hybrid_rows] == ["1"],
                "hybrid search returns top-k only within its proven filter",
                hybrid_rows,
            )

            widening_result = self.session.call(
                "oracle_semantic_search",
                {
                    **search_args,
                    "filter": {"column": "label OR 1=1", "value": "nearest"},
                },
            )
            widening_refusal = structured(widening_result)
            require(
                widening_result.get("isError") is True
                and widening_refusal.get("error_class") == "INVALID_ARGUMENTS",
                "a widening hybrid predicate is refused before it can become SQL",
                widening_refusal,
            )

            direct_result = self.session.call(
                "oracle_query",
                {
                    "sql": f"SELECT id FROM {vector_table} WHERE label = :1 ORDER BY id",
                    "binds": ["nearest"],
                },
            )
            direct = structured(direct_result)
            require(
                direct_result.get("isError") is not True
                and [row.get("ID") for row in (direct.get("rows") or [])]
                == [row.get("ID") for row in hybrid_rows],
                "hybrid search cannot infer rows outside an equivalent direct read",
                {"hybrid": hybrid_rows, "direct": direct},
            )

            # Oracle Free can return ORA-01466 to a second session that opens
            # while the DDL-owning session still holds its read snapshot. Close
            # that served session first, then prove masked egress from a fresh
            # READ_ONLY MCP client against the committed synthetic fixture.
            # This is a lifecycle boundary, not a retry: an initialization or
            # masked read failure remains a hard test failure.
            self.session.close()
            # Oracle's 23ai dictionary can expose a just-created VECTOR table
            # to a new session before its definition-SCN settles, yielding
            # ORA-01466 instead of a stable read. This single post-DDL barrier
            # is not a retry and is deliberately short; the following served
            # call still has exactly one chance to prove masked egress.
            time.sleep(2)
            masked = McpSession(self.args.binary, self.semantic_masked_profile)
            try:
                init = masked.rpc(
                    "initialize",
                    {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "oracle-vector-mask-e2e", "version": "1"},
                    },
                )
                require(
                    init.get("result", {}).get("serverInfo", {}).get("name") == "oraclemcp",
                    "masked semantic-search session identifies the served server",
                    init,
                )
                masked.notify("notifications/initialized")
                masked_hybrid_result = masked.call("oracle_semantic_search", hybrid_args)
                masked_hybrid_refusal = structured(masked_hybrid_result)
                require(
                    masked_hybrid_result.get("isError") is True
                    and masked_hybrid_refusal.get("error_class") == "POLICY_DENIED",
                    "a masked filter column cannot leak row presence through hybrid retrieval",
                    masked_hybrid_refusal,
                )
                masked_result = masked.call("oracle_semantic_search", search_args)
                masked_content = structured(masked_result)
                require(
                    masked_result.get("isError") is not True,
                    "READ_ONLY masked profile can run semantic search",
                    masked_content,
                )
                require(
                    "do-not-return-vector-secret" not in json.dumps(masked_content),
                    "semantic search never leaks the synthetic secret through a masked profile",
                    masked_content,
                )
                certificate = masked_content.get("mask_certificate") or {}
                decisions = certificate.get("decisions") or []
                require(
                    certificate.get("audit_entry_hash"),
                    "semantic-search masking certificate is bound to the sibling audit chain",
                    certificate,
                )
                require(
                    any(decision.get("column") == "SECRET" for decision in decisions),
                    "semantic-search masking certificate records the secret-column decision",
                    certificate,
                )
            finally:
                masked.close()

            # Resume the main ladder on a fresh primary session. The fixture's
            # DDL/DML was committed through the prior governed session, and the
            # cleanup below still goes through the normal DDL confirmation gate.
            self.session = McpSession(self.args.binary, self.primary_profile)
            resumed = self.session.rpc(
                "initialize",
                {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "oracle-vector-resume-e2e", "version": "1"},
                },
            )
            require(
                resumed.get("result", {}).get("serverInfo", {}).get("name") == "oraclemcp",
                "resumed primary session identifies the served server",
                resumed,
            )
            self.session.notify("notifications/initialized")
            self.harness.profile = self.primary_profile
            self.elevate("DDL")

            self.governed_execute(
                f"DROP TABLE {vector_table} PURGE", commit=True, expect={"committed": True}
            )
            self.vector_table_dropped = True
            return {
                "distance": distance,
                "vector_column": "VECTOR(3, FLOAT32)",
                "top_k": [row.get("ID") for row in semantic_rows],
                "hybrid_top_k": [row.get("ID") for row in hybrid_rows],
                "masked_secret_absent": True,
                "raw_filter_refused": filter_refusal.get("error_class"),
                "widening_filter_refused": widening_refusal.get("error_class"),
                "masked_filter_refused": masked_hybrid_refusal.get("error_class"),
            }

        # --- Source-object governed-DDL sub-ladder (still at DDL) -----------
        # Exercises oracle_create_or_replace / oracle_compile_object /
        # oracle_patch_source through the preview -> single-use grant -> execute
        # gate, asserting VALUES (object status, patched source text) rather than
        # exit codes, plus a wrong-grant refusal. Ground truth wired in here:
        #   * oracle_create_or_replace mints its OWN DDL grant for every
        #     DDL-classified object. A VIEW is DDL; and as of oracle-p0d6 a
        #     PL/SQL-bearing CREATE OR REPLACE (PROCEDURE/FUNCTION/…) also floors
        #     at DDL (was READ_WRITE), so BOTH the VIEW and the PROCEDURE drive
        #     the create_or_replace grant flow and are audited under the tool's
        #     own name.
        #   * oracle_patch_source ALWAYS forces the DDL gate (dispatch/mod.rs
        #     patch_required_level = Some(Ddl)) and mints its own grant, so a
        #     PROCEDURE drives compile_object + patch_source.
        # The audit assertions for these tools live in verify_audit_records.
        view = self.view
        proc = self.proc
        view_src = f"CREATE OR REPLACE VIEW {view} AS SELECT 1 AS id FROM dual"
        proc_src = f"CREATE OR REPLACE PROCEDURE {proc} AS BEGIN NULL; END;"

        def source_create_or_replace_view():
            preview = structured(
                self.session.call(
                    "oracle_create_or_replace", {"source_code": view_src}
                )
            )
            require(
                preview.get("gate_decision") == "allow",
                "create_or_replace(view) preview allows at DDL",
                preview,
            )
            require(
                preview.get("required_level") == "DDL",
                "create_or_replace of a VIEW is DDL-gated",
                preview,
            )
            token = (preview.get("confirmation") or {}).get("confirm")
            require(
                token, "create_or_replace(view) preview mints a single-use grant", preview
            )
            detected = preview.get("detected_object") or {}
            require(
                str(detected.get("name", "")).upper() == view.upper()
                and detected.get("object_type") == "VIEW",
                "preview detects the target VIEW",
                detected,
            )
            self.harness.grant = "execute"
            out = structured(
                self.session.call(
                    "oracle_create_or_replace",
                    {"source_code": view_src, "execute": True, "confirm": token},
                )
            )
            self.harness.grant = "none"
            require(out.get("applied") is True, "create_or_replace(view) applied", out)
            require(out.get("committed") is True, "create_or_replace(view) committed", out)
            self.view_created = True
            self.proc_owner = (out.get("detected_object") or detected).get("owner")
            return {"detected_object": detected, "applied": True}

        def source_create_or_replace_wrong_grant_refused():
            # Mint a real single-use grant via a fresh preview, then present a
            # WRONG confirmation token: the apply must be refused fail-closed and
            # nothing may be applied.
            structured(
                self.session.call(
                    "oracle_create_or_replace", {"source_code": view_src}
                )
            )
            result = self.session.call(
                "oracle_create_or_replace",
                {
                    "source_code": view_src,
                    "execute": True,
                    "confirm": "not-a-valid-grant-token",
                },
            )
            content = structured(result)
            require(
                result.get("isError") is True,
                "a wrong/stale execution grant is refused",
                content,
            )
            require(
                isinstance(content.get("error_class"), str)
                and content.get("error_class"),
                "the refusal carries a structured error_class",
                content,
            )
            require(
                content.get("applied") in (None, False),
                "nothing is applied on a refused grant",
                content,
            )
            return {"error_class": content.get("error_class")}

        def source_create_procedure_via_create_or_replace():
            # oracle-p0d6: a PL/SQL CREATE OR REPLACE now floors at DDL (was
            # READ_WRITE) and drives oracle_create_or_replace's OWN DDL grant
            # flow (preview -> single-use grant -> apply), exactly like the VIEW.
            # It must be audited under `oracle_create_or_replace`, not the
            # delegated `oracle_execute`.
            preview = structured(
                self.session.call(
                    "oracle_create_or_replace", {"source_code": proc_src}
                )
            )
            require(
                preview.get("gate_decision") == "allow",
                "create_or_replace(procedure) preview allows at DDL",
                preview,
            )
            require(
                preview.get("required_level") == "DDL",
                "create_or_replace of a PL/SQL PROCEDURE floors at DDL (not READ_WRITE)",
                preview,
            )
            token = (preview.get("confirmation") or {}).get("confirm")
            require(
                token,
                "create_or_replace(procedure) preview mints its OWN single-use grant",
                preview,
            )
            self.harness.grant = "execute"
            out = structured(
                self.session.call(
                    "oracle_create_or_replace",
                    {"source_code": proc_src, "execute": True, "confirm": token},
                )
            )
            self.harness.grant = "none"
            require(
                out.get("applied") is True, "create_or_replace(procedure) applied", out
            )
            require(
                out.get("committed") is True,
                "create_or_replace(procedure) committed",
                out,
            )
            self.proc_created = True
            errors = structured(self.session.call("oracle_compile_errors", {"name": proc}))
            require(
                errors.get("errors") == [],
                "created PROCEDURE has no compile errors through the dedicated dictionary tool",
                errors,
            )
            return out

        def source_compile_object():
            args_c = {"object_type": "PROCEDURE", "name": proc}
            if self.proc_owner:
                args_c["owner"] = self.proc_owner
            preview = structured(self.session.call("oracle_compile_object", args_c))
            require(
                preview.get("gate_decision") == "allow",
                "compile_object preview allows at DDL",
                preview,
            )
            require(
                preview.get("required_level") == "DDL",
                "compile_object requires the DDL level (ALTER ... COMPILE is DDL)",
                preview,
            )
            token = (preview.get("confirmation") or {}).get("confirm")
            require(token, "compile_object preview mints a single-use grant", preview)
            execute_args = dict(args_c)
            execute_args["execute"] = True
            execute_args["confirmation_token"] = token
            out = structured(self.session.call("oracle_compile_object", execute_args))
            require(out.get("compiled") is True, "object compiled", out)
            errors = structured(self.session.call("oracle_compile_errors", {"name": proc}))
            require(
                errors.get("errors") == [],
                "compiled procedure has no compile errors through the dedicated dictionary tool",
                errors,
            )
            return {"compiled": True}

        def source_patch_source():
            args_p = {
                "object_type": "PROCEDURE",
                "name": proc,
                "old_text": "NULL",
                "new_text": "NULL; NULL",
            }
            if self.proc_owner:
                args_p["owner"] = self.proc_owner
            preview = structured(self.session.call("oracle_patch_source", args_p))
            require(
                preview.get("match_count") == 1,
                "patch old_text matches the source exactly once",
                preview,
            )
            require(
                preview.get("required_level") == "DDL",
                "patch_source enforces the DDL gate",
                preview,
            )
            token = (preview.get("confirmation") or {}).get("confirm")
            require(token, "patch_source preview mints a single-use grant", preview)
            execute_args = dict(args_p)
            execute_args["execute"] = True
            execute_args["confirm"] = token
            out = structured(self.session.call("oracle_patch_source", execute_args))
            require(out.get("applied") is True, "patch_source applied", out)
            source = structured(
                self.session.call(
                    "oracle_get_source",
                    {"name": proc, "object_type": "PROCEDURE", "max_chars": 4096},
                )
            )
            source_text = (source.get("source") or {}).get("source") or ""
            require(
                "NULL; NULL" in source_text,
                "patched source text is returned by the capped dedicated source tool",
                source,
            )
            return {"applied": True}

        def source_drop_objects():
            self.governed_execute(
                f"DROP PROCEDURE {proc}", commit=True, expect={"committed": True}
            )
            self.proc_dropped = True
            self.governed_execute(
                f"DROP VIEW {view}", commit=True, expect={"committed": True}
            )
            self.view_dropped = True
            proc_source = structured(
                self.session.call(
                    "oracle_get_source",
                    {"name": proc, "object_type": "PROCEDURE", "max_chars": 4096},
                )
            )
            require(
                (proc_source.get("source") or {}).get("line_count") == 0,
                "the dropped PROCEDURE is absent through the dedicated source tool",
                proc_source,
            )
            return {"dropped": [proc, view]}

        def drop_to_read_only_mid():
            dropped = self.drop_level()
            refusal = self.query_refused(
                f"INSERT INTO {table} (id, note) VALUES (1, 'refused-again')"
            )
            return {"dropped": dropped, "refusal": refusal}

        def elevate_read_write():
            return self.elevate("READ_WRITE")

        def raw_alter_session_container_refused_and_identity_preserved():
            # Regression for QA83: READ_WRITE authority must not bypass the
            # reviewed ALTER SESSION parameter policy. SET CONTAINER persists
            # outside transaction rollback, so prove both that no execution
            # grant is minted and that the live container identity is unchanged.
            identity_sql = (
                "SELECT SYS_CONTEXT('USERENV', 'CON_NAME') AS con_name FROM dual"
            )
            before_rows = self.query_rows(identity_sql)
            require(
                len(before_rows) == 1 and before_rows[0].get("CON_NAME"),
                "the live session exposes its current container identity",
                before_rows,
            )
            before = before_rows[0].get("CON_NAME")
            sql = "ALTER SESSION SET CONTAINER = CDB$ROOT"
            preview = self.preview(sql)
            require(
                preview.get("gate_decision") == "blocked",
                "raw SET CONTAINER is blocked at READ_WRITE",
                preview,
            )
            require(
                (preview.get("blocked_reason") or {}).get("type") == "forbidden",
                "SET CONTAINER is a policy refusal, not an elevation request",
                preview,
            )
            require(
                preview.get("execute_confirmation") is None,
                "a forbidden session change never mints an execution grant",
                preview,
            )

            result = self.session.call("oracle_execute", {"sql": sql})
            content = structured(result)
            require(
                result.get("isError") is True,
                "raw SET CONTAINER is refused before Oracle sees it",
                content,
            )
            require(
                content.get("error_class") == "FORBIDDEN_STATEMENT",
                "SET CONTAINER refusal has the fail-closed error class",
                content,
            )
            after_rows = self.query_rows(identity_sql)
            after = after_rows[0].get("CON_NAME") if len(after_rows) == 1 else None
            require(
                after == before,
                "the live container identity is unchanged after refusal",
                {"before": before, "after": after},
            )
            return {
                "error_class": content.get("error_class"),
                "container_before": before,
                "container_after": after,
            }

        def parsed_ddl_refused_at_read_write_and_table_preserved():
            # Regression for QA84: COMMENT ON parses successfully, but Oracle
            # treats it as implicit-commit DDL. At READ_WRITE it must require a
            # DDL step-up and never reach Oracle, otherwise the outer rollback
            # would falsely claim to undo a persistent metadata change.
            before = self.count_rows(f"SELECT COUNT(*) AS n FROM {table}")
            require(
                before == 0,
                "the live target has no rows before the refused DDL",
                before,
            )
            sql = f"COMMENT ON TABLE {table} IS 'qa84-must-not-land'"
            preview = self.preview(sql)
            require(
                preview.get("required_level") == "DDL",
                "parsed COMMENT ON keeps the DDL floor",
                preview,
            )
            require(
                preview.get("gate_decision") == "require_step_up",
                "COMMENT ON cannot execute at READ_WRITE",
                preview,
            )
            require(
                preview.get("execute_confirmation") is None,
                "no DDL grant is minted below DDL",
                preview,
            )

            result = self.session.call(
                "oracle_execute", {"sql": sql, "commit": False}
            )
            content = structured(result)
            require(
                result.get("isError") is True,
                "parsed COMMENT ON is refused before Oracle at READ_WRITE",
                content,
            )
            require(
                content.get("error_class") == "OPERATING_LEVEL_TOO_LOW",
                "parsed DDL refusal names the operating-level boundary",
                content,
            )
            after = self.count_rows(f"SELECT COUNT(*) AS n FROM {table}")
            require(
                after == before,
                "the target table's rows are unchanged after the pre-Oracle DDL refusal",
                {"before": before, "after": after},
            )
            return {
                "error_class": content.get("error_class"),
                "table_preserved": True,
            }

        def opaque_plsql_ddl_call_refused_and_target_preserved():
            # Regression for QA81: DBMS_UTILITY can execute caller-provided DDL,
            # so an opaque package call must never inherit the READ_WRITE block
            # floor. Prove the live target still exists after both preview and
            # execution refuse the statement before Oracle sees it.
            sql = (
                "BEGIN DBMS_UTILITY.EXEC_DDL_STATEMENT("
                f"'DROP TABLE {table} PURGE'); END;"
            )
            preview = self.preview(sql)
            require(
                preview.get("gate_decision") == "blocked",
                "opaque DBMS_UTILITY DDL is blocked at READ_WRITE",
                preview,
            )
            require(
                preview.get("execute_confirmation") is None,
                "a forbidden opaque call never mints an execution grant",
                preview,
            )
            result = self.session.call("oracle_execute", {"sql": sql})
            content = structured(result)
            require(
                result.get("isError") is True,
                "opaque DBMS_UTILITY DDL is refused before execution",
                content,
            )
            require(
                content.get("error_class") == "FORBIDDEN_STATEMENT",
                "opaque-call refusal has the fail-closed error class",
                content,
            )
            remaining_rows = self.count_rows(f"SELECT COUNT(*) AS n FROM {table}")
            require(
                remaining_rows == 0,
                "the live target table remains after the refused opaque call",
                remaining_rows,
            )
            return {"error_class": content.get("error_class"), "target_present": True}

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

        def dml_commit_clob_row():
            # A second committed row carrying a known CLOB body (100 'X'), so the
            # sample_rows cap and read_clob value/cap steps have real data.
            result = self.governed_execute(
                f"INSERT INTO {table} (id, note, body) "
                f"VALUES (4, 'clob-row', RPAD('X', 100, 'X'))",
                commit=True,
                expect={"committed": True, "rolled_back": False, "rows_affected": 1},
            )
            count = self.count_rows(f"SELECT COUNT(*) AS n FROM {table}")
            require(count == 2, "table now holds exactly two committed rows", count)
            return result

        def sample_rows_values_and_cap():
            # VALUE assertion: sampled rows carry the committed values; the cap is
            # enforced. Identical structured shape on every lane/version.
            full = self.sample_rows({"table": table})
            require(
                full.get("row_count") == 2, "sample_rows returns both rows", full
            )
            by_id = {
                str(r.get("ID")): r for r in full.get("rows", []) if r.get("ID")
            }
            require(
                by_id.get("2", {}).get("NOTE") == "commit-me",
                "sampled row id=2 carries its committed NOTE value",
                full,
            )
            require(
                by_id.get("4", {}).get("NOTE") == "clob-row",
                "sampled row id=4 carries its committed NOTE value",
                full,
            )
            capped = self.sample_rows({"table": table, "max_rows": 1})
            require(
                capped.get("row_count") == 1,
                "sample_rows honours the max_rows cap (1 of 2)",
                capped,
            )
            return {"row_count": full.get("row_count"), "capped": capped.get("row_count")}

        def read_clob_value_and_cap():
            # Full read: the 100-char CLOB round-trips, not truncated.
            full = self.read_clob(
                {
                    "table": table,
                    "clob_column": "body",
                    "pk_column": "id",
                    "pk_value": "4",
                }
            )
            require(
                full.get("char_count") == 100 and full.get("truncated") is False,
                "read_clob returns the full 100-char CLOB, not truncated",
                full,
            )
            require(
                full.get("value") == "X" * 100,
                "read_clob value round-trips the stored CLOB bytes",
                full,
            )
            # Capped read: max_chars=10 truncates the decoded cell; char_count
            # still reports the true length.
            capped = self.read_clob(
                {
                    "table": table,
                    "clob_column": "body",
                    "pk_column": "id",
                    "pk_value": "4",
                    "max_chars": 10,
                }
            )
            require(
                capped.get("truncated") is True
                and capped.get("value") == "X" * 10
                and capped.get("char_count") == 100,
                "read_clob honours the max_chars byte/char cap (decode cap)",
                capped,
            )
            return {"char_count": full.get("char_count")}

        def dbms_output_capture_caps():
            # A PL/SQL block emitting 50 DBMS_OUTPUT lines, captured with a
            # 10-line cap: the capture is truncated and the line cap is enforced.
            output_calls = " ".join(
                f"SYS.DBMS_OUTPUT.PUT_LINE('ladder line {i}');"
                for i in range(1, 51)
            )
            dbms = self.governed_execute_capture(
                f"BEGIN {output_calls} END;",
                dbms_output_max_lines=10,
            )
            require(
                dbms.get("max_lines") == 10,
                "the requested DBMS_OUTPUT line cap is echoed",
                dbms,
            )
            require(
                dbms.get("line_count") == 10 and len(dbms.get("lines", [])) == 10,
                "DBMS_OUTPUT capture is bounded to the line cap",
                dbms,
            )
            require(
                dbms.get("truncated") is True,
                "DBMS_OUTPUT capture reports truncation past the cap",
                dbms,
            )
            require(
                dbms.get("lines", [None])[0] == "ladder line 1",
                "captured DBMS_OUTPUT lines carry their emitted values",
                dbms,
            )
            return {"line_count": dbms.get("line_count"), "truncated": dbms.get("truncated")}

        def explain_plan_read_write_allowed():
            # At READ_WRITE with allow_plan_table_write=true the PLAN_TABLE
            # diagnostic write is permitted and a real plan comes back.
            result = self.session.call(
                "oracle_explain_plan",
                {"sql": f"SELECT * FROM {table}", "allow_plan_table_write": True},
            )
            content = structured(result)
            require(
                result.get("isError") is not True,
                "explain_plan executes at READ_WRITE with the diagnostic write allowed",
                content,
            )
            plan = content.get("plan") or []
            plan_text = " ".join(
                str(row.get("PLAN_TABLE_OUTPUT", "")) for row in plan
            )
            require(
                len(plan) >= 1 and "SELECT STATEMENT" in plan_text.upper(),
                "explain_plan returns a non-empty plan naming the SELECT STATEMENT",
                content,
            )
            require(
                (content.get("diagnostic_write") or {}).get("explicitly_allowed")
                is True,
                "the plan result records the explicit PLAN_TABLE write consent",
                content,
            )
            return {"plan_rows": len(plan)}

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
            description = structured(
                self.session.call("oracle_describe", {"table": table})
            )
            require(
                description.get("columns") == [],
                "table is absent through the bounded describe tool",
                description,
            )
            return result

        def drop_to_read_only_final():
            dropped = self.drop_level()
            refusal = self.query_refused(
                f"INSERT INTO {table} (id, note) VALUES (3, 'refused-final')"
            )
            return {"dropped": dropped, "refusal": refusal}

        def switch_profile_reconnect_and_posture():
            # oracle_switch_profile: reconnect to a READ_ONLY-ceiling sibling and
            # prove the posture CHANGED (elevation blocked by the ceiling), then
            # reconnect back to the primary and prove the DDL ceiling is restored.
            # VALUE + structured-gate assertions, identical on every lane.
            if not self.ro_profile:
                return {"skipped": "no --ro-profile provided"}

            switched = self.switch_profile(self.ro_profile)
            require(
                switched.get("connected") is True
                and switched.get("active_profile") == self.ro_profile,
                "switch reconnects to the read-only sibling profile",
                switched,
            )
            require(
                (switched.get("connection") or {}).get("server_version"),
                "the reconnected session reports a live server version",
                switched,
            )
            self.harness.profile = self.ro_profile

            blocked = self.preview_elevation("READ_WRITE")
            gate = blocked.get("gate") or {}
            reason = gate.get("reason") or {}
            require(
                gate.get("decision") == "blocked"
                and reason.get("type") == "exceeds_ceiling",
                "posture: READ_WRITE elevation is ceiling-blocked on the RO profile",
                blocked,
            )
            require(
                (blocked.get("session") or {}).get("max_level") == "READ_ONLY",
                "posture: the RO profile reports a READ_ONLY ceiling",
                blocked,
            )

            back = self.switch_profile(self.primary_profile)
            require(
                back.get("connected") is True
                and back.get("active_profile") == self.primary_profile,
                "switch reconnects back to the primary profile",
                back,
            )
            self.harness.profile = self.primary_profile

            restored = self.preview_elevation("READ_WRITE")
            require(
                (restored.get("execute_confirmation") is not None)
                or ((restored.get("confirmation") or {}).get("confirm"))
                or restored.get("gate", {}).get("decision") != "blocked",
                "posture: the primary profile again permits a READ_WRITE step-up",
                restored,
            )
            return {"switched_to": self.ro_profile, "restored": self.primary_profile}

        steps = [
            ("session_initialize", session_initialize),
            ("read_only_server_version", read_only_server_version),
            (
                "semantic_text_capability_is_typed_and_fail_closed",
                semantic_text_capability_is_typed_and_fail_closed,
            ),
            ("read_only_arithmetic", read_only_arithmetic),
            ("read_only_write_refused", read_only_write_refused),
            (
                "read_only_forbidden_statement_refused",
                read_only_forbidden_statement_refused,
            ),
            (
                "read_only_smuggled_dml_not_served_as_read",
                read_only_smuggled_dml_not_served_as_read,
            ),
            ("explain_plan_refused_at_read_only", explain_plan_refused_at_read_only),
            ("explain_plan_refused_on_standby", explain_plan_refused_on_standby),
            (
                "explain_plan_allow_requires_read_write_at_read_only",
                explain_plan_allow_requires_read_write_at_read_only,
            ),
            ("custom_read_only_tool_callable", custom_read_only_tool_callable),
            ("preview_insert_requires_step_up", preview_insert_requires_step_up),
            ("elevate_ddl", elevate_ddl),
            ("ddl_create_table", ddl_create_table),
            ("vector_distance_smoke", vector_distance_smoke),
            ("verify_table_exists", verify_table_exists),
            ("source_create_or_replace_view", source_create_or_replace_view),
            (
                "source_create_or_replace_wrong_grant_refused",
                source_create_or_replace_wrong_grant_refused,
            ),
            (
                "source_create_procedure_via_create_or_replace",
                source_create_procedure_via_create_or_replace,
            ),
            ("source_compile_object", source_compile_object),
            ("source_patch_source", source_patch_source),
            ("source_drop_objects", source_drop_objects),
            ("drop_to_read_only_mid", drop_to_read_only_mid),
            ("elevate_read_write", elevate_read_write),
            (
                "raw_alter_session_container_refused_and_identity_preserved",
                raw_alter_session_container_refused_and_identity_preserved,
            ),
            (
                "parsed_ddl_refused_at_read_write_and_table_preserved",
                parsed_ddl_refused_at_read_write_and_table_preserved,
            ),
            (
                "opaque_plsql_ddl_call_refused_and_target_preserved",
                opaque_plsql_ddl_call_refused_and_target_preserved,
            ),
            ("dml_rollback_by_default", dml_rollback_by_default),
            ("dml_commit", dml_commit),
            ("dml_commit_clob_row", dml_commit_clob_row),
            ("sample_rows_values_and_cap", sample_rows_values_and_cap),
            ("read_clob_value_and_cap", read_clob_value_and_cap),
            ("dbms_output_capture_caps", dbms_output_capture_caps),
            ("explain_plan_read_write_allowed", explain_plan_read_write_allowed),
            ("ddl_requires_step_up_at_read_write", ddl_requires_step_up_at_read_write),
            ("elevate_ddl_again", elevate_ddl_again),
            ("ddl_drop_table", ddl_drop_table),
            ("drop_to_read_only_final", drop_to_read_only_final),
            (
                "switch_profile_reconnect_and_posture",
                switch_profile_reconnect_and_posture,
            ),
        ]
        try:
            for name, fn in steps:
                self.step(name, fn)
        finally:
            self.cleanup()

    def cleanup(self):
        """Best-effort governed teardown of the throwaway objects, then exit."""
        if self.vector_table_created and not self.vector_table_dropped:
            try:
                self.elevate("DDL")
                self.governed_execute(
                    f"DROP TABLE {self.vector_table} PURGE", commit=True, expect={}
                )
                self.harness.emit(
                    "cleanup_drop_vector_table", "teardown", "pass", 0,
                    "governed teardown dropped the throwaway VECTOR table",
                )
            except (StepFailure, OSError, ValueError) as exc:
                self.harness.emit(
                    "cleanup_drop_vector_table", "teardown", "fail", 0,
                    f"governed teardown failed; throwaway VECTOR table may remain: {exc}",
                )
        leftovers = []
        if self.proc_created and not self.proc_dropped:
            leftovers.append(("PROCEDURE", self.proc))
        if self.view_created and not self.view_dropped:
            leftovers.append(("VIEW", self.view))
        if leftovers:
            try:
                self.elevate("DDL")
                for kind, name in leftovers:
                    self.governed_execute(
                        f"DROP {kind} {name}", commit=True, expect={}
                    )
                self.harness.emit(
                    "cleanup_drop_source_objects", "teardown", "pass", 0,
                    "governed teardown dropped the throwaway source objects",
                )
            except (StepFailure, OSError, ValueError) as exc:
                self.harness.emit(
                    "cleanup_drop_source_objects", "teardown", "fail", 0,
                    f"governed teardown failed; throwaway objects may remain: {exc}",
                )
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

    # AuditRecord skip-serializes signature/key_id when the record is unsigned,
    # so their absence means the signing key never reached the oraclemcp binary
    # (the wrapper exports ORACLEMCP_AUDIT_KEY). Fail with a clear diagnosis
    # instead of a bare per-field assertion.
    unsigned = [
        index
        for index, record in enumerate(records)
        if "signature" not in record or "key_id" not in record
    ]
    if unsigned:
        raise StepFailure(
            "audit records are UNSIGNED (no signature/key_id) at indices "
            f"{unsigned[:5]}{'...' if len(unsigned) > 5 else ''} of {len(records)}: "
            "the audit signing key did not reach the oraclemcp binary — ensure "
            "ORACLEMCP_AUDIT_KEY is exported in the server's environment "
            "(oracle_version_matrix.sh sets it before launching the ladder)"
        )

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
    # Source-object governed-DDL sub-ladder: create_or_replace, compile_object,
    # and patch_source each write their own signed, ALLOWED, SUCCEEDED audit
    # record. (oracle-p0d6: a PL/SQL CREATE OR REPLACE now floors at DDL and
    # mints its own grant, so it is audited under `oracle_create_or_replace`,
    # NOT the delegated `oracle_execute` — both the VIEW and the PROCEDURE apply
    # under the tool's own name.)
    require(
        has("oracle_create_or_replace", outcome="SUCCEEDED", decision="ALLOWED"),
        "audit chain records the governed create_or_replace under its own tool name",
        len(records),
    )
    require(
        has("oracle_compile_object", outcome="SUCCEEDED", decision="ALLOWED"),
        "audit chain records the governed compile_object",
        len(records),
    )
    require(
        has("oracle_patch_source", outcome="SUCCEEDED", decision="ALLOWED"),
        "audit chain records the governed patch_source",
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
    parser.add_argument("--server-version-regex", required=True)
    parser.add_argument("--table", required=True)
    parser.add_argument("--evidence", required=True)
    # A READ_ONLY-ceiling sibling profile (same lane DSN) for the
    # oracle_switch_profile reconnect + posture assertions. The wrapper adds it
    # to the generated config. Absent -> the switch-profile step is skipped
    # (kept optional so the driver still runs standalone).
    parser.add_argument("--ro-profile", default=None)
    # An operator-defined READ_ONLY custom tool the wrapper wrote into
    # ORACLEMCP_TOOLS_DIR; the ladder asserts it is served and returns its value.
    parser.add_argument("--custom-tool", default=None)
    parser.add_argument(
        "--vector-smoke",
        action="store_true",
        help="create a synthetic VECTOR column and verify VECTOR_DISTANCE (FREE 23ai only)",
    )
    parser.add_argument(
        "--semantic-masked-profile",
        default=None,
        help="READ_ONLY sibling profile whose masking policy proves vector-search egress",
    )
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
