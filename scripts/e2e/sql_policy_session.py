#!/usr/bin/env python3
"""Served MCP proof for Arc N's monotone, profile-scoped SQL policy.

The wrapper creates a local-only profile and a throwaway table. This driver
never reads an operator config or emits credentials: durable evidence contains
only synthetic rule identifiers, counts, and SHA-256 digests.
"""

import argparse
import hashlib
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
    """A failed served-surface assertion."""


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


class Harness:
    """Shared JSON-line events plus secret-free durable evidence."""

    def __init__(self, evidence_path):
        self.log_enabled = os.environ.get("E2E_LOG", "0") == "1"
        self.evidence = open(evidence_path, "a", encoding="utf-8")

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
                    "lane": os.environ.get("E2E_LANE", "free23"),
                    "subject": os.environ.get("E2E_SUBJECT", "test-harness"),
                    "sid": os.environ.get("E2E_SID", str(os.getpid())),
                    "profile": os.environ.get("E2E_PROFILE", "policy"),
                    "level": os.environ.get("E2E_LEVEL", "DDL"),
                    "grant": "none",
                    "outcome": outcome,
                    "scenario": os.environ.get("E2E_SCENARIO", "sql_policy"),
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
                {"ts": now_iso(), "step": step, "outcome": outcome, "detail": detail},
                sort_keys=True,
            )
            + "\n"
        )
        self.evidence.flush()

    def close(self):
        self.evidence.close()


def server_env(config, state_home=None):
    """Keep only deliberate server inputs; no ambient operator config leaks in."""

    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("ORACLEMCP_")
        or key in {"ORACLEMCP_CONFIG", "ORACLEMCP_AUDIT_KEY"}
    }
    env["ORACLEMCP_CONFIG"] = str(config)
    if state_home is not None:
        env["XDG_STATE_HOME"] = str(state_home)
    return env


class McpSession:
    """One real, long-lived MCP stdio session against the served binary."""

    def __init__(self, binary, profile, server_stderr, config, state_home):
        self.stderr = open(server_stderr, "a", encoding="utf-8")
        self.proc = subprocess.Popen(
            [binary, "serve", "--profile", profile, "--allow-no-auth"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=server_env(config, state_home),
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
                raise StepFailure("server exited before the expected MCP reply")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise StepFailure(f"timeout waiting for reply to {method}")
            try:
                line = self.queue.get(timeout=min(remaining, 0.5))
            except queue.Empty:
                continue
            try:
                reply = json.loads(line)
            except json.JSONDecodeError as error:
                raise StepFailure("server emitted malformed JSON-RPC") from error
            if reply.get("id") == self.request_id:
                return reply

    def initialize(self):
        reply = self.rpc(
            "initialize",
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "oraclemcp-sql-policy-e2e", "version": "1"},
            },
        )
        require(
            reply.get("result", {}).get("serverInfo", {}).get("name") == "oraclemcp",
            "served MCP server identifies itself",
            reply,
        )
        self.proc.stdin.write(
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
        )
        self.proc.stdin.flush()

    def call(self, tool, arguments):
        reply = self.rpc("tools/call", {"name": tool, "arguments": arguments})
        require("error" not in reply, f"{tool} returned a JSON-RPC protocol error", reply)
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


class PolicyScenario:
    def __init__(self, args, harness):
        self.args = args
        self.harness = harness
        self.session = None
        self.created = False

    def open_session(self, config, state_home):
        return McpSession(
            self.args.binary,
            self.args.profile,
            self.args.server_stderr,
            config,
            state_home,
        )

    def step(self, name, fn):
        started = time.monotonic()
        self.harness.emit(name, "act", "running", 0, f"step {name} started")
        try:
            detail = fn()
        except StepFailure as error:
            duration = int((time.monotonic() - started) * 1000)
            self.harness.emit(name, "assert", "fail", duration, str(error))
            self.harness.evidence_line(name, "fail", {"error": str(error)})
            raise
        duration = int((time.monotonic() - started) * 1000)
        self.harness.emit(name, "assert", "pass", duration, f"step {name} passed")
        self.harness.evidence_line(name, "pass", detail)
        return detail

    def execute(self, sql):
        require(self.session is not None, "fixture session is active", None)
        preview = structured(self.session.call("oracle_preview_sql", {"sql": sql}))
        require(preview.get("gate_decision") == "allow", "preview allows lab mutation", preview)
        confirm = (preview.get("execute_confirmation") or {}).get("confirm")
        require(confirm, "preview supplies execution confirmation", preview)
        result = self.session.call(
            "oracle_execute", {"sql": sql, "commit": True, "confirm": confirm}
        )
        content = structured(result)
        require(result.get("isError") is not True, "governed mutation succeeds", content)
        require(content.get("executed") is True, "governed mutation executed", content)
        return content

    def audit_record_for_query(self):
        path = Path(self.args.audit_file)
        require(path.exists(), "query audit file exists", str(path))
        records = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        for record in reversed(records):
            if record.get("tool") == "oracle_query" and record.get("outcome") == "SUCCEEDED":
                return record
        raise StepFailure("no successful oracle_query audit record was persisted")

    def run(self):
        def bootstrap_fixture():
            self.session = self.open_session(
                self.args.bootstrap_config, self.args.bootstrap_state
            )
            try:
                self.session.initialize()
                self.execute(
                    f"CREATE TABLE {self.args.table} (id NUMBER PRIMARY KEY, tenant_id NUMBER NOT NULL, label VARCHAR2(32))"
                )
                self.created = True
                self.execute(
                    f"INSERT INTO {self.args.table} (id, tenant_id, label) VALUES (7, 7, 'allowed')"
                )
                self.execute(
                    f"INSERT INTO {self.args.table} (id, tenant_id, label) VALUES (8, 8, 'filtered')"
                )
            finally:
                self.session.close()
                self.session = None
            return {"fixture": "throwaway-table-created", "inserted_rows": 2}

        self.step("bootstrap_fixture_through_served_surface", bootstrap_fixture)

        self.session = self.open_session(self.args.policy_config, self.args.policy_state)
        self.step("initialize_policy_profile", self.session.initialize)

        qualified_table = f"{self.args.schema}.{self.args.table}"
        original_sql = f"SELECT id, tenant_id, label FROM {qualified_table}"

        def narrowing_reclassifies_and_reaches_oracle():
            result = self.session.call("oracle_query", {"sql": original_sql})
            content = structured(result)
            require(result.get("isError") is not True, "narrowed read succeeds", content)
            narrow = (content.get("policy") or {}).get("Narrow") or {}
            require(
                narrow,
                "served profile attaches the policy proof to the wire response",
                content,
            )
            rows = content.get("rows") or []
            tenants = {str(row.get("TENANT_ID")) for row in rows}
            require(tenants == {"7"}, "predicate filters out the non-matching tenant", rows)

            require(
                narrow.get("base_required_level") == "READ_ONLY",
                "policy proof retains the classifier's original level",
                narrow,
            )
            require(
                narrow.get("required_level") == "DDL",
                "policy floor raises the required level on the wire",
                narrow,
            )
            rule_ids = set(narrow.get("matched_rule_ids") or [])
            require(
                {"policy-e2e-query-needs-ddl", "policy-e2e-tenant-seven"}.issubset(rule_ids),
                "wire proof identifies both tightening rules",
                narrow,
            )
            predicates = narrow.get("predicates") or []
            require(
                any(
                    predicate.get("rule_id") == "policy-e2e-tenant-seven"
                    and predicate.get("sql_fragment") == "tenant_id = 7"
                    for predicate in predicates
                ),
                "wire proof identifies the applied predicate",
                narrow,
            )

            # The query response only exposes redacted policy proof, never its
            # server-generated SQL. The signed audit record is the independently
            # checkable witness: it must bind the classifier certificate to a
            # digest that is NOT the client-supplied SQL (with its normal marker).
            # Together with the filtered rows above, this proves the policy's
            # rewritten candidate, rather than the stored base verdict, was the
            # statement re-entering the classifier before execution.
            record = self.audit_record_for_query()
            certificate = record.get("verdict_certificate") or {}
            original_marked = (
                "/* oraclemcp llm=oraclemcp profile=policy tool=oracle_query */ "
                + original_sql
            )
            original_digest = "sha256:" + hashlib.sha256(
                original_marked.encode("utf-8")
            ).hexdigest()
            require(
                certificate.get("stmt_digest") == record.get("sql_sha256"),
                "signed certificate binds the actually classified query text",
                record,
            )
            require(
                record.get("sql_sha256") != original_digest,
                "audit digest differs from client SQL, proving the policy candidate was classified",
                {"original_digest": original_digest, "record_digest": record.get("sql_sha256")},
            )
            return {
                "returned_tenant_count": len(rows),
                "matched_rule_count": len(rule_ids),
                "base_required_level": narrow.get("base_required_level"),
                "required_level": narrow.get("required_level"),
                "candidate_digest_differs": True,
            }

        self.step("narrow_reclassifies_and_proves_on_wire", narrowing_reclassifies_and_reaches_oracle)

        def unprovable_policy_target_refuses():
            # The base classifier admits this as a read, but the policy cannot
            # safely place a static predicate through an alias. Its inability to
            # prove the exact target is therefore a typed refusal, never a
            # fall-open read of both tenants.
            result = self.session.call(
                "oracle_query", {"sql": f"SELECT p.id FROM {qualified_table} p"}
            )
            content = structured(result)
            require(result.get("isError") is True, "unprovable policy target refuses", content)
            require(
                content.get("error_class") == "POLICY_DENIED",
                "policy evaluation failure uses the typed policy envelope",
                content,
            )
            tightening = (content.get("structured_reason") or {}).get("policy_tightening") or {}
            deny = tightening.get("Deny") or tightening.get("deny") or {}
            require(
                deny.get("reason") == "unresolved_policy_target",
                "policy target derivation fails closed instead of guessing an alias",
                content,
            )
            return {"error_class": content.get("error_class"), "reason": deny.get("reason")}

        self.step("policy_evaluation_failure_refuses", unprovable_policy_target_refuses)

        def deny_refuses_at_dispatch():
            result = self.session.call(
                "oracle_execute",
                {"sql": f"DELETE FROM {qualified_table} WHERE id = 7", "commit": True},
            )
            content = structured(result)
            require(result.get("isError") is True, "configured Deny refuses", content)
            require(
                content.get("error_class") == "POLICY_DENIED",
                "Deny returns the typed policy error envelope",
                content,
            )
            tightening = (content.get("structured_reason") or {}).get("policy_tightening") or {}
            deny = tightening.get("Deny") or tightening.get("deny") or {}
            require(
                "deny-policy-e2e-delete" in (deny.get("matched_rule_ids") or []),
                "Deny envelope identifies its matched policy rule",
                content,
            )
            return {"error_class": content.get("error_class"), "matched_rule_count": 1}

        self.step("deny_refuses_at_dispatch", deny_refuses_at_dispatch)

        def base_classifier_stays_authoritative():
            result = self.session.call(
                "oracle_execute",
                {
                    "sql": "BEGIN EXECUTE IMMEDIATE 'DROP TABLE E2E_POLICY_NEVER_EXECUTES'; END;",
                    "commit": True,
                },
            )
            content = structured(result)
            require(result.get("isError") is True, "base-forbidden SQL is refused", content)
            require(
                content.get("error_class") == "FORBIDDEN_STATEMENT",
                "policy does not widen a base-classifier refusal",
                content,
            )
            return {"error_class": content.get("error_class")}

        self.step("base_classifier_refusal_is_not_widened", base_classifier_stays_authoritative)

        def invalid_policy_fails_closed_at_startup():
            invalid_state = Path(self.args.invalid_state)
            invalid_state.mkdir(parents=True, exist_ok=True)
            result = subprocess.run(
                [self.args.binary, "serve", "--profile", "invalid-policy", "--allow-no-auth"],
                input="",
                capture_output=True,
                text=True,
                timeout=30,
                env=server_env(self.args.invalid_config, invalid_state),
                check=False,
            )
            combined = f"{result.stdout}\n{result.stderr}".lower()
            require(
                result.returncode != 0,
                "an unevaluatable policy cannot start an unpoliced server",
                {"returncode": result.returncode},
            )
            require(
                "invalid sql_policy" in combined or "unknown policy grammar" in combined,
                "startup refusal identifies the invalid policy grammar without serving requests",
                {"returncode": result.returncode},
            )
            return {"startup_refused": True}

        self.step("invalid_policy_fails_closed", invalid_policy_fails_closed_at_startup)

    def cleanup(self):
        try:
            if self.session is not None:
                self.session.close()
                self.session = None
            if self.created:
                self.session = self.open_session(
                    self.args.bootstrap_config, self.args.bootstrap_state
                )
                self.session.initialize()
                self.execute(f"DROP TABLE {self.args.table} PURGE")
                self.harness.emit("cleanup_drop_table", "teardown", "pass", 0, "dropped throwaway SQL-policy table")
        except (StepFailure, OSError, ValueError) as error:
            self.harness.emit("cleanup_drop_table", "teardown", "fail", 0, str(error))
        finally:
            if self.session is not None:
                self.session.close()
                self.session = None


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--policy-config", required=True)
    parser.add_argument("--policy-state", required=True)
    parser.add_argument("--bootstrap-config", required=True)
    parser.add_argument("--bootstrap-state", required=True)
    parser.add_argument("--schema", required=True)
    parser.add_argument("--table", required=True)
    parser.add_argument("--audit-file", required=True)
    parser.add_argument("--invalid-config", required=True)
    parser.add_argument("--invalid-state", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--server-stderr", required=True)
    args = parser.parse_args()
    for flag, value in (("--schema", args.schema), ("--table", args.table)):
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,29}", value):
            parser.error(f"{flag} must be a safe unquoted Oracle identifier")
    return args


def main():
    args = parse_args()
    harness = Harness(args.evidence)
    scenario = PolicyScenario(args, harness)
    try:
        scenario.run()
    except StepFailure as error:
        harness.emit("sql_policy_session", "assert", "fail", 0, str(error))
        harness.evidence_line("sql_policy_session", "fail", {"error": str(error)})
        return 1
    finally:
        scenario.cleanup()
        harness.close()
    harness.emit("sql_policy_session", "assert", "pass", 0, "served SQL-policy assertions passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
