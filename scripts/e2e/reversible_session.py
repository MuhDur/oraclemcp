#!/usr/bin/env python3
"""Live MCP driver for scripts/e2e/reversible.sh (Arc I — the reversible workspace).

The wrapper supplies one isolated lab profile. This driver creates a disposable
table with one committed baseline row, then proves — through the real MCP stdio
surface, on a real Oracle — the three claims the reversible workspace makes:

  * a named checkpoint plus exploratory DML plus an undo restores the exact
    state, and the held work is never visible outside the session;
  * a dry run shows before/after for a reversible DML and REFUSES a
    sequence-touching one with a cannot-undo label, without advancing it; and
  * committing re-classifies the exact statement — a confirmation carried onto a
    different statement is refused, and the grant is spent exactly once.
  * a READ_ONLY witness observes a commit made after its first read, proving
    each read begins a fresh database-enforced read-only transaction rather
    than retaining Oracle's transaction-level snapshot indefinitely.

Every claim is checked against the committed table read back from a second,
independent session: nothing here trusts the server's own report of itself.
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
                    "ts": now_iso(),
                    "scenario": os.environ.get("E2E_SCENARIO", "reversible"),
                    "event": event,
                    "phase": phase,
                    "outcome": outcome,
                    "duration_ms": duration_ms,
                    "lane": os.environ.get("E2E_LANE", "reversible"),
                    "profile": os.environ.get("E2E_PROFILE", "reversible"),
                    "level": self.level,
                    "grant": self.grant,
                    "message": message,
                }
            ),
            flush=True,
        )

    def evidence_line(self, step, outcome, detail):
        self.evidence.write(
            json.dumps(
                {
                    "ts": now_iso(),
                    "step": step,
                    "outcome": outcome,
                    "detail": detail,
                }
            )
            + "\n"
        )
        self.evidence.flush()

    def close(self):
        self.evidence.close()


class McpSession:
    """One real, long-lived MCP stdio connection to the selected lab lane."""

    def __init__(self, binary, profile, server_stderr, state_home=None):
        self.stderr = open(server_stderr, "a", encoding="utf-8")
        env = dict(os.environ)
        if state_home is not None:
            # A second server needs its own state root: the audit sink takes an
            # exclusive lock on its chain, and two servers must not share one.
            os.makedirs(state_home, exist_ok=True)
            env["XDG_STATE_HOME"] = state_home
        self.proc = subprocess.Popen(
            [binary, "serve", "--profile", profile, "--allow-no-auth"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
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
        except (AttributeError, OSError):
            pass
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=15)
        self.stderr.close()


class Reversible:
    def __init__(self, args, harness):
        self.args = args
        self.harness = harness
        self.session = McpSession(args.binary, args.profile, args.server_stderr)
        # A second, independent connection to the same database. Everything the
        # served session claims about what is and is not committed is checked
        # from here, where only committed data is visible.
        self.witness = McpSession(
            args.binary,
            args.profile,
            args.witness_stderr,
            state_home=args.witness_state,
        )
        self.table = args.table
        self.sequence = f"{args.table}_SEQ"
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

    # --- primitives -------------------------------------------------------

    def query(self, sql, session=None):
        result = (session or self.session).call("oracle_query", {"sql": sql})
        content = structured(result)
        require(result.get("isError") is not True, "oracle_query succeeds", content)
        return content

    def committed_value(self):
        """The row as an INDEPENDENT session sees it — i.e. what is committed."""
        rows = self.query(
            f"SELECT V FROM {self.table} WHERE ID = 1", session=self.witness
        ).get("rows") or []
        return rows[0].get("V") if rows else None

    def refused(self, tool, arguments, expected_class):
        result = self.session.call(tool, arguments)
        content = structured(result)
        require(result.get("isError") is True, f"{tool} is refused", content)
        require(
            content.get("error_class") == expected_class,
            f"{tool} refusal is {expected_class}",
            content,
        )
        return content

    def elevate(self, level):
        preview = structured(
            self.session.call("oracle_set_session_level", {"level": level})
        )
        token = (preview.get("confirmation") or {}).get("confirm")
        require(token, f"{level} elevation preview returns a confirmation grant", preview)
        self.harness.grant = "session-level"
        applied = structured(
            self.session.call(
                "oracle_set_session_level",
                {"level": level, "execute": True, "confirm": token},
            )
        )
        self.harness.grant = "none"
        session = applied.get("session") or {}
        require(
            session.get("current_level") == level,
            f"confirmed elevation reaches {level}",
            applied,
        )
        self.harness.level = level
        return applied

    def confirm_for(self, sql):
        preview = structured(self.session.call("oracle_preview_sql", {"sql": sql}))
        token = (preview.get("execute_confirmation") or {}).get("confirm")
        require(token, "preview returns an execution confirmation grant", preview)
        return token

    def execute(self, sql, session=None):
        """A governed, committed mutation: preview → confirm → commit."""
        target = session or self.session
        preview = structured(target.call("oracle_preview_sql", {"sql": sql}))
        token = (preview.get("execute_confirmation") or {}).get("confirm")
        require(token, "preview returns an execution confirmation grant", preview)
        self.harness.grant = "execute"
        result = target.call(
            "oracle_execute", {"sql": sql, "commit": True, "confirm": token}
        )
        self.harness.grant = "none"
        content = structured(result)
        require(result.get("isError") is not True, "governed mutation succeeds", content)
        require(content.get("executed") is True, "governed mutation was executed", content)
        return content

    # --- the scenario -----------------------------------------------------

    def run(self):
        def initialize():
            reply = self.session.rpc(
                "initialize",
                {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "oraclemcp-reversible-e2e", "version": "1"},
                },
            )
            require("result" in reply, "initialize succeeds", reply)
            self.session.notify("notifications/initialized")
            witness_reply = self.witness.rpc(
                "initialize",
                {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "oraclemcp-reversible-e2e-witness",
                        "version": "1",
                    },
                },
            )
            require("result" in witness_reply, "witness session initializes", witness_reply)
            self.witness.notify("notifications/initialized")
            return {"server": reply["result"].get("serverInfo")}

        def seed():
            self.elevate("DDL")
            self.execute(
                f"CREATE TABLE {self.table} (ID NUMBER PRIMARY KEY, V VARCHAR2(30))"
            )
            self.created = True
            # NOCACHE so the dictionary's LAST_NUMBER tracks the sequence exactly:
            # it is how we prove, from outside, that a refused dry run never
            # advanced it. (Reading SEQ.NEXTVAL would not do — the classifier
            # refuses a "read" that permanently advances a sequence.)
            self.execute(
                f"CREATE SEQUENCE {self.sequence} START WITH 1 INCREMENT BY 1 NOCACHE"
            )
            self.execute(f"INSERT INTO {self.table} (ID, V) VALUES (1, 'baseline')")
            # The witness session needs no elevation: it only reads, and a read is
            # the one thing every profile starts out able to do.
            require(
                self.committed_value() == "baseline",
                "the baseline row is committed and visible to an independent session",
                self.committed_value(),
            )
            return {"table": self.table, "sequence": self.sequence}

        def read_only_witness_refreshes_after_commit():
            # Regression for oraclemcp-8s77. The witness stays at the product's
            # default READ_ONLY level. Its first read opens a database-enforced
            # READ ONLY transaction; the primary session then commits an update;
            # its second read must observe that committed value rather than the
            # original transaction-level snapshot.
            before = self.committed_value()
            require(
                before == "baseline",
                "the READ_ONLY witness sees the initial committed value",
                before,
            )
            self.execute(
                f"UPDATE {self.table} SET V = 'fresh-after-commit' WHERE ID = 1"
            )
            after = self.committed_value()
            require(
                after == "fresh-after-commit",
                "the same READ_ONLY witness observes the later committed value",
                {"before": before, "after": after},
            )
            # Preserve the baseline expected by the Arc-I workspace cases below.
            self.execute(f"UPDATE {self.table} SET V = 'baseline' WHERE ID = 1")
            return {"before": before, "after": after}

        def checkpoint_dml_undo():
            checkpoint = structured(
                self.session.call("oracle_checkpoint", {"name": "before_change"})
            )
            require(
                checkpoint.get("checkpoint") == "BEFORE_CHANGE"
                and (checkpoint.get("workspace") or {}).get("open") is True,
                "oracle_checkpoint opens the reversible workspace",
                checkpoint,
            )

            held = structured(
                self.session.call(
                    "oracle_execute",
                    {
                        "sql": f"UPDATE {self.table} SET V = 'explored' WHERE ID = 1",
                        "hold": True,
                    },
                )
            )
            require(held.get("held") is True, "the DML is held, not rolled back", held)
            require(
                held.get("committed") is False and held.get("rolled_back") is False,
                "held work is neither committed nor rolled back",
                held,
            )

            inside = (self.query(f"SELECT V FROM {self.table} WHERE ID = 1").get("rows") or [])
            require(
                inside and inside[0].get("V") == "explored",
                "the held change is real, uncommitted work in its own session",
                inside,
            )
            require(
                self.committed_value() == "baseline",
                "and is invisible to every other session — it is not committed",
                self.committed_value(),
            )

            undo = structured(
                self.session.call("oracle_undo_to", {"name": "before_change"})
            )
            require(
                undo.get("undone_to") == "BEFORE_CHANGE"
                and undo.get("discarded_statements") == 1,
                "oracle_undo_to walks the held statement back",
                undo,
            )
            restored = (self.query(f"SELECT V FROM {self.table} WHERE ID = 1").get("rows") or [])
            require(
                restored and restored[0].get("V") == "baseline",
                "undo restored the exact prior state",
                restored,
            )

            discarded = structured(self.session.call("oracle_undo_to", {}))
            require(
                (discarded.get("workspace") or {}).get("open") is False,
                "undo with no name discards the whole workspace",
                discarded,
            )
            require(
                self.committed_value() == "baseline",
                "the whole exploration committed nothing",
                self.committed_value(),
            )
            return {"checkpoint": checkpoint, "held": held, "undo": undo}

        def open_workspace_refuses_to_commit():
            self.session.call("oracle_checkpoint", {"name": "cp_commit_guard"})
            self.session.call(
                "oracle_execute",
                {"sql": f"DELETE FROM {self.table} WHERE ID = 1", "hold": True},
            )
            # A COMMIT is transaction-wide: a *different*, fully confirmed
            # statement must not be able to carry the held DELETE into permanence.
            sql = f"UPDATE {self.table} SET V = 'confirmed' WHERE ID = 1"
            token = self.confirm_for(sql)
            refusal = self.refused(
                "oracle_execute",
                {"sql": sql, "commit": True, "confirm": token},
                "POLICY_DENIED",
            )
            require(
                self.committed_value() == "baseline",
                "the refused commit left the committed row untouched",
                self.committed_value(),
            )
            self.session.call("oracle_undo_to", {})
            # The refusal came before the grant was spent, so it still works.
            applied = structured(
                self.session.call(
                    "oracle_execute", {"sql": sql, "commit": True, "confirm": token}
                )
            )
            require(
                applied.get("committed") is True,
                "the unspent grant still commits on a closed workspace",
                applied,
            )
            require(
                self.committed_value() == "confirmed",
                "only the confirmed statement was committed — never the held one",
                self.committed_value(),
            )
            self.execute(f"UPDATE {self.table} SET V = 'baseline' WHERE ID = 1")
            return {"refusal": refusal}

        def dry_run_shows_before_and_after():
            preview = structured(
                self.session.call(
                    "oracle_preview_dml",
                    {
                        "sql": f"UPDATE {self.table} SET V = 'previewed' WHERE ID = 1",
                        "witness": f"SELECT ID, V FROM {self.table} WHERE ID = 1",
                    },
                )
            )
            require(
                preview.get("previewed") is True and preview.get("reversible") is True,
                "a reversible DML is dry-run in the sandbox",
                preview,
            )
            before = ((preview.get("before") or {}).get("rows") or [])
            after = ((preview.get("after") or {}).get("rows") or [])
            require(
                before and before[0].get("V") == "baseline",
                "before: the row as it stood",
                before,
            )
            require(
                after and after[0].get("V") == "previewed",
                "after: the row as the DML would leave it",
                after,
            )
            require(
                self.committed_value() == "baseline",
                "a dry run commits nothing",
                self.committed_value(),
            )
            return {"before": before, "after": after}

        def dry_run_labels_what_it_cannot_undo():
            labeled = structured(
                self.session.call(
                    "oracle_preview_dml",
                    {
                        "sql": (
                            f"INSERT INTO {self.table} (ID, V) "
                            f"VALUES ({self.sequence}.NEXTVAL + 100, 'seq')"
                        )
                    },
                )
            )
            require(
                labeled.get("previewed") is False and labeled.get("reversible") is False,
                "a sequence-touching statement is NOT dry-run",
                labeled,
            )
            require(
                labeled.get("cannot_undo"),
                "and is returned labeled cannot_undo",
                labeled,
            )
            # Proof it was never run, from the sequence itself: the FIRST real
            # use of a NOCACHE sequence that starts at 1 must return 1. If the
            # refused dry run had advanced it "just to show what would happen",
            # this row would land at 102 instead of 101.
            self.execute(
                f"INSERT INTO {self.table} (ID, V) "
                f"VALUES ({self.sequence}.NEXTVAL + 100, 'seq')"
            )
            rows = (
                self.query(
                    f"SELECT ID FROM {self.table} WHERE V = 'seq'", session=self.witness
                ).get("rows")
                or []
            )
            require(
                rows and str(rows[0].get("ID")) == "101",
                "the refused dry run did not advance the sequence: its first real use returned 1",
                rows,
            )
            return {"labeled": labeled, "first_sequence_use": rows}

        def commit_re_classifies():
            reviewed = f"UPDATE {self.table} SET V = 'reviewed' WHERE ID = 1"
            token = self.confirm_for(reviewed)

            # The confirmation is digest-bound: it cannot be carried onto another
            # statement, and the refusal does not spend it.
            self.refused(
                "oracle_execute",
                {
                    "sql": f"DELETE FROM {self.table} WHERE ID = 1",
                    "commit": True,
                    "confirm": token,
                },
                "CHALLENGE_REQUIRED",
            )
            require(
                self.committed_value() == "baseline",
                "the smuggled DELETE never ran",
                self.committed_value(),
            )

            applied = structured(
                self.session.call(
                    "oracle_execute",
                    {"sql": reviewed, "commit": True, "confirm": token},
                )
            )
            require(applied.get("committed") is True, "the reviewed statement commits", applied)

            # Single-use: the same token cannot commit the same change twice.
            self.refused(
                "oracle_execute",
                {"sql": reviewed, "commit": True, "confirm": token},
                "CHALLENGE_REQUIRED",
            )
            require(
                self.committed_value() == "reviewed",
                "the committed table reflects exactly the reviewed statement, once",
                self.committed_value(),
            )
            return {"applied": applied}

        def rollback_preview_labels_a_persistent_effect():
            sql = (
                f"INSERT INTO {self.table} (ID, V) "
                f"VALUES ({self.sequence}.NEXTVAL + 200, 'seq')"
            )
            token = self.confirm_for(sql)
            out = structured(
                self.session.call(
                    "oracle_execute", {"sql": sql, "commit": False, "confirm": token}
                )
            )
            require(
                out.get("rolled_back") is True,
                "the transaction was rolled back",
                out,
            )
            require(
                out.get("fully_reverted") is False and out.get("cannot_undo"),
                "but the response says plainly that the sequence advanced anyway",
                out,
            )
            return {"labeled": out}

        self.step("initialize", initialize)
        self.step("seed_lab_table", seed)
        self.step(
            "read_only_witness_refreshes_after_commit",
            read_only_witness_refreshes_after_commit,
        )
        self.step("checkpoint_dml_undo", checkpoint_dml_undo)
        self.step("open_workspace_refuses_to_commit", open_workspace_refuses_to_commit)
        self.step("dry_run_before_after", dry_run_shows_before_and_after)
        self.step("dry_run_cannot_undo_label", dry_run_labels_what_it_cannot_undo)
        self.step("commit_re_classifies", commit_re_classifies)
        self.step("rollback_preview_cannot_undo_label", rollback_preview_labels_a_persistent_effect)

    def cleanup(self):
        try:
            if self.created:
                self.execute(f"DROP TABLE {self.table} PURGE")
                self.execute(f"DROP SEQUENCE {self.sequence}")
                self.harness.emit(
                    "cleanup_drop_objects",
                    "teardown",
                    "pass",
                    0,
                    "dropped the throwaway reversible-workspace objects",
                )
        except (StepFailure, OSError, ValueError) as exc:
            self.harness.emit(
                "cleanup_drop_objects",
                "teardown",
                "fail",
                0,
                f"governed teardown failed; throwaway objects may remain: {exc}",
            )
        finally:
            self.session.close()
            self.witness.close()


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--table", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--server-stderr", required=True)
    parser.add_argument("--witness-stderr", required=True)
    parser.add_argument("--witness-state", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,25}", args.table):
        parser.error("--table must be a safe unquoted Oracle identifier (<=26 chars)")
    return args


def main():
    args = parse_args()
    harness = Harness(args.evidence)
    scenario = Reversible(args, harness)
    try:
        scenario.run()
    except StepFailure as exc:
        harness.emit("reversible_session", "assert", "fail", 0, str(exc))
        harness.evidence_line("reversible_session", "fail", {"error": str(exc)})
        return 1
    finally:
        scenario.cleanup()
        harness.close()
    harness.emit(
        "reversible_session", "assert", "pass", 0, "reversible-workspace assertions passed"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
