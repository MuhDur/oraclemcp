#!/usr/bin/env python3
"""Real stdio MCP proof for the default served refusal-corpus writer.

All raw inputs below are intentionally synthetic. The harness writes only
redacted evidence metadata, never the request, corpus payload, configuration,
or server diagnostics, so an e2e artifact cannot become a disclosure channel.
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


def require(condition, description):
    if not condition:
        raise StepFailure(f"assertion failed: {description}")


class Harness:
    """Structured events and sanitized durable evidence."""

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
                    "lane": os.environ.get("E2E_LANE", "served-stdio"),
                    "subject": os.environ.get("E2E_SUBJECT", "test-harness"),
                    "sid": os.environ.get("E2E_SID", str(os.getpid())),
                    "profile": os.environ.get("E2E_PROFILE", "offline"),
                    "level": os.environ.get("E2E_LEVEL", "READ_ONLY"),
                    "grant": "none",
                    "outcome": outcome,
                    "scenario": os.environ.get("E2E_SCENARIO", "refusal_corpus"),
                    "seed": os.environ.get("ORACLEMCP_E2E_SEED", "0"),
                    "message": message,
                },
                separators=(",", ":"),
            ),
            file=sys.stderr,
            flush=True,
        )

    def evidence_line(self, outcome, detail):
        self.evidence.write(
            json.dumps(
                {"ts": now_iso(), "outcome": outcome, "detail": detail}, sort_keys=True
            )
            + "\n"
        )
        self.evidence.flush()

    def close(self):
        self.evidence.close()


class McpSession:
    """One real server process with an isolated, zero-profile configuration."""

    def __init__(self, binary, state_home, server_stderr):
        self.stderr = open(server_stderr, "a", encoding="utf-8")
        self.server_stderr = server_stderr
        state_root = Path(state_home)
        state_root.mkdir(parents=True, exist_ok=True)
        config_home = state_root.parent / "config"
        config_home.mkdir(parents=True, exist_ok=True)
        config_path = config_home / "oraclemcp.toml"
        config_path.write_text("schema_version = 2\n", encoding="utf-8")

        # Do not inherit an operator profile, Oracle credential, DSN, or e2e
        # control variable. The empty config makes the server's normal startup
        # construct its default switchable dispatcher while guaranteeing the
        # refused request cannot target any external database.
        child_env = {
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "LANG", "LC_ALL", "TERM"}
        }
        child_env["HOME"] = str(state_root.parent / "home")
        child_env["XDG_STATE_HOME"] = str(state_root)
        child_env["XDG_CONFIG_HOME"] = str(config_home)
        child_env["ORACLEMCP_CONFIG"] = str(config_path)

        self.proc = subprocess.Popen(
            [binary, "serve", "--allow-no-auth"],
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

    def rpc(self, method, params=None, timeout=30):
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
                raise StepFailure(f"timeout waiting for {method}")
            try:
                line = self.queue.get(timeout=min(remaining, 0.5))
            except queue.Empty:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError as error:
                raise StepFailure("server emitted malformed JSON-RPC") from error
            if message.get("id") == self.request_id:
                return message

    def initialize(self):
        reply = self.rpc(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "oraclemcp-refusal-corpus-e2e", "version": "1"},
            },
        )
        require(
            reply.get("result", {}).get("serverInfo", {}).get("name") == "oraclemcp",
            "served MCP server identifies itself",
        )
        self.proc.stdin.write(
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"
        )
        self.proc.stdin.flush()

    def call(self, tool, arguments):
        reply = self.rpc("tools/call", {"name": tool, "arguments": arguments})
        require("error" not in reply, f"{tool} does not return a JSON-RPC protocol error")
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


# These are intentionally synthetic sentinels. They cover an identifier, a
# bind name/value, and a literal secret without resembling an operator value.
REFUSED_SQL = """
BEGIN
  IF synthetic_corpus_identifier = :synthetic_bind_value
     AND synthetic_guard = 'synthetic-secret-value' THEN
    EXECUTE IMMEDIATE 'DROP TABLE synthetic_corpus_schema.synthetic_corpus_table';
  END IF;
END;
"""
RAW_MARKERS = {
    "identifier": "synthetic_corpus_identifier",
    "qualified_identifier": "synthetic_corpus_schema.synthetic_corpus_table",
    "bind_name": ":synthetic_bind_value",
    "bind_value": "synthetic-bind-secret-value",
    "secret_literal": "synthetic-secret-value",
}


def validate_record(corpus_path):
    raw = corpus_path.read_bytes()
    require(raw.endswith(b"\n"), "corpus record is newline-delimited JSONL")
    lines = [line for line in raw.splitlines() if line]
    require(len(lines) == 1, "default served dispatcher appended exactly one record")
    try:
        record = json.loads(lines[0])
    except json.JSONDecodeError as error:
        raise StepFailure("corpus line is not valid JSON") from error

    require(isinstance(record, dict), "corpus line is a JSON object")
    require(
        set(record).issuperset({"id", "refused_sql_redacted", "refusal_class", "why"}),
        "corpus line carries the public record schema",
    )
    require(
        isinstance(record.get("id"), str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", record["id"]) is not None,
        "corpus record has a content-addressed identifier",
    )
    require(
        all(isinstance(record.get(field), str) for field in ("refused_sql_redacted", "refusal_class", "why")),
        "corpus record text fields are present",
    )

    # `suggest_parameterized_form` can bind the equality literal above, but its
    # candidate still contains EXECUTE IMMEDIATE and is Forbidden. The served
    # writer must therefore drop it rather than storing unsafe advice.
    require(
        record.get("suggested_rewrite_redacted") is None,
        "forbidden suggested rewrite is not persisted",
    )

    lowered = raw.lower()
    for label, marker in RAW_MARKERS.items():
        require(marker.encode("utf-8") not in lowered, f"raw {label} is absent from corpus bytes")

    return {
        "record_count": len(lines),
        "record_id_prefix": record["id"][:7],
        "refusal_class": record["refusal_class"],
        "raw_markers_absent": len(RAW_MARKERS),
        "unsafe_rewrite_persisted": False,
        "corpus_bytes_sha256": hashlib.sha256(raw).hexdigest(),
    }


def run(args):
    harness = Harness(args.evidence)
    started = time.monotonic()
    session = McpSession(args.binary, args.state_home, args.server_stderr)
    try:
        session.initialize()
        result = session.call(
            "oracle_query",
            {
                "sql": REFUSED_SQL,
                "binds": ["synthetic-bind-secret-value"],
            },
        )
        content = result.get("structuredContent")
        require(result.get("isError") is True, "synthetic dynamic SQL is refused")
        require(isinstance(content, dict), "refusal has structured content")
    finally:
        session.close()

    corpus_path = Path(args.state_home) / "oraclemcp" / "corpus" / "refusals.jsonl"
    require(corpus_path.is_file(), "served default dispatcher created its corpus state file")
    detail = validate_record(corpus_path)
    duration_ms = int((time.monotonic() - started) * 1000)
    harness.evidence_line("pass", detail)
    harness.emit(
        "served_refusal_corpus",
        "assert",
        "pass",
        duration_ms,
        "served refusal produced one redacted corpus record without an unsafe rewrite",
    )
    harness.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--state-home", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--server-stderr", required=True)
    args = parser.parse_args()
    try:
        run(args)
    except StepFailure as error:
        print(f"refusal-corpus e2e failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
