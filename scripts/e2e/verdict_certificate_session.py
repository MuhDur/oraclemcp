#!/usr/bin/env python3
"""No-mock live session for the served verdict-certificate E2E scenario.

All SQL, bind, and database connection values are synthetic or supplied only
through the operator's environment. The committed JSON-line event log is
redaction-safe; the private evidence bundle is placed under target/e2e with
mode 0600 solely so the standalone verifier can inspect the exact wire proof.
"""

from __future__ import annotations

import argparse
import copy
import http.client
import json
import os
from pathlib import Path
import resource
import signal
import socket
import subprocess
import sys
import time
from urllib.parse import urlsplit


AUDIT_KEY_ENV = "E2E_VERDICT_CERTIFICATE_AUDIT_KEY"
DB_PASSWORD_ENV = "E2E_VERDICT_CERTIFICATE_DB_PASSWORD"
SAFE_SQL = 'SELECT :1 AS "SYNTHETIC_CERTIFICATE_IDENTIFIER" FROM dual'
SAFE_BIND = "synthetic-certificate-bind-secret"
REPLAY_SQL = "DELETE FROM synthetic_certificate_replay_target WHERE 1 = 0"
# `oraclemcp` is the server's documented, non-secret default marker label.
# Do not set `ORACLEMCP_AGENT_MODEL` here: the strict configuration loader
# correctly treats every `ORACLEMCP_*` environment variable as configuration.
MARKER_MODEL = "oraclemcp"
EXECUTED_SQL = (
    f"/* oraclemcp llm={MARKER_MODEL} profile=verdict_certificate tool=oracle_query */ "
    f"{SAFE_SQL}"
)


class StepFailure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise StepFailure(message)


def private_write(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)


class EvidenceLog:
    def __init__(self, path: Path) -> None:
        self.path = path

    def emit(self, event: str, phase: str, outcome: str, detail: str) -> None:
        line = {
            "event": event,
            "phase": phase,
            "outcome": outcome,
            "scenario": "verdict_certificate",
            "detail": detail,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(line, sort_keys=True) + "\n")


def safe_toml_scalar(label: str, value: str) -> str:
    if not value or any(character in value for character in ("\n", "\r", '"', "\\")):
        raise StepFailure(f"{label} is not safe to place in the ephemeral test TOML")
    return value


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def http_raw(port: int, method: str, path: str, body: dict | None = None, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
    payload = b"" if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    request_headers = {
        "Accept": "application/json, text/event-stream",
        "Host": f"127.0.0.1:{port}",
        "Connection": "close",
    }
    if body is not None:
        request_headers["Content-Type"] = "application/json"
    if headers:
        request_headers.update(headers)
    request = [f"{method} {path} HTTP/1.1"]
    request.extend(f"{name}: {value}" for name, value in request_headers.items())
    request.append(f"Content-Length: {len(payload)}")
    request.append("")
    request.append("")
    wire = "\r\n".join(request).encode("ascii") + payload
    connection = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        connection.settimeout(10)
        connection.sendall(wire)
        connection.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = connection.recv(65_536)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        connection.close()
    raw = b"".join(chunks)
    head, separator, response_body = raw.partition(b"\r\n\r\n")
    require(bool(separator), f"served endpoint returned no HTTP response for {path}")
    lines = head.decode("iso-8859-1").split("\r\n")
    status_parts = lines[0].split()
    require(len(status_parts) >= 2 and status_parts[1].isdigit(), f"served endpoint returned an invalid HTTP status for {path}")
    response_headers = {
        name.strip().lower(): value.strip()
        for line in lines[1:]
        if ":" in line
        for name, value in [line.split(":", 1)]
    }
    return int(status_parts[1]), response_headers, response_body


def decode_json_message(raw: bytes, path: str) -> dict:
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        # Stateful MCP POST replies are SSE-framed even when the server is
        # configured for JSON capability discovery. Decode the last data frame
        # exactly as a real Streamable-HTTP MCP client does.
        frames = []
        for line in raw.decode("utf-8", errors="replace").splitlines():
            if line.startswith("data: ") and line[6:] != "null":
                try:
                    frames.append(json.loads(line[6:]))
                except json.JSONDecodeError:
                    continue
        if not frames:
            raise StepFailure(f"served endpoint returned no JSON message for {path}")
        decoded = frames[-1]
    return decoded


def http_json(port: int, method: str, path: str, body: dict | None = None, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], dict]:
    if path != "/mcp":
        status, response_headers, raw = http_raw(port, method, path, body, headers)
        return status, response_headers, decode_json_message(raw, path)

    payload = b"" if body is None else json.dumps(body, separators=(",", ":")).encode("utf-8")
    request_headers = {
        "Accept": "application/json, text/event-stream",
        "Host": f"127.0.0.1:{port}",
        "Connection": "close",
    }
    if body is not None:
        request_headers["Content-Type"] = "application/json"
    if headers:
        request_headers.update(headers)
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        connection.request(method, path, body=payload, headers=request_headers)
        response = connection.getresponse()
        raw = response.read()
        response_headers = {name.lower(): value for name, value in response.getheaders()}
        return response.status, response_headers, decode_json_message(raw, path)
    finally:
        connection.close()


def limit_audit_file_size() -> None:
    # This is a real OS-enforced write failure, not an audit-sink mock. Ignore
    # SIGXFSZ so Rust receives EFBIG and can return a structured fail-closed MCP
    # response instead of terminating before it can report the refusal.
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024, 1024))
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)


class ServedServer:
    def __init__(
        self,
        binary: Path,
        run_dir: Path,
        config: Path,
        audit_key: str,
        fail_audit_append: bool,
    ) -> None:
        self.port = free_loopback_port()
        # The OS-size-limit failure lane must limit the audit file only. Its
        # normal startup diagnostics can exceed 1 KiB, so send them to the
        # non-regular null device rather than accidentally testing logging.
        self.stdout = None if fail_audit_append else (run_dir / "server.stdout").open("w", encoding="utf-8")
        self.stderr = None if fail_audit_append else (run_dir / "server.stderr").open("w", encoding="utf-8")
        environment = os.environ.copy()
        # This shell-only harness selector is not server configuration. The
        # server's strict `ORACLEMCP_*` config parser must never see it.
        environment.pop("ORACLEMCP_VERDICT_CERTIFICATE_BINARY", None)
        environment["ORACLEMCP_CONFIG"] = str(config)
        environment["XDG_STATE_HOME"] = str(run_dir / "state")
        environment["XDG_RUNTIME_DIR"] = str(run_dir / "runtime")
        environment[DB_PASSWORD_ENV] = os.environ["ORACLEMCP_TEST_PASSWORD"]
        environment[AUDIT_KEY_ENV] = audit_key
        command = [
            str(binary),
            "--json",
            "serve",
            "--listen",
            f"127.0.0.1:{self.port}",
            "--allow-no-auth",
            "--http-stateful",
            "--http-json-response",
            "--profile",
            "verdict_certificate",
        ]
        self.process = subprocess.Popen(
            command,
            cwd=run_dir,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL if self.stdout is None else self.stdout,
            stderr=subprocess.DEVNULL if self.stderr is None else self.stderr,
            env=environment,
            preexec_fn=limit_audit_file_size if fail_audit_append else None,
        )
        self.binary = binary
        self.environment = environment

    def wait_ready(self) -> None:
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise StepFailure("served MCP process exited before it became ready")
            try:
                status, _, _ = http_json(self.port, "GET", "/readyz")
                if status == 200:
                    return
            except (ConnectionError, OSError, http.client.HTTPException, StepFailure):
                pass
            time.sleep(0.1)
        raise StepFailure("served MCP process did not become ready")

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=15)
        if self.stdout is not None:
            self.stdout.close()
        if self.stderr is not None:
            self.stderr.close()

    def dashboard_cookie(self) -> str:
        command = [
            str(self.binary),
            "--json",
            "dashboard",
            "--url",
            f"http://127.0.0.1:{self.port}",
            "--no-open",
        ]
        paired = subprocess.run(
            command,
            cwd=self.environment["XDG_STATE_HOME"],
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
        )
        require(paired.returncode == 0, "local dashboard pairing command must succeed")
        try:
            pairing = json.loads(paired.stdout)
        except json.JSONDecodeError as error:
            raise StepFailure("local dashboard pairing command returned invalid JSON") from error
        pairing_url = pairing.get("url")
        require(isinstance(pairing_url, str), "local dashboard pairing command must return a URL")
        parsed = urlsplit(pairing_url)
        path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        status, headers, _ = http_raw(self.port, "GET", path)
        require(status == 303, "local dashboard pairing URL must set a session cookie")
        cookie = headers.get("set-cookie", "").split(";", 1)[0]
        require(cookie, "local dashboard pairing must return a cookie")
        return cookie


def write_config(path: Path, audit_path: Path, dsn: str, user: str) -> None:
    config = f'''schema_version = 2
default_profile = "verdict_certificate"

[audit]
path = "{audit_path}"
key_id = "verdict-certificate-e2e"
key_ref = "env:{AUDIT_KEY_ENV}"

[[profiles]]
name = "verdict_certificate"
description = "synthetic served verdict-certificate E2E profile"
connect_string = "{dsn}"
username = "{user}"
credential_ref = "env:{DB_PASSWORD_ENV}"
# The active level remains READ_ONLY. The reachable ceiling is READ_WRITE only
# so the production auditor is armed, making the served operator audit-tail
# available for this certificate proof.
max_level = "READ_WRITE"
default_level = "READ_ONLY"
'''
    private_write(path, config)


def initialize(port: int) -> str:
    status, headers, reply = http_json(
        port,
        "POST",
        "/mcp",
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "oraclemcp-verdict-certificate-e2e", "version": "1"},
            },
        },
        {"MCP-Protocol-Version": "2025-11-25"},
    )
    require(status == 200, "served MCP initialize must return HTTP 200")
    require(reply.get("result", {}).get("serverInfo", {}).get("name") == "oraclemcp", "real served MCP server identifies itself")
    session_id = headers.get("mcp-session-id")
    require(isinstance(session_id, str) and session_id, "stateful served MCP initialize must issue a session id")
    return session_id


def tool_call(port: int, session_id: str, request_id: int, name: str, arguments: dict) -> dict:
    status, _, reply = http_json(
        port,
        "POST",
        "/mcp",
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
        {
            "MCP-Protocol-Version": "2025-11-25",
            "Mcp-Session-Id": session_id,
        },
    )
    require(status == 200, f"served MCP {name} call must return HTTP 200")
    require("error" not in reply, f"served MCP {name} must return a tool result, not a JSON-RPC error")
    return reply.get("result", {})


def served_tail_record(port: int, cookie: str) -> dict:
    status, _, response = http_json(
        port,
        "GET",
        "/operator/v1/audit-tail?limit=20",
        headers={"Cookie": cookie},
    )
    require(status == 200, f"served operator audit-tail must return HTTP 200 (received {status})")
    records = response.get("data", {}).get("records")
    require(isinstance(records, list), "served audit-tail must return records")
    for record in records:
        if (
            record.get("tool") == "oracle_query"
            and record.get("outcome") == "SUCCEEDED"
            and isinstance(record.get("verdict_certificate"), dict)
        ):
            return record
    raise StepFailure("served audit-tail did not project a successful certificate-bearing oracle_query record")


def persisted_record(audit_path: Path, entry_hash: str) -> dict:
    raw = audit_path.read_text(encoding="utf-8")
    for line in raw.splitlines():
        if not line:
            continue
        record = json.loads(line)
        if record.get("entry_hash") == entry_hash:
            return record
    raise StepFailure("persisted signed audit record named by served certificate was not found")


def prove_redaction(tail_record: dict) -> None:
    rendered = json.dumps(tail_record, sort_keys=True)
    for forbidden in (
        "SYNTHETIC_CERTIFICATE_IDENTIFIER",
        SAFE_BIND,
        "SELECT :1",
        "FROM dual",
    ):
        require(forbidden not in rendered, "served certificate projection must not expose SQL, binds, or identifiers")
    certificate = tail_record.get("verdict_certificate")
    require(isinstance(certificate, dict), "served audit-tail record carries a proof certificate")
    require(certificate.get("bound_audit_hash") == tail_record.get("proof", {}).get("entry_hash"), "wire certificate is bound to the projected signed record")
    require(certificate.get("stmt_digest") == tail_record.get("sql_sha256"), "wire certificate digest is bound to the projected SQL digest")


def prove_replay_cannot_authorize(server: ServedServer, session_id: str, certificate: dict) -> None:
    forged = copy.deepcopy(certificate)
    derivation = forged.get("derivation")
    require(isinstance(derivation, list) and derivation, "wire certificate must have a derivation to tamper")
    derivation[-1]["construct"] = "final_verdict:FORBIDDEN"
    for request_id, candidate in ((3, certificate), (4, forged)):
        result = tool_call(
            server.port,
            session_id,
            request_id,
            "oracle_execute",
            {
                "sql": REPLAY_SQL,
                "commit": False,
                "verdict_certificate": candidate,
            },
        )
        require(result.get("isError") is True, "a replayed or forged certificate must not widen a destructive request")
        rendered = json.dumps(result, sort_keys=True).lower()
        require("read_write" in rendered, "apply-time classifier and active READ_ONLY ceiling must still govern the destructive request")


def prove_audit_failure_refuses(binary: Path, run_dir: Path, dsn: str, user: str, audit_key: str) -> None:
    failure_dir = run_dir / "audit-append-failure"
    failure_dir.mkdir(mode=0o700)
    config = failure_dir / "profiles.toml"
    audit_path = failure_dir / "audit.jsonl"
    write_config(config, audit_path, dsn, user)
    server = ServedServer(binary, failure_dir, config, audit_key, fail_audit_append=True)
    try:
        server.wait_ready()
        session_id = initialize(server.port)
        result = tool_call(
            server.port,
            session_id,
            9,
            "oracle_query",
            {"sql": SAFE_SQL, "binds": [SAFE_BIND], "max_rows": 1},
        )
        require(result.get("isError") is True, "a real certificate-aware audit append failure must refuse the query")
        require(
            "audit" in json.dumps(result, sort_keys=True).lower(),
            "audit append failure must surface as an audited-path refusal rather than a successful row response",
        )
    finally:
        server.close()


def run(args: argparse.Namespace) -> None:
    run_dir = Path(args.run_dir)
    evidence_path = Path(args.evidence)
    events = EvidenceLog(Path(args.events))
    binary = Path(args.binary)
    dsn = safe_toml_scalar("ORACLEMCP_TEST_DSN", os.environ["ORACLEMCP_TEST_DSN"])
    user = safe_toml_scalar("ORACLEMCP_TEST_USER", os.environ["ORACLEMCP_TEST_USER"])
    audit_key = os.environ[AUDIT_KEY_ENV]
    require(bool(audit_key), "scenario must receive a private generated audit key")
    require(bool(os.environ.get("ORACLEMCP_TEST_PASSWORD")), "scenario must receive the live test password")

    config = run_dir / "profiles.toml"
    audit_path = run_dir / "audit.jsonl"
    write_config(config, audit_path, dsn, user)
    events.emit("served_server", "setup", "running", "starting real loopback MCP server")
    server = ServedServer(binary, run_dir, config, audit_key, fail_audit_append=False)
    try:
        server.wait_ready()
        session_id = initialize(server.port)
        result = tool_call(
            server.port,
            session_id,
            2,
            "oracle_query",
            {"sql": SAFE_SQL, "binds": [SAFE_BIND], "max_rows": 1},
        )
        require(result.get("isError") is False, "real governed oracle_query must return a live result")
        events.emit("live_query", "act", "pass", "served MCP query completed against the live local Oracle")

        operator_cookie = server.dashboard_cookie()
        tail_record = served_tail_record(server.port, operator_cookie)
        prove_redaction(tail_record)
        certificate = tail_record["verdict_certificate"]
        prove_replay_cannot_authorize(server, session_id, certificate)
        persisted = persisted_record(audit_path, tail_record["proof"]["entry_hash"])
        private_write(
            evidence_path,
            json.dumps(
                {
                    # oracle_query classifies and executes its server-marked
                    # text. The private proof input is therefore this exact
                    # synthetic marked statement, never the redacted wire
                    # certificate alone.
                    "sql": EXECUTED_SQL,
                    "certificate": certificate,
                    "audit_record": persisted,
                    "audit_key_id": args.audit_key_id,
                },
                sort_keys=True,
            )
            + "\n",
        )
        events.emit("wire_certificate", "assert", "pass", "served certificate is audit-bound and redacted; replay and forgery cannot authorize")
    finally:
        server.close()

    prove_audit_failure_refuses(binary, run_dir, dsn, user, audit_key)
    events.emit("audit_append_failure", "assert", "pass", "OS-enforced audit append failure returned a fail-closed MCP result")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--events", required=True)
    parser.add_argument("--audit-key-id", required=True)
    args = parser.parse_args()
    try:
        run(args)
    except (KeyError, OSError, http.client.HTTPException, StepFailure, json.JSONDecodeError) as error:
        print(f"verdict-certificate e2e failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
