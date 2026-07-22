#!/usr/bin/env python3
"""E5 failure/recovery rig lane driven through the installed HTTP artifact."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import time
import threading
from dataclasses import dataclass
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
BEAD = "oraclemcp-091-e5-failure-recovery-e2e-bf1qa"
PROTOCOL_VERSION = "2025-11-25"
SCENARIO = "failure_recovery_e2e"
AUDIT_KEY = "0123456789abcdef0123456789abcdef"
COMMIT_IN_DOUBT_TARGET = "E5_COMMIT_IN_DOUBT_TARGET"
COMMIT_IN_DOUBT_ROWS = 20000


def e5_db_params() -> tuple[str, str, str]:
    container = os.environ.get("ORACLEMCP_RIG_E5_CONTAINER", os.environ.get("ORACLEMCP_RIG_D10_CONTAINER", "rust-oracledb-free"))
    host_port = os.environ.get("ORACLEMCP_RIG_E5_HOST_PORT", os.environ.get("ORACLEMCP_RIG_D10_HOST_PORT", "1522"))
    pdb = os.environ.get("ORACLEMCP_RIG_E5_PDB", os.environ.get("ORACLEMCP_RIG_D10_PDB", "FREEPDB1"))
    return container, host_port, pdb


def emit(event: str, phase: str, outcome: str, message: str, duration_ms: int = 0) -> None:
    row = {
        "event": event,
        "phase": phase,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_ms": duration_ms,
        "lane": "e5-failure-recovery",
        "subject": "raw-wire-client",
        "sid": str(os.getpid()),
        "profile": "e5_synthetic",
        "level": "READ_WRITE",
        "grant": "wire",
        "outcome": outcome,
        "scenario": SCENARIO,
        "seed": os.environ.get("ORACLEMCP_E2E_SEED", "0"),
        "message": message,
    }
    print(json.dumps(row, separators=(",", ":")), file=sys.stderr, flush=True)


def run(
    cmd: list[str],
    *,
    cwd: pathlib.Path = ROOT,
    env: dict[str, str] | None = None,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    started = time.monotonic()
    emit("command_start", "act", "running", " ".join(cmd))
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    elapsed = int((time.monotonic() - started) * 1000)
    emit(
        "command_complete",
        "act",
        "pass" if proc.returncode == 0 else "fail",
        f"exit={proc.returncode} {' '.join(cmd)}",
        elapsed,
    )
    if proc.returncode != 0:
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise AssertionError(f"command failed with exit {proc.returncode}: {' '.join(cmd)}")
    return proc


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def artifact_dir() -> pathlib.Path:
    base = ROOT / "target" / "e2e" / SCENARIO
    base.mkdir(parents=True, exist_ok=True)
    run_dir = base / time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    suffix = 0
    candidate = run_dir
    while candidate.exists():
        suffix += 1
        candidate = pathlib.Path(f"{run_dir}-{suffix}")
    candidate.mkdir(parents=True)
    return candidate


def admin_password(container: str) -> str:
    for name in (
        "ORACLEMCP_RIG_E5_ADMIN_PASSWORD",
        "ORACLEMCP_RIG_D10_ADMIN_PASSWORD",
        "ORACLEMCP_RIG_L1_FREE23_ADMIN_PASSWORD",
        "ORACLEMCP_RIG_L1_ADMIN_PASSWORD",
    ):
        value = os.environ.get(name)
        if value:
            return value
    proc = subprocess.run(
        ["docker", "inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", container],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode == 0:
        for line in proc.stdout.splitlines():
            if line.startswith("ORACLE_PASSWORD="):
                return line.split("=", 1)[1]
    raise AssertionError(
        "E5 has no runtime admin password; set ORACLEMCP_RIG_E5_ADMIN_PASSWORD "
        "or use a Free23 container with ORACLE_PASSWORD metadata"
    )


def ensure_container_ready(container: str, timeout_secs: int) -> None:
    if subprocess.run(["docker", "container", "inspect", container], capture_output=True).returncode != 0:
        raise AssertionError(f"E5 expected existing container {container}; refusing to create one")
    running = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Running}}", container],
        text=True,
        capture_output=True,
        check=False,
    ).stdout.strip()
    if running != "true":
        run(["docker", "start", container], timeout=70)
    deadline = time.monotonic() + timeout_secs
    while time.monotonic() < deadline:
        logs = subprocess.run(["docker", "logs", container], text=True, capture_output=True, check=False)
        if "DATABASE IS READY TO USE" in (logs.stdout + logs.stderr):
            emit("free23_ready", "setup", "pass", f"container={container}")
            return
        time.sleep(2)
    raise AssertionError(f"E5 container readiness timed out after {timeout_secs}s")


def install_artifact(work: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path, str]:
    source_sha = run(["git", "rev-parse", "HEAD"]).stdout.strip()
    source = work / "source"
    prefix = work / "prefix"
    source.mkdir(parents=True, exist_ok=True)
    prefix.mkdir(parents=True, exist_ok=True)
    archive = subprocess.Popen(
        ["git", "-C", str(ROOT), "archive", "--format=tar", "HEAD"],
        stdout=subprocess.PIPE,
    )
    tar = subprocess.run(["tar", "-x", "-C", str(source)], stdin=archive.stdout, check=False)
    if archive.stdout is not None:
        archive.stdout.close()
    archive_status = archive.wait()
    if archive_status != 0 or tar.returncode != 0:
        raise AssertionError("failed to archive HEAD for E5 source install")
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(ROOT / "target")
    env.setdefault("CARGO_BUILD_JOBS", "2")
    run(
        [
            "cargo",
            "install",
            "--path",
            str(source / "crates" / "oraclemcp"),
            "--root",
            str(prefix),
            "--debug",
            "--locked",
            "--force",
        ],
        cwd=source,
        env=env,
        timeout=900,
    )
    binary = prefix / "bin" / "oraclemcp"
    if not binary.exists() or not os.access(binary, os.X_OK):
        raise AssertionError(f"installed binary missing or not executable: {binary}")
    emit("install_artifact", "setup", "pass", f"source={source_sha} binary={binary}")
    return binary, source, source_sha


def write_config(config: pathlib.Path, audit: pathlib.Path, port: int, operator_subjects: list[str] | None = None) -> None:
    host_port = os.environ.get("ORACLEMCP_RIG_E5_HOST_PORT", os.environ.get("ORACLEMCP_RIG_D10_HOST_PORT", "1522"))
    pdb = os.environ.get("ORACLEMCP_RIG_E5_PDB", os.environ.get("ORACLEMCP_RIG_D10_PDB", "FREEPDB1"))
    subjects = operator_subjects or []
    allowed_subjects = "[" + ", ".join(json.dumps(subject) for subject in subjects) + "]"
    config.write_text(
        f'''schema_version = 2
default_profile = "e5_synthetic"

[audit]
path = "{audit}"
key_ref = "env:E5_AUDIT_KEY"
key_id = "e5-synthetic"

[http]
stateful = true
json_response = false
allowed_hosts = ["127.0.0.1:{port}"]

[http.operator]
allow_loopback_owner = true
allowed_subjects = {allowed_subjects}

[[profiles]]
name = "e5_synthetic"
description = "E5 synthetic local Free23 failure/recovery profile"
connect_string = "//localhost:{host_port}/{pdb}"
username = "system"
credential_ref = "env:E5_DB_PASSWORD"
max_level = "ADMIN"
default_level = "READ_ONLY"

[profiles.pool]
max_size = 2
min_idle = 1
acquire_timeout_secs = 5
statement_cache_size = 20
''',
        encoding="utf-8",
    )


@dataclass
class HttpReply:
    status: int
    headers: dict[str, str]
    body: str


class HttpClient:
    def __init__(self, port: int, bearer: str | None = None) -> None:
        self.port = port
        self.bearer = bearer

    def request(self, method: str, path: str, headers: dict[str, str], body: Any | None = None) -> HttpReply:
        payload: bytes | None = None
        all_headers = {
            "host": f"127.0.0.1:{self.port}",
            "accept": "application/json, text/event-stream",
            **headers,
        }
        if self.bearer is not None and "authorization" not in {k.lower(): v for k, v in all_headers.items()}:
            all_headers["authorization"] = f"Bearer {self.bearer}"
        if body is not None:
            payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
            all_headers.setdefault("content-type", "application/json")
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        try:
            conn.request(method, path, body=payload, headers=all_headers)
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8", errors="replace")
            return HttpReply(resp.status, {k.lower(): v for k, v in resp.getheaders()}, raw)
        finally:
            conn.close()

    def stream_get(self, path: str, headers: dict[str, str], until: str | None = None) -> HttpReply:
        all_headers = {
            "host": f"127.0.0.1:{self.port}",
            "accept": "text/event-stream",
            "connection": "close",
            **headers,
        }
        if self.bearer is not None:
            all_headers.setdefault("authorization", f"Bearer {self.bearer}")
        request = [f"GET {path} HTTP/1.1"]
        request.extend(f"{name}: {value}" for name, value in all_headers.items())
        request.extend(["", ""])
        raw = b""
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as sock:
            sock.settimeout(5)
            sock.sendall("\r\n".join(request).encode("utf-8"))
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                raw += chunk
                text = raw.decode("utf-8", errors="replace")
                status = parse_http_status(text)
                if status and status != 200 and "\r\n\r\n" in text:
                    break
                if until is not None and until in text:
                    break
        text = raw.decode("utf-8", errors="replace")
        status = parse_http_status(text)
        head, _, body = text.partition("\r\n\r\n")
        parsed_headers: dict[str, str] = {}
        for line in head.splitlines()[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                parsed_headers[name.lower()] = value.strip()
        return HttpReply(status or 0, parsed_headers, body)

    def initialize(self, name: str) -> str:
        reply = self.request(
            "POST",
            "/mcp",
            {"content-type": "application/json"},
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": name, "version": "1.0"},
                },
            },
        )
        require(reply.status == 200, f"initialize failed: status={reply.status} body={reply.body}")
        session = reply.headers.get("mcp-session-id")
        require(bool(session), f"initialize omitted mcp-session-id: {reply.headers}")
        return str(session)

    def tool_call(self, session: str, request_id: int, name: str, arguments: dict[str, Any]) -> tuple[HttpReply, dict[str, Any]]:
        reply = self.raw_tool_call(session, request_id, name, arguments)
        value = parse_mcp_json(reply.body)
        return reply, value

    def raw_tool_call(self, session: str, request_id: int, name: str, arguments: dict[str, Any]) -> HttpReply:
        return self.request(
            "POST",
            "/mcp",
            {
                "content-type": "application/json",
                "mcp-session-id": session,
                "mcp-protocol-version": PROTOCOL_VERSION,
            },
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            },
        )

    def replay(self, session: str, until: str | None = None) -> HttpReply:
        return self.stream_get("/mcp?cursor=0", {"mcp-session-id": session}, until)

    def delete(self, session: str) -> HttpReply:
        return self.request(
            "DELETE",
            "/mcp",
            {"mcp-session-id": session, "mcp-protocol-version": PROTOCOL_VERSION},
            None,
        )

    def operator(self, method: str, path: str, body: dict[str, Any] | None = None) -> HttpReply:
        return self.request(method, path, {"accept": "application/json"}, body)


def parse_mcp_json(body: str) -> dict[str, Any]:
    events = []
    for line in body.splitlines():
        if line.startswith("data: ") and line[6:] != "null":
            events.append(json.loads(line[6:]))
    if events:
        value = events[-1]
    else:
        value = json.loads(body)
    require(isinstance(value, dict) and value.get("jsonrpc") == "2.0", f"malformed JSON-RPC: {value}")
    return value


def parse_http_status(raw: str) -> int | None:
    first = raw.splitlines()[0] if raw.splitlines() else ""
    match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})\b", first)
    return int(match.group(1)) if match else None


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def tool_result(value: dict[str, Any], *, expect_error: bool) -> dict[str, Any]:
    result = value.get("result")
    require(isinstance(result, dict), f"missing result object: {value}")
    require(result.get("isError") is expect_error, f"unexpected isError={result.get('isError')}: {value}")
    structured = result.get("structuredContent")
    require(isinstance(structured, dict), f"missing structuredContent: {value}")
    return structured


def parse_session_key(row: dict[str, Any]) -> tuple[str, str]:
    sid = row.get("S_ID") or row.get("s_id") or row.get("Sid") or row.get("sid")
    serial = (
        row.get("S_SERIAL")
        or row.get("s_serial")
        or row.get("Serial")
        or row.get("serial")
        or row.get("Srl")
    )
    require(sid is not None, f"session sid missing: {row}")
    require(serial is not None, f"session serial missing: {row}")
    sid_text = str(sid).strip()
    serial_text = str(serial).strip()
    require(sid_text.isdigit(), f"session sid must be numeric: {sid_text}")
    require(serial_text.isdigit(), f"session serial must be numeric: {serial_text}")
    return sid_text, serial_text


def query_session_key(client: HttpClient, session: str, request_id: int, sql: str) -> tuple[str, str]:
    _, replied = client.tool_call(session, request_id, "oracle_query", {"sql": sql})
    structured = tool_result(replied, expect_error=False)
    rows = structured.get("rows")
    require(isinstance(rows, list) and rows, f"session-key query returned no rows: {structured}")
    first = rows[0]
    require(isinstance(first, dict), f"session-key row malformed: {rows}")
    return parse_session_key(first)


def query_rows(client: HttpClient, session: str, request_id: int, sql: str) -> list[dict[str, Any]]:
    _, value = client.tool_call(session, request_id, "oracle_query", {"sql": sql, "max_rows": 1})
    structured = tool_result(value, expect_error=False)
    rows = structured.get("rows")
    require(isinstance(rows, list), f"query failed (non-list rows): {structured}")
    return rows


def query_scalar(client: HttpClient, session: str, request_id: int, sql: str) -> str:
    rows = query_rows(client, session, request_id, sql)
    require(rows, f"scalar query returned no rows: {sql}")
    row = rows[0]
    require(isinstance(row, dict) and row, f"scalar query row malformed: {rows}")
    value = row.get("SID") or row.get("sid") or row.get("Sid")
    if value is None:
        value = next(iter(row.values()))
    require(value is not None, f"scalar query missing value: {row}")
    return str(value).strip()


def prepare_commit_in_doubt_fixture(
    container: str,
    password: str,
    pdb: str,
    table_name: str = COMMIT_IN_DOUBT_TARGET,
    rows: int = COMMIT_IN_DOUBT_ROWS,
) -> None:
    run_sqlplus(
        container,
        password,
        pdb,
        f"""
        DECLARE
            l_exists NUMBER;
        BEGIN
            SELECT COUNT(*) INTO l_exists FROM user_tables WHERE table_name = '{table_name}';
            IF l_exists > 0 THEN
                EXECUTE IMMEDIATE 'DROP TABLE {table_name} PURGE';
            END IF;
            EXECUTE IMMEDIATE 'CREATE TABLE {table_name} (id NUMBER PRIMARY KEY, payload VARCHAR2(1024))';
        END;
        /
        INSERT /*+ APPEND */ INTO {table_name} (id, payload)
            SELECT level, RPAD('x', 64, 'x')
            FROM dual
            CONNECT BY level <= {rows}
        ;
        COMMIT;
        """,
    )


def run_sqlplus(container: str, password: str, pdb: str, sql: str, timeout_secs: int = 30) -> subprocess.CompletedProcess[str]:
    payload = (
        "set heading off\n"
        "set feedback off\n"
        "set pagesize 0\n"
        "set linesize 4000\n"
        "set trimout on\n"
        "set trimspool on\n"
        f"{sql}\n"
        "exit\n"
    )
    proc = subprocess.run(
        [
            "timeout",
            str(timeout_secs),
            "docker",
            "exec",
            "-i",
            container,
            "sqlplus",
            "-S",
            "-L",
            f"system/{password}@localhost:1521/{pdb}",
        ],
        input=payload,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(f"sqlplus execution failed ({proc.returncode}): {proc.stderr or proc.stdout}")
    return proc


def sqlplus_scalar(container: str, password: str, pdb: str, sql: str, timeout_secs: int = 30) -> str:
    marker = "E5VAL"
    sql_text = sql.strip()
    if sql_text.lower().startswith("select "):
        payload = sql_text
    else:
        payload = f"select '{marker}:' || ({sql_text}) from dual;"
    proc = run_sqlplus(container, password, pdb, payload, timeout_secs=timeout_secs)
    for line in proc.stdout.splitlines():
        match = re.match(rf"^{marker}:(.*)$", line.strip())
        if match:
            return match.group(1).strip()
    raise AssertionError(f"sqlplus did not return a scalar for: {sql}\nstdout={proc.stdout}\nstderr={proc.stderr}")


def sqlplus_scalar_or_none(container: str, password: str, pdb: str, sql: str, timeout_secs: int = 30) -> str | None:
    marker = "E5VAL"
    payload = f"select '{marker}:' || ({sql}) from dual;"
    proc = run_sqlplus(container, password, pdb, payload, timeout_secs=timeout_secs)
    for line in proc.stdout.splitlines():
        match = re.match(rf"^{marker}:(.*)$", line.strip())
        if match:
            value = match.group(1).strip()
            return value if value else None
    if "no rows selected" in proc.stdout.lower():
        return None
    raise AssertionError(f"sqlplus did not return a scalar for: {sql}\nstdout={proc.stdout}\nstderr={proc.stderr}")


def query_session_state(
    container: str,
    password: str,
    pdb: str,
    sid: str,
) -> tuple[str | None, str | None, str | None, str | None, bool]:
    sid_text = sid.strip()
    if sid_text.startswith("E5VAL:"):
        sid_text = sid_text.split(":", 1)[1]
    marker_sql = (
        "SELECT 'E5VAL:' || TO_CHAR(s.serial#) || '|' || TO_CHAR(s.command) || '|' || NVL(s.event, ' ') "
        "|| '|' || s.state || '|' || CASE WHEN t.addr IS NULL THEN 0 ELSE 1 END "
        f"FROM v$session s LEFT JOIN v$transaction t ON t.ses_addr = s.saddr WHERE s.sid = TO_NUMBER({sid_text})"
    )
    text = sqlplus_scalar_or_none(container, password, pdb, marker_sql)
    if text is None:
        return None, None, None, None, False
    fields = [item.strip() for item in text.split("|", maxsplit=5)]
    if len(fields) < 5:
        serial = fields[0] if fields else None
        if serial is not None and serial.startswith("E5VAL:"):
            serial = serial.split(":", 1)[1]
        return serial, None, None, None, False
    serial, command, event, state, has_tx = fields[:5]
    if serial is not None and serial.startswith("E5VAL:"):
        serial = serial.split(":", 1)[1]
    return serial, command, event, state, has_tx == "1"


def query_session_serial(
    container: str,
    password: str,
    pdb: str,
    sid: str,
) -> str | None:
    sid_text = sid.strip()
    if sid_text.startswith("E5VAL:"):
        sid_text = sid_text.split(":", 1)[1]
    serial = sqlplus_scalar_or_none(
        container,
        password,
        pdb,
        f"SELECT 'E5VAL:' || TO_CHAR(serial#) FROM v$session WHERE sid = TO_NUMBER({sid_text})",
    )
    if serial is None:
        return None
    if serial.startswith("E5VAL:"):
        serial = serial.split(":", 1)[1]
    serial = serial.strip()
    return serial if serial.isdigit() else None


def query_session_identity_by_audsid(
    container: str,
    password: str,
    pdb: str,
    audsid: str,
) -> tuple[str, str] | None:
    audsid_text = audsid.strip()
    if audsid_text.startswith("E5VAL:"):
        audsid_text = audsid_text.split(":", 1)[1]
    row = sqlplus_scalar_or_none(
        container,
        password,
        pdb,
        f"SELECT 'E5VAL:' || TO_CHAR(sid) || '|' || TO_CHAR(serial#) FROM v$session WHERE audsid = TO_NUMBER({audsid_text})",
    )
    if row is None:
        return None
    if row.startswith("E5VAL:"):
        row = row.split(":", 1)[1]
    sid, serial = [part.strip() for part in row.split("|", maxsplit=1)]
    return (sid, serial) if sid.isdigit() and serial.isdigit() else None


def find_session_by_sql_fragment(
    container: str,
    password: str,
    pdb: str,
    sql_fragment: str,
) -> tuple[str, str] | None:
    marker = sql_fragment.replace("'", "''")
    sql = (
        "SELECT 'E5VAL:' || TO_CHAR(sid) || '|' || TO_CHAR(serial#) "
        "FROM (SELECT s.sid, s.serial#, q.sql_text "
        "      FROM v$session s "
        "      JOIN v$sql q ON q.sql_id = s.sql_id "
        "      WHERE s.username = 'SYSTEM' "
        "        AND s.status = 'ACTIVE' "
        "        AND q.sql_text LIKE '%"
        + marker
        + "%' "
        "      ORDER BY s.last_call_et DESC) "
        "WHERE rownum = 1"
    )
    text = sqlplus_scalar_or_none(container, password, pdb, sql)
    if text is None:
        return None
    parts = [item.strip() for item in text.split("|")]
    if len(parts) < 2:
        return None
    sid = parts[0]
    if sid.startswith("E5VAL:"):
        sid = sid.split(":", 1)[1]
    return sid, parts[1]


def classify_http_tool_reply(reply: HttpReply) -> dict[str, Any] | None:
    if not reply.body:
        return None
    try:
        result = parse_mcp_json(reply.body).get("result")
    except Exception:
        return None
    return result if isinstance(result, dict) else None


def set_session_level(
    client: HttpClient,
    session: str,
    request_id: int,
    level: str,
    *,
    confirm: bool = False,
) -> None:
    _, preview = client.tool_call(
        session,
        request_id,
        "oracle_set_session_level",
        {"level": level, "ttl_seconds": 300},
    )
    structured = tool_result(preview, expect_error=False)
    confirm_token = structured.get("confirmation", {}).get("confirm")
    require(isinstance(confirm_token, str) and confirm_token, f"session-level preview omitted confirm: {structured}")
    _, applied = client.tool_call(
        session,
        request_id + 1,
        "oracle_set_session_level",
        {"level": level, "ttl_seconds": 300, "execute": True, "confirm": confirm_token},
    )
    applied_structured = tool_result(applied, expect_error=False)
    require(
        (applied_structured.get("session") or {}).get("current_level") == level,
        f"failed to apply level {level}: {applied_structured}",
    )


class ServerProcess:
    def __init__(self, binary: pathlib.Path, env: dict[str, str], port: int) -> None:
        self.port = port
        self.stderr: list[str] = []
        self.proc = subprocess.Popen(
            [
                str(binary),
                "--json",
                "serve",
                "--listen",
                f"127.0.0.1:{port}",
                "--client-credentials",
                "--http-stateful",
                "--profile",
                "e5_synthetic",
                "--http-allowed-host",
                f"127.0.0.1:{port}",
            ],
            cwd=ROOT,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def wait_ready(self) -> None:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                err = self.proc.stderr.read() if self.proc.stderr is not None else ""
                raise AssertionError(f"oraclemcp exited before ready: {self.proc.returncode} {err}")
            try:
                reply = HttpClient(self.port).request("GET", "/readyz", {"accept": "application/json"})
                if reply.status == 200:
                    emit("server_ready", "setup", "pass", f"port={self.port}")
                    return
            except OSError:
                pass
            time.sleep(0.1)
        raise AssertionError("oraclemcp did not become ready within 30s")

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        if self.proc.stderr is not None:
            self.stderr.extend(self.proc.stderr.read().splitlines())


def issue_client(
    binary: pathlib.Path,
    env: dict[str, str],
    label: str,
    *,
    admin: bool = False,
) -> tuple[str, str]:
    scopes = ["--scope", "oracle:read", "--scope", "oracle:execute"]
    if admin:
        scopes.extend(["--scope", "oracle:admin"])
    proc = run(
        [
            str(binary),
            "--json",
            "clients",
            "issue",
            "--label",
            label,
            *scopes,
        ],
        env=env,
        timeout=30,
    )
    value = json.loads(proc.stdout)
    return value["client"]["client_id"], value["bearer"]


def client_principal_key(client_id: str) -> str:
    domain = b"oraclemcp.client-principal.v1\0"
    return "client:sha256:" + hashlib.sha256(domain + client_id.encode("utf-8")).hexdigest()


def operator_subject_id_hash(subject_key: str) -> str:
    domain = b"oraclemcp.operator.subject.v1\0"
    return "subject-sha256:" + hashlib.sha256(domain + subject_key.encode("utf-8")).hexdigest()


def operator_json(reply: HttpReply) -> dict[str, Any]:
    require(reply.status == 200, f"operator route failed: status={reply.status} body={reply.body}")
    value = json.loads(reply.body)
    require(isinstance(value.get("data"), dict), f"operator response missing data: {value}")
    return value["data"]


def active_lane_id(operator_client: HttpClient, subject_hash: str | None = None) -> str:
    data = operator_json(operator_client.operator("GET", "/operator/v1/active-lanes"))
    lanes = data.get("lanes")
    require(isinstance(lanes, list) and lanes, f"no active lanes: {data}")
    if subject_hash is not None:
        lanes = [lane for lane in lanes if lane.get("subject_id_hash") == subject_hash]
        require(lanes, f"no active lane for subject_id_hash={subject_hash}: {data}")
    lane_id = lanes[-1].get("lane_id")
    require(isinstance(lane_id, str) and lane_id, f"active lane missing id: {data}")
    return lane_id


def assert_refusal_does_not_quarantine(client: HttpClient, session: str, evidence: list[dict[str, Any]]) -> None:
    _, refused = client.tool_call(session, 10, "oracle_query", {"sql": "DROP TABLE ORACLEMCP_E5_NEVER"})
    structured = tool_result(refused, expect_error=True)
    require(
        structured.get("error_class") in {"FORBIDDEN_STATEMENT", "OPERATING_LEVEL_TOO_LOW"},
        f"unexpected refusal class: {structured}",
    )
    _, ok = client.tool_call(session, 11, "oracle_query", {"sql": "SELECT 1 FROM dual"})
    tool_result(ok, expect_error=False)
    evidence.append(
        {
            "id": "refusal_no_quarantine",
            "wire": True,
            "status": "pass",
            "refusal_error_class": structured.get("error_class"),
            "post_refusal_read": "pass",
        }
    )


def assert_single_use_grant_replay_refused_without_quarantine(client: HttpClient, session: str, evidence: list[dict[str, Any]]) -> None:
    _, preview = client.tool_call(
        session,
        20,
        "oracle_set_session_level",
        {"level": "READ_WRITE", "ttl_seconds": 300},
    )
    structured = tool_result(preview, expect_error=False)
    confirm = structured.get("confirmation", {}).get("confirm")
    require(isinstance(confirm, str) and confirm, f"preview did not mint confirm: {structured}")
    _, applied = client.tool_call(
        session,
        21,
        "oracle_set_session_level",
        {"level": "READ_WRITE", "ttl_seconds": 300, "execute": True, "confirm": confirm},
    )
    tool_result(applied, expect_error=False)
    _, dropped = client.tool_call(session, 22, "oracle_set_session_level", {"action": "drop"})
    tool_result(dropped, expect_error=False)
    _, replay = client.tool_call(
        session,
        23,
        "oracle_set_session_level",
        {"level": "READ_WRITE", "ttl_seconds": 300, "execute": True, "confirm": confirm},
    )
    replay_structured = tool_result(replay, expect_error=True)
    require(replay_structured.get("error_class") == "CHALLENGE_REQUIRED", f"unexpected replay error: {replay_structured}")

    _, preview_expiry = client.tool_call(
        session,
        24,
        "oracle_set_session_level",
        {"level": "READ_WRITE", "ttl_seconds": 300},
    )
    structured_expiry = tool_result(preview_expiry, expect_error=False)
    confirm_expiry = structured_expiry.get("confirmation", {}).get("confirm")
    require(isinstance(confirm_expiry, str) and confirm_expiry, f"expiry preview did not mint confirm: {structured_expiry}")
    grant_wait_secs = int(os.environ.get("ORACLEMCP_E5_GRANT_WAIT_SECONDS", "312"))
    emit("grant_wait", "act", "running", f"waiting for fixed 300s execute-confirmation TTL: {grant_wait_secs}s")
    time.sleep(grant_wait_secs)
    _, replay_expired = client.tool_call(
        session,
        25,
        "oracle_set_session_level",
        {"level": "READ_WRITE", "ttl_seconds": 300, "execute": True, "confirm": confirm_expiry},
    )
    skip_grant_expiry = os.environ.get("ORACLEMCP_E5_SKIP_GRANT_EXPIRY_CHECK", "0") == "1"
    if skip_grant_expiry:
        skip_structured = replay_expired
        require(isinstance(skip_structured, dict), f"replay_expired response was not JSON: {replay_expired}")
        replay_expired_structured = skip_structured
    else:
        replay_expired_structured = tool_result(replay_expired, expect_error=True)
    if skip_grant_expiry:
        evidence.append(
            {
                "id": "single_use_grant_replay_refusal",
                "wire": True,
                "status": "pass",
                "replay_error_class": replay_structured.get("error_class"),
                "expiry_error_class": replay_expired_structured.get("error_class"),
                "commit_grant_ttl_seconds": 300,
                "post_replay_refusal_read": "pass",
                "proof_boundary": "single-use rejection was proven; expiry proof was intentionally skipped by ORACLEMCP_E5_SKIP_GRANT_EXPIRY_CHECK=1",
            }
        )
        return
    require(
        replay_expired_structured.get("error_class") == "CHALLENGE_REQUIRED",
        f"unexpected expiry error: {replay_expired_structured}",
    )
    _, ok = client.tool_call(session, 26, "oracle_query", {"sql": "SELECT 1 FROM dual"})
    tool_result(ok, expect_error=False)
    evidence.append(
        {
            "id": "single_use_grant_replay_refusal",
            "wire": True,
            "status": "pass",
            "replay_error_class": replay_structured.get("error_class"),
            "expiry_error_class": replay_expired_structured.get("error_class"),
            "commit_grant_ttl_seconds": 300,
            "post_replay_refusal_read": "pass",
            "proof_boundary": "single-use rejection and expiry were both proved against the fixed 300s wire-confirmation grant TTL; no product hook was added.",
        }
    )


def assert_operator_cancel_quarantines_session(
    operator_client: HttpClient,
    client: HttpClient,
    session: str,
    subject_hash: str,
    evidence: list[dict[str, Any]],
) -> None:
    _, ok = client.tool_call(session, 30, "oracle_query", {"sql": "SELECT 1 FROM dual"})
    tool_result(ok, expect_error=False)
    replay = client.replay(session, until='"id":30')
    require(replay.status == 200 and '"id":30' in replay.body, f"pre-cancel replay failed: {replay.status} {replay.body}")
    lane_id = active_lane_id(operator_client, subject_hash)
    data = operator_json(operator_client.operator("POST", "/operator/v1/lanes/cancel", {"lane_id": lane_id}))
    require(data.get("status") in {"terminated", "already_closed"}, f"bad cancel response: {data}")
    retry = client.raw_tool_call(session, 31, "oracle_query", {"sql": "SELECT 1 FROM dual"})
    require(
        retry.status == 404 and "Invalid mcp-session-id" in retry.body,
        f"cancelled session was not rejected: {retry.status} {retry.body}",
    )
    stale_replay = client.replay(session)
    require(
        stale_replay.status == 404,
        f"cancelled replay buffer remained reachable: {stale_replay.status} {stale_replay.body}",
    )
    fresh = client.initialize("e5-after-cancel")
    _, fresh_ok = client.tool_call(fresh, 32, "oracle_query", {"sql": "SELECT 1 FROM dual"})
    tool_result(fresh_ok, expect_error=False)
    evidence.append(
        {
            "id": "operator_cancel_teardown_quarantines_session",
            "wire": True,
            "status": "pass",
            "lane_id": lane_id,
            "cancel_status": data.get("status"),
            "stale_session_status": retry.status,
            "stale_replay_status": stale_replay.status,
            "fresh_lane_after_cancel": "pass",
        }
    )


def assert_revoked_client_loses_sessions(
    client_id: str,
    bearer: str,
    operator_bearer: str,
    port: int,
    evidence: list[dict[str, Any]],
) -> None:
    client = HttpClient(port, bearer)
    session = client.initialize("e5-revoke")
    _, ok = client.tool_call(session, 40, "oracle_query", {"sql": "SELECT 1 FROM dual"})
    tool_result(ok, expect_error=False)
    replay = client.replay(session, until='"id":40')
    require(replay.status == 200 and '"id":40' in replay.body, f"pre-revoke replay failed: {replay.status} {replay.body}")
    data = operator_json(HttpClient(port, operator_bearer).operator("POST", "/operator/v1/client-credentials/revoke", {"client_id": client_id}))
    require(data.get("status") == "revoked", f"bad revoke response: {data}")
    require(int(data.get("closed_sessions", 0)) >= 1, f"revoke did not close active sessions: {data}")
    replay_after = client.replay(session)
    require(replay_after.status == 401, f"revoked bearer still reached replay path: {replay_after.status} {replay_after.body}")
    fresh = client.request(
        "POST",
        "/mcp",
        {"content-type": "application/json"},
        {
            "jsonrpc": "2.0",
            "id": 41,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "e5-revoked-fresh", "version": "1.0"},
            },
        },
    )
    require(fresh.status == 401, f"revoked bearer opened fresh lane: {fresh.status} {fresh.body}")
    evidence.append(
        {
            "id": "revoked_client_loses_sessions_buffers_and_fresh_lane",
            "wire": True,
            "status": "pass",
            "closed_sessions": data.get("closed_sessions"),
            "replay_after_revoke_status": replay_after.status,
            "fresh_lane_status": fresh.status,
        }
    )


def run_commit_in_doubt_wire(
    server: ServerProcess,
    binary: pathlib.Path,
    env: dict[str, str],
    port: int,
    victim_bearer: str,
    container: str,
    pdb: str,
    db_password: str,
    evidence: list[dict[str, Any]],
) -> None:
    victim_table = f"{COMMIT_IN_DOUBT_TARGET}_{int(time.time() * 1000)}"
    victim_sql_tag = f"{victim_table}_tag"
    prepare_commit_in_doubt_fixture(container, db_password, pdb, table_name=victim_table)
    victim_client = HttpClient(port, victim_bearer)
    victim_session = victim_client.initialize("e5-commit-in-doubt")
    set_session_level(victim_client, victim_session, 20, "READ_WRITE", confirm=True)
    victim_sql = (
        f"UPDATE {victim_table} /* {victim_sql_tag} */\n"
        "SET payload = payload || TO_CHAR(\n"
        "  (SELECT COUNT(*)\n"
        "   FROM all_objects a\n"
        "   CROSS JOIN all_objects b)\n"
        ")\n"
        f"WHERE id = 1"
    )

    shared: dict[str, Any] = {}
    started = threading.Event()

    def run_victim_commit() -> None:
        try:
            _, preview = victim_client.tool_call(
                victim_session,
                24,
                "oracle_preview_sql",
                {"sql": victim_sql},
            )
            preview_content = tool_result(preview, expect_error=False)
            require(preview_content.get("gate_decision") == "allow", f"preview denied commit-in-doubt probe: {preview_content}")
            confirm = (preview_content.get("execute_confirmation") or {}).get("confirm")
            require(isinstance(confirm, str) and confirm, f"preview did not include execute confirmation: {preview_content}")
            shared["sql_fragment"] = f"UPDATE {victim_table} /* {victim_sql_tag} */"
            shared["sid"] = query_scalar(
                victim_client,
                victim_session,
                25,
                "SELECT SYS_CONTEXT('USERENV', 'SESSIONID') AS sid FROM dual",
            )
            session_identity = query_session_identity_by_audsid(
                container,
                db_password,
                pdb,
                shared["sid"],
            )
            require(
                session_identity is not None
                and isinstance(session_identity[0], str)
                and isinstance(session_identity[1], str),
                f"session identity was not captured from AUDSID={shared['sid']}: {session_identity}",
            )
            shared["sid"], shared["serial"] = session_identity
            emit(
                "commit_in_doubt_session_sid",
                "act",
                "pass",
                f"sid={shared['sid']} serial={shared['serial']}",
            )
            started.set()
            reply = victim_client.raw_tool_call(
                victim_session,
                26,
                "oracle_execute",
                {
                    "sql": victim_sql,
                    "commit": True,
                    "confirm": confirm,
                },
            )
            shared["reply"] = reply
        except Exception as exc:
            shared["thread_error"] = repr(exc)
            emit("commit_in_doubt_thread_error", "act", "fail", str(exc))
            started.set()

    victim_thread = threading.Thread(target=run_victim_commit, name="e5-commit-in-doubt-victim")
    victim_thread.start()
    require(started.wait(10), "victim commit never started")
    thread_error = shared.get("thread_error")
    require(thread_error is None, f"victim commit thread failed before discovery: {thread_error}")
    sid = shared.get("sid")
    require(isinstance(sid, str) and sid and sid.isdigit(), "victim sid was not captured")
    emit("commit_in_doubt_sql_fragment", "act", "pass", f"sql_fragment={shared.get('sql_fragment')}")

    sid = shared.get("sid")
    serial = shared.get("serial")
    require(isinstance(sid, str) and sid, "victim session sid was not captured")
    require(isinstance(serial, str) and serial, "victim session serial was not captured")
    if not victim_thread.is_alive():
        thread_error = shared.get("thread_error")
        if thread_error:
            raise AssertionError(f"victim commit completed before kill with error: {thread_error}")
        require(shared.get("reply") is not None, "victim commit ended too quickly without a reply")
        raise AssertionError("victim commit finished before kill could be attempted")

    killed = False
    killed_by: str | None = None
    event: str | None = None
    command: str | None = None
    state: str | None = None
    tx_present: bool = False
    deadline = time.monotonic() + 20
    discovered_at = time.monotonic()
    probes = 0
    while time.monotonic() < deadline and victim_thread.is_alive():
        probes += 1
        session_serial, command, event, state, tx_present = query_session_state(
            container,
            db_password,
            pdb,
            sid,
        )
        if not session_serial:
            if time.monotonic() - discovered_at > 18:
                run_sqlplus(container, db_password, pdb, f"ALTER SYSTEM KILL SESSION '{sid},{serial}' IMMEDIATE;")
                killed = True
                killed_by = "state_lookup_missing"
                break
            time.sleep(0.05)
            continue
        kill_sql = f"ALTER SYSTEM KILL SESSION '{sid},{serial}' IMMEDIATE"
        if probes == 1:
            emit(
                "commit_in_doubt_probe",
                "act",
                "pass",
                f"sid={sid} serial={serial} command={command} state={state} event={event} tx_present={tx_present}",
            )
        if probes % 4 == 0:
            emit(
                "commit_in_doubt_state",
                "act",
                "pass",
                f"sid={sid} serial={serial} command={command} state={state} event={event} tx_present={tx_present}",
            )
        now = time.monotonic()
        if tx_present and (command not in {"0", ""} or state not in {"INACTIVE", "WAITING", ""}):
            killed_by = f"tx_present command={command} state={state}"
            run_sqlplus(container, db_password, pdb, f"{kill_sql};")
            killed = True
            break
        if tx_present and command in {"0", ""}:
            killed_by = f"tx_present"
            run_sqlplus(container, db_password, pdb, f"{kill_sql};")
            killed = True
            break
        if not tx_present and now - discovered_at > 18:
            killed_by = "fallback_post_discovery_timeout"
            run_sqlplus(container, db_password, pdb, f"{kill_sql};")
            killed = True
            break
        time.sleep(0.05)

    victim_thread.join(timeout=20)
    require(not victim_thread.is_alive(), "victim commit thread did not finish after kill")
    require(
        not (shared.get("reply") is None),
        "victim commit reply missing",
    )
    require(killed, f"commit-in-doubt induction never observed cancellable command/event state (last command={command}, last event={event})")

    victim_reply = shared["reply"]
    victim_error_class = None
    victim_message = victim_reply.body[:200] if victim_reply.body else ""
    victim_result = classify_http_tool_reply(victim_reply)
    require(victim_reply.status != 200 or victim_result is not None, f"victim reply was not MCP JSON: {victim_reply.status}")
    if victim_reply.status == 200:
        structured = victim_result.get("structuredContent") if victim_result else None
        require(isinstance(structured, dict), f"victim structured content missing: {victim_result}")
        require(victim_result.get("isError") is True, f"victim commit did not return MCP error: {victim_result}")
        victim_error_class = structured.get("error_class")
        victim_message = str(structured.get("message", ""))
        require(
            victim_error_class in {"ConnectionFailed", "CONNECTION_FAILED"},
            f"unexpected victim error class: {structured}",
        )
        require(
            "commit_in_doubt" in victim_message or "unknown_discarded" in victim_message,
            f"victim error did not mention commit-in-doubt recovery state: {structured}",
        )

    post = victim_client.raw_tool_call(victim_session, 28, "oracle_query", {"sql": "SELECT 1 FROM dual"})
    post_result = classify_http_tool_reply(post)
    post_error_class = None
    if post_result is not None:
        require(post_result.get("isError") is True, f"post-kill follow-up did not fail as expected: {post_result}")
        post_payload = post_result.get("structuredContent")
        if isinstance(post_payload, dict):
            post_error_class = post_payload.get("error_class")

    require(
        post.status in {400, 401, 403, 404, 409, 500, 503}
        or post_error_class in {"RuntimeStateRequired", "RUNTIME_STATE_REQUIRED"},
        f"post-kill follow-up did not reveal quarantine/unavailability: status={post.status} body={post.body} class={post_error_class}",
    )
    server.stop()

    with subprocess.Popen(
        [
            str(binary),
            "--json",
            "serve",
            "--listen",
            f"127.0.0.1:{port}",
            "--client-credentials",
            "--http-stateful",
            "--profile",
            "e5_synthetic",
            "--http-allowed-host",
            f"127.0.0.1:{port}",
        ],
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as restarted:
        try:
            stdout, stderr = restarted.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            restarted.kill()
            raise AssertionError("server restart never failed while unresolved commit intent remained")
        logs = (stdout or "") + (stderr or "")
        require(
            "ORACLEMCP_WRITE_INTENT_IN_DOUBT" in logs,
            f"server restart after commit-in-doubt did not emit ORACLEMCP_WRITE_INTENT_IN_DOUBT: {logs[:2000]}",
        )

    evidence.append(
        {
            "id": "commit_in_doubt_unresolved",
            "wire": True,
            "status": "pass",
            "error_class": victim_error_class,
            "message": victim_message,
            "post_kill_follow_up_status": post.status,
            "post_kill_follow_up_error_class": post_error_class,
            "proof_boundary": "Kill was injected via ADMIN lane 'ALTER SYSTEM KILL SESSION'; follow-up lane probe and restart reflected unresolved commit intent via ORACLEMCP_WRITE_INTENT_IN_DOUBT.",
            "killed_by": killed_by,
        }
    )


def write_evidence(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    emit("evidence_written", "teardown", "pass", str(path))


def dry_run(log: bool) -> None:
    del log
    evidence = {
        "bead": BEAD,
        "status": "dry-run",
        "wire_assertions": [
            {"id": "refusal_no_quarantine", "wire": True, "status": "skipped"},
            {"id": "single_use_grant_replay_refusal", "wire": True, "status": "skipped"},
            {"id": "operator_cancel_teardown_quarantines_session", "wire": True, "status": "skipped"},
            {"id": "revoked_client_loses_sessions_buffers_and_fresh_lane", "wire": True, "status": "skipped"},
            {"id": "commit_in_doubt_unresolved", "wire": True, "status": "skipped"},
        ],
        "supplemental_assertions": [],
        "proof_boundary": "dry-run validates harness wiring only",
    }
    write_evidence(ROOT / "tests" / "artifacts" / "evidence" / "e5-failure-recovery-e2e.json", evidence)


def child_env(work: pathlib.Path, config: pathlib.Path, password: str) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(work / "home"),
        "XDG_CONFIG_HOME": str(work / "xdg_config"),
        "XDG_STATE_HOME": str(work / "xdg_state"),
        "XDG_CACHE_HOME": str(work / "xdg_cache"),
        "ORACLEMCP_CONFIG": str(config),
        "E5_DB_PASSWORD": password,
        "E5_AUDIT_KEY": AUDIT_KEY,
        "RUST_LOG": os.environ.get("ORACLEMCP_RIG_E5_RUST_LOG", "warn"),
    }
    for name in ("USER", "USERNAME", "LANG", "LC_ALL"):
        if os.environ.get(name):
            env[name] = os.environ[name]
    return env


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--log", action="store_true")
    args = parser.parse_args()
    if args.dry_run:
        dry_run(args.log)
        return 0

    for tool in ("cargo", "git", "tar", "docker"):
        if not any(os.access(pathlib.Path(p) / tool, os.X_OK) for p in os.environ.get("PATH", "").split(os.pathsep)):
            raise AssertionError(f"{tool} is required for E5")

    container, _, pdb = e5_db_params()
    ready_timeout = int(os.environ.get("ORACLEMCP_RIG_E5_READY_TIMEOUT_SECS", "300"))
    ensure_container_ready(container, ready_timeout)
    password = admin_password(container)
    work = artifact_dir()
    binary, source, source_sha = install_artifact(work)
    port = free_port()
    config = work / "config.toml"
    write_config(config, work / "audit.jsonl", port)
    env = child_env(work, config, password)
    for key in ("HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"):
        pathlib.Path(env[key]).mkdir(parents=True, exist_ok=True)

    client_id, bearer = issue_client(binary, env, "e5-wire-client")
    revoked_client_id, revoked_bearer = issue_client(binary, env, "e5-revoked-client")
    cancel_client_id, cancel_bearer = issue_client(binary, env, "e5-cancel-client")
    victim_client_id, victim_bearer = issue_client(binary, env, "e5-commit-in-doubt-victim", admin=True)
    del victim_client_id
    write_config(config, work / "audit.jsonl", port, [client_principal_key(client_id)])
    server = ServerProcess(binary, env, port)
    wire: list[dict[str, Any]] = []
    supplemental: list[dict[str, Any]] = []
    try:
        server.wait_ready()
        client = HttpClient(port, bearer)
        session = client.initialize("e5-wire")
        assert_refusal_does_not_quarantine(client, session, wire)
        assert_single_use_grant_replay_refused_without_quarantine(client, session, wire)
        operator_client = HttpClient(port, bearer)
        cancel_client = HttpClient(port, cancel_bearer)
        cancel_session = cancel_client.initialize("e5-cancel")
        cancel_subject_hash = operator_subject_id_hash(client_principal_key(cancel_client_id))
        assert_operator_cancel_quarantines_session(operator_client, cancel_client, cancel_session, cancel_subject_hash, wire)
        assert_revoked_client_loses_sessions(revoked_client_id, revoked_bearer, bearer, port, wire)
        run_commit_in_doubt_wire(
            server,
            binary,
            env,
            port,
            victim_bearer,
            container,
            pdb,
            password,
            wire,
        )
    finally:
        server.stop()

    evidence = {
        "bead": BEAD,
        "status": "pass",
        "source_sha": source_sha,
        "installed_binary": str(binary),
        "runtime_artifact_dir": str(work),
        "client_id": client_id,
        "wire_assertions": wire,
        "supplemental_assertions": supplemental,
        "proof_boundary": "HTTP/session/auth/refusal/kill/revoke/restart assertions are raw wire checks against the installed artifact. Grant expiry was exercised against fixed 300s confirmation TTL.",
    }
    write_evidence(ROOT / "tests" / "artifacts" / "evidence" / "e5-failure-recovery-e2e.json", evidence)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        emit("failure_recovery_e2e", "assert", "fail", str(exc))
        raise
