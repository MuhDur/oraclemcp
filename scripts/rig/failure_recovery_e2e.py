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
from dataclasses import dataclass
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
BEAD = "oraclemcp-091-e5-failure-recovery-e2e-bf1qa"
PROTOCOL_VERSION = "2025-11-25"
SCENARIO = "failure_recovery_e2e"
AUDIT_KEY = "0123456789abcdef0123456789abcdef"


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


def issue_client(binary: pathlib.Path, env: dict[str, str], label: str) -> tuple[str, str]:
    proc = run(
        [
            str(binary),
            "--json",
            "clients",
            "issue",
            "--label",
            label,
            "--scope",
            "oracle:read",
            "--scope",
            "oracle:execute",
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
        {"level": "READ_WRITE", "ttl_seconds": 1},
    )
    structured = tool_result(preview, expect_error=False)
    confirm = structured.get("confirmation", {}).get("confirm")
    require(isinstance(confirm, str) and confirm, f"preview did not mint confirm: {structured}")
    _, applied = client.tool_call(
        session,
        21,
        "oracle_set_session_level",
        {"level": "READ_WRITE", "ttl_seconds": 1, "execute": True, "confirm": confirm},
    )
    tool_result(applied, expect_error=False)
    _, dropped = client.tool_call(session, 22, "oracle_set_session_level", {"action": "drop"})
    tool_result(dropped, expect_error=False)
    _, replay = client.tool_call(
        session,
        23,
        "oracle_set_session_level",
        {"level": "READ_WRITE", "ttl_seconds": 1, "execute": True, "confirm": confirm},
    )
    replay_structured = tool_result(replay, expect_error=True)
    require(replay_structured.get("error_class") == "CHALLENGE_REQUIRED", f"unexpected replay error: {replay_structured}")
    _, ok = client.tool_call(session, 24, "oracle_query", {"sql": "SELECT 1 FROM dual"})
    tool_result(ok, expect_error=False)
    evidence.append(
        {
            "id": "single_use_grant_replay_refusal",
            "wire": True,
            "status": "pass",
            "replay_error_class": replay_structured.get("error_class"),
            "post_replay_refusal_read": "pass",
            "proof_boundary": "public wire grant expiry is fixed at 300s; this bounded rig proves single-use replay refusal but does not wait for expiry",
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


def run_commit_in_doubt_supplement(source: pathlib.Path, evidence: list[dict[str, Any]]) -> None:
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(ROOT / "target")
    env.setdefault("CARGO_BUILD_JOBS", "2")
    run(
        [
            "cargo",
            "test",
            "-p",
            "oraclemcp",
            "execute_commit_in_doubt_leaves_durable_intent_unresolved",
            "--",
            "--exact",
        ],
        cwd=source,
        env=env,
        timeout=300,
    )
    evidence.append(
        {
            "id": "commit_in_doubt_unresolved",
            "wire": False,
            "status": "pass",
            "proof_boundary": "CommitInDoubtMock is test-only; no public installed-binary fault hook exists for a wire-level commit-in-doubt injection.",
            "command": "cargo test -p oraclemcp execute_commit_in_doubt_leaves_durable_intent_unresolved -- --exact",
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
        ],
        "supplemental_assertions": [
            {"id": "commit_in_doubt_unresolved", "wire": False, "status": "skipped"}
        ],
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

    container = os.environ.get("ORACLEMCP_RIG_E5_CONTAINER", os.environ.get("ORACLEMCP_RIG_D10_CONTAINER", "rust-oracledb-free"))
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
        run_commit_in_doubt_supplement(source, supplemental)
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
        "proof_boundary": "HTTP/session/auth/refusal/single-use-replay/teardown/revocation assertions are raw wire checks against the installed artifact. Grant expiry is not exercised because the public confirmation-grant TTL is fixed at 300s; commit_in_doubt remains a supplemental archived-source cargo test because the installed binary has no public commit-in-doubt fault injection hook.",
    }
    write_evidence(ROOT / "tests" / "artifacts" / "evidence" / "e5-failure-recovery-e2e.json", evidence)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        emit("failure_recovery_e2e", "assert", "fail", str(exc))
        raise
