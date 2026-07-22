#!/usr/bin/env python3
"""R-fail deterministic failure-injection rig lane over the installed artifact."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import time
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
BEAD = "oraclemcp-091-rfail-injection-lanes-ok400"
SCENARIO = "failure_injection_lanes"
AUDIT_KEY = "0123456789abcdef0123456789abcdef"
OAUTH_SECRET = "rfail-oauth-secret-0123456789abcdef"
OAUTH_ISSUER = "https://idp.oraclemcp.invalid"
OAUTH_RESOURCE = "https://oraclemcp.invalid/mcp"

E5_PATH = ROOT / "scripts" / "rig" / "failure_recovery_e2e.py"
SPEC = importlib.util.spec_from_file_location("failure_recovery_e2e", E5_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {E5_PATH}")
e5 = importlib.util.module_from_spec(SPEC)
sys.modules["failure_recovery_e2e"] = e5
SPEC.loader.exec_module(e5)


def emit(event: str, phase: str, outcome: str, message: str, duration_ms: int = 0) -> None:
    row = {
        "event": event,
        "phase": phase,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_ms": duration_ms,
        "lane": "rfail-wire-faults",
        "subject": "raw-wire-client",
        "sid": str(os.getpid()),
        "profile": "rfail_synthetic",
        "level": "READ_WRITE",
        "grant": "wire",
        "outcome": outcome,
        "scenario": SCENARIO,
        "seed": os.environ.get("ORACLEMCP_E2E_SEED", "0"),
        "message": message,
    }
    print(json.dumps(row, separators=(",", ":")), file=sys.stderr, flush=True)


def run(cmd: list[str], *, cwd: pathlib.Path = ROOT, env: dict[str, str] | None = None, timeout: int = 120) -> subprocess.CompletedProcess[str]:
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
    emit("command_complete", "act", "pass" if proc.returncode == 0 else "fail", f"exit={proc.returncode} {' '.join(cmd)}", elapsed)
    if proc.returncode != 0:
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise AssertionError(f"command failed with exit {proc.returncode}: {' '.join(cmd)}")
    return proc


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def write_evidence(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    emit("evidence_written", "teardown", "pass", str(path))


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def hs256_jwt(*, sub: str, client_id: str, exp: int, jti: str, scope: str = "oracle:read") -> str:
    header = {"alg": "HS256", "typ": "at+jwt"}
    claims = {
        "iss": OAUTH_ISSUER,
        "aud": OAUTH_RESOURCE,
        "exp": exp,
        "sub": sub,
        "client_id": client_id,
        "iat": max(0, int(time.time()) - 1),
        "jti": jti,
        "scope": scope,
    }
    signing_input = ".".join(
        [
            b64url(json.dumps(header, separators=(",", ":")).encode("utf-8")),
            b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8")),
        ]
    )
    signature = hmac.new(OAUTH_SECRET.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{b64url(signature)}"


def write_config(config: pathlib.Path, audit: pathlib.Path, port: int, operator_subjects: list[str] | None = None) -> None:
    host_port = os.environ.get("ORACLEMCP_RFAIL_HOST_PORT", os.environ.get("ORACLEMCP_RIG_D10_HOST_PORT", "1522"))
    pdb = os.environ.get("ORACLEMCP_RFAIL_PDB", os.environ.get("ORACLEMCP_RIG_D10_PDB", "FREEPDB1"))
    subjects = "[" + ", ".join(json.dumps(subject) for subject in (operator_subjects or [])) + "]"
    config.write_text(
        f'''schema_version = 2
default_profile = "rfail_synthetic"

[audit]
path = "{audit}"
key_ref = "env:RFAIL_AUDIT_KEY"
key_id = "rfail-synthetic"

[http]
stateful = true
json_response = false
allowed_hosts = ["127.0.0.1:{port}"]
stateful_idle_ttl_seconds = 2

[http.oauth]
resource = "{OAUTH_RESOURCE}"
allowed_issuers = ["{OAUTH_ISSUER}"]
authorization_servers = ["{OAUTH_ISSUER}"]
required_scopes = ["oracle:read"]
hs256_secret_ref = "env:RFAIL_OAUTH_SECRET"

[http.operator]
allow_loopback_owner = true
allowed_subjects = {subjects}

[[profiles]]
name = "rfail_synthetic"
description = "R-fail synthetic local Free23 failure-injection profile"
connect_string = "//localhost:{host_port}/{pdb}"
username = "system"
credential_ref = "env:RFAIL_DB_PASSWORD"
max_level = "ADMIN"
default_level = "READ_ONLY"

[profiles.pool]
max_size = 3
min_idle = 1
acquire_timeout_secs = 5
statement_cache_size = 20
''',
        encoding="utf-8",
    )


def child_env(work: pathlib.Path, config: pathlib.Path, password: str) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(work / "home"),
        "XDG_CONFIG_HOME": str(work / "xdg_config"),
        "XDG_STATE_HOME": str(work / "xdg_state"),
        "XDG_CACHE_HOME": str(work / "xdg_cache"),
        "ORACLEMCP_CONFIG": str(config),
        "RFAIL_DB_PASSWORD": password,
        "RFAIL_AUDIT_KEY": AUDIT_KEY,
        "RFAIL_OAUTH_SECRET": OAUTH_SECRET,
        "RUST_LOG": os.environ.get("ORACLEMCP_RFAIL_RUST_LOG", "warn"),
    }
    for name in ("USER", "USERNAME", "LANG", "LC_ALL"):
        if os.environ.get(name):
            env[name] = os.environ[name]
    return env


class ServerProcess:
    def __init__(self, binary: pathlib.Path, env: dict[str, str], port: int) -> None:
        self.port = port
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
                "rfail_synthetic",
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
                reply = e5.HttpClient(self.port).request("GET", "/readyz", {"accept": "application/json"})
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
            "--scope",
            "oracle:admin",
        ],
        env=env,
        timeout=30,
    )
    value = json.loads(proc.stdout)
    return value["client"]["client_id"], value["bearer"]


def structured(value: dict[str, Any], *, expect_error: bool = False) -> dict[str, Any]:
    return e5.tool_result(value, expect_error=expect_error)


def query_rows(client: Any, session: str, request_id: int, sql: str) -> list[dict[str, Any]]:
    _, value = client.tool_call(session, request_id, "oracle_query", {"sql": sql, "max_rows": 5})
    content = structured(value, expect_error=False)
    rows = content.get("rows")
    require(isinstance(rows, list), f"query returned no rows list: {content}")
    return rows


def elevate(client: Any, session: str, level: str, request_id: int) -> None:
    _, preview = client.tool_call(session, request_id, "oracle_set_session_level", {"level": level, "ttl_seconds": 60})
    preview_content = structured(preview, expect_error=False)
    confirm = (preview_content.get("confirmation") or {}).get("confirm")
    require(isinstance(confirm, str) and confirm, f"level preview omitted confirmation: {preview_content}")
    _, applied = client.tool_call(
        session,
        request_id + 1,
        "oracle_set_session_level",
        {"level": level, "ttl_seconds": 60, "execute": True, "confirm": confirm},
    )
    applied_content = structured(applied, expect_error=False)
    require((applied_content.get("session") or {}).get("current_level") == level, f"level did not apply: {applied_content}")


def governed_execute(client: Any, session: str, request_id: int, sql: str, *, commit: bool) -> dict[str, Any]:
    _, preview = client.tool_call(session, request_id, "oracle_preview_sql", {"sql": sql})
    preview_content = structured(preview, expect_error=False)
    require(preview_content.get("gate_decision") == "allow", f"preview did not allow: {preview_content}")
    confirm = (preview_content.get("execute_confirmation") or {}).get("confirm")
    require(isinstance(confirm, str) and confirm, f"preview omitted execute confirmation: {preview_content}")
    _, executed = client.tool_call(session, request_id + 1, "oracle_execute", {"sql": sql, "commit": commit, "confirm": confirm})
    return structured(executed, expect_error=False)


def assert_wire_kill(binary: pathlib.Path, env: dict[str, str], port: int, operator_bearer: str, evidence: list[dict[str, Any]]) -> None:
    _victim_id, victim_bearer = issue_client(binary, env, "rfail-kill-victim")
    _killer_id, killer_bearer = issue_client(binary, env, "rfail-kill-admin")
    victim = e5.HttpClient(port, victim_bearer)
    killer = e5.HttpClient(port, killer_bearer)
    victim_session = victim.initialize("rfail-kill-victim")
    killer_session = killer.initialize("rfail-kill-admin")
    rows = query_rows(
        victim,
        victim_session,
        10,
        "SELECT sid AS s_id, serial# AS s_serial FROM v$session WHERE sid = SYS_CONTEXT('USERENV', 'SID')",
    )
    require(len(rows) == 1, f"victim identity query returned {rows}")
    sid = str(rows[0].get("S_ID", ""))
    serial = str(rows[0].get("S_SERIAL", ""))
    require(sid.isdigit() and serial.isdigit(), f"victim SID/SERIAL not numeric: {rows}")
    elevate(killer, killer_session, "ADMIN", 20)
    kill_sql = f"ALTER SYSTEM KILL SESSION '{sid},{serial}' IMMEDIATE"
    outcome = governed_execute(killer, killer_session, 30, kill_sql, commit=True)
    require(outcome.get("executed") is True and outcome.get("committed") is True, f"kill did not execute: {outcome}")
    time.sleep(1)
    reply = victim.raw_tool_call(victim_session, 40, "oracle_query", {"sql": "SELECT 1 FROM dual"})
    if reply.status in {401, 404, 409, 500, 503}:
        status = reply.status
        detail = reply.body[:200]
    else:
        value = e5.parse_mcp_json(reply.body)
        content = structured(value, expect_error=True)
        status = reply.status
        detail = str(content.get("error_class") or content.get("message"))
    fresh_client = e5.HttpClient(port, operator_bearer)
    fresh = fresh_client.initialize("rfail-kill-fresh")
    fresh_rows = query_rows(fresh_client, fresh, 41, "SELECT 1 AS ok FROM dual")
    require(fresh_rows and str(fresh_rows[0].get("OK")) == "1", f"fresh lane after kill failed: {fresh_rows}")
    evidence.append(
        {
            "id": "wire_oracle_session_kill",
            "wire": True,
            "status": "pass",
            "victim_status_after_kill": status,
            "victim_error": detail,
            "fresh_lane_after_kill": "pass",
        }
    )


def assert_revoke(binary: pathlib.Path, env: dict[str, str], port: int, operator_bearer: str, evidence: list[dict[str, Any]]) -> None:
    client_id, bearer = issue_client(binary, env, "rfail-revoke")
    client = e5.HttpClient(port, bearer)
    session = client.initialize("rfail-revoke")
    query_rows(client, session, 50, "SELECT 1 AS ok FROM dual")
    replay = client.replay(session, until='"id":50')
    require(replay.status == 200 and '"id":50' in replay.body, f"pre-revoke replay failed: {replay.status} {replay.body}")
    data = e5.operator_json(e5.HttpClient(port, operator_bearer).operator("POST", "/operator/v1/client-credentials/revoke", {"client_id": client_id}))
    require(data.get("status") == "revoked", f"revoke failed: {data}")
    require(int(data.get("closed_sessions", 0)) >= 1, f"revoke did not close session: {data}")
    replay_after = client.replay(session)
    fresh = client.request(
        "POST",
        "/mcp",
        {"content-type": "application/json"},
        {"jsonrpc": "2.0", "id": 51, "method": "initialize", "params": {"protocolVersion": e5.PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": "rfail-revoked", "version": "1.0"}}},
    )
    require(replay_after.status == 401 and fresh.status == 401, f"revoked bearer survived: replay={replay_after.status} fresh={fresh.status}")
    evidence.append(
        {
            "id": "wire_client_revoke",
            "wire": True,
            "status": "pass",
            "closed_sessions": data.get("closed_sessions"),
            "replay_after_revoke_status": replay_after.status,
            "fresh_after_revoke_status": fresh.status,
        }
    )


def assert_rotate(binary: pathlib.Path, env: dict[str, str], port: int, operator_bearer: str, evidence: list[dict[str, Any]]) -> None:
    client_id, old_bearer = issue_client(binary, env, "rfail-rotate")
    old_client = e5.HttpClient(port, old_bearer)
    session = old_client.initialize("rfail-rotate")
    query_rows(old_client, session, 60, "SELECT 1 AS ok FROM dual")
    data = e5.operator_json(e5.HttpClient(port, operator_bearer).operator("POST", "/operator/v1/client-credentials/rotate", {"client_id": client_id}))
    new_bearer = data.get("bearer")
    require(data.get("status") == "rotated" and isinstance(new_bearer, str) and new_bearer, f"rotate failed: {data}")
    require(int(data.get("closed_sessions", 0)) >= 1, f"rotate did not close session: {data}")
    old_fresh = old_client.request(
        "POST",
        "/mcp",
        {"content-type": "application/json"},
        {"jsonrpc": "2.0", "id": 61, "method": "initialize", "params": {"protocolVersion": e5.PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": "rfail-old-rotated", "version": "1.0"}}},
    )
    require(old_fresh.status == 401, f"old bearer still opens lane after rotate: {old_fresh.status} {old_fresh.body}")
    new_client = e5.HttpClient(port, new_bearer)
    new_session = new_client.initialize("rfail-rotated")
    rows = query_rows(new_client, new_session, 62, "SELECT 1 AS ok FROM dual")
    require(rows and str(rows[0].get("OK")) == "1", f"new bearer failed after rotate: {rows}")
    evidence.append(
        {
            "id": "wire_client_rotate",
            "wire": True,
            "status": "pass",
            "closed_sessions": data.get("closed_sessions"),
            "old_bearer_fresh_status": old_fresh.status,
            "new_bearer_fresh": "pass",
            "bearer_recorded": False,
        }
    )


def complete_server_restart(old_server: ServerProcess, binary: pathlib.Path, env: dict[str, str], port: int, bearer: str, old_session: str, evidence: list[dict[str, Any]]) -> ServerProcess:
    old_server.stop()
    restarted = ServerProcess(binary, env, port)
    restarted.wait_ready()
    client = e5.HttpClient(port, bearer)
    old = client.raw_tool_call(old_session, 71, "oracle_query", {"sql": "SELECT 1 FROM dual"})
    require(old.status == 404 and "Invalid mcp-session-id" in old.body, f"old session survived restart: {old.status} {old.body}")
    fresh = client.initialize("rfail-restart-after")
    rows = query_rows(client, fresh, 72, "SELECT 1 AS ok FROM dual")
    require(rows and str(rows[0].get("OK")) == "1", f"fresh lane after restart failed: {rows}")
    evidence.append(
        {
            "id": "wire_server_restart",
            "wire": True,
            "status": "pass",
            "old_session_status": old.status,
            "fresh_lane_after_restart": "pass",
        }
    )
    return restarted


def assert_oauth_expiry(port: int, evidence: list[dict[str, Any]]) -> None:
    now = int(time.time())
    expiring = hs256_jwt(sub="rfail-subject", client_id="rfail-oauth-client", exp=now + 2, jti=f"rfail-expiring-{now}")
    expired = hs256_jwt(sub="rfail-subject", client_id="rfail-oauth-client", exp=now - 30, jti=f"rfail-expired-{now}")
    expired_client = e5.HttpClient(port, expired)
    expired_reply = expired_client.request(
        "POST",
        "/mcp",
        {"content-type": "application/json"},
        {"jsonrpc": "2.0", "id": 80, "method": "initialize", "params": {"protocolVersion": e5.PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": "rfail-expired", "version": "1.0"}}},
    )
    require(expired_reply.status == 401 and expired not in expired_reply.body, f"expired token not refused opaquely: {expired_reply.status} {expired_reply.body}")
    client = e5.HttpClient(port, expiring)
    session = client.initialize("rfail-expiring")
    query_rows(client, session, 81, "SELECT 1 AS ok FROM dual")
    time.sleep(4)
    after = client.raw_tool_call(session, 82, "oracle_query", {"sql": "SELECT 1 FROM dual"})
    require(after.status == 401 and expiring not in after.body, f"expired held token still admitted or leaked: {after.status} {after.body}")
    evidence.append(
        {
            "id": "wire_oauth_token_expiry",
            "wire": True,
            "status": "pass",
            "initial_expired_status": expired_reply.status,
            "held_token_after_expiry_status": after.status,
            "token_material_recorded": False,
        }
    )


def dry_run() -> None:
    write_evidence(
        ROOT / "tests" / "artifacts" / "evidence" / "rfail-failure-injection-lanes.json",
        {
            "bead": BEAD,
            "status": "dry-run",
            "wire_assertions": [
                {"id": "wire_oracle_session_kill", "status": "skipped", "wire": True},
                {"id": "wire_client_revoke", "status": "skipped", "wire": True},
                {"id": "wire_client_rotate", "status": "skipped", "wire": True},
                {"id": "wire_server_restart", "status": "skipped", "wire": True},
                {"id": "wire_oauth_token_expiry", "status": "skipped", "wire": True},
            ],
            "proof_boundary": "dry-run validates harness wiring only",
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--log", action="store_true")
    args = parser.parse_args()
    if args.dry_run:
        dry_run()
        return 0

    for tool in ("cargo", "git", "tar", "docker"):
        if not any(os.access(pathlib.Path(p) / tool, os.X_OK) for p in os.environ.get("PATH", "").split(os.pathsep)):
            raise AssertionError(f"{tool} is required for R-fail")

    container = os.environ.get("ORACLEMCP_RFAIL_CONTAINER", os.environ.get("ORACLEMCP_RIG_D10_CONTAINER", "rust-oracledb-free"))
    e5.ensure_container_ready(container, int(os.environ.get("ORACLEMCP_RFAIL_READY_TIMEOUT_SECS", "300")))
    work = e5.artifact_dir()
    binary, _source, source_sha = e5.install_artifact(work)
    port = e5.free_port()
    config = work / "config.toml"
    password = e5.admin_password(container)
    write_config(config, work / "audit.jsonl", port)
    env = child_env(work, config, password)
    for key in ("HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"):
        pathlib.Path(env[key]).mkdir(parents=True, exist_ok=True)

    operator_id, operator_bearer = issue_client(binary, env, "rfail-operator")
    _restart_id, restart_bearer = issue_client(binary, env, "rfail-restart")
    write_config(config, work / "audit.jsonl", port, [e5.client_principal_key(operator_id)])
    server = ServerProcess(binary, env, port)
    wire: list[dict[str, Any]] = []
    try:
        server.wait_ready()
        assert_wire_kill(binary, env, port, operator_bearer, wire)
        assert_revoke(binary, env, port, operator_bearer, wire)
        assert_rotate(binary, env, port, operator_bearer, wire)
        restart_client = e5.HttpClient(port, restart_bearer)
        old_session = restart_client.initialize("rfail-restart-before")
        query_rows(restart_client, old_session, 70, "SELECT 1 AS ok FROM dual")
        server = complete_server_restart(server, binary, env, port, restart_bearer, old_session, wire)
        assert_oauth_expiry(port, wire)
    finally:
        server.stop()

    write_evidence(
        ROOT / "tests" / "artifacts" / "evidence" / "rfail-failure-injection-lanes.json",
        {
            "bead": BEAD,
            "status": "pass",
            "source_sha": source_sha,
            "installed_binary": str(binary),
            "runtime_artifact_dir": str(work),
            "wire_assertions": wire,
            "proof_boundary": "All assertions use raw HTTP/MCP/operator requests against the installed artifact. Database inputs are local synthetic Free23 only. The lane proves server/process restart; disruptive Docker container restart remains intentionally out of the default shared-checkout run.",
        },
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        emit("failure_injection_lanes", "assert", "fail", str(exc))
        raise
