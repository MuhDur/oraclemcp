#!/usr/bin/env python3
"""Real served Arc-D edition lifecycle proof for ``scripts/e2e/editions.sh``.

The harness launches the real binary on loopback with a generated, authenticated
operator identity. It does not use a mock dispatcher or a synthetic Oracle
connection. All committed literals are synthetic; connection material exists
only in the ignored per-run configuration and process environment.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import hmac
import json
import os
import queue
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


ISSUER = "https://synthetic-editions.invalid"
OAUTH_SUBJECT = "synthetic-editions-e2e"
OAUTH_CLIENT = "synthetic-editions-client"
OAUTH_SCOPE = "oracle:admin"


class StepFailure(RuntimeError):
    """A live assertion failed without rendering secret-bearing response data."""


class GuardedExecutionRefusal(StepFailure):
    """A bounded guard refusal observed through the served MCP envelope."""

    def __init__(self, message: str, category: str, ora_code: int) -> None:
        super().__init__(message)
        self.category = category
        self.ora_code = ora_code


class LivePrerequisiteUnavailable(RuntimeError):
    """A local lane cannot safely host an isolated edition lifecycle."""


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise StepFailure(message)


def private_write(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)


def safe_toml_scalar(label: str, value: str) -> str:
    if not value or any(character in value for character in ("\n", "\r", '"', "\\")):
        raise StepFailure(f"{label} is unsafe for the ephemeral test TOML")
    return value


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def oauth_principal_key() -> str:
    material = "\n".join(
        [
            f"iss={ISSUER}",
            f"sub={OAUTH_SUBJECT}",
            f"client_id={OAUTH_CLIENT}",
        ]
    )
    return f"oauth:{hashlib.sha256(material.encode()).hexdigest()}"


def mint_oauth_token(audience: str, secret: str) -> str:
    header = b64url(b'{"alg":"HS256","typ":"at+jwt"}')
    claims = {
        "iss": ISSUER,
        "aud": audience,
        "exp": int(time.time()) + 900,
        "iat": int(time.time()),
        "sub": OAUTH_SUBJECT,
        "client_id": OAUTH_CLIENT,
        "scope": OAUTH_SCOPE,
        "jti": "synthetic-editions-e2e",
    }
    payload = b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{b64url(signature)}"


class Harness:
    """Shared JSON-line log contract plus redacted durable evidence."""

    def __init__(self, evidence_path: Path) -> None:
        self.evidence = evidence_path.open("a", encoding="utf-8")
        self.log_enabled = os.environ.get("E2E_LOG", "0") == "1"
        self.level = "READ_ONLY"
        self.grant = "none"

    def emit(self, event: str, phase: str, outcome: str, message: str) -> None:
        if not self.log_enabled:
            return
        print(
            json.dumps(
                {
                    "event": event,
                    "phase": phase,
                    "ts": now_iso(),
                    "duration_ms": 0,
                    "lane": os.environ.get("E2E_LANE", "editions"),
                    "subject": os.environ.get("E2E_SUBJECT", "test-harness"),
                    "sid": os.environ.get("E2E_SID", str(os.getpid())),
                    "profile": os.environ.get("E2E_PROFILE", "editions"),
                    "level": self.level,
                    "grant": self.grant,
                    "outcome": outcome,
                    "scenario": os.environ.get("E2E_SCENARIO", "editions"),
                    "seed": os.environ.get("ORACLEMCP_E2E_SEED", "0"),
                    "message": message,
                },
                separators=(",", ":"),
            ),
            file=sys.stderr,
            flush=True,
        )

    def evidence_line(self, step: str, outcome: str, detail: dict) -> None:
        self.evidence.write(
            json.dumps(
                {
                    "ts": now_iso(),
                    "step": step,
                    "outcome": outcome,
                    "detail": detail,
                },
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
        self.evidence.flush()

    def step(self, name: str, action) -> dict | None:
        self.emit(name, "act", "running", f"step {name} started")
        started = time.monotonic()
        try:
            detail = action()
        except LivePrerequisiteUnavailable as error:
            self.emit(name, "assert", "skipped", str(error))
            self.evidence_line(name, "skipped", {"reason": str(error)})
            raise
        except StepFailure as error:
            self.emit(name, "assert", "fail", str(error))
            self.evidence_line(name, "fail", {"reason": str(error)})
            raise
        duration_ms = int((time.monotonic() - started) * 1000)
        self.emit(name, "assert", "pass", f"step {name} passed in {duration_ms}ms")
        self.evidence_line(name, "pass", detail or {})
        return detail

    def close(self) -> None:
        self.evidence.close()


def http_raw(
    port: int,
    method: str,
    path: str,
    body: dict | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    payload = b"" if body is None else json.dumps(body, separators=(",", ":")).encode()
    request_headers = {
        "Accept": "application/json",
        "Host": f"127.0.0.1:{port}",
        "Connection": "close",
    }
    if body is not None:
        request_headers["Content-Type"] = "application/json"
    if headers:
        request_headers.update(headers)
    request_lines = [f"{method} {path} HTTP/1.1"]
    request_lines.extend(f"{name}: {value}" for name, value in request_headers.items())
    request_lines.extend([f"Content-Length: {len(payload)}", "", ""])
    connection = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        connection.settimeout(15)
        connection.sendall("\r\n".join(request_lines).encode("ascii") + payload)
        connection.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        while True:
            chunk = connection.recv(65_536)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        connection.close()
    head, separator, response_body = b"".join(chunks).partition(b"\r\n\r\n")
    require(bool(separator), f"served endpoint returned no HTTP response for {path}")
    lines = head.decode("iso-8859-1").split("\r\n")
    parts = lines[0].split()
    require(len(parts) >= 2 and parts[1].isdigit(), f"invalid HTTP status from {path}")
    response_headers = {
        name.strip().lower(): value.strip()
        for line in lines[1:]
        if ":" in line
        for name, value in [line.split(":", 1)]
    }
    return int(parts[1]), response_headers, response_body


def http_json(
    port: int,
    method: str,
    path: str,
    body: dict | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], dict]:
    status, response_headers, raw = http_raw(port, method, path, body, headers)
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as error:
        raise StepFailure(f"served endpoint returned invalid JSON for {path}") from error
    require(isinstance(decoded, dict), f"served endpoint returned non-object JSON for {path}")
    return status, response_headers, decoded


def response_data(response: dict, path: str) -> dict:
    data = response.get("data")
    require(isinstance(data, dict), f"operator response had no data object for {path}")
    return data


def mcp_content(data: dict, action: str) -> tuple[dict, dict]:
    mcp = data.get("mcp_response")
    require(isinstance(mcp, dict), f"operator {action} returned no MCP response")
    result = mcp.get("result")
    require(isinstance(result, dict), f"operator {action} returned no MCP result")
    content = result.get("structuredContent")
    require(isinstance(content, dict), f"operator {action} returned no structured MCP content")
    return result, content


def error_content(data: dict, action: str) -> tuple[dict, dict]:
    result, content = mcp_content(data, action)
    require(result.get("isError") is True, f"{action} must be refused")
    return result, content


def token_from(content: dict, field: str, action: str) -> str:
    block = content.get(field)
    require(isinstance(block, dict), f"{action} did not return {field}")
    token = block.get("confirm")
    require(isinstance(token, str) and token, f"{action} did not return a confirmation grant")
    return token


def row_value(content: dict, column: str) -> str:
    rows = content.get("rows")
    require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict), "query must return exactly one row")
    value = rows[0].get(column)
    if value is None:
        # Oracle column labels are normally preserved, but permit a one-column
        # row shape without coupling this E2E to client-side casing.
        require(len(rows[0]) == 1, "query row did not carry the expected column")
        value = next(iter(rows[0].values()))
    return str(value)


class ServedServer:
    def __init__(
        self,
        binary: Path,
        run_dir: Path,
        config: Path,
        db_password: str,
        audit_key: str,
        oauth_secret: str,
        port: int,
    ) -> None:
        self.port = port
        self.stdout = (run_dir / "server.stdout").open("w", encoding="utf-8")
        self.stderr = (run_dir / "server.stderr").open("w", encoding="utf-8")
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("ORACLEMCP_")
        }
        environment.update(
            {
                "ORACLEMCP_CONFIG": str(config),
                "XDG_STATE_HOME": str(run_dir / "state"),
                "XDG_RUNTIME_DIR": str(run_dir / "runtime"),
                "E2E_EDITIONS_DB_PASSWORD": db_password,
                "E2E_EDITIONS_AUDIT_KEY": audit_key,
                "E2E_EDITIONS_OAUTH_SECRET": oauth_secret,
            }
        )
        self.process = subprocess.Popen(
            [
                str(binary),
                "--json",
                "serve",
                "--listen",
                f"127.0.0.1:{port}",
                "--allow-no-auth",
                "--http-json-response",
                "--profile",
                "editions",
            ],
            cwd=run_dir,
            stdin=subprocess.DEVNULL,
            stdout=self.stdout,
            stderr=self.stderr,
            env=environment,
        )

    def wait_ready(self) -> None:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise StepFailure("served editions process exited before readiness")
            try:
                status, _, _ = http_json(self.port, "GET", "/readyz")
                if status == 200:
                    return
            except (OSError, StepFailure):
                pass
            time.sleep(0.1)
        raise StepFailure("served editions process did not become ready against its live lab lane")

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=15)
        self.stdout.close()
        self.stderr.close()


class McpSession:
    """Fresh stdio process used to prove default editions affect new sessions."""

    def __init__(self, binary: Path, profile: str, config: Path, state_home: Path, environment: dict[str, str], stderr_path: Path) -> None:
        self.stderr = stderr_path.open("a", encoding="utf-8")
        env = dict(environment)
        env["ORACLEMCP_CONFIG"] = str(config)
        env["XDG_STATE_HOME"] = str(state_home)
        env["XDG_RUNTIME_DIR"] = str(state_home / "runtime")
        self.proc = subprocess.Popen(
            [str(binary), "serve", "--profile", profile, "--allow-no-auth"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
        )
        self.queue: queue.Queue[str] = queue.Queue()
        self.request_id = 0
        threading.Thread(target=self._reader, daemon=True).start()
        threading.Thread(target=self._drain_stderr, daemon=True).start()

    def _reader(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            line = line.strip()
            if line:
                self.queue.put(line)

    def _drain_stderr(self) -> None:
        assert self.proc.stderr is not None
        for line in self.proc.stderr:
            self.stderr.write(line)
            self.stderr.flush()

    def rpc(self, method: str, params: dict | None = None) -> dict:
        self.request_id += 1
        request: dict = {"jsonrpc": "2.0", "id": self.request_id, "method": method}
        if params is not None:
            request["params"] = params
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(request) + "\n")
        self.proc.stdin.flush()
        deadline = time.monotonic() + 120
        while True:
            if self.proc.poll() is not None:
                raise StepFailure("fresh witness MCP process exited before its response")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise StepFailure(f"timed out waiting for fresh witness {method}")
            try:
                message = json.loads(self.queue.get(timeout=min(remaining, 0.5)))
            except queue.Empty:
                continue
            except json.JSONDecodeError as error:
                raise StepFailure("fresh witness emitted malformed JSON-RPC") from error
            if message.get("id") == self.request_id:
                return message

    def initialize(self) -> None:
        reply = self.rpc(
            "initialize",
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "oraclemcp-editions-e2e", "version": "1"},
            },
        )
        require(reply.get("result", {}).get("serverInfo", {}).get("name") == "oraclemcp", "fresh witness must identify the real server")
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        self.proc.stdin.flush()

    def query(self, sql: str) -> dict:
        reply = self.rpc("tools/call", {"name": "oracle_query", "arguments": {"sql": sql}})
        require("error" not in reply, "fresh witness query must not be a JSON-RPC error")
        result = reply.get("result")
        require(isinstance(result, dict) and result.get("isError") is not True, "fresh witness query must succeed")
        content = result.get("structuredContent")
        require(isinstance(content, dict), "fresh witness query must provide structured content")
        return content

    def close(self) -> None:
        try:
            assert self.proc.stdin is not None
            self.proc.stdin.close()
        except (AssertionError, OSError):
            pass
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=15)
        self.stderr.close()


class EditionsScenario:
    def __init__(self, args: argparse.Namespace, harness: Harness, server: ServedServer, token: str, witness_config: Path, witness_environment: dict[str, str]) -> None:
        self.args = args
        self.harness = harness
        self.server = server
        self.token = token
        self.witness_config = witness_config
        self.witness_environment = witness_environment
        tag = secrets.token_hex(5).upper()
        self.parent = f"E2E_ED_PARENT_{tag}"
        self.child = f"E2E_ED_CHILD_{tag}"
        self.competing_child = f"E2E_ED_FORK_{tag}"
        self.competing_child_two = f"E2E_ED_FORK2_{tag}"
        self.view = f"E2E_ED_VIEW_{tag}"
        self.initial_edition = ""
        self.proposal_id = ""
        self.current_edition_query_count = 0
        self.parent_created = False
        self.child_created = False
        self.merged = False

    def operator(self, path: str, body: dict) -> tuple[int, dict]:
        status, _, response = http_json(
            self.server.port,
            "POST",
            path,
            body,
            {"Authorization": f"Bearer {self.token}"},
        )
        return status, response

    def action_preview(self, tool: str, arguments: dict) -> dict:
        status, response = self.operator("/operator/v1/actions/preview", {"tool": tool, "arguments": arguments})
        require(status == 200, f"operator preview failed for {tool}")
        _, content = mcp_content(response_data(response, "/operator/v1/actions/preview"), f"preview {tool}")
        return content

    def action_execute(self, tool: str, arguments: dict, key: str) -> tuple[dict, dict]:
        status, response = self.operator(
            "/operator/v1/actions/execute",
            {"tool": tool, "arguments": arguments, "idempotency_key": key},
        )
        require(status == 200, f"operator execute failed at the HTTP layer for {tool}")
        return mcp_content(response_data(response, "/operator/v1/actions/execute"), f"execute {tool}")

    def confirmed_execute(self, sql: str, key: str) -> dict:
        preview = self.action_preview("oracle_preview_sql", {"sql": sql})
        require(preview.get("gate_decision") == "allow", "edition SQL preview must be allowed at the active level")
        confirm = token_from(preview, "execute_confirmation", "edition SQL preview")
        self.harness.grant = "execute"
        result, content = self.action_execute(
            "oracle_execute",
            {"sql": sql, "commit": True, "confirm": confirm},
            key,
        )
        self.harness.grant = "none"
        if result.get("isError") is True or content.get("executed") is not True:
            # Keep failure evidence useful without copying a driver/database
            # message (which can carry connection or deployment identifiers).
            # The structured category and numeric ORA code are the bounded,
            # operator-facing refusal contract.
            reason = content.get("structured_reason")
            category = reason.get("category") if isinstance(reason, dict) else None
            category = category if isinstance(category, str) and category.isascii() and category.isupper() else "absent"
            ora_code = content.get("ora_code")
            ora_code = ora_code if isinstance(ora_code, int) and 0 <= ora_code <= 99_999 else 0
            raise GuardedExecutionRefusal(
                f"confirmed edition SQL must execute (category={category}, ora_code={ora_code})",
                category,
                ora_code,
            )
        return content

    def query_current_edition(self) -> str:
        preview = self.action_preview("oracle_preview_sql", {"sql": "SELECT SYS_CONTEXT('USERENV', 'CURRENT_EDITION_NAME') AS CURRENT_EDITION FROM dual"})
        # Use the ordinary MCP tool for reads: operator preview only proves the
        # SQL has a verdict, while this query must obtain the actual value.
        self.current_edition_query_count += 1
        result, content = self.action_execute(
            "oracle_query",
            {"sql": "SELECT SYS_CONTEXT('USERENV', 'CURRENT_EDITION_NAME') AS CURRENT_EDITION FROM dual"},
            f"synthetic-editions-current-edition-{self.current_edition_query_count}",
        )
        require(result.get("isError") is not True, "current-edition query must succeed")
        _ = preview
        return row_value(content, "CURRENT_EDITION")

    def elevate_admin(self) -> dict:
        status, response = self.operator("/operator/v1/session/set-level", {"level": "ADMIN"})
        require(status == 200, "ADMIN elevation preview must return HTTP 200")
        _, preview = mcp_content(response_data(response, "/operator/v1/session/set-level"), "ADMIN elevation preview")
        confirm = token_from(preview, "confirmation", "ADMIN elevation preview")
        self.harness.grant = "session-level"
        status, response = self.operator(
            "/operator/v1/session/set-level",
            {"level": "ADMIN", "execute": True, "confirm": confirm},
        )
        self.harness.grant = "none"
        require(status == 200, "ADMIN elevation apply must return HTTP 200")
        _, applied = mcp_content(response_data(response, "/operator/v1/session/set-level"), "ADMIN elevation apply")
        session = applied.get("session")
        require(isinstance(session, dict) and session.get("current_level") == "ADMIN", "server must enter ADMIN only after its confirmation")
        self.harness.level = "ADMIN"
        return {"level": "ADMIN", "confirmation_bound": True}

    def draft_and_review(self) -> dict:
        status, response = self.operator(
            "/operator/v1/edition-proposals/draft",
            {
                "profile": "editions",
                "base_edition": self.parent,
                "child_edition": self.child,
                "objects": [self.view],
            },
        )
        require(status == 200, "synthetic edition proposal must be accepted as review metadata")
        data = response_data(response, "/operator/v1/edition-proposals/draft")
        proposal = data.get("proposal")
        require(isinstance(proposal, dict) and data.get("authority") == "request_only", "edition board must remain request-only")
        proposal_id = proposal.get("proposal_id")
        require(isinstance(proposal_id, str) and proposal_id, "edition proposal must receive an id")
        self.proposal_id = proposal_id
        status, response = self.operator(
            "/operator/v1/edition-proposals/transition",
            {"proposal_id": proposal_id, "status": "reviewing"},
        )
        require(status == 200, "synthetic edition proposal review transition must succeed")
        transitioned = response_data(response, "/operator/v1/edition-proposals/transition").get("proposal")
        require(isinstance(transitioned, dict) and transitioned.get("status") == "reviewing", "edition proposal must be independently reviewed before a default flip")
        return {"reviewed": True, "request_only": True}

    def create_parent_and_child(self) -> dict:
        self.initial_edition = self.query_current_edition()
        require(self.initial_edition, "live lane must report its current default edition")
        base_edition = os.environ.get("E2E_EDITIONS_BASE_EDITION", self.initial_edition)
        require(
            re.fullmatch(r"[A-Za-z][A-Za-z0-9_$#]{0,127}", base_edition) is not None,
            "the configured edition base must be an unquoted Oracle identifier",
        )
        try:
            self.confirmed_execute(
                f"CREATE EDITION {self.parent} AS CHILD OF {base_edition}",
                "synthetic-editions-create-parent",
            )
        except GuardedExecutionRefusal as error:
            if error.category == "ONE_CHILD_EDITION" and error.ora_code == 38_807:
                raise LivePrerequisiteUnavailable(
                    "connect_or_skip: current default edition already has a child; refusing to alter the shared edition timeline"
                ) from error
            raise
        self.parent_created = True
        self.confirmed_execute(
            f"ALTER SESSION SET EDITION = {self.parent}",
            "synthetic-editions-enter-parent",
        )
        self.confirmed_execute(
            f"CREATE OR REPLACE EDITIONABLE VIEW {self.view} AS SELECT 'SYNTHETIC_EDITION_PARENT' AS EDITION_MARKER FROM dual",
            "synthetic-editions-parent-view",
        )
        self.confirmed_execute(
            f"CREATE EDITION {self.child} AS CHILD OF {self.parent}",
            "synthetic-editions-create-child",
        )
        self.child_created = True
        return {"single_child_created": True, "view": "synthetic editionable view"}

    def competing_child_refusal(self) -> dict:
        # Issue two distinct child applications concurrently. The real server
        # may serialize its lane after transport admission, but both requests
        # are in flight at the operator boundary. Neither may turn the existing
        # single child into a branch or consume its own confirmation on refusal.
        candidates = [self.competing_child, self.competing_child_two]
        approvals: list[tuple[str, str]] = []
        for candidate in candidates:
            sql = f"CREATE EDITION {candidate} AS CHILD OF {self.parent}"
            preview = self.action_preview("oracle_preview_sql", {"sql": sql})
            approvals.append((sql, token_from(preview, "execute_confirmation", "competing child preview")))

        def apply_competing(index: int, sql: str, confirm: str) -> tuple[dict, dict]:
            return self.action_execute(
                "oracle_execute",
                {"sql": sql, "commit": True, "confirm": confirm},
                f"synthetic-editions-competing-child-{index}",
            )

        self.harness.grant = "execute"
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            replies = list(
                executor.map(
                    lambda item: apply_competing(item[0], item[1][0], item[1][1]),
                    enumerate(approvals, start=1),
                )
            )
        self.harness.grant = "none"
        for result, content in replies:
            require(result.get("isError") is True, "concurrent competing child apply must be refused")
            reason = content.get("structured_reason")
            require(isinstance(reason, dict) and reason.get("category") == "ONE_CHILD_EDITION", "second child must return typed ONE_CHILD_EDITION")
            require(int(content.get("ora_code", 0)) == 38807, "second child refusal must surface ORA-38807 honestly")
        return {
            "concurrent_requests": 2,
            "typed_refusal": "ONE_CHILD_EDITION",
            "ora_code": 38807,
            "database_execute": False,
        }

    def not_editionable_refusal(self) -> dict:
        status, response = self.operator(
            "/operator/v1/actions/preview",
            {
                "tool": "oracle_create_or_replace",
                "arguments": {"source_code": f"CREATE TABLE E2E_ED_TABLE_{self.child[-10:]} (ID NUMBER)"},
            },
        )
        require(status == 200, "non-editionable preview must return an MCP refusal envelope")
        _, content = error_content(response_data(response, "/operator/v1/actions/preview"), "non-editionable table stage")
        reason = content.get("structured_reason")
        require(isinstance(reason, dict) and reason.get("category") == "NOT_EDITIONABLE", "table staging must return typed NOT_EDITIONABLE")
        return {"typed_refusal": "NOT_EDITIONABLE", "database_execute": False}

    def test_in_child(self) -> dict:
        self.confirmed_execute(
            f"ALTER SESSION SET EDITION = {self.child}",
            "synthetic-editions-enter-child",
        )
        self.confirmed_execute(
            f"CREATE OR REPLACE EDITIONABLE VIEW {self.view} AS SELECT 'SYNTHETIC_EDITION_CHILD' AS EDITION_MARKER FROM dual",
            "synthetic-editions-child-view",
        )
        result, content = self.action_execute(
            "oracle_query",
            {"sql": f"SELECT EDITION_MARKER FROM {self.view}"},
            "synthetic-editions-query-child-view",
        )
        require(result.get("isError") is not True, "child-edition view query must succeed")
        require(row_value(content, "EDITION_MARKER") == "SYNTHETIC_EDITION_CHILD", "child session must observe its editioned view definition")
        require(self.query_current_edition() == self.child, "ALTER SESSION must set the synthetic child edition")
        return {"child_session_verified": True, "marker": "synthetic child"}

    def default_flip(self, action: str, target: str) -> dict:
        canonical_sql = f"ALTER DATABASE DEFAULT EDITION = {target}"
        preview = self.action_preview("oracle_preview_sql", {"sql": canonical_sql})
        require(preview.get("required_level") == "ADMIN", "default-edition preview must remain ADMIN-gated")
        confirm = token_from(preview, "execute_confirmation", f"{action} default flip preview")
        self.harness.grant = "execute"
        status, response = self.operator(
            f"/operator/v1/edition-proposals/{action}",
            {
                "proposal_id": self.proposal_id,
                "confirm": confirm,
                "idempotency_key": f"synthetic-editions-{action}",
            },
        )
        self.harness.grant = "none"
        require(status == 200, f"reviewed {action} must reach the guarded action seam")
        data = response_data(response, f"/operator/v1/edition-proposals/{action}")
        require(data.get("action") == action and data.get("status") == "forwarded", f"reviewed {action} must be forwarded only through guarded execution")
        reclassified = data.get("reclassified")
        require(isinstance(reclassified, dict) and reclassified.get("required_level") == "ADMIN" and reclassified.get("stored_proposal_is_authority") is False, f"{action} must freshly classify canonical ADMIN SQL")
        result, content = mcp_content(data, f"{action} default flip")
        require(result.get("isError") is not True and content.get("executed") is True, f"{action} default flip must execute after ADMIN confirmation")
        if action == "rollback":
            scope = data.get("rollback_scope")
            require(isinstance(scope, dict) and scope.get("changes_default_edition_for") == "new_sessions_only" and scope.get("not_a_global_instant_undo") is True, "rollback must honestly state its new-sessions-only limit")
            self.merged = False
        else:
            self.merged = True
        return {"action": action, "admin_gated": True, "audit_bound": True}

    def fresh_session_observes(self, expected_edition: str, expected_marker: str, name: str) -> dict:
        state = Path(self.args.run_dir) / f"witness-{name}-state"
        session = McpSession(
            Path(self.args.binary),
            "editions",
            self.witness_config,
            state,
            self.witness_environment,
            Path(self.args.run_dir) / f"witness-{name}.stderr",
        )
        try:
            session.initialize()
            current = row_value(session.query("SELECT SYS_CONTEXT('USERENV', 'CURRENT_EDITION_NAME') AS CURRENT_EDITION FROM dual"), "CURRENT_EDITION")
            marker = row_value(session.query(f"SELECT EDITION_MARKER FROM {self.view}"), "EDITION_MARKER")
        finally:
            session.close()
        require(current == expected_edition, "fresh database session must observe the reviewed default edition")
        require(marker == expected_marker, "fresh database session must observe the corresponding editioned view")
        return {"fresh_session": True, "default_edition": "expected", "marker": "expected"}

    def verify_audit(self) -> dict:
        path = Path(self.args.audit_file)
        require(path.exists(), "primary served audit chain must exist")
        records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
        require(len(records) >= 12, "primary audit chain must record the governed lifecycle")
        tools = {record.get("tool") for record in records}
        require("oracle_set_session_level" in tools, "audit chain must record the ADMIN step-up")
        require("oracle_execute" in tools, "audit chain must record guarded lifecycle and default flips")
        require("operator_api" in tools, "audit chain must record operator proposal and default-flip routes")
        return {"operator_and_guarded_actions_audited": True, "record_count_at_least": 12}

    def cleanup(self) -> None:
        # Cleanup remains inside the same guarded path.  A failure after merge
        # must first re-flip the default, then restore the initial default before
        # the transient parent can be retired.  This never treats an edition
        # rollback as a global undo.
        if not self.parent_created or not self.initial_edition:
            return
        try:
            if self.merged:
                self.default_flip("rollback", self.parent)
            self.confirmed_execute(
                f"ALTER SESSION SET EDITION = {self.initial_edition}",
                "synthetic-editions-cleanup-enter-base",
            )
            self.confirmed_execute(
                f"ALTER DATABASE DEFAULT EDITION = {self.initial_edition}",
                "synthetic-editions-cleanup-restore-default",
            )
            if self.child_created:
                self.confirmed_execute(
                    f"DROP EDITION {self.child} CASCADE",
                    "synthetic-editions-cleanup-drop-child",
                )
            self.confirmed_execute(
                f"DROP EDITION {self.parent} CASCADE",
                "synthetic-editions-cleanup-drop-parent",
            )
        except StepFailure:
            self.harness.emit("editions_cleanup", "teardown", "fail", "cleanup failed after primary lifecycle evidence was recorded")
            raise

    def run(self) -> None:
        try:
            self.harness.step("admin_step_up", self.elevate_admin)
            self.harness.step("propose_and_review", self.draft_and_review)
            self.harness.step("apply_single_child", self.create_parent_and_child)
            self.harness.step("one_child_refusal", self.competing_child_refusal)
            self.harness.step("not_editionable_refusal", self.not_editionable_refusal)
            self.harness.step("test_under_child_edition", self.test_in_child)
            self.harness.step("merge_admin_audited", lambda: self.default_flip("merge", self.child))
            self.harness.step(
                "merge_new_session",
                lambda: self.fresh_session_observes(self.child, "SYNTHETIC_EDITION_CHILD", "after-merge"),
            )
            self.harness.step("rollback_admin_audited", lambda: self.default_flip("rollback", self.parent))
            self.harness.step(
                "rollback_new_session",
                lambda: self.fresh_session_observes(self.parent, "SYNTHETIC_EDITION_PARENT", "after-rollback"),
            )
            self.harness.step("audit_binding", self.verify_audit)
        except StepFailure:
            # Preserve the primary failure; cleanup is still attempted and logs
            # any independent failure without disguising the original evidence.
            try:
                self.cleanup()
            except StepFailure:
                pass
            raise
        else:
            self.cleanup()


def write_config(path: Path, audit_path: Path, dsn: str, user: str, audience: str, operator_principal: str) -> None:
    config = f'''schema_version = 2
default_profile = "editions"

[audit]
path = "{audit_path}"
key_id = "synthetic-editions-e2e"
key_ref = "env:E2E_EDITIONS_AUDIT_KEY"

[http.oauth]
resource = "{audience}"
allowed_issuers = ["{ISSUER}"]
authorization_servers = ["{ISSUER}"]
required_scopes = ["{OAUTH_SCOPE}"]
hs256_secret_ref = "env:E2E_EDITIONS_OAUTH_SECRET"

[http.operator]
allow_loopback_owner = false
allowed_subjects = ["{operator_principal}"]

[[profiles]]
name = "editions"
description = "synthetic editions lifecycle E2E profile"
connect_string = "{dsn}"
username = "{user}"
credential_ref = "env:E2E_EDITIONS_DB_PASSWORD"
max_level = "ADMIN"
default_level = "READ_ONLY"
'''
    private_write(path, config)


def run(args: argparse.Namespace) -> None:
    run_dir = Path(args.run_dir)
    run_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    dsn = safe_toml_scalar("E2E_EDITIONS_DSN", os.environ["E2E_EDITIONS_DSN"])
    user = safe_toml_scalar("E2E_EDITIONS_USER", os.environ["E2E_EDITIONS_USER"])
    password = os.environ["E2E_EDITIONS_PASSWORD"]
    require(bool(password), "live editions lane needs its supplied test password")
    binary = Path(args.binary)
    require(binary.is_file() and os.access(binary, os.X_OK), "configured editions binary is not executable")

    port = free_loopback_port()
    audience = f"http://127.0.0.1:{port}/mcp"
    audit_key = secrets.token_hex(32)
    oauth_secret = secrets.token_hex(32)
    principal = oauth_principal_key()
    config = run_dir / "profiles.toml"
    witness_config = run_dir / "witness-profiles.toml"
    write_config(config, Path(args.audit_file), dsn, user, audience, principal)
    write_config(witness_config, run_dir / "witness-audit.jsonl", dsn, user, audience, principal)
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("ORACLEMCP_")
    }
    environment.update(
        {
            "E2E_EDITIONS_DB_PASSWORD": password,
            "E2E_EDITIONS_AUDIT_KEY": audit_key,
            "E2E_EDITIONS_OAUTH_SECRET": oauth_secret,
        }
    )
    token = mint_oauth_token(audience, oauth_secret)
    harness = Harness(Path(args.evidence))
    server = ServedServer(binary, run_dir, config, password, audit_key, oauth_secret, port)
    try:
        harness.emit("served_operator", "setup", "running", "starting authenticated local operator surface")
        server.wait_ready()
        scenario = EditionsScenario(args, harness, server, token, witness_config, environment)
        scenario.run()
    finally:
        server.close()
        harness.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--lane", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--audit-file", required=True)
    parser.add_argument("--evidence", required=True)
    args = parser.parse_args()
    try:
        run(args)
    except LivePrerequisiteUnavailable as error:
        print(f"editions e2e skipped: {error}", file=sys.stderr)
        raise SystemExit(77) from error
    except (KeyError, OSError, StepFailure, json.JSONDecodeError) as error:
        print(f"editions e2e failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
