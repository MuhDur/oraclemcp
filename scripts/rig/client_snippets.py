#!/usr/bin/env python3
"""Prove setup snippets with installed MCP clients, not protocol stand-ins.

The runner starts each vendor CLI in an isolated HOME and traces its stdio
exchange with the configured oraclemcp process. A pass requires the real client
to request tools/list and the server to return a non-empty tool array. The
digest is over canonical JSON for that returned array.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
import tomllib
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CLIENTS_DIR = ROOT / "target/e2e/clients"
REAL_HOME = Path.home()


@dataclass(frozen=True)
class Adapter:
    name: str
    binary: str
    setup_field: str
    config_relative_path: str
    version_args: tuple[str, ...]
    run_args: tuple[str, ...]
    headless_listing: bool = True


_TRUSTED_ADAPTERS = (
    Adapter("claude", "claude", "claude_mcp_json", ".claude.json", ("--version",), ("mcp", "list")),
    Adapter("cursor", "cursor-agent", "cursor_mcp_json", ".cursor/mcp.json", ("--version",), ("mcp", "list")),
    Adapter("vscode", "code", "vscode_mcp_json", ".vscode/mcp.json", ("--version",), (), False),
    Adapter("codex", "codex", "codex_config_toml", ".codex/config.toml", ("--version",),
            ("-c", 'model_reasoning_effort="low"', "exec", "--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only", "--json",
             "List the names of tools exposed by the oracle MCP server. Do not call any tool.")),
    Adapter("gemini", "gemini", "gemini_settings_json", ".gemini/settings.json", ("--version",), ("mcp", "list")),
)
ADAPTERS = {adapter.name: adapter for adapter in _TRUSTED_ADAPTERS}


class ProofError(RuntimeError):
    pass


def reject_untrusted_adapter(adapter: Adapter) -> None:
    if not any(adapter is trusted for trusted in _TRUSTED_ADAPTERS):
        raise ProofError("refusing untrusted or planted client adapter")


def render_config(adapter: Adapter, setup: dict[str, Any]) -> str:
    reject_untrusted_adapter(adapter)
    value = setup.get(adapter.setup_field)
    if adapter.name == "codex":
        if not isinstance(value, str) or "[mcp_servers.oracle]" not in value:
            raise ProofError("setup output lacks the Codex TOML snippet")
        return value
    if not isinstance(value, dict):
        raise ProofError(f"setup output lacks {adapter.setup_field}")
    if adapter.name == "vscode":
        server = value.get("servers", {}).get("oracle", {})
        if server.get("type") != "stdio":
            raise ProofError("VS Code snippet must declare a stdio server")
    else:
        server = value.get("mcpServers", {}).get("oracle", {})
    if not isinstance(server, dict) or not isinstance(server.get("command"), str):
        raise ProofError(f"setup output has an invalid {adapter.name} server snippet")
    if not isinstance(server.get("args"), list) or not all(isinstance(arg, str) for arg in server["args"]):
        raise ProofError(f"setup output has invalid {adapter.name} server args")
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _frames(stream: bytes):
    """Yield JSON values from MCP Content-Length or line-delimited stdio."""
    remaining = stream
    while remaining:
        while remaining.startswith((b"\r\n", b"\n")):
            remaining = remaining[2:] if remaining.startswith(b"\r\n") else remaining[1:]
        if not remaining:
            break
        if remaining.startswith(b"Content-Length:"):
            split = remaining.find(b"\r\n\r\n")
            if split < 0:
                break
            header = remaining[:split].decode("ascii", "replace")
            match = re.search(r"(?im)^Content-Length:\s*(\d+)\s*$", header)
            if not match:
                break
            size = int(match.group(1))
            start = split + 4
            if len(remaining) < start + size:
                break
            raw = remaining[start : start + size]
            remaining = remaining[start + size :]
        else:
            end = remaining.find(b"\n")
            if end < 0:
                raw = remaining
                remaining = b""
            else:
                raw = remaining[:end].strip()
                remaining = remaining[end + 1 :]
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            yield value


_SYSCALL_STRING = re.compile(r"^(read|write)\((\d+), (\"(?:\\.|[^\"\\])*\"), \d+\) = (\d+)")


def _trace_streams(trace_prefix: Path) -> dict[int, dict[str, bytearray]]:
    streams: dict[int, dict[str, bytearray]] = {}
    for path in trace_prefix.parent.glob(trace_prefix.name + ".*"):
        try:
            pid = int(path.name.rsplit(".", 1)[1])
        except ValueError:
            continue
        channels = streams.setdefault(pid, {"in": bytearray(), "out": bytearray()})
        for line in path.read_text(errors="replace").splitlines():
            match = _SYSCALL_STRING.match(line)
            if not match:
                continue
            call, fd_text, quoted, result = match.groups()
            fd = int(fd_text)
            try:
                # strace escapes each original byte as C octal/hex; Latin-1
                # maps the decoded code point back to that byte without
                # double-encoding UTF-8 tool descriptions.
                data = ast.literal_eval(quoted).encode("latin-1")
            except (SyntaxError, ValueError, UnicodeEncodeError):
                continue
            data = data[: int(result)]
            if call == "read" and fd == 0:
                channels["in"].extend(data)
            elif call == "write" and fd == 1:
                channels["out"].extend(data)
    return streams


def tools_list_exchange(trace_prefix: Path) -> tuple[list[dict[str, Any]], str]:
    for channels in _trace_streams(trace_prefix).values():
        requests = [value for value in _frames(bytes(channels["in"])) if value.get("method") == "tools/list"]
        responses = {json.dumps(value.get("id"), sort_keys=True): value
                     for value in _frames(bytes(channels["out"])) if "id" in value and "result" in value}
        pages = []
        for request in requests:
            response = responses.get(json.dumps(request.get("id"), sort_keys=True))
            if response is None:
                continue
            result = response.get("result", {})
            if not isinstance(result, dict):
                continue
            page = result.get("tools")
            if isinstance(page, list):
                params = request.get("params")
                cursor = params.get("cursor") if isinstance(params, dict) else None
                pages.append((cursor, page, result.get("nextCursor")))
        if pages:
            first = next((page for cursor, page, _ in pages if cursor is None), None)
            if first is None:
                continue
            tools = list(first)
            next_cursor = next_cursor_for(pages, None)
            seen = set()
            while next_cursor is not None and next_cursor not in seen:
                if not isinstance(next_cursor, str):
                    raise ProofError("server returned an invalid tools/list pagination cursor")
                seen.add(next_cursor)
                matching = next((page for cursor, page, _ in pages if cursor == next_cursor), None)
                if matching is None:
                    raise ProofError("client/server MCP exchange omitted a requested tools/list page")
                tools.extend(matching)
                next_cursor = next_cursor_for(pages, next_cursor)
            if tools:
                canonical = json.dumps(tools, sort_keys=True, separators=(",", ":")).encode()
                return tools, hashlib.sha256(canonical).hexdigest()
    raise ProofError("real client session did not receive a non-empty tools/list response")


def next_cursor_for(pages: list[tuple[Any, list[dict[str, Any]], Any]], cursor: Any) -> Any:
    return next((next_cursor for request_cursor, _, next_cursor in pages if request_cursor == cursor), None)


def artifact_for(*, client: str, client_version: str, launch_command: list[str], transport: str,
                 server_launch_command: list[str], exit_status: int, proof_source: str,
                 tools: list[dict[str, Any]], digest: str) -> dict[str, Any]:
    if proof_source != "live_client_stdio_trace":
        raise ProofError("schema/parser-only and mock-client proof cannot create a live artifact")
    if exit_status != 0 or not tools or not digest:
        raise ProofError("live client proof is incomplete")
    artifact = {
        "client": client,
        "client_version": client_version,
        "launch_command": launch_command,
        "server_launch_command": server_launch_command,
        "transport": transport,
        "tools_list_sha256": digest,
        "exit_status": exit_status,
        "proof_source": proof_source,
        "tools_count": len(tools),
    }
    validate_artifact(artifact)
    return artifact


def validate_artifact(artifact: dict[str, Any]) -> None:
    required = {"client", "client_version", "launch_command", "server_launch_command", "transport", "tools_list_sha256", "exit_status", "proof_source", "tools_count"}
    if not required.issubset(artifact):
        raise ProofError("client artifact is missing required fields")
    if not isinstance(artifact["client_version"], str) or not artifact["client_version"].strip():
        raise ProofError("client artifact has no recorded client version")
    if artifact["transport"] != "stdio" or artifact["exit_status"] != 0:
        raise ProofError("client artifact does not record a successful stdio run")
    if not re.fullmatch(r"[0-9a-f]{64}", str(artifact["tools_list_sha256"])):
        raise ProofError("client artifact has an invalid tools/list SHA-256")
    if not isinstance(artifact["launch_command"], list) or not artifact["launch_command"]:
        raise ProofError("client artifact has no launch command")
    if not isinstance(artifact["server_launch_command"], list) or not artifact["server_launch_command"]:
        raise ProofError("client artifact has no server launch command")
    if not isinstance(artifact["tools_count"], int) or artifact["tools_count"] <= 0:
        raise ProofError("client artifact has no served tools")


def _setup_output(binary: str) -> dict[str, Any]:
    result = subprocess.run([binary, "--json", "setup", "--profile", "client_snippets"],
                            text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise ProofError(f"oraclemcp setup failed with exit {result.returncode}: {result.stderr.strip()}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ProofError(f"oraclemcp setup did not emit JSON: {exc}") from exc
    if value.get("kind") != "oraclemcp_setup":
        raise ProofError("setup output has unexpected kind")
    return value


def _write_adapter_config(adapter: Adapter, setup: dict[str, Any], home: Path) -> Path:
    config = home / adapter.config_relative_path
    config.parent.mkdir(parents=True, exist_ok=True)
    rendered = render_config(adapter, setup)
    if adapter.name == "codex":
        config.write_text(rendered)
        return config
    if adapter.name == "gemini":
        # Gemini checks for a selected provider auth method before it starts
        # MCP discovery. Carry only the non-secret auth mode from the host's
        # local settings; the mcpServers snippet itself remains setup output.
        selected_type = None
        source_settings = REAL_HOME / ".gemini/settings.json"
        try:
            existing = json.loads(source_settings.read_text())
            selected_type = existing.get("security", {}).get("auth", {}).get("selectedType")
        except (OSError, ValueError, AttributeError):
            pass
        value = json.loads(rendered)
        if isinstance(selected_type, str) and selected_type:
            value["security"] = {"auth": {"selectedType": selected_type}}
        rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    config.write_text(rendered)
    return config


def _link_client_auth_file(home: Path, relative_path: str, source_home: Path) -> None:
    """Let a CLI reuse its existing local login without copying credentials."""
    source = source_home / relative_path
    target = home / relative_path
    if source.is_file() and not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(source)


def _version(adapter: Adapter, binary_path: str, env: dict[str, str]) -> str:
    result = subprocess.run([binary_path, *adapter.version_args], env=env, text=True,
                            capture_output=True, check=False)
    version = (result.stdout or result.stderr).strip()
    if result.returncode != 0 or not version:
        raise ProofError(f"{adapter.binary} --version failed with exit {result.returncode}")
    return version


def _safe_exit_reason(result: subprocess.CompletedProcess[str]) -> str:
    output = f"{result.stdout}\n{result.stderr}"
    if "IneligibleTierError" in output and "UNSUPPORTED_CLIENT" in output:
        return "Gemini CLI rejected the stored provider entitlement (IneligibleTierError: UNSUPPORTED_CLIENT)"
    return f"client exited with status {result.returncode}"


def run_client(adapter: Adapter, setup: dict[str, Any], binary: str) -> dict[str, Any]:
    reject_untrusted_adapter(adapter)
    binary_path = shutil.which(adapter.binary)
    if not binary_path:
        return {"client": adapter.name, "binary": adapter.binary, "status": "blocked", "reason": "binary_unavailable"}
    if not adapter.headless_listing:
        return {"client": adapter.name, "binary": adapter.binary, "status": "blocked", "reason": "no_headless_tools_listing_mode"}
    runs_dir = CLIENTS_DIR / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    home = Path(tempfile.mkdtemp(prefix=f"{adapter.name}-", dir=runs_dir))
    env = os.environ.copy()
    env["HOME"] = str(home)
    env["ORACLEMCP_CONFIG"] = str(home / ".config/oraclemcp/profiles.toml")
    env["CARGO_TARGET_DIR"] = os.environ.get("CARGO_TARGET_DIR", str(ROOT / "target"))
    profile_toml = setup.get("profiles_toml")
    if not isinstance(profile_toml, str):
        raise ProofError("setup output lacks the offline profile template")
    Path(env["ORACLEMCP_CONFIG"]).parent.mkdir(parents=True, exist_ok=True)
    Path(env["ORACLEMCP_CONFIG"]).write_text(profile_toml)
    if adapter.name == "codex":
        codex_home = home / ".codex"
        codex_home.mkdir(parents=True, exist_ok=True)
        source_codex_home = Path(os.environ.get("CODEX_HOME", REAL_HOME / ".codex"))
        _link_client_auth_file(codex_home, "auth.json", source_codex_home)
        env["CODEX_HOME"] = str(codex_home)
    if adapter.name == "gemini":
        # This host's installed Bun launcher resolves ~/.bun through HOME;
        # point that runtime path at the installed CLI without sharing config.
        bun_home = REAL_HOME / ".bun"
        if bun_home.is_dir():
            (home / ".bun").symlink_to(bun_home, target_is_directory=True)
        _link_client_auth_file(home, ".gemini/oauth_creds.json", REAL_HOME)
        _link_client_auth_file(home, ".gemini/google_accounts.json", REAL_HOME)
    config_path = _write_adapter_config(adapter, setup, home)
    version = _version(adapter, binary_path, env)
    command = [binary_path, *adapter.run_args]
    if adapter.name == "gemini":
        command.insert(1, "--skip-trust")
    trace_prefix = home / "strace"
    traced = ["strace", "-ff", "-qq", "-s", "2000000", "-e", "trace=read,write",
              "-e", "trace-fds=0,1", "-o", str(trace_prefix), "--", *command]
    result = subprocess.run(traced, env=env, cwd=home, text=True, capture_output=True,
                            check=False, timeout=240)
    try:
        tools, digest = tools_list_exchange(trace_prefix)
    except ProofError as exc:
        if result.returncode != 0:
            return {"client": adapter.name, "client_version": version, "launch_command": command,
                    "transport": "stdio", "exit_status": result.returncode, "status": "fail",
                    "reason": f"{_safe_exit_reason(result)}; {exc}"}
        raise
    if result.returncode != 0:
        return {"client": adapter.name, "client_version": version, "launch_command": command,
                "transport": "stdio", "tools_list_sha256": digest, "tools_count": len(tools),
                "exit_status": result.returncode, "status": "fail", "reason": _safe_exit_reason(result)}
    snippet = setup[adapter.setup_field]
    if adapter.name == "codex":
        parsed = tomllib.loads(snippet)
        server = parsed["mcp_servers"]["oracle"]
        server_launch_command = [server["command"], *server["args"]]
    else:
        key = "servers" if adapter.name == "vscode" else "mcpServers"
        server = snippet[key]["oracle"]
        server_launch_command = [server["command"], *server["args"]]
    artifact = artifact_for(
        client=adapter.name,
        client_version=version,
        launch_command=command,
        server_launch_command=server_launch_command,
        transport="stdio",
        exit_status=result.returncode,
        proof_source="live_client_stdio_trace",
        tools=tools,
        digest=digest,
    )
    artifact["status"] = "pass"
    artifact["config_path"] = adapter.config_relative_path
    return artifact


def selftest() -> None:
    golden = {
        "kind": "oraclemcp_setup",
        "claude_mcp_json": {"mcpServers": {"oracle": {"command": "/tmp/oraclemcp", "args": ["serve", "--profile", "client_snippets", "--allow-no-auth"]}}},
        "cursor_mcp_json": {"mcpServers": {"oracle": {"command": "/tmp/oraclemcp", "args": ["serve", "--profile", "client_snippets", "--allow-no-auth"]}}},
        "vscode_mcp_json": {"servers": {"oracle": {"type": "stdio", "command": "/tmp/oraclemcp", "args": ["serve", "--profile", "client_snippets", "--allow-no-auth"]}}},
        "gemini_settings_json": {"mcpServers": {"oracle": {"command": "/tmp/oraclemcp", "args": ["serve", "--profile", "client_snippets", "--allow-no-auth"]}}},
        "codex_config_toml": "[mcp_servers.oracle]\ncommand = '/tmp/oraclemcp'\nargs = ['serve', '--profile', 'client_snippets', '--allow-no-auth']\n",
    }
    for adapter in _TRUSTED_ADAPTERS:
        assert render_config(adapter, golden)
    planted = Adapter("claude", "mock-client", "claude_mcp_json", ".claude.json", ("--version",), ())
    try:
        ADAPTERS["planted-mock"] = planted
        run_client(ADAPTERS["planted-mock"], golden, "/tmp/oraclemcp")
    except ProofError:
        pass
    else:
        raise AssertionError("planted mock client adapter was accepted")
    finally:
        ADAPTERS.pop("planted-mock", None)
    try:
        artifact_for(client="claude", client_version="fake", launch_command=["claude"],
                     transport="stdio", server_launch_command=["/tmp/oraclemcp", "serve"], exit_status=0, proof_source="schema_parser_only",
                     tools=[{"name": "oracle_query"}], digest="a" * 64)
    except ProofError:
        pass
    else:
        raise AssertionError("schema/parser-only artifact was accepted as live proof")
    valid = artifact_for(client="claude", client_version="2.1.282", launch_command=["claude", "-p"],
                         transport="stdio", server_launch_command=["/tmp/oraclemcp", "serve"],
                         exit_status=0, proof_source="live_client_stdio_trace",
                         tools=[{"name": "oracle_query"}], digest="a" * 64)
    assert valid["tools_count"] == 1
    try:
        validate_artifact({"client": "claude", "proof_source": "live_client_stdio_trace"})
    except ProofError:
        pass
    else:
        raise AssertionError("incomplete client artifact was accepted")
    expected = [{"name": "oracle_query", "inputSchema": {"type": "object"}}]
    frame = json.dumps({"jsonrpc": "2.0", "id": 7, "result": {"tools": expected}}, separators=(",", ":")).encode()
    wire = b"Content-Length: " + str(len(frame)).encode() + b"\r\n\r\n" + frame
    parsed = list(_frames(wire))
    assert parsed[0]["result"]["tools"] == expected
    print("client_snippets: selftest PASS (5 adapters, mock and schema-only refusals, MCP trace parser)")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--binary", default=os.environ.get("ORACLEMCP_BIN", "oraclemcp"))
    parser.add_argument("--client", choices=[*ADAPTERS, "all"], default="all")
    parser.add_argument("--summary", action="store_true", help="print one JSON summary for tier_c.sh")
    parser.add_argument("--summary-file", type=Path, help="write the tier-C clients section to this path")
    args = parser.parse_args()
    if args.selftest:
        selftest()
        return 0
    setup = _setup_output(args.binary)
    selected = _TRUSTED_ADAPTERS if args.client == "all" else (ADAPTERS[args.client],)
    records = []
    for adapter in selected:
        try:
            record = run_client(adapter, setup, args.binary)
        except (ProofError, OSError, subprocess.TimeoutExpired) as exc:
            record = {"client": adapter.name, "binary": adapter.binary, "status": "fail", "reason": str(exc)}
        records.append(record)
        print(json.dumps({key: record.get(key) for key in ("client", "client_version", "transport", "tools_list_sha256", "exit_status", "status", "reason")}, sort_keys=True), flush=True)
        if record.get("status") == "pass":
            CLIENTS_DIR.mkdir(parents=True, exist_ok=True)
            (CLIENTS_DIR / f"{adapter.name}.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    summary = {"clients": records}
    if args.summary_file:
        args.summary_file.parent.mkdir(parents=True, exist_ok=True)
        args.summary_file.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    if args.summary or args.summary_file:
        print(json.dumps(summary, sort_keys=True))
    return 1 if any(record.get("status") == "fail" for record in records) else 0


if __name__ == "__main__":
    sys.exit(main())
