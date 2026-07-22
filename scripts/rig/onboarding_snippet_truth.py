#!/usr/bin/env python3
"""C9 setup-printed onboarding snippet truth runner.

The runner intentionally avoids importing oraclemcp crates or MCP helper
libraries. It installs the binary from `git archive HEAD`, extracts client
snippets from real `oraclemcp setup` output, and drives raw JSON-RPC frames
against the emitted command/URL.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import time
import tomllib
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "2025-11-25"
MAX_WAIT_SECONDS = 20


def run(argv: list[str], *, env: dict[str, str], cwd: Path, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def checked(argv: list[str], *, env: dict[str, str], cwd: Path, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    result = run(argv, env=env, cwd=cwd, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {shlex.join(argv)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def extract_between(text: str, start: str, end: str) -> str:
    try:
        after = text.split(start, 1)[1]
        return after.split(end, 1)[0].strip()
    except IndexError as exc:
        raise RuntimeError(f"setup output missing block {start!r}..{end!r}") from exc


def extract_prefixed_line(text: str, prefix: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped[len(prefix) :].strip()
    raise RuntimeError(f"setup output missing line prefix {prefix!r}")


def initialize_frame(client_name: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": client_name, "version": "0.0.0-c9"},
        },
    }


def initialized_notification() -> dict[str, Any]:
    return {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}


def tools_list_frame() -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}


def parse_json_lines(stdout: str) -> list[dict[str, Any]]:
    frames = []
    for line in stdout.splitlines():
        if line.strip():
            frames.append(json.loads(line))
    return frames


def assert_initialize(reply: dict[str, Any]) -> None:
    if reply.get("jsonrpc") != "2.0":
        raise AssertionError(f"initialize reply is not JSON-RPC 2.0: {reply}")
    result = reply.get("result")
    if not isinstance(result, dict):
        raise AssertionError(f"initialize did not return a result: {reply}")
    if result.get("protocolVersion") != PROTOCOL_VERSION:
        raise AssertionError(f"initialize negotiated unexpected protocol: {reply}")
    server = result.get("serverInfo")
    if not isinstance(server, dict) or server.get("name") != "oraclemcp":
        raise AssertionError(f"initialize did not reach oraclemcp: {reply}")


def assert_tools(reply: dict[str, Any]) -> None:
    tools = reply.get("result", {}).get("tools")
    if not isinstance(tools, list):
        raise AssertionError(f"tools/list did not return tools: {reply}")
    names = {tool.get("name") for tool in tools if isinstance(tool, dict)}
    if "oracle_query" not in names or "oracle_capabilities" not in names:
        raise AssertionError(f"tools/list missed expected Oracle tools: {reply}")


def run_stdio_snippet(name: str, command: str, args: list[str], env: dict[str, str], artifact: Path) -> dict[str, Any]:
    frames = [initialize_frame(name), initialized_notification(), tools_list_frame()]
    stdin = "".join(json.dumps(frame, separators=(",", ":")) + "\n" for frame in frames)
    result = subprocess.run(
        [command, *args],
        input=stdin,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=MAX_WAIT_SECONDS,
        check=False,
    )
    (artifact / f"{name}.stdout").write_text(result.stdout)
    (artifact / f"{name}.stderr").write_text(result.stderr)
    if result.returncode != 0:
        raise AssertionError(f"{name} exited {result.returncode}; stderr={result.stderr[:800]}")
    replies = parse_json_lines(result.stdout)
    if len(replies) != 2:
        raise AssertionError(f"{name} expected initialize/tools replies, got {len(replies)}: {replies}")
    assert_initialize(replies[0])
    assert_tools(replies[1])
    return {"name": name, "status": "pass", "command": command, "args": args}


def reserve_7070() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 7070))
    sock.listen(1)
    return sock


def wait_for_port(port: int, child: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + MAX_WAIT_SECONDS
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise AssertionError(f"HTTP server exited before accepting connections: status={child.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("HTTP server did not accept loopback connections before deadline")


def read_http_response(sock: socket.socket) -> tuple[int, dict[str, Any] | None, str]:
    sock.settimeout(MAX_WAIT_SECONDS)
    chunks: list[bytes] = []
    while True:
        data = sock.recv(65536)
        if not data:
            break
        chunks.append(data)
    raw = b"".join(chunks).decode("utf-8", errors="replace")
    head, _, body = raw.partition("\r\n\r\n")
    status = int(head.splitlines()[0].split()[1]) if head else 0
    parsed: dict[str, Any] | None = None
    stripped = body.strip()
    if stripped.startswith("{"):
        parsed = json.loads(stripped)
    elif "data: " in body:
        for line in body.splitlines():
            if line.startswith("data: ") and line[6:].strip() != "null":
                parsed = json.loads(line[6:])
                break
    return status, parsed, raw


def post_initialize(url: str, headers: list[tuple[str, str]]) -> tuple[int, dict[str, Any] | None, str]:
    if url != "http://127.0.0.1:7070/mcp":
        raise AssertionError(f"C9 only permits the setup-printed loopback MCP URL, got {url}")
    body = json.dumps(initialize_frame("c9-http-claude"), separators=(",", ":"))
    header_lines = [
        "POST /mcp HTTP/1.1",
        "host: 127.0.0.1:7070",
        "content-type: application/json",
        "accept: application/json, text/event-stream",
        f"mcp-protocol-version: {PROTOCOL_VERSION}",
        f"content-length: {len(body)}",
        "connection: close",
    ]
    for key, value in headers:
        header_lines.append(f"{key}: {value}")
    request = "\r\n".join(header_lines) + "\r\n\r\n" + body
    with socket.create_connection(("127.0.0.1", 7070), timeout=MAX_WAIT_SECONDS) as sock:
        sock.sendall(request.encode("utf-8"))
        sock.shutdown(socket.SHUT_WR)
        return read_http_response(sock)


def parse_claude_registration(argv: list[str], env: dict[str, str], artifact: Path) -> tuple[str, list[tuple[str, str]]]:
    shim_dir = artifact / "shim-bin"
    shim_dir.mkdir(parents=True, exist_ok=True)
    capture = artifact / "claude-mcp-add.argv.json"
    shim = shim_dir / "claude"
    shim.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "open(os.environ['C9_CLAUDE_CAPTURE'], 'w').write(json.dumps(sys.argv[1:]))\n"
    )
    shim.chmod(0o755)
    shim_env = dict(env)
    shim_env["PATH"] = f"{shim_dir}:{shim_env.get('PATH', '')}"
    shim_env["C9_CLAUDE_CAPTURE"] = str(capture)
    result = run(argv, env=shim_env, cwd=artifact, timeout=10)
    if result.returncode != 0:
        raise AssertionError(f"claude snippet exited {result.returncode}: {result.stderr}")
    captured = json.loads(capture.read_text())
    if captured[:4] != ["mcp", "add", "oracle", "--transport"]:
        raise AssertionError(f"claude snippet did not register the oracle MCP server: {captured}")
    if len(captured) < 6 or captured[4] != "http":
        raise AssertionError(f"claude snippet did not request HTTP transport: {captured}")
    url = captured[5]
    headers: list[tuple[str, str]] = []
    index = 6
    while index < len(captured):
        arg = captured[index]
        if arg in {"--header", "-H"}:
            if index + 1 >= len(captured):
                raise AssertionError(f"missing value after {arg}: {captured}")
            key, sep, value = captured[index + 1].partition(":")
            if not sep:
                raise AssertionError(f"header lacks ':' separator: {captured[index + 1]}")
            headers.append((key.strip(), value.strip()))
            index += 2
            continue
        raise AssertionError(f"unsupported claude mcp add option in printed snippet: {arg}")
    return url, headers


def bearer_from_clients_issue_stdout(stdout: str) -> str:
    for line in stdout.splitlines():
        prefix = "bearer (shown once): "
        if line.startswith(prefix):
            bearer = line[len(prefix) :].strip()
            if bearer:
                return bearer
    raise AssertionError("clients issue output did not include the shown-once bearer")


def substitute_bearer_placeholder(argv: list[str], bearer: str) -> list[str]:
    return [arg.replace("<bearer>", bearer) for arg in argv]


def install_from_head(root: Path, artifact: Path) -> tuple[str, Path]:
    source_sha = checked(["git", "rev-parse", "HEAD"], env=os.environ.copy(), cwd=root).stdout.strip()
    source = artifact / "source"
    source.mkdir(parents=True, exist_ok=True)
    archive = subprocess.Popen(["git", "archive", "--format=tar", "HEAD"], cwd=root, stdout=subprocess.PIPE)
    extract = subprocess.run(["tar", "-xf", "-", "-C", str(source)], stdin=archive.stdout, text=False)
    if archive.stdout is not None:
        archive.stdout.close()
    archive_status = archive.wait()
    if archive_status != 0 or extract.returncode != 0:
        raise RuntimeError(f"git archive extraction failed: git={archive_status} tar={extract.returncode}")
    prefix = artifact / "prefix"
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(root / "target")
    checked(
        [
            "cargo",
            "install",
            "--path",
            str(source / "crates/oraclemcp"),
            "--root",
            str(prefix),
            "--debug",
            "--locked",
            "--force",
        ],
        env=env,
        cwd=source,
        timeout=300,
    )
    binary = prefix / "bin/oraclemcp"
    if not binary.exists():
        raise RuntimeError(f"installed binary not found: {binary}")
    return source_sha, binary


def configured_env(binary: Path, artifact: Path, profiles_toml: str) -> dict[str, str]:
    home = artifact / "home"
    config = artifact / "config/oraclemcp"
    state = artifact / "state"
    cache = artifact / "cache"
    tools = artifact / "tools.d"
    for path in [home, config, state, cache, tools]:
        path.mkdir(parents=True, exist_ok=True)
    profile_path = config / "profiles.toml"
    profile_path.write_text(profiles_toml)
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(artifact / "config"),
            "XDG_STATE_HOME": str(state),
            "XDG_CACHE_HOME": str(cache),
            "ORACLEMCP_CONFIG": str(profile_path),
            "ORACLEMCP_TOOLS_DIR": str(tools),
            "ORACLE_APP_PASSWORD": "c9-synthetic-password",
            "PATH": f"{binary.parent}:{env.get('PATH', '')}",
        }
    )
    env.pop("ORACLEMCP_STDIO_TOKEN", None)
    env.pop("CARGO_TARGET_DIR", None)
    return env


def run_http_snippet(binary: Path, setup_json: dict[str, Any], claude_argv: list[str], env: dict[str, str], artifact: Path) -> dict[str, Any]:
    # The setup output hard-codes port 7070. Reserving it first makes a port
    # collision an explicit fixture result instead of a stray server bind race.
    guard = reserve_7070()
    guard.close()
    issue_argv = setup_json["http_client_credentials"]["issue_once"]
    issue = checked([str(binary) if part == "oraclemcp" else part for part in issue_argv], env=env, cwd=artifact, timeout=30)
    bearer = bearer_from_clients_issue_stdout(issue.stdout)
    (artifact / "clients-issue.stdout.redacted").write_text("<redacted bearer output>\n")
    if issue.stderr:
        (artifact / "clients-issue.stderr").write_text(issue.stderr)
    serve_args = setup_json["http_client_credentials"]["serve_args"]
    server = subprocess.Popen(
        [str(binary), *serve_args, "--http-json-response", "--http-allowed-host", "127.0.0.1:7070"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        wait_for_port(7070, server)
        url, headers = parse_claude_registration(
            substitute_bearer_placeholder(claude_argv, bearer), env, artifact
        )
        status, body, raw = post_initialize(url, headers)
        (artifact / "http-initialize.raw").write_text(raw)
        if status != 200:
            raise AssertionError(f"HTTP initialize via printed Claude snippet returned status {status}: {body}")
        if body is None:
            raise AssertionError("HTTP initialize returned no JSON body")
        assert_initialize(body)
        return {"name": "http_client_credentials.claude_mcp_add", "status": "pass", "argv": claude_argv}
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
        if server.stderr is not None:
            stderr = server.stderr.read()
            if stderr:
                (artifact / "http-server.stderr").write_text(stderr)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["run", "xfail"], required=True)
    parser.add_argument("--artifact-dir", required=True)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]
    artifact = Path(args.artifact_dir).resolve()
    artifact.mkdir(parents=True, exist_ok=True)

    source_sha, binary = install_from_head(root, artifact)
    setup_config_path = artifact / "config/oraclemcp/profiles.toml"
    setup_tools_dir = artifact / "tools.d"
    setup_plain = checked(
        [
            str(binary),
            "setup",
            "--profile",
            "c9_ro",
            "--config-path",
            str(setup_config_path),
            "--tools-dir",
            str(setup_tools_dir),
        ],
        env=os.environ.copy(),
        cwd=root,
        timeout=30,
    ).stdout
    (artifact / "setup.stdout").write_text(setup_plain)
    setup_json = json.loads(
        checked(
            [
                str(binary),
                "--json",
                "setup",
                "--profile",
                "c9_ro",
                "--config-path",
                str(setup_config_path),
                "--tools-dir",
                str(setup_tools_dir),
            ],
            env=os.environ.copy(),
            cwd=root,
            timeout=30,
        ).stdout
    )

    profiles_toml = extract_between(setup_plain, "profiles.toml template:\n", "\n\nSnippet command:")
    env = configured_env(binary, artifact, profiles_toml)

    claude_block = extract_between(setup_plain, "Claude MCP JSON:\n", "\n\nCodex config TOML:")
    claude_json = json.loads(claude_block)
    claude_server = claude_json["mcpServers"]["oracle"]

    codex_block = extract_between(setup_plain, "Codex config TOML:\n", "\nHTTP per-client credentials:")
    codex_config = tomllib.loads(codex_block)
    codex_server = codex_config["mcp_servers"]["oracle"]

    claude_http = shlex.split(extract_prefixed_line(setup_plain, "claude: "))

    checks: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    for label, command, command_args in [
        ("claude_mcp_json", claude_server["command"], claude_server["args"]),
        ("codex_config_toml", codex_server["command"], codex_server["args"]),
    ]:
        try:
            checks.append(run_stdio_snippet(label, command, command_args, env, artifact))
        except Exception as exc:  # noqa: BLE001 - fixture records the wire failure
            failures.append({"name": label, "status": "fail", "reason": str(exc)})

    try:
        checks.append(run_http_snippet(binary, setup_json, claude_http, env, artifact))
    except Exception as exc:  # noqa: BLE001 - current C9 defect is captured here
        failures.append(
            {
                "name": "http_client_credentials.claude_mcp_add",
                "status": "fail",
                "reason": str(exc),
            }
        )

    secure_stdio_present = '"secure_stdio"' in setup_plain or "Secure stdio" in setup_plain
    summary = {
        "bead_id": "oraclemcp-091-c9-snippet-truth-00gb2",
        "source_sha": source_sha,
        "installed_binary": str(binary),
        "setup_output": str(artifact / "setup.stdout"),
        "mode": args.mode,
        "extracted_from_real_setup_output": True,
        "secure_stdio_snippet_present": secure_stdio_present,
        "checks": checks,
        "failures": failures,
    }
    if args.mode == "xfail":
        expected = {failure["name"] for failure in failures}
        summary["expected_failure_mode"] = True
        summary["expected_failures_observed"] = "http_client_credentials.claude_mcp_add" in expected
    else:
        summary["expected_failure_mode"] = False
        summary["expected_failures_observed"] = False
    (artifact / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")

    if failures and args.mode == "run":
        print(json.dumps(summary, sort_keys=True))
        return 10
    if args.mode == "xfail" and not summary["expected_failures_observed"]:
        print(json.dumps(summary, sort_keys=True))
        return 11
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
