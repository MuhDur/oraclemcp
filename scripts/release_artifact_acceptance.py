#!/usr/bin/env python3
"""Execute a release binary or image and verify its advertised MCP tool surface."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

EXPECTED_TOOLS = {
    "oracle_plsql_parse",
    "oracle_plsql_analyze",
    "oracle_plsql_what_breaks",
    "oracle_plsql_lineage",
    "oracle_lineage",
    "oracle_plsql_sast",
    "oracle_plsql_doc",
    "oracle_plsql_live_snapshot",
    "oracle_plsql_blast_radius",
}


def run(argv: list[str], *, input_bytes: bytes | None = None, env: dict[str, str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(argv, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)


def frame(message: dict[str, object]) -> bytes:
    return json.dumps(message, separators=(",", ":")).encode() + b"\n"


def parse_frames(data: bytes) -> list[dict[str, object]]:
    messages = []
    for line in data.splitlines():
        if not line.strip():
            continue
        value = json.loads(line)
        if isinstance(value, dict):
            messages.append(value)
    return messages


def command_for(binary: str | None, image: str | None, mode: str, config: Path) -> list[str]:
    if image:
        container_config = "/tmp/oraclemcp-release-acceptance.toml"
        return [
            "docker", "run", "--rm", "-i",
            "--mount", f"type=bind,source={config.resolve()},target={container_config},readonly",
            "--env", f"ORACLEMCP_CONFIG={container_config}",
            "--entrypoint", "oraclemcp", image, *mode.split(),
        ]
    if not binary:
        raise RuntimeError("provide --binary or --image")
    return [str(Path(binary).resolve()), *mode.split()]


def main() -> int:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--binary")
    source.add_argument("--image")
    parser.add_argument("--target", required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="oraclemcp-release-acceptance-") as home:
        env = os.environ.copy()
        env.update({"HOME": home, "XDG_CONFIG_HOME": f"{home}/.config", "XDG_STATE_HOME": f"{home}/.local/state"})
        config = Path(home) / "profiles.toml"
        config.write_text(
            'schema_version = 2\n'
            'default_profile = "release_acceptance"\n\n'
            '[[profiles]]\n'
            'name = "release_acceptance"\n'
            'connect_string = "127.0.0.1:1/RELEASE_ACCEPTANCE"\n'
            'default_level = "READ_ONLY"\n'
            'max_level = "READ_ONLY"\n',
            encoding="utf-8",
        )
        env["ORACLEMCP_CONFIG"] = str(config)
        version = run(command_for(args.binary, args.image, "--version", config), env=env)
        if version.returncode != 0:
            raise RuntimeError(f"--version failed ({version.returncode}): {version.stderr.decode(errors='replace')}")
        info = run(command_for(args.binary, args.image, "--json info", config), env=env)
        if info.returncode != 0:
            raise RuntimeError(f"--json info failed ({info.returncode}): {info.stderr.decode(errors='replace')}")
        info_value = json.loads(info.stdout)
        if info_value.get("engine") is not True:
            raise RuntimeError(f"--json info did not report engine=true: {info_value}")
        info_tools = set(info_value.get("tools", []))
        missing_info = sorted(EXPECTED_TOOLS - info_tools)
        if missing_info:
            raise RuntimeError(f"--json info missing required tools: {missing_info}")
        doctor = run(command_for(args.binary, args.image, "--json doctor", config), env=env)
        if doctor.returncode != 0:
            raise RuntimeError(f"doctor failed ({doctor.returncode}): {doctor.stderr.decode(errors='replace')}")
        stdio = run(
            command_for(args.binary, args.image, "serve --allow-no-auth", config),
            input_bytes=b"".join(
                [
                    frame({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "release-artifact-acceptance", "version": "1"}}}),
                    frame({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
                    frame({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
                ]
            ),
            env=env,
        )
        if stdio.returncode != 0:
            raise RuntimeError(f"stdio MCP server failed ({stdio.returncode}): {stdio.stderr.decode(errors='replace')}")
        replies = {message.get("id"): message for message in parse_frames(stdio.stdout)}
        tools_reply = replies.get(2)
        if not isinstance(tools_reply, dict) or "result" not in tools_reply:
            raise RuntimeError(f"tools/list did not return a result: {replies}")
        tools = tools_reply["result"].get("tools", [])  # type: ignore[union-attr]
        names = {tool.get("name") for tool in tools if isinstance(tool, dict)}
        missing = sorted(EXPECTED_TOOLS - names)
        if missing:
            raise RuntimeError(f"tools/list missing required tools: {missing}; returned {sorted(names)}")
        print(f"target={args.target}")
        print(version.stdout.decode(errors="replace").strip())
        print(
            f"engine=true doctor=PASS tool_count={len(tools)} "
            f"required_tools={','.join(sorted(EXPECTED_TOOLS))}"
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # noqa: BLE001 - acceptance output must report subprocess diagnostics
        print(f"release-artifact-acceptance: FAIL: {error}", file=sys.stderr)
        raise SystemExit(1) from error
