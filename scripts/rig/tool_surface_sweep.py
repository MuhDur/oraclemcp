#!/usr/bin/env python3
"""R2 raw-wire tool-surface sweep for the Local Integrator Rig.

This client deliberately does not import oraclemcp crates, test helpers, or
MCP helper libraries. It installs the binary from a git-archive copy of HEAD
and talks line-delimited JSON-RPC over stdio like an external MCP client.
"""

from __future__ import annotations

import json
import os
import pathlib
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[2]
PROTOCOL_VERSION = "2025-11-25"
MAX_RESPONSE_BYTES = 1_048_576
EXPECTED_REGISTRY_CANONICAL = 34
EXPECTED_REGISTRY_ALIASES = 25
EXPECTED_REGISTRY_TOTAL = EXPECTED_REGISTRY_CANONICAL + EXPECTED_REGISTRY_ALIASES
EXPECTED_WIRE_TOTAL = EXPECTED_REGISTRY_TOTAL + 1
AUDIT_KEY = "0123456789abcdef0123456789abcdef"
FIXTURE_PASSWORD = (
    os.environ.get("ORACLEMCP_RIG_L1_FIXTURE_PASSWORD")
    or os.environ.get("PYO_TEST_MAIN_PASSWORD")
    or "testpw"
)
D9_PASSWORD = "D9_Governance_Test_42"
KNOWN_ERROR_CLASSES = {
    "OBJECT_NOT_FOUND",
    "INSUFFICIENT_PRIVILEGE",
    "SYNTAX_ERROR",
    "CONNECTION_FAILED",
    "RUNTIME_STATE_REQUIRED",
    "CHALLENGE_REQUIRED",
    "LEASE_REQUIRED",
    "FORBIDDEN_STATEMENT",
    "OPERATING_LEVEL_TOO_LOW",
    "BUSY",
    "AT_CAPACITY",
    "INVALID_ARGUMENTS",
    "POLICY_DENIED",
    "TIMEOUT",
    "TRANSIENT",
    "FLASHBACK_RETENTION_EXCEEDED",
    "FLASHBACK_DEFINITION_CHANGED",
    "FLASHBACK_NOT_FLASHBACKABLE",
    "FLASHBACK_CAPABILITY_UNAVAILABLE",
    "INTERNAL",
}
KNOWN_REASON_CATEGORIES = {
    "MULTI_STATEMENT_BATCH",
    "DYNAMIC_SQL",
    "TRANSACTION_CONTROL",
    "UNBALANCED_BLOCK",
    "PL_SQL_BLOCK",
    "REQUIRES_HIGHER_LEVEL",
    "COST_BUDGET_EXCEEDED",
    "BLOCK_LISTED",
    "UNPROVEN_SIDE_EFFECT",
    "POLICY_DENIED",
    "ONE_CHILD_EDITION",
    "NOT_EDITIONABLE",
    "OTHER",
}


def emit(event: str, phase: str, outcome: str, message: str, duration_ms: int = 0) -> None:
    row = {
        "event": event,
        "phase": phase,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_ms": duration_ms,
        "lane": "tool-surface",
        "subject": "raw-wire-client",
        "sid": str(os.getpid()),
        "profile": "matrix",
        "level": "READ_ONLY",
        "grant": "none",
        "outcome": outcome,
        "scenario": "rig_tool_surface_sweep",
        "seed": os.environ.get("ORACLEMCP_E2E_SEED", "0"),
        "message": message,
    }
    print(json.dumps(row, separators=(",", ":")), file=sys.stderr, flush=True)


def run(cmd: list[str], *, cwd: pathlib.Path = ROOT, env: dict[str, str] | None = None) -> str:
    started = time.monotonic()
    emit("command_start", "act", "running", " ".join(cmd))
    proc = subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True, check=False)
    elapsed = int((time.monotonic() - started) * 1000)
    if proc.returncode != 0:
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        emit("command_complete", "act", "fail", " ".join(cmd), elapsed)
        raise SystemExit(f"command failed with exit {proc.returncode}: {' '.join(cmd)}")
    emit("command_complete", "act", "pass", " ".join(cmd), elapsed)
    return proc.stdout


@dataclass(frozen=True)
class Profile:
    name: str
    max_level: str
    expect_admin_surface: bool


PROFILES = [
    Profile("read_only", "READ_ONLY", False),
    Profile("protected", "READ_ONLY", False),
    Profile("proxy_auth", "READ_ONLY", False),
    Profile("pooled", "ADMIN", True),
    Profile("drcp", "ADMIN", True),
]


class StdioClient:
    def __init__(self, binary: pathlib.Path, config: pathlib.Path, home: pathlib.Path, profile: str):
        env = {key: value for key, value in os.environ.items() if key in {"PATH", "LANG", "LC_ALL", "TERM"}}
        env.update(
            {
                "HOME": str(home / "home"),
                "XDG_STATE_HOME": str(home / "state"),
                "XDG_CONFIG_HOME": str(home / "xdg-config"),
                "ORACLEMCP_CONFIG": str(config),
                "ORACLEMCP_TOOLS_DIR": str(home / "tools.d"),
                "R2_SYNTH_PASSWORD": FIXTURE_PASSWORD,
                "R2_D9_PASSWORD": D9_PASSWORD,
                "R2_AUDIT_KEY": AUDIT_KEY,
            }
        )
        for key in list(env):
            if key.startswith("ORACLEMCP_") and key not in {"ORACLEMCP_CONFIG", "ORACLEMCP_TOOLS_DIR"}:
                del env[key]
        self.proc = subprocess.Popen(
            [str(binary), "--json", "serve", "--allow-no-auth", "--profile", profile],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
        )
        self.replies: "queue.Queue[tuple[int, dict[str, Any], bytes]]" = queue.Queue()
        self.stderr_lines: list[str] = []
        self.next_id = 1
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    def _read_stdout(self) -> None:
        assert self.proc.stdout is not None
        for raw in self.proc.stdout:
            if not raw.strip():
                continue
            value = json.loads(raw)
            request_id = value.get("id")
            if request_id is not None:
                self.replies.put((request_id, value, raw.encode("utf-8")))

    def _read_stderr(self) -> None:
        assert self.proc.stderr is not None
        for raw in self.proc.stderr:
            self.stderr_lines.append(raw.rstrip("\n"))

    def send_notification(self, method: str, params: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        frame = {"jsonrpc": "2.0", "method": method, "params": params}
        self.proc.stdin.write(json.dumps(frame, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: dict[str, Any] | None = None, timeout: float = 30.0) -> tuple[dict[str, Any], bytes]:
        request_id = self.next_id
        self.next_id += 1
        frame: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            frame["params"] = params
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(frame, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                reply_id, reply, raw = self.replies.get(timeout=0.1)
            except queue.Empty:
                if self.proc.poll() is not None:
                    raise AssertionError(
                        f"server exited while waiting for id={request_id}; stderr={self.stderr_lines[-20:]}"
                    )
                continue
            if reply_id == request_id:
                return reply, raw
            raise AssertionError(f"unexpected reply id {reply_id}; expected {request_id}: {reply}")
        raise AssertionError(f"timed out waiting for id={request_id}; stderr={self.stderr_lines[-20:]}")

    def close(self) -> None:
        if self.proc.stdin is not None:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        if self.proc.returncode != 0:
            raise AssertionError(f"server exited {self.proc.returncode}; stderr={self.stderr_lines[-20:]}")


def install_artifact(work: pathlib.Path) -> tuple[pathlib.Path, str]:
    source_sha = run(["git", "rev-parse", "HEAD"]).strip()
    source = work / "source"
    prefix = work / "prefix"
    source.mkdir(parents=True, exist_ok=True)
    prefix.mkdir(parents=True, exist_ok=True)
    archive = subprocess.Popen(["git", "-C", str(ROOT), "archive", "--format=tar", "HEAD"], stdout=subprocess.PIPE)
    tar = subprocess.run(["tar", "-x", "-C", str(source)], stdin=archive.stdout, text=False, check=False)
    if archive.stdout is not None:
        archive.stdout.close()
    archive_status = archive.wait()
    if archive_status != 0 or tar.returncode != 0:
        raise SystemExit("failed to archive HEAD for R2 source install")
    env = os.environ.copy()
    env.pop("CARGO_TARGET_DIR", None)
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
    )
    binary = prefix / "bin" / "oraclemcp"
    if not binary.exists() or not os.access(binary, os.X_OK):
        raise AssertionError(f"installed binary missing or not executable: {binary}")
    emit("install_artifact", "setup", "pass", f"source={source_sha} binary={binary}")
    return binary, source_sha


def write_config(path: pathlib.Path, audit_path: pathlib.Path) -> None:
    path.write_text(
        f'''schema_version = 2
default_profile = "read_only"

[audit]
path = "{audit_path}"
key_ref = "env:R2_AUDIT_KEY"
key_id = "r2-synthetic"

[[profiles]]
name = "read_only"
description = "R2 synthetic read-only Free23 profile"
connect_string = "//localhost:1522/FREEPDB1"
username = "pythontest"
credential_ref = "env:R2_SYNTH_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"

[[profiles]]
name = "protected"
description = "R2 synthetic protected Free23 profile"
connect_string = "//localhost:1522/FREEPDB1"
username = "pythontest"
credential_ref = "env:R2_SYNTH_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"
protected = true

[[profiles]]
name = "proxy_auth"
description = "R2 synthetic proxy-auth profile over D9 governance fixture"
connect_string = "//localhost:1522/FREEPDB1"
username = "ORACLEMCP_D9_PROXY"
credential_ref = "env:R2_D9_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"
[profiles.proxy_auth]
proxy_user = "ORACLEMCP_D9_PROXY"
target_schema = "ORACLEMCP_D9_TARGET"

[[profiles]]
name = "pooled"
description = "R2 synthetic pooled Free23 profile"
connect_string = "//localhost:1522/FREEPDB1"
username = "pythontest"
credential_ref = "env:R2_SYNTH_PASSWORD"
max_level = "ADMIN"
default_level = "READ_ONLY"
[profiles.pool]
max_size = 2
min_idle = 1
acquire_timeout_secs = 5
statement_cache_size = 20

[[profiles]]
name = "drcp"
description = "R2 synthetic DRCP routed Free23 profile"
connect_string = "//localhost:1522/FREEPDB1"
username = "pythontest"
credential_ref = "env:R2_SYNTH_PASSWORD"
max_level = "ADMIN"
default_level = "READ_ONLY"
[profiles.drcp]
pooled = true
connection_class = "ORACLEMCP_R2_SWEEP"
purity = "reuse"
''',
        encoding="utf-8",
    )


def assert_jsonrpc_envelope(profile: str, tool: str, reply: dict[str, Any], raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_RESPONSE_BYTES:
        raise AssertionError(f"{profile}/{tool}: response {len(raw)} bytes exceeds {MAX_RESPONSE_BYTES}")
    if reply.get("jsonrpc") != "2.0":
        raise AssertionError(f"{profile}/{tool}: malformed JSON-RPC envelope: {reply}")
    if "error" in reply:
        error = reply["error"]
        if not isinstance(error, dict) or "code" not in error or "message" not in error:
            raise AssertionError(f"{profile}/{tool}: malformed JSON-RPC error: {reply}")
        data = error.get("data")
        if isinstance(data, dict) and data.get("error_class") not in KNOWN_ERROR_CLASSES:
            raise AssertionError(f"{profile}/{tool}: unknown JSON-RPC error_class: {data}")
        return {"transport_error": True}
    result = reply.get("result")
    if not isinstance(result, dict):
        raise AssertionError(f"{profile}/{tool}: tools/call did not return object result: {reply}")
    if not isinstance(result.get("content"), list):
        raise AssertionError(f"{profile}/{tool}: missing MCP content array: {reply}")
    if "isError" not in result:
        raise AssertionError(f"{profile}/{tool}: missing MCP isError: {reply}")
    structured = result.get("structuredContent")
    if result.get("isError") is True:
        if not isinstance(structured, dict):
            raise AssertionError(f"{profile}/{tool}: tool error missing structuredContent: {reply}")
        error_class = structured.get("error_class")
        if error_class not in KNOWN_ERROR_CLASSES:
            raise AssertionError(f"{profile}/{tool}: unknown tool error_class {error_class}: {structured}")
        reason = structured.get("structured_reason")
        if reason is not None:
            category = reason.get("category") if isinstance(reason, dict) else None
            if category not in KNOWN_REASON_CATEGORIES:
                raise AssertionError(f"{profile}/{tool}: unknown structured_reason category {category}: {structured}")
    return result


def validate_output_schema(profile: str, tool: str, descriptor: dict[str, Any], result: dict[str, Any]) -> None:
    if result.get("isError") is True:
        return
    schema = descriptor.get("outputSchema")
    if not isinstance(schema, dict):
        return
    structured = result.get("structuredContent")
    if schema.get("type") == "object" and not isinstance(structured, dict):
        raise AssertionError(f"{profile}/{tool}: outputSchema wants object structuredContent: {result}")
    for required in schema.get("required", []):
        if isinstance(structured, dict) and required not in structured:
            raise AssertionError(f"{profile}/{tool}: outputSchema required key missing: {required}")


def tool_args(name: str) -> dict[str, Any]:
    if name == "oracle_capabilities":
        return {"detail_level": "compact"}
    return {"__r2_wire_sweep_invalid__": True}


def list_tools(client: StdioClient) -> list[dict[str, Any]]:
    reply, raw = client.request("tools/list")
    if len(raw) > MAX_RESPONSE_BYTES:
        raise AssertionError("tools/list exceeded response budget")
    tools = reply.get("result", {}).get("tools")
    if not isinstance(tools, list) or not tools:
        raise AssertionError(f"tools/list returned no tools: {reply}")
    names = [tool.get("name") for tool in tools]
    if len(names) != len(set(names)):
        raise AssertionError(f"tools/list contains duplicate names: {names}")
    return tools


def call_tool(client: StdioClient, name: str, args: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    return client.request("tools/call", {"name": name, "arguments": args}, timeout=45.0)


def preview_and_apply_admin(client: StdioClient, profile: Profile) -> bool:
    reply, raw = call_tool(client, "oracle_set_session_level", {"level": "ADMIN"})
    result = assert_jsonrpc_envelope(profile.name, "oracle_set_session_level.preview_admin", reply, raw)
    if not profile.expect_admin_surface:
        structured = result.get("structuredContent", {})
        gate = structured.get("gate", {})
        session = structured.get("session", {})
        if (
            result.get("isError") is True
            or structured.get("confirmation") is not None
            or gate.get("decision") != "blocked"
            or session.get("max_level") != "READ_ONLY"
            or session.get("has_active_elevation") is not False
        ):
            raise AssertionError(
                f"{profile.name}: READ_ONLY/protected ADMIN preview did not stay blocked: {result}"
            )
        return False
    if result.get("isError") is True:
        raise AssertionError(f"{profile.name}: ADMIN preview failed: {result}")
    confirmation = result.get("structuredContent", {}).get("confirmation", {})
    token = confirmation.get("confirm")
    if not isinstance(token, str) or not token:
        raise AssertionError(f"{profile.name}: ADMIN preview did not return confirmation token: {result}")
    reply, raw = call_tool(
        client,
        "oracle_set_session_level",
        {"level": "ADMIN", "execute": True, "confirm": token},
    )
    result = assert_jsonrpc_envelope(profile.name, "oracle_set_session_level.apply_admin", reply, raw)
    if result.get("isError") is True or result.get("structuredContent", {}).get("changed") is not True:
        raise AssertionError(f"{profile.name}: ADMIN apply failed: {result}")
    return True


def assert_registry_truth(profile: str, tools: list[dict[str, Any]], require_full: bool) -> dict[str, int]:
    names = [tool["name"] for tool in tools]
    has_cap = "oracle_capabilities" in names
    canonical = sum(1 for name in names if name.startswith("oracle_") and name != "oracle_capabilities")
    aliases = sum(1 for name in names if not name.startswith("oracle_"))
    if require_full:
        if len(names) != EXPECTED_WIRE_TOTAL or canonical != EXPECTED_REGISTRY_CANONICAL or aliases != EXPECTED_REGISTRY_ALIASES or not has_cap:
            raise AssertionError(
                f"{profile}: full ADMIN surface mismatch: total={len(names)} canonical={canonical} aliases={aliases} has_cap={has_cap}"
            )
    return {"wire_total": len(names), "canonical": canonical, "aliases": aliases, "has_capabilities": int(has_cap)}


def sweep_profile(binary: pathlib.Path, config: pathlib.Path, work: pathlib.Path, profile: Profile) -> dict[str, Any]:
    home = work / f"profile-{profile.name}"
    for child in ["home", "state", "xdg-config", "tools.d"]:
        (home / child).mkdir(parents=True, exist_ok=True)
    client = StdioClient(binary, config, home, profile.name)
    try:
        init, raw = client.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "oraclemcp-r2-raw-wire", "version": "0"},
            },
        )
        if len(raw) > MAX_RESPONSE_BYTES or init.get("result", {}).get("protocolVersion") != PROTOCOL_VERSION:
            raise AssertionError(f"{profile.name}: initialize failed: {init}")
        client.send_notification("notifications/initialized", {})
        initial_tools = list_tools(client)
        initial_counts = assert_registry_truth(profile.name, initial_tools, False)
        elevated = preview_and_apply_admin(client, profile)
        advertised = initial_tools
        if elevated:
            advertised = list_tools(client)
        counts = assert_registry_truth(profile.name, advertised, profile.expect_admin_surface)

        descriptors = {tool["name"]: tool for tool in advertised}
        guard_category = None
        if "oracle_query" in descriptors:
            reply, raw = call_tool(client, "oracle_query", {"sql": "select 1 from dual"})
            result = assert_jsonrpc_envelope(profile.name, "oracle_query.guard_probe", reply, raw)
            reason = result.get("structuredContent", {}).get("structured_reason", {})
            guard_category = reason.get("category")
            if guard_category not in KNOWN_REASON_CATEGORIES:
                raise AssertionError(f"{profile.name}: guard probe missed structured_reason: {result}")

        failures = []
        for name, descriptor in sorted(descriptors.items(), key=lambda item: item[0] == "disable_writes"):
            reply, raw = call_tool(client, name, tool_args(name))
            try:
                result = assert_jsonrpc_envelope(profile.name, name, reply, raw)
                validate_output_schema(profile.name, name, descriptor, result)
            except AssertionError as exc:
                failures.append(str(exc))
        if failures:
            raise AssertionError(f"{profile.name}: sweep failures: {failures[:5]}")
        emit(
            "profile_sweep",
            "assert",
            "pass",
            f"profile={profile.name} initial={initial_counts['wire_total']} swept={counts['wire_total']} canonical={counts['canonical']} aliases={counts['aliases']} guard={guard_category}",
        )
        return {
            "profile": profile.name,
            "initial_counts": initial_counts,
            "swept_counts": counts,
            "elevated_to_admin": elevated,
            "swept_tools": sorted(descriptors),
            "guard_refusal_category": guard_category,
        }
    finally:
        client.close()


def main() -> int:
    artifact_root = pathlib.Path(os.environ.get("ORACLEMCP_E2E_ARTIFACT_DIR", ROOT / "target" / "e2e"))
    work = pathlib.Path(tempfile.mkdtemp(prefix="r2-tool-surface-", dir=str(artifact_root)))
    (work / "audit").mkdir(parents=True, exist_ok=True)
    binary, source_sha = install_artifact(work)
    config = work / "oraclemcp.toml"
    write_config(config, work / "audit" / "audit.jsonl")
    results = []
    for profile in PROFILES:
        results.append(sweep_profile(binary, config, work, profile))
    guard_categories = {row["guard_refusal_category"] for row in results if row["guard_refusal_category"]}
    if len(guard_categories) != 1:
        raise AssertionError(f"guard refusal grammar drifted across profiles: {guard_categories}")
    summary = {
        "source_sha": source_sha,
        "installed_binary": str(binary),
        "artifact_dir": str(work),
        "expected_registry": {
            "canonical": EXPECTED_REGISTRY_CANONICAL,
            "aliases": EXPECTED_REGISTRY_ALIASES,
            "wire_with_oracle_capabilities": EXPECTED_WIRE_TOTAL,
        },
        "profiles": results,
        "wire_assertions": [
            "well_formed_envelope_and_known_error_class",
            "serialized_response_byte_budget",
            "refusal_grammar_uniformity",
        ],
    }
    summary_path = work / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    emit("wire_sweep", "assert", "pass", f"summary={summary_path}")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        emit("wire_sweep", "assert", "fail", str(exc))
        raise
