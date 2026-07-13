#!/usr/bin/env python3
"""Real served-MCP proof for result masking and hidden-profile non-inference.

The test fixture consists only of run-unique synthetic literals selected from
Oracle's DUAL. Values are deliberately never persisted in evidence or failure
messages. Assertions operate on the exact JSON-RPC response lines received by
the client, not a reconstructed result object.
"""

import argparse
import json
import os
import queue
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


MASKED_VALUE = "<masked>"
VISIBLE_PROFILE = "egress_visible"
HIDDEN_PROFILE = "egress_hidden"


class StepFailure(Exception):
    """An assertion failed without disclosing synthetic fixture content."""


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def require(condition, description):
    if not condition:
        raise StepFailure(f"assertion failed: {description}")


def structured(result, tool):
    content = result.get("structuredContent")
    require(isinstance(content, dict), f"{tool} returns structured content")
    require(result.get("isError") is not True, f"{tool} succeeds through served MCP")
    return content


def server_env(config, state_home):
    """Pass only deliberate server inputs, never ambient operator config."""

    allowed = {
        "PATH",
        "LANG",
        "LC_ALL",
        "TERM",
        "ORACLEMCP_AUDIT_KEY",
        "E2E_SERVED_EGRESS_PASSWORD",
    }
    env = {key: value for key, value in os.environ.items() if key in allowed}
    env["ORACLEMCP_CONFIG"] = str(config)
    env["XDG_STATE_HOME"] = str(state_home)
    return env


class Harness:
    """JSON-line events plus redacted durable evidence."""

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
                    "lane": os.environ.get("E2E_LANE", "free23"),
                    "subject": os.environ.get("E2E_SUBJECT", "test-harness"),
                    "sid": os.environ.get("E2E_SID", str(os.getpid())),
                    "profile": os.environ.get("E2E_PROFILE", VISIBLE_PROFILE),
                    "level": os.environ.get("E2E_LEVEL", "READ_ONLY"),
                    "grant": "none",
                    "outcome": outcome,
                    "scenario": os.environ.get("E2E_SCENARIO", "served_egress"),
                    "seed": os.environ.get("ORACLEMCP_E2E_SEED", "0"),
                    "message": message,
                },
                separators=(",", ":"),
            ),
            file=sys.stderr,
            flush=True,
        )

    def evidence_line(self, step, outcome, detail):
        self.evidence.write(
            json.dumps(
                {"ts": now_iso(), "step": step, "outcome": outcome, "detail": detail},
                sort_keys=True,
            )
            + "\n"
        )
        self.evidence.flush()

    def close(self):
        self.evidence.close()


class McpSession:
    """One actual stdio client connection to an actual oraclemcp process."""

    def __init__(self, binary, config, state_home, stderr_path):
        self.stderr = open(stderr_path, "a", encoding="utf-8")
        self.stderr_path = stderr_path
        self.proc = subprocess.Popen(
            [binary, "serve", "--profile", VISIBLE_PROFILE, "--allow-no-auth"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=server_env(config, state_home),
        )
        self.queue = queue.Queue()
        self.request_id = 0
        threading.Thread(target=self._reader, daemon=True).start()
        threading.Thread(target=self._drain_stderr, daemon=True).start()

    def _reader(self):
        for line in self.proc.stdout:
            line = line.rstrip("\r\n")
            if line:
                self.queue.put(line)

    def _drain_stderr(self):
        for line in self.proc.stderr:
            self.stderr.write(line)
            self.stderr.flush()

    def rpc(self, method, params=None, timeout=90):
        self.request_id += 1
        request = {"jsonrpc": "2.0", "id": self.request_id, "method": method}
        if params is not None:
            request["params"] = params
        self.proc.stdin.write(json.dumps(request) + "\n")
        self.proc.stdin.flush()

        deadline = time.monotonic() + timeout
        while True:
            if self.proc.poll() is not None:
                raise StepFailure(f"server exited before replying to {method}")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise StepFailure(f"timeout waiting for {method}")
            try:
                raw = self.queue.get(timeout=min(remaining, 0.5))
            except queue.Empty:
                continue
            try:
                message = json.loads(raw)
            except json.JSONDecodeError as error:
                raise StepFailure("server emitted malformed JSON-RPC") from error
            if message.get("id") == self.request_id:
                return message, raw

    def initialize(self):
        reply, _ = self.rpc(
            "initialize",
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "oraclemcp-served-egress-e2e", "version": "1"},
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
        reply, raw = self.rpc("tools/call", {"name": tool, "arguments": arguments})
        require("error" not in reply, f"{tool} does not return a JSON-RPC protocol error")
        return reply["result"], raw

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


def audit_record_for_hash(audit_path, entry_hash):
    require(Path(audit_path).is_file(), "audit record was persisted before masked response escaped")
    for line in reversed(Path(audit_path).read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("entry_hash") == entry_hash:
            return record
    raise StepFailure("response certificate references a persisted audit record")


def assert_audit_bound_certificate(certificate, audit_path, binary, config, state_home):
    require(certificate.get("profile") == VISIBLE_PROFILE, "certificate identifies the visible policy")
    policy_id = certificate.get("policy_id")
    require(isinstance(policy_id, str) and policy_id.startswith("sha256:"), "certificate has a policy digest")
    entry_hash = certificate.get("audit_entry_hash")
    require(isinstance(entry_hash, str) and entry_hash.startswith("sha256:"), "certificate carries audit entry hash")
    decisions = certificate.get("decisions")
    require(isinstance(decisions, list) and decisions, "certificate carries column decisions")

    record = audit_record_for_hash(audit_path, entry_hash)
    require(record.get("tool") == "oracle_query", "certificate binds the served query audit record")
    require(record.get("outcome") == "SUCCEEDED", "certificate binds a successful audit record")
    audited = record.get("result_masking")
    require(isinstance(audited, dict), "audit record stores a masking certificate")
    response_without_self_reference = dict(certificate)
    response_without_self_reference.pop("audit_entry_hash", None)
    require(audited == response_without_self_reference, "audit certificate exactly re-derives client certificate")

    verify = subprocess.run(
        [binary, "audit", "verify", str(audit_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env=server_env(config, state_home),
    )
    require(verify.returncode == 0, "audit chain and certificate binding verify with the server key")
    return {
        "certificate_decisions": len(decisions),
        "audit_certificate_rederived": True,
        "audit_chain_verified": True,
    }


def decision_for(certificate, column):
    decisions = certificate.get("decisions") or []
    return next((entry for entry in decisions if entry.get("column") == column), None)


class ServedEgressScenario:
    def __init__(self, args, harness):
        self.args = args
        self.harness = harness

    def run_step(self, name, fn):
        started = time.monotonic()
        self.harness.emit(name, "act", "running", 0, f"{name} started")
        try:
            detail = fn()
        except StepFailure as error:
            duration = int((time.monotonic() - started) * 1000)
            self.harness.emit(name, "assert", "fail", duration, str(error))
            self.harness.evidence_line(name, "fail", {"reason": str(error)})
            raise
        duration = int((time.monotonic() - started) * 1000)
        self.harness.emit(name, "assert", "pass", duration, f"{name} passed")
        self.harness.evidence_line(name, "pass", detail)
        return detail

    def with_session(self, config, state_label, body):
        state_home = Path(self.args.state_home) / state_label
        state_home.mkdir(parents=True, exist_ok=True)
        session = McpSession(
            self.args.binary,
            config,
            state_home,
            str(Path(self.args.server_stderr_dir) / f"{state_label}.stderr"),
        )
        try:
            session.initialize()
            return body(session, state_home)
        finally:
            session.close()

    def run(self):
        nonce = uuid.uuid4().hex
        masked_marker = f"synthetic_mcp_mask_{nonce}"
        unknown_marker = f"synthetic_mcp_unknown_{nonce}"
        query = (
            f"SELECT '{masked_marker}' AS POLICY_MASKED, "
            f"'{unknown_marker}' AS UNKNOWN_VALUE FROM dual"
        )

        def hidden_configuration_proof():
            def body(session, state_home):
                profiles_result, profiles_raw = session.call("oracle_list_profiles", {})
                profiles = structured(profiles_result, "oracle_list_profiles")
                require(HIDDEN_PROFILE.encode() not in profiles_raw.encode(), "hidden profile name is absent from profile-list wire bytes")
                rendered_profiles = json.dumps(profiles, sort_keys=True).encode()
                require(HIDDEN_PROFILE.encode() not in rendered_profiles, "hidden profile name is absent from structured profile list")

                query_result, query_raw = session.call("oracle_query", {"sql": query})
                content = structured(query_result, "oracle_query")
                raw_bytes = query_raw.encode()
                require(masked_marker.encode() not in raw_bytes, "explicitly masked synthetic literal is absent from actual response bytes")
                require(unknown_marker.encode() not in raw_bytes, "unknown synthetic literal is absent from actual response bytes")
                rows = content.get("rows")
                require(isinstance(rows, list) and len(rows) == 1, "served query returns the one real DUAL row")
                row = rows[0]
                require(row.get("POLICY_MASKED") == MASKED_VALUE, "configured column is masked on the served response")
                require(row.get("UNKNOWN_VALUE") == MASKED_VALUE, "unconfigured column masks by the fail-closed default")
                certificate = content.get("mask_certificate")
                require(isinstance(certificate, dict), "served result carries masking certificate")
                explicit = decision_for(certificate, "POLICY_MASKED")
                unknown = decision_for(certificate, "UNKNOWN_VALUE")
                require(
                    isinstance(explicit, dict)
                    and explicit.get("action") == "mask"
                    and explicit.get("source") == "rule",
                    "certificate records the explicit mask that reached the wire",
                )
                require(
                    isinstance(unknown, dict)
                    and unknown.get("action") == "mask"
                    and unknown.get("source") == "mask_unknown_default",
                    "certificate records the fail-closed unknown-column mask that reached the wire",
                )
                certificate_detail = assert_audit_bound_certificate(
                    certificate,
                    self.args.hidden_audit,
                    self.args.binary,
                    self.args.hidden_config,
                    state_home,
                )

                catalog_result, catalog_raw = session.call(
                    "oracle_search_objects",
                    {"fleet": True, "detail_level": "names", "max_rows": 1},
                )
                catalog = structured(catalog_result, "oracle_search_objects")
                require(HIDDEN_PROFILE.encode() not in catalog_raw.encode(), "hidden profile name is absent from fleet-catalog wire bytes")
                require(
                    not any(
                        field in catalog
                        for field in ("profiles", "summary", "profile_count", "reachable_count", "unreachable_count")
                    ),
                    "fleet catalog exposes neither roster nor profile counters",
                )
                rows = catalog.get("results")
                require(isinstance(rows, list) and rows, "fleet catalog returns a real Oracle object row")
                require(
                    all(row.get("profile") == VISIBLE_PROFILE for row in rows),
                    "hidden profile contributes no catalog result",
                )
                return {
                    "profile_roster_hidden": True,
                    "raw_plaintext_markers_absent": 2,
                    "served_rows_masked": 2,
                    "catalog_count": catalog.get("count"),
                    **certificate_detail,
                }

            return self.with_session(self.args.hidden_config, "with-hidden", body)

        hidden_detail = self.run_step("served_masking_and_hidden_profile", hidden_configuration_proof)

        def baseline_count_proof():
            def body(session, _state_home):
                result, raw = session.call(
                    "oracle_search_objects",
                    {"fleet": True, "detail_level": "names", "max_rows": 1},
                )
                catalog = structured(result, "oracle_search_objects")
                require(HIDDEN_PROFILE.encode() not in raw.encode(), "baseline catalog has no hidden-profile marker")
                count = catalog.get("count")
                require(isinstance(count, int), "baseline catalog provides bounded result count")
                return {"baseline_catalog_count": count}

            return self.with_session(self.args.baseline_config, "visible-only", body)

        baseline_detail = self.run_step("hidden_profile_has_no_count_side_channel", baseline_count_proof)
        require(
            hidden_detail["catalog_count"] == baseline_detail["baseline_catalog_count"],
            "hidden profile leaves the caller-visible fleet object count unchanged",
        )
        self.harness.evidence_line(
            "hidden_profile_count_comparison",
            "pass",
            {"count_equal_with_and_without_hidden_profile": True},
        )


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--hidden-config", required=True)
    parser.add_argument("--baseline-config", required=True)
    parser.add_argument("--hidden-audit", required=True)
    parser.add_argument("--baseline-audit", required=True)
    parser.add_argument("--state-home", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--server-stderr-dir", required=True)
    args = parser.parse_args()
    for config in (args.hidden_config, args.baseline_config):
        if not Path(config).is_file():
            parser.error(f"runtime config is missing: {config}")
    Path(args.server_stderr_dir).mkdir(parents=True, exist_ok=True)
    return args


def main():
    args = parse_args()
    harness = Harness(args.evidence)
    try:
        ServedEgressScenario(args, harness).run()
    except StepFailure as error:
        harness.emit("served_egress_session", "assert", "fail", 0, str(error))
        harness.evidence_line("served_egress_session", "fail", {"reason": str(error)})
        return 1
    finally:
        harness.close()
    harness.emit("served_egress_session", "assert", "pass", 0, "served egress MCP assertions passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
