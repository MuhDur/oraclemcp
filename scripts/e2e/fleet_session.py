#!/usr/bin/env python3
"""Live MCP driver for scripts/e2e/fleet.sh.

Each case creates a fresh real server process against a two-profile runtime
configuration. Evidence intentionally records only synthetic profile labels and
counts: the suite proves egress behavior without preserving live object names,
users, DSNs, or rows in an artifact.
"""

import argparse
import json
import os
import queue
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


class StepFailure(Exception):
    """A failed live-MCP assertion."""


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def require(condition, description):
    if not condition:
        raise StepFailure(f"assertion failed: {description}")


def structured(result, tool):
    content = result.get("structuredContent")
    require(isinstance(content, dict), f"{tool} returned no structured content")
    if result.get("isError") is True:
        error_class = content.get("error_class")
        if not isinstance(error_class, str):
            error_class = "unclassified error"
        raise StepFailure(f"{tool} returned {error_class}")
    return content


class Harness:
    """JSON-line events plus redacted, durable per-case evidence."""

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
                    "lane": os.environ.get("E2E_LANE", "fleet"),
                    "subject": os.environ.get("E2E_SUBJECT", "test-harness"),
                    "sid": os.environ.get("E2E_SID", str(os.getpid())),
                    "profile": os.environ.get("E2E_PROFILE", "fleet_left"),
                    "level": os.environ.get("E2E_LEVEL", "READ_ONLY"),
                    "grant": "none",
                    "outcome": outcome,
                    "scenario": os.environ.get("E2E_SCENARIO", "fleet"),
                    "seed": os.environ.get("ORACLEMCP_E2E_SEED", "0"),
                    "message": message,
                },
                separators=(",", ":"),
            ),
            file=sys.stderr,
            flush=True,
        )

    def evidence_line(self, case, outcome, detail):
        self.evidence.write(
            json.dumps(
                {
                    "ts": now_iso(),
                    "case": case,
                    "outcome": outcome,
                    "detail": detail,
                },
                sort_keys=True,
            )
            + "\n"
        )
        self.evidence.flush()

    def close(self):
        self.evidence.close()


class McpSession:
    """A long-lived stdio connection to one real oraclemcp process."""

    def __init__(self, binary, config, profile, stderr_path):
        self.stderr = open(stderr_path, "a", encoding="utf-8")
        self.stderr_path = stderr_path
        # E2E control variables are not server configuration. Preserve only the
        # server config/audit inputs; credential_ref resolves the separately
        # named ORACLE_FLEET_* variables inherited below.
        child_env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("ORACLEMCP_")
            or key in {"ORACLEMCP_AUDIT_KEY"}
        }
        child_env["ORACLEMCP_CONFIG"] = config
        self.proc = subprocess.Popen(
            [binary, "serve", "--profile", profile, "--allow-no-auth"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=child_env,
        )
        self.queue = queue.Queue()
        self.request_id = 0
        self.last_wire_response = ""
        threading.Thread(target=self._reader, daemon=True).start()
        threading.Thread(target=self._drain_stderr, daemon=True).start()

    def _reader(self):
        for line in self.proc.stdout:
            line = line.strip()
            if line:
                self.queue.put(line)

    def _drain_stderr(self):
        for line in self.proc.stderr:
            self.stderr.write(line)
            self.stderr.flush()

    def rpc(self, method, params=None, timeout=120):
        self.request_id += 1
        request = {"jsonrpc": "2.0", "id": self.request_id, "method": method}
        if params is not None:
            request["params"] = params
        self.proc.stdin.write(json.dumps(request) + "\n")
        self.proc.stdin.flush()

        deadline = time.monotonic() + timeout
        while True:
            if self.proc.poll() is not None:
                raise StepFailure(f"server exited before replying to {method}; inspect {self.stderr_path}")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise StepFailure(f"timeout waiting for reply to {method}")
            try:
                line = self.queue.get(timeout=min(remaining, 0.5))
            except queue.Empty:
                continue
            message = json.loads(line)
            if message.get("id") == self.request_id:
                self.last_wire_response = line
                return message

    def initialize(self):
        reply = self.rpc(
            "initialize",
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "oraclemcp-fleet-e2e", "version": "1"},
            },
        )
        server = reply.get("result", {}).get("serverInfo", {})
        require(server.get("name") == "oraclemcp", "server identifies itself")
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        self.proc.stdin.flush()

    def call(self, tool, arguments):
        reply = self.rpc("tools/call", {"name": tool, "arguments": arguments})
        if "error" in reply:
            raise StepFailure(f"{tool} returned a JSON-RPC error")
        return reply["result"]

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


class FleetScenario:
    def __init__(self, args, harness):
        self.args = args
        self.harness = harness

    def run_case(self, name, fn):
        started = time.monotonic()
        self.harness.emit(name, "act", "running", 0, f"{name} started")
        try:
            detail = fn()
        except StepFailure as exc:
            duration = int((time.monotonic() - started) * 1000)
            self.harness.emit(name, "assert", "fail", duration, str(exc))
            self.harness.evidence_line(name, "fail", {"reason": str(exc)})
            raise
        duration = int((time.monotonic() - started) * 1000)
        self.harness.emit(name, "assert", "pass", duration, f"{name} passed")
        self.harness.evidence_line(name, "pass", detail)

    def with_session(self, config, profile, label, body):
        session = McpSession(
            self.args.binary,
            config,
            profile,
            str(Path(self.args.server_stderr_dir) / f"{label}.stderr"),
        )
        try:
            session.initialize()
            return body(session)
        finally:
            session.close()

    def orient_degrades_one_unreachable_lane(self):
        def body(session):
            out = structured(
                session.call("oracle_orient", {"fleet": True, "include": ["freshness"]}),
                "oracle_orient",
            )
            profiles = out.get("profiles")
            require(isinstance(profiles, list) and len(profiles) == 2, "fleet orient returns exactly two profiles")
            statuses = {entry.get("profile"): entry.get("status") for entry in profiles}
            require(
                statuses == {"fleet_live": "REACHABLE", "fleet_down": "UNREACHABLE"},
                "fleet orient preserves reachable and deliberately-down lanes",
            )
            summary = out.get("summary") or {}
            require(summary.get("reachable_count") == 1, "fleet orient reports one reachable lane")
            require(summary.get("unreachable_count") == 1, "fleet orient reports one unreachable lane")
            return {"profiles": 2, "reachable": 1, "unreachable": 1}

        return self.with_session(self.args.orient_config, "fleet_live", "orient", body)

    def diff_reports_a_semantic_live_delta(self):
        def body(session):
            out = structured(
                session.call(
                    "oracle_diff",
                    {
                        # `UNIQUE_SESSION_ID` is not a valid USERENV parameter
                        # on supported XE 18/21 lanes. `SID` is supported by the
                        # same portable USERENV surface that the driver records
                        # for session evidence, and keeps this proof on DUAL's
                        # classifier-proven read-only path. The harness records
                        # only the resulting delta count, never either SID.
                        "sql": "SELECT 1 AS id, SYS_CONTEXT('USERENV', 'SID') AS session_token FROM dual",
                        "profile_a": "fleet_left",
                        "profile_b": "fleet_right",
                        "key": ["ID"],
                    },
                ),
                "oracle_diff",
            )
            require(out.get("keyed") is True, "cross-database diff aligns the explicit ID key")
            changed = out.get("changed")
            require(
                isinstance(changed, list) and changed,
                "separate live database sessions produce a semantic changed row",
            )
            require((out.get("source_a") or {}).get("profile") == "fleet_left", "diff identifies synthetic source A")
            require((out.get("source_b") or {}).get("profile") == "fleet_right", "diff identifies synthetic source B")
            return {"changed_rows": len(changed), "keyed": True}

        return self.with_session(self.args.diff_config, "fleet_left", "diff", body)

    def catalog_masks_and_hides_forbidden_source(self):
        def catalog_response(session):
            result = session.call(
                "oracle_search_objects",
                {"fleet": True, "detail_level": "names", "max_rows": 10},
            )
            wire = session.last_wire_response
            require(isinstance(wire, str) and wire, "catalog returned a real wire response")
            return structured(result, "oracle_search_objects"), wire

        def public_shape(out):
            rows = out.get("results")
            require(isinstance(rows, list) and rows, "fleet catalog returns live object rows")
            certificates = out.get("mask_certificates")
            require(isinstance(certificates, list) and certificates, "catalog carries a masking certificate")
            return {
                "catalog_rows": len(rows),
                "certificate_count": len(certificates),
                "result_keys": sorted({tuple(sorted(row)) for row in rows if isinstance(row, dict)}),
            }

        def body(session):
            out, wire = catalog_response(session)
            rows = out.get("results")
            require(
                all(row.get("profile") == "fleet_visible" for row in rows),
                "hidden profile contributes no catalog row",
            )
            require(
                all(row.get("object_name") == "<masked>" for row in rows),
                "source object names are masked before aggregation",
            )
            require("fleet_private" not in wire, "forbidden profile name is not inferable from real response bytes")
            require('"profiles"' not in wire and '"summary"' not in wire, "real response bytes contain no roster or count metadata")
            require("profiles" not in out and "summary" not in out, "catalog emits no roster or profile counts")
            certificates = out.get("mask_certificates")
            require(isinstance(certificates, list) and certificates, "catalog carries a masking certificate")
            masked = any(
                isinstance(entry.get("certificate"), dict)
                and any(
                    decision.get("column") == "OBJECT_NAME" and decision.get("action") == "mask"
                    for decision in (entry["certificate"].get("decisions") or [])
                )
                and isinstance(entry["certificate"].get("audit_entry_hash"), str)
                and bool(entry["certificate"]["audit_entry_hash"])
                for entry in certificates
            )
            require(masked, "catalog certificate proves the object-name mask was audit-bound")
            return public_shape(out)

        protected = self.with_session(self.args.catalog_config, "fleet_visible", "catalog", body)

        def baseline_body(session):
            out, wire = catalog_response(session)
            require("fleet_private" not in wire, "baseline response contains no private profile name")
            return public_shape(out)

        baseline = self.with_session(
            self.args.catalog_baseline_config,
            "fleet_visible",
            "catalog-baseline",
            baseline_body,
        )
        require(
            protected == baseline,
            "adding the caller-invisible source changes neither catalog count nor public response shape",
        )
        return {"catalog_rows": protected["catalog_rows"], "mask_certificates": protected["certificate_count"]}

    def run(self):
        self.run_case("fleet_orient_unreachable", self.orient_degrades_one_unreachable_lane)
        self.run_case("fleet_cross_db_delta", self.diff_reports_a_semantic_live_delta)
        self.run_case("fleet_catalog_egress", self.catalog_masks_and_hides_forbidden_source)


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--orient-config", required=True)
    parser.add_argument("--diff-config", required=True)
    parser.add_argument("--catalog-config", required=True)
    parser.add_argument("--catalog-baseline-config", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--server-stderr-dir", required=True)
    args = parser.parse_args()
    for path in (args.orient_config, args.diff_config, args.catalog_config, args.catalog_baseline_config):
        if not Path(path).is_file():
            parser.error(f"runtime config is missing: {path}")
    Path(args.server_stderr_dir).mkdir(parents=True, exist_ok=True)
    return args


def main():
    args = parse_args()
    harness = Harness(args.evidence)
    try:
        FleetScenario(args, harness).run()
    except StepFailure as exc:
        harness.emit("fleet_session", "assert", "fail", 0, str(exc))
        harness.evidence_line("fleet_session", "fail", {"reason": str(exc)})
        return 1
    finally:
        harness.close()
    harness.emit("fleet_session", "assert", "pass", 0, "fleet live MCP assertions passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
