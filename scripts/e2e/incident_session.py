#!/usr/bin/env python3
"""Real `om incident` command proof with synthetic-only incident material.

The raw statement is passed only on the child's standard input. Evidence keeps
only manifest/digest metadata, so the E2E artifact cannot become an exfiltration
channel while it proves that capture's bundle is clean and replay is stable.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


class StepFailure(Exception):
    """A failed real-command assertion."""


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def require(condition, description):
    if not condition:
        raise StepFailure(f"assertion failed: {description}")


class Harness:
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
                    "lane": os.environ.get("E2E_LANE", "offline-lab-runtime"),
                    "subject": os.environ.get("E2E_SUBJECT", "test-harness"),
                    "sid": os.environ.get("E2E_SID", str(os.getpid())),
                    "profile": os.environ.get("E2E_PROFILE", "offline"),
                    "level": os.environ.get("E2E_LEVEL", "READ_ONLY"),
                    "grant": "none",
                    "outcome": outcome,
                    "scenario": os.environ.get("E2E_SCENARIO", "incident"),
                    "seed": os.environ.get("ORACLEMCP_E2E_SEED", "0"),
                    "message": message,
                },
                separators=(",", ":"),
            ),
            file=sys.stderr,
            flush=True,
        )

    def evidence_line(self, outcome, detail):
        self.evidence.write(json.dumps({"ts": now_iso(), "outcome": outcome, "detail": detail}, sort_keys=True) + "\n")
        self.evidence.flush()

    def close(self):
        self.evidence.close()


# These synthetic sentinels cover identifiers, a bind, and a literal. They do
# not name an operator, service, wallet, database, or customer.
RAW_STATEMENT = """
UPDATE synthetic_incident_schema.synthetic_incident_table
SET synthetic_incident_value = 'synthetic-incident-secret'
WHERE synthetic_incident_key = :synthetic_incident_bind
"""
RAW_MARKERS = (
    "synthetic_incident_schema",
    "synthetic_incident_table",
    "synthetic_incident_value",
    "synthetic_incident_key",
    "synthetic_incident_bind",
    "synthetic-incident-secret",
)


def child_env(run_dir):
    """A zero-profile environment: the scenario cannot contact a database."""
    config_home = run_dir / "config"
    config_home.mkdir(parents=True, exist_ok=True)
    config = config_home / "profiles.toml"
    config.write_text("schema_version = 2\n", encoding="utf-8")
    env = {key: value for key, value in os.environ.items() if key in {"PATH", "LANG", "LC_ALL", "TERM"}}
    env["HOME"] = str(run_dir / "home")
    env["XDG_CONFIG_HOME"] = str(config_home)
    env["XDG_STATE_HOME"] = str(run_dir / "state")
    env["ORACLEMCP_CONFIG"] = str(config)
    return env


def command(binary, argv, env, stdin=None):
    completed = subprocess.run(
        [binary, "--json", *argv],
        input=stdin,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=30,
        check=False,
    )
    require(completed.returncode == 0, "real om incident command exits successfully")
    try:
        return completed.stdout.encode("utf-8"), json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise StepFailure("real om incident command returned one JSON object") from error


def bundle_bytes(bundle):
    return [path.read_bytes() for path in sorted(bundle.rglob("*")) if path.is_file()]


def assert_clean_bundle(bundle):
    files = bundle_bytes(bundle)
    require(len(files) == 4, "capture writes manifest, config, audit tail, and one cassette")
    haystack = b"\n".join(files).lower()
    for marker in RAW_MARKERS:
        require(marker.encode("utf-8") not in haystack, "raw incident marker is absent from every bundle file")
    require(b"credential_ref" not in haystack, "bundle excludes credential references")
    require(b"password=" not in haystack, "bundle excludes password shapes")
    return hashlib.sha256(haystack).hexdigest()


def run(args):
    harness = Harness(args.evidence)
    started = time.monotonic()
    run_dir = Path(args.run_dir)
    bundle = run_dir / "incident-bundle"
    env = child_env(run_dir)

    capture_bytes, captured = command(
        args.binary,
        ["incident", "capture", str(bundle), "--seed", str(args.seed)],
        env,
        stdin=RAW_STATEMENT,
    )
    require(captured.get("kind") == "oraclemcp_incident_capture", "capture identifies its bounded response kind")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", captured.get("bundle_id", "")) is not None, "capture returns a content-addressed bundle id")
    require(captured.get("seed") == args.seed, "capture records the requested deterministic seed")
    for marker in RAW_MARKERS:
        require(marker.encode("utf-8") not in capture_bytes.lower(), "capture response omits raw incident material")
    harness.emit("incident_capture", "act", "pass", 0, "real command wrote one redacted bundle")

    artifact_hash = assert_clean_bundle(bundle)
    harness.emit("incident_redaction_gate", "assert", "pass", 0, "all raw identifiers binds and literals are absent")

    first_bytes, first = command(args.binary, ["incident", "replay", str(bundle)], env)
    second_bytes, second = command(args.binary, ["incident", "replay", str(bundle)], env)
    require(first_bytes == second_bytes, "two replays return byte-identical JSON")
    require(first == second, "two replays return the same structured report")
    require(first.get("kind") == "oraclemcp_incident_replay", "replay identifies its bounded response kind")
    require(first.get("seed") == args.seed, "replay uses the captured LabRuntime seed")
    require(first.get("replayed_steps") == 1, "replay classifies the captured cassette step")
    verdicts = first.get("verdicts")
    require(isinstance(verdicts, list) and len(verdicts) == 1, "replay returns one fresh verdict")
    require(verdicts[0].get("danger") != "Safe", "replay does not trust a stored safe verdict")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", first.get("audit_tail_sha256", "")) is not None, "replay returns only an audit-tail digest")
    for marker in RAW_MARKERS:
        require(marker.encode("utf-8") not in first_bytes.lower(), "replay response omits raw incident material")
    harness.emit("incident_replay_first", "act", "pass", 0, "fresh classification completed under the recorded seed")
    harness.emit("incident_replay_second", "act", "pass", 0, "same seed reproduced byte-identical replay output")

    duration_ms = int((time.monotonic() - started) * 1000)
    harness.evidence_line(
        "pass",
        {
            "artifact_sha256": artifact_hash,
            "bundle_id": captured["bundle_id"],
            "replayed_steps": first["replayed_steps"],
            "audit_tail_sha256": first["audit_tail_sha256"],
            "verdict_danger": verdicts[0]["danger"],
        },
    )
    harness.emit("incident_determinism", "assert", "pass", duration_ms, "clean bundle and deterministic replay verified")
    harness.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--seed", required=True, type=int)
    args = parser.parse_args()
    try:
        run(args)
    except (StepFailure, subprocess.TimeoutExpired) as error:
        print(f"incident e2e failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
