#!/usr/bin/env python3
"""Audit WS-C fixture evidence for installed-artifact wire coverage."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CLOSE_DIR = ROOT / "tests" / "artifacts" / "evidence" / "closes"
RED_DIR = ROOT / "tests" / "artifacts" / "evidence" / "ws-c-red-runs"


@dataclass(frozen=True)
class Fixture:
    code: str
    bead_id: str
    title: str
    close_evidence: Path
    red_evidence: Path | None
    assertion_boundary: str
    installed_artifact_wire: bool
    basis: str
    binding: str


FIXTURES = [
    Fixture(
        "C1",
        "oraclemcp-091-c1-oauth-literal-jwt-v9m9z",
        "OAuth literal JWT",
        CLOSE_DIR / "oraclemcp-091-c1-oauth-literal-jwt-v9m9z.json",
        RED_DIR / "oraclemcp-091-c1-oauth-literal-jwt-v9m9z.json",
        "in-process HTTP route handler plus verifier API",
        False,
        "Close evidence drives handle_http_request and ResourceServerConfig::validate from a crate test; it does not start the installed oraclemcp artifact and issue raw external HTTP.",
        "Needs a C1 wire lift before WS-C can close.",
    ),
    Fixture(
        "C2",
        "oraclemcp-091-c2-stdio-token-literal-frame-t2b5q",
        "Stdio init-token literal frame",
        CLOSE_DIR / "oraclemcp-091-c2-stdio-token-literal-frame-t2b5q.json",
        RED_DIR / "oraclemcp-091-c2-stdio-token-literal-frame-t2b5q.json",
        "in-process stdio service helper",
        False,
        "Close evidence uses serve_stdio_with_io from a crate test; it does not execute the installed binary over raw stdio.",
        "Needs a C2 wire lift before WS-C can close.",
    ),
    Fixture(
        "C3",
        "oraclemcp-091-c3-mtls-literal-fingerprints-fqh5k",
        "mTLS literal fingerprints",
        CLOSE_DIR / "oraclemcp-091-c3-mtls-literal-fingerprints-fqh5k.json",
        RED_DIR / "oraclemcp-091-c3-mtls-literal-fingerprints-fqh5k.json",
        "in-process HTTP route handler",
        False,
        "Close evidence drives handle_http_request directly; it does not run TLS/mTLS through the installed artifact.",
        "Needs a C3 wire lift before WS-C can close.",
    ),
    Fixture(
        "C4",
        "oraclemcp-091-c4-dashboard-browser-flow-cw3e2",
        "Dashboard browser flow",
        CLOSE_DIR / "oraclemcp-091-c4-dashboard-browser-flow-cw3e2.json",
        None,
        "installed artifact plus Chromium browser wire",
        True,
        "Bound to R3/C4 close evidence: rig_browser_lane builds the installed artifact with omcpb, then Playwright drives Chromium against the served dashboard.",
        "No duplicate fixture required; C4 is the binding.",
    ),
    Fixture(
        "C5",
        "oraclemcp-091-c5-setup-ordering-postures-02d0i",
        "Session setup ordering",
        CLOSE_DIR / "oraclemcp-091-c5-setup-ordering-postures-02d0i.json",
        RED_DIR / "oraclemcp-091-c5-setup-ordering-postures-02d0i.json",
        "config/session-context API",
        False,
        "Close evidence asserts setup ordering in the session-context builder layer, not through a running installed server connection.",
        "Needs a C5 wire lift before WS-C can close.",
    ),
    Fixture(
        "C6",
        "oraclemcp-091-c6-cli-vs-server-collision-6o0m9",
        "CLI versus running server collision",
        CLOSE_DIR / "oraclemcp-091-c6-cli-vs-server-collision-6o0m9.json",
        RED_DIR / "oraclemcp-091-c6-cli-vs-server-collision-6o0m9.json",
        "separate CLI process contention",
        False,
        "C6 crosses a process boundary, but the recorded fixture uses the Cargo test harness and CARGO_BIN_EXE rather than the installed artifact under the rig.",
        "Needs a C6 installed-artifact lift before WS-C can close.",
    ),
    Fixture(
        "C7",
        "oraclemcp-091-c7-zero-rows-columns-v6zdw",
        "Zero-row columns population",
        CLOSE_DIR / "oraclemcp-091-c7-zero-rows-columns-v6zdw.json",
        RED_DIR / "oraclemcp-091-c7-zero-rows-columns-v6zdw.json",
        "QueryPageBuilder API",
        False,
        "Close evidence asserts the builder contract directly; it does not issue a raw MCP tool call to a running installed artifact.",
        "Needs a C7 wire lift before WS-C can close.",
    ),
    Fixture(
        "C8",
        "oraclemcp-091-c8-blind-catalog-refuse-w9iie",
        "Blind catalog refusal",
        CLOSE_DIR / "oraclemcp-091-c8-blind-catalog-refuse-w9iie.json",
        RED_DIR / "oraclemcp-091-c8-blind-catalog-refuse-w9iie.json",
        "catalog resolver API with mocked connection",
        False,
        "Close evidence asserts catalog_resolver behavior directly; it does not query a running installed artifact over MCP wire.",
        "Needs a C8 wire lift before WS-C can close.",
    ),
    Fixture(
        "C9",
        "oraclemcp-091-c9-snippet-truth-00gb2",
        "Onboarding snippet truth",
        CLOSE_DIR / "oraclemcp-091-c9-snippet-truth-00gb2.json",
        RED_DIR / "oraclemcp-091-c9-snippet-truth-00gb2.json",
        "installed artifact plus raw stdio/HTTP clients",
        True,
        "Bound to C9 close evidence: onboarding_snippet_truth installs oraclemcp from a git archive of HEAD, extracts real setup output, and runs raw JSON-RPC/HTTP clients.",
        "No duplicate fixture required; C9 is the binding.",
    ),
]


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def git_sha() -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
    ).strip()


def git_dirty() -> list[str]:
    output = subprocess.check_output(
        ["git", "status", "--short", "--", "scripts/rig", "tests/artifacts/evidence"],
        cwd=ROOT,
        text=True,
    )
    return [line for line in output.splitlines() if line.strip()]


def build_ledger() -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    missing: list[str] = []
    gaps: list[dict[str, str]] = []

    for fixture in FIXTURES:
        close_exists = fixture.close_evidence.exists()
        red_exists = fixture.red_evidence.exists() if fixture.red_evidence else True
        close_source = None
        red_source = None
        close_scope: list[str] = []
        if close_exists:
            close = load_json(fixture.close_evidence)
            close_source = close.get("source", {}).get("sha")
            close_scope = close.get("scope", {}).get("in_scope", [])
        if fixture.red_evidence and red_exists:
            red = load_json(fixture.red_evidence)
            red_source = red.get("source_commit") or red.get("red_run", {}).get("source_commit")

        if not close_exists:
            missing.append(str(fixture.close_evidence.relative_to(ROOT)))
        if fixture.red_evidence and not red_exists:
            missing.append(str(fixture.red_evidence.relative_to(ROOT)))

        if not fixture.installed_artifact_wire:
            gaps.append(
                {
                    "code": fixture.code,
                    "bead_id": fixture.bead_id,
                    "reason": fixture.basis,
                    "required_action": fixture.binding,
                }
            )

        entries.append(
            {
                "code": fixture.code,
                "bead_id": fixture.bead_id,
                "title": fixture.title,
                "close_evidence": str(fixture.close_evidence.relative_to(ROOT)),
                "red_evidence": str(fixture.red_evidence.relative_to(ROOT)) if fixture.red_evidence else None,
                "close_evidence_present": close_exists,
                "red_evidence_present": red_exists,
                "close_source_sha": close_source,
                "red_source_sha": red_source,
                "close_scope": close_scope,
                "assertion_boundary": fixture.assertion_boundary,
                "installed_artifact_wire": fixture.installed_artifact_wire,
                "basis": fixture.basis,
                "binding": fixture.binding,
            }
        )

    status = "pass" if not missing and not gaps else "fail"
    return {
        "schema": "ws-c-wire-fixture-ledger/v1",
        "repo": "oraclemcp",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source": {
            "sha": git_sha(),
            "dirty_paths_under_audit_scope": git_dirty(),
        },
        "requirement": "Every C1-C9 fixture that asserts a process or protocol contract must prove it over the wire against the installed oraclemcp artifact. C4 and C9 bind to their existing installed-artifact lanes instead of duplicating them.",
        "status": status,
        "summary": {
            "fixtures_total": len(entries),
            "installed_artifact_wire_count": sum(1 for entry in entries if entry["installed_artifact_wire"]),
            "gap_count": len(gaps),
            "missing_evidence_count": len(missing),
        },
        "fixtures": entries,
        "gaps": gaps,
        "missing_evidence": missing,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, help="Write the ledger JSON to this path")
    parser.add_argument(
        "--expect-fail",
        action="store_true",
        help="Return success only when the ledger still contains installed-artifact wire gaps",
    )
    args = parser.parse_args()

    ledger = build_ledger()
    text = json.dumps(ledger, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)

    failed = ledger["status"] != "pass"
    if args.expect_fail:
        return 0 if failed else 1
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
