#!/usr/bin/env python3
"""Validate embedded selftest cases against the fixture-free W4 subset."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EMBEDDED = ROOT / "crates/oraclemcp/selftest/readonly_cases.json"
W4_CASES = ROOT / "scripts/e2e/w4/cases"


def check() -> list[str]:
    sources: dict[str, dict] = {}
    for path in sorted(W4_CASES.glob("*.json")):
        for case in json.loads(path.read_text()):
            if "case_id" in case:
                sources[case["case_id"]] = case
    failures: list[str] = []
    for case in json.loads(EMBEDDED.read_text()):
        source_id = case.get("source_case_id")
        source = sources.get(source_id)
        if source is None:
            failures.append(f"{case.get('case_id')}: missing W4 source {source_id!r}")
        elif case.get("level") != "READ_ONLY" or source.get("level") != "READ_ONLY":
            failures.append(f"{source_id}: selftest and source must be READ_ONLY")
        elif source.get("setup", []) or source.get("requires", []):
            failures.append(f"{source_id}: selftest source must be fixture-free")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", required=True)
    parser.parse_args()
    failures = check()
    if failures:
        print("selftest W4 drift check failed:\n" + "\n".join(f"- {x}" for x in failures))
        return 1
    print("selftest W4 drift check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
