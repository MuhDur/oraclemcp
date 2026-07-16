#!/usr/bin/env python3
"""Validate a mutation-result/v1 artifact against the exact current tree."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from validate_evidence import validate_doc


ROOT=Path(__file__).resolve().parents[1]


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument("artifact",type=Path)
    a=p.parse_args()
    doc=json.loads(a.artifact.read_text())
    findings = validate_doc(doc)
    if findings:
        finding = findings[0]
        raise SystemExit(f"{finding.code}: {finding.path}: {finding.message}")
    sha=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    if doc.get("source",{}).get("sha") != sha: raise SystemExit("E_STALE_SHA: artifact is not for HEAD")
    print(f"mutation-result: OK ({doc['rate']:.6f})")


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, json.JSONDecodeError) as e:
        raise SystemExit(f"E_INVALID: {e}")
