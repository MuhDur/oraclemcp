#!/usr/bin/env python3
"""Validate a mutation-result/v1 artifact against the exact current tree."""
from __future__ import annotations
import argparse, json, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("artifact",type=Path); a=p.parse_args()
    doc=json.loads(a.artifact.read_text())
    if doc.get("schema") != "mutation-result/v1": raise SystemExit("E_SCHEMA: expected mutation-result/v1")
    sha=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    if doc.get("source",{}).get("sha") != sha: raise SystemExit("E_STALE_SHA: artifact is not for HEAD")
    if doc.get("source",{}).get("tree_clean") is not True: raise SystemExit("E_TREE_DIRTY")
    if doc.get("ended_at") is None: raise SystemExit("E_UNFINISHED")
    if any(s.get("status") != "complete" for s in doc.get("shards",[])): raise SystemExit("E_SHARD_INCOMPLETE")
    c=doc["counts"]; denom=c["caught"]+c["missed"]+(c["timeout"] if doc["denominator"]=="caught+missed+timeout" else 0)
    expected=c["caught"]/denom if denom else 0.0
    if abs(doc["rate"]-expected)>1e-9: raise SystemExit("E_RATE_MISMATCH")
    if len(doc["survivors"]) != c["missed"]: raise SystemExit("E_SURVIVOR_COUNT_MISMATCH")
    if any("mutant_fails_test" not in k or "head_passes_test" not in k for k in doc["kills"]): raise SystemExit("E_KILL_WITNESS_MISSING")
    print(f"mutation-result: OK ({doc['rate']:.6f})")
if __name__ == "__main__":
    try: main()
    except (OSError, KeyError, json.JSONDecodeError) as e: raise SystemExit(f"E_INVALID: {e}")
