#!/usr/bin/env python3
"""Fail-closed, non-mutating candidate release proof generator."""
from __future__ import annotations
import argparse, datetime as dt, json, re, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
def run(*argv: str) -> str:
    return subprocess.check_output(argv, cwd=ROOT, text=True).strip()
def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument("--tag", required=True); p.add_argument("--sha", required=True)
    p.add_argument("--required-proof", type=Path); p.add_argument("--ci-json", type=Path)
    p.add_argument("--artifact", action="append", default=[]); p.add_argument("--output", type=Path)
    a=p.parse_args(); tag=a.tag; sha=a.sha
    if not SHA_RE.fullmatch(sha): p.error("--sha must be a full lowercase SHA")
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", tag): p.error("invalid candidate tag")
    if run("git", "rev-parse", "HEAD") != sha: raise SystemExit("E_SHA_MISMATCH: HEAD is not --sha")
    if run("git", "status", "--porcelain"): raise SystemExit("E_TREE_DIRTY: clean tree required")
    version=tag[1:].split("-",1)[0]
    manifest=json.loads(json.dumps({}))
    cargo=(ROOT/"Cargo.toml").read_text()
    if f'version = "{version}"' not in cargo and f'version = "{version}"' not in (ROOT/"crates/oraclemcp/Cargo.toml").read_text():
        raise SystemExit("E_TAG_VERSION_MISMATCH: candidate version is not declared")
    proof=a.required_proof or (ROOT/"tests/artifacts/evidence/required"/f"required-proof-{sha}.json")
    if not proof.exists(): raise SystemExit("E_REQUIRED_PROOF_MISSING: required-proof artifact not found")
    doc=json.loads(proof.read_text())
    if doc.get("schema") != "required-proof/v1" or doc.get("source",{}).get("sha") != sha or doc.get("verdict") != "pass": raise SystemExit("E_REQUIRED_PROOF_INVALID")
    if not a.ci_json: raise SystemExit("E_REQUIRED_CI_MISSING: provide --ci-json from terminal CI")
    ci=json.loads(a.ci_json.read_text())
    jobs=ci.get("jobs", ci if isinstance(ci,list) else [])
    for job in jobs:
        if job.get("tier") == "required" and (job.get("status") != "completed" or job.get("conclusion") != "success"): raise SystemExit("E_REQUIRED_CI_NOT_GREEN")
    artifacts=[]
    for path in a.artifact:
        if not Path(path).exists(): raise SystemExit(f"E_ARTIFACT_MISSING: {path}")
        artifacts.append({"kind":"release-artifact","path":path,"sha":sha})
    if not artifacts: raise SystemExit("E_ARTIFACT_MISSING: provide --artifact")
    out=a.output or ROOT/f"tests/artifacts/evidence/release-candidate-{sha}.json"; out.parent.mkdir(parents=True,exist_ok=True)
    payload={"schema":"release-candidate-proof/v1","repo":"oraclemcp","generated_at":dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00','Z'),"candidate":{"tag":tag,"version":version},"source":{"sha":sha,"tree_clean":True},"required_proof":{"schema":"required-proof/v1","path":str(proof.relative_to(ROOT)),"sha":sha},"required_ci":{"sha":sha,"jobs":jobs},"artifacts":artifacts,"verdict":"pass"}
    out.write_text(json.dumps(payload,indent=2)+"\n"); print(f"release-candidate-proof: wrote {out}")
    return 0
if __name__ == "__main__":
    try: raise SystemExit(main())
    except subprocess.CalledProcessError as e: raise SystemExit(f"command failed: {e}")
