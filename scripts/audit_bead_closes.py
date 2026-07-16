#!/usr/bin/env python3
"""Read-only audit of bead close evidence.

READ-ONLY, and that is a design constraint, not a disclaimer: this command never
writes a bead, never closes or reopens anything, and never touches a file. An
auditor that can change the thing it audits is not an auditor. `--template` is
the one exception and it only prints to stdout.

What it audits
--------------
Closes that carry a bead-close-evidence/v1 document under
tests/artifacts/evidence/closes/<bead-id>.json get the full check: the document
must satisfy the contract, its proof references must exist on disk, and every
SHA it cites must be a real commit in this repository.

Closes that carry no document are reported as UNEVIDENCED. They are not failures.
This repo has hundreds of closes that predate the contract, and retroactively
failing them would only teach people to ignore the audit. Coverage is reported as
a number so it can move in one direction.

Two tiers, kept apart on purpose
--------------------------------
  hard      Structural, exit non-zero. Every check is decidable: a document
            either satisfies the schema or does not; a SHA either resolves or
            does not.
  advisory  Heuristics over free-text close reasons, reported and never gating.
            Text scanning cannot be made reliable -- see the note on upstream
            SHAs in _scan_reason -- and an audit that cries wolf gets muted,
            which is worse than one that stays quiet.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLOSES_DIR = ROOT / "tests" / "artifacts" / "evidence" / "closes"

_spec = importlib.util.spec_from_file_location(
    "validate_evidence", ROOT / "scripts" / "validate_evidence.py"
)
_ve = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ve)

# A bare 7-40 hex run. Deliberately loose; every hit is treated as advisory only.
_SHA_RE = re.compile(r"\b([0-9a-f]{7,40})\b")

# Claims that assert behaviour against something real and external. If a close
# says one of these, the reader is entitled to an artifact.
_LIVE_CLAIM_RE = re.compile(
    r"\b(live|end-to-end|e2e|23ai|21c|18c|against the (database|server)|"
    r"real (database|server))\b",
    re.I,
)


class Finding:
    def __init__(self, tier: str, bead: str, code: str, message: str) -> None:
        self.tier = tier
        self.bead = bead
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"[{self.tier}] {self.bead}: {self.code} — {self.message}"


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=False
    )


def _commit_exists(sha: str) -> bool:
    return _git("cat-file", "-e", f"{sha}^{{commit}}").returncode == 0


def _closed_beads() -> list:
    out = subprocess.run(
        ["br", "list", "--status", "closed", "--json", "--limit", "1000"],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    if out.returncode != 0:
        print(f"audit: br list failed: {out.stderr.strip()}", file=sys.stderr)
        raise SystemExit(2)
    payload = json.loads(out.stdout)
    return payload["issues"] if isinstance(payload, dict) else payload


def _reason_of(bead: dict) -> str:
    for key in ("close_reason", "reason", "resolution"):
        if bead.get(key):
            return str(bead[key])
    return ""


def _scan_reason(bead: dict) -> list:
    """Advisory heuristics over a free-text close reason.

    Never hard. A close reason legitimately cites SHAs this repository does not
    contain -- upstream python-oracledb commits, for one (etib.2 cites
    6cfd00aa642e, an upstream reference that will never resolve here). Failing on
    an unresolvable SHA would flag correct closes, so this reports and moves on.
    """
    findings: list = []
    bead_id = bead["id"]
    reason = _reason_of(bead)
    if not reason:
        return findings

    shas = [s for s in _SHA_RE.findall(reason) if not s.isdigit()]
    unresolvable = [s for s in shas if not _commit_exists(s)]
    if unresolvable:
        findings.append(
            Finding(
                "advisory",
                bead_id,
                "CITED_SHA_UNRESOLVABLE",
                f"close cites {', '.join(unresolvable)}, which do not resolve to a "
                "commit here (may be an upstream reference, or may be fabricated)",
            )
        )

    if _LIVE_CLAIM_RE.search(reason) and not shas:
        findings.append(
            Finding(
                "advisory",
                bead_id,
                "LIVE_CLAIM_WITHOUT_REFERENCE",
                "close makes a live/end-to-end claim but cites no commit or artifact",
            )
        )
    return findings


def _audit_document(path: Path) -> list:
    """Hard checks on one bead-close-evidence/v1 document."""
    findings: list = []
    bead_id = path.stem

    try:
        doc = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        return [Finding("hard", bead_id, "MALFORMED_JSON", str(exc))]

    for f in _ve.validate_doc(doc):
        findings.append(
            Finding("hard", bead_id, f.code, f"{f.path or '/'}: {f.message}")
        )
    if findings:
        # The contract rejected it; deeper checks would index into a document
        # that is not the shape they assume.
        return findings

    if doc["bead_id"] != bead_id:
        findings.append(
            Finding(
                "hard",
                bead_id,
                "BEAD_ID_MISMATCH",
                f"file is named {bead_id}.json but declares {doc['bead_id']!r}",
            )
        )

    if not _commit_exists(doc["source"]["sha"]):
        findings.append(
            Finding(
                "hard",
                bead_id,
                "SOURCE_SHA_ABSENT",
                f"{doc['source']['sha']} is not a commit in this repository",
            )
        )

    for proof in doc["proofs"]:
        if not (ROOT / proof["path"]).exists():
            findings.append(
                Finding(
                    "hard",
                    bead_id,
                    "PROOF_ARTIFACT_ABSENT",
                    f"{proof['schema']} references {proof['path']}, which is not on disk",
                )
            )

    for artifact in doc["live_evidence"]["artifacts"]:
        if not (ROOT / artifact["path"]).exists():
            findings.append(
                Finding(
                    "hard",
                    bead_id,
                    "LIVE_ARTIFACT_ABSENT",
                    f"live claim references {artifact['path']}, which is not on disk",
                )
            )

    return findings


TEMPLATE = {
    "schema": "bead-close-evidence/v1",
    "repo": "oraclemcp",
    "generated_at": "REPLACE-WITH-RFC3339-UTC",
    "bead_id": "REPLACE",
    "scope": {
        "summary": "What this close covers, in one sentence.",
        "in_scope": ["path or behaviour actually delivered"],
        "out_of_scope": ["what a reader might assume was done but was not"],
    },
    "source": {"sha": "REPLACE-WITH-40-HEX", "tree_clean": True, "branch": "main"},
    "proofs": [],
    "integration_evidence": {
        "entry_points": [
            {
                "name": "the command or route that reaches this change",
                "kind": "cli",
                "trace": "the test or artifact tracing it to a result",
            }
        ]
    },
    "live_evidence": {"claimed": False, "artifacts": []},
    "limitations": ["State them. Empty means you assert there are none."],
    "known_defects": [],
    "follow_ups": [],
    "readiness": {"claim": "not-ready", "basis": "scoped-test"},
}


def template(bead_id: str) -> int:
    doc = json.loads(json.dumps(TEMPLATE))
    doc["bead_id"] = bead_id
    head = _git("rev-parse", "HEAD").stdout.strip()
    if head:
        doc["source"]["sha"] = head
    doc["source"]["tree_clean"] = not _git("status", "--porcelain").stdout.strip()
    print(json.dumps(doc, indent=2))
    print(
        f"\n# Write to tests/artifacts/evidence/closes/{bead_id}.json, then:\n"
        f"#   scripts/check_bead_close_evidence.sh",
        file=sys.stderr,
    )
    return 0


def audit(strict: bool) -> int:
    beads = _closed_beads()
    documents = sorted(CLOSES_DIR.glob("*.json")) if CLOSES_DIR.exists() else []
    evidenced = {p.stem for p in documents}

    findings: list = []
    for path in documents:
        findings.extend(_audit_document(path))
    for bead in beads:
        findings.extend(_scan_reason(bead))

    hard = [f for f in findings if f.tier == "hard"]
    advisory = [f for f in findings if f.tier == "advisory"]

    closed_ids = {b["id"] for b in beads}
    orphans = sorted(evidenced - closed_ids)
    unevidenced = len(closed_ids - evidenced)

    if hard:
        print("HARD findings (these fail the audit):")
        for f in hard:
            print(f"  {f}")
        print()
    if advisory:
        print(f"Advisory findings ({len(advisory)}, never gating):")
        for f in advisory[:20]:
            print(f"  {f}")
        if len(advisory) > 20:
            print(f"  ... and {len(advisory) - 20} more")
        print()
    if orphans:
        print("Close evidence for beads that are not closed:")
        for bead_id in orphans:
            print(f"  [advisory] {bead_id}: evidence exists but the bead is not closed")
        print()

    print(
        f"audit: {len(closed_ids)} closed beads, {len(evidenced & closed_ids)} with "
        f"close evidence, {unevidenced} unevidenced (pre-contract closes are not "
        f"failures); {len(hard)} hard, {len(advisory)} advisory findings"
    )

    if hard:
        return 1
    if strict and unevidenced:
        print(
            f"audit: --strict, and {unevidenced} closed beads carry no evidence",
            file=sys.stderr,
        )
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only audit of bead close evidence.")
    parser.add_argument("--template", metavar="BEAD_ID", help="print a close-evidence skeleton")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="also fail when any closed bead has no evidence (not the default: "
        "this repo predates the contract)",
    )
    args = parser.parse_args()

    if args.template:
        return template(args.template)
    return audit(args.strict)


if __name__ == "__main__":
    sys.exit(main())
