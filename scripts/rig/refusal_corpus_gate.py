#!/usr/bin/env python3
"""R4 refusal-corpus regression gate and punch-list report emitter."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FORBIDDEN_ARTIFACT_PATTERNS = {
    "oci_ocid": re.compile(r"ocid1\.[a-z0-9]+\.", re.IGNORECASE),
    "oraclecloud_cn": re.compile(r"CN=[^\s]*\.oraclecloud\.com", re.IGNORECASE),
    "quarantine_path": re.compile(r"todelete[/\\]todelete[0-9]", re.IGNORECASE),
}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path: Path) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for line_no, raw in enumerate(path.read_text().splitlines(), 1):
        if not raw.strip():
            continue
        record = json.loads(raw)
        case_id = record.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError(f"{path}:{line_no}: missing string case_id")
        if case_id in records:
            raise ValueError(f"{path}:{line_no}: duplicate case_id {case_id}")
        if not isinstance(record.get("allowed"), bool):
            raise ValueError(f"{path}:{line_no}: missing boolean allowed")
        if not isinstance(record.get("category"), str) or not record["category"]:
            raise ValueError(f"{path}:{line_no}: missing category")
        records[case_id] = record
    return records


def severity_for(kind: str, baseline: dict[str, Any]) -> str:
    if kind == "newly_allowed":
        return "P0"
    if kind == "category_changed":
        return baseline.get("severity", "P1")
    return "P2"


def finding(kind: str, case_id: str, baseline: dict[str, Any] | None, candidate: dict[str, Any] | None) -> dict[str, Any]:
    base_category = baseline.get("category") if baseline else None
    cand_category = candidate.get("category") if candidate else None
    base_allowed = baseline.get("allowed") if baseline else None
    cand_allowed = candidate.get("allowed") if candidate else None
    severity = severity_for(kind, baseline or {})
    return {
        "severity": severity,
        "id": f"R4-{kind}-{case_id}",
        "kind": kind,
        "case_id": case_id,
        "summary": f"Refusal corpus regression: {case_id} {kind.replace('_', ' ')}",
        "repro": (baseline or candidate or {}).get("repro", f"re-run refusal corpus case {case_id}"),
        "envelope_evidence": {
            "baseline_allowed": base_allowed,
            "candidate_allowed": cand_allowed,
            "baseline_category": base_category,
            "candidate_category": cand_category,
            "candidate_envelope": (candidate or {}).get("envelope"),
        },
    }


def diff_records(baseline: dict[str, dict[str, Any]], candidate: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for case_id, base in sorted(baseline.items()):
        cand = candidate.get(case_id)
        if cand is None:
            findings.append(finding("missing_candidate", case_id, base, None))
            continue
        if base["allowed"] is False and cand["allowed"] is True:
            findings.append(finding("newly_allowed", case_id, base, cand))
            continue
        if base["category"] != cand["category"]:
            findings.append(finding("category_changed", case_id, base, cand))
    for case_id, cand in sorted(candidate.items()):
        if case_id not in baseline:
            findings.append(finding("new_candidate", case_id, None, cand))
    return findings


def write_jsonl(path: Path, findings: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for item in findings:
            handle.write(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n")


def write_markdown(path: Path, findings: list[dict[str, Any]], baseline: Path, candidate: Path) -> None:
    lines = [
        "# R4 Rig Findings",
        "",
        f"- generated_at: `{now_iso()}`",
        f"- baseline: `{baseline}`",
        f"- candidate: `{candidate}`",
        "",
    ]
    if not findings:
        lines.extend(["No refusal-corpus regressions detected.", ""])
    for item in findings:
        evidence = item["envelope_evidence"]
        lines.extend(
            [
                f"## {item['severity']} {item['id']}",
                "",
                item["summary"],
                "",
                f"- repro: `{item['repro']}`",
                f"- baseline: allowed=`{evidence['baseline_allowed']}` category=`{evidence['baseline_category']}`",
                f"- candidate: allowed=`{evidence['candidate_allowed']}` category=`{evidence['candidate_category']}`",
                f"- envelope evidence: `{json.dumps(evidence['candidate_envelope'], sort_keys=True)}`",
                "",
            ]
        )
    path.write_text("\n".join(lines), encoding="utf-8")


def scan_output(paths: list[Path]) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for name, pattern in FORBIDDEN_ARTIFACT_PATTERNS.items():
            if pattern.search(text):
                hits.append({"path": str(path), "pattern": name})
    return hits


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--expect-findings", type=int)
    parser.add_argument("--scan-output", action="store_true")
    args = parser.parse_args()

    baseline_path = Path(args.baseline)
    candidate_path = Path(args.candidate)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    baseline = read_jsonl(baseline_path)
    candidate = read_jsonl(candidate_path)
    findings = diff_records(baseline, candidate)

    findings_jsonl = out_dir / "findings.jsonl"
    findings_md = out_dir / "findings.md"
    write_jsonl(findings_jsonl, findings)
    write_markdown(findings_md, findings, baseline_path, candidate_path)

    scan_hits = scan_output([findings_jsonl, findings_md]) if args.scan_output else []
    summary = {
        "kind": "oraclemcp_r4_refusal_corpus_gate",
        "generated_at": now_iso(),
        "baseline": str(baseline_path),
        "candidate": str(candidate_path),
        "findings_jsonl": str(findings_jsonl),
        "findings_md": str(findings_md),
        "finding_count": len(findings),
        "newly_allowed_count": sum(1 for item in findings if item["kind"] == "newly_allowed"),
        "category_changed_count": sum(1 for item in findings if item["kind"] == "category_changed"),
        "sensitive_scan_hits": scan_hits,
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True))

    if scan_hits:
        return 3
    if args.expect_findings is not None:
        return 0 if len(findings) >= args.expect_findings else 4
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
