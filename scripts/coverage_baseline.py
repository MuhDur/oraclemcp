#!/usr/bin/env python3
"""Aggregate a raw cargo-llvm-cov JSON export into the committed coverage
baseline (bead D1 / oraclemcp-eng-program-bp8ia.5.1).

Two subcommands, invoked by scripts/coverage_baseline.sh -- see that script's
header for the full contract, what is and isn't measured, and why there is
no drift/ratchet gate here (that is bead D2's job):

  generate --raw <path> --out-dir <dir> --command "<cmd>"
      Parse the raw `cargo llvm-cov --json --summary-only` export, aggregate
      per crate (crates/<name>/src/...) plus a workspace TOTAL, and write
      <out-dir>/BASELINE.json (schema coverage-baseline/v1) and
      <out-dir>/BASELINE.md (human-readable summary + regen instructions).

  check --out-dir <dir>
      Structural validation only: the committed baseline exists, is
      well-formed JSON, and matches its declared schema. Does NOT re-run
      coverage and does NOT detect numeric drift from HEAD.
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "coverage-baseline/v1"
CRATE_RE = re.compile(r"crates/([^/]+)/src/")
METRICS = ("lines", "regions", "functions")


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def _percent(covered: int, count: int) -> float:
    return round((covered / count) * 100, 2) if count else 0.0


def aggregate(raw: dict) -> dict:
    data = raw["data"][0]
    per_crate: dict[str, dict[str, list[int]]] = {}
    unmatched: list[str] = []
    for f in data["files"]:
        filename = f["filename"]
        try:
            rel = Path(filename).resolve().relative_to(ROOT).as_posix()
        except ValueError:
            rel = filename
        m = CRATE_RE.search(rel)
        if not m:
            unmatched.append(rel)
            continue
        crate = m.group(1)
        bucket = per_crate.setdefault(crate, {metric: [0, 0] for metric in METRICS})
        summary = f["summary"]
        for metric in METRICS:
            bucket[metric][0] += summary[metric]["count"]
            bucket[metric][1] += summary[metric]["covered"]

    crates = []
    for name in sorted(per_crate):
        b = per_crate[name]
        entry = {"name": name}
        for metric in METRICS:
            count, covered = b[metric]
            entry[metric] = {"count": count, "covered": covered, "percent": _percent(covered, count)}
        crates.append(entry)

    totals = data["totals"]
    total = {}
    for metric in METRICS:
        count = totals[metric]["count"]
        covered = totals[metric]["covered"]
        total[metric] = {"count": count, "covered": covered, "percent": _percent(covered, count)}

    # Sanity check: per-crate sums should equal the reported workspace
    # totals. This workspace's crates all live under crates/*/src, and
    # cargo-llvm-cov already scopes its report to workspace-member source
    # (verified empirically -- see coverage_baseline.sh's header), so a
    # mismatch here means the layout changed and this script's crate-name
    # regex needs updating, not that the numbers are wrong.
    summed_lines = sum(c["lines"]["count"] for c in crates)
    if summed_lines != total["lines"]["count"]:
        note = f" ({len(unmatched)} unmatched files, e.g. {unmatched[:5]})" if unmatched else ""
        print(
            f"coverage_baseline: WARNING: per-crate line count sum ({summed_lines}) != "
            f"workspace total ({total['lines']['count']}){note}",
            file=sys.stderr,
        )

    return {"crates": crates, "total": total, "unmatched_files": unmatched}


def render_markdown(doc: dict) -> str:
    lines = [
        "# Coverage baseline",
        "",
        "**Generated, not hand-authored.** Regenerate with"
        " `bash scripts/coverage_baseline.sh` (heavy, instrumented; Tier 2 /"
        " nightly, not per-PR -- see `docs/test-tiers.md`). Do not hand-edit"
        " this file or `BASELINE.json`.",
        "",
        f"- Generated at: `{doc['generated_at']}`",
        f"- Git SHA: `{doc['git_sha']}`",
        f"- Tool: `{doc['cargo_llvm_cov_version']}`",
        f"- Command: `{doc['command']}`",
        f"- Scope: {doc['measured']['scope']}, features={doc['measured']['features']}",
        f"- Excluded: {', '.join(doc['measured']['excludes'])}",
        f"- Unit: {doc['measured']['unit']}",
        "",
        "This is bead D1 (plan §30.2): an EMPIRICAL baseline only. There is"
        " no ratchet or gate here yet -- that is bead D2 (changed-line"
        " coverage plus a per-crate mutation floor on guard/audit/db, not a"
        " naive never-decrease global line; plan §32.2 TRI-1).",
        "",
        "## Workspace total",
        "",
        "| Metric | Covered | Total | Percent |",
        "| --- | ---: | ---: | ---: |",
    ]
    for metric in METRICS:
        t = doc["total"][metric]
        lines.append(f"| {metric} | {t['covered']} | {t['count']} | {t['percent']}% |")
    lines += [
        "",
        "## Per crate",
        "",
        "| Crate | Line % | Lines | Region % | Regions | Function % | Functions |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for c in doc["crates"]:
        line, region, func = c["lines"], c["regions"], c["functions"]
        lines.append(
            f"| {c['name']} | {line['percent']}% | {line['covered']}/{line['count']} "
            f"| {region['percent']}% | {region['covered']}/{region['count']} "
            f"| {func['percent']}% | {func['covered']}/{func['count']} |"
        )
    if doc.get("unmatched_files"):
        lines += [
            "",
            f"**{len(doc['unmatched_files'])} file(s) reported by cargo-llvm-cov did not match"
            " any `crates/<name>/src/` path** and are excluded from the per-crate table above"
            " (see `unmatched_files` in `BASELINE.json`).",
        ]
    lines.append("")
    return "\n".join(lines)


def cmd_generate(args: argparse.Namespace) -> int:
    raw = json.loads(Path(args.raw).read_text())
    agg = aggregate(raw)
    sha = _git("rev-parse", "HEAD")
    generated_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cov_version = subprocess.check_output(["cargo", "llvm-cov", "--version"], cwd=ROOT, text=True).strip()

    doc = {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "git_sha": sha,
        "cargo_llvm_cov_version": cov_version,
        "command": args.command,
        "measured": {
            "scope": "oraclemcp workspace (crates/*); the driver, rust-oracledb, is a separate repo and needs its own baseline",
            "features": "default",
            "excludes": ["live-xe", "plsql-intelligence", "doctests"],
            "unit": "source lines/regions/functions under crates/*/src (cargo-llvm-cov's own workspace scoping; integration tests, fuzz targets, and dependencies are not instrumented)",
        },
        "crates": agg["crates"],
        "total": agg["total"],
    }
    if agg["unmatched_files"]:
        doc["unmatched_files"] = agg["unmatched_files"]

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    baseline_json = out_dir / "BASELINE.json"
    baseline_json.write_text(json.dumps(doc, indent=2) + "\n")
    (out_dir / "BASELINE.md").write_text(render_markdown(doc))
    print(f"coverage_baseline: wrote {baseline_json}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir)
    baseline_json = out_dir / "BASELINE.json"
    baseline_md = out_dir / "BASELINE.md"
    errors: list[str] = []
    if not baseline_json.is_file():
        errors.append(f"missing {baseline_json}")
    if not baseline_md.is_file():
        errors.append(f"missing {baseline_md}")
    if errors:
        for e in errors:
            print(f"coverage_baseline: FAIL: {e}", file=sys.stderr)
        return 1
    try:
        doc = json.loads(baseline_json.read_text())
    except json.JSONDecodeError as e:
        print(f"coverage_baseline: FAIL: {baseline_json} is not valid JSON: {e}", file=sys.stderr)
        return 1
    if doc.get("schema") != SCHEMA:
        print(f"coverage_baseline: FAIL: schema must be {SCHEMA!r}, got {doc.get('schema')!r}", file=sys.stderr)
        return 1
    if not doc.get("crates"):
        print("coverage_baseline: FAIL: crates list is empty", file=sys.stderr)
        return 1
    if "total" not in doc:
        print("coverage_baseline: FAIL: no total row", file=sys.stderr)
        return 1
    for metric in METRICS:
        if metric not in doc["total"]:
            print(f"coverage_baseline: FAIL: total row missing {metric}", file=sys.stderr)
            return 1
    print(
        "coverage_baseline: OK (structural check only -- committed baseline is well-formed; "
        "this does NOT re-run coverage or detect drift from HEAD, that ratchet is bead D2's job)."
    )
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="action", required=True)

    g = sub.add_parser("generate")
    g.add_argument("--raw", required=True)
    g.add_argument("--out-dir", required=True)
    g.add_argument("--command", required=True)
    g.set_defaults(func=cmd_generate)

    c = sub.add_parser("check")
    c.add_argument("--out-dir", required=True)
    c.set_defaults(func=cmd_check)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, KeyError, json.JSONDecodeError, subprocess.CalledProcessError) as e:
        raise SystemExit(f"coverage_baseline: E_INVALID: {e}")
