#!/usr/bin/env python3
"""plan-bead-graph lint (G9 / bead oraclemcp-plan-bead-graph-lint-eshv, v1).

Deterministic, stdlib-only validator for a normalized plan-to-beads
conversion, run BEFORE a converted graph is promoted to execution
(plan v8 sec.10; first target: the 091/090 field-hardening train).

Checks (hard unless noted):
  H1  unique issue ids.
  H2  no label contains a dot (br label constraint).
  H3  the blocks-dependency graph is acyclic (recomputed here,
      independently of `br dep cycles`).
  H4  SINK PROPERTY: every train-labeled, non-closed, non-deferred bead
      that does not carry the `sink-exempt` label is an ancestor of the
      declared terminal sink through blocks edges (the sink transitively
      depends on it). Exemptions are the operator-ruled allowlist
      (plan v8 sec.10) expressed as the `sink-exempt` label so the lint
      never hardcodes ids.
  H5  the sink itself has at least one open blocks-dependency
      (publishing can never be `ready` while train work is open).
  H6  self-containedness for beads AUTHORED by the conversion (id
      contains the train slug marker, e.g. `-091-` / `-090-`):
      description >= 200 chars and mentions ACCEPTANCE.
  W1  (warn) legacy beads pulled into the train (train label, no slug
      marker) whose description lacks an acceptance mention.

Usage:
  scripts/plan_bead_graph_lint.py --train-label train-091 \
      --sink oraclemcp-eng-program-bp8ia.13 --marker -091- [--input dump.json]

Reads `br list --limit 0 --json` from the current checkout unless
--input provides a saved dump. Exits 0 on pass, 1 on any hard finding.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import defaultdict


def load_issues(path: str | None) -> list[dict]:
    if path:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    else:
        out = subprocess.run(
            ["br", "list", "--limit", "0", "--json"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        doc = json.loads(out)
    issues = doc["issues"] if isinstance(doc, dict) else doc
    if not isinstance(issues, list):
        raise SystemExit("lint: unexpected br list shape")
    return issues


def load_deps(issue_id: str) -> list[tuple[str, str]]:
    out = subprocess.run(
        ["br", "dep", "list", issue_id, "--json"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    doc = json.loads(out)
    rows = doc if isinstance(doc, list) else doc.get("dependencies", [])
    edges = []
    for row in rows:
        target = row.get("depends_on_id") or row.get("id") or row.get("to_id")
        dep_type = row.get("dep_type") or row.get("type") or "blocks"
        if target:
            edges.append((target, dep_type))
    return edges


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-label", required=True)
    ap.add_argument("--sink", required=True)
    ap.add_argument("--marker", required=True, help="id substring marking conversion-authored beads")
    ap.add_argument("--input", default=None)
    args = ap.parse_args()

    issues = load_issues(args.input)
    by_id = {}
    hard: list[str] = []
    warn: list[str] = []

    # H1 unique ids
    for issue in issues:
        iid = issue.get("id")
        if iid in by_id:
            hard.append(f"H1 duplicate id: {iid}")
        by_id[iid] = issue

    train = {
        iid: iss
        for iid, iss in by_id.items()
        if args.train_label in (iss.get("labels") or [])
    }
    if args.sink not in by_id:
        hard.append(f"H4 sink {args.sink} not found")
        report(hard, warn, train)
        return 1

    # H2 label hygiene
    for iid, iss in train.items():
        for label in iss.get("labels") or []:
            if "." in label:
                hard.append(f"H2 label with dot on {iid}: {label}")

    # Build the blocks graph over train beads + sink (queried live per bead).
    graph: dict[str, set[str]] = defaultdict(set)  # issue -> its dependencies
    universe = set(train) | {args.sink}
    for iid in sorted(universe):
        for target, dep_type in load_deps(iid):
            if dep_type == "blocks":
                graph[iid].add(target)

    # H3 acyclicity (iterative DFS over the queried subgraph)
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = defaultdict(int)
    for start in sorted(universe):
        if color[start] != WHITE:
            continue
        stack = [(start, iter(sorted(graph.get(start, ()))))]
        color[start] = GRAY
        while stack:
            node, it = stack[-1]
            advanced = False
            for nxt in it:
                if color[nxt] == GRAY:
                    hard.append(f"H3 cycle through {node} -> {nxt}")
                elif color[nxt] == WHITE and nxt in universe:
                    color[nxt] = GRAY
                    stack.append((nxt, iter(sorted(graph.get(nxt, ())))))
                    advanced = True
                    break
            if not advanced:
                color[node] = BLACK
                stack.pop()

    # H4 sink property: ancestors(sink) via blocks edges
    ancestors: set[str] = set()
    frontier = [args.sink]
    while frontier:
        node = frontier.pop()
        for dep in graph.get(node, ()):
            if dep not in ancestors:
                ancestors.add(dep)
                if dep in universe:
                    frontier.append(dep)
                else:
                    # dependency outside the train universe: load its deps once
                    for target, dep_type in load_deps(dep):
                        if dep_type == "blocks":
                            graph[dep].add(target)
                    frontier.append(dep)
    for iid, iss in sorted(train.items()):
        if iid == args.sink:
            continue
        status = iss.get("status")
        if status in ("closed", "deferred"):
            continue
        if "sink-exempt" in (iss.get("labels") or []):
            continue
        if iid not in ancestors:
            hard.append(f"H4 not a sink ancestor: {iid}")

    # H5 sink must be blocked by open work
    open_blockers = [
        dep
        for dep in graph.get(args.sink, ())
        if by_id.get(dep, {}).get("status") in ("open", "in_progress")
    ]
    if not open_blockers:
        hard.append("H5 sink has no open blocks-dependency (would be ready)")

    # H6 / W1 self-containedness
    for iid, iss in sorted(train.items()):
        if iss.get("status") in ("closed",):
            continue
        desc = (iss.get("description") or "") + (iss.get("notes") or "")
        authored = args.marker in iid
        if iss.get("issue_type") == "epic":
            continue
        if authored:
            if len(desc) < 200:
                hard.append(f"H6 short description ({len(desc)}) on {iid}")
            if "acceptance" not in desc.lower():
                hard.append(f"H6 no acceptance criterion on {iid}")
        elif "acceptance" not in desc.lower():
            warn.append(f"W1 legacy train bead without acceptance text: {iid}")

    report(hard, warn, train)
    return 1 if hard else 0


def report(hard: list[str], warn: list[str], train: dict) -> None:
    for line in warn:
        print(f"lint: WARN {line}")
    for line in hard:
        print(f"lint: HARD {line}")
    verdict = "FAIL" if hard else "PASS"
    print(
        f"plan-bead-graph-lint: {verdict} — train beads={len(train)} "
        f"hard={len(hard)} warn={len(warn)}"
    )


if __name__ == "__main__":
    sys.exit(main())
