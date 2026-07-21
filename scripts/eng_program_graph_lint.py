#!/usr/bin/env python3
"""P6 / n4rnp — structural gate over the LIVE engineering-program bead graph.

`plan_bead_graph_lint.py` validates a normalized plan-to-Beads *manifest* before
promotion. This validates the graph that actually exists in `.beads/issues.jsonl`
afterwards, which is where the damage shows up: a graph can be promoted from a
clean manifest and then drift as edges are hand-added, parents are closed, and
beads are tombstoned.

Four structural invariants, each with its own error code so a failure names what
is wrong rather than reporting "invalid graph":

  E_DANGLING              an edge points at a bead that does not exist
  E_ORPHAN_CHILD          a child's parent is missing or tombstoned, so the
                          child can never be closed through its parent
  E_CYCLE_SEQUENCING      a cycle over `blocks` edges: nothing in it can start
  E_CYCLE_HIERARCHY       a cycle over `parent-child` edges: a bead is its own
                          ancestor
  E_CLOSED_PARENT_OPEN_CHILD
                          a parent was closed while a child is still open, so
                          the tracker reports finished work that is not finished

`--selftest` feeds it one deliberately malformed graph per rule and requires the
matching code, plus a well-formed graph that must be ACCEPTED. A validator only
ever observed passing is indistinguishable from one that returns true
unconditionally, and this repository removed several of those today.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Statuses that mean "this work is not finished".
OPEN_STATUSES = {"open", "in_progress"}
# Statuses that mean the bead is no longer a live participant in the graph.
RETIRED_STATUSES = {"tombstone"}
# `discovered-from` and `related` are provenance only: they carry no sequencing,
# so a loop through them is not a contradiction (bead r3sti settled exactly this
# for the close gate).
#
# THE TWO CLASSES ARE CHECKED SEPARATELY, ON PURPOSE. Mixing them reports the
# NORMAL epic shape as a cycle: an epic depends on its children (`epic --blocks-->
# child`, so the epic cannot close until the child does) while each child points
# back up (`child --parent-child--> epic`). Together that is a 2-cycle in a
# combined graph, and the first version of this lint filed six of them against a
# perfectly well-formed program. A cycle is only a contradiction WITHIN one
# class: work that cannot start, or a bead that is its own ancestor.
SEQUENCING_EDGES = {"blocks"}
HIERARCHY_EDGES = {"parent-child"}


class Findings:
    def __init__(self) -> None:
        self.items: list[tuple[str, str]] = []

    def error(self, code: str, message: str) -> None:
        self.items.append((code, message))

    def codes(self) -> set[str]:
        return {code for code, _ in self.items}

    def __len__(self) -> int:
        return len(self.items)


def load_records(path: Path) -> list[dict]:
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(json.loads(line))
    return records


def _edges(record: dict) -> list[dict]:
    return record.get("dependencies") or []


def find_cycles(nodes: dict[str, dict], edge_types: set[str]) -> list[list[str]]:
    """Cycles within ONE edge class, as explicit paths."""
    adjacency: dict[str, list[str]] = {}
    for issue_id, record in nodes.items():
        targets = []
        for edge in _edges(record):
            if edge.get("type") not in edge_types:
                continue
            target = edge.get("depends_on_id")
            if target in nodes:
                targets.append(target)
        adjacency[issue_id] = targets

    cycles: list[list[str]] = []
    seen: set[str] = set()
    # Iterative DFS with an explicit stack: the real graph is >1200 nodes and a
    # recursive walk would risk the interpreter limit rather than reporting.
    for root in adjacency:
        if root in seen:
            continue
        stack = [(root, iter(adjacency[root]))]
        path = [root]
        on_path = {root}
        while stack:
            node, children = stack[-1]
            advanced = False
            for child in children:
                if child in on_path:
                    start = path.index(child)
                    cycles.append(path[start:] + [child])
                    continue
                if child in seen:
                    continue
                stack.append((child, iter(adjacency.get(child, []))))
                path.append(child)
                on_path.add(child)
                advanced = True
                break
            if not advanced:
                stack.pop()
                seen.add(node)
                on_path.discard(node)
                if path:
                    path.pop()
    return cycles


def validate(records: list[dict]) -> Findings:
    findings = Findings()
    nodes = {r["id"]: r for r in records if r.get("id")}

    for issue_id, record in sorted(nodes.items()):
        status = record.get("status")
        for edge in _edges(record):
            target_id = edge.get("depends_on_id")
            edge_type = edge.get("type")
            target = nodes.get(target_id)

            if target is None:
                findings.error(
                    "E_DANGLING",
                    f"{issue_id} has a {edge_type} edge to {target_id!r}, which is not in the graph",
                )
                continue

            if edge_type == "parent-child":
                if target.get("status") in RETIRED_STATUSES:
                    findings.error(
                        "E_ORPHAN_CHILD",
                        f"{issue_id} is a child of {target_id}, which is {target.get('status')} "
                        f"— the child can never be closed through a retired parent",
                    )
                # A closed parent with an unfinished child reports work as done
                # that is not done. This is the one an operator actually reads
                # off a board and believes.
                if target.get("status") == "closed" and status in OPEN_STATUSES:
                    # Carry the parent's stated close reason into the finding.
                    # These are usually DELIBERATE — a parent whose own scope
                    # finished while its children track separate work — and a
                    # reader needs to judge that without opening the tracker.
                    # It stays an ERROR either way: whatever the intent, a board
                    # that shows the parent done while five children are not is
                    # misleading, and `br` itself refuses this close unless
                    # forced.
                    reason = (target.get("close_reason") or "").split("[closing=")[0].strip()
                    excerpt = f" — parent's stated reason: {reason[:120]!r}" if reason else ""
                    findings.error(
                        "E_CLOSED_PARENT_OPEN_CHILD",
                        f"parent {target_id} is closed but child {issue_id} is {status}{excerpt}",
                    )

    for cycle in find_cycles(nodes, SEQUENCING_EDGES):
        findings.error(
            "E_CYCLE_SEQUENCING",
            "blocks cycle (nothing in it can start): " + " -> ".join(cycle),
        )
    for cycle in find_cycles(nodes, HIERARCHY_EDGES):
        findings.error(
            "E_CYCLE_HIERARCHY",
            "parent-child cycle (a bead is its own ancestor): " + " -> ".join(cycle),
        )
    return findings


# --------------------------------------------------------------------------
# selftest
# --------------------------------------------------------------------------

def _bead(issue_id: str, status: str = "open", deps: list[tuple[str, str]] | None = None) -> dict:
    return {
        "id": issue_id,
        "status": status,
        "dependencies": [
            {"issue_id": issue_id, "depends_on_id": target, "type": kind}
            for target, kind in (deps or [])
        ],
    }


def selftest() -> int:
    failures = 0

    def expect(label: str, records: list[dict], code: str | None) -> None:
        nonlocal failures
        findings = validate(records)
        if code is None:
            if len(findings):
                print(f"selftest: {label}: a well-formed graph was REJECTED: {findings.items}", file=sys.stderr)
                failures += 1
            return
        if code not in findings.codes():
            print(
                f"selftest: {label}: expected {code}, got {sorted(findings.codes()) or 'no findings'}",
                file=sys.stderr,
            )
            failures += 1

    # The accept case comes first: a validator that rejects everything is as
    # useless as one that rejects nothing, and only this case can tell them apart.
    expect(
        "well-formed graph",
        [
            _bead("p", "open"),
            _bead("p.1", "closed", [("p", "parent-child")]),
            _bead("p.2", "open", [("p", "parent-child"), ("p.1", "blocks")]),
        ],
        None,
    )

    expect(
        "dangling dependency",
        [_bead("a", "open", [("does-not-exist", "blocks")])],
        "E_DANGLING",
    )

    expect(
        "orphaned child (retired parent)",
        [_bead("parent", "tombstone"), _bead("parent.1", "open", [("parent", "parent-child")])],
        "E_ORPHAN_CHILD",
    )

    expect(
        "parent closed with an open child",
        [_bead("done", "closed"), _bead("done.1", "in_progress", [("done", "parent-child")])],
        "E_CLOSED_PARENT_OPEN_CHILD",
    )

    expect(
        "two-node blocks cycle",
        [
            _bead("x", "open", [("y", "blocks")]),
            _bead("y", "open", [("x", "blocks")]),
        ],
        "E_CYCLE_SEQUENCING",
    )

    expect(
        "three-node blocks cycle",
        [
            _bead("c1", "open", [("c2", "blocks")]),
            _bead("c2", "open", [("c3", "blocks")]),
            _bead("c3", "open", [("c1", "blocks")]),
        ],
        "E_CYCLE_SEQUENCING",
    )

    expect(
        "a bead that is its own ancestor",
        [
            _bead("h1", "open", [("h2", "parent-child")]),
            _bead("h2", "open", [("h1", "parent-child")]),
        ],
        "E_CYCLE_HIERARCHY",
    )

    # THE FALSE-POSITIVE GUARD. This is the normal epic shape and it must be
    # ACCEPTED: the epic depends on its child so it cannot close first, and the
    # child names the epic as its parent. Checking the two edge classes together
    # reports this as a cycle -- the first version of this lint did, filing six
    # against a well-formed program.
    expect(
        "an epic blocked by its own child is not a cycle",
        [
            _bead("epic", "open", [("epic.1", "blocks")]),
            _bead("epic.1", "open", [("epic", "parent-child")]),
        ],
        None,
    )

    # Provenance edges carry no sequencing, so a loop through them is NOT a
    # contradiction. Reporting it would train readers to ignore E_CYCLE.
    expect(
        "provenance-only loop is not a cycle",
        [
            _bead("d1", "open", [("d2", "discovered-from")]),
            _bead("d2", "open", [("d1", "related")]),
        ],
        None,
    )

    if failures:
        print("eng_program_graph_lint selftest: FAIL", file=sys.stderr)
        return 1
    print("eng_program_graph_lint selftest: OK (every rule rejects its own malformation; a well-formed graph is accepted)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jsonl", type=Path, default=Path(".beads/issues.jsonl"))
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument(
        "--label",
        help="restrict the scope to beads carrying this label (default: the whole graph)",
    )
    args = parser.parse_args()

    if args.selftest:
        return selftest()

    records = load_records(args.jsonl)
    if args.label:
        records = [r for r in records if args.label in (r.get("labels") or [])]
    findings = validate(records)

    print(f"eng-program graph: {len(records)} beads from {args.jsonl}")
    if not len(findings):
        print("PASS eng_program_graph_lint: no structural violations")
        return 0

    by_code: dict[str, list[str]] = {}
    for code, message in findings.items:
        by_code.setdefault(code, []).append(message)
    for code in sorted(by_code):
        print(f"\n{code}: {len(by_code[code])}")
        for message in by_code[code][:20]:
            print(f"  {message}")
        if len(by_code[code]) > 20:
            print(f"  … and {len(by_code[code]) - 20} more")
    print(f"\nFAIL eng_program_graph_lint: {len(findings)} structural violation(s)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
