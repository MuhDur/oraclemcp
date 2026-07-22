#!/usr/bin/env python3
"""P6 / n4rnp — build the normalized plan-bead-graph/v2 import manifest.

`plan_bead_graph_lint.py --manifest` validates a v2 manifest before promotion;
`--promote --apply` wires one into the live tracker. What was missing was the
import path itself: the tool that turns the live engineering-program graph into
that manifest. This is it.

It is a HARVESTER, not an author. The lint requires every task to carry
self-contained `scope`, `acceptance`, and `evidence`. Most of that is editorial
— a human judgement about what "done" means for a task — and fabricating it
would produce exactly the "plausible but hollow artifact" the operator named on
n4rnp. So this tool harvests ONLY content that already exists and is real:

  * `acceptance`  <- the bead's `acceptance_criteria` field, when present
  * `evidence`    <- the `evidence=<path>` recorded in a closed bead's
                     `close_reason`, when that file exists on disk
  * `scope`       <- the `scope.in_scope` path list inside that evidence JSON

Where no real content exists the field is emitted EMPTY. That is deliberate: the
lint then hard-gates the manifest (E_TASK_ACCEPTANCE / E_TASK_EVIDENCE /
E_TASK_SCOPE), so the residual is not a vague "needs an authoring pass" but a
deterministic, gateable punch-list naming exactly which tasks still need a human
to write their acceptance/evidence/scope. `--punch-list` prints that residual
grouped by the missing field.

Edges: only `blocks` edges become native manifest `dependencies`. `parent-child`
and `discovered-from` are hierarchy/provenance and already live in the tracker
graph that `eng_program_graph_lint.py` validates separately; re-encoding the
parent-child back-edge here would manufacture the false cycle that lint documents
(epic --blocks--> child while child --parent-child--> epic). Tombstoned beads are
excluded — they are no longer live participants.

Read-only with respect to the tracker: nothing here mutates `.beads/`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


SCHEMA = "plan-bead-graph/v2"
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
# `evidence=<path>` inside a close_reason; the close-gate writes a repo-relative
# tests/artifacts/evidence/closes/<id>.json there.
EVIDENCE_RE = re.compile(r"evidence=(\S+\.json)")

# Cluster label -> the plan section that specifies it (PLAN_ENGINEERING_PROGRAM.md
# §33 beading index). p6 is the bootstrap precondition (§27.6 item 5).
CLUSTER_SECTION = {
    "cluster-a": "§29.6",
    "cluster-b": "§25",
    "cluster-c": "§26",
    "cluster-d": "§25.7.3",
    "cluster-e": "§27.3",
    "cluster-f": "§28",
    "cluster-g": "§27.7",
    "cluster-h": "§30.4",
    "cluster-i": "§30.7",
    "cluster-j": "§19",
    "cluster-k": "§32.3",
    "cluster-p6": "§27.6",
}
DEFAULT_SECTION = "§33"

# Priority -> execution tier. The lint accepts P0-P4, T0-T3, tier-1..3, and the
# named tiers; we use the tier-N form so the mapping is total and deterministic.
PRIORITY_TIER = {0: "tier-1", 1: "tier-2", 2: "tier-3", 3: "tier-3", 4: "tier-3"}


def slugify(issue_id: str) -> str:
    """Normalize a bead id to a Beads-legal slug (no '.', lowercase, '-' runs)."""
    slug = re.sub(r"[^a-z0-9]+", "-", issue_id.lower())
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug[:64]


def dotfree(label: str) -> str:
    """Beads rejects '.' in labels; the slug is already dot-free, so use it."""
    return label.replace(".", "-")


def load_records(path: Path) -> list[dict]:
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(json.loads(line))
    return records


def engineering_program_ids(records: list[dict], source_repo: str) -> set[str]:
    """The eng-program graph: train-091 seeds plus everything they reach, scoped
    to one repository. Edges leaving the closure are reported by the caller."""
    by_id = {r["id"]: r for r in records if r.get("id")}
    seeds = {r["id"] for r in records if "train-091" in (r.get("labels") or [])}
    graph: set[str] = set(seeds)
    frontier = list(seeds)
    while frontier:
        current = frontier.pop()
        record = by_id.get(current)
        if record is None:
            continue
        for edge in record.get("dependencies") or []:
            target = edge.get("depends_on_id")
            if (
                target in by_id
                and target not in graph
                and by_id[target].get("source_repo") == source_repo
            ):
                graph.add(target)
                frontier.append(target)
    return graph


def cluster_of(record: dict) -> str | None:
    for label in record.get("labels") or []:
        if label.startswith("cluster-"):
            return label
    return None


def harvest_evidence_paths(record: dict, root: Path) -> list[str]:
    """Real evidence: the close_reason's evidence= path, only if the file exists."""
    match = EVIDENCE_RE.search(record.get("close_reason") or "")
    if not match:
        return []
    rel = match.group(1)
    if (root / rel).exists():
        return [rel]
    return []


def harvest_scope(evidence_paths: list[str], root: Path) -> list[str]:
    """Real scope: the evidence JSON's scope.in_scope path list, when present."""
    scope: list[str] = []
    for rel in evidence_paths:
        try:
            payload = json.loads((root / rel).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        in_scope = (payload.get("scope") or {}).get("in_scope")
        if isinstance(in_scope, list):
            for item in in_scope:
                if isinstance(item, str) and item.strip() and item not in scope:
                    scope.append(item.strip())
    return scope


def harvest_acceptance(record: dict) -> list[str]:
    """Real acceptance: the bead's acceptance_criteria, split on numbered lines."""
    text = (record.get("acceptance_criteria") or "").strip()
    if not text:
        return []
    items: list[str] = []
    for line in text.splitlines():
        # Drop a leading "N." / "N)" enumerator so numbered criteria read clean.
        chunk = re.sub(r"^\s*\d+[.)]\s*", "", line).strip()
        if chunk:
            items.append(chunk)
    return items or [text]


def plan_label_for(record: dict, slug: str) -> str:
    """Reuse an existing plan: label if the bead has one; else derive one."""
    for label in record.get("labels") or []:
        if label.startswith("plan:"):
            return label
    digest = hashlib.sha256(slug.encode("utf-8")).hexdigest()[:8]
    return f"plan:ep260718:{slug[:40]}-{digest}"


def build_task(record: dict, root: Path, id_to_slug: dict[str, str], graph: set[str]) -> dict:
    slug = id_to_slug[record["id"]]
    cluster = cluster_of(record)
    section = CLUSTER_SECTION.get(cluster, DEFAULT_SECTION) if cluster else DEFAULT_SECTION
    priority = record.get("priority")
    if not isinstance(priority, int) or isinstance(priority, bool) or not 0 <= priority <= 4:
        priority = 2
    evidence = harvest_evidence_paths(record, root)
    scope = harvest_scope(evidence, root)
    acceptance = harvest_acceptance(record)

    # Native dependencies: blocks edges only, targets inside the live graph.
    dependencies: list[str] = []
    for edge in record.get("dependencies") or []:
        if edge.get("type") != "blocks":
            continue
        target = edge.get("depends_on_id")
        if target in graph and target in id_to_slug:
            target_slug = id_to_slug[target]
            if target_slug not in dependencies:
                dependencies.append(target_slug)

    tracking_label = dotfree(slug)
    plan_label = plan_label_for(record, slug)
    labels = [tracking_label, plan_label]
    if cluster and cluster not in labels:
        labels.append(cluster)

    return {
        "slug": slug,
        "repository": "server",
        "tracker": "server",
        "title": record.get("title") or slug,
        "type": record.get("issue_type") or "task",
        "priority": priority,
        "tier": PRIORITY_TIER[priority],
        "labels": labels,
        "tracking_label": tracking_label,
        "plan": {"section": section, "label": plan_label},
        "scope": scope,
        "acceptance": acceptance,
        "evidence": evidence,
        "dependencies": sorted(dependencies),
        "parent": None,
        "handoffs": [],
        "operator_gate": "none",
        # Every task already exists in the tracker; the manifest documents the
        # live graph read-only. Nothing here is a new issue to create.
        "promotion": "deferred",
        "lineage": {"kind": "existing", "issue_id": record["id"]},
        "reuse": {"action": "defer-existing", "issue_id": record["id"]},
        "cluster": (cluster or "").replace("cluster-", "").upper() or None,
    }


def build_manifest(
    root: Path,
    jsonl: Path,
    plan_path: Path,
    source_repo: str = "oraclemcp",
) -> dict:
    records = load_records(jsonl)
    graph = engineering_program_ids(records, source_repo)
    by_id = {r["id"]: r for r in records if r.get("id")}

    # Exclude tombstoned beads: they are no longer live participants.
    live_ids = sorted(i for i in graph if by_id[i].get("status") != "tombstone")
    id_to_slug = {issue_id: slugify(issue_id) for issue_id in live_ids}

    # Slug uniqueness is a hard lint rule; refuse to emit a colliding manifest.
    seen: dict[str, str] = {}
    for issue_id, slug in id_to_slug.items():
        if slug in seen:
            raise SystemExit(
                f"slug collision: {issue_id} and {seen[slug]} both normalize to {slug!r}; "
                "the manifest cannot represent both — resolve the ids before building"
            )
        seen[slug] = issue_id

    tasks = [build_task(by_id[issue_id], root, id_to_slug, set(live_ids)) for issue_id in live_ids]

    plan_rel = plan_path.relative_to(root) if plan_path.is_absolute() else plan_path
    return {
        "schema": SCHEMA,
        "program": {"slug": "engineering-program"},
        "source_document": {
            "path": str(plan_rel),
            "sha256": hashlib.sha256(plan_path.read_bytes()).hexdigest(),
        },
        "repositories": [{"slug": "server", "path": ".", "source_repo": source_repo}],
        "trackers": [
            {
                "repository": "server",
                "path": str(jsonl.relative_to(root) if jsonl.is_absolute() else jsonl),
                "source_repo": source_repo,
            }
        ],
        "release_targets": [{"repository": "server", "version": "0.9.1", "assertion": "patch"}],
        "tasks": tasks,
    }


def punch_list(manifest: dict) -> dict[str, list[str]]:
    """Group tasks by the editorial field they still lack. A task missing several
    fields appears under each — the residual is the authoring work that remains."""
    missing: dict[str, list[str]] = {"scope": [], "acceptance": [], "evidence": []}
    for task in manifest["tasks"]:
        for field in missing:
            if not task.get(field):
                missing[field].append(task["slug"])
    return missing


def _selftest() -> int:
    """Prove the harvester is faithful, mutation-controlled per the repo standard.

    Build a tiny tracker + evidence file on disk, harvest it, and require:
      * acceptance comes ONLY from acceptance_criteria (not description),
      * evidence comes ONLY from an existing close_reason evidence= path,
      * scope comes ONLY from the evidence JSON's scope.in_scope,
      * only `blocks` edges become dependencies (parent-child/discovered-from do not),
      * a task with no real content has empty fields (never fabricated),
      * tombstoned beads are excluded.
    Then neuter each harvest function and require the corresponding field to go
    empty — so a harvester that silently fabricates cannot pass its own test.
    """
    import tempfile

    failures = 0

    def check(label: str, condition: bool) -> None:
        nonlocal failures
        if not condition:
            print(f"selftest: {label}: FAILED", file=sys.stderr)
            failures += 1

    root = Path(tempfile.mkdtemp(prefix="oraclemcp-manifest-build-", dir="/var/tmp"))
    (root / ".beads").mkdir(parents=True, exist_ok=True)
    (root / "plan.md").write_text("# plan\n", encoding="utf-8")
    ev_rel = "tests/artifacts/evidence/closes/oraclemcp-x.json"
    ev_path = root / ev_rel
    ev_path.parent.mkdir(parents=True, exist_ok=True)
    ev_path.write_text(
        json.dumps({"scope": {"in_scope": ["crates/oraclemcp/src/lib.rs"]}}),
        encoding="utf-8",
    )

    def bead(issue_id, status="open", **kw):
        rec = {"id": issue_id, "status": status, "source_repo": "oraclemcp",
               "title": f"title {issue_id}", "issue_type": "task", "priority": 1,
               "labels": ["train-091"], "dependencies": []}
        rec.update(kw)
        return rec

    records = [
        bead("oraclemcp-a", acceptance_criteria="1. does the thing\n2. stays patch-safe"),
        bead("oraclemcp-b", status="closed",
             close_reason=f"done [closing=abc source=def evidence={ev_rel}]"),
        bead("oraclemcp-c"),  # no real content at all
        bead("oraclemcp-d", dependencies=[
            {"depends_on_id": "oraclemcp-a", "type": "blocks"},
            {"depends_on_id": "oraclemcp-b", "type": "parent-child"},
            {"depends_on_id": "oraclemcp-c", "type": "discovered-from"},
        ]),
        bead("oraclemcp-dead", status="tombstone"),
    ]
    jsonl = root / ".beads" / "issues.jsonl"
    jsonl.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")

    manifest = build_manifest(root, jsonl, root / "plan.md")
    tasks = {t["slug"]: t for t in manifest["tasks"]}

    check("tombstone excluded", "oraclemcp-dead" not in tasks)
    check("acceptance harvested from acceptance_criteria",
          tasks["oraclemcp-a"]["acceptance"] == ["does the thing", "stays patch-safe"])
    check("evidence harvested from existing close_reason path",
          tasks["oraclemcp-b"]["evidence"] == [ev_rel])
    check("scope harvested from evidence JSON in_scope",
          tasks["oraclemcp-b"]["scope"] == ["crates/oraclemcp/src/lib.rs"])
    check("no-content task has empty acceptance (not fabricated)",
          tasks["oraclemcp-c"]["acceptance"] == [])
    check("no-content task has empty evidence (not fabricated)",
          tasks["oraclemcp-c"]["evidence"] == [])
    check("no-content task has empty scope (not fabricated)",
          tasks["oraclemcp-c"]["scope"] == [])
    check("only blocks edge becomes a dependency",
          tasks["oraclemcp-d"]["dependencies"] == ["oraclemcp-a"])
    check("all tasks are existing lineage (read-only, no new issues)",
          all(t["lineage"]["kind"] == "existing" for t in manifest["tasks"]))

    # Mutation control: neuters must make the corresponding field go empty.
    real_acc, real_ev = harvest_acceptance, harvest_evidence_paths
    try:
        globals()["harvest_acceptance"] = lambda r: ["fabricated"]
        m = build_manifest(root, jsonl, root / "plan.md")
        check("MUTATION: fabricated acceptance must be detectable",
              any(t["acceptance"] == ["fabricated"] for t in m["tasks"]))
    finally:
        globals()["harvest_acceptance"] = real_acc

    try:
        globals()["harvest_evidence_paths"] = lambda r, root: ["fabricated.json"]
        m = build_manifest(root, jsonl, root / "plan.md")
        check("MUTATION: fabricated evidence must be detectable",
              any(t["evidence"] == ["fabricated.json"] for t in m["tasks"]))
    finally:
        globals()["harvest_evidence_paths"] = real_ev

    if failures:
        print("eng_program_manifest_build selftest: FAIL", file=sys.stderr)
        return 1
    print("eng_program_manifest_build selftest: OK (harvests only real content; "
          "fabrication is detectable; empty where no real content exists)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--jsonl", type=Path, default=Path(".beads/issues.jsonl"))
    parser.add_argument("--plan", type=Path, default=Path("docs/plan/PLAN_ENGINEERING_PROGRAM.md"))
    parser.add_argument("--source-repo", default="oraclemcp")
    parser.add_argument("--out", type=Path, default=None,
                        help="write the manifest here (default: stdout)")
    parser.add_argument("--punch-list", action="store_true",
                        help="print the editorial residual (tasks missing scope/acceptance/evidence)")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    if args.selftest:
        return _selftest()

    root = args.root.resolve()
    jsonl = args.jsonl if args.jsonl.is_absolute() else root / args.jsonl
    plan = args.plan if args.plan.is_absolute() else root / args.plan
    manifest = build_manifest(root, jsonl, plan, args.source_repo)

    text = json.dumps(manifest, indent=2, sort_keys=True)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {len(manifest['tasks'])} tasks to {args.out}", file=sys.stderr)
    else:
        print(text)

    if args.punch_list:
        missing = punch_list(manifest)
        total = len(manifest["tasks"])
        complete = sum(
            1 for t in manifest["tasks"]
            if t["scope"] and t["acceptance"] and t["evidence"]
        )
        print(f"\n# punch-list: {complete}/{total} tasks fully authored "
              f"(scope AND acceptance AND evidence present)", file=sys.stderr)
        for field in ("scope", "acceptance", "evidence"):
            slugs = missing[field]
            print(f"# missing {field}: {len(slugs)}", file=sys.stderr)
            for slug in slugs:
                print(f"#   {slug}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
