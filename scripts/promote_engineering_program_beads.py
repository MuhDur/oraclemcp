#!/usr/bin/env python3
"""Promote the linted engineering-program import specification into Beads.

The command is dry-run by default. ``--apply`` is intentionally required for
tracker mutation. Site-wave specifications, record-only decisions, and strict
second-wave deferrals are never promoted by this command.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from engineering_program_bead_manifest import manifest
from plan_bead_graph_lint import validate


ROOT = Path(__file__).resolve().parent.parent
REPO_PATHS = {
    "server": ROOT,
    "driver": (ROOT / "../rust-oracledb").resolve(),
    "site": (ROOT / "../durakovic-ai").resolve(),
}
PROMOTED = {"create", "reuse"}
ACTOR = "BronzeHeron"
BLOCKING_EDGE_TYPES = {"blocks", "parent-child"}
ORIGINAL_STATUS_LABEL_PREFIX = "plan-original-status:"


def run(repo: str, args: list[str]) -> Any:
    if args[:2] in (["br", "create"], ["br", "update"], ["br", "reopen"]):
        args = [*args, "--actor", ACTOR]
    elif args[:3] == ["br", "dep", "add"]:
        args = [*args, "--actor", ACTOR]
    completed = subprocess.run(
        args,
        cwd=REPO_PATHS[repo],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        command = " ".join(args[:3])
        raise RuntimeError(
            f"{repo}: {command} failed ({completed.returncode}): "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )
    if not completed.stdout.strip():
        return None
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError:
        return completed.stdout.strip()


def tracker_records(repo: str) -> dict[str, dict[str, Any]]:
    path = REPO_PATHS[repo] / ".beads/issues.jsonl"
    records: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            records[record["id"]] = record
    return records


def issue_id_from_create(value: Any) -> str:
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    if isinstance(value, dict) and isinstance(value.get("id"), str):
        return value["id"]
    raise RuntimeError(f"unexpected br create output: {value!r}")


def normalized_notes(task: dict[str, Any], document: dict[str, Any]) -> str:
    evidence = "\n".join(f"- {item}" for item in task["evidence"])
    acceptance = "\n".join(f"- {item}" for item in task["acceptance_criteria"])
    handoffs = task["handoffs"]
    handoff_text = "none"
    if handoffs:
        handoff_text = "\n".join(
            f"- prerequisite `{item['task']}`; artifact: {item['artifact']}; checksum: required"
            for item in handoffs
        )
    lineage = task.get("lineage", [])
    lineage_text = "none"
    if lineage:
        lineage_text = "\n".join(
            f"- {item['relation']} `{item['id']}`" for item in lineage
        )
    return (
        f"PLAN IMPORT {task['tracking_label']}\n"
        f"Source: {external_reference(task, document)}\n"
        f"Tier: {task['tier']}\n"
        f"Operator gate: {task['operator_gate']}\n"
        f"Reuse action: {task.get('reuse_action', 'not-reused')}\n"
        f"Normalized scope: {task['scope']}\n"
        f"Acceptance criteria:\n{acceptance}\n"
        f"Evidence required:\n{evidence}\n"
        f"Cross-repository checksum handoffs: {handoff_text}\n"
        f"Tracker lineage: {lineage_text}"
    )


def cluster(task: dict[str, Any]) -> str:
    labels = [label for label in task["labels"] if label.startswith("cluster-")]
    if len(labels) != 1:
        raise RuntimeError(f"{task['slug']}: expected exactly one cluster label")
    return labels[0].removeprefix("cluster-").upper()


def hold_reasons(task: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    if task["operator_gate"] != "none":
        reasons.append(f"operator:{task['operator_gate']}")
    if task["handoffs"] and task.get("reuse_action") != "record-complete":
        reasons.append("checksum-handoff")
    return reasons


def desired_labels(task: dict[str, Any]) -> list[str]:
    labels = list(task["labels"])
    if task["operator_gate"] != "none":
        labels.extend(["operator-gated", f"gate:{task['operator_gate']}"])
    if task["handoffs"] and task.get("reuse_action") != "record-complete":
        labels.append("handoff-blocked")
    return labels


def saved_original_status(record: dict[str, Any]) -> str | None:
    matches = [
        label.removeprefix(ORIGINAL_STATUS_LABEL_PREFIX)
        for label in record.get("labels", [])
        if isinstance(label, str) and label.startswith(ORIGINAL_STATUS_LABEL_PREFIX)
    ]
    if len(matches) > 1:
        raise RuntimeError(f"issue {record.get('id')}: multiple saved original-status labels")
    return matches[0] if matches else None


def assert_tracker_bindings(document: dict[str, Any]) -> None:
    for repo in ("server", "driver"):
        declared = (ROOT / document["trackers"][repo]["path"]).resolve()
        expected = (REPO_PATHS[repo] / ".beads/issues.jsonl").resolve()
        if declared != expected:
            raise RuntimeError(
                f"{repo}: validated tracker {declared} does not match live mutation target {expected}"
            )


def external_reference(task: dict[str, Any], document: dict[str, Any]) -> str:
    plan_path = document["source_document"]["path"]
    ranges = ",".join(source.rsplit(":", 1)[1] for source in task["source_refs"])
    return (
        f"{plan_path}:{ranges}#task={task['slug']}"
        f"&sha256={document['source_document']['sha256']}"
    )


def cycle_path(edges: dict[str, list[str]]) -> list[str] | None:
    state = {node: 0 for node in edges}
    for start in sorted(edges):
        if state[start] != 0:
            continue
        active = [start]
        positions = {start: 0}
        state[start] = 1
        work: list[tuple[str, int, list[str]]] = [
            (start, 0, sorted(target for target in edges[start] if target in edges))
        ]
        while work:
            node, index, targets = work[-1]
            if index >= len(targets):
                work.pop()
                active.pop()
                positions.pop(node, None)
                state[node] = 2
                continue
            target = targets[index]
            work[-1] = (node, index + 1, targets)
            if state[target] == 0:
                state[target] = 1
                positions[target] = len(active)
                active.append(target)
                work.append(
                    (target, 0, sorted(candidate for candidate in edges[target] if candidate in edges))
                )
            elif state[target] == 1:
                return active[positions[target] :] + [target]
    return None


def acceptance_text(task: dict[str, Any]) -> str:
    return "\n".join(
        f"{index}. {criterion}"
        for index, criterion in enumerate(task["acceptance_criteria"], start=1)
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="mutate the server and driver trackers")
    parser.add_argument(
        "--include-gcp",
        action="store_true",
        help="include the separately authorized cluster-J GCP wave (site Wave 2 remains deferred)",
    )
    args = parser.parse_args(argv)

    document = manifest()
    findings = validate(document, ROOT)
    if findings:
        for finding in findings:
            print(finding.render(), file=sys.stderr)
        return 1
    assert_tracker_bindings(document)

    all_promotable = [task for task in document["tasks"] if task["promotion"] in PROMOTED]
    gcp_held = [task for task in all_promotable if cluster(task) == "J" and not args.include_gcp]
    promoted_tasks = [task for task in all_promotable if task not in gcp_held]
    skipped = [task for task in document["tasks"] if task["promotion"] not in PROMOTED]
    for task in promoted_tasks:
        reference = external_reference(task, document)
        if len(reference) > 200 or any(character.isspace() for character in reference):
            raise RuntimeError(
                f"{task['slug']}: external reference must be whitespace-free and at most 200 characters"
            )
        if any(len(label) > 50 for label in desired_labels(task)):
            raise RuntimeError(f"{task['slug']}: Beads labels must be at most 50 characters")
    by_slug = {task["slug"]: task for task in document["tasks"]}
    records = {repo: tracker_records(repo) for repo in ("server", "driver")}
    tracking_to_id: dict[tuple[str, str], str] = {}
    for repo, repo_records in records.items():
        for issue_id, record in repo_records.items():
            for label in record.get("labels", []):
                if isinstance(label, str) and label.startswith("plan:"):
                    key = (repo, label)
                    if key in tracking_to_id and tracking_to_id[key] != issue_id:
                        raise RuntimeError(f"duplicate tracking label {label!r} in {repo}")
                    tracking_to_id[key] = issue_id

    slug_to_node: dict[str, str] = {}
    create_needed = 0
    existing_owned = 0
    for task in promoted_tasks:
        repo = task["repo"]
        if repo not in ("server", "driver"):
            raise RuntimeError(f"promotable task unexpectedly targets {repo}: {task['slug']}")
        tracking_key = (repo, task["tracking_label"])
        issue_id = tracking_to_id.get(tracking_key)
        if task["promotion"] == "reuse":
            expected = task["existing_id"]
            if issue_id is not None and issue_id != expected:
                raise RuntimeError(
                    f"{task['slug']}: tracking label maps to {issue_id}, expected {expected}"
                )
            issue_id = expected
            if issue_id not in records[repo]:
                raise RuntimeError(f"{task['slug']}: missing reused issue {issue_id}")
            existing_owned += 1
        elif issue_id is None:
            issue_id = f"@plan:{task['slug']}"
            create_needed += 1
        else:
            existing_owned += 1
        slug_to_node[task["slug"]] = issue_id

    for task in promoted_tasks:
        node = slug_to_node[task["slug"]]
        if node.startswith("@plan:"):
            continue
        record = records[task["repo"]][node]
        status = record.get("status")
        needs_staging = bool(task["depends_on"] or task.get("parent") or hold_reasons(task))
        if status == "in_progress" and needs_staging:
            raise RuntimeError(
                f"{task['slug']}: reused issue {node} is in_progress and cannot be staged safely"
            )

    planned_edges = 0
    planned_parents = 0
    planned_lineage = 0
    for repo in ("server", "driver"):
        union_edges: dict[str, list[str]] = {issue_id: [] for issue_id in records[repo]}
        for issue_id, record in records[repo].items():
            for edge in record.get("dependencies") or []:
                if isinstance(edge, dict) and edge.get("type") in BLOCKING_EDGE_TYPES:
                    dependency_id = edge.get("depends_on_id")
                    if isinstance(dependency_id, str):
                        union_edges[issue_id].append(dependency_id)
        for task in promoted_tasks:
            if task["repo"] != repo:
                continue
            node = slug_to_node[task["slug"]]
            union_edges.setdefault(node, [])
            for dependency_slug in task["depends_on"]:
                if dependency_slug not in slug_to_node:
                    raise RuntimeError(
                        f"{task['slug']}: selected promotion omits dependency {dependency_slug}"
                    )
                union_edges[node].append(slug_to_node[dependency_slug])
                planned_edges += 1
            parent_slug = task.get("parent")
            if parent_slug is not None:
                if parent_slug not in slug_to_node:
                    raise RuntimeError(
                        f"{task['slug']}: selected promotion omits parent {parent_slug}"
                    )
                union_edges[node].append(slug_to_node[parent_slug])
                planned_parents += 1
            planned_lineage += len(task.get("lineage", []))
        cycle = cycle_path(union_edges)
        if cycle is not None:
            raise RuntimeError(f"{repo}: live-plus-plan dependency cycle: {' -> '.join(cycle)}")
        live_cycles = run(
            repo,
            ["br", "dep", "cycles", "--blocking-only", "--include-closed", "--json"],
        )
        if isinstance(live_cycles, dict):
            has_cycles = bool(live_cycles.get("cycles")) or live_cycles.get("count", 0) != 0
        else:
            has_cycles = bool(live_cycles)
        if has_cycles:
            raise RuntimeError(f"{repo}: existing tracker contains dependency cycles: {live_cycles!r}")

    summary: dict[str, Any] = {
        "apply": args.apply,
        "include_gcp": args.include_gcp,
        "manifest_tasks": len(document["tasks"]),
        "selected_promotable": len(promoted_tasks),
        "create_specs": sum(task["promotion"] == "create" for task in promoted_tasks),
        "reuse_specs": sum(task["promotion"] == "reuse" for task in promoted_tasks),
        "new_issues_planned": create_needed,
        "existing_issues_owned_or_reused": existing_owned,
        "native_edges_planned": planned_edges,
        "parents_planned": planned_parents,
        "lineage_edges_planned": planned_lineage,
        "checksum_blocked_specs": sum(bool(task["handoffs"]) for task in promoted_tasks),
        "gcp_specs_held": len(gcp_held),
        "deferred_specs": sum(task["promotion"] == "defer" for task in skipped),
        "record_only_specs": sum(task["promotion"] == "record-only" for task in skipped),
    }
    if not args.apply:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    for repo in ("server", "driver"):
        run(repo, ["br", "sync", "--flush-only"])

    original_status: dict[str, str | None] = {}
    slug_to_id: dict[str, str] = {}
    created = 0
    staged = 0

    # Phase 1: put every plan-owned issue in a non-actionable staging state.
    for task in promoted_tasks:
        repo = task["repo"]
        node = slug_to_node[task["slug"]]
        if node.startswith("@plan:"):
            labels = desired_labels(task)
            created_output = run(
                repo,
                [
                    "br",
                    "create",
                    task["title"],
                    "--slug",
                    task["slug"],
                    "--type",
                    task["type"],
                    "--priority",
                    str(task["priority"]),
                    "--description",
                    task["description"],
                    "--labels",
                    ",".join(labels),
                    "--external-ref",
                    external_reference(task, document),
                    "--status",
                    "deferred",
                    "--json",
                ],
            )
            issue_id = issue_id_from_create(created_output)
            records[repo][issue_id] = {
                "id": issue_id,
                "labels": labels,
                "notes": "",
                "status": "deferred",
            }
            created += 1
            original_status[task["slug"]] = None
        else:
            issue_id = node
            record = records[repo][issue_id]
            status = record.get("status") if isinstance(record.get("status"), str) else None
            original_status[task["slug"]] = saved_original_status(record) or status
            needs_staging = bool(task["depends_on"] or task.get("parent") or hold_reasons(task))
            if status == "in_progress" and needs_staging:
                raise RuntimeError(
                    f"{task['slug']}: reused issue {issue_id} is in_progress and cannot be staged safely"
                )
            if status not in {"closed", "tombstone", "deferred"} and needs_staging:
                status_label = f"{ORIGINAL_STATUS_LABEL_PREFIX}{status}"
                if status_label not in record.get("labels", []):
                    run(repo, ["br", "update", issue_id, "--add-label", status_label, "--json"])
                    if status_label not in record.get("labels", []):
                        record.setdefault("labels", []).append(status_label)
                run(repo, ["br", "update", issue_id, "--status", "deferred", "--json"])
                record["status"] = "deferred"
                staged += 1
        slug_to_id[task["slug"]] = issue_id

    # Phase 2: converge plan-owned fields and append a replaceable import block.
    for task in promoted_tasks:
        repo = task["repo"]
        issue_id = slug_to_id[task["slug"]]
        record = records[repo][issue_id]
        existing_labels = set(record.get("labels", []))
        for label in desired_labels(task):
            if label not in existing_labels:
                run(repo, ["br", "update", issue_id, "--add-label", label, "--json"])
                existing_labels.add(label)

        update_args = ["br", "update", issue_id]
        if task["promotion"] == "create":
            update_args.extend(
                [
                    "--title",
                    task["title"],
                    "--type",
                    task["type"],
                    "--priority",
                    str(task["priority"]),
                    "--description",
                    task["description"],
                    "--external-ref",
                    external_reference(task, document),
                    "--design",
                    task["scope"],
                    "--acceptance-criteria",
                    acceptance_text(task),
                ]
            )
        elif task["reuse_action"] in {"reopen-correct", "reactivate"}:
            update_args.extend(
                [
                    "--design",
                    task["scope"],
                    "--acceptance-criteria",
                    acceptance_text(task),
                ]
            )

        fresh_value = run(repo, ["br", "show", issue_id, "--json"])
        fresh = fresh_value[0] if isinstance(fresh_value, list) and fresh_value else {}
        old_notes = fresh.get("notes") if isinstance(fresh, dict) else ""
        old_notes = old_notes if isinstance(old_notes, str) else ""
        begin = f"PLAN IMPORT BEGIN {task['tracking_label']}"
        end = f"PLAN IMPORT END {task['tracking_label']}"
        block = f"{begin}\n{normalized_notes(task, document)}\n{end}"
        begin_index = old_notes.find(begin)
        end_index = old_notes.find(end)
        if begin_index >= 0 and end_index >= begin_index:
            end_index += len(end)
            notes = f"{old_notes[:begin_index]}{block}{old_notes[end_index:]}".strip()
        else:
            notes = f"{old_notes.rstrip()}\n\n{block}".strip()
        update_args.extend(["--notes", notes, "--json"])
        run(repo, update_args)

    # Phase 3: wire native, parent, and nonblocking lineage edges.
    edges_added = 0
    parents_set = 0
    lineage_added = 0
    for task in promoted_tasks:
        issue_id = slug_to_id[task["slug"]]
        repo = task["repo"]
        existing_edges_value = run(repo, ["br", "dep", "list", issue_id, "--json"])
        existing_edges = existing_edges_value if isinstance(existing_edges_value, list) else []
        edge_pairs = {
            (edge.get("depends_on_id"), edge.get("type"))
            for edge in existing_edges
            if isinstance(edge, dict)
        }
        parent_slug = task.get("parent")
        if parent_slug is not None:
            parent_id = slug_to_id[parent_slug]
            if (parent_id, "parent-child") not in edge_pairs:
                run(repo, ["br", "update", issue_id, "--parent", parent_id, "--json"])
                edge_pairs.add((parent_id, "parent-child"))
                parents_set += 1
        for dependency_slug in task["depends_on"]:
            dependency_id = slug_to_id[dependency_slug]
            if (dependency_id, "blocks") not in edge_pairs:
                run(
                    repo,
                    [
                        "br",
                        "dep",
                        "add",
                        issue_id,
                        dependency_id,
                        "--type",
                        "blocks",
                        "--metadata",
                        json.dumps({"plan_slug": dependency_slug}, sort_keys=True),
                        "--json",
                    ],
                )
                edge_pairs.add((dependency_id, "blocks"))
                edges_added += 1
        for lineage in task.get("lineage", []):
            edge_type = "discovered-from" if lineage["relation"] == "discovered-from" else "related"
            lineage_id = lineage["id"]
            if (lineage_id, edge_type) not in edge_pairs:
                run(
                    repo,
                    [
                        "br",
                        "dep",
                        "add",
                        issue_id,
                        lineage_id,
                        "--type",
                        edge_type,
                        "--metadata",
                        json.dumps({"plan_relation": lineage["relation"]}, sort_keys=True),
                        "--json",
                    ],
                )
                edge_pairs.add((lineage_id, edge_type))
                lineage_added += 1

    for repo in ("server", "driver"):
        cycles = run(
            repo,
            ["br", "dep", "cycles", "--blocking-only", "--include-closed", "--json"],
        )
        if isinstance(cycles, dict):
            has_cycles = bool(cycles.get("cycles")) or cycles.get("count", 0) != 0
        else:
            has_cycles = bool(cycles)
        if has_cycles:
            raise RuntimeError(f"{repo}: dependency cycles after staged promotion: {cycles!r}")

    # Phase 4: only now activate tasks without an operator or checksum hold.
    activated = 0
    reopened = 0
    for task in promoted_tasks:
        if hold_reasons(task) or task.get("reuse_action") == "record-complete":
            continue
        repo = task["repo"]
        issue_id = slug_to_id[task["slug"]]
        action = task.get("reuse_action")
        original = original_status[task["slug"]]
        fresh_value = run(repo, ["br", "show", issue_id, "--json"])
        fresh = fresh_value[0] if isinstance(fresh_value, list) and fresh_value else {}
        status = fresh.get("status") if isinstance(fresh, dict) else None
        if action in {"reopen-correct", "reactivate"} and status in {"closed", "tombstone"}:
            run(
                repo,
                [
                    "br",
                    "reopen",
                    issue_id,
                    "--reason",
                    f"Reactivated by {task['tracking_label']} after validated graph promotion",
                    "--json",
                ],
            )
            reopened += 1
            continue
        should_open = task["promotion"] == "create" or action in {"reopen-correct", "reactivate"}
        should_open = should_open or original == "open"
        if status == "deferred" and should_open:
            update_args = ["br", "update", issue_id, "--status", "open"]
            saved = f"{ORIGINAL_STATUS_LABEL_PREFIX}{original}"
            if original is not None and saved in fresh.get("labels", []):
                update_args.extend(["--remove-label", saved])
            update_args.append("--json")
            run(repo, update_args)
            activated += 1

    for repo in ("server", "driver"):
        run(repo, ["br", "sync", "--flush-only"])
        final_cycles = run(
            repo,
            ["br", "dep", "cycles", "--blocking-only", "--include-closed", "--json"],
        )
        if isinstance(final_cycles, dict):
            has_cycles = bool(final_cycles.get("cycles")) or final_cycles.get("count", 0) != 0
        else:
            has_cycles = bool(final_cycles)
        if has_cycles:
            raise RuntimeError(f"{repo}: dependency cycles after activation: {final_cycles!r}")

    summary.update(
        {
            "created": created,
            "staged_existing": staged,
            "activated": activated,
            "reopened": reopened,
            "parents_set": parents_set,
            "dependency_edges_added": edges_added,
            "lineage_edges_added": lineage_added,
        }
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
