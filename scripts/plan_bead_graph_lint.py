#!/usr/bin/env python3
"""Lint normalized plan-to-Beads graphs before they are promoted.

The original ``--train-label`` mode is retained for the already-promoted 090/091
train graphs.  New conversions use ``--manifest`` and a deliberately small,
stdlib-only JSON contract:

.. code-block:: json

  {
    "schema": "plan-bead-graph/v2",
    "program": {"slug": "engineering-program"},
    "source_document": {"path": "docs/plan/PLAN.md", "sha256": "..."},
    "repositories": [{"slug": "server", "path": ".", "source_repo": "oraclemcp"}],
    "trackers": [{"repository": "server", "path": ".beads/issues.jsonl",
                  "source_repo": "oraclemcp"}],
    "release_targets": [{"repository": "server", "version": "0.9.1",
                         "assertion": "patch"}],
    "tasks": [{
      "slug": "g1", "repository": "server", "tracker": "server",
      "title": "...", "type": "task", "priority": 1, "tier": "tier-1",
      "labels": ["train-091", "plan:example:g1"],
      "tracking_label": "train-091", "plan": {"section": "§27", "label": "plan:example:g1"},
      "scope": ["scripts/example.py"], "acceptance": ["..."], "evidence": ["..."],
      "dependencies": [], "parent": null, "handoffs": [], "operator_gate": "none",
      "promotion": "activate", "lineage": {"kind": "new"},
      "reuse": {"action": "create"}
    }]
  }

``dependencies`` and ``parent`` are native Beads edges and must stay in one
repository.  A cross-repository prerequisite is a ``handoffs`` item with a
target task, artifact name, and SHA-256; it is logical ordering only and never
becomes a native edge.  Existing issue mappings use ``lineage.kind=existing``
and ``reuse.action=defer-existing`` or ``reuse-existing``.  They are resolved
read-only and never mutated by promotion.

``--manifest`` is read-only.  ``--promote`` prints the deterministic mutation
plan; only ``--promote --apply`` invokes ``br``.  Apply stages every new issue
as ``deferred``, wires all local parent/blocker edges, rechecks the staged graph,
and activates only ungated, non-handoff, non-GCP tasks.  Cluster J stays out
unless ``--include-gcp`` is explicit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "plan-bead-graph/v2"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-(?:0|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
TIER_RE = re.compile(r"^(?:P[0-4]|T[0-3]|tier-[1-3]|local|ci|nightly|live)$", re.I)
ISSUE_TYPES = {"bug", "chore", "epic", "feature", "task"}
REUSE_ACTIONS = {"create", "defer-existing", "reuse-existing"}
PROMOTION_DISPOSITIONS = {"activate", "deferred", "held", "excluded"}


@dataclass
class Findings:
    hard: list[str] = field(default_factory=list)
    warn: list[str] = field(default_factory=list)

    def error(self, code: str, message: str) -> None:
        self.hard.append(f"{code} {message}")


@dataclass
class ManifestState:
    path: Path
    base: Path
    raw: dict[str, Any]
    repositories: dict[str, dict[str, Any]]
    trackers: dict[str, dict[str, Any]]
    release_targets: dict[str, dict[str, Any]]
    tasks: dict[str, dict[str, Any]]
    live: dict[str, dict[str, dict[str, Any]]]
    graph: dict[str, set[str]]
    incoming_handoffs: set[str]
    findings: Findings


@dataclass(frozen=True)
class PromotionOperation:
    phase: str
    task: str
    detail: str


def _nonempty_string(value: Any, findings: Findings, code: str, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        findings.error(code, f"{context} must be a non-empty string")
        return ""
    return value.strip()


def _string_list(value: Any, findings: Findings, code: str, context: str, *, minimum: int = 0) -> list[str]:
    if not isinstance(value, list):
        findings.error(code, f"{context} must be an array of strings")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            findings.error(code, f"{context}[{index}] must be a non-empty string")
            continue
        result.append(item.strip())
    if len(result) < minimum:
        findings.error(code, f"{context} must contain at least {minimum} item(s)")
    return result


def _mapping(value: Any, findings: Findings, code: str, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        findings.error(code, f"{context} must be an object")
        return {}
    return value


def _safe_path(value: Any, base: Path, findings: Findings, code: str, context: str, *, must_exist: bool) -> Path | None:
    raw = _nonempty_string(value, findings, code, context)
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = base / path
    try:
        resolved = path.resolve(strict=must_exist)
    except OSError as exc:
        findings.error(code, f"{context} cannot be resolved: {exc}")
        return None
    if must_exist and not resolved.exists():
        findings.error(code, f"{context} does not exist: {resolved}")
        return None
    return resolved


def _load_json(path: Path, findings: Findings, code: str, context: str) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except UnicodeDecodeError as exc:
        findings.error(code, f"{context} is not UTF-8: {exc}")
    except OSError as exc:
        findings.error(code, f"{context} cannot be read: {exc}")
    except json.JSONDecodeError as exc:
        findings.error(code, f"{context} is not JSON: line {exc.lineno}, column {exc.colno}")
    return None


def _records(
    value: Any,
    findings: Findings,
    code: str,
    context: str,
    *,
    key: str = "slug",
) -> list[dict[str, Any]]:
    """Accept a JSON array or keyed object while keeping validation deterministic."""
    if isinstance(value, list):
        values = value
    elif isinstance(value, dict):
        values = []
        for record_key in sorted(value):
            record = value[record_key]
            if isinstance(record, dict) and key not in record:
                record = dict(record)
                record[key] = record_key
            values.append(record)
    else:
        findings.error(code, f"{context} must be an array or object")
        return []
    result = []
    for index, record in enumerate(values):
        if not isinstance(record, dict):
            findings.error(code, f"{context}[{index}] must be an object")
            continue
        result.append(record)
    return result


def _parse_tracker_jsonl(path: Path, source_repo: str, findings: Findings, context: str) -> dict[str, dict[str, Any]]:
    issues: dict[str, dict[str, Any]] = {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            lines = list(handle)
    except UnicodeDecodeError as exc:
        findings.error("E_TRACKER_UTF8", f"{context} is not UTF-8: {exc}")
        return issues
    except OSError as exc:
        findings.error("E_TRACKER_PATH", f"{context} cannot be read: {exc}")
        return issues
    for line_no, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            issue = json.loads(line)
        except json.JSONDecodeError as exc:
            findings.error("E_TRACKER_JSONL", f"{context}:{line_no} invalid JSON: {exc.msg}")
            continue
        if not isinstance(issue, dict):
            findings.error("E_TRACKER_JSONL", f"{context}:{line_no} must be an object")
            continue
        issue_id = issue.get("id")
        if not isinstance(issue_id, str) or not issue_id:
            findings.error("E_TRACKER_JSONL", f"{context}:{line_no} has no issue id")
            continue
        if issue_id in issues:
            findings.error("E_TRACKER_DUPLICATE_ID", f"{context} repeats issue id {issue_id}")
            continue
        issue_source_repo = issue.get("source_repo")
        if issue_source_repo not in (None, source_repo):
            findings.error(
                "E_TRACKER_SOURCE_REPO",
                f"{context}:{line_no} has source_repo {issue_source_repo!r}, expected {source_repo!r}",
            )
        issues[issue_id] = issue
    return issues


def _task_ref(value: Any, findings: Findings, context: str) -> tuple[str, str, str | None]:
    """Return ``(kind, target, explicit_repository)`` for a native reference."""
    if isinstance(value, str) and value.strip():
        return ("ambiguous", value.strip(), None)
    if not isinstance(value, dict):
        findings.error("E_REFERENCE_TYPE", f"{context} must be a task slug, issue id, or object reference")
        return ("invalid", "", None)
    repository = value.get("repository")
    if repository is not None and (not isinstance(repository, str) or not repository.strip()):
        findings.error("E_REFERENCE_TYPE", f"{context}.repository must be a non-empty string when present")
        repository = None
    if isinstance(value.get("task"), str) and value["task"].strip():
        return ("task", value["task"].strip(), repository)
    if isinstance(value.get("slug"), str) and value["slug"].strip():
        return ("task", value["slug"].strip(), repository)
    if isinstance(value.get("issue_id"), str) and value["issue_id"].strip():
        return ("live", value["issue_id"].strip(), repository)
    findings.error("E_REFERENCE_TYPE", f"{context} must name task, slug, or issue_id")
    return ("invalid", "", None)


def _node_for_task(task: dict[str, Any]) -> str:
    lineage = task["_lineage"]
    if lineage["kind"] == "existing":
        return f"live:{task['repository']}:{lineage['issue_id']}"
    return f"plan:{task['slug']}"


def _iterative_cycles(graph: dict[str, set[str]]) -> list[tuple[str, str]]:
    """Find back edges without recursive depth limits."""
    white, gray, black = 0, 1, 2
    color: dict[str, int] = defaultdict(int)
    cycles: list[tuple[str, str]] = []
    for start in sorted(graph):
        if color[start] != white:
            continue
        color[start] = gray
        stack: list[tuple[str, Iterable[str]]] = [(start, iter(sorted(graph.get(start, ()))))]
        while stack:
            node, iterator = stack[-1]
            try:
                target = next(iterator)
            except StopIteration:
                color[node] = black
                stack.pop()
                continue
            state = color[target]
            if state == gray:
                cycles.append((node, target))
            elif state == white:
                color[target] = gray
                stack.append((target, iter(sorted(graph.get(target, ())))))
    return cycles


def _dependency_ids(issue: dict[str, Any]) -> Iterable[str]:
    for dependency in issue.get("dependencies") or []:
        if not isinstance(dependency, dict):
            continue
        target = dependency.get("depends_on_id") or dependency.get("id") or dependency.get("to_id")
        if isinstance(target, str) and target:
            yield target


# Edge classes for cycle detection. A cycle is a contradiction only WITHIN one
# class: sequencing work that cannot start, or a bead that is its own ancestor.
# Mixing the classes reports the NORMAL epic shape as a cycle — an epic depends
# on its child (`epic --blocks--> child`, so it cannot close first) while the
# child names the epic as its parent (`child --parent-child--> epic`). Together
# that is a 2-cycle in a combined graph, and the first version of this check
# filed several against a well-formed program. `eng_program_graph_lint.py`
# settled this for the live graph; the manifest check must use the same split.
SEQUENCING_EDGE_TYPES = {"blocks"}
HIERARCHY_EDGE_TYPES = {"parent-child"}
# Provenance edges carry no sequencing, so a loop through them is not a
# contradiction (bead r3sti settled this for the close gate).
PROVENANCE_EDGE_TYPES = {"discovered-from", "related"}


def _live_typed_edges(issue: dict[str, Any]) -> Iterable[tuple[str, str | None]]:
    """Yield ``(target, edge_type)`` so callers can separate edge classes."""
    for dependency in issue.get("dependencies") or []:
        if not isinstance(dependency, dict):
            continue
        target = dependency.get("depends_on_id") or dependency.get("id") or dependency.get("to_id")
        if isinstance(target, str) and target:
            yield target, dependency.get("type")


def _validate_source_document(raw: dict[str, Any], base: Path, findings: Findings) -> None:
    source = _mapping(raw.get("source_document"), findings, "E_SOURCE_DOCUMENT", "source_document")
    path = _safe_path(source.get("path"), base, findings, "E_SOURCE_DOCUMENT", "source_document.path", must_exist=True)
    claimed = _nonempty_string(source.get("sha256"), findings, "E_SOURCE_SHA256", "source_document.sha256").lower()
    if claimed and not SHA256_RE.fullmatch(claimed):
        findings.error("E_SOURCE_SHA256", "source_document.sha256 must be lowercase 64-hex SHA-256")
    if path is not None and SHA256_RE.fullmatch(claimed):
        try:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            findings.error("E_SOURCE_DOCUMENT", f"cannot hash {path}: {exc}")
            return
        if actual != claimed:
            findings.error(
                "E_SOURCE_SHA256",
                f"source_document checksum mismatch for {path}: expected {claimed}, got {actual}",
            )


def _validate_repositories(raw: dict[str, Any], base: Path, findings: Findings) -> dict[str, dict[str, Any]]:
    repositories: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(_records(raw.get("repositories"), findings, "E_REPOSITORIES", "repositories")):
        context = f"repositories[{index}]"
        slug = _nonempty_string(record.get("slug"), findings, "E_REPOSITORY_SLUG", f"{context}.slug")
        if slug and not SLUG_RE.fullmatch(slug):
            findings.error("E_REPOSITORY_SLUG", f"{context}.slug {slug!r} is not a normalized slug")
        source_repo = _nonempty_string(record.get("source_repo"), findings, "E_REPOSITORY_SOURCE", f"{context}.source_repo")
        path = _safe_path(record.get("path"), base, findings, "E_REPOSITORY_PATH", f"{context}.path", must_exist=True)
        if path is not None and not path.is_dir():
            findings.error("E_REPOSITORY_PATH", f"{context}.path is not a directory: {path}")
        if not slug or slug in repositories:
            if slug in repositories:
                findings.error("E_REPOSITORY_SLUG", f"duplicate repository slug {slug}")
            continue
        repositories[slug] = {"slug": slug, "source_repo": source_repo, "path": path}
    if not repositories:
        findings.error("E_REPOSITORIES", "repositories must define at least one repository")
    return repositories


def _validate_trackers(
    raw: dict[str, Any],
    base: Path,
    repositories: dict[str, dict[str, Any]],
    findings: Findings,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, dict[str, Any]]]]:
    trackers: dict[str, dict[str, Any]] = {}
    live: dict[str, dict[str, dict[str, Any]]] = {}
    for index, record in enumerate(_records(raw.get("trackers"), findings, "E_TRACKERS", "trackers", key="repository")):
        context = f"trackers[{index}]"
        repository = _nonempty_string(record.get("repository"), findings, "E_TRACKER_REPOSITORY", f"{context}.repository")
        source_repo = _nonempty_string(record.get("source_repo"), findings, "E_TRACKER_SOURCE_REPO", f"{context}.source_repo")
        if repository not in repositories:
            findings.error("E_TRACKER_REPOSITORY", f"{context}.repository {repository!r} is not declared")
            continue
        if source_repo != repositories[repository]["source_repo"]:
            findings.error(
                "E_TRACKER_SOURCE_REPO",
                f"{context}.source_repo {source_repo!r} does not match repository {repository!r}",
            )
        path = _safe_path(record.get("path"), base, findings, "E_TRACKER_PATH", f"{context}.path", must_exist=True)
        if path is not None and not path.is_file():
            findings.error("E_TRACKER_PATH", f"{context}.path is not a file: {path}")
            path = None
        if repository in trackers:
            findings.error("E_TRACKER_REPOSITORY", f"duplicate tracker for repository {repository}")
            continue
        trackers[repository] = {
            "repository": repository,
            "source_repo": source_repo,
            "path": path,
        }
        live[repository] = _parse_tracker_jsonl(path, source_repo, findings, context) if path else {}
    for slug in sorted(repositories):
        if slug not in trackers:
            findings.error("E_TRACKER_REPOSITORY", f"repository {slug!r} has no tracker")
    return trackers, live


def _validate_release_targets(
    raw: dict[str, Any], repositories: dict[str, dict[str, Any]], findings: Findings
) -> dict[str, dict[str, Any]]:
    targets: dict[str, dict[str, Any]] = {}
    for index, record in enumerate(_records(raw.get("release_targets"), findings, "E_RELEASE_TARGETS", "release_targets", key="repository")):
        context = f"release_targets[{index}]"
        repository = _nonempty_string(record.get("repository"), findings, "E_RELEASE_REPOSITORY", f"{context}.repository")
        version = _nonempty_string(record.get("version"), findings, "E_SEMVER", f"{context}.version")
        assertion = _nonempty_string(record.get("assertion"), findings, "E_SEMVER_ASSERTION", f"{context}.assertion").lower()
        if repository not in repositories:
            findings.error("E_RELEASE_REPOSITORY", f"{context}.repository {repository!r} is not declared")
        if version and not SEMVER_RE.fullmatch(version):
            findings.error("E_SEMVER", f"{context}.version {version!r} is not SemVer")
        if assertion not in {"patch", "minor", "major"}:
            findings.error("E_SEMVER_ASSERTION", f"{context}.assertion must be patch, minor, or major")
        if repository in targets:
            findings.error("E_RELEASE_REPOSITORY", f"duplicate release target for repository {repository}")
            continue
        targets[repository] = {"version": version, "assertion": assertion}
    for slug in sorted(repositories):
        if slug not in targets:
            findings.error("E_RELEASE_REPOSITORY", f"repository {slug!r} has no SemVer target assertion")
    return targets


def _parse_task(
    record: dict[str, Any],
    index: int,
    repositories: dict[str, dict[str, Any]],
    trackers: dict[str, dict[str, Any]],
    release_targets: dict[str, dict[str, Any]],
    live: dict[str, dict[str, dict[str, Any]]],
    findings: Findings,
) -> dict[str, Any] | None:
    context = f"tasks[{index}]"
    slug = _nonempty_string(record.get("slug"), findings, "E_TASK_SLUG", f"{context}.slug")
    if slug and not SLUG_RE.fullmatch(slug):
        findings.error("E_TASK_SLUG", f"{context}.slug {slug!r} is not a normalized slug")
    repository = _nonempty_string(record.get("repository"), findings, "E_TASK_REPOSITORY", f"{context}.repository")
    tracker = _nonempty_string(record.get("tracker"), findings, "E_TASK_TRACKER", f"{context}.tracker")
    if repository not in repositories:
        findings.error("E_TASK_REPOSITORY", f"{context}.repository {repository!r} is not declared")
    if tracker != repository or tracker not in trackers:
        findings.error("E_TASK_TRACKER", f"{context}.tracker must name the repository-local tracker {repository!r}")
    title = _nonempty_string(record.get("title"), findings, "E_TASK_TITLE", f"{context}.title")
    issue_type = _nonempty_string(record.get("type"), findings, "E_TASK_TYPE", f"{context}.type")
    if issue_type and issue_type not in ISSUE_TYPES:
        findings.error("E_TASK_TYPE", f"{context}.type {issue_type!r} is not a supported Beads type")
    priority = record.get("priority")
    if isinstance(priority, bool) or not isinstance(priority, int) or not 0 <= priority <= 4:
        findings.error("E_TASK_PRIORITY", f"{context}.priority must be an integer from 0 through 4")
        priority = 4
    tier = _nonempty_string(record.get("tier"), findings, "E_TASK_TIER", f"{context}.tier")
    if tier and not TIER_RE.fullmatch(tier):
        findings.error("E_TASK_TIER", f"{context}.tier {tier!r} is not a recognized execution tier")
    labels = _string_list(record.get("labels"), findings, "E_TASK_LABELS", f"{context}.labels", minimum=1)
    if len(set(labels)) != len(labels):
        findings.error("E_TASK_LABELS", f"{context}.labels contains duplicates")
    tracking_label = _nonempty_string(record.get("tracking_label"), findings, "E_TASK_LABEL", f"{context}.tracking_label")
    plan = _mapping(record.get("plan"), findings, "E_PLAN_PROVENANCE", f"{context}.plan")
    plan_section = _nonempty_string(plan.get("section"), findings, "E_PLAN_PROVENANCE", f"{context}.plan.section")
    plan_label = _nonempty_string(plan.get("label"), findings, "E_PLAN_PROVENANCE", f"{context}.plan.label")
    for label_context, label in (("tracking_label", tracking_label), ("plan.label", plan_label), *[("labels", label) for label in labels]):
        if label and "." in label:
            findings.error("E_TASK_LABEL", f"{context}.{label_context} contains '.', which Beads labels reject: {label}")
    if tracking_label and tracking_label not in labels:
        findings.error("E_TASK_LABEL", f"{context}.labels must contain tracking_label {tracking_label!r}")
    if plan_label and plan_label not in labels:
        findings.error("E_PLAN_PROVENANCE", f"{context}.labels must contain plan.label {plan_label!r}")
    scope_value = record.get("scope")
    if isinstance(scope_value, dict):
        scope_value = scope_value.get("paths")
    scope = _string_list(scope_value, findings, "E_TASK_SCOPE", f"{context}.scope", minimum=1)
    acceptance = _string_list(
        record.get("acceptance") if isinstance(record.get("acceptance"), list) else [record.get("acceptance")],
        findings,
        "E_TASK_ACCEPTANCE",
        f"{context}.acceptance",
        minimum=1,
    )
    evidence = _string_list(
        record.get("evidence") if isinstance(record.get("evidence"), list) else [record.get("evidence")],
        findings,
        "E_TASK_EVIDENCE",
        f"{context}.evidence",
        minimum=1,
    )
    operator_gate = _nonempty_string(record.get("operator_gate"), findings, "E_OPERATOR_GATE", f"{context}.operator_gate")
    promotion = _nonempty_string(record.get("promotion"), findings, "E_PROMOTION", f"{context}.promotion")
    if promotion and promotion not in PROMOTION_DISPOSITIONS:
        findings.error("E_PROMOTION", f"{context}.promotion must be one of {sorted(PROMOTION_DISPOSITIONS)}")
    release_target = record.get("release_target")
    if release_target is not None:
        release_target = _nonempty_string(release_target, findings, "E_SEMVER_ASSERTION", f"{context}.release_target")
        if repository in release_targets and release_target != release_targets[repository]["version"]:
            findings.error(
                "E_SEMVER_ASSERTION",
                f"{context}.release_target {release_target!r} does not match {repository!r}'s declared target",
            )
    cluster = record.get("cluster")
    if cluster is not None and (not isinstance(cluster, str) or not cluster.strip()):
        findings.error("E_TASK_CLUSTER", f"{context}.cluster must be a non-empty string when present")
        cluster = None
    lineage_raw = _mapping(record.get("lineage"), findings, "E_LINEAGE", f"{context}.lineage")
    lineage_kind = _nonempty_string(lineage_raw.get("kind"), findings, "E_LINEAGE", f"{context}.lineage.kind")
    lineage_issue = lineage_raw.get("issue_id")
    if lineage_kind not in {"new", "existing"}:
        findings.error("E_LINEAGE", f"{context}.lineage.kind must be new or existing")
    if lineage_kind == "existing":
        lineage_issue = _nonempty_string(lineage_issue, findings, "E_LINEAGE", f"{context}.lineage.issue_id")
        if repository in live and lineage_issue not in live[repository]:
            findings.error("E_LINEAGE", f"{context}.lineage.issue_id {lineage_issue!r} is absent from {repository!r}'s tracker")
    elif lineage_issue is not None:
        findings.error("E_LINEAGE", f"{context}.lineage.issue_id is only valid for existing lineage")
        lineage_issue = None
    reuse_raw = _mapping(record.get("reuse"), findings, "E_REUSE", f"{context}.reuse")
    reuse_action = _nonempty_string(reuse_raw.get("action"), findings, "E_REUSE", f"{context}.reuse.action")
    reuse_issue = reuse_raw.get("issue_id")
    if reuse_action not in REUSE_ACTIONS:
        findings.error("E_REUSE", f"{context}.reuse.action must be one of {sorted(REUSE_ACTIONS)}")
    if reuse_action == "create" and lineage_kind != "new":
        findings.error("E_REUSE", f"{context}.reuse.action=create requires lineage.kind=new")
    if reuse_action != "create":
        reuse_issue = _nonempty_string(reuse_issue, findings, "E_REUSE", f"{context}.reuse.issue_id")
        if lineage_kind != "existing" or reuse_issue != lineage_issue:
            findings.error("E_REUSE", f"{context}.reuse existing issue must exactly match lineage.issue_id")
    elif reuse_issue is not None:
        findings.error("E_REUSE", f"{context}.reuse.issue_id is invalid for action=create")
    dependency_field = "dependencies" if "dependencies" in record else "blockers"
    if "dependencies" in record and "blockers" in record:
        findings.error("E_NATIVE_DEPENDENCY", f"{context} must use dependencies or blockers, not both")
    dependencies_raw = record.get(dependency_field, [])
    if not isinstance(dependencies_raw, list):
        findings.error("E_NATIVE_DEPENDENCY", f"{context}.{dependency_field} must be an array")
        dependencies_raw = []
    dependencies = [_task_ref(item, findings, f"{context}.{dependency_field}[{item_index}]") for item_index, item in enumerate(dependencies_raw)]
    parent = None if record.get("parent") is None else _task_ref(record.get("parent"), findings, f"{context}.parent")
    handoffs_raw = record.get("handoffs", [])
    if not isinstance(handoffs_raw, list):
        findings.error("E_HANDOFF", f"{context}.handoffs must be an array")
        handoffs_raw = []
    handoffs: list[dict[str, Any]] = []
    for handoff_index, handoff in enumerate(handoffs_raw):
        handoff_context = f"{context}.handoffs[{handoff_index}]"
        if not isinstance(handoff, dict):
            findings.error("E_HANDOFF", f"{handoff_context} must be an object")
            continue
        target_value = handoff.get("to", handoff.get("task"))
        target = _task_ref(target_value, findings, f"{handoff_context}.to")
        artifact = _nonempty_string(handoff.get("artifact"), findings, "E_HANDOFF", f"{handoff_context}.artifact")
        checksum = _nonempty_string(handoff.get("sha256"), findings, "E_HANDOFF_SHA256", f"{handoff_context}.sha256").lower()
        if checksum and not SHA256_RE.fullmatch(checksum):
            findings.error("E_HANDOFF_SHA256", f"{handoff_context}.sha256 must be lowercase 64-hex SHA-256")
        handoffs.append({"target": target, "artifact": artifact, "sha256": checksum})
    return {
        "slug": slug,
        "repository": repository,
        "tracker": tracker,
        "title": title,
        "type": issue_type,
        "priority": priority,
        "tier": tier,
        "labels": labels,
        "tracking_label": tracking_label,
        "plan_section": plan_section,
        "plan_label": plan_label,
        "scope": scope,
        "acceptance": acceptance,
        "evidence": evidence,
        "operator_gate": operator_gate,
        "promotion": promotion,
        "cluster": cluster,
        "_lineage": {"kind": lineage_kind, "issue_id": lineage_issue},
        "_reuse": {"action": reuse_action, "issue_id": reuse_issue},
        "_dependencies": dependencies,
        "_parent": parent,
        "_handoffs": handoffs,
    }


def _resolve_native_reference(
    source: dict[str, Any],
    reference: tuple[str, str, str | None],
    tasks: dict[str, dict[str, Any]],
    live: dict[str, dict[str, dict[str, Any]]],
    findings: Findings,
    context: str,
) -> str | None:
    kind, target, explicit_repository = reference
    if kind == "invalid" or not target:
        return None
    if explicit_repository is not None and explicit_repository != source["repository"]:
        findings.error("E_CROSS_REPO_NATIVE_EDGE", f"{context} names repository {explicit_repository!r}; native edges are repository-local")
        return None
    if kind in {"task", "ambiguous"} and target in tasks:
        task = tasks[target]
        if task["repository"] != source["repository"]:
            findings.error("E_CROSS_REPO_NATIVE_EDGE", f"{context} targets task {target!r} in {task['repository']!r}")
            return None
        return _node_for_task(task)
    if kind in {"live", "ambiguous"} and target in live.get(source["repository"], {}):
        return f"live:{source['repository']}:{target}"
    for repository, issues in live.items():
        if target in issues and repository != source["repository"]:
            findings.error("E_CROSS_REPO_NATIVE_EDGE", f"{context} targets issue {target!r} in {repository!r}")
            return None
    findings.error("E_REFERENCE_UNKNOWN", f"{context} cannot resolve {target!r} in repository {source['repository']!r}")
    return None


def _validate_graph(
    tasks: dict[str, dict[str, Any]],
    live: dict[str, dict[str, dict[str, Any]]],
    findings: Findings,
) -> tuple[dict[str, set[str]], set[str]]:
    graph: dict[str, set[str]] = defaultdict(set)
    # Cycle detection runs PER EDGE CLASS (see SEQUENCING_EDGE_TYPES above):
    # sequencing (blocks + cross-repo handoffs) and hierarchy (parent-child).
    # The combined `graph` is still returned for the promotion-order contract,
    # but a cycle is only reported within one class — mixing them flags the
    # normal epic shape as a cycle.
    sequencing: dict[str, set[str]] = defaultdict(set)
    hierarchy: dict[str, set[str]] = defaultdict(set)
    for repository, issues in sorted(live.items()):
        for issue_id, issue in sorted(issues.items()):
            node = f"live:{repository}:{issue_id}"
            graph.setdefault(node, set())
            for target, edge_type in _live_typed_edges(issue):
                if target not in issues:
                    findings.error("E_LIVE_REFERENCE", f"live issue {repository}:{issue_id} depends on missing local issue {target}")
                    continue
                target_node = f"live:{repository}:{target}"
                graph[node].add(target_node)
                if edge_type in HIERARCHY_EDGE_TYPES:
                    hierarchy[node].add(target_node)
                elif edge_type in SEQUENCING_EDGE_TYPES:
                    sequencing[node].add(target_node)
                # PROVENANCE_EDGE_TYPES are deliberately not sequenced.
    incoming_handoffs: set[str] = set()
    for slug, task in sorted(tasks.items()):
        node = _node_for_task(task)
        graph.setdefault(node, set())
        for index, reference in enumerate(task["_dependencies"]):
            target = _resolve_native_reference(task, reference, tasks, live, findings, f"task {slug}.dependencies[{index}]")
            if target is not None:
                graph[node].add(target)
                sequencing[node].add(target)
                ref_slug = reference[1]
                if task["promotion"] == "activate" and ref_slug in tasks and tasks[ref_slug]["promotion"] != "activate":
                    findings.error("E_PROMOTED_DEPENDS_NONPROMOTED", f"task {slug!r} activates but depends on non-promoted task {ref_slug!r}")
        if task["_parent"] is not None:
            target = _resolve_native_reference(task, task["_parent"], tasks, live, findings, f"task {slug}.parent")
            if target is not None:
                graph[node].add(target)
                hierarchy[node].add(target)
        for index, handoff in enumerate(task["_handoffs"]):
            kind, target_slug, target_repo = handoff["target"]
            context = f"task {slug}.handoffs[{index}]"
            if kind == "invalid" or target_slug not in tasks:
                findings.error("E_HANDOFF_REFERENCE", f"{context} must target a normalized task slug")
                continue
            target_task = tasks[target_slug]
            if target_repo is not None and target_repo != target_task["repository"]:
                findings.error("E_HANDOFF_REFERENCE", f"{context} repository does not match target task {target_slug!r}")
            if target_task["repository"] == task["repository"]:
                findings.error("E_HANDOFF_NATIVE", f"{context} is same-repository; use dependencies instead of a handoff")
                continue
            if target_task["promotion"] == "activate":
                findings.error("E_HANDOFF_PROMOTION", f"{context} target {target_slug!r} must remain deferred or held")
            incoming_handoffs.add(target_slug)
            target_node = _node_for_task(target_task)
            graph[target_node].add(node)
            # A handoff is cross-repository logical ordering: sequencing class.
            sequencing[target_node].add(node)
    for source, target in _iterative_cycles(sequencing):
        findings.error("E_GRAPH_CYCLE", f"sequencing cycle (blocks/handoff; nothing in it can start) through {source} -> {target}")
    for source, target in _iterative_cycles(hierarchy):
        findings.error("E_GRAPH_CYCLE", f"hierarchy cycle (parent-child; a bead is its own ancestor) through {source} -> {target}")
    return graph, incoming_handoffs


def _validate_live_graph(
    live: dict[str, dict[str, dict[str, Any]]], findings: Findings, *, context: str
) -> None:
    """Validate exported tracker state, including closed/tombstoned nodes.

    Cycles are checked PER EDGE CLASS (sequencing vs hierarchy) so the normal
    epic shape — `epic --blocks--> child` with `child --parent-child--> epic` —
    is not reported as a cycle. See SEQUENCING_EDGE_TYPES.
    """
    graph: dict[str, set[str]] = defaultdict(set)
    sequencing: dict[str, set[str]] = defaultdict(set)
    hierarchy: dict[str, set[str]] = defaultdict(set)
    for repository, issues in sorted(live.items()):
        for issue_id, issue in sorted(issues.items()):
            node = f"live:{repository}:{issue_id}"
            graph.setdefault(node, set())
            for target, edge_type in _live_typed_edges(issue):
                if target not in issues:
                    findings.error("E_LIVE_REFERENCE", f"{context}: {repository}:{issue_id} depends on missing local issue {target}")
                    continue
                target_node = f"live:{repository}:{target}"
                graph[node].add(target_node)
                if edge_type in HIERARCHY_EDGE_TYPES:
                    hierarchy[node].add(target_node)
                elif edge_type in SEQUENCING_EDGE_TYPES:
                    sequencing[node].add(target_node)
    for source, target in _iterative_cycles(sequencing):
        findings.error("E_GRAPH_CYCLE", f"{context}: live sequencing cycle through {source} -> {target}")
    for source, target in _iterative_cycles(hierarchy):
        findings.error("E_GRAPH_CYCLE", f"{context}: live hierarchy cycle through {source} -> {target}")


def validate_manifest(path: Path) -> ManifestState:
    findings = Findings()
    resolved = path.resolve()
    document = _load_json(resolved, findings, "E_MANIFEST_JSON", "manifest")
    raw = _mapping(document, findings, "E_MANIFEST_OBJECT", "manifest")
    if raw.get("schema") != SCHEMA:
        findings.error("E_SCHEMA", f"manifest.schema must be {SCHEMA!r}")
    program = _mapping(raw.get("program"), findings, "E_PROGRAM", "program")
    program_slug = _nonempty_string(program.get("slug"), findings, "E_PROGRAM", "program.slug")
    if program_slug and not SLUG_RE.fullmatch(program_slug):
        findings.error("E_PROGRAM", f"program.slug {program_slug!r} is not a normalized slug")
    _validate_source_document(raw, resolved.parent, findings)
    repositories = _validate_repositories(raw, resolved.parent, findings)
    trackers, live = _validate_trackers(raw, resolved.parent, repositories, findings)
    release_targets = _validate_release_targets(raw, repositories, findings)
    tasks: dict[str, dict[str, Any]] = {}
    seen_tracking_labels: set[str] = set()
    seen_plan_labels: set[str] = set()
    seen_lineage: set[tuple[str, str]] = set()
    for index, record in enumerate(_records(raw.get("tasks"), findings, "E_TASKS", "tasks")):
        task = _parse_task(record, index, repositories, trackers, release_targets, live, findings)
        if task is None or not task["slug"]:
            continue
        slug = task["slug"]
        if slug in tasks:
            findings.error("E_TASK_SLUG", f"duplicate task slug {slug!r}")
            continue
        tasks[slug] = task
        if task["tracking_label"] in seen_tracking_labels:
            findings.error("E_TASK_LABEL", f"duplicate tracking_label {task['tracking_label']!r}")
        seen_tracking_labels.add(task["tracking_label"])
        if task["plan_label"] in seen_plan_labels:
            findings.error("E_PLAN_PROVENANCE", f"duplicate plan.label {task['plan_label']!r}")
        seen_plan_labels.add(task["plan_label"])
        if task["_lineage"]["kind"] == "existing":
            lineage = (task["repository"], task["_lineage"]["issue_id"])
            if lineage in seen_lineage:
                findings.error("E_LINEAGE", f"duplicate existing lineage mapping {lineage[0]}:{lineage[1]}")
            seen_lineage.add(lineage)
    if not tasks:
        findings.error("E_TASKS", "tasks must contain at least one task")
    graph, incoming_handoffs = _validate_graph(tasks, live, findings)
    return ManifestState(
        path=resolved,
        base=resolved.parent,
        raw=raw,
        repositories=repositories,
        trackers=trackers,
        release_targets=release_targets,
        tasks=tasks,
        live=live,
        graph=graph,
        incoming_handoffs=incoming_handoffs,
        findings=findings,
    )


def promotion_operations(state: ManifestState, include_gcp: bool) -> list[PromotionOperation]:
    """Build the only legal mutation order, without mutating a tracker."""
    operations: list[PromotionOperation] = []
    included: set[str] = set()
    for slug, task in sorted(state.tasks.items()):
        is_gcp = task.get("cluster") == "J"
        if is_gcp and not include_gcp:
            operations.append(PromotionOperation("hold", slug, "cluster J excluded without --include-gcp"))
            continue
        if task["promotion"] == "excluded":
            operations.append(PromotionOperation("hold", slug, "manifest disposition excluded"))
            continue
        included.add(slug)
        if task["_reuse"]["action"] == "create":
            operations.append(PromotionOperation("stage", slug, "create deferred"))
        else:
            operations.append(PromotionOperation("reuse", slug, "validated existing mapping; no mutation"))
    for slug in sorted(included):
        task = state.tasks[slug]
        if task["_reuse"]["action"] != "create":
            continue
        for reference in task["_dependencies"]:
            operations.append(PromotionOperation("wire", slug, f"blocks:{reference[1]}"))
        if task["_parent"] is not None:
            operations.append(PromotionOperation("wire", slug, f"parent-child:{task['_parent'][1]}"))
    operations.append(PromotionOperation("verify", "*", "recheck live-plus-plan graph including closed nodes"))
    for slug in sorted(included):
        task = state.tasks[slug]
        held = (
            task["promotion"] != "activate"
            or task["operator_gate"].lower() != "none"
            or slug in state.incoming_handoffs
            or task["_reuse"]["action"] != "create"
        )
        if held:
            continue
        operations.append(PromotionOperation("activate", slug, "open after graph verification"))
    return operations


def _task_description(task: dict[str, Any]) -> str:
    lines = [
        f"Plan provenance: {task['plan_section']} ({task['plan_label']}).",
        "Scope:",
        *[f"- {item}" for item in task["scope"]],
        "Acceptance:",
        *[f"- {item}" for item in task["acceptance"]],
        "Evidence:",
        *[f"- {item}" for item in task["evidence"]],
        f"Execution tier: {task['tier']}. Operator gate: {task['operator_gate'] }.",
    ]
    return "\n".join(lines)


def _run_command(argv: list[str], cwd: Path) -> str:
    completed = subprocess.run(argv, cwd=cwd, capture_output=True, text=True)
    if completed.returncode:
        message = completed.stderr.strip() or completed.stdout.strip() or f"exit {completed.returncode}"
        raise RuntimeError(f"{' '.join(argv)}: {message}")
    return completed.stdout


def _extract_created_id(output: str) -> str:
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"br create returned invalid JSON: {exc}") from exc
    if isinstance(payload, list):
        payload = payload[0] if payload else None
    if not isinstance(payload, dict) or not isinstance(payload.get("id"), str) or not payload["id"]:
        raise RuntimeError("br create JSON did not include an issue id")
    return payload["id"]


def apply_promotion(state: ManifestState, include_gcp: bool) -> tuple[int, int, int]:
    """Apply a previously validated plan in stage -> wire -> verify -> activate order."""
    operations = promotion_operations(state, include_gcp)
    created: dict[str, str] = {}
    resolved: dict[str, str] = {}
    for slug, task in state.tasks.items():
        if task["_lineage"]["kind"] == "existing":
            resolved[slug] = task["_lineage"]["issue_id"]
    staged = wired = activated = 0
    for operation in operations:
        if operation.phase != "stage":
            continue
        task = state.tasks[operation.task]
        repository = state.repositories[task["repository"]]
        labels = list(dict.fromkeys([*task["labels"], task["tracking_label"], task["plan_label"]]))
        output = _run_command(
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
                _task_description(task),
                "--labels",
                ",".join(labels),
                "--status",
                "deferred",
                "--json",
            ],
            repository["path"],
        )
        created[operation.task] = _extract_created_id(output)
        resolved[operation.task] = created[operation.task]
        staged += 1
    for operation in operations:
        if operation.phase != "wire":
            continue
        task = state.tasks[operation.task]
        source_id = resolved.get(operation.task)
        target_slug = operation.detail.split(":", 1)[1]
        target_id = resolved.get(target_slug)
        if target_id is None and target_slug in state.live.get(task["repository"], {}):
            target_id = target_slug
        if not source_id or not target_id:
            raise RuntimeError(f"cannot wire unresolved task reference {operation.task} -> {target_slug}")
        edge_type = operation.detail.split(":", 1)[0]
        _run_command(
            ["br", "dep", "add", source_id, target_id, "--type", edge_type, "--json"],
            state.repositories[task["repository"]]["path"],
        )
        wired += 1
    # The plan graph was checked before any mutation.  Re-read all declared JSONL
    # trackers now so stale/failed auto-export cannot silently activate staged work.
    refreshed_live: dict[str, dict[str, dict[str, Any]]] = {}
    for repository, tracker in state.trackers.items():
        current = _parse_tracker_jsonl(tracker["path"], tracker["source_repo"], state.findings, f"promotion tracker {repository}")
        refreshed_live[repository] = current
        for slug, issue_id in created.items():
            if state.tasks[slug]["repository"] == repository and issue_id not in current:
                raise RuntimeError(f"staged issue {issue_id} is absent from {tracker['path']}")
    _validate_live_graph(refreshed_live, state.findings, context="post-stage")
    if state.findings.hard:
        raise RuntimeError("post-stage tracker validation failed: " + "; ".join(sorted(state.findings.hard)))
    for operation in operations:
        if operation.phase != "activate":
            continue
        task = state.tasks[operation.task]
        issue_id = resolved.get(operation.task)
        if not issue_id:
            raise RuntimeError(f"cannot activate unresolved task {operation.task}")
        _run_command(
            ["br", "update", issue_id, "--status", "open", "--json"],
            state.repositories[task["repository"]]["path"],
        )
        activated += 1
    return staged, wired, activated


def _selftest_manifest(base: Path) -> dict[str, Any]:
    """A minimal manifest that MUST pass, built on disk under `base`."""
    plan = base / "PLAN.md"
    plan.write_text("# plan\n", encoding="utf-8")
    for repo in ("server", "driver"):
        (base / repo / ".beads").mkdir(parents=True, exist_ok=True)
        (base / repo / ".beads" / "issues.jsonl").write_text("", encoding="utf-8")

    def task(slug: str, repository: str, **overrides: Any) -> dict[str, Any]:
        record = {
            "slug": slug,
            "repository": repository,
            "tracker": repository,
            "title": f"task {slug}",
            "type": "task",
            "priority": 1,
            "tier": "tier-1",
            "labels": [f"train-{slug}", f"plan:{slug}"],
            "tracking_label": f"train-{slug}",
            "plan": {"section": "§33", "label": f"plan:{slug}"},
            "scope": ["scripts/plan_bead_graph_lint.py"],
            "acceptance": ["the lint rejects a malformed graph"],
            "evidence": ["selftest output"],
            "dependencies": [],
            "parent": None,
            "handoffs": [],
            "operator_gate": "none",
            "promotion": "activate",
            "lineage": {"kind": "new"},
            "reuse": {"action": "create"},
        }
        record.update(overrides)
        return record

    return {
        "schema": SCHEMA,
        "program": {"slug": "selftest-program"},
        "source_document": {
            "path": "PLAN.md",
            "sha256": hashlib.sha256(plan.read_bytes()).hexdigest(),
        },
        "repositories": [
            {"slug": "server", "path": "server", "source_repo": "oraclemcp"},
            {"slug": "driver", "path": "driver", "source_repo": "rust-oracledb"},
        ],
        "trackers": [
            {"repository": "server", "path": "server/.beads/issues.jsonl", "source_repo": "oraclemcp"},
            {"repository": "driver", "path": "driver/.beads/issues.jsonl", "source_repo": "rust-oracledb"},
        ],
        "release_targets": [
            {"repository": "server", "version": "0.9.1", "assertion": "patch"},
            {"repository": "driver", "version": "0.9.0", "assertion": "minor"},
        ],
        "tasks": [task("alpha", "server"), task("beta", "server"), task("gamma", "driver")],
    }


def selftest() -> int:
    """Prove the manifest validator can FAIL, rule by rule.

    A graph lint that has only ever been observed passing is indistinguishable
    from one that returns true unconditionally. This builds a manifest that must
    pass, then applies one targeted mutation per rule and requires the matching
    error code — so every rule below is evidenced as reachable, not assumed.
    """
    import tempfile

    def run(document: dict[str, Any], base: Path) -> list[str]:
        target = base / "manifest.json"
        target.write_text(json.dumps(document), encoding="utf-8")
        return validate_manifest(target).findings.hard

    def mutate_dup_slug(doc: dict[str, Any]) -> None:
        doc["tasks"][1]["slug"] = doc["tasks"][0]["slug"]

    def mutate_dup_tracking_label(doc: dict[str, Any]) -> None:
        doc["tasks"][1]["tracking_label"] = doc["tasks"][0]["tracking_label"]
        doc["tasks"][1]["labels"] = [doc["tasks"][0]["tracking_label"], "plan:beta"]

    def mutate_unknown_reference(doc: dict[str, Any]) -> None:
        doc["tasks"][0]["dependencies"] = ["no-such-task"]

    def mutate_cycle(doc: dict[str, Any]) -> None:
        doc["tasks"][0]["dependencies"] = ["beta"]
        doc["tasks"][1]["dependencies"] = ["alpha"]

    def mutate_cross_repo_native_edge(doc: dict[str, Any]) -> None:
        doc["tasks"][0]["dependencies"] = ["gamma"]

    def mutate_source_checksum(doc: dict[str, Any]) -> None:
        doc["source_document"]["sha256"] = "0" * 64

    def mutate_schema(doc: dict[str, Any]) -> None:
        doc["schema"] = "plan-bead-graph/v1"

    def mutate_missing_acceptance(doc: dict[str, Any]) -> None:
        doc["tasks"][0]["acceptance"] = []

    def mutate_release_target(doc: dict[str, Any]) -> None:
        doc["tasks"][0]["release_target"] = "9.9.9"

    def mutate_label_with_dot(doc: dict[str, Any]) -> None:
        doc["tasks"][0]["tracking_label"] = "train.alpha"

    # Rules that existed but had never been OBSERVED failing. 39 codes were
    # defined and 8 were exercised; a code that has only ever been read is not
    # evidence of anything, which is the same standard applied to this file's
    # first ten cases.
    def mutate_native_dependency(doc: dict[str, Any]) -> None:
        # Both spellings at once: the record no longer says which edge set is
        # authoritative.
        doc["tasks"][0]["dependencies"] = ["beta"]
        doc["tasks"][0]["blockers"] = ["beta"]

    def mutate_same_repo_handoff(doc: dict[str, Any]) -> None:
        # A handoff is the CROSS-repository mechanism. Using one inside a single
        # repository hides an ordinary dependency from the graph, which is
        # exactly what this manifest exists to make visible.
        # `beta` lives in the same repository as `alpha`, so this handoff is a
        # native edge wearing a cross-repo costume.
        doc["tasks"][0]["handoffs"] = [
            {"to": "beta", "artifact": "checksum-handoff.json", "sha256": "0" * 64}
        ]

    def mutate_promoted_depends_deferred(doc: dict[str, Any]) -> None:
        # Promotion order: activating a task whose dependency is not promoted
        # schedules work that cannot start.
        doc["tasks"][0]["promotion"] = "activate"
        doc["tasks"][0]["dependencies"] = ["beta"]
        doc["tasks"][1]["promotion"] = "defer"
        doc["tasks"][0]["labels"] = ["train.alpha", "plan:alpha"]

    cases: list[tuple[str, str, Any]] = [
        ("duplicate task slug", "E_TASK_SLUG", mutate_dup_slug),
        ("duplicate tracking label", "E_TASK_LABEL", mutate_dup_tracking_label),
        ("dependency on an unknown task", "E_REFERENCE_UNKNOWN", mutate_unknown_reference),
        ("dependency cycle", "E_GRAPH_CYCLE", mutate_cycle),
        ("cross-repo native edge", "E_CROSS_REPO_NATIVE_EDGE", mutate_cross_repo_native_edge),
        ("plan checksum drift", "E_SOURCE_SHA256", mutate_source_checksum),
        ("unsupported schema", "E_SCHEMA", mutate_schema),
        ("missing acceptance text", "E_TASK_ACCEPTANCE", mutate_missing_acceptance),
        ("release target disagreement", "E_SEMVER_ASSERTION", mutate_release_target),
        ("Beads-rejected '.' in a label", "E_TASK_LABEL", mutate_label_with_dot),
        ("both dependencies and blockers", "E_NATIVE_DEPENDENCY", mutate_native_dependency),
        ("same-repository handoff", "E_HANDOFF_NATIVE", mutate_same_repo_handoff),
        ("activated task depending on a deferred one", "E_PROMOTED_DEPENDS_NONPROMOTED", mutate_promoted_depends_deferred),
    ]

    checks = 0
    with tempfile.TemporaryDirectory() as raw_base:
        base = Path(raw_base)
        good = _selftest_manifest(base)
        hard = run(good, base)
        if hard:
            print("plan-bead-graph selftest: the known-good manifest was REJECTED:", file=sys.stderr)
            for line in hard:
                print(f"  {line}", file=sys.stderr)
            return 1
        print("PASS selftest: a well-formed manifest is accepted")
        checks += 1

        for label, code, mutate in cases:
            document = json.loads(json.dumps(good))
            mutate(document)
            hard = run(document, base)
            if not any(line.startswith(code) for line in hard):
                print(
                    f"plan-bead-graph selftest: {label} was NOT rejected with {code}; got {hard or 'no findings'}",
                    file=sys.stderr,
                )
                return 1
            print(f"PASS selftest: {label} is rejected ({code})")
            checks += 1

        # THE LIVE-GRAPH PATH. E_LIVE_REFERENCE guards the exported tracker
        # state rather than the manifest, so no manifest mutation can reach it —
        # which is precisely why it had never been observed failing. It needs a
        # tracker whose issue depends on an id that is not in that tracker.
        tracker = base / "server" / ".beads" / "issues.jsonl"
        original = tracker.read_text(encoding="utf-8")
        tracker.write_text(
            json.dumps(
                {
                    "id": "server-1",
                    "status": "open",
                    "dependencies": [
                        {"issue_id": "server-1", "depends_on_id": "server-missing", "type": "blocks"}
                    ],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        hard = run(good, base)
        tracker.write_text(original, encoding="utf-8")
        if not any(line.startswith("E_LIVE_REFERENCE") for line in hard):
            print(
                "plan-bead-graph selftest: a dangling edge in the LIVE tracker was NOT rejected with "
                f"E_LIVE_REFERENCE; got {hard or 'no findings'}",
                file=sys.stderr,
            )
            return 1
        print("PASS selftest: a dangling edge in the live tracker is rejected (E_LIVE_REFERENCE)")
        checks += 1

    print(f"plan-bead-graph selftest: OK ({checks} checks; the validator rejects every mutated graph)")
    return 0


def report_manifest(state: ManifestState) -> None:
    for line in sorted(state.findings.warn):
        print(f"lint: WARN {line}")
    for line in sorted(state.findings.hard):
        print(f"lint: HARD {line}")
    promotions = Counter(task["promotion"] for task in state.tasks.values())
    promotion_summary = ",".join(f"{name}:{promotions[name]}" for name in sorted(promotions))
    verdict = "FAIL" if state.findings.hard else "PASS"
    print(
        f"plan-bead-graph: {verdict} — program={state.raw.get('program', {}).get('slug', '?')} "
        f"tasks={len(state.tasks)} repositories={len(state.repositories)} "
        f"promotions={promotion_summary} hard={len(state.findings.hard)}"
    )


def report_promotion(operations: list[PromotionOperation], *, applied: tuple[int, int, int] | None = None) -> None:
    for operation in operations:
        print(f"promotion: {operation.phase} {operation.task} — {operation.detail}")
    if applied is None:
        print(
            "promotion: PLAN — "
            f"stage={sum(op.phase == 'stage' for op in operations)} "
            f"wire={sum(op.phase == 'wire' for op in operations)} "
            f"activate={sum(op.phase == 'activate' for op in operations)}"
        )
    else:
        staged, wired, activated = applied
        print(f"promotion: APPLIED — stage={staged} wire={wired} activate={activated}")


# ---------------------------------------------------------------------------
# Legacy v1 live-train checks.  Keep this mode while the currently promoted
# conversion graphs still use it; normalized manifests are the import contract.


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


def legacy_report(hard: list[str], warn: list[str], train: dict[str, dict]) -> None:
    for line in warn:
        print(f"lint: WARN {line}")
    for line in hard:
        print(f"lint: HARD {line}")
    verdict = "FAIL" if hard else "PASS"
    print(f"plan-bead-graph-lint: {verdict} — train beads={len(train)} hard={len(hard)} warn={len(warn)}")


def legacy_main(args: argparse.Namespace) -> int:
    issues = load_issues(args.input)
    by_id = {}
    hard: list[str] = []
    warn: list[str] = []
    for issue in issues:
        iid = issue.get("id")
        if iid in by_id:
            hard.append(f"H1 duplicate id: {iid}")
        by_id[iid] = issue
    train = {iid: issue for iid, issue in by_id.items() if args.train_label in (issue.get("labels") or [])}
    if args.sink not in by_id:
        hard.append(f"H4 sink {args.sink} not found")
        legacy_report(hard, warn, train)
        return 1
    for iid, issue in train.items():
        for label in issue.get("labels") or []:
            if "." in label:
                hard.append(f"H2 label with dot on {iid}: {label}")
    graph: dict[str, set[str]] = defaultdict(set)
    universe = set(train) | {args.sink}
    for iid in sorted(universe):
        for target, dep_type in load_deps(iid):
            if dep_type == "blocks":
                graph[iid].add(target)
    for source, target in _iterative_cycles(graph):
        hard.append(f"H3 cycle through {source} -> {target}")
    ancestors: set[str] = set()
    frontier = [args.sink]
    while frontier:
        node = frontier.pop()
        for dependency in graph.get(node, ()):
            if dependency not in ancestors:
                ancestors.add(dependency)
                if dependency not in graph:
                    for target, dep_type in load_deps(dependency):
                        if dep_type == "blocks":
                            graph[dependency].add(target)
                frontier.append(dependency)
    for iid, issue in sorted(train.items()):
        if iid == args.sink or issue.get("status") in ("closed", "deferred") or "sink-exempt" in (issue.get("labels") or []):
            continue
        if iid not in ancestors:
            hard.append(f"H4 not a sink ancestor: {iid}")
    open_blockers = [
        dependency
        for dependency in graph.get(args.sink, ())
        if by_id.get(dependency, {}).get("status") in ("open", "in_progress")
    ]
    if not open_blockers:
        hard.append("H5 sink has no open blocks-dependency (would be ready)")
    for iid, issue in sorted(train.items()):
        if issue.get("status") == "closed" or issue.get("issue_type") == "epic":
            continue
        description = (issue.get("description") or "") + (issue.get("notes") or "")
        if args.marker in iid:
            if len(description) < 200:
                hard.append(f"H6 short description ({len(description)}) on {iid}")
            if "acceptance" not in description.lower():
                hard.append(f"H6 no acceptance criterion on {iid}")
        elif "acceptance" not in description.lower():
            warn.append(f"W1 legacy train bead without acceptance text: {iid}")
    legacy_report(hard, warn, train)
    return 1 if hard else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", help="normalized plan-to-Beads manifest JSON")
    parser.add_argument("--promote", action="store_true", help="print the staged promotion plan for --manifest")
    parser.add_argument("--apply", action="store_true", help="with --promote, execute the staged promotion plan")
    parser.add_argument("--include-gcp", action="store_true", help="permit cluster J in a promotion plan")
    parser.add_argument("--train-label", help="legacy live-train label")
    parser.add_argument("--sink", help="legacy terminal sink issue id")
    parser.add_argument("--marker", help="legacy conversion-authored id marker")
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="prove the manifest validator rejects a malformed graph, rule by rule",
    )
    parser.add_argument("--input", default=None, help="legacy saved br list JSON")
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    if args.manifest:
        if any((args.train_label, args.sink, args.marker, args.input)):
            parser.error("--manifest cannot be combined with legacy --train-label/--sink/--marker/--input")
        if args.apply and not args.promote:
            parser.error("--apply requires --promote")
        state = validate_manifest(Path(args.manifest))
        report_manifest(state)
        if state.findings.hard:
            return 1
        if not args.promote:
            return 0
        operations = promotion_operations(state, args.include_gcp)
        if not args.apply:
            report_promotion(operations)
            return 0
        try:
            applied = apply_promotion(state, args.include_gcp)
        except RuntimeError as exc:
            print(f"promotion: HARD E_PROMOTION_APPLY {exc}", file=sys.stderr)
            return 1
        report_promotion(operations, applied=applied)
        return 0
    if args.promote or args.apply or args.include_gcp:
        parser.error("--promote, --apply, and --include-gcp require --manifest")
    if not all((args.train_label, args.sink, args.marker)):
        parser.error("legacy mode requires --train-label, --sink, and --marker")
    return legacy_main(args)


if __name__ == "__main__":
    sys.exit(main())
