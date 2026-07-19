#!/usr/bin/env python3
"""Validate a normalized plan-to-Beads graph before tracker promotion.

The input is an import specification, not a second issue tracker: status and
assignee fields are deliberately forbidden.  The linter proves that identifiers,
repository-local dependency edges, cross-repository handoffs, source anchors, and
declared release-version transitions are coherent before ``br create`` is run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA = "oraclemcp-plan-bead-graph/v1"
SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
LABEL_RE = re.compile(r"^plan:[a-z0-9][a-z0-9:._-]*$")
SOURCE_REF_RE = re.compile(r"^(?P<path>[^:]+):(?P<start>[1-9][0-9]*)(?:-(?P<end>[1-9][0-9]*))?$")
SEMVER_RE = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")

TOP_LEVEL_KEYS = {
    "schema",
    "program",
    "source_document",
    "repositories",
    "trackers",
    "release_targets",
    "tasks",
}
TASK_KEYS = {
    "slug",
    "tracking_label",
    "repo",
    "title",
    "type",
    "priority",
    "labels",
    "source_refs",
    "scope",
    "description",
    "acceptance_criteria",
    "evidence",
    "tier",
    "depends_on",
    "handoffs",
    "parent",
    "operator_gate",
    "promotion",
    "existing_id",
    "condition",
    "lineage",
    "reuse_action",
}
REQUIRED_TASK_KEYS = {
    "slug",
    "tracking_label",
    "repo",
    "title",
    "type",
    "priority",
    "labels",
    "source_refs",
    "scope",
    "description",
    "acceptance_criteria",
    "evidence",
    "tier",
    "depends_on",
    "handoffs",
    "operator_gate",
    "promotion",
}
ISSUE_TYPES = {"bug", "feature", "task", "epic", "chore"}
TIERS = {"tier-0", "tier-1", "tier-2", "tier-3", "process", "operator-gated"}
OPERATOR_GATES = {
    "none",
    "operator-input",
    "cost",
    "release",
    "production-deploy",
    "public-launch",
    "destructive",
}
LINEAGE_RELATIONS = {"extends", "supersedes", "discovered-from"}
REUSE_ACTIONS = {"record-complete", "continue", "reopen-correct", "reactivate"}
BUMPS = {"exact", "patch", "minor", "major"}
PROMOTIONS = {"create", "reuse", "defer", "record-only"}
HANDOFF_KEYS = {"task", "artifact", "checksum"}
TRACKER_KEYS = {"path", "source_repo"}
SOURCE_DOCUMENT_KEYS = {"path", "sha256"}


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    message: str

    def render(self) -> str:
        return f"{self.path}: {self.message}"


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _nonempty_string(value: Any, minimum: int = 1) -> bool:
    return isinstance(value, str) and len(value.strip()) >= minimum


def _is_promoted(value: Any) -> bool:
    return isinstance(value, str) and value in ("create", "reuse")


def _unknown_keys(value: dict[Any, Any], allowed: set[str]) -> list[str]:
    return sorted(
        key if isinstance(key, str) else repr(key)
        for key in value
        if not isinstance(key, str) or key not in allowed
    )


def _has_forbidden_control(value: str) -> bool:
    try:
        value.encode("utf-8")
    except UnicodeError:
        return True
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _parse_semver(value: Any) -> tuple[int, int, int] | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    match = SEMVER_RE.fullmatch(value)
    if match is None:
        return None
    try:
        return tuple(int(part) for part in match.groups())  # type: ignore[return-value]
    except ValueError:
        return None


def _expected_version(current: tuple[int, int, int], bump: str) -> tuple[int, int, int]:
    major, minor, patch = current
    if bump == "exact":
        return current
    if bump == "patch":
        return major, minor, patch + 1
    if bump == "minor":
        return major, minor + 1, 0
    return major + 1, 0, 0


def _validate_release_targets(
    value: Any, repositories: set[str], findings: list[Finding]
) -> None:
    if not isinstance(value, list):
        findings.append(Finding("release_targets", "must be an array"))
        return

    seen_repositories: set[str] = set()
    allowed_keys = {"repo", "current", "next", "bump"}
    for index, target in enumerate(value):
        path = f"release_targets[{index}]"
        if not isinstance(target, dict):
            findings.append(Finding(path, "must be an object"))
            continue
        unknown = _unknown_keys(target, allowed_keys)
        if unknown:
            findings.append(Finding(path, f"unknown fields: {', '.join(unknown)}"))
        missing = sorted(allowed_keys - set(target))
        if missing:
            findings.append(Finding(path, f"missing fields: {', '.join(missing)}"))
            continue

        repo = target["repo"]
        if not isinstance(repo, str):
            findings.append(Finding(f"{path}.repo", "must be a repository slug"))
        elif repo not in repositories:
            findings.append(Finding(f"{path}.repo", f"unknown repository {repo!r}"))
        elif repo in seen_repositories:
            findings.append(Finding(f"{path}.repo", f"duplicate release target for {repo!r}"))
        else:
            seen_repositories.add(repo)

        bump = target["bump"]
        if not isinstance(bump, str) or bump not in BUMPS:
            findings.append(Finding(f"{path}.bump", f"must be one of {sorted(BUMPS)}"))
            continue
        current = _parse_semver(target["current"])
        next_version = _parse_semver(target["next"])
        if current is None:
            findings.append(Finding(f"{path}.current", "must be strict MAJOR.MINOR.PATCH"))
        if next_version is None:
            findings.append(Finding(f"{path}.next", "must be strict MAJOR.MINOR.PATCH"))
        if current is not None and next_version is not None:
            expected = _expected_version(current, bump)
            if next_version != expected:
                expected_text = ".".join(str(part) for part in expected)
                findings.append(
                    Finding(
                        f"{path}.next",
                        f"{bump} transition from {target['current']} must be {expected_text}",
                    )
                )


def _load_tracker_ids(
    value: Any,
    repositories: set[str],
    repo_root: Path,
    findings: list[Finding],
) -> tuple[dict[str, dict[str, str | None]], dict[str, str]]:
    tracker_issues: dict[str, dict[str, str | None]] = {}
    tracker_sources: dict[str, str] = {}
    if not isinstance(value, dict):
        findings.append(Finding("trackers", "must be an object keyed by repository slug"))
        return tracker_issues, tracker_sources

    unknown = sorted(repr(key) for key in value if not isinstance(key, str) or key not in repositories)
    if unknown:
        findings.append(Finding("trackers", f"unknown repository keys: {', '.join(unknown)}"))
    missing = sorted(repositories - {key for key in value if isinstance(key, str)})
    if missing:
        findings.append(Finding("trackers", f"missing repository keys: {', '.join(missing)}"))

    for repo in sorted(repositories):
        tracker = value.get(repo)
        path = f"trackers.{repo}"
        if not isinstance(tracker, dict):
            findings.append(Finding(path, "must be an object"))
            continue
        unknown_fields = _unknown_keys(tracker, TRACKER_KEYS)
        if unknown_fields:
            findings.append(Finding(path, f"unknown fields: {', '.join(unknown_fields)}"))
        missing_fields = sorted(TRACKER_KEYS - set(tracker))
        if missing_fields:
            findings.append(Finding(path, f"missing fields: {', '.join(missing_fields)}"))
            continue
        tracker_path = tracker["path"]
        expected_source_repo = tracker["source_repo"]
        if not _nonempty_string(tracker_path):
            findings.append(Finding(f"{path}.path", "must name a JSONL tracker index"))
            continue
        if not _nonempty_string(expected_source_repo):
            findings.append(Finding(f"{path}.source_repo", "must name the repository identity"))
            continue
        try:
            candidate = Path(tracker_path)
            resolved = candidate if candidate.is_absolute() else repo_root / candidate
            resolved = resolved.resolve()
            exists = resolved.is_file()
        except (OSError, UnicodeError, ValueError) as error:
            findings.append(Finding(f"{path}.path", f"invalid tracker path: {error}"))
            continue
        if not exists:
            findings.append(Finding(f"{path}.path", f"tracker index does not exist: {tracker_path}"))
            continue
        issues: dict[str, str | None] = {}
        try:
            with resolved.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    try:
                        issue = json.loads(line)
                    except json.JSONDecodeError as error:
                        findings.append(
                            Finding(path, f"invalid JSON at line {line_number}: {error.msg}")
                        )
                        continue
                    issue_id = issue.get("id") if isinstance(issue, dict) else None
                    if not _nonempty_string(issue_id):
                        findings.append(Finding(path, f"line {line_number} has no non-empty issue id"))
                    else:
                        issue_source = issue.get("source_repo")
                        issue_source = issue_source if isinstance(issue_source, str) else None
                        if issue_id in issues:
                            findings.append(Finding(path, f"duplicate issue id {issue_id!r}"))
                        issues[issue_id] = issue_source
        except (OSError, UnicodeError) as error:
            findings.append(Finding(path, f"cannot read tracker index: {error}"))
            continue
        tracker_issues[repo] = issues
        tracker_sources[repo] = expected_source_repo
    return tracker_issues, tracker_sources


def _validate_source_document(value: Any, repo_root: Path, findings: list[Finding]) -> None:
    if not isinstance(value, dict):
        findings.append(Finding("source_document", "must be an object"))
        return
    unknown = _unknown_keys(value, SOURCE_DOCUMENT_KEYS)
    missing = sorted(SOURCE_DOCUMENT_KEYS - set(value))
    if unknown:
        findings.append(Finding("source_document", f"unknown fields: {', '.join(unknown)}"))
    if missing:
        findings.append(Finding("source_document", f"missing fields: {', '.join(missing)}"))
        return
    source_path = value.get("path")
    expected_digest = value.get("sha256")
    if not _nonempty_string(source_path):
        findings.append(Finding("source_document.path", "must name the governing plan"))
        return
    if not isinstance(expected_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        findings.append(Finding("source_document.sha256", "must be a lowercase SHA-256 digest"))
        return
    try:
        relative = Path(source_path)
        if relative.is_absolute() or ".." in relative.parts:
            findings.append(
                Finding("source_document.path", "must stay relative to the repository root")
            )
            return
        resolved = (repo_root / relative).resolve()
        resolved.relative_to(repo_root)
        payload = resolved.read_bytes()
    except (OSError, UnicodeError, ValueError) as error:
        findings.append(Finding("source_document.path", f"cannot read governing plan: {error}"))
        return
    actual_digest = hashlib.sha256(payload).hexdigest()
    if actual_digest != expected_digest:
        findings.append(
            Finding(
                "source_document.sha256",
                f"checksum mismatch: found {actual_digest}, expected {expected_digest}",
            )
        )


def _validate_source_ref(
    source_ref: str,
    path: str,
    repo_root: Path,
    line_counts: dict[Path, int],
    findings: list[Finding],
    expected_source_path: str | None,
) -> None:
    match = SOURCE_REF_RE.fullmatch(source_ref)
    if match is None:
        findings.append(Finding(path, "must use relative/path:LINE or relative/path:START-END"))
        return
    if expected_source_path is not None and match.group("path") != expected_source_path:
        findings.append(
            Finding(path, f"must reference the bound source document {expected_source_path!r}")
        )
        return
    try:
        relative = Path(match.group("path"))
        absolute = relative.is_absolute()
        parts = relative.parts
    except (OSError, UnicodeError, ValueError) as error:
        findings.append(Finding(path, f"invalid source path: {error}"))
        return
    if absolute or ".." in parts:
        findings.append(Finding(path, "source path must stay relative to the repository root"))
        return
    try:
        resolved = (repo_root / relative).resolve()
        is_file = resolved.is_file()
    except (OSError, UnicodeError, ValueError) as error:
        findings.append(Finding(path, f"invalid source path: {error}"))
        return
    try:
        resolved.relative_to(repo_root)
    except ValueError:
        findings.append(Finding(path, "source path escapes the repository root"))
        return
    if not is_file:
        findings.append(Finding(path, f"source file does not exist: {relative}"))
        return
    if resolved not in line_counts:
        try:
            with resolved.open("r", encoding="utf-8") as handle:
                line_counts[resolved] = sum(1 for _ in handle)
        except UnicodeError as error:
            findings.append(Finding(path, f"source file is not valid UTF-8: {error}"))
            return
    start_text = match.group("start")
    end_text = match.group("end") or start_text
    if len(start_text) > 12 or len(end_text) > 12:
        findings.append(Finding(path, "source line numbers are unreasonably large"))
        return
    try:
        start = int(start_text)
        end = int(end_text)
    except ValueError:
        findings.append(Finding(path, "source line numbers must be decimal integers"))
        return
    if end < start:
        findings.append(Finding(path, "source range end precedes its start"))
    elif end > line_counts[resolved]:
        findings.append(
            Finding(path, f"source range ends at {end}, but {relative} has {line_counts[resolved]} lines")
        )


def _cycle_path(edges: dict[str, list[str]]) -> list[str] | None:
    state: dict[str, int] = {node: 0 for node in edges}
    for start_node in sorted(edges):
        if state[start_node] != 0:
            continue
        active: list[str] = [start_node]
        positions = {start_node: 0}
        state[start_node] = 1
        work: list[tuple[str, int, list[str]]] = [
            (start_node, 0, sorted(dependency for dependency in edges[start_node] if dependency in edges))
        ]
        while work:
            node, index, dependencies = work[-1]
            if index >= len(dependencies):
                work.pop()
                active.pop()
                positions.pop(node, None)
                state[node] = 2
                continue
            dependency = dependencies[index]
            work[-1] = (node, index + 1, dependencies)
            if state[dependency] == 0:
                state[dependency] = 1
                positions[dependency] = len(active)
                active.append(dependency)
                next_dependencies = sorted(
                    candidate for candidate in edges[dependency] if candidate in edges
                )
                work.append((dependency, 0, next_dependencies))
            elif state[dependency] == 1:
                cycle_start = positions[dependency]
                return active[cycle_start:] + [dependency]
    return None


def validate(document: Any, repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    repo_root = repo_root.resolve()
    if not isinstance(document, dict):
        return [Finding("$", "top-level value must be an object")]

    unknown_top = _unknown_keys(document, TOP_LEVEL_KEYS)
    if unknown_top:
        findings.append(Finding("$", f"unknown fields: {', '.join(unknown_top)}"))
    missing_top = sorted(TOP_LEVEL_KEYS - set(document))
    if missing_top:
        findings.append(Finding("$", f"missing fields: {', '.join(missing_top)}"))
    if document.get("schema") != SCHEMA:
        findings.append(Finding("schema", f"must equal {SCHEMA!r}"))
    if not _nonempty_string(document.get("program")):
        findings.append(Finding("program", "must be a non-empty string"))
    if "source_document" in document:
        _validate_source_document(document["source_document"], repo_root, findings)
    source_document = document.get("source_document")
    expected_source_path = (
        source_document.get("path")
        if isinstance(source_document, dict) and isinstance(source_document.get("path"), str)
        else None
    )

    repositories_value = document.get("repositories")
    repositories: set[str] = set()
    if not _is_string_list(repositories_value) or not repositories_value:
        findings.append(Finding("repositories", "must be a non-empty string array"))
    else:
        repositories = set(repositories_value)
        if len(repositories) != len(repositories_value):
            findings.append(Finding("repositories", "must not contain duplicates"))
        for index, repo in enumerate(repositories_value):
            if not SLUG_RE.fullmatch(repo):
                findings.append(Finding(f"repositories[{index}]", "must be a normalized slug"))

    tracker_issues: dict[str, dict[str, str | None]] = {}
    tracker_sources: dict[str, str] = {}
    if "trackers" in document:
        tracker_issues, tracker_sources = _load_tracker_ids(
            document["trackers"], repositories, repo_root, findings
        )

    if "release_targets" in document:
        _validate_release_targets(document["release_targets"], repositories, findings)

    tasks_value = document.get("tasks")
    if "tasks" not in document:
        return sorted(findings)
    if not isinstance(tasks_value, list) or not tasks_value:
        findings.append(Finding("tasks", "must be a non-empty array"))
        return sorted(findings)

    tasks: dict[str, dict[str, Any]] = {}
    tracking_labels: dict[str, str] = {}
    promoted_plan_labels: dict[str, str] = {}
    reused_issue_ids: dict[tuple[str, str], str] = {}
    line_counts: dict[Path, int] = {}
    for index, task in enumerate(tasks_value):
        path = f"tasks[{index}]"
        if not isinstance(task, dict):
            findings.append(Finding(path, "must be an object"))
            continue
        unknown = _unknown_keys(task, TASK_KEYS)
        if unknown:
            findings.append(Finding(path, f"unknown fields: {', '.join(unknown)}"))
        missing = sorted(REQUIRED_TASK_KEYS - set(task))
        if missing:
            findings.append(Finding(path, f"missing fields: {', '.join(missing)}"))

        slug = task.get("slug")
        if not isinstance(slug, str) or not SLUG_RE.fullmatch(slug):
            findings.append(Finding(f"{path}.slug", "must be a normalized 1-64 character slug"))
            continue
        if slug in tasks:
            findings.append(Finding(f"{path}.slug", f"duplicate slug {slug!r}"))
        else:
            tasks[slug] = task

        tracking_label = task.get("tracking_label")
        if (
            not isinstance(tracking_label, str)
            or len(tracking_label) > 50
            or not LABEL_RE.fullmatch(tracking_label)
        ):
            findings.append(
                Finding(
                    f"{path}.tracking_label",
                    "must be a normalized plan: label of at most 50 characters",
                )
            )
        elif tracking_label in tracking_labels:
            findings.append(
                Finding(
                    f"{path}.tracking_label",
                    f"duplicate tracking label {tracking_label!r} (also {tracking_labels[tracking_label]})",
                )
            )
        else:
            tracking_labels[tracking_label] = slug

        repo = task.get("repo")
        if not isinstance(repo, str):
            findings.append(Finding(f"{path}.repo", "must be a repository slug"))
        elif repo not in repositories:
            findings.append(Finding(f"{path}.repo", f"unknown repository {repo!r}"))
        if not _nonempty_string(task.get("title"), 8):
            findings.append(Finding(f"{path}.title", "must contain at least 8 non-blank characters"))
        elif _has_forbidden_control(task["title"]):
            findings.append(
                Finding(f"{path}.title", "must not contain control or non-UTF-8 characters")
            )
        issue_type = task.get("type")
        if not isinstance(issue_type, str) or issue_type not in ISSUE_TYPES:
            findings.append(Finding(f"{path}.type", f"must be one of {sorted(ISSUE_TYPES)}"))
        priority = task.get("priority")
        if isinstance(priority, bool) or not isinstance(priority, int) or priority not in range(5):
            findings.append(Finding(f"{path}.priority", "must be an integer from 0 through 4"))
        tier = task.get("tier")
        if not isinstance(tier, str) or tier not in TIERS:
            findings.append(Finding(f"{path}.tier", f"must be one of {sorted(TIERS)}"))
        operator_gate = task.get("operator_gate")
        if not isinstance(operator_gate, str) or operator_gate not in OPERATOR_GATES:
            findings.append(
                Finding(f"{path}.operator_gate", f"must be one of {sorted(OPERATOR_GATES)}")
            )
        promotion = task.get("promotion")
        if not isinstance(promotion, str) or promotion not in PROMOTIONS:
            findings.append(Finding(f"{path}.promotion", f"must be one of {sorted(PROMOTIONS)}"))
        existing_id = task.get("existing_id")
        condition = task.get("condition")
        reuse_action = task.get("reuse_action")
        if promotion == "reuse" and not _nonempty_string(existing_id):
            findings.append(Finding(f"{path}.existing_id", "is required for reused tasks"))
        if promotion == "reuse":
            if not isinstance(reuse_action, str) or reuse_action not in REUSE_ACTIONS:
                findings.append(
                    Finding(
                        f"{path}.reuse_action",
                        f"must be one of {sorted(REUSE_ACTIONS)} for reused tasks",
                    )
                )
        elif reuse_action is not None:
            findings.append(Finding(f"{path}.reuse_action", "is allowed only for reused tasks"))
        if promotion in ("reuse", "defer") and existing_id is not None:
            if not _nonempty_string(existing_id):
                findings.append(Finding(f"{path}.existing_id", "must be a non-empty issue id"))
            elif isinstance(repo, str) and repo in tracker_issues:
                reuse_key = (repo, existing_id)
                previous_slug = reused_issue_ids.get(reuse_key)
                if previous_slug is not None:
                    findings.append(
                        Finding(
                            f"{path}.existing_id",
                            f"is already mapped by task {previous_slug!r}",
                        )
                    )
                else:
                    reused_issue_ids[reuse_key] = slug
                issue_source = tracker_issues[repo].get(existing_id)
                if existing_id not in tracker_issues[repo]:
                    findings.append(
                        Finding(
                            f"{path}.existing_id",
                            f"does not resolve in the {repo!r} repo-local tracker",
                        )
                    )
                elif issue_source != tracker_sources.get(repo):
                    findings.append(
                        Finding(
                            f"{path}.existing_id",
                            f"resolves to source_repo {issue_source!r}, expected {tracker_sources.get(repo)!r}",
                        )
                    )
        elif promotion not in ("reuse", "defer") and existing_id is not None:
            findings.append(
                Finding(
                    f"{path}.existing_id",
                    "is allowed only when promotion is reuse or a deferred existing-Bead mapping",
                )
            )
        if promotion in ("defer", "record-only"):
            if not _nonempty_string(condition, 12):
                findings.append(
                    Finding(f"{path}.condition", "must explain why promotion is deferred or record-only")
                )
        elif condition is not None:
            findings.append(
                Finding(f"{path}.condition", "is allowed only for deferred or record-only tasks")
            )

        lineage = task.get("lineage", [])
        if not isinstance(lineage, list):
            findings.append(Finding(f"{path}.lineage", "must be an array when present"))
        else:
            seen_lineage: set[str] = set()
            for lineage_index, item in enumerate(lineage):
                lineage_path = f"{path}.lineage[{lineage_index}]"
                if not isinstance(item, dict):
                    findings.append(Finding(lineage_path, "must be an object"))
                    continue
                if set(item) != {"id", "relation"}:
                    findings.append(
                        Finding(lineage_path, "must contain exactly id and relation")
                    )
                    continue
                issue_id = item.get("id")
                relation = item.get("relation")
                if not _nonempty_string(issue_id):
                    findings.append(Finding(f"{lineage_path}.id", "must be a non-empty issue id"))
                    continue
                if not isinstance(relation, str) or relation not in LINEAGE_RELATIONS:
                    findings.append(
                        Finding(
                            f"{lineage_path}.relation",
                            f"must be one of {sorted(LINEAGE_RELATIONS)}",
                        )
                    )
                    continue
                if issue_id in seen_lineage:
                    findings.append(Finding(lineage_path, "duplicates a lineage issue id"))
                    continue
                seen_lineage.add(issue_id)
                if promotion == "reuse" and issue_id == existing_id:
                    findings.append(
                        Finding(f"{lineage_path}.id", "cannot reference the reused issue itself")
                    )
                if isinstance(repo, str) and repo in tracker_issues:
                    issue_source = tracker_issues[repo].get(issue_id)
                    if issue_id not in tracker_issues[repo]:
                        findings.append(
                            Finding(
                                f"{lineage_path}.id",
                                f"does not resolve in the {repo!r} repo-local tracker",
                            )
                        )
                    elif issue_source != tracker_sources.get(repo):
                        findings.append(
                            Finding(
                                f"{lineage_path}.id",
                                f"resolves to source_repo {issue_source!r}, expected {tracker_sources.get(repo)!r}",
                            )
                        )
        if not _nonempty_string(task.get("scope"), 40):
            findings.append(Finding(f"{path}.scope", "must contain at least 40 non-blank characters"))
        elif _has_forbidden_control(task["scope"]):
            findings.append(
                Finding(f"{path}.scope", "must not contain control or non-UTF-8 characters")
            )
        if not _nonempty_string(task.get("description"), 40):
            findings.append(
                Finding(f"{path}.description", "must contain at least 40 non-blank characters")
            )
        elif _has_forbidden_control(task["description"]):
            findings.append(
                Finding(
                    f"{path}.description",
                    "must not contain control or non-UTF-8 characters",
                )
            )

        labels = task.get("labels")
        if not _is_string_list(labels) or not labels:
            findings.append(Finding(f"{path}.labels", "must be a non-empty string array"))
        else:
            if len(labels) != len(set(labels)):
                findings.append(Finding(f"{path}.labels", "must not contain duplicate labels"))
            if any(len(label) > 50 for label in labels):
                findings.append(
                    Finding(f"{path}.labels", "each label must be at most 50 characters")
                )
            if any("," in label or _has_forbidden_control(label) for label in labels):
                findings.append(
                    Finding(
                        f"{path}.labels",
                        "must not contain commas, control, or non-UTF-8 characters",
                    )
                )
            cluster_labels = [label for label in labels if label.startswith("cluster-")]
            if len(cluster_labels) != 1 or not SLUG_RE.fullmatch(cluster_labels[0]):
                findings.append(
                    Finding(f"{path}.labels", "must contain exactly one normalized cluster-* label")
                )
            if tracking_label not in labels:
                findings.append(Finding(f"{path}.labels", "must contain tracking_label"))
            plan_labels = [label for label in labels if label.startswith("plan:")]
            if plan_labels != [tracking_label]:
                findings.append(
                    Finding(f"{path}.labels", "must contain exactly its own tracking_label as a plan: label")
                )
            for label in plan_labels:
                owner = promoted_plan_labels.get(label)
                if owner is not None and owner != slug:
                    findings.append(
                        Finding(f"{path}.labels", f"plan label {label!r} is already owned by {owner!r}")
                    )
                else:
                    promoted_plan_labels[label] = slug

        source_refs = task.get("source_refs")
        if not _is_string_list(source_refs) or not source_refs:
            findings.append(Finding(f"{path}.source_refs", "must be a non-empty string array"))
        else:
            if len(source_refs) != len(set(source_refs)):
                findings.append(Finding(f"{path}.source_refs", "must not contain duplicates"))
            for ref_index, source_ref in enumerate(source_refs):
                _validate_source_ref(
                    source_ref,
                    f"{path}.source_refs[{ref_index}]",
                    repo_root,
                    line_counts,
                    findings,
                    expected_source_path,
                )

        acceptance = task.get("acceptance_criteria")
        if not _is_string_list(acceptance) or not acceptance:
            findings.append(
                Finding(f"{path}.acceptance_criteria", "must be a non-empty string array")
            )
        elif any(len(item.strip()) < 12 for item in acceptance):
            findings.append(
                Finding(f"{path}.acceptance_criteria", "each criterion must contain at least 12 characters")
            )
        elif any(_has_forbidden_control(item) for item in acceptance):
            findings.append(
                Finding(
                    f"{path}.acceptance_criteria",
                    "items must not contain control or non-UTF-8 characters",
                )
            )

        evidence = task.get("evidence")
        if not _is_string_list(evidence) or not evidence:
            findings.append(Finding(f"{path}.evidence", "must be a non-empty string array"))
        elif any(len(item.strip()) < 12 for item in evidence):
            findings.append(Finding(f"{path}.evidence", "each item must contain at least 12 characters"))
        elif any(_has_forbidden_control(item) for item in evidence):
            findings.append(
                Finding(
                    f"{path}.evidence",
                    "items must not contain control or non-UTF-8 characters",
                )
            )

        depends_on = task.get("depends_on")
        if not _is_string_list(depends_on):
            findings.append(Finding(f"{path}.depends_on", "must be a string array"))
        elif len(depends_on) != len(set(depends_on)):
            findings.append(Finding(f"{path}.depends_on", "must not contain duplicates"))

        handoffs = task.get("handoffs")
        if not isinstance(handoffs, list):
            findings.append(Finding(f"{path}.handoffs", "must be an array"))
        else:
            seen_handoffs: set[str] = set()
            for handoff_index, handoff in enumerate(handoffs):
                handoff_path = f"{path}.handoffs[{handoff_index}]"
                if not isinstance(handoff, dict):
                    findings.append(Finding(handoff_path, "must be an object"))
                    continue
                unknown_handoff = _unknown_keys(handoff, HANDOFF_KEYS)
                if unknown_handoff:
                    findings.append(
                        Finding(handoff_path, f"unknown fields: {', '.join(unknown_handoff)}")
                    )
                missing_handoff = sorted(HANDOFF_KEYS - set(handoff))
                if missing_handoff:
                    findings.append(
                        Finding(handoff_path, f"missing fields: {', '.join(missing_handoff)}")
                    )
                    continue
                handoff_task = handoff["task"]
                if not isinstance(handoff_task, str) or not SLUG_RE.fullmatch(handoff_task):
                    findings.append(Finding(f"{handoff_path}.task", "must be a normalized task slug"))
                elif handoff_task in seen_handoffs:
                    findings.append(Finding(f"{path}.handoffs", "must not contain duplicate task refs"))
                else:
                    seen_handoffs.add(handoff_task)
                if not _nonempty_string(handoff["artifact"], 12):
                    findings.append(
                        Finding(f"{handoff_path}.artifact", "must name the handoff artifact")
                    )
                elif _has_forbidden_control(handoff["artifact"]):
                    findings.append(
                        Finding(
                            f"{handoff_path}.artifact",
                            "must not contain control or non-UTF-8 characters",
                        )
                    )
                if handoff["checksum"] != "required":
                    findings.append(
                        Finding(f"{handoff_path}.checksum", "must equal 'required'")
                    )
        parent = task.get("parent")
        if parent is not None and not isinstance(parent, str):
            findings.append(Finding(f"{path}.parent", "must be a task slug when present"))

    dependency_edges: dict[str, list[str]] = {slug: [] for slug in tasks}
    parent_edges: dict[str, list[str]] = {slug: [] for slug in tasks}
    for slug, task in tasks.items():
        task_path = f"tasks[{slug}]"
        edge_fields: list[tuple[str, list[str]]] = []
        depends_on = task.get("depends_on")
        if _is_string_list(depends_on):
            edge_fields.append(("depends_on", depends_on))
        handoffs = task.get("handoffs")
        if isinstance(handoffs, list):
            handoff_refs = [
                handoff.get("task")
                for handoff in handoffs
                if isinstance(handoff, dict) and isinstance(handoff.get("task"), str)
            ]
            edge_fields.append(("handoffs", handoff_refs))

        for field, refs in edge_fields:
            for reference in refs:
                if reference == slug:
                    findings.append(Finding(f"{task_path}.{field}", "self-reference is forbidden"))
                    continue
                target = tasks.get(reference)
                if target is None:
                    findings.append(
                        Finding(f"{task_path}.{field}", f"unknown task reference {reference!r}")
                    )
                    continue
                same_repo = target.get("repo") == task.get("repo")
                if field == "depends_on" and not same_repo:
                    findings.append(
                        Finding(
                            f"{task_path}.{field}",
                            f"native dependency {reference!r} crosses repositories; use handoffs",
                        )
                    )
                if field == "handoffs" and same_repo:
                    findings.append(
                        Finding(
                            f"{task_path}.{field}",
                            f"handoff {reference!r} stays in one repository; use depends_on",
                        )
                    )
                if (
                    field == "depends_on"
                    and same_repo
                    and _is_promoted(task.get("promotion"))
                    and not _is_promoted(target.get("promotion"))
                ):
                    findings.append(
                        Finding(
                            f"{task_path}.{field}",
                            f"promoted task cannot depend on non-promoted task {reference!r}",
                        )
                    )
                dependency_edges[slug].append(reference)

        parent = task.get("parent")
        if isinstance(parent, str):
            if parent == slug:
                findings.append(Finding(f"{task_path}.parent", "task cannot parent itself"))
            elif parent not in tasks:
                findings.append(Finding(f"{task_path}.parent", f"unknown parent {parent!r}"))
            elif tasks[parent].get("repo") != task.get("repo"):
                findings.append(
                    Finding(f"{task_path}.parent", "parent must be in the same repository")
                )
            elif (
                _is_promoted(task.get("promotion"))
                and not _is_promoted(tasks[parent].get("promotion"))
            ):
                findings.append(
                    Finding(
                        f"{task_path}.parent",
                        "promoted task cannot use a non-promoted parent",
                    )
                )
            else:
                parent_edges[slug].append(parent)
                dependency_edges[slug].append(parent)

    cycle = _cycle_path(dependency_edges)
    if cycle is not None:
        findings.append(Finding("tasks", "dependency/handoff cycle: " + " -> ".join(cycle)))
    parent_cycle = _cycle_path(parent_edges)
    if parent_cycle is not None:
        findings.append(Finding("tasks", "parent cycle: " + " -> ".join(parent_cycle)))
    return sorted(set(findings))


def _load_document(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="normalized graph JSON path, or - for stdin")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="root used to resolve source_refs (default: script repository)",
    )
    parser.add_argument("--json", action="store_true", help="emit one JSON result")
    args = parser.parse_args(argv)

    try:
        document = _load_document(args.input)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        if args.json:
            print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        else:
            print(f"plan-bead-graph-lint: input error: {error}", file=sys.stderr)
        return 2

    findings = validate(document, args.repo_root)
    tasks = document.get("tasks") if isinstance(document, dict) else None
    task_count = len(tasks) if isinstance(tasks, list) else 0
    if args.json:
        print(
            json.dumps(
                {
                    "ok": not findings,
                    "schema": SCHEMA,
                    "task_count": task_count,
                    "findings": [finding.render() for finding in findings],
                },
                sort_keys=True,
            )
        )
    elif findings:
        print("plan-bead-graph-lint: FAIL", file=sys.stderr)
        for finding in findings:
            print(f"- {finding.render()}", file=sys.stderr)
    else:
        print(f"plan-bead-graph-lint: OK - {task_count} normalized task(s), graph is coherent")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
