#!/usr/bin/env python3
"""Derive and evaluate the repository CI taxonomy without network-only state.

The workflow files remain the source of truth. This tool deliberately parses
the small GitHub Actions YAML subset used by this repository rather than
depending on a package manager at CI time. In addition to producing the
machine-readable taxonomy, it rejects duplicate mapping keys -- including the
otherwise easy-to-miss duplicate ``with:`` inside a step list.
"""

from __future__ import annotations

import argparse
import json
import itertools
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "ci-taxonomy/v1"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORKFLOW_DIR = ROOT / ".github" / "workflows"
FIXTURE_DIR = ROOT / "tests" / "ci_taxonomy"
TAXONOMY_PATH = ROOT / "docs" / "ci_taxonomy.json"
MAPPING_KEY = re.compile(r"^(?P<key>[A-Za-z0-9_.\-/]+):(?:[ \t]*(?P<value>.*))?$")
EXPRESSION = re.compile(r"\$\{\{.*?\}\}")
MATRIX_EXPRESSION = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_.-]+)\s*\}\}")


class WorkflowError(ValueError):
    """A workflow cannot be used as a trustworthy CI contract."""


@dataclass
class MappingFrame:
    indent: int
    keys: set[str] = field(default_factory=set)


@dataclass
class Job:
    identifier: str
    display_name: str
    advisory: bool = False
    timeout_minutes: int | None = None
    has_permissions: bool = False
    matrix_values: dict[str, list[str]] = field(default_factory=dict)
    matrix_includes: list[dict[str, str]] = field(default_factory=list)


@dataclass
class Workflow:
    path: Path
    name: str
    triggers: set[str]
    has_permissions: bool
    jobs: list[Job]
    push_branches: bool = False
    push_tags: bool = False
    path_filtered: bool = False


def strip_comment(text: str) -> str:
    """Drop YAML comments while preserving quoted scalar values."""

    quote: str | None = None
    escaped = False
    for index, character in enumerate(text):
        if quote == '"' and escaped:
            escaped = False
            continue
        if quote == '"' and character == "\\":
            escaped = True
            continue
        if character in {"'", '"'}:
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
            continue
        if character == "#" and quote is None:
            return text[:index].rstrip()
    return text.rstrip()


def split_mapping(text: str) -> tuple[str, str] | None:
    """Return a plain GitHub Actions mapping key and its scalar tail."""

    match = MAPPING_KEY.match(text)
    if not match:
        return None
    return match.group("key"), (match.group("value") or "").strip()


def plain_scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def workflow_lines(path: Path) -> Iterable[tuple[int, int, str]]:
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        text = strip_comment(raw_line)
        if not text.strip() or text.lstrip().startswith("---"):
            continue
        indent = len(text) - len(text.lstrip(" "))
        if "\t" in text[:indent]:
            raise WorkflowError(f"{path}:{line_number}: tabs are not allowed for YAML indentation")
        yield line_number, indent, text.strip()


def reject_duplicate_keys(path: Path) -> None:
    """Lint the mapping shape used in workflow YAML, including list-item maps."""

    frames: list[MappingFrame] = [MappingFrame(indent=0)]
    scalar_indent: int | None = None

    for line_number, indent, text in workflow_lines(path):
        if scalar_indent is not None:
            if indent > scalar_indent:
                continue
            scalar_indent = None

        list_item = text.startswith("- ")
        mapping_text = text[2:].lstrip() if list_item else text
        mapping = split_mapping(mapping_text)
        if mapping is None:
            continue

        key, value = mapping
        logical_indent = indent + 2 if list_item else indent
        while frames and frames[-1].indent > logical_indent:
            frames.pop()
        if list_item:
            while frames and frames[-1].indent >= logical_indent:
                frames.pop()

        if not frames or frames[-1].indent != logical_indent:
            frames.append(MappingFrame(indent=logical_indent))
        frame = frames[-1]
        if key in frame.keys:
            raise WorkflowError(f"{path}:{line_number}: duplicate mapping key {key!r}")
        frame.keys.add(key)

        if value in {"|", "|-", "|+", ">", ">-", ">+"}:
            scalar_indent = logical_indent


def parse_triggers(value: str) -> set[str]:
    value = value.strip()
    if not value.startswith("[") or not value.endswith("]"):
        return set()
    return {plain_scalar(item) for item in value[1:-1].split(",") if item.strip()}


def parse_workflow(path: Path) -> Workflow:
    reject_duplicate_keys(path)

    name = path.stem
    triggers: set[str] = set()
    has_permissions = False
    jobs: list[Job] = []
    push_branches = False
    push_tags = False
    path_filtered = False
    in_on = False
    in_jobs = False
    active_trigger: str | None = None
    current_job: Job | None = None
    in_strategy = False
    in_matrix = False
    matrix_key: str | None = None
    matrix_include: dict[str, str] | None = None

    for _line_number, indent, text in workflow_lines(path):
        list_item = text.startswith("- ")
        mapping = split_mapping(text[2:].lstrip() if list_item else text)
        if mapping is None:
            if (
                current_job is not None
                and in_strategy
                and in_matrix
                and indent == 10
                and list_item
                and matrix_key is not None
                and matrix_key != "include"
            ):
                current_job.matrix_values.setdefault(matrix_key, []).append(
                    plain_scalar(text[2:].strip())
                )
            continue
        key, value = mapping

        if indent == 0:
            in_on = key == "on"
            in_jobs = key == "jobs"
            active_trigger = None
            current_job = None
            in_strategy = False
            in_matrix = False
            matrix_key = None
            matrix_include = None
            if key == "name":
                name = plain_scalar(value)
            elif key == "on":
                triggers.update(parse_triggers(value))
            elif key == "permissions":
                has_permissions = True
            continue

        if in_on:
            if indent == 2:
                active_trigger = key
                triggers.add(key)
                continue
            if indent == 4 and active_trigger == "push":
                if key == "branches":
                    push_branches = True
                elif key == "tags":
                    push_tags = True
                elif key == "paths":
                    path_filtered = True
            continue

        if not in_jobs:
            continue
        if indent == 2:
            current_job = Job(identifier=key, display_name=key)
            jobs.append(current_job)
            in_strategy = False
            in_matrix = False
            matrix_key = None
            matrix_include = None
            continue
        if current_job is None:
            continue
        if indent == 4:
            in_strategy = key == "strategy"
            in_matrix = False
            matrix_key = None
            matrix_include = None
            if key == "name":
                current_job.display_name = plain_scalar(value)
            elif key == "continue-on-error":
                current_job.advisory = plain_scalar(value).lower() == "true"
            elif key == "timeout-minutes":
                try:
                    current_job.timeout_minutes = int(plain_scalar(value))
                except ValueError as error:
                    raise WorkflowError(
                        f"{path}: timeout-minutes for job {current_job.identifier!r} must be an integer"
                    ) from error
            elif key == "permissions":
                current_job.has_permissions = True
            continue
        if not in_strategy:
            continue
        if indent == 6:
            in_matrix = key == "matrix"
            matrix_key = None
            matrix_include = None
            continue
        if not in_matrix:
            continue
        if indent == 8:
            matrix_key = key
            matrix_include = None
            if value.startswith("[") and value.endswith("]"):
                values = [plain_scalar(item) for item in value[1:-1].split(",") if item.strip()]
                current_job.matrix_values[key] = values
                matrix_key = None
            continue
        if indent == 10 and list_item and matrix_key is not None:
            if matrix_key == "include":
                matrix_include = {}
                current_job.matrix_includes.append(matrix_include)
                if value:
                    matrix_include[key] = plain_scalar(value)
            else:
                current_job.matrix_values.setdefault(matrix_key, []).append(plain_scalar(key))
            continue
        if indent == 12 and matrix_include is not None:
            matrix_include[key] = plain_scalar(value)

    if "push" in triggers and not push_branches and not push_tags:
        # A bare `push:` means all branch and tag pushes; it is required in the
        # same way an explicit branch list is required.
        push_branches = True
        push_tags = True
    # A repository can keep local CI input data beside workflow files. It is
    # not a GitHub Actions workflow unless it declares at least one trigger;
    # do not invent timeout/permission requirements for data GitHub never
    # executes. Trigger-bearing files still fail closed if they lack jobs.
    if triggers and not jobs:
        raise WorkflowError(f"{path}: no jobs mapping found")
    return Workflow(
        path=path,
        name=name,
        triggers=triggers,
        has_permissions=has_permissions,
        jobs=jobs,
        push_branches=push_branches,
        push_tags=push_tags,
        path_filtered=path_filtered,
    )


def load_workflows(workflow_dir: Path) -> list[Workflow]:
    paths = sorted((*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")))
    if not paths:
        raise WorkflowError(f"{workflow_dir}: no workflow YAML files found")
    workflows = [parse_workflow(path) for path in paths]
    triggered = [workflow for workflow in workflows if workflow.triggers]
    if not triggered:
        raise WorkflowError(f"{workflow_dir}: no trigger-bearing workflow YAML files found")
    return triggered


def job_tier(workflow: Workflow, job: Job) -> str:
    if job.advisory:
        return "advisory"
    if "pull_request" in workflow.triggers or workflow.push_branches:
        return "required"
    if workflow.push_tags:
        return "release"
    if "schedule" in workflow.triggers:
        return "scheduled"
    return "manual"


def matrix_combinations(job: Job) -> list[dict[str, str]]:
    if job.matrix_includes:
        return job.matrix_includes
    if not job.matrix_values:
        return [{}]
    keys = list(job.matrix_values)
    if any(not job.matrix_values[key] for key in keys):
        raise WorkflowError(f"job {job.identifier}: matrix axis has no values")
    return [dict(zip(keys, values)) for values in itertools.product(*(job.matrix_values[key] for key in keys))]


def check_names(job: Job) -> list[str]:
    names: list[str] = []
    for combo in matrix_combinations(job):
        def replace(match: re.Match[str]) -> str:
            key = match.group(1)
            if key not in combo:
                raise WorkflowError(
                    f"job {job.identifier}: cannot resolve matrix expression {match.group(0)!r}"
                )
            return combo[key]

        name = MATRIX_EXPRESSION.sub(replace, job.display_name)
        if EXPRESSION.search(name):
            raise WorkflowError(
                f"job {job.identifier}: unresolved GitHub expression in check name {name!r}"
            )
        # GitHub appends the sole matrix value when the job itself has no
        # expression in `name:`; that is how the floating-nightly check-runs
        # become `… (nightly)` rather than two indistinguishable names.
        if combo and not MATRIX_EXPRESSION.search(job.display_name):
            name = f"{name} ({', '.join(combo.values())})"
        names.append(name)
    return names


def taxonomy_document(workflows: list[Workflow]) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for workflow in workflows:
        for job in workflow.jobs:
            for name in check_names(job):
                entries.append(
                    {
                        "check_name": name,
                        "tier": job_tier(workflow, job),
                        "workflow": workflow.name,
                        "workflow_file": workflow.path.name,
                        "job_id": job.identifier,
                        "triggers": sorted(workflow.triggers),
                        "path_filtered": workflow.path_filtered,
                    }
                )
    entries.sort(key=lambda entry: (entry["workflow_file"], entry["check_name"]))
    workflow_view: dict[str, dict[str, Any]] = {}
    groups: dict[str, list[str]] = {}
    for entry in entries:
        view = workflow_view.setdefault(
            entry["workflow_file"],
            {"name": entry["workflow"], "triggers": entry["triggers"], "jobs": []},
        )
        view["jobs"].append(entry["check_name"])
        groups.setdefault(entry["tier"], []).append(entry["check_name"])
    return {
        "schema": SCHEMA,
        "repo": "oraclemcp",
        "note": (
            "Generated by scripts/ci_taxonomy.py from trigger-bearing GitHub Actions "
            "workflows under .github/workflows/. "
            "Do not hand-edit: run scripts/ci_taxonomy.py --write. A required "
            "job must be a completed success for a SHA to be releasable; "
            "advisory jobs never gate. `workflows` and `groups` are derived "
            "views over `jobs`, which is the single source of truth for tiers."
        ),
        "jobs": entries,
        "workflows": dict(sorted(workflow_view.items())),
        "groups": {tier: sorted(names) for tier, names in sorted(groups.items())},
    }


def validate_workflow_policy(workflows: list[Workflow]) -> None:
    errors: list[str] = []
    for workflow in workflows:
        for job in workflow.jobs:
            if job.timeout_minutes is None:
                errors.append(
                    f"{workflow.path.relative_to(ROOT)}:{job.identifier}: missing timeout-minutes"
                )
            if not workflow.has_permissions and not job.has_permissions:
                errors.append(
                    f"{workflow.path.relative_to(ROOT)}:{job.identifier}: missing explicit permissions"
                )
    if errors:
        raise WorkflowError("\n".join(errors))


def job_is_success(job: dict[str, Any]) -> bool:
    return job.get("status") == "completed" and job.get("conclusion") == "success"


def status_report(taxonomy: dict[str, Any], sha: str, runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Return the shared ci-taxonomy/v1 report for exact GitHub check-runs."""
    by_name = {job["check_name"]: job for job in taxonomy["jobs"]}
    actual_by_name = {str(run.get("name")): run for run in runs if isinstance(run.get("name"), str)}
    jobs: list[dict[str, Any]] = []
    unknown: list[str] = []
    for name, run in sorted(actual_by_name.items()):
        known = by_name.get(name)
        if known is None:
            unknown.append(name)
            continue
        jobs.append(
            {
                "name": name,
                "tier": known["tier"],
                "status": run.get("status"),
                "conclusion": run.get("conclusion"),
            }
        )

    seen = set(actual_by_name)
    absent = [
        job
        for job in taxonomy["jobs"]
        if job["tier"] == "required" and job["check_name"] not in seen
    ]
    missing_filtered = sorted(job["check_name"] for job in absent if job["path_filtered"])
    missing_unexpected = sorted(job["check_name"] for job in absent if not job["path_filtered"])
    required_not_green = sorted(
        job["name"]
        for job in jobs
        if job["tier"] == "required" and not job_is_success(job)
    )
    advisory_not_green = sorted(
        job["name"]
        for job in jobs
        if job["tier"] == "advisory" and not job_is_success(job)
    )
    ci_green = not (
        required_not_green or missing_filtered or missing_unexpected or unknown
    )
    return {
        "schema": SCHEMA,
        "sha": sha,
        "ci_green": ci_green,
        "jobs": jobs,
        "required_not_green": required_not_green,
        "required_missing_path_filtered": missing_filtered,
        "required_missing_unexpected": missing_unexpected,
        "advisory_not_green": advisory_not_green,
        "unknown_jobs": unknown,
    }


def fetch_check_runs(sha: str) -> list[dict[str, Any]]:
    completed = subprocess.run(
        [
            "gh",
            "api",
            "--paginate",
            f"repos/MuhDur/oraclemcp/commits/{sha}/check-runs?per_page=100",
            "--jq",
            ".check_runs[] | {name, status, conclusion}",
        ],
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode:
        raise WorkflowError(completed.stderr.strip() or "gh api check-runs failed")
    return [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]


def load_run_fixture(path: Path) -> tuple[str, list[dict[str, Any]]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise WorkflowError(f"{path}: fixture must be one run object")
    jobs = document.get("jobs")
    if not isinstance(jobs, list):
        raise WorkflowError(f"{path}: fixture jobs must be a list")
    return str(document.get("headSha", "fixture-sha")), jobs


def check_fixtures() -> None:
    workflow = parse_workflow(FIXTURE_DIR / "valid-workflow.yml")
    taxonomy = taxonomy_document([workflow])
    if set(taxonomy["groups"]["required"]) != {"required gate"}:
        raise WorkflowError("valid fixture did not classify its required job")
    if set(taxonomy["groups"]["advisory"]) != {"floating gate"}:
        raise WorkflowError("valid fixture did not classify its advisory job")
    if set(taxonomy["groups"]["required"]) != {"required gate"}:
        raise WorkflowError("valid fixture did not classify the push gate as required")

    projection = parse_workflow(FIXTURE_DIR / "projection-without-trigger.yml")
    if projection.triggers:
        raise WorkflowError("local projection fixture unexpectedly declared a trigger")
    if projection.jobs and projection.jobs[0].timeout_minutes is not None:
        raise WorkflowError("local projection fixture unexpectedly acquired workflow policy fields")
    triggered = [candidate for candidate in (workflow, projection) if candidate.triggers]
    if [candidate.path.name for candidate in triggered] != ["valid-workflow.yml"]:
        raise WorkflowError("a YAML file without an on: trigger entered the CI taxonomy")

    try:
        parse_workflow(FIXTURE_DIR / "invalid-duplicate-with.yml")
    except WorkflowError as error:
        if "duplicate mapping key 'with'" not in str(error):
            raise
    else:
        raise WorkflowError("duplicate with: fixture was accepted")

    required_sha, required_jobs = load_run_fixture(FIXTURE_DIR / "required-failure-run.json")
    required_failure = status_report(taxonomy, required_sha, required_jobs)
    if required_failure["ci_green"] or len(required_failure["required_not_green"]) != 1:
        raise WorkflowError("failed required job was called green")

    advisory_sha, advisory_jobs = load_run_fixture(FIXTURE_DIR / "advisory-failure-run.json")
    advisory_failure = status_report(taxonomy, advisory_sha, advisory_jobs)
    if not advisory_failure["ci_green"] or len(advisory_failure["advisory_not_green"]) != 1:
        raise WorkflowError("advisory failure did not stay separate from the required result")

    missing_sha, missing_jobs = load_run_fixture(FIXTURE_DIR / "required-missing-run.json")
    missing_required = status_report(taxonomy, missing_sha, missing_jobs)
    if missing_required["ci_green"] or missing_required["required_missing_unexpected"] != ["required gate"]:
        raise WorkflowError("missing required job was called green or not reported precisely")

    unknown_sha, unknown_jobs = load_run_fixture(FIXTURE_DIR / "unknown-check-run.json")
    unknown_check = status_report(taxonomy, unknown_sha, unknown_jobs)
    if unknown_check["ci_green"] or unknown_check["unknown_jobs"] != ["new unclassified check"]:
        raise WorkflowError("unknown check-run was called green or not reported precisely")


def check_taxonomy(workflows: list[Workflow]) -> None:
    validate_workflow_policy(workflows)
    check_fixtures()
    derived = taxonomy_document(workflows)
    if not TAXONOMY_PATH.exists():
        raise WorkflowError(
            f"{TAXONOMY_PATH.relative_to(ROOT)} is missing; run scripts/ci_taxonomy.py --write"
        )
    committed = json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))
    if committed != derived:
        raise WorkflowError(
            "committed CI taxonomy drifted from .github/workflows; "
            "run scripts/ci_taxonomy.py --write and review the diff"
        )


def write_document(document: dict[str, Any]) -> None:
    json.dump(document, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow-dir", type=Path, default=DEFAULT_WORKFLOW_DIR)
    parser.add_argument("--list", action="store_true", help="write the derived CI taxonomy JSON")
    parser.add_argument("--write", action="store_true", help="regenerate docs/ci_taxonomy.json")
    parser.add_argument("--check", action="store_true", help="fail if workflow policy or committed taxonomy drifts")
    parser.add_argument("--check-workflows", action="store_true", help="reject duplicate keys and missing permissions/timeouts")
    parser.add_argument("--check-fixtures", action="store_true", help="run offline taxonomy regression fixtures")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--status", help="evaluate all GitHub check-runs for a commit SHA")
    source.add_argument("--verify-names", help="fail if any live check-run is not classified")
    arguments = parser.parse_args()

    try:
        workflows = load_workflows(arguments.workflow_dir)
        if arguments.check_workflows:
            validate_workflow_policy(workflows)
        if arguments.check_fixtures:
            check_fixtures()
        if arguments.check:
            check_taxonomy(workflows)

        taxonomy = taxonomy_document(workflows)
        if arguments.list:
            write_document(taxonomy_document(workflows))
        elif arguments.write:
            TAXONOMY_PATH.write_text(json.dumps(taxonomy, indent=2) + "\n", encoding="utf-8")
            print(f"ci-taxonomy: wrote {TAXONOMY_PATH.relative_to(ROOT)}")
        elif arguments.status:
            report = status_report(taxonomy, arguments.status, fetch_check_runs(arguments.status))
            write_document(report)
            return 0 if report["ci_green"] else 1
        elif arguments.verify_names:
            known = {job["check_name"] for job in taxonomy["jobs"]}
            actual = {str(job.get("name")) for job in fetch_check_runs(arguments.verify_names)}
            unknown = sorted(actual - known)
            for name in sorted(actual):
                print(f"  {'OK      ' if name in known else 'UNKNOWN '} {name}")
            if unknown:
                raise WorkflowError(
                    f"{len(unknown)} check-run(s) at {arguments.verify_names[:12]} are unclassified: {', '.join(unknown)}"
                )
        elif not arguments.check_workflows and not arguments.check_fixtures and not arguments.check:
            parser.error("choose --list, --write, --check, --check-workflows, --check-fixtures, --status, or --verify-names")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ci-taxonomy: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
