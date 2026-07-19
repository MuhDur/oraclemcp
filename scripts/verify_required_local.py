#!/usr/bin/env python3
"""Run the local Required graph and emit a self-validating required-proof/v1.

The graph is derived from `.github/required/_quality.yml`, not copied here.
Every workflow step and condition must be classified below.  An unfamiliar step,
action, or condition is a hard error: silently omitting a newly required gate
would make the proof less strict exactly when CI became stricter.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
QUALITY_WORKFLOW = ROOT / ".github/required/_quality.yml"
RESOURCE_BUDGET = ROOT / "scripts/resource_budget.sh"
VALIDATOR = ROOT / "scripts/validate_evidence.py"

META_STEPS = {
    "Validate inputs",
    "Select budget",
    "Forced evidence failure",
    "Show selected target",
}
ALLOWED_ACTION_PREFIXES = (
    "actions/checkout@",
    "dtolnay/rust-toolchain@",
    "Swatinem/rust-cache@",
    "taiki-e/install-action@",
)
CONDITIONS = {
    "": True,
    "${{ inputs.force_failure }}": False,
    "${{ inputs.profile != 'canary' }}": True,
    "${{ inputs.profile == 'release-qualification' }}": False,
    "${{ inputs.profile == 'soak' || inputs.profile == 'release-qualification' }}": False,
    "${{ steps.budget.outputs.package == 'true' }}": False,
    "${{ steps.budget.outputs.fuzz_seconds != '0' }}": False,
}


class ContractError(RuntimeError):
    """The workflow cannot be translated without weakening the local proof."""


@dataclass
class Step:
    name: str
    condition: str = ""
    uses: str | None = None
    run: str | None = None
    shell: str | None = None
    working_directory: str | None = None
    has_environment: bool = False


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def command_output(argv: list[str]) -> str:
    try:
        return subprocess.check_output(argv, cwd=ROOT, text=True, stderr=subprocess.STDOUT).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"


def parse_quality_steps(text: str) -> list[Step]:
    """Parse the deliberately small YAML subset used by `jobs.quality.steps`.

    A dependency on a general YAML parser would make the proof depend on ambient
    Python packages.  This parser accepts only the workflow shape we audit and
    fails if it changes beyond that shape.
    """

    steps: list[Step] = []
    current: Step | None = None
    collecting_run = False
    run_lines: list[str] = []
    in_steps = False

    def finish_current() -> None:
        nonlocal current, collecting_run, run_lines
        if current is not None:
            if collecting_run:
                current.run = "\n".join(run_lines).strip()
            steps.append(current)
        current = None
        collecting_run = False
        run_lines = []

    for raw in text.splitlines():
        if raw == "    steps:":
            in_steps = True
            continue
        if not in_steps:
            continue
        if raw and not raw.startswith("      "):
            finish_current()
            break

        start = re.match(r"^      - (?:(?:name: (?P<name>.+))|(?:uses: (?P<uses>.+)))$", raw)
        if start:
            finish_current()
            uses = start.group("uses")
            current = Step(name=start.group("name") or f"uses: {uses}", uses=uses)
            continue
        if current is None:
            continue
        if collecting_run:
            if raw.startswith("          "):
                run_lines.append(raw[10:])
                continue
            current.run = "\n".join(run_lines).strip()
            collecting_run = False
            run_lines = []

        field = re.match(
            r"^        (?P<key>name|if|uses|run|shell|working-directory|env|id|with):(?P<value>.*)$",
            raw,
        )
        if not field:
            if raw.startswith("        ") and not raw.startswith("          "):
                raise ContractError(f"{current.name}: unclassified workflow field {raw.strip()!r}")
            continue
        key, value = field.group("key"), field.group("value").strip()
        if key == "name":
            current.name = value
        elif key == "if":
            current.condition = value
        elif key == "uses":
            current.uses = value
            if current.name.startswith("uses: "):
                current.name = f"uses: {value}"
        elif key == "run":
            if value == "|":
                collecting_run = True
            elif value:
                current.run = value
            else:
                raise ContractError(f"{current.name}: empty run field")
        elif key == "shell":
            current.shell = value
        elif key == "working-directory":
            current.working_directory = value
        elif key == "env":
            current.has_environment = True
    finish_current()
    if not steps:
        raise ContractError("could not find jobs.quality.steps in _quality.yml")
    return steps


def effective_plan(workflow: Path = QUALITY_WORKFLOW) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for step in parse_quality_steps(workflow.read_text()):
        if step.condition not in CONDITIONS:
            raise ContractError(f"{step.name}: unclassified condition {step.condition!r}")
        enabled = CONDITIONS[step.condition]
        record: dict[str, object] = {
            "name": step.name,
            "condition": step.condition or None,
            "enabled_for_required": enabled,
        }
        if step.name in META_STEPS:
            record["classification"] = "ci-meta"
            record["reason"] = "github-expression-or-reporting-step-is-not-a-quality-gate"
        elif step.uses is not None:
            if not step.uses.startswith(ALLOWED_ACTION_PREFIXES):
                raise ContractError(f"{step.name}: unclassified setup action {step.uses!r}")
            record["classification"] = "setup-action"
            record["reason"] = "local-runner-uses-existing-checkout-toolchain-and-cache"
        elif step.run is None:
            if step.name not in META_STEPS:
                raise ContractError(f"{step.name}: neither a classified action nor a runnable command")
            record["classification"] = "ci-meta"
            record["reason"] = "github-expression-or-reporting-step-has-no-local-command"
        elif not enabled:
            record["classification"] = "profile-excluded"
            record["reason"] = "condition-is-false-for-profile-required"
        elif step.shell not in (None, "bash"):
            raise ContractError(f"{step.name}: unsupported active shell {step.shell!r}")
        elif step.working_directory is not None:
            raise ContractError(
                f"{step.name}: active working-directory {step.working_directory!r} is not yet replayable"
            )
        elif step.has_environment:
            raise ContractError(f"{step.name}: active environment block is not yet replayable")
        else:
            record["classification"] = "required-command"
            record["argv"] = ["bash", "-lc", step.run]
        entries.append(record)
    if not any(row["classification"] == "required-command" for row in entries):
        raise ContractError("required profile has no executable commands")
    return entries


def git_clean() -> bool:
    return subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, text=True, capture_output=True).stdout == ""


def git_sha() -> str:
    return command_output(["git", "rev-parse", "HEAD"])


def default_output(sha: str) -> Path:
    return ROOT / "tests/artifacts/evidence/required" / f"required-proof-{sha}.json"


def source_ref(sha: str, branch: str) -> dict[str, object]:
    source: dict[str, object] = {"sha": sha, "tree_clean": True}
    if branch:
        source["branch"] = branch
    return source


def emitted_budget(run_id: str) -> dict[str, object]:
    raw = subprocess.check_output(
        [str(RESOURCE_BUDGET), "--profile", "test", "--run-id", run_id, "--emit-budget"],
        cwd=ROOT,
        text=True,
    )
    return json.loads(raw)


def run_required(plan: list[dict[str, object]], sha: str, output: Path, run_id: str) -> int:
    commands: list[dict[str, object]] = []
    logs = output.parent / "logs" / sha
    logs.mkdir(parents=True, exist_ok=True)

    for row in plan:
        if row["classification"] != "required-command":
            continue
        argv = row["argv"]
        assert isinstance(argv, list)
        started = utc_now()
        try:
            completed = subprocess.run(argv, cwd=ROOT, text=True, capture_output=True, check=False)
            outcome = "pass" if completed.returncode == 0 else "fail"
            exit_code: int | None = completed.returncode
            output_text = completed.stdout + completed.stderr
        except FileNotFoundError as exc:
            outcome = "skip"
            exit_code = None
            output_text = str(exc)
        (logs / f"{str(row['name']).lower().replace(' ', '-')}.log").write_text(output_text)
        record: dict[str, object] = {
            "id": str(row["name"]).lower().replace(" ", "-").replace("/", "-"),
            "tier": "required",
            "argv": argv,
            "sha": sha,
            "outcome": outcome,
            "exit_code": exit_code,
            "started_at": started,
            "ended_at": utc_now() if outcome != "skip" else None,
        }
        if outcome == "skip":
            record["skip_reason"] = "required-tool-unavailable"
        commands.append(record)

    commands.append(
        {
            "id": "live-matrix",
            "tier": "advisory",
            "argv": ["scripts/version_matrix.sh", "full", "all"],
            "sha": sha,
            "outcome": "skip",
            "skip_reason": "not-run-by-required-local",
            "exit_code": None,
            "started_at": utc_now(),
            "ended_at": None,
        }
    )
    verdict = "pass" if all(c["outcome"] == "pass" for c in commands if c["tier"] == "required") else "fail"
    proof = {
        "schema": "required-proof/v1",
        "repo": "oraclemcp",
        "generated_at": utc_now(),
        "source": source_ref(sha, command_output(["git", "branch", "--show-current"])),
        "tool_versions": {
            "rustc": command_output(["rustc", "--version"]),
            "cargo": command_output(["cargo", "--version"]),
            "cargo-deny": command_output(["cargo-deny", "--version"]),
            "runner": "scripts/verify_required_local.py",
        },
        "resource_budget": emitted_budget(run_id),
        "commands": commands,
        "verdict": verdict,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(proof, indent=2) + "\n")
    validated = subprocess.run([sys.executable, str(VALIDATOR), str(output), "--json"], cwd=ROOT, check=False)
    if validated.returncode != 0:
        return validated.returncode
    print(f"required-proof: wrote {output} (verdict={verdict})")
    return 0 if verdict == "pass" else 1


def self_test() -> None:
    sha = "0" * 40
    assert source_ref(sha, "") == {"sha": sha, "tree_clean": True}
    assert source_ref(sha, "main")["branch"] == "main"
    unknown = "jobs:\n  quality:\n    steps:\n      - name: New required gate\n        run: echo hi\n        if: ${{ inputs.not_known }}\n"
    try:
        parse_quality_steps(unknown)
        # Parsing is deliberately separate from classification.
        if "${{ inputs.not_known }}" not in CONDITIONS:
            raise ContractError("New required gate: unclassified condition '${{ inputs.not_known }}'")
    except ContractError:
        pass
    else:
        raise AssertionError("unknown conditions must fail closed")
    unknown_action = "jobs:\n  quality:\n    steps:\n      - uses: unreviewed/new-action@v1\n"
    try:
        for step in parse_quality_steps(unknown_action):
            if step.uses is not None and not step.uses.startswith(ALLOWED_ACTION_PREFIXES):
                raise ContractError(f"{step.name}: unclassified setup action {step.uses!r}")
    except ContractError:
        pass
    else:
        raise AssertionError("unknown setup actions must fail closed")
    print("verify-required-local: self-test OK")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument("--internal", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0
    plan = effective_plan()
    if args.plan:
        print(json.dumps({"profile": "required", "steps": plan}, indent=2))
        return 0

    sha = git_sha()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ContractError(f"could not resolve an exact HEAD SHA: {sha!r}")
    output = args.output or default_output(sha)
    run_id = args.run_id or f"required-{sha[:12]}"

    if not args.internal:
        command = [
            str(RESOURCE_BUDGET),
            "--profile",
            "test",
            "--run-id",
            run_id,
            "--",
            sys.executable,
            str(Path(__file__).resolve()),
            "--internal",
            "--run-id",
            run_id,
            "--output",
            str(output),
        ]
        return subprocess.run(command, cwd=ROOT, check=False).returncode

    if not git_clean():
        print(
            "required-proof: REFUSING to run on a dirty tree; use a detached clean worktree at HEAD "
            "so every command and the emitted source.sha describe the same code",
            file=sys.stderr,
        )
        return 78
    return run_required(plan, sha, output, run_id)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractError as exc:
        print(f"required-proof: {exc}", file=sys.stderr)
        raise SystemExit(2)
