#!/usr/bin/env python3
"""D4 — a step must not use a tool the job has not installed YET.

This exists because the same bug bit the driver repo twice.

  1. `EXPECTED_QUALITY_COMMANDS` widened what the local replay treated as
     "required" to include tool-INSTALL steps. Those steps read pinned versions
     from a workflow-level `env:` the replay never applied, so they ran as
     `cargo install <tool> --version "" --locked` and clap rejected them. The
     release-qualification proof failed with a tag already in flight.
  2. Later, a fixture needing ripgrep was placed in a step that runs BEFORE
     ripgrep is installed.

Both are the same mistake in different clothes: widening or reordering the set
of steps that must work, without enumerating what those steps DEPEND ON. The
first instance is guarded by `verify_required_local.py` (it now refuses a
workflow- or job-level `env:` and any `${{ }}` in a required run). This guards
the second: within a job, the step that USES a tool must come after the step
that PROVIDES it.

Deliberately narrow, because a broad "does this command exist" checker would be
a false-positive generator. It reasons only about tools the workflow installs
for itself, plus a small watchlist of tools that are NOT present on a stock
GitHub runner and are therefore easy to assume.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Tools a stock ubuntu-latest runner does NOT provide, so using one without an
# install step in the same job is a bug even if it never reorders.
NOT_PREINSTALLED = {
    "rg": "ripgrep",
    "ripgrep": "ripgrep",
    "shellcheck": "shellcheck",
    "cargo-llvm-cov": "cargo-llvm-cov",
    "cargo-hack": "cargo-hack",
    "cargo-deny": "cargo-deny",
    "cargo-fuzz": "cargo-fuzz",
    "cargo-public-api": "cargo-public-api",
    "cargo-semver-checks": "cargo-semver-checks",
}

# `cargo <sub>` invocations that require an installed cargo-<sub> binary.
CARGO_SUBCOMMAND_TOOLS = {
    "llvm-cov": "cargo-llvm-cov",
    "hack": "cargo-hack",
    "deny": "cargo-deny",
    "fuzz": "cargo-fuzz",
    "public-api": "cargo-public-api",
    "semver-checks": "cargo-semver-checks",
}


class Step:
    def __init__(self, job: str, index: int, line: int) -> None:
        self.job = job
        self.index = index
        self.line = line
        self.provides: set[str] = set()
        self.uses: set[str] = set()


def parse_jobs(text: str) -> dict[str, list[Step]]:
    """A deliberately small reader for the shapes this workflow actually uses."""
    jobs: dict[str, list[Step]] = {}
    job = None
    step: Step | None = None
    in_steps = False
    step_index = 0

    for number, raw in enumerate(text.splitlines(), start=1):
        job_match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", raw)
        if job_match:
            job = job_match.group(1)
            jobs[job] = []
            in_steps = False
            step = None
            step_index = 0
            continue
        if job is None:
            continue
        if re.match(r"^    steps:\s*$", raw):
            in_steps = True
            continue
        if not in_steps:
            continue
        if re.match(r"^      - ", raw):
            step_index += 1
            step = Step(job, step_index, number)
            jobs[job].append(step)

        if step is None:
            continue

        # A COMMENT IS NOT A CALL. Without this the block of prose that
        # introduces the next job gets attributed to the previous job's last
        # step, and the lint files "uses cargo-deny, never installed" against a
        # step that runs `bash scripts/provenance_check.sh`. The first run of
        # this lint produced exactly four such findings, all of them prose.
        if raw.lstrip().startswith("#"):
            continue

        # What the step PROVIDES.
        tool_match = re.search(r"^\s+tool:\s*(.+?)\s*$", raw)
        if tool_match:
            for tool in tool_match.group(1).split(","):
                step.provides.add(tool.strip())
        apt_match = re.search(r"apt-get install[^\n]*", raw)
        if apt_match:
            for word in apt_match.group(0).split()[3:]:
                if not word.startswith("-"):
                    step.provides.add(word)
        install_match = re.search(r"cargo install\s+([A-Za-z0-9_-]+)", raw)
        if install_match:
            step.provides.add(install_match.group(1))

        # What the step USES. Only bare invocations count: a word inside a
        # longer path or a comment is not a call.
        for token, _package in NOT_PREINSTALLED.items():
            if re.search(rf"(?<![\w/-]){re.escape(token)}\b", raw) and "install" not in raw:
                step.uses.add(token)
        for sub, tool in CARGO_SUBCOMMAND_TOOLS.items():
            if re.search(rf"(?<![\w-])cargo\s+{re.escape(sub)}\b", raw):
                step.uses.add(tool)

    return jobs


def validate(jobs: dict[str, list[Step]]) -> list[str]:
    findings: list[str] = []
    for job, steps in jobs.items():
        provided_at: dict[str, int] = {}
        for step in steps:
            for tool in step.provides:
                provided_at.setdefault(tool, step.index)
        for step in steps:
            for tool in sorted(step.uses):
                package = NOT_PREINSTALLED.get(tool, tool)
                if tool in step.provides or package in step.provides:
                    continue
                where = provided_at.get(tool, provided_at.get(package))
                if where is None:
                    findings.append(
                        f"E_TOOL_NEVER_INSTALLED: job {job!r} step #{step.index} (line {step.line}) "
                        f"uses {tool!r}, which no step in that job installs and a stock runner does "
                        f"not provide"
                    )
                elif where > step.index:
                    findings.append(
                        f"E_TOOL_USED_BEFORE_INSTALL: job {job!r} step #{step.index} (line {step.line}) "
                        f"uses {tool!r}, but the step that installs it is #{where} — later in the same job"
                    )
    return findings


def selftest() -> int:
    failures = 0

    def expect(label: str, yaml: str, code: str | None) -> None:
        nonlocal failures
        found = validate(parse_jobs(yaml))
        if code is None:
            if found:
                print(f"selftest: {label}: well-formed workflow REJECTED: {found}", file=sys.stderr)
                failures += 1
            return
        if not any(f.startswith(code) for f in found):
            print(f"selftest: {label}: expected {code}, got {found or 'no findings'}", file=sys.stderr)
            failures += 1

    ordered = """
jobs:
  good:
    steps:
      - uses: taiki-e/install-action@v2
        with:
          tool: cargo-deny
      - run: cargo deny check
"""
    # The accept case first: a checker that flags everything is as useless as
    # one that flags nothing.
    expect("install before use", ordered, None)

    reordered = """
jobs:
  bad:
    steps:
      - run: cargo deny check
      - uses: taiki-e/install-action@v2
        with:
          tool: cargo-deny
"""
    expect("use before install", reordered, "E_TOOL_USED_BEFORE_INSTALL")

    # The exact second incident: a fixture step needing ripgrep placed before
    # (here: without) the install.
    missing = """
jobs:
  bad:
    steps:
      - run: rg --files > fixture.txt
"""
    expect("ripgrep never installed", missing, "E_TOOL_NEVER_INSTALLED")

    # THE FALSE-POSITIVE GUARD. Prose naming a tool is not an invocation of it,
    # and workflow files are full of comments explaining which job does what.
    commented = """
jobs:
  good:
    steps:
      - run: bash scripts/provenance_check.sh
  # The next job runs cargo-deny and cargo-fuzz; this sentence must not count
  # as a use of either.
  other:
    steps:
      - uses: taiki-e/install-action@v2
        with:
          tool: cargo-deny
      - run: cargo deny check
"""
    expect("a comment naming a tool is not a use", commented, None)

    ripgrep_ordered = """
jobs:
  good:
    steps:
      - run: sudo apt-get install -y ripgrep
      - run: rg --files > fixture.txt
"""
    expect("ripgrep installed first", ripgrep_ordered, None)

    if failures:
        print("ci_step_tool_order_lint selftest: FAIL", file=sys.stderr)
        return 1
    print("ci_step_tool_order_lint selftest: OK (use-before-install and never-installed are both rejected; correct ordering is accepted)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", type=Path, action="append", default=None)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    if args.selftest:
        return selftest()

    workflows = args.workflow or sorted(Path(".github/workflows").glob("*.yml"))
    findings: list[str] = []
    for path in workflows:
        for finding in validate(parse_jobs(path.read_text(encoding="utf-8"))):
            findings.append(f"{path}: {finding}")

    if not findings:
        print(f"PASS ci_step_tool_order_lint: {len(workflows)} workflow(s), no step uses a tool its job installs later")
        return 0
    for finding in findings:
        print(f"  {finding}")
    print(f"FAIL ci_step_tool_order_lint: {len(findings)} finding(s)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
