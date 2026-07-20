#!/usr/bin/env python3
"""Deterministic DB-free contract test for the mutation shard sealer."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]


def mutant(name: str, line: int) -> dict:
    return {
        "Mutant": {
            "name": name,
            "file": "src/lib.rs",
            "span": {"start": {"line": line}},
        }
    }


def scope_state(scope: str, source_sha: str) -> tuple[int, str]:
    roots = {
        "guard": "crates/oraclemcp-guard/src",
        "audit": "crates/oraclemcp-audit/src",
        "db": "crates/oraclemcp-db/src",
    }
    paths = subprocess.check_output(
        ["git", "ls-tree", "-r", "--name-only", source_sha, "--", roots[scope]],
        cwd=root,
        text=True,
    ).splitlines()
    paths = sorted(path for path in paths if path.endswith(".rs"))
    digest = hashlib.sha256()
    for path in paths:
        content = subprocess.check_output(
            ["git", "show", f"{source_sha}:{path}"], cwd=root
        )
        digest.update(path.encode())
        digest.update(b"\0")
        digest.update(hashlib.sha256(content).hexdigest().encode())
        digest.update(b"\n")
    return len(paths), digest.hexdigest()


# Do not clean this directory: the repository contract forbids test cleanup
# without an explicit operator command. It also makes a failed test inspectable.
workdir = Path(tempfile.mkdtemp(prefix="oraclemcp-mutation-result-", dir="/var/tmp"))
baseline_command = ["cargo", "test", "--package=example@0.1.0", "baseline"]
outcomes_document = {
    "start_time": "2026-01-01T00:00:00Z",
    "end_time": "2026-01-01T00:01:00Z",
    "caught": 1,
    "missed": 1,
    "timeout": 1,
    "unviable": 0,
    "outcomes": [
        {
            "scenario": "Baseline",
            "phase_results": [
                {
                    "phase": "Test",
                    "process_status": "Success",
                    "argv": baseline_command,
                }
            ],
        },
        {
            "scenario": mutant("caught", 4),
            "summary": "CaughtMutant",
            "phase_results": [
                {
                    "phase": "Test",
                    "process_status": "Failure",
                    "argv": ["cargo", "test", "--package=example@0.1.0", "caught"],
                }
            ],
        },
        {
            "scenario": mutant("missed", 8),
            "summary": "MissedMutant",
            "phase_results": [
                {
                    "phase": "Test",
                    "process_status": "Success",
                    "argv": ["cargo", "test", "--package=example@0.1.0", "missed"],
                }
            ],
        },
        {
            "scenario": mutant("timeout", 12),
            "summary": "Timeout",
            "phase_results": [
                {
                    "phase": "Test",
                    "process_status": "Timeout",
                    "argv": ["cargo", "test", "--package=example@0.1.0", "timeout"],
                }
            ],
        },
    ],
}
outcomes = workdir / "outcomes.json"
outcomes.write_text(json.dumps(outcomes_document))
integrity_document = {
    "schema": "mutation-shard-integrity/v1",
    "scope": "fixture",
    "shard_index": 1,
    "shard_total": 1,
    "status": "complete",
    "source_sha": None,
    "covered_file_count": 1,
    "scope_sha256": "0" * 64,
    "campaign_mutant_total": 3,
    "mutant_count": 3,
    "mutant_ids": ["caught", "missed", "timeout"],
    "outcomes_sha256": hashlib.sha256(outcomes.read_bytes()).hexdigest(),
    "oom_kill_delta": 0,
    "command_exit": 1,
    "memory_max_bytes": 8_589_934_592,
    "pid_task_max": 8_192,
    "pid_max_delta": 0,
    "oom_policy": "continue",
    "cargo_mutants_version": "cargo-mutants fixture",
    "scratch_path": "/var/tmp/oraclemcp-mutation-result-scratch",
    "scratch_filesystem": "ext4",
    "rustc_wrapper_disabled": True,
}
budget = workdir / "budget.json"
budget.write_text(
    json.dumps(
        {
            "isolated_target_dir": "/var/tmp/oraclemcp-mutation-result-target",
            "memory_max_bytes": 8_589_934_592,
            "pid_task_max": 8_192,
        }
    )
)
output = workdir / "result.json"
sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
integrity_document["source_sha"] = sha
integrity = workdir / "integrity.json"
integrity.write_text(json.dumps(integrity_document))
subprocess.run(
    [
        sys.executable,
        str(root / "scripts/migrate_mutation_result.py"),
        "--outcomes",
        str(outcomes),
        "--integrity",
        str(integrity),
        "--source-sha",
        sha,
        "--scope-target",
        "src/lib.rs",
        "--description",
        "fixture archive conversion",
        "--resource-budget",
        str(budget),
        "--output",
        str(output),
        "--generated-at",
        "2026-01-01T00:02:00Z",
    ],
    check=True,
)
subprocess.run(
    [sys.executable, str(root / "scripts/validate_evidence.py"), str(output)],
    check=True,
)
result = json.loads(output.read_text())
assert result["counts"] == {"caught": 1, "missed": 1, "timeout": 1, "unviable": 0}
assert result["denominator"] == "caught+missed+timeout"
assert result["rate"] == 1 / 3
assert len(result["kills"]) == 1
assert result["kills"][0]["mutant_fails_test"]["outcome"] == "fail"
assert result["kills"][0]["head_passes_test"] == {
    "test": "cargo test --package=example@0.1.0 baseline",
    "outcome": "pass",
}
assert result["survivors"] == [
    {
        "mutant_id": "missed",
        "location": "src/lib.rs:8",
        "taxonomy": "triage-pending",
        "note": (
            "Archived cargo-mutants output records this survivor but not its campaign "
            "adjudication; retained explicitly rather than inventing an equivalence claim."
        ),
    }
]

for label, extra_arguments in [("invalid-sha", ["--source-sha", "not-a-sha"])]:
    rejected_output = workdir / f"{label}.json"
    command = [
        sys.executable,
        str(root / "scripts/migrate_mutation_result.py"),
        "--outcomes",
        str(outcomes),
        "--integrity",
        str(integrity),
        "--source-sha",
        sha,
        "--scope-target",
        "src/lib.rs",
        "--description",
        "rejection fixture",
        "--resource-budget",
        str(budget),
        "--output",
        str(rejected_output),
        *extra_arguments,
    ]
    rejected = subprocess.run(command, capture_output=True, text=True)
    assert rejected.returncode == 2, rejected.stderr
    assert not rejected_output.exists()


def run_rejection(label: str, changed_integrity: dict, expected: str) -> None:
    rejected_integrity = workdir / f"{label}-integrity.json"
    rejected_integrity.write_text(json.dumps(changed_integrity))
    rejected_output = workdir / f"{label}.json"
    rejected = subprocess.run(
        [
            sys.executable,
            str(root / "scripts/migrate_mutation_result.py"),
            "--outcomes",
            str(outcomes),
            "--integrity",
            str(rejected_integrity),
            "--source-sha",
            sha,
            "--scope-target",
            "src/lib.rs",
            "--description",
            "rejection fixture",
            "--resource-budget",
            str(budget),
            "--output",
            str(rejected_output),
        ],
        capture_output=True,
        text=True,
    )
    assert rejected.returncode == 1, rejected.stderr
    assert expected in rejected.stderr, rejected.stderr
    assert not rejected_output.exists()


oom_integrity = dict(integrity_document)
oom_integrity.update(status="errored", oom_kill_delta=1)
run_rejection("oom", oom_integrity, "E_OOM_MUTANT")

pid_integrity = dict(integrity_document)
pid_integrity.update(status="errored", pid_max_delta=1)
run_rejection("task-cap", pid_integrity, "E_TASK_CAP")

missing_shard_integrity = dict(integrity_document)
missing_shard_integrity.update(shard_total=2, campaign_mutant_total=6)
run_rejection("missing-shard", missing_shard_integrity, "E_SHARD_INCOMPLETE")

unfinished_document = dict(outcomes_document)
unfinished_document["end_time"] = None
unfinished_outcomes = workdir / "unfinished-outcomes.json"
unfinished_outcomes.write_text(json.dumps(unfinished_document))
unfinished_integrity = dict(integrity_document)
unfinished_integrity["outcomes_sha256"] = hashlib.sha256(
    unfinished_outcomes.read_bytes()
).hexdigest()
unfinished_integrity_path = workdir / "unfinished-integrity.json"
unfinished_integrity_path.write_text(json.dumps(unfinished_integrity))
unfinished_output = workdir / "unfinished.json"
unfinished = subprocess.run(
    [
        sys.executable,
        str(root / "scripts/migrate_mutation_result.py"),
        "--outcomes",
        str(unfinished_outcomes),
        "--integrity",
        str(unfinished_integrity_path),
        "--source-sha",
        sha,
        "--scope-target",
        "src/lib.rs",
        "--description",
        "unfinished fixture",
        "--resource-budget",
        str(budget),
        "--output",
        str(unfinished_output),
    ],
    capture_output=True,
    text=True,
)
assert unfinished.returncode == 1, unfinished.stderr
assert "unfinished archived outcomes" in unfinished.stderr
assert not unfinished_output.exists()

# End-to-end D2 path: three complete exact-SHA scope shards -> raw
# mutation-result/v1 + compact floor report -> current-tree floor checker.
d2_outcomes: list[Path] = []
d2_integrities: list[Path] = []
for scope_index, scope in enumerate(("guard", "audit", "db"), start=1):
    scope_mutant = mutant(f"{scope}-caught", scope_index)
    scope_outcomes_document = {
        "start_time": f"2026-01-01T00:0{scope_index}:00Z",
        "end_time": f"2026-01-01T00:0{scope_index}:30Z",
        "caught": 1,
        "missed": 0,
        "timeout": 0,
        "unviable": 0,
        "outcomes": [
            {
                "scenario": "Baseline",
                "phase_results": [
                    {
                        "phase": "Test",
                        "process_status": "Success",
                        "argv": baseline_command,
                    }
                ],
            },
            {
                "scenario": scope_mutant,
                "summary": "CaughtMutant",
                "phase_results": [
                    {
                        "phase": "Test",
                        "process_status": "Failure",
                        "argv": [
                            "cargo",
                            "test",
                            "--package=example@0.1.0",
                            f"{scope}-caught",
                        ],
                    }
                ],
            },
        ],
    }
    scope_outcomes = workdir / f"d2-{scope}-outcomes.json"
    scope_outcomes.write_text(json.dumps(scope_outcomes_document))
    covered_file_count, scope_sha256 = scope_state(scope, sha)
    scope_integrity_document = dict(integrity_document)
    scope_integrity_document.update(
        scope=scope,
        covered_file_count=covered_file_count,
        scope_sha256=scope_sha256,
        campaign_mutant_total=1,
        mutant_count=1,
        mutant_ids=[f"{scope}-caught"],
        outcomes_sha256=hashlib.sha256(scope_outcomes.read_bytes()).hexdigest(),
    )
    scope_integrity = workdir / f"d2-{scope}-integrity.json"
    scope_integrity.write_text(json.dumps(scope_integrity_document))
    d2_outcomes.append(scope_outcomes)
    d2_integrities.append(scope_integrity)

d2_output = workdir / "d2-result.json"
d2_report = workdir / "d2-report.md"
d2_command = [sys.executable, str(root / "scripts/migrate_mutation_result.py")]
for scope_outcomes, scope_integrity in zip(d2_outcomes, d2_integrities, strict=True):
    d2_command.extend(["--outcomes", str(scope_outcomes), "--integrity", str(scope_integrity)])
d2_command.extend(
    [
        "--source-sha",
        sha,
        "--scope-target",
        "crates/oraclemcp-guard/src/**/*.rs",
        "--scope-target",
        "crates/oraclemcp-audit/src/**/*.rs",
        "--scope-target",
        "crates/oraclemcp-db/src/**/*.rs",
        "--required-scope",
        "guard",
        "--required-scope",
        "audit",
        "--required-scope",
        "db",
        "--description",
        "D2 exact-SHA floor fixture",
        "--resource-budget",
        str(budget),
        "--output",
        str(d2_output),
        "--floor-report",
        str(d2_report),
        "--floor",
        "guard=90",
        "--floor",
        "audit=90",
        "--floor",
        "db=90",
        "--generated-at",
        "2026-01-01T00:05:00Z",
    ]
)
subprocess.run(d2_command, check=True)
subprocess.run(
    [sys.executable, str(root / "scripts/validate_evidence.py"), str(d2_output)],
    check=True,
)
subprocess.run(
    [
        "bash",
        str(root / "scripts/mutation_safety_gate.sh"),
        "check-floor-report",
        "--report",
        str(d2_report),
    ],
    check=True,
)
print(f"migrate-mutation-result: contract OK ({workdir})")
