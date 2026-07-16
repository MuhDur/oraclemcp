#!/usr/bin/env python3
"""Deterministic DB-free contract test for the archive converter."""
from __future__ import annotations

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
subprocess.run(
    [
        sys.executable,
        str(root / "scripts/migrate_mutation_result.py"),
        "--outcomes",
        str(outcomes),
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
print(f"migrate-mutation-result: contract OK ({workdir})")
