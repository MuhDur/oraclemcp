#!/usr/bin/env bash
# DB-free contract tests for the required-proof local runner.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="$ROOT/scripts/verify_required_local.sh"

"$RUNNER" --self-test
PYTHONPATH="$ROOT" python3 - <<'PY'
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
import scripts.verify_required_local as runner
from scripts.verify_required_local import (
    ContractError,
    command_graph_commitment,
    default_output,
    effective_plan,
    expected_command_records,
    parse_required_policy_ids,
    parse_required_policy_graph_sha256,
    required_command_ids,
    required_graph_sha256,
    validate_command_coverage,
)

sha = f"{os.getpid():040x}"
plan = effective_plan()
expected = expected_command_records(plan)
graph = command_graph_commitment(plan)
assert graph["command_ids"] == sorted(expected)
canonical = json.dumps(graph["command_ids"], ensure_ascii=False, separators=(",", ":"))
assert graph["sha256"] == hashlib.sha256(canonical.encode()).hexdigest()

commands = [
    {"id": identifier, "tier": record["tier"], "argv": record["argv"]}
    for identifier, record in expected.items()
]
validate_command_coverage(commands, plan)
for mutation in (commands[1:], [{**commands[0], "argv": ["true"]}, *commands[1:]]):
    try:
        validate_command_coverage(mutation, plan)
    except ContractError:
        pass
    else:
        raise AssertionError("fabricated Required graph was accepted")

policy = parse_required_policy_ids(runner.CI_WORKFLOW.read_text(encoding="utf-8"))
assert required_command_ids(plan) == policy
assert required_graph_sha256(plan) == parse_required_policy_graph_sha256(
    runner.CI_WORKFLOW.read_text(encoding="utf-8")
)
with tempfile.TemporaryDirectory() as scratch:
    weakened_projection = Path(scratch) / "_quality.yml"
    projection_text = runner.QUALITY_WORKFLOW.read_text(encoding="utf-8")
    weakened_projection.write_text(
        projection_text.replace(
            "      - name: Supply-chain checks\n        run: cargo deny check\n",
            "",
        ),
        encoding="utf-8",
    )
    weakened_commands = [
        command for command in commands if command["id"] != "supply-chain-checks"
    ]
    assert len(weakened_commands) == len(commands) - 1
    try:
        weakened_plan = effective_plan(weakened_projection)
        validate_command_coverage(weakened_commands, weakened_plan)
    except ContractError as error:
        assert "projection missing supply-chain-checks" in str(error), error
    else:
        raise AssertionError("projection+proof weakening escaped the independent CI policy")

    weakened_argv_projection = Path(scratch) / "_quality-argv.yml"
    weakened_argv_projection.write_text(
        projection_text.replace("        run: cargo deny check\n", "        run: 'true'\n"),
        encoding="utf-8",
    )
    weakened_argv_commands = [
        {
            **command,
            "argv": ["bash", "-lc", "'true'"]
            if command["id"] == "supply-chain-checks"
            else command["argv"],
        }
        for command in commands
    ]
    try:
        weakened_plan = effective_plan(weakened_argv_projection)
        validate_command_coverage(weakened_argv_commands, weakened_plan)
    except ContractError as error:
        assert "argv differs from CI-owned graph SHA-256" in str(error), error
    else:
        raise AssertionError("projection+proof argv weakening escaped the independent CI policy")

path = default_output(sha)
assert "target/release-evidence/required" in path.as_posix()
before = subprocess.check_output(["git", "status", "--porcelain"], text=True)
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text("default handoff probe\n")
after = subprocess.check_output(["git", "status", "--porcelain"], text=True)
assert after == before, "default required-proof output dirtied the source tree"
assert subprocess.run(["git", "check-ignore", "-q", str(path)], check=False).returncode == 0

synthetic_plan = [{
    "name": "Synthetic Required",
    "condition": None,
    "enabled_for_required": True,
    "classification": "required-command",
    "argv": ["true"],
}]
runner.command_output = lambda _argv: "test-tool"
runner.emitted_budget = lambda _run_id: {
    "isolated_target_dir": "/tmp/required-proof-test-target",
    "memory_max_bytes": 1073741824,
    "pid_task_max": 64,
}
assert runner.run_required(synthetic_plan, sha, path, "required-proof-test") == 0
proof = json.loads(path.read_text())
assert proof["schema"] == "required-proof/v2"
assert proof["command_graph"] == command_graph_commitment(synthetic_plan)
assert subprocess.check_output(["git", "status", "--porcelain"], text=True) == before
print("verify-required-local: v2 command graph and ignored default handoff OK")
PY
"$RUNNER" --policy-check
"$RUNNER" --plan | python3 -c '
import json
import sys

plan = json.load(sys.stdin)["steps"]
commands = {item["name"] for item in plan if item["classification"] == "required-command"}
assert {"Format", "Clippy", "Test workspace", "Surface sync", "Seam lint", "Honesty grep", "API lock", "Supply-chain checks"} <= commands, commands
assert all(item["classification"] != "profile-excluded" or item["enabled_for_required"] is False for item in plan)
assert any(item["name"] == "Live matrix" and item["classification"] == "profile-excluded" for item in plan)
print("verify-required-local: plan contains every active Required gate")
'
