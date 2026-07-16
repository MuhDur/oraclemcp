#!/usr/bin/env bash
# DB-free contract tests for the required-proof local runner.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="$ROOT/scripts/verify_required_local.sh"

"$RUNNER" --self-test
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
