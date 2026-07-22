#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$(mktemp -d /var/tmp/oraclemcp-ci-heartbeat.XXXXXX)"
taxonomy="$workdir/ci_taxonomy.json"
out="$workdir/ci-heartbeat.json"
stderr="$workdir/stderr.txt"
stdout="$workdir/stdout.json"
mkdir -p "$workdir/bin"

python3 - "$taxonomy" <<'PY'
import json
import sys

taxonomy = {
    "schema": "ci-taxonomy/v1",
    "repo": "oraclemcp",
    "jobs": [
        {
            "check_name": "required gate",
            "tier": "required",
            "workflow": "Required",
            "workflow_file": "required.yml",
            "job_id": "required",
            "triggers": ["push"],
            "path_filtered": False,
        },
        {
            "check_name": "bounded loom model checks",
            "tier": "scheduled",
            "workflow": "Loom Concurrency Invariants",
            "workflow_file": "loom.yml",
            "job_id": "loom",
            "triggers": ["schedule"],
            "path_filtered": False,
        },
        {
            "check_name": "core shard offset 1",
            "tier": "scheduled",
            "workflow": "Mutation Safety",
            "workflow_file": "mutation-safety.yml",
            "job_id": "scheduled-shard",
            "triggers": ["schedule"],
            "path_filtered": False,
        },
        {
            "check_name": "db shard offset 0",
            "tier": "scheduled",
            "workflow": "Mutation Safety",
            "workflow_file": "mutation-safety.yml",
            "job_id": "scheduled-shard",
            "triggers": ["schedule"],
            "path_filtered": False,
        },
        {
            "check_name": "db shard offset 1",
            "tier": "scheduled",
            "workflow": "Mutation Safety",
            "workflow_file": "mutation-safety.yml",
            "job_id": "scheduled-shard",
            "triggers": ["schedule"],
            "path_filtered": False,
        },
        {
            "check_name": "dispatch shard offset 0",
            "tier": "scheduled",
            "workflow": "Mutation Safety",
            "workflow_file": "mutation-safety.yml",
            "job_id": "scheduled-shard",
            "triggers": ["schedule"],
            "path_filtered": False,
        },
        {
            "check_name": "dispatch shard offset 1",
            "tier": "scheduled",
            "workflow": "Mutation Safety",
            "workflow_file": "mutation-safety.yml",
            "job_id": "scheduled-shard",
            "triggers": ["schedule"],
            "path_filtered": False,
        },
        {
            "check_name": "guard shard offset 0",
            "tier": "scheduled",
            "workflow": "Mutation Safety",
            "workflow_file": "mutation-safety.yml",
            "job_id": "scheduled-shard",
            "triggers": ["schedule"],
            "path_filtered": False,
        },
    ],
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(taxonomy, handle)
PY

python3 - "$workdir/bin/gh" <<'PY'
import json
import sys
from pathlib import Path

script = r'''#!/usr/bin/env python3
import json
import sys

args = sys.argv[1:]
if len(args) < 2 or args[0] != "api":
    raise SystemExit("fake gh only supports gh api")
path = args[1]
sha = "e004ebd5b5532a4b85984a62f8ad48a81aa3460c"

def runs(run_id, conclusion="success"):
    return {
        "workflow_runs": [
            {
                "id": run_id,
                "status": "completed",
                "conclusion": conclusion,
                "html_url": f"https://github.com/MuhDur/oraclemcp/actions/runs/{run_id}",
                "head_sha": sha,
                "updated_at": "2026-07-21T14:34:00Z",
            }
        ]
    }

if "actions/workflows/required.yml/runs" in path:
    print(json.dumps(runs(29800000001)))
elif "actions/workflows/loom.yml/runs" in path:
    print(json.dumps({"workflow_runs": []}))
elif "actions/workflows/mutation-safety.yml/runs" in path:
    print(json.dumps(runs(29804146226, "failure")))
elif "actions/runs/29804146226/jobs" in path:
    jobs = []
    for name in [
        "core shard offset 1",
        "db shard offset 0",
        "db shard offset 1",
        "dispatch shard offset 0",
        "dispatch shard offset 1",
    ]:
        jobs.append({
            "name": name,
            "status": "completed",
            "conclusion": "failure",
            "html_url": "https://github.com/MuhDur/oraclemcp/actions/runs/29804146226",
            "completed_at": "2026-07-21T14:34:00Z",
        })
    jobs.append({
        "name": "guard shard offset 0",
        "status": "completed",
        "conclusion": "success",
        "html_url": "https://github.com/MuhDur/oraclemcp/actions/runs/29804146226",
        "completed_at": "2026-07-21T14:34:00Z",
    })
    print(json.dumps({"jobs": jobs}))
else:
    raise SystemExit(f"unexpected fake gh path: {path}")
'''
path = Path(sys.argv[1])
path.write_text(script, encoding="utf-8")
path.chmod(0o755)
PY

PATH="$workdir/bin:$PATH" \
CI_HEARTBEAT_TAXONOMY="$taxonomy" \
bash "$root/scripts/ci_heartbeat.sh" --no-driver --out "$out" >"$stdout" 2>"$stderr"

jq -e '
  .blocked == false and
  .any_red == false and
  .any_unknown == false and
  .required_blocked == false and
  .watched_blocked == true and
  .watched_red == true and
  .watched_unknown == true and
  ([.lanes[] | select(.state == "not_green" and .run_url == "https://github.com/MuhDur/oraclemcp/actions/runs/29804146226")] | length) == 5 and
  ([.lanes[] | select(.check_name == "bounded loom model checks" and .state == "unknown")] | length) == 1
' "$out" >/dev/null

grep -Fq "required lanes are green, but an advisory watched lane is red or unknown" "$stderr"
grep -Fq "no completed non-superseded scheduled run was found" "$stderr"
if grep -Fq "all watched lanes are green" "$stderr"; then
  echo "ci-heartbeat test: advisory red/unknown evidence was reported as green" >&2
  exit 1
fi

echo "ci-heartbeat: advisory lane honesty regression OK ($workdir)"
