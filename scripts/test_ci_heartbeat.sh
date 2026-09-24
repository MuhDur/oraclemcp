#!/usr/bin/env bash
# Fixture replay for scripts/ci_heartbeat.sh (beads bp8ia.6.4, .2.1).
#
# A fake `gh` serves recorded or synthetic GitHub API responses per case; the
# taxonomy is the real `fuzz.yml` tier-B jobs from docs/ci_taxonomy.json plus a
# synthetic required gate. Each case logs one JSONL line
# {case, expected_exit, actual_exit, scheduled_not_green} and fails the script
# on any mismatch. `scheduled_setup_failure_exits_nonzero` replays the real
# 2026-09-23 Fuzz Campaign run (every job failed at "Set up job"), which the
# heartbeat used to report with exit 0.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workdir="$(mktemp -d /var/tmp/oraclemcp-ci-heartbeat.XXXXXX)"
taxonomy="$workdir/ci_taxonomy.json"
mkdir -p "$workdir/bin"

python3 - "$root/docs/ci_taxonomy.json" "$taxonomy" <<'PY'
import json
import sys

real = json.load(open(sys.argv[1], encoding="utf-8"))
fuzz = [job for job in real["jobs"] if job["workflow_file"] == "fuzz.yml" and job["tier"] == "scheduled"]
if len(fuzz) != 8:
    raise SystemExit(f"expected the 8 fuzz.yml tier-B jobs in docs/ci_taxonomy.json, found {len(fuzz)}")
required = {
    "check_name": "required gate",
    "tier": "required",
    "workflow": "Required",
    "workflow_file": "required.yml",
    "job_id": "required",
    "triggers": ["push"],
    "path_filtered": False,
}
json.dump({"schema": "ci-taxonomy/v1", "repo": "oraclemcp", "jobs": [required, *fuzz]}, open(sys.argv[2], "w"))
PY

python3 - "$workdir/bin/gh" <<'PY'
import sys
from pathlib import Path

script = r'''#!/usr/bin/env python3
import json
import os
import sys

args = sys.argv[1:]
if len(args) < 2 or args[0] != "api":
    raise SystemExit("fake gh only supports gh api")
path = args[1]
scenario = os.environ["HB_SCENARIO"]
fixtures = os.environ["HB_FIXTURES"]
taxonomy = json.load(open(os.environ["CI_HEARTBEAT_TAXONOMY"]))
fuzz_names = sorted(job["check_name"] for job in taxonomy["jobs"] if job["workflow_file"] == "fuzz.yml")
sha = "e004ebd5b5532a4b85984a62f8ad48a81aa3460c"
recorded = "fuzz-setup-job-failure-2026-09-23"
FUZZ_RUN = 29900000002


def runs(run_id, conclusion="success"):
    return {
        "workflow_runs": [
            {
                "id": run_id,
                "status": "completed",
                "conclusion": conclusion,
                "html_url": f"https://github.com/MuhDur/oraclemcp/actions/runs/{run_id}",
                "head_sha": sha,
                "updated_at": "2026-09-23T14:34:00Z",
            }
        ]
    }


def jobs(red=()):
    return {
        "jobs": [
            {
                "name": name,
                "status": "completed",
                "conclusion": "failure" if name in red else "success",
                "completed_at": "2026-09-23T14:34:00Z",
            }
            for name in fuzz_names
        ]
    }


def emit(document):
    print(json.dumps(document))


if "repos/MuhDur/oraclemcp/releases/tags/" in path:
    tag = path.rsplit("/", 1)[1]
    release = os.environ.get("HB_RELEASE", "absent")
    if release == "absent":
        print('{"message":"Not Found","status":"404"}')
        sys.stderr.write("gh: Not Found (HTTP 404)\n")
        raise SystemExit(1)
    emit({"tag_name": tag, "draft": release == "draft", "prerelease": False})
elif "MuhDur/rust-oracledb/actions/workflows/" in path:
    emit(runs(29900000009, "failure" if scenario == "driver_advisory_red_still_exits_zero" else "success"))
elif "actions/workflows/required.yml/runs" in path:
    emit(runs(29900000001))
elif "actions/workflows/fuzz.yml/runs" in path:
    if scenario == "scheduled_setup_failure_exits_nonzero":
        print(open(os.path.join(fixtures, recorded + ".runs.json")).read())
    elif scenario == "scheduled_unknown_exits_nonzero":
        emit({"workflow_runs": []})
    elif scenario == "scheduled_red_exits_nonzero":
        emit(runs(FUZZ_RUN, "failure"))
    else:
        emit(runs(FUZZ_RUN))
elif "actions/runs/35839299781/jobs" in path and scenario == "scheduled_setup_failure_exits_nonzero":
    print(open(os.path.join(fixtures, recorded + ".jobs.json")).read())
elif f"actions/runs/{FUZZ_RUN}/jobs" in path:
    emit(jobs(red={fuzz_names[0]} if scenario == "scheduled_red_exits_nonzero" else ()))
else:
    raise SystemExit(f"unexpected fake gh path for {scenario}: {path}")
'''
path = Path(sys.argv[1])
path.write_text(script, encoding="utf-8")
path.chmod(0o755)
PY

failures=0
# case expected_exit expected_scheduled_not_green_count driver(0|1)
run_case() {
  local name="$1" expected_exit="$2" expected_count="$3" driver="$4"
  local out="$workdir/$name.json" stderr="$workdir/$name.stderr" actual_exit=0
  local driver_flag=(--no-driver)
  [ "$driver" = "1" ] && driver_flag=()
  HB_SCENARIO="$name" HB_FIXTURES="$root/tests/ci_heartbeat" \
    PATH="$workdir/bin:$PATH" CI_HEARTBEAT_TAXONOMY="$taxonomy" \
    bash "$root/scripts/ci_heartbeat.sh" "${driver_flag[@]}" --quiet --out "$out" \
    2>"$stderr" || actual_exit=$?
  local not_green='null' ok=1
  if [ -s "$out" ]; then
    not_green="$(jq -c '.scheduled_not_green' "$out")"
    # ci-heartbeat/v1 readers (crates/oraclemcp-core/src/http/ci_lanes.rs)
    # reject a snapshot whose `blocked` disagrees with `any_red || any_unknown`.
    jq -e '.blocked == (.any_red or .any_unknown)' "$out" >/dev/null || ok=0
    [ "$(jq '.scheduled_not_green | length' "$out")" = "$expected_count" ] || ok=0
  else
    ok=0
  fi
  [ "$actual_exit" = "$expected_exit" ] || ok=0
  jq -nc --arg case "$name" --argjson expected_exit "$expected_exit" \
    --argjson actual_exit "$actual_exit" --argjson scheduled_not_green "$not_green" \
    '{case: $case, expected_exit: $expected_exit, actual_exit: $actual_exit, scheduled_not_green: $scheduled_not_green}'
  if [ "$ok" != "1" ]; then
    echo "ci-heartbeat test: $name failed (stderr: $stderr)" >&2
    failures=$((failures + 1))
  fi
}

run_case scheduled_red_exits_nonzero 1 1 0
run_case scheduled_setup_failure_exits_nonzero 1 8 0
run_case scheduled_unknown_exits_nonzero 1 8 0
run_case scheduled_green_required_green_exits_zero 0 0 0
run_case driver_advisory_red_still_exits_zero 0 0 1

# The replayed setup failure must name the observed run, and the driver case
# must still report the red driver lane rather than hide it.
jq -e '[.lanes[] | select(.state == "not_green" and .conclusion == "failure"
  and .run_url == "https://github.com/MuhDur/oraclemcp/actions/runs/35839299781")] | length == 8' \
  "$workdir/scheduled_setup_failure_exits_nonzero.json" >/dev/null || {
  echo "ci-heartbeat test: the replayed setup failure did not record all 8 fuzz jobs red" >&2
  failures=$((failures + 1))
}
jq -e '.watched_red == true and .blocked == false and
  ([.lanes[] | select(.tier == "driver_advisory" and .state == "not_green")] | length) == 1' \
  "$workdir/driver_advisory_red_still_exits_zero.json" >/dev/null || {
  echo "ci-heartbeat test: the red driver advisory lane was hidden or gated" >&2
  failures=$((failures + 1))
}
grep -Fq "scheduled_not_green: fuzz" "$workdir/scheduled_red_exits_nonzero.stderr" || {
  echo "ci-heartbeat test: the stderr banner does not name the red scheduled lane" >&2
  failures=$((failures + 1))
}

# The tag gate: scripts/release_preflight.sh runs this same check in tag context
# (release.yml). It must refuse the replayed red lanes and name each one as
# `lane -> found -> expected`, and it must pass when every tier-B lane is green.
preflight_case() {
  local name="$1" scenario="$2" expected_exit="$3" actual_exit=0
  local stderr="$workdir/$name.stderr"
  HB_SCENARIO="$scenario" HB_FIXTURES="$root/tests/ci_heartbeat" \
    PATH="$workdir/bin:$PATH" CI_HEARTBEAT_TAXONOMY="$taxonomy" \
    bash "$root/scripts/release_preflight.sh" --check-scheduled-lanes >/dev/null \
    2>"$stderr" || actual_exit=$?
  jq -nc --arg case "$name" --argjson expected_exit "$expected_exit" \
    --argjson actual_exit "$actual_exit" \
    '{case: $case, expected_exit: $expected_exit, actual_exit: $actual_exit}'
  if [ "$actual_exit" != "$expected_exit" ]; then
    echo "ci-heartbeat test: $name exited $actual_exit, expected $expected_exit ($stderr)" >&2
    failures=$((failures + 1))
  fi
}
preflight_case release_preflight_refuses_red_scheduled_lane scheduled_setup_failure_exits_nonzero 1
preflight_case release_preflight_accepts_green_scheduled_lanes scheduled_green_required_green_exits_zero 0
# RELEASE_PREFLIGHT_EXISTING_RELEASE may skip the tier-B gate only for a tag
# whose GitHub release is proven published; otherwise it would let a new tag
# past a red lane. Every case below replays the red lanes.
tag_gate_case() {
  local name="$1" flag="$2" release="$3" expected_exit="$4" actual_exit=0
  local stderr="$workdir/$name.stderr"
  HB_SCENARIO=scheduled_setup_failure_exits_nonzero HB_FIXTURES="$root/tests/ci_heartbeat" \
    HB_RELEASE="$release" RELEASE_TAG=v9.9.9 RELEASE_PREFLIGHT_EXISTING_RELEASE="$flag" \
    PATH="$workdir/bin:$PATH" CI_HEARTBEAT_TAXONOMY="$taxonomy" \
    bash "$root/scripts/release_preflight.sh" --check-tag-gate >/dev/null \
    2>"$stderr" || actual_exit=$?
  jq -nc --arg case "$name" --argjson expected_exit "$expected_exit" \
    --argjson actual_exit "$actual_exit" \
    '{case: $case, expected_exit: $expected_exit, actual_exit: $actual_exit}'
  if [ "$actual_exit" != "$expected_exit" ]; then
    echo "ci-heartbeat test: $name exited $actual_exit, expected $expected_exit ($stderr)" >&2
    failures=$((failures + 1))
  fi
}
tag_gate_case tag_gate_new_tag_red_lanes_refused 0 absent 1
tag_gate_case tag_gate_existing_release_flag_without_release_refused 1 absent 1
tag_gate_case tag_gate_existing_release_flag_draft_release_refused 1 draft 1
tag_gate_case tag_gate_existing_release_flag_published_release_accepted 1 published 0
for refused in tag_gate_existing_release_flag_without_release_refused tag_gate_existing_release_flag_draft_release_refused; do
  grep -Fq "no published GitHub release exists for v9.9.9" "$workdir/$refused.stderr" || {
    echo "ci-heartbeat test: $refused was not refused for the missing release" >&2
    failures=$((failures + 1))
  }
done
grep -Fq "classify_fuzz shard 0/1 -> failure -> expected success" \
  "$workdir/tag_gate_new_tag_red_lanes_refused.stderr" || {
  echo "ci-heartbeat test: a new tag was not refused for the red scheduled lanes" >&2
  failures=$((failures + 1))
}

grep -Fq "fuzz oraclemcp-guard / classify_fuzz shard 0/1 -> failure -> expected success" \
  "$workdir/release_preflight_refuses_red_scheduled_lane.stderr" || {
  echo "ci-heartbeat test: the tag refusal does not name the red lane as lane -> found -> expected" >&2
  failures=$((failures + 1))
}

if [ "$failures" != "0" ]; then
  echo "ci-heartbeat test: $failures failure(s) ($workdir)" >&2
  exit 1
fi
echo "ci-heartbeat: scheduled-lane gate regression OK ($workdir)"
