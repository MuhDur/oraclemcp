#!/usr/bin/env bash
# CI heartbeat / notifier (bead oraclemcp-eng-program-bp8ia.6.4, plan §27.4 O3
# + C8): "the deepest operator-trust wound was the operator discovering red CI
# himself." This script polls the REAL GitHub Actions state — never local git
# state, which can be stale or unpushed — for the required + scheduled lanes
# this repo's own `docs/ci_taxonomy.json` names, plus, trivially in scope, the
# sibling driver repo's required lane and its Live nightly (the chronically-red
# lane plan §27.7 F-D2 names by hand). It is designed to run on a schedule (see
# `.github/workflows/ci-heartbeat.yml`) so a red or blocked lane is surfaced
# within one cycle, not discovered later by a human reading the Actions tab.
#
# Design notes:
#   - A "cancelled" run is a superseded run (this repo's `cancel-in-progress`
#     concurrency groups cancel dozens of runs a day on rapid pushes — the
#     retro's own "119-cancel supersede band"), NOT a failure. Treating it as
#     red would itself be a "gate that lies" — the exact failure class this
#     bead exists to close. This script walks back through recent completed
#     runs to the first non-cancelled conclusion.
#   - A lane the script cannot observe (gh/network failure, no completed run
#     yet) renders `unknown`, never a fabricated `success` — the same
#     fail-closed rule `crates/oraclemcp-core/src/http/ci_lanes.rs` already
#     enforces for the dashboard tile. `unknown` still counts as blocked: a
#     silent gap is exactly what let CI go undiscovered before.
#   - Scheduled server workflows are resolved to exact job names from the
#     generated taxonomy. A workflow-level success is never copied across a
#     matrix or onto a job that did not run for the observed event.
#   - The exit code IS the notification path for the REQUIRED lanes: a non-zero
#     exit turns THIS script's own scheduled workflow run red, which rides
#     GitHub's existing scheduled-workflow-failure notification — no bespoke
#     webhook, no new secret, no new always-on service (AGENTS.md: no surprise
#     costs, don't invent a heavyweight service). Local/cron use gets the same
#     signal via the process exit code and the stderr banner.
#   - Scheduled/nightly lanes are ADVISORY: recorded in the snapshot for
#     visibility but they do NOT drive the exit code. Nightlies are
#     infra-dependent and intermittently red (the driver Live nightly, e.g.,
#     self-skips its operator-only wallet secrets), and each already rides its
#     own repo's scheduled-workflow-failure notification. Letting a flaky nightly
#     fail this heartbeat would perpetually redden the repo and train the operator
#     to ignore it — the opposite of this bead's operator-trust goal.
#
# Usage:
#   scripts/ci_heartbeat.sh [--out PATH] [--no-driver] [--quiet]
#
# Exit codes: 0 = every REQUIRED lane confirmed green (advisory scheduled reds
# or unknowns are reported honestly but never fail the heartbeat); 1 = at least
# one required lane is red or unknown (see the printed report for which); 2 =
# the harness itself could not run (missing `gh`/`jq`/`python3`, or the local
# taxonomy is broken).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON:-python3}"
TAXONOMY="${CI_HEARTBEAT_TAXONOMY:-$ROOT/docs/ci_taxonomy.json}"

SERVER_REPO="MuhDur/oraclemcp"
DRIVER_REPO="MuhDur/rust-oracledb"
# The driver repo's own CI taxonomy is not generated/embedded here (that would
# be a second copy of a different repo's source of truth — out of proportion
# for a heartbeat). Its required gate (hard-fail) and its Live nightly (advisory;
# plan §27.7 F-D2) are small and stable enough to name directly; review this
# list if the driver restructures its workflows.
DRIVER_REQUIRED_WORKFLOWS=("required.yml")
DRIVER_SCHEDULED_WORKFLOWS=("live.yml")

INCLUDE_DRIVER=1
QUIET=0
OUT_PATH="${CI_HEARTBEAT_OUTPUT:-${XDG_STATE_HOME:-$HOME/.local/state}/oraclemcp/ci-heartbeat.json}"

while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT_PATH="$2"; shift 2 ;;
    --no-driver) INCLUDE_DRIVER=0; shift ;;
    --quiet) QUIET=1; shift ;;
    -h|--help)
      sed -n '2,33p' "$0"
      exit 0
      ;;
    *) echo "ci-heartbeat: unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ "${CI_HEARTBEAT_SKIP_DRIVER:-0}" = "1" ]; then
  INCLUDE_DRIVER=0
fi

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ci-heartbeat: missing required command: $1" >&2
    exit 2
  }
}
require_cmd gh
require_cmd jq
require_cmd "$PYTHON_BIN"

if [ ! -f "$TAXONOMY" ]; then
  echo "ci-heartbeat: $TAXONOMY is missing; run scripts/ci_taxonomy.py --write" >&2
  exit 2
fi

tmp_lanes="$(mktemp)"
trap 'rm -f "$tmp_lanes"' EXIT

# Required lanes drive this script's exit code and preserve the original
# ci-heartbeat/v1 `blocked` / `any_*` semantics consumed by existing readers.
required_red=0
required_unknown=0
# Watched lanes include advisory scheduled lanes. These fields prevent the
# report from saying the watched set is green when advisory evidence is red,
# missing, or otherwise unknown.
watched_red=0
watched_unknown=0
declare -a report_errors=()

note_lane_state() {
  # state notify_required
  case "$1" in
    not_green)
      watched_red=1
      if [ "$2" = "1" ]; then
        required_red=1
      fi
      ;;
    unknown)
      watched_unknown=1
      if [ "$2" = "1" ]; then
        required_unknown=1
      fi
      ;;
  esac
}

record_lane() {
  # repo check_name tier state conclusion run_url head_sha updated_at
  jq -nc \
    --arg repo "$1" --arg check_name "$2" --arg tier "$3" --arg state "$4" \
    --arg conclusion "$5" --arg run_url "$6" --arg head_sha "$7" --arg updated_at "$8" \
    '{
      repo: $repo,
      check_name: $check_name,
      tier: $tier,
      state: $state,
      conclusion: (if $conclusion == "" then null else $conclusion end),
      run_url: (if $run_url == "" then null else $run_url end),
      head_sha: (if $head_sha == "" then null else $head_sha end),
      updated_at: (if $updated_at == "" then null else $updated_at end)
    }' >> "$tmp_lanes"
}

record_job_lane() {
  # repo check_name tier workflow_file job_id event state conclusion run_url head_sha updated_at
  jq -nc \
    --arg repo "$1" --arg check_name "$2" --arg tier "$3" \
    --arg workflow_file "$4" --arg job_id "$5" --arg event "$6" \
    --arg state "$7" --arg conclusion "$8" --arg run_url "$9" \
    --arg head_sha "${10}" --arg updated_at "${11}" \
    '{
      repo: $repo,
      check_name: $check_name,
      tier: $tier,
      workflow_file: $workflow_file,
      job_id: $job_id,
      event: $event,
      state: $state,
      conclusion: (if $conclusion == "" then null else $conclusion end),
      run_url: (if $run_url == "" then null else $run_url end),
      head_sha: (if $head_sha == "" then null else $head_sha end),
      updated_at: (if $updated_at == "" then null else $updated_at end)
    }' >> "$tmp_lanes"
}

# Fetch the most recent COMPLETED, non-superseded run of one workflow file.
# Echoes a single JSON object (or `null` if none exists) on success; returns
# non-zero if the GitHub API call itself failed (network, auth, 404).
fetch_latest_run() {
  local repo="$1" workflow_file="$2" query_suffix="$3"
  local raw
  # shellcheck disable=SC2034 # loop count only; the body ignores the index.
  for attempt in 1 2; do
    if raw="$(gh api "repos/${repo}/actions/workflows/${workflow_file}/runs?status=completed&per_page=10${query_suffix}" 2>&1)"; then
      jq -c '([.workflow_runs[]? | select(.conclusion != "cancelled")] | .[0]) // null' <<<"$raw"
      return 0
    fi
    sleep 2
  done
  echo "ci-heartbeat: gh api failed for ${repo} ${workflow_file}: ${raw}" >&2
  return 1
}

fetch_run_jobs() {
  local repo="$1" run_id="$2" raw
  # shellcheck disable=SC2034 # loop count only; the body ignores the index.
  for attempt in 1 2; do
    if raw="$(gh api "repos/${repo}/actions/runs/${run_id}/jobs?filter=latest&per_page=100" 2>&1)"; then
      printf '%s\n' "$raw"
      return 0
    fi
    sleep 2
  done
  echo "ci-heartbeat: gh api failed for ${repo} run ${run_id} jobs: ${raw}" >&2
  return 1
}

# Resolve one workflow's latest definitive run and record it as a lane.
# `notify=1` means a red/unknown result here counts toward the exit code.
watch_workflow() {
  local repo="$1" workflow_file="$2" tier="$3" query_suffix="$4" notify="$5"
  local check_name="${tier}:${workflow_file}"
  local run_json
  if ! run_json="$(fetch_latest_run "$repo" "$workflow_file" "$query_suffix")"; then
    record_lane "$repo" "$check_name" "$tier" "unknown" "" "" "" ""
    note_lane_state "unknown" "$notify"
    report_errors+=("${repo} ${workflow_file}: gh api call failed")
    return
  fi
  if [ "$run_json" = "null" ]; then
    record_lane "$repo" "$check_name" "$tier" "unknown" "" "" "" ""
    note_lane_state "unknown" "$notify"
    report_errors+=("${repo} ${workflow_file}: no completed non-superseded run was found")
    return
  fi
  local conclusion url sha updated state
  conclusion="$(jq -r '.conclusion // ""' <<<"$run_json")"
  url="$(jq -r '.html_url // ""' <<<"$run_json")"
  sha="$(jq -r '.head_sha // ""' <<<"$run_json")"
  updated="$(jq -r '.updated_at // ""' <<<"$run_json")"
  if [ "$conclusion" = "success" ]; then
    state="success"
  else
    state="not_green"
  fi
  record_lane "$repo" "$check_name" "$tier" "$state" "$conclusion" "$url" "$sha" "$updated"
  note_lane_state "$state" "$notify"
}

record_unknown_server_scheduled_jobs() {
  local workflow_file="$1" reason="$2"
  while IFS=$'\t' read -r check_name job_id; do
    record_job_lane \
      "$SERVER_REPO" "$check_name" "scheduled" "$workflow_file" "$job_id" \
      "schedule" "unknown" "" "" "" ""
    note_lane_state "unknown" 0
  done < <(
    jq -r --arg workflow_file "$workflow_file" \
      '.jobs[] | select(.tier == "scheduled" and .workflow_file == $workflow_file) |
       [.check_name, .job_id] | @tsv' "$TAXONOMY"
  )
  report_errors+=("${SERVER_REPO} ${workflow_file}: ${reason}")
}

# Resolve one scheduled workflow run to exact job observations. Workflow-level
# success is insufficient for a multi-job workflow: a skipped/manual-only job,
# an advisory job, and a real successful scheduled job are different evidence.
watch_server_scheduled_jobs() {
  local workflow_file="$1" run_json jobs_json run_id run_url head_sha run_updated
  if ! run_json="$(fetch_latest_run "$SERVER_REPO" "$workflow_file" "&event=schedule")"; then
    record_unknown_server_scheduled_jobs "$workflow_file" "gh workflow API call failed"
    return
  fi
  if [ "$run_json" = "null" ]; then
    record_unknown_server_scheduled_jobs \
      "$workflow_file" "no completed non-superseded scheduled run was found"
    return
  fi
  run_id="$(jq -r '.id // ""' <<<"$run_json")"
  run_url="$(jq -r '.html_url // ""' <<<"$run_json")"
  head_sha="$(jq -r '.head_sha // ""' <<<"$run_json")"
  run_updated="$(jq -r '.updated_at // ""' <<<"$run_json")"
  if [ -z "$run_id" ] || ! jobs_json="$(fetch_run_jobs "$SERVER_REPO" "$run_id")"; then
    record_unknown_server_scheduled_jobs "$workflow_file" "gh jobs API call failed"
    return
  fi

  while IFS=$'\t' read -r check_name job_id; do
    local matches count status conclusion completed_at state
    matches="$(jq -c --arg check_name "$check_name" \
      '[.jobs[]? | select(.name == $check_name)]' <<<"$jobs_json")"
    count="$(jq 'length' <<<"$matches")"
    if [ "$count" != "1" ]; then
      record_job_lane \
        "$SERVER_REPO" "$check_name" "scheduled" "$workflow_file" "$job_id" \
        "schedule" "unknown" "" "" "" ""
      note_lane_state "unknown" 0
      report_errors+=(
        "${SERVER_REPO} ${workflow_file}: expected one ${check_name} job, found ${count}"
      )
      continue
    fi
    status="$(jq -r '.[0].status // ""' <<<"$matches")"
    conclusion="$(jq -r '.[0].conclusion // ""' <<<"$matches")"
    completed_at="$(jq -r --arg fallback "$run_updated" \
      '.[0].completed_at // $fallback' <<<"$matches")"
    if [ "$status" != "completed" ] || [ -z "$conclusion" ]; then
      state="unknown"
      conclusion=""
      report_errors+=(
        "${SERVER_REPO} ${workflow_file}: ${check_name} has no completed conclusion"
      )
    elif [ "$conclusion" = "success" ]; then
      state="success"
    else
      state="not_green"
    fi
    record_job_lane \
      "$SERVER_REPO" "$check_name" "scheduled" "$workflow_file" "$job_id" \
      "schedule" "$state" "$conclusion" "$run_url" "$head_sha" "$completed_at"
    note_lane_state "$state" 0
  done < <(
    jq -r --arg workflow_file "$workflow_file" \
      '.jobs[] | select(.tier == "scheduled" and .workflow_file == $workflow_file) |
       [.check_name, .job_id] | @tsv' "$TAXONOMY"
  )
}

# --- Server (oraclemcp): required + scheduled workflow files, derived from
# the generated taxonomy so this stays in sync automatically. Advisory lanes
# (ci.yml's continue-on-error nightly-toolchain jobs) are already a live,
# fail-closed dashboard tile (crates/oraclemcp-core/src/http/ci_lanes.rs) and
# are non-gating by repo convention, so this heartbeat leaves them for that
# tile rather than duplicating the same visibility here.
mapfile -t server_required_files < <(
  jq -r '[.jobs[] | select(.tier == "required") | .workflow_file] | unique | .[]' "$TAXONOMY"
)
for file in "${server_required_files[@]}"; do
  watch_workflow "$SERVER_REPO" "$file" "required" "&branch=main&event=push" 1
done

# This script's own workflow file (.github/workflows/ci-heartbeat.yml) is
# itself a `scheduled` taxonomy entry (it only triggers on
# schedule/workflow_dispatch). Watching it would create a self-referential
# feedback loop: a run that fails because some OTHER lane was red leaves its
# own history "not_green", which would then keep the heartbeat reporting red
# for one extra cycle after everything else recovers. Excluded by name, not by
# tier, so a genuinely different scheduled lane is never silently dropped.
SELF_WORKFLOW_FILE="ci-heartbeat.yml"
mapfile -t server_scheduled_files < <(
  jq -r --arg self "$SELF_WORKFLOW_FILE" \
    '[.jobs[] | select(.tier == "scheduled") | .workflow_file] | unique | .[] | select(. != $self)' \
    "$TAXONOMY"
)
# Scheduled/nightly lanes are ADVISORY: still recorded in the snapshot
# so the operator can see them, but a red nightly does NOT fail this heartbeat.
# Nightlies are infra-dependent and intermittently red (e.g. the driver Live
# nightly needs operator-only wallet secrets), and each already rides its OWN
# repo's scheduled-workflow-failure notification. Only the required gates hard-fail
# this heartbeat, so a flaky/pre-fix nightly never falsely reddens the repo.
for file in "${server_scheduled_files[@]}"; do
  watch_server_scheduled_jobs "$file"
done

# --- Driver (rust-oracledb): trivially-in-scope required + Live nightly.
if [ "$INCLUDE_DRIVER" = "1" ]; then
  for file in "${DRIVER_REQUIRED_WORKFLOWS[@]}"; do
    watch_workflow "$DRIVER_REPO" "$file" "driver_required" "&branch=main&event=push" 1
  done
  for file in "${DRIVER_SCHEDULED_WORKFLOWS[@]}"; do
    # Advisory (see the scheduled note above): the Live nightly self-skips its
    # operator-only real-wallet TCPS test, so an unattended nightly must never
    # redden this heartbeat; it is still recorded for visibility.
    watch_workflow "$DRIVER_REPO" "$file" "driver_scheduled" "&event=schedule" 0
  done
fi

lanes_json="$(jq -s '.' "$tmp_lanes")"
now_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
required_blocked=false
if [ "$required_red" = "1" ] || [ "$required_unknown" = "1" ]; then
  required_blocked=true
fi
watched_blocked=false
if [ "$watched_red" = "1" ] || [ "$watched_unknown" = "1" ]; then
  watched_blocked=true
fi

errors_json="$(printf '%s\n' "${report_errors[@]+"${report_errors[@]}"}" | jq -R . | jq -s 'map(select(length > 0))')"

report="$(jq -n \
  --arg schema "ci-heartbeat/v1" \
  --arg generated_at "$now_utc" \
  --argjson blocked "$required_blocked" \
  --argjson any_red "$([ "$required_red" = "1" ] && echo true || echo false)" \
  --argjson any_unknown "$([ "$required_unknown" = "1" ] && echo true || echo false)" \
  --argjson required_blocked "$required_blocked" \
  --argjson required_red "$([ "$required_red" = "1" ] && echo true || echo false)" \
  --argjson required_unknown "$([ "$required_unknown" = "1" ] && echo true || echo false)" \
  --argjson watched_blocked "$watched_blocked" \
  --argjson watched_red "$([ "$watched_red" = "1" ] && echo true || echo false)" \
  --argjson watched_unknown "$([ "$watched_unknown" = "1" ] && echo true || echo false)" \
  --argjson lanes "$lanes_json" \
  --argjson errors "$errors_json" \
  '{
    schema: $schema,
    generated_at: $generated_at,
    blocked: $blocked,
    any_red: $any_red,
    any_unknown: $any_unknown,
    required_blocked: $required_blocked,
    required_red: $required_red,
    required_unknown: $required_unknown,
    watched_blocked: $watched_blocked,
    watched_red: $watched_red,
    watched_unknown: $watched_unknown,
    lanes: $lanes,
    errors: $errors
  }'
)"

mkdir -p "$(dirname "$OUT_PATH")"
tmp_out="$(mktemp "$(dirname "$OUT_PATH")/.ci-heartbeat.XXXXXX")"
printf '%s\n' "$report" > "$tmp_out"
mv "$tmp_out" "$OUT_PATH"

if [ "$QUIET" != "1" ]; then
  printf '%s\n' "$report"
fi

if [ "$required_blocked" = "true" ]; then
  {
    echo "::error::ci-heartbeat: at least one required lane is red or unknown"
    echo "ci-heartbeat: BLOCKED — a required lane is red or unknown (snapshot: $OUT_PATH)"
    jq -r '.lanes[] | select(.state != "success") | "  \(.state)\t\(.repo)\t\(.check_name)\t\(.run_url // "no run observed")"' <<<"$report"
    for error in "${report_errors[@]+"${report_errors[@]}"}"; do
      echo "  error: $error"
    done
  } >&2
  exit 1
fi

if [ "$watched_blocked" = "true" ]; then
  if [ "$QUIET" != "1" ]; then
    {
      echo "::warning::ci-heartbeat: required lanes are green, but an advisory watched lane is red or unknown"
      echo "ci-heartbeat: ADVISORY — scheduled/advisory lane evidence is red or unknown (snapshot: $OUT_PATH)"
      jq -r '.lanes[] | select(.state != "success") | "  \(.state)\t\(.repo)\t\(.check_name)\t\(.run_url // "no run observed")"' <<<"$report"
      for error in "${report_errors[@]+"${report_errors[@]}"}"; do
        echo "  error: $error"
      done
    } >&2
  fi
  exit 0
fi

[ "$QUIET" = "1" ] || echo "ci-heartbeat: all watched lanes are green" >&2
exit 0
