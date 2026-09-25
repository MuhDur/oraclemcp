#!/usr/bin/env bash
# CI heartbeat / notifier (bead oraclemcp-eng-program-bp8ia.6.4, plan §27.4 O3
# + C8): "the deepest operator-trust wound was the operator discovering red CI
# himself." This script polls the REAL GitHub Actions state — never local git
# state, which can be stale or unpushed — for the required + scheduled lanes
# this repo's own `docs/ci_taxonomy.json` names, plus advisory-only sibling
# driver and PL/SQL engine tier-B lanes. Their state is published separately
# as `sibling_scheduled`. It is designed to run on a schedule (see
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
#   - The exit code IS the notification path for this repo's REQUIRED (tier A)
#     and SCHEDULED (tier B) lanes: a non-zero exit turns THIS script's own
#     scheduled workflow run red, which rides GitHub's existing
#     scheduled-workflow-failure notification — no bespoke webhook, no new
#     secret, no new always-on service (AGENTS.md: no surprise costs, don't
#     invent a heavyweight service). Local/cron use gets the same signal via
#     the process exit code and the stderr banner.
#   - Tier-B lanes gate too (plan §7, bead .2.1): the Fuzz Campaign failed at
#     "Set up job" every night for six days while each run's own failure
#     notification went unnoticed. A red or unknown scheduled server lane is
#     listed in `scheduled_not_green`, fails this heartbeat, and makes
#     scripts/release_preflight.sh refuse a release tag.
#   - Sibling tier-B lanes stay ADVISORY (R1): recorded under
#     `sibling_scheduled` for visibility, never part of the exit code.
#
# Usage:
#   scripts/ci_heartbeat.sh [--out PATH] [--no-driver] [--quiet]
#
# Exit codes: 0 = every required and scheduled server lane confirmed green
# (sibling advisory reds or unknowns are reported honestly but never fail the
# heartbeat); 1 = at least one required or scheduled server lane is red or
# unknown (see the printed report and `scheduled_not_green`); 2 =
# the harness itself could not run (missing `gh`/`jq`/`python3`, or the local
# taxonomy is broken).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON:-python3}"
TAXONOMY="${CI_HEARTBEAT_TAXONOMY:-$ROOT/docs/ci_taxonomy.json}"

SERVER_REPO="MuhDur/oraclemcp"
DRIVER_REPO="MuhDur/rust-oracledb"
ENGINE_REPO="MuhDur/plsql-intelligence"
# Sibling repo workflow files are named directly rather than embedding a
# second repository's generated taxonomy here. Keep these lists aligned with
# their `# tier: B` workflow headers; all are advisory from oraclemcp's view.
DRIVER_SCHEDULED_WORKFLOWS=("canary.yml" "live.yml" "soak.yml" "tsan.yml" "version-matrix.yml")
ENGINE_SCHEDULED_WORKFLOWS=("bindgen-roundtrip.yml" "fuzz.yml" "usr.yml")

INCLUDE_DRIVER=1
INCLUDE_ENGINE=1
QUIET=0
OUT_PATH="${CI_HEARTBEAT_OUTPUT:-${XDG_STATE_HOME:-$HOME/.local/state}/oraclemcp/ci-heartbeat.json}"

while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT_PATH="$2"; shift 2 ;;
    --no-driver) INCLUDE_DRIVER=0; shift ;;
    --quiet) QUIET=1; shift ;;
    -h|--help)
      sed -n '2,39p' "$0"
      exit 0
      ;;
    *) echo "ci-heartbeat: unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ "${CI_HEARTBEAT_SKIP_DRIVER:-0}" = "1" ]; then
  INCLUDE_DRIVER=0
fi
if [ "${CI_HEARTBEAT_SKIP_ENGINE:-0}" = "1" ]; then
  INCLUDE_ENGINE=0
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

# Required and scheduled server lanes drive this script's exit code; `blocked`
# / `any_*` (the ci-heartbeat/v1 fields existing readers consume) cover both,
# while `required_*` and `scheduled_*` name which tier caused it.
required_red=0
required_unknown=0
scheduled_red=0
scheduled_unknown=0
# Watched lanes include advisory scheduled lanes. These fields prevent the
# report from saying the watched set is green when advisory evidence is red,
# missing, or otherwise unknown.
watched_red=0
watched_unknown=0
declare -a report_errors=()

note_lane_state() {
  # state gate: 0 = advisory (watched only), 1 = required, 2 = scheduled
  case "$1" in
    not_green)
      watched_red=1
      case "$2" in
        1) required_red=1 ;;
        2) scheduled_red=1 ;;
      esac
      ;;
    unknown)
      watched_unknown=1
      case "$2" in
        1) required_unknown=1 ;;
        2) scheduled_unknown=1 ;;
      esac
      ;;
  esac
}

record_lane() {
  # repo check_name tier state conclusion run_url head_sha updated_at event
  jq -nc \
    --arg repo "$1" --arg check_name "$2" --arg tier "$3" --arg state "$4" \
    --arg conclusion "$5" --arg run_url "$6" --arg head_sha "$7" --arg updated_at "$8" \
    --arg event "${9:-}" \
    '{
      repo: $repo,
      check_name: $check_name,
      tier: $tier,
      state: $state,
      conclusion: (if $conclusion == "" then null else $conclusion end),
      run_url: (if $run_url == "" then null else $run_url end),
      head_sha: (if $head_sha == "" then null else $head_sha end),
      updated_at: (if $updated_at == "" then null else $updated_at end),
      event: (if $event == "" then null else $event end)
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
  local repo="$1" workflow_file="$2" query_suffix="$3" accepted_events="${4:-}"
  local raw
  # shellcheck disable=SC2034 # loop count only; the body ignores the index.
  for attempt in 1 2; do
    if raw="$(gh api "repos/${repo}/actions/workflows/${workflow_file}/runs?status=completed&per_page=100${query_suffix}" 2>&1)"; then
      if [ -n "$accepted_events" ]; then
        jq -c --argjson accepted_events "$accepted_events" \
          '([.workflow_runs[]? | select(.conclusion != "cancelled") |
             select(.event as $event | $accepted_events | index($event))] | .[0]) // null' <<<"$raw"
      else
        jq -c '([.workflow_runs[]? | select(.conclusion != "cancelled")] | .[0]) // null' <<<"$raw"
      fi
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
  local repo="$1" workflow_file="$2" tier="$3" query_suffix="$4" notify="$5" accepted_events="${6:-}"
  local check_name="${tier}:${workflow_file}"
  local run_json
  if ! run_json="$(fetch_latest_run "$repo" "$workflow_file" "$query_suffix" "$accepted_events")"; then
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
  local conclusion url sha updated event state
  conclusion="$(jq -r '.conclusion // ""' <<<"$run_json")"
  url="$(jq -r '.html_url // ""' <<<"$run_json")"
  sha="$(jq -r '.head_sha // ""' <<<"$run_json")"
  updated="$(jq -r '.updated_at // ""' <<<"$run_json")"
  event="$(jq -r '.event // ""' <<<"$run_json")"
  if [ "$conclusion" = "success" ]; then
    state="success"
  else
    state="not_green"
  fi
  record_lane "$repo" "$check_name" "$tier" "$state" "$conclusion" "$url" "$sha" "$updated" "$event"
  note_lane_state "$state" "$notify"
}

record_unknown_server_scheduled_jobs() {
  local workflow_file="$1" reason="$2"
  while IFS=$'\t' read -r check_name job_id; do
    record_job_lane \
      "$SERVER_REPO" "$check_name" "scheduled" "$workflow_file" "$job_id" \
      "schedule" "unknown" "" "" "" ""
    note_lane_state "unknown" 2
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
      note_lane_state "unknown" 2
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
    note_lane_state "$state" 2
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
# Tier-B server lanes gate this heartbeat: a red or unknown scheduled job is
# listed in `scheduled_not_green` and fails the run (see the header).
for file in "${server_scheduled_files[@]}"; do
  watch_server_scheduled_jobs "$file"
done

# --- Sibling Tier-B workflows are watched ADVISORY-only (R1). Their exact
# conclusions are kept in `sibling_scheduled`, but cannot affect this repo's
# exit status.
if [ "$INCLUDE_DRIVER" = "1" ]; then
  for file in "${DRIVER_SCHEDULED_WORKFLOWS[@]}"; do
    watch_workflow "$DRIVER_REPO" "$file" "driver_scheduled" "&branch=main" 0 '["schedule", "workflow_dispatch"]'
  done
fi
if [ "$INCLUDE_ENGINE" = "1" ]; then
  for file in "${ENGINE_SCHEDULED_WORKFLOWS[@]}"; do
    watch_workflow "$ENGINE_REPO" "$file" "engine_scheduled" "&branch=main" 0 '["schedule", "workflow_dispatch"]'
  done
fi

lanes_json="$(jq -s '.' "$tmp_lanes")"
sibling_scheduled="$(jq -c '[.[] | select(.tier == "driver_scheduled" or .tier == "engine_scheduled") | {
  repo, check_name, workflow_file: (.check_name | sub("^[^:]+:"; "")), tier, state, conclusion, event, run_url, head_sha, updated_at
}]' <<<"$lanes_json")"
now_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
required_blocked=false
if [ "$required_red" = "1" ] || [ "$required_unknown" = "1" ]; then
  required_blocked=true
fi
scheduled_blocked=false
if [ "$scheduled_red" = "1" ] || [ "$scheduled_unknown" = "1" ]; then
  scheduled_blocked=true
fi
blocked=false
if [ "$required_blocked" = "true" ] || [ "$scheduled_blocked" = "true" ]; then
  blocked=true
fi
any_red=false
if [ "$required_red" = "1" ] || [ "$scheduled_red" = "1" ]; then
  any_red=true
fi
any_unknown=false
if [ "$required_unknown" = "1" ] || [ "$scheduled_unknown" = "1" ]; then
  any_unknown=true
fi
scheduled_not_green="$(jq -c --arg repo "$SERVER_REPO" \
  '[.[] | select(.repo == $repo and .tier == "scheduled" and .state != "success") | .check_name] | unique' \
  <<<"$lanes_json")"
watched_blocked=false
if [ "$watched_red" = "1" ] || [ "$watched_unknown" = "1" ]; then
  watched_blocked=true
fi

errors_json="$(printf '%s\n' "${report_errors[@]+"${report_errors[@]}"}" | jq -R . | jq -s 'map(select(length > 0))')"

report="$(jq -n \
  --arg schema "ci-heartbeat/v1" \
  --arg generated_at "$now_utc" \
  --argjson blocked "$blocked" \
  --argjson any_red "$any_red" \
  --argjson any_unknown "$any_unknown" \
  --argjson required_blocked "$required_blocked" \
  --argjson required_red "$([ "$required_red" = "1" ] && echo true || echo false)" \
  --argjson required_unknown "$([ "$required_unknown" = "1" ] && echo true || echo false)" \
  --argjson scheduled_blocked "$scheduled_blocked" \
  --argjson scheduled_not_green "$scheduled_not_green" \
  --argjson watched_blocked "$watched_blocked" \
  --argjson watched_red "$([ "$watched_red" = "1" ] && echo true || echo false)" \
  --argjson watched_unknown "$([ "$watched_unknown" = "1" ] && echo true || echo false)" \
  --argjson sibling_scheduled "$sibling_scheduled" \
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
    scheduled_blocked: $scheduled_blocked,
    scheduled_not_green: $scheduled_not_green,
    watched_blocked: $watched_blocked,
    watched_red: $watched_red,
    watched_unknown: $watched_unknown,
    sibling_scheduled: $sibling_scheduled,
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

if [ "$blocked" = "true" ]; then
  {
    echo "::error::ci-heartbeat: at least one required or scheduled lane is red or unknown"
    echo "ci-heartbeat: BLOCKED — a required or scheduled lane is red or unknown (snapshot: $OUT_PATH)"
    jq -r '.[] | "  scheduled_not_green: \(.)"' <<<"$scheduled_not_green"
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
      echo "::warning::ci-heartbeat: required and scheduled lanes are green, but an advisory watched lane is red or unknown"
      echo "ci-heartbeat: ADVISORY — sibling scheduled lane evidence is red or unknown (snapshot: $OUT_PATH)"
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
