#!/usr/bin/env bash
# Evidence-gated, serialized tracker state transitions (E5 / T1-T4).
#
# The close auditor stays read-only. This is the deliberately separate mutation
# boundary. Every transition here takes one lock shared by all git worktrees.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON:-python3}"
BR_BIN="${BR_BIN:-br}"

usage() {
  cat <<'EOF'
Usage:
  scripts/bead_tracker_guard.sh close BEAD_ID --evidence PATH --summary TEXT
  scripts/bead_tracker_guard.sh release-claim BEAD_ID
  scripts/bead_tracker_guard.sh correct-false-close --original-bead BEAD_ID \
      --evidence PATH --summary TEXT
  scripts/bead_tracker_guard.sh --selftest

close
  Requires canonical, committed close evidence; clean in-scope paths; and an
  exact source/closing-commit binding. The evidence file must already be in HEAD.
  An open parent epic may be crossed with br --force only when every open
  dependency is parent-child; any real open blocker is still refused.

release-claim
  Changes in_progress to open under the shared transition lock. A bead observed
  closed is preserved as closed; it is never passed to `br update --status open`.

correct-false-close
  Reopens and re-closes the explicitly named ORIGINAL bead with replacement
  evidence. If the re-close fails, the bead remains honestly open.
EOF
}

die() {
  printf 'bead-tracker-guard: %s\n' "$*" >&2
  exit 64
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

validate_bead_id() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
    || die "invalid bead id: $1"
}

validate_summary() {
  [[ -n "$1" ]] || die "--summary must not be empty"
  [[ "$1" != *$'\n'* && "$1" != *$'\r'* ]] \
    || die "--summary must be one line"
  [[ "$1" != *'[closing='* && "$1" != *' evidence='* ]] \
    || die "--summary must not contain close-binding syntax"
}

json_field() {
  local field="$1"
  "$PYTHON_BIN" -c '
import json, sys
field = sys.argv[1]
payload = json.load(sys.stdin)
if isinstance(payload, list):
    rows = payload
elif isinstance(payload, dict) and isinstance(payload.get("issues"), list):
    rows = payload["issues"]
elif isinstance(payload, dict):
    rows = [payload]
else:
    raise SystemExit("unexpected br show JSON shape")
if len(rows) != 1 or not isinstance(rows[0], dict):
    raise SystemExit(f"expected exactly one issue, got {len(rows)}")
value = rows[0].get(field)
if value is not None:
    print(value)
' "$field"
}

tracker_field() {
  local bead_id="$1" field="$2" payload
  payload="$("$BR_BIN" show "$bead_id" --json)"
  printf '%s' "$payload" | json_field "$field"
}

dependency_close_mode() {
  "$PYTHON_BIN" -c '
import json, sys
payload = json.load(sys.stdin)
if isinstance(payload, list):
    rows = payload
elif isinstance(payload, dict) and isinstance(payload.get("issues"), list):
    rows = payload["issues"]
elif isinstance(payload, dict):
    rows = [payload]
else:
    raise SystemExit("unexpected br show JSON shape")
if len(rows) != 1 or not isinstance(rows[0], dict):
    raise SystemExit(f"expected exactly one issue, got {len(rows)}")
open_dependencies = [
    dependency
    for dependency in rows[0].get("dependencies", [])
    if isinstance(dependency, dict) and dependency.get("status") != "closed"
]
real_blockers = [
    dependency
    for dependency in open_dependencies
    if dependency.get("dependency_type") != "parent-child"
]
if real_blockers:
    details = ", ".join(
        "{}({}:{})".format(
            dependency.get("id", "<unknown>"),
            dependency.get("dependency_type", "<unknown>"),
            dependency.get("status", "<unknown>"),
        )
        for dependency in real_blockers
    )
    print(f"refusing open non-parent dependencies: {details}", file=sys.stderr)
    raise SystemExit(65)
print("force-parent-only" if open_dependencies else "normal")
'
}

tracker_close_mode() {
  local bead_id="$1" payload
  payload="$("$BR_BIN" show "$bead_id" --json)"
  printf '%s' "$payload" | dependency_close_mode
}

release_decision() {
  case "$1" in
    in_progress) printf '%s\n' release ;;
    closed) printf '%s\n' preserve-closed ;;
    *) printf '%s\n' no-claim ;;
  esac
}

canonical_evidence_path() {
  "$PYTHON_BIN" -c '
from pathlib import Path
import sys
root = Path(sys.argv[1]).resolve()
candidate = Path(sys.argv[2])
if not candidate.is_absolute():
    candidate = root / candidate
resolved = candidate.resolve(strict=True)
try:
    print(resolved.relative_to(root).as_posix())
except ValueError:
    raise SystemExit("evidence path escapes repository")
' "$ROOT" "$1"
}

source_sha() {
  "$PYTHON_BIN" -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle)["source"]["sha"])
' "$ROOT/$1"
}

parse_evidence_and_summary() {
  EVIDENCE=""
  SUMMARY=""
  while (( $# )); do
    case "$1" in
      --evidence)
        (( $# >= 2 )) || die "--evidence requires a path"
        EVIDENCE="$2"
        shift 2
        ;;
      --summary)
        (( $# >= 2 )) || die "--summary requires text"
        SUMMARY="$2"
        shift 2
        ;;
      *) die "unknown argument: $1" ;;
    esac
  done
  [[ -n "$EVIDENCE" ]] || die "--evidence is required"
  validate_summary "$SUMMARY"
}

acquire_transition_lock() {
  local common_git_dir
  require_command flock
  common_git_dir="$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir)"
  TRACKER_LOCK_PATH="${ORACLEMCP_TRACKER_LOCK:-$common_git_dir/oraclemcp-tracker-guard.lock}"
  exec {TRACKER_LOCK_FD}>"$TRACKER_LOCK_PATH"
  flock -x "$TRACKER_LOCK_FD"
}

prepare_close() {
  local bead_id="$1" evidence_argument="$2"
  EVIDENCE="$(canonical_evidence_path "$evidence_argument")"
  "$PYTHON_BIN" "$ROOT/scripts/audit_bead_closes.py" \
    --pre-close "$bead_id" --evidence "$EVIDENCE"
  SOURCE_SHA="$(source_sha "$EVIDENCE")"
  CLOSING_SHA="$(git -C "$ROOT" rev-parse HEAD)"
  CLOSE_REASON="$SUMMARY [closing=$CLOSING_SHA source=$SOURCE_SHA evidence=$EVIDENCE]"
}

verify_closed() {
  local bead_id="$1" status actual_reason
  status="$(tracker_field "$bead_id" status)"
  [[ "$status" == closed ]] \
    || die "postcondition failed: $bead_id is $status, expected closed"
  actual_reason="$(tracker_field "$bead_id" close_reason)"
  [[ "$actual_reason" == "$CLOSE_REASON" ]] \
    || die "postcondition failed: close_reason does not match the exact commit binding"
}

perform_close() {
  local bead_id="$1" close_mode
  local -a close_args=("$bead_id" --reason "$CLOSE_REASON" --json)
  close_mode="$(tracker_close_mode "$bead_id")"
  case "$close_mode" in
    normal) ;;
    force-parent-only) close_args+=(--force) ;;
    *) die "unexpected dependency close mode: $close_mode" ;;
  esac
  "$BR_BIN" close "${close_args[@]}"
}

close_bead() {
  local bead_id="$1" status
  shift
  validate_bead_id "$bead_id"
  parse_evidence_and_summary "$@"
  acquire_transition_lock
  prepare_close "$bead_id" "$EVIDENCE"
  status="$(tracker_field "$bead_id" status)"
  case "$status" in
    open|in_progress) ;;
    closed) die "$bead_id is already closed; use correct-false-close for a correction" ;;
    *) die "$bead_id is $status; refusing close transition" ;;
  esac
  perform_close "$bead_id"
  verify_closed "$bead_id"
  printf 'bead-tracker-guard: closed %s at %s\n' "$bead_id" "$CLOSING_SHA"
}

release_claim() {
  local bead_id="$1" status decision final_status
  validate_bead_id "$bead_id"
  acquire_transition_lock
  status="$(tracker_field "$bead_id" status)"
  decision="$(release_decision "$status")"
  case "$decision" in
    preserve-closed)
      printf 'bead-tracker-guard: %s is closed; preserved without update\n' "$bead_id"
      return 0
      ;;
    no-claim)
      printf 'bead-tracker-guard: %s is %s; no in-progress claim to release\n' \
        "$bead_id" "$status"
      return 0
      ;;
    release)
      "$BR_BIN" update "$bead_id" --status open --assignee "" --json
      ;;
  esac
  final_status="$(tracker_field "$bead_id" status)"
  [[ "$final_status" == open ]] \
    || die "postcondition failed: $bead_id is $final_status, expected open"
  printf 'bead-tracker-guard: released claim on %s\n' "$bead_id"
}

correct_false_close() {
  local original_bead="" status
  [[ "${1:-}" == --original-bead ]] \
    || die "correct-false-close requires --original-bead BEAD_ID"
  [[ -n "${2:-}" ]] || die "--original-bead requires an id"
  original_bead="$2"
  shift 2
  validate_bead_id "$original_bead"
  parse_evidence_and_summary "$@"
  SUMMARY="CORRECTION: $SUMMARY"
  acquire_transition_lock
  prepare_close "$original_bead" "$EVIDENCE"
  status="$(tracker_field "$original_bead" status)"
  [[ "$status" == closed ]] \
    || die "$original_bead is $status; false-close correction requires the closed original bead"
  "$BR_BIN" reopen "$original_bead" --json
  perform_close "$original_bead"
  verify_closed "$original_bead"
  printf 'bead-tracker-guard: corrected original bead %s at %s\n' \
    "$original_bead" "$CLOSING_SHA"
}

selftest() {
  local status
  status="$(printf '%s' '[{"id":"x","status":"closed"}]' | json_field status)"
  [[ "$status" == closed ]] || die "selftest: list-shaped status parse failed"
  printf 'PASS selftest: list-shaped tracker JSON\n'
  status="$(printf '%s' '{"issues":[{"id":"x","status":"in_progress"}]}' \
    | json_field status)"
  [[ "$status" == in_progress ]] || die "selftest: wrapper-shaped status parse failed"
  printf 'PASS selftest: wrapper-shaped tracker JSON\n'
  [[ "$(release_decision closed)" == preserve-closed ]] \
    || die "selftest: closed issue would be released"
  printf 'PASS selftest: observed closed state is preserved\n'
  [[ "$(release_decision in_progress)" == release ]] \
    || die "selftest: in-progress claim was not releasable"
  printf 'PASS selftest: in-progress claim is releasable\n'
  status="$(printf '%s' \
    '[{"id":"child","dependencies":[{"id":"parent","status":"open","dependency_type":"parent-child"}]}]' \
    | dependency_close_mode)"
  [[ "$status" == force-parent-only ]] \
    || die "selftest: open parent-child dependency was not narrowly forceable"
  printf 'PASS selftest: open parent epic is narrowly forceable\n'
  if printf '%s' \
    '[{"id":"child","dependencies":[{"id":"blocker","status":"open","dependency_type":"blocks"}]}]' \
    | dependency_close_mode >/dev/null 2>&1; then
    die "selftest: real open blocker was accepted"
  fi
  printf 'PASS selftest: real open blocker is refused\n'
}

command_name="${1:-}"
case "$command_name" in
  --selftest)
    require_command "$PYTHON_BIN"
    selftest
    ;;
  close)
    (( $# >= 2 )) || die "close requires BEAD_ID"
    require_command "$PYTHON_BIN"
    require_command "$BR_BIN"
    close_bead "$2" "${@:3}"
    ;;
  release-claim)
    [[ $# -eq 2 ]] || die "release-claim requires exactly one BEAD_ID"
    require_command "$PYTHON_BIN"
    require_command "$BR_BIN"
    release_claim "$2"
    ;;
  correct-false-close)
    require_command "$PYTHON_BIN"
    require_command "$BR_BIN"
    correct_false_close "${@:2}"
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage >&2
    exit 64
    ;;
esac
