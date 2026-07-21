#!/usr/bin/env bash
# D3 / TRI-2 — deterministic, OOM-honest mutation shards.
# (bead oraclemcp-eng-program-bp8ia.5.3; plan §27.2 C3 / §32.2 TRI-2.)
#
# The runner covers guard, audit, core, db, and the server dispatch module. It
# runs exactly one deterministic cargo-mutants shard at -j1. The shard has a
# hard mutant-count budget, an enforced cgroup MemoryMax/TasksMax, and
# OOMPolicy=continue. The wrapper reads the shard cgroup's memory.events before
# and after cargo-mutants. Any oom_kill delta grades the SHARD `errored`; its
# cargo-mutants counters are never allowed into a seal (a killed test process
# can otherwise be misreported as a caught mutant).
#
# A complete campaign is assembled by `migrate_mutation_result.py`, which
# verifies the integrity sidecar for every shard, rejects OOM/error/incomplete
# shards, and proves that each scope has every index 1..N with a duplicate-free
# mutant population equal to the declared full count. Timeouts remain separate
# evidence and are NEVER promoted to confirmed-test-failure kills.
#
# Subcommands:
#   run-shard     run one deterministic shard:
#                 --scope guard|audit|core|db|dispatch --shard I/N
#   check-report  cheap: parse the committed report (docs/quality/mutation-safety.md)
#                 and fail closed unless its v2 marker proves a complete,
#                 OOM-free, current five-surface seal above the floor.
#                 Called by scripts/release_preflight.sh so the tag is gated by
#                 committed evidence without rerunning a mutation campaign.
#   check-floor-report
#                 cheap D2 gate: require the independent guard/audit/db floor
#                 report to describe a complete current exact-SHA campaign,
#                 with per-crate counts, floors, hashes, and zero OOM/task hits.
#   self-test     DB/build-free marker acceptance and stale-hash rejection.
#   __capped      internal cgroup wrapper; not an operator entry point.
#
# ─────────────────────────────────────────────────────────────────────────────
# CORRECTNESS TRAP (do not "optimize" away): this lane is fixed at -j1 and
# unsets CARGO_TARGET_DIR. Concurrent mutants sharing incremental artifacts have
# already produced false survivors. `--copy-target=false` ensures each
# cargo-mutants build directory owns its target; a scheduled workflow obtains
# parallelism only from isolated runner VMs, never within one shard.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

TIMEOUT="${MUTATION_TIMEOUT:-120}"
MEMMAX="${MUTATION_MEMMAX:-12G}"
TASKSMAX="${MUTATION_TASKSMAX:-8192}"
MAX_MUTANTS="${MUTATION_MAX_MUTANTS_PER_SHARD:-32}"
OUTPUT_BASE="${MUTATION_OUTPUT:-$ROOT/target/mutants}"
SCRATCH_BASE="${MUTATION_SCRATCH:-$ROOT/target/mutation-scratch}"
REPORT="${MUTATION_REPORT:-$ROOT/docs/quality/mutation-safety.md}"
FLOOR_REPORT="${MUTATION_FLOOR_REPORT:-$ROOT/docs/quality/mutation-safety-d2.md}"
SCOPE=""
SHARD=""

die() { echo "mutation-gate: $*" >&2; exit 1; }

scope_package() {
  case "$1" in
    guard) echo oraclemcp-guard ;;
    audit) echo oraclemcp-audit ;;
    core) echo oraclemcp-core ;;
    db) echo oraclemcp-db ;;
    dispatch) echo oraclemcp ;;
    *) die "unknown scope '$1' (expected guard | audit | core | db | dispatch)" ;;
  esac
}

scope_file() {
  case "$1" in
    guard) echo 'crates/oraclemcp-guard/src/**/*.rs' ;;
    audit) echo 'crates/oraclemcp-audit/src/**/*.rs' ;;
    core) echo 'crates/oraclemcp-core/src/**/*.rs' ;;
    db) echo 'crates/oraclemcp-db/src/**/*.rs' ;;
    dispatch) echo 'crates/oraclemcp/src/dispatch/*.rs' ;;
    *) die "unknown scope '$1'" ;;
  esac
}

parse_shard() {
  [[ "$SHARD" =~ ^([1-9][0-9]*)/([1-9][0-9]*)$ ]] ||
    die "--shard must be I/N with positive integers (got '$SHARD')"
  SHARD_INDEX="${BASH_REMATCH[1]}"
  SHARD_TOTAL="${BASH_REMATCH[2]}"
  [ "$SHARD_INDEX" -le "$SHARD_TOTAL" ] || die "shard index exceeds total: $SHARD"
}

scope_state() { # <scope-csv> [git-ref] -> "count digest"
  python3 - "$1" "${2:-}" <<'PY'
import hashlib
import subprocess
import sys
from pathlib import Path

roots = {
    "guard": "crates/oraclemcp-guard/src",
    "audit": "crates/oraclemcp-audit/src",
    "core": "crates/oraclemcp-core/src",
    "db": "crates/oraclemcp-db/src",
    "dispatch": "crates/oraclemcp/src/dispatch",
}
selected = sys.argv[1].split(",")
git_ref = sys.argv[2]
try:
    requested = [roots[name] for name in selected]
except KeyError as error:
    raise SystemExit(f"mutation-gate: unknown marker scope: {error.args[0]}")
if git_ref:
    paths = subprocess.check_output(
        ["git", "ls-tree", "-r", "--name-only", git_ref, "--", *requested], text=True
    ).splitlines()
else:
    paths = subprocess.check_output(
        ["git", "ls-files", "--", *requested], text=True
    ).splitlines()
paths = sorted(path for path in paths if path.endswith(".rs"))
digest = hashlib.sha256()
for name in paths:
    content = (
        subprocess.check_output(["git", "show", f"{git_ref}:{name}"])
        if git_ref
        else Path(name).read_bytes()
    )
    content_hash = hashlib.sha256(content).hexdigest()
    digest.update(name.encode())
    digest.update(b"\0")
    digest.update(content_hash.encode())
    digest.update(b"\n")
print(len(paths), digest.hexdigest())
PY
}

# Internal entry: execute a command in the already-created cgroup and preserve
# the cgroup's oom_kill delta even when cargo-mutants returns non-zero. The
# wrapper itself exits zero after writing status; a missing status file means
# the controller/wrapper died and is therefore an error, never a verdict.
cmd_capped() {
  local status_file="$1"; shift
  local cgroup_path events pid_events before after pid_before pid_after rc memory_max pid_max
  cgroup_path="$(awk -F: '$1 == "0" {print $3}' /proc/self/cgroup)"
  [ -n "$cgroup_path" ] || die "cannot locate cgroup-v2 path"
  events="/sys/fs/cgroup${cgroup_path}/memory.events"
  pid_events="/sys/fs/cgroup${cgroup_path}/pids.events"
  [ -r "$events" ] || die "cannot read cgroup memory events: $events"
  [ -r "$pid_events" ] || die "cannot read cgroup PID events: $pid_events"
  before="$(awk '$1 == "oom_kill" {print $2}' "$events")"
  pid_before="$(awk '$1 == "max" {print $2}' "$pid_events")"
  [ -n "$before" ] || die "memory.events has no oom_kill counter: $events"
  [ -n "$pid_before" ] || die "pids.events has no max counter: $pid_events"
  memory_max="$(<"/sys/fs/cgroup${cgroup_path}/memory.max")"
  pid_max="$(<"/sys/fs/cgroup${cgroup_path}/pids.max")"
  [[ "$memory_max" =~ ^[1-9][0-9]*$ ]] || die "cgroup MemoryMax is not enforced: $memory_max"
  [[ "$pid_max" =~ ^[1-9][0-9]*$ ]] || die "cgroup TasksMax is not enforced: $pid_max"
  set +e
  "$@"
  rc=$?
  set -e
  after="$(awk '$1 == "oom_kill" {print $2}' "$events")"
  pid_after="$(awk '$1 == "max" {print $2}' "$pid_events")"
  printf 'command_exit=%s\nmemory_max_bytes=%s\npid_task_max=%s\npid_max_before=%s\npid_max_after=%s\npid_max_delta=%s\noom_kill_before=%s\noom_kill_after=%s\noom_kill_delta=%s\n' \
    "$rc" "$memory_max" "$pid_max" "$pid_before" "$pid_after" "$((pid_after - pid_before))" \
    "$before" "$after" "$((after - before))" >"$status_file"
}

write_integrity() { # <path> <status> <outcomes-or-empty> <inventory> <full-inventory> <cgroup-status> <scratch> <scratch-fs>
  local integrity="$1" status="$2" outcomes="$3" inventory="$4" full_inventory="$5" cgroup_status="$6"
  local scratch="$7" scratch_fs="$8"
  local source_sha state file_count scope_hash
  source_sha="$(git rev-parse HEAD)"
  state="$(scope_state "$SCOPE")"
  file_count="${state%% *}"
  scope_hash="${state##* }"
  python3 - "$integrity" "$status" "$outcomes" "$inventory" "$full_inventory" \
    "$cgroup_status" "$SCOPE" "$SHARD_INDEX" "$SHARD_TOTAL" "$source_sha" \
    "$file_count" "$scope_hash" "$(cargo mutants --version)" "$scratch" "$scratch_fs" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

(
    output, status, outcomes_name, inventory_name, full_inventory_name,
    cgroup_name, scope, shard_index, shard_total, source_sha,
    covered_file_count, scope_sha256, tool_version, scratch_path, scratch_filesystem,
) = sys.argv[1:]
inventory = json.loads(Path(inventory_name).read_text())
full_inventory = json.loads(Path(full_inventory_name).read_text())
cgroup = {}
if Path(cgroup_name).is_file():
    for line in Path(cgroup_name).read_text().splitlines():
        key, value = line.split("=", 1)
        cgroup[key] = int(value)
outcomes_sha256 = None
if outcomes_name and Path(outcomes_name).is_file():
    outcomes_sha256 = hashlib.sha256(Path(outcomes_name).read_bytes()).hexdigest()
doc = {
    "schema": "mutation-shard-integrity/v1",
    "scope": scope,
    "shard_index": int(shard_index),
    "shard_total": int(shard_total),
    "status": status,
    "source_sha": source_sha,
    "covered_file_count": int(covered_file_count),
    "scope_sha256": scope_sha256,
    "campaign_mutant_total": len(full_inventory),
    "mutant_count": len(inventory),
    "mutant_ids": [mutant["name"] for mutant in inventory],
    "outcomes_sha256": outcomes_sha256,
    "oom_kill_delta": cgroup.get("oom_kill_delta"),
    "command_exit": cgroup.get("command_exit"),
    "memory_max_bytes": cgroup.get("memory_max_bytes"),
    "pid_task_max": cgroup.get("pid_task_max"),
    "pid_max_delta": cgroup.get("pid_max_delta"),
    "oom_policy": "continue",
    "cargo_mutants_version": tool_version,
    "scratch_path": scratch_path,
    "scratch_filesystem": scratch_filesystem,
    "rustc_wrapper_disabled": True,
}
Path(output).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
PY
}

cmd_run_shard() {
  command -v cargo-mutants >/dev/null 2>&1 ||
    die "cargo-mutants not installed (cargo install cargo-mutants --version 27.1.0 --locked)"
  command -v jq >/dev/null 2>&1 || die "jq is required"
  command -v systemd-run >/dev/null 2>&1 ||
    die "systemd-run is required; refusing an unbounded mutation shard"
  [ -n "$SCOPE" ] || die "run-shard requires --scope"
  [ -n "$SHARD" ] || die "run-shard requires --shard I/N"
  parse_shard
  if ! git diff --quiet -- || ! git diff --cached --quiet --; then
    die "run-shard requires a clean tracked tree so its source SHA is reproducible"
  fi

  local package file out inventory full_inventory run_log cgroup_status outcomes integrity scratch scratch_fs
  package="$(scope_package "$SCOPE")"
  file="$(scope_file "$SCOPE")"
  out="$OUTPUT_BASE/$SCOPE/shard-${SHARD_INDEX}of${SHARD_TOTAL}"
  [ ! -e "$out" ] || die "output already exists; preserve it and choose a new MUTATION_OUTPUT: $out"
  mkdir -p "$out"
  inventory="$out/mutants.json"
  full_inventory="$out/mutants-full.json"
  run_log="$out/run.log"
  cgroup_status="$out/cgroup.status"
  integrity="$out/integrity.json"
  scratch="$SCRATCH_BASE/$SCOPE/shard-${SHARD_INDEX}of${SHARD_TOTAL}"
  [ ! -e "$scratch" ] || die "scratch already exists; preserve it and choose a new MUTATION_SCRATCH: $scratch"
  mkdir -p "$scratch"
  command -v findmnt >/dev/null 2>&1 || die "findmnt is required to verify mutation scratch storage"
  scratch_fs="$(findmnt -n -o FSTYPE --target "$scratch" | head -1)"
  [ -n "$scratch_fs" ] || die "cannot determine scratch filesystem: $scratch"
  case "$scratch_fs" in
    tmpfs|ramfs) die "mutation scratch must be disk-backed, not $scratch_fs: $scratch" ;;
  esac

  cargo mutants -p "$package" --file "$file" --list --json --no-shuffle >"$full_inventory"
  cargo mutants -p "$package" --file "$file" --list --json --no-shuffle \
    --shard "$SHARD" >"$inventory"
  local selected
  selected="$(jq 'length' "$inventory")"
  [ "$selected" -gt 0 ] || die "$SCOPE shard $SHARD selected zero mutants"
  [ "$selected" -le "$MAX_MUTANTS" ] ||
    die "$SCOPE shard $SHARD selects $selected mutants, above deterministic budget $MAX_MUTANTS; increase N"

  echo "mutation-gate: scope=$SCOPE shard=$SHARD mutants=$selected max=$MAX_MUTANTS j=1 timeout=${TIMEOUT}s memory=$MEMMAX tasks=$TASKSMAX scratch_fs=$scratch_fs" >&2
  set +e
  systemd-run --user --scope --quiet --collect \
    -p "MemoryMax=$MEMMAX" -p MemorySwapMax=0 -p "TasksMax=$TASKSMAX" \
    -p OOMPolicy=continue -- \
    "$ROOT/scripts/mutation_safety_gate.sh" __capped "$cgroup_status" \
    env -u CARGO_TARGET_DIR RUSTC_WRAPPER= RUSTC_WORKSPACE_WRAPPER= \
      SCCACHE_DISABLE=1 TMPDIR="$scratch" CARGO_BUILD_JOBS=2 cargo mutants -p "$package" \
      --file "$file" --no-shuffle --shard "$SHARD" -j 1 \
      --copy-target=false --timeout "$TIMEOUT" --no-times --output "$out" \
      >"$run_log" 2>&1
  local wrapper_rc=$?
  set -e
  outcomes="$out/mutants.out/outcomes.json"
  if [ "$wrapper_rc" -ne 0 ] || [ ! -f "$cgroup_status" ]; then
    write_integrity "$integrity" errored "" "$inventory" "$full_inventory" "$cgroup_status" "$scratch" "$scratch_fs"
    die "$SCOPE shard $SHARD controller failed before a complete cgroup status was recorded (rc=$wrapper_rc)"
  fi
  local oom_delta
  oom_delta="$(awk -F= '$1 == "oom_kill_delta" {print $2}' "$cgroup_status")"
  if [ -z "$oom_delta" ] || [ "$oom_delta" -ne 0 ]; then
    write_integrity "$integrity" errored "$outcomes" "$inventory" "$full_inventory" "$cgroup_status" "$scratch" "$scratch_fs"
    die "E_OOM_MUTANT: $SCOPE shard $SHARD observed oom_kill delta ${oom_delta:-unknown}; graded ERRORED, never caught"
  fi
  local pid_delta
  pid_delta="$(awk -F= '$1 == "pid_max_delta" {print $2}' "$cgroup_status")"
  if [ -z "$pid_delta" ] || [ "$pid_delta" -ne 0 ]; then
    write_integrity "$integrity" errored "$outcomes" "$inventory" "$full_inventory" "$cgroup_status" "$scratch" "$scratch_fs"
    die "E_TASK_CAP: $SCOPE shard $SHARD hit TasksMax ${pid_delta:-unknown} time(s); graded ERRORED, never caught"
  fi
  [ -f "$outcomes" ] || {
    write_integrity "$integrity" incomplete "" "$inventory" "$full_inventory" "$cgroup_status" "$scratch" "$scratch_fs"
    die "$SCOPE shard $SHARD produced no outcomes.json"
  }
  jq -e '.end_time != null' "$outcomes" >/dev/null || {
    write_integrity "$integrity" incomplete "$outcomes" "$inventory" "$full_inventory" "$cgroup_status" "$scratch" "$scratch_fs"
    die "$SCOPE shard $SHARD has null end_time; partial counters cannot seal"
  }
  local accounted
  accounted="$(jq '.caught + .missed + .timeout + .unviable' "$outcomes")"
  [ "$accounted" -eq "$selected" ] || {
    write_integrity "$integrity" incomplete "$outcomes" "$inventory" "$full_inventory" "$cgroup_status" "$scratch" "$scratch_fs"
    die "$SCOPE shard $SHARD accounts for $accounted/$selected mutants; partial counters cannot seal"
  }
  write_integrity "$integrity" complete "$outcomes" "$inventory" "$full_inventory" "$cgroup_status" "$scratch" "$scratch_fs"
  echo "mutation-gate: COMPLETE scope=$SCOPE shard=$SHARD mutants=$selected integrity=$integrity"
}

# Parse the machine-readable v2 marker. A percentage alone is not a seal: the
# marker also binds the covered files, population, complete shard count, and
# OOM total. Legacy/advisory/stale/partial markers fail closed.
cmd_check_report() {
  [ -f "$REPORT" ] || die "committed mutation report missing: $REPORT"
  local marker
  marker="$(grep -oE '<!-- MUTATION-GATE [^>]*-->' "$REPORT" | tail -1)" \
    || die "report $REPORT has no MUTATION-GATE marker"
  marker_value() {
    local key="$1" value
    value="$(grep -oE "(^|[[:space:]])${key}=[^[:space:]]+" <<<"${marker#<!-- MUTATION-GATE }" | head -1 | sed -E "s/^[[:space:]]*${key}=//")"
    [ -n "$value" ] || die "v2 report marker is missing $key"
    printf '%s\n' "$value"
  }
  local version source scopes recorded_hash files mutants shards oom thresh status
  version="$(marker_value v)"
  source="$(marker_value source)"
  scopes="$(marker_value scopes)"
  recorded_hash="$(marker_value scope_sha256)"
  files="$(marker_value covered_files)"
  mutants="$(marker_value mutants)"
  shards="$(marker_value shards)"
  oom="$(marker_value oom)"
  thresh="$(marker_value threshold)"
  status="$(marker_value status)"
  [ "$version" = 2 ] || die "unsupported mutation marker version: $version"
  echo "mutation-gate: marker v=2 source=$source scopes=$scopes files=$files mutants=$mutants shards=$shards oom=$oom status=$status"
  if [ "$status" != "enforcing" ]; then
    # Z2 (the fresh five-surface campaign) is deferred out of the 0.9.1 train
    # (plan v7 §Z2): a seal binds to a source SHA and re-stales on every safety-crate
    # fix, so it is produced ONCE on the release candidate. ALLOW_STALE_MUTATION_SEAL
    # is set for per-push development CI only (ci.yml) — the release path
    # (release.yml / docker.yml / publish-mcp.yml) does NOT set it, so an actual
    # release still hard-fails without a fresh seal.
    if [ "${ALLOW_STALE_MUTATION_SEAL:-0}" = 1 ]; then
      echo "mutation-gate: WARNING E_STALE_SEAL deferred (status=$status) — ALLOW_STALE_MUTATION_SEAL set; the fresh seal is a release-candidate gate (plan v7 §Z2), enforced on the release path, not per-push." >&2
      return 0
    fi
    die "E_STALE_SEAL: committed mutation marker status=$status; a fresh complete five-surface campaign is required"
  fi
  [[ "$source" =~ ^[0-9a-f]{40}$ ]] || die "enforcing marker has invalid source SHA"
  [ "$scopes" = "guard,audit,core,db,dispatch" ] ||
    die "enforcing marker scope is incomplete: $scopes"
  [[ "$recorded_hash" =~ ^[0-9a-f]{64}$ ]] || die "enforcing marker has invalid scope_sha256"
  [[ "$files" =~ ^[1-9][0-9]*$ ]] || die "enforcing marker has invalid covered_files"
  [[ "$mutants" =~ ^[1-9][0-9]*$ ]] || die "enforcing marker has invalid mutant count"
  [[ "$shards" =~ ^([1-9][0-9]*)/([1-9][0-9]*)$ ]] || die "enforcing marker has invalid shards"
  [ "${BASH_REMATCH[1]}" -eq "${BASH_REMATCH[2]}" ] || die "E_SHARD_INCOMPLETE: marker shards=$shards"
  [ "$oom" = 0 ] || die "E_OOM_MUTANT: enforcing marker records oom=$oom"
  local sealed_state sealed_files sealed_hash current_state current_files current_hash
  git cat-file -e "$source^{commit}" 2>/dev/null || die "enforcing marker source commit does not exist: $source"
  sealed_state="$(scope_state "$scopes" "$source")"
  sealed_files="${sealed_state%% *}"
  sealed_hash="${sealed_state##* }"
  [ "$sealed_files" -eq "$files" ] ||
    die "E_SEAL_SOURCE_MISMATCH: source commit has $sealed_files files, marker records $files"
  [ "$sealed_hash" = "$recorded_hash" ] ||
    die "E_SEAL_SOURCE_MISMATCH: marker hash does not describe source $source"
  current_state="$(scope_state "$scopes")"
  current_files="${current_state%% *}"
  current_hash="${current_state##* }"
  [ "$current_files" -eq "$files" ] ||
    die "E_STALE_SCOPE: covered file count changed (sealed=$files current=$current_files)"
  [ "$current_hash" = "$recorded_hash" ] ||
    die "E_STALE_SCOPE: covered-file hash changed (sealed=$recorded_hash current=$current_hash)"
  local scope value
  for scope in guard audit core db dispatch; do
    value="$(marker_value "$scope")"
    [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "$scope has no numeric confirmed-failure rate"
    awk -v rate="$value" -v floor="$thresh" 'BEGIN { exit !(rate + 0 < floor + 0) }' &&
      die "$scope confirmed-failure rate ${value}% is below the enforcing floor ${thresh}%"
  done
  echo "mutation-gate: OK — complete OOM-free five-surface seal is current and meets ${thresh}%"
}

# D2 intentionally has a narrower seal than D3: the ratchet's literal contract
# is guard/audit/db, while D3 remains red until core and dispatch are also
# complete. Both use the same shard integrity mechanism and confirmed-failure
# denominator; neither can borrow partial or OOM-affected counters from the other.
cmd_check_floor_report() {
  # The whole D2 mutation-floor enforcement is deferred with Z2 (plan v7 §Z2):
  # the fresh five-surface campaign that produces both the floor report and its
  # enforcing seal is a release-candidate gate, not per-push. Set for per-push CI
  # only (ci.yml); the release path does not set it and therefore still enforces.
  if [ "${ALLOW_STALE_MUTATION_SEAL:-0}" = 1 ]; then
    echo "mutation-gate: WARNING D2 mutation-floor check deferred — ALLOW_STALE_MUTATION_SEAL set; the floor report + seal are a release-candidate gate (plan v7 §Z2), enforced on the release path, not per-push." >&2
    return 0
  fi
  [ -f "$FLOOR_REPORT" ] || die "committed D2 mutation-floor report missing: $FLOOR_REPORT"
  local marker
  marker="$(grep -oE '<!-- MUTATION-FLOOR [^>]*-->' "$FLOOR_REPORT" | tail -1)" \
    || die "report $FLOOR_REPORT has no MUTATION-FLOOR marker"
  marker_value() {
    local key="$1" value
    value="$(grep -oE "(^|[[:space:]])${key}=[^[:space:]]+" <<<"${marker#<!-- MUTATION-FLOOR }" | head -1 | sed -E "s/^[[:space:]]*${key}=//")"
    [ -n "$value" ] || die "D2 mutation-floor marker is missing $key"
    printf '%s\n' "$value"
  }

  local version source declared_scopes mutants shards oom task_cap status
  version="$(marker_value v)"
  source="$(marker_value source)"
  declared_scopes="$(marker_value scopes)"
  mutants="$(marker_value mutants)"
  shards="$(marker_value shards)"
  oom="$(marker_value oom)"
  task_cap="$(marker_value task_cap)"
  status="$(marker_value status)"
  [ "$version" = 1 ] || die "unsupported D2 mutation-floor marker version: $version"
  if [ "$status" != enforcing ]; then
    # See the check-report note above — the fresh seal is a release-candidate gate
    # (plan v7 §Z2), deferred for per-push CI, enforced on the release path.
    if [ "${ALLOW_STALE_MUTATION_SEAL:-0}" = 1 ]; then
      echo "mutation-gate: WARNING E_STALE_SEAL (D2 floor) deferred (status=$status) — ALLOW_STALE_MUTATION_SEAL set; enforced on the release path, not per-push." >&2
      return 0
    fi
    die "E_STALE_SEAL: D2 mutation-floor marker status=$status"
  fi
  [[ "$source" =~ ^[0-9a-f]{40}$ ]] || die "D2 enforcing marker has invalid source SHA"
  [ "$declared_scopes" = guard,audit,db ] ||
    die "D2 enforcing marker scope is incomplete: $declared_scopes"
  [[ "$mutants" =~ ^[1-9][0-9]*$ ]] || die "D2 enforcing marker has invalid mutant count"
  [[ "$shards" =~ ^([1-9][0-9]*)/([1-9][0-9]*)$ ]] ||
    die "D2 enforcing marker has invalid shard count"
  [ "${BASH_REMATCH[1]}" -eq "${BASH_REMATCH[2]}" ] ||
    die "E_SHARD_INCOMPLETE: D2 marker shards=$shards"
  [ "$oom" = 0 ] || die "E_OOM_MUTANT: D2 marker records oom=$oom"
  [ "$task_cap" = 0 ] || die "E_TASK_CAP: D2 marker records task_cap=$task_cap"
  git cat-file -e "$source^{commit}" 2>/dev/null ||
    die "D2 enforcing marker source commit does not exist: $source"

  local total_mutants=0 total_shards=0
  local scope rate floor caught missed timeout unviable scope_mutants scope_shards scope_shard_count
  local files recorded_hash sealed_state sealed_files sealed_hash current_state current_files current_hash
  for scope in guard audit db; do
    rate="$(marker_value "${scope}_rate")"
    floor="$(marker_value "${scope}_floor")"
    caught="$(marker_value "${scope}_caught")"
    missed="$(marker_value "${scope}_missed")"
    timeout="$(marker_value "${scope}_timeout")"
    unviable="$(marker_value "${scope}_unviable")"
    scope_mutants="$(marker_value "${scope}_mutants")"
    scope_shards="$(marker_value "${scope}_shards")"
    files="$(marker_value "${scope}_files")"
    recorded_hash="$(marker_value "${scope}_sha256")"

    [[ "$rate" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "$scope has no numeric confirmed-failure rate"
    [[ "$floor" =~ ^[0-9]+([.][0-9]+)?$ ]] || die "$scope has no numeric mutation floor"
    for value in "$caught" "$missed" "$timeout" "$unviable"; do
      [[ "$value" =~ ^[0-9]+$ ]] || die "$scope marker has a non-numeric outcome count"
    done
    [[ "$scope_mutants" =~ ^[1-9][0-9]*$ ]] || die "$scope marker has invalid mutant count"
    [[ "$scope_shards" =~ ^([1-9][0-9]*)/([1-9][0-9]*)$ ]] ||
      die "$scope marker has invalid shard count"
    [ "${BASH_REMATCH[1]}" -eq "${BASH_REMATCH[2]}" ] ||
      die "E_SHARD_INCOMPLETE: $scope marker shards=$scope_shards"
    scope_shard_count="${BASH_REMATCH[1]}"
    [[ "$files" =~ ^[1-9][0-9]*$ ]] || die "$scope marker has invalid covered-file count"
    [[ "$recorded_hash" =~ ^[0-9a-f]{64}$ ]] || die "$scope marker has invalid scope hash"

    python3 - "$scope" "$rate" "$floor" "$caught" "$missed" "$timeout" "$unviable" "$scope_mutants" <<'PY'
import math
import sys

scope, rate_text, floor_text, caught, missed, timeout, unviable, mutants = sys.argv[1:]
rate = float(rate_text)
floor = float(floor_text)
counts = [int(caught), int(missed), int(timeout), int(unviable)]
mutant_total = int(mutants)
if sum(counts) != mutant_total:
    raise SystemExit(
        f"mutation-gate: {scope} counts account for {sum(counts)}/{mutant_total} mutants"
    )
denominator = counts[0] + counts[1] + counts[2]
if denominator == 0:
    raise SystemExit(f"mutation-gate: {scope} has an empty confirmed-failure denominator")
expected = 100.0 * counts[0] / denominator
if not math.isclose(rate, expected, rel_tol=0.0, abs_tol=0.0000005):
    raise SystemExit(
        f"mutation-gate: {scope} rate {rate}% disagrees with counts ({expected:.6f}%)"
    )
if rate < floor:
    raise SystemExit(
        f"mutation-gate: {scope} confirmed-failure rate {rate}% is below its floor {floor}%"
    )
PY

    sealed_state="$(scope_state "$scope" "$source")"
    sealed_files="${sealed_state%% *}"
    sealed_hash="${sealed_state##* }"
    [ "$sealed_files" -eq "$files" ] ||
      die "E_SEAL_SOURCE_MISMATCH: $scope source has $sealed_files files, marker records $files"
    [ "$sealed_hash" = "$recorded_hash" ] ||
      die "E_SEAL_SOURCE_MISMATCH: $scope marker hash does not describe source $source"
    current_state="$(scope_state "$scope")"
    current_files="${current_state%% *}"
    current_hash="${current_state##* }"
    [ "$current_files" -eq "$files" ] ||
      die "E_STALE_SCOPE: $scope covered-file count changed (sealed=$files current=$current_files)"
    [ "$current_hash" = "$recorded_hash" ] ||
      die "E_STALE_SCOPE: $scope covered-file hash changed (sealed=$recorded_hash current=$current_hash)"

    total_mutants=$((total_mutants + scope_mutants))
    total_shards=$((total_shards + scope_shard_count))
    echo "mutation-gate: D2 $scope ${rate}% >= ${floor}% (mutants=$scope_mutants shards=$scope_shards)"
  done
  [ "$total_mutants" -eq "$mutants" ] ||
    die "D2 aggregate mutant count mismatch: scopes=$total_mutants marker=$mutants"
  [ "$total_shards" -eq "${shards%/*}" ] ||
    die "D2 aggregate shard count mismatch: scopes=$total_shards marker=$shards"
  echo "mutation-gate: OK — current exact-SHA guard/audit/db floor seal is complete and OOM-free"
}

cmd_self_test() {
  local work state files hash source good bad stale_output fixture output scope
  work="$(mktemp -d /var/tmp/oraclemcp-mutation-gate-self-test.XXXXXX)"
  state="$(scope_state guard,audit,core,db,dispatch)"
  files="${state%% *}"
  hash="${state##* }"
  source="$(git rev-parse HEAD)"
  good="$work/enforcing.md"
  bad="$work/stale-scope.md"
  printf '<!-- MUTATION-GATE v=2 source=%s scopes=guard,audit,core,db,dispatch scope_sha256=%s covered_files=%s mutants=1 shards=1/1 oom=0 guard=95 audit=95 core=95 db=95 dispatch=95 threshold=90 status=enforcing -->\n' \
    "$source" "$hash" "$files" >"$good"
  printf '<!-- MUTATION-GATE v=2 source=%s scopes=guard,audit,core,db,dispatch scope_sha256=%064d covered_files=%s mutants=1 shards=1/1 oom=0 guard=95 audit=95 core=95 db=95 dispatch=95 threshold=90 status=enforcing -->\n' \
    "$source" 0 "$files" >"$bad"
  "$ROOT/scripts/mutation_safety_gate.sh" check-report --report "$good" >/dev/null
  if stale_output="$("$ROOT/scripts/mutation_safety_gate.sh" check-report --report "$bad" 2>&1)"; then
    die "self-test accepted a stale covered-file hash"
  fi
  [[ "$stale_output" == *E_SEAL_SOURCE_MISMATCH* ]] ||
    die "self-test stale marker failed for the wrong reason: $stale_output"

  local guard_state audit_state db_state guard_files guard_hash audit_files audit_hash db_files db_hash
  guard_state="$(scope_state guard)"; guard_files="${guard_state%% *}"; guard_hash="${guard_state##* }"
  audit_state="$(scope_state audit)"; audit_files="${audit_state%% *}"; audit_hash="${audit_state##* }"
  db_state="$(scope_state db)"; db_files="${db_state%% *}"; db_hash="${db_state##* }"
  for fixture in "$ROOT"/tests/fixtures/coverage_ratchet/mutation-floor-*.md.in; do
    output="$work/$(basename "${fixture%.in}")"
    sed -e "s/@SOURCE@/$source/g" \
      -e "s/@GUARD_FILES@/$guard_files/g" -e "s/@GUARD_HASH@/$guard_hash/g" \
      -e "s/@AUDIT_FILES@/$audit_files/g" -e "s/@AUDIT_HASH@/$audit_hash/g" \
      -e "s/@DB_FILES@/$db_files/g" -e "s/@DB_HASH@/$db_hash/g" \
      "$fixture" >"$output"
    case "$(basename "$fixture")" in
      mutation-floor-valid.md.in)
        "$ROOT/scripts/mutation_safety_gate.sh" check-floor-report --report "$output" >/dev/null
        ;;
      mutation-floor-low-guard.md.in) scope=guard ;;
      mutation-floor-low-audit.md.in) scope=audit ;;
      mutation-floor-low-db.md.in) scope=db ;;
      *) die "unexpected D2 mutation-floor fixture: $fixture" ;;
    esac
    if [ "$(basename "$fixture")" != mutation-floor-valid.md.in ]; then
      if stale_output="$("$ROOT/scripts/mutation_safety_gate.sh" check-floor-report --report "$output" 2>&1)"; then
        die "self-test accepted the lowered $scope mutation floor fixture"
      fi
      [[ "$stale_output" == *"$scope confirmed-failure rate"* ]] ||
        die "lowered $scope fixture failed for the wrong reason: $stale_output"
    fi
  done
  echo "mutation-gate: self-test OK (D3 stale-hash rejection + D2 valid pass and lowered guard/audit/db failures; fixtures=$work)"
}

sub="${1:-check-report}"; shift || true
if [ "$sub" = "__capped" ]; then
  cmd_capped "$@"
  exit 0
fi
while [ "$#" -gt 0 ]; do
  case "$1" in
    --timeout) TIMEOUT="$2"; shift ;;
    --output) OUTPUT_BASE="$2"; shift ;;
    --report) REPORT="$2"; shift ;;
    --floor-report) FLOOR_REPORT="$2"; shift ;;
    --scope) SCOPE="$2"; shift ;;
    --shard) SHARD="$2"; shift ;;
    --max-mutants) MAX_MUTANTS="$2"; shift ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done

case "$sub" in
  run-shard) cmd_run_shard ;;
  check-report) cmd_check_report ;;
  check-floor-report)
    [ "$REPORT" = "$ROOT/docs/quality/mutation-safety.md" ] || FLOOR_REPORT="$REPORT"
    cmd_check_floor_report
    ;;
  self-test) cmd_self_test ;;
  *) die "unknown subcommand '$sub' (expected: run-shard | check-report | check-floor-report | self-test)" ;;
esac
