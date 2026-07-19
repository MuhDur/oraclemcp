#!/usr/bin/env bash
# Run a heavy command under a declared, ENFORCED resource budget (bead yg4x.9).
#
#   scripts/resource_budget.sh --profile build -- cargo test --workspace
#   scripts/resource_budget.sh --profile mutants --emit-budget   # JSON only, runs nothing
#
# Why this exists
# ---------------
# Three incidents, one shape: a heavy run helps itself to the whole box.
#
#   ~40GB RSS global OOM.
#   cargo-mutants fanned out to ~9,700 threads and exhausted the cgroup's 512-task
#   limit, so even fork() failed; a "safe" 4-shard rerun re-created the lockout.
#   2026-07-16: eight concurrent --workspace builds filled the 124G tmpfs behind
#   CARGO_TARGET_DIR and wedged the machine for every agent.
#
# The retrospective's finding, which this encodes: **a memory cap alone was not
# enough** — the PID/task budget was the scarce resource. So every budget here
# declares memory AND tasks AND an isolated target dir, and the kernel enforces
# all three.
#
# Mechanism: systemd-run --user --scope, i.e. a real cgroup v2 scope per run.
#
# NOT ulimit -u. RLIMIT_NPROC is per-UID, not per-process-tree. Every agent in
# this swarm runs as the same user, so `ulimit -u 256` would cap against the
# other agents' processes too: your build would fail to fork because someone
# else's test suite was busy. It is also one-way (a lowered limit cannot be
# raised back). A cgroup scope binds this run's subtree and nothing else.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Base for isolated per-run target dirs. MUST be disk-backed; see the tmpfs guard.
BUDGET_BASE="${ORACLEMCP_BUDGET_BASE:-$HOME/.cache/oraclemcp-budget-runs}"

usage() {
  cat >&2 <<'EOF'
usage: resource_budget.sh --profile <name> [--run-id ID] [--emit-budget] [-- CMD...]

  --profile NAME   one of: build, test, mutants, live
  --run-id ID      name the run (default: profile-$$); fixes the target dir
  --tasks N        override pid_task_max (use MEASURED evidence, not a hunch)
  --memory BYTES   override memory_max_bytes
  --min-free-bytes BYTES
                   refuse unless the target filesystem has at least BYTES free
                   (default: 8589934592, configurable with
                   ORACLEMCP_BUDGET_MIN_FREE_BYTES)
  --emit-budget    print the resource_budget JSON and exit without running
  -- CMD...        the command to run under the budget

profiles (memory_max_bytes / pid_task_max):
  build     16G / 8192   cargo build|check|clippy
  test      16G / 8192   cargo test
  mutants   12G / 8192   cargo-mutants (runs cargo builds, so it needs build room)
  live       8G / 4096   live/container-backed suites

Task budgets are MEASURED, not guessed. See the note in this script.
EOF
  exit 64
}

PROFILE=""
RUN_ID=""
EMIT_ONLY=false
CMD=()

while [ $# -gt 0 ]; do
  case "$1" in
    --profile) PROFILE="${2:-}"; shift 2 ;;
    --run-id)  RUN_ID="${2:-}"; shift 2 ;;
    --tasks)   OVERRIDE_TASKS="${2:-}"; shift 2 ;;
    --memory)  OVERRIDE_MEM="${2:-}"; shift 2 ;;
    --min-free-bytes) OVERRIDE_MIN_FREE="${2:-}"; shift 2 ;;
    --emit-budget) EMIT_ONLY=true; shift ;;
    --help|-h) usage ;;
    --) shift; CMD=("$@"); break ;;
    *) echo "resource_budget: unknown argument: $1" >&2; usage ;;
  esac
done

[ -n "$PROFILE" ] || usage

# ---------------------------------------------------------------------------
# Task budgets are MEASURED, not guessed. The first version of this file guessed
# 512/256 and was wrong in the dangerous direction: it strangled legitimate work.
# A scoped `cargo mutants` run died on its BASELINE build with
#   failed to spawn thread: Os { code: 11, kind: WouldBlock }
# because a single-crate build needs far more tasks than it looks like it should.
#
# Measured on this host (128 cores, cargo jobs=4), by reading the run's own
# cgroup pids.peak/memory.peak:
#
#   cargo build -p oraclemcp-db --tests       peak_tasks =  602   mem ~0.95 GiB
#   cargo mutants -j1, one file, cold deps     peak_tasks = 5850   mem ~1.6  GiB
#
# 5850 tasks to mutate ONE 91-line file is not intuitive, and it is why guessing
# does not work here: `jobs=4` bounds concurrent rustc PROCESSES, but each rustc
# sizes its own thread pool from the machine's CORE COUNT (128 here). Task usage
# therefore scales with cores and with cache coldness -- a cold dep tree costs
# ~10x a warm scoped build -- not with the jobs flag.
#
# A budget has to sit between two numbers:
#   above  ~5850  or it breaks legitimate work. It did: the first version of this
#                 file guessed 256 and 512 and killed a real mutation run on its
#                 baseline build ("failed to spawn thread: WouldBlock").
#   below  the runaway. The retrospective's cargo-mutants incident reached ~9,700
#                 threads and exhausted a 512-task limit until fork() failed.
#
# That window is narrower than it looks, so these are floors from measurement
# plus headroom, not round numbers someone liked. RE-MEASURE rather than raise on
# a hunch: run under a generous cap, read pids.peak from the run's cgroup, put
# the number here. Callers with evidence can override per-run with --tasks and
# --memory rather than editing this table.
#
# These numbers are HOST-SPECIFIC (128 cores). On a smaller machine they are
# loose; on a bigger one they may be tight.
# ---------------------------------------------------------------------------
case "$PROFILE" in
  build)   MEM_BYTES=$((16 * 1024 * 1024 * 1024)); TASKS=8192 ;;
  test)    MEM_BYTES=$((16 * 1024 * 1024 * 1024)); TASKS=8192 ;;
  mutants) MEM_BYTES=$((12 * 1024 * 1024 * 1024)); TASKS=8192 ;;
  live)    MEM_BYTES=$((8 * 1024 * 1024 * 1024));  TASKS=4096 ;;
  *) echo "resource_budget: unknown profile: $PROFILE" >&2; usage ;;
esac

# Evidence-backed per-run overrides.
[ -n "${OVERRIDE_TASKS:-}" ] && TASKS="$OVERRIDE_TASKS"
[ -n "${OVERRIDE_MEM:-}" ] && MEM_BYTES="$OVERRIDE_MEM"
MIN_FREE_BYTES="${ORACLEMCP_BUDGET_MIN_FREE_BYTES:-8589934592}"
[ -n "${OVERRIDE_MIN_FREE:-}" ] && MIN_FREE_BYTES="$OVERRIDE_MIN_FREE"
if [[ ! "$MIN_FREE_BYTES" =~ ^[0-9]+$ ]] || [ "${#MIN_FREE_BYTES}" -gt 18 ]; then
  echo "resource_budget: --min-free-bytes must be a non-negative integer of at most 18 digits" >&2
  exit 64
fi

RUN_ID="${RUN_ID:-${PROFILE}-$$}"
TARGET_DIR="$BUDGET_BASE/$RUN_ID/target"

# ---------------------------------------------------------------------------
# Fail-closed real-disk preflight.
#
# This is 2026-07-16 encoded as a check rather than a docs paragraph. tmpfs is
# RAM: a 73G build cache there is 73G of memory the box cannot use, and when it
# fills, the failure is EDQUOT and a wedged machine, not a clean "disk full".
# Refuse rather than "warn": a warning on a heavy run is a warning nobody reads.
#
# Inspect the nearest existing ancestor before creating TARGET_DIR. A refused
# tmpfs or low-space run must not materialize the cache path it rejects. After
# creation, a fixed write/fsync/read canary catches unwritable filesystems,
# EDQUOT reported only on fsync, and silent truncation before any heavy command.
# ---------------------------------------------------------------------------
existing_ancestor_for_planned_path() {
  local path="$1"
  local parent

  while [ ! -e "$path" ]; do
    parent="$(dirname -- "$path")"
    if [ "$parent" = "$path" ]; then
      return 1
    fi
    path="$parent"
  done

  printf '%s\n' "$path"
}

disk_refusal() {
  local reason="$1"
  cat >&2 <<EOF
resource_budget: REFUSING to run: DISK, not OOM.

  target dir : $TARGET_DIR
  reason     : $reason
EOF
}

if ! planned_ancestor="$(existing_ancestor_for_planned_path "$TARGET_DIR")"; then
  disk_refusal "cannot find an existing ancestor for the planned target path"
  exit 78
fi

if ! fstype="$(stat -f -c %T "$planned_ancestor")"; then
  disk_refusal "cannot inspect the target filesystem"
  exit 78
fi
if [ "$fstype" = "tmpfs" ] || [ "$fstype" = "ramfs" ]; then
  cat >&2 <<EOF
resource_budget: REFUSING to run: DISK, not OOM.

  target dir : $TARGET_DIR
  filesystem : $fstype  (RAM-backed)

A build cache on tmpfs is build artifacts stored in RAM. On 2026-07-16 that
filled a 124G tmpfs and wedged the box for every agent: writes returned EDQUOT,
the linker died with SIGBUS, and commands that produced output failed with no
output at all.

Point ORACLEMCP_BUDGET_BASE at a disk-backed path.
EOF
  exit 78
fi

if ! space_fields="$(stat -f -c '%a %S' "$planned_ancestor")"; then
  disk_refusal "cannot measure free space on the target filesystem"
  exit 78
fi
read -r available_blocks block_size <<<"$space_fields"
if [[ ! "$available_blocks" =~ ^[0-9]+$ ]] || [[ ! "$block_size" =~ ^[0-9]+$ ]]; then
  disk_refusal "target filesystem returned an invalid free-space measurement"
  exit 78
fi
available_bytes=$((available_blocks * block_size))
if [ "$available_bytes" -lt "$MIN_FREE_BYTES" ]; then
  disk_refusal "only $available_bytes bytes free; configured minimum is $MIN_FREE_BYTES bytes"
  exit 78
fi

if ! mkdir -p "$TARGET_DIR"; then
  disk_refusal "cannot create the isolated target directory"
  exit 78
fi

CANARY_PATH="$TARGET_DIR/.resource-budget-canary"
CANARY_VALUE="resource-budget-canary/v1"
if ! printf '%s\n' "$CANARY_VALUE" >"$CANARY_PATH"; then
  disk_refusal "write/fsync/read canary failed during write"
  exit 78
fi
if ! sync "$CANARY_PATH"; then
  disk_refusal "write/fsync/read canary failed during fsync"
  exit 78
fi
if ! IFS= read -r canary_read <"$CANARY_PATH"; then
  disk_refusal "write/fsync/read canary failed during read"
  exit 78
fi
if [ "$canary_read" != "$CANARY_VALUE" ]; then
  disk_refusal "write/fsync/read canary detected silent truncation or corruption"
  exit 78
fi

if $EMIT_ONLY; then
  # The exact resource_budget block required by required-proof/v1 and
  # mutation-result/v1, so a proof embeds the budget it actually ran under
  # rather than a number someone typed.
  printf '{\n  "isolated_target_dir": "%s",\n  "memory_max_bytes": %s,\n  "pid_task_max": %s\n}\n' \
    "$TARGET_DIR" "$MEM_BYTES" "$TASKS"
  exit 0
fi

[ "${#CMD[@]}" -gt 0 ] || { echo "resource_budget: no command given" >&2; usage; }

if ! command -v systemd-run >/dev/null 2>&1; then
  echo "resource_budget: systemd-run is required to enforce the budget; refusing to run unbounded" >&2
  exit 78
fi

echo "resource_budget: profile=$PROFILE tasks=$TASKS memory=$((MEM_BYTES / 1024 / 1024 / 1024))G" >&2
echo "resource_budget: isolated target dir=$TARGET_DIR ($fstype)" >&2

# --scope runs the command in a transient cgroup scope in this session.
# --collect reaps the unit even when the command fails, so a failed run does not
# leave a unit behind and break the next one.
# CARGO_TARGET_DIR is exported into the scope: an isolated target dir is part of
# the budget, not a suggestion, and it is what makes a run's inputs attributable.
exec systemd-run --user --scope --quiet --collect \
  -p "TasksMax=$TASKS" \
  -p "MemoryMax=$MEM_BYTES" \
  --setenv=CARGO_TARGET_DIR="$TARGET_DIR" \
  -- "${CMD[@]}"
