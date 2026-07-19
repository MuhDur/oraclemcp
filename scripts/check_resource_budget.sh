#!/usr/bin/env bash
# Resource-budget harness gate (bead yg4x.9).
#
# Proves the budget is ENFORCED, not merely declared. The bead's acceptance is
# "a heavy run cannot exceed the declared task/PID budget (proven by a
# bounded-fanout test)", so this actually tries to exceed it and asserts the
# kernel says no.
#
# Every experiment here is bounded and runs inside the very cgroup under test: a
# fanout that escaped its budget would be the bug, and the test is what proves it
# does not. Nothing here touches /tmp/cargo-target or any shared state.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUDGET="$ROOT/scripts/resource_budget.sh"

pass=0
fail=0

ok()   { printf '  PASS  %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  FAIL  %s\n' "$1" >&2; fail=$((fail + 1)); }

if ! command -v systemd-run >/dev/null 2>&1; then
  echo "resource-budget: systemd-run absent; cannot verify enforcement" >&2
  exit 2
fi

echo "=== 1. the declared budget is actually applied to the run's cgroup ==="
# Ask the kernel what the running process's own cgroup limits are, rather than
# trusting that the flags were passed.
read -r got_tasks got_mem < <(
  "$BUDGET" --profile mutants --run-id selftest-limits -- \
    bash -c 'cg=/sys/fs/cgroup$(awk -F: "/^0::/{print \$3}" /proc/self/cgroup); \
             echo "$(cat "$cg/pids.max") $(cat "$cg/memory.max")"' 2>/dev/null
)
if [ "$got_tasks" = "8192" ]; then
  ok "mutants profile: kernel reports pids.max=8192 (measured: cargo-mutants peaks at 5850)"
else
  bad "mutants profile: kernel reports pids.max=$got_tasks, expected 8192"
fi
if [ "$got_mem" = "$((12 * 1024 * 1024 * 1024))" ]; then
  ok "mutants profile: kernel reports memory.max=12G"
else
  bad "mutants profile: kernel reports memory.max=$got_mem, expected 12884901888"
fi

echo
echo "=== 2. bounded fanout CANNOT exceed the task budget ==="
# Deliberately try to exceed the budget from inside it, against a tiny TasksMax
# so refusal is forced. Two things make this test honest:
#
#   Report with BUILTINS ONLY. Past the cap there is no fork left, so $(cat) or
#   an external `echo` would hang -- that IS the incident ("even fork() failed").
#   `read`/`echo` are bash builtins and keep working.
#
#   Do not count via `if cmd &`. Backgrounding always returns 0 and bash retries
#   a failed fork internally, so a `&`-based counter reports success even while
#   the kernel is refusing. Ask the KERNEL instead:
#     pids.peak       - the high-water mark; must never exceed the budget
#     pids.events max - how many forks the kernel denied; must be > 0 here
#
#   Overshoot the cap MODERATELY (cap + 8). Overshooting hard is self-defeating:
#   at ~4x the cap the reporting shell is killed by the very denial it is
#   measuring -- a SIGCHLD interrupts a retrying fork and bash aborts with
#   "fork: Interrupted system call" before it can print anything. cap+8 reliably
#   reaches the cap and triggers denials while leaving the reporter alive.
#   Retry a few times. The reporting shell lives inside the cgroup it is
#   measuring, so under heavy load (another agent mid-build) it can still lose a
#   race and print nothing. Observed once, on a busy box. A gate that goes red
#   because the machine was busy gets muted, so distinguish "no answer, ask
#   again" from "the wrong answer", and only the second one fails.
fanout_out=""
for _attempt in 1 2 3; do
  fanout_out="$(
    systemd-run --user --scope --quiet --collect -p TasksMax=16 -- bash -c '
      cgpath=$(awk -F: "/^0::/{print \$3}" /proc/self/cgroup)
      cg=/sys/fs/cgroup$cgpath
      for ((i=0;i<24;i++)); do sleep 2 & done
      read -r maxv < "$cg/pids.max"
      read -r peak < "$cg/pids.peak"
      denied=0
      while read -r k v; do [ "$k" = "max" ] && denied=$v; done < "$cg/pids.events"
      echo "max=$maxv peak=$peak denied=$denied"
    ' 2>/dev/null
  )" || true
  [[ "$fanout_out" == *peak=* ]] && break
  sleep 2
done

f_max="$(sed -n 's/.*max=\([0-9]*\) peak.*/\1/p' <<<"$fanout_out")"
f_peak="$(sed -n 's/.*peak=\([0-9]*\).*/\1/p' <<<"$fanout_out")"
f_denied="$(sed -n 's/.*denied=\([0-9]*\).*/\1/p' <<<"$fanout_out")"

if [ -n "${f_peak:-}" ] && [ -n "${f_max:-}" ] && [ "$f_peak" -le "$f_max" ]; then
  ok "24 forks attempted under TasksMax=$f_max: peak was $f_peak — the budget was never exceeded"
else
  bad "fanout exceeded its budget (peak=${f_peak:-?} max=${f_max:-?}) — NOT enforced"
fi

if [ -n "${f_denied:-}" ] && [ "$f_denied" -gt 0 ]; then
  ok "kernel denied $f_denied fork(s) (pids.events max) — refusal is real, not theoretical"
else
  bad "no forks were denied (pids.events max=${f_denied:-?}); the test never reached the cap, so it proves nothing"
fi

echo
echo "=== 3. the host survives: the budget fails the RUN, not the box ==="
if [ "$(echo alive)" = "alive" ]; then
  ok "shell still forks after the bounded-fanout experiment (containment held)"
else
  bad "environment damaged by the fanout experiment"
fi

echo
echo "=== 4. tmpfs target dir is REFUSED (2026-07-16, as a check not a paragraph) ==="
tmpfs_run_id="resource-budget-tmpfs-probe-$$"
tmpfs_probe="/tmp/$tmpfs_run_id"
if [ "$(stat -f -c %T /tmp)" != "tmpfs" ]; then
  echo "  SKIP  /tmp is not tmpfs on this host; cannot exercise the guard" >&2
else
  if tmpfs_err="$(ORACLEMCP_BUDGET_BASE=/tmp "$BUDGET" --profile build --run-id "$tmpfs_run_id" --emit-budget 2>&1 >/dev/null)"; then
    bad "a tmpfs target dir was ACCEPTED; the guard does not work"
  else
    tmpfs_status=$?
    if [ "$tmpfs_status" -ne 78 ]; then
      bad "tmpfs refusal exited $tmpfs_status, expected 78"
    elif [[ "$tmpfs_err" != *"DISK, not OOM"* ]]; then
      bad "tmpfs refusal omitted the DISK, not OOM diagnosis"
    elif [ -e "$tmpfs_probe" ]; then
      bad "tmpfs refusal materialized $tmpfs_probe; the negative-control probe leaked"
    else
      ok "tmpfs target dir refused as DISK, not OOM without materializing its target"
    fi
  fi
fi

echo
echo "=== 5. healthy real-disk target passes write/fsync/read canary ==="
disk_probe_base="${ORACLEMCP_BUDGET_TEST_BASE:-$HOME/.cache/oraclemcp-budget-runs}"
healthy_run_id="resource-budget-disk-healthy-$$"
if healthy_json="$(ORACLEMCP_BUDGET_BASE="$disk_probe_base" "$BUDGET" --profile build --run-id "$healthy_run_id" --min-free-bytes 1 --emit-budget)"; then
  healthy_target="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["isolated_target_dir"])' <<<"$healthy_json")"
  healthy_canary="$healthy_target/.resource-budget-canary"
  healthy_value=""
  if [ -f "$healthy_canary" ] && IFS= read -r healthy_value <"$healthy_canary" && [ "$healthy_value" = "resource-budget-canary/v1" ]; then
    ok "real-disk target passed the persisted write/fsync/read canary"
  else
    bad "healthy real-disk target did not retain the expected canary"
  fi
else
  bad "healthy real-disk target was refused"
fi

echo
echo "=== 6. forced low space is REFUSED before target creation or command start ==="
low_run_id="resource-budget-low-space-probe-$$"
low_target="$disk_probe_base/$low_run_id/target"
if low_err="$(ORACLEMCP_BUDGET_BASE="$disk_probe_base" "$BUDGET" --profile build --run-id "$low_run_id" --min-free-bytes 999999999999999999 -- bash -c 'printf RESOURCE_BUDGET_COMMAND_RAN >&2; exit 99' 2>&1 >/dev/null)"; then
  bad "forced-low-space target was ACCEPTED"
else
  low_status=$?
  if [ "$low_status" -ne 78 ]; then
    bad "forced-low-space refusal exited $low_status, expected 78"
  elif [[ "$low_err" != *"DISK, not OOM"* ]] || [[ "$low_err" != *"configured minimum"* ]]; then
    bad "forced-low-space refusal omitted its specific DISK, not OOM diagnosis"
  elif [[ "$low_err" == *"RESOURCE_BUDGET_COMMAND_RAN"* ]]; then
    bad "forced-low-space refusal started the guarded command"
  elif [ -e "$low_target" ]; then
    bad "forced-low-space refusal materialized $low_target"
  else
    ok "low space refused as DISK, not OOM before target creation or command start"
  fi
fi

echo
echo "=== 7. unwritable target fails the canary before command start ==="
readonly_target=""
for candidate in /usr/lib/nsight-compute/target /usr/lib/modules/*/kernel/drivers/target /usr/src/linux-headers-*/drivers/target; do
  if [ -d "$candidate" ] && [ ! -w "$candidate" ] && [ ! -e "$candidate/.resource-budget-canary" ]; then
    readonly_target="$candidate"
    break
  fi
done
if [ -z "$readonly_target" ]; then
  echo "  SKIP  no suitable pre-existing unwritable disk-backed target directory on this host" >&2
else
  readonly_parent="$(dirname -- "$readonly_target")"
  readonly_base="$(dirname -- "$readonly_parent")"
  readonly_run_id="$(basename -- "$readonly_parent")"
  if readonly_err="$(ORACLEMCP_BUDGET_BASE="$readonly_base" "$BUDGET" --profile build --run-id "$readonly_run_id" --min-free-bytes 1 -- bash -c 'printf RESOURCE_BUDGET_COMMAND_RAN >&2; exit 99' 2>&1 >/dev/null)"; then
    bad "unwritable target was ACCEPTED"
  else
    readonly_status=$?
    if [ "$readonly_status" -ne 78 ]; then
      bad "unwritable-target refusal exited $readonly_status, expected 78"
    elif [[ "$readonly_err" != *"DISK, not OOM"* ]] || [[ "$readonly_err" != *"canary failed during write"* ]]; then
      bad "unwritable-target refusal omitted its canary-specific DISK, not OOM diagnosis"
    elif [[ "$readonly_err" == *"RESOURCE_BUDGET_COMMAND_RAN"* ]]; then
      bad "unwritable-target refusal started the guarded command"
    else
      ok "unwritable target failed the write canary as DISK, not OOM before command start"
    fi
  fi
fi

echo
echo "=== 8. emitted budget satisfies the resource_budget contract ==="
budget_json="$("$BUDGET" --profile mutants --run-id selftest-emit --emit-budget)"
if python3 - "$budget_json" <<'PY'
import json, sys
b = json.loads(sys.argv[1])
assert set(b) == {"isolated_target_dir", "memory_max_bytes", "pid_task_max"}, b
assert isinstance(b["memory_max_bytes"], int) and b["memory_max_bytes"] > 0
assert isinstance(b["pid_task_max"], int) and b["pid_task_max"] > 0
assert b["isolated_target_dir"]
PY
then
  ok "resource_budget block matches required-proof/v1 and mutation-result/v1"
else
  bad "emitted resource_budget does not match the contract"
fi

echo
if [ "$fail" -ne 0 ]; then
  echo "resource-budget: $fail of $((pass + fail)) checks FAILED" >&2
  exit 1
fi
echo "resource-budget: all $pass checks passed (budget enforced by the kernel, not declared)"
