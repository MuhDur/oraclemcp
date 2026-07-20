#!/usr/bin/env bash
# Build lease: hard serialization of heavy cargo operations (bead eng-program E1, W3).
#
# Why this exists
# ---------------
# The 2026-07 retro's root cause was shared mutable build infrastructure: N
# concurrent agents each launching a full workspace compile on one box. An
# ADVISORY cap ("acquire a build slot before a full build") was mandated and
# then unenforceable — the agent-mail slot primitive was disabled server-side —
# and the result was the fork-EAGAIN freeze, tmpfs exhaustion, and OOM pressure.
#
# This wrapper is the enforced replacement: a machine-wide flock(2) lease.
# Heavy cargo operations run as
#
#   scripts/build_lease.sh -- cargo test --workspace
#   scripts/build_lease.sh -- scripts/resource_budget.sh --profile mutants -- cargo mutants ...
#
# and N concurrent agents SERIALIZE through the lease instead of launching N
# simultaneous full compiles. The lock is held by the open file description,
# The wrapper keeps the lock fd open while the leased command runs, so an
# intermediate launcher cannot accidentally close the lease before the actual
# build finishes. The kernel releases it when the wrapper exits, crash included.
# There is no unlock step to forget and no stale-lease daemon to run.
#
# The other half of the discipline — a DEDICATED per-agent CARGO_TARGET_DIR,
# never a shared target dir — is checked by scripts/check_build_lease.sh before
# the lease is taken, so a leased build cannot still poison a shared cache.
#
# Scope: the lease domain is the MACHINE (default lease dir lives in $HOME, not
# in any checkout), because the scarce resources — RAM, PIDs, disk bandwidth —
# are machine-wide. Two agents in two different checkouts still contend for the
# same lease, which is the point.
#
#   ORACLEMCP_BUILD_LEASE_DIR    lease directory (default ~/.cache/oraclemcp-build-lease)
#   ORACLEMCP_BUILD_LEASE_SLOTS  concurrent heavy builds allowed (default 1: serialize)
#
# Exit codes: 64 usage, 75 lease not acquired within the wait budget (EX_TEMPFAIL),
# 78 configuration refusal from the target-dir preflight (EX_CONFIG).
set -euo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

LEASE_DIR="${ORACLEMCP_BUILD_LEASE_DIR:-$HOME/.cache/oraclemcp-build-lease}"
SLOTS="${ORACLEMCP_BUILD_LEASE_SLOTS:-1}"
TIMEOUT=3600
LABEL="${USER:-agent}-$$"

usage() {
  cat >&2 <<'EOF'
usage: build_lease.sh [--slots N] [--timeout SECS] [--label TEXT] -- CMD...
       build_lease.sh --status
       build_lease.sh --selftest

Acquire a machine-wide build-lease slot (flock-based), then exec CMD with the
lease held for CMD's whole process tree. Default is ONE slot: concurrent heavy
builds serialize instead of running simultaneously.

  --slots N       number of concurrent slots (default $ORACLEMCP_BUILD_LEASE_SLOTS or 1)
  --timeout SECS  give up waiting for a slot after SECS (default 3600)
  --label TEXT    holder label recorded in the slot file for diagnosis
  --status        show each slot's state and last recorded holder
  --selftest      prove serialization with two real concurrent processes
EOF
  exit 64
}

CMD=()
MODE="run"
while [ $# -gt 0 ]; do
  case "$1" in
    --slots)   SLOTS="${2:?--slots requires a value}"; shift 2 ;;
    --timeout) TIMEOUT="${2:?--timeout requires a value}"; shift 2 ;;
    --label)   LABEL="${2:?--label requires a value}"; shift 2 ;;
    --status)  MODE="status"; shift ;;
    --selftest) MODE="selftest"; shift ;;
    --help|-h) usage ;;
    --) shift; CMD=("$@"); break ;;
    *) echo "build_lease: unknown argument: $1" >&2; usage ;;
  esac
done

case "$SLOTS" in
  ''|*[!0-9]*|0) echo "build_lease: --slots must be a positive integer" >&2; exit 64 ;;
esac
case "$TIMEOUT" in
  ''|*[!0-9]*|0) echo "build_lease: --timeout must be a positive integer" >&2; exit 64 ;;
esac

mkdir -p "$LEASE_DIR"

status() {
  local i slot fd
  echo "build_lease: dir=$LEASE_DIR slots=$SLOTS"
  for ((i = 0; i < SLOTS; i++)); do
    slot="$LEASE_DIR/slot.$i"
    [ -e "$slot" ] || { echo "  slot $i: free (never used)"; continue; }
    if exec {fd}>>"$slot" && flock -n "$fd"; then
      echo "  slot $i: free (last holder: $(head -n1 "$slot" 2>/dev/null || echo none))"
    else
      echo "  slot $i: HELD ($(head -n1 "$slot" 2>/dev/null || echo unknown))"
    fi
    exec {fd}>&- || true
  done
}

# Acquire one slot and run CMD while this wrapper retains the lock fd. Keeping
# the holder outside CMD matters for launchers such as systemd-run, which may
# close inherited descriptors before starting the actual build.
acquire_and_run() {
  local i slot fd deadline now remaining rc
  # Target-dir discipline first: a leased build against a shared or tmpfs
  # target dir is still a poisoned build. Checked here only when the leased
  # command invokes cargo directly with the ambient CARGO_TARGET_DIR;
  # resource_budget.sh isolates its own per-run target dir and re-runs the
  # check against the dir it actually uses.
  case " ${CMD[*]} " in
    *resource_budget.sh*) : ;;
    *cargo*) "$ROOT/scripts/check_build_lease.sh" --target-only -- "${CMD[@]}" ;;
  esac

  deadline=$(($(date +%s) + TIMEOUT))
  while :; do
    for ((i = 0; i < SLOTS; i++)); do
      slot="$LEASE_DIR/slot.$i"
      exec {fd}>>"$slot"
      if flock -n "$fd"; then
        printf 'label=%s pid=%s acquired=%s cmd=%s\n' \
          "$LABEL" "$$" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${CMD[*]}" >"$slot"
        echo "build_lease: slot $i acquired ($LABEL); running: ${CMD[*]}" >&2
        export ORACLEMCP_BUILD_LEASE="slot=$i pid=$$ label=$LABEL"
        set +e
        (
          # The wrapper is the lock owner. Do not leak its fd into compilers or
          # long-lived helpers such as sccache, or a daemon can retain the slot
          # after the wrapped build exits.
          exec {fd}>&-
          "${CMD[@]}"
        )
        rc=$?
        set -e
        return "$rc"
      fi
      exec {fd}>&-
    done
    now=$(date +%s)
    if [ "$now" -ge "$deadline" ]; then
      echo "build_lease: REFUSING to run un-leased: no slot free within ${TIMEOUT}s." >&2
      echo "build_lease: another agent's heavy build holds the lease; see --status." >&2
      exit 75
    fi
    if [ "$SLOTS" -eq 1 ]; then
      # Single-slot: let the kernel queue us (FIFO-ish) instead of polling.
      slot="$LEASE_DIR/slot.0"
      exec {fd}>>"$slot"
      remaining=$((deadline - now))
      echo "build_lease: slot busy; waiting up to ${remaining}s ($LABEL)..." >&2
      if flock -w "$remaining" "$fd"; then
        printf 'label=%s pid=%s acquired=%s cmd=%s\n' \
          "$LABEL" "$$" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${CMD[*]}" >"$slot"
        echo "build_lease: slot 0 acquired after wait ($LABEL); running: ${CMD[*]}" >&2
        export ORACLEMCP_BUILD_LEASE="slot=0 pid=$$ label=$LABEL"
        set +e
        (
          # See the immediate-acquire path above: only this wrapper retains the
          # lease fd; the command receives the marker, not the descriptor.
          exec {fd}>&-
          "${CMD[@]}"
        )
        rc=$?
        set -e
        return "$rc"
      fi
      exec {fd}>&-
    else
      sleep 1
    fi
  done
}

# Two-process serialization proof: two concurrent leased critical sections must
# never overlap. The stable cache path is reused and truncated on each run; the
# repository's no-delete rule therefore remains true even inside self-tests.
selftest() {
  local tmp log test_fd pid_a pid_b
  exec {test_fd}>>"$LEASE_DIR/selftest.lock"
  if ! flock -w 30 "$test_fd"; then
    echo "build_lease: selftest could not acquire its test lock" >&2
    exit 75
  fi
  tmp="$LEASE_DIR/selftest"
  mkdir -p "$tmp/lease"
  log="$tmp/events.log"
  : >"$log"

  run_child() {
    ORACLEMCP_BUILD_LEASE_DIR="$tmp/lease" ORACLEMCP_BUILD_LEASE_SLOTS=1 \
      "$SELF" --label "$1" --timeout 30 -- bash -c '
        echo "START $1 $(date +%s.%N)" >> "$2"
        sleep 0.7
        echo "END $1 $(date +%s.%N)" >> "$2"
      ' _ "$1" "$log"
  }

  run_child a & pid_a=$!
  run_child b & pid_b=$!
  wait "$pid_a"; wait "$pid_b"

  python3 - "$log" <<'PY'
import sys

events = [line.split() for line in open(sys.argv[1]) if line.strip()]
assert len(events) == 4, f"expected 4 events, got {events}"
open_section = None
order = []
for kind, who, stamp in events:
    if kind == "START":
        assert open_section is None, (
            f"OVERLAP: {who} started while {open_section} still inside "
            "the leased critical section"
        )
        open_section = who
    else:
        assert open_section == who, f"END {who} without matching START"
        open_section = None
        order.append(who)
assert open_section is None, "a critical section never ended"
assert sorted(order) == ["a", "b"], f"both children must run exactly once: {order}"
starts = {w: float(s) for k, w, s in events if k == "START"}
ends = {w: float(s) for k, w, s in events if k == "END"}
first, second = order
assert starts[second] >= ends[first], (
    f"second START ({starts[second]}) precedes first END ({ends[first]})"
)
print(
    f"build_lease selftest: serialized OK — {first} ran "
    f"[{starts[first]:.3f}..{ends[first]:.3f}], then {second} ran "
    f"[{starts[second]:.3f}..{ends[second]:.3f}] (no overlap)"
)
PY
  echo "build_lease: selftest OK — two concurrent leased builds serialized (evidence: $log)."
}

case "$MODE" in
  status) status ;;
  selftest) selftest ;;
  run)
    [ "${#CMD[@]}" -gt 0 ] || { echo "build_lease: no command given" >&2; usage; }
    acquire_and_run
    ;;
esac
