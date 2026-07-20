#!/usr/bin/env bash
# Build-lease + isolated-target preflight (bead eng-program E1, W3).
#
# Refuses the two shapes of build that took the box down in the 2026-07 retro:
#
#   1. A HEAVY cargo operation (workspace-wide build/test/clippy, cargo-mutants,
#      cargo-hack powerset, or an unscoped bare `cargo build/test/...`) running
#      WITHOUT the build lease. Heavy builds go through scripts/build_lease.sh,
#      which exports a CARGO_SWARM_BUILD_LEASE_* identity into the leased
#      process tree; this check verifies the named live flock rather than
#      trusting a caller-supplied Boolean marker.
#   2. Any cargo operation against a SHARED or RAM-backed target dir. The
#      effective CARGO_TARGET_DIR must be per-agent: the checkout's own target/
#      is fine (each agent checkout has its own), a resource_budget.sh per-run
#      dir is fine, tmpfs and the historical shared caches are refused.
#
# Callers:
#   check_build_lease.sh --require-lease            # I know I am heavy; demand the lease
#   check_build_lease.sh -- CMD...                  # classify CMD, demand lease iff heavy
#   check_build_lease.sh --target-only -- CMD...    # target-dir discipline only
#   check_build_lease.sh --selftest
#
# CI exemption: on a CI runner ($CI set) the lease requirement passes with a
# note. The lease serializes agents sharing ONE dev box; a hosted CI runner is
# single-tenant by construction, so there is nobody to serialize against. The
# target-dir checks still apply everywhere.
#
# Exit codes: 64 usage, 75 un-leased heavy build (EX_TEMPFAIL — take the lease
# and retry), 78 target-dir refusal (EX_CONFIG).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

MODE="classify"
CMD=()

usage() {
  sed -n '3,26p' "${BASH_SOURCE[0]}" >&2
  exit 64
}

while [ $# -gt 0 ]; do
  case "$1" in
    --require-lease) MODE="require"; shift ;;
    --target-only)   MODE="target-only"; shift ;;
    --selftest)      MODE="selftest"; shift ;;
    --help|-h)       usage ;;
    --) shift; CMD=("$@"); break ;;
    *) echo "check_build_lease: unknown argument: $1" >&2; usage ;;
  esac
done

# ---------------------------------------------------------------------------
# Target-dir discipline. Decidable rules, no heuristics:
#   - effective target dir = CARGO_TARGET_DIR, else <checkout>/target (per-agent
#     by construction: each checkout carries its own).
#   - refuse tmpfs/ramfs (the 2026-07-16 wedge, same rule as resource_budget.sh).
#   - refuse the known shared caches by name: /tmp/cargo-target and
#     ~/.cache/cargo-target are the documented multi-agent shared dirs
#     (docs/multi-agent-build-policy.md); ORACLEMCP_SHARED_TARGET_DENYLIST is a
#     colon-separated extension point.
# ---------------------------------------------------------------------------
check_target_dir() {
  local target resolved probe fstype deny raw
  target="${CARGO_TARGET_DIR:-$ROOT/target}"
  resolved="$(readlink -f "$target" 2>/dev/null || echo "$target")"

  # Probe the nearest existing ancestor: the dir may not exist yet, but the
  # filesystem it would land on already does. A check never mkdirs.
  probe="$resolved"
  while [ ! -d "$probe" ] && [ "$probe" != "/" ]; do
    probe="$(dirname "$probe")"
  done
  if [ -d "$probe" ]; then
    # GNU stat is used on Linux. BSD/macOS stat has different flags; leave the
    # type unknown rather than turning every macOS Cargo invocation into a
    # tooling failure. The explicit shared-target denylist still applies.
    fstype="$(stat -f -c %T "$probe" 2>/dev/null || true)"
    if [ "$fstype" = "tmpfs" ] || [ "$fstype" = "ramfs" ]; then
      cat >&2 <<EOF
check_build_lease: REFUSING — target dir is RAM-backed.

  target dir : $target
  filesystem : $fstype

A build cache on tmpfs is build artifacts stored in RAM (the 2026-07-16 wedge).
Point CARGO_TARGET_DIR at a disk-backed, per-agent path.
EOF
      exit 78
    fi
  fi

  deny="/tmp/cargo-target:$HOME/.cache/cargo-target"
  [ -n "${ORACLEMCP_SHARED_TARGET_DENYLIST:-}" ] &&
    deny="$deny:$ORACLEMCP_SHARED_TARGET_DENYLIST"
  local IFS=':'
  for raw in $deny; do
    [ -n "$raw" ] || continue
    local raw_resolved
    raw_resolved="$(readlink -f "$raw" 2>/dev/null || echo "$raw")"
    if [ "$target" = "$raw" ] || [ "$resolved" = "$raw" ] ||
      [ "$resolved" = "$raw_resolved" ] ||
      [[ "$resolved" == "$raw_resolved"/* ]]; then
      cat >&2 <<EOF
check_build_lease: REFUSING — target dir is a SHARED build cache.

  target dir : $target  (resolves to $resolved)

Shared target dirs are how one agent's half-finished state breaks every other
agent's build. Heavy builds use a DEDICATED per-agent CARGO_TARGET_DIR: the
checkout's own target/, or a scripts/resource_budget.sh per-run dir.
EOF
      exit 78
    fi
  done
}

# ---------------------------------------------------------------------------
# Heavy classification. Heavy = compiles substantially more than one crate:
#   - any cargo invocation with --workspace or --all
#   - cargo mutants (its baseline alone peaked at 5850 tasks; measured)
#   - cargo hack (feature-powerset fanout)
#   - a bare cargo build/test/check/clippy with NO -p/--package scope, run from
#     a workspace: it builds everything, whether or not that was meant.
# Scoped `-p` builds are the sanctioned iteration path and are never gated.
# ---------------------------------------------------------------------------
is_heavy() {
  local joined=" ${*} "
  case "$joined" in
    *cargo*) : ;;
    *) return 1 ;;
  esac
  case "$joined" in
    *" --workspace "*|*" --all "*) return 0 ;;
    *" mutants "*|*"cargo-mutants"*) return 0 ;;
    *" hack "*|*"cargo-hack"*) return 0 ;;
  esac
  case "$joined" in
    *" build "*|*" test "*|*" check "*|*" clippy "*|*" doc "*)
      case "$joined" in
        *" -p "*|*" --package "*) return 1 ;;
        *) return 0 ;;
      esac
      ;;
  esac
  return 1
}

require_lease() {
  local why="$1"
  local lease_dir="${CARGO_SWARM_BUILD_LEASE_DIR:-}"
  local lease_slot="${CARGO_SWARM_BUILD_LEASE_SLOT:-}"
  local lease_pid="${CARGO_SWARM_BUILD_LEASE_PID:-}"
  local slot_file record lease_fd
  if [ -n "$lease_dir" ] && [ -n "$lease_slot" ] && [ -n "$lease_pid" ]; then
    case "$lease_slot:$lease_pid" in
      *[!0-9:]*|:*|*:) ;;
      *)
        slot_file="$lease_dir/slot.$lease_slot"
        record=""
        if [ -f "$slot_file" ]; then
          IFS= read -r record <"$slot_file" || true
        fi
        if kill -0 "$lease_pid" 2>/dev/null &&
          [[ " $record " == *" pid=$lease_pid "* ]]; then
          exec {lease_fd}>>"$slot_file"
          if ! flock -n "$lease_fd"; then
            exec {lease_fd}>&-
            echo "check_build_lease: OK — verified live build lease (slot=$lease_slot pid=$lease_pid)." >&2
            return 0
          fi
          exec {lease_fd}>&-
        fi
        ;;
    esac
    echo "check_build_lease: supplied build-lease identity is not a live held flock; refusing." >&2
  fi
  if [ -n "${CI:-}" ]; then
    echo "check_build_lease: OK — CI runner is single-tenant; lease requirement waived." >&2
    return 0
  fi
  cat >&2 <<EOF
check_build_lease: REFUSING un-leased heavy build ($why).

Heavy cargo operations serialize through the machine-wide build lease so N
agents cannot launch N simultaneous full compiles (the fork-EAGAIN class).
Run it as:

  scripts/build_lease.sh -- <your command>

Iterating? Use a scoped build instead: cargo check/test/clippy -p <crate>.
EOF
  exit 75
}

selftest() {
  local self="$ROOT/scripts/check_build_lease.sh" rc tmp_target lease_test_dir spoof_dir
  local pass=0 fail=0
  verdict() { # verdict WANT_RC GOT_RC DESCRIPTION
    if [ "$2" -eq "$1" ]; then
      echo "  PASS  $3 (rc=$2)"
      pass=$((pass + 1))
    else
      echo "  FAIL  $3 (rc=$2, want $1)" >&2
      fail=$((fail + 1))
    fi
  }

  # 1. heavy + un-leased + not CI => refused with exit 75
  rc=0
  env -u CARGO_SWARM_BUILD_LEASE_DIR -u CARGO_SWARM_BUILD_LEASE_SLOT \
    -u CARGO_SWARM_BUILD_LEASE_PID -u CI -u CARGO_TARGET_DIR \
    "$self" -- cargo test --workspace >/dev/null 2>&1 || rc=$?
  verdict 75 "$rc" "un-leased 'cargo test --workspace' refused"

  # 2. heavy + lease marker => passes
  rc=0
  lease_test_dir="$HOME/.cache/oraclemcp-build-lease-check-selftest"
  env -u CI -u CARGO_TARGET_DIR CARGO_SWARM_BUILD_LEASE_DIR="$lease_test_dir" \
    "$ROOT/scripts/build_lease.sh" --timeout 30 --label check-selftest -- \
      "$self" -- cargo test --workspace >/dev/null 2>&1 || rc=$?
  verdict 0 "$rc" "leased heavy build passes"

  # 3. A caller cannot turn a string into a lease. The checker verifies that
  # the named slot is currently flocked, not merely that marker variables exist.
  spoof_dir="$lease_test_dir/spoof"
  mkdir -p "$spoof_dir"
  printf 'label=spoof pid=%s acquired=never cmd=none\n' "$$" >"$spoof_dir/slot.0"
  rc=0
  env -u CI -u CARGO_TARGET_DIR \
    CARGO_SWARM_BUILD_LEASE_DIR="$spoof_dir" \
    CARGO_SWARM_BUILD_LEASE_SLOT=0 CARGO_SWARM_BUILD_LEASE_PID="$$" \
    "$self" -- cargo test --workspace >/dev/null 2>&1 || rc=$?
  verdict 75 "$rc" "spoofed marker without a held flock is refused"

  # 4. heavy + CI runner => passes with waiver
  rc=0
  env -u CARGO_SWARM_BUILD_LEASE_DIR -u CARGO_SWARM_BUILD_LEASE_SLOT \
    -u CARGO_SWARM_BUILD_LEASE_PID -u CARGO_TARGET_DIR CI=true \
    "$self" -- cargo test --workspace >/dev/null 2>&1 || rc=$?
  verdict 0 "$rc" "CI runner waiver applies"

  # 5. scoped build, un-leased => passes (iteration path is never gated)
  rc=0
  env -u CARGO_SWARM_BUILD_LEASE_DIR -u CARGO_SWARM_BUILD_LEASE_SLOT \
    -u CARGO_SWARM_BUILD_LEASE_PID -u CI -u CARGO_TARGET_DIR \
    "$self" -- cargo test -p oraclemcp-db >/dev/null 2>&1 || rc=$?
  verdict 0 "$rc" "scoped 'cargo test -p' passes without a lease"

  # 6. cargo-mutants is heavy even when scoped
  rc=0
  env -u CARGO_SWARM_BUILD_LEASE_DIR -u CARGO_SWARM_BUILD_LEASE_SLOT \
    -u CARGO_SWARM_BUILD_LEASE_PID -u CI -u CARGO_TARGET_DIR \
    "$self" -- cargo mutants -p oraclemcp-db >/dev/null 2>&1 || rc=$?
  verdict 75 "$rc" "cargo mutants classified heavy"

  # 7. shared target dir refused with exit 78 before checking the lease
  rc=0
  env -u CI -u CARGO_SWARM_BUILD_LEASE_DIR -u CARGO_SWARM_BUILD_LEASE_SLOT \
    -u CARGO_SWARM_BUILD_LEASE_PID CARGO_TARGET_DIR="$HOME/.cache/cargo-target" \
    "$self" -- cargo test --workspace >/dev/null 2>&1 || rc=$?
  verdict 78 "$rc" "shared ~/.cache/cargo-target refused"

  # 8. tmpfs target dir refused (skipped when /tmp is not tmpfs on this host).
  # The target need not exist: check_target_dir deliberately probes its nearest
  # existing ancestor, so this test creates and deletes no scratch directory.
  tmp_target="/tmp/oraclemcp-build-lease-selftest-target"
  if [ "$(stat -f -c %T /tmp)" != "tmpfs" ]; then
    echo "  SKIP  /tmp is not tmpfs on this host; tmpfs refusal not exercisable"
  else
    rc=0
    env -u CI -u CARGO_SWARM_BUILD_LEASE_DIR -u CARGO_SWARM_BUILD_LEASE_SLOT \
      -u CARGO_SWARM_BUILD_LEASE_PID CARGO_TARGET_DIR="$tmp_target" \
      "$self" -- cargo test --workspace >/dev/null 2>&1 || rc=$?
    verdict 78 "$rc" "tmpfs target dir refused"
  fi

  echo
  if [ "$fail" -ne 0 ]; then
    echo "check_build_lease: selftest FAILED ($fail of $((pass + fail)))" >&2
    exit 1
  fi
  echo "check_build_lease: selftest OK ($pass checks)"
}

case "$MODE" in
  selftest)
    selftest
    ;;
  target-only)
    check_target_dir
    echo "check_build_lease: OK — target dir is per-agent and disk-backed." >&2
    ;;
  require)
    check_target_dir
    require_lease "caller declared itself heavy"
    ;;
  classify)
    check_target_dir
    if [ "${#CMD[@]}" -eq 0 ]; then
      echo "check_build_lease: OK — no command to classify; target dir checked." >&2
      exit 0
    fi
    if is_heavy "${CMD[@]}"; then
      require_lease "classified heavy: ${CMD[*]}"
    else
      echo "check_build_lease: OK — not a heavy build (${CMD[*]}); no lease needed." >&2
    fi
    ;;
esac
