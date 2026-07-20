#!/usr/bin/env bash
# Fail-closed preflight for one multi-agent spawn wave (E3 / O4).
#
# The orchestrator supplies the facts only it knows (requested/candidate model,
# provider quota, and its remaining context). This script adds live Linux host
# headroom checks for the resources implicated in the 2026-07 fork-EAGAIN
# incident: tasks/PIDs, memory, and file descriptors. It does not spawn agents.
set -euo pipefail

AGENTS=""
REQUESTED_MODEL=""
CANDIDATE_MODEL=""
QUOTA_REMAINING=""
CONTEXT_REMAINING_PCT=""
MODE="check"

MAX_AGENTS="${ORACLEMCP_SWARM_MAX_AGENTS:-8}"
MIN_CONTEXT_PCT="${ORACLEMCP_SWARM_MIN_CONTEXT_PCT:-20}"
MEM_PER_AGENT_MIB="${ORACLEMCP_SWARM_MEM_PER_AGENT_MIB:-2048}"
MEM_RESERVE_MIB="${ORACLEMCP_SWARM_MEM_RESERVE_MIB:-4096}"
PIDS_PER_AGENT="${ORACLEMCP_SWARM_PIDS_PER_AGENT:-512}"
PIDS_RESERVE="${ORACLEMCP_SWARM_PIDS_RESERVE:-1024}"
FDS_PER_AGENT="${ORACLEMCP_SWARM_FDS_PER_AGENT:-128}"
FDS_RESERVE="${ORACLEMCP_SWARM_FDS_RESERVE:-256}"

# Set only inside deterministic self-test subshells. There is no environment
# bypass for the live host probes.
TEST_MODE=false
TEST_MEM_AVAILABLE_MIB=""
TEST_PIDS_AVAILABLE=""
TEST_FDS_AVAILABLE=""

usage() {
  cat >&2 <<'EOF'
usage: swarm_spawn_preflight.sh \
         --agents N \
         --requested-model MODEL --candidate-model MODEL \
         --quota-remaining N --context-remaining-pct N
       swarm_spawn_preflight.sh --selftest

Checks one proposed wave and exits before any spawn on mismatch or insufficient
headroom. quota-remaining is the harness/provider's available spawn-slot count;
context-remaining-pct is the orchestrator pane's integer percentage (0..100).

Defaults: max wave 8 agents; minimum context 20%; per-agent reserves 2 GiB RAM,
512 tasks, and 128 file descriptors, plus fixed reserves of 4 GiB/1024/256.
Operator-only ORACLEMCP_SWARM_* environment variables may tighten or widen them.
EOF
  exit 64
}

while [ $# -gt 0 ]; do
  case "$1" in
    --agents)
      [ $# -ge 2 ] || usage
      AGENTS="$2"; shift 2
      ;;
    --requested-model)
      [ $# -ge 2 ] || usage
      REQUESTED_MODEL="$2"; shift 2
      ;;
    --candidate-model)
      [ $# -ge 2 ] || usage
      CANDIDATE_MODEL="$2"; shift 2
      ;;
    --quota-remaining)
      [ $# -ge 2 ] || usage
      QUOTA_REMAINING="$2"; shift 2
      ;;
    --context-remaining-pct)
      [ $# -ge 2 ] || usage
      CONTEXT_REMAINING_PCT="$2"; shift 2
      ;;
    --selftest) MODE="selftest"; shift ;;
    --help|-h) usage ;;
    *) echo "swarm_spawn_preflight: unknown argument: $1" >&2; usage ;;
  esac
done

is_uint() {
  case "$1" in
    ''|*[!0-9]*|0[0-9]*) return 1 ;;
    *) [ "${#1}" -le 18 ] ;;
  esac
}

require_uint_setting() {
  local setting_name="$1" setting_value="$2"
  if ! is_uint "$setting_value" || [ "$setting_value" -gt 1000000000 ]; then
    echo "swarm_spawn_preflight: $setting_name must be an integer in 0..1000000000" >&2
    exit 64
  fi
}

validate_policy() {
  require_uint_setting ORACLEMCP_SWARM_MAX_AGENTS "$MAX_AGENTS"
  require_uint_setting ORACLEMCP_SWARM_MIN_CONTEXT_PCT "$MIN_CONTEXT_PCT"
  require_uint_setting ORACLEMCP_SWARM_MEM_PER_AGENT_MIB "$MEM_PER_AGENT_MIB"
  require_uint_setting ORACLEMCP_SWARM_MEM_RESERVE_MIB "$MEM_RESERVE_MIB"
  require_uint_setting ORACLEMCP_SWARM_PIDS_PER_AGENT "$PIDS_PER_AGENT"
  require_uint_setting ORACLEMCP_SWARM_PIDS_RESERVE "$PIDS_RESERVE"
  require_uint_setting ORACLEMCP_SWARM_FDS_PER_AGENT "$FDS_PER_AGENT"
  require_uint_setting ORACLEMCP_SWARM_FDS_RESERVE "$FDS_RESERVE"
  [ "$MAX_AGENTS" -gt 0 ] && [ "$MAX_AGENTS" -le 1000000 ] || {
    echo "swarm_spawn_preflight: max agents must be in 1..1000000" >&2
    exit 64
  }
  [ "$MIN_CONTEXT_PCT" -le 100 ] || {
    echo "swarm_spawn_preflight: minimum context percent cannot exceed 100" >&2
    exit 64
  }
}

min_headroom() {
  # min_headroom CURRENT CANDIDATE; an empty current means no bound seen yet.
  if [ -z "$1" ] || [ "$2" -lt "$1" ]; then
    printf '%s\n' "$2"
  else
    printf '%s\n' "$1"
  fi
}

detect_pids_available() {
  local best="" cg_rel cg_dir cg_max cg_current available
  local nproc_limit uid_tasks system_max system_current

  cg_rel="$(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup)"
  while [ -n "$cg_rel" ]; do
    cg_dir="/sys/fs/cgroup$cg_rel"
    if [ -r "$cg_dir/pids.max" ] && [ -r "$cg_dir/pids.current" ]; then
      cg_max="$(<"$cg_dir/pids.max")"
      cg_current="$(<"$cg_dir/pids.current")"
      if is_uint "$cg_max" && is_uint "$cg_current"; then
        available=$((cg_max > cg_current ? cg_max - cg_current : 0))
        best="$(min_headroom "$best" "$available")"
      fi
    fi
    [ "$cg_rel" = "/" ] && break
    cg_rel="$(dirname "$cg_rel")"
  done

  nproc_limit="$(ulimit -u)"
  if is_uint "$nproc_limit"; then
    uid_tasks="$(ps -eLo ruid= | awk -v uid_value="$(id -u)" \
      '$1 == uid_value { count++ } END { print count + 0 }')"
    available=$((nproc_limit > uid_tasks ? nproc_limit - uid_tasks : 0))
    best="$(min_headroom "$best" "$available")"
  fi

  if [ -r /proc/sys/kernel/threads-max ]; then
    system_max="$(</proc/sys/kernel/threads-max)"
    system_current="$(ps -eL --no-headers | wc -l)"
    if is_uint "$system_max" && is_uint "$system_current"; then
      available=$((system_max > system_current ? system_max - system_current : 0))
      best="$(min_headroom "$best" "$available")"
    fi
  fi

  [ -n "$best" ] || {
    echo "swarm_spawn_preflight: cannot determine a PID/task ceiling" >&2
    return 1
  }
  printf '%s\n' "$best"
}

detect_mem_available_mib() {
  awk '/^MemAvailable:/ { print int($2 / 1024); found=1 } END { exit !found }' \
    /proc/meminfo
}

detect_fds_available() {
  local soft_limit open_fds per_process_available
  local system_allocated system_max system_available best
  local -a fd_entries

  soft_limit="$(ulimit -n)"
  is_uint "$soft_limit" || {
    echo "swarm_spawn_preflight: cannot determine the file-descriptor ceiling" >&2
    return 1
  }
  shopt -s nullglob
  fd_entries=(/proc/$$/fd/*)
  shopt -u nullglob
  open_fds="${#fd_entries[@]}"
  per_process_available=$((soft_limit > open_fds ? soft_limit - open_fds : 0))
  best="$per_process_available"

  if [ -r /proc/sys/fs/file-nr ] && [ -r /proc/sys/fs/file-max ]; then
    read -r system_allocated _ </proc/sys/fs/file-nr
    system_max="$(</proc/sys/fs/file-max)"
    if is_uint "$system_allocated" && is_uint "$system_max"; then
      system_available=$((system_max > system_allocated ? system_max - system_allocated : 0))
      best="$(min_headroom "$best" "$system_available")"
    fi
  fi
  printf '%s\n' "$best"
}

check_wave() {
  local mem_available_mib pids_available fds_available
  local mem_required_mib pids_required fds_required failures=0

  [ -r /proc/meminfo ] && [ -r /proc/self/cgroup ] || {
    echo "swarm_spawn_preflight: REFUSE — Linux /proc and cgroup data are required" >&2
    exit 75
  }
  is_uint "$AGENTS" && [ "$AGENTS" -gt 0 ] && [ "$AGENTS" -le 1000000 ] || usage
  is_uint "$QUOTA_REMAINING" || usage
  is_uint "$CONTEXT_REMAINING_PCT" && [ "$CONTEXT_REMAINING_PCT" -le 100 ] || usage
  [ -n "$REQUESTED_MODEL" ] && [ -n "$CANDIDATE_MODEL" ] || usage
  case "$REQUESTED_MODEL$CANDIDATE_MODEL" in
    *[!A-Za-z0-9._:+/@-]*) usage ;;
  esac

  if $TEST_MODE; then
    mem_available_mib="$TEST_MEM_AVAILABLE_MIB"
    pids_available="$TEST_PIDS_AVAILABLE"
    fds_available="$TEST_FDS_AVAILABLE"
  else
    mem_available_mib="$(detect_mem_available_mib)" || {
      echo "swarm_spawn_preflight: REFUSE — cannot read available memory" >&2
      exit 75
    }
    pids_available="$(detect_pids_available)" || exit 75
    fds_available="$(detect_fds_available)" || exit 75
  fi
  require_uint_setting detected_memory_mib "$mem_available_mib"
  require_uint_setting detected_PID_headroom "$pids_available"
  require_uint_setting detected_FD_headroom "$fds_available"

  mem_required_mib=$((MEM_RESERVE_MIB + AGENTS * MEM_PER_AGENT_MIB))
  pids_required=$((PIDS_RESERVE + AGENTS * PIDS_PER_AGENT))
  fds_required=$((FDS_RESERVE + AGENTS * FDS_PER_AGENT))

  refuse() {
    echo "swarm_spawn_preflight: REFUSE — $1" >&2
    failures=$((failures + 1))
  }

  [ "$AGENTS" -le "$MAX_AGENTS" ] || \
    refuse "wave requests $AGENTS agents; documented ceiling is $MAX_AGENTS"
  [ "$REQUESTED_MODEL" = "$CANDIDATE_MODEL" ] || \
    refuse "candidate model '$CANDIDATE_MODEL' does not match requested '$REQUESTED_MODEL'"
  [ "$QUOTA_REMAINING" -ge "$AGENTS" ] || \
    refuse "quota has $QUOTA_REMAINING spawn slots, but wave needs $AGENTS"
  [ "$CONTEXT_REMAINING_PCT" -ge "$MIN_CONTEXT_PCT" ] || \
    refuse "orchestrator context is ${CONTEXT_REMAINING_PCT}%; floor is ${MIN_CONTEXT_PCT}%"
  [ "$mem_available_mib" -ge "$mem_required_mib" ] || \
    refuse "memory headroom ${mem_available_mib} MiB is below required ${mem_required_mib} MiB"
  [ "$pids_available" -ge "$pids_required" ] || \
    refuse "PID/task headroom $pids_available is below required $pids_required"
  [ "$fds_available" -ge "$fds_required" ] || \
    refuse "file-descriptor headroom $fds_available is below required $fds_required"

  if [ "$failures" -ne 0 ]; then
    echo "swarm_spawn_preflight: blocked ($failures failed check(s)); no agents may spawn" >&2
    exit 75
  fi
  printf 'swarm_spawn_preflight: OK — agents=%s/%s model=%s quota=%s context=%s%% mem=%s/%sMiB pids=%s/%s fds=%s/%s\n' \
    "$AGENTS" "$MAX_AGENTS" "$CANDIDATE_MODEL" "$QUOTA_REMAINING" \
    "$CONTEXT_REMAINING_PCT" "$mem_available_mib" "$mem_required_mib" \
    "$pids_available" "$pids_required" "$fds_available" "$fds_required"
}

selftest() {
  local pass=0 fail=0 rc
  run_case() {
    local case_name="$1" want_rc="$2" description="$3"
    rc=0
    (
      TEST_MODE=true
      TEST_MEM_AVAILABLE_MIB=65536
      TEST_PIDS_AVAILABLE=16384
      TEST_FDS_AVAILABLE=16384
      AGENTS=4
      REQUESTED_MODEL=fable
      CANDIDATE_MODEL=fable
      QUOTA_REMAINING=4
      CONTEXT_REMAINING_PCT=80
      case "$case_name" in
        healthy) ;;
        max-agents) MAX_AGENTS=3 ;;
        model) CANDIDATE_MODEL=wrong ;;
        quota) QUOTA_REMAINING=3 ;;
        context) CONTEXT_REMAINING_PCT=19 ;;
        memory) TEST_MEM_AVAILABLE_MIB=12287 ;;
        pids) TEST_PIDS_AVAILABLE=3071 ;;
        fds) TEST_FDS_AVAILABLE=767 ;;
        *) exit 64 ;;
      esac
      validate_policy
      check_wave
    ) >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq "$want_rc" ]; then
      echo "  PASS  $description (rc=$rc)"
      pass=$((pass + 1))
    else
      echo "  FAIL  $description (rc=$rc, want $want_rc)" >&2
      fail=$((fail + 1))
    fi
  }

  run_case healthy 0 "healthy wave admitted"
  run_case max-agents 75 "static wave ceiling enforced"
  run_case model 75 "model mismatch refused"
  run_case quota 75 "quota exhaustion refused"
  run_case context 75 "near-full orchestrator refused"
  run_case memory 75 "memory headroom enforced"
  run_case pids 75 "PID/task headroom enforced"
  run_case fds 75 "file-descriptor headroom enforced"

  if [ "$fail" -ne 0 ]; then
    echo "swarm_spawn_preflight: selftest FAILED ($fail of $((pass + fail)))" >&2
    exit 1
  fi
  echo "swarm_spawn_preflight: selftest OK ($pass checks)"
}

validate_policy
case "$MODE" in
  check) check_wave ;;
  selftest) selftest ;;
esac
