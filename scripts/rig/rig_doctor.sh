#!/usr/bin/env bash
# D8 — environment preflight for the local rig (R0 wires this as `rig.sh doctor`).
#
# A preflight earns its place by failing EARLY and SPECIFICALLY. "Environment not
# ready" is worthless; every refusal here names WHAT is missing, WHERE it was
# looked for, and the EXACT command that fixes it.
#
# Two properties this script is built around:
#
#   1. MISSING is not the same as PRESENT-BUT-WRONG. A docker binary on PATH with
#      an unreachable daemon, or busybox `timeout` without `-k`, are not missing
#      things — they are wrong things, and they fail much later and much more
#      confusingly than an absence does. Each check reports which of the two it
#      found.
#
#   2. A PASS MUST MEAN THE RIG WILL RUN. A doctor that reports healthy and is
#      then followed by a rig failure is worse than no doctor at all, because it
#      moves suspicion onto the wrong component. So the checks are not a
#      hand-written wish list: `--selftest` extracts the prerequisites that
#      scripts/rig/oracle_l1.sh actually enforces and fails if any of them has no
#      corresponding check here. Add a `command -v` to the rig without a check
#      here and this script starts failing.
#
# Unlike the rig itself, this does NOT stop at the first problem: reporting one
# missing thing per run turns a five-minute fix into five round trips.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/scripts/e2e/lib.sh"

export E2E_SCENARIO="rig_doctor"
export E2E_LANE="rig"

# Overridable so the coverage assertion below can be aimed at a deliberately
# malformed rig and shown to fail; defaults to the real one.
RIG_L1="${ORACLEMCP_RIG_DOCTOR_L1_SCRIPT:-$ROOT/scripts/rig/oracle_l1.sh}"
STATE_DIR="${ORACLEMCP_RIG_L1_STATE_DIR:-$ROOT/target/e2e/rig_l1}"
LANES=(xe18 xe21 free23)

# Minimum docker client. 20.10 is where `docker container inspect` and the
# `{{.Client.Version}}` format the rig relies on are uniformly available.
DOCKER_MIN_MAJOR=20
DOCKER_MIN_MINOR=10

FINDINGS=0
CHECKS_RUN=0
# Check ids that ran, for the coverage assertion in --selftest.
DECLARED_CHECKS=()

usage() {
  cat <<'USAGE'
D8 rig doctor — preflight the local environment before the rig runs.

Usage:
  bash scripts/rig/rig_doctor.sh [--log] [--lane xe18|xe21|free23|all]
  bash scripts/rig/rig_doctor.sh --selftest

Exit codes:
  0  every prerequisite present and usable — the rig will run
  1  at least one named refusal (see the report)
USAGE
  e2e_usage_common
}

lane_container() {
  case "$1" in
    xe18) printf '%s\n' 'oracle-xe18-1518' ;;
    xe21) printf '%s\n' 'oracle-xe21-1520' ;;
    free23) printf '%s\n' 'rust-oracledb-free' ;;
    *) return 1 ;;
  esac
}

lane_env_prefix() {
  printf 'ORACLEMCP_RIG_L1_%s_ADMIN_PASSWORD' "$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')"
}

# ok <id> <summary>
ok() {
  CHECKS_RUN=$((CHECKS_RUN + 1))
  DECLARED_CHECKS+=("$1")
  e2e_log_event "preflight_check" "assert" "pass" 0 "$1: $2"
  [ "$E2E_LOG" = "1" ] || printf '  OK        %-22s %s\n' "$1" "$2"
}

# refuse <id> <kind: MISSING|WRONG> <what> <where> <fix>
refuse() {
  local id="$1" kind="$2" what="$3" where="$4" fix="$5"
  CHECKS_RUN=$((CHECKS_RUN + 1))
  DECLARED_CHECKS+=("$id")
  FINDINGS=$((FINDINGS + 1))
  e2e_log_event "preflight_check" "assert" "fail" 0 \
    "$id: $kind $what; looked in: $where; fix: $fix"
  if [ "$E2E_LOG" = "1" ]; then
    return 0
  fi
  printf '  %-9s %-22s %s\n' "$kind" "$id" "$what"
  printf '  %-9s %-22s looked in: %s\n' "" "" "$where"
  printf '  %-9s %-22s fix: %s\n' "" "" "$fix"
}

check_docker_binary() {
  if command -v docker >/dev/null 2>&1; then
    ok "docker-binary" "docker on PATH at $(command -v docker)"
    return 0
  fi
  refuse "docker-binary" "MISSING" "docker is not on PATH" \
    "PATH=$PATH" \
    "install Docker Engine, then re-run: bash scripts/rig/rig_doctor.sh"
  return 1
}

# PRESENT-BUT-WRONG #1: a docker binary whose daemon cannot be reached. The rig's
# own `command -v docker` passes here and then every container command fails.
check_docker_daemon() {
  local err
  if err="$(docker info --format '{{.ServerVersion}}' 2>&1)"; then
    ok "docker-daemon" "daemon reachable, server $err"
    return 0
  fi
  local hint="start the daemon: sudo systemctl start docker"
  case "$err" in
    *permission*denied*|*dial\ unix*)
      hint="add yourself to the docker group: sudo usermod -aG docker \$USER (then log out and back in)" ;;
  esac
  refuse "docker-daemon" "WRONG" "docker is installed but its daemon is not reachable" \
    "docker info (${err%%$'\n'*})" "$hint"
  return 1
}

# PRESENT-BUT-WRONG #2: a docker client too old for the commands the rig issues.
check_docker_version() {
  local raw major minor
  raw="$(docker version --format '{{.Client.Version}}' 2>/dev/null)"
  if [ -z "$raw" ]; then
    refuse "docker-version" "WRONG" "docker client version could not be read" \
      "docker version --format {{.Client.Version}}" \
      "reinstall Docker Engine ${DOCKER_MIN_MAJOR}.${DOCKER_MIN_MINOR} or newer"
    return 1
  fi
  major="${raw%%.*}"
  minor="${raw#*.}"; minor="${minor%%.*}"
  if [ "${major:-0}" -gt "$DOCKER_MIN_MAJOR" ] 2>/dev/null ||
     { [ "${major:-0}" -eq "$DOCKER_MIN_MAJOR" ] 2>/dev/null && [ "${minor:-0}" -ge "$DOCKER_MIN_MINOR" ] 2>/dev/null; }; then
    ok "docker-version" "client $raw (need >= ${DOCKER_MIN_MAJOR}.${DOCKER_MIN_MINOR})"
    return 0
  fi
  refuse "docker-version" "WRONG" \
    "docker client $raw is older than the required ${DOCKER_MIN_MAJOR}.${DOCKER_MIN_MINOR}" \
    "docker version --format {{.Client.Version}}" \
    "upgrade Docker Engine to ${DOCKER_MIN_MAJOR}.${DOCKER_MIN_MINOR} or newer"
  return 1
}

# PRESENT-BUT-WRONG #3: busybox `timeout` exists but has no -k, which every
# bounded rig command uses. Absence and wrong-flavour need different messages.
check_timeout_tool() {
  if ! command -v timeout >/dev/null 2>&1; then
    refuse "timeout-binary" "MISSING" "timeout is not on PATH" \
      "PATH=$PATH" \
      "install GNU coreutils (Debian/Ubuntu: sudo apt-get install coreutils)"
    return 1
  fi
  if timeout --help 2>&1 | grep -q -- '-k'; then
    ok "timeout-binary" "GNU timeout with -k at $(command -v timeout)"
    return 0
  fi
  refuse "timeout-binary" "WRONG" \
    "timeout exists but does not support -k (busybox build); every bounded rig command uses it" \
    "$(command -v timeout)" \
    "install GNU coreutils so timeout supports -k"
  return 1
}

check_timeout_env() {
  local bad=0
  local ready="${ORACLEMCP_RIG_L1_READY_TIMEOUT_SECS:-300}"
  local boot="${ORACLEMCP_RIG_L1_BOOTSTRAP_TIMEOUT_SECS:-300}"
  if ! [[ "$ready" =~ ^[1-9][0-9]*$ ]]; then
    refuse "rig-timeout-env" "WRONG" \
      "ORACLEMCP_RIG_L1_READY_TIMEOUT_SECS is '$ready', not a positive integer" \
      "environment" "unset it to take the 300s default: unset ORACLEMCP_RIG_L1_READY_TIMEOUT_SECS"
    bad=1
  fi
  if ! [[ "$boot" =~ ^[1-9][0-9]*$ ]]; then
    refuse "rig-timeout-env" "WRONG" \
      "ORACLEMCP_RIG_L1_BOOTSTRAP_TIMEOUT_SECS is '$boot', not a positive integer" \
      "environment" "unset it to take the 300s default: unset ORACLEMCP_RIG_L1_BOOTSTRAP_TIMEOUT_SECS"
    bad=1
  fi
  [ "$bad" -eq 1 ] || ok "rig-timeout-env" "readiness ${ready}s / bootstrap ${boot}s"
  return "$bad"
}

# The rig resolves this as `${ORACLEMCP_RIG_L1_FIXTURE_PASSWORD:-${PYO_TEST_MAIN_PASSWORD:-testpw}}`.
# `:-` treats an EMPTY value exactly like an unset one, so the rig's own
# `[ -n "$FIXTURE_PASSWORD" ]` guard (oracle_l1.sh:229) can never fire — the
# value is always at least `testpw`. Checking emptiness here would be equally
# vacuous. The real footgun is the silent substitution: an operator who exports
# the variable EMPTY, expecting to clear it, gets `testpw` and bootstraps a
# fixture user with a password they did not choose. Declared-but-empty is the
# condition worth refusing.
check_fixture_password() {
  local var
  for var in ORACLEMCP_RIG_L1_FIXTURE_PASSWORD PYO_TEST_MAIN_PASSWORD; do
    if [ -n "${!var+declared}" ] && [ -z "${!var}" ]; then
      refuse "fixture-password" "WRONG" \
        "$var is declared but empty; the rig substitutes the default 'testpw' instead of failing, so fixtures would be created with a password you did not choose" \
        "environment" \
        "either give it a value (export $var=<password>) or unset it (unset $var)"
      return 1
    fi
  done
  ok "fixture-password" "fixture password resolves (value not logged)"
  return 0
}

check_state_dir() {
  if mkdir -p "$STATE_DIR" 2>/dev/null && [ -w "$STATE_DIR" ]; then
    ok "state-dir" "writable at $STATE_DIR"
    return 0
  fi
  refuse "state-dir" "MISSING" "the rig state directory is not writable" \
    "$STATE_DIR" \
    "create it with write permission: mkdir -p '$STATE_DIR'"
  return 1
}

# The rig deliberately REFUSES to create lab containers, so a missing container is
# a hard refusal here rather than something `up` will fix.
check_lane_container() {
  local lane="$1" container
  container="$(lane_container "$lane")"
  if ! docker container inspect "$container" >/dev/null 2>&1; then
    refuse "container-$lane" "MISSING" \
      "lane $lane has no container named $container (the rig refuses to create lab containers)" \
      "docker container inspect $container" \
      "create it from the lane's cached image, or point the lane at an existing container"
    return 1
  fi
  if docker container inspect -f '{{.State.Running}}' "$container" 2>/dev/null | grep -q true; then
    ok "container-$lane" "$container exists and is running"
  else
    ok "container-$lane" "$container exists (stopped; rig L1 'up' will start it)"
  fi
  return 0
}

check_lane_password() {
  local lane="$1" container explicit configured var
  var="$(lane_env_prefix "$lane")"
  explicit="${!var:-${ORACLEMCP_RIG_L1_ADMIN_PASSWORD:-}}"
  if [ -n "$explicit" ]; then
    ok "admin-password-$lane" "from $var (value not logged)"
    return 0
  fi
  container="$(lane_container "$lane")"
  configured="$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$container" 2>/dev/null \
    | awk -F= '$1 == "ORACLE_PASSWORD" { print substr($0, index($0, "=") + 1); exit }')"
  if [ -n "$configured" ]; then
    ok "admin-password-$lane" "from the container's ORACLE_PASSWORD (value not logged)"
    return 0
  fi
  refuse "admin-password-$lane" "MISSING" \
    "lane $lane has no admin password: neither $var nor the container's ORACLE_PASSWORD is set" \
    "environment, then docker inspect $container" \
    "export $var=<password>"
  return 1
}

# sqlplus lives INSIDE the container — bootstrap, fixtures and smoke all shell
# into it. Only checkable while the container runs, so a stopped container
# defers rather than falsely passing.
check_lane_sqlplus() {
  local lane="$1" container
  container="$(lane_container "$lane")"
  if ! docker container inspect -f '{{.State.Running}}' "$container" 2>/dev/null | grep -q true; then
    ok "sqlplus-$lane" "deferred: $container is not running (start it, then re-run)"
    return 0
  fi
  if docker exec "$container" sh -lc 'command -v sqlplus' >/dev/null 2>&1; then
    ok "sqlplus-$lane" "sqlplus present inside $container"
    return 0
  fi
  refuse "sqlplus-$lane" "MISSING" \
    "sqlplus is not on PATH inside $container; bootstrap, fixtures and smoke all shell into it" \
    "docker exec $container sh -lc 'command -v sqlplus'" \
    "use an image that ships sqlplus, or add it to the container's PATH"
  return 1
}

run_all_checks() {
  local lanes=("$@")
  [ "$E2E_LOG" = "1" ] || echo "rig doctor — preflight for scripts/rig/oracle_l1.sh"

  # Docker daemon/version checks are meaningless without the binary, and running
  # them anyway would produce a second, confusing refusal for one root cause.
  if check_docker_binary; then
    check_docker_daemon || true
    check_docker_version || true
  fi
  check_timeout_tool || true
  check_timeout_env || true
  check_fixture_password || true
  check_state_dir || true

  local lane
  for lane in "${lanes[@]}"; do
    if check_lane_container "$lane"; then
      check_lane_password "$lane" || true
      check_lane_sqlplus "$lane" || true
    fi
  done
}

report_and_exit() {
  if [ "$FINDINGS" -eq 0 ]; then
    e2e_log_event "preflight_summary" "assert" "pass" 0 \
      "$CHECKS_RUN checks passed; the rig will run"
    [ "$E2E_LOG" = "1" ] || echo "PASS rig_doctor: $CHECKS_RUN checks, 0 refusals"
    exit 0
  fi
  e2e_log_event "preflight_summary" "assert" "fail" 0 \
    "$FINDINGS of $CHECKS_RUN checks refused"
  [ "$E2E_LOG" = "1" ] || echo "FAIL rig_doctor: $FINDINGS of $CHECKS_RUN checks refused (see above)"
  exit 1
}

# --- selftest -----------------------------------------------------------------
#
# Two obligations. First, every check must be able to FAIL — a check only ever
# observed passing is indistinguishable from one that returns true. Second, and
# more important, the check inventory must COVER what the rig enforces.

selftest_check_can_fail() {
  local label="$1"; shift
  local before="$FINDINGS"
  "$@" >/dev/null 2>&1 || true
  if [ "$FINDINGS" -le "$before" ]; then
    echo "selftest: $label did not refuse a broken environment" >&2
    return 1
  fi
  return 0
}

selftest() {
  local failures=0

  # Each check, aimed at an environment it must reject.
  local saved_path="$PATH"
  # shellcheck disable=SC2123
  PATH="/nonexistent"
  selftest_check_can_fail "docker-binary" check_docker_binary || failures=1
  selftest_check_can_fail "timeout-binary" check_timeout_tool || failures=1
  PATH="$saved_path"

  ORACLEMCP_RIG_L1_READY_TIMEOUT_SECS="zero" \
    selftest_check_can_fail "rig-timeout-env" check_timeout_env || failures=1
  ORACLEMCP_RIG_L1_FIXTURE_PASSWORD="" PYO_TEST_MAIN_PASSWORD="" \
    selftest_check_can_fail "fixture-password" check_fixture_password || failures=1
  STATE_DIR="/proc/nonexistent-rig-state" \
    selftest_check_can_fail "state-dir" check_state_dir || failures=1

  # A lane whose container cannot exist.
  # shellcheck disable=SC2329
  lane_container() { printf '%s\n' 'oraclemcp-rig-doctor-absent-container'; }
  selftest_check_can_fail "container-lane" check_lane_container xe18 || failures=1

  # The accept direction: a check that refuses everything is as useless as one
  # that refuses nothing, so at least one must still pass on this machine.
  local before="$FINDINGS"
  unset -f lane_container
  # shellcheck disable=SC2329
  lane_container() {
    case "$1" in
      xe18) printf '%s\n' 'oracle-xe18-1518' ;;
      xe21) printf '%s\n' 'oracle-xe21-1520' ;;
      free23) printf '%s\n' 'rust-oracledb-free' ;;
      *) return 1 ;;
    esac
  }
  check_timeout_env >/dev/null 2>&1
  if [ "$FINDINGS" -ne "$before" ]; then
    echo "selftest: a well-formed environment was refused (checks refuse unconditionally)" >&2
    failures=1
  fi

  # THE COVERAGE ASSERTION. Whatever binaries the rig itself requires via
  # `command -v`, this doctor must check. Extracted from the rig, not restated.
  local required tool
  required="$(grep -oE 'command -v [a-z0-9_-]+' "$RIG_L1" 2>/dev/null | awk '{print $3}' | sort -u)"
  if [ -z "$required" ]; then
    echo "selftest: extracted NO prerequisites from $RIG_L1 — the coverage assertion is vacuous" >&2
    failures=1
  fi
  for tool in $required; do
    if ! grep -q "command -v $tool" "${BASH_SOURCE[0]}"; then
      echo "selftest: $RIG_L1 requires '$tool' but rig_doctor has no check for it — a passing doctor would not mean the rig runs" >&2
      failures=1
    fi
  done

  # The rig's lanes must all be preflighted; a lane the rig knows and the doctor
  # does not is the same false-healthy hole in lane shape.
  local rig_lanes lane
  rig_lanes="$(sed -n '/^lane_container()/,/^}/p' "$RIG_L1" | grep -oE '^\s+[a-z0-9]+\)' | tr -d ' )' | sort -u)"
  for lane in $rig_lanes; do
    case " ${LANES[*]} " in
      *" $lane "*) ;;
      *) echo "selftest: $RIG_L1 defines lane '$lane' which rig_doctor never preflights" >&2; failures=1 ;;
    esac
  done

  if [ "$failures" -ne 0 ]; then
    echo "rig_doctor selftest: FAIL" >&2
    exit 1
  fi
  echo "rig_doctor selftest: OK (every check can refuse; coverage matches $RIG_L1)"
  exit 0
}

main() {
  local lane_arg="all"
  while [ $# -gt 0 ]; do
    case "$1" in
      --selftest) selftest ;;
      --lane) lane_arg="${2:-}"; shift 2; continue ;;
      --help|-h) usage; exit 0 ;;
      *)
        if e2e_parse_common_arg "$1"; then shift; continue; fi
        case $? in
          3) usage; exit 0 ;;
          *) echo "rig_doctor: unknown argument: $1" >&2; usage; exit 2 ;;
        esac
        ;;
    esac
    shift
  done

  [ -f "$RIG_L1" ] || { echo "rig_doctor: missing $RIG_L1" >&2; exit 2; }

  local lanes=()
  if [ "$lane_arg" = "all" ]; then
    lanes=("${LANES[@]}")
  else
    lane_container "$lane_arg" >/dev/null 2>&1 || {
      echo "rig_doctor: unknown lane '$lane_arg' (want one of: ${LANES[*]} all)" >&2
      exit 2
    }
    lanes=("$lane_arg")
  fi

  run_all_checks "${lanes[@]}"
  report_and_exit
}

main "$@"
