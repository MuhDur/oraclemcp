#!/usr/bin/env bash
# Live Arc-H fleet reach matrix (bead oraclemcp-epic-09x-alien-6sj8.10.4).
#
# This is deliberately an MCP stdio scenario, not a direct-driver smoke test.
# For each ordered pair of configured lab lanes it proves three independent
# two-profile fleets against the real server:
#
#   * orient: one reachable profile plus a deliberately unreachable companion;
#     the companion is returned as UNREACHABLE rather than aborting or vanishing;
#   * diff: one read-only SQL statement is resolved and run against both live
#     databases, yielding a semantic version delta; and
#   * catalog: an object-name mask is applied before fleet aggregation while a
#     second, hidden profile remains absent from every result and counter.
#
# Lab containers only. The defaults are the local XE 18c / XE 21c / Free 23ai
# lanes. Credentials are supplied solely by environment variables and are never
# written to the repository, diagnostics, or structured events.
#
# Required opt-in:
#   ORACLEMCP_LIVE_XE=1
#   ORACLE_MATRIX_XE18_USER / ORACLE_MATRIX_XE18_PASSWORD
#   ORACLE_MATRIX_XE21_USER / ORACLE_MATRIX_XE21_PASSWORD
#   ORACLE_MATRIX_FREE23_USER / ORACLE_MATRIX_FREE23_PASSWORD
#
# Optional:
#   ORACLE_MATRIX_<LANE>_DSN (defaults to the local lab service)
#   ORACLEMCP_FLEET_BINARY (an already omcpb-built binary)
#   ORACLEMCP_FLEET_LANE_TIMEOUT_SECS (default 300, per ordered pair)
#
# Options:
#   --lane xe18|xe21|free23  repeatable; default is all three lanes in a ring
#   plus the common --log / --dry-run / --help options.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="fleet"
E2E_LANE="fleet-matrix"
E2E_PROFILE="fleet"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

selected_lanes=()
expect_lane_arg=0
for arg in "$@"; do
  if [ "$expect_lane_arg" = "1" ]; then
    selected_lanes+=("$arg")
    expect_lane_arg=0
    continue
  fi
  if [ "$arg" = "--lane" ]; then
    expect_lane_arg=1
    continue
  fi
  set +e
  e2e_parse_common_arg "$arg"
  parsed=$?
  set -e
  case "$parsed" in
    0) continue ;;
    3)
      echo "Run the live Arc-H fleet matrix (orient degrade, cross-DB diff, egress-safe catalog)."
      echo "Options: --lane <xe18|xe21|free23> (repeatable; default all three)"
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "fleet: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done
if [ "$expect_lane_arg" = "1" ]; then
  echo "fleet: --lane needs a value (xe18|xe21|free23)" >&2
  exit 2
fi
[ "${#selected_lanes[@]}" -gt 0 ] || selected_lanes=(xe18 xe21 free23)

lane_dsn() {
  case "$1" in
    xe18) printf '%s\n' "${ORACLE_MATRIX_XE18_DSN:-localhost:1518/XEPDB1}" ;;
    xe21) printf '%s\n' "${ORACLE_MATRIX_XE21_DSN:-localhost:1520/XEPDB1}" ;;
    free23) printf '%s\n' "${ORACLE_MATRIX_FREE23_DSN:-localhost:1522/FREEPDB1}" ;;
    *) return 1 ;;
  esac
}

lane_user() {
  case "$1" in
    xe18) printf '%s\n' "${ORACLE_MATRIX_XE18_USER:-}" ;;
    xe21) printf '%s\n' "${ORACLE_MATRIX_XE21_USER:-}" ;;
    free23) printf '%s\n' "${ORACLE_MATRIX_FREE23_USER:-}" ;;
    *) return 1 ;;
  esac
}

lane_password() {
  case "$1" in
    xe18) printf '%s\n' "${ORACLE_MATRIX_XE18_PASSWORD:-}" ;;
    xe21) printf '%s\n' "${ORACLE_MATRIX_XE21_PASSWORD:-}" ;;
    free23) printf '%s\n' "${ORACLE_MATRIX_FREE23_PASSWORD:-}" ;;
    *) return 1 ;;
  esac
}

lane_env_label() {
  printf '%s' "$1" | tr '[:lower:]' '[:upper:]'
}

# Live suites remain opt-in. Once opted in, a missing/unreachable selected lane
# is a hard failure — silently calling it a green skip would defeat this proof.
connect_or_skip() {
  if [ "${ORACLEMCP_LIVE_XE:-}" != "1" ]; then
    e2e_finish_skip "set ORACLEMCP_LIVE_XE=1 plus ORACLE_MATRIX_*_USER/_PASSWORD to run the fleet matrix"
  fi
  if [ "${#selected_lanes[@]}" -lt 2 ]; then
    e2e_finish_fail "fleet matrix needs at least two --lane values"
  fi
  for lane in "${selected_lanes[@]}"; do
    if ! lane_dsn "$lane" >/dev/null 2>&1; then
      e2e_finish_fail "unknown fleet lane '$lane' (expected xe18|xe21|free23)"
    fi
    local dsn user password upper
    dsn="$(lane_dsn "$lane")"
    user="$(lane_user "$lane")"
    password="$(lane_password "$lane")"
    upper="$(lane_env_label "$lane")"
    if [ -z "$user" ] || [ -z "$password" ]; then
      e2e_finish_fail "ORACLEMCP_LIVE_XE=1 is set but lane $lane is missing ORACLE_MATRIX_${upper}_USER / _PASSWORD"
    fi
    if e2e_value_has_production_marker "$dsn" || e2e_value_has_production_marker "$user"; then
      e2e_finish_fail "refusing production-looking target for fleet lane $lane"
    fi
    if ! e2e_value_has_test_marker "$dsn"; then
      e2e_finish_fail "fleet lane $lane DSN must include a local/free/xe/test marker"
    fi
  done
}

# TOML is runtime-only, but reject characters that could turn a lab variable
# into another config field. The error identifies only the field role, never its
# value, so diagnostics cannot become a credential/DSN side channel.
require_safe_toml_scalar() {
  local label="$1"
  local value="$2"
  case "$value" in
    *$'\n'*|*$'\r'*|*'"'*|*'\\'*) e2e_finish_fail "fleet $label contains unsupported TOML characters" ;;
  esac
}

write_orient_config() {
  local path="$1" dsn="$2" user="$3"
  cat >"$path" <<EOF
schema_version = 2
default_profile = "fleet_live"

[[profiles]]
name = "fleet_live"
description = "fleet e2e reachable lab profile"
connect_string = "$dsn"
username = "$user"
credential_ref = "env:ORACLE_FLEET_PRIMARY_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"

[[profiles]]
name = "fleet_down"
description = "fleet e2e intentionally unreachable lab profile"
connect_string = "//127.0.0.1:1/FLEET_DOWN"
username = "$user"
credential_ref = "env:ORACLE_FLEET_PRIMARY_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"
EOF
}

write_diff_config() {
  local path="$1" left_dsn="$2" left_user="$3" right_dsn="$4" right_user="$5"
  cat >"$path" <<EOF
schema_version = 2
default_profile = "fleet_left"

[[profiles]]
name = "fleet_left"
description = "fleet e2e left lab profile"
connect_string = "$left_dsn"
username = "$left_user"
credential_ref = "env:ORACLE_FLEET_LEFT_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"

[[profiles]]
name = "fleet_right"
description = "fleet e2e right lab profile"
connect_string = "$right_dsn"
username = "$right_user"
credential_ref = "env:ORACLE_FLEET_RIGHT_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"
EOF
}

write_catalog_config() {
  local path="$1" visible_dsn="$2" visible_user="$3" private_dsn="$4" private_user="$5"
  cat >"$path" <<EOF
schema_version = 2
default_profile = "fleet_visible"

[[profiles]]
name = "fleet_visible"
description = "fleet e2e egress-visible lab profile"
connect_string = "$visible_dsn"
username = "$visible_user"
credential_ref = "env:ORACLE_FLEET_LEFT_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"

[profiles.masking]
mask_unknown_default = false

[[profiles.masking.rules]]
column_match = { column = "OBJECT_NAME" }
action = "mask"
tag = "e2e.fleet.object-name"

[[profiles]]
name = "fleet_private"
description = "fleet e2e forbidden lab profile"
connect_string = "$private_dsn"
username = "$private_user"
credential_ref = "env:ORACLE_FLEET_RIGHT_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"
mcp_exposed = false
EOF
}

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "Arc-H live fleet matrix lanes=${selected_lanes[*]}"
connect_or_skip
command -v python3 >/dev/null 2>&1 || e2e_finish_fail "python3 is required for the fleet MCP harness"

if [ -n "${ORACLEMCP_FLEET_BINARY:-}" ]; then
  BINARY="$ORACLEMCP_FLEET_BINARY"
  e2e_log_event "prebuilt_binary" "setup" "pass" 0 "using explicit prebuilt fleet binary"
else
  command -v omcpb >/dev/null 2>&1 || e2e_finish_fail "omcpb is required to build the fleet MCP binary"
  if ! e2e_run_command "setup" omcpb build -p oraclemcp --bin oraclemcp; then
    e2e_finish_fail "building the oraclemcp binary through omcpb failed"
  fi
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: fleet wiring validated, no live lanes exercised"
    e2e_finish_pass
    exit 0
  fi
  build_output="$(e2e_artifact_dir)/output.txt"
  build_target="$(sed -n 's/^omcpb: lane [0-9][0-9]*  target=\([^ ]*\)  jobs=.*/\1/p' "$build_output" | tail -n 1)"
  [ -n "$build_target" ] || e2e_finish_fail "omcpb completed without reporting its selected target directory"
  BINARY="$build_target/debug/oraclemcp"
fi

if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: fleet wiring validated, no live lanes exercised"
  e2e_finish_pass
  exit 0
fi

[ -x "$BINARY" ] || e2e_finish_fail "configured fleet binary not found at $BINARY"
command -v timeout >/dev/null 2>&1 || e2e_finish_fail "timeout is required for live fleet lanes"

run_stamp="$(date -u +"%Y%m%dT%H%M%SZ")-$$"
matrix_dir="$ORACLEMCP_E2E_ARTIFACT_DIR/$E2E_SCENARIO/$run_stamp"
mkdir -p "$matrix_dir"
audit_key="$(openssl rand -hex 32 2>/dev/null || date +%s%N | sha256sum | cut -d' ' -f1)"
lane_timeout_secs="${ORACLEMCP_FLEET_LANE_TIMEOUT_SECS:-300}"

run_pair() {
  set -e
  local left="$1" right="$2"
  local left_dsn left_user left_password right_dsn right_user right_password
  left_dsn="$(lane_dsn "$left")"
  left_user="$(lane_user "$left")"
  left_password="$(lane_password "$left")"
  right_dsn="$(lane_dsn "$right")"
  right_user="$(lane_user "$right")"
  right_password="$(lane_password "$right")"
  require_safe_toml_scalar "left DSN" "$left_dsn"
  require_safe_toml_scalar "left username" "$left_user"
  require_safe_toml_scalar "right DSN" "$right_dsn"
  require_safe_toml_scalar "right username" "$right_user"

  local pair_dir state_dir orient_config diff_config catalog_config evidence
  pair_dir="$matrix_dir/${left}-to-${right}"
  state_dir="$pair_dir/state"
  orient_config="$pair_dir/orient.toml"
  diff_config="$pair_dir/diff.toml"
  catalog_config="$pair_dir/catalog.toml"
  evidence="$pair_dir/evidence.jsonl"
  mkdir -p "$pair_dir" "$state_dir"
  write_orient_config "$orient_config" "$left_dsn" "$left_user"
  write_diff_config "$diff_config" "$left_dsn" "$left_user" "$right_dsn" "$right_user"
  write_catalog_config "$catalog_config" "$left_dsn" "$left_user" "$right_dsn" "$right_user"

  export ORACLE_FLEET_PRIMARY_PASSWORD="$left_password"
  export ORACLE_FLEET_LEFT_PASSWORD="$left_password"
  export ORACLE_FLEET_RIGHT_PASSWORD="$right_password"
  export ORACLEMCP_AUDIT_KEY="$audit_key"
  export XDG_STATE_HOME="$state_dir"
  export E2E_LANE="${left}-to-${right}" E2E_PROFILE="fleet_left" E2E_LEVEL="READ_ONLY"

  e2e_log_event "fleet_pair_start" "act" "running" 0 "ordered live pair $left -> $right"
  set +e
  timeout -k 15 "$lane_timeout_secs" python3 "$ROOT/scripts/e2e/fleet_session.py" \
    --binary "$BINARY" \
    --orient-config "$orient_config" \
    --diff-config "$diff_config" \
    --catalog-config "$catalog_config" \
    --evidence "$evidence" \
    --server-stderr-dir "$pair_dir" \
    >"$pair_dir/session.stdout"
  local status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    e2e_log_event "fleet_pair" "assert" "fail" 0 "ordered live pair $left -> $right failed; evidence=$evidence"
    return 1
  fi

  e2e_log_event "fleet_pair" "assert" "pass" 0 "ordered live pair $left -> $right: unreachable, delta, and egress assertions green"
}

overall_fail=0
for index in "${!selected_lanes[@]}"; do
  next_index=$(((index + 1) % ${#selected_lanes[@]}))
  if ! (run_pair "${selected_lanes[$index]}" "${selected_lanes[$next_index]}"); then
    overall_fail=1
  fi
done

if [ "$overall_fail" -ne 0 ]; then
  e2e_finish_fail "one or more fleet live pairs failed (artifacts: $matrix_dir)"
fi
e2e_finish_pass
