#!/usr/bin/env bash
# Served MCP governed-egress proof (bead oraclemcp-2slc).
#
# This is intentionally a real stdio client -> served oraclemcp -> real Oracle
# path. It uses only SELECT literals from dual, so the fixture has no DDL,
# writes, or cleanup burden. The Python client verifies the raw JSON-RPC reply
# bytes as received, then independently re-derives the client certificate from
# the signed audit record.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="served_egress"
E2E_LANE="free23"
E2E_PROFILE="egress_visible"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

for arg in "$@"; do
  set +e
  e2e_parse_common_arg "$arg"
  parsed=$?
  set -e
  case "$parsed" in
    0) continue ;;
    3)
      echo "Exercise served MCP result masking and hidden-profile non-inference against FREE 23ai."
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "served_egress: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

live_or_skip() {
  if [ "${ORACLEMCP_LIVE_XE:-}" != "1" ]; then
    e2e_finish_skip "set ORACLEMCP_LIVE_XE=1 plus ORACLEMCP_SERVED_EGRESS_USER/_PASSWORD to run served egress"
  fi
  if [ -z "${ORACLEMCP_SERVED_EGRESS_USER:-}" ] || [ -z "${ORACLEMCP_SERVED_EGRESS_PASSWORD:-}" ]; then
    e2e_finish_fail "ORACLEMCP_LIVE_XE=1 is set but served-egress user or password is missing"
  fi
  if e2e_value_has_production_marker "$ORACLEMCP_SERVED_EGRESS_DSN" ||
    e2e_value_has_production_marker "$ORACLEMCP_SERVED_EGRESS_USER"; then
    e2e_finish_fail "refusing production-looking served-egress target"
  fi
  if ! e2e_value_has_test_marker "$ORACLEMCP_SERVED_EGRESS_DSN"; then
    e2e_finish_fail "served-egress DSN must include a local/free/xe/test marker"
  fi
}

# Runtime TOML must not let a lab variable inject another field. Diagnostics
# name only the role, never the credential or connect string value.
require_safe_toml_scalar() {
  local label="$1"
  local value="$2"
  case "$value" in
    *$'\n'*|*$'\r'*|*'"'*|*'\\'*) e2e_finish_fail "served-egress $label contains unsupported TOML characters" ;;
  esac
}

write_profile() {
  local path="$1" audit_path="$2" include_hidden="$3"
  cat >"$path" <<EOF
schema_version = 2
default_profile = "egress_visible"

[audit]
path = "$audit_path"
key_id = "served-egress-e2e"
key_ref = "env:ORACLEMCP_AUDIT_KEY"

[[profiles]]
name = "egress_visible"
description = "served egress E2E visible FREE 23ai profile"
connect_string = "$ORACLEMCP_SERVED_EGRESS_DSN"
username = "$ORACLEMCP_SERVED_EGRESS_USER"
credential_ref = "env:E2E_SERVED_EGRESS_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"

[profiles.masking]
mask_unknown_default = true

[[profiles.masking.rules]]
column_match = { column = "POLICY_MASKED" }
action = "mask"
tag = "e2e.served-egress.explicit"
EOF

  if [ "$include_hidden" = "1" ]; then
    cat >>"$path" <<EOF

[[profiles]]
name = "egress_hidden"
description = "served egress E2E caller-invisible profile"
connect_string = "$ORACLEMCP_SERVED_EGRESS_DSN"
username = "$ORACLEMCP_SERVED_EGRESS_USER"
credential_ref = "env:E2E_SERVED_EGRESS_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"
mcp_exposed = false

[profiles.masking]
mask_unknown_default = true

[[profiles.masking.rules]]
column_match = { column = "POLICY_MASKED" }
action = "mask"
tag = "e2e.served-egress.hidden"
EOF
  fi
}

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "served MCP result-masking and profile non-inference proof"

ORACLEMCP_SERVED_EGRESS_DSN="${ORACLEMCP_SERVED_EGRESS_DSN:-localhost:1522/FREEPDB1}"
export ORACLEMCP_SERVED_EGRESS_DSN
live_or_skip
require_safe_toml_scalar "DSN" "$ORACLEMCP_SERVED_EGRESS_DSN"
require_safe_toml_scalar "username" "$ORACLEMCP_SERVED_EGRESS_USER"
command -v python3 >/dev/null 2>&1 || e2e_finish_fail "python3 is required for the served-egress MCP harness"

if [ -n "${ORACLEMCP_SERVED_EGRESS_BINARY:-}" ]; then
  BINARY="$ORACLEMCP_SERVED_EGRESS_BINARY"
  e2e_log_event "prebuilt_binary" "setup" "pass" 0 "using explicit prebuilt served-egress binary"
else
  command -v omcpb >/dev/null 2>&1 || e2e_finish_fail "omcpb is required to build the served-egress MCP binary"
  if ! e2e_run_command "setup" omcpb build -p oraclemcp --bin oraclemcp; then
    e2e_finish_fail "building the oraclemcp binary through omcpb failed"
  fi
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: served-egress wiring validated, no server started"
    e2e_finish_pass
    exit 0
  fi
  build_output="$(e2e_artifact_dir)/output.txt"
  build_target="$(sed -n 's/^omcpb: lane [0-9][0-9]*  target=\([^ ]*\)  jobs=.*/\1/p' "$build_output" | tail -n 1)"
  [ -n "$build_target" ] || e2e_finish_fail "omcpb completed without reporting its selected target directory"
  BINARY="$build_target/debug/oraclemcp"
fi

if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: served-egress wiring validated, no server started"
  e2e_finish_pass
  exit 0
fi

[ -x "$BINARY" ] || e2e_finish_fail "configured served-egress binary not found at $BINARY"
command -v timeout >/dev/null 2>&1 || e2e_finish_fail "timeout is required for the served-egress MCP harness"

run_dir="$(e2e_artifact_dir)/free23-$(date -u +"%Y%m%dT%H%M%SZ")-$$"
mkdir -p "$run_dir"
audit_key="$(openssl rand -hex 32 2>/dev/null || date +%s%N | sha256sum | cut -d' ' -f1)"
hidden_config="$run_dir/with-hidden.toml"
baseline_config="$run_dir/visible-only.toml"
hidden_audit="$run_dir/with-hidden-audit.jsonl"
baseline_audit="$run_dir/visible-only-audit.jsonl"
evidence="$run_dir/evidence.jsonl"
write_profile "$hidden_config" "$hidden_audit" 1
write_profile "$baseline_config" "$baseline_audit" 0

export ORACLEMCP_AUDIT_KEY="$audit_key"
export E2E_SERVED_EGRESS_PASSWORD="$ORACLEMCP_SERVED_EGRESS_PASSWORD"
export XDG_STATE_HOME="$run_dir/state"
set +e
timeout -k 15 180 python3 "$ROOT/scripts/e2e/served_egress_session.py" \
  --binary "$BINARY" \
  --hidden-config "$hidden_config" \
  --baseline-config "$baseline_config" \
  --hidden-audit "$hidden_audit" \
  --baseline-audit "$baseline_audit" \
  --state-home "$run_dir/state" \
  --evidence "$evidence" \
  --server-stderr-dir "$run_dir/server-stderr"
status=$?
set -e
if [ "$status" -ne 0 ]; then
  e2e_log_event "served_egress" "assert" "fail" 0 "served egress scenario failed; inspect sanitized evidence under $run_dir"
  e2e_finish_fail "served egress MCP scenario failed"
fi

e2e_log_event "served_egress" "assert" "pass" 0 "raw wire masking, certificate re-derivation, and hidden-profile non-inference passed"
e2e_finish_pass
