#!/usr/bin/env bash
# Live Arc-N policy-as-code E2E. The served MCP process starts with a real,
# profile-scoped sql_policy and a disposable table on the local Oracle lab.
# It proves deny, monotone level/predicate narrowing, base-classifier refusal,
# and invalid-policy startup refusal through the actual stdio wire.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="sql_policy"
E2E_LANE="free23"
E2E_PROFILE="policy"
E2E_LEVEL="DDL"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

for arg in "$@"; do
  set +e
  e2e_parse_common_arg "$arg"
  parsed=$?
  set -e
  case "$parsed" in
    0) continue ;;
    3)
      echo "Run the served SQL-policy E2E against the local Oracle lab."
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "sql_policy: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "served SQL-policy MCP proof"
e2e_require_live_oracle_env
command -v python3 >/dev/null 2>&1 || e2e_finish_fail "python3 is required for the SQL-policy MCP harness"

if [ -n "${ORACLEMCP_SQL_POLICY_BINARY:-}" ]; then
  BINARY="$ORACLEMCP_SQL_POLICY_BINARY"
  e2e_log_event "prebuilt_binary" "setup" "pass" 0 "using explicit prebuilt SQL-policy binary"
else
  command -v omcpb >/dev/null 2>&1 || e2e_finish_fail "omcpb is required to build the SQL-policy MCP binary"
  if ! e2e_run_command "setup" omcpb build -p oraclemcp --bin oraclemcp; then
    e2e_finish_fail "building the oraclemcp binary through omcpb failed"
  fi
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: SQL-policy wiring validated, no server started"
    e2e_finish_pass
    exit 0
  fi
  build_output="$(e2e_artifact_dir)/output.txt"
  build_target="$(sed -n 's/^omcpb: lane [0-9][0-9]*  target=\([^ ]*\)  jobs=.*/\1/p' "$build_output" | tail -n 1)"
  [ -n "$build_target" ] || e2e_finish_fail "omcpb completed without reporting its selected target directory"
  BINARY="$build_target/debug/oraclemcp"
fi

if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "scenario_assert" "assert" "skipped" 0 "dry-run: SQL-policy wiring validated, no server started"
  e2e_finish_pass
  exit 0
fi

[ -x "$BINARY" ] || e2e_finish_fail "configured SQL-policy binary not found at $BINARY"
command -v timeout >/dev/null 2>&1 || e2e_finish_fail "timeout is required for the SQL-policy MCP harness"

artifact_root="$(e2e_artifact_dir)"
artifact_root="$(cd "$artifact_root" && pwd)"
run_dir="$artifact_root/free23-$(date -u +"%Y%m%dT%H%M%SZ")-$$"
state_dir="$run_dir/state"
profiles_file="$run_dir/profiles.toml"
bootstrap_profiles_file="$run_dir/bootstrap-profiles.toml"
invalid_profiles_file="$run_dir/invalid-policy.toml"
audit_file="$state_dir/oraclemcp/audit/audit.jsonl"
evidence="$run_dir/sql_policy_evidence.jsonl"
mkdir -p "$run_dir" "$state_dir"

# This value is only written into the ignored per-run config, never a committed
# artifact. Policy selectors are Oracle identifiers, so reject a quoted or
# otherwise nonstandard local lab user rather than generating ambiguous TOML.
policy_schema="$(printf '%s' "$ORACLEMCP_TEST_USER" | tr '[:lower:]' '[:upper:]')"
if ! [[ "$policy_schema" =~ ^[A-Z][A-Z0-9_\$#]{0,29}$ ]]; then
  e2e_finish_fail "ORACLEMCP_TEST_USER must be an unquoted Oracle identifier for the SQL-policy lab"
fi
table="E2E_POLICY_${$}"
audit_key="$(openssl rand -hex 32 2>/dev/null || date +%s%N | sha256sum | cut -d' ' -f1)"

cat >"$profiles_file" <<PROFILES
schema_version = 2
default_profile = "policy"

[[profiles]]
name = "policy"
description = "throwaway local SQL-policy E2E profile"
connect_string = "$ORACLEMCP_TEST_DSN"
username = "$ORACLEMCP_TEST_USER"
credential_ref = "env:E2E_SQL_POLICY_ACTIVE_PASSWORD"
max_level = "DDL"
default_level = "DDL"

[profiles.sql_policy]
version = 1

[[profiles.sql_policy.rules]]
id = "deny-policy-e2e-delete"
match = { schema = "$policy_schema", object = "$table", verb = "delete" }
effect = { kind = "deny" }

[[profiles.sql_policy.rules]]
id = "policy-e2e-query-needs-ddl"
match = { schema = "$policy_schema", object = "$table", verb = "select" }
effect = { kind = "require_level", level = "DDL" }

[[profiles.sql_policy.rules]]
id = "policy-e2e-tenant-seven"
match = { schema = "$policy_schema", object = "$table", verb = "select" }
effect = { kind = "require_predicate", sql_fragment = "tenant_id = 7" }
PROFILES

# Provision the disposable fixture through a separate served process with the
# same DDL-level profile but no policy. A configured policy deliberately
# refuses an unqualified DDL target when the driver cannot establish a
# server-derived CURRENT_SCHEMA; using it to create the fixture would test that
# unrelated fail-closed path instead of the real policy assertions below.
cat >"$bootstrap_profiles_file" <<PROFILES
schema_version = 2
default_profile = "policy"

[[profiles]]
name = "policy"
description = "throwaway SQL-policy E2E fixture bootstrap"
connect_string = "$ORACLEMCP_TEST_DSN"
username = "$ORACLEMCP_TEST_USER"
credential_ref = "env:E2E_SQL_POLICY_ACTIVE_PASSWORD"
max_level = "DDL"
default_level = "DDL"
PROFILES

# A separate profile file deliberately names an unsupported grammar version.
# Config load must reject it before a served dispatcher can run unpoliced.
cat >"$invalid_profiles_file" <<'PROFILES'
schema_version = 2

[[profiles]]
name = "invalid-policy"
description = "synthetic invalid SQL-policy E2E fixture"
connect_string = "localhost:1522/SYNTHETIC"

[profiles.sql_policy]
version = 99
PROFILES

export ORACLEMCP_CONFIG="$profiles_file"
export E2E_SQL_POLICY_ACTIVE_PASSWORD="$ORACLEMCP_TEST_PASSWORD"
export ORACLEMCP_AUDIT_KEY="$audit_key"
export XDG_STATE_HOME="$state_dir"

set +e
timeout -k 15 240 python3 "$ROOT/scripts/e2e/sql_policy_session.py" \
  --binary "$BINARY" \
  --profile policy \
  --policy-config "$profiles_file" \
  --policy-state "$state_dir" \
  --bootstrap-config "$bootstrap_profiles_file" \
  --bootstrap-state "$run_dir/bootstrap-state" \
  --schema "$policy_schema" \
  --table "$table" \
  --audit-file "$audit_file" \
  --invalid-config "$invalid_profiles_file" \
  --invalid-state "$run_dir/invalid-state" \
  --evidence "$evidence" \
  --server-stderr "$run_dir/server.stderr"
status=$?
set -e
if [ "$status" -ne 0 ]; then
  e2e_log_event "sql_policy" "assert" "fail" 0 "served SQL-policy scenario failed; inspect $evidence"
  e2e_finish_fail "served SQL-policy MCP scenario failed"
fi

e2e_log_event "sql_policy" "assert" "pass" 0 "deny, narrow/reclassification, evaluation refusal, base refusal, invalid policy, and wire proof passed"
e2e_finish_pass
