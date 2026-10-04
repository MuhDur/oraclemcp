#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"
E2E_SCENARIO=selftest E2E_LANE=free23 E2E_PROFILE=selftest_admin E2E_LEVEL=READ_ONLY
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL
for arg in "$@"; do
  case "$arg" in --log|--dry-run) e2e_parse_common_arg "$arg";; --help|-h) echo "Usage: scripts/e2e/selftest.sh [--log] [--dry-run]"; exit 0;; *) e2e_finish_fail "unknown argument: $arg";; esac
done
if [ "$E2E_DRY_RUN" = 1 ]; then e2e_run_command assert python3 "$ROOT/scripts/e2e/w4/export_selftest_cases.py" --check; e2e_finish_pass; fi
e2e_require_live_oracle_env
run_dir="${ORACLEMCP_E2E_ARTIFACT_DIR:-$ROOT/target/e2e-artifacts}/selftest"
mkdir -p "$run_dir/state" "$run_dir/drafts"
profiles="$run_dir/profiles.toml"
cat >"$profiles" <<EOF
schema_version = 2
default_profile = "selftest_admin"
[[profiles]]
name = "selftest_admin"
connect_string = "${ORACLEMCP_TEST_DSN}"
username = "${ORACLEMCP_TEST_USER}"
credential_ref = "env:E2E_SELFTEST_PASSWORD"
max_level = "ADMIN"
default_level = "READ_ONLY"
call_timeout_seconds = 30
EOF
binary="${ORACLEMCP_SELFTEST_BINARY:-${CARGO_TARGET_DIR:-$ROOT/target}/debug/oraclemcp}"
if [ ! -x "$binary" ]; then e2e_run_command setup cargo build -p oraclemcp; binary="${CARGO_TARGET_DIR:-$ROOT/target}/debug/oraclemcp"; fi
# This selector belongs to the outer harness.  The child config loader treats
# every ORACLEMCP_* variable as server configuration and correctly rejects it.
export ORACLEMCP_CONFIG="$profiles" E2E_SELFTEST_PASSWORD="$ORACLEMCP_TEST_PASSWORD" XDG_STATE_HOME="$run_dir/state"
e2e_run_command assert python3 "$ROOT/scripts/e2e/w4/export_selftest_cases.py" --check
set +e; env -u ORACLEMCP_SELFTEST_BINARY -u ORACLEMCP_E2E_ARTIFACT_DIR "$binary" --json selftest --profile selftest_admin --budget 120 >"$run_dir/clean.json" 2>"$run_dir/clean.stderr"; clean_status=$?; set -e
[ "$clean_status" -eq 0 ] || { cat "$run_dir/clean.stderr" >&2; e2e_finish_fail "selftest_e2e_clean_lane_exit_0 status=$clean_status"; }
grep -Fq 'pinned max_level = READ_ONLY' "$run_dir/clean.json" || e2e_finish_fail "forced READ_ONLY not reported"
python3 - "$run_dir/clean.json" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
writes = [outcome for outcome in report["outcomes"] if outcome["probe"].startswith("write:")]
if not writes or any(outcome["outcome"] != "expected_refusal" for outcome in writes):
    raise SystemExit("selftest_e2e_forced_readonly_on_admin_profile: write sweep was not wholly expected_refusal")
if report.get("audit_records") != 0:
    raise SystemExit("selftest_e2e_forced_readonly_on_admin_profile: audit recorded a probe action")
PY
# The live Oracle listener accepts TCP but cannot speak MCP/HTTP.  That makes
# this a deterministic transport defect (exit 2), unlike an unresolvable host
# which is deliberately classified as an environmental finding (exit 3).
canary_host='selftest-host-canary.invalid'
canary_schema='SELFTEST_SCHEMA_CANARY'
canary_table='SELFTEST_TABLE_CANARY'
canary_bind='selftest-bind-canary'
canary_password='selftest-password-canary'
canary="http://${ORACLEMCP_TEST_DSN#//}/${canary_host}/${canary_schema}/${canary_table}?bind=${canary_bind}&password=${canary_password}"
set +e; env -u ORACLEMCP_SELFTEST_BINARY -u ORACLEMCP_E2E_ARTIFACT_DIR "$binary" --json selftest --profile selftest_admin --http "$canary" --issue-draft "$run_dir/drafts" --budget 120 >"$run_dir/defect.json" 2>"$run_dir/defect.stderr"; defect_status=$?; set -e
[ "$defect_status" -eq 2 ] || e2e_finish_fail "selftest_e2e_injected_defect_exit_2 status=$defect_status"
for canary_marker in "$canary_host" "$canary_schema" "$canary_table" "$canary_bind" "$canary_password"; do
  if grep -R -Fq "$canary_marker" "$run_dir/defect.json" "$run_dir/defect.stderr" "$run_dir/drafts"; then
    e2e_finish_fail "selftest_e2e_redaction_canaries leaked $canary_marker"
  fi
done
[ "$(find "$run_dir/drafts" -name 'selftest-*.md' -type f | wc -l)" -ge 1 ] || e2e_finish_fail "injected defect wrote no issue draft"
e2e_finish_pass
