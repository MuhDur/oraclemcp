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
EOF
binary="${ORACLEMCP_SELFTEST_BINARY:-$ROOT/target/swarm-GreenTiger/debug/oraclemcp}"
if [ ! -x "$binary" ]; then e2e_run_command setup cargo build -p oraclemcp; binary="$ROOT/target/swarm-GreenTiger/debug/oraclemcp"; fi
# This selector belongs to the outer harness.  The child config loader treats
# every ORACLEMCP_* variable as server configuration and correctly rejects it.
unset ORACLEMCP_SELFTEST_BINARY ORACLEMCP_E2E_ARTIFACT_DIR
export ORACLEMCP_CONFIG="$profiles" E2E_SELFTEST_PASSWORD="$ORACLEMCP_TEST_PASSWORD" XDG_STATE_HOME="$run_dir/state"
e2e_run_command assert python3 "$ROOT/scripts/e2e/w4/export_selftest_cases.py" --check
set +e; "$binary" --json selftest --profile selftest_admin --budget 120 >"$run_dir/clean.json" 2>"$run_dir/clean.stderr"; clean_status=$?; set -e
[ "$clean_status" -eq 0 ] || { cat "$run_dir/clean.stderr" >&2; e2e_finish_fail "selftest_e2e_clean_lane_exit_0 status=$clean_status"; }
grep -Fq 'pinned max_level = READ_ONLY' "$run_dir/clean.json" || e2e_finish_fail "forced READ_ONLY not reported"
# The live Oracle listener accepts TCP but cannot speak MCP/HTTP.  That makes
# this a deterministic transport defect (exit 2), unlike an unresolvable host
# which is deliberately classified as an environmental finding (exit 3).
canary="http://${ORACLEMCP_TEST_DSN#//}/oraclemcp-selftest-canary"
set +e; "$binary" --json selftest --profile selftest_admin --http "$canary" --issue-draft "$run_dir/drafts" --budget 120 >"$run_dir/defect.json" 2>"$run_dir/defect.stderr"; defect_status=$?; set -e
[ "$defect_status" -eq 2 ] || e2e_finish_fail "selftest_e2e_injected_defect_exit_2 status=$defect_status"
grep -R -Fq "$canary" "$run_dir/defect.json" "$run_dir/drafts" && e2e_finish_fail "selftest_e2e_redaction_canaries leaked HTTP canary"
[ "$(find "$run_dir/drafts" -name 'selftest-*.md' -type f | wc -l)" -ge 1 ] || e2e_finish_fail "injected defect wrote no issue draft"
e2e_finish_pass
