#!/usr/bin/env bash
# WP-G hardening acceptance suite (Appendix B.11 + B.13#5/#7).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="hardening_acceptance"
E2E_LANE="hardening"
E2E_PROFILE="release"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

usage() {
  cat <<'USAGE'
Run the WP-G hardening acceptance suite.

This suite aggregates the existing hardening proofs for:
  - surface auth/no-leak inventory;
  - uniform auth errors;
  - honesty and sensitive-data release gates;
  - conformance and golden behavior;
  - audit DB-evidence verification;
  - doctor detect-only self-heal;
  - B.13 recovery, installer, and stdio tail rows.
USAGE
  e2e_usage_common
}

for arg in "$@"; do
  set +e
  e2e_parse_common_arg "$arg"
  parsed=$?
  set -e
  case "$parsed" in
    0) continue ;;
    3)
      usage
      exit 0
      ;;
    1)
      echo "hardening_acceptance: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"
mkdir -p "$ROOT/target/tmp"
e2e_log_event "scenario_start" "setup" "running" 0 "Appendix B.11 and B.13 hardening acceptance suite"

required=(
  scripts/e2e/hardening_acceptance.sh
  scripts/e2e/conformance_coverage.sh
  scripts/e2e/mcp_and_operator_v1_conformance_matrix.sh
  scripts/oraclemcp_honesty_grep.sh
  scripts/sensitive_data_lint.sh
  scripts/installer_lint_and_offline_smoke.sh
  scripts/e2e/COVERAGE.md
  scripts/e2e/PROVENANCE.md
  tests/conformance/COVERAGE.md
  tests/golden/PROVENANCE.md
  crates/oraclemcp/tests/e2e_harness.rs
  crates/oraclemcp/tests/installer_e2e.rs
  crates/oraclemcp/tests/e2e_stdio.rs
  crates/oraclemcp/tests/golden_behavior.rs
  crates/oraclemcp/tests/e2e_http_oauth.rs
  crates/oraclemcp-core/tests/golden_behavior.rs
  crates/oraclemcp-core/tests/mcp_conformance.rs
  crates/oraclemcp-core/src/http/mod.rs
  crates/oraclemcp-core/src/doctor.rs
  crates/oraclemcp/src/main.rs
  crates/oraclemcp/src/service_lifecycle.rs
  crates/oraclemcp/src/dispatch/tests.rs
  crates/oraclemcp-db/tests/structured_schema_golden.rs
)
missing=0
for path in "${required[@]}"; do
  if [ ! -f "$path" ]; then
    echo "missing hardening acceptance file: $path" >&2
    missing=$((missing + 1))
  fi
done
if [ "$missing" -ne 0 ]; then
  e2e_finish_fail "$missing hardening acceptance file(s) missing"
fi

require_text() {
  local path="$1" needle="$2"
  if ! grep -F "$needle" "$path" >/dev/null; then
    e2e_finish_fail "$path must contain: $needle"
  fi
}

require_text scripts/e2e/COVERAGE.md "WP-G hardening acceptance suite"
require_text scripts/e2e/PROVENANCE.md "scripts/e2e/hardening_acceptance.sh --log"
require_text tests/conformance/COVERAGE.md "surface_inventory_authn_no_leak"
require_text tests/conformance/COVERAGE.md "uniform_auth_errors_no_enumeration_oracle"
require_text tests/conformance/COVERAGE.md "audit_verify_with_db_evidence_command_parses"
require_text tests/conformance/COVERAGE.md "audit_db_evidence_summary_correlates_signed_session_tags"
require_text tests/conformance/COVERAGE.md "cp_apply_reclassifies_never_trusts_stored_verdict"
require_text tests/conformance/COVERAGE.md "backup_restore_verifies_audit_chain"
require_text tests/conformance/COVERAGE.md "golden_stdio_main_tool_transcript"
require_text tests/conformance/COVERAGE.md "golden_http_stateful_streamable_session"
require_text tests/conformance/COVERAGE.md "scripts/installer_lint_and_offline_smoke.sh"

for id in B13-RECOVERY-001 B13-INSTALLER-001 B13-STDIO-001; do
  if ! grep -F "| $id |" tests/conformance/COVERAGE.md | grep -F "| covered |" >/dev/null; then
    e2e_finish_fail "$id must be marked covered in tests/conformance/COVERAGE.md"
  fi
done
if grep -F "| B13-" tests/conformance/COVERAGE.md | grep -F "owned by follow-up" >/dev/null; then
  e2e_finish_fail "B.13 follow-up rows must not remain owned by follow-up"
fi

run_gate() {
  local label="$1"
  shift
  if ! e2e_run_command "assert" "$@"; then
    e2e_finish_fail "$label failed"
  fi
}

# For NAME-FILTERED cargo runs. `cargo test <filter>` exits 0 when the filter
# matches nothing, so run_gate alone would keep these gates green while they
# assert nothing (see e2e_cargo_test_filter in lib.sh).
run_test_gate() {
  local label="$1"
  shift
  e2e_cargo_test_filter "assert" "$label" 1 -- \
    env CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/target/tmp" "$@"
}

run_gate "honesty grep including server.json" bash scripts/oraclemcp_honesty_grep.sh
run_gate "sensitive data lint" bash scripts/sensitive_data_lint.sh
run_gate "conformance coverage accounting" bash scripts/e2e/conformance_coverage.sh --log
run_gate "MCP/operator conformance matrix" bash scripts/e2e/mcp_and_operator_v1_conformance_matrix.sh --log
run_gate "installer lint and offline smoke" bash scripts/installer_lint_and_offline_smoke.sh

run_test_gate "surface inventory auth/no-leak" \
  cargo test -p oraclemcp-core surface_inventory_authn_no_leak
run_test_gate "uniform auth errors" \
  cargo test -p oraclemcp-core uniform_auth_errors_no_enumeration_oracle
run_test_gate "doctor self-heal down never up" \
  cargo test -p oraclemcp-core self_heal_down_never_up_refuses_protected_profile_repair

run_test_gate "recovery CP apply reclassification" \
  cargo test -p oraclemcp-core cp_apply_reclassifies_never_trusts_stored_verdict
run_test_gate "recovery config rollback audit" \
  cargo test -p oraclemcp-core operator_config_draft_apply_and_rollback_are_redacted_and_audited
run_test_gate "recovery legacy audit migration" \
  cargo test -p oraclemcp-core legacy_state_layout_detects_and_migrates_audit_jsonl_once
run_test_gate "recovery backup restore audit verify" \
  cargo test -p oraclemcp backup_restore_verifies_audit_chain
run_test_gate "recovery drained profile active refusal" \
  cargo test -p oraclemcp s5_active_drained_profile_refuses_non_diagnostic_work
run_test_gate "recovery draining profile switch refusal" \
  cargo test -p oraclemcp s5_draining_profiles_are_not_listed_or_switchable

run_test_gate "audit verify DB evidence parser" \
  cargo test -p oraclemcp audit_verify_with_db_evidence_command_parses
run_test_gate "audit DB evidence summary" \
  cargo test -p oraclemcp audit_db_evidence_summary

run_gate "HTTP OAuth lane e2e" env CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/target/tmp" \
  cargo test -p oraclemcp --test e2e_http_oauth
run_gate "stdio e2e" env CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/target/tmp" \
  cargo test -p oraclemcp --test e2e_stdio
run_gate "stdio golden behavior" env CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/target/tmp" \
  cargo test -p oraclemcp --test golden_behavior
run_gate "HTTP golden behavior" env CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/target/tmp" \
  cargo test -p oraclemcp-core --test golden_behavior golden_http_stateful_streamable_session
run_gate "MCP conformance" env CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/target/tmp" \
  cargo test -p oraclemcp-core --test mcp_conformance
run_gate "structured schema goldens" env CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/target/tmp" \
  cargo test -p oraclemcp-db --test structured_schema_golden
run_gate "installer e2e contracts" env CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/target/tmp" \
  cargo test -p oraclemcp --test installer_e2e

e2e_log_event "suite_summary" "assert" "pass" 0 "WP-G hardening, B.13 recovery/installer/stdio, conformance, goldens, audit evidence, and leak gates accounted"
e2e_finish_pass
