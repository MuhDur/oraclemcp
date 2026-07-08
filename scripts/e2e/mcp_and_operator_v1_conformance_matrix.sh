#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="mcp_and_operator_v1_conformance_matrix"
E2E_LANE="operator-v1"
E2E_PROFILE="offline"
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
      echo "Validate B.6 MCP + operator v1 conformance accounting and schema fixtures."
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "mcp_and_operator_v1_conformance_matrix: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"
e2e_log_event "scenario_start" "setup" "running" 0 "B.6 MCP + operator v1 conformance"
mkdir -p "$ROOT/target/tmp"

required=(
  tests/conformance/COVERAGE.md
  schemas/operator.schema.json
  ui/generated/operator-v1.ts
  scripts/ui_fixtures_validate_against_rust_schema.sh
  tests/fixtures/ui/operator-v1/route-index.json
  tests/fixtures/ui/operator-v1/change-proposals.json
  tests/fixtures/ui/operator-v1/event-snapshot.json
)
missing=0
for path in "${required[@]}"; do
  if [ ! -f "$path" ]; then
    echo "missing required B.6 file: $path" >&2
    missing=$((missing + 1))
  fi
done
if [ "$missing" -ne 0 ]; then
  e2e_finish_fail "$missing required B.6 file(s) missing"
fi

if ! grep -F "| Operator v1 | 9 | 0 | 9 | 9 | 0 | 100% |" tests/conformance/COVERAGE.md >/dev/null; then
  e2e_finish_fail "Operator v1 MUST coverage must be 9/9 score=1.00"
fi
if ! grep -F "| HTTP client credentials | 1 | 0 | 1 | 1 | 0 | 100% |" tests/conformance/COVERAGE.md >/dev/null; then
  e2e_finish_fail "HTTP client credential coverage must include isolated rotate/revoke"
fi
if ! grep -F "| Dashboard B.8 | 10 | 0 | 10 | 10 | 0 | 100% |" tests/conformance/COVERAGE.md >/dev/null; then
  e2e_finish_fail "Dashboard B.8 coverage must include W10 client credentials"
fi
if ! grep -F "| HTTP negotiation | 2 | 0 | 2 | 2 | 0 | 100% |" tests/conformance/COVERAGE.md >/dev/null; then
  e2e_finish_fail "HTTP negotiation coverage must include MCP-Protocol-Version"
fi
if ! grep -F "| Durable SQL idempotency | 1 | 0 | 1 | 1 | 0 | 100% |" tests/conformance/COVERAGE.md >/dev/null; then
  e2e_finish_fail "Durable SQL idempotency coverage must include cross-restart replay protection"
fi
if ! grep -F "| WP-N concurrency/session | 11 | 0 | 11 | 11 | 0 | 100% |" tests/conformance/COVERAGE.md >/dev/null; then
  e2e_finish_fail "WP-N concurrency/session coverage must include the N9 contract"
fi
if ! grep -F "| WP-S persistent service | 2 | 0 | 2 | 2 | 0 | 100% |" tests/conformance/COVERAGE.md >/dev/null; then
  e2e_finish_fail "WP-S persistent service coverage must include backup/restore audit verification and S4"
fi
if ! grep -F "| WP-G hardening/docs | 1 | 0 | 1 | 1 | 0 | 100% |" tests/conformance/COVERAGE.md >/dev/null; then
  e2e_finish_fail "WP-G hardening/docs coverage must include audit verify DB evidence"
fi
if ! grep -F "Total tracked requirements: 79 MUST, 2 SHOULD, 81 tested." tests/conformance/COVERAGE.md >/dev/null; then
  e2e_finish_fail "B.6 coverage totals are stale (regenerate: bash scripts/gen_coverage_report.sh --write)"
fi
if grep -RInE '(^|[^A-Z])SKIP([^A-Z]|$)' tests/conformance/COVERAGE.md >/dev/null; then
  e2e_finish_fail "B.6 conformance docs must use XFAIL terminology, not SKIP"
fi

e2e_run_command "assert" scripts/ui_fixtures_validate_against_rust_schema.sh
e2e_run_command "assert" env CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/target/tmp" \
  cargo test -p oraclemcp-core --lib http::tests::
e2e_run_command "assert" env CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/target/tmp" \
  cargo test -p oraclemcp-core --test mcp_conformance
e2e_run_command "assert" env CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/target/tmp" \
  cargo test -p oraclemcp --test e2e_http_oauth
e2e_run_command "assert" env CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/target/tmp" \
  cargo test -p oraclemcp-db --test structured_schema_golden
e2e_run_command "assert" env CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/target/tmp" \
  cargo test -p oraclemcp-core resolved_intent_survives_reopen_and_rejects_same_grant_sql_replay
e2e_run_command "assert" env CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/target/tmp" \
  cargo test -p oraclemcp build_write_intent_log_fails_closed_on_unresolved_restart_intent
e2e_run_command "assert" env CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/target/tmp" \
  cargo test -p oraclemcp execute_commit_in_doubt_leaves_durable_intent_unresolved

e2e_log_event "coverage_summary" "assert" "pass" 0 "B.6 + dashboard + WP-N/WP-S/WP-G MUST coverage 75/75 score=1.00"
e2e_finish_pass
