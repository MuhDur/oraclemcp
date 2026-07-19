#!/usr/bin/env bash
# Offline capability smoke (plan section 30.6 Tier 1 / bead H9): a per-step,
# structured-logged sweep of the tool-capability surface that is reachable
# WITHOUT a live Oracle — query, explain-plan guarding, dictionary tools,
# the execute/compile/patch write ladder, and session-level dry-run wiring
# (preview -> confirm -> apply). Every step runs against the repo's existing
# driver-free mocks (crates/oraclemcp/src/dispatch/tests.rs, crates/oraclemcp/
# tests/e2e_stdio.rs, crates/oraclemcp-guard/src/classifier.rs) — this script
# does not add new Rust tests, it re-runs curated, already-proven ones with
# a much finer-grained, capability-labeled log than a bare `cargo test` gives
# you, so a red run tells you WHICH capability broke from the log alone.
#
# What this script does NOT cover (Tier 3, needs a real/live target):
#   - the actual Oracle round trip for oracle_explain_plan (DBMS_XPLAN output)
#     and any live-catalog dictionary read — see crates/oraclemcp-db/tests/
#     live_oracle.rs / live_catalog_resolver.rs and the version-matrix e2e;
#   - the driver connect paths (password/wallet-TCPS/IAM) — see
#     scripts/e2e/real_adb_tcps_signoff.sh and oci_adb_terraform.sh;
#   - SAVEPOINT/ROLLBACK really restoring rows for the reversible workspace —
#     see crates/oraclemcp/tests/reversible_workspace.rs (--features live-xe).
# Those stay exactly where the plan puts them: deliberate, non-per-PR
# dispatch, never a substitute for this offline sweep.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="capability_smoke"
E2E_LANE="stdio"
E2E_PROFILE="offline"
E2E_LEVEL="mixed"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

for arg in "$@"; do
  set +e
  e2e_parse_common_arg "$arg"
  parsed=$?
  set -e
  case "$parsed" in
    0) continue ;;
    3)
      echo "Offline capability smoke: query/explain/dictionary/execute-ladder/session-level, one structured log line per step."
      e2e_usage_common
      exit 0
      ;;
    1)
      echo "capability_smoke: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"

# `cargo test <filter>` that matches ZERO tests still exits 0 ("0 passed") —
# a stale or typo'd filter would silently turn a capability step into a
# no-op that reports "pass" for nothing. Every step below asserts a minimum
# matched/passed test count parsed from the captured libtest summary line,
# not just the process exit code, so that failure mode is caught here
# instead of discovered later as a false-green (retro Theme C).
capability_passed_count() {
  local n
  n="$(grep -oE '[0-9]+ passed' "$1" | tail -1 | grep -oE '[0-9]+' || true)"
  printf '%s\n' "${n:-0}"
}

# capability_step <capability> <narrative> <min_passed> -- <cargo test invocation...>
capability_step() {
  local capability="$1"
  local narrative="$2"
  local min_tests="$3"
  shift 3
  if [ "${1:-}" = "--" ]; then
    shift
  fi

  e2e_log_event "capability_step_start" "act" "running" 0 "$capability: $narrative"
  local start end
  start="$(e2e_epoch_ms)"

  if ! e2e_run_command "act" "$@"; then
    e2e_finish_fail "$capability: command failed -- $*"
  fi

  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_log_event "capability_step_dry_run" "act" "skipped" 0 \
      "$capability: dry-run, matched-test-count not checked"
    return 0
  fi

  local out
  out="$(e2e_artifact_dir)/output.txt"
  local passed
  passed="$(capability_passed_count "$out")"
  end="$(e2e_epoch_ms)"
  if [ "$passed" -lt "$min_tests" ]; then
    e2e_log_event "capability_step_underran" "assert" "fail" "$((end - start))" \
      "$capability: expected >= $min_tests passing test(s), matched $passed -- filter is stale, renamed, or the capability regressed out of the offline set"
    e2e_finish_fail "$capability: only $passed test(s) matched (need >= $min_tests) -- $*"
  fi
  e2e_log_event "capability_step_pass" "assert" "pass" "$((end - start))" \
    "$capability: $passed test(s) passed -- $narrative"
}

# --- 1. query -------------------------------------------------------------
# oracle_query round-trips a real SELECT through the actual registry +
# OracleDispatcher over native stdio JSON-RPC, against a driver-free mock;
# proves structuredContent matches the advertised outputSchema and that
# NUMBER stays a lossless string.
capability_step "query" \
  "oracle_query structuredContent matches its advertised outputSchema (NUMBER-as-string preserved), driven end to end over stdio" \
  1 -- \
  cargo test -p oraclemcp --test e2e_stdio -- oracle_query_structured_content_matches_advertised_output_schema_fields

# --- 2. explain -------------------------------------------------------------
# EXPLAIN PLAN is guarded (never classified plain-safe) at the classifier,
# and the registry's advertised outputSchema/required_level for
# oracle_explain_plan is truthful -- both provable with no database.
capability_step "explain" \
  "EXPLAIN PLAN is never classified plain-safe by the guard, and oracle_query/oracle_explain_plan advertise truthful output schemas" \
  1 -- \
  cargo test -p oraclemcp-guard --lib -- classifier::tests::explain_plan_is_guarded_never_safe
capability_step "explain" \
  "the registry's oracle_explain_plan tool descriptor advertises a truthful outputSchema (diagnostic_write.required_level = READ_WRITE)" \
  1 -- \
  cargo test -p oraclemcp --lib -- registry::tests::query_and_explain_plan_declare_truthful_output_schemas

# --- 3. dictionary ----------------------------------------------------------
# The dictionary tool surface (describe/get_ddl/get_source/sample_rows/
# read_clob/compile_errors/search_source/plscope_inspect, list_schemas,
# search_objects) accepts its documented argument aliases and qualified
# names, and returns owner-qualified, well-shaped results -- against a
# driver-free mock, no live catalog needed.
capability_step "dictionary" \
  "oracle_describe/get_ddl/get_source/sample_rows/read_clob/compile_errors/search_source/plscope_inspect accept default-owner + qualified-name aliases" \
  1 -- \
  cargo test -p oraclemcp --lib -- dispatch::tests::dictionary_tools_accept_default_owner_qualified_names_and_aliases
capability_step "dictionary" \
  "oracle_list_schemas accepts its filter/limit aliases" \
  1 -- \
  cargo test -p oraclemcp --lib -- dispatch::tests::list_schemas_accepts_filter_and_limit_alias
capability_step "dictionary" \
  "oracle_search_objects honors detail levels and truncates predictably" \
  1 -- \
  cargo test -p oraclemcp --lib -- dispatch::tests::search_objects_detail_levels_and_truncation_through_dispatch
capability_step "dictionary" \
  "a failing dictionary lookup (oracle_schema_inspect against a mock ORA-00942) returns a structured isError envelope over stdio, never a panic" \
  1 -- \
  cargo test -p oraclemcp --test e2e_stdio -- live_tool_offline_returns_a_structured_error_envelope_not_a_panic

# --- 4. execute-ladder -------------------------------------------------------
# The audited write ladder: session-level escalation, oracle_execute/
# oracle_compile_object/oracle_patch_source pending-then-signed audit
# outcomes, masked-read audit-bound certificates, and every audit-write-
# failure path refusing before it ever reaches the database. This is the
# `dispatch::tests::audit_wiring` submodule in full (16 tests) -- the
# deterministic half of Arc I the reversible-workspace live suite documents
# as living here.
capability_step "execute_ladder" \
  "session escalation, execute/compile/patch pending->signed audit records, masked-read certificates, and audit-write-fail-closed all run before/around DB I/O, never bypassing it" \
  10 -- \
  cargo test -p oraclemcp --lib -- dispatch::tests::audit_wiring::

# --- 5. session-level dry-run wiring -----------------------------------------
# oracle_set_session_level's preview -> confirm -> apply cycle: elevation
# previews before it takes effect, requires confirmation to apply, can
# always lower without confirmation, cannot exceed the profile ceiling, and
# a stale confirmation grant is refused even when the live gate would allow
# it (SEC-1: the guard re-checks at apply, it never trusts a stored
# verdict). Plus the tools/list protocol surface: hidden/visible tools flip
# correctly across READ_ONLY vs an elevated DDL session, and an
# `oracle:read` scope grant clamps the ceiling even on a DDL-capable
# profile.
capability_step "session_level" \
  "oracle_set_session_level preview/confirm/lower/ceiling-clamp/stale-grant-refusal, offline, no live gate involved" \
  5 -- \
  cargo test -p oraclemcp --lib -- set_session_level_
capability_step "session_level" \
  "tools/list hides write-ladder tools at READ_ONLY and reveals them at an elevated DDL level; explain_plan's required_level is advertised truthfully" \
  1 -- \
  cargo test -p oraclemcp --test e2e_stdio -- tools_list_reflects_the_calling_session_level
capability_step "session_level" \
  "an oracle:read scope grant clamps tools/list to read-only even on a DDL-capable profile" \
  1 -- \
  cargo test -p oraclemcp --test e2e_stdio -- tools_list_honors_request_scope_ceiling

e2e_log_event "coverage_summary" "assert" "pass" 0 \
  "Tier-1 offline covered: query, explain (classifier+registry), dictionary (8 tools), execute-ladder (audit_wiring, 16 tests), session-level (set_session_level_ + tools/list ladder+scope). Tier-3 deferred: live EXPLAIN PLAN/DBMS_XPLAN output, live dictionary catalog reads, driver connect paths (password/wallet-TCPS/IAM), and SAVEPOINT/ROLLBACK really restoring rows -- see real_adb_tcps_signoff.sh, oci_adb_terraform.sh, reversible_workspace.rs --features live-xe."
e2e_finish_pass
