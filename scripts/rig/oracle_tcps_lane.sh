#!/usr/bin/env bash
# Rig D6: local synthetic TCPS lane.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="rig_tcps_lane"
E2E_LANE="oracle-tcps"
E2E_PROFILE="synthetic-local"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

CARGO_TARGET_DIR="${ORACLEMCP_RIG_CARGO_TARGET_DIR:-$ROOT/target}"
export CARGO_TARGET_DIR

usage() {
  cat <<'USAGE'
Local synthetic TCPS lane.

Usage:
  bash scripts/rig/oracle_tcps_lane.sh [run] [--log|--dry-run]

Validates:
  B5    UnknownIssuer with retry_count=20 returns inside the fast budget.
  B6    SSL_CERT_FILE and SSL_CERT_DIR trust synthetic public roots.
  P2-4  Wallet profile with unset SNI reaches the local TCPS terminator.
  P-U4  Legacy 3DES ewallet.p12 decrypts through the server wallet path.
USAGE
  e2e_usage_common
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      run) shift ;;
      --help|-h) usage; exit 0 ;;
      *)
        if e2e_parse_common_arg "$1"; then shift; continue; fi
        case $? in
          3) usage; exit 0 ;;
          *) e2e_finish_fail "unknown argument: $1" ;;
        esac
        ;;
    esac
  done
}

assert_no_field_material_markers() {
  local pattern='ocid1|oraclecloud\.com|adb\.[[:alnum:].-]+|tenancy'
  local paths=(
    "$ROOT/crates/oraclemcp-core/tests/oci_tcps_e2e.rs"
    "$ROOT/crates/oraclemcp-core/tests/fixtures/wallet/PROVENANCE.md"
  )
  if command -v rg >/dev/null 2>&1; then
    if rg -n -i "$pattern" "${paths[@]}"; then
      e2e_finish_fail "D6 lane contains non-synthetic TCPS material markers"
    fi
  else
    if grep -R -n -i -E "$pattern" "${paths[@]}"; then
      e2e_finish_fail "D6 lane contains non-synthetic TCPS material markers"
    fi
  fi
  e2e_log_event "synthetic_material_scan" "assert" "pass" 0 "D6 lane has no field-material markers"
}

run_b5_current_red() {
  local output status=0 started end
  started="$(e2e_epoch_ms)"
  e2e_log_event "command_start" "assert" "running" 0 \
    "cargo test -p oraclemcp-core --test oci_tcps_e2e b5_unknown_issuer_with_retry_count_20_fails_inside_fast_budget -- --ignored --nocapture"
  if [ "$E2E_DRY_RUN" = "1" ]; then
    end="$(e2e_epoch_ms)"
    e2e_log_event "command_dry_run" "assert" "skipped" "$((end - started))" "B5 current-red validation"
    return 0
  fi
  set +e
  output="$(cargo test -p oraclemcp-core --test oci_tcps_e2e \
    b5_unknown_issuer_with_retry_count_20_fails_inside_fast_budget -- --ignored --nocapture 2>&1)"
  status=$?
  set -e
  printf '%s\n' "$output"
  if [ "$status" -eq 0 ]; then
    e2e_finish_fail "B5 unexpectedly green; flip the lane to assert fast UnknownIssuer success"
  fi
  if ! printf '%s\n' "$output" | grep -F 'test b5_unknown_issuer_with_retry_count_20_fails_inside_fast_budget' >/dev/null; then
    e2e_finish_fail "B5 current-red filter matched no test"
  fi
  if ! printf '%s\n' "$output" | grep -F 'call timeout of 20000 ms exceeded' >/dev/null; then
    e2e_finish_fail "B5 current-red signature changed; expected the 20s call-timeout failure"
  fi
  end="$(e2e_epoch_ms)"
  e2e_log_event "current_red_observed" "assert" "pass" "$((end - started))" \
    "B5 current-red: UnknownIssuer still burns the 20s call-timeout budget"
}

run_lane() {
  assert_no_field_material_markers
  run_b5_current_red
  e2e_cargo_test_filter "assert" "B6 SSL_CERT_FILE root override" 1 -- \
    cargo test -p oraclemcp-core --test oci_tcps_e2e \
      b6_ssl_cert_file_public_root_reaches_local_tcps_terminator -- --nocapture
  e2e_cargo_test_filter "assert" "B6 SSL_CERT_DIR root override" 1 -- \
    cargo test -p oraclemcp-core --test oci_tcps_e2e \
      b6_ssl_cert_dir_public_root_reaches_local_tcps_terminator -- --nocapture
  e2e_cargo_test_filter "assert" "P2-4 wallet default SNI reaches terminator" 1 -- \
    cargo test -p oraclemcp-core --test oci_tcps_e2e \
      p2_4_wallet_profile_without_explicit_sni_reaches_local_tcps_terminator -- --nocapture
  e2e_cargo_test_filter "assert" "P-U4 legacy 3DES server wallet path" 1 -- \
    cargo test -p oraclemcp-core --test doctor_wallet_posture \
      legacy_3des_p12_decrypts_through_the_server_wallet_path -- --nocapture
}

parse_args "$@"
run_lane
e2e_finish_pass
