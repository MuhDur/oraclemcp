#!/usr/bin/env bash
# D3.2 local pre-tag gate: run the autonomous synthetic TCPS/OCI proof and,
# on explicit request, delegate to the real ADB/OCI-IAM signoff harness.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="local_release_gate"
E2E_LANE="release-local"
E2E_PROFILE="synthetic-oci-tcps"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

run_real_adb=false
commit_proof=false
proof_dir=""

usage() {
  cat <<'USAGE'
Run the local pre-tag release gate.

Default mode is fully autonomous and synthetic: it exercises the OCI/TCPS
wallet + IAM-token path against a loopback TCPS terminator using CN=oracle-test.invalid.

Options:
  --real-adb       also run scripts/e2e/real_adb_tcps_signoff.sh; requires real
                   operator-supplied ADB wallet and IAM-token environment
  --commit-proof   write the sanitized synthetic proof under tests/artifacts/local_gate
  --proof-dir DIR  override the synthetic proof output directory
USAGE
  e2e_usage_common
}

while [ "$#" -gt 0 ]; do
  arg="$1"
  shift
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
      case "$arg" in
        --real-adb)
          run_real_adb=true
          ;;
        --commit-proof)
          commit_proof=true
          ;;
        --proof-dir)
          [ "$#" -gt 0 ] || {
            echo "local_release_gate: --proof-dir requires a value" >&2
            exit 2
          }
          proof_dir="$1"
          shift
          ;;
        *)
          echo "local_release_gate: unknown argument: $arg" >&2
          exit 2
          ;;
      esac
      ;;
  esac
done

cd "$ROOT"

need() {
  command -v "$1" >/dev/null 2>&1 || e2e_finish_fail "missing required command: $1"
}

proof_scan() {
  local path="$1"
  if grep -nE 'ocid1\.|CN=[^[:space:]]*\.oraclecloud\.com|-----BEGIN [A-Z ]*PRIVATE KEY-----|todelete[/\\]todelete[0-9]+' "$path" >/dev/null; then
    e2e_finish_fail "synthetic proof contains a forbidden live/cloud/confidential marker: $path"
  fi
}

write_synthetic_proof() {
  local out="$1"
  local source_sha="$2"
  local created_at
  created_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  mkdir -p "$(dirname "$out")"
  jq -n \
    --arg created_at "$created_at" \
    --arg source_sha "$source_sha" \
    '{
      schema_version: 1,
      gate: "D3.2 local pre-tag release gate",
      source_sha: $source_sha,
      created_at: $created_at,
      confidentiality: {
        committed_identifiers: "synthetic-only",
        server_certificate_subject: "CN=oracle-test.invalid",
        real_adb_evidence: "out-of-band; never committed"
      },
      checks: [
        {
          name: "synthetic_oci_tcps_wallet_iam_token",
          status: "pass",
          command: "cargo test -p oraclemcp-core --test oci_tcps_e2e profile_wallet_and_iam_token_reach_local_tcps_terminator -- --nocapture",
          verifies: [
            "synthetic wallet material reaches a local TCPS terminator",
            "the server injects an IAM database token over TCPS only",
            "mTLS peer certificate and post-TLS Oracle Net bytes are observed",
            "token and wallet paths are not leaked in the asserted error text"
          ]
        }
      ]
    }' >"$out"
  proof_scan "$out"
  e2e_log_event "proof_written" "assert" "pass" 0 "$out"
  echo "local-release-gate proof: $out"
}

need git
need jq

source_sha="${ORACLEMCP_LOCAL_GATE_SHA:-$(git rev-parse --short=12 HEAD)}"
if [ -z "$proof_dir" ]; then
  if [ "$commit_proof" = true ]; then
    proof_dir="$ROOT/tests/artifacts/local_gate"
  else
    proof_dir="$ORACLEMCP_E2E_ARTIFACT_DIR/local_release_gate"
  fi
fi
proof_path="$proof_dir/results-$source_sha.json"

e2e_log_event "scenario_start" "setup" "running" 0 "D3.2 local pre-tag gate: synthetic OCI/TCPS proof"

if ! e2e_run_cargo_capped "act" test -p oraclemcp-core --test oci_tcps_e2e profile_wallet_and_iam_token_reach_local_tcps_terminator -- --nocapture; then
  e2e_finish_fail "synthetic OCI/TCPS proof failed"
fi

if [ "$E2E_DRY_RUN" = "1" ]; then
  e2e_log_event "proof_dry_run" "assert" "skipped" 0 "$proof_path"
else
  write_synthetic_proof "$proof_path" "$source_sha"
fi

if [ "$run_real_adb" = true ]; then
  real_args=()
  [ "$E2E_LOG" = "1" ] && real_args+=(--log)
  if ! e2e_run_command "act" bash scripts/e2e/real_adb_tcps_signoff.sh "${real_args[@]}"; then
    e2e_finish_fail "real ADB/OCI-IAM signoff harness failed"
  fi
else
  e2e_log_event "real_adb_deferred" "assert" "skipped" 0 "real ADB/OCI-IAM signoff requires operator-supplied runtime credentials"
fi

if [ "$commit_proof" = true ] && [ "$E2E_DRY_RUN" != "1" ]; then
  bash "$ROOT/scripts/local_release_gate_check.sh" --proof "$proof_path" --source-sha "$source_sha" --require
fi

e2e_finish_pass
