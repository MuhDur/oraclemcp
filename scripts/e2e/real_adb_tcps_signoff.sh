#!/usr/bin/env bash
# C5 operator-run smoke: real Autonomous Database TCPS wallet + OCI IAM token.
# All live identifiers stay in runtime env/config under target/e2e and are never
# written to committed artifacts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="real_adb_tcps_signoff"
E2E_LANE="real-adb-tcps"
E2E_PROFILE="real-adb"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

usage() {
  cat <<'USAGE'
Run the real ADB TCPS + OCI-IAM signoff harness.

Required live-run env:
  ORACLEMCP_REAL_ADB_SIGNOFF=1
  ORACLEMCP_REAL_ADB_NON_CUSTOMER_ASSERTION=1
  ORACLEMCP_REAL_ADB_CONNECT_STRING
  ORACLEMCP_REAL_ADB_PASSWORD_USER
  ORACLEMCP_REAL_ADB_IAM_DATABASE_USER
  ORACLEMCP_REAL_ADB_IAM_USER
  ORACLEMCP_REAL_ADB_PASSWORD
  ORACLEMCP_REAL_ADB_WALLET_LOCATION
  ORACLEMCP_REAL_ADB_IAM_TOKEN

Optional env:
  ORACLEMCP_REAL_ADB_WALLET_PASSWORD
  ORACLEMCP_REAL_ADB_SSL_SERVER_CERT_DN
  ORACLEMCP_REAL_ADB_USE_SNI=true|false
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
      echo "real_adb_tcps_signoff: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT"

need() {
  command -v "$1" >/dev/null 2>&1 || e2e_finish_fail "missing required command: $1"
}

toml_string() {
  jq -Rn --arg value "$1" '$value'
}

require_live_env() {
  if [ "${ORACLEMCP_REAL_ADB_SIGNOFF:-}" != "1" ]; then
    e2e_finish_skip "set ORACLEMCP_REAL_ADB_SIGNOFF=1 to run the real ADB signoff"
  fi
  if [ "${ORACLEMCP_REAL_ADB_NON_CUSTOMER_ASSERTION:-}" != "1" ]; then
    e2e_finish_fail "set ORACLEMCP_REAL_ADB_NON_CUSTOMER_ASSERTION=1 after confirming the lane is non-customer/throwaway"
  fi
  for name in \
    ORACLEMCP_REAL_ADB_CONNECT_STRING \
    ORACLEMCP_REAL_ADB_PASSWORD_USER \
    ORACLEMCP_REAL_ADB_IAM_DATABASE_USER \
    ORACLEMCP_REAL_ADB_IAM_USER \
    ORACLEMCP_REAL_ADB_PASSWORD \
    ORACLEMCP_REAL_ADB_WALLET_LOCATION \
    ORACLEMCP_REAL_ADB_IAM_TOKEN \
    ORACLEMCP_REAL_ADB_IAM_TOKEN_KEY_FILE
  do
    if [ -z "${!name:-}" ]; then
      e2e_finish_fail "set $name for real ADB signoff"
    fi
  done
  if [ ! -d "$ORACLEMCP_REAL_ADB_WALLET_LOCATION" ]; then
    e2e_finish_fail "ORACLEMCP_REAL_ADB_WALLET_LOCATION must be a directory"
  fi
  # OCI IAM database tokens are proof-of-possession: the bound private key
  # (oci_db_key.pem) must be present so the driver can sign the auth header.
  if [ ! -f "$ORACLEMCP_REAL_ADB_IAM_TOKEN_KEY_FILE" ]; then
    e2e_finish_fail "ORACLEMCP_REAL_ADB_IAM_TOKEN_KEY_FILE must be the OCI db-token private key file (oci_db_key.pem)"
  fi
  if [ ! -f "$ORACLEMCP_REAL_ADB_WALLET_LOCATION/tnsnames.ora" ]; then
    e2e_finish_fail "wallet directory must contain tnsnames.ora"
  fi
}

write_profile() {
  local path="$1"
  local profile="$2"
  local profile_user="$3"
  local use_iam="$4"
  local connect_string user wallet ssl_dn use_sni
  connect_string="$(toml_string "$ORACLEMCP_REAL_ADB_CONNECT_STRING")"
  user="$(toml_string "$profile_user")"
  wallet="$(toml_string "$ORACLEMCP_REAL_ADB_WALLET_LOCATION")"
  ssl_dn="$(toml_string "${ORACLEMCP_REAL_ADB_SSL_SERVER_CERT_DN:-}")"
  # OCI ADB can require the service-form SNI.  The Terraform acceptance
  # harness passes its known-good value explicitly; keep direct live signoff
  # aligned with that strict default.
  use_sni="${ORACLEMCP_REAL_ADB_USE_SNI:-true}"
  case "$use_sni" in
    true|false) ;;
    *) e2e_finish_fail "ORACLEMCP_REAL_ADB_USE_SNI must be true or false" ;;
  esac

  {
    printf 'schema_version = 2\n'
    printf 'default_profile = "%s"\n\n' "$profile"
    printf '[[profiles]]\n'
    printf 'name = "%s"\n' "$profile"
    printf 'description = "operator-run real ADB TCPS signoff profile; runtime-only config under target/e2e"\n'
    printf 'connect_string = %s\n' "$connect_string"
    printf 'username = %s\n' "$user"
    if [ "$use_iam" = "false" ]; then
      printf 'credential_ref = "env:ADB_PASSWORD"\n'
    fi
    printf 'max_level = "READ_ONLY"\n'
    printf 'default_level = "READ_ONLY"\n'
    printf 'connect_timeout_seconds = 60\n'
    printf 'call_timeout_seconds = 30\n'
    printf '\n'
    printf '[profiles.oci]\n'
    printf 'wallet_location = %s\n' "$wallet"
    if [ -n "${ORACLEMCP_REAL_ADB_WALLET_PASSWORD:-}" ]; then
      printf 'wallet_password_ref = "env:ADB_WALLET_PASSWORD"\n'
    fi
    printf 'ssl_server_dn_match = true\n'
    if [ -n "${ORACLEMCP_REAL_ADB_SSL_SERVER_CERT_DN:-}" ]; then
      printf 'ssl_server_cert_dn = %s\n' "$ssl_dn"
    fi
    printf 'use_sni = %s\n' "$use_sni"
    if [ "$use_iam" = "true" ]; then
      printf 'use_iam_token = true\n'
      printf 'token_env = "ADB_IAM_TOKEN"\n'
      # The OCI IAM database token is proof-of-possession: point the profile at
      # the bound private key so the driver signs AUTH_HEADER/AUTH_SIGNATURE.
      printf 'token_key_file = %s\n' "$(toml_string "$ORACLEMCP_REAL_ADB_IAM_TOKEN_KEY_FILE")"
    fi
  } >"$path"
  chmod 600 "$path"
}

need jq

artifact_root="$(realpath -m "$ORACLEMCP_E2E_ARTIFACT_DIR")"
target_root="$(realpath -m "$ROOT/target")"
case "$artifact_root/" in
  "$target_root"/*) ;;
  *) e2e_finish_fail "real signoff artifacts must stay under ignored target/: $artifact_root" ;;
esac

e2e_log_event "scenario_start" "setup" "running" 0 "real ADB TCPS + OCI-IAM signoff harness"
e2e_log_event "env_contract" "setup" "running" 0 "requires ORACLEMCP_REAL_ADB_* env at runtime; values are never logged or committed"

run_stamp="$(date -u +"%Y%m%dT%H%M%SZ")-$$"
run_dir="$ORACLEMCP_E2E_ARTIFACT_DIR/$E2E_SCENARIO/$run_stamp"
mkdir -p "$run_dir"

wallet_profile="real_adb_wallet_smoke"
iam_profile="real_adb_iam_smoke"
wallet_config="$run_dir/wallet-profile.toml"
iam_config="$run_dir/iam-profile.toml"
state_dir="$run_dir/state"
mkdir -p "$state_dir"

cargo_target_dir="${CARGO_TARGET_DIR:-/home/durakovic/.cache/cargo-target-server}"
binary="$cargo_target_dir/debug/oraclemcp"

if [ "$E2E_DRY_RUN" != "1" ]; then
  require_live_env
  write_profile "$wallet_config" "$wallet_profile" "$ORACLEMCP_REAL_ADB_PASSWORD_USER" false
  # OCI IAM resolves the token against its global-user mapping. The profile
  # username must be that mapped database schema, which the guarded query also
  # proves with SELECT USER FROM DUAL.
  write_profile "$iam_config" "$iam_profile" "$ORACLEMCP_REAL_ADB_IAM_DATABASE_USER" true
else
  e2e_log_event "dry_run_env" "setup" "skipped" 0 "live env validation skipped in --dry-run"
fi

if ! e2e_run_cargo_capped "setup" build -p oraclemcp --bin oraclemcp; then
  e2e_finish_fail "building oraclemcp binary failed"
fi

run_real_adb_doctor() {
  local config="$1"
  local state_home="$2"
  local profile="$3"
  # The public harness inputs use ORACLEMCP_REAL_ADB_* names, but that prefix
  # is the server's config-override namespace. Give the child only the exact
  # neutral secret references its generated profile resolves.
  env -i \
    "HOME=$HOME" \
    "PATH=$PATH" \
    "ORACLEMCP_CONFIG=$config" \
    "XDG_STATE_HOME=$state_home" \
    "ADB_PASSWORD=$ORACLEMCP_REAL_ADB_PASSWORD" \
    "ADB_WALLET_PASSWORD=${ORACLEMCP_REAL_ADB_WALLET_PASSWORD:-}" \
    "ADB_IAM_TOKEN=$ORACLEMCP_REAL_ADB_IAM_TOKEN" \
    "$binary" --json doctor --online --profile "$profile"
}

# Retry the IAM-token doctor to tolerate OCI IAM propagation lag. On a freshly
# provisioned ADB the sequence DBMS_CLOUD_ADMIN.ENABLE_EXTERNAL_AUTHENTICATION
# + CREATE USER ... IDENTIFIED GLOBALLY AS 'IAM_PRINCIPAL_NAME=<default-domain
# user>' does not take effect instantly: the database must pick up the new IAM
# external-authentication configuration and global-user mapping before a scoped
# token resolves, and until it does the token login fails closed with ORA-01017.
# This mirrors the pre-bootstrap wait_for_adb_tcps readiness loop; it never
# weakens the guard (each attempt is a full fail-closed doctor at READ_ONLY) and
# it only ever waits for a *correct* mapping to become live. The wallet/password
# path needs no such wait, so only the IAM path is wrapped.
run_real_adb_iam_doctor() {
  local config="$1"
  local state_home="$2"
  local profile="$3"
  local attempt max status
  max="${ORACLEMCP_REAL_ADB_IAM_MAX_ATTEMPTS:-15}"
  status=1
  for ((attempt = 1; attempt <= max; attempt++)); do
    if run_real_adb_doctor "$config" "$state_home/attempt-$attempt" "$profile"; then
      if [ "$attempt" -gt 1 ]; then
        printf 'OCI IAM token doctor authenticated on attempt %d/%d after mapping propagation\n' \
          "$attempt" "$max"
      fi
      return 0
    fi
    status=$?
    if [ "$attempt" -lt "$max" ]; then
      printf 'OCI IAM token doctor attempt %d/%d not yet authenticated (IAM mapping/enablement propagation lag); waiting 20s\n' \
        "$attempt" "$max"
      sleep 20
    fi
  done
  return "$status"
}

# Prove the MCP surface itself can use each authenticated session.  `doctor`
# opens a connection and runs its own health checks, but this explicit stdio
# exchange additionally proves the fail-closed READ_ONLY classifier admits a
# real query after authentication.  The IAM profile must return the mapped
# global database user, not merely reach token minting.
run_guarded_readonly_query() {
  local config="$1"
  local state_home="$2"
  local profile="$3"
  local expected_user="$4"
  local transcript reply actual_user

  transcript="$({
    jq -cn '{jsonrpc:"2.0", id:1, method:"initialize", params:{protocolVersion:"2025-03-26", capabilities:{}, clientInfo:{name:"oraclemcp-real-adb-signoff", version:"1"}}}'
    jq -cn '{jsonrpc:"2.0", method:"notifications/initialized"}'
    jq -cn '{jsonrpc:"2.0", id:2, method:"tools/call", params:{name:"oracle_query", arguments:{sql:"SELECT USER FROM DUAL", max_rows:1}}}'
  } | env -i \
    "HOME=$HOME" \
    "PATH=$PATH" \
    "ORACLEMCP_CONFIG=$config" \
    "XDG_STATE_HOME=$state_home" \
    "ADB_PASSWORD=$ORACLEMCP_REAL_ADB_PASSWORD" \
    "ADB_WALLET_PASSWORD=${ORACLEMCP_REAL_ADB_WALLET_PASSWORD:-}" \
    "ADB_IAM_TOKEN=$ORACLEMCP_REAL_ADB_IAM_TOKEN" \
    "$binary" --json serve --profile "$profile" --allow-no-auth
  )" || {
    printf '%s\n' "$transcript"
    return 1
  }

  reply="$(printf '%s\n' "$transcript" | jq -ce 'select(.id == 2)')" || {
    printf 'guarded READ_ONLY query returned no tool reply\n' >&2
    return 1
  }
  if [ "$(jq -r 'if .result.isError == false then "false" else "true" end' <<<"$reply")" != "false" ]; then
    printf 'guarded READ_ONLY query was refused: %s\n' "$reply" >&2
    return 1
  fi
  actual_user="$(jq -r '.result.structuredContent.rows[0].USER // empty' <<<"$reply")"
  if [ "$actual_user" != "$expected_user" ]; then
    printf 'guarded READ_ONLY query returned unexpected database user: %s\n' "$reply" >&2
    return 1
  fi
}

wallet_expected_user="${ORACLEMCP_REAL_ADB_PASSWORD_USER:-ADMIN}"
iam_expected_user="${ORACLEMCP_REAL_ADB_IAM_USER:-OMCP_IAM_ACCEPT}"

if ! e2e_run_command "act" run_real_adb_doctor "$wallet_config" "$state_dir/wallet" "$wallet_profile"; then
  e2e_finish_fail "real ADB wallet/password doctor signoff failed"
fi
if ! e2e_run_command "act" run_guarded_readonly_query \
  "$wallet_config" "$state_dir/wallet-query" "$wallet_profile" "$wallet_expected_user"; then
  e2e_finish_fail "real ADB wallet/password guarded READ_ONLY query failed"
fi

if ! e2e_run_command "act" run_real_adb_iam_doctor "$iam_config" "$state_dir/iam" "$iam_profile"; then
  e2e_finish_fail "real ADB OCI-IAM token doctor signoff failed"
fi
if ! e2e_run_command "act" run_guarded_readonly_query \
  "$iam_config" "$state_dir/iam-query" "$iam_profile" "$iam_expected_user"; then
  e2e_finish_fail "real ADB OCI-IAM token guarded READ_ONLY query failed"
fi

summary="$run_dir/summary.json"
if [ "$E2E_DRY_RUN" != "1" ]; then
  jq -n \
    --arg created_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
    --arg summary_path "$summary" \
    '{
      schema_version: 1,
      scenario: "real_adb_tcps_signoff",
      created_at: $created_at,
      artifact_path: $summary_path,
      committed_evidence: "none",
      confidentiality: "runtime-only target/e2e artifacts; no live identifiers committed",
      checks: [
        "oraclemcp binary built under capped cargo",
        "doctor --online passed for TCPS wallet username/password",
        "oracle_query SELECT USER FROM DUAL passed for TCPS wallet username/password",
        "doctor --online passed for TCPS OCI IAM database token",
        "oracle_query SELECT USER FROM DUAL passed for TCPS OCI IAM database token"
      ]
    }' >"$summary"
fi

if ! e2e_run_command "assert" bash scripts/secret_scan.sh; then
  e2e_finish_fail "committed-tree confidentiality scan failed"
fi

e2e_log_event "signoff_summary" "assert" "pass" 0 "auto-verified wallet/password + OCI-IAM doctor and guarded READ_ONLY query paths; evidence remains under target/e2e"
e2e_finish_pass
