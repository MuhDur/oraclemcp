#!/usr/bin/env bash
# Operator-gated C5 lane: provision an Always Free ADB, prove password and IAM
# token TCPS paths, then destroy it. Runtime state and all credentials remain
# under ignored target/e2e/; the script never prints them.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/e2e/lib.sh"

E2E_SCENARIO="oci_adb_terraform"
E2E_LANE="oci-adb-acceptance"
E2E_PROFILE="real-adb"
E2E_LEVEL="READ_ONLY"
export E2E_SCENARIO E2E_LANE E2E_PROFILE E2E_LEVEL

mode="plan"

usage() {
  cat <<'USAGE'
Plan, or explicitly provision and destroy, the real Always Free ADB acceptance lane.

Default mode is a credential-gated Terraform plan. The destructive cloud path
requires both --apply-and-signoff and ORACLEMCP_REAL_ADB_NON_CUSTOMER_ASSERTION=1.

Required live-run env:
  TF_VAR_tenancy_ocid
  TF_VAR_user_ocid
  TF_VAR_fingerprint
  TF_VAR_private_key_path
  TF_VAR_region
  TF_VAR_compartment_ocid

Required only with --apply-and-signoff:
  ORACLEMCP_REAL_ADB_NON_CUSTOMER_ASSERTION=1
  ORACLEMCP_ADB_IAM_PRINCIPAL_NAME
USAGE
  e2e_usage_common
}

for arg in "$@"; do
  case "$arg" in
    --apply-and-signoff) mode="apply-and-signoff" ;;
    *)
      set +e
      e2e_parse_common_arg "$arg"
      parsed=$?
      set -e
      case "$parsed" in
        0) ;;
        3)
          usage
          exit 0
          ;;
        1)
          echo "oci_adb_terraform: unknown argument: $arg" >&2
          exit 2
          ;;
      esac
      ;;
  esac
done

cd "$ROOT"

# Declare the runtime-only Terraform environment here so static analysis sees
# the same contract that require_value enforces below.
TF_VAR_tenancy_ocid="${TF_VAR_tenancy_ocid:-}"
TF_VAR_user_ocid="${TF_VAR_user_ocid:-}"
TF_VAR_fingerprint="${TF_VAR_fingerprint:-}"
TF_VAR_private_key_path="${TF_VAR_private_key_path:-}"
TF_VAR_region="${TF_VAR_region:-}"
TF_VAR_compartment_ocid="${TF_VAR_compartment_ocid:-}"

need() {
  command -v "$1" >/dev/null 2>&1 || e2e_finish_fail "missing required command: $1"
}

require_value() {
  local name="$1"
  [ -n "${!name:-}" ] || e2e_finish_skip "SKIP_BLOCKED_OCI_CREDS: set $name"
}

run_dir="$ORACLEMCP_E2E_ARTIFACT_DIR/$E2E_SCENARIO/$(date -u +"%Y%m%dT%H%M%SZ")-$$"
state_dir="$run_dir/terraform"
state_file="$state_dir/terraform.tfstate"
plan_file="$state_dir/signoff.tfplan"
wallet_dir="$run_dir/wallet"
token_dir="$run_dir/oci-db-token"
oci_config="$run_dir/oci-config"
terraform_source="$ROOT/infra/oci-adb"
terraform_dir="$state_dir/module"
destroy_needed=false

assert_free_tier_module() {
  local module="$1"
  # Fail closed before init/plan/apply if the checked-in module is changed to
  # request a paid database. This is intentionally textual: it also catches a
  # provider-schema change before Terraform can evaluate a plan.
  grep -Eq '^[[:space:]]*is_free_tier[[:space:]]*=[[:space:]]*true[[:space:]]*$' "$module/main.tf" || \
    e2e_finish_fail "REFUSING: OCI harness is FREE TIER ONLY — is_free_tier=true is required"
  if grep -Eq '^[[:space:]]*is_free_tier[[:space:]]*=[[:space:]]*false[[:space:]]*$' "$module/main.tf"; then
    e2e_finish_fail "REFUSING: OCI harness is FREE TIER ONLY — paid ADB is forbidden"
  fi
}

mkdir -p "$state_dir"
chmod 700 "$run_dir" "$state_dir"
export TF_DATA_DIR="$state_dir/.terraform"

run_redacted() {
  local phase="$1"
  local label="$2"
  shift 2
  local started status ended output
  started="$(e2e_epoch_ms)"
  output="$run_dir/${label//[^A-Za-z0-9]/_}.log"
  e2e_log_event "command_start" "$phase" "running" 0 "$label"
  if [ "$E2E_DRY_RUN" = "1" ]; then
    ended="$(e2e_epoch_ms)"
    e2e_log_event "command_dry_run" "$phase" "skipped" "$((ended - started))" "$label"
    return 0
  fi
  set +e
  "$@" >"$output" 2>&1
  status=$?
  set -e
  ended="$(e2e_epoch_ms)"
  if [ "$status" -eq 0 ]; then
    e2e_log_event "command_complete" "$phase" "pass" "$((ended - started))" "$label"
    return 0
  fi
  e2e_log_event "command_complete" "$phase" "fail" "$((ended - started))" "$label"
  echo "OCI ADB acceptance stage failed: $label (raw runtime output is retained only under target/e2e/)" >&2
  return "$status"
}

cleanup() {
  local prior_status=$?
  local destroy_status=0
  trap - EXIT
  if [ "$destroy_needed" = true ] && [ "$E2E_DRY_RUN" != "1" ]; then
    e2e_log_event "terraform_destroy" "teardown" "running" 0 "destroying throwaway Always Free ADB"
    set +e
    terraform -chdir="$terraform_dir" destroy -input=false -auto-approve -no-color \
      -state="$state_file" >"$run_dir/terraform_destroy.log" 2>&1
    destroy_status=$?
    set -e
    if [ "$destroy_status" -eq 0 ]; then
      e2e_log_event "terraform_destroy" "teardown" "pass" 0 "throwaway Always Free ADB destroyed"
    else
      e2e_log_event "terraform_destroy" "teardown" "fail" 0 "terraform destroy failed; trying OCI CLI fallback"
      adb_id=""
      if [ -f "$oci_config" ] && command -v oci >/dev/null 2>&1; then
        adb_id="$(terraform -chdir="$terraform_dir" output -state="$state_file" -raw adb_id 2>/dev/null || true)"
        if [ -n "$adb_id" ] && OCI_CLI_CONFIG_FILE="$oci_config" oci db autonomous-database delete \
          --autonomous-database-id "$adb_id" --force >"$run_dir/oci_cli_destroy.log" 2>&1; then
          e2e_log_event "terraform_destroy" "teardown" "pass" 0 "OCI CLI deleted throwaway Always Free ADB after Terraform destroy failure"
          destroy_status=0
        else
          e2e_log_event "terraform_destroy" "teardown" "fail" 0 "OCI CLI fallback could not delete throwaway ADB; inspect runtime-only artifact"
        fi
      else
        e2e_log_event "terraform_destroy" "teardown" "fail" 0 "OCI CLI fallback unavailable; inspect runtime-only artifact"
      fi
      if [ "$destroy_status" -ne 0 ]; then
        echo "OCI ADB acceptance teardown failed; the operator must destroy the throwaway resource using its runtime state." >&2
      fi
    fi
  fi
  if [ "$prior_status" -eq 0 ] && [ "$destroy_status" -ne 0 ]; then
    exit "$destroy_status"
  fi
  exit "$prior_status"
}
trap cleanup EXIT

e2e_log_event "scenario_start" "setup" "running" 0 "OCI Always Free ADB Terraform acceptance mode=$mode"
e2e_log_event "env_contract" "setup" "running" 0 "OCI values, Terraform state, wallet, token, and raw logs remain runtime-only under target/e2e"

if [ "$E2E_DRY_RUN" = "1" ]; then
  run_redacted "setup" "terraform init (offline wiring)" terraform -chdir="$terraform_dir" init -backend=false -input=false -no-color
  run_redacted "act" "terraform plan (no cloud mutation)" terraform -chdir="$terraform_dir" plan -input=false -no-color -state="$state_file" -out="$plan_file"
  if [ "$mode" = "apply-and-signoff" ]; then
    run_redacted "act" "terraform apply throwaway Always Free ADB" terraform -chdir="$terraform_dir" apply -input=false -auto-approve -no-color -state="$state_file" "$plan_file"
    run_redacted "act" "configure OCI IAM global user mapping" true
    run_redacted "act" "mint scoped OCI database token" true
    run_redacted "act" "real ADB TCPS password and IAM signoff" bash scripts/e2e/real_adb_tcps_signoff.sh --log --dry-run
    e2e_log_event "terraform_destroy" "teardown" "skipped" 0 "dry-run never provisions a cloud database"
  fi
  e2e_log_event "dry_run_summary" "assert" "pass" 0 "wiring only; no OCI API call, ADB, wallet, token, or Terraform state was created"
  e2e_finish_pass
  exit 0
fi

for name in \
  TF_VAR_tenancy_ocid \
  TF_VAR_user_ocid \
  TF_VAR_fingerprint \
  TF_VAR_private_key_path \
  TF_VAR_region \
  TF_VAR_compartment_ocid
do
  require_value "$name"
done
[ -f "$TF_VAR_private_key_path" ] || e2e_finish_skip "SKIP_BLOCKED_OCI_CREDS: TF_VAR_private_key_path does not name a file"

need base64
need jq
need oci
need python3
need terraform
need unzip

if [ "$mode" = "apply-and-signoff" ]; then
  [ "${ORACLEMCP_REAL_ADB_NON_CUSTOMER_ASSERTION:-}" = "1" ] || \
    e2e_finish_fail "set ORACLEMCP_REAL_ADB_NON_CUSTOMER_ASSERTION=1 after confirming the lane is throwaway"
  require_value ORACLEMCP_ADB_IAM_PRINCIPAL_NAME
  if ! [[ "$ORACLEMCP_ADB_IAM_PRINCIPAL_NAME" =~ ^[A-Za-z0-9._@:/=-]{1,128}$ ]]; then
    e2e_finish_fail "ORACLEMCP_ADB_IAM_PRINCIPAL_NAME has unsupported characters"
  fi
fi

umask 077
mkdir -p "$terraform_dir"
cp -R "$terraform_source/." "$terraform_dir/"
assert_free_tier_module "$terraform_dir"
cat >"$oci_config" <<EOF
[DEFAULT]
user=$TF_VAR_user_ocid
fingerprint=$TF_VAR_fingerprint
tenancy=$TF_VAR_tenancy_ocid
region=$TF_VAR_region
key_file=$TF_VAR_private_key_path
EOF
chmod 600 "$oci_config"

if ! run_redacted "setup" "terraform init (OCI provider lock)" terraform -chdir="$terraform_dir" init -backend=false -input=false -no-color; then
  e2e_finish_fail "Terraform initialization failed"
fi
if ! run_redacted "act" "terraform plan (no cloud mutation)" terraform -chdir="$terraform_dir" plan -input=false -no-color -state="$state_file" -out="$plan_file"; then
  e2e_finish_fail "Terraform plan failed"
fi

if [ "$mode" = "plan" ]; then
  e2e_log_event "plan_summary" "assert" "pass" 0 "OCI credentials produced a no-mutation Terraform plan; apply requires explicit operator confirmation"
  e2e_finish_pass
  exit 0
fi

destroy_needed=true
if ! run_redacted "act" "terraform apply throwaway Always Free ADB" terraform -chdir="$terraform_dir" apply -input=false -auto-approve -no-color -state="$state_file" "$plan_file"; then
  e2e_finish_fail "Terraform apply failed"
fi

terraform_output() {
  local name="$1"
  local destination="$2"
  if ! terraform -chdir="$terraform_dir" output -state="$state_file" -raw "$name" >"$destination" 2>"$run_dir/terraform_output_${name}.log"; then
    e2e_finish_fail "Terraform output '$name' could not be captured"
  fi
  chmod 600 "$destination"
  e2e_log_event "terraform_output" "setup" "pass" 0 "captured redacted Terraform output $name"
}

terraform_output adb_id "$run_dir/adb_id"
terraform_output admin_connect_string "$run_dir/admin_connect_string"
terraform_output admin_password "$run_dir/admin_password"
terraform_output wallet_base64 "$run_dir/wallet_base64"
terraform_output wallet_password "$run_dir/wallet_password"
terraform_output iam_database_user "$run_dir/iam_database_user"

admin_password="$(<"$run_dir/admin_password")"
wallet_password="$(<"$run_dir/wallet_password")"
if [[ "${admin_password,,}" == *admin* || "$admin_password" == *'"'* ]] ||
  ! [[ "$admin_password" =~ [[:upper:]] && "$admin_password" =~ [[:lower:]] && "$admin_password" =~ [[:digit:]] ]]; then
  e2e_finish_fail "Terraform generated an Autonomous Database admin password that violates its documented policy"
fi

mkdir -p "$wallet_dir" "$token_dir"
base64 --decode "$run_dir/wallet_base64" >"$run_dir/wallet.zip"
unzip -qq "$run_dir/wallet.zip" -d "$wallet_dir"
chmod -R u=rwX,go= "$wallet_dir"
[ -s "$wallet_dir/tnsnames.ora" ] || e2e_finish_fail "downloaded ADB wallet has no tnsnames.ora"
ssl_dn="$(sed -n 's/.*SSL_SERVER_CERT_DN=\([^)]*\).*/\1/p' "$wallet_dir/tnsnames.ora" | head -n 1)"
[ -n "$ssl_dn" ] || e2e_finish_fail "downloaded ADB wallet has no SSL_SERVER_CERT_DN"

adb_id="$(<"$run_dir/adb_id")"
scope="urn:oracle:db::id::$TF_VAR_compartment_ocid::$adb_id"
if ! run_redacted "act" "mint scoped OCI database token" env OCI_CLI_CONFIG_FILE="$oci_config" oci --profile DEFAULT iam db-token get --db-token-location "$token_dir" --scope "$scope"; then
  e2e_finish_fail "OCI database-token mint failed"
fi
[ -s "$token_dir/token" ] || e2e_finish_fail "OCI CLI did not write a database token"
chmod 600 "$token_dir/token"

bootstrap_script="$run_dir/configure_iam_global_user.py"
cat >"$bootstrap_script" <<'PY'
import os
import re

import oracledb

principal = os.environ["ORACLEMCP_ADB_IAM_PRINCIPAL_NAME"]
database_user = os.environ["ORACLEMCP_ADB_IAM_DATABASE_USER"]
if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,29}", database_user):
    raise SystemExit("invalid generated IAM database username")
if not re.fullmatch(r"[A-Za-z0-9._@:/=-]{1,128}", principal):
    raise SystemExit("invalid IAM principal name")

connection = oracledb.connect(
    user="ADMIN",
    password=os.environ["ORACLEMCP_ADB_ADMIN_PASSWORD"],
    dsn=os.environ["ORACLEMCP_ADB_CONNECT_STRING"],
    config_dir=os.environ["ORACLEMCP_ADB_WALLET_LOCATION"],
    wallet_location=os.environ["ORACLEMCP_ADB_WALLET_LOCATION"],
    wallet_password=os.environ["ORACLEMCP_ADB_WALLET_PASSWORD"],
)
try:
    with connection.cursor() as cursor:
        cursor.execute("BEGIN DBMS_CLOUD_ADMIN.ENABLE_EXTERNAL_AUTHENTICATION('OCI_IAM'); END;")
        cursor.execute(
            f"CREATE USER {database_user} IDENTIFIED GLOBALLY AS "
            f"'IAM_PRINCIPAL_NAME={principal}'"
        )
        cursor.execute(f"GRANT CREATE SESSION TO {database_user}")
    connection.commit()
finally:
    connection.close()
PY
chmod 700 "$bootstrap_script"

if ! run_redacted "act" "configure OCI IAM global user mapping" env \
  ORACLEMCP_ADB_IAM_PRINCIPAL_NAME="$ORACLEMCP_ADB_IAM_PRINCIPAL_NAME" \
  ORACLEMCP_ADB_IAM_DATABASE_USER="$(<"$run_dir/iam_database_user")" \
  ORACLEMCP_ADB_ADMIN_PASSWORD="$admin_password" \
  ORACLEMCP_ADB_CONNECT_STRING="$(<"$run_dir/admin_connect_string")" \
  ORACLEMCP_ADB_WALLET_LOCATION="$wallet_dir" \
  ORACLEMCP_ADB_WALLET_PASSWORD="$wallet_password" \
  python3 "$bootstrap_script"; then
  e2e_finish_fail "creating OCI IAM global-user mapping failed"
fi

if ! run_redacted "act" "real ADB TCPS password and IAM signoff" env \
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$run_dir/cargo-target}" \
  ORACLEMCP_REAL_ADB_SIGNOFF=1 \
  ORACLEMCP_REAL_ADB_NON_CUSTOMER_ASSERTION=1 \
  ORACLEMCP_REAL_ADB_CONNECT_STRING="$(<"$run_dir/admin_connect_string")" \
  ORACLEMCP_REAL_ADB_PASSWORD_USER=ADMIN \
  ORACLEMCP_REAL_ADB_IAM_USER="$(<"$run_dir/iam_database_user")" \
  ORACLEMCP_REAL_ADB_PASSWORD="$admin_password" \
  ORACLEMCP_REAL_ADB_WALLET_LOCATION="$wallet_dir" \
  ORACLEMCP_REAL_ADB_WALLET_PASSWORD="$wallet_password" \
  ORACLEMCP_REAL_ADB_SSL_SERVER_CERT_DN="$ssl_dn" \
  ORACLEMCP_REAL_ADB_IAM_TOKEN="$(<"$token_dir/token")" \
  bash scripts/e2e/real_adb_tcps_signoff.sh --log; then
  e2e_finish_fail "real ADB TCPS signoff failed"
fi

if ! run_redacted "assert" "committed tree secret scan" bash scripts/secret_scan.sh; then
  e2e_finish_fail "committed-tree confidentiality scan failed"
fi

e2e_log_event "signoff_summary" "assert" "pass" 0 "verified password and scoped OCI-IAM token against a throwaway Always Free ADB; teardown follows"
e2e_finish_pass
