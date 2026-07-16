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
need openssl
need python3
need terraform
need timeout
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
ssl_dn="$(python3 "$ROOT/scripts/e2e/extract_ssl_server_cert_dn.py" \
  "$wallet_dir/tnsnames.ora" "$wallet_dir/sqlnet.ora" 2>/dev/null || true)"
if [ -n "$ssl_dn" ]; then
  e2e_log_event "wallet_server_dn" "setup" "pass" 0 \
    "extracted explicit SSL_SERVER_CERT_DN from downloaded ADB wallet"
else
  # Modern ADB wallets commonly specify SSL_SERVER_DN_MATCH=YES but omit the
  # optional literal certificate subject. The concrete descriptor below still
  # gives the driver a DNS-safe HOST for strict host/SAN validation.
  e2e_log_event "wallet_server_dn" "setup" "pass" 0 \
    "wallet has no explicit SSL_SERVER_CERT_DN; strict host/SAN matching remains enabled"
fi

provider_connect_string="$(<"$run_dir/admin_connect_string")"
# OCI's all_connection_strings HIGH value is a host/port/service string. The
# downloaded wallet's HIGH entry carries the required TCPS descriptor,
# including its TLS security stanza. Resolve the entry into its concrete
# descriptor here rather than relying on a later alias lookup, so the
# pre-bootstrap probe and its SNI setting bind to the exact same endpoint.
wallet_high_target="$run_dir/wallet_high_target.json"
if python3 - "$wallet_dir/tnsnames.ora" >"$wallet_high_target" <<'PY'
import json
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
alias = re.search(r"(?mi)^\s*([A-Z0-9][A-Z0-9_.-]*_HIGH)\s*=\s*", text)
if alias is None:
    raise SystemExit("wallet has no HIGH service alias")

start = alias.end()
while start < len(text) and text[start].isspace():
    start += 1
if start == len(text) or text[start] != "(":
    raise SystemExit("wallet HIGH service does not contain a connect descriptor")

depth = 0
end = start
for end in range(start, len(text)):
    char = text[end]
    if char == "(":
        depth += 1
    elif char == ")":
        depth -= 1
        if depth == 0:
            end += 1
            break
else:
    raise SystemExit("wallet HIGH connect descriptor is unterminated")

descriptor = text[start:end]
if not re.search(r"\(PROTOCOL\s*=\s*TCPS\s*\)", descriptor, re.I):
    raise SystemExit("wallet HIGH connect descriptor is not TCPS")

def value(name: str) -> str:
    match = re.search(r"\(" + name + r"\s*=\s*([^)\s]+)\s*\)", descriptor, re.I)
    if match is None:
        raise SystemExit(f"wallet HIGH connect descriptor has no {name}")
    return match.group(1)

host = value("HOST")
port = value("PORT")
if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
    raise SystemExit("wallet HIGH host is not a DNS-safe name")
if not re.fullmatch(r"[1-9][0-9]{0,4}", port) or int(port) > 65535:
    raise SystemExit("wallet HIGH port is invalid")

json.dump({"descriptor": descriptor, "host": host, "port": int(port)}, sys.stdout)
PY
then
  admin_connect_string="$(jq -r '.descriptor' "$wallet_high_target")"
  wallet_server_host="$(jq -r '.host' "$wallet_high_target")"
  wallet_server_port="$(jq -r '.port' "$wallet_high_target")"
  [ -n "$admin_connect_string" ] && [ "$admin_connect_string" != null ] || \
    e2e_finish_fail "wallet HIGH connect descriptor was empty"
  printf '%s' "$admin_connect_string" >"$run_dir/admin_connect_string"
  chmod 600 "$run_dir/admin_connect_string"
  e2e_log_event "wallet_service_alias" "setup" "pass" 0 \
    "resolved HIGH TCPS connect descriptor from downloaded wallet"
else
  [ -n "$provider_connect_string" ] || \
    e2e_finish_fail "Terraform returned no ADB connect string and the wallet has no HIGH service alias"
  admin_connect_string="$provider_connect_string"
  wallet_server_host=""
  wallet_server_port=""
  e2e_log_event "wallet_service_alias" "setup" "pass" 0 \
    "wallet has no HIGH alias; using the Terraform connect string fallback"
fi

# `ssl_server_dn_match` remains true even when a modern wallet omits an
# explicit DN: then the driver performs the stricter host/SAN match against
# this descriptor's DNS-safe HOST. SNI must use that host, never the service
# alias (which can contain underscores).
wallet_use_sni=true

adb_id="$(<"$run_dir/adb_id")"
scope="urn:oracle:db::id::$TF_VAR_compartment_ocid::$adb_id"
if ! run_redacted "act" "mint scoped OCI database token" env OCI_CLI_CONFIG_FILE="$oci_config" oci --profile DEFAULT iam db-token get --db-token-location "$token_dir" --scope "$scope"; then
  e2e_finish_fail "OCI database-token mint failed"
fi
[ -s "$token_dir/token" ] || e2e_finish_fail "OCI CLI did not write a database token"
chmod 600 "$token_dir/token"

toml_string() {
  jq -Rn --arg value "$1" '$value'
}

bootstrap_config="$run_dir/bootstrap-admin-profile.toml"
bootstrap_state="$run_dir/bootstrap-state"
bootstrap_binary="${CARGO_TARGET_DIR:-/home/durakovic/.cache/cargo-target-server}/debug/oraclemcp"
bootstrap_connect_string="$(toml_string "$(<"$run_dir/admin_connect_string")")"
bootstrap_wallet="$(toml_string "$wallet_dir")"
bootstrap_ssl_dn="$(toml_string "$ssl_dn")"
{
  printf 'schema_version = 2\n'
  printf 'default_profile = "oci_adb_bootstrap"\n\n'
  printf '[[profiles]]\n'
  printf 'name = "oci_adb_bootstrap"\n'
  printf 'description = "runtime-only throwaway ADB IAM bootstrap; never committed"\n'
  printf 'connect_string = %s\n' "$bootstrap_connect_string"
  printf 'username = "ADMIN"\n'
  printf 'credential_ref = "env:ADB_ADMIN_PASSWORD"\n'
  printf 'max_level = "ADMIN"\n'
  printf 'default_level = "READ_ONLY"\n'
  printf 'call_timeout_seconds = 30\n\n'
  printf 'connect_timeout_seconds = 60\n\n'
  printf '[profiles.oci]\n'
  printf 'wallet_location = %s\n' "$bootstrap_wallet"
  printf 'wallet_password_ref = "env:ADB_WALLET_PASSWORD"\n'
  printf 'ssl_server_dn_match = true\n'
  if [ -n "$ssl_dn" ]; then
    printf 'ssl_server_cert_dn = %s\n' "$bootstrap_ssl_dn"
  fi
  printf 'use_sni = %s\n' "$wallet_use_sni"
} >"$bootstrap_config"
chmod 600 "$bootstrap_config"

if ! e2e_run_cargo_capped "setup" build -p oraclemcp --bin oraclemcp; then
  e2e_finish_fail "building oraclemcp for the guarded IAM bootstrap failed"
fi
[ -x "$bootstrap_binary" ] || e2e_finish_fail "guarded IAM bootstrap binary was not produced"

wait_for_adb_tcps() {
  local attempt status started ended output cert_chain server_dn
  # Terraform waits for resource creation, but the freshly-created ADB's TCPS
  # listener can lag that state briefly. Probe through the real server before
  # any ADMIN mapping; never retry the mapping itself.
  for attempt in 1 2 3 4 5 6; do
    started="$(e2e_epoch_ms)"
    output="$run_dir/adb_tcps_readiness_${attempt}.log"
    e2e_log_event "adb_tcps_readiness" "setup" "running" 0 \
      "real server doctor attempt $attempt/6 before guarded IAM bootstrap"
    # Capture the actual leaf-certificate DN from the same concrete TCPS
    # endpoint. This is evidence only; the server still performs strict
    # certificate matching itself via ssl_server_dn_match=true.
    if [ -n "$wallet_server_host" ] && [ -n "$wallet_server_port" ]; then
      cert_chain="$run_dir/adb_server_chain_${attempt}.pem"
      set +e
      timeout 30 openssl s_client \
        -connect "$wallet_server_host:$wallet_server_port" \
        -servername "$wallet_server_host" \
        -showcerts </dev/null >"$run_dir/adb_server_cert_${attempt}.log" 2>&1
      status=$?
      set -e
      if [ -s "$run_dir/adb_server_cert_${attempt}.log" ]; then
        awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/ { print; if ($0 == "-----END CERTIFICATE-----") exit }' \
          "$run_dir/adb_server_cert_${attempt}.log" >"$cert_chain"
        server_dn="$(openssl x509 -in "$cert_chain" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//')"
        if [ -n "$server_dn" ] && [ "$server_dn" != "subject=" ]; then
          printf '%s' "$server_dn" >"$run_dir/adb_server_cert_dn"
          chmod 600 "$run_dir/adb_server_cert_dn"
          e2e_log_event "adb_server_certificate" "setup" "pass" 0 \
            "captured real TCPS leaf certificate DN before guarded IAM bootstrap"
        fi
      fi
    fi
    set +e
    env -i \
      "HOME=$HOME" \
      "PATH=$PATH" \
      "XDG_STATE_HOME=$bootstrap_state" \
      "ORACLEMCP_CONFIG=$bootstrap_config" \
      "ORACLEMCP_AUDIT_KEY=$bootstrap_audit_key" \
      "ADB_ADMIN_PASSWORD=$admin_password" \
      "ADB_WALLET_PASSWORD=$wallet_password" \
      "$bootstrap_binary" --json doctor --online --profile oci_adb_bootstrap >"$output" 2>&1
    status=$?
    set -e
    ended="$(e2e_epoch_ms)"
    if [ "$status" -eq 0 ]; then
      e2e_log_event "adb_tcps_readiness" "setup" "pass" "$((ended - started))" \
        "real server doctor connected before guarded IAM bootstrap"
      return 0
    fi
    e2e_log_event "adb_tcps_readiness" "setup" "running" "$((ended - started))" \
      "TCPS listener not ready yet; no database mutation was attempted"
    if [ "$attempt" -lt 6 ]; then
      sleep 10
    fi
  done
  return 1
}

bootstrap_script="$run_dir/configure_iam_global_user.py"
bootstrap_audit_key="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
[ "${#bootstrap_audit_key}" -eq 64 ] || e2e_finish_fail "could not generate runtime-only bootstrap audit key"
cat >"$bootstrap_script" <<'PY'
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time


class BootstrapFailure(Exception):
    pass


class McpSession:
    def __init__(self, binary, config, state_dir, server_log):
        # `ORACLEMCP_*` is a configuration-override namespace. The enclosing
        # harness deliberately uses that namespace for its own values, so do
        # not leak those helpers into the child server process.
        env = {key: value for key, value in os.environ.items() if not key.startswith("ORACLEMCP_")}
        env["ORACLEMCP_CONFIG"] = config
        # ADMIN bootstrap actions must be recorded by the server's signed audit
        # chain. This key is generated for this throwaway run only.
        env["ORACLEMCP_AUDIT_KEY"] = os.environ["ORACLEMCP_AUDIT_KEY"]
        env["XDG_STATE_HOME"] = state_dir
        self.log = open(server_log, "a", encoding="utf-8")
        self.proc = subprocess.Popen(
            [binary, "serve", "--profile", "oci_adb_bootstrap", "--allow-no-auth"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.log,
            text=True,
            bufsize=1,
            env=env,
        )
        self.responses = queue.Queue()
        self.request_id = 0
        threading.Thread(target=self._read_stdout, daemon=True).start()

    def _read_stdout(self):
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            line = line.strip()
            if line:
                self.responses.put(line)

    def rpc(self, method, params=None, timeout=90):
        self.request_id += 1
        request = {"jsonrpc": "2.0", "id": self.request_id, "method": method}
        if params is not None:
            request["params"] = params
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(request) + "\n")
        self.proc.stdin.flush()
        deadline = time.monotonic() + timeout
        while True:
            if self.proc.poll() is not None:
                raise BootstrapFailure("guarded IAM bootstrap server exited before replying")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BootstrapFailure(f"timed out waiting for guarded MCP {method}")
            try:
                line = self.responses.get(timeout=min(remaining, 0.5))
            except queue.Empty:
                continue
            try:
                reply = json.loads(line)
            except json.JSONDecodeError as error:
                raise BootstrapFailure("guarded IAM bootstrap server emitted malformed JSON-RPC") from error
            if reply.get("id") == self.request_id:
                if "error" in reply:
                    raise BootstrapFailure(f"guarded MCP {method} returned a protocol error")
                return reply

    def notify(self, method):
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
        self.proc.stdin.flush()

    def call(self, tool, arguments):
        reply = self.rpc("tools/call", {"name": tool, "arguments": arguments})
        result = reply.get("result")
        if not isinstance(result, dict) or result.get("isError") is True:
            raise BootstrapFailure(f"guarded MCP {tool} refused the IAM bootstrap operation")
        content = result.get("structuredContent")
        if not isinstance(content, dict):
            raise BootstrapFailure(f"guarded MCP {tool} returned no structured result")
        return content

    def close(self):
        try:
            if self.proc.stdin is not None:
                self.proc.stdin.close()
            self.proc.wait(timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            self.proc.kill()
            self.proc.wait(timeout=15)
        finally:
            self.log.close()


def require(condition, message):
    if not condition:
        raise BootstrapFailure(message)


def elevate_to_admin(session):
    preview = session.call("oracle_set_session_level", {"level": "ADMIN", "ttl_seconds": 120})
    token = (preview.get("confirmation") or {}).get("confirm")
    require(token, "ADMIN elevation did not issue a confirmation grant")
    applied = session.call(
        "oracle_set_session_level",
        {"level": "ADMIN", "ttl_seconds": 120, "execute": True, "confirm": token},
    )
    require(
        (applied.get("session") or {}).get("current_level") == "ADMIN",
        "confirmed ADMIN elevation did not take effect",
    )


def execute_admin(session, statement):
    preview = session.call("oracle_preview_sql", {"sql": statement})
    require(preview.get("gate_decision") == "allow", "guard did not allow the approved ADMIN statement")
    token = (preview.get("execute_confirmation") or {}).get("confirm")
    require(token, "ADMIN statement preview did not issue an execution confirmation")
    outcome = session.call(
        "oracle_execute", {"sql": statement, "commit": True, "confirm": token}
    )
    require(outcome.get("executed") is True, "approved ADMIN statement was not executed")


def main():
    binary, config, state_dir, server_log = sys.argv[1:5]
    principal = os.environ["ORACLEMCP_ADB_IAM_PRINCIPAL_NAME"]
    database_user = os.environ["ORACLEMCP_ADB_IAM_DATABASE_USER"]
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,29}", database_user):
        raise BootstrapFailure("invalid generated IAM database username")
    if not re.fullmatch(r"[A-Za-z0-9._@:/=-]{1,128}", principal):
        raise BootstrapFailure("invalid IAM principal name")

    session = McpSession(binary, config, state_dir, server_log)
    try:
        initialize = session.rpc(
            "initialize",
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "oci-adb-acceptance", "version": "1"},
            },
        )
        require(
            initialize.get("result", {}).get("serverInfo", {}).get("name") == "oraclemcp",
            "guarded IAM bootstrap server did not identify as oraclemcp",
        )
        session.notify("notifications/initialized")
        elevate_to_admin(session)
        execute_admin(session, "BEGIN DBMS_CLOUD_ADMIN.ENABLE_EXTERNAL_AUTHENTICATION('OCI_IAM'); END;")
        execute_admin(
            session,
            f"CREATE USER {database_user} IDENTIFIED GLOBALLY AS 'IAM_PRINCIPAL_NAME={principal}'",
        )
        execute_admin(session, f"GRANT CREATE SESSION TO {database_user}")
    finally:
        session.close()


try:
    main()
except (BootstrapFailure, IndexError, KeyError) as error:
    raise SystemExit(f"guarded IAM bootstrap failed: {error}") from None
PY
chmod 700 "$bootstrap_script"

if ! wait_for_adb_tcps; then
  e2e_finish_fail "throwaway ADB TCPS listener did not become ready before guarded IAM bootstrap"
fi

if ! run_redacted "act" "configure OCI IAM global user mapping" env \
  ORACLEMCP_ADB_IAM_PRINCIPAL_NAME="$ORACLEMCP_ADB_IAM_PRINCIPAL_NAME" \
  ORACLEMCP_AUDIT_KEY="$bootstrap_audit_key" \
  ORACLEMCP_ADB_IAM_DATABASE_USER="$(<"$run_dir/iam_database_user")" \
  ADB_ADMIN_PASSWORD="$admin_password" \
  ADB_WALLET_PASSWORD="$wallet_password" \
  python3 "$bootstrap_script" "$bootstrap_binary" "$bootstrap_config" "$bootstrap_state" \
  "$run_dir/bootstrap-server.log"; then
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
  ORACLEMCP_REAL_ADB_USE_SNI="$wallet_use_sni" \
  ORACLEMCP_REAL_ADB_IAM_TOKEN="$(<"$token_dir/token")" \
  bash scripts/e2e/real_adb_tcps_signoff.sh --log; then
  e2e_finish_fail "real ADB TCPS signoff failed"
fi

if ! run_redacted "assert" "committed tree secret scan" bash scripts/secret_scan.sh; then
  e2e_finish_fail "committed-tree confidentiality scan failed"
fi

e2e_log_event "signoff_summary" "assert" "pass" 0 "verified password and scoped OCI-IAM token against a throwaway Always Free ADB; teardown follows"
e2e_finish_pass
