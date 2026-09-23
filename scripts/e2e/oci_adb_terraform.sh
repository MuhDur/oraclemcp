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

Modes:
  (default)            credential-gated Terraform plan, no cloud mutation
  --apply-and-signoff  provision one ADB, run the password + IAM signoff, destroy
  --tier-c             tier-C lane: zero-cost check, discover every free-tier
                       enabled ADB version, then per version (one at a time)
                       provision -> python-oracledb control connect -> oraclemcp
                       doctor attempt -> run schema open -> --run hook -> close
                       -> destroy; zero-cost check again; write the scanned
                       results JSON. Requires ORACLEMCP_REAL_ADB_NON_CUSTOMER_ASSERTION=1.
  --selftest           offline checks of version filter, ownership and
                       zero-cost decisions against synthetic fixtures

Options:
  --db-version V       exact ADB version (default: discovered; plan and
                       apply-and-signoff use the highest free-enabled version)
  --run CMD            tier-C hook, run per version with ORACLEMCP_OCI_TARGET_ENV
                       naming a runner-private env file (connect string file,
                       wallet dir, credentials files, version, run id, schema)
  --fail-after-apply   test switch: fail right after provisioning; teardown
                       must still destroy the ADB and the run must be red
  --results-out FILE   tier-C: copy the confidentiality-scanned results JSON here

Optional env:
  ORACLEMCP_OCI_PYTHON  Python with python-oracledb for the control connect
                        (default python3)
USAGE
  e2e_usage_common
}

db_version=""
run_id=""
run_cmd=""
fail_after_apply=false
results_file=""
results_out=""
deny_file="${ORACLEMCP_OCI_DENY_FILE:-}"

while [ "$#" -gt 0 ]; do
  arg="$1"
  shift
  case "$arg" in
    --apply-and-signoff) mode="apply-and-signoff" ;;
    --tier-c) mode="tier-c" ;;
    --provision-only) mode="provision-only" ;;
    --selftest) mode="selftest" ;;
    --fail-after-apply) fail_after_apply=true ;;
    --db-version|--run-id|--run|--results-file|--results-out)
      [ "$#" -gt 0 ] || {
        echo "oci_adb_terraform: $arg requires a value" >&2
        exit 2
      }
      case "$arg" in
        --db-version) db_version="$1" ;;
        --run-id) run_id="$1" ;;
        --run) run_cmd="$1" ;;
        --results-file) results_file="$1" ;;
        --results-out) results_out="$1" ;;
      esac
      shift
      ;;
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

# ---------------------------------------------------------------------------
# Pure decisions over OCI CLI JSON. No network; output carries no identifier
# except ids the caller passed in. Exercised offline by --selftest against the
# synthetic fixtures under scripts/e2e/fixtures/oci/.
# ---------------------------------------------------------------------------

# $1: file holding `oci db autonomous-db-version list` output. The CLI prints
# nothing at all for an empty list, so an empty file means "no versions".
# Stdout: exact free-tier-enabled, non-dedicated version strings, sorted.
# Exit 3 = SKIP_NO_FREE_VERSION (never a silent pass); exit 4 = malformed.
oci_free_versions() {
  local versions
  if ! versions="$(jq -r '
      (.data // [])[]
      | select(."is-free-tier-enabled" == true)
      | select((."is-dedicated" // false) == false)
      | .version' "$1")"; then
    return 4
  fi
  versions="$(printf '%s\n' "$versions" | grep -E '^[0-9A-Za-z][0-9A-Za-z._-]{0,31}$' | sort -uV || true)"
  [ -n "$versions" ] || return 3
  printf '%s\n' "$versions"
}

# $1: ADB list captured before apply; $2: ADB list after apply; $3: run id.
# Stdout: the ADBs this run owns: new since $1, tagged with this run id, and
# not terminated. Anything that existed before the run is never selected, even
# when it carries the same tag.
oci_owned_adbs() {
  jq -r --arg run "$3" --slurpfile pre "$1" '
    ([($pre[0] // {}) | (.data // [])[] | .id]) as $preids
    | (.data // [])[]
    | select(.id as $id | ($preids | index($id)) | not)
    | select((."freeform-tags" // {})["oraclemcp-run-id"] == $run)
    | select(."lifecycle-state" != "TERMINATED" and ."lifecycle-state" != "TERMINATING")
    | .id' "$2"
}

# $1 pre list, $2 post list, $3 run id, $4 the id Terraform reports.
# Exit 0 only if the run owns exactly one ADB, it is Terraform's, and it is
# Always Free. On failure prints a typed reason.
oci_assert_single_owned() {
  local owned count free
  owned="$(oci_owned_adbs "$1" "$2" "$3")" || {
    echo OWNERSHIP_UNREADABLE
    return 1
  }
  count="$(printf '%s' "$owned" | grep -c . || true)"
  if [ "$count" -ne 1 ]; then
    echo "OWNERSHIP_COUNT_$count"
    return 1
  fi
  if [ "$owned" != "$4" ]; then
    echo OWNERSHIP_TERRAFORM_MISMATCH
    return 1
  fi
  free="$(jq -r --arg id "$owned" '(.data // [])[] | select(.id == $id) | ."is-free-tier"' "$2")"
  if [ "$free" != true ]; then
    echo OWNERSHIP_NOT_FREE_TIER
    return 1
  fi
}

# $1 control output (`oci iam compartment list` under the tenancy, a
# known-non-empty query that must contain $3 as ACTIVE), $2 the ADB list for
# $3 (empty when the CLI omitted it), $3 compartment id, $4 the run's own ADB
# id or empty. Passes only when the control proves the principal can see $3
# and no ADB other than the run's own Always Free one is in a non-terminated
# state. Without the control, "empty" is indistinguishable from
# "unauthorized", so a missing or non-matching control fails closed.
oci_zero_cost_verdict() {
  local control_hits foreign owned_free
  control_hits="$(jq -r --arg c "$3" '
    [(.data // [])[] | select(.id == $c and ."lifecycle-state" == "ACTIVE")] | length' "$1" 2>/dev/null || true)"
  if [ "$control_hits" != 1 ]; then
    echo ZERO_COST_CONTROL_MISSING
    return 1
  fi
  if [ -s "$2" ]; then
    if ! foreign="$(jq -r --arg own "$4" '
        [(.data // [])[]
          | select(."lifecycle-state" != "TERMINATED")
          | select(.id != $own)] | length' "$2" 2>/dev/null)"; then
      echo ZERO_COST_LIST_MALFORMED
      return 1
    fi
    if [ "$foreign" != 0 ]; then
      echo "ZERO_COST_FOREIGN_ADB_$foreign"
      return 1
    fi
    if [ -n "$4" ]; then
      owned_free="$(jq -r --arg own "$4" '(.data // [])[] | select(.id == $own) | ."is-free-tier"' "$2")"
      if [ -n "$owned_free" ] && [ "$owned_free" != true ]; then
        echo ZERO_COST_OWNED_NOT_FREE
        return 1
      fi
    fi
  fi
  echo ZERO_COST_PASS
}

oci_selftest() {
  local fx="$ROOT/scripts/e2e/fixtures/oci"
  local scratch out status r
  local failures=0
  scratch="$(mktemp -d)"
  : >"$scratch/empty.json"

  check() {
    if [ "$2" = true ]; then
      echo "ok $1"
    else
      echo "FAIL $1" >&2
      failures=$((failures + 1))
    fi
  }

  # oci_harness_version_filter
  out="$(oci_free_versions "$fx/versions_mixed.json")" && status=0 || status=$?
  [ "$status" -eq 0 ] && [ "$out" = "$(printf '19c\n23ai')" ] && r=true || r=false
  check "oci_harness_version_filter: free, shared versions only" "$r"
  oci_free_versions "$fx/versions_none_free.json" >/dev/null && status=0 || status=$?
  [ "$status" -eq 3 ] && r=true || r=false
  check "oci_harness_version_filter: all non-free -> SKIP_NO_FREE_VERSION" "$r"
  oci_free_versions "$scratch/empty.json" >/dev/null && status=0 || status=$?
  [ "$status" -eq 3 ] && r=true || r=false
  check "oci_harness_version_filter: CLI-omitted empty list -> SKIP_NO_FREE_VERSION" "$r"

  # oci_harness_ownership
  out="$(oci_owned_adbs "$fx/adb_list_pre.json" "$fx/adb_list_post.json" omcp-selftest-run-v1)"
  [ "$out" = synthetic-adb-owned-0001 ] && r=true || r=false
  check "oci_harness_ownership: only the new, run-tagged, live ADB is owned" "$r"
  if printf '%s\n' "$out" | grep -q '^synthetic-adb-pre-'; then r=false; else r=true; fi
  check "oci_harness_ownership: pre-existing ADBs (even same-tagged) never selected" "$r"
  oci_assert_single_owned "$fx/adb_list_pre.json" "$fx/adb_list_post.json" \
    omcp-selftest-run-v1 synthetic-adb-owned-0001 >/dev/null && r=true || r=false
  check "oci_harness_ownership: exactly one owned ADB matching Terraform passes" "$r"
  out="$(oci_assert_single_owned "$fx/adb_list_pre.json" "$fx/adb_list_post.json" \
    omcp-selftest-run-v1 synthetic-adb-pre-0001)" && r=false || r=true
  [ "$out" = OWNERSHIP_TERRAFORM_MISMATCH ] || r=false
  check "oci_harness_ownership: a pre-existing id is refused as the owned target" "$r"
  out="$(oci_assert_single_owned "$fx/adb_list_pre.json" "$fx/adb_list_pre.json" \
    omcp-selftest-run-v1 synthetic-adb-owned-0001)" && r=false || r=true
  [ "$out" = OWNERSHIP_COUNT_0 ] || r=false
  check "oci_harness_ownership: nothing new -> refused (count 0)" "$r"

  # oci_harness_zero_cost_empty_list
  out="$(oci_zero_cost_verdict "$fx/compartment_control.json" "$scratch/empty.json" synthetic-compartment-0001 "")"
  [ "$out" = ZERO_COST_PASS ] && r=true || r=false
  check "oci_harness_zero_cost_empty_list: empty list with control present passes" "$r"
  out="$(oci_zero_cost_verdict "$scratch/empty.json" "$scratch/empty.json" synthetic-compartment-0001 "")" && r=false || r=true
  [ "$out" = ZERO_COST_CONTROL_MISSING ] || r=false
  check "oci_harness_zero_cost_empty_list: missing control result fails closed" "$r"
  out="$(oci_zero_cost_verdict "$fx/compartment_control.json" "$scratch/empty.json" synthetic-compartment-0002 "")" && r=false || r=true
  [ "$out" = ZERO_COST_CONTROL_MISSING ] || r=false
  check "oci_harness_zero_cost_empty_list: control for another compartment fails closed" "$r"
  out="$(oci_zero_cost_verdict "$fx/compartment_control.json" "$scratch/empty.json" synthetic-compartment-0003 "")" && r=false || r=true
  [ "$out" = ZERO_COST_CONTROL_MISSING ] || r=false
  check "oci_harness_zero_cost_empty_list: a non-ACTIVE compartment fails closed" "$r"
  out="$(oci_zero_cost_verdict "$fx/compartment_control.json" "$fx/adb_list_post.json" synthetic-compartment-0001 synthetic-adb-owned-0001)" && r=false || r=true
  [ "$out" = ZERO_COST_FOREIGN_ADB_3 ] || r=false
  check "oci_harness_zero_cost: foreign live ADBs fail (terminated ones ignored)" "$r"
  out="$(oci_zero_cost_verdict "$fx/compartment_control.json" "$fx/adb_list_owned_only.json" synthetic-compartment-0001 synthetic-adb-owned-0001)"
  [ "$out" = ZERO_COST_PASS ] && r=true || r=false
  check "oci_harness_zero_cost: only the run's own Always Free ADB passes" "$r"
  out="$(oci_zero_cost_verdict "$fx/compartment_control.json" "$fx/adb_list_owned_only.json" synthetic-compartment-0001 "")" && r=false || r=true
  [ "$out" = ZERO_COST_FOREIGN_ADB_1 ] || r=false
  check "oci_harness_zero_cost: a live ADB the run does not own fails" "$r"

  rm -r -- "$scratch"
  if [ "$failures" -ne 0 ]; then
    echo "oci_adb_terraform selftest: $failures failure(s)" >&2
    return 1
  fi
  echo "oci_adb_terraform selftest: OK"
}

if [ "$mode" = selftest ]; then
  oci_selftest
  exit $?
fi

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
steps_file="$run_dir/steps.jsonl"
owned_file="$run_dir/owned_adb_id"
teardown_verdict="not_needed"
zero_cost_pre="not_run"
zero_cost_post="not_run"
oci_python="${ORACLEMCP_OCI_PYTHON:-python3}"
export SUPPRESS_LABEL_WARNING=True

oci_cli() {
  OCI_CLI_CONFIG_FILE="$oci_config" oci --profile DEFAULT "$@"
}

# One identifier-free JSONL record per harness step:
# {case_id, phase, expected, actual, verdict, duration_ms, gating}.
oci_step() {
  jq -cn --arg case_id "$1" --arg phase "$2" --arg expected "$3" --arg actual "$4" \
    --arg verdict "$5" --argjson duration_ms "${6:-0}" --argjson gating "${7:-true}" \
    '{case_id: $case_id, phase: $phase, expected: $expected, actual: $actual,
      verdict: $verdict, duration_ms: $duration_ms, gating: $gating}' >>"$steps_file"
}

# Record this run's live values in the runner-private deny file (never
# uploaded); the confidentiality scan fails any artifact containing one.
# Values shorter than 6 characters are too generic to deny exactly.
oci_deny() {
  local value
  [ -n "$deny_file" ] || return 0
  for value in "$@"; do
    [ "${#value}" -ge 6 ] && printf '%s\n' "$value" >>"$deny_file"
  done
  return 0
}

# Authoritative zero-cost check for the run's compartment (the only
# compartment this principal may create ADBs in). $1 label, $2 the run's own
# ADB id or empty. Prints the typed verdict; exit 0 only on ZERO_COST_PASS.
zero_cost_check() {
  local label="$1" own="$2"
  local control="$run_dir/zero_cost_${label}_control.json"
  local list="$run_dir/zero_cost_${label}_adb_list.json"
  if ! oci_cli iam compartment list --compartment-id "$TF_VAR_tenancy_ocid" --all \
    >"$control" 2>"$control.err"; then
    : >"$control"
  fi
  if ! oci_cli db autonomous-database list --compartment-id "$TF_VAR_compartment_ocid" --all \
    >"$list" 2>"$list.err"; then
    echo ZERO_COST_LIST_FAILED
    return 1
  fi
  oci_zero_cost_verdict "$control" "$list" "$TF_VAR_compartment_ocid" "$own"
}

# $1 ADB id. Exit 0 once OCI reports it TERMINATED (or no longer knows it).
verify_destroyed() {
  local attempt state
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if oci_cli db autonomous-database get --autonomous-database-id "$1" \
      >"$run_dir/verify_destroyed.json" 2>"$run_dir/verify_destroyed.err"; then
      state="$(jq -r '.data."lifecycle-state"' "$run_dir/verify_destroyed.json")"
    elif grep -q '"status": 404' "$run_dir/verify_destroyed.err"; then
      state=GONE
    else
      state=UNKNOWN
    fi
    case "$state" in
      TERMINATED | GONE) return 0 ;;
    esac
    [ "$attempt" -lt 10 ] && sleep 30
  done
  return 1
}

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
        adb_id="$(cat "$owned_file" 2>/dev/null || true)"
        if [ -z "$adb_id" ]; then
          # Ownership was never proven (failure between apply and the post
          # snapshot): delete Terraform's id only if it carries this run's tag.
          adb_id="$(terraform -chdir="$terraform_dir" output -state="$state_file" -raw adb_id 2>/dev/null || true)"
          if [ -n "$adb_id" ] && ! oci_cli db autonomous-database get --autonomous-database-id "$adb_id" 2>/dev/null |
            jq -e --arg run "$run_id" '.data."freeform-tags"["oraclemcp-run-id"] == $run' >/dev/null; then
            e2e_log_event "terraform_destroy" "teardown" "fail" 0 "refusing OCI CLI delete: Terraform's ADB does not carry this run's tag"
            adb_id=""
          fi
        fi
        if [ -n "$adb_id" ] && oci_cli db autonomous-database delete \
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
    teardown_verdict="destroy_failed"
    if [ "$destroy_status" -eq 0 ]; then
      if [ ! -s "$owned_file" ] || verify_destroyed "$(<"$owned_file")"; then
        teardown_verdict="destroyed"
      else
        teardown_verdict="destroy_unverified"
        destroy_status=1
        e2e_log_event "terraform_destroy" "teardown" "fail" 0 "OCI still reports the owned ADB as not terminated"
      fi
    fi
    oci_step teardown teardown destroyed "$teardown_verdict" \
      "$([ "$teardown_verdict" = destroyed ] && echo pass || echo fail)"
  fi
  if [ "$mode" = provision-only ] && [ "$E2E_DRY_RUN" != "1" ] && [ -f "$oci_config" ]; then
    zero_cost_post="$(zero_cost_check post "")" || destroy_status=1
    oci_step zero_cost_post teardown ZERO_COST_PASS "$zero_cost_post" \
      "$([ "$zero_cost_post" = ZERO_COST_PASS ] && echo pass || echo fail)"
    if [ -n "$results_file" ]; then
      touch "$steps_file"
      jq -n --arg db_version "$db_version" --arg run_id "$run_id" \
        --arg teardown "$teardown_verdict" --arg zpre "$zero_cost_pre" --arg zpost "$zero_cost_post" \
        --argjson ok "$([ "$prior_status" -eq 0 ] && [ "$destroy_status" -eq 0 ] && echo true || echo false)" \
        --slurpfile cases "$steps_file" \
        '{db_version: $db_version, run_id: $run_id, connection: "adb_high",
          cases: $cases, teardown: $teardown,
          zero_cost: {pre: $zpre, post: $zpost},
          verdict: (if $ok then "pass" else "fail" end)}' >"$results_file"
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
if [ "$mode" = tier-c ] || [ "$mode" = provision-only ]; then
  [ "${ORACLEMCP_REAL_ADB_NON_CUSTOMER_ASSERTION:-}" = "1" ] || \
    e2e_finish_fail "set ORACLEMCP_REAL_ADB_NON_CUSTOMER_ASSERTION=1 after confirming the lane is throwaway"
fi
if [ "$mode" = provision-only ] && [ -z "$db_version" ]; then
  e2e_finish_fail "--provision-only requires --db-version"
fi

if [ -z "$run_id" ]; then
  run_id="omcp-$(date -u +%Y%m%d%H%M%S)-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
fi
[[ "$run_id" =~ ^[a-z0-9][a-z0-9-]{5,62}$ ]] || e2e_finish_fail "run id must be 6-63 lowercase alphanumerics or hyphens"

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

if [ "$mode" = tier-c ]; then
  deny_file="$run_dir/deny_values"
  : >"$deny_file"
  chmod 600 "$deny_file"
  export ORACLEMCP_OCI_DENY_FILE="$deny_file"
fi
oci_deny "$TF_VAR_tenancy_ocid" "$TF_VAR_user_ocid" "$TF_VAR_compartment_ocid" \
  "$TF_VAR_region" "$TF_VAR_fingerprint"

# Discover the free-tier-enabled versions OCI offers this compartment today.
discover_free_versions() {
  local raw="$run_dir/adb_versions.json" status
  if ! oci_cli db autonomous-db-version list --compartment-id "$TF_VAR_compartment_ocid" \
    --db-workload OLTP --all >"$raw" 2>"$raw.err"; then
    e2e_finish_fail "listing ADB versions failed"
  fi
  oci_free_versions "$raw" >"$run_dir/free_versions" && status=0 || status=$?
  case "$status" in
    0) ;;
    3) e2e_finish_fail "SKIP_NO_FREE_VERSION: OCI offers no free-tier-enabled OLTP ADB version" ;;
    *) e2e_finish_fail "ADB version list was malformed" ;;
  esac
  jq -r '(.data // [])[] | "candidate version=\(.version) free_tier=\(."is-free-tier-enabled") dedicated=\(."is-dedicated" // false)"' \
    "$raw" | while IFS= read -r line; do
    e2e_log_event "version_candidate" "setup" "running" 0 "$line"
  done
}

if [ "$mode" = tier-c ]; then
  if [ "$E2E_DRY_RUN" = "1" ]; then
    e2e_finish_fail "--tier-c has no dry-run; use --selftest for the offline checks"
  fi
  zero_cost_pre="$(zero_cost_check pre "")" || e2e_finish_fail "zero-cost pre-check failed: $zero_cost_pre"
  e2e_log_event "zero_cost" "setup" "pass" 0 "pre-run: $zero_cost_pre"
  discover_free_versions
  mapfile -t versions <"$run_dir/free_versions"
  e2e_log_event "version_discovery" "setup" "pass" 0 "${#versions[@]} free-tier-enabled version(s): ${versions[*]}"

  lane_ok=true
  index=0
  for version in "${versions[@]}"; do
    index=$((index + 1))
    child_args=(--provision-only --db-version "$version" --run-id "$run_id-v$index"
      --results-file "$run_dir/results_v$index.json")
    [ -n "$run_cmd" ] && child_args+=(--run "$run_cmd")
    [ "$fail_after_apply" = true ] && child_args+=(--fail-after-apply)
    [ "$E2E_LOG" = "1" ] && child_args+=(--log)
    e2e_log_event "version_run" "act" "running" 0 "version $version: provision, exercise, destroy"
    if bash "$ROOT/scripts/e2e/oci_adb_terraform.sh" "${child_args[@]}"; then
      e2e_log_event "version_run" "act" "pass" 0 "version $version passed"
    else
      lane_ok=false
      e2e_log_event "version_run" "act" "fail" 0 "version $version failed"
    fi
    if [ ! -s "$run_dir/results_v$index.json" ]; then
      jq -n --arg v "$version" '{db_version: $v, cases: [], teardown: "unknown", verdict: "no_result"}' \
        >"$run_dir/results_v$index.json"
    fi
    # Never provision the next version while this one may still exist.
    if [ "$(jq -r '.teardown' "$run_dir/results_v$index.json")" != destroyed ]; then
      lane_ok=false
      e2e_log_event "version_run" "act" "fail" 0 "teardown of version $version not proven; stopping before the next version"
      break
    fi
  done

  zero_cost_post="$(zero_cost_check post "")" || lane_ok=false
  e2e_log_event "zero_cost" "teardown" "$([ "$zero_cost_post" = ZERO_COST_PASS ] && echo pass || echo fail)" 0 \
    "post-run: $zero_cost_post"

  mkdir -p "$run_dir/publish"
  results_json="$run_dir/publish/oci_adb_results.json"
  jq -s --arg run_id "$run_id" --arg zpre "$zero_cost_pre" --arg zpost "$zero_cost_post" \
    --argjson ok "$lane_ok" --argjson discovered "$(jq -R . "$run_dir/free_versions" | jq -s .)" \
    '{schema: "oraclemcp-oci-adb-results/v1", lane: "tier-c-oci-adb", run_id: $run_id,
      discovered_free_versions: $discovered, versions: .,
      zero_cost: {pre: $zpre, post: $zpost},
      verdict: (if $ok and $zpost == "ZERO_COST_PASS" and ([.[] | .verdict == "pass"] | all)
                then "pass" else "fail" end)}' \
    "$run_dir"/results_v*.json >"$results_json"

  # Nothing leaves the run dir until it is free of every live value.
  if ! bash "$ROOT/scripts/secret_scan.sh" --deny-values-from "$deny_file" "$results_json" \
    >"$run_dir/confidentiality_scan.log" 2>&1; then
    e2e_finish_fail "confidentiality scan found a live identifier in the results; nothing was published"
  fi
  e2e_log_event "confidentiality_scan" "assert" "pass" 0 "results JSON free of live identifiers"
  if [ -n "$results_out" ]; then
    cp "$results_json" "$results_out"
  fi
  if [ "$(jq -r .verdict "$results_json")" != pass ]; then
    e2e_finish_fail "tier-C OCI lane failed; see the per-version verdicts in the results JSON"
  fi
  e2e_finish_pass
  exit 0
fi

if [ -z "$db_version" ]; then
  discover_free_versions
  db_version="$(tail -n 1 "$run_dir/free_versions")"
fi
[[ "$db_version" =~ ^[0-9A-Za-z][0-9A-Za-z._-]{0,31}$ ]] || e2e_finish_fail "unsafe ADB version string"
export TF_VAR_db_version="$db_version"
export TF_VAR_run_id="$run_id"
e2e_log_event "adb_version" "setup" "running" 0 "ADB version $db_version, run tag set"

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

zero_cost_pre="$(zero_cost_check pre "")" || {
  oci_step zero_cost_pre setup ZERO_COST_PASS "$zero_cost_pre" fail
  e2e_finish_fail "zero-cost pre-check failed before provisioning: $zero_cost_pre"
}
oci_step zero_cost_pre setup ZERO_COST_PASS "$zero_cost_pre" pass
if ! oci_cli db autonomous-database list --compartment-id "$TF_VAR_compartment_ocid" --all \
  >"$run_dir/adb_list_pre.json" 2>"$run_dir/adb_list_pre.err"; then
  e2e_finish_fail "could not snapshot pre-existing ADBs before apply"
fi

destroy_needed=true
apply_started="$(e2e_epoch_ms)"
if ! run_redacted "act" "terraform apply throwaway Always Free ADB" terraform -chdir="$terraform_dir" apply -input=false -auto-approve -no-color -state="$state_file" "$plan_file"; then
  oci_step provision act "Always Free ADB AVAILABLE" "terraform apply failed" fail "$(($(e2e_epoch_ms) - apply_started))"
  e2e_finish_fail "Terraform apply failed"
fi
oci_step provision act "Always Free ADB AVAILABLE" "terraform apply succeeded" pass "$(($(e2e_epoch_ms) - apply_started))"

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

# Ownership: the run owns exactly the new ADB carrying its run tag, and it
# must be the one Terraform reports. Assertions and the teardown fallback act
# on that id only; pre-existing ADBs are never touched.
ownership_started="$(e2e_epoch_ms)"
ownership=""
for attempt in 1 2 3; do
  if oci_cli db autonomous-database list --compartment-id "$TF_VAR_compartment_ocid" --all \
    >"$run_dir/adb_list_post.json" 2>"$run_dir/adb_list_post.err" &&
    ownership="$(oci_assert_single_owned "$run_dir/adb_list_pre.json" "$run_dir/adb_list_post.json" \
      "$run_id" "$(<"$run_dir/adb_id")")"; then
    ownership=OWNED
    break
  fi
  [ "$attempt" -lt 3 ] && sleep 10
done
if [ "$ownership" != OWNED ]; then
  oci_step ownership act "exactly one new run-tagged Always Free ADB" "${ownership:-list_failed}" fail \
    "$(($(e2e_epoch_ms) - ownership_started))"
  e2e_finish_fail "ownership check failed: ${ownership:-ADB list failed}"
fi
cp "$run_dir/adb_id" "$owned_file"
chmod 600 "$owned_file"
oci_step ownership act "exactly one new run-tagged Always Free ADB" "owned" pass \
  "$(($(e2e_epoch_ms) - ownership_started))"
oci_deny "$(<"$owned_file")" "$(<"$run_dir/admin_password")" "$(<"$run_dir/wallet_password")" \
  "$(jq -r --arg id "$(<"$owned_file")" '(.data // [])[] | select(.id == $id) | ."db-name" // empty' "$run_dir/adb_list_post.json")" \
  "$(jq -r --arg id "$(<"$owned_file")" '(.data // [])[] | select(.id == $id) | ."display-name" // empty' "$run_dir/adb_list_post.json")"

if [ "$fail_after_apply" = true ]; then
  oci_step forced_failure act "test switch fails after apply" "forced failure" fail 0
  e2e_finish_fail "FORCED_FAILURE_AFTER_APPLY: teardown must still destroy the owned ADB"
fi

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

# A full DESCRIPTION descriptor owns its transport settings.  The server
# deliberately rejects the profile-level connect_timeout_seconds in this case,
# so add the bounded connect timeout to the descriptor itself.  Replace an
# existing scalar rather than producing ambiguous duplicate settings.
transport_timeout = re.compile(
    r"\(TRANSPORT_CONNECT_TIMEOUT\s*=\s*[0-9]+\s*\)", re.I
)
if transport_timeout.search(descriptor):
    descriptor = transport_timeout.sub("(TRANSPORT_CONNECT_TIMEOUT=60)", descriptor)
else:
    descriptor = descriptor[:-1] + "(TRANSPORT_CONNECT_TIMEOUT=60))"
if len(transport_timeout.findall(descriptor)) != 1:
    raise SystemExit("wallet HIGH descriptor has an ambiguous transport connect timeout")

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

json.dump(
    {
        "descriptor": descriptor,
        "host": host,
        "port": int(port),
        "transport_connect_timeout": 60,
    },
    sys.stdout,
)
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
# this descriptor's DNS-safe HOST. OCI's front end requires the wallet's
# service-form SNI, so preserve it while keeping the DN check enabled.
wallet_use_sni=true

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
  printf 'description = "runtime-only throwaway ADB IAM TCPS readiness probe; never committed"\n'
  printf 'connect_string = %s\n' "$bootstrap_connect_string"
  printf 'username = "ADMIN"\n'
  printf 'credential_ref = "env:ADB_ADMIN_PASSWORD"\n'
  printf 'max_level = "READ_ONLY"\n'
  printf 'default_level = "READ_ONLY"\n'
  # The wallet supplies a full Oracle Net descriptor.  The server correctly
  # refuses to inject connect_timeout_seconds into one; a harness retry bounds
  # startup instead, while any descriptor-specific transport timeout remains
  # authored inside tnsnames.ora.
  printf 'call_timeout_seconds = 30\n\n'
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

if [ "$mode" = provision-only ]; then
  # The doctor attempt is informational in the tier-C lane: a build failure
  # is recorded by that step, not allowed to mask the control connect.
  e2e_run_cargo_capped "setup" build -p oraclemcp --bin oraclemcp || true
else
  if ! e2e_run_cargo_capped "setup" build -p oraclemcp --bin oraclemcp; then
    e2e_finish_fail "building oraclemcp for the IAM TCPS readiness probe failed"
  fi
  [ -x "$bootstrap_binary" ] || e2e_finish_fail "IAM TCPS readiness-probe binary was not produced"
fi

adb_id="$(<"$run_dir/adb_id")"

# ADMIN control actions (connect / open-schema / close-schema) through the
# independent python-oracledb helper; see scripts/e2e/oci_adb_control.py.
adb_py() {
  env ADB_ADMIN_PASSWORD="$admin_password" ADB_WALLET_PASSWORD="$wallet_password" \
    RUN_SCHEMA_PASSWORD="${run_schema_password:-}" \
    "$oci_python" "$ROOT/scripts/e2e/oci_adb_control.py" \
    "$run_dir/admin_connect_string" "$wallet_dir" "$@"
}

# Time one gating or informational step and record it.
timed_step() {
  local case_id="$1" expected="$2" gating="$3"
  shift 3
  local started status
  started="$(e2e_epoch_ms)"
  set +e
  "$@" >"$run_dir/step_${case_id}.log" 2>&1
  status=$?
  set -e
  oci_step "$case_id" act "$expected" "exit $status" \
    "$([ "$status" -eq 0 ] && echo pass || echo fail)" "$(($(e2e_epoch_ms) - started))" "$gating"
  return "$status"
}

if [ "$mode" = provision-only ]; then
  # Wallet endpoints are live identifiers: deny them in every artifact.
  mapfile -t wallet_values < <(grep -oiE '\((host|service_name)[[:space:]]*=[[:space:]]*[^)[:space:]]+' \
    "$wallet_dir/tnsnames.ora" | sed -E 's/^[^=]*=[[:space:]]*//' | sort -u)
  for value in "${wallet_values[@]}"; do
    oci_deny "$value"
    if [[ "$value" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
      mapfile -t addresses < <(getent ahosts "$value" 2>/dev/null | awk '{print $1}' | sort -u)
      [ "${#addresses[@]}" -eq 0 ] || oci_deny "${addresses[@]}"
    fi
  done
  oci_deny "$ssl_dn"

  lane_ok=true
  if timed_step control_connect "python-oracledb thin ADMIN connect over the wallet" true \
    adb_py control; then
    e2e_log_event "control_connect" "act" "pass" 0 "python-oracledb thin control connect succeeded"
  else
    lane_ok=false
    e2e_log_event "control_connect" "act" "fail" 0 "python-oracledb thin control connect failed"
    e2e_finish_fail "control connect failed; the ADB, wallet or credentials are not usable"
  fi

  # Informational until T9.3: the verdict is recorded, never hidden, and does
  # not gate this lane.
  timed_step doctor_online "oraclemcp doctor --online (informational until T9.3)" false \
    env -i "HOME=$HOME" "PATH=$PATH" "XDG_STATE_HOME=$bootstrap_state" \
    "ORACLEMCP_CONFIG=$bootstrap_config" "ADB_ADMIN_PASSWORD=$admin_password" \
    "ADB_WALLET_PASSWORD=$wallet_password" \
    "$bootstrap_binary" --json doctor --online --profile oci_adb_bootstrap || true

  run_schema="OMCP_RUN_$(printf '%s' "$run_id" | tr 'a-z-' 'A-Z_')"
  run_schema_password="$(python3 -c 'import secrets, string
alphabet = string.ascii_letters + string.digits + "_#"
while True:
    p = "R" + "".join(secrets.choice(alphabet) for _ in range(23))
    if any(c.islower() for c in p) and any(c.isupper() for c in p) and any(c.isdigit() for c in p):
        print(p)
        break')"
  oci_deny "$run_schema_password"
  schema_open=false
  if timed_step schema_open "isolated run schema created" true adb_py open-schema "$run_schema"; then
    schema_open=true
  else
    lane_ok=false
  fi

  if [ "$schema_open" = true ] && [ -n "$run_cmd" ]; then
    jq -n --arg u ADMIN --arg p "$admin_password" --arg w "$wallet_password" \
      '{user: $u, password: $p, wallet_password: $w}' >"$run_dir/admin_credentials.json"
    jq -n --arg u "$run_schema" --arg p "$run_schema_password" --arg w "$wallet_password" \
      '{user: $u, password: $p, wallet_password: $w}' >"$run_dir/run_schema_credentials.json"
    target_env="$run_dir/target.env"
    {
      printf 'ORACLEMCP_OCI_DB_VERSION=%s\n' "$db_version"
      printf 'ORACLEMCP_OCI_RUN_ID=%s\n' "$run_id"
      printf 'ORACLEMCP_OCI_CONNECTION=adb_high\n'
      printf 'ORACLEMCP_OCI_CONNECT_STRING_FILE=%s\n' "$run_dir/admin_connect_string"
      printf 'ORACLEMCP_OCI_WALLET_DIR=%s\n' "$wallet_dir"
      printf 'ORACLEMCP_OCI_ADMIN_CREDENTIALS_FILE=%s\n' "$run_dir/admin_credentials.json"
      printf 'ORACLEMCP_OCI_CREDENTIALS_FILE=%s\n' "$run_dir/run_schema_credentials.json"
      printf 'ORACLEMCP_OCI_RUN_SCHEMA=%s\n' "$run_schema"
    } >"$target_env"
    if timed_step run_hook "supplied tier-C command exits 0" true \
      env ORACLEMCP_OCI_TARGET_ENV="$target_env" bash -c "$run_cmd"; then
      e2e_log_event "run_hook" "act" "pass" 0 "tier-C command passed on version $db_version"
    else
      lane_ok=false
      e2e_log_event "run_hook" "act" "fail" 0 "tier-C command failed on version $db_version"
    fi
  fi

  if [ "$schema_open" = true ]; then
    timed_step schema_close "isolated run schema dropped" true adb_py close-schema "$run_schema" ||
      lane_ok=false
  fi

  if [ "$lane_ok" != true ]; then
    e2e_finish_fail "tier-C version $db_version failed; see its results cases"
  fi
  e2e_finish_pass
  exit 0
fi

scope="urn:oracle:db::id::$TF_VAR_compartment_ocid::$adb_id"
if ! run_redacted "act" "mint scoped OCI database token" env OCI_CLI_CONFIG_FILE="$oci_config" oci --profile DEFAULT iam db-token get --db-token-location "$token_dir" --scope "$scope"; then
  e2e_finish_fail "OCI database-token mint failed"
fi
[ -s "$token_dir/token" ] || e2e_finish_fail "OCI CLI did not write a database token"
chmod 600 "$token_dir/token"
# `oci iam db-token get` also writes the RSA private key the token is bound to
# (`oci_db_key.pem`). OCI IAM database tokens are proof-of-possession, so the
# server-side IAM probe must sign the auth header with this key; a bearer token
# alone is refused with ORA-01017.
[ -s "$token_dir/oci_db_key.pem" ] || e2e_finish_fail "OCI CLI did not write the db-token private key (oci_db_key.pem)"
chmod 600 "$token_dir/oci_db_key.pem"

# OCI's scoped database token names the IAM principal twice: `userName` and
# `dbUserName` carry the human-readable OCI user name. This *name* is what the
# ADB `IDENTIFIED GLOBALLY AS 'IAM_PRINCIPAL_NAME=<name>'` mapping matches at
# token-auth time (Oracle resolves the name to the OCID at CREATE USER and
# stores it in DBA_USERS.EXTERNAL_NAME). `sub` is the stable OCID, captured
# only for logging/audit — it is NOT the global-user mapping key (mapping the
# OCID as IAM_PRINCIPAL_NAME never matches the token's principal and yields
# ORA-01017). The database schema is a separate mapped global user. Decode only
# these non-secret claims and refuse a mismatch before creating any mapping or
# opening the token probe.
token_identity="$run_dir/iam_token_identity"
if ! python3 - "$token_dir/token" >"$token_identity" <<'PY'
import base64
import json
import re
import sys

token = open(sys.argv[1], encoding="utf-8").read().strip()
parts = token.split(".")
if len(parts) != 3:
    raise SystemExit("OCI database token is not a three-segment JWT")
payload = parts[1] + "=" * (-len(parts[1]) % 4)
try:
    claims = json.loads(base64.urlsafe_b64decode(payload))
except (ValueError, json.JSONDecodeError) as error:
    raise SystemExit("OCI database token payload is not valid JSON") from error

principal = claims.get("userName")
login_user = claims.get("dbUserName")
subject = claims.get("sub")
if not all(isinstance(value, str) for value in (principal, login_user, subject)):
    raise SystemExit("OCI database token omits userName, dbUserName, or sub")
if principal != login_user:
    raise SystemExit("OCI database token userName and dbUserName differ")
for claim_name, value in (("principal", principal), ("subject", subject)):
    if not re.fullmatch(r"[A-Za-z0-9._@:/=-]{1,128}", value):
        raise SystemExit(f"OCI database token {claim_name} has unsupported characters")
print(principal)
print(subject)
PY
then
  e2e_finish_fail "could not verify OCI database token identity"
fi
chmod 600 "$token_identity"
mapfile -t token_identity_lines <"$token_identity"
if [ "${#token_identity_lines[@]}" -ne 2 ]; then
  e2e_finish_fail "OCI database token identity extraction returned an invalid claim count"
fi
token_principal="${token_identity_lines[0]}"
token_subject="${token_identity_lines[1]}"
if [ "$token_principal" != "$ORACLEMCP_ADB_IAM_PRINCIPAL_NAME" ]; then
  e2e_finish_fail "OCI database token principal does not match ORACLEMCP_ADB_IAM_PRINCIPAL_NAME"
fi
e2e_log_event "iam_token_principal" "act" "pass" 0 \
  "scoped OCI token userName/dbUserName matches the configured IAM user (${#token_subject} char sub OCID captured for audit only; the principal NAME is the IAM_PRINCIPAL_NAME mapping key)"


wait_for_adb_tcps() {
  local attempt status started ended output cert_chain server_dn
  # Terraform waits for resource creation, but the freshly-created ADB's TCPS
  # listener can lag that state briefly. Probe through the real server before
  # any direct ADMIN mapping; never retry the mapping itself.
  for attempt in 1 2 3 4 5 6; do
    started="$(e2e_epoch_ms)"
    output="$run_dir/adb_tcps_readiness_${attempt}.log"
    e2e_log_event "adb_tcps_readiness" "setup" "running" 0 \
      "real server doctor attempt $attempt/6 before direct IAM bootstrap"
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
            "captured real TCPS leaf certificate DN before direct IAM bootstrap"
        fi
      fi
    fi
    set +e
    env -i \
      "HOME=$HOME" \
      "PATH=$PATH" \
      "XDG_STATE_HOME=$bootstrap_state" \
      "ORACLEMCP_CONFIG=$bootstrap_config" \
      "ADB_ADMIN_PASSWORD=$admin_password" \
      "ADB_WALLET_PASSWORD=$wallet_password" \
      "$bootstrap_binary" --json doctor --online --profile oci_adb_bootstrap >"$output" 2>&1
    status=$?
    set -e
    ended="$(e2e_epoch_ms)"
    if [ "$status" -eq 0 ]; then
      e2e_log_event "adb_tcps_readiness" "setup" "pass" "$((ended - started))" \
        "real server doctor connected before direct IAM bootstrap"
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

if ! wait_for_adb_tcps; then
  e2e_finish_fail "throwaway ADB TCPS listener did not become ready before direct IAM bootstrap"
fi

bootstrap_manifest="$ROOT/scripts/e2e/oci_adb_iam_bootstrap/Cargo.toml"
[ -f "$bootstrap_manifest" ] || e2e_finish_fail "missing direct OCI IAM bootstrap helper"

e2e_log_event "iam_admin_bootstrap" "act" "running" 0 \
  "direct ADMIN wallet setup enables OCI IAM and maps the throwaway principal"
if ! ORACLEMCP_ADB_CONNECT_STRING="$(<"$run_dir/admin_connect_string")" \
  ORACLEMCP_ADB_ADMIN_PASSWORD="$admin_password" \
  ORACLEMCP_ADB_WALLET_LOCATION="$wallet_dir" \
  ORACLEMCP_ADB_WALLET_PASSWORD="$wallet_password" \
  ORACLEMCP_ADB_SSL_SERVER_CERT_DN="$ssl_dn" \
  ORACLEMCP_ADB_IAM_PRINCIPAL_NAME="$token_principal" \
  ORACLEMCP_ADB_IAM_DATABASE_USER="$(<"$run_dir/iam_database_user")" \
  e2e_run_cargo_capped "act" run --quiet --manifest-path "$bootstrap_manifest"; then
  e2e_finish_fail "creating OCI IAM global-user mapping failed"
fi
e2e_log_event "iam_admin_bootstrap" "act" "pass" 0 \
  "direct ADMIN wallet setup enabled OCI IAM and mapped the throwaway principal"

if ! run_redacted "act" "real ADB TCPS password and IAM signoff" env \
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$run_dir/cargo-target}" \
  ORACLEMCP_REAL_ADB_SIGNOFF=1 \
  ORACLEMCP_REAL_ADB_NON_CUSTOMER_ASSERTION=1 \
  ORACLEMCP_REAL_ADB_CONNECT_STRING="$(<"$run_dir/admin_connect_string")" \
  ORACLEMCP_REAL_ADB_PASSWORD_USER=ADMIN \
  ORACLEMCP_REAL_ADB_IAM_DATABASE_USER="$(<"$run_dir/iam_database_user")" \
  ORACLEMCP_REAL_ADB_IAM_USER="$(<"$run_dir/iam_database_user")" \
  ORACLEMCP_REAL_ADB_PASSWORD="$admin_password" \
  ORACLEMCP_REAL_ADB_WALLET_LOCATION="$wallet_dir" \
  ORACLEMCP_REAL_ADB_WALLET_PASSWORD="$wallet_password" \
  ORACLEMCP_REAL_ADB_SSL_SERVER_CERT_DN="$ssl_dn" \
  ORACLEMCP_REAL_ADB_USE_SNI="$wallet_use_sni" \
  ORACLEMCP_REAL_ADB_IAM_TOKEN="$(<"$token_dir/token")" \
  ORACLEMCP_REAL_ADB_IAM_TOKEN_KEY_FILE="$token_dir/oci_db_key.pem" \
  bash scripts/e2e/real_adb_tcps_signoff.sh --log; then
  e2e_finish_fail "real ADB TCPS signoff failed"
fi

if ! run_redacted "assert" "committed tree secret scan" bash scripts/secret_scan.sh; then
  e2e_finish_fail "committed-tree confidentiality scan failed"
fi

e2e_log_event "signoff_summary" "assert" "pass" 0 "verified password and scoped OCI-IAM token against a throwaway Always Free ADB; teardown follows"
e2e_finish_pass
