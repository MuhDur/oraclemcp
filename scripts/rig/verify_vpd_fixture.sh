#!/usr/bin/env bash
# D3 — the VPD/RLS lane, built the pessimistic way round.
#
# A round-3 field test found the VPD gate FAILING OPEN. A lane that asserted
# "the query succeeded" or "a policy is attached" would have passed happily
# through that defect, which is how it survived to be found in the field. So
# this lane asserts the only thing that distinguishes a working gate from a
# failed-open one: THE RESTRICTED ROWS ARE ABSENT FROM RESULTS.
#
# Two things that are easy to get wrong and were measured here, not assumed:
#
#   * GROUND TRUTH CANNOT COME FROM SYSTEM OR FROM THE TABLE OWNER. Both are
#     subject to the policy — the owner sees 1,2 exactly like everyone else. A
#     lane that took the owner's row set as "what really exists" would compare 2
#     against 2 and conclude nothing was withheld, and a fail-open would be
#     invisible to it. Only SYS (or a principal with EXEMPT ACCESS POLICY) sees
#     all four.
#
#   * BLINDNESS IS NOT ABOUT ROLES. ALL_POLICIES lists policies for every object
#     ACCESSIBLE to the caller, so a direct SELECT on the protected table lets a
#     principal read the policy out of the catalog however few roles it holds.
#     Genuine blindness needs access via a view whose owner holds the base
#     privileges.
#
# Usage:
#   bash scripts/rig/verify_vpd_fixture.sh [--lane free23|xe21|xe18]
#   bash scripts/rig/verify_vpd_fixture.sh --mutation-control
#
# --mutation-control proves the lane can FAIL: it swaps the policy predicate for
# '1=1' (exactly D4's no-op policy, and exactly the fail-open shape), re-runs the
# assertions, requires them to FAIL, then restores the real predicate.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LANE="${ORACLEMCP_D3_LANE:-free23}"
PW_FIXTURE="D3_Vpd_Test_42"
FINDINGS=0

lane_container() {
  case "$1" in
    xe18) printf '%s\n' 'oracle-xe18-1518' ;;
    xe21) printf '%s\n' 'oracle-xe21-1520' ;;
    free23) printf '%s\n' 'rust-oracledb-free' ;;
    *) return 1 ;;
  esac
}

lane_pdb() {
  case "$1" in
    xe18 | xe21) printf '%s\n' 'XEPDB1' ;;
    free23) printf '%s\n' 'FREEPDB1' ;;
    *) return 1 ;;
  esac
}

CONTAINER="$(lane_container "$LANE")" || { echo "unknown lane: $LANE" >&2; exit 2; }
PDB="$(lane_pdb "$LANE")"

# SQL as a given principal; stdout is the query output.
as_user() {
  local user="$1" pw="$2" sql="$3"
  printf 'set heading off feedback off pagesize 0\n%s\nexit\n' "$sql" \
    | timeout 90 docker exec -i "$CONTAINER" \
        sqlplus -S -L "${user}/${pw}@localhost:1521/${PDB}" 2>&1
}

# SYS inside the PDB — the only vantage point the policy does not filter.
as_sys() {
  local sql="$1"
  printf 'set heading off feedback off pagesize 0\nalter session set container=%s;\n%s\nexit\n' \
    "$PDB" "$sql" \
    | timeout 90 docker exec -i "$CONTAINER" sqlplus -S -L "/ as sysdba" 2>&1
}

ok()   { printf '  OK      %s\n' "$1"; }
bad()  { FINDINGS=$((FINDINGS + 1)); printf '  FAILED  %s\n' "$1" >&2; }
note() { printf '  NOTE    %s\n' "$1"; }

trim() { printf '%s' "$1" | tr -d ' \r\n'; }

# SQL*Plus on 23ai decorates a bare numeric column with box-drawing characters
# (the raw bytes are "|--| 2"), so pattern-matching the output for ^[0-9]+$
# silently yields the EMPTY STRING. That then compares unequal to every
# expectation and reads as a failed assertion rather than as a broken parse —
# a measurement bug wearing the costume of a finding.
#
# So every value is fetched as a MARKED string instead: concatenating a marker
# forces character output, which sqlplus leaves alone.
marked() { printf '%s' "$1" | grep -oE 'D3VAL:[0-9,]*' | head -1 | cut -d: -f2; }

# value_as <user> <pw> <expression> <from-clause>
value_as() { marked "$(as_user "$1" "$2" "select 'D3VAL:'||($3) $4;")"; }
value_sys() { marked "$(as_sys "select 'D3VAL:'||($1) $2;")"; }

run_assertions() {
  FINDINGS=0

  # ---------------------------------------------------------------------
  # Ground truth. Everything below is meaningless without it: "the blind
  # principal saw 2 rows" only implies withholding if more than 2 exist.
  # ---------------------------------------------------------------------
  local truth
  truth="$(value_sys "listagg(id,',') within group (order by id)" "from ORACLEMCP_D3_OWNER.ORACLEMCP_D3_PROTECTED")"
  if [ "$truth" = "1,2,3,4" ]; then
    ok "ground truth (SYS, exempt): rows 1,2,3,4 exist"
  else
    bad "ground truth is '$truth', expected '1,2,3,4' — the fixture is not loaded as this lane expects, so nothing below can be trusted"
    return 1
  fi

  # ---------------------------------------------------------------------
  # THE ASSERTION THAT MATTERS. Not "the query succeeded" — the withheld rows
  # must be absent.
  # ---------------------------------------------------------------------
  local blind_ids
  blind_ids="$(value_as ORACLEMCP_D3_BLIND "$PW_FIXTURE" "listagg(id,',') within group (order by id)" "from ORACLEMCP_D3_OWNER.ORACLEMCP_D3_PROTECTED_V")"
  case ",$blind_ids," in
    *,3,*|*,4,*)
      bad "FAIL-OPEN: the blind principal read restricted rows — got '$blind_ids', which contains an id the policy must withhold" ;;
    *)
      if [ "$blind_ids" = "1,2" ]; then
        ok "restricted rows are ABSENT for the blind principal (saw '$blind_ids', ground truth '$truth')"
      else
        bad "unexpected blind row set '$blind_ids' (expected exactly '1,2')"
      fi ;;
  esac

  local sighted_ids
  sighted_ids="$(value_as ORACLEMCP_D3_SIGHTED "$PW_FIXTURE" "listagg(id,',') within group (order by id)" "from ORACLEMCP_D3_OWNER.ORACLEMCP_D3_PROTECTED_SYN")"
  if [ "$sighted_ids" = "1,2" ]; then
    ok "the policy survives the SYNONYM: a second name for the object is still filtered"
  else
    bad "through the synonym the sighted principal saw '$sighted_ids', expected '1,2' — resolving identity by NAME lost the policy"
  fi

  # ---------------------------------------------------------------------
  # Inference, not just reading. Aggregates must not leak the withheld rows.
  # ---------------------------------------------------------------------
  local blind_count blind_max
  blind_count="$(value_as ORACLEMCP_D3_BLIND "$PW_FIXTURE" "count(*)" "from ORACLEMCP_D3_OWNER.ORACLEMCP_D3_PROTECTED_V")"
  blind_max="$(value_as ORACLEMCP_D3_BLIND "$PW_FIXTURE" "max(id)" "from ORACLEMCP_D3_OWNER.ORACLEMCP_D3_PROTECTED_V")"
  if [ "$blind_count" = "2" ] && [ "$blind_max" = "2" ]; then
    ok "aggregates do not leak: COUNT=$blind_count MAX=$blind_max are computed over the filtered set"
  else
    bad "aggregate leak: COUNT=$blind_count MAX=$blind_max (a filtered caller must not see totals over withheld rows)"
  fi

  # ---------------------------------------------------------------------
  # The silent-empty condition: the blind caller cannot learn a filter exists.
  # ---------------------------------------------------------------------
  local pol tabs
  pol="$(value_as ORACLEMCP_D3_BLIND "$PW_FIXTURE" "count(*)" "from all_policies")"
  tabs="$(value_as ORACLEMCP_D3_BLIND "$PW_FIXTURE" "count(*)" "from all_tables where owner='ORACLEMCP_D3_OWNER'")"
  if [ "$pol" = "0" ] && [ "$tabs" = "0" ]; then
    ok "the blind principal sees 0 policies and 0 base tables — a short answer with nothing to explain it (A1a's target)"
  else
    bad "the blind principal is not blind: policies=$pol tables=$tabs"
  fi

  # A1e: the sighted principal must be able to NAME the policy, or doctor cannot.
  local named
  named="$(as_user ORACLEMCP_D3_SIGHTED "$PW_FIXTURE" "select policy_name from all_policies where object_owner='ORACLEMCP_D3_OWNER';" | grep -c 'ORACLEMCP_D3_VPD')"
  if [ "$named" -ge 1 ]; then
    ok "the sighted principal NAMES the policy (ORACLEMCP_D3_VPD) — the A1e half is reachable"
  else
    bad "the sighted principal cannot name the policy; doctor could not surface it either"
  fi
}

# The side channel is reported separately because it is a RECORDED DEFECT, not a
# property that currently holds. It is the D3 failing half.
report_side_channel() {
  local hidden control
  hidden="$(as_user ORACLEMCP_D3_BLIND "$PW_FIXTURE" "insert into ORACLEMCP_D3_OWNER.ORACLEMCP_D3_PROTECTED_V values (3,'PUBLIC','probe');")"
  control="$(as_user ORACLEMCP_D3_BLIND "$PW_FIXTURE" "insert into ORACLEMCP_D3_OWNER.ORACLEMCP_D3_PROTECTED_V values (99,'PUBLIC','probe');
rollback;")"

  if printf '%s' "$hidden" | grep -q 'ORA-00001' && ! printf '%s' "$control" | grep -q 'ORA-00001'; then
    note "SIDE CHANNEL REPRODUCED (recorded failing half): inserting the primary key of a row the caller CANNOT SELECT raises ORA-00001, while an id that genuinely does not exist inserts cleanly. Hidden keys are therefore enumerable by probing."
    if printf '%s' "$hidden" | grep -q 'ORA-03301'; then
      note "AND THE ERROR DISCLOSES THE VALUE: this database also returns ORA-03301 naming the colliding column value of the unreadable row."
    fi
  else
    note "side channel did NOT reproduce on this lane — if a fix landed, update this lane deliberately rather than deleting the check."
  fi
}

mutation_control() {
  echo "MUTATION CONTROL: replacing the policy predicate with '1=1' (D4's no-op shape, and the fail-open shape)"
  as_sys "create or replace function ORACLEMCP_D3_OWNER.ORACLEMCP_D3_VPD (schema_name varchar2, object_name varchar2) return varchar2 authid definer as begin return '1=1'; end;
/" >/dev/null

  run_assertions >/tmp/d3_mutant.log 2>&1
  local mutant_findings="$FINDINGS"

  echo "RESTORING the real predicate"
  as_sys "create or replace function ORACLEMCP_D3_OWNER.ORACLEMCP_D3_VPD (schema_name varchar2, object_name varchar2) return varchar2 authid definer as begin return 'classification = ''PUBLIC'''; end;
/" >/dev/null

  run_assertions >/tmp/d3_restored.log 2>&1
  local restored_findings="$FINDINGS"

  if [ "$mutant_findings" -eq 0 ]; then
    echo "MUTATION CONTROL FAILED: a '1=1' policy withholds nothing, yet the lane reported no findings — it cannot detect a fail-open." >&2
    grep -E 'OK|FAILED' /tmp/d3_mutant.log >&2
    exit 1
  fi
  if [ "$restored_findings" -ne 0 ]; then
    echo "MUTATION CONTROL FAILED: the lane still reports findings after restoring the real predicate." >&2
    grep -E 'OK|FAILED' /tmp/d3_restored.log >&2
    exit 1
  fi
  echo "MUTATION CONTROL OK: the fail-open predicate produced $mutant_findings finding(s); the real predicate produces 0."
  grep -E 'FAILED' /tmp/d3_mutant.log | head -3
  exit 0
}

main() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --lane) LANE="${2:-}"; CONTAINER="$(lane_container "$LANE")" || exit 2; PDB="$(lane_pdb "$LANE")"; shift 2; continue ;;
      --mutation-control) mutation_control ;;
      --help|-h) sed -n '1,40p' "${BASH_SOURCE[0]}"; exit 0 ;;
      *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
  done

  command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 2; }
  echo "D3 VPD lane on ${LANE} (${CONTAINER}/${PDB})"
  run_assertions
  report_side_channel
  if [ "$FINDINGS" -ne 0 ]; then
    echo "FAIL verify_vpd_fixture: $FINDINGS finding(s)" >&2
    exit 1
  fi
  echo "PASS verify_vpd_fixture: restricted rows withheld on every read path"
}

main "$@"
