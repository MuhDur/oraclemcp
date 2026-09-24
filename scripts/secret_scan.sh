#!/usr/bin/env bash
# C4 release blocker: scan the tracked tree for confidential deployment identifiers.
#
# - Structural patterns (safe to publish) always run in CI.
# - Operator-specific literals live in a gitignored denylist (never committed).
# - Delegates to sensitive_data_lint.sh for rendered-surface + generic heuristics.
#
# Usage:
#   bash scripts/secret_scan.sh           # full scan (exit 1 on any hit)
#   bash scripts/secret_scan.sh --self-test  # verify the scanner trips on a planted marker
#   bash scripts/secret_scan.sh --deny-values-from FILE PATH...
#       scan artifacts a lane is about to persist against the structural
#       patterns plus the exact live values in FILE (one per line, runner-
#       private, never committed). Hits are reported by file:line only; the
#       matched value is never echoed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SELFTEST=false
DENY_VALUES_FILE=""
DENY_VALUES_PATHS=()
if [[ "${1:-}" == --self-test ]]; then
  SELFTEST=true
elif [[ "${1:-}" == --deny-values-from ]]; then
  [[ $# -ge 3 ]] || {
    echo "secret_scan: --deny-values-from needs FILE and at least one PATH" >&2
    exit 2
  }
  DENY_VALUES_FILE="$2"
  shift 2
  DENY_VALUES_PATHS=("$@")
fi

# Gitignored operator denylist (one regex per line; # comments allowed).
DEFAULT_DENYLIST="$ROOT/.secret_scan_denylist"
DENYLIST_FILE="${SECRET_SCAN_DENYLIST_FILE:-$DEFAULT_DENYLIST}"

# Publishable structural patterns (field-test shapes — no operator literals).
STRUCTURAL_PATTERNS=(
  'CN=[^[:space:]]*\.oraclecloud\.com'
  'ocid1\.[a-z0-9]+\.[a-z0-9-]+\.[a-z0-9]+\.'
  'todelete/todelete[0-9]'
  'todelete\\todelete[0-9]'
)

scan_paths() {
  # Self-test plants a scratch file and scans only that path (proves the gate fails).
  if [[ -n "${SECRET_SCAN_SELFTEST_PATH:-}" ]]; then
    printf '%s\0' "$SECRET_SCAN_SELFTEST_PATH"
    return
  fi
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git ls-files -z
  else
    find . -type f \
      ! -path './.git/*' \
      ! -path './target/*' \
      ! -path './node_modules/*' \
      ! -path './web/node_modules/*' \
      -print0
  fi
}

run_structural_and_denylist() {
  local hits=0
  local pattern path

  for pattern in "${STRUCTURAL_PATTERNS[@]}"; do
    while IFS= read -r -d '' path; do
      [[ -f "$path" ]] || continue
      if grep -nE -- "$pattern" "$path" >/dev/null 2>&1; then
        echo "secret_scan: structural match ($pattern) in $path" >&2
        grep -nE -- "$pattern" "$path" | head -5 >&2 || true
        hits=$((hits + 1))
      fi
    done < <(scan_paths)
  done

  if [[ -f "$DENYLIST_FILE" ]]; then
    while IFS= read -r pattern || [[ -n "$pattern" ]]; do
      pattern="${pattern%%#*}"
      pattern="${pattern#"${pattern%%[![:space:]]*}"}"
      pattern="${pattern%"${pattern##*[![:space:]]}"}}"
      [[ -z "$pattern" ]] && continue
      while IFS= read -r -d '' path; do
        [[ -f "$path" ]] || continue
        if grep -nE -- "$pattern" "$path" >/dev/null 2>&1; then
          echo "secret_scan: denylist match in $path (pattern from $DENYLIST_FILE)" >&2
          grep -nE -- "$pattern" "$path" | head -5 >&2 || true
          hits=$((hits + 1))
        fi
      done < <(scan_paths)
    done < "$DENYLIST_FILE"
  fi

  return "$hits"
}

run_selftest() {
  local scratch
  scratch="$(mktemp)"
  trap 'rm -f "$scratch"' RETURN
  # Must match a structural pattern without using a real confidential value.
  # Build the marker domain from parts so this scanner's own committed source
  # does not itself self-match STRUCTURAL_PATTERNS (the marker is synthetic).
  local _mk_dom="oracle""cloud.com"
  printf '%s\n' "CN=scan-selftest.example.${_mk_dom}" >"$scratch"

  # Production path must FAIL when the planted marker is the only scanned file.
  SECRET_SCAN_SELFTEST_PATH="$scratch"
  if run_structural_and_denylist; then
    echo "secret_scan: self-test FAILED (scanner did not fail on planted marker)" >&2
    unset SECRET_SCAN_SELFTEST_PATH
    return 1
  fi
  unset SECRET_SCAN_SELFTEST_PATH
  echo "secret_scan: self-test OK (planted marker trips structural scan)" >&2
  return 0
}

# Scan PATH... (files or directories) for the structural patterns and for every
# exact value (>= 6 chars) in the deny file. Fails closed on an unreadable deny
# file or a missing path. Reports only file:line so a hit never re-leaks.
run_deny_values_scan() {
  local deny_file="$1"
  shift
  local hits=0 path pattern values lines
  [[ -r "$deny_file" ]] || {
    echo "secret_scan: deny-values file is not readable" >&2
    return 1
  }
  values="$(mktemp)"
  awk 'length($0) >= 6' "$deny_file" | sort -u >"$values"
  for path in "$@"; do
    [[ -e "$path" ]] || {
      echo "secret_scan: artifact path does not exist: $path" >&2
      hits=$((hits + 1))
      continue
    }
    for pattern in "${STRUCTURAL_PATTERNS[@]}"; do
      lines="$(grep -rnE -- "$pattern" "$path" | cut -d: -f1,2 | head -5 || true)"
      if [[ -n "$lines" ]]; then
        echo "secret_scan: structural match in: ${lines//$'\n'/ }" >&2
        hits=$((hits + 1))
      fi
    done
    if [[ -s "$values" ]]; then
      lines="$(grep -rnF -f "$values" -- "$path" | cut -d: -f1,2 | head -5 || true)"
      if [[ -n "$lines" ]]; then
        echo "secret_scan: live deny-value match in: ${lines//$'\n'/ }" >&2
        hits=$((hits + 1))
      fi
    fi
  done
  rm -f "$values"
  if [[ "$hits" -gt 0 ]]; then
    echo "secret_scan: FAIL (artifact contains live identifiers; do not persist it)" >&2
    return 1
  fi
  echo "secret_scan: OK (artifacts free of structural patterns and deny values)"
}

# oci_confidentiality_deny_values: a planted synthetic deny value must fail the
# artifact scan without being echoed; the clean synthetic artifact must pass.
run_deny_values_selftest() {
  local scratch planted="omcp-synthetic-deny-value-7f3a" output
  scratch="$(mktemp -d)"
  printf '%s\n' "$planted" "short" >"$scratch/deny"
  printf '{"db_version":"23ai","note":"prefix %s suffix"}\n' "$planted" >"$scratch/dirty.json"
  printf '{"db_version":"23ai","note":"synthetic clean result"}\n' >"$scratch/clean.json"
  printf 'the word short alone is below the exact-match floor\n' >"$scratch/short.txt"
  local ok=true
  if output="$(run_deny_values_scan "$scratch/deny" "$scratch/dirty.json" 2>&1)"; then
    echo "secret_scan: oci_confidentiality_deny_values FAILED (planted deny value passed)" >&2
    ok=false
  elif [[ "$output" == *"$planted"* ]]; then
    echo "secret_scan: oci_confidentiality_deny_values FAILED (scan output echoed the value)" >&2
    ok=false
  fi
  if ! run_deny_values_scan "$scratch/deny" "$scratch/clean.json" "$scratch/short.txt" >/dev/null 2>&1; then
    echo "secret_scan: oci_confidentiality_deny_values FAILED (clean artifact rejected)" >&2
    ok=false
  fi
  if run_deny_values_scan "$scratch/missing-deny" "$scratch/clean.json" >/dev/null 2>&1; then
    echo "secret_scan: oci_confidentiality_deny_values FAILED (missing deny file passed)" >&2
    ok=false
  fi
  rm -rf "$scratch"
  $ok || return 1
  echo "secret_scan: self-test OK (oci_confidentiality_deny_values)" >&2
}

if $SELFTEST; then
  run_selftest && run_deny_values_selftest
  exit $?
fi

if [[ -n "$DENY_VALUES_FILE" ]]; then
  run_deny_values_scan "$DENY_VALUES_FILE" "${DENY_VALUES_PATHS[@]}"
  exit $?
fi

hits=0
run_structural_and_denylist
r=$?
[[ $r -ne 0 ]] && hits=$((hits + r))

# Rendered surfaces + generic heuristics (existing gate).
if ! bash "$ROOT/scripts/sensitive_data_lint.sh"; then
  hits=$((hits + 1))
fi

if [[ "$hits" -gt 0 ]]; then
  echo "secret_scan: FAIL ($hits issue class(es))" >&2
  echo "Add operator literals only to $DEFAULT_DENYLIST (gitignored), never to the repo." >&2
  exit 1
fi

echo "secret_scan: OK (tracked tree + rendered surfaces)"
