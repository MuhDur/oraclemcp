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
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SELFTEST=false
if [[ "${1:-}" == --self-test ]]; then
  SELFTEST=true
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
  if [[ -d .git ]]; then
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

if $SELFTEST; then
  run_selftest
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