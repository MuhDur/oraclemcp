#!/usr/bin/env bash
# oraclemcp sensitive-data lint.
#
# Fails if the working tree appears to contain secrets or deployment-specific
# identifiers that must never be committed to a public repository.
#
# Two layers:
#   1. Generic, publishable heuristics (private IPs, embedded URL credentials,
#      cloud access-key IDs, full PEM private-key blocks). These run everywhere,
#      including CI, and need no configuration.
#   2. An OPTIONAL site-specific denylist loaded from the file named by
#      $ORACLEMCP_SENSITIVE_DENYLIST_FILE (one extended-regex per line, '#'
#      comments allowed). Keep that file OUTSIDE this repository — it enumerates
#      the very strings you are trying to keep out, so it must not be committed.
#      Wire it into a local pre-push hook so a leak is caught before it reaches
#      the remote.
#
# A line may opt out of a match with a trailing `sensitive-lint:allow` marker
# (use sparingly, only for deliberate test fixtures / placeholders).
#
# Exit 0 = clean. Exit 1 = a suspected leak (printed). Exit 2 = usage error.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  mapfile -t FILES < <(git ls-files)
else
  mapfile -t FILES < <(find . -type f -not -path './target/*' -not -path './.git/*')
fi
[ "${#FILES[@]}" -gt 0 ] || { echo "sensitive-data-lint: no files to scan" >&2; exit 0; }

# Generic, safe-to-publish patterns. High-confidence only: private IPs and
# loopback are deliberately NOT flagged (they are legitimate in transport code,
# tests, and examples) — site-specific hostnames/IPs belong in the external
# denylist instead, which is where the real deployment-leak protection lives.
GENERIC_PATTERNS=(
  '[a-zA-Z][a-zA-Z0-9+.-]*://[^/[:space:]:@"]+:[^/[:space:]@"]+@'  # url with embedded user:password
  '\bAKIA[0-9A-Z]{16}\b'                                     # AWS access key id
  '-----BEGIN [A-Z ]*PRIVATE KEY-----[A-Za-z0-9+/=[:space:]]{40,}'  # real PEM private-key block
)

hits=0
report() { echo "SENSITIVE-DATA LEAK SUSPECTED ($1):" >&2; echo "  $2" >&2; hits=$((hits + 1)); }

scan_pattern() {
  local pat="$1"
  # -I skips binary files; -n gives line numbers; -E extended regex.
  grep -InE "$pat" "${FILES[@]}" 2>/dev/null | grep -v 'sensitive-lint:allow' | while IFS= read -r line; do
    printf '%s\n' "$line"
  done
}

for pat in "${GENERIC_PATTERNS[@]}"; do
  while IFS= read -r line; do
    [ -n "$line" ] && report "generic" "$line"
  done < <(scan_pattern "$pat")
done

DENYLIST="${ORACLEMCP_SENSITIVE_DENYLIST_FILE:-}"
if [ -n "$DENYLIST" ]; then
  [ -f "$DENYLIST" ] || { echo "sensitive-data-lint: denylist file not found: $DENYLIST" >&2; exit 2; }
  while IFS= read -r raw; do
    pat="${raw%%#*}"
    pat="${pat%"${pat##*[![:space:]]}"}"
    [ -z "$pat" ] && continue
    while IFS= read -r line; do
      [ -n "$line" ] && report "site-denylist" "$line"
    done < <(scan_pattern "$pat")
  done < "$DENYLIST"
else
  echo "sensitive-data-lint: note — \$ORACLEMCP_SENSITIVE_DENYLIST_FILE not set; running generic heuristics only." >&2
fi

if [ "$hits" -ne 0 ]; then
  echo "" >&2
  echo "sensitive-data-lint: $hits suspected leak(s); refusing. Remove the data or annotate a deliberate fixture with 'sensitive-lint:allow'." >&2
  exit 1
fi
echo "sensitive-data-lint: clean (${#FILES[@]} files scanned)."
