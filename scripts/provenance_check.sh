#!/usr/bin/env bash
# Committed generated-artifact provenance gate (bead D6.3b / iec3.4.9).
#
# Enumerates every committed (and every untracked, non-ignored) generated
# artifact under the in-scope roots and FAILS if any lacks a verbatim entry in
# tests/conformance/PROVENANCE.md. This is what keeps a fixture/cassette/wallet
# from being regenerated later with no record of how it was originally made.
#
# In-scope roots: tests/golden/, tests/fixtures/, crates/*/tests/fixtures/,
# schemas/, ui/generated/. Out of scope: tests/artifacts/perf/ (self-describing
# performance-campaign evidence) and *.md / *.rs / *.actual support files.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
REGISTER="tests/conformance/PROVENANCE.md"

[ -f "$REGISTER" ] || { echo "provenance_check: missing register: $REGISTER" >&2; exit 2; }

SCOPE_RE='^(tests/golden/|tests/fixtures/|schemas/|ui/generated/|crates/[^/]+/tests/fixtures/)'
EXCLUDE_RE='(\.md|\.rs|\.actual)$'

# Tracked + untracked-but-not-ignored, so a planted (uncommitted) artifact is
# still caught before it can be committed without provenance.
artifacts="$( { git ls-files; git ls-files --others --exclude-standard; } \
  | grep -E "$SCOPE_RE" | grep -Ev "$EXCLUDE_RE" | sort -u )"

if [ -z "$artifacts" ]; then
  echo "provenance_check: no in-scope artifacts found (unexpected)" >&2
  exit 2
fi

missing=0
total=0
while IFS= read -r path; do
  [ -n "$path" ] || continue
  total=$((total + 1))
  # Match the backtick-delimited path token so a short name cannot be a
  # substring of a longer registered path.
  if ! grep -Fq -- "\`$path\`" "$REGISTER"; then
    echo "provenance_check: MISSING provenance entry for: $path" >&2
    missing=$((missing + 1))
  fi
done <<< "$artifacts"

if [ "$missing" -ne 0 ]; then
  echo "provenance_check: $missing of $total in-scope artifact(s) lack a $REGISTER entry." >&2
  echo "Add each to the register (Artifact | Origin | Regenerate / source) and re-run." >&2
  exit 1
fi

echo "provenance_check: all $total in-scope artifacts have a provenance entry in $REGISTER."
