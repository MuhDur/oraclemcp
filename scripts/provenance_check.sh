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

# ---------------------------------------------------------------------------
# Vendored third-party trees carry their provenance as DATA, not prose.
#
# A tree vendored with a `vendored-sample-schemas/v1` MANIFEST.json already
# records upstream repository, tag, commit, license, retrieval date, and a
# git-blob-sha1 per file. Copying nineteen of those rows into markdown would
# create a second register with nothing keeping the two in agreement, and the
# markdown copy has no hashes — so the duplicate would be strictly weaker than
# the thing it duplicates, and the first drift would be silent.
#
# So the manifest satisfies provenance for the files it covers, and in exchange
# this gate VERIFIES it: every listed file must hash to its recorded blob sha1.
# That is tamper-detection the register never had — the actual risk a provenance
# record exists to manage for third-party code. The manifest itself still needs
# a PROVENANCE.md row, so the prose register keeps pointing at the source of
# truth rather than losing sight of the tree.
#
# A file inside a vendored tree that the manifest does NOT list is not covered
# and still needs its own row: that is how something gets quietly added to a
# vendored directory.
# ---------------------------------------------------------------------------
command -v jq >/dev/null 2>&1 || { echo "provenance_check: missing required command: jq" >&2; exit 2; }

manifest_covered=""   # newline-separated paths proven by a verified manifest
manifest_failures=0

while IFS= read -r manifest; do
  [ -n "$manifest" ] || continue
  schema="$(jq -r '.schema // ""' "$manifest" 2>/dev/null || true)"
  case "$schema" in
    vendored-sample-schemas/v*) ;;
    *) continue ;;
  esac

  tree="$(dirname "$manifest")"
  algorithm="$(jq -r '.hash_algorithm // ""' "$manifest")"
  if [ "$algorithm" != "git-blob-sha1" ]; then
    echo "provenance_check: $manifest declares unsupported hash_algorithm '$algorithm'" >&2
    manifest_failures=$((manifest_failures + 1))
    continue
  fi
  for field in .upstream.repository .upstream.commit .upstream.license .retrieved_utc; do
    value="$(jq -r "$field // \"\"" "$manifest")"
    if [ -z "$value" ]; then
      echo "provenance_check: $manifest is missing $field" >&2
      manifest_failures=$((manifest_failures + 1))
    fi
  done

  covered_count=0
  while IFS=$'\t' read -r relative expected; do
    [ -n "$relative" ] || continue
    file="$tree/$relative"
    if [ ! -f "$file" ]; then
      echo "provenance_check: $manifest lists a file that is not present: $file" >&2
      manifest_failures=$((manifest_failures + 1))
      continue
    fi
    actual="$(git hash-object -- "$file")"
    if [ "$actual" != "$expected" ]; then
      echo "provenance_check: VENDORED FILE ALTERED since it was recorded: $file" >&2
      echo "  manifest ($manifest) records git-blob-sha1 $expected" >&2
      echo "  the committed bytes hash to                 $actual" >&2
      echo "  Vendored upstream code is never edited in place. Re-vendor from" >&2
      echo "  $(jq -r '.upstream.repository' "$manifest") and update the manifest," >&2
      echo "  or restore the recorded bytes." >&2
      manifest_failures=$((manifest_failures + 1))
      continue
    fi
    manifest_covered="$manifest_covered$file"$'\n'
    covered_count=$((covered_count + 1))
  done < <(jq -r '.files | to_entries[] | [.key, .value] | @tsv' "$manifest")

  echo "provenance_check: $manifest verified $covered_count vendored file(s) against recorded git-blob-sha1"
done < <( { git ls-files; git ls-files --others --exclude-standard; } \
  | grep -E "$SCOPE_RE" | grep -E '(^|/)MANIFEST\.json$' | sort -u )

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
  # Provenance recorded as verified data beats provenance recorded as prose.
  if printf '%s' "$manifest_covered" | grep -Fxq -- "$path"; then
    continue
  fi
  # Match the backtick-delimited path token so a short name cannot be a
  # substring of a longer registered path.
  if ! grep -Fq -- "\`$path\`" "$REGISTER"; then
    echo "provenance_check: MISSING provenance entry for: $path" >&2
    missing=$((missing + 1))
  fi
done <<< "$artifacts"

if [ "$manifest_failures" -ne 0 ]; then
  echo "provenance_check: $manifest_failures vendored-manifest problem(s); see above." >&2
  exit 1
fi

if [ "$missing" -ne 0 ]; then
  echo "provenance_check: $missing of $total in-scope artifact(s) lack a $REGISTER entry." >&2
  echo "Add each to the register (Artifact | Origin | Regenerate / source) and re-run." >&2
  exit 1
fi

verified="$(printf '%s' "$manifest_covered" | grep -c . || true)"
echo "provenance_check: all $total in-scope artifacts have provenance ($verified via a verified vendored manifest, the rest registered in $REGISTER)."
