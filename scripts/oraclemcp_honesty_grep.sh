#!/usr/bin/env bash
# oraclemcp honesty-grep gate (bead F1a / plan §8 item 8).
#
# Fails if over-claiming / stale framing appears in RELEASE-VISIBLE text: the
# README, docs, package metadata (Cargo.toml descriptions), and shipped source
# doc-comments. oraclemcp is GOVERNED and least-privilege — a fail-closed SQL
# guard with an explicit, confirmation-gated operating-level ladder (read-only by
# default, escalation up to ADMIN within per-profile ceilings). It is NOT
# "safe-by-default", NOT a "read-only binary", and NOT "fully audited".
#
# Escape hatch: append a `honesty-allow: <reason>` marker to a line that
# legitimately needs a forbidden phrase (a historical note, a negative example).
set -euo pipefail
cd "$(dirname "$0")/.."

# Forbidden framing (case-insensitive). Keep this list aligned with the Rust
# guard test in crates/oraclemcp/tests/honesty_grep.rs.  honesty-allow: pattern definition
PATTERN='safe[- ]by[- ]default|read-only binary|fully audited'

# Release-visible surfaces. Test/fuzz sources and the planning doc are excluded
# (not shipped / discuss the framing on purpose).
mapfile -t FILES < <(
  git ls-files README.md docs crates \
    | grep -E '\.(md|rs|toml)$' \
    | grep -vE '/tests?/|tests\.rs$|/fuzz/'
)

violations=0
for f in "${FILES[@]}"; do
  [ -n "$f" ] || continue
  while IFS=: read -r line text; do
    case "$text" in
      *honesty-allow*) continue ;;
    esac
    printf 'FORBIDDEN framing  %s:%s:%s\n' "$f" "$line" "${text#"${text%%[![:space:]]*}"}"
    violations=$((violations + 1))
  done < <(grep -niE "$PATTERN" "$f" 2>/dev/null || true)
done

if [ "$violations" -gt 0 ]; then
  echo "oraclemcp-honesty-grep: FAIL — $violations over-claiming occurrence(s)."
  echo "Reframe to governed/least-privilege, or add a 'honesty-allow: <reason>' marker."
  exit 1
fi
echo "oraclemcp-honesty-grep: OK — no over-claiming framing in release-visible text."
