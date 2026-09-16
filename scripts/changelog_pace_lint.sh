#!/usr/bin/env bash
# changelog-pace lint (bead oraclemcp-2q4em.2.2).
#
# Keep-a-Changelog's [Unreleased] section is a contract, not a scratchpad: every
# commit that lands a user-visible change (feat/fix/security/perf) since the last
# release tag must be recorded under [Unreleased] before that release is cut.
# This gate fails when such commits have no matching commit link under
# [Unreleased], listing each unrecorded subject with its short SHA so the fix is
# mechanical. A generic bullet is not enough: it could describe an unrelated
# change and must not vouch for every later user-visible commit.
#
# Contract:
#   * range   = <most-recent-tag>..HEAD (tag discovered with `git describe`)
#   * subject = a commit subject matching ^(feat|fix|security|perf)(\(|:)
#   * coverage = every matching short SHA occurs in an [Unreleased] commit link
#   * failure = any matching commit has no such link
#   * typed skip (exit 0) when no tag is reachable: there is no pace to measure
#
# Env overrides (used by scripts/test_changelog_pace_lint.sh):
#   CHANGELOG_REPO_DIR  repo whose history is judged (default: this checkout)
#   CHANGELOG_PATH      changelog file read for [Unreleased]
set -euo pipefail

DEFAULT_REPO="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
REPO_DIR="${CHANGELOG_REPO_DIR:-$DEFAULT_REPO}"
CHANGELOG="${CHANGELOG_PATH:-$REPO_DIR/CHANGELOG.md}"

if [ ! -f "$CHANGELOG" ]; then
  echo "changelog-pace: FAIL: no CHANGELOG.md at $CHANGELOG" >&2
  exit 1
fi

# The most recent release tag reachable from HEAD. With no tag there is no
# release to pace against; that is a typed skip, not a pass we can vouch for.
if ! last_tag="$(git -C "$REPO_DIR" describe --tags --abbrev=0 2>/dev/null)"; then
  echo "changelog-pace: skip (no-tag): no reachable release tag; nothing to pace against"
  exit 0
fi

# Every commit since the tag whose subject declares a user-visible change.
# `%h<TAB>%s` is CR-stripped so a stray CRLF cannot hide a matching subject, and a
# subject containing `[` or `]` is data, never a regex fragment, so it cannot
# break the scan.
offending="$(
  git -C "$REPO_DIR" log "${last_tag}..HEAD" --pretty=format:'%h%x09%s' \
    | tr -d '\r' \
    | grep -E '^[0-9a-f]+[[:space:]]+(feat|fix|security|perf)(\(|:)' \
    || true
)"

if [ -z "$offending" ]; then
  echo "changelog-pace: OK (no feat/fix/security/perf commits since $last_tag)"
  exit 0
fi

# Extract [Unreleased] with Python so CRLF line endings and bracket characters
# cannot fool the section scan. The body is then checked below for a commit link
# for each visible commit. Exit 2 means no [Unreleased] section exists.
set +e
unreleased="$(python3 - "$CHANGELOG" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8", newline="").read()
lines = text.splitlines()

start = None
for index, line in enumerate(lines):
    if re.match(r"^##\s+\[Unreleased\]\s*$", line.rstrip("\r")):
        start = index + 1
        break
if start is None:
    sys.exit(2)

for line in lines[start:]:
    stripped = line.rstrip("\r")
    if stripped.startswith("## "):
        break
    print(stripped)
PY
)"
unreleased_status=$?
set -e

if [ "$unreleased_status" -ne 0 ]; then
  echo "changelog-pace: FAIL: CHANGELOG.md has no [Unreleased] section" >&2
  exit 1
fi

unrecorded=""
while IFS=$'\t' read -r short_sha subject; do
  [ -n "$short_sha" ] || continue
  # A `.../commit/<short-sha>` link explicitly binds the entry to this landed
  # change. Full SHAs also match because they begin with the short SHA.
  if ! printf '%s\n' "$unreleased" | grep -Fq "/commit/$short_sha"; then
    unrecorded+="$short_sha $subject"$'\n'
  fi
done <<< "$offending"

if [ -n "$unrecorded" ]; then
  count="$(printf '%s' "$unrecorded" | grep -c .)"
  echo "changelog-pace: FAIL: $count feat/fix/security/perf commit(s) since $last_tag lack an [Unreleased] commit link:" >&2
  printf '%s' "$unrecorded" | sed 's/^/  /' >&2
  exit 1
fi

echo "changelog-pace: OK (each feat/fix/security/perf commit since $last_tag has an [Unreleased] commit link)"
