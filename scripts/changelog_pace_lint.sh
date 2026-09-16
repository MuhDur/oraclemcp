#!/usr/bin/env bash
# changelog-pace lint (bead oraclemcp-2q4em.2.2).
#
# Keep-a-Changelog's [Unreleased] section is a contract, not a scratchpad: every
# commit that lands a user-visible change (feat/fix/security/perf) since the last
# release tag must be recorded under [Unreleased] before that release is cut.
# This gate fails when such commits exist and [Unreleased] carries no bullet,
# listing the pending subjects with their short SHAs so the missing release note
# is actionable. The changelog records user-facing changes collectively; it is
# not a per-commit ledger.
#
# Contract:
#   * range   = <most-recent-tag>..HEAD (tag discovered with `git describe`)
#   * subject = a commit subject matching ^(feat|fix|security|perf)(\(|:)
#   * coverage = [Unreleased] has at least one non-empty bullet
#   * failure = matching commits exist AND [Unreleased] has no bullet
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

# Does [Unreleased] carry at least one bullet? Parsed with Python so CRLF line
# endings and bracket characters cannot fool the section scan.
#   exit 0 = at least one bullet, 1 = section present but empty,
#   exit 2 = no [Unreleased] section at all.
set +e
python3 - "$CHANGELOG" <<'PY'
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
    if re.match(r"^\s*-\s+\S", stripped):
        sys.exit(0)
sys.exit(1)
PY
bullet_status=$?
set -e

case "$bullet_status" in
  0)
    echo "changelog-pace: OK (feat/fix/security/perf commits since $last_tag are recorded under [Unreleased])"
    exit 0
    ;;
  1)
    count="$(printf '%s\n' "$offending" | grep -c .)"
    echo "changelog-pace: FAIL: $count feat/fix/security/perf commit(s) since $last_tag are not recorded under [Unreleased]:" >&2
    printf '%s\n' "$offending" | sed 's/^/  /' >&2
    exit 1
    ;;
  *)
    echo "changelog-pace: FAIL: CHANGELOG.md has no [Unreleased] section" >&2
    exit 1
    ;;
esac
