#!/usr/bin/env bash
# Contract tests for scripts/changelog_pace_lint.sh (bead oraclemcp-2q4em.2.3).
#
# Each case builds a throwaway git repo (no network) and drives the real lint
# through CHANGELOG_REPO_DIR, printing the case id and expected/actual exit.
#
#   (a) feat + fix commits, empty [Unreleased]       -> exit 1, subjects listed
#   (b) chore/test-only commits, empty [Unreleased]  -> exit 0
#   (c) each visible commit linked under [Unreleased] -> exit 0
#   (d) one of two visible commits linked             -> exit 1
#   (e) no tag yet                                    -> typed skip, exit 0
#   (f) CRLF changelog + bracketed subject            -> parse-safe (1, then 0)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LINT="$ROOT/scripts/changelog_pace_lint.sh"
workdir="$(mktemp -d /var/tmp/oraclemcp-changelog-pace.XXXXXX)"

CASE_OUT=""
CASE_CODE=0

init_repo() {
  local dir="$1"
  mkdir -p "$dir"
  git -c init.defaultBranch=main -C "$dir" init -q
  git -C "$dir" config user.name "changelog-pace-test"
  git -C "$dir" config user.email "changelog-pace-test@example.invalid"
  git -C "$dir" config commit.gpgsign false
  # Isolate from any host-level hooks (the swarm pre-commit guards).
  git -C "$dir" config core.hooksPath /dev/null
}

# seed_changelog <dir> <unreleased-body> writes a minimal Keep-a-Changelog file
# with an [Unreleased] section whose body is exactly <unreleased-body>.
seed_changelog() {
  local dir="$1" body="$2"
  printf '# Changelog\n\n## [Unreleased]\n%s\n## [0.0.1]\n' "$body" > "$dir/CHANGELOG.md"
}

# commit_file <dir> <relative-path> <content> <subject>.
commit_file() {
  local dir="$1" rel="$2" content="$3" subject="$4"
  printf '%s\n' "$content" > "$dir/$rel"
  git -C "$dir" add -A
  git -C "$dir" commit -q -m "$subject"
}

# run_lint <dir> drives the lint; sets CASE_OUT and CASE_CODE.
run_lint() {
  local dir="$1" out code
  set +e
  out="$(CHANGELOG_REPO_DIR="$dir" bash "$LINT" 2>&1)"
  code=$?
  set -e
  CASE_OUT="$out"
  CASE_CODE="$code"
}

report_case() {
  printf 'changelog-pace test: case %s expected=%s actual=%s\n' "$1" "$2" "$CASE_CODE"
}

fail_case() {
  printf 'changelog-pace test: case %s FAIL: %s\n' "$1" "$2" >&2
  printf '%s\n' "$CASE_OUT" >&2
  exit 1
}

# --- (a) feat/fix commits + empty [Unreleased] -> exit 1, subjects listed -----
a="$workdir/a"
init_repo "$a"
seed_changelog "$a" ""
commit_file "$a" .seed "seed" "chore: seed changelog"
git -C "$a" tag v0.0.1
commit_file "$a" feat.txt "1" "feat: add widget"
commit_file "$a" fix.txt "2" "fix(core): squash bug"
run_lint "$a"
report_case a 1
[ "$CASE_CODE" -eq 1 ] || fail_case a "expected exit 1"
printf '%s' "$CASE_OUT" | grep -Fq "feat: add widget" || fail_case a "subject 'feat: add widget' not listed"
printf '%s' "$CASE_OUT" | grep -Fq "fix(core): squash bug" || fail_case a "subject 'fix(core): squash bug' not listed"
a_sha="$(git -C "$a" rev-parse --short HEAD)"
printf '%s' "$CASE_OUT" | grep -Fq "$a_sha fix(core): squash bug" ||
  fail_case a "short SHA not paired with the subject"

# --- (b) chore/test-only commits + empty [Unreleased] -> exit 0 ---------------
b="$workdir/b"
init_repo "$b"
seed_changelog "$b" ""
commit_file "$b" .seed "seed" "chore: seed changelog"
git -C "$b" tag v0.0.1
commit_file "$b" chore.txt "1" "chore: tidy build"
commit_file "$b" test.txt "2" "test: cover widget"
run_lint "$b"
report_case b 0
[ "$CASE_CODE" -eq 0 ] || fail_case b "chore/test-only history must not be paced"

# --- (c) every visible commit linked under [Unreleased] -> exit 0 --------------
c="$workdir/c"
init_repo "$c"
seed_changelog "$c" ""
commit_file "$c" .seed "seed" "chore: seed changelog"
git -C "$c" tag v0.0.1
commit_file "$c" feat.txt "1" "feat: add widget"
feat_sha="$(git -C "$c" rev-parse --short HEAD)"
printf '# Changelog\n\n## [Unreleased]\n- Add a widget. See [commit](https://example.invalid/commit/%s).\n\n## [0.0.1]\n' "$feat_sha" > "$c/CHANGELOG.md"
run_lint "$c"
report_case c 0
[ "$CASE_CODE" -eq 0 ] || fail_case c "a matching [Unreleased] commit link must pass"

# --- (d) a generic/partial entry must not cover an unrelated commit -----------
d="$workdir/d"
init_repo "$d"
seed_changelog "$d" ""
commit_file "$d" .seed "seed" "chore: seed changelog"
git -C "$d" tag v0.0.1
commit_file "$d" feat.txt "1" "feat: add widget"
covered_sha="$(git -C "$d" rev-parse --short HEAD)"
commit_file "$d" fix.txt "2" "fix(core): squash bug"
missing_sha="$(git -C "$d" rev-parse --short HEAD)"
printf '# Changelog\n\n## [Unreleased]\n- Add a widget. See [commit](https://example.invalid/commit/%s).\n\n## [0.0.1]\n' "$covered_sha" > "$d/CHANGELOG.md"
run_lint "$d"
report_case d 1
[ "$CASE_CODE" -eq 1 ] || fail_case d "a partial commit-link set must fail"
printf '%s' "$CASE_OUT" | grep -Fq "$missing_sha fix(core): squash bug" ||
  fail_case d "the unlinked commit must be listed"
if printf '%s' "$CASE_OUT" | grep -Fq "$covered_sha feat: add widget"; then
  fail_case d "the linked commit must not be listed as unrecorded"
fi

# --- (e) no tag yet -> typed skip, exit 0 -------------------------------------
e="$workdir/e"
init_repo "$e"
seed_changelog "$e" ""
commit_file "$e" .seed "seed" "chore: seed changelog"
commit_file "$e" feat.txt "1" "feat: untagged work"
run_lint "$e"
report_case e 0
[ "$CASE_CODE" -eq 0 ] || fail_case e "an untagged repo must skip, not fail"
printf '%s' "$CASE_OUT" | grep -Fq "skip (no-tag)" || fail_case e "typed skip message missing"

# --- (f) CRLF changelog + bracketed subject -> parse-safe ---------------------
f="$workdir/f"
init_repo "$f"
printf '# Changelog\r\n\r\n## [Unreleased]\r\n\r\n## [0.0.1]\r\n' > "$f/CHANGELOG.md"
git -C "$f" add -A
git -C "$f" commit -q -m "chore: seed changelog"
git -C "$f" tag v0.0.1
commit_file "$f" fix.txt "1" "fix(ci): handle [bracketed] path"
run_lint "$f"
report_case f 1
[ "$CASE_CODE" -eq 1 ] || fail_case f "a CRLF empty [Unreleased] must still fail"
printf '%s' "$CASE_OUT" | grep -Fq "fix(ci): handle [bracketed] path" ||
  fail_case f "bracketed subject not listed"

# Complete CRLF variant (working-tree edit only) -> exit 0.
f_sha="$(git -C "$f" rev-parse --short HEAD)"
printf '# Changelog\r\n\r\n## [Unreleased]\r\n\r\n- Handle bracketed paths. See [commit](https://example.invalid/commit/%s).\r\n\r\n## [0.0.1]\r\n' "$f_sha" > "$f/CHANGELOG.md"
run_lint "$f"
report_case f-complete 0
[ "$CASE_CODE" -eq 0 ] || fail_case f-complete "a CRLF linked [Unreleased] entry must pass"

# The old any-bullet rule would have accepted the partial entry above; keep the
# distinction explicit so this cannot regress back to a single generic bullet.
if ! printf '%s' "$CASE_OUT" | grep -Fq 'each feat/fix/security/perf commit'; then
  fail_case f-complete "success output must state per-commit coverage"
fi

echo "changelog-pace test: all cases OK ($workdir)"
