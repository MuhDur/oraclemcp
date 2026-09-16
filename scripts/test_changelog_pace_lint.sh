#!/usr/bin/env bash
# Contract tests for scripts/changelog_pace_lint.sh (bead oraclemcp-2q4em.2.3).
#
# Each case builds a throwaway git repo (no network) and drives the real lint
# through CHANGELOG_REPO_DIR, printing the case id and expected/actual exit.
#
#   (a) feat + fix commits, empty [Unreleased]       -> exit 1, subjects listed
#   (b) chore/test-only commits, empty [Unreleased]  -> exit 0
#   (c) populated [Unreleased]                       -> exit 0
#   (d) no tag yet                                   -> typed skip, exit 0
#   (e) CRLF changelog + bracketed subject           -> parse-safe (1, then 0)
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

# --- (c) populated [Unreleased] -> exit 0 -------------------------------------
c="$workdir/c"
init_repo "$c"
seed_changelog "$c" "- Add a widget."
commit_file "$c" .seed "seed" "chore: seed changelog"
git -C "$c" tag v0.0.1
commit_file "$c" feat.txt "1" "feat: add widget"
run_lint "$c"
report_case c 0
[ "$CASE_CODE" -eq 0 ] || fail_case c "a populated [Unreleased] must pass"

# --- (d) no tag yet -> typed skip, exit 0 -------------------------------------
d="$workdir/d"
init_repo "$d"
seed_changelog "$d" ""
commit_file "$d" .seed "seed" "chore: seed changelog"
commit_file "$d" feat.txt "1" "feat: untagged work"
run_lint "$d"
report_case d 0
[ "$CASE_CODE" -eq 0 ] || fail_case d "an untagged repo must skip, not fail"
printf '%s' "$CASE_OUT" | grep -Fq "skip (no-tag)" || fail_case d "typed skip message missing"

# --- (e) CRLF changelog + bracketed subject -> parse-safe ---------------------
e="$workdir/e"
init_repo "$e"
printf '# Changelog\r\n\r\n## [Unreleased]\r\n\r\n## [0.0.1]\r\n' > "$e/CHANGELOG.md"
git -C "$e" add -A
git -C "$e" commit -q -m "chore: seed changelog"
git -C "$e" tag v0.0.1
commit_file "$e" fix.txt "1" "fix(ci): handle [bracketed] path"
run_lint "$e"
report_case e 1
[ "$CASE_CODE" -eq 1 ] || fail_case e "a CRLF empty [Unreleased] must still fail"
printf '%s' "$CASE_OUT" | grep -Fq "fix(ci): handle [bracketed] path" ||
  fail_case e "bracketed subject not listed"

# populated CRLF variant (working-tree edit only) -> exit 0
printf '# Changelog\r\n\r\n## [Unreleased]\r\n\r\n- Handle bracketed paths.\r\n\r\n## [0.0.1]\r\n' > "$e/CHANGELOG.md"
run_lint "$e"
report_case e-populated 0
[ "$CASE_CODE" -eq 0 ] || fail_case e-populated "a CRLF populated [Unreleased] must pass"

echo "changelog-pace test: all cases OK ($workdir)"
