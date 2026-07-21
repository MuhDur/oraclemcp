#!/usr/bin/env bash
# D2 -- the coverage ratchet gate (bead oraclemcp-eng-program-bp8ia.5.2,
# plan §30.2 item 2, reconciled with §32.2 TRI-1; builds ON the D1 baseline
# in tests/coverage/BASELINE.{json,md} -- see docs/test-tiers.md §6/§7).
#
# TWO legs, both must pass:
#
#   1. CHANGED-LINE coverage: the added/changed lines of the diff (vs a base
#      ref) inside crates/<crate>/src/*.rs must be exercised by the affected
#      crates' own test suites, measured with a SCOPED
#      `cargo llvm-cov -p <crate>... --lcov` run (instrumented; only the
#      crates the diff touches are built and tested, never the whole
#      workspace per PR). Floors: 80% default, 90% for the safety crates
#      (guard/audit/db). Evaluation logic + fixtures live in
#      scripts/coverage_ratchet.py.
#   2. MUTATION floor: `scripts/mutation_safety_gate.sh check-floor-report`
#      enforces independent committed mutation kill-rate floors on guard,
#      audit, and db. This is what makes leg 1 non-gameable: coverage proves
#      the changed code RAN; the mutation floor proves the tests ASSERT.
#
# Deliberately NOT a "total coverage never decreases" gate: that design is
# gamed by assertion-free tests that raise the global number while proving
# nothing (§30.9-C / §32.2 TRI-1). The global per-crate numbers stay
# recorded and trend-watched in tests/coverage/BASELINE.json (bead D1),
# never hard-gated. Scope caveat, stated exactly: the per-crate mutation
# floor is sealed independently in docs/quality/mutation-safety-d2.md for
# guard + audit + db. D3's broader guard/audit/core/db/dispatch seal remains a
# separate contract; D2 never claims those extra scopes.
#
# Modes:
#   scripts/coverage_ratchet.sh run [--base <ref>]
#       The PR-time gate. Base defaults to $COVERAGE_RATCHET_BASE, else
#       merge-base of HEAD and origin/main. Diffs the working tree against
#       the base, runs scoped instrumented coverage for the affected
#       crates, evaluates changed-line coverage, then checks the mutation
#       floor. Heavy-ish (instrumented build of the touched crates only).
#   scripts/coverage_ratchet.sh --check
#       Cheap structural leg for non-PR contexts: validates the committed
#       D1 baseline and enforces the mutation floor. No coverage run.
#   scripts/coverage_ratchet.sh --self-test
#       Offline fixture matrix proving the evaluator fails uncovered
#       changed lines, passes covered ones, and applies the safety floor,
#       plus the per-leg status -> attestation-outcome mapping below.
#   scripts/coverage_ratchet.sh attestation-outcomes
#       Print the NAME=PASS|SKIP lines describing what the last run in this
#       workspace ACTUALLY enforced, read from the status file.
#
# Per-leg status (COVERAGE_RATCHET_STATUS_FILE, default
# target/coverage-ratchet-status.env). A leg that did not run must not be
# attested as PASS: the mutation floor is advisory this train (operator ruling
# 2026-07-21, plan v8 §Z2, ALLOW_STALE_MUTATION_SEAL), so it reports `deferred`
# and attests SKIP until the RC seal (bead oraclemcp-091-rc-mutation-seal-5aqwf)
# makes it enforcing. A leg that FAILS never reaches the status file: the gate
# exits non-zero first.
#
# Prerequisites for `run`: cargo-llvm-cov + the llvm-tools rustup component
# (same as scripts/coverage_baseline.sh; fails closed with the install
# commands). Resource discipline: the instrumented build is wrapped in a
# systemd --user memory scope (COVERAGE_RATCHET_MEMMAX, default 32G) when
# available and honours CARGO_BUILD_JOBS.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FLOOR="${COVERAGE_RATCHET_FLOOR:-80}"
SAFETY_FLOOR="${COVERAGE_RATCHET_SAFETY_FLOOR:-90}"
MEMMAX="${COVERAGE_RATCHET_MEMMAX:-32G}"
STATUS_FILE="${COVERAGE_RATCHET_STATUS_FILE:-$ROOT/target/coverage-ratchet-status.env}"
SRC_PATHSPEC='crates/*/src/*'

CHANGED_LINE_STATUS=not-run
MUTATION_FLOOR_STATUS=not-run

die() { echo "coverage-ratchet: $*" >&2; exit 1; }

write_status() {
  mkdir -p "$(dirname "$STATUS_FILE")"
  {
    printf 'changed_line=%s\n' "$CHANGED_LINE_STATUS"
    printf 'mutation_floor=%s\n' "$MUTATION_FLOOR_STATUS"
  } >"$STATUS_FILE"
}

# enforced -> PASS; anything that did not actually run -> SKIP. A failing leg
# never gets here.
outcome_for() {
  case "$1" in
    enforced) printf 'PASS\n' ;;
    *) printf 'SKIP\n' ;;
  esac
}

attestation_outcomes() {
  [ -f "$STATUS_FILE" ] ||
    die "no status file at $STATUS_FILE; run the gate before deriving attestation outcomes"
  local changed_line mutation_floor
  changed_line="$(sed -n 's/^changed_line=//p' "$STATUS_FILE" | tail -1)"
  mutation_floor="$(sed -n 's/^mutation_floor=//p' "$STATUS_FILE" | tail -1)"
  [ -n "$changed_line" ] && [ -n "$mutation_floor" ] ||
    die "status file $STATUS_FILE is missing a leg"
  printf 'coverage-ratchet:changed-line-floor=%s\n' "$(outcome_for "$changed_line")"
  printf 'coverage-ratchet:mutation-floor=%s\n' "$(outcome_for "$mutation_floor")"
}

MODE="run"
BASE="${COVERAGE_RATCHET_BASE:-}"
case "${1:-run}" in
  run) shift || true ;;
  --check) MODE="check"; shift || true ;;
  --self-test) MODE="self-test"; shift || true ;;
  attestation-outcomes) MODE="attestation-outcomes"; shift || true ;;
  -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  --base) MODE="run" ;; # fall through to the argument loop below
  *) die "unknown argument: $1" ;;
esac
while [ "$#" -gt 0 ]; do
  case "$1" in
    --base) BASE="$2"; shift ;;
    *) die "unknown argument: $1" ;;
  esac
  shift
done

mutation_floor_leg() {
  echo "coverage-ratchet: mutation-floor leg (per-crate kill-rate floor on the safety crates):"
  local output
  # The gate is the single source of truth for whether this leg was enforced
  # or deferred; duplicating the ALLOW_STALE_MUTATION_SEAL condition here is
  # how the two would drift apart.
  output="$(bash "$ROOT/scripts/mutation_safety_gate.sh" check-floor-report 2>&1)" || {
    printf '%s\n' "$output" >&2
    return 1
  }
  printf '%s\n' "$output"
  MUTATION_FLOOR_STATUS="$(
    printf '%s\n' "$output" | sed -n 's/.*STATUS mutation-floor=//p' | tail -1
  )"
  [ -n "$MUTATION_FLOOR_STATUS" ] ||
    die "the mutation gate reported no STATUS mutation-floor token; refusing to guess whether the leg ran"
}

# The bug this pins: `crates/*/src` selected NOTHING (a pathspec with a wildcard
# must match the whole path, and no file under src/ equals `crates/<x>/src`), so
# every run took the "no changed crates" branch and the leg was decorative while
# reporting green. A gate that cannot see a diff is worse than no gate.
self_test_pathspec() {
  local work selected
  work="$(mktemp -d)"
  # shellcheck disable=SC2064 # expand $work now, not when the trap fires
  trap "rm -rf '$work'" RETURN
  git -C "$work" init -q
  git -C "$work" config user.email selftest@example.invalid
  git -C "$work" config user.name selftest
  mkdir -p "$work/crates/demo/src" "$work/crates/demo/tests"
  printf 'pub fn a() -> u8 { 1 }\n' >"$work/crates/demo/src/lib.rs"
  printf 'fn t() {}\n' >"$work/crates/demo/tests/it.rs"
  git -C "$work" add -A
  git -C "$work" commit -qm base
  printf 'pub fn b() -> u8 { 2 }\n' >>"$work/crates/demo/src/lib.rs"
  printf 'fn u() {}\n' >>"$work/crates/demo/tests/it.rs"

  selected="$(git -C "$work" diff --name-only HEAD -- "$SRC_PATHSPEC")"
  [ "$selected" = "crates/demo/src/lib.rs" ] ||
    die "self-test: the source pathspec '$SRC_PATHSPEC' selected [$selected], not the changed crate source"
  # and the shape that was broken must still be recognisably broken, so a
  # future "simplification" back to it cannot pass this test.
  [ -z "$(git -C "$work" diff --name-only HEAD -- 'crates/*/src')" ] ||
    die "self-test: 'crates/*/src' now selects files; re-derive the pathspec contract before trusting it"
  echo "coverage-ratchet: self-test OK (source pathspec selects changed crates/<crate>/src files and excludes tests/)"
}

# Proves the mapping in both directions: a deferred leg must never attest PASS,
# and an enforced leg must not be understated as SKIP.
self_test_status_mapping() {
  local work expected actual
  work="$(mktemp -d)"
  # shellcheck disable=SC2064 # expand $work now; the trap must not depend on it later
  trap "rm -rf '$work'" RETURN

  printf 'changed_line=enforced\nmutation_floor=deferred\n' >"$work/status.env"
  expected='coverage-ratchet:changed-line-floor=PASS
coverage-ratchet:mutation-floor=SKIP'
  actual="$(COVERAGE_RATCHET_STATUS_FILE="$work/status.env" bash "$0" attestation-outcomes)"
  [ "$actual" = "$expected" ] ||
    die "self-test: a deferred mutation floor did not attest SKIP; got: $actual"

  printf 'changed_line=enforced\nmutation_floor=enforced\n' >"$work/status.env"
  expected='coverage-ratchet:changed-line-floor=PASS
coverage-ratchet:mutation-floor=PASS'
  actual="$(COVERAGE_RATCHET_STATUS_FILE="$work/status.env" bash "$0" attestation-outcomes)"
  [ "$actual" = "$expected" ] ||
    die "self-test: an enforced mutation floor was understated; got: $actual"

  printf 'changed_line=no-changed-lines\nmutation_floor=enforced\n' >"$work/status.env"
  actual="$(COVERAGE_RATCHET_STATUS_FILE="$work/status.env" bash "$0" attestation-outcomes)"
  [ "${actual%%$'\n'*}" = 'coverage-ratchet:changed-line-floor=SKIP' ] ||
    die "self-test: a diff with no changed lines was attested PASS; got: $actual"

  if COVERAGE_RATCHET_STATUS_FILE="$work/absent.env" bash "$0" attestation-outcomes >/dev/null 2>&1; then
    die "self-test: attestation outcomes were derived without a status file"
  fi
  echo "coverage-ratchet: self-test OK (leg status -> attestation outcome; deferred attests SKIP, absent status fails closed)"
}

case "$MODE" in
  self-test)
    python3 "$ROOT/scripts/coverage_ratchet.py" self-test
    self_test_pathspec
    self_test_status_mapping
    exit 0
    ;;
  attestation-outcomes)
    attestation_outcomes
    exit 0
    ;;
  check)
    python3 "$ROOT/scripts/coverage_baseline.py" check --out-dir "$ROOT/tests/coverage"
    CHANGED_LINE_STATUS=not-run   # --check never diffs; only 'run' enforces it
    mutation_floor_leg
    write_status
    echo "coverage-ratchet: OK (structural check: D1 baseline well-formed;" \
         "mutation floor $MUTATION_FLOOR_STATUS; the changed-line leg runs in 'run' mode against a PR diff)"
    exit 0
    ;;
esac

# ---- run mode -------------------------------------------------------------
# A push event's `before` SHA is all zeros for a new branch (and a rewritten
# ref can name a commit this checkout no longer has). Falling back to the
# merge-base keeps the gate measuring a real diff instead of going red for a
# reason that has nothing to do with coverage.
if [ -n "$BASE" ] && ! git rev-parse --verify --quiet "$BASE^{commit}" >/dev/null; then
  echo "coverage-ratchet: base ref '$BASE' does not resolve here; falling back to the merge-base" >&2
  BASE=""
fi
if [ -z "$BASE" ]; then
  BASE="$(git merge-base HEAD origin/main 2>/dev/null || true)"
  [ -n "$BASE" ] || BASE="$(git merge-base HEAD main 2>/dev/null || true)"
  [ -n "$BASE" ] || die "cannot determine a base ref (no origin/main or main); pass --base <ref>"
fi
git rev-parse --verify --quiet "$BASE^{commit}" >/dev/null || die "base ref does not resolve: $BASE"
echo "coverage-ratchet: base=$BASE floor=${FLOOR}% safety-floor=${SAFETY_FLOOR}%"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
diff_file="$tmpdir/changed.diff"
lcov_file="$tmpdir/coverage.lcov"

# Pathspec, exactly: `crates/*/src` matches a path that IS `crates/<x>/src`,
# never a file under it, so it selected NOTHING and the leg reported "trivially
# green" on every change ever measured. Keep the trailing `/*` and keep the
# self-test that would have caught it.
git diff --no-color --no-ext-diff --unified=0 "$BASE" -- "$SRC_PATHSPEC" >"$diff_file"

mapfile -t crates < <(
  git diff --name-only "$BASE" -- "$SRC_PATHSPEC" |
    grep -E '^crates/[^/]+/src/.*\.rs$' |
    sed -E 's|^crates/([^/]+)/src/.*|\1|' |
    sort -u
)

if [ "${#crates[@]}" -eq 0 ]; then
  CHANGED_LINE_STATUS=no-changed-lines
  echo "coverage-ratchet: no changed crates/<crate>/src/*.rs lines vs $BASE -- changed-line leg trivially green"
else
  command -v cargo-llvm-cov >/dev/null 2>&1 || die "cargo-llvm-cov is not installed.
Install it (and the llvm-tools component for the pinned toolchain) with:
  cargo install cargo-llvm-cov
  rustup component add llvm-tools --toolchain nightly-2026-05-11"

  PKG_ARGS=()
  for crate in "${crates[@]}"; do
    PKG_ARGS+=(-p "$crate")
  done

  # Memory-cap wrapper (transient user scope); loud fallback when the user
  # systemd instance is unavailable. Same pattern as mutation_safety_gate.sh.
  MEMCAP=()
  if systemd-run --user --scope -q -p MemoryMax=64M -p MemorySwapMax=0 -- true 2>/dev/null; then
    MEMCAP=(systemd-run --user --scope -q -p "MemoryMax=$MEMMAX" -p MemorySwapMax=0 --)
  else
    echo "coverage-ratchet: WARNING -- no systemd --user cgroup cap available; running the instrumented build UNCAPPED" >&2
  fi

  echo "coverage-ratchet: scoped instrumented run: cargo llvm-cov ${PKG_ARGS[*]} --locked --lcov" >&2
  "${MEMCAP[@]}" cargo llvm-cov "${PKG_ARGS[@]}" --locked --lcov --output-path "$lcov_file"

  python3 "$ROOT/scripts/coverage_ratchet.py" evaluate \
    --diff "$diff_file" \
    --lcov "$lcov_file" \
    --floor "$FLOOR" \
    --safety-floor "$SAFETY_FLOOR"
  CHANGED_LINE_STATUS=enforced
fi

mutation_floor_leg
write_status
echo "coverage-ratchet: OK (changed-line=$CHANGED_LINE_STATUS mutation-floor=$MUTATION_FLOOR_STATUS)"
if [ "$MUTATION_FLOOR_STATUS" != enforced ]; then
  echo "coverage-ratchet: NOTE the mutation-floor leg was $MUTATION_FLOOR_STATUS, not enforced." \
       "This lane attests it SKIP, never PASS (bead oraclemcp-091-rc-mutation-seal-5aqwf)." >&2
fi
