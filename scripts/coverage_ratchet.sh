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
#   2. MUTATION floor: `scripts/mutation_safety_gate.sh check-report`
#      enforces the committed per-crate mutation kill-rate floor on the
#      safety crates. This is what makes leg 1 non-gameable: coverage proves
#      the changed code RAN; the mutation floor proves the tests ASSERT.
#
# Deliberately NOT a "total coverage never decreases" gate: that design is
# gamed by assertion-free tests that raise the global number while proving
# nothing (§30.9-C / §32.2 TRI-1). The global per-crate numbers stay
# recorded and trend-watched in tests/coverage/BASELINE.json (bead D1),
# never hard-gated. Scope caveat, stated exactly: the per-crate mutation
# floor currently covers guard + audit (the committed
# docs/quality/mutation-safety.md seal); oraclemcp-db has NO committed
# mutation result yet -- extending the mutation lane to db (and
# core/dispatch) is §32.2 TRI-2 follow-up work, and this gate says so
# rather than pretending db is mutation-guarded.
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
#       changed lines, passes covered ones, and applies the safety floor.
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

die() { echo "coverage-ratchet: $*" >&2; exit 1; }

MODE="run"
BASE="${COVERAGE_RATCHET_BASE:-}"
case "${1:-run}" in
  run) shift || true ;;
  --check) MODE="check"; shift || true ;;
  --self-test) MODE="self-test"; shift || true ;;
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
  bash "$ROOT/scripts/mutation_safety_gate.sh" check-report
  echo "coverage-ratchet: NOTE oraclemcp-db has no committed mutation result yet" \
       "(mutation-lane extension to db/core/dispatch is §32.2 TRI-2 follow-up work" \
       "-- not silently claimed as covered here)."
}

case "$MODE" in
  self-test)
    exec python3 "$ROOT/scripts/coverage_ratchet.py" self-test
    ;;
  check)
    python3 "$ROOT/scripts/coverage_baseline.py" check --out-dir "$ROOT/tests/coverage"
    mutation_floor_leg
    echo "coverage-ratchet: OK (structural check: D1 baseline well-formed + mutation floor enforced;" \
         "the changed-line leg runs in 'run' mode against a PR diff)"
    exit 0
    ;;
esac

# ---- run mode -------------------------------------------------------------
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

git diff --no-color --no-ext-diff --unified=0 "$BASE" -- 'crates/*/src' >"$diff_file"

mapfile -t crates < <(
  git diff --name-only "$BASE" -- 'crates/*/src' |
    grep -E '^crates/[^/]+/src/.*\.rs$' |
    sed -E 's|^crates/([^/]+)/src/.*|\1|' |
    sort -u
)

if [ "${#crates[@]}" -eq 0 ]; then
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
fi

mutation_floor_leg
echo "coverage-ratchet: OK (changed-line leg + mutation floor)"
