#!/usr/bin/env bash
# Empirical cargo-llvm-cov coverage baseline (bead D1 / oraclemcp-eng-program-bp8ia.5.1).
#
# THIS IS THE FOUNDATION ONLY (docs/plan/PLAN_ENGINEERING_PROGRAM.md §30.2,
# §32.2 TRI-1): a reproducible line/region coverage measurement plus a
# committed baseline. There is NO ratchet, NO changed-line diff gate, and NO
# per-crate mutation floor here -- that ranking/gating logic is bead D2's
# job (plan §30.2 item 2: gate on changed-line coverage of the diff plus a
# named invariant/negative test for safety-critical crates, never a naive
# "coverage must never decrease" line, which rewards assertion-free tests).
# This script only answers "what does coverage measure RIGHT NOW",
# empirically, per crate -- see tests/coverage/BASELINE.md for the numbers.
#
# What is measured (read this before trusting a number in the baseline):
#   - LINE, REGION, and FUNCTION coverage from cargo-llvm-cov's raw JSON
#     export (`llvm-cov export -format=text`), aggregated per crate by
#     source path (crates/<crate>/src/...) plus a workspace TOTAL row.
#   - Default Cargo features only, matching the Tier 1 `cargo test
#     --workspace` lane (docs/test-tiers.md §3): the live-xe feature-gated
#     live-Oracle suites and the plsql-intelligence feature are OUT of scope
#     for this baseline. A live-xe / plsql-intelligence baseline is a
#     documented follow-up, not silently folded in here.
#   - cargo-llvm-cov already scopes its report to each workspace crate's own
#     `src/`: dependency source, integration-test files
#     (crates/*/tests/*.rs), and fuzz targets never appear in the raw
#     export, so this is source-line coverage, not "how much of the test
#     suite ran". Verified empirically against this workspace's own layout
#     (oraclemcp-config, which has a tests/ dir) before relying on it here.
#   - Doctests are excluded: `--doctests` is unstable in the pinned
#     cargo-llvm-cov (0.8.7) and slow; `cargo test --workspace --doc` is a
#     separate, existing Tier-1 lane and not part of this measurement.
#
# Scope note: this covers the oraclemcp workspace only. The driver
# (rust-oracledb, a separate repo) needs its own baseline -- tracked as a
# follow-up, not built here.
#
# Modes:
#   scripts/coverage_baseline.sh            Run the full instrumented build +
#                                            test pass and overwrite the
#                                            committed baseline
#                                            (tests/coverage/BASELINE.json,
#                                            tests/coverage/BASELINE.md).
#   scripts/coverage_baseline.sh --check    Structural validation ONLY: the
#                                            committed baseline exists, is
#                                            well-formed, and matches its own
#                                            recorded schema. This does NOT
#                                            re-run coverage and does NOT
#                                            detect that the numbers have
#                                            drifted from HEAD -- that drift
#                                            check is bead D2's ratchet, to
#                                            be built on top of this.
#
# Prerequisites: the `cargo-llvm-cov` cargo subcommand plus the `llvm-tools`
# rustup component for the pinned toolchain (rust-toolchain.toml). This
# script fails closed with the exact install command when either is missing,
# rather than fabricating numbers:
#   cargo install cargo-llvm-cov
#   rustup component add llvm-tools --toolchain nightly-2026-05-11
#
# This is a heavy, slow, INSTRUMENTED build -- run it deliberately (Tier 2 /
# nightly per docs/test-tiers.md), never per-PR. Set CARGO_TARGET_DIR to a
# dedicated directory first if another build is using the default target/
# concurrently, and consider capping CARGO_BUILD_JOBS on a shared host.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT/tests/coverage"

MODE="write"
case "${1:-}" in
  ""|--write) MODE="write" ;;
  --check) MODE="check" ;;
  -h|--help)
    grep '^#' "$0" | sed 's/^# \{0,1\}//'
    exit 0 ;;
  *) echo "coverage_baseline: unknown argument: $1" >&2; exit 2 ;;
esac

if [ "$MODE" = "check" ]; then
  exec python3 "$ROOT/scripts/coverage_baseline.py" check --out-dir "$OUT_DIR"
fi

if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
  cat >&2 <<'EOF'
coverage_baseline: cargo-llvm-cov is not installed.

Install it (and the llvm-tools component for the pinned toolchain) with:
  cargo install cargo-llvm-cov
  rustup component add llvm-tools --toolchain nightly-2026-05-11

Then re-run: scripts/coverage_baseline.sh
EOF
  exit 2
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
raw_json="$tmpdir/raw-llvm-cov.json"

CMD=(cargo llvm-cov --workspace --locked --summary-only --json --output-path "$raw_json")
echo "coverage_baseline: running: ${CMD[*]}" >&2
echo "coverage_baseline: this is a full instrumented workspace build + test pass; it is slow by design, be patient." >&2
"${CMD[@]}"

mkdir -p "$OUT_DIR"
python3 "$ROOT/scripts/coverage_baseline.py" generate \
  --raw "$raw_json" \
  --out-dir "$OUT_DIR" \
  --command "${CMD[*]}"

echo "coverage_baseline: wrote $OUT_DIR/BASELINE.json and $OUT_DIR/BASELINE.md" >&2
