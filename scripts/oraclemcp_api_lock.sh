#!/usr/bin/env bash
# oraclemcp public-API lock gate (B5; plan §12, ADR-0002 mirror).
#
# `oraclemcp-db` is the canonical shared Oracle foundation (ADR-0006) and the
# engine-free spine crates `oraclemcp-error` / `oraclemcp-guard` are the
# published surface `plsql-mcp` converges onto. Because those surfaces have two
# consumers, an unintended breaking change must be caught BEFORE it reaches
# `plsql-mcp`.
#
# This gate renders each locked crate's current public API with
# `cargo public-api` and diffs it against the committed baseline under
# `crates/<crate>/api/<crate>.txt`. Any drift (an added, removed, or changed
# public item) that is not reflected in the committed baseline fails the build.
#
# When a public-API change is INTENTIONAL, regenerate the baseline in the same
# PR so the diff is reviewable:
#
#   cargo public-api -p <crate> > crates/<crate>/api/<crate>.txt
#
# (run under the pinned nightly toolchain so the rendered surface is stable).
# The companion `cargo semver-checks` job classifies the diff as
# major/minor/patch; this script is the exact-surface lock.
#
# Exit 0 = every locked surface matches its baseline. Exit 1 = drift detected.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# The locked crates: the published spine plsql-mcp consumes, plus the canonical
# foundation. oraclemcp-core (the binary-facing aggregation crate) is
# deliberately NOT locked — it is an internal consumer, not a shared product API.
LOCKED_CRATES=(
  oraclemcp-error
  oraclemcp-guard
  oraclemcp-db
)

if ! command -v cargo-public-api >/dev/null 2>&1; then
  echo "oraclemcp-api-lock: cargo-public-api not installed." >&2
  echo "Install it with: cargo install --locked cargo-public-api" >&2
  echo "(CI installs it via taiki-e/install-action@cargo-public-api.)" >&2
  exit 1
fi

violations=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

for crate in "${LOCKED_CRATES[@]}"; do
  baseline="crates/$crate/api/$crate.txt"
  if [ ! -f "$baseline" ]; then
    echo "oraclemcp-api-lock: missing baseline $baseline" >&2
    echo "  Generate it with: cargo public-api -p $crate > $baseline" >&2
    violations=$((violations + 1))
    continue
  fi
  current="$tmp/$crate.txt"
  if ! cargo public-api -p "$crate" >"$current" 2>"$tmp/$crate.err"; then
    echo "oraclemcp-api-lock: cargo public-api failed for $crate:" >&2
    cat "$tmp/$crate.err" >&2
    violations=$((violations + 1))
    continue
  fi
  if diff -u "$baseline" "$current"; then
    echo "oraclemcp-api-lock: OK — $crate matches $baseline"
  else
    echo "" >&2
    echo "oraclemcp-api-lock: DRIFT — $crate public API differs from $baseline." >&2
    echo "  If this change is intentional, refresh the baseline in this PR:" >&2
    echo "    cargo public-api -p $crate > $baseline" >&2
    violations=$((violations + 1))
  fi
done

if [ "$violations" -ne 0 ]; then
  echo "" >&2
  echo "oraclemcp-api-lock: FAIL — $violations locked crate(s) drifted or are unbaselined." >&2
  exit 1
fi

echo "oraclemcp-api-lock: OK — all locked public-API surfaces match their baselines."
