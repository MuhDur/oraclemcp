#!/usr/bin/env bash
# Disk-free preflight for the feature-powerset (cargo-hack) CI job.
#
# Retro C5 (docs/plan/PLAN_ENGINEERING_PROGRAM.md §27.2 / bead
# oraclemcp-eng-program-bp8ia.3.2): the powerset job hit ENOSPC mid-build
# repeatedly across several 2026-07-17 fix commits, each failure surfacing
# minutes into a `cargo hack clippy` sweep as an opaque linker/compiler I/O
# error instead of a clear disk message. Run this immediately before the
# powerset build (after toolchain install + cache restore, so it observes the
# REAL disk state the build will see) to turn that failure class into an
# immediate, legible preflight instead of a mid-build death.
#
# Usage: scripts/feature_powerset_disk_preflight.sh
# Env:
#   ORACLEMCP_POWERSET_MIN_FREE_GB  minimum free GB required to proceed
#                                   (default 10)
#   ORACLEMCP_POWERSET_DISK_PATH   filesystem path to check (default: repo root)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK_PATH="${ORACLEMCP_POWERSET_DISK_PATH:-$ROOT}"
MIN_FREE_GB="${ORACLEMCP_POWERSET_MIN_FREE_GB:-10}"

if ! [[ "$MIN_FREE_GB" =~ ^[0-9]+$ ]]; then
  echo "feature-powerset disk preflight: ORACLEMCP_POWERSET_MIN_FREE_GB must be a non-negative integer, got '$MIN_FREE_GB'" >&2
  exit 2
fi

avail_gb() {
  # GNU df: available space in whole GiB (1024^3), last data row, whitespace-trimmed.
  df --output=avail -BG "$CHECK_PATH" 2>/dev/null | tail -n1 | tr -dc '0-9'
}

free_gb="$(avail_gb || true)"
if [ -z "$free_gb" ]; then
  echo "feature-powerset disk preflight: could not read free disk space for '$CHECK_PATH' (df failed or produced no numeric output); not blocking the build on an unreadable signal" >&2
  exit 0
fi

echo "feature-powerset disk preflight: ${free_gb}GB free at $CHECK_PATH (need >= ${MIN_FREE_GB}GB)"

if [ "$free_gb" -lt "$MIN_FREE_GB" ]; then
  echo "feature-powerset disk preflight: below threshold, pruning target/**/incremental before re-check" >&2
  if [ -d "$ROOT/target" ]; then
    find "$ROOT/target" -maxdepth 4 -type d -name incremental -prune -exec rm -rf {} + 2>/dev/null || true
  fi
  free_gb="$(avail_gb || true)"
  echo "feature-powerset disk preflight: ${free_gb:-unknown}GB free after prune"
fi

if [ -z "$free_gb" ] || [ "$free_gb" -lt "$MIN_FREE_GB" ]; then
  cat >&2 <<EOF
feature-powerset disk preflight: FAIL — only ${free_gb:-0}GB free at $CHECK_PATH, need >= ${MIN_FREE_GB}GB.

This is a DISK-space constraint (the recurring ENOSPC class tracked in
docs/plan/PLAN_ENGINEERING_PROGRAM.md §27.2, retro item C5), not a compile or
test failure. Pruning target/**/incremental did not free enough space. Free
additional runner disk earlier in this job (remove unused preinstalled
toolchains/images) or, if this threshold is deliberately being lowered,
override ORACLEMCP_POWERSET_MIN_FREE_GB explicitly rather than letting the
build run into ENOSPC mid-compile.
EOF
  exit 1
fi

echo "feature-powerset disk preflight: OK — sufficient disk space, proceeding to the powerset build."
