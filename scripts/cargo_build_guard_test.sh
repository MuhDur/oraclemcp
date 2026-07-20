#!/usr/bin/env bash
# Integration proof for the mandatory direct-Cargo build-lease interceptor.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIRECT_TARGET="$ROOT/target/e1-cargo-guard-direct"
SCOPED_TARGET="$ROOT/target/e1-cargo-guard-scoped"
LOG_DIR="$ROOT/target/e1-cargo-guard-selftest"
DIRECT_LOG="$LOG_DIR/direct.log"
SHARED_LOG="$LOG_DIR/shared.log"
SHARED_CLI_LOG="$LOG_DIR/shared-cli.log"
RAM_LOG="$LOG_DIR/ram.log"
SCOPED_LOG="$LOG_DIR/scoped.log"

mkdir -p "$LOG_DIR"
: >"$DIRECT_LOG"
: >"$SHARED_LOG"
: >"$SHARED_CLI_LOG"
: >"$RAM_LOG"
: >"$SCOPED_LOG"

rc=0
env -u CARGO_SWARM_BUILD_LEASE_DIR -u CARGO_SWARM_BUILD_LEASE_SLOT \
  -u CARGO_SWARM_BUILD_LEASE_PID -u CI \
  CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR="$DIRECT_TARGET" \
  cargo test --workspace --no-run >"$DIRECT_LOG" 2>&1 || rc=$?
if [ "$rc" -ne 101 ]; then
  echo "cargo_build_guard_test: Cargo rc=$rc, want 101 for a compiler-wrapper failure" >&2
  sed -n '1,80p' "$DIRECT_LOG" >&2
  exit 1
fi
if ! grep -q 'REFUSING un-leased heavy build' "$DIRECT_LOG"; then
  echo "cargo_build_guard_test: direct refusal did not come from lease gate" >&2
  sed -n '1,80p' "$DIRECT_LOG" >&2
  exit 1
fi
if ! grep -q 'exit status: 75' "$DIRECT_LOG"; then
  echo "cargo_build_guard_test: Cargo did not report the gate's exit 75" >&2
  sed -n '1,80p' "$DIRECT_LOG" >&2
  exit 1
fi
if grep -q '^ *Compiling ' "$DIRECT_LOG"; then
  echo "cargo_build_guard_test: rustc compilation began before refusal" >&2
  sed -n '1,80p' "$DIRECT_LOG" >&2
  exit 1
fi
echo "  PASS  direct workspace Cargo refused before compilation (gate=75, cargo=101)"

rc=0
env -u CARGO_SWARM_BUILD_LEASE_DIR -u CARGO_SWARM_BUILD_LEASE_SLOT \
  -u CARGO_SWARM_BUILD_LEASE_PID -u CI \
  CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR="$HOME/.cache/cargo-target" \
  cargo check -p oraclemcp-error >"$SHARED_LOG" 2>&1 || rc=$?
if [ "$rc" -ne 101 ]; then
  echo "cargo_build_guard_test: shared-target Cargo rc=$rc, want 101" >&2
  sed -n '1,80p' "$SHARED_LOG" >&2
  exit 1
fi
if ! grep -q 'target dir is a SHARED build cache' "$SHARED_LOG"; then
  echo "cargo_build_guard_test: shared target refusal was not explicit" >&2
  sed -n '1,80p' "$SHARED_LOG" >&2
  exit 1
fi
if ! grep -q 'exit status: 78' "$SHARED_LOG"; then
  echo "cargo_build_guard_test: Cargo did not report the target gate's exit 78" >&2
  sed -n '1,80p' "$SHARED_LOG" >&2
  exit 1
fi
echo "  PASS  direct shared-target Cargo refused before compilation (gate=78, cargo=101)"

rc=0
env -u CARGO_SWARM_BUILD_LEASE_DIR -u CARGO_SWARM_BUILD_LEASE_SLOT \
  -u CARGO_SWARM_BUILD_LEASE_PID -u CI -u CARGO_TARGET_DIR \
  CARGO_BUILD_JOBS=1 \
  cargo check -p oraclemcp-error \
    --target-dir "$HOME/.cache/cargo-target" >"$SHARED_CLI_LOG" 2>&1 || rc=$?
if [ "$rc" -ne 101 ] ||
  ! grep -q 'exit status: 78' "$SHARED_CLI_LOG" ||
  ! grep -q 'target dir is a SHARED build cache' "$SHARED_CLI_LOG"; then
  echo "cargo_build_guard_test: --target-dir shared-cache bypass was not refused" >&2
  sed -n '1,80p' "$SHARED_CLI_LOG" >&2
  exit 1
fi
echo "  PASS  direct Cargo --target-dir shared-cache override refused"

if [ -d /dev/shm ] && [ "$(stat -f -c %T /dev/shm 2>/dev/null || true)" = "tmpfs" ]; then
  rc=0
  env -u CARGO_SWARM_BUILD_LEASE_DIR -u CARGO_SWARM_BUILD_LEASE_SLOT \
    -u CARGO_SWARM_BUILD_LEASE_PID -u CI \
    CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR="/dev/shm/oraclemcp-e1-ram-target" \
    cargo check -p oraclemcp-error >"$RAM_LOG" 2>&1 || rc=$?
  if [ "$rc" -ne 101 ] ||
    ! grep -q 'exit status: 78' "$RAM_LOG" ||
    ! grep -q 'target dir is RAM-backed' "$RAM_LOG"; then
    echo "cargo_build_guard_test: RAM-backed direct target was not refused" >&2
    sed -n '1,80p' "$RAM_LOG" >&2
    exit 1
  fi
  echo "  PASS  direct Cargo RAM-backed target refused before compilation"
else
  echo "  SKIP  /dev/shm is not an observable tmpfs on this host"
fi

# Scoped single-package iteration remains available without a lease. Use the
# smallest leaf crate and a dedicated worktree-local target.
env -u CARGO_SWARM_BUILD_LEASE_DIR -u CARGO_SWARM_BUILD_LEASE_SLOT \
  -u CARGO_SWARM_BUILD_LEASE_PID -u CI \
  CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR="$SCOPED_TARGET" \
  cargo check -p oraclemcp-error >"$SCOPED_LOG" 2>&1
echo "  PASS  scoped 'cargo check -p oraclemcp-error' remains unleased and green"

echo "cargo_build_guard_test: OK"
