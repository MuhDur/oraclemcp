#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p "$ROOT/target/tmp"
export CARGO_TARGET_DIR="$ROOT/target"
export TMPDIR="$ROOT/target/tmp"

cargo test -p oraclemcp-core --lib operator_protocol::tests::
