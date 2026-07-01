#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p "$ROOT/target/tmp"
export CARGO_TARGET_DIR="$ROOT/target"
export TMPDIR="$ROOT/target/tmp"

UPDATE_OPERATOR_SCHEMA=1 cargo test -p oraclemcp-core \
  --lib \
  generated_operator_schema_artifacts_match
