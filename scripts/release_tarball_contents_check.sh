#!/usr/bin/env bash
# Verify every workspace crate's packaged tarball is self-contained (release
# rehearsal counterpart to `cargo package --workspace --locked --no-verify`).
# See scripts/release_tarball_contents_check.py for the full rationale.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$ROOT/scripts/release_tarball_contents_check.py" "$@"
