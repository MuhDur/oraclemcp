#!/usr/bin/env bash
# Stable CI entry point for the declarative current release-surface manifest.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

exec python3 "$root/scripts/release_surface_manifest.py" --check
