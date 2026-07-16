#!/usr/bin/env bash
# Emit required-proof/v1 for the effective `required` quality graph.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$ROOT/scripts/verify_required_local.py" "$@"
