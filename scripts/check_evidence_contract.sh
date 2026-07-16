#!/usr/bin/env bash
# Versioned cross-repo-evidence-contract gate (bead f1cl.1).
#
# Validates every fixture under schemas/evidence/fixtures against the versioned
# evidence schemas, offline and with no database, network or third-party
# package. Valid fixtures must be accepted; each invalid fixture must be
# rejected for the exact rule it declares in the manifest, and for nothing else.
#
# The point of the negative half is that a rule which silently stops firing
# still looks green. Asserting "rejected, with this code, at this path" is what
# makes a dead rule fail loudly.
#
# The schemas themselves are mirrored byte-for-byte with the sibling oraclemcp
# repo; see docs/EVIDENCE_CONTRACT.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PYTHON_BIN="${PYTHON:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "evidence-contract: no $PYTHON_BIN on PATH" >&2
  exit 2
fi

exec "$PYTHON_BIN" "$ROOT/scripts/validate_evidence.py" --check-fixtures "$@"
