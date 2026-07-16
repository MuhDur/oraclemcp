#!/usr/bin/env bash
# Bead close-evidence audit (bead yg4x.5).
#
# READ-ONLY. Never writes a bead, never closes or reopens anything, never edits
# a file. An auditor that can change what it audits is not an auditor.
#
# Fails only on HARD findings: a close-evidence document that violates
# bead-close-evidence/v1, names a SHA that is not a commit here, or points at a
# proof/artifact that is not on disk. Free-text heuristics over close reasons are
# reported as advisory and never gate — see docs/BEAD_CLOSE_EVIDENCE.md for why.
#
# Pass --strict to also fail when any closed bead carries no evidence. Not the
# default: this repo has hundreds of closes that predate the contract, and
# failing them retroactively would only teach people to ignore the audit.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PYTHON_BIN="${PYTHON:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "bead-close-evidence: no $PYTHON_BIN on PATH" >&2
  exit 2
fi

if ! command -v br >/dev/null 2>&1; then
  echo "bead-close-evidence: br (beads) is required to enumerate closed beads" >&2
  exit 2
fi

exec "$PYTHON_BIN" "$ROOT/scripts/audit_bead_closes.py" "$@"
