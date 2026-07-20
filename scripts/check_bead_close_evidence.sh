#!/usr/bin/env bash
# Bead close-evidence audit (bead yg4x.5).
#
# READ-ONLY. Never writes a bead, never closes or reopens anything, never edits
# a file. An auditor that can change what it audits is not an auditor.
#
# Fails on HARD findings: invalid or unlanded evidence, post-enforcement closes
# without evidence and an exact commit binding, dirty claimed paths at pre-close,
# live claims without scheduled-lane metadata, or self-skipping tests as sole
# proof. Free-text heuristics over legacy reasons remain advisory.
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

exec "$PYTHON_BIN" "$ROOT/scripts/audit_bead_closes.py" "$@"
