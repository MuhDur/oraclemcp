#!/usr/bin/env bash
# Prove pip rejects a transitive wheel hash mutation before installation.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lock="$ROOT/containers/python-oracledb-requirements.lock"
work="$(mktemp -d "${TMPDIR:-/tmp}/oraclemcp-python-lock.XXXXXX")"
wheelhouse="$work/wheelhouse"
mkdir -p "$wheelhouse"

python3 -m pip download --disable-pip-version-check --only-binary=:all: \
  --require-hashes --dest "$wheelhouse" -r "$lock"
python3 - "$lock" "$work/mutated.lock" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
mutated, count = re.subn(
    r"(?m)(--hash=sha256:)[0-9a-f]",
    lambda match: match.group(1) + ("0" if match.group(0)[-1] != "0" else "1"),
    source,
    count=1,
)
if count != 1:
    raise SystemExit("could not mutate one locked wheel hash")
pathlib.Path(sys.argv[2]).write_text(mutated, encoding="utf-8")
PY

if python3 -m pip install --disable-pip-version-check --dry-run --no-index \
  --find-links "$wheelhouse" --require-hashes -r "$work/mutated.lock" \
  >"$work/pip.log" 2>&1; then
  cat "$work/pip.log" >&2
  echo "container-python-lock-selftest: FAIL — pip accepted a mutated wheel hash" >&2
  exit 1
fi
grep -Ei 'hash|checksum|expected' "$work/pip.log" >/dev/null || {
  cat "$work/pip.log" >&2
  echo "container-python-lock-selftest: FAIL — pip rejected for an unrelated reason" >&2
  exit 1
}
echo "container-python-lock-selftest: OK — pip refused the mutated wheel hash before install"
