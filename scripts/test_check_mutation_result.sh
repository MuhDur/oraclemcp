#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Keep the fixture on failure: this repository does not delete test artifacts
# without an explicit operator command.
workdir="$(mktemp -d /var/tmp/oraclemcp-check-mutation-result.XXXXXX)"
valid="$workdir/valid.json"
unwitnessed="$workdir/unwitnessed.json"
foreign="$workdir/foreign.json"

python3 - "$root" "$valid" "$unwitnessed" "$foreign" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
valid_path = Path(sys.argv[2])
unwitnessed_path = Path(sys.argv[3])
foreign_path = Path(sys.argv[4])
fixture = root / "schemas/evidence/fixtures/valid/mutation-result.json"
document = json.loads(fixture.read_text())
document["repo"] = "oraclemcp"
document["source"]["sha"] = subprocess.check_output(
    ["git", "rev-parse", "HEAD"], cwd=root, text=True
).strip()
document["source"]["tree_clean"] = True
valid_path.write_text(json.dumps(document))
document["kills"] = []
unwitnessed_path.write_text(json.dumps(document))
document["kills"] = json.loads(fixture.read_text())["kills"]
document["repo"] = "rust-oracledb"
foreign_path.write_text(json.dumps(document))
PY

python3 "$root/scripts/check_mutation_result.py" "$valid"
if python3 "$root/scripts/check_mutation_result.py" "$unwitnessed" >"$workdir/unwitnessed.out" 2>&1; then
  echo "check-mutation-result: accepted a caught count without kill witnesses" >&2
  exit 1
fi
grep -Fq 'E_MISSING_WITNESS: /kills:' "$workdir/unwitnessed.out"
if python3 "$root/scripts/check_mutation_result.py" "$foreign" >"$workdir/foreign.out" 2>&1; then
  echo "check-mutation-result: accepted a foreign-repository artifact" >&2
  exit 1
fi
grep -Fqx "E_REPO_MISMATCH: expected 'oraclemcp', got 'rust-oracledb'" "$workdir/foreign.out"
echo "check-mutation-result: witness-count rejection OK ($workdir)"
