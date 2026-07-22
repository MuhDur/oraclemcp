#!/usr/bin/env bash
# Cheap R0 boundary lint for the Local Integrator Rig.
#
# The external-client probe/harness must stay black-box: no imports from the
# Rust server, no reuse of e2e_harness.rs, and no cargo-run shortcut in the rig
# scaffold. This is intentionally static and CI-safe; live reachability belongs
# to the optional rig lanes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
violations=0
scan_files=()

while IFS= read -r path; do
  scan_files+=("$path")
done < <(find "$ROOT/scripts/rig" -type f ! -name 'rig_boundary_lint.sh' | sort)

fail() {
  printf 'rig-boundary-lint: %s\n' "$*" >&2
  violations=$((violations + 1))
}

if [ ! -x "$ROOT/scripts/rig/rig.sh" ]; then
  fail "scripts/rig/rig.sh is missing or not executable"
fi

if grep -InE 'e2e_harness\.rs|oraclemcp::|oraclemcp_core::|oraclemcp_db::' "${scan_files[@]}" >/dev/null 2>&1; then
  grep -InE 'e2e_harness\.rs|oraclemcp::|oraclemcp_core::|oraclemcp_db::' "${scan_files[@]}" >&2
  fail "rig scripts must not share server/e2e_harness Rust code"
fi

if grep -InE 'cargo[[:space:]]+run|cargo[[:space:]]+\+[[:alnum:]_.-]+[[:space:]]+run' "${scan_files[@]}" >/dev/null 2>&1; then
  grep -InE 'cargo[[:space:]]+run|cargo[[:space:]]+\+[[:alnum:]_.-]+[[:space:]]+run' "${scan_files[@]}" >&2
  fail "rig must drive installed/built artifacts, never cargo run"
fi

if ! grep -F 'HOME=' "$ROOT/scripts/rig/rig.sh" >/dev/null ||
   ! grep -F 'XDG_CONFIG_HOME=' "$ROOT/scripts/rig/rig.sh" >/dev/null ||
   ! grep -F 'XDG_STATE_HOME=' "$ROOT/scripts/rig/rig.sh" >/dev/null ||
   ! grep -F 'XDG_RUNTIME_DIR=' "$ROOT/scripts/rig/rig.sh" >/dev/null; then
  fail "rig.sh must redirect HOME and XDG_* for Tier A"
fi

if ! grep -F 'host_hygiene' "$ROOT/scripts/rig/rig.sh" >/dev/null; then
  fail "rig.sh must include the host-hygiene assertion"
fi

if [ "$violations" -ne 0 ]; then
  printf 'rig-boundary-lint: FAIL (%s violation(s))\n' "$violations" >&2
  exit 1
fi

printf 'rig-boundary-lint: OK\n'
