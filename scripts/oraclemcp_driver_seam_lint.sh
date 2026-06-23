#!/usr/bin/env bash
# oraclemcp driver-adapter seam lint (B2; plan §8 release gate).
#
# The `oracledb` driver is isolated behind ONE adapter file. Every real
# `oracledb::` call (connect, the execute_query* family, fetch, LOB, REF CURSOR,
# auth, commit/rollback, ping, error sanitization) must live in that adapter and
# nowhere else, so the eventual `oracledb` 0.3.0 cut-over touches exactly one
# file. This script is the CI gate that keeps the seam structural and enforced.
#
# It FAILS if an `oracledb::` driver path appears in any crate source outside the
# allowlisted adapter file(s). It deliberately matches the DRIVER crate path
# `oracledb::` and NOT the workspace crate `oraclemcp_db::` — the left word
# boundary `(^|[^A-Za-z0-9_])` prevents `oraclemcp_db::` from matching.
#
# Doc-comments and human-readable driver descriptions that merely mention the
# word `oracledb` (no `::` path) are fine and are not matched.
#
# Mirrored by the `driver_seam` test in crates/oraclemcp-db/src/connection.rs so
# `cargo test` catches a leak even without this shell script. If a new legitimate
# `oracledb::` site is ever required, add it to BOTH allowlists with an inline
# justification.
#
# Exit 0 = seam holds. Exit 1 = a driver call leaked outside the adapter.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATES_DIR="$ROOT/crates"
cd "$ROOT"

# The single, enforced isolation boundary. Paths are relative to $ROOT. Every
# entry is the adapter and the ONLY place a real `oracledb::` call may appear.
ADAPTER_ALLOWLIST=(
  "crates/oraclemcp-db/src/connection.rs" # B2 adapter: wraps the whole oracledb driver surface.
)

# Driver-path pattern: `oracledb::` with a non-identifier char (or start of line)
# to its left, so `oraclemcp_db::` (our own crate) never matches.
DRIVER_PATTERN='(^|[^A-Za-z0-9_])oracledb[[:space:]]*::'

is_allowlisted() {
  local rel="$1"
  local allowed
  for allowed in "${ADAPTER_ALLOWLIST[@]}"; do
    if [ "$rel" = "$allowed" ]; then
      return 0
    fi
  done
  return 1
}

violations=0

# All Rust sources under crates/, with their hits, NUL-safe against odd paths.
while IFS= read -r -d '' file; do
  rel="${file#"$ROOT"/}"
  if is_allowlisted "$rel"; then
    continue
  fi
  if hits="$(grep -nE "$DRIVER_PATTERN" "$file" 2>/dev/null)"; then
    echo "SEAM VIOLATION: $rel names an oracledb:: driver path outside the adapter:" >&2
    while IFS= read -r line; do
      printf '  %s\n' "$line" >&2
    done <<<"$hits"
    violations=$((violations + 1))
  fi
done < <(find "$CRATES_DIR" -type f -name '*.rs' -print0 | sort -z)

if [ "$violations" -ne 0 ]; then
  echo "" >&2
  echo "oraclemcp-driver-seam-lint: $violations file(s) leak an oracledb:: driver" >&2
  echo "path. The oracledb driver MUST stay behind the adapter so the 0.3.0" >&2
  echo "cut-over touches exactly one file. Move the call behind an" >&2
  echo "OracleConnection / adapter method, or (if it is a legitimate new adapter" >&2
  echo "site) add it to ADAPTER_ALLOWLIST here AND in the driver_seam test." >&2
  exit 1
fi

echo "oraclemcp-driver-seam-lint: OK — all oracledb:: driver paths are confined to:"
for allowed in "${ADAPTER_ALLOWLIST[@]}"; do
  echo "  $allowed"
done
