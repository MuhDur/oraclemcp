#!/usr/bin/env bash
# oraclemcp driver-adapter seam lint (B2; plan §8 release gate).
#
# The `oraclemcp-driver-cx` driver is isolated behind ONE adapter file. Every real
# `oraclemcp_driver_cx::` call (connect, execute, fetch, LOB, REF CURSOR,
# auth, commit/rollback, ping, error sanitization) must live in that adapter and
# nowhere else. This script is the CI gate that keeps the seam structural and
# enforced.
#
# It FAILS if an `oraclemcp_driver_cx::` path appears outside the
# allowlisted adapter file(s). It deliberately matches the DRIVER crate path
# and not the protocol crate or workspace crate: the exact crate identifier and
# left word boundary prevent both from matching.
#
# Doc-comments and human-readable driver descriptions that merely mention the
# driver (no `::` path) are fine and are not matched.
#
# Mirrored by the `driver_seam` test in crates/oraclemcp-db/src/connection.rs so
# `cargo test` catches a leak even without this shell script. If a new legitimate
# `oraclemcp_driver_cx::` site is ever required, add it to BOTH allowlists with an inline
# justification.
#
# Exit 0 = seam holds. Exit 1 = a driver call leaked outside the adapter.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATES_DIR="$ROOT/crates"
cd "$ROOT"

# The single, enforced isolation boundary. Paths are relative to $ROOT. Every
# entry is the adapter and the ONLY place a real driver-cx call may appear.
ADAPTER_ALLOWLIST=(
  "crates/oraclemcp-db/src/connection.rs" # B2 adapter: wraps the whole driver-cx surface.
)

# Driver-path pattern with a non-identifier char (or start of line) to its left.
DRIVER_PATTERN='(^|[^A-Za-z0-9_])oraclemcp_driver_cx[[:space:]]*::'

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
    echo "SEAM VIOLATION: $rel names an oraclemcp_driver_cx:: path outside the adapter:" >&2
    while IFS= read -r line; do
      printf '  %s\n' "$line" >&2
    done <<<"$hits"
    violations=$((violations + 1))
  fi
done < <(find "$CRATES_DIR" -type f -name '*.rs' -print0 | sort -z)

if [ "$violations" -ne 0 ]; then
  echo "" >&2
  echo "oraclemcp-driver-seam-lint: $violations file(s) leak a driver-cx path." >&2
  echo "The driver MUST stay behind the adapter. Move the call behind an" >&2
  echo "OracleConnection / adapter method, or (if it is a legitimate new adapter" >&2
  echo "site) add it to ADAPTER_ALLOWLIST here AND in the driver_seam test." >&2
  exit 1
fi

echo "oraclemcp-driver-seam-lint: OK — all driver-cx paths are confined to:"
for allowed in "${ADAPTER_ALLOWLIST[@]}"; do
  echo "  $allowed"
done
