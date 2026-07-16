#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE="$ROOT/scripts/e2e/fixtures/oci-wallet"
helper="$ROOT/scripts/e2e/extract_ssl_server_cert_dn.py"
test "$(python3 "$helper" "$FIXTURE/tnsnames.ora" "$FIXTURE/sqlnet.ora")" = 'CN=adb.example.invalid'
test "$(python3 "$helper" "$FIXTURE/missing.ora" "$FIXTURE/sqlnet.ora")" = 'CN=fallback.example.invalid'
if python3 "$helper" "$FIXTURE/tnsnames-no-explicit-dn.ora" "$FIXTURE/missing.ora" >/dev/null 2>&1; then
  echo "oci-wallet-dn: expected a wallet without an explicit certificate DN to return no override" >&2
  exit 1
fi
echo "oci-wallet-dn: fixtures OK"
