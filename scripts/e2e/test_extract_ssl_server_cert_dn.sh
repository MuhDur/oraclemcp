#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE="$ROOT/scripts/e2e/fixtures/oci-wallet"
helper="$ROOT/scripts/e2e/extract_ssl_server_cert_dn.py"
test "$(python3 "$helper" "$FIXTURE/tnsnames.ora" "$FIXTURE/sqlnet.ora")" = 'CN=adb.example.invalid'
test "$(python3 "$helper" "$FIXTURE/missing.ora" "$FIXTURE/sqlnet.ora")" = 'CN=fallback.example.invalid'
echo "oci-wallet-dn: fixtures OK"
