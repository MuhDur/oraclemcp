#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
set +e
"$ROOT/scripts/verify_release_exact_sha.sh" --tag v0.9.0 --sha 0000000000000000000000000000000000000000 --ci-json /dev/null --artifact /nope >/tmp/release-proof-test.out 2>&1
status=$?
set -e
test "$status" -ne 0
grep -q 'E_SHA_MISMATCH' /tmp/release-proof-test.out
echo 'verify-release-exact-sha: negative contract OK'
