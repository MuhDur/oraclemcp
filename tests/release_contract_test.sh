#!/usr/bin/env bash
# Deterministic release metadata, publish-order, and crates.io response contracts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SELF="$ROOT/tests/release_contract_test.sh"
HELPER="$ROOT/scripts/release_surface_manifest.py"

fail() {
  echo "release-contract-test: $*" >&2
  exit 1
}

require_argument_pair() {
  local expected_flag="$1"
  local expected_value="$2"
  shift 2
  local -a arguments=("$@")
  local index
  for ((index = 0; index + 1 < ${#arguments[@]}; index++)); do
    if [ "${arguments[$index]}" = "$expected_flag" ] &&
      [ "${arguments[$((index + 1))]}" = "$expected_value" ]; then
      return 0
    fi
  done
  fail "fake curl did not receive $expected_flag $expected_value"
}

require_argument() {
  local expected="$1"
  shift
  local argument
  for argument in "$@"; do
    [ "$argument" = "$expected" ] && return 0
  done
  fail "fake curl did not receive $expected"
}

# The test file doubles as a fake curl executable. This keeps the contract
# hermetic without creating a temporary PATH tree or starting a local server.
if [ -n "${ORACLEMCP_RELEASE_FAKE_CURL_MODE:-}" ]; then
  require_argument_pair --connect-timeout "${ORACLEMCP_CRATES_IO_CONNECT_TIMEOUT_SECONDS:?}" "$@"
  require_argument_pair --max-time "${ORACLEMCP_CRATES_IO_MAX_TIME_SECONDS:?}" "$@"
  require_argument_pair --retry "${ORACLEMCP_CRATES_IO_RETRIES:?}" "$@"
  require_argument_pair --retry-delay "${ORACLEMCP_CRATES_IO_RETRY_DELAY_SECONDS:?}" "$@"
  require_argument_pair --retry-max-time "${ORACLEMCP_CRATES_IO_RETRY_MAX_TIME_SECONDS:?}" "$@"
  require_argument --retry-connrefused "$@"

  output=""
  url=""
  arguments=("$@")
  for ((index = 0; index < ${#arguments[@]}; index++)); do
    case "${arguments[$index]}" in
      --output)
        index=$((index + 1))
        output="${arguments[$index]:-}"
        ;;
      http://* | https://*) url="${arguments[$index]}" ;;
    esac
  done
  [ -n "$output" ] || fail "fake curl received no --output path"
  [ -n "$url" ] || fail "fake curl received no registry URL"

  version="${url##*/}"
  crate_path="${url%/*}"
  crate="${crate_path##*/}"
  mode="$ORACLEMCP_RELEASE_FAKE_CURL_MODE"
  if [ "${ORACLEMCP_FAKE_YANKED_CRATE:-}" = "$crate" ]; then
    mode="yanked"
  fi

  case "$mode" in
    valid)
      printf '{"version":{"crate":"%s","num":"%s","yanked":false}}' "$crate" "$version" >"$output"
      status=200
      ;;
    yanked)
      printf '{"version":{"crate":"%s","num":"%s","yanked":true}}' "$crate" "$version" >"$output"
      status=200
      ;;
    missing-yanked)
      printf '{"version":{"crate":"%s","num":"%s"}}' "$crate" "$version" >"$output"
      status=200
      ;;
    wrong-version)
      printf '{"version":{"crate":"%s","num":"9.9.9","yanked":false}}' "$crate" >"$output"
      status=200
      ;;
    malformed)
      printf '{not-json' >"$output"
      status=200
      ;;
    not-found)
      printf '{"errors":[{"detail":"not found"}]}' >"$output"
      status=404
      ;;
    server-error)
      printf '{"errors":[{"detail":"unavailable"}]}' >"$output"
      status=503
      ;;
    transport-error)
      printf '000'
      exit 28
      ;;
    *) fail "unknown fake curl mode: $mode" ;;
  esac
  printf '%s' "$status"
  exit 0
fi

run_with_fake_curl() {
  local mode="$1"
  shift
  env \
    ORACLEMCP_CURL_BIN="$SELF" \
    ORACLEMCP_RELEASE_FAKE_CURL_MODE="$mode" \
    ORACLEMCP_CRATES_IO_CONNECT_TIMEOUT_SECONDS=1 \
    ORACLEMCP_CRATES_IO_MAX_TIME_SECONDS=2 \
    ORACLEMCP_CRATES_IO_RETRIES=0 \
    ORACLEMCP_CRATES_IO_RETRY_DELAY_SECONDS=0 \
    ORACLEMCP_CRATES_IO_RETRY_MAX_TIME_SECONDS=2 \
    "$@"
}

assert_fails_with() {
  local expected="$1"
  shift
  local output
  if output="$("$@" 2>&1)"; then
    fail "command unexpectedly passed: $*"
  fi
  [[ "$output" == *"$expected"* ]] ||
    fail "failure did not contain '$expected': $output"
}

cd "$ROOT"

python3 "$HELPER" --check >/dev/null
driver_version="$(python3 "$HELPER" --value driver_version)"
[[ "$driver_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  fail "canonical driver pin was not parsed as exact stable semver: $driver_version"
server_version="$(python3 "$HELPER" --value server_version)"

PYTHONPATH="$ROOT" python3 - <<'PY'
from scripts.release_surface_manifest import SEMVER

for candidate in ("0.10.1", "0.10.1-rc.1", "10.20.30-preview.alpha.2"):
    assert SEMVER.fullmatch(candidate), f"valid release SemVer rejected: {candidate}"
for candidate in ("01.10.1", "0.10.1-01", "0.10.1-rc..1", "0.10"):
    assert not SEMVER.fullmatch(candidate), f"invalid release SemVer accepted: {candidate}"
PY

fixture_metadata="$(cat <<'JSON'
{
  "workspace_members": ["error", "verifier", "private", "guard", "audit", "app"],
  "packages": [
    {"id":"error","name":"error","version":"1.2.3","publish":null,"manifest_path":"/fixture/error/Cargo.toml","dependencies":[]},
    {"id":"verifier","name":"verifier","version":"1.2.3","publish":null,"manifest_path":"/fixture/verifier/Cargo.toml","dependencies":[{"path":"/fixture/guard"}]},
    {"id":"private","name":"private","version":"1.2.3","publish":[],"manifest_path":"/fixture/private/Cargo.toml","dependencies":[]},
    {"id":"guard","name":"guard","version":"1.2.3","publish":null,"manifest_path":"/fixture/guard/Cargo.toml","dependencies":[{"path":"/fixture/audit"}]},
    {"id":"audit","name":"audit","version":"1.2.3","publish":["crates-io"],"manifest_path":"/fixture/audit/Cargo.toml","dependencies":[{"path":"/fixture/error"}]},
    {"id":"app","name":"app","version":"1.2.3","publish":null,"manifest_path":"/fixture/app/Cargo.toml","dependencies":[{"path":"/fixture/verifier"}]}
  ]
}
JSON
)"
fixture_order="$(printf '%s\n' "$fixture_metadata" | python3 "$HELPER" --publish-order -)"
expected_fixture_order=$'error\t1.2.3\naudit\t1.2.3\nguard\t1.2.3\nverifier\t1.2.3\napp\t1.2.3'
[ "$fixture_order" = "$expected_fixture_order" ] ||
  fail "fixture publish order was not dependency-complete: $fixture_order"

printf '%s\n' '{"version":{"crate":"demo","num":"1.2.3","yanked":false}}' |
  python3 "$HELPER" --validate-registry-response - --crate demo --expected-version 1.2.3
if printf '%s\n' '{"version":{"crate":"demo","num":"1.2.3","yanked":true}}' |
  python3 "$HELPER" --validate-registry-response - --crate demo --expected-version 1.2.3 >/dev/null 2>&1; then
  fail "yanked registry version was accepted"
fi
if printf '%s\n' '{"version":{"crate":"demo","num":"1.2.4","yanked":false}}' |
  python3 "$HELPER" --validate-registry-response - --crate demo --expected-version 1.2.3 >/dev/null 2>&1; then
  fail "wrong registry version was accepted"
fi
if printf '%s\n' '{"version":{"crate":"demo","num":"1.2.3"}}' |
  python3 "$HELPER" --validate-registry-response - --crate demo --expected-version 1.2.3 >/dev/null 2>&1; then
  fail "registry response without explicit yanked=false was accepted"
fi

current_order="$(bash "$ROOT/scripts/publish_crates.sh" --print-order)"
expected_current_order="$(cat <<'ORDER'
oraclemcp-error
oraclemcp-telemetry
oraclemcp-audit
oraclemcp-guard
oraclemcp-verifier
oraclemcp-config
oraclemcp-db
oraclemcp-auth
oraclemcp-core
oraclemcp
ORDER
)"
[ "$current_order" = "$expected_current_order" ] ||
  fail "workspace publish order is incomplete or dependency-invalid: $current_order"

run_with_fake_curl valid bash "$ROOT/scripts/release_preflight.sh" --check-driver-registry >/dev/null
assert_fails_with "yanked" run_with_fake_curl yanked \
  bash "$ROOT/scripts/release_preflight.sh" --check-driver-registry
assert_fails_with "does not match '$driver_version'" run_with_fake_curl wrong-version \
  bash "$ROOT/scripts/release_preflight.sh" --check-driver-registry
assert_fails_with "lacks yanked=false" run_with_fake_curl missing-yanked \
  bash "$ROOT/scripts/release_preflight.sh" --check-driver-registry
assert_fails_with "not published" run_with_fake_curl not-found \
  bash "$ROOT/scripts/release_preflight.sh" --check-driver-registry
assert_fails_with "HTTP 503" run_with_fake_curl server-error \
  bash "$ROOT/scripts/release_preflight.sh" --check-driver-registry
assert_fails_with "bounded retry window" run_with_fake_curl transport-error \
  bash "$ROOT/scripts/release_preflight.sh" --check-driver-registry

assert_fails_with "between 1 and 60" env \
  ORACLEMCP_CURL_BIN="$SELF" \
  ORACLEMCP_RELEASE_FAKE_CURL_MODE=valid \
  ORACLEMCP_CRATES_IO_MAX_TIME_SECONDS=999 \
  bash "$ROOT/scripts/release_preflight.sh" --check-driver-registry

run_with_fake_curl valid bash "$ROOT/scripts/publish_crates.sh" >/dev/null
assert_fails_with "oraclemcp-verifier $server_version is yanked" run_with_fake_curl valid \
  env ORACLEMCP_FAKE_YANKED_CRATE=oraclemcp-verifier \
  bash "$ROOT/scripts/publish_crates.sh"
assert_fails_with "invalid crates.io response" run_with_fake_curl malformed \
  bash "$ROOT/scripts/publish_crates.sh"

echo "release-contract-test: OK (manifest, publish order, strict registry JSON, bounded curl)"
