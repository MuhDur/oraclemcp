#!/usr/bin/env bash
# Deterministic release metadata, publish-order, and crates.io response contracts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SELF="$ROOT/tests/release_contract_test.sh"
HELPER="$ROOT/scripts/release_surface_manifest.py"
CARGO_PATCH_WARNING_GUARD="$ROOT/scripts/cargo_patch_warning_guard.sh"

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
  if [ "${ORACLEMCP_FAKE_MISSING_CRATE:-}" = "$crate" ]; then
    mode="not-found"
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

# Dev pins may be used during the train, but must never make it onto a release
# tag. Exercise the release refusal against isolated copies of the three input
# manifests so these checks stay offline and cannot see the live workspace.
dev_pin_log_dir="$ROOT/target/e2e/release-contract"
dev_pin_fixture_root="$ROOT/target/e2e/dev-pin-fixtures-$$"
dev_pin_log="$dev_pin_log_dir/dev_pins-$$.jsonl"
mkdir -p "$dev_pin_log_dir" "$dev_pin_fixture_root"

new_dev_pin_fixture() {
  local name="$1"
  local fixture="$dev_pin_fixture_root/$name"
  mkdir -p "$fixture/scripts"
  cp "$ROOT/Cargo.toml" "$ROOT/Cargo.lock" "$ROOT/deny.toml" "$fixture/"
  cp "$ROOT/scripts/local_release_gate_check.sh" "$fixture/scripts/"
  cat >"$fixture/Cargo.toml" <<'TOML'
[workspace]
resolver = "2"
TOML
  cat >"$fixture/deny.toml" <<'TOML'
[sources]
unknown-git = "deny"
allow-git = []
TOML
  cat >"$fixture/Cargo.lock" <<'TOML'
version = 4

[[package]]
name = "release-contract-fixture"
version = "0.1.0"
TOML
  git -C "$fixture" init -q
  git -C "$fixture" -c user.name=release-contract -c user.email=release-contract.invalid \
    commit --allow-empty -qm fixture
  printf '%s\n' "$fixture"
}

record_dev_pin_case() {
  local case_name="$1" expected="$2" actual="$3" status="$4"
  jq -cn --arg case "$case_name" --arg expected "$expected" --arg actual "$actual" \
    --argjson exit "$status" '{case:$case,expected:$expected,actual:$actual,exit:$exit}' >>"$dev_pin_log"
}

run_dev_pin_case() {
  local fixture="$1" case_name="$2" expected="$3" mode="$4" needle="$5"
  shift 5
  local output status actual
  set +e
  if [ "$mode" = "explicit" ]; then
    output="$(env -u RELEASE_TAG -u GITHUB_REF_TYPE -u GITHUB_REF \
      bash "$fixture/scripts/local_release_gate_check.sh" --refuse-dev-pins "$@" 2>&1)"
  elif [ "$mode" = "tag" ]; then
    output="$(env -u RELEASE_TAG -u GITHUB_REF_TYPE GITHUB_REF=refs/tags/v0.12.0 \
      bash "$fixture/scripts/local_release_gate_check.sh" "$@" 2>&1)"
  else
    output="$(env -u RELEASE_TAG -u GITHUB_REF_TYPE -u GITHUB_REF -u RELEASE_REQUIRE_LOCAL_GATE \
      bash "$fixture/scripts/local_release_gate_check.sh" "$@" 2>&1)"
  fi
  status=$?
  set -e
  if [ "$expected" = "refuse" ]; then
    actual=refuse
    [ "$status" -ne 0 ] || fail "$case_name unexpectedly accepted dev pins"
    [[ "$output" == *"$needle"* ]] || fail "$case_name refusal omitted '$needle': $output"
  else
    actual=pass
    [ "$status" -eq 0 ] || fail "$case_name unexpectedly refused: $output"
  fi
  record_dev_pin_case "$case_name" "$expected" "$actual" "$status"
}

dev_pin_fixture="$(new_dev_pin_fixture patch-entry)"
cat >>"$dev_pin_fixture/Cargo.toml" <<'TOML'

[patch.crates-io]
oraclemcp-driver-cx = { git = "https://github.com/MuhDur/rust-oracledb", rev = "deadbeef" }
TOML
run_dev_pin_case "$dev_pin_fixture" dev_pins_refuse_tag_patch_entry refuse explicit \
  'Cargo.toml.[patch.crates-io]'

dev_pin_fixture="$(new_dev_pin_fixture allow-git)"
python3 - "$dev_pin_fixture/deny.toml" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
text = path.read_text()
needle = 'allow-git = []'
assert text.count(needle) == 1
path.write_text(text.replace(needle, 'allow-git = ["https://github.com/MuhDur/rust-oracledb"]'))
PY
run_dev_pin_case "$dev_pin_fixture" dev_pins_refuse_tag_allow_git refuse explicit \
  'deny.toml.sources.allow-git'

dev_pin_fixture="$(new_dev_pin_fixture git-lock-source)"
cat >>"$dev_pin_fixture/Cargo.lock" <<'TOML'

[[package]]
name = "dev-pin-fixture"
version = "0.0.0"
source = "git+https://github.com/MuhDur/rust-oracledb?rev=deadbeef#deadbeef"
TOML
run_dev_pin_case "$dev_pin_fixture" dev_pins_refuse_tag_git_lock_source refuse explicit \
  'Cargo.lock.package['

dev_pin_fixture="$(new_dev_pin_fixture clean)"
run_dev_pin_case "$dev_pin_fixture" dev_pins_clean_manifest_passes pass explicit ''

dev_pin_fixture="$(new_dev_pin_fixture non-tag)"
cat >>"$dev_pin_fixture/Cargo.toml" <<'TOML'

[patch.crates-io]
oraclemcp-driver-cx = { git = "https://github.com/MuhDur/rust-oracledb", rev = "deadbeef" }
TOML
run_dev_pin_case "$dev_pin_fixture" dev_pins_non_tag_run_is_not_refused pass non-tag ''

dev_pin_fixture="$(new_dev_pin_fixture tag-context)"
cat >>"$dev_pin_fixture/Cargo.toml" <<'TOML'

[patch.crates-io]
oraclemcp-driver-cx = { git = "https://github.com/MuhDur/rust-oracledb", rev = "deadbeef" }
TOML
run_dev_pin_case "$dev_pin_fixture" dev_pins_refuse_tag_context refuse tag \
  'Cargo.toml.[patch.crates-io]'

dev_pin_fixture="$(new_dev_pin_fixture tag-parse-error)"
cat >"$dev_pin_fixture/Cargo.lock" <<'TOML'
not-valid = [toml
TOML
run_dev_pin_case "$dev_pin_fixture" dev_pins_refuse_tag_parse_error refuse tag \
  'Cargo.lock parse'

dev_pin_fixture="$(new_dev_pin_fixture cargo-parse-error)"
cat >"$dev_pin_fixture/Cargo.toml" <<'TOML'
not-valid = [toml
TOML
run_dev_pin_case "$dev_pin_fixture" dev_pins_refuse_tag_cargo_parse_error refuse tag \
  'Cargo.toml parse'

dev_pin_fixture="$(new_dev_pin_fixture deny-parse-error)"
cat >"$dev_pin_fixture/deny.toml" <<'TOML'
not-valid = [toml
TOML
run_dev_pin_case "$dev_pin_fixture" dev_pins_refuse_tag_deny_parse_error refuse tag \
  'deny.toml parse'

# Cargo exits successfully when a patch version cannot satisfy the dependency,
# but warns that the patch was not used. The release check must treat that as a
# failed pin check. Keep this as a real, offline Cargo metadata fixture.
unused_patch_fixture="$ROOT/target/e2e/cargo-unused-patch-fixtures-$$"
mkdir -p "$unused_patch_fixture/src" "$unused_patch_fixture/patched-serde/src"
cat >"$unused_patch_fixture/Cargo.toml" <<'TOML'
[workspace]

[package]
name = "cargo-unused-patch-fixture"
version = "0.1.0"
edition = "2024"

[dependencies]
serde = "=1.0.228"

[patch.crates-io]
serde = { path = "patched-serde" }
TOML
cat >"$unused_patch_fixture/src/main.rs" <<'RS'
fn main() {}
RS
cat >"$unused_patch_fixture/patched-serde/Cargo.toml" <<'TOML'
[package]
name = "serde"
version = "1.0.229"
edition = "2021"
TOML
cat >"$unused_patch_fixture/patched-serde/src/lib.rs" <<'RS'
#![no_std]
RS

cargo_target_dir="${CARGO_TARGET_DIR:-$ROOT/target}"
metadata_args=(--manifest-path "$unused_patch_fixture/Cargo.toml" --format-version 1 --offline)
set +e
raw_output="$(CARGO_TARGET_DIR="$cargo_target_dir" cargo metadata "${metadata_args[@]}" 2>&1)"
raw_status=$?
set -e
[ "$raw_status" -eq 0 ] || fail "unused-patch Cargo fixture failed before the guard: $raw_output"
[[ "$raw_output" == *'warning: patch `serde v1.0.229'* ]] ||
  fail "mismatched Cargo fixture did not produce Cargo's unused-patch warning: $raw_output"

set +e
guarded_output="$(CARGO_TARGET_DIR="$cargo_target_dir" \
  "$CARGO_PATCH_WARNING_GUARD" "${metadata_args[@]}" 2>&1)"
guarded_status=$?
set -e
[ "$guarded_status" -ne 0 ] || fail "unused-patch warning guard accepted a mismatched Cargo patch"
[[ "$guarded_output" == *"cargo-patch-warning-guard: refusing Cargo output with an unused patch"* ]] ||
  fail "unused-patch warning guard did not identify Cargo's warning: $guarded_output"
record_dev_pin_case dev_pins_refuse_unused_patch_warning refuse refuse "$guarded_status"

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

# verifier_package_list: the published oraclemcp-verifier package carries its
# library, binary, README and license texts, and nothing else (no tests or
# fixtures). A change to the list must update the committed expectation.
expected_verifier_package="$ROOT/tests/fixtures/release/oraclemcp-verifier.package-list"
actual_verifier_package="$(cargo package --list -p oraclemcp-verifier --allow-dirty 2>/dev/null)" ||
  fail "cargo package --list -p oraclemcp-verifier failed"
[ "$actual_verifier_package" = "$(cat "$expected_verifier_package")" ] ||
  fail "oraclemcp-verifier package list drifted from $expected_verifier_package: $actual_verifier_package"

# --verify-published is read-only and fails before any install when crates.io
# lacks the exact version or reports it yanked.
# publish_crates_verify_published_rejects_missing_version
assert_fails_with "oraclemcp-verifier $server_version is not published" run_with_fake_curl valid \
  env ORACLEMCP_FAKE_MISSING_CRATE=oraclemcp-verifier \
  bash "$ROOT/scripts/publish_crates.sh" --verify-published
# publish_crates_verify_published_rejects_yanked
assert_fails_with "oraclemcp-verifier $server_version is yanked" run_with_fake_curl valid \
  env ORACLEMCP_FAKE_YANKED_CRATE=oraclemcp-verifier \
  bash "$ROOT/scripts/publish_crates.sh" --verify-published
assert_fails_with "does not match" run_with_fake_curl wrong-version \
  bash "$ROOT/scripts/publish_crates.sh" --verify-published
assert_fails_with "unknown argument" bash "$ROOT/scripts/publish_crates.sh" --verify-publish

echo "release-contract-test: OK (manifest, publish order, strict registry JSON, bounded curl, verifier package list, verify-published)"
