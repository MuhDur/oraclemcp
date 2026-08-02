#!/usr/bin/env bash
# Hermetic regression tests for release workflow trust boundaries.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fail() {
  echo "release-workflow-security-test: $*" >&2
  exit 1
}

expect_fail() {
  local label="$1"
  shift
  if "$@" >"$TMP/expect-fail.out" 2>&1; then
    fail "$label unexpectedly passed"
  fi
}

digest="sha256:1111111111111111111111111111111111111111111111111111111111111111"
other_digest="sha256:2222222222222222222222222222222222222222222222222222222222222222"
source_sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
other_sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

mkdir -p "$TMP/bin" "$TMP/artifacts"

cat >"$TMP/bin/cosign" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
[ "${FAKE_COSIGN_FAIL:-0}" != 1 ] || exit 1
case "${1:-}" in
  verify-blob)
    shift
    bundle=""
    identity=""
    issuer=""
    payload=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --bundle) bundle="$2"; shift 2 ;;
        --certificate-identity) identity="$2"; shift 2 ;;
        --certificate-oidc-issuer) issuer="$2"; shift 2 ;;
        *) payload="$1"; shift ;;
      esac
    done
    [ -s "$payload" ]
    [ "$(cat "$bundle")" = valid-signature-bundle ]
    [ -n "$identity" ]
    [ -n "$issuer" ]
    ;;
  verify-blob-attestation)
    shift
    bundle=""
    identity=""
    issuer=""
    payload=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --bundle) bundle="$2"; shift 2 ;;
        --type) shift 2 ;;
        --certificate-identity) identity="$2"; shift 2 ;;
        --certificate-oidc-issuer) issuer="$2"; shift 2 ;;
        *) payload="$1"; shift ;;
      esac
    done
    [ -s "$payload" ]
    [ "$(cat "$bundle")" = valid-bundle ]
    [ -n "$identity" ]
    [ -n "$issuer" ]
    ;;
  verify)
    shift
    identity=""
    issuer=""
    subject=""
    annotations=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --certificate-identity) identity="$2"; shift 2 ;;
        --certificate-oidc-issuer) issuer="$2"; shift 2 ;;
        -a) annotations="${annotations}${2}"$'\n'; shift 2 ;;
        *) subject="$1"; shift ;;
      esac
    done
    [ -n "$issuer" ]
    [[ "$subject" == ghcr.io/muhdur/oraclemcp@sha256:* ]]
    case "${FAKE_COSIGN_SIGNATURE_KIND:-release}" in
      release)
        [[ "$identity" == *'/.github/workflows/release.yml@refs/tags/v'* ]]
        [ -z "$annotations" ]
        ;;
      recovery)
        [ "$identity" = 'https://github.com/MuhDur/oraclemcp/.github/workflows/docker.yml@refs/heads/main' ]
        grep -Fx "oraclemcp.source_sha=${FAKE_EXPECTED_RECOVERY_SOURCE_SHA:-${FAKE_SOURCE_SHA:?}}" <<<"$annotations" >/dev/null
        grep -Fx "oraclemcp.version=${FAKE_EXPECTED_RECOVERY_VERSION:-${VERSION:?}}" <<<"$annotations" >/dev/null
        grep -Fx "oraclemcp.variant=${FAKE_EXPECTED_RECOVERY_VARIANT:-core}" <<<"$annotations" >/dev/null
        [ "$(grep -c . <<<"$annotations")" -eq 3 ]
        ;;
      *) exit 2 ;;
    esac
    ;;
  *) exit 2 ;;
esac
FAKE

cat >"$TMP/bin/gh" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-} ${2:-}" in
  "attestation verify")
    [ "${FAKE_GH_ATTESTATION_FAIL:-0}" != 1 ]
    for required in --repo --signer-workflow --source-ref --source-digest --cert-identity --cert-oidc-issuer; do
      case " $* " in
        *" $required "*) ;;
        *) exit 2 ;;
      esac
    done
    ;;
  "release view")
    [ "${FAKE_GH_RELEASE_FAIL:-0}" != 1 ]
    printf '{"tagName":"v%s","isDraft":%s,"isPrerelease":%s}\n' \
      "${VERSION:?}" "${FAKE_RELEASE_DRAFT:-false}" "${FAKE_RELEASE_PRERELEASE:-false}"
    ;;
  *) exit 2 ;;
esac
FAKE

cat >"$TMP/bin/git" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  show-ref) [ "${FAKE_GIT_NO_TAG:-0}" != 1 ] ;;
  rev-parse)
    if [ "${2:-}" = HEAD ]; then
      printf '%s\n' "${FAKE_SOURCE_SHA:?}"
    else
      printf '%s\n' "${FAKE_TAG_SHA:-${FAKE_SOURCE_SHA:?}}"
    fi
    ;;
  fetch) [ "${FAKE_GIT_FETCH_FAIL:-0}" != 1 ] ;;
  merge-base) [ "${FAKE_GIT_ANCESTRY_FAIL:-0}" != 1 ] ;;
  *) exit 2 ;;
esac
FAKE

cat >"$TMP/bin/docker-mcp" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
[ "${FAKE_DOCKER_INSPECT_FAIL:-0}" != 1 ] || exit 1
[ "${1:-} ${2:-} ${3:-}" = "buildx imagetools inspect" ] || exit 2
printf '%s\n' "${FAKE_MCP_DIGEST:?}"
FAKE

cat >"$TMP/bin/docker-promote" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_DOCKER_LOG:?}"
key_for() {
  printf '%s' "$1" | tr '/:@' '____'
}
if [ "${1:-} ${2:-} ${3:-}" = "buildx imagetools inspect" ]; then
  image="$4"
  state="${FAKE_DOCKER_STATE:?}/$(key_for "$image")"
  if [ -s "$state" ]; then
    cat "$state"
    exit 0
  fi
  case "${FAKE_DOCKER_MODE:-missing}" in
    missing) echo "ERROR: $image: not found" >&2; exit 1 ;;
    different) printf '%s\n' "${FAKE_OTHER_DIGEST:?}" ;;
    same) printf '%s\n' "${DIGEST:?}" ;;
    registry-error) echo "ERROR: registry connection timed out" >&2; exit 1 ;;
    *) exit 2 ;;
  esac
elif [ "${1:-} ${2:-} ${3:-}" = "buildx imagetools create" ]; then
  [ "${4:-}" = --tag ] || exit 2
  printf '%s\n' "${DIGEST:?}" >"${FAKE_DOCKER_STATE:?}/$(key_for "$5")"
elif [ "${1:-}" = pull ]; then
  [ "${FAKE_PULL_FAIL:-0}" != 1 ]
elif [ "${1:-}" = run ]; then
  [ "${FAKE_RUN_FAIL:-0}" != 1 ]
else
  exit 2
fi
FAKE

chmod +x "$TMP/bin/"*

# Release payload verification rejects every independently tampered proof.
archive="$TMP/artifacts/oraclemcp-test.tar.gz"
sbom="$TMP/artifacts/oraclemcp-test.cdx.json"
printf 'archive-bytes\n' >"$archive"
printf '{"bomFormat":"CycloneDX"}\n' >"$sbom"
write_archive_checksum() {
  (cd "$(dirname "$archive")" && sha256sum "$(basename "$archive")" >"$(basename "$archive").sha256")
}
write_archive_checksum
for payload in "$archive" "$sbom"; do
  printf 'valid-signature-bundle\n' >"$payload.sigstore.json"
  printf 'valid-bundle\n' >"$payload.attestation.sigstore.json"
done

run_artifact_verify() {
  GITHUB_REPOSITORY=MuhDur/oraclemcp \
    GITHUB_REF=refs/tags/v0.10.0 \
    GITHUB_SHA="$source_sha" \
    EXPECTED_CERTIFICATE_IDENTITY=https://github.com/MuhDur/oraclemcp/.github/workflows/release.yml@refs/tags/v0.10.0 \
    ORACLEMCP_COSIGN_BIN="$TMP/bin/cosign" \
    ORACLEMCP_GH_BIN="$TMP/bin/gh" \
    bash "$ROOT/scripts/verify_release_artifacts.sh" "$TMP/artifacts"
}

run_artifact_verify >/dev/null
printf 'tampered\n' >>"$archive"
expect_fail "tampered archive bytes" run_artifact_verify
printf 'archive-bytes\n' >"$archive"
write_archive_checksum
printf '%064d  %s\n' 0 "$(basename "$archive")" >"$archive.sha256"
expect_fail "tampered checksum" run_artifact_verify
write_archive_checksum
printf '%s  %s\n' "$(sha256sum "$archive" | awk '{print $1}')" wrong-name.tar.gz >"$archive.sha256"
expect_fail "checksum for wrong basename" run_artifact_verify
write_archive_checksum
printf 'tampered\n' >"$archive.sigstore.json"
expect_fail "tampered signature bundle" run_artifact_verify
printf 'valid-signature-bundle\n' >"$archive.sigstore.json"
printf 'tampered\n' >"$archive.attestation.sigstore.json"
expect_fail "tampered bundle" run_artifact_verify
printf 'valid-bundle\n' >"$archive.attestation.sigstore.json"
FAKE_GH_ATTESTATION_FAIL=1 expect_fail "failed GitHub attestation" run_artifact_verify

# Image promotion refuses every pre-promotion failure without creating a tag.
run_promotion() {
  local state="$1"
  mkdir -p "$state"
  : >"$state/docker.log"
  IMAGE_REPOSITORY=ghcr.io/muhdur/oraclemcp \
    VERSION=0.10.0 \
    DIGEST="$digest" \
    PUBLISH_LATEST=true \
    EXPECTED_CERTIFICATE_IDENTITY=https://github.com/MuhDur/oraclemcp/.github/workflows/release.yml@refs/tags/v0.10.0 \
    ORACLEMCP_DOCKER_BIN="$TMP/bin/docker-promote" \
    ORACLEMCP_COSIGN_BIN="$TMP/bin/cosign" \
    FAKE_DOCKER_STATE="$state" \
    FAKE_DOCKER_LOG="$state/docker.log" \
    FAKE_OTHER_DIGEST="$other_digest" \
    bash "$ROOT/scripts/promote_release_image.sh"
}

assert_no_tag_write() {
  local log="$1"
  if grep -F 'buildx imagetools create' "$log" >/dev/null; then
    fail "failure path mutated an image tag: $log"
  fi
}

state="$TMP/promote-different"
FAKE_DOCKER_MODE=different expect_fail "different immutable digest" run_promotion "$state"
assert_no_tag_write "$state/docker.log"
state="$TMP/promote-registry-error"
FAKE_DOCKER_MODE=registry-error expect_fail "registry lookup error" run_promotion "$state"
assert_no_tag_write "$state/docker.log"
state="$TMP/promote-cosign-error"
FAKE_DOCKER_MODE=missing FAKE_COSIGN_FAIL=1 expect_fail "image signature error" run_promotion "$state"
assert_no_tag_write "$state/docker.log"
state="$TMP/promote-smoke-error"
FAKE_DOCKER_MODE=missing FAKE_RUN_FAIL=1 expect_fail "digest smoke error" run_promotion "$state"
assert_no_tag_write "$state/docker.log"
state="$TMP/promote-success"
FAKE_DOCKER_MODE=missing run_promotion "$state" >/dev/null
mapfile -t creates < <(grep -F 'buildx imagetools create' "$state/docker.log")
[ "${#creates[@]}" -eq 2 ] || fail "successful promotion did not create exactly two tags"
[[ "${creates[0]}" == *'--tag ghcr.io/muhdur/oraclemcp:0.10.0 '* ]] ||
  fail "immutable version tag was not created first"
[[ "${creates[1]}" == *'--tag ghcr.io/muhdur/oraclemcp:latest '* ]] ||
  fail "latest tag was not created last"
run_line="$(grep -n '^run ' "$state/docker.log" | cut -d: -f1)"
create_line="$(grep -n -m 1 'buildx imagetools create' "$state/docker.log" | cut -d: -f1)"
[ "$run_line" -lt "$create_line" ] || fail "candidate was tagged before its smoke test"
state="$TMP/promote-idempotent"
FAKE_DOCKER_MODE=same run_promotion "$state" >/dev/null
mapfile -t creates < <(grep -F 'buildx imagetools create' "$state/docker.log")
[ "${#creates[@]}" -eq 1 ] || fail "same-digest rerun rewrote the immutable version tag"
[[ "${creates[0]}" == *'--tag ghcr.io/muhdur/oraclemcp:latest '* ]] ||
  fail "same-digest rerun did not limit mutation to latest"

# MCP validation binds the exact source/tag/main/release/image/signature tuple.
version="$(python3 "$ROOT/scripts/release_surface_manifest.py" --value server_version)"
run_mcp_verify() {
  local mode="$1"
  GITHUB_REPOSITORY=MuhDur/oraclemcp \
    VERSION="$version" \
    FAKE_SOURCE_SHA="$source_sha" \
    FAKE_MCP_DIGEST="$digest" \
    ORACLEMCP_RELEASE_ROOT="$ROOT" \
    ORACLEMCP_GIT_BIN="$TMP/bin/git" \
    ORACLEMCP_GH_BIN="$TMP/bin/gh" \
    ORACLEMCP_DOCKER_BIN="$TMP/bin/docker-mcp" \
    ORACLEMCP_COSIGN_BIN="$TMP/bin/cosign" \
    bash "$ROOT/scripts/verify_mcp_release.sh" "$mode"
}

GITHUB_OUTPUT="$TMP/mcp-output" run_mcp_verify validate >/dev/null
grep -Fx "source_sha=$source_sha" "$TMP/mcp-output" >/dev/null || fail "source SHA output missing"
grep -Fx "image_digest=$digest" "$TMP/mcp-output" >/dev/null || fail "image digest output missing"
FAKE_TAG_SHA="$other_sha" expect_fail "tag/checkout mismatch" run_mcp_verify validate
FAKE_GIT_ANCESTRY_FAIL=1 expect_fail "tag outside main" run_mcp_verify validate
FAKE_RELEASE_PRERELEASE=true expect_fail "stable version marked prerelease" run_mcp_verify validate
FAKE_COSIGN_FAIL=1 expect_fail "unsigned MCP image" run_mcp_verify validate
EXPECTED_SOURCE_SHA="$source_sha" EXPECTED_IMAGE_DIGEST="$other_digest" \
  expect_fail "digest changed before OIDC" run_mcp_verify revalidate
FAKE_COSIGN_SIGNATURE_KIND=recovery run_mcp_verify validate >/dev/null
FAKE_COSIGN_SIGNATURE_KIND=recovery FAKE_EXPECTED_RECOVERY_SOURCE_SHA="$other_sha" \
  expect_fail "recovery signature with wrong source annotation" run_mcp_verify validate
FAKE_COSIGN_SIGNATURE_KIND=recovery FAKE_EXPECTED_RECOVERY_VERSION=9.9.9 \
  expect_fail "recovery signature with wrong version annotation" run_mcp_verify validate
FAKE_COSIGN_SIGNATURE_KIND=recovery FAKE_EXPECTED_RECOVERY_VARIANT=plsql-intelligence \
  expect_fail "recovery signature with wrong variant annotation" run_mcp_verify validate

# Execute the recovery metadata step itself: prereleases must emit an exact
# empty GitHub Actions output, not an invalid image reference ending in ':'.
provenance_script="$TMP/docker-provenance-step.sh"
python3 - "$ROOT/.github/workflows/docker.yml" "$provenance_script" <<'PY'
from pathlib import Path
import sys

lines = Path(sys.argv[1]).read_text().splitlines()
name = "      - name: Verify tag commit and release metadata"
start = lines.index(name)
run = next(i for i in range(start + 1, len(lines)) if lines[i] == "        run: |")
body = []
for line in lines[run + 1:]:
    if line.startswith("      - "):
        break
    if not line:
        body.append("")
        continue
    if not line.startswith("          "):
        break
    body.append(line[10:])
Path(sys.argv[2]).write_text("\n".join(body) + "\n")
PY
provenance_bin="$TMP/provenance-bin"
mkdir -p "$provenance_bin"
cat >"$provenance_bin/git" <<'FAKE'
#!/bin/bash
set -euo pipefail
case "${1:-}" in
  show-ref) exit 0 ;;
  rev-parse) printf '%s\n' "${FAKE_SOURCE_SHA:?}" ;;
  *) exit 2 ;;
esac
FAKE
cat >"$provenance_bin/cargo" <<'FAKE'
#!/bin/bash
printf '{}\n'
FAKE
cat >"$provenance_bin/jq" <<'FAKE'
#!/bin/bash
set -euo pipefail
printf '%s\n' "${VERSION:?}"
FAKE
cat >"$provenance_bin/bash" <<'FAKE'
#!/bin/bash
exit 0
FAKE
chmod +x "$provenance_bin/"*
run_provenance_step() {
  local version_value="$1"
  local output="$2"
  : >"$output"
  PATH="$provenance_bin:$PATH" \
    VERSION="$version_value" \
    VARIANT=core \
    IMAGE_REPOSITORY=ghcr.io/muhdur/oraclemcp \
    GITHUB_OUTPUT="$output" \
    FAKE_SOURCE_SHA="$source_sha" \
    "${BASH}" "$provenance_script"
}
run_provenance_step 1.2.3-rc.1 "$TMP/prerelease-output"
grep -Fx 'rolling_image=' "$TMP/prerelease-output" >/dev/null ||
  fail "prerelease recovery did not emit an exact empty rolling output"
run_provenance_step 1.2.3 "$TMP/stable-output"
grep -Fx 'rolling_image=ghcr.io/muhdur/oraclemcp:latest' "$TMP/stable-output" >/dev/null ||
  fail "stable recovery did not emit the latest rolling image"

# Static contracts reject removal or reordering of each release gate.
bash "$ROOT/scripts/validate_release_security_workflows.sh" >/dev/null
sed "s/cosign-release: 'v3.1.2'/cosign-release: 'v2.4.1'/g" \
  "$ROOT/.github/workflows/release.yml" >"$TMP/release-cosign-v2.yml"
expect_fail "release reverted to cosign v2" env \
  ORACLEMCP_RELEASE_WORKFLOW="$TMP/release-cosign-v2.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"
# shellcheck disable=SC2016 # The workflow's shell variables must stay literal.
sed 's/--bundle "$f.sigstore.json"/--output-signature "$f.sig"/' \
  "$ROOT/.github/workflows/release.yml" >"$TMP/release-detached-signature.yml"
expect_fail "release without standardized signature bundle" env \
  ORACLEMCP_RELEASE_WORKFLOW="$TMP/release-detached-signature.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"
sed 's/npm run test:e2e:dashboard/npm run test:e2e:removed/' \
  "$ROOT/.github/workflows/release.yml" >"$TMP/release-no-browser.yml"
expect_fail "release without browser proof" env \
  ORACLEMCP_RELEASE_WORKFLOW="$TMP/release-no-browser.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"
sed '/target\/playwright\/dashboard-report/d' \
  "$ROOT/.github/workflows/release.yml" >"$TMP/release-no-browser-report.yml"
expect_fail "release without retained browser report" env \
  ORACLEMCP_RELEASE_WORKFLOW="$TMP/release-no-browser-report.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"
sed 's/push-by-digest=true/push-by-digest=false/' \
  "$ROOT/.github/workflows/release.yml" >"$TMP/release-tagged-build.yml"
expect_fail "release with mutable build tags" env \
  ORACLEMCP_RELEASE_WORKFLOW="$TMP/release-tagged-build.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"
sed 's|bash scripts/verify_release_artifacts.sh artifacts|bash scripts/disabled_artifact_check.sh artifacts|' \
  "$ROOT/.github/workflows/release.yml" >"$TMP/release-no-self-verify.yml"
expect_fail "release without artifact self-verification" env \
  ORACLEMCP_RELEASE_WORKFLOW="$TMP/release-no-self-verify.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"
# A comment is not an executable gate. This exact decoy defeated the previous
# grep-only validator while leaving all expected text in the workflow.
sed 's|run: bash scripts/verify_release_artifacts.sh artifacts|run: true # bash scripts/verify_release_artifacts.sh artifacts|' \
  "$ROOT/.github/workflows/release.yml" >"$TMP/release-comment-decoy.yml"
expect_fail "artifact verifier present only in a comment" env \
  ORACLEMCP_RELEASE_WORKFLOW="$TMP/release-comment-decoy.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"

python3 - "$ROOT/.github/workflows/release.yml" "$TMP/release-wrong-job.yml" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text()
command = "run: bash scripts/verify_release_artifacts.sh artifacts"
source = source.replace(command, "run: true", 1)
source = source.replace(
    "    steps:\n",
    "    steps:\n      - run: bash scripts/verify_release_artifacts.sh artifacts\n",
    1,
)
Path(sys.argv[2]).write_text(source)
PY
expect_fail "artifact verifier moved to the wrong job" env \
  ORACLEMCP_RELEASE_WORKFLOW="$TMP/release-wrong-job.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"

sed 's@run: bash scripts/verify_release_artifacts.sh artifacts@run: bash scripts/verify_release_artifacts.sh artifacts || true@' \
  "$ROOT/.github/workflows/release.yml" >"$TMP/release-shell-suffix.yml"
expect_fail "artifact verifier masked by a shell suffix" env \
  ORACLEMCP_RELEASE_WORKFLOW="$TMP/release-shell-suffix.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"
python3 - "$ROOT/.github/workflows/release.yml" "$TMP/release-disabled-step.yml" \
  "$TMP/release-continue-on-error.yml" "$TMP/release-shell-decoy.yml" \
  "$TMP/release-quoted-if.yml" "$TMP/release-empty-single-if.yml" \
  "$TMP/release-empty-double-if.yml" "$TMP/release-null-if.yml" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text()
command = "        run: bash scripts/verify_release_artifacts.sh artifacts\n"
assert source.count(command) == 1
Path(sys.argv[2]).write_text(source.replace(command, command + "        if: false\n"))
Path(sys.argv[3]).write_text(
    source.replace(command, command + "        continue-on-error: true\n")
)
Path(sys.argv[4]).write_text(source.replace(
    command,
    "        run: |\n"
    "          true\n"
    "          bash scripts/verify_release_artifacts.sh artifacts\n",
))
Path(sys.argv[5]).write_text(source.replace(command, command + '        "if": false\n'))
Path(sys.argv[6]).write_text(source.replace(command, command + "        if: ''\n"))
Path(sys.argv[7]).write_text(source.replace(command, command + '        if: ""\n'))
Path(sys.argv[8]).write_text(source.replace(command, command + "        if:\n"))
PY
expect_fail "disabled artifact verifier step" env \
  ORACLEMCP_RELEASE_WORKFLOW="$TMP/release-disabled-step.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"
expect_fail "continue-on-error artifact verifier step" env \
  ORACLEMCP_RELEASE_WORKFLOW="$TMP/release-continue-on-error.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"
expect_fail "artifact command present only after a successful decoy" env \
  ORACLEMCP_RELEASE_WORKFLOW="$TMP/release-shell-decoy.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"
expect_fail "artifact verifier disabled by a quoted YAML if key" env \
  ORACLEMCP_RELEASE_WORKFLOW="$TMP/release-quoted-if.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"
expect_fail "artifact verifier disabled by an empty single-quoted condition" env \
  ORACLEMCP_RELEASE_WORKFLOW="$TMP/release-empty-single-if.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"
expect_fail "artifact verifier disabled by an empty double-quoted condition" env \
  ORACLEMCP_RELEASE_WORKFLOW="$TMP/release-empty-double-if.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"
expect_fail "artifact verifier disabled by a null condition" env \
  ORACLEMCP_RELEASE_WORKFLOW="$TMP/release-null-if.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"

sed 's|bash scripts/verify_mcp_release.sh revalidate|bash scripts/verify_mcp_release.sh disabled|' \
  "$ROOT/.github/workflows/publish-mcp.yml" >"$TMP/mcp-no-revalidate.yml"
expect_fail "MCP publish without revalidation" env \
  ORACLEMCP_MCP_WORKFLOW="$TMP/mcp-no-revalidate.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"
sed 's|bash scripts/verify_mcp_release.sh revalidate|bash scripts/verify_mcp_release.sh disabled|' \
  "$ROOT/.github/workflows/release.yml" >"$TMP/release-mcp-no-revalidate.yml"
expect_fail "normal MCP publish without exact digest revalidation" env \
  ORACLEMCP_RELEASE_WORKFLOW="$TMP/release-mcp-no-revalidate.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"
# shellcheck disable=SC2016 # Workflow shell variables must remain literal.
sed 's@\[ "$GITHUB_REF" = "refs/heads/main" \] || {@true || {@' \
  "$ROOT/.github/workflows/docker.yml" >"$TMP/docker-non-main-policy.yml"
expect_fail "manual Docker policy without main-ref gate" env \
  ORACLEMCP_DOCKER_WORKFLOW="$TMP/docker-non-main-policy.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"

# Quoted YAML job keys are semantically ordinary keys. They must not let a
# weakened verify-release job borrow an exact guard from a later post-mutation
# promote step.
python3 - "$ROOT/.github/workflows/docker.yml" "$TMP/docker-quoted-promote.yml" \
  "$TMP/docker-single-quoted-promote.yml" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text()
guard = '          [ "$GITHUB_REF" = "refs/heads/main" ] || {\n'
assert source.count(guard) == 1
source = source.replace(guard, "          true || {\n")
promote = "  promote:\n"
record = "      - name: Record immutable provenance\n"
assert source.count(promote) == 1
assert source.count(record) == 1
late_guard = (
    "      - name: Late main-ref decoy after tag mutation\n"
    "        shell: bash\n"
    "        run: |\n"
    "          set -euo pipefail\n"
    + guard
    + "            exit 1\n"
    + "          }\n\n"
)
source = source.replace(record, late_guard + record)
Path(sys.argv[2]).write_text(source.replace(promote, '  "promote":\n'))
Path(sys.argv[3]).write_text(source.replace(promote, "  'promote':\n"))
PY
expect_fail "double-quoted next job cannot lend a late main-ref guard" env \
  ORACLEMCP_DOCKER_WORKFLOW="$TMP/docker-quoted-promote.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"
expect_fail "single-quoted next job cannot lend a late main-ref guard" env \
  ORACLEMCP_DOCKER_WORKFLOW="$TMP/docker-single-quoted-promote.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"

# shellcheck disable=SC2016 # Workflow shell variables must remain literal.
sed 's/rolling_image=""/rolling_image="$IMAGE_REPOSITORY:$stable_rolling"/' \
  "$ROOT/.github/workflows/docker.yml" >"$TMP/docker-prerelease-latest.yml"
expect_fail "prerelease recovery can move rolling tag" env \
  ORACLEMCP_DOCKER_WORKFLOW="$TMP/docker-prerelease-latest.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"
sed 's/group: docker-provenance-v${{ inputs.version }}-${{ inputs.variant }}/group: docker-recovery-${{ inputs.version }}/' \
  "$ROOT/.github/workflows/docker.yml" >"$TMP/docker-unserialized.yml"
expect_fail "manual recovery not serialized with normal release" env \
  ORACLEMCP_DOCKER_WORKFLOW="$TMP/docker-unserialized.yml" \
  bash "$ROOT/scripts/validate_release_security_workflows.sh"

# Mutable actions are accepted only for first-party actions in ordinary
# read-only jobs. Write/OIDC jobs and release workflows require full SHAs.
mkdir -p "$TMP/pins"
cat >"$TMP/pins/ci.yml" <<'YAML'
name: Read only
on: [push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v7
YAML
ORACLEMCP_WORKFLOW_ROOT="$TMP/pins" \
  bash "$ROOT/scripts/workflow_supply_chain_check.sh" --action-pins-only
cat >"$TMP/pins/write.yml" <<'YAML'
name: OIDC writer
on: [workflow_dispatch]
permissions:
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@v7
YAML
expect_fail "mutable first-party action in OIDC job" env \
  ORACLEMCP_WORKFLOW_ROOT="$TMP/pins" \
  bash "$ROOT/scripts/workflow_supply_chain_check.sh" --action-pins-only
sed -i 's|actions/checkout@v7|actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1|' \
  "$TMP/pins/write.yml"
ORACLEMCP_WORKFLOW_ROOT="$TMP/pins" \
  bash "$ROOT/scripts/workflow_supply_chain_check.sh" --action-pins-only
cat >"$TMP/pins/global-write.yml" <<'YAML'
name: Inherited OIDC writer
on: [workflow_dispatch]
permissions:
  contents: read
  id-token: write
jobs:
  publish:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v7
YAML
expect_fail "mutable first-party action with inherited OIDC" env \
  ORACLEMCP_WORKFLOW_ROOT="$TMP/pins" \
  bash "$ROOT/scripts/workflow_supply_chain_check.sh" --action-pins-only
sed -i 's|actions/checkout@v7|actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1|' \
  "$TMP/pins/global-write.yml"
ORACLEMCP_WORKFLOW_ROOT="$TMP/pins" \
  bash "$ROOT/scripts/workflow_supply_chain_check.sh" --action-pins-only
cat >"$TMP/pins/inline-write.yml" <<'YAML'
name: Inline writer
on: [workflow_dispatch]
permissions: { contents: read, id-token: write }
jobs:
  publish:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v7
YAML
expect_fail "mutable first-party action with inline OIDC" env \
  ORACLEMCP_WORKFLOW_ROOT="$TMP/pins" \
  bash "$ROOT/scripts/workflow_supply_chain_check.sh" --action-pins-only
sed -i 's|actions/checkout@v7|actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1|' \
  "$TMP/pins/inline-write.yml"
ORACLEMCP_WORKFLOW_ROOT="$TMP/pins" \
  bash "$ROOT/scripts/workflow_supply_chain_check.sh" --action-pins-only
cat >"$TMP/pins/third-party.yml" <<'YAML'
name: Third party
on: [push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - uses: example/action@v1
YAML
expect_fail "mutable third-party action" env \
  ORACLEMCP_WORKFLOW_ROOT="$TMP/pins" \
  bash "$ROOT/scripts/workflow_supply_chain_check.sh" --action-pins-only

echo "release-workflow-security-test: OK hermetic release failure paths"
