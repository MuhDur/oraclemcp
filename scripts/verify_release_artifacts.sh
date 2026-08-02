#!/usr/bin/env bash
# Verify exact release payload bytes and every proof before GitHub upload.
set -euo pipefail

fail() {
  echo "verify-release-artifacts: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

artifact_dir="${1:-artifacts}"
cosign_bin="${ORACLEMCP_COSIGN_BIN:-cosign}"
gh_bin="${ORACLEMCP_GH_BIN:-gh}"
repository="${GITHUB_REPOSITORY:-}"
source_ref="${GITHUB_REF:-}"
source_digest="${GITHUB_SHA:-}"
certificate_identity="${EXPECTED_CERTIFICATE_IDENTITY:-}"
oidc_issuer="${EXPECTED_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

[ -d "$artifact_dir" ] || fail "missing artifact directory: $artifact_dir"
[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
  fail "GITHUB_REPOSITORY must be owner/repository"
[[ "$source_ref" == refs/tags/v* ]] || fail "GITHUB_REF must be an immutable release tag"
[[ "$source_digest" =~ ^[0-9a-f]{40}$ ]] || fail "GITHUB_SHA must be a commit SHA"
[ -n "$certificate_identity" ] || fail "EXPECTED_CERTIFICATE_IDENTITY is required"
need "$cosign_bin"
need "$gh_bin"
need sha256sum

shopt -s nullglob
payloads=("$artifact_dir"/*.tar.gz "$artifact_dir"/*.zip "$artifact_dir"/*.cdx.json)
[ "${#payloads[@]}" -gt 0 ] || fail "no release archives or SBOM found in $artifact_dir"
saw_archive=false
saw_sbom=false

for payload in "${payloads[@]}"; do
  [ -s "$payload" ] || fail "release payload is missing or empty: $payload"
  case "$payload" in
    *.tar.gz | *.zip)
      saw_archive=true
      checksum="$payload.sha256"
      [ -s "$checksum" ] || fail "missing checksum: $checksum"
      mapfile -t checksum_records < <(sed '/^[[:space:]]*$/d' "$checksum")
      [ "${#checksum_records[@]}" -eq 1 ] ||
        fail "$checksum must contain exactly one checksum record"
      [[ "${checksum_records[0]}" =~ ^([0-9A-Fa-f]{64})[[:space:]]+\*?([^[:space:]]+)$ ]] ||
        fail "$checksum contains a malformed checksum record"
      declared_hash="$(printf '%s' "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')"
      declared_name="${BASH_REMATCH[2]}"
      [ "$declared_name" = "$(basename "$payload")" ] ||
        fail "$checksum names $declared_name instead of $(basename "$payload")"
      actual_hash="$(sha256sum "$payload" | awk '{print $1}')"
      [ "$actual_hash" = "$declared_hash" ] ||
        fail "checksum mismatch for $payload"
      ;;
    *.cdx.json) saw_sbom=true ;;
  esac

  signature_bundle="$payload.sigstore.json"
  attestation_bundle="$payload.attestation.sigstore.json"
  [ -s "$signature_bundle" ] || fail "missing signature bundle: $signature_bundle"
  [ -s "$attestation_bundle" ] || fail "missing attestation bundle: $attestation_bundle"

  "$cosign_bin" verify-blob \
    --bundle "$signature_bundle" \
    --certificate-identity "$certificate_identity" \
    --certificate-oidc-issuer "$oidc_issuer" \
    "$payload" >/dev/null || fail "cosign signature verification failed for $payload"
  "$cosign_bin" verify-blob-attestation \
    --bundle "$attestation_bundle" \
    --type slsaprovenance1 \
    --certificate-identity "$certificate_identity" \
    --certificate-oidc-issuer "$oidc_issuer" \
    "$payload" >/dev/null || fail "cosign attestation verification failed for $payload"
  "$gh_bin" attestation verify "$payload" \
    --repo "$repository" \
    --signer-workflow "$repository/.github/workflows/release.yml" \
    --source-ref "$source_ref" \
    --source-digest "$source_digest" \
    --cert-identity "$certificate_identity" \
    --cert-oidc-issuer "$oidc_issuer" >/dev/null ||
    fail "GitHub provenance attestation verification failed for $payload"
done

[ "$saw_archive" = "true" ] || fail "release payload set contains no archive"
[ "$saw_sbom" = "true" ] || fail "release payload set contains no SBOM"

echo "verify-release-artifacts: OK payloads=${#payloads[@]} identity=$certificate_identity"
