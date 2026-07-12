#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

failures=0
while IFS=: read -r file line_number source; do
  ref="${source#*uses:}"
  ref="${ref%%#*}"
  ref="$(printf '%s' "$ref" | xargs)"
  case "$ref" in
    ./* | docker://* | actions/*@*) continue ;;
  esac
  revision="${ref##*@}"
  if [[ ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then
    echo "$file:$line_number: remote action is not pinned to a full commit SHA: $ref" >&2
    failures=1
  fi
done < <(grep -RInE --include='*.yml' --include='*.yaml' \
  '^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*[^[:space:]#]+' .github/workflows)

if grep -RInE --include='*.yml' --include='*.yaml' \
  'releases/latest|curl[^|]*\|[[:space:]]*(sh|bash|tar)' .github/workflows; then
  echo "workflow contains a mutable executable download or curl pipeline" >&2
  failures=1
fi

# Publication authority is job-scoped. Any new OIDC/package writer must be
# reviewed and added by its exact workflow and job name, never inherited by a
# build or test job.
for workflow in .github/workflows/*.yml; do
  current_job=""
  while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]{2}([a-zA-Z0-9_-]+):[[:space:]]*$ ]]; then
      current_job="${BASH_REMATCH[1]}"
    fi
    if [[ "$line" =~ ^[[:space:]]{6}(id-token|packages):[[:space:]]write([[:space:]]|$) ]]; then
      permission="${BASH_REMATCH[1]}"
      authority="${workflow}:${current_job}:${permission}"
      case "$authority" in
        .github/workflows/docker.yml:promote:id-token | \
          .github/workflows/docker.yml:promote:packages | \
          .github/workflows/publish-mcp.yml:publish:id-token | \
          .github/workflows/publish-npm.yml:publish:id-token | \
          .github/workflows/release.yml:release:id-token | \
          .github/workflows/release.yml:docker:id-token | \
          .github/workflows/release.yml:docker:packages | \
          .github/workflows/release.yml:publish-mcp-registry:id-token) ;;
        *)
          echo "$workflow: unapproved publication authority in job $current_job: $permission: write" >&2
          failures=1
          ;;
      esac
    fi
  done <"$workflow"
done

installer_calls="$(grep -lE 'bash scripts/install_mcp_publisher\.sh' \
  .github/workflows/release.yml .github/workflows/publish-mcp.yml | wc -l | tr -d '[:space:]')"
if [[ "$installer_calls" != "2" ]]; then
  echo "both MCP publication workflows must use the pinned publisher installer" >&2
  failures=1
fi

# Exercise every published upstream platform tuple and both checksum outcomes.
source scripts/install_mcp_publisher.sh
for platform in \
  darwin_amd64 darwin_arm64 linux_amd64 linux_arm64 windows_amd64 windows_arm64; do
  IFS=_ read -r os arch <<<"$platform"
  metadata="$(mcp_publisher_platform "$os" "$arch")"
  IFS=$'\t' read -r artifact digest executable <<<"$metadata"
  [[ "$artifact" == "mcp-publisher_${platform}.tar.gz" ]] || {
    echo "incorrect artifact mapping for $platform" >&2
    failures=1
  }
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || {
    echo "invalid digest mapping for $platform" >&2
    failures=1
  }
  [[ -n "$executable" ]] || {
    echo "missing executable mapping for $platform" >&2
    failures=1
  }
done

fixture="scripts/install_mcp_publisher.sh"
fixture_digest="$(sha256_file "$fixture")"
verify_sha256 "$fixture" "$fixture_digest"
if verify_sha256 "$fixture" "$(printf '0%.0s' {1..64})" >/dev/null 2>&1; then
  echo "wrong publisher digest was accepted" >&2
  failures=1
fi

verify_line="$(grep -nE '^[[:space:]]*verify_sha256 \"\$archive\"' scripts/install_mcp_publisher.sh | cut -d: -f1)"
extract_line="$(grep -nE '^[[:space:]]*tar -xzf \"\$archive\"' scripts/install_mcp_publisher.sh | cut -d: -f1)"
if [[ -z "$verify_line" || -z "$extract_line" || "$verify_line" -ge "$extract_line" ]]; then
  echo "publisher archive must be verified before extraction" >&2
  failures=1
fi

exit "$failures"
