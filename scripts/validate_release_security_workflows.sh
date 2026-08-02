#!/usr/bin/env bash
# Static release-workflow contracts for browser, registry, and artifact trust boundaries.
# shellcheck disable=SC2016 # Fixed strings intentionally contain GitHub expression syntax.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_WORKFLOW="${ORACLEMCP_RELEASE_WORKFLOW:-$ROOT/.github/workflows/release.yml}"
MCP_WORKFLOW="${ORACLEMCP_MCP_WORKFLOW:-$ROOT/.github/workflows/publish-mcp.yml}"
DOCKER_WORKFLOW="${ORACLEMCP_DOCKER_WORKFLOW:-$ROOT/.github/workflows/docker.yml}"

fail() {
  echo "release-security-workflows: $*" >&2
  exit 1
}

require() {
  local file="$1"
  local needle="$2"
  grep -F -- "$needle" "$file" >/dev/null ||
    fail "$(basename "$file") is missing required contract: $needle"
}

require_exact() {
  local file="$1"
  local needle="$2"
  grep -Fx -- "$needle" "$file" >/dev/null ||
    fail "$(basename "$file") is missing required exact contract: $needle"
}

forbid() {
  local file="$1"
  local needle="$2"
  if grep -F -- "$needle" "$file" >/dev/null; then
    fail "$(basename "$file") contains forbidden contract: $needle"
  fi
}

line_of() {
  local file="$1"
  local needle="$2"
  local line
  line="$(grep -nF -- "$needle" "$file" | head -n 1 | cut -d: -f1)"
  [ -n "$line" ] || fail "cannot order missing contract in $(basename "$file"): $needle"
  printf '%s\n' "$line"
}

before() {
  local file="$1"
  local first="$2"
  local second="$3"
  [ "$(line_of "$file" "$first")" -lt "$(line_of "$file" "$second")" ] ||
    fail "expected '$first' before '$second' in $(basename "$file")"
}

# Parse the narrow GitHub Actions job/step shape we rely on without a third-party
# YAML dependency. Required commands must occupy an enabled, fail-closed step;
# comments, suffixes, disabled steps, and continue-on-error decoys do not count.
require_job_run_contract() {
  local file="$1"
  local job="$2"
  local command="$3"
  local later_step="${4:-}"
  local mode="$5"
  if ! python3 - "$file" "$job" "$command" "$later_step" "$mode" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
job_name, command, later_name, mode = sys.argv[2:6]
lines = path.read_text(encoding="utf-8").splitlines()


def strip_comment(text: str) -> str:
    quote = None
    escaped = False
    for index, character in enumerate(text):
        if quote == '"' and escaped:
            escaped = False
            continue
        if quote == '"' and character == "\\":
            escaped = True
            continue
        if character in {"'", '"'}:
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
            continue
        if character == "#" and quote is None:
            return text[:index].rstrip()
    return text.rstrip()


def scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def step_mapping(text: str) -> tuple[str, str] | None:
    text = strip_comment(text).strip()
    if not text:
        return None
    match = re.fullmatch(r"([A-Za-z0-9_-]+):\s*(.*)", text)
    if not match:
        # Quoted or otherwise exotic YAML keys can be semantically equivalent
        # to security-relevant fields such as `if`. Refuse shapes this narrow
        # parser cannot classify instead of silently treating the step as safe.
        raise SystemExit(1)
    return match.groups()


start = next(
    (index for index, raw in enumerate(lines) if re.fullmatch(rf"  {re.escape(job_name)}:\s*(?:#.*)?", raw)),
    None,
)
if start is None:
    raise SystemExit(1)
end = len(lines)
for index in range(start + 1, len(lines)):
    raw = lines[index]
    if not raw.startswith("  ") or raw.startswith("    "):
        continue
    boundary = strip_comment(raw[2:]).strip()
    if not boundary:
        continue
    if not re.fullmatch(r"[A-Za-z0-9_-]+:", boundary):
        # Every exact two-space mapping under `jobs` is a job boundary. A
        # quoted key is YAML-equivalent but cannot be allowed to merge the
        # following job's steps into the job whose contract we are checking.
        raise SystemExit(1)
    end = index
    break

steps_start = next(
    (index for index in range(start + 1, end) if re.fullmatch(r"    steps:\s*(?:#.*)?", lines[index])),
    None,
)
if steps_start is None:
    raise SystemExit(1)

step_fields = {
    "name",
    "run",
    "uses",
    "if",
    "continue-on-error",
    "shell",
    "working-directory",
}
steps: list[dict[str, str | list[str] | None]] = []
current: dict[str, str | list[str] | None] | None = None
block_run = False
for raw in lines[steps_start + 1 : end]:
    if re.match(r"^      -(?:\s|$)", raw):
        current = {
            "name": "",
            "run": [],
            "uses": None,
            "if": None,
            "continue-on-error": None,
            "shell": None,
            "working-directory": None,
        }
        steps.append(current)
        block_run = False
        tail = raw[7:].lstrip()
        mapping = step_mapping(tail)
        if mapping:
            key, value = mapping
            if key in step_fields:
                current[key] = scalar(value)
            if key == "run":
                if value in {"|", "|-", ">", ">-"}:
                    current["run"] = []
                    block_run = True
        continue
    if current is None:
        continue
    if block_run and re.match(r"^          ", raw):
        executable = strip_comment(raw[10:]).strip()
        if executable:
            assert isinstance(current["run"], list)
            current["run"].append(executable)
        continue
    block_run = False
    if not raw.startswith("        ") or raw.startswith("          "):
        continue
    mapping = step_mapping(raw[8:])
    if mapping is None:
        continue
    key, value = mapping
    if key not in step_fields:
        continue
    current[key] = scalar(value)
    if key == "run":
        if value in {"|", "|-", ">", ">-"}:
            current["run"] = []
            block_run = True

def run_lines(step: dict[str, str | list[str] | None]) -> list[str]:
    value = step["run"]
    if isinstance(value, list):
        return value
    return [value] if isinstance(value, str) else []


def fail_closed(step: dict[str, str | list[str] | None]) -> bool:
    return (
        step["uses"] is None
        and step["if"] is None
        and step["continue-on-error"] in {None, "false"}
        and step["shell"] in {None, "bash"}
        and step["working-directory"] is None
    )


def matches(step: dict[str, str | list[str] | None]) -> bool:
    if not fail_closed(step):
        return False
    executable = run_lines(step)
    if mode == "exact":
        return executable == [command]
    if mode == "line":
        return command in executable and "set -euo pipefail" in executable
    raise SystemExit(2)


command_indexes = [index for index, step in enumerate(steps) if matches(step)]
if not command_indexes:
    raise SystemExit(1)
if later_name:
    later_indexes = [
        index for index, step in enumerate(steps) if step["name"] == later_name
    ]
    if not later_indexes or min(command_indexes) >= min(later_indexes):
        raise SystemExit(1)
PY
  then
    fail "$(basename "$file") lacks enabled fail-closed '$command' in job '$job'${later_step:+ before step '$later_step'}"
  fi
}

require_job_run() {
  require_job_run_contract "$1" "$2" "$3" "${4:-}" exact
}

require_job_run_line() {
  require_job_run_contract "$1" "$2" "$3" "${4:-}" line
}

for workflow in "$RELEASE_WORKFLOW" "$MCP_WORKFLOW" "$DOCKER_WORKFLOW"; do
  [ -f "$workflow" ] || fail "missing workflow: $workflow"
  require "$workflow" "cosign-release: 'v3.1.2'"
  forbid "$workflow" "cosign-release: 'v2.4.1'"
done
command -v python3 >/dev/null || fail "missing required command: python3"
for helper in \
  "$ROOT/scripts/promote_release_image.sh" \
  "$ROOT/scripts/verify_mcp_release.sh" \
  "$ROOT/scripts/verify_release_artifacts.sh"; do
  [ -x "$helper" ] || fail "missing executable release helper: $helper"
done

# A release cannot package an untested dashboard. Browser diagnostics survive
# failed Playwright runs so the gate is debuggable rather than silently red.
require "$RELEASE_WORKFLOW" 'npx playwright install --with-deps chromium'
require "$RELEASE_WORKFLOW" 'npm run test:e2e:dashboard -- --reporter=line,html'
require "$RELEASE_WORKFLOW" 'name: Retain dashboard Chromium failure evidence'
require "$RELEASE_WORKFLOW" 'if: failure()'
require_exact "$RELEASE_WORKFLOW" '            target/playwright/dashboard'
require_exact "$RELEASE_WORKFLOW" '            target/playwright/dashboard-report'
before "$RELEASE_WORKFLOW" 'npm run test:e2e:dashboard' 'bash scripts/dashboard_bundle_check.sh'
before "$RELEASE_WORKFLOW" 'npm run test:e2e:dashboard' 'name: Upload build artifacts'

# Normal image publishing writes an untagged digest, then verifies and smokes
# that digest before the helper creates the immutable version tag and, last,
# the rolling latest tag.
require "$RELEASE_WORKFLOW" 'push-by-digest=true,name-canonical=true,push=true'
require "$RELEASE_WORKFLOW" 'subject-digest: ${{ steps.build.outputs.digest }}'
require "$RELEASE_WORKFLOW" 'cosign sign --recursive "ghcr.io/muhdur/oraclemcp@${{ steps.build.outputs.digest }}"'
require "$RELEASE_WORKFLOW" 'run: bash scripts/promote_release_image.sh'
forbid "$RELEASE_WORKFLOW" 'tags: ${{ steps.tags.outputs.tags }}'
before "$RELEASE_WORKFLOW" 'Build and push candidate by digest' 'Attest image build provenance'
before "$RELEASE_WORKFLOW" 'Attest image build provenance' 'Sign image (keyless)'
before "$RELEASE_WORKFLOW" 'Sign image (keyless)' 'Verify, smoke, and promote release image'

# The recovery lane follows the same mutation ordering for both rollback and
# exact rebuild operations.
require "$DOCKER_WORKFLOW" 'name: Smoke verified immutable digest'
require "$DOCKER_WORKFLOW" 'image="$IMAGE_REPOSITORY@$DIGEST"'
before "$DOCKER_WORKFLOW" 'Smoke verified immutable digest' 'Publish missing immutable version tag'
before "$DOCKER_WORKFLOW" 'Smoke verified immutable digest' 'Promote verified digest to rolling tag'

# Every archive checksum and every archive/SBOM proof is verified against exact
# bytes and workflow identity before action-gh-release can upload any payload.
require "$RELEASE_WORKFLOW" 'run: bash scripts/verify_release_artifacts.sh artifacts'
require "$RELEASE_WORKFLOW" 'GH_TOKEN: ${{ github.token }}'
require "$RELEASE_WORKFLOW" 'EXPECTED_CERTIFICATE_IDENTITY: https://github.com/${{ github.repository }}/.github/workflows/release.yml@${{ github.ref }}'
require "$RELEASE_WORKFLOW" '--bundle "$f.sigstore.json"'
require_exact "$RELEASE_WORKFLOW" '            artifacts/*.tar.gz.sigstore.json'
require_exact "$RELEASE_WORKFLOW" '            artifacts/*.zip.sigstore.json'
require_exact "$RELEASE_WORKFLOW" '            artifacts/*.cdx.json.sigstore.json'
forbid "$RELEASE_WORKFLOW" '--output-signature'
forbid "$RELEASE_WORKFLOW" '--output-certificate'
before "$RELEASE_WORKFLOW" 'Verify release payloads and proofs before upload' 'Publish release with checksums, SBOM, and signatures'
require_job_run "$RELEASE_WORKFLOW" release \
  'bash scripts/verify_release_artifacts.sh artifacts' \
  'Publish release with checksums, SBOM, and signatures'
forbid "$ROOT/docs/operations.md" '`*.sig` / `*.crt`'
forbid "$ROOT/docs/operations.md" '--signature   "oraclemcp-'

# Manual MCP publication starts from an explicit stable version, checks out
# its exact tag in every job, and revalidates the carried source/digest before
# the first OIDC credential is requested.
require "$MCP_WORKFLOW" 'description: "Existing stable release version to publish (without v)."'
require "$MCP_WORKFLOW" 'group: publish-mcp-${{ inputs.version }}'
require "$MCP_WORKFLOW" 'ref: refs/tags/v${{ inputs.version }}'
require "$MCP_WORKFLOW" 'ref: refs/tags/v${{ needs.validate.outputs.version }}'
require "$MCP_WORKFLOW" 'run: bash scripts/verify_mcp_release.sh validate'
require "$MCP_WORKFLOW" 'EXPECTED_SOURCE_SHA: ${{ needs.validate.outputs.source_sha }}'
require "$MCP_WORKFLOW" 'EXPECTED_IMAGE_DIGEST: ${{ needs.validate.outputs.image_digest }}'
require "$MCP_WORKFLOW" 'run: bash scripts/verify_mcp_release.sh revalidate'
before "$MCP_WORKFLOW" 'Bind tag, source, release, and signed image' 'id-token: write'
before "$MCP_WORKFLOW" 'Revalidate exact release before OIDC login' 'Authenticate to the MCP Registry (GitHub OIDC)'
require_job_run "$MCP_WORKFLOW" validate 'bash scripts/verify_mcp_release.sh validate'
require_job_run "$MCP_WORKFLOW" publish \
  'bash scripts/verify_mcp_release.sh revalidate' \
  'Authenticate to the MCP Registry (GitHub OIDC)'

# The normal tag pipeline carries the exact source and image digest out of the
# serialized Docker job and revalidates both immediately before MCP OIDC login.
require "$RELEASE_WORKFLOW" 'group: docker-provenance-${{ github.ref_name }}-core'
require "$DOCKER_WORKFLOW" 'group: docker-provenance-v${{ inputs.version }}-${{ inputs.variant }}'
require "$RELEASE_WORKFLOW" 'EXPECTED_SOURCE_SHA: ${{ needs.docker.outputs.source_sha }}'
require "$RELEASE_WORKFLOW" 'EXPECTED_IMAGE_DIGEST: ${{ needs.docker.outputs.image_digest }}'
require_job_run "$RELEASE_WORKFLOW" publish-mcp-registry \
  'bash scripts/verify_mcp_release.sh revalidate' \
  'Authenticate to the MCP Registry (GitHub OIDC)'

# Manual recovery policy is main-only. Prereleases may repair their immutable
# version tag but cannot move either production rolling tag.
require_job_run_line "$DOCKER_WORKFLOW" verify-release \
  '[ "$GITHUB_REF" = "refs/heads/main" ] || {'
require "$DOCKER_WORKFLOW" 'if [[ "$VERSION" == *-* ]]; then'
require "$DOCKER_WORKFLOW" 'rolling_image=""'
require "$DOCKER_WORKFLOW" 'echo "rolling_image=$rolling_image"'
require "$DOCKER_WORKFLOW" "if: needs.verify-release.outputs.rolling_image != ''"

echo "release-security-workflows: OK dashboard, MCP, image, artifact, and recovery contracts"
