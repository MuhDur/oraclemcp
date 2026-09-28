#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016 # Intentional local source and literal contract regexes.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

mode="${1:-}"
case "$mode" in
  "" | --action-pins-only) ;;
  *) echo "workflow-supply-chain: usage: $0 [--action-pins-only]" >&2; exit 2 ;;
esac
workflow_root="${ORACLEMCP_WORKFLOW_ROOT:-.github/workflows}"
[ -d "$workflow_root" ] || {
  echo "workflow-supply-chain: missing workflow directory: $workflow_root" >&2
  exit 2
}

# CI taxonomy is derived from the workflow source itself. It fails closed on
# duplicate YAML mapping keys (notably duplicate step-level `with:` blocks),
# missing explicit permission policy, missing job timeouts, and drift from the
# committed cross-repo ci-taxonomy/v1 document.
if [ -z "$mode" ]; then
  python3 scripts/ci_taxonomy.py --check
fi

failures=0

check_action_pins() {
  local root="$1"
  local workflow current_job line line_number ref revision key permission trust_workflow
  local in_jobs in_permissions
  local -A privileged_jobs=()
  local -A privileged_workflows=()
  local -a workflows=("$root"/*.yml "$root"/*.yaml)

  # First-party version tags remain allowed in ordinary read-only jobs. Any job
  # holding a write permission (including OIDC or attestations), and every job
  # in the release-capable workflows, is a privileged trust boundary and must
  # pin actions/* to an immutable reviewed commit SHA.
  for workflow in "${workflows[@]}"; do
    [ -f "$workflow" ] || continue
    current_job=""
    in_jobs=false
    in_permissions=false
    while IFS= read -r line; do
      if [[ "$line" =~ ^jobs:[[:space:]]*$ ]]; then
        in_jobs=true
        in_permissions=false
        continue
      fi
      if [ "$in_jobs" = false ]; then
        if [[ "$line" =~ ^permissions:[[:space:]]*write-all([[:space:]]|$) ]]; then
          privileged_workflows["$workflow"]="write-all"
          continue
        fi
        if [[ "$line" =~ ^permissions:[[:space:]]*\{.*:[[:space:]]*write([[:space:],}]|$) ]]; then
          privileged_workflows["$workflow"]="inline-write"
          continue
        fi
        if [[ "$line" =~ ^permissions:[[:space:]]*$ ]]; then
          in_permissions=true
          continue
        fi
        if [ "$in_permissions" = true ] &&
          [[ "$line" =~ ^[[:space:]]{2}([a-zA-Z0-9_-]+):[[:space:]]write([[:space:]]|$) ]]; then
          privileged_workflows["$workflow"]="${BASH_REMATCH[1]}"
          continue
        fi
        if [ "$in_permissions" = true ] && [[ "$line" =~ ^[^[:space:]#] ]]; then
          in_permissions=false
        fi
        continue
      fi
      if [[ "$line" =~ ^[[:space:]]{2}([a-zA-Z0-9_-]+):[[:space:]]*$ ]]; then
        current_job="${BASH_REMATCH[1]}"
        in_permissions=false
        continue
      fi
      if [[ "$line" =~ ^[[:space:]]{4}permissions:[[:space:]]*write-all([[:space:]]|$) ]]; then
        privileged_jobs["$workflow:$current_job"]="write-all"
        continue
      fi
      if [[ "$line" =~ ^[[:space:]]{4}permissions:[[:space:]]*\{.*:[[:space:]]*write([[:space:],}]|$) ]]; then
        privileged_jobs["$workflow:$current_job"]="inline-write"
        continue
      fi
      if [[ "$line" =~ ^[[:space:]]{4}permissions:[[:space:]]*$ ]]; then
        in_permissions=true
        continue
      fi
      if [ "$in_permissions" = true ] &&
        [[ "$line" =~ ^[[:space:]]{6}([a-zA-Z0-9_-]+):[[:space:]]write([[:space:]]|$) ]]; then
        permission="${BASH_REMATCH[1]}"
        privileged_jobs["$workflow:$current_job"]="$permission"
        continue
      fi
      if [ "$in_permissions" = true ] && [[ "$line" =~ ^[[:space:]]{4}[^[:space:]#] ]]; then
        in_permissions=false
      fi
    done <"$workflow"
  done

  for workflow in "${workflows[@]}"; do
    [ -f "$workflow" ] || continue
    case "$(basename "$workflow")" in
      release.yml | publish-mcp.yml | docker.yml) trust_workflow=true ;;
      *) trust_workflow=false ;;
    esac
    current_job=""
    line_number=0
    while IFS= read -r line; do
      line_number=$((line_number + 1))
      if [[ "$line" =~ ^[[:space:]]{2}([a-zA-Z0-9_-]+):[[:space:]]*$ ]]; then
        current_job="${BASH_REMATCH[1]}"
      fi
      if [[ ! "$line" =~ ^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*([^[:space:]#]+) ]]; then
        continue
      fi
      ref="${BASH_REMATCH[1]}"
      case "$ref" in
        ./* | docker://*) continue ;;
      esac
      revision="${ref##*@}"
      key="$workflow:$current_job"
      if [[ "$ref" == actions/* ]] && [ "$trust_workflow" = false ] &&
        [[ -z "${privileged_workflows[$workflow]:-}" ]] &&
        [[ -z "${privileged_jobs[$key]:-}" ]]; then
        continue
      fi
      if [[ ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then
        if [[ "$ref" == actions/* ]]; then
          echo "$workflow:$line_number: privileged job $current_job uses mutable first-party action: $ref" >&2
        else
          echo "$workflow:$line_number: remote action is not pinned to a full commit SHA: $ref" >&2
        fi
        failures=1
      fi
    done <"$workflow"
  done
}

check_action_pins "$workflow_root"

if [ "$mode" = "--action-pins-only" ]; then
  exit "$failures"
fi

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

# ---------------------------------------------------------------------------
# R22: install_mcp_publisher must delete exactly the mcp-publisher.XXXXXX
# directory it created on every exit path, and must not clobber a caller's
# EXIT trap when the script is sourced. Fully offline: curl is stubbed through
# PATH and the platform metadata is overridden with a locally built fixture.
# ---------------------------------------------------------------------------
check_installer_cleanup() {
  local fixture_name="mcp-publisher_fixture.tar.gz"
  local tmp_root stub_bin case_root build_dir fixture digest dest rc
  local actual remains

  tmp_root="$(mktemp -d "${TMPDIR:-/tmp}/mcp-installer-check.XXXXXX")"
  stub_bin="$tmp_root/bin"
  mkdir -p "$stub_bin"

  cat >"$stub_bin/curl" <<'CURL_STUB'
#!/usr/bin/env bash
set -euo pipefail
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [[ -n "${CURL_STUB_EXIT:-}" ]]; then
  exit "${CURL_STUB_EXIT}"
fi
[[ -n "$out" ]] || exit 2
cp "${CURL_STUB_FIXTURE:?missing CURL_STUB_FIXTURE}" "$out"
CURL_STUB
  chmod +x "$stub_bin/curl"

  # One real tar.gz fixture with an executable member, so the success case
  # exercises extraction and `install`, not just the cleanup trap.
  build_dir="$tmp_root/build"
  mkdir -p "$build_dir"
  printf '#!/usr/bin/env bash\necho mcp-publisher-stub\n' >"$build_dir/mcp-publisher"
  chmod +x "$build_dir/mcp-publisher"
  fixture="$tmp_root/$fixture_name"
  tar -czf "$fixture" -C "$build_dir" mcp-publisher
  digest="$(sha256_file "$fixture")"

  # want_sha is the digest the installer will expect; pass the real one for a
  # success/short-circuit, 64 zeros for a genuine verify_sha256 mismatch.
  run_cleanup_case() {
    local id="$1" mode="$2" want_sha="$3"
    case_root="$(mktemp -d "$tmp_root/case.XXXXXX")"
    mkdir -p "$case_root/out"
    dest="$case_root/out/mcp-publisher"

    set +e
    (
      set -e
      if [[ "$mode" == download_failure ]]; then
        export CURL_STUB_EXIT=22
      fi
      mcp_publisher_platform() {
        printf '%s\t%s\t%s\n' "$fixture_name" "$want_sha" "mcp-publisher"
      }
      export PATH="$stub_bin:$PATH"
      export RUNNER_TEMP="$case_root" TMPDIR="$case_root" CURL_STUB_FIXTURE="$fixture"
      install_mcp_publisher "$dest"
    )
    rc=$?
    set -e

    remains="$(find "$case_root" -maxdepth 1 -name 'mcp-publisher.*' -print -quit)"
    if [[ -n "$remains" ]]; then actual="present"; else actual="absent"; fi
    printf '{"case_id": "%s", "expected": "absent", "actual": "%s"}\n' "$id" "$actual"
    [[ "$actual" == absent ]] || {
      echo "$id: installer work dir was not removed: $remains" >&2
      failures=1
    }

    if [[ "$mode" == success ]]; then
      [[ "$rc" -eq 0 && -x "$dest" ]] || {
        echo "$id: expected a successful install at $dest (rc=$rc)" >&2
        failures=1
      }
    else
      [[ "$rc" -ne 0 && ! -e "$dest" ]] || {
        echo "$id: expected a failed install with no destination (rc=$rc)" >&2
        failures=1
      }
    fi
  }

  run_cleanup_case mcp_publisher_workdir_removed_on_success success "$digest"
  run_cleanup_case mcp_publisher_workdir_removed_on_sha_mismatch sha_mismatch \
    "0000000000000000000000000000000000000000000000000000000000000000"
  run_cleanup_case mcp_publisher_workdir_removed_on_download_failure download_failure "$digest"

  # The subshell-function form must leave a caller's own EXIT trap intact when
  # the installer is sourced. A fresh child shell is the honest simulation of
  # the workflows' `source scripts/install_mcp_publisher.sh` contract.
  case_root="$(mktemp -d "$tmp_root/case.XXXXXX")"
  mkdir -p "$case_root/out"
  dest="$case_root/out/mcp-publisher"
  cat >"$case_root/caller.sh" <<'CALLER'
#!/usr/bin/env bash
set -euo pipefail
trap 'printf fired >"$CALLER_MARKER"' EXIT
source "$REPO_ROOT/scripts/install_mcp_publisher.sh"
mcp_publisher_platform() {
  printf '%s\t%s\t%s\n' "$FIXTURE_NAME" "$EXPECTED" "mcp-publisher"
}
export PATH="$STUB_BIN:$PATH"
export RUNNER_TEMP="$CASE_ROOT" TMPDIR="$CASE_ROOT" CURL_STUB_FIXTURE="$FIXTURE"
install_mcp_publisher "$DEST"
CALLER
  if env REPO_ROOT="$repo_root" STUB_BIN="$stub_bin" CASE_ROOT="$case_root" \
    FIXTURE="$fixture" FIXTURE_NAME="$fixture_name" EXPECTED="$digest" \
    DEST="$dest" CALLER_MARKER="$case_root/caller-trap-fired" \
    bash "$case_root/caller.sh"; then
    rc=0
  else
    rc=$?
  fi
  if [[ -f "$case_root/caller-trap-fired" ]]; then actual="fired"; else actual="missing"; fi
  printf '{"case_id": "%s", "expected": "caller-exit-trap-fired", "actual": "%s"}\n' \
    "mcp_publisher_caller_exit_trap_intact" "$actual"
  [[ "$actual" == fired && "$rc" -eq 0 ]] || {
    echo "mcp_publisher_caller_exit_trap_intact: caller EXIT trap was clobbered (rc=$rc)" >&2
    failures=1
  }

  rm -rf -- "$tmp_root"
}

check_installer_cleanup

# This hermetic suite also invokes validate_release_security_workflows.sh and
# supplies fake GitHub, registry, Docker, and cosign clients. Its own nested
# policy checks use --action-pins-only, which deliberately returns above.
if ! bash tests/release_workflow_security_test.sh; then
  failures=1
fi

exit "$failures"
