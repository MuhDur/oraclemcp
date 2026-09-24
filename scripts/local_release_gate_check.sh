#!/usr/bin/env bash
# Validate the sanitized D3.2 local-release-gate proof. In normal local runs this
# is advisory; tag/release preflight requires it.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

require=false
proof=""
source_sha=""
refuse_dev_pins_requested=false

usage() {
  cat <<'USAGE'
Validate the local-release-gate proof.

Options:
  --require          fail when no proof is present
  --proof PATH       validate this proof file instead of auto-discovering
  --source-sha SHA   expected source commit short SHA
  --refuse-dev-pins  refuse development git pins in release inputs
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --require)
      require=true
      shift
      ;;
    --proof)
      [ "$#" -ge 2 ] || {
        echo "local-release-gate-check: --proof requires a path" >&2
        exit 2
      }
      proof="$2"
      shift 2
      ;;
    --source-sha)
      [ "$#" -ge 2 ] || {
        echo "local-release-gate-check: --source-sha requires a value" >&2
        exit 2
      }
      source_sha="$2"
      shift 2
      ;;
    --refuse-dev-pins)
      refuse_dev_pins_requested=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "local-release-gate-check: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

refuse_dev_pins() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo "local-release-gate-check: missing required command: python3" >&2
    return 2
  fi
  python3 - "$ROOT" <<'PY'
import pathlib
import sys
import tomllib

root = pathlib.Path(sys.argv[1])
paths = {
    "Cargo.toml": root / "Cargo.toml",
    "deny.toml": root / "deny.toml",
    "Cargo.lock": root / "Cargo.lock",
}
offenders = []
parsed = {}
for label, path in paths.items():
    try:
        with path.open("rb") as source:
            parsed[label] = tomllib.load(source)
    except (OSError, tomllib.TOMLDecodeError) as error:
        offenders.append(f"{label} parse -> {error} -> expected none")

cargo = parsed.get("Cargo.toml")
if cargo is not None:
    patch = cargo.get("patch")
    if patch is not None:
        if isinstance(patch, dict):
            for registry, entries in patch.items():
                if isinstance(entries, dict) and entries:
                    for crate, value in entries.items():
                        offenders.append(
                            f"Cargo.toml.[patch.{registry}].{crate} -> {value!r} -> expected none"
                        )
                else:
                    offenders.append(
                        f"Cargo.toml.[patch.{registry}] -> {entries!r} -> expected none"
                    )
            if not patch:
                offenders.append("Cargo.toml.[patch] -> empty patch table -> expected none")
        else:
            offenders.append(f"Cargo.toml.patch -> {patch!r} -> expected none")

deny = parsed.get("deny.toml")
if deny is not None:
    sources = deny.get("sources", {})
    if not isinstance(sources, dict):
        sources = {}
        offenders.append(f"deny.toml.sources -> malformed -> expected a table")
    allow_git = sources.get("allow-git", [])
    if not isinstance(allow_git, list):
        offenders.append(f"deny.toml.sources.allow-git -> {allow_git!r} -> expected none")
    elif allow_git:
        offenders.append(f"deny.toml.sources.allow-git -> {allow_git!r} -> expected none")

lock = parsed.get("Cargo.lock")
if lock is not None:
    for index, package in enumerate(lock.get("package", [])):
        source = package.get("source")
        if isinstance(source, str) and source.startswith("git+"):
            offenders.append(f"Cargo.lock.package[{index}].source -> {source} -> expected none")

if offenders:
    for offender in offenders:
        print(f"local-release-gate-check: dev pin refusal: {offender}", file=sys.stderr)
    raise SystemExit(1)
PY
}

tag_context=false
if [ -n "${RELEASE_TAG:-}" ] || [ "${GITHUB_REF_TYPE:-}" = "tag" ] || [[ "${GITHUB_REF:-}" == refs/tags/* ]]; then
  tag_context=true
fi
if [ "$refuse_dev_pins_requested" = true ]; then
  refuse_dev_pins || exit $?
  echo "local-release-gate-check: dev pins absent"
  exit 0
elif [ "$tag_context" = true ]; then
  refuse_dev_pins || exit $?
fi

fail() {
  echo "local-release-gate-check: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

need git
need jq

if [ "${RELEASE_REQUIRE_LOCAL_GATE:-false}" = "true" ] || [ -n "${RELEASE_TAG:-}" ]; then
  require=true
fi
if [ "${GITHUB_REF_TYPE:-}" = "tag" ] || [[ "${GITHUB_REF:-}" == refs/tags/* ]]; then
  require=true
fi

head_sha="$(git rev-parse --short=12 HEAD)"
if [ -z "$source_sha" ]; then
  source_sha="$head_sha"
fi

proof_dir="${ORACLEMCP_LOCAL_GATE_PROOF_DIR:-$ROOT/tests/artifacts/local_gate}"
if [ -z "$proof" ]; then
  proof="$proof_dir/results-$source_sha.json"
fi

accepted_parent_proof=false
if [ ! -f "$proof" ] && [ "$source_sha" = "$head_sha" ]; then
  parent_sha="$(git rev-parse --short=12 HEAD^ 2>/dev/null || true)"
  parent_proof="$proof_dir/results-$parent_sha.json"
  if [ -n "$parent_sha" ] && [ -f "$parent_proof" ]; then
    non_evidence_paths="$(
      git diff --name-only HEAD^..HEAD |
        grep -Ev '^tests/artifacts/local_gate/' || true
    )"
    if [ -z "$non_evidence_paths" ]; then
      proof="$parent_proof"
      source_sha="$parent_sha"
      accepted_parent_proof=true
    fi
  fi
fi

if [ ! -f "$proof" ]; then
  if [ "$require" = true ]; then
    fail "required proof missing: $proof"
  fi
  echo "local-release-gate-check: skip (no proof required for this non-tag run)"
  exit 0
fi

schema_version="$(jq -r '.schema_version // empty' "$proof")"
[ "$schema_version" = "1" ] || fail "$proof has schema_version '$schema_version' (expected 1)"

json_sha="$(jq -r '.source_sha // empty' "$proof")"
[ "$json_sha" = "$source_sha" ] || fail "$proof source_sha '$json_sha' does not match expected '$source_sha'"

server_subject="$(jq -r '.confidentiality.server_certificate_subject // empty' "$proof")"
[ "$server_subject" = "CN=oracle-test.invalid" ] || fail "$proof must use only CN=oracle-test.invalid"

real_evidence="$(jq -r '.confidentiality.real_adb_evidence // empty' "$proof")"
case "$real_evidence" in
  *"out-of-band"*"never committed"*) ;;
  *) fail "$proof must mark real ADB evidence out-of-band and never committed" ;;
esac

if ! jq -e '.checks | type == "array" and length > 0 and all(.status == "pass")' "$proof" >/dev/null; then
  fail "$proof must contain at least one passing check"
fi

if grep -nE 'ocid1\.|CN=[^[:space:]]*\.oraclecloud\.com|-----BEGIN [A-Z ]*PRIVATE KEY-----|todelete[/\\]todelete[0-9]+' "$proof" >/dev/null; then
  fail "$proof contains a forbidden live/cloud/confidential marker"
fi

suffix=""
[ "$accepted_parent_proof" = false ] || suffix=" (accepted parent source proof from evidence-only commit)"
echo "local-release-gate-check: OK proof=$proof source_sha=$source_sha$suffix"
