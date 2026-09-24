#!/usr/bin/env bash
# oraclemcp public-API lock gate (B5; plan §12, ADR-0002 mirror).
#
# `oraclemcp-db` is the canonical shared Oracle foundation (ADR-0006) and the
# engine-free spine crates `oraclemcp-error` / `oraclemcp-guard` are the
# published surface `plsql-mcp` converges onto. Because those surfaces have two
# consumers, an unintended breaking change must be caught BEFORE it reaches
# `plsql-mcp`.
#
# This gate renders each locked crate's current public API with
# `cargo public-api` and diffs it against the committed baseline under
# `crates/<crate>/api/<crate>.txt`. Any drift (an added, removed, or changed
# public item) that is not reflected in the committed baseline fails the build.
#
# When a public-API change is INTENTIONAL, regenerate the baseline in the same
# PR so the diff is reviewable:
#
#   cargo public-api -p <crate> > crates/<crate>/api/<crate>.txt
#
# (run under the pinned nightly toolchain so the rendered surface is stable).
# The companion `cargo semver-checks` check classifies the diff as
# major/minor/patch against the previous in-repository release tag and that
# tag's committed Cargo.lock. This makes the baseline independent of registry
# yanks; both checks run here so CI and local verification have one entrypoint.
#
# Exit 0 = every locked surface and semver comparison passes. Exit 1 = drift or
# an unavailable/invalid historical baseline.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# The locked crates: the published spine plsql-mcp consumes, the canonical
# foundation, and the standalone verifier external auditors build on (R23).
# oraclemcp-core (the binary-facing aggregation crate) is deliberately NOT
# locked — it is an internal consumer, not a shared product API.
LOCKED_CRATES=(
  oraclemcp-error
  oraclemcp-guard
  oraclemcp-db
  oraclemcp-verifier
)

SEMVER_CRATES=(
  oraclemcp-error
  oraclemcp-guard
  oraclemcp-db
  oraclemcp-verifier
)

workspace_version() {
  cargo metadata --no-deps --format-version 1 | python3 -c '
import json, sys
metadata = json.load(sys.stdin)
for package in metadata["packages"]:
    if package["name"] == "oraclemcp":
        print(package["version"])
        break
else:
    raise SystemExit("oraclemcp-api-lock: oraclemcp package version is unavailable")
'
}

select_baseline_tag() {
  local version="$1" tag
  if [ -n "${ORACLEMCP_SEMVER_BASELINE_TAG:-}" ]; then
    tag="$ORACLEMCP_SEMVER_BASELINE_TAG"
  else
    tag="$(git describe --tags --abbrev=0 --match 'v[0-9]*' --exclude="v$version" HEAD)" || {
      echo "oraclemcp-api-lock: no previous release tag found before workspace version $version" >&2
      return 1
    }
  fi
  if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-.][[:alnum:].-]+)?$ ]]; then
    echo "oraclemcp-api-lock: invalid baseline release tag '$tag'" >&2
    return 1
  fi
  local tag_version="${tag#v}"
  if [ "$tag_version" = "$version" ]; then
    echo "oraclemcp-api-lock: baseline $tag is the workspace version $version" >&2
    return 1
  fi
  if ! git rev-parse --verify --quiet "$tag^{commit}" >/dev/null; then
    echo "oraclemcp-api-lock: baseline tag '$tag' is unavailable locally; fetch tags first" >&2
    return 1
  fi
  if ! git merge-base --is-ancestor "$tag" HEAD; then
    echo "oraclemcp-api-lock: baseline tag '$tag' is not an ancestor of HEAD" >&2
    return 1
  fi
  printf '%s\n' "$tag"
}

run_semver_check() {
  local baseline_tag="$1" crate archive baseline_metadata baseline_target baseline_rustdoc
  echo "oraclemcp-api-lock: semver baseline tag: $baseline_tag"
  archive="${CARGO_TARGET_DIR:-$ROOT/target}/semver-baseline-${baseline_tag}"
  baseline_target="${CARGO_TARGET_DIR:-$ROOT/target}/semver-baseline-target-${baseline_tag}"
  mkdir -p "$archive" "$baseline_target"
  git archive "$baseline_tag" | tar -x -C "$archive"
  baseline_metadata="$(cargo --offline --locked metadata --no-deps --format-version 1 \
    --manifest-path "$archive/Cargo.toml")"
  for crate in "${SEMVER_CRATES[@]}"; do
    if ! BASELINE_METADATA_JSON="$baseline_metadata" python3 - "$crate" <<'PY'
import json, os, sys
name = sys.argv[1]
metadata = json.loads(os.environ["BASELINE_METADATA_JSON"])
raise SystemExit(0 if any(package["name"] == name for package in metadata["packages"]) else 1)
PY
    then
      echo "oraclemcp-api-lock: SKIP — $crate did not exist at $baseline_tag"
      continue
    fi
    RUSTDOCFLAGS="-Z unstable-options --output-format json" \
      cargo --offline --locked doc --manifest-path "$archive/Cargo.toml" \
        --package "$crate" --lib --no-deps --target-dir "$baseline_target"
    baseline_rustdoc="$baseline_target/doc/${crate//-/_}.json"
    if [ ! -s "$baseline_rustdoc" ]; then
      echo "oraclemcp-api-lock: missing baseline rustdoc JSON for $crate at $baseline_tag: $baseline_rustdoc" >&2
      return 1
    fi
    cargo --offline --locked semver-checks check-release \
      --baseline-rustdoc "$baseline_rustdoc" -p "$crate"
  done
}

log_selftest_case() {
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import json, sys
print(json.dumps({"case_id": sys.argv[1], "baseline_tag": sys.argv[2],
                  "expected": sys.argv[3], "actual": sys.argv[4]}))
PY
}

selftest() {
  local version baseline scratch yanked_root planted_root planted_tag actual output
  version="$(workspace_version)"
  baseline="$(select_baseline_tag "$version")"
  if run_semver_check "$baseline"; then
    log_selftest_case semver_baseline_head_passes "$baseline" pass pass
  else
    actual=fail
    log_selftest_case semver_baseline_head_passes "$baseline" pass "$actual"
    return 1
  fi

  # Clone the committed tree with its tags, then remove a real public function
  # only in that disposable test clone. The expected semver failure must name
  # the removed symbol, so a build/setup failure cannot masquerade as detection.
  scratch="${CARGO_TARGET_DIR:-$ROOT/target}/api-lock-selftest-$$"
  mkdir -p "$scratch"
  planted_root="$scratch/planted-break"
  git clone --quiet --shared --no-checkout "$ROOT" "$planted_root"
  git -C "$planted_root" checkout --quiet --detach HEAD
  python3 - "$planted_root/crates/oraclemcp-error/src/lib.rs" <<'PY'
from pathlib import Path
import sys
p = Path(sys.argv[1])
text = p.read_text()
symbol = "oracle_retry_action_from_message"
start = text.index(f"#[must_use]\npub fn {symbol}(")
body = text.index("{", start)
depth = 0
end = None
for i in range(body, len(text)):
    if text[i] == "{": depth += 1
    elif text[i] == "}":
        depth -= 1
        if depth == 0:
            end = i + 1
            break
if end is None:
    raise SystemExit(f"could not find {symbol} function end")
line_start = text.rfind("\n", 0, start) + 1
doc_start = text.rfind("/// Return the retry action encoded", 0, start)
if doc_start >= 0:
    line_start = doc_start
p.write_text(text[:line_start] + text[end:].lstrip("\n"))
PY
  local planted_baseline planted_target planted_rustdoc
  planted_tag="v$version"
  if ! git rev-parse --verify --quiet "$planted_tag^{commit}" >/dev/null; then
    echo "oraclemcp-api-lock: selftest needs current-version tag $planted_tag for the planted-break case" >&2
    return 1
  fi
  planted_baseline="$scratch/planted-baseline"
  planted_target="$scratch/planted-baseline-target"
  mkdir -p "$planted_baseline" "$planted_target"
  git -C "$planted_root" archive "$planted_tag" | tar -x -C "$planted_baseline"
  RUSTDOCFLAGS="-Z unstable-options --output-format json" \
    cargo --offline --locked doc --manifest-path "$planted_baseline/Cargo.toml" \
      --package oraclemcp-error --lib --no-deps --target-dir "$planted_target"
  planted_rustdoc="$planted_target/doc/oraclemcp_error.json"
  if output="$(cd "$planted_root" && cargo --offline --locked semver-checks check-release \
      --baseline-rustdoc "$planted_rustdoc" -p oraclemcp-error 2>&1)"; then
    printf '%s\n' "$output"
    log_selftest_case semver_baseline_detects_planted_break "$planted_tag" fail pass
    return 1
  fi
  if ! grep -q 'oracle_retry_action_from_message' <<<"$output"; then
    printf '%s\n' "$output" >&2
    log_selftest_case semver_baseline_detects_planted_break "$planted_tag" \
      oracle_retry_action_from_message fail
    return 1
  fi
  printf '%s\n' "$output"
  log_selftest_case semver_baseline_detects_planted_break "$planted_tag" fail fail-detected

  # v0.10.0 locks the now-yanked oracledb 0.9.1. Fetch that committed lock
  # first, then force offline mode for the semver comparison to prove the
  # baseline uses the tag's lock rather than resolving the yanked version.
  yanked_root="$scratch/yanked-v0.10.0"
  git clone --quiet --shared --no-checkout "$ROOT" "$yanked_root"
  git -C "$yanked_root" checkout --quiet --detach v0.10.0
  if ! cargo fetch --locked --manifest-path "$yanked_root/Cargo.toml"; then
    log_selftest_case semver_baseline_yanked_dependency_reproducible v0.10.0 pass fetch-failed
    return 1
  fi
  if ORACLEMCP_SEMVER_BASELINE_TAG=v0.10.0 run_semver_check v0.10.0; then
    log_selftest_case semver_baseline_yanked_dependency_reproducible v0.10.0 pass pass
  else
    log_selftest_case semver_baseline_yanked_dependency_reproducible v0.10.0 pass fail
    return 1
  fi
}

if [ "${1:-}" = "--selftest" ]; then
  selftest
  exit $?
elif [ "$#" -ne 0 ]; then
  echo "usage: bash scripts/oraclemcp_api_lock.sh [--selftest]" >&2
  exit 2
fi

if ! command -v cargo-public-api >/dev/null 2>&1; then
  echo "oraclemcp-api-lock: cargo-public-api not installed." >&2
  echo "Install it with: cargo install --locked cargo-public-api" >&2
  echo "(CI installs it via taiki-e/install-action@cargo-public-api.)" >&2
  exit 1
fi

violations=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

for crate in "${LOCKED_CRATES[@]}"; do
  baseline="crates/$crate/api/$crate.txt"
  if [ ! -f "$baseline" ]; then
    echo "oraclemcp-api-lock: missing baseline $baseline" >&2
    echo "  Generate it with: cargo public-api -p $crate > $baseline" >&2
    violations=$((violations + 1))
    continue
  fi
  current="$tmp/$crate.txt"
  if ! cargo public-api -p "$crate" >"$current" 2>"$tmp/$crate.err"; then
    echo "oraclemcp-api-lock: cargo public-api failed for $crate:" >&2
    cat "$tmp/$crate.err" >&2
    violations=$((violations + 1))
    continue
  fi
  if diff -u "$baseline" "$current"; then
    echo "oraclemcp-api-lock: OK — $crate matches $baseline"
  else
    echo "" >&2
    echo "oraclemcp-api-lock: DRIFT — $crate public API differs from $baseline." >&2
    echo "  If this change is intentional, refresh the baseline in this PR:" >&2
    echo "    cargo public-api -p $crate > $baseline" >&2
    violations=$((violations + 1))
  fi
done

version="$(workspace_version)"
baseline_tag="$(select_baseline_tag "$version")"
run_semver_check "$baseline_tag"

if [ "$violations" -ne 0 ]; then
  echo "" >&2
  echo "oraclemcp-api-lock: FAIL — $violations locked crate(s) drifted or are unbaselined." >&2
  exit 1
fi

echo "oraclemcp-api-lock: OK — all locked public-API surfaces match their baselines."
