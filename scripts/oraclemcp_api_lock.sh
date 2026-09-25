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
# The companion `cargo semver-checks` check reports the diff against the
# previous in-repository release tag and that tag's committed Cargo.lock. Its
# release type comes from the planned version recorded under CHANGELOG.md's
# `[Unreleased]` section; for 0.x crates, a minor-version increment is a major
# SemVer release. The committed public-API snapshot remains the gate for
# unreviewed API changes. This makes the baseline independent of registry yanks.
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

planned_release_version() {
  python3 - "$ROOT/CHANGELOG.md" <<'PY'
import re, sys
from pathlib import Path

in_unreleased = False
for line in Path(sys.argv[1]).read_text().splitlines():
    if line == "## [Unreleased]":
        in_unreleased = True
        continue
    if in_unreleased and line.startswith("## "):
        break
    if in_unreleased:
        match = re.fullmatch(r"### Planned release: ([0-9]+\.[0-9]+\.[0-9]+)", line)
        if match:
            print(match.group(1))
            raise SystemExit(0)
raise SystemExit("oraclemcp-api-lock: CHANGELOG.md [Unreleased] must declare '### Planned release: X.Y.Z'")
PY
}

release_type_for_plan() {
  local baseline_tag="$1" planned="$2"
  python3 - "${baseline_tag#v}" "$planned" <<'PY'
import re, sys

def parse(value):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
        raise SystemExit(f"oraclemcp-api-lock: invalid numeric release version {value!r}")
    return tuple(map(int, value.split(".")))

baseline = parse(sys.argv[1])
planned = parse(sys.argv[2])
if planned <= baseline:
    raise SystemExit(f"oraclemcp-api-lock: planned version {sys.argv[2]} must be newer than baseline v{sys.argv[1]}")
if planned[0] > baseline[0] or (baseline[0] == planned[0] == 0 and planned[1] > baseline[1]):
    print("major")
elif planned[0] == baseline[0] and planned[1] > baseline[1]:
    print("minor")
else:
    print("patch")
PY
}

select_baseline_tag() {
  local version="$1" tag tag_commit head_commit
  if [ -n "${ORACLEMCP_SEMVER_BASELINE_TAG:-}" ]; then
    tag="$ORACLEMCP_SEMVER_BASELINE_TAG"
  else
    tag="$(git describe --tags --abbrev=0 --match 'v[0-9]*' HEAD)" || {
      echo "oraclemcp-api-lock: no previous release tag found before workspace version $version" >&2
      return 1
    }
    tag_commit="$(git rev-parse "$tag^{commit}")"
    head_commit="$(git rev-parse HEAD)"
    if [ "$tag_commit" = "$head_commit" ]; then
      tag="$(git describe --tags --abbrev=0 --match 'v[0-9]*' --exclude="$tag" HEAD)" || {
        echo "oraclemcp-api-lock: no earlier release tag found before $tag" >&2
        return 1
      }
    fi
  fi
  if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-.][[:alnum:].-]+)?$ ]]; then
    echo "oraclemcp-api-lock: invalid baseline release tag '$tag'" >&2
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
  local baseline_tag="$1" release_type="$2" require_checks="${3:-true}"
  local crate archive baseline_metadata baseline_target baseline_rustdoc output check_count skipped_count semver_status
  SEMVER_CHECKS_RUN=0
  echo "oraclemcp-api-lock: semver baseline tag: $baseline_tag"
  archive="${CARGO_TARGET_DIR:-$ROOT/target}/semver-baseline-${baseline_tag}"
  baseline_target="${CARGO_TARGET_DIR:-$ROOT/target}/semver-baseline-target-${baseline_tag}"
  mkdir -p "$archive" "$baseline_target"
  git archive "$baseline_tag" | tar -x -C "$archive"
  echo "oraclemcp-api-lock: fetching locked dependencies for baseline $baseline_tag"
  cargo fetch --locked --manifest-path "$archive/Cargo.toml"
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
    semver_status=0
    output="$(cargo --offline --locked semver-checks check-release \
      --release-type "$release_type" --baseline-rustdoc "$baseline_rustdoc" \
      -p "$crate" 2>&1)" || semver_status=$?
    printf '%s\n' "$output"
    check_count="$(sed -nE 's/.*Checked \[[^]]+\] ([0-9]+) checks:.*/\1/p' <<<"$output" | tail -n 1)"
    if [[ ! "$check_count" =~ ^[0-9]+$ ]]; then
      echo "oraclemcp-api-lock: could not read semver check count for $crate at $baseline_tag" >&2
      return 1
    fi
    skipped_count="$(sed -nE 's/.*checks:.* ([0-9]+) skips?$/\1/p' <<<"$output" | tail -n 1)"
    skipped_count="${skipped_count:-0}"
    if [[ ! "$skipped_count" =~ ^[0-9]+$ ]]; then
      echo "oraclemcp-api-lock: could not read semver skip count for $crate at $baseline_tag" >&2
      return 1
    fi
    local crate_checks_run=$((check_count + skipped_count))
    SEMVER_CHECKS_RUN=$((SEMVER_CHECKS_RUN + crate_checks_run))
    echo "oraclemcp-api-lock: $crate SemVer report: checks_run=$crate_checks_run evaluated=$check_count skipped=$skipped_count"
    if [ "$semver_status" -ne 0 ]; then
      return 1
    fi
    if [ "$require_checks" = true ] && [ "$crate_checks_run" -eq 0 ]; then
      echo "oraclemcp-api-lock: cargo-semver-checks reported no checks for $crate at $baseline_tag" >&2
      return 1
    fi
  done
}

log_selftest_case() {
  python3 - "$1" "$2" "$3" "$4" "${5:-}" <<'PY'
import json, sys
checks_run = int(sys.argv[5]) if sys.argv[5] else None
print(json.dumps({"case_id": sys.argv[1], "baseline_tag": sys.argv[2],
                  "expected": sys.argv[3], "actual": sys.argv[4],
                  "checks_run": checks_run}))
PY
}

selftest() {
  local version planned baseline release_type scratch yanked_root planted_root actual yanked_release_type
  version="$(workspace_version)"
  planned="$(planned_release_version)"
  baseline="$(select_baseline_tag "$version")"
  release_type="$(release_type_for_plan "$baseline" "$planned")"
  echo "oraclemcp-api-lock: workspace version $version; planned release $planned; baseline $baseline; SemVer release type $release_type"
  if run_semver_check "$baseline" "$release_type" true; then
    if [ "$SEMVER_CHECKS_RUN" -le 0 ]; then
      echo "oraclemcp-api-lock: head SemVer selftest reported no checks" >&2
      log_selftest_case semver_baseline_head_passes "$baseline" nonzero-check-count zero "$SEMVER_CHECKS_RUN"
      return 1
    fi
    log_selftest_case semver_baseline_head_passes "$baseline" pass pass "$SEMVER_CHECKS_RUN"
  else
    actual=fail
    log_selftest_case semver_baseline_head_passes "$baseline" pass "$actual" "$SEMVER_CHECKS_RUN"
    return 1
  fi

  # Remove a real public function only in a disposable clone and verify that
  # the committed public-API snapshot rejects the drift. The planned 0.x minor
  # release intentionally permits SemVer breaks, so this is the negative gate.
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
  local planted_current planted_diff
  planted_current="$scratch/planted-oraclemcp-error-api.txt"
  planted_diff="$scratch/planted-oraclemcp-error-api.diff"
  if ! (cd "$planted_root" && cargo public-api -p oraclemcp-error >"$planted_current"); then
    echo "oraclemcp-api-lock: planted-break cargo public-api failed" >&2
    log_selftest_case semver_baseline_detects_planted_break "$baseline" snapshot-drift public-api-failed
    return 1
  fi
  if diff -u "$planted_root/crates/oraclemcp-error/api/oraclemcp-error.txt" "$planted_current" >"$planted_diff"; then
    echo "oraclemcp-api-lock: planted public API break did not drift from its committed snapshot" >&2
    log_selftest_case semver_baseline_detects_planted_break "$baseline" snapshot-drift no-drift
    return 1
  fi
  if ! grep -q 'oracle_retry_action_from_message' "$planted_diff"; then
    cat "$planted_diff" >&2
    log_selftest_case semver_baseline_detects_planted_break "$baseline" \
      oracle_retry_action_from_message snapshot-drift
    return 1
  fi
  cat "$planted_diff"
  log_selftest_case semver_baseline_detects_planted_break "$baseline" \
    snapshot-drift fail-detected

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
  yanked_release_type="$(release_type_for_plan v0.10.0 "$planned")"
  if run_semver_check v0.10.0 "$yanked_release_type" false; then
    log_selftest_case semver_baseline_yanked_dependency_reproducible v0.10.0 pass pass "$SEMVER_CHECKS_RUN"
  else
    log_selftest_case semver_baseline_yanked_dependency_reproducible v0.10.0 pass fail "$SEMVER_CHECKS_RUN"
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
planned="$(planned_release_version)"
release_type="$(release_type_for_plan "$baseline_tag" "$planned")"
echo "oraclemcp-api-lock: workspace version $version; planned release $planned; baseline $baseline_tag; SemVer release type $release_type"
run_semver_check "$baseline_tag" "$release_type" true

if [ "$violations" -ne 0 ]; then
  echo "" >&2
  echo "oraclemcp-api-lock: FAIL — $violations locked crate(s) drifted or are unbaselined." >&2
  exit 1
fi

echo "oraclemcp-api-lock: OK — all locked public-API surfaces match their baselines."
