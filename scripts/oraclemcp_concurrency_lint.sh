#!/usr/bin/env bash
# oraclemcp concurrency-audit lint (DL-9).
#
# This gate keeps the thin-native service on the intended concurrency contract:
# explicit block_on boundaries only, no Tokio spawn drift, no production
# std::sync::Mutex in oraclemcp-core or the audit-chain writer, bounded queues
# only, and no lane command sender leakage across module boundaries.
#
# Usage:
#   bash scripts/oraclemcp_concurrency_lint.sh                    # scan the tracked tree
#   bash scripts/oraclemcp_concurrency_lint.sh --self-test        # prove the E7 scoping fix
#   bash scripts/oraclemcp_concurrency_lint.sh --test-output PATH # also scan a cargo-test log
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_OUTPUT=""
SELFTEST=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    --test-output)
      if [ "$#" -lt 2 ]; then
        echo "oraclemcp-concurrency-lint: --test-output requires a path" >&2
        exit 2
      fi
      TEST_OUTPUT="$2"
      shift 2
      ;;
    --self-test)
      SELFTEST=true
      shift
      ;;
    *)
      echo "oraclemcp-concurrency-lint: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

# E7 (oraclemcp-eng-program-bp8ia.6.7): prove the git_files() test-file scoping
# fix — a bare (non-#[cfg(test)]/#[test]-annotated) helper fn inside a
# `tests_*.rs`-named src file (the shape of
# crates/oraclemcp-core/src/http/tests_ci_lanes.rs's `drive()`, reached via
# `include!()` from a #[cfg(test)] mod and so carrying no #[cfg(test)] marker
# of its own) must NOT be scanned as production, while the identical helper in
# an ordinarily-named production file still must trip the lint.
run_selftest() {
  local scratch_dir
  scratch_dir="$(mktemp -d)"
  trap 'rm -rf "$scratch_dir"' RETURN

  local prod_file="$scratch_dir/scratch_helper.rs"
  local test_support_file="$scratch_dir/tests_scratch_helper.rs"
  local helper_body='fn helper_runs_future_inline<F: std::future::Future>(future: F) -> F::Output {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("scratch runtime builds");
    runtime.block_on(future)
}
'

  printf '%s' "$helper_body" >"$prod_file"
  printf '%s' "$helper_body" >"$test_support_file"

  echo "oraclemcp-concurrency-lint: self-test - planted unmarked block_on helper at $prod_file (ordinary filename)" >&2
  if ORACLEMCP_CONCURRENCY_LINT_SELFTEST_FILES="$prod_file" bash "${BASH_SOURCE[0]}" >/dev/null 2>&1; then
    echo "oraclemcp-concurrency-lint: self-test FAILED (an unmarked block_on in a non-test-support file must still trip the lint)" >&2
    return 1
  fi
  echo "oraclemcp-concurrency-lint: self-test OK (baseline production violation still caught)" >&2

  echo "oraclemcp-concurrency-lint: self-test - planted the identical helper at $test_support_file (tests_*.rs filename)" >&2
  if ! ORACLEMCP_CONCURRENCY_LINT_SELFTEST_FILES="$test_support_file" bash "${BASH_SOURCE[0]}" >/dev/null 2>&1; then
    echo "oraclemcp-concurrency-lint: self-test FAILED (a tests_*.rs-named test-support file must be excluded from the production scan, not flagged)" >&2
    return 1
  fi
  echo "oraclemcp-concurrency-lint: self-test OK (tests_*.rs-named helper correctly excluded, E7 scoping gap closed)" >&2
  return 0
}

if $SELFTEST; then
  run_selftest
  exit $?
fi

export ORACLEMCP_CONCURRENCY_LINT_ROOT="$ROOT"
export ORACLEMCP_CONCURRENCY_LINT_TEST_OUTPUT="$TEST_OUTPUT"
export ORACLEMCP_CONCURRENCY_LINT_SELFTEST_FILES="${ORACLEMCP_CONCURRENCY_LINT_SELFTEST_FILES:-}"

python3 - <<'PY'
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(os.environ["ORACLEMCP_CONCURRENCY_LINT_ROOT"])
TEST_OUTPUT = os.environ.get("ORACLEMCP_CONCURRENCY_LINT_TEST_OUTPUT", "")


def is_test_support_path(rel_posix: str) -> bool:
    """True for paths that are always test-only, never production.

    Covers the existing `tests/` directory and `tests.rs` module exclusions,
    plus (E7) the `tests_*.rs` / `*_tests.rs` naming convention used for
    oversized test modules that are reached via `include!()` or a
    `#[cfg(test)] #[path = "..."]` attribute from elsewhere (e.g.
    `crates/oraclemcp-core/src/http/tests_ci_lanes.rs`,
    `crates/oraclemcp/src/main_tests.rs`). Those files carry no `#[cfg(test)]`
    marker of their own, so `production_lines()` cannot strip them by content
    inspection; excluding them by filename here is the only place the skip can
    happen. This mirrors `oraclemcp_fixture_lint.sh`'s `is_test_path()`
    naming heuristic (kept independent rather than shared, since the two
    scripts skip test files for opposite reasons: the fixture lint scans
    *only* test files, this lint scans everything *except* them).
    """
    if rel_posix.endswith("/tests.rs") or rel_posix == "tests.rs":
        return True
    if "/tests/" in f"/{rel_posix}":
        return True
    basename = rel_posix.rsplit("/", 1)[-1]
    return basename.startswith("tests_") or basename.endswith("_tests.rs")


def git_files(*pathspecs: str) -> list[Path]:
    override = os.environ.get("ORACLEMCP_CONCURRENCY_LINT_SELFTEST_FILES", "")
    if override:
        # Self-test mode (E7): scan exactly the planted scratch file(s) instead
        # of the tracked tree, still through the same is_test_support_path()
        # filter so the self-test exercises the real policy, not a bypass.
        lines = [p for p in override.split(os.pathsep) if p]
    else:
        output = subprocess.check_output(
            ["git", "ls-files", *pathspecs],
            cwd=ROOT,
            text=True,
        )
        lines = output.splitlines()
    return [
        ROOT / line
        for line in lines
        if line.endswith(".rs") and not is_test_support_path(line)
    ]


def brace_delta(line: str) -> int:
    """Cheap brace counter for Rust item skipping; ignores strings/comments."""
    delta = 0
    in_string = False
    escaped = False
    i = 0
    while i < len(line):
        ch = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ""
        if not in_string and ch == "/" and nxt == "/":
            break
        if escaped:
            escaped = False
        elif ch == "\\" and in_string:
            escaped = True
        elif ch == '"':
            in_string = not in_string
        elif not in_string:
            if ch == "{":
                delta += 1
            elif ch == "}":
                delta -= 1
        i += 1
    return delta


def production_lines(path: Path) -> list[tuple[int, str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    output: list[tuple[int, str]] = []
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped.startswith("#[cfg(test)]") or stripped.startswith("#[test]"):
            i += 1
            while i < len(lines) and lines[i].strip().startswith("#["):
                i += 1
            saw_brace = False
            depth = 0
            while i < len(lines):
                line = lines[i]
                depth += brace_delta(line)
                if "{" in line:
                    saw_brace = True
                i += 1
                if saw_brace and depth <= 0:
                    break
                if not saw_brace and line.strip().endswith(";"):
                    break
            continue
        output.append((i + 1, lines[i]))
        i += 1
    return output


def rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        # Self-test scratch files live outside ROOT (mktemp -d); report the
        # absolute path rather than crashing on a path that isn't under ROOT.
        return str(path)


def is_comment(line: str) -> bool:
    return line.strip().startswith("//")


def report_violation(kind: str, path: Path, line_no: int, line: str) -> None:
    violations.append(
        f"{kind}: {rel(path)}:{line_no}: {line.strip()}"
    )


rust_files = git_files("crates/oraclemcp-audit/src", "crates/oraclemcp-core/src", "crates/oraclemcp/src")
prod: dict[Path, list[tuple[int, str]]] = {path: production_lines(path) for path in rust_files}
violations: list[str] = []
warnings: list[str] = []

block_on = re.compile(r"(?<![A-Za-z0-9_])(?:\.)?block_on\s*\(")
tokio_spawn = re.compile(r"\btokio::spawn\s*\(")
std_mutex = re.compile(
    r"\bstd::sync::Mutex\b|use\s+std::sync::Mutex\b|use\s+std::sync::\{[^}]*\bMutex\b"
)
unbounded_queue = re.compile(
    r"\b(?:mpsc|channel|async_channel)::unbounded(?:_channel)?\s*\(|\bunbounded_channel\s*\("
)
lane_sender_leak = re.compile(r"\bLaneCommand\b")

for path, lines in prod.items():
    path_rel = rel(path)
    for idx, (line_no, line) in enumerate(lines):
        if is_comment(line):
            continue
        if tokio_spawn.search(line):
            report_violation("FORBIDDEN[tokio-spawn]", path, line_no, line)
        if unbounded_queue.search(line):
            report_violation("FORBIDDEN[unbounded-queue]", path, line_no, line)
        if (
            path_rel.startswith("crates/oraclemcp-core/src/")
            or path_rel.startswith("crates/oraclemcp-audit/src/")
        ) and std_mutex.search(line):
            report_violation("FORBIDDEN[poisoning-mutex]", path, line_no, line)
        if path_rel != "crates/oraclemcp-core/src/lane.rs" and lane_sender_leak.search(line):
            report_violation("FORBIDDEN[lane-sender-leak]", path, line_no, line)
        if block_on.search(line):
            window = lines[max(0, idx - 6):idx + 1]
            marked = any("block-on-boundary:" in prior for _, prior in window)
            if not marked:
                report_violation("FORBIDDEN[unsanctioned-block-on]", path, line_no, line)

loop_targets = {
    ROOT / "crates/oraclemcp-core/src/lane.rs",
    ROOT / "crates/oraclemcp/src/dispatch/mod.rs",
}
loop_pattern = re.compile(r"\b(?:loop|while)\b.*\{")
checkpoint_pattern = re.compile(r"\b(?:dispatch_)?checkpoint\s*\(")

for path in sorted(loop_targets):
    lines = prod.get(path, [])
    for idx, (line_no, line) in enumerate(lines):
        if is_comment(line) or not loop_pattern.search(line):
            continue
        window = lines[idx:min(len(lines), idx + 21)]
        if not any(checkpoint_pattern.search(candidate) for _, candidate in window):
            warnings.append(
                f"WARN[loop-checkpoint-review]: {rel(path)}:{line_no}: {line.strip()}"
            )

if TEST_OUTPUT:
    output_path = ROOT / TEST_OUTPUT if not os.path.isabs(TEST_OUTPUT) else Path(TEST_OUTPUT)
    if not output_path.is_file():
        print(f"oraclemcp-concurrency-lint: test output not found: {output_path}", file=sys.stderr)
        sys.exit(2)
    markers = ("ObligationLeak", "FuturelockViolation", "RegionCloseTimeout")
    for line_no, line in enumerate(output_path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if any(marker in line for marker in markers):
            violations.append(
                f"FORBIDDEN[test-output-marker]: {output_path}:{line_no}: {line.strip()}"
            )
else:
    print("oraclemcp-concurrency-lint: note - no --test-output supplied; cargo-test marker scan skipped.")

for warning in warnings:
    print(warning, file=sys.stderr)

if violations:
    print("oraclemcp-concurrency-lint: FAIL", file=sys.stderr)
    for violation in violations:
        print(f"  {violation}", file=sys.stderr)
    sys.exit(1)

print(
    "oraclemcp-concurrency-lint: OK - production concurrency contract holds"
    f" ({len(rust_files)} Rust source files scanned, {len(warnings)} review warning(s))."
)
PY
