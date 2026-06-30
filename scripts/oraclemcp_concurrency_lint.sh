#!/usr/bin/env bash
# oraclemcp concurrency-audit lint (DL-9).
#
# This gate keeps the thin-native service on the intended concurrency contract:
# explicit block_on boundaries only, no Tokio spawn drift, no production
# std::sync::Mutex in oraclemcp-core, bounded queues only, and no lane command
# sender leakage across module boundaries.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_OUTPUT=""

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
    *)
      echo "oraclemcp-concurrency-lint: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

export ORACLEMCP_CONCURRENCY_LINT_ROOT="$ROOT"
export ORACLEMCP_CONCURRENCY_LINT_TEST_OUTPUT="$TEST_OUTPUT"

python3 - <<'PY'
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(os.environ["ORACLEMCP_CONCURRENCY_LINT_ROOT"])
TEST_OUTPUT = os.environ.get("ORACLEMCP_CONCURRENCY_LINT_TEST_OUTPUT", "")


def git_files(*pathspecs: str) -> list[Path]:
    output = subprocess.check_output(
        ["git", "ls-files", *pathspecs],
        cwd=ROOT,
        text=True,
    )
    return [
        ROOT / line
        for line in output.splitlines()
        if line.endswith(".rs") and not line.endswith("/tests.rs") and "/tests/" not in line
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
    return path.relative_to(ROOT).as_posix()


def is_comment(line: str) -> bool:
    return line.strip().startswith("//")


def report_violation(kind: str, path: Path, line_no: int, line: str) -> None:
    violations.append(
        f"{kind}: {rel(path)}:{line_no}: {line.strip()}"
    )


rust_files = git_files("crates/oraclemcp-core/src", "crates/oraclemcp/src")
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
        if path_rel.startswith("crates/oraclemcp-core/src/") and std_mutex.search(line):
            report_violation("FORBIDDEN[core-std-mutex]", path, line_no, line)
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
