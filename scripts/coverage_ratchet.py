#!/usr/bin/env python3
"""Changed-line coverage evaluator for the D2 coverage ratchet
(bead oraclemcp-eng-program-bp8ia.5.2, plan §30.2 item 2 = §32.2 TRI-1).

Invoked by scripts/coverage_ratchet.sh -- see that script's header for the
full gate contract. This module is the pure, offline half: it takes a
unified git diff and an lcov export that scripts/coverage_ratchet.sh
produced with cargo-llvm-cov, and decides whether the CHANGED lines of the
diff are exercised.

Anti-gaming rationale (why this is NOT a "total coverage never decreases"
gate): a global never-decrease line is trivially gamed by assertion-free
tests that execute code without checking anything -- they RAISE the global
number while proving nothing (§30.9-C, §32.2 TRI-1). This gate therefore:

  1. measures only the CHANGED lines of the diff (new/changed code must be
     exercised by some test -- the property that actually protects a PR);
  2. leaves the global percentage recorded and trend-watched in
     tests/coverage/BASELINE.json (bead D1), never hard-gated; and
  3. delegates the "are the tests asserting anything" question to the
     per-crate MUTATION floor on the safety crates
     (scripts/mutation_safety_gate.sh check-floor-report), which coverage cannot
     answer by construction: a mutant survives an assertion-free test.

Subcommands:
  evaluate --diff <file> --lcov <file> [--floor N] [--safety-floor N]
      Parse the unified diff, keep added lines in crates/<crate>/src/*.rs,
      intersect with the lcov DA (line execution) records, and fail when a
      crate's changed-line coverage is below its floor. Safety crates
      (guard/audit/db) use the stricter --safety-floor. A changed source
      file with no lcov record at all is a hard failure (fail-closed: the
      coverage run did not exercise that crate, so nothing is proven).
  self-test
      Run the built-in fixture matrix proving the gate fails uncovered
      changed lines, passes covered ones, excludes non-instrumentable
      lines, and applies the stricter safety floor.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC_FILE_RE = re.compile(r"^crates/(?P<crate>[^/]+)/src/.+\.rs$")
HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,(?P<count>\d+))? @@")
# Stricter floor + review notice for the fail-closed safety core (plan
# §30.2 item 2: "per-crate mutation floor on guard/audit/db"; the same
# three crates get the stricter changed-line floor here).
SAFETY_FLOOR_CRATES = frozenset({"oraclemcp-guard", "oraclemcp-audit", "oraclemcp-db"})
# Crates whose diffs additionally require a NAMED invariant or negative
# test in review (§32.2 TRI-1; `oraclemcp` is the dispatch/main crate).
SAFETY_NOTICE_CRATES = SAFETY_FLOOR_CRATES | {"oraclemcp"}
MAX_UNCOVERED_LISTED = 50


def parse_diff_added_lines(diff_text: str) -> dict[str, set[int]]:
    """Map crates/<crate>/src/*.rs paths to the set of added/changed line
    numbers (new-file numbering). Deleted lines have no coverage to check."""
    added: dict[str, set[int]] = {}
    current: str | None = None
    new_line = 0
    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            path = raw[4:].strip()
            if path.startswith("b/"):
                path = path[2:]
            current = path if SRC_FILE_RE.match(path) else None
            continue
        if raw.startswith("@@"):
            match = HUNK_RE.match(raw)
            if not match:
                raise SystemExit(f"coverage-ratchet: E_BAD_DIFF: unparseable hunk header: {raw!r}")
            new_line = int(match.group("start"))
            continue
        if current is None:
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            added.setdefault(current, set()).add(new_line)
            new_line += 1
        elif raw.startswith(" "):
            new_line += 1
        # '-' lines advance only the old file; '\ No newline' advances neither.
    return added


def parse_lcov(lcov_text: str) -> dict[str, dict[int, int]]:
    """Map ROOT-relative source paths to {line: execution_count}."""
    files: dict[str, dict[int, int]] = {}
    current: dict[int, int] | None = None
    for raw in lcov_text.splitlines():
        if raw.startswith("SF:"):
            path = raw[3:].strip()
            try:
                rel = Path(path).resolve().relative_to(ROOT).as_posix()
            except ValueError:
                rel = path
            current = files.setdefault(rel, {})
        elif raw.startswith("DA:") and current is not None:
            line_str, count_str = raw[3:].split(",")[:2]
            current[int(line_str)] = max(current.get(int(line_str), 0), int(count_str))
        elif raw.strip() == "end_of_record":
            current = None
    return files


def evaluate(
    diff_text: str,
    lcov_text: str,
    floor: float,
    safety_floor: float,
    *,
    file_exists=None,
) -> tuple[bool, list[str]]:
    """Return (ok, report_lines). Pure so the self-test can pin it."""
    if file_exists is None:
        file_exists = lambda rel: (ROOT / rel).is_file()  # noqa: E731
    added = parse_diff_added_lines(diff_text)
    lcov = parse_lcov(lcov_text)
    lines: list[str] = []
    per_crate: dict[str, tuple[int, int, list[str]]] = {}
    for path in sorted(added):
        if not file_exists(path):
            lines.append(f"  skip (deleted/renamed away): {path}")
            continue
        crate = SRC_FILE_RE.match(path).group("crate")
        if path not in lcov:
            lines.append(
                f"coverage-ratchet: FAIL E_NO_COVERAGE_DATA: changed source file {path} has no "
                "lcov record -- the coverage run did not include its crate's tests, so its "
                "changed lines are unproven (fail-closed; check the -p crate scoping)"
            )
            return False, lines
        instrumented = added[path] & set(lcov[path])
        covered = {line for line in instrumented if lcov[path][line] > 0}
        total, hit, uncovered = per_crate.get(crate, (0, 0, []))
        uncovered = uncovered + [f"{path}:{line}" for line in sorted(instrumented - covered)]
        per_crate[crate] = (total + len(instrumented), hit + len(covered), uncovered)

    ok = True
    safety_touched = sorted(set(per_crate) & SAFETY_NOTICE_CRATES)
    lines.append("crate                    changed  covered   pct    floor  verdict")
    for crate in sorted(per_crate):
        total, hit, uncovered = per_crate[crate]
        crate_floor = safety_floor if crate in SAFETY_FLOOR_CRATES else floor
        if total == 0:
            lines.append(f"{crate:<24} {total:>7} {hit:>8}     --  {crate_floor:>5.1f}%  PASS (no instrumentable changed lines)")
            continue
        pct = 100.0 * hit / total
        verdict = "PASS" if pct >= crate_floor else "FAIL"
        if verdict == "FAIL":
            ok = False
        lines.append(f"{crate:<24} {total:>7} {hit:>8} {pct:>5.1f}%  {crate_floor:>5.1f}%  {verdict}")
        if verdict == "FAIL":
            for entry in uncovered[:MAX_UNCOVERED_LISTED]:
                lines.append(f"    uncovered changed line: {entry}")
            if len(uncovered) > MAX_UNCOVERED_LISTED:
                lines.append(f"    ... and {len(uncovered) - MAX_UNCOVERED_LISTED} more")
    if not per_crate:
        lines.append("(no changed crates/<crate>/src/*.rs lines in the diff -- changed-line leg trivially green)")
    if safety_touched:
        lines.append(
            "coverage-ratchet: SAFETY-CRITICAL DIFF (" + ", ".join(safety_touched) + "): "
            "review must name the invariant or negative test this change is pinned by "
            "(plan §30.2 item 2 / §32.2 TRI-1); the per-crate mutation floor "
            "(scripts/mutation_safety_gate.sh check-floor-report) guards that requirement mechanically."
        )
    return ok, lines


def cmd_evaluate(args: argparse.Namespace) -> int:
    diff_text = Path(args.diff).read_text()
    lcov_text = Path(args.lcov).read_text()
    ok, lines = evaluate(diff_text, lcov_text, args.floor, args.safety_floor)
    for line in lines:
        print(line)
    if not ok:
        print(
            f"coverage-ratchet: FAIL -- changed-line coverage below the floor "
            f"(floor={args.floor}%, safety-floor={args.safety_floor}%). Exercise the changed "
            "lines with a test that ASSERTS behaviour; do not pad unrelated tests (see the "
            "anti-gaming rationale in this script's header).",
            file=sys.stderr,
        )
        return 1
    print("coverage-ratchet: changed-line leg OK")
    return 0


def cmd_self_test(_args: argparse.Namespace) -> int:
    fixture_dir = ROOT / "tests/fixtures/coverage_ratchet"
    fixture_diff = (fixture_dir / "changed-line.diff").read_text()
    fixture_covered = (fixture_dir / "changed-line-covered.lcov").read_text()
    fixture_lowered = (fixture_dir / "changed-line-lowered.lcov").read_text()
    fixture_exists = lambda _rel: True  # noqa: E731
    fixture_ok, _ = evaluate(
        fixture_diff, fixture_covered, 80.0, 90.0, file_exists=fixture_exists
    )
    lowered_ok, lowered_lines = evaluate(
        fixture_diff, fixture_lowered, 80.0, 90.0, file_exists=fixture_exists
    )
    fixture_failures: list[str] = []
    if not fixture_ok:
        fixture_failures.append("tracked legitimate changed-line fixture was rejected")
    if lowered_ok or not any("uncovered changed line" in line for line in lowered_lines):
        fixture_failures.append("tracked lowered changed-line fixture was accepted")

    diff = """\
diff --git a/crates/oraclemcp-error/src/lib.rs b/crates/oraclemcp-error/src/lib.rs
--- a/crates/oraclemcp-error/src/lib.rs
+++ b/crates/oraclemcp-error/src/lib.rs
@@ -1,0 +10,3 @@
+fn covered_line() {}
+fn uncovered_line() {}
+// a comment: not instrumentable
diff --git a/crates/oraclemcp-guard/src/lib.rs b/crates/oraclemcp-guard/src/lib.rs
--- a/crates/oraclemcp-guard/src/lib.rs
+++ b/crates/oraclemcp-guard/src/lib.rs
@@ -1,0 +20,2 @@
+fn guard_a() {}
+fn guard_b() {}
"""
    lcov = """\
SF:crates/oraclemcp-error/src/lib.rs
DA:10,7
DA:11,0
end_of_record
SF:crates/oraclemcp-guard/src/lib.rs
DA:20,3
DA:21,3
end_of_record
"""
    exists = lambda _rel: True  # noqa: E731
    failures: list[str] = fixture_failures

    # 1. An uncovered changed line drags oraclemcp-error to 50% < 80% floor.
    ok, lines = evaluate(diff, lcov, 80.0, 90.0, file_exists=exists)
    if ok:
        failures.append("uncovered changed line was accepted")
    # 2. The comment line (no DA record) must be excluded from the denominator:
    #    error crate is 1 covered of 2 instrumentable, not 1 of 3.
    error_row = next((ln for ln in lines if ln.startswith("oraclemcp-error")), "")
    tokens = error_row.split()
    if len(tokens) < 3 or tokens[1] != "2" or tokens[2] != "1":
        failures.append(f"non-instrumentable line entered the denominator: {error_row!r}")
    # 3. Fully covered guard lines pass, and the safety notice names the crate.
    if not any("SAFETY-CRITICAL DIFF" in ln and "oraclemcp-guard" in ln for ln in lines):
        failures.append("safety-critical diff notice missing")
    # 4. Covered-only diff passes.
    covered_only = diff.split("diff --git a/crates/oraclemcp-guard")[0]
    covered_lcov = "SF:crates/oraclemcp-error/src/lib.rs\nDA:10,7\nDA:11,4\nend_of_record\n"
    ok, _ = evaluate(covered_only, covered_lcov, 80.0, 90.0, file_exists=exists)
    if not ok:
        failures.append("fully covered change was rejected")
    # 5. Safety floor is stricter: guard at 1/2 = 50% fails the 90% floor even
    #    with a permissive 40% base floor.
    guard_half_lcov = "SF:crates/oraclemcp-guard/src/lib.rs\nDA:20,3\nDA:21,0\nend_of_record\n"
    guard_only = "diff --git a/crates/oraclemcp-guard/src/lib.rs b/crates/oraclemcp-guard/src/lib.rs\n" + diff.split("diff --git a/crates/oraclemcp-guard/src/lib.rs b/crates/oraclemcp-guard/src/lib.rs\n")[1]
    ok, _ = evaluate(guard_only, guard_half_lcov, 40.0, 90.0, file_exists=exists)
    if ok:
        failures.append("safety floor was not applied to a guard diff")
    # 6. A changed file absent from the lcov export is a hard fail-closed error.
    ok, lines = evaluate(covered_only, "SF:crates/other/src/lib.rs\nDA:1,1\nend_of_record\n", 80.0, 90.0, file_exists=exists)
    if ok or not any("E_NO_COVERAGE_DATA" in ln for ln in lines):
        failures.append("changed file without coverage data was accepted")
    # 7. A diff outside crates/*/src is trivially green.
    ok, lines = evaluate(
        "+++ b/docs/README.md\n@@ -1,0 +1,1 @@\n+hello\n", covered_lcov, 80.0, 90.0, file_exists=exists
    )
    if not ok or not any("trivially green" in ln for ln in lines):
        failures.append("non-source diff was not trivially green")

    if failures:
        for failure in failures:
            print(f"coverage-ratchet: SELF-TEST FAIL: {failure}", file=sys.stderr)
        return 1
    print("coverage-ratchet: self-test OK (tracked legitimate/lowered fixtures; fails "
          "uncovered changed lines; excludes non-instrumentable; safety floor stricter; "
          "no-data is fail-closed)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    ev = sub.add_parser("evaluate")
    ev.add_argument("--diff", required=True)
    ev.add_argument("--lcov", required=True)
    ev.add_argument("--floor", type=float, default=80.0)
    ev.add_argument("--safety-floor", type=float, default=90.0)
    ev.set_defaults(func=cmd_evaluate)
    st = sub.add_parser("self-test")
    st.set_defaults(func=cmd_self_test)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except OSError as error:
        raise SystemExit(f"coverage-ratchet: E_IO: {error}")
