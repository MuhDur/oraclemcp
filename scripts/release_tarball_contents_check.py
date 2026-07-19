#!/usr/bin/env python3
"""Verify every workspace crate's `cargo package` tarball is self-contained.

This is the release-rehearsal counterpart to `cargo package --workspace
--locked --no-verify` (release.yml's `checks` job): that step proves the
tarball ASSEMBLES, but `--no-verify` deliberately skips compiling it (a
compile-verify build cannot resolve sibling `oraclemcp-*` path dependencies
until each one is actually published on crates.io in dependency order --
see the comment on that step and `scripts/publish_crates.sh`).

That gap is exactly what broke the 0.9.0 tag on its second attempt: `oraclemcp`
embedded `install.sh`/`install.ps1` via `include_bytes!("../../../install.sh")`,
a path outside the crate directory, so `cargo package` happily assembled a
tarball missing those files and only `cargo publish --dry-run`'s COMPILE step
(minutes into the real tag pipeline) caught it (fix: cfc650b, "embed installers
from crate-local copies so the tarball verifies").

Rather than fighting the sibling-resolution problem, this check verifies the
same failure class directly and cheaply: every `include_bytes!`/`include_str!`
literal-path argument in each crate's non-test source must resolve to a file
`cargo package --list` actually includes in that crate's tarball. `--list` does
no dependency resolution and no compilation, so it works identically for a
brand-new, not-yet-published version -- unlike a real verify build.

Usage:
    scripts/release_tarball_contents_check.py [--allow-dirty]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

INCLUDE_MACRO = re.compile(r'\b(include_bytes|include_str)!\s*\(\s*"([^"]+)"\s*\)')
CFG_TEST_ATTR = re.compile(r"#\[\s*cfg\s*\(\s*test\s*\)\s*\]")

# Whole-file skip: this repo's convention for unit-test modules living inside
# `src/` (e.g. `tests_ci_lanes.rs`, `main_tests.rs`). `cargo package`'s default
# verify build (like `cargo build`) does not compile `#[cfg(test)]` items, and
# these files are conventionally test-only end to end, so flagging an
# out-of-crate include here would be a false positive against the real gate
# this script stands in for.
TEST_FILE_PATTERNS = (
    re.compile(r"(^|/)tests_[^/]*\.rs$"),
    re.compile(r"(^|/)[^/]*_tests\.rs$"),
    re.compile(r"(^|/)tests/"),
)


def is_test_only_file(rel_path: str) -> bool:
    return any(p.search(rel_path) for p in TEST_FILE_PATTERNS)


def is_cfg_test_gated(lines: list[str], macro_line_idx: int) -> bool:
    """Best-effort: does a `#[cfg(test)]` attribute sit within the few lines
    immediately above the item containing this macro call? This mirrors what
    the real default verify build would skip; it is deliberately conservative
    (a missed cfg(test) just means we ALSO run the (harmless, still-cheap)
    inclusion check on it, never the reverse)."""
    lookback = 5
    start = max(0, macro_line_idx - lookback)
    for line in lines[start:macro_line_idx]:
        if CFG_TEST_ATTR.search(line):
            return True
    return False


def cargo_metadata() -> list[dict]:
    raw = subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=ROOT,
        text=True,
    )
    return json.loads(raw)["packages"]


def package_list(crate_name: str, crate_root: Path, allow_dirty: bool) -> set[str]:
    cmd = ["cargo", "package", "-p", crate_name, "--locked", "--list"]
    if allow_dirty:
        cmd.append("--allow-dirty")
    completed = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
    if completed.returncode != 0:
        sys.stderr.write(
            f"release-tarball-contents-check: `cargo package -p {crate_name} --list` failed:\n"
            f"{completed.stdout}{completed.stderr}\n"
        )
        raise SystemExit(1)
    return {line.strip() for line in completed.stdout.splitlines() if line.strip()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()

    packages = cargo_metadata()
    failures: list[str] = []
    checked_files = 0
    checked_crates = 0

    for pkg in packages:
        crate_name = pkg["name"]
        manifest_path = Path(pkg["manifest_path"])
        crate_root = manifest_path.parent
        src_dir = crate_root / "src"
        if not src_dir.is_dir():
            continue

        rs_files = sorted(src_dir.rglob("*.rs"))
        macro_files = []
        for rs_file in rs_files:
            rel_to_crate = rs_file.relative_to(crate_root).as_posix()
            if is_test_only_file(rel_to_crate):
                continue
            text = rs_file.read_text(encoding="utf-8", errors="replace")
            if "include_bytes!" not in text and "include_str!" not in text:
                continue
            macro_files.append((rs_file, rel_to_crate, text))

        if not macro_files:
            continue

        checked_crates += 1
        listed = package_list(crate_name, crate_root, args.allow_dirty)

        for rs_file, rel_to_crate, text in macro_files:
            lines = text.splitlines()
            for match in INCLUDE_MACRO.finditer(text):
                macro_name, literal = match.group(1), match.group(2)
                line_idx = text.count("\n", 0, match.start())
                if is_cfg_test_gated(lines, line_idx):
                    continue
                checked_files += 1
                target = (rs_file.parent / literal).resolve()
                try:
                    rel_to_root = target.relative_to(crate_root.resolve()).as_posix()
                except ValueError:
                    failures.append(
                        f"{rel_to_crate}:{line_idx + 1}: {crate_name}: "
                        f'{macro_name}!("{literal}") resolves to {target}, OUTSIDE the crate '
                        f"directory ({crate_root}) -- `cargo package` can never include this file, "
                        f"so the tarball will fail to compile on publish (this is the exact class of "
                        f"bug fixed in cfc650b for install.sh/install.ps1)"
                    )
                    continue
                if rel_to_root not in listed:
                    failures.append(
                        f"{rel_to_crate}:{line_idx + 1}: {crate_name}: "
                        f'{macro_name}!("{literal}") resolves to {rel_to_root}, which is inside the '
                        f"crate directory but is NOT in `cargo package -p {crate_name} --list` output "
                        f"(check Cargo.toml include/exclude, or that the file is git-tracked)"
                    )

    if failures:
        sys.stderr.write("release-tarball-contents-check: FAIL\n\n")
        for failure in failures:
            sys.stderr.write(f"  {failure}\n")
        sys.stderr.write(
            f"\nchecked {checked_files} include_bytes!/include_str! reference(s) across "
            f"{checked_crates} crate(s); {len(failures)} would break `cargo package`/`cargo publish` "
            f"verification.\n"
        )
        return 1

    print(
        f"release-tarball-contents-check: OK -- {checked_files} include_bytes!/include_str! "
        f"reference(s) across {checked_crates} crate(s) all resolve inside their packaged tarball."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
