#!/usr/bin/env python3
"""Run a release build and record its elapsed time and peak process RSS."""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def process_tree_rss(root_pid: int) -> int:
    if os.name == "nt":
        rows = csv.reader(
            subprocess.check_output(["tasklist", "/fo", "csv", "/nh"], text=True).splitlines()
        )
        relevant = {"cargo.exe", "rustc.exe", "rust-lld.exe", "link.exe", "cl.exe"}
        return sum(
            int(row[4].replace(",", "").split()[0]) * 1024
            for row in rows
            if len(row) >= 5 and row[0].lower() in relevant
        )

    output = subprocess.check_output(["ps", "-eo", "pid=,ppid=,rss="], text=True)
    parent: dict[int, int] = {}
    rss: dict[int, int] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 3:
            pid, ppid, rss_kib = map(int, parts)
            parent[pid] = ppid
            rss[pid] = rss_kib * 1024
    tree = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, ppid in parent.items():
            if ppid in tree and pid not in tree:
                tree.add(pid)
                changed = True
    return sum(rss.get(pid, 0) for pid in tree)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command and args.command[0] == "--" else args.command
    if not command:
        parser.error("a build command is required after --")

    start = time.monotonic()
    process = subprocess.Popen(command)
    peak_rss = 0
    try:
        while process.poll() is None:
            try:
                peak_rss = max(peak_rss, process_tree_rss(process.pid))
            except (OSError, subprocess.CalledProcessError, ValueError):
                pass
            time.sleep(0.25)
    finally:
        status = process.wait()
    elapsed = time.monotonic() - start
    record = {
        "target": args.target,
        "elapsed_seconds": round(elapsed, 2),
        "peak_process_tree_rss_bytes": peak_rss,
        "exit_code": status,
        "command": command,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(
        f"release-build-metrics target={args.target} elapsed_seconds={record['elapsed_seconds']} "
        f"peak_process_tree_rss_bytes={peak_rss} exit_code={status}"
    )
    return status


if __name__ == "__main__":
    raise SystemExit(main())
