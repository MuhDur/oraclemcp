#!/usr/bin/env python3
"""Extract an Oracle Net SSL server DN from wallet network config files."""
from __future__ import annotations
import re
import sys
from pathlib import Path

PATTERN = re.compile(r"ssl_server_cert_dn\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s)]+))", re.I)

def extract(paths: list[Path]) -> str:
    for path in paths:
        if not path.is_file():
            continue
        match = PATTERN.search(path.read_text(errors="replace"))
        if match:
            return next(value for value in match.groups() if value is not None).strip()
    return ""

if __name__ == "__main__":
    value = extract([Path(arg) for arg in sys.argv[1:]])
    if value:
        print(value)
    else:
        raise SystemExit(1)
