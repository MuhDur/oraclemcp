#!/usr/bin/env bash
# entry-trace/v1 contract (bead yg4x.6).
#
# This is intentionally an offline source contract: it does not replace a live
# Oracle run. It proves that a live result can be traced from a concrete
# dispatch, through its canonical runner, to an explicit result surface. The
# actual live runners still use gvenzl services or the declared local Oracle
# lane; this gate never synthesizes a success for them.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "entry-trace: no $PYTHON_BIN on PATH" >&2
  exit 2
fi

exec "$PYTHON_BIN" - "$ROOT" "${1:-}" <<'PY'
from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
mode = sys.argv[2]
manifest_path = root / "scripts" / "entry_trace_contract.json"


def check(document: dict, *, source_root: Path) -> list[str]:
    errors: list[str] = []
    if document.get("schema") != "entry-trace/v1":
        errors.append("schema must be entry-trace/v1")

    tri = document.get("tri_state")
    if not isinstance(tri, dict) or tri.get("outcomes") != ["PASS", "SKIP", "FAIL"]:
        errors.append("tri_state.outcomes must be exactly PASS/SKIP/FAIL")
    if not isinstance(tri, dict) or tri.get("required_skip") != "FAIL":
        errors.append("tri_state.required_skip must be FAIL")
    try:
        skip_reason = re.compile(str(tri["skip_reason_pattern"]))
    except (KeyError, re.error):
        errors.append("tri_state.skip_reason_pattern must be a valid regex")
        skip_reason = re.compile("$")

    inventory = document.get("script_inventory")
    if not isinstance(inventory, list):
        return errors + ["script_inventory must be a list"]
    paths: set[str] = set()
    for item in inventory:
        if not isinstance(item, dict):
            errors.append("script_inventory entry must be an object")
            continue
        path = item.get("path")
        kind = item.get("kind")
        if not isinstance(path, str) or not path.startswith("scripts/"):
            errors.append(f"inventory path is not a scripts/ path: {path!r}")
            continue
        if path in paths:
            errors.append(f"duplicate inventory path: {path}")
        paths.add(path)
        if kind == "entry_point":
            if not isinstance(item.get("trace"), str):
                errors.append(f"entry point has no trace: {path}")
        elif kind == "helper":
            reason = item.get("excluded_reason")
            if not isinstance(reason, str) or not skip_reason.fullmatch(reason):
                errors.append(f"helper has no machine-readable exclusion reason: {path}")
        else:
            errors.append(f"inventory kind must be entry_point or helper: {path}")

    discovered = {
        p.relative_to(source_root).as_posix()
        for p in (source_root / "scripts").iterdir()
        if p.is_file() and p.suffix in {".sh", ".py"}
    }
    missing = sorted(discovered - paths)
    extra = sorted(paths - discovered)
    for path in missing:
        errors.append(f"unregistered script: {path}")
    for path in extra:
        errors.append(f"inventory names missing script: {path}")

    traces = document.get("traces")
    if not isinstance(traces, list):
        return errors + ["traces must be a list"]
    trace_ids: set[str] = set()
    for trace in traces:
        if not isinstance(trace, dict):
            errors.append("trace must be an object")
            continue
        ident = trace.get("id")
        if not isinstance(ident, str) or not ident:
            errors.append("trace has no id")
            continue
        if ident in trace_ids:
            errors.append(f"duplicate trace id: {ident}")
        trace_ids.add(ident)
        if trace.get("skip_policy") not in {"fail", "typed-skip-reason"}:
            errors.append(f"trace {ident} has no valid skip policy")
        if trace.get("tier") == "required" and trace.get("skip_policy") != "fail":
            errors.append(f"required trace {ident} must turn SKIP into FAIL")
        runner = trace.get("runner")
        if not isinstance(runner, str) or not (source_root / runner).is_file():
            errors.append(f"trace {ident} has no existing runner")
        for dispatch in trace.get("dispatch", []):
            _require_markers(errors, source_root, ident, "dispatch", dispatch)
        result = trace.get("result")
        if not isinstance(result, dict):
            errors.append(f"trace {ident} has no result surface")
        else:
            _require_markers(errors, source_root, ident, "result", result)
        for cap in trace.get("capabilities", []):
            if not isinstance(cap, dict) or not isinstance(cap.get("name"), str):
                errors.append(f"trace {ident} has malformed capability")
                continue
            _require_markers(
                errors,
                source_root,
                ident,
                f"capability {cap['name']}",
                {"path": cap.get("provisioner"), "markers": [cap.get("marker")]},
            )

    for item in inventory:
        if isinstance(item, dict) and item.get("kind") == "entry_point" and item.get("trace") not in trace_ids:
            errors.append(f"entry point references unknown trace: {item['path']}")

    return errors


def _require_markers(errors: list[str], source_root: Path, ident: str, role: str, entry: object) -> None:
    if not isinstance(entry, dict):
        errors.append(f"trace {ident} has malformed {role}")
        return
    path = entry.get("path")
    markers = entry.get("markers", [entry.get("marker")])
    if not isinstance(path, str) or not (source_root / path).is_file():
        errors.append(f"trace {ident} {role} has no existing path")
        return
    if not isinstance(markers, list) or not all(isinstance(m, str) and m for m in markers):
        errors.append(f"trace {ident} {role} has no marker")
        return
    _require_source_markers(errors, source_root / path, f"trace {ident} {role}", markers)


def _require_source_markers(errors: list[str], path: Path, label: str, markers: list[str]) -> None:
    text = path.read_text()
    for marker in markers:
        if marker not in text:
            errors.append(f"{label} missing marker {marker!r} in {path.relative_to(root)}")


document = json.loads(manifest_path.read_text())
errors = check(document, source_root=root)
if mode == "--self-test":
    missing_script = copy.deepcopy(document)
    missing_script["script_inventory"] = missing_script["script_inventory"][1:]
    if not any("unregistered script" in error for error in check(missing_script, source_root=root)):
        errors.append("self-test failed: an unregistered script was accepted")
    bad_required = copy.deepcopy(document)
    bad_required["traces"][0]["skip_policy"] = "typed-skip-reason"
    if not any("required trace" in error for error in check(bad_required, source_root=root)):
        errors.append("self-test failed: a required skip policy was accepted")
elif mode:
    errors.append(f"unknown mode: {mode}")

if errors:
    for error in errors:
        print(f"entry-trace: FAIL: {error}", file=sys.stderr)
    sys.exit(1)
print("entry-trace: OK (entry-trace/v1; required SKIP=FAIL; live SKIP requires reason)")
PY
