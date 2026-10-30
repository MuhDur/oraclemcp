#!/usr/bin/env python3
"""Generate the installed selftest's fixture-free projections of W4 cases."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EMBEDDED = ROOT / "crates/oraclemcp/selftest/readonly_cases.json"
W4_CASES = ROOT / "scripts/e2e/w4/cases"

# Explicit substitutions keep installed probes independent of W4's disposable
# owners. Tools, levels and success/refusal expectations come from W4 itself.
PROJECTIONS = (
    ("selftest_query_dual", "rel012_i28_order_alias", {"sql": "SELECT 1 AS n FROM DUAL", "max_rows": 5}),
    ("selftest_list_schemas_all_users", "w4_list_schemas_name_like_filter", {"name_like": "ALL"}),
    ("selftest_connection_info", "w4_connection_info_effective_access_readonly_pinned", {}),
    ("selftest_db_health", "w4_db_health_subcheck_filter", {}),
)


def generate() -> list[dict]:
    sources: dict[str, dict] = {}
    for path in sorted(W4_CASES.glob("*.json")):
        if path.name == "schema.json":
            continue
        parsed = json.loads(path.read_text())
        # aliases.json also defines runtime-generated pairs. Only its ordinary
        # static cases can be a source for an embedded installed-binary probe.
        items = parsed.get("cases", []) if isinstance(parsed, dict) else parsed
        if not isinstance(items, list):
            raise ValueError(f"{path.name}: ordinary cases must be an array")
        for case in items:
            source_id = case["case_id"]
            if source_id in sources:
                raise ValueError(f"duplicate W4 source {source_id}")
            sources[source_id] = case
    result = []
    for case_id, source_id, arguments in PROJECTIONS:
        source = sources.get(source_id)
        if source is None:
            raise ValueError(f"{case_id}: missing W4 source {source_id!r}")
        if source.get("level") != "READ_ONLY" or source.get("setup", []) or source.get("requires", []):
            raise ValueError(f"{source_id}: source must be READ_ONLY with no setup or requirements")
        error_class = source["expect"].get("error_class")
        expect = {"kind": "typed_error", "error_class": error_class} if error_class else {"kind": "rows"}
        result.append(dict(case_id=case_id, source_case_id=source_id, tool=source["tool"],
                           level=source["level"], arguments=arguments, expect=expect))
    return result


def check() -> list[str]:
    try:
        expected = generate()
    except (ValueError, KeyError) as error:
        return [str(error)]
    if json.loads(EMBEDDED.read_text()) != expected:
        return ["embedded cases differ from their W4 projections; inspect the source change before --write"]
    return []


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.write:
        EMBEDDED.write_text(json.dumps(generate(), indent=2) + "\n")
        return 0
    failures = check()
    if failures:
        print("selftest W4 drift check failed:\n" + "\n".join(f"- {x}" for x in failures))
        return 1
    print("selftest W4 drift check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
