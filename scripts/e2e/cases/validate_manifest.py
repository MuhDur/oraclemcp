#!/usr/bin/env python3
"""Validate the 0.12 release cases and enforce their executed results.

The manifest is an input to the external W4 runner. A case listed here is not
evidence that its regression is fixed. --check-results reads a JSON object with
``cases`` (case_id, lane, transport, test_id, verdict) and ``cargo_test_logs``
(paths to unmodified cargo test output). Every applicable live case must have
one matching pass, and each unit test must appear as ``test ... ok`` in cargo
output. ``--capability`` adds measured target capabilities to the lane's
version and ADB label; it must not be used to assume a privilege exists.
"""

import argparse
import copy
import json
import re
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
DEFAULT_MANIFEST = HERE / "release_0_12.json"
SCHEMA = HERE / "release_0_12.schema.json"
LANE_CAPABILITIES = {
    "xe18": {"version:18"},
    "xe21": {"version:21"},
    "free23": {"version:23"},
    "adb": {"version:23", "adb"},
}
FORBIDDEN_INPUT = {
    "OCID": re.compile(r"\bocid1\.[A-Za-z0-9._-]+", re.I),
    "IP address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "hostname": re.compile(r"\b(?:[A-Za-z0-9-]+\.)+(?:com|net|org|cloud|local|internal)\b", re.I),
    "connect string": re.compile(r"//[^/\s:]+:\d+|\b(?:host|service_name)\s*=", re.I),
    "wallet path": re.compile(r"(?:[/\\](?:home|Users|etc|tmp)[/\\].*(?:wallet|tns)|[/\\][^\s]+\.(?:sso|p12|pem))", re.I),
}
OBJECT_REFERENCE = re.compile(r"\b(?:FROM|JOIN|UPDATE|INTO)\s+([A-Za-z][A-Za-z0-9_<>.]*)", re.I)
CTE_NAME = re.compile(r"\b(?:WITH|,)\s+([A-Za-z][A-Za-z0-9_]*)\s+AS\s*\(", re.I)
FIXTURE_NAME = re.compile(r"^W4_<run>(?:_[A-Z0-9_]+)?$", re.I)
SAFE_ORACLE_OBJECTS = {"DUAL", "USER_OBJECTS"}
SAFE_SQL_WORDS = {
    "SELECT", "FROM", "WHERE", "AS", "GROUP", "BY", "ORDER", "DESC",
    "COUNT", "MAX", "JOIN", "NATURAL", "USING", "WITH", "UNION", "ALL", "EXISTS",
    "IN", "ID", "GRP", "N", "A", "X", "T", "DOC", "CUSTOMER",
    "OBJECT_NAME", "ORA_ROWSCN", "DUAL", "USER_OBJECTS",
}
SQL_WORD = re.compile(r"[A-Za-z][A-Za-z0-9_$#]*")
FIXTURE_IN_SQL = re.compile(r"W4_<run>(?:_[A-Z0-9_]+)?", re.I)


class ValidationError(ValueError):
    pass


def log(case_id, check, verdict):
    print(json.dumps({"case_id": case_id, "check": check, "verdict": verdict}), file=sys.stderr)


def fail(message):
    raise ValidationError(message)


def schema_check(value, rule, location):
    kind = rule.get("type")
    types = {
        "array": lambda x: isinstance(x, list),
        "object": lambda x: isinstance(x, dict),
        "string": lambda x: isinstance(x, str),
        "integer": lambda x: type(x) is int,
    }
    if kind and not types[kind](value):
        fail(f"{location}: expected {kind}")
    if "const" in rule and value != rule["const"]:
        fail(f"{location}: expected {rule['const']!r}")
    if "enum" in rule and value not in rule["enum"]:
        fail(f"{location}: value outside enum: {value!r}")
    if kind == "string":
        if len(value) < rule.get("minLength", 0):
            fail(f"{location}: empty string")
        if "pattern" in rule and re.fullmatch(rule["pattern"], value) is None:
            fail(f"{location}: pattern mismatch: {value!r}")
    if kind == "integer" and not rule.get("minimum", value) <= value <= rule.get("maximum", value):
        fail(f"{location}: outside allowed range")
    if kind == "array":
        if len(value) < rule.get("minItems", 0):
            fail(f"{location}: too few items")
        if rule.get("uniqueItems") and len({json.dumps(x, sort_keys=True) for x in value}) != len(value):
            fail(f"{location}: duplicate items")
        for index, item in enumerate(value):
            schema_check(item, rule.get("items", {}), f"{location}[{index}]")
    if kind == "object":
        if len(value) < rule.get("minProperties", 0):
            fail(f"{location}: too few properties")
        required = set(rule.get("required", []))
        missing = required - value.keys()
        if missing:
            fail(f"{location}: missing {sorted(missing)}")
        properties = rule.get("properties", {})
        if rule.get("additionalProperties") is False and value.keys() - properties.keys():
            fail(f"{location}: unknown properties {sorted(value.keys() - properties.keys())}")
        for key, item in value.items():
            schema_check(item, properties.get(key, {}), f"{location}.{key}")


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


def named_values(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from named_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from named_values(item)


def check_synthetic_input(case):
    for item in strings(case["input"]):
        for name, pattern in FORBIDDEN_INPUT.items():
            if pattern.search(item):
                fail(f"{case['case_id']}: input contains {name}")
        if not item.lstrip().upper().startswith(("SELECT ", "WITH ", "UPDATE ", "INSERT ", "DELETE ")):
            continue
        cte_names = {name.upper() for name in CTE_NAME.findall(item)}
        for object_name in OBJECT_REFERENCE.findall(item):
            # The source of a relation must be a run-stamped fixture or a
            # specifically named, public Oracle dictionary/builtin object.
            parts = object_name.upper().split(".")
            if not all(FIXTURE_NAME.fullmatch(part) for part in parts) and object_name.upper() not in SAFE_ORACLE_OBJECTS | cte_names:
                fail(f"{case['case_id']}: non-synthetic SQL object {object_name}")
        unquoted = re.sub(r"'[^']*'|/\*.*?\*/|--[^\n]*", " ", item, flags=re.S)
        without_fixtures = FIXTURE_IN_SQL.sub(" ", unquoted)
        for word in SQL_WORD.findall(without_fixtures):
            if word.upper() not in SAFE_SQL_WORDS | cte_names:
                fail(f"{case['case_id']}: SQL identifier outside fixture vocabulary: {word}")
    for key, value in named_values(case["input"]):
        if key in {"name", "owner", "table", "profile"} and (
            not isinstance(value, str) or not FIXTURE_NAME.fullmatch(value)
        ):
            fail(f"{case['case_id']}: non-synthetic {key}")


def validate_manifest(cases, schema):
    schema_check(cases, schema, "manifest")
    seen_cases, seen_tests, issues = set(), set(), set()
    for case in cases:
        case_id = case["case_id"]
        if case_id in seen_cases:
            fail(f"duplicate case_id {case_id}")
        seen_cases.add(case_id)
        if case["test_id"] in seen_tests:
            fail(f"duplicate test_id {case['test_id']}")
        seen_tests.add(case["test_id"])
        if not case_id.startswith(f"rel012_i{case['issue']}_"):
            fail(f"{case_id}: issue number disagrees with case_id")
        if case["evidence_path"] != f"target/e2e/w4/{{lane}}/{case_id}.jsonl":
            fail(f"{case_id}: evidence_path disagrees with case_id")
        if case["reproducible"] == "live" and re.fullmatch(r"w4_[a-z0-9_]+", case["test_id"]) is None:
            fail(f"{case_id}: live test_id must use w4_<tool>_<case> form")
        if case["reproducible"] == "unit" and re.fullmatch(r"[A-Za-z0-9_]+(?:::[A-Za-z0-9_]+)+", case["test_id"]) is None:
            fail(f"{case_id}: unit test_id must be a Rust test path")
        check_synthetic_input(case)
        issues.add(case["issue"])
        log(case_id, "manifest", "pass")
    missing = set(range(28, 57)) - issues
    if missing:
        fail(f"missing issue(s): {sorted(missing)}")
    return cases


def required_live(cases, lane, extra_capabilities=()):
    if lane not in LANE_CAPABILITIES:
        fail(f"unknown lane {lane!r}; choose {', '.join(LANE_CAPABILITIES)}")
    available = LANE_CAPABILITIES[lane] | set(extra_capabilities)
    return [case for case in cases if case["reproducible"] == "live"
            and any(version in available for version in case["versions"])
            and set(case["capabilities"]).issubset(available)]


def validate_results(cases, results, lane, transport, extra_capabilities=()):
    if transport not in {"stdio", "http"}:
        fail("--transport must be stdio or http")
    runs = results.get("cases", [])
    if not isinstance(runs, list):
        fail("results.cases must be an array")
    indexed = {}
    for run in runs:
        if not isinstance(run, dict) or not {"case_id", "lane", "transport", "verdict"} <= run.keys():
            fail("result case needs case_id, lane, transport, verdict")
        key = (run["case_id"], run["lane"], run["transport"])
        if key in indexed:
            fail(f"duplicate result for {key}")
        indexed[key] = run
    for case in required_live(cases, lane, extra_capabilities):
        case_id = case["case_id"]
        run = indexed.get((case_id, lane, transport))
        if run is None:
            log(case_id, "result", "missing")
            fail(f"missing required live case {case_id} on {lane}/{transport}")
        if run["verdict"] != "pass" or run.get("test_id") != case["test_id"]:
            log(case_id, "result", "red")
            fail(f"red or mismatched live case {case_id} on {lane}/{transport}")
        log(case_id, "result", "pass")
    cargo_output = results.get("cargo_test_output", "")
    if not isinstance(cargo_output, str):
        fail("results.cargo_test_output must be a string")
    for case in cases:
        if case["reproducible"] != "unit":
            continue
        name = case["test_id"].split("::", 1)[-1]
        if re.search(r"^test\s+" + re.escape(name) + r"\s+\.\.\.\s+ok\s*$", cargo_output, re.M) is None:
            log(case["case_id"], "unit_result", "missing")
            fail(f"missing green cargo test {case['test_id']}")
        log(case["case_id"], "unit_result", "pass")


def selftest(cases, schema):
    def rejected(name, mutation, expected):
        sample = copy.deepcopy(cases)
        mutation(sample)
        try:
            validate_manifest(sample, schema)
        except ValidationError as exc:
            if expected not in str(exc):
                fail(f"selftest {name}: wrong refusal {exc}")
            print(f"{name}: rejected ({expected})")
            return
        fail(f"selftest {name}: accepted invalid manifest")

    validate_manifest(cases, schema)
    rejected("missing_issue_40", lambda xs: xs.__setitem__(slice(None), [x for x in xs if x["issue"] != 40]), "missing issue")
    rejected("duplicate_case_id", lambda xs: xs.append(copy.deepcopy(xs[0])), "duplicate case_id")
    rejected("unsanitized_hostname", lambda xs: xs[0]["input"].update({"host": "field.example.com"}), "hostname")
    rejected("unsanitized_ocid", lambda xs: xs[0]["input"].update({"id": "ocid1.autonomousdatabase.oc1.example"}), "OCID")
    rejected("non_synthetic_object", lambda xs: xs[0]["input"].update({"sql": "SELECT id FROM CUSTOMER_TABLE"}), "non-synthetic SQL object")
    rejected("unreviewed", lambda xs: xs[0].update(confidentiality_reviewed=False), "expected True")
    live = required_live(cases, "free23")
    results = {"cases": [{"case_id": c["case_id"], "lane": "free23", "transport": "stdio", "verdict": "pass", "test_id": c["test_id"]} for c in live],
               "cargo_test_output": "\n".join(f"test {c['test_id'].split('::', 1)[-1]} ... ok" for c in cases if c["reproducible"] == "unit")}
    validate_results(cases, results, "free23", "stdio")
    results["cases"].pop()
    try:
        validate_results(cases, results, "free23", "stdio")
    except ValidationError as exc:
        if "missing required live case" not in str(exc):
            fail(f"selftest missing_live_result: wrong refusal {exc}")
        print(f"missing_live_result: rejected ({exc})")
    else:
        fail("selftest missing_live_result: accepted missing result")
    results["cases"].append({"case_id": live[-1]["case_id"], "lane": "free23", "transport": "stdio", "verdict": "pass", "test_id": live[-1]["test_id"]})
    results["cargo_test_output"] = ""
    try:
        validate_results(cases, results, "free23", "stdio")
    except ValidationError as exc:
        if "missing green cargo test" not in str(exc):
            fail(f"selftest missing_unit_result: wrong refusal {exc}")
        print(f"missing_unit_result: rejected ({exc})")
    else:
        fail("selftest missing_unit_result: accepted missing unit result")
    print("selftest: pass")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="?", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--required-ids", action="store_true")
    parser.add_argument("--check-results", type=Path)
    parser.add_argument("--lane", choices=LANE_CAPABILITIES)
    parser.add_argument("--transport", choices=("stdio", "http"))
    parser.add_argument("--capability", action="append", default=[])
    args = parser.parse_args()
    if (args.required_ids or args.check_results) and (not args.lane or not args.transport):
        parser.error("--required-ids/--check-results need --lane and --transport")
    try:
        schema = json.loads(SCHEMA.read_text())
        cases = validate_manifest(json.loads(args.manifest.read_text()), schema)
        if args.selftest:
            selftest(cases, schema)
        elif args.required_ids:
            for case in required_live(cases, args.lane, args.capability):
                print(case["case_id"])
        elif args.check_results:
            results = json.loads(args.check_results.read_text())
            for log_path in results.get("cargo_test_logs", []):
                results["cargo_test_output"] = results.get("cargo_test_output", "") + "\n" + Path(log_path).read_text()
            validate_results(cases, results, args.lane, args.transport, args.capability)
            print(f"results: pass ({args.lane}/{args.transport})")
        else:
            print(f"manifest: pass ({len(cases)} cases, {len({c['issue'] for c in cases})} issues)")
    except (ValidationError, OSError, json.JSONDecodeError) as exc:
        print(f"manifest: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
