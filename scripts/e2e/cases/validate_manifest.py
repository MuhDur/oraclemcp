#!/usr/bin/env python3
"""Validate the 0.12 release cases and enforce their executed results.

The manifest is an input to the external W4 runner. A case listed here is not
evidence that its regression is fixed. --check-results reads a JSON object with
``cases`` (case_id, lane, transport, test_id, verdict) and ``cargo_test_logs``
(paths to unmodified cargo test output). Every applicable live case must have
one matching pass, and each Rust unit test must resolve to a source ``#[test]``
function and appear as ``test ... ok`` in cargo output. ``--capability`` adds measured target capabilities to the lane's
version and ADB label; it must not be used to assume a privilege exists.
"""

import argparse
import copy
import json
import re
import secrets
import subprocess
import sys
import tomllib
from pathlib import Path


HERE = Path(__file__).resolve().parent
DEFAULT_MANIFEST = HERE / "release_0_12.json"
SCHEMA = HERE / "release_0_12.schema.json"
ROOT = HERE.parents[2]
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
        for key, item in value.items():
            yield key
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
    for item in strings(case):
        for name, pattern in FORBIDDEN_INPUT.items():
            if pattern.search(item):
                fail(f"{case['case_id']}: case contains {name}")
    for item in strings(case["input"]):
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


def rust_tokens(source):
    """Keep literal tokens opaque; comments and quoted test text are not items."""
    pattern = re.compile(r'//[^\n]*|/\*|b?r(?P<hashes>\#*)"|b?"(?:\\.|[^"\\])*"'
                         r"|b?'(?:\\.|[^'\\\n])'|[A-Za-z_][A-Za-z0-9_]*|[^\s]", re.S)
    tokens, position = [], 0
    while match := pattern.search(source, position):
        token, position = match.group(), match.end()
        if token.startswith("//"):
            continue
        if token == "/*":
            depth = 1
            while depth:
                boundary = re.search(r"/\*|\*/", source[position:])
                if boundary is None:
                    fail("unterminated Rust comment")
                position += boundary.end()
                depth += 1 if boundary.group() == "/*" else -1
            continue
        if match.group("hashes") is not None:
            end = source.find('"' + match.group("hashes"), position)
            if end < 0:
                fail("unterminated Rust raw string")
            position = end + 1 + len(match.group("hashes"))
            token = source[match.start():position]
        tokens.append(token)
    return tokens


def closing_token(tokens, start, opening, closing):
    depth = 1
    for index in range(start + 1, len(tokens)):
        depth += (tokens[index] == opening) - (tokens[index] == closing)
        if depth == 0:
            return index
    fail("unbalanced Rust item")


def rust_scope(tokens):
    """Read module declarations and attributed functions at this scope only."""
    items, attributes, index = [], [], 0
    while index < len(tokens):
        token = tokens[index]
        if token == "#" and tokens[index + 1:index + 2] == ["["]:
            end = closing_token(tokens, index + 1, "[", "]")
            attributes.append(tokens[index + 2:end])
            index = end + 1
            continue
        if token == "mod" and index + 2 < len(tokens) and tokens[index + 2] in (";", "{"):
            name, body = tokens[index + 1], None
            end = index + 2
            if tokens[end] == "{":
                end = closing_token(tokens, end, "{", "}")
                body = tokens[index + 3:end]
            items.append(("mod", name, attributes, body))
            attributes, index = [], end + 1
            continue
        if token == "fn" and index + 1 < len(tokens):
            if ["test"] in attributes:
                items.append(("test", tokens[index + 1], [], None))
            attributes = []
        if token == "{":
            index = closing_token(tokens, index, "{", "}")
            attributes = []
        elif token == ";":
            attributes = []
        index += 1
    return items


def rust_test_exists(test_id):
    crate, *modules, function = test_id.split("::")
    package = ROOT / "crates" / crate.replace("_", "-")
    manifest = package / "Cargo.toml"
    if not manifest.is_file():
        return False
    cargo = tomllib.loads(manifest.read_text())
    lib = cargo.get("lib", {})
    roots = []
    if lib.get("name", cargo["package"]["name"].replace("-", "_")) == crate:
        roots.append(package / lib.get("path", "src/lib.rs"))
    for binary in cargo.get("bin", [{"name": cargo["package"]["name"], "path": "src/main.rs"}]):
        if binary["name"].replace("-", "_") == crate:
            roots.append(package / binary.get("path", "src/main.rs"))

    def resolve(tokens, file, directory, remaining):
        items = rust_scope(tokens)
        if not remaining:
            return any(kind == "test" and name == function for kind, name, _, _ in items)
        for kind, name, attributes, body in items:
            if kind != "mod" or name != remaining[0]:
                continue
            if body is not None:
                if resolve(body, file, directory / name, remaining[1:]):
                    return True
                continue
            overrides = [attribute[2] for attribute in attributes
                         if len(attribute) == 3 and attribute[:2] == ["path", "="]]
            candidates = ([file.parent / json.loads(overrides[0])] if overrides else
                          [directory / (name + ".rs"), directory / name / "mod.rs"])
            for child in candidates:
                if child.is_file():
                    child_directory = child.parent if child.name == "mod.rs" else child.with_suffix("")
                    if resolve(rust_tokens(child.read_text()), child, child_directory, remaining[1:]):
                        return True
        return False

    return any(resolve(rust_tokens(file.read_text()), file, file.parent, modules)
               for file in roots if file.is_file())


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
        if case["reproducible"] == "unit" and not rust_test_exists(case["test_id"]):
            fail(f"{case_id}: test_id does not resolve to an existing #[test] fn: {case['test_id']}")
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


def validate_results(cases, results, lane, transport, extra_capabilities=(), cargo_output=None):
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
    if cargo_output is None:
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


def read_cargo_test_logs(paths):
    """Explicit CLI logs are the evidence, not a possibly stale embedded copy."""
    output = []
    for path in paths:
        text = path.read_text()
        if not text.strip():
            fail(f"empty cargo test log: {path}")
        output.append(text)
    return "\n".join(output)


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
    unit_index = next(index for index, case in enumerate(cases) if case["reproducible"] == "unit")
    rejected("nonexistent_test_id", lambda xs: xs[unit_index].update(
        test_id="oraclemcp_config::profile::tests::planted_missing_test"), "existing #[test] fn")
    rejected("wrong_test_module", lambda xs: xs[unit_index].update(
        test_id="oraclemcp_config::wrong_module::tests::issue48_zero_call_timeout_refused_at_load"),
        "existing #[test] fn")
    rejected("ordinary_function_is_not_test", lambda xs: xs[unit_index].update(
        test_id="oraclemcp::tests::issue51::second_serve_instance_reports_audit_lock"),
        "existing #[test] fn")
    issue48 = next(case for case in cases if case["issue"] == 48)
    if issue48["test_id"] != "oraclemcp_config::profile::tests::issue48_zero_call_timeout_refused_at_load":
        fail("#48 must bind the real zero-timeout config regression")
    print("issue48_existing_test: pass")
    lexical = rust_scope(rust_tokens('''
        /* outer /* nested */ #[test] fn commented() {} */
        const TEXT: &str = r###"#[test] fn quoted() { }"###;
        fn ordinary() {}
        #[test] fn real() { let text = "{ \\\n            }"; }
        mod inner { #[test] fn nested() {} }
    '''))
    if [name for kind, name, _, _ in lexical if kind == "test"] != ["real"]:
        fail("Rust source resolver confused comments, strings, nested scopes or unattributed functions with tests")
    print("rust_test_source_tokens: pass")
    for field, value, reason in (
        ("title", "field.example.com", "hostname"),
        ("pre_fix_outcome", "10.23.45.67", "IP address"),
        ("post_fix_expected", "host=synthetic", "connect string"),
        ("assertions", ["ocid1.database.oc1.example"], "OCID"),
        ("symbols", ["/tmp/wallet/cert.pem"], "wallet path"),
        ("tool_or_path", "field.internal", "hostname"),
    ):
        rejected("non_input_" + field, lambda xs, field=field, value=value:
                 xs[0].update({field: value}), reason)
    rejected("nested_string_key", lambda xs: xs[0]["input"].update(
        {"field.example.com": "synthetic"}), "hostname")
    live = required_live(cases, "free23")
    results = {"cases": [{"case_id": c["case_id"], "lane": "free23", "transport": "stdio", "verdict": "pass", "test_id": c["test_id"]} for c in live],
               "cargo_test_output": "\n".join(f"test {c['test_id'].split('::', 1)[-1]} ... ok" for c in cases if c["reproducible"] == "unit")}
    validate_results(cases, results, "free23", "stdio")
    for output in ("", "test missing::test ... ok\n", results["cargo_test_output"].replace(" ... ok", " ... ignored")):
        try:
            validate_results(cases, results, "free23", "stdio", cargo_output=output)
        except ValidationError as exc:
            if "missing green cargo test" not in str(exc):
                fail(f"explicit cargo evidence: wrong refusal {exc}")
        else:
            fail("explicit cargo logs accepted missing/ignored tests via the embedded green output")
    print("explicit_cargo_logs_override_embedded_evidence: pass")
    # Exercise the public CLI, including file reading and explicit-log precedence.
    # These are validator fixtures, not evidence of an executed Rust test.
    work = ROOT / "target/e2e/manifest-selftest" / secrets.token_hex(8)
    work.mkdir(parents=True)
    result_path, log_path = work / "results.json", work / "cargo.log"
    result_path.write_text(json.dumps(results))
    command = [sys.executable, str(Path(__file__).resolve()), "--check-results",
               str(result_path), "--lane", "free23", "--transport", "stdio",
               "--cargo-test-log", str(log_path)]
    for name, output, expected in (
        ("cli_green_log", results["cargo_test_output"], 0),
        ("cli_empty_log", "", 1),
        ("cli_ignored_log", results["cargo_test_output"].replace(" ... ok", " ... ignored"), 1),
    ):
        log_path.write_text(output)
        checked = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if checked.returncode != expected:
            fail(f"{name}: unexpected CLI exit {checked.returncode}: {checked.stderr}")
        print(f"{name}: pass")
    checked = subprocess.run(command[:-1] + [str(work / "missing.log")],
                             capture_output=True, text=True, timeout=30)
    if checked.returncode != 1 or "No such file" not in checked.stderr:
        fail("cli_missing_log: missing explicit evidence was accepted")
    print("cli_missing_log: pass")
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
    parser.add_argument("--cargo-test-log", action="append", type=Path, default=[],
                        help="Unmodified cargo test output; repeat for multiple real runs. Overrides embedded output.")
    args = parser.parse_args()
    if (args.required_ids or args.check_results) and (not args.lane or not args.transport):
        parser.error("--required-ids/--check-results need --lane and --transport")
    if args.cargo_test_log and not args.check_results:
        parser.error("--cargo-test-log needs --check-results")
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
            explicit_output = read_cargo_test_logs(args.cargo_test_log) if args.cargo_test_log else None
            if explicit_output is None:
                for log_path in results.get("cargo_test_logs", []):
                    results["cargo_test_output"] = results.get("cargo_test_output", "") + "\n" + Path(log_path).read_text()
            validate_results(cases, results, args.lane, args.transport, args.capability, explicit_output)
            print(f"results: pass ({args.lane}/{args.transport})")
        else:
            print(f"manifest: pass ({len(cases)} cases, {len({c['issue'] for c in cases})} issues)")
    except (ValidationError, OSError, json.JSONDecodeError) as exc:
        print(f"manifest: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
