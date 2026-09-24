#!/usr/bin/env python3
"""External, raw-wire W4 MCP tool matrix against disposable Oracle lab lanes.

The client uses only the Python standard library for MCP. python-oracledb is
used separately to probe Oracle capabilities and re-read mutated state.
"""

import argparse
import base64
import collections
import contextlib
import datetime
import decimal
import array
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import queue
import re
import secrets
import socket
import subprocess
import sys
import threading
import time

from fixture import admin_password, load_lane, new_run_id, setup as fixture_setup, teardown as fixture_teardown
from scrub import scrub


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
PROTOCOL = "2025-11-25"
MAX_RESPONSE_BYTES = 1_048_576
CAPABILITIES = HERE / "capabilities.json"
CASES = HERE / "cases"
MANIFEST = ROOT / "scripts/e2e/cases/validate_manifest.py"
CASE_FIELDS = {"case_id", "tool", "level", "transports", "requires", "setup",
               "call", "expect", "db_reread", "audit_expect", "on_unsupported"}
OPTIONAL_CASE_FIELDS = {"setup_phase", "setup_ready_sql", "profile_variant", "audit_zero_executions",
                        "steps", "expect_by_version", "cleanup", "plan_contains"}
PROFILE_VARIANTS = {"masked", "synthetic_raw", "synthetic_owner", "synthetic_owner_rw", "synthetic_cross_rw",
                    "synthetic_cross_rw_strict", "protected", "capped_rw"}
LEVELS = ("READ_ONLY", "READ_WRITE", "DDL", "ADMIN")
# A multi-step case captures structured values from one step and feeds them
# to later ones (a confirmation token from a preview, for example).
CAPTURE = re.compile(r"\$\{cap:([a-z][a-z0-9_]{0,31})\}")
EXPECT_KINDS = {"rows", "error_class", "error_classes", "json_subset", "golden"}
CURRENT_SESSION = object()


class DriverError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise DriverError(message)


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def sha256(value):
    return hashlib.sha256(compact(value).encode()).hexdigest()


def expand_case(value, run_id, transport, lane=None):
    replacements = {"${run_id}": run_id, "${owner}": "W4O_" + run_id,
                    "${cross}": "W4X_" + run_id, "${transport}": transport}
    if lane is not None:
        # Version-specific output (DBMS_METADATA DDL text) has one golden per lane.
        replacements["${lane}"] = lane
    if isinstance(value, str):
        for key, replacement in replacements.items():
            value = value.replace(key, replacement)
        # ${cap:name} is filled at run time from an earlier step's capture.
        require("${" not in CAPTURE.sub("", value), "unresolved W4 case placeholder")
        return value
    if isinstance(value, list):
        return [expand_case(item, run_id, transport, lane) for item in value]
    if isinstance(value, dict):
        return {key: expand_case(item, run_id, transport, lane) for key, item in value.items()}
    return value


def fill_captures(value, captures):
    """Substitute ${cap:name} from earlier steps; an unknown capture fails the case."""
    if isinstance(value, str):
        whole = CAPTURE.fullmatch(value)
        if whole:
            require(whole.group(1) in captures, f"capture {whole.group(1)} was never recorded")
            return captures[whole.group(1)]

        def replace(match):
            require(match.group(1) in captures, f"capture {match.group(1)} was never recorded")
            require(isinstance(captures[match.group(1)], str),
                    f"capture {match.group(1)} is not a string and cannot be embedded")
            return captures[match.group(1)]
        return CAPTURE.sub(replace, value)
    if isinstance(value, list):
        return [fill_captures(item, captures) for item in value]
    if isinstance(value, dict):
        return {key: fill_captures(item, captures) for key, item in value.items()}
    return value


def json_pointer(document, pointer):
    require(pointer.startswith("/"), f"capture pointer {pointer!r} must start with /")
    node = document
    for raw in pointer[1:].split("/"):
        part = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, list):
            require(part.isdigit() and int(part) < len(node), f"capture pointer {pointer} missing")
            node = node[int(part)]
        else:
            require(isinstance(node, dict) and part in node, f"capture pointer {pointer} missing")
            node = node[part]
    require(node is not None and node != "", f"capture pointer {pointer} resolved to an empty value")
    return node


def freshen_vsql_marker(case):
    marker = case["call"].get("vsql_absent_marker")
    if marker is None:
        return case
    require(marker in compact(case["call"]["arguments"]),
            "V$SQL absence marker must occur in the SQL sent by the case")
    fresh = "W4MARK_" + secrets.token_hex(12).upper()

    def replace(value):
        if isinstance(value, str):
            return value.replace(marker, fresh)
        if isinstance(value, list):
            return [replace(item) for item in value]
        if isinstance(value, dict):
            return {key: replace(item) for key, item in value.items()}
        return value

    return replace(case)


def deep_subset(expected, actual):
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            key in actual and deep_subset(value, actual[key]) for key, value in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and len(expected) == len(actual) and all(
            deep_subset(left, right) for left, right in zip(expected, actual))
    return expected == actual


def tool_payload(reply):
    require(isinstance(reply, dict), "non-object JSON-RPC response")
    if "error" in reply:
        error = reply["error"]
        return {"isError": True, "structuredContent": error.get("data", error)}
    require(isinstance(reply.get("result"), dict), "missing MCP result object")
    return reply["result"]


def explain_statement_id(reply):
    payload = tool_payload(reply)
    structured = payload.get("structuredContent", {})
    diagnostic = structured.get("diagnostic_write", {})
    statement_id = diagnostic.get("statement_id")
    require(isinstance(statement_id, str)
            and re.fullmatch(r"OMCP_[A-Z0-9]{24}", statement_id) is not None,
            "EXPLAIN did not return its validated server-generated statement id")
    require(diagnostic.get("savepoint") == "OMCP_EXPLAIN_PLAN"
            and diagnostic.get("rolled_back") is True,
            "EXPLAIN response did not attest to savepoint rollback")
    return statement_id


def verify_envelope(reply, descriptor=None):
    require(isinstance(reply, dict) and reply.get("jsonrpc") == "2.0",
            "malformed JSON-RPC envelope")
    require("id" in reply, "JSON-RPC response omitted id")
    require(len(compact(reply).encode()) <= MAX_RESPONSE_BYTES, "MCP response exceeded byte budget")
    if "error" in reply:
        error = reply["error"]
        require(isinstance(error, dict) and type(error.get("code")) is int
                and isinstance(error.get("message"), str),
                "malformed JSON-RPC error")
        data = error.get("data")
        if isinstance(data, dict) and "error_class" in data:
            require(isinstance(data["error_class"], str) and data["error_class"],
                    "malformed JSON-RPC error class")
        return
    result = reply.get("result")
    require(isinstance(result, dict) and isinstance(result.get("content"), list)
            and type(result.get("isError")) is bool,
            "MCP tool result lacks content/isError")
    if result["isError"]:
        structured = result.get("structuredContent")
        require(isinstance(structured, dict)
                and isinstance(structured.get("error_class"), str)
                and structured["error_class"],
                "typed tool error lacks structured error class")
    elif descriptor and isinstance(descriptor.get("outputSchema"), dict):
        schema = descriptor["outputSchema"]
        structured = result.get("structuredContent")
        if schema.get("type") == "object":
            require(isinstance(structured, dict), "outputSchema requires structured object")
        for key in schema.get("required", []):
            require(isinstance(structured, dict) and key in structured,
                    f"outputSchema missing required key {key}")


def verify_expect(expect, reply, golden_root=None):
    require(isinstance(expect, dict) and len(EXPECT_KINDS & expect.keys()) == 1,
            "expect needs exactly one rows/error_class/json_subset/golden selector")
    payload = tool_payload(reply)
    structured = payload.get("structuredContent", {})
    require(isinstance(structured, dict), "structuredContent must be an object")
    if "rows" in expect:
        require(payload.get("isError") is not True, "expected rows but tool refused")
        require(structured.get("rows") == expect["rows"], "ordered rows differ")
    elif "error_class" in expect:
        require(payload.get("isError") is True, "expected typed tool refusal")
        require(structured.get("error_class") == expect["error_class"], "wrong error class")
        if "reason_code" in expect:
            require(structured.get("structured_reason", {}).get("offending_construct") == expect["reason_code"],
                    "wrong structured refusal reason")
        if "ora_code" in expect:
            require(structured.get("ora_code") == expect["ora_code"], "wrong ORA code")
    elif "error_classes" in expect:
        require(payload.get("isError") is True, "expected a typed tool refusal")
        require(structured.get("error_class") in expect["error_classes"],
                "wrong typed refusal class")
    elif "json_subset" in expect:
        require(deep_subset(expect["json_subset"], structured), "JSON subset differs")
    else:
        require(golden_root is not None, "golden root missing")
        name = expect["golden"]
        require(re.fullmatch(r"[a-zA-Z0-9_.-]+\.json", name) is not None,
                "unsafe golden filename")
        golden = json.loads((golden_root / name).read_text())
        require(scrub(structured) == golden, "scrubbed golden differs")
    return scrub(structured)


def verify_audit(expected, records, verified):
    require(verified, "audit chain verification failed")
    require(len(expected) == len(records),
            f"audit record count differs: expected {len(expected)}, observed {len(records)}")
    for item, record in zip(expected, records):
        require(deep_subset(item, record),
                f"wrong ordered audit record for {item.get('tool', 'unknown tool')}")


def verify_coverage(tools, cases):
    report = coverage_status(tools, cases)
    require(not report["missing_positive"],
            f"tools without a positive case: {', '.join(report['missing_positive'])}")
    return report


def coverage_status(tools, cases):
    matrix = json.loads(CAPABILITIES.read_text())
    declared = []
    for lane in matrix["lanes"].values():
        facts = {f"version:{lane['version']}", f"edition:{lane['edition']}"}
        facts.update("feature:" + feature for feature in lane["features"])
        facts.update("priv:" + privilege for privilege in lane["privileges"])
        facts.update("licence:" + licence for licence in lane["licences"])
        if lane["adb"]:
            facts.add("adb")
        declared.append(facts)
    positives = {case["tool"] for case in cases
                 if "error_class" not in case["expect"]
                 and case["case_id"].startswith(("w4_", "rel012_"))
                 and any(set(case["requires"]) <= facts for facts in declared)}
    canonical = {name for name in tools if name.startswith("oracle_")}
    missing = sorted(canonical - positives)
    return {"registered": len(tools), "canonical": len(canonical),
            "positive_covered": len(canonical & positives),
            "missing_positive": missing}


def validate_case(case, filename):
    require(isinstance(case, dict), f"{filename}: case must be an object")
    require(CASE_FIELDS <= case.keys() and case.keys() <= CASE_FIELDS | OPTIONAL_CASE_FIELDS,
            f"{filename}: case fields mismatch: {sorted(case.keys() ^ CASE_FIELDS)}")
    require(re.fullmatch(r"(?:w4|rel012)_[a-z0-9_]+", case["case_id"]), "invalid case_id")
    require(isinstance(case["tool"], str) and case["tool"], "missing tool name")
    require(case["level"] in {"READ_ONLY", "READ_WRITE", "DDL", "ADMIN"}, "invalid level")
    require(case.get("profile_variant", "masked") in PROFILE_VARIANTS,
            f"profile_variant must be one of {sorted(PROFILE_VARIANTS)}")
    if case.get("profile_variant") in {"synthetic_raw", "synthetic_owner"}:
        require(case["level"] == "READ_ONLY" and case.get("setup_phase") == "before_server",
                "synthetic fixture profiles require precreated READ_ONLY fixtures")
    if case.get("profile_variant") == "synthetic_owner_rw":
        require(case["level"] == "READ_WRITE",
                "synthetic owner write profile is restricted to explicit READ_WRITE cases")
    if case.get("profile_variant") in {"synthetic_cross_rw", "synthetic_cross_rw_strict"}:
        require(case["level"] == "READ_WRITE",
                "least-privilege cross-schema profile is restricted to explicit READ_WRITE cases")
    require("plan_contains" not in case
            or (isinstance(case["plan_contains"], str) and case["plan_contains"]),
            "plan_contains must be a nonempty string")
    if case.get("profile_variant") == "protected":
        require(case["level"] == "READ_ONLY", "a protected profile is pinned at READ_ONLY")
    if case.get("profile_variant") == "capped_rw":
        require(case["level"] in {"READ_ONLY", "READ_WRITE"},
                "the capped_rw profile's ceiling is READ_WRITE")
    if "steps" in case:
        validate_steps(case)
    require(isinstance(case["transports"], list) and case["transports"]
            and set(case["transports"]) <= {"stdio", "http"}
            and len(case["transports"]) == len(set(case["transports"])), "invalid transports")
    require(isinstance(case["requires"], list) and all(isinstance(x, str) for x in case["requires"]),
            "invalid requires")
    require(len(case["requires"]) == len(set(case["requires"])), "duplicate capability requirement")
    if "expect_by_version" in case:
        by_version = case["expect_by_version"]
        require(isinstance(by_version, dict) and set(by_version) == {"23", "pre23"},
                "expect_by_version must define both 23 and pre23 projections")
        for expectation in by_version.values():
            verify_expect_shape(expectation)
    require(isinstance(case["setup"], list), "setup must be an array")
    require(case.get("setup_phase", "before_call") in {"before_call", "before_server"},
            "setup_phase must be before_call or before_server")
    require("audit_zero_executions" not in case or type(case["audit_zero_executions"]) is bool,
            "audit_zero_executions must be boolean")
    if "setup_ready_sql" in case:
        require(case.get("setup_phase") == "before_server"
                and isinstance(case["setup_ready_sql"], str)
                and case["setup_ready_sql"].lstrip().upper().startswith("SELECT "),
                "setup_ready_sql needs a before_server case and a SELECT")
    for action in case["setup"]:
        require(isinstance(action, dict) and set(action) == {"sql"}
                and isinstance(action["sql"], str) and action["sql"],
                "setup action needs exact nonempty sql field")
    require(isinstance(case["call"], dict) and isinstance(case["call"].get("arguments"), dict),
            "call.arguments must be an object")
    require(set(case["call"]) <= {"arguments", "raw_arguments", "retry", "retry_expect", "parallel", "mutation", "baseline_arguments", "contract_baseline", "vsql_absent_marker", "cancel_marker"},
            "unknown call field")
    if "contract_baseline" in case["call"]:
        require(isinstance(case["call"]["contract_baseline"], dict)
                and case["level"] == "READ_ONLY" and not case["call"].get("mutation")
                and not case["setup"],
                "contract_baseline needs a READ_ONLY case without mutation or setup")
    if "vsql_absent_marker" in case["call"]:
        require(isinstance(case["call"]["vsql_absent_marker"], str)
                and re.fullmatch(r"W4MARK_[A-Z0-9]{12,32}", case["call"]["vsql_absent_marker"]),
                "vsql_absent_marker needs a unique synthetic marker")
        require("error_class" in case["expect"] and "priv:SELECT_V_SQL" in case["requires"],
                "V$SQL absence is only valid for a refusal case on a probed capable lane")
    if "cancel_marker" in case["call"]:
        require(isinstance(case["call"]["cancel_marker"], str)
                and re.fullmatch(r"W4MARK_[A-Z0-9]{12,32}", case["call"]["cancel_marker"])
                and "priv:SELECT_V_SQL" in case["requires"],
                "cancel_marker needs a unique synthetic marker and V$SQL capability")
        require("parallel" not in case["call"] and "raw_arguments" not in case["call"],
                "cancel case cannot use parallel or raw arguments")
        require(case["call"]["cancel_marker"] in compact(case["call"]["arguments"]),
                "cancel marker must appear in the tool arguments")
    require("retry" not in case["call"] or type(case["call"]["retry"]) is bool,
            "call.retry must be boolean")
    require("mutation" not in case["call"] or type(case["call"]["mutation"]) is bool,
            "call.mutation must be boolean")
    require("raw_arguments" not in case["call"] or isinstance(case["call"]["raw_arguments"], str),
            "call.raw_arguments must be a JSON string")
    require("baseline_arguments" not in case["call"] or
            (case["case_id"].startswith("w4_contract_") and
             isinstance(case["call"]["baseline_arguments"], dict)),
            "baseline_arguments is reserved for generated contract cases")
    if "retry_expect" in case["call"]:
        require(case["call"].get("retry") is True, "retry_expect requires retry")
        verify_expect_shape(case["call"]["retry_expect"])
    if "parallel" in case["call"]:
        workers = case["call"]["parallel"]
        require(isinstance(workers, list) and 2 <= len(workers) <= 8,
                "parallel call requires 2..8 workers")
        require(case["transports"] == ["http"], "parallel calls require HTTP transport")
        require(all(isinstance(worker, dict)
                    and set(worker) in ({"arguments", "expect"},
                                       {"arguments", "expect", "plan_contains"})
                    and isinstance(worker["arguments"], dict) for worker in workers),
                "parallel worker needs arguments and expect")
        for worker in workers:
            verify_expect_shape(worker["expect"])
            require("plan_contains" not in worker
                    or (isinstance(worker["plan_contains"], str) and worker["plan_contains"]),
                    "parallel plan_contains must be a nonempty string")
        require("json_subset" in case["expect"], "parallel aggregate expects json_subset")
    require(isinstance(case["db_reread"], list) and isinstance(case["audit_expect"], list),
            "db_reread/audit_expect must be arrays")
    for reread in case["db_reread"]:
        require(isinstance(reread, dict) and set(reread) == {"sql", "rows"}
                and isinstance(reread["sql"], str) and isinstance(reread["rows"], list),
                "db_reread needs SQL and exact rows")
    for item in case["audit_expect"]:
        require(isinstance(item, dict) and {"tool", "decision", "outcome"} <= item.keys()
                and all(isinstance(item[key], str) for key in ("tool", "decision", "outcome")),
                "audit_expect needs tool, decision, outcome")
    require("cleanup" not in case or isinstance(case["cleanup"], list),
            "cleanup must be an array of run-owned DDL actions")
    for action in case.get("cleanup", []):
        require(isinstance(action, dict) and set(action) == {"sql"}
                and isinstance(action["sql"], str) and action["sql"],
                "cleanup action needs exact nonempty SQL")
    if case["call"].get("mutation"):
        require(case["db_reread"] and case["audit_expect"],
                "mutating case needs independent DB re-read and audit expectations")
    require(isinstance(case["on_unsupported"], dict)
            and isinstance(case["on_unsupported"].get("error_class"), str),
            "on_unsupported needs exact error_class")
    verify_expect_shape(case["expect"])
    verify_expect_shape(case["on_unsupported"])
    return case


def validate_steps(case):
    """Steps run in order on the case's own session before its `call`.

    A step is exactly one of: a tool call {tool, arguments, expect, capture?};
    {wait_level, deadline_seconds} which polls the session status until the
    level is reached (an event barrier with a deadline, never a bare sleep);
    or {audit_report: {contains: [...]}} which renders this run's audit file.
    """
    steps = case["steps"]
    require(isinstance(steps, list) and 1 <= len(steps) <= 8, "steps needs 1..8 entries")
    require(not ({"parallel", "cancel_marker", "retry", "raw_arguments", "baseline_arguments"}
                 & case["call"].keys()),
            "steps cannot be combined with parallel, cancel, retry or raw calls")
    require(case.get("profile_variant", "masked") not in {"synthetic_raw", "synthetic_owner"},
            "steps need a writable lab profile")
    require(not case["requires"],
            "steps cases run on every lane; an unsupported lane would skip the steps unasserted")
    known = set()
    for step in steps:
        require(isinstance(step, dict), "step must be an object")
        if "tool" in step:
            require(set(step) <= {"tool", "arguments", "expect", "capture"}
                    and {"tool", "arguments", "expect"} <= step.keys(),
                    "tool step needs tool, arguments, expect and optional capture")
            require(isinstance(step["tool"], str) and step["tool"]
                    and isinstance(step["arguments"], dict), "tool step needs a name and arguments")
            verify_expect_shape(step["expect"])
            for name in CAPTURE.findall(compact(step["arguments"])):
                require(name in known, f"step uses capture {name} before it is recorded")
            capture = step.get("capture", {})
            require(isinstance(capture, dict)
                    and all(re.fullmatch(r"[a-z][a-z0-9_]{0,31}", name) and isinstance(pointer, str)
                            and pointer.startswith("/") for name, pointer in capture.items()),
                    "capture maps names to JSON pointers into structuredContent")
            known |= set(capture)
        elif "wait_level" in step:
            require(set(step) == {"wait_level", "deadline_seconds"}
                    and step["wait_level"] in LEVELS
                    and type(step["deadline_seconds"]) is int and 1 <= step["deadline_seconds"] <= 120,
                    "wait_level step needs a level and a 1..120 s deadline")
        else:
            require(set(step) == {"audit_report"} and isinstance(step["audit_report"], dict)
                    and set(step["audit_report"]) == {"contains"}
                    and isinstance(step["audit_report"]["contains"], list)
                    and step["audit_report"]["contains"]
                    and all(isinstance(item, str) and item for item in step["audit_report"]["contains"]),
                    "audit_report step needs a nonempty contains list")
    for name in CAPTURE.findall(compact(case["call"]["arguments"])):
        require(name in known, f"call uses capture {name} that no step records")


def verify_expect_shape(expect):
    require(isinstance(expect, dict) and len(EXPECT_KINDS & expect.keys()) == 1,
            "expect must select one verification mode")
    require(set(expect) <= EXPECT_KINDS | {"ora_code", "reason_code"}, "unknown expect key")
    require("ora_code" not in expect or "error_class" in expect, "ora_code needs error_class")
    require("reason_code" not in expect or ("error_class" in expect and isinstance(expect["reason_code"], str)),
            "reason_code needs error_class and a string value")
    if "error_classes" in expect:
        require(isinstance(expect["error_classes"], list) and expect["error_classes"]
                and all(isinstance(item, str) and item for item in expect["error_classes"]),
                "error_classes needs one or more exact class names")
    if "ora_code" in expect:
        require(type(expect["ora_code"]) is int and expect["ora_code"] > 0,
                "ora_code must be a positive integer")
    if "rows" in expect:
        require(isinstance(expect["rows"], list), "rows expectation must be an array")
    if "json_subset" in expect:
        require(isinstance(expect["json_subset"], dict) and expect["json_subset"],
                "json_subset must be a nonempty object")
    if "golden" in expect:
        name = expect["golden"]
        require(isinstance(name, str) and name.count("${lane}") <= 1
                and re.fullmatch(r"[a-zA-Z0-9_.-]+\.json", name.replace("${lane}", "lane")),
                "invalid golden filename")
        lanes = (("free23", "xe18", "xe21") if "${lane}" in name else (None,))
        for lane in lanes:
            concrete = name if lane is None else name.replace("${lane}", lane)
            require(re.fullmatch(r"[a-zA-Z0-9_.-]+\.json", concrete) is not None, "invalid golden filename")
            require((ROOT / "tests/golden/w4" / concrete).is_file(), f"golden file {concrete} is missing")


def merge_expectation(base, overlay):
    if isinstance(base, dict) and isinstance(overlay, dict):
        merged = dict(base)
        for key, value in overlay.items():
            merged[key] = merge_expectation(merged[key], value) if key in merged else value
        return merged
    if isinstance(base, list) and isinstance(overlay, list):
        require(len(base) == len(overlay), "version expectation list lengths differ")
        return [merge_expectation(left, right) for left, right in zip(base, overlay)]
    return overlay


def expected_for_case(case, capabilities):
    if not set(case["requires"]) <= capabilities:
        return case["on_unsupported"]
    by_version = case.get("expect_by_version")
    if by_version is None:
        return case["expect"]
    version = "23" if "version:23" in capabilities else "pre23"
    return merge_expectation(case["expect"], by_version[version])


def load_cases():
    cases, seen = [], set()
    vocabulary = set(json.loads(CAPABILITIES.read_text())["vocabulary"])
    for path in sorted(CASES.glob("*.json")):
        if path.name == "schema.json":
            continue
        data = json.loads(path.read_text())
        require(isinstance(data, list), f"{path.name}: family must be an array")
        for value in data:
            case = validate_case(value, path.name)
            require(set(case["requires"]) <= vocabulary,
                    f"{case['case_id']}: unknown capability requirement")
            require(case["case_id"] not in seen, f"duplicate case_id {case['case_id']}")
            seen.add(case["case_id"])
            cases.append(case)
    return cases


def contract_baselines(cases):
    result = {}
    for case in cases:
        baseline = case["call"].get("contract_baseline")
        if baseline is not None:
            previous = result.setdefault(case["tool"], baseline)
            require(previous == baseline,
                    f"conflicting contract baselines for {case['tool']}")
    return result


class StdioClient:
    def __init__(self, binary, profile, env):
        self.process = subprocess.Popen(
            [str(binary), "serve", "--profile", profile, "--allow-no-auth"],
            env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1)
        self.lines = queue.Queue()
        self.stderr_tail = collections.deque(maxlen=20)
        self.next_id = 0
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._drain, daemon=True).start()

    def _read(self):
        for line in self.process.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def _drain(self):
        for line in self.process.stderr:
            self.stderr_tail.append(line.rstrip())

    def rpc(self, method, params=None, raw_arguments=None):
        self.next_id += 1
        if raw_arguments is None:
            request = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
            if params is not None:
                request["params"] = params
            frame = compact(request)
        else:
            require(method == "tools/call", "raw arguments only supported for tools/call")
            frame = (f'{{"jsonrpc":"2.0","id":{self.next_id},"method":"tools/call",'
                     f'"params":{{"name":{json.dumps(params["name"])},"arguments":{raw_arguments}}}}}')
        self.process.stdin.write(frame + "\n")
        self.process.stdin.flush()
        deadline = time.monotonic() + 45
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0, f"stdio timeout for {method}; exit={self.process.poll()}; stderr={list(self.stderr_tail)}")
            try:
                line = self.lines.get(timeout=remaining)
            except queue.Empty as exc:
                raise DriverError(f"stdio timeout for {method}; exit={self.process.poll()}; stderr={list(self.stderr_tail)}") from exc
            if line is None:
                raise DriverError(f"stdio server closed before {method}; exit={self.process.poll()}; stderr={list(self.stderr_tail)}")
            reply = json.loads(line)
            if reply.get("id") == self.next_id:
                return reply

    def notify(self, method, params=None):
        frame = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            frame["params"] = params
        self.process.stdin.write(compact(frame) + "\n")
        self.process.stdin.flush()

    def malformed_frame(self):
        self.process.stdin.write('{"jsonrpc":"2.0","id":910001,"method":\n')
        self.process.stdin.flush()
        try:
            line = self.lines.get(timeout=10)
        except queue.Empty as exc:
            raise DriverError("stdio malformed frame got no bounded response") from exc
        require(line is not None, "stdio server exited on malformed frame")
        return json.loads(line)

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                self.process.wait(timeout=10)


class HttpClient:
    def __init__(self, binary, profile, env, port, secret, audience):
        self.port, self.secret, self.audience = port, secret, audience
        self.session_id = None
        self.next_id = 0
        self.session_ids = {}
        self.session_lock = threading.Lock()
        self.stderr_tail = collections.deque(maxlen=20)
        self.process = subprocess.Popen(
            [str(binary), "--json", "serve", "--listen", f"127.0.0.1:{port}",
             "--http-stateful", "--http-json-response", "--profile", profile],
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True)
        threading.Thread(target=self._drain, args=(self.process.stdout, None), daemon=True).start()
        threading.Thread(target=self._drain, args=(self.process.stderr, self.stderr_tail), daemon=True).start()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            require(self.process.poll() is None,
                    f"HTTP server exited before readiness: {list(self.stderr_tail)}")
            try:
                status, _, _ = self._request("GET", "/readyz", None, auth=False)
                if status == 200:
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.1)
        raise DriverError(f"HTTP readiness deadline expired: {list(self.stderr_tail)}")

    @staticmethod
    def _drain(stream, tail):
        for line in stream:
            if tail is not None:
                tail.append(line.rstrip())

    @staticmethod
    def _b64(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

    def token(self, scope="oracle:read oracle:admin", expires_in=900):
        header = self._b64(b'{"alg":"HS256","typ":"at+jwt"}')
        now = int(time.time())
        claims = {"iss": "https://synthetic-w4.invalid", "aud": self.audience,
                  "exp": now + expires_in, "iat": now, "sub": "synthetic-w4-client",
                  "client_id": "w4-driver", "jti": secrets.token_hex(8), "scope": scope}
        payload = self._b64(compact(claims).encode())
        body = f"{header}.{payload}"
        signature = self._b64(hmac.new(self.secret.encode(), body.encode(), hashlib.sha256).digest())
        return f"{body}.{signature}"

    def _request(self, method, path, body, auth=True, token=None,
                 session_id=CURRENT_SESSION):
        headers = {"Accept": "application/json, text/event-stream",
                   "Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = f"Bearer {token or self.token()}"
        selected_session = self.session_id if session_id is CURRENT_SESSION else session_id
        if selected_session:
            headers["mcp-session-id"] = selected_session
            headers["mcp-protocol-version"] = PROTOCOL
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return response.status, dict((key.lower(), value) for key, value in response.getheaders()), response.read()
        finally:
            connection.close()

    def rpc(self, method, params=None, raw_arguments=None):
        self.next_id += 1
        if raw_arguments is None:
            request = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
            if params is not None:
                request["params"] = params
            frame = compact(request)
        else:
            require(method == "tools/call", "raw arguments only supported for tools/call")
            frame = (f'{{"jsonrpc":"2.0","id":{self.next_id},"method":"tools/call",'
                     f'"params":{{"name":{json.dumps(params["name"])},"arguments":{raw_arguments}}}}}')
        status, headers, body = self._request("POST", "/mcp", frame.encode())
        require(status == 200, f"HTTP {method} returned {status}")
        if method == "initialize":
            self.session_id = headers.get("mcp-session-id")
            require(self.session_id, "stateful HTTP initialize lacked session id")
        return self.decode_body(body)

    @staticmethod
    def decode_body(body):
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            frames = [json.loads(line[6:]) for line in body.decode().splitlines()
                      if line.startswith("data: ") and line[6:] != "null"]
            require(frames, "HTTP SSE response had no JSON frame")
            return frames[-1]

    def notify(self, method, params=None):
        request = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            request["params"] = params
        frame = compact(request).encode()
        status, _, _ = self._request("POST", "/mcp", frame)
        require(status in {200, 202}, f"HTTP notification returned {status}")

    def malformed_frame(self):
        status, _, body = self._request(
            "POST", "/mcp", b'{"jsonrpc":"2.0","id":910001,"method":')
        require(status in {200, 400}, f"HTTP malformed frame returned {status}")
        return self.decode_body(body)

    def new_session(self):
        request = compact({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"protocolVersion": PROTOCOL, "capabilities": {},
                                      "clientInfo": {"name": "w4-parallel-client", "version": "1"}}}).encode()
        status, headers, body = self._request("POST", "/mcp", request, session_id=None)
        require(status == 200 and self.decode_body(body).get("result", {}).get("protocolVersion") == PROTOCOL,
                "parallel HTTP initialize failed")
        session_id = headers.get("mcp-session-id")
        require(session_id, "parallel HTTP session id missing")
        notification = compact({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode()
        status, _, _ = self._request("POST", "/mcp", notification, session_id=session_id)
        require(status in {200, 202}, "parallel HTTP initialized notification failed")
        with self.session_lock:
            self.session_ids[session_id] = 1
        return session_id

    def session_rpc(self, session_id, method, params=None):
        with self.session_lock:
            require(session_id in self.session_ids, "unknown parallel HTTP session")
            self.session_ids[session_id] += 1
            request_id = self.session_ids[session_id]
        request_object = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            request_object["params"] = params
        request = compact(request_object).encode()
        status, _, body = self._request("POST", "/mcp", request, session_id=session_id)
        require(status == 200, f"parallel HTTP {method} returned {status}")
        return self.decode_body(body)

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)


class BarrierPool:
    """Named, bounded synchronization for concurrent external clients."""

    def __init__(self):
        self.lock = threading.Lock()
        self.barriers = {}

    def wait(self, name, parties, timeout=30):
        require(isinstance(name, str) and name and 1 <= parties <= 32, "invalid barrier")
        with self.lock:
            existing = self.barriers.get(name)
            if existing is None:
                existing = threading.Barrier(parties)
                self.barriers[name] = existing
            require(existing.parties == parties, "barrier party count changed")
        try:
            return existing.wait(timeout=timeout)
        except threading.BrokenBarrierError as exc:
            raise DriverError(f"barrier {name} timed out") from exc


def initialize(client):
    reply = client.rpc("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                      "clientInfo": {"name": "w4-external-client", "version": "1"}})
    require(reply.get("result", {}).get("protocolVersion") == PROTOCOL,
            "initialize did not negotiate pinned MCP protocol")
    client.notify("notifications/initialized")


def list_tools(client):
    reply = client.rpc("tools/list")
    require("error" not in reply, "tools/list returned JSON-RPC error")
    tools = reply.get("result", {}).get("tools")
    require(isinstance(tools, list) and tools, "tools/list returned no descriptors")
    names = [tool.get("name") for tool in tools]
    require(all(isinstance(name, str) and name for name in names), "invalid tool name")
    require(len(names) == len(set(names)), "duplicate tool names in tools/list")
    return {tool["name"]: tool for tool in tools}


def elevate(client, level):
    if level == "READ_ONLY":
        return
    preview = tool_payload(client.rpc("tools/call", {
        "name": "oracle_set_session_level", "arguments": {"level": level}}))
    require(preview.get("isError") is not True, f"{level} preview refused")
    token = preview.get("structuredContent", {}).get("confirmation", {}).get("confirm")
    require(isinstance(token, str) and token, f"{level} preview lacked confirmation")
    applied = tool_payload(client.rpc("tools/call", {
        "name": "oracle_set_session_level",
        "arguments": {"level": level, "execute": True, "confirm": token}}))
    require(applied.get("isError") is not True and
            applied.get("structuredContent", {}).get("changed") is True,
            f"{level} step-up did not apply")


def pick_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def write_lab_config(path, lane, dsn, port, owner=None, cross=None):
    audience = f"http://127.0.0.1:{port}/mcp"
    content = f'''schema_version = 2
default_profile = "{lane}"

[http.oauth]
resource = "{audience}"
allowed_issuers = ["https://synthetic-w4.invalid"]
authorization_servers = ["https://synthetic-w4.invalid"]
required_scopes = ["oracle:read"]
hs256_secret_ref = "env:W4_OAUTH_SECRET"

[[profiles]]
name = "{lane}"
description = "synthetic W4 disposable lab lane"
connect_string = "{dsn}"
username = "system"
credential_ref = "env:W4_DB_PASSWORD"
max_level = "ADMIN"
default_level = "READ_ONLY"

[profiles.masking]
mask_unknown_default = true

[[profiles.masking.rules]]
column_match = {{ column = "SECRET_TEXT" }}
action = "mask"
tag = "w4.synthetic.mask"

[[profiles]]
name = "{lane}_protected"
description = "synthetic W4 protected profile: pinned at READ_ONLY"
connect_string = "{dsn}"
username = "system"
credential_ref = "env:W4_DB_PASSWORD"
protected = true
max_level = "READ_ONLY"
default_level = "READ_ONLY"

[[profiles]]
name = "{lane}_capped"
description = "synthetic W4 writable profile whose ceiling is READ_WRITE"
connect_string = "{dsn}"
username = "system"
credential_ref = "env:W4_DB_PASSWORD"
max_level = "READ_WRITE"
default_level = "READ_ONLY"

[profiles.masking]
mask_unknown_default = true

[[profiles]]
name = "{lane}_raw"
description = "synthetic W4 type-fidelity fixtures only"
connect_string = "{dsn}"
username = "system"
credential_ref = "env:W4_DB_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"
'''
    if owner is not None:
        require(re.fullmatch(r"W4O_W4[0-9]{4}[A-F0-9]{6}", owner) is not None,
                "owner profile must name the exact W4 fixture")
        content += f'''
[[profiles]]
name = "{lane}_owner"
description = "synthetic W4 disposable owner fixture"
connect_string = "{dsn}"
username = "{owner}"
credential_ref = "env:W4_OWNER_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"
'''
        content += f'''
[[profiles]]
name = "{lane}_owner_rw"
description = "synthetic W4 disposable owner fixture for explicit EXPLAIN write tests"
connect_string = "{dsn}"
username = "{owner}"
credential_ref = "env:W4_OWNER_PASSWORD"
max_level = "ADMIN"
default_level = "READ_ONLY"
'''
    if cross is not None:
        require(re.fullmatch(r"W4X_W4[0-9]{4}[A-F0-9]{6}", cross) is not None,
                "cross profile must name the exact W4 fixture")
        content += f'''
[[profiles]]
name = "{lane}_cross_rw"
description = "synthetic W4 least-privilege cross-schema reader for EXPLAIN evidence tests"
connect_string = "{dsn}"
username = "{cross}"
credential_ref = "env:W4_CROSS_PASSWORD"
max_level = "ADMIN"
default_level = "READ_ONLY"
'''
        content += f'''
[[profiles]]
name = "{lane}_cross_rw_strict"
description = "synthetic W4 least-privilege cross-schema reader requiring complete hard-parse evidence"
connect_string = "{dsn}"
username = "{cross}"
credential_ref = "env:W4_CROSS_PASSWORD"
max_level = "ADMIN"
default_level = "READ_ONLY"
require_hard_parse_evidence = true
'''
    path.write_text(content)
    return audience


def probe_capabilities(lane, settings, config):
    try:
        import oracledb
    except ImportError as exc:
        raise DriverError("live W4 driver needs pinned python-oracledb 4.0.2") from exc
    require(oracledb.__version__ == "4.0.2", "python-oracledb version drift")
    password = admin_password(lane, settings)
    connection = oracledb.connect(user="system", password=password, dsn=settings["dsn"])
    try:
        cursor = connection.cursor()
        version = int(cursor.execute("SELECT VERSION FROM V$INSTANCE").fetchone()[0].split(".")[0])
        banner = cursor.execute("SELECT BANNER FROM V$VERSION WHERE ROWNUM=1").fetchone()[0]
        edition = "XE" if "Express Edition" in banner else "FREE" if "Free" in banner else "UNKNOWN"
        privileges = {row[0] for row in cursor.execute("SELECT PRIVILEGE FROM SESSION_PRIVS")}
        cloud_service = cursor.execute("SELECT SYS_CONTEXT('USERENV','CLOUD_SERVICE') FROM DUAL").fetchone()[0]
        observed = {f"version:{version}", f"edition:{edition}"}
        if version >= 23:
            try:
                cursor.execute("SELECT JSON_OBJECT('kind' VALUE 'w4' RETURNING JSON) FROM DUAL").fetchone()
                observed.add("feature:JSON_TYPE")
            except oracledb.DatabaseError:
                pass
            try:
                cursor.execute("SELECT VECTOR_DISTANCE(TO_VECTOR('[1,0,0]'),TO_VECTOR('[1,0,0]')) FROM DUAL").fetchone()
                observed.add("feature:VECTOR")
            except oracledb.DatabaseError:
                pass
        if cursor.execute("SELECT COUNT(*) FROM ALL_PROCEDURES WHERE OWNER='SYS' AND OBJECT_NAME='DBMS_RLS'").fetchone()[0]:
            observed.add("feature:VPD")
        for name in ("CREATE TABLE", "CREATE PROCEDURE", "CREATE TYPE"):
            if name in privileges:
                observed.add("priv:" + name.replace(" ", "_"))
        try:
            cursor.execute("SELECT COUNT(*) FROM V$SQL WHERE ROWNUM=1").fetchone()
            observed.add("priv:SELECT_V_SQL")
        except oracledb.DatabaseError:
            pass
        expected = config["lanes"][lane]
        require(version == expected["version"] and edition == expected["edition"],
                f"{lane}: declared/observed Oracle version or edition mismatch")
        declared_features = {"feature:" + feature for feature in expected["features"]}
        observed_features = {item for item in observed if item.startswith("feature:")}
        require(declared_features == observed_features,
                f"{lane}: declared/observed features differ: {sorted(declared_features ^ observed_features)}")
        declared_privileges = {"priv:" + privilege for privilege in expected["privileges"]}
        observed_privileges = {item for item in observed if item.startswith("priv:")}
        require(declared_privileges == observed_privileges,
                f"{lane}: declared/observed privileges differ: {sorted(declared_privileges ^ observed_privileges)}")
        require(expected["adb"] is False and cloud_service is None,
                "local W4 rig does not match observed cloud-service posture")
        return observed, connection, password
    except Exception:
        connection.close()
        raise


def db_rows(connection, sql):
    require(sql.lstrip().upper().startswith(("SELECT ", "WITH ")),
            "harness re-read must be SELECT/WITH")
    cursor = connection.cursor()
    rows = cursor.execute(sql).fetchall()
    return [[canonical_db_value(value) for value in row] for row in rows]


def vsql_marker_count(connection, marker):
    cursor = connection.cursor()
    return cursor.execute(
        "SELECT COUNT(*) FROM V$SQL WHERE INSTR(SQL_TEXT, :marker) > 0",
        {"marker": marker}).fetchone()[0]


def canonical_db_value(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, decimal.Decimal):
        return str(value)
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex().upper()
    if isinstance(value, array.array):
        return list(value)
    if hasattr(value, "read"):
        return canonical_db_value(value.read())
    raise DriverError(f"unsupported independent DB value type: {type(value).__name__}")


def apply_setup(connection, actions):
    for action in actions:
        require(isinstance(action, dict) and set(action) == {"sql"},
                "invalid setup action")
        require(not re.search(r"\b(?:DROP\s+USER|ALTER\s+USER)\b", action["sql"], re.I),
                "case setup cannot modify users")
        require(re.search(r"\b(?:W4O_|W4X_)W4[0-9]{4}[A-F0-9]{6}\b", action["sql"]) is not None,
                "case setup SQL must target a run-owned W4 schema")
        connection.cursor().execute(action["sql"])
        connection.commit()


def wait_for_setup_ready(settings, password, sql):
    """Wait for Oracle's post-DDL definition SCN using fresh-session reads."""
    import oracledb
    deadline = time.monotonic() + 20
    consecutive = 0
    while time.monotonic() < deadline:
        probe = oracledb.connect(user="system", password=password, dsn=settings["dsn"])
        try:
            cursor = probe.cursor()
            cursor.execute("SET TRANSACTION READ ONLY")
            cursor.execute(sql).fetchone()
            consecutive += 1
            if consecutive == 2:
                return
        except oracledb.DatabaseError as exc:
            if exc.args[0].code != 1466:
                raise
            consecutive = 0
        finally:
            probe.close()
        time.sleep(0.1)
    raise DriverError("post-DDL fresh-session readiness deadline expired")


def alias_target(rule):
    if not isinstance(rule, dict):
        return None
    description = rule.get("description")
    if not isinstance(description, str):
        return None
    match = re.search(
        r"\b(?:runtime\s+compatibility\s+|compatibility\s+|legacy\s+)?alias\s+for\s+`?([a-z][a-z0-9_]*)`?",
        description,
        re.IGNORECASE,
    )
    return match.group(1) if match else None


def schema_placeholder(rule, field="", lane=""):
    if not isinstance(rule, dict):
        return None
    if "const" in rule:
        return rule["const"]
    if isinstance(rule.get("enum"), list) and rule["enum"]:
        return rule["enum"][0]
    for arm in ("oneOf", "anyOf"):
        if isinstance(rule.get(arm), list) and rule[arm]:
            return schema_placeholder(rule[arm][0], field, lane)
    kind = rule.get("type")
    if isinstance(kind, list):
        kind = next((item for item in kind if item != "null"), kind[0])
    if kind == "string":
        field_name = field.lower()
        alias = alias_target(rule)
        if field_name == "sql_id":
            return "0000000000000"
        if field_name == "ddl":
            return "CREATE TABLE W4O_W40000ABCDEF (ID NUMBER)"
        if field_name == "source_code":
            return "CREATE OR REPLACE VIEW W4O_W40000ABCDEF AS SELECT 1 AS ID FROM dual"
        if field_name == "sql" and alias in {"ddl", "source_code"}:
            if alias == "ddl":
                return "CREATE TABLE W4O_W40000ABCDEF (ID NUMBER)"
            return "CREATE OR REPLACE VIEW W4O_W40000ABCDEF AS SELECT 1 AS ID FROM dual"
        if field_name == "sql":
            return "SELECT 1 FROM dual"
        if field_name in {"profile", "db"}:
            return lane
        if field_name in {"name", "table", "owner", "object_name"}:
            return "W4O_W40000ABCDEF"
        return "X"
    if kind in {"integer", "number"}:
        return max(1, rule.get("minimum", 1))
    if kind == "boolean":
        return False
    if kind == "array":
        return [schema_placeholder(rule.get("items", {}), field, lane)
                for _ in range(rule.get("minItems", 0))]
    if kind == "object":
        properties = rule.get("properties", {})
        return {name: schema_placeholder(properties.get(name, {}), name, lane)
                for name in rule.get("required", [])}
    return None


def duplicate_member_json(arguments, name, value):
    fields = [f"{json.dumps(key)}:{compact(item)}" for key, item in arguments.items()]
    fields.append(f"{json.dumps(name)}:{compact(value)}")
    if name not in arguments:
        fields.append(f"{json.dumps(name)}:{compact(value)}")
    return "{" + ",".join(fields) + "}"


def generic_contract_cases(descriptors, lane, baselines=None):
    baselines = baselines or {}
    for name, descriptor in descriptors.items():
        schema = descriptor.get("inputSchema", {})
        properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
        minimal = baselines.get(name)
        if minimal is None:
            minimal = schema_placeholder(schema, lane=lane)
        require(isinstance(minimal, dict), f"{name}: inputSchema is not an object")
        base = {"tool": name, "level": "READ_ONLY", "transports": ["stdio", "http"],
                "requires": [], "setup": [], "db_reread": [], "audit_expect": [],
                "on_unsupported": {"error_class": "INVALID_ARGUMENTS"}}
        unknown_args = {**minimal, "__w4_unknown_argument": True}
        unknown = dict(base, case_id=f"w4_contract_{name}_unknown_argument",
                       call={"arguments": unknown_args, "baseline_arguments": minimal},
                       expect={"error_class": "INVALID_ARGUMENTS"})
        yield unknown
        chosen = next(iter(minimal), next(iter(properties), "__w4_duplicate_member"))
        value = minimal.get(chosen, schema_placeholder(properties.get(chosen, {}), chosen, lane))
        raw = duplicate_member_json(minimal, chosen, value)
        yield dict(base, case_id=f"w4_contract_{name}_duplicate_member",
                   call={"arguments": minimal, "raw_arguments": raw,
                         "baseline_arguments": minimal},
                   expect={"error_class": "INVALID_ARGUMENTS"})
        for prop, rule in properties.items():
            if isinstance(rule, dict) and isinstance(rule.get("enum"), list):
                baseline = dict(minimal)
                canonical = alias_target(rule)
                if canonical and canonical != prop:
                    baseline.pop(canonical, None)
                baseline[prop] = rule["enum"][0]
                invalid = dict(baseline)
                invalid[prop] = "__w4_wrong_enum__"
                yield dict(base, case_id=f"w4_contract_{name}_{prop}_wrong_enum",
                           call={"arguments": invalid,
                                 "baseline_arguments": baseline},
                           expect={"error_class": "INVALID_ARGUMENTS"})


def audit_records(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def audit_verify(binary, path, env):
    if not path.exists():
        return False
    process = subprocess.run([str(binary), "--json", "audit", "verify", str(path)],
                             cwd=ROOT, env=env, text=True, capture_output=True, timeout=60)
    if process.returncode != 0:
        return False
    result = json.loads(process.stdout)
    return result.get("ok") is True and result.get("anchor", {}).get("status") in {"match", "behind"}


def parallel_http_call(client, case, barriers):
    workers = case["call"]["parallel"]
    sessions = [client.new_session() for _ in workers]
    if case["level"] != "READ_ONLY":
        for session_id in sessions:
            preview = tool_payload(client.session_rpc(session_id, "tools/call", {
                "name": "oracle_set_session_level", "arguments": {"level": case["level"]}}))
            token = preview.get("structuredContent", {}).get("confirmation", {}).get("confirm")
            require(preview.get("isError") is not True and token,
                    "parallel client level preview failed")
            applied = tool_payload(client.session_rpc(session_id, "tools/call", {
                "name": "oracle_set_session_level",
                "arguments": {"level": case["level"], "execute": True, "confirm": token}}))
            require(applied.get("isError") is not True and
                    applied.get("structuredContent", {}).get("changed") is True,
                    "parallel client level apply failed")
    replies = [None] * len(workers)
    errors = []

    def invoke(index):
        try:
            barriers.wait(case["case_id"], len(workers))
            replies[index] = client.session_rpc(
                sessions[index], "tools/call",
                {"name": case["tool"], "arguments": workers[index]["arguments"]})
        except Exception as exc:
            errors.append(f"worker {index}: {type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=invoke, args=(index,)) for index in range(len(workers))]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + 45
    for thread in threads:
        thread.join(timeout=max(0, deadline - time.monotonic()))
    require(not any(thread.is_alive() for thread in threads), "parallel HTTP call deadline expired")
    require(not errors, f"parallel HTTP call failed: {errors}")
    for worker, reply in zip(workers, replies):
        verify_envelope(reply)
        verify_expect(worker["expect"], reply, ROOT / "tests/golden/w4")
        if case["tool"] == "oracle_explain_plan":
            explain_statement_id(reply)
            if "plan_contains" in worker:
                plan = compact(tool_payload(reply).get("structuredContent", {}).get("plan", []))
                require(worker["plan_contains"] in plan,
                        "parallel EXPLAIN returned the other statement's plan")
    if case["tool"] == "oracle_explain_plan":
        ids = [explain_statement_id(reply) for reply in replies]
        require(len(ids) == len(set(ids)), "parallel EXPLAIN requests reused a statement id")
    return {"jsonrpc": "2.0", "id": 0, "result": {"content": [], "isError": False,
            "structuredContent": {"parallel": [
                tool_payload(reply).get("structuredContent", {}) for reply in replies]}}}


def cancelled_call(client, case, connection, marker_probe=vsql_marker_count):
    marker = case["call"]["cancel_marker"]
    require(marker_probe(connection, marker) == 0,
            "cancellation marker already present before call")
    request_id = client.next_id + 1
    result = {}

    def invoke():
        try:
            result["reply"] = client.rpc("tools/call", {
                "name": case["tool"], "arguments": case["call"]["arguments"]})
        except Exception as exc:
            result["error"] = exc

    worker = threading.Thread(target=invoke, daemon=True)
    worker.start()
    deadline = time.monotonic() + 20
    observed = False
    while time.monotonic() < deadline and worker.is_alive():
        if marker_probe(connection, marker) > 0:
            observed = True
            break
        time.sleep(0.05)
    if not observed:
        if worker.is_alive():
            client.notify("notifications/cancelled", {
                "requestId": request_id, "reason": "synthetic W4 cancellation timeout"})
            worker.join(timeout=45)
        require(not worker.is_alive(), "unobserved call did not settle after cancellation")
        raise DriverError("marked call finished or was not observed in V$SQL before cancellation")
    require(worker.is_alive(), "marked call completed before cancellation")
    client.notify("notifications/cancelled", {
        "requestId": request_id, "reason": "synthetic W4 cancellation"})
    worker.join(timeout=45)
    require(not worker.is_alive(), "cancelled call did not settle within deadline")
    if "error" in result:
        raise result["error"]
    require("reply" in result, "cancelled call produced no response")
    return result["reply"]


def session_level(client):
    status = tool_payload(client.rpc("tools/call", {
        "name": "oracle_set_session_level", "arguments": {"action": "status"}}))
    require(status.get("isError") is not True, "session level status call refused")
    return status.get("structuredContent", {}).get("session", {}).get("current_level")


def run_steps(client, case, row, binary, audit_path, env):
    """Run a multi-step case's steps in order; every step is verified, none is skipped."""
    captures, observed = {}, []
    for index, step in enumerate(case["steps"]):
        if "tool" in step:
            reply = client.rpc("tools/call", {"name": step["tool"],
                                               "arguments": fill_captures(step["arguments"], captures)})
            verify_envelope(reply)
            observed.append({"step": index, "tool": step["tool"], "actual": scrub(tool_payload(reply))})
            row["steps"] = observed
            try:
                verify_expect(step["expect"], reply, ROOT / "tests/golden/w4")
            except DriverError as exc:
                raise DriverError(f"step {index} ({step['tool']}): {exc}") from exc
            structured = tool_payload(reply).get("structuredContent", {})
            for name, pointer in step.get("capture", {}).items():
                captures[name] = json_pointer(structured, pointer)
        elif "wait_level" in step:
            deadline = time.monotonic() + step["deadline_seconds"]
            level = session_level(client)
            while level != step["wait_level"]:
                require(time.monotonic() < deadline,
                        f"step {index}: session stayed {level}, never reached {step['wait_level']}")
                time.sleep(0.5)
                level = session_level(client)
            observed.append({"step": index, "wait_level": level})
        else:
            report = subprocess.run([str(binary), "audit", "report", str(audit_path)], cwd=ROOT,
                                    env=env, text=True, capture_output=True, timeout=60)
            observed.append({"step": index, "audit_report_exit": report.returncode})
            row["steps"] = observed
            require(report.returncode == 0,
                    f"step {index}: audit report exited {report.returncode}: {report.stderr.strip()[:160]}")
            missing = [item for item in step["audit_report"]["contains"] if item not in report.stdout]
            require(not missing, f"step {index}: audit report lacks {missing}")
    row["steps"] = observed
    return captures


def verify_case_rereads(connection, case, row):
    actual_rows = []
    for reread in case["db_reread"]:
        require(set(reread) == {"sql", "rows"}, "db_reread needs sql and rows")
        actual_rows.append(db_rows(connection, reread["sql"]))
    if actual_rows:
        row["db_reread_actual"] = scrub(actual_rows)
    for reread, actual in zip(case["db_reread"], actual_rows):
        require(actual == reread["rows"],
                f"{case['case_id']}: independent DB re-read differed")


def run_case(client, case, transport, lane, capabilities, connection, barriers,
             binary, audit_path, env, descriptor=None):
    start = time.monotonic()
    supported = set(case["requires"]) <= capabilities
    expected = expected_for_case(case, capabilities)
    input_value = {"tool": case["tool"], "arguments": case["call"]["arguments"]}
    input_value["profile_variant"] = case.get("profile_variant", "masked")
    if "raw_arguments" in case["call"]:
        input_value["raw_arguments"] = case["call"]["raw_arguments"]
    if case["call"].get("retry"):
        input_value["retry"] = True
    if case["call"].get("mutation"):
        input_value["mutation"] = True
    if "parallel" in case["call"]:
        input_value["parallel"] = case["call"]["parallel"]
    if "baseline_arguments" in case["call"]:
        input_value["baseline_arguments"] = case["call"]["baseline_arguments"]
    if "vsql_absent_marker" in case["call"]:
        input_value["vsql_absent_marker"] = case["call"]["vsql_absent_marker"]
    if "cancel_marker" in case["call"]:
        input_value["cancel_marker"] = case["call"]["cancel_marker"]
    if "steps" in case:
        input_value["steps"] = case["steps"]
    row = {"case_id": case["case_id"], "test_id": case.get("test_id", case["case_id"]),
           "tool": case["tool"], "level": case["level"], "lane": lane,
           "transport": transport, "input_sha256": sha256(input_value),
           "expected": scrub(expected), "actual": None, "verdict": "fail", "duration_ms": 0}
    try:
        if case.get("setup_phase", "before_call") == "before_call":
            apply_setup(connection, case["setup"])
        if "baseline_arguments" in case["call"]:
            baseline = client.rpc("tools/call", {
                "name": case["tool"], "arguments": case["call"]["baseline_arguments"]})
            verify_envelope(baseline, descriptor)
            baseline_payload = tool_payload(baseline)
            row["baseline"] = scrub(baseline_payload)
            baseline_class = baseline_payload.get("structuredContent", {}).get("error_class")
            require(not (baseline_payload.get("isError") is True and baseline_class == "INVALID_ARGUMENTS"),
                    "contract baseline unproven: itself refused as INVALID_ARGUMENTS")
        marker = case["call"].get("vsql_absent_marker")
        if marker and supported:
            require(vsql_marker_count(connection, marker) == 0,
                    "V$SQL marker already present before refusal test")
        before = len(audit_records(audit_path))
        captures = run_steps(client, case, row, binary, audit_path, env) if "steps" in case else {}
        if "cancel_marker" in case["call"] and supported:
            reply = cancelled_call(client, case, connection)
        elif "parallel" in case["call"] and supported:
            require(transport == "http", "parallel case requires HTTP transport")
            reply = parallel_http_call(client, case, barriers)
        else:
            reply = client.rpc("tools/call", {"name": case["tool"],
                                               "arguments": fill_captures(case["call"]["arguments"],
                                                                          captures)},
                               raw_arguments=case["call"].get("raw_arguments"))
        verify_envelope(reply, None if "parallel" in case["call"] else descriptor)
        if (case["tool"] == "oracle_explain_plan" and "parallel" not in case["call"]
                and tool_payload(reply).get("isError") is not True):
            explain_statement_id(reply)
            structured = tool_payload(reply).get("structuredContent", {})
            plan = compact(structured.get("plan", []))
            require(structured.get("plan"), "EXPLAIN returned no plan rows")
            if "plan_contains" in case:
                require(case["plan_contains"] in plan,
                        "EXPLAIN plan did not contain the requested statement's object")
        row["actual"] = scrub(tool_payload(reply))
        if supported and not case["call"].get("retry"):
            verify_case_rereads(connection, case, row)
        verify_expect(expected, reply, ROOT / "tests/golden/w4")
        if marker and supported:
            require(vsql_marker_count(connection, marker) == 0,
                    "refused SQL marker reached V$SQL")
        if case["call"].get("retry"):
            repeated = client.rpc("tools/call", {"name": case["tool"],
                                                 "arguments": case["call"]["arguments"]},
                                  raw_arguments=case["call"].get("raw_arguments"))
            verify_envelope(repeated, descriptor)
            row["actual"] = {"first": row["actual"], "retry": scrub(tool_payload(repeated))}
            verify_expect(case["call"].get("retry_expect", expected), repeated,
                          ROOT / "tests/golden/w4")
            if supported:
                verify_case_rereads(connection, case, row)
        if case["audit_expect"]:
            verify_audit(case["audit_expect"], audit_records(audit_path)[before:],
                         audit_verify(binary, audit_path, env))
        if case.get("audit_zero_executions"):
            records = audit_records(audit_path)[before:]
            require(not any(record.get("decision") == "ALLOWED" or record.get("outcome") == "SUCCEEDED"
                            for record in records),
                    "FGA refusal produced an allowed or succeeded audit record")
            row["audit_zero_executions"] = True
        row["verdict"] = "pass"
    except Exception as exc:
        row["verification_failure"] = {"class": type(exc).__name__, "detail": str(exc)[:240]}
    finally:
        if case.get("cleanup"):
            apply_setup(connection, case["cleanup"])
    row["duration_ms"] = round((time.monotonic() - start) * 1000)
    return row


def run_http_auth_family(client, lane):
    frame = compact({"jsonrpc": "2.0", "id": 900000, "method": "tools/list"}).encode()
    checks = (
        ("missing_bearer", False, None, 401, None),
        ("bad_signature", True, client.token() + "x", 401, "invalid_token"),
        ("expired_bearer", True, client.token(expires_in=-10), 401, "invalid_token"),
        ("missing_scope", True, client.token(scope=""), 403, "insufficient_scope"),
        ("valid_bearer", True, client.token(), 200, None),
    )
    rows = []
    for name, auth, token, expected_status, expected_error in checks:
        started = time.monotonic()
        row = {"case_id": "w4_http_auth_" + name, "test_id": "w4_http_auth_" + name,
               "tool": "http_auth", "level": "READ_ONLY", "lane": lane, "transport": "http",
               "input_sha256": sha256({"case": name, "frame": "tools/list"}),
               "expected": {"http_status": expected_status, "auth_error": expected_error},
               "actual": None, "verdict": "fail", "duration_ms": 0}
        try:
            status, headers, body = client._request("POST", "/mcp", frame, auth=auth, token=token)
            challenge = headers.get("www-authenticate", "")
            actual_error = re.search(r'error="([a-z_]+)"', challenge)
            row["actual"] = {"http_status": status,
                             "auth_error": actual_error.group(1) if actual_error else None}
            require(status == expected_status, f"auth {name}: HTTP {status}, expected {expected_status}")
            require(row["actual"]["auth_error"] == expected_error,
                    f"auth {name}: wrong WWW-Authenticate class")
            if status == 200:
                require(isinstance(HttpClient.decode_body(body).get("result", {}).get("tools"), list),
                        "valid bearer did not expose tools/list")
            else:
                require(token is None or token not in challenge,
                        "auth challenge echoed bearer token")
            row["verdict"] = "pass"
        except Exception as exc:
            row["verification_failure"] = {"class": type(exc).__name__, "detail": str(exc)[:240]}
        row["duration_ms"] = round((time.monotonic() - started) * 1000)
        rows.append(row)
    return rows


def run_http_parallel_discovery(client, lane, barriers):
    started = time.monotonic()
    row = {"case_id": "w4_http_parallel_tools_list", "test_id": "w4_http_parallel_tools_list",
           "tool": "tools/list", "level": "READ_ONLY", "lane": lane, "transport": "http",
           "input_sha256": sha256({"method": "tools/list", "clients": 2}),
           "expected": {"distinct_sessions": True, "same_registry": True},
           "actual": None, "verdict": "fail", "duration_ms": 0}
    try:
        sessions = [client.new_session(), client.new_session()]
        require(sessions[0] != sessions[1], "parallel clients reused one session id")
        replies = [None, None]
        errors = []

        def discover(index):
            try:
                barriers.wait("w4-http-parallel-discovery", 2)
                replies[index] = client.session_rpc(sessions[index], "tools/list")
            except Exception as exc:
                errors.append(f"client {index}: {type(exc).__name__}")

        threads = [threading.Thread(target=discover, args=(index,)) for index in range(2)]
        for thread in threads:
            thread.start()
        deadline = time.monotonic() + 30
        for thread in threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        require(not any(thread.is_alive() for thread in threads) and not errors,
                f"parallel discovery failed: {errors}")
        names = [{tool["name"] for tool in reply["result"]["tools"]} for reply in replies]
        row["actual"] = {"distinct_sessions": True, "same_registry": bool(names[0] and names[0] == names[1]),
                         "registry_count": len(names[0])}
        require(row["actual"]["same_registry"], "parallel clients saw different tool registries")
        row["verdict"] = "pass"
    except Exception as exc:
        row["verification_failure"] = {"class": type(exc).__name__, "detail": str(exc)[:240]}
    row["duration_ms"] = round((time.monotonic() - started) * 1000)
    return row


def run_malformed_frame(client, lane, transport):
    started = time.monotonic()
    row = {"case_id": "w4_error_malformed_frame", "test_id": "w4_error_malformed_frame",
           "tool": "JSON-RPC", "level": "READ_ONLY", "lane": lane,
           "transport": transport, "input_sha256": sha256({"malformed_frame": True}),
           "expected": {"jsonrpc_error_code": -32700, "server_recovered": True},
           "actual": None, "verdict": "fail", "duration_ms": 0}
    try:
        reply = client.malformed_frame()
        verify_envelope(reply)
        error = reply.get("error")
        require(isinstance(error, dict) and error.get("code") == -32700,
                "malformed frame did not yield JSON-RPC parse error")
        recovered = bool(list_tools(client))
        row["actual"] = {"jsonrpc_error_code": error["code"],
                         "server_recovered": recovered}
        require(recovered, "server did not recover after malformed frame")
        row["verdict"] = "pass"
    except Exception as exc:
        row["verification_failure"] = {"class": type(exc).__name__, "detail": str(exc)[:240]}
    row["duration_ms"] = round((time.monotonic() - started) * 1000)
    return row


def run_restart_recovery(client, binary, lane, env, transport, port, secret,
                         audience, descriptors):
    started = time.monotonic()
    row = {"case_id": "w4_error_server_kill_restart",
           "test_id": "w4_error_server_kill_restart", "tool": "tools/list",
           "level": "ADMIN", "lane": lane, "transport": transport,
           "input_sha256": sha256({"fault": "kill_restart", "transport": transport}),
           "expected": {"registry_recovered": True}, "actual": None,
           "verdict": "fail", "duration_ms": 0}
    replacement = None
    try:
        client.process.kill()
        client.process.wait(timeout=10)
        replacement = (StdioClient(binary, lane, env) if transport == "stdio"
                       else HttpClient(binary, lane, env, port, secret, audience))
        initialize(replacement)
        elevate(replacement, "ADMIN")
        current = list_tools(replacement)
        recovered = set(current) == set(descriptors)
        row["actual"] = {"registry_recovered": recovered,
                         "registry_count": len(current)}
        require(recovered, "registry changed after server kill and restart")
        row["verdict"] = "pass"
    except Exception as exc:
        row["verification_failure"] = {"class": type(exc).__name__, "detail": str(exc)[:240]}
    row["duration_ms"] = round((time.monotonic() - started) * 1000)
    return row, replacement


def manifest_required(lane, transport, capabilities):
    command = [sys.executable, str(MANIFEST), "--required-ids", "--lane", lane,
               "--transport", transport]
    for value in sorted(capabilities):
        command.extend(["--capability", value])
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=30)
    require(result.returncode == 0, f"manifest required-ids failed: {result.stderr.strip()[-240:]}")
    return set(result.stdout.splitlines())


def enforce_manifest(results_path, lane, transport, capabilities):
    required = manifest_required(lane, transport, capabilities)
    results = json.loads(results_path.read_text())
    present = {row["case_id"] for row in results["cases"]
               if row["transport"] == transport and row["verdict"] == "pass"}
    missing = sorted(required - present)
    require(not missing, f"missing or red release manifest case on {transport}: {', '.join(missing)}")
    command = [sys.executable, str(MANIFEST), "--check-results", str(results_path),
               "--lane", lane, "--transport", transport]
    for value in sorted(capabilities):
        command.extend(["--capability", value])
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=30)
    require(result.returncode == 0, f"manifest check-results failed: {result.stderr.strip()[-240:]}")


def manifest_enforcement_integration():
    required = manifest_required("free23", "stdio", {"version:23"})
    require(required, "manifest integration has no required live cases")
    missing = sorted(required)[0]
    path = ROOT / "target/e2e/w4/selftest/missing-one-manifest-case.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"cases": [
        {"case_id": case_id, "transport": "stdio", "verdict": "pass"}
        for case_id in sorted(required - {missing})],
        "cargo_test_logs": []}, sort_keys=True) + "\n")
    try:
        enforce_manifest(path, "free23", "stdio", {"version:23"})
    except DriverError as exc:
        require(missing in str(exc),
                "missing manifest failure did not name the single omitted case")
        print(compact({"integration": "manifest_enforcement_integration",
                       "missing_case": missing, "verdict": "rejected"}))
    else:
        raise DriverError("manifest integration accepted one omitted required case")


def summary_table(rows):
    table = collections.defaultdict(lambda: collections.defaultdict(lambda: {"pass": 0, "fail": 0}))
    for row in rows:
        table[row["tool"]][row["transport"]][row["verdict"]] += 1
    return {tool: dict(transports) for tool, transports in sorted(table.items())}


def run_lane(args):
    settings = load_lane(HERE / "rig.toml", args.lane)
    config = json.loads(CAPABILITIES.read_text())
    require(config.get("schema_version") == 1 and args.lane in config.get("lanes", {}),
            "capability matrix has no declared lane")
    capabilities, connection, password = probe_capabilities(args.lane, settings, config)
    base = ROOT / "target/e2e/w4" / args.lane
    base.mkdir(parents=True, exist_ok=True)
    run_id = "w4-" + secrets.token_hex(8)
    work = base / run_id
    work.mkdir(parents=True, exist_ok=True)
    port = pick_port()
    audience = write_lab_config(work / "profiles.toml", args.lane, settings["dsn"], port)
    secret = secrets.token_hex(32)
    key = secrets.token_hex(32)
    env = {name: value for name, value in os.environ.items() if not name.startswith("ORACLEMCP_")}
    env.update({"ORACLEMCP_CONFIG": str(work / "profiles.toml"), "ORACLEMCP_AUDIT_KEY": key,
                "W4_DB_PASSWORD": password, "W4_OAUTH_SECRET": secret})
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()
    binary = args.binary or target_dir / "release/oraclemcp"
    checkout_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    built_here = False
    if not binary.is_file() and not args.binary:
        build = subprocess.run(["cargo", "build", "--release", "-p", "oraclemcp", "--bin", "oraclemcp"],
                               cwd=ROOT, env={**env, "CARGO_TARGET_DIR": str(target_dir),
                                              "CARGO_BUILD_JOBS": os.environ.get("CARGO_BUILD_JOBS", "16")},
                               timeout=1200)
        require(build.returncode == 0, "scoped release binary build failed")
        built_here = True
    require(binary.is_file(), "release binary not found")
    require(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() == checkout_sha,
            "checkout revision changed while preparing the binary")
    binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
    family_cases = load_cases()
    if args.case:
        selected = set(args.case)
        available = {case["case_id"] for case in family_cases}
        require(selected <= available,
                f"unknown scoped W4 case(s): {', '.join(sorted(selected - available))}")
        family_cases = [case for case in family_cases if case["case_id"] in selected]
    release_ids = {case["case_id"]: case["test_id"] for case in json.loads(
        (ROOT / "scripts/e2e/cases/release_0_12.json").read_text())}
    for case in family_cases:
        if case["case_id"] in release_ids:
            case["test_id"] = release_ids[case["case_id"]]
    rows, descriptors, fixture_runs = [], None, {}
    barriers = BarrierPool()
    try:
        for transport in ("stdio", "http"):
            state = work / transport / "state"
            state.mkdir(parents=True, exist_ok=True)
            audit_path = state / "oraclemcp/audit/audit.jsonl"
            fixture_id = None
            client = None
            try:
                if not args.contract_only:
                    fixture_id = new_run_id()
                    with (work / "fixture.jsonl").open("a") as fixture_log:
                        with contextlib.redirect_stdout(fixture_log):
                            fixture_setup(args.lane, settings, fixture_id,
                                          owner_password_sink=lambda value: env.__setitem__("W4_OWNER_PASSWORD", value),
                                          cross_password_sink=lambda value: env.__setitem__("W4_CROSS_PASSWORD", value))
                    fixture_runs[transport] = fixture_id
                    owner = "W4O_" + fixture_id
                    wait_for_setup_ready(
                        settings, password,
                        f"SELECT ID FROM {owner}.T_PARENT_{fixture_id} WHERE ROWNUM <= 1")
                    if any(case.get("profile_variant") in {"synthetic_owner", "synthetic_owner_rw"}
                           for case in family_cases if transport in case["transports"]):
                        # The disposable owner needs the same FGA catalog proof
                        # that every served relation read requires.
                        connection.cursor().execute(f"GRANT SELECT ANY DICTIONARY TO {owner}")
                    write_lab_config(work / "profiles.toml", args.lane, settings["dsn"], port,
                                     owner=owner, cross="W4X_" + fixture_id)
                client_env = {**env, "XDG_STATE_HOME": str(state)}
                expanded_family = ([] if args.contract_only else [
                    freshen_vsql_marker(expand_case(case, fixture_id, transport, args.lane)) for case in family_cases
                    if transport in case["transports"]])
                for case in expanded_family:
                    if (case.get("setup_phase") == "before_server"
                            and set(case["requires"]) <= capabilities):
                        apply_setup(connection, case["setup"])
                        if "setup_ready_sql" in case:
                            wait_for_setup_ready(settings, password, case["setup_ready_sql"])
                client = (StdioClient(binary, args.lane, client_env) if transport == "stdio"
                          else HttpClient(binary, args.lane, client_env, port, secret, audience))
                initialize(client)
                if not args.case:
                    rows.append(run_malformed_frame(client, args.lane, transport))
                if transport == "http" and not args.case:
                    rows.extend(run_http_auth_family(client, args.lane))
                    rows.append(run_http_parallel_discovery(client, args.lane, barriers))
                elevate(client, "ADMIN")
                discovered = list_tools(client)
                for case in family_cases:
                    if set(case["requires"]) <= capabilities:
                        require(case["tool"] in discovered,
                                f"supported case {case['case_id']} names unadvertised tool {case['tool']}")
                if descriptors is None:
                    descriptors = discovered
                else:
                    require(set(descriptors) == set(discovered), "stdio/HTTP tool registries differ")
                dropped = tool_payload(client.rpc("tools/call", {
                    "name": "oracle_set_session_level", "arguments": {"action": "drop"}}))
                require(dropped.get("structuredContent", {}).get("session", {}).get("current_level") == "READ_ONLY",
                        "could not return to READ_ONLY after discovery")
                cases = list(expanded_family)
                if not args.case:
                    cases += list(generic_contract_cases(
                        discovered, args.lane, contract_baselines(expanded_family)))
                current_level = "READ_ONLY"
                current_profile = args.lane
                for case in cases:
                    variant = case.get("profile_variant")
                    desired_profile = (args.lane + "_raw" if variant == "synthetic_raw"
                                       else args.lane + "_owner" if variant == "synthetic_owner"
                                       else args.lane + "_owner_rw" if variant == "synthetic_owner_rw"
                                       else args.lane + "_cross_rw" if variant == "synthetic_cross_rw"
                                       else args.lane + "_cross_rw_strict" if variant == "synthetic_cross_rw_strict"
                                       else args.lane + "_protected" if variant == "protected"
                                       else args.lane + "_capped" if variant == "capped_rw"
                                       else args.lane)
                    if desired_profile != current_profile:
                        if current_level != "READ_ONLY":
                            dropped = tool_payload(client.rpc("tools/call", {
                                "name": "oracle_set_session_level", "arguments": {"action": "drop"}}))
                            require(dropped.get("structuredContent", {}).get("session", {}).get("current_level") == "READ_ONLY",
                                    "failed to drop before profile switch")
                        switched = tool_payload(client.rpc("tools/call", {
                            "name": "oracle_switch_profile", "arguments": {"profile": desired_profile}}))
                        require(switched.get("isError") is not True,
                                f"could not switch to W4 profile {desired_profile}")
                        current_profile = desired_profile
                        current_level = "READ_ONLY"
                    if case["level"] != current_level:
                        if current_level != "READ_ONLY":
                            dropped = tool_payload(client.rpc("tools/call", {
                                "name": "oracle_set_session_level", "arguments": {"action": "drop"}}))
                            require(dropped.get("structuredContent", {}).get("session", {}).get("current_level") == "READ_ONLY",
                                    "failed to drop between case levels")
                        elevate(client, case["level"])
                        current_level = case["level"]
                    rows.append(run_case(client, case, transport, args.lane, capabilities, connection,
                                         barriers, binary, audit_path, client_env,
                                         discovered.get(case["tool"])))
                    if "steps" in case:
                        # Steps may elevate, expire or drop the session level on
                        # their own; re-establish the tracked READ_ONLY baseline.
                        dropped = tool_payload(client.rpc("tools/call", {
                            "name": "oracle_set_session_level", "arguments": {"action": "drop"}}))
                        require(dropped.get("structuredContent", {}).get("session", {}).get("current_level") == "READ_ONLY",
                                "failed to drop after a multi-step case")
                        current_level = "READ_ONLY"
                if not args.case:
                    restart_row, replacement = run_restart_recovery(
                        client, binary, args.lane, client_env, transport, port,
                        secret, audience, discovered)
                    rows.append(restart_row)
                    if replacement is not None:
                        client = replacement
                require(audit_path.exists() and audit_verify(binary, audit_path, client_env),
                        f"{transport}: final audit chain verification failed")
            finally:
                if client is not None:
                    client.close()
                if fixture_id is not None:
                    with (work / "fixture.jsonl").open("a") as fixture_log:
                        with contextlib.redirect_stdout(fixture_log):
                            fixture_teardown(args.lane, settings, fixture_id)
                env.pop("W4_OWNER_PASSWORD", None)
        output = {"lane": args.lane, "checkout_sha": checkout_sha,
                  "binary_source_sha": args.binary_source_sha or (checkout_sha if built_here else None),
                  "binary_sha256": binary_sha256,
                  "fixture_runs": fixture_runs,
                  "capabilities": sorted(capabilities), "registry": sorted(descriptors),
                  "cases": rows, "summary": summary_table(rows),
                  "cargo_test_logs": [str(path) for path in args.cargo_test_log]}
        results_path = base / "results.json"
        results_path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
        (base / "cases.jsonl").write_text("".join(compact(row) + "\n" for row in rows))
        if args.coverage_report:
            (base / "coverage.json").write_text(json.dumps(
                coverage_status(descriptors, family_cases), indent=2, sort_keys=True) + "\n")
        if not args.contract_only and not args.case:
            for transport in ("stdio", "http"):
                enforce_manifest(results_path, args.lane, transport, capabilities)
        if (not args.contract_only and not args.case) or args.coverage_report:
            verify_coverage(descriptors, family_cases)
        failed = [row["case_id"] for row in rows if row["verdict"] != "pass"]
        require(not failed, f"red W4 cases: {', '.join(failed[:12])} ({len(failed)} total)")
        print(compact({"lane": args.lane, "registry_count": len(descriptors),
                       "cases": len(rows), "verdict": "pass", "results": str(results_path)}))
    finally:
        connection.close()


def selftest():
    load_cases()
    version_case = {
        "requires": [],
        "expect": {"json_subset": {"columns": [
            {"COLUMN_NAME": "LABEL", "DATA_DEFAULT": "'w4' "}]}},
        "expect_by_version": {
            "23": {"json_subset": {"columns": [
                {"COLUMN_NAME": "LABEL", "DATA_DEFAULT": "'w4' "}]}},
            "pre23": {"json_subset": {"columns": [
                {"COLUMN_NAME": "LABEL", "DATA_DEFAULT": None}]}}},
        "on_unsupported": {"error_class": "INVALID_ARGUMENTS"},
    }
    require(expected_for_case(version_case, {"version:23"})["json_subset"]["columns"][0]
            ["DATA_DEFAULT"] == "'w4' ", "23ai expectation did not retain bounded default text")
    require(expected_for_case(version_case, {"version:18"})["json_subset"]["columns"][0]
            ["DATA_DEFAULT"] is None, "pre-23 expectation did not require a null default")
    original_marker = "W4MARK_FGAHANDLER000001"
    marker_case = {"call": {"arguments": {"sql": f"SELECT 1 /* {original_marker} */"},
                            "vsql_absent_marker": original_marker}}
    first = freshen_vsql_marker(marker_case)
    second = freshen_vsql_marker(marker_case)
    for expanded in (first, second):
        marker = expanded["call"]["vsql_absent_marker"]
        require(re.fullmatch(r"W4MARK_[A-Z0-9]{12,32}", marker) is not None,
                "fresh V$SQL marker has invalid shape")
        require(marker in expanded["call"]["arguments"]["sql"]
                and original_marker not in expanded["call"]["arguments"]["sql"],
                "fresh V$SQL marker did not replace the sent SQL")
    require(first["call"]["vsql_absent_marker"] != second["call"]["vsql_absent_marker"],
            "two runs reused a V$SQL refusal marker")
    require(marker_case["call"]["vsql_absent_marker"] == original_marker,
            "fresh V$SQL marker mutated the manifest case")
    synthetic_descriptor = {"inputSchema": {"type": "object", "properties": {
        "object_name": {"type": "string"}}, "required": ["object_name"]}}
    generated = list(generic_contract_cases(
        {"oracle_synthetic": synthetic_descriptor}, "free23",
        {"oracle_synthetic": {"object_name": "W4O_VALID"}}))
    require(generated[0]["call"]["baseline_arguments"] == {"object_name": "W4O_VALID"},
            "per-family contract baseline did not override schema placeholder")
    enum_schema = {"inputSchema": {"type": "object", "properties": {
        "level": {"type": "string", "enum": ["READ_ONLY", "DDL"]},
        "target_level": {"type": "string", "enum": ["READ_ONLY", "DDL"],
                         "description": "Alias for level."}},
        "required": ["level"]}}
    enum_cases = list(generic_contract_cases(
        {"oracle_synthetic_level": enum_schema}, "free23"))
    alias_enum = next(case for case in enum_cases
                      if case["case_id"].endswith("target_level_wrong_enum"))
    require(alias_enum["call"]["baseline_arguments"] == {"target_level": "READ_ONLY"}
            and alias_enum["call"]["arguments"] ==
            {"target_level": "__w4_wrong_enum__"},
            "enum alias cases must never send canonical and alias fields together")
    sql_id = schema_placeholder(
        {"type": "string", "minLength": 13, "maxLength": 13}, "sql_id")
    require(isinstance(sql_id, str) and len(sql_id) == 13,
            "SQL-ID placeholder must satisfy the advertised 13-character bound")
    ddl = schema_placeholder({"type": "string"}, "ddl")
    require(ddl.startswith("CREATE TABLE ") and ddl.endswith("(ID NUMBER)"),
            "DDL placeholder must be a real CREATE TABLE statement")
    ddl_alias = schema_placeholder(
        {"type": "string", "description": "Alias for ddl."}, "sql")
    require(ddl_alias == ddl, "DDL aliases must receive a real CREATE TABLE statement")
    source_code = schema_placeholder({"type": "string"}, "source_code")
    require(source_code.startswith("CREATE OR REPLACE VIEW ")
            and " AS SELECT 1 AS ID FROM dual" in source_code,
            "source-code placeholder must be a real CREATE OR REPLACE statement")
    source_alias = schema_placeholder(
        {"type": "string", "description": "Runtime compatibility alias for source_code."},
        "sql")
    require(source_alias == source_code,
            "source-code aliases must receive a real CREATE OR REPLACE statement")
    rejected_marker = {"case_id": "w4_selftest_marker", "tool": "oracle_synthetic",
                       "level": "READ_ONLY", "transports": ["stdio"],
                       "requires": ["priv:SELECT_V_SQL"], "setup": [],
                       "call": {"arguments": {}, "vsql_absent_marker": "not_synthetic"},
                       "expect": {"error_class": "INVALID_ARGUMENTS"},
                       "db_reread": [], "audit_expect": [],
                       "on_unsupported": {"error_class": "INVALID_ARGUMENTS"}}
    require(expand_case("${owner}.T_TYPES_${run_id}", "W41234ABCDEF", "stdio") ==
            "W4O_W41234ABCDEF.T_TYPES_W41234ABCDEF", "run-owned placeholder expansion failed")
    require(scrub({"meta": {"timestamp": "moving"},
                   "rows": [{"timestamp": "2020-02-29 23:30:00 +05:45"}]}) ==
            {"meta": {"timestamp": "<volatile>"},
             "rows": [{"timestamp": "2020-02-29 23:30:00 +05:45"}]},
            "scrubber hid semantic timestamp or leaked metadata timestamp")
    correct = {"jsonrpc": "2.0", "id": 1, "result": {"content": [], "isError": False,
               "structuredContent": {"rows": [[1], [2]]}}}
    verify_expect({"rows": [[1], [2]]}, correct)
    def rejected(label, operation):
        try:
            operation()
        except DriverError:
            print(compact({"selftest": label, "verdict": "rejected"}))
        else:
            raise DriverError(f"selftest accepted planted {label}")
    rejected("invalid_vsql_marker", lambda: validate_case(rejected_marker, "selftest"))
    rejected("wrong_row_order", lambda: verify_expect({"rows": [[2], [1]]}, correct))
    rejected("malformed_wire_envelope", lambda: verify_envelope({"result": {"content": []}}))
    rejected("missing_output_schema_key", lambda: verify_envelope(
        correct, {"outputSchema": {"type": "object", "required": ["missing"]}}))
    rejected("unresolved_placeholder", lambda: expand_case("${unknown}", "W41234ABCDEF", "stdio"))
    rejected("non_owned_setup", lambda: apply_setup(object(), [{"sql": "DROP TABLE OTHER_TABLE"}]))
    error = {"jsonrpc": "2.0", "id": 1, "result": {"content": [], "isError": True,
             "structuredContent": {"error_class": "INVALID_ARGUMENTS"}}}
    rejected("wrong_error_class", lambda: verify_expect({"error_class": "FORBIDDEN_STATEMENT"}, error))
    plan_reply = {"result": {"content": [], "isError": False, "structuredContent": {
        "diagnostic_write": {"statement_id": "OMCP_" + "A" * 24,
                             "savepoint": "OMCP_EXPLAIN_PLAN", "rolled_back": True}}}}
    require(explain_statement_id(plan_reply) == "OMCP_" + "A" * 24,
            "EXPLAIN statement-id verifier lost the generated identifier")
    rejected("invalid_explain_statement_id", lambda: explain_statement_id({
        "result": {"content": [], "isError": False, "structuredContent": {
            "diagnostic_write": {"statement_id": "unsafe", "savepoint": "OMCP_EXPLAIN_PLAN",
                                 "rolled_back": True}}}}))
    rejected("untyped_error_class_family", lambda: verify_expect(
        {"error_classes": ["FORBIDDEN_STATEMENT"]}, error))
    rejected("missing_audit_record", lambda: verify_audit([{"tool": "oracle_query"}], [], True))
    rejected("extra_audit_record", lambda: verify_audit(
        [{"tool": "oracle_query"}],
        [{"tool": "oracle_query"}, {"tool": "oracle_execute"}], True))
    rejected("wrong_audit_order", lambda: verify_audit(
        [{"tool": "oracle_query"}, {"tool": "oracle_execute"}],
        [{"tool": "oracle_execute"}, {"tool": "oracle_query"}], True))
    rejected("broken_chain", lambda: verify_audit([], [], False))
    class StubClient:
        def __init__(self):
            self.calls = 0

        def rpc(self, method, params, raw_arguments=None):
            self.calls += 1
            return error

    unsupported = {"case_id": "w4_selftest_unsupported", "tool": "oracle_query",
                   "level": "READ_ONLY", "requires": ["feature:VECTOR"], "setup": [],
                   "call": {"arguments": {}}, "expect": {"rows": [[1]]},
                   "on_unsupported": {"error_class": "INVALID_ARGUMENTS"},
                   "db_reread": [], "audit_expect": []}
    stub = StubClient()
    unsupported_row = run_case(stub, unsupported, "stdio", "xe18", set(), object(),
                               BarrierPool(), Path("unused"), Path("unused"), {})
    require(stub.calls == 1 and unsupported_row["verdict"] == "pass",
            "unsupported case silently skipped instead of asserting typed refusal")
    print(compact({"selftest": "unsupported_not_skipped", "verdict": "pass"}))
    retry_case = {**unsupported, "requires": [],
                  "expect": {"error_class": "INVALID_ARGUMENTS"},
                  "call": {"arguments": {}, "retry": True}}
    retry_stub = StubClient()
    retry_row = run_case(retry_stub, retry_case, "stdio", "free23", set(), object(),
                         BarrierPool(), Path("unused"), Path("unused"), {})
    require(retry_stub.calls == 2 and retry_row["verdict"] == "pass",
            "retry path failed to issue two independently verified calls")
    class StepStub:
        """Plays a server for the preview -> confirm -> replay sequence."""

        def __init__(self, replay_accepted=False, status_level="READ_ONLY"):
            self.replay_accepted = replay_accepted
            self.status_level = status_level
            self.executions = 0
            self.sent = []

        def rpc(self, method, params, raw_arguments=None):
            self.sent.append(params)
            args = params["arguments"]
            if params["name"] == "oracle_preview_sql":
                structured = {"execute_confirmation": {"confirm": "tok-synthetic-1"}}
                return {"jsonrpc": "2.0", "id": 1, "result": {
                    "content": [], "isError": False, "structuredContent": structured}}
            if params["name"] == "oracle_set_session_level":
                return {"jsonrpc": "2.0", "id": 1, "result": {
                    "content": [], "isError": False,
                    "structuredContent": {"session": {"current_level": self.status_level}}}}
            self.executions += 1
            accepted = self.executions == 1 or self.replay_accepted
            require(args.get("confirm") == "tok-synthetic-1", "stub received an unfilled capture")
            structured = ({"executed": True, "committed": True} if accepted
                          else {"error_class": "CHALLENGE_REQUIRED"})
            return {"jsonrpc": "2.0", "id": 1, "result": {
                "content": [], "isError": not accepted, "structuredContent": structured}}

    replay_case = {"case_id": "w4_selftest_token_replay", "tool": "oracle_execute",
                   "level": "READ_WRITE", "transports": ["stdio"], "requires": [], "setup": [],
                   "steps": [
                       {"tool": "oracle_preview_sql", "arguments": {"sql": "UPDATE T SET X = 1"},
                        "expect": {"json_subset": {"execute_confirmation": {}}},
                        "capture": {"token": "/execute_confirmation/confirm"}},
                       {"tool": "oracle_execute",
                        "arguments": {"sql": "UPDATE T SET X = 1", "commit": True, "confirm": "${cap:token}"},
                        "expect": {"json_subset": {"committed": True}}}],
                   "call": {"arguments": {"sql": "UPDATE T SET X = 1", "commit": True,
                                          "confirm": "${cap:token}"}},
                   "expect": {"error_class": "CHALLENGE_REQUIRED"},
                   "db_reread": [], "audit_expect": [],
                   "on_unsupported": {"error_class": "CHALLENGE_REQUIRED"}}
    validate_case(replay_case, "selftest")

    def step_row(stub, case):
        return run_case(stub, case, "stdio", "free23", set(), object(), BarrierPool(),
                        Path("unused"), Path("unused"), {})

    honest = StepStub()
    honest_row = step_row(honest, replay_case)
    require(honest_row["verdict"] == "pass" and honest.executions == 2
            and honest.sent[-1]["arguments"]["confirm"] == "tok-synthetic-1",
            "multi-step replay case did not run preview, apply and replay with the captured token")
    print(compact({"selftest": "multi_step_token_replay_refused", "verdict": "pass"}))

    def step_failed(label, stub, case):
        row = step_row(stub, case)
        require(row["verdict"] == "fail", f"selftest accepted planted {label}")
        print(compact({"selftest": label, "verdict": "rejected",
                       "detail": row["verification_failure"]["detail"][:80]}))

    step_failed("replayed_token_accepted", StepStub(replay_accepted=True), replay_case)
    wrong_step = json.loads(json.dumps(replay_case))
    wrong_step["steps"][1]["expect"] = {"json_subset": {"committed": False}}
    step_failed("wrong_step_expectation", StepStub(), wrong_step)
    missing_pointer = json.loads(json.dumps(replay_case))
    missing_pointer["steps"][0]["capture"] = {"token": "/execute_confirmation/absent"}
    step_failed("missing_capture_pointer", StepStub(), missing_pointer)
    expiry_case = {**replay_case, "case_id": "w4_selftest_expiry",
                   "steps": [{"wait_level": "READ_ONLY", "deadline_seconds": 1}],
                   "call": {"arguments": {"sql": "UPDATE T SET X = 1"}},
                   "expect": {"json_subset": {"committed": True}}}
    validate_case(expiry_case, "selftest")
    step_failed("level_never_reached", StepStub(status_level="READ_WRITE"), expiry_case)
    early_capture = json.loads(json.dumps(replay_case))
    early_capture["steps"][0]["arguments"]["sql"] = "${cap:token}"
    rejected("capture_used_before_recorded", lambda: validate_case(early_capture, "selftest"))
    rejected("unknown_profile_variant", lambda: validate_case(
        {**replay_case, "profile_variant": "writable_everything"}, "selftest"))
    rejected("protected_profile_elevated", lambda: validate_case(
        {**replay_case, "profile_variant": "protected"}, "selftest"))
    class ParallelStub:
        def __init__(self):
            self.next_session = 0

        def new_session(self):
            self.next_session += 1
            return f"session-{self.next_session}"

        def session_rpc(self, session_id, method, params):
            return {"jsonrpc": "2.0", "id": 2, "result": {"content": [],
                    "isError": False, "structuredContent": {"rows": [[1]]}}}

    parallel_case = {"case_id": "w4_selftest_parallel", "tool": "oracle_query",
                     "level": "READ_ONLY",
                     "call": {"parallel": [
                         {"arguments": {}, "expect": {"rows": [[1]]}},
                         {"arguments": {}, "expect": {"rows": [[1]]}}]}}
    parallel_stub = ParallelStub()
    parallel_reply = parallel_http_call(parallel_stub, parallel_case, BarrierPool())
    verify_expect({"json_subset": {"parallel": [{"rows": [[1]]}, {"rows": [[1]]}]}},
                  parallel_reply)
    require(parallel_stub.next_session == 2, "parallel call did not create two clients")
    class CancelStub:
        def __init__(self):
            self.next_id = 0
            self.started = threading.Event()
            self.released = threading.Event()
            self.notification = None

        def rpc(self, method, params):
            self.next_id += 1
            self.started.set()
            require(self.released.wait(5), "stub cancellation notification absent")
            return {"jsonrpc": "2.0", "id": self.next_id,
                    "result": {"content": [], "isError": True,
                               "structuredContent": {"error_class": "CANCELLED"}}}

        def notify(self, method, params):
            self.notification = (method, params)
            self.released.set()

    cancel_stub = CancelStub()
    cancel_case = {"tool": "oracle_synthetic", "call": {
        "arguments": {}, "cancel_marker": "W4MARK_123456789ABC"}}
    cancelled = cancelled_call(
        cancel_stub, cancel_case, object(),
        marker_probe=lambda _connection, _marker: int(cancel_stub.started.is_set()))
    require(tool_payload(cancelled)["structuredContent"]["error_class"] == "CANCELLED"
            and cancel_stub.notification == (
                "notifications/cancelled", {"requestId": 1,
                                            "reason": "synthetic W4 cancellation"}),
            "cancellation did not wait for marker and send bound request id")
    rejected("missing_positive_case", lambda: verify_coverage({"oracle_query": {}}, []))
    manifest_enforcement_integration()
    left, right = [], []
    pool = BarrierPool()
    one = threading.Thread(target=lambda: left.append(pool.wait("ordered", 2)))
    two = threading.Thread(target=lambda: right.append(pool.wait("ordered", 2)))
    one.start(); two.start(); one.join(5); two.join(5)
    require(not one.is_alive() and not two.is_alive() and len(left) == len(right) == 1,
            "concurrent barrier failed")
    print("selftest: pass")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--manifest-enforcement-integration", action="store_true")
    parser.add_argument("--lane", choices=("free23", "xe18", "xe21"))
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--binary-source-sha", help="verified source revision of an external binary")
    parser.add_argument("--contract-only", action="store_true",
                        help="run generated W3 contracts without the release manifest")
    parser.add_argument("--case", action="append",
                        help="run one named live case (repeatable); scoped run skips broad manifest and contract gates")
    parser.add_argument("--coverage-report", action="store_true")
    parser.add_argument("--cargo-test-log", type=Path, action="append", default=[])
    args = parser.parse_args()
    try:
        require(not (args.case and args.contract_only), "--case and --contract-only cannot be combined")
        require(not args.binary_source_sha or re.fullmatch(r"[0-9a-f]{40}", args.binary_source_sha),
                "--binary-source-sha needs a full Git SHA")
        if args.selftest:
            selftest()
        elif args.manifest_enforcement_integration:
            manifest_enforcement_integration()
        else:
            require(args.lane, "--lane is required for a live run")
            run_lane(args)
    except (DriverError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"w4 driver: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
