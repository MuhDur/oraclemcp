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

from fixture import (admin_password, kill_session_sql, load_lane, new_run_id,
                     set_flashback_grant, setup as fixture_setup, teardown as fixture_teardown)
from scrub import scrub


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
PROTOCOL = "2025-11-25"
MAX_RESPONSE_BYTES = 1_048_576
CAPABILITIES = HERE / "capabilities.json"
CASES = HERE / "cases"
MANIFEST = ROOT / "scripts/e2e/cases/validate_manifest.py"
RELEASE_MANIFEST = ROOT / "scripts/e2e/cases/release_0_12.json"
CASE_FIELDS = {"case_id", "tool", "level", "transports", "requires", "setup",
               "call", "expect", "db_reread", "audit_expect", "on_unsupported"}
OPTIONAL_CASE_FIELDS = {"setup_phase", "setup_ready_sql", "profile_variant", "audit_zero_executions",
                        "steps", "expect_by_version", "cleanup", "cleanup_reread", "plan_contains", "row_contains",
                        "finding_row_contains", "runtime_retention_probe", "flashback_grant_owner",
                        "environment_skips", "runtime_awr_probe", "audit_optional_prefix"}
PROFILE_VARIANTS = {"masked", "synthetic_raw", "synthetic_owner", "synthetic_owner_rw", "synthetic_cross_rw",
                    "synthetic_cross_rw_strict", "synthetic_cross_security",
                    "synthetic_cross_security_strict", "protected", "capped_rw", "synthetic_licensed",
                    "trusted_views", "short_admin"}
LEVELS = ("READ_ONLY", "READ_WRITE", "DDL", "ADMIN")
# A multi-step case captures structured values from one step and feeds them
# to later ones (a confirmation token from a preview, for example).
CAPTURE = re.compile(r"\$\{cap:([a-z][a-z0-9_]{0,31})\}")
EXPECT_KINDS = {"rows", "error_class", "error_classes", "json_subset", "golden", "goldens"}
CURRENT_SESSION = object()


class DriverError(RuntimeError):
    pass


RETENTION_SOURCE_SKIP = "RETENTION_SOURCE_NEWER_THAN_EXPIRED_SCN"
RETENTION_HISTORY_SKIP = "RETENTION_SCN_HISTORY_UNAVAILABLE"
RETENTION_SKIP_CODES = [RETENTION_SOURCE_SKIP, RETENTION_HISTORY_SKIP]
AWR_SKIP_CODES = ["AWR_PACK_NOT_ENABLED", "AWR_CATALOG_UNAVAILABLE", "AWR_NO_SNAPSHOTS",
                  "AWR_NO_SQL_HISTORY", "AWR_TOP_SQL_HAS_NO_PLAN_HISTORY"]


class EnvironmentSkip(DriverError):
    def __init__(self, reason):
        super().__init__(reason["message"])
        self.reason = reason


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
    marker = case["call"].get("vsql_absent_marker") or case["call"].get("cancel_marker")
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
            "expect needs exactly one rows/error_class/json_subset/golden/goldens selector")
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
    elif "golden" in expect:
        require(golden_root is not None, "golden root missing")
        name = expect["golden"]
        require(re.fullmatch(r"[a-zA-Z0-9_.-]+\.json", name) is not None,
                "unsafe golden filename")
        golden = json.loads((golden_root / name).read_text())
        require(scrub(structured) == golden, "scrubbed golden differs")
    else:
        require(golden_root is not None, "golden root missing")
        names = expect["goldens"]
        require(isinstance(names, list) and len(names) == 2,
                "goldens needs exactly the proved rollback and unknown terminal variants")
        goldens = []
        for name in names:
            require(isinstance(name, str) and re.fullmatch(r"[a-zA-Z0-9_.-]+\.json", name),
                    "unsafe golden filename")
            goldens.append(json.loads((golden_root / name).read_text()))
        require(scrub(structured) in goldens,
                "scrubbed result differs from both proved terminal-outcome goldens")
    return scrub(structured)


def verify_row_contains(reply, expected_row):
    require(isinstance(expected_row, dict) and expected_row,
            "row_contains must be a nonempty object")
    payload = tool_payload(reply)
    require(payload.get("isError") is not True, "row_contains expected a successful tool result")
    rows = payload.get("structuredContent", {}).get("rows")
    require(isinstance(rows, list), "row_contains requires a rows array")
    def matches(row):
        return isinstance(row, dict) and all(
            key in row and (value in row[key] if isinstance(value, str) and isinstance(row[key], str)
                            else row[key] == value)
            for key, value in expected_row.items())
    require(any(matches(row) for row in rows), "rows did not contain the expected row")


def verify_finding_row_contains(reply, expected_row):
    require(isinstance(expected_row, dict) and expected_row,
            "finding_row_contains must be a nonempty object")
    payload = tool_payload(reply)
    require(payload.get("isError") is not True,
            "finding_row_contains expected a successful tool result")
    findings = payload.get("structuredContent", {}).get("findings")
    require(isinstance(findings, list), "finding_row_contains requires a findings array")
    rows = []
    for finding in findings:
        if isinstance(finding, dict):
            detail = finding.get("detail")
            if isinstance(detail, dict) and isinstance(detail.get("rows"), list):
                rows.extend(detail["rows"])
    def matches(row):
        return isinstance(row, dict) and all(
            key in row and (value in row[key] if isinstance(value, str) and isinstance(row[key], str)
                            else row[key] == value)
            for key, value in expected_row.items())
    require(any(matches(row) for row in rows),
            "findings did not contain the expected row")


def verify_audit(expected, records, verified, optional_prefix=None):
    require(verified, "audit chain verification failed")
    if optional_prefix and records and records[0].get("tool") == optional_prefix["record"]["tool"]:
        require(deep_subset(optional_prefix["record"], records[0]),
                "wrong optional audit prefix record")
        records = records[1:]
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
    if case.get("profile_variant") in {"synthetic_cross_security", "synthetic_cross_security_strict"}:
        require(case["level"] == "READ_ONLY",
                "security evidence profiles are pinned to READ_ONLY")
    require("plan_contains" not in case
            or (isinstance(case["plan_contains"], str) and case["plan_contains"]),
            "plan_contains must be a nonempty string")
    require("row_contains" not in case
            or (isinstance(case["row_contains"], dict) and case["row_contains"]
                and all(isinstance(key, str) and key for key in case["row_contains"])),
            "row_contains must be a nonempty object with nonempty string keys")
    require("finding_row_contains" not in case
            or (isinstance(case["finding_row_contains"], dict) and case["finding_row_contains"]
                and all(isinstance(key, str) and key
                        for key in case["finding_row_contains"])),
            "finding_row_contains must be a nonempty object with nonempty string keys")
    if case.get("profile_variant") == "protected":
        require(case["level"] == "READ_ONLY", "a protected profile is pinned at READ_ONLY")
    if case.get("profile_variant") == "capped_rw":
        require(case["level"] in {"READ_ONLY", "READ_WRITE"},
                "the capped_rw profile's ceiling is READ_WRITE")
    if case.get("profile_variant") == "short_admin":
        require(case["level"] == "ADMIN",
                "short_admin is reserved for deadline-accounted lane cases")
    if "runtime_retention_probe" in case:
        require(case["runtime_retention_probe"] is True
                and case["case_id"] == "w4_diff_retention_exceeded_typed"
                and case["tool"] == "oracle_diff" and case["level"] == "READ_ONLY",
                "runtime retention probing is reserved for the oracle_diff retention case")
    if "runtime_awr_probe" in case:
        require(case["runtime_awr_probe"] is True
                and case["case_id"] == "w4_diagnostics_licensed_profile_serves_awr"
                and case["tool"] == "oracle_plan_timeline"
                and case.get("profile_variant") == "synthetic_licensed"
                and case["level"] == "READ_ONLY",
                "runtime AWR probing is reserved for the positive licensed AWR case")
    if "environment_skips" in case:
        require((case.get("runtime_retention_probe") is True
                 and case["environment_skips"] == RETENTION_SKIP_CODES)
                or (case.get("runtime_awr_probe") is True
                    and case["environment_skips"] == AWR_SKIP_CODES),
                "environment skip must name the exact declared retention or AWR limitation")
    if "flashback_grant_owner" in case:
        require(case["flashback_grant_owner"] is True
                and case["case_id"] == "w4_diff_as_of_scn_detects_change"
                and case.get("profile_variant") == "synthetic_owner_rw",
                "flashback grant is reserved for the positive disposable-owner diff case")
    if "audit_optional_prefix" in case:
        prefix = case["audit_optional_prefix"]
        require(case["case_id"] == "w4_runtime_issue47_killed_session_dml_not_replayed"
                and "kill_served_session_dml_user" in case["call"]
                and isinstance(prefix, dict) and set(prefix) == {"record", "max_count", "reason"}
                and type(prefix["max_count"]) is int and prefix["max_count"] == 1
                and isinstance(prefix["reason"], str) and prefix["reason"].strip()
                and prefix["record"] == {"tool": "scn_capability_probe", "decision": "ALLOWED",
                                         "outcome": "FAILED", "failure": {
                                             "error_class": "FLASHBACK_CAPABILITY_UNAVAILABLE"}},
                "killed-DML audit allows only one explicitly explained degraded SCN prefix")
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
    require(set(case["call"]) <= {"arguments", "raw_arguments", "retry", "retry_expect", "repeat_count", "repeat_expect", "parallel", "mutation", "baseline_arguments", "contract_baseline", "vsql_absent_marker", "cancel_marker", "cancel_barrier", "progress_token", "reuse_after_cancel", "cancel_audit", "lock_sql", "cancel_mutation_audit", "cancel_after_completion", "kill_served_session_user", "kill_served_session_dml_user", "scn_cache_expect", "session_busy"},
            "unknown call field")
    if "session_busy" in case["call"]:
        busy = case["call"]["session_busy"]
        require(case["case_id"] == "w4_runtime_issue50_session_busy"
                and case["transports"] == ["http"]
                and case.get("profile_variant", "masked") == "masked"
                and isinstance(busy, dict)
                and set(busy) == {"marker", "lock_sql", "queued_arguments", "retry_arguments"}
                and all(isinstance(busy[key], str) and busy[key]
                        for key in ("marker", "lock_sql"))
                and all(isinstance(busy[key], dict)
                        for key in ("queued_arguments", "retry_arguments")),
                "issue50 session-busy case needs exact same-session pipe barrier fields")
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
    if "cancel_barrier" in case["call"]:
        require("cancel_marker" in case["call"]
                and isinstance(case["call"]["cancel_barrier"], str)
                and case["call"]["cancel_barrier"],
                "cancel_barrier needs a marked cancellation call and a nonempty DBMS_PIPE name")
    if "progress_token" in case["call"]:
        require("cancel_marker" in case["call"]
                and isinstance(case["call"]["progress_token"], str)
                and case["call"]["progress_token"],
                "progress_token needs a marked cancellation call and a nonempty token")
    if "reuse_after_cancel" in case["call"]:
        require(case["call"]["reuse_after_cancel"] is True and "cancel_marker" in case["call"],
                "reuse_after_cancel is only meaningful after a marked cancellation")
    if "cancel_audit" in case["call"]:
        require(case["call"]["cancel_audit"] is True and "cancel_marker" in case["call"],
                "cancel_audit is only meaningful after a marked cancellation")
    if "lock_sql" in case["call"]:
        require("cancel_marker" in case["call"]
                and isinstance(case["call"]["lock_sql"], str)
                and case["call"]["lock_sql"].strip(),
                "lock_sql is only meaningful for a marked cancellation call")
    if "cancel_mutation_audit" in case["call"]:
        require(case["call"]["cancel_mutation_audit"] is True
                and case["call"].get("mutation") is True
                and "cancel_marker" in case["call"],
                "cancel_mutation_audit needs a marked mutation")
    if "cancel_after_completion" in case["call"]:
        require(case["call"]["cancel_after_completion"] is True
                and case["call"].get("mutation") is True
                and case["call"]["arguments"].get("commit") is True,
                "cancel_after_completion needs a committed mutation")
    if "kill_served_session_user" in case["call"]:
        user = case["call"]["kill_served_session_user"]
        require(isinstance(user, str) and (user == "${owner}" or re.fullmatch(r"W4O_W4[0-9]{4}[A-F0-9]{6}", user)),
                "kill_served_session_user must be the exact run-owned owner")
        require(case["tool"] == "oracle_query" and case["transports"] == ["stdio"]
                and case["level"] == "READ_ONLY" and not case["call"].get("mutation"),
                "killed-session recovery is a read-only stdio oracle_query case")
    if "kill_served_session_dml_user" in case["call"]:
        user = case["call"]["kill_served_session_dml_user"]
        require(isinstance(user, str) and (user == "${owner}" or re.fullmatch(r"W4O_W4[0-9]{4}[A-F0-9]{6}", user)),
                "kill_served_session_dml_user must be the exact run-owned owner")
        require(case["tool"] == "oracle_execute" and case["transports"] == ["stdio"]
                and case["level"] == "READ_WRITE" and case["call"].get("mutation"),
                "killed-session DML is a mutating stdio oracle_execute case")
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
    if "repeat_count" in case["call"]:
        require(type(case["call"]["repeat_count"]) is int and 2 <= case["call"]["repeat_count"] <= 20,
                "repeat_count must be a bounded integer in 2..20")
        if "repeat_expect" in case["call"]:
                verify_expect_shape(case["call"]["repeat_expect"])
    if "scn_cache_expect" in case["call"]:
        require(case["call"]["scn_cache_expect"] is True
                and case["case_id"] == "w4_runtime_issue46_scn_probe_cached"
                and case["call"].get("repeat_count") == 20,
                "SCN cache expectation is reserved for the 20-read issue46 case")
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
    require(isinstance(case.get("cleanup_reread", []), list),
            "cleanup_reread must be an array")
    for reread in case["db_reread"] + case.get("cleanup_reread", []):
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
        step_audits = any("audit_record" in step or "audit_records" in step
                          for step in case.get("steps", []))
        require(case["db_reread"] and (case["audit_expect"] or step_audits
                                         or case["call"].get("cancel_mutation_audit")),
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
    or {audit_report: {contains: [...]}} which renders this run's audit file;
    or {audit_record: {tool, ...}} / {audit_records: [...]} which checks exact readable audit fields.
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
        elif "external_scn_capture" in step:
            require(set(step) == {"external_scn_capture"}
                    and isinstance(step["external_scn_capture"], str)
                    and re.fullmatch(r"[a-z][a-z0-9_]{0,31}", step["external_scn_capture"]),
                    "external_scn_capture needs one stable capture name")
            known.add(step["external_scn_capture"])
        elif "wait_level" in step:
            require(set(step) == {"wait_level", "deadline_seconds"}
                    and step["wait_level"] in LEVELS
                    and type(step["deadline_seconds"]) is int and 1 <= step["deadline_seconds"] <= 120,
                    "wait_level step needs a level and a 1..120 s deadline")
        elif "audit_report" in step:
            require(set(step) == {"audit_report"} and isinstance(step["audit_report"], dict)
                    and set(step["audit_report"]) == {"contains"}
                    and isinstance(step["audit_report"]["contains"], list)
                    and step["audit_report"]["contains"]
                    and all(isinstance(item, str) and item for item in step["audit_report"]["contains"]),
                    "audit_report step needs a nonempty contains list")
        elif "audit_record" in step:
            require(set(step) == {"audit_record"} and isinstance(step["audit_record"], dict)
                    and {"tool", "outcome"} <= step["audit_record"].keys()
                    and set(step["audit_record"]) <= {
                        "tool", "danger_level", "decision", "outcome", "rows_affected", "sql_preview"
                    }
                    and all(isinstance(value, str) for key, value in step["audit_record"].items()
                            if key != "rows_affected")
                    and ("rows_affected" not in step["audit_record"]
                         or type(step["audit_record"]["rows_affected"]) is int),
                    "audit_record step needs exact readable audit fields")
        else:
            require(set(step) == {"audit_records"} and isinstance(step["audit_records"], list)
                    and 1 <= len(step["audit_records"]) <= 4,
                    "audit_records step needs 1..4 exact records")
            for expected in step["audit_records"]:
                validate_steps({**case, "steps": [{"audit_record": expected}]})
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
    if "goldens" in expect:
        names = expect["goldens"]
        require(isinstance(names, list) and len(names) == 2,
                "goldens needs exactly two terminal-outcome golden names")
        for name in names:
            require(isinstance(name, str) and name.count("${lane}") <= 1
                    and re.fullmatch(r"[a-zA-Z0-9_.-]+\.json", name.replace("${lane}", "lane")),
                    "invalid golden filename")
            lanes = (("free23", "xe18", "xe21") if "${lane}" in name else (None,))
            for lane in lanes:
                concrete = name if lane is None else name.replace("${lane}", lane)
                require((ROOT / "tests/golden/w4" / concrete).is_file(),
                        f"golden file {concrete} is missing")


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
        self.notifications = []
        self.notifications_lock = threading.Lock()
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
            if "method" in reply:
                with self.notifications_lock:
                    self.notifications.append(reply)

    def notifications_since(self, start):
        with self.notifications_lock:
            return list(self.notifications[start:])

    def notification_count(self):
        with self.notifications_lock:
            return len(self.notifications)

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
    def __init__(self, binary, profile, env, port, secret, audience, streaming=False):
        self.port, self.secret, self.audience = port, secret, audience
        self.session_id = None
        self.next_id = 0
        self.session_ids = {}
        self.session_lock = threading.Lock()
        self.notifications = []
        self.notifications_lock = threading.Lock()
        self.last_response_frames = []
        self.stderr_tail = collections.deque(maxlen=20)
        command = [str(binary), "--json", "serve", "--listen", f"127.0.0.1:{port}"]
        if not streaming:
            command.append("--http-json-response")
        command.extend(["--profile", profile])
        self.process = subprocess.Popen(
            command,
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
        # `SESSION_BUSY` is a JSON-RPC tool error carried with HTTP 429 so
        # clients can honor Retry-After without losing the typed envelope.
        require(status in {200, 429}, f"HTTP {method} returned {status}")
        if method == "initialize":
            self.session_id = headers.get("mcp-session-id")
            require(self.session_id, "stateful HTTP initialize lacked session id")
        return self.decode_body(body, self)

    @staticmethod
    def decode_body(body, client=None):
        try:
            decoded = json.loads(body)
            if client is not None:
                client.last_response_frames = [decoded]
            return decoded
        except json.JSONDecodeError:
            frames = [json.loads(line[6:]) for line in body.decode().splitlines()
                      if line.startswith("data: ") and line[6:] != "null"]
            require(frames, "HTTP SSE response had no JSON frame")
            if client is not None:
                client.last_response_frames = frames
                with client.notifications_lock:
                    client.notifications.extend(frame for frame in frames if "method" in frame)
            replies = [frame for frame in frames if "id" in frame]
            require(replies, "HTTP SSE response had no JSON-RPC reply")
            return replies[-1]

    def notifications_since(self, start):
        with self.notifications_lock:
            return list(self.notifications[start:])

    def notification_count(self):
        with self.notifications_lock:
            return len(self.notifications)

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

[[profiles]]
name = "{lane}_licensed"
description = "synthetic W4 lane with an explicit Diagnostics Pack license attestation"
connect_string = "{dsn}"
username = "system"
credential_ref = "env:W4_DB_PASSWORD"
max_level = "ADMIN"
default_level = "READ_ONLY"
diagnostics_pack_licensed = true
'''
    content += f'''
[[profiles]]
name = "{lane}_short_admin"
description = "synthetic W4 two-second pinned-session queue deadline"
connect_string = "{dsn}"
username = "system"
credential_ref = "env:W4_DB_PASSWORD"
max_level = "ADMIN"
default_level = "READ_ONLY"
call_timeout_seconds = 2
'''
    if owner is not None:
        require(re.fullmatch(r"W4O_W4[0-9]{4}[A-F0-9]{6}", owner) is not None,
                "owner profile must name the exact W4 fixture")
        run_owner_suffix = owner.removeprefix("W4O_")
        content += f'''
[[profiles]]
name = "{lane}_trusted_views"
description = "synthetic W4 profile for recursive trusted application-view proof"
connect_string = "{dsn}"
username = "system"
credential_ref = "env:W4_DB_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"
trusted_views = ["{owner}.V35_INNER_{run_owner_suffix}", "{owner}.V35_OUTER_{run_owner_suffix}", "{owner}.V35_SIDE_{run_owner_suffix}"]

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
        content += f'''
[[profiles]]
name = "{lane}_cross_security"
description = "synthetic W4 least-privilege read profile with default security evidence behavior"
connect_string = "{dsn}"
username = "{cross}"
credential_ref = "env:W4_CROSS_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"
'''
        content += f'''
[[profiles]]
name = "{lane}_cross_security_strict"
description = "synthetic W4 least-privilege read profile requiring security catalog evidence"
connect_string = "{dsn}"
username = "{cross}"
credential_ref = "env:W4_CROSS_PASSWORD"
max_level = "READ_ONLY"
default_level = "READ_ONLY"
require_security_feature_evidence = true
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


def active_cancel_marker_count(connection, marker, blocked_on_row=False):
    # Parsing/caching SQL is not an admission barrier. Observe the marked
    # statement on an active Oracle session; a locked mutation must also be
    # waiting on the harness's row lock before cancellation is sent.
    sql = ("SELECT COUNT(*) FROM V$SESSION S JOIN V$SQL Q "
           "ON Q.SQL_ID = S.SQL_ID AND Q.CHILD_NUMBER = S.SQL_CHILD_NUMBER "
           "WHERE S.STATUS = 'ACTIVE' AND INSTR(Q.SQL_TEXT, :marker) > 0")
    if blocked_on_row:
        sql += " AND S.EVENT = 'enq: TX - row lock contention'"
    return connection.cursor().execute(sql, {"marker": marker}).fetchone()[0]


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


def audit_record_matches(records, expected):
    """Match readable audit fields structurally; never search serialized blobs."""
    return any(all(record.get(key) == value for key, value in expected.items())
               for record in records)


def audit_records_since(records, starting_count):
    """Restrict a step's audit expectations to records appended by that step."""
    return records[starting_count:]


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


def wait_cancel_barrier(connection, pipe_name, worker):
    """Wait for the fixture function's DBMS_PIPE signal, never a timing guess."""
    cursor = connection.cursor()
    for _ in range(20):
        status = cursor.var(int)
        cursor.execute(
            "BEGIN :status := DBMS_PIPE.RECEIVE_MESSAGE(:pipe_name, 1); END;",
            {"status": status, "pipe_name": pipe_name},
        )
        if status.getvalue() == 0:
            return
        if not worker.is_alive():
            return
    raise DriverError(f"DBMS_PIPE cancellation barrier {pipe_name} was not signalled before its deadline")


def session_busy_call(client, case, connection):
    """Exercise one HTTP MCP session with a DBMS_PIPE-held admin call.

    The holder and both reads use the *same* MCP session id. The independent
    SYSTEM connection holds/release a fixture-row lock, while V$SQL observes
    the holder's marked static SQL without a timing guess.
    """
    busy = case["call"]["session_busy"]
    holder = {}
    preview = tool_payload(client.rpc("tools/call", {
        "name": "oracle_preview_sql",
        "arguments": {"sql": case["call"]["arguments"]["sql"]},
    }))
    confirm = ((preview.get("structuredContent") or {}).get("execute_confirmation") or {}).get("confirm")
    require(preview.get("isError") is not True and isinstance(confirm, str) and confirm,
            "issue50 holder preview did not issue an execute confirmation: "
            + compact(scrub(preview))[:3_000])
    holder_arguments = {**case["call"]["arguments"], "confirm": confirm}
    queued_preview = tool_payload(client.rpc("tools/call", {
        "name": "oracle_preview_sql",
        "arguments": {"sql": busy["queued_arguments"]["sql"],
                      "timeout_seconds": busy["queued_arguments"]["timeout_seconds"]},
    }))
    queued_confirm = ((queued_preview.get("structuredContent") or {})
                      .get("execute_confirmation") or {}).get("confirm")
    require(queued_preview.get("isError") is not True
            and isinstance(queued_confirm, str) and queued_confirm,
            "issue50 queued write preview did not issue an execute confirmation")
    queued_arguments = {**busy["queued_arguments"], "confirm": queued_confirm}

    def invoke_holder():
        try:
            holder["reply"] = client.rpc("tools/call", {
                "name": case["tool"], "arguments": holder_arguments})
        except Exception as exc:
            holder["error"] = exc

    connection.cursor().execute(busy["lock_sql"])
    worker = threading.Thread(target=invoke_holder, daemon=True)
    worker.start()
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and worker.is_alive():
            if vsql_marker_count(connection, busy["marker"]) > 0:
                break
            time.sleep(0.05)
        else:
            raise DriverError("issue50 marked static holder did not reach Oracle before deadline")
        require(worker.is_alive(), "issue50 holder completed before queue contention")

        queued_result = {}

        def invoke_queued():
            try:
                queued_result["reply"] = client.rpc("tools/call", {
                    "name": "oracle_execute", "arguments": queued_arguments})
            except Exception as exc:
                queued_result["error"] = exc

        queued_worker = threading.Thread(target=invoke_queued, daemon=True)
        queued_worker.start()
        # A bounded database-side wait keeps A holding the fixture lock beyond
        # B's two-second budget without a wall-clock sleep in the test driver.
        status = connection.cursor().var(int)
        connection.cursor().execute(
            "BEGIN :status := DBMS_PIPE.RECEIVE_MESSAGE(:pipe_name, 3); END;",
            {"status": status, "pipe_name": f"W4I50_DELAY_{secrets.token_hex(8)}"},
        )
        require(status.getvalue() == 1, "issue50 DBMS_PIPE delay was unexpectedly signalled")
        connection.rollback()
        queued_worker.join(timeout=10)
        require(not queued_worker.is_alive(), "issue50 queued request did not settle after lock release")
        if "error" in queued_result:
            raise queued_result["error"]
        queued = queued_result["reply"]
        payload = tool_payload(queued)
        structured = payload.get("structuredContent", {})
        if not (payload.get("isError") is True and structured.get("error_class") == "SESSION_BUSY"):
            print("issue50-queued=" + compact(payload), file=sys.stderr)
        require(payload.get("isError") is True and structured.get("error_class") == "SESSION_BUSY",
                "same-session queued request did not return typed SESSION_BUSY: "
                + compact(scrub(payload))[:400])
        require(isinstance(structured.get("retry_after_ms"), int)
                and structured["retry_after_ms"] > 0,
                "SESSION_BUSY retry_after_ms must be positive")
        require(isinstance(structured.get("queued_ms"), int) and structured["queued_ms"] > 0,
                "SESSION_BUSY queued_ms must record real mailbox wait")
    finally:
        connection.rollback()
        worker.join(timeout=10)
    require(not worker.is_alive(), "issue50 holder did not settle after DBMS_PIPE release")
    if "error" in holder:
        raise holder["error"]
    verify_envelope(holder["reply"])
    require(tool_payload(holder["reply"]).get("isError") is not True,
            "issue50 holder failed after DBMS_PIPE release")
    retried = client.rpc("tools/call", {
        "name": "oracle_query", "arguments": busy["retry_arguments"]})
    verify_envelope(retried)
    require(tool_payload(retried).get("isError") is not True,
            "issue50 retry after holder release did not succeed")
    return queued, {"queued": scrub(payload), "holder": scrub(tool_payload(holder["reply"])),
                    "retry": scrub(tool_payload(retried))}


def cancelled_call(client, case, connection, marker_probe=vsql_marker_count):
    marker = case["call"]["cancel_marker"]
    require(marker_probe(connection, marker) == 0,
            "cancellation marker already present before call")
    request_id = client.next_id + 1
    result = {}
    notification_start = client.notification_count() if hasattr(client, "notification_count") else 0

    def invoke():
        try:
            params = {"name": case["tool"], "arguments": case["call"]["arguments"]}
            if "progress_token" in case["call"]:
                params["_meta"] = {"progressToken": case["call"]["progress_token"]}
            result["reply"] = client.rpc("tools/call", params)
        except Exception as exc:
            result["error"] = exc

    worker = threading.Thread(target=invoke, daemon=True)
    worker.start()
    barrier = case["call"].get("cancel_barrier")
    if barrier:
        wait_cancel_barrier(connection, barrier, worker)
        observed = True
    else:
        deadline = time.monotonic() + 20
        observed = False
        while time.monotonic() < deadline and worker.is_alive():
            if marker_probe(connection, marker) > 0:
                observed = True
                break
            time.sleep(0.05)
    if barrier and not worker.is_alive():
        if "error" in result:
            raise result["error"]
        raise DriverError("marked cancellation call completed before the DBMS_PIPE barrier: "
                          + compact(scrub(tool_payload(result.get("reply", {}))))[:400])
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
    notifications = (client.notifications_since(notification_start)
                     if hasattr(client, "notifications_since") else [])
    if "progress_token" in case["call"]:
        token = case["call"]["progress_token"]
        require(any(frame.get("method") == "notifications/progress"
                    and frame.get("params", {}).get("progressToken") == token
                    for frame in notifications),
                "progressToken request received no in-flight progress notification")
        if hasattr(client, "last_response_frames"):
            progress_indices = [index for index, frame in enumerate(client.last_response_frames)
                                if frame.get("method") == "notifications/progress"
                                and frame.get("params", {}).get("progressToken") == token]
            reply_indices = [index for index, frame in enumerate(client.last_response_frames)
                             if "id" in frame]
            require(progress_indices and reply_indices and min(progress_indices) < max(reply_indices),
                    "HTTP progress notification was not emitted before completion")
    else:
        require(not any(frame.get("method") == "notifications/progress" for frame in notifications),
                "request without progressToken emitted a progress notification")
    if case["call"].get("reuse_after_cancel"):
        reuse = client.rpc("tools/call", {
            "name": "oracle_query", "arguments": {"sql": "SELECT 1 AS C FROM dual"}})
        verify_envelope(reuse)
        require(tool_payload(reuse).get("isError") is not True,
                "served session was not reusable after confirmed cancellation")
    client.last_cancel_observation = {
        "request_id": request_id,
        "barrier": barrier,
        "progress_notifications": scrub(notifications),
        "session_reused": bool(case["call"].get("reuse_after_cancel")),
    }
    return result["reply"]


def completed_before_cancel_call(client, case, captures):
    """Issue cancellation only after the committed response was acknowledged."""
    request_id = client.next_id + 1
    reply = client.rpc("tools/call", {
        "name": case["tool"],
        "arguments": fill_captures(case["call"]["arguments"], captures),
    })
    verify_envelope(reply)
    require(tool_payload(reply).get("isError") is not True,
            "commit-race setup did not receive the committed result")
    client.notify("notifications/cancelled", {
        "requestId": request_id,
        "reason": "synthetic W4 cancellation after acknowledged commit",
    })
    client.last_cancel_observation = {
        "request_id": request_id,
        "after_completion": True,
        "session_reused": False,
    }
    return reply


def session_level(client):
    status = tool_payload(client.rpc("tools/call", {
        "name": "oracle_set_session_level", "arguments": {"action": "status"}}))
    require(status.get("isError") is not True, "session level status call refused")
    return status.get("structuredContent", {}).get("session", {}).get("current_level")


def run_steps(client, case, row, binary, audit_path, env, connection):
    """Run a multi-step case's steps in order; every step is verified, none is skipped."""
    captures, observed = {}, []
    audit_scope_start = len(audit_records(audit_path))
    for index, step in enumerate(case["steps"]):
        if "external_scn_capture" in step:
            name = step["external_scn_capture"]
            require(isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,31}", name),
                    f"step {index}: external SCN capture needs a stable capture name")
            scn = connection.cursor().execute("SELECT CURRENT_SCN FROM V$DATABASE").fetchone()[0]
            require(type(scn) is int and scn > 0,
                    f"step {index}: V$DATABASE did not return a positive integer SCN")
            captures[name] = str(scn)
            observed.append({"step": index, "external_scn_capture": name})
        elif "tool" in step:
            audit_scope_start = len(audit_records(audit_path))
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
            audit_scope_start = len(audit_records(audit_path))
            deadline = time.monotonic() + step["deadline_seconds"]
            level = session_level(client)
            while level != step["wait_level"]:
                require(time.monotonic() < deadline,
                        f"step {index}: session stayed {level}, never reached {step['wait_level']}")
                time.sleep(0.5)
                level = session_level(client)
            observed.append({"step": index, "wait_level": level})
        elif "audit_report" in step:
            records = audit_records(audit_path)
            report = "\n".join(compact(record) for record in records)
            observed.append({"step": index, "audit_record_count": len(records)})
            row["steps"] = observed
            missing = [item for item in step["audit_report"]["contains"] if item not in report]
            require(not missing, f"step {index}: audit report lacks {missing}")
        elif "audit_record" in step:
            records = audit_records_since(audit_records(audit_path), audit_scope_start)
            expected = step["audit_record"]
            require(audit_record_matches(records, expected),
                    f"step {index}: no audit record matches exact fields {expected}")
            observed.append({"step": index, "audit_record": expected})
        else:
            records = audit_records_since(audit_records(audit_path), audit_scope_start)
            for expected in step["audit_records"]:
                require(audit_record_matches(records, expected),
                        f"step {index}: no audit record matches exact fields {expected}")
            observed.append({"step": index, "audit_records": step["audit_records"]})
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


def killed_session_recovery_call(client, case, connection, descriptor):
    """Kill only this W4 run's served session, then prove next-call re-lease.

    This case deliberately uses the disposable ``synthetic_owner`` profile so
    its SYSDBA-side kill can target only the exact run-owned session. That
    profile exposes the synthetic ``SELECT 1`` value, hence ``C: "1"`` is the
    expected result here; it does not relax the normal masked-profile contract
    (which remains covered by the issue-46 case).

    The first query establishes the pinned session. The second call is expected
    to observe the dead wire and quarantine it; only the third, separate
    statement may obtain a replacement. This deliberately proves no in-flight
    statement is replayed.
    """
    arguments = case["call"]["arguments"]
    first = client.rpc("tools/call", {"name": case["tool"], "arguments": arguments})
    verify_envelope(first, descriptor)
    require(tool_payload(first).get("isError") is not True,
            "baseline read failed before killed-session exercise")
    user = case["call"]["kill_served_session_user"]
    sessions = connection.cursor().execute(
        "SELECT SID, SERIAL# FROM V$SESSION "
        "WHERE USERNAME=:1 AND TYPE='USER' AND STATUS <> 'KILLED' ORDER BY SID",
        (user,)).fetchall()
    require(sessions, "no exact run-owned served Oracle session found to kill")
    cursor = connection.cursor()
    for sid, serial in sessions:
        cursor.execute(kill_session_sql(int(sid), int(serial)))
    connection.commit()
    recovered = client.rpc("tools/call", {"name": case["tool"], "arguments": arguments})
    verify_envelope(recovered, descriptor)
    require(tool_payload(recovered).get("isError") is not True,
            "the first read after a killed session did not transparently re-lease: "
            + compact(scrub(tool_payload(recovered)))[:400])
    return recovered, {"baseline": scrub(tool_payload(first)),
                       "killed_sessions": len(sessions),
                       "recovered": scrub(tool_payload(recovered))}


def killed_session_dml_call(client, case, connection, descriptor):
    """Kill the exact disposable-owner wire before one governed DML attempt.

    This proves the mutation is not replayed: the attempt must surface a typed
    uncertain outcome, while the independent reread stays at the fixture value.
    """
    baseline = client.rpc("tools/call", {"name": "oracle_query",
                                          "arguments": {"sql": "SELECT 1 AS C FROM dual"}})
    verify_envelope(baseline, descriptor)
    require(tool_payload(baseline).get("isError") is not True,
            "baseline read failed before killed-session DML exercise")
    user = case["call"]["kill_served_session_dml_user"]
    sessions = connection.cursor().execute(
        "SELECT SID, SERIAL# FROM V$SESSION "
        "WHERE USERNAME=:1 AND TYPE='USER' AND STATUS <> 'KILLED' ORDER BY SID",
        (user,)).fetchall()
    require(sessions, "no exact run-owned served Oracle session found to kill")
    cursor = connection.cursor()
    for sid, serial in sessions:
        cursor.execute(kill_session_sql(int(sid), int(serial)))
    connection.commit()
    lost = client.rpc("tools/call", {"name": case["tool"], "arguments": case["call"]["arguments"]})
    verify_envelope(lost, descriptor)
    payload = tool_payload(lost)
    outcome = payload.get("structuredContent", {}).get("statement_outcome")
    require(payload.get("isError") is True and outcome == "protocol_unsynchronized"
            and "no statement was executed" in payload.get("structuredContent", {}).get("message", ""),
            "killed DML did not report its unexecuted protocol-unsynchronized preflight")
    # Flush the quarantined lease's terminal audit before checking this case.
    # The lane already restarts this client after killed DML; close is idempotent.
    client.close()
    return lost, {"baseline": scrub(tool_payload(baseline)), "killed_sessions": len(sessions),
                  "loss": scrub(payload)}


@contextlib.contextmanager
def case_flashback_grant(case, lane, settings, owner, change_grant=set_flashback_grant):
    """Keep the positive diff privilege inside its case, even when setup or execution fails.

    A failed revoke aborts the lane rather than letting another case inherit the grant.
    """
    if not case.get("flashback_grant_owner"):
        yield
        return
    try:
        change_grant(lane, settings, owner, True)
        yield
    finally:
        change_grant(lane, settings, owner, False)


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
    if "repeat_count" in case["call"]:
        repeat_count = case["call"]["repeat_count"]
        require(type(repeat_count) is int and 2 <= repeat_count <= 20,
                "repeat_count must be a bounded integer in 2..20")
        input_value["repeat_count"] = repeat_count
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
    for field in ("cancel_barrier", "progress_token", "reuse_after_cancel", "cancel_audit", "lock_sql",
                  "cancel_mutation_audit",
                  "cancel_after_completion"):
        if field in case["call"]:
            input_value[field] = case["call"][field]
    if "steps" in case:
        input_value["steps"] = case["steps"]
    row = {"case_id": case["case_id"], "test_id": case.get("test_id", case["case_id"]),
           "tool": case["tool"], "level": case["level"], "lane": lane,
           "transport": transport, "input_sha256": sha256(input_value),
           "expected": scrub(expected), "actual": None, "verdict": "fail", "duration_ms": 0}
    if "retention_probe" in case:
        row["retention_probe"] = scrub(case["retention_probe"])
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
        captures = (run_steps(client, case, row, binary, audit_path, env, connection)
                    if "steps" in case else {})
        if "kill_served_session_user" in case["call"] and supported:
            reply, recovery_actual = killed_session_recovery_call(client, case, connection, descriptor)
            row["killed_session_recovery"] = recovery_actual
        elif "kill_served_session_dml_user" in case["call"] and supported:
            reply, recovery_actual = killed_session_dml_call(client, case, connection, descriptor)
            row["killed_session_recovery"] = recovery_actual
        elif "cancel_marker" in case["call"] and supported:
            lock_sql = case["call"].get("lock_sql")
            if lock_sql:
                connection.cursor().execute(lock_sql)
            try:
                reply = cancelled_call(client, case, connection,
                                       marker_probe=lambda conn, marker: active_cancel_marker_count(
                                           conn, marker, blocked_on_row=bool(lock_sql)))
            finally:
                if lock_sql:
                    connection.rollback()
            row["cancel_observation"] = client.last_cancel_observation
            row["cancel_observation"]["db_admission_barrier"] = (
                "active_row_lock" if lock_sql else "active_statement")
        elif case["call"].get("cancel_after_completion") and supported:
            reply = completed_before_cancel_call(client, case, captures)
            row["cancel_observation"] = client.last_cancel_observation
        elif "session_busy" in case["call"] and supported:
            require(transport == "http", "issue50 same-session contention requires HTTP")
            reply, busy_actual = session_busy_call(client, case, connection)
            row["session_busy"] = busy_actual
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
        if "row_contains" in case:
            verify_row_contains(reply, case["row_contains"])
        if "finding_row_contains" in case:
            verify_finding_row_contains(reply, case["finding_row_contains"])
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
        if "repeat_count" in case["call"]:
            replies = [reply]
            for _ in range(case["call"]["repeat_count"] - 1):
                repeated = client.rpc("tools/call", {"name": case["tool"],
                                                       "arguments": case["call"]["arguments"]})
                verify_envelope(repeated, descriptor)
                verify_expect(case["call"].get("repeat_expect", expected), repeated,
                              ROOT / "tests/golden/w4")
                replies.append(repeated)
            row["actual"] = {"repeat_count": len(replies),
                             "last": scrub(tool_payload(replies[-1]))}
            if case["call"].get("scn_cache_expect"):
                records = audit_records(audit_path)[before:]
                probes = [record for record in records
                          if record.get("tool") == "scn_capability_probe"]
                require(len(probes) == 1 and probes[0].get("outcome") == "FAILED",
                        "no-grant SCN cache case needs exactly one degraded probe audit")
                reads = [record for record in records
                         if record.get("tool") == "oracle_query" and record.get("outcome") == "SUCCEEDED"]
                require(len(reads) == len(replies)
                        and all(record.get("verdict_certificate", {}).get("observed_scn") is None
                                for record in reads),
                        "no-grant SCN cache needs null observed_scn on every audited read")
                row["scn_cache"] = {"observed_scn_null_reads": len(reads),
                                    "degraded_probe_audits": len(probes)}
        if case["call"].get("cancel_audit"):
            records = audit_records(audit_path)[before:]
            cancelled = [record for record in records
                         if record.get("tool") == case["tool"]
                         and record.get("outcome") == "FAILED"
                         and record.get("failure", {}).get("ora_code") == 1013]
            require(len(cancelled) == 1,
                    "cancelled query needs exactly one terminal FAILED ORA-01013 audit record")
            row["cancel_audit"] = {"terminal_outcome": cancelled[0]["outcome"],
                                   "ora_code": cancelled[0]["failure"]["ora_code"]}
        if case["call"].get("cancel_mutation_audit"):
            structured = tool_payload(reply)["structuredContent"]
            writes = [record for record in audit_records(audit_path)[before:]
                      if record.get("tool") == case["tool"]]
            require(len(writes) == 2 and writes[0].get("decision") == "ALLOWED"
                    and writes[0].get("outcome") == "PENDING",
                    "cancelled mutation needs exactly one pending audit before its terminal audit")
            terminal = writes[1].get("outcome")
            expected_response = ({"error_class": "REQUEST_CANCELLED",
                                  "cancel_outcome": "cancel_confirmed",
                                  "statement_outcome": "rolled_back"}
                                 if terminal == "ROLLED_BACK" else
                                 {"error_class": "CONNECTION_FAILED",
                                  "cancel_outcome": "outcome_unknown",
                                  "statement_outcome": "protocol_unsynchronized"})
            require(terminal in {"ROLLED_BACK", "UNKNOWN_DISCARDED"}
                    and deep_subset(expected_response, structured),
                    "cancelled mutation response does not match its proved terminal outcome")
            require([(record.get("decision"), record.get("outcome")) for record in writes]
                    == [("ALLOWED", "PENDING"), ("ALLOWED", terminal)],
                    "cancelled mutation needs one pending audit and one terminal no-retry audit")
            row["cancel_mutation_audit"] = {"terminal_outcome": terminal,
                                             "write_attempts": len(writes)}
        if "session_busy" in case["call"] and supported:
            busy_audits = [record for record in audit_records(audit_path)[before:]
                           if record.get("tool") == "session_busy"]
            require(len(busy_audits) == 1
                    and busy_audits[0].get("decision") == "BLOCKED"
                    and busy_audits[0].get("outcome") == "FAILED",
                    "SESSION_BUSY must append exactly one blocked audit record")
            row["session_busy_audit"] = {"count": len(busy_audits)}
        if case["audit_expect"]:
            verify_audit(case["audit_expect"], audit_records(audit_path)[before:],
                         audit_verify(binary, audit_path, env), case.get("audit_optional_prefix"))
            if "kill_served_session_dml_user" in case["call"] and supported:
                records = audit_records(audit_path)[before:]
                row["killed_dml_audit"] = {
                    "records": [{key: record[key] for key in
                                 ("tool", "decision", "outcome", "failure", "cancel") if key in record}
                                for record in records],
                    "mutation_execution_records": sum(record.get("tool") == case["tool"]
                                                      for record in records),
                    "scn_probe_records": sum(record.get("tool") == "scn_capability_probe"
                                             for record in records)}
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
        try:
            if case.get("cleanup"):
                apply_setup(connection, case["cleanup"])
            if case.get("cleanup_reread"):
                cleanup_row = {}
                verify_case_rereads(connection,
                                    {"case_id": case["case_id"], "db_reread": case["cleanup_reread"]},
                                    cleanup_row)
                row["cleanup_reread_actual"] = cleanup_row["db_reread_actual"]
        except Exception as exc:
            row["verdict"] = "fail"
            row["cleanup_failure"] = {"class": type(exc).__name__, "detail": str(exc)[:240]}
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


def map_live_manifest_case_ids(results, release_cases, required_ids):
    case_id_by_test_id = {
        case["test_id"]: case["case_id"]
        for case in release_cases
        if case.get("reproducible") == "live"
    }
    changed = False
    for row in results["cases"]:
        manifest_case_id = case_id_by_test_id.get(row.get("test_id"))
        if manifest_case_id in required_ids and row.get("case_id") == row.get("test_id"):
            row["case_id"] = manifest_case_id
            changed = True
    return changed


def enforce_manifest(results_path, lane, transport, capabilities):
    required = manifest_required(lane, transport, capabilities)
    results = json.loads(results_path.read_text())
    release_cases = json.loads(RELEASE_MANIFEST.read_text())
    if map_live_manifest_case_ids(results, release_cases, required):
        results_path.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
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
    table = collections.defaultdict(lambda: collections.defaultdict(lambda: {"pass": 0, "fail": 0, "skip": 0}))
    for row in rows:
        table[row["tool"]][row["transport"]][row["verdict"]] += 1
    return {tool: dict(transports) for tool, transports in sorted(table.items())}


def verify_awr_skip_evidence(reason):
    code = reason["code"]
    if code == "AWR_PACK_NOT_ENABLED":
        require(reason.get("pack_setting") == "NONE",
                "AWR pack skip needs the actual disabled server setting")
    elif code == "AWR_CATALOG_UNAVAILABLE":
        require(reason.get("catalog") in {"V$PARAMETER", "DBA_HIST_SNAPSHOT", "DBA_HIST_SQLSTAT"}
                and reason.get("external_error", "").startswith(("ORA-00942", "ORA-01031")),
                "AWR catalog skip needs an actual absence/privilege error")
    else:
        require(reason.get("pack_setting") in {"DIAGNOSTIC", "DIAGNOSTIC+TUNING"},
                "AWR history skip needs an enabled server pack setting")
        snapshots = reason.get("snapshot_count")
        history = reason.get("sql_history_count")
        require(type(snapshots) is int and snapshots >= 0,
                "AWR history skip needs an actual snapshot count")
        if code == "AWR_NO_SNAPSHOTS":
            require(snapshots == 0, "AWR no-snapshot skip requires zero real snapshots")
        elif code == "AWR_NO_SQL_HISTORY":
            require(snapshots > 0 and type(history) is int and history == 0,
                    "AWR empty SQL history skip requires snapshots and zero SQL rows")
        elif code == "AWR_TOP_SQL_HAS_NO_PLAN_HISTORY":
            require(snapshots > 0 and type(history) is int and history > 0
                    and re.fullmatch(r"[a-z0-9]{13}", reason.get("sql_id", ""))
                    and type(reason.get("plan_point_count")) is int
                    and reason["plan_point_count"] == 0,
                    "AWR plan-history skip needs an actual top SQL ID and zero matching points")
        else:
            raise DriverError("unknown AWR environment skip")


def probe_awr_environment(connection):
    """Observe prerequisites without enabling packs or creating licensed snapshots."""
    cursor = connection.cursor()
    evidence = {}
    catalog = "V$PARAMETER"
    def absent(code, message):
        reason = {"code": code, "message": message, **evidence}
        verify_awr_skip_evidence(reason)
        raise EnvironmentSkip(reason)
    try:
        row = cursor.execute(
            "SELECT value FROM v$parameter WHERE name = 'control_management_pack_access'").fetchone()
        require(row and row[0] in {"NONE", "DIAGNOSTIC", "DIAGNOSTIC+TUNING"},
                "AWR pack probe did not report a recognized server setting")
        evidence["pack_setting"] = row[0]
        if row[0] == "NONE":
            absent("AWR_PACK_NOT_ENABLED", "server control_management_pack_access=NONE; AWR is not enabled")
        catalog = "DBA_HIST_SNAPSHOT"
        snapshots = cursor.execute("SELECT COUNT(*) FROM DBA_HIST_SNAPSHOT").fetchone()[0]
        require(type(snapshots) is int and snapshots >= 0, "invalid AWR snapshot count")
        evidence["snapshot_count"] = snapshots
        if snapshots == 0:
            absent("AWR_NO_SNAPSHOTS", "DBA_HIST_SNAPSHOT contains 0 rows; the positive AWR case has no captured snapshot interval")
        catalog = "DBA_HIST_SQLSTAT"
        history = cursor.execute("SELECT COUNT(*) FROM DBA_HIST_SQLSTAT").fetchone()[0]
        require(type(history) is int and history >= 0, "invalid AWR SQL history count")
        evidence["sql_history_count"] = history
        if history == 0:
            absent("AWR_NO_SQL_HISTORY", "AWR snapshots exist but DBA_HIST_SQLSTAT contains 0 rows; no historical SQL ID can be captured")
        # Match the positive case's elapsed-time top_sql selection, then its
        # timeline's snapshot join. AWR need not capture every cursor in a plan interval.
        row = cursor.execute(
            "SELECT sql_id FROM (SELECT sql_id, SUM(elapsed_time_delta) AS elapsed_time "
            "FROM DBA_HIST_SQLSTAT GROUP BY sql_id ORDER BY elapsed_time DESC NULLS LAST) "
            "WHERE ROWNUM <= 1").fetchone()
        require(row and isinstance(row[0], str) and re.fullmatch(r"[a-z0-9]{13}", row[0]),
                "AWR top SQL probe did not report a valid SQL ID")
        evidence["sql_id"] = row[0]
        points = cursor.execute(
            "SELECT COUNT(*) FROM DBA_HIST_SQLSTAT s JOIN DBA_HIST_SNAPSHOT sn "
            "ON sn.snap_id = s.snap_id AND sn.dbid = s.dbid "
            "AND sn.instance_number = s.instance_number WHERE s.sql_id = :1", (row[0],)).fetchone()[0]
        require(type(points) is int and points >= 0, "invalid AWR plan-point count")
        evidence["plan_point_count"] = points
        if points == 0:
            absent("AWR_TOP_SQL_HAS_NO_PLAN_HISTORY", "the elapsed-time top AWR SQL ID has 0 matching snapshot intervals; its plan timeline cannot contain a point")
        return evidence
    except EnvironmentSkip:
        raise
    except Exception as exc:
        first = str(exc).splitlines()[0]
        if first.startswith(("ORA-00942", "ORA-01031")):
            evidence.update({"catalog": catalog, "external_error": first})
            absent("AWR_CATALOG_UNAVAILABLE", f"AWR prerequisite catalog {catalog} is unavailable: {first}")
        raise


def environment_skip_row(case, transport, lane, reason):
    require(reason["code"] in case.get("environment_skips", []),
            f"undeclared environment skip for {case['case_id']}")
    if reason["code"] == RETENTION_SOURCE_SKIP:
        require(reason.get("candidates")
                and all(item["external_error"].startswith("ORA-01466")
                        for item in reason["candidates"]),
                "retention source skip requires actual table-definition evidence")
    elif reason["code"] == RETENTION_HISTORY_SKIP:
        candidates = reason.get("candidates", [])
        require(len(candidates) == 5
                and [item.get("multiplier") for item in candidates] == [2, 4, 8, 16, 32]
                and all(item.get("stage") in {"timestamp_to_scn", "flashback_read"}
                        and item.get("external_error", "").startswith(
                            ("ORA-08180", "ORA-08186", "ORA-01466"))
                        for item in candidates)
                and any(item["external_error"].startswith(("ORA-08180", "ORA-08186"))
                        for item in candidates)
                and all(item["stage"] == "flashback_read"
                        or not item["external_error"].startswith("ORA-01466")
                        for item in candidates)
                and "scn_a" not in reason and "scn_b" not in reason,
                "retention history skip requires all five unavailable candidates, never expiry proof")
    else:
        verify_awr_skip_evidence(reason)
    return {"case_id": case["case_id"], "test_id": case.get("test_id", case["case_id"]),
            "tool": case["tool"], "level": case["level"], "lane": lane,
            "transport": transport, "expected": case["expect"], "actual": None,
            "verdict": "skip", "skip_reason": reason, "duration_ms": 0}


def run_verdict(rows):
    failed = [row["case_id"] for row in rows if row["verdict"] not in {"pass", "skip"}]
    for row in rows:
        if row["verdict"] == "skip":
            declaration = next((case for case in load_cases()
                                if case["case_id"] == row["case_id"]), None)
            require(declaration is not None, "skip has no file-backed declaration")
            environment_skip_row(declaration, row["transport"], row["lane"], row["skip_reason"])
    return "fail" if failed else "skip" if any(row["verdict"] == "skip" for row in rows) else "pass"


def ci_summary(results_path, summary_path, output_path):
    results = json.loads(results_path.read_text())
    rows = results["cases"]
    verdict = run_verdict(rows)
    if results.get("run_failure"):
        verdict = "fail"
    require(results.get("verdict") == verdict, "W4 declared verdict disagrees with case results")
    slots = collections.defaultdict(lambda: {"pass": 0, "fail": 0, "skip": 0, "duration_ms": 0})
    for row in rows:
        slot = slots[row["transport"]]
        slot[row["verdict"]] += 1
        slot["duration_ms"] += row.get("duration_ms", 0)
    with summary_path.open("a") as out:
        out.write(f"W4 disposition: {verdict.upper()}\n\n")
        out.write("| Transport | Passed cases | Failed cases | Skipped cases | Duration ms |\n|---|---:|---:|---:|---:|\n")
        for transport, slot in sorted(slots.items()):
            out.write(f"| {transport} | {slot['pass']} | {slot['fail']} | {slot['skip']} | {slot['duration_ms']} |\n")
        for row in rows:
            if row["verdict"] == "skip":
                reason = row["skip_reason"]
                out.write(f"\nSKIP {row['case_id']} ({row['transport']}): {reason['code']}: {reason['message']}\n")
        if results.get("run_failure"):
            out.write(f"\nRun failure: {results['run_failure']['class']}: {results['run_failure']['detail']}\n")
    with output_path.open("a") as out:
        out.write(f"verdict={verdict}\n")
    print(compact({"ci_verdict": verdict, "passed": sum(slot["pass"] for slot in slots.values()),
                   "failed": sum(slot["fail"] for slot in slots.values()),
                   "skipped": sum(slot["skip"] for slot in slots.values())}))
    require(verdict != "fail", "W4 results contain failures")


def select_cases(file_cases, generated_cases, selected):
    """Select file-backed or generated contract cases by their stable case id."""
    available = {case["case_id"] for case in file_cases + generated_cases}
    missing = selected - available
    require(not missing, f"unknown scoped W4 case(s): {', '.join(sorted(missing))}")
    return [case for case in file_cases + generated_cases if case["case_id"] in selected]


def select_requested_cases(file_cases, generated_cases, requested):
    """Resolve --case only after descriptors have generated contract cases."""
    if requested is None:
        return list(file_cases) + list(generated_cases)
    return select_cases(file_cases, generated_cases, set(requested))


def probe_expired_retention_scn(connection):
    """Find a real expired SCN and prove it against the durable W4 registry.

    `V$UNDOSTAT` supplies the lab's current retention observation; the candidate
    is accepted only when an independent system connection reproduces a
    flashback retention error while reading `W4_RIG.W4_RUNS`.  This keeps the
    served oracle_diff case free of invented SCNs and makes the fixture usable
    despite lane-specific SCN rates and undo pressure.
    """
    cursor = connection.cursor()
    retention = cursor.execute("SELECT MAX(TUNED_UNDORETENTION) FROM V$UNDOSTAT").fetchone()[0]
    require(type(retention) is int and retention > 0,
            "V$UNDOSTAT did not report a positive tuned undo retention")
    current_scn = cursor.execute("SELECT CURRENT_SCN FROM V$DATABASE").fetchone()[0]
    require(type(current_scn) is int and current_scn > 0,
            "V$DATABASE did not report a positive current SCN")
    definition_errors = []
    unavailable_candidates = []
    readable_candidates = 0
    for multiplier in (2, 4, 8, 16, 32):
        seconds = retention * multiplier
        try:
            scn = cursor.execute(
                "SELECT TIMESTAMP_TO_SCN(SYSTIMESTAMP - NUMTODSINTERVAL(:1,'SECOND')) FROM DUAL",
                (seconds,)).fetchone()[0]
        except Exception as exc:
            message = str(exc)
            require(any(code in message for code in ("ORA-08180", "ORA-08186")),
                    f"retention SCN timestamp probe failed unexpectedly: {message[:180]}")
            unavailable_candidates.append({"stage": "timestamp_to_scn", "multiplier": multiplier,
                                           "seconds_past": seconds,
                                           "external_error": message.split("\n", 1)[0]})
            continue
        require(type(scn) is int and scn > 0, "retention timestamp probe returned no SCN")
        try:
            cursor.execute("BEGIN DBMS_FLASHBACK.ENABLE_AT_SYSTEM_CHANGE_NUMBER(:1); END;", (scn,))
            cursor.execute("SELECT COUNT(*) FROM W4_RIG.W4_RUNS").fetchone()
        except Exception as exc:
            message = str(exc)
            try:
                cursor.execute("BEGIN DBMS_FLASHBACK.DISABLE; END;")
            except Exception as cleanup:
                raise DriverError("retention probe could not disable flashback") from cleanup
            if any(code in message for code in ("ORA-01466", "ORA-08180", "ORA-08186")):
                candidate = {"stage": "flashback_read", "multiplier": multiplier,
                             "scn": scn, "seconds_past": seconds,
                             "external_error": message.split("\n", 1)[0]}
                unavailable_candidates.append(candidate)
                if "ORA-01466" in message:
                    definition_errors.append(candidate)
                continue
            if "ORA-01555" in message:
                return {"tuned_undo_retention_seconds": retention,
                        "seconds_past": seconds, "multiplier": multiplier,
                        "scn_a": scn, "scn_b": current_scn,
                        "external_error": message.split("\n", 1)[0]}
            raise DriverError(f"retention candidate {scn} failed unexpectedly: {message[:180]}") from exc
        else:
            cursor.execute("BEGIN DBMS_FLASHBACK.DISABLE; END;")
            readable_candidates += 1
    if len(unavailable_candidates) == 5 and len(definition_errors) != 5 and not readable_candidates:
        raise EnvironmentSkip({
            "code": RETENTION_HISTORY_SKIP,
            "message": "No retention-expired candidate is observable: Oracle SCN/snapshot history "
                       "is unavailable (ORA-08180/ORA-08186); these errors do not prove undo expiry",
            "tuned_undo_retention_seconds": retention, "candidates": unavailable_candidates})
    if len(definition_errors) == 5 and not readable_candidates:
        raise EnvironmentSkip({
            "code": RETENTION_SOURCE_SKIP,
            "message": "W4_RIG.W4_RUNS is newer than every SCN tested beyond tuned undo retention "
                       "(ORA-01466); no honest expired-SCN candidate exists on this database",
            "tuned_undo_retention_seconds": retention, "candidates": definition_errors})
    raise DriverError("lab retained every SCN tested beyond its reported undo retention")


def persist_run_results(base, output):
    base.mkdir(parents=True, exist_ok=True)
    (base / "results.json").write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    (base / "cases.jsonl").write_text("".join(compact(row) + "\n" for row in output["cases"]))


def run_lane(args):
    base = ROOT / "target/e2e/w4" / args.lane
    output = {"lane": args.lane, "verdict": "fail", "checkout_sha": subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "binary_source_sha": args.binary_source_sha, "binary_sha256": None,
        "fixture_runs": {}, "capabilities": [], "registry": [], "cases": [], "summary": {},
        "cargo_test_logs": [str(path) for path in args.cargo_test_log],
        "run_failure": {"class": "DriverError", "detail": "W4 run did not complete"}}
    persist_run_results(base, output)
    try:
        _run_lane(args, output)
    except BaseException as exc:
        output["verdict"] = "fail"
        output["summary"] = summary_table(output["cases"])
        output["run_failure"] = {"class": type(exc).__name__, "detail": str(exc)[:240]}
        persist_run_results(base, output)
        raise


def _run_lane(args, output):
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
    release_ids = {case["case_id"]: case["test_id"] for case in json.loads(
        (ROOT / "scripts/e2e/cases/release_0_12.json").read_text())}
    for case in family_cases:
        if case["case_id"] in release_ids:
            case["test_id"] = release_ids[case["case_id"]]
    rows, descriptors, fixture_runs, selected_case_ids = [], None, {}, set()
    output.update({"checkout_sha": checkout_sha,
                   "binary_source_sha": args.binary_source_sha or (checkout_sha if built_here else None),
                   "binary_sha256": binary_sha256, "fixture_runs": fixture_runs,
                   "capabilities": sorted(capabilities), "cases": rows})
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
                needs_retention_probe = any(
                    case.get("runtime_retention_probe")
                    and (not args.case or case["case_id"] in args.case)
                    and transport in case["transports"]
                    for case in family_cases)
                retention_skip = None
                try:
                    retention_probe = (probe_expired_retention_scn(connection)
                                       if needs_retention_probe else None)
                except EnvironmentSkip as exc:
                    retention_probe = None
                    retention_skip = exc.reason
                awr_skip = None
                if any(case.get("runtime_awr_probe")
                       and (not args.case or case["case_id"] in args.case)
                       and transport in case["transports"] for case in family_cases):
                    try:
                        probe_awr_environment(connection)
                    except EnvironmentSkip as exc:
                        awr_skip = exc.reason
                client_env = {**env, "XDG_STATE_HOME": str(state)}
                expanded_family = ([] if args.contract_only else [
                    freshen_vsql_marker(expand_case(case, fixture_id, transport, args.lane)) for case in family_cases
                    if transport in case["transports"]])
                if retention_probe is not None:
                    for case in expanded_family:
                        if case.get("runtime_retention_probe"):
                            arguments = case["call"]["arguments"]
                            arguments["scn_a"] = retention_probe["scn_a"]
                            arguments["scn_b"] = retention_probe["scn_b"]
                            case["retention_probe"] = retention_probe
                for case in expanded_family:
                    if (case.get("setup_phase") == "before_server"
                            and (not args.case or case["case_id"] in args.case)
                            and set(case["requires"]) <= capabilities):
                        apply_setup(connection, case["setup"])
                        if "setup_ready_sql" in case:
                            wait_for_setup_ready(settings, password, case["setup_ready_sql"])
                needs_streaming = any(
                    "progress_token" in case.get("call", {})
                    and (not args.case or case["case_id"] in args.case)
                    for case in expanded_family)
                client = (StdioClient(binary, args.lane, client_env) if transport == "stdio"
                          else HttpClient(binary, args.lane, client_env, port, secret, audience,
                                          streaming=needs_streaming))
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
                generated_cases = list(generic_contract_cases(
                    discovered, args.lane, contract_baselines(expanded_family)))
                available_here = {case["case_id"] for case in expanded_family + generated_cases}
                requested_here = set(args.case or ()) & available_here
                selected_case_ids.update(requested_here)
                cases = select_requested_cases(expanded_family, generated_cases,
                                               requested_here if args.case else None)
                current_level = "READ_ONLY"
                current_profile = args.lane
                for case in cases:
                    if case.get("runtime_awr_probe") and awr_skip is not None:
                        rows.append(environment_skip_row(case, transport, args.lane, awr_skip))
                        continue
                    if case.get("runtime_retention_probe") and retention_skip is not None:
                        rows.append(environment_skip_row(case, transport, args.lane, retention_skip))
                        continue
                    variant = case.get("profile_variant")
                    desired_profile = (args.lane + "_raw" if variant == "synthetic_raw"
                                       else args.lane + "_licensed" if variant == "synthetic_licensed"
                                       else args.lane + "_owner" if variant == "synthetic_owner"
                                       else args.lane + "_owner_rw" if variant == "synthetic_owner_rw"
                                       else args.lane + "_cross_rw" if variant == "synthetic_cross_rw"
                                       else args.lane + "_cross_rw_strict" if variant == "synthetic_cross_rw_strict"
                                       else args.lane + "_cross_security" if variant == "synthetic_cross_security"
                                       else args.lane + "_cross_security_strict" if variant == "synthetic_cross_security_strict"
                                       else args.lane + "_trusted_views" if variant == "trusted_views"
                                       else args.lane + "_protected" if variant == "protected"
                                       else args.lane + "_capped" if variant == "capped_rw"
                                       else args.lane + "_short_admin" if variant == "short_admin"
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
                    with case_flashback_grant(case, args.lane, settings,
                                             "W4O_" + fixture_id if fixture_id else None):
                        row = run_case(client, case, transport, args.lane, capabilities, connection,
                                       barriers, binary, audit_path, client_env,
                                       discovered.get(case["tool"]))
                    if case.get("flashback_grant_owner"):
                        row["flashback_grant"] = {"scope": "case", "revoked": True}
                    rows.append(row)
                    cancelled_mutation = case["call"].get("cancel_mutation_audit") is True
                    if "kill_served_session_dml_user" in case["call"] or cancelled_mutation:
                        # A killed session, and every cancelled mutation whose wire outcome
                        # dispatch quarantined, cannot service the normal level drop. Restart
                        # at the lane's READ_ONLY baseline before another selected W4 case.
                        client.close()
                        client = (StdioClient(binary, args.lane, client_env) if transport == "stdio"
                                  else HttpClient(binary, args.lane, client_env, port, secret, audience,
                                                  streaming=needs_streaming))
                        initialize(client)
                        current_profile = args.lane
                        current_level = "READ_ONLY"
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
        if args.case:
            missing = set(args.case) - selected_case_ids
            require(not missing, f"unknown scoped W4 case(s): {', '.join(sorted(missing))}")
        verdict = run_verdict(rows)
        output.update({"verdict": verdict, "registry": sorted(descriptors),
                       "summary": summary_table(rows)})
        output.pop("run_failure", None)
        results_path = base / "results.json"
        persist_run_results(base, output)
        failed = [row["case_id"] for row in rows if row["verdict"] not in {"pass", "skip"}]
        require(verdict != "fail", f"red W4 cases: {', '.join(failed[:12])} ({len(failed)} total)")
        if args.coverage_report:
            (base / "coverage.json").write_text(json.dumps(
                coverage_status(descriptors, family_cases), indent=2, sort_keys=True) + "\n")
        if not args.contract_only and not args.case:
            for transport in ("stdio", "http"):
                enforce_manifest(results_path, args.lane, transport, capabilities)
        if (not args.contract_only and not args.case) or args.coverage_report:
            verify_coverage(descriptors, family_cases)
        print(compact({"lane": args.lane, "registry_count": len(descriptors),
                       "cases": len(rows), "verdict": verdict, "results": str(results_path)}))
    finally:
        connection.close()


def retention_probe_selftest():
    class RetentionProbeConnection:
        """Unit-only cursor covering timestamp history errors, not live proof."""
        def __init__(self, timestamp_error):
            self.timestamp_error = timestamp_error
            self.timestamp_seconds = []

        def cursor(self):
            return self

        def execute(self, sql, binds=()):
            if "MAX(TUNED_UNDORETENTION)" in sql:
                self.row = (100,)
            elif "CURRENT_SCN FROM V$DATABASE" in sql:
                self.row = (10000,)
            elif "TIMESTAMP_TO_SCN" in sql:
                self.timestamp_seconds.append(binds[0])
                if len(self.timestamp_seconds) == 1:
                    raise RuntimeError(self.timestamp_error)
                self.row = (9000,)
            elif "SELECT COUNT(*) FROM W4_RIG.W4_RUNS" in sql:
                raise RuntimeError("ORA-01555: snapshot too old")
            else:
                require(sql.startswith("BEGIN DBMS_FLASHBACK."),
                        f"unexpected retention selftest SQL: {sql}")
            return self

        def fetchone(self):
            return self.row

    for code in ("ORA-08180", "ORA-08186"):
        connection = RetentionProbeConnection(code)
        result = probe_expired_retention_scn(connection)
        require(connection.timestamp_seconds == [200, 400],
                f"{code} did not continue to the next retention multiplier")
        require(result["multiplier"] == 4 and result["seconds_past"] == 400
                and result["scn_a"] == 9000 and result["scn_b"] == 10000
                and result["external_error"].startswith("ORA-01555"),
                f"{code} produced incorrect retention evidence: {result}")
        print(compact({"selftest": f"retention_timestamp_{code}_continues",
                       "verdict": "pass"}))
    connection = RetentionProbeConnection("ORA-00942: table or view does not exist")
    try:
        probe_expired_retention_scn(connection)
    except DriverError as exc:
        require("ORA-00942" in str(exc) and connection.timestamp_seconds == [200],
                "unexpected timestamp error was not rejected at its first multiplier")
    else:
        raise DriverError("retention timestamp probe accepted an unexpected error")
    print(compact({"selftest": "retention_timestamp_unexpected_error_refused",
                   "verdict": "pass"}))

    class FlashbackConnection(RetentionProbeConnection):
        def __init__(self, errors):
            super().__init__(None)
            self.errors = iter(errors)
            self.disabled = 0

        def execute(self, sql, binds=()):
            if "TIMESTAMP_TO_SCN" in sql:
                self.timestamp_seconds.append(binds[0])
                self.row = (9000 - len(self.timestamp_seconds),)
                return self
            if "SELECT COUNT(*) FROM W4_RIG.W4_RUNS" in sql:
                error = next(self.errors)
                if error:
                    raise RuntimeError(error)
                self.row = (0,)
                return self
            if "DBMS_FLASHBACK.DISABLE" in sql:
                self.disabled += 1
            return super().execute(sql, binds)

    definition_error = "ORA-01466: unable to read data - table definition has changed"
    connection = FlashbackConnection([definition_error] * 5)
    try:
        probe_expired_retention_scn(connection)
    except EnvironmentSkip as exc:
        reason = exc.reason
        require(reason["code"] == RETENTION_SOURCE_SKIP and len(reason["candidates"]) == 5
                and connection.disabled == 5 and "scn_a" not in reason,
                "table definition errors were promoted into retention proof")
    else:
        raise DriverError("ORA-01466 incorrectly produced retention proof")
    case = next(case for case in load_cases() if case.get("runtime_retention_probe"))
    row = environment_skip_row(case, "stdio", "free23", reason)
    require(row["actual"] is None and row["verdict"] == "skip"
            and run_verdict([row]) == "skip"
            and summary_table([row])["oracle_diff"]["stdio"] == {"pass": 0, "fail": 0, "skip": 1},
            "declared environment skip was counted as a pass")
    require(run_verdict([row, {"case_id": "planted", "verdict": "fail"}]) == "fail",
            "a declared skip must never hide a failed case")
    directory = ROOT / "target/e2e/w4/selftest"
    directory.mkdir(parents=True, exist_ok=True)
    results_path = directory / "retention-skip-results.json"
    summary_path = directory / "retention-skip-summary.md"
    output_path = directory / "retention-skip-output.txt"
    results_path.write_text(compact({"verdict": "skip", "cases": [row]}))
    summary_path.write_text("")
    output_path.write_text("")
    ci_summary(results_path, summary_path, output_path)
    require(output_path.read_text() == "verdict=skip\n"
            and "SKIP" in summary_path.read_text() and "| stdio | 0 | 0 | 1 |" in summary_path.read_text(),
            "CI did not declare skipped disposition and separate skip count")
    for label, operation in (
            ("undeclared_skip", lambda: environment_skip_row(
                {**case, "environment_skips": []}, "stdio", "free23", reason)),
            ("wrong_skip_evidence", lambda: environment_skip_row(
                case, "stdio", "free23", {**reason, "candidates": [{"external_error": "ORA-01555"}]})),
            ("skip_cannot_claim_pass", lambda: ci_summary(
                results_path, summary_path, output_path))):
        if label == "skip_cannot_claim_pass":
            results_path.write_text(compact({"verdict": "pass", "cases": [row]}))
        try:
            operation()
        except DriverError:
            pass
        else:
            raise DriverError(f"retention selftest accepted {label}")
    require(probe_expired_retention_scn(FlashbackConnection(
        [definition_error, "ORA-01555: snapshot too old"]))["external_error"].startswith("ORA-01555"),
        "a later genuine retention error did not win over a definition error")
    for errors in ([None] * 5, [definition_error, None, None, None, None],
                   ["ORA-00942: table or view does not exist"]):
        try:
            probe_expired_retention_scn(FlashbackConnection(errors))
        except EnvironmentSkip:
            raise DriverError("readable or unexpectedly failing source was incorrectly skipped")
        except DriverError:
            pass
        else:
            raise DriverError("non-expired or unexpectedly failing source produced retention proof")
    print(compact({"selftest": "retention_definition_age_declared_skip_and_negatives", "verdict": "pass"}))

    class MissingTimestampHistory(RetentionProbeConnection):
        def execute(self, sql, binds=()):
            if "TIMESTAMP_TO_SCN" in sql:
                self.timestamp_seconds.append(binds[0])
                raise RuntimeError(self.timestamp_error)
            return super().execute(sql, binds)

    for code in ("ORA-08180", "ORA-08186"):
        for connection in (MissingTimestampHistory(code), FlashbackConnection([code] * 5)):
            try:
                probe_expired_retention_scn(connection)
            except EnvironmentSkip as exc:
                history_reason = exc.reason
            else:
                raise DriverError(f"{code} missing history became retention proof")
            require(history_reason["code"] == RETENTION_HISTORY_SKIP
                    and connection.timestamp_seconds == [200, 400, 800, 1600, 3200],
                    "missing history did not exhaust all multipliers")
            history_row = environment_skip_row(case, "stdio", "free23", history_reason)
            require(history_row["actual"] is None and run_verdict([history_row]) == "skip",
                    "history skip was promoted to a pass")
            # The following case remains present; skip does not short-circuit the lane.
            following = {"case_id": "rel012_i28_order_alias", "verdict": "pass"}
            require(run_verdict([history_row, following]) == "skip",
                    "retention skip prevented later lane results")
            summary_path.write_text("")
            output_path.write_text("")
            following["transport"] = "stdio"
            results_path.write_text(compact({"verdict": "skip", "cases": [history_row, following]}))
            ci_summary(results_path, summary_path, output_path)
            require("| stdio | 1 | 0 | 1 |" in summary_path.read_text(),
                    "CI lost the following case or counted history skip as pass")
            for invalid in ({**history_reason, "candidates": history_reason["candidates"][:4]},
                            {**history_reason, "scn_a": 9000},
                            {**history_reason, "candidates": [
                                {**item, "external_error": "ORA-01555"}
                                for item in history_reason["candidates"]]}):
                try:
                    environment_skip_row(case, "stdio", "free23", invalid)
                except DriverError:
                    pass
                else:
                    raise DriverError("invalid history evidence was accepted")
        require(probe_expired_retention_scn(FlashbackConnection(
            [code, "ORA-01555: snapshot too old"]))["external_error"].startswith("ORA-01555"),
            "unavailable snapshot prevented a later genuine retention proof")
        print(compact({"selftest": f"retention_{code}_history_skip_not_proof", "verdict": "pass"}))
    mixed = FlashbackConnection([definition_error, "ORA-08180", definition_error,
                                "ORA-08186", definition_error])
    try:
        probe_expired_retention_scn(mixed)
    except EnvironmentSkip as exc:
        require(exc.reason["code"] == RETENTION_HISTORY_SKIP and mixed.disabled == 5,
                "mixed unavailable candidates lost their history evidence or cleanup")
        environment_skip_row(case, "stdio", "free23", exc.reason)
    else:
        raise DriverError("mixed unavailable candidates produced proof")
    for errors in (["ORA-08180", None, None, None, None], ["ORA-08180", "ORA-00942"]):
        try:
            probe_expired_retention_scn(FlashbackConnection(errors))
        except EnvironmentSkip:
            raise DriverError("history skip hid a readable or unexpected candidate")
        except DriverError:
            pass
        else:
            raise DriverError("history errors produced false retention proof")
    class DisableFails(FlashbackConnection):
        def execute(self, sql, binds=()):
            if "DBMS_FLASHBACK.DISABLE" in sql:
                raise RuntimeError("ORA-03113")
            return super().execute(sql, binds)
    try:
        probe_expired_retention_scn(DisableFails(["ORA-08180"]))
    except EnvironmentSkip:
        raise DriverError("history skip hid failed flashback cleanup")
    except DriverError as exc:
        require("could not disable flashback" in str(exc), "cleanup failure lost its cause")
    else:
        raise DriverError("failed flashback disable was accepted")



def awr_environment_selftest():
    class AwrConnection:
        """Unit-only catalog responses; real Oracle is proved separately."""
        def __init__(self, setting="DIAGNOSTIC+TUNING", snapshots=2, history=3, points=1, error=None):
            self.setting, self.snapshots, self.history, self.points = setting, snapshots, history, points
            self.error = error
            self.queries = []
        def cursor(self):
            return self
        def execute(self, sql, binds=()):
            self.queries.append(sql)
            if self.error:
                raise DriverError(self.error)
            if "v$parameter" in sql:
                self.row = (self.setting,)
            elif sql == "SELECT COUNT(*) FROM DBA_HIST_SNAPSHOT":
                self.row = (self.snapshots,)
            elif sql == "SELECT COUNT(*) FROM DBA_HIST_SQLSTAT":
                self.row = (self.history,)
            elif sql.startswith("SELECT sql_id FROM"):
                self.row = ("123456789abcd",)
            else:
                self.row = (self.points,)
            return self
        def fetchone(self):
            return self.row
    case = next(case for case in load_cases() if case.get("runtime_awr_probe"))
    for code, connection in (
            ("AWR_PACK_NOT_ENABLED", AwrConnection(setting="NONE")),
            ("AWR_NO_SNAPSHOTS", AwrConnection(snapshots=0)),
            ("AWR_NO_SQL_HISTORY", AwrConnection(history=0)),
            ("AWR_TOP_SQL_HAS_NO_PLAN_HISTORY", AwrConnection(points=0)),
            ("AWR_CATALOG_UNAVAILABLE", AwrConnection(error="ORA-00942: table or view does not exist"))):
        try:
            probe_awr_environment(connection)
        except EnvironmentSkip as exc:
            require(exc.reason["code"] == code, "wrong typed AWR environment reason")
            row = environment_skip_row(case, "stdio", "free23", exc.reason)
            require(row["verdict"] == "skip" and row["actual"] is None
                    and run_verdict([row]) == "skip", "AWR absence was counted as a positive pass")
            require(run_verdict([row, {"case_id": "planted", "verdict": "fail"}]) == "fail",
                    "AWR skip masked a failed case")
            try:
                environment_skip_row({**case, "environment_skips": []}, "stdio", "free23", exc.reason)
            except DriverError:
                pass
            else:
                raise DriverError("undeclared AWR skip accepted")
        else:
            raise DriverError("AWR absence was reported as available")
        if code == "AWR_PACK_NOT_ENABLED":
            require(len(connection.queries) == 1, "disabled pack caused an AWR history read")
        require(not any("DBMS_WORKLOAD_REPOSITORY" in q for q in connection.queries),
                "AWR probe created an unapproved snapshot")
    available = probe_awr_environment(AwrConnection())
    require(available["snapshot_count"] == 2 and available["plan_point_count"] == 1,
            "real available history must retain the positive case")
    for error in ("ORA-03113: end-of-file on communication channel", "ORA-00600: internal error"):
        try:
            probe_awr_environment(AwrConnection(error=error))
        except EnvironmentSkip:
            raise DriverError("unexpected AWR failure was hidden as an environment skip")
        except DriverError:
            pass
        else:
            raise DriverError("unexpected AWR failure accepted")
    for reason in (
            {"code": "AWR_NO_SNAPSHOTS", "pack_setting": "DIAGNOSTIC", "snapshot_count": 1},
            {"code": "AWR_PACK_NOT_ENABLED", "pack_setting": "DIAGNOSTIC"},
            {"code": "AWR_CATALOG_UNAVAILABLE", "catalog": "DBA_HIST_SNAPSHOT", "external_error": "ORA-03113"}):
        try:
            verify_awr_skip_evidence(reason)
        except DriverError:
            pass
        else:
            raise DriverError("AWR skip accepted contradictory evidence")
    print(compact({"selftest": "awr_declared_environment_skips_preserve_positive_and_failures", "verdict": "pass"}))


def failed_results_selftest():
    global ROOT, _run_lane
    original_root, original_runner = ROOT, _run_lane
    ROOT = ROOT / "target/e2e/w4/selftest/red-results-source"
    ROOT.mkdir(parents=True, exist_ok=True)
    base = ROOT / "target/e2e/w4/free23"
    args = argparse.Namespace(lane="free23", binary_source_sha=None, cargo_test_log=[])
    try:
        for stage in ("startup", "case", "cleanup", "interrupt"):
            persist_run_results(base, {"verdict": "pass", "cases": [{"case_id": "old", "verdict": "pass"}]})
            def fail_runner(args, output):
                primed = json.loads((base / "results.json").read_text())
                require(primed["verdict"] == "fail" and primed["cases"] == []
                        and primed["checkout_sha"], "run did not invalidate stale pass before startup")
                if stage != "startup":
                    output["capabilities"] = ["version:23"]
                    output["cases"].append({"case_id": "current", "tool": "oracle_query", "lane": "free23",
                                            "transport": "stdio", "verdict": "fail"})
                if stage == "interrupt":
                    raise KeyboardInterrupt()
                raise DriverError("planted " + stage + " failure")
            _run_lane = fail_runner
            try:
                run_lane(args)
            except (DriverError, KeyboardInterrupt):
                pass
            else:
                raise DriverError("failed run returned success")
            current = json.loads((base / "results.json").read_text())
            require(current["verdict"] == "fail" and current["checkout_sha"]
                    and "run_failure" in current and not any(r["case_id"] == "old" for r in current["cases"]),
                    "current failure did not replace stale passing results")
            require((stage == "startup" and current["cases"] == [])
                    or (stage != "startup" and current["cases"][0]["case_id"] == "current"),
                    "failed results lost completed case evidence")
        summary, output_file = base / "summary.md", base / "output.txt"
        summary.write_text(""); output_file.write_text("")
        try:
            ci_summary(base / "results.json", summary, output_file)
        except DriverError:
            pass
        else:
            raise DriverError("CI accepted failed results")
        require(output_file.read_text() == "verdict=fail\n" and "FAIL" in summary.read_text()
                and "| stdio | 0 | 1 | 0 |" in summary.read_text(),
                "CI did not record an honest failed disposition and failed count")
    finally:
        ROOT, _run_lane = original_root, original_runner
    print(compact({"selftest": "current_failed_results_persist_before_nonzero_exit", "verdict": "pass"}))


def killed_dml_audit_selftest():
    """Unit audit transcripts, not a substitute for live killed-session proof."""
    case = next(case for case in load_cases()
                if case["case_id"] == "w4_runtime_issue47_killed_session_dml_not_replayed")
    expected, prefix = case["audit_expect"], case["audit_optional_prefix"]
    probe = prefix["record"]
    cold = [probe, *expected]
    verify_audit(expected, cold, True, prefix)
    verify_audit(expected, expected, True, prefix)
    planted = {
        "duplicate_probe": [probe, probe, *expected],
        "wrong_probe_reason": [{**probe, "failure": {"error_class": "CONNECTION_FAILED"}}, *expected],
        "wrong_probe_outcome": [{**probe, "outcome": "SUCCEEDED"}, *expected],
        "late_probe": [expected[0], probe, *expected[1:]],
        "missing_query_pending": [probe, *expected[1:]],
        "missing_query_success": [probe, expected[0], expected[2]],
        "missing_quarantine_terminal": cold[:-1],
        "wrong_quarantine_terminal": [probe, *expected[:2], {**expected[2], "outcome": "ROLLED_BACK"}],
        "duplicate_baseline_execution": [probe, expected[0], expected[1], expected[1], expected[2]],
        "unexpected_mutation_pending": [*cold, {"tool": "oracle_execute", "decision": "ALLOWED", "outcome": "PENDING"}],
        "unexpected_mutation_success": [*cold, {"tool": "oracle_execute", "decision": "ALLOWED", "outcome": "SUCCEEDED"}],
        "unknown_extra_audit": [*cold, {"tool": "unexpected", "decision": "ALLOWED", "outcome": "FAILED"}],
    }
    for label, records in planted.items():
        try:
            verify_audit(expected, records, True, prefix)
        except DriverError:
            pass
        else:
            raise DriverError(f"killed-DML audit accepted planted {label}")
    for change in ({"max_count": 2}, {"reason": ""},
                   {"record": {**probe, "tool": "oracle_execute"}}):
        try:
            validate_case({**case, "audit_optional_prefix": {**prefix, **change}}, "selftest")
        except DriverError:
            pass
        else:
            raise DriverError("killed-DML audit accepted a broadened prefix declaration")
    try:
        verify_audit(expected, cold, False, prefix)
    except DriverError:
        pass
    else:
        raise DriverError("killed-DML audit accepted an unverified chain")
    print(compact({"selftest": "killed_dml_exact_audits_bounded_scn_probe_and_no_replay", "verdict": "pass"}))


def flashback_grant_selftest():
    positive = {"flashback_grant_owner": True}
    owner = "W4O_W41234ABCDEF"
    for outcome in ("pass", "failed_row", "exception", "interrupt", "grant_failure"):
        events = []
        def change_grant(lane, settings, name, granted):
            require(lane == "free23" and settings == {} and name == owner,
                    "case grant targeted the wrong principal")
            events.append("grant" if granted else "revoke")
            if granted and outcome == "grant_failure":
                raise DriverError("grant failed after sending DDL")
        try:
            with case_flashback_grant(positive, "free23", {}, owner, change_grant):
                require(events == ["grant"], "case must start after its grant")
                events.append("case_setup")
                if outcome == "exception":
                    raise DriverError("case setup/execution failed")
                if outcome == "interrupt":
                    raise KeyboardInterrupt()
                events.append(outcome)
        except (DriverError, KeyboardInterrupt):
            require(outcome in {"exception", "interrupt", "grant_failure"},
                    "unexpected case-scope failure")
        else:
            require(outcome in {"pass", "failed_row"}, "case exception was swallowed")
        expected = (["grant", "revoke"] if outcome == "grant_failure" else
                    ["grant", "case_setup", "revoke"] if outcome in {"exception", "interrupt"} else
                    ["grant", "case_setup", outcome, "revoke"])
        require(events == expected, "case did not revoke its grant on every exit path")
    events = []
    def revoke_fails(lane, settings, name, granted):
        events.append("grant" if granted else "revoke")
        if not granted:
            raise DriverError("revoke failed")
    try:
        with case_flashback_grant(positive, "free23", {}, owner, revoke_fails):
            events.append("case")
        events.append("next_case")
    except DriverError:
        pass
    require(events == ["grant", "case", "revoke"],
            "a revoke failure must stop the lane before the next case")
    events = []
    with case_flashback_grant({}, "free23", {}, owner,
                              lambda *args: events.append("unexpected privilege change")):
        events.append("no_grant_case")
    require(events == ["no_grant_case"], "negative cases must never change the grant")
    print(compact({"selftest": "flashback_grant_case_scope_all_exit_paths", "verdict": "pass"}))


def selftest():
    retention_probe_selftest()
    flashback_grant_selftest()
    awr_environment_selftest()
    failed_results_selftest()
    killed_dml_audit_selftest()
    load_cases()
    expected_live_ids = {
        "w4_get_source_argument_class": "rel012_i38_argument_class",
        "w4_sample_rows_generated_refusal": "rel012_i42_generated_refusal",
        "w4_query_audit_failure_cause": "rel012_i45_audit_failure_cause",
    }
    mapped_results = {"cases": [
        {"case_id": test_id, "test_id": test_id, "lane": "free23",
         "transport": "stdio", "verdict": "pass"}
        for test_id in expected_live_ids
    ]}
    mapped = map_live_manifest_case_ids(mapped_results, json.loads(RELEASE_MANIFEST.read_text()),
                                        set(expected_live_ids.values()))
    require(mapped and {row["case_id"] for row in mapped_results["cases"]}
            == set(expected_live_ids.values()),
            "live manifest test_ids were not normalized to their release case_ids")
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
    hard_parse_record = {
        "tool": "hard_parse_evidence_unavailable[served_tool=oracle_query;observation=hard_parse_evidence_no_privilege]",
        "danger_level": "READ_ONLY", "decision": "ALLOWED", "outcome": "SUCCEEDED",
    }
    require(audit_record_matches([hard_parse_record], hard_parse_record),
            "exact audit fields did not match the readable record")
    changed_observation = {**hard_parse_record,
                           "tool": hard_parse_record["tool"].replace(
                               "hard_parse_evidence_no_privilege", "different_observation")}
    require(not audit_record_matches([hard_parse_record], changed_observation),
            "audit matcher accepted a different observation code")
    scoped_records = audit_records_since([hard_parse_record, {"tool": "oracle_query"}], 1)
    require(not audit_record_matches(scoped_records, hard_parse_record),
            "an earlier audit record satisfied a later step's assertion")
    print(compact({"selftest": "audit_record_exact_observation", "verdict": "pass"}))
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
    selected_enum = select_requested_cases(
        [{"case_id": "w4_file_case"}], enum_cases,
        [alias_enum["case_id"]])
    require(selected_enum == [alias_enum],
            "--case must select a generated enum contract case after descriptor discovery")
    # A requested stdio-only file case is absent from HTTP's local family, but
    # remains selected for the whole run after its stdio pass succeeds.
    stdio_only = {"case_id": "w4_stdio_only", "transports": ["stdio"]}
    selected_case_ids = set()
    for file_cases in ([stdio_only], []):
        requested_here = {"w4_stdio_only"} & {case["case_id"] for case in file_cases}
        selected_case_ids.update(requested_here)
        select_requested_cases(file_cases, [], requested_here)
    require(selected_case_ids == {"w4_stdio_only"},
            "--case selection lost a stdio-only case during the HTTP pass")
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
    marker_rows = {"result": {"content": [], "isError": False,
                   "structuredContent": {"rows": [{"SQL_TEXT": "SELECT /* W4MARK */ 1 FROM DUAL"}]}}}
    verify_row_contains(marker_rows, {"SQL_TEXT": "W4MARK"})
    finding_rows = {"result": {"content": [], "isError": False,
                    "structuredContent": {"findings": [
                        {"detail": {"rows": [{"OWNER": "W4O", "OBJECT_TYPE": "PROCEDURE",
                                                "SAMPLE_OBJECTS": "P_BAD_W4MARK"}]}}]}}}
    verify_finding_row_contains(finding_rows,
                                {"OWNER": "W4O", "OBJECT_TYPE": "PROCEDURE",
                                 "SAMPLE_OBJECTS": "P_BAD_W4MARK"})
    def rejected(label, operation):
        try:
            operation()
        except DriverError:
            print(compact({"selftest": label, "verdict": "rejected"}))
        else:
            raise DriverError(f"selftest accepted planted {label}")
    rejected("invalid_vsql_marker", lambda: validate_case(rejected_marker, "selftest"))
    rejected("foreign_killed_session_target", lambda: validate_case(
        {**rejected_marker,
         "tool": "oracle_query",
         "transports": ["stdio"],
         "call": {"arguments": {"sql": "SELECT 1 FROM dual"},
                  "kill_served_session_user": "SYSTEM"}}, "selftest"))
    rejected("foreign_killed_session_dml_target", lambda: validate_case(
        {**rejected_marker,
         "tool": "oracle_execute",
         "level": "READ_WRITE",
         "transports": ["stdio"],
         "call": {"arguments": {"sql": "UPDATE T SET X = 1"}, "mutation": True,
                  "kill_served_session_dml_user": "SYSTEM"}}, "selftest"))
    rejected("wrong_row_order", lambda: verify_expect({"rows": [[2], [1]]}, correct))
    rejected("row_contains_marker_absent",
             lambda: verify_row_contains(marker_rows, {"SQL_TEXT": "OTHER_MARKER"}))
    rejected("finding_row_contains_marker_absent",
             lambda: verify_finding_row_contains(
                 finding_rows, {"SAMPLE_OBJECTS": "P_BAD_OTHER_MARKER"}))
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
    mutation_step_audit = {"case_id": "w4_selftest_mutation_step_audit", "tool": "oracle_diff",
                           "level": "READ_WRITE", "transports": ["stdio"], "requires": [], "setup": [],
                           "steps": [{"audit_record": {"tool": "oracle_execute",
                                                        "decision": "ALLOWED",
                                                        "outcome": "SUCCEEDED"}}],
                           "call": {"arguments": {}, "mutation": True},
                           "expect": {"error_class": "INVALID_ARGUMENTS"},
                           "on_unsupported": {"error_class": "INVALID_ARGUMENTS"},
                           "db_reread": [{"sql": "SELECT 1 FROM dual", "rows": [[1]]}],
                           "audit_expect": []}
    validate_case(mutation_step_audit, "selftest")
    print(compact({"selftest": "mutation_step_audit_is_accepted", "verdict": "pass"}))
    rejected("mutation_without_any_audit", lambda: validate_case(
        {**mutation_step_audit, "steps": []}, "selftest"))
    stub = StubClient()
    unsupported_row = run_case(stub, unsupported, "stdio", "xe18", set(), object(),
                               BarrierPool(), Path("unused"), Path("unused"), {})
    require(stub.calls == 1 and unsupported_row["verdict"] == "pass",
            "unsupported case silently skipped instead of asserting typed refusal")
    print(compact({"selftest": "unsupported_not_skipped", "verdict": "pass"}))
    class CleanupConnection:
        def __init__(self, restore=True):
            self.label = "w4-commit-race"
            self.commits = 0
            self.restore = restore

        def cursor(self):
            return self

        def execute(self, sql):
            if sql.startswith("UPDATE") and self.restore:
                self.label = "parent-2"
            return self

        def fetchall(self):
            return [(2, self.label)]

        def commit(self):
            self.commits += 1

    cleanup_case = {**unsupported, "requires": [],
                    "cleanup": [{"sql": "UPDATE W4O_W41234ABCDEF.T_PARENT_W41234ABCDEF SET LABEL = 'parent-2' WHERE ID = 2"}],
                    "cleanup_reread": [{"sql": "SELECT ID, LABEL FROM W4O_W41234ABCDEF.T_PARENT_W41234ABCDEF WHERE ID = 2",
                                        "rows": [[2, "parent-2"]]}]}
    for expected, verdict in (({"error_class": "INVALID_ARGUMENTS"}, "pass"),
                              ({"rows": [[1]]}, "fail")):
        cleanup_connection = CleanupConnection()
        cleanup_row = run_case(StubClient(), {**cleanup_case, "expect": expected}, "stdio", "free23",
                               set(), cleanup_connection, BarrierPool(), Path("unused"), Path("unused"), {})
        require(cleanup_row["verdict"] == verdict and cleanup_connection.commits == 1
                and cleanup_row.get("cleanup_reread_actual") == [[[2, "parent-2"]]],
                "case cleanup must restore and independently reread state even after verification fails")
    cleanup_row = run_case(StubClient(), {**cleanup_case, "expect": {"error_class": "INVALID_ARGUMENTS"}},
                           "stdio", "free23", set(), CleanupConnection(restore=False), BarrierPool(),
                           Path("unused"), Path("unused"), {})
    require(cleanup_row["verdict"] == "fail" and "cleanup_failure" in cleanup_row,
            "cleanup reread must fail a case that leaves its committed row behind")
    print(compact({"selftest": "commit_race_cleanup_on_success_and_failure", "verdict": "pass"}))
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
    rejected("cancel_barrier_without_marked_call", lambda: validate_case(
        {**replay_case, "call": {"arguments": {}, "cancel_barrier": "W4PIPE_SELFTEST"}},
        "selftest"))
    rejected("cancel_audit_without_marked_call", lambda: validate_case(
        {**replay_case, "call": {"arguments": {}, "cancel_audit": True}},
        "selftest"))
    rejected("lock_sql_without_marked_call", lambda: validate_case(
        {**replay_case, "call": {"arguments": {}, "lock_sql": "UPDATE T SET X = 1"}},
        "selftest"))
    rejected("cancel_mutation_audit_without_marked_mutation", lambda: validate_case(
        {**replay_case, "call": {"arguments": {}, "cancel_marker": "W4MARK_123456789ABC",
                                   "cancel_mutation_audit": True}},
        "selftest"))
    rejected("cancel_after_completion_without_committed_mutation", lambda: validate_case(
        {**replay_case, "call": {"arguments": {}, "cancel_after_completion": True}},
        "selftest"))
    rejected("goldens_not_exactly_two", lambda: verify_expect_shape(
        {"goldens": ["issue49-cancel-read.free23.json"]}))
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
    parser.add_argument("--ci-summary", type=Path, help="validate W4 disposition and write CI pass/skip summary")
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
        if args.ci_summary:
            ci_summary(args.ci_summary, Path(os.environ["GITHUB_STEP_SUMMARY"]),
                       Path(os.environ["GITHUB_OUTPUT"]))
        elif args.selftest:
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
