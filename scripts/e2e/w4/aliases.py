"""Registry-derived alias proofs executed by the external W4 client.

Templates reuse the fixture assertions of ordinary cases. Each side reseeds
the fixture and runs the real steps, mutation rereads and audit verification.
"""

import copy
import datetime
import hashlib
import itertools
import json
import re
import secrets
import time


WRAPPERS = {"execute_approved", "deploy_ddl", "read_patch_preview", "get_schema"}
DEFAULTS = {"enable_writes": {"level": "READ_WRITE"},
            "disable_writes": {"action": "drop"},
            "compile_with_warnings": {"warnings": True},
            "patch_package": {"object_type": "PACKAGE BODY"},
            "patch_view": {"object_type": "VIEW"}}

# Canonical DDL advances object freshness before the alias repeats it. These
# exact impact paths cannot be equal across the two successful executions.
# Keep every field and compare all source/effect/identity facts unchanged.
ALIAS_FRESHNESS_PATHS = {
    ("binding", "decisive", "compile_parse_closure_digest"): "status_sha256",
    ("dependents", "value", "dependency_hash"): "sha256",
    ("dependents", "value", "roots", "*", "last_ddl_time"): "ddl_timestamp",
}

VERIFIED_FRESHNESS_PATHS = {
    ("binding", "decisive", "envelope_digest"): "envelope",
    ("binding", "decisive", "objects", "value", "*", "dependency_hash"): "dependencies",
}


def _digest_bytes(api, value):
    _freshness_digest(api, value)
    return bytes(value)


def _binding_digest(api, binding):
    """Reference the public V1 byte encoding; never infer an opaque digest."""
    unavailable = ("level_below_required untrusted_triggers unsupported_dml_shape engine_not_wired "
        "read_only_txn hard_parse_callbacks vpd no_privilege plan_table_unverified timeout truncated "
        "not_wired catalog_unavailable unresolved_dependency engine_failed object_not_found syntax_error "
        "connection_failed runtime_state_required challenge_required repreview_required lease_required "
        "forbidden_statement busy session_busy at_capacity invalid_arguments policy_denied request_cancelled "
        "transient flashback_retention_exceeded flashback_definition_changed flashback_not_flashbackable "
        "flashback_capability_unavailable snapshot_too_old internal "
        "impact_decisive_unavailable impact_decisive_truncated not_collected").split()
    not_applicable = "not_dml no_object no_source no_effect level_below_required untrusted_triggers".split()
    action_fields = ("envelope object_identities object_status mutation_effect_closure rows edition "
        "current_schema profile_generation lane_generation dependents predicted_invalid_set ddl_effect_closure "
        "source_effects reversibility profile_ceiling oauth_ceiling closure_fact_key routine_effects "
        "masking_profile_output edition_manifest changed_edition_manifest db_identity default_equals_base "
        "edition_parentage edition_exposure service_editions scope_digest policy_floor").split()

    def integer(value, width=8):
        api.require(type(value) is int and 0 <= value < 1 << (8 * width), "invalid impact integer")
        return value.to_bytes(width, "big")

    def blob(value):
        return integer(len(value)) + value

    def text(value):
        api.require(isinstance(value, str), "invalid impact text")
        return blob(value.encode())

    def digest(value):
        return blob(_digest_bytes(api, value))

    def status(value, encode):
        api.require(isinstance(value, dict), "invalid impact field")
        tag = value.get("status")
        if tag in {"computed", "estimated"}:
            api.require(set(value) == {"status", "value"}, "invalid valued impact field")
            return bytes([1 if tag == "computed" else 2]) + encode(value["value"])
        reasons = unavailable if tag == "unavailable" else not_applicable if tag == "not_applicable" else []
        api.require(set(value) == {"status", "reason"} and value.get("reason") in reasons,
                    "invalid unvalued impact field")
        return bytes([3 if tag == "unavailable" else 4, reasons.index(value["reason"]) + 1])

    def objects(values):
        api.require(isinstance(values, list), "invalid impact objects")
        encoded = [b"".join(status(value[key], encoder) for key, encoder in [
            ("identity", text), ("status", text), ("source_hash", digest),
            ("dependency_hash", digest), ("trigger_hash", digest)]) for value in values]
        return integer(len(encoded)) + b"".join(blob(value) for value in sorted(encoded))

    encoders = [
        ("envelope_digest", digest), ("statement_digest", digest), ("bind_hmac", digest),
        ("objects", objects), ("edition", text), ("compiler_facts", text),
        ("compile_parse_closure_digest", digest), ("engine_version", text), ("ruleset_digest", digest),
        ("effective_plan_digest", digest), ("policy_schema_digest", digest), ("policy_ruleset_digest", digest),
        ("matched_policy_rule_ids", lambda ids: integer(len(ids)) + b"".join(text(v) for v in ids)),
        ("rewrite_algorithm_version", lambda v: integer(v, 2)),
        ("db_identity", lambda v: integer(v["dbid"]) + integer(v["con_uid"])),
        ("current_schema", text), ("profile_generation", integer), ("lane_generation", integer),
        ("scope_digest", lambda v: b"\0" if v is None else b"\1" + digest(v)),
    ]
    api.require(binding.get("version") == 1, "unsupported impact binding version")
    facts = binding["decisive"]
    api.require(set(facts) == {key for key, _ in encoders} | {"action_fields"},
                "unknown or missing decisive impact field")
    encoded = blob(b"omcp/impact-binding/decisive/v1") + b"\1"
    encoded += b"".join(status(facts[key], encode) for key, encode in encoders)
    supplied = facts["action_fields"]
    api.require(isinstance(supplied, dict) and set(supplied) <= set(action_fields),
                "unknown action-specific impact field")
    encoded += integer(len(supplied))
    for field in action_fields:
        if field in supplied:
            encoded += blob(json.dumps(field).encode()) + status(supplied[field], digest)
    return hashlib.sha256(encoded).digest()


def _dependency_digest(api, graph):
    """Independent encoding of the published DependentsClosure commitment."""
    def fields(value, names):
        api.require(isinstance(value, dict) and set(names) <= value.keys(),
                    "incomplete dependency commitment facts")
        return {key: value[key] for key in names}

    def obj(value):
        return fields(value, ("owner", "name", "object_type")) if value is not None else None

    def node(value):
        result = fields(value, ("object", "depth", "object_id", "status", "last_ddl_time", "source_hash"))
        result["object"] = obj(result["object"])
        source = result["source_hash"]
        keys = {"computed": ("status", "sha256"), "unavailable": ("status", "reason"),
                "not_applicable": ("status",)}.get(source.get("status"))
        api.require(keys is not None, "invalid dependency source status")
        result["source_hash"] = fields(source, keys)
        return result

    result = fields(graph, ("requested_roots", "roots", "nodes", "edges", "caps", "truncated",
                            "truncation", "uncertainties", "dependency_hash"))
    result["requested_roots"] = [obj(value) for value in result["requested_roots"]]
    for key in ("roots", "nodes"):
        result[key] = [node(value) for value in result[key]]
    result["edges"] = [fields(value, ("dependent", "referenced", "referenced_object_id",
        "referenced_link_name", "dependency_type")) for value in result["edges"]]
    for edge in result["edges"]:
        edge["dependent"], edge["referenced"] = obj(edge["dependent"]), obj(edge["referenced"])
    result["caps"] = fields(result["caps"], ("max_depth", "max_count"))
    # predict_invalid_set replaces this display list with tagged catalog gaps
    # plus lineage warnings. Only catalog gaps entered the collector digest;
    # every warning remains unchanged in the separate equivalence comparison.
    gaps = []
    for value in result["uncertainties"]:
        if value.get("source") == "lineage":
            api.require(set(value) == {"source", "reason", "description", "owner", "name"},
                        "invalid lineage warning in dependency display")
            continue
        api.require("source" not in value or value["source"] == "catalog",
                    "unknown dependency uncertainty producer")
        gaps.append(fields(value, ("reason", "object")))
    result["uncertainties"] = gaps
    for gap in result["uncertainties"]:
        gap["object"] = obj(gap["object"])
    result["dependency_hash"] = [0] * 32
    encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(b"omcp/dependents-closure/v1\0" + encoded).digest()


def _native_dependency_edges(api, connection, graph):
    """Reread both directions at every published frontier, including missing nodes."""
    nodes = [*graph["roots"], *graph["nodes"]]
    objects = [node["object"] for node in nodes]
    api.require(0 < len(graph["requested_roots"]) <= 32
                and len(objects) <= 1032, "native dependency frontier exceeds collector bounds")
    requested = json.dumps(objects, ensure_ascii=False, separators=(",", ":"))
    api.require(len(requested.encode()) <= 32767, "native dependency frontier exceeds bind bound")
    rows = connection.cursor().execute("""SELECT * FROM (
        WITH bound AS (
            SELECT j.owner, j.name, j.object_type
            FROM JSON_TABLE(:1, '$[*]' COLUMNS (
                owner VARCHAR2(128) PATH '$.owner', name VARCHAR2(128) PATH '$.name',
                object_type VARCHAR2(30) PATH '$.object_type')) j
        )
        SELECT DISTINCT d.owner, d.name, d.type, d.referenced_owner, d.referenced_name,
            d.referenced_type, o.object_id, d.referenced_link_name, d.dependency_type
        FROM SYS.ALL_DEPENDENCIES d
        LEFT JOIN SYS.ALL_OBJECTS o ON d.referenced_link_name IS NULL
            AND o.owner=d.referenced_owner AND o.object_name=d.referenced_name
            AND o.object_type=d.referenced_type AND o.subobject_name IS NULL
        WHERE EXISTS (SELECT 1 FROM bound b
            WHERE (d.owner=b.owner AND d.name=b.name AND d.type=b.object_type)
            OR ((d.referenced_owner=b.owner OR d.referenced_owner IS NULL)
                AND d.referenced_name=b.name
                AND (d.referenced_type=b.object_type OR d.referenced_type IS NULL
                    OR d.referenced_type='NON-EXISTENT')))
        ) WHERE ROWNUM <= 8001""", (requested,)).fetchall()
    api.require(len(rows) <= 8000, "native dependency edge reread exceeds collector bound")

    def obj(values):
        return dict(zip(("owner", "name", "object_type"), values)) if all(values) else None

    observed = [{"dependent": obj(row[:3]), "referenced": obj(row[3:6]),
                 "referenced_object_id": row[6], "referenced_link_name": row[7],
                 "dependency_type": row[8]} for row in rows]
    api.require(sorted(map(api.compact, observed)) == sorted(map(api.compact, graph["edges"])),
                "dependency edge set differs from native ALL_DEPENDENCIES reread")
    if not graph["truncated"]:
        identities = {api.compact(value) for value in objects}
        for edge in observed:
            if edge["referenced_link_name"] is None and api.compact(edge["referenced"]) in identities:
                api.require(api.compact(edge["dependent"]) in identities,
                            "complete dependency closure omits a native dependent")


def _native_dependency_facts(api, connection, graph):
    digest = _dependency_digest(api, graph)
    api.require(digest == _digest_bytes(api, graph["dependency_hash"]),
                "dependency_hash differs from its complete dependency facts")
    _native_dependency_edges(api, connection, graph)
    observed = []
    for node in [*graph["roots"], *graph["nodes"]]:
        obj = node["object"]
        cursor = connection.cursor()
        rows = cursor.execute("SELECT OBJECT_ID, STATUS, TO_CHAR(LAST_DDL_TIME, 'YYYY-MM-DD\"T\"HH24:MI:SS') "
            "FROM SYS.ALL_OBJECTS WHERE OWNER=:1 AND OBJECT_NAME=:2 AND OBJECT_TYPE=:3 "
            "AND SUBOBJECT_NAME IS NULL", (obj["owner"], obj["name"], obj["object_type"])).fetchall()
        api.require(rows == [(node["object_id"], node["status"], node["last_ddl_time"])],
                    "dependency identity/status/timestamp differs from native reread")
        source = node["source_hash"]
        if source["status"] == "computed":
            if obj["object_type"] == "VIEW":
                lines = cursor.execute("SELECT TEXT_VC FROM SYS.ALL_VIEWS WHERE OWNER=:1 AND VIEW_NAME=:2",
                    (obj["owner"], obj["name"])).fetchall()
            else:
                lines = cursor.execute("SELECT TEXT FROM SYS.ALL_SOURCE WHERE OWNER=:1 AND NAME=:2 "
                    "AND TYPE=:3 ORDER BY LINE", (obj["owner"], obj["name"], obj["object_type"])).fetchall()
            api.require(lines and all(isinstance(row[0], str) for row in lines),
                        "computed source is unavailable in native reread")
            actual = hashlib.sha256("".join(row[0] for row in lines).encode()).digest()
            api.require(actual == _digest_bytes(api, source["sha256"]),
                        "dependency source hash differs from native reread")
        observed.append({"object": obj, "object_id": rows[0][0], "status": rows[0][1],
                         "last_ddl_time": rows[0][2], "source_hash": source})
    return digest, observed


def _validate_impact_preview(api, connection, payload, reread_graph=None):
    impact = payload.get("impact", {})
    if "binding" not in impact:
        return None
    token = (payload.get("confirmation") or payload.get("execute_confirmation") or {}).get("confirm")
    if not isinstance(token, str):
        return None
    facts = impact["binding"]["decisive"]
    envelope = facts["envelope_digest"]
    api.require(envelope.get("status") == "computed", "confirmation lacks computed envelope digest")
    parts = token.rsplit(".", 1)[0].rsplit("~", 2)
    api.require(len(parts) == 3 and re.fullmatch(r"[0-9a-f]{64}", parts[1])
                and re.fullmatch(r"[0-9a-f]{64}", parts[2]), "invalid impact-bound grant reference")
    api.require(_digest_bytes(api, facts["statement_digest"]["value"]).hex() == parts[1],
                "statement digest differs from the confirmation's execution material")
    api.require(_binding_digest(api, impact["binding"]).hex() == parts[2],
                "decisive facts, including envelope_digest, differ from the confirmation binding")
    record = {"payload_digest": hashlib.sha256(api.compact(api.scrub(payload)).encode()).hexdigest(),
              "envelope": _digest_bytes(api, envelope["value"]).hex()}
    graph = reread_graph or impact.get("dependents", {}).get("value")
    if isinstance(graph, dict) and "dependency_hash" in graph:
        digest, observed = _native_dependency_facts(api, connection, graph)
        objects = facts["objects"]
        api.require(objects.get("status") in {"computed", "estimated"}
                    and len(objects["value"]) == len(observed), "binding dependency object count differs")
        for fact, node in zip(objects["value"], [*graph["roots"], *graph["nodes"]]):
            obj = node["object"]
            api.require(fact["identity"].get("status") == "computed"
                        and json.loads(fact["identity"]["value"]) == [
                            obj["owner"], obj["name"], obj["object_type"], node["object_id"]],
                        "binding object identity differs from native dependency facts")
            status = fact["dependency_hash"]
            api.require(status.get("status") in {"computed", "estimated"}
                        and _digest_bytes(api, status["value"]) == digest,
                        "binding dependency_hash differs from native-checked dependency facts")
        record.update(dependencies=digest.hex(), native_objects=observed)
    return record


def binding_freshness_selftest(api):
    """Checker units; live alias runs perform the actual independent reads."""
    api.require(VERIFIED_FRESHNESS_PATHS == {
        ("binding", "decisive", "envelope_digest"): "envelope",
        ("binding", "decisive", "objects", "value", "*", "dependency_hash"): "dependencies",
    }, "verified freshness paths widened beyond the two independently checked digests")
    source = "PROCEDURE P AS BEGIN NULL; END;\n"
    obj = {"owner": "APP", "name": "P", "object_type": "PROCEDURE"}

    class NativeRows:
        def __init__(self, timestamp, edges=()):
            self.timestamp = timestamp
            self.edges = list(edges)

        def cursor(self):
            return self

        def execute(self, sql, binds):
            if "SYS.ALL_DEPENDENCIES" in sql:
                api.require(json.loads(binds[0]) == [obj], "unexpected checker-unit frontier")
                self.rows = self.edges
            else:
                api.require(binds[:2] == ("APP", "P"), "unexpected checker-unit object")
                self.rows = ([(7, "VALID", self.timestamp)] if "SYS.ALL_OBJECTS" in sql else [(source,)])
            return self

        def fetchall(self):
            return self.rows

    def fixture(byte, timestamp, decisive_changes=None):
        graph = {"requested_roots": [obj], "roots": [{"object": obj, "depth": 0,
            "object_id": 7, "status": "VALID", "last_ddl_time": timestamp,
            "source_hash": {"status": "computed", "sha256": list(hashlib.sha256(source.encode()).digest())}}],
            "nodes": [], "edges": [], "caps": {"max_depth": 10, "max_count": 1000},
            "truncated": False, "truncation": [], "uncertainties": [], "dependency_hash": [0] * 32}
        graph["dependency_hash"] = list(_dependency_digest(api, graph))
        envelope = [byte] * 32
        body = {"impact": {"binding": {"version": 1, "decisive": {
            "envelope_digest": {"status": "computed", "value": envelope},
            "compile_parse_closure_digest": {"status": "computed", "value": [8] * 32},
            "objects": {"status": "computed", "value": [{
                "identity": {"status": "computed", "value": json.dumps(["APP", "P", "PROCEDURE", 7])},
                "status": {"status": "computed", "value": "VALID"},
                "source_hash": {"status": "computed", "value": graph["roots"][0]["source_hash"]["sha256"]},
                "trigger_hash": {"status": "unavailable", "reason": "not_wired"},
                "dependency_hash": {"status": "computed", "value": graph["dependency_hash"]}}]} }},
            "dependents": {"status": "estimated", "value": graph}},
            "confirmation": {"confirm": "xgrant-1~" + bytes(envelope).hex() + "~" + "a" * 64 + "." + "b" * 64}}
        # The real wire decoder creates distinct arrays at distinct JSON paths.
        body = json.loads(json.dumps(body))
        facts = body["impact"]["binding"]["decisive"]
        for key in ("statement_digest bind_hmac edition compiler_facts engine_version ruleset_digest "
                    "effective_plan_digest policy_schema_digest policy_ruleset_digest matched_policy_rule_ids "
                    "rewrite_algorithm_version db_identity current_schema profile_generation lane_generation "
                    "scope_digest").split():
            facts[key] = {"status": "unavailable", "reason": "not_wired"}
        facts["statement_digest"] = {"status": "computed", "value": [3] * 32}
        facts["action_fields"] = {}
        facts.update(decisive_changes or {})
        body["confirmation"]["confirm"] = ("xgrant-1~" + bytes([3] * 32).hex() + "~"
            + _binding_digest(api, body["impact"]["binding"]).hex() + "." + "b" * 64)
        checked = _validate_impact_preview(api, NativeRows(timestamp), body)
        payload = {"isError": False, "structuredContent": body,
                   "content": [{"type": "text", "text": json.dumps(body)}]}
        return body, {"case": {"actual": payload}, "audit_semantics": [],
                      "native_impact_facts": [checked]}

    before, left = fixture(1, "2026-10-31T12:00:00")
    # Pinned by the guard's public Rust V1 encoder for this exact fixture.
    # The display label does not change the wire reason's canonical byte tag.
    for reason, expected in {
        "impact_decisive_unavailable": "4e940bb40b1754187dcd94709dff6efe482b025e75c31e6a9b698b2929254b96",
        "impact_decisive_truncated": "6d012aeec83edac7e5b74916fc43c8a978d9d80338fa2e904096b87cc65570f8",
        "not_collected": "2dbf76e94b163d9e54e894d21146bcc9ccb564fa127d4223f8a7daddee6014fd",
    }.items():
        binding = copy.deepcopy(before["impact"]["binding"])
        binding["decisive"]["engine_version"] = {"status": "unavailable", "reason": reason}
        api.require(_binding_digest(api, binding).hex() == expected,
                    f"public V1 reason tag changed: {reason}")
    binding["decisive"]["engine_version"]["reason"] = "not_a_public_reason"
    try:
        _binding_digest(api, binding)
    except api.DriverError:
        pass
    else:
        raise api.DriverError("reference codec accepted an unknown public reason")
    after, right = fixture(2, "2026-10-31T12:00:01")
    verify_equivalent_runs(api, left, right, {})
    for field, values in {
        "lane_generation": (3, 4), "ruleset_digest": ([4] * 32, [5] * 32),
    }.items():
        runs = [fixture(2, "2026-10-31T12:00:01", {
            field: {"status": "computed", "value": value}})[1] for value in values]
        try:
            verify_equivalent_runs(api, *runs, {})
        except api.DriverError:
            pass
        else:
            raise api.DriverError(f"alias comparator masked non-freshness decisive field {field}")
    for path in ("envelope_digest", "dependency_hash", "graph_dependency_hash", "native_timestamp"):
        bad = copy.deepcopy(after)
        facts = bad["impact"]["binding"]["decisive"]
        if path == "envelope_digest":
            facts["envelope_digest"]["value"][0] ^= 1
        elif path == "dependency_hash":
            facts["objects"]["value"][0]["dependency_hash"]["value"][0] ^= 1
        elif path == "graph_dependency_hash":
            bad["impact"]["dependents"]["value"]["dependency_hash"][0] ^= 1
        else:
            graph = bad["impact"]["dependents"]["value"]
            graph["roots"][0]["last_ddl_time"] = "2020-01-01T00:00:00"
            graph["dependency_hash"] = list(_dependency_digest(api, graph))
            facts["objects"]["value"][0]["dependency_hash"]["value"] = graph["dependency_hash"]
        if path != "envelope_digest":
            bad["confirmation"]["confirm"] = ("xgrant-1~" + bytes([3] * 32).hex() + "~"
                + _binding_digest(api, bad["impact"]["binding"]).hex() + "." + "b" * 64)
        try:
            _validate_impact_preview(api, NativeRows("2026-10-31T12:00:01"), bad)
        except api.DriverError:
            continue
        raise api.DriverError(f"native alias fact checker accepted wrong {path}")
    outgoing = ("APP", "P", "PROCEDURE", "APP", "T", "TABLE", 11, None, "HARD")
    incoming = ("APP", "Q", "PROCEDURE", "APP", "P", "PROCEDURE", 7, None, "HARD")
    for label, declared, native, accepted in [
        ("matching native edge", [outgoing], [outgoing], True),
        ("omitted outgoing edge", [], [outgoing], False),
        ("omitted dependent edge", [], [incoming], False),
        ("omitted dependent node", [incoming], [incoming], False),
    ]:
        bad = copy.deepcopy(after)
        graph = bad["impact"]["dependents"]["value"]
        graph["edges"] = [{"dependent": dict(zip(("owner", "name", "object_type"), row[:3])),
            "referenced": dict(zip(("owner", "name", "object_type"), row[3:6])),
            "referenced_object_id": row[6], "referenced_link_name": row[7],
            "dependency_type": row[8]} for row in declared]
        graph["dependency_hash"] = list(_dependency_digest(api, graph))
        bad["impact"]["binding"]["decisive"]["objects"]["value"][0]["dependency_hash"]["value"] = (
            list(graph["dependency_hash"]))
        bad["confirmation"]["confirm"] = ("xgrant-1~" + bytes([3] * 32).hex() + "~"
            + _binding_digest(api, bad["impact"]["binding"]).hex() + "." + "b" * 64)
        try:
            _validate_impact_preview(api, NativeRows("2026-10-31T12:00:01", native), bad)
        except api.DriverError:
            api.require(not accepted, f"native edge verifier refused {label}")
        else:
            api.require(accepted, f"native edge verifier accepted {label}")
    unwitnessed = {**right, "native_impact_facts": []}
    try:
        verify_equivalent_runs(api, left, unwitnessed, {})
    except api.DriverError:
        pass
    else:
        raise api.DriverError("alias comparator accepted an unverified binding digest")
    print(api.compact({"selftest": "alias_native_dependency_envelope_and_timestamp_facts", "verdict": "pass"}))


class _NativeImpactClient:
    """Observe each preview before the next step can change its Oracle facts."""
    def __init__(self, api, client, connection):
        self.api, self.client, self.connection, self.records = api, client, connection, []

    def __getattr__(self, name):
        return getattr(self.client, name)

    def rpc(self, method, params=None, **kwargs):
        reply = self.client.rpc(method, params, **kwargs)
        if method == "tools/call":
            payload = self.api.tool_payload(reply).get("structuredContent", {})
            impact = payload.get("impact", {})
            facts = impact.get("binding", {}).get("decisive", {})
            graph = None
            if not isinstance(impact.get("dependents", {}).get("value"), dict):
                objects = facts.get("objects", {}).get("value", [])
                # deploy_ddl returns the bound facts but omits the advisory
                # graph. Read a fresh, nonexecuting preview of the same root;
                # recompute that graph and independently read its node facts.
                if objects and objects[0].get("source_hash", {}).get("status") == "computed":
                    identity = objects[0]["identity"]
                    self.api.require(identity.get("status") == "computed", "missing reread identity")
                    owner, name, kind, _ = json.loads(identity["value"])
                    fresh = self.client.rpc("tools/call", {"name": "oracle_compile_object", "arguments": {
                        "owner": owner, "name": name, "object_type": kind, "execute": False}})
                    self.api.verify_expect({"json_subset": {"preview": True, "compiled": False}}, fresh)
                    graph = self.api.tool_payload(fresh).get("structuredContent", {}).get(
                        "impact", {}).get("dependents", {}).get("value")
                    self.api.require(isinstance(graph, dict), "fresh dependency graph unavailable")
            checked = _validate_impact_preview(self.api, self.connection, payload, graph)
            if checked is not None:
                self.records.append(self.api.scrub(checked))
        return reply


def load_rules(api):
    value = json.loads((api.CASES / "aliases.json").read_text())
    api.require(isinstance(value, dict) and set(value) == {"schema_version", "operations", "cases", "wrapper_cases", "argument_values"}
                and value["schema_version"] == 1 and isinstance(value["operations"], dict)
                and isinstance(value["cases"], list) and isinstance(value["wrapper_cases"], list)
                and isinstance(value["argument_values"], dict), "invalid alias pairing rules")
    for tool, rule in value["operations"].items():
        api.require(isinstance(tool, str) and isinstance(rule, dict)
                    and set(rule) <= {"case", "prototype", "arguments", "argument_values", "setup_prefix"}
                    and ("case" in rule) != ("prototype" in rule), "invalid alias operation template")
    return value


def registry_index(api, descriptors, document):
    api.require(document.get("ok") is True and isinstance(document.get("tools"), list),
                "robot-docs tools did not return the actual tool registry")
    rows = document["tools"]
    api.require(len({row["name"] for row in rows}) == len(rows), "duplicate robot-docs tool")
    index = {row["name"]: row for row in rows}
    for name, row in index.items():
        api.require(name in descriptors, f"documented tool absent from tools/list: {name}")
        schema = descriptors[name].get("inputSchema", {})
        notes = schema.get("x-deprecated-aliases", [])
        api.require(notes == row["argument_aliases"], f"{name}: docs/schema aliases differ")
        api.require(len({note["argument"] for note in notes}) == len(notes),
                    f"{name}: duplicate argument alias annotation")
        for note in notes:
            api.require(note == api.argument_deprecation(note["argument"], note["canonical"])
                        and note["argument"] not in schema["properties"]
                        and note["argument"] not in schema.get("required", [])
                        and note["canonical"] in schema["properties"],
                        f"{name}: noncanonical schema or incorrect deprecation")
        if row["alias_of"]:
            api.require(row["alias_of"] in descriptors,
                        f"{name}: documented canonical target absent from tools/list")
    return index


def _calls(case):
    return [*[(index, step) for index, step in enumerate(case.get("steps", [])) if "tool" in step],
            ("call", {"tool": case["tool"], "arguments": case["call"]["arguments"],
                       "expect": case["expect"]})]


def _put(case, position, call):
    if position == "call":
        case["tool"] = call["tool"]
        case["call"]["arguments"] = call["arguments"]
        case["expect"] = call["expect"]
    else:
        case["steps"][position] = call


def canonical_arguments(api, tool, arguments, index):
    arguments = copy.deepcopy(arguments)
    for note in index.get(tool, {}).get("argument_aliases", []):
        alias, canonical = note["argument"], note["canonical"]
        if alias not in arguments:
            continue
        api.require(canonical not in arguments, f"ambiguous canonical baseline for {tool}")
        value = arguments.pop(alias)
        if alias == "object_type" and isinstance(value, str):
            value = [value]
        arguments[canonical] = value
    return arguments


def _canonical_prototype(api, source, index):
    case = copy.deepcopy(source)
    for position, call in _calls(case):
        if {"error_class", "error_classes"} & call["expect"].keys() or "error_class" in call["expect"].get("json_subset", {}):
            continue
        tool = call["tool"]
        call["arguments"] = canonical_arguments(api, tool, call["arguments"], index)
        call["expect"]["deprecations"] = []
        if tool in DEFAULTS:
            call["arguments"].update(DEFAULTS[tool])
        target = index.get(tool, {}).get("alias_of")
        if target and tool not in WRAPPERS:
            call["tool"] = target
            call["expect"] = _retarget_expected(call["expect"], tool, target)
        _put(case, position, call)
    return case


def _retarget_expected(value, old, new):
    if isinstance(value, dict):
        return {key: new if key == "tool" and item == old else _retarget_expected(item, old, new)
                for key, item in value.items()}
    if isinstance(value, list):
        return [_retarget_expected(item, old, new) for item in value]
    return value


def _invoked_prototype(case, canonical, invoked):
    case = copy.deepcopy(case)
    if case["tool"] == invoked and invoked in WRAPPERS:
        return case
    for position, call in _calls(case):
        if call["tool"] != canonical:
            continue
        if invoked == "enable_writes" and (call["arguments"].get("level") != "READ_WRITE"
                                            or call["arguments"].get("action") in {"drop", "status"}):
            continue
        if invoked == "disable_writes" and call["arguments"].get("action") != "drop":
            continue
        call["tool"] = invoked
        for field in DEFAULTS.get(invoked, {}):
            call["arguments"].pop(field, None)
        if invoked == "execute_approved" and "confirm" in call["arguments"]:
            call["arguments"]["token"] = call["arguments"].pop("confirm")
        if invoked == "deploy_ddl" and "source_code" in call["arguments"]:
            call["arguments"]["ddl"] = call["arguments"].pop("source_code")
        if canonical != "oracle_create_or_replace":
            call["expect"] = _retarget_expected(call["expect"], canonical, invoked)
        _put(case, position, call)
    # Elevation auditing deliberately records the canonical control-plane path.
    if canonical not in {"oracle_set_session_level", "oracle_create_or_replace"} and invoked != "execute_approved":
        case["audit_expect"] = _retarget_expected(case["audit_expect"], canonical, invoked)
    return case


def _operation(api, invoked, index, rules, sources):
    canonical = index[invoked]["alias_of"] or invoked
    rule = rules["operations"].get(invoked, rules["operations"].get(canonical))
    api.require(rule is not None, f"alias operation lacks a live template: {invoked}")
    if "case" in rule:
        api.require(rule["case"] in sources, f"alias template case missing: {rule['case']}")
        original = sources[rule["case"]]
    else:
        original = api.validate_case(copy.deepcopy(rule["prototype"]), "aliases.json prototype")
    case = _canonical_prototype(api, original, index)
    for position, call in _calls(case):
        if call["tool"] == canonical:
            call["arguments"].update(rule.get("arguments", {}))
            _put(case, position, call)
    case["setup"] = copy.deepcopy(rule.get("setup_prefix", [])) + case["setup"]
    case["setup_phase"] = "before_call"
    # Repeated confirmed writes start from the same real fixture state.
    case.pop("setup_ready_sql", None)
    case.pop("test_id", None)
    return canonical, case


def _argument_target(api, prototype, canonical, invoked, field, rule):
    target = _invoked_prototype(prototype, canonical, invoked)
    calls = [(position, call) for position, call in _calls(target) if call["tool"] == invoked]
    api.require(calls, f"{invoked}: prototype does not exercise the invoked tool")
    eligible = [(p, c) for p, c in calls if field in c["arguments"]]
    if not eligible:
        values = rule.get("argument_values", {})
        api.require(field in values, f"{invoked}.{field}: no positive canonical argument value")
        position, call = next(((p, c) for p, c in reversed(calls) if c["arguments"].get("execute") is True), calls[-1])
        for p, candidate in _calls(target):
            if candidate["tool"] == invoked or (field.startswith("dbms_output_") or field == "capture_dbms_output") and candidate["tool"] == "oracle_preview_sql":
                candidate["arguments"][field] = copy.deepcopy(values[field])
                _put(target, p, candidate)
        eligible = [(p, c) for p, c in _calls(target) if c["tool"] == invoked and field in c["arguments"]]
    position, _ = next(((p, c) for p, c in reversed(eligible) if c["arguments"].get("execute") is True), eligible[-1])
    return target, position


def generated_cases(api, descriptors, document, family, lane, fixture_id, transport):
    index = registry_index(api, descriptors, document)
    rules = api.expand_case(load_rules(api), fixture_id, transport, lane)
    sources = {case["case_id"]: case for case in family}
    generated = []
    for invoked, row in index.items():
        if not row["alias_of"] and not row["argument_aliases"]:
            continue
        canonical, prototype = _operation(api, invoked, index, rules, sources)
        stem = "tool_alias_" + invoked if row["alias_of"] else invoked.removeprefix("oracle_")
        base = {"tool": invoked, "level": prototype["level"],
                "profile_variant": prototype.get("profile_variant", "masked"),
                "transports": ["stdio", "http"], "requires": prototype["requires"],
                "setup": [], "call": {"arguments": {}}, "expect": {"json_subset": {"equivalent": True}},
                "db_reread": [], "audit_expect": [], "on_unsupported": {"error_class": "INVALID_ARGUMENTS"}}
        if row["alias_of"] and invoked not in WRAPPERS:
            generated.append({**base, "case_id": f"w4_alias_{invoked}_equivalent",
                              "alias_proof": {"kind": "tool", "invoked": invoked, "canonical": canonical,
                                              "prototype": prototype, "index": index}})
        for note in row["argument_aliases"]:
            rule = {"argument_values": rules["argument_values"], **rules["operations"].get(invoked, rules["operations"].get(canonical))}
            target, position = _argument_target(api, prototype, canonical, invoked, note["canonical"], rule)
            for kind in ("equivalent", "conflict_equal", "conflict_different"):
                generated.append({**base, "case_id": f"w4_alias_arg_{stem}_{note['argument']}_{kind}",
                    "alias_proof": {"kind": kind, "invoked": invoked, "canonical": canonical,
                                    "note": note, "position": position, "prototype": target, "index": index}})
        groups = {}
        for note in row["argument_aliases"]:
            groups.setdefault(note["canonical"], []).append(note)
        for field, notes in groups.items():
            for first, second in itertools.combinations(notes, 2):
                rule = {"argument_values": rules["argument_values"], **rules["operations"].get(invoked, rules["operations"].get(canonical))}
                target, position = _argument_target(api, prototype, canonical, invoked, field, rule)
                generated.append({**base, "case_id": f"w4_alias_arg_{stem}_{first['argument']}_{second['argument']}_conflict",
                    "alias_proof": {"kind": "two_aliases", "invoked": invoked, "canonical": canonical,
                                    "note": first, "other_note": second, "position": position,
                                    "prototype": target, "index": index}})
    api.require(len({case["case_id"] for case in generated}) == len(generated), "alias case ID collision")
    wrapper_kinds = {"execute": "execute_approved", "without_token": "execute_approved",
                     "deploy": "deploy_ddl", "wait_timeout": "deploy_ddl", "read_preview": "read_patch_preview",
                     "schema": "get_schema"}
    api.require(len(rules["wrapper_cases"]) == len(wrapper_kinds)
                and {rule["kind"] for rule in rules["wrapper_cases"]} == set(wrapper_kinds),
                "explicit wrapper proof family is incomplete")
    for rule in rules["wrapper_cases"]:
        invoked = wrapper_kinds[rule["kind"]]
        api.require(invoked in index and index[invoked]["alias_of"], "wrapper absent from actual registry")
        generated.append({"case_id": rule["case_id"], "tool": invoked,
            "level": {"execute_approved": "READ_WRITE", "get_schema": "READ_ONLY"}.get(invoked, "DDL"),
            "transports": ["stdio", "http"], "requires": [], "setup": [], "call": {"arguments": {}},
            "expect": {"json_subset": {"equivalent": True}}, "db_reread": [], "audit_expect": [],
            "on_unsupported": {"error_class": "INVALID_ARGUMENTS"},
            "alias_proof": {"kind": "wrapper_" + rule["kind"], "invoked": invoked,
                            "canonical": index[invoked]["alias_of"], "index": index,
                            "owner": "W4O_" + fixture_id, "fixture_id": fixture_id}})
    api.require(len({case["case_id"] for case in generated}) == len(generated), "wrapper case ID collision")
    return generated


def _normal(api, value, index, path=()):
    if isinstance(value, dict) and {"content", "structuredContent", "isError"} <= value.keys():
        api.require(isinstance(value["content"], list) and len(value["content"]) == 1
                    and value["content"][0].get("type") == "text", "alias payload changed content representation")
        text = value["content"][0]["text"]
        if "\n<untrusted-user-data-" in text:
            start = text.index("\n", text.index("\n<untrusted-user-data-") + 1) + 1
            text = text[start:text.rindex("\n</untrusted-user-data-")]
        human = _normal(api, json.loads(text), index, path + ("application",))
        structured = _normal(api, value["structuredContent"], index, path + ("application",))
        api.require(human == structured, "alias text and structured application results differ")
        metadata = dict(value.get("_meta", {}))
        metadata.pop("deprecations", None)
        return {"isError": value["isError"], "structuredContent": structured,
                "metadata": _normal(api, metadata, index, path + ("metadata",))}
    value = api.scrub(value, path)
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key == "_meta" and "rows" not in path:
                api.require(set(item) <= {"deprecations"}, "unaccounted metadata in equivalence result")
                continue
            if "rows" not in path and key in {"confirm", "token"} and isinstance(item, str):
                api.require(len(item) >= 16, "invalid confirmation token in comparison")
                result[key] = "<confirmation>"
            elif "rows" not in path and key == "statement_id":
                api.require(isinstance(item, str) and re.fullmatch(r"OMCP_[A-Z0-9]{24}", item),
                            "invalid generated plan statement ID")
                result[key] = "<statement_id>"
            elif "rows" not in path and key == "custom_catalog_generation":
                api.require(type(item) is int and item > 0, "invalid custom catalog generation")
                result[key] = "<catalog_generation>"
            elif path and path[-1] == "mask_certificate" and key == "audit_entry_hash":
                api.require(isinstance(item, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", item),
                            "invalid mask certificate audit hash")
                result[key] = "<bound_audit_hash>"
            elif "rows" not in path and key in {"expires_at", "expires_unix_seconds", "elevation_expires_unix", "ttl_remaining_seconds"}:
                api.require(isinstance(item, (str, int, float)), "invalid volatile expiry")
                result[key] = "<expiry>"
            elif "rows" not in path and key in {"tool", "patch_tool"} and isinstance(item, str):
                result[key] = index.get(item, {}).get("alias_of") or item
            else:
                result[key] = _normal(api, item, index, path + (key,))
        return result
    if isinstance(value, list):
        return [_normal(api, item, index, path) for item in value]
    return value


def _audit_projection(records, index):
    keys = ("tool", "decision", "outcome", "rows_affected", "sql_sha256", "failure", "profile")
    return [{key: (index.get(record[key], {}).get("alias_of") or record[key]) if key == "tool" else record[key]
             for key in keys if key in record} for record in records]


def _freshness_digest(api, value):
    # Rust [u8; 32] is a JSON array, not a free-form string. Validate the wire
    # representation before deriving its canonical SHA256 hex representation.
    api.require(isinstance(value, list) and len(value) == 32
                and all(type(byte) is int and 0 <= byte <= 255 for byte in value),
                "invalid alias freshness SHA256 bytes")
    api.require(re.fullmatch(r"[0-9a-f]{64}", bytes(value).hex()),
                "invalid alias freshness SHA256 hex")
    return "<freshness_sha256>"


def _impact_freshness(api, value, path=(), verified=()):
    if path in {("binding",), ("binding", "decisive"), ("dependents",),
                ("dependents", "value"), ("dependents", "value", "roots", "*")}:
        api.require(isinstance(value, dict), "invalid alias impact freshness container")
    if path == ("dependents", "value", "roots"):
        api.require(isinstance(value, list), "invalid alias dependency roots")
    rule = ALIAS_FRESHNESS_PATHS.get(path)
    if VERIFIED_FRESHNESS_PATHS.get(path) in verified:
        rule = "status_sha256"
    if rule == "status_sha256":
        api.require(isinstance(value, dict) and value.get("status") in {
            "computed", "estimated", "unavailable", "not_applicable"},
            "invalid alias closure-digest field status")
        if value["status"] in {"computed", "estimated"}:
            api.require("value" in value, "missing alias closure digest")
            return {**value, "value": _freshness_digest(api, value["value"])}
        api.require("value" not in value, "unavailable alias closure digest has a value")
        return copy.deepcopy(value)
    if rule == "sha256":
        return _freshness_digest(api, value)
    if rule == "ddl_timestamp":
        if value is None:
            return None  # Unknown freshness must remain distinct from a known time.
        api.require(isinstance(value, str) and len(value) >= 19,
                    "invalid alias root DDL timestamp")
        try:
            datetime.datetime.fromisoformat(value)
        except ValueError as error:
            raise api.DriverError("invalid alias root DDL timestamp") from error
        return "<ddl_freshness>"
    if isinstance(value, dict):
        required = {
            ("binding", "decisive"): {"compile_parse_closure_digest"},
            ("dependents", "value"): {"dependency_hash", "roots"},
            ("dependents", "value", "roots", "*"): {"last_ddl_time"},
        }.get(path, set())
        api.require(required <= value.keys(), "missing alias impact freshness field")
        return {key: _impact_freshness(api, item, path + (key,), verified)
                for key, item in value.items()}
    if isinstance(value, list):
        return [_impact_freshness(api, item, path + (
            "*" if path in {("dependents", "value", "roots"),
                            ("binding", "decisive", "objects", "value")} else str(index),), verified)
                for index, item in enumerate(value)]
    return value


def _equivalence_result(api, run, index):
    actual = run["case"]
    verified = {}
    for observed in [actual, *actual.get("steps", [])]:
        result = observed.get("actual")
        payload = result.get("structuredContent") if isinstance(result, dict) else None
        if isinstance(payload, dict):
            key = hashlib.sha256(api.compact(payload).encode()).hexdigest()
            verified[key] = next((record for record in run.get("native_impact_facts", [])
                                  if record["payload_digest"] == key), {})
    normalized = _normal(api, {key: actual[key] for key in (
        "actual", "steps", "db_reread_actual") if key in actual}, index)
    # _normal must compare the two wire representations before freshness is
    # projected across executions. A corrupt text/structured pair still fails.
    for original, observed in zip([actual, *actual.get("steps", [])],
                                  [normalized, *normalized.get("steps", [])]):
        result = observed.get("actual")
        payload = result.get("structuredContent") if isinstance(result, dict) else None
        if isinstance(payload, dict) and "impact" in payload:
            api.require(isinstance(payload["impact"], dict), "invalid alias impact object")
            raw = original["actual"]["structuredContent"]
            key = hashlib.sha256(api.compact(raw).encode()).hexdigest()
            payload["impact"] = _impact_freshness(api, payload["impact"], verified=verified[key])
    return normalized


def freshness_equivalence_selftest(api):
    """Checker units; CI/native replay uses the same comparator separately."""
    def run(byte, ddl_time):
        body = {"required_level": "DDL", "statements": ["ALTER PROCEDURE APP.P COMPILE"],
            "impact": {
                "binding": {"decisive": {"compile_parse_closure_digest": {
                    "status": "computed", "value": [byte] * 32}}},
                "dependents": {"status": "estimated", "value": {
                    "dependency_hash": [byte] * 32, "requested_roots": 1,
                    "roots": [{"object": {"owner": "APP", "name": "P", "object_type": "PROCEDURE"},
                        "last_ddl_time": ddl_time, "object_id": 7, "status": "VALID", "depth": 0,
                        "source_hash": {"status": "computed", "sha256": [3] * 32}}],
                    "nodes": [], "edges": [], "predicted_invalid_count": 0}},
                "effects": {"status": "computed", "value": {"after": ["ReadDb"]}}}}
        payload = {"isError": False, "content": [{"type": "text", "text": json.dumps(body)}],
                   "structuredContent": copy.deepcopy(body)}
        return {"case": {"steps": [{"actual": payload}], "db_reread_actual": [[["VALID"]]]},
                "audit_semantics": [{"tool": "oracle_compile_object", "outcome": "SUCCEEDED"}]}

    def body(observed):
        return observed["case"]["steps"][0]["actual"]["structuredContent"]

    def changed(observed, change, synchronize=True):
        observed = copy.deepcopy(observed)
        change(body(observed))
        if synchronize:
            observed["case"]["steps"][0]["actual"]["content"][0]["text"] = json.dumps(body(observed))
        return observed

    def rejected(left, right, label):
        try:
            verify_equivalent_runs(api, left, right, {})
        except api.DriverError:
            return
        raise api.DriverError(f"alias freshness projection accepted {label}")

    left, right = run(1, "2026-10-31T12:00:00"), run(2, "2026-10-31T12:00:01")
    verify_equivalent_runs(api, left, right, {})
    projected = _equivalence_result(api, right, {})["steps"][0]["actual"]["structuredContent"]["impact"]
    api.require(set(projected["binding"]["decisive"]["compile_parse_closure_digest"]) == {"status", "value"}
                and "dependency_hash" in projected["dependents"]["value"]
                and "last_ddl_time" in projected["dependents"]["value"]["roots"][0],
                "alias freshness projection removed a field")
    root = lambda value: value["impact"]["dependents"]["value"]["roots"][0]
    closure = lambda value: value["impact"]["binding"]["decisive"]["compile_parse_closure_digest"]
    mutations = {
        "changed root name": lambda value: root(value)["object"].update(name="WRONG"),
        "changed root owner": lambda value: root(value)["object"].update(owner="OTHER"),
        "changed root type": lambda value: root(value)["object"].update(object_type="FUNCTION"),
        "dropped root": lambda value: value["impact"]["dependents"]["value"]["roots"].clear(),
        "malformed digest": lambda value: closure(value)["value"].pop(),
        "boolean digest byte": lambda value: closure(value)["value"].__setitem__(0, True),
        "out-of-range digest byte": lambda value: closure(value)["value"].__setitem__(0, 256),
        "missing closure digest": lambda value: value["impact"]["binding"]["decisive"].pop("compile_parse_closure_digest"),
        "missing dependency digest": lambda value: value["impact"]["dependents"]["value"].pop("dependency_hash"),
        "malformed roots": lambda value: value["impact"]["dependents"]["value"].update(roots={}),
        "malformed root": lambda value: value["impact"]["dependents"]["value"]["roots"].__setitem__(0, None),
        "changed source": lambda value: root(value)["source_hash"]["sha256"].__setitem__(0, 99),
        "changed effects": lambda value: value["impact"]["effects"]["value"].update(after=["Autonomous"]),
        "changed statement": lambda value: value.update(statements=["DROP PROCEDURE APP.P"]),
        "changed digest status": lambda value: closure(value).update(status="estimated"),
        "malformed timestamp": lambda value: root(value).update(last_ddl_time="not-a-timestamp"),
        "missing timestamp": lambda value: root(value).pop("last_ddl_time"),
        "lost known freshness": lambda value: root(value).update(last_ddl_time=None),
    }
    for label, change in mutations.items():
        rejected(left, changed(right, change), label)
    for label in ("malformed digest", "missing closure digest", "missing dependency digest", "missing timestamp",
                  "malformed roots", "malformed root"):
        rejected(changed(left, mutations[label]), changed(right, mutations[label]), label + " on both sides")
    rejected(left, changed(right, lambda value: root(value).update(last_ddl_time="2026-10-31T12:00:02"), False),
             "one-wire-representation timestamp difference")
    rejected(left, changed(right, mutations["changed source"], False), "one-wire-representation source difference")
    two_left, two_right = copy.deepcopy(left), copy.deepcopy(right)
    for observed in (two_left, two_right):
        graph = body(observed)["impact"]["dependents"]["value"]
        second = copy.deepcopy(graph["roots"][0])
        second["object"]["name"] = "Q"
        graph["roots"].append(second)
        graph["requested_roots"] = 2
        observed["case"]["steps"][0]["actual"]["content"][0]["text"] = json.dumps(body(observed))
    verify_equivalent_runs(api, two_left, two_right, {})
    rejected(two_left, changed(two_right, lambda value: value["impact"]["dependents"]["value"]["roots"].reverse()),
             "changed root order")


def verify_equivalent_runs(api, left, right, index):
    for run in (left, right):
        _verify_mask_bindings(api, run["case"], run.get("audit", []))
    first = left["case"].get("actual", {}).get("structuredContent", {})
    second = right["case"].get("actual", {}).get("structuredContent", {})
    if "custom_catalog_generation" in first or "custom_catalog_generation" in second:
        api.require(type(first.get("custom_catalog_generation")) is int
                    and second.get("custom_catalog_generation") == first["custom_catalog_generation"] + 2,
                    "profile restore and repeated switch did not advance the catalog twice")
    api.require(_equivalence_result(api, left, index) == _equivalence_result(api, right, index),
                "alias result, steps or independent rereads differ")
    api.require(left["audit_semantics"] == right["audit_semantics"], "alias executed audit paths differ")


def _verify_mask_bindings(api, case, records):
    for observed in [case, *case.get("steps", [])]:
        certificate = observed.get("actual", {}).get("structuredContent", {}).get("mask_certificate")
        if certificate is None:
            continue
        core = {key: item for key, item in certificate.items() if key != "audit_entry_hash"}
        matches = [record for record in records if record.get("outcome") == "SUCCEEDED"
                   and record.get("entry_hash") == certificate.get("audit_entry_hash")
                   and record.get("result_masking") == core]
        api.require(len(matches) == 1, "alias mask certificate lacks its unique terminal audit binding")


def _profile(lane, variant):
    return {"masked": lane, "protected": lane + "_protected", "synthetic_raw": lane + "_raw",
            "synthetic_owner": lane + "_owner", "synthetic_owner_rw": lane + "_owner_rw",
            "trusted_views": lane + "_trusted_views"}[variant]


def _drop(api, client):
    reply = client.rpc("tools/call", {"name": "oracle_set_session_level", "arguments": {"action": "drop"}})
    api.verify_expect({"json_subset": {"session": {"current_level": "READ_ONLY"}}}, reply)


def _audit_offset(path):
    return path.stat().st_size if path.exists() else 0


def _audit_since(path, offset):
    if not path.exists():
        return []
    with path.open("rb") as stream:
        stream.seek(offset)
        return [json.loads(line) for line in stream if line.strip()]


def finalize_audit_rows(rows, lane, transport, verified):
    for row in rows:
        if row.get("lane") != lane or row.get("transport") != transport:
            continue
        if row.pop("audit_pending_final_chain", False):
            row["audit_chain_verified"] = verified
            failed = any(key in row for key in ("failure", "verification_failure", "cleanup_failure"))
            row["verdict"] = "pass" if verified and not failed else "fail"
            if not verified:
                row["failure"] = {"class": "DriverError", "detail": "final native audit chain verification failed"}


def _negative_run(api, client, inner, spec, connection, binary, audit_path, env):
    observed = {"verdict": "fail", "actual": None}
    api.apply_setup(connection, inner["setup"])
    position = spec["position"]
    prefix = inner.get("steps", []) if position == "call" else inner.get("steps", [])[:position]
    captures = api.run_steps(client, {**inner, "steps": prefix}, observed,
                             binary, audit_path, env, connection)
    call = dict(_calls(inner))[position]
    reads = inner["db_reread"]
    state_before = [api.db_rows(connection, read["sql"]) for read in reads]
    level_before = api.session_level(client)
    before = _audit_offset(audit_path)
    reply = client.rpc("tools/call", {"name": call["tool"],
        "arguments": api.fill_captures(call["arguments"], captures)})
    api.verify_envelope(reply)
    observed["actual"] = api.scrub(api.tool_payload(reply))
    api.verify_expect(call["expect"], reply)
    detail = api.tool_payload(reply)["structuredContent"]
    keys = [spec["note"]["argument"], spec.get("other_note", {}).get("argument", spec["note"]["canonical"])]
    api.require(all(key in detail.get("message", "") for key in keys) and detail.get("next_steps"),
                "alias conflict lacks exact keys or safe next steps")
    records = _audit_since(audit_path, before)
    api.require(not any(record.get("decision") == "ALLOWED" for record in records),
                "alias conflict reached an execution audit")
    state_after = [api.db_rows(connection, read["sql"]) for read in reads]
    api.require(state_before == state_after and api.session_level(client) == level_before,
                "alias conflict changed fixture state or authority")
    observed["db_reread_before"], observed["db_reread_actual"] = state_before, state_after
    if any(step.get("tool") == "oracle_checkpoint" for step in prefix):
        cleanup = client.rpc("tools/call", {"name": "oracle_undo_to", "arguments": {}})
        api.verify_expect({"json_subset": {"workspace": {"open": False}}}, cleanup)
    api.apply_setup(connection, inner.get("cleanup", []))
    observed["verdict"] = "pass"
    return observed


def _reset_created_objects(api, connection, actions):
    for action in actions:
        match = re.match(r"CREATE\s+(?:UNIQUE\s+)?(TABLE|INDEX|SEQUENCE)\s+"
                         r"(W4O_W4[0-9]{4}[A-F0-9]{6})\.([A-Z][A-Z0-9_]+)\b",
                         action["sql"], re.IGNORECASE)
        if not match:
            continue
        kind, owner, name = (part.upper() for part in match.groups())
        api.require(name.endswith(owner.removeprefix("W4O_")), "alias reset object is not run-owned")
        existing = api.db_rows(connection, f"SELECT OBJECT_TYPE FROM ALL_OBJECTS WHERE OWNER='{owner}' "
                              f"AND OBJECT_NAME='{name}' AND OBJECT_TYPE='{kind}'")
        api.require(existing in ([], [[kind]]), "ambiguous alias reset object")
        if existing:
            suffix = " CASCADE CONSTRAINTS PURGE" if kind == "TABLE" else ""
            api.apply_setup(connection, [{"sql": f"DROP {kind} {owner}.{name}{suffix}"}])


def run_proof(api, client, case, row, transport, lane, capabilities, connection, barriers,
              binary, audit_path, env, descriptors):
    if case["alias_proof"]["kind"].startswith("wrapper_"):
        return run_wrapper(api, client, case, row, connection, audit_path)
    start = time.monotonic()
    spec = case["alias_proof"]
    index, invoked, canonical = spec["index"], spec["invoked"], spec["canonical"]
    prototype = copy.deepcopy(spec["prototype"])
    stable_read_fixture = prototype["level"] == "READ_ONLY"
    row["expected"] = {"kind": spec["kind"], "canonical": canonical, "invoked": invoked,
                       "note": spec.get("note"), "fixture": prototype["case_id"]}
    row["actual"] = {"runs": []}
    try:
        api.require(set(prototype["requires"]) <= capabilities, "alias proof lacks required live capabilities")
        for side in ("canonical", "alias"):
            inner = copy.deepcopy(prototype)
            if spec["kind"] == "tool" and side == "alias":
                inner = _invoked_prototype(inner, canonical, invoked)
            if spec["kind"] != "tool" and side == "alias":
                position = spec["position"]
                call = dict(_calls(inner))[position]
                field, alias = spec["note"]["canonical"], spec["note"]["argument"]
                value = call["arguments"][field]
                if spec["kind"] == "equivalent":
                    call["arguments"][alias] = call["arguments"].pop(field)
                    if alias == "object_type" and isinstance(value, list) and len(value) == 1:
                        call["arguments"][alias] = value[0]
                    call["expect"]["deprecations"] = [spec["note"]]
                else:
                    call["arguments"][alias] = copy.deepcopy(value)
                    if spec["kind"] == "conflict_different":
                        call["arguments"][alias] = "W4_DIFFERENT_ALIAS_VALUE"
                    if spec["kind"] == "two_aliases":
                        call["arguments"].pop(field)
                        call["arguments"][spec["other_note"]["argument"]] = copy.deepcopy(value)
                    call["expect"] = {"error_class": "INVALID_ARGUMENTS"}
                _put(inner, position, call)
            _drop(api, client)
            api.elevate(client, inner["level"])
            if stable_read_fixture and side == "alias":
                inner["setup"] = []
            _reset_created_objects(api, connection, inner["setup"])
            if canonical == "oracle_orient":
                warmed = client.rpc("tools/call", {"name": "oracle_orient",
                    "arguments": canonical_arguments(api, prototype["tool"], prototype["call"]["arguments"], index)})
                api.verify_envelope(warmed)
                api.require(not api.tool_payload(warmed).get("isError"), "cannot prepare the same warm orient cache state")
                row["actual"].setdefault("cache_preparation", []).append(api.scrub(api.tool_payload(warmed)))
            expected_audit = inner["audit_expect"]
            api.require(not ({"view_proof_audit", "mask_certificate_audit"} & inner.keys()),
                        "alias template needs specialized audit binding verification")
            inner["audit_expect"] = []
            if stable_read_fixture or canonical == "oracle_get_source":
                # Both reads see the same physical objects, including Oracle's
                # generated names and DDL timestamps. Clean up after the pair.
                inner["cleanup"] = []
            before = _audit_offset(audit_path)
            checked_client = _NativeImpactClient(api, client, connection)
            observed = (_negative_run(api, checked_client, inner, spec, connection, binary, audit_path, env)
                        if side == "alias" and spec["kind"] not in {"tool", "equivalent"} else
                        api.run_case(checked_client, inner, transport, lane, capabilities, connection, barriers,
                                     binary, audit_path, env, descriptors.get(inner["tool"])))
            records = _audit_since(audit_path, before)
            row["actual"]["runs"].append({"side": side, "case": observed,
                "native_impact_facts": checked_client.records,
                "audit": api.scrub(records), "audit_semantics": _audit_projection(records, index)})
            api.require(observed["verdict"] == "pass", f"{side} alias scenario failed: {observed.get('verification_failure', observed.get('failure'))}")
            _verify_mask_bindings(api, observed, records)
            actual = (observed.get("actual") or {}).get("structuredContent", {})
            if (side == "canonical" or spec["kind"] in {"tool", "equivalent"}) and canonical == "oracle_get_source":
                arguments = canonical_arguments(api, inner["tool"], inner["call"]["arguments"], index)
                owner, name = arguments["owner"], arguments["name"]
                object_type = arguments["object_type"].replace("_", " ")
                source_rows = api.db_rows(connection, f"SELECT TEXT FROM ALL_SOURCE WHERE OWNER='{owner}' "
                    f"AND NAME='{name}' AND TYPE='{object_type}' ORDER BY LINE")
                source_text = "".join(value[0] for value in source_rows)
                observed["source_reread_actual"] = api.scrub(source_rows)
                api.require(source_rows and actual["source"]["source"] == api.scrub(source_text)
                            and actual["source"]["char_count"] == len(source_text)
                            and actual["source"]["line_count"] == len(source_rows)
                            and actual["source"]["truncated"] is False,
                            f"served source differs from Oracle dictionary: wire chars={actual['source']['char_count']} "
                            f"dictionary chars={len(source_text)}, dictionary lines={len(source_rows)}")
            if "patch_tool" in actual and inner["tool"] in {"oracle_patch_source", "patch_package", "patch_view"}:
                api.require(actual["patch_tool"] == inner["tool"], "patch result lost the invoked tool identity")
            if expected_audit and (side == "canonical" or spec["kind"] in {"tool", "equivalent"}):
                api.verify_audit_records(expected_audit, records, inner.get("audit_optional_prefix"))
            if any(call["tool"] in {"oracle_switch_profile", "switch_database"} for _, call in _calls(inner)):
                _drop(api, client)
                reply = client.rpc("tools/call", {"name": "oracle_switch_profile",
                    "arguments": {"profile": _profile(lane, case.get("profile_variant", "masked"))}})
                api.require(not api.tool_payload(reply).get("isError"), "cannot restore alias proof profile")
        if spec["kind"] in {"tool", "equivalent"}:
            left, right = row["actual"]["runs"]
            verify_equivalent_runs(api, left, right, index)
        row["actual"]["equivalent"] = True
        # The parent driver verifies the native hash chain once per transport.
        # A successful semantic proof remains FAIL until that verification passes.
        row["audit_pending_final_chain"] = True
    except (api.DriverError, KeyError, StopIteration) as exc:
        row["failure"] = {"class": type(exc).__name__, "detail": str(exc)[:500]}
    finally:
        if stable_read_fixture or canonical == "oracle_get_source":
            api.apply_setup(connection, prototype.get("cleanup", []))
        if any(call["tool"] == "oracle_checkpoint" for _, call in _calls(prototype)):
            cleanup = client.rpc("tools/call", {"name": "oracle_undo_to", "arguments": {}})
            api.verify_expect({"json_subset": {"workspace": {"open": False}}}, cleanup)
        _drop(api, client)
        if any(call["tool"] in {"oracle_switch_profile", "switch_database"} for _, call in _calls(prototype)):
            restored = client.rpc("tools/call", {"name": "oracle_switch_profile", "arguments": {
                "profile": _profile(lane, case.get("profile_variant", "masked"))}})
            api.require(not api.tool_payload(restored).get("isError"), "failed to restore profile after alias case")
    row["duration_ms"] = round((time.monotonic() - start) * 1000)
    return row


def run_wrapper(api, client, case, row, connection, audit_path):
    start = time.monotonic()
    spec = case["alias_proof"]
    owner, fixture_id, kind = spec["owner"], spec["fixture_id"], spec["kind"]
    row["expected"] = {"kind": kind, "canonical": spec["canonical"], "invoked": spec["invoked"]}
    row["actual"] = {"calls": [], "independent_rereads": []}
    parent = f"{owner}.T_PARENT_{fixture_id}"

    def call(name, arguments, expected):
        reply = client.rpc("tools/call", {"name": name, "arguments": arguments})
        row["actual"]["calls"].append({"tool": name, "input_sha256": api.sha256(arguments),
                                        "actual": api.scrub(api.tool_payload(reply))})
        api.verify_envelope(reply)
        api.verify_expect({**expected, "deprecations": []}, reply)
        return api.tool_payload(reply)["structuredContent"]

    def reread(sql, expected=None):
        values = api.db_rows(connection, sql)
        row["actual"]["independent_rereads"].append({"sql": sql, "rows": api.scrub(values)})
        if expected is not None:
            api.require(values == expected, "wrapper independent database reread differs")
        return values

    def reset_parent():
        api.apply_setup(connection, [{"sql": f"UPDATE {parent} SET LABEL='parent-1' WHERE ID=1"}])

    try:
        _drop(api, client)
        api.elevate(client, case["level"])
        if kind == "wrapper_without_token":
            reset_parent()
            marker = "W4MARK_" + secrets.token_hex(10).upper()
            sql = f"UPDATE {parent} SET LABEL='unexpected-alias-write' WHERE ID=1 /* {marker} */"
            api.require(api.vsql_marker_count(connection, marker) == 0, "wrapper marker was already present")
            before = _audit_offset(audit_path)
            call("execute_approved", {"sql": sql, "commit": True}, {"error_class": "INVALID_ARGUMENTS"})
            reread(f"SELECT LABEL FROM {parent} WHERE ID=1", [["parent-1"]])
            api.require(api.vsql_marker_count(connection, marker) == 0, "unapproved wrapper SQL reached Oracle")
            records = _audit_since(audit_path, before)
            api.require(not any(record.get("decision") == "ALLOWED" for record in records),
                        "unapproved wrapper reached an execution audit")
        elif kind == "wrapper_execute":
            sql = f"UPDATE {parent} SET LABEL='w4-alias-approved' WHERE ID=1"
            outcomes = []
            for tool in ("oracle_execute", "execute_approved"):
                reset_parent()
                before = _audit_offset(audit_path)
                preview = call("oracle_preview_sql", {"sql": sql, "commit": True},
                               {"json_subset": {"execute_confirmation": {}}})
                token = preview["execute_confirmation"]["confirm"]
                arguments = ({"sql": sql, "confirm": token, "commit": True} if tool == "oracle_execute"
                             else {"token": token, "commit": True})
                result = call(tool, arguments, {"json_subset": {"executed": True, "committed": True,
                                                                "rolled_back": False, "rows_affected": 1}})
                state = reread(f"SELECT LABEL FROM {parent} WHERE ID=1", [["w4-alias-approved"]])
                records = _audit_since(audit_path, before)
                api.verify_audit_records([{"tool": "oracle_execute", "decision": "ALLOWED", "outcome": "PENDING"},
                                          {"tool": "oracle_execute", "decision": "ALLOWED", "outcome": "SUCCEEDED",
                                           "rows_affected": 1}], records)
                outcomes.append({"result": _normal(api, result, spec["index"]), "state": state,
                                 "audit": _audit_projection(records, spec["index"])})
            api.require(outcomes[0] == outcomes[1], "approval wrapper differs from canonical committed execution")
            before = _audit_offset(audit_path)
            call("execute_approved", {"token": token, "commit": True}, {"error_class": "CHALLENGE_REQUIRED"})
            reread(f"SELECT LABEL FROM {parent} WHERE ID=1", [["w4-alias-approved"]])
            api.require(not any(r.get("decision") == "ALLOWED" for r in _audit_since(audit_path, before)),
                        "consumed approval wrapper token was executed again")
        elif kind in {"wrapper_deploy", "wrapper_wait_timeout"}:
            name = "P_DAL_" + fixture_id
            original = f"CREATE OR REPLACE PROCEDURE {owner}.{name} AS BEGIN NULL; END;"
            source = f"CREATE OR REPLACE PROCEDURE {owner}.{name} AS\nBEGIN\n NULL; -- w4-alias-deploy\nEND;"
            tools = ("oracle_create_or_replace", "deploy_ddl") if kind == "wrapper_deploy" else ("deploy_ddl",)
            outcomes = []
            for tool in tools:
                api.apply_setup(connection, [{"sql": original}])
                args = {"source_code" if tool == "oracle_create_or_replace" else "ddl": source}
                if kind == "wrapper_wait_timeout":
                    args.update({"wait_seconds": 7, "timeout_seconds": 2})
                    baseline = reread(f"SELECT TEXT FROM ALL_SOURCE WHERE OWNER='{owner}' AND NAME='{name}' AND TYPE='PROCEDURE' ORDER BY LINE")
                    before = _audit_offset(audit_path)
                    call(tool, {**args, "timeout_seconds": 0}, {"error_class": "INVALID_ARGUMENTS"})
                    reread(f"SELECT TEXT FROM ALL_SOURCE WHERE OWNER='{owner}' AND NAME='{name}' AND TYPE='PROCEDURE' ORDER BY LINE", baseline)
                    api.require(not any(r.get("decision") == "ALLOWED" for r in _audit_since(audit_path, before)),
                                "invalid wrapper timeout reached execution")
                before = _audit_offset(audit_path)
                preview = call(tool, args, {"json_subset": {"confirmation": {}, "preview": True, "applied": False}})
                result = call(tool, {**args, "execute": True, "confirm": preview["confirmation"]["confirm"]},
                              {"json_subset": {"applied": True, "committed": True, "error_count": 0}})
                reread(f"SELECT STATUS FROM ALL_OBJECTS WHERE OWNER='{owner}' AND OBJECT_NAME='{name}' AND OBJECT_TYPE='PROCEDURE'", [["VALID"]])
                reread(f"SELECT COUNT(*) FROM ALL_SOURCE WHERE OWNER='{owner}' AND NAME='{name}' AND INSTR(TEXT,'w4-alias-deploy')>0", [[1]])
                state = reread(f"SELECT TEXT FROM ALL_SOURCE WHERE OWNER='{owner}' AND NAME='{name}' AND TYPE='PROCEDURE' ORDER BY LINE")
                if tool == "deploy_ddl":
                    for response in (preview, result):
                        api.require(response.get("compatibility_tool") == tool
                                    and response.get("wait_seconds") == args.get("wait_seconds", 0)
                                    and response.get("deploy_name") is None,
                                    "DDL wrapper documented compatibility fields differ")
                    result = {k: v for k, v in result.items()
                              if k not in {"compatibility_tool", "wait_seconds", "deploy_name"}}
                records = _audit_since(audit_path, before)
                api.verify_audit_records([{"tool": "oracle_create_or_replace", "decision": "ALLOWED", "outcome": "PENDING"},
                                          {"tool": "oracle_create_or_replace", "decision": "ALLOWED", "outcome": "SUCCEEDED"}], records)
                outcomes.append({"result": _normal(api, result, spec["index"]), "state": state,
                                 "audit": _audit_projection(records, spec["index"])})
            if len(outcomes) == 2:
                api.require(outcomes[0] == outcomes[1], "DDL wrapper differs from canonical guarded replacement")
        elif kind == "wrapper_schema":
            fields = ("OWNER", "OBJECT_NAME", "OBJECT_TYPE", "STATUS")
            independent = reread("SELECT OWNER, OBJECT_NAME, OBJECT_TYPE, STATUS FROM ALL_OBJECTS "
                f"WHERE OWNER='{owner}' AND OBJECT_TYPE IN ('TABLE','VIEW','PACKAGE') "
                "ORDER BY OWNER, OBJECT_TYPE, OBJECT_NAME")
            api.require(len(independent) > 2, "compact schema fixture cannot exercise continuation")
            full = call("oracle_schema_inspect", {"owner": owner, "max_rows": 1000},
                        {"json_subset": {"truncated": False}})
            identity = lambda item: tuple(item[field] for field in fields[:3])
            canonical = {identity(item): item for item in full["objects"]}

            def check_page(page, bound):
                api.require(page["max_rows"] == bound and len(page["objects"]) <= bound
                            and page["projection"] == ["TABLE", "VIEW", "PACKAGE"],
                            "compact schema bound or default projection differs")
                for item in page["objects"]:
                    other = canonical.get(identity(item))
                    api.require(other is not None and set(fields) <= item.keys() & other.keys()
                                and all(item[key] == other[key] for key in item.keys() & other.keys()),
                                "compact schema object differs from its canonical shared fields")
                return [[item[field] for field in fields] for item in page["objects"]]

            default = call("get_schema", {"owner": owner}, {"json_subset": {"max_rows": 100}})
            api.require(check_page(default, 100) == independent[:100], "compact default page differs from Oracle")
            capped = call("get_schema", {"owner": owner, "max_rows": 999},
                          {"json_subset": {"max_rows": 250}})
            api.require(check_page(capped, 250) == independent[:250], "compact capped page differs from Oracle")
            collected, seen, cursor, first_cursor = [], set(), None, None
            for _ in range(len(independent) + 1):
                args = {"owner": owner, "max_rows": 2}
                if cursor is not None:
                    args["cursor"] = cursor
                page = call("get_schema", args, {"json_subset": {"max_rows": 2}})
                collected.extend(check_page(page, 2))
                cursor = page["next_cursor"]
                api.require(page["truncated"] is (cursor is not None), "compact continuation flag differs")
                if cursor is None:
                    break
                api.require(isinstance(cursor, str) and len(cursor) > 16 and cursor not in seen,
                            "compact continuation cursor is invalid or repeats")
                seen.add(cursor)
                first_cursor = first_cursor or cursor
            api.require(collected == independent and first_cursor is not None
                        and len({tuple(value[:3]) for value in collected}) == len(collected),
                        "compact pagination has a gap, duplicate, wrong order or missing continuation")
            before = _audit_offset(audit_path)
            call("get_schema", {"owner": owner, "max_rows": 2, "cursor": first_cursor + "x"},
                 {"error_class": "INVALID_ARGUMENTS"})
            api.require(not any(record.get("decision") == "ALLOWED" for record in _audit_since(audit_path, before)),
                        "tampered compact cursor reached a catalog execution")
        elif kind == "wrapper_read_preview":
            name = "P_RAL_" + fixture_id
            api.apply_setup(connection, [{"sql": f"CREATE OR REPLACE PROCEDURE {owner}.{name} AS BEGIN NULL; END;"}])
            source_sql = f"SELECT TEXT FROM ALL_SOURCE WHERE OWNER='{owner}' AND NAME='{name}' AND TYPE='PROCEDURE' ORDER BY LINE"
            original = reread(source_sql)
            before = _audit_offset(audit_path)
            preview = call("oracle_patch_source", {"object_type": "PROCEDURE", "owner": owner, "name": name,
                "old_text": "NULL;", "new_text": "NULL; /* w4-alias-preview */"},
                {"json_subset": {"preview": True, "applied": False, "confirmation": {}}})
            reread(source_sql, original)
            result = call("read_patch_preview", {"name": f"{owner}.{name}", "max_chars": 1000},
                          {"json_subset": {"preview_available": True, "source": "in_memory_patch_preview"}})
            api.require(result["ddl_preview"] == preview["patched_ddl_preview"]
                        and result["patch_tool"] == "oracle_patch_source"
                        and result["compatibility_tool"] == "read_patch_preview",
                        "preview wrapper differs from the remembered canonical patch")
            reread(source_sql, original)
            api.require(not any(record.get("decision") == "ALLOWED" for record in _audit_since(audit_path, before)),
                        "read_patch_preview applied an unconfirmed source mutation")
        else:
            raise api.DriverError("unknown wrapper proof kind")
        row["actual"]["equivalent"] = True
        row["audit_pending_final_chain"] = True
    except Exception as exc:
        if kind in {"wrapper_deploy", "wrapper_wait_timeout"}:
            name = "P_DAL_" + fixture_id
            reread(f"SELECT TEXT FROM ALL_SOURCE WHERE OWNER='{owner}' AND NAME='{name}' AND TYPE='PROCEDURE' ORDER BY LINE")
        row["failure"] = {"class": type(exc).__name__, "detail": str(exc)[:500]}
    finally:
        if kind in {"wrapper_execute", "wrapper_without_token"}:
            reset_parent()
        _drop(api, client)
    row["input_sha256"] = api.sha256([{key: call[key] for key in ("tool", "input_sha256")}
                                      for call in row["actual"]["calls"]])
    row["duration_ms"] = round((time.monotonic() - start) * 1000)
    return row
