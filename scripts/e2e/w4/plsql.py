"""Real MCP PL/SQL fixture cases and independent catalog comparisons for W4."""

import copy
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time


ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "tests/fixtures/plsql"
FAMILY = Path(__file__).resolve().parent / "cases/plsql.json"
LIVE_TOOLS = {"oracle_lineage", "oracle_plsql_live_snapshot", "oracle_plsql_blast_radius"}
FIXTURE_TOKEN = re.compile(r"\$\{plsql_(source|project|json):([a-zA-Z0-9_./-]+)\}\Z")


def engine_tools(descriptors):
    """Select the advertised engine surface; the denominator is never a literal."""
    return {name for name in descriptors if name.startswith("oracle_plsql_") or name == "oracle_lineage"}


def fixture_path(d, name):
    path = (FIXTURES / name).resolve()
    d.require(path.is_relative_to(FIXTURES.resolve()) and ".." not in Path(name).parts,
              "PL/SQL fixture path escapes its committed source root")
    d.require(path.exists(), f"PL/SQL fixture is missing: {name}")
    return path


def expand_fixture(d, token, run_id, transport, lane):
    match = FIXTURE_TOKEN.fullmatch(token)
    d.require(match is not None, "invalid PL/SQL fixture placeholder")
    kind, name = match.groups()
    path = fixture_path(d, name)
    if kind == "project":
        d.require(path.is_dir(), "PL/SQL project fixture must be a directory")
        if name == "live":
            rendered = d.plsql_project_path(run_id, transport, lane) / "catalog-fixture"
            rendered.mkdir(parents=True, exist_ok=True)
            for source in sorted(path.glob("*.sql")):
                (rendered / source.name).write_text(d.expand_case(
                    source.read_text(), run_id, transport, lane))
            return str(rendered)
        return str(path)
    d.require(path.is_file(), "PL/SQL source/JSON fixture must be a file")
    source = path.read_text()
    return json.loads(source) if kind == "json" else source


def golden_reply(d, case, reply):
    """Normalize only the declared absolute fixture-root response metadata."""
    if not case["expect"].get("golden", "").startswith("plsql/"):
        return reply
    normalized = copy.deepcopy(reply)
    value = d.tool_payload(normalized)["structuredContent"]
    if case["tool"] == "oracle_plsql_analyze":
        # The adapter sorts this metadata sample by logical_id only. A package
        # spec/body can share that key, so hash-map iteration swaps their IDs.
        # Canonicalize ties while retaining every row, ID and semantic value.
        value["ide"]["definition_sample"].sort(key=lambda item: (
            item["logical_id"], item["node_id"]))
    if "project_root" in value:
        actual = value["project_root"]
        requested = case["call"]["arguments"].get("project_root")
        d.require(actual == requested, "PL/SQL response changed the requested project identity")
        path = Path(actual).resolve()
        d.require(path.is_relative_to(FIXTURES.resolve()), "PL/SQL golden project is outside fixtures")
        value["project_root"] = "<plsql-fixture>/" + path.relative_to(FIXTURES.resolve()).as_posix()
    return normalized


def verify_offline_coverage(d, descriptors, cases):
    advertised = engine_tools(descriptors) - LIVE_TOOLS
    positive = {case["tool"] for case in cases if "error_class" not in case["expect"]}
    negative = {case["tool"] for case in cases if "error_class" in case["expect"]}
    d.require(advertised and positive == advertised and negative == advertised,
              f"PL/SQL offline registry coverage differs: positive={sorted(positive ^ advertised)}, "
              f"negative={sorted(negative ^ advertised)}")
    return sorted(advertised)


def registry_coverage(d, descriptors, cases):
    names = engine_tools(descriptors)
    if not names:
        return {"advertised": [], "count": 0}
    declared = [case for case in cases if case["case_id"] in
                {item["case_id"] for item in json.loads(FAMILY.read_text())}]
    positive = {case["tool"] for case in declared if "error_class" not in case["expect"]}
    negative = {case["tool"] for case in declared if "error_class" in case["expect"]}
    d.require(positive == names and negative == names,
              "PL/SQL case declarations do not cover the advertised positive/negative surface")
    return {"advertised": sorted(names), "count": len(names),
            "positive": sorted(positive), "negative": sorted(negative)}


def verify_case(d, case, reply, row, connection):
    if case["case_id"] not in {item["case_id"] for item in json.loads(FAMILY.read_text())}:
        return
    payload = d.tool_payload(reply)
    value = payload["structuredContent"]
    if "error_class" in case["expect"]:
        if case["case_id"] == "w4_plsql_parse_syntax_error_typed":
            d.require("parser error" in value.get("message", ""),
                      "malformed fixture did not reach real grammar validation")
        return
    d.require(payload.get("isError") is False, "PL/SQL positive fixture returned a refusal")
    tool = case["tool"]
    if tool in LIVE_TOOLS:
        verify_live_case(d, case, value, row, connection)
        return
    if tool == "oracle_plsql_parse":
        d.require(value["declarations"][0]["name"] == "W4_PARSE"
                  and value["error_count"] == 0 and value["recovered"] is False,
                  "valid routine did not produce its actual grammar declaration")
    elif tool == "oracle_plsql_analyze":
        expected_files = len(list((FIXTURES / "project").iterdir()))
        d.require(value["file_count"] == expected_files
                  and value["completeness"]["files_recovered"] == 0,
                  "analysis omitted or recovered a committed fixture file")
        d.require(any(edge["from"] == "ORDER_API.TOTAL" and edge["to"] == "APP.ORDERS"
                      and edge["kind"] == "Reads" for edge in value["ide"]["dependency_sample"]),
                  "real source read dependency is missing from analysis")
    elif tool == "oracle_plsql_lineage":
        d.require(value.get("found") is True
                  and [node["logical_id"] for node in value["result"]["affected_nodes"]]
                      == ["ORDER_API.TOTAL"], "source-derived dependent differs")
        d.require(value["result"]["edges"] == [{"confidence": "heuristic", "kind": "Reads",
                  "source": "ORDER_API.TOTAL", "target": "APP.ORDERS"}],
                  "source-derived lineage lost or changed the actual read edge")
    elif tool == "oracle_plsql_what_breaks":
        invalidations = value["payload"]["invalidations"]
        d.require(len(invalidations) == 1 and invalidations[0]["reason_code"] == "package_spec_changed"
                  and invalidations[0]["owner_symbol"] == 1 and invalidations[0]["name_symbol"] == 2,
                  "package specification change did not produce its direct invalidation")
    elif tool == "oracle_plsql_sast":
        report = value["report"]
        d.require(value["rule_evaluation_count"] == report["rules_run"] + report["rules_gated"]
                  and report["rules_run"] >= 1 and report["rules_gated"] > 0,
                  "SAST fixture did not execute the real rule or concealed missing fact families")
        if case["case_id"] == "w4_plsql_sast_concat_dynamic_sql_finding":
            d.require(len(report["findings"]) == 1 and report["findings"][0]["rule_id"] == "SEC001"
                      and report["findings"][0]["severity"] == "critical",
                      "unsafe concatenation has no real critical SEC001 finding")
        else:
            d.require(report["findings"] == [], "constant SQL produced a spurious SAST finding")
    elif tool == "oracle_plsql_doc":
        if "markdown" in value:
            d.require("# ORDER_API" in value["markdown"] and "Order identifier." in value["markdown"],
                      "documentation renderer omitted the fixture package or parameter")
        else:
            d.require(any("recorded order amount" in comment["text"] for comment in value["matches"]),
                      "documentation extractor did not read the committed source comment")


def prepare_case(d, client, case, row, connection):
    """Resolve public symbol IDs from the real catalog after native fixture DDL."""
    if case["case_id"] != "w4_plsql_blast_radius_dependents_exact":
        return
    arguments = case["call"]["arguments"]
    owner = arguments["schemas"][0]
    package = "PKG_W4_" + owner.removeprefix("W4O_")
    reply = client.rpc("tools/call", {"name": "oracle_plsql_live_snapshot", "arguments": {
        "schemas": [owner], "include_plscope": False, "include_snapshot": True}})
    d.verify_envelope(reply)
    payload = d.tool_payload(reply)
    if payload.get("isError") is True:
        row["symbol_resolution_refusal"] = d.scrub(payload)
    d.require(payload.get("isError") is False, "blast symbol resolution refused the catalog")
    snapshot = payload["structuredContent"]
    d.require(snapshot.get("snapshot_export", {}).get("status") in {"complete", "partial"}
              and "catalog_snapshot" in snapshot, "blast fixture catalog is not exportable")
    symbols = snapshot["catalog_snapshot"]["interner"]
    case["_plsql_symbols"] = symbols
    arguments["changeset"] = {"objects": [{"owner": symbols.index(owner),
        "name": symbols.index(package), "kind": "PackageSpec", "new_hash": "new",
        "previous_hash": "old", "file_paths": ["fixture-package.pks"], "uncertainties": []}],
        "unclassified_files": []}
    row["symbol_resolution"] = {"symbol_count": len(symbols), "owner": symbols.index(owner),
                                "package": symbols.index(package),
                                "snapshot_export": snapshot["snapshot_export"]}


def native_rows(connection, sql, binds):
    with connection.cursor() as cursor:
        return [list(item) for item in cursor.execute(sql, binds).fetchall()]


def verify_live_case(d, case, value, row, connection):
    arguments = case["call"]["arguments"]
    if case["tool"] == "oracle_lineage":
        owner, name, column = arguments["owner"], arguments["object"], arguments["column"]
        native = native_rows(connection, "SELECT table_name,column_name,data_type FROM "
            "SYS.all_tab_columns WHERE owner=:owner AND table_name IN (:object,:base) "
            "ORDER BY table_name,column_id", {"owner": owner, "object": name,
            "base": name.replace("V_TYPES_", "T_TYPES_")})
        row["native_columns"] = native
        if case["case_id"] == "w4_plsql_live_missing_object_not_found":
            d.require(native == [] and value.get("found") is False,
                      "missing fixture column was reported as found")
            return
        d.require(value.get("found") is True and value["catalog_marker"]["status"] == "verified",
                  "live column target is absent or not verified")
        d.require([name, column, "NUMBER"] in native, "target column lacks native catalog proof")
        upstream = value["upstream"]["edges"]
        base = name.replace("V_TYPES_", "T_TYPES_")
        d.require([base, column, "NUMBER"] in native, "base column lacks native catalog proof")
        # The source graph canonicalizes unquoted Oracle names to lower case.
        expected = (owner + "." + base + "." + column).lower()
        d.require(len(upstream) == 1 and upstream[0]["object"] == expected
                  and upstream[0]["catalog_marker"]["status"] == "verified"
                  and upstream[0]["edge_kind"] == "DerivesColumn"
                  and upstream[0]["confidence"] == "Exact"
                  and upstream[0]["is_unknown_column_of_table"] is False,
                  "live source-derived view edge differs from its native columns")
        d.require(value["catalog_cross_check"]["enabled"] is True,
                  "live lineage omitted its guarded catalog cross-check")
        return
    owner = arguments["schemas"][0]
    if case["tool"] == "oracle_plsql_live_snapshot":
        supported = "('TABLE','VIEW','MATERIALIZED VIEW','SEQUENCE','TYPE','PACKAGE'," \
                    "'PROCEDURE','FUNCTION','TRIGGER','EDITIONING VIEW')"
        native = native_rows(connection, "SELECT object_name,object_type,status FROM SYS.all_objects "
            "WHERE owner=:owner AND object_type IN " + supported + " ORDER BY object_name,object_type",
            {"owner": owner})
        row["native_objects"] = native
        counts = {item["row_set"]: item["row_count"] for item in value["row_counts"]}
        d.require(counts["objects"] == len(native) and len(native) > 0,
                  "live snapshot object count differs from independent ALL_OBJECTS")
        if not arguments.get("include_snapshot"):
            d.require("catalog_snapshot" not in value, "summary unexpectedly exports a catalog")
            return
        status = value["snapshot_export"]
        d.require(status["status"] in {"complete", "partial"}, "small owned fixture is too large")
        snapshot = value["catalog_snapshot"]
        symbols = snapshot["interner"]
        schema = snapshot["schemas"][str(symbols.index(owner))]
        kinds = {"Table": "TABLE", "View": "VIEW", "MaterializedView": "MATERIALIZED VIEW",
                 "Sequence": "SEQUENCE", "Type": "TYPE", "Package": "PACKAGE",
                 "Procedure": "PROCEDURE", "Function": "FUNCTION", "Trigger": "TRIGGER",
                 "EditioningView": "EDITIONING VIEW"}
        objects = []
        for tagged in schema["objects"].values():
            d.require(len(tagged) == 1, "catalog object has no exact type tag")
            kind, item = next(iter(tagged.items()))
            common = item["common"]
            d.require(symbols[common["owner"]] == owner, "catalog changed object ownership")
            objects.append([symbols[common["name"]], kinds[kind], common["status"].upper()])
        d.require(sorted(objects) == native, "catalog object identities/types/status differ from Oracle")
        public = native_rows(connection, "SELECT synonym_name FROM SYS.all_synonyms "
            "WHERE owner='PUBLIC' ORDER BY synonym_name", {})
        page = status["public_synonyms"]
        public_schema = snapshot["schemas"].get(str(symbols.index("PUBLIC")), {})
        names = sorted(symbols[int(name)] for name in public_schema.get("synonyms", {}))
        offset = arguments.get("public_synonym_offset", 0)
        expected = [item[0] for item in public[offset:offset + page["limit"]]]
        d.require(names == expected and page["total"] == len(public)
                  and page["included"] == len(expected)
                  and page["omitted"] == len(public) - len(expected)
                  and page["next_offset"] == (offset + len(expected)
                       if offset + len(expected) < len(public) else None),
                  "PUBLIC synonym page differs from independent ordered catalog rows")
        row["native_public_synonym_page"] = {"total": len(public), "offset": offset, "names": expected}
        return
    symbols = case["_plsql_symbols"]
    package = "PKG_W4_" + owner.removeprefix("W4O_")
    native = native_rows(connection, "SELECT owner,name,type,referenced_owner,referenced_name,"
        "referenced_type FROM SYS.all_dependencies WHERE owner=:owner AND referenced_owner=:owner "
        "AND referenced_link_name IS NULL ORDER BY name,type,referenced_name,referenced_type",
        {"owner": owner})
    expected = {}
    frontier = [((owner, package, "PACKAGE"), 0)]
    while frontier:
        target, distance = frontier.pop(0)
        for item in native:
            node = tuple(item[:3])
            if tuple(item[3:]) == target and node not in expected:
                expected[node] = distance + 1
                frontier.append((node, distance + 1))
    d.require(any(distance == 2 for distance in expected.values()) and len(expected) >= 3,
              "native fixture has no direct/transitive package dependency chain")
    prediction = value["prediction"]["payload"]
    actual = sorted([symbols[item["owner_symbol"]], symbols[item["name_symbol"]],
                     item["object_type"], item["distance"]] for item in prediction["invalidations"])
    expected_rows = sorted([[*node, distance] for node, distance in expected.items()]
                           + [[owner, package, "PACKAGE", 1]])
    row["native_dependencies"] = native
    row["dependency_comparison"] = {"expected": expected_rows, "actual": actual}
    d.require(actual == expected_rows, "live blast radius differs from independent dependency BFS")
    recompile = sorted([symbols[item["owner_symbol"]], symbols[item["name_symbol"]],
                        item["object_type"]] for item in prediction["recompile_plan"])
    d.require(recompile == sorted([list(node) for node in expected])
              and all(item["force_compile"] is True for item in prediction["recompile_plan"]),
              "recompile guidance omits or invents a native fixture dependent")
    d.require(prediction["summary"]["invalidation_count"] == len(expected_rows)
              and prediction["summary"]["recompile_count"] == len(expected)
              and prediction["summary"]["uncertainty_count"] == len(prediction["uncertainties"]),
              "blast radius summary differs from its actual rows")


@contextlib.contextmanager
def owned_broker(d, binary, env, work):
    """Own the actual broker process so a test cannot leave detached workers."""
    with (work / "broker.stdout.log").open("w") as out, (work / "broker.stderr.log").open("w") as err:
        process = subprocess.Popen([str(binary), "broker", "--allow-no-auth"], env=env,
                                   stdin=subprocess.DEVNULL, stdout=out, stderr=err)
        try:
            locator = Path(env["XDG_STATE_HOME"]) / "oraclemcp/broker.json"
            deadline = time.monotonic() + 30
            while not locator.exists():
                d.require(process.poll() is None, "offline broker exited during startup")
                d.require(time.monotonic() < deadline, "offline broker startup deadline expired")
                time.sleep(0.05)
            d.require(json.loads(locator.read_text())["pid"] == process.pid,
                      "offline broker locator does not identify this test's child")
            yield
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)


@contextlib.contextmanager
def offline_client(d, binary, env, transport, work):
    with owned_broker(d, binary, env, work):
        client = (d.StdioClient(binary, None, env) if transport == "stdio" else
                  d.HttpClient(binary, None, env, d.pick_port(), None, "offline-plsql"))
        try:
            yield client
        finally:
            client.close()


def run_offline(d, args):
    """Run actual stdio/HTTP calls without configuring any database profile."""
    d.require(args.binary is not None and args.binary.is_file(),
              "offline PL/SQL tests need --binary pointing to the actual built server")
    d.require(not args.contract_only and not args.alias_contracts_only,
              "offline PL/SQL cases do not run database contract/alias families")
    binary = args.binary.resolve()
    source_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    cases = [d.validate_case(case, "plsql.json") for case in json.loads(FAMILY.read_text())
             if case["tool"] not in LIVE_TOOLS]
    if args.case:
        requested = set(args.case)
        d.require(requested <= {case["case_id"] for case in cases}, "unknown offline PL/SQL case")
        cases = [case for case in cases if case["case_id"] in requested]
    base = ROOT / "target/e2e/w4/offline"
    work = base / ("plsql-" + secrets.token_hex(8))
    work.mkdir(parents=True)
    config = work / "profiles.toml"
    config.write_text("profiles = []\n")
    env = {name: value for name, value in os.environ.items()
           if not name.startswith(("ORACLEMCP_", "W4_"))}
    env.pop("RUST_MIN_STACK", None)
    env.update(ORACLEMCP_CONFIG=str(config), ORACLEMCP_AUDIT_KEY=secrets.token_hex(32))
    rows = []
    output = {"lane": "offline", "verdict": "fail", "checkout_sha": source_sha,
              "binary_source_sha": args.binary_source_sha,
              "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "configured_profiles": [], "registry": [], "cases": rows, "run_dir": str(work),
              "transports": list(d.selected_transports(args)), "summary": {}}
    d.persist_run_results(base, output)
    try:
        registry = None
        for transport in d.selected_transports(args):
            client_env = {**env, "XDG_STATE_HOME": str(work / transport / "state")}
            audit = Path(client_env["XDG_STATE_HOME"]) / "oraclemcp/audit/audit.jsonl"
            transport_work = work / transport
            transport_work.mkdir(parents=True, exist_ok=True)
            with offline_client(d, binary, client_env, transport, transport_work) as client:
                d.initialize(client)
                descriptors = d.list_tools(client)
                names = engine_tools(descriptors)
                d.require(names, "server does not advertise its embedded PL/SQL engine")
                if registry is not None:
                    d.require(registry == names, "offline stdio/HTTP engine registries differ")
                registry = names
                output["registry"] = sorted(names)
                output["registry_count"] = len(names)
                expanded = [d.expand_case(case, "W40000000000", transport, "offline") for case in cases]
                if not args.case:
                    output["offline_tools"] = verify_offline_coverage(d, descriptors, expanded)
                for case in expanded:
                    row = d.run_case(client, case, transport, "offline", set(), None,
                                     d.BarrierPool(), binary, audit, client_env,
                                     descriptors.get(case["tool"]))
                    rows.append(row)
                    d.persist_run_results(base, output)
                    d.persist_run_results(work, output)
                if audit.is_file():
                    checked = subprocess.run([str(binary), "--json", "audit", "verify", str(audit)],
                                             cwd=ROOT, env=client_env, capture_output=True,
                                             text=True, timeout=60)
                    verification = json.loads(checked.stdout)
                    output.setdefault("audit_verification", {})[transport] = verification
                    if checked.stderr:
                        print(checked.stderr, file=d.sys.stderr, end="")
                    # Static calls with no profiles produce no database audit
                    # actions. Verify that exact empty chain; a head anchor is
                    # first created by a durable action, which this lane forbids.
                    d.require(checked.returncode == 0 and verification.get("ok") is True
                              and verification.get("records") == 0
                              and not d.audit_records(audit)
                              and verification.get("anchor", {}).get("status") == "absent",
                              f"offline audit chain failed: {d.compact(verification)}")
        output["summary"] = d.summary_table(rows)
        output["verdict"] = d.run_verdict(rows)
        d.require(output["verdict"] == "pass", "offline PL/SQL cases failed")
        d.require(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
                  == source_sha, "checkout changed during offline PL/SQL proof")
        print(d.compact({"lane": "offline", "registry_count": len(registry),
                         "cases": len(rows), "verdict": output["verdict"],
                         "results": str(base / "results.json")}))
    except BaseException as exc:
        output["verdict"] = "fail"
        output["run_failure"] = {"class": type(exc).__name__, "detail": str(exc)[:240]}
        raise
    finally:
        d.persist_run_results(base, output)
        d.persist_run_results(work, output)
