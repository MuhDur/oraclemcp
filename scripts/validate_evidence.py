#!/usr/bin/env python3
"""Offline validator for cross-repo-evidence-contract-v1 documents.

The contract has two layers, and both are load-bearing:

  structural  the four schemas/evidence/*.schema.json files (draft 2020-12).
              These are the cross-repo contract and are mirrored byte-for-byte
              between rust-oracledb and oraclemcp.

  semantic    cross-field invariants JSON Schema cannot express. A rate is only
              evidence if it can be recomputed from the counts; an artifact is
              only evidence for a commit if it was recorded at that commit.
              Neither is expressible in JSON Schema, which has no arithmetic and
              no comparison between fields. Mirroring only the .json files would
              therefore accept an arithmetic-mismatch document silently.

The rule codes are contract; this implementation is not. The sibling repo is
free to re-implement these checks in any language so long as the same document
yields the same code.

Dependencies: the Python standard library only. This validator runs inside the
Required graph, and a gate that needs a network install to say "no" is a gate
that says "yes" the day the network is down.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

CONTRACT = "cross-repo-evidence-contract-v1"

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "schemas" / "evidence"
FIXTURE_DIR = SCHEMA_DIR / "fixtures"

# Document `schema` discriminator -> schema file.
SCHEMA_FILES = {
    "required-proof/v1": "required-proof-v1.schema.json",
    "release-candidate-proof/v1": "release-candidate-proof-v1.schema.json",
    "mutation-result/v1": "mutation-result-v1.schema.json",
    "bead-close-evidence/v1": "bead-close-evidence-v1.schema.json",
}

# $defs that appear in more than one schema must be identical everywhere, or the
# four schemas drift into four dialects. Enforced by check_shared_defs().
SHARED_DEFS = (
    "sha1",
    "sourceRef",
    "timestamp",
    "nullableTimestamp",
    "resourceBudget",
    "artifactRef",
)

_DATE_TIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$"
)

# Rate comparison tolerance. Wide enough for float round-tripping through JSON,
# far tighter than any honest disagreement about a kill rate.
RATE_EPSILON = 1e-9


class Finding:
    """One reason a document is not evidence."""

    def __init__(self, code: str, path: str, message: str) -> None:
        self.code = code
        self.path = path
        self.message = message

    def as_dict(self) -> dict:
        return {"code": self.code, "path": self.path, "message": self.message}

    def __str__(self) -> str:
        return f"{self.code} at {self.path or '/'}: {self.message}"


# --------------------------------------------------------------------------
# structural layer: the subset of JSON Schema draft 2020-12 these schemas use
# --------------------------------------------------------------------------

def _json_eq(a, b) -> bool:
    """JSON equality. Python's `True == 1` is not JSON's."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if type(a) is not type(b):
        return False
    return a == b


def _type_ok(instance, name: str) -> bool:
    if name == "object":
        return isinstance(instance, dict)
    if name == "array":
        return isinstance(instance, list)
    if name == "string":
        return isinstance(instance, str)
    if name == "boolean":
        return isinstance(instance, bool)
    if name == "null":
        return instance is None
    if name == "integer":
        if isinstance(instance, bool):
            return False
        if isinstance(instance, int):
            return True
        return isinstance(instance, float) and instance.is_integer()
    if name == "number":
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)
    raise ValueError(f"unsupported type keyword: {name}")


def _resolve(root: dict, ref: str) -> dict:
    if not ref.startswith("#/"):
        raise ValueError(f"unsupported $ref (local refs only): {ref}")
    node = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        node = node[part]
    return node


def _structural(instance, schema: dict, root: dict, path: str, out: list) -> None:
    """Validate `instance` against `schema`, appending E_SCHEMA findings."""
    if "$ref" in schema:
        _structural(instance, _resolve(root, schema["$ref"]), root, path, out)

    if "type" in schema:
        names = schema["type"]
        names = [names] if isinstance(names, str) else names
        if not any(_type_ok(instance, n) for n in names):
            out.append(
                Finding(
                    "E_SCHEMA",
                    path,
                    f"expected type {'|'.join(names)}, got {_kind(instance)}",
                )
            )
            # Every other keyword assumes the type held; stop here to keep the
            # report pointed at the actual defect.
            return

    if "const" in schema and not _json_eq(instance, schema["const"]):
        out.append(
            Finding(
                "E_SCHEMA",
                path,
                f"expected const {schema['const']!r}, got {instance!r}",
            )
        )

    if "enum" in schema and not any(_json_eq(instance, e) for e in schema["enum"]):
        allowed = ", ".join(repr(e) for e in schema["enum"])
        out.append(Finding("E_SCHEMA", path, f"{instance!r} not one of [{allowed}]"))

    if isinstance(instance, str):
        pattern = schema.get("pattern")
        if pattern is not None and re.search(pattern, instance) is None:
            out.append(
                Finding("E_SCHEMA", path, f"{instance!r} does not match /{pattern}/")
            )
        if schema.get("format") == "date-time" and not _DATE_TIME_RE.match(instance):
            out.append(
                Finding("E_SCHEMA", path, f"{instance!r} is not an RFC 3339 date-time")
            )
        min_length = schema.get("minLength")
        if min_length is not None and len(instance) < min_length:
            out.append(
                Finding("E_SCHEMA", path, f"shorter than minLength {min_length}")
            )

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        minimum = schema.get("minimum")
        if minimum is not None and instance < minimum:
            out.append(Finding("E_SCHEMA", path, f"{instance} < minimum {minimum}"))
        maximum = schema.get("maximum")
        if maximum is not None and instance > maximum:
            out.append(Finding("E_SCHEMA", path, f"{instance} > maximum {maximum}"))

    if isinstance(instance, list):
        min_items = schema.get("minItems")
        if min_items is not None and len(instance) < min_items:
            out.append(
                Finding(
                    "E_SCHEMA", path, f"{len(instance)} items, minItems is {min_items}"
                )
            )
        item_schema = schema.get("items")
        if item_schema is not None:
            for i, item in enumerate(instance):
                _structural(item, item_schema, root, f"{path}/{i}", out)

    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                out.append(
                    Finding("E_SCHEMA", f"{path}/{key}", "required property is missing")
                )
        min_properties = schema.get("minProperties")
        if min_properties is not None and len(instance) < min_properties:
            out.append(
                Finding(
                    "E_SCHEMA",
                    path,
                    f"{len(instance)} properties, minProperties is {min_properties}",
                )
            )
        properties = schema.get("properties", {})
        for key, value in instance.items():
            child = f"{path}/{key}"
            if key in properties:
                _structural(value, properties[key], root, child, out)
                continue
            extra = schema.get("additionalProperties")
            if extra is False:
                out.append(
                    Finding("E_SCHEMA", child, "property is not allowed here")
                )
            elif isinstance(extra, dict):
                _structural(value, extra, root, child, out)


def _kind(instance) -> str:
    if instance is None:
        return "null"
    if isinstance(instance, bool):
        return "boolean"
    if isinstance(instance, str):
        return "string"
    if isinstance(instance, list):
        return "array"
    if isinstance(instance, dict):
        return "object"
    if isinstance(instance, int):
        return "integer"
    if isinstance(instance, float):
        return "number"
    return type(instance).__name__


# --------------------------------------------------------------------------
# semantic layer: cross-field invariants JSON Schema cannot express
# --------------------------------------------------------------------------

def _tree_clean(doc: dict, out: list) -> None:
    if doc["source"]["tree_clean"] is False:
        out.append(
            Finding(
                "E_TREE_DIRTY",
                "/source/tree_clean",
                "evidence was produced from a tree with uncommitted changes, so it "
                "describes code that exists at no commit and cannot be reproduced",
            )
        )


def _semantic_required_proof(doc: dict) -> list:
    out: list = []
    _tree_clean(doc, out)
    source_sha = doc["source"]["sha"]

    saw_required_fail = False
    saw_required_skip = False

    for i, cmd in enumerate(doc["commands"]):
        path = f"/commands/{i}"
        required = cmd["tier"] == "required"

        if cmd["sha"] != source_sha:
            out.append(
                Finding(
                    "E_STALE_SHA",
                    f"{path}/sha",
                    f"command ran against {cmd['sha']} but this proof is for "
                    f"{source_sha}; a result carried over from another commit is "
                    "not evidence for this one",
                )
            )

        if cmd["outcome"] == "skip":
            if not cmd.get("skip_reason"):
                out.append(
                    Finding(
                        "E_SKIP_WITHOUT_REASON",
                        f"{path}/skip_reason",
                        f"command {cmd['id']!r} was skipped without a machine-readable "
                        "reason; an unexplained skip is indistinguishable from a gap",
                    )
                )
            if required:
                saw_required_skip = True
        elif cmd["ended_at"] is None:
            # A skip legitimately has no end time: it never ran. Anything else
            # with a null end time claims an outcome it never reached.
            out.append(
                Finding(
                    "E_UNFINISHED",
                    f"{path}/ended_at",
                    f"command {cmd['id']!r} reports outcome {cmd['outcome']!r} but has "
                    "no end time, so it never ran to completion",
                )
            )

        if required and cmd["outcome"] == "fail":
            saw_required_fail = True

    derived = "fail" if (saw_required_fail or saw_required_skip) else "pass"
    if doc["verdict"] != derived:
        if doc["verdict"] == "pass" and saw_required_skip:
            out.append(
                Finding(
                    "E_SKIPPED_AS_PASS",
                    "/verdict",
                    "a required command was skipped, yet the proof declares pass; a "
                    "skip is not a pass, and a required-tier skip is a failure",
                )
            )
        else:
            out.append(
                Finding(
                    "E_VERDICT_MISMATCH",
                    "/verdict",
                    f"declared verdict {doc['verdict']!r} but the command records "
                    f"derive {derived!r}",
                )
            )
    return out


def _semantic_release_candidate_proof(doc: dict) -> list:
    out: list = []
    _tree_clean(doc, out)
    source_sha = doc["source"]["sha"]

    tag, version = doc["candidate"]["tag"], doc["candidate"]["version"]
    if tag != f"v{version}":
        out.append(
            Finding(
                "E_TAG_VERSION_MISMATCH",
                "/candidate/tag",
                f"tag {tag!r} does not name the version the tree ships ({version!r})",
            )
        )

    if doc["required_proof"]["sha"] != source_sha:
        out.append(
            Finding(
                "E_STALE_SHA",
                "/required_proof/sha",
                f"required proof is for {doc['required_proof']['sha']} but this "
                f"candidate is {source_sha}",
            )
        )

    if doc["required_ci"]["sha"] != source_sha:
        out.append(
            Finding(
                "E_STALE_SHA",
                "/required_ci/sha",
                f"CI status is for {doc['required_ci']['sha']} but this candidate is "
                f"{source_sha}",
            )
        )

    for i, job in enumerate(doc["required_ci"]["jobs"]):
        if job["tier"] != "required":
            continue
        if job["status"] != "completed" or job["conclusion"] != "success":
            out.append(
                Finding(
                    "E_REQUIRED_CI_NOT_GREEN",
                    f"/required_ci/jobs/{i}",
                    f"required job {job['name']!r} is status={job['status']!r} "
                    f"conclusion={job['conclusion']!r}; only a completed/success "
                    "required job counts as green",
                )
            )

    for i, artifact in enumerate(doc["artifacts"]):
        if artifact["sha"] != source_sha:
            out.append(
                Finding(
                    "E_ARTIFACT_SHA_MISMATCH",
                    f"/artifacts/{i}/sha",
                    f"artifact {artifact['kind']!r} was recorded for "
                    f"{artifact['sha']} but this candidate is {source_sha}; an "
                    "artifact from another commit is a substitution, not evidence",
                )
            )
    return out


def _semantic_mutation_result(doc: dict) -> list:
    out: list = []
    _tree_clean(doc, out)

    if doc["ended_at"] is None:
        out.append(
            Finding(
                "E_UNFINISHED",
                "/ended_at",
                "the run has no end time, so it never completed; its counts are "
                "whatever had been reached when it stopped, not a measurement",
            )
        )

    for i, shard in enumerate(doc["shards"]):
        if shard["status"] != "complete":
            out.append(
                Finding(
                    "E_SHARD_INCOMPLETE",
                    f"/shards/{i}/status",
                    f"shard {shard['id']!r} did not complete, so the mutant "
                    "population was never fully evaluated",
                )
            )

    counts = doc["counts"]
    caught, missed, timeout = counts["caught"], counts["missed"], counts["timeout"]
    denominator = (
        caught + missed
        if doc["denominator"] == "caught+missed"
        else caught + missed + timeout
    )
    expected = (caught / denominator) if denominator > 0 else 0.0
    if abs(doc["rate"] - expected) > RATE_EPSILON:
        out.append(
            Finding(
                "E_RATE_MISMATCH",
                "/rate",
                f"declared rate {doc['rate']} but {doc['denominator']} over these "
                f"counts gives {expected:.6f} ({caught}/{denominator})",
            )
        )

    if len(doc["survivors"]) != missed:
        out.append(
            Finding(
                "E_SURVIVOR_COUNT_MISMATCH",
                "/survivors",
                f"{len(doc['survivors'])} survivor records for {missed} missed "
                "mutants; every survivor must be classified, not counted",
            )
        )

    if len(doc["kills"]) != caught:
        out.append(
            Finding(
                "E_MISSING_WITNESS",
                "/kills",
                f"{len(doc['kills'])} witnessed kills for {caught} claimed; a kill "
                "without a witness is an assertion, not evidence",
            )
        )
    return out


def _semantic_bead_close_evidence(doc: dict) -> list:
    out: list = []
    _tree_clean(doc, out)
    source_sha = doc["source"]["sha"]

    for i, proof in enumerate(doc["proofs"]):
        if proof["sha"] != source_sha:
            out.append(
                Finding(
                    "E_STALE_SHA",
                    f"/proofs/{i}/sha",
                    f"proof is for {proof['sha']} but this close is for {source_sha}",
                )
            )

    live = doc["live_evidence"]
    if live["claimed"] and not live["artifacts"]:
        out.append(
            Finding(
                "E_LIVE_CLAIM_WITHOUT_ARTIFACT",
                "/live_evidence/artifacts",
                "the close claims live evidence but points at no artifact",
            )
        )
    for i, artifact in enumerate(live["artifacts"]):
        if artifact["sha"] != source_sha:
            out.append(
                Finding(
                    "E_ARTIFACT_SHA_MISMATCH",
                    f"/live_evidence/artifacts/{i}/sha",
                    f"live artifact {artifact['kind']!r} was recorded for "
                    f"{artifact['sha']} but this close is for {source_sha}",
                )
            )

    for i, defect in enumerate(doc["known_defects"]):
        if defect["bead_id"] is None:
            out.append(
                Finding(
                    "E_DEFECT_WITHOUT_BEAD",
                    f"/known_defects/{i}/bead_id",
                    "a defect known at close time has no bead tracking it, which is "
                    "how a known defect becomes an unknown one",
                )
            )

    readiness = doc["readiness"]
    if readiness["claim"] == "ready":
        if readiness["basis"] == "scoped-test":
            out.append(
                Finding(
                    "E_SCOPED_TEST_CANNOT_MARK_READY",
                    "/readiness/basis",
                    "a scoped test exercises part of the change and says nothing "
                    "about the rest, so it cannot mark a bead ready",
                )
            )
        elif readiness["basis"] == "manual-review":
            out.append(
                Finding(
                    "E_INSUFFICIENT_READINESS_BASIS",
                    "/readiness/basis",
                    "manual review is reading, not running; it cannot mark a bead "
                    "ready",
                )
            )
    return out


SEMANTIC_RULES = {
    "required-proof/v1": _semantic_required_proof,
    "release-candidate-proof/v1": _semantic_release_candidate_proof,
    "mutation-result/v1": _semantic_mutation_result,
    "bead-close-evidence/v1": _semantic_bead_close_evidence,
}


# --------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------

def load_schema(name: str) -> dict:
    return json.loads((SCHEMA_DIR / SCHEMA_FILES[name]).read_text())


def validate_doc(doc) -> list:
    """Validate one parsed document. Returns findings; empty means valid."""
    if not isinstance(doc, dict) or "schema" not in doc:
        return [
            Finding(
                "E_UNSUPPORTED_SCHEMA",
                "/schema",
                "document does not declare a schema, so there is no contract to "
                "hold it to",
            )
        ]

    name = doc["schema"]
    if name not in SCHEMA_FILES:
        return [
            Finding(
                "E_UNSUPPORTED_SCHEMA",
                "/schema",
                f"{name!r} is not part of {CONTRACT}; refusing to guess at its "
                "meaning",
            )
        ]

    schema = load_schema(name)
    findings: list = []
    _structural(doc, schema, schema, "", findings)
    if findings:
        # Semantic rules index into the document freely; running them over a
        # structurally invalid document would raise rather than report.
        return findings
    return SEMANTIC_RULES[name](doc)


def check_shared_defs() -> list:
    """Every $def shared by two schemas must be identical in both."""
    errors: list = []
    seen: dict = {}
    for name, filename in sorted(SCHEMA_FILES.items()):
        defs = load_schema(name).get("$defs", {})
        for def_name in SHARED_DEFS:
            if def_name not in defs:
                continue
            canonical = json.dumps(defs[def_name], sort_keys=True)
            if def_name in seen:
                origin, expected = seen[def_name]
                if canonical != expected:
                    errors.append(
                        f"$defs/{def_name} differs between {origin} and {filename}; "
                        "shared definitions must be identical or the four schemas "
                        "drift into four dialects"
                    )
            else:
                seen[def_name] = (filename, canonical)
    return errors


def check_fixtures() -> int:
    """Run the fixture suite. Valid fixtures must pass; invalid fixtures must be
    rejected for the exact declared reason, not merely rejected."""
    manifest = json.loads((FIXTURE_DIR / "manifest.json").read_text())
    failures = 0
    checked = 0

    for entry in manifest["valid"]:
        checked += 1
        path = FIXTURE_DIR / "valid" / entry["file"]
        findings = validate_doc(json.loads(path.read_text()))
        if findings:
            failures += 1
            print(f"FAIL {entry['file']}: expected valid, got:", file=sys.stderr)
            for f in findings:
                print(f"       {f}", file=sys.stderr)

    for entry in manifest["invalid"]:
        checked += 1
        path = FIXTURE_DIR / "invalid" / entry["file"]
        findings = validate_doc(json.loads(path.read_text()))
        want_code, want_path = entry["expect_code"], entry["expect_path"]
        got = ", ".join(f"{f.code}@{f.path}" for f in findings) or "no findings"

        # Each negative fixture must be a valid document with exactly one defect
        # planted in it. Demanding a single finding proves two things at once:
        # the rule fires for its declared reason, and the fixture is not being
        # rejected for some unrelated mistake that would mask the rule going
        # dead. "It was rejected" is not the same claim as "this rule rejected
        # it", and only the second one is worth testing.
        if len(findings) != 1 or findings[0].code != want_code or findings[0].path != want_path:
            failures += 1
            print(
                f"FAIL {entry['file']}: expected exactly {want_code} at {want_path}, "
                f"got {got}",
                file=sys.stderr,
            )

    for error in check_shared_defs():
        failures += 1
        print(f"FAIL shared-defs: {error}", file=sys.stderr)

    if failures:
        print(f"\nevidence-contract: {failures} of {checked} checks failed", file=sys.stderr)
        return 1
    print(
        f"evidence-contract: {checked} fixtures OK "
        f"({len(manifest['valid'])} valid accepted, "
        f"{len(manifest['invalid'])} invalid rejected for the declared reason), "
        f"shared $defs identical across {len(SCHEMA_FILES)} schemas"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=f"Validate {CONTRACT} evidence documents offline."
    )
    parser.add_argument("files", nargs="*", type=Path, help="documents to validate")
    parser.add_argument(
        "--check-fixtures",
        action="store_true",
        help="run the fixture suite instead of validating files",
    )
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    args = parser.parse_args()

    if args.check_fixtures:
        return check_fixtures()

    if not args.files:
        parser.error("pass at least one document, or --check-fixtures")

    results = []
    worst = 0
    for path in args.files:
        findings = validate_doc(json.loads(path.read_text()))
        results.append(
            {
                "file": str(path),
                "ok": not findings,
                "findings": [f.as_dict() for f in findings],
            }
        )
        if findings:
            worst = 1

    if args.json:
        print(json.dumps({"results": results}, indent=2))
    else:
        for result in results:
            if result["ok"]:
                print(f"OK   {result['file']}")
            else:
                print(f"FAIL {result['file']}", file=sys.stderr)
                for finding in result["findings"]:
                    print(
                        f"       {finding['code']} at {finding['path'] or '/'}: "
                        f"{finding['message']}",
                        file=sys.stderr,
                    )
    return worst


if __name__ == "__main__":
    sys.exit(main())
