#!/usr/bin/env python3
"""Regression tests for plan_bead_graph_lint.py."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


SCRIPT = Path(__file__).with_name("plan_bead_graph_lint.py")
SPEC = importlib.util.spec_from_file_location("plan_bead_graph_lint", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class PlanBeadGraphLintTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        (self.root / "plan.md").write_text("one\ntwo\nthree\nfour\n", encoding="utf-8")
        (self.root / "server.jsonl").write_text("", encoding="utf-8")
        (self.root / "driver.jsonl").write_text("", encoding="utf-8")
        self.document = self.valid_document()

    @staticmethod
    def task(slug: str, repo: str, **overrides: Any) -> dict[str, Any]:
        task: dict[str, Any] = {
            "slug": slug,
            "tracking_label": f"plan:program:{slug}",
            "repo": repo,
            "title": f"Implement {slug} contract",
            "type": "task",
            "priority": 1,
            "labels": ["engineering-program", "cluster-test", f"plan:program:{slug}"],
            "source_refs": ["plan.md:1-2"],
            "scope": "Implement the complete observable scope for this normalized program task.",
            "description": "A self-contained implementation description long enough for a future agent.",
            "acceptance_criteria": ["The observable contract is covered by a discriminating test."],
            "evidence": ["A focused test result and the exact landed file paths."],
            "tier": "tier-1",
            "depends_on": [],
            "handoffs": [],
            "operator_gate": "none",
            "promotion": "create",
        }
        task.update(overrides)
        return task

    @staticmethod
    def handoff(task: str, **overrides: Any) -> dict[str, Any]:
        handoff: dict[str, Any] = {
            "task": task,
            "artifact": "Exact-SHA handoff manifest with artifact digest",
            "checksum": "required",
        }
        handoff.update(overrides)
        return handoff

    def valid_document(self) -> dict[str, Any]:
        foundation = self.task("foundation", "server")
        driver = self.task("driver-fix", "driver")
        integration = self.task(
            "integration",
            "server",
            depends_on=["foundation"],
            handoffs=[self.handoff("driver-fix")],
            parent="foundation",
        )
        return {
            "schema": MODULE.SCHEMA,
            "program": "engineering-program",
            "source_document": {
                "path": "plan.md",
                "sha256": hashlib.sha256((self.root / "plan.md").read_bytes()).hexdigest(),
            },
            "repositories": ["server", "driver"],
            "trackers": {
                "server": {"path": "server.jsonl", "source_repo": "oraclemcp"},
                "driver": {"path": "driver.jsonl", "source_repo": "rust-oracledb"},
            },
            "release_targets": [
                {"repo": "server", "current": "0.9.0", "next": "0.9.1", "bump": "patch"},
                {"repo": "driver", "current": "0.8.4", "next": "0.8.5", "bump": "patch"},
            ],
            "tasks": [foundation, driver, integration],
        }

    def messages(self, document: dict[str, Any] | None = None) -> list[str]:
        selected = self.document if document is None else document
        return [finding.render() for finding in MODULE.validate(selected, self.root)]

    def assert_has(self, needle: str, document: dict[str, Any] | None = None) -> None:
        messages = self.messages(document)
        self.assertTrue(any(needle in message for message in messages), messages)

    def test_valid_two_repository_graph(self) -> None:
        self.assertEqual(self.messages(), [])

    def test_source_document_checksum_is_binding(self) -> None:
        self.document["source_document"]["sha256"] = "0" * 64
        self.assert_has("checksum mismatch")
        self.document["source_document"]["sha256"] = "not-a-digest"
        self.assert_has("lowercase SHA-256")

    def test_duplicate_slug_and_tracking_label_fail(self) -> None:
        duplicate = copy.deepcopy(self.document["tasks"][0])
        self.document["tasks"].append(duplicate)
        self.assert_has("duplicate slug")
        self.assert_has("duplicate tracking label")

    def test_duplicate_task_label_fails(self) -> None:
        self.document["tasks"][0]["labels"].append("engineering-program")
        self.assert_has("duplicate labels")

    def test_missing_and_unknown_references_fail(self) -> None:
        self.document["tasks"][0]["depends_on"] = ["missing"]
        self.document["tasks"][2]["handoffs"] = [self.handoff("also-missing")]
        self.document["tasks"][1]["parent"] = "also-missing"
        self.assert_has("unknown task reference")
        self.assert_has("unknown parent")

    def test_cross_repository_edge_kinds_are_enforced(self) -> None:
        self.document["tasks"][0]["depends_on"] = ["driver-fix"]
        self.document["tasks"][2]["handoffs"] = [self.handoff("foundation")]
        self.assert_has("crosses repositories; use handoffs")
        self.assert_has("stays in one repository; use depends_on")

    def test_promoted_task_cannot_depend_on_deferred_native_task(self) -> None:
        self.document["tasks"][0].update(
            promotion="defer",
            condition="Wait for an accepted external prerequisite checksum.",
        )
        self.assert_has("promoted task cannot depend on non-promoted task")
        self.assert_has("promoted task cannot use a non-promoted parent")

    def test_self_edge_and_dependency_cycle_fail(self) -> None:
        self.document["tasks"][0]["depends_on"] = ["foundation"]
        self.assert_has("self-reference is forbidden")
        self.document["tasks"][0]["depends_on"] = ["integration"]
        self.assert_has("dependency/handoff cycle")

    def test_mixed_dependency_handoff_cycle_fails(self) -> None:
        self.document["tasks"][1]["handoffs"] = [self.handoff("foundation")]
        self.document["tasks"][0]["depends_on"] = ["integration"]
        self.assert_has("dependency/handoff cycle")

    def test_parent_cycle_fails(self) -> None:
        self.document["tasks"][0]["parent"] = "integration"
        self.assert_has("parent cycle")

    def test_mixed_parent_dependency_cycle_fails(self) -> None:
        self.document["tasks"][0]["parent"] = "integration"
        self.assert_has("dependency/handoff cycle")

    def test_required_self_contained_fields_fail_closed(self) -> None:
        task = self.document["tasks"][0]
        del task["acceptance_criteria"]
        task["description"] = "too short"
        task["scope"] = "too short"
        task["evidence"] = []
        task["priority"] = True
        self.assert_has("missing fields: acceptance_criteria")
        self.assert_has("at least 40")
        self.assert_has("evidence: must be a non-empty")
        self.assert_has("integer from 0 through 4")

    def test_invalid_scalar_types_never_crash(self) -> None:
        task = self.document["tasks"][0]
        for field in ("repo", "type", "tier", "operator_gate", "promotion"):
            task[field] = []
        self.document["release_targets"][0]["repo"] = []
        self.document["release_targets"][1]["bump"] = []
        messages = self.messages()
        for field in ("repo", "type", "tier", "operator_gate", "promotion", "bump"):
            self.assertTrue(any(field in message for message in messages), messages)

    def test_invalid_promotion_on_dependency_target_never_crashes(self) -> None:
        self.document["tasks"][0]["promotion"] = []
        self.assert_has("promotion: must be one of")

    def test_invalid_task_enum_and_title_fields_fail(self) -> None:
        task = self.document["tasks"][0]
        task.update(
            repo="unknown",
            type="story",
            tier="tier-9",
            operator_gate="maybe",
            promotion="later",
            title="short",
        )
        for needle in (
            "unknown repository",
            "must be one of",
            "tier",
            "operator_gate",
            "promotion",
            "at least 8",
        ):
            self.assert_has(needle)

    def test_promotion_contract_is_enforced(self) -> None:
        task = self.document["tasks"][0]
        task["promotion"] = "reuse"
        self.assert_has("existing_id: is required")
        task["promotion"] = "defer"
        self.assert_has("condition: must explain")
        task["condition"] = "Wait for the accepted upstream checksum handoff."
        self.assertFalse(any("condition:" in message for message in self.messages()))

    def test_reused_task_must_resolve_in_repo_tracker(self) -> None:
        task = self.document["tasks"][0]
        task.update(
            promotion="reuse",
            existing_id="server-existing-123",
            reuse_action="continue",
        )
        self.assert_has("does not resolve")
        (self.root / "server.jsonl").write_text(
            json.dumps({"id": "server-existing-123", "source_repo": "oraclemcp"}) + "\n",
            encoding="utf-8",
        )
        self.assertEqual(self.messages(), [])

    def test_deferred_existing_bead_mapping_must_resolve(self) -> None:
        task = self.document["tasks"][0]
        task.update(
            promotion="defer",
            existing_id="server-existing-123",
            condition="Wait for the accepted upstream checksum handoff.",
        )
        self.assert_has("does not resolve")
        (self.root / "server.jsonl").write_text(
            json.dumps({"id": "server-existing-123", "source_repo": "oraclemcp"}) + "\n",
            encoding="utf-8",
        )
        self.document["tasks"][2]["depends_on"] = []
        self.document["tasks"][2].pop("parent")
        self.assertEqual(self.messages(), [])

    def test_reused_task_must_match_tracker_repository_identity(self) -> None:
        task = self.document["tasks"][0]
        task.update(promotion="reuse", existing_id="driver-owned", reuse_action="continue")
        (self.root / "server.jsonl").write_text(
            json.dumps({"id": "driver-owned", "source_repo": "rust-oracledb"}) + "\n",
            encoding="utf-8",
        )
        self.assert_has("expected 'oraclemcp'")

    def test_existing_bead_cannot_map_to_two_tasks(self) -> None:
        (self.root / "server.jsonl").write_text(
            json.dumps({"id": "server-existing", "source_repo": "oraclemcp"}) + "\n",
            encoding="utf-8",
        )
        for task in (self.document["tasks"][0], self.document["tasks"][2]):
            task.update(
                promotion="reuse",
                existing_id="server-existing",
                reuse_action="continue",
            )
        self.assert_has("already mapped by task")

    def test_lineage_must_resolve_in_the_same_tracker(self) -> None:
        task = self.document["tasks"][0]
        task["lineage"] = [{"id": "server-prior", "relation": "supersedes"}]
        self.assert_has("does not resolve")
        (self.root / "server.jsonl").write_text(
            json.dumps({"id": "server-prior", "source_repo": "oraclemcp"}) + "\n",
            encoding="utf-8",
        )
        self.assertEqual(self.messages(), [])
        task["lineage"][0]["relation"] = "replaces"
        self.assert_has("must be one of")

    def test_lineage_cannot_self_reference_or_repeat_an_issue(self) -> None:
        (self.root / "server.jsonl").write_text(
            json.dumps({"id": "server-existing", "source_repo": "oraclemcp"}) + "\n",
            encoding="utf-8",
        )
        task = self.document["tasks"][0]
        task.update(
            promotion="reuse",
            existing_id="server-existing",
            reuse_action="continue",
            lineage=[
                {"id": "server-existing", "relation": "extends"},
                {"id": "server-existing", "relation": "supersedes"},
            ],
        )
        self.assert_has("cannot reference the reused issue itself")
        self.assert_has("duplicates a lineage issue id")

    def test_cluster_and_cli_bound_labels_fail_closed(self) -> None:
        labels = self.document["tasks"][0]["labels"]
        labels.append("cluster-second")
        labels.append("bad,label")
        self.assert_has("exactly one normalized cluster")
        self.assert_has("commas, control, or non-UTF-8")

    def test_cli_bound_labels_enforce_beads_length_limit(self) -> None:
        task = self.document["tasks"][0]
        task["labels"].append("x" * 51)
        task["labels"].remove(task["tracking_label"])
        task["tracking_label"] = f"plan:{'x' * 46}"
        task["labels"].append(task["tracking_label"])
        self.assert_has("tracking_label: must be a normalized plan: label of at most 50")
        self.assert_has("labels: each label must be at most 50")

    def test_cli_bound_text_rejects_controls_and_non_utf8(self) -> None:
        for suffix in ("\nnewline", "\ttab", "\0nul", "\ud800surrogate"):
            with self.subTest(field="labels", suffix=repr(suffix)):
                document = copy.deepcopy(self.document)
                document["tasks"][0]["labels"].append(f"bad{suffix}")
                messages = self.messages(document)
                self.assertTrue(
                    any("control, or non-UTF-8" in message for message in messages),
                    messages,
                )

        prose_cases = {
            "title": lambda task: task.__setitem__(
                "title", "A valid task title with a \ud800 surrogate"
            ),
            "scope": lambda task: task.__setitem__(
                "scope", "A complete task scope with a forbidden\tcontrol character."
            ),
            "description": lambda task: task.__setitem__(
                "description", "A complete task description with a forbidden\ncontrol character."
            ),
            "acceptance_criteria": lambda task: task.__setitem__(
                "acceptance_criteria", ["A forbidden\0control is rejected."]
            ),
            "evidence": lambda task: task.__setitem__(
                "evidence", ["A forbidden \ud800 surrogate is rejected."]
            ),
            "handoff artifact": lambda task: task["handoffs"][0].__setitem__(
                "artifact", "A forbidden\tcontrol is rejected."
            ),
        }
        for field, mutate in prose_cases.items():
            with self.subTest(field=field):
                document = copy.deepcopy(self.document)
                task_index = 2 if field == "handoff artifact" else 0
                mutate(document["tasks"][task_index])
                messages = self.messages(document)
                self.assertTrue(
                    any("control or non-UTF-8" in message for message in messages),
                    messages,
                )

    def test_reuse_action_is_required_only_for_reuse(self) -> None:
        task = self.document["tasks"][0]
        task["reuse_action"] = "continue"
        self.assert_has("allowed only for reused")
        task.update(
            promotion="reuse",
            existing_id="server-existing",
            reuse_action="unknown",
        )
        self.assert_has("must be one of")

    def test_tracker_input_failures_are_findings(self) -> None:
        cases = {
            "missing": ("absent.jsonl", "does not exist"),
            "nul": ("bad\x00path", "invalid tracker path"),
            "surrogate": ("bad\ud800path", "invalid tracker path"),
        }
        for name, (tracker_path, expected) in cases.items():
            with self.subTest(name=name):
                document = copy.deepcopy(self.document)
                document["trackers"]["server"]["path"] = tracker_path
                self.assert_has(expected, document)

        invalid_json = self.root / "invalid-tracker.jsonl"
        invalid_json.write_text("not-json\n{}\n", encoding="utf-8")
        self.document["trackers"]["server"]["path"] = invalid_json.name
        self.assert_has("invalid JSON")
        self.assert_has("has no non-empty issue id")

        invalid_utf8 = self.root / "invalid-utf8.jsonl"
        invalid_utf8.write_bytes(b"\xff\n")
        self.document["trackers"]["server"]["path"] = invalid_utf8.name
        self.assert_has("cannot read tracker index")

    def test_plan_labels_are_exclusive_to_one_task(self) -> None:
        foreign = self.document["tasks"][1]["tracking_label"]
        self.document["tasks"][0]["labels"].append(foreign)
        self.assert_has("exactly its own tracking_label")
        self.assert_has("already owned")

    def test_checksum_handoff_contract_is_enforced(self) -> None:
        self.document["tasks"][2]["handoffs"] = [
            self.handoff("driver-fix", artifact="short", checksum="optional")
        ]
        self.assert_has("must name the handoff artifact")
        self.assert_has("must equal 'required'")

    def test_handoff_self_duplicate_and_invalid_task_fail(self) -> None:
        self.document["tasks"][0]["handoffs"] = [
            self.handoff("foundation"),
            self.handoff("foundation"),
            self.handoff("Bad slug"),
        ]
        self.assert_has("duplicate task refs")
        self.assert_has("normalized task slug")
        self.assert_has("self-reference is forbidden")

    def test_parent_self_and_cross_repository_fail(self) -> None:
        self.document["tasks"][0]["parent"] = "foundation"
        self.document["tasks"][1]["parent"] = "foundation"
        self.assert_has("task cannot parent itself")
        self.assert_has("parent must be in the same repository")

    def test_existing_id_and_condition_are_forbidden_for_create(self) -> None:
        self.document["tasks"][0]["existing_id"] = "server-existing"
        self.document["tasks"][1]["condition"] = "This condition is not allowed for create promotion."
        self.assert_has("existing_id: is allowed only")
        self.assert_has("condition: is allowed only")

    def test_status_is_forbidden_because_input_is_not_a_tracker(self) -> None:
        self.document["tasks"][0]["status"] = "open"
        self.assert_has("unknown fields: status")

    def test_semver_transition_is_enforced(self) -> None:
        self.document["release_targets"][0]["next"] = "0.10.0"
        self.assert_has("patch transition from 0.9.0 must be 0.9.1")

    def test_all_semver_transition_modes(self) -> None:
        cases = [
            ("exact", "1.2.3", "1.2.3"),
            ("patch", "1.2.3", "1.2.4"),
            ("minor", "1.2.3", "1.3.0"),
            ("major", "1.2.3", "2.0.0"),
        ]
        for bump, current, next_version in cases:
            with self.subTest(bump=bump):
                document = copy.deepcopy(self.document)
                document["release_targets"] = [
                    {"repo": "server", "current": current, "next": next_version, "bump": bump}
                ]
                self.assertEqual(self.messages(document), [])

    def test_release_target_shape_and_uniqueness_fail(self) -> None:
        self.document["release_targets"].append(
            {"repo": "server", "current": "v1", "next": "1.2", "bump": "sideways"}
        )
        self.assert_has("duplicate release target")
        self.assert_has("must be one of")
        self.document["release_targets"][0]["repo"] = "missing"
        self.assert_has("unknown repository")

    def test_malformed_semver_values_fail_with_valid_bump(self) -> None:
        self.document["release_targets"][0]["current"] = "v0.9.0"
        self.document["release_targets"][1]["next"] = "0.8"
        self.assert_has("current: must be strict")
        self.assert_has("next: must be strict")

    def test_huge_semver_component_is_bounded(self) -> None:
        self.document["release_targets"][0]["current"] = "9" * 5_000 + ".1.1"
        self.assert_has("current: must be strict")

    def test_source_reference_must_exist_and_fit(self) -> None:
        self.document["tasks"][0]["source_refs"] = ["missing.md:1", "plan.md:2-99"]
        self.assert_has("must reference the bound source document")
        self.assert_has("has 4 lines")

    def test_source_refs_must_use_the_checksum_bound_plan(self) -> None:
        (self.root / "foreign.md").write_text("foreign\n", encoding="utf-8")
        self.document["tasks"][0]["source_refs"] = ["foreign.md:1"]
        self.assert_has("must reference the bound source document")

    def test_non_utf8_source_reference_is_a_finding(self) -> None:
        (self.root / "binary.md").write_bytes(b"\xff\xfe\x00")
        self.document["source_document"] = {
            "path": "binary.md",
            "sha256": hashlib.sha256((self.root / "binary.md").read_bytes()).hexdigest(),
        }
        self.document["tasks"][0]["source_refs"] = ["binary.md:1"]
        self.assert_has("not valid UTF-8")

    def test_source_reference_hostile_shapes_fail_closed(self) -> None:
        huge = "9" * 5_000
        self.document["tasks"][0]["source_refs"] = [
            "bad\x00path.md:1",
            "bad\ud800path.md:1",
            f"plan.md:{huge}",
            "plan.md:4-2",
            "../plan.md:1",
            "not-a-source-ref",
            "plan.md:1",
            "plan.md:1",
        ]
        self.assert_has("must reference the bound source document")
        self.assert_has("unreasonably large")
        self.assert_has("range end precedes")
        self.assert_has("must use relative/path")
        self.assert_has("must not contain duplicates")

    def test_deep_acyclic_graph_does_not_recurse(self) -> None:
        tasks = []
        for index in range(1_500):
            slug = f"node-{index:04d}"
            depends_on = [f"node-{index - 1:04d}"] if index else []
            tasks.append(self.task(slug, "server", depends_on=depends_on))
        document = {
            "schema": MODULE.SCHEMA,
            "program": "deep-graph",
            "source_document": copy.deepcopy(self.document["source_document"]),
            "repositories": ["server"],
            "trackers": {
                "server": {"path": "server.jsonl", "source_repo": "oraclemcp"}
            },
            "release_targets": [
                {"repo": "server", "current": "0.9.0", "next": "0.9.1", "bump": "patch"}
            ],
            "tasks": tasks,
        }
        self.assertEqual(self.messages(document), [])

    def test_top_level_and_handoff_shapes_fail_closed(self) -> None:
        self.document["trackers"] = {
            "server": {"path": "server.jsonl", "source_repo": "oraclemcp"},
            "unknown": 1,
        }
        self.document["tasks"][2]["handoffs"] = [
            1,
            {"task": "driver-fix"},
            self.handoff("driver-fix", surprise=True),
        ]
        self.assert_has("unknown repository keys")
        self.assert_has("missing repository keys")
        self.assert_has("must be an object")
        self.assert_has("missing fields")
        self.assert_has("unknown fields")

    def test_non_string_mapping_keys_never_crash(self) -> None:
        self.document[1] = "top"
        self.document["source_document"][2] = "source"
        self.document["release_targets"][0][3] = "release"
        self.document["tasks"][0][4] = "task"
        self.document["tasks"][2]["handoffs"][0][5] = "handoff"
        messages = self.messages()
        self.assertGreaterEqual(sum("unknown fields" in message for message in messages), 5)

    def test_empty_document_is_not_replaced_by_fixture(self) -> None:
        self.assert_has("missing fields", {})

    def test_cli_success_failure_json_and_input_error(self) -> None:
        valid_path = self.root / "valid.json"
        invalid_path = self.root / "invalid.json"
        valid_path.write_text(json.dumps(self.document), encoding="utf-8")
        invalid = copy.deepcopy(self.document)
        invalid["tasks"][0]["depends_on"] = ["missing"]
        invalid_path.write_text(json.dumps(invalid), encoding="utf-8")

        success = subprocess.run(
            [sys.executable, str(SCRIPT), str(valid_path), "--repo-root", str(self.root)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertIn("3 normalized task(s)", success.stdout)

        failure = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(invalid_path),
                "--repo-root",
                str(self.root),
                "--json",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(failure.returncode, 1, failure.stderr)
        payload = json.loads(failure.stdout)
        self.assertFalse(payload["ok"])
        self.assertTrue(any("unknown task reference" in item for item in payload["findings"]))

        input_error = subprocess.run(
            [sys.executable, str(SCRIPT), str(self.root / "absent.json"), "--json"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(input_error.returncode, 2)
        self.assertFalse(json.loads(input_error.stdout)["ok"])

    def test_cli_malformed_task_shape_returns_json_finding(self) -> None:
        malformed = copy.deepcopy(self.document)
        malformed["tasks"] = 1
        path = self.root / "malformed.json"
        path.write_text(json.dumps(malformed), encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(path),
                "--repo-root",
                str(self.root),
                "--json",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["task_count"], 0)
        self.assertTrue(any("tasks: must be a non-empty array" in item for item in payload["findings"]))

    def test_cli_escaped_lone_surrogate_returns_json_finding(self) -> None:
        document = copy.deepcopy(self.document)
        document["tasks"][0]["title"] = "A valid task title with a \ud800 surrogate"
        path = self.root / "escaped-surrogate.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                str(path),
                "--repo-root",
                str(self.root),
                "--json",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stderr, "")
        payload = json.loads(result.stdout)
        self.assertFalse(payload["ok"])
        self.assertTrue(
            any(
                "tasks[0].title" in item and "non-UTF-8" in item
                for item in payload["findings"]
            ),
            payload,
        )


if __name__ == "__main__":
    unittest.main()
