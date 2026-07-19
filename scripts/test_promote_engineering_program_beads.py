#!/usr/bin/env python3
"""Regression tests for fail-closed engineering-program promotion."""

from __future__ import annotations

import importlib.util
import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("promote_engineering_program_beads.py")
SPEC = importlib.util.spec_from_file_location("promote_engineering_program_beads", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class FakeBeads:
    def __init__(self, records: dict[str, dict[str, dict[str, Any]]]) -> None:
        self.records = records
        self.calls: list[tuple[str, list[str]]] = []
        self.next_id = 0
        self.fail_next_dependency = False

    def tracker_records(self, repo: str) -> dict[str, dict[str, Any]]:
        return self.records[repo]

    def run(self, repo: str, args: list[str]) -> Any:
        self.calls.append((repo, list(args)))
        if "--external-ref" in args:
            external_ref = args[args.index("--external-ref") + 1]
            if any(character.isspace() for character in external_ref):
                raise RuntimeError("external_ref: cannot contain whitespace")
        if args[:3] == ["br", "dep", "cycles"]:
            return {"cycles": [], "count": 0, "active_count": 0}
        if args[:2] == ["br", "sync"]:
            return None
        if args[:2] == ["br", "create"]:
            self.next_id += 1
            issue_id = f"{repo}-created-{self.next_id}"
            status = args[args.index("--status") + 1]
            labels = args[args.index("--labels") + 1].split(",")
            self.records[repo][issue_id] = {
                "id": issue_id,
                "status": status,
                "labels": labels,
                "notes": "",
            }
            return {"id": issue_id}
        if args[:2] == ["br", "show"]:
            return [self.records[repo][args[2]]]
        if args[:3] == ["br", "dep", "list"]:
            return []
        if args[:3] == ["br", "dep", "add"]:
            if self.fail_next_dependency:
                self.fail_next_dependency = False
                raise RuntimeError("injected dependency failure")
            return {}
        if args[:2] == ["br", "update"]:
            record = self.records[repo][args[2]]
            if "--status" in args:
                record["status"] = args[args.index("--status") + 1]
            if "--notes" in args:
                record["notes"] = args[args.index("--notes") + 1]
            if "--add-label" in args:
                record.setdefault("labels", []).append(args[args.index("--add-label") + 1])
            if "--remove-label" in args:
                label = args[args.index("--remove-label") + 1]
                record["labels"] = [item for item in record.get("labels", []) if item != label]
            return {}
        if args[:2] == ["br", "reopen"]:
            self.records[repo][args[2]]["status"] = "open"
            return {}
        raise AssertionError((repo, args))


class PromotionTests(unittest.TestCase):
    @staticmethod
    def task(
        slug: str,
        *,
        depends_on: list[str] | None = None,
        handoffs: list[dict[str, str]] | None = None,
        cluster: str = "A",
    ) -> dict[str, Any]:
        return {
            "slug": slug,
            "tracking_label": f"plan:test:{slug}",
            "repo": "server",
            "title": f"Implement {slug}",
            "type": "task",
            "priority": 1,
            "labels": ["engineering-program", f"cluster-{cluster.lower()}", f"plan:test:{slug}"],
            "source_refs": ["docs/plan/PLAN_ENGINEERING_PROGRAM.md:1-2"],
            "scope": "A complete self-contained implementation scope for the promotion regression.",
            "description": "A complete self-contained implementation description for the promotion regression.",
            "acceptance_criteria": ["The observable contract is proven."],
            "evidence": ["A focused regression transcript."],
            "tier": "tier-1",
            "depends_on": depends_on or [],
            "handoffs": handoffs or [],
            "operator_gate": "none",
            "promotion": "create",
        }

    def document(self, tasks: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "source_document": {
                "path": "docs/plan/PLAN_ENGINEERING_PROGRAM.md",
                "sha256": "0" * 64,
            },
            "trackers": {
                "server": {"path": ".beads/issues.jsonl"},
                "driver": {"path": "../rust-oracledb/.beads/issues.jsonl"},
            },
            "tasks": tasks,
        }

    def invoke(
        self, tasks: list[dict[str, Any]], argv: list[str] | None = None
    ) -> FakeBeads:
        fake = FakeBeads({"server": {}, "driver": {}})
        with (
            patch.object(MODULE, "manifest", return_value=self.document(tasks)),
            patch.object(MODULE, "validate", return_value=[]),
            patch.object(MODULE, "assert_tracker_bindings", return_value=None),
            patch.object(MODULE, "tracker_records", side_effect=fake.tracker_records),
            patch.object(MODULE, "run", side_effect=fake.run),
        ):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(MODULE.main(argv or ["--apply"]), 0)
        return fake

    def test_new_issues_stage_before_edges_and_activation(self) -> None:
        fake = self.invoke([self.task("foundation"), self.task("consumer", depends_on=["foundation"])])
        creates = [index for index, (_, args) in enumerate(fake.calls) if args[:2] == ["br", "create"]]
        adds = [index for index, (_, args) in enumerate(fake.calls) if args[:3] == ["br", "dep", "add"]]
        opens = [
            index
            for index, (_, args) in enumerate(fake.calls)
            if args[:2] == ["br", "update"]
            and "--status" in args
            and args[args.index("--status") + 1] == "open"
        ]
        self.assertTrue(creates and adds and opens)
        self.assertLess(max(creates), min(adds))
        self.assertLess(max(adds), min(opens))
        for _, args in (fake.calls[index] for index in creates):
            self.assertEqual(args[args.index("--status") + 1], "deferred")

    def test_checksum_handoff_remains_deferred(self) -> None:
        task = self.task(
            "consumer",
            handoffs=[
                {
                    "task": "driver-provider",
                    "artifact": "Accepted exact-SHA provider artifact digest",
                    "checksum": "required",
                }
            ],
        )
        fake = self.invoke([task])
        statuses = [record["status"] for record in fake.records["server"].values()]
        self.assertEqual(statuses, ["deferred"])

    def test_gcp_cluster_is_held_without_explicit_flag(self) -> None:
        fake = self.invoke([self.task("gcp", cluster="J")])
        self.assertFalse(any(args[:2] == ["br", "create"] for _, args in fake.calls))

    def test_cycle_path_detects_mixed_live_and_plan_cycle(self) -> None:
        self.assertEqual(
            MODULE.cycle_path({"live": ["planned"], "planned": ["live"]}),
            ["live", "planned", "live"],
        )

    def test_tracker_binding_rejects_decoy_index(self) -> None:
        document = self.document([])
        document["trackers"]["server"]["path"] = "decoy/issues.jsonl"
        with self.assertRaisesRegex(RuntimeError, "does not match live mutation target"):
            MODULE.assert_tracker_bindings(document)

    def test_external_reference_is_whitespace_free_and_checksum_bound(self) -> None:
        task = self.task("source-proof")
        task["source_refs"].append("docs/plan/PLAN_ENGINEERING_PROGRAM.md:7-9")
        document = self.document([task])
        value = MODULE.external_reference(task, document)
        self.assertFalse(any(character.isspace() for character in value), value)
        self.assertLessEqual(len(value), 200)
        self.assertIn(":1-2,7-9#task=source-proof&sha256=", value)
        self.assertTrue(value.endswith("0" * 64))
        peer = self.task("source-peer")
        self.assertNotEqual(value, MODULE.external_reference(peer, self.document([peer])))

    def test_in_progress_reuse_with_new_blocker_fails_before_mutation(self) -> None:
        foundation = self.task("foundation")
        reused = self.task("reused", depends_on=["foundation"])
        reused.update(
            promotion="reuse",
            existing_id="server-existing",
            reuse_action="continue",
        )
        fake = FakeBeads(
            {
                "server": {
                    "server-existing": {
                        "id": "server-existing",
                        "status": "in_progress",
                        "labels": [reused["tracking_label"]],
                        "notes": "",
                    }
                },
                "driver": {},
            }
        )
        with (
            patch.object(MODULE, "manifest", return_value=self.document([foundation, reused])),
            patch.object(MODULE, "validate", return_value=[]),
            patch.object(MODULE, "assert_tracker_bindings", return_value=None),
            patch.object(MODULE, "tracker_records", side_effect=fake.tracker_records),
            patch.object(MODULE, "run", side_effect=fake.run),
            redirect_stdout(io.StringIO()),
        ):
            with self.assertRaisesRegex(RuntimeError, "in_progress"):
                MODULE.main(["--apply"])
        self.assertFalse(fake.calls)

    def test_retry_restores_open_reused_issue_after_staging_failure(self) -> None:
        foundation = self.task("foundation")
        reused = self.task("reused", depends_on=["foundation"])
        reused.update(
            promotion="reuse",
            existing_id="server-existing",
            reuse_action="continue",
        )
        fake = FakeBeads(
            {
                "server": {
                    "server-existing": {
                        "id": "server-existing",
                        "status": "open",
                        "labels": [reused["tracking_label"]],
                        "notes": "",
                    }
                },
                "driver": {},
            }
        )
        fake.fail_next_dependency = True
        with (
            patch.object(MODULE, "manifest", return_value=self.document([foundation, reused])),
            patch.object(MODULE, "validate", return_value=[]),
            patch.object(MODULE, "assert_tracker_bindings", return_value=None),
            patch.object(MODULE, "tracker_records", side_effect=fake.tracker_records),
            patch.object(MODULE, "run", side_effect=fake.run),
            redirect_stdout(io.StringIO()),
        ):
            with self.assertRaisesRegex(RuntimeError, "injected dependency failure"):
                MODULE.main(["--apply"])
            self.assertEqual(fake.records["server"]["server-existing"]["status"], "deferred")
            self.assertEqual(MODULE.main(["--apply"]), 0)
        record = fake.records["server"]["server-existing"]
        self.assertEqual(record["status"], "open")
        self.assertFalse(
            any(label.startswith(MODULE.ORIGINAL_STATUS_LABEL_PREFIX) for label in record["labels"])
        )


if __name__ == "__main__":
    unittest.main()
