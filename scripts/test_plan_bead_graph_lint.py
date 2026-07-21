#!/usr/bin/env python3
"""DB-free contract tests for normalized plan-to-Beads graph linting."""

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
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
LINT_PATH = ROOT / "scripts" / "plan_bead_graph_lint.py"
SPEC = importlib.util.spec_from_file_location("plan_bead_graph_lint", LINT_PATH)
assert SPEC is not None and SPEC.loader is not None
LINT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = LINT
SPEC.loader.exec_module(LINT)


class ManifestFixture:
    """Inspectable fixture directory; intentionally retained on failure/success."""

    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="oraclemcp-plan-graph-lint-", dir="/var/tmp"))
        self.plan = self.root / "plan.md"
        self.plan.write_text("# normalized plan fixture\n", encoding="utf-8")
        self._tracker("core")

    def _tracker(self, repository: str) -> None:
        tracker = self.root / repository / ".beads" / "issues.jsonl"
        tracker.parent.mkdir(parents=True, exist_ok=True)
        tracker.write_text("", encoding="utf-8")

    def add_repository(self, repository: str, source_repo: str) -> None:
        (self.root / repository).mkdir(exist_ok=True)
        self._tracker(repository)

    def manifest(self) -> dict:
        sha256 = hashlib.sha256(self.plan.read_bytes()).hexdigest()
        return {
            "schema": "plan-bead-graph/v2",
            "program": {"slug": "fixture-program"},
            "source_document": {"path": "plan.md", "sha256": sha256},
            "repositories": [{"slug": "core", "path": "core", "source_repo": "fixture-core"}],
            "trackers": [
                {
                    "repository": "core",
                    "path": "core/.beads/issues.jsonl",
                    "source_repo": "fixture-core",
                }
            ],
            "release_targets": [{"repository": "core", "version": "0.9.1", "assertion": "patch"}],
            "tasks": [self.task("base"), self.task("child", dependencies=["base"])],
        }

    @staticmethod
    def task(slug: str, *, dependencies: list[str] | None = None) -> dict:
        return {
            "slug": slug,
            "repository": "core",
            "tracker": "core",
            "title": f"fixture {slug}",
            "type": "task",
            "priority": 1,
            "tier": "tier-1",
            "labels": [f"track-{slug}", f"plan-fixture-{slug}"],
            "tracking_label": f"track-{slug}",
            "plan": {"section": "§27.6", "label": f"plan-fixture-{slug}"},
            "scope": [f"scripts/{slug}.py"],
            "acceptance": [f"{slug} is independently testable"],
            "evidence": [f"unit evidence for {slug}"],
            "dependencies": dependencies or [],
            "parent": None,
            "handoffs": [],
            "operator_gate": "none",
            "promotion": "activate",
            "lineage": {"kind": "new"},
            "reuse": {"action": "create"},
        }

    def write(self, manifest: dict, name: str = "manifest.json") -> Path:
        path = self.root / name
        path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return path


class PlanBeadGraphLintTests(unittest.TestCase):
    def test_valid_manifest_has_deterministic_promotion_order(self) -> None:
        fixture = ManifestFixture()
        state = LINT.validate_manifest(fixture.write(fixture.manifest()))
        self.assertEqual(state.findings.hard, [])
        operations = LINT.promotion_operations(state, include_gcp=False)
        phases = [operation.phase for operation in operations]
        self.assertEqual(phases[:2], ["stage", "stage"])
        self.assertIn("wire", phases)
        self.assertLess(max(index for index, phase in enumerate(phases) if phase == "stage"), phases.index("wire"))
        self.assertLess(phases.index("wire"), phases.index("verify"))
        self.assertLess(phases.index("verify"), phases.index("activate"))
        self.assertEqual([operation.task for operation in operations if operation.phase == "activate"], ["base", "child"])

    def test_cli_reports_pass_and_bad_checksum_fails_without_crash(self) -> None:
        fixture = ManifestFixture()
        manifest = fixture.manifest()
        path = fixture.write(manifest)
        passed = subprocess.run([sys.executable, str(LINT_PATH), "--manifest", str(path)], capture_output=True, text=True)
        self.assertEqual(passed.returncode, 0, passed.stderr)
        self.assertIn("plan-bead-graph: PASS", passed.stdout)
        broken = copy.deepcopy(manifest)
        broken["source_document"]["sha256"] = "0" * 64
        rejected = subprocess.run(
            [sys.executable, str(LINT_PATH), "--manifest", str(fixture.write(broken, "bad-checksum.json"))],
            capture_output=True,
            text=True,
        )
        self.assertEqual(rejected.returncode, 1, rejected.stderr)
        self.assertIn("E_SOURCE_SHA256", rejected.stdout)

    def test_duplicate_slug_tracking_label_plan_label_and_lineage_fail(self) -> None:
        fixture = ManifestFixture()
        manifest = fixture.manifest()
        duplicate = copy.deepcopy(manifest["tasks"][1])
        duplicate["slug"] = "base"
        duplicate["tracking_label"] = manifest["tasks"][0]["tracking_label"]
        duplicate["labels"][0] = manifest["tasks"][0]["tracking_label"]
        duplicate["plan"]["label"] = manifest["tasks"][0]["plan"]["label"]
        duplicate["labels"][1] = manifest["tasks"][0]["plan"]["label"]
        manifest["tasks"].append(duplicate)
        repeated_labels = fixture.task("third")
        repeated_labels["tracking_label"] = manifest["tasks"][0]["tracking_label"]
        repeated_labels["labels"][0] = manifest["tasks"][0]["tracking_label"]
        repeated_labels["plan"]["label"] = manifest["tasks"][0]["plan"]["label"]
        repeated_labels["labels"][1] = manifest["tasks"][0]["plan"]["label"]
        manifest["tasks"].append(repeated_labels)
        state = LINT.validate_manifest(fixture.write(manifest))
        codes = "\n".join(state.findings.hard)
        self.assertIn("E_TASK_SLUG", codes)
        self.assertIn("E_TASK_LABEL", codes)
        self.assertIn("E_PLAN_PROVENANCE", codes)

    def test_cross_repository_native_dependency_fails(self) -> None:
        fixture = ManifestFixture()
        fixture.add_repository("site", "fixture-site")
        manifest = fixture.manifest()
        manifest["repositories"].append({"slug": "site", "path": "site", "source_repo": "fixture-site"})
        manifest["trackers"].append(
            {"repository": "site", "path": "site/.beads/issues.jsonl", "source_repo": "fixture-site"}
        )
        manifest["release_targets"].append({"repository": "site", "version": "1.2.3", "assertion": "minor"})
        site_task = fixture.task("site-task", dependencies=["base"])
        site_task.update(repository="site", tracker="site")
        manifest["tasks"].append(site_task)
        state = LINT.validate_manifest(fixture.write(manifest))
        self.assertTrue(any(line.startswith("E_CROSS_REPO_NATIVE_EDGE") for line in state.findings.hard))

    def test_cross_repository_handoff_requires_checksum_and_holds_target(self) -> None:
        fixture = ManifestFixture()
        fixture.add_repository("site", "fixture-site")
        manifest = fixture.manifest()
        manifest["repositories"].append({"slug": "site", "path": "site", "source_repo": "fixture-site"})
        manifest["trackers"].append(
            {"repository": "site", "path": "site/.beads/issues.jsonl", "source_repo": "fixture-site"}
        )
        manifest["release_targets"].append({"repository": "site", "version": "1.2.3", "assertion": "minor"})
        site_task = fixture.task("site-task")
        site_task.update(repository="site", tracker="site", promotion="deferred")
        manifest["tasks"].append(site_task)
        manifest["tasks"][0]["handoffs"] = [{"to": "site-task", "artifact": "release/g7.json", "sha256": "a" * 64}]
        state = LINT.validate_manifest(fixture.write(manifest))
        self.assertEqual(state.findings.hard, [])
        self.assertIn("site-task", state.incoming_handoffs)
        broken = copy.deepcopy(manifest)
        del broken["tasks"][0]["handoffs"][0]["sha256"]
        bad = LINT.validate_manifest(fixture.write(broken, "bad-handoff.json"))
        self.assertTrue(any(line.startswith("E_HANDOFF_SHA256") for line in bad.findings.hard))

    def test_mixed_parent_dependency_cycle_fails_iteratively(self) -> None:
        fixture = ManifestFixture()
        manifest = fixture.manifest()
        manifest["tasks"][0]["parent"] = "child"
        state = LINT.validate_manifest(fixture.write(manifest))
        self.assertTrue(any(line.startswith("E_GRAPH_CYCLE") for line in state.findings.hard))

    def test_cluster_j_is_excluded_without_flag(self) -> None:
        fixture = ManifestFixture()
        manifest = fixture.manifest()
        gcp = fixture.task("gcp-task")
        gcp["cluster"] = "J"
        manifest["tasks"].append(gcp)
        state = LINT.validate_manifest(fixture.write(manifest))
        self.assertEqual(state.findings.hard, [])
        operations = LINT.promotion_operations(state, include_gcp=False)
        self.assertIn(("hold", "gcp-task"), [(operation.phase, operation.task) for operation in operations])
        with_gcp = LINT.promotion_operations(state, include_gcp=True)
        self.assertIn(("stage", "gcp-task"), [(operation.phase, operation.task) for operation in with_gcp])

    def test_apply_stages_then_wires_then_activates(self) -> None:
        fixture = ManifestFixture()
        state = LINT.validate_manifest(fixture.write(fixture.manifest()))
        self.assertEqual(state.findings.hard, [])
        commands: list[list[str]] = []

        def fake_run(argv: list[str], _cwd: Path) -> str:
            commands.append(argv)
            if argv[:2] == ["br", "create"]:
                return json.dumps({"id": f"issue-{argv[argv.index('--slug') + 1]}"})
            return json.dumps({"ok": True})

        staged_tracker = {
            "issue-base": {"id": "issue-base", "source_repo": "fixture-core"},
            "issue-child": {"id": "issue-child", "source_repo": "fixture-core"},
        }
        with (
            patch.object(LINT, "_run_command", side_effect=fake_run),
            patch.object(LINT, "_parse_tracker_jsonl", return_value=staged_tracker),
        ):
            self.assertEqual(LINT.apply_promotion(state, include_gcp=False), (2, 1, 2))
        self.assertEqual([command[1] for command in commands], ["create", "create", "dep", "update", "update"])
        self.assertTrue(all("deferred" in command for command in commands[:2]))
        self.assertEqual(commands[2][2:4], ["add", "issue-child"])
        self.assertTrue(all(command[command.index("--status") + 1] == "open" for command in commands[3:]))


if __name__ == "__main__":
    unittest.main()
