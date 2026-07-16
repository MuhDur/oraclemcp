#!/usr/bin/env python3
"""Create a mutation-result/v1 artifact from archived cargo-mutants outcomes.

This is intentionally a converter, not a mutation runner.  It lets a release
retain the raw outcome records from a completed frozen run without pretending a
new mutation campaign happened during a documentation migration.
"""

from __future__ import annotations

import argparse
import json
import shlex
from datetime import UTC, datetime
from pathlib import Path


def iso_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def test_command(outcome: dict, wanted_status: str) -> str:
    for phase in outcome["phase_results"]:
        if phase["phase"] != "Test":
            continue
        status = phase["process_status"]
        if wanted_status == "fail" and status != "Success":
            return shlex.join(phase["argv"])
        if wanted_status == "pass" and status == "Success":
            return shlex.join(phase["argv"])
    raise ValueError(f"no {wanted_status} test command for {outcome['scenario']!r}")


def mutant_location(mutant: dict) -> str:
    return f"{mutant['file']}:{mutant['span']['start']['line']}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outcomes", type=Path, action="append", required=True)
    parser.add_argument("--shard-id", action="append", default=[])
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--scope-target", action="append", required=True)
    parser.add_argument("--description", required=True)
    parser.add_argument("--resource-budget", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--generated-at", default=None)
    args = parser.parse_args()

    if args.shard_id and len(args.shard_id) != len(args.outcomes):
        parser.error("--shard-id must be supplied once for every --outcomes file")

    budget = json.loads(args.resource_budget.read_text())
    outcomes_docs = [json.loads(path.read_text()) for path in args.outcomes]
    for path, outcomes in zip(args.outcomes, outcomes_docs, strict=True):
        if outcomes.get("end_time") is None:
            raise SystemExit(f"unfinished archived outcomes: {path}")
        baseline = next(
            (entry for entry in outcomes["outcomes"] if entry["scenario"] == "Baseline"),
            None,
        )
        if baseline is None:
            raise SystemExit(f"no baseline record in {path}")
        test_command(baseline, "pass")

    counts = {"caught": 0, "missed": 0, "timeout": 0, "unviable": 0}
    kills: list[dict] = []
    survivors: list[dict] = []
    started_at: list[str] = []
    ended_at: list[str] = []

    for outcomes in outcomes_docs:
        started_at.append(outcomes["start_time"])
        ended_at.append(outcomes["end_time"])
        for key in counts:
            counts[key] += outcomes[key]

        baseline = next(entry for entry in outcomes["outcomes"] if entry["scenario"] == "Baseline")
        head_test = test_command(baseline, "pass")
        for outcome in outcomes["outcomes"]:
            if outcome["scenario"] == "Baseline":
                continue
            mutant = outcome["scenario"]["Mutant"]
            summary = outcome["summary"]
            if summary == "CaughtMutant":
                kills.append(
                    {
                        "mutant_id": mutant["name"],
                        "location": mutant_location(mutant),
                        "mutant_fails_test": {
                            "test": test_command(outcome, "fail"),
                            "outcome": "fail",
                        },
                        "head_passes_test": {"test": head_test, "outcome": "pass"},
                    }
                )
            elif summary == "MissedMutant":
                survivors.append(
                    {
                        "mutant_id": mutant["name"],
                        "location": mutant_location(mutant),
                        "taxonomy": "triage-pending",
                        "note": (
                            "Archived cargo-mutants output records this survivor but not "
                            "its campaign adjudication; retained explicitly rather than "
                            "inventing an equivalence claim."
                        ),
                    }
                )

    if len(kills) != counts["caught"]:
        raise SystemExit(f"caught count {counts['caught']} disagrees with {len(kills)} records")
    if len(survivors) != counts["missed"]:
        raise SystemExit(f"missed count {counts['missed']} disagrees with {len(survivors)} records")

    denominator = counts["caught"] + counts["missed"] + counts["timeout"]
    # v1 freezes the declared rate as caught / the selected denominator.  A
    # timeout remains in the denominator but is never silently promoted to a
    # kill.
    rate = counts["caught"] / denominator if denominator else 0.0
    shard_ids = args.shard_id or [
        f"shard-{index + 1}of{len(outcomes_docs)}" for index in range(len(outcomes_docs))
    ]
    doc = {
        "schema": "mutation-result/v1",
        "repo": "oraclemcp",
        "generated_at": args.generated_at or iso_now(),
        "source": {"sha": args.source_sha, "tree_clean": True, "branch": "gate-seal-archive"},
        "scope": {
            "claim": "scoped",
            "description": args.description,
            "targets": args.scope_target,
        },
        "started_at": min(started_at),
        "ended_at": max(ended_at),
        "resource_budget": budget,
        "shards": [{"id": shard_id, "status": "complete"} for shard_id in shard_ids],
        "counts": counts,
        "denominator": "caught+missed+timeout",
        "rate": rate,
        "survivors": survivors,
        "kills": kills,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(doc, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
