#!/usr/bin/env python3
"""Seal complete OOM-free cargo-mutants shards as mutation-result/v1.

This is intentionally a verifier/converter, not a mutation runner. Every raw
outcomes document needs its runner-produced mutation-shard-integrity/v1
sidecar. A partial, OOM-affected, mismatched, duplicated, or missing shard is
rejected before an evidence artifact can exist.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
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
    parser.add_argument(
        "--integrity",
        type=Path,
        action="append",
        required=True,
        help="mutation-shard-integrity/v1 sidecar paired positionally with --outcomes",
    )
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--scope-target", action="append", required=True)
    parser.add_argument("--description", required=True)
    parser.add_argument("--resource-budget", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--generated-at", default=None)
    args = parser.parse_args()

    if len(args.integrity) != len(args.outcomes):
        parser.error("--integrity must be supplied once for every --outcomes file")
    if re.fullmatch(r"[0-9a-f]{40}", args.source_sha) is None:
        parser.error("--source-sha must be a full lowercase 40-character Git SHA")

    budget = json.loads(args.resource_budget.read_text())
    outcomes_docs = [json.loads(path.read_text()) for path in args.outcomes]
    integrity_docs = [json.loads(path.read_text()) for path in args.integrity]
    scopes: dict[str, list[dict]] = {}
    for outcomes_path, outcomes, integrity_path, integrity in zip(
        args.outcomes, outcomes_docs, args.integrity, integrity_docs, strict=True
    ):
        if integrity.get("schema") != "mutation-shard-integrity/v1":
            raise SystemExit(f"unsupported shard integrity document: {integrity_path}")
        if integrity.get("oom_kill_delta") != 0:
            raise SystemExit(
                f"E_OOM_MUTANT: {integrity_path} records "
                f"oom_kill_delta={integrity.get('oom_kill_delta')!r}; never grade it caught"
            )
        if integrity.get("pid_max_delta") != 0:
            raise SystemExit(
                f"E_TASK_CAP: {integrity_path} records "
                f"pid_max_delta={integrity.get('pid_max_delta')!r}; never grade it caught"
            )
        if integrity.get("oom_policy") != "continue":
            raise SystemExit(f"shard did not enforce OOMPolicy=continue: {integrity_path}")
        for field in ("memory_max_bytes", "pid_task_max"):
            if integrity.get(field) != budget.get(field):
                raise SystemExit(
                    f"resource budget mismatch for {field}: {integrity_path} recorded "
                    f"{integrity.get(field)!r}, budget declares {budget.get(field)!r}"
                )
        if integrity.get("status") != "complete":
            raise SystemExit(
                f"shard is not complete: {integrity_path} status={integrity.get('status')!r}"
            )
        if integrity.get("source_sha") != args.source_sha:
            raise SystemExit(
                f"source SHA mismatch: {integrity_path} has {integrity.get('source_sha')!r}"
            )
        actual_hash = hashlib.sha256(outcomes_path.read_bytes()).hexdigest()
        if integrity.get("outcomes_sha256") != actual_hash:
            raise SystemExit(f"outcomes hash mismatch: {outcomes_path}")
        if outcomes.get("end_time") is None:
            raise SystemExit(f"unfinished archived outcomes: {outcomes_path}")
        baseline = next(
            (entry for entry in outcomes["outcomes"] if entry["scenario"] == "Baseline"),
            None,
        )
        if baseline is None:
            raise SystemExit(f"no baseline record in {outcomes_path}")
        test_command(baseline, "pass")
        accounted = sum(outcomes[key] for key in ("caught", "missed", "timeout", "unviable"))
        if accounted != integrity.get("mutant_count"):
            raise SystemExit(
                f"partial shard counters: {outcomes_path} accounts for {accounted}/"
                f"{integrity.get('mutant_count')} mutants"
            )
        mutant_ids = integrity.get("mutant_ids")
        if not isinstance(mutant_ids, list) or len(mutant_ids) != integrity.get(
            "mutant_count"
        ):
            raise SystemExit(f"invalid mutant inventory: {integrity_path}")
        outcome_ids = [
            entry["scenario"]["Mutant"]["name"]
            for entry in outcomes["outcomes"]
            if entry["scenario"] != "Baseline"
        ]
        if sorted(outcome_ids) != sorted(mutant_ids):
            raise SystemExit(f"outcomes mutant population differs from inventory: {outcomes_path}")
        scope = integrity.get("scope")
        if scope not in {"guard", "audit", "core", "db", "dispatch", "fixture"}:
            raise SystemExit(f"invalid mutation scope: {scope!r}")
        scope_hash = integrity.get("scope_sha256")
        if not isinstance(scope_hash, str) or re.fullmatch(r"[0-9a-f]{64}", scope_hash) is None:
            raise SystemExit(f"invalid covered-file hash: {integrity_path}")
        covered_files = integrity.get("covered_file_count")
        if not isinstance(covered_files, int) or covered_files < 1:
            raise SystemExit(f"invalid covered-file count: {integrity_path}")
        scopes.setdefault(scope, []).append(integrity)

    for scope, shards in scopes.items():
        totals = {shard.get("shard_total") for shard in shards}
        populations = {shard.get("campaign_mutant_total") for shard in shards}
        hashes = {shard.get("scope_sha256") for shard in shards}
        file_counts = {shard.get("covered_file_count") for shard in shards}
        tool_versions = {shard.get("cargo_mutants_version") for shard in shards}
        if (
            len(totals) != 1
            or len(populations) != 1
            or len(hashes) != 1
            or len(file_counts) != 1
            or len(tool_versions) != 1
        ):
            raise SystemExit(f"inconsistent campaign metadata for scope {scope}")
        total = next(iter(totals))
        population = next(iter(populations))
        if (
            not isinstance(total, int)
            or total < 1
            or not isinstance(population, int)
            or population < 1
        ):
            raise SystemExit(f"invalid campaign totals for scope {scope}")
        indices = [shard.get("shard_index") for shard in shards]
        if not all(isinstance(index, int) and index >= 1 for index in indices):
            raise SystemExit(f"invalid shard index for scope {scope}")
        indices.sort()
        if indices != list(range(1, total + 1)):
            raise SystemExit(
                f"E_SHARD_INCOMPLETE: scope {scope} has indices {indices}, expected 1..{total}"
            )
        mutant_ids = [mutant_id for shard in shards for mutant_id in shard["mutant_ids"]]
        if len(mutant_ids) != len(set(mutant_ids)):
            raise SystemExit(f"duplicate mutant across shards for scope {scope}")
        if len(mutant_ids) != population:
            raise SystemExit(
                f"incomplete mutant population for scope {scope}: "
                f"{len(mutant_ids)}/{population}"
            )

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
    shard_ids = [
        f"{integrity['scope']}-{integrity['shard_index']}of{integrity['shard_total']}"
        for integrity in integrity_docs
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
