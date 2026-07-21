#!/usr/bin/env python3
"""CI lane budget evidence (bead D2/D4 family, plan §25.7.3).

Two questions this answers with artifacts instead of assertions:

  fuzz-bound  Is every fuzz lane sharded and wall-clock bounded? Offline: it
              reads the workflow YAML, so it runs in CI and locally.

  rq-prep     Did a Release Qualification `prep` run actually reduce the
              cold-start of the `strict` run that followed it? This one is the
              reason bead oraclemcp-eng-program-bp8ia.5.4 was reopened on
              2026-07-20: the acceptance claimed a cold-start reduction that
              nobody had measured, and "a local workflow/parser pass cannot
              prove GitHub runner/cache cold-start behavior".

`rq-prep` therefore refuses to produce a positive verdict unless the evidence
is real:

  * both runs are at the IDENTICAL candidate SHA (E_SHA_MISMATCH),
  * a `prep` run exists (E_NO_PREP) and a `strict` run exists (E_NO_STRICT),
  * the strict run STARTED AFTER the prep run COMPLETED (E_NOT_WARMED) — a
    strict run that overlapped prep was not warmed by it, whatever the clock
    says,
  * and a claimed reduction is a measured delta, never an assumption
    (E_NO_REDUCTION when the warm run was not faster).

Exit codes: 0 satisfied · 64 usage · 65 refused (evidence missing or negative).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# A fuzz shard may sit on a runner this long. The point of sharding is that the
# lane's wall clock is one shard, not the sum, so this is the lane budget too.
DEFAULT_SHARD_CEILING_MINUTES = 120


def _fail(code: str, message: str) -> int:
    print(f"ci-lane-budget: REFUSED [{code}] {message}", file=sys.stderr)
    return 65


def _die(message: str) -> int:
    print(f"ci-lane-budget: {message}", file=sys.stderr)
    return 64


# ---------------------------------------------------------------------------
# fuzz-bound
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> dict:
    import yaml  # imported lazily so `rq-prep` needs no YAML dependency

    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _shard_count(job: dict) -> int:
    matrix = job.get("strategy", {}).get("matrix", {})
    if not isinstance(matrix, dict):
        return 1
    if isinstance(matrix.get("include"), list):
        return len(matrix["include"])
    counts = [len(v) for v in matrix.values() if isinstance(v, list)]
    if not counts:
        return 1
    product = 1
    for count in counts:
        product *= count
    return product


def _job_text(job: dict) -> str:
    return json.dumps(job)


def fuzz_bound(workflows: list[Path], ceiling: int) -> int:
    findings: list[str] = []
    inspected = 0

    for path in workflows:
        if not path.is_file():
            return _die(f"workflow not found: {path}")
        document = _load_yaml(path)
        for name, job in (document.get("jobs") or {}).items():
            if "fuzz" not in name.lower():
                continue
            inspected += 1
            where = f"{path.name}:{name}"
            timeout = job.get("timeout-minutes")
            if not isinstance(timeout, int):
                findings.append(f"{where}: no timeout-minutes; the shard is unbounded")
            elif timeout > ceiling:
                findings.append(
                    f"{where}: timeout-minutes {timeout} exceeds the {ceiling}m shard ceiling"
                )
            shards = _shard_count(job)
            if shards < 2:
                findings.append(
                    f"{where}: not sharded ({shards} shard); one runner carries the whole lane"
                )
            text = _job_text(job)
            if "max_total_time" not in text:
                findings.append(
                    f"{where}: no -max_total_time; libFuzzer would run until the job timeout"
                )

    if inspected == 0:
        return _fail("E_NO_FUZZ_JOB", "no fuzz job found in the given workflows")
    for finding in findings:
        print(f"  {finding}", file=sys.stderr)
    if findings:
        return _fail("E_UNBOUNDED_FUZZ_LANE", f"{len(findings)} unbounded fuzz lane finding(s)")
    print(
        f"ci-lane-budget: OK — {inspected} fuzz job(s) sharded and bounded "
        f"(shard ceiling {ceiling}m, each shard carries -max_total_time)"
    )
    return 0


# ---------------------------------------------------------------------------
# rq-prep
# ---------------------------------------------------------------------------


def _parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _run_span(run: dict) -> tuple[datetime, datetime] | None:
    """Wall clock of a run: first job start to last job completion."""
    starts, ends = [], []
    for job in run.get("jobs", []):
        start = _parse_ts(job.get("startedAt"))
        end = _parse_ts(job.get("completedAt"))
        if start:
            starts.append(start)
        if end and end.year > 1971:  # GitHub reports 0001/1970 for unfinished jobs
            ends.append(end)
    if not starts or not ends:
        return None
    return min(starts), max(ends)


def _fetch_runs(repo: str, sha: str, workflow: str) -> list[dict]:
    listing = subprocess.run(
        [
            "gh", "run", "list", "--repo", repo, "--workflow", workflow,
            "--limit", "50", "--json", "databaseId,headSha,event,status,conclusion,displayTitle",
        ],
        check=True, capture_output=True, text=True,
    )
    runs = [row for row in json.loads(listing.stdout) if row["headSha"] == sha]
    detailed = []
    for row in runs:
        view = subprocess.run(
            ["gh", "run", "view", str(row["databaseId"]), "--repo", repo, "--json", "jobs"],
            check=True, capture_output=True, text=True,
        )
        row["jobs"] = json.loads(view.stdout).get("jobs", [])
        detailed.append(row)
    return detailed


def _mode_of(run: dict) -> str | None:
    """Classify a completed run as prep or strict from its job list.

    The API does not expose dispatch inputs on a completed run, so the mode is
    inferred: the proof-emitting jobs are gated on `inputs.mode == 'strict'`,
    and their presence is therefore proof of a strict run.

    Their ABSENCE proves nothing on its own, and assuming otherwise is how this
    measurement would lie. Those jobs are additionally gated on
    `needs.release-qualification.result == 'success'`, so a FAILED strict run
    has no proof jobs either and is indistinguishable from prep by shape alone.
    Only a successful run without them is prep; anything else is unknown and is
    excluded from the pairing rather than guessed at.
    """
    declared = run.get("mode")
    if declared in {"prep", "strict"}:
        return declared
    names = " ".join(job.get("name", "") for job in run.get("jobs", []))
    if "emit exact required proof" in names or "emit exact version-matrix evidence" in names:
        return "strict"
    if run.get("jobs") and run.get("conclusion") == "success":
        return "prep"
    return None


def rq_prep(runs: list[dict], sha: str, require_reduction: bool, out: Path | None) -> int:
    shas = {run["headSha"] for run in runs}
    if len(shas) > 1:
        return _fail("E_SHA_MISMATCH", f"runs span more than one candidate SHA: {sorted(shas)}")
    if shas and sha and shas != {sha}:
        return _fail("E_SHA_MISMATCH", f"runs are for {shas.pop()}, not the requested {sha}")

    preps = [r for r in runs if _mode_of(r) == "prep"]
    stricts = [r for r in runs if _mode_of(r) == "strict"]
    if not preps:
        return _fail(
            "E_NO_PREP",
            f"no prep run at {sha or 'the requested SHA'}; dispatch Release Qualification "
            "with mode=prep at this exact SHA before claiming a cold-start reduction",
        )
    if not stricts:
        return _fail("E_NO_STRICT", f"no strict run at {sha or 'the requested SHA'}")

    prep = min(preps, key=lambda r: (_run_span(r) or (datetime.max, datetime.max))[0])
    prep_span = _run_span(prep)
    if not prep_span:
        return _fail("E_INCOMPLETE_RUN", f"prep run {prep['databaseId']} has no completed jobs")

    warmed = []
    for run in stricts:
        span = _run_span(run)
        if span and span[0] >= prep_span[1]:
            warmed.append((run, span))
    if not warmed:
        return _fail(
            "E_NOT_WARMED",
            f"no strict run started after the prep run finished ({prep_span[1].isoformat()}); "
            "a strict run that overlapped prep was not warmed by it",
        )

    warm_run, warm_span = min(warmed, key=lambda pair: pair[1][0])
    warm_seconds = (warm_span[1] - warm_span[0]).total_seconds()

    cold = []
    for run in stricts:
        span = _run_span(run)
        if span and span[1] <= prep_span[0]:
            cold.append((run, span))
    cold_seconds = None
    if cold:
        cold_run, cold_span = max(cold, key=lambda pair: pair[1][1])
        cold_seconds = (cold_span[1] - cold_span[0]).total_seconds()

    evidence = {
        "schema": "rq-prep-evidence/v1",
        "candidate_sha": sha or (shas.pop() if shas else ""),
        "prep_run_id": prep["databaseId"],
        "prep_seconds": (prep_span[1] - prep_span[0]).total_seconds(),
        "warm_strict_run_id": warm_run["databaseId"],
        "warm_strict_seconds": warm_seconds,
        "cold_strict_run_id": cold[0][0]["databaseId"] if cold else None,
        "cold_strict_seconds": cold_seconds,
        "reduction_seconds": (cold_seconds - warm_seconds) if cold_seconds is not None else None,
        "verdict": "unproven",
    }
    if cold_seconds is None:
        evidence["verdict"] = "unproven"
        print(json.dumps(evidence, indent=2))
        return _fail(
            "E_NO_COLD_BASELINE",
            "a warmed strict run exists but no strict run at this SHA predates the prep run, "
            "so there is nothing to measure the reduction against",
        )
    evidence["verdict"] = "reduced" if cold_seconds > warm_seconds else "not-reduced"

    if out:
        out.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2))
    if evidence["verdict"] != "reduced":
        message = (
            f"warm strict ({warm_seconds:.0f}s) was not faster than cold strict "
            f"({cold_seconds:.0f}s); prep did not reduce the critical path"
        )
        if require_reduction:
            return _fail("E_NO_REDUCTION", message)
        print(f"ci-lane-budget: NOTE {message}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# selftest
# ---------------------------------------------------------------------------


def _run_fixture(
    run_id: int,
    mode: str,
    start: str,
    end: str,
    sha: str = "a" * 40,
    conclusion: str = "success",
) -> dict:
    jobs = [{"name": "quality", "startedAt": start, "completedAt": end}]
    if mode == "strict":
        jobs.append({"name": "emit exact required proof", "startedAt": end, "completedAt": end})
    return {
        "databaseId": run_id,
        "headSha": sha,
        "conclusion": conclusion,
        "jobs": jobs,
    }


def selftest() -> int:
    checks = 0

    def expect(actual: int, wanted: int, label: str) -> None:
        nonlocal checks
        assert actual == wanted, f"selftest: {label}: expected {wanted}, got {actual}"
        checks += 1
        print(f"PASS selftest: {label}")

    prep = _run_fixture(1, "prep", "2026-07-21T10:00:00Z", "2026-07-21T10:20:00Z")
    cold = _run_fixture(2, "strict", "2026-07-21T09:00:00Z", "2026-07-21T09:40:00Z")
    warm = _run_fixture(3, "strict", "2026-07-21T10:30:00Z", "2026-07-21T10:50:00Z")
    overlap = _run_fixture(4, "strict", "2026-07-21T10:10:00Z", "2026-07-21T10:45:00Z")

    expect(rq_prep([cold, warm], "a" * 40, True, None), 65, "no prep run is refused")
    expect(rq_prep([prep], "a" * 40, True, None), 65, "no strict run is refused")
    expect(
        rq_prep([prep, overlap], "a" * 40, True, None), 65,
        "a strict run overlapping prep is not counted as warmed",
    )
    expect(
        rq_prep([prep, warm], "a" * 40, True, None), 65,
        "a warm run with no cold baseline cannot claim a reduction",
    )
    expect(
        rq_prep([prep, cold, warm], "a" * 40, True, None), 0,
        "an exact-SHA prep -> warm strict pair with a cold baseline is measured",
    )

    slow_warm = _run_fixture(5, "strict", "2026-07-21T10:30:00Z", "2026-07-21T11:40:00Z")
    expect(
        rq_prep([prep, cold, slow_warm], "a" * 40, True, None), 65,
        "a warm run that was not faster is refused, not spun as success",
    )
    expect(
        rq_prep([prep, cold, slow_warm], "a" * 40, False, None), 0,
        "without --require-reduction the same case reports instead of failing",
    )

    mixed = _run_fixture(6, "strict", "2026-07-21T10:30:00Z", "2026-07-21T10:50:00Z", sha="b" * 40)
    expect(rq_prep([prep, mixed], "a" * 40, True, None), 65, "runs at two SHAs are refused")

    # A FAILED strict run has no proof jobs either — the workflow gates them on
    # success — so shape alone cannot tell it from prep. It must not be counted
    # as the prep half of a pair.
    failed_strict = _run_fixture(
        7, "prep", "2026-07-21T10:00:00Z", "2026-07-21T10:20:00Z", conclusion="failure"
    )
    expect(
        rq_prep([failed_strict, warm], "a" * 40, True, None), 65,
        "a failed run is not silently promoted to the prep half of the pair",
    )

    fuzz = ROOT / ".github" / "workflows" / "fuzz.yml"
    expect(fuzz_bound([fuzz], DEFAULT_SHARD_CEILING_MINUTES), 0, "this repo's fuzz lane is bounded")
    expect(fuzz_bound([fuzz], 1), 65, "a ceiling the lane exceeds is refused")

    print(f"ci-lane-budget: self-test OK ({checks} checks)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command")

    bound = sub.add_parser("fuzz-bound", help="assert every fuzz lane is sharded and bounded")
    bound.add_argument("--workflow", action="append", type=Path, default=None)
    bound.add_argument("--ceiling-minutes", type=int, default=DEFAULT_SHARD_CEILING_MINUTES)

    prep = sub.add_parser("rq-prep", help="measure whether an RQ prep run warmed the strict run")
    prep.add_argument("--repo", help="owner/name (live mode, needs gh)")
    prep.add_argument("--sha", default="", help="exact candidate SHA")
    prep.add_argument("--workflow", default="release-qualification.yml")
    prep.add_argument("--runs-json", type=Path, help="offline run fixtures instead of gh")
    prep.add_argument("--out", type=Path, help="write the evidence document here")
    prep.add_argument("--require-reduction", action="store_true")

    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    if args.command == "fuzz-bound":
        workflows = args.workflow or [ROOT / ".github" / "workflows" / "fuzz.yml"]
        return fuzz_bound(workflows, args.ceiling_minutes)
    if args.command == "rq-prep":
        if args.runs_json:
            runs = json.loads(args.runs_json.read_text(encoding="utf-8"))
        elif args.repo and args.sha:
            runs = _fetch_runs(args.repo, args.sha, args.workflow)
        else:
            return _die("rq-prep needs --runs-json, or --repo with --sha")
        return rq_prep(runs, args.sha, args.require_reduction, args.out)
    parser.print_help(sys.stderr)
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
