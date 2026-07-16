# CI taxonomy

`scripts/ci_taxonomy.py` derives the machine-readable CI contract directly
from `.github/workflows/*.yml` and writes it to
[`ci_taxonomy.json`](ci_taxonomy.json). Its `jobs[]` list is the one source of
truth for each check-run tier; the `workflows` and `groups` fields are derived
views, so they cannot disagree with the list.

The required result is deliberately stricter than a workflow badge: a run is
green only when every required job is `completed` with a `success` conclusion.
Cancelled, skipped, neutral, missing, in-progress, and failed required jobs are
all non-green. Advisory failures are reported separately and never upgrade or
downgrade that required result.

Run the offline contract checks:

```bash
python3 scripts/ci_taxonomy.py --check
python3 scripts/ci_taxonomy.py --list
python3 scripts/ci_taxonomy.py --write
```

With authenticated GitHub CLI access, evaluate an actual run or all workflow
runs for a commit:

```bash
python3 scripts/ci_taxonomy.py --status 714d70c652f59caa66915d8be88d6beadbdf534a
python3 scripts/ci_taxonomy.py --verify-names 714d70c652f59caa66915d8be88d6beadbdf534a
```

The workflow parser is intentionally narrow and stdlib-only. It accepts the
mapping/list/block-scalar patterns used by this repository and fails closed on
duplicate mapping keys. In particular, it catches a duplicate `with:` mapping
inside a `steps` list item, rather than silently accepting the last value. It
also expands the current matrix names and refuses to emit a check name with an
expression it cannot resolve.

## Shared v1 result

The sibling `rust-oracledb` repository mirrors the `ci-taxonomy/v1` shape. The
workflow content differs by repository, but both documents use `schema`,
`jobs[]` entries with `{check_name, tier, workflow, workflow_file, job_id,
triggers, path_filtered}`, derived `workflows`/`groups`, and status reports
with `ci_green`, `required_not_green`, `advisory_not_green`,
`required_missing_path_filtered`, `required_missing_unexpected`, and
`unknown_jobs`.

`--status` calls GitHub's check-runs endpoint, not run-level conclusions. It
returns non-zero unless every required check is a completed success; a missing
or unclassified check is non-green. `--verify-names` is the live reality check
for the derived labels, because plausible-looking YAML templates can otherwise
remain unmatched forever.

## Floating-nightly disposition

Run `29441201576` on Dependabot PR #18 had every required job succeed, while
the advisory `multi-nightly` floating entry was cancelled during
`cargo +nightly test --workspace --all-targets` after almost exactly six hours.
That is evidence of the old unbounded job reaching GitHub Actions' default
limit, not a compiler or test regression. The later `main` run `29493263831`
completed both the pinned and floating entries successfully (about fifteen and
nine minutes respectively). The workflow now pins an explicit bounded timeout
for that advisory job, so a future hang is reported as advisory evidence rather
than consuming the platform default.
