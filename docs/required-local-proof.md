# Local Required proof

`scripts/verify_required_local.sh` is the local counterpart to the effective
`required` profile in `.github/required/_quality.yml`. It emits
`required-proof/v2`: an exact SHA, tool versions, enforced resource budget, and
one outcome record for every effective Required command. It never claims that
GitHub CI is green and it never tags, pushes, publishes, or creates a release.

The command derives its plan from the projection. Every workflow step, action,
and condition must have an explicit classification; an unrecognised addition
fails closed rather than quietly falling out of the local graph. The resulting
required command IDs and their exact argv graph must also match the independent
`REQUIRED_LOCAL_COMMAND_IDS` and `REQUIRED_LOCAL_GRAPH_SHA256` commitments in
`.github/workflows/ci.yml`. CI checks that binding in its required `boundary`
job, so weakening the projection and a proof together without changing the
reviewed CI policy is rejected.

The producer records a sorted command-ID commitment and validates every emitted
ID, tier, and argv against its derived plan. The exact-SHA release consumer then
derives the plan independently from the candidate checkout and compares it with
the proof. An internally consistent but fabricated command graph is therefore
not release evidence.

The release consumer accepts a GitHub Actions run ID, not caller-authored job
JSON. It obtains the run, attempt jobs, and other Required workflow checks from
GitHub's HTTPS API, pins them to the candidate SHA, repository, `main` push, and
workflow path, and applies the repository CI taxonomy to those server-originated
records. The emitted release-candidate proof retains the validated Actions run
and attempt URLs as `github-actions-run` artifact references for later audit.

## Run it honestly

The proof requires a clean tree. In this shared checkout that normally means a
detached clean worktree at the exact SHA being proved. Running a workspace graph
against another pane's uncommitted code and recording `HEAD` would be false
evidence, so the runner exits 78 before it starts in that state.

Before the workspace commands, acquire the repository's Agent Mail build slot.
Then run:

```bash
scripts/verify_required_local.sh
```

The runner re-execs under `scripts/resource_budget.sh --profile test`, which
creates an isolated disk-backed target directory and enforces both memory and
PID/task ceilings. Its output is written to the ignored handoff path
`target/release-evidence/required/required-proof-<sha>.json` and immediately
checked by `scripts/validate_evidence.py`. The producer still refuses a dirty
tree before it runs; writing the proof under `target/` keeps the verified source
tree clean so `verify_release_exact_sha.sh` can consume that default path
without an exclusion file or a self-referential evidence commit.

Required commands that cannot run are records with `outcome: "skip"`; the v2
semantic validator treats that as a failing proof. The advisory live matrix is
recorded separately as a typed skip (`not-run-by-required-local`), never rounded
up to a pass.

For a DB-free graph/contract check without running the heavy commands:

```bash
scripts/test_verify_required_local.sh
```
