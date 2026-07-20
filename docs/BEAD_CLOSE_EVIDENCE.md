# Bead close evidence

A bead close is a claim: *this work is done, and here is why you should believe
it.* The failure this exists to prevent is the close that makes the claim and
skips the reason — the one that says "verified against 23ai" with nothing to
point at, or cites a proof that is red, or mentions a defect that no bead tracks.

The shape of the claim is
[`bead-close-evidence/v1`](../schemas/evidence/bead-close-evidence-v1.schema.json);
this document is how it is produced and audited.

```bash
scripts/audit_bead_closes.py --template <bead-id>   # scaffold, prefilled from git
scripts/audit_bead_closes.py --self-test            # no tracker or filesystem mutation
scripts/check_bead_close_evidence.sh                # read-only audit
scripts/check_bead_close_evidence.sh --strict       # also fail on unevidenced closes
scripts/bead_tracker_guard.sh close <bead-id> \
  --evidence tests/artifacts/evidence/closes/<bead-id>.json \
  --summary "What landed and which gates passed"
```

Documents live at `tests/artifacts/evidence/closes/<bead-id>.json`. The filename
must match the document's `bead_id`; the audit checks it.

## The audit is read-only

It never writes a bead, never closes or reopens anything, never edits a file.
`--template` prints to stdout and nothing else. An auditor that can change what it
audits is not an auditor.

The audit reads `.beads/issues.jsonl` directly instead of invoking `br`; use
`--issues-jsonl PATH` when auditing a different exported snapshot. Tracker
mutations live in the separate `bead_tracker_guard.sh` boundary. Malformed JSON,
non-integer `priority`, or non-integer `compaction_level` is a tracker-input
error (exit 2), reported with the exact JSONL path and line before any close is
trusted.

## Two tiers, kept apart on purpose

**Hard** — fails the audit. Every check is decidable:

| finding | meaning |
|---|---|
| any `E_*` from the contract | the document violates `bead-close-evidence/v1` |
| `MALFORMED_JSON` | it is not JSON |
| `BEAD_ID_MISMATCH` | the filename and the declared `bead_id` disagree |
| `SOURCE_SHA_ABSENT` | `source.sha` is not a commit in this repository |
| `PROOF_ARTIFACT_ABSENT` | a cited proof is not on disk |
| `LIVE_ARTIFACT_ABSENT` | a live claim points at a file that does not exist |
| `CLOSE_EVIDENCE_MISSING` | a post-enforcement close has no canonical evidence document |
| `CLOSE_REASON_UNBOUND` | the reason does not bind the closing commit, source commit, and evidence path |
| `CLOSE_EVIDENCE_NOT_LANDED` | the canonical evidence file was absent from the closing commit |
| `SCOPE_DIRTY_AT_CLOSE` | a pre-close check found uncommitted changes in claimed paths |
| `SCOPE_CHANGED_AFTER_SOURCE` | claimed paths changed between `source.sha` and the closing commit |
| `LIVE_RUN_ID_MISSING` / `LIVE_LANE_MISSING` | a live artifact lacks scheduled-lane identity |
| `LIVE_ARTIFACT_SOURCE_MISMATCH` | live artifact metadata does not name the exact source SHA |
| `SELF_SKIPPING_SOLE_PROOF` | `#[ignore]` or a self-skipping test is the only cited proof |

**Advisory** — reported, never gating. These are heuristics over free-text close
reasons, and they are kept out of the gate deliberately:

| finding | meaning |
|---|---|
| `CITED_SHA_UNRESOLVABLE` | the reason cites a hex string that does not resolve here |
| `LIVE_CLAIM_WITHOUT_REFERENCE` | the reason makes a live/e2e claim citing no commit or artifact |

`CITED_SHA_UNRESOLVABLE` **must not** be hard, and the reason is concrete: `etib.2`
legitimately cites `6cfd00aa642e`, an **upstream python-oracledb** commit that will
never resolve in this repository. Failing on it would flag a correct close. An
audit that cries wolf gets muted, and a muted audit is worse than no audit.

## Legacy debt and the enforcement epoch

This repo has many closed beads and the contract is new. Retroactively failing
every close that predates it would produce a permanently red gate, which teaches
people to ignore it. The hard gate therefore starts at
`2026-07-20T07:36:00Z`: a close at or after that instant must carry canonical
evidence and the exact close-reason binding. Older missing documents remain a
reported coverage number. `--strict` also fails on that legacy debt.

The advisory `LIVE_CLAIM_WITHOUT_REFERENCE` hits are a real finding about this
repo's history, not noise to suppress: legacy closes claim live or end-to-end
work without citing a commit or artifact. That is the pattern the epic was
opened for. They are recorded rather than rewritten, because historical
correction must happen on the original bead with replacement evidence.

## `tree_clean` means "in scope", for a close

**This is a deliberate reading of a shared field, and the mirror repo must use the
same one.**

`source.tree_clean` in a close document asserts that **every file this close
claims is committed at `source.sha`** — objectively checkable:

```bash
git status --porcelain -- <scope.in_scope paths>    # empty => tree_clean: true
```

It is **not** a claim that the entire working directory was pristine. This is a
multi-agent shared checkout: other panes routinely have unrelated files dirty, and
under a whole-tree reading *no agent could ever produce a valid close* — the gate
would be permanently red for everyone, for reasons having nothing to do with their
work.

The stricter whole-tree reading still applies where it earns its keep:
`required-proof/v1` and `mutation-result/v1` record commands that **actually
executed against the working tree**, so unrelated dirt genuinely can change what
they measured. A close document runs nothing; it is a set of references to a
commit, and a commit is by construction a clean tree.

This was found by dogfooding, not by a fixture: the first two close documents
written were the author's own, and the literal reading rejected one of them for
another agent's uncommitted file.

## Close evidence lands before the tracker close

A document names `source.sha` — the commit the work landed in — so it cannot be
inside that commit. The order is:

1. Commit the completed work; this is `source.sha`.
2. Add and commit `tests/artifacts/evidence/closes/<bead-id>.json`.
3. Run the guarded close command. Its preflight proves that the evidence is in
   `HEAD`, `source.sha` is its ancestor, all claimed paths are clean, and those
   paths did not change after `source.sha`.
4. The guard records all three references in `close_reason`:

   ```text
   [closing=<40-hex HEAD> source=<40-hex source.sha> evidence=<canonical path>]
   ```

The audit later resolves the binding and compares the evidence file with its
bytes at the recorded closing commit. A clobbered reason or edited-after-close
document is therefore detectable.

## Live claims and self-skipping tests

`live_evidence.claimed: true` requires a committed JSON artifact. In addition to
the artifact reference in the close document, that JSON object must carry:

- `run_id` or `workflow_run_id`;
- `lane`, `lane_name`, or `job`; and
- `source_sha`, `commit_sha`, `head_sha`, or `sha`, exactly equal to
  `source.sha`.

These fields make the scheduled lane and exact code revision independently
checkable. A trace that cites `#[ignore]`, `self-skip`, or `self-skipping` while
providing neither a proof document nor live artifact fails as sole proof.

## Serialized tracker transitions

Raw `br close` and `br update <id> --status open` are not safe swarm operations.
Use `scripts/bead_tracker_guard.sh`, which holds a lock in the repository's
shared git directory across the preflight, state read, and mutation. The lock is
common to every linked worktree.

Defense in depth is repository-native. `.beads/policy.yaml` makes `br close`
itself require the exact closing/source/evidence binding suffix and disables
`--bypass-policy`. The Required graph and the `boundary` CI job both run
`scripts/check_bead_close_evidence.sh`, which validates that native policy and
then proves the referenced evidence was committed, belongs to the bead, and
matches the bound commits. A direct raw close therefore fails immediately when
it omits the binding and cannot silently merge when it forges a binding without
the corresponding landed evidence.

The serialization guarantee covers guarded transitions. A raw tracker mutation
does not take this repository-level lock, which is why the operating contract
above prohibits raw close and claim-release commands rather than presenting the
wrapper as protection from a non-compliant writer.

```bash
# Release only an actual in-progress claim; a concurrently closed bead is kept.
scripts/bead_tracker_guard.sh release-claim <bead-id>

# Correct the bead that made the false claim, not a sibling or new placeholder.
scripts/bead_tracker_guard.sh correct-false-close \
  --original-bead <original-bead-id> \
  --evidence tests/artifacts/evidence/closes/<original-bead-id>.json \
  --summary "Corrected scope and evidence"
```

The correction command preflights the replacement evidence, then reopens and
re-closes the explicitly named original bead under the same lock. If re-closing
fails, the bead remains open; it never restores the false closed state.

## Readiness: what a close may claim

`readiness` is a **pair**, and the pair is checked:

| basis | may claim `ready`? |
|---|---|
| `required-proof` | yes — the full Required graph ran at this SHA |
| `live-evidence` | yes — an exact-SHA live artifact exists |
| `scoped-test` | **no** → `E_SCOPED_TEST_CANNOT_MARK_READY` |
| `manual-review` | **no** → `E_INSUFFICIENT_READINESS_BASIS` |

A scoped test exercises the part of the change you were thinking about and says
nothing about the rest. Declaring `not-ready` on a scoped test is the honest way
to record complete-but-unproven work, and it is what the first two close documents
in this repo do — including this bead's own.

Note the consequence, which is intended: **until `f1cl.2` ships the
`required-proof/v1` producer, nothing here can honestly claim
`basis: required-proof`.** That is not a gap in the tooling; it is the tooling
telling the truth about what evidence exists.
