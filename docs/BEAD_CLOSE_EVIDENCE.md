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
scripts/check_bead_close_evidence.sh                # read-only audit
scripts/check_bead_close_evidence.sh --strict       # also fail on unevidenced closes
scripts/check_bead_close_evidence.sh --self-test    # deterministic control tests
```

Documents live at `tests/artifacts/evidence/closes/<bead-id>.json`. The filename
must match the document's `bead_id`; the audit checks it.

## The audit is read-only

It never writes a bead, never closes or reopens anything, never edits a file.
`--template` prints to stdout and nothing else. An auditor that can change what it
audits is not an auditor.

## Two tiers, kept apart on purpose

**Hard** — fails the audit. Every check is decidable:

| finding | meaning |
|---|---|
| any `E_*` from the contract | the document violates `bead-close-evidence/v1` |
| `MALFORMED_JSON` | it is not JSON |
| `BEAD_ID_MISMATCH` | the filename and the declared `bead_id` disagree |
| `SOURCE_SHA_ABSENT` | `source.sha` is not a commit in this repository |
| `SOURCE_SHA_NOT_AT_HEAD` | the source commit is not landed in HEAD ancestry |
| `PROOF_ARTIFACT_ABSENT` | a cited proof is not on disk |
| `LIVE_ARTIFACT_ABSENT` | a live claim points at a file that does not exist |
| `ORIGINAL_FALSE_CLOSE_UNCORRECTED` | a comment proves the original close false, but its own `close_reason` was not corrected |

Closes at or after `2026-07-18T20:00:00Z` also fail unless they carry evidence
that binds the close reason to `source.sha`, proves the source is landed, names
clean tracked scope entries as `path:<repo-relative pathspec>`, and finds an
exact `Bead: <id>` trailer in the source commit. A live/e2e close additionally
records both `lane` and immutable `run_id` in `live_evidence`. An ignored or
self-skipping test without that scheduled-lane artifact is never sufficient.
For Rust traces written as `path/to/test.rs::test_name`, the auditor reads the
named function's attributes and detects `#[ignore]`; the close cannot evade the
rule by omitting the word "ignored" from its prose.
Re-closing a pre-charter false-close solely to repair its original tracker text
is not a new delivery: it is exempt from source-path evidence only when the
original discovery comment remains, the corrected reason explicitly retracts
the claim, and it records both a run ID and corrective commit SHA.

```json
"live_evidence": {
  "claimed": true,
  "lane": "scheduled-oracle-matrix",
  "run_id": "gh-29638451182",
  "artifacts": [{ "kind": "version-matrix", "path": "...", "sha": "..." }]
}
```

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

## Unevidenced closes are not failures

This repo has many closed beads and the contract is new. Retroactively failing
every close that predates it would produce a permanently red gate, which teaches
people to ignore it. So the audit reports coverage as a number — currently 15
evidenced legacy closes — and that number should only move one way. CI pins it
with `--exact-evidence-floor 15`; deleting or invalidating evidence fails, and
adding valid evidence fails until the floor is raised in the same change.
`--strict` opts into failing on every historical gap, for a future
where the backlog is worked down. Post-charter closes are always gated.

The 70 advisory `LIVE_CLAIM_WITHOUT_REFERENCE` hits are a real finding about this
repo's history, not noise to suppress: 70 closes claim live or end-to-end work
without citing a commit or artifact. That is the pattern the epic was opened for.
They are recorded rather than fixed, because rewriting other agents' historical
closes is not this bead's job.

## `tree_clean` means "in scope", for a close

**This is a deliberate reading of a shared field, and the mirror repo must use the
same one.**

`source.tree_clean` in a close document asserts that **every file this close
claims is committed at `source.sha`** — objectively checkable:

```bash
git status --porcelain -- <scope.in_scope pathspecs> # empty => tree_clean: true
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

Each post-charter path entry uses the unambiguous form
`path:crates/example/src/lib.rs`. Absolute paths, pathspec magic, and `..`
escapes are rejected; a pathspec must exist in `source.sha` and be clean at HEAD.

## Close evidence lands one commit after the work

A document names `source.sha` — the commit the work landed in — so it cannot be
inside that commit. The order is: land the work with an exact `Bead: <id>`
trailer, then add its close evidence in the following commit, then close the
bead with `source.sha` (or an unambiguous prefix) in `close_reason`. The audit
requires that `source.sha` is an ancestor of HEAD and every scope path is clean.

## Tracker enumeration is fail-closed

Local audits ask `br list --all --deferred --json` for bounded pages and continue
until `has_more` is false. Every page, total, offset, and captured ID is
validated; duplicates, malformed JSON, or a changing total abort the audit.
Because list pages omit comments and dependency records, the local audit also
requires `.beads/issues.jsonl` to match live IDs and `updated_at` values; run
`br sync --flush-only` when it reports drift.
CI reads the checked-in `.beads/issues.jsonl` snapshot with the same unique-ID
validation, so it needs no network or tracker binary. All tracker timestamps
must carry explicit UTC. Umbrellas closed over unfinished leaves and ordinary
leaf-to-epic blocking edges are surfaced instead of hiding leaf readiness.

Before any bulk bead operation, capture and validate the complete machine
surface first; do not scrape human output or silently accept the first page:

```bash
br list --all --deferred --json --limit 0 \
  | scripts/audit_bead_closes.py --validate-id-capture -
```

The validator emits one JSON object containing `count` and the exact `ids`
array. It refuses malformed objects, duplicate IDs, mismatched totals, and any
capture whose `has_more` is not explicitly false.

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
