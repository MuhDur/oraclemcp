# Mutation Safety Gate

<!-- MUTATION-GATE guard=92.6 audit=96.9 threshold=90 status=enforcing -->

D6.4 validates the safety-critical server crates with `cargo-mutants` through
`scripts/mutation_safety_gate.sh`. The gate covers:

- `oraclemcp-guard`: fail-closed classifier, purity plumbing, operating-level
  helpers.
- `oraclemcp-audit`: signed audit records, head anchor, verifier, local sink,
  and shipping format helpers.

## Current Proof

Run date: 2026-07-14 (GATE-SEAL, bead `oraclemcp-epic-09x-alien-6sj8.16`).

The prior marker recorded `guard=95.0` / `audit=90.0` as `enforcing`. That was
FALSE: the guard runs behind it had died early (only `classifier.rs` was ever
tested; `policy.rs` / `levels.rs` were never reached), so the true first
complete guard score was 83.5%, and the audit crate had never had a complete
mutation pass. This proof is the corrected, complete result after a
survivor-killing campaign. Every mutant was run to a non-null `end_time`;
survivor-killing tests were verified by applying each mutation and confirming the
new test fails under it (generate-and-verify), never merely passing on HEAD.

Method: `cargo-mutants` at `-j1` per mutant (the validated safe default), audit
run sharded 2-way (`--shard i/2`, each `-j1`, isolated target + frozen HEAD
snapshot) and merged. Kill rate = `(caught + timeout) / (caught + missed +
timeout)`; `unviable` (won't compile) excluded.

Results:

| Crate | Kill rate | Caught | Missed | Timeout | Unviable |
| --- | ---: | ---: | ---: | ---: | ---: |
| `oraclemcp-guard` | 92.6% | 1017 | 82 | 2 | 142 |
| `oraclemcp-audit` | 96.9% | 527 | 17 | 34 | 68 |

The guard figure is a certified floor: it is a complete run whose guard *source*
(non-test code) is unchanged on the current HEAD; additional kill-tests landed
since can only raise it. The audit figure is fresh against the release HEAD.

## Survivor Triage

Every surviving mutant was individually adjudicated (see the campaign log). No
survivor required weakening guard or audit production logic; the killing tests
pinned real safety contracts. The residue falls into honest classes:

- **True equivalents** — the mutation cannot change any observable outcome:
  guard fallback-equivalent classifier arms (deletion falls through to the same
  fail-closed catch-all); audit disjoint-nibble `|`/`^` hex decode; `Drop` impls
  whose effect (fd-close releasing an flock) is identical to the no-op on the
  success path; `&`/`|` on file-mode type bits that never overlap; platform
  `cfg`-gated branches; an `analyze_resume_log` index that only feeds a discarded
  diagnostic field.
- **`cfg(kani)` proof harnesses** — compiled OUT of the `cargo test` binary the
  gate runs, so the mutation is never executed (tracked separately as
  `oraclemcp-d6ij`: the proofs also need anti-vacuity guards).
- **Diagnostic-log-only** — audit `enqueue`/`acknowledge` counters whose mutated
  local feeds only a `tracing::debug!` field; the atomics observable via
  `status()` are un-mutated, so real behavior is correct. Not killed via a
  flaky global-subscriber capture; documented instead.
- **fsync error-path only** — `WormFileForwarder::flush` / `FileAuditSink::flush`
  wrap `File::sync_all()`; the success path is byte-identical to `Ok(())` and only
  the (unreachable-in-unit-test) fsync-error path differs. No injectable fault
  seam; documented, not dismissed as equivalent.

## Gate Policy

`scripts/mutation_safety_gate.sh run` is the authoritative slow proof and runs
nightly. `scripts/release_preflight.sh` calls
`scripts/mutation_safety_gate.sh check-report`, which enforces the committed
marker above without rerunning the slow mutation pass during every release
preflight.
