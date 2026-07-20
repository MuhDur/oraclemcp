# Mutation Safety Gate

<!-- MUTATION-GATE v=2 source=4dca0b286bf12bd65810307e8c8d11a83e597622 scopes=guard,audit scope_sha256=317b00bb6268a599c3eea7909ca4c2a46f9a6c73ba5c78b7e66ad297dfd4885f covered_files=27 mutants=1889 shards=3/3 oom=unknown guard=92.6 audit=96.9 core=pending db=pending dispatch=pending threshold=90 status=stale -->

D3 / TRI-2 validates the safety-critical server surfaces with `cargo-mutants`
through `scripts/mutation_safety_gate.sh`. The campaign covers:

- `oraclemcp-guard`: fail-closed classifier, purity plumbing, operating-level
  helpers.
- `oraclemcp-audit`: signed audit records, head anchor, verifier, local sink,
  and shipping format helpers.
- `oraclemcp-core`: runtime policy and protocol control surfaces.
- `oraclemcp-db`: database execution and transaction boundaries.
- `oraclemcp/src/dispatch`: the final tool-dispatch boundary.

## Current Seal Status: Stale (Fail-Closed)

The v2 marker is deliberately `status=stale`. The last completed proof predates
the D3 integrity contract, recorded no cgroup OOM counter, covered only guard and
audit, and the covered source has changed since its seal commit. It therefore
cannot certify the expanded five-surface scope. `check-report` now returns
`E_STALE_SEAL`; release preflight and the D2 mutation leg stay red until a fresh,
complete, OOM-free campaign is assembled and reviewed. Keeping the old
percentages visible is provenance, not an enforcing claim.

## Legacy Proof (Not a Current Seal)

Run date: 2026-07-14 (GATE-SEAL, bead `oraclemcp-epic-09x-alien-6sj8.16`).

The prior marker recorded `guard=95.0` / `audit=90.0` as `enforcing`. That was
FALSE: the guard runs behind it had died early (only `classifier.rs` was ever
tested; `policy.rs` / `levels.rs` were never reached), so the true first
complete guard score was 83.5%, and the audit crate had never had a complete
mutation pass. This proof is the corrected, complete result after a
survivor-killing campaign. Every mutant was run to a non-null `end_time`;
survivor-killing tests were verified by applying each mutation and confirming the
new test fails under it (generate-and-verify), never merely passing on HEAD.

Legacy method: `cargo-mutants` at `-j1` per mutant, audit
run sharded 2-way (`--shard i/2`, each `-j1`, isolated target + frozen HEAD
snapshot) and merged. Kill rate = `(caught + timeout) / (caught + missed +
timeout)`; `unviable` (won't compile) excluded. D3 does **not** carry that
denominator forward: timeouts are reported separately and never promoted to a
confirmed-test-failure kill.

Results:

| Crate | Kill rate | Caught | Missed | Timeout | Unviable |
| --- | ---: | ---: | ---: | ---: | ---: |
| `oraclemcp-guard` | 92.6% | 1017 | 82 | 2 | 142 |
| `oraclemcp-audit` | 96.9% | 527 | 17 | 34 | 68 |

These figures were the certified floor for that historical tree. They are not a
certified floor for current HEAD.

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

## D3 Shard Integrity Contract

Run exactly one deterministic shard with:

```bash
bash scripts/mutation_safety_gate.sh self-test
bash scripts/mutation_safety_gate.sh run-shard \
  --scope guard --shard 1/40
```

The runner is fixed at `-j1`, unsets `CARGO_TARGET_DIR`, refuses a shard above 32
mutants, and requires a systemd cgroup with explicit `MemoryMax`, `TasksMax`,
`MemorySwapMax=0`, and `OOMPolicy=continue` (local defaults: 12G/8192; the
smaller hosted runner uses 6G/384 so the child ceiling is below its parent).
Its inner wrapper reads `memory.events:oom_kill` and `pids.events:max` before
and after cargo-mutants. A non-zero delta writes an `errored` integrity sidecar
and fails `E_OOM_MUTANT` or `E_TASK_CAP`; it is never counted as `caught`, even
if cargo-mutants observed a killed or failed-to-spawn test process.

Each shard retains:

- the full and selected mutant inventories;
- raw `outcomes.json` and logs;
- `integrity.json`, binding the source SHA, covered-file hash, shard index/total,
  full and selected mutant populations, raw-outcomes hash, command exit, and OOM
  delta.

`scripts/migrate_mutation_result.py` is the seal boundary. It requires one
integrity sidecar per outcomes file and refuses OOM/task-cap/error/null-`end_time`
shards, partial counters, a changed outcomes hash, missing shard indices,
duplicate mutants, or a union smaller than the full declared population. Only
then can it emit `mutation-result/v1`. That artifact reports confirmed test
failures (`caught`) separately from `timeout` and `unviable`; timeout is in the
declared denominator but never appears as a witnessed kill.

The scheduled workflow rotates two deterministic shards per scope per night.
Fixed shard totals keep every shard at at most 32 current mutants; if source
growth crosses that budget, the runner fails and the total must be deliberately
raised. The 128-shard core cycle completes in 64 nights, within the 90-day
artifact retention window. `workflow_dispatch` accepts an exact scope and
`I/N` shard for recovery or a deliberate full-campaign sweep.

## Gate Policy

`scripts/mutation_safety_gate.sh check-report` accepts only a v2 marker with all
five scopes, numeric per-scope confirmed-failure rates above the threshold,
complete shard counts, `oom=0`, and a covered-file hash matching the current
tree. There is no advisory-green path. The committed marker remains stale until
the first complete D3 campaign is reviewed and its exact seal values replace it.
