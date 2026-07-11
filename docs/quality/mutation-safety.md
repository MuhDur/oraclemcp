# Mutation Safety Gate

<!-- MUTATION-GATE guard=91.5 audit=95.7 threshold=90 status=enforcing -->

D6.4 validates the safety-critical server crates with `cargo-mutants` through
`scripts/mutation_safety_gate.sh`. The gate covers:

- `oraclemcp-guard`: fail-closed classifier, purity plumbing, operating-level
  helpers.
- `oraclemcp-audit`: signed audit records, head anchor, verifier, local sink,
  and shipping format helpers.

## Current Proof

Run date: 2026-07-08

Command shape:

```bash
export CARGO_TARGET_DIR=/home/durakovic/.cache/cargo-target-server
export CARGO_BUILD_JOBS=16
bash scripts/mutation_safety_gate.sh run --advisory --jobs 1 --crate oraclemcp-audit
bash scripts/mutation_safety_gate.sh run --advisory --jobs 1 --crate oraclemcp-guard
```

Results:

| Crate | Kill rate | Caught | Missed | Timeout | Unviable |
| --- | ---: | ---: | ---: | ---: | ---: |
| `oraclemcp-guard` | 91.5% | 173 | 16 | 0 | 13 |
| `oraclemcp-audit` | 95.7% | 201 | 9 | 0 | 19 |

The validated safe default is one mutant build at a time. An initial capped
`-j4` guard attempt was killed inside the MemoryMax cgroup before producing a
complete outcome set; `-j1` completed both crates cleanly and is now the script
default. Operators may opt into higher concurrency with `--jobs` on larger
runners, but release gating should use the default.

## Survivor Triage

The remaining survivors are below the enforcing threshold. They fall into these
classes:

- Guard classifier fallback-equivalent arms where deleting an explicit
  `Insert`/`Merge`/transaction arm falls through to the same fail-closed
  `Guarded / ReadWrite` catch-all.
- Guard parser-shape diagnostics that are redundant with other fail-closed
  branches in the public classifier verdict.
- Guard process-generation bit-mixing alternatives that still produce a stable,
  nontrivial per-process nonce; expiry semantics stay pinned by stale-generation
  tests.
- Audit platform-observability edges where success-only `fsync`/unlock paths do
  not expose a deterministic behavior difference without fault-injection hooks.
- Audit v2 legacy hash helper coverage where v3/v4/v5 production verification
  is fully pinned and v2 compatibility still has direct valid-record tests.

No survivor required weakening guard or audit production logic. The added tests
pin the missing safety contracts directly: allow-list specificity, marker
tokenization, nested DML walkers, block body segmentation, anchor MAC preimages,
versioned audit hashes, SIEM severity/escaping, missing-log resume, and empty
head-anchor behavior.

## Gate Policy

`scripts/mutation_safety_gate.sh run` is the authoritative slow proof and runs
nightly. `scripts/release_preflight.sh` calls
`scripts/mutation_safety_gate.sh check-report`, which enforces the committed
marker above without rerunning the slow mutation pass during every release
preflight.
