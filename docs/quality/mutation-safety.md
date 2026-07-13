# Mutation Safety Gate

<!-- MUTATION-GATE guard=95.0 audit=90.7 threshold=90 status=enforcing -->

D6.4 validates the safety-critical server crates with `cargo-mutants` through
`scripts/mutation_safety_gate.sh`. The gate covers:

- `oraclemcp-guard`: fail-closed classifier, purity plumbing, operating-level
  helpers.
- `oraclemcp-audit`: signed audit records, head anchor, verifier, local sink,
  and shipping format helpers.

## Current Proof

Run date: 2026-07-13

Command shape:

```bash
TMPDIR=/var/tmp \
MUTATION_OUTPUT=/var/tmp/oraclemcp-mutation-bgec2-20260712T234242Z \
scripts/mutation_safety_gate.sh run --crate oraclemcp-guard --jobs 1

TMPDIR=/var/tmp \
MUTATION_JOBS=2 \
MUTATION_TIMEOUT=45 \
MUTATION_OUTPUT=/var/tmp/oraclemcp-mutation-audit-final-j2t45-20260713T014539Z \
scripts/mutation_safety_gate.sh run --crate oraclemcp-audit --jobs 2
```

Results:

| Crate | Kill rate | Caught | Missed | Timeout | Unviable |
| --- | ---: | ---: | ---: | ---: | ---: |
| `oraclemcp-guard` | 95.0% | 470 | 25 | 1 | 64 |
| `oraclemcp-audit` | 90.7% | 374 | 40 | 18 | 52 |

The validated safe default remains one mutant build at a time. The guard proof
used the default `-j1`. The audit proof used `-j2` plus a 45-second mutant test
timeout because the unmutated audit baseline completed in roughly four seconds
and several killed mutants otherwise spent the full default timeout in
panic-path worker waits. Operators may opt into higher concurrency with
`--jobs` on larger runners, but guard runs should stay conservative unless the
runner is known to tolerate the extra build pressure.

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
- Audit platform-observability edges where success-only `fsync`, flush, unlock,
  worker-drop, and directory-sync paths do not expose a deterministic behavior
  difference without fault-injection hooks.
- Audit proof/diagnostic-only surfaces (`cfg(kani)`, display formatting, and
  line-number diagnostics) where normal unit tests do not execute the proof
  harness or where the mutation is equivalent for the production byte stream.

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
