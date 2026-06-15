# O3 Optimization Convergence

Scope: final `extreme-software-optimization` pass for bead `oraclemcp-8fc.2`.

The optimization loop now has two landed changes:

1. O1 lazy `tools/list` cache for repeated discovery calls.
2. O2 cursor lifecycle fix that keeps thin-driver statement-cache reuse valid
   on long-lived Oracle sessions.

Remaining measured candidates:

| Candidate | Best current evidence | Score | Decision |
| --- | --- | ---: | --- |
| Cold physical Oracle connect | O2 live Oracle 23ai cold connect: p50 144.346 ms, p95 154.685 ms. | 1.6 | Do not change in oraclemcp. This is driver/network/database startup; a product-level warmup or driver pool design is needed before code changes. |
| Steady `describe()` metadata | O2 steady describe: p50 1.310 ms, p95 1.559 ms. | 1.7 | Do not cache yet. Correct invalidation needs profile/session/role/open-mode design. |
| Steady scalar/bind query | O2 steady scalar query p50 0.195 ms, bind query p50 0.207 ms. | 0.9 | Already below threshold; safety and type fidelity risk outweigh possible gains. |
| Classifier | P2 classifier p95 about 14.36 us per statement. | 0.7 | Not a hotspot and is the fail-closed guard. |
| BLOB/base64 serialization | P2 BLOB cap benchmark p50 116.82 us. | 1.5 | Defer until a real workload shows it dominates. |

Convergence decision:

- No remaining in-repo optimization candidate clears the score threshold.
- The largest latency is cold physical connection setup, which should be handled
  as a separate product/driver design rather than a local micro-optimization.
- The code path touched by O2 is now covered by a live 23ai regression and the
  ignored phase-split profiler for future campaigns.

Stop condition satisfied: one convergence pass with no safe score >= 2.0 after
two landed optimizations and full workspace/live verification.
