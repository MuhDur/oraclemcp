# Architecture Decision Records

Short records of the load-bearing decisions behind `oraclemcp`. Each ADR follows
a standard shape — **Status / Context / Decision / Consequences** — and adds an
explicit, objective **Review trigger**: the observable condition under which the
decision should be revisited, so a future reader knows *when* it expires rather
than treating it as permanent.

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-pinned-nightly-toolchain.md) | Pinned nightly toolchain — asupersync needs nightly-only features (no stable MSRV) | Accepted |
| [0002](0002-driver-adapter-seam.md) | Driver-adapter seam isolates `oracledb` churn to one file (+ B5 public-API lock addendum) | Accepted |
| [0003](0003-keyed-mac-audit-chain.md) | Keyed-MAC (HMAC-SHA256) signed audit chain wired into served dispatch | Accepted |
| [0004](0004-governed-operating-level-ladder.md) | Governed operating-level ladder with confirmation-gated escalation | Accepted |
| [0005](0005-awr-diagnostics-license-gating.md) | AWR / Diagnostics-Pack license gating (never invoke a paid pack unlicensed) | Accepted |
| [0006](0006-oraclemcp-db-canonical-foundation.md) | `oraclemcp-db` is the canonical shared driver foundation; converge `plsql-mcp` onto it | Accepted |
| [0007](0007-phase0-lane-bridge.md) | Phase-0 lane bridge for non-Send Oracle sessions | Accepted |

These records describe *why*, not *how*. For the runtime behavior they govern,
see the [`README.md`](../../README.md) safety model and
[`docs/operations.md`](../operations.md).
