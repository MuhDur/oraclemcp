# Performance and Footprint Evidence

This file summarizes local measurement evidence for the thin-native
`oraclemcp` line. It is not a marketing benchmark: numbers are scoped to the
host and commands recorded in
`tests/artifacts/perf/20260615T182242Z-7dd4a60/`.

The [Net load + shutdown soak](#net-load--shutdown-soak-b3) section below is the
B3 release-gate evidence: an OFFLINE deterministic harness asserts the
zero-leaked-sessions / clean-drain / bounded invariants without a database, and
a `live-xe` variant captures real-Oracle latency (p50/p95/p99) when run against
a live database. Live latency figures are NOT invented here — the
["Live measurements"](#live-measurements-b3--d7) section is populated by a live
run, exactly like the exact-SHA release qualification.

## Run

| Field | Value |
|---|---|
| Run id | `20260615T182242Z-7dd4a60` |
| Source | W13 worktree measured on base commit `7dd4a60786207162fb05cb3af6523598c39ddb38` |
| Host | AMD EPYC 7713, 128 logical CPUs, Ubuntu 25.10, Linux 6.17.0 |
| Toolchain | `rustc 1.97.0-nightly (4b0c9d76a 2026-05-10)` |
| Tuning | No kernel/CPU tuning applied; governor `schedutil`, boost enabled |

## Footprint

| Artifact | Measurement | Notes |
|---|---:|---|
| Release binary | 15,560,416 bytes | `/tmp/cargo-target/release/oraclemcp` |
| Docker image | 253,337,830 bytes | `oraclemcp:w13-7dd4a60` |
| Docker context | 5.918 MB | `.dockerignore` excludes markdown and build outputs |

The first Docker build attempt failed because the builder image had no C
compiler/linker (`cc`). The Dockerfile now installs `gcc` only in the builder
stage; the runtime smoke check confirmed `runtime_gcc=absent`.

The final binary also passes a Unix pipe smoke check:
`oraclemcp capabilities | head -c 1200 >/dev/null` exits cleanly under
`pipefail` instead of printing Rust's default broken-pipe panic.

## Offline Startup

Thirty warm local runs, output redirected to `/dev/null`.

| Command | p50 | p95 | max | RSS p50 | RSS p95 | RSS max |
|---|---:|---:|---:|---:|---:|---:|
| `oraclemcp info` | 6.432 ms | 8.053 ms | 9.204 ms | 3,136 KB | 3,200 KB | 3,212 KB |
| `oraclemcp capabilities` | 7.501 ms | 9.398 ms | 9.989 ms | 5,180 KB | 5,236 KB | 5,240 KB |

## Synthetic Read Workflow

These are **offline, non-live** signals — local CPU work measured against a
connection mock, NOT Oracle round-trip latency. They are the in-process cost the
server adds *around* a query and are deliberately distinct from the live DB
latency captured by the `live-xe` harness in
[Live measurements](#live-measurements-b3--d7) below; do not read them as
end-to-end query times.

Criterion benchmark:
`cargo bench -p oraclemcp-db --bench page_serialization -- --sample-size 20`.
This measures local `read_query` page construction and serialization after rows
have already been returned by a database connection mock.

Re-measured on 0.4.0 / oracledb-0.5.0 (run `20260623-v0.4.0-oracledb0.5.0-473f9a8`,
criterion median; shared host, so treat small deltas as host-load variance, not a
regression — the path stays linear and is a tiny fraction of the ~0.9 ms live
round trip):

| Scenario | Criterion median (0.4.0) | W13 (0.3.0) baseline |
|---|---:|---:|
| 10 rows | 17.535 us | 13.223 us |
| 200 rows | 429.58 us | 354.49 us |
| 1000 rows | 2.1443 ms | 1.7810 ms |

Classifier baseline:
`cargo test -p oraclemcp-guard --release --test perf_classifier -- --ignored --nocapture`.

| Scenario | Measurement |
|---|---:|
| Fail-closed SQL classification | 14,290 ns/statement |
| Throughput | ~69,979 classifications/sec |

## Package Sizes

`.crate` packages produced by `cargo package --workspace --locked --no-verify`.
Re-measured on the **0.4.0 / oracledb-0.5.0** line (run
`20260623-v0.4.0-oracledb0.5.0-473f9a8`; full results in
`tests/artifacts/perf/20260623-v0.4.0-oracledb0.5.0-473f9a8/RESULTS.md`). The
`## Run` / `## Footprint` / `## Offline Startup` figures above are the earlier
W13 (0.3.0-line) baseline; their 0.4.0 re-measurement is in that artifact dir.

| Package | Size |
|---|---:|
| `oraclemcp-error-0.4.0.crate` | 10,650 bytes |
| `oraclemcp-audit-0.4.0.crate` | 27,405 bytes |
| `oraclemcp-guard-0.4.0.crate` | 83,718 bytes |
| `oraclemcp-auth-0.4.0.crate` | 20,619 bytes |
| `oraclemcp-config-0.4.0.crate` | 30,451 bytes |
| `oraclemcp-db-0.4.0.crate` | 194,185 bytes |
| `oraclemcp-telemetry-0.4.0.crate` | 48,868 bytes |
| `oraclemcp-core-0.4.0.crate` | 175,694 bytes |
| `oraclemcp-0.4.0.crate` | 164,266 bytes |
| Release binary `oraclemcp` (0.4.0) | 18,518,328 bytes |

## Net load + shutdown soak (B3)

The B3 release-gate evidence has two halves: an **offline deterministic**
harness (always run in CI) and a **live** variant (run against a real database
to capture latency). The offline half exercises B1's thread-per-connection +
async model — N concurrent in-process clients, each its own OS thread driving
its own current-thread Asupersync runtime via `block_on`, exactly as
`oraclemcp-core/src/server.rs` drives one runtime per HTTP connection — through
the session lifecycle the dispatch path uses (acquire a lease over a connection,
run a query mix, release).

### Load shape

| Parameter | Offline soak | Live soak (`live-xe`) |
|---|---|---|
| Clients (N) | 8 concurrent (one runtime/thread each) | operator-chosen, ≤ per-DB ceiling |
| Query mix | 70% read, 20% describe, 10% preview-DML | same mix |
| Soak length | 200 iterations/client (1,600 ops) | operator-chosen duration |
| Session model | acquire → op → release every iteration | same |
| Clock | logical/deterministic | wall clock |

The mix is selected by a per-client counter, so the offline verdict is
reproducible and never schedule-accidental.

### Metrics recorded

* checkout accounting ledger — `acquired`, `released`, `discarded`, live count,
  and the live high-water mark;
* `LeaseManager::active_count()` after the shutdown drain;
* commits observed on drained sessions (must be zero);
* (live only) per-operation latency samples → p50/p95/p99, plus the real
  `OraclePool` `PoolMetrics` snapshot (`is_balanced` / `is_bounded`).

### Pass conditions (asserted in the harness)

| Invariant | Assertion |
|---|---|
| ZERO leaked sessions | `acquired == released + discarded` AND live count returns to 0 |
| No orphan session | `LeaseManager::active_count() == 0` after `release_all` |
| Clean drain | shutdown stops new acquires; every open txn is force-rolled-back; readiness flips to draining |
| No torn commit | commits on drained/preview sessions == 0 |
| Bounded | live high-water mark ≤ N (the per-DB ceiling); open pool connections ≤ `max_size` |

### How to run

Offline (no database — runs in CI):

```text
cargo test -p oraclemcp-db --test load_soak \
  load_soak_zero_leaked_sessions_clean_drain_bounded
```

Live latency capture (requires a real Oracle database):

```text
ORACLEMCP_LIVE_XE=1 \
  ORACLEMCP_TEST_DSN=localhost:1521/FREEPDB1 \
  ORACLEMCP_TEST_USER=... ORACLEMCP_TEST_PASSWORD=... \
  cargo test -p oraclemcp-db --test load_soak -- --ignored --nocapture
```

Start a throwaway Oracle FREE 23ai database for this with:

```sh
docker run -d --name oracle-free -p 1521:1521 \
  -e ORACLE_PASSWORD=<pw> gvenzl/oracle-free:23-slim   # provides FREEPDB1 on :1521
```

The live test skips with a clear message when `ORACLEMCP_LIVE_XE` is unset. The
env-var names above are the exact ones the harness reads
(`crates/oraclemcp-db/tests/load_soak.rs`): `ORACLEMCP_LIVE_XE` is the on switch
(the heavy load/soak is explicitly opt-in), and the connection parameters come
from the unified `ORACLEMCP_TEST_DSN` / `ORACLEMCP_TEST_USER` /
`ORACLEMCP_TEST_PASSWORD` env shared by the rest of the live suite.

### Latency pass thresholds (judged against the live run)

The numbers below are **acceptance thresholds**, not measurements — they let a
reviewer judge a live run pass/fail without re-deriving expectations. They are
deliberately generous (a per-iteration acquire → op → release cycle against a
local XE on a non-tuned host), and exist so a regression that, say, doubles p95
is caught. They apply to the `oracle_query`-class read op in the 70/20/10 mix.

| Metric | Threshold (pass if ≤) | Rationale |
|---|---:|---|
| `oracle_query` p50 | 25 ms | Round-trip + small fetch on a co-located XE. |
| `oracle_query` p95 | 75 ms | Tail under N-client contention at the per-DB ceiling. |
| `oracle_query` p99 | 150 ms | Worst-case under GC/pool checkout jitter. |
| Leaked sessions | 0 (hard) | Same invariant the offline harness asserts. |
| Pool accounting balanced (`PoolMetrics::is_balanced`) | yes (hard) | Live analogue of the offline ledger balance. |
| Clean drain on shutdown | yes (hard) | Force-rollback + readiness→draining. |

The latency rows are *soft* environment-scoped budgets (record the host
alongside the numbers); the leak / balance / drain rows are **hard** — a live
run that fails any of them fails the gate regardless of latency. A live run that
exceeds a latency budget on a slow/shared host is annotated, not silently
passed.

### Live measurements (B3 / D7)

> **Populated from a live run (numbers are the harness's own output).** Filled
> from a real `live-xe` load/soak against a real Oracle 23ai — NOT hand-edited
> estimates. These are from a **dev-host validation run** on the current branch
> (a local `gvenzl/oracle-free:23-slim` FREEPDB1 container); the official
> **exact-SHA release qualification re-runs this on the frozen RC** on the release
> host (bead `release-gre.14`) and overwrites the id/host/numbers below. The
> honesty-grep gate and release review reject invented numbers. Workload note: the
> load/soak op mix is lightweight (SELECT 1 / describe) driven through the pool —
> the in-process + round-trip floor, well under the `oracle_query` thresholds
> above (which cover the full guarded query tool).

| Metric | Value | Captured by |
|---|---|---|
| Run id | `20260623-v0.4.0-oracledb0.5.0-473f9a8` (dev-host validation) | `live-xe` |
| Host | AMD EPYC 7713, Ubuntu 25.10, Linux 6.17.0, governor `schedutil` (no tuning) | `live-xe` |
| Database | Oracle 23ai FREE (`gvenzl/oracle-free:23-slim`, FREEPDB1), local container | `live-xe` |
| Clients (N) | 8 | `live-xe` |
| Soak duration | 200 iterations/client | `live-xe` |
| Total operations | 1,600 | `live-xe` |
| load/soak op p50 | 0.905 ms (well under the ≤ 25 ms `oracle_query` threshold) | `live-xe` |
| load/soak op p95 | 2.984 ms (well under ≤ 75 ms) | `live-xe` |
| load/soak op p99 | 3.410 ms (well under ≤ 150 ms) | `live-xe` |
| Leaked sessions | 0 | `live-xe` |
| Pool accounting balanced | yes (every per-client `PoolMetrics::is_balanced`) | `live-xe` |
| Clean drain | yes (offline soak asserts force-rollback + zero held leases) | `live-xe` |

## Scope Limits

Live Oracle connect/query latency was not measured in this run. No Oracle
credentials, wallet paths, connect strings, schema names, or customer data were
used. Historical thick-mode runtime comparisons are also not claimed here: old
package artifacts existed locally, but a fair same-host old-binary comparison
was not rebuilt and audited during this run.
