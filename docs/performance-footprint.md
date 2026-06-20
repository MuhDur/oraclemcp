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

Criterion benchmark:
`cargo bench -p oraclemcp-db --bench page_serialization -- --sample-size 20`.
This measures local `read_query` page construction and serialization after rows
have already been returned by a database connection mock.

| Scenario | Criterion estimate |
|---|---:|
| 10 rows | 13.223 us |
| 200 rows | 354.49 us |
| 1000 rows | 1.7810 ms |

Classifier baseline:
`cargo test -p oraclemcp-guard --release --test perf_classifier -- --ignored --nocapture`.

| Scenario | Measurement |
|---|---:|
| Fail-closed SQL classification | 14,290 ns/statement |
| Throughput | ~69,979 classifications/sec |

## Package Sizes

Current `.crate` packages produced by `cargo package --workspace --locked
--no-verify`. Package filenames and compressed sizes were refreshed after the
W14 version bump; the timing and binary measurements above remain the W13
baseline.

| Package | Size |
|---|---:|
| `oraclemcp-error-0.3.0.crate` | 9,042 bytes |
| `oraclemcp-audit-0.3.0.crate` | 13,805 bytes |
| `oraclemcp-guard-0.3.0.crate` | 65,990 bytes |
| `oraclemcp-auth-0.3.0.crate` | 19,785 bytes |
| `oraclemcp-config-0.3.0.crate` | 16,370 bytes |
| `oraclemcp-db-0.3.0.crate` | 86,935 bytes |
| `oraclemcp-telemetry-0.3.0.crate` | 8,098 bytes |
| `oraclemcp-core-0.3.0.crate` | 104,982 bytes |
| `oraclemcp-0.3.0.crate` | 93,880 bytes |

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
ORACLEMCP_LIVE_XE=1 ORACLEMCP_LIVE_DSN=... ORACLEMCP_LIVE_USER=... \
  ORACLEMCP_LIVE_PASSWORD=... \
  cargo test -p oraclemcp-db --test load_soak -- --ignored --nocapture
```

The live test skips with a clear message when `ORACLEMCP_LIVE_XE` is unset.

### Live measurements (B3 / D7)

> **Populated by a live run.** The figures below are intentionally left as
> placeholders. They are filled in by the `live-xe` load/soak run against a real
> Oracle database (coordinated with D7, which lands the numbers), the same way
> the exact-SHA release qualification is filled in from a real build+run. Do NOT
> hand-edit estimates into this table — the honesty-grep gate and the release
> review reject invented performance numbers.

| Metric | Value | Captured by |
|---|---|---|
| Run id | _pending live run_ | `live-xe` |
| Database | _pending live run_ (Oracle XE / ADB / RAC) | `live-xe` |
| Clients (N) | _pending live run_ | `live-xe` |
| Soak duration | _pending live run_ | `live-xe` |
| Total operations | _pending live run_ | `live-xe` |
| `oracle_query` p50 | _pending live run_ | `live-xe` |
| `oracle_query` p95 | _pending live run_ | `live-xe` |
| `oracle_query` p99 | _pending live run_ | `live-xe` |
| Leaked sessions | _pending live run_ (expected: 0) | `live-xe` |
| Pool accounting balanced | _pending live run_ (expected: yes) | `live-xe` |
| Clean drain | _pending live run_ (expected: yes) | `live-xe` |

## Scope Limits

Live Oracle connect/query latency was not measured in this run. No Oracle
credentials, wallet paths, connect strings, schema names, or customer data were
used. Historical thick-mode runtime comparisons are also not claimed here: old
package artifacts existed locally, but a fair same-host old-binary comparison
was not rebuilt and audited during this run.
