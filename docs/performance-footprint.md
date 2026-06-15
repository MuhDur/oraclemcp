# Performance and Footprint Evidence

This file summarizes local measurement evidence for the thin-native
`oraclemcp` line. It is not a marketing benchmark: numbers are scoped to the
host and commands recorded in
`tests/artifacts/perf/20260615T182242Z-7dd4a60/`.

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

## Scope Limits

Live Oracle connect/query latency was not measured in this run. No Oracle
credentials, wallet paths, connect strings, schema names, or customer data were
used. Historical thick-mode runtime comparisons are also not claimed here: old
package artifacts existed locally, but a fair same-host old-binary comparison
was not rebuilt and audited during this run.
