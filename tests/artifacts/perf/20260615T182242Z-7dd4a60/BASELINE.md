# Baseline - Thin-Native Footprint - 2026-06-15 - 7dd4a60

## Release Build

Command:

```bash
cargo build --release -p oraclemcp
```

Result:

- Initial full build finished `release` profile in 1m 53s.
- Final rebuild after the CLI stdout fix finished in 2.25s with prior release
  dependencies already built.
- Binary path: `/tmp/cargo-target/release/oraclemcp`.
- Binary size: 15,560,416 bytes.

## Offline CLI Startup

Timing command:

```bash
for cmd in info capabilities; do
  for i in $(seq 1 30); do
    start=$(date +%s%N)
    /tmp/cargo-target/release/oraclemcp "$cmd" >/dev/null
    end=$(date +%s%N)
    echo "$cmd $((end - start))"
  done
done
```

RSS command:

```bash
for cmd in info capabilities; do
  for i in $(seq 1 20); do
    /usr/bin/time -f "$cmd %M" /tmp/cargo-target/release/oraclemcp "$cmd" >/dev/null
  done
done
```

| Command | Samples | p50 | p95 | max | RSS p50 | RSS p95 | RSS max |
|---|---:|---:|---:|---:|---:|---:|---:|
| `info` | 30 | 6.432 ms | 8.053 ms | 9.204 ms | 3,136 KB | 3,200 KB | 3,212 KB |
| `capabilities` | 30 | 7.501 ms | 9.398 ms | 9.989 ms | 5,180 KB | 5,236 KB | 5,240 KB |

## CLI Pipe Smoke

Command:

```bash
set -o pipefail
/tmp/cargo-target/release/oraclemcp capabilities | head -c 1200 >/dev/null
```

Result: exit code 0; no Rust broken-pipe panic printed.

## Synthetic Read Query Serialization

Command:

```bash
cargo bench -p oraclemcp-db --bench page_serialization -- --sample-size 20
```

| Scenario | Criterion interval | Estimate |
|---|---:|---:|
| `read_query_10_rows` | 13.207 us - 13.238 us | 13.223 us |
| `read_query_200_rows` | 350.15 us - 360.29 us | 354.49 us |
| `read_query_1000_rows` | 1.7758 ms - 1.7856 ms | 1.7810 ms |

## SQL Classifier

Command:

```bash
cargo test -p oraclemcp-guard --release --test perf_classifier -- --ignored --nocapture
```

Result:

```text
perf.profile.span_summary {"span":"classifier.classify","classifications":240000,"ns_per":14290,"per_sec":69979,"corpus":12 }
CLASSIFIER BASELINE: 14290 ns/statement  (~69979 classifications/sec)  over 240000 runs
```

## Docker Image

First attempt:

```bash
docker build -t oraclemcp:w13-7dd4a60 .
```

Result before the Dockerfile fix: failed with `error: linker 'cc' not found`.

Fixed builder stage:

```dockerfile
RUN dnf -y install ca-certificates curl gcc && dnf clean all && \
```

Result after fix:

- Docker build succeeded.
- Final container cargo release step finished in 2m 01s.
- Image id: `sha256:cb8fc76d7ad66ac56599cee9d2fda9350454a26a1c71ea51f37d459857ef8704`.
- Image size: 253,337,830 bytes.
- Runtime smoke: `runtime_gcc=absent`; `/usr/local/bin/oraclemcp` exists;
  `oraclemcp info` succeeds; `oraclemcp capabilities | head -c 1200`
  exits cleanly under `pipefail`.

## Package Sizes

Command:

```bash
find /tmp/cargo-target/package -maxdepth 1 -type f -name 'oraclemcp*.crate' -printf '%f %s\n' | sort
```

Current `0.2.1` package sizes:

| Package | Size |
|---|---:|
| `oraclemcp-0.2.1.crate` | 93,871 bytes |
| `oraclemcp-audit-0.2.1.crate` | 13,792 bytes |
| `oraclemcp-auth-0.2.1.crate` | 19,771 bytes |
| `oraclemcp-config-0.2.1.crate` | 16,359 bytes |
| `oraclemcp-core-0.2.1.crate` | 104,955 bytes |
| `oraclemcp-db-0.2.1.crate` | 86,918 bytes |
| `oraclemcp-error-0.2.1.crate` | 9,034 bytes |
| `oraclemcp-guard-0.2.1.crate` | 65,975 bytes |
| `oraclemcp-telemetry-0.2.1.crate` | 8,091 bytes |

## Tests

The run also used focused local checks while capturing W13 evidence: release
build, Docker build/smoke, package generation with `--allow-dirty`, fmt check,
and targeted unit coverage for broken-pipe handling. Full clean gates run
before W13 closure.
