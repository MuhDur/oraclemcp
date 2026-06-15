# P2 Baseline

Run ID: `2026-06-15-campaign-p2`
Git SHA: captured in `raw/environment-recheck.log`
Build: `/tmp/cargo-target/release/oraclemcp`, release profile

This pass measured S0-S5 from the P1 scenario map. It did not change
production Rust code, tune the OS, install tools, or print credential values.
Percentiles from 30-50 samples are useful for ranking, but p99 is conservative
because the sample count is below 1000.

## Environment

- `perf_event_paranoid=4`; CPU stack sampling with `perf record` remains gated
  on operator-approved kernel tuning.
- `hyperfine`, `samply`, `heaptrack`, and `cargo-flamegraph` were not installed,
  so this pass used `/usr/bin/time`, shell nanosecond timing, Criterion, and
  release test binaries.
- Local Oracle 23ai path was available through `plsql-intelligence-xe`; the
  password was kept in shell variables and unset after use.
- `/tmp/cargo-target` was used as Cargo target directory.

Raw environment details: `raw/environment-recheck.log`.

## Results

| Scenario | Measurement | Samples | p50 | p95 | p99 | Max | Peak RSS | Evidence |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| S0 | `oraclemcp info` startup | 50 | 8 ms | 9 ms | 9.51 ms | 10 ms | 3.12 MiB p50 | `raw/s0-cli-startup-ns.csv` |
| S0 | `oraclemcp capabilities` startup | 50 | 9 ms | 10 ms | 10 ms | 10 ms | 5.07 MiB p50 | `raw/s0-cli-startup-ns.csv` |
| S1 | stdio initialize + `tools/list` | 50 | 13 ms | 14 ms | 14 ms | 14 ms | 9.06 MiB p50 | `raw/s1-stdio-handshake-tools-list.csv` |
| S2 | classifier throughput test wall time | 30 | 3551.5 ms | 3645.95 ms | 3709.64 ms | 3734 ms | 4.07 MiB p50 | `raw/s2-perf-classifier.csv` |
| S2 | classifier per statement | 30 | 13982 ns | 14358.85 ns | 14616.66 ns | 14717 ns | n/a | `raw/s2-perf-classifier.csv` |
| S5 | live Oracle 23ai connect, ping, bind query, describe | 30 | 50 ms | 54.55 ms | 56.42 ms | 57 ms | 5.06 MiB p50 | `raw/s5-live-connect-smoke-release.csv` |

Criterion estimates:

| Scenario | Benchmark | Estimate | 95% interval | Evidence |
| --- | --- | ---: | ---: | --- |
| S3 | `page_serialization/read_query_10_rows` | 13.426 us | 13.400-13.465 us | `raw/s3-page-serialization-bench.log` |
| S3 | `page_serialization/read_query_200_rows` | 357.76 us | 356.87-359.03 us | `raw/s3-page-serialization-bench.log` |
| S3 | `page_serialization/read_query_1000_rows` | 1.7955 ms | 1.7744-1.8236 ms | `raw/s3-page-serialization-bench.log` |
| S4 | `lob_capping/clob_under_cap` | 13.670 us | 13.592-13.784 us | `raw/s4-lob-capping-bench.log` |
| S4 | `lob_capping/clob_over_cap_truncates` | 10.680 us | 10.604-10.792 us | `raw/s4-lob-capping-bench.log` |
| S4 | `lob_capping/blob_base64_over_cap` | 116.82 us | 116.45-117.51 us | `raw/s4-lob-capping-bench.log` |
| S4 | `classify_type/classify_per_call` | 285.05 ns | 283.66-287.45 ns | `raw/s4-classify-type-bench.log` |
| S4 | `classify_type/serialize_row_classifies_columns` | 454.91 ns | 451.44-460.09 ns | `raw/s4-classify-type-bench.log` |

## Correctness Gates

- `oraclemcp info` and `oraclemcp capabilities` exited 0 in all S0 samples.
- `raw/s0-capabilities-output.json` parses with `jq`.
- S1 smoke transcript produced two JSON-RPC replies and 44,095 output bytes:
  `raw/s1-stdio-smoke-output.jsonl` and
  `raw/s1-stdio-smoke-output.bytes`.
- `cargo test -p oraclemcp-guard --release --test perf_classifier -- --ignored --nocapture`
  passed and produced the classifier span summary.
- Criterion benches completed for page serialization, LOB capping, and type
  classification.
- Live Oracle release smoke passed against Oracle `23.26.1.0.0`:
  `raw/s5-live-smoke-cargo-release.log`.

## Excluded Raw Measurements

- `raw/s0-cli-startup.csv`: aborted setup attempt caused by a zsh reserved
  variable name before data collection.
- `raw/s5-live-connect-smoke.csv`: excluded because it selected a stale debug
  test binary; the raw log shows `0 tests` run. The corrected release artifact
  is `raw/s5-live-connect-smoke-release.csv`.

## Commands Run

```bash
git status --short --branch
git rev-parse HEAD
rustc -Vv
cargo -V
rustup show active-toolchain
cargo metadata --no-deps --format-version 1
docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
cat /proc/sys/kernel/perf_event_paranoid
uname -a
lscpu
free -h
df -h / /tmp
cargo build --release -p oraclemcp
/tmp/cargo-target/release/oraclemcp --help
/tmp/cargo-target/release/oraclemcp info
/tmp/cargo-target/release/oraclemcp capabilities
jq type tests/artifacts/perf/2026-06-15-campaign-p2/raw/s0-capabilities-output.json
for subcmd in info capabilities; do ... /usr/bin/time -f '%M' /tmp/cargo-target/release/oraclemcp "$subcmd" ...; done
printf '%b' "$payload" | ORACLEMCP_LOG=error /tmp/cargo-target/release/oraclemcp serve --allow-no-auth
for i in $(seq 1 50); do ... /usr/bin/time -f '%M' /tmp/cargo-target/release/oraclemcp serve --allow-no-auth ...; done
cargo test -p oraclemcp-guard --release --test perf_classifier -- --ignored --nocapture
/tmp/cargo-target/release/deps/perf_classifier-* --ignored --nocapture
cargo bench -p oraclemcp-db --bench page_serialization -- --sample-size 30
cargo bench -p oraclemcp-db --bench lob_capping -- --sample-size 30
cargo bench -p oraclemcp-db --bench classify_type -- --sample-size 30
cargo test -p oraclemcp-db --features live-xe --test live_oracle live_connect_ping_query_bind_describe -- --exact --nocapture
cargo test -p oraclemcp-db --release --features live-xe --test live_oracle live_connect_ping_query_bind_describe -- --exact --nocapture
/tmp/cargo-target/release/deps/live_oracle-* live_connect_ping_query_bind_describe --exact --nocapture
```
