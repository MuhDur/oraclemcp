# Command Plan For P2

Run ID: `2026-06-15-campaign-p1`

P2 should collect baselines and enough attribution to rank hotspots. Keep all
credential values in shell variables and do not echo them.

## Environment Recheck

```bash
git status --short --branch
git rev-parse HEAD
rustc -Vv
cargo -V
rustup show active-toolchain
cargo metadata --no-deps --format-version 1
docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
cat /proc/sys/kernel/perf_event_paranoid
```

## Offline Startup

Use `/usr/bin/time -v` because `hyperfine` is not installed.

```bash
cargo build --release -p oraclemcp
for i in $(seq 1 30); do /usr/bin/time -v /tmp/cargo-target/release/oraclemcp info >/dev/null; done
for i in $(seq 1 30); do /usr/bin/time -v /tmp/cargo-target/release/oraclemcp capabilities >/dev/null; done
```

Record p50/p95/p99/max wall time and peak RSS in P2 artifacts. If `hyperfine`
is installed later, prefer:

```bash
hyperfine --warmup 3 --runs 30 --export-json tests/artifacts/perf/2026-06-15-campaign-p2/offline-startup.json \
  '/tmp/cargo-target/release/oraclemcp info >/dev/null' \
  '/tmp/cargo-target/release/oraclemcp capabilities >/dev/null'
```

## Existing Rust Benchmarks

```bash
cargo bench -p oraclemcp-db --bench page_serialization -- --sample-size 30
cargo bench -p oraclemcp-db --bench lob_capping -- --sample-size 30
cargo bench -p oraclemcp-db --bench classify_type -- --sample-size 30
cargo test -p oraclemcp-guard --release --test perf_classifier -- --ignored --nocapture
```

## Live Oracle 23ai Smoke And Baseline

Safe password handling pattern:

```bash
PW="$(docker inspect plsql-intelligence-xe --format '{{range .Config.Env}}{{println .}}{{end}}' | awk -F= '$1=="ORACLE_PASSWORD" {print substr($0,index($0,"=")+1); found=1} END {if (!found) exit 1}')"
ORACLEMCP_TEST_DSN='//localhost:1521/FREEPDB1' \
ORACLEMCP_TEST_USER=system \
ORACLEMCP_TEST_PASSWORD="$PW" \
cargo test -p oraclemcp-db --features live-xe --test live_oracle live_connect_ping_query_bind_describe -- --exact
unset PW
```

For P2 baselines, repeat selected live tests enough to estimate p50/p95, but do
not print captured env values and do not include raw connect strings beyond the
local test endpoint.

## CPU Sampling

`perf` exists but unprivileged profiling is blocked by `perf_event_paranoid=4`.
Do not change that in P2 unless the operator explicitly approves kernel tuning.
Without approval, use Criterion output, `/usr/bin/time -v`, and test-level timing
as the baseline. If approval is later granted, capture a separate artifact that
records the tuning and revert plan before running `perf record`.

## Output Artifacts Expected From P2

- `BASELINE.md` with p50/p95/p99/max and RSS per scenario.
- `hotspot_table.md` with ranked rows and evidence paths.
- `hypothesis.md` with supported/rejected explanations.
- Raw JSON/log outputs for commands that produce machine-readable data.
