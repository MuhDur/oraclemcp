# Risk Notes

Run ID: `2026-06-15-campaign-p1`

## Measurement Risks

- `perf` is installed, but `perf stat true` failed because
  `perf_event_paranoid=4`. P2 cannot rely on unprivileged CPU sampling unless
  the operator approves OS tuning.
- `hyperfine`, `samply`, `heaptrack`, `cargo-flamegraph`, and `flamegraph` are
  missing. P2 should either use available tools or pause for approved installs.
- Cargo currently targets `/tmp/cargo-target`, and `/tmp` is a tmpfs at 94%
  used. Long compile or benchmark output runs may add noise or fail from space
  pressure.
- The host has substantial running workload: 132Gi RAM used, 6.7Gi swap used,
  and multiple Oracle containers running. Same-host comparison is still useful,
  but p95 drift above 10% should be treated as noise until repeated.
- CPU governor is `schedutil` and frequency boost is enabled. No kernel or CPU
  tuning was applied in P1.
- Existing performance docs reference an older run at commit `7dd4a60`; current
  P2 numbers must be captured against HEAD `6a39e43` and not mixed with the old
  baseline as if they were current.
- `Cargo.toml` has no `release-perf` profile. P2 can use release builds for
  wall-clock baselines, but flame-quality attribution may need a later explicit
  profiling profile change.

## Safety And Security Risks

- Oracle credentials are available in the local container environment, but P1
  only recorded presence, never values.
- Live test commands must keep password values in shell variables, avoid
  `set -x`, and unset temporary variables after use.
- Performance pressure must not weaken the fail-closed SQL guard, operating
  level ceiling, rollback-by-default execution posture, or credential redaction.
- P1 did not modify production Rust code and did not run privileged commands.
