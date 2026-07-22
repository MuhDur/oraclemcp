# Resource budgets for heavy runs

A heavy run must not be able to take the machine down. Three incidents say it can:

- **~40GB RSS** global OOM.
- **cargo-mutants fanned out to ~9,700 threads**, exhausting the cgroup's 512-task
  limit until even `fork()` failed. A "safe" 4-shard rerun re-created the lockout.
- **2026-07-16**: eight concurrent `--workspace` builds filled the 124G tmpfs
  behind a shared `CARGO_TARGET_DIR` and wedged the box for every agent.

The retrospective's finding is the one worth keeping: **a memory cap alone was not
enough — the PID/task budget was the scarce resource.** So a budget here declares
memory *and* tasks *and* an isolated target dir, and the kernel enforces all three.

```bash
scripts/resource_budget.sh --profile build   -- cargo test --workspace
scripts/resource_budget.sh --profile mutants -- cargo mutants -p oraclemcp-db
scripts/resource_budget.sh --profile mutants --emit-budget    # JSON only, runs nothing
scripts/check_resource_budget.sh                              # prove it is enforced
```

| profile | memory | tasks | for |
|---|---:|---:|---|
| `build` | 16G | 512 | `cargo build` / `check` / `clippy` |
| `test` | 16G | 512 | `cargo test` |
| `mutants` | 8G | 256 | cargo-mutants — the incident profile, deliberately tightest |
| `live` | 8G | 256 | live / container-backed suites |

## Mechanism: a cgroup scope, not `ulimit`

```bash
systemd-run --user --scope -p TasksMax=N -p MemoryMax=M -- <cmd>
```

**`ulimit -u` is the wrong tool here, and the reason is not obvious.**
`RLIMIT_NPROC` is **per-UID, not per-process-tree**. Every agent in this swarm runs
as the same user, and that UID routinely has 200+ processes. `ulimit -u 256` would
therefore cap your build against *other agents'* processes: your build fails to
fork because someone else's test suite is busy. It is also one-way — a lowered
limit cannot be raised back in the same shell.

A cgroup scope binds **this run's subtree and nothing else**, which is what "a
budget for this run" actually means.

## The tmpfs guard fails closed

The wrapper refuses to run — exit 78 — if the target dir is on `tmpfs`/`ramfs`:

```
resource_budget: REFUSING to run.
  target dir : /tmp/…/target
  filesystem : tmpfs  (RAM-backed)
```

This is 2026-07-16 encoded as a check rather than a paragraph. A build cache on
tmpfs *is* build artifacts held in RAM: 73G of cache was 73G of memory the box
could not use, and when it filled, the failure was not a clean "disk full" but
`EDQUOT`, a linker dying with `SIGBUS`, and commands that produced output failing
with **no output at all**.

It refuses rather than warns. A warning printed at the start of a 20-minute build
is a warning nobody reads.

> Today `/tmp/cargo-target` is a **bind mount onto ext4** (`/home/durakovic/.cache/cargo-target`),
> so it passes this guard. It would have been refused that morning. Do not
> delete or recreate that path — it is a mount, not a directory.

## Isolated target dirs are affordable because of sccache

Each run gets `~/.cache/oraclemcp-budget-runs/<run-id>/target`. Isolation is what
makes a run's inputs attributable — a shared target dir means you cannot say which
run produced what, and two runs can fight over the same lock.

The obvious objection is that a fresh target dir means a cold build every time.
In practice it does not, because `~/.cargo/config.toml` sets
`rustc-wrapper = sccache`: compilation results are cached *across* target dirs.
Measured here — a cold, isolated `cargo check -p oraclemcp-db` finished in
**2.54s** against a warm sccache (3538 cache hits). Isolation costs approximately
nothing; sccache is what pays for it.

Reuse a dir across runs by passing the same `--run-id`.

## It is proven, not declared

`scripts/check_resource_budget.sh` tries to **exceed** the budget and asserts the
kernel refuses. Two details make that test honest, and both were learned the hard
way:

**Ask the kernel, not the shell.** A counter built on `if cmd &` reports success
even while forks are being denied — backgrounding always returns 0, and bash
retries a failed fork internally. The authoritative signals are
`pids.peak` (high-water mark, must never exceed the budget) and
`pids.events: max` (how many forks the kernel denied, must be > 0 or the test
never reached the cap and proves nothing).

**Report with builtins only.** Past the cap there is no fork left, so `$(cat)`
hangs — which *is* the incident. `read` and `echo` are bash builtins and keep
working when nothing else does.

**Overshoot the cap moderately (cap + 8), not hard.** The first version attempted
60 forks against `TasksMax=16` and was flaky: at roughly 4× the cap the reporting
shell is killed by the very denial it is measuring — a `SIGCHLD` from an exiting
child interrupts a retrying `fork()` and bash aborts with
`fork: Interrupted system call` before printing anything. The test then reports
nothing and looks like "not enforced" when enforcement is in fact working
perfectly. `cap + 8` reaches the cap and triggers denials while leaving the
reporter alive: 5 consecutive runs, `peak=16` every time. A gate that flakes is a
gate that gets muted.

Current result, on a `TasksMax=16` scope with 60 forks attempted:

```
peak was 16 — the budget was never exceeded
kernel denied 6 fork(s) (pids.events max)
shell still forks afterwards — containment held: the budget fails the RUN, not the box
```

## Feeding the evidence contract

`--emit-budget` prints exactly the `resource_budget` block that
[`required-proof/v1`](../schemas/evidence/required-proof-v1.schema.json) and
[`mutation-result/v1`](../schemas/evidence/mutation-result-v1.schema.json)
require:

```json
{
  "isolated_target_dir": "/home/durakovic/.cache/oraclemcp-budget-runs/mutants-123/target",
  "memory_max_bytes": 8589934592,
  "pid_task_max": 256
}
```

So a proof embeds the budget the run **actually executed under**, rather than
three numbers someone typed into a JSON file. That is the whole reason those
fields are required in the schema: a mutation result produced by a run that
silently exhausted the host is not a measurement.
