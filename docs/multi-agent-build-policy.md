# Multi-agent build & scratch-space policy

Rules for running several agents against one checkout on one machine. They exist
because on 2026-07-16 an 8-agent swarm wedged the whole box for ~20 minutes
(`oraclemcp-gctl`). One agent can exhaust a shared resource and stop everyone,
so these are operating rules, not suggestions.

## The rules

1. **A shared `CARGO_TARGET_DIR` never lives on tmpfs.** tmpfs is RAM. Build
   artifacts there compete with the machine for memory, and `/tmp` here is
   additionally mounted `usrquota`, so one user's artifacts hit a quota long
   before the filesystem looks full. Keep it on real disk.
2. **Bound concurrent full builds — through the build lease.** Any heavy cargo
   operation (workspace-wide build/test/clippy, `cargo mutants`, `cargo hack`)
   runs as `scripts/build_lease.sh -- <cmd>`: a machine-wide flock(2) lease,
   one slot by default, so N agents queue instead of compiling simultaneously.
   Enforced, not advisory: `.cargo/config.toml` installs
   `scripts/cargo_build_guard.sh` as Cargo's compiler wrapper, so even a direct
   built-in heavy Cargo command reaches `scripts/check_build_lease.sh` before
   rustc and is refused without the lease (exit 75).
3. **Iterate with scoped builds.** `cargo check -p <crate>` / `cargo test -p <crate>`
   for normal work. A full `--workspace` build is a deliberate, slot-gated act.
4. **Cap per-build parallelism.** `~/.cargo/config.toml` sets `[build] jobs = 4`
   as defense in depth. Don't raise it to "use the whole box" — the box is shared.
5. **Don't fix a shared-resource problem by deleting shared state.** A
   `cargo clean` or an `rm -rf` on the shared target dir forces a cold rebuild on
   every other agent mid-flight. It's an operator call (AGENTS.md RULE 1), and it
   buys time rather than fixing anything.

## Recognising the failure — this is the part that costs hours

The exhaustion is **deceptive**. Symptoms in the order you'll meet them:

| What you see | What it actually means |
|---|---|
| `ld terminated with signal 7 [Bus error]` | Not a linker bug. Out of space. |
| `rustc-LLVM ERROR: IO failure on output stream: Disk quota exceeded` | The real error, if you're lucky enough to get it. |
| `echo hello` returns **exit 1 with no output**, while `true` succeeds | The harness buffers stdout through `/tmp`; it can't write. Your shell is not broken. |

**`df` will lie to you.** During the incident it reported 25G free and inodes at
19% the entire time, because the binding limit was a per-user quota, not disk.
The tell is **`EDQUOT` / "Disk quota exceeded" (os error 122)** — never `ENOSPC`.

Diagnose in this order:

```sh
findmnt -no OPTIONS /tmp     # usrquota? tmpfs?
du -sh "$CARGO_TARGET_DIR"   # who actually ate it
free -g                      # tmpfs usage shows up under `shared`
df -h /tmp                   # LAST, and do not trust it
```

## Current state (2026-07-16)

- `CARGO_TARGET_DIR` is off tmpfs: `/tmp/cargo-target` is bind-mounted onto the
  4.5 TB root, and `~/.zshrc` points new shells at `~/.cache/cargo-target`.
  Verify with `df -h "$(readlink -f /tmp/cargo-target)"` — it must **not** report
  `tmpfs`.
- `[build] jobs = 4` is set.

**Rule 2 gap closed (2026-07-20).** The original rule leaned on Agent Mail's
`acquire_build_slot`, which was disabled server-side (`Build slots are
disabled. Enable WORKTREES_ENABLED to use this tool.`) — an advisory cap
nobody could actually take is how the incident happened. The enforced
replacement is `scripts/build_lease.sh` (flock-based, no server dependency,
lease retained by the wrapper until the command exits and released by the
kernel when the wrapper exits) plus the
`scripts/check_build_lease.sh` preflight. The preflight remains wired into
`resource_budget.sh` and `oraclemcp_feature_powerset.sh`, and is also mandatory
for ordinary direct Cargo compilation through `.cargo/config.toml`'s
`rustc-wrapper`. `scripts/cargo_build_guard_test.sh` proves a real direct
workspace compile attempt exits 75 before a `Compiling` line, a direct shared
target exits 78, and scoped `-p` iteration still compiles. Those are the inner
gate statuses; Cargo reports a rejected compiler wrapper with its standard exit
101 while preserving the inner status in stderr. Agent Mail build slots, if
ever enabled, are additional coordination — the lease does not depend on them.

The compiler interceptor and flock lease are Linux-hosted. Non-Linux CI
explicitly disables the wrapper under the documented single-tenant CI waiver;
local macOS and Windows workspace-wide builds are not an E1-supported swarm
path and must use an isolated runner. Like every repository-local Cargo config,
an operator can deliberately override it with `RUSTC_WRAPPER` or `--config`.
That is an explicit safety-control bypass, not a normal direct Cargo invocation;
the negative integration proof covers the unmodified repository path.

## Spawn-wave preflight

Run `scripts/swarm_spawn_preflight.sh` immediately before every multi-agent
wave. The script is a check, not a launcher: an exit 75 means no agent in that
wave may spawn until the reported constraint changes or the wave is reduced.

The orchestrator supplies four scheduler facts that the host cannot discover:
the requested and candidate model names (which must match exactly), remaining
provider/harness spawn slots (which must cover the whole proposed wave), and
its own remaining context percentage. A pane below the default 20% context
floor does not receive new work, especially release-finalization work.

The live host checks use the tightest finite cgroup/user/system task ceiling,
`MemAvailable`, and the per-process/system file-descriptor ceilings. Defaults:

| Limit | Default |
|---|---:|
| Agents in one wave | 8 maximum |
| Context remaining | 20% minimum |
| Memory reserve | 4096 MiB fixed + 2048 MiB per agent |
| PID/task reserve | 1024 fixed + 512 per agent |
| File-descriptor reserve | 256 fixed + 128 per agent |

These are admission reserves, not promises that agents may consume the full
amount. Build processes remain governed separately by the build lease and
`resource_budget.sh`. Operators may tune the values with the documented
`ORACLEMCP_SWARM_*` variables printed by `--help`; agents do not relax a failed
preflight on their own.

Example for a four-slot wave:

```sh
scripts/swarm_spawn_preflight.sh \
  --agents 4 \
  --requested-model claude-fable-5 \
  --candidate-model claude-fable-5 \
  --quota-remaining 4 \
  --context-remaining-pct 80
```

## Working in a shared checkout

Two hazards that are not about disk, both observed the same day:

- **Never `git add -A`.** Other panes have uncommitted work in the same tree; you
  will commit theirs inside your bead. Stage only the paths you own.
- **A tree that doesn't compile blocks every pane.** Keep non-compiling states
  short. If you need a clean build while someone else's edit is mid-flight, build
  from `HEAD` in your own `git worktree` rather than reverting their files. Live
  harnesses accept a prebuilt binary for exactly this (e.g.
  `ORACLEMCP_ORACLE_MATRIX_BINARY`).

Reserve files through Agent Mail before editing, and honour a
`FILE_RESERVATION_CONFLICT` instead of routing around it.
