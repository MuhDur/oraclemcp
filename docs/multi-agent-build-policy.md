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
2. **Bound concurrent full builds.** Acquire an Agent Mail build slot
   (cap **2** concurrent full builds per repo) before any full
   `cargo build/test/clippy --workspace`. See the caveat below — this is
   currently unenforceable.
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

**Known gap — rule 2 is currently unenforceable.** `acquire_build_slot` returns
`Build slots are disabled. Enable WORKTREES_ENABLED to use this tool.` Until
that is enabled, an agent told to take a slot before a full build can only block
or bypass, and neither is good: blocking stalls real work, bypassing is how the
incident happened. Blocking is the correct choice of the two. Enable
`WORKTREES_ENABLED`, or name an explicit alternative in the swarm brief.

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
