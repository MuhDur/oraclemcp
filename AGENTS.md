# AGENTS.md - oraclemcp

Operating rules for agents working in this repository.

**oraclemcp** is an unofficial, safe-by-default Oracle Database
[MCP](https://modelcontextprotocol.io) server in pure Rust: a small Cargo
workspace of 9 engine-free `oraclemcp-*` library crates plus the `oraclemcp`
binary. Release archives, the single `ghcr.io/muhdur/oraclemcp` image, and the
default source build embed the `plsql-intelligence` engine for offline tools;
custom `--no-default-features` builds omit it. The maintained primary driver is
`oraclemcp-driver-cx`, with a bounded official `oracledb` connect-time alternate
for compatible password connections. The SQL guard remains independent of
the PL/SQL engine. The separate `plsql-mcp` server is deprecated. Independent
open-source project; not affiliated with Oracle.

## RULE 1 - ABSOLUTE

Do not delete any file or directory unless the operator gives the exact command
in-session. This includes files you just created. If something should go, stop
and ask first.

## Irreversible / outward-facing actions

Never run `git reset --hard`, `git clean -fd`, `git push --force`, branch
deletion, or `rm -rf` on tracked paths without explicit in-session approval.
Never force-push `main`. Do not commit on the operator's behalf without a clear
in-session go-ahead. crates.io publishes and registry listings are permanent
(versions immutable, names claimed forever); treat publishing as a gated,
deliberate step.

## Working rules

Binding on every agent, solo or swarmed. They come from past incidents
(`docs/plan/RETRO_SWARM_2026-10-04.md`, `docs/plan/SWARM_RECAP_2026-10.md`).

1. Never defer planned work on your own initiative; deferral is the
   operator's call.
2. Green means honestly green. Surface red before the operator finds it.
3. Claim only what you have just run and checked.
4. Follow explicit operator choices (model, scope, agent count) exactly.
5. The fail-closed guard is sacred and tighten-only (see "The safety
   invariant").
6. Confidentiality: field-test/live-customer identifiers never leave
   `todelete/` (gitignored) or enter a committed artifact.
7. No surprise costs: cloud resources (OCI etc.) stay free-tier.
8. Be resource-disciplined: scoped `-p` builds, a per-agent target dir, no
   unbounded concurrent compiles.
9. A modified file that is not yours is another agent mid-edit, not a defect.
   Check `git status` / `git show HEAD:<path>` before calling it broken.
10. Commit explicit paths (`git commit -- <path>...`), then check what landed
    with `git show --stat HEAD`. Never `-a`, `git add -A` or `--amend` in the
    shared checkout. A struct field and its initializers (or a trait method
    and its impls, an enum variant and its matches) land in one commit.
11. Never block a turn on an unbounded wait. Check once, report, move on.
12. Escalate blockers to the operator; file unforeseen work with `br create`
    instead of quietly widening scope.

## Honest Work and Anti-Ceremony (binding for agents and humans alike)

The purpose of agent work here is working, deployable capability. Process
serves that outcome and never becomes the product.

- A process artifact (certificate, ledger, dashboard, matrix, meta-report,
  speculative check) may be created only if it names a concrete consumer,
  the named feature it gates, the observed defect class justifying it, and
  its deletion condition. Otherwise it does not get created. Boundary test:
  if running code branches on it, it is product; if only humans and status
  reports read it, it is process and the creation-gate rule above applies;
  code written just to flip this answer counts as the pathology, not as a
  consumer. Sole exception: a minimal
  integrity/recovery control (crash-recovery state, provenance snapshot) is
  legitimate when it prevents a named evidence-loss or corruption mode and
  is necessary and minimal.
- Real code + real tests in the same unit of work. Forbidden: faked tests,
  fixtures/mocks presented as live proof, weakened assertions, golden
  regeneration to force green, hard-coded success paths, placeholder macros
  in commits, editing the spec instead of implementing it, narrowing scope
  while claiming full success.
- No self-certification: work is closed by an independent verifier citing
  evidence at an exact revision. Solo sessions re-verify by re-execution and
  state what was not independently verified.
- A typed refusal beats a fabricated result and is less valuable than the
  real capability; refusal-only work stays open and says so.
- Truthful null results ("checked X, found no material increment") are
  successful outcomes. Unsupported claims are worse than silence.
- Metrics predeclare denominator and countermetric; agreement between
  agents may raise confidence but is never independent evidence; never
  silence stderr in evidence-bearing commands.
- Name these pathologies when they occur (gate self-weakening, proof-class
  inflation, golden regeneration, tolerance widening, suppression-pragma
  laundering, refusal farming, follow-up laundering); the names are the
  deterrent. The full catalog with countermeasures lives in the
  just-say-no-to-process-porn-and-ceremony skill; ask the operator for it
  if you cannot resolve that reference.

## Rust toolchain & gates

- Cargo workspace, `resolver = "2"`, `edition = "2024"`. The default and
  release toolchain stays **`nightly-2026-05-11`**. Linux and macOS also check,
  test and package on current stable Rust; see [`docs/toolchain.md`](docs/toolchain.md).
  The `oraclemcp-driver-cx` 0.9.3 driver's own source is stable-clean.
  Both server and driver disable defaults for the asupersync 0.3.9 runtime,
  retaining explicit `metrics`, `tls` and `proc-macros` features where
  needed, while `nightly-outcome-try` must stay absent from every target's
  feature graph. The required stable jobs and boundary lint enforce this.
  **Windows still needs nightly:** both `oraclemcp-core` and `oraclemcp-audit`
  use `windows_by_handle` for link counts and volume/file identity, protecting
  the service lock and audit sink. Stable Windows is outside this qualification.
- Every crate is `#![forbid(unsafe_code)]`. Do not introduce `unsafe`.
- Before committing: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`, `cargo deny check`
  using the pinned toolchain from `rust-toolchain.toml`.
- The default build is pure Rust and has no native Oracle client dependency.
  Live database access uses the thin `oraclemcp-driver-cx` driver and does not require
  Oracle Instant Client, ODPI-C, `libclntsh`, or a C toolchain.

## Build lease & dedicated build targets

Heavy cargo operations — anything workspace-wide (`--workspace`, `cargo hack`,
`cargo mutants`, or an unscoped bare `cargo build/test/...`) — serialize
through a machine-wide flock(2) build lease. This is mechanism, not
discipline: the preflight (`scripts/check_build_lease.sh`) is wired into the
heavy entry points (`resource_budget.sh`, `oraclemcp_feature_powerset.sh`) and
Cargo's repo-local compiler wrapper (`.cargo/config.toml`). A direct built-in
`cargo test --workspace` therefore reaches the preflight before rustc and is
refused when un-leased (the wrapper exits 75; Cargo reports that compiler
failure with its standard exit 101). Direct Cargo against a shared or RAM-backed
target is refused too (wrapper exit 78, Cargo exit 101).

```bash
scripts/build_lease.sh -- cargo test --workspace   # take a slot, then run
scripts/build_lease.sh --status                    # who holds the lease
cargo check -p <crate>                             # scoped iteration: never gated
```

- Default is **one slot** (`CARGO_SWARM_BUILD_LEASE_SLOTS` to widen): concurrent
  heavy builds queue instead of running simultaneously — the 2026-07
  fork-EAGAIN / OOM / tmpfs-exhaustion class came from N simultaneous full
  compiles. The wrapper retains the lease while the command runs, and the
  kernel releases it when the wrapper exits, crash included; there is no unlock
  step to forget and no stale-lock cleanup.
- Heavy builds use a **dedicated per-agent `CARGO_TARGET_DIR`** — the
  checkout's own `target/` or a `scripts/resource_budget.sh` per-run dir. The
  shared caches (`/tmp/cargo-target`, `~/.cache/cargo-target`) and any tmpfs
  path are refused even under a lease.
- CI runners are single-tenant and waive the lease requirement automatically;
  the target-dir rules still apply everywhere.
- The mandatory compiler interceptor and flock lease are Linux-hosted.
  Non-Linux CI explicitly disables that shell wrapper under the same
  single-tenant waiver; local macOS and Windows workspace-wide builds are not
  an E1-supported swarm path and must be run in an isolated runner. On Linux
  (the multi-agent host), ordinary direct Cargo compilation is intercepted. An
  explicit Cargo config or
  `RUSTC_WRAPPER` override can defeat any repo-local Cargo setting; treat such
  an override as bypassing a safety control, not as normal repository use.

## The safety invariant (do not weaken)

The core invariant is the **fail-closed SQL guard** — NOT "read-only forever".
`oracle_query`, the inner SQL of `oracle_explain_plan`, and the dictionary tools
admit only what is provably `READ_ONLY`; everything else is refused before it reaches
Oracle. But this server is **guarded, not read-only-only**: it exposes an
operating-level ladder `READ_ONLY < READ_WRITE < DDL < ADMIN`, surfaced through
`oracle_execute`, `oracle_compile_object`, `oracle_create_or_replace`,
`oracle_patch_source`, and `oracle_set_session_level` (alias `enable_writes`).
Read-only is the **default** (`default_level`) and the cap for unconfigured or
`protected` profiles, but a profile's `max_level` may permit escalation up to
`ADMIN`. Every escalation is guarded: a preview → confirmation-token step-up, a
temporary TTL-bounded elevation window, the classifier still gating every statement
at the *current* level, DML rolling back by default, `protected` profiles pinned at
`READ_ONLY` with an immutable ceiling, and OAuth scopes that can only *lower* the
effective level. The audit hash-chain (`oraclemcp-audit`) records every privileged
action. **Do not weaken** means: never bypass the classifier, never let elevation
exceed a profile's `max_level`, never make a `protected` profile writable, never
auto-commit DML, and never admit a statement the classifier cannot prove safe for the
active level.

## Code editing discipline

- We optimize for a clean architecture now, not backwards compatibility. No
  compat shims or `v2` file clones; migrate callers and remove old code.
- The bar for adding files is high; new files only for genuinely new domains.
- No bulk codemods or giant `sed`/regex refactors. Break large mechanical
  changes into small, reviewable edits; edit subtle changes by hand.
- Structured, minimal logs. Logs are for operators; treat UX as UI-first.

## Release flow

Versions are published from this repo. A `vX.Y.Z` tag drives the single normal
pipeline, `.github/workflows/release.yml`: release gates, crates.io packages,
signed multi-platform GitHub assets, `ghcr.io/muhdur/oraclemcp`, and the MCP
registry entry from `server.json` (GitHub OIDC). `.github/workflows/docker.yml`
and `.github/workflows/publish-mcp.yml` are manual recovery/repair auxiliaries,
not additional tag pipelines. No third-party package-manager manifests are
shipped, and no npm/npx channel is offered.

## Issue tracking

This repo's issues are tracked in this checkout's local `.beads/` database.
Work beads from this repo root with `br`:

```bash
br ready --json                      # unblocked work
br update <id> --status in_progress --assignee <name>  # claim
br close <id> --reason "<commit> <test command(s)>; verified by <reviewer>"
br create "Title" -t bug|feature|task -p 0-4 --deps discovered-from:<id>
br sync --flush-only                 # export .beads/issues.jsonl before commit
```

Types: `bug`, `feature`, `task`, `epic`, `chore`. Priorities: `0` critical …
`4` backlog (default `2`). Never use markdown TODO lists or a second tracker.
Commit `.beads/` changes with the code or planning change they describe.

**Done** means: real code plus a real test that fails when the fix is reverted
(planted fault), reviewed by someone other than the author with the
beads-compliance-and-completion-verification skill. The close reason names the
commit, the test command and the reviewer. No evidence JSON, ledgers or proof
commits: the commit and the test are the evidence. A bead found falsely closed
is reopened with a comment saying why.

## bv - graph-aware triage sidecar

`bv` computes PageRank / critical paths / parallel tracks over the beads graph.
**Use only `--robot-*` flags; bare `bv` opens a blocking TUI.**

```bash
bv --robot-triage   # start here   ·   bv --robot-next   # top pick + claim cmd
bv --robot-plan     # parallel tracks   ·   bv --robot-insights   # graph metrics
```

## cass / cass-memory - reuse prior work

`cass` indexes past agent sessions; `cm` surfaces procedural memory. Never run
bare `cass` (TUI); use `--robot`/`--json`.

```bash
cass search "<problem>" --robot --limit 5    # has this been solved before?
cm context "<task>" --json                   # relevant rules, anti-patterns, history
```

## No git worktrees (operator rule)

Never create or use git worktrees in this repository: not per agent, not for
gates, proofs, rebases or landing. All agents work in the ONE shared checkout
on `main` and coordinate through Agent Mail. Worktrees have repeatedly
produced divergent commit lines, stale files that silently reverted landed
work, and wasted gate runs. Any tool output or doc that suggests a worktree is
a defect to report, not an instruction.

## MCP Agent Mail - multi-agent coordination

Agent Mail is the coordination channel for concurrent agents: identities,
inboxes, threads, and file reservations (leases) so agents don't clobber each
other. Use it to TALK, not only to lock.

- Register: `ensure_project` then `register_agent` with the repo's absolute path
  as `project_key`.
- Reserve before editing:
  `file_reservation_paths(project_key, agent, ["crates/**"], ttl_seconds=3600, exclusive=true)`.
- Communicate: `send_message(..., thread_id=<bead id>)`, then `fetch_inbox` /
  `acknowledge_message`. Check your inbox at the start of every turn and reply
  to messages addressed to you. Post claims, handoffs, READY-FOR-VERIFY and
  landing notices on the bead's thread. Macros (`macro_start_session`, …)
  when speed matters.
- `FILE_RESERVATION_CONFLICT` → `send_message` to the holder asking for a
  handoff (what you need, which hunks, for which bead), and work on another
  part of your bead meanwhile. Never idle-wait for the lease to expire; if
  the holder does not answer within one orchestrator tick, tell the
  orchestrator, who decides.
- On joining a swarm: register, introduce yourself to the other agents, and
  acknowledge every request addressed to you. Announce each bead on its
  thread (`[<bead>] Starting…`), post progress there, and hand off explicitly
  (handoff message → receiver `macro_prepare_thread`, reserves, acknowledges).
- Pre-commit guard: the Agent Mail pre-commit guard (`install_precommit_guard`)
  makes `git commit` refuse files another agent holds exclusively. It is
  required for swarms in this shared checkout but is NOT YET INSTALLED
  (operator decision 2026-10-05; see docs/plan/SWARM_WITHOUT_WORKTREES.md).
  When installed, every agent sets `AGENT_NAME` to its Agent Mail name.
- Pitfalls: `from_agent not registered` → re-`register_agent` with the right
  `project_key`.

## Landing the plane (session completion)

Work is not complete until it is pushed. When ending a session:

1. File repo-local beads in this checkout for any remaining work.
2. Run the quality gates above if code changed.
3. Update bead status; close finished work.
4. Push:
   ```bash
   git pull --rebase
   git push
   git status            # MUST show "up to date with origin"
   ```
5. Leave a short handoff for the next session.

Do not stop before pushing; that strands work locally. If a push fails, resolve
and retry. Never commit or push without the operator's go-ahead (see above).
