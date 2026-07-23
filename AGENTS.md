# AGENTS.md - oraclemcp

Operating rules for agents working in this repository.

**oraclemcp** is an unofficial, engine-free, safe-by-default Oracle Database
[MCP](https://modelcontextprotocol.io) server in pure Rust: a small Cargo
workspace of 8 `oraclemcp-*` library crates plus the `oraclemcp` binary. Its
optional `plsql-intelligence` feature embeds the PL/SQL engine for offline
tools; the separate `plsql-mcp` server is deprecated. Independent open-source
project; not affiliated with Oracle.

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

## Swarm operating constitution

Eighteen rules. Rules 1-12 were mined from the 2026-07 multi-repo swarm
retrospective (`docs/plan/RETRO_SWARM_CAMPAIGN_2026-07.md` §3G,
`docs/plan/PLAN_ENGINEERING_PROGRAM.md` §27.3); rules 13-17 were mined from the
2026-07-21 five-agent session, one per incident it produced (rule 18 from an
incident during the session that encoded the others). Binding on every
agent in this repo, solo or swarmed — most are new; a few name-and-link existing
rules above so the constitution stays the one place to check:

1. Never defer planned work on your own initiative — deferral is the
   operator's call, not an agent's judgment call.
2. Green means *honestly* green; surface red before the operator finds it.
3. Claims must be evidence-backed — never assert what you haven't just run
   and checked.
4. Reread this file (and `README.md`) until understood, every session,
   before acting.
5. Think before acting ("ultrathink"): verify, then execute — don't patch on
   a hunch.
6. Be resource-disciplined: don't trash the host, the disk, or the
   token/session budget (`CARGO_BUILD_JOBS` caps, scoped `-p` builds over
   full-workspace ones, no unbounded concurrent compiles).
7. Keep driving autonomously, but follow explicit operator choices — model,
   agent freshness, scope — *exactly*; deviation is the fastest path to anger.
8. The fail-closed guard is sacred and tighten-only — see "The safety
   invariant" below; this rule doesn't restate it, it just makes the
   constitution complete.
9. Confidentiality is absolute: field-test/live-customer identifiers never
   leave quarantine (`todelete/`, gitignored) or enter a committed artifact.
10. No surprise costs — cloud resources (OCI, etc.) stay free-tier; a hard
    rule, not a target.
11. Land complete, not sliced across version bumps or half-shipped across
    sessions.
12. Escalate blockers to the operator; delegate unforeseen work to the
    tracker (`br create`), don't quietly derail the authoritative prompt's
    scope.
13. **A modified file that is not yours is another agent mid-edit, not a
    defect.** Check `git status` on a file before declaring it broken, and
    judge the committed truth (`git show HEAD:<path>`) before filing a build
    blocker or going idle on one.
14. **Close evidence comes from a tree verified clean of other agents' work.**
    Derive the evidence `source` block from git rather than asserting it;
    commit your in-scope work first, and generate a whole-tree reproducibility
    proof from a dedicated clean worktree at HEAD.
15. **Read the gate verdict yourself; never infer a pass from a successful
    push.** `git push` reports what the remote accepted, not what the gate
    decided. A gate that printed a failure is a failure no matter how the push
    went.
16. **Never block a turn on an unbounded wait.** Check once, report, move on.
    Every wait carries a deadline, and reaching the deadline is a result to
    report — not a reason to wait again. A blocked turn queues every dispatch
    behind it.
17. **A struct field and its initializers are ONE logical change, landed in ONE
    commit by ONE agent.** The same holds for any edit whose halves do not
    compile apart: a `git mv` and its references, a trait method and its impls,
    an enum variant and its exhaustive matches. Split it across panes and you
    break the build for everyone in the shared checkout.
18. **Commit explicit paths, then verify what landed.** `git commit -- <path>...`
    and `git show --stat HEAD`; never `-a`/`git add -A` in a shared checkout.
    A deletion of a path that still exists in the worktree is a stale index
    snapshot committed over someone else's landed work, not a delete.

Rules 13-18 are mechanized, one subcommand per rule, so the question each one
answers is settled by git or an exit status rather than by a buffer or a hope:

```bash
scripts/swarm_discipline.sh foreign-edit <path>...          # 13
scripts/swarm_discipline.sh evidence-source --kind close --from <evidence.json>  # 14
scripts/swarm_discipline.sh verified-push \
  --gate-cmd 'cargo fmt --all -- --check && scripts/build_lease.sh -- cargo clippy --workspace --all-targets -- -D warnings && scripts/build_lease.sh -- cargo test --workspace' \
  -- origin main                                            # 15
scripts/swarm_discipline.sh bounded-run --timeout 120 -- <cmd>                   # 16
scripts/swarm_discipline.sh unbounded-wait-lint                                  # 16
scripts/swarm_discipline.sh struct-atomicity --staged                            # 17
scripts/swarm_discipline.sh stale-delete-check --staged                           # 18
```

Exit 65 from any of them is a refusal, not advice. `--selftest` proves each
refusal and each acceptance; CI runs it alongside the other lints.

## Rust toolchain & gates

- Cargo workspace, `resolver = "2"`, pinned nightly
  **`nightly-2026-05-11`**, `edition = "2024"`. There is no stable MSRV, for two
  independent reasons — see [`docs/toolchain.md`](docs/toolchain.md):
  1. **asupersync 0.3.9's `nightly-outcome-try` feature** enables
     `feature(try_trait_v2)` + `try_trait_v2_residual` inside asupersync itself
     (`asupersync-0.3.9/src/lib.rs:52-53`). It is **opt-in but on by default**,
     not something asupersync inherently requires. We ask for
     `default-features = false` (`Cargo.toml`), but `oracledb` depends on
     asupersync *without* opting out, so feature unification turns it back on
     for the whole graph. Neither driver nor server source uses the nightly
     syntax — the feature arrives transitively and unrequested. Whether it can
     be dropped is bead `oraclemcp-yi2z`; until then **the nightly pin is real
     and required**.
  2. **Windows only:** `oraclemcp-core` enables `windows_by_handle` for
     `MetadataExt::number_of_links`, which `file_store` needs to refuse a
     hard-linked service lock (and the audit sink needs for file identity).
     There is no stable `std` equivalent, so Windows needs nightly regardless of
     reason 1.
  Note the pinned `oracledb` 0.9.1 driver's own source is stable-clean; it is
  its asupersync **dependency declaration** that pulls the nightly feature in.
  Do not restate this as "asupersync requires nightly" — that attribution is
  wrong and sent a prior audit looking in the wrong place.
- Every crate is `#![forbid(unsafe_code)]`. Do not introduce `unsafe`.
- Before committing: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`, `cargo deny check`
  using the pinned toolchain from `rust-toolchain.toml`.
- The default build is pure Rust and has no native Oracle client dependency.
  Live database access uses the thin `oracledb` driver and does not require
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

Before launching a multi-agent wave, run the host + scheduler preflight. It
refuses wrong-model, insufficient-quota, near-full-context, oversized-wave, and
low memory/PID/FD headroom states before a spawn occurs:

```bash
scripts/swarm_spawn_preflight.sh --agents 4 \
  --requested-model fable --candidate-model fable \
  --quota-remaining 4 --context-remaining-pct 80
```

The documented default ceiling is 8 agents per wave with at least 20% context
remaining. The exact per-agent and fixed host reserves are documented in
[`docs/multi-agent-build-policy.md`](docs/multi-agent-build-policy.md).

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
not additional tag pipelines. Homebrew and winget manifests ship as GitHub
release assets for separate registry promotion. No npm/npx channel is offered.

## Issue tracking

This repo's issues are tracked in this checkout's local `.beads/` database.
Do not use the parent `plsql-intelligence` tracker for new oraclemcp work unless
the operator explicitly asks for a cross-repo migration. Work beads from this
repo root with `br`:

```bash
br ready --json                      # unblocked work
br update <id> --status in_progress  # claim
python3 scripts/audit_bead_closes.py --template <id> --scope <path>  # scaffold evidence
scripts/bead_tracker_guard.sh close <id> --evidence \
  tests/artifacts/evidence/closes/<id>.json --summary "…"
br create "Title" -t bug|feature|task -p 0-4 --deps discovered-from:<id>
br sync --flush-only                 # export .beads/issues.jsonl before commit
```

Types: `bug`, `feature`, `task`, `epic`, `chore`. Priorities: `0` critical …
`4` backlog (default `2`). Never use markdown TODO lists or a second tracker.
Commit `.beads/` changes with the code or planning change they describe.

Never use raw `br close` or `br update <id> --status open` in a swarm. The
guarded close requires committed evidence and binds the work commit, evidence
commit, and canonical evidence path into `close_reason`. Release a claim with
`scripts/bead_tracker_guard.sh release-claim <id>`; it serializes with guarded
closes and preserves a bead that became closed. When a false close is found,
correct that original bead with `bead_tracker_guard.sh correct-false-close
--original-bead <id> ...`, never only a sibling. See
[`docs/bead-close-evidence.md`](docs/bead-close-evidence.md).

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

## MCP Agent Mail - multi-agent coordination

For concurrent agents: identities, inboxes, searchable threads, and advisory
file reservations (leases) so agents don't clobber each other.

- Register: `ensure_project` then `register_agent` with the repo's absolute path
  as `project_key`.
- Reserve before editing:
  `file_reservation_paths(project_key, agent, ["crates/**"], ttl_seconds=3600, exclusive=true)`.
- Communicate: `send_message(..., thread_id=…)`, then `fetch_inbox` /
  `acknowledge_message`. Macros (`macro_start_session`, …) when speed matters.
- Pitfalls: `from_agent not registered` → re-`register_agent` with the right
  `project_key`. `FILE_RESERVATION_CONFLICT` → adjust patterns or wait for expiry.

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
