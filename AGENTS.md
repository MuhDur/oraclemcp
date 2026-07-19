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

## Rust toolchain & gates

- Cargo workspace, `resolver = "2"`, pinned nightly
  **`nightly-2026-05-11`**, `edition = "2024"`. There is no stable MSRV, for two
  independent reasons — see [`docs/TOOLCHAIN.md`](docs/TOOLCHAIN.md):
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
  Note the pinned `oracledb` 0.8.4 driver's own source is stable-clean; it is
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

## Swarm operations charter v2

The operator constitution is binding: never defer planned work unilaterally;
report red before calling anything green; make only evidence-backed claims;
reread this file and README.md every session; verify before acting; protect host,
disk, and token budgets; drive autonomously while following operator choices
exactly; keep the SQL guard tighten-only; quarantine field identifiers and
secrets; create no surprise cost (OCI must remain provably free-tier); land the
complete release scope rather than spreading it across version bumps; and
escalate true blockers while delegating unforeseen in-scope work.

- Shared-tree work is limited to at most three agents on disjoint reserved
  domains. A build-heavy swarm requires one managed git worktree and one
  per-agent `CARGO_TARGET_DIR` on real disk per agent, short-lived bead-scoped
  branches, one canonical tracker database, fixture bootstrap, sccache, and
  managed merge/removal. Never place build state on tmpfs. Preflight free space
  plus a write/read canary and report capacity failures as `DISK`, not `OOM`.
- Every Cargo invocation goes through the repository concurrency guard. Probe
  Agent Mail build slots once; if that service is disabled, fall through to the
  local enforced lock and existing job/TasksMax limits instead of polling it.
  Default to scoped `-p` checks. `rch` may accelerate marathon lanes after
  `rch doctor`, but unreachable workers must fall back locally and no gate may
  require remote capacity.
- Pin one Agent Mail identity to each pane and persist its registration token
  outside compactable chat context. Reattach after compaction; never remint.
  Before spawning, verify requested model, quota, and context headroom; size
  waves to capacity, reconcile silently failed children, and never route release
  finalization to a near-full pane.
- The self-drive loop is `br ready` → claim → implement → prove → close; never
  park an `in_progress` claim. Keep orders, Beads, and a running scratch summary
  current. Child completion is event-driven. CI status is reported on a fixed
  heartbeat and every transition, using a durable scheduler and debounced idle
  notifications.
- Before an expensive live loop, capture all diagnostics once and falsify the
  hypothesis offline. Seed durable campaign lessons and the constitution into
  repo-local cass-memory; the retro is evidence, this charter is policy, and
  memory is only the task-time retrieval layer.

## Issue tracking

This repo's issues are tracked in this checkout's local `.beads/` database.
Do not use the parent `plsql-intelligence` tracker for new oraclemcp work unless
the operator explicitly asks for a cross-repo migration. Work beads from this
repo root with `br`:

```bash
br ready --json                      # unblocked work
br update <id> --status in_progress  # claim
br close  <id> --reason "…"          # finish; commit .beads/ with the code
br create "Title" -t bug|feature|task -p 0-4 --deps discovered-from:<id>
br sync --flush-only                 # export .beads/issues.jsonl before commit
```

Types: `bug`, `feature`, `task`, `epic`, `chore`. Priorities: `0` critical …
`4` backlog (default `2`). Never use markdown TODO lists or a second tracker.
Commit `.beads/` changes with the code or planning change they describe.

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
