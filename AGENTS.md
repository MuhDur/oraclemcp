# AGENTS.md — oraclemcp

Operating rules for agents working in this repository.

**oraclemcp** is an unofficial, engine-free, safe-by-default Oracle Database
[MCP](https://modelcontextprotocol.io) server in pure Rust: a small Cargo
workspace of 8 `oraclemcp-*` library crates plus the `oraclemcp` binary. It is
the lean half of a two-binary family — the full PL/SQL intelligence superset
lives in [plsql-intelligence](https://github.com/MuhDur/plsql-intelligence) as
`plsql-mcp`. Independent open-source project; not affiliated with Oracle.

## RULE 1 — ABSOLUTE

Do not delete any file or directory unless the operator gives the exact command
in-session. This includes files you just created. If something should go, stop
and ask first.

## Irreversible / outward-facing actions

Never run `git reset --hard`, `git clean -fd`, `git push --force`, branch
deletion, or `rm -rf` on tracked paths without explicit in-session approval.
Never force-push `main`. Do not commit on the operator's behalf without a clear
in-session go-ahead. crates.io publishes and registry listings are permanent
(versions immutable, names claimed forever) — treat publishing as a gated,
deliberate step.

## Rust toolchain & gates

- Cargo workspace, `resolver = "2"`, pinned nightly
  **`nightly-2026-05-11`**, `edition = "2024"`. The thin-native line has no
  stable MSRV while Asupersync/oracledb require nightly-only features.
- Every crate is `#![forbid(unsafe_code)]`. Do not introduce `unsafe`.
- Before committing: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`, `cargo deny check`
  using the pinned toolchain from `rust-toolchain.toml`.
- The default build is offline (no native deps). The Oracle driver (ODPI-C) is
  behind the opt-in `live-db` feature and needs Oracle Instant Client at runtime.

## The safety invariant (do not weaken)

The whole point of this server is the **fail-closed SQL guard**. `oracle_query`
and `oracle_explain_plan` classify every statement through `oraclemcp-guard` and
admit only what is provably `READ_ONLY`; everything else is refused before it
reaches Oracle. The binary pins each session to `OperatingLevel::ReadOnly` with
step-up disabled. Never relax this to "allow by default." The guarded-write
machinery (`oraclemcp-guard`/`-audit`/`-auth`, exec grants, step-up, audit
hash-chain) is built but deliberately not surfaced by this binary.

## Code editing discipline

- We optimize for a clean architecture now, not backwards compatibility. No
  compat shims or `v2` file clones; migrate callers and remove old code.
- The bar for adding files is high — new files only for genuinely new domains.
- No bulk codemods or giant `sed`/regex refactors. Break large mechanical
  changes into small, reviewable edits; edit subtle changes by hand.
- Structured, minimal logs. Logs are for operators; treat UX as UI-first.

## Release flow

Versions are published from this repo. crates.io: `cargo publish --workspace`
(cargo computes the topological order). Binaries + GitHub release: tag `vX.Y.Z`
→ `.github/workflows/release.yml`. Docker (`ghcr.io/muhdur/oraclemcp`):
`.github/workflows/docker.yml`. MCP registry: `server.json` +
`.github/workflows/publish-mcp.yml` (GitHub OIDC).

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

## bv — graph-aware triage sidecar

`bv` computes PageRank / critical paths / parallel tracks over the beads graph.
**Use only `--robot-*` flags; bare `bv` opens a blocking TUI.**

```bash
bv --robot-triage   # start here   ·   bv --robot-next   # top pick + claim cmd
bv --robot-plan     # parallel tracks   ·   bv --robot-insights   # graph metrics
```

## cass / cass-memory — reuse prior work

`cass` indexes past agent sessions; `cm` surfaces procedural memory. Never run
bare `cass` (TUI) — use `--robot`/`--json`.

```bash
cass search "<problem>" --robot --limit 5    # has this been solved before?
cm context "<task>" --json                   # relevant rules, anti-patterns, history
```

## MCP Agent Mail — multi-agent coordination

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

Do not stop before pushing — that strands work locally. If a push fails, resolve
and retry. Never commit or push without the operator's go-ahead (see above).
