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
Never force-push `main`. crates.io publishes and registry listings are
permanent (versions immutable, names claimed forever) — treat publishing as a
gated, deliberate step.

## Rust toolchain & gates

- Cargo workspace, `resolver = "2"`, MSRV **1.88**, `edition = "2024"`.
- Every crate is `#![forbid(unsafe_code)]`. Do not introduce `unsafe`.
- Before committing: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`, `cargo deny check`.
- The default build is offline (no native deps). The Oracle driver (ODPI-C) is
  behind the opt-in `live-db` feature and needs Oracle Instant Client at runtime.

## The safety invariant (do not weaken)

The whole point of this server is the **fail-closed SQL guard**. `oracle_query`
and `oracle_explain_plan` classify every statement through `oraclemcp-guard` and
admit only what is provably `READ_ONLY`; everything else is refused before it
reaches Oracle. Never relax this to "allow by default."

## Release flow

- Versions are published from this repo. crates.io: `cargo publish --workspace`
  (cargo computes the topological order). Binaries + GitHub release: tag `vX.Y.Z`
  -> `.github/workflows/release.yml`. Docker (`ghcr.io/muhdur/oraclemcp`):
  `.github/workflows/docker.yml`. MCP registry: `server.json` +
  `.github/workflows/publish-mcp.yml` (GitHub OIDC).

## Issue tracking

This repo's issues are tracked in the parent plsql-intelligence beads under the
oraclemcp (`oracle-qmwz`) epics; there is no separate beads database here.
