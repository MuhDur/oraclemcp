# ADR 0001 — Pinned nightly toolchain (Asupersync needs nightly-only features), no stable MSRV

## Status

Accepted (0.4.0).

## Context

`oraclemcp` is engine-free pure Rust with the thin `oracledb` driver compiled
in. The workspace has no stable MSRV because **asupersync 0.3.4** — the async
runtime the transport and DB seam run on — uses nightly-only language features
(`#![feature(try_trait_v2)]` and `try_trait_v2_residual`). The pinned `oracledb`
0.5.1 driver itself is **stable-clean**: it is *not* the reason for the nightly
pin. Asupersync is pre-1.0 and still moving, and `try_trait_v2` is unstable.

We could chase a stable MSRV by forking the runtime, vendoring patched
dependencies, or dropping the thin driver for a thick (Instant Client / ODPI-C)
path. Each trades the project's core property — a single self-contained binary
with no native Oracle client — for toolchain convenience.

## Decision

Pin the toolchain to a single nightly (`nightly-2026-05-11`, recorded in
`rust-toolchain.toml`) and accept the nightly dependency for as long as
asupersync requires those nightly-only language features. The pin is
**build-time only**: the shipped binary and the `ghcr.io/muhdur/oraclemcp`
runtime image carry no Rust toolchain and have no runtime dependency on nightly.
Operators run a plain native binary. CI, `release.yml`, and `docker.yml` all
build on the pinned toolchain.

## Consequences

- The single-binary, no-Instant-Client deployment story is preserved (the main
  reason the project exists).
- Source builders (`cargo install`) must use the pinned toolchain; operators who
  use the released binary or image are unaffected.
- We carry the maintenance cost of bumping the pin deliberately and re-running
  the gates, rather than tracking stable automatically.
- Documentation must repeatedly clarify "nightly is build-time-only" because it
  reads as a runtime requirement to newcomers (see `docs/operations.md` §1).

## Review trigger

Revisit when **asupersync no longer requires nightly-only language features** —
either `try_trait_v2` / `try_trait_v2_residual` stabilize on a stable Rust
release, or an asupersync version drops its use of them. At that point (the
`oracledb` driver is already stable-clean) evaluate adopting a stable MSRV and
dropping the nightly pin.

The concrete procedure for bumping the pin in the meantime — when, the exact
files to edit, how to validate, and how to roll back — lives in
[`docs/TOOLCHAIN.md`](../TOOLCHAIN.md).
