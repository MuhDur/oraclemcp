# ADR 0001 — Pinned nightly toolchain + Asupersync, no stable MSRV until `oracledb` 1.0

## Status

Accepted (0.4.0).

## Context

`oraclemcp` is engine-free pure Rust with the thin `oracledb` driver compiled
in. The thin-native line (the `oracledb` driver on the Asupersync async runtime)
uses nightly-only language features, so the workspace has no stable MSRV. Both
`oracledb` and Asupersync are pre-1.0 and still moving.

We could chase a stable MSRV by forking the runtime, vendoring patched
dependencies, or dropping the thin driver for a thick (Instant Client / ODPI-C)
path. Each trades the project's core property — a single self-contained binary
with no native Oracle client — for toolchain convenience.

## Decision

Pin the toolchain to a single nightly (`nightly-2026-05-11`, recorded in
`rust-toolchain.toml`) and accept the nightly dependency until `oracledb`
reaches 1.0 and the required features land on stable. The pin is **build-time
only**: the shipped binary and the `ghcr.io/muhdur/oraclemcp` runtime image
carry no Rust toolchain and have no runtime dependency on nightly. Operators run
a plain native binary. CI, `release.yml`, and `docker.yml` all build on the
pinned toolchain.

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

Revisit when **`oracledb` ships a 1.0 release** *and* the language features
Asupersync/`oracledb` rely on are available on a stable Rust release. At that
point, evaluate adopting a stable MSRV and dropping the nightly pin.
