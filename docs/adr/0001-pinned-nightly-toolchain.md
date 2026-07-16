# ADR 0001 — Pinned nightly toolchain, no stable MSRV

## Status

Accepted (0.4.0). **Decision stands; its stated reason was corrected 2026-07-16
— see [Correction](#correction-2026-07-16-bead-oraclemcp-yi2z) before relying on
the Context below.** In short: asupersync does not *require* nightly (the
feature is opt-in, merely on by default), `oracledb` *is* the proximate cause
(its dependency declaration does not opt out), and Windows needs nightly for a
second, unrelated reason. The Context is preserved as written for the record.

## Context

`oraclemcp` is engine-free pure Rust with the thin `oracledb` driver compiled
in. The workspace has no stable MSRV because **asupersync 0.3.5** — the async
runtime the transport and DB seam run on — uses nightly-only language features
(`#![feature(try_trait_v2)]` and `try_trait_v2_residual`). The pinned `oracledb`
0.8.3 driver itself is **stable-clean**: it is *not* the reason for the nightly
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

## Correction (2026-07-16, bead `oraclemcp-yi2z`)

The decision above stands — the pin is real and still required — but two factual
statements in it are **wrong**, and they matter because they point the review
trigger at the wrong lever. Left in place above as the record of what was
decided; corrected here:

1. **"asupersync requires nightly-only language features" is inaccurate.**
   asupersync gates them behind its `nightly-outcome-try` cargo feature
   (`asupersync-0.3.5/src/lib.rs:52-53`). The feature is opt-in — it is merely
   in asupersync's `default` set. A consumer that opts out does not get it.
2. **"the `oracledb` driver is not the reason for the pin" is inaccurate.** Its
   *source* is stable-clean, but it declares its asupersync dependency **without
   `default-features = false`**, so cargo feature unification re-enables the
   nightly feature for the whole graph — overriding this workspace's own opt-out.
   `cargo tree -i asupersync -e features` shows `asupersync feature "default"
   <- oracledb`. It is the proximate cause.
3. **Missed at the time:** on **Windows**, `oraclemcp-core` independently needs
   `windows_by_handle` for `MetadataExt::number_of_links` (hard-linked-lock
   refusal). Windows needs nightly even if 1 and 2 are resolved.

## Review trigger (corrected)

Two levers, not one — and the first needs nobody upstream:

- **Now, and independently of any upstream release:** evaluate having `oracledb`
  set `default-features = false` on asupersync (keeping `proc-macros`, its other
  default). Neither driver nor server source uses the nightly syntax, so this may
  drop the requirement outright on non-Windows. Tracked by `oraclemcp-yi2z`;
  **prove it builds and gates green on stable before dropping the pin.**
- **Upstream:** `try_trait_v2` / `try_trait_v2_residual` stabilizing, or
  asupersync dropping the feature from its defaults, would resolve it without
  the driver change.
- **Windows:** additionally needs `windows_by_handle` (rust-lang/rust#63010) to
  stabilize, or a stable replacement for `number_of_links`.

The concrete procedure for bumping the pin in the meantime — when, the exact
files to edit, how to validate, and how to roll back — lives in
[`docs/TOOLCHAIN.md`](../TOOLCHAIN.md).
