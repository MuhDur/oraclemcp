# Toolchain: pinned nightly + re-pin runbook

`oraclemcp` builds on a single pinned Rust nightly. This document is the
concrete runbook for **bumping that pin** — when to do it, the exact files to
change, how to validate the bump, and how to roll it back. It is the operational
companion to [ADR-0001](adr/0001-pinned-nightly-toolchain.md) (the *why*) and
[`operations.md` §1](operations.md#1-the-pinned-nightly-toolchain-is-build-time-only)
(the operator-facing "nightly is build-time-only" framing).

The current pin is **`nightly-2026-05-11`**.

> **Nightly is build-time-only.** The pin is a property of *building*
> oraclemcp, not of *running* it. The shipped binary and the published image
> carry no Rust toolchain. This runbook concerns people who build from source;
> it does not change anything for operators who run the released artifact.

---

## 1. Why the pin exists (one paragraph)

The thin-native line runs on the **asupersync 0.3.4** async runtime, and
asupersync uses nightly-only language features (`#![feature(try_trait_v2)]` and
`try_trait_v2_residual`). There is therefore **no stable MSRV** for this
workspace. The pinned `oracledb` 0.6.0 driver is **stable-clean** and is *not*
the reason for the nightly pin; asupersync is the constraint, and it is pre-1.0
and still moving. We pin a single nightly and bump it **deliberately**, rather
than tracking `nightly` automatically, so a surprise upstream toolchain change
can never silently break a build or a release. See ADR-0001 for the full
decision and its review trigger (asupersync no longer needing those nightly-only
features — `try_trait_v2` reaching stable, or asupersync dropping it).

---

## 2. When to re-pin

Re-pin **deliberately and infrequently**, coordinated with the stack — never to
chase the newest nightly for its own sake. Trigger a bump when:

- **An asupersync upgrade requires it.** This is the primary driver: asupersync
  is what depends on nightly-only language features, so a new asupersync release
  may need a feature only present in a later nightly. The toolchain bump and the
  asupersync bump land together. (An `oracledb` upgrade does not by itself force
  a re-pin — the driver is stable-clean — but bump the pin if a coordinated
  `oracledb` upgrade rides along with an asupersync change that needs it.)
- **The multi-nightly early-warning job has gone red and you have triaged it.**
  CI runs an advisory `multi-nightly` matrix (pinned date + the floating
  `nightly` channel, `continue-on-error: true`) precisely so an upcoming
  toolchain break is visible *before* you are forced into it. A red square there
  is a signal to investigate, not an instruction to bump — confirm the breakage
  is real and unavoidable on the path you need, then schedule the re-pin.
- **A security or soundness fix you need lands only in a newer nightly.**

Do **not** re-pin to clear a transient `fuzz-build` failure: that job is
`continue-on-error` because cargo-fuzz + `build-std` is inherently churn-prone,
and a flake there is not a toolchain-pin problem.

---

## 3. How to re-pin (the exact change set)

Pick the candidate nightly (usually the minimum date that satisfies the
Asupersync/`oracledb` upgrade you are landing with). Then update **every** place
the date is written. There are four:

1. **`rust-toolchain.toml`** — the local-build selector.
   ```toml
   [toolchain]
   channel = "nightly-YYYY-MM-DD"
   components = ["rustfmt", "clippy"]
   ```

2. **`.github/workflows/ci.yml`** — the `env.RUST_TOOLCHAIN` value. Every gated
   job derives its toolchain from this one variable, so a single edit re-points
   fmt, clippy, test, the pinned-nightly build, docs, the boundary/seam/honesty
   lints, `cargo deny`, the thin-db build, and `fuzz-build`. Also update the
   *baseline* entry in the `multi-nightly` matrix (the date repeated as the
   apples-to-apples comparison point alongside the floating `nightly`).

3. **Other workflow pins.** Search the workflow tree for the old date and update
   any literal that does not read from `env.RUST_TOOLCHAIN`:
   ```sh
   grep -RIn 'nightly-2026-05-11' .github/workflows
   ```
   At minimum check `release.yml` and `docker.yml`. The Dockerfile compiles in
   the builder stage with the pinned toolchain — if it pins a date literally
   (rather than reading `rust-toolchain.toml`), update it too:
   ```sh
   grep -RIn 'nightly-2026-05-11' Dockerfile* .github
   ```

4. **The README badge.** Update the toolchain badge near the top of
   [`README.md`](../README.md):
   ```
   <img src="https://img.shields.io/badge/rustc-nightly--YYYY--MM--DD-orange.svg" alt="nightly-YYYY-MM-DD">
   ```
   and the prose pin references in the Quick start section
   (`rustup toolchain install …`, `cargo +nightly-… install …`).

Then sweep for stragglers across the whole repo so no doc or comment keeps the
stale date:

```sh
grep -RIn --exclude-dir=target 'nightly-2026-05-11' .
```

Expected remaining hits after a bump are historical only — for example
ADR-0001 records `nightly-2026-05-11` as the date the decision was taken. Leave
those as history; do not rewrite them. If you change the *active* pin, add a
short note to ADR-0001's Consequences (or a follow-up ADR) recording the new
date and the Asupersync/`oracledb` versions it was coordinated with, so the pin
history stays auditable.

---

## 4. How to validate the bump

Install the candidate toolchain, then run the full gate set locally on it. These
are the same gates CI enforces on the pinned nightly (see
[`release-checklist.md`](release-checklist.md)); all must be green before the
bump is considered done.

```sh
rustup toolchain install nightly-YYYY-MM-DD --component rustfmt --component clippy

cargo +nightly-YYYY-MM-DD fmt --all -- --check
cargo +nightly-YYYY-MM-DD clippy --workspace --all-targets -- -D warnings
cargo +nightly-YYYY-MM-DD test --workspace --all-targets
cargo +nightly-YYYY-MM-DD test --workspace --doc
cargo +nightly-YYYY-MM-DD build --workspace
cargo +nightly-YYYY-MM-DD doc --workspace --no-deps

bash scripts/oraclemcp_boundary_lint.sh      # incl. the opentelemetry-sdk rt-tokio early-warning
bash scripts/oraclemcp_agent_surface_lint.sh
bash scripts/oraclemcp_driver_seam_lint.sh
bash scripts/oraclemcp_honesty_grep.sh
bash scripts/sensitive_data_lint.sh
cargo +nightly-YYYY-MM-DD deny check
```

Then let CI confirm it on a branch: push the change set and verify the required
jobs are green on the new pin. The advisory `multi-nightly` job may still be red
(the floating `nightly` can be ahead of your new pin) — that is expected and is
not a blocker; only the required jobs gate the merge.

A bump that cannot get all required gates green on the candidate nightly is not
ready: hold the pin and resolve the breakage (or pick a different candidate
date) before merging.

---

## 5. How to roll back

The pin lives entirely in tracked files, so rollback is a revert — no rebuild of
released artifacts is involved (nightly is build-time-only).

- **Before merge:** drop the branch, or `git checkout -- rust-toolchain.toml
  .github/workflows README.md` to restore the previous date, and reinstall the
  old toolchain (`rustup toolchain install nightly-2026-05-11 …`).
- **After merge, before a release:** revert the bump commit
  (`git revert <sha>`). Because the four edit sites all derive from the same date
  string, the revert restores every pin together; re-run §4 on the restored date
  to confirm green.
- **After a release built on the bad pin:** the released binary/image is already
  compiled and unaffected at runtime, so there is nothing to roll back for
  operators. Revert the pin on `main` for future builds and cut a follow-up patch
  release if a *source* build (`cargo install`) is materially affected.

Keep the previous toolchain installed (`rustup toolchain list`) until the new pin
has shipped at least one green release, so a rollback never blocks on a missing
toolchain.

---

## 6. The multi-nightly early-warning, in brief

`ci.yml` runs a `multi-nightly` matrix job that builds and tests on the pinned
date **and** the floating `nightly` channel, marked `continue-on-error: true`.
It is **advisory, not a gate**: because the line has no stable MSRV and depends
on specific nightly-only features in **asupersync** (`try_trait_v2` +
`try_trait_v2_residual`; the `oracledb` driver is stable-clean), a future
toolchain breaking us is a *when*, not an *if*. The job turns that into an early warning —
a red square that tells you to start §2 triage — instead of a release-day
surprise. The boundary lint additionally surfaces an `opentelemetry-sdk`
`rt-tokio` feature flip (which would drag Tokio into the forbidden-dependency
gate) so that specific upstream change is named at its cause, not chased through
a downstream Tokio failure.
