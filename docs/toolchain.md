# Toolchain: pinned nightly + re-pin runbook

`oraclemcp` builds on stable Rust on Linux/macOS and retains a pinned nightly
for default and release builds. Windows requires that nightly. This document is the
concrete runbook for **bumping that pin** — when to do it, the exact files to
change, how to validate the bump, and how to roll it back. It is the operational
companion to [ADR-0001](adr/0001-pinned-nightly-toolchain.md) (the *why*) and
[`operations.md` §1](operations.md#1-the-pinned-nightly-toolchain-is-build-time-only)
(the operator-facing "nightly is build-time-only" framing).

The current pin is **`nightly-2026-05-11`**.

The maintained primary Oracle driver is `oraclemcp-driver-cx`, pinned by the
workspace manifest. The official `oracledb` adapter is a bounded connect-time
alternate for compatible password connections. Release archives and the single
`ghcr.io/muhdur/oraclemcp` image include the PL/SQL-intelligence engine; the
default source build includes it as well.

> **Nightly is build-time-only.** The pin is a property of *building*
> oraclemcp, not of *running* it. The shipped binary and the published image
> carry no Rust toolchain. This runbook concerns people who build from source;
> it does not change anything for operators who run the released artifact.

---

## 1. Why the pin exists (one paragraph)

Linux and macOS check, test and package on the current stable Rust toolchain.
The pinned nightly remains the default and the release toolchain so those
builds stay reproducible. Changing the default is a separate decision.

The `oraclemcp-driver-cx` 0.9.3 driver's own source is stable-clean.

**Runtime features.** Both the server and driver opt out of asupersync 0.3.9's
default features. The driver explicitly retains `tls` and `proc-macros`;
`nightly-outcome-try` must remain absent. That optional default feature enables
`try_trait_v2` and `try_trait_v2_residual` inside asupersync. Previously the
server opted out but the driver's dependency declaration re-enabled it through
Cargo feature unification. The stable jobs and boundary lint now reject that
regression across all features and targets:

```sh
cargo tree --locked -e features --workspace --all-features --target all -i asupersync
```

**Windows.** Both `oraclemcp-core` and `oraclemcp-audit` enable
`windows_by_handle` for `MetadataExt::number_of_links` and file identity
(`volume_serial_number`). These checks protect the service lock and audit sink
against hard-link and identity substitution. Windows retains nightly for these
standard-library APIs. Stable Windows is outside this qualification.

Stable CI covers Linux and macOS. Nightly release jobs and Windows jobs retain
`nightly-2026-05-11`; the pin is bumped deliberately with the checks below.

---

## 2. When to re-pin

Re-pin **deliberately and infrequently**, coordinated with the stack — never to
chase the newest nightly for its own sake. Trigger a bump when:

- **A dependency upgrade requires it.** Keep asupersync's optional nightly
  feature disabled and preserve stable Linux/macOS. If an upgrade requires a
  newer release compiler, coordinate that dependency and toolchain change;
  never re-enable nightly features silently.
- **The multi-nightly early-warning job has gone red and you have triaged it.**
  The tier-C `multi-nightly` job builds and tests on the floating `nightly`
  channel for every release candidate precisely so an upcoming toolchain break
  is visible *before* you are forced into it. A red result there
  is a signal to investigate, not an instruction to bump — confirm the breakage
  is real and unavoidable on the path you need, then schedule the re-pin.
- **A security or soundness fix you need lands only in a newer nightly.**

Do **not** re-pin to clear a transient `fuzz-build` failure. The job's
cargo-fuzz *install* step is the only tolerant one — a bounded retry makes the
tool available or fails the job explicitly — and cargo-fuzz + `build-std` is
inherently churn-prone, so a flake there is not a toolchain-pin problem. The
four target builds and the planted-negative step are blocking, though, so a
genuinely red `fuzz-build` is a real signal to triage rather than re-pin around.

---

## 3. How to re-pin (the exact change set)

Pick the candidate nightly (usually the minimum date that satisfies the
Asupersync/driver-cx upgrade you are landing with). Then update **every** place
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
   lints, `cargo deny`, the thin-driver build (a `pinned-nightly` step), and
   `fuzz-build`. The tier-C `multi-nightly` job builds only the floating
   `nightly`, so it has no date to update.

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
date and the Asupersync/driver-cx versions it was coordinated with, so the pin
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

`ci.yml` has a `multi-nightly` job that builds and tests on the floating
`nightly` channel (the pinned date is covered by the tier-A jobs). It is tier C:
it runs when the tier-C runner dispatches `ci.yml` on a release candidate, and
its result is recorded in the release proof rather than on each push. The
required stable jobs cover Linux/macOS separately; Windows continues to use
`windows_by_handle` (§1). The floating job warns about an upcoming compiler
change before it reaches the pinned default and release builds.
The boundary lint additionally surfaces an `opentelemetry-sdk`
`rt-tokio` feature flip (which would drag Tokio into the forbidden-dependency
gate) so that specific upstream change is named at its cause, not chased through
a downstream Tokio failure.
