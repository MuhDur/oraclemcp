# Release checklist — the gates that must be green on the frozen RC

This is the release-gate checklist for `oraclemcp` (bead `release-gre.1`, plan
§8 item 1). It enumerates the standard quality gates that **must be green in CI
on the exact frozen release-candidate (RC) commit** before a tag is cut, and
records that the CI run on that commit is the evidence.

These gates are not aspirational: every one of them already runs in
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) on the pinned
toolchain (`nightly-2026-05-11`, see
[`TOOLCHAIN.md`](TOOLCHAIN.md) and [ADR-0001](adr/0001-pinned-nightly-toolchain.md)).
The checklist exists so the release operator confirms they ran on the **frozen
RC SHA specifically** — not an earlier green run — and links that run from the
release notes.

---

## The required gates (all on the pinned nightly)

Each row is a standing CI job. The gate is "green on the RC commit"; the
evidence is the CI run for that commit (linked below at release time).

| Gate | Command | CI job |
| --- | --- | --- |
| Formatting | `cargo fmt --all -- --check` | `fmt` |
| Lint (deny warnings) | `cargo clippy --workspace --all-targets -- -D warnings` | `clippy` |
| Tests | `cargo test --workspace --all-targets` + `--doc` | `test` |
| Pinned-nightly build | `cargo build --workspace` | `pinned-nightly` |
| Supply chain | `cargo deny check` (advisories, licenses, bans, sources) | `supply-chain` |
| Engine-free boundary + forbidden-deps | `scripts/oraclemcp_boundary_lint.sh` | `boundary` |
| Driver-adapter seam | `scripts/oraclemcp_driver_seam_lint.sh` | `boundary` |
| Honesty framing | `scripts/oraclemcp_honesty_grep.sh` | `boundary` |
| Sensitive-data lint | `scripts/sensitive_data_lint.sh` | `sensitive-data` |
| Release metadata sync | `scripts/release_preflight.sh` | `release-metadata` |

All ten run on the pinned nightly (every toolchain-bearing job derives its
toolchain from `env.RUST_TOOLCHAIN` in `ci.yml`).

### Advisory (not release-blocking)

These jobs run but do **not** gate the tag; a red square is a signal to
investigate, not a blocker:

- `fuzz-build` — compiles the cargo-fuzz targets so they cannot rot
  (`continue-on-error`; cargo-fuzz + `build-std` is churn-prone).
- `multi-nightly` — builds/tests on the pinned date plus the floating `nightly`
  channel as an early warning for an upcoming toolchain break
  (`continue-on-error`; see [`TOOLCHAIN.md`](TOOLCHAIN.md) §6).

---

## Release-day procedure

1. **Freeze the RC.** Pick the commit you intend to tag. Everything below runs
   against that exact SHA — do not amend or rebase after this point.
2. **Run the metadata preflight locally** as a fast pre-check
   (it is also the `release-metadata` CI job):
   ```sh
   RELEASE_TAG=vX.Y.Z bash scripts/release_preflight.sh
   ```
   It verifies the workspace shares one version, `server.json`/README/CHANGELOG
   agree on it, the OCI image reference matches, no stale image-version strings
   linger, the boundary lint holds, and the honesty gate passes. With
   `RELEASE_TAG` set it also checks the tag is `vX.Y.Z` and matches the
   workspace version.
3. **Confirm CI is green on the RC commit.** Open the CI run for that exact SHA
   and confirm every **required** gate in the table above is green. The advisory
   jobs (`fuzz-build`, `multi-nightly`) may be red without blocking.
4. **Link the run as evidence.** Record the CI run URL for the RC commit in the
   release notes / `CHANGELOG.md` entry for `vX.Y.Z`. That linked, green run on
   the frozen SHA *is* the release-gate evidence — there is nothing to attest
   beyond it.
5. **Tag and publish.** Only after steps 3–4 hold, push the `vX.Y.Z` tag. The
   `release.yml` / `docker.yml` / `publish-mcp.yml` workflows build the
   artifacts on the pinned toolchain from that tag.

> **Honesty note.** This checklist documents the gates that exist today and the
> procedure for proving them green on the RC. The "green on the frozen RC +
> linked run" assertion is satisfied *at release time* by the operator linking
> that run — it is deliberately not pre-filled here, so the checklist never
> claims evidence that has not yet been produced.

---

## RC sign-off block (copy into the release notes)

```
Release: vX.Y.Z
Frozen RC commit: <full SHA>
Pinned toolchain: nightly-2026-05-11
CI run (evidence): <URL to the CI run for the RC commit>

Required gates green on the RC commit:
- [ ] fmt              (cargo fmt --all -- --check)
- [ ] clippy           (-D warnings)
- [ ] test             (--workspace --all-targets + --doc)
- [ ] pinned-nightly   (cargo build --workspace)
- [ ] supply-chain     (cargo deny check)
- [ ] boundary         (engine-free + forbidden-deps + driver-seam + honesty)
- [ ] sensitive-data   (sensitive_data_lint.sh)
- [ ] release-metadata (release_preflight.sh)
```

See also: [`TOOLCHAIN.md`](TOOLCHAIN.md) for re-pinning the toolchain,
[`operations.md`](operations.md) for the deployment runbook, and
[`hardening.md`](hardening.md) for the security checklist.
