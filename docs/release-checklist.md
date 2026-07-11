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
| Agent surface lint | `scripts/oraclemcp_agent_surface_lint.sh` | `boundary` |
| Driver-adapter seam | `scripts/oraclemcp_driver_seam_lint.sh` | `boundary` |
| Honesty framing | `scripts/oraclemcp_honesty_grep.sh` | `boundary` |
| Sensitive-data lint | `scripts/secret_scan.sh` (structural + rendered surfaces) | `sensitive-data` |
| Release acceptance suite | `scripts/release_acceptance_ci_suite.sh` | `release-acceptance` |
| Release version surfaces (D3.1) | `scripts/release_surface_sync_check.sh` | `release-metadata` |
| Release metadata sync | `scripts/release_preflight.sh` | `release-metadata` |

All thirteen run on the pinned nightly (every toolchain-bearing job derives its
toolchain from `env.RUST_TOOLCHAIN` in `ci.yml`).

### Required operator-run gate: Oracle version matrix (pre-23ai coverage)

CI has no live databases, so this gate is run by the release operator on the
frozen RC — it is **required**, not advisory. A release must not ship with
live verification that has only ever seen Oracle 23ai: the 0.6.x field test
proved a connect path that could not reach *any* pre-23ai server can pass
every offline gate and first fail at a customer install.

| Gate | Command | Where |
| --- | --- | --- |
| Oracle version matrix (XE 18 + XE 21 + FREE 23ai, full operating-level ladder over MCP stdio) | `bash scripts/e2e/oracle_version_matrix.sh --log` | operator-run, lab lanes |

Bring up the three throwaway lab lanes (any local ports; the defaults below
match the script), export the opt-in env, and require **all three lanes
green** — `free23` is the regression bar, `xe18`/`xe21` are the pre-23ai
coverage this gate exists for:

```sh
docker run -d --name oracle-xe18 -p 1518:1521 -e ORACLE_PASSWORD=<pw> gvenzl/oracle-xe:18-slim
docker run -d --name oracle-xe21 -p 1520:1521 -e ORACLE_PASSWORD=<pw> gvenzl/oracle-xe:21-slim
docker run -d --name oracle-free -p 1522:1521 -e ORACLE_PASSWORD=<pw> gvenzl/oracle-free:23-slim

ORACLEMCP_LIVE_XE=1 \
ORACLE_MATRIX_XE18_USER=<lab-user>  ORACLE_MATRIX_XE18_PASSWORD=<lab-pw> \
ORACLE_MATRIX_XE21_USER=<lab-user>  ORACLE_MATRIX_XE21_PASSWORD=<lab-pw> \
ORACLE_MATRIX_FREE23_USER=<lab-user> ORACLE_MATRIX_FREE23_PASSWORD=<lab-pw> \
bash scripts/e2e/oracle_version_matrix.sh --log
```

Per lane it drives the real binary end-to-end (doctor `--online`, READ_ONLY
row-value asserts + refusal, READ_WRITE preview→grant→rollback/commit, governed
DDL create/drop, drop back to READ_ONLY, audit hash-chain verify); details in
[`operations.md`](operations.md) §5.7.1. An optional genuine-19c lane is
documented there as an operator-run extra, not a gate requirement.

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

1. **Freeze the source RC.** Pick the source commit you intend to qualify. Do
   not amend or rebase that source commit after this point. The D3.2 proof step
   may add one evidence-only commit containing only
   `tests/artifacts/local_gate/results-*.json`; tag that evidence commit.
2. **Run the metadata preflight locally** as a fast pre-check
   (it is also the `release-metadata` CI job):
   ```sh
   bash scripts/local_release_gate.sh --log --commit-proof
   git add tests/artifacts/local_gate/results-*.json
   git commit -m "test(release): add local gate proof for frozen RC"
   RELEASE_TAG=vX.Y.Z bash scripts/release_preflight.sh
   ```
   It verifies the workspace shares one version, `server.json`/README/CHANGELOG
   agree on it, the OCI image reference matches, no stale image-version strings
   linger, the local D3.2 synthetic TCPS proof is present and sanitized, the
   boundary lint holds, and the honesty gate passes. With
   `RELEASE_TAG` set it also checks the tag is `vX.Y.Z` and matches the
   workspace version.
   Also run the confidentiality gate self-test before tagging:
   ```sh
   bash scripts/secret_scan.sh --self-test
   bash scripts/secret_scan.sh
   ```
3. **Run the installer sandbox smoke against the built binary.** This exercises
   the real offline Unix installer path in a disposable prefix under
   `target/installer-smoke`; it does not request a service install:
   ```sh
   cargo build -p oraclemcp
   TMPDIR=/dev/shm ORACLEMCP_INSTALLER_BUILT_BINARY="$PWD/target/debug/oraclemcp" \
     bash scripts/installer_lint_and_offline_smoke.sh --log
   ```
4. **Confirm CI is green on the RC commit.** Open the CI run for that exact SHA
   and confirm every **required** gate in the table above is green. The advisory
   jobs (`fuzz-build`, `multi-nightly`) may be red without blocking.
5. **Link the run as evidence.** Record the CI run URL for the RC commit in the
   release notes / `CHANGELOG.md` entry for `vX.Y.Z`. That linked, green run on
   the frozen SHA *is* the release-gate evidence — there is nothing to attest
   beyond it.
6. **Tag and publish.** Only after steps 4–5 hold, push the `vX.Y.Z` tag. The
   `release.yml` / `docker.yml` / `publish-mcp.yml` workflows build the
   artifacts on the pinned toolchain from that tag.

> **Honesty note.** This checklist documents the gates that exist today and the
> procedure for proving them green on the RC. The "green on the frozen RC +
> linked run" assertion is satisfied *at release time* by the operator linking
> that run — it is deliberately not pre-filled here, so the checklist never
> claims evidence that has not yet been produced.

---

## Rollback runbook for a broken `v0.6.0`

Run the dry-run first and paste its JSON-line output into the incident notes:

```sh
bash scripts/e2e/release_rollback_dry_run.sh --log --dry-run
```

The dry-run is intentionally non-mutating and fails closed without `--dry-run`.
After explicit operator approval, execute the reviewed commands in this order:

1. **Stop promotion.** Cancel still-running release, Docker, and MCP-registry
   workflows for the broken tag before changing public state.
2. **Yank crates.io packages.** Yank every published `0.6.0` crate:
   `oraclemcp-error`, `oraclemcp-telemetry`, `oraclemcp-audit`,
   `oraclemcp-guard`, `oraclemcp-config`, `oraclemcp-db`, `oraclemcp-auth`,
   `oraclemcp-core`, and `oraclemcp`.
3. **Mark or remove the GitHub release.** First mark `v0.6.0` as prerelease.
   Delete the GitHub release and cleanup tag only if the artifacts must be
   hidden; otherwise leave the prerelease visible with the incident note.
4. **Revert GHCR `:latest` without rebuilding history.** Dispatch `docker.yml`
   for the previous good version with `variant=core` and
   `operation=rollback`; if the PL/SQL intelligence image shipped, dispatch the
   same version with `variant=plsql-intelligence`. The workflow resolves
   `refs/tags/v<version>`, verifies Cargo/server metadata plus the existing
   digest's keyless signature, and retags only `:latest` (or
   `:plsql-intelligence-latest`). It never rewrites the versioned image. Use
   `operation=rebuild` only as a reproducibility proof: a digest mismatch is a
   hard failure and still leaves both versioned and rolling tags unchanged. A
   rebuild can repair an absent version tag from the exact release source, but
   it checks again immediately before creation and refuses to replace a tag
   that already exists. For a legacy image without source-bound annotations,
   rollback refuses it; `operation=rebuild` may add the binding only after the
   exact-tag rebuild produces the already-published digest byte for byte.
5. **Revert MCP registry metadata.** Restore `server.json` from the previous
   good tag, commit that rollback on `main`, push, then dispatch
   `publish-mcp.yml` so the registry no longer points at the broken image.
6. **Handle npm correctly.** npm packages cannot be unpublished after the
   short unpublish window and must not be treated as reversible. Deprecate
   `oraclemcp@0.6.0` with a clear message and move the `latest` dist-tag back
   to the previous good version.
7. **Document Homebrew and winget lag.** Both are pull/manifest-update
   channels. Submit rollback PRs or manifest updates promptly, but assume users
   may still see the broken version until those ecosystems process the change.

Do not call this rollback complete until crates.io, GitHub release state, GHCR
`:latest`, MCP registry `server.json`, npm deprecation/dist-tag, and the
Homebrew/winget lag note are all recorded in the incident notes.

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
- [ ] sensitive-data   (secret_scan.sh)
- [ ] release-acceptance (B.12: DL-9 + ERG-10 + DOC-10 + E0 + feature-powerset + arch-fitness)
- [ ] release-metadata (release_preflight.sh)
- [ ] rollback dry-run (scripts/e2e/release_rollback_dry_run.sh --log --dry-run)
- [ ] local-release-gate (scripts/local_release_gate.sh --log --commit-proof,
      committed sanitized synthetic proof under tests/artifacts/local_gate/)
- [ ] real-adb-tcps-signoff (operator-run when real ADB/OCI-IAM creds are available:
      scripts/e2e/real_adb_tcps_signoff.sh --log; evidence stays out-of-band)
- [ ] oracle-version-matrix (operator-run: scripts/e2e/oracle_version_matrix.sh --log,
      all three lanes xe18/xe21/free23 green)
```

> **This checklist proves the gates are _green_; it does not by itself qualify
> the release.** The certifying gate is the severity policy +
> exact-SHA qualification in [`severity-policy.md`](severity-policy.md) (D9): no
> open P0/P1, every P2 fixed-or-signed, two consecutive clean fresh-eyes
> bug-hunt passes, certified against the exact frozen RC SHA. Copy *both* the
> block above and the D9 sign-off block into the release evidence. The
> supply-chain artifacts (SBOM + provenance + signatures, D3) are produced by
> [`release.yml`](../.github/workflows/release.yml); operators verify them with
> the commands in
> [`operations.md` §6](operations.md#6-verifying-release-artifacts-sbom-provenance-signatures).

See also: [`severity-policy.md`](severity-policy.md) for the certifying gate
(D9), [`TOOLCHAIN.md`](TOOLCHAIN.md) for re-pinning the toolchain,
[`operations.md`](operations.md) for the deployment runbook and release-artifact
verification (§6), and [`hardening.md`](hardening.md) for the security
checklist.
