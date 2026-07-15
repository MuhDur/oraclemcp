# Release version surfaces (D3.1 audit)

Every file in the inventory table below must carry its expected release version
before a tag is cut — the shared workspace version for the `oraclemcp-*`
surfaces, and the pinned driver version for the driver-pin surfaces (server and
driver version independently since 0.8.0). User-facing install/pull EXAMPLES are
deliberately excluded — they are version-agnostic (see the section after the
table).
`scripts/release_surface_sync_check.sh` enforces this inventory mechanically;
`scripts/release_preflight.sh` and `scripts/release_acceptance_ci_suite.sh` call it on every release gate run. For drift drills only, `ORACLEMCP_RELEASE_SURFACE_SYNC_HEALTH_PATH` overrides the operator health fixture path (see `release_surface_drift_fails_fast` in `crates/oraclemcp/tests/e2e_harness.rs`).

The expected workspace version is always read from `cargo metadata` (all nine
`oraclemcp-*` workspace packages share one version). The `oracledb` /
`oracledb-protocol` driver pins are exact `=X.Y.Z` pins on the **separately
versioned** driver release train (currently `=0.8.3`); the sync check verifies
each driver pin against the driver's own version, not the workspace version.

| Surface | Path / check |
| --- | --- |
| Workspace driver pins | `Cargo.toml` (`oracledb`, `oracledb-protocol` `=version`) |
| Crate manifests | `crates/oraclemcp-*/Cargo.toml` (`version =`) |
| Lockfile | `Cargo.lock` (workspace crates + `oracledb` + `oracledb-protocol`) |
| Driver seam pin test | `crates/oraclemcp-db/src/connection.rs` (`pin_is_0_8_2_and_seam_intact` asserts the `=version`) |
| Dependency provenance docs/comments | `AGENTS.md`, `README.md`, `.github/workflows/ci.yml`, `docs/operations.md`, `docs/TOOLCHAIN.md`, `docs/adr/0001-pinned-nightly-toolchain.md`, `docs/behavior-inventory.md`, `Cargo.toml`, `crates/oraclemcp-core/src/capability.rs`, `crates/oraclemcp-db/src/tns.rs`, `crates/oraclemcp-core/tests/fixtures/wallet/PROVENANCE.md` |
| MCP registry | `server.json` (`version`, OCI `ghcr.io/muhdur/oraclemcp:version`) |
| Dashboard npm | `web/package.json`, `web/package-lock.json` (root + `packages[""]`) |
| Changelog | `CHANGELOG.md` (`## [version]`) |
| Operator UI fixture | `tests/fixtures/ui/operator-v1/health.json` (`data.liveness.version`) |
| Stdio goldens | `tests/golden/stdio/*.json` (`serverInfo.version`) |
| Dashboard SBOM | `web/dist/oraclemcp-dashboard.cyclonedx.json` (metadata purl @version) |

## Version-agnostic install-example surfaces (NOT workspace-pinned)

The user-facing install and pull examples intentionally track the **latest
published** release, not the in-development workspace version, so a fresh clone of
`main` never tells a user to fetch an unpublished version. These are deliberately
**excluded** from the sync inventory above:

- `README.md` — the `curl … | install.sh` install one-liner and `self-update`
  examples omit `--version` (installer defaults to `latest`); the `docker run`
  examples use `ghcr.io/muhdur/oraclemcp:latest`, and the PL/SQL variant uses
  `:plsql-intelligence-latest`. Air-gapped/offline examples keep an illustrative
  pinned version because they install a specific downloaded archive.
- `install.sh` — the `--version` help text uses a stable `X.Y.Z` placeholder.
- `docs/operations.md` — `docker run` "try it" examples use `:latest`; the
  production Kubernetes sketch shows a pinned `:X.Y.Z` placeholder.
- `docs/hardening.md` — the "pin to an immutable tag" checklist item shows a
  pinned `:X.Y.Z` placeholder (never `:latest`).

`release_preflight.sh` still guards against a **stale hardcoded numeric** image
tag, but only in source / workflow / manifest surfaces (`server.json`,
`crates/oraclemcp/src`, `.github/workflows`, `Dockerfile`) — the install-example
docs above are no longer scanned, since a moving `:latest` / placeholder tag
there is correct by design.

Note: `README.md`, `docs/operations.md`, and the workflow/manifest files still
appear in the inventory table's driver-provenance row — that row tracks the
pinned **driver** version string (e.g. `oracledb 0.8.3`), which is unrelated to
these install-example tags.
