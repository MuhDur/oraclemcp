# Release version surfaces (D3.1 audit)

Every file below must carry the **same** workspace release version before a tag is cut.
`scripts/release_surface_sync_check.sh` enforces this inventory mechanically;
`scripts/release_preflight.sh` and `scripts/release_acceptance_ci_suite.sh` call it on every release gate run. For drift drills only, `ORACLEMCP_RELEASE_SURFACE_SYNC_HEALTH_PATH` overrides the operator health fixture path (see `release_surface_drift_fails_fast` in `crates/oraclemcp/tests/e2e_harness.rs`).

The expected version is always read from `cargo metadata` (all nine `oraclemcp-*`
workspace packages share one version). The driver exact pins (`oracledb`,
`oracledb-protocol`) must match that version as `=X.Y.Z`.

| Surface | Path / check |
| --- | --- |
| Workspace driver pins | `Cargo.toml` (`oracledb`, `oracledb-protocol` `=version`) |
| Crate manifests | `crates/oraclemcp-*/Cargo.toml` (`version =`) |
| Lockfile | `Cargo.lock` (workspace crates + `oracledb` + `oracledb-protocol`) |
| Driver seam pin test | `crates/oraclemcp-db/src/connection.rs` (`pin_is_0_7_*` asserts `=version`) |
| MCP registry | `server.json` (`version`, OCI `ghcr.io/muhdur/oraclemcp:version`) |
| Dashboard npm | `web/package.json`, `web/package-lock.json` (root + `packages[""]`) |
| npm wrapper | `npm/oraclemcp/package.json` |
| Changelog | `CHANGELOG.md` (`## [version]`) |
| Install help | `install.sh` (`e.g. version or vversion`) |
| README OCI | `README.md` (`ghcr.io/muhdur/oraclemcp:version`) |
| Operator UI fixture | `tests/fixtures/ui/operator-v1/health.json` (`data.liveness.version`) |
| Stdio goldens | `tests/golden/stdio/*.json` (`serverInfo.version`) |
| Dashboard SBOM | `web/dist/oraclemcp-dashboard.cyclonedx.json` (metadata purl @version) |

Stale **versioned** Docker image references in release-visible paths are still
caught by `release_preflight.sh` (separate from this inventory).