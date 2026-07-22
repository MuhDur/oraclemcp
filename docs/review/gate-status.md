# Gate Status At Committed HEAD

- Recorded: 2026-07-22 15:56 Europe/Vienna
- HEAD checked: `0cdc76a217f867c3c77a3bae8addf62542f2cb55`
- Clean worktree: `/var/tmp/oraclemcp-green-gate-0cdc76a-p5`
- Target dir: `/var/tmp/oraclemcp-green-gate-0cdc76a-p5-target`
- Scope: verdict-gathering only; no push performed.

## Verdicts

| Gate | Bound | Verdict | Evidence |
| --- | ---: | --- | --- |
| `cargo fmt --all -- --check` | 300s | PASS | Exited 0. |
| `scripts/build_lease.sh -- cargo clippy --workspace --all-targets -- -D warnings` | 1800s | PASS | Exited 0 under build lease; finished in 2m 22s. |
| `scripts/build_lease.sh -- cargo test --workspace` | 1800s | FAIL | Exited 101 under build lease. Failing test: `tests::embedded_installers_match_repo_root` in `oraclemcp --bin oraclemcp`; assertion says `crates/oraclemcp/install.ps1` drifted from repo-root `install.ps1`. |
| `cargo deny check` | 900s | PASS | Exited 0. Warnings only: unmatched license/advisory allowances; deny summary: advisories ok, bans ok, licenses ok, sources ok. |
| `bash scripts/oraclemcp_agent_surface_lint.sh` | 300s | PASS | Exited 0: `call_routine` absent from agent-facing surfaces. |
| `bash scripts/oraclemcp_driver_seam_lint.sh` | 300s | PASS | Exited 0: all `oracledb::` driver paths confined to `crates/oraclemcp-db/src/connection.rs`. |
| `bash scripts/oraclemcp_honesty_grep.sh` | 300s | FAIL | Exited 1: 9 forbidden-framing occurrences, all reported in `docs/plan/PLAN_0_4_0_PRODUCTION_HARDENING.md`. |
| `bash scripts/oraclemcp_api_lock.sh` | 300s | PASS | Exited 0 with dedicated `CARGO_TARGET_DIR`; locked public API surfaces match baselines for `oraclemcp-error`, `oraclemcp-guard`, and `oraclemcp-db`. |
| `bash scripts/release_surface_sync_check.sh` | 300s | FAIL | Exited 1: missing dashboard SBOM at `web/dist/oraclemcp-dashboard.cyclonedx.json`. |

## Notes

- The shared checkout was dirty with peer in-flight files, so these gates ran from the clean detached worktree above at committed HEAD.
- The initial API-lock attempt omitted `CARGO_TARGET_DIR` and was correctly refused by the build guard for trying to use `/home/durakovic/.cache/cargo-target`; the recorded verdict is from the corrected rerun with the dedicated target dir.
- The workspace test was not rerun after the failure. A bounded single-test probe confirmed the named failure and assertion text.
