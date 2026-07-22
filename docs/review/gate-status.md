# Gate Status (Measured at Clean Worktree HEAD)

Measurement run on: `2026-07-22 18:32:00+02:00` (operator-requested full 9-gate sweep)
Branch: `main`
Git HEAD: `ebb87123` (`ci: make dashboard SBOM generation install deps deterministically`)
Worktree: `/tmp/oraclemcp-gate-measure-1784737421` (detached `HEAD ebb87123`)
Target dir: `/home/durakovic/projects/oraclemcp-gate-target/ci-gate-ebb87123` (disk-backed, per-agent)

Each step was executed with 30-minute bounded run; workspace-wide commands used
`build_lease` and did not stop on earlier failures.

## Command results

| Command | Exit | Verdict | Notes |
| --- | --- | --- | --- |
| `cargo fmt --all -- --check` | 0 | PASS | Formatting check clean. |
| `./scripts/build_lease.sh -- cargo clippy --workspace --all-targets -- -D warnings` | 0 | PASS | Completed with active lease. |
| `./scripts/build_lease.sh -- cargo test --workspace` | 0 | PASS | Entire workspace test suite passed. |
| `cargo deny check` | 0 | PASS | Exits 0; advisory/allow-list has existing non-blocking warnings. |
| `./scripts/oraclemcp_agent_surface_lint.sh` | 0 | PASS | No agent surface violations. |
| `./scripts/oraclemcp_driver_seam_lint.sh` | 0 | PASS | Driver usage remains confined to expected seam. |
| `./scripts/oraclemcp_honesty_grep.sh` | 1 | **FAIL** | Expected by operator policy; 18 forbidden over-claiming occurrences. This is an honesty policy decision point, not a test infra failure. |
| `./scripts/oraclemcp_api_lock.sh` | 0 | PASS | `oraclemcp-error`, `oraclemcp-guard`, `oraclemcp-db` API surfaces match baselines. |
| `./scripts/release_surface_sync_check.sh` | 0 | PASS | Completed successfully in this clean worktree. |

## Honesty-grep failure summary

- 18 forbidden occurrences, including entries re-quoted in `docs/review/round1-p9.md`.
- Failure originates from over-claiming framing (e.g., `"safe-by-default"`, `"fully audited"`) in `docs/plan/PLAN_0_4_0_PRODUCTION_HARDENING.md` and `docs/plan/PLAN_0_6_0_INTERACTIVE_ALWAYS_ON.md`, with some counted via review artifacts.

## Net verdict

Measured gate status: **8/9 PASS, 1/9 EXPECTED FAIL (honesty-grep policy hold)**.
