# Gate Status At Committed HEAD

- Recorded: 2026-07-22T17:16:42+02:00 (beedfff3 baseline)
- HEAD checked: `beedfff3` (historical baseline)
- HEAD checked (targeted): `075b5ce6` (dedicated clean worktree)
- Clean worktree: `/tmp/oraclemcp-gate-full` at `HEAD beedfff3`
- Targeted clean worktree: `/home/durakovic/projects/oraclemcp-gate-check-ov3WDk`
- Target dir: `/home/durakovic/projects/oraclemcp-gate-check-ov3WDk/target/ci-gate`
- Scope: full 9-gate baseline at beedfff3, targeted rerun at 075b5ce6 for two user-requested gates only.

## Verdicts

Each command was executed under a bounded timeout (1800s, with heavy commands
still taking `scripts/build_lease.sh`).

| Command | Verdict | Failure detail |
| --- | --- | --- |
| `cargo fmt --all -- --check` | PASS | Exited 0. |
| `scripts/build_lease.sh -- cargo clippy --workspace --all-targets -- -D warnings` | PASS | Exited 0 under lease (target guard passed). |
| `scripts/build_lease.sh -- cargo test --workspace` | **FAIL** | Exited 101 under lease. Failing test: `oracle_query_structured_content_matches_advertised_output_schema_fields` in `crates/oraclemcp/tests/e2e_stdio.rs:341`. Panic: `structuredContent must include required outputSchema field columns`. |
| `cargo deny check` | PASS | Exited 0. Warnings only for unmatched deny.toml allowances (`MIT-0`, `MPL-2.0`, `UPL-1.0`, `Unicode-DFS-2016`, `BSL-1.0`, and stale RustSec entries). |
| `bash scripts/oraclemcp_agent_surface_lint.sh` | PASS | Exited 0. |
| `bash scripts/oraclemcp_driver_seam_lint.sh` | PASS | Exited 0. |
| `bash scripts/oraclemcp_honesty_grep.sh` | **FAIL** | Exited 1. 18 over-claiming occurrences (expected per current branch policy; mostly `docs/plan/PLAN_0_4_0_PRODUCTION_HARDENING.md` and review artifacts). |
| `bash scripts/oraclemcp_api_lock.sh` | PASS | Exited 0 with dedicated target dir; all three locked crates (`oraclemcp-error`, `oraclemcp-guard`, `oraclemcp-db`) match baselines. |
| `bash scripts/release_surface_sync_check.sh` | PASS | Exited 0. |

### 075b5ce6 targeted rerun (requested gates)

| Command | Verdict | Failure detail |
| --- | --- | --- |
| `scripts/build_lease.sh -- cargo test --workspace` | **FAIL** | Failed 3 tests in `crates/oraclemcp/tests/golden_behavior.rs`: `golden_stdio_query_export_resource_and_resource_link`, `golden_stdio_query_opaque_cursor_pagination`, `golden_stdio_main_tool_transcript`. |
| `bash scripts/release_surface_sync_check.sh` | **FAIL** | npm SBOM step missing frontend dependencies (for example `@tanstack/react-query@5.101.2`, `react@19.2.7`, `vite@8.1.2`). |

## Notes

- The run used a dedicated clean worktree at `beedfff3` because shared checkout is currently dirty with peer edits.
- The targeted rerun used `/home/durakovic/projects/oraclemcp-gate-check-ov3WDk` at `HEAD 075b5ce6` and did not re-run the other seven baseline gates because their last run at beedfff3 is unchanged.
