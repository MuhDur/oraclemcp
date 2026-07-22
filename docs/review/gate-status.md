# Gate Status At Committed HEAD

- Recorded: 2026-07-22T17:16:42+02:00
- HEAD checked: `beedfff3`
- Clean worktree: `/tmp/oraclemcp-gate-full` at `HEAD beedfff3`
- Target dir: `/var/tmp/oraclemcp-gate-full-target`
- Scope: verdict-gathering only; no push performed.

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

## Notes

- The run used a dedicated clean worktree at `beedfff3` because shared checkout is currently dirty with peer edits.
