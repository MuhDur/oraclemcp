# Coverage baseline

**Generated, not hand-authored.** Regenerate with `bash scripts/coverage_baseline.sh` (heavy, instrumented; Tier 2 / nightly, not per-PR -- see `docs/test-tiers.md`). Do not hand-edit this file or `BASELINE.json`.

- Generated at: `2026-07-19T22:09:34Z`
- Git SHA: `4b46e87bb874427f1f117b38bbeec39a1c2f790f`
- Tool: `cargo-llvm-cov 0.8.7`
- Command: `cargo llvm-cov --workspace --locked --summary-only --json --output-path /tmp/tmp.Ygxp5Xqror/raw-llvm-cov.json`
- Scope: oraclemcp workspace (crates/*); the driver, rust-oracledb, is a separate repo and needs its own baseline, features=default
- Excluded: live-xe, plsql-intelligence, doctests
- Unit: source lines/regions/functions under crates/*/src (cargo-llvm-cov's own workspace scoping; integration tests, fuzz targets, and dependencies are not instrumented)

This is bead D1 (plan §30.2): an EMPIRICAL baseline only. There is no ratchet or gate here yet -- that is bead D2 (changed-line coverage plus a per-crate mutation floor on guard/audit/db, not a naive never-decrease global line; plan §32.2 TRI-1).

## Workspace total

| Metric | Covered | Total | Percent |
| --- | ---: | ---: | ---: |
| lines | 100749 | 113616 | 88.68% |
| regions | 145265 | 162988 | 89.13% |
| functions | 8637 | 10063 | 85.83% |

## Per crate

| Crate | Line % | Lines | Region % | Regions | Function % | Functions |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| oraclemcp | 77.25% | 18736/24255 | 78.34% | 26101/33318 | 72.7% | 1294/1780 |
| oraclemcp-audit | 97.07% | 8628/8888 | 97.28% | 13918/14307 | 94.7% | 643/679 |
| oraclemcp-auth | 95.02% | 1317/1386 | 93.97% | 2165/2304 | 96.63% | 172/178 |
| oraclemcp-config | 96.05% | 4765/4961 | 95.77% | 6052/6319 | 97.26% | 390/401 |
| oraclemcp-core | 91.87% | 38920/42365 | 92.11% | 57647/62582 | 88.63% | 3266/3685 |
| oraclemcp-db | 85.18% | 16663/19563 | 85.17% | 23007/27012 | 80.7% | 1811/2244 |
| oraclemcp-error | 97.93% | 474/484 | 98.1% | 721/735 | 98.11% | 52/53 |
| oraclemcp-guard | 97.27% | 8928/9179 | 96.89% | 12239/12632 | 98.44% | 757/769 |
| oraclemcp-telemetry | 91.59% | 2264/2472 | 90.46% | 3347/3700 | 91.88% | 249/271 |
| oraclemcp-verifier | 85.71% | 54/63 | 86.08% | 68/79 | 100.0% | 3/3 |
