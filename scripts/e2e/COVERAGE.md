# oraclemcp E2E Harness Coverage

This file accounts for the test-harness standard in bead
`oraclemcp-epic-060-f4xo.11.15`. Scenario-specific acceptance beads should add
their own rows or generated reports instead of replacing this base contract.

| Requirement | Level | Covered by | Status |
|-------------|-------|------------|--------|
| Script JSON-line events carry `event`, `phase`, `ts`, `duration_ms`, `lane`, `subject`, `sid`, `profile`, `level`, `grant`, and `outcome`. | MUST | `scripts/e2e/lib.sh`, `crates/oraclemcp/tests/e2e_harness.rs` | PASS |
| Top-level orchestrator runs scenarios in order and aggregates pass/fail/skipped status. | MUST | `scripts/e2e/run_all.sh`, `crates/oraclemcp/tests/e2e_harness.rs` | PASS |
| Failure handling emits a CRASHPACK path and replay SEED. | MUST | `scripts/e2e/lib.sh`, `crates/oraclemcp/tests/e2e_harness.rs` | PASS |
| Live Oracle scenarios are env-gated and refuse production-looking targets. | MUST | `scripts/e2e/live_oracle.sh`, `scripts/e2e/load_soak.sh`, `crates/oraclemcp/tests/e2e_harness.rs` | PASS |
| The harness adds no script-level mocks; Score-at-least-8 acceptance beads must use live-Oracle or real-file scenarios. | MUST | `scripts/e2e/audit_append.sh`, `scripts/e2e/live_oracle.sh`, `scripts/e2e/load_soak.sh`, this coverage rule | PASS |
| Conformance accounting documents XFAIL policy and fixture provenance. | MUST | `scripts/e2e/COVERAGE.md`, `scripts/e2e/DISCREPANCIES.md`, `scripts/e2e/PROVENANCE.md` | PASS |

| Summary | MUST total | Tested | Passing | XFAIL | Score |
|---------|------------|--------|---------|-------|-------|
| MUST coverage | 6 | 6 | 6 | 0 | 1.00 |

## Scenario Acceptance Gates

| Scenario | Release bead | Covered by | Status |
|----------|--------------|------------|--------|
| 0.6.0 read-only dashboard | `oraclemcp-epic-060-f4xo.8.26` | `scripts/e2e/dashboard_readonly.sh`, `crates/oraclemcp/tests/dashboard_e2e.rs` | PASS |
