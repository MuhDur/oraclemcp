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
| Conformance accounting documents XFAIL policy and fixture provenance. | MUST | `scripts/e2e/COVERAGE.md`, `scripts/e2e/DISCREPANCIES.md`, `scripts/e2e/PROVENANCE.md`, `tests/conformance/COVERAGE.md`, `tests/conformance/DISCREPANCIES.md`, `tests/golden/PROVENANCE.md` | PASS |

| Summary | MUST total | Tested | Passing | XFAIL | Score |
|---------|------------|--------|---------|-------|-------|
| MUST coverage | 6 | 6 | 6 | 0 | 1.00 |

## Scenario Acceptance Gates

| Scenario | Release bead | Covered by | Status |
|----------|--------------|------------|--------|
| Curated feature-powerset CI | `oraclemcp-epic-060-f4xo.12.10` | `scripts/oraclemcp_feature_powerset.sh`, `.github/workflows/ci.yml` | PASS |
| Architecture fitness dependency lint | `oraclemcp-epic-060-f4xo.12.11` | `scripts/oraclemcp_arch_fitness_lint.sh`, `.github/workflows/ci.yml` | PASS |
| Doctor fixture/accounting gate | `oraclemcp-epic-060-f4xo.12.12` | `scripts/e2e/doctor_fixtures.sh`, `crates/oraclemcp-core/src/doctor.rs::tests::doctor_fix_fixture_gate_current_repairs_are_fixture_accounted` | PASS |
| Agent ergonomics drift guard | `oraclemcp-epic-060-f4xo.12.9` | `scripts/oraclemcp_ergonomics_lint.sh`, `.github/workflows/ci.yml`, `crates/oraclemcp/src/main.rs::tests::agent_ergonomics_drift_guard_*` | PASS |
| Release acceptance CI suite | `oraclemcp-epic-060-f4xo.12.13` | `scripts/release_acceptance_ci_suite.sh`, `.github/workflows/ci.yml`, `.github/workflows/release.yml` | PASS |
| 0.6.0 read-only dashboard | `oraclemcp-epic-060-f4xo.8.26` | `scripts/e2e/dashboard_readonly.sh`, `crates/oraclemcp/tests/dashboard_e2e.rs` | PASS |
| WP-W B.8 dashboard acceptance suite | `oraclemcp-epic-060-f4xo.8.20` | `crates/oraclemcp/tests/dashboard_e2e.rs`, `crates/oraclemcp-core/src/http.rs`, `scripts/e2e/dashboard_readonly.sh`, `scripts/dashboard_bundle_check.sh`, `scripts/dashboard_skin_lint.sh`, `scripts/sensitive_data_lint.sh` | PASS |
| W9 read-only health/stats mirror | `oraclemcp-epic-060-f4xo.8.11` | `crates/oraclemcp/tests/dashboard_e2e.rs::w9_read_only_health_stats_mirror_is_flag_gated`, `web/src/app/App.tsx::HealthPage`, `web/src/app/App.tsx::CapacityPage`, `web/src/app/operator-client.ts::fetchOperatorHealth`, `web/src/app/operator-client.ts::fetchOperatorMetrics`, `crates/oraclemcp-core/src/http.rs::tests::operator_v1_serves_schema_health_events_and_action_mapping` | PASS |
| WD-Search global database search | `oraclemcp-epic-060-f4xo.8.17` | `web/src/app/App.tsx`, `web/src/app/operator-client.ts`, `crates/oraclemcp/tests/dashboard_e2e.rs::wd_search_global_explorer_uses_guarded_dictionary_tools` | PASS |
| WD-History source snapshots and revert | `oraclemcp-epic-060-f4xo.8.18` | `crates/oraclemcp-core/src/http.rs::tests::source_history_snapshots_prior_source_and_revert_drafts_review_proposal`, `crates/oraclemcp-core/src/source_history.rs::tests::list_views_exclude_source_text`, `crates/oraclemcp/tests/dashboard_e2e.rs::wd_history_source_snapshots_and_revert_are_review_gated`, `web/src/app/App.tsx::SourceHistoryPanel`, `web/src/app/operator-client.ts::fetchSourceHistory` | PASS |
| WD-Diff schema diff + migration export | `oraclemcp-epic-060-f4xo.8.21` | `crates/oraclemcp-core/src/http.rs::tests::schema_diff_export_is_redacted_and_review_gated`, `crates/oraclemcp-core/src/schema_diff_export.rs`, `crates/oraclemcp/tests/dashboard_e2e.rs::wd_diff_schema_diff_exports_migration_through_reviews`, `web/src/app/App.tsx::SchemaDiffPanel`, `web/src/app/operator-client.ts::previewSchemaDiff` | PASS |
| W8b proof bundle for gated actions | `oraclemcp-epic-060-f4xo.8.10` | `crates/oraclemcp-core/src/http.rs::tests::audit_tail_filters_exports_redacted_proof_bundle`, `crates/oraclemcp/tests/dashboard_e2e.rs::w8b_proof_bundle_is_redacted_and_exportable`, `web/src/app/App.tsx::AuditProofBundlePanel`, `web/src/app/operator-client.ts::fetchAuditTail` | PASS |
| W10 client-credentials dashboard | `oraclemcp-epic-060-f4xo.8.12` | `crates/oraclemcp-core/src/http.rs::tests::operator_client_credentials_screen_lists_rotates_revokes_without_token_leak`, `crates/oraclemcp/tests/dashboard_e2e.rs::w10_client_credentials_screen_is_redacted_and_isolated`, `web/src/app/App.tsx::ClientsPage`, `web/src/app/operator-client.ts::fetchClientCredentials` | PASS |
| G6 live-XE headline | `oraclemcp-epic-060-f4xo.11.6` | `scripts/e2e/live_xe_headline.sh`, `crates/oraclemcp-db/tests/multi_lane_live_xe.rs`, `crates/oraclemcp/tests/live_xe_service_attach.rs` | PASS |
