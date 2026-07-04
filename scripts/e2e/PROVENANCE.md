# E2E Harness Fixture Provenance

The base harness has no external golden fixtures. It wraps in-repository Rust
tests and live-Oracle scripts from this checkout.

Current generated evidence:

| Artifact | Generator | Version source | Command |
|----------|-----------|----------------|---------|
| JSON-line script contract | `scripts/e2e/lib.sh` | current git checkout | `bash scripts/e2e/run_all.sh --log --dry-run` |
| Curated feature-powerset CI | `cargo-hack` | current git checkout | `bash scripts/oraclemcp_feature_powerset.sh` |
| Architecture fitness dependency lint | `cargo metadata --locked --no-deps` | current git checkout | `bash scripts/oraclemcp_arch_fitness_lint.sh` |
| Doctor fixture/accounting gate | `crates/oraclemcp-core/src/doctor.rs` | current git checkout | `bash scripts/e2e/doctor_fixtures.sh --log` |
| Agent ergonomics drift guard | `crates/oraclemcp/src/main.rs` | current git checkout | `bash scripts/oraclemcp_ergonomics_lint.sh` |
| Release acceptance CI suite | `scripts/release_acceptance_ci_suite.sh` | current git checkout | `bash scripts/release_acceptance_ci_suite.sh --log --dry-run` |
| Rollback runbook dry-run | `scripts/e2e/release_rollback_dry_run.sh` | current git checkout | `bash scripts/e2e/release_rollback_dry_run.sh --log --dry-run` |
| WP-G hardening acceptance suite | `scripts/e2e/hardening_acceptance.sh` | current git checkout | `bash scripts/e2e/hardening_acceptance.sh --log` |
| Offline stdio protocol coverage | `crates/oraclemcp/tests/e2e_stdio.rs` | current git checkout | `cargo test -p oraclemcp --test e2e_stdio -- --nocapture` |
| Offline HTTP OAuth/lane coverage | `crates/oraclemcp/tests/e2e_http_oauth.rs` | current git checkout | `cargo test -p oraclemcp --test e2e_http_oauth -- --nocapture` |
| Read-only dashboard acceptance gate | `scripts/e2e/dashboard_readonly.sh` | current git checkout | `bash scripts/e2e/dashboard_readonly.sh --log` |
| Audit append/hash-chain coverage | `crates/oraclemcp-audit` tests | current git checkout | `cargo test -p oraclemcp-audit concurrent_appends_keep_one_valid_chain -- --nocapture` |
| Live Oracle coverage | `crates/oraclemcp-db/tests/live_oracle.rs` | `ORACLEMCP_TEST_*` test database | `cargo test -p oraclemcp-db --features live-xe --test live_oracle -- --nocapture` |
| Live load/soak coverage | `crates/oraclemcp-db/tests/load_soak.rs` | `ORACLEMCP_TEST_*` test database with `ORACLEMCP_LIVE_XE=1` | `cargo test -p oraclemcp-db --test load_soak live_xe_load_soak_pool_accounting_and_latency -- --ignored --nocapture` |
| Live multi-lane DB coverage | `crates/oraclemcp-db/tests/multi_lane_live_xe.rs` | `ORACLEMCP_TEST_*_A/B` test databases with `ORACLEMCP_MULTI_DB_LIVE_XE=1` | `cargo test -p oraclemcp-db --features live-xe --test multi_lane_live_xe -- --ignored --nocapture` |
| G6 live-XE headline service attach | `scripts/e2e/live_xe_headline.sh`, `crates/oraclemcp/tests/live_xe_service_attach.rs` | `ORACLEMCP_TEST_*` plus multi-DB and contention gates | `bash scripts/e2e/live_xe_headline.sh --log` |
| Oracle version-matrix operating-level ladder | `scripts/e2e/oracle_version_matrix.sh`, `scripts/e2e/oracle_ladder_session.py` | Three throwaway lab lanes (gvenzl XE 18 / XE 21 / FREE 23ai) with `ORACLEMCP_LIVE_XE=1` and `ORACLE_MATRIX_*` lane credentials | `bash scripts/e2e/oracle_version_matrix.sh --log` |
| H5 clean-machine e2e | `scripts/e2e/clean_machine_e2e.sh`, `crates/oraclemcp/tests/clean_machine_e2e.rs` | Rebooted clean-machine sandbox with an already-running user service, loopback dashboard pairing, per-agent bearers or explicit allow-no-auth, and two live test/free/xe/local DB profiles | `bash scripts/e2e/clean_machine_e2e.sh --log` |
