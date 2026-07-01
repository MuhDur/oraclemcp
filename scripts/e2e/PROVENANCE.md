# E2E Harness Fixture Provenance

The base harness has no external golden fixtures. It wraps in-repository Rust
tests and live-Oracle scripts from this checkout.

Current generated evidence:

| Artifact | Generator | Version source | Command |
|----------|-----------|----------------|---------|
| JSON-line script contract | `scripts/e2e/lib.sh` | current git checkout | `bash scripts/e2e/run_all.sh --log --dry-run` |
| Doctor fixture/accounting gate | `crates/oraclemcp-core/src/doctor.rs` | current git checkout | `bash scripts/e2e/doctor_fixtures.sh --log` |
| Offline stdio protocol coverage | `crates/oraclemcp/tests/e2e_stdio.rs` | current git checkout | `cargo test -p oraclemcp --test e2e_stdio -- --nocapture` |
| Offline HTTP OAuth/lane coverage | `crates/oraclemcp/tests/e2e_http_oauth.rs` | current git checkout | `cargo test -p oraclemcp --test e2e_http_oauth -- --nocapture` |
| Read-only dashboard acceptance gate | `scripts/e2e/dashboard_readonly.sh` | current git checkout | `bash scripts/e2e/dashboard_readonly.sh --log` |
| Audit append/hash-chain coverage | `crates/oraclemcp-audit` tests | current git checkout | `cargo test -p oraclemcp-audit concurrent_appends_keep_one_valid_chain -- --nocapture` |
| Live Oracle coverage | `crates/oraclemcp-db/tests/live_oracle.rs` | `ORACLEMCP_TEST_*` test database | `cargo test -p oraclemcp-db --features live-xe --test live_oracle -- --nocapture` |
| Live load/soak coverage | `crates/oraclemcp-db/tests/load_soak.rs` | `ORACLEMCP_TEST_*` test database with `ORACLEMCP_LIVE_XE=1` | `cargo test -p oraclemcp-db --test load_soak live_xe_load_soak_pool_accounting_and_latency -- --ignored --nocapture` |
