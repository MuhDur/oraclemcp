## [HIGH] SEC-6 close evidence binds the wrong source commit
- Where: tests/artifacts/evidence/closes/oraclemcp-yxg1u.json:21
- Claim checked: SEC-6 close evidence for uniform OAuth rejection must bind to the commit containing the OAuth auth-oracle fix.
- Method: `git show --stat --name-status 3719ed8d dc092cdc` and `sed -n '1,120p' tests/artifacts/evidence/closes/oraclemcp-yxg1u.json`.
- Verdict: CONFIRMED DEFECT - evidence source `3719ed8d` is the synthetic TCPS lane; the OAuth implementation is `dc092cdc`.

## [MEDIUM] C6 classifier close evidence binds a later metadata commit
- Where: tests/artifacts/evidence/closes/oraclemcp-eng-program-bp8ia.4.6.4.json:21
- Claim checked: C6 classifier split evidence should bind to the classifier split that preserves fail-closed behavior.
- Method: `git show --stat --name-status 984de104 b233fff0` and `nl -ba tests/artifacts/evidence/closes/oraclemcp-eng-program-bp8ia.4.6.4.json | sed -n '1,140p'`.
- Verdict: CONFIRMED DEFECT - `source.sha` is `984de104`, while the classifier split is `b233fff0`; the evidence prose names the real implementation SHA, so the proof boundary is honest but the machine-readable source is wrong.

## [MEDIUM] Multiple closes use tracker/evidence SHAs as source commits
- Where: b514ee3c, 56994f4a, a6e5cea5, 332c2c65
- Claim checked: Close evidence should bind to a commit that contains the claimed implementation or proof.
- Method: `git show --stat --name-status b514ee3c 56994f4a a6e5cea5 332c2c65 5e1aca16 ae3aed82 b5736dce fb7c093e 4e6a95ea d6aafc64` and sampled JSON under `tests/artifacts/evidence/closes/`.
- Verdict: CONFIRMED DEFECT - B12c/jjtrc, B14b, P2-8/20cw3, and D10 evidence files use tracker/evidence/bookkeeping commits as `source.sha`; sampled live/proof claims were otherwise bounded honestly.

## [LOW] Historical plan docs retain stale lease/session references
- Where: docs/plan/PLAN_0_6_0_INTERACTIVE_ALWAYS_ON.md; docs/plan/PLAN_ASUPERSYNC_THIN_NATIVE.md
- Claim checked: B14b removed the dead lease subsystem and no reachable core resource surface remains.
- Method: `test ! -e crates/oraclemcp-db/src/lease.rs`, `test ! -e crates/oraclemcp-core/src/session_tool.rs`, exact-name `rg` for lease/session resource strings, `cargo test -p oraclemcp-core --lib resources -- --nocapture`, and `cargo test -p oraclemcp-core --test mcp_conformance resources -- --nocapture`.
- Verdict: CONFIRMED DEFECT - runtime reachability is clean, but historical planning text still mentions deleted lease/session files.

## [LOW] Core test helpers triggered clippy type-complexity warnings
- Where: 3934cde6
- Claim checked: The core lane should remain clippy-clean after the TCPS/IAM test helper work.
- Method: `cargo clippy -p oraclemcp-core --all-targets -- -D warnings`.
- Verdict: CONFIRMED DEFECT - fixed in `3934cde6` with local test-helper type aliases; rerun passed.

## [LOW] Full workspace formatting was blocked by unrelated dirty dispatch work
- Where: crates/oraclemcp/src/dispatch/mod.rs; crates/oraclemcp/src/dispatch/orient.rs
- Claim checked: Whole-workspace formatting status after the core review fix.
- Method: `cargo fmt --all -- --check` and `git status --short`.
- Verdict: UNPROVEN - full formatting could not be credited to this lane because unrelated live dispatch/orient work was dirty; core-scoped formatting and clippy checks passed.

## [CLEAN] Doctor redaction survived the doctor split
- Where: b0833a8c; ed55693e
- Claim checked: Doctor output must omit connect strings, usernames, credential_ref values, passwords, proxy identities, wallet passwords, IAM tokens, wallet paths, and server DNs.
- Method: `cargo test -p oraclemcp-core doctor::tests::auth_capability_matrix_is_thin_and_redaction_safe -- --exact`, `cargo test -p oraclemcp-core redacts`, and `cargo test -p oraclemcp-core --test doctor_secret_golden`.
- Verdict: CLEAN - targeted doctor redaction tests passed.

## [CLEAN] Custom-tool skip-and-warn does not silently admit security failures
- Where: 5e1aca16; ae3aed82
- Claim checked: Malformed/config-quality custom tools skip and warn, while over-ceiling, forbidden, and tampered-signature tools refuse startup.
- Method: `cargo test -p oraclemcp custom_tool_loader_ -- --nocapture`, `cargo test -p oraclemcp-core skipped_custom_tools -- --nocapture`, and `cargo test -p oraclemcp-core custom_tools -- --nocapture`.
- Verdict: CLEAN - scoped loader tests passed; security-critical custom-tool failures remain refusals.

## [CLEAN] Deleted lease subsystem is not reachable at runtime
- Where: b5736dce; fb7c093e
- Claim checked: B14b deletion removed the dead lease/session subsystem from the served core surface.
- Method: `test ! -e crates/oraclemcp-db/src/lease.rs`, `test ! -e crates/oraclemcp-core/src/session_tool.rs`, exact-name `rg` over runtime resource strings, `cargo test -p oraclemcp-core --lib resources -- --nocapture`, and `cargo test -p oraclemcp-core --test mcp_conformance resources -- --nocapture`.
- Verdict: CLEAN - no served core lease/session resource surface was found.

## [CLEAN] E3 evidence binds to the implementation test commit
- Where: tests/artifacts/evidence/closes/oraclemcp-091-e3-audit-chain-e2e-69bbf.json:17
- Claim checked: E3 close evidence should bind to the commit containing the adversarial audit-chain test suite.
- Method: `git show --stat --name-status e0f319d0 6f1da17c a3fbc7c1 d0263cb2 -- tests/artifacts/evidence/closes/oraclemcp-091-e3-audit-chain-e2e-69bbf.json crates/oraclemcp-audit/tests/e3_audit_chain_e2e.rs` and `br show oraclemcp-091-e3-audit-chain-e2e-69bbf --json`.
- Verdict: CLEAN - source `e0f319d0` actually modifies `crates/oraclemcp-audit/tests/e3_audit_chain_e2e.rs`; close/evidence commits only update evidence metadata.

## [CLEAN] Audit chain detects record tampering and HMAC recompute forgery
- Where: crates/oraclemcp-audit/src/verify.rs; crates/oraclemcp-audit/src/record.rs
- Claim checked: Hash-chained HMAC-SHA256 JSONL must detect in-place tamper and recompute-from-genesis forgery without the key.
- Method: `cargo test -p oraclemcp-audit recompute -- --nocapture`, `cargo test -p oraclemcp-audit hmac -- --nocapture`, and a generated temp-log probe where `oraclemcp audit verify` exited 2 after editing record 2.
- Verdict: CLEAN - recompute/HMAC tests passed and the binary verifier rejected the edited record with `entry_hash does not match the record content`.

## [CLEAN] Audit verify fails on a truncated tail when the anchor survives
- Where: crates/oraclemcp/src/main.rs:5672; crates/oraclemcp-audit/src/anchor.rs:373
- Claim checked: `oraclemcp audit verify` must fail closed on a truncated audit JSONL tail against its `.anchor` sidecar.
- Method: Generated a 3-record signed temp JSONL with `.anchor`, copied the original anchor beside a 2-line truncated JSONL, then ran `ORACLEMCP_AUDIT_KEY=0123456789abcdef0123456789abcdef cargo run -q -p oraclemcp -- --json audit verify <file>` for both files.
- Verdict: CLEAN - intact log exited 0 with `anchor.status=match`; truncated copy exited 2 with `truncated=true`.

## [CLEAN] SEC-3 audit-write failure is fail-closed
- Where: crates/oraclemcp-audit/tests/e3_audit_chain_e2e.rs; crates/oraclemcp-audit/src/sink.rs; crates/oraclemcp/src/dispatch/mod.rs:9067
- Claim checked: Audit write/open failure must stop execution or quarantine instead of allowing unaudited privileged work.
- Method: `cargo test -p oraclemcp-audit --test e3_audit_chain_e2e -- --nocapture`, `cargo test -p oraclemcp-audit anchor -- --nocapture`, `cargo test -p oraclemcp ddl_mutators_resolve_uncertain_evidence_as_aborted_before_execute -- --nocapture`, `cargo test -p oraclemcp cancelled_audit_evidence_preflight_quarantines_before_execute -- --nocapture`, and `cargo test -p oraclemcp commit_in_doubt_remains_primary_when_terminal_audit_also_fails -- --nocapture`.
- Verdict: CLEAN - tests passed; pending audit append is before execution, and terminal audit failure preserves uncertain DB outcome.

## [CLEAN] Unsigned refusal trail does not masquerade as signed audit
- Where: crates/oraclemcp/src/refusal_corpus.rs:50
- Claim checked: The unsigned refusal/security-event corpus must stay distinct from the signed HMAC audit tier.
- Method: `cargo test -p oraclemcp refusal_corpus -- --nocapture`, `cargo test -p oraclemcp signature_rejection -- --nocapture`, and `ORACLEMCP_AUDIT_KEY=0123456789abcdef0123456789abcdef cargo run -q -p oraclemcp -- --json audit verify tests/fixtures/rig/refusal_corpus_baseline.jsonl`.
- Verdict: CLEAN - refusal corpus tests passed; feeding the corpus to `audit verify` exited 2 as malformed audit JSONL rather than verifying as signed audit.

## [HIGH] Doctor RLS/VPD check renders session user
- Where: crates/oraclemcp-core/src/doctor.rs:2356
- Claim checked: Doctor output must omit usernames and proxy identities because operators paste doctor output into agent sessions.
- Method: Code read of `rls_vpd_check_from_observation` plus `CARGO_TARGET_DIR=/home/durakovic/projects/oraclemcp/target cargo test -p oraclemcp-core doctor_rls_vpd_visibility_names_visible_policy -- --nocapture`.
- Verdict: CONFIRMED DEFECT - the passing test at crates/oraclemcp-core/src/doctor.rs:3734 asserts `session_user=ORACLEMCP_D3_SIGHTED` is present in doctor detail; the scrubber only removes values already present in `DoctorContext.sensitive_values`, so live observed session users can be rendered.

## [LOW] Doctor connectivity/auth secret redaction
- Where: crates/oraclemcp-core/src/doctor.rs:3871
- Claim checked: Doctor connectivity and auth diagnostics must not leak connect strings, usernames, credential values, wallet paths/passwords, IAM tokens, server DNs, or proxy identities.
- Method: `CARGO_TARGET_DIR=/home/durakovic/projects/oraclemcp/target cargo test -p oraclemcp-core connection_error_redacts_profile_sensitive_values wallet_decrypt_password_echo_is_redacted iam_token_refresh_failure_redacts_jwt iam_token_check_never_renders_the_token auth_capability_matrix_is_thin_and_redaction_safe -- --nocapture` run as exact per-test filters; also `CARGO_TARGET_DIR=/home/durakovic/projects/oraclemcp/target cargo test -p oraclemcp-core --test doctor_secret_golden -- --nocapture`.
- Verdict: CLEAN - the targeted checks passed and the inspected code routes connectivity details through `sanitized_detail`.

## [LOW] oracle_connection_info redacts identity/topology by default
- Where: crates/oraclemcp/src/dispatch/mod.rs:11315
- Claim checked: `oracle_connection_info` must not leak usernames, proxy identities, connect strings, credential refs, passwords, wallet paths/passwords, IAM tokens, or server DNs.
- Method: Code read of `connection_info_json` / `connection_info_for_transport` plus `CARGO_TARGET_DIR=/home/durakovic/projects/oraclemcp/target cargo test -p oraclemcp connection_info_reports_the_active_profile connection_info_keeps_schema_and_service_redacted_for_remote_transport connection_diagnostics_report_exact_generation_without_config_secrets -- --nocapture` run as exact per-test filters, and `CARGO_TARGET_DIR=/home/durakovic/projects/oraclemcp/target cargo test -p oraclemcp-db connection_info_debug_and_redacted_json_are_allowlist_first debug_redacts_connect_material debug_redacts_session_identity_values -- --nocapture`.
- Verdict: CLEAN - the served tool serializes `OracleConnectionInfo::redacted()`, remote HTTP keeps schema/service redacted, and local transport exposes only `current_schema`/`service_name` while session/proxy/user fields remain absent and listed as redacted.

## [LOW] list_profiles omits profile secrets and topology
- Where: crates/oraclemcp-config/src/profile.rs:1142
- Claim checked: `oracle_list_profiles` / CLI profile listing must not expose connect strings, usernames, credential refs, passwords, proxy identities, wallet passwords, IAM tokens, wallet paths, or server DNs.
- Method: Code read of `ConnectionProfile::metadata`, `OracleMcpConfig::list_profiles`, `ProfileDrainState::mcp_profiles_snapshot`, and `profiles_json`; `CARGO_TARGET_DIR=/home/durakovic/projects/oraclemcp/target cargo test -p oraclemcp profiles_json_reports_non_secret_metadata profile_response_omits_connection_and_secret_material doctor_profile_auth_capabilities_are_metadata_only resolved_secret_material_is_absent_from_rendered_surfaces profile_secret_resolution_errors_do_not_echo_secret_locators -- --nocapture` run as exact per-test filters.
- Verdict: CLEAN - metadata deliberately omits raw connection/profile secret fields and the targeted tests passed.

## [LOW] Auth and dashboard error envelopes avoid credential oracle detail
- Where: crates/oraclemcp-core/src/http/tests_auth.rs:716
- Claim checked: Error envelopes must not reveal why a credential was rejected and must not leak bearer tokens or dashboard pairing secrets.
- Method: `CARGO_TARGET_DIR=/home/durakovic/projects/oraclemcp/target cargo test -p oraclemcp-core uniform_auth_errors_no_enumeration_oracle operator_config_draft_apply_and_rollback_are_redacted_and_audited mcp_post_rate_limit_returns_429_retry_after_and_redacts_principal operator_client_credentials_screen_lists_rotates_revokes_without_token_leak -- --nocapture` run as exact per-test filters; also inspected dashboard 403 assertions at crates/oraclemcp-core/src/http/tests_dashboard.rs:338.
- Verdict: CLEAN - uniform missing/unknown/revoked credential responses match, dashboard config redaction passed, principal buckets are redacted, and credential list/rotate/revoke screens do not return stored bearer material.

## [LOW] MCP tool errors remain structured ErrorEnvelopes
- Where: crates/oraclemcp-error/src/lib.rs:25; crates/oraclemcp-error/src/lib.rs:320; crates/oraclemcp-core/src/server.rs:2753
- Claim checked: Agent-facing errors should be structured ErrorEnvelopes with machine-stable classes rather than bare strings.
- Method: Code read of ErrorClass/ErrorEnvelope rendering plus `CARGO_TARGET_DIR=/home/durakovic/projects/oraclemcp/target cargo test -p oraclemcp-error every_oracle_mcp_error_variant_maps_to_its_documented_class envelope_serde_roundtrip_is_stable structured_reason_roundtrips_and_omits_empty_fields structured_reason_carries_query_cost_refusal_details oracle_message_roundtrips_through_envelope -- --nocapture` run as exact per-test filters, and `CARGO_TARGET_DIR=/home/durakovic/projects/oraclemcp/target cargo test -p oraclemcp-core cancelled_tool_call_returns_timeout_and_quiesces_active_work run_tool_replaces_unadvertised_suggested_tools run_tool_preserves_advertised_suggested_tools -- --nocapture` run as exact per-test filters.
- Verdict: CLEAN - the error type serializes stable classes, MCP tool failures put the envelope in structuredContent, and the targeted tests passed.

## [LOW] Guard refusals stop before Oracle with typed classes and next steps
- Where: crates/oraclemcp/src/dispatch/mod.rs:6490; crates/oraclemcp/src/dispatch/tests.rs:6235; crates/oraclemcp/src/dispatch/tests.rs:6462; crates/oraclemcp/src/dispatch/tests.rs:7996; crates/oraclemcp/src/dispatch/tests.rs:11924
- Claim checked: Forbidden constructs must be refused before reaching Oracle with OperatingLevelTooLow or ForbiddenStatement plus suggested safe alternatives or next steps.
- Method: Code read of `gate_error` plus `CARGO_TARGET_DIR=/home/durakovic/projects/oraclemcp/target cargo test -p oraclemcp refused_write_with_inline_literal_gets_a_parameterization_hint write_needs_higher_level_with_minimal_rewrite multi_statement_batch_suggests_splitting dynamic_sql_has_category_but_no_minimal_rewrite served_gate_refuses_parenless_qualified_callable raw_query_cannot_claim_the_local_embedding_exception served_read_gate_refuses_view_policy_and_zero_arg_function_before_evaluation guard_refusal_appends_only_a_redacted_classifier_proven_corpus_record explicit_refusal_trail_opt_out_keeps_the_guard_refusal_without_a_record writes_ddl_and_dcl_are_refused_before_touching_the_db malformed_and_unauthorized_sql_are_refused_before_any_db_io sequence_nextval_is_refused_by_oracle_query_before_any_db_io caller_transaction_control_is_refused_before_database_io opaque_plsql_calls_are_refused_before_database_io non_allowlisted_alter_session_is_refused_before_database_io multi_statement_batch_with_a_write_is_refused streaming_write_refusal_opens_zero_row_streams -- --nocapture` run as exact per-test filters.
- Verdict: CLEAN - sampled read/write/DDL/DCL/transaction-control/streaming refusals returned typed guard classes and the mocks recorded zero DB I/O on the pre-Oracle refusal paths.

## [MEDIUM] Semantic-search RuntimeStateRequired proof is masked by an earlier guard refusal
- Where: crates/oraclemcp/src/dispatch/tests.rs:374
- Claim checked: Offline or unconfigured semantic-search paths should degrade to RuntimeStateRequired rather than crashing or silently falling through.
- Method: `CARGO_TARGET_DIR=/home/durakovic/projects/oraclemcp/target cargo test -p oraclemcp semantic_text_search_requires_both_capabilities_before_a_read_can_escape -- --nocapture`.
- Verdict: CONFIRMED DEFECT - the test fails before reaching its RuntimeStateRequired assertions because the generated read is refused as `FORBIDDEN_STATEMENT` with `unresolved semantic read dependency`; the narrower `semantic_text_search_refuses_an_absent_or_ambiguous_local_model` and `raw_query_cannot_claim_the_local_embedding_exception` checks still pass.

## [LOW] Broad offline registry route proof is currently unproven in this shared checkout
- Where: crates/oraclemcp/src/dispatch/tests.rs:2107; crates/oraclemcp/src/dispatch/tests.rs:2228
- Claim checked: The offline registry test should prove every registered tool routes and deserializes without a live Oracle connection.
- Method: `git diff -- crates/oraclemcp/src/dispatch/tests.rs`, `git show HEAD:crates/oraclemcp/src/dispatch/tests.rs | nl -ba | sed -n '2096,2248p'`, and `CARGO_TARGET_DIR=/home/durakovic/projects/oraclemcp/target cargo test -p oraclemcp every_registry_tool_routes_and_deserializes_offline -- --nocapture`.
- Verdict: UNPROVEN - the test fails in the shared working tree because another pane's uncommitted helper change feeds `oracle_query` an unproven `app.employees` relation instead of HEAD's `SELECT 1 FROM dual`; I did not edit or revert the live dirty file.

## [LOW] oracle_connection_info degrades in band with structured recovery
- Where: crates/oraclemcp/src/dispatch/mod.rs:11315; crates/oraclemcp/src/dispatch/tests.rs:2997
- Claim checked: `oracle_connection_info` should return `connected=false` with structured `connection_error` and `next_actions` rather than failing hard.
- Method: Code read of `connection_info_json` plus `CARGO_TARGET_DIR=/home/durakovic/projects/oraclemcp/target cargo test -p oraclemcp connection_info_degrades_when_describe_fails connection_info_reports_disconnected_when_the_liveness_round_trip_fails profile_switch_reports_metadata_errors_after_switching -- --nocapture` run as exact per-test filters.
- Verdict: CLEAN - metadata and liveness failures returned in-band JSON with `connected=false`, structured `connection_error`, suggested recovery tooling, and `next_actions`.

## [LOW] Error-adjacent surfaces preserve redaction in sampled paths
- Where: crates/oraclemcp/src/dispatch/tests.rs:616; crates/oraclemcp/src/dispatch/mod.rs:11315; crates/oraclemcp-db/src/types.rs
- Claim checked: Error paths must not leak connect strings, usernames, credential_ref values, passwords, proxy identities, wallet passwords, IAM tokens, wallet paths, or server DNs.
- Method: `CARGO_TARGET_DIR=/home/durakovic/projects/oraclemcp/target cargo test -p oraclemcp-core connection_error_redacts_profile_sensitive_values wallet_decrypt_password_echo_is_redacted iam_token_refresh_failure_redacts_jwt -- --nocapture`, `CARGO_TARGET_DIR=/home/durakovic/projects/oraclemcp/target cargo test -p oraclemcp profile_secret_resolution_errors_do_not_echo_secret_locators connection_diagnostics_report_exact_generation_without_config_secrets profile_response_omits_connection_and_secret_material guard_refusal_appends_only_a_redacted_classifier_proven_corpus_record -- --nocapture`, and `CARGO_TARGET_DIR=/home/durakovic/projects/oraclemcp/target cargo test -p oraclemcp-db connection_info_debug_and_redacted_json_are_allowlist_first debug_redacts_connect_material debug_redacts_session_identity_values -- --nocapture`.
- Verdict: CLEAN - sampled profile-resolution errors, connection diagnostics, refusal corpus output, and connection-info JSON did not echo the tested secret or identity values.
