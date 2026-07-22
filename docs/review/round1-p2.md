## [LOW] C6 dispatch alias tests route into fail-closed semantic-read refusal
- Where: 80f300ac; crates/oraclemcp/src/dispatch/mod.rs
- Claim checked: C6 dispatch routing split was isomorphic and did not widen or break routing behavior.
- Method: env -u CARGO_TARGET_DIR cargo test -p oraclemcp every_registry_tool_routes_and_deserializes_offline -- --nocapture; env -u CARGO_TARGET_DIR cargo test -p oraclemcp compatibility_aliases_route_to_prefixed_tools -- --nocapture; compared current red shape with tests/artifacts/evidence/closes/oraclemcp-eng-program-bp8ia.4.6.2.json.
- Verdict: CLEAN for routing isomorphism; current red tests reach oracle_query and then fail closed with ErrorClass::ForbiddenStatement, matching pre-existing C6 evidence rather than proving dispatch drift.

## [LOW] C6 classifier split preserved checked fail-closed classifier behavior
- Where: b233fff0; crates/oraclemcp-guard/src/classifier.rs
- Claim checked: Classifier split was isomorphic and did not weaken the fail-closed guard.
- Method: env -u CARGO_TARGET_DIR cargo test -p oraclemcp-guard vector_embedding -- --nocapture; env -u CARGO_TARGET_DIR cargo test -p oraclemcp-guard --test adversarial_corpus -- --nocapture.
- Verdict: CLEAN.

## [LOW] C6 dispatch terminal-effect helpers preserved checked behavior
- Where: 80f300ac; crates/oraclemcp/src/dispatch/mod.rs
- Claim checked: Dispatch routing split preserved terminal-effect classification behavior.
- Method: env -u CARGO_TARGET_DIR cargo test -p oraclemcp successful_checkpoint_and_undo_are_terminal_effects -- --nocapture; env -u CARGO_TARGET_DIR cargo test -p oraclemcp previews_and_effectless_bodies_stay_cancellable -- --nocapture.
- Verdict: CLEAN.

## [MEDIUM] PowerShell installer auto-consented to discovery under -Yes
- Where: 0a51dcb9; install.ps1:727
- Claim checked: README promises non-interactive installer runs never prompt, scan, or start a service; discovery must be consent-gated.
- Method: Static trace of Read-InstallerConsent and Invoke-OptionalDiscovery showed -Yes returned true before any interactive check; fixed in 0a51dcb9, then ran env -u CARGO_TARGET_DIR cargo test -p oraclemcp --test installer_e2e installers_offer_consent_gated_tns_discovery_via_the_binary -- --nocapture and env -u CARGO_TARGET_DIR cargo test -p oraclemcp --test installer_e2e windows_installer_verifies_before_mutating_and_requires_service_consent -- --nocapture.
- Verdict: CONFIRMED DEFECT; fixed by requiring Test-InteractiveInstall before the PowerShell installer offers discovery.

## [LOW] Discovery writer anti-rot contract was stale after session teardown fields
- Where: 0a51dcb9; crates/oraclemcp-config/src/discovery/contract.rs:403; crates/oraclemcp-config/tests/golden/discovery_annotated.toml
- Claim checked: Discovery annotated writer anti-rot tests should cover every ConnectionProfile serde field and keep the golden in sync.
- Method: env -u CARGO_TARGET_DIR cargo test -p oraclemcp-config discovery -- --nocapture initially failed on a 33-vs-35 field count and stale golden; fixed in 0a51dcb9; reran the same command.
- Verdict: CONFIRMED DEFECT; fixed, rerun was CLEAN with 39 passed.

## [LOW] Unix installer verification and no-surprise behavior held under scoped smoke
- Where: install.sh
- Claim checked: README claims SHA-256 is required, cosign is verified when present, non-interactive runs do not prompt/scan/start service, service is explicit, and reinstall/update/uninstall behavior is idempotent.
- Method: bash -n install.sh; env -u CARGO_TARGET_DIR cargo test -p oraclemcp --test installer_e2e installer_lint_and_offline_smoke_passes -- --nocapture.
- Verdict: CLEAN.

## [LOW] setup --discover consent, redaction, READ_ONLY cap, and idempotent merge held
- Where: crates/oraclemcp/src/discover.rs; crates/oraclemcp-config/src/discovery
- Claim checked: README claims non-interactive discovery without --discover-tns/--yes refuses with exit 2 and scans nothing; discovery writes no secrets, caps profiles at READ_ONLY, and preserves existing profiles.
- Method: env -u CARGO_TARGET_DIR cargo test -p oraclemcp discover::tests -- --nocapture; env -u CARGO_TARGET_DIR cargo test -p oraclemcp --test discover_e2e discover_onboarding_clean_machine_e2e -- --nocapture; env -u CARGO_TARGET_DIR cargo test -p oraclemcp-config discovery -- --nocapture.
- Verdict: CLEAN.

## [LOW] HTTP --listen startup guard remains fail-closed
- Where: crates/oraclemcp/src/main.rs:3650; crates/oraclemcp/src/main.rs:4156
- Claim checked: --listen refuses to start without client-credentials, OAuth, mTLS, or explicit --allow-no-auth; auth refusal must precede remote-bind checks.
- Method: env -u CARGO_TARGET_DIR cargo test -p oraclemcp http_listen -- --nocapture.
- Verdict: CLEAN.

## [LOW] HTTP non-loopback bind requires explicit remote opt-in
- Where: crates/oraclemcp/src/main.rs:4179
- Claim checked: Non-loopback bind refuses without ORACLEMCP_HTTP_ALLOW_REMOTE=1 or equivalent config opt-in, even when TLS/auth is configured.
- Method: env -u CARGO_TARGET_DIR cargo test -p oraclemcp http_listen -- --nocapture.
- Verdict: CLEAN.

## [LOW] CA-verified mTLS certificates are not identity until fingerprint registration
- Where: crates/oraclemcp-core/src/http/mod.rs:654; crates/oraclemcp-core/src/http/tests_serve_tls.rs:507
- Claim checked: A CA-verified mTLS client certificate is not an application identity until its leaf DER SHA-256 fingerprint is registered.
- Method: env -u CARGO_TARGET_DIR cargo test -p oraclemcp-core mtls -- --nocapture.
- Verdict: CLEAN.

## [LOW] Registered mTLS leaf fingerprint becomes the principal key
- Where: crates/oraclemcp-core/src/http/tests_serve_tls.rs:542
- Claim checked: Registered mTLS clients authenticate as mtls:sha256:<leaf-der-sha256>.
- Method: env -u CARGO_TARGET_DIR cargo test -p oraclemcp-core mtls -- --nocapture.
- Verdict: CLEAN.

## [LOW] Rejected OAuth bearers stay generic on the public challenge
- Where: crates/oraclemcp-core/src/http/mod.rs:642; crates/oraclemcp-core/src/http/tests_serve.rs:791; crates/oraclemcp-auth/src/oauth_rs.rs:258
- Claim checked: A presented but rejected bearer returns error="invalid_token" with no error_description; detailed rejection category stays in audit.
- Method: env -u CARGO_TARGET_DIR cargo test -p oraclemcp-core oauth -- --nocapture; env -u CARGO_TARGET_DIR cargo test -p oraclemcp-auth metadata_and_challenge -- --nocapture; env -u CARGO_TARGET_DIR cargo test -p oraclemcp --test e2e_http_oauth -- --nocapture.
- Verdict: CLEAN.

## [LOW] Remote plaintext does not receive privileged cookies
- Where: crates/oraclemcp-core/src/http/mod.rs:899; crates/oraclemcp-core/src/http/tests_serve.rs:209; crates/oraclemcp-core/src/http/mod.rs:1295
- Claim checked: Privileged browser cookies are Secure under HTTPS, allowed without Secure only for server-observed loopback HTTP, and suppressed/refused for remote plaintext even with forwarded HTTPS headers.
- Method: env -u CARGO_TARGET_DIR cargo test -p oraclemcp-core cookie -- --nocapture.
- Verdict: CLEAN.

## [LOW] Profile base inheritance remains reuse, not a safety ceiling
- Where: README.md:810; crates/oraclemcp-config/src/lib.rs:1242; crates/oraclemcp-config/tests/profile_merge_property.rs:184
- Claim checked: `base` inherits only unset fields, a child can raise `max_level` above its base, and only `protected = true` pins the immutable READ_ONLY ceiling.
- Method: env -u CARGO_TARGET_DIR cargo test -p oraclemcp-config --test profile_merge_property -- --nocapture; inspected `OracleMcpConfig::from_toml_str` validation and profile merge tests.
- Verdict: CLEAN.

## [LOW] MCP profile exposure stays a visibility opt-out for list, switch, and fleet search
- Where: README.md:864; crates/oraclemcp-config/src/lib.rs:1288; crates/oraclemcp/src/dispatch/tests.rs:3391; crates/oraclemcp/src/dispatch/tests.rs:3440; crates/oraclemcp/src/dispatch/tests.rs:14425; crates/oraclemcp/src/main.rs:6252
- Claim checked: `mcp_exposed = false` is per-profile visibility, not access control; hidden profiles are indistinguishable from guessed names on `oracle_list_profiles`, `oracle_switch_profile`, and fleet `oracle_search_objects`, while operator profile JSON still uses the all-profile view.
- Method: env -u CARGO_TARGET_DIR cargo test -p oraclemcp-config mcp_exposure -- --nocapture; env -u CARGO_TARGET_DIR cargo test -p oraclemcp e5_ -- --nocapture; env -u CARGO_TARGET_DIR cargo test -p oraclemcp fleet_catalog_hidden_profile_is_indistinguishable_from_absence -- --nocapture; env -u CARGO_TARGET_DIR cargo test -p oraclemcp profiles_json_reports_non_secret_metadata -- --nocapture.
- Verdict: CLEAN.

## [LOW] Profile completion hidden-profile behavior lacks a direct regression
- Where: README.md:867; crates/oraclemcp-core/src/server.rs:2161; crates/oraclemcp-core/src/server.rs:2300
- Claim checked: Completion for `profile`/`db` must fail closed like the MCP-visible profile list and must not offer hidden profile names.
- Method: rg -n "completion_complete.*profile|profile_completion|completion.*oracle_list_profiles|oracle_list_profiles.*completion|\"argument\": \\{ \"name\": \"profile\"" crates/oraclemcp/tests crates/oraclemcp-core/src; inspected `handle_completion_complete`, `complete_profiles`, and `completion_kind`.
- Verdict: UNPROVEN; code routes profile/db completion through filtered `oracle_list_profiles`, but I found no executable test that drives `completion/complete` for a hidden profile name.

## [LOW] Protected profiles reject literal credential references
- Where: README.md:893; crates/oraclemcp-auth/src/secrets.rs:192; crates/oraclemcp/src/main_tests.rs:1253; crates/oraclemcp/src/main_tests.rs:2383
- Claim checked: `literal:` credential refs are allowed only for local development and are rejected when the effective profile is protected.
- Method: env -u CARGO_TARGET_DIR cargo test -p oraclemcp-auth literal_is_denied_under_protected_profile -- --nocapture; env -u CARGO_TARGET_DIR cargo test -p oraclemcp http_oauth_literal_secret_is_rejected_for_protected_profiles -- --nocapture; env -u CARGO_TARGET_DIR cargo test -p oraclemcp wallet_password_ref_uses_profile_secret_resolution_policy -- --nocapture.
- Verdict: CLEAN.

## [LOW] Historical plan docs pointed at deleted lease/session files
- Where: docs/plan/PLAN_ENGINEERING_PROGRAM.md:5359; docs/plan/PLAN_0_6_0_INTERACTIVE_ALWAYS_ON.md:143; docs/plan/PLAN_ASUPERSYNC_THIN_NATIVE.md:239; docs/plan/PLAN_0_9_1_FIELD_HARDENING.md:2421
- Claim checked: Historical planning docs should not send future readers looking for `crates/oraclemcp-db/src/lease.rs` or `crates/oraclemcp-core/src/session_tool.rs` after B14b removed the dead lease/session-tool subsystem.
- Method: git log --all --oneline --name-status -- crates/oraclemcp-db/src/lease.rs crates/oraclemcp-core/src/session_tool.rs; rg -n 'lease\\.rs|session_tool\\.rs|session\\.rs' docs/plan; edited only stale source-path references in the working tree to mark them as former/deleted-by-B14b history; left those edits uncommitted because the same plan paths already carry a pre-existing staged docs/plan move and unrelated doc-normalization hunks.
- Verdict: CONFIRMED DEFECT.

## [LOW] Resources and prompts advertise only the intended browsable surface
- Where: crates/oraclemcp-core/src/server.rs:1756; crates/oraclemcp-core/src/server.rs:2527; crates/oraclemcp-core/src/resources.rs:124; crates/oraclemcp-core/src/resources.rs:244
- Claim checked: `resources/list` exposes `oracle://capabilities` and `oracle://tools`; `resources/templates/list` exposes schema/object read templates; `prompts/list` serves the expert playbook catalog.
- Method: env -u CARGO_TARGET_DIR cargo test -p oraclemcp-core resource -- --nocapture; env -u CARGO_TARGET_DIR cargo test -p oraclemcp-core prompt -- --nocapture.
- Verdict: CLEAN.

## [LOW] Resource template reads preserve the guarded dispatch and transport context
- Where: crates/oraclemcp-core/src/server.rs:1802; crates/oraclemcp-core/src/server.rs:1938; crates/oraclemcp-core/src/server.rs:1963; crates/oraclemcp-core/src/server.rs:2022; crates/oraclemcp-core/src/server.rs:3568
- Claim checked: Reading `oracle://schema/{owner}` or `oracle://object/{owner}/{type}/{name}` cannot bypass the guard; it must route through `oracle_schema_inspect`, `oracle_get_source`, or `oracle_get_ddl` with the same transport authorization context.
- Method: Added `resource_template_reads_route_through_dispatch_with_transport_context`; ran env -u CARGO_TARGET_DIR cargo test -p oraclemcp-core resource_template_reads_route_through_dispatch_with_transport_context -- --nocapture; env -u CARGO_TARGET_DIR cargo test -p oraclemcp-core resource -- --nocapture; env -u CARGO_TARGET_DIR cargo test -p oraclemcp discovery_resources_reflect_the_calling_session_level -- --nocapture; env -u CARGO_TARGET_DIR cargo clippy -p oraclemcp-core --lib --tests -- -D warnings.
- Verdict: CLEAN.

## [LOW] Signed audit chain detects tail truncation through the anchor sidecar
- Where: README.md:652; README.md:767; crates/oraclemcp-audit/tests/e3_audit_chain_e2e.rs:240; crates/oraclemcp/src/main.rs:1610
- Claim checked: The signed audit chain is append-only, hash-chained, HMAC-SHA256 signed, and `oraclemcp audit verify` detects a truncated tail against the `.anchor` sidecar.
- Method: env -u CARGO_TARGET_DIR cargo test -p oraclemcp-audit concurrent_appends_keep_one_valid_chain -- --nocapture; env -u CARGO_TARGET_DIR cargo test -p oraclemcp-audit hmac -- --nocapture; env -u CARGO_TARGET_DIR cargo test -p oraclemcp-audit --test e3_audit_chain_e2e tail_truncation_is_invisible_to_the_chain_and_caught_by_the_anchor -- --nocapture.
- Verdict: CLEAN.

## [LOW] Unsigned refusal corpus is not accepted by signed audit verification
- Where: README.md:667; README.md:770; crates/oraclemcp/src/main.rs:5380; crates/oraclemcp/src/main.rs:5391; crates/oraclemcp/src/main.rs:6690; crates/oraclemcp-guard/src/corpus.rs:146
- Claim checked: The unsigned refusal trail is explicitly not tamper-evident and must never be presented as, or substituted for, the signed audit tier.
- Method: Wrote a syntactically valid refusal-corpus JSONL line with `authenticity:"unsigned_not_tamper_evident"` to `/var/tmp/oraclemcp-refusal-audit-p2/refusals.jsonl`; ran `ORACLEMCP_AUDIT_KEY=0123456789abcdef0123456789abcdef target/debug/oraclemcp --json audit verify /var/tmp/oraclemcp-refusal-audit-p2/refusals.jsonl`; it exited 2 with `ORACLEMCP_AUDIT_MALFORMED` (`missing field seq`). Also ran env -u CARGO_TARGET_DIR cargo test -p oraclemcp refusal_corpus -- --nocapture.
- Verdict: CLEAN.

## [LOW] Startup and doctor keep the unsigned refusal floor below the signed tier
- Where: crates/oraclemcp/src/main.rs:1515; crates/oraclemcp/src/main.rs:6690; crates/oraclemcp/src/main.rs:6751; crates/oraclemcp-core/src/doctor.rs:2709
- Claim checked: `unsigned_refusal_log` defaults on only when no signed auditor exists because every reachable profile is READ_ONLY; a writable reachable profile without a signing key fails startup closed; doctor must not infer a signed auditor from the default path or from the unsigned trail.
- Method: env -u CARGO_TARGET_DIR cargo test -p oraclemcp build_auditor_fails_closed_when_a_switchable_profile_can_write -- --nocapture; env -u CARGO_TARGET_DIR cargo test -p oraclemcp audit_posture -- --nocapture.
- Verdict: CLEAN.

## [LOW] Refusal-trail observer cannot weaken guard refusal or replace audit-write failure
- Where: crates/oraclemcp/src/dispatch/mod.rs:790; crates/oraclemcp/src/dispatch/mod.rs:801; crates/oraclemcp/src/dispatch/mod.rs:6798; crates/oraclemcp/src/dispatch/tests.rs:642; crates/oraclemcp-audit/tests/e3_audit_chain_e2e.rs:440
- Claim checked: Refusal-corpus persistence is an unsigned observer only; disabling or failing that observer cannot alter the original guard refusal, while signed audit-write failure remains fail-closed (SEC-3).
- Method: env -u CARGO_TARGET_DIR cargo test -p oraclemcp guard_refusal_appends_only_a_redacted_classifier_proven_corpus_record -- --nocapture; env -u CARGO_TARGET_DIR cargo test -p oraclemcp explicit_refusal_trail_opt_out_keeps_the_guard_refusal_without_a_record -- --nocapture; env -u CARGO_TARGET_DIR cargo test -p oraclemcp-audit --test e3_audit_chain_e2e an_unwritable_audit_destination_fails_closed_at_open -- --nocapture.
- Verdict: CLEAN.
