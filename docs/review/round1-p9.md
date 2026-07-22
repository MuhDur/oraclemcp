## [HIGH] Write-capable custom tools load but refuse before invocation reaches Oracle
- Where: HEAD 0a51dcb9; `crates/oraclemcp-core/src/custom_tools.rs:413`; `crates/oraclemcp/src/dispatch/mod.rs:14219`; `crates/oraclemcp/src/dispatch/mod.rs:11146`
- Claim checked: When a loaded custom tool requires `READ_WRITE`, named invocation either routes through the same `oracle_execute` preview/confirmation/single-use grant/rollback/write-intent path, or executes directly against Oracle.
- Method: Added the following scratch-only dispatcher test in `/tmp/oraclemcp-cod6-review-ladder-0a51dcb9/crates/oraclemcp/src/dispatch/tests.rs` and ran `CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/home/durakovic/projects/oraclemcp/target/cod6-review-ladder cargo test -p oraclemcp write_capable_custom_tool_invocation_refuses_before_oracle_execute_path -- --nocapture`.

```rust
#[test]
fn write_capable_custom_tool_invocation_refuses_before_oracle_execute_path() {
    let defs = oraclemcp_core::parse_tools_file(
        r#"
            [[tool]]
            name = "app_customer_bump"
            description = "Write customer status"
            sql = "UPDATE app_customers SET status = 'ACTIVE' WHERE id = 7"
            output_mode = "rows"
            "#,
    )
    .expect("custom tool parses");
    let loaded = oraclemcp_core::load_tools(
        &defs,
        &Classifier::new(ClassifierConfig::new()),
        OperatingLevel::ReadWrite,
    )
    .expect("write-capable custom tool loads on writable profile");
    assert_eq!(loaded[0].required_level, OperatingLevel::ReadWrite);

    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_switchable_with_custom_tools(
        Box::new(ExecRecordingMock::new(state.clone())),
        Some("dev".to_owned()),
        read_write_level(),
        Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
        CustomToolCatalog::new(loaded),
        None,
    );

    let err = dispatcher
        .dispatch("app_customer_bump", json!({}))
        .expect_err("write-capable custom tool refuses on invocation");

    assert_eq!(err.error_class, ErrorClass::OperatingLevelTooLow);
    assert!(
        err.message
            .contains("this server executes only READ_ONLY custom tools"),
        "{}",
        err.message
    );
    assert!(
        state.executed.lock().expect("exec mutex").is_empty(),
        "custom invocation must not call OracleConnection::execute directly"
    );
    assert_eq!(state.commits.load(Ordering::SeqCst), 0);
    assert_eq!(state.rollbacks.load(Ordering::SeqCst), 0);
}
```

- Verdict: Neither proposed branch is exactly true. This is not (a): named custom-tool invocation does not route through the `oracle_execute` preview/confirmation grant, durable write-intent, rollback-unless-commit flow. It is also not (b) as phrased: the production executor refuses `READ_WRITE` custom tools before any `OracleConnection::execute`, `commit`, or `rollback`, so the test did not find a named unguarded write path. The defect is a high-severity contract/surface honesty gap: writable custom tools can be loaded and advertised on writable profiles, but invocation is fail-closed with `OperatingLevelTooLow` instead of executing through the write-grant path.

## [HIGH] A1a semantic-read tightening invalidated offline witnesses beyond the five known failures
- Where: current clean HEAD `8d8c8228`; A1a source `fa93e169`; gate surface `crates/oraclemcp/src/dispatch/mod.rs:4994` (`ForbiddenStatement` / `unresolved semantic read dependency`) and `crates/oraclemcp/src/dispatch/mod.rs:5059` (`ensure_resolved_read_only`).
- Claim checked: every offline test witness whose asserted property depends on `oracle_query`, `query`, `oracle_diff`, or `oracle_preview_dml` running a caller read should either model the resolver's positive catalog proof or be counted as stale. A1a is correct to fail closed; the defect is coverage that still looks green while no longer reaching its real assertion.
- Method: clean detached worktrees at `/tmp/oraclemcp-cod6-a1a-full-1784725811` (HEAD `8d8c8228`) and `/tmp/oraclemcp-cod6-a1a-blast-0a51dcb9` (earlier HEAD `c99491a3`); `rg` sweep over `oracle_query`, `query`, `oracle_diff`, `oracle_preview_dml`, and non-DUAL `SELECT ... FROM ...` strings under `crates/oraclemcp/src/dispatch/tests*` and `crates/oraclemcp/tests`; focused `cargo test -p oraclemcp` filters for active red and repaired lanes.

- [CRITICAL] Active stale golden: `golden_stdio_main_tool_transcript` at `crates/oraclemcp/tests/golden_behavior.rs:450`, witness `select object_name, owner from all_objects where rownum <= 1`. Focused run returns `FORBIDDEN_STATEMENT` / `unresolved semantic read dependency` instead of the expected structured success transcript, so the first stdio transcript no longer proves successful `oracle_query` framing.
- [CRITICAL] Active stale golden: `golden_stdio_query_opaque_cursor_pagination` at `crates/oraclemcp/tests/golden_behavior.rs:535`, witness `select id from all_objects` at `:512`. Page 1 returns `FORBIDDEN_STATEMENT` / `unresolved semantic read dependency`, so the test no longer proves opaque cursor minting, forged-offset rejection, or cross-statement cursor binding. The later `select id from other_table` cross-statement witness at `:566` is also unreachable.
- [CRITICAL] Active stale golden: `golden_stdio_query_export_resource_and_resource_link` at `crates/oraclemcp/tests/golden_behavior.rs:820`, witness `select id, name from people` at `:841`. The call returns `FORBIDDEN_STATEMENT` / `unresolved semantic read dependency` before export materialization, so the test no longer proves resource-link export or `resources/read` of exported query results.
- [CRITICAL] Active stale stdio schema proof: `oracle_query_structured_content_matches_advertised_output_schema_fields` at `crates/oraclemcp/tests/e2e_stdio.rs:306`, witness `SELECT object_count FROM dual` at `:313`. The reply is the same `FORBIDDEN_STATEMENT` / `unresolved semantic read dependency` ErrorEnvelope rather than the advertised success schema, so the test no longer proves required `oracle_query` output fields.

- [HIGH] Repaired dispatch semantic-read fixtures, known witness group 1: `served_read_gate_executes_only_exact_plain_table_columns` (`SELECT o.id FROM app.orders o`, `crates/oraclemcp/src/dispatch/tests.rs:387`); `semantic_text_search_requires_both_capabilities_before_a_read_can_escape` (generated `APP.ORDERS` vector read, `:399`); `semantic_hybrid_filter_is_bound_proven_and_cannot_widen` (generated `APP.ORDERS` vector read with filter, `:465`); and the intended negative gate rows in `served_read_gate_refuses_view_policy_and_zero_arg_function_before_evaluation` / `served_read_gate_reports_missing_relations_and_columns_without_suggesting_escalation` (`:578`, `:607`). These were A1a-sensitive, but current HEAD has a positive semantic catalog model and the focused filters pass.
- [HIGH] Repaired audit-wiring semantic-read fixtures, expanded from the historical 65-failure bucket: `masked_read_carries_audit_bound_certificate` (`SELECT owner FROM all_objects`, `crates/oraclemcp/src/dispatch/tests/audit_wiring.rs:347`); `masked_arrow_read_contains_only_audit_bound_masked_values` (`SELECT owner, object_name FROM all_objects`, `:412`); `masked_read_fails_closed_when_audit_append_fails` (`:464`); `masked_read_fails_closed_without_audit_sink` (`:482`); `masked_streaming_query_is_refused_until_certificates_can_precede_rows` (`:504`); `masked_diff_carries_before_after_audit_bound_certificates` (`oracle_diff` over `SELECT owner FROM all_objects`, `:523`). Evidence `tests/artifacts/evidence/closes/oraclemcp-nl105.json` records the root cause: empty `ALL_POLICIES`/`ALL_TAB_COLS` answers proved blindness, not safety. Focused audit-wiring filter passed 16 tests after repair.
- [HIGH] Repaired preview-DML sandbox witness, known witness group 2: `preview_dml_runs_the_statement_in_a_sandbox_and_rolls_it_back` at `crates/oraclemcp/src/dispatch/tests.rs:14745`, witness `SELECT e.id FROM app.employees e WHERE e.id = :1` at `:14755`. Before `cd90a3e3`, the stale witness refused before SAVEPOINT/ROLLBACK assertions, as recorded in `docs/review/round1-p3.md`; the focused filter now passes with a modeled `app.employees` relation.
- [HIGH] Repaired registry smoke witness, known witness group 3: `every_registry_tool_routes_and_deserializes_offline`, whose `args_for("oracle_query")` uses `SELECT o.id FROM app.orders o WHERE o.id = :1` at `crates/oraclemcp/src/dispatch/tests.rs:2133`. This was stale when it named an unmodeled table; current focused filter passes.
- [HIGH] Repaired semantic-search `RuntimeStateRequired` proof, known witness group 4: `semantic_text_search_requires_both_capabilities_before_a_read_can_escape` at `crates/oraclemcp/src/dispatch/tests.rs:399`. Before repair, the generated read failed `ensure_resolved_read_only` before the pre-23.4 `RuntimeStateRequired` branch; current focused filter passes and `docs/review/round1-p5.md` records the old failure.
- [HIGH] Repaired offline registry route / compatibility alias witness, known witness group 5: `compatibility_aliases_route_to_prefixed_tools`, whose alias `query` uses `SELECT o.id FROM app.orders o WHERE o.id = :1` at `crates/oraclemcp/src/dispatch/tests.rs:2200`. Current focused filter passes and alias routing is again covered by the same semantic model as `oracle_query`.

- [MEDIUM] Swept clean but A1a-sensitive: `query_export_resource_is_bound_to_oauth_principal_and_scope` (`SELECT object_name FROM user_objects`, `crates/oraclemcp/src/dispatch/tests.rs:5273`); `arrow_query_decodes_to_the_same_governed_rows_as_json_mode` (`SELECT owner, object_name FROM all_objects`, `:5295`); `query_accepts_page_and_width_compatibility_args` (`SELECT object_name, lob_value FROM user_objects`, `:5365`); `query_bind_values_do_not_echo_to_protocol_output` (`SELECT * FROM t WHERE payload = :1 AND id = :2`, `:5343`); `query_binds_are_accepted_and_typed` (`SELECT * FROM t WHERE id = :1 AND active = :2`, `:5282`). These are not active reds at current HEAD, but they are in the blast radius because their coverage depends on the shared positive dictionary model staying honest.
- [MEDIUM] Swept clean but A1a-sensitive streaming/cursor/query-state fixtures: `row_streaming_dispatch_emits_one_sse_frame_per_row_byte_identically`, `streaming_query_delivers_chunks_byte_identical_to_a_full_read`, `streaming_resume_cursor_matches_a_manual_incremental_fetch`, and related streaming refusal variants over `SELECT id, name FROM t` / `SELECT id FROM t` at `crates/oraclemcp/src/dispatch/tests.rs:11899-12188`; workspace read `SELECT c FROM t` at `:13651`; cross-database diff reads `SELECT id, val FROM app.orders...` at `:14290`, `:14702`, `:14714`, `:14727`; policy rewrite read `SELECT id FROM app.employees` at `:15264`. These pass at current HEAD or are covered by the passing full dispatch filter, so I did not count them as active stale witnesses.
- [LOW] Excluded after sweep: tests whose intended assertion is a refusal (`FORBIDDEN_STATEMENT`, `OperatingLevelTooLow`, `RuntimeStateRequired`, parser/classifier-only strings, or hidden-object negatives); live-XE tests that use a real catalog rather than offline witness mocks (`crates/oraclemcp/tests/reversible_workspace.rs`, `rls_vpd_visibility.rs`, `live_xe_service_attach.rs`, `trust_safety.rs`, `plsql_live_xe.rs`); strings that never enter `ensure_resolved_read_only`.

- Verdict: true current active residue is **4 tests** and true total A1a blast radius in the offline test surface is larger than the five known groups: **4 active stale tests + 5 known repaired groups + 2 broader swept-clean A1a-sensitive groups**. The active failures are coverage defects, not guard defects; the guard is failing closed correctly. Repairs should add positive catalog proof to mocks or choose modeled plain-table witnesses. Weakening A1a would be a regression.

## [INVESTIGATION] oraclemcp-honesty-grep forbidden-framing classification

Run result: `scripts/oraclemcp_honesty_grep.sh` reports `FAIL — 9 over-claiming occurrence(s)`.

1. docs/plan/PLAN_0_4_0_PRODUCTION_HARDENING.md:115 — exact phrase: `"Fully audited"`
   - Classification: (b)
   - Historical planning narrative in conversion notes about clarifying dependency-audit claims.
2. docs/plan/PLAN_0_4_0_PRODUCTION_HARDENING.md:233 — exact phrase: `"audit" / "fully audited" / "every action audited"`
   - Classification: (b)
   - Plan requirement text for what to refrain from claiming before WP-A8 audit wiring is done.
3. docs/plan/PLAN_0_4_0_PRODUCTION_HARDENING.md:237 — exact phrase: `"safe-by-default"`
   - Classification: (b)
   - Historical DoD/guardrail wording for release hygiene, not current product behavior claim.
4. docs/plan/PLAN_0_4_0_PRODUCTION_HARDENING.md:238 — exact phrase: `"read-only binary", "fully audited", "PAM"`
   - Classification: (b)
   - Plan checklist text defining prohibited release phrasing for that campaign phase.
5. docs/plan/PLAN_0_4_0_PRODUCTION_HARDENING.md:677 — exact phrase: `"safe-by-default" / "fail-closed by construction"`
   - Classification: (b)
   - Explicit task backlog in an earlier plan sweep item, including an old wording correction.
6. docs/plan/PLAN_0_4_0_PRODUCTION_HARDENING.md:690 — exact phrase: `"fully audited"`
   - Classification: (b)
   - Staged statement tied to A8 milestone, still planning context.
7. docs/plan/PLAN_0_4_0_PRODUCTION_HARDENING.md:732 — exact phrase: `"safe-by-default", "read-only binary", "fully audited"`
   - Classification: (b)
   - Release checklist text in plan section; historical control language, not release claim.
8. docs/plan/PLAN_0_4_0_PRODUCTION_HARDENING.md:1008 — exact phrase: `"safe-by-default", and behavior inventory still says "read-only binary"`
   - Classification: (b)
   - Retrospective evidence entry for bead R2-06, not a present-tense shipping claim.
9. docs/plan/PLAN_0_6_0_INTERACTIVE_ALWAYS_ON.md:824 — exact phrase: `"safe-by-default"`
   - Classification: (b)
   - Plan-side note in 0_6_0 for future doc/gate expectations, not current product framing.

## [INVESTIGATION] Honesty-grep growth: counts + file list

- Total occurrences now: 18
- (a) product/README/code surfaces: 0
- (b) historical plan docs: 9
- (c) docs/review artifacts (quoted-analysis carryover): 9

File list:

- (a) product/README/code surfaces: none
- (b) historical plan docs: `docs/plan/PLAN_0_4_0_PRODUCTION_HARDENING.md`, `docs/plan/PLAN_0_6_0_INTERACTIVE_ALWAYS_ON.md`
- (c) docs/review artifacts: `docs/review/round1-p9.md`
