## [HIGH] Write path requires preview grant before commit or non-transactional effect
- Where: crates/oraclemcp/src/dispatch/mod.rs:6563; crates/oraclemcp/src/dispatch/mod.rs:8992; crates/oraclemcp-guard/src/exec_grant.rs:176
- Claim checked: README contract that commits and non-transactional effects such as sequence NEXTVAL require the single-use preview grant from oracle_preview_sql.
- Method: CARGO_TARGET_DIR=target cargo test -p oraclemcp execute_commit; CARGO_TARGET_DIR=target cargo test -p oraclemcp sequence_nextval; CARGO_TARGET_DIR=target cargo test -p oraclemcp-guard exec_grant -- --nocapture
- Verdict: CLEAN

## [HIGH] DML rolls back unless commit=true
- Where: crates/oraclemcp/src/dispatch/mod.rs:9280; crates/oraclemcp/src/dispatch/tests.rs:9283
- Claim checked: README contract that oracle_execute accepts one non-read statement and rolls DML back unless commit=true.
- Method: CARGO_TARGET_DIR=target cargo test -p oraclemcp execute_approved_token_only_rolls_back_by_default_and_replays_token_once; CARGO_TARGET_DIR=target cargo test -p oraclemcp a_rolled_back_statement_that_escapes_rollback_is_labeled_cannot_undo
- Verdict: CLEAN

## [HIGH] Query-shaped NEXTVAL is refused instead of executed without fetch proof
- Where: crates/oraclemcp/src/dispatch/mod.rs:8904; crates/oraclemcp/src/dispatch/tests.rs:6647
- Claim checked: README contract that query-shaped NEXTVAL is refused because oracle_execute reports row counts rather than fetching rows.
- Method: CARGO_TARGET_DIR=target cargo test -p oraclemcp sequence_nextval
- Verdict: CLEAN

## [HIGH] DDL requires commit=true plus confirmation
- Where: crates/oraclemcp/src/dispatch/mod.rs:8946; crates/oraclemcp/src/dispatch/tests.rs:9461
- Claim checked: README contract that DDL/Admin statements cannot be rollback-previewed and require commit=true plus confirmation before execution.
- Method: CARGO_TARGET_DIR=target cargo test -p oraclemcp execute_requires_commit_confirmation_for_ddl_without_executing
- Verdict: CLEAN

## [CRITICAL] Failed commit remains commit_in_doubt and does not get repaired by rollback
- Where: crates/oraclemcp/src/dispatch/mod.rs:9256; crates/oraclemcp/src/dispatch/tests.rs:9193
- Claim checked: README contract that a failed commit is never fixed by a follow-up rollback and quarantines the session as commit_in_doubt.
- Method: CARGO_TARGET_DIR=target cargo test -p oraclemcp execute_commit; CARGO_TARGET_DIR=target cargo test -p oraclemcp execute_commit_in_doubt_leaves_durable_intent_unresolved
- Verdict: CLEAN

## [CRITICAL] Unresolved durable write intent fails writable startup closed
- Where: crates/oraclemcp/src/main.rs:1708; crates/oraclemcp/src/main_tests.rs:1104; crates/oraclemcp-core/src/write_intent.rs:428
- Claim checked: README contract that unresolved durable write intent makes writable server startup fail closed with ORACLEMCP_WRITE_INTENT_IN_DOUBT.
- Method: CARGO_TARGET_DIR=target cargo test -p oraclemcp build_write_intent_log_fails_closed_on_unresolved_restart_intent; CARGO_TARGET_DIR=target cargo test -p oraclemcp-core resolved_intent_survives_reopen_and_rejects_same_grant_sql_replay
- Verdict: CLEAN

## [HIGH] Grants are process-local and single-use
- Where: crates/oraclemcp-guard/src/exec_grant.rs:114; crates/oraclemcp-guard/src/exec_grant.rs:215; crates/oraclemcp/src/dispatch/mod.rs:6680
- Claim checked: README contract that execution grants are process-local, single-use, exact-SQL and lane/session/principal/profile/generation bound.
- Method: CARGO_TARGET_DIR=target cargo test -p oraclemcp-guard exec_grant -- --nocapture; CARGO_TARGET_DIR=target cargo test -p oraclemcp the_commit_grant_is_consumed_exactly_once; CARGO_TARGET_DIR=target cargo test -p oraclemcp commit_re_; CARGO_TARGET_DIR=target cargo test -p oraclemcp execute_confirmation_preserves_semantic_whitespace_before_database_io
- Verdict: CLEAN

## [HIGH] Failed or cancelled pooled calls are dirty-discarded
- Where: crates/oraclemcp-db/src/pool.rs:431; crates/oraclemcp-db/src/pool.rs:504; crates/oraclemcp-db/src/pool.rs:755; crates/oraclemcp-db/src/pool.rs:781
- Claim checked: Round 2 lifecycle contract that a cancelled or failed pooled call is DISCARDED and never returned to idle reuse.
- Method: git log --since="8 hours ago" --oneline -- crates/oraclemcp-db crates/oraclemcp/src/dispatch/mod.rs crates/oraclemcp/src/dispatch/tests.rs; CARGO_TARGET_DIR=target cargo test -p oraclemcp-db pool::tests
- Verdict: CLEAN

## [CRITICAL] Commit-in-doubt stays primary and quarantines
- Where: crates/oraclemcp/src/dispatch/mod.rs:9256; crates/oraclemcp/src/dispatch/tests.rs:9193; crates/oraclemcp/src/dispatch/tests.rs:9253; crates/oraclemcp/src/dispatch/tests.rs:10543
- Claim checked: Round 2 lifecycle contract that a failed commit is never fixed by a follow-up rollback and quarantines the session as commit_in_doubt.
- Method: CARGO_TARGET_DIR=target cargo test -p oraclemcp commit_in_doubt
- Verdict: CLEAN

## [HIGH] Preview-DML sandbox proof test is stale under fail-closed catalog gate
- Where: crates/oraclemcp/src/dispatch/tests.rs:14715
- Claim checked: Round 2 lifecycle contract that lease-backed preview DML rolls back to its savepoint after the DML path.
- Method: CARGO_TARGET_DIR=target cargo test -p oraclemcp preview_dml_runs_the_statement_in_a_sandbox_and_rolls_it_back; CARGO_TARGET_DIR=target cargo test -p oraclemcp every_registry_tool_routes_and_deserializes_offline
- Verdict: CONFIRMED DEFECT - the focused sandbox test exits 101 before asserting SAVEPOINT/ROLLBACK because the tightened semantic read gate refuses the test witness with "unresolved semantic read dependency"; the registry smoke test also exits 101 at oracle_query for the same fail-closed catalog reason.

## [HIGH] Preview-DML late-cancellation-after-DML proof is not pinned by passing tests
- Where: crates/oraclemcp/src/dispatch/mod.rs:8505; crates/oraclemcp/src/dispatch/mod.rs:8649; crates/oraclemcp/src/dispatch/mod.rs:8674; crates/oraclemcp/src/dispatch/tests.rs:10437; crates/oraclemcp/src/dispatch/tests.rs:14715
- Claim checked: Round 2 lifecycle contract that lease-backed preview DML rolls back to its savepoint even when cancellation is observed after the DML.
- Method: rg -n "preview_dml.*cancel|cancel.*preview_dml|late cancellation|cancel_on_execute|cancel_on_rollback|OMCP_PREVIEW_DML|ROLLBACK TO SAVEPOINT" crates/oraclemcp/src/dispatch/tests.rs crates/oraclemcp/src/dispatch/mod.rs; CARGO_TARGET_DIR=target cargo test -p oraclemcp rollback_preview_with_late_cancellation_is_not_reported_as_success; CARGO_TARGET_DIR=target cargo test -p oraclemcp preview_dml_runs_the_statement_in_a_sandbox_and_rolls_it_back
- Verdict: UNPROVEN - source drives ROLLBACK TO SAVEPOINT through cleanup after the sandboxed DML future resolves, and the adjacent rollback-preview late-cancellation test passes, but no passing focused test injects cancellation after oracle_preview_dml's DML execute; the ordinary sandbox proof is currently red.

## [HIGH] Oracle NUMBER stays string by default and floats only by explicit opt-in
- Where: README.md:1170; crates/oraclemcp-db/src/serialize.rs:163; crates/oraclemcp-db/src/serialize.rs:497; crates/oraclemcp-db/tests/type_fidelity.rs:21
- Claim checked: Round 3 serialization contract that Oracle NUMBER cells stay JSON strings by default and only become JSON numbers when numbers_as_float=true is explicitly set.
- Method: CARGO_TARGET_DIR=target cargo test -p oraclemcp-db --test type_fidelity
- Verdict: CLEAN

## [HIGH] Structured ARRAY/JSON/VECTOR decode is capped and deep_decode only widens to capped limits
- Where: README.md:1171; crates/oraclemcp-db/src/serialize.rs:95; crates/oraclemcp-db/src/connection.rs:3469; crates/oraclemcp-db/src/connection.rs:3538; crates/oraclemcp-db/src/connection.rs:3820; crates/oraclemcp-db/src/connection.rs:4020; crates/oraclemcp/src/dispatch/mod.rs:3681
- Claim checked: Round 3 serialization contract that structured ARRAY/JSON/VECTOR decode honors row/cell/byte/depth caps, and deep_decode only widens to the larger capped limits.
- Method: CARGO_TARGET_DIR=target cargo test -p oraclemcp-db structured_decode_caps; CARGO_TARGET_DIR=target cargo test -p oraclemcp query_structured_decode_caps_require_deep_decode_for_larger_limits
- Verdict: CLEAN

## [HIGH] Nested REF CURSOR materialization uses separate row cell byte and depth caps
- Where: README.md:921; crates/oraclemcp-db/src/serialize.rs:174; crates/oraclemcp-db/src/serialize.rs:544; crates/oraclemcp-db/src/connection.rs:4202; crates/oraclemcp-db/src/connection.rs:4281; crates/oraclemcp-db/tests/live_oracle.rs:1398
- Claim checked: Round 3 serialization contract that nested REF CURSOR and implicit result materialization respects separate nested cursor row, cell, byte, and depth caps.
- Method: CARGO_TARGET_DIR=target cargo test -p oraclemcp-db nested_result; CARGO_TARGET_DIR=target cargo test -p oraclemcp-db cursor_caps
- Verdict: CLEAN

## [HIGH] Structured unsupported markers carry typed provenance on normal value paths
- Where: README.md:924; crates/oraclemcp-db/src/types.rs:316; crates/oraclemcp-db/src/connection.rs:3799; crates/oraclemcp-db/src/connection.rs:4119; crates/oraclemcp-db/src/connection.rs:4129; crates/oraclemcp-db/tests/structured_schema_golden.rs:126; crates/oraclemcp-db/tests/structured_schema_golden.rs:242
- Claim checked: Round 3 honesty contract that unsupported structured Oracle shapes are reported as typed unsupported markers with provenance rather than flattened or guessed into ordinary-looking placeholders.
- Method: CARGO_TARGET_DIR=target cargo test -p oraclemcp-db --test structured_schema_golden; CARGO_TARGET_DIR=target cargo test -p oraclemcp-db contract_type_unsupported_is_explicit_marker_never_silent
- Verdict: CLEAN

## [HIGH] Non-cursor implicit result values are ordinary placeholder strings
- Where: crates/oraclemcp-db/src/connection.rs:4183
- Claim checked: Round 3 honesty contract that an unsupported shape is reported as a typed unsupported marker with provenance rather than silently flattened or guessed into an ordinary-looking placeholder string.
- Method: rg -n "implicit.*unsupported|unsupported.*implicit|QueryValue::Cursor|QueryValue::Text\(|RETURN_RESULT" crates/oraclemcp-db/src/connection.rs crates/oraclemcp-db/tests; source inspection of crates/oraclemcp-db/src/connection.rs:4160-4192; CARGO_TARGET_DIR=target cargo test -p oraclemcp-db --test structured_schema_golden
- Verdict: CONFIRMED DEFECT - implicit_result_row maps any non-cursor implicit result QueryValue to OracleCell::new("VARCHAR2", Some("<unsupported implicit resultset value ...>")), so the serialized output is an ordinary string and loses the structured unsupported marker/provenance shape used by the normal value paths.
