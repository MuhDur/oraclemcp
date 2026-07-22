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
