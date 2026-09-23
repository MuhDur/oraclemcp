use super::*;

const UPDATE: &str = "UPDATE employees SET name = :1 WHERE employee_id = :2";

fn dispatcher() -> (OracleDispatcher, Arc<ExecState>) {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(Arc::clone(&state))),
        Some("action-envelope-test".to_owned()),
        read_write_level(),
    );
    (dispatcher, state)
}

fn confirm(dispatcher: &OracleDispatcher, args: Value) -> String {
    dispatcher
        .dispatch("oracle_preview_sql", args)
        .expect("preview")
        .pointer("/execute_confirmation/confirm")
        .and_then(Value::as_str)
        .expect("confirmation")
        .to_owned()
}

fn assert_repreview(dispatcher: &OracleDispatcher, state: &ExecState, args: Value) {
    let before = state.executed.lock().expect("executed mutex").len();
    let error = dispatcher
        .dispatch("oracle_execute", args)
        .expect_err("different execution envelope must be refused");
    assert_eq!(
        error.error_class,
        ErrorClass::RepreviewRequired,
        "{error:?}"
    );
    assert_eq!(error.statement_outcome, Some(StatementOutcome::NotStarted));
    assert_eq!(state.executed.lock().expect("executed mutex").len(), before);
}

#[test]
fn envelope_matching_sql_and_binds_executes() {
    let (dispatcher, state) = dispatcher();
    let token = confirm(
        &dispatcher,
        json!({"sql": UPDATE, "binds": ["Ada", 7], "commit": true}),
    );
    let result = dispatcher
        .dispatch(
            "oracle_execute",
            json!({"sql": UPDATE, "binds": ["Ada", 7], "commit": true, "confirm": token}),
        )
        .expect("identical envelope executes");
    assert_eq!(result["executed"], true);
    assert_eq!(state.executed.lock().expect("executed mutex").len(), 1);
}

#[test]
fn envelope_commit_flip_repreview_required() {
    let (dispatcher, state) = dispatcher();
    let token = confirm(&dispatcher, json!({"sql": UPDATE, "binds": ["Ada", 7]}));
    assert_repreview(
        &dispatcher,
        &state,
        json!({"sql": UPDATE, "binds": ["Ada", 7], "commit": true, "confirm": token}),
    );
}

#[test]
fn envelope_hold_flip_repreview_required() {
    let (dispatcher, state) = dispatcher();
    dispatcher
        .dispatch("oracle_checkpoint", json!({"name": "before_hold"}))
        .expect("checkpoint opens reversible workspace");
    let token = confirm(&dispatcher, json!({"sql": UPDATE, "binds": ["Ada", 7]}));
    assert_repreview(
        &dispatcher,
        &state,
        json!({"sql": UPDATE, "binds": ["Ada", 7], "hold": true, "confirm": token}),
    );
}

#[test]
fn envelope_bind_value_change_repreview_required() {
    let (dispatcher, state) = dispatcher();
    let token = confirm(
        &dispatcher,
        json!({"sql": UPDATE, "binds": ["Ada", 7], "commit": true}),
    );
    assert_repreview(
        &dispatcher,
        &state,
        json!({"sql": UPDATE, "binds": ["Ada", 8], "commit": true, "confirm": token}),
    );
}

#[test]
fn envelope_bind_type_change_repreview_required() {
    let (dispatcher, state) = dispatcher();
    let token = confirm(
        &dispatcher,
        json!({"sql": UPDATE, "binds": ["Ada", 7], "commit": true}),
    );
    assert_repreview(
        &dispatcher,
        &state,
        json!({"sql": UPDATE, "binds": ["Ada", "7"], "commit": true, "confirm": token}),
    );
}

#[test]
fn envelope_sql_swap_repreview_required() {
    let (dispatcher, state) = dispatcher();
    let token = confirm(
        &dispatcher,
        json!({"sql": UPDATE, "binds": ["Ada", 7], "commit": true}),
    );
    assert_repreview(
        &dispatcher,
        &state,
        json!({"sql": "UPDATE employees SET name = :1 WHERE employee_id = :2 AND active = 1", "binds": ["Ada", 7], "commit": true, "confirm": token}),
    );
}

#[test]
fn envelope_output_caps_change_repreview_required() {
    let (dispatcher, state) = dispatcher();
    let token = confirm(
        &dispatcher,
        json!({"sql": UPDATE, "binds": ["Ada", 7], "commit": true, "dbms_output_max_lines": 50}),
    );
    assert_repreview(
        &dispatcher,
        &state,
        json!({"sql": UPDATE, "binds": ["Ada", 7], "commit": true, "dbms_output_max_lines": 51, "confirm": token}),
    );
}

#[test]
fn envelope_action_kind_mismatch_refused() {
    let sql = "CREATE OR REPLACE VIEW app.v AS SELECT 1 n FROM dual";
    let grants = ExecGrantStore::new();
    let binding = ExecGrantBinding::new("session", "lane", "subject", 1);
    let preview_material = ddl_action_material(sql, ActionKind::CreateOrReplace, None);
    let token = issue_confirmation_grant(
        &grants,
        &binding,
        Some("action-envelope-test"),
        &preview_material,
        OperatingLevel::Ddl,
    );
    let apply_material = ddl_action_material(sql, ActionKind::ExecuteDdlAdmin, None);
    let error = consume_execute_confirmation(
        &apply_material,
        OperatingLevel::Ddl,
        Some("action-envelope-test"),
        &grants,
        &binding,
        Some(&token),
        false,
    )
    .expect_err("a token for another action kind must not execute");
    assert_eq!(error.error_class, ErrorClass::RepreviewRequired);
}

#[test]
fn envelope_cross_tool_action_kind_mismatch_refused_before_database_io() {
    let state = Arc::new(ExecState::default());
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(ExecRecordingMock::new(Arc::clone(&state))),
        Some("action-envelope-test".to_owned()),
        ddl_level(),
    );
    let sql = "CREATE OR REPLACE VIEW emp_v AS SELECT 1 AS id FROM dual";
    let token = confirm(&dispatcher, json!({"sql": sql, "commit": true}));
    let error = dispatcher
        .dispatch(
            "oracle_create_or_replace",
            json!({"source_code": sql, "execute": true, "confirm": token}),
        )
        .expect_err("generic SQL approval cannot authorize a different action kind");
    assert_eq!(error.error_class, ErrorClass::RepreviewRequired);
    assert!(state.executed.lock().expect("executed mutex").is_empty());
}

fn grant_generation(dispatcher: &OracleDispatcher) -> u64 {
    RuntimeBuilder::current_thread()
        .build()
        .expect("asupersync test runtime")
        .block_on(async {
            let cx = Cx::current().expect("current Cx");
            dispatcher
                .state
                .lock(&cx)
                .await
                .expect("dispatcher lock")
                .grant_generation
        })
}

fn assert_alter_session_invalidates_confirmation(sql: &str) {
    let (dispatcher, state) = dispatcher();
    let old_token = confirm(&dispatcher, json!({"sql": UPDATE, "commit": true}));
    let alter_token = confirm(&dispatcher, json!({"sql": sql}));
    let before = grant_generation(&dispatcher);
    let result = dispatcher
        .dispatch(
            "oracle_execute",
            json!({"sql": sql, "confirm": alter_token}),
        )
        .expect("allowlisted ALTER SESSION executes");
    assert_eq!(result["executed"], true);
    assert_eq!(grant_generation(&dispatcher), before + 1);
    let error = dispatcher
        .dispatch(
            "oracle_execute",
            json!({"sql": UPDATE, "commit": true, "confirm": old_token}),
        )
        .expect_err("old confirmation must be invalidated");
    assert!(matches!(
        error.error_class,
        ErrorClass::ChallengeRequired | ErrorClass::RepreviewRequired
    ));
    assert_eq!(state.executed.lock().expect("executed mutex").len(), 1);
}

#[test]
fn alter_session_nls_bumps_generation_and_invalidates_confirmations() {
    assert_alter_session_invalidates_confirmation(
        "ALTER SESSION SET NLS_DATE_FORMAT = 'YYYY-MM-DD'",
    );
}

#[test]
fn alter_session_current_schema_bumps_generation() {
    assert_alter_session_invalidates_confirmation("ALTER SESSION SET CURRENT_SCHEMA = APP");
}

#[test]
fn bind_redaction_canary_absent_from_audit_and_logs() {
    use oraclemcp_audit::{
        AuditError, AuditRecord, AuditSink, Auditor, MemoryAuditSink, SigningKey,
    };
    use std::io::Write;

    struct SharedSink(Arc<MemoryAuditSink>);
    impl AuditSink for SharedSink {
        fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.0.append(record)
        }

        fn flush(&self) -> Result<(), AuditError> {
            self.0.flush()
        }
    }

    struct LogWriter(Arc<Mutex<Vec<u8>>>);
    impl Write for LogWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("log buffer").extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let canary = "OMCP_SYNTHETIC_BIND_CANARY_7F1C";
    let sink = Arc::new(MemoryAuditSink::new());
    let auditor = Arc::new(Auditor::new(
        Box::new(SharedSink(Arc::clone(&sink))),
        SigningKey::new(
            "envelope-test-key",
            b"envelope-redaction-test-key-123456".to_vec(),
        )
        .expect("valid signing key"),
    ));
    let logs = Arc::new(Mutex::new(Vec::new()));
    let logs_for_writer = Arc::clone(&logs);
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || LogWriter(Arc::clone(&logs_for_writer)))
        .with_ansi(false)
        .finish();
    let _log_scope = tracing::subscriber::set_default(subscriber);
    let (dispatcher, state) = dispatcher();
    let dispatcher = dispatcher.with_auditor(auditor);
    let preview = dispatcher
        .dispatch(
            "oracle_preview_sql",
            json!({"sql": UPDATE, "binds": [canary, 7], "commit": true}),
        )
        .expect("preview");
    let token = preview["execute_confirmation"]["confirm"]
        .as_str()
        .expect("confirmation");
    let result = dispatcher
        .dispatch(
            "oracle_execute",
            json!({"sql": UPDATE, "binds": [canary, 7], "commit": true, "confirm": token}),
        )
        .expect("execution");
    assert_eq!(state.executed.lock().expect("executed mutex").len(), 1);
    assert!(
        !sink.records().is_empty(),
        "execution must emit an audit record"
    );
    assert!(!preview.to_string().contains(canary));
    assert!(!result.to_string().contains(canary));
    assert!(!format!("{:?}", sink.records()).contains(canary));
    assert!(
        !String::from_utf8(logs.lock().expect("log buffer").clone())
            .expect("UTF-8 logs")
            .contains(canary)
    );
}

#[test]
fn preview_strict_decoding_rejects_unknown_envelope_member() {
    let (dispatcher, state) = dispatcher();
    let error = dispatcher
        .dispatch(
            "oracle_preview_sql",
            json!({"sql": UPDATE, "bind_typo": "canary"}),
        )
        .expect_err("unknown member must be refused");
    assert_eq!(error.error_class, ErrorClass::InvalidArguments);
    assert!(state.executed.lock().expect("executed mutex").is_empty());
}
