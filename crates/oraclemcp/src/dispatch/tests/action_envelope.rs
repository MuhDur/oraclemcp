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
    let preview_material = oraclemcp_guard::GrantMaterial::new(
        &preview_material,
        &local_impact(
            &preview_material,
            ImpactGenerations {
                profile: binding.generation,
                lane: binding.generation,
            },
        ),
    )
    .unwrap();
    let token = issue_confirmation_grant(
        &grants,
        &binding,
        Some("action-envelope-test"),
        &preview_material,
        OperatingLevel::Ddl,
    );
    let apply_material = ddl_action_material(sql, ActionKind::ExecuteDdlAdmin, None);
    let apply_material = oraclemcp_guard::GrantMaterial::new(
        &apply_material,
        &local_impact(
            &apply_material,
            ImpactGenerations {
                profile: binding.generation,
                lane: binding.generation,
            },
        ),
    )
    .unwrap();
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

#[cfg(not(feature = "plsql-intelligence"))]
#[test]
fn envelope_cross_tool_action_kind_mismatch_refused_before_database_io() {
    let source = "CREATE OR REPLACE VIEW emp_v AS SELECT 1 AS id FROM dual";
    assert_engine_free_compile_counterpart(&[
        ("oracle_preview_sql", json!({"sql":source,"commit":true})),
        ("oracle_create_or_replace", json!({"source_code":source})),
    ]);
}

#[cfg(feature = "plsql-intelligence")]
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
    // ALTER SESSION revokes the old generation and clears its grants; this is
    // a revoked reference, distinct from a live grant whose facts drifted.
    assert_eq!(error.error_class, ErrorClass::ChallengeRequired);
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

/// QA85: cancellation and secondary-finalization failures at a mutation's
/// terminal boundary must never invite an unsafe retry or let a preview escape
/// its request cancellation.
mod qa85_terminal_boundaries {
    use super::*;
    use oraclemcp_audit::{
        AuditError, AuditOutcome, AuditRecord, AuditSink, Auditor, MemoryAuditSink, SigningKey,
    };
    use std::task::Poll;

    struct SharedSink(Arc<MemoryAuditSink>);

    impl AuditSink for SharedSink {
        fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.0.append(record)
        }

        fn flush(&self) -> Result<(), AuditError> {
            self.0.flush()
        }
    }

    fn auditor_with_sink() -> (Arc<Auditor>, Arc<MemoryAuditSink>) {
        let sink = Arc::new(MemoryAuditSink::new());
        let auditor = Arc::new(Auditor::new(
            Box::new(SharedSink(Arc::clone(&sink))),
            SigningKey::new(
                "qa85-test-key",
                b"qa85-terminal-boundary-key-12345".to_vec(),
            )
            .expect("valid test key"),
        ));
        (auditor, sink)
    }

    struct FailAfterFirstAppendSink {
        inner: Arc<MemoryAuditSink>,
        appends: Arc<AtomicUsize>,
    }

    impl AuditSink for FailAfterFirstAppendSink {
        fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
            let append_index = self.appends.fetch_add(1, Ordering::SeqCst);
            if append_index > 0 {
                return Err(AuditError::Io(
                    "injected terminal audit sink failure".to_owned(),
                ));
            }
            self.inner.append(record)
        }

        fn flush(&self) -> Result<(), AuditError> {
            self.inner.flush()
        }
    }

    struct CancelOnAppendSink {
        inner: Arc<MemoryAuditSink>,
        cx: Cx,
    }

    impl AuditSink for CancelOnAppendSink {
        fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
            self.inner.append(record)?;
            self.cx.set_cancel_requested(true);
            Ok(())
        }

        fn flush(&self) -> Result<(), AuditError> {
            self.inner.flush()
        }
    }

    fn level_and_generation(dispatcher: &OracleDispatcher) -> (OperatingLevel, u64) {
        RuntimeBuilder::current_thread()
            .build()
            .expect("asupersync test runtime builds")
            .block_on(async {
                let cx = Cx::current().expect("block_on installs a current Cx");
                let state = dispatcher
                    .state
                    .lock(&cx)
                    .await
                    .expect("dispatcher state lock");
                (state.level.effective_level(), state.grant_generation)
            })
    }

    #[cfg(feature = "plsql-intelligence")]
    fn assert_uncertain_ddl_preflight_aborts(case: &str, tool: &str, mut args: Value) {
        let state = Arc::new(ExecState::default());
        let intents = write_intent_log(case);
        let (auditor, sink) = auditor_with_sink();
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            ddl_level(),
        )
        .with_auditor(auditor)
        .with_write_intent_log(Arc::clone(&intents));

        let preview = dispatcher
            .dispatch(tool, args.clone())
            .unwrap_or_else(|error| panic!("{case}: preview failed: {error:?}"));
        let confirm = preview["confirmation"]["confirm"]
            .as_str()
            .unwrap_or_else(|| panic!("{case}: preview did not mint confirmation"))
            .to_owned();
        *state.describe_error.lock().expect("describe error mutex") = Some(DbError::Cancelled(
            format!("{case}: injected evidence cancellation"),
        ));
        args["execute"] = json!(true);
        args["confirm"] = json!(confirm);

        let error = match dispatcher.dispatch(tool, args) {
            Ok(value) => panic!("{case}: uncertain evidence unexpectedly applied: {value}"),
            Err(error) => error,
        };
        assert_eq!(error.error_class, ErrorClass::ConnectionFailed, "{case}");
        assert!(
            error.message.contains("unknown_discarded"),
            "{case}: {error:?}"
        );
        assert!(
            state.executed.lock().expect("exec mutex").is_empty(),
            "{case}: evidence uncertainty must stop before DDL execution"
        );
        assert!(
            sink.records().is_empty(),
            "{case}: Pending audit must not be written"
        );
        assert!(
            intents.unresolved().expect("intent snapshot").is_empty(),
            "{case}: pre-execute failure must resolve the durable intent"
        );
        let ledger = std::fs::read_to_string(intents.path().expect("intent path"))
            .expect("intent ledger is readable");
        assert!(
            ledger.contains("ABORTED_BEFORE_EXECUTE"),
            "{case}: terminal intent resolution must distinguish pre-execute abort: {ledger}"
        );
        let quarantine = dispatcher
            .connection_quarantine()
            .expect("quarantine lock")
            .expect("uncertain preflight quarantines");
        assert_eq!(quarantine.outcome, AuditOutcome::UnknownDiscarded, "{case}");
    }

    #[test]
    fn cancelled_profile_prepare_cannot_cross_switch_commit_point() {
        let candidate = Arc::new(ExecState::default());
        candidate.cancel_on_describe.store(1, Ordering::SeqCst);
        let connector_state = Arc::clone(&candidate);
        let dispatcher = OracleDispatcher::new_switchable(
            Box::new(OneRowMock),
            Some("dev".to_owned()),
            default_read_only_level(),
            Arc::new(move |_cx, _profile| {
                let state = Arc::clone(&connector_state);
                Box::pin(async move { Ok(session_bundle(ExecRecordingMock::new(state))) })
            }),
        );
        let before = level_and_generation(&dispatcher);

        let error = dispatcher
            .dispatch("oracle_switch_profile", json!({ "profile": "other" }))
            .expect_err("cancellation during candidate metadata aborts before switch commit");
        assert_eq!(error.error_class, ErrorClass::Timeout);
        assert_eq!(level_and_generation(&dispatcher), before);
        assert_eq!(candidate.describe_calls.load(Ordering::SeqCst), 1);

        let active = dispatcher
            .dispatch("oracle_connection_info", json!({}))
            .expect("old profile remains usable after aborted switch");
        assert_eq!(active["active_profile"], json!("dev"));
    }

    #[test]
    fn dropped_elevation_evidence_future_cannot_mutate_live_authority() {
        let state = Arc::new(ExecState::default());
        let (auditor, sink) = auditor_with_sink();
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            SessionLevelState::new(OperatingLevel::ReadWrite, false),
        )
        .with_auditor(auditor);
        let preview = dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({ "level": "READ_WRITE", "ttl_seconds": 60 }),
            )
            .expect("preview elevation");
        let confirm = preview["confirmation"]["confirm"]
            .as_str()
            .expect("elevation grant")
            .to_owned();
        let before = level_and_generation(&dispatcher);
        state.describe_pending.store(1, Ordering::SeqCst);

        RuntimeBuilder::current_thread()
            .build()
            .expect("asupersync test runtime builds")
            .block_on(async {
                let cx = Cx::current().expect("block_on installs a current Cx");
                let mut apply = ToolDispatch::dispatch(
                    &dispatcher,
                    &cx,
                    DispatchContext::default(),
                    "oracle_set_session_level",
                    json!({
                        "level": "READ_WRITE",
                        "ttl_seconds": 60,
                        "execute": true,
                        "confirm": confirm,
                    }),
                );
                std::future::poll_fn(|task_cx| match apply.as_mut().poll(task_cx) {
                    Poll::Ready(outcome) => {
                        panic!("pending evidence dispatch unexpectedly completed: {outcome:?}")
                    }
                    Poll::Pending if state.describe_calls.load(Ordering::SeqCst) > 0 => {
                        Poll::Ready(())
                    }
                    Poll::Pending => {
                        task_cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                })
                .await;
                drop(apply);
            });

        state.describe_pending.store(0, Ordering::SeqCst);
        assert_eq!(level_and_generation(&dispatcher), before);
        assert!(
            sink.records().is_empty(),
            "no successful elevation audit exists, so live authority must stay unchanged"
        );
        let retry = dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({
                    "level": "READ_WRITE",
                    "ttl_seconds": 60,
                    "execute": true,
                    "confirm": confirm,
                }),
            )
            .expect_err("a staged transition still consumes its single-use confirmation");
        assert_eq!(retry.error_class, ErrorClass::ChallengeRequired);
    }

    #[test]
    fn uncertain_elevation_evidence_cannot_mutate_level_or_generation() {
        let state = Arc::new(ExecState::default());
        let (auditor, sink) = auditor_with_sink();
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            SessionLevelState::new(OperatingLevel::ReadWrite, false),
        )
        .with_auditor(auditor);
        let preview = dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({ "level": "READ_WRITE", "ttl_seconds": 60 }),
            )
            .expect("preview elevation");
        let confirm = preview["confirmation"]["confirm"]
            .as_str()
            .expect("elevation grant")
            .to_owned();
        let before = level_and_generation(&dispatcher);
        *state.describe_error.lock().expect("describe error mutex") = Some(DbError::Cancelled(
            "injected elevation evidence cancellation".to_owned(),
        ));

        let error = dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({
                    "level": "READ_WRITE",
                    "ttl_seconds": 60,
                    "execute": true,
                    "confirm": confirm,
                }),
            )
            .expect_err("uncertain evidence refuses elevation");
        assert_eq!(error.error_class, ErrorClass::ConnectionFailed);
        assert!(error.message.contains("unknown_discarded"), "{error:?}");
        assert_eq!(level_and_generation(&dispatcher), before);
        assert!(sink.records().is_empty());
        assert_eq!(
            dispatcher
                .connection_quarantine()
                .expect("quarantine lock")
                .expect("uncertain evidence quarantines")
                .outcome,
            AuditOutcome::UnknownDiscarded
        );
    }

    #[test]
    fn streaming_dispatch_preserves_durably_audited_elevation_after_late_cancellation() {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("asupersync test runtime builds");
        runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            let sink = Arc::new(MemoryAuditSink::new());
            let auditor = Arc::new(Auditor::new(
                Box::new(CancelOnAppendSink {
                    inner: Arc::clone(&sink),
                    cx: cx.clone(),
                }),
                SigningKey::new(
                    "qa85-test-key",
                    b"qa85-cancel-after-elevation-audit".to_vec(),
                )
                .expect("valid test key"),
            ));
            let dispatcher = OracleDispatcher::new_with_profile_level(
                Box::new(ExecRecordingMock::new(Arc::new(ExecState::default()))),
                Some("dev".to_owned()),
                SessionLevelState::new(OperatingLevel::ReadWrite, false),
            )
            .with_auditor(auditor);
            let preview = match ToolDispatch::dispatch(
                &dispatcher,
                &cx,
                DispatchContext::default(),
                "oracle_set_session_level",
                json!({ "level": "READ_WRITE", "ttl_seconds": 60 }),
            )
            .await
            {
                Outcome::Ok(value) => value,
                other => panic!("elevation preview failed: {other:?}"),
            };
            let confirm = preview["confirmation"]["confirm"]
                .as_str()
                .expect("elevation grant")
                .to_owned();
            let before_generation = dispatcher
                .state
                .lock(&cx)
                .await
                .expect("dispatcher state lock")
                .grant_generation;
            let (frames_tx, _frames_rx) = mpsc::channel(1);
            let outcome = ToolDispatch::dispatch_stream(
                &dispatcher,
                &cx,
                DispatchContext::default(),
                "oracle_set_session_level",
                json!({
                    "level": "READ_WRITE",
                    "ttl_seconds": 60,
                    "execute": true,
                    "confirm": confirm,
                }),
                frames_tx,
            )
            .await;
            let value = match outcome {
                Outcome::Ok(value) => value,
                other => panic!("terminal elevation must win late cancellation: {other:?}"),
            };
            assert_eq!(value["changed"], json!(true));
            assert_eq!(value["session"]["current_level"], json!("READ_WRITE"));
            assert_eq!(value["deadline_observed_after_effect"], json!(true));
            let records = sink.records();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].outcome, AuditOutcome::Succeeded);

            cx.set_cancel_requested(false);
            let state = dispatcher
                .state
                .lock(&cx)
                .await
                .expect("dispatcher state lock after clearing test cancellation");
            assert_eq!(state.level.effective_level(), OperatingLevel::ReadWrite);
            assert!(state.grant_generation > before_generation);
        });
    }

    #[cfg(not(feature = "plsql-intelligence"))]
    #[test]
    fn ddl_mutators_resolve_uncertain_evidence_as_aborted_before_execute() {
        assert_engine_free_compile_counterpart(&[
            (
                "oracle_compile_object",
                json!({"owner":"APP","object_type":"PACKAGE","name":"EMP_API"}),
            ),
            (
                "oracle_create_or_replace",
                json!({"source_code":"CREATE OR REPLACE VIEW EMP_V AS SELECT 1 AS ID FROM dual"}),
            ),
            (
                "oracle_patch_source",
                json!({"owner":"APP","name":"EMP_API","object_type":"PACKAGE_BODY","old_text":"NULL","new_text":"NULL /* patched */"}),
            ),
        ]);
    }

    #[cfg(feature = "plsql-intelligence")]
    #[test]
    fn ddl_mutators_resolve_uncertain_evidence_as_aborted_before_execute() {
        assert_uncertain_ddl_preflight_aborts(
            "qa85-compile-evidence-cancel",
            "oracle_compile_object",
            json!({ "owner": "APP", "object_type": "PACKAGE", "name": "EMP_API" }),
        );
        assert_uncertain_ddl_preflight_aborts(
            "qa85-create-evidence-cancel",
            "oracle_create_or_replace",
            json!({
                "source_code": "CREATE OR REPLACE VIEW EMP_V AS SELECT 1 AS ID FROM dual"
            }),
        );
        assert_uncertain_ddl_preflight_aborts(
            "qa85-patch-evidence-cancel",
            "oracle_patch_source",
            json!({
                "owner": "APP",
                "name": "EMP_API",
                "object_type": "PACKAGE_BODY",
                "old_text": "NULL",
                "new_text": "NULL /* patched */"
            }),
        );
    }

    #[test]
    fn uncertain_dbms_output_setup_aborts_before_main_execute() {
        let state = Arc::new(ExecState::default());
        *state
            .dbms_output_enable_error
            .lock()
            .expect("DBMS_OUTPUT enable error mutex") = Some(DbError::Cancelled(
            "injected DBMS_OUTPUT setup cancellation".to_owned(),
        ));
        let intents = write_intent_log("qa85-dbms-output-enable-cancel");
        let (auditor, sink) = auditor_with_sink();
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            read_write_level(),
        )
        .with_auditor(auditor)
        .with_write_intent_log(Arc::clone(&intents));
        let sql = "BEGIN SYS.DBMS_OUTPUT.PUT_LINE('never-ran'); END;";
        let confirm = preview_confirm_with_args(
            &dispatcher,
            json!({ "sql": sql, "commit": true, "dbms_output": true }),
        );

        let error = dispatcher
            .dispatch(
                "oracle_execute",
                json!({
                    "sql": sql,
                    "commit": true,
                    "confirm": confirm,
                    "dbms_output": true,
                }),
            )
            .expect_err("uncertain DBMS_OUTPUT setup must fail closed");
        assert_eq!(error.error_class, ErrorClass::ConnectionFailed);
        assert!(error.message.contains("unknown_discarded"), "{error:?}");
        assert_eq!(state.dbms_output_enabled.load(Ordering::SeqCst), 1);
        assert!(
            state.executed.lock().expect("exec mutex").is_empty(),
            "the approved statement must not run after DBMS_OUTPUT setup uncertainty"
        );
        assert_eq!(state.commits.load(Ordering::SeqCst), 0);
        assert_eq!(state.rollbacks.load(Ordering::SeqCst), 0);
        let records = sink.records();
        assert_eq!(records.len(), 2, "Pending plus terminal uncertainty");
        assert_eq!(records[0].outcome, AuditOutcome::Pending);
        assert_eq!(records[1].outcome, AuditOutcome::UnknownDiscarded);
        assert!(intents.unresolved().expect("intent snapshot").is_empty());
        let ledger = std::fs::read_to_string(intents.path().expect("intent path"))
            .expect("intent ledger is readable");
        assert!(ledger.contains("ABORTED_BEFORE_EXECUTE"), "{ledger}");
    }

    #[test]
    fn confirmed_commit_survives_late_cancellation_and_finalizes_durable_records() {
        let state = Arc::new(ExecState::default());
        state.cancel_on_commit.store(1, Ordering::SeqCst);
        let intents = write_intent_log("qa85-late-cancel-after-commit");
        let (auditor, sink) = auditor_with_sink();
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            read_write_level(),
        )
        .with_auditor(auditor)
        .with_write_intent_log(Arc::clone(&intents));
        let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
        let confirm = preview_confirm(&dispatcher, sql);

        run_with_current_cx(|cx| {
            let out = dispatcher
                .dispatch_with_cx(
                    cx,
                    "oracle_execute",
                    json!({ "sql": sql, "commit": true, "confirm": confirm }),
                )
                .expect("a confirmed commit remains successful after late cancellation");
            assert_eq!(out["executed"], json!(true));
            assert_eq!(out["committed"], json!(true));
            assert_eq!(out["deadline_observed_after_effect"], json!(true));
        });

        assert_eq!(state.commits.load(Ordering::SeqCst), 1);
        assert!(
            intents.unresolved().expect("intent snapshot").is_empty(),
            "known commit success resolves the durable write intent"
        );
        let records = sink.records();
        assert_eq!(records.len(), 2, "pending plus terminal audit record");
        assert_eq!(records[0].outcome, AuditOutcome::Pending);
        assert_eq!(records[1].outcome, AuditOutcome::Succeeded);
    }

    #[test]
    fn rollback_preview_with_late_cancellation_is_not_reported_as_success() {
        let state = Arc::new(ExecState::default());
        state.cancel_on_rollback.store(1, Ordering::SeqCst);
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            read_write_level(),
        );
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("asupersync test runtime builds");
        let outcome = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            ToolDispatch::dispatch(
                &dispatcher,
                &cx,
                DispatchContext::default(),
                "oracle_execute",
                json!({
                    "sql": "UPDATE employees SET name = name WHERE employee_id = 100",
                    "commit": false,
                }),
            )
            .await
        });

        assert!(
            matches!(outcome, Outcome::Cancelled(_)),
            "rollback-only execution is a cancellable preview, got {outcome:?}"
        );
        assert_eq!(state.commits.load(Ordering::SeqCst), 0);
        assert_eq!(state.rollbacks.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn issue49_cancel_successful_rollback_preserves_transaction_proof() {
        for failure in [
            DbError::Execute("ORA-01013: user requested cancel of current operation".to_owned()),
            DbError::Cancelled("driver break acknowledged".to_owned()),
        ] {
            let state = Arc::new(ExecState::default());
            *state.execute_error.lock().expect("execute error mutex") = Some(failure);
            let (auditor, sink) = auditor_with_sink();
            let dispatcher = OracleDispatcher::new_with_profile_level(
                Box::new(ExecRecordingMock::new(Arc::clone(&state))),
                Some("dev".to_owned()),
                read_write_level(),
            )
            .with_auditor(auditor);
            let args = json!({ "sql": "UPDATE employees SET name = name WHERE employee_id = 100", "commit": false });
            let error = dispatcher
                .dispatch("oracle_execute", args.clone())
                .expect_err("cancelled update does not return success");
            assert_eq!(error.statement_outcome, Some(StatementOutcome::RolledBack));
            assert_eq!(state.rollbacks.load(Ordering::SeqCst), 1);
            assert_eq!(state.commits.load(Ordering::SeqCst), 0);
            assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);
            let records = sink.records();
            assert_eq!(records.len(), 2);
            assert_eq!(records[0].outcome, AuditOutcome::Pending);
            assert_eq!(records[1].outcome, AuditOutcome::RolledBack);
            assert_eq!(
                dispatcher
                    .connection_quarantine()
                    .expect("quarantine lock")
                    .expect("uncertain wire stays quarantined")
                    .outcome,
                AuditOutcome::RolledBack
            );
            let retry = dispatcher
                .dispatch("oracle_execute", args)
                .expect_err("quarantine prevents replay despite known rollback");
            assert_eq!(retry.error_class, ErrorClass::RuntimeStateRequired);
            assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);
        }
    }

    #[test]
    fn issue49_cancel_rollback_failure_quarantines_connection() {
        let state = Arc::new(ExecState::default());
        *state.execute_error.lock().expect("execute error mutex") = Some(DbError::Cancelled(
            "driver break acknowledged the blocked update".to_owned(),
        ));
        *state.rollback_error.lock().expect("rollback error mutex") = Some(DbError::Query(
            "rollback drain was not confirmed".to_owned(),
        ));
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            read_write_level(),
        );
        let sql = "UPDATE employees SET name = name WHERE employee_id = 100";

        let error = dispatcher
            .dispatch("oracle_execute", json!({ "sql": sql, "commit": false }))
            .expect_err("unconfirmed cancellation cleanup must refuse a result");
        assert_eq!(error.error_class, ErrorClass::ConnectionFailed);
        assert_eq!(state.rollbacks.load(Ordering::SeqCst), 1);
        assert_eq!(
            error.statement_outcome,
            Some(StatementOutcome::ProtocolUnsynchronized)
        );
        assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);
        let quarantine = dispatcher
            .connection_quarantine()
            .expect("quarantine lock")
            .expect("failed cancellation rollback quarantines the pinned connection");
        assert_eq!(quarantine.outcome, AuditOutcome::UnknownDiscarded);

        let retry = dispatcher
            .dispatch("oracle_execute", json!({ "sql": sql, "commit": false }))
            .expect_err("a quarantined cancelled mutation must never be replayed");
        assert_eq!(retry.error_class, ErrorClass::RuntimeStateRequired);
    }

    /// F-DI1: a held statement's effect already ran inside the open workspace
    /// transaction (Arc I) — pending, but real. Before the fix,
    /// `response_reports_terminal_effect` judged a `hold=true` result
    /// non-terminal (it only checked `committed`/`non_transactional_effect`),
    /// so a late client cancellation was reported as `Cancelled` even though
    /// the DML had already executed and was sitting in the workspace. An
    /// agent that reasonably retries after a `Cancelled` result would then
    /// call `oracle_execute(hold=true, ...)` again and apply the SAME
    /// statement a second time on top of the still-pending first one — a
    /// held-execute double-apply. The fix adds `held` to the terminal check;
    /// this test proves the late-cancelled held call now completes honestly.
    #[test]
    fn held_execute_survives_late_cancellation_and_is_not_reported_as_cancelled() {
        let state = Arc::new(ExecState::default());
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            read_write_level(),
        );
        dispatcher
            .dispatch("oracle_checkpoint", json!({ "name": "before_change" }))
            .expect("checkpoint opens the workspace");

        let held_sql = "UPDATE employees SET salary = salary * 2 WHERE employee_id = :1";
        let held_confirm = preview_hold_confirm(&dispatcher, held_sql, json!([100]));

        // Only the held DML's execute (not the checkpoint's SAVEPOINT) should
        // observe a late cancellation.
        state.cancel_on_execute.store(1, Ordering::SeqCst);

        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("asupersync test runtime builds");
        let outcome = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            ToolDispatch::dispatch(
                &dispatcher,
                &cx,
                DispatchContext::default(),
                "oracle_execute",
                json!({
                    "sql": "UPDATE employees SET salary = salary * 2 WHERE employee_id = :1",
                    "binds": [100],
                    "hold": true,
                    "confirm": held_confirm,
                }),
            )
            .await
        });

        let Outcome::Ok(value) = outcome else {
            panic!(
                "a held statement's effect already ran and must not be reported as cancelled, got {outcome:?}"
            );
        };
        assert_eq!(value["executed"], json!(true));
        assert_eq!(value["held"], json!(true));
        assert_eq!(value["committed"], json!(false));
        assert_eq!(
            state.executed.lock().expect("exec mutex").len(),
            2,
            "the checkpoint SAVEPOINT plus exactly one held DML execution"
        );
        assert_eq!(
            state.commits.load(Ordering::SeqCst),
            0,
            "holding never commits"
        );
        assert_eq!(
            state.rollbacks.load(Ordering::SeqCst),
            0,
            "holding must not end the transaction"
        );
    }

    /// Model a naive MCP client that retries a tool call whenever it observes a
    /// retryable `Cancelled`. The `attempts < 4` cap keeps a terminal-effect
    /// regression from hanging the suite: if a call whose database effect had
    /// already succeeded were (wrongly) reported `Cancelled`, this loop would
    /// re-dispatch it — re-applying the effect on each pass — until the cap, and
    /// the caller's execution-count assertion would then fail loudly. With the
    /// DI1/DI6 terminal-effect recognition the succeeded effect is reported `Ok`,
    /// so the loop stops after exactly one dispatch. Returns (attempts, final
    /// outcome). This drives the SAME async boundary the server uses
    /// (`ToolDispatch::dispatch`), where the `cx.is_cancel_requested() &&
    /// !terminal_result` decision lives — the sync `dispatch` helper bypasses it.
    async fn cancel_retry_loop(
        dispatcher: &OracleDispatcher,
        cx: &Cx,
        name: &str,
        args: Value,
    ) -> (u32, Outcome<Value, ErrorEnvelope>) {
        let mut attempts = 0u32;
        loop {
            attempts += 1;
            let outcome = ToolDispatch::dispatch(
                dispatcher,
                cx,
                DispatchContext::default(),
                name,
                args.clone(),
            )
            .await;
            if matches!(outcome, Outcome::Cancelled(_)) && attempts < 4 {
                // The client clears its cancellation and retries — precisely the
                // behavior the terminal-effect fix exists to make unnecessary.
                cx.set_cancel_requested(false);
                continue;
            }
            return (attempts, outcome);
        }
    }

    /// F-DI1 double-apply regression guard, driven through the naive retry loop
    /// the fix exists to stop. A held `oracle_execute` runs its DML on the wire,
    /// then the request deadline elapses during finalization (`cancel_on_execute`
    /// sets the cancel bit AFTER the wire effect returns, exactly as an outer
    /// deadline would). A client that retries on `Cancelled` would re-apply the
    /// held DML on top of the still-pending first one. Because the succeeded held
    /// effect is TERMINAL, the first dispatch returns `Ok`, the loop stops at
    /// attempt 1, and the DML is applied EXACTLY once. Were the terminal
    /// recognition to regress, attempt 1 would be `Cancelled`, the loop would
    /// retry, and `executed` would grow past the single held application.
    #[test]
    fn held_execute_deadline_boundary_retry_loop_applies_exactly_once() {
        let state = Arc::new(ExecState::default());
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            read_write_level(),
        );
        dispatcher
            .dispatch("oracle_checkpoint", json!({ "name": "before_change" }))
            .expect("checkpoint opens the workspace");

        let held_sql = "UPDATE employees SET salary = salary * 2 WHERE employee_id = :1";
        let held_confirm = preview_hold_confirm(&dispatcher, held_sql, json!([100]));

        // From here every execute reports success on the wire and THEN trips the
        // request deadline — the finalization-window race the fix addresses.
        state.cancel_on_execute.store(1, Ordering::SeqCst);

        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("asupersync test runtime builds");
        let (attempts, outcome) = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            cancel_retry_loop(
                &dispatcher,
                &cx,
                "oracle_execute",
                json!({
                    "sql": "UPDATE employees SET salary = salary * 2 WHERE employee_id = :1",
                    "binds": [100],
                    "hold": true,
                    "confirm": held_confirm,
                }),
            )
            .await
        });

        assert_eq!(
            attempts, 1,
            "a succeeded held effect is terminal; the retry loop must stop after the first dispatch"
        );
        let Outcome::Ok(value) = outcome else {
            panic!(
                "the terminal held effect must be reported Ok, not a retryable Cancelled: {outcome:?}"
            );
        };
        assert_eq!(value["executed"], json!(true));
        assert_eq!(value["held"], json!(true));
        assert_eq!(value["committed"], json!(false));
        assert_eq!(
            state.executed.lock().expect("exec mutex").len(),
            2,
            "the checkpoint SAVEPOINT plus EXACTLY ONE held DML execution — no double-apply"
        );
        assert_eq!(
            state.commits.load(Ordering::SeqCst),
            0,
            "holding never commits"
        );
        assert_eq!(
            state.rollbacks.load(Ordering::SeqCst),
            0,
            "holding must not end the transaction"
        );
    }

    /// F-DI6 double-apply regression guard for `oracle_undo_to`, the strongest of
    /// the three: `ROLLBACK TO SAVEPOINT` KEEPS its savepoint (Oracle semantics,
    /// mirrored by `commit_undo_to`), so a naive retry of the same undo genuinely
    /// re-runs the rollback — a real double-apply, not merely a redundant call.
    /// The rollback reaches Oracle and THEN the deadline trips. Because a taken
    /// undo is TERMINAL, the first dispatch returns `Ok`, the loop stops, and the
    /// `ROLLBACK TO SAVEPOINT` ran exactly once.
    #[test]
    fn undo_deadline_boundary_retry_loop_rolls_back_exactly_once() {
        let state = Arc::new(ExecState::default());
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            read_write_level(),
        );
        dispatcher
            .dispatch("oracle_checkpoint", json!({ "name": "cp1" }))
            .expect("checkpoint opens the workspace");

        // The undo's ROLLBACK reaches Oracle, then the deadline trips.
        state.cancel_on_execute.store(1, Ordering::SeqCst);

        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("asupersync test runtime builds");
        let (attempts, outcome) = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            cancel_retry_loop(&dispatcher, &cx, "oracle_undo_to", json!({ "name": "cp1" })).await
        });

        assert_eq!(
            attempts, 1,
            "a taken ROLLBACK TO SAVEPOINT is terminal; the retry loop must not re-run it"
        );
        let Outcome::Ok(value) = outcome else {
            panic!("a taken undo must be reported Ok, not a retryable Cancelled: {outcome:?}");
        };
        // Oracle identifiers are normalized to upper case by the checkpoint-name
        // validator, so the round-tripped name and statement come back upper-cased.
        assert_eq!(value["undone_to"], json!("CP1"));
        assert_eq!(value["statement"], json!("ROLLBACK TO SAVEPOINT CP1"));
        assert_eq!(
            state.executed.lock().expect("exec mutex").len(),
            2,
            "the SAVEPOINT plus EXACTLY ONE ROLLBACK TO SAVEPOINT — the undo ran once"
        );
        assert_eq!(
            state.commits.load(Ordering::SeqCst),
            0,
            "undo never commits"
        );
    }

    /// F-DI6 double-apply regression guard for `oracle_checkpoint`: the SAVEPOINT
    /// reaches Oracle and THEN the deadline trips. An established SAVEPOINT is
    /// TERMINAL, so the first dispatch returns `Ok` and the retry loop stops — the
    /// checkpoint is not re-established. (The duplicate-name guard is a second
    /// line of defense, but the point proven here is that no `Cancelled` is
    /// emitted for a savepoint Oracle already accepted.)
    #[test]
    fn checkpoint_deadline_boundary_retry_loop_establishes_savepoint_once() {
        let state = Arc::new(ExecState::default());
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            read_write_level(),
        );

        // The SAVEPOINT reaches Oracle and THEN the deadline trips.
        state.cancel_on_execute.store(1, Ordering::SeqCst);

        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("asupersync test runtime builds");
        let (attempts, outcome) = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            cancel_retry_loop(
                &dispatcher,
                &cx,
                "oracle_checkpoint",
                json!({ "name": "cp1" }),
            )
            .await
        });

        assert_eq!(
            attempts, 1,
            "an established SAVEPOINT is terminal; the retry loop must stop after the first dispatch"
        );
        let Outcome::Ok(value) = outcome else {
            panic!(
                "an established SAVEPOINT must be reported Ok, not a retryable Cancelled: {outcome:?}"
            );
        };
        // The checkpoint-name validator upper-cases the identifier, so the
        // response name and statement come back upper-cased.
        assert_eq!(value["checkpoint"], json!("CP1"));
        assert_eq!(value["statement"], json!("SAVEPOINT CP1"));
        assert_eq!(
            state.executed.lock().expect("exec mutex").len(),
            1,
            "exactly one SAVEPOINT reached Oracle — the checkpoint was not re-established"
        );
    }

    #[test]
    fn commit_in_doubt_remains_primary_when_terminal_audit_also_fails() {
        let state = Arc::new(ExecState::default());
        let intents = write_intent_log("qa85-commit-in-doubt-audit-failure");
        let memory_sink = Arc::new(MemoryAuditSink::new());
        let append_count = Arc::new(AtomicUsize::new(0));
        let auditor = Arc::new(Auditor::new(
            Box::new(FailAfterFirstAppendSink {
                inner: Arc::clone(&memory_sink),
                appends: Arc::clone(&append_count),
            }),
            SigningKey::new(
                "qa85-test-key",
                b"qa85-terminal-audit-failure-1234".to_vec(),
            )
            .expect("valid test key"),
        ));
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(CommitInDoubtMock {
                state: Arc::clone(&state),
            }),
            Some("dev".to_owned()),
            read_write_level(),
        )
        .with_auditor(auditor)
        .with_write_intent_log(Arc::clone(&intents));
        let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
        let confirm = preview_confirm(&dispatcher, sql);

        let err = dispatcher
            .dispatch(
                "oracle_execute",
                json!({ "sql": sql, "commit": true, "confirm": confirm }),
            )
            .expect_err("lost commit response remains commit-in-doubt");
        assert_eq!(err.error_class, ErrorClass::ConnectionFailed);
        assert!(err.message.contains("commit_in_doubt"), "{}", err.message);
        assert_eq!(append_count.load(Ordering::SeqCst), 2);
        assert_eq!(memory_sink.records().len(), 1, "only Pending was durable");
        assert_eq!(state.commits.load(Ordering::SeqCst), 1);
        assert_eq!(state.rollbacks.load(Ordering::SeqCst), 0);
        assert_eq!(
            intents.unresolved().expect("intent snapshot").len(),
            1,
            "an in-doubt commit must leave its durable intent unresolved"
        );

        let later = dispatcher
            .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
            .expect_err("commit-in-doubt quarantines the connection");
        assert_eq!(later.error_class, ErrorClass::RuntimeStateRequired);
    }

    #[test]
    fn cancelled_audit_evidence_preflight_quarantines_before_execute() {
        let state = Arc::new(ExecState::default());
        *state.describe_error.lock().expect("describe error mutex") = Some(DbError::Cancelled(
            "injected audit-evidence cancellation".to_owned(),
        ));
        let (auditor, sink) = auditor_with_sink();
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            read_write_level(),
        )
        .with_auditor(auditor);
        let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
        let confirm = preview_confirm(&dispatcher, sql);

        let err = dispatcher
            .dispatch(
                "oracle_execute",
                json!({ "sql": sql, "commit": true, "confirm": confirm }),
            )
            .expect_err("uncertain audit evidence must stop before execute");
        assert_eq!(err.error_class, ErrorClass::ConnectionFailed);
        assert!(err.message.contains("unknown_discarded"), "{}", err.message);
        assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
        assert_eq!(state.commits.load(Ordering::SeqCst), 0);
        assert!(
            sink.records().is_empty(),
            "Pending is not written preflight"
        );

        let later = dispatcher
            .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
            .expect_err("uncertain preflight quarantines the connection");
        assert_eq!(later.error_class, ErrorClass::RuntimeStateRequired);
    }

    #[test]
    fn uncertain_dbms_output_after_commit_is_in_band_and_quarantines_reuse() {
        let state = Arc::new(ExecState::default());
        *state.dbms_output_error.lock().expect("output error mutex") = Some(DbError::Cancelled(
            "injected DBMS_OUTPUT drain cancellation".to_owned(),
        ));
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(Arc::clone(&state))),
            Some("dev".to_owned()),
            read_write_level(),
        );
        let sql = "BEGIN SYS.DBMS_OUTPUT.PUT_LINE('done'); END;";
        let confirm = preview_confirm_with_args(
            &dispatcher,
            json!({ "sql": sql, "commit": true, "dbms_output": true }),
        );

        let out = dispatcher
            .dispatch(
                "oracle_execute",
                json!({
                    "sql": sql,
                    "commit": true,
                    "confirm": confirm,
                    "dbms_output": true,
                }),
            )
            .expect("known commit survives optional diagnostic uncertainty");
        assert_eq!(out["executed"], json!(true));
        assert_eq!(out["committed"], json!(true));
        assert!(out.get("dbms_output").is_none());
        assert!(
            out["dbms_output_unavailable"]
                .as_str()
                .is_some_and(|reason| reason.contains("terminal database outcome")),
            "optional diagnostic loss is reported in-band: {out}"
        );
        assert_eq!(state.commits.load(Ordering::SeqCst), 1);

        let later = dispatcher
            .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
            .expect_err("uncertain optional diagnostic quarantines later reuse");
        assert_eq!(later.error_class, ErrorClass::RuntimeStateRequired);
        assert!(later.message.contains("quarantined"), "{}", later.message);
    }
}

#[test]
fn revalidate_served_final_checkpoint_prevents_execution_after_consume() {
    use oraclemcp_audit::{AuditError, AuditRecord, AuditSink, SigningKey};
    struct DriftOnAttempt(Arc<ExecState>);
    impl AuditSink for DriftOnAttempt {
        fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
            if record.tool == "oracle_execute" && record.outcome == AuditOutcome::Pending {
                self.0.impact_schema_epoch.store(1, Ordering::SeqCst);
            }
            Ok(())
        }
        fn flush(&self) -> Result<(), AuditError> {
            Ok(())
        }
    }
    let (dispatcher, state) = dispatcher();
    let token = confirm(
        &dispatcher,
        json!({"sql": UPDATE, "binds": ["Ada", 7], "commit": true}),
    );
    let auditor = Arc::new(Auditor::new(
        Box::new(DriftOnAttempt(state.clone())),
        SigningKey::new("final-impact", vec![9; 32]).unwrap(),
    ));
    let dispatcher = dispatcher.with_auditor(auditor);
    let error = dispatcher
        .dispatch(
            "oracle_execute",
            json!({
                "sql": UPDATE, "binds": ["Ada", 7], "commit": true, "confirm": token,
            }),
        )
        .expect_err("facts changed by the pre-execution audit callback must refuse");
    assert_eq!(error.error_class, ErrorClass::RepreviewRequired);
    assert_eq!(error.statement_outcome, Some(StatementOutcome::NotStarted));
    assert!(state.executed.lock().unwrap().is_empty());
    assert_eq!(state.commits.load(Ordering::SeqCst), 0);
}

#[test]
fn preview_signs_the_exact_displayed_decisive_binding() {
    let (dispatcher, _) = dispatcher();
    let preview = dispatcher
        .dispatch(
            "oracle_preview_sql",
            json!({"sql": UPDATE, "binds": ["Ada", 7], "commit": true}),
        )
        .unwrap();
    let binding: oraclemcp_guard::ImpactBindingV1 =
        serde_json::from_value(preview["impact"]["binding"].clone()).unwrap();
    let token = preview["execute_confirmation"]["confirm"].as_str().unwrap();
    let signed_digest = token
        .rsplit_once('.')
        .unwrap()
        .0
        .rsplit_once('~')
        .unwrap()
        .1;
    let expected = binding
        .decisive_digest()
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(signed_digest, expected);
}

#[test]
fn unchanged_served_impact_round_trip_audits_both_digests() {
    let (dispatcher, state) = dispatcher();
    let (auditor, sink) = super::audit_wiring::auditor_with_sink();
    let dispatcher = dispatcher.with_auditor(auditor);
    let preview = dispatcher
        .dispatch(
            "oracle_preview_sql",
            json!({"sql": UPDATE, "binds": ["Ada", 7], "commit": true}),
        )
        .unwrap();
    let impact: oraclemcp_guard::ImpactBindingV1 =
        serde_json::from_value(preview["impact"]["binding"].clone()).unwrap();
    let decisive = format!(
        "sha256:{}",
        impact
            .decisive_digest()
            .unwrap()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let result = dispatcher
        .dispatch(
            "oracle_execute",
            json!({"sql": UPDATE, "binds": ["Ada", 7],
        "commit": true, "confirm": preview["execute_confirmation"]["confirm"]}),
        )
        .unwrap();
    assert_eq!(result["executed"], true);
    assert_eq!(state.executed.lock().unwrap().len(), 1);
    let records = sink
        .records()
        .into_iter()
        .filter(|record| record.tool == "oracle_execute")
        .collect::<Vec<_>>();
    assert_eq!(
        records.len(),
        2,
        "one durable attempt and one terminal record"
    );
    assert_eq!(records[0].outcome, AuditOutcome::Pending);
    assert_eq!(
        records[0].revalidated_at,
        Some(oraclemcp_audit::AuditRevalidationStage::BeforeConsume)
    );
    assert_eq!(records[1].outcome, AuditOutcome::Succeeded);
    assert_eq!(
        records[1].revalidated_at,
        Some(oraclemcp_audit::AuditRevalidationStage::BeforeExecute)
    );
    for record in records {
        assert_eq!(
            record.statement_digest.as_deref(),
            Some(oraclemcp_guard::sql_digest(UPDATE).as_str())
        );
        assert_eq!(record.decisive_digest.as_deref(), Some(decisive.as_str()));
        assert!(record.hash_is_valid());
    }
}
