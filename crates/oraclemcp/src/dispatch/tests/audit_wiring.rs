use super::*;
use oraclemcp_audit::{
    AuditError, AuditOutcome, AuditRecord, AuditSink, AuditSubject, MemoryAuditSink, SigningKey,
};
use std::sync::Arc;

/// Share one `MemoryAuditSink` between the `Auditor` (which owns a
/// `Box<dyn AuditSink>`) and the test (which inspects the records).
struct SharedSink(Arc<MemoryAuditSink>);
impl AuditSink for SharedSink {
    fn append(&self, r: &AuditRecord) -> Result<(), AuditError> {
        self.0.append(r)
    }
    fn append_with_verdict_certificate(
        &self,
        record: &AuditRecord,
        certificate: &oraclemcp_audit::BoundAuditVerdictCertificate,
    ) -> Result<(), AuditError> {
        self.0.append_with_verdict_certificate(record, certificate)
    }
    fn flush(&self) -> Result<(), AuditError> {
        self.0.flush()
    }
}

fn auditor_with_sink() -> (Arc<Auditor>, Arc<MemoryAuditSink>) {
    let sink = Arc::new(MemoryAuditSink::new());
    let key = SigningKey::new("test-key", b"0123456789abcdef0123456789abcdef".to_vec())
        .expect("valid test key");
    let auditor = Arc::new(Auditor::new(Box::new(SharedSink(sink.clone())), key));
    (auditor, sink)
}

/// Ceiling permits DDL but the session starts read-only, so a level increase
/// is gated by step-up (the path that A8 must audit).
fn escalatable_read_only() -> SessionLevelState {
    SessionLevelState::new(OperatingLevel::Ddl, false)
}

fn dispatcher_with(level: SessionLevelState, auditor: Arc<Auditor>) -> OracleDispatcher {
    dispatcher_with_conn(Box::new(OneRowMock), level, auditor)
}

fn dispatcher_with_conn(
    conn: Box<dyn OracleConnection>,
    level: SessionLevelState,
    auditor: Arc<Auditor>,
) -> OracleDispatcher {
    OracleDispatcher::new_switchable(
        conn,
        Some("dev".to_owned()),
        level,
        Arc::new(|_cx, _profile| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
    )
    .with_auditor(auditor)
}

struct FailingSink;
impl AuditSink for FailingSink {
    fn append(&self, _r: &AuditRecord) -> Result<(), AuditError> {
        Err(AuditError::Io("test audit sink failure".to_owned()))
    }
    fn flush(&self) -> Result<(), AuditError> {
        Ok(())
    }
}

fn failing_auditor() -> Arc<Auditor> {
    let key = SigningKey::new("test-key", b"0123456789abcdef0123456789abcdef".to_vec())
        .expect("valid test key");
    Arc::new(Auditor::new(Box::new(FailingSink), key))
}

fn mask_all_policy() -> ResultMaskingPolicy {
    ResultMaskingPolicy::new(Vec::new(), true).with_profile("dev")
}

fn preview_confirm_with_context(
    dispatcher: &OracleDispatcher,
    context: DispatchContext<'_>,
    sql: &str,
) -> String {
    dispatcher
        .dispatch_with_context(
            "oracle_preview_sql",
            json!({
                "sql": sql,
                "agent_identity": "attacker",
                "operator_name": "HumanOperator",
                "label": "spoofed",
            }),
            context,
        )
        .expect("preview")
        .pointer("/execute_confirmation/confirm")
        .and_then(Value::as_str)
        .expect("preview minted execute grant")
        .to_owned()
}

#[test]
fn served_write_appends_pending_then_signed_outcome() {
    let (auditor, sink) = auditor_with_sink();
    let dispatcher = dispatcher_with(ddl_level(), auditor);
    let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
    let confirm = preview_confirm(&dispatcher, sql);
    let out = dispatcher
        .dispatch(
            "execute_approved",
            json!({ "sql": sql, "token": confirm, "commit": true }),
        )
        .expect("write dispatches");
    assert!(out.is_object());

    let recs = sink.records();
    assert_eq!(
        recs.len(),
        2,
        "a served write logs Pending then its outcome"
    );
    assert_eq!(recs[0].outcome, AuditOutcome::Pending);
    assert_eq!(recs[1].outcome, AuditOutcome::Succeeded);
    // Hash chain links pre -> post.
    assert_eq!(recs[1].prev_hash, recs[0].entry_hash);
    // Every served record is signed by the keyed MAC (not forgeable by a
    // bare recompute-from-genesis).
    assert!(recs[0].signature.is_some(), "pre record is signed");
    assert!(recs[1].signature.is_some(), "post record is signed");
    assert_eq!(recs[1].key_id.as_deref(), Some("test-key"));
    // The SQL bytes are never stored verbatim — only the digest + preview.
    assert!(recs[1].sql_sha256.starts_with("sha256:"));
}

#[test]
fn caller_supplied_identity_cannot_change_audit_subject_or_db_evidence() {
    let (auditor, sink) = auditor_with_sink();
    let state = Arc::new(ExecState::default());
    let dispatcher = dispatcher_with_conn(
        Box::new(ExecRecordingMock::new(state.clone())),
        ddl_level(),
        auditor,
    );
    let context = DispatchContext::default()
        .with_http_session_id("mcp-session-1")
        .with_principal_key("oauth:subject-hash")
        .with_lane_identity("lane-1", 7);
    let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
    let confirm = preview_confirm_with_context(&dispatcher, context, sql);

    dispatcher
        .dispatch_with_context(
            "execute_approved",
            json!({
                "token": confirm,
                "commit": true,
                "agent_identity": "attacker",
                "operator_name": "HumanOperator",
                "label": "spoofed",
            }),
            context,
        )
        .expect("write dispatches");

    let recs = sink.records();
    assert_eq!(recs.len(), 2);
    let expected_subject = AuditSubject::new("oauth", "subject-hash").with_authn_method("oauth");
    for rec in &recs {
        assert_eq!(rec.subject, expected_subject);
        assert_eq!(rec.agent_identity, "oauth:subject-hash");
        assert!(
            !rec.agent_identity.contains("attacker")
                && !rec.agent_identity.contains("HumanOperator")
                && !rec.agent_identity.contains("spoofed")
        );
        let evidence = rec.db_evidence.as_ref().expect("DB evidence captured");
        assert_eq!(evidence.availability.as_deref(), Some("captured"));
        assert_eq!(evidence.db_unique_name.as_deref(), Some("ORCL23A"));
        assert_eq!(evidence.service_name.as_deref(), Some("freepdb1"));
        assert_eq!(evidence.instance_name.as_deref(), Some("free"));
        assert_eq!(evidence.session_user.as_deref(), Some("APP"));
        assert_eq!(evidence.proxy_user.as_deref(), Some("MCP_PROXY"));
        assert_eq!(evidence.sid.as_deref(), Some("101"));
        assert_eq!(evidence.serial_number.as_deref(), Some("202"));
        assert_eq!(evidence.client_identifier.as_deref(), Some("oauth-subject"));
        assert_eq!(evidence.module.as_deref(), Some("oraclemcp-test"));
        assert_eq!(evidence.action.as_deref(), Some("execute"));
    }
}

#[test]
fn served_read_is_audited_with_a_replay_scn() {
    let (auditor, sink) = auditor_with_sink();
    let dispatcher = dispatcher_with(ddl_level(), auditor);
    let _ = dispatcher
        .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
        .expect("read dispatches");
    let records = sink.records();
    assert_eq!(records.len(), 2, "a read logs Pending then Succeeded");
    assert_eq!(records[0].outcome, AuditOutcome::Pending);
    assert_eq!(records[1].outcome, AuditOutcome::Succeeded);
    assert_eq!(records[0].observed_scn, Some(424_242));
    assert_eq!(records[1].observed_scn, Some(424_242));
    assert_eq!(records[1].prev_hash, records[0].entry_hash);
    let certificates = sink.certificates();
    assert!(
        certificates
            .iter()
            .zip(&records)
            .all(|(certificate, record)| {
                certificate
                    .as_ref()
                    .is_some_and(|certificate| certificate.matches_record(record))
            })
    );
}

/// F-S1 discriminating fixture: a profile whose Oracle account lacks
/// EXECUTE on `SYS.DBMS_FLASHBACK`. Every other read succeeds normally
/// (mirroring [`OneRowMock`]); only `DBMS_FLASHBACK.GET_SYSTEM_CHANGE_NUMBER`
/// fails ORA-00904 — the exact real-world capability gap F-S1 targets.
/// Before the fix, `AsOf::current_system_change_number` caught this ORA
/// code and silently re-issued `V$DATABASE.CURRENT_SCN` under the same
/// `Ok` result; this mock has no branch for that legacy query, so a
/// regression back to the silent substitution would surface as a parse
/// failure ("Oracle returned no current system change number") rather
/// than quietly succeeding.
struct ScnCapabilityUnavailableMock;
#[async_trait::async_trait(?Send)]
impl OracleConnection for ScnCapabilityUnavailableMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    async fn close(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo {
            current_schema: Some("APP".to_owned()),
            ..Default::default()
        })
    }
    async fn query_rows(
        &self,
        _cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        if let Some(rows) = mock_plain_table_dictionary(sql, binds) {
            return Ok(rows);
        }
        if sql
            .to_ascii_lowercase()
            .contains("get_system_change_number")
        {
            return Err(DbError::Query(
                "ORA-00904: \"SYS\".\"DBMS_FLASHBACK\": invalid identifier".to_owned(),
            ));
        }
        Ok(vec![OracleRow {
            columns: vec![(
                "C".to_owned(),
                OracleCell::new("NUMBER", Some("1".to_owned())),
            )],
        }])
    }
    async fn execute(&self, _cx: &Cx, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
        Ok(0)
    }
    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Ok(())
    }
}

/// F-S1 / SEC-4 discriminating test (bead oraclemcp-eng-program-bp8ia.8.3):
/// when the SCN-capture capability is absent, `oracle_query` must degrade
/// EXPLICITLY and AUDIT the degradation — never silently substitute a
/// different SQL source under an unmarked `Ok`. Before the fix this test
/// fails: the pre-fix probe swallowed ORA-00904 internally and returned a
/// plain `Some(424242)`-shaped success indistinguishable from the
/// capability actually being present, so none of the assertions below
/// (the dedicated `scn_capability_probe` record, or `observed_scn: None`
/// on the read's own records) would hold.
#[test]
fn scn_capability_absent_degrades_explicitly_and_audits_instead_of_silently_falling_back() {
    let (auditor, sink) = auditor_with_sink();
    let dispatcher =
        dispatcher_with_conn(Box::new(ScnCapabilityUnavailableMock), ddl_level(), auditor);
    let out = dispatcher
        .dispatch("oracle_query", json!({ "sql": "SELECT 1 FROM dual" }))
        .expect("a missing DBMS_FLASHBACK grant degrades the read; it must not refuse it");
    assert!(
        out.get("rows").is_some(),
        "F-S1 degrades explicitly rather than blocking every audited profile \
             that has not granted DBMS_FLASHBACK"
    );
    assert!(
        out.get("observed_scn").is_none_or(|v| v.is_null()),
        "no SCN was captured, so none is echoed to the client"
    );

    let records = sink.records();
    assert_eq!(
        records.len(),
        3,
        "an explicit degradation marker, then Pending then Succeeded for the read itself"
    );
    assert_eq!(records[0].tool, "scn_capability_probe");
    assert_eq!(records[0].outcome, AuditOutcome::Failed);
    assert_eq!(
        records[0].observed_scn, None,
        "the probe failure record carries no SCN"
    );
    assert_eq!(records[1].tool, "oracle_query");
    assert_eq!(records[1].outcome, AuditOutcome::Pending);
    assert_eq!(records[2].tool, "oracle_query");
    assert_eq!(records[2].outcome, AuditOutcome::Succeeded);
    assert_eq!(
        records[1].observed_scn, None,
        "the read is audited without ever fabricating a substitute SCN"
    );
    assert_eq!(records[2].observed_scn, None);
    assert_eq!(records[2].prev_hash, records[1].entry_hash);

    // The verdict certificate still binds the (SCN-less) read records —
    // the read stays proof-carrying even in the degraded case.
    let certificates = sink.certificates();
    assert!(
        certificates[1]
            .as_ref()
            .is_some_and(|certificate| certificate.matches_record(&records[1])),
        "Pending record still carries a bound verdict certificate"
    );
    assert!(
        certificates[2]
            .as_ref()
            .is_some_and(|certificate| certificate.matches_record(&records[2])),
        "Succeeded record still carries a bound verdict certificate"
    );
}

#[test]
fn masked_read_carries_audit_bound_certificate() {
    let (auditor, sink) = auditor_with_sink();
    let dispatcher =
        dispatcher_with(ddl_level(), auditor).with_result_masking_policy(Some(mask_all_policy()));

    let out = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT owner FROM all_objects" }),
        )
        .expect("masked read dispatches");

    let certificate = out["mask_certificate"]
        .as_object()
        .expect("masked response carries certificate");
    let audit_entry_hash = certificate["audit_entry_hash"]
        .as_str()
        .expect("certificate names audit entry hash");
    assert_eq!(certificate["profile"], json!("dev"));
    assert!(
        certificate["policy_id"]
            .as_str()
            .is_some_and(|policy_id| policy_id.starts_with("sha256:"))
    );
    assert!(
        certificate["decisions"]
            .as_array()
            .is_some_and(|decisions| !decisions.is_empty()),
        "certificate records column decisions"
    );
    assert!(
        !out["rows"].to_string().contains("EMPLOYEES"),
        "masked data must not leak original row values"
    );

    let records = sink.records();
    assert_eq!(
        records.len(),
        2,
        "masked read appends Pending then certificate-bound Succeeded records"
    );
    let record = &records[1];
    assert_eq!(records[0].outcome, AuditOutcome::Pending);
    assert_eq!(record.tool, "oracle_query");
    assert_eq!(record.danger_level, "READ_ONLY");
    assert_eq!(record.outcome, AuditOutcome::Succeeded);
    assert_eq!(record.observed_scn, Some(424_242));
    assert_eq!(audit_entry_hash, record.entry_hash);
    assert!(record.hash_is_valid(), "audit certificate is hash-covered");
    let audited = record
        .result_masking
        .as_ref()
        .expect("audit record stores mask certificate");
    assert_eq!(audited.profile.as_deref(), Some("dev"));
    assert_eq!(
        audited.policy_id.as_str(),
        certificate["policy_id"].as_str().expect("policy id")
    );
    assert_eq!(
        audited.decisions.len(),
        certificate["decisions"].as_array().unwrap().len()
    );
}

#[test]
fn masked_arrow_read_contains_only_audit_bound_masked_values() {
    let (auditor, sink) = auditor_with_sink();
    let dispatcher =
        dispatcher_with(ddl_level(), auditor).with_result_masking_policy(Some(mask_all_policy()));

    let out = dispatcher
        .dispatch(
            "oracle_query",
            json!({
                "sql": "SELECT owner, object_name FROM all_objects",
                "format": "arrow"
            }),
        )
        .expect("masked Arrow read dispatches");

    assert!(out.get("rows").is_none(), "Arrow omits JSON rows");
    let decoded_rows = decode_arrow_json_rows(&out);
    assert!(
        !Value::Array(decoded_rows.clone())
            .to_string()
            .contains("EMPLOYEES"),
        "the Arrow payload must not recover a pre-mask value: {decoded_rows:?}"
    );
    assert!(
        decoded_rows
            .iter()
            .all(|row| row.as_object().is_some_and(|row| {
                row.values()
                    .all(|value| value == &json!(oraclemcp_db::MASKED_RESULT_VALUE))
            })),
        "every masked output column stays masked after Arrow decode: {decoded_rows:?}"
    );
    let certificate = out["mask_certificate"]
        .as_object()
        .expect("masked Arrow response retains its audit certificate");
    let audit_entry_hash = certificate["audit_entry_hash"]
        .as_str()
        .expect("certificate remains audit-bound");
    let records = sink.records();
    assert_eq!(
        records.len(),
        2,
        "read audit has pending and succeeded records"
    );
    assert_eq!(records[1].entry_hash, audit_entry_hash);
    assert!(
        records[1].result_masking.is_some(),
        "audit record binds the same masking decision before Arrow egress"
    );
}

#[test]
fn masked_read_fails_closed_when_audit_append_fails() {
    let dispatcher = dispatcher_with(ddl_level(), failing_auditor())
        .with_result_masking_policy(Some(mask_all_policy()));

    let err = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT owner FROM all_objects" }),
        )
        .expect_err("masked read refuses unaudited result");

    assert!(
        err.message.contains("audit append failed"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn masked_read_fails_closed_without_audit_sink() {
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(OneRowMock),
        Some("dev".to_owned()),
        ddl_level(),
    )
    .with_result_masking_policy(Some(mask_all_policy()));

    let err = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT owner FROM all_objects" }),
        )
        .expect_err("masked read requires audit binding");

    assert!(
        err.message.contains("no audit sink is configured"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn masked_streaming_query_is_refused_until_certificates_can_precede_rows() {
    let (auditor, _sink) = auditor_with_sink();
    let dispatcher =
        dispatcher_with(ddl_level(), auditor).with_result_masking_policy(Some(mask_all_policy()));

    let err = dispatcher
        .dispatch(
            "oracle_query",
            json!({ "sql": "SELECT owner FROM all_objects", "streaming": true }),
        )
        .expect_err("masked streaming is refused");

    assert!(
        err.message.contains("streaming masked query results"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn masked_diff_carries_before_after_audit_bound_certificates() {
    let (auditor, sink) = auditor_with_sink();
    let dispatcher =
        dispatcher_with(ddl_level(), auditor).with_result_masking_policy(Some(mask_all_policy()));

    let out = dispatcher
        .dispatch(
            "oracle_diff",
            json!({
                "sql": "SELECT owner FROM all_objects",
                "scn_a": 1,
                "scn_b": 2,
                "key": ["OWNER"]
            }),
        )
        .expect("masked diff dispatches");

    let certificates = out["mask_certificates"]
        .as_object()
        .expect("masked diff carries before/after certificates");
    let before_hash = certificates["before"]["audit_entry_hash"]
        .as_str()
        .expect("before cert audit hash");
    let after_hash = certificates["after"]["audit_entry_hash"]
        .as_str()
        .expect("after cert audit hash");
    assert_ne!(before_hash, after_hash);

    let records = sink.records();
    assert_eq!(records.len(), 2, "diff binds both flashback pages");
    assert_eq!(records[0].tool, "oracle_diff");
    assert_eq!(records[1].tool, "oracle_diff");
    assert_eq!(before_hash, records[0].entry_hash);
    assert_eq!(after_hash, records[1].entry_hash);
    assert!(records.iter().all(AuditRecord::hash_is_valid));
    assert!(records.iter().all(|record| record.result_masking.is_some()));
}

#[test]
fn session_level_escalation_is_audited() {
    let (auditor, sink) = auditor_with_sink();
    let dispatcher = dispatcher_with(escalatable_read_only(), auditor);
    // A preview mints the single-use confirmation grant; apply escalates.
    let preview = dispatcher
        .dispatch(
            "oracle_set_session_level",
            json!({ "level": "READ_WRITE", "ttl_seconds": 60 }),
        )
        .expect("preview elevation");
    let confirm = preview["confirmation"]["confirm"]
        .as_str()
        .expect("confirm grant");
    let out = dispatcher
        .dispatch(
            "oracle_set_session_level",
            json!({
                "level": "READ_WRITE",
                "ttl_seconds": 60,
                "execute": true,
                "confirm": confirm,
            }),
        )
        .expect("escalation dispatches");
    assert_eq!(out["changed"], json!(true), "escalation applied");

    let recs = sink.records();
    assert_eq!(recs.len(), 1, "a level increase logs exactly one record");
    assert_eq!(recs[0].tool, "oracle_set_session_level");
    assert_eq!(recs[0].outcome, AuditOutcome::Succeeded);
    assert!(recs[0].signature.is_some(), "escalation record is signed");
}

#[test]
fn compile_object_execute_is_audited_pending_then_signed_outcome() {
    let (auditor, sink) = auditor_with_sink();
    let state = Arc::new(ExecState::default());
    let dispatcher = dispatcher_with_conn(
        Box::new(ExecRecordingMock::new(state.clone())),
        ddl_level(),
        auditor,
    );
    let preview = dispatcher
        .dispatch(
            "oracle_compile_object",
            json!({ "object_type": "PACKAGE", "name": "EMP_API" }),
        )
        .expect("compile preview");
    let confirm = preview["confirmation"]["confirm"]
        .as_str()
        .expect("confirm grant");

    let out = dispatcher
        .dispatch(
            "oracle_compile_object",
            json!({
                "object_type": "PACKAGE",
                "name": "EMP_API",
                "execute": true,
                "confirm": confirm,
            }),
        )
        .expect("compile executes");
    assert_eq!(out["compiled"], json!(true));

    let recs = sink.records();
    assert_eq!(recs.len(), 2, "compile logs Pending then outcome");
    assert_eq!(recs[0].tool, "oracle_compile_object");
    assert_eq!(recs[0].outcome, AuditOutcome::Pending);
    assert_eq!(recs[1].outcome, AuditOutcome::Succeeded);
    assert_eq!(recs[1].prev_hash, recs[0].entry_hash);
    assert!(recs[0].signature.is_some());
    assert_eq!(recs[0].sql_preview, "<sql text redacted; see sql_sha256>");
    assert!(recs[0].sql_sha256.starts_with("sha256:"));
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);
}

#[test]
fn definite_compile_failure_has_no_prior_session_effect_and_resolves_intent() {
    let (auditor, sink) = auditor_with_sink();
    let state = Arc::new(ExecState::default());
    *state.execute_error.lock().expect("execute error mutex") = Some(DbError::Execute(
        "ORA-04043: object APP.EMP_API does not exist".to_owned(),
    ));
    let intents = write_intent_log("qa110-definite-compile-failure");
    let dispatcher = dispatcher_with_conn(
        Box::new(ExecRecordingMock::new(state.clone())),
        ddl_level(),
        auditor,
    )
    .with_write_intent_log(intents.clone());
    let preview = dispatcher
        .dispatch(
            "oracle_compile_object",
            json!({
                "object_type": "PACKAGE",
                "name": "EMP_API",
                "plscope": true,
                "warnings": true
            }),
        )
        .expect("compile preview");
    let confirm = preview["confirmation"]["confirm"]
        .as_str()
        .expect("confirm grant");

    let error = dispatcher
        .dispatch(
            "oracle_compile_object",
            json!({
                "object_type": "PACKAGE",
                "name": "EMP_API",
                "plscope": true,
                "warnings": true,
                "execute": true,
                "confirm": confirm,
            }),
        )
        .expect_err("definite compile failure surfaces");
    assert_eq!(error.error_class, ErrorClass::ObjectNotFound);

    let executed = state.executed.lock().expect("exec mutex");
    assert_eq!(executed.len(), 1, "compile performs one database effect");
    assert_eq!(
        executed[0].0,
        "ALTER PACKAGE APP.EMP_API COMPILE PLSQL_WARNINGS = 'ENABLE:ALL' PLSCOPE_SETTINGS = 'IDENTIFIERS:ALL, STATEMENTS:ALL' REUSE SETTINGS"
    );
    assert!(!executed[0].0.contains("ALTER SESSION"));
    drop(executed);

    let recs = sink.records();
    assert_eq!(recs.len(), 2, "compile logs Pending then Failed");
    assert_eq!(recs[0].outcome, AuditOutcome::Pending);
    assert_eq!(recs[1].outcome, AuditOutcome::Failed);
    assert_eq!(recs[1].prev_hash, recs[0].entry_hash);
    assert!(
        intents.unresolved().expect("intent snapshot").is_empty(),
        "a definite one-statement failure is safe to resolve"
    );
    let ledger = std::fs::read_to_string(intents.path().expect("intent path"))
        .expect("intent ledger is readable");
    assert!(ledger.contains("\"outcome\":\"FAILED\""), "{ledger}");
    assert!(
        dispatcher
            .connection_quarantine()
            .expect("quarantine lock")
            .is_none(),
        "a definite failure with no earlier session effect remains reusable"
    );
    dispatcher
        .dispatch("oracle_connection_info", json!({}))
        .expect("connection remains usable after the definite failure");
}

#[test]
fn patch_source_execute_is_audited_pending_then_signed_outcome() {
    let (auditor, sink) = auditor_with_sink();
    let state = Arc::new(ExecState::default());
    let dispatcher = dispatcher_with_conn(
        Box::new(ExecRecordingMock::new(state.clone())),
        ddl_level(),
        auditor,
    );
    let preview_args = json!({
        "owner": "APP",
        "name": "EMP_API",
        "object_type": "PACKAGE_BODY",
        "old_text": "NULL",
        "new_text": "1",
    });
    let preview = dispatcher
        .dispatch("oracle_patch_source", preview_args.clone())
        .expect("patch preview");
    let confirm = preview["confirmation"]["confirm"]
        .as_str()
        .expect("confirm grant")
        .to_owned();
    let mut execute_args = preview_args;
    execute_args["execute"] = json!(true);
    execute_args["confirm"] = json!(confirm);

    let out = dispatcher
        .dispatch("oracle_patch_source", execute_args)
        .expect("patch executes");
    assert_eq!(out["applied"], json!(true));

    let recs = sink.records();
    assert_eq!(recs.len(), 2, "patch logs Pending then outcome");
    assert_eq!(recs[0].tool, "oracle_patch_source");
    assert_eq!(recs[0].outcome, AuditOutcome::Pending);
    assert_eq!(recs[1].outcome, AuditOutcome::Succeeded);
    assert_eq!(recs[1].prev_hash, recs[0].entry_hash);
    assert!(recs[0].signature.is_some());
    assert_eq!(recs[0].sql_preview, "<sql text redacted; see sql_sha256>");
    assert!(recs[0].sql_sha256.starts_with("sha256:"));
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);
}

#[test]
fn audit_write_failure_refuses_compile_before_db_execute() {
    let state = Arc::new(ExecState::default());
    let dispatcher = dispatcher_with_conn(
        Box::new(ExecRecordingMock::new(state.clone())),
        ddl_level(),
        failing_auditor(),
    );
    let preview = dispatcher
        .dispatch(
            "oracle_compile_object",
            json!({ "object_type": "PACKAGE", "name": "EMP_API" }),
        )
        .expect("compile preview");
    let confirm = preview["confirmation"]["confirm"]
        .as_str()
        .expect("confirm grant");

    let err = dispatcher
        .dispatch(
            "oracle_compile_object",
            json!({
                "object_type": "PACKAGE",
                "name": "EMP_API",
                "execute": true,
                "confirm": confirm,
            }),
        )
        .expect_err("audit failure refuses compile");
    assert_eq!(err.error_class, ErrorClass::Internal);
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
}

#[test]
fn audit_write_failure_refuses_patch_before_db_execute() {
    let state = Arc::new(ExecState::default());
    let dispatcher = dispatcher_with_conn(
        Box::new(ExecRecordingMock::new(state.clone())),
        ddl_level(),
        failing_auditor(),
    );
    let preview_args = json!({
        "owner": "APP",
        "name": "EMP_API",
        "object_type": "PACKAGE_BODY",
        "old_text": "NULL",
        "new_text": "1",
    });
    let preview = dispatcher
        .dispatch("oracle_patch_source", preview_args.clone())
        .expect("patch preview");
    let confirm = preview["confirmation"]["confirm"]
        .as_str()
        .expect("confirm grant")
        .to_owned();
    let mut execute_args = preview_args;
    execute_args["execute"] = json!(true);
    execute_args["confirm"] = json!(confirm);

    let err = dispatcher
        .dispatch("oracle_patch_source", execute_args)
        .expect_err("audit failure refuses patch");
    assert_eq!(err.error_class, ErrorClass::Internal);
    assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
}
