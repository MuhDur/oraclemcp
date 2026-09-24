//! R36: FGA evidence the principal cannot read must not block reads.
//!
//! A least-privilege account gets ORA-00942 from `ALL_AUDIT_POLICIES`. That is
//! UNAVAILABLE evidence, not a proven handler: the read is admitted with an
//! `fga_evidence: unavailable` observation and a signed audit marker, unless
//! the profile sets `require_fga_evidence`. A proven FGA handler refuses
//! whatever the profile says.

use super::*;
use oraclemcp_audit::{AuditError, AuditRecord, AuditSink, MemoryAuditSink, SigningKey};

const READ: &str = "SELECT id FROM APP.ORDERS";

fn unreadable_fga_dispatcher(
    policy: FgaEvidencePolicy,
) -> (OracleDispatcher, Arc<SemanticGuardState>) {
    let (dispatcher, state) = semantic_dispatcher();
    *state
        .fga_catalog_unreadable
        .lock()
        .expect("FGA catalog fixture lock") = true;
    (dispatcher.with_fga_evidence_policy(policy), state)
}

fn offending_construct(error: &ErrorEnvelope) -> Option<&str> {
    error
        .structured_reason
        .as_ref()
        .and_then(|reason| reason.offending_construct.as_deref())
}

#[test]
fn unavailable_fga_evidence_admits_the_read_with_an_observation() {
    let (dispatcher, state) = unreadable_fga_dispatcher(FgaEvidencePolicy::AdmitUnavailable);
    let result = dispatcher
        .dispatch("oracle_query", json!({"sql": READ}))
        .expect("an unreadable FGA catalog must not block a plain read");
    assert!(!result["rows"].as_array().expect("rows array").is_empty());
    assert_eq!(result["fga_evidence"], json!("unavailable"));
    assert_eq!(state.caller_queries.load(Ordering::SeqCst), 1);
}

#[test]
fn unavailable_fga_evidence_admits_sample_rows_with_an_observation() {
    let (dispatcher, state) = unreadable_fga_dispatcher(FgaEvidencePolicy::AdmitUnavailable);
    let result = dispatcher
        .dispatch(
            "oracle_sample_rows",
            json!({"owner": "APP", "table": "ORDERS", "max_rows": 1}),
        )
        .expect("server-generated reads follow the same rule");
    assert_eq!(result["fga_evidence"], json!("unavailable"));
    assert_eq!(state.caller_queries.load(Ordering::SeqCst), 1);
}

#[test]
fn require_fga_evidence_refuses_the_unavailable_read() {
    let (dispatcher, state) = unreadable_fga_dispatcher(FgaEvidencePolicy::RequireProof);
    let error = dispatcher
        .dispatch("oracle_query", json!({"sql": READ}))
        .expect_err("require_fga_evidence restores the strict refusal");
    assert_eq!(error.error_class, ErrorClass::ForbiddenStatement);
    assert_eq!(offending_construct(&error), Some("fga_evidence_unknown"));
    assert_eq!(state.caller_queries.load(Ordering::SeqCst), 0);
}

#[test]
fn proven_fga_handler_refuses_under_either_policy() {
    for policy in [
        FgaEvidencePolicy::AdmitUnavailable,
        FgaEvidencePolicy::RequireProof,
    ] {
        let (dispatcher, state) = semantic_dispatcher();
        let dispatcher = dispatcher.with_fga_evidence_policy(policy);
        *state.fga_handler_table.lock().expect("FGA fixture lock") = Some("ORDERS".to_owned());
        let error = dispatcher
            .dispatch("oracle_query", json!({"sql": READ}))
            .expect_err("a proven FGA handler must refuse");
        assert_eq!(
            error.error_class,
            ErrorClass::ForbiddenStatement,
            "{policy:?}"
        );
        assert_eq!(
            offending_construct(&error),
            Some("fga_handler_autonomous"),
            "{policy:?}"
        );
        assert_eq!(state.caller_queries.load(Ordering::SeqCst), 0, "{policy:?}");
    }
}

#[test]
fn proven_absence_admits_without_an_observation() {
    for policy in [
        FgaEvidencePolicy::AdmitUnavailable,
        FgaEvidencePolicy::RequireProof,
    ] {
        let (dispatcher, state) = semantic_dispatcher();
        let dispatcher = dispatcher.with_fga_evidence_policy(policy);
        let result = dispatcher
            .dispatch("oracle_query", json!({"sql": READ}))
            .expect("a readable, empty FGA catalog proves the read");
        assert!(
            result.get("fga_evidence").is_none(),
            "{policy:?}: proven evidence carries no observation"
        );
        assert_eq!(state.caller_queries.load(Ordering::SeqCst), 1, "{policy:?}");
    }
}

struct SharedSink(Arc<MemoryAuditSink>);

impl AuditSink for SharedSink {
    fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.0.append(record)
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

#[test]
fn unavailable_fga_evidence_is_recorded_in_the_audit_chain_before_the_read() {
    let sink = Arc::new(MemoryAuditSink::new());
    let auditor = Arc::new(oraclemcp_audit::Auditor::new(
        Box::new(SharedSink(Arc::clone(&sink))),
        SigningKey::new("r36-test-key", b"r36-fga-evidence-audit-test-key!".to_vec())
            .expect("valid test key"),
    ));
    let (dispatcher, state) = unreadable_fga_dispatcher(FgaEvidencePolicy::AdmitUnavailable);
    let dispatcher = dispatcher.with_auditor(auditor);
    let result = dispatcher
        .dispatch("oracle_query", json!({"sql": READ}))
        .expect("admitted with the observation");
    assert_eq!(result["fga_evidence"], json!("unavailable"));
    assert_eq!(state.caller_queries.load(Ordering::SeqCst), 1);

    let records = sink.records();
    let marker = records
        .iter()
        .position(|record| record.tool == "fga_evidence_unavailable")
        .expect("a signed fga_evidence_unavailable record");
    assert_eq!(records[marker].outcome, AuditOutcome::Succeeded);
    let read = records
        .iter()
        .position(|record| record.tool == "oracle_query")
        .expect("the read's own audit record");
    assert!(
        marker < read,
        "the observation is chained before the read executes: {:?}",
        records
            .iter()
            .map(|record| &record.tool)
            .collect::<Vec<_>>()
    );
}

#[test]
fn proven_evidence_writes_no_fga_marker() {
    let sink = Arc::new(MemoryAuditSink::new());
    let auditor = Arc::new(oraclemcp_audit::Auditor::new(
        Box::new(SharedSink(Arc::clone(&sink))),
        SigningKey::new("r36-test-key", b"r36-fga-evidence-audit-test-key!".to_vec())
            .expect("valid test key"),
    ));
    let (dispatcher, _state) = semantic_dispatcher();
    let dispatcher = dispatcher.with_auditor(auditor);
    dispatcher
        .dispatch("oracle_query", json!({"sql": READ}))
        .expect("proven read");
    assert!(
        sink.records()
            .iter()
            .all(|record| record.tool != "fga_evidence_unavailable")
    );
}

#[test]
fn hard_parse_evidence_unavailable_has_a_readable_signed_record() {
    let sink = Arc::new(MemoryAuditSink::new());
    let auditor = oraclemcp_audit::Auditor::new(
        Box::new(SharedSink(Arc::clone(&sink))),
        SigningKey::new(
            "hard-parse-test-key",
            b"hard-parse-evidence-audit-test-key".to_vec(),
        )
        .expect("valid test key"),
    );
    let subject = AuditSubject::new("profile", "synthetic-cross-rw");
    append_hard_parse_evidence_unavailable_audit(
        AuditEntryCtx {
            auditor: Some(&auditor),
            subject: &subject,
            db_evidence: None,
        },
        "oracle_explain_plan",
        true,
        Some("plan_table_verification_no_privilege_sys_fallback"),
    )
    .expect("the admission record is durable before EXPLAIN is attempted");

    let records = sink.records();
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.tool, "hard_parse_evidence_unavailable");
    assert_eq!(record.subject, subject);
    assert_eq!(record.danger_level, "READ_ONLY");
    assert_eq!(record.decision, AuditDecision::Allowed);
    assert_eq!(record.outcome, AuditOutcome::Succeeded);
    assert_eq!(record.rows_affected, None);
    assert_eq!(record.sql_preview, "<sql text redacted; see sql_sha256>");
    assert!(record.hash_is_valid());
    assert!(record.signature.is_some());
}

#[test]
fn hard_parse_cost_closure_refusal_keeps_the_typed_odci_reason() {
    let error = query_cost_runtime_unavailable("odci_stats_callback");
    assert_eq!(error.error_class, ErrorClass::RuntimeStateRequired);
    assert_eq!(
        error
            .structured_reason
            .as_ref()
            .and_then(|reason| reason.offending_construct.as_deref()),
        Some("odci_stats_callback")
    );

    let read_path_error = query_cost_unavailable("odci_stats_callback");
    assert_eq!(
        read_path_error.error_class,
        ErrorClass::RuntimeStateRequired
    );
    assert_eq!(
        read_path_error
            .structured_reason
            .as_ref()
            .and_then(|reason| reason.offending_construct.as_deref()),
        Some("odci_stats_callback")
    );
}

/// The initially served profile is governed by its own `require_fga_evidence`:
/// binding the accepted config snapshot installs the rule, exactly as a
/// profile switch would.
#[test]
fn startup_profile_require_fga_evidence_is_installed_from_the_config_snapshot() {
    for (toml_flag, expected) in [
        ("", FgaEvidencePolicy::AdmitUnavailable),
        (
            "require_fga_evidence = false",
            FgaEvidencePolicy::AdmitUnavailable,
        ),
        (
            "require_fga_evidence = true",
            FgaEvidencePolicy::RequireProof,
        ),
    ] {
        let config = OracleMcpConfig::from_toml_str(&format!(
            r#"
            [[profiles]]
            name = "dev"
            connect_string = "dev:1521/svc"
            {toml_flag}
            "#
        ))
        .expect("config");
        let state = Arc::new(SemanticGuardState::default());
        *state
            .fga_catalog_unreadable
            .lock()
            .expect("FGA catalog fixture lock") = true;
        let dispatcher = OracleDispatcher::new_switchable(
            Box::new(SemanticGuardMock {
                state: Arc::clone(&state),
            }),
            Some("dev".to_owned()),
            default_read_only_level(),
            Arc::new(|_cx, _generation| Box::pin(async move { Ok(session_bundle(OneRowMock)) })),
        )
        .with_profile_drain_state(ProfileDrainState::from_config(config));
        let outcome = dispatcher.dispatch("oracle_query", json!({"sql": READ}));
        match expected {
            FgaEvidencePolicy::AdmitUnavailable => {
                let result = outcome.unwrap_or_else(|error| panic!("{toml_flag:?}: {error:?}"));
                assert_eq!(
                    result["fga_evidence"],
                    json!("unavailable"),
                    "{toml_flag:?}"
                );
            }
            FgaEvidencePolicy::RequireProof => {
                let error = outcome.expect_err("require_fga_evidence = true refuses");
                assert_eq!(offending_construct(&error), Some("fga_evidence_unknown"));
                assert_eq!(state.caller_queries.load(Ordering::SeqCst), 0);
            }
        }
    }
}
