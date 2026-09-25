//! R36: FGA evidence the principal cannot read must not block reads.
//!
//! A least-privilege account gets ORA-00942 from `ALL_AUDIT_POLICIES`. That is
//! UNAVAILABLE evidence, not a proven handler: the read is admitted with an
//! `fga_evidence: unavailable` observation and a signed audit marker, unless
//! the profile sets `require_fga_evidence`. A proven FGA handler refuses
//! whatever the profile says.

use super::*;
use oraclemcp_audit::{AuditError, AuditRecord, AuditSink, MemoryAuditSink, SigningKey};
use oraclemcp_db::{PLAN_COST_ESTIMATE_NOTE, PlanCostSummary};

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
    assert_eq!(records.len(), 2);
    for (record, observation) in records.iter().zip([
        "hard_parse_evidence_no_privilege",
        "plan_table_verification_no_privilege_sys_fallback",
    ]) {
        assert_eq!(
            record.tool,
            format!(
                "hard_parse_evidence_unavailable[served_tool=oracle_explain_plan;observation={observation}]"
            )
        );
        assert_eq!(record.sql_preview, "<sql text redacted; see sql_sha256>");
        assert_eq!(record.subject, subject);
        assert_eq!(record.danger_level, "READ_ONLY");
        assert_eq!(record.decision, AuditDecision::Allowed);
        assert_eq!(record.outcome, AuditOutcome::Succeeded);
        assert_eq!(record.rows_affected, None);
        assert!(record.hash_is_valid());
        assert!(record.signature.is_some());
    }
}

#[test]
fn dispatched_read_writes_readable_cost_unavailable_audit_before_admission() {
    let sink = Arc::new(MemoryAuditSink::new());
    let auditor = Arc::new(oraclemcp_audit::Auditor::new(
        Box::new(SharedSink(Arc::clone(&sink))),
        SigningKey::new(
            "hard-parse-dispatch",
            b"hard-parse-dispatch-audit-test-key-32".to_vec(),
        )
        .expect("valid test key"),
    ));
    let state = Arc::new(QueryCostGateState::new(PlanCostFixture::NoRoot));
    let dispatcher = OracleDispatcher::new_with_profile_level(
        Box::new(CostAuditMock(QueryCostGateMock {
            state: Arc::clone(&state),
        })),
        Some("dev".to_owned()),
        read_write_level(),
    )
    .with_max_query_cost(Some(1_000))
    .with_auditor(auditor);

    let result = dispatcher
        .dispatch(
            "oracle_query",
            json!({"sql": READ, "allow_plan_table_write": true}),
        )
        .expect("non-strict policy admits an unmeasurable read with an observation");
    assert!(
        result["verification_observations"]
            .as_array()
            .is_some_and(|observations| {
                observations.contains(&json!("hard_parse_evidence_no_privilege"))
                    && observations.contains(&json!("cost_unavailable"))
            })
    );
    assert!(result["row_count"].as_u64().is_some());

    let records = sink.records();
    let marker = records
        .iter()
        .position(|record| {
            record.tool
                == "hard_parse_evidence_unavailable[served_tool=oracle_query;observation=hard_parse_evidence_no_privilege]"
        })
        .unwrap_or_else(|| panic!("dispatch omitted readable hard-parse marker: {records:?}"));
    assert!(records[marker].hash_is_valid());
    assert!(records[marker].signature.is_some());
    assert_eq!(records[marker].decision, AuditDecision::Allowed);
    assert_eq!(records[marker].outcome, AuditOutcome::Succeeded);
    let query = records
        .iter()
        .position(|record| record.tool == "oracle_query")
        .expect("read's own audit transcript");
    assert!(
        marker < query,
        "cost observation must precede the target read"
    );
}

struct CostAuditMock(QueryCostGateMock);

#[async_trait::async_trait(?Send)]
impl OracleConnection for CostAuditMock {
    fn backend(&self) -> OracleBackend {
        self.0.backend()
    }

    async fn close(&self, cx: &Cx) -> Result<(), DbError> {
        self.0.close(cx).await
    }

    async fn ping(&self, cx: &Cx) -> Result<(), DbError> {
        self.0.ping(cx).await
    }

    async fn describe(&self, cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        self.0.describe(cx).await
    }

    async fn query_rows(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        let normalized = sql.to_ascii_lowercase();
        if normalized.contains("from all_policies")
            || normalized.contains("from redaction_policies")
        {
            return Ok(Vec::new());
        }
        if [
            "all_sa_table_policies",
            "all_sa_schema_policies",
            "all_xs_applied_policies",
        ]
        .iter()
        .any(|catalog| normalized.contains(catalog))
        {
            return Err(DbError::ServerQuery(
                "ORA-00942: table or view does not exist".to_owned(),
            ));
        }
        if normalized.contains("dbms_flashback.get_system_change_number") {
            return Ok(vec![semantic_row(&[("OBSERVED_SCN", Some("424242"))])]);
        }
        self.0.query_rows(cx, sql, binds).await
    }

    async fn execute(&self, cx: &Cx, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError> {
        self.0.execute(cx, sql, binds).await
    }

    async fn commit(&self, cx: &Cx) -> Result<(), DbError> {
        self.0.commit(cx).await
    }

    async fn rollback(&self, cx: &Cx) -> Result<(), DbError> {
        self.0.rollback(cx).await
    }
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
    assert_eq!(read_path_error.error_class, ErrorClass::ForbiddenStatement);
    assert_eq!(
        read_path_error
            .structured_reason
            .as_ref()
            .and_then(|reason| reason.offending_construct.as_deref()),
        Some("odci_stats_callback")
    );
}

#[test]
fn query_cost_unavailable_is_observable_but_measured_overage_stays_typed() {
    let unavailable = query_cost_runtime_unavailable("read_only_txn");
    assert!(query_cost_is_unavailable(&unavailable));

    let positive_evidence = query_cost_unavailable("odci_stats_callback");
    assert!(!query_cost_is_unavailable(&positive_evidence));
    assert_eq!(
        positive_evidence.error_class,
        ErrorClass::ForbiddenStatement
    );

    let overage = query_cost_exceeded(
        &PlanCostEstimate {
            summary: PlanCostSummary {
                total_cost: Some(9),
                total_cardinality: Some(1),
                total_bytes: Some(8),
            },
            rows: Vec::new(),
            note: PLAN_COST_ESTIMATE_NOTE.to_owned(),
        },
        9,
        1,
    );
    assert_eq!(overage.error_class, ErrorClass::PolicyDenied);
    assert_eq!(
        overage
            .structured_reason
            .as_ref()
            .and_then(|reason| reason.offending_construct.as_deref()),
        Some("query_cost_exceeded")
    );
}

#[test]
fn hard_parse_unknown_remains_a_refusal_when_strict_evidence_is_required() {
    let unknown = HardParseEffectClosureV1::AdmittedWithObservation {
        reason: "no_privilege",
    };
    assert!(hard_parse_closure_error(unknown.clone(), false).is_none());
    let strict = hard_parse_closure_error(unknown, true).expect("strict mode refuses unknown");
    assert_eq!(strict.error_class, ErrorClass::RuntimeStateRequired);
    assert_eq!(offending_construct(&strict), Some("no_privilege"));
}

#[test]
fn query_cost_strict_key_is_independent_from_hard_parse_strict_key() {
    for (hard_parse, query_cost, expected_hard_parse, expected_query_cost) in [
        ("", "", false, false),
        ("require_hard_parse_evidence = true", "", true, false),
        ("", "require_query_cost_estimate = true", false, true),
    ] {
        let config = OracleMcpConfig::from_toml_str(&format!(
            r#"
            [[profiles]]
            name = "dev"
            connect_string = "dev:1521/svc"
            {hard_parse}
            {query_cost}
            "#
        ))
        .expect("config");
        let profile = config.profile("dev").expect("dev profile");
        assert_eq!(profile.require_hard_parse_evidence(), expected_hard_parse);
        assert_eq!(profile.require_query_cost_estimate(), expected_query_cost);
    }
}

struct ReadOnlyTxnCostMock(QueryCostGateMock);

#[async_trait::async_trait(?Send)]
impl OracleConnection for ReadOnlyTxnCostMock {
    fn backend(&self) -> OracleBackend {
        self.0.backend()
    }

    async fn close(&self, cx: &Cx) -> Result<(), DbError> {
        self.0.close(cx).await
    }

    async fn ping(&self, cx: &Cx) -> Result<(), DbError> {
        self.0.ping(cx).await
    }

    async fn describe(&self, cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        self.0.describe(cx).await
    }

    async fn query_rows(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        self.0.query_rows(cx, sql, binds).await
    }

    async fn execute(&self, cx: &Cx, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError> {
        if sql == EXPLAIN_SAVEPOINT_SQL {
            return Err(DbError::ServerExecute(
                "ORA-01456: cannot specify SAVEPOINT in a read-only transaction".to_owned(),
            ));
        }
        self.0.execute(cx, sql, binds).await
    }

    async fn commit(&self, cx: &Cx) -> Result<(), DbError> {
        self.0.commit(cx).await
    }

    async fn rollback(&self, cx: &Cx) -> Result<(), DbError> {
        self.0.rollback(cx).await
    }
}

fn switchable_read_only_cost_dispatcher(
    root: PlanCostFixture,
    max_query_cost: u64,
    require_query_cost_estimate: bool,
) -> (
    OracleDispatcher,
    Arc<QueryCostGateState>,
    Arc<AtomicUsize>,
    Arc<TouchCounts>,
) {
    let state = Arc::new(QueryCostGateState::new(root));
    let opened_metadata_sessions = Arc::new(AtomicUsize::new(0));
    let opened = Arc::clone(&opened_metadata_sessions);
    let metadata_state = Arc::clone(&state);
    let metadata_pool_closes = Arc::new(TouchCounts::default());
    let pool_closes = Arc::clone(&metadata_pool_closes);
    let connector: Arc<ProfileConnector> = Arc::new(move |_cx, _generation| {
        opened.fetch_add(1, Ordering::SeqCst);
        let state = Arc::clone(&metadata_state);
        let pool_closes = Arc::clone(&pool_closes);
        Box::pin(async move {
            Ok(ProfileConnectionBundle::new(
                Box::new(QueryCostGateMock { state }),
                Some(Box::new(LabeledMock::new(
                    "cost-metadata-pool",
                    "stateless_metadata_pool",
                    pool_closes,
                ))),
            ))
        })
    });
    let strict_cost = if require_query_cost_estimate {
        "require_query_cost_estimate = true\n"
    } else {
        ""
    };
    let config = OracleMcpConfig::from_toml_str(&format!(
        "[[profiles]]\nname = \"dev\"\nconnect_string = \"dev:1521/svc\"\n{strict_cost}"
    ))
    .expect("profile config");
    let dispatcher = OracleDispatcher::new_switchable(
        Box::new(ReadOnlyTxnCostMock(QueryCostGateMock {
            state: Arc::clone(&state),
        })),
        Some("dev".to_owned()),
        read_write_level(),
        connector,
    )
    .with_profile_drain_state(ProfileDrainState::from_config(config))
    .with_max_query_cost(Some(max_query_cost));
    (
        dispatcher,
        state,
        opened_metadata_sessions,
        metadata_pool_closes,
    )
}

#[test]
fn read_only_transaction_uses_metadata_session_and_still_enforces_cost_cap() {
    let (over, over_state, over_opens, over_pool_closes) =
        switchable_read_only_cost_dispatcher(PlanCostFixture::Root(Some(190_000)), 50_000, false);
    let over_error = over
        .dispatch(
            "oracle_query",
            json!({"sql": "SELECT 1 FROM dual", "allow_plan_table_write": true}),
        )
        .expect_err("over-cap reads refuse even if the caller session is transaction-read-only");
    assert_eq!(over_error.error_class, ErrorClass::PolicyDenied);
    assert_eq!(
        over_error
            .structured_reason
            .as_ref()
            .and_then(|reason| reason.offending_construct.as_deref()),
        Some("query_cost_exceeded")
    );
    assert_eq!(over_state.actual_reads.load(Ordering::SeqCst), 0);
    assert!(over_opens.load(Ordering::SeqCst) > 0);
    assert_eq!(
        over_pool_closes.close.load(Ordering::SeqCst),
        over_opens.load(Ordering::SeqCst)
    );

    let (under, under_state, under_opens, under_pool_closes) =
        switchable_read_only_cost_dispatcher(PlanCostFixture::Root(Some(2)), 50_000, false);
    let result = under
        .dispatch(
            "oracle_query",
            json!({"sql": "SELECT 1 FROM dual", "allow_plan_table_write": true}),
        )
        .expect("under-cap reads proceed after metadata-session estimation");
    assert_eq!(result["row_count"], json!(1));
    assert_eq!(under_state.actual_reads.load(Ordering::SeqCst), 1);
    assert!(under_opens.load(Ordering::SeqCst) > 0);
    assert_eq!(
        under_pool_closes.close.load(Ordering::SeqCst),
        under_opens.load(Ordering::SeqCst)
    );

    let (strict, strict_state, strict_opens, strict_pool_closes) =
        switchable_read_only_cost_dispatcher(PlanCostFixture::NoRoot, 50_000, true);
    let strict_error = strict
        .dispatch(
            "oracle_query",
            json!({"sql": "SELECT 1 FROM dual", "allow_plan_table_write": true}),
        )
        .expect_err("dedicated strict cost key refuses an unavailable estimate");
    assert_eq!(strict_error.error_class, ErrorClass::RuntimeStateRequired);
    assert_eq!(strict_state.actual_reads.load(Ordering::SeqCst), 0);
    assert!(strict_opens.load(Ordering::SeqCst) > 0);
    assert_eq!(
        strict_pool_closes.close.load(Ordering::SeqCst),
        strict_opens.load(Ordering::SeqCst)
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
