#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use asupersync::Cx;
use asupersync::cx::NoCaps;
use oraclemcp_audit::{AuditRecord, AuditSink, Auditor, MemoryAuditSink, SigningKey};
use oraclemcp_core::error::{ErrorClass, ErrorEnvelope};
use oraclemcp_core::{AdmissionController, AdmissionPermit, ExecuteParams, StatementExecutor};
use oraclemcp_guard::{
    Classifier, ClassifierConfig, ExecGrantBinding, ExecGrantStore, OperatingLevel,
    SessionLevelState,
};

#[derive(Clone, Copy, Debug)]
enum TerminalPath {
    Success,
    Error,
    Cancel,
    Timeout,
    Delete,
    Reaper,
    Shutdown,
    Panic,
}

struct ModelLane {
    permit: Option<AdmissionPermit>,
    terminal: Option<TerminalPath>,
}

impl ModelLane {
    fn new(permit: AdmissionPermit) -> Self {
        Self {
            permit: Some(permit),
            terminal: None,
        }
    }

    fn terminal_transition(&mut self, path: TerminalPath) {
        if self.terminal.is_none() {
            self.terminal = Some(path);
            drop(self.permit.take());
        }
    }
}

#[test]
fn permit_released_exactly_once_for_every_terminal_lane_path() {
    for path in [
        TerminalPath::Success,
        TerminalPath::Error,
        TerminalPath::Cancel,
        TerminalPath::Timeout,
        TerminalPath::Delete,
        TerminalPath::Reaper,
        TerminalPath::Shutdown,
        TerminalPath::Panic,
    ] {
        let cx = Cx::<NoCaps>::detached_cancel_context();
        let admission = AdmissionController::new(1, 1);
        let permit = admission
            .try_admit(&cx, "subject-a")
            .expect("model lane admits one permit");
        assert_eq!(admission.available_global(), 0);

        let mut lane = ModelLane::new(permit);
        lane.terminal_transition(path);
        assert_eq!(
            admission.available_global(),
            1,
            "{path:?} releases the lane permit"
        );

        lane.terminal_transition(path);
        lane.terminal_transition(TerminalPath::Shutdown);
        assert_eq!(
            admission.available_global(),
            1,
            "{path:?} is idempotent and cannot double-release"
        );
    }
}

#[test]
fn panic_terminal_path_releases_capacity_without_touching_sibling_lane() {
    let cx = Cx::<NoCaps>::detached_cancel_context();
    let admission = AdmissionController::new(2, 1);
    let panicking_permit = admission
        .try_admit(&cx, "panic-subject")
        .expect("panic lane admitted");
    let sibling_permit = admission
        .try_admit(&cx, "sibling-subject")
        .expect("sibling lane admitted");
    assert_eq!(admission.available_global(), 0);

    let mut panicking = ModelLane::new(panicking_permit);
    let mut sibling = ModelLane::new(sibling_permit);

    panicking.terminal_transition(TerminalPath::Panic);
    assert_eq!(
        admission.available_global(),
        1,
        "a panicked lane must release its bulkhead permit"
    );

    let replacement = admission
        .try_admit(&cx, "replacement-subject")
        .expect("capacity released by panic admits a replacement lane");
    assert_eq!(admission.available_global(), 0);
    assert!(
        sibling.terminal.is_none(),
        "panic terminal path must not mutate a sibling lane"
    );

    sibling.terminal_transition(TerminalPath::Success);
    assert_eq!(
        admission.available_global(),
        1,
        "sibling release is independent while replacement is still held"
    );
    drop(replacement);
    assert_eq!(admission.available_global(), 2);
}

struct CountingExecutor {
    calls: AtomicU64,
}

impl StatementExecutor for CountingExecutor {
    fn execute(&self, _sql: &str, _level: OperatingLevel) -> Result<u64, ErrorEnvelope> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(1)
    }
}

struct SharedSink(Arc<MemoryAuditSink>);

impl AuditSink for SharedSink {
    fn append(&self, record: &AuditRecord) -> Result<(), oraclemcp_audit::AuditError> {
        self.0.append(record)
    }

    fn append_with_verdict_certificate(
        &self,
        record: &AuditRecord,
        certificate: &oraclemcp_audit::BoundAuditVerdictCertificate,
    ) -> Result<(), oraclemcp_audit::AuditError> {
        self.0.append_with_verdict_certificate(record, certificate)
    }

    fn flush(&self) -> Result<(), oraclemcp_audit::AuditError> {
        self.0.flush()
    }
}

fn params(
    token: &str,
    sql: &str,
    session_id: &str,
    lane_id: &str,
    subject_id: &str,
    generation: u64,
) -> ExecuteParams {
    ExecuteParams {
        token: token.to_owned(),
        sql: sql.to_owned(),
        session_id: session_id.to_owned(),
        lane_id: lane_id.to_owned(),
        subject_id: subject_id.to_owned(),
        generation,
        requested_level: Some("READ_WRITE".to_owned()),
    }
}

#[test]
fn switch_generation_invalidates_stale_grants_and_subject_mix() {
    let sql = "UPDATE employees SET salary = salary WHERE employee_id = 1";
    let grants = ExecGrantStore::new();
    let binding = ExecGrantBinding::new("sid-a", "lane-a", "subject-a", 1);
    let token = grants.issue(
        sql,
        binding,
        OperatingLevel::ReadWrite,
        Duration::from_secs(60),
    );
    let sink = Arc::new(MemoryAuditSink::new());
    let auditor = Auditor::new(
        Box::new(SharedSink(Arc::clone(&sink))),
        SigningKey::new("n9-test", b"n9-state-machine-test-key-12345678".to_vec())
            .expect("valid test key"),
    );
    let executor = CountingExecutor {
        calls: AtomicU64::new(0),
    };
    let subject =
        oraclemcp_audit::AuditSubject::new("oauth", "subject-a").with_authn_method("oauth");

    // SEC-1 re-gate inputs: the default fail-closed classifier and a live session
    // at READ_WRITE, so the re-gate `Allow`s this UPDATE and the test exercises the
    // grant generation/subject rejection paths (not the level gate).
    let classifier = Classifier::new(ClassifierConfig::new());
    let mut session = SessionLevelState::new(OperatingLevel::ReadWrite, false);
    session
        .set_current_level(OperatingLevel::ReadWrite)
        .expect("READ_WRITE is within the ceiling");

    let stale = params(&token, sql, "sid-a", "lane-a", "subject-a", 2);
    let err = oraclemcp_core::oracle_query_execute(
        &grants,
        &classifier,
        &session,
        &auditor,
        &executor,
        &subject,
        &stale,
        || "t-stale".to_owned(),
    )
    .expect_err("stale generation is rejected before execution");
    assert_eq!(err.error_class, ErrorClass::ChallengeRequired);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    assert!(
        sink.records().is_empty(),
        "rejected stale grants must not append audit records"
    );

    let wrong_subject = params(&token, sql, "sid-a", "lane-a", "subject-b", 1);
    let err = oraclemcp_core::oracle_query_execute(
        &grants,
        &classifier,
        &session,
        &auditor,
        &executor,
        &subject,
        &wrong_subject,
        || "t-wrong-subject".to_owned(),
    )
    .expect_err("wrong subject is rejected before execution");
    assert_eq!(err.error_class, ErrorClass::RuntimeStateRequired);
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    assert!(
        sink.records().is_empty(),
        "wrong-subject grants must not append audit records"
    );

    let accepted = params(&token, sql, "sid-a", "lane-a", "subject-a", 1);
    let out = oraclemcp_core::oracle_query_execute(
        &grants,
        &classifier,
        &session,
        &auditor,
        &executor,
        &subject,
        &accepted,
        || "t-ok".to_owned(),
    )
    .expect("current generation and subject consume the grant");
    assert_eq!(out["executed"], serde_json::json!(true));
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    let records = sink.records();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].subject, subject);
    assert_eq!(records[1].subject, subject);
    assert_eq!(records[1].prev_hash, records[0].entry_hash);
}
