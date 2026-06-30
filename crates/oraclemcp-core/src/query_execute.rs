//! The `oracle_query_execute` tool (plan §8.1; bead P1-QE / oracle-qmwz.2.16).
//!
//! The write-execution path: the agent presents the single-use execution grant
//! ([`ExecGrantStore`]) minted when `oracle_query` classified a write statement
//! and the step-up gate approved an operating level. This handler validates the
//! grant (single-use, SQL-digest match, session match, not expired, requested
//! level ≤ granted), then — **fsync-before-execute** (§5.13) — durably logs the
//! approved statement *before* it runs, executes exactly that statement at the
//! granted level via the injected [`StatementExecutor`], and durably logs the
//! outcome. The executor is injected so this handler (and the one-way boundary)
//! stays engine-free and unit-testable.
//!
//! In P1 this executes the approved statement *without* the execute-in-savepoint
//! ground-truth preview — that is P2-3.

use oraclemcp_audit::{AuditDecision, AuditEntryDraft, AuditOutcome, AuditSubject, Auditor};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use oraclemcp_guard::{ExecGrantBinding, ExecGrantError, ExecGrantStore, OperatingLevel};
use serde::Deserialize;
use serde_json::{Value, json};

/// Runs a pre-classified, pre-approved statement at the granted operating level
/// (engine/DB-side, within the consuming session's lease transaction).
pub trait StatementExecutor: Send + Sync {
    /// Execute `sql` at `level`; return rows affected.
    fn execute(&self, sql: &str, level: OperatingLevel) -> Result<u64, ErrorEnvelope>;
}

/// `oracle_query_execute` arguments (flat object schema, §8.1).
#[derive(Debug, Deserialize)]
pub struct ExecuteParams {
    /// The opaque execution-grant token from the approval step.
    pub token: String,
    /// The exact statement to run (must match the approved digest).
    pub sql: String,
    /// The session the grant was issued to.
    pub session_id: String,
    /// The server-assigned lane id the grant was issued to.
    pub lane_id: String,
    /// The verified, server-derived subject id the grant was issued to.
    pub subject_id: String,
    /// The lane/profile/level generation captured when the grant was issued.
    pub generation: u64,
    /// The operating level the caller asserts it needs (≤ granted). Defaults to
    /// `READ_WRITE` (the common DML case) when omitted.
    #[serde(default)]
    pub requested_level: Option<String>,
}

/// Parse a flat operating-level string; `None` → `READ_WRITE`.
fn parse_level(s: Option<&str>) -> Result<OperatingLevel, ErrorEnvelope> {
    match s {
        None => Ok(OperatingLevel::ReadWrite),
        Some(raw) => OperatingLevel::parse(raw).ok_or_else(|| {
            ErrorEnvelope::new(
                ErrorClass::InvalidArguments,
                format!(
                    "unknown operating level '{}'",
                    raw.trim().to_ascii_uppercase()
                ),
            )
        }),
    }
}

fn grant_error_to_envelope(e: ExecGrantError) -> ErrorEnvelope {
    match e {
        ExecGrantError::Unknown => ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            "execution grant is unknown or already used (single-use); request a fresh approval",
        )
        .with_next_step("re-run oracle_query and complete the step-up to mint a new grant"),
        ExecGrantError::Expired => ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            "execution grant has expired; request a fresh approval",
        )
        .with_next_step("re-run oracle_query and complete the step-up to mint a new grant"),
        ExecGrantError::DigestMismatch => ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            "sql does not match the approved statement (digest mismatch)",
        ),
        ExecGrantError::SessionMismatch => ErrorEnvelope::new(
            ErrorClass::RuntimeStateRequired,
            "execution grant belongs to a different session",
        ),
        ExecGrantError::LaneMismatch => ErrorEnvelope::new(
            ErrorClass::RuntimeStateRequired,
            "execution grant belongs to a different lane",
        ),
        ExecGrantError::SubjectMismatch => ErrorEnvelope::new(
            ErrorClass::RuntimeStateRequired,
            "execution grant belongs to a different subject",
        ),
        ExecGrantError::GenerationMismatch { presented, granted } => ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            format!(
                "execution grant was minted for generation {granted}, but current generation is {presented}"
            ),
        )
        .with_next_step("preview the statement again on the current lane/profile generation"),
        ExecGrantError::LevelExceedsGrant { requested, granted } => ErrorEnvelope::new(
            ErrorClass::OperatingLevelTooLow,
            format!(
                "requested level {} exceeds the granted level {}",
                requested.as_str(),
                granted.as_str()
            ),
        ),
        // `ExecGrantError` is #[non_exhaustive]; fail closed on any future variant.
        _ => ErrorEnvelope::new(ErrorClass::ChallengeRequired, "execution grant rejected"),
    }
}

fn audit_error_to_envelope(e: oraclemcp_audit::AuditError) -> ErrorEnvelope {
    ErrorEnvelope::new(ErrorClass::Internal, format!("audit append failed: {e}"))
}

/// Run `oracle_query_execute`. `now` supplies audit timestamps (injected so the
/// handler is pure/testable). Returns the structured execution result, or an
/// [`ErrorEnvelope`] for grant/audit/execution failure.
pub fn oracle_query_execute(
    grants: &ExecGrantStore,
    auditor: &Auditor,
    executor: &dyn StatementExecutor,
    server_subject: &AuditSubject,
    params: &ExecuteParams,
    mut now: impl FnMut() -> String,
) -> Result<Value, ErrorEnvelope> {
    let requested = parse_level(params.requested_level.as_deref())?;

    // 1) Consume the grant: single-use, digest, session, level, expiry.
    let binding = ExecGrantBinding::new(
        params.session_id.clone(),
        params.lane_id.clone(),
        params.subject_id.clone(),
        params.generation,
    );
    let granted = grants
        .consume(&params.token, &params.sql, &binding, requested)
        .map_err(grant_error_to_envelope)?;

    // 2) fsync-before-execute: durably log the approved statement BEFORE it runs,
    //    so a crash between here and the execute leaves the log written and the
    //    database untouched.
    let subject = server_subject.clone();
    let pre = AuditEntryDraft {
        subject: subject.clone(),
        db_evidence: None,
        cancel: None,
        tool: "oracle_query_execute".to_owned(),
        sql: params.sql.clone(),
        danger_level: granted.as_str().to_owned(),
        decision: AuditDecision::Allowed,
        rows_affected: None,
        outcome: AuditOutcome::Pending,
    };
    auditor
        .append(&pre, now(), true)
        .map_err(audit_error_to_envelope)?;

    // 3) Execute exactly the approved statement at the granted level.
    let result = executor.execute(&params.sql, granted);

    // 4) Durably log the outcome (append-only; the chain is the record of truth).
    let (outcome, rows) = match &result {
        Ok(n) => (AuditOutcome::Succeeded, Some(*n)),
        Err(_) => (AuditOutcome::Failed, None),
    };
    let post = AuditEntryDraft {
        subject,
        db_evidence: None,
        cancel: None,
        tool: "oracle_query_execute".to_owned(),
        sql: params.sql.clone(),
        danger_level: granted.as_str().to_owned(),
        decision: AuditDecision::Allowed,
        rows_affected: rows,
        outcome,
    };
    auditor
        .append(&post, now(), true)
        .map_err(audit_error_to_envelope)?;

    let rows_affected = result?;
    Ok(json!({
        "executed": true,
        "rows_affected": rows_affected,
        "operating_level": granted.as_str(),
        "session_id": params.session_id,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use oraclemcp_audit::MemoryAuditSink;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    /// Mock executor counting calls; returns a fixed row count or an error.
    struct MockExecutor {
        calls: AtomicU64,
        result: Result<u64, ()>,
    }
    impl MockExecutor {
        fn ok(rows: u64) -> Self {
            MockExecutor {
                calls: AtomicU64::new(0),
                result: Ok(rows),
            }
        }
        fn fail() -> Self {
            MockExecutor {
                calls: AtomicU64::new(0),
                result: Err(()),
            }
        }
        fn call_count(&self) -> u64 {
            self.calls.load(Ordering::SeqCst)
        }
    }
    impl StatementExecutor for MockExecutor {
        fn execute(&self, _sql: &str, _level: OperatingLevel) -> Result<u64, ErrorEnvelope> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result
                .map_err(|()| ErrorEnvelope::new(ErrorClass::Internal, "boom"))
        }
    }

    fn clock() -> impl FnMut() -> String {
        let mut n = 0u64;
        move || {
            n += 1;
            format!("t{n}")
        }
    }

    fn auditor() -> (Auditor, Arc<MemoryAuditSink>) {
        let sink = Arc::new(MemoryAuditSink::new());
        // Auditor takes Box<dyn AuditSink>; wrap the shared handle.
        struct Shared(Arc<MemoryAuditSink>);
        impl oraclemcp_audit::AuditSink for Shared {
            fn append(
                &self,
                r: &oraclemcp_audit::AuditRecord,
            ) -> Result<(), oraclemcp_audit::AuditError> {
                self.0.append(r)
            }
            fn flush(&self) -> Result<(), oraclemcp_audit::AuditError> {
                self.0.flush()
            }
        }
        (
            Auditor::new(
                Box::new(Shared(sink.clone())),
                oraclemcp_audit::SigningKey::new("test", b"qe-test-key".to_vec()),
            ),
            sink,
        )
    }

    const SQL: &str = "UPDATE orders SET status='X' WHERE id=42";

    fn binding() -> ExecGrantBinding {
        ExecGrantBinding::new("sess-1", "lane-1", "subject-1", 1)
    }

    fn params(token: &str, sql: &str, level: Option<&str>) -> ExecuteParams {
        ExecuteParams {
            token: token.to_owned(),
            sql: sql.to_owned(),
            session_id: "sess-1".to_owned(),
            lane_id: "lane-1".to_owned(),
            subject_id: "subject-1".to_owned(),
            generation: 1,
            requested_level: level.map(str::to_owned),
        }
    }

    fn subject() -> AuditSubject {
        AuditSubject::new("oauth", "subject-1").with_authn_method("oauth")
    }

    #[test]
    fn valid_grant_executes_once_and_audits_pre_and_post() {
        let grants = ExecGrantStore::new();
        let tok = grants.issue(
            SQL,
            binding(),
            OperatingLevel::ReadWrite,
            Duration::from_secs(60),
        );
        let (aud, sink) = auditor();
        let exec = MockExecutor::ok(3);

        let out = oracle_query_execute(
            &grants,
            &aud,
            &exec,
            &subject(),
            &params(&tok, SQL, Some("READ_WRITE")),
            clock(),
        )
        .expect("execute ok");
        assert_eq!(out["executed"], json!(true));
        assert_eq!(out["rows_affected"], json!(3));
        assert_eq!(out["operating_level"], json!("READ_WRITE"));
        assert_eq!(exec.call_count(), 1);

        // Two durable records: Pending (pre) then SUCCEEDED (post).
        let recs = sink.records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].outcome, AuditOutcome::Pending);
        assert_eq!(recs[1].outcome, AuditOutcome::Succeeded);
        assert_eq!(recs[1].rows_affected, Some(3));
        // Chain links: post.prev_hash == pre.entry_hash.
        assert_eq!(recs[1].prev_hash, recs[0].entry_hash);

        // Replay is rejected (single-use) and never reaches the executor.
        let err = oracle_query_execute(
            &grants,
            &aud,
            &exec,
            &subject(),
            &params(&tok, SQL, Some("READ_WRITE")),
            clock(),
        )
        .expect_err("replay rejected");
        assert_eq!(err.error_class, ErrorClass::ChallengeRequired);
        assert_eq!(exec.call_count(), 1, "replay must not execute");
    }

    #[test]
    fn digest_mismatch_does_not_execute() {
        let grants = ExecGrantStore::new();
        let tok = grants.issue(
            SQL,
            binding(),
            OperatingLevel::ReadWrite,
            Duration::from_secs(60),
        );
        let (aud, sink) = auditor();
        let exec = MockExecutor::ok(1);
        let err = oracle_query_execute(
            &grants,
            &aud,
            &exec,
            &subject(),
            &params(&tok, "DROP TABLE orders", None),
            clock(),
        )
        .expect_err("digest mismatch");
        assert_eq!(err.error_class, ErrorClass::InvalidArguments);
        assert_eq!(exec.call_count(), 0);
        assert!(
            sink.records().is_empty(),
            "no audit before a rejected grant"
        );
    }

    #[test]
    fn stale_generation_does_not_execute() {
        let grants = ExecGrantStore::new();
        let tok = grants.issue(
            SQL,
            binding(),
            OperatingLevel::ReadWrite,
            Duration::from_secs(60),
        );
        let (aud, sink) = auditor();
        let exec = MockExecutor::ok(1);
        let mut stale = params(&tok, SQL, Some("READ_WRITE"));
        stale.generation = 2;

        let err = oracle_query_execute(&grants, &aud, &exec, &subject(), &stale, clock())
            .expect_err("stale generation rejected");
        assert_eq!(err.error_class, ErrorClass::ChallengeRequired);
        assert_eq!(exec.call_count(), 0);
        assert!(
            sink.records().is_empty(),
            "no audit before a rejected stale-generation grant"
        );

        let out = oracle_query_execute(
            &grants,
            &aud,
            &exec,
            &subject(),
            &params(&tok, SQL, Some("READ_WRITE")),
            clock(),
        )
        .expect("correct generation still consumes the grant");
        assert_eq!(out["executed"], json!(true));
        assert_eq!(exec.call_count(), 1);
    }

    #[test]
    fn requesting_above_grant_is_rejected() {
        let grants = ExecGrantStore::new();
        let tok = grants.issue(
            "DROP TABLE t",
            binding(),
            OperatingLevel::ReadWrite,
            Duration::from_secs(60),
        );
        let (aud, _sink) = auditor();
        let exec = MockExecutor::ok(0);
        let err = oracle_query_execute(
            &grants,
            &aud,
            &exec,
            &subject(),
            &params(&tok, "DROP TABLE t", Some("DDL")),
            clock(),
        )
        .expect_err("level too low");
        assert_eq!(err.error_class, ErrorClass::OperatingLevelTooLow);
        assert_eq!(exec.call_count(), 0);
    }

    #[test]
    fn executor_failure_is_audited_as_failed_and_propagated() {
        let grants = ExecGrantStore::new();
        let tok = grants.issue(
            SQL,
            binding(),
            OperatingLevel::ReadWrite,
            Duration::from_secs(60),
        );
        let (aud, sink) = auditor();
        let exec = MockExecutor::fail();
        let err = oracle_query_execute(
            &grants,
            &aud,
            &exec,
            &subject(),
            &params(&tok, SQL, None),
            clock(),
        )
        .expect_err("executor failed");
        assert_eq!(err.error_class, ErrorClass::Internal);
        let recs = sink.records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].outcome, AuditOutcome::Pending);
        assert_eq!(recs[1].outcome, AuditOutcome::Failed);
    }
}
