//! Step-up / approval-token security suite (plan §7.2, §12; bead T-TOKEN).
//!
//! Asserts the token properties a production claim rests on: single-use,
//! replay-rejected, binding-checked (SQL-digest), monotonic-TTL, hashed-at-rest,
//! and never-in-audit-clear. `oraclemcp-guard` depends on `oraclemcp-audit`, so
//! the audit-cleartext property is checked here end-to-end.

use std::time::Duration;

use oraclemcp_audit::{
    AuditDecision, AuditEntryDraft, AuditOutcome, AuditRecord, AuditSubject, GENESIS_HASH,
};
use oraclemcp_guard::{
    AllowOnceError, AllowOnceStore, CiToken, ExecGrantBinding, ExecGrantError, ExecGrantStore,
    OperatingLevel, StepUpOption, StepUpRegistry, sql_digest,
};

const QUOTED_IDENTIFIER_TWO_SPACES: &str = "UPDATE \"A  B\" SET x = 1";
const QUOTED_IDENTIFIER_ONE_SPACE: &str = "UPDATE \"A B\" SET x = 1";

#[test]
fn allow_once_is_single_use_and_replay_rejected() {
    let store = AllowOnceStore::new();
    let sql = "UPDATE orders SET status='X' WHERE id=42";
    let tok = store.issue(sql, Duration::from_secs(60));
    assert_eq!(store.consume(&tok, sql), Ok(()));
    // Replay of a consumed token is rejected.
    assert_eq!(store.consume(&tok, sql), Err(AllowOnceError::Unknown));
}

#[test]
fn allow_once_is_digest_bound() {
    let store = AllowOnceStore::new();
    let tok = store.issue("DELETE FROM orders WHERE id=1", Duration::from_secs(60));
    // A different statement cannot consume the token (and does not burn it).
    assert_eq!(
        store.consume(&tok, "DROP TABLE orders"),
        Err(AllowOnceError::DigestMismatch)
    );
    // The originally-approved statement still works.
    assert_eq!(store.consume(&tok, "DELETE FROM orders WHERE id=1"), Ok(()));
}

#[test]
fn authorization_digests_preserve_semantic_whitespace() {
    assert_ne!(
        sql_digest(QUOTED_IDENTIFIER_TWO_SPACES),
        sql_digest(QUOTED_IDENTIFIER_ONE_SPACE),
        "quoted Oracle identifiers with different whitespace name different objects"
    );
    assert_ne!(
        sql_digest("UPDATE t SET value = 'A  B'"),
        sql_digest("UPDATE t SET value = 'A B'"),
        "ordinary string literal contents are semantic data"
    );
    assert_ne!(
        sql_digest("UPDATE t SET value = N'A  B'"),
        sql_digest("UPDATE t SET value = N'A B'"),
        "national string literal contents are semantic data"
    );
    assert_ne!(
        sql_digest("UPDATE t SET value = q'[A  B]'"),
        sql_digest("UPDATE t SET value = q'[A B]'"),
        "alternative-quoted literal contents are semantic data"
    );

    let allow_once = AllowOnceStore::new();
    let allow_token = allow_once.issue(QUOTED_IDENTIFIER_TWO_SPACES, Duration::from_secs(60));
    assert_eq!(
        allow_once.consume(&allow_token, QUOTED_IDENTIFIER_ONE_SPACE),
        Err(AllowOnceError::DigestMismatch)
    );

    let binding = ExecGrantBinding::new("session", "lane", "subject", 7);
    let grants = ExecGrantStore::new();
    let grant = grants.issue(
        QUOTED_IDENTIFIER_TWO_SPACES,
        binding.clone(),
        OperatingLevel::ReadWrite,
        Duration::from_secs(60),
    );
    assert_eq!(
        grants.consume(
            &grant,
            QUOTED_IDENTIFIER_ONE_SPACE,
            &binding,
            OperatingLevel::ReadWrite,
        ),
        Err(ExecGrantError::DigestMismatch)
    );

    let step_up = StepUpRegistry::new();
    let challenge = step_up.issue(
        OperatingLevel::ReadWrite,
        QUOTED_IDENTIFIER_TWO_SPACES,
        "write",
        Duration::from_secs(60),
    );
    step_up
        .resolve(&challenge.challenge_id, StepUpOption::ApproveOnce)
        .expect("resolve step-up challenge");
    assert!(!step_up.approval_matches_sql(&challenge.challenge_id, QUOTED_IDENTIFIER_ONE_SPACE,));
}

#[test]
fn allow_once_monotonic_ttl_expires() {
    let store = AllowOnceStore::new();
    let tok = store.issue("SELECT 1 FROM dual", Duration::from_secs(0));
    // Expired on the monotonic clock (a wall-clock jump cannot revive it —
    // MonotonicDeadline is the authoritative anchor).
    assert_eq!(
        store.consume(&tok, "SELECT 1 FROM dual"),
        Err(AllowOnceError::Expired)
    );
}

#[test]
fn stepup_approve_once_is_digest_bound_and_resolves_once() {
    let reg = StepUpRegistry::new();
    let sql = "UPDATE t SET x=1 WHERE id=2";
    let chal = reg.issue(
        OperatingLevel::ReadWrite,
        sql,
        "w",
        Duration::from_secs(300),
    );
    reg.resolve(&chal.challenge_id, StepUpOption::ApproveOnce)
        .expect("resolve");
    // The approval is bound to the exact statement digest.
    assert!(reg.approval_matches_sql(&chal.challenge_id, sql));
    assert!(!reg.approval_matches_sql(&chal.challenge_id, "DROP TABLE t"));
}

#[test]
fn ci_token_is_scope_and_ttl_bound() {
    let token = CiToken::issue(
        "secret",
        OperatingLevel::ReadWrite,
        Duration::from_secs(3600),
    );
    assert!(token.authorizes("secret", OperatingLevel::ReadWrite));
    assert!(!token.authorizes("secret", OperatingLevel::Ddl)); // above scope
    assert!(!token.authorizes("wrong-secret", OperatingLevel::ReadOnly)); // wrong secret
    let expired = CiToken::issue("secret", OperatingLevel::Admin, Duration::from_secs(0));
    assert!(!expired.authorizes("secret", OperatingLevel::ReadOnly)); // expired
}

#[test]
fn ci_token_secret_is_compared_in_constant_time() {
    // oracle-rwjl.10: the CI escalation secret is compared with a constant-time
    // byte comparison (no per-byte short-circuit timing side channel), matching
    // the codebase convention for the init token (oraclemcp-core) and OAuth HMAC
    // (oraclemcp-auth). Behavioural regression: a wrong secret that shares a
    // long prefix with the real one — and one of a different length — must both
    // be rejected exactly like any other wrong secret.
    let token = CiToken::issue(
        "ci-escalation-secret",
        OperatingLevel::ReadWrite,
        Duration::from_secs(3600),
    );
    assert!(token.authorizes("ci-escalation-secret", OperatingLevel::ReadWrite));
    // Shares all but the final byte with the real secret → rejected.
    assert!(!token.authorizes("ci-escalation-secreX", OperatingLevel::ReadWrite));
    // Correct prefix, truncated → rejected.
    assert!(!token.authorizes("ci-escalation", OperatingLevel::ReadWrite));
    // Longer than the real secret → rejected.
    assert!(!token.authorizes("ci-escalation-secret-extra", OperatingLevel::ReadWrite));
    // Empty → rejected.
    assert!(!token.authorizes("", OperatingLevel::ReadWrite));
}

#[test]
fn sql_is_hashed_at_rest_not_stored_clear() {
    // The approval binds to a sha256 digest, never the clear SQL.
    let sql = "UPDATE secret_table SET pw='hunter2' WHERE id=1";
    let digest = sql_digest(sql);
    assert!(digest.starts_with("sha256:"));
    assert!(
        !digest.contains("hunter2"),
        "secret value must not appear in the digest"
    );
    assert!(!digest.contains("secret_table"));
    // The StepUpChallenge carries the digest, not the raw SQL.
    let reg = StepUpRegistry::new();
    let chal = reg.issue(
        OperatingLevel::ReadWrite,
        sql,
        "redacted summary",
        Duration::from_secs(60),
    );
    assert_eq!(chal.sql_digest, digest);
    let json = serde_json::to_string(&chal).expect("serialize");
    assert!(
        !json.contains("hunter2"),
        "challenge must not serialize the secret bind value"
    );
}

#[test]
fn approval_token_never_appears_in_the_audit_record() {
    // An audit record stores the SQL sha256 + a preview — never the approval
    // token id and never bind values (plan §6.4).
    let store = AllowOnceStore::new();
    let sql = "UPDATE orders SET status='X' WHERE id=42";
    let token = store.issue(sql, Duration::from_secs(60));

    let draft = AuditEntryDraft {
        subject: AuditSubject::new("agent", "agent-1"),
        db_evidence: None,
        cancel: None,
        result_masking: None,
        tool: "oracle_query_execute".to_owned(),
        sql: sql.to_owned(),
        danger_level: "GUARDED".to_owned(),
        decision: AuditDecision::Allowed,
        rows_affected: Some(1),
        outcome: AuditOutcome::Succeeded,
    };
    let record =
        AuditRecord::chained_unsigned(&draft, 1, GENESIS_HASH, "2026-06-01T00:00:00Z".to_owned());
    let json = serde_json::to_string(&record).expect("serialize");
    assert!(
        !json.contains(&token),
        "the approval token id must never be in the audit record"
    );
    assert!(record.sql_sha256.starts_with("sha256:"));
    // The preview is bounded text, not the token.
    assert!(!record.sql_preview.contains(&token));
}
