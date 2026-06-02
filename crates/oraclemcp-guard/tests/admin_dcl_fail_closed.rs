//! End-to-end (public-API) regression for oracle-clgt.3 / oracle-clgt.13: an
//! admin/DCL statement that sqlparser 0.62 cannot parse (or that parses to a
//! variant which used to hit the ReadWrite catch-all) must fail CLOSED to
//! `OperatingLevel::Admin`, so a session elevated only to `ReadWrite` is forced
//! to step up to `Admin` (never silently Allowed) before any privilege
//! escalation runs. This exercises the real `Classifier` public surface, not the
//! crate-internal `classify` test helper.

use oraclemcp_guard::classifier::Classifier;
use oraclemcp_guard::levels::{DangerLevel, LevelDecision, OperatingLevel, SessionLevelState};

#[test]
fn admin_dcl_requires_admin_step_up_via_public_api() {
    // A session whose ceiling is Admin, currently elevated only to ReadWrite —
    // the precise escalation the bead describes.
    let mut session = SessionLevelState::new(OperatingLevel::Admin, false);
    session
        .set_current_level(OperatingLevel::ReadWrite)
        .expect("step current level to ReadWrite");
    let classifier = Classifier::default();

    for sql in [
        "GRANT DBA TO scott",
        "REVOKE DBA FROM scott",
        "ALTER USER sys IDENTIFIED BY hacked",
        "ALTER SYSTEM SET sga_target = 0",
        "ALTER DATABASE OPEN",
        "ALTER PROFILE default LIMIT sessions_per_user 10",
        "CREATE USER evil IDENTIFIED BY pw",
        "ALTER ROLE evil",
        "AUDIT SELECT ON orders",
        "NOAUDIT SELECT ON orders",
        "CREATE ROLE evil",
        "DROP ROLE evil",
        "DROP USER evil",
        "SET ROLE dba",
    ] {
        let decision = classifier.classify(sql);
        assert_eq!(
            decision.danger,
            DangerLevel::Destructive,
            "admin/DCL must be Destructive: {sql:?}"
        );
        assert_eq!(
            decision.required_level,
            Some(OperatingLevel::Admin),
            "admin/DCL must require Admin: {sql:?}"
        );
        assert_eq!(
            decision.gate(&session),
            LevelDecision::RequireStepUp {
                target: OperatingLevel::Admin
            },
            "a ReadWrite-elevated session must be forced to step up to Admin: {sql:?}"
        );
    }
}

#[test]
fn non_admin_statements_are_not_over_escalated_via_public_api() {
    // Word-boundary / leading-only guard: identifiers that merely begin with an
    // admin verb's letters, and admin verbs that are not statement-leading, must
    // never be over-escalated to Admin.
    let classifier = Classifier::default();
    for sql in [
        "SELECT deleted_flag FROM t",
        "SELECT granted_flag FROM audit_log",
        "UPDATE t SET granted_flag = 1 WHERE id = 1",
        "INSERT INTO grants_audit (auditor) VALUES ('x')",
    ] {
        let decision = classifier.classify(sql);
        assert_ne!(
            decision.required_level,
            Some(OperatingLevel::Admin),
            "{sql:?} must not require Admin"
        );
    }
}
