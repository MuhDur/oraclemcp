//! Read-only enforcement layers (plan §6.3) and the session-setting allowlist
//! (§6.5). Three complementary layers protect a read-only session, strongest
//! first:
//!
//! - **(A) DB-privilege ceiling** — a least-privilege Oracle user (operator's
//!   responsibility; see `docs/oraclemcp/least-privilege.md`). The only hard
//!   boundary.
//! - **(B) `SET TRANSACTION READ ONLY`** — issued whenever the session level is
//!   `READ_ONLY`, so a *misclassified* direct DML still raises `ORA-01456`.
//! - **(C) The fail-closed classifier** (P1-1) + the operating-level gate (P0-7).
//!
//! Caveat (carried everywhere): layer B does **not** stop
//! `PRAGMA AUTONOMOUS_TRANSACTION` side-effects fired by triggers/VPD functions
//! (they commit independently, no `ORA-01456`). The classifier's trigger/VPD
//! walk is the defense; on a `protected` profile, layer A is the real boundary.

use crate::levels::OperatingLevel;

/// The statement that makes the current transaction read-only at the engine.
pub const SET_TRANSACTION_READ_ONLY: &str = "SET TRANSACTION READ ONLY";

/// Session-setup statements to apply for a session at `level` on a profile
/// (`protected` = production). At `READ_ONLY` this issues
/// `SET TRANSACTION READ ONLY` (layer B). `SET ROLE` and non-allowlisted
/// `ALTER SESSION` are blocked by the classifier (layer C), so a session cannot
/// enable a write-bearing role post-connect.
#[must_use]
pub fn read_only_setup_statements(level: OperatingLevel) -> Vec<&'static str> {
    if level == OperatingLevel::ReadOnly {
        vec![SET_TRANSACTION_READ_ONLY]
    } else {
        Vec::new()
    }
}

/// The allowlist of `ALTER SESSION SET <param>` parameters an agent may set at
/// `READ_ONLY` (§6.5): session-scoped, non-data-mutating, non-security.
const ALTER_SESSION_ALLOWLIST: &[&str] = &[
    "CURRENT_SCHEMA",
    "NLS_DATE_FORMAT",
    "NLS_TIMESTAMP_FORMAT",
    "NLS_TIMESTAMP_TZ_FORMAT",
    "NLS_NUMERIC_CHARACTERS",
    "NLS_LANGUAGE",
    "NLS_TERRITORY",
    "NLS_SORT",
    "NLS_COMP",
    "TIME_ZONE",
    "OPTIMIZER_MODE",
    "STATISTICS_LEVEL",
    "OPTIMIZER_DYNAMIC_SAMPLING",
];

/// Whether an `ALTER SESSION SET <param> = …` statement targets an allowlisted,
/// safe session parameter (§6.5). Anything outside the allowlist (e.g. statements
/// that change security/audit context) is rejected. Case-insensitive.
#[must_use]
pub fn is_allowed_alter_session(stmt: &str) -> bool {
    let upper = stmt.trim().to_ascii_uppercase();
    let Some(rest) = upper.strip_prefix("ALTER SESSION SET ") else {
        return false;
    };
    // The parameter name is the token up to `=` or whitespace.
    let param = rest.split(['=', ' ', '\t']).next().unwrap_or("").trim();
    ALTER_SESSION_ALLOWLIST.contains(&param)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_level_sets_transaction_read_only() {
        assert_eq!(
            read_only_setup_statements(OperatingLevel::ReadOnly),
            vec![SET_TRANSACTION_READ_ONLY]
        );
        assert!(read_only_setup_statements(OperatingLevel::ReadWrite).is_empty());
        assert!(read_only_setup_statements(OperatingLevel::Ddl).is_empty());
    }

    #[test]
    fn alter_session_allowlist_permits_safe_params() {
        assert!(is_allowed_alter_session(
            "ALTER SESSION SET CURRENT_SCHEMA = HR"
        ));
        assert!(is_allowed_alter_session(
            "alter session set nls_date_format='YYYY'"
        ));
        assert!(is_allowed_alter_session(
            "ALTER SESSION SET OPTIMIZER_MODE = ALL_ROWS"
        ));
    }

    #[test]
    fn alter_session_allowlist_rejects_security_and_unknown() {
        // Security/audit context changes are rejected.
        assert!(!is_allowed_alter_session(
            "ALTER SESSION SET CONTAINER = CDB$ROOT"
        ));
        assert!(!is_allowed_alter_session(
            "ALTER SESSION SET SQL_TRACE = TRUE"
        ));
        // SET ROLE is not an ALTER SESSION and is rejected here too.
        assert!(!is_allowed_alter_session("SET ROLE DBA"));
        assert!(!is_allowed_alter_session("DROP TABLE t"));
        assert!(!is_allowed_alter_session(
            "ALTER SESSION SET EVENTS '10046'"
        ));
    }
}
