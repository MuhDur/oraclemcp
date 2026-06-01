//! Privilege-degradation tests under a least-privilege account (bead T-PRIV /
//! oracle-qmwz.6.6). Many features need privileges a least-privilege account
//! lacks; they MUST degrade with a clear "needs privilege X" structured error —
//! **never an empty success** — and `oracle_capabilities` must report the real
//! tier. This suite drives the P2-9 privilege probe + degradation matrix with an
//! in-process least-privilege connection (the live tagged job runs the same
//! assertions against a real least-priv Oracle account).

use oraclemcp_db::error_envelope::{ErrorClass, classify_ora_code};
use oraclemcp_db::{
    DictionaryTier, OracleBackend, OracleBind, OracleConnection, OracleConnectionInfo, OracleRow,
    probe_privileges, requirement_matrix,
};

/// A least-privilege account: every dictionary view above `USER_*` is denied,
/// `v$parameter` is denied (no Diagnostics Pack visibility), and PL/Scope
/// identifiers are denied — exactly what a locked-down service user sees.
struct LeastPrivConn;

impl OracleConnection for LeastPrivConn {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    fn ping(&self) -> Result<(), oraclemcp_db::DbError> {
        Ok(())
    }
    fn describe(&self) -> Result<OracleConnectionInfo, oraclemcp_db::DbError> {
        Ok(OracleConnectionInfo::default())
    }
    fn query_rows(
        &self,
        sql: &str,
        _binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, oraclemcp_db::DbError> {
        let lower = sql.to_ascii_lowercase();
        // DBA_*, ALL_*, v$parameter, and *_identifiers are all denied (ORA-00942
        // / ORA-01031) — only USER_* is readable.
        if lower.contains("dba_")
            || lower.contains("all_")
            || lower.contains("v$parameter")
            || lower.contains("all_identifiers")
        {
            return Err(oraclemcp_db::DbError::Query(
                "ORA-00942: table or view does not exist".to_owned(),
            ));
        }
        Ok(vec![OracleRow { columns: vec![] }])
    }
    fn execute(&self, _sql: &str, _binds: &[OracleBind]) -> Result<u64, oraclemcp_db::DbError> {
        Ok(0)
    }
    fn commit(&self) -> Result<(), oraclemcp_db::DbError> {
        Ok(())
    }
    fn rollback(&self) -> Result<(), oraclemcp_db::DbError> {
        Ok(())
    }
}

#[test]
fn least_privilege_account_degrades_to_user_tier() {
    let profile = probe_privileges(&LeastPrivConn);
    // The probe falls back DBA_* -> ALL_* -> USER_* and lands on USER_.
    assert_eq!(profile.dictionary_tier, DictionaryTier::User);
    // No Diagnostics Pack visibility and no PL/Scope — reported honestly.
    assert!(!profile.diagnostics_pack);
    assert!(!profile.plscope);
}

#[test]
fn dictionary_tier_picks_the_right_view_prefix() {
    // The degraded tier drives the DBA_* -> ALL_* -> USER_* view fallback.
    assert_eq!(DictionaryTier::Dba.view_prefix(), "DBA_");
    assert_eq!(DictionaryTier::All.view_prefix(), "ALL_");
    assert_eq!(DictionaryTier::User.view_prefix(), "USER_");
}

#[test]
fn requirement_matrix_documents_degradation_never_empty_success() {
    let matrix = requirement_matrix();
    assert!(
        matrix.len() >= 4,
        "every privilege-gated tool is documented"
    );
    for row in matrix {
        assert!(!row.tool.is_empty());
        assert!(
            !row.requires.is_empty(),
            "{}: documents the privilege it needs",
            row.tool
        );
        assert!(
            !row.degraded.is_empty(),
            "{}: documents the degraded behavior",
            row.tool
        );
    }
    // The matrix must promise a clear error / fallback — never silent empty success.
    let degraded_text: String = matrix.iter().map(|r| r.degraded.to_lowercase()).collect();
    assert!(
        degraded_text.contains("fall back")
            || degraded_text.contains("insufficient privilege")
            || degraded_text.contains("license required")
            || degraded_text.contains("never empty"),
        "the matrix documents structured degradation, not empty success"
    );
    // AWR/ASH is license-gated; get_ddl must never return empty on a privilege miss.
    assert!(
        matrix
            .iter()
            .any(|r| r.tool.contains("AWR") && r.degraded.to_lowercase().contains("license"))
    );
    assert!(
        matrix.iter().any(
            |r| r.tool.contains("get_ddl") && r.degraded.to_lowercase().contains("never empty")
        )
    );
}

#[test]
fn insufficient_privilege_maps_to_a_clear_structured_error() {
    // ORA-01031 (insufficient privileges) and friends classify to a precise
    // error class — the agent sees "needs privilege X", not an empty result.
    for ora in [1031, 1017, 1045] {
        assert_eq!(classify_ora_code(ora), ErrorClass::InsufficientPrivilege);
    }
    // ORA-00942 (object not found — what a least-priv account hits on DBA_*)
    // is a distinct, actionable class, never a silent empty success.
    assert_eq!(classify_ora_code(942), ErrorClass::ObjectNotFound);
}
