//! Privilege graceful-degradation matrix + capability probe (plan §5.11; bead
//! P2-9). Many features need privileges (`SELECT ANY DICTIONARY`, `DBA_*`,
//! PL/Scope, a licensed Diagnostics Pack) a least-privilege account lacks.
//! Rather than silently returning empty or erroring opaquely, the server probes
//! the account at startup, caches a [`PrivilegeProfile`] (reported by
//! `oracle_capabilities`), falls back `DBA_* → ALL_* → USER_*`, and returns a
//! clear "needs privilege X" structured error — never an empty success.

use serde::{Deserialize, Serialize};

use crate::connection::OracleConnection;

/// The dictionary-access tier the connected account has.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DictionaryTier {
    /// `DBA_*` readable (most complete; `SELECT ANY DICTIONARY` / DBA role).
    Dba,
    /// `ALL_*` readable (objects the account is granted on).
    All,
    /// Only `USER_*` (own schema).
    User,
}

impl DictionaryTier {
    /// The dictionary-view prefix to use for this tier (`DBA_` / `ALL_` / `USER_`).
    #[must_use]
    pub fn view_prefix(self) -> &'static str {
        match self {
            DictionaryTier::Dba => "DBA_",
            DictionaryTier::All => "ALL_",
            DictionaryTier::User => "USER_",
        }
    }
}

/// The probed, cached capability profile of the connected account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivilegeProfile {
    /// The dictionary-access tier.
    pub dictionary_tier: DictionaryTier,
    /// Whether a licensed Diagnostics Pack (AWR/ASH) appears available
    /// (`control_management_pack_access` includes DIAGNOSTIC).
    pub diagnostics_pack: bool,
    /// Whether PL/Scope identifiers (`*_IDENTIFIERS`) are readable.
    pub plscope: bool,
}

/// Probe an account's capabilities. Best-effort: each probe tolerates a
/// privilege error (the absence is recorded, never fatal).
pub fn probe_privileges(conn: &dyn OracleConnection) -> PrivilegeProfile {
    let can = |sql: &str| conn.query_rows(sql, &[]).is_ok();
    let dictionary_tier = if can("SELECT 1 FROM dba_objects WHERE rownum = 1") {
        DictionaryTier::Dba
    } else if can("SELECT 1 FROM all_objects WHERE rownum = 1") {
        DictionaryTier::All
    } else {
        DictionaryTier::User
    };
    let diagnostics_pack = conn
        .query_rows(
            "SELECT value FROM v$parameter WHERE name = 'control_management_pack_access'",
            &[],
        )
        .ok()
        .and_then(|rows| {
            rows.first()
                .and_then(|r| r.text("VALUE").map(str::to_owned))
        })
        .is_some_and(|v| v.to_ascii_uppercase().contains("DIAGNOSTIC"));
    let plscope = can("SELECT 1 FROM all_identifiers WHERE rownum = 1");
    PrivilegeProfile {
        dictionary_tier,
        diagnostics_pack,
        plscope,
    }
}

/// One row of the privilege-degradation matrix: a tool, the privilege it needs,
/// and the documented degraded behavior when it is absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ToolRequirement {
    /// The tool / capability.
    pub tool: &'static str,
    /// The Oracle privilege / license it ideally needs.
    pub requires: &'static str,
    /// What happens (degraded) when the privilege is absent.
    pub degraded: &'static str,
}

/// The single source-of-truth privilege-degradation matrix (§5.11).
#[must_use]
pub fn requirement_matrix() -> &'static [ToolRequirement] {
    &[
        ToolRequirement {
            tool: "oracle_schema_inspect (cross-schema)",
            requires: "SELECT on DBA_*/ALL_* (or SELECT ANY DICTIONARY)",
            degraded: "fall back DBA_* -> ALL_* -> USER_*; cross-schema returns only granted objects",
        },
        ToolRequirement {
            tool: "oracle_plsql_analyze (PL/Scope)",
            requires: "SELECT on *_IDENTIFIERS + PLSCOPE_SETTINGS recompile",
            degraded: "lint without PL/Scope cross-reference; 'needs PL/Scope' note",
        },
        ToolRequirement {
            tool: "AWR/ASH top-SQL (Tier-3)",
            requires: "Diagnostics Pack license (control_management_pack_access != NONE)",
            degraded: "disabled; offer Statspack; structured 'license required' error",
        },
        ToolRequirement {
            tool: "oracle_get_ddl",
            requires: "SELECT on the object / DBMS_METADATA access",
            degraded: "structured 'insufficient privilege: needs SELECT on <obj>' — never empty",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DbError;
    use crate::types::{OracleBackend, OracleBind, OracleConnectionInfo, OracleRow};

    /// A mock whose `query_rows` succeeds only for SQL NOT containing any of the
    /// `deny` substrings (case-insensitive) — to simulate privilege tiers.
    struct TierMock {
        deny: Vec<&'static str>,
    }
    impl OracleConnection for TierMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        fn ping(&self) -> Result<(), DbError> {
            Ok(())
        }
        fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }
        fn query_rows(&self, sql: &str, _b: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
            let lower = sql.to_ascii_lowercase();
            if self.deny.iter().any(|d| lower.contains(d)) {
                Err(DbError::Query(
                    "ORA-00942: table or view does not exist".to_owned(),
                ))
            } else {
                Ok(vec![OracleRow {
                    columns: vec![(
                        "VALUE".to_owned(),
                        crate::types::OracleCell::new("VARCHAR2", Some("1".to_owned())),
                    )],
                }])
            }
        }
        fn execute(&self, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
            Ok(0)
        }
        fn commit(&self) -> Result<(), DbError> {
            Ok(())
        }
        fn rollback(&self) -> Result<(), DbError> {
            Ok(())
        }
    }

    #[test]
    fn view_prefixes() {
        assert_eq!(DictionaryTier::Dba.view_prefix(), "DBA_");
        assert_eq!(DictionaryTier::All.view_prefix(), "ALL_");
        assert_eq!(DictionaryTier::User.view_prefix(), "USER_");
    }

    #[test]
    fn tier_falls_back_dba_to_all_to_user() {
        // DBA readable -> Dba.
        let p = probe_privileges(&TierMock { deny: vec![] });
        assert_eq!(p.dictionary_tier, DictionaryTier::Dba);
        // DBA denied, ALL ok -> All.
        let p = probe_privileges(&TierMock { deny: vec!["dba_"] });
        assert_eq!(p.dictionary_tier, DictionaryTier::All);
        // DBA + ALL denied -> User.
        let p = probe_privileges(&TierMock {
            deny: vec!["dba_", "all_"],
        });
        assert_eq!(p.dictionary_tier, DictionaryTier::User);
    }

    #[test]
    fn plscope_and_diagnostics_detected() {
        let p = probe_privileges(&TierMock { deny: vec![] });
        assert!(p.plscope, "all_identifiers readable -> PL/Scope available");
        // VALUE='1' does not contain DIAGNOSTIC -> diagnostics pack not detected.
        assert!(!p.diagnostics_pack);
        // all_identifiers denied -> no PL/Scope.
        let p = probe_privileges(&TierMock {
            deny: vec!["all_identifiers"],
        });
        assert!(!p.plscope);
    }

    #[test]
    fn matrix_is_populated() {
        let m = requirement_matrix();
        assert!(m.len() >= 4);
        assert!(
            m.iter()
                .all(|r| !r.tool.is_empty() && !r.degraded.is_empty())
        );
    }
}
