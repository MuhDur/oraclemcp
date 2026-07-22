//! Privilege graceful-degradation matrix + capability probe (plan §5.11; bead
//! P2-9). Many features need privileges (`SELECT ANY DICTIONARY`, `DBA_*`,
//! PL/Scope, a licensed Diagnostics Pack) a least-privilege account lacks.
//! Rather than silently returning empty or erroring opaquely, the server probes
//! the account at startup, caches a [`PrivilegeProfile`] (reported by
//! `oracle_capabilities`), falls back `DBA_* → ALL_* → USER_*`, and returns a
//! clear "needs privilege X" structured error — never an empty success.

use asupersync::Cx;
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
pub async fn probe_privileges(cx: &Cx, conn: &dyn OracleConnection) -> PrivilegeProfile {
    async fn can(cx: &Cx, conn: &dyn OracleConnection, sql: &str) -> bool {
        conn.query_rows(cx, sql, &[]).await.is_ok()
    }
    let dictionary_tier = if can(cx, conn, "SELECT 1 FROM dba_objects WHERE rownum = 1").await {
        DictionaryTier::Dba
    } else if can(cx, conn, "SELECT 1 FROM all_objects WHERE rownum = 1").await {
        DictionaryTier::All
    } else {
        DictionaryTier::User
    };
    let diagnostics_pack = conn
        .query_rows(
            cx,
            "SELECT value FROM v$parameter WHERE name = 'control_management_pack_access'",
            &[],
        )
        .await
        .ok()
        .and_then(|rows| {
            rows.first()
                .and_then(|r| r.text("VALUE").map(str::to_owned))
        })
        .is_some_and(|v| v.to_ascii_uppercase().contains("DIAGNOSTIC"));
    let plscope = can(cx, conn, "SELECT 1 FROM all_identifiers WHERE rownum = 1").await;
    PrivilegeProfile {
        dictionary_tier,
        diagnostics_pack,
        plscope,
    }
}

/// System privileges that let a principal mutate data or schema. A
/// least-privilege / read-only proxy account holds NONE of these (it has at most
/// `CREATE SESSION` plus `SELECT`/`SELECT ANY DICTIONARY`). Their presence is the
/// signal that the session is NOT a read-only posture under the classifier + A1.
const WRITE_IMPLYING_PRIVS: &[&str] = &[
    "INSERT ANY TABLE",
    "UPDATE ANY TABLE",
    "DELETE ANY TABLE",
    "CREATE TABLE",
    "CREATE ANY TABLE",
    "DROP ANY TABLE",
    "ALTER ANY TABLE",
    "CREATE PROCEDURE",
    "CREATE ANY PROCEDURE",
    "ALTER ANY PROCEDURE",
    "DROP ANY PROCEDURE",
    "CREATE TRIGGER",
    "CREATE ANY TRIGGER",
    "CREATE ANY INDEX",
    "CREATE VIEW",
    "CREATE ANY VIEW",
    "GRANT ANY PRIVILEGE",
    "GRANT ANY ROLE",
    "CREATE USER",
    "DROP USER",
    "ALTER SYSTEM",
    "ALTER DATABASE",
    "SYSDBA",
    "SYSOPER",
];

/// The least-privilege / read-only posture of the connected principal (bead A2).
///
/// A least-privilege proxy user or a read-only role holds no write-implying
/// system privileges, so this is the real boundary the operator should confirm:
/// the classifier + per-DB ceiling are the enforced control, but a principal
/// that *cannot* write at the database is defense in depth.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WritePosture {
    /// Whether the principal holds any write-implying system privilege.
    /// `None` means the posture could not be determined (probe failed) — treated
    /// as a "cannot confirm read-only" warning, never a silent pass.
    pub can_write: Option<bool>,
    /// The write-implying privileges that were observed (for the operator note).
    pub write_privileges: Vec<String>,
    /// Whether a proxy/least-privilege connect user is in effect.
    pub proxy_user: bool,
}

/// Probe the connected principal's write posture from `SESSION_PRIVS` (the
/// session's own effective privileges — always readable by the session, no DBA
/// grant needed). Read-only and best-effort: a probe failure yields
/// `can_write: None` so the doctor warns rather than falsely reporting safe.
pub async fn probe_write_posture(
    cx: &Cx,
    conn: &dyn OracleConnection,
    proxy_user: bool,
) -> WritePosture {
    match conn
        .query_rows(cx, "SELECT privilege FROM session_privs", &[])
        .await
    {
        Ok(rows) => {
            let held: Vec<String> = rows
                .iter()
                .filter_map(|r| r.text("PRIVILEGE").map(|p| p.trim().to_ascii_uppercase()))
                .collect();
            let write_privileges: Vec<String> = WRITE_IMPLYING_PRIVS
                .iter()
                .filter(|p| held.iter().any(|h| h == **p))
                .map(|p| (*p).to_owned())
                .collect();
            WritePosture {
                can_write: Some(!write_privileges.is_empty()),
                write_privileges,
                proxy_user,
            }
        }
        Err(_) => WritePosture {
            can_write: None,
            write_privileges: Vec::new(),
            proxy_user,
        },
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
    use asupersync::runtime::RuntimeBuilder;

    fn run_with_cx<F, Fut, T>(body: F) -> T
    where
        F: FnOnce(Cx) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        runtime.block_on(async move {
            let cx = Cx::current().expect("block_on installs a current Cx");
            body(cx).await
        })
    }

    /// A mock whose `query_rows` succeeds only for SQL NOT containing any of the
    /// `deny` substrings (case-insensitive) — to simulate privilege tiers.
    struct TierMock {
        deny: Vec<&'static str>,
    }
    #[async_trait::async_trait(?Send)]
    impl OracleConnection for TierMock {
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
            Ok(OracleConnectionInfo::default())
        }
        async fn query_rows(
            &self,
            _cx: &Cx,
            sql: &str,
            _b: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
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
        async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
            Ok(0)
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
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
        run_with_cx(|cx| async move {
            // DBA readable -> Dba.
            let p = probe_privileges(&cx, &TierMock { deny: vec![] }).await;
            assert_eq!(p.dictionary_tier, DictionaryTier::Dba);
            // DBA denied, ALL ok -> All.
            let p = probe_privileges(&cx, &TierMock { deny: vec!["dba_"] }).await;
            assert_eq!(p.dictionary_tier, DictionaryTier::All);
            // DBA + ALL denied -> User.
            let p = probe_privileges(
                &cx,
                &TierMock {
                    deny: vec!["dba_", "all_"],
                },
            )
            .await;
            assert_eq!(p.dictionary_tier, DictionaryTier::User);
        });
    }

    #[test]
    fn plscope_and_diagnostics_detected() {
        run_with_cx(|cx| async move {
            let p = probe_privileges(&cx, &TierMock { deny: vec![] }).await;
            assert!(p.plscope, "all_identifiers readable -> PL/Scope available");
            // VALUE='1' does not contain DIAGNOSTIC -> diagnostics pack not detected.
            assert!(!p.diagnostics_pack);
            // all_identifiers denied -> no PL/Scope.
            let p = probe_privileges(
                &cx,
                &TierMock {
                    deny: vec!["all_identifiers"],
                },
            )
            .await;
            assert!(!p.plscope);
        });
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

    /// A mock returning a fixed set of `SESSION_PRIVS.PRIVILEGE` rows (or an
    /// error) to exercise the A2 write-posture probe.
    struct SessionPrivsMock {
        privileges: Option<Vec<&'static str>>,
    }
    #[async_trait::async_trait(?Send)]
    impl OracleConnection for SessionPrivsMock {
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
            Ok(OracleConnectionInfo::default())
        }
        async fn query_rows(
            &self,
            _cx: &Cx,
            _sql: &str,
            _b: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            match &self.privileges {
                Some(privs) => Ok(privs
                    .iter()
                    .map(|p| OracleRow {
                        columns: vec![(
                            "PRIVILEGE".to_owned(),
                            crate::types::OracleCell::new("VARCHAR2", Some((*p).to_owned())),
                        )],
                    })
                    .collect()),
                None => Err(DbError::Query("ORA-00942".to_owned())),
            }
        }
        async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
            Ok(0)
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    #[test]
    fn read_only_principal_reports_cannot_write() {
        // A least-privilege session holds only CREATE SESSION + SELECT-type privs.
        let posture = run_with_cx(|cx| async move {
            probe_write_posture(
                &cx,
                &SessionPrivsMock {
                    privileges: Some(vec!["CREATE SESSION", "SELECT ANY DICTIONARY"]),
                },
                false,
            )
            .await
        });
        assert_eq!(posture.can_write, Some(false));
        assert!(posture.write_privileges.is_empty());
    }

    #[test]
    fn write_capable_principal_is_detected_with_evidence() {
        let posture = run_with_cx(|cx| async move {
            probe_write_posture(
                &cx,
                &SessionPrivsMock {
                    privileges: Some(vec![
                        "CREATE SESSION",
                        "CREATE ANY TABLE",
                        "INSERT ANY TABLE",
                    ]),
                },
                true,
            )
            .await
        });
        assert_eq!(posture.can_write, Some(true));
        assert!(
            posture
                .write_privileges
                .contains(&"CREATE ANY TABLE".to_owned())
        );
        assert!(
            posture
                .write_privileges
                .contains(&"INSERT ANY TABLE".to_owned())
        );
        assert!(posture.proxy_user);
    }

    #[test]
    fn unprobeable_posture_is_unknown_not_falsely_safe() {
        let posture = run_with_cx(|cx| async move {
            probe_write_posture(&cx, &SessionPrivsMock { privileges: None }, false).await
        });
        // Fail-closed: a probe failure must NOT report a safe read-only posture.
        assert_eq!(posture.can_write, None);
    }
}
