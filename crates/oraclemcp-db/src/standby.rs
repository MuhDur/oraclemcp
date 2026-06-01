//! Standby / read-replica auto-detection (plan §5.8; bead P1-7).
//!
//! Active Data Guard physical standbys are *physically* read-only and reject
//! even `EXPLAIN PLAN` (it writes `PLAN_TABLE`). Auto-detected at connect via
//! `V$DATABASE.database_role`/`open_mode`: on a standby the server forces
//! `READ_ONLY` (independently of the profile ceiling) and routes plan analysis
//! to `DBMS_XPLAN.DISPLAY_CURSOR`. `oracle_capabilities` reports the status.

use serde::{Deserialize, Serialize};

use crate::connection::OracleConnection;
use crate::error::DbError;

/// The detected standby posture of a connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandbyStatus {
    /// `V$DATABASE.DATABASE_ROLE`, if readable.
    pub database_role: Option<String>,
    /// `V$DATABASE.OPEN_MODE`, if readable.
    pub open_mode: Option<String>,
    /// Whether the target is a physically read-only standby/replica.
    pub read_only_standby: bool,
}

impl StandbyStatus {
    /// When true the server must force `READ_ONLY` and disable
    /// `EXPLAIN PLAN`-into-`PLAN_TABLE` regardless of the profile ceiling.
    #[must_use]
    pub fn forces_read_only(&self) -> bool {
        self.read_only_standby
    }
}

/// Detect the standby posture from a live connection (`describe` reads
/// `V$DATABASE`). Best-effort: if the role/open-mode are not readable (a
/// least-privilege account), `read_only_standby` is `false` and the operator's
/// `read_only_standby` profile flag (or `protected`) remains the control.
pub fn detect_standby(conn: &dyn OracleConnection) -> Result<StandbyStatus, DbError> {
    let info = conn.describe()?;
    Ok(StandbyStatus {
        read_only_standby: info.is_read_only_standby(),
        database_role: info.database_role,
        open_mode: info.open_mode,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{OracleBackend, OracleBind, OracleConnectionInfo, OracleRow};

    struct InfoMock(OracleConnectionInfo);
    impl OracleConnection for InfoMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        fn ping(&self) -> Result<(), DbError> {
            Ok(())
        }
        fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
            Ok(self.0.clone())
        }
        fn query_rows(&self, _s: &str, _b: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
            Ok(vec![])
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

    fn detect(role: Option<&str>, mode: Option<&str>) -> StandbyStatus {
        let info = OracleConnectionInfo {
            database_role: role.map(str::to_owned),
            open_mode: mode.map(str::to_owned),
            ..Default::default()
        };
        detect_standby(&InfoMock(info)).expect("detect")
    }

    #[test]
    fn primary_read_write_is_not_standby() {
        let s = detect(Some("PRIMARY"), Some("READ WRITE"));
        assert!(!s.forces_read_only());
    }

    #[test]
    fn physical_standby_forces_read_only() {
        assert!(detect(Some("PHYSICAL STANDBY"), Some("READ ONLY")).forces_read_only());
        // Read-only open mode on any role also forces it.
        assert!(detect(Some("PRIMARY"), Some("READ ONLY")).forces_read_only());
    }

    #[test]
    fn unreadable_role_is_not_assumed_standby() {
        // A least-privilege account can't read V$DATABASE; we do not guess.
        assert!(!detect(None, None).forces_read_only());
    }
}
