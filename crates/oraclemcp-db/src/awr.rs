//! Tier-3 AWR/ASH performance diagnostics, license-gated (plan §11.3; bead P3-3
//! / oracle-qmwz.4.3). AWR (`DBA_HIST_*`) and ASH (`V$ACTIVE_SESSION_HISTORY`)
//! require a licensed **Diagnostics Pack** (`control_management_pack_access` ≠
//! `NONE`) **and** DBA-tier dictionary access. This is opportunistic, NOT a
//! headline feature: when the pack is not licensed we fall back to the free
//! **Statspack** (`STATS$*`) if it is installed, and otherwise return a clear
//! structured error — **never a silent empty result** (the §5.11 degradation
//! contract, gated by the P2-9 privilege matrix).

use crate::error_envelope::{ErrorClass, ErrorEnvelope};

/// Which performance-diagnostics source is available for this target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticsSource {
    /// Licensed Diagnostics Pack — AWR + ASH.
    AwrAsh,
    /// Free Statspack fallback (`PERFSTAT.STATS$*`).
    Statspack,
    /// Neither available — Tier-3 disabled.
    Unavailable,
}

/// Select the diagnostics source from the licensing + install posture:
/// Diagnostics Pack wins; else Statspack if installed; else unavailable.
#[must_use]
pub fn select_diagnostics_source(
    diagnostics_pack: bool,
    statspack_installed: bool,
) -> DiagnosticsSource {
    if diagnostics_pack {
        DiagnosticsSource::AwrAsh
    } else if statspack_installed {
        DiagnosticsSource::Statspack
    } else {
        DiagnosticsSource::Unavailable
    }
}

/// Detect whether Statspack is installed (the `PERFSTAT.STATS$SNAPSHOT` table is
/// readable). Best-effort: any error means "not available".
#[must_use]
pub fn detect_statspack(conn: &dyn crate::connection::OracleConnection) -> bool {
    conn.query_rows(
        "SELECT 1 FROM perfstat.stats$snapshot WHERE rownum = 1",
        &[],
    )
    .is_ok()
}

/// The top-SQL query for a source. `top_n` is clamped to a sane range.
/// `Unavailable` returns a structured "diagnostics not licensed" error that
/// offers Statspack — never an empty success.
// `ErrorEnvelope` is the deliberate agent-facing error payload (§8.2); boxing it
// on this cold error path would add noise for no real benefit.
#[allow(clippy::result_large_err)]
pub fn top_sql_query(source: DiagnosticsSource, top_n: u32) -> Result<String, ErrorEnvelope> {
    let n = top_n.clamp(1, 100);
    match source {
        DiagnosticsSource::AwrAsh => Ok(format!(
            "SELECT * FROM (\
               SELECT sql_id, SUM(elapsed_time_delta) AS elapsed, SUM(executions_delta) AS execs \
               FROM dba_hist_sqlstat GROUP BY sql_id ORDER BY elapsed DESC\
             ) WHERE rownum <= {n}"
        )),
        DiagnosticsSource::Statspack => Ok(format!(
            "SELECT * FROM (\
               SELECT old_hash_value AS sql_id, SUM(elapsed_time) AS elapsed, SUM(executions) AS execs \
               FROM stats$sql_summary GROUP BY old_hash_value ORDER BY elapsed DESC\
             ) WHERE rownum <= {n}"
        )),
        DiagnosticsSource::Unavailable => Err(ErrorEnvelope::new(
            ErrorClass::PolicyDenied,
            "Tier-3 performance diagnostics require a licensed Diagnostics Pack \
             (control_management_pack_access != NONE) or an installed Statspack (PERFSTAT).",
        )
        .with_next_step(
            "install Statspack (free) or enable the Diagnostics Pack to use AWR/ASH top-SQL",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_pack_selects_awr_ash() {
        assert_eq!(
            select_diagnostics_source(true, false),
            DiagnosticsSource::AwrAsh
        );
        // A licensed pack wins even if Statspack is also installed.
        assert_eq!(
            select_diagnostics_source(true, true),
            DiagnosticsSource::AwrAsh
        );
    }

    #[test]
    fn unlicensed_falls_back_to_statspack_then_unavailable() {
        assert_eq!(
            select_diagnostics_source(false, true),
            DiagnosticsSource::Statspack
        );
        assert_eq!(
            select_diagnostics_source(false, false),
            DiagnosticsSource::Unavailable
        );
    }

    #[test]
    fn awr_query_targets_dba_hist() {
        let q = top_sql_query(DiagnosticsSource::AwrAsh, 10).expect("awr query");
        assert!(q.to_ascii_lowercase().contains("dba_hist_sqlstat"));
        assert!(q.contains("rownum <= 10"));
    }

    #[test]
    fn statspack_query_targets_stats_tables() {
        let q = top_sql_query(DiagnosticsSource::Statspack, 5).expect("statspack query");
        assert!(q.to_ascii_lowercase().contains("stats$sql_summary"));
        assert!(q.contains("rownum <= 5"));
    }

    #[test]
    fn top_n_is_clamped() {
        // 0 -> 1, huge -> 100 (no unbounded scan).
        assert!(
            top_sql_query(DiagnosticsSource::AwrAsh, 0)
                .unwrap()
                .contains("rownum <= 1")
        );
        assert!(
            top_sql_query(DiagnosticsSource::AwrAsh, 9999)
                .unwrap()
                .contains("rownum <= 100")
        );
    }

    #[test]
    fn unavailable_is_a_clear_error_offering_statspack_never_empty() {
        let envelope = top_sql_query(DiagnosticsSource::Unavailable, 10).unwrap_err();
        // A precise, actionable error — not an empty success.
        assert!(envelope.is_error);
        assert_eq!(envelope.error_class, ErrorClass::PolicyDenied);
        assert!(envelope.message.to_lowercase().contains("diagnostics pack"));
        assert!(
            envelope
                .next_steps
                .iter()
                .any(|s| s.to_lowercase().contains("statspack"))
        );
    }
}
