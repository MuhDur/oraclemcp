//! Tier-3 AWR/ASH performance diagnostics, license-gated (plan §11.3; bead P3-3
//! / oracle-qmwz.4.3). AWR (`DBA_HIST_*`) and ASH (`V$ACTIVE_SESSION_HISTORY`)
//! require a licensed **Diagnostics Pack** (`control_management_pack_access` ≠
//! `NONE`) **and** DBA-tier dictionary access. This is opportunistic, NOT a
//! headline feature: when the pack is not licensed we fall back to the free
//! **Statspack** (`STATS$*`) if it is installed, and otherwise return a clear
//! structured error — **never a silent empty result** (the §5.11 degradation
//! contract, gated by the P2-9 privilege matrix).

use crate::error_envelope::{ErrorClass, ErrorEnvelope};
use oraclemcp_error::parse_ora_code;

/// Which performance-diagnostics source is available for this target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticsSource {
    /// Always-available live cursor cache (`V$SQLSTATS`) — free, needs no
    /// Diagnostics Pack and keeps no history. The default top-SQL source.
    LiveCursor,
    /// Licensed Diagnostics Pack — AWR + ASH (historical, `DBA_HIST_*`).
    AwrAsh,
    /// Free Statspack fallback (`PERFSTAT.STATS$*`).
    Statspack,
    /// Neither historical source available — Tier-3 history disabled.
    Unavailable,
}

/// The ranking metric for top-SQL. Every source aliases these to a uniform set
/// of output columns so the order key is source-independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopSqlMetric {
    /// Total elapsed time (the default).
    Elapsed,
    /// CPU time.
    Cpu,
    /// Logical reads (buffer gets).
    BufferGets,
    /// Physical reads (disk reads).
    DiskReads,
}

impl TopSqlMetric {
    /// The aliased output column this metric ranks by (uniform across sources).
    #[must_use]
    pub fn order_column(self) -> &'static str {
        match self {
            TopSqlMetric::Elapsed => "elapsed_time",
            TopSqlMetric::Cpu => "cpu_time",
            TopSqlMetric::BufferGets => "buffer_gets",
            TopSqlMetric::DiskReads => "disk_reads",
        }
    }

    /// Parse the agent-facing metric name. `None` lets the caller default.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "elapsed" | "elapsed_time" => Some(TopSqlMetric::Elapsed),
            "cpu" | "cpu_time" => Some(TopSqlMetric::Cpu),
            "buffer_gets" | "gets" | "logical_reads" => Some(TopSqlMetric::BufferGets),
            "disk_reads" | "reads" | "physical_reads" => Some(TopSqlMetric::DiskReads),
            _ => None,
        }
    }
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
pub async fn detect_statspack(
    cx: &asupersync::Cx,
    conn: &dyn crate::connection::OracleConnection,
) -> bool {
    detect_statspack_for_preflight(cx, conn)
        .await
        .unwrap_or(false)
}

/// A historical-source probe may degrade only when Oracle positively reports
/// that the catalog object is absent or unreadable by this principal. Arbitrary
/// SQL/adapter failures are not evidence that the feature is unavailable.
fn is_probe_absence_or_privilege(error: &crate::error::DbError) -> bool {
    let crate::error::DbError::Query(message) = error else {
        return false;
    };
    parse_ora_code(message).is_some_and(|code| matches!(code, 942 | 1031))
}

/// Detect Statspack for the DBA-suite preflight while preserving structurally
/// uncertain connection failures. Proven absence/privilege failures still
/// degrade to `false`, matching [`detect_statspack`]'s best-effort public
/// contract; cancellation, connection loss, and arbitrary adapter/query
/// failures propagate instead of describing an untrustworthy result.
pub(crate) async fn detect_statspack_for_preflight(
    cx: &asupersync::Cx,
    conn: &dyn crate::connection::OracleConnection,
) -> Result<bool, crate::error::DbError> {
    match conn
        .query_rows(
            cx,
            "SELECT 1 FROM perfstat.stats$snapshot WHERE rownum = 1",
            &[],
        )
        .await
    {
        Ok(_) => Ok(true),
        Err(error) if error.is_uncertain_session_state() => Err(error),
        Err(error) if is_probe_absence_or_privilege(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Detect a licensed Diagnostics Pack: `control_management_pack_access` includes
/// `DIAGNOSTIC`. Best-effort and **fail closed** — any error (including the
/// common "no SELECT on V$PARAMETER") means "not licensed", so we never touch
/// `DBA_HIST_*` on an unlicensed instance.
pub async fn detect_diagnostics_pack(
    cx: &asupersync::Cx,
    conn: &dyn crate::connection::OracleConnection,
) -> bool {
    detect_diagnostics_pack_for_preflight(cx, conn)
        .await
        .unwrap_or(false)
}

/// Detect Diagnostics Pack licensing for the DBA-suite preflight while
/// preserving structurally uncertain connection failures. Proven
/// absence/privilege failures remain fail-closed as "not licensed";
/// cancellation, session loss, and arbitrary adapter/query failures propagate
/// because the preflight cannot truthfully report connection posture afterward.
pub(crate) async fn detect_diagnostics_pack_for_preflight(
    cx: &asupersync::Cx,
    conn: &dyn crate::connection::OracleConnection,
) -> Result<bool, crate::error::DbError> {
    match conn
        .query_rows(
            cx,
            "SELECT value FROM v$parameter WHERE name = 'control_management_pack_access'",
            &[],
        )
        .await
    {
        Ok(rows) => Ok(rows
            .first()
            .and_then(|row| row.text("value").map(str::to_owned))
            .is_some_and(|value| value.to_ascii_uppercase().contains("DIAGNOSTIC"))),
        Err(error) if error.is_uncertain_session_state() => Err(error),
        Err(error) if is_probe_absence_or_privilege(&error) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Resolve the top-SQL source from the request. The free live cursor cache is
/// the default; `historical` opts into AWR (only when the Diagnostics Pack is
/// licensed) → Statspack → structured-unavailable. We **never** probe or query a
/// licensed pack object unless the license probe confirmed it. Structurally
/// uncertain probe failures propagate so the connection owner can quarantine
/// or discard the affected physical session instead of relabelling uncertainty
/// as an ordinary unavailable feature.
pub async fn resolve_top_sql_source(
    cx: &asupersync::Cx,
    conn: &dyn crate::connection::OracleConnection,
    historical: bool,
) -> Result<DiagnosticsSource, crate::error::DbError> {
    if !historical {
        return Ok(DiagnosticsSource::LiveCursor);
    }
    if detect_diagnostics_pack_for_preflight(cx, conn).await? {
        return Ok(DiagnosticsSource::AwrAsh);
    }
    Ok(select_diagnostics_source(
        false,
        detect_statspack_for_preflight(cx, conn).await?,
    ))
}

/// The top-SQL query for a source, ranked by `metric`. `top_n` is clamped to a
/// sane range. For the free `LiveCursor` source, `min_pct_of_total` (e.g. 5)
/// keeps only statements whose share of the total selected metric meets the
/// threshold (the "5%-of-total" mode). `Unavailable` returns a structured
/// "diagnostics not licensed" error that offers Statspack — never an empty
/// success. Every source aliases the four ranking metrics to a uniform output
/// column set (`elapsed_time`/`cpu_time`/`buffer_gets`/`disk_reads`) plus
/// `sql_id`, `sql_text`, and `executions`.
// `ErrorEnvelope` is the deliberate agent-facing error payload (§8.2); boxing it
// on this cold error path would add noise for no real benefit.
#[allow(clippy::result_large_err)]
pub fn top_sql_query(
    source: DiagnosticsSource,
    metric: TopSqlMetric,
    top_n: u32,
    min_pct_of_total: Option<u8>,
) -> Result<String, ErrorEnvelope> {
    let n = top_n.clamp(1, 100);
    let order = metric.order_column();
    match source {
        DiagnosticsSource::LiveCursor => {
            // RATIO_TO_REPORT gives each row's share of the total selected
            // metric; the optional threshold is the "5%-of-total" mode.
            let pct_filter = match min_pct_of_total {
                Some(pct) => format!("pct_of_total >= {} AND ", pct.min(100)),
                None => String::new(),
            };
            Ok(format!(
                "SELECT * FROM (\
                   SELECT sql_id, SUBSTR(sql_text, 1, 200) AS sql_text, executions, \
                          elapsed_time, cpu_time, buffer_gets, disk_reads, \
                          ROUND(RATIO_TO_REPORT({order}) OVER () * 100, 2) AS pct_of_total \
                   FROM v$sqlstats ORDER BY {order} DESC NULLS LAST\
                 ) WHERE {pct_filter}rownum <= {n}"
            ))
        }
        DiagnosticsSource::AwrAsh => Ok(format!(
            "SELECT * FROM (\
               SELECT s.sql_id, \
                      (SELECT SUBSTR(t.sql_text, 1, 200) FROM dba_hist_sqltext t \
                         WHERE t.sql_id = s.sql_id AND rownum = 1) AS sql_text, \
                      SUM(s.executions_delta) AS executions, \
                      SUM(s.elapsed_time_delta) AS elapsed_time, \
                      SUM(s.cpu_time_delta) AS cpu_time, \
                      SUM(s.buffer_gets_delta) AS buffer_gets, \
                      SUM(s.disk_reads_delta) AS disk_reads \
               FROM dba_hist_sqlstat s GROUP BY s.sql_id ORDER BY {order} DESC NULLS LAST\
             ) WHERE rownum <= {n}"
        )),
        DiagnosticsSource::Statspack => Ok(format!(
            "SELECT * FROM (\
               SELECT old_hash_value AS sql_id, SUBSTR(MAX(sql_text), 1, 200) AS sql_text, \
                      SUM(executions) AS executions, \
                      SUM(elapsed_time) AS elapsed_time, \
                      SUM(cpu_time) AS cpu_time, \
                      SUM(buffer_gets) AS buffer_gets, \
                      SUM(disk_reads) AS disk_reads \
               FROM stats$sql_summary GROUP BY old_hash_value ORDER BY {order} DESC NULLS LAST\
             ) WHERE rownum <= {n}"
        )),
        DiagnosticsSource::Unavailable => Err(ErrorEnvelope::new(
            ErrorClass::PolicyDenied,
            "Historical performance diagnostics require a licensed Diagnostics Pack \
             (control_management_pack_access != NONE) or an installed Statspack (PERFSTAT). \
             Live top-SQL over V$SQLSTATS is always available without a pack.",
        )
        .with_next_step(
            "use the default live source, or install Statspack (free) / enable the Diagnostics Pack for history",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::OracleConnection;
    use crate::error::DbError;
    use crate::types::{OracleBackend, OracleBind, OracleCell, OracleConnectionInfo, OracleRow};
    use asupersync::{Cx, runtime::RuntimeBuilder};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct ProbeMock {
        outcomes: Mutex<VecDeque<Result<Vec<OracleRow>, DbError>>>,
        sql: Mutex<Vec<String>>,
    }

    impl ProbeMock {
        fn new(outcomes: Vec<Result<Vec<OracleRow>, DbError>>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes.into()),
                sql: Mutex::new(Vec::new()),
            }
        }

        fn sql(&self) -> Vec<String> {
            self.sql.lock().expect("SQL mutex").clone()
        }
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for ProbeMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
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
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.sql.lock().expect("SQL mutex").push(sql.to_owned());
            self.outcomes
                .lock()
                .expect("outcome mutex")
                .pop_front()
                .expect("unexpected diagnostics probe")
        }

        async fn execute(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            Ok(0)
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    fn run_with_cx<F, Fut, T>(body: F) -> T
    where
        F: FnOnce(Cx) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime")
            .block_on(async move {
                let cx = Cx::current().expect("block_on installs a current Cx");
                body(cx).await
            })
    }

    fn diagnostics_pack_row() -> OracleRow {
        OracleRow {
            columns: vec![(
                "VALUE".to_owned(),
                OracleCell::new("VARCHAR2", Some("DIAGNOSTIC+TUNING".to_owned())),
            )],
        }
    }

    #[test]
    fn cancelled_license_probe_stops_before_statspack_fallback() {
        run_with_cx(|cx| async move {
            let conn = ProbeMock::new(vec![Err(DbError::Cancelled(
                "license probe deadline exceeded".to_owned(),
            ))]);

            let error = resolve_top_sql_source(&cx, &conn, true)
                .await
                .expect_err("cancellation must propagate");

            assert!(matches!(error, DbError::Cancelled(_)), "{error:?}");
            let sql = conn.sql();
            assert_eq!(sql.len(), 1);
            assert!(sql[0].contains("v$parameter"));
        });
    }

    #[test]
    fn disconnected_license_probe_stops_before_statspack_fallback() {
        run_with_cx(|cx| async move {
            let conn = ProbeMock::new(vec![Err(DbError::Query(
                "ORA-03113: end-of-file on communication channel".to_owned(),
            ))]);

            let error = resolve_top_sql_source(&cx, &conn, true)
                .await
                .expect_err("connection uncertainty must propagate");

            assert!(error.is_uncertain_session_state());
            assert_eq!(conn.sql().len(), 1);
        });
    }

    #[test]
    fn deterministic_unlicensed_probe_falls_back_to_statspack() {
        run_with_cx(|cx| async move {
            let conn = ProbeMock::new(vec![
                Err(DbError::Query(
                    "ORA-01031: insufficient privileges".to_owned(),
                )),
                Ok(Vec::new()),
            ]);

            let source = resolve_top_sql_source(&cx, &conn, true)
                .await
                .expect("ordinary privilege failure may use the free fallback");

            assert_eq!(source, DiagnosticsSource::Statspack);
            let sql = conn.sql();
            assert_eq!(sql.len(), 2);
            assert!(sql[1].contains("perfstat.stats$snapshot"));
        });
    }

    #[test]
    fn arbitrary_oracle_probe_failure_does_not_select_fallback() {
        run_with_cx(|cx| async move {
            let conn = ProbeMock::new(vec![Err(DbError::Query(
                "ORA-00600: internal error code".to_owned(),
            ))]);

            let error = resolve_top_sql_source(&cx, &conn, true)
                .await
                .expect_err("an arbitrary query failure is not an unlicensed result");

            assert!(matches!(error, DbError::Query(_)), "{error:?}");
            assert_eq!(conn.sql().len(), 1, "fallback requires proven absence");
        });
    }

    #[test]
    fn licensed_awr_short_circuits_statspack_probe() {
        run_with_cx(|cx| async move {
            let conn = ProbeMock::new(vec![Ok(vec![diagnostics_pack_row()])]);

            let source = resolve_top_sql_source(&cx, &conn, true)
                .await
                .expect("licensed AWR source");

            assert_eq!(source, DiagnosticsSource::AwrAsh);
            assert_eq!(conn.sql().len(), 1, "licensed AWR needs no fallback probe");
        });
    }

    #[test]
    fn live_source_performs_no_historical_probe() {
        run_with_cx(|cx| async move {
            let conn = ProbeMock::new(Vec::new());

            let source = resolve_top_sql_source(&cx, &conn, false)
                .await
                .expect("live source");

            assert_eq!(source, DiagnosticsSource::LiveCursor);
            assert!(conn.sql().is_empty());
        });
    }

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
        let q = top_sql_query(DiagnosticsSource::AwrAsh, TopSqlMetric::Elapsed, 10, None)
            .expect("awr query");
        assert!(q.to_ascii_lowercase().contains("dba_hist_sqlstat"));
        assert!(q.contains("rownum <= 10"));
    }

    #[test]
    fn statspack_query_targets_stats_tables() {
        let q = top_sql_query(DiagnosticsSource::Statspack, TopSqlMetric::Elapsed, 5, None)
            .expect("statspack query");
        assert!(q.to_ascii_lowercase().contains("stats$sql_summary"));
        assert!(q.contains("rownum <= 5"));
    }

    #[test]
    fn live_cursor_is_free_and_targets_v_sqlstats() {
        // The default source needs no Diagnostics Pack — it reads the live
        // cursor cache and is never "unavailable".
        let q = top_sql_query(
            DiagnosticsSource::LiveCursor,
            TopSqlMetric::Elapsed,
            10,
            None,
        )
        .expect("live query");
        assert!(q.to_ascii_lowercase().contains("v$sqlstats"));
        assert!(q.contains("ORDER BY elapsed_time DESC"));
        assert!(q.contains("rownum <= 10"));
    }

    #[test]
    fn metric_selection_changes_the_order_column() {
        for (m, col) in [
            (TopSqlMetric::Cpu, "cpu_time"),
            (TopSqlMetric::BufferGets, "buffer_gets"),
            (TopSqlMetric::DiskReads, "disk_reads"),
        ] {
            let q = top_sql_query(DiagnosticsSource::LiveCursor, m, 5, None).expect("q");
            assert!(
                q.contains(&format!("ORDER BY {col} DESC")),
                "metric {m:?} should rank by {col}"
            );
        }
    }

    #[test]
    fn five_pct_of_total_mode_adds_a_share_threshold() {
        let q = top_sql_query(
            DiagnosticsSource::LiveCursor,
            TopSqlMetric::Elapsed,
            50,
            Some(5),
        )
        .expect("q");
        assert!(q.contains("RATIO_TO_REPORT"), "computes share of total");
        assert!(
            q.contains("pct_of_total >= 5"),
            "keeps only the >=5% statements"
        );
        // Without the threshold there is no pct filter.
        let unfiltered = top_sql_query(
            DiagnosticsSource::LiveCursor,
            TopSqlMetric::Elapsed,
            50,
            None,
        )
        .unwrap();
        assert!(!unfiltered.contains("pct_of_total >="));
    }

    #[test]
    fn metric_parse_accepts_aliases() {
        assert_eq!(TopSqlMetric::parse("elapsed"), Some(TopSqlMetric::Elapsed));
        assert_eq!(TopSqlMetric::parse("CPU"), Some(TopSqlMetric::Cpu));
        assert_eq!(TopSqlMetric::parse("gets"), Some(TopSqlMetric::BufferGets));
        assert_eq!(TopSqlMetric::parse("reads"), Some(TopSqlMetric::DiskReads));
        assert_eq!(TopSqlMetric::parse("nonsense"), None);
    }

    #[test]
    fn top_n_is_clamped() {
        // 0 -> 1, huge -> 100 (no unbounded scan).
        assert!(
            top_sql_query(DiagnosticsSource::AwrAsh, TopSqlMetric::Elapsed, 0, None)
                .unwrap()
                .contains("rownum <= 1")
        );
        assert!(
            top_sql_query(DiagnosticsSource::AwrAsh, TopSqlMetric::Elapsed, 9999, None)
                .unwrap()
                .contains("rownum <= 100")
        );
    }

    #[test]
    fn unavailable_is_a_clear_error_offering_statspack_never_empty() {
        let envelope = top_sql_query(
            DiagnosticsSource::Unavailable,
            TopSqlMetric::Elapsed,
            10,
            None,
        )
        .unwrap_err();
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
