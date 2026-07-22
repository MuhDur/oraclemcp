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

/// A single AWR snapshot's optimizer-plan observation.
///
/// `snapshot_id` and the interval bounds describe the *AWR sampling window*,
/// not an exact historical SCN. AWR reports a plan only when the statement was
/// captured in that snapshot, so a plan change is bounded by adjacent sampled
/// windows rather than proven to have happened at their boundary.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PlanCostTimelinePoint {
    /// AWR snapshot identifier for this observation.
    pub snapshot_id: i64,
    /// RAC instance that contributed the captured cursor.
    pub instance_number: i64,
    /// Start of the AWR snapshot interval in the database session's time zone.
    pub snapshot_begin_time: Option<String>,
    /// End of the AWR snapshot interval in the database session's time zone.
    pub snapshot_end_time: Option<String>,
    /// Oracle's stable numerical fingerprint for the captured plan.
    pub plan_hash_value: i64,
    /// The optimizer's relative cost at this snapshot, when Oracle recorded
    /// one. It is not an elapsed-time measurement or a runtime guarantee.
    pub optimizer_cost: Option<i64>,
}

/// Historical optimizer-plan observations for one Oracle SQL ID.
///
/// This is deliberately snapshot-bounded: AWR has no authoritative mapping
/// from a captured plan to an exact SCN. Consumers can identify a plan flip by
/// comparing adjacent [`PlanCostTimelinePoint::plan_hash_value`] values.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PlanCostTimeline {
    /// The normalized 13-character Oracle SQL ID that was queried.
    pub sql_id: String,
    /// Ordered AWR observations, capped by the requested limit.
    pub points: Vec<PlanCostTimelinePoint>,
    /// Scope and interpretation contract for the data in `points`.
    pub note: String,
}

/// Interpretation contract returned with every [`PlanCostTimeline`].
pub const PLAN_COST_TIMELINE_NOTE: &str = "AWR observations are bounded by snapshot intervals, \
not exact historical SCNs. optimizer_cost is the optimizer's relative estimate, not elapsed time \
or a runtime guarantee; a row exists only when AWR captured that SQL cursor in the interval.";

const PLAN_COST_TIMELINE_SQL: &str = "SELECT * FROM (\
SELECT s.snap_id AS snapshot_id, s.instance_number AS instance_number, \
       TO_CHAR(sn.begin_interval_time, 'YYYY-MM-DD\"T\"HH24:MI:SS.FF6') AS snapshot_begin_time, \
       TO_CHAR(sn.end_interval_time, 'YYYY-MM-DD\"T\"HH24:MI:SS.FF6') AS snapshot_end_time, \
       s.plan_hash_value AS plan_hash_value, \
       COALESCE(s.optimizer_cost, p.cost) AS optimizer_cost \
FROM dba_hist_sqlstat s \
JOIN dba_hist_snapshot sn \
  ON sn.snap_id = s.snap_id \
 AND sn.dbid = s.dbid \
 AND sn.instance_number = s.instance_number \
LEFT JOIN dba_hist_sql_plan p \
  ON p.dbid = s.dbid \
 AND p.sql_id = s.sql_id \
 AND p.plan_hash_value = s.plan_hash_value \
 AND p.id = 0 \
WHERE s.sql_id = :1 \
ORDER BY s.snap_id ASC, s.instance_number ASC, s.plan_hash_value ASC\
) WHERE ROWNUM <= :2";

// This validation runs before any database call. Keeping the actionable
// envelope unboxed makes the rejection directly usable by the tool boundary.
#[allow(clippy::result_large_err)]
fn normalize_sql_id(sql_id: &str) -> Result<String, ErrorEnvelope> {
    let normalized = sql_id.trim().to_ascii_lowercase();
    if normalized.len() == 13 && normalized.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Ok(normalized);
    }

    Err(ErrorEnvelope::new(
        ErrorClass::InvalidArguments,
        "sql_id must be the 13-character alphanumeric Oracle SQL identifier",
    )
    .with_next_step("obtain the SQL ID from oracle_top_queries or a trusted Oracle diagnostic"))
}

fn diagnostics_pack_required() -> ErrorEnvelope {
    ErrorEnvelope::new(
        ErrorClass::PolicyDenied,
        "historical plan-cost timeline requires a licensed Oracle Diagnostics Pack; \
         control_management_pack_access did not prove DIAGNOSTIC access",
    )
    .with_next_step(
        "enable the Diagnostics Pack only when your Oracle license permits it, then retry",
    )
    .with_next_step(
        "use oracle_top_queries without historical=true for free live cursor-cache diagnostics",
    )
}

fn assemble_plan_cost_timeline(
    sql_id: String,
    rows: &[crate::types::OracleRow],
) -> PlanCostTimeline {
    let points = rows
        .iter()
        .filter_map(|row| {
            Some(PlanCostTimelinePoint {
                snapshot_id: row.parse_i64("SNAPSHOT_ID")?,
                instance_number: row.parse_i64("INSTANCE_NUMBER")?,
                snapshot_begin_time: row.text("SNAPSHOT_BEGIN_TIME").map(str::to_owned),
                snapshot_end_time: row.text("SNAPSHOT_END_TIME").map(str::to_owned),
                plan_hash_value: row.parse_i64("PLAN_HASH_VALUE")?,
                optimizer_cost: row.parse_i64("OPTIMIZER_COST"),
            })
        })
        .collect();
    PlanCostTimeline {
        sql_id,
        points,
        note: PLAN_COST_TIMELINE_NOTE.to_owned(),
    }
}

/// Read the licensed AWR plan-cost history for an Oracle SQL ID.
///
/// The Diagnostics Pack probe runs before the AWR query. If the probe cannot
/// positively prove `DIAGNOSTIC` access (including absent dictionary privilege),
/// this returns a typed [`ErrorClass::PolicyDenied`] refusal and never touches
/// `DBA_HIST_*`. Connection uncertainty from the probe remains an ordinary
/// database error envelope rather than being misreported as a license result.
///
/// `max_points` is clamped to `1..=1_000` to bound the read. All user input is
/// positional-bound; the SQL ID is never interpolated into the AWR query.
#[allow(clippy::result_large_err)]
pub async fn plan_cost_timeline(
    cx: &asupersync::Cx,
    conn: &dyn crate::connection::OracleConnection,
    sql_id: &str,
    max_points: u32,
) -> Result<PlanCostTimeline, ErrorEnvelope> {
    let sql_id = normalize_sql_id(sql_id)?;
    match detect_diagnostics_pack_for_preflight(cx, conn).await {
        Ok(true) => {}
        Ok(false) => return Err(diagnostics_pack_required()),
        Err(error) => return Err(error.into_envelope()),
    }

    let rows = conn
        .query_rows(
            cx,
            PLAN_COST_TIMELINE_SQL,
            &[
                crate::types::OracleBind::String(sql_id.clone()),
                crate::types::OracleBind::I64(i64::from(max_points.clamp(1, 1_000))),
            ],
        )
        .await
        .map_err(crate::error::DbError::into_envelope)?;
    Ok(assemble_plan_cost_timeline(sql_id, &rows))
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
        binds: Mutex<Vec<Vec<OracleBind>>>,
    }

    impl ProbeMock {
        fn new(outcomes: Vec<Result<Vec<OracleRow>, DbError>>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes.into()),
                sql: Mutex::new(Vec::new()),
                binds: Mutex::new(Vec::new()),
            }
        }

        fn sql(&self) -> Vec<String> {
            self.sql.lock().expect("SQL mutex").clone()
        }

        fn binds(&self) -> Vec<Vec<OracleBind>> {
            self.binds.lock().expect("bind mutex").clone()
        }
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for ProbeMock {
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
            binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.sql.lock().expect("SQL mutex").push(sql.to_owned());
            self.binds.lock().expect("bind mutex").push(binds.to_vec());
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

    fn no_diagnostics_pack_row() -> OracleRow {
        OracleRow {
            columns: vec![(
                "VALUE".to_owned(),
                OracleCell::new("VARCHAR2", Some("NONE".to_owned())),
            )],
        }
    }

    fn plan_timeline_row(
        snapshot_id: i64,
        instance_number: i64,
        plan_hash_value: i64,
        optimizer_cost: Option<i64>,
    ) -> OracleRow {
        let cell = |value: Option<String>| OracleCell::new("VARCHAR2", value);
        OracleRow {
            columns: vec![
                (
                    "SNAPSHOT_ID".to_owned(),
                    cell(Some(snapshot_id.to_string())),
                ),
                (
                    "INSTANCE_NUMBER".to_owned(),
                    cell(Some(instance_number.to_string())),
                ),
                (
                    "SNAPSHOT_BEGIN_TIME".to_owned(),
                    cell(Some("2026-07-13T10:00:00.000000".to_owned())),
                ),
                (
                    "SNAPSHOT_END_TIME".to_owned(),
                    cell(Some("2026-07-13T11:00:00.000000".to_owned())),
                ),
                (
                    "PLAN_HASH_VALUE".to_owned(),
                    cell(Some(plan_hash_value.to_string())),
                ),
                (
                    "OPTIMIZER_COST".to_owned(),
                    cell(optimizer_cost.map(|v| v.to_string())),
                ),
            ],
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

    #[test]
    fn plan_timeline_refuses_unlicensed_before_any_awr_query() {
        run_with_cx(|cx| async move {
            let conn = ProbeMock::new(vec![Err(DbError::Query(
                "ORA-01031: insufficient privileges".to_owned(),
            ))]);

            let error = plan_cost_timeline(&cx, &conn, "abc123def4567", 20)
                .await
                .expect_err("unlicensed history must be a typed refusal");

            assert_eq!(error.error_class, ErrorClass::PolicyDenied);
            assert!(
                error
                    .message
                    .to_ascii_lowercase()
                    .contains("diagnostics pack")
            );
            assert!(
                error
                    .next_steps
                    .iter()
                    .any(|step| step.to_ascii_lowercase().contains("license"))
            );
            let sql = conn.sql();
            assert_eq!(sql.len(), 1, "the pack probe is the only database call");
            assert!(sql[0].contains("v$parameter"));
            assert!(
                !sql.iter().any(|query| query.contains("dba_hist_")),
                "unlicensed refusal must not touch paid AWR views"
            );
        });
    }

    #[test]
    fn plan_timeline_refuses_when_license_parameter_is_none_before_any_awr_query() {
        run_with_cx(|cx| async move {
            let conn = ProbeMock::new(vec![Ok(vec![no_diagnostics_pack_row()])]);

            let error = plan_cost_timeline(&cx, &conn, "abc123def4567", 20)
                .await
                .expect_err("a NONE Diagnostics Pack parameter must be refused");

            assert_eq!(error.error_class, ErrorClass::PolicyDenied);
            assert_eq!(conn.sql().len(), 1, "never query AWR after NONE");
            assert!(conn.sql()[0].contains("v$parameter"));
        });
    }

    #[test]
    fn plan_timeline_preserves_probe_uncertainty_without_awr_fallback() {
        run_with_cx(|cx| async move {
            let conn = ProbeMock::new(vec![Err(DbError::Cancelled(
                "license probe deadline exceeded".to_owned(),
            ))]);

            let error = plan_cost_timeline(&cx, &conn, "abc123def4567", 20)
                .await
                .expect_err("uncertain probe must propagate");

            assert_ne!(error.error_class, ErrorClass::PolicyDenied);
            assert_eq!(conn.sql().len(), 1);
        });
    }

    #[test]
    fn plan_timeline_returns_snapshot_bounded_cost_history_with_bound_sql_id() {
        run_with_cx(|cx| async move {
            let conn = ProbeMock::new(vec![
                Ok(vec![diagnostics_pack_row()]),
                Ok(vec![
                    plan_timeline_row(41, 1, 7_654_321, Some(2)),
                    plan_timeline_row(42, 1, 9_876_543, Some(19)),
                ]),
            ]);

            let timeline = plan_cost_timeline(&cx, &conn, "ABC123DEF4567", 9_999)
                .await
                .expect("licensed AWR history");

            assert_eq!(timeline.sql_id, "abc123def4567");
            assert_eq!(timeline.points.len(), 2);
            assert_eq!(timeline.points[0].snapshot_id, 41);
            assert_eq!(timeline.points[0].optimizer_cost, Some(2));
            assert_eq!(timeline.points[1].plan_hash_value, 9_876_543);
            assert_eq!(timeline.points[1].optimizer_cost, Some(19));
            assert!(timeline.note.contains("not exact historical SCNs"));

            let sql = conn.sql();
            assert_eq!(sql.len(), 2);
            let awr = &sql[1];
            assert!(awr.contains("dba_hist_sqlstat"));
            assert!(awr.contains("dba_hist_snapshot"));
            assert!(awr.contains("dba_hist_sql_plan"));
            assert!(awr.contains("ROWNUM <= :2"));
            assert!(!awr.contains("ABC123DEF4567"));

            assert_eq!(
                conn.binds()[1],
                vec![
                    OracleBind::String("abc123def4567".to_owned()),
                    OracleBind::I64(1_000),
                ]
            );
        });
    }

    #[test]
    fn plan_timeline_rejects_malformed_sql_id_without_a_probe() {
        run_with_cx(|cx| async move {
            let conn = ProbeMock::new(Vec::new());
            let error = plan_cost_timeline(&cx, &conn, "not a SQL id", 20)
                .await
                .expect_err("bad SQL IDs are rejected locally");

            assert_eq!(error.error_class, ErrorClass::InvalidArguments);
            assert!(conn.sql().is_empty());
        });
    }
}
