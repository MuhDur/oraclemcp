//! Read-only DBA health-check suite (bead WP-C; C1 framework + C2–C7
//! subchecks). One `oracle_db_health` tool runs a requested set of pure
//! dictionary/V$ subchecks, aggregates structured [`Finding`]s tagged with a
//! [`Severity`] and the `source_view` each came from, and returns them
//! together with the lists of checks actually run vs. skipped.
//!
//! The load-bearing C1 acceptance criterion is **privilege degradation**: each
//! subcheck prefers the `DBA_*` dictionary view, automatically falls back to
//! the session-scoped `ALL_*` view when the connected user lacks `DBA_*`
//! access, and — when even `ALL_*` is inaccessible — yields a structured
//! `skipped`/insufficient-privilege [`Finding`] rather than a raw `ORA-` error.
//! A single failing subcheck never fails the whole suite. Every statement is a
//! pure read against `V$`/`DBA_*`/`ALL_*` and is routed through the normal
//! read path, so it is safe at any operating level.

use crate::connection::OracleConnection;
use serde_json::{Value, json};

/// One DBA health subcheck. The variants map 1:1 to beads C2–C7.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthSubcheck {
    /// C2 — `INVALID` objects (failed/stale PL/SQL, views, etc.).
    InvalidObjects,
    /// C3 — `UNUSABLE` indexes (and, where index monitoring is enabled, unused).
    UnusableIndexes,
    /// C4 — tablespace + UNDO/temp headroom near capacity.
    TablespaceUndo,
    /// C5 — non-CYCLE sequences approaching their ceiling (an outage risk).
    SequenceCeiling,
    /// C6 — `DISABLED` / `NOT VALIDATED` constraints (unenforced integrity).
    DisabledConstraints,
    /// C7 — buffer cache hit ratio (a coarse, advisory signal).
    BufferCacheHitRatio,
}

impl HealthSubcheck {
    /// Every subcheck, in a stable reporting order (used by `health_type=all`).
    #[must_use]
    pub fn all() -> &'static [HealthSubcheck] {
        &[
            HealthSubcheck::InvalidObjects,
            HealthSubcheck::UnusableIndexes,
            HealthSubcheck::TablespaceUndo,
            HealthSubcheck::SequenceCeiling,
            HealthSubcheck::DisabledConstraints,
            HealthSubcheck::BufferCacheHitRatio,
        ]
    }

    /// The canonical, agent-facing name (also the value accepted in the
    /// comma-separated `health_type` list and emitted in `checks_run`).
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            HealthSubcheck::InvalidObjects => "invalid_objects",
            HealthSubcheck::UnusableIndexes => "unusable_indexes",
            HealthSubcheck::TablespaceUndo => "tablespace_undo",
            HealthSubcheck::SequenceCeiling => "sequence_ceiling",
            HealthSubcheck::DisabledConstraints => "disabled_constraints",
            HealthSubcheck::BufferCacheHitRatio => "buffer_cache_hit_ratio",
        }
    }

    /// The dictionary views this subcheck probes, as a `(dba_view, all_view)`
    /// pair. When a subcheck has no `ALL_*` analogue (the DBA-only metrics view
    /// `DBA_TABLESPACE_USAGE_METRICS`, or a `V$` view), `all_view` is `None` and
    /// degradation is "DBA/V$ available or skip" rather than "DBA→ALL→skip".
    /// Reused by both [`run_subcheck`] and the C9 preflight so the tier-probe
    /// targets stay defined in exactly one place.
    #[must_use]
    pub fn probe_views(self) -> (&'static str, Option<&'static str>) {
        match self {
            HealthSubcheck::InvalidObjects => ("DBA_OBJECTS", Some("ALL_OBJECTS")),
            HealthSubcheck::UnusableIndexes => ("DBA_INDEXES", Some("ALL_INDEXES")),
            HealthSubcheck::TablespaceUndo => ("DBA_TABLESPACE_USAGE_METRICS", None),
            HealthSubcheck::SequenceCeiling => ("DBA_SEQUENCES", Some("ALL_SEQUENCES")),
            HealthSubcheck::DisabledConstraints => ("DBA_CONSTRAINTS", Some("ALL_CONSTRAINTS")),
            HealthSubcheck::BufferCacheHitRatio => ("V$SYSSTAT", None),
        }
    }

    /// Parse a single subcheck token. Accepts the canonical name plus a few
    /// obvious aliases; whitespace-trimmed and case-insensitive. `None` for an
    /// unknown token — the caller decides how to surface it.
    #[must_use]
    pub fn parse_one(token: &str) -> Option<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "invalid_objects" | "invalid" | "objects" => Some(HealthSubcheck::InvalidObjects),
            "unusable_indexes" | "indexes" | "index" => Some(HealthSubcheck::UnusableIndexes),
            "tablespace_undo" | "tablespace" | "tablespaces" | "undo" => {
                Some(HealthSubcheck::TablespaceUndo)
            }
            "sequence_ceiling" | "sequences" | "sequence" => Some(HealthSubcheck::SequenceCeiling),
            "disabled_constraints" | "constraints" | "constraint" => {
                Some(HealthSubcheck::DisabledConstraints)
            }
            "buffer_cache_hit_ratio" | "buffer_cache" | "cache_hit_ratio" | "hit_ratio" => {
                Some(HealthSubcheck::BufferCacheHitRatio)
            }
            _ => None,
        }
    }
}

/// The outcome of parsing the `health_type` argument: the resolved subchecks
/// plus any tokens that did not name a known subcheck. Unknown tokens are
/// reported (never silently dropped) but do **not** fail the call — the suite
/// runs the recognized subchecks and notes the rest as skipped (C1's
/// "never a hard failure" contract extends to bad input).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParsedHealthRequest {
    /// Recognized subchecks, de-duplicated, in canonical `all()` order.
    pub subchecks: Vec<HealthSubcheck>,
    /// Tokens that did not match any subcheck name/alias.
    pub unknown: Vec<String>,
}

/// Parse the `health_type` argument. `"all"` (or empty/whitespace) selects
/// every subcheck; otherwise it is a comma-separated list of subcheck names.
/// Recognized subchecks are returned de-duplicated and ordered by [`HealthSubcheck::all`];
/// unrecognized tokens are collected in [`ParsedHealthRequest::unknown`].
#[must_use]
pub fn parse_health_request(health_type: &str) -> ParsedHealthRequest {
    let trimmed = health_type.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("all") {
        return ParsedHealthRequest {
            subchecks: HealthSubcheck::all().to_vec(),
            unknown: Vec::new(),
        };
    }

    let mut selected: Vec<HealthSubcheck> = Vec::new();
    let mut unknown: Vec<String> = Vec::new();
    for token in trimmed.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        // A nested "all" inside a list still means everything.
        if token.eq_ignore_ascii_case("all") {
            return ParsedHealthRequest {
                subchecks: HealthSubcheck::all().to_vec(),
                unknown: Vec::new(),
            };
        }
        match HealthSubcheck::parse_one(token) {
            Some(sub) if !selected.contains(&sub) => selected.push(sub),
            Some(_) => {}
            None => {
                let owned = token.to_owned();
                if !unknown.contains(&owned) {
                    unknown.push(owned);
                }
            }
        }
    }

    // Emit in canonical order so the report shape is deterministic.
    let subchecks = HealthSubcheck::all()
        .iter()
        .copied()
        .filter(|s| selected.contains(s))
        .collect();

    ParsedHealthRequest { subchecks, unknown }
}

/// Severity of a [`Finding`]. Ordered from least to most urgent so callers can
/// compare/aggregate (`Ok < Info < Warning < Critical`).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Nothing of concern.
    Ok,
    /// Advisory / informational (e.g. a coarse signal, monitoring caveat).
    Info,
    /// Worth attention but not an outage.
    Warning,
    /// An imminent or active operational risk.
    Critical,
}

/// One aggregated health finding. `detail` carries the structured, subcheck-
/// specific payload (rows, ratios, the skip reason, etc.).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    /// Which subcheck produced this finding.
    pub subcheck: HealthSubcheck,
    /// How urgent it is.
    pub severity: Severity,
    /// The dictionary/V$ view the data came from (or that was attempted, when
    /// the finding is a skip). E.g. `DBA_OBJECTS`, `ALL_INDEXES`, `V$SYSSTAT`.
    pub source_view: String,
    /// A short human-readable summary line.
    pub summary: String,
    /// Structured, subcheck-specific detail (rows, counts, the skip reason…).
    pub detail: Value,
}

impl Finding {
    fn skipped(
        subcheck: HealthSubcheck,
        attempted_views: &[&str],
        reason: impl Into<String>,
    ) -> Self {
        let reason = reason.into();
        Finding {
            subcheck,
            severity: Severity::Info,
            source_view: attempted_views.first().copied().unwrap_or("").to_owned(),
            summary: format!("{} skipped: insufficient privilege", subcheck.name()),
            detail: json!({
                "status": "skipped",
                "reason": reason,
                "attempted_views": attempted_views,
            }),
        }
    }
}

/// Which dictionary tier a subcheck resolved to. `Dba` is preferred; `All` is
/// the session-scoped degradation; `None` means neither was accessible.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewTier {
    /// The privileged `DBA_*` view.
    Dba,
    /// The session-scoped `ALL_*` fallback.
    All,
}

/// Best-effort, fail-safe probe of which dictionary tier is readable for a
/// subcheck. Tries the `DBA_*` view first; on any error (the common
/// "ORA-00942 / no SELECT privilege" case) falls back to probing the `ALL_*`
/// view; if that also errors, returns `None` so the subcheck degrades to a
/// structured skip. Mirrors `awr.rs`'s `detect_*` fail-closed pattern — never
/// surfaces a raw `ORA-` and never panics. Each probe is a `WHERE 1=0` read
/// that returns no rows but still trips the privilege check, so it costs
/// nothing and never runs the actual diagnostic query.
#[must_use]
pub fn detect_view_tier(
    conn: &dyn OracleConnection,
    dba_view: &str,
    all_view: &str,
) -> Option<ViewTier> {
    if conn.query_rows(&probe_sql(dba_view), &[]).is_ok() {
        return Some(ViewTier::Dba);
    }
    if conn.query_rows(&probe_sql(all_view), &[]).is_ok() {
        return Some(ViewTier::All);
    }
    None
}

/// A cheap existence/privilege probe for a dictionary view: select nothing
/// (`WHERE 1=0`) so it costs no rows but still fails if the view is not
/// visible to the session. Pure read.
fn probe_sql(view: &str) -> String {
    format!("SELECT 1 FROM {view} WHERE 1 = 0")
}

// ---------------------------------------------------------------------------
// C9 — DBA-suite privilege/feature preflight (report-only).
//
// Given a connection, report — per [`HealthSubcheck`] and for `oracle_top_queries`
// — which dictionary tier / diagnostics feature is actually available, so an
// operator can see what `oracle_db_health` / `oracle_top_queries` will be able
// to run BEFORE running them. It runs ONLY the cheap `WHERE 1=0` tier probes and
// the fail-closed `detect_*` feature probes (all reused from `health.rs` /
// `awr.rs`); it NEVER runs a diagnostic query and NEVER touches a paid-pack
// object — `resolve_top_sql_source` only ever probes a `DBA_HIST_*` object after
// `detect_diagnostics_pack` has confirmed the license. The report informs; it
// never fails anything.
// ---------------------------------------------------------------------------

/// The preflight resolution for one [`HealthSubcheck`]: which dictionary tier it
/// would use, or that it would `skip`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SubcheckPreflight {
    /// The subcheck this row describes.
    pub subcheck: HealthSubcheck,
    /// The tier the subcheck would run against (`Dba`/`All`), or `None` when
    /// neither tier is readable and the subcheck would degrade to a skip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<ViewTier>,
    /// The view the subcheck would read at the resolved tier (or, on a skip,
    /// the privileged view it tried first).
    pub view: String,
    /// A short operator-facing line: which view/tier is available, or "skip".
    pub status: String,
}

/// The full C9 preflight report: a per-subcheck tier/feature resolution plus the
/// resolved `oracle_top_queries` diagnostics source for both the default (live)
/// and historical modes. Report-only — `oracle_db_health` / `oracle_top_queries`
/// behavior is unchanged; this just tells the operator what they will be able to
/// run.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PreflightReport {
    /// One row per [`HealthSubcheck`], in canonical [`HealthSubcheck::all`] order.
    pub subchecks: Vec<SubcheckPreflight>,
    /// The source `oracle_top_queries` resolves to in its default (live) mode —
    /// always [`DiagnosticsSource::LiveCursor`] (free, no pack).
    pub top_queries_default: crate::awr::DiagnosticsSource,
    /// The source `oracle_top_queries` resolves to with `historical=true`:
    /// `AwrAsh` only when the Diagnostics Pack is licensed, else `Statspack` if
    /// installed, else `Unavailable`.
    pub top_queries_historical: crate::awr::DiagnosticsSource,
    /// Whether a licensed Diagnostics Pack was detected (fail-closed).
    pub diagnostics_pack_licensed: bool,
    /// Whether a free Statspack install was detected.
    pub statspack_installed: bool,
}

impl PreflightReport {
    /// How many subchecks would actually run (resolve to a readable tier) vs.
    /// degrade to a skip, as `(runnable, skipped)`.
    #[must_use]
    pub fn runnable_skipped(&self) -> (usize, usize) {
        let runnable = self.subchecks.iter().filter(|s| s.tier.is_some()).count();
        (runnable, self.subchecks.len() - runnable)
    }
}

/// Run the C9 report-only preflight against `conn`. Reuses [`detect_view_tier`]
/// for the dictionary tier of each subcheck and [`crate::awr::detect_diagnostics_pack`] /
/// [`crate::awr::detect_statspack`] / [`crate::awr::resolve_top_sql_source`] for
/// the top-queries diagnostics posture — no detection logic is duplicated. Runs
/// only the cheap tier/feature probes; never a diagnostic query and never a
/// paid-pack object (the historical resolution only touches `DBA_HIST_*` after
/// the license is confirmed). It cannot fail: an inaccessible view is reported
/// as a `skip`, not an error.
#[must_use]
pub fn preflight(conn: &dyn OracleConnection) -> PreflightReport {
    let subchecks = HealthSubcheck::all()
        .iter()
        .map(|&subcheck| {
            let (dba_view, all_view) = subcheck.probe_views();
            // No ALL_* analogue (DBA-only metrics view or a V$ view): the only
            // tier that can satisfy it is the privileged one. Probe it directly
            // rather than inventing an ALL_* fallback that does not exist.
            let tier = match all_view {
                Some(all_view) => detect_view_tier(conn, dba_view, all_view),
                None => conn
                    .query_rows(&probe_sql(dba_view), &[])
                    .is_ok()
                    .then_some(ViewTier::Dba),
            };
            let (view, status) = match tier {
                Some(ViewTier::Dba) => (dba_view.to_owned(), format!("available via {dba_view}")),
                Some(ViewTier::All) => {
                    let all = all_view.unwrap_or(dba_view);
                    (
                        all.to_owned(),
                        format!("degraded to {all} (no DBA_* access)"),
                    )
                }
                None => (
                    dba_view.to_owned(),
                    "skip: no readable dictionary/V$ view".to_owned(),
                ),
            };
            SubcheckPreflight {
                subcheck,
                tier,
                view,
                status,
            }
        })
        .collect();

    let diagnostics_pack_licensed = crate::awr::detect_diagnostics_pack(conn);
    let statspack_installed = crate::awr::detect_statspack(conn);
    PreflightReport {
        subchecks,
        // Reuse the same resolver the live tool uses so the preflight can never
        // drift from real behavior. The default (non-historical) mode is always
        // the free live cursor cache; historical re-derives from the detected
        // pack/Statspack posture (and never probes a pack object unless licensed).
        top_queries_default: crate::awr::resolve_top_sql_source(conn, false),
        top_queries_historical: crate::awr::resolve_top_sql_source(conn, true),
        diagnostics_pack_licensed,
        statspack_installed,
    }
}

// ---------------------------------------------------------------------------
// Per-subcheck SQL builders. Each takes the resolved [`ViewTier`] and returns
// the view name it targets plus the read-only SQL. All are pure functions so
// the unit tests can assert the exact view + predicate without a live DB.
// ---------------------------------------------------------------------------

/// C2 — invalid objects grouped by owner/type, with a per-group count and a
/// small sample of object names. `*_OBJECTS.STATUS = 'INVALID'`.
#[must_use]
pub fn invalid_objects_sql(tier: ViewTier) -> (&'static str, String) {
    let view = match tier {
        ViewTier::Dba => "DBA_OBJECTS",
        ViewTier::All => "ALL_OBJECTS",
    };
    let sql = format!(
        "SELECT owner, object_type, COUNT(*) AS invalid_count, \
                SUBSTR(LISTAGG(object_name, ',') WITHIN GROUP (ORDER BY object_name), 1, 400) AS sample_objects \
         FROM {view} WHERE status = 'INVALID' \
         GROUP BY owner, object_type ORDER BY invalid_count DESC, owner, object_type"
    );
    (view, sql)
}

/// C3 — unusable indexes. `*_INDEXES.STATUS = 'UNUSABLE'` (partitioned indexes
/// also expose `N/A`; we flag the plain UNUSABLE state). Unused-index
/// detection depends on index monitoring being enabled, which is a separate
/// caveat surfaced in the finding detail rather than queried here.
#[must_use]
pub fn unusable_indexes_sql(tier: ViewTier) -> (&'static str, String) {
    let view = match tier {
        ViewTier::Dba => "DBA_INDEXES",
        ViewTier::All => "ALL_INDEXES",
    };
    let sql = format!(
        "SELECT owner, index_name, table_name, status \
         FROM {view} WHERE status = 'UNUSABLE' \
         ORDER BY owner, table_name, index_name"
    );
    (view, sql)
}

/// C4 — tablespace headroom from `DBA_TABLESPACE_USAGE_METRICS.used_percent`.
/// This metrics view is DBA-only (there is no `ALL_*` analogue), so when
/// `DBA_*` is unavailable the subcheck degrades to a structured skip rather
/// than a different view. Returns the per-tablespace used percent ordered
/// worst-first; the threshold/severity decision is applied in `run_health`.
#[must_use]
pub fn tablespace_usage_sql() -> (&'static str, String) {
    let view = "DBA_TABLESPACE_USAGE_METRICS";
    let sql = format!(
        "SELECT tablespace_name, ROUND(used_percent, 2) AS used_percent, \
                used_space, tablespace_size \
         FROM {view} ORDER BY used_percent DESC"
    );
    (view, sql)
}

/// C5 — non-CYCLE sequences approaching their ceiling. Flags sequences whose
/// consumed fraction `(last_number / max_value)` meets `threshold_pct`
/// (a real outage risk: a non-cycling sequence that hits max_value raises
/// ORA-08004 on the next nextval). `CYCLE_FLAG = 'N'` only.
#[must_use]
pub fn sequence_ceiling_sql(tier: ViewTier, threshold_pct: u8) -> (&'static str, String) {
    let view = match tier {
        ViewTier::Dba => "DBA_SEQUENCES",
        ViewTier::All => "ALL_SEQUENCES",
    };
    let frac = f64::from(threshold_pct.min(100)) / 100.0;
    let sql = format!(
        "SELECT sequence_owner, sequence_name, last_number, max_value, increment_by, cycle_flag, \
                ROUND((last_number / max_value) * 100, 2) AS pct_consumed \
         FROM {view} \
         WHERE cycle_flag = 'N' AND max_value > 0 AND last_number >= max_value * {frac} \
         ORDER BY pct_consumed DESC, sequence_owner, sequence_name"
    );
    (view, sql)
}

/// C6 — disabled / not-validated constraints (unenforced integrity).
/// `*_CONSTRAINTS.STATUS = 'DISABLED' OR VALIDATED = 'NOT VALIDATED'`.
#[must_use]
pub fn disabled_constraints_sql(tier: ViewTier) -> (&'static str, String) {
    let view = match tier {
        ViewTier::Dba => "DBA_CONSTRAINTS",
        ViewTier::All => "ALL_CONSTRAINTS",
    };
    let sql = format!(
        "SELECT owner, table_name, constraint_name, constraint_type, status, validated \
         FROM {view} \
         WHERE status = 'DISABLED' OR validated = 'NOT VALIDATED' \
         ORDER BY owner, table_name, constraint_name"
    );
    (view, sql)
}

/// C7 — instance-wide buffer cache hit ratio from `V$SYSSTAT`:
/// `1 - physical reads (cache) / (db block gets + consistent gets)`. This is a
/// coarse, advisory signal (a high ratio does not prove health, a low one does
/// not prove a problem) — the caveat travels in the finding detail. `V$SYSSTAT`
/// has no `ALL_*` analogue, so lack of access degrades to a structured skip.
#[must_use]
pub fn buffer_cache_hit_ratio_sql() -> (&'static str, String) {
    let view = "V$SYSSTAT";
    // Pull the three relevant cumulative stats; the ratio is computed in Rust
    // so the SQL stays a trivial pure read.
    let sql = format!(
        "SELECT name, value FROM {view} \
         WHERE name IN ('db block gets', 'consistent gets', 'physical reads cache') \
         ORDER BY name"
    );
    (view, sql)
}

/// Run the requested subchecks against the connection, aggregating their
/// [`Finding`]s. Each subcheck is isolated: any per-subcheck error (including a
/// driver/query failure) is caught and converted into a `skipped` finding so a
/// single failing check never fails the whole suite. Returns the findings in
/// request order. Pure orchestration — all SQL is read-only.
#[must_use]
pub fn run_health(conn: &dyn OracleConnection, subchecks: &[HealthSubcheck]) -> Vec<Finding> {
    subchecks
        .iter()
        .map(|&sub| run_subcheck(conn, sub))
        .collect()
}

/// Default fraction (percent) at which a sequence is flagged as near-ceiling.
const SEQUENCE_CEILING_PCT: u8 = 90;
/// Tablespace used-percent at which we warn / go critical.
const TABLESPACE_WARN_PCT: f64 = 85.0;
const TABLESPACE_CRITICAL_PCT: f64 = 95.0;

fn run_subcheck(conn: &dyn OracleConnection, subcheck: HealthSubcheck) -> Finding {
    // The (dba_view, all_view) targets come from `HealthSubcheck::probe_views`,
    // the single source of truth the C9 preflight also reads.
    let (dba_view, all_view) = subcheck.probe_views();
    match subcheck {
        HealthSubcheck::InvalidObjects => degrading_count_subcheck(
            conn,
            subcheck,
            dba_view,
            all_view.unwrap_or(dba_view),
            invalid_objects_sql,
        ),
        HealthSubcheck::UnusableIndexes => {
            degrading_index_subcheck(conn, subcheck, dba_view, all_view.unwrap_or(dba_view))
        }
        HealthSubcheck::TablespaceUndo => tablespace_subcheck(conn, subcheck),
        HealthSubcheck::SequenceCeiling => {
            degrading_sequence_subcheck(conn, subcheck, dba_view, all_view.unwrap_or(dba_view))
        }
        HealthSubcheck::DisabledConstraints => degrading_count_subcheck(
            conn,
            subcheck,
            dba_view,
            all_view.unwrap_or(dba_view),
            disabled_constraints_sql,
        ),
        HealthSubcheck::BufferCacheHitRatio => buffer_cache_subcheck(conn, subcheck),
    }
}

/// Serialize a list of rows to a plain JSON array of `{column: value}` objects
/// (NUMBER stays a string via `OracleCell::text`, honoring the NUMBER→string
/// invariant). Kept local so `health.rs` does not depend on the serializer's
/// fuller [`crate::serialize`] machinery for these simple dictionary reads.
fn rows_to_json(rows: &[crate::types::OracleRow]) -> Vec<Value> {
    rows.iter()
        .map(|row| {
            let mut obj = serde_json::Map::new();
            for (name, cell) in &row.columns {
                obj.insert(
                    name.clone(),
                    cell.text()
                        .map_or(Value::Null, |t| Value::String(t.to_owned())),
                );
            }
            Value::Object(obj)
        })
        .collect()
}

/// A subcheck that simply runs one query (with DBA→ALL degradation) and reports
/// the rows; severity is `Warning` when any row came back, else `Ok`.
fn degrading_count_subcheck(
    conn: &dyn OracleConnection,
    subcheck: HealthSubcheck,
    dba_view: &str,
    all_view: &str,
    build: impl Fn(ViewTier) -> (&'static str, String),
) -> Finding {
    let tier = match detect_view_tier(conn, dba_view, all_view) {
        Some(tier) => tier,
        None => {
            return Finding::skipped(
                subcheck,
                &[dba_view, all_view],
                "no SELECT on DBA_* or ALL_* view",
            );
        }
    };
    let (view, sql) = build(tier);
    match conn.query_rows(&sql, &[]) {
        Ok(rows) => {
            let count = rows.len();
            Finding {
                subcheck,
                severity: if count == 0 {
                    Severity::Ok
                } else {
                    Severity::Warning
                },
                source_view: view.to_owned(),
                summary: format!("{count} group(s) found in {view}"),
                detail: json!({ "status": "ok", "group_count": count, "rows": rows_to_json(&rows) }),
            }
        }
        Err(err) => Finding::skipped(subcheck, &[view], err.to_string()),
    }
}

/// C3 specialization: unusable indexes plus the index-monitoring caveat for
/// unused indexes.
fn degrading_index_subcheck(
    conn: &dyn OracleConnection,
    subcheck: HealthSubcheck,
    dba_view: &str,
    all_view: &str,
) -> Finding {
    let tier = match detect_view_tier(conn, dba_view, all_view) {
        Some(tier) => tier,
        None => {
            return Finding::skipped(
                subcheck,
                &[dba_view, all_view],
                "no SELECT on DBA_* or ALL_* view",
            );
        }
    };
    let (view, sql) = unusable_indexes_sql(tier);
    match conn.query_rows(&sql, &[]) {
        Ok(rows) => {
            let count = rows.len();
            Finding {
                subcheck,
                severity: if count == 0 {
                    Severity::Ok
                } else {
                    Severity::Warning
                },
                source_view: view.to_owned(),
                summary: format!("{count} unusable index(es) in {view}"),
                detail: json!({
                    "status": "ok",
                    "unusable_count": count,
                    "rows": rows_to_json(&rows),
                    "monitoring_caveat": "Unused-index detection requires index monitoring \
                        (ALTER INDEX ... MONITORING USAGE) to have been enabled; only UNUSABLE \
                        indexes are reported here.",
                }),
            }
        }
        Err(err) => Finding::skipped(subcheck, &[view], err.to_string()),
    }
}

/// C5 specialization: near-ceiling non-CYCLE sequences are a real outage risk,
/// so a hit is `Critical`.
fn degrading_sequence_subcheck(
    conn: &dyn OracleConnection,
    subcheck: HealthSubcheck,
    dba_view: &str,
    all_view: &str,
) -> Finding {
    let tier = match detect_view_tier(conn, dba_view, all_view) {
        Some(tier) => tier,
        None => {
            return Finding::skipped(
                subcheck,
                &[dba_view, all_view],
                "no SELECT on DBA_* or ALL_* view",
            );
        }
    };
    let (view, sql) = sequence_ceiling_sql(tier, SEQUENCE_CEILING_PCT);
    match conn.query_rows(&sql, &[]) {
        Ok(rows) => {
            let count = rows.len();
            Finding {
                subcheck,
                severity: if count == 0 {
                    Severity::Ok
                } else {
                    Severity::Critical
                },
                source_view: view.to_owned(),
                summary: format!(
                    "{count} non-cycling sequence(s) at or above {SEQUENCE_CEILING_PCT}% of ceiling in {view}"
                ),
                detail: json!({
                    "status": "ok",
                    "threshold_pct": SEQUENCE_CEILING_PCT,
                    "near_ceiling_count": count,
                    "rows": rows_to_json(&rows),
                }),
            }
        }
        Err(err) => Finding::skipped(subcheck, &[view], err.to_string()),
    }
}

/// C4: tablespace + UNDO headroom. DBA-only metrics view; degrades to skip.
fn tablespace_subcheck(conn: &dyn OracleConnection, subcheck: HealthSubcheck) -> Finding {
    let (view, sql) = tablespace_usage_sql();
    let rows = match conn.query_rows(&sql, &[]) {
        Ok(rows) => rows,
        Err(err) => return Finding::skipped(subcheck, &[view], err.to_string()),
    };
    // Compute the worst used_percent to set severity.
    let mut worst = 0.0_f64;
    for row in &rows {
        if let Some(pct) = row.text("USED_PERCENT").and_then(|t| t.parse::<f64>().ok())
            && pct > worst
        {
            worst = pct;
        }
    }
    let severity = if worst >= TABLESPACE_CRITICAL_PCT {
        Severity::Critical
    } else if worst >= TABLESPACE_WARN_PCT {
        Severity::Warning
    } else {
        Severity::Ok
    };
    Finding {
        subcheck,
        severity,
        source_view: view.to_owned(),
        summary: format!(
            "worst tablespace used {worst:.2}% (warn>={TABLESPACE_WARN_PCT}, critical>={TABLESPACE_CRITICAL_PCT})"
        ),
        detail: json!({
            "status": "ok",
            "worst_used_percent": worst,
            "warn_pct": TABLESPACE_WARN_PCT,
            "critical_pct": TABLESPACE_CRITICAL_PCT,
            "rows": rows_to_json(&rows),
        }),
    }
}

/// C7: buffer cache hit ratio computed from V$SYSSTAT cumulative counters.
fn buffer_cache_subcheck(conn: &dyn OracleConnection, subcheck: HealthSubcheck) -> Finding {
    let (view, sql) = buffer_cache_hit_ratio_sql();
    let rows = match conn.query_rows(&sql, &[]) {
        Ok(rows) => rows,
        Err(err) => return Finding::skipped(subcheck, &[view], err.to_string()),
    };
    let mut db_block_gets = 0.0_f64;
    let mut consistent_gets = 0.0_f64;
    let mut physical_reads_cache = 0.0_f64;
    for row in &rows {
        let name = row.text("NAME").unwrap_or("").to_ascii_lowercase();
        let value = row
            .text("VALUE")
            .and_then(|t| t.parse::<f64>().ok())
            .unwrap_or(0.0);
        match name.as_str() {
            "db block gets" => db_block_gets = value,
            "consistent gets" => consistent_gets = value,
            "physical reads cache" => physical_reads_cache = value,
            _ => {}
        }
    }
    let logical_reads = db_block_gets + consistent_gets;
    let ratio = if logical_reads > 0.0 {
        ((1.0 - physical_reads_cache / logical_reads) * 100.0).clamp(0.0, 100.0)
    } else {
        // No activity yet — report as informational rather than a false alarm.
        100.0
    };
    Finding {
        subcheck,
        // Hit ratio is advisory only; never raise it above Info on its own.
        severity: Severity::Info,
        source_view: view.to_owned(),
        summary: format!("buffer cache hit ratio {ratio:.2}% (coarse, advisory signal)"),
        detail: json!({
            "status": "ok",
            "hit_ratio_pct": (ratio * 100.0).round() / 100.0,
            "db_block_gets": db_block_gets,
            "consistent_gets": consistent_gets,
            "physical_reads_cache": physical_reads_cache,
            "caveat": "Buffer cache hit ratio is a coarse signal: a high ratio does not prove \
                health and a low ratio does not prove a problem. Use AWR/ASH and wait events for \
                real diagnosis.",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_lists_every_subcheck_once() {
        let all = HealthSubcheck::all();
        assert_eq!(all.len(), 6);
        // Names are unique and stable.
        let mut names: Vec<&str> = all.iter().map(|s| s.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 6);
    }

    #[test]
    fn parse_all_selects_everything() {
        let req = parse_health_request("all");
        assert_eq!(req.subchecks, HealthSubcheck::all().to_vec());
        assert!(req.unknown.is_empty());
        // Empty / whitespace also means all.
        assert_eq!(parse_health_request("   ").subchecks.len(), 6);
        assert_eq!(parse_health_request("").subchecks.len(), 6);
    }

    #[test]
    fn parse_comma_list_resolves_and_orders_canonically() {
        // Out-of-order, with aliases and a duplicate.
        let req = parse_health_request("sequences, invalid, indexes, sequence_ceiling");
        assert_eq!(
            req.subchecks,
            vec![
                HealthSubcheck::InvalidObjects,
                HealthSubcheck::UnusableIndexes,
                HealthSubcheck::SequenceCeiling,
            ],
            "recognized subchecks are de-duplicated and emitted in canonical order"
        );
        assert!(req.unknown.is_empty());
    }

    #[test]
    fn parse_collects_unknown_tokens_without_failing() {
        let req = parse_health_request("invalid_objects, not_a_check, , another_bogus");
        assert_eq!(req.subchecks, vec![HealthSubcheck::InvalidObjects]);
        assert_eq!(req.unknown, vec!["not_a_check", "another_bogus"]);
    }

    #[test]
    fn nested_all_in_list_still_means_everything() {
        let req = parse_health_request("invalid, all, bogus");
        assert_eq!(req.subchecks, HealthSubcheck::all().to_vec());
        assert!(req.unknown.is_empty());
    }

    #[test]
    fn invalid_objects_sql_targets_the_right_view_and_predicate() {
        let (dba_view, dba_sql) = invalid_objects_sql(ViewTier::Dba);
        assert_eq!(dba_view, "DBA_OBJECTS");
        assert!(dba_sql.contains("FROM DBA_OBJECTS"));
        assert!(dba_sql.contains("status = 'INVALID'"));
        assert!(is_read_only(&dba_sql));

        // DBA→ALL degradation picks the ALL_* view name.
        let (all_view, all_sql) = invalid_objects_sql(ViewTier::All);
        assert_eq!(all_view, "ALL_OBJECTS");
        assert!(all_sql.contains("FROM ALL_OBJECTS"));
        assert!(!all_sql.contains("DBA_OBJECTS"));
    }

    #[test]
    fn unusable_indexes_sql_targets_status_unusable() {
        let (view, sql) = unusable_indexes_sql(ViewTier::Dba);
        assert_eq!(view, "DBA_INDEXES");
        assert!(sql.contains("status = 'UNUSABLE'"));
        assert!(is_read_only(&sql));
        assert_eq!(unusable_indexes_sql(ViewTier::All).0, "ALL_INDEXES");
    }

    #[test]
    fn tablespace_sql_uses_usage_metrics_view() {
        let (view, sql) = tablespace_usage_sql();
        assert_eq!(view, "DBA_TABLESPACE_USAGE_METRICS");
        assert!(sql.contains("used_percent"));
        assert!(is_read_only(&sql));
    }

    #[test]
    fn sequence_sql_filters_non_cycle_near_ceiling() {
        let (view, sql) = sequence_ceiling_sql(ViewTier::Dba, 90);
        assert_eq!(view, "DBA_SEQUENCES");
        assert!(sql.contains("cycle_flag = 'N'"));
        assert!(sql.contains("last_number >= max_value * 0.9"));
        assert!(is_read_only(&sql));
        assert_eq!(sequence_ceiling_sql(ViewTier::All, 90).0, "ALL_SEQUENCES");
    }

    #[test]
    fn constraint_sql_flags_disabled_or_not_validated() {
        let (view, sql) = disabled_constraints_sql(ViewTier::Dba);
        assert_eq!(view, "DBA_CONSTRAINTS");
        assert!(sql.contains("status = 'DISABLED'"));
        assert!(sql.contains("validated = 'NOT VALIDATED'"));
        assert!(is_read_only(&sql));
        assert_eq!(disabled_constraints_sql(ViewTier::All).0, "ALL_CONSTRAINTS");
    }

    #[test]
    fn buffer_cache_sql_reads_v_sysstat() {
        let (view, sql) = buffer_cache_hit_ratio_sql();
        assert_eq!(view, "V$SYSSTAT");
        assert!(sql.contains("FROM V$SYSSTAT"));
        assert!(sql.contains("physical reads cache"));
        assert!(is_read_only(&sql));
    }

    /// A skipped finding is structured (never a raw ORA-), Info severity, and
    /// names the views it tried.
    #[test]
    fn skipped_finding_is_structured() {
        let f = Finding::skipped(
            HealthSubcheck::InvalidObjects,
            &["DBA_OBJECTS", "ALL_OBJECTS"],
            "no privilege",
        );
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.detail["status"], json!("skipped"));
        assert_eq!(
            f.detail["attempted_views"],
            json!(["DBA_OBJECTS", "ALL_OBJECTS"])
        );
    }

    #[test]
    fn severity_orders_ok_below_critical() {
        assert!(Severity::Ok < Severity::Info);
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Critical);
    }

    // -----------------------------------------------------------------------
    // C10 — consolidated DBA-suite coverage (privilege degradation + C9
    // preflight). This module, plus `awr.rs`'s unit tests and the dispatch
    // `db_health`/`top_queries` tests, plus the `live-xe` suite in
    // `tests/live_oracle.rs`, is the full coverage for WP-C: every subcheck,
    // top_queries Statspack-fallback, and DBA_*→ALL_*→skip degradation. The
    // live AC is "CI-green-with-Oracle = all of the above pass against 23ai".
    // The mocks below are small and local to this test module per AGENTS.md.
    // -----------------------------------------------------------------------

    use crate::error::DbError;
    use crate::types::{OracleBackend, OracleConnectionInfo};

    /// A mock whose `query_rows` outcome is decided by a predicate over the SQL
    /// text: `Err` (a privilege miss) for any view named in `deny`, `Ok` (one
    /// empty row) otherwise. Lets a single type drive every degradation path.
    struct TierMock {
        /// Lowercased substrings that must fail with ORA-00942 (denied view).
        deny: &'static [&'static str],
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
        fn query_rows(
            &self,
            sql: &str,
            _binds: &[crate::types::OracleBind],
        ) -> Result<Vec<crate::types::OracleRow>, DbError> {
            let lower = sql.to_ascii_lowercase();
            if self.deny.iter().any(|needle| lower.contains(needle)) {
                return Err(DbError::Query(
                    "ORA-00942: table or view does not exist".to_owned(),
                ));
            }
            Ok(vec![crate::types::OracleRow { columns: vec![] }])
        }
        fn execute(&self, _sql: &str, _binds: &[crate::types::OracleBind]) -> Result<u64, DbError> {
            Ok(0)
        }
        fn commit(&self) -> Result<(), DbError> {
            Ok(())
        }
        fn rollback(&self) -> Result<(), DbError> {
            Ok(())
        }
    }

    /// DBA_*→ALL_* degradation: when the `DBA_*` probe errors but the `ALL_*`
    /// probe succeeds, the subcheck must run against the `ALL_*` tier (never a
    /// hard failure, never a skip).
    #[test]
    fn degrades_from_dba_to_all_when_dba_is_denied() {
        // Deny only the DBA_* dictionary views; ALL_* stays readable.
        let conn = TierMock { deny: &["dba_"] };
        assert_eq!(
            detect_view_tier(&conn, "DBA_OBJECTS", "ALL_OBJECTS"),
            Some(ViewTier::All),
            "DBA_* denied but ALL_* readable -> ALL tier"
        );
        // End to end: the invalid-objects subcheck reads ALL_OBJECTS and is OK.
        let finding = run_subcheck(&conn, HealthSubcheck::InvalidObjects);
        assert_eq!(finding.source_view, "ALL_OBJECTS");
        assert_eq!(finding.detail["status"], json!("ok"));
    }

    /// DBA_*→ALL_*→skip degradation: when BOTH tiers are denied, the subcheck
    /// yields a structured `skipped` finding (Info severity, names the views it
    /// tried) — never a raw ORA- and never a hard failure.
    #[test]
    fn degrades_to_structured_skip_when_dba_and_all_denied() {
        // Deny every dictionary tier; only a V$ view would survive (irrelevant
        // for a DBA/ALL subcheck).
        let conn = TierMock {
            deny: &["dba_", "all_"],
        };
        assert_eq!(detect_view_tier(&conn, "DBA_OBJECTS", "ALL_OBJECTS"), None);
        let finding = run_subcheck(&conn, HealthSubcheck::InvalidObjects);
        assert_eq!(finding.detail["status"], json!("skipped"));
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(
            finding.detail["attempted_views"],
            json!(["DBA_OBJECTS", "ALL_OBJECTS"])
        );
        assert!(
            !finding.summary.contains("ORA-"),
            "a skip never surfaces a raw ORA- error"
        );
    }

    /// C9 preflight (report-only, offline mock): with full access every subcheck
    /// resolves to its DBA tier and top_queries resolves to the free live cursor
    /// by default; the report carries the historical diagnostics posture too.
    #[test]
    fn preflight_reports_full_access_posture() {
        // Nothing denied -> every probe + feature check succeeds.
        let conn = TierMock { deny: &[] };
        let report = preflight(&conn);
        assert_eq!(report.subchecks.len(), HealthSubcheck::all().len());
        for row in &report.subchecks {
            assert_eq!(row.tier, Some(ViewTier::Dba), "{:?}", row.subcheck);
            assert!(row.status.contains("available"));
        }
        // Default top-queries is always the free live cursor (no pack probe).
        assert_eq!(
            report.top_queries_default,
            crate::awr::DiagnosticsSource::LiveCursor
        );
        // v$parameter answers (an empty row), so detect_diagnostics_pack is
        // false (no DIAGNOSTIC value) but perfstat.stats$snapshot is readable,
        // so historical resolves to Statspack.
        assert!(!report.diagnostics_pack_licensed);
        assert!(report.statspack_installed);
        assert_eq!(
            report.top_queries_historical,
            crate::awr::DiagnosticsSource::Statspack
        );
        assert_eq!(report.runnable_skipped(), (HealthSubcheck::all().len(), 0));
    }

    /// C9 preflight under a least-privilege account: DBA_* + ALL_* denied means
    /// every DBA/ALL subcheck reports a `skip`, V$/DBA-only subchecks likewise,
    /// and historical top-queries degrades to Unavailable — all report-only,
    /// no panic, no error.
    #[test]
    fn preflight_reports_degraded_posture_as_skips() {
        // Deny all dictionary tiers, V$, and the Statspack table -> everything
        // degrades; nothing is a hard error.
        let conn = TierMock {
            deny: &["dba_", "all_", "v$", "perfstat"],
        };
        let report = preflight(&conn);
        for row in &report.subchecks {
            assert_eq!(row.tier, None, "{:?} should be a skip", row.subcheck);
            assert!(row.status.starts_with("skip"));
        }
        let (runnable, skipped) = report.runnable_skipped();
        assert_eq!(runnable, 0);
        assert_eq!(skipped, HealthSubcheck::all().len());
        // No pack, no Statspack -> historical top-queries is Unavailable (a
        // clear structured posture, never a silent empty success).
        assert!(!report.diagnostics_pack_licensed);
        assert!(!report.statspack_installed);
        assert_eq!(
            report.top_queries_historical,
            crate::awr::DiagnosticsSource::Unavailable
        );
        // The default live source is unaffected by missing privileges.
        assert_eq!(
            report.top_queries_default,
            crate::awr::DiagnosticsSource::LiveCursor
        );
    }

    /// top_queries Statspack-fallback (C8): when the Diagnostics Pack is NOT
    /// licensed but Statspack IS installed, historical resolves to Statspack;
    /// when both are absent it resolves to Unavailable; the non-historical
    /// default is always the free live cursor regardless.
    #[test]
    fn top_queries_statspack_fallback_through_preflight() {
        // Pack absent (v$parameter has no DIAGNOSTIC value), Statspack present.
        let with_statspack = TierMock { deny: &[] };
        assert!(!crate::awr::detect_diagnostics_pack(&with_statspack));
        assert!(crate::awr::detect_statspack(&with_statspack));
        assert_eq!(
            crate::awr::resolve_top_sql_source(&with_statspack, true),
            crate::awr::DiagnosticsSource::Statspack,
            "no pack + Statspack installed -> Statspack"
        );
        assert_eq!(
            crate::awr::resolve_top_sql_source(&with_statspack, false),
            crate::awr::DiagnosticsSource::LiveCursor,
            "default mode is unaffected by the historical fallback"
        );

        // Pack absent AND Statspack absent -> historical is Unavailable.
        let without_statspack = TierMock {
            deny: &["perfstat"],
        };
        assert!(!crate::awr::detect_statspack(&without_statspack));
        assert_eq!(
            crate::awr::resolve_top_sql_source(&without_statspack, true),
            crate::awr::DiagnosticsSource::Unavailable
        );
        assert_eq!(
            crate::awr::resolve_top_sql_source(&without_statspack, false),
            crate::awr::DiagnosticsSource::LiveCursor
        );
    }

    /// The preflight serializes to a stable, report-only JSON shape (so a doctor
    /// check can embed it without bespoke formatting).
    #[test]
    fn preflight_serializes_to_stable_json() {
        let conn = TierMock { deny: &[] };
        let value = serde_json::to_value(preflight(&conn)).expect("preflight serializes");
        assert!(value["subchecks"].is_array());
        assert_eq!(value["top_queries_default"], json!("live_cursor"));
        assert!(value["diagnostics_pack_licensed"].is_boolean());
        assert!(value["statspack_installed"].is_boolean());
    }

    /// Lightweight read-only assertion used by the SQL-shape tests: a SELECT
    /// with no DML keyword. Mirrors the dispatch-layer `ensure_read_only`
    /// intent at the builder level.
    fn is_read_only(sql: &str) -> bool {
        let lc = sql.to_ascii_lowercase();
        lc.trim_start().starts_with("select")
            && !lc.contains("insert ")
            && !lc.contains("update ")
            && !lc.contains("delete ")
            && !lc.contains("merge ")
            && !lc.contains("drop ")
            && !lc.contains("alter ")
            && !lc.contains("create ")
    }
}
