//! The `oracle_query` read path (plan §8.2, §9.2; bead P1-2): bind-first
//! execution, cursor pagination, and row/byte caps. The classifier gate (P1-1)
//! and the durable audit (P1-4) are applied by the tool layer *before* this
//! runs; this module owns the execution + pagination + serialization mechanics.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use asupersync::Cx;
use oraclemcp_error::parse_ora_code;

// Cancellation checkpoints route through the single crate-wide
// `connection::db_checkpoint`, which is generic over the `Cx` capability row:
// a read handler running under a narrowed `Cx<ReadPathCaps>` (A9) checkpoints
// exactly like one under the full row — no `SPAWN`/`REMOTE`/`RANDOM` needed.
use crate::connection::{OracleConnection, db_checkpoint};
use crate::error::{
    DbError, FlashbackRefusalKind, QuarantineOutcome, classify_flashback_refusal_message,
};
use crate::masking::ResultMaskingCertificate;
use crate::serialize::{PageColumnCache, SerializeOptions, checked_byte_budget_add};
use crate::types::OracleBind;

#[cfg(test)]
use crate::serialize::json_byte_len;

/// Caps on a single page of results (plan §8.2 / §10).
#[derive(Clone, Copy, Debug)]
pub struct QueryCaps {
    /// Max rows per page.
    pub max_rows: usize,
    /// Max compact serialized bytes across row objects in one page. Column
    /// metadata, pagination fields, and outer MCP response framing are excluded.
    /// The page truncates before this row-payload budget is exceeded.
    pub max_result_bytes: usize,
}

impl Default for QueryCaps {
    fn default() -> Self {
        // Plan §8.2: default 200 rows, 10 MB, sized against the ~25k-token
        // tool-response limit.
        QueryCaps {
            max_rows: 200,
            max_result_bytes: 10 * 1024 * 1024,
        }
    }
}

/// A page of query results (dual-output friendly: `rows` is structured JSON).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryResponse {
    /// Column names in select-list order (from statement describe metadata when
    /// available, otherwise from the first materialized row).
    pub columns: Vec<String>,
    /// Serialized rows (each a JSON object per the §5.2 type table).
    pub rows: Vec<Value>,
    /// Rows in this page.
    pub row_count: usize,
    /// Whether more rows exist (row or byte cap hit).
    pub truncated: bool,
    /// Opaque cursor for the next page (the next offset), if truncated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Compact serialized bytes across the row objects in this page. Column
    /// metadata, pagination fields, and outer MCP response framing are excluded.
    pub total_bytes: usize,
    /// Exact database snapshot used for a flashback (`as_of`) read. A timestamp
    /// target is resolved by Oracle before the read and echoed here as its SCN,
    /// so callers can replay the same snapshot without a lossy wall-clock hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_scn: Option<u64>,
    /// Proof-carrying egress certificate for result masking, present only when
    /// the page's active masking policy transformed one or more columns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mask_certificate: Option<ResultMaskingCertificate>,
}

/// Wrap a SELECT in an Oracle 12c+ OFFSET/FETCH envelope for stateless cursor
/// pagination. `offset`/`fetch` are server-controlled integers (never agent
/// input), so formatting them in is not an injection vector; the inner query is
/// untouched and its binds still apply.
#[must_use]
pub fn paginated_sql(sql: &str, offset: usize, fetch: usize) -> String {
    let inner = sql.trim().trim_end_matches(';').trim_end();
    format!("SELECT * FROM (\n{inner}\n) OFFSET {offset} ROWS FETCH NEXT {fetch} ROWS ONLY")
}

/// Parse an opaque cursor (the next offset) back to a usize; absent / malformed
/// cursors start at offset 0.
#[must_use]
pub fn cursor_to_offset(cursor: Option<&str>) -> usize {
    cursor
        .and_then(|c| c.trim().parse::<usize>().ok())
        .unwrap_or(0)
}

/// Execute one page of a read query against `conn`: bind-first, paginated, and
/// capped. Fetches `max_rows + 1` to detect "more"; truncates on the byte cap.
///
/// `Cx`-first and `async` (B1): cancellation/budget travel with the call, and
/// the DB round trip is `.await`-ed on the one ambient runtime. The
/// page-building/serialization loop is checkpointed against the SAME `cx`. The
/// read DB round trip needs the full `&Cx` (the native driver requires `IO`);
/// the dispatcher still narrows its handler-level context to
/// `oraclemcp_core::ReadPathCaps` for the A9 structural guarantee — the DB
/// round trip is the one place that legitimately needs the unnarrowed effect
/// row.
pub async fn read_query(
    cx: &Cx,
    conn: &dyn OracleConnection,
    sql: &str,
    binds: &[OracleBind],
    caps: QueryCaps,
    offset: usize,
    serialize_opts: &SerializeOptions,
) -> Result<QueryResponse, DbError> {
    let fetch = caps.max_rows.saturating_add(1).max(1);
    let wrapped = paginated_sql(sql, offset, fetch);
    if let Some(page) = conn
        .query_bounded_page(cx, &wrapped, binds, caps, offset, serialize_opts)
        .await?
    {
        return Ok(page);
    }
    let rows = conn
        .query_rows_with_serialize_options(cx, &wrapped, binds, serialize_opts)
        .await?;
    query_response_from_rows_checked(cx, rows, caps, offset, serialize_opts)
}

/// Execute one page of a read query with named binds (`:name`). This is used by
/// operator-defined tools, whose SQL is authored in config and naturally refers
/// to named parameters. `Cx`-first and `async` (B1) — see [`read_query`].
pub async fn read_query_named(
    cx: &Cx,
    conn: &dyn OracleConnection,
    sql: &str,
    binds: &[(String, OracleBind)],
    caps: QueryCaps,
    offset: usize,
    serialize_opts: &SerializeOptions,
) -> Result<QueryResponse, DbError> {
    let fetch = caps.max_rows.saturating_add(1).max(1);
    let wrapped = paginated_sql(sql, offset, fetch);
    if let Some(page) = conn
        .query_bounded_page_named(cx, &wrapped, binds, caps, offset, serialize_opts)
        .await?
    {
        return Ok(page);
    }
    let rows = conn
        .query_rows_named_with_serialize_options(cx, &wrapped, binds, serialize_opts)
        .await?;
    query_response_from_rows_checked(cx, rows, caps, offset, serialize_opts)
}

/// A point-in-time flashback target for a *proven-read* query (K9).
///
/// The base `SELECT` is classified read-only by the UNCHANGED guard classifier
/// **before** any flashback is applied; a flashback read only changes WHICH
/// committed snapshot is read, never read-vs-write, so no new proof obligation
/// arises and the prover is never handed flashback SQL. The SCN / timestamp is
/// always carried as a **bind** to the `DBMS_FLASHBACK` call — never
/// interpolated into SQL text (no injection through the value).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AsOf {
    /// Read as of a system change number (the deterministic form).
    Scn(u64),
    /// Read as of a wall-clock timestamp `YYYY-MM-DD HH24:MI:SS` (a leading `T`
    /// date/time separator is accepted and normalized to a space). Oracle
    /// resolves the timestamp to the nearest SCN (~3s granularity).
    Timestamp(String),
}

const CURRENT_SCN_SQL: &str =
    "SELECT DBMS_FLASHBACK.GET_SYSTEM_CHANGE_NUMBER AS OBSERVED_SCN FROM DUAL";
const TIMESTAMP_TO_SCN_SQL: &str =
    "SELECT TIMESTAMP_TO_SCN(TO_TIMESTAMP(:1, 'YYYY-MM-DD HH24:MI:SS')) AS OBSERVED_SCN FROM DUAL";

/// ORA-00904 on [`CURRENT_SCN_SQL`] means the `DBMS_FLASHBACK` expression did
/// not resolve for THIS session — verified live (18c/21c/23ai) to be a
/// missing EXECUTE grant on `SYS.DBMS_FLASHBACK` rather than a version gap:
/// the package is present and VALID on every version in the matrix, and the
/// expression works once granted.
fn current_scn_expression_is_unavailable(error: &DbError) -> bool {
    matches!(error, DbError::Query(message) if parse_ora_code(message) == Some(904))
}

fn parse_observed_scn(rows: &[crate::types::OracleRow], source: &str) -> Result<u64, DbError> {
    let value = rows
        .first()
        .and_then(|row| row.text("OBSERVED_SCN"))
        .ok_or_else(|| DbError::Query(format!("Oracle returned no {source}")))?;
    value
        .parse::<u64>()
        .map_err(|_| DbError::Query(format!("Oracle returned a non-numeric {source}: {value:?}")))
}

impl AsOf {
    /// Capture the SCN of the current read-only transaction snapshot.
    ///
    /// Call this as the first query after `SET TRANSACTION READ ONLY`: Oracle
    /// keeps later reads in that transaction on the same consistent snapshot,
    /// while the returned SCN is a deterministic `DBMS_FLASHBACK` replay
    /// target. The profile needs execute access to `DBMS_FLASHBACK`, which the
    /// subsequent replay operation needs too.
    ///
    /// F-S1 / SEC-4 (self-heal DOWN, never silently UP): a missing grant
    /// (ORA-00904) is a **PROBED capability**, not a recoverable hiccup — this
    /// returns a typed [`DbError::FlashbackRefusal`] with
    /// [`crate::FlashbackRefusalKind::CapabilityUnavailable`] rather than
    /// silently substituting a different server-owned SCN source
    /// (`V$DATABASE.CURRENT_SCN`) under the same "success" result. Earlier
    /// revisions of this probe did exactly that substitution, invisibly, which
    /// let an audit trail's `observed_scn` provenance quietly change meaning
    /// without record. Callers that still want to serve the surrounding read
    /// when the capability is absent make that choice themselves, explicitly,
    /// against this typed refusal — writing an audited degraded-mode record
    /// rather than letting this probe paper over the gap. The SQL is
    /// server-owned and uses no caller-supplied text.
    pub async fn current_system_change_number(
        cx: &Cx,
        conn: &dyn OracleConnection,
    ) -> Result<u64, DbError> {
        let rows = match conn.query_rows(cx, CURRENT_SCN_SQL, &[]).await {
            Ok(rows) => rows,
            // 23ai accepts the package expression above only without
            // parentheses. A privilege, connection, or any other error stays
            // fail-closed and propagates untouched below; only ORA-00904 gets
            // the typed capability-unavailable treatment.
            Err(error) if current_scn_expression_is_unavailable(&error) => {
                let message = match &error {
                    DbError::Query(message) => message.clone(),
                    other => other.to_string(),
                };
                return Err(DbError::FlashbackRefusal {
                    kind: FlashbackRefusalKind::CapabilityUnavailable,
                    message,
                    ora_code: Some(904),
                });
            }
            Err(error) => return Err(error),
        };
        parse_observed_scn(&rows, "current system change number")
    }

    /// Resolve this structured flashback target to the exact SCN used for
    /// replay.
    ///
    /// An SCN target is already deterministic. A timestamp target is converted
    /// by Oracle before the flashback window is opened, so the recorded audit
    /// value is an SCN rather than a lossy wall-clock hint.
    pub async fn resolve_to_scn(
        &self,
        cx: &Cx,
        conn: &dyn OracleConnection,
    ) -> Result<u64, DbError> {
        match self {
            Self::Scn(scn) => Ok(*scn),
            Self::Timestamp(timestamp) => {
                let bind = OracleBind::String(timestamp.trim().replacen('T', " ", 1));
                let rows = conn
                    .query_rows(cx, TIMESTAMP_TO_SCN_SQL, std::slice::from_ref(&bind))
                    .await
                    .map_err(map_flashback_refusal)?;
                parse_observed_scn(&rows, "timestamp flashback target")
                    .map_err(map_flashback_refusal)
            }
        }
    }

    /// The `DBMS_FLASHBACK.ENABLE_*` anonymous PL/SQL block and its single bound
    /// argument. The SCN/timestamp is the ONLY value and it is a positional bind
    /// (`:1`) against a FIXED template, so the value can never be interpolated or
    /// injected into the SQL text.
    fn enable_call(&self) -> (&'static str, OracleBind) {
        match self {
            AsOf::Scn(scn) => (
                "BEGIN DBMS_FLASHBACK.ENABLE_AT_SYSTEM_CHANGE_NUMBER(:1); END;",
                // SCNs are ~48-bit, comfortably inside i64. A hypothetical
                // overflow saturates to i64::MAX, which Oracle rejects as a
                // future SCN (fail-closed) — it never silently reads a wrong
                // snapshot.
                OracleBind::I64(i64::try_from(*scn).unwrap_or(i64::MAX)),
            ),
            AsOf::Timestamp(ts) => (
                "BEGIN DBMS_FLASHBACK.ENABLE_AT_TIME(TO_TIMESTAMP(:1, 'YYYY-MM-DD HH24:MI:SS')); END;",
                OracleBind::String(ts.trim().replacen('T', " ", 1)),
            ),
        }
    }
}

/// Execute a proven-read query as of a past SCN/timestamp by bounding it in a
/// session-level `DBMS_FLASHBACK` window (K9).
///
/// The `sql` handed here is the SAME already-classified read-only statement the
/// non-flashback path runs — it is executed **unchanged** (no per-table `AS OF`
/// rewrite). The flashback target is set on the SESSION via
/// `DBMS_FLASHBACK.ENABLE_*` (the SCN/timestamp **bound**, never interpolated),
/// the proven query runs, and the window is ALWAYS torn down.
///
/// Session-mode contract (verified live against 23ai): Oracle refuses to enable
/// flashback inside a transaction (`ORA-08183`), so this rolls back first — that
/// is why the A1 `SET TRANSACTION READ ONLY` backstop is not armed on this path
/// (the dispatcher resets its belief). While flashback is enabled the session
/// itself refuses DML, so defense-in-depth is preserved by a different DB
/// mechanism. `DBMS_FLASHBACK.DISABLE` runs even if the read is cancelled (see
/// [`OracleConnection::flashback_disable`]) so the pinned session is never left
/// stranded reading a stale snapshot.
#[allow(clippy::too_many_arguments)]
pub async fn read_query_as_of(
    cx: &Cx,
    conn: &dyn OracleConnection,
    sql: &str,
    binds: &[OracleBind],
    caps: QueryCaps,
    offset: usize,
    serialize_opts: &SerializeOptions,
    as_of: &AsOf,
) -> Result<QueryResponse, DbError> {
    // The thin cleanup path conservatively discards its connection before it
    // returns a DBMS_FLASHBACK failure. Capture version metadata while the
    // session is still healthy so a later typed refusal can name the actual
    // Oracle version even when that conservative discard occurs.
    let flashback_server_version = conn
        .describe(cx)
        .await
        .ok()
        .and_then(|info| info.server_version);
    // Resolve a timestamp before opening the flashback window. The fixed,
    // server-owned conversion preserves the exact SCN Oracle chose and lets the
    // response carry a deterministic replay handle for either input form.
    let observed_scn = as_of.resolve_to_scn(cx, conn).await.map_err(|error| {
        map_flashback_refusal_with_server_version(error, flashback_server_version.as_deref())
    })?;
    let resolved_as_of = AsOf::Scn(observed_scn);
    // ORA-08183: ENABLE must not run inside a transaction. Clear any open
    // (startup / metadata / read-only-backstop) transaction first.
    conn.rollback(cx).await.map_err(|error| {
        map_flashback_refusal_with_server_version(error, flashback_server_version.as_deref())
    })?;
    // Defensive: clear any flashback window leaked by a prior aborted call so
    // ENABLE cannot hit ORA-08184 ("re-enable while in Flashback mode").
    if let Err(error) = conn.flashback_disable(cx).await {
        return Err(map_flashback_refusal_with_server_version(
            error,
            flashback_server_version.as_deref(),
        ));
    }

    let (enable_sql, bind) = resolved_as_of.enable_call();
    // Set the session read snapshot. A failure here (e.g. ORA-01031 missing
    // FLASHBACK privilege, ORA-08180 no snapshot at that SCN) is surfaced
    // fail-closed; flashback was NOT enabled, so no window is left open.
    if let Err(error) = conn
        .execute(cx, enable_sql, std::slice::from_ref(&bind))
        .await
    {
        return Err(map_flashback_refusal_with_server_version(
            error,
            flashback_server_version.as_deref(),
        ));
    }

    // Flashback is now active: guarantee teardown regardless of the read
    // outcome. Capture the result WITHOUT `?` so the window is always closed.
    let read = read_query(cx, conn, sql, binds, caps, offset, serialize_opts)
        .await
        .map(|mut response| {
            response.observed_scn = Some(observed_scn);
            response
        })
        .map_err(map_flashback_refusal);
    let disable = conn.flashback_disable(cx).await;
    // End the flashback read transaction so the next statement starts clean.
    let rollback = conn.rollback(cx).await;

    match (disable, rollback) {
        (Ok(()), Ok(())) => read,
        (disable, rollback) => {
            let primary = match &read {
                Ok(_) => "flashback read succeeded".to_owned(),
                Err(read_err) => format!("flashback read failed: {read_err}"),
            };
            let mut cleanup_failures = Vec::with_capacity(2);
            if let Err(disable_err) = disable {
                cleanup_failures.push(format!("DBMS_FLASHBACK.DISABLE failed: {disable_err}"));
            }
            if let Err(rollback_err) = rollback {
                cleanup_failures.push(format!("final rollback failed: {rollback_err}"));
            }
            Err(DbError::Quarantined {
                outcome: QuarantineOutcome::UnknownDiscarded,
                message: format!(
                    "{primary}; teardown could not prove the session clean: {}",
                    cleanup_failures.join("; ")
                ),
            })
        }
    }
}

fn map_flashback_refusal(error: DbError) -> DbError {
    match error {
        DbError::Query(message) => {
            if let Some((kind, ora_code)) = classify_flashback_refusal_message(&message) {
                DbError::FlashbackRefusal {
                    kind,
                    message,
                    ora_code,
                }
            } else {
                DbError::Query(message)
            }
        }
        DbError::Execute(message) => {
            if let Some((kind, ora_code)) = classify_flashback_refusal_message(&message) {
                DbError::FlashbackRefusal {
                    kind,
                    message,
                    ora_code,
                }
            } else {
                DbError::Execute(message)
            }
        }
        DbError::Quarantined { outcome, message } => {
            if let Some((kind, ora_code)) = classify_flashback_refusal_message(&message) {
                DbError::FlashbackRefusal {
                    kind,
                    message,
                    ora_code,
                }
            } else {
                DbError::Quarantined { outcome, message }
            }
        }
        other => other,
    }
}

/// Preserve the actual Oracle version in a capability refusal when it was
/// observable before the flashback cleanup boundary. A failed
/// `DBMS_FLASHBACK` call is already terminal; this best-effort metadata can
/// never turn that refusal into a current read or another database operation.
fn map_flashback_refusal_with_server_version(
    error: DbError,
    server_version: Option<&str>,
) -> DbError {
    let refusal = map_flashback_refusal(error);
    let DbError::FlashbackRefusal {
        kind: crate::FlashbackRefusalKind::CapabilityUnavailable,
        mut message,
        ora_code,
    } = refusal
    else {
        return refusal;
    };

    if let Some(version) = server_version {
        message.push_str("; database version ");
        message.push_str(version);
    }
    DbError::FlashbackRefusal {
        kind: crate::FlashbackRefusalKind::CapabilityUnavailable,
        message,
        ora_code,
    }
}

pub(crate) struct QueryPageBuilder {
    caps: QueryCaps,
    offset: usize,
    columns: Vec<String>,
    column_cache: Option<PageColumnCache>,
    mask_certificate: Option<ResultMaskingCertificate>,
    rows: Vec<Value>,
    total_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QueryPagePush {
    Accepted,
    ByteLimit,
}

impl QueryPageBuilder {
    pub(crate) fn new(caps: QueryCaps, offset: usize, columns: Vec<String>) -> Self {
        Self {
            caps,
            offset,
            columns,
            column_cache: None,
            mask_certificate: None,
            rows: Vec::with_capacity(caps.max_rows),
            total_bytes: 0,
        }
    }

    pub(crate) fn push_with_options<Caps>(
        &mut self,
        cx: &Cx<Caps>,
        row: &crate::types::OracleRow,
        serialize_opts: &SerializeOptions,
    ) -> Result<QueryPagePush, DbError> {
        if self.rows.len() >= self.caps.max_rows {
            return Ok(QueryPagePush::ByteLimit);
        }
        if self.rows.len().is_multiple_of(64) {
            db_checkpoint(cx, "oracle_query.serialize.rows")?;
        }
        if self.column_cache.is_none() {
            self.columns = row.columns.iter().map(|(name, _)| name.clone()).collect();
            self.column_cache = Some(PageColumnCache::from_row(row));
            self.mask_certificate = serialize_opts
                .result_masking
                .as_ref()
                .and_then(|policy| policy.certificate_for_row(row));
        }
        let remaining = self.caps.max_result_bytes.saturating_sub(self.total_bytes);
        let serialized = self
            .column_cache
            .as_ref()
            .expect("first row installs the column cache")
            .serialize_row_with_budget(row, serialize_opts, remaining);
        let (value, size) = match serialized {
            Ok(serialized) => serialized,
            Err(size) if self.rows.is_empty() => {
                return Err(DbError::QueryRowTooLarge {
                    row_offset: self.offset,
                    row_bytes: size,
                    max_result_bytes: self.caps.max_result_bytes,
                });
            }
            Err(_) => return Ok(QueryPagePush::ByteLimit),
        };
        let Some(next_total) =
            checked_byte_budget_add(self.total_bytes, size, self.caps.max_result_bytes)
        else {
            return Ok(QueryPagePush::ByteLimit);
        };
        self.total_bytes = next_total;
        self.rows.push(value);
        Ok(QueryPagePush::Accepted)
    }

    #[must_use]
    pub(crate) fn row_count(&self) -> usize {
        self.rows.len()
    }

    pub(crate) fn finish<Caps>(
        self,
        cx: &Cx<Caps>,
        truncated: bool,
    ) -> Result<QueryResponse, DbError> {
        db_checkpoint(cx, "oracle_query.serialize.after")?;
        let next_cursor = truncated.then(|| (self.offset + self.rows.len()).to_string());
        Ok(QueryResponse {
            columns: self.columns,
            row_count: self.rows.len(),
            rows: self.rows,
            truncated,
            next_cursor,
            total_bytes: self.total_bytes,
            observed_scn: None,
            mask_certificate: self.mask_certificate,
        })
    }
}

pub(crate) fn query_response_from_rows_checked<Caps>(
    cx: &Cx<Caps>,
    rows: Vec<crate::types::OracleRow>,
    caps: QueryCaps,
    offset: usize,
    serialize_opts: &SerializeOptions,
) -> Result<QueryResponse, DbError> {
    db_checkpoint(cx, "oracle_query.serialize.before")?;
    let more_by_rows = rows.len() > caps.max_rows;
    let columns = rows
        .first()
        .map(|row| row.columns.iter().map(|(name, _)| name.clone()).collect())
        .unwrap_or_default();
    let mut builder = QueryPageBuilder::new(caps, offset, columns);
    let mut byte_truncated = false;
    for row in rows.iter().take(caps.max_rows) {
        if builder.push_with_options(cx, row, serialize_opts)? == QueryPagePush::ByteLimit {
            byte_truncated = true;
            break;
        }
    }
    builder.finish(cx, more_by_rows || byte_truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{OracleCell, OracleConnectionInfo, OracleRow};
    use crate::{ProfileMaskingSalt, ResultMaskingAction, ResultMaskingPolicy, ResultMaskingRule};

    use asupersync::runtime::RuntimeBuilder;

    /// Run an async test body on a fresh current-thread runtime, handing it the
    /// installed request `Cx`.
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

    /// Build a query response from already-materialized rows on a real `Cx`
    /// (the serialize path is checkpointed, so it needs a context).
    fn query_response_from_rows(
        rows: Vec<crate::types::OracleRow>,
        caps: QueryCaps,
        offset: usize,
        serialize_opts: &SerializeOptions,
    ) -> QueryResponse {
        try_query_response_from_rows(rows, caps, offset, serialize_opts)
            .expect("uncancelled query response construction succeeds")
    }

    fn try_query_response_from_rows(
        rows: Vec<crate::types::OracleRow>,
        caps: QueryCaps,
        offset: usize,
        serialize_opts: &SerializeOptions,
    ) -> Result<QueryResponse, DbError> {
        run_with_cx(|cx| async move {
            query_response_from_rows_checked(&cx, rows, caps, offset, serialize_opts)
        })
    }

    /// A mock returning `n` synthetic rows for any query (ignores pagination SQL
    /// — pagination wrapping is exercised separately by `paginated_sql` + the
    /// live test).
    struct NRowMock {
        n: usize,
    }
    #[async_trait::async_trait(?Send)]
    impl OracleConnection for NRowMock {
        fn backend(&self) -> crate::types::OracleBackend {
            crate::types::OracleBackend::RustOracle
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
            Ok((0..self.n)
                .map(|i| OracleRow {
                    columns: vec![
                        (
                            "ID".to_owned(),
                            OracleCell::new("NUMBER", Some(i.to_string())),
                        ),
                        (
                            "NAME".to_owned(),
                            OracleCell::new("VARCHAR2", Some(format!("n{i}"))),
                        ),
                    ],
                })
                .collect())
        }
        async fn query_rows_named(
            &self,
            cx: &Cx,
            _sql: &str,
            b: &[(String, OracleBind)],
        ) -> Result<Vec<OracleRow>, DbError> {
            assert_eq!(b, &[("id".to_owned(), OracleBind::I64(42))]);
            self.query_rows(cx, "", &[]).await
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

    struct BoundedPageMock {
        rows: Vec<OracleRow>,
        generated: std::sync::atomic::AtomicUsize,
        named_calls: std::sync::atomic::AtomicUsize,
    }

    impl BoundedPageMock {
        fn new(rows: Vec<OracleRow>) -> Self {
            Self {
                rows,
                generated: std::sync::atomic::AtomicUsize::new(0),
                named_calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn page(
            &self,
            cx: &Cx,
            caps: QueryCaps,
            offset: usize,
            serialize_opts: &SerializeOptions,
        ) -> Result<QueryResponse, DbError> {
            let columns = self
                .rows
                .first()
                .map(|row| row.columns.iter().map(|(name, _)| name.clone()).collect())
                .unwrap_or_default();
            let mut builder = QueryPageBuilder::new(caps, offset, columns);
            let mut truncated = false;
            let available = self.rows.len().saturating_sub(offset);
            for row in self.rows.iter().skip(offset) {
                self.generated
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if builder.push_with_options(cx, row, serialize_opts)? == QueryPagePush::ByteLimit {
                    truncated = true;
                    break;
                }
                if builder.row_count() >= caps.max_rows {
                    truncated = builder.row_count() < available;
                    break;
                }
            }
            builder.finish(cx, truncated)
        }
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for BoundedPageMock {
        fn backend(&self) -> crate::types::OracleBackend {
            crate::types::OracleBackend::RustOracle
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
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            panic!("bounded page hook must run before Vec materialization")
        }
        async fn query_bounded_page(
            &self,
            cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
            caps: QueryCaps,
            offset: usize,
            serialize_opts: &SerializeOptions,
        ) -> Result<Option<QueryResponse>, DbError> {
            self.page(cx, caps, offset, serialize_opts).map(Some)
        }
        async fn query_bounded_page_named(
            &self,
            cx: &Cx,
            _sql: &str,
            binds: &[(String, OracleBind)],
            caps: QueryCaps,
            offset: usize,
            serialize_opts: &SerializeOptions,
        ) -> Result<Option<QueryResponse>, DbError> {
            assert_eq!(binds, &[("id".to_owned(), OracleBind::I64(42))]);
            self.named_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.page(cx, caps, offset, serialize_opts).map(Some)
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

    fn run(n: usize, caps: QueryCaps) -> QueryResponse {
        run_with_cx(|cx| async move {
            read_query(
                &cx,
                &NRowMock { n },
                "SELECT id, name FROM t",
                &[],
                caps,
                0,
                &SerializeOptions::default(),
            )
            .await
            .expect("read")
        })
    }

    #[test]
    fn read_query_named_uses_named_binds_and_paginates() {
        let caps = QueryCaps {
            max_rows: 2,
            max_result_bytes: 1_000_000,
        };
        let response = run_with_cx(|cx| async move {
            read_query_named(
                &cx,
                &NRowMock { n: 3 },
                "SELECT * FROM t WHERE id = :id",
                &[("id".to_owned(), OracleBind::I64(42))],
                caps,
                5,
                &SerializeOptions::default(),
            )
            .await
            .expect("read named")
        });
        assert_eq!(response.row_count, 2);
        assert_eq!(response.next_cursor.as_deref(), Some("7"));
    }

    #[test]
    fn ordinary_positional_and_named_reads_prefer_bounded_page_hook() {
        let rows = varied_rows(5_000);
        let conn = BoundedPageMock::new(rows);
        run_with_cx(|cx| async move {
            let caps = QueryCaps {
                max_rows: 7,
                max_result_bytes: 1_000_000,
            };
            let positional = read_query(
                &cx,
                &conn,
                "SELECT id FROM t WHERE id = :1",
                &[OracleBind::I64(42)],
                caps,
                0,
                &SerializeOptions::default(),
            )
            .await
            .expect("bounded positional page");
            assert_eq!(positional.row_count, 7);
            assert_eq!(positional.next_cursor.as_deref(), Some("7"));
            assert_eq!(
                conn.generated.load(std::sync::atomic::Ordering::SeqCst),
                7,
                "the producer is stopped at the row cap instead of materializing 5000 rows"
            );

            let named = read_query_named(
                &cx,
                &conn,
                "SELECT id FROM t WHERE id = :id",
                &[("id".to_owned(), OracleBind::I64(42))],
                caps,
                7,
                &SerializeOptions::default(),
            )
            .await
            .expect("bounded named page");
            assert_eq!(named.row_count, 7);
            assert_eq!(named.next_cursor.as_deref(), Some("14"));
            assert_eq!(
                conn.named_calls.load(std::sync::atomic::Ordering::SeqCst),
                1
            );
            assert_eq!(
                conn.generated.load(std::sync::atomic::Ordering::SeqCst),
                14,
                "named reads use the same bounded producer"
            );
        });
    }

    #[test]
    fn bounded_page_stops_before_later_oversize_and_resume_does_not_skip_it() {
        let small = OracleRow {
            columns: vec![(
                "V".to_owned(),
                OracleCell::new("VARCHAR2", Some("ok".to_owned())),
            )],
        };
        let oversized = OracleRow {
            columns: vec![(
                "V".to_owned(),
                OracleCell::new("VARCHAR2", Some("x".repeat(16_384))),
            )],
        };
        let conn = BoundedPageMock::new(
            std::iter::once(small)
                .chain(std::iter::once(oversized))
                .chain(varied_rows(5_000))
                .collect(),
        );
        run_with_cx(|cx| async move {
            let caps = QueryCaps {
                max_rows: 5_000,
                max_result_bytes: 128,
            };
            let first = read_query(
                &cx,
                &conn,
                "SELECT v FROM t",
                &[],
                caps,
                0,
                &SerializeOptions::default(),
            )
            .await
            .expect("first small row forms a bounded page");
            assert_eq!(first.row_count, 1);
            assert_eq!(first.next_cursor.as_deref(), Some("1"));
            assert_eq!(
                conn.generated.load(std::sync::atomic::Ordering::SeqCst),
                2,
                "only the admitted row plus one bounded candidate is materialized"
            );

            let error = read_query(
                &cx,
                &conn,
                "SELECT v FROM t",
                &[],
                caps,
                1,
                &SerializeOptions::default(),
            )
            .await
            .expect_err("resuming must confront, not skip, the oversized row");
            assert!(matches!(
                error,
                DbError::QueryRowTooLarge {
                    row_offset: 1,
                    max_result_bytes: 128,
                    ..
                }
            ));
            assert_eq!(
                conn.generated.load(std::sync::atomic::Ordering::SeqCst),
                3,
                "resume materializes only the same oversized candidate"
            );
        });
    }

    #[test]
    fn paginated_sql_wraps_and_strips_trailing_semicolon() {
        let s = paginated_sql("SELECT * FROM t;", 40, 21);
        assert!(s.contains("OFFSET 40 ROWS FETCH NEXT 21 ROWS ONLY"));
        assert!(
            s.contains("SELECT * FROM t\n)"),
            "trailing ; stripped, inner intact"
        );
    }

    #[test]
    fn row_cap_truncates_and_sets_cursor() {
        // n+1 fetched (mock returns exactly max_rows+1) -> more, truncated.
        let caps = QueryCaps {
            max_rows: 5,
            max_result_bytes: 1_000_000,
        };
        let r = run(6, caps);
        assert_eq!(r.row_count, 5);
        assert!(r.truncated);
        assert_eq!(r.next_cursor.as_deref(), Some("5"));
        assert_eq!(r.columns, vec!["ID".to_owned(), "NAME".to_owned()]);
        // NUMBER fidelity preserved through the read path.
        assert_eq!(r.rows[0]["ID"], serde_json::json!("0"));
    }

    #[test]
    fn query_response_applies_result_masking_before_rows_escape() {
        let policy = ResultMaskingPolicy::new(
            vec![
                ResultMaskingRule::column("EMAIL_A", ResultMaskingAction::Tokenize),
                ResultMaskingRule::column("EMAIL_B", ResultMaskingAction::Tokenize),
            ],
            true,
        )
        .with_token_salt(
            ProfileMaskingSalt::new("profile:prod:masking:v1", (0_u8..32).collect::<Vec<_>>())
                .expect("valid test salt"),
        );
        let opts = SerializeOptions {
            result_masking: Some(policy),
            ..Default::default()
        };
        let response = query_response_from_rows(
            vec![OracleRow {
                columns: vec![
                    (
                        "EMAIL_A".to_owned(),
                        OracleCell::new("VARCHAR2", Some("alice@example.com".to_owned())),
                    ),
                    (
                        "EMAIL_B".to_owned(),
                        OracleCell::new("VARCHAR2", Some("alice@example.com".to_owned())),
                    ),
                    (
                        "SSN".to_owned(),
                        OracleCell::new("VARCHAR2", Some("123-45-6789".to_owned())),
                    ),
                ],
            }],
            QueryCaps {
                max_rows: 10,
                max_result_bytes: 1_000,
            },
            0,
            &opts,
        );

        assert_eq!(response.row_count, 1);
        assert_eq!(response.rows[0]["EMAIL_A"], response.rows[0]["EMAIL_B"]);
        assert_eq!(response.rows[0]["SSN"], serde_json::json!("<masked>"));
        let escaped = serde_json::to_string(&response).expect("query response JSON");
        assert!(!escaped.contains("alice@example.com"));
        assert!(!escaped.contains("123-45-6789"));
    }

    #[test]
    fn under_cap_is_not_truncated() {
        let caps = QueryCaps {
            max_rows: 100,
            max_result_bytes: 1_000_000,
        };
        let r = run(3, caps);
        assert_eq!(r.row_count, 3);
        assert!(!r.truncated);
        assert!(r.next_cursor.is_none());
    }

    #[test]
    fn first_row_above_byte_cap_fails_closed_without_skipping() {
        let caps = QueryCaps {
            max_rows: 100,
            max_result_bytes: 10,
        };
        let error = run_with_cx(|cx| async move {
            read_query(
                &cx,
                &NRowMock { n: 50 },
                "SELECT id, name FROM t",
                &[],
                caps,
                0,
                &SerializeOptions::default(),
            )
            .await
            .expect_err("first oversized row must not bypass the byte cap")
        });
        match &error {
            DbError::QueryRowTooLarge {
                row_offset,
                row_bytes,
                max_result_bytes,
            } => {
                assert_eq!(*row_offset, 0, "the oversized row is not skipped");
                assert!(*row_bytes > 10);
                assert_eq!(*max_result_bytes, 10);
            }
            other => panic!("expected QueryRowTooLarge, got {other:?}"),
        }
        let envelope = error.into_envelope();
        assert_eq!(
            envelope.error_class,
            oraclemcp_error::ErrorClass::InvalidArguments
        );
        assert!(envelope.message.contains("row at offset 0"));
        assert!(
            envelope
                .next_steps
                .iter()
                .any(|step| step.contains("fewer columns"))
        );
        assert!(
            envelope
                .next_steps
                .iter()
                .any(|step| step.contains("max_lob_chars"))
        );
        assert!(
            envelope.to_json().to_string().len() < 1_024,
            "row-too-large error envelope must remain bounded"
        );
    }

    #[test]
    fn first_row_byte_cap_exact_boundary_and_cap_minus_one() {
        let opts = SerializeOptions::default();
        let rows = varied_rows(1);
        let row_bytes = json_byte_len(&crate::serialize::serialize_row(&rows[0], &opts));
        let exact = query_response_from_rows(
            rows.clone(),
            QueryCaps {
                max_rows: 1,
                max_result_bytes: row_bytes,
            },
            17,
            &opts,
        );
        assert_eq!(exact.row_count, 1);
        assert_eq!(exact.total_bytes, row_bytes);
        assert!(!exact.truncated);

        let error = try_query_response_from_rows(
            rows,
            QueryCaps {
                max_rows: 1,
                max_result_bytes: row_bytes - 1,
            },
            17,
            &opts,
        )
        .expect_err("cap minus one must refuse row zero of this page");
        assert!(matches!(
            error,
            DbError::QueryRowTooLarge {
                row_offset: 17,
                row_bytes: actual,
                max_result_bytes: cap,
            } if actual == row_bytes && cap == row_bytes - 1
        ));
    }

    #[test]
    fn many_wide_columns_cannot_bypass_first_row_cap() {
        let wide_row = OracleRow {
            columns: (0..256)
                .map(|idx| {
                    (
                        format!("COLUMN_{idx}"),
                        OracleCell::new("VARCHAR2", Some("x".repeat(1024))),
                    )
                })
                .collect(),
        };
        let error = try_query_response_from_rows(
            vec![wide_row],
            QueryCaps {
                max_rows: 1,
                max_result_bytes: 4096,
            },
            0,
            &SerializeOptions::default(),
        )
        .expect_err("wide first row must not be included as a progress sentinel");
        assert!(matches!(
            error,
            DbError::QueryRowTooLarge {
                row_offset: 0,
                row_bytes,
                max_result_bytes: 4096,
            } if row_bytes > 4096
        ));
    }

    #[test]
    fn cursor_roundtrips() {
        assert_eq!(cursor_to_offset(Some("40")), 40);
        assert_eq!(cursor_to_offset(None), 0);
        assert_eq!(cursor_to_offset(Some("garbage")), 0);
    }

    /// Reference page builder using the pre-T1 measurement (`serialize_row` then
    /// `Value::to_string().len()`), so the optimized single-pass path can be
    /// proven byte-identical for the cap decision and the totals.
    fn reference_page(
        rows: &[OracleRow],
        caps: QueryCaps,
        offset: usize,
        opts: &SerializeOptions,
    ) -> Result<(usize, bool, Option<String>, usize), usize> {
        let more_by_rows = rows.len() > caps.max_rows;
        let page = &rows[..rows.len().min(caps.max_rows)];
        let mut out = 0usize;
        let mut total = 0usize;
        let mut byte_truncated = false;
        for row in page {
            let value = crate::serialize::serialize_row(row, opts);
            let size = value.to_string().len();
            let Some(next_total) = total.checked_add(size) else {
                if out == 0 {
                    return Err(size);
                }
                byte_truncated = true;
                break;
            };
            if next_total > caps.max_result_bytes {
                if out == 0 {
                    return Err(size);
                }
                byte_truncated = true;
                break;
            }
            total = next_total;
            out += 1;
        }
        let truncated = more_by_rows || byte_truncated;
        let cursor = truncated.then(|| (offset + out).to_string());
        Ok((out, truncated, cursor, total))
    }

    fn varied_rows(n: usize) -> Vec<OracleRow> {
        (0..n)
            .map(|i| OracleRow {
                columns: vec![
                    (
                        "ID".to_owned(),
                        OracleCell::new("NUMBER", Some(format!("{}", i * 1_000_003))),
                    ),
                    (
                        "WHEN".to_owned(),
                        OracleCell::new("DATE", Some("2026-06-01 12:00:00".to_owned())),
                    ),
                    (
                        "NAME".to_owned(),
                        OracleCell::new("VARCHAR2", Some(format!("row-{i}-héllo"))),
                    ),
                ],
            })
            .collect()
    }

    #[test]
    fn single_pass_byte_cap_matches_reference_across_caps() {
        // T1: which row truncates, the truncated flag, the cursor, and the byte
        // total must all be byte-identical to the pre-change two-pass logic.
        let opts = SerializeOptions::default();
        let rows = varied_rows(40);
        for &max_rows in &[5usize, 20, 100] {
            for &max_result_bytes in &[1usize, 10, 50, 120, 500, 10_000, 10 * 1024 * 1024] {
                let caps = QueryCaps {
                    max_rows,
                    max_result_bytes,
                };
                let offset = 7;
                let got = try_query_response_from_rows(rows.clone(), caps, offset, &opts);
                match reference_page(&rows, caps, offset, &opts) {
                    Ok((rc, trunc, cursor, total)) => {
                        let got = got.expect("reference admits this page");
                        assert_eq!(
                            got.row_count, rc,
                            "row_count @ {max_rows}/{max_result_bytes}"
                        );
                        assert_eq!(
                            got.truncated, trunc,
                            "truncated @ {max_rows}/{max_result_bytes}"
                        );
                        assert_eq!(
                            got.next_cursor, cursor,
                            "cursor @ {max_rows}/{max_result_bytes}"
                        );
                        assert_eq!(
                            got.total_bytes, total,
                            "total_bytes @ {max_rows}/{max_result_bytes}"
                        );
                    }
                    Err(row_bytes) => assert!(matches!(
                        got,
                        Err(DbError::QueryRowTooLarge {
                            row_offset: 7,
                            row_bytes: actual,
                            max_result_bytes: cap,
                        }) if actual == row_bytes && cap == max_result_bytes
                    )),
                }
            }
        }
    }

    // ===================================================================
    // K9 — flashback / AS-OF read mode
    // ===================================================================

    /// Records the ORDER of session operations (rollback / execute-with-SQL /
    /// query) so the flashback wrapper's rollback→disable→enable→read→disable
    /// discipline is observable, and optionally fails the read to prove the
    /// window is still torn down.
    #[derive(Default)]
    struct FlashbackRecorder {
        events: std::sync::Mutex<Vec<String>>,
        fail_read: bool,
        fail_read_message: Option<String>,
        current_scn_error: Option<String>,
        fail_enable_message: Option<String>,
        fail_disable_call: Option<usize>,
        fail_disable_message: Option<String>,
        fail_rollback_call: Option<usize>,
        fail_rollback_message: Option<String>,
        connection_info: OracleConnectionInfo,
        disable_calls: std::sync::atomic::AtomicUsize,
        rollback_calls: std::sync::atomic::AtomicUsize,
    }
    #[async_trait::async_trait(?Send)]
    impl OracleConnection for FlashbackRecorder {
        fn backend(&self) -> crate::types::OracleBackend {
            crate::types::OracleBackend::RustOracle
        }
        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(self.connection_info.clone())
        }
        async fn query_rows(
            &self,
            _cx: &Cx,
            sql: &str,
            binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            let event = if sql == CURRENT_SCN_SQL || sql == TIMESTAMP_TO_SCN_SQL {
                format!("query[{}]:{sql}", binds.len())
            } else {
                "query".to_owned()
            };
            self.events.lock().expect("events").push(event);
            if sql == CURRENT_SCN_SQL
                && let Some(message) = &self.current_scn_error
            {
                return Err(DbError::Query(message.clone()));
            }
            if self.fail_read {
                return Err(DbError::Query(
                    self.fail_read_message
                        .clone()
                        .unwrap_or_else(|| "boom".to_owned()),
                ));
            }
            Ok(vec![OracleRow {
                columns: if sql == CURRENT_SCN_SQL || sql == TIMESTAMP_TO_SCN_SQL {
                    vec![(
                        "OBSERVED_SCN".to_owned(),
                        OracleCell::new("NUMBER", Some("4242".to_owned())),
                    )]
                } else {
                    vec![(
                        "C".to_owned(),
                        OracleCell::new("NUMBER", Some("1".to_owned())),
                    )]
                },
            }])
        }
        async fn execute(&self, _cx: &Cx, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError> {
            self.events
                .lock()
                .expect("events")
                .push(format!("exec[{}]:{sql}", binds.len()));
            if sql.starts_with("BEGIN DBMS_FLASHBACK.ENABLE_")
                && let Some(message) = &self.fail_enable_message
            {
                return Err(DbError::Execute(message.clone()));
            }
            if sql == crate::connection::DBMS_FLASHBACK_DISABLE {
                let call = self
                    .disable_calls
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                    + 1;
                if self.fail_disable_call == Some(call) {
                    return Err(DbError::Execute(
                        self.fail_disable_message
                            .clone()
                            .unwrap_or_else(|| format!("disable failure on call {call}")),
                    ));
                }
            }
            Ok(0)
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            self.events
                .lock()
                .expect("events")
                .push("rollback".to_owned());
            let call = self
                .rollback_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            if self.fail_rollback_call == Some(call) {
                return Err(DbError::Execute(
                    self.fail_rollback_message
                        .clone()
                        .unwrap_or_else(|| format!("rollback failure on call {call}")),
                ));
            }
            Ok(())
        }
    }

    #[test]
    fn as_of_scn_binds_the_scn_and_never_interpolates_it() {
        let (sql, bind) = AsOf::Scn(9_031_816).enable_call();
        assert_eq!(
            sql,
            "BEGIN DBMS_FLASHBACK.ENABLE_AT_SYSTEM_CHANGE_NUMBER(:1); END;"
        );
        assert!(sql.contains(":1"), "the scn is a positional bind");
        assert!(
            !sql.contains("9031816"),
            "the scn value never appears in the SQL text (bound, not interpolated)"
        );
        assert_eq!(bind, OracleBind::I64(9_031_816));
    }

    #[test]
    fn as_of_timestamp_binds_a_normalized_string_and_never_interpolates_it() {
        let (sql, bind) = AsOf::Timestamp("2026-07-08T10:11:12".to_owned()).enable_call();
        assert_eq!(
            sql,
            "BEGIN DBMS_FLASHBACK.ENABLE_AT_TIME(TO_TIMESTAMP(:1, 'YYYY-MM-DD HH24:MI:SS')); END;"
        );
        assert!(
            !sql.contains("2026"),
            "the timestamp value never appears in the SQL text (bound, not interpolated)"
        );
        // The `T` date/time separator is normalized to a space; the value is BOUND.
        assert_eq!(bind, OracleBind::String("2026-07-08 10:11:12".to_owned()));
    }

    #[test]
    fn observed_scn_helpers_use_server_owned_bound_queries() {
        assert_eq!(
            CURRENT_SCN_SQL,
            "SELECT DBMS_FLASHBACK.GET_SYSTEM_CHANGE_NUMBER AS OBSERVED_SCN FROM DUAL",
            "Oracle requires the server-owned SCN expression without parentheses"
        );
        let conn = FlashbackRecorder::default();
        let (current, timestamp_target, events) = run_with_cx(|cx| async move {
            let current = AsOf::current_system_change_number(&cx, &conn)
                .await
                .expect("current SCN");
            let timestamp_target = AsOf::Timestamp("2026-07-08T10:11:12".to_owned())
                .resolve_to_scn(&cx, &conn)
                .await
                .expect("timestamp resolves to SCN");
            (
                current,
                timestamp_target,
                conn.events.into_inner().expect("events"),
            )
        });

        assert_eq!(current, 4242);
        assert_eq!(timestamp_target, 4242);
        assert_eq!(
            events,
            vec![
                format!("query[0]:{CURRENT_SCN_SQL}"),
                format!("query[1]:{TIMESTAMP_TO_SCN_SQL}"),
            ]
        );
    }

    /// F-S1 (bead oraclemcp-eng-program-bp8ia.8.3): a missing DBMS_FLASHBACK
    /// grant (ORA-00904) must return a TYPED refusal, never a silent
    /// substitution of a different SQL source presented as success. This is
    /// the discriminating regression test for the silent-fallback bug: before
    /// the fix, this probe caught ORA-00904 and transparently re-issued
    /// `LEGACY_CURRENT_SCN_SQL` (`V$DATABASE.CURRENT_SCN`), returning `Ok`
    /// with no signal that a different mechanism served the value.
    #[test]
    fn observed_scn_returns_typed_capability_refusal_when_oracle_rejects_the_23ai_expression() {
        let conn = FlashbackRecorder {
            current_scn_error: Some(
                "ORA-00904: \"SYS\".\"DBMS_FLASHBACK\": invalid identifier".to_owned(),
            ),
            ..Default::default()
        };
        let (error, events) = run_with_cx(|cx| async move {
            let error = AsOf::current_system_change_number(&cx, &conn)
                .await
                .expect_err("a missing DBMS_FLASHBACK grant must refuse, not silently degrade");
            (error, conn.events.into_inner().expect("events"))
        });

        assert!(
            matches!(
                &error,
                DbError::FlashbackRefusal {
                    kind: FlashbackRefusalKind::CapabilityUnavailable,
                    ora_code: Some(904),
                    ..
                }
            ),
            "expected a typed CapabilityUnavailable refusal, got {error:?}"
        );
        // Only the primary probe ran; nothing silently re-issued a different
        // server-owned query under the same "success" result.
        assert_eq!(events, vec![format!("query[0]:{CURRENT_SCN_SQL}")]);
    }

    #[test]
    fn observed_scn_does_not_fallback_after_any_other_primary_error() {
        let conn = FlashbackRecorder {
            current_scn_error: Some("ORA-01031: insufficient privileges".to_owned()),
            ..Default::default()
        };
        let (error, events) = run_with_cx(|cx| async move {
            let error = AsOf::current_system_change_number(&cx, &conn)
                .await
                .expect_err("permission failure must propagate");
            (error, conn.events.into_inner().expect("events"))
        });

        assert!(matches!(error, DbError::Query(message) if message.contains("ORA-01031")));
        assert_eq!(events, vec![format!("query[0]:{CURRENT_SCN_SQL}")]);
    }

    #[test]
    fn read_query_as_of_brackets_the_proven_read_with_enable_disable() {
        let conn = FlashbackRecorder::default();
        let (response, events) = run_with_cx(|cx| async move {
            let response = read_query_as_of(
                &cx,
                &conn,
                "SELECT count(*) AS c FROM t",
                &[],
                QueryCaps::default(),
                0,
                &SerializeOptions::default(),
                &AsOf::Scn(4242),
            )
            .await
            .expect("flashback read");
            (response, conn.events.into_inner().expect("events"))
        });
        assert_eq!(response.observed_scn, Some(4242));
        // rollback(pre) → defensive DISABLE → ENABLE(:1) → query → DISABLE → rollback
        assert_eq!(
            events,
            vec![
                "rollback".to_owned(),
                "exec[0]:BEGIN DBMS_FLASHBACK.DISABLE; END;".to_owned(),
                "exec[1]:BEGIN DBMS_FLASHBACK.ENABLE_AT_SYSTEM_CHANGE_NUMBER(:1); END;".to_owned(),
                "query".to_owned(),
                "exec[0]:BEGIN DBMS_FLASHBACK.DISABLE; END;".to_owned(),
                "rollback".to_owned(),
            ]
        );
    }

    #[test]
    fn read_query_as_of_timestamp_echoes_oracles_resolved_scn() {
        let conn = FlashbackRecorder::default();
        let (response, events) = run_with_cx(|cx| async move {
            let response = read_query_as_of(
                &cx,
                &conn,
                "SELECT count(*) AS c FROM t",
                &[],
                QueryCaps::default(),
                0,
                &SerializeOptions::default(),
                &AsOf::Timestamp("2026-07-13 12:00:00".to_owned()),
            )
            .await
            .expect("timestamp flashback read");
            (response, conn.events.into_inner().expect("events"))
        });

        assert_eq!(response.observed_scn, Some(4242));
        assert_eq!(
            events,
            vec![
                format!("query[1]:{TIMESTAMP_TO_SCN_SQL}"),
                "rollback".to_owned(),
                "exec[0]:BEGIN DBMS_FLASHBACK.DISABLE; END;".to_owned(),
                "exec[1]:BEGIN DBMS_FLASHBACK.ENABLE_AT_SYSTEM_CHANGE_NUMBER(:1); END;".to_owned(),
                "query".to_owned(),
                "exec[0]:BEGIN DBMS_FLASHBACK.DISABLE; END;".to_owned(),
                "rollback".to_owned(),
            ],
            "timestamp conversion is fixed and bound, then the resolved SCN drives flashback"
        );
    }

    #[test]
    fn read_query_as_of_maps_old_snapshot_enable_error_to_typed_retention_refusal() {
        let conn = FlashbackRecorder {
            fail_enable_message: Some(
                "ORA-08180: no snapshot found based on specified time".to_owned(),
            ),
            ..Default::default()
        };
        let (error, events) = run_with_cx(|cx| async move {
            let error = read_query_as_of(
                &cx,
                &conn,
                "SELECT 1 FROM t",
                &[],
                QueryCaps::default(),
                0,
                &SerializeOptions::default(),
                &AsOf::Scn(1),
            )
            .await
            .expect_err("old SCN is a typed flashback refusal");
            (error, conn.events.into_inner().expect("events"))
        });

        match error {
            DbError::FlashbackRefusal {
                kind,
                message,
                ora_code,
            } => {
                assert_eq!(kind, crate::FlashbackRefusalKind::RetentionExceeded);
                assert_eq!(ora_code, Some(8180));
                assert!(message.contains("ORA-08180"), "{message}");
            }
            other => panic!("expected flashback retention refusal, got {other:?}"),
        }
        assert_eq!(
            events,
            vec![
                "rollback".to_owned(),
                "exec[0]:BEGIN DBMS_FLASHBACK.DISABLE; END;".to_owned(),
                "exec[1]:BEGIN DBMS_FLASHBACK.ENABLE_AT_SYSTEM_CHANGE_NUMBER(:1); END;".to_owned(),
            ],
            "ENABLE failure happens before a flashback window is active"
        );
    }

    #[test]
    fn read_query_as_of_refuses_missing_dbms_flashback_before_opening_a_window() {
        let conn = FlashbackRecorder {
            fail_disable_call: Some(1),
            fail_disable_message: Some(
                "ORA-06550: line 1, column 7:\nPLS-00201: identifier 'DBMS_FLASHBACK' must be declared"
                    .to_owned(),
            ),
            connection_info: OracleConnectionInfo {
                server_version: Some("18.4.0.0.0".to_owned()),
                ..Default::default()
            },
            ..Default::default()
        };
        let (error, events) = run_with_cx(|cx| async move {
            let error = read_query_as_of(
                &cx,
                &conn,
                "SELECT 1 FROM t",
                &[],
                QueryCaps::default(),
                0,
                &SerializeOptions::default(),
                &AsOf::Scn(1),
            )
            .await
            .expect_err("missing DBMS_FLASHBACK must fail closed");
            (error, conn.events.into_inner().expect("events"))
        });

        let env = error.clone().into_envelope();
        match error {
            DbError::FlashbackRefusal {
                kind,
                message,
                ora_code,
            } => {
                assert_eq!(kind, crate::FlashbackRefusalKind::CapabilityUnavailable);
                assert_eq!(ora_code, None, "the PLS wrapper is not the root cause");
                assert!(message.contains("DBMS_FLASHBACK"), "{message}");
                assert!(message.contains("18.4.0.0.0"), "{message}");
            }
            other => panic!("expected typed capability refusal, got {other:?}"),
        }
        assert_eq!(
            env.error_class,
            oraclemcp_error::ErrorClass::FlashbackCapabilityUnavailable
        );
        assert_eq!(
            events,
            vec![
                "rollback".to_owned(),
                "exec[0]:BEGIN DBMS_FLASHBACK.DISABLE; END;".to_owned(),
            ],
            "the unsupported capability must be refused before ENABLE or the caller read"
        );
    }

    #[test]
    fn read_query_as_of_keeps_missing_flashback_capability_typed_after_quarantine() {
        let conn = FlashbackRecorder {
            fail_rollback_call: Some(1),
            fail_rollback_message: Some(
                "database session quarantined (unknown_discarded): DBMS_FLASHBACK.DISABLE cleanup failed; \
                 the thin connection was discarded: server returned Oracle error: ORA-06550: line 1, column 7:\n\
                 PLS-00201: identifier 'DBMS_FLASHBACK' must be declared"
                    .to_owned(),
            ),
            connection_info: OracleConnectionInfo {
                server_version: Some("21.3.0.0.0".to_owned()),
                ..Default::default()
            },
            ..Default::default()
        };
        let (error, events) = run_with_cx(|cx| async move {
            let error = read_query_as_of(
                &cx,
                &conn,
                "SELECT 1 FROM t",
                &[],
                QueryCaps::default(),
                0,
                &SerializeOptions::default(),
                &AsOf::Scn(1),
            )
            .await
            .expect_err("a quarantined follow-up must preserve the typed refusal");
            (error, conn.events.into_inner().expect("events"))
        });

        let envelope = error.clone().into_envelope();
        assert!(matches!(
            error,
            DbError::FlashbackRefusal {
                kind: crate::FlashbackRefusalKind::CapabilityUnavailable,
                ora_code: None,
                ..
            }
        ));
        assert_eq!(
            envelope.error_class,
            oraclemcp_error::ErrorClass::FlashbackCapabilityUnavailable
        );
        assert!(envelope.message.contains("DBMS_FLASHBACK"));
        assert!(envelope.message.contains("21.3.0.0.0"));
        assert_eq!(
            events,
            vec!["rollback".to_owned()],
            "the inherited quarantine is refused before a new window is opened"
        );
    }

    #[test]
    fn read_query_as_of_maps_snapshot_too_old_read_error_to_typed_retention_refusal() {
        let conn = FlashbackRecorder {
            fail_read: true,
            fail_read_message: Some("ORA-01555: snapshot too old".to_owned()),
            ..Default::default()
        };
        let error = run_with_cx(|cx| async move {
            read_query_as_of(
                &cx,
                &conn,
                "SELECT 1 FROM t",
                &[],
                QueryCaps::default(),
                0,
                &SerializeOptions::default(),
                &AsOf::Scn(42),
            )
            .await
            .expect_err("snapshot-too-old read is a typed flashback refusal")
        });

        match error {
            DbError::FlashbackRefusal {
                kind,
                ora_code,
                message,
            } => {
                assert_eq!(kind, crate::FlashbackRefusalKind::RetentionExceeded);
                assert_eq!(ora_code, Some(1555));
                assert!(message.contains("ORA-01555"), "{message}");
            }
            other => panic!("expected flashback retention refusal, got {other:?}"),
        }
    }

    #[test]
    fn read_query_as_of_maps_definition_change_to_typed_refusal() {
        let conn = FlashbackRecorder {
            fail_read: true,
            fail_read_message: Some(
                "ORA-01466: unable to read data - table definition has changed".to_owned(),
            ),
            ..Default::default()
        };
        let error = run_with_cx(|cx| async move {
            read_query_as_of(
                &cx,
                &conn,
                "SELECT 1 FROM t",
                &[],
                QueryCaps::default(),
                0,
                &SerializeOptions::default(),
                &AsOf::Scn(42),
            )
            .await
            .expect_err("post-DDL SCN is a typed flashback refusal")
        });

        match error {
            DbError::FlashbackRefusal {
                kind,
                ora_code,
                message,
            } => {
                assert_eq!(kind, crate::FlashbackRefusalKind::DefinitionChanged);
                assert_eq!(ora_code, Some(1466));
                assert!(message.contains("ORA-01466"), "{message}");
            }
            other => panic!("expected flashback definition-change refusal, got {other:?}"),
        }
    }

    #[test]
    fn read_query_as_of_maps_non_flashbackable_target_to_typed_refusal() {
        let conn = FlashbackRecorder {
            fail_read: true,
            fail_read_message: Some(
                "ORA-02070: database REMOTE does not support flashback in this context".to_owned(),
            ),
            ..Default::default()
        };
        let error = run_with_cx(|cx| async move {
            read_query_as_of(
                &cx,
                &conn,
                "SELECT 1 FROM t@remote",
                &[],
                QueryCaps::default(),
                0,
                &SerializeOptions::default(),
                &AsOf::Scn(42),
            )
            .await
            .expect_err("remote/non-flashbackable read is a typed refusal")
        });

        match error {
            DbError::FlashbackRefusal {
                kind,
                ora_code,
                message,
            } => {
                assert_eq!(kind, crate::FlashbackRefusalKind::NotFlashbackable);
                assert_eq!(ora_code, Some(2070));
                assert!(message.contains("ORA-02070"), "{message}");
            }
            other => panic!("expected flashback unsupported refusal, got {other:?}"),
        }
    }

    #[test]
    fn flashback_refusal_mapper_does_not_reclassify_non_query_execute_errors() {
        let error = map_flashback_refusal(DbError::Cancelled(
            "ORA-08180: no snapshot found based on specified time".to_owned(),
        ));

        assert!(
            matches!(error, DbError::Cancelled(_)),
            "only Oracle Query/Execute errors from the flashback path are typed"
        );
    }

    #[test]
    fn flashback_refusal_mapper_recovers_the_known_capability_from_cleanup_quarantine() {
        let error = map_flashback_refusal_with_server_version(
            DbError::Quarantined {
                outcome: QuarantineOutcome::UnknownDiscarded,
                message: "DBMS_FLASHBACK.DISABLE cleanup failed; the thin connection was discarded: ORA-06550: line 1, column 7: PLS-00201: identifier 'DBMS_FLASHBACK' must be declared"
                    .to_owned(),
            },
            Some("21.3.0.0.0"),
        );

        match error {
            DbError::FlashbackRefusal {
                kind,
                message,
                ora_code,
            } => {
                assert_eq!(kind, crate::FlashbackRefusalKind::CapabilityUnavailable);
                assert_eq!(ora_code, None);
                assert!(message.contains("21.3.0.0.0"), "{message}");
            }
            other => panic!("expected recovered capability refusal, got {other:?}"),
        }
    }

    // ===================================================================
    // K10 — incremental fetch: resume == full-fetch byte-identity
    // ===================================================================

    /// A mock whose `query_rows` HONORS the `OFFSET n ROWS FETCH NEXT m ROWS
    /// ONLY` envelope that [`paginated_sql`] wraps around the inner SELECT, so a
    /// resumed page returns the true next window of a fixed dataset. This lets a
    /// pure unit test prove the incremental-fetch contract (K10 phase 1): paging
    /// with the returned cursor yields rows BYTE-IDENTICAL to a single full
    /// fetch, because every row serializes deterministically regardless of the
    /// page it lands on.
    struct OffsetAwareMock {
        total: usize,
    }

    impl OffsetAwareMock {
        /// Parse `OFFSET {offset} ROWS FETCH NEXT {fetch} ROWS ONLY` out of the
        /// server-built pagination envelope. Absent (an unwrapped query) means
        /// "the whole dataset from 0".
        fn window(sql: &str) -> (usize, usize) {
            let after = |marker: &str| -> Option<usize> {
                let idx = sql.find(marker)? + marker.len();
                sql[idx..]
                    .split_whitespace()
                    .next()
                    .and_then(|tok| tok.parse::<usize>().ok())
            };
            let offset = after("OFFSET ").unwrap_or(0);
            let fetch = after("FETCH NEXT ").unwrap_or(usize::MAX);
            (offset, fetch)
        }
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for OffsetAwareMock {
        fn backend(&self) -> crate::types::OracleBackend {
            crate::types::OracleBackend::RustOracle
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
            let (offset, fetch) = Self::window(sql);
            let end = offset.saturating_add(fetch).min(self.total);
            let start = offset.min(self.total);
            Ok((start..end)
                .map(|i| OracleRow {
                    columns: vec![
                        (
                            "ID".to_owned(),
                            OracleCell::new("NUMBER", Some(format!("{}", i * 7 + 1))),
                        ),
                        (
                            "NAME".to_owned(),
                            OracleCell::new("VARCHAR2", Some(format!("row-{i}-héllo"))),
                        ),
                    ],
                })
                .collect())
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

    /// Walk the cursor from `offset 0` in `page_rows`-sized pages, concatenating
    /// every page's serialized rows. Returns `(all_rows, page_row_counts)`.
    fn drain_by_cursor(conn: &OffsetAwareMock, page_rows: usize) -> (Vec<Value>, Vec<usize>) {
        run_with_cx(|cx| async move {
            let caps = QueryCaps {
                max_rows: page_rows,
                max_result_bytes: 1_000_000,
            };
            let opts = SerializeOptions::default();
            let mut all: Vec<Value> = Vec::new();
            let mut counts: Vec<usize> = Vec::new();
            let mut cursor: Option<String> = None;
            loop {
                let offset = cursor_to_offset(cursor.as_deref());
                let page = read_query(
                    &cx,
                    conn,
                    "SELECT id, name FROM t",
                    &[],
                    caps,
                    offset,
                    &opts,
                )
                .await
                .expect("page read");
                counts.push(page.row_count);
                all.extend(page.rows);
                match page.next_cursor {
                    Some(next) => cursor = Some(next),
                    None => break,
                }
            }
            (all, counts)
        })
    }

    #[test]
    fn incremental_fetch_resume_is_byte_identical_to_full_fetch() {
        // K10 phase 1. A large read paged with the returned cursor must tile the
        // full result exactly: same rows, same order, byte-identical serialized
        // cells — the cursor changes DELIVERY, never the proven-read bytes.
        let conn = OffsetAwareMock { total: 25 };
        let full = run_with_cx(|cx| async move {
            read_query(
                &cx,
                &OffsetAwareMock { total: 25 },
                "SELECT id, name FROM t",
                &[],
                QueryCaps {
                    max_rows: 1_000,
                    max_result_bytes: 10 * 1024 * 1024,
                },
                0,
                &SerializeOptions::default(),
            )
            .await
            .expect("full fetch")
        });
        assert_eq!(full.row_count, 25);
        assert!(!full.truncated, "a single big page reads all 25 rows");
        assert!(full.next_cursor.is_none());

        for page_rows in [1usize, 4, 7, 10, 25, 40] {
            let (paged, counts) = drain_by_cursor(&conn, page_rows);
            assert_eq!(
                paged, full.rows,
                "cursor-resumed pages of {page_rows} are byte-identical to the full fetch"
            );
            // Pages tile the result with no gaps or overlaps.
            assert_eq!(counts.iter().sum::<usize>(), 25);
            let full_pages = 25 / page_rows;
            for c in counts.iter().take(full_pages) {
                assert_eq!(*c, page_rows, "each non-final page is exactly page_rows");
            }
        }
    }

    #[test]
    fn incremental_fetch_empty_result_terminates_without_a_cursor() {
        let conn = OffsetAwareMock { total: 0 };
        let (paged, counts) = drain_by_cursor(&conn, 5);
        assert!(paged.is_empty(), "no rows");
        assert_eq!(
            counts,
            vec![0],
            "exactly one terminal empty page, no cursor"
        );
    }

    #[test]
    fn read_query_as_of_disables_even_when_the_read_fails() {
        let conn = FlashbackRecorder {
            fail_read: true,
            ..Default::default()
        };
        let (err, events) = run_with_cx(|cx| async move {
            let err = read_query_as_of(
                &cx,
                &conn,
                "SELECT 1 FROM t",
                &[],
                QueryCaps::default(),
                0,
                &SerializeOptions::default(),
                &AsOf::Scn(42),
            )
            .await
            .expect_err("read fails");
            (err, conn.events.into_inner().expect("events"))
        });
        assert!(
            matches!(&err, DbError::Query(message) if message == "boom"),
            "successful teardown preserves the exact read error: {err:?}"
        );
        // The window is torn down AFTER the failed read: DISABLE + rollback follow "query".
        let after_query: Vec<_> = events
            .iter()
            .skip_while(|e| *e != "query")
            .cloned()
            .collect();
        assert_eq!(
            after_query,
            vec![
                "query".to_owned(),
                "exec[0]:BEGIN DBMS_FLASHBACK.DISABLE; END;".to_owned(),
                "rollback".to_owned(),
            ],
            "flashback is disabled and the read transaction ended even when the read errors"
        );
    }

    #[test]
    fn read_error_plus_disable_error_is_structurally_quarantined() {
        let conn = FlashbackRecorder {
            fail_read: true,
            // Call 1 is the defensive pre-enable DISABLE; call 2 is teardown.
            fail_disable_call: Some(2),
            ..Default::default()
        };
        let (error, events) = run_with_cx(|cx| async move {
            let error = read_query_as_of(
                &cx,
                &conn,
                "SELECT 1 FROM t",
                &[],
                QueryCaps::default(),
                0,
                &SerializeOptions::default(),
                &AsOf::Scn(42),
            )
            .await
            .expect_err("failed teardown quarantines the session");
            (error, conn.events.into_inner().expect("events"))
        });

        match error {
            DbError::Quarantined { outcome, message } => {
                assert_eq!(outcome, QuarantineOutcome::UnknownDiscarded);
                assert!(
                    message.contains("flashback read failed: oracle query failed: boom"),
                    "primary read diagnostic is retained: {message}"
                );
                assert!(
                    message.contains("DBMS_FLASHBACK.DISABLE failed")
                        && message.contains("disable failure on call 2"),
                    "failed teardown is identified: {message}"
                );
            }
            other => panic!("expected structural quarantine, got {other:?}"),
        }
        assert_eq!(
            events.last().map(String::as_str),
            Some("rollback"),
            "rollback is still attempted after DISABLE fails"
        );
    }

    #[test]
    fn successful_read_plus_final_rollback_error_is_structurally_quarantined() {
        let conn = FlashbackRecorder {
            // Call 1 clears startup state; call 2 ends the flashback read txn.
            fail_rollback_call: Some(2),
            ..Default::default()
        };
        let error = run_with_cx(|cx| async move {
            read_query_as_of(
                &cx,
                &conn,
                "SELECT 1 FROM t",
                &[],
                QueryCaps::default(),
                0,
                &SerializeOptions::default(),
                &AsOf::Scn(42),
            )
            .await
            .expect_err("failed rollback quarantines the session")
        });

        match error {
            DbError::Quarantined { outcome, message } => {
                assert_eq!(outcome, QuarantineOutcome::UnknownDiscarded);
                assert!(
                    message.contains("flashback read succeeded"),
                    "the primary operation outcome is retained: {message}"
                );
                assert!(
                    message.contains("final rollback failed")
                        && message.contains("rollback failure on call 2"),
                    "failed final rollback is identified: {message}"
                );
            }
            other => panic!("expected structural quarantine, got {other:?}"),
        }
    }

    // ---------------------------------------------------------------------
    // C7 wire-contract fixture — a zero-row page must still describe itself.
    // Plan §4-C7 / §A.2.4, bead oraclemcp-091-c7-zero-rows-columns-v6zdw.
    // ---------------------------------------------------------------------

    /// The observable contrast, and the reason the next test matters: the same
    /// query shape reports its schema when a row survives and forgets it when
    /// none does. Column names reach the page only through
    /// `push_with_options` (gated on the first row). The real driver path must
    /// instead seed the page from statement describe metadata before fetching.
    ///
    /// This passes today and pins the working half.
    #[test]
    fn c7_a_page_with_rows_reports_its_columns() {
        let caps = QueryCaps {
            max_rows: 10,
            max_result_bytes: 64 * 1024,
        };
        let row = OracleRow {
            columns: vec![
                (
                    "CUSTOMER_ID".to_owned(),
                    OracleCell::new("NUMBER", Some("1".to_owned())),
                ),
                (
                    "REGION".to_owned(),
                    OracleCell::new("VARCHAR2", Some("EMEA".to_owned())),
                ),
            ],
        };
        let response = query_response_from_rows(vec![row], caps, 0, &SerializeOptions::default());

        assert_eq!(response.row_count, 1);
        assert_eq!(
            response.columns,
            vec!["CUSTOMER_ID".to_owned(), "REGION".to_owned()],
            "a page that kept a row reports the select-list columns"
        );
    }

    /// The failing half of C7.
    ///
    /// A row-level security policy, a `WHERE` that matches nothing, or an
    /// offset past the end all produce the same page: zero rows and, today,
    /// zero columns. An agent cannot tell "this object exists, you may read it,
    /// and nothing matched" from "wrong object" or "no access" — three
    /// situations with three different next actions, collapsed into one
    /// response. The builder must receive statement describe metadata at
    /// construction, before any row is fetched.
    #[test]
    fn c7_a_zero_row_page_still_reports_its_columns() {
        let caps = QueryCaps {
            max_rows: 10,
            max_result_bytes: 64 * 1024,
        };
        let response = run_with_cx(|cx| async move {
            QueryPageBuilder::new(caps, 0, vec!["CUSTOMER_ID".to_owned(), "REGION".to_owned()])
                .finish(&cx, false)
                .expect("an empty page finishes")
        });

        assert_eq!(response.row_count, 0, "the fixture is about an empty page");
        assert_eq!(
            response.columns,
            vec!["CUSTOMER_ID".to_owned(), "REGION".to_owned()],
            "a zero-row page must preserve statement describe metadata"
        );
    }
}
