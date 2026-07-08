//! The `oracle_query` read path (plan §8.2, §9.2; bead P1-2): bind-first
//! execution, cursor pagination, and row/byte caps. The classifier gate (P1-1)
//! and the durable audit (P1-4) are applied by the tool layer *before* this
//! runs; this module owns the execution + pagination + serialization mechanics.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use asupersync::Cx;

// Cancellation checkpoints route through the single crate-wide
// `connection::db_checkpoint`, which is generic over the `Cx` capability row:
// a read handler running under a narrowed `Cx<ReadPathCaps>` (A9) checkpoints
// exactly like one under the full row — no `SPAWN`/`REMOTE`/`RANDOM` needed.
use crate::connection::{OracleConnection, db_checkpoint};
use crate::error::DbError;
use crate::serialize::{PageColumnCache, SerializeOptions, json_byte_len};
use crate::types::OracleBind;

/// Caps on a single page of results (plan §8.2 / §10).
#[derive(Clone, Copy, Debug)]
pub struct QueryCaps {
    /// Max rows per page.
    pub max_rows: usize,
    /// Max serialized bytes per page (the page truncates before exceeding it).
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
    /// Column names in select-list order (from the first row).
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
    /// Serialized byte size of this page.
    pub total_bytes: usize,
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

impl AsOf {
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
    // ORA-08183: ENABLE must not run inside a transaction. Clear any open
    // (startup / metadata / read-only-backstop) transaction first.
    conn.rollback(cx).await?;
    // Defensive: clear any flashback window leaked by a prior aborted call so
    // ENABLE cannot hit ORA-08184 ("re-enable while in Flashback mode").
    conn.flashback_disable(cx).await?;

    let (enable_sql, bind) = as_of.enable_call();
    // Set the session read snapshot. A failure here (e.g. ORA-01031 missing
    // FLASHBACK privilege, ORA-08180 no snapshot at that SCN) is surfaced
    // fail-closed; flashback was NOT enabled, so no window is left open.
    conn.execute(cx, enable_sql, std::slice::from_ref(&bind))
        .await?;

    // Flashback is now active: guarantee teardown regardless of the read
    // outcome. Capture the result WITHOUT `?` so the window is always closed.
    let read = read_query(cx, conn, sql, binds, caps, offset, serialize_opts).await;
    let disable = conn.flashback_disable(cx).await;
    // End the flashback read transaction so the next statement starts clean.
    let _ = conn.rollback(cx).await;

    match (read, disable) {
        (Ok(response), Ok(())) => Ok(response),
        // The read error is the primary signal.
        (Err(read_err), _) => Err(read_err),
        // Read succeeded but the session could not leave Flashback mode — surface
        // it: a silently-flashback session would serve stale data to later reads.
        (Ok(_), Err(disable_err)) => Err(disable_err),
    }
}

fn query_response_from_rows_checked<Caps>(
    cx: &Cx<Caps>,
    rows: Vec<crate::types::OracleRow>,
    caps: QueryCaps,
    offset: usize,
    serialize_opts: &SerializeOptions,
) -> Result<QueryResponse, DbError> {
    db_checkpoint(cx, "oracle_query.serialize.before")?;
    let more_by_rows = rows.len() > caps.max_rows;
    let page = &rows[..rows.len().min(caps.max_rows)];

    let columns: Vec<String> = page
        .first()
        .map(|r| r.columns.iter().map(|(n, _)| n.clone()).collect())
        .unwrap_or_default();
    let column_cache = page.first().map(PageColumnCache::from_row);

    let mut out_rows: Vec<Value> = Vec::with_capacity(page.len());
    let mut total_bytes = 0usize;
    let mut byte_truncated = false;
    for (idx, row) in page.iter().enumerate() {
        if idx % 64 == 0 {
            db_checkpoint(cx, "oracle_query.serialize.rows")?;
        }
        let value = match &column_cache {
            Some(cache) => cache.serialize_row(row, serialize_opts),
            None => crate::serialize::serialize_row(row, serialize_opts),
        };
        let size = json_byte_len(&value);
        // Always include at least one row; otherwise stop before exceeding the cap.
        if !out_rows.is_empty() && total_bytes + size > caps.max_result_bytes {
            byte_truncated = true;
            break;
        }
        total_bytes += size;
        out_rows.push(value);
    }

    let truncated = more_by_rows || byte_truncated;
    let next_cursor = if truncated {
        Some((offset + out_rows.len()).to_string())
    } else {
        None
    };

    db_checkpoint(cx, "oracle_query.serialize.after")?;
    Ok(QueryResponse {
        columns,
        row_count: out_rows.len(),
        rows: out_rows,
        truncated,
        next_cursor,
        total_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{OracleCell, OracleConnectionInfo, OracleRow};

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
        run_with_cx(|cx| async move {
            query_response_from_rows_checked(&cx, rows, caps, offset, serialize_opts)
                .expect("uncancelled query response construction cannot be cancelled")
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
    fn byte_cap_truncates_mid_page() {
        // Tiny byte cap -> only the first (always-included) row fits.
        let caps = QueryCaps {
            max_rows: 100,
            max_result_bytes: 10,
        };
        let r = run(50, caps);
        assert_eq!(r.row_count, 1, "always include at least one row, then stop");
        assert!(r.truncated);
        assert_eq!(r.next_cursor.as_deref(), Some("1"));
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
    ) -> (usize, bool, Option<String>, usize) {
        let more_by_rows = rows.len() > caps.max_rows;
        let page = &rows[..rows.len().min(caps.max_rows)];
        let mut out = 0usize;
        let mut total = 0usize;
        let mut byte_truncated = false;
        for row in page {
            let value = crate::serialize::serialize_row(row, opts);
            let size = value.to_string().len();
            if out != 0 && total + size > caps.max_result_bytes {
                byte_truncated = true;
                break;
            }
            total += size;
            out += 1;
        }
        let truncated = more_by_rows || byte_truncated;
        let cursor = truncated.then(|| (offset + out).to_string());
        (out, truncated, cursor, total)
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
                let got = query_response_from_rows(rows.clone(), caps, offset, &opts);
                let (rc, trunc, cursor, total) = reference_page(&rows, caps, offset, &opts);
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
            Ok(OracleConnectionInfo::default())
        }
        async fn query_rows(
            &self,
            _cx: &Cx,
            _sql: &str,
            _b: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.events.lock().expect("events").push("query".to_owned());
            if self.fail_read {
                return Err(DbError::Query("boom".to_owned()));
            }
            Ok(vec![OracleRow {
                columns: vec![(
                    "C".to_owned(),
                    OracleCell::new("NUMBER", Some("1".to_owned())),
                )],
            }])
        }
        async fn execute(&self, _cx: &Cx, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError> {
            self.events
                .lock()
                .expect("events")
                .push(format!("exec[{}]:{sql}", binds.len()));
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
    fn read_query_as_of_brackets_the_proven_read_with_enable_disable() {
        let conn = FlashbackRecorder::default();
        let events = run_with_cx(|cx| async move {
            read_query_as_of(
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
            conn.events.into_inner().expect("events")
        });
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
                &AsOf::Timestamp("2026-01-01 00:00:00".to_owned()),
            )
            .await
            .expect_err("read fails");
            (err, conn.events.into_inner().expect("events"))
        });
        assert!(
            matches!(err, DbError::Query(_)),
            "the read error is the surfaced signal: {err:?}"
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
}
