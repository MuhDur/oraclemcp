//! The `oracle_query` read path (plan §8.2, §9.2; bead P1-2): bind-first
//! execution, cursor pagination, and row/byte caps. The classifier gate (P1-1)
//! and the durable audit (P1-4) are applied by the tool layer *before* this
//! runs; this module owns the execution + pagination + serialization mechanics.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use asupersync::Cx;

use crate::connection::OracleConnection;
use crate::error::DbError;
use crate::serialize::{PageColumnCache, SerializeOptions, json_byte_len};
use crate::types::OracleBind;

/// Cancellation checkpoint that works for ANY capability row. Cancellation /
/// budget state lives on `Cx` independent of the effect capabilities, so a
/// read handler running under a narrowed `Cx<ReadPathCaps>` (A9) checkpoints
/// exactly like one under the full row — no `SPAWN`/`REMOTE`/`RANDOM` needed.
fn query_checkpoint<Caps>(cx: &Cx<Caps>, phase: &'static str) -> Result<(), DbError> {
    cx.checkpoint_with(phase)
        .map_err(|err| DbError::Cancelled(format!("{phase}: {err}")))
}

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

fn query_response_from_rows_checked<Caps>(
    cx: &Cx<Caps>,
    rows: Vec<crate::types::OracleRow>,
    caps: QueryCaps,
    offset: usize,
    serialize_opts: &SerializeOptions,
) -> Result<QueryResponse, DbError> {
    query_checkpoint(cx, "oracle_query.serialize.before")?;
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
            query_checkpoint(cx, "oracle_query.serialize.rows")?;
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

    query_checkpoint(cx, "oracle_query.serialize.after")?;
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
}
