//! Benchmarks the full page-building path (`read_query`): per-column
//! classification reuse plus the single-pass byte-cap accounting (PERF T1/T2).

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use oraclemcp_db::{
    DbError, OracleBackend, OracleBind, OracleCell, OracleConnection, OracleConnectionInfo,
    OracleRow, QueryCaps, SerializeOptions, read_query,
};

struct PageMock {
    rows: Vec<OracleRow>,
}

impl OracleConnection for PageMock {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }
    fn ping(&self) -> Result<(), DbError> {
        Ok(())
    }
    fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
        Ok(OracleConnectionInfo::default())
    }
    fn query_rows(&self, _sql: &str, _binds: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
        Ok(self.rows.clone())
    }
    fn query_rows_named(
        &self,
        _sql: &str,
        _binds: &[(String, OracleBind)],
    ) -> Result<Vec<OracleRow>, DbError> {
        Ok(self.rows.clone())
    }
    fn execute(&self, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
        Ok(0)
    }
    fn commit(&self) -> Result<(), DbError> {
        Ok(())
    }
    fn rollback(&self) -> Result<(), DbError> {
        Ok(())
    }
}

fn wide_rows(n: usize) -> Vec<OracleRow> {
    (0..n)
        .map(|i| OracleRow {
            columns: vec![
                (
                    "ID".to_owned(),
                    OracleCell::new("NUMBER", Some(format!("{}", i * 1_000_003))),
                ),
                (
                    "CREATED".to_owned(),
                    OracleCell::new("DATE", Some("2026-06-01 12:00:00".to_owned())),
                ),
                (
                    "TS".to_owned(),
                    OracleCell::new(
                        "TIMESTAMP(6) WITH TIME ZONE",
                        Some("2026-06-01 12:00:00.000000 +00:00".to_owned()),
                    ),
                ),
                (
                    "NAME".to_owned(),
                    OracleCell::new("VARCHAR2(200)", Some(format!("row-{i}-héllo-world"))),
                ),
                (
                    "RATIO".to_owned(),
                    OracleCell::new("BINARY_DOUBLE", Some("3.14159".to_owned())),
                ),
                (
                    "NOTE".to_owned(),
                    OracleCell::new("CLOB", Some("a moderately sized note".repeat(4))),
                ),
            ],
        })
        .collect()
}

fn bench_page(c: &mut Criterion) {
    let opts = SerializeOptions::default();
    let mut group = c.benchmark_group("page_serialization");
    for &n in &[10usize, 200, 1000] {
        let mock = PageMock { rows: wide_rows(n) };
        let caps = QueryCaps {
            max_rows: n,
            max_result_bytes: 10 * 1024 * 1024,
        };
        group.bench_function(format!("read_query_{n}_rows"), |b| {
            b.iter(|| {
                let resp = read_query(
                    black_box(&mock),
                    black_box("SELECT * FROM t"),
                    black_box(&[]),
                    black_box(caps),
                    black_box(0),
                    black_box(&opts),
                )
                .expect("page");
                black_box(resp.total_bytes)
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_page);
criterion_main!(benches);
