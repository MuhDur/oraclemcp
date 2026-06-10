//! Benchmarks type classification: the cost of `classify_type` per call versus
//! amortizing it across a page of rows by classifying each column once (PERF
//! T2). The page path is approximated with repeated `serialize_row` over rows
//! that share a fixed column descriptor.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use oraclemcp_db::{OracleCell, OracleRow, SerializeOptions, classify_type, serialize_row};

const TYPE_NAMES: &[&str] = &[
    "NUMBER",
    "NUMBER(10,2)",
    "VARCHAR2(200)",
    "DATE",
    "TIMESTAMP(6) WITH TIME ZONE",
    "BINARY_DOUBLE",
    "CLOB",
    "RAW(2000)",
    "INTERVAL DAY(2) TO SECOND(6)",
    "SDO_GEOMETRY",
];

fn bench_classify(c: &mut Criterion) {
    let mut group = c.benchmark_group("classify_type");
    group.bench_function("classify_per_call", |b| {
        b.iter(|| {
            for t in TYPE_NAMES {
                black_box(classify_type(black_box(t)));
            }
        });
    });

    let opts = SerializeOptions::default();
    let row = OracleRow {
        columns: vec![
            (
                "ID".to_owned(),
                OracleCell::new("NUMBER", Some("42".to_owned())),
            ),
            (
                "WHEN".to_owned(),
                OracleCell::new("DATE", Some("2026-06-01 12:00:00".to_owned())),
            ),
            (
                "NAME".to_owned(),
                OracleCell::new("VARCHAR2(200)", Some("héllo".to_owned())),
            ),
            (
                "BODY".to_owned(),
                OracleCell::new("CLOB", Some("note".to_owned())),
            ),
        ],
    };
    group.bench_function("serialize_row_classifies_columns", |b| {
        b.iter(|| black_box(serialize_row(black_box(&row), black_box(&opts))));
    });
    group.finish();
}

criterion_group!(benches, bench_classify);
criterion_main!(benches);
