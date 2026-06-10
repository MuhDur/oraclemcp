//! Benchmarks the CLOB/text and BLOB capping paths in `serialize_cell` (PERF T2:
//! the CLOB char count is computed once in the cap path).

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use oraclemcp_db::{OracleCell, SerializeOptions, serialize_cell};

fn bench_lob(c: &mut Criterion) {
    let mut group = c.benchmark_group("lob_capping");

    let big_clob = OracleCell::new("CLOB", Some("héllo-clob-".repeat(20_000)));
    let under_cap = SerializeOptions {
        max_lob_chars: usize::MAX,
        ..Default::default()
    };
    let over_cap = SerializeOptions {
        max_lob_chars: 1_024,
        ..Default::default()
    };
    group.bench_function("clob_under_cap", |b| {
        b.iter(|| black_box(serialize_cell(black_box(&big_clob), black_box(&under_cap))));
    });
    group.bench_function("clob_over_cap_truncates", |b| {
        b.iter(|| black_box(serialize_cell(black_box(&big_clob), black_box(&over_cap))));
    });

    let blob = OracleCell::binary("BLOB", vec![0xABu8; 1_048_576]);
    let blob_opts = SerializeOptions {
        max_blob_bytes: 65_536,
        ..Default::default()
    };
    group.bench_function("blob_base64_over_cap", |b| {
        b.iter(|| black_box(serialize_cell(black_box(&blob), black_box(&blob_opts))));
    });
    group.finish();
}

criterion_group!(benches, bench_lob);
criterion_main!(benches);
