//! Profiling baseline for the fail-closed classifier hot path (the per-statement
//! gate that runs on EVERY agent query). Measurement-only; `#[ignore]`d so it
//! never gates CI. Run with:
//!   cargo test -p oraclemcp-guard --release --test perf_classifier -- --ignored --nocapture
//!
//! Purpose (profiling-software-performance §BASELINE): quantify the classifier's
//! per-statement CPU cost so the hotspot table can rank it against the inherent
//! DB/HTTP I/O cost (≈10^5–10^7 ns per round-trip). If the classifier is in the
//! microsecond range it is NOT a hotspot — optimizing it would be premature.

use std::time::Instant;

use oraclemcp_guard::{Classifier, ClassifierConfig};

/// A representative corpus spanning the classifier's branches: allow-listed
/// pure SELECTs, DML, DDL, multi-statement batches, and PL/SQL blocks.
const CORPUS: &[&str] = &[
    "SELECT id, name FROM customers WHERE region = 'EMEA' ORDER BY name",
    "SELECT COUNT(*) FROM orders o JOIN line_items l ON o.id = l.order_id",
    "UPDATE accounts SET balance = balance - 100 WHERE id = 42",
    "DELETE FROM sessions WHERE last_seen < SYSDATE - 30",
    "INSERT INTO audit_log (event, ts) VALUES ('login', SYSTIMESTAMP)",
    "DROP TABLE staging_temp",
    "CREATE INDEX idx_cust_region ON customers(region)",
    "BEGIN pkg_billing.recalc(:acct); END;",
    "BEGIN EXECUTE IMMEDIATE 'TRUNCATE TABLE t'; END;",
    "SELECT 1 FROM dual; DROP TABLE t",
    "MERGE INTO target t USING src s ON (t.id = s.id) WHEN MATCHED THEN UPDATE SET t.v = s.v",
    "SELECT billing.lookup(:x) FROM dual",
];

#[test]
#[ignore = "profiling baseline; run explicitly with --release --ignored --nocapture"]
fn classifier_throughput_baseline() {
    let classifier = Classifier::new(ClassifierConfig::new());

    // Iteration counts are env-configurable (measurement-only) so the same
    // harness can be driven under callgrind with a small workload; defaults
    // are unchanged when the env vars are unset.
    let env_u32 = |k: &str, d: u32| {
        std::env::var(k).ok().and_then(|s| s.parse().ok()).unwrap_or(d)
    };
    let warmup = env_u32("PERF_WARMUP", 1_000);
    let iters = env_u32("PERF_ITERS", 20_000);

    // Warm up (prime caches / lazies).
    for _ in 0..warmup {
        for sql in CORPUS {
            std::hint::black_box(classifier.classify(std::hint::black_box(sql)));
        }
    }

    let start = Instant::now();
    let mut sink = 0u64;
    for _ in 0..iters {
        for sql in CORPUS {
            let d = classifier.classify(std::hint::black_box(sql));
            sink = sink.wrapping_add(d.required_level.is_some() as u64);
        }
    }
    let elapsed = start.elapsed();
    std::hint::black_box(sink);

    let total_classifications = iters as u128 * CORPUS.len() as u128;
    let ns_per = elapsed.as_nanos() / total_classifications;
    let per_sec = 1_000_000_000u128 / ns_per.max(1);
    println!(
        "perf.profile.span_summary {{\"span\":\"classifier.classify\",\"classifications\":{total_classifications},\"ns_per\":{ns_per},\"per_sec\":{per_sec},\"corpus\":{} }}",
        CORPUS.len()
    );
    println!(
        "CLASSIFIER BASELINE: {ns_per} ns/statement  (~{per_sec} classifications/sec)  over {total_classifications} runs"
    );
    // Sanity floor: the classifier must be far below a DB round-trip (~1e5 ns).
    // This asserts the profiling conclusion, not a micro-budget.
    assert!(
        ns_per < 100_000,
        "classifier should be << a DB round-trip; got {ns_per} ns"
    );
}
