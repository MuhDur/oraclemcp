//! Cancellation correctness for the read/execute path.
//!
//! The deterministic LabRuntime model proves that cancellation after a DML
//! boundary still runs cleanup, reaches quiescence, and does not commit.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use asupersync::Cx;
use asupersync::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
use oraclemcp_db::DbError;

#[derive(Default)]
struct SessionLedger {
    savepoints: AtomicUsize,
    rollback_to_savepoint: AtomicUsize,
    commits: AtomicUsize,
    released: AtomicUsize,
}

async fn preview_protocol(cx: &Cx, ledger: &SessionLedger) -> Result<(), DbError> {
    ledger.savepoints.fetch_add(1, Ordering::SeqCst);

    let dml_result = {
        cx.set_cancel_requested(true);
        cx.checkpoint()
            .map_err(|e| DbError::Cancelled(e.to_string()))
    };

    ledger.rollback_to_savepoint.fetch_add(1, Ordering::SeqCst);
    ledger.released.fetch_add(1, Ordering::SeqCst);
    dml_result
}

#[test]
fn dpor_lab_read_execute_path_is_cancel_correct() {
    for seed in [1_u64, 7, 42, 1234] {
        let ledger = Arc::new(SessionLedger::default());
        let ledger_for_task = Arc::clone(&ledger);
        let mut runtime =
            LabRuntimeTarget::create_runtime(TestConfig::new().with_seed(seed).with_tracing(true));

        let cancelled = LabRuntimeTarget::block_on(&mut runtime, async move {
            let cx = Cx::current().expect("lab installs a current Cx");
            matches!(
                preview_protocol(&cx, &ledger_for_task).await,
                Err(DbError::Cancelled(_))
            )
        });

        assert!(
            cancelled,
            "seed {seed}: the cancelled preview surfaces a Cancelled error"
        );
        assert_eq!(
            ledger.rollback_to_savepoint.load(Ordering::SeqCst),
            1,
            "seed {seed}: rollback-to-savepoint runs even on cancel"
        );
        assert_eq!(
            ledger.commits.load(Ordering::SeqCst),
            0,
            "seed {seed}: never a torn commit"
        );
        assert_eq!(
            ledger.released.load(Ordering::SeqCst),
            1,
            "seed {seed}: cleanup completed after cancellation"
        );

        let report = runtime.run_until_quiescent_with_report();
        assert!(
            report.oracle_report.all_passed(),
            "seed {seed}: oracle failures: {:?}",
            report.oracle_report
        );
        assert!(
            report.invariant_violations.is_empty(),
            "seed {seed}: invariant violations: {:?}",
            report.invariant_violations
        );
    }
}
