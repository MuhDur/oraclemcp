//! Loom model checks for the stateful-lane lifecycle/registry lock order
//! (bead oraclemcp-eng-program-bp8ia.9.6, H6).
//!
//! Run (nightly Tier 2, not part of ordinary `cargo test`):
//!
//! ```text
//! RUSTFLAGS="--cfg loom" cargo +nightly-2026-05-11 test -p oraclemcp-core \
//!     --test loom_lane_lock_order --release
//! ```
//!
//! `StatefulLaneDispatch` in `src/lane.rs` documents and enforces the
//! canonical Lifecycle -> Registry order. Its production mutexes are
//! `parking_lot` primitives, so this small mirror gives loom control over the
//! exact two-lock skeleton. The injected reverse-order child proves the model
//! detects the prohibited AB-BA shape instead of merely testing two benign
//! operations.

#![cfg(loom)]

use loom::sync::{Arc, Mutex};
use loom::thread;

struct LaneLocks {
    lifecycle: Mutex<()>,
    registry: Mutex<()>,
}

impl LaneLocks {
    fn new() -> Self {
        Self {
            lifecycle: Mutex::new(()),
            registry: Mutex::new(()),
        }
    }

    /// Mirrors the canonical Lifecycle -> Registry sections used to install
    /// and close a `StatefulLaneDispatch` lane.
    fn lifecycle_then_registry(&self) {
        let _lifecycle = self.lifecycle.lock().unwrap();
        thread::yield_now();
        let _registry = self.registry.lock().unwrap();
    }

    /// Deliberately injected prohibited edge: Registry -> Lifecycle.
    fn registry_then_lifecycle_bug(&self) {
        let _registry = self.registry.lock().unwrap();
        thread::yield_now();
        let _lifecycle = self.lifecycle.lock().unwrap();
    }
}

const REVERSED_ORDER_INNER_ENV: &str = "ORACLEMCP_LOOM_REVERSED_ORDER_INNER";

/// Two production-shaped operations can contend but cannot form a cycle when
/// both obey Lifecycle -> Registry.
#[test]
fn canonical_lifecycle_then_registry_order_never_deadlocks() {
    loom::model(|| {
        let locks = Arc::new(LaneLocks::new());
        let first = {
            let locks = Arc::clone(&locks);
            thread::spawn(move || locks.lifecycle_then_registry())
        };
        let second = {
            let locks = Arc::clone(&locks);
            thread::spawn(move || locks.lifecycle_then_registry())
        };
        first.join().expect("first canonical operation exits");
        second.join().expect("second canonical operation exits");
    });
}

/// Sensitivity proof: adding one Registry -> Lifecycle edge opposite the
/// canonical operation must make loom find the AB-BA deadlock. Loom aborts
/// while cleaning up a deadlocked execution, so—as in the shipping-spool
/// regression model—the failing shape runs in a child process and the parent
/// requires both non-success and loom's explicit `deadlock` report.
#[test]
fn injected_registry_then_lifecycle_edge_deadlocks() {
    if std::env::var_os(REVERSED_ORDER_INNER_ENV).is_some() {
        loom::model(|| {
            let locks = Arc::new(LaneLocks::new());
            let canonical = {
                let locks = Arc::clone(&locks);
                thread::spawn(move || locks.lifecycle_then_registry())
            };
            let reversed = {
                let locks = Arc::clone(&locks);
                thread::spawn(move || locks.registry_then_lifecycle_bug())
            };
            let _ = canonical.join();
            let _ = reversed.join();
        });
        return;
    }

    let exe = std::env::current_exe().expect("test binary path");
    let output = std::process::Command::new(exe)
        .args([
            "--exact",
            "injected_registry_then_lifecycle_edge_deadlocks",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(REVERSED_ORDER_INNER_ENV, "1")
        .output()
        .expect("spawn inner loom lock-order model process");
    assert!(
        !output.status.success(),
        "the reversed lock edge must deadlock under loom; a passing inner run \
         means the model lost the AB-BA bug shape"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("deadlock") || stderr.contains("deadlock"),
        "the inner failure must be loom's deadlock report, not an unrelated \
         error;\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}
