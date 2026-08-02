//! Loom model checks for the shipping-spool worker/shutdown/enqueue sync
//! skeleton (bead oraclemcp-eng-program-bp8ia.9.6, H6).
//!
//! Run (nightly Tier 2, not part of ordinary `cargo test`):
//!
//! ```text
//! RUSTFLAGS="--cfg loom" cargo +nightly-2026-05-11 test -p oraclemcp-audit \
//!     --test loom_shipping_spool --release
//! ```
//!
//! Optionally bound exploration with `LOOM_MAX_PREEMPTIONS=3` (loom reads the
//! env var); these models are small enough to run exhaustively in well under a
//! second each.
//!
//! ## Why a mirror model
//!
//! `DurableShippingForwarder` (src/shipping_spool.rs) synchronizes with
//! `parking_lot::{Mutex, Condvar}`, `std::thread`, and real file I/O — none of
//! which loom can instrument. These models therefore mirror the exact
//! synchronization skeleton with loom primitives, statement for statement:
//!
//! - [`SpoolModel::run_worker`] mirrors `run_worker` (idle-park loop gated by
//!   `worker_stop`, peek under the lock, destination I/O outside the lock, then
//!   ack-remove under the lock).
//! - [`SpoolModel::enqueue`] mirrors `enqueue` (an `enqueue_closed` check both
//!   before and after taking the queue lock, insert, unlock, `notify_one`).
//! - [`SpoolModel::shutdown_signal_fixed`] mirrors the FIXED `shutdown`
//!   (close enqueue, stop worker, notify, bridge with the queue mutex, notify).
//! - Worker completion closes enqueue authority before releasing the modeled
//!   filesystem lease, matching `WorkerCompletionGuard`'s drop order.
//! - [`SpoolModel::shutdown_signal_prefix`] reproduces the PRE-FIX `shutdown`
//!   shape (store + `notify_all` with NO mutex bridge) whose lost wakeup
//!   stranded the worker forever and hung `join()` — observed as a 75-minute
//!   Windows CI timeout in `a_spool_refuses_a_second_concurrent_worker`.
//!
//! If the production skeleton changes shape, update the mirror in the same
//! commit; the model is only as honest as its correspondence to the source.

#![cfg(loom)]

use std::collections::VecDeque;

use loom::sync::atomic::{AtomicBool, Ordering};
use loom::sync::{Arc, Condvar, Mutex};
use loom::thread;

/// The synchronization skeleton of `DurableShippingForwarder`'s `Shared`
/// (src/shipping_spool.rs `struct Shared`): the queue mutex, the wake condvar,
/// the split lifecycle flags. Records are plain sequence numbers; destination
/// and disk I/O are irrelevant to the interleavings under test. The lease flag
/// models the worker-owned `SpoolLock` becoming available to a successor.
struct SpoolModel {
    queue: Mutex<VecDeque<u32>>,
    wake: Condvar,
    enqueue_closed: AtomicBool,
    worker_stop: AtomicBool,
    lease_released: AtomicBool,
}

impl SpoolModel {
    fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            wake: Condvar::new(),
            enqueue_closed: AtomicBool::new(false),
            worker_stop: AtomicBool::new(false),
            lease_released: AtomicBool::new(false),
        }
    }

    /// Mirrors `run_worker` (src/shipping_spool.rs): park while idle, exit on
    /// `worker_stop`, otherwise peek the head under the lock, deliver outside
    /// the lock, then ack-remove under the lock. Worker completion revokes
    /// enqueue authority before releasing the modeled lease.
    fn run_worker(&self) -> Vec<u32> {
        let mut delivered = Vec::new();
        loop {
            let (stop, next) = {
                let mut queue = self.queue.lock().unwrap();
                while queue.is_empty() && !self.worker_stop.load(Ordering::Acquire) {
                    queue = self.wake.wait(queue).unwrap();
                }
                let stop = self.worker_stop.load(Ordering::Acquire);
                let next = (!stop).then(|| queue.front().copied()).flatten();
                (stop, next)
            };
            if stop {
                // Production drops the queue guard as `run_worker` returns;
                // only then does `WorkerCompletionGuard` revoke enqueue before
                // the subsequently-declared filesystem lease is released.
                self.finish_worker();
                return delivered;
            }
            let Some(seq) = next else {
                continue;
            };
            // Destination I/O happens outside the queue lock in production;
            // a successful forward is modeled as recording the sequence.
            delivered.push(seq);
            // Mirrors `acknowledge`: remove the delivered head under the lock.
            let mut queue = self.queue.lock().unwrap();
            if queue.front() == Some(&seq) {
                queue.pop_front();
            }
        }
    }

    fn finish_worker(&self) {
        self.enqueue_closed.store(true, Ordering::Release);
        self.lease_released.store(true, Ordering::Release);
    }

    /// Mirrors `enqueue`: refuse after facade/worker completion, re-check after
    /// taking the queue lock, insert, release the lock, then notify the worker.
    fn enqueue(&self, seq: u32) -> bool {
        if self.enqueue_closed.load(Ordering::Acquire) {
            return false;
        }
        let mut queue = self.queue.lock().unwrap();
        if self.enqueue_closed.load(Ordering::Acquire) {
            return false;
        }
        queue.push_back(seq);
        drop(queue);
        self.wake.notify_one();
        true
    }

    /// The PRE-FIX `shutdown` signal shape: store the lifecycle flags and
    /// notify with no mutex bridge. Both operations can land inside the
    /// worker's check-to-park window (between its `worker_stop` load and its
    /// `wake.wait`), so the notify finds no parked waiter and the worker
    /// parks forever — the lost-wakeup deadlock the fix removed.
    fn shutdown_signal_prefix(&self) {
        self.enqueue_closed.store(true, Ordering::Release);
        self.worker_stop.store(true, Ordering::Release);
        self.wake.notify_all();
    }

    /// The FIXED `shutdown` signal shape (src/shipping_spool.rs `shutdown`):
    /// notify once, then acquire and release the queue mutex before notifying
    /// again. The bridge blocks until the worker either parks (wait releases
    /// the lock) or re-checks `worker_stop`, so the second notify always lands.
    fn shutdown_signal_fixed(&self) {
        self.enqueue_closed.store(true, Ordering::Release);
        self.worker_stop.store(true, Ordering::Release);
        self.wake.notify_all();
        drop(self.queue.lock().unwrap());
        self.wake.notify_all();
    }

    /// Mirrors an internal worker failure: delivery stops without the facade
    /// closing enqueue first. `finish_worker` must revoke enqueue before the
    /// worker-owned lease becomes available to a successor.
    fn worker_failure_signal(&self) {
        self.worker_stop.store(true, Ordering::Release);
        self.wake.notify_all();
        drop(self.queue.lock().unwrap());
        self.wake.notify_all();
    }

    /// Models the bounded `try_lock_for` shutdown branch. Loom has no modeled
    /// clock, so one non-blocking `try_lock` represents budget expiry while the
    /// queue mutex is unavailable; the lifecycle stores and first wake still
    /// happen before the bounded bridge attempt.
    fn shutdown_signal_bounded(&self) -> bool {
        self.enqueue_closed.store(true, Ordering::Release);
        self.worker_stop.store(true, Ordering::Release);
        self.wake.notify_all();
        let Ok(queue) = self.queue.try_lock() else {
            return false;
        };
        drop(queue);
        self.wake.notify_all();
        true
    }
}

/// Guards the inner (expected-to-abort) mode of the pre-fix model below
/// against unbounded self-recursion.
const PREFIX_SHAPE_INNER_ENV: &str = "ORACLEMCP_LOOM_PREFIX_SHAPE_INNER";

/// Would-have-caught regression model: the pre-fix `shutdown()` shape loses
/// the wakeup on some interleavings, stranding the worker in `wake.wait`
/// while `join` waits on the worker — loom's deadlock detector must find that
/// execution and report `deadlock; threads = [.., Blocked, ..]`.
///
/// Loom's deadlock panic double-panics in generator cleanup and ABORTS the
/// process (SIGABRT), which `#[should_panic]` cannot observe, so the model
/// runs in a child process re-executing this same test binary: the child must
/// die unsuccessfully AND print the deadlock report. If this test ever stops
/// failing-in-the-child, the model has lost the bug shape and must be
/// re-examined.
#[test]
fn prefix_shutdown_shape_strands_the_worker_via_lost_wakeup() {
    if std::env::var_os(PREFIX_SHAPE_INNER_ENV).is_some() {
        // Inner mode: explore the pre-fix shape; loom aborts on the lost
        // wakeup, which the parent asserts on.
        loom::model(|| {
            let spool = Arc::new(SpoolModel::new());
            let worker = {
                let spool = Arc::clone(&spool);
                thread::spawn(move || spool.run_worker())
            };
            spool.shutdown_signal_prefix();
            let _ = worker.join();
        });
        return;
    }
    let exe = std::env::current_exe().expect("test binary path");
    let output = std::process::Command::new(exe)
        .args([
            "--exact",
            "prefix_shutdown_shape_strands_the_worker_via_lost_wakeup",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PREFIX_SHAPE_INNER_ENV, "1")
        .output()
        .expect("spawn inner loom model process");
    assert!(
        !output.status.success(),
        "the pre-fix shutdown shape must deadlock under loom; a passing inner \
         run means the model lost the lost-wakeup bug shape"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("deadlock") || stderr.contains("deadlock"),
        "the inner failure must be loom's deadlock report, not an unrelated \
         error;\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// The shipped fix: bridging the store and the notify with the queue mutex
/// makes shutdown wake the worker on EVERY interleaving — no execution may
/// deadlock, and the worker always returns so `join` completes.
#[test]
fn fixed_shutdown_bridge_always_wakes_the_worker() {
    loom::model(|| {
        let spool = Arc::new(SpoolModel::new());
        let worker = {
            let spool = Arc::clone(&spool);
            thread::spawn(move || spool.run_worker())
        };
        spool.shutdown_signal_fixed();
        let delivered = worker.join().expect("worker exits cleanly");
        assert!(
            delivered.is_empty(),
            "nothing was enqueued, so nothing may be delivered"
        );
    });
}

/// Worker/shutdown/enqueue interaction: a record accepted by `enqueue` is
/// either delivered exactly once by the worker or left durably queued for
/// restart replay — never lost, never double-shipped — on every interleaving
/// of the worker with a shutdown racing right behind the enqueue.
#[test]
fn enqueued_record_is_delivered_once_or_left_queued_never_lost() {
    loom::model(|| {
        let spool = Arc::new(SpoolModel::new());
        let worker = {
            let spool = Arc::clone(&spool);
            thread::spawn(move || spool.run_worker())
        };
        let enqueuer = {
            let spool = Arc::clone(&spool);
            thread::spawn(move || spool.enqueue(1))
        };
        let shutdown = {
            let spool = Arc::clone(&spool);
            thread::spawn(move || spool.shutdown_signal_fixed())
        };
        let accepted = enqueuer.join().expect("enqueuer exits cleanly");
        shutdown.join().expect("shutdown exits cleanly");
        let delivered = worker.join().expect("worker exits cleanly");
        let queued: Vec<u32> = spool.queue.lock().unwrap().iter().copied().collect();
        let retained = delivered.len() + queued.len();
        if accepted {
            assert_eq!(
                retained, 1,
                "accepted record must be delivered exactly once or remain queued for \
                 restart replay (delivered={delivered:?}, queued={queued:?})"
            );
        } else {
            assert_eq!(
                retained, 0,
                "a refused record must neither ship nor enter the durable queue"
            );
        }
    });
}

/// Enqueue after shutdown is refused fail-closed (mirrors the `enqueue`
/// stopping gate): once the fixed shutdown signal has run, `enqueue` must
/// observe `stopping` and reject, and the worker still terminates.
#[test]
fn enqueue_after_shutdown_is_refused_and_worker_still_exits() {
    loom::model(|| {
        let spool = Arc::new(SpoolModel::new());
        let worker = {
            let spool = Arc::clone(&spool);
            thread::spawn(move || spool.run_worker())
        };
        spool.shutdown_signal_fixed();
        assert!(
            !spool.enqueue(2),
            "an enqueue sequenced after shutdown must be refused"
        );
        let delivered = worker.join().expect("worker exits cleanly");
        assert!(delivered.is_empty(), "refused records must never ship");
    });
}

/// A worker can stop itself after an integrity or destination failure without
/// facade shutdown running first. Its completion guard must revoke the old
/// facade's enqueue authority before the worker-owned filesystem lease is
/// released to a successor.
#[test]
fn worker_exit_revokes_enqueue_before_releasing_the_spool_lease() {
    loom::model(|| {
        let spool = Arc::new(SpoolModel::new());
        let worker = {
            let spool = Arc::clone(&spool);
            thread::spawn(move || spool.run_worker())
        };
        spool.worker_failure_signal();
        let delivered = worker.join().expect("worker exits cleanly");
        assert!(delivered.is_empty());
        assert!(
            spool.lease_released.load(Ordering::Acquire),
            "the worker releases its modeled filesystem lease"
        );
        assert!(
            spool.enqueue_closed.load(Ordering::Acquire),
            "enqueue authority is revoked before lease transfer"
        );
        assert!(
            !spool.enqueue(3),
            "the old facade cannot write after a successor can acquire the lease"
        );
    });
}

/// The real shutdown bridge waits only within `shutdown_timeout`. If that
/// budget expires while the queue mutex is held, shutdown reports timeout but
/// must already have closed enqueue and signalled the worker to stop.
#[test]
fn bounded_shutdown_bridge_times_out_with_lifecycle_already_closed() {
    loom::model(|| {
        let spool = SpoolModel::new();
        let queue = spool.queue.lock().unwrap();
        assert!(
            !spool.shutdown_signal_bounded(),
            "a held queue mutex exhausts the modeled bridge budget"
        );
        assert!(spool.enqueue_closed.load(Ordering::Acquire));
        assert!(spool.worker_stop.load(Ordering::Acquire));
        drop(queue);
    });
}
