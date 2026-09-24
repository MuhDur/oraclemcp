//! Loom mirror of the official-driver actor lifecycle and connect guard
//! (train-0.12 bead .11.10).
//!
//! Run (nightly Tier C):
//!
//! ```text
//! LOOM_MAX_PREEMPTIONS=3 RUSTFLAGS="--cfg loom" \
//!   cargo +nightly-2026-05-11 test -p oraclemcp-db \
//!   --test loom_official_actor --release -- --test-threads=1
//! ```
//!
//! The production code uses asupersync mpsc/oneshot channels and
//! `std::sync::Mutex`, which Loom cannot instrument. This model mirrors the
//! synchronization skeleton with Loom atomics, a one-command mailbox state,
//! and a mutex/condition-variable completion acknowledgement:
//!
//! - `BlockingConnectionActor::call_inner` checks `ActorState::require_active`,
//!   admits one `ActorCommand::Call`, waits for its oneshot reply, performs the
//!   post-completion checkpoint, then sends Continue or Quarantine.
//! - `run_actor_loop` owns the resource, runs one blocking operation, sends
//!   the reply, and waits for the acknowledgement before another command can
//!   execute. A dropped reply or non-Continue acknowledgement quarantines and
//!   retires the actor.
//! - `ActorState::quarantine` changes ACTIVE to QUARANTINED once;
//!   `run_actor_thread` closes the terminal state after its loop exits.
//! - `OfficialConnectGuard::acquire` supplies a capacity-two permit. The slot
//!   moves to actor ownership while a native connect may be stuck; spawn
//!   failure, failed connect retirement, successful publication, or eventual
//!   retirement releases it.
//! - `completion_ack_wait` uses a deadline or a 250 ms grace. Loom has no
//!   clock, so the join model represents the timeout firing as an explicit
//!   event and checks that the actor exits after that bounded branch.
//! - `injected_reuse_after_cancel_bug` splits the active check from the actor
//!   use. Loom must find the cancellation in that gap.
//!
//! Source anchors (re-derive with `rg -n`):
//! `ACTOR_ACTIVE`/`ACTOR_QUARANTINED`/`ACTOR_CLOSED`,
//! `ACTOR_MAILBOX_CAPACITY`, `OFFICIAL_CONNECT_GUARD_CAPACITY`,
//! `OfficialConnectGuard::acquire`, `OfficialConnectSlot`,
//! `BlockingConnectionActor::call_inner`, `ActorCompletionAck`,
//! `ActorState::require_active`/`quarantine`/`close`, `run_actor_loop`, and
//! `completion_ack_wait` in `src/oracledb_actor.rs`.
//!
//! If the production synchronization skeleton changes, update this mirror in
//! the same commit. Passing the mirror does not prove that production still
//! matches it beyond the documented source correspondence.

#![cfg(loom)]

use loom::sync::atomic::{AtomicUsize, Ordering};
use loom::sync::{Arc, Condvar, Mutex};
use loom::thread;

const ACTIVE: usize = 0;
const QUARANTINED: usize = 1;
const CLOSED: usize = 2;
const CONNECT_GUARD_CAPACITY: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ack {
    Continue,
    Quarantine,
}

#[derive(Default)]
struct Handshake {
    command_pending: bool,
    actor_started: bool,
    receiver_live: bool,
    reply_ready: bool,
    cancelled: bool,
    acknowledgement: Option<Ack>,
    timeout_fired: bool,
    caller_returned: bool,
}

struct ActorModel {
    state: AtomicUsize,
    handshake: Mutex<Handshake>,
    changed: Condvar,
    operations: AtomicUsize,
    resource_drops: AtomicUsize,
}

impl ActorModel {
    fn new() -> Self {
        Self {
            state: AtomicUsize::new(ACTIVE),
            handshake: Mutex::new(Handshake {
                command_pending: true,
                receiver_live: true,
                ..Handshake::default()
            }),
            changed: Condvar::new(),
            operations: AtomicUsize::new(0),
            resource_drops: AtomicUsize::new(0),
        }
    }

    /// Mirrors one iteration of `run_actor_loop`, including reply delivery
    /// followed by the completion-ack boundary before actor reuse.
    fn run_one(&self) {
        let mut handshake = self.handshake.lock().unwrap();
        while !handshake.command_pending {
            handshake = self.changed.wait(handshake).unwrap();
        }
        handshake.actor_started = true;
        self.changed.notify_all();
        drop(handshake);

        // Represents the synchronous operation running outside the channel
        // state lock. Cancellation can win before its reply is published.
        thread::yield_now();

        let mut handshake = self.handshake.lock().unwrap();
        if self.state.load(Ordering::Acquire) != ACTIVE || !handshake.receiver_live {
            self.quarantine();
            self.retire();
            self.changed.notify_all();
            return;
        }
        self.operations.fetch_add(1, Ordering::Relaxed);
        handshake.reply_ready = true;
        self.changed.notify_all();

        while handshake.acknowledgement.is_none()
            && !handshake.timeout_fired
            && self.state.load(Ordering::Acquire) == ACTIVE
        {
            handshake = self.changed.wait(handshake).unwrap();
        }
        match handshake.acknowledgement {
            Some(Ack::Continue) if !handshake.cancelled && !handshake.timeout_fired => {
                handshake.caller_returned = true;
                self.state.store(CLOSED, Ordering::Release);
            }
            _ => self.quarantine(),
        }
        drop(handshake);
        self.retire();
        self.changed.notify_all();
    }

    fn quarantine(&self) {
        let _ =
            self.state
                .compare_exchange(ACTIVE, QUARANTINED, Ordering::AcqRel, Ordering::Acquire);
    }

    fn retire(&self) {
        self.resource_drops.fetch_add(1, Ordering::Relaxed);
        if self.state.load(Ordering::Acquire) == ACTIVE {
            self.state.store(CLOSED, Ordering::Release);
        }
    }
}

/// Caller cancellation races the actor's reply send. The only completed
/// outcomes are a successful return or quarantine; both cannot be lost.
#[test]
fn loom_actor_cancel_vs_completion_no_lost_wakeup() {
    loom::model(|| {
        let actor = Arc::new(ActorModel::new());
        let actor_thread = {
            let actor = Arc::clone(&actor);
            thread::spawn(move || actor.run_one())
        };
        let caller = {
            let actor = Arc::clone(&actor);
            thread::spawn(move || {
                let mut handshake = actor.handshake.lock().unwrap();
                while !handshake.reply_ready && actor.state.load(Ordering::Acquire) == ACTIVE {
                    handshake = actor.changed.wait(handshake).unwrap();
                }
                if handshake.reply_ready {
                    if handshake.cancelled {
                        handshake.acknowledgement = Some(Ack::Quarantine);
                    } else {
                        handshake.acknowledgement = Some(Ack::Continue);
                    }
                    actor.changed.notify_all();
                }
            })
        };
        let canceller = {
            let actor = Arc::clone(&actor);
            thread::spawn(move || {
                thread::yield_now();
                let mut handshake = actor.handshake.lock().unwrap();
                if handshake.acknowledgement != Some(Ack::Continue) {
                    handshake.cancelled = true;
                    handshake.receiver_live = false;
                    if handshake.reply_ready {
                        handshake.acknowledgement = Some(Ack::Quarantine);
                    }
                    actor.changed.notify_all();
                }
            })
        };

        actor_thread.join().expect("actor retires");
        caller.join().expect("caller leaves the reply boundary");
        canceller.join().expect("cancellation race completes");
        let handshake = actor.handshake.lock().unwrap();
        let returned = handshake.caller_returned;
        let quarantined = actor.state.load(Ordering::Acquire) == QUARANTINED;
        assert_ne!(returned, quarantined, "one terminal outcome must win");
        assert_eq!(actor.resource_drops.load(Ordering::Acquire), 1);
        assert!(actor.operations.load(Ordering::Acquire) <= 1);
    });
}

/// A quarantined actor refuses a later command and drops its resource once.
#[test]
fn loom_actor_no_reuse_after_quarantine() {
    loom::model(|| {
        let actor = Arc::new(ActorModel::new());
        {
            let mut handshake = actor.handshake.lock().unwrap();
            handshake.cancelled = true;
            handshake.receiver_live = false;
        }
        let actor_thread = {
            let actor = Arc::clone(&actor);
            thread::spawn(move || actor.run_one())
        };
        actor_thread.join().expect("quarantined actor retires");

        let accepted = actor.state.load(Ordering::Acquire) == ACTIVE;
        if accepted {
            actor.operations.fetch_add(1, Ordering::Relaxed);
        }
        assert!(!accepted, "quarantine must refuse mailbox reuse");
        assert_eq!(actor.operations.load(Ordering::Acquire), 0);
        assert_eq!(actor.resource_drops.load(Ordering::Acquire), 1);
    });
}

/// The completion wait's modeled timeout event retires the actor, so joining
/// does not wait on a live sender that never acknowledges its reply.
#[test]
fn loom_actor_join_bounded() {
    loom::model(|| {
        let actor = Arc::new(ActorModel::new());
        let actor_thread = {
            let actor = Arc::clone(&actor);
            thread::spawn(move || actor.run_one())
        };
        let stalled_caller = {
            let actor = Arc::clone(&actor);
            thread::spawn(move || {
                let mut handshake = actor.handshake.lock().unwrap();
                while !handshake.reply_ready {
                    handshake = actor.changed.wait(handshake).unwrap();
                }
                handshake.timeout_fired = true;
                actor.changed.notify_all();
            })
        };
        actor_thread.join().expect("timeout branch retires actor");
        stalled_caller
            .join()
            .expect("stalled caller releases the ack boundary");
        assert_eq!(actor.state.load(Ordering::Acquire), QUARANTINED);
        assert_eq!(actor.resource_drops.load(Ordering::Acquire), 1);
    });
}

struct ConnectGuardModel {
    in_use: AtomicUsize,
}

struct ConnectSlot(Arc<ConnectGuardModel>);

impl ConnectGuardModel {
    fn acquire(guard: &Arc<Self>) -> ConnectSlot {
        let previous = guard.in_use.fetch_add(1, Ordering::AcqRel);
        assert!(
            previous < CONNECT_GUARD_CAPACITY,
            "connect guard over-admitted"
        );
        ConnectSlot(Arc::clone(guard))
    }
}

impl Drop for ConnectSlot {
    fn drop(&mut self) {
        let previous = self.0.in_use.fetch_sub(1, Ordering::AcqRel);
        assert!(previous > 0, "connect guard slot released more than once");
    }
}

/// The guard slot returns on connect success, connect error/actor retirement,
/// spawn failure, and a cancelled caller whose stuck connect later retires.
#[test]
fn loom_connect_guard_slots_always_returned() {
    loom::model(|| {
        let guard = Arc::new(ConnectGuardModel {
            in_use: AtomicUsize::new(0),
        });

        // Successful setup releases the transient connect slot once the
        // established session has been published.
        drop(ConnectGuardModel::acquire(&guard));
        assert_eq!(guard.in_use.load(Ordering::Acquire), 0);

        // A connect error retains actor ownership until retirement.
        let failed_connect_slot = ConnectGuardModel::acquire(&guard);
        assert_eq!(guard.in_use.load(Ordering::Acquire), 1);
        drop(failed_connect_slot);
        assert_eq!(guard.in_use.load(Ordering::Acquire), 0);

        // Thread spawn failure leaves ownership local, so unwinding the setup
        // path releases the reserved slot.
        let spawn_failure_slot = ConnectGuardModel::acquire(&guard);
        drop(spawn_failure_slot);
        assert_eq!(guard.in_use.load(Ordering::Acquire), 0);

        // Cancellation cannot release a slot while the native connect is
        // stuck. The actor releases it only after its eventual retirement.
        let stuck_slot = ConnectGuardModel::acquire(&guard);
        let released = Arc::new(AtomicUsize::new(0));
        let release_gate = Arc::new((Mutex::new(false), Condvar::new()));
        let connect_actor = {
            let released = Arc::clone(&released);
            let release_gate = Arc::clone(&release_gate);
            thread::spawn(move || {
                let _owned_slot = stuck_slot;
                let (lock, changed) = &*release_gate;
                let mut retire = lock.lock().unwrap();
                while !*retire {
                    retire = changed.wait(retire).unwrap();
                }
                released.store(1, Ordering::Release);
            })
        };
        thread::yield_now();
        assert_eq!(guard.in_use.load(Ordering::Acquire), 1);
        let (lock, changed) = &*release_gate;
        *lock.lock().unwrap() = true;
        changed.notify_all();
        connect_actor
            .join()
            .expect("stuck connect eventually retires");
        assert_eq!(released.load(Ordering::Acquire), 1);
        assert_eq!(guard.in_use.load(Ordering::Acquire), 0);
    });
}

/// Injects the check/use split that would allow a quarantined physical session
/// to be reused after caller cancellation. Loom must find that ordering.
#[test]
#[should_panic(expected = "injected reuse after cancellation")]
fn loom_injected_reuse_after_cancel_bug_is_detected() {
    loom::model(|| {
        let state = Arc::new(AtomicUsize::new(ACTIVE));
        let actor = {
            let state = Arc::clone(&state);
            thread::spawn(move || {
                assert_eq!(state.load(Ordering::Acquire), ACTIVE);
                thread::yield_now();
                assert_eq!(
                    state.load(Ordering::Acquire),
                    ACTIVE,
                    "injected reuse after cancellation"
                );
            })
        };
        let canceller = {
            let state = Arc::clone(&state);
            thread::spawn(move || {
                thread::yield_now();
                state.store(QUARANTINED, Ordering::Release);
            })
        };
        let actor_result = actor.join();
        canceller.join().expect("quarantine transition completes");
        if let Err(panic) = actor_result {
            std::panic::resume_unwind(panic);
        }
    });
}
