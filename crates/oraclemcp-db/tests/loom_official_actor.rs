//! Loom mirror of the official-driver actor lifecycle and connect guard
//! (train-0.12 bead .11.10).
//!
//! Run (nightly Tier C):
//!
//! LOOM_MAX_PREEMPTIONS=3 RUSTFLAGS="--cfg loom" \
//!   cargo +nightly-2026-05-11 test -p oraclemcp-db \
//!   --test loom_official_actor --release -- --test-threads=1
//!
//! Production uses asupersync mpsc/oneshot channels and std::sync::Mutex,
//! which Loom cannot instrument. This model mirrors their synchronization
//! skeleton with Loom primitives. The operation-admission event is the
//! run_actor_loop ACTIVE status re-check immediately before execute; counters
//! observe whether admission happened after quarantine.
//!
//! Source correspondence (re-derive with rg -n in src/oracledb_actor.rs):
//! - BlockingConnectionActor::call_inner: ActorState::require_active, one-slot
//!   command send, reply receive, caller-side quarantine after cancellation,
//!   and Continue acknowledgement (~lines 289-392).
//! - run_actor_loop: command receive, ACTIVE re-check before execute, reply
//!   send, completion-ack wait, and loop to the next command (~lines 579-680).
//!   The second-command model exercises that loop's re-check after the first
//!   command's Continue acknowledgement.
//! - ActorState::quarantine and close: ACTIVE -> QUARANTINED -> CLOSED
//!   transitions (~lines 480-525).
//! - OfficialConnectGuard::acquire and OfficialConnectSlot::drop: the
//!   capacity-two admission bound and permit transfer into actor ownership
//!   (~lines 57-112).
//! - completion_ack_wait: deadline or 250 ms grace (~lines 686-710); the
//!   bounded-join model represents timeout as an explicit event because Loom
//!   has no clock.
//!
//! loom_injected_second_command_without_status_recheck_panics removes the
//! mirror's second-iteration status re-check. Loom must find that the canceled
//! caller quarantines before the queued second command is admitted.
//!
//! If production's synchronization skeleton changes, update this mirror in
//! the same commit. Passing the mirror does not prove production still matches
//! it beyond this documented source correspondence.

#![cfg(loom)]

use loom::sync::atomic::{AtomicUsize, Ordering};
use loom::sync::{Arc, Condvar, Mutex};
use loom::thread;

const ACTIVE: usize = 0;
const QUARANTINED: usize = 1;
const CLOSED: usize = 2;
const COMMANDS: usize = 2;
const CONNECT_GUARD_CAPACITY: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ack {
    Continue,
    Quarantine,
}

#[derive(Default)]
struct Handshake {
    command_pending: [bool; COMMANDS],
    actor_started: [bool; COMMANDS],
    receiver_live: [bool; COMMANDS],
    reply_ready: [bool; COMMANDS],
    cancelled: [bool; COMMANDS],
    acknowledgement: [Option<Ack>; COMMANDS],
    timeout_fired: [bool; COMMANDS],
    caller_returned: [bool; COMMANDS],
    actor_stopped: bool,
}

struct ActorModel {
    state: AtomicUsize,
    handshake: Mutex<Handshake>,
    changed: Condvar,
    operations: AtomicUsize,
    operations_admitted_after_quarantine: AtomicUsize,
    refused_commands: AtomicUsize,
    resource_drops: AtomicUsize,
}

impl ActorModel {
    fn new() -> Self {
        let mut handshake = Handshake::default();
        handshake.command_pending[0] = true;
        handshake.receiver_live[0] = true;
        Self {
            state: AtomicUsize::new(ACTIVE),
            handshake: Mutex::new(handshake),
            changed: Condvar::new(),
            operations: AtomicUsize::new(0),
            operations_admitted_after_quarantine: AtomicUsize::new(0),
            refused_commands: AtomicUsize::new(0),
            resource_drops: AtomicUsize::new(0),
        }
    }

    /// Mirrors receive -> status-check -> execute -> reply -> ack in production.
    /// The status load is the model's operation-admission linearization point.
    fn run_actor_loop(&self, command_count: usize, status_recheck: bool) {
        for command in 0..command_count {
            let mut handshake = self.handshake.lock().unwrap();
            while !handshake.command_pending[command] && !handshake.actor_stopped {
                handshake = self.changed.wait(handshake).unwrap();
            }
            if handshake.actor_stopped {
                break;
            }
            handshake.actor_started[command] = true;
            self.changed.notify_all();
            drop(handshake);

            // Represents blocking work outside the mailbox/handshake lock.
            thread::yield_now();

            let admitted_state = self.state.load(Ordering::Acquire);
            if status_recheck && admitted_state != ACTIVE {
                self.refused_commands.fetch_add(1, Ordering::Relaxed);
                let mut handshake = self.handshake.lock().unwrap();
                handshake.actor_stopped = true;
                self.changed.notify_all();
                break;
            }
            if admitted_state != ACTIVE {
                self.operations_admitted_after_quarantine
                    .fetch_add(1, Ordering::Relaxed);
            }
            let mut handshake = self.handshake.lock().unwrap();
            if !handshake.receiver_live[command] {
                self.refused_commands.fetch_add(1, Ordering::Relaxed);
                self.quarantine();
                handshake.actor_stopped = true;
                self.changed.notify_all();
                break;
            }

            self.operations.fetch_add(1, Ordering::Relaxed);
            handshake.reply_ready[command] = true;
            self.changed.notify_all();

            while handshake.acknowledgement[command].is_none()
                && !handshake.timeout_fired[command]
                && self.state.load(Ordering::Acquire) == ACTIVE
            {
                handshake = self.changed.wait(handshake).unwrap();
            }
            match handshake.acknowledgement[command] {
                Some(Ack::Continue)
                    if !handshake.cancelled[command] && !handshake.timeout_fired[command] =>
                {
                    // Caller-return state is written by the caller thread.
                }
                _ => {
                    self.quarantine();
                    handshake.actor_stopped = true;
                    self.changed.notify_all();
                    break;
                }
            }
        }

        self.retire();
        self.changed.notify_all();
    }

    fn quarantine(&self) {
        let _ =
            self.state
                .compare_exchange(ACTIVE, QUARANTINED, Ordering::AcqRel, Ordering::Acquire);
    }

    fn retire(&self) {
        if self.state.load(Ordering::Acquire) == ACTIVE {
            self.state.store(CLOSED, Ordering::Release);
        }
        self.resource_drops.fetch_add(1, Ordering::Relaxed);
    }
}

/// Caller cancellation races reply completion. Exactly one valid outcome
/// wins: the caller returns after Continue, or it quarantines the actor.
#[test]
fn loom_actor_cancel_vs_completion_no_lost_wakeup() {
    loom::model(|| {
        let actor = Arc::new(ActorModel::new());
        let actor_thread = {
            let actor = Arc::clone(&actor);
            thread::spawn(move || actor.run_actor_loop(1, true))
        };
        let caller = {
            let actor = Arc::clone(&actor);
            thread::spawn(move || {
                let mut handshake = actor.handshake.lock().unwrap();
                while !handshake.reply_ready[0] && actor.state.load(Ordering::Acquire) == ACTIVE {
                    handshake = actor.changed.wait(handshake).unwrap();
                }
                if handshake.reply_ready[0] && !handshake.cancelled[0] {
                    handshake.acknowledgement[0] = Some(Ack::Continue);
                    handshake.caller_returned[0] = true;
                    actor.changed.notify_all();
                }
            })
        };
        let canceller = {
            let actor = Arc::clone(&actor);
            thread::spawn(move || {
                thread::yield_now();
                let mut handshake = actor.handshake.lock().unwrap();
                if handshake.acknowledgement[0] != Some(Ack::Continue) {
                    handshake.cancelled[0] = true;
                    handshake.receiver_live[0] = false;
                    if handshake.reply_ready[0] {
                        handshake.acknowledgement[0] = Some(Ack::Quarantine);
                    }
                    actor.quarantine();
                    actor.changed.notify_all();
                }
            })
        };

        actor_thread.join().expect("actor retires");
        caller.join().expect("caller leaves the reply boundary");
        canceller.join().expect("cancellation race completes");

        let handshake = actor.handshake.lock().unwrap();
        let caller_returned = handshake.caller_returned[0];
        let cancelled = handshake.cancelled[0];
        drop(handshake);
        let state = actor.state.load(Ordering::Acquire);
        assert!(
            (caller_returned && state == CLOSED && !cancelled)
                || (!caller_returned && state == QUARANTINED && cancelled),
            "terminal caller and actor states must agree"
        );
        assert_eq!(
            actor
                .operations_admitted_after_quarantine
                .load(Ordering::Acquire),
            0,
            "no operation is admitted after quarantine"
        );
        assert_eq!(actor.resource_drops.load(Ordering::Acquire), 1);
    });
}

/// A second queued command reaches the loop after caller cancellation. The
/// ACTIVE re-check refuses it, and a cancelled caller never acknowledges it.
#[test]
fn loom_actor_no_reuse_after_quarantine() {
    loom::model(|| {
        let actor = Arc::new(ActorModel::new());
        let actor_thread = {
            let actor = Arc::clone(&actor);
            thread::spawn(move || actor.run_actor_loop(COMMANDS, true))
        };
        let caller = {
            let actor = Arc::clone(&actor);
            thread::spawn(move || {
                let mut handshake = actor.handshake.lock().unwrap();
                while !handshake.reply_ready[0] {
                    handshake = actor.changed.wait(handshake).unwrap();
                }

                // First completion is acknowledged; command two is pending in
                // the one-slot mailbox before its caller cancels.
                handshake.acknowledgement[0] = Some(Ack::Continue);
                handshake.caller_returned[0] = true;
                handshake.command_pending[1] = true;
                handshake.receiver_live[1] = true;
                actor.changed.notify_all();
                drop(handshake);

                thread::yield_now();

                // Mirrors call_inner's caller-side quarantine after cancel.
                let mut handshake = actor.handshake.lock().unwrap();
                handshake.cancelled[1] = true;
                handshake.receiver_live[1] = false;
                actor.quarantine();
                actor.changed.notify_all();
            })
        };

        actor_thread.join().expect("quarantined actor retires");
        caller.join().expect("cancelled caller exits");

        let handshake = actor.handshake.lock().unwrap();
        assert!(
            handshake.actor_started[1],
            "second command reaches the loop"
        );
        assert!(
            handshake.acknowledgement[1] != Some(Ack::Continue),
            "a cancelled caller never receives Continue"
        );
        assert!(!handshake.caller_returned[1]);
        drop(handshake);
        assert_eq!(
            actor
                .operations_admitted_after_quarantine
                .load(Ordering::Acquire),
            0,
            "no operation executes after the second-command check sees quarantine"
        );
        let operations = actor.operations.load(Ordering::Acquire);
        let refused = actor.refused_commands.load(Ordering::Acquire);
        assert_eq!(
            operations + refused,
            2,
            "the first operation and queued second command each have one admission outcome"
        );
        assert_eq!(actor.resource_drops.load(Ordering::Acquire), 1);
    });
}

/// The completion wait's modeled timeout event retires the actor instead of
/// waiting indefinitely for an acknowledgement.
#[test]
fn loom_actor_join_bounded() {
    loom::model(|| {
        let actor = Arc::new(ActorModel::new());
        let actor_thread = {
            let actor = Arc::clone(&actor);
            thread::spawn(move || actor.run_actor_loop(1, true))
        };
        let stalled_caller = {
            let actor = Arc::clone(&actor);
            thread::spawn(move || {
                let mut handshake = actor.handshake.lock().unwrap();
                while !handshake.reply_ready[0] {
                    handshake = actor.changed.wait(handshake).unwrap();
                }
                handshake.timeout_fired[0] = true;
                actor.changed.notify_all();
            })
        };
        actor_thread.join().expect("timeout branch retires actor");
        stalled_caller
            .join()
            .expect("stalled caller releases the acknowledgement boundary");
        assert_eq!(actor.state.load(Ordering::Acquire), QUARANTINED);
        assert_eq!(actor.resource_drops.load(Ordering::Acquire), 1);
    });
}

#[derive(Default)]
struct ConnectGuardState {
    in_use: usize,
    waiting_acquirers: usize,
    max_in_use: usize,
    release_actors: bool,
}

struct ConnectGuardModel {
    state: Mutex<ConnectGuardState>,
    changed: Condvar,
}

struct ConnectSlot(Arc<ConnectGuardModel>);

impl ConnectGuardModel {
    fn new() -> Self {
        Self {
            state: Mutex::new(ConnectGuardState::default()),
            changed: Condvar::new(),
        }
    }

    fn acquire(guard: &Arc<Self>) -> ConnectSlot {
        let mut state = guard.state.lock().unwrap();
        let waited = state.in_use == CONNECT_GUARD_CAPACITY;
        if waited {
            state.waiting_acquirers += 1;
            state.release_actors = true;
            guard.changed.notify_all();
        }
        while state.in_use == CONNECT_GUARD_CAPACITY {
            state = guard.changed.wait(state).unwrap();
        }
        if waited {
            state.waiting_acquirers -= 1;
        }
        state.in_use += 1;
        state.max_in_use = state.max_in_use.max(state.in_use);
        guard.changed.notify_all();
        ConnectSlot(Arc::clone(guard))
    }
}

impl Drop for ConnectSlot {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap();
        assert!(state.in_use > 0, "connect guard slot released once");
        state.in_use -= 1;
        self.0.changed.notify_all();
    }
}

/// Three concurrent acquirers contend for two permits. A permit acquired on a
/// setup thread moves into an actor thread and returns only when it retires.
/// Local drops cover connect-error and spawn-failure setup paths.
#[test]
fn loom_connect_guard_slots_always_returned() {
    let mut builder = loom::model::Builder::new();
    builder.max_threads = 5;
    builder.check(|| {
        let guard = Arc::new(ConnectGuardModel::new());
        let transferred_slot = ConnectGuardModel::acquire(&guard);
        let transferred_guard = Arc::clone(&guard);
        let transferred_actor = thread::spawn(move || {
            let _actor_state = Arc::clone(&transferred_guard);
            drop(transferred_slot);
        });
        transferred_actor
            .join()
            .expect("connect permit transfers into actor thread");

        let acquirers: Vec<_> = (0..2)
            .map(|_| {
                let guard = Arc::clone(&guard);
                thread::spawn(move || {
                    let actor_slot = ConnectGuardModel::acquire(&guard);
                    let mut state = guard.state.lock().unwrap();
                    while !state.release_actors {
                        state = guard.changed.wait(state).unwrap();
                    }
                    drop(state);
                    drop(actor_slot);
                })
            })
            .collect();

        let mut state = guard.state.lock().unwrap();
        while state.in_use < CONNECT_GUARD_CAPACITY {
            state = guard.changed.wait(state).unwrap();
        }
        assert_eq!(state.in_use, CONNECT_GUARD_CAPACITY);
        drop(state);

        // This is the third acquire attempt. It waits at capacity two; the
        // guard wakes both permit-owning actor threads so their slots retire.
        let third_slot = ConnectGuardModel::acquire(&guard);
        drop(third_slot);

        for acquirer in acquirers {
            acquirer.join().expect("connect-actor permit retires");
        }

        let state = guard.state.lock().unwrap();
        assert_eq!(state.waiting_acquirers, 0);
        assert_eq!(state.max_in_use, CONNECT_GUARD_CAPACITY);
        assert_eq!(state.in_use, 0);
        drop(state);

        // These setup paths retain local ownership until publication or
        // failure cleanup; each returns its permit exactly once.
        let successful_connect_slot = ConnectGuardModel::acquire(&guard);
        drop(successful_connect_slot);
        assert_eq!(guard.state.lock().unwrap().in_use, 0);

        let failed_connect_slot = ConnectGuardModel::acquire(&guard);
        drop(failed_connect_slot);
        assert_eq!(guard.state.lock().unwrap().in_use, 0);

        let spawn_failure_slot = ConnectGuardModel::acquire(&guard);
        drop(spawn_failure_slot);
        assert_eq!(guard.state.lock().unwrap().in_use, 0);
    });
}

/// The planted bug is the actor model with the second-iteration status
/// re-check removed. Loom finds a canceled second command admitted afterward.
#[test]
#[should_panic(expected = "injected actor operation admitted after quarantine")]
fn loom_injected_second_command_without_status_recheck_panics() {
    loom::model(|| {
        let actor = Arc::new(ActorModel::new());
        let actor_thread = {
            let actor = Arc::clone(&actor);
            thread::spawn(move || actor.run_actor_loop(COMMANDS, false))
        };
        let caller = {
            let actor = Arc::clone(&actor);
            thread::spawn(move || {
                let mut handshake = actor.handshake.lock().unwrap();
                while !handshake.reply_ready[0] {
                    handshake = actor.changed.wait(handshake).unwrap();
                }
                handshake.acknowledgement[0] = Some(Ack::Continue);
                handshake.caller_returned[0] = true;
                handshake.command_pending[1] = true;
                handshake.receiver_live[1] = true;
                actor.changed.notify_all();
                drop(handshake);

                thread::yield_now();

                let mut handshake = actor.handshake.lock().unwrap();
                handshake.cancelled[1] = true;
                handshake.receiver_live[1] = false;
                actor.quarantine();
                actor.changed.notify_all();
            })
        };

        actor_thread.join().expect("buggy actor loop retires");
        caller.join().expect("caller cancellation completes");
        assert_eq!(
            actor
                .operations_admitted_after_quarantine
                .load(Ordering::Acquire),
            0,
            "injected actor operation admitted after quarantine"
        );
    });
}
