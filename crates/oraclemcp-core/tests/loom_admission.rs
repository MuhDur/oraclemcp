//! Loom model checks for the admission permit/promotion accounting
//! (bead oraclemcp-eng-program-bp8ia.9.6, H6).
//!
//! Run (nightly Tier 2, not part of ordinary `cargo test`):
//!
//! ```text
//! RUSTFLAGS="--cfg loom" cargo +nightly-2026-05-11 test -p oraclemcp-core \
//!     --test loom_admission
//! ```
//!
//! Optionally bound exploration with `LOOM_MAX_PREEMPTIONS=3` (loom reads the
//! env var); these models are small enough to run exhaustively in well under a
//! second each.
//!
//! ## Why a mirror model
//!
//! `AdmissionController` (src/admission.rs) synchronizes with
//! `parking_lot::{Mutex, Condvar}`, which loom cannot instrument, so these
//! models mirror the exact accounting skeleton with loom primitives:
//!
//! - [`AdmissionModel::try_admit`] mirrors `try_admit` +
//!   `subject_can_admit_locked` + `admit_regular_locked`: the capacity check
//!   and the counter increments happen atomically under ONE critical section.
//! - [`AdmissionModel::release_regular`] mirrors `Drop for AdmissionPermit`
//!   (Regular arm): decrement under the lock, remove the idle per-agent entry,
//!   release the lock, then `notify_all`.
//! - [`AdmissionModel::try_admit_control_probe`] /
//!   [`AdmissionModel::promote`] / [`AdmissionModel::release_reserved`]
//!   mirror `try_admit_control_probe`, `promote_control_probe`, and the
//!   reserved `Drop` arms.
//! - [`AdmissionModel::try_admit_toctou_bug`] is a deliberately INJECTED
//!   ordering bug — the same check and admit split across two critical
//!   sections — proving these models fail loudly when the
//!   check-and-admit-atomically shape is broken (H6 acceptance:
//!   "would fail on an injected ordering bug").
//! - [`switch_at_capacity_preserves_the_held_lane_then_retries`] pins the
//!   switch-at-capacity contract: a replacement admission is refused without
//!   mutating the held lane's accounting, then succeeds after that permit is
//!   released.
//!
//! If the production skeleton changes shape, update the mirror in the same
//! commit; the model is only as honest as its correspondence to the source.

#![cfg(loom)]

use std::collections::HashMap;

use loom::sync::{Arc, Condvar, Mutex};
use loom::thread;

/// Reserved-class targets a control probe may be promoted to (mirrors the
/// promotable subset of `AdmissionClass` in src/admission.rs).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Promoted {
    Operator,
    Doctor,
}

/// Mirror of `AdmissionState`: every counter the production ledger tracks for
/// the paths under test.
#[derive(Default)]
struct ModelState {
    global_in_use: usize,
    regular_in_use: usize,
    operator_in_use: usize,
    doctor_in_use: usize,
    control_probes_in_use: usize,
    agents: HashMap<&'static str, usize>,
}

/// Mirror of `AdmissionInner`'s capacity configuration + synchronized state.
struct AdmissionModel {
    global_cap: usize,
    regular_global_cap: usize,
    operator_reserved: usize,
    doctor_reserved: usize,
    per_agent_cap: usize,
    state: Mutex<ModelState>,
    changed: Condvar,
}

impl AdmissionModel {
    fn new(
        global_cap: usize,
        per_agent_cap: usize,
        operator_reserved: usize,
        doctor_reserved: usize,
    ) -> Self {
        // Mirrors `with_reserved_and_wait`'s cap derivation.
        let operator_reserved = operator_reserved.min(global_cap);
        let doctor_reserved = doctor_reserved.min(global_cap - operator_reserved);
        Self {
            global_cap,
            regular_global_cap: global_cap - operator_reserved - doctor_reserved,
            operator_reserved,
            doctor_reserved,
            per_agent_cap,
            state: Mutex::new(ModelState::default()),
            changed: Condvar::new(),
        }
    }

    /// Assert every ceiling the production ledger promises. Called under the
    /// state lock after each mutation so ANY interleaving that overshoots a
    /// cap fails the model immediately.
    fn assert_caps(&self, state: &ModelState) {
        assert!(
            state.global_in_use <= self.global_cap,
            "global permits exceed global_cap"
        );
        assert!(
            state.regular_in_use <= self.regular_global_cap,
            "regular permits exceed the cap"
        );
        assert!(
            state.operator_in_use <= self.operator_reserved,
            "operator permits exceed the reserve"
        );
        assert!(
            state.doctor_in_use <= self.doctor_reserved,
            "doctor permits exceed the reserve"
        );
        assert!(
            state.control_probes_in_use
                <= usize::from(self.operator_reserved + self.doctor_reserved > 0),
            "more than one concurrent pre-auth control probe"
        );
        for (agent, held) in &state.agents {
            assert!(
                *held <= self.per_agent_cap,
                "agent {agent} exceeds the per-agent cap"
            );
        }
    }

    /// Mirrors `try_admit` (`subject_can_admit_locked` + `admit_regular_locked`):
    /// check and admit atomically under one critical section.
    fn try_admit(&self, agent: &'static str) -> bool {
        let mut state = self.state.lock().unwrap();
        let can_admit = state.global_in_use < self.regular_global_cap
            && state.agents.get(agent).copied().unwrap_or(0) < self.per_agent_cap;
        if !can_admit {
            return false;
        }
        state.global_in_use += 1;
        state.regular_in_use += 1;
        *state.agents.entry(agent).or_insert(0) += 1;
        self.assert_caps(&state);
        true
    }

    /// INJECTED ORDERING BUG (never the production shape): the capacity check
    /// and the admit are split across two critical sections, re-creating the
    /// TOCTOU race `try_admit` prevents by holding one lock across both.
    fn try_admit_toctou_bug(&self, agent: &'static str) -> bool {
        {
            let state = self.state.lock().unwrap();
            let can_admit = state.global_in_use < self.regular_global_cap
                && state.agents.get(agent).copied().unwrap_or(0) < self.per_agent_cap;
            if !can_admit {
                return false;
            }
        }
        // BUG WINDOW: another thread can pass the same check here.
        let mut state = self.state.lock().unwrap();
        state.global_in_use += 1;
        state.regular_in_use += 1;
        *state.agents.entry(agent).or_insert(0) += 1;
        self.assert_caps(&state);
        true
    }

    /// Mirrors `Drop for AdmissionPermit` (Regular arm): decrement under the
    /// lock, reclaim the idle per-agent entry, unlock, `notify_all`.
    fn release_regular(&self, agent: &'static str) {
        let mut state = self.state.lock().unwrap();
        state.global_in_use = state.global_in_use.saturating_sub(1);
        state.regular_in_use = state.regular_in_use.saturating_sub(1);
        match state.agents.get_mut(agent) {
            Some(count) if *count > 1 => *count -= 1,
            Some(_) => {
                state.agents.remove(agent);
            }
            None => {}
        }
        drop(state);
        self.changed.notify_all();
    }

    /// Mirrors `try_admit_control_probe` + `admit_reserved_locked`.
    fn try_admit_control_probe(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        let reserved_cap = self.operator_reserved + self.doctor_reserved;
        let reserved_in_use =
            state.operator_in_use + state.doctor_in_use + state.control_probes_in_use;
        if state.global_in_use >= self.global_cap
            || reserved_in_use >= reserved_cap
            || state.control_probes_in_use >= usize::from(reserved_cap > 0)
        {
            return false;
        }
        state.global_in_use += 1;
        state.control_probes_in_use += 1;
        self.assert_caps(&state);
        true
    }

    /// Mirrors `promote_control_probe`: swap a held probe slot for an exact
    /// reserved class atomically under one critical section.
    fn promote(&self, target: Promoted) -> bool {
        let mut state = self.state.lock().unwrap();
        let available = match target {
            Promoted::Operator => state.operator_in_use < self.operator_reserved,
            Promoted::Doctor => state.doctor_in_use < self.doctor_reserved,
        };
        if !available {
            return false;
        }
        state.control_probes_in_use = state.control_probes_in_use.saturating_sub(1);
        match target {
            Promoted::Operator => state.operator_in_use += 1,
            Promoted::Doctor => state.doctor_in_use += 1,
        }
        self.assert_caps(&state);
        true
    }

    /// Mirrors `Drop for AdmissionPermit` (ControlProbe / promoted arms).
    fn release_reserved(&self, class: Option<Promoted>) {
        let mut state = self.state.lock().unwrap();
        state.global_in_use = state.global_in_use.saturating_sub(1);
        match class {
            None => {
                state.control_probes_in_use = state.control_probes_in_use.saturating_sub(1);
            }
            Some(Promoted::Operator) => {
                state.operator_in_use = state.operator_in_use.saturating_sub(1);
            }
            Some(Promoted::Doctor) => {
                state.doctor_in_use = state.doctor_in_use.saturating_sub(1);
            }
        }
        drop(state);
        self.changed.notify_all();
    }

    /// The leak-freedom postcondition: after every permit is dropped, all
    /// counters are zero and the per-agent ledger is fully reclaimed.
    fn assert_fully_released(&self) {
        let state = self.state.lock().unwrap();
        assert_eq!(state.global_in_use, 0, "global permits leaked");
        assert_eq!(state.regular_in_use, 0, "regular permits leaked");
        assert_eq!(state.operator_in_use, 0, "operator permits leaked");
        assert_eq!(state.doctor_in_use, 0, "doctor permits leaked");
        assert_eq!(state.control_probes_in_use, 0, "control probes leaked");
        assert!(
            state.agents.is_empty(),
            "idle per-agent ledger entries must be reclaimed"
        );
    }

    /// Assert the exact regular-ledger state while a lane remains held. This
    /// makes a refused switch observable: it must not release, replace, or
    /// duplicate the old lane's permit as a side effect.
    fn assert_one_regular_held_by(&self, agent: &'static str) {
        let state = self.state.lock().unwrap();
        assert_eq!(state.global_in_use, 1, "held lane lost its global permit");
        assert_eq!(state.regular_in_use, 1, "held lane lost its regular permit");
        assert_eq!(
            state.agents.get(agent),
            Some(&1),
            "held lane's subject accounting changed"
        );
        assert_eq!(state.agents.len(), 1, "refused switch mutated the ledger");
        self.assert_caps(&state);
    }
}

/// Permit-leak model: two subjects hammer a one-slot regular pool. On every
/// interleaving at most one permit is held at a time and after both threads
/// finish every counter is back to zero with the per-agent map reclaimed.
#[test]
fn regular_permits_never_exceed_caps_and_always_return() {
    loom::model(|| {
        let model = Arc::new(AdmissionModel::new(1, 1, 0, 0));
        let contenders: Vec<_> = ["subject-a", "subject-b"]
            .into_iter()
            .map(|agent| {
                let model = Arc::clone(&model);
                thread::spawn(move || {
                    let admitted = model.try_admit(agent);
                    if admitted {
                        model.release_regular(agent);
                    }
                    admitted
                })
            })
            .collect();
        let admitted: Vec<bool> = contenders
            .into_iter()
            .map(|handle| handle.join().expect("contender exits cleanly"))
            .collect();
        assert!(
            admitted.iter().any(|&ok| ok),
            "a one-slot pool must admit at least one of two sequential-or-racing subjects"
        );
        model.assert_fully_released();
    });
}

/// Switch-at-capacity model: the old lane keeps its permit while a replacement
/// admission races at the one-slot ceiling. The replacement must be refused
/// without mutating that old lane's ledger entry; after the old permit drops,
/// the same replacement admission succeeds and is itself fully returned.
#[test]
fn switch_at_capacity_preserves_the_held_lane_then_retries() {
    loom::model(|| {
        let model = Arc::new(AdmissionModel::new(1, 1, 0, 0));
        assert!(model.try_admit("subject-a"), "old lane acquires the slot");

        let replacement = {
            let model = Arc::clone(&model);
            thread::spawn(move || model.try_admit("subject-a"))
        };
        assert!(
            !replacement.join().expect("replacement exits cleanly"),
            "replacement must refuse while the old lane holds the cap"
        );
        model.assert_one_regular_held_by("subject-a");

        model.release_regular("subject-a");
        assert!(
            model.try_admit("subject-a"),
            "replacement admits after the old lane releases capacity"
        );
        model.release_regular("subject-a");
        model.assert_fully_released();
    });
}

/// Injected-bug detector (H6 acceptance): splitting the capacity check and the
/// admit across two critical sections re-opens the TOCTOU window, and loom
/// must find the interleaving where both subjects pass the one-slot check and
/// the cap assertion fires. If this test ever stops panicking, the model has
/// lost its power to catch the ordering-bug class.
#[test]
#[should_panic(expected = "global permits exceed global_cap")]
fn injected_toctou_admit_overshoots_the_cap() {
    loom::model(|| {
        let model = Arc::new(AdmissionModel::new(1, 1, 0, 0));
        let contenders: Vec<_> = ["subject-a", "subject-b"]
            .into_iter()
            .map(|agent| {
                let model = Arc::clone(&model);
                thread::spawn(move || {
                    if model.try_admit_toctou_bug(agent) {
                        model.release_regular(agent);
                    }
                })
            })
            .collect();
        for handle in contenders {
            handle.join().expect("contender exits cleanly");
        }
        model.assert_fully_released();
    });
}

/// Control-probe promotion accounting: two threads race the single pre-auth
/// probe slot and promote toward different reserved classes. On every
/// interleaving the reserved ceilings hold (asserted inside each mutation),
/// at most one probe exists at a time, and everything is released with no
/// counter left behind.
#[test]
fn control_probe_promotion_preserves_reserved_accounting() {
    loom::model(|| {
        let model = Arc::new(AdmissionModel::new(4, 1, 1, 1));
        let racers: Vec<_> = [Promoted::Operator, Promoted::Doctor]
            .into_iter()
            .map(|target| {
                let model = Arc::clone(&model);
                thread::spawn(move || {
                    if !model.try_admit_control_probe() {
                        return;
                    }
                    if model.promote(target) {
                        model.release_reserved(Some(target));
                    } else {
                        model.release_reserved(None);
                    }
                })
            })
            .collect();
        for handle in racers {
            handle.join().expect("racer exits cleanly");
        }
        model.assert_fully_released();
    });
}
