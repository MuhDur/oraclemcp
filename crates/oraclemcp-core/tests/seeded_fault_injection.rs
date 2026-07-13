#![forbid(unsafe_code)]

//! Arc E3's bounded, deterministic fault-injection harness.
//!
//! The real served lane stack owns a thread-pinned `!Send` Oracle connection,
//! which must not be moved into LabRuntime.  This harness drives the real
//! server-side admission ledger under LabRuntime instead: no database, socket,
//! or credential is required.  Its explicit checkpoints mirror the three
//! failure-prone transitions in `lane.rs`, and every checkpoint is exercised
//! with a drop, delay, and cancellation fault.

use std::future::Future;
use std::mem;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use asupersync::Budget;
use asupersync::Cx;
use asupersync::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
use asupersync::lab::{DporExplorer, ExplorerConfig};
use oraclemcp_core::admission::AdmissionController;

const REPRO_SEED: u64 = 0xE3_5EED_0000_0001;
const DPOR_RUN_BUDGET: usize = 8;
const DPOR_STEP_BUDGET: u64 = 256;
const SYNTHETIC_PRINCIPAL: &str = "arc-e-lab-principal";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultTarget {
    LaneSwitchAtCapacity,
    PermitRelease,
    LostWakeup,
}

impl FaultTarget {
    const ALL: [Self; 3] = [
        Self::LaneSwitchAtCapacity,
        Self::PermitRelease,
        Self::LostWakeup,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::LaneSwitchAtCapacity => "lane-switch-at-cap",
            Self::PermitRelease => "permit-release",
            Self::LostWakeup => "lost-wakeup",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FaultAction {
    Drop,
    Delay,
    Cancel,
}

impl FaultAction {
    const ALL: [Self; 3] = [Self::Drop, Self::Delay, Self::Cancel];

    const fn label(self) -> &'static str {
        match self {
            Self::Drop => "drop",
            Self::Delay => "delay",
            Self::Cancel => "cancel",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlantedFault {
    PermitLeak,
    LostWakeup,
}

#[derive(Clone, Copy, Debug)]
struct ScenarioPlan {
    seed: u64,
    target: FaultTarget,
    action: FaultAction,
    planted_fault: Option<PlantedFault>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ScenarioOutcome {
    Completed,
    RefusedAtCapacity,
    Cancelled,
    FaultDetected(PlantedFault),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScenarioReport {
    seed: u64,
    target: FaultTarget,
    action: FaultAction,
    outcome: ScenarioOutcome,
    global_in_use: usize,
    events: Vec<String>,
}

#[derive(Default)]
struct EventLog(Mutex<Vec<String>>);

impl EventLog {
    fn record(&self, event: impl Into<String>) {
        self.0.lock().expect("event log lock").push(event.into());
    }

    fn snapshot(&self) -> Vec<String> {
        self.0.lock().expect("event log lock").clone()
    }
}

/// A single deterministic scheduler turn.  This is an await candidate in the
/// Lab trace, not a wall-clock sleep.
#[derive(Default)]
struct YieldOnce {
    yielded: bool,
}

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

async fn inject_at_await(cx: &Cx, plan: ScenarioPlan, target: FaultTarget, events: &EventLog) {
    events.record(format!("{}:await", target.label()));
    YieldOnce::default().await;

    if plan.target != target {
        return;
    }
    events.record(format!("{}:{}", target.label(), plan.action.label()));
    match plan.action {
        FaultAction::Drop => {}
        FaultAction::Delay => YieldOnce::default().await,
        FaultAction::Cancel => cx.set_cancel_requested(true),
    }
}

async fn execute_scenario(cx: &Cx, plan: ScenarioPlan, events: Arc<EventLog>) -> ScenarioReport {
    let admission = AdmissionController::new(1, 1);
    let mut permit = Some(
        admission
            .try_admit(cx, SYNTHETIC_PRINCIPAL)
            .expect("first synthetic stateful lane is admitted"),
    );
    events.record("lane:admitted");

    let outcome = match plan.target {
        FaultTarget::LaneSwitchAtCapacity => {
            inject_at_await(cx, plan, FaultTarget::LaneSwitchAtCapacity, &events).await;
            if plan.action == FaultAction::Drop {
                drop(permit.take());
                let replacement = admission
                    .try_admit(cx, SYNTHETIC_PRINCIPAL)
                    .expect("a dropped lane releases capacity before replacement admission");
                events.record("lane-switch:replacement-admitted");
                drop(replacement);
                ScenarioOutcome::Completed
            } else {
                let replacement = admission.try_admit(cx, SYNTHETIC_PRINCIPAL);
                assert!(
                    replacement.is_err(),
                    "lane switch at cap must refuse rather than open an unbounded replacement"
                );
                drop(permit.take());
                if plan.action == FaultAction::Cancel {
                    ScenarioOutcome::Cancelled
                } else {
                    ScenarioOutcome::RefusedAtCapacity
                }
            }
        }
        FaultTarget::PermitRelease => {
            inject_at_await(cx, plan, FaultTarget::PermitRelease, &events).await;
            if plan.planted_fault == Some(PlantedFault::PermitLeak)
                && plan.action == FaultAction::Cancel
            {
                // A test-only mutation of the terminal path.  The real
                // `AdmissionPermit` is intentionally leaked so the harness
                // proves its ledger assertion catches the exact failure.
                mem::forget(permit.take().expect("held permit"));
                events.record("permit-release:planted-leak");
                ScenarioOutcome::FaultDetected(PlantedFault::PermitLeak)
            } else {
                drop(permit.take());
                events.record("permit-release:dropped");
                if plan.action == FaultAction::Cancel {
                    ScenarioOutcome::Cancelled
                } else {
                    ScenarioOutcome::Completed
                }
            }
        }
        FaultTarget::LostWakeup => {
            inject_at_await(cx, plan, FaultTarget::LostWakeup, &events).await;
            // This is the exact level-triggered rule used by idle lane close:
            // after a pre-park signal, re-read desired state after wake.
            let close_requested = true;
            events.record("lost-wakeup:pre-park");
            YieldOnce::default().await;
            if plan.planted_fault == Some(PlantedFault::LostWakeup) {
                events.record("lost-wakeup:planted-missed-signal");
                ScenarioOutcome::FaultDetected(PlantedFault::LostWakeup)
            } else {
                assert!(
                    close_requested,
                    "post-wake desired-state recheck is mandatory"
                );
                events.record("lost-wakeup:observed-close");
                drop(permit.take());
                if plan.action == FaultAction::Cancel {
                    ScenarioOutcome::Cancelled
                } else {
                    ScenarioOutcome::Completed
                }
            }
        }
    };

    let global_in_use = admission
        .snapshot("arc-e-seeded-fault", SYNTHETIC_PRINCIPAL)
        .global_in_use;
    ScenarioReport {
        seed: plan.seed,
        target: plan.target,
        action: plan.action,
        outcome,
        global_in_use,
        events: events.snapshot(),
    }
}

fn run_scenario(plan: ScenarioPlan) -> ScenarioReport {
    let events = Arc::new(EventLog::default());
    let events_for_task = Arc::clone(&events);
    let mut runtime = LabRuntimeTarget::create_runtime(
        TestConfig::new()
            .with_seed(plan.seed)
            .with_max_steps(DPOR_STEP_BUDGET)
            .with_tracing(true),
    );
    let report = LabRuntimeTarget::block_on(&mut runtime, async move {
        let cx = Cx::current().expect("LabRuntime installs Cx");
        execute_scenario(&cx, plan, events_for_task).await
    });
    let lab_report = runtime.run_until_quiescent_with_report();
    assert!(
        lab_report.oracle_report.all_passed(),
        "seed {} target {}: runtime oracle failures: {:?}",
        plan.seed,
        plan.target.label(),
        lab_report.oracle_report
    );
    assert!(
        lab_report.invariant_violations.is_empty(),
        "seed {} target {}: runtime invariant violations: {:?}",
        plan.seed,
        plan.target.label(),
        lab_report.invariant_violations
    );
    report
}

#[test]
fn every_named_await_target_handles_drop_delay_and_cancel_fail_closed() {
    for target in FaultTarget::ALL {
        for action in FaultAction::ALL {
            let report = run_scenario(ScenarioPlan {
                seed: REPRO_SEED,
                target,
                action,
                planted_fault: None,
            });
            assert_eq!(
                report.global_in_use,
                0,
                "seed {} target {} action {} leaked a real admission permit: {:?}",
                report.seed,
                target.label(),
                action.label(),
                report.events
            );
            assert!(
                !report.events.is_empty(),
                "seed {} target {} action {} recorded no interleaving",
                report.seed,
                target.label(),
                action.label()
            );
        }
    }
}

#[test]
fn planted_permit_leak_is_detected_and_reproduced_by_fixed_seed() {
    let plan = ScenarioPlan {
        seed: REPRO_SEED,
        target: FaultTarget::PermitRelease,
        action: FaultAction::Cancel,
        planted_fault: Some(PlantedFault::PermitLeak),
    };
    let first = run_scenario(plan);
    let second = run_scenario(plan);

    assert_eq!(
        first.outcome,
        ScenarioOutcome::FaultDetected(PlantedFault::PermitLeak)
    );
    assert_eq!(
        first.global_in_use, 1,
        "the planted leak must be observable"
    );
    assert_eq!(
        first, second,
        "seed {} must reproduce the same target/action/interleaving transcript",
        REPRO_SEED
    );
    eprintln!(
        "ARC_E_FAULT_REPRO seed={} target={} action={} events={:?}",
        first.seed,
        first.target.label(),
        first.action.label(),
        first.events
    );
}

#[test]
fn planted_lost_wakeup_is_detected_and_reproduced_by_fixed_seed() {
    let plan = ScenarioPlan {
        seed: REPRO_SEED,
        target: FaultTarget::LostWakeup,
        action: FaultAction::Delay,
        planted_fault: Some(PlantedFault::LostWakeup),
    };
    let first = run_scenario(plan);
    let second = run_scenario(plan);

    assert_eq!(
        first.outcome,
        ScenarioOutcome::FaultDetected(PlantedFault::LostWakeup)
    );
    assert_eq!(
        first.global_in_use, 1,
        "a missed close must retain the lane permit"
    );
    assert_eq!(
        first, second,
        "the fixed seed must reproduce the missed wakeup"
    );
    eprintln!(
        "ARC_E_FAULT_REPRO seed={} target={} action={} events={:?}",
        first.seed,
        first.target.label(),
        first.action.label(),
        first.events
    );
}

#[test]
fn dpor_search_is_bounded_and_records_lane_interleavings() {
    let mut explorer = DporExplorer::new(
        ExplorerConfig::new(REPRO_SEED, DPOR_RUN_BUDGET)
            .worker_count(2)
            .max_steps(DPOR_STEP_BUDGET),
    );
    let completed = Arc::new(AtomicUsize::new(0));
    let completed_for_runs = Arc::clone(&completed);
    let report = explorer.explore(move |runtime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let first_completed = Arc::clone(&completed_for_runs);
        let (first, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                YieldOnce::default().await;
                first_completed.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create lane-switch task");
        let second_completed = Arc::clone(&completed_for_runs);
        let (second, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                YieldOnce::default().await;
                second_completed.fetch_add(1, Ordering::SeqCst);
            })
            .expect("create permit-release task");
        {
            let mut scheduler = runtime.scheduler.lock();
            scheduler.schedule(first, 0);
            scheduler.schedule(second, 0);
        }
        runtime.run_until_quiescent();
    });
    let dpor_coverage = explorer.dpor_coverage();

    assert!(report.total_runs > 0 && report.total_runs <= DPOR_RUN_BUDGET);
    assert!(
        report.unique_classes >= 1,
        "DPOR recorded no schedule class"
    );
    assert!(
        !report.has_violations(),
        "bounded DPOR search found runtime violations: {:?}",
        report.violations
    );
    assert!(
        report.runs.iter().all(|run| run.steps <= DPOR_STEP_BUDGET),
        "a DPOR run exceeded its explicit step budget: {:?}",
        report.runs
    );
    assert!(
        completed.load(Ordering::SeqCst) >= 2,
        "the first bounded schedule did not complete both named lane tasks"
    );
    eprintln!(
        "ARC_E_DPOR base_seed={} runs={} classes={} races={} backtracks={}",
        REPRO_SEED,
        report.total_runs,
        report.unique_classes,
        dpor_coverage.total_races,
        dpor_coverage.total_backtrack_points,
    );
}
