//! Admission control & backpressure (plan §5.6; bead P2-1).
//!
//! A fixed pool + N agents × M concurrent calls = pool starvation and
//! `ORA-12519`. The admission controller bounds concurrency *before* the pool
//! is touched: a global cap (= pool `max_size`) plus a per-agent cap, both
//! enforced with a drop-released permit ledger. Over budget returns a structured
//! `BUSY { retry_after_ms }`; the stateful-lane path may wait briefly in a
//! bounded fair queue, but it never queues unboundedly.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::cx::CapSetRuntimeMask;
use oraclemcp_error::{ErrorClass, ErrorEnvelope, OracleMcpError};
use parking_lot::{Condvar, Mutex};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Default `retry_after_ms` returned with a `BUSY`.
pub const DEFAULT_RETRY_AFTER_MS: u64 = 250;
/// Brief bounded wait for stateful lane admission before returning AT_CAPACITY.
pub const DEFAULT_FAIR_ADMISSION_WAIT_MS: u64 = 25;
/// CX-I6 capacity measurement that finalized the shipped N4 upper-bound caps.
///
/// Evidence: `tests/artifacts/perf/20260630-cx-i6-phase0-capacity/RESULTS.md`.
#[cfg(test)]
const N4B_CAPACITY_MEASUREMENT_ID: &str = "20260630-cx-i6-phase0-capacity";

/// N4b finalized upper-bound default for stateless read connections per profile.
pub const DEFAULT_READ_PER_PROFILE_CAP: usize = 16;
/// N4b finalized upper-bound default for stateful/write lanes per profile.
pub const DEFAULT_STATEFUL_PER_PROFILE_CAP: usize = 8;
/// N4b finalized upper-bound default for all lane slots on one host.
pub const DEFAULT_GLOBAL_HOST_CAP: usize = 64;
/// N4 operator reserve: kept out of regular agent admission.
pub const DEFAULT_OPERATOR_RESERVED_LANES: usize = 1;
/// N4 doctor/readiness reserve: kept out of regular agent admission.
pub const DEFAULT_DOCTOR_RESERVED_LANES: usize = 1;

/// A held admission permit. Dropping it returns capacity to both the global and
/// per-agent counters.
#[derive(Debug)]
pub struct AdmissionPermit {
    inner: Arc<AdmissionInner>,
    agent: String,
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        let mut state = self.inner.state.lock();
        state.global_in_use = state.global_in_use.saturating_sub(1);
        match state.agents.get_mut(&self.agent) {
            Some(count) if *count > 1 => *count -= 1,
            Some(_) => {
                state.agents.remove(&self.agent);
            }
            None => {}
        }
        drop(state);
        self.inner.changed.notify_all();
    }
}

/// Bounds concurrency globally and per-agent.
pub struct AdmissionController {
    inner: Arc<AdmissionInner>,
}

#[derive(Debug)]
struct AdmissionInner {
    global_cap: usize,
    regular_global_cap: usize,
    operator_reserved: usize,
    doctor_reserved: usize,
    per_agent_cap: usize,
    queued_per_subject_cap: usize,
    queued_global_cap: usize,
    fair_wait: Duration,
    retry_after_ms: u64,
    draining: AtomicBool,
    state: Mutex<AdmissionState>,
    changed: Condvar,
}

#[derive(Debug, Default)]
struct AdmissionState {
    global_in_use: usize,
    agents: HashMap<String, usize>,
    queued_total: usize,
    queued_subjects: HashMap<String, usize>,
    queue_order: VecDeque<String>,
}

/// Redaction-safe capacity facts included in `AT_CAPACITY` diagnostics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacitySnapshot {
    /// Capacity surface being admitted, e.g. `stateful_lane`.
    pub scope: String,
    /// Redacted, server-derived subject/principal bucket.
    pub subject: String,
    /// Configured global ceiling, including reserved slots.
    pub global_cap: usize,
    /// Regular-agent slots after operator/doctor reserve is removed.
    pub regular_global_cap: usize,
    /// Currently available regular-agent global slots.
    pub regular_global_available: usize,
    /// Slots reserved for operator access.
    pub operator_reserved: usize,
    /// Slots reserved for doctor/readiness access.
    pub doctor_reserved: usize,
    /// Per-subject ceiling.
    pub per_subject_cap: usize,
    /// Currently available slots for this subject bucket.
    pub per_subject_available: usize,
    /// Suggested retry delay.
    pub retry_after_ms: u64,
}

impl AdmissionController {
    /// A controller with a global cap (size the pool) and a per-agent cap.
    ///
    /// # Identity contract
    /// `agent` (the key passed to [`try_admit`]) MUST be a **low-cardinality,
    /// server-controlled principal** — e.g. a configured agent/client id or a
    /// validated, enumerable role. It MUST NOT be a raw client-supplied or
    /// per-request value (an OAuth token subject, a request id, a free-form
    /// header) whose cardinality an attacker can drive. The per-agent ledger
    /// removes idle entries when permits drop, but only a low-cardinality key
    /// keeps the steady-state footprint bounded under churn.
    ///
    /// [`try_admit`]: Self::try_admit
    #[must_use]
    pub fn new(global_cap: usize, per_agent_cap: usize) -> Self {
        Self::with_reserved(global_cap, per_agent_cap, 0, 0)
    }

    /// A controller with regular-agent capacity reduced by explicit reserves.
    #[must_use]
    pub fn with_reserved(
        global_cap: usize,
        per_agent_cap: usize,
        operator_reserved: usize,
        doctor_reserved: usize,
    ) -> Self {
        Self::with_reserved_and_wait(
            global_cap,
            per_agent_cap,
            operator_reserved,
            doctor_reserved,
            Duration::from_millis(DEFAULT_FAIR_ADMISSION_WAIT_MS),
        )
    }

    fn with_reserved_and_wait(
        global_cap: usize,
        per_agent_cap: usize,
        operator_reserved: usize,
        doctor_reserved: usize,
        fair_wait: Duration,
    ) -> Self {
        let global_cap = global_cap.max(1);
        let per_agent_cap = per_agent_cap.max(1);
        let reserved = operator_reserved.saturating_add(doctor_reserved);
        let regular_global_cap = global_cap.saturating_sub(reserved);
        let queued_global_cap = regular_global_cap.saturating_mul(2).max(1);
        AdmissionController {
            inner: Arc::new(AdmissionInner {
                global_cap,
                regular_global_cap,
                operator_reserved,
                doctor_reserved,
                per_agent_cap,
                queued_per_subject_cap: per_agent_cap.min(queued_global_cap).max(1),
                queued_global_cap,
                fair_wait,
                retry_after_ms: DEFAULT_RETRY_AFTER_MS,
                draining: AtomicBool::new(false),
                state: Mutex::new(AdmissionState::default()),
                changed: Condvar::new(),
            }),
        }
    }

    /// N4b finalized defaults for stateful/write lanes: 8 per subject/profile,
    /// 64 global upper bound, with one operator and one doctor slot reserved
    /// outside regular agent admission.
    ///
    /// These upper bounds are pinned to the CX-I6 measurement recorded as
    /// `20260630-cx-i6-phase0-capacity`: 16 real lane-owned Oracle sessions,
    /// 2.00 observed OS threads per lane, 4.00 observed fds per lane, and host
    /// limits supporting the 64-lane candidate on the measured dev host.
    #[must_use]
    pub fn n4_stateful_defaults() -> Self {
        Self::with_reserved(
            DEFAULT_GLOBAL_HOST_CAP,
            DEFAULT_STATEFUL_PER_PROFILE_CAP,
            DEFAULT_OPERATOR_RESERVED_LANES,
            DEFAULT_DOCTOR_RESERVED_LANES,
        )
    }

    /// Try to admit a call for `agent` in `cx` without waiting. Returns a
    /// permit, or a `BUSY` envelope when over the global or per-agent budget.
    /// Global and per-agent budgets are checked atomically under one short
    /// critical section, so a single noisy agent hits its own cap without
    /// starving the host-level pool.
    ///
    /// The explicit [`Cx`] keeps the call site honest about request/lane context
    /// even though the permit ledger itself is drop-based and can be held for a
    /// stateful lane's lifetime.
    ///
    /// `agent` MUST be a low-cardinality, server-controlled principal — see the
    /// identity contract on [`new`]. Idle per-agent entries are removed when
    /// permits drop so the backing map tracks active agents, not every agent
    /// ever seen.
    ///
    /// [`new`]: Self::new
    ///
    /// # Errors
    /// Returns [`OracleMcpError::Busy`] when no capacity is available.
    pub fn try_admit<Caps>(
        &self,
        cx: &Cx<Caps>,
        agent: &str,
    ) -> Result<AdmissionPermit, OracleMcpError>
    where
        Caps: CapSetRuntimeMask,
    {
        if cx.checkpoint().is_err() {
            return Err(self.busy_error());
        }
        if self.is_draining() {
            return Err(OracleMcpError::Busy {
                retry_after_ms: self.inner.retry_after_ms,
            });
        }
        if self.inner.regular_global_cap == 0 {
            return Err(OracleMcpError::Busy {
                retry_after_ms: self.inner.retry_after_ms,
            });
        }
        let mut state = self.inner.state.lock();
        if self.is_draining() || cx.checkpoint().is_err() {
            return Err(OracleMcpError::Busy {
                retry_after_ms: self.inner.retry_after_ms,
            });
        }
        if state.queued_total > 0 || !self.subject_can_admit_locked(&state, agent) {
            return Err(OracleMcpError::Busy {
                retry_after_ms: self.inner.retry_after_ms,
            });
        }
        Ok(self.admit_locked(&mut state, agent))
    }

    /// Admit or return an agent-facing `AT_CAPACITY` envelope with a redacted
    /// snapshot. This is the served N4 path.
    pub fn try_admit_capacity<Caps>(
        &self,
        cx: &Cx<Caps>,
        subject: &str,
        scope: &str,
    ) -> Result<AdmissionPermit, ErrorEnvelope>
    where
        Caps: CapSetRuntimeMask,
    {
        self.try_admit(cx, subject).map_err(|_| {
            self.at_capacity_envelope(scope, subject).with_next_step(
                "retry after retry_after_ms, or wait for an existing lane to idle out",
            )
        })
    }

    /// Admit after a bounded fair wait, or return an agent-facing
    /// `AT_CAPACITY` envelope with a redacted snapshot.
    pub fn admit_capacity_with_fair_wait<Caps>(
        &self,
        cx: &Cx<Caps>,
        subject: &str,
        scope: &str,
    ) -> Result<AdmissionPermit, ErrorEnvelope>
    where
        Caps: CapSetRuntimeMask,
    {
        self.admit_with_fair_wait(cx, subject).map_err(|_| {
            self.at_capacity_envelope(scope, subject).with_next_step(
                "retry after retry_after_ms; admission already waited briefly in the bounded fair queue",
            )
        })
    }

    /// Admit through the bounded per-subject queue used by stateful lane
    /// allocation. A subject with multiple queued requests gets one turn, then
    /// rotates to the back so another eligible subject can acquire the next
    /// released slot.
    ///
    /// # Errors
    /// Returns [`OracleMcpError::Busy`] when capacity is unavailable after the
    /// bounded wait, queue caps are full, or shutdown drain is active.
    pub fn admit_with_fair_wait<Caps>(
        &self,
        cx: &Cx<Caps>,
        agent: &str,
    ) -> Result<AdmissionPermit, OracleMcpError>
    where
        Caps: CapSetRuntimeMask,
    {
        if cx.checkpoint().is_err() || self.is_draining() || self.inner.regular_global_cap == 0 {
            return Err(self.busy_error());
        }

        let deadline = Instant::now()
            .checked_add(self.inner.fair_wait)
            .unwrap_or_else(Instant::now);
        let mut state = self.inner.state.lock();
        if self.is_draining() || cx.checkpoint().is_err() {
            return Err(self.busy_error());
        }
        if state.queued_total == 0 && self.subject_can_admit_locked(&state, agent) {
            return Ok(self.admit_locked(&mut state, agent));
        }
        if !self.enqueue_locked(&mut state, agent) {
            return Err(self.busy_error());
        }

        loop {
            if self.is_draining() || cx.checkpoint().is_err() {
                Self::dequeue_locked(&mut state, agent);
                drop(state);
                self.inner.changed.notify_all();
                return Err(self.busy_error());
            }
            if self.subject_has_fair_turn_locked(&state, agent) {
                Self::dequeue_locked(&mut state, agent);
                let permit = self.admit_locked(&mut state, agent);
                drop(state);
                self.inner.changed.notify_all();
                return Ok(permit);
            }

            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                Self::dequeue_locked(&mut state, agent);
                drop(state);
                self.inner.changed.notify_all();
                return Err(self.busy_error());
            };
            if remaining.is_zero() {
                Self::dequeue_locked(&mut state, agent);
                drop(state);
                self.inner.changed.notify_all();
                return Err(self.busy_error());
            }
            // Condvar notification cannot observe task cancellation. Wake in
            // short bounded slices so a cancelled request cannot sit for the
            // full fair-admission window and then allocate an idle lane.
            let wait = self
                .inner
                .changed
                .wait_for(&mut state, remaining.min(Duration::from_millis(5)));
            if wait.timed_out()
                && deadline <= Instant::now()
                && !self.subject_has_fair_turn_locked(&state, agent)
            {
                Self::dequeue_locked(&mut state, agent);
                drop(state);
                self.inner.changed.notify_all();
                return Err(self.busy_error());
            }
        }
    }

    /// Stop admitting new work while preserving existing permits so in-flight
    /// calls can drain and release their capacity normally. Idempotent.
    pub fn begin_drain(&self) {
        self.inner.draining.store(true, Ordering::SeqCst);
        self.inner.changed.notify_all();
    }

    /// Whether the controller is refusing new work during shutdown drain.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.inner.draining.load(Ordering::SeqCst)
    }

    /// Convenience: the agent-facing `BUSY` envelope.
    #[must_use]
    pub fn busy_envelope(&self) -> ErrorEnvelope {
        self.busy_error().into_envelope()
    }

    /// Redaction-safe snapshot of current regular-agent capacity.
    #[must_use]
    pub fn snapshot(&self, scope: &str, subject: &str) -> CapacitySnapshot {
        let state = self.inner.state.lock();
        let subject_in_use = state.agents.get(subject).copied().unwrap_or(0);
        CapacitySnapshot {
            scope: scope.to_owned(),
            subject: redact_subject_for_capacity(subject),
            global_cap: self.inner.global_cap,
            regular_global_cap: self.inner.regular_global_cap,
            regular_global_available: self
                .inner
                .regular_global_cap
                .saturating_sub(state.global_in_use),
            operator_reserved: self.inner.operator_reserved,
            doctor_reserved: self.inner.doctor_reserved,
            per_subject_cap: self.inner.per_agent_cap,
            per_subject_available: self.inner.per_agent_cap.saturating_sub(subject_in_use),
            retry_after_ms: self.inner.retry_after_ms,
        }
    }

    /// Agent-facing at-capacity envelope with a machine-stable class and a
    /// redacted JSON snapshot embedded in the message.
    #[must_use]
    pub fn at_capacity_envelope(&self, scope: &str, subject: &str) -> ErrorEnvelope {
        let snapshot = self.snapshot(scope, subject);
        ErrorEnvelope::new(
            ErrorClass::AtCapacity,
            format!(
                "at capacity for {scope}; capacity_snapshot={}",
                serde_json::to_string(&snapshot).unwrap_or_else(|_| {
                    json!({
                        "scope": scope,
                        "subject": "redacted",
                        "retry_after_ms": self.inner.retry_after_ms
                    })
                    .to_string()
                })
            ),
        )
        .with_retry_after_ms(self.inner.retry_after_ms)
    }

    /// Current available global permits (for `/readyz` / metrics).
    #[must_use]
    pub fn available_global(&self) -> usize {
        let state = self.inner.state.lock();
        self.inner
            .regular_global_cap
            .saturating_sub(state.global_in_use)
    }

    /// Regular-agent global capacity after operator/doctor reserve.
    #[must_use]
    pub fn regular_global_cap(&self) -> usize {
        self.inner.regular_global_cap
    }

    fn busy_error(&self) -> OracleMcpError {
        OracleMcpError::Busy {
            retry_after_ms: self.inner.retry_after_ms,
        }
    }

    fn subject_can_admit_locked(&self, state: &AdmissionState, agent: &str) -> bool {
        state.global_in_use < self.inner.regular_global_cap
            && state.agents.get(agent).copied().unwrap_or(0) < self.inner.per_agent_cap
    }

    fn subject_has_fair_turn_locked(&self, state: &AdmissionState, agent: &str) -> bool {
        for queued in &state.queue_order {
            if self.subject_can_admit_locked(state, queued) {
                return queued == agent;
            }
        }
        false
    }

    fn admit_locked(&self, state: &mut AdmissionState, agent: &str) -> AdmissionPermit {
        state.global_in_use += 1;
        *state.agents.entry(agent.to_owned()).or_insert(0) += 1;
        AdmissionPermit {
            inner: Arc::clone(&self.inner),
            agent: agent.to_owned(),
        }
    }

    fn enqueue_locked(&self, state: &mut AdmissionState, agent: &str) -> bool {
        if state.queued_total >= self.inner.queued_global_cap {
            return false;
        }
        let queued_for_subject = state.queued_subjects.get(agent).copied().unwrap_or(0);
        if queued_for_subject >= self.inner.queued_per_subject_cap {
            return false;
        }
        if queued_for_subject == 0 {
            state.queue_order.push_back(agent.to_owned());
        }
        state
            .queued_subjects
            .insert(agent.to_owned(), queued_for_subject + 1);
        state.queued_total += 1;
        true
    }

    fn dequeue_locked(state: &mut AdmissionState, agent: &str) {
        let queued_for_subject = state.queued_subjects.get(agent).copied().unwrap_or(0);
        if queued_for_subject == 0 {
            return;
        }
        state.queued_total = state.queued_total.saturating_sub(1);
        if queued_for_subject == 1 {
            state.queued_subjects.remove(agent);
        } else {
            state
                .queued_subjects
                .insert(agent.to_owned(), queued_for_subject - 1);
        }
        if let Some(position) = state.queue_order.iter().position(|queued| queued == agent) {
            let _ = state.queue_order.remove(position);
        }
        if queued_for_subject > 1 {
            state.queue_order.push_back(agent.to_owned());
        }
    }

    /// Number of resident per-agent entries (test-only: the reclamation invariant).
    #[cfg(test)]
    fn tracked_agents(&self) -> usize {
        self.inner.state.lock().agents.len()
    }

    #[cfg(test)]
    fn queued_subject_count(&self, subject: &str) -> usize {
        self.inner
            .state
            .lock()
            .queued_subjects
            .get(subject)
            .copied()
            .unwrap_or(0)
    }
}

fn redact_subject_for_capacity(subject: &str) -> String {
    if subject.is_empty() {
        return "anonymous".to_owned();
    }
    format!("subject-len{}", subject.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::cx::NoCaps;
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::{Duration, Instant};

    fn test_cx() -> Cx<NoCaps> {
        Cx::<NoCaps>::detached_cancel_context()
    }

    fn wait_until(description: &str, mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if condition() {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("{description}");
    }

    fn spawn_waiter(
        ctrl: Arc<AdmissionController>,
        subject: &'static str,
        label: &'static str,
        admitted: mpsc::Sender<String>,
    ) -> (String, mpsc::Sender<()>, thread::JoinHandle<()>) {
        let (release_tx, release_rx) = mpsc::channel();
        let label_string = label.to_owned();
        let handle_label = label_string.clone();
        let handle = thread::spawn(move || {
            let cx = test_cx();
            let permit = ctrl
                .admit_with_fair_wait(&cx, subject)
                .expect("waiter admitted through fair queue");
            admitted
                .send(handle_label)
                .expect("test receiver accepts admission event");
            release_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("test releases admitted waiter");
            drop(permit);
        });
        (label_string, release_tx, handle)
    }

    fn release_waiter(releases: &mut Vec<(String, mpsc::Sender<()>)>, label: &str) {
        let position = releases
            .iter()
            .position(|(queued_label, _)| queued_label == label)
            .expect("release channel for admitted waiter");
        let (_, release) = releases.remove(position);
        release.send(()).expect("waiter still alive");
    }

    fn recv_admitted(admitted: &mpsc::Receiver<String>) -> String {
        admitted
            .recv_timeout(Duration::from_secs(2))
            .expect("queued waiter admitted before test timeout")
    }

    #[test]
    fn admits_up_to_global_cap_then_busy() {
        let cx = test_cx();
        let ctrl = AdmissionController::new(2, 10);
        let p1 = ctrl.try_admit(&cx, "a").expect("1");
        let p2 = ctrl.try_admit(&cx, "b").expect("2");
        // Global cap (2) reached -> BUSY.
        assert!(matches!(
            ctrl.try_admit(&cx, "c"),
            Err(OracleMcpError::Busy { .. })
        ));
        drop(p1);
        // Capacity returned -> admits again.
        let _p3 = ctrl.try_admit(&cx, "c").expect("3 after release");
        drop(p2);
    }

    #[test]
    fn per_agent_cap_isolates_a_noisy_agent() {
        let cx = test_cx();
        let ctrl = AdmissionController::new(100, 2);
        let _a1 = ctrl.try_admit(&cx, "noisy").expect("a1");
        let _a2 = ctrl.try_admit(&cx, "noisy").expect("a2");
        // The noisy agent hits its own cap (2) while the global pool is free.
        assert!(matches!(
            ctrl.try_admit(&cx, "noisy"),
            Err(OracleMcpError::Busy { .. })
        ));
        // A different agent is unaffected.
        let _b1 = ctrl.try_admit(&cx, "quiet").expect("other agent admitted");
    }

    #[test]
    fn busy_envelope_carries_retry_after() {
        let ctrl = AdmissionController::new(1, 1);
        let env = ctrl.busy_envelope();
        assert_eq!(env.retry_after_ms, Some(DEFAULT_RETRY_AFTER_MS));
    }

    #[test]
    fn n4_defaults_keep_operator_and_doctor_reserve_out_of_regular_capacity() {
        let cx = test_cx();
        let ctrl = AdmissionController::n4_stateful_defaults();
        assert_eq!(
            N4B_CAPACITY_MEASUREMENT_ID,
            "20260630-cx-i6-phase0-capacity"
        );
        assert_eq!(DEFAULT_READ_PER_PROFILE_CAP, 16);
        assert_eq!(DEFAULT_STATEFUL_PER_PROFILE_CAP, 8);
        assert_eq!(DEFAULT_GLOBAL_HOST_CAP, 64);
        assert_eq!(DEFAULT_OPERATOR_RESERVED_LANES, 1);
        assert_eq!(DEFAULT_DOCTOR_RESERVED_LANES, 1);
        assert_eq!(
            ctrl.regular_global_cap(),
            DEFAULT_GLOBAL_HOST_CAP
                - DEFAULT_OPERATOR_RESERVED_LANES
                - DEFAULT_DOCTOR_RESERVED_LANES
        );
        let mut permits = Vec::new();
        for i in 0..ctrl.regular_global_cap() {
            permits.push(
                ctrl.try_admit_capacity(&cx, &format!("subject-{i}"), "stateful_lane")
                    .expect("regular capacity admits"),
            );
        }

        let err = ctrl
            .try_admit_capacity(&cx, "overflow-subject", "stateful_lane")
            .expect_err("operator/doctor reserve is not consumed by regular lanes");
        assert_eq!(err.error_class, ErrorClass::AtCapacity);
        assert_eq!(err.retry_after_ms, Some(DEFAULT_RETRY_AFTER_MS));
        assert!(err.message.contains("\"operator_reserved\":1"));
        assert!(err.message.contains("\"doctor_reserved\":1"));
        assert!(err.message.contains("\"subject\":\"subject-len16\""));
        assert!(
            !err.message.contains("overflow-subject"),
            "capacity snapshots must not echo raw principal keys"
        );
        drop(permits);
        assert_eq!(ctrl.available_global(), ctrl.regular_global_cap());
    }

    #[test]
    fn queued_admission_waits_for_release_before_at_capacity() {
        let cx = test_cx();
        let ctrl = Arc::new(AdmissionController::with_reserved_and_wait(
            1,
            1,
            0,
            0,
            Duration::from_millis(200),
        ));
        let held = ctrl.try_admit(&cx, "holder").expect("holder admitted");
        let (admitted_tx, admitted_rx) = mpsc::channel();
        let (label, release, handle) =
            spawn_waiter(Arc::clone(&ctrl), "waiter", "waiter-1", admitted_tx);
        wait_until("waiter enters bounded queue", || {
            ctrl.queued_subject_count("waiter") == 1
        });

        drop(held);
        assert_eq!(recv_admitted(&admitted_rx), label);
        release.send(()).expect("release waiter");
        handle.join().expect("waiter thread exits");
        assert_eq!(ctrl.available_global(), 1);
    }

    #[test]
    fn queued_admission_round_robins_between_subjects() {
        let cx = test_cx();
        let ctrl = Arc::new(AdmissionController::with_reserved_and_wait(
            2,
            2,
            0,
            0,
            Duration::from_millis(500),
        ));
        let held_a = ctrl.try_admit(&cx, "holder-a").expect("holder a");
        let held_b = ctrl.try_admit(&cx, "holder-b").expect("holder b");
        let (admitted_tx, admitted_rx) = mpsc::channel();
        let mut releases = Vec::new();
        let mut handles = Vec::new();

        let (label, release, handle) =
            spawn_waiter(Arc::clone(&ctrl), "noisy", "noisy-1", admitted_tx.clone());
        releases.push((label, release));
        handles.push(handle);
        wait_until("first noisy request queues", || {
            ctrl.queued_subject_count("noisy") == 1
        });

        let (label, release, handle) =
            spawn_waiter(Arc::clone(&ctrl), "quiet", "quiet-1", admitted_tx.clone());
        releases.push((label, release));
        handles.push(handle);
        wait_until("quiet request queues", || {
            ctrl.queued_subject_count("quiet") == 1
        });

        let (label, release, handle) =
            spawn_waiter(Arc::clone(&ctrl), "noisy", "noisy-2", admitted_tx);
        releases.push((label, release));
        handles.push(handle);
        wait_until("second noisy request queues", || {
            ctrl.queued_subject_count("noisy") == 2
        });

        drop(held_a);
        let first = recv_admitted(&admitted_rx);
        assert!(
            first.starts_with("noisy-"),
            "the first subject in the fair queue should admit first, got {first}"
        );
        release_waiter(&mut releases, &first);

        let second = recv_admitted(&admitted_rx);
        assert_eq!(
            second, "quiet-1",
            "a subject with multiple queued requests must rotate behind another eligible subject"
        );
        release_waiter(&mut releases, &second);

        let third = recv_admitted(&admitted_rx);
        assert!(
            third.starts_with("noisy-"),
            "the noisy subject's remaining queued turn should run after quiet, got {third}"
        );
        release_waiter(&mut releases, &third);

        drop(held_b);
        for handle in handles {
            handle.join().expect("waiter thread exits");
        }
        assert_eq!(ctrl.available_global(), 2);
    }

    #[test]
    fn bounded_queue_at_capacity_keeps_snapshot_redacted() {
        let cx = test_cx();
        let ctrl =
            AdmissionController::with_reserved_and_wait(1, 1, 0, 0, Duration::from_millis(1));
        let _held = ctrl
            .try_admit(&cx, "holder")
            .expect("holder consumes the only regular slot");

        let err = ctrl
            .admit_capacity_with_fair_wait(&cx, "raw-principal-secret", "stateful_lane")
            .expect_err("bounded wait ends at capacity");
        assert_eq!(err.error_class, ErrorClass::AtCapacity);
        assert_eq!(err.retry_after_ms, Some(DEFAULT_RETRY_AFTER_MS));
        assert!(err.message.contains("capacity_snapshot"));
        assert!(err.message.contains("\"subject\":\"subject-len20\""));
        assert!(
            !err.message.contains("raw-principal-secret"),
            "capacity snapshots must not echo raw principal keys"
        );
        assert_eq!(ctrl.queued_subject_count("raw-principal-secret"), 0);
    }

    #[test]
    fn idle_agent_entries_are_reclaimed_after_churn() {
        let cx = test_cx();
        // REGRESSION (oracle-clgt.12): the per-agent map used to be insert-only,
        // so a churn of distinct agent strings grew it without bound. With
        // drop-time reclamation, the map returns to baseline as permits release.
        let ctrl = AdmissionController::new(1000, 4);
        // Churn 500 distinct agents, dropping each permit immediately.
        for i in 0..500 {
            let p = ctrl.try_admit(&cx, &format!("agent-{i}")).expect("admit");
            drop(p);
        }
        // Only the current agent remains resident, not 500+ leaked entries.
        let _final = ctrl.try_admit(&cx, "agent-final").expect("admit final");
        assert!(
            ctrl.tracked_agents() <= 1,
            "idle entries must be reclaimed; map held {} entries",
            ctrl.tracked_agents()
        );
    }

    #[test]
    fn active_agent_entries_are_not_reclaimed() {
        let cx = test_cx();
        // Reclamation must never evict an agent that still holds a permit, or
        // its concurrency budget would silently reset. Hold one agent's permit
        // across another agent's churn and confirm the held agent stays capped.
        let ctrl = AdmissionController::new(1000, 1);
        let held = ctrl.try_admit(&cx, "busy").expect("busy admitted");
        // Churn other agents (each triggers a reclamation pass).
        for i in 0..50 {
            drop(
                ctrl.try_admit(&cx, &format!("other-{i}"))
                    .expect("other admit"),
            );
        }
        // "busy" still holds its only permit, so a second admit for it is BUSY —
        // proving its semaphore survived the reclamation passes intact.
        assert!(
            matches!(
                ctrl.try_admit(&cx, "busy"),
                Err(OracleMcpError::Busy { .. })
            ),
            "an active agent's per-agent cap must survive reclamation"
        );
        drop(held);
        // Once released, the agent admits again.
        let _again = ctrl
            .try_admit(&cx, "busy")
            .expect("busy admits after release");
    }

    #[test]
    fn permit_release_restores_global_capacity() {
        let cx = test_cx();
        let ctrl = AdmissionController::new(1, 5);
        assert_eq!(ctrl.available_global(), 1);
        let p = ctrl.try_admit(&cx, "a").expect("admit");
        assert_eq!(ctrl.available_global(), 0);
        drop(p);
        assert_eq!(ctrl.available_global(), 1);
    }

    #[test]
    fn drain_refuses_new_work_without_discarding_existing_permits() {
        let cx = test_cx();
        let ctrl = AdmissionController::new(1, 1);
        let permit = ctrl.try_admit(&cx, "a").expect("first admitted");
        ctrl.begin_drain();
        assert!(ctrl.is_draining());
        assert!(matches!(
            ctrl.try_admit(&cx, "b"),
            Err(OracleMcpError::Busy { .. })
        ));
        drop(permit);
        assert_eq!(ctrl.available_global(), 1);
        assert!(matches!(
            ctrl.try_admit(&cx, "a"),
            Err(OracleMcpError::Busy { .. })
        ));
    }
}
