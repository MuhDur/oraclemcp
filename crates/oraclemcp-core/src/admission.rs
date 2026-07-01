//! Admission control & backpressure (plan §5.6; bead P2-1).
//!
//! A fixed pool + N agents × M concurrent calls = pool starvation and
//! `ORA-12519`. The admission controller bounds concurrency *before* the pool
//! is touched: a global cap (= pool `max_size`) plus a per-agent cap, both
//! enforced with a drop-released permit ledger. Over budget returns a structured
//! `BUSY { retry_after_ms }` rather than queueing unboundedly.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use asupersync::Cx;
use asupersync::cx::CapSetRuntimeMask;
use oraclemcp_error::{ErrorClass, ErrorEnvelope, OracleMcpError};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Default `retry_after_ms` returned with a `BUSY`.
pub const DEFAULT_RETRY_AFTER_MS: u64 = 250;
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
    retry_after_ms: u64,
    draining: AtomicBool,
    state: Mutex<AdmissionState>,
}

#[derive(Debug, Default)]
struct AdmissionState {
    global_in_use: usize,
    agents: HashMap<String, usize>,
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
        let global_cap = global_cap.max(1);
        let reserved = operator_reserved.saturating_add(doctor_reserved);
        let regular_global_cap = global_cap.saturating_sub(reserved);
        AdmissionController {
            inner: Arc::new(AdmissionInner {
                global_cap,
                regular_global_cap,
                operator_reserved,
                doctor_reserved,
                per_agent_cap: per_agent_cap.max(1),
                retry_after_ms: DEFAULT_RETRY_AFTER_MS,
                draining: AtomicBool::new(false),
                state: Mutex::new(AdmissionState::default()),
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
        _cx: &Cx<Caps>,
        agent: &str,
    ) -> Result<AdmissionPermit, OracleMcpError>
    where
        Caps: CapSetRuntimeMask,
    {
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
        if self.is_draining() {
            return Err(OracleMcpError::Busy {
                retry_after_ms: self.inner.retry_after_ms,
            });
        }
        let agent_in_use = state.agents.get(agent).copied().unwrap_or(0);
        if agent_in_use >= self.inner.per_agent_cap
            || state.global_in_use >= self.inner.regular_global_cap
        {
            return Err(OracleMcpError::Busy {
                retry_after_ms: self.inner.retry_after_ms,
            });
        }
        state.global_in_use += 1;
        *state.agents.entry(agent.to_owned()).or_insert(0) += 1;
        Ok(AdmissionPermit {
            inner: Arc::clone(&self.inner),
            agent: agent.to_owned(),
        })
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

    /// Stop admitting new work while preserving existing permits so in-flight
    /// calls can drain and release their capacity normally. Idempotent.
    pub fn begin_drain(&self) {
        self.inner.draining.store(true, Ordering::SeqCst);
    }

    /// Whether the controller is refusing new work during shutdown drain.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.inner.draining.load(Ordering::SeqCst)
    }

    /// Convenience: the agent-facing `BUSY` envelope.
    #[must_use]
    pub fn busy_envelope(&self) -> ErrorEnvelope {
        OracleMcpError::Busy {
            retry_after_ms: self.inner.retry_after_ms,
        }
        .into_envelope()
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

    /// Number of resident per-agent entries (test-only: the reclamation invariant).
    #[cfg(test)]
    fn tracked_agents(&self) -> usize {
        self.inner.state.lock().agents.len()
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

    fn test_cx() -> Cx<NoCaps> {
        Cx::<NoCaps>::detached_cancel_context()
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
