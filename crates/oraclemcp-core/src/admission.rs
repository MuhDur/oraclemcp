//! Admission control & backpressure (plan §5.6; bead P2-1).
//!
//! A fixed pool + N agents × M concurrent calls = pool starvation and
//! `ORA-12519`. The admission controller bounds concurrency *before* the pool
//! is touched: a global cap (= pool `max_size`) plus a per-agent cap, both
//! enforced with `asupersync::sync::Semaphore`. Over budget returns a structured
//! `BUSY { retry_after_ms }` rather than queueing unboundedly — the semaphore,
//! never the 512-thread blocking pool, is the limiter.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use asupersync::Cx;
use asupersync::cx::CapSetRuntimeMask;
use asupersync::sync::{OwnedSemaphorePermit, Semaphore};
use oraclemcp_error::{ErrorEnvelope, OracleMcpError};

/// Default `retry_after_ms` returned with a `BUSY`.
pub const DEFAULT_RETRY_AFTER_MS: u64 = 250;

/// A held admission permit. Dropping it returns capacity to both the global and
/// per-agent semaphores.
#[derive(Debug)]
pub struct AdmissionPermit {
    _global: OwnedSemaphorePermit,
    _agent: OwnedSemaphorePermit,
}

/// Bounds concurrency globally and per-agent.
pub struct AdmissionController {
    global: Arc<Semaphore>,
    per_agent_cap: usize,
    agents: Mutex<HashMap<String, Arc<Semaphore>>>,
    retry_after_ms: u64,
    draining: AtomicBool,
}

impl AdmissionController {
    /// A controller with a global cap (size the pool) and a per-agent cap.
    ///
    /// # Identity contract
    /// `agent` (the key passed to [`try_admit`]) MUST be a **low-cardinality,
    /// server-controlled principal** — e.g. a configured agent/client id or a
    /// validated, enumerable role. It MUST NOT be a raw client-supplied or
    /// per-request value (an OAuth token subject, a request id, a free-form
    /// header) whose cardinality an attacker can drive. The per-agent semaphore
    /// map reclaims idle entries (see [`try_admit`]), but only a low-cardinality
    /// key keeps the steady-state footprint bounded under churn.
    ///
    /// [`try_admit`]: Self::try_admit
    #[must_use]
    pub fn new(global_cap: usize, per_agent_cap: usize) -> Self {
        AdmissionController {
            global: Arc::new(Semaphore::new(global_cap.max(1))),
            per_agent_cap: per_agent_cap.max(1),
            agents: Mutex::new(HashMap::new()),
            retry_after_ms: DEFAULT_RETRY_AFTER_MS,
            draining: AtomicBool::new(false),
        }
    }

    fn agent_semaphore(&self, agent: &str) -> Arc<Semaphore> {
        let mut agents = self.agents.lock().expect("admission mutex poisoned");
        // Reclaim idle entries before inserting so the map tracks *active* agents
        // rather than every agent ever seen. An entry is idle iff all its permits
        // are back (available == cap) AND no outstanding permit/clone still holds
        // the Arc (strong_count == 1, i.e. only the map references it); dropping
        // such an entry is behaviour-preserving — the next call for that agent
        // just rebuilds a fresh, fully-available semaphore. The currently-keyed
        // `agent` is exempt: we are about to use it.
        let cap = self.per_agent_cap;
        agents.retain(|key, sem| {
            key == agent || Arc::strong_count(sem) > 1 || sem.available_permits() < cap
        });
        Arc::clone(
            agents
                .entry(agent.to_owned())
                .or_insert_with(|| Arc::new(Semaphore::new(self.per_agent_cap))),
        )
    }

    /// Try to admit a call for `agent` in `cx` without waiting. Returns a
    /// permit, or a `BUSY` envelope when over the global or per-agent budget.
    /// The per-agent permit is taken first (a single noisy agent hits its own
    /// cap before starving the global pool).
    ///
    /// The explicit [`Cx`] is installed only for the acquisition window so
    /// Asupersync's semaphore obligation tokens are scoped to the request
    /// region. Callers outside an Asupersync runtime must create a request/test
    /// context instead of relying on ambient task state.
    ///
    /// `agent` MUST be a low-cardinality, server-controlled principal — see the
    /// identity contract on [`new`]. Idle per-agent entries are reclaimed on
    /// each call so the backing map tracks active agents, not every agent ever
    /// seen.
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
        if self.is_draining() {
            return Err(OracleMcpError::Busy {
                retry_after_ms: self.retry_after_ms,
            });
        }
        let _cx_guard = cx.clone().set_current_restricted();
        let agent_sem = self.agent_semaphore(agent);
        let agent_permit = OwnedSemaphorePermit::try_acquire_arc(&agent_sem, 1).map_err(|_| {
            OracleMcpError::Busy {
                retry_after_ms: self.retry_after_ms,
            }
        })?;
        let global_permit =
            OwnedSemaphorePermit::try_acquire_arc(&self.global, 1).map_err(|_| {
                OracleMcpError::Busy {
                    retry_after_ms: self.retry_after_ms,
                }
            })?;
        if self.is_draining() {
            return Err(OracleMcpError::Busy {
                retry_after_ms: self.retry_after_ms,
            });
        }
        // agent_permit released on the early-return above if global fails.
        Ok(AdmissionPermit {
            _global: global_permit,
            _agent: agent_permit,
        })
    }

    /// Stop admitting new work while preserving existing permits so in-flight
    /// calls can drain and release their capacity normally. Idempotent.
    pub fn begin_drain(&self) {
        self.draining.store(true, Ordering::SeqCst);
    }

    /// Whether the controller is refusing new work during shutdown drain.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    /// Convenience: the agent-facing `BUSY` envelope.
    #[must_use]
    pub fn busy_envelope(&self) -> ErrorEnvelope {
        OracleMcpError::Busy {
            retry_after_ms: self.retry_after_ms,
        }
        .into_envelope()
    }

    /// Current available global permits (for `/readyz` / metrics).
    #[must_use]
    pub fn available_global(&self) -> usize {
        self.global.available_permits()
    }

    /// Number of resident per-agent entries (test-only: the reclamation invariant).
    #[cfg(test)]
    fn tracked_agents(&self) -> usize {
        self.agents.lock().expect("admission mutex poisoned").len()
    }
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
    fn idle_agent_entries_are_reclaimed_after_churn() {
        let cx = test_cx();
        // REGRESSION (oracle-clgt.12): the per-agent map used to be insert-only,
        // so a churn of distinct agent strings grew it without bound. With idle
        // reclamation, the map must return to baseline (~the one currently-keyed
        // agent) once all churned permits are dropped.
        let ctrl = AdmissionController::new(1000, 4);
        // Churn 500 distinct agents, dropping each permit immediately.
        for i in 0..500 {
            let p = ctrl.try_admit(&cx, &format!("agent-{i}")).expect("admit");
            drop(p);
        }
        // The next call reclaims every now-idle prior entry; only the current
        // agent remains resident, not 500+ leaked entries.
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
        // Reclamation must never evict an agent that still holds a permit, or its
        // concurrency budget would silently reset. Hold one agent's permit across
        // another agent's churn and confirm the held agent stays capped.
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
