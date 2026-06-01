//! Admission control & backpressure (plan §5.6; bead P2-1).
//!
//! A fixed pool + N agents × M concurrent calls = pool starvation and
//! `ORA-12519`. The admission controller bounds concurrency *before* the pool
//! is touched: a global cap (= pool `max_size`) plus a per-agent cap, both
//! enforced with `tokio::sync::Semaphore`. Over budget returns a structured
//! `BUSY { retry_after_ms }` rather than queueing unboundedly — the semaphore,
//! never the 512-thread blocking pool, is the limiter.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use oraclemcp_error::{ErrorEnvelope, OracleMcpError};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

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
}

impl AdmissionController {
    /// A controller with a global cap (size the pool) and a per-agent cap.
    #[must_use]
    pub fn new(global_cap: usize, per_agent_cap: usize) -> Self {
        AdmissionController {
            global: Arc::new(Semaphore::new(global_cap.max(1))),
            per_agent_cap: per_agent_cap.max(1),
            agents: Mutex::new(HashMap::new()),
            retry_after_ms: DEFAULT_RETRY_AFTER_MS,
        }
    }

    fn agent_semaphore(&self, agent: &str) -> Arc<Semaphore> {
        let mut agents = self.agents.lock().expect("admission mutex poisoned");
        Arc::clone(
            agents
                .entry(agent.to_owned())
                .or_insert_with(|| Arc::new(Semaphore::new(self.per_agent_cap))),
        )
    }

    /// Try to admit a call for `agent` without waiting. Returns a permit, or a
    /// `BUSY` envelope when over the global or per-agent budget. The per-agent
    /// permit is taken first (a single noisy agent hits its own cap before
    /// starving the global pool).
    ///
    /// # Errors
    /// Returns [`OracleMcpError::Busy`] when no capacity is available.
    pub fn try_admit(&self, agent: &str) -> Result<AdmissionPermit, OracleMcpError> {
        let agent_sem = self.agent_semaphore(agent);
        let agent_permit = agent_sem
            .try_acquire_owned()
            .map_err(|_| OracleMcpError::Busy {
                retry_after_ms: self.retry_after_ms,
            })?;
        let global_permit =
            Arc::clone(&self.global)
                .try_acquire_owned()
                .map_err(|_| OracleMcpError::Busy {
                    retry_after_ms: self.retry_after_ms,
                })?;
        // agent_permit released on the early-return above if global fails.
        Ok(AdmissionPermit {
            _global: global_permit,
            _agent: agent_permit,
        })
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_up_to_global_cap_then_busy() {
        let ctrl = AdmissionController::new(2, 10);
        let p1 = ctrl.try_admit("a").expect("1");
        let p2 = ctrl.try_admit("b").expect("2");
        // Global cap (2) reached -> BUSY.
        assert!(matches!(
            ctrl.try_admit("c"),
            Err(OracleMcpError::Busy { .. })
        ));
        drop(p1);
        // Capacity returned -> admits again.
        let _p3 = ctrl.try_admit("c").expect("3 after release");
        drop(p2);
    }

    #[test]
    fn per_agent_cap_isolates_a_noisy_agent() {
        let ctrl = AdmissionController::new(100, 2);
        let _a1 = ctrl.try_admit("noisy").expect("a1");
        let _a2 = ctrl.try_admit("noisy").expect("a2");
        // The noisy agent hits its own cap (2) while the global pool is free.
        assert!(matches!(
            ctrl.try_admit("noisy"),
            Err(OracleMcpError::Busy { .. })
        ));
        // A different agent is unaffected.
        let _b1 = ctrl.try_admit("quiet").expect("other agent admitted");
    }

    #[test]
    fn busy_envelope_carries_retry_after() {
        let ctrl = AdmissionController::new(1, 1);
        let env = ctrl.busy_envelope();
        assert_eq!(env.retry_after_ms, Some(DEFAULT_RETRY_AFTER_MS));
    }

    #[test]
    fn permit_release_restores_global_capacity() {
        let ctrl = AdmissionController::new(1, 5);
        assert_eq!(ctrl.available_global(), 1);
        let p = ctrl.try_admit("a").expect("admit");
        assert_eq!(ctrl.available_global(), 0);
        drop(p);
        assert_eq!(ctrl.available_global(), 1);
    }
}
