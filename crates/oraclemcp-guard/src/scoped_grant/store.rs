//! The in-process scoped-grant lifecycle store.
//!
//! A grant is pinned to the [`ExecGrantBinding`] that minted it: it is visible
//! only to that session/lane/subject, and it dies on TTL, explicit drop, and any
//! lane generation change (reconnect and profile switch bump the generation).
//! A dead grant leaves a tombstone until its original deadline, so a lookup
//! answers a typed `Revoked`/`Expired` instead of silently `Unknown`; the
//! tombstone drops the grant (and with it the zeroizing predicate values)
//! immediately. Atomic reserve/finalize accounting is T13.5.
//!
//! Capacity is bounded by [`MAX_LIVE_SCOPED_GRANTS`]. Unlike the single-use
//! execution grant store, a full store **refuses** a new grant rather than
//! evicting a live one: eviction would let one session revoke another's grant.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::clock::MonotonicDeadline;
use crate::exec_grant::ExecGrantBinding;

use super::{ScopedGrant, hex};

/// Hard cap on grants (live plus tombstones) held by one store.
pub const MAX_LIVE_SCOPED_GRANTS: usize = 1024;

/// Why a grant was suspended (it can no longer be used; T13.5 owns resume).
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SuspendReason {
    /// The target's catalog identity or `LAST_DDL_TIME` drifted.
    TargetDrift,
    /// The DML effect closure changed.
    ClosureDrift,
    /// The recorded scope digest no longer recomputes.
    DigestMismatch,
    /// An operator suspended it.
    Operator,
}

/// The lifecycle state of a grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrantState {
    /// Usable (subject to per-use checks).
    Active,
    /// Temporarily unusable.
    Suspended {
        /// Why.
        reason: SuspendReason,
    },
    /// Dropped, or killed by a generation change. Terminal.
    Revoked,
    /// The TTL passed. Terminal.
    Expired,
}

/// Why a lookup refused.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopedGrantLookupError {
    /// Never issued, or purged.
    Unknown,
    /// The TTL passed.
    Expired,
    /// Dropped or killed by a generation change.
    Revoked,
    /// Suspended.
    Suspended {
        /// Why.
        reason: SuspendReason,
    },
    /// Presented by a different session.
    SessionMismatch,
    /// Presented on a different lane.
    LaneMismatch,
    /// Presented by a different subject.
    SubjectMismatch,
    /// The lane generation differs from the minting generation.
    GenerationMismatch {
        /// The generation presented.
        presented: u64,
        /// The generation the grant was minted under.
        granted: u64,
    },
    /// The store is at [`MAX_LIVE_SCOPED_GRANTS`]; nothing was evicted.
    StoreFull,
}

impl ScopedGrantLookupError {
    /// The stable machine-readable refusal code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            ScopedGrantLookupError::Unknown => "GRANT_UNKNOWN",
            ScopedGrantLookupError::Expired => "GRANT_EXPIRED",
            ScopedGrantLookupError::Revoked => "GRANT_REVOKED",
            ScopedGrantLookupError::Suspended { .. } => "GRANT_SUSPENDED",
            ScopedGrantLookupError::SessionMismatch
            | ScopedGrantLookupError::LaneMismatch
            | ScopedGrantLookupError::SubjectMismatch => "GRANT_BINDING_MISMATCH",
            ScopedGrantLookupError::GenerationMismatch { .. } => "GRANT_GENERATION_MISMATCH",
            ScopedGrantLookupError::StoreFull => "GRANT_STORE_FULL",
        }
    }
}

/// A redacted listing row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedGrantSummary {
    /// The raw grant id (sign it with [`super::SignedGrantRef`] before handing
    /// it to a client).
    pub id: String,
    /// Lifecycle state.
    pub state: GrantState,
    /// Hex keyed scope digest.
    pub scope_digest: String,
    /// Time left before expiry.
    pub remaining: Duration,
}

struct GrantEntry {
    binding: ExecGrantBinding,
    deadline: MonotonicDeadline,
    state: GrantState,
    scope_digest: [u8; 32],
    /// `None` once the grant is dead: a tombstone keeps no predicate values.
    grant: Option<Arc<ScopedGrant>>,
}

impl GrantEntry {
    fn kill(&mut self, state: GrantState) {
        self.state = state;
        self.grant = None;
    }

    fn is_live(&self) -> bool {
        matches!(
            self.state,
            GrantState::Active | GrantState::Suspended { .. }
        )
    }

    /// Settle expiry: an expired live grant becomes an `Expired` tombstone.
    fn settle(&mut self) {
        if self.is_live() && self.deadline.is_expired() {
            self.kill(GrantState::Expired);
        }
    }
}

fn check_identity(
    entry: &ExecGrantBinding,
    presented: &ExecGrantBinding,
) -> Result<(), ScopedGrantLookupError> {
    if entry.session_id != presented.session_id {
        return Err(ScopedGrantLookupError::SessionMismatch);
    }
    if entry.lane_id != presented.lane_id {
        return Err(ScopedGrantLookupError::LaneMismatch);
    }
    if entry.subject_id != presented.subject_id {
        return Err(ScopedGrantLookupError::SubjectMismatch);
    }
    Ok(())
}

/// In-process store of scoped grants keyed by an opaque id.
#[derive(Default)]
pub struct ScopedGrantStore {
    entries: Mutex<HashMap<String, GrantEntry>>,
    counter: AtomicU64,
}

impl ScopedGrantStore {
    /// A new empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store `grant`, starting its TTL now. Returns the raw grant id.
    ///
    /// Expired entries are purged first, then tombstones are dropped if
    /// needed; if the store is still full the grant is refused
    /// ([`ScopedGrantLookupError::StoreFull`]) — a live grant is never evicted.
    pub fn issue(&self, grant: ScopedGrant) -> Result<String, ScopedGrantLookupError> {
        let mut entries = self.entries.lock().expect("poisoned");
        entries.retain(|_, entry| !entry.deadline.is_expired());
        if entries.len() >= MAX_LIVE_SCOPED_GRANTS {
            entries.retain(|_, entry| entry.is_live());
        }
        if entries.len() >= MAX_LIVE_SCOPED_GRANTS {
            return Err(ScopedGrantLookupError::StoreFull);
        }
        let id = format!(
            "sgrant-{}-{}",
            std::process::id(),
            self.counter.fetch_add(1, Ordering::SeqCst)
        );
        entries.insert(
            id.clone(),
            GrantEntry {
                binding: grant.binding().clone(),
                deadline: MonotonicDeadline::after(grant.ttl()),
                state: GrantState::Active,
                scope_digest: grant.scope_digest(),
                grant: Some(Arc::new(grant)),
            },
        );
        Ok(id)
    }

    /// Look up grant `id` for `binding`. Only an `Active` grant presented by
    /// its own session/lane/subject at its minting generation is returned. A
    /// presented generation *newer* than the minting one means the lane moved
    /// on (reconnect or profile switch), so the grant is revoked on the spot.
    pub fn get(
        &self,
        id: &str,
        binding: &ExecGrantBinding,
    ) -> Result<Arc<ScopedGrant>, ScopedGrantLookupError> {
        let mut entries = self.entries.lock().expect("poisoned");
        let entry = entries.get_mut(id).ok_or(ScopedGrantLookupError::Unknown)?;
        check_identity(&entry.binding, binding)?;
        entry.settle();
        if entry.is_live() && binding.generation != entry.binding.generation {
            let granted = entry.binding.generation;
            if binding.generation > granted {
                entry.kill(GrantState::Revoked);
            }
            return Err(ScopedGrantLookupError::GenerationMismatch {
                presented: binding.generation,
                granted,
            });
        }
        match (&entry.state, &entry.grant) {
            (GrantState::Active, Some(grant)) => Ok(Arc::clone(grant)),
            (GrantState::Suspended { reason }, _) => Err(ScopedGrantLookupError::Suspended {
                reason: reason.clone(),
            }),
            (GrantState::Expired, _) => Err(ScopedGrantLookupError::Expired),
            (GrantState::Revoked, _) | (GrantState::Active, None) => {
                Err(ScopedGrantLookupError::Revoked)
            }
        }
    }

    /// Redacted rows for every grant held by `binding`'s session/lane/subject
    /// (any generation, so a caller can see what a reconnect killed).
    #[must_use]
    pub fn list_for_binding(&self, binding: &ExecGrantBinding) -> Vec<ScopedGrantSummary> {
        let mut entries = self.entries.lock().expect("poisoned");
        let mut rows = entries
            .iter_mut()
            .filter(|(_, entry)| check_identity(&entry.binding, binding).is_ok())
            .map(|(id, entry)| {
                entry.settle();
                ScopedGrantSummary {
                    id: id.clone(),
                    state: entry.state.clone(),
                    scope_digest: hex(&entry.scope_digest),
                    remaining: entry.deadline.remaining(),
                }
            })
            .collect::<Vec<_>>();
        rows.sort_by(|a, b| a.id.cmp(&b.id));
        rows
    }

    /// Drop (revoke) grant `id` on behalf of its own session/lane/subject.
    pub fn drop_grant(
        &self,
        id: &str,
        binding: &ExecGrantBinding,
    ) -> Result<(), ScopedGrantLookupError> {
        let mut entries = self.entries.lock().expect("poisoned");
        let entry = entries.get_mut(id).ok_or(ScopedGrantLookupError::Unknown)?;
        check_identity(&entry.binding, binding)?;
        entry.settle();
        match entry.state {
            GrantState::Expired => Err(ScopedGrantLookupError::Expired),
            GrantState::Revoked => Err(ScopedGrantLookupError::Revoked),
            GrantState::Active | GrantState::Suspended { .. } => {
                entry.kill(GrantState::Revoked);
                Ok(())
            }
        }
    }

    /// Server-side suspension of a live grant (drift detected, operator).
    pub fn suspend(&self, id: &str, reason: SuspendReason) -> Result<(), ScopedGrantLookupError> {
        let mut entries = self.entries.lock().expect("poisoned");
        let entry = entries.get_mut(id).ok_or(ScopedGrantLookupError::Unknown)?;
        entry.settle();
        match entry.state {
            GrantState::Expired => Err(ScopedGrantLookupError::Expired),
            GrantState::Revoked => Err(ScopedGrantLookupError::Revoked),
            GrantState::Active | GrantState::Suspended { .. } => {
                entry.state = GrantState::Suspended { reason };
                Ok(())
            }
        }
    }

    /// The lane `(session_id, lane_id)` is now at `current_generation`: revoke
    /// every live grant of that lane minted under another generation. Returns
    /// the number revoked. Call on reconnect and profile/level switch.
    pub fn invalidate_generation(
        &self,
        session_id: &str,
        lane_id: &str,
        current_generation: u64,
    ) -> usize {
        let mut entries = self.entries.lock().expect("poisoned");
        let mut revoked = 0;
        for entry in entries.values_mut() {
            if entry.binding.session_id == session_id
                && entry.binding.lane_id == lane_id
                && entry.binding.generation != current_generation
                && entry.is_live()
            {
                entry.kill(GrantState::Revoked);
                revoked += 1;
            }
        }
        revoked
    }

    /// Remove every entry (live or tombstone) whose deadline passed. Returns
    /// the count removed; those ids now look up as `Unknown`.
    pub fn purge_expired(&self) -> usize {
        let mut entries = self.entries.lock().expect("poisoned");
        let before = entries.len();
        entries.retain(|_, entry| !entry.deadline.is_expired());
        before - entries.len()
    }

    /// Revoke every live grant (key rotation, shutdown). Returns the count.
    pub fn revoke_all(&self) -> usize {
        let mut entries = self.entries.lock().expect("poisoned");
        let mut revoked = 0;
        for entry in entries.values_mut().filter(|entry| entry.is_live()) {
            entry.kill(GrantState::Revoked);
            revoked += 1;
        }
        revoked
    }
}
