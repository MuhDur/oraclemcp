//! The execution grant (plan §5.5, §8.1; bead P1-QE / oracle-qmwz.2.16).
//!
//! When `oracle_query` classifies a write statement and the step-up gate
//! approves an operating level, the server mints an execution grant bound to the
//! SQL digest, the issuing lane/session/subject binding, the lane generation,
//! the granted operating level, and a **monotonic** deadline (P0-CLK).
//! `oracle_query_execute` later consumes it, validating those invariants before
//! the statement runs:
//!
//! - **single-use** — a consumed grant cannot be replayed;
//! - **digest match** — the executed SQL must be byte-for-byte (whitespace-
//!   normalized) the statement that was approved;
//! - **binding match** — the grant is pinned to the lane/session/subject that
//!   requested it;
//! - **generation match** — a grant minted before profile/level generation
//!   changes cannot be replayed after the change;
//! - **not expired** — the monotonic deadline has not passed;
//! - **level not exceeded** — the requested level is ≤ the granted level.
//!
//! Like the allow-once token ([`crate::token`]) this is **friction + an audit
//! artifact, not a security boundary** — the agent is untrusted and the real
//! walls are the DB-privilege ceiling and the human step-up. The grant only
//! ensures the *execute* call runs exactly the approved statement, once, at no
//! more than the approved level.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::clock::MonotonicDeadline;
use crate::levels::OperatingLevel;
use crate::token::sql_digest;

/// Why consuming an execution grant failed. Validation failures other than
/// `Expired` do **not** consume the grant (a correct retry can still succeed);
/// `Expired` removes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExecGrantError {
    /// The token is unknown — never issued, already consumed (replay), or purged.
    Unknown,
    /// The monotonic deadline has passed (the grant is removed).
    Expired,
    /// The presented SQL does not match the approved statement's digest.
    DigestMismatch,
    /// The presented session id does not match the grant's session.
    SessionMismatch,
    /// The presented lane id does not match the grant's lane.
    LaneMismatch,
    /// The presented subject id does not match the grant's subject.
    SubjectMismatch,
    /// The lane/profile generation changed after the grant was minted.
    GenerationMismatch {
        /// The generation presented by the caller.
        presented: u64,
        /// The generation captured when the grant was minted.
        granted: u64,
    },
    /// The requested operating level exceeds the granted level.
    LevelExceedsGrant {
        /// The level the caller asked to run at.
        requested: OperatingLevel,
        /// The level the grant actually authorizes.
        granted: OperatingLevel,
    },
}

/// The non-secret lane binding captured when an execution grant is minted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecGrantBinding {
    /// MCP Streamable HTTP session id or equivalent server-owned session key.
    pub session_id: String,
    /// Server-assigned lane id.
    pub lane_id: String,
    /// Verified, server-derived subject/principal id.
    pub subject_id: String,
    /// Monotonic lane/profile/level generation.
    pub generation: u64,
}

impl ExecGrantBinding {
    /// Build a binding from already-verified, non-secret lane identity values.
    #[must_use]
    pub fn new(
        session_id: impl Into<String>,
        lane_id: impl Into<String>,
        subject_id: impl Into<String>,
        generation: u64,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            lane_id: lane_id.into(),
            subject_id: subject_id.into(),
            generation,
        }
    }
}

struct Entry {
    sql_digest: String,
    binding: ExecGrantBinding,
    granted_level: OperatingLevel,
    deadline: MonotonicDeadline,
}

/// An in-process, single-use store of execution grants keyed by an opaque id.
#[derive(Default)]
pub struct ExecGrantStore {
    entries: Mutex<HashMap<String, Entry>>,
    counter: AtomicU64,
}

impl ExecGrantStore {
    /// A new empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a grant binding `sql`, `binding`, and `granted_level` for `ttl`.
    /// Returns the opaque token id the agent echoes back to `oracle_query_execute`.
    pub fn issue(
        &self,
        sql: &str,
        binding: ExecGrantBinding,
        granted_level: OperatingLevel,
        ttl: Duration,
    ) -> String {
        let id = format!(
            "xgrant-{}-{}",
            std::process::id(),
            self.counter.fetch_add(1, Ordering::SeqCst)
        );
        self.entries.lock().expect("poisoned").insert(
            id.clone(),
            Entry {
                sql_digest: sql_digest(sql),
                binding,
                granted_level,
                deadline: MonotonicDeadline::after(ttl),
            },
        );
        id
    }

    /// Consume `token` to run `sql` under `binding` at `requested_level`.
    /// Validates single-use, expiry, digest, lane/session/subject binding,
    /// generation, and level; on success the grant is removed (cannot be
    /// replayed) and the **granted** level returned.
    pub fn consume(
        &self,
        token: &str,
        sql: &str,
        binding: &ExecGrantBinding,
        requested_level: OperatingLevel,
    ) -> Result<OperatingLevel, ExecGrantError> {
        let mut entries = self.entries.lock().expect("poisoned");
        let entry = entries.get(token).ok_or(ExecGrantError::Unknown)?;
        if entry.deadline.is_expired() {
            entries.remove(token);
            return Err(ExecGrantError::Expired);
        }
        // Non-consuming validation failures (a correct retry may still succeed).
        if entry.binding.session_id != binding.session_id {
            return Err(ExecGrantError::SessionMismatch);
        }
        if entry.binding.lane_id != binding.lane_id {
            return Err(ExecGrantError::LaneMismatch);
        }
        if entry.binding.subject_id != binding.subject_id {
            return Err(ExecGrantError::SubjectMismatch);
        }
        if entry.binding.generation != binding.generation {
            return Err(ExecGrantError::GenerationMismatch {
                presented: binding.generation,
                granted: entry.binding.generation,
            });
        }
        if entry.sql_digest != sql_digest(sql) {
            return Err(ExecGrantError::DigestMismatch);
        }
        if requested_level > entry.granted_level {
            return Err(ExecGrantError::LevelExceedsGrant {
                requested: requested_level,
                granted: entry.granted_level,
            });
        }
        let granted = entry.granted_level;
        entries.remove(token); // single-use
        Ok(granted)
    }

    /// Drop expired grants; returns the count removed.
    pub fn purge_expired(&self) -> usize {
        let mut entries = self.entries.lock().expect("poisoned");
        let before = entries.len();
        entries.retain(|_, e| !e.deadline.is_expired());
        before - entries.len()
    }

    /// Drop all in-process grants, for example after a lane profile/level
    /// generation transition. Existing client tokens become unknown.
    pub fn clear(&self) {
        self.entries.lock().expect("poisoned").clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SQL: &str = "UPDATE orders SET status='X' WHERE id=42";
    const TTL: Duration = Duration::from_secs(60);

    fn binding() -> ExecGrantBinding {
        ExecGrantBinding::new("sess-1", "lane-1", "subject-1", 1)
    }

    #[test]
    fn valid_grant_runs_once_then_replay_is_rejected() {
        let store = ExecGrantStore::new();
        let binding = binding();
        let tok = store.issue(SQL, binding.clone(), OperatingLevel::ReadWrite, TTL);
        // Whitespace-insensitive digest match, same session, level <= grant.
        assert_eq!(
            store.consume(
                &tok,
                "UPDATE   orders SET status='X' WHERE id=42",
                &binding,
                OperatingLevel::ReadWrite
            ),
            Ok(OperatingLevel::ReadWrite)
        );
        // Replay -> unknown (single-use).
        assert_eq!(
            store.consume(&tok, SQL, &binding, OperatingLevel::ReadWrite),
            Err(ExecGrantError::Unknown)
        );
    }

    #[test]
    fn digest_mismatch_does_not_consume() {
        let store = ExecGrantStore::new();
        let binding = binding();
        let tok = store.issue(SQL, binding.clone(), OperatingLevel::ReadWrite, TTL);
        assert_eq!(
            store.consume(
                &tok,
                "DROP TABLE orders",
                &binding,
                OperatingLevel::ReadWrite
            ),
            Err(ExecGrantError::DigestMismatch)
        );
        // Not consumed: the correct SQL still works.
        assert_eq!(
            store.consume(&tok, SQL, &binding, OperatingLevel::ReadWrite),
            Ok(OperatingLevel::ReadWrite)
        );
    }

    #[test]
    fn session_mismatch_is_rejected_without_consuming() {
        let store = ExecGrantStore::new();
        let binding = binding();
        let tok = store.issue(SQL, binding.clone(), OperatingLevel::ReadWrite, TTL);
        let other_session = ExecGrantBinding::new("other-session", "lane-1", "subject-1", 1);
        assert_eq!(
            store.consume(&tok, SQL, &other_session, OperatingLevel::ReadWrite),
            Err(ExecGrantError::SessionMismatch)
        );
        assert_eq!(
            store.consume(&tok, SQL, &binding, OperatingLevel::ReadWrite),
            Ok(OperatingLevel::ReadWrite)
        );
    }

    #[test]
    fn lane_subject_and_generation_mismatch_do_not_consume() {
        let store = ExecGrantStore::new();
        let binding = binding();

        let lane_tok = store.issue(SQL, binding.clone(), OperatingLevel::ReadWrite, TTL);
        let other_lane = ExecGrantBinding::new("sess-1", "lane-2", "subject-1", 1);
        assert_eq!(
            store.consume(&lane_tok, SQL, &other_lane, OperatingLevel::ReadWrite),
            Err(ExecGrantError::LaneMismatch)
        );
        assert_eq!(
            store.consume(&lane_tok, SQL, &binding, OperatingLevel::ReadWrite),
            Ok(OperatingLevel::ReadWrite)
        );

        let subject_tok = store.issue(SQL, binding.clone(), OperatingLevel::ReadWrite, TTL);
        let other_subject = ExecGrantBinding::new("sess-1", "lane-1", "subject-2", 1);
        assert_eq!(
            store.consume(&subject_tok, SQL, &other_subject, OperatingLevel::ReadWrite),
            Err(ExecGrantError::SubjectMismatch)
        );
        assert_eq!(
            store.consume(&subject_tok, SQL, &binding, OperatingLevel::ReadWrite),
            Ok(OperatingLevel::ReadWrite)
        );

        let generation_tok = store.issue(SQL, binding.clone(), OperatingLevel::ReadWrite, TTL);
        let stale_generation = ExecGrantBinding::new("sess-1", "lane-1", "subject-1", 2);
        assert_eq!(
            store.consume(
                &generation_tok,
                SQL,
                &stale_generation,
                OperatingLevel::ReadWrite
            ),
            Err(ExecGrantError::GenerationMismatch {
                presented: 2,
                granted: 1,
            })
        );
        assert_eq!(
            store.consume(&generation_tok, SQL, &binding, OperatingLevel::ReadWrite),
            Ok(OperatingLevel::ReadWrite)
        );
    }

    #[test]
    fn requesting_above_the_granted_level_is_rejected() {
        let store = ExecGrantStore::new();
        let binding = ExecGrantBinding::new("s", "lane", "subject", 1);
        let tok = store.issue(
            "DROP TABLE t",
            binding.clone(),
            OperatingLevel::ReadWrite,
            TTL,
        );
        assert_eq!(
            store.consume(&tok, "DROP TABLE t", &binding, OperatingLevel::Ddl),
            Err(ExecGrantError::LevelExceedsGrant {
                requested: OperatingLevel::Ddl,
                granted: OperatingLevel::ReadWrite,
            })
        );
        // A request AT the granted level is fine, and consumes the grant.
        assert_eq!(
            store.consume(&tok, "DROP TABLE t", &binding, OperatingLevel::ReadWrite),
            Ok(OperatingLevel::ReadWrite)
        );
    }

    #[test]
    fn expired_grant_is_rejected_and_purged() {
        let store = ExecGrantStore::new();
        let binding = ExecGrantBinding::new("s", "lane", "subject", 1);
        let tok = store.issue(
            SQL,
            binding.clone(),
            OperatingLevel::ReadWrite,
            Duration::from_secs(0),
        );
        assert_eq!(
            store.consume(&tok, SQL, &binding, OperatingLevel::ReadWrite),
            Err(ExecGrantError::Expired)
        );
        assert_eq!(
            store.consume(&tok, SQL, &binding, OperatingLevel::ReadWrite),
            Err(ExecGrantError::Unknown)
        );
    }

    #[test]
    fn purge_drops_only_expired() {
        let store = ExecGrantStore::new();
        let binding = ExecGrantBinding::new("s", "lane", "subject", 1);
        store.issue(
            "a",
            binding.clone(),
            OperatingLevel::ReadWrite,
            Duration::from_secs(0),
        );
        store.issue(
            "b",
            binding,
            OperatingLevel::ReadWrite,
            Duration::from_secs(3600),
        );
        assert_eq!(store.purge_expired(), 1);
    }
}
