//! The execution grant (plan §5.5, §8.1; bead P1-QE / oracle-qmwz.2.16).
//!
//! When `oracle_query` classifies a write statement and the step-up gate
//! approves an operating level, the server mints an [`ExecGrant`] bound to the
//! SQL digest, the issuing session, the granted operating level, and a
//! **monotonic** deadline (P0-CLK). `oracle_query_execute` later consumes it,
//! validating all four invariants before the statement runs:
//!
//! - **single-use** — a consumed grant cannot be replayed;
//! - **digest match** — the executed SQL must be byte-for-byte (whitespace-
//!   normalized) the statement that was approved;
//! - **session match** — the grant is pinned to the session that requested it;
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

/// Why consuming an [`ExecGrant`] failed. Validation failures other than
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
    /// The requested operating level exceeds the granted level.
    LevelExceedsGrant {
        /// The level the caller asked to run at.
        requested: OperatingLevel,
        /// The level the grant actually authorizes.
        granted: OperatingLevel,
    },
}

struct Entry {
    sql_digest: String,
    session_id: String,
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

    /// Mint a grant binding `sql`, `session_id`, and `granted_level` for `ttl`.
    /// Returns the opaque token id the agent echoes back to `oracle_query_execute`.
    pub fn issue(
        &self,
        sql: &str,
        session_id: impl Into<String>,
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
                session_id: session_id.into(),
                granted_level,
                deadline: MonotonicDeadline::after(ttl),
            },
        );
        id
    }

    /// Consume `token` to run `sql` in `session_id` at `requested_level`.
    /// Validates single-use, expiry, digest, session, and level; on success the
    /// grant is removed (cannot be replayed) and the **granted** level returned.
    pub fn consume(
        &self,
        token: &str,
        sql: &str,
        session_id: &str,
        requested_level: OperatingLevel,
    ) -> Result<OperatingLevel, ExecGrantError> {
        let mut entries = self.entries.lock().expect("poisoned");
        let entry = entries.get(token).ok_or(ExecGrantError::Unknown)?;
        if entry.deadline.is_expired() {
            entries.remove(token);
            return Err(ExecGrantError::Expired);
        }
        // Non-consuming validation failures (a correct retry may still succeed).
        if entry.session_id != session_id {
            return Err(ExecGrantError::SessionMismatch);
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
}

#[cfg(test)]
mod tests {
    use super::*;

    const SQL: &str = "UPDATE orders SET status='X' WHERE id=42";
    const TTL: Duration = Duration::from_secs(60);

    #[test]
    fn valid_grant_runs_once_then_replay_is_rejected() {
        let store = ExecGrantStore::new();
        let tok = store.issue(SQL, "sess-1", OperatingLevel::ReadWrite, TTL);
        // Whitespace-insensitive digest match, same session, level <= grant.
        assert_eq!(
            store.consume(
                &tok,
                "UPDATE   orders SET status='X' WHERE id=42",
                "sess-1",
                OperatingLevel::ReadWrite
            ),
            Ok(OperatingLevel::ReadWrite)
        );
        // Replay -> unknown (single-use).
        assert_eq!(
            store.consume(&tok, SQL, "sess-1", OperatingLevel::ReadWrite),
            Err(ExecGrantError::Unknown)
        );
    }

    #[test]
    fn digest_mismatch_does_not_consume() {
        let store = ExecGrantStore::new();
        let tok = store.issue(SQL, "sess-1", OperatingLevel::ReadWrite, TTL);
        assert_eq!(
            store.consume(
                &tok,
                "DROP TABLE orders",
                "sess-1",
                OperatingLevel::ReadWrite
            ),
            Err(ExecGrantError::DigestMismatch)
        );
        // Not consumed: the correct SQL still works.
        assert_eq!(
            store.consume(&tok, SQL, "sess-1", OperatingLevel::ReadWrite),
            Ok(OperatingLevel::ReadWrite)
        );
    }

    #[test]
    fn session_mismatch_is_rejected_without_consuming() {
        let store = ExecGrantStore::new();
        let tok = store.issue(SQL, "sess-1", OperatingLevel::ReadWrite, TTL);
        assert_eq!(
            store.consume(&tok, SQL, "other-session", OperatingLevel::ReadWrite),
            Err(ExecGrantError::SessionMismatch)
        );
        assert_eq!(
            store.consume(&tok, SQL, "sess-1", OperatingLevel::ReadWrite),
            Ok(OperatingLevel::ReadWrite)
        );
    }

    #[test]
    fn requesting_above_the_granted_level_is_rejected() {
        let store = ExecGrantStore::new();
        let tok = store.issue("DROP TABLE t", "s", OperatingLevel::ReadWrite, TTL);
        assert_eq!(
            store.consume(&tok, "DROP TABLE t", "s", OperatingLevel::Ddl),
            Err(ExecGrantError::LevelExceedsGrant {
                requested: OperatingLevel::Ddl,
                granted: OperatingLevel::ReadWrite,
            })
        );
        // A request AT the granted level is fine, and consumes the grant.
        assert_eq!(
            store.consume(&tok, "DROP TABLE t", "s", OperatingLevel::ReadWrite),
            Ok(OperatingLevel::ReadWrite)
        );
    }

    #[test]
    fn expired_grant_is_rejected_and_purged() {
        let store = ExecGrantStore::new();
        let tok = store.issue(SQL, "s", OperatingLevel::ReadWrite, Duration::from_secs(0));
        assert_eq!(
            store.consume(&tok, SQL, "s", OperatingLevel::ReadWrite),
            Err(ExecGrantError::Expired)
        );
        assert_eq!(
            store.consume(&tok, SQL, "s", OperatingLevel::ReadWrite),
            Err(ExecGrantError::Unknown)
        );
    }

    #[test]
    fn purge_drops_only_expired() {
        let store = ExecGrantStore::new();
        store.issue("a", "s", OperatingLevel::ReadWrite, Duration::from_secs(0));
        store.issue(
            "b",
            "s",
            OperatingLevel::ReadWrite,
            Duration::from_secs(3600),
        );
        assert_eq!(store.purge_expired(), 1);
    }
}
