//! The honest allow-once token (plan §5.5; bead P1-6).
//!
//! **This is friction + an audit artifact, NOT a security control.** The agent
//! is the untrusted party and can self-issue the token, so it can never be a
//! boundary. The real boundaries are the DB-privilege ceiling and the human
//! step-up confirmation. The token's only jobs are: (a) make the agent take a
//! deliberate second step, and (b) bind that step to a specific SQL digest so a
//! later `execute` can verify it is the same statement that was previewed.
//!
//! Tokens live in an in-process store keyed by an opaque id; the authoritative
//! single-use + expiry state is server-side (the agent only holds the id), and
//! the deadline is monotonic (P0-CLK) so a clock jump cannot extend it.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::clock::MonotonicDeadline;

/// Default TTL for an allow-once token.
pub const ALLOW_ONCE_TTL: Duration = Duration::from_secs(60);

/// Why consuming an allow-once token failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AllowOnceError {
    /// The token id is unknown (never issued, already consumed, or purged).
    Unknown,
    /// The token has expired (monotonic deadline passed).
    Expired,
    /// The presented SQL digest does not match the previewed statement.
    DigestMismatch,
}

struct Entry {
    sql_digest: String,
    deadline: MonotonicDeadline,
}

/// An in-process, single-use, SQL-digest-bound allow-once token store.
#[derive(Default)]
pub struct AllowOnceStore {
    entries: Mutex<HashMap<String, Entry>>,
    counter: AtomicU64,
}

/// SHA-256 (`sha256:<hex>`) of the exact SQL bytes.
///
/// Authorization bindings deliberately do not normalize whitespace or case:
/// both are semantic inside Oracle quoted identifiers and literals. The
/// statement presented for execution must therefore be byte-identical to the
/// statement that was reviewed.
#[must_use]
pub fn sql_digest(sql: &str) -> String {
    let digest = Sha256::digest(sql.as_bytes());
    let mut out = String::with_capacity(7 + digest.len() * 2);
    out.push_str("sha256:");
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

impl AllowOnceStore {
    /// A new empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue a token bound to `sql`'s digest, valid for `ttl`. Returns the
    /// opaque token id the agent echoes back.
    pub fn issue(&self, sql: &str, ttl: Duration) -> String {
        let id = format!(
            "aot-{}-{}",
            std::process::id(),
            self.counter.fetch_add(1, Ordering::SeqCst)
        );
        self.entries.lock().expect("poisoned").insert(
            id.clone(),
            Entry {
                sql_digest: sql_digest(sql),
                deadline: MonotonicDeadline::after(ttl),
            },
        );
        id
    }

    /// Consume `token` for `sql`: single-use, expiry-checked, and digest-bound.
    /// On success the token is removed (cannot be replayed).
    pub fn consume(&self, token: &str, sql: &str) -> Result<(), AllowOnceError> {
        let mut entries = self.entries.lock().expect("poisoned");
        let entry = entries.get(token).ok_or(AllowOnceError::Unknown)?;
        if entry.deadline.is_expired() {
            entries.remove(token);
            return Err(AllowOnceError::Expired);
        }
        if entry.sql_digest != sql_digest(sql) {
            // A mismatch does NOT consume the token (the right SQL can retry).
            return Err(AllowOnceError::DigestMismatch);
        }
        entries.remove(token); // single-use
        Ok(())
    }

    /// Drop expired tokens; returns the count removed.
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

    #[test]
    fn consume_is_single_use_and_digest_bound() {
        let store = AllowOnceStore::new();
        let sql = "UPDATE orders SET status='X' WHERE id=42";
        let tok = store.issue(sql, ALLOW_ONCE_TTL);
        // Wrong SQL -> mismatch, token NOT consumed.
        assert_eq!(
            store.consume(&tok, "DROP TABLE orders"),
            Err(AllowOnceError::DigestMismatch)
        );
        // The exact approved SQL succeeds and consumes the token.
        assert_eq!(store.consume(&tok, sql), Ok(()));
        // Replay -> unknown.
        assert_eq!(store.consume(&tok, sql), Err(AllowOnceError::Unknown));
    }

    #[test]
    fn expired_token_is_rejected_and_purged() {
        let store = AllowOnceStore::new();
        let tok = store.issue("SELECT 1 FROM dual", Duration::from_secs(0));
        assert_eq!(
            store.consume(&tok, "SELECT 1 FROM dual"),
            Err(AllowOnceError::Expired)
        );
        // Already removed on the failed consume.
        assert_eq!(
            store.consume(&tok, "SELECT 1 FROM dual"),
            Err(AllowOnceError::Unknown)
        );
    }

    #[test]
    fn purge_drops_expired() {
        let store = AllowOnceStore::new();
        store.issue("a", Duration::from_secs(0));
        store.issue("b", Duration::from_secs(3600));
        assert_eq!(store.purge_expired(), 1);
    }

    #[test]
    fn purge_keeps_fresh_tokens() {
        let store = AllowOnceStore::new();
        store.issue("a", Duration::from_secs(3600));
        store.issue("b", Duration::from_secs(3600));
        assert_eq!(store.purge_expired(), 0);
    }
}
