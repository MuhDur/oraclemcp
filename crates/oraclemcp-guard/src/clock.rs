//! Monotonic-deadline primitive for all server TTLs (plan §5.10; beads P0-7,
//! P0-CLK, P1-10).
//!
//! **Why monotonic.** Challenge / lease / elevation-window / preview-token TTLs
//! must never be computed from the wall clock: a backward NTP or VM clock
//! correction makes a naive `now - issued_at` clamp to zero, so an *expired*
//! token reads as fresh and a write window silently extends — a fail-open
//! footgun. [`MonotonicDeadline`] is anchored on [`std::time::Instant`]
//! (monotonic, never moves backward), so a wall-clock jump cannot extend it.
//!
//! **Why a generation nonce.** A deadline is intentionally *not* serializable:
//! the authoritative expiry lives in the server's in-process token store and
//! the agent only ever holds an opaque handle. The per-process
//! [`process_generation`] nonce is the belt-and-braces guarantee that even if a
//! deadline were reconstructed across a process restart it is treated as
//! expired (fail-closed) — there is no way to revive a window by replaying a
//! prior process's state.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// A nonce that is stable within a process and differs across restarts with
/// overwhelming probability. Used only to fail-close a deadline whose anchor
/// is from a prior process generation — never for expiry arithmetic.
fn process_generation() -> u64 {
    static GEN: OnceLock<u64> = OnceLock::new();
    *GEN.get_or_init(|| {
        // Wall clock at *startup* is a fine generation nonce (it only needs to
        // differ across restarts); it is never used for TTL arithmetic.
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        nanos ^ u64::from(std::process::id()).wrapping_mul(0x9E37_79B9_7F4A_7C15)
    })
}

/// A monotonic expiry deadline. Cheap to copy; not serializable by design.
#[derive(Debug, Clone, Copy)]
pub struct MonotonicDeadline {
    deadline: Instant,
    generation: u64,
}

impl MonotonicDeadline {
    /// A deadline `ttl` from now, anchored on the monotonic clock and the
    /// current process generation.
    #[must_use]
    pub fn after(ttl: Duration) -> Self {
        MonotonicDeadline {
            deadline: Instant::now().checked_add(ttl).unwrap_or_else(Instant::now),
            generation: process_generation(),
        }
    }

    /// Whether the deadline has passed. A deadline whose generation does not
    /// match the current process is **always** expired (fail-closed) — a stale
    /// generation can never read as fresh.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.generation != process_generation() || Instant::now() >= self.deadline
    }

    /// Time remaining, or zero if expired.
    #[must_use]
    pub fn remaining(&self) -> Duration {
        if self.is_expired() {
            Duration::ZERO
        } else {
            self.deadline.saturating_duration_since(Instant::now())
        }
    }

    /// A deadline already in the past (test helper).
    #[cfg(test)]
    #[must_use]
    pub fn already_expired() -> Self {
        MonotonicDeadline {
            deadline: Instant::now(),
            generation: process_generation(),
        }
    }

    /// A non-expired deadline carrying a *prior*-generation nonce, to prove the
    /// fail-closed generation check (test helper).
    #[cfg(test)]
    #[must_use]
    pub fn stale_generation() -> Self {
        MonotonicDeadline {
            deadline: Instant::now() + Duration::from_secs(3600),
            generation: process_generation().wrapping_add(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_deadline_is_not_expired() {
        let d = MonotonicDeadline::after(Duration::from_secs(60));
        assert!(!d.is_expired());
        assert!(d.remaining() > Duration::from_secs(50));
    }

    #[test]
    fn past_deadline_is_expired() {
        let d = MonotonicDeadline::already_expired();
        assert!(d.is_expired());
        assert_eq!(d.remaining(), Duration::ZERO);
    }

    #[test]
    fn stale_generation_is_always_expired() {
        // Even with an hour of nominal time left, a prior-generation anchor is
        // treated as expired — the P0-CLK fail-closed guarantee.
        let d = MonotonicDeadline::stale_generation();
        assert!(d.is_expired());
        assert_eq!(d.remaining(), Duration::ZERO);
    }

    #[test]
    fn zero_ttl_is_immediately_expired() {
        let d = MonotonicDeadline::after(Duration::ZERO);
        assert!(d.is_expired());
    }
}
