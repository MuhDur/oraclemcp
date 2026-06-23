//! Per-request resource bounds via asupersync's [`Budget`] (B6).
//!
//! Before B6 the only per-request bound was the per-profile *call timeout*
//! (`call_timeout_seconds`), which the DB adapter pushes down as an Oracle
//! op-deadline (`OCI_ATTR_CALL_TIMEOUT`). That bounds a single round trip but
//! says nothing about the *whole request*: a runaway tool call that issues many
//! short round trips, or spins in the dispatcher, is not bounded by it.
//!
//! [`RequestBudget`] adopts asupersync's [`Budget`] (a deadline, poll/cost
//! quotas, and a priority, with [`Budget::meet`] propagation) to give the
//! *whole* request a single cooperative bound:
//!
//! * the request gets a [`Budget`] derived from its per-call timeout (or a
//!   default), anchored to the runtime/lab clock so production and lab share one
//!   deterministic time source;
//! * the DB round trips already checkpoint `&Cx` before/after every call, and a
//!   budgeted `Cx` makes those checkpoints fail closed once the deadline or a
//!   quota is exhausted — so a runaway request is bounded **cooperatively**
//!   rather than by killing a thread;
//! * exhaustion maps to the timeout-class [`DbError::Cancelled`], preserving the
//!   `Cancelled`/`Timeout` mapping B1 established (the transport then maps
//!   `Cancelled` to its `499`-style code; a normal request is unaffected);
//! * cleanup/finalizers get a SHORT bounded budget ([`Budget::MINIMAL`] met with
//!   the request budget) so teardown still runs after the request budget is
//!   spent, but can never itself run away.
//!
//! Against the pinned `oracledb` 0.5.0 driver the budget composes with the
//! adapter's per-call timeout: the seam maps this budget's deadline onto the
//! driver's `execute_raw` timeout (see `crates/oraclemcp-db/src/connection.rs`).
//!
//! The type is deliberately small and pure so it is testable with
//! [`Cx::for_testing_with_budget`](asupersync::Cx) / a `LabRuntime` clock with
//! no database in the loop.

use std::time::Duration;

use asupersync::{Budget, Cx, Time};
use oraclemcp_db::DbError;

/// The default per-request deadline when a profile does not set
/// `call_timeout_seconds`. Mirrors `resilience::DEFAULT_CALL_TIMEOUT` (§10) so
/// the request budget and the per-round-trip timeout agree by default.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A poll-quota ceiling for a single request. A request that polls more than
/// this without completing is treated as runaway and bounded. The figure is
/// generous (a healthy request polls far fewer times) so it never trips a
/// normal call; it exists to bound a pathological spin that makes no forward
/// progress against the deadline.
pub const DEFAULT_REQUEST_POLL_QUOTA: u32 = 1_000_000;

/// The poll quota a bounded cleanup/finalize section gets. Matches
/// [`Budget::MINIMAL`]'s 100-poll allowance — enough to roll back, close
/// cursors, and release a lease, but not enough to run away.
pub const CLEANUP_POLL_QUOTA: u32 = 100;

/// A per-request resource budget (B6).
///
/// Wraps an asupersync [`Budget`] with the dispatch-boundary policy: how to
/// derive it from a call timeout, how to bound cleanup, and how exhaustion maps
/// to the timeout-class [`DbError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestBudget {
    budget: Budget,
}

impl RequestBudget {
    /// Derive a request budget from a per-call timeout (or the default when
    /// `None`), anchored to `now` (the runtime/lab clock — pass `cx.now()`).
    ///
    /// The deadline is `now + timeout`; the poll quota is
    /// [`DEFAULT_REQUEST_POLL_QUOTA`]. A zero timeout is floored to 1ns so the
    /// deadline is strictly after `now` (a budget with `deadline == now` would
    /// be born already exhausted).
    #[must_use]
    pub fn from_call_timeout(now: Time, timeout: Option<Duration>) -> Self {
        let timeout = timeout
            .unwrap_or(DEFAULT_REQUEST_TIMEOUT)
            .max(Duration::from_nanos(1));
        let budget = Budget::new()
            .with_timeout(now, timeout)
            .with_poll_quota(DEFAULT_REQUEST_POLL_QUOTA);
        RequestBudget { budget }
    }

    /// Wrap an explicit [`Budget`] (e.g. one already carried by a parent `Cx`).
    #[must_use]
    pub fn from_budget(budget: Budget) -> Self {
        RequestBudget { budget }
    }

    /// The underlying asupersync [`Budget`], for attaching to a request `Cx` or
    /// for `meet`-ing with another budget.
    #[must_use]
    pub fn budget(self) -> Budget {
        self.budget
    }

    /// Combine with another budget, taking the tighter constraint
    /// ([`Budget::meet`]). Use this so a nested/hedged DB op inherits a budget
    /// no looser than its caller (budget propagation is correctness, not just
    /// tuning).
    #[must_use]
    pub fn meet(self, other: Budget) -> Self {
        RequestBudget {
            budget: self.budget.meet(other),
        }
    }

    /// A SHORT bounded cleanup budget for finalizers (rollback, cursor close,
    /// lease release). It keeps the request deadline (so cleanup cannot outlive
    /// the request indefinitely) but caps polls at [`CLEANUP_POLL_QUOTA`] — the
    /// asupersync "give cleanup a bounded budget" rule. Built by `meet`-ing the
    /// request budget with [`Budget::MINIMAL`], so it is never looser than the
    /// request.
    #[must_use]
    pub fn cleanup(self) -> Budget {
        self.budget.meet(Budget::MINIMAL)
    }

    /// Whether the budget is already spent at `now`: past its deadline OR out of
    /// poll/cost quota. A non-time check (quota) is independent of `now`.
    #[must_use]
    pub fn is_exhausted_at(self, now: Time) -> bool {
        self.budget.is_past_deadline(now) || self.budget.is_exhausted()
    }

    /// Enforce the budget at `now`, mapping exhaustion to the timeout-class
    /// [`DbError::Cancelled`] (preserving B1's `Cancelled`/`Timeout` mapping).
    /// A request still within budget returns `Ok(())` and is unaffected.
    ///
    /// This is the dispatch-boundary check woven around DB round trips, the
    /// budget analogue of the adapter's `db_checkpoint`. It is deliberately a
    /// pure function of `(budget, now)` so it is deterministic under a lab
    /// clock.
    ///
    /// # Errors
    /// [`DbError::Cancelled`] when the deadline has passed or a quota is spent.
    pub fn enforce_at(self, now: Time) -> Result<(), DbError> {
        if self.budget.is_past_deadline(now) {
            return Err(DbError::Cancelled(
                "request budget exhausted: deadline exceeded".to_owned(),
            ));
        }
        if self.budget.is_exhausted() {
            return Err(DbError::Cancelled(
                "request budget exhausted: poll/cost quota spent".to_owned(),
            ));
        }
        Ok(())
    }

    /// Enforce the budget against a context's clock, AND observe any
    /// cancellation already pending on `cx` (so a caller-cancelled request is
    /// surfaced too). Combines the budget check with `cx.checkpoint`, mapping
    /// either trigger to [`DbError::Cancelled`].
    ///
    /// `cx` must carry the [`HasTime`](asupersync::cx::HasTime) capability (the
    /// request `Cx` installed by `block_on` does).
    ///
    /// # Errors
    /// [`DbError::Cancelled`] on budget exhaustion or pending cancellation.
    pub fn enforce(&self, cx: &Cx) -> Result<(), DbError> {
        cx.checkpoint_with("request_budget.enforce")
            .map_err(|err| DbError::Cancelled(format!("request cancelled: {err}")))?;
        self.enforce_at(cx.now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::runtime::RuntimeBuilder;

    // A request well inside its budget is unaffected.
    #[test]
    fn normal_request_is_not_bounded() {
        let now = Time::from_secs(100);
        let rb = RequestBudget::from_call_timeout(now, Some(Duration::from_secs(30)));
        // Still 30s of headroom: enforce at the same instant succeeds.
        assert!(rb.enforce_at(now).is_ok());
        // And a little later, still inside the window.
        assert!(rb.enforce_at(Time::from_secs(110)).is_ok());
        assert!(!rb.is_exhausted_at(Time::from_secs(110)));
    }

    // A request that runs past its deadline is bounded (Cancelled/Timeout).
    #[test]
    fn request_past_deadline_is_cancelled() {
        let now = Time::from_secs(100);
        let rb = RequestBudget::from_call_timeout(now, Some(Duration::from_secs(5)));
        // 6s later — past the 5s deadline.
        let later = Time::from_secs(106);
        assert!(rb.is_exhausted_at(later));
        let err = rb
            .enforce_at(later)
            .expect_err("a past-deadline request is bounded");
        assert!(
            matches!(err, DbError::Cancelled(ref m) if m.contains("deadline")),
            "exhaustion maps to the timeout-class Cancelled: {err:?}"
        );
    }

    // A spent poll quota bounds the request even with deadline headroom.
    #[test]
    fn spent_poll_quota_is_cancelled() {
        let now = Time::from_secs(100);
        let rb = RequestBudget::from_budget(
            Budget::new()
                .with_deadline(Time::from_secs(1_000)) // far away
                .with_poll_quota(0), // but no polls left
        );
        let err = rb
            .enforce_at(now)
            .expect_err("a spent quota bounds the request");
        assert!(matches!(err, DbError::Cancelled(ref m) if m.contains("quota")));
    }

    // The cleanup budget is bounded and never looser than the request budget.
    #[test]
    fn cleanup_budget_is_short_and_bounded() {
        let now = Time::from_secs(100);
        let rb = RequestBudget::from_call_timeout(now, Some(Duration::from_secs(30)));
        let cleanup = rb.cleanup();
        // Cleanup caps polls at the MINIMAL allowance (100), far below the
        // request's million-poll ceiling.
        assert_eq!(cleanup.poll_quota, CLEANUP_POLL_QUOTA);
        // And it keeps the (tighter-or-equal) request deadline.
        assert_eq!(cleanup.deadline, Some(now + Duration::from_secs(30)));
        // meet() is monotone: cleanup is never looser than the request.
        assert!(cleanup.poll_quota <= rb.budget().poll_quota);
    }

    // meet() tightens: a nested op inherits the stricter of caller/child.
    #[test]
    fn meet_takes_the_tighter_deadline() {
        let now = Time::from_secs(0);
        let parent = RequestBudget::from_call_timeout(now, Some(Duration::from_secs(30)));
        let child = Budget::new().with_timeout(now, Duration::from_secs(10));
        let combined = parent.meet(child);
        assert_eq!(
            combined.budget().deadline,
            Some(now + Duration::from_secs(10)),
            "the tighter (10s) deadline wins"
        );
    }

    // A zero timeout is floored so the budget is not born exhausted at `now`.
    #[test]
    fn zero_timeout_is_floored_above_now() {
        let now = Time::from_secs(100);
        let rb = RequestBudget::from_call_timeout(now, Some(Duration::ZERO));
        assert!(
            !rb.is_exhausted_at(now),
            "a zero timeout still leaves a sub-ns sliver so it is not born dead at now"
        );
    }

    // enforce() also observes a cancellation already pending on the cx,
    // mapping it to Cancelled — exercised on a real runtime Cx.
    #[test]
    fn enforce_observes_pending_cancellation() {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            // A generous budget — the only trigger here is the cx cancellation.
            let rb = RequestBudget::from_call_timeout(cx.now(), Some(Duration::from_secs(300)));
            assert!(rb.enforce(&cx).is_ok(), "healthy cx within budget is fine");
            cx.set_cancel_requested(true);
            let err = rb
                .enforce(&cx)
                .expect_err("a cancelled cx is surfaced through enforce");
            assert!(matches!(err, DbError::Cancelled(_)));
        });
    }
}
