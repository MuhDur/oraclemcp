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
//! * every clone shares one consumed checkpoint quota, so copying a budget into
//!   nested helpers cannot silently reset the request allowance;
//! * cleanup/finalizers get a fresh, independent, SHORT bounded budget so
//!   teardown can still run after the request deadline or cancellation has
//!   fired, but can never itself run away.
//!
//! Against the pinned `oracledb` 0.8.3 driver the budget composes with the
//! adapter's per-call timeout: the seam maps this budget's deadline onto the
//! driver's `execute_raw` timeout (see `crates/oraclemcp-db/src/connection.rs`).
//!
//! The type is deliberately small and pure so it is testable with
//! [`Cx::for_testing_with_budget`](asupersync::Cx) / a `LabRuntime` clock with
//! no database in the loop.

use std::time::Duration;

use asupersync::{Budget, Cx, Time};
use oraclemcp_db::{DbError, DbRequestQuota};

/// The default per-request deadline when a profile does not set
/// `call_timeout_seconds`. Mirrors `resilience::DEFAULT_CALL_TIMEOUT` (§10) so
/// the request budget and the per-round-trip timeout agree by default.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A cooperative-checkpoint ceiling for a single request. Every
/// [`RequestBudget::enforce`] consumes one shared unit in addition to the
/// caller [`Cx`]'s own runtime poll accounting. The figure is generous so it
/// never trips a normal call; it exists to keep explicit nested request/DB
/// checkpoints from resetting their allowance when the budget is cloned.
pub const DEFAULT_REQUEST_POLL_QUOTA: u32 = 1_000_000;

/// The cooperative-checkpoint quota a bounded cleanup/finalize section gets.
/// Matches [`Budget::MINIMAL`]'s 100-poll allowance — enough to roll back,
/// close cursors, and release a lease, but not enough to run away.
pub const CLEANUP_POLL_QUOTA: u32 = 100;

/// Wall-clock ceiling for a fresh cleanup/finalizer attempt.
///
/// Cleanup runs after the request budget may already be expired, so its
/// deadline must be anchored to cleanup admission rather than inherited from
/// the dead request. Five seconds leaves rollback/close enough time for one
/// bounded network round trip without turning finalization into an unbounded
/// shutdown path.
pub const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

/// A per-request resource budget (B6).
///
/// Wraps an asupersync [`Budget`] with the dispatch-boundary policy: how to
/// derive it from a call timeout, how to bound cleanup, and how exhaustion maps
/// to the timeout-class [`DbError`].
#[derive(Clone, Debug)]
pub struct RequestBudget {
    admitted_at: Time,
    budget: Budget,
    shared_quota: DbRequestQuota,
}

impl RequestBudget {
    /// Derive a request budget from a per-call timeout (or the default when
    /// `None`), anchored to the instant the request entered dispatch (the
    /// runtime/lab clock).
    ///
    /// The deadline is `admitted_at + timeout`; the poll quota is
    /// [`DEFAULT_REQUEST_POLL_QUOTA`]. A zero timeout is floored to 1ns so the
    /// deadline is strictly after admission (a budget with
    /// `deadline == admitted_at` would be born already exhausted).
    #[must_use]
    pub fn from_call_timeout(admitted_at: Time, timeout: Option<Duration>) -> Self {
        let timeout = timeout
            .unwrap_or(DEFAULT_REQUEST_TIMEOUT)
            .max(Duration::from_nanos(1));
        let budget = Budget::new()
            .with_timeout(admitted_at, timeout)
            .with_poll_quota(DEFAULT_REQUEST_POLL_QUOTA);
        Self::from_budget_at(admitted_at, budget)
    }

    /// Wrap an explicit [`Budget`] anchored to request admission.
    ///
    /// Keeping the anchor separate from the deadline is intentional: a
    /// per-tool timeout can later be tightened relative to the original
    /// admission instant even when the parent budget supplied an earlier
    /// absolute deadline.
    #[must_use]
    pub fn from_budget_at(admitted_at: Time, budget: Budget) -> Self {
        Self {
            admitted_at,
            budget,
            shared_quota: DbRequestQuota::new(budget),
        }
    }

    /// The underlying asupersync [`Budget`], for attaching to a request `Cx` or
    /// for `meet`-ing with another budget. The returned quota fields are a
    /// point-in-time snapshot of the shared remaining allowance.
    #[must_use]
    pub fn budget(&self) -> Budget {
        Budget {
            deadline: self.budget.deadline,
            poll_quota: self
                .budget
                .poll_quota
                .min(self.shared_quota.polls_remaining()),
            cost_quota: match (self.budget.cost_quota, self.shared_quota.cost_remaining()) {
                (Some(limit), Some(remaining)) => Some(limit.min(remaining)),
                (limit, None) => limit,
                (None, remaining) => remaining,
            },
            priority: self.budget.priority,
        }
    }

    /// Original lane/request admission instant used to derive relative
    /// timeouts. Queue wait therefore consumes the same total deadline as DB
    /// work.
    #[must_use]
    pub const fn admitted_at(&self) -> Time {
        self.admitted_at
    }

    /// Effective absolute request deadline.
    #[must_use]
    pub const fn deadline(&self) -> Option<Time> {
        self.budget.deadline
    }

    /// Shared quota handle installed on database wire boundaries.
    ///
    /// The returned clone charges the same atomics as [`Self::enforce`]; it is
    /// not a replenished snapshot.
    #[must_use]
    pub fn db_quota(&self) -> DbRequestQuota {
        self.shared_quota.clone()
    }

    /// Combine with another budget, taking the tighter constraint
    /// ([`Budget::meet`]). Use this so a nested/hedged DB op inherits a budget
    /// no looser than its caller (budget propagation is correctness, not just
    /// tuning).
    #[must_use]
    pub fn meet(mut self, other: Budget) -> Self {
        self.budget = self.budget.meet(other);
        self.shared_quota.tighten(self.budget);
        self
    }

    /// Tighten a per-tool timeout relative to the original request admission.
    ///
    /// This deliberately does **not** use `cx.now()`: doing so after mailbox
    /// dequeue would give queued work a fresh timeout window. Clones continue
    /// sharing the same consumed quota.
    #[must_use]
    pub fn tighten_timeout(&self, timeout: Duration) -> Self {
        self.clone().meet(
            Budget::new().with_timeout(self.admitted_at, timeout.max(Duration::from_nanos(1))),
        )
    }

    /// A fresh, independent SHORT budget for finalizers (rollback, cursor
    /// close, lease release).
    ///
    /// It intentionally does not inherit the request deadline, cancellation,
    /// or spent quota: those may be the reason cleanup is running. The caller
    /// supplies the cleanup admission time, producing a new absolute deadline
    /// and a new shared quota bounded by [`CLEANUP_TIMEOUT`] and
    /// [`CLEANUP_POLL_QUOTA`].
    #[must_use]
    pub fn fresh_cleanup(cleanup_admitted_at: Time) -> Self {
        Self::from_budget_at(
            cleanup_admitted_at,
            Budget::new()
                .with_timeout(cleanup_admitted_at, CLEANUP_TIMEOUT)
                .with_poll_quota(CLEANUP_POLL_QUOTA),
        )
    }

    /// Whether the budget is already spent at `now`: past its deadline OR out of
    /// poll/cost quota. A non-time check (quota) is independent of `now`.
    #[must_use]
    pub fn is_exhausted_at(&self, now: Time) -> bool {
        let budget = self.budget();
        budget.is_past_deadline(now) || budget.is_exhausted()
    }

    /// Enforce the budget at `now`, mapping exhaustion to the timeout-class
    /// [`DbError::Cancelled`] (preserving B1's `Cancelled`/`Timeout` mapping).
    /// A request still within budget consumes one shared cooperative
    /// checkpoint and returns `Ok(())`.
    ///
    /// This is the dispatch-boundary check woven around DB round trips, the
    /// budget analogue of the adapter's `db_checkpoint`. Consumption is shared
    /// by all clones and deterministic under a lab clock.
    ///
    /// # Errors
    /// [`DbError::Cancelled`] when the deadline has passed or a quota is spent.
    pub fn enforce_at(&self, now: Time) -> Result<(), DbError> {
        if self.budget.is_past_deadline(now) {
            return Err(DbError::Cancelled(
                "request budget exhausted: deadline exceeded".to_owned(),
            ));
        }
        self.shared_quota
            .consume_checkpoint("request budget")
            .map_err(|_| {
                DbError::Cancelled("request budget exhausted: poll/cost quota spent".to_owned())
            })
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
        let rb = RequestBudget::from_budget_at(
            now,
            Budget::new()
                .with_deadline(Time::from_secs(1_000)) // far away
                .with_poll_quota(0), // but no polls left
        );
        let err = rb
            .enforce_at(now)
            .expect_err("a spent quota bounds the request");
        assert!(matches!(err, DbError::Cancelled(ref m) if m.contains("quota")));
    }

    // Cleanup is independently bounded and usable after the request expired.
    #[test]
    fn cleanup_budget_is_fresh_after_request_expiry() {
        let now = Time::from_secs(100);
        let request = RequestBudget::from_call_timeout(now, Some(Duration::from_secs(1)));
        let cleanup_admitted_at = Time::from_secs(102);
        assert!(request.enforce_at(cleanup_admitted_at).is_err());

        let cleanup = RequestBudget::fresh_cleanup(cleanup_admitted_at);
        assert_eq!(cleanup.admitted_at(), cleanup_admitted_at);
        assert_eq!(cleanup.budget().poll_quota, CLEANUP_POLL_QUOTA);
        assert_eq!(
            cleanup.deadline(),
            Some(cleanup_admitted_at + CLEANUP_TIMEOUT)
        );
        assert!(
            cleanup.enforce_at(cleanup_admitted_at).is_ok(),
            "expired request state must not poison its fresh cleanup budget"
        );
    }

    // meet() tightens: a nested op inherits the stricter of caller/child.
    #[test]
    fn meet_takes_the_tighter_deadline() {
        let now = Time::from_secs(0);
        let parent = RequestBudget::from_call_timeout(now, Some(Duration::from_secs(30)));
        let child = Budget::new().with_timeout(now, Duration::from_secs(10));
        let combined = parent.meet(child);
        assert_eq!(
            combined.deadline(),
            Some(now + Duration::from_secs(10)),
            "the tighter (10s) deadline wins"
        );
    }

    #[test]
    fn budget_meet_replaces_three_timers() {
        let now = Time::from_secs(1_000);
        let service_root = Budget::new()
            .with_timeout(now, Duration::from_secs(60))
            .with_poll_quota(50_000);
        let profile_ceiling = Budget::new()
            .with_timeout(now, Duration::from_secs(30))
            .with_poll_quota(10_000);
        let per_request_deadline = Budget::new()
            .with_timeout(now, Duration::from_secs(7))
            .with_poll_quota(20_000);

        let effective = RequestBudget::from_budget_at(now, service_root)
            .meet(profile_ceiling)
            .meet(per_request_deadline)
            .budget();

        assert_eq!(effective.deadline, Some(now + Duration::from_secs(7)));
        assert_eq!(effective.poll_quota, 10_000);
        assert_eq!(
            effective,
            service_root
                .meet(profile_ceiling)
                .meet(per_request_deadline)
        );
    }

    #[test]
    fn per_tool_timeout_is_anchored_to_original_admission() {
        let admitted_at = Time::from_secs(100);
        let request = RequestBudget::from_call_timeout(admitted_at, Some(Duration::from_secs(30)));

        // Pretend dequeue happened at t=108. Tightening to 10s still expires at
        // t=110, not at t=118.
        let tool = request.tighten_timeout(Duration::from_secs(10));
        assert_eq!(tool.admitted_at(), admitted_at);
        assert_eq!(tool.deadline(), Some(Time::from_secs(110)));
        assert!(tool.enforce_at(Time::from_secs(109)).is_ok());
        assert!(tool.enforce_at(Time::from_secs(111)).is_err());
    }

    #[test]
    fn cloned_budgets_share_and_consume_one_quota() {
        let now = Time::from_secs(100);
        let request = RequestBudget::from_budget_at(
            now,
            Budget::new()
                .with_deadline(Time::from_secs(1_000))
                .with_poll_quota(2),
        );
        let nested = request.clone();

        assert!(request.enforce_at(now).is_ok());
        assert_eq!(nested.budget().poll_quota, 1);
        assert!(nested.enforce_at(now).is_ok());
        assert_eq!(request.budget().poll_quota, 0);
        let err = request
            .enforce_at(now)
            .expect_err("all clones observe the spent request quota");
        assert!(matches!(err, DbError::Cancelled(ref message) if message.contains("quota")));
    }

    #[test]
    fn later_meet_tightens_shared_quota_for_existing_clones() {
        let now = Time::from_secs(100);
        let request = RequestBudget::from_budget_at(
            now,
            Budget::new()
                .with_deadline(Time::from_secs(1_000))
                .with_poll_quota(10),
        );
        let existing = request.clone();
        let tightened = request.meet(Budget::new().with_poll_quota(2));

        assert_eq!(existing.budget().poll_quota, 2);
        assert_eq!(tightened.budget().poll_quota, 2);
    }

    #[test]
    fn finite_cost_added_by_meet_is_shared_and_consumed() {
        let now = Time::from_secs(100);
        let request = RequestBudget::from_budget_at(
            now,
            Budget::new()
                .with_deadline(Time::from_secs(1_000))
                .with_poll_quota(10),
        );
        let existing = request.clone();
        let tightened = request.meet(Budget::new().with_cost_quota(1));

        assert_eq!(existing.budget().cost_quota, Some(1));
        assert!(tightened.enforce_at(now).is_ok());
        assert_eq!(existing.budget().cost_quota, Some(0));
        assert!(existing.enforce_at(now).is_err());
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
