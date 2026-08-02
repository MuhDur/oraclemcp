//! Bounded thin-mode connection pool for callers that need reusable sessions.
//!
//! `Cx`-first and `async` (B1): callers get bounded session reuse without a
//! Tokio/r2d2 boundary, and cancellation is observed through explicit
//! `&asupersync::Cx` checkpoints around checkout and through the native-async
//! DB calls themselves. A cancelled or failed pooled call discards the checked-out
//! connection DIRTY (it never returns to the idle set) so a torn round trip can
//! never be reused. A known safe, idempotent read failure may be retried once
//! under the shared driver taxonomy; only the final result decides whether the
//! session can return to the idle set.
//!
//! ## Sizing and failover posture (B4)
//!
//! `PoolSettings::max_size` is a *ceiling*; the effective ceiling applied at
//! construction is `min(max_size, cpu*2+1)` (plan §10) via
//! [`PoolSettings::resolved`]. Checkout waits up to `acquire_timeout_secs` for a
//! free or newly-openable connection and then returns a `Pool` (BUSY) error.
//! Exhausted checkouts park on Asupersync's cancel-safe FIFO semaphore. One
//! freed slot wakes one live waiter, queued callers cannot be bypassed by new
//! arrivals, and a dropped head waiter hands the permit to its successor. A
//! bounded cancellation checkpoint wakes at most the waiting task; it never
//! removes and re-enqueues the semaphore waiter. [`PoolMetrics`] exposes the
//! checkout accounting (`acquired`/`released`/`discarded`/`in_use`/`open`) so
//! the zero-leaked-session invariant (`is_balanced`) and the bound
//! (`is_bounded`) are observable.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use asupersync::sync::{AcquireError, OwnedSemaphorePermit, Semaphore};
use asupersync::{Cx, RegionId, TaskId, Time};
use async_trait::async_trait;

use crate::connection::{DbRequestQuota, OracleConnection, RustOracleConnection, db_checkpoint};
use crate::error::{DbError, RetryPolicy};
use crate::types::{
    OracleBackend, OracleBind, OracleConnectOptions, OracleConnectionInfo, OracleRow,
};

/// Opens thin [`RustOracleConnection`]s from one profile.
#[derive(Clone, Debug)]
pub struct OracleConnectionManager {
    opts: OracleConnectOptions,
}

impl OracleConnectionManager {
    /// A manager for the given connect options.
    #[must_use]
    pub fn new(opts: OracleConnectOptions) -> Self {
        OracleConnectionManager { opts }
    }
}

impl OracleConnectionManager {
    async fn connect(&self, cx: &Cx) -> Result<RustOracleConnection, DbError> {
        db_checkpoint(cx, "oracle_pool.connect.before")?;
        let conn = RustOracleConnection::connect(cx, self.opts.clone()).await?;
        db_checkpoint(cx, "oracle_pool.connect.after")?;
        Ok(conn)
    }

    async fn is_valid(&self, cx: &Cx, conn: &RustOracleConnection) -> Result<(), DbError> {
        conn.ping(cx).await
    }

    async fn has_broken(&self, cx: &Cx, conn: &RustOracleConnection) -> bool {
        conn.ping(cx).await.is_err()
    }
}

/// Pool sizing knobs (mirrors `oraclemcp_config::PoolConfig`; kept independent
/// so this crate stays config-agnostic).
#[derive(Clone, Copy, Debug)]
pub struct PoolSettings {
    /// Maximum pooled connections.
    pub max_size: u32,
    /// Minimum idle connections.
    pub min_idle: u32,
    /// Seconds to wait for a connection before `BUSY`.
    pub acquire_timeout_secs: u64,
    /// Per-connection statement-cache size for pool-created sessions.
    pub statement_cache_size: u32,
}

/// Largest supported pool-checkout wait, matching the strict config contract.
const MAX_POOL_ACQUIRE_TIMEOUT_SECS: u64 = 60 * 60;
const POOL_CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(100);
impl Default for PoolSettings {
    fn default() -> Self {
        PoolSettings {
            max_size: 16,
            min_idle: 2,
            acquire_timeout_secs: 5,
            statement_cache_size: 50,
        }
    }
}

/// The CPU-derived sizing ceiling from plan §10: `cpu * 2 + 1`, where `cpu`
/// is the available parallelism (defaulting to 1 when the platform cannot
/// report it). The configured `max_size` is treated as a hard ceiling, so the
/// effective ceiling is `min(configured_max_size, cpu * 2 + 1)`.
///
/// Kept as a free function (not a `PoolSettings` method) so the derivation is
/// testable with an injected `cpu` count independent of the host.
#[must_use]
fn cpu_derived_ceiling(cpu: u32) -> u32 {
    cpu.saturating_mul(2).saturating_add(1)
}

/// Available parallelism reported by the platform, clamped to at least 1.
#[must_use]
fn available_cpus() -> u32 {
    std::thread::available_parallelism()
        .map(|n| u32::try_from(n.get()).unwrap_or(u32::MAX))
        .unwrap_or(1)
        .max(1)
}

impl PoolSettings {
    /// Resolve the effective sizing for the async path (B4; plan §10).
    ///
    /// `max_size` is clamped to `min(configured, cpu * 2 + 1)` — the configured
    /// value is the documented ceiling, and the CPU-derived figure keeps a
    /// large configured ceiling (e.g. the default 16) from over-provisioning
    /// sessions on a small host. `min_idle` is then clamped to the resolved
    /// `max_size`, and every field is forced into its valid range so a
    /// hand-rolled `PoolSettings` can never build a degenerate pool. The static
    /// config default (`max_size = 16`) remains the ceiling; this is where the
    /// CPU-derived sizing the config doc-comment promises is actually applied.
    #[must_use]
    pub fn resolved(self) -> Self {
        self.resolved_for_cpus(available_cpus())
    }

    /// `resolved` against an explicit `cpu` count (deterministic; used by the
    /// async-path sizing tests so the verdict does not depend on the host).
    #[must_use]
    pub fn resolved_for_cpus(self, cpu: u32) -> Self {
        let configured = self.max_size.max(1);
        let max_size = configured.min(cpu_derived_ceiling(cpu)).max(1);
        PoolSettings {
            max_size,
            min_idle: self.min_idle.min(max_size),
            acquire_timeout_secs: self.acquire_timeout_secs.max(1),
            statement_cache_size: self.statement_cache_size,
        }
    }
}

/// A point-in-time snapshot of pool checkout accounting (B3/B4).
///
/// Used by the load/soak harness to assert ZERO leaked sessions: across a run,
/// `acquired` must equal `released + discarded` and, once every client has
/// finished, `in_use` must be `0` while `open` never exceeds `max_size`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolMetrics {
    /// Connections currently open (idle + in-use).
    pub open: u32,
    /// Connections currently idle (available for checkout).
    pub idle: u32,
    /// Connections currently checked out (in flight).
    pub in_use: u32,
    /// Configured maximum (the bound `open` must never exceed).
    pub max_size: u32,
    /// Total successful checkouts over the pool's lifetime.
    pub acquired: u64,
    /// Total clean check-ins (connection returned to the idle set).
    pub released: u64,
    /// Total dirty discards (errored/cancelled/broken — connection NOT reused).
    pub discarded: u64,
}

impl PoolMetrics {
    /// Whether checkout accounting balances: every acquire has either been
    /// returned clean or discarded dirty, and nothing is still checked out.
    /// This is the zero-leaked-session invariant the B3 soak asserts after a
    /// run quiesces.
    #[must_use]
    pub fn is_balanced(&self) -> bool {
        self.in_use == 0 && self.acquired == self.released + self.discarded
    }

    /// Whether the open-connection count respects the configured ceiling.
    #[must_use]
    pub fn is_bounded(&self) -> bool {
        self.open <= self.max_size
    }
}

struct PoolState {
    idle: Vec<RustOracleConnection>,
    open_count: u32,
    /// Once shutdown begins, no checkout may create or reuse a session and a
    /// late check-in is discarded instead of returning to the idle set.
    closing: bool,
    /// In-flight (checked-out) connections — the difference between a checkout
    /// and its matching check-in. Drives the zero-leaked-session accounting.
    in_use: u32,
    /// Lifetime checkout/return/discard counters (B3/B4 leak accounting).
    acquired: u64,
    released: u64,
    discarded: u64,
}

#[derive(Clone, Debug, Default)]
struct PoolRequestLimits {
    deadline: Option<Time>,
    quota: Option<DbRequestQuota>,
}

type PoolRequestKey = (RegionId, TaskId);

/// A small async thin-mode Oracle connection pool.
#[derive(Clone)]
pub struct OraclePool {
    manager: OracleConnectionManager,
    settings: PoolSettings,
    state: Arc<Mutex<PoolState>>,
    /// One permit is held from checkout admission until the connection state is
    /// returned or discarded. Asupersync's semaphore supplies FIFO ordering,
    /// anti-barging, and cancellation baton handoff.
    capacity: Arc<Semaphore>,
    /// Request limits are keyed by the explicit Asupersync task identity, not
    /// stored as one mutable pool-wide value. Concurrent callers therefore
    /// cannot overwrite or restore each other's absolute deadlines/quotas.
    request_limits: Arc<Mutex<HashMap<PoolRequestKey, PoolRequestLimits>>>,
}

impl OraclePool {
    fn request_key(cx: &Cx) -> PoolRequestKey {
        (cx.region_id(), cx.task_id())
    }

    fn request_limits_for(&self, cx: &Cx) -> Result<PoolRequestLimits, DbError> {
        self.request_limits
            .lock()
            .map(|limits| {
                limits
                    .get(&Self::request_key(cx))
                    .cloned()
                    .unwrap_or_default()
            })
            .map_err(|err| DbError::Internal(format!("pool request-limits lock poisoned: {err}")))
    }

    fn update_request_limits(
        &self,
        cx: &Cx,
        update: impl FnOnce(&mut PoolRequestLimits),
    ) -> Result<(), DbError> {
        let key = Self::request_key(cx);
        let mut limits = self.request_limits.lock().map_err(|err| {
            DbError::Internal(format!("pool request-limits lock poisoned: {err}"))
        })?;
        update(limits.entry(key).or_default());
        if limits
            .get(&key)
            .is_some_and(|limits| limits.deadline.is_none() && limits.quota.is_none())
        {
            limits.remove(&key);
        }
        Ok(())
    }

    /// Build a pool, eagerly establishing `min_idle` connections (so a bad
    /// profile fails fast). Requires a reachable database.
    pub async fn connect(
        cx: &Cx,
        opts: OracleConnectOptions,
        settings: PoolSettings,
    ) -> Result<Self, DbError> {
        let manager = OracleConnectionManager::new(opts);
        // B4: apply the plan §10 CPU-derived sizing ceiling — the configured
        // `max_size` is the ceiling, the effective is `min(configured,
        // cpu*2+1)`. This is the single place the config's documented
        // "cpu-derived sizing is applied at pool construction" actually happens.
        let settings = settings.resolved();
        let mut idle = Vec::new();
        for _ in 0..settings.min_idle {
            idle.push(manager.connect(cx).await?);
        }
        Ok(OraclePool {
            manager,
            settings,
            state: Arc::new(Mutex::new(PoolState {
                open_count: idle.len() as u32,
                idle,
                closing: false,
                in_use: 0,
                acquired: 0,
                released: 0,
                discarded: 0,
            })),
            capacity: Arc::new(Semaphore::with_name(
                "oracle-pool-checkout-capacity",
                settings.max_size as usize,
            )),
            request_limits: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Current number of idle + in-use connections in the pool.
    pub fn state_connections(&self) -> Result<u32, DbError> {
        self.state
            .lock()
            .map(|state| state.open_count)
            .map_err(|err| DbError::Internal(format!("pool lock poisoned: {err}")))
    }

    /// The settings actually in force after CPU-derived resolution (B4).
    #[must_use]
    pub fn settings(&self) -> PoolSettings {
        self.settings
    }

    /// Log off every idle physical session and prevent future reuse.
    ///
    /// A lane calls this only after it has stopped dispatching through the
    /// pool. If a checkout is still unwinding, its check-in observes `closing`
    /// and discards that session instead of putting it back into the idle set.
    pub async fn close(&self, cx: &Cx) -> Result<(), DbError> {
        let idle = {
            let mut state = self
                .state
                .lock()
                .map_err(|err| DbError::Internal(format!("pool lock poisoned: {err}")))?;
            state.closing = true;
            let idle = std::mem::take(&mut state.idle);
            state.open_count = state.open_count.saturating_sub(idle.len() as u32);
            idle
        };
        self.capacity.close();

        let mut first_error = None;
        for connection in idle {
            if let Err(error) = connection.close(cx).await {
                tracing::warn!(error = %error, "pooled Oracle session logical close failed");
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// A snapshot of checkout accounting (B3/B4 zero-leaked-session evidence).
    pub fn metrics(&self) -> Result<PoolMetrics, DbError> {
        self.state
            .lock()
            .map(|state| PoolMetrics {
                open: state.open_count,
                idle: state.idle.len() as u32,
                in_use: state.in_use,
                max_size: self.settings.max_size,
                acquired: state.acquired,
                released: state.released,
                discarded: state.discarded,
            })
            .map_err(|err| DbError::Internal(format!("pool lock poisoned: {err}")))
    }

    /// Run a query on a pooled connection with cancellation-aware checkout and
    /// DB execution boundaries.
    pub async fn query_rows(
        &self,
        cx: &Cx,
        sql: impl Into<String>,
        binds: Vec<OracleBind>,
    ) -> Result<Vec<OracleRow>, DbError> {
        let sql = sql.into();
        self.with_conn(cx, |cx, conn| {
            let sql = sql.clone();
            let binds = binds.clone();
            Box::pin(async move { conn.query_rows(cx, &sql, &binds).await })
        })
        .await
    }

    /// Run one page of a read query (bind-first, paginated, capped) on a pooled
    /// connection (plan §8.2, bead P1-2).
    pub async fn read_query(
        &self,
        cx: &Cx,
        sql: impl Into<String>,
        binds: Vec<OracleBind>,
        caps: crate::query::QueryCaps,
        offset: usize,
        serialize_opts: crate::serialize::SerializeOptions,
    ) -> Result<crate::query::QueryResponse, DbError> {
        let sql = sql.into();
        self.with_conn(cx, |cx, conn| {
            let sql = sql.clone();
            let binds = binds.clone();
            let serialize_opts = serialize_opts.clone();
            Box::pin(async move {
                crate::query::read_query(cx, conn, &sql, &binds, caps, offset, &serialize_opts)
                    .await
            })
        })
        .await
    }

    /// Describe a pooled connection (version / role / open-mode / schema) with
    /// cancellation-aware checkout and DB execution boundaries.
    pub async fn describe(&self, cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        self.with_conn(cx, |cx, conn| {
            Box::pin(async move { conn.describe(cx).await })
        })
        .await
    }

    /// Confirm a pooled connection is live with cancellation-aware checkout.
    pub async fn ping(&self, cx: &Cx) -> Result<(), DbError> {
        self.with_conn(cx, |cx, conn| Box::pin(async move { conn.ping(cx).await }))
            .await
    }

    async fn with_conn<'c, T, F>(&self, cx: &'c Cx, f: F) -> Result<T, DbError>
    where
        F: for<'a> Fn(
            &'a Cx,
            &'a RustOracleConnection,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, DbError>> + 'a>,
        >,
    {
        let retry_policy = RetryPolicy::one_immediate_retry();
        // Count every execution of `f`, regardless of whether it occurs on the
        // same session or after a reconnect. The retry budget is per request,
        // not per error category: a package reset followed by a connection
        // loss must not turn one permitted replay into two.
        let mut attempt = 1;
        loop {
            db_checkpoint(cx, "oracle_pool.checkout.before")?;
            let (conn, permit) = self.checkout(cx).await?;
            self.on_checked_out()?;
            // From this point, future drop is an unconditional dirty discard.
            // The guard owns both the physical session and the accounting edge,
            // so a lane hard timeout cannot leak `in_use`/`open_count`.
            let checkout = CheckedOutConnection::new(conn, Arc::clone(&self.state), permit);
            let limits = self.request_limits_for(cx)?;
            let previous_deadline = checkout.connection().request_deadline(cx)?;
            let previous_quota = checkout.connection().request_quota(cx)?;
            if let Err(error) = checkout
                .connection()
                .set_request_deadline(cx, limits.deadline)
            {
                checkout.finish(true)?;
                return Err(error);
            }
            if let Err(error) = checkout
                .connection()
                .set_request_quota(cx, limits.quota.clone())
            {
                let _ = checkout
                    .connection()
                    .set_request_deadline(cx, previous_deadline);
                checkout.finish(true)?;
                return Err(error);
            }

            let first_result = f(cx, checkout.connection()).await;
            let result = match &first_result {
                Err(error)
                    if retry_now(
                        retry_policy,
                        1,
                        error.retry_action(),
                        oraclemcp_error::OracleRetryAction::RetrySameConnection,
                    ) =>
                {
                    // ORA-04068 and driver retry-in-place conditions leave the
                    // session usable. Yield once before the one safe replay;
                    // this runtime deliberately has no timer dependency.
                    attempt += 1;
                    asupersync::runtime::yield_now().await;
                    f(cx, checkout.connection()).await
                }
                _ => first_result,
            };

            let retry_fresh = matches!(
                &result,
                Err(error)
                    if retry_now(
                        retry_policy,
                        attempt,
                        error.retry_action(),
                        oraclemcp_error::OracleRetryAction::ReconnectThenRetry,
                    )
            );
            let quota_restore = checkout.connection().set_request_quota(cx, previous_quota);
            let deadline_restore = checkout
                .connection()
                .set_request_deadline(cx, previous_deadline);
            let restore_error = quota_restore.err().or_else(|| deadline_restore.err());
            let release_error = if result.is_ok() && restore_error.is_none() {
                checkout
                    .connection()
                    .run_session_release_statements(cx)
                    .await
                    .err()
            } else {
                None
            };
            // Any final failure may have crossed an Oracle boundary and must
            // be discarded. A successful call returns to idle only after
            // request limits are restored, operator-owned release hooks pass,
            // and a final liveness check succeeds.
            let discard_after_call = match &result {
                Err(_) => true,
                Ok(_) if release_error.is_some() => true,
                Ok(_) => self.manager.has_broken(cx, checkout.connection()).await,
            };
            let discard = discard_after_call || restore_error.is_some();
            if discard && let Err(error) = checkout.connection().close(cx).await {
                tracing::warn!(error = %error, "discarded pooled Oracle session logical close failed");
            }
            checkout.finish(discard)?;
            if retry_fresh && restore_error.is_none() {
                attempt += 1;
                asupersync::runtime::yield_now().await;
                continue;
            }
            return match result {
                Err(primary) => Err(primary),
                Ok(value) => match restore_error {
                    Some(error) => Err(error),
                    None => match release_error {
                        Some(error) => Err(error),
                        None => Ok(value),
                    },
                },
            };
        }
    }

    async fn checkout(
        &self,
        cx: &Cx,
    ) -> Result<(RustOracleConnection, OwnedSemaphorePermit), DbError> {
        let deadline = checkout_deadline(
            asupersync::time::wall_now(),
            self.settings.acquire_timeout_secs,
        )?;
        let permit = self.acquire_checkout_permit(cx, deadline).await?;
        db_checkpoint(cx, "oracle_pool.checkout.admitted")?;
        let connection = self.open_connection_for_permit(cx).await?;
        Ok((connection, permit))
    }

    async fn acquire_checkout_permit(
        &self,
        cx: &Cx,
        deadline: Time,
    ) -> Result<OwnedSemaphorePermit, DbError> {
        db_checkpoint(cx, "oracle_pool.checkout.wait.before")?;
        let mut acquire = Box::pin(OwnedSemaphorePermit::acquire(
            Arc::clone(&self.capacity),
            cx,
            1,
        ));
        loop {
            let now = asupersync::time::wall_now();
            check_checkout_wait_deadline(cx, deadline, now)?;
            let poll_deadline = checkout_poll_deadline(now, deadline);
            match asupersync::time::timeout_at(poll_deadline, acquire.as_mut()).await {
                Ok(Ok(permit)) => {
                    db_checkpoint(cx, "oracle_pool.checkout.wait.after")?;
                    if asupersync::time::wall_now() > deadline {
                        return Err(pool_acquire_timeout());
                    }
                    return Ok(permit);
                }
                Ok(Err(AcquireError::Cancelled)) => {
                    return match db_checkpoint(cx, "oracle_pool.checkout.wait.cancelled") {
                        Err(error) => Err(error),
                        Ok(()) => Err(DbError::Cancelled(
                            "thin Oracle connection checkout cancelled".to_owned(),
                        )),
                    };
                }
                Ok(Err(AcquireError::Closed)) => {
                    return Err(DbError::Pool(
                        "thin Oracle connection pool is closing".to_owned(),
                    ));
                }
                Ok(Err(AcquireError::PolledAfterCompletion)) => {
                    return Err(DbError::Internal(
                        "pool capacity acquire was polled after completion".to_owned(),
                    ));
                }
                Err(_) => check_checkout_wait_deadline(cx, deadline, asupersync::time::wall_now())?,
            }
        }
    }

    async fn open_connection_for_permit(&self, cx: &Cx) -> Result<RustOracleConnection, DbError> {
        if self.is_closing()? {
            return Err(DbError::Pool(
                "thin Oracle connection pool is closing".to_owned(),
            ));
        }
        loop {
            if let Some(conn) = self.take_idle_connection()? {
                let pending_slot = PendingOpenSlot::new(Arc::clone(&self.state));
                if self.manager.is_valid(cx, &conn).await.is_ok() {
                    pending_slot.complete();
                    return Ok(conn);
                }
                pending_slot.discard()?;
                continue;
            }
            if self.reserve_new_connection()? {
                let pending_slot = PendingOpenSlot::new(Arc::clone(&self.state));
                match self.manager.connect(cx).await {
                    Ok(conn) => {
                        pending_slot.complete();
                        return Ok(conn);
                    }
                    Err(err) => {
                        pending_slot.discard()?;
                        return Err(err);
                    }
                }
            }
            return Err(DbError::Internal(
                "pool capacity permit had no idle or openable connection slot".to_owned(),
            ));
        }
    }

    fn take_idle_connection(&self) -> Result<Option<RustOracleConnection>, DbError> {
        let mut state = self
            .state
            .lock()
            .map_err(|err| DbError::Internal(format!("pool lock poisoned: {err}")))?;
        Ok(state.idle.pop())
    }

    fn reserve_new_connection(&self) -> Result<bool, DbError> {
        let mut state = self
            .state
            .lock()
            .map_err(|err| DbError::Internal(format!("pool lock poisoned: {err}")))?;
        if !state.closing && state.open_count < self.settings.max_size {
            state.open_count += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn on_checked_out(&self) -> Result<(), DbError> {
        let mut state = self
            .state
            .lock()
            .map_err(|err| DbError::Internal(format!("pool lock poisoned: {err}")))?;
        state.in_use += 1;
        state.acquired += 1;
        Ok(())
    }

    fn is_closing(&self) -> Result<bool, DbError> {
        self.state
            .lock()
            .map(|state| state.closing)
            .map_err(|err| DbError::Internal(format!("pool lock poisoned: {err}")))
    }

    /// Build a pool WITHOUT connecting, pre-seeded to a chosen open-count, for
    /// offline tests of the bounded-reservation and acquire-timeout paths (B4).
    /// The manager is never used to `connect` in these tests because every
    /// `connect` site is guarded by an idle/reservation check that the seeded
    /// state forces to fail first.
    #[cfg(test)]
    fn for_test_at_open_count(settings: PoolSettings, open_count: u32) -> Self {
        let settings = settings.resolved();
        OraclePool {
            manager: OracleConnectionManager::new(OracleConnectOptions::default()),
            settings,
            state: Arc::new(Mutex::new(PoolState {
                idle: Vec::new(),
                open_count,
                closing: false,
                in_use: 0,
                acquired: 0,
                released: 0,
                discarded: 0,
            })),
            capacity: Arc::new(Semaphore::with_name(
                "oracle-pool-checkout-capacity-test",
                settings.max_size.saturating_sub(open_count) as usize,
            )),
            request_limits: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

fn checkout_deadline(now: Time, acquire_timeout_secs: u64) -> Result<Time, DbError> {
    if acquire_timeout_secs > MAX_POOL_ACQUIRE_TIMEOUT_SECS {
        return Err(DbError::Pool(format!(
            "acquire_timeout_secs must be at most {MAX_POOL_ACQUIRE_TIMEOUT_SECS}"
        )));
    }
    let timeout_nanos = Duration::from_secs(acquire_timeout_secs).as_nanos();
    let timeout_nanos = u64::try_from(timeout_nanos)
        .map_err(|_| DbError::Pool("acquire timeout cannot be represented".to_owned()))?;
    now.as_nanos()
        .checked_add(timeout_nanos)
        .map(Time::from_nanos)
        .ok_or_else(|| DbError::Pool("acquire timeout cannot be represented".to_owned()))
}

fn checkout_poll_deadline(now: Time, deadline: Time) -> Time {
    deadline.min(now + POOL_CANCEL_POLL_INTERVAL)
}

fn check_checkout_wait_deadline(cx: &Cx, deadline: Time, now: Time) -> Result<(), DbError> {
    db_checkpoint(cx, "oracle_pool.checkout.wait.poll")?;
    if now >= deadline {
        Err(pool_acquire_timeout())
    } else {
        Ok(())
    }
}

fn pool_acquire_timeout() -> DbError {
    DbError::Pool("timed out waiting for thin Oracle connection".to_owned())
}

/// Tracks an open pool slot while an idle-session validation or a new connect
/// is awaiting. Dropping either future must release the slot even though the
/// connection has not yet reached the acquired/in-use accounting phase.
struct PendingOpenSlot {
    state: Arc<Mutex<PoolState>>,
    active: bool,
}

impl PendingOpenSlot {
    fn new(state: Arc<Mutex<PoolState>>) -> Self {
        Self {
            state,
            active: true,
        }
    }

    fn complete(mut self) {
        self.active = false;
    }

    fn discard(mut self) -> Result<(), DbError> {
        let mut state = self
            .state
            .lock()
            .map_err(|err| DbError::Internal(format!("pool lock poisoned: {err}")))?;
        state.open_count = state.open_count.saturating_sub(1);
        self.active = false;
        Ok(())
    }
}

impl Drop for PendingOpenSlot {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        match self.state.lock() {
            Ok(mut state) => {
                state.open_count = state.open_count.saturating_sub(1);
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    "pending pool open slot dropped after the accounting lock was poisoned"
                );
            }
        }
    }
}

/// Owns one successful pool checkout until it is explicitly checked in.
/// Dropping an in-flight future therefore performs the dirty accounting edge
/// synchronously and never returns a possibly torn session to the idle set.
struct CheckedOutConnection<T> {
    connection: Option<T>,
    state: Arc<Mutex<PoolState>>,
    permit: Option<OwnedSemaphorePermit>,
}

impl<T> CheckedOutConnection<T> {
    fn new(connection: T, state: Arc<Mutex<PoolState>>, permit: OwnedSemaphorePermit) -> Self {
        Self {
            connection: Some(connection),
            state,
            permit: Some(permit),
        }
    }

    #[cfg(test)]
    fn new_without_permit(connection: T, state: Arc<Mutex<PoolState>>) -> Self {
        Self {
            connection: Some(connection),
            state,
            permit: None,
        }
    }

    fn connection(&self) -> &T {
        self.connection
            .as_ref()
            .expect("checked-out connection remains owned until finish")
    }
}

impl CheckedOutConnection<RustOracleConnection> {
    fn finish(mut self, broken: bool) -> Result<(), DbError> {
        let mut state = self
            .state
            .lock()
            .map_err(|err| DbError::Internal(format!("pool lock poisoned: {err}")))?;
        let connection = self
            .connection
            .take()
            .expect("checked-out connection finishes exactly once");
        if record_checkin(&mut state, broken) {
            state.idle.push(connection);
            drop(state);
        } else {
            drop(state);
            drop(connection);
        }
        drop(self.permit.take());
        Ok(())
    }
}

impl<T> Drop for CheckedOutConnection<T> {
    fn drop(&mut self) {
        let Some(connection) = self.connection.take() else {
            return;
        };
        match self.state.lock() {
            Ok(mut state) => {
                let _ = record_checkin(&mut state, true);
            }
            Err(error) => {
                tracing::error!(
                    error = %error,
                    "pool checkout dropped after the accounting lock was poisoned"
                );
            }
        }
        drop(connection);
        drop(self.permit.take());
    }
}

/// Connection-agnostic check-in accounting (B4): decrement the in-use count and
/// either count a clean release (returns `true` — caller stashes the connection
/// for reuse) or a dirty discard (returns `false` — caller drops it, and
/// `open_count` is decremented so the slot can be re-opened). Split out so the
/// dirty-discard + accounting state machine is testable without a live driver
/// connection.
fn record_checkin(state: &mut PoolState, broken: bool) -> bool {
    // Every checkout decrements in-use exactly once here, regardless of whether
    // the connection is returned clean or discarded dirty.
    state.in_use = state.in_use.saturating_sub(1);
    if broken || state.closing {
        state.open_count = state.open_count.saturating_sub(1);
        state.discarded += 1;
        false
    } else {
        state.released += 1;
        true
    }
}

#[async_trait(?Send)]
impl OracleConnection for OraclePool {
    fn backend(&self) -> OracleBackend {
        OracleBackend::RustOracle
    }

    fn request_deadline(&self, cx: &Cx) -> Result<Option<Time>, DbError> {
        Ok(self.request_limits_for(cx)?.deadline)
    }

    fn set_request_deadline(&self, cx: &Cx, deadline: Option<Time>) -> Result<(), DbError> {
        self.update_request_limits(cx, |limits| limits.deadline = deadline)
    }

    fn request_quota(&self, cx: &Cx) -> Result<Option<DbRequestQuota>, DbError> {
        Ok(self.request_limits_for(cx)?.quota)
    }

    fn set_request_quota(&self, cx: &Cx, quota: Option<DbRequestQuota>) -> Result<(), DbError> {
        self.update_request_limits(cx, |limits| limits.quota = quota)
    }

    async fn ping(&self, cx: &Cx) -> Result<(), DbError> {
        OraclePool::ping(self, cx).await
    }

    async fn close(&self, cx: &Cx) -> Result<(), DbError> {
        OraclePool::close(self, cx).await
    }

    async fn describe(&self, cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        let mut info = OraclePool::describe(self, cx).await?;
        info.connection_strategy = Some("stateless_metadata_pool".to_owned());
        info.pool_open_connections = Some(self.state_connections()?);
        Ok(info)
    }

    async fn query_rows(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        OraclePool::query_rows(self, cx, sql.to_owned(), binds.to_vec()).await
    }

    async fn execute(&self, _cx: &Cx, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
        Err(DbError::Execute(
            "pooled stateless metadata connection does not execute statements".to_owned(),
        ))
    }

    async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
        Err(DbError::Execute(
            "pooled stateless metadata connection does not own transactions".to_owned(),
        ))
    }

    async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
        Err(DbError::Execute(
            "pooled stateless metadata connection does not own transactions".to_owned(),
        ))
    }
}

fn retry_now(
    retry_policy: RetryPolicy,
    attempt: u32,
    actual_action: oraclemcp_error::OracleRetryAction,
    expected_action: oraclemcp_error::OracleRetryAction,
) -> bool {
    actual_action == expected_action
        && retry_policy
            .next_delay_for_action(attempt, false, actual_action)
            .is_some_and(|delay| delay.is_zero())
}

#[cfg(test)]
fn should_discard_after_call<T>(
    result: &Result<T, DbError>,
    manager_broken: impl FnOnce() -> bool,
) -> bool {
    result.is_err() || manager_broken()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::{Future, pending};
    use std::panic::AssertUnwindSafe;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::Instant;

    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;

    #[derive(Default)]
    struct WakeCounter(AtomicUsize);

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[test]
    fn pool_settings_defaults() {
        let s = PoolSettings::default();
        assert_eq!(s.max_size, 16);
        assert_eq!(s.min_idle, 2);
        assert_eq!(s.acquire_timeout_secs, 5);
        assert_eq!(s.statement_cache_size, 50);
    }

    #[test]
    fn checkout_deadline_rejects_every_out_of_contract_boundary_without_panicking() {
        let now = Time::from_secs(17);
        for timeout in [
            0,
            1,
            MAX_POOL_ACQUIRE_TIMEOUT_SECS,
            MAX_POOL_ACQUIRE_TIMEOUT_SECS + 1,
            u64::MAX,
        ] {
            let result = std::panic::catch_unwind(|| checkout_deadline(now, timeout));
            let result = result.expect("checkout deadline construction must never panic");
            if timeout <= MAX_POOL_ACQUIRE_TIMEOUT_SECS {
                assert!(result.is_ok(), "accepted timeout {timeout}: {result:?}");
            } else {
                assert!(
                    matches!(result, Err(DbError::Pool(_))),
                    "rejected timeout {timeout}: {result:?}"
                );
            }
        }

        assert!(
            checkout_deadline(Time::MAX, 1).is_err(),
            "absolute deadline arithmetic fails closed on overflow"
        );
    }

    #[test]
    fn checkout_poll_slice_never_moves_the_absolute_deadline_forward() {
        let deadline = Time::from_secs(10);
        assert_eq!(
            checkout_poll_deadline(Time::from_millis(9_950), deadline),
            deadline,
            "the final cancellation slice is capped by the original deadline"
        );
        assert_eq!(
            checkout_poll_deadline(Time::from_secs(11), deadline),
            deadline,
            "a delayed first poll cannot restart or extend the timeout"
        );
    }

    #[test]
    fn checkout_deadline_classification_preserves_cancellation_at_the_boundary() {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            cx.set_cancel_requested(true);
            let deadline = Time::from_secs(10);
            let result = check_checkout_wait_deadline(&cx, deadline, deadline);
            assert!(
                matches!(result, Err(DbError::Cancelled(_))),
                "cancellation wins when it arrives at the checkout deadline: {result:?}"
            );
        });
    }

    #[test]
    fn stateless_pool_refuses_mutation_without_checking_out_a_session() {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        let pool = OraclePool::for_test_at_open_count(PoolSettings::default(), 0);

        runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            let concrete_error = pool
                .execute(&cx, "UPDATE sensitive_table SET value = 1", &[])
                .await
                .expect_err("concrete stateless pool must refuse mutation");
            assert!(
                matches!(
                    concrete_error,
                    DbError::Execute(ref message)
                        if message == "pooled stateless metadata connection does not execute statements"
                ),
                "unexpected concrete refusal: {concrete_error:?}"
            );

            let connection: &dyn OracleConnection = &pool;
            let trait_error = connection
                .execute(&cx, "ALTER SESSION SET CURRENT_SCHEMA = OTHER", &[])
                .await
                .expect_err("trait-object stateless pool must refuse mutation");
            assert!(
                matches!(
                    trait_error,
                    DbError::Execute(ref message)
                        if message == "pooled stateless metadata connection does not execute statements"
                ),
                "unexpected trait-object refusal: {trait_error:?}"
            );
        });

        let metrics = pool.metrics().expect("pool metrics");
        assert_eq!(metrics.acquired, 0, "refusal must happen before checkout");
        assert_eq!(metrics.released, 0);
        assert_eq!(metrics.discarded, 0);
        assert_eq!(metrics.in_use, 0);
    }

    #[test]
    fn cpu_derived_ceiling_is_two_n_plus_one() {
        assert_eq!(cpu_derived_ceiling(1), 3);
        assert_eq!(cpu_derived_ceiling(4), 9);
        assert_eq!(cpu_derived_ceiling(8), 17);
        // The default config ceiling (16) is reached at cpu>=8 (cpu*2+1>=17).
        assert!(cpu_derived_ceiling(8) > 16);
        // Saturating: no overflow at the u32 edge.
        assert_eq!(cpu_derived_ceiling(u32::MAX), u32::MAX);
    }

    #[test]
    fn resolved_clamps_max_size_to_cpu_ceiling() {
        // On a small host (1 cpu => ceiling 3) the default max_size=16 is
        // clamped DOWN to 3 — the cpu-derived sizing the config promises.
        let resolved = PoolSettings::default().resolved_for_cpus(1);
        assert_eq!(resolved.max_size, 3, "max_size clamped to cpu*2+1");
        // min_idle (2) still fits under the resolved ceiling.
        assert_eq!(resolved.min_idle, 2);
        assert_eq!(resolved.acquire_timeout_secs, 5);
        assert_eq!(resolved.statement_cache_size, 50);
    }

    #[test]
    fn resolved_keeps_configured_max_when_below_cpu_ceiling() {
        // A small configured ceiling is the binding constraint even on a big
        // host (the configured value is a ceiling, never a floor).
        let configured = PoolSettings {
            max_size: 4,
            min_idle: 8, // deliberately too large
            acquire_timeout_secs: 0,
            statement_cache_size: 64,
        };
        let resolved = configured.resolved_for_cpus(64);
        assert_eq!(
            resolved.max_size, 4,
            "configured ceiling wins under big cpu"
        );
        assert_eq!(resolved.min_idle, 4, "min_idle clamped to max_size");
        assert_eq!(
            resolved.acquire_timeout_secs, 1,
            "acquire timeout floored to >=1s"
        );
    }

    #[test]
    fn pool_metrics_balance_and_bound_predicates() {
        let balanced = PoolMetrics {
            open: 2,
            idle: 2,
            in_use: 0,
            max_size: 4,
            acquired: 10,
            released: 7,
            discarded: 3,
        };
        assert!(balanced.is_balanced(), "10 == 7 + 3 and nothing in flight");
        assert!(balanced.is_bounded(), "open 2 <= max 4");

        let leaked = PoolMetrics {
            in_use: 1,
            ..balanced
        };
        assert!(!leaked.is_balanced(), "a connection is still checked out");

        let unbalanced = PoolMetrics {
            discarded: 2,
            ..balanced
        };
        assert!(
            !unbalanced.is_balanced(),
            "10 != 7 + 2 — an acquire is unaccounted for"
        );

        let over = PoolMetrics {
            open: 5,
            ..balanced
        };
        assert!(!over.is_bounded(), "open 5 > max 4");
    }

    #[test]
    fn released_permit_wakes_only_fifo_head_and_blocks_barging() {
        let capacity = Arc::new(Semaphore::new(1));
        let held = OwnedSemaphorePermit::try_acquire_arc(&capacity, 1).expect("initial permit");
        let first_context = Cx::<asupersync::cx::cap::None>::detached_cancel_context();
        let second_context = Cx::<asupersync::cx::cap::None>::detached_cancel_context();
        let mut first_wait = Box::pin(OwnedSemaphorePermit::acquire(
            Arc::clone(&capacity),
            &first_context,
            1,
        ));
        let mut second_wait = Box::pin(OwnedSemaphorePermit::acquire(
            Arc::clone(&capacity),
            &second_context,
            1,
        ));
        let first_wakes = Arc::new(WakeCounter::default());
        let second_wakes = Arc::new(WakeCounter::default());
        let first_waker = Waker::from(Arc::clone(&first_wakes));
        let second_waker = Waker::from(Arc::clone(&second_wakes));
        let mut first_cx = Context::from_waker(&first_waker);
        let mut second_cx = Context::from_waker(&second_waker);

        assert!(first_wait.as_mut().poll(&mut first_cx).is_pending());
        assert!(second_wait.as_mut().poll(&mut second_cx).is_pending());
        drop(held);
        assert_eq!(
            first_wakes.0.load(Ordering::Acquire),
            1,
            "one released slot wakes one parked checkout exactly once"
        );
        assert_eq!(
            second_wakes.0.load(Ordering::Acquire),
            0,
            "one released slot must not wake the rest of the checkout queue"
        );
        assert!(
            OwnedSemaphorePermit::try_acquire_arc(&capacity, 1).is_err(),
            "new arrivals cannot barge ahead of the queued FIFO head"
        );
        assert!(second_wait.as_mut().poll(&mut second_cx).is_pending());
        let first_permit = match first_wait.as_mut().poll(&mut first_cx) {
            Poll::Ready(Ok(permit)) => permit,
            other => panic!("FIFO head must acquire the released permit: {other:?}"),
        };
        drop(first_permit);
        let second_permit = match second_wait.as_mut().poll(&mut second_cx) {
            Poll::Ready(Ok(permit)) => permit,
            other => panic!("FIFO successor must acquire after the head: {other:?}"),
        };
        drop(second_permit);
    }

    #[test]
    fn dropping_woken_fifo_head_hands_the_permit_to_its_successor() {
        let capacity = Arc::new(Semaphore::new(1));
        let held = OwnedSemaphorePermit::try_acquire_arc(&capacity, 1).expect("initial permit");
        let first_context = Cx::<asupersync::cx::cap::None>::detached_cancel_context();
        let second_context = Cx::<asupersync::cx::cap::None>::detached_cancel_context();
        let mut first_wait = Box::pin(OwnedSemaphorePermit::acquire(
            Arc::clone(&capacity),
            &first_context,
            1,
        ));
        let mut second_wait = Box::pin(OwnedSemaphorePermit::acquire(
            Arc::clone(&capacity),
            &second_context,
            1,
        ));
        let first_wakes = Arc::new(WakeCounter::default());
        let second_wakes = Arc::new(WakeCounter::default());
        let first_waker = Waker::from(Arc::clone(&first_wakes));
        let second_waker = Waker::from(Arc::clone(&second_wakes));
        let mut first_cx = Context::from_waker(&first_waker);
        let mut second_cx = Context::from_waker(&second_waker);

        assert!(first_wait.as_mut().poll(&mut first_cx).is_pending());
        assert!(second_wait.as_mut().poll(&mut second_cx).is_pending());
        drop(held);
        assert_eq!(
            first_wakes.0.load(Ordering::Acquire),
            1,
            "the released permit first wakes the FIFO head"
        );
        drop(first_wait);
        assert_eq!(
            second_wakes.0.load(Ordering::Acquire),
            1,
            "dropping the selected head hands runnable capacity to its successor"
        );
        let second_permit = match second_wait.as_mut().poll(&mut second_cx) {
            Poll::Ready(Ok(permit)) => permit,
            other => panic!("successor must acquire the handed-off permit: {other:?}"),
        };
        drop(second_permit);
    }

    #[test]
    fn cancelled_fifo_acquire_removes_its_registration() {
        let capacity = Arc::new(Semaphore::new(1));
        let held = OwnedSemaphorePermit::try_acquire_arc(&capacity, 1).expect("initial permit");
        let cancelled_context = Cx::<asupersync::cx::cap::None>::detached_cancel_context();
        let mut waiter = Box::pin(OwnedSemaphorePermit::acquire(
            Arc::clone(&capacity),
            &cancelled_context,
            1,
        ));
        let mut task_cx = Context::from_waker(Waker::noop());
        assert!(waiter.as_mut().poll(&mut task_cx).is_pending());
        cancelled_context.set_cancel_requested(true);
        assert!(
            matches!(
                waiter.as_mut().poll(&mut task_cx),
                Poll::Ready(Err(AcquireError::Cancelled))
            ),
            "the queued acquire observes its Cx cancellation"
        );
        drop(waiter);
        drop(held);
        assert!(
            OwnedSemaphorePermit::try_acquire_arc(&capacity, 1).is_ok(),
            "cancelled waiter registration cannot retain or consume capacity"
        );
    }

    #[test]
    fn poisoned_pool_accounting_is_an_error_not_healthy_zeroes() {
        let pool = OraclePool::for_test_at_open_count(PoolSettings::default(), 1);
        let state = Arc::clone(&pool.state);
        let poisoned = std::panic::catch_unwind(AssertUnwindSafe(move || {
            let _guard = state.lock().expect("pool state starts healthy");
            panic!("poison pool state for deterministic test");
        }));
        assert!(poisoned.is_err());
        assert!(matches!(pool.metrics(), Err(DbError::Internal(_))));
        assert!(matches!(
            pool.state_connections(),
            Err(DbError::Internal(_))
        ));
    }

    #[test]
    fn every_final_failure_discards_checked_out_connection() {
        let cancelled: Result<(), DbError> =
            Err(DbError::Cancelled("test cancellation".to_owned()));
        assert!(
            should_discard_after_call(&cancelled, || false),
            "a cancelled DB call may have crossed an Oracle boundary and must not return clean"
        );
        let package_reset: Result<(), DbError> = Err(DbError::Query(
            "ORA-04068: existing state of packages has been discarded".to_owned(),
        ));
        assert!(
            should_discard_after_call(&package_reset, || false),
            "a final failed pooled call is discarded even if the error class was retry-in-place"
        );
        let syntax_error: Result<(), DbError> = Err(DbError::Query("ORA-00942".to_owned()));
        assert!(
            should_discard_after_call(&syntax_error, || false),
            "ordinary final SQL errors are not returned to the idle pool"
        );
        let ok: Result<(), DbError> = Ok(());
        assert!(!should_discard_after_call(&ok, || false));
        assert!(should_discard_after_call(&ok, || true));
    }

    #[test]
    fn retry_policy_allows_exactly_one_immediate_retry_per_request() {
        let policy = RetryPolicy::one_immediate_retry();
        for action in [
            oraclemcp_error::OracleRetryAction::RetrySameConnection,
            oraclemcp_error::OracleRetryAction::ReconnectThenRetry,
        ] {
            assert!(
                retry_now(policy, 1, action, action),
                "first {action:?} failure gets one immediate replay"
            );
            assert!(
                !retry_now(policy, 2, action, action),
                "the retry budget is exhausted after the first replay"
            );
        }
        assert!(!retry_now(
            policy,
            1,
            oraclemcp_error::OracleRetryAction::Never,
            oraclemcp_error::OracleRetryAction::ReconnectThenRetry,
        ));
    }

    fn seeded_state(open_count: u32) -> PoolState {
        PoolState {
            idle: Vec::new(),
            open_count,
            closing: false,
            in_use: 1,
            acquired: 1,
            released: 0,
            discarded: 0,
        }
    }

    #[test]
    fn record_checkin_clean_returns_to_idle_and_counts_release() {
        // A healthy connection: returns true (caller stashes it for reuse), the
        // release counter advances, and the open-count is unchanged.
        let mut state = seeded_state(3);
        let stash = record_checkin(&mut state, false);
        assert!(stash, "a clean connection is returned to the idle set");
        assert_eq!(state.released, 1);
        assert_eq!(state.discarded, 0);
        assert_eq!(
            state.open_count, 3,
            "a clean check-in does not close the slot"
        );
        assert_eq!(state.in_use, 0, "the checkout is no longer in flight");
    }

    #[test]
    fn record_checkin_dirty_discards_and_frees_slot() {
        // A dirty/errored/cancelled connection: returns false (caller DROPS it,
        // never reuses it), the discard counter advances, and the open-count is
        // decremented so the freed slot can be re-opened with a fresh session.
        let mut state = seeded_state(3);
        let stash = record_checkin(&mut state, true);
        assert!(!stash, "a dirty connection is NOT returned to the idle set");
        assert_eq!(state.discarded, 1);
        assert_eq!(state.released, 0);
        assert_eq!(state.open_count, 2, "the dirty connection's slot is freed");
        assert_eq!(state.in_use, 0);
        // Accounting balances: 1 acquired == 0 released + 1 discarded.
        assert_eq!(state.acquired, state.released + state.discarded);
    }

    #[test]
    fn closing_pool_discards_a_late_clean_checkin() {
        // A shutdown race must never reintroduce a session after `close` has
        // drained the idle set. The late checkout is discarded and its slot is
        // accounted for exactly like a broken connection.
        let mut state = seeded_state(3);
        state.closing = true;
        let stash = record_checkin(&mut state, false);
        assert!(!stash, "a closing pool never reuses a checked-in session");
        assert_eq!(state.discarded, 1);
        assert_eq!(state.released, 0);
        assert_eq!(state.open_count, 2);
        assert_eq!(state.in_use, 0);
    }

    #[test]
    fn dirty_discard_no_pool_return() {
        let settings = PoolSettings {
            max_size: 2,
            min_idle: 0,
            acquire_timeout_secs: 1,
            statement_cache_size: 50,
        };
        let pool = OraclePool::for_test_at_open_count(settings, 2);
        {
            let mut state = pool.state.lock().expect("pool state lock");
            state.in_use = 1;
            state.acquired = 1;
            assert_eq!(state.open_count, pool.settings.max_size);
            assert_eq!(state.idle.len(), 0);

            let return_to_idle = record_checkin(&mut state, true);
            assert!(!return_to_idle, "dirty connection is dropped, not pooled");
            assert_eq!(state.idle.len(), 0, "dirty connection never reaches idle");
            assert_eq!(state.discarded, 1);
            assert_eq!(state.released, 0);
            assert_eq!(state.open_count, pool.settings.max_size - 1);
            assert_eq!(state.in_use, 0);
        }

        assert!(
            pool.reserve_new_connection().expect("replacement slot"),
            "dirty discard frees capacity only for a fresh connection"
        );
        let metrics = pool.metrics().expect("pool metrics");
        assert!(metrics.is_balanced());
        assert!(metrics.is_bounded());
        assert_eq!(metrics.open, metrics.max_size);
        assert_eq!(metrics.idle, 0, "replacement was reserved, not reused idle");
    }

    #[test]
    fn request_limits_are_isolated_by_runtime_task_identity() {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        let pool = OraclePool::for_test_at_open_count(PoolSettings::default(), 0);
        let ready = Arc::new(AtomicUsize::new(0));

        let deadline_a = Time::from_secs(11);
        let quota_a = DbRequestQuota::new(Budget::new().with_poll_quota(3).with_cost_quota(13));
        let task_a = {
            let pool = pool.clone();
            let ready = Arc::clone(&ready);
            let expected_quota = quota_a.clone();
            runtime.handle().spawn(async move {
                let cx = Cx::current().expect("spawned task installs its own Cx");
                pool.set_request_deadline(&cx, Some(deadline_a))
                    .expect("task A deadline");
                pool.set_request_quota(&cx, Some(expected_quota))
                    .expect("task A quota");
                ready.fetch_add(1, Ordering::AcqRel);
                while ready.load(Ordering::Acquire) < 2 {
                    asupersync::runtime::yield_now().await;
                }
                let observed = (
                    OraclePool::request_key(&cx),
                    pool.request_deadline(&cx).expect("task A deadline read"),
                    pool.request_quota(&cx).expect("task A quota read"),
                );
                pool.set_request_deadline(&cx, None)
                    .expect("clear task A deadline");
                pool.set_request_quota(&cx, None)
                    .expect("clear task A quota");
                observed
            })
        };

        let deadline_b = Time::from_secs(29);
        let quota_b = DbRequestQuota::new(Budget::new().with_poll_quota(7).with_cost_quota(31));
        let task_b = {
            let pool = pool.clone();
            let ready = Arc::clone(&ready);
            let expected_quota = quota_b.clone();
            runtime.handle().spawn(async move {
                let cx = Cx::current().expect("spawned task installs its own Cx");
                pool.set_request_deadline(&cx, Some(deadline_b))
                    .expect("task B deadline");
                pool.set_request_quota(&cx, Some(expected_quota))
                    .expect("task B quota");
                ready.fetch_add(1, Ordering::AcqRel);
                while ready.load(Ordering::Acquire) < 2 {
                    asupersync::runtime::yield_now().await;
                }
                let observed = (
                    OraclePool::request_key(&cx),
                    pool.request_deadline(&cx).expect("task B deadline read"),
                    pool.request_quota(&cx).expect("task B quota read"),
                );
                pool.set_request_deadline(&cx, None)
                    .expect("clear task B deadline");
                pool.set_request_quota(&cx, None)
                    .expect("clear task B quota");
                observed
            })
        };

        let observed_a = runtime.block_on(task_a);
        let observed_b = runtime.block_on(task_b);
        assert_ne!(
            observed_a.0, observed_b.0,
            "spawned requests must have distinct pool request-limit keys"
        );
        assert_eq!(observed_a.1, Some(deadline_a));
        assert_eq!(observed_b.1, Some(deadline_b));
        let observed_quota_a = observed_a.2.expect("task A quota remains installed");
        let observed_quota_b = observed_b.2.expect("task B quota remains installed");
        assert!(observed_quota_a.ptr_eq(&quota_a));
        assert!(!observed_quota_a.ptr_eq(&quota_b));
        assert_eq!(observed_quota_a.polls_remaining(), 3);
        assert_eq!(observed_quota_a.cost_remaining(), Some(13));
        assert!(observed_quota_b.ptr_eq(&quota_b));
        assert!(!observed_quota_b.ptr_eq(&quota_a));
        assert_eq!(observed_quota_b.polls_remaining(), 7);
        assert_eq!(observed_quota_b.cost_remaining(), Some(31));
        assert!(
            pool.request_limits
                .lock()
                .expect("request limits lock")
                .is_empty(),
            "restoring both limits to None removes the per-task map entries"
        );
    }

    #[test]
    fn dropped_checked_out_future_dirty_discards_without_accounting_leak() {
        let state = Arc::new(Mutex::new(seeded_state(1)));
        let guard_state = Arc::clone(&state);
        let mut in_flight = Box::pin(async move {
            let _checkout = CheckedOutConnection::new_without_permit((), guard_state);
            pending::<()>().await;
        });
        let mut task_cx = Context::from_waker(Waker::noop());
        assert!(
            in_flight.as_mut().poll(&mut task_cx).is_pending(),
            "future reaches its in-flight wait with the checkout guard alive"
        );

        drop(in_flight);

        let state = state.lock().expect("pool state lock");
        assert_eq!(state.open_count, 0, "dirty drop frees the open slot");
        assert_eq!(state.in_use, 0, "dirty drop closes the in-use edge");
        assert_eq!(state.discarded, 1);
        assert_eq!(state.released, 0);
        assert_eq!(state.acquired, state.released + state.discarded);
        assert!(state.idle.is_empty(), "a torn checkout is never reused");
    }

    #[test]
    fn dropped_pending_open_future_releases_reserved_slot() {
        let state = Arc::new(Mutex::new(PoolState {
            idle: Vec::new(),
            open_count: 1,
            closing: false,
            in_use: 0,
            acquired: 0,
            released: 0,
            discarded: 0,
        }));
        let guard_state = Arc::clone(&state);
        let mut opening = Box::pin(async move {
            let _pending_slot = PendingOpenSlot::new(guard_state);
            pending::<()>().await;
        });
        let mut task_cx = Context::from_waker(Waker::noop());
        assert!(
            opening.as_mut().poll(&mut task_cx).is_pending(),
            "future reaches its connection wait with the reservation alive"
        );

        drop(opening);

        let state = state.lock().expect("pool state lock");
        assert_eq!(
            state.open_count, 0,
            "dropping connection establishment releases its reserved capacity"
        );
        assert_eq!(state.in_use, 0);
        assert_eq!(state.acquired, 0);
        assert_eq!(state.released, 0);
        assert_eq!(state.discarded, 0);
    }

    #[test]
    fn reserve_new_connection_is_bounded_by_max_size() {
        // At the ceiling, no new connection may be reserved (so the pool can
        // never open more than `max_size` sessions to one DB).
        let pool = OraclePool::for_test_at_open_count(PoolSettings::default(), 0);
        let max = pool.settings.max_size;
        // Reserve up to the ceiling.
        for _ in 0..max {
            assert!(pool.reserve_new_connection().expect("reserve ok"));
        }
        assert!(
            !pool.reserve_new_connection().expect("reserve ok"),
            "reservation refused once open_count hits max_size"
        );
        let metrics = pool.metrics().expect("pool metrics");
        assert_eq!(metrics.open, max, "open never exceeds the ceiling");
        assert!(metrics.is_bounded());
    }

    #[test]
    fn parked_checkout_permit_is_woken_by_cx_cancellation() {
        let settings = PoolSettings {
            max_size: 1,
            min_idle: 0,
            acquire_timeout_secs: 5,
            statement_cache_size: 0,
        };
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        runtime.block_on(async move {
            let cancel_cx = Cx::current().expect("block_on installs a current Cx");
            let pool = OraclePool::for_test_at_open_count(settings, 1);
            let deadline =
                checkout_deadline(asupersync::time::wall_now(), settings.acquire_timeout_secs)
                    .expect("representable checkout deadline");
            let canceller_cx = cancel_cx.clone();
            let capacity = Arc::clone(&pool.capacity);
            let canceller = std::thread::spawn(move || {
                let registration_deadline = Instant::now() + Duration::from_secs(1);
                let registered = loop {
                    if capacity.telemetry_snapshot(0).waiter_count == 1 {
                        break true;
                    }
                    if Instant::now() >= registration_deadline {
                        break false;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                };
                canceller_cx.cancel_fast(asupersync::types::CancelKind::User);
                registered
            });
            let started = Instant::now();
            let result = pool.acquire_checkout_permit(&cancel_cx, deadline).await;
            let registered = canceller.join().expect("cancellation helper joins");
            assert!(registered, "the checkout was parked before cancellation");
            assert!(
                matches!(result, Err(DbError::Cancelled(_))),
                "the parked checkout preserves cancellation classification: {result:?}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "cancellation must not wait for the five-second acquire deadline"
            );
        });
    }

    #[test]
    fn checkout_respects_acquire_timeout_when_exhausted() {
        // A pool seeded full (open_count == max_size) with no idle connections
        // must time out the checkout with a `Pool` (BUSY) error — never block
        // forever and never call `connect` (the manager has no reachable DB).
        let settings = PoolSettings {
            max_size: 2,
            min_idle: 0,
            acquire_timeout_secs: 1,
            statement_cache_size: 50,
        };
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let runtime = RuntimeBuilder::current_thread()
                .build()
                .expect("current-thread runtime");
            let observation = runtime.block_on(async {
                let cx = Cx::current().expect("block_on installs a current Cx");
                // Resolve to learn the effective ceiling, then seed the pool full.
                let effective_max = settings.resolved().max_size;
                let pool = OraclePool::for_test_at_open_count(settings, effective_max);
                let start = Instant::now();
                let result = pool.checkout(&cx).await;
                (matches!(result, Err(DbError::Pool(_))), start.elapsed())
            });
            let _ = result_tx.send(observation);
        });

        let (timed_out_as_busy, elapsed) = result_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("watchdog: exhausted checkout must finish within three seconds");
        assert!(
            timed_out_as_busy,
            "an exhausted pool times out with a Pool/BUSY error"
        );
        assert!(
            elapsed >= Duration::from_secs(1),
            "the checkout waited for the full acquire timeout before giving up"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "the checkout exceeded its one-second absolute deadline by too much: {elapsed:?}"
        );
    }
}
