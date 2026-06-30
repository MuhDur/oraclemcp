//! Bounded thin-mode connection pool for callers that need reusable sessions.
//!
//! `Cx`-first and `async` (B1): callers get bounded session reuse without a
//! Tokio/r2d2 boundary, and cancellation is observed through explicit
//! `&asupersync::Cx` checkpoints around checkout and through the native-async
//! DB calls themselves. A cancelled or failed call discards the checked-out
//! connection DIRTY (it never returns to the idle set) so a torn round trip
//! can never be reused.
//!
//! ## Sizing and failover posture (B4)
//!
//! `PoolSettings::max_size` is a *ceiling*; the effective ceiling applied at
//! construction is `min(max_size, cpu*2+1)` (plan §10) via
//! [`PoolSettings::resolved`]. Checkout waits up to `acquire_timeout_secs` for a
//! free or newly-openable connection and then returns a `Pool` (BUSY) error —
//! the acquire loop yields cooperatively (`yield_now`) rather than sleeping on a
//! timer, so the timeout is enforced even on the bare timer-less dispatch
//! runtime. [`PoolMetrics`] exposes the checkout accounting
//! (`acquired`/`released`/`discarded`/`in_use`/`open`) so the zero-leaked-session
//! invariant (`is_balanced`) and the bound (`is_bounded`) are observable.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use asupersync::Cx;
use async_trait::async_trait;

use crate::connection::{OracleConnection, RustOracleConnection, db_checkpoint};
use crate::error::DbError;
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
    /// In-flight (checked-out) connections — the difference between a checkout
    /// and its matching check-in. Drives the zero-leaked-session accounting.
    in_use: u32,
    /// Lifetime checkout/return/discard counters (B3/B4 leak accounting).
    acquired: u64,
    released: u64,
    discarded: u64,
}

/// A small async thin-mode Oracle connection pool.
#[derive(Clone)]
pub struct OraclePool {
    manager: OracleConnectionManager,
    settings: PoolSettings,
    state: Arc<Mutex<PoolState>>,
}

impl OraclePool {
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
                in_use: 0,
                acquired: 0,
                released: 0,
                discarded: 0,
            })),
        })
    }

    /// Current number of idle + in-use connections in the pool.
    #[must_use]
    pub fn state_connections(&self) -> u32 {
        self.state
            .lock()
            .map(|state| state.open_count)
            .unwrap_or_default()
    }

    /// The settings actually in force after CPU-derived resolution (B4).
    #[must_use]
    pub fn settings(&self) -> PoolSettings {
        self.settings
    }

    /// A snapshot of checkout accounting (B3/B4 zero-leaked-session evidence).
    #[must_use]
    pub fn metrics(&self) -> PoolMetrics {
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
            .unwrap_or_default()
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
            Box::pin(async move { conn.query_rows(cx, &sql, &binds).await })
        })
        .await
    }

    /// Run a DML/DDL statement on a pooled connection with cancellation-aware
    /// checkout and DB execution boundaries. Cancelled or failed mutating calls
    /// discard the checked-out connection.
    pub async fn execute(
        &self,
        cx: &Cx,
        sql: impl Into<String>,
        binds: Vec<OracleBind>,
    ) -> Result<u64, DbError> {
        let sql = sql.into();
        self.with_conn(cx, |cx, conn| {
            Box::pin(async move { conn.execute(cx, &sql, &binds).await })
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
        F: for<'a> FnOnce(
            &'a Cx,
            &'a RustOracleConnection,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, DbError>> + 'a>,
        >,
    {
        db_checkpoint(cx, "oracle_pool.checkout.before")?;
        let conn = self.checkout(cx).await?;
        // A connection is in our hands: the matching check-in below is
        // UNCONDITIONAL (it runs on every exit path of `f`, success, error, or
        // cancellation) so the in-use count can never leak.
        self.on_checked_out()?;
        let result = f(cx, &conn).await;
        // A cancelled or errored call may have crossed an Oracle boundary
        // (torn round trip); discard the connection DIRTY rather than returning
        // it to the idle set. A clean call still re-validates with a ping.
        let broken = should_discard_after_call(&result, || {
            // Only ping when the call itself succeeded; a failed/cancelled call
            // is already discarded and a ping might block on a dirty socket.
            false
        });
        let broken = if broken {
            true
        } else {
            self.manager.has_broken(cx, &conn).await
        };
        self.checkin(conn, broken)?;
        result
    }

    async fn checkout(&self, cx: &Cx) -> Result<RustOracleConnection, DbError> {
        let deadline = Instant::now() + Duration::from_secs(self.settings.acquire_timeout_secs);
        loop {
            db_checkpoint(cx, "oracle_pool.checkout.loop")?;
            if let Some(conn) = self.try_checkout(cx).await? {
                return Ok(conn);
            }
            if Instant::now() >= deadline {
                return Err(DbError::Pool(
                    "timed out waiting for thin Oracle connection".to_owned(),
                ));
            }
            // B4: yield cooperatively and re-check the wall-clock deadline. We
            // deliberately do NOT use `asupersync::time::sleep` here: the sleep
            // future only wakes when a timer driver is advancing, and the MCP
            // dispatch runtime (`oraclemcp-core/server.rs`) is a bare
            // current-thread runtime with no timer driver — a timer-driven sleep
            // would PARK FOREVER on an exhausted pool and the acquire timeout
            // would never fire. `yield_now` re-schedules this task without a
            // timer, so the deadline below is always re-evaluated and the
            // acquire timeout is enforced regardless of timer-driver config.
            asupersync::runtime::yield_now().await;
        }
    }

    async fn try_checkout(&self, cx: &Cx) -> Result<Option<RustOracleConnection>, DbError> {
        loop {
            if let Some(conn) = self.take_idle_connection()? {
                if self.manager.is_valid(cx, &conn).await.is_ok() {
                    return Ok(Some(conn));
                }
                self.forget_open_connection()?;
                continue;
            }
            if self.reserve_new_connection()? {
                match self.manager.connect(cx).await {
                    Ok(conn) => return Ok(Some(conn)),
                    Err(err) => {
                        self.forget_open_connection()?;
                        return Err(err);
                    }
                }
            }
            return Ok(None);
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
        if state.open_count < self.settings.max_size {
            state.open_count += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn forget_open_connection(&self) -> Result<(), DbError> {
        let mut state = self
            .state
            .lock()
            .map_err(|err| DbError::Internal(format!("pool lock poisoned: {err}")))?;
        state.open_count = state.open_count.saturating_sub(1);
        Ok(())
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

    fn checkin(&self, conn: RustOracleConnection, broken: bool) -> Result<(), DbError> {
        let mut state = self
            .state
            .lock()
            .map_err(|err| DbError::Internal(format!("pool lock poisoned: {err}")))?;
        if record_checkin(&mut state, broken) {
            // Clean: returns to the idle set for reuse.
            state.idle.push(conn);
        }
        // Dirty discard (B4): `broken` connection is dropped here (never pushed),
        // so a torn round trip can never be reused. `record_checkin` already
        // decremented `open_count` and the in-use count for it.
        Ok(())
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
                in_use: 0,
                acquired: 0,
                released: 0,
                discarded: 0,
            })),
        }
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
    if broken {
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

    async fn ping(&self, cx: &Cx) -> Result<(), DbError> {
        OraclePool::ping(self, cx).await
    }

    async fn describe(&self, cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        let mut info = OraclePool::describe(self, cx).await?;
        info.connection_strategy = Some("stateless_metadata_pool".to_owned());
        info.pool_open_connections = Some(self.state_connections());
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

fn should_discard_after_call<T>(
    result: &Result<T, DbError>,
    manager_broken: impl FnOnce() -> bool,
) -> bool {
    result.is_err() || manager_broken()
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::runtime::RuntimeBuilder;

    #[test]
    fn pool_settings_defaults() {
        let s = PoolSettings::default();
        assert_eq!(s.max_size, 16);
        assert_eq!(s.min_idle, 2);
        assert_eq!(s.acquire_timeout_secs, 5);
        assert_eq!(s.statement_cache_size, 50);
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
    fn cancelled_call_discards_checked_out_connection() {
        let cancelled: Result<(), DbError> =
            Err(DbError::Cancelled("test cancellation".to_owned()));
        assert!(
            should_discard_after_call(&cancelled, || false),
            "a cancelled DB call may have crossed an Oracle boundary and must not return clean"
        );
        let ok: Result<(), DbError> = Ok(());
        assert!(!should_discard_after_call(&ok, || false));
        assert!(should_discard_after_call(&ok, || true));
    }

    fn seeded_state(open_count: u32) -> PoolState {
        PoolState {
            idle: Vec::new(),
            open_count,
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
        let metrics = pool.metrics();
        assert!(metrics.is_balanced());
        assert!(metrics.is_bounded());
        assert_eq!(metrics.open, metrics.max_size);
        assert_eq!(metrics.idle, 0, "replacement was reserved, not reused idle");
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
        assert_eq!(pool.metrics().open, max, "open never exceeds the ceiling");
        assert!(pool.metrics().is_bounded());
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
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            // Resolve to learn the effective ceiling, then seed the pool full.
            let effective_max = settings.resolved().max_size;
            let pool = OraclePool::for_test_at_open_count(settings, effective_max);
            let start = Instant::now();
            let result = pool.checkout(&cx).await;
            let elapsed = start.elapsed();
            assert!(
                matches!(result, Err(DbError::Pool(_))),
                "an exhausted pool times out with a Pool/BUSY error"
            );
            assert!(
                elapsed >= Duration::from_secs(1),
                "the checkout waited for the full acquire timeout before giving up"
            );
        });
    }
}
