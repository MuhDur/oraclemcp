//! Bounded thin-mode connection pool for callers that need reusable sessions.
//!
//! `Cx`-first and `async` (B1): callers get bounded session reuse without a
//! Tokio/r2d2 boundary, and cancellation is observed through explicit
//! `&asupersync::Cx` checkpoints around checkout and through the native-async
//! DB calls themselves. A cancelled or failed call discards the checked-out
//! connection DIRTY (it never returns to the idle set) so a torn round trip
//! can never be reused.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use asupersync::Cx;
use async_trait::async_trait;

use crate::connection::{OracleConnection, RustOracleConnection};
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
        cx.checkpoint_with("oracle_pool.connect.before")
            .map_err(|err| DbError::Cancelled(format!("oracle_pool.connect.before: {err}")))?;
        let conn = RustOracleConnection::connect(cx, self.opts.clone()).await?;
        cx.checkpoint_with("oracle_pool.connect.after")
            .map_err(|err| DbError::Cancelled(format!("oracle_pool.connect.after: {err}")))?;
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
            max_size: 20,
            min_idle: 2,
            acquire_timeout_secs: 5,
            statement_cache_size: 50,
        }
    }
}

struct PoolState {
    idle: Vec<RustOracleConnection>,
    open_count: u32,
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
        let settings = PoolSettings {
            max_size: settings.max_size.max(1),
            min_idle: settings.min_idle.min(settings.max_size.max(1)),
            acquire_timeout_secs: settings.acquire_timeout_secs.max(1),
            statement_cache_size: settings.statement_cache_size,
        };
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
        cx.checkpoint_with("oracle_pool.checkout.before")
            .map_err(|err| DbError::Cancelled(format!("oracle_pool.checkout.before: {err}")))?;
        let conn = self.checkout(cx).await?;
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
            cx.checkpoint_with("oracle_pool.checkout.loop")
                .map_err(|err| DbError::Cancelled(format!("oracle_pool.checkout.loop: {err}")))?;
            if let Some(conn) = self.try_checkout(cx).await? {
                return Ok(conn);
            }
            if Instant::now() >= deadline {
                return Err(DbError::Pool(
                    "timed out waiting for thin Oracle connection".to_owned(),
                ));
            }
            asupersync::time::sleep(cx.now(), Duration::from_millis(10)).await;
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

    fn checkin(&self, conn: RustOracleConnection, broken: bool) -> Result<(), DbError> {
        let mut state = self
            .state
            .lock()
            .map_err(|err| DbError::Internal(format!("pool lock poisoned: {err}")))?;
        if broken {
            state.open_count = state.open_count.saturating_sub(1);
        } else {
            state.idle.push(conn);
        }
        Ok(())
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

    #[test]
    fn pool_settings_defaults() {
        let s = PoolSettings::default();
        assert_eq!(s.max_size, 20);
        assert_eq!(s.min_idle, 2);
        assert_eq!(s.acquire_timeout_secs, 5);
        assert_eq!(s.statement_cache_size, 50);
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
}
