//! Bounded thin-mode connection pool for callers that need reusable sessions.
//!
//! This is deliberately small: W4 removes the old r2d2/Tokio boundary, while
//! W6b moves the DB surface to explicit `&asupersync::Cx` cancellation.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use asupersync::Cx;

use crate::connection::{OracleConnection, RustOracleConnection};
use crate::error::DbError;
use crate::types::{OracleBind, OracleConnectOptions, OracleConnectionInfo, OracleRow};

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
    fn connect(&self) -> Result<RustOracleConnection, DbError> {
        RustOracleConnection::connect(self.opts.clone())
    }

    fn connect_cx(&self, cx: &Cx) -> Result<RustOracleConnection, DbError> {
        cx.checkpoint_with("oracle_pool.connect.before")
            .map_err(|err| DbError::Cancelled(format!("oracle_pool.connect.before: {err}")))?;
        let conn = self.connect()?;
        cx.checkpoint_with("oracle_pool.connect.after")
            .map_err(|err| DbError::Cancelled(format!("oracle_pool.connect.after: {err}")))?;
        Ok(conn)
    }

    fn is_valid(&self, conn: &RustOracleConnection) -> Result<(), DbError> {
        conn.ping()
    }

    fn is_valid_cx(&self, cx: &Cx, conn: &RustOracleConnection) -> Result<(), DbError> {
        conn.ping_cx(cx)
    }

    fn has_broken(&self, conn: &RustOracleConnection) -> bool {
        conn.ping().is_err()
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
}

impl Default for PoolSettings {
    fn default() -> Self {
        PoolSettings {
            max_size: 20,
            min_idle: 2,
            acquire_timeout_secs: 5,
        }
    }
}

struct PoolState {
    idle: Vec<RustOracleConnection>,
    open_count: u32,
}

/// A small synchronous thin-mode Oracle connection pool.
#[derive(Clone)]
pub struct OraclePool {
    manager: OracleConnectionManager,
    settings: PoolSettings,
    state: Arc<Mutex<PoolState>>,
}

impl OraclePool {
    /// Build a pool, eagerly establishing `min_idle` connections (so a bad
    /// profile fails fast). Requires a reachable database.
    pub fn connect(opts: OracleConnectOptions, settings: PoolSettings) -> Result<Self, DbError> {
        let manager = OracleConnectionManager::new(opts);
        let settings = PoolSettings {
            max_size: settings.max_size.max(1),
            min_idle: settings.min_idle.min(settings.max_size.max(1)),
            acquire_timeout_secs: settings.acquire_timeout_secs.max(1),
        };
        let mut idle = Vec::new();
        for _ in 0..settings.min_idle {
            idle.push(manager.connect()?);
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

    /// Run a query on a pooled connection.
    pub fn query_rows(
        &self,
        sql: impl Into<String>,
        binds: Vec<OracleBind>,
    ) -> Result<Vec<OracleRow>, DbError> {
        let sql = sql.into();
        self.with_conn(|conn| conn.query_rows(&sql, &binds))
    }

    /// Run a query on a pooled connection with cancellation-aware checkout and
    /// DB execution boundaries.
    pub fn query_rows_cx(
        &self,
        cx: &Cx,
        sql: impl Into<String>,
        binds: Vec<OracleBind>,
    ) -> Result<Vec<OracleRow>, DbError> {
        let sql = sql.into();
        self.with_conn_cx(cx, |conn| conn.query_rows_cx(cx, &sql, &binds))
    }

    /// Run a DML/DDL statement on a pooled connection.
    pub fn execute(&self, sql: impl Into<String>, binds: Vec<OracleBind>) -> Result<u64, DbError> {
        let sql = sql.into();
        self.with_conn(|conn| conn.execute(&sql, &binds))
    }

    /// Run a DML/DDL statement on a pooled connection with cancellation-aware
    /// checkout and DB execution boundaries. Cancelled or failed mutating calls
    /// discard the checked-out connection.
    pub fn execute_cx(
        &self,
        cx: &Cx,
        sql: impl Into<String>,
        binds: Vec<OracleBind>,
    ) -> Result<u64, DbError> {
        let sql = sql.into();
        self.with_conn_cx(cx, |conn| conn.execute_cx(cx, &sql, &binds))
    }

    /// Run one page of a read query (bind-first, paginated, capped) on a pooled
    /// connection (plan §8.2, bead P1-2).
    pub fn read_query(
        &self,
        sql: impl Into<String>,
        binds: Vec<OracleBind>,
        caps: crate::query::QueryCaps,
        offset: usize,
        serialize_opts: crate::serialize::SerializeOptions,
    ) -> Result<crate::query::QueryResponse, DbError> {
        let sql = sql.into();
        self.with_conn(|conn| {
            crate::query::read_query(conn, &sql, &binds, caps, offset, &serialize_opts)
        })
    }

    /// Cancellation-aware variant of [`Self::read_query`].
    pub fn read_query_cx(
        &self,
        cx: &Cx,
        sql: impl Into<String>,
        binds: Vec<OracleBind>,
        caps: crate::query::QueryCaps,
        offset: usize,
        serialize_opts: crate::serialize::SerializeOptions,
    ) -> Result<crate::query::QueryResponse, DbError> {
        let sql = sql.into();
        self.with_conn_cx(cx, |conn| {
            crate::query::read_query_cx(cx, conn, &sql, &binds, caps, offset, &serialize_opts)
        })
    }

    /// Describe a pooled connection (version / role / open-mode / schema).
    pub fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
        self.with_conn(OracleConnection::describe)
    }

    /// Describe a pooled connection with cancellation-aware checkout and DB
    /// execution boundaries.
    pub fn describe_cx(&self, cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        self.with_conn_cx(cx, |conn| conn.describe_cx(cx))
    }

    /// Confirm a pooled connection is live.
    pub fn ping(&self) -> Result<(), DbError> {
        self.with_conn(OracleConnection::ping)
    }

    /// Confirm a pooled connection is live with cancellation-aware checkout.
    pub fn ping_cx(&self, cx: &Cx) -> Result<(), DbError> {
        self.with_conn_cx(cx, |conn| conn.ping_cx(cx))
    }

    fn with_conn<T>(
        &self,
        f: impl FnOnce(&RustOracleConnection) -> Result<T, DbError>,
    ) -> Result<T, DbError> {
        let conn = self.checkout()?;
        let result = f(&conn);
        let broken = self.manager.has_broken(&conn);
        self.checkin(conn, broken)?;
        result
    }

    fn with_conn_cx<T>(
        &self,
        cx: &Cx,
        f: impl FnOnce(&RustOracleConnection) -> Result<T, DbError>,
    ) -> Result<T, DbError> {
        cx.checkpoint_with("oracle_pool.checkout.before")
            .map_err(|err| DbError::Cancelled(format!("oracle_pool.checkout.before: {err}")))?;
        let conn = self.checkout_cx(cx)?;
        let result = f(&conn);
        let broken = should_discard_after_cx_call(&result, self.manager.has_broken(&conn));
        self.checkin(conn, broken)?;
        result
    }

    fn checkout(&self) -> Result<RustOracleConnection, DbError> {
        let deadline = Instant::now() + Duration::from_secs(self.settings.acquire_timeout_secs);
        loop {
            if let Some(conn) = self.try_checkout()? {
                return Ok(conn);
            }
            if Instant::now() >= deadline {
                return Err(DbError::Pool(
                    "timed out waiting for thin Oracle connection".to_owned(),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn checkout_cx(&self, cx: &Cx) -> Result<RustOracleConnection, DbError> {
        let deadline = Instant::now() + Duration::from_secs(self.settings.acquire_timeout_secs);
        loop {
            cx.checkpoint_with("oracle_pool.checkout.loop")
                .map_err(|err| DbError::Cancelled(format!("oracle_pool.checkout.loop: {err}")))?;
            if let Some(conn) = self.try_checkout_cx(cx)? {
                return Ok(conn);
            }
            if Instant::now() >= deadline {
                return Err(DbError::Pool(
                    "timed out waiting for thin Oracle connection".to_owned(),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn try_checkout(&self) -> Result<Option<RustOracleConnection>, DbError> {
        let mut state = self
            .state
            .lock()
            .map_err(|err| DbError::Internal(format!("pool lock poisoned: {err}")))?;
        while let Some(conn) = state.idle.pop() {
            if self.manager.is_valid(&conn).is_ok() {
                return Ok(Some(conn));
            }
            state.open_count = state.open_count.saturating_sub(1);
        }
        if state.open_count < self.settings.max_size {
            state.open_count += 1;
            drop(state);
            match self.manager.connect() {
                Ok(conn) => Ok(Some(conn)),
                Err(err) => {
                    let mut state = self.state.lock().map_err(|lock_err| {
                        DbError::Internal(format!("pool lock poisoned: {lock_err}"))
                    })?;
                    state.open_count = state.open_count.saturating_sub(1);
                    Err(err)
                }
            }
        } else {
            Ok(None)
        }
    }

    fn try_checkout_cx(&self, cx: &Cx) -> Result<Option<RustOracleConnection>, DbError> {
        let mut state = self
            .state
            .lock()
            .map_err(|err| DbError::Internal(format!("pool lock poisoned: {err}")))?;
        while let Some(conn) = state.idle.pop() {
            if self.manager.is_valid_cx(cx, &conn).is_ok() {
                return Ok(Some(conn));
            }
            state.open_count = state.open_count.saturating_sub(1);
        }
        if state.open_count < self.settings.max_size {
            state.open_count += 1;
            drop(state);
            match self.manager.connect_cx(cx) {
                Ok(conn) => Ok(Some(conn)),
                Err(err) => {
                    let mut state = self.state.lock().map_err(|lock_err| {
                        DbError::Internal(format!("pool lock poisoned: {lock_err}"))
                    })?;
                    state.open_count = state.open_count.saturating_sub(1);
                    Err(err)
                }
            }
        } else {
            Ok(None)
        }
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

fn should_discard_after_cx_call<T>(result: &Result<T, DbError>, manager_broken: bool) -> bool {
    result.is_err() || manager_broken
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
    }

    #[test]
    fn cancelled_cx_call_discards_checked_out_connection() {
        let cancelled: Result<(), DbError> =
            Err(DbError::Cancelled("test cancellation".to_owned()));
        assert!(
            should_discard_after_cx_call(&cancelled, false),
            "a cancelled DB call may have crossed an Oracle boundary and must not return clean"
        );
        let ok: Result<(), DbError> = Ok(());
        assert!(!should_discard_after_cx_call(&ok, false));
        assert!(should_discard_after_cx_call(&ok, true));
    }
}
