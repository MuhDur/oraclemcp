//! `r2d2` connection pool + the `tokio::task::spawn_blocking` async boundary
//! (plan §3.1, §4.3, §10). Compiled only with the `oracle-driver` feature.
//!
//! The one invariant above all (§4.3): an `oracle::Connection` is never held
//! across an `.await`. It enters and leaves the `spawn_blocking` closure by
//! ownership (the pooled connection is moved into the closure and dropped
//! there), so the compiler guarantees the rule.

use std::time::Duration;

use crate::connection::{OracleConnection, RustOracleConnection};
use crate::error::DbError;
use crate::types::{OracleBind, OracleConnectOptions, OracleConnectionInfo, OracleRow};

/// An `r2d2` manager that opens [`RustOracleConnection`]s from one profile.
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

impl r2d2::ManageConnection for OracleConnectionManager {
    type Connection = RustOracleConnection;
    type Error = DbError;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        RustOracleConnection::connect(self.opts.clone())
    }

    fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        conn.ping()
    }

    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
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

/// An async-friendly Oracle connection pool. Every DB round-trip is dispatched
/// to a blocking worker via [`tokio::task::spawn_blocking`]; the pooled
/// connection is owned by the closure and never crosses an `.await`.
#[derive(Clone)]
pub struct OraclePool {
    pool: r2d2::Pool<OracleConnectionManager>,
}

impl OraclePool {
    /// Build a pool, eagerly establishing `min_idle` connections (so a bad
    /// profile fails fast). Requires a reachable database + Instant Client.
    pub fn connect(opts: OracleConnectOptions, settings: PoolSettings) -> Result<Self, DbError> {
        let manager = OracleConnectionManager::new(opts);
        let pool = r2d2::Pool::builder()
            .max_size(settings.max_size.max(1))
            .min_idle(Some(settings.min_idle))
            .connection_timeout(Duration::from_secs(settings.acquire_timeout_secs.max(1)))
            .build(manager)
            .map_err(|e| DbError::Pool(e.to_string()))?;
        Ok(OraclePool { pool })
    }

    /// Current number of idle + in-use connections in the pool.
    #[must_use]
    pub fn state_connections(&self) -> u32 {
        self.pool.state().connections
    }

    /// Run a query on a pooled connection, off the async executor.
    pub async fn query_rows(
        &self,
        sql: impl Into<String>,
        binds: Vec<OracleBind>,
    ) -> Result<Vec<OracleRow>, DbError> {
        let pool = self.pool.clone();
        let sql = sql.into();
        spawn_blocking_db(move || {
            let conn = pool.get().map_err(|e| DbError::Pool(e.to_string()))?;
            conn.query_rows(&sql, &binds)
        })
        .await
    }

    /// Run a DML/DDL statement on a pooled connection, off the async executor.
    pub async fn execute(
        &self,
        sql: impl Into<String>,
        binds: Vec<OracleBind>,
    ) -> Result<u64, DbError> {
        let pool = self.pool.clone();
        let sql = sql.into();
        spawn_blocking_db(move || {
            let conn = pool.get().map_err(|e| DbError::Pool(e.to_string()))?;
            conn.execute(&sql, &binds)
        })
        .await
    }

    /// Describe a pooled connection (version / role / open-mode / schema).
    pub async fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
        let pool = self.pool.clone();
        spawn_blocking_db(move || {
            let conn = pool.get().map_err(|e| DbError::Pool(e.to_string()))?;
            conn.describe()
        })
        .await
    }

    /// Confirm a pooled connection is live.
    pub async fn ping(&self) -> Result<(), DbError> {
        let pool = self.pool.clone();
        spawn_blocking_db(move || {
            let conn = pool.get().map_err(|e| DbError::Pool(e.to_string()))?;
            conn.ping()
        })
        .await
    }
}

/// Run a blocking DB closure on the blocking pool, flattening the join error.
async fn spawn_blocking_db<T, F>(f: F) -> Result<T, DbError>
where
    F: FnOnce() -> Result<T, DbError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| DbError::Internal(format!("blocking task failed: {e}")))?
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
}
