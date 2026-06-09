//! The backend-independent [`OracleConnection`] trait and the
//! `oracle`-crate-backed [`RustOracleConnection`] (plan §4.3).
//!
//! The trait is `Send` so the pool can hand connections across the
//! `spawn_blocking` boundary; an `oracle::Connection` is never held across an
//! `.await` (ownership-enforced — it lives only inside the blocking closure).

use crate::error::DbError;
use crate::types::{
    OracleBackend, OracleBind, OracleConnectOptions, OracleConnectionInfo, OracleRow,
};

/// A synchronous Oracle connection. Implementors run on a `spawn_blocking`
/// worker; never on the async executor (§4.3).
pub trait OracleConnection: Send {
    /// The backend in use.
    fn backend(&self) -> OracleBackend;
    /// Round-trip the server to confirm liveness (`SELECT 1 FROM dual`).
    fn ping(&self) -> Result<(), DbError>;
    /// Best-effort connection metadata (version, role/open-mode, schema).
    fn describe(&self) -> Result<OracleConnectionInfo, DbError>;
    /// Run a query, binding `binds` positionally (`:1`, `:2`, …). Values are
    /// always bound, never interpolated.
    fn query_rows(&self, sql: &str, binds: &[OracleBind]) -> Result<Vec<OracleRow>, DbError>;
    /// Run a DML/DDL statement; returns rows affected (`SQL%ROWCOUNT`).
    fn execute(&self, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError>;

    /// Commit the current transaction on this session.
    fn commit(&self) -> Result<(), DbError>;

    /// Roll back the current transaction on this session.
    fn rollback(&self) -> Result<(), DbError>;

    /// Run a query expecting at most one row.
    fn query_optional_row(
        &self,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Option<OracleRow>, DbError> {
        Ok(self.query_rows(sql, binds)?.into_iter().next())
    }
}

/// The `oracle` crate (ODPI-C / Instant Client) connection wrapper.
pub struct RustOracleConnection {
    #[cfg(feature = "oracle-driver")]
    opts: OracleConnectOptions,
    #[cfg(feature = "oracle-driver")]
    inner: oracle::Connection,
}

impl RustOracleConnection {
    /// Open a connection per `opts`. Returns [`DbError::BackendNotCompiled`]
    /// when the `oracle-driver` feature is off (the offline build).
    pub fn connect(opts: OracleConnectOptions) -> Result<Self, DbError> {
        #[cfg(not(feature = "oracle-driver"))]
        {
            let _ = opts;
            Err(DbError::BackendNotCompiled {
                backend: OracleBackend::RustOracle,
            })
        }
        #[cfg(feature = "oracle-driver")]
        {
            driver::connect(opts)
        }
    }
}

#[cfg(feature = "oracle-driver")]
mod driver {
    use super::RustOracleConnection;
    use crate::error::DbError;
    use crate::types::{
        OracleCell, OracleConnectOptions, OracleConnectionInfo, OracleRow, OracleSessionIdentity,
    };
    use oracle::sql_type::ToSql;

    /// Fold a wallet directory into an EZConnect-Plus descriptor so we never
    /// have to mutate `TNS_ADMIN` (which needs `unsafe std::env::set_var` under
    /// edition 2024 — forbidden workspace-wide). A plain alias is returned
    /// unchanged (the operator sets `TNS_ADMIN` for that case).
    fn effective_connect_string(opts: &OracleConnectOptions) -> String {
        match &opts.wallet_location {
            Some(wallet)
                if opts.connect_string.starts_with("tcps://")
                    && !opts.connect_string.contains("wallet_location") =>
            {
                let sep = if opts.connect_string.contains('?') {
                    '&'
                } else {
                    '?'
                };
                format!(
                    "{}{}wallet_location=\"{}\"",
                    opts.connect_string,
                    sep,
                    wallet.display()
                )
            }
            _ => opts.connect_string.clone(),
        }
    }

    fn connector(
        opts: &OracleConnectOptions,
        user: impl Into<String>,
        pass: impl Into<String>,
        connect_string: impl Into<String>,
    ) -> oracle::Connector {
        let mut connector = oracle::Connector::new(user, pass, connect_string);
        if opts.external_auth || (opts.username.is_none() && opts.password.is_none()) {
            connector.external_auth(true);
        }
        if let Some(driver_name) = opts
            .session_identity
            .as_ref()
            .and_then(|identity| identity.driver_name.as_deref())
        {
            connector.driver_name(driver_name);
        }
        connector
    }

    fn apply_session_identity(
        inner: &oracle::Connection,
        identity: Option<&OracleSessionIdentity>,
    ) -> Result<(), DbError> {
        let Some(identity) = identity.filter(|identity| !identity.is_empty()) else {
            return Ok(());
        };
        if let Some(module) = identity.module.as_deref() {
            inner
                .set_module(module)
                .map_err(|e| DbError::Connect(e.to_string()))?;
        }
        if let Some(action) = identity.action.as_deref() {
            inner
                .set_action(action)
                .map_err(|e| DbError::Connect(e.to_string()))?;
        }
        if let Some(client_identifier) = identity.client_identifier.as_deref() {
            inner
                .set_client_identifier(client_identifier)
                .map_err(|e| DbError::Connect(e.to_string()))?;
        }
        if let Some(client_info) = identity.client_info.as_deref() {
            inner
                .set_client_info(client_info)
                .map_err(|e| DbError::Connect(e.to_string()))?;
        }
        Ok(())
    }

    pub(super) fn connect(opts: OracleConnectOptions) -> Result<RustOracleConnection, DbError> {
        if opts.use_iam_token {
            // OCI IAM database-token auth needs ODPI-C access-token plumbing
            // not exposed by `oracle` 0.6.x; hardened in P1-11 via odpic-sys.
            return Err(DbError::UnsupportedAuth(
                "OCI IAM token auth is implemented in P1-11 (oracle-qmwz.2.11)".to_owned(),
            ));
        }
        let connect_string = effective_connect_string(&opts);
        let inner = if opts.external_auth || (opts.username.is_none() && opts.password.is_none()) {
            // Wallet / external auth: empty credentials, the wallet supplies them.
            connector(&opts, "", "", &connect_string)
                .connect()
                .map_err(|e| DbError::Connect(e.to_string()))?
        } else {
            let user = opts.username.as_deref().unwrap_or("");
            let pass = opts.password.as_deref().unwrap_or("");
            connector(&opts, user, pass, &connect_string)
                .connect()
                .map_err(|e| DbError::Connect(e.to_string()))?
        };
        apply_session_identity(&inner, opts.session_identity.as_ref())?;
        // Pin canonical, NLS-decoupled output (ISO-8601 dates, period decimals)
        // so identical queries return identical values regardless of host NLS
        // (plan §5.2, P0-5b). ALTER SESSION is non-mutating and session-scoped.
        for stmt in crate::serialize::canonical_nls_statements() {
            inner
                .execute(stmt, &[])
                .map_err(|e| DbError::Connect(e.to_string()))?;
        }
        Ok(RustOracleConnection { opts, inner })
    }

    /// Map an [`OracleBind`] to a boxed `ToSql` driver value.
    fn to_param(bind: &crate::types::OracleBind) -> Box<dyn ToSql> {
        use crate::types::OracleBind;
        match bind {
            OracleBind::Null => Box::new(Option::<String>::None),
            OracleBind::String(s) => Box::new(s.clone()),
            OracleBind::I64(v) => Box::new(*v),
            OracleBind::F64(v) => Box::new(*v),
            OracleBind::Bool(b) => Box::new(if *b { 1i32 } else { 0i32 }),
        }
    }

    impl super::OracleConnection for RustOracleConnection {
        fn backend(&self) -> crate::types::OracleBackend {
            crate::types::OracleBackend::RustOracle
        }

        fn ping(&self) -> Result<(), DbError> {
            self.inner.ping().map_err(|e| DbError::Query(e.to_string()))
        }

        fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
            let mut info = OracleConnectionInfo {
                backend: Some(crate::types::OracleBackend::RustOracle),
                ..Default::default()
            };
            // Each probe is best-effort: a least-privilege account may lack
            // V$ access, so a failure leaves the field None rather than erroring.
            if let Ok(rows) = self.query_rows(
                "SELECT version_full FROM product_component_version WHERE rownum = 1",
                &[],
            ) {
                info.server_version = rows
                    .first()
                    .and_then(|r| r.text("VERSION_FULL").map(str::to_owned));
            }
            if let Ok(rows) =
                self.query_rows("SELECT database_role, open_mode FROM v$database", &[])
            {
                if let Some(r) = rows.first() {
                    info.database_role = r.text("DATABASE_ROLE").map(str::to_owned);
                    info.open_mode = r.text("OPEN_MODE").map(str::to_owned);
                }
            }
            if let Ok(rows) = self.query_rows(
                "SELECT SYS_CONTEXT('USERENV','CURRENT_SCHEMA') AS s FROM dual",
                &[],
            ) {
                info.current_schema = rows.first().and_then(|r| r.text("S").map(str::to_owned));
            }
            Ok(info)
        }

        fn query_rows(
            &self,
            sql: &str,
            binds: &[crate::types::OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            let params: Vec<Box<dyn ToSql>> = binds.iter().map(to_param).collect();
            let refs: Vec<&dyn ToSql> = params.iter().map(std::convert::AsRef::as_ref).collect();
            let result_set = self
                .inner
                .query(sql, &refs)
                .map_err(|e| DbError::Query(e.to_string()))?;
            let col_info: Vec<(String, String)> = result_set
                .column_info()
                .iter()
                .map(|ci| (ci.name().to_owned(), ci.oracle_type().to_string()))
                .collect();
            let mut out = Vec::new();
            for row in result_set {
                let row = row.map_err(|e| DbError::Query(e.to_string()))?;
                let mut cells = Vec::with_capacity(col_info.len());
                for (i, (name, oratype)) in col_info.iter().enumerate() {
                    let value: Option<String> =
                        row.get(i).map_err(|e| DbError::Query(e.to_string()))?;
                    cells.push((name.clone(), OracleCell::new(oratype.clone(), value)));
                }
                out.push(OracleRow { columns: cells });
            }
            Ok(out)
        }

        fn execute(&self, sql: &str, binds: &[crate::types::OracleBind]) -> Result<u64, DbError> {
            let params: Vec<Box<dyn ToSql>> = binds.iter().map(to_param).collect();
            let refs: Vec<&dyn ToSql> = params.iter().map(std::convert::AsRef::as_ref).collect();
            let stmt = self
                .inner
                .execute(sql, &refs)
                .map_err(|e| DbError::Execute(e.to_string()))?;
            stmt.row_count()
                .map_err(|e| DbError::Execute(e.to_string()))
        }

        fn commit(&self) -> Result<(), DbError> {
            self.inner
                .commit()
                .map_err(|e| DbError::Execute(e.to_string()))
        }

        fn rollback(&self) -> Result<(), DbError> {
            self.inner
                .rollback()
                .map_err(|e| DbError::Execute(e.to_string()))
        }
    }

    impl RustOracleConnection {
        /// The options this connection was opened with.
        #[must_use]
        pub fn options(&self) -> &OracleConnectOptions {
            &self.opts
        }
    }
}

#[cfg(all(test, not(feature = "oracle-driver")))]
mod tests {
    use super::*;

    #[test]
    fn offline_build_reports_backend_not_compiled() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            ..Default::default()
        };
        let result = RustOracleConnection::connect(opts);
        assert!(matches!(result, Err(DbError::BackendNotCompiled { .. })));
    }
}
