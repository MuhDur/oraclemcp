//! The backend-independent [`OracleConnection`] trait and the thin
//! [`oracledb`]-backed [`RustOracleConnection`] (plan §4.3).
//!
//! W4 keeps this trait synchronous while replacing the thick ODPI-C adapter.
//! W6b threads `&asupersync::Cx` through this surface so cancellation/deadline
//! semantics become part of the DB API contract.

use crate::error::DbError;
use crate::types::{
    OracleBackend, OracleBind, OracleConnectOptions, OracleConnectionInfo, OracleRow,
};
use asupersync::Cx;
use serde::{Deserialize, Serialize};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

fn db_checkpoint(cx: &Cx, phase: &'static str) -> Result<(), DbError> {
    cx.checkpoint_with(phase)
        .map_err(|err| DbError::Cancelled(format!("{phase}: {err}")))
}

fn db_checkpointed<T>(
    cx: &Cx,
    before: &'static str,
    after: &'static str,
    f: impl FnOnce() -> Result<T, DbError>,
) -> Result<T, DbError> {
    db_checkpoint(cx, before)?;
    let value = f()?;
    db_checkpoint(cx, after)?;
    Ok(value)
}

/// Bounded `DBMS_OUTPUT` lines captured from a single Oracle session.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbmsOutput {
    pub lines: Vec<String>,
    pub line_count: usize,
    pub char_count: usize,
    pub truncated: bool,
}

/// A synchronous Oracle connection.
pub trait OracleConnection: Send {
    /// The backend in use.
    fn backend(&self) -> OracleBackend;
    /// Round-trip the server to confirm liveness (`SELECT 1 FROM dual`).
    fn ping(&self) -> Result<(), DbError>;
    /// Cancellation-aware liveness check.
    fn ping_cx(&self, cx: &Cx) -> Result<(), DbError> {
        db_checkpointed(cx, "oracle_db.ping.before", "oracle_db.ping.after", || {
            self.ping()
        })
    }
    /// Best-effort connection metadata (version, role/open-mode, schema).
    fn describe(&self) -> Result<OracleConnectionInfo, DbError>;
    /// Cancellation-aware connection metadata.
    fn describe_cx(&self, cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
        db_checkpointed(
            cx,
            "oracle_db.describe.before",
            "oracle_db.describe.after",
            || self.describe(),
        )
    }
    /// Run a query, binding `binds` positionally (`:1`, `:2`, …). Values are
    /// always bound, never interpolated.
    fn query_rows(&self, sql: &str, binds: &[OracleBind]) -> Result<Vec<OracleRow>, DbError>;
    /// Cancellation-aware positional query.
    fn query_rows_cx(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError> {
        db_checkpointed(
            cx,
            "oracle_db.query_rows.before",
            "oracle_db.query_rows.after",
            || self.query_rows(sql, binds),
        )
    }
    /// Run a query, binding `binds` by name (`:name`). Values are always bound,
    /// never interpolated. Backends that cannot bind by name should fail
    /// explicitly instead of trying to rewrite SQL.
    fn query_rows_named(
        &self,
        sql: &str,
        binds: &[(String, OracleBind)],
    ) -> Result<Vec<OracleRow>, DbError> {
        let _ = (sql, binds);
        Err(DbError::Query(
            "named binds are not supported by this Oracle backend".to_owned(),
        ))
    }
    /// Cancellation-aware named-bind query.
    fn query_rows_named_cx(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[(String, OracleBind)],
    ) -> Result<Vec<OracleRow>, DbError> {
        db_checkpointed(
            cx,
            "oracle_db.query_rows_named.before",
            "oracle_db.query_rows_named.after",
            || self.query_rows_named(sql, binds),
        )
    }
    /// Run a DML/DDL statement; returns rows affected (`SQL%ROWCOUNT`).
    fn execute(&self, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError>;
    /// Cancellation-aware DML/DDL execution.
    ///
    /// If this observes cancellation after Oracle has returned success, callers
    /// must treat the session as dirty and run cleanup rollback/discard logic.
    fn execute_cx(&self, cx: &Cx, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError> {
        db_checkpointed(
            cx,
            "oracle_db.execute.before",
            "oracle_db.execute.after",
            || self.execute(sql, binds),
        )
    }

    /// Current Oracle per-round-trip call timeout, when supported by the backend.
    fn call_timeout(&self) -> Result<Option<Duration>, DbError> {
        Ok(None)
    }

    /// Set the Oracle per-round-trip call timeout. `None` disables it.
    fn set_call_timeout(&self, timeout: Option<Duration>) -> Result<(), DbError> {
        let _ = timeout;
        Ok(())
    }

    /// Enable `DBMS_OUTPUT` for this session. `buffer_bytes` is passed through
    /// to Oracle; callers should keep it bounded.
    fn enable_dbms_output(&self, buffer_bytes: Option<u32>) -> Result<(), DbError> {
        match buffer_bytes {
            Some(bytes) => self
                .execute(
                    "BEGIN DBMS_OUTPUT.ENABLE(:1); END;",
                    &[OracleBind::I64(i64::from(bytes))],
                )
                .map(|_| ()),
            None => self
                .execute("BEGIN DBMS_OUTPUT.ENABLE(NULL); END;", &[])
                .map(|_| ()),
        }
    }
    /// Cancellation-aware `DBMS_OUTPUT.ENABLE`.
    fn enable_dbms_output_cx(&self, cx: &Cx, buffer_bytes: Option<u32>) -> Result<(), DbError> {
        db_checkpointed(
            cx,
            "oracle_db.enable_dbms_output.before",
            "oracle_db.enable_dbms_output.after",
            || self.enable_dbms_output(buffer_bytes),
        )
    }

    /// Drain `DBMS_OUTPUT` from this session, bounded by line and character
    /// limits. Backends without output-bind support must fail explicitly.
    fn read_dbms_output(&self, max_lines: usize, max_chars: usize) -> Result<DbmsOutput, DbError> {
        let _ = (max_lines, max_chars);
        Err(DbError::Execute(
            "DBMS_OUTPUT capture is not supported by this Oracle backend".to_owned(),
        ))
    }
    /// Cancellation-aware `DBMS_OUTPUT` drain.
    fn read_dbms_output_cx(
        &self,
        cx: &Cx,
        max_lines: usize,
        max_chars: usize,
    ) -> Result<DbmsOutput, DbError> {
        db_checkpointed(
            cx,
            "oracle_db.read_dbms_output.before",
            "oracle_db.read_dbms_output.after",
            || self.read_dbms_output(max_lines, max_chars),
        )
    }

    /// Commit the current transaction on this session.
    fn commit(&self) -> Result<(), DbError>;
    /// Cancellation-aware commit. There is intentionally no post-commit
    /// checkpoint: once Oracle commits, cancellation cannot undo it.
    fn commit_cx(&self, cx: &Cx) -> Result<(), DbError> {
        db_checkpoint(cx, "oracle_db.commit.before")?;
        self.commit()
    }

    /// Roll back the current transaction on this session.
    fn rollback(&self) -> Result<(), DbError>;
    /// Cancellation-aware user-requested rollback.
    fn rollback_cx(&self, cx: &Cx) -> Result<(), DbError> {
        db_checkpoint(cx, "oracle_db.rollback.before")?;
        self.rollback()
    }

    /// Run a query expecting at most one row.
    fn query_optional_row(
        &self,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Option<OracleRow>, DbError> {
        Ok(self.query_rows(sql, binds)?.into_iter().next())
    }
    /// Cancellation-aware query expecting at most one row.
    fn query_optional_row_cx(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Option<OracleRow>, DbError> {
        Ok(self.query_rows_cx(cx, sql, binds)?.into_iter().next())
    }
}

/// Thin pure-Rust Oracle connection wrapper.
pub struct RustOracleConnection {
    opts: OracleConnectOptions,
    inner: Mutex<oracledb::Connection>,
    call_timeout: Mutex<Option<Duration>>,
}

impl RustOracleConnection {
    /// Open a thin-mode connection per `opts`.
    pub fn connect(opts: OracleConnectOptions) -> Result<Self, DbError> {
        driver::connect(opts)
    }

    fn lock_inner(&self) -> Result<MutexGuard<'_, oracledb::Connection>, DbError> {
        self.inner
            .lock()
            .map_err(|err| DbError::Internal(format!("thin connection lock poisoned: {err}")))
    }

    fn timeout_ms(&self) -> Result<Option<u32>, DbError> {
        self.call_timeout
            .lock()
            .map(|timeout| timeout.map(duration_to_millis))
            .map_err(|err| DbError::Internal(format!("call-timeout lock poisoned: {err}")))
    }

    /// The options this connection was opened with.
    #[must_use]
    pub fn options(&self) -> &OracleConnectOptions {
        &self.opts
    }

    fn query_first_row(&self, sql: &str) -> Option<OracleRow> {
        self.query_rows(sql, &[])
            .ok()
            .and_then(|rows| rows.into_iter().next())
    }
}

fn duration_to_millis(duration: Duration) -> u32 {
    let millis = duration.as_millis().min(u128::from(u32::MAX));
    u32::try_from(millis).unwrap_or(u32::MAX)
}

mod driver {
    use super::{DbmsOutput, RustOracleConnection};
    use crate::error::DbError;
    use crate::types::{
        OracleBind, OracleCell, OracleConnectOptions, OracleConnectionInfo, OracleRow,
        OracleSessionIdentity,
    };
    use oracledb::protocol::{
        ClientIdentity,
        thin::{
            BindValue, ColumnMetadata, ORA_TYPE_NUM_BFILE, ORA_TYPE_NUM_BINARY_DOUBLE,
            ORA_TYPE_NUM_BINARY_FLOAT, ORA_TYPE_NUM_BINARY_INTEGER, ORA_TYPE_NUM_BLOB,
            ORA_TYPE_NUM_BOOLEAN, ORA_TYPE_NUM_CHAR, ORA_TYPE_NUM_CLOB, ORA_TYPE_NUM_CURSOR,
            ORA_TYPE_NUM_DATE, ORA_TYPE_NUM_INTERVAL_DS, ORA_TYPE_NUM_INTERVAL_YM,
            ORA_TYPE_NUM_JSON, ORA_TYPE_NUM_LONG, ORA_TYPE_NUM_LONG_RAW, ORA_TYPE_NUM_NUMBER,
            ORA_TYPE_NUM_OBJECT, ORA_TYPE_NUM_RAW, ORA_TYPE_NUM_ROWID, ORA_TYPE_NUM_TIMESTAMP,
            ORA_TYPE_NUM_TIMESTAMP_LTZ, ORA_TYPE_NUM_TIMESTAMP_TZ, ORA_TYPE_NUM_UROWID,
            ORA_TYPE_NUM_VARCHAR, ORA_TYPE_NUM_VECTOR, QueryResult, QueryValue,
        },
    };
    use std::fmt::Display;
    use std::sync::Mutex;

    const FETCH_BATCH_ROWS: u32 = 512;

    pub(super) fn connect(opts: OracleConnectOptions) -> Result<RustOracleConnection, DbError> {
        let mut inner = oracledb::BlockingConnection::connect(to_connect_options(&opts)?)
            .map_err(|err| DbError::Connect(sanitize_driver_error(err, &opts)))?;
        apply_session_identity(&mut inner, opts.session_identity.as_ref(), &opts)?;
        for stmt in crate::serialize::canonical_nls_statements() {
            execute_raw(&mut inner, stmt, &[], &opts, "connect")?;
        }
        for stmt in &opts.session_statements {
            execute_raw(&mut inner, stmt, &[], &opts, "session setup")?;
        }
        let call_timeout = opts.call_timeout;
        Ok(RustOracleConnection {
            opts,
            inner: Mutex::new(inner),
            call_timeout: Mutex::new(call_timeout),
        })
    }

    fn to_connect_options(
        opts: &OracleConnectOptions,
    ) -> Result<oracledb::ConnectOptions, DbError> {
        if opts.use_iam_token || opts.iam_token.is_some() {
            return Err(DbError::UnsupportedAuth(
                "OCI IAM database-token auth is not supported by the published thin driver yet"
                    .to_owned(),
            ));
        }
        if opts.external_auth {
            return Err(DbError::UnsupportedAuth(
                "external/wallet auth without username and password is not supported by the published thin driver yet"
                    .to_owned(),
            ));
        }
        let user = opts.username.as_deref().ok_or_else(|| {
            DbError::UnsupportedAuth("thin mode currently requires an explicit username".to_owned())
        })?;
        let password = opts.password.as_deref().ok_or_else(|| {
            DbError::UnsupportedAuth("thin mode currently requires an explicit password".to_owned())
        })?;
        let identity = client_identity(opts.session_identity.as_ref())?;
        let mut connect_options =
            oracledb::ConnectOptions::new(&opts.connect_string, user, password, identity);
        if let Some(wallet) = &opts.wallet_location {
            connect_options = connect_options.with_wallet_location(wallet.display().to_string());
            connect_options = connect_options.with_use_sni(true);
        }
        Ok(connect_options)
    }

    fn client_identity(
        identity: Option<&OracleSessionIdentity>,
    ) -> Result<ClientIdentity, DbError> {
        let module = identity
            .and_then(|value| value.module.as_deref())
            .unwrap_or("oraclemcp");
        let terminal = identity
            .and_then(|value| value.client_identifier.as_deref())
            .unwrap_or("oraclemcp");
        let driver_name = identity
            .and_then(|value| value.driver_name.as_deref())
            .unwrap_or("oraclemcp-thin");
        let machine = std::env::var("HOSTNAME").unwrap_or_else(|_| "oraclemcp".to_owned());
        let osuser = std::env::var("USER").unwrap_or_else(|_| "oraclemcp".to_owned());
        ClientIdentity::new(module, machine, osuser, terminal, driver_name)
            .map_err(|err| DbError::Connect(err.to_string()))
    }

    fn apply_session_identity(
        inner: &mut oracledb::Connection,
        identity: Option<&OracleSessionIdentity>,
        opts: &OracleConnectOptions,
    ) -> Result<(), DbError> {
        let Some(identity) = identity.filter(|identity| !identity.is_empty()) else {
            return Ok(());
        };
        if identity.edition.is_some() {
            return Err(DbError::UnsupportedFeature(
                "edition-based redefinition selection is not supported by the published thin driver yet"
                    .to_owned(),
            ));
        }
        if let Some(module) = identity.module.as_deref() {
            let action = identity.action.as_deref().unwrap_or("");
            execute_raw(
                inner,
                "BEGIN DBMS_APPLICATION_INFO.SET_MODULE(:1, :2); END;",
                &[
                    BindValue::Text(module.to_owned()),
                    BindValue::Text(action.to_owned()),
                ],
                opts,
                "session identity",
            )?;
        } else if let Some(action) = identity.action.as_deref() {
            execute_raw(
                inner,
                "BEGIN DBMS_APPLICATION_INFO.SET_ACTION(:1); END;",
                &[BindValue::Text(action.to_owned())],
                opts,
                "session identity",
            )?;
        }
        if let Some(client_identifier) = identity.client_identifier.as_deref() {
            execute_raw(
                inner,
                "BEGIN DBMS_SESSION.SET_IDENTIFIER(:1); END;",
                &[BindValue::Text(client_identifier.to_owned())],
                opts,
                "session identity",
            )?;
        }
        if let Some(client_info) = identity.client_info.as_deref() {
            execute_raw(
                inner,
                "BEGIN DBMS_APPLICATION_INFO.SET_CLIENT_INFO(:1); END;",
                &[BindValue::Text(client_info.to_owned())],
                opts,
                "session identity",
            )?;
        }
        Ok(())
    }

    fn to_bind(bind: &OracleBind) -> BindValue {
        match bind {
            OracleBind::Null => BindValue::Null,
            OracleBind::String(value) => BindValue::Text(value.clone()),
            OracleBind::I64(value) => BindValue::Number(value.to_string()),
            OracleBind::F64(value) => BindValue::BinaryDouble(*value),
            OracleBind::Bool(value) => BindValue::Number(if *value { "1" } else { "0" }.to_owned()),
        }
    }

    fn execute_raw(
        inner: &mut oracledb::Connection,
        sql: &str,
        binds: &[BindValue],
        opts: &OracleConnectOptions,
        context: &'static str,
    ) -> Result<QueryResult, DbError> {
        oracledb::BlockingConnection::execute_query_with_binds(inner, sql, 0, binds).map_err(
            |err| DbError::Execute(format!("{context}: {}", sanitize_driver_error(err, opts))),
        )
    }

    fn execute_with_timeout(
        inner: &mut oracledb::Connection,
        sql: &str,
        prefetch_rows: u32,
        binds: &[BindValue],
        timeout_ms: Option<u32>,
        opts: &OracleConnectOptions,
        context: &'static str,
    ) -> Result<QueryResult, DbError> {
        oracledb::BlockingConnection::execute_query_with_binds_and_timeout(
            inner,
            sql,
            prefetch_rows,
            binds,
            timeout_ms,
        )
        .map_err(|err| DbError::Query(format!("{context}: {}", sanitize_driver_error(err, opts))))
    }

    fn collect_all_rows(
        inner: &mut oracledb::Connection,
        mut result: QueryResult,
        opts: &OracleConnectOptions,
    ) -> Result<Vec<OracleRow>, DbError> {
        let cursor_id = result.cursor_id;
        let mut columns = result.columns.clone();
        let mut rows = std::mem::take(&mut result.rows);
        let mut previous_row = rows.last().cloned();
        while result.more_rows && cursor_id != 0 {
            let fetched = oracledb::BlockingConnection::fetch_rows_with_columns(
                inner,
                cursor_id,
                FETCH_BATCH_ROWS,
                &columns,
                previous_row.as_deref(),
            )
            .map_err(|err| DbError::Query(sanitize_driver_error(err, opts)))?;
            if !fetched.columns.is_empty() {
                columns = fetched.columns.clone();
            }
            previous_row = fetched.rows.last().cloned();
            rows.extend(fetched.rows);
            result.more_rows = fetched.more_rows;
        }
        if cursor_id != 0 {
            inner.release_cursor(cursor_id);
        }
        rows_to_oracle_rows(&columns, rows)
    }

    fn rows_to_oracle_rows(
        columns: &[ColumnMetadata],
        rows: Vec<Vec<Option<QueryValue>>>,
    ) -> Result<Vec<OracleRow>, DbError> {
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let mut cells = Vec::with_capacity(columns.len());
            for (idx, meta) in columns.iter().enumerate() {
                let value = row.get(idx).cloned().flatten();
                cells.push((meta.name.clone(), value_to_cell(meta, value)));
            }
            out.push(OracleRow { columns: cells });
        }
        Ok(out)
    }

    fn value_to_cell(meta: &ColumnMetadata, value: Option<QueryValue>) -> OracleCell {
        let oracle_type = oracle_type_name(meta);
        match value {
            None => OracleCell::new(oracle_type, None),
            Some(
                QueryValue::Text(value)
                | QueryValue::Rowid(value)
                | QueryValue::BinaryDouble(value),
            ) => OracleCell::new(oracle_type, Some(value)),
            Some(QueryValue::TextRaw { bytes, .. } | QueryValue::Raw(bytes)) => {
                OracleCell::binary(oracle_type, bytes)
            }
            Some(QueryValue::Number(value)) => {
                OracleCell::new(oracle_type, Some(value.to_canonical_string()))
            }
            Some(QueryValue::Boolean(value)) => OracleCell::new(
                oracle_type,
                Some(if value { "true" } else { "false" }.to_owned()),
            ),
            Some(QueryValue::DateTime {
                year,
                month,
                day,
                hour,
                minute,
                second,
                nanosecond,
            }) => OracleCell::new(
                oracle_type,
                Some(format_datetime(
                    year, month, day, hour, minute, second, nanosecond,
                )),
            ),
            Some(QueryValue::IntervalDS {
                days,
                hours,
                minutes,
                seconds,
                fseconds,
            }) => OracleCell::new(
                oracle_type,
                Some(format!(
                    "{days} {hours:02}:{minutes:02}:{seconds:02}.{fseconds:09}"
                )),
            ),
            Some(QueryValue::IntervalYM { years, months }) => {
                OracleCell::new(oracle_type, Some(format!("{years}-{months}")))
            }
            Some(QueryValue::Cursor(cursor)) => OracleCell::new(
                oracle_type,
                Some(format!(
                    "<unsupported REF CURSOR {} columns cursor_id={}>",
                    cursor.columns.len(),
                    cursor.cursor_id
                )),
            ),
            Some(QueryValue::Object(value)) => OracleCell::binary(oracle_type, value.packed_data),
            Some(QueryValue::Lob(value)) => OracleCell::new(
                oracle_type,
                Some(format!("<unsupported LOB locator size={}>", value.size)),
            ),
            Some(QueryValue::Vector(value)) => {
                OracleCell::new(oracle_type, Some(format!("{value:?}")))
            }
            Some(QueryValue::Json(value)) => {
                OracleCell::new(oracle_type, Some(format!("{value:?}")))
            }
            Some(QueryValue::Array(values)) => OracleCell::new(
                oracle_type,
                Some(format!("<unsupported ARRAY len={}>", values.len())),
            ),
        }
    }

    fn format_datetime(
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        nanosecond: u32,
    ) -> String {
        if nanosecond == 0 {
            format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
        } else {
            format!(
                "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{nanosecond:09}"
            )
        }
    }

    fn oracle_type_name(meta: &ColumnMetadata) -> String {
        let base = match meta.ora_type_num {
            ORA_TYPE_NUM_VARCHAR => "VARCHAR2",
            ORA_TYPE_NUM_NUMBER => "NUMBER",
            ORA_TYPE_NUM_BINARY_INTEGER => "BINARY_INTEGER",
            ORA_TYPE_NUM_LONG => "LONG",
            ORA_TYPE_NUM_ROWID => "ROWID",
            ORA_TYPE_NUM_DATE => "DATE",
            ORA_TYPE_NUM_RAW => "RAW",
            ORA_TYPE_NUM_BINARY_FLOAT => "BINARY_FLOAT",
            ORA_TYPE_NUM_BINARY_DOUBLE => "BINARY_DOUBLE",
            ORA_TYPE_NUM_BOOLEAN => "BOOLEAN",
            ORA_TYPE_NUM_CURSOR => "CURSOR",
            ORA_TYPE_NUM_LONG_RAW => "LONG RAW",
            ORA_TYPE_NUM_CHAR => "CHAR",
            ORA_TYPE_NUM_CLOB => "CLOB",
            ORA_TYPE_NUM_BLOB => "BLOB",
            ORA_TYPE_NUM_BFILE => "BFILE",
            ORA_TYPE_NUM_OBJECT => "OBJECT",
            ORA_TYPE_NUM_JSON => "JSON",
            ORA_TYPE_NUM_TIMESTAMP => "TIMESTAMP",
            ORA_TYPE_NUM_TIMESTAMP_TZ => "TIMESTAMP WITH TIME ZONE",
            ORA_TYPE_NUM_INTERVAL_DS => "INTERVAL DAY TO SECOND",
            ORA_TYPE_NUM_INTERVAL_YM => "INTERVAL YEAR TO MONTH",
            ORA_TYPE_NUM_UROWID => "UROWID",
            ORA_TYPE_NUM_TIMESTAMP_LTZ => "TIMESTAMP WITH LOCAL TIME ZONE",
            ORA_TYPE_NUM_VECTOR => "VECTOR",
            other => return format!("ORA_TYPE_{other}"),
        };
        if meta.is_json && base != "JSON" {
            "JSON".to_owned()
        } else {
            base.to_owned()
        }
    }

    pub(super) fn sanitize_driver_error(err: impl Display, opts: &OracleConnectOptions) -> String {
        let mut message = err.to_string();
        let mut secrets = vec![opts.connect_string.clone()];
        if let Some(username) = &opts.username {
            secrets.push(username.clone());
        }
        if let Some(password) = &opts.password {
            secrets.push(password.clone());
        }
        if let Some(token) = &opts.iam_token {
            secrets.push(token.clone());
        }
        if let Some(wallet) = &opts.wallet_location {
            secrets.push(wallet.display().to_string());
        }
        for secret in secrets.iter().filter(|value| !value.is_empty()) {
            message = message.replace(secret, "<redacted>");
        }
        message
    }

    impl super::OracleConnection for RustOracleConnection {
        fn backend(&self) -> crate::types::OracleBackend {
            crate::types::OracleBackend::RustOracle
        }

        fn ping(&self) -> Result<(), DbError> {
            let timeout = self.timeout_ms()?;
            let mut inner = self.lock_inner()?;
            match timeout {
                Some(timeout) => {
                    oracledb::BlockingConnection::ping_with_timeout(&mut inner, timeout)
                }
                None => oracledb::BlockingConnection::ping(&mut inner),
            }
            .map_err(|err| DbError::Query(sanitize_driver_error(err, &self.opts)))
        }

        fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
            let mut info = OracleConnectionInfo {
                backend: Some(crate::types::OracleBackend::RustOracle),
                ..Default::default()
            };
            if let Some(r) = self.query_first_row(
                "SELECT version_full FROM product_component_version WHERE rownum = 1",
            ) {
                info.server_version = r.text("VERSION_FULL").map(str::to_owned);
            }
            if let Some(r) = self.query_first_row("SELECT database_role, open_mode FROM v$database")
            {
                info.database_role = r.text("DATABASE_ROLE").map(str::to_owned);
                info.open_mode = r.text("OPEN_MODE").map(str::to_owned);
            }
            if let Some(r) = self.query_first_row(
                "SELECT \
                    SYS_CONTEXT('USERENV','CURRENT_SCHEMA') AS current_schema, \
                    SYS_CONTEXT('USERENV','CURRENT_EDITION_NAME') AS current_edition, \
                    SYS_CONTEXT('USERENV','SESSION_USER') AS session_user, \
                    SYS_CONTEXT('USERENV','CURRENT_USER') AS current_user, \
                    SYS_CONTEXT('USERENV','MODULE') AS module, \
                    SYS_CONTEXT('USERENV','ACTION') AS session_action, \
                    SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER') AS client_identifier, \
                    SYS_CONTEXT('USERENV','CLIENT_INFO') AS client_info, \
                    SYS_CONTEXT('USERENV','OS_USER') AS os_user, \
                    SYS_CONTEXT('USERENV','HOST') AS host, \
                    SYS_CONTEXT('USERENV','TERMINAL') AS terminal \
                 FROM dual",
            ) {
                info.current_schema = r.text("CURRENT_SCHEMA").map(str::to_owned);
                info.current_edition = r.text("CURRENT_EDITION").map(str::to_owned);
                info.session_user = r.text("SESSION_USER").map(str::to_owned);
                info.current_user = r.text("CURRENT_USER").map(str::to_owned);
                info.module = r.text("MODULE").map(str::to_owned);
                info.action = r.text("SESSION_ACTION").map(str::to_owned);
                info.client_identifier = r.text("CLIENT_IDENTIFIER").map(str::to_owned);
                info.client_info = r.text("CLIENT_INFO").map(str::to_owned);
                info.os_user = r.text("OS_USER").map(str::to_owned);
                info.host = r.text("HOST").map(str::to_owned);
                info.terminal = r.text("TERMINAL").map(str::to_owned);
            }
            if let Some(r) = self.query_first_row(
                "SELECT osuser, machine, terminal, program \
                 FROM v$session \
                 WHERE sid = TO_NUMBER(SYS_CONTEXT('USERENV','SID')) \
                 FETCH FIRST 1 ROWS ONLY",
            ) {
                info.os_user = r
                    .text("OSUSER")
                    .map(str::to_owned)
                    .or_else(|| info.os_user.take());
                info.machine = r.text("MACHINE").map(str::to_owned);
                info.terminal = r
                    .text("TERMINAL")
                    .map(str::to_owned)
                    .or_else(|| info.terminal.take());
                info.program = r.text("PROGRAM").map(str::to_owned);
            }
            if let Some(r) = self.query_first_row(
                "SELECT client_driver \
                 FROM v$session_connect_info \
                 WHERE sid = TO_NUMBER(SYS_CONTEXT('USERENV','SID')) \
                   AND client_driver IS NOT NULL \
                 FETCH FIRST 1 ROWS ONLY",
            ) {
                info.client_driver = r.text("CLIENT_DRIVER").map(str::to_owned);
            }
            Ok(info.with_read_only_status())
        }

        fn query_rows(&self, sql: &str, binds: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
            let binds: Vec<BindValue> = binds.iter().map(to_bind).collect();
            let timeout = self.timeout_ms()?;
            let mut inner = self.lock_inner()?;
            let result = execute_with_timeout(
                &mut inner,
                sql,
                FETCH_BATCH_ROWS,
                &binds,
                timeout,
                &self.opts,
                "query",
            )?;
            collect_all_rows(&mut inner, result, &self.opts)
        }

        fn query_rows_named(
            &self,
            sql: &str,
            binds: &[(String, OracleBind)],
        ) -> Result<Vec<OracleRow>, DbError> {
            let binds: Vec<(String, BindValue)> = binds
                .iter()
                .map(|(name, bind)| (name.clone(), to_bind(bind)))
                .collect();
            let mut inner = self.lock_inner()?;
            let result = oracledb::BlockingConnection::query_named(&mut inner, sql, binds)
                .map_err(|err| DbError::Query(sanitize_driver_error(err, &self.opts)))?;
            collect_all_rows(&mut inner, result, &self.opts)
        }

        fn execute(&self, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError> {
            let binds: Vec<BindValue> = binds.iter().map(to_bind).collect();
            let timeout = self.timeout_ms()?;
            let mut inner = self.lock_inner()?;
            let result =
                execute_with_timeout(&mut inner, sql, 0, &binds, timeout, &self.opts, "execute")
                    .map_err(|err| match err {
                        DbError::Query(msg) => DbError::Execute(msg),
                        other => other,
                    })?;
            Ok(result.row_count)
        }

        fn call_timeout(&self) -> Result<Option<std::time::Duration>, DbError> {
            self.call_timeout
                .lock()
                .map(|timeout| *timeout)
                .map_err(|err| DbError::Internal(format!("call-timeout lock poisoned: {err}")))
        }

        fn set_call_timeout(&self, timeout: Option<std::time::Duration>) -> Result<(), DbError> {
            let mut guard = self
                .call_timeout
                .lock()
                .map_err(|err| DbError::Internal(format!("call-timeout lock poisoned: {err}")))?;
            *guard = timeout;
            Ok(())
        }

        fn read_dbms_output(
            &self,
            max_lines: usize,
            max_chars: usize,
        ) -> Result<DbmsOutput, DbError> {
            let _ = (max_lines, max_chars);
            Err(DbError::UnsupportedFeature(
                "DBMS_OUTPUT capture needs PL/SQL OUT binds; the published thin driver does not expose that API yet"
                    .to_owned(),
            ))
        }

        fn commit(&self) -> Result<(), DbError> {
            let mut inner = self.lock_inner()?;
            oracledb::BlockingConnection::commit(&mut inner)
                .map_err(|err| DbError::Execute(sanitize_driver_error(err, &self.opts)))
        }

        fn rollback(&self) -> Result<(), DbError> {
            let mut inner = self.lock_inner()?;
            oracledb::BlockingConnection::rollback(&mut inner)
                .map_err(|err| DbError::Execute(sanitize_driver_error(err, &self.opts)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thin_mode_rejects_external_auth_before_connecting() {
        let opts = crate::types::OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            external_auth: true,
            ..Default::default()
        };
        let result = RustOracleConnection::connect(opts);
        assert!(matches!(result, Err(DbError::UnsupportedAuth(_))));
    }

    #[test]
    fn duration_to_millis_saturates() {
        assert_eq!(duration_to_millis(Duration::from_millis(42)), 42);
        assert_eq!(duration_to_millis(Duration::from_secs(u64::MAX)), u32::MAX);
    }

    #[test]
    fn driver_error_redaction_removes_connect_material() {
        let opts = OracleConnectOptions {
            connect_string: "dbhost:1521/private_service".to_owned(),
            username: Some("app_user".to_owned()),
            password: Some("super_secret".to_owned()),
            wallet_location: Some("/wallets/private".into()),
            iam_token: Some("iam.jwt.token".to_owned()),
            ..Default::default()
        };
        let redacted = driver::sanitize_driver_error(
            "connect app_user/super_secret@dbhost:1521/private_service with /wallets/private and iam.jwt.token failed",
            &opts,
        );
        for forbidden in [
            "app_user",
            "super_secret",
            "dbhost:1521/private_service",
            "/wallets/private",
            "iam.jwt.token",
        ] {
            assert!(!redacted.contains(forbidden), "{redacted}");
        }
        assert!(redacted.contains("<redacted>"));
    }
}
