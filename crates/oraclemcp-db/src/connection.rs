//! The backend-independent [`OracleConnection`] trait and the thin
//! [`oracledb`]-backed [`RustOracleConnection`].
//!
//! The trait is synchronous because the current Oracle driver surface is
//! blocking. Cancellation and deadline boundaries are explicit
//! `&asupersync::Cx` checkpoints around DB calls.
//!
//! # Driver-adapter seam (B2; plan §8 release gate)
//!
//! This file is **the adapter** — the single, enforced isolation boundary for
//! the `oracledb` driver. Every real `oracledb::` call (connect, the
//! `execute_query*` family, fetch, LOB, REF CURSOR, auth, commit/rollback,
//! ping, error sanitization) lives here and nowhere else. The rest of the
//! workspace talks to Oracle exclusively through the [`OracleConnection`] trait
//! and the `oraclemcp-db` public surface; no other crate or module names an
//! `oracledb::` path. References to `oracledb` elsewhere are intentionally only
//! doc-links and human-readable driver descriptions (no driver calls).
//!
//! Isolating the driver here means the `oracledb` 0.3.0 cut-over (four
//! operation-specific request types, single absolute op-deadline, accessor-based
//! result/metadata types with selective `#[non_exhaustive]`, module/re-export
//! path moves) touches exactly this one file. Drive that migration from
//! `oracledb`'s `MIGRATING-0.3.md`; never lean on the 0.3.0 deprecated shims.
//! Against today's pinned 0.2.2 surface, error classification is string-based
//! (`oraclemcp_error::parse_ora_code`) and the driver `Error` type is consumed
//! generically via [`Display`](std::fmt::Display) in `sanitize_driver_error`, so
//! no exhaustive match on `oracledb::{BindValue,QueryValue,Error}` exists to
//! break.
//!
//! The seam is mechanically enforced two ways, both of which must keep passing:
//! - `scripts/oraclemcp_driver_seam_lint.sh` (wired into `.github/workflows/ci.yml`)
//!   fails if an `oracledb::` driver path appears outside this file.
//! - the `driver_seam` test module below greps the crate sources for the same
//!   invariant, so `cargo test` catches a leak even without the shell script.
//!
//! Both enforcers share one allowlist: this file is the only adapter site. If a
//! new legitimate `oracledb::` site is ever needed, it must be added to both the
//! shell lint's `ADAPTER_ALLOWLIST` and the test's `ADAPTER_ALLOWLIST`, with an
//! inline justification.

use crate::error::DbError;
use crate::serialize::SerializeOptions;
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
    /// Run a query with serialization caps available to the backend. Backends
    /// that materialize driver-side locators should use these caps; backends
    /// without locator values can fall back to [`OracleConnection::query_rows`].
    fn query_rows_with_serialize_options(
        &self,
        sql: &str,
        binds: &[OracleBind],
        serialize_opts: &SerializeOptions,
    ) -> Result<Vec<OracleRow>, DbError> {
        let _ = serialize_opts;
        self.query_rows(sql, binds)
    }
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
    /// Cancellation-aware positional query with serialization caps.
    fn query_rows_with_serialize_options_cx(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
        serialize_opts: &SerializeOptions,
    ) -> Result<Vec<OracleRow>, DbError> {
        db_checkpointed(
            cx,
            "oracle_db.query_rows.before",
            "oracle_db.query_rows.after",
            || self.query_rows_with_serialize_options(sql, binds, serialize_opts),
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
    /// Run a named-bind query with serialization caps available to the backend.
    fn query_rows_named_with_serialize_options(
        &self,
        sql: &str,
        binds: &[(String, OracleBind)],
        serialize_opts: &SerializeOptions,
    ) -> Result<Vec<OracleRow>, DbError> {
        let _ = serialize_opts;
        self.query_rows_named(sql, binds)
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
    /// Cancellation-aware named-bind query with serialization caps.
    fn query_rows_named_with_serialize_options_cx(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[(String, OracleBind)],
        serialize_opts: &SerializeOptions,
    ) -> Result<Vec<OracleRow>, DbError> {
        db_checkpointed(
            cx,
            "oracle_db.query_rows_named.before",
            "oracle_db.query_rows_named.after",
            || self.query_rows_named_with_serialize_options(sql, binds, serialize_opts),
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
    use crate::auth_adapter::AuthAdapter;
    use crate::error::DbError;
    use crate::serialize::SerializeOptions;
    use crate::types::{
        OracleBind, OracleCell, OracleConnectOptions, OracleConnectionInfo, OracleNestedResult,
        OracleRow, OracleSessionIdentity,
    };
    use oracledb::protocol::thin::{CursorValue, LobValue};
    use oracledb::protocol::{
        ClientIdentity,
        thin::{
            BindValue, CS_FORM_IMPLICIT, ColumnMetadata, ORA_TYPE_NUM_BFILE,
            ORA_TYPE_NUM_BINARY_DOUBLE, ORA_TYPE_NUM_BINARY_FLOAT, ORA_TYPE_NUM_BINARY_INTEGER,
            ORA_TYPE_NUM_BLOB, ORA_TYPE_NUM_BOOLEAN, ORA_TYPE_NUM_CHAR, ORA_TYPE_NUM_CLOB,
            ORA_TYPE_NUM_CURSOR, ORA_TYPE_NUM_DATE, ORA_TYPE_NUM_INTERVAL_DS,
            ORA_TYPE_NUM_INTERVAL_YM, ORA_TYPE_NUM_JSON, ORA_TYPE_NUM_LONG, ORA_TYPE_NUM_LONG_RAW,
            ORA_TYPE_NUM_NUMBER, ORA_TYPE_NUM_OBJECT, ORA_TYPE_NUM_RAW, ORA_TYPE_NUM_ROWID,
            ORA_TYPE_NUM_TIMESTAMP, ORA_TYPE_NUM_TIMESTAMP_LTZ, ORA_TYPE_NUM_TIMESTAMP_TZ,
            ORA_TYPE_NUM_UROWID, ORA_TYPE_NUM_VARCHAR, ORA_TYPE_NUM_VECTOR, QueryResult,
            QueryValue, decode_lob_text,
        },
    };
    use std::fmt::Display;
    use std::sync::Mutex;

    const FETCH_BATCH_ROWS: u32 = 512;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct LobReadLimits {
        max_lob_chars: usize,
        max_blob_bytes: usize,
    }

    impl From<&SerializeOptions> for LobReadLimits {
        fn from(opts: &SerializeOptions) -> Self {
            Self {
                max_lob_chars: opts.max_lob_chars,
                max_blob_bytes: opts.max_blob_bytes,
            }
        }
    }

    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct LobReadData {
        data: Option<Vec<u8>>,
    }

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

    /// Whether this profile's transport is TLS/TCPS, as far as we can tell
    /// *before* opening the socket. An OCI IAM database token must only ever
    /// travel over TCPS (it would otherwise be exposed in clear text), so we
    /// fail closed here rather than relying solely on the driver's own
    /// [`oracledb::Error::AccessTokenRequiresTcps`] check at connect time. A
    /// connect string is treated as TLS when it uses the `tcps://` scheme, a
    /// `PROTOCOL=TCPS` descriptor, or a wallet / explicit server-cert DN is
    /// configured (all of which imply mTLS/TLS for the Oracle Net transport).
    fn transport_is_tcps(opts: &OracleConnectOptions) -> bool {
        let compact: String = opts
            .connect_string
            .chars()
            .filter(|c| !c.is_whitespace())
            .map(|c| c.to_ascii_lowercase())
            .collect();
        compact.starts_with("tcps://")
            || compact.contains("protocol=tcps")
            || opts.wallet_location.is_some()
            || opts.ssl_server_cert_dn.is_some()
    }

    pub(super) fn to_connect_options(
        opts: &OracleConnectOptions,
    ) -> Result<oracledb::ConnectOptions, DbError> {
        opts.auth_adapter
            .validate()
            .map_err(|err| DbError::UnsupportedAuth(err.to_string()))?;
        // Enterprise auth modes the published thin driver cannot satisfy. These
        // are DRIVER-UNSUPPORTED, distinct from a bad credential, a TLS/wallet
        // failure, or a listener error — the doctor classifies them apart.
        match &opts.auth_adapter {
            AuthAdapter::Kerberos { .. } => {
                return Err(DbError::UnsupportedAuth(
                    "Kerberos authentication is not supported by the published thin driver yet"
                        .to_owned(),
                ));
            }
            AuthAdapter::Radius => {
                return Err(DbError::UnsupportedAuth(
                    "RADIUS/native MFA authentication is not supported by the published thin driver yet"
                        .to_owned(),
                ));
            }
            AuthAdapter::External => {
                return Err(DbError::UnsupportedAuth(
                    "external/wallet auth without username and password is not supported by the published thin driver yet"
                        .to_owned(),
                ));
            }
            AuthAdapter::Password | AuthAdapter::Proxy { .. } => {}
        }
        if opts.external_auth {
            return Err(DbError::UnsupportedAuth(
                "external/wallet auth without username and password is not supported by the published thin driver yet"
                    .to_owned(),
            ));
        }
        // OCI IAM database-token auth. The pinned driver DOES support it via
        // `ConnectOptions::with_access_token` (the token is sent as `AUTH_TOKEN`
        // with no password verifier). It is only wireable once a token has been
        // fetched from OCI IAM; `use_iam_token` without a token means the
        // token-source seam (oraclemcp_db::IamTokenSource / ensure_fresh_token)
        // has not run yet — a setup error, not a driver-unsupported one.
        let iam_token = match (opts.use_iam_token, opts.iam_token.as_deref()) {
            (_, Some(token)) => Some(token),
            (true, None) => {
                return Err(DbError::UnsupportedAuth(
                    "OCI IAM database-token auth is configured (use_iam_token) but no token was \
                     fetched; obtain one via the IAM token source before connecting"
                        .to_owned(),
                ));
            }
            (false, None) => None,
        };
        // A database access token must never travel in clear text. Fail closed
        // on a non-TCPS transport BEFORE we hand the token to the driver (the
        // driver also rejects this, but defense-in-depth keeps the token off a
        // plaintext socket and gives a precise typed error).
        if iam_token.is_some() && !transport_is_tcps(opts) {
            return Err(DbError::UnsupportedAuth(
                "OCI IAM database-token auth requires a TLS (TCPS) transport; use a tcps:// \
                 connect string or a wallet-backed TLS descriptor"
                    .to_owned(),
            ));
        }
        let user = opts.username.as_deref().ok_or_else(|| {
            DbError::UnsupportedAuth("thin mode currently requires an explicit username".to_owned())
        })?;
        // Token auth carries the credential in the token itself, so no password
        // is required (or used) when an IAM token is present.
        let password = match iam_token {
            Some(_) => "",
            None => opts.password.as_deref().ok_or_else(|| {
                DbError::UnsupportedAuth(
                    "thin mode currently requires an explicit password".to_owned(),
                )
            })?,
        };
        let identity = client_identity(opts.session_identity.as_ref())?;
        let mut connect_options =
            oracledb::ConnectOptions::new(&opts.connect_string, user, password, identity);
        if let Some(token) = iam_token {
            connect_options = connect_options.with_access_token(token.to_owned());
        }
        // session_identity.edition must be sent during authentication so no user
        // SQL runs under the default edition before the requested edition applies.
        if let Some(edition) = opts
            .session_identity
            .as_ref()
            .and_then(|identity| identity.edition.as_deref())
        {
            connect_options = connect_options.with_edition(edition.to_owned());
        }
        if !opts.app_context.is_empty() {
            connect_options = connect_options.with_app_context(opts.app_context.clone());
        }
        if let Some(sdu) = opts.sdu {
            connect_options = connect_options.with_sdu(sdu);
        }
        if let Some(statement_cache_size) = opts.statement_cache_size {
            connect_options =
                connect_options.with_statement_cache_size(statement_cache_size as usize);
        }
        if let Some(proxy_user) = opts.auth_adapter.proxy_connect_user() {
            connect_options = connect_options.with_proxy_user(Some(proxy_user));
        }
        if let Some(wallet) = &opts.wallet_location {
            connect_options = connect_options.with_wallet_location(wallet.display().to_string());
        }
        if let Some(wallet_password) = &opts.wallet_password {
            connect_options = connect_options.with_wallet_password(wallet_password.clone());
        }
        if let Some(enabled) = opts.ssl_server_dn_match {
            connect_options = connect_options.with_ssl_server_dn_match(enabled);
        }
        if let Some(dn) = &opts.ssl_server_cert_dn {
            connect_options = connect_options.with_ssl_server_cert_dn(dn.clone());
        }
        if let Some(use_sni) = opts.use_sni {
            connect_options = connect_options.with_use_sni(use_sni);
        } else if opts.wallet_location.is_some() {
            connect_options = connect_options.with_use_sni(true);
        }
        Ok(connect_options)
    }

    fn client_identity(
        identity: Option<&OracleSessionIdentity>,
    ) -> Result<ClientIdentity, DbError> {
        let program = identity
            .and_then(|value| value.program.as_deref())
            .or_else(|| identity.and_then(|value| value.module.as_deref()))
            .unwrap_or("oraclemcp");
        let terminal = identity
            .and_then(|value| value.terminal.as_deref())
            .or_else(|| identity.and_then(|value| value.client_identifier.as_deref()))
            .unwrap_or("oraclemcp");
        let driver_name = identity
            .and_then(|value| value.driver_name.as_deref())
            .unwrap_or("oraclemcp-thin");
        let machine = identity
            .and_then(|value| value.machine.clone())
            .unwrap_or_else(|| {
                std::env::var("HOSTNAME").unwrap_or_else(|_| "oraclemcp".to_owned())
            });
        let osuser = identity
            .and_then(|value| value.os_user.clone())
            .unwrap_or_else(|| std::env::var("USER").unwrap_or_else(|_| "oraclemcp".to_owned()));
        ClientIdentity::new(program, machine, osuser, terminal, driver_name)
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

    pub(super) fn prefetch_rows_for_statement(sql: &str) -> u32 {
        if sql
            .trim_start()
            .split(|ch: char| !ch.is_ascii_alphabetic())
            .next()
            .is_some_and(|keyword| keyword.eq_ignore_ascii_case("select"))
        {
            FETCH_BATCH_ROWS
        } else {
            0
        }
    }

    fn output_value(result: &QueryResult, bind_index: usize) -> Option<&QueryValue> {
        result
            .out_values
            .iter()
            .find_map(|(index, value)| (*index == bind_index).then_some(value.as_ref()).flatten())
    }

    fn order_named_binds_for_driver(sql: &str, named: Vec<(String, BindValue)>) -> Vec<BindValue> {
        let order = placeholder_order(sql);
        let mut remaining = named;
        let mut out = Vec::with_capacity(remaining.len());
        for placeholder in &order {
            if let Some(pos) = remaining
                .iter()
                .position(|(name, _)| name_matches(name, placeholder))
            {
                let (_, value) = remaining.remove(pos);
                out.push(value);
            }
        }
        for (_, value) in remaining {
            out.push(value);
        }
        out
    }

    fn name_matches(supplied: &str, scanned: &str) -> bool {
        supplied
            .trim_start_matches(':')
            .eq_ignore_ascii_case(scanned.trim_start_matches(':'))
    }

    fn placeholder_order(sql: &str) -> Vec<String> {
        let bytes = sql.as_bytes();
        let mut seen: Vec<String> = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'\'' => {
                    i += 1;
                    while i < bytes.len() {
                        if bytes[i] == b'\'' {
                            if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                                i += 2;
                                continue;
                            }
                            i += 1;
                            break;
                        }
                        i += 1;
                    }
                }
                b'"' => {
                    i += 1;
                    while i < bytes.len() && bytes[i] != b'"' {
                        i += 1;
                    }
                    i = i.saturating_add(1);
                }
                b'-' if i + 1 < bytes.len() && bytes[i + 1] == b'-' => {
                    while i < bytes.len() && bytes[i] != b'\n' {
                        i += 1;
                    }
                }
                b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                    i += 2;
                    while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                        i += 1;
                    }
                    i = i.saturating_add(2).min(bytes.len());
                }
                b':' => {
                    let start = i + 1;
                    let mut j = start;
                    while j < bytes.len()
                        && (bytes[j].is_ascii_alphanumeric()
                            || bytes[j] == b'_'
                            || bytes[j] == b'$')
                    {
                        j += 1;
                    }
                    if j > start {
                        let name = sql[start..j].to_owned();
                        if !seen.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
                            seen.push(name);
                        }
                    }
                    i = j;
                }
                _ => i += 1,
            }
        }
        seen
    }

    fn collect_all_rows(
        inner: &mut oracledb::Connection,
        mut result: QueryResult,
        opts: &OracleConnectOptions,
        serialize_opts: &SerializeOptions,
        timeout_ms: Option<u32>,
    ) -> Result<Vec<OracleRow>, DbError> {
        let cursor_id = result.cursor_id;
        let implicit_resultsets = result.implicit_resultsets.take();
        let mut columns = result.columns.clone();
        let mut rows = std::mem::take(&mut result.rows);
        let mut previous_row = rows.last().cloned();
        let has_parent_result = !columns.is_empty();
        if has_parent_result
            && rows.is_empty()
            && cursor_id != 0
            && columns_require_define(&columns)
        {
            let fetched = oracledb::BlockingConnection::define_and_fetch_rows_with_columns(
                inner,
                cursor_id,
                FETCH_BATCH_ROWS,
                &columns,
                None,
            )
            .map_err(|err| DbError::Query(sanitize_driver_error(err, opts)))?;
            if !fetched.columns.is_empty() {
                columns = fetched.columns.clone();
            }
            previous_row = fetched.rows.last().cloned();
            rows.extend(fetched.rows);
            result.more_rows = fetched.more_rows;
        }
        while has_parent_result && result.more_rows && cursor_id != 0 {
            let fetched = if columns_require_define(&columns) {
                oracledb::BlockingConnection::define_and_fetch_rows_with_columns(
                    inner,
                    cursor_id,
                    FETCH_BATCH_ROWS,
                    &columns,
                    previous_row.as_deref(),
                )
            } else {
                oracledb::BlockingConnection::fetch_rows_with_columns(
                    inner,
                    cursor_id,
                    FETCH_BATCH_ROWS,
                    &columns,
                    previous_row.as_deref(),
                )
            }
            .map_err(|err| DbError::Query(sanitize_driver_error(err, opts)))?;
            if !fetched.columns.is_empty() {
                columns = fetched.columns.clone();
            }
            previous_row = fetched.rows.last().cloned();
            rows.extend(fetched.rows);
            result.more_rows = fetched.more_rows;
        }
        let mut converted =
            rows_to_oracle_rows(inner, &columns, rows, opts, serialize_opts, timeout_ms, 0)?;
        if let Some(implicit_resultsets) = implicit_resultsets
            && let Some(row) = implicit_resultsets_to_row(
                inner,
                implicit_resultsets,
                opts,
                serialize_opts,
                timeout_ms,
            )?
        {
            converted.push(row);
        }
        if cursor_id != 0 {
            inner.release_cursor(cursor_id);
        }
        Ok(converted)
    }

    fn columns_require_define(columns: &[ColumnMetadata]) -> bool {
        columns.iter().any(|column| {
            matches!(
                column.ora_type_num,
                ORA_TYPE_NUM_CLOB | ORA_TYPE_NUM_BLOB | ORA_TYPE_NUM_VECTOR | ORA_TYPE_NUM_JSON
            )
        })
    }

    fn rows_to_oracle_rows(
        inner: &mut oracledb::Connection,
        columns: &[ColumnMetadata],
        rows: Vec<Vec<Option<QueryValue>>>,
        opts: &OracleConnectOptions,
        serialize_opts: &SerializeOptions,
        timeout_ms: Option<u32>,
        depth: usize,
    ) -> Result<Vec<OracleRow>, DbError> {
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let mut cells = Vec::with_capacity(columns.len());
            for (idx, meta) in columns.iter().enumerate() {
                let value = row.get(idx).cloned().flatten();
                cells.push((
                    meta.name.clone(),
                    value_to_cell(inner, meta, value, opts, serialize_opts, timeout_ms, depth)?,
                ));
            }
            out.push(OracleRow { columns: cells });
        }
        Ok(out)
    }

    fn value_to_cell(
        inner: &mut oracledb::Connection,
        meta: &ColumnMetadata,
        value: Option<QueryValue>,
        opts: &OracleConnectOptions,
        serialize_opts: &SerializeOptions,
        timeout_ms: Option<u32>,
        depth: usize,
    ) -> Result<OracleCell, DbError> {
        let oracle_type = oracle_type_name(meta);
        let cell = match value {
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
            Some(QueryValue::Cursor(cursor)) => {
                return materialize_cursor_cell(
                    inner,
                    oracle_type,
                    &cursor,
                    opts,
                    serialize_opts,
                    timeout_ms,
                    depth,
                );
            }
            Some(QueryValue::Object(value)) => OracleCell::binary(oracle_type, value.packed_data),
            Some(QueryValue::Lob(value)) => {
                let limits = LobReadLimits::from(serialize_opts);
                let mut read_lob =
                    |locator: &[u8], offset: u64, amount: u64| -> Result<LobReadData, DbError> {
                        oracledb::BlockingConnection::read_lob_with_timeout(
                            inner, locator, offset, amount, timeout_ms,
                        )
                        .map(|result| LobReadData { data: result.data })
                        .map_err(|err| {
                            DbError::Query(format!(
                                "LOB locator read failed: {}",
                                sanitize_driver_error(err, opts)
                            ))
                        })
                    };
                return materialize_lob_cell(oracle_type, &value, limits, &mut read_lob);
            }
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
        };
        Ok(cell)
    }

    fn implicit_resultsets_to_row(
        inner: &mut oracledb::Connection,
        values: Vec<QueryValue>,
        opts: &OracleConnectOptions,
        serialize_opts: &SerializeOptions,
        timeout_ms: Option<u32>,
    ) -> Result<Option<OracleRow>, DbError> {
        let mut columns = Vec::with_capacity(values.len());
        for (idx, value) in values.into_iter().enumerate() {
            let name = format!("IMPLICIT_RESULT_{}", idx + 1);
            let cell = match value {
                QueryValue::Cursor(cursor) => materialize_cursor_cell(
                    inner,
                    "REF CURSOR".to_owned(),
                    &cursor,
                    opts,
                    serialize_opts,
                    timeout_ms,
                    0,
                )?,
                other => OracleCell::new(
                    "VARCHAR2",
                    Some(format!(
                        "<unsupported implicit resultset value {}: {other:?}>",
                        idx + 1
                    )),
                ),
            };
            columns.push((name, cell));
        }
        if columns.is_empty() {
            Ok(None)
        } else {
            Ok(Some(OracleRow { columns }))
        }
    }

    fn materialize_cursor_cell(
        inner: &mut oracledb::Connection,
        oracle_type: String,
        cursor: &CursorValue,
        opts: &OracleConnectOptions,
        serialize_opts: &SerializeOptions,
        timeout_ms: Option<u32>,
        depth: usize,
    ) -> Result<OracleCell, DbError> {
        if depth >= serialize_opts.max_nested_cursor_depth {
            inner.release_cursor(cursor.cursor_id);
            return Ok(OracleCell::nested_result(
                oracle_type,
                OracleNestedResult {
                    columns: cursor_column_names(&cursor.columns),
                    truncated: true,
                    ..Default::default()
                },
            ));
        }
        let (row_cap, fetch_limit, cell_limited) = cursor_caps(cursor, serialize_opts);
        let result = match oracledb::BlockingConnection::fetch_cursor(inner, cursor, fetch_limit) {
            Ok(result) => result,
            Err(err) => {
                inner.release_cursor(cursor.cursor_id);
                return Err(DbError::Query(format!(
                    "REF CURSOR fetch failed: {}",
                    sanitize_driver_error(err, opts)
                )));
            }
        };
        let mut rows = result.rows;
        let fetched_count = rows.len().min(row_cap);
        let row_limited = rows.len() > row_cap;
        rows.truncate(row_cap);
        let columns = if result.columns.is_empty() {
            cursor.columns.clone()
        } else {
            result.columns
        };
        let nested_rows = rows_to_oracle_rows(
            inner,
            &columns,
            rows,
            opts,
            serialize_opts,
            timeout_ms,
            depth + 1,
        )?;
        Ok(OracleCell::nested_result(
            oracle_type,
            OracleNestedResult {
                columns: cursor_column_names(&columns),
                row_count: nested_rows.len(),
                fetched_count,
                rows: nested_rows,
                truncated: row_limited || cell_limited,
            },
        ))
    }

    fn cursor_caps(cursor: &CursorValue, opts: &SerializeOptions) -> (usize, usize, bool) {
        let column_count = cursor.columns.len().max(1);
        let rows_by_cells = opts.max_nested_cursor_cells / column_count;
        let row_cap = opts.max_nested_cursor_rows.min(rows_by_cells);
        let cell_limited = row_cap < opts.max_nested_cursor_rows;
        let fetch_limit = row_cap.saturating_add(1).max(1);
        (row_cap, fetch_limit, cell_limited)
    }

    fn cursor_column_names(columns: &[ColumnMetadata]) -> Vec<String> {
        columns.iter().map(|column| column.name.clone()).collect()
    }

    fn materialize_lob_cell(
        oracle_type: String,
        lob: &LobValue,
        limits: LobReadLimits,
        read_lob: &mut impl FnMut(&[u8], u64, u64) -> Result<LobReadData, DbError>,
    ) -> Result<OracleCell, DbError> {
        match lob.ora_type_num {
            ORA_TYPE_NUM_CLOB => materialize_text_lob(oracle_type, lob, limits, read_lob),
            ORA_TYPE_NUM_BLOB => materialize_binary_lob(
                oracle_type,
                lob,
                Some(lob.size),
                limits.max_blob_bytes,
                read_lob,
            ),
            ORA_TYPE_NUM_BFILE => {
                materialize_binary_lob(oracle_type, lob, None, limits.max_blob_bytes, read_lob)
            }
            other => Err(DbError::Query(format!(
                "unsupported LOB locator type ORA_TYPE_{other}"
            ))),
        }
    }

    fn materialize_text_lob(
        oracle_type: String,
        lob: &LobValue,
        limits: LobReadLimits,
        read_lob: &mut impl FnMut(&[u8], u64, u64) -> Result<LobReadData, DbError>,
    ) -> Result<OracleCell, DbError> {
        let source_length = saturating_usize(lob.size);
        let amount = known_lob_read_amount(lob.size, limits.max_lob_chars);
        let data = read_lob_bytes(lob, amount, read_lob)?;
        let text = if data.is_empty() {
            String::new()
        } else {
            decode_lob_text(&data, lob.csfrm, Some(&lob.locator))
                .map_err(|err| DbError::Query(format!("LOB text decode failed: {err}")))?
        };
        Ok(OracleCell::new(oracle_type, Some(text)).with_source_length(source_length))
    }

    fn materialize_binary_lob(
        oracle_type: String,
        lob: &LobValue,
        known_size: Option<u64>,
        cap: usize,
        read_lob: &mut impl FnMut(&[u8], u64, u64) -> Result<LobReadData, DbError>,
    ) -> Result<OracleCell, DbError> {
        let amount = known_size.map_or_else(
            || unknown_lob_read_amount(cap),
            |size| known_lob_read_amount(size, cap),
        );
        let data = read_lob_bytes(lob, amount, read_lob)?;
        let mut cell = OracleCell::binary(oracle_type, data);
        if let Some(source_length) = known_size.map(saturating_usize) {
            cell = cell.with_source_length(source_length);
        }
        Ok(cell)
    }

    fn read_lob_bytes(
        lob: &LobValue,
        amount: u64,
        read_lob: &mut impl FnMut(&[u8], u64, u64) -> Result<LobReadData, DbError>,
    ) -> Result<Vec<u8>, DbError> {
        if amount == 0 {
            return Ok(Vec::new());
        }
        Ok(read_lob(&lob.locator, 1, amount)?.data.unwrap_or_default())
    }

    fn known_lob_read_amount(size: u64, cap: usize) -> u64 {
        size.min(u64::try_from(cap).unwrap_or(u64::MAX))
    }

    fn unknown_lob_read_amount(cap: usize) -> u64 {
        u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1)
    }

    fn saturating_usize(value: u64) -> usize {
        usize::try_from(value).unwrap_or(usize::MAX)
    }

    #[cfg(test)]
    #[allow(clippy::items_after_test_module)]
    mod lob_tests {
        use super::*;
        use crate::serialize::serialize_cell;
        use oracledb::protocol::thin::{CS_FORM_IMPLICIT, ORA_TYPE_NUM_RAW};
        use serde_json::json;

        fn lob(ora_type_num: u8, size: u64) -> LobValue {
            LobValue {
                ora_type_num,
                csfrm: CS_FORM_IMPLICIT,
                locator: vec![7; 40],
                size,
                chunk_size: 8192,
            }
        }

        fn cursor(column_count: usize) -> CursorValue {
            CursorValue {
                columns: (0..column_count)
                    .map(|idx| ColumnMetadata {
                        name: format!("C{idx}"),
                        ..Default::default()
                    })
                    .collect(),
                cursor_id: 42,
            }
        }

        #[cfg(feature = "live-xe")]
        fn live_opts_from_env() -> Option<OracleConnectOptions> {
            Some(OracleConnectOptions {
                connect_string: std::env::var("ORACLEMCP_TEST_DSN").ok()?,
                username: Some(std::env::var("ORACLEMCP_TEST_USER").ok()?),
                password: Some(std::env::var("ORACLEMCP_TEST_PASSWORD").ok()?),
                ..Default::default()
            })
        }

        #[test]
        fn cursor_caps_enforce_rows_and_cells_with_sentinel_fetch() {
            let opts = SerializeOptions {
                max_nested_cursor_rows: 10,
                max_nested_cursor_cells: 12,
                ..Default::default()
            };

            assert_eq!(cursor_caps(&cursor(2), &opts), (6, 7, true));
            assert_eq!(cursor_caps(&cursor(1), &opts), (10, 11, false));
        }

        #[test]
        fn named_binds_are_ordered_by_first_real_placeholder() {
            let ordered = order_named_binds_for_driver(
                "select ':ignored' as s, :a, :b, :a from dual -- :commented\n\
                 where c = :c /* :also_ignored */ and quoted = \":identifier\"",
                vec![
                    (":c".to_owned(), BindValue::Text("three".to_owned())),
                    (":b".to_owned(), BindValue::Number("2".to_owned())),
                    (":a".to_owned(), BindValue::Number("1".to_owned())),
                    (":unused".to_owned(), BindValue::Text("tail".to_owned())),
                ],
            );

            assert_eq!(ordered.len(), 4);
            assert!(matches!(&ordered[0], BindValue::Number(value) if value == "1"));
            assert!(matches!(&ordered[1], BindValue::Number(value) if value == "2"));
            assert!(matches!(&ordered[2], BindValue::Text(value) if value == "three"));
            assert!(matches!(&ordered[3], BindValue::Text(value) if value == "tail"));
        }

        #[cfg(feature = "live-xe")]
        #[test]
        fn cursor_fetch_failure_leaves_connection_usable() {
            let Some(opts) = live_opts_from_env() else {
                eprintln!(
                    "[live-xe] SKIP cursor_fetch_failure_leaves_connection_usable: set ORACLEMCP_TEST_*"
                );
                return;
            };
            let mut inner = match oracledb::BlockingConnection::connect(
                to_connect_options(&opts).expect("connect options"),
            ) {
                Ok(conn) => conn,
                Err(err) => {
                    eprintln!(
                        "[live-xe] SKIP cursor_fetch_failure_leaves_connection_usable: no reachable Oracle ({})",
                        sanitize_driver_error(err, &opts)
                    );
                    return;
                }
            };
            let mut invalid_cursor = cursor(1);
            invalid_cursor.cursor_id = u32::MAX;

            let err = materialize_cursor_cell(
                &mut inner,
                "REF CURSOR".to_owned(),
                &invalid_cursor,
                &opts,
                &SerializeOptions::default(),
                None,
                0,
            )
            .expect_err("invalid cursor id should fail");

            assert!(
                err.to_string().contains("REF CURSOR fetch failed"),
                "unexpected error: {err}"
            );
            let probe = oracledb::BlockingConnection::execute_query(
                &mut inner,
                "SELECT 1 AS n FROM dual",
                1,
            )
            .expect("connection remains usable after cursor fetch failure");
            let n = probe.rows[0][0]
                .as_ref()
                .and_then(QueryValue::as_i64)
                .expect("numeric probe cell");
            assert_eq!(n, 1);
        }

        #[test]
        fn materializes_clob_locator_as_text() {
            let lob = lob(ORA_TYPE_NUM_CLOB, 5);
            let mut calls = Vec::new();
            let mut read_lob = |locator: &[u8], offset: u64, amount: u64| {
                assert_eq!(locator, lob.locator.as_slice());
                calls.push((offset, amount));
                Ok(LobReadData {
                    data: Some(b"hello".to_vec()),
                })
            };

            let cell = materialize_lob_cell(
                "CLOB".to_owned(),
                &lob,
                LobReadLimits {
                    max_lob_chars: 32,
                    max_blob_bytes: 1024,
                },
                &mut read_lob,
            )
            .expect("clob materialized");

            assert_eq!(cell.text(), Some("hello"));
            assert_eq!(cell.source_length, Some(5));
            assert_eq!(calls, vec![(1, 5)]);
        }

        #[test]
        fn materializes_blob_locator_as_binary() {
            let lob = lob(ORA_TYPE_NUM_BLOB, 3);
            let mut read_lob = |_locator: &[u8], offset: u64, amount: u64| {
                assert_eq!((offset, amount), (1, 3));
                Ok(LobReadData {
                    data: Some(vec![1, 2, 3]),
                })
            };

            let cell = materialize_lob_cell(
                "BLOB".to_owned(),
                &lob,
                LobReadLimits {
                    max_lob_chars: 32,
                    max_blob_bytes: 1024,
                },
                &mut read_lob,
            )
            .expect("blob materialized");

            assert_eq!(cell.bytes.as_deref(), Some([1, 2, 3].as_slice()));
            assert_eq!(cell.source_length, Some(3));
        }

        #[test]
        fn null_clob_cell_serializes_as_null() {
            let cell = OracleCell::new("CLOB", None);

            assert_eq!(
                serialize_cell(&cell, &SerializeOptions::default()),
                serde_json::Value::Null
            );
        }

        #[test]
        fn clob_locator_read_is_bounded_and_reports_full_length() {
            let lob = lob(ORA_TYPE_NUM_CLOB, 100);
            let mut read_lob = |_locator: &[u8], offset: u64, amount: u64| {
                assert_eq!((offset, amount), (1, 4));
                Ok(LobReadData {
                    data: Some(b"abcd".to_vec()),
                })
            };

            let cell = materialize_lob_cell(
                "CLOB".to_owned(),
                &lob,
                LobReadLimits {
                    max_lob_chars: 4,
                    max_blob_bytes: 1024,
                },
                &mut read_lob,
            )
            .expect("clob materialized");
            let rendered = serialize_cell(
                &cell,
                &SerializeOptions {
                    max_lob_chars: 4,
                    ..Default::default()
                },
            );

            assert_eq!(
                rendered,
                json!({ "value": "abcd", "truncated": true, "char_length": 100 })
            );
        }

        #[test]
        fn bfile_locator_read_is_bounded_when_size_is_unknown() {
            let lob = lob(ORA_TYPE_NUM_BFILE, 0);
            let mut read_lob = |_locator: &[u8], offset: u64, amount: u64| {
                assert_eq!((offset, amount), (1, 3));
                Ok(LobReadData {
                    data: Some(vec![1, 2, 3]),
                })
            };

            let cell = materialize_lob_cell(
                "BFILE".to_owned(),
                &lob,
                LobReadLimits {
                    max_lob_chars: 32,
                    max_blob_bytes: 2,
                },
                &mut read_lob,
            )
            .expect("bfile materialized");
            let rendered = serialize_cell(
                &cell,
                &SerializeOptions {
                    max_blob_bytes: 2,
                    ..Default::default()
                },
            );

            assert_eq!(rendered["byte_length"], json!(3));
            assert_eq!(rendered["truncated"], json!(true));
        }

        #[test]
        fn locator_read_failure_is_structured() {
            let lob = lob(ORA_TYPE_NUM_CLOB, 8);
            let mut read_lob = |_locator: &[u8], _offset: u64, _amount: u64| {
                Err(DbError::Query("read failed".to_owned()))
            };

            let err = materialize_lob_cell(
                "CLOB".to_owned(),
                &lob,
                LobReadLimits {
                    max_lob_chars: 4,
                    max_blob_bytes: 1024,
                },
                &mut read_lob,
            )
            .expect_err("read failure should propagate");

            assert!(err.to_string().contains("read failed"));
        }

        #[test]
        fn unsupported_lob_subtype_is_explicit_error() {
            let lob = lob(ORA_TYPE_NUM_RAW, 8);
            let mut read_lob = |_locator: &[u8], _offset: u64, _amount: u64| {
                panic!("unsupported subtype must not read")
            };

            let err = materialize_lob_cell(
                "RAW".to_owned(),
                &lob,
                LobReadLimits {
                    max_lob_chars: 4,
                    max_blob_bytes: 1024,
                },
                &mut read_lob,
            )
            .expect_err("unsupported subtype");

            assert!(
                err.to_string()
                    .contains("unsupported LOB locator type ORA_TYPE_23")
            );
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
        if let Some(wallet_password) = &opts.wallet_password {
            secrets.push(wallet_password.clone());
        }
        if let Some(dn) = &opts.ssl_server_cert_dn {
            secrets.push(dn.clone());
        }
        for (namespace, key, value) in &opts.app_context {
            secrets.push(namespace.clone());
            secrets.push(key.clone());
            secrets.push(value.clone());
        }
        secrets.extend(
            opts.auth_adapter
                .sensitive_values()
                .into_iter()
                .map(ToOwned::to_owned),
        );
        if let Some(identity) = &opts.session_identity {
            for value in [
                &identity.edition,
                &identity.program,
                &identity.machine,
                &identity.os_user,
                &identity.terminal,
                &identity.module,
                &identity.action,
                &identity.client_identifier,
                &identity.client_info,
                &identity.driver_name,
            ]
            .into_iter()
            .flatten()
            {
                secrets.push(value.clone());
            }
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
                connection_strategy: Some("single_session".to_owned()),
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
            self.query_rows_with_serialize_options(sql, binds, &SerializeOptions::default())
        }

        fn query_rows_with_serialize_options(
            &self,
            sql: &str,
            binds: &[OracleBind],
            serialize_opts: &SerializeOptions,
        ) -> Result<Vec<OracleRow>, DbError> {
            let binds: Vec<BindValue> = binds.iter().map(to_bind).collect();
            let timeout = self.timeout_ms()?;
            let mut inner = self.lock_inner()?;
            let result = if binds.is_empty() && timeout.is_none() {
                oracledb::BlockingConnection::execute_query(
                    &mut inner,
                    sql,
                    prefetch_rows_for_statement(sql),
                )
                .map_err(|err| DbError::Query(sanitize_driver_error(err, &self.opts)))?
            } else {
                execute_with_timeout(
                    &mut inner,
                    sql,
                    prefetch_rows_for_statement(sql),
                    &binds,
                    timeout,
                    &self.opts,
                    "query",
                )?
            };
            collect_all_rows(&mut inner, result, &self.opts, serialize_opts, timeout)
        }

        fn query_rows_named(
            &self,
            sql: &str,
            binds: &[(String, OracleBind)],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.query_rows_named_with_serialize_options(sql, binds, &SerializeOptions::default())
        }

        fn query_rows_named_with_serialize_options(
            &self,
            sql: &str,
            binds: &[(String, OracleBind)],
            serialize_opts: &SerializeOptions,
        ) -> Result<Vec<OracleRow>, DbError> {
            let binds: Vec<(String, BindValue)> = binds
                .iter()
                .map(|(name, bind)| (name.clone(), to_bind(bind)))
                .collect();
            let timeout = self.timeout_ms()?;
            let mut inner = self.lock_inner()?;
            let result = if binds.is_empty() {
                if timeout.is_none() {
                    oracledb::BlockingConnection::execute_query(
                        &mut inner,
                        sql,
                        prefetch_rows_for_statement(sql),
                    )
                    .map_err(|err| DbError::Query(sanitize_driver_error(err, &self.opts)))?
                } else {
                    execute_with_timeout(
                        &mut inner,
                        sql,
                        prefetch_rows_for_statement(sql),
                        &[],
                        timeout,
                        &self.opts,
                        "query named",
                    )?
                }
            } else {
                let ordered_binds = order_named_binds_for_driver(sql, binds);
                execute_with_timeout(
                    &mut inner,
                    sql,
                    prefetch_rows_for_statement(sql),
                    &ordered_binds,
                    timeout,
                    &self.opts,
                    "query named",
                )?
            };
            collect_all_rows(&mut inner, result, &self.opts, serialize_opts, timeout)
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
            let timeout = self.timeout_ms()?;
            let mut lines = Vec::new();
            let mut char_count = 0usize;
            let mut truncated = false;
            let mut inner = self.lock_inner()?;
            for _ in 0..max_lines {
                let result = oracledb::BlockingConnection::execute_query_with_binds_and_timeout(
                    &mut inner,
                    "BEGIN DBMS_OUTPUT.GET_LINE(:1, :2); END;",
                    0,
                    &[
                        BindValue::Output {
                            ora_type_num: ORA_TYPE_NUM_VARCHAR,
                            csfrm: CS_FORM_IMPLICIT,
                            buffer_size: 32_767,
                        },
                        BindValue::Output {
                            ora_type_num: ORA_TYPE_NUM_NUMBER,
                            csfrm: CS_FORM_IMPLICIT,
                            buffer_size: 22,
                        },
                    ],
                    timeout,
                )
                .map_err(|err| DbError::Execute(sanitize_driver_error(err, &self.opts)))?;
                let status = output_value(&result, 1)
                    .and_then(QueryValue::as_i64)
                    .ok_or_else(|| {
                        DbError::Execute(
                            "DBMS_OUTPUT.GET_LINE did not return a numeric status".to_owned(),
                        )
                    })?;
                if status != 0 {
                    break;
                }
                let line = match output_value(&result, 0) {
                    Some(QueryValue::Text(value) | QueryValue::Rowid(value)) => value.to_owned(),
                    Some(QueryValue::Number(value)) => value.to_canonical_string(),
                    Some(value) => format!("{value:?}"),
                    None => String::new(),
                };
                let next_count = char_count.saturating_add(line.chars().count());
                if next_count > max_chars {
                    truncated = true;
                    break;
                }
                char_count = next_count;
                lines.push(line);
            }
            if lines.len() == max_lines {
                truncated = true;
            }
            Ok(DbmsOutput {
                line_count: lines.len(),
                lines,
                char_count,
                truncated,
            })
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
    use crate::auth_adapter::AuthAdapter;
    use crate::types::OracleSessionIdentity;

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
    fn prefetch_rows_only_for_select_statements() {
        assert_eq!(
            driver::prefetch_rows_for_statement("SELECT 1 FROM dual"),
            512
        );
        assert_eq!(
            driver::prefetch_rows_for_statement("  \nselect * from dual"),
            512
        );
        assert_eq!(
            driver::prefetch_rows_for_statement("BEGIN DBMS_SQL.RETURN_RESULT(NULL); END;"),
            0
        );
        assert_eq!(
            driver::prefetch_rows_for_statement("DECLARE rc SYS_REFCURSOR; BEGIN NULL; END;"),
            0
        );
    }

    #[test]
    fn thin_connect_options_use_explicit_client_identity_fields() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("app".to_owned()),
            password: Some("secret".to_owned()),
            session_identity: Some(OracleSessionIdentity {
                program: Some("profile-program".to_owned()),
                machine: Some("profile-machine".to_owned()),
                os_user: Some("profile-os-user".to_owned()),
                terminal: Some("profile-terminal".to_owned()),
                module: Some("session-module".to_owned()),
                client_identifier: Some("session-client-id".to_owned()),
                driver_name: Some("profile-driver".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.identity.program, "profile-program");
        assert_eq!(connect.identity.machine, "profile-machine");
        assert_eq!(connect.identity.osuser, "profile-os-user");
        assert_eq!(connect.identity.terminal, "profile-terminal");
        assert_eq!(connect.identity.driver_name, "profile-driver");
    }

    #[test]
    fn thin_connect_options_keep_legacy_identity_fallbacks() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("app".to_owned()),
            password: Some("secret".to_owned()),
            session_identity: Some(OracleSessionIdentity {
                module: Some("legacy-module-program".to_owned()),
                client_identifier: Some("legacy-client-terminal".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.identity.program, "legacy-module-program");
        assert_eq!(connect.identity.terminal, "legacy-client-terminal");
        assert_eq!(connect.identity.driver_name, "oraclemcp-thin");
        assert!(!connect.identity.machine.is_empty());
        assert!(!connect.identity.osuser.is_empty());
    }

    #[test]
    fn thin_connect_options_apply_explicit_tls_fields() {
        let opts = OracleConnectOptions {
            connect_string: "tcps://adb.example.com/service".to_owned(),
            username: Some("app".to_owned()),
            password: Some("secret".to_owned()),
            wallet_location: Some("/wallets/private".into()),
            wallet_password: Some("wallet-secret".to_owned()),
            ssl_server_dn_match: Some(false),
            ssl_server_cert_dn: Some("CN=db.example.com,O=Example,C=US".to_owned()),
            use_sni: Some(false),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.wallet_location.as_deref(), Some("/wallets/private"));
        assert_eq!(connect.wallet_password.as_deref(), Some("wallet-secret"));
        assert!(!connect.ssl_server_dn_match);
        assert_eq!(
            connect.ssl_server_cert_dn.as_deref(),
            Some("CN=db.example.com,O=Example,C=US")
        );
        assert!(!connect.use_sni);
    }

    #[test]
    fn thin_connect_options_keep_wallet_sni_default() {
        let opts = OracleConnectOptions {
            connect_string: "tcps://adb.example.com/service".to_owned(),
            username: Some("app".to_owned()),
            password: Some("secret".to_owned()),
            wallet_location: Some("/wallets/private".into()),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.wallet_location.as_deref(), Some("/wallets/private"));
        assert!(
            connect.use_sni,
            "existing wallet profiles default to SNI on"
        );
        assert!(connect.ssl_server_dn_match);
        assert_eq!(connect.wallet_password, None);
        assert_eq!(connect.ssl_server_cert_dn, None);
    }

    #[test]
    fn thin_connect_options_apply_proxy_auth() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("MCP_PROXY".to_owned()),
            password: Some("proxy-secret".to_owned()),
            auth_adapter: AuthAdapter::Proxy {
                proxy_user: "MCP_PROXY".to_owned(),
                target_schema: "APP_OWNER".to_owned(),
            },
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.user, "MCP_PROXY");
        assert_eq!(connect.proxy_user.as_deref(), Some("APP_OWNER"));
    }

    #[test]
    fn thin_connect_options_apply_app_context_in_order() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            app_context: vec![
                (
                    "ORACLEMCP_CTX".to_owned(),
                    "tenant_id".to_owned(),
                    "tenant-123".to_owned(),
                ),
                (
                    "ORACLEMCP_CTX".to_owned(),
                    "request_id".to_owned(),
                    "req-456".to_owned(),
                ),
            ],
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.app_context, opts.app_context);
    }

    #[test]
    fn thin_connect_options_apply_sdu_when_configured() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            sdu: Some(32_768),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.sdu, 32_768u16);
    }

    #[test]
    fn thin_connect_options_keep_driver_default_sdu_when_unset() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.sdu, 8192u16);
    }

    #[test]
    fn thin_connect_options_apply_statement_cache_size_when_configured() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            statement_cache_size: Some(128),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.statement_cache_size, 128);
    }

    #[test]
    fn thin_connect_options_keep_driver_default_statement_cache_when_unset() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.statement_cache_size, 20);
    }

    #[test]
    fn thin_connect_options_apply_edition_when_configured() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            session_identity: Some(OracleSessionIdentity {
                edition: Some("E_TEST".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(connect.edition.as_deref(), Some("E_TEST"));
    }

    #[test]
    fn thin_connect_options_reject_unsupported_enterprise_auth() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            auth_adapter: AuthAdapter::Radius,
            ..Default::default()
        };

        let err = driver::to_connect_options(&opts).expect_err("unsupported");
        assert!(matches!(err, DbError::UnsupportedAuth(_)));
        assert!(err.to_string().contains("RADIUS/native MFA"));
    }

    #[test]
    fn iam_token_over_tcps_is_wired_through_with_access_token() {
        // A5: the pinned driver supports OCI IAM database-token auth. With a
        // fetched token and a TCPS transport, to_connect_options succeeds and
        // sets the driver's access token (no password is required or used).
        let opts = OracleConnectOptions {
            connect_string: "tcps://adb.eu.oraclecloud.com:1522/svc_high".to_owned(),
            username: Some("APP_USER".to_owned()),
            password: None,
            use_iam_token: true,
            iam_token: Some("iam.jwt.token".to_owned()),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("iam token connect options");
        assert!(
            connect.access_token.is_some(),
            "the IAM token must be wired through with_access_token"
        );
        // The token must never leak through Debug.
        let rendered = format!("{:?}", connect.access_token);
        assert!(!rendered.contains("iam.jwt.token"), "{rendered}");
    }

    #[test]
    fn iam_token_over_non_tcps_is_refused_fail_closed() {
        // A5: an IAM token must never travel over a plaintext transport. We fail
        // closed BEFORE handing the token to the driver.
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP_USER".to_owned()),
            use_iam_token: true,
            iam_token: Some("iam.jwt.token".to_owned()),
            ..Default::default()
        };

        let err = driver::to_connect_options(&opts).expect_err("non-tcps token refused");
        assert!(matches!(err, DbError::UnsupportedAuth(_)));
        assert!(err.to_string().contains("TLS (TCPS)"), "{err}");
        // The refusal must not echo the token.
        assert!(!err.to_string().contains("iam.jwt.token"), "{err}");
    }

    #[test]
    fn iam_token_wired_via_wallet_backed_tls_descriptor() {
        // A wallet-backed connection is TLS, so an IAM token is allowed even
        // without an explicit tcps:// scheme.
        let opts = OracleConnectOptions {
            connect_string: "adb_high".to_owned(),
            username: Some("APP_USER".to_owned()),
            wallet_location: Some("/wallets/adb".into()),
            iam_token: Some("iam.jwt.token".to_owned()),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("wallet-backed token options");
        assert!(connect.access_token.is_some());
    }

    #[test]
    fn use_iam_token_without_a_fetched_token_is_a_setup_error() {
        // use_iam_token set but no token fetched yet: a setup error pointing at
        // the IAM token-source seam, NOT a driver-unsupported error.
        let opts = OracleConnectOptions {
            connect_string: "tcps://adb.eu.oraclecloud.com:1522/svc_high".to_owned(),
            username: Some("APP_USER".to_owned()),
            use_iam_token: true,
            iam_token: None,
            ..Default::default()
        };

        let err = driver::to_connect_options(&opts).expect_err("no token fetched");
        assert!(matches!(err, DbError::UnsupportedAuth(_)));
        assert!(err.to_string().contains("no token was fetched"), "{err}");
    }

    #[test]
    fn driver_error_redaction_removes_connect_material() {
        let opts = OracleConnectOptions {
            connect_string: "dbhost:1521/private_service".to_owned(),
            username: Some("app_user".to_owned()),
            password: Some("super_secret".to_owned()),
            auth_adapter: AuthAdapter::Proxy {
                proxy_user: "MCP_PROXY".to_owned(),
                target_schema: "APP_OWNER".to_owned(),
            },
            wallet_location: Some("/wallets/private".into()),
            wallet_password: Some("wallet_secret".to_owned()),
            ssl_server_cert_dn: Some("CN=private-db,O=Example,C=US".to_owned()),
            iam_token: Some("iam.jwt.token".to_owned()),
            app_context: vec![(
                "private-namespace".to_owned(),
                "private-key".to_owned(),
                "private-value".to_owned(),
            )],
            session_identity: Some(OracleSessionIdentity {
                program: Some("private-program".to_owned()),
                machine: Some("private-machine".to_owned()),
                os_user: Some("private-os-user".to_owned()),
                terminal: Some("private-terminal".to_owned()),
                module: Some("private-module".to_owned()),
                action: Some("private-action".to_owned()),
                client_identifier: Some("private-client-id".to_owned()),
                client_info: Some("private-client-info".to_owned()),
                driver_name: Some("private-driver".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let redacted = driver::sanitize_driver_error(
            "connect app_user/super_secret@dbhost:1521/private_service proxy MCP_PROXY APP_OWNER with /wallets/private \
             wallet_secret CN=private-db,O=Example,C=US and iam.jwt.token failed for private-program private-machine private-os-user \
             private-terminal private-module private-action private-client-id private-client-info \
             private-driver private-namespace private-key private-value",
            &opts,
        );
        for forbidden in [
            "app_user",
            "super_secret",
            "MCP_PROXY",
            "APP_OWNER",
            "dbhost:1521/private_service",
            "/wallets/private",
            "wallet_secret",
            "CN=private-db",
            "iam.jwt.token",
            "private-program",
            "private-machine",
            "private-os-user",
            "private-terminal",
            "private-module",
            "private-action",
            "private-client-id",
            "private-client-info",
            "private-driver",
            "private-namespace",
            "private-key",
            "private-value",
        ] {
            assert!(!redacted.contains(forbidden), "{redacted}");
        }
        assert!(redacted.contains("<redacted>"));
    }
}

/// Rust-level guard for the driver-adapter seam (B2; plan §8 release gate).
///
/// Mirrors `scripts/oraclemcp_driver_seam_lint.sh` so `cargo test` catches an
/// `oracledb::` driver call that leaks outside the adapter even when the shell
/// lint is not run. The two enforcers share one allowlist: this file is the
/// only adapter site. Add a new legitimate `oracledb::` site to BOTH the shell
/// lint's `ADAPTER_ALLOWLIST` and `ADAPTER_ALLOWLIST` below, with a
/// justification.
#[cfg(test)]
mod driver_seam {
    use std::path::{Path, PathBuf};

    /// Workspace-relative paths that ARE the adapter — the only sources allowed
    /// to name an `oracledb::` driver path.
    const ADAPTER_ALLOWLIST: &[&str] = &[
        // B2 adapter: wraps the whole oracledb driver surface.
        "crates/oraclemcp-db/src/connection.rs",
    ];

    /// Walk to the workspace root from this crate's manifest dir
    /// (`.../crates/oraclemcp-db` -> `...`).
    fn workspace_root() -> PathBuf {
        let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        crate_dir
            .parent() // crates/
            .and_then(Path::parent) // workspace root
            .expect("crate manifest dir has a workspace root two levels up")
            .to_path_buf()
    }

    fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|err| panic!("read_dir {}: {err}", dir.display()));
        for entry in entries {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    /// True iff `line` names the DRIVER crate path `oracledb::` (and not the
    /// workspace crate `oraclemcp_db::`). Requires a non-identifier char (or
    /// start of line) to the left of `oracledb`, then optional whitespace, then
    /// `::` — matching the shell lint's `(^|[^A-Za-z0-9_])oracledb[[:space:]]*::`.
    fn names_driver_path(line: &str) -> bool {
        let bytes = line.as_bytes();
        let mut search_from = 0;
        while let Some(rel) = line[search_from..].find("oracledb") {
            let start = search_from + rel;
            let left_ok = start == 0 || {
                let c = bytes[start - 1];
                !(c.is_ascii_alphanumeric() || c == b'_')
            };
            if left_ok {
                // Skip past "oracledb" and any whitespace, expect "::".
                let mut idx = start + "oracledb".len();
                while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                    idx += 1;
                }
                if line[idx..].starts_with("::") {
                    return true;
                }
            }
            search_from = start + "oracledb".len();
        }
        false
    }

    #[test]
    fn no_oracledb_driver_call_outside_adapter() {
        let root = workspace_root();
        let crates_dir = root.join("crates");
        let mut files = Vec::new();
        collect_rs_files(&crates_dir, &mut files);
        files.sort();
        assert!(!files.is_empty(), "no crate sources found under crates/");

        let mut violations: Vec<String> = Vec::new();
        for file in &files {
            let rel = file
                .strip_prefix(&root)
                .expect("file under workspace root")
                .to_string_lossy()
                .replace('\\', "/");
            if ADAPTER_ALLOWLIST.contains(&rel.as_str()) {
                continue;
            }
            let contents = std::fs::read_to_string(file)
                .unwrap_or_else(|err| panic!("read {}: {err}", file.display()));
            for (n, line) in contents.lines().enumerate() {
                if names_driver_path(line) {
                    violations.push(format!("{rel}:{}: {}", n + 1, line.trim()));
                }
            }
        }

        assert!(
            violations.is_empty(),
            "oracledb:: driver path(s) leaked outside the adapter \
             ({:?}); move them behind an OracleConnection / adapter method, or \
             add a legitimate new adapter site to ADAPTER_ALLOWLIST here AND in \
             scripts/oraclemcp_driver_seam_lint.sh:\n{}",
            ADAPTER_ALLOWLIST,
            violations.join("\n"),
        );
    }

    #[test]
    fn pattern_distinguishes_driver_from_workspace_crate() {
        // The DRIVER crate path is a violation.
        assert!(names_driver_path("use oracledb::Connection;"));
        assert!(names_driver_path("    inner: Mutex<oracledb::Connection>,"));
        assert!(names_driver_path(
            "oracledb :: BlockingConnection::connect(x)"
        ));
        // The workspace crate `oraclemcp_db::` is NOT a violation.
        assert!(!names_driver_path("use oraclemcp_db::OracleCell;"));
        assert!(!names_driver_path(
            "let x = oraclemcp_db::serialize_cell(c, o);"
        ));
        // A bare mention of the word without a `::` path is fine.
        assert!(!names_driver_path(
            "//! the thin oracledb-backed connection"
        ));
        assert!(!names_driver_path(
            r#""driver": "pure-Rust oracledb thin driver""#
        ));
    }
}
