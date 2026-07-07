//! The backend-independent [`OracleConnection`] trait and the thin
//! [`oracledb`]-backed [`RustOracleConnection`].
//!
//! The trait is `async` and `Cx`-first (B1): every method takes an explicit
//! `&asupersync::Cx`, so cancellation and the deadline/budget travel with the
//! call. Each round trip is bracketed by explicit `Cx` checkpoints (the
//! native-async driver also checkpoints `cx` internally).
//!
//! # Driver-adapter seam (B2; plan §8 release gate)
//!
//! This file is **the adapter** — the single, enforced isolation boundary for
//! the `oracledb` driver. Every real `oracledb::` call (connect, the
//! `execute_raw` execute path, fetch, LOB, REF CURSOR, auth, commit/rollback,
//! ping, error sanitization) lives here and nowhere else. The rest of the
//! workspace talks to Oracle exclusively through the [`OracleConnection`] trait
//! and the `oraclemcp-db` public surface; no other crate or module names an
//! `oracledb::` path. References to `oracledb` elsewhere are intentionally only
//! doc-links and human-readable driver descriptions (no driver calls).
//!
//! Isolating the driver here meant the `oracledb` 0.2.2 -> 0.5.x cut-over touched
//! exactly this one file: the removed `execute_query*` initial-execute family
//! collapsed onto the retained low-level `Connection::execute_raw` (same
//! `QueryResult`, same prefetch + optional per-call timeout, still composing with
//! the fetch primitives below); `QueryValue`/`BindValue` became
//! `#[non_exhaustive]`; and `oracledb::ConnectOptions` field reads moved to
//! getters. Error classification stays string-based
//! (`oraclemcp_error::parse_ora_code`) and the driver `Error` type is consumed
//! generically via [`Display`](std::fmt::Display) in `sanitize_driver_error`, so
//! no exhaustive match on the driver `Error` type exists to break; the one
//! exhaustive `QueryValue` match carries a fail-safe wildcard arm for any future
//! `#[non_exhaustive]` value kind.
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
    OracleBackend, OracleBind, OracleCell, OracleConnectOptions, OracleConnectionInfo, OracleRow,
};
use asupersync::Cx;
use asupersync::sync::Mutex as AsyncMutex;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::Duration;

/// Map an asupersync cancellation/budget checkpoint failure to the
/// timeout-class [`DbError::Cancelled`]. Used as the explicit before/after
/// cancellation boundary around every native-async driver round trip; the
/// driver itself also checkpoints `cx` internally, so a cancelled call is
/// observed either here or inside the driver and never silently completes.
///
/// Generic over the `Cx` capability row (A9): a read handler running under a
/// narrowed `Cx<ReadPathCaps>` checkpoints identically to one under the full
/// row, since cancellation/budget state lives on `Cx` independent of the effect
/// capabilities. This is the single crate-wide checkpoint helper; `query.rs`,
/// `lease.rs`, and `pool.rs` all route through it.
pub(crate) fn db_checkpoint<Caps>(cx: &Cx<Caps>, phase: &'static str) -> Result<(), DbError> {
    cx.checkpoint_with(phase)
        .map_err(|err| DbError::Cancelled(format!("{phase}: {err}")))
}

/// Bounded `DBMS_OUTPUT` lines captured from a single Oracle session.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbmsOutput {
    /// The captured `DBMS_OUTPUT` lines, in emission order.
    pub lines: Vec<String>,
    /// Number of lines captured (`lines.len()`).
    pub line_count: usize,
    /// Total character count across all captured lines.
    pub char_count: usize,
    /// Whether the line or character cap stopped the drain before exhaustion.
    pub truncated: bool,
}

/// Adapter-layer PL/SQL routine argument for IN, OUT, IN-OUT, and return values.
///
/// This type is intentionally **not** deserializable: routine execution is an
/// internal adapter capability, not an agent-facing tool argument surface. It
/// wraps the thin driver's bind variants privately so callers can mix ordinary
/// input binds with output slots without exposing driver types across the
/// public API.
#[derive(Clone, PartialEq)]
pub struct OracleRoutineArg {
    bind: oracledb::protocol::thin::BindValue,
}

impl OracleRoutineArg {
    /// Build an input-only routine argument.
    #[must_use]
    pub fn input(value: OracleBind) -> Self {
        Self {
            bind: oracle_bind_to_driver(&value),
        }
    }

    /// Build a scalar OUT or IN-OUT argument. The pinned driver has no separate
    /// IN-OUT bind variant; its `Output` bind covers both cases.
    #[must_use]
    pub fn output(ora_type_num: u8, csfrm: u8, buffer_size: u32) -> Self {
        Self {
            bind: oracledb::protocol::thin::BindValue::Output {
                ora_type_num,
                csfrm,
                buffer_size,
            },
        }
    }

    /// Build a scalar return-value argument.
    ///
    /// Oracle routine function returns are bound by placing a normal output bind
    /// at the return position (usually `:1 := fn(...)`). The driver's
    /// `ReturnOutput` variant is for DML `RETURNING` shapes, not this routine
    /// adapter path.
    #[must_use]
    pub fn return_output(ora_type_num: u8, csfrm: u8, buffer_size: u32) -> Self {
        Self {
            bind: oracledb::protocol::thin::BindValue::Output {
                ora_type_num,
                csfrm,
                buffer_size,
            },
        }
    }

    /// Build an object OUT or IN-OUT argument.
    ///
    /// `oid` and `version` are the Oracle object type identity metadata already
    /// discovered by the adapter before routine execution.
    #[must_use]
    pub fn object_output(
        schema: String,
        type_name: String,
        oid: Vec<u8>,
        version: u32,
        buffer_size: u32,
    ) -> Self {
        Self::object_output_inner(schema, type_name, oid, version, buffer_size, false)
    }

    /// Build an object return-value argument.
    ///
    /// `oid` and `version` are the Oracle object type identity metadata already
    /// discovered by the adapter before routine execution.
    #[must_use]
    pub fn object_return_output(
        schema: String,
        type_name: String,
        oid: Vec<u8>,
        version: u32,
        buffer_size: u32,
    ) -> Self {
        Self::object_output_inner(schema, type_name, oid, version, buffer_size, true)
    }

    fn object_output_inner(
        schema: String,
        type_name: String,
        oid: Vec<u8>,
        version: u32,
        buffer_size: u32,
        is_return: bool,
    ) -> Self {
        Self {
            bind: oracledb::protocol::thin::BindValue::ObjectOutput {
                schema,
                type_name,
                oid,
                version,
                buffer_size,
                is_return,
            },
        }
    }

    pub(crate) fn into_driver_bind(self) -> oracledb::protocol::thin::BindValue {
        self.bind
    }

    fn is_output_bind(&self) -> bool {
        matches!(
            self.bind,
            oracledb::protocol::thin::BindValue::Output { .. }
                | oracledb::protocol::thin::BindValue::ReturnOutput { .. }
                | oracledb::protocol::thin::BindValue::ObjectOutput { .. }
        )
    }
}

impl std::fmt::Debug for OracleRoutineArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OracleRoutineArg")
            .field("kind", &self.bind.variant_name())
            .field("value", &"<driver-output-bind>")
            .finish()
    }
}

fn oracle_bind_to_driver(bind: &OracleBind) -> oracledb::protocol::thin::BindValue {
    match bind {
        OracleBind::Null => oracledb::protocol::thin::BindValue::Null,
        OracleBind::String(value) => oracledb::protocol::thin::BindValue::Text(value.clone()),
        OracleBind::I64(value) => oracledb::protocol::thin::BindValue::Number(value.to_string()),
        OracleBind::F64(value) => oracledb::protocol::thin::BindValue::BinaryDouble(*value),
        OracleBind::Bool(value) => {
            oracledb::protocol::thin::BindValue::Number(if *value { "1" } else { "0" }.to_owned())
        }
        OracleBind::TimestampTz {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanosecond,
            offset_minutes,
        } => oracledb::protocol::thin::BindValue::TimestampTz {
            year: *year,
            month: *month,
            day: *day,
            hour: *hour,
            minute: *minute,
            second: *second,
            nanosecond: *nanosecond,
            offset_minutes: *offset_minutes,
        },
    }
}

/// Result of adapter-internal PL/SQL routine execution.
///
/// Routine execution is deliberately a DB-crate adapter capability, not an
/// agent-facing tool. OUT, IN-OUT, and return values are exposed as
/// [`OracleCell`]s in the same positional order as the caller-declared
/// [`OracleRoutineArg`] list, independent of the driver's raw OUT-bind return
/// order.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecuteOutcome {
    rows_affected: u64,
    out_binds: Vec<OracleCell>,
}

impl ExecuteOutcome {
    /// Build an execution outcome from an affected-row count and already
    /// ordered OUT-bind cells.
    #[must_use]
    pub fn new(rows_affected: u64, out_binds: Vec<OracleCell>) -> Self {
        Self {
            rows_affected,
            out_binds,
        }
    }

    /// Rows affected as reported by Oracle for the executed PL/SQL block.
    #[must_use]
    pub const fn rows_affected(&self) -> u64 {
        self.rows_affected
    }

    /// OUT, IN-OUT, and return values in declared routine-argument order.
    #[must_use]
    pub fn out_binds(&self) -> &[OracleCell] {
        &self.out_binds
    }

    /// Consume the outcome and return its ordered OUT-bind cells.
    #[must_use]
    pub fn into_out_binds(self) -> Vec<OracleCell> {
        self.out_binds
    }
}

/// An async, `Cx`-first Oracle connection (B1).
///
/// Every method is `async` and takes an explicit `&Cx` so cancellation and the
/// deadline/budget travel with the call: the native-async `oracledb` driver
/// checkpoints `cx` on every round trip, and this trait adds explicit
/// before/after `db_checkpoint` boundaries so a cancelled call is mapped to
/// the timeout-class [`DbError::Cancelled`] and never silently completes.
///
/// The trait is made object-safe with `async_trait` in `?Send` mode: the
/// MCP dispatch runtime is a single current-thread Asupersync runtime
/// (`oraclemcp-core/src/server.rs`) and no dispatch future is ever spawned
/// across OS threads, so the boxed method futures do not need to be `Send`.
/// This keeps `&dyn OracleConnection` / `Box<dyn OracleConnection>` usable
/// everywhere while letting an implementation hold an Asupersync `Mutex` guard
/// (which is `!Send`) across an `.await`.
#[async_trait(?Send)]
pub trait OracleConnection: Send + Sync {
    /// The backend in use.
    fn backend(&self) -> OracleBackend;
    /// Round-trip the server to confirm liveness (`SELECT 1 FROM dual`).
    async fn ping(&self, cx: &Cx) -> Result<(), DbError>;
    /// Best-effort connection metadata (version, role/open-mode, schema).
    async fn describe(&self, cx: &Cx) -> Result<OracleConnectionInfo, DbError>;
    /// Run a query, binding `binds` positionally (`:1`, `:2`, …). Values are
    /// always bound, never interpolated.
    async fn query_rows(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Vec<OracleRow>, DbError>;
    /// Run a query with serialization caps available to the backend. Backends
    /// that materialize driver-side locators should use these caps; backends
    /// without locator values can fall back to [`OracleConnection::query_rows`].
    async fn query_rows_with_serialize_options(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
        serialize_opts: &SerializeOptions,
    ) -> Result<Vec<OracleRow>, DbError> {
        let _ = serialize_opts;
        self.query_rows(cx, sql, binds).await
    }
    /// Run a query, binding `binds` by name (`:name`). Values are always bound,
    /// never interpolated. Backends that cannot bind by name should fail
    /// explicitly instead of trying to rewrite SQL.
    async fn query_rows_named(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[(String, OracleBind)],
    ) -> Result<Vec<OracleRow>, DbError> {
        let _ = (cx, sql, binds);
        Err(DbError::Query(
            "named binds are not supported by this Oracle backend".to_owned(),
        ))
    }
    /// Run a named-bind query with serialization caps available to the backend.
    async fn query_rows_named_with_serialize_options(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[(String, OracleBind)],
        serialize_opts: &SerializeOptions,
    ) -> Result<Vec<OracleRow>, DbError> {
        let _ = serialize_opts;
        self.query_rows_named(cx, sql, binds).await
    }
    /// Run a DML/DDL statement; returns rows affected (`SQL%ROWCOUNT`).
    ///
    /// If this observes cancellation after Oracle has returned success, callers
    /// must treat the session as dirty and run cleanup rollback/discard logic.
    async fn execute(&self, cx: &Cx, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError>;

    /// Execute an adapter-internal PL/SQL routine block with positional OUT,
    /// IN-OUT, or return bind slots.
    ///
    /// This is intentionally not an agent-facing routine tool. The caller
    /// supplies the exact PL/SQL block and a positional [`OracleRoutineArg`]
    /// list; returned OUT cells are ordered by that list, not by the driver's
    /// raw OUT-bind vector. A called routine may execute `COMMIT` internally;
    /// callers that need transactional guarantees must account for that Oracle
    /// behavior before invoking this adapter path.
    async fn call_routine(
        &self,
        cx: &Cx,
        plsql_block: &str,
        args: &[OracleRoutineArg],
    ) -> Result<ExecuteOutcome, DbError> {
        let _ = (cx, plsql_block, args);
        Err(DbError::Execute(
            "routine execution is not supported by this Oracle backend".to_owned(),
        ))
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
    async fn enable_dbms_output(&self, cx: &Cx, buffer_bytes: Option<u32>) -> Result<(), DbError> {
        match buffer_bytes {
            Some(bytes) => self
                .execute(
                    cx,
                    "BEGIN DBMS_OUTPUT.ENABLE(:1); END;",
                    &[OracleBind::I64(i64::from(bytes))],
                )
                .await
                .map(|_| ()),
            None => self
                .execute(cx, "BEGIN DBMS_OUTPUT.ENABLE(NULL); END;", &[])
                .await
                .map(|_| ()),
        }
    }

    /// Drain `DBMS_OUTPUT` from this session, bounded by line and character
    /// limits. Backends without output-bind support must fail explicitly.
    async fn read_dbms_output(
        &self,
        cx: &Cx,
        max_lines: usize,
        max_chars: usize,
    ) -> Result<DbmsOutput, DbError> {
        let _ = (cx, max_lines, max_chars);
        Err(DbError::Execute(
            "DBMS_OUTPUT capture is not supported by this Oracle backend".to_owned(),
        ))
    }

    /// Commit the current transaction on this session. There is intentionally
    /// no post-commit checkpoint: once Oracle commits, cancellation cannot
    /// undo it.
    async fn commit(&self, cx: &Cx) -> Result<(), DbError>;

    /// Roll back the current transaction on this session.
    async fn rollback(&self, cx: &Cx) -> Result<(), DbError>;

    /// Run a query expecting at most one row.
    async fn query_optional_row(
        &self,
        cx: &Cx,
        sql: &str,
        binds: &[OracleBind],
    ) -> Result<Option<OracleRow>, DbError> {
        Ok(self.query_rows(cx, sql, binds).await?.into_iter().next())
    }
}

/// Thin pure-Rust Oracle connection wrapper over the native-async
/// [`oracledb::Connection`] (B1).
///
/// The driver connection lives behind an Asupersync [`AsyncMutex`] so its
/// `&mut self` round trips can be driven by `&self` trait methods while
/// staying cancellation-safe: the guard is async-aware and may be held across
/// an `.await` (unlike `std::sync::Mutex`, which would be a deadlock/cancel
/// hazard). The connection is single-owner per lease and the server is
/// OS-thread-per-connection, so the mutex never actually contends — it is the
/// interior-mutability primitive, not a concurrency throttle. The
/// `BlockingConnection` facade (and its per-call `build_io_runtime` +
/// `block_on`) is gone: every round trip runs on the one ambient Asupersync
/// runtime.
pub struct RustOracleConnection {
    opts: OracleConnectOptions,
    inner: AsyncMutex<oracledb::Connection>,
    /// Per-round-trip call timeout. A plain `std::sync::Mutex` is fine here: it
    /// is only ever locked-and-dropped synchronously (never held across an
    /// `.await`), so it cannot deadlock the cooperative scheduler.
    call_timeout: Mutex<Option<Duration>>,
}

impl RustOracleConnection {
    /// Open a thin-mode connection per `opts`.
    pub async fn connect(cx: &Cx, opts: OracleConnectOptions) -> Result<Self, DbError> {
        driver::connect(cx, opts).await
    }

    async fn lock_inner(
        &self,
        cx: &Cx,
    ) -> Result<asupersync::sync::MutexGuard<'_, oracledb::Connection>, DbError> {
        self.inner
            .lock(cx)
            .await
            .map_err(|err| DbError::Internal(format!("thin connection lock failed: {err}")))
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

    async fn query_first_row(&self, cx: &Cx, sql: &str) -> Option<OracleRow> {
        self.query_rows(cx, sql, &[])
            .await
            .ok()
            .and_then(|rows| rows.into_iter().next())
    }
}

fn duration_to_millis(duration: Duration) -> u32 {
    let millis = duration.as_millis().min(u128::from(u32::MAX));
    u32::try_from(millis).unwrap_or(u32::MAX)
}

mod driver {
    use super::{
        DbmsOutput, ExecuteOutcome, OracleRoutineArg, RustOracleConnection, oracle_bind_to_driver,
    };
    use crate::auth_adapter::AuthAdapter;
    use crate::error::{ConnectFailureKind, DbError};
    use crate::serialize::{SerializeOptions, StructuredDecodeCaps, json_byte_len};
    use crate::types::{
        OracleBind, OracleCell, OracleConnectOptions, OracleConnectionInfo, OracleNestedResult,
        OracleRow, OracleSessionIdentity,
    };
    use asupersync::Cx;
    use asupersync::sync::Mutex as AsyncMutex;
    use oracledb::protocol::thin::{CursorValue, LobValue, ObjectValue};
    use oracledb::protocol::{
        ClientIdentity,
        oson::OsonValue,
        thin::{
            BindValue, CS_FORM_IMPLICIT, ColumnMetadata, ExecuteOptions, ORA_TYPE_NUM_BFILE,
            ORA_TYPE_NUM_BINARY_DOUBLE, ORA_TYPE_NUM_BINARY_FLOAT, ORA_TYPE_NUM_BINARY_INTEGER,
            ORA_TYPE_NUM_BLOB, ORA_TYPE_NUM_BOOLEAN, ORA_TYPE_NUM_CHAR, ORA_TYPE_NUM_CLOB,
            ORA_TYPE_NUM_CURSOR, ORA_TYPE_NUM_DATE, ORA_TYPE_NUM_INTERVAL_DS,
            ORA_TYPE_NUM_INTERVAL_YM, ORA_TYPE_NUM_JSON, ORA_TYPE_NUM_LONG, ORA_TYPE_NUM_LONG_RAW,
            ORA_TYPE_NUM_NUMBER, ORA_TYPE_NUM_OBJECT, ORA_TYPE_NUM_RAW, ORA_TYPE_NUM_ROWID,
            ORA_TYPE_NUM_TIMESTAMP, ORA_TYPE_NUM_TIMESTAMP_LTZ, ORA_TYPE_NUM_TIMESTAMP_TZ,
            ORA_TYPE_NUM_UROWID, ORA_TYPE_NUM_VARCHAR, ORA_TYPE_NUM_VECTOR, QueryResult,
            QueryValue, decode_lob_text,
        },
        vector::{Vector, VectorValues},
    };
    use serde_json::{Number, Value, json};
    use std::fmt::Display;
    use std::future::Future;
    use std::path::PathBuf;
    use std::sync::Mutex as SyncMutex;
    use std::time::Duration;

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

    pub(super) async fn connect(
        cx: &Cx,
        opts: OracleConnectOptions,
    ) -> Result<RustOracleConnection, DbError> {
        let mut inner = oracledb::Connection::connect(cx, to_connect_options(&opts)?)
            .await
            .map_err(|err| connect_error_to_db_error(&err, &opts))?;
        apply_session_identity(cx, &mut inner, opts.session_identity.as_ref(), &opts).await?;
        for stmt in crate::serialize::canonical_nls_statements() {
            execute_raw(cx, &mut inner, stmt, &[], &opts, "connect").await?;
        }
        for stmt in &opts.session_statements {
            execute_raw(cx, &mut inner, stmt, &[], &opts, "session setup").await?;
        }
        let call_timeout = opts.call_timeout;
        Ok(RustOracleConnection {
            opts,
            inner: AsyncMutex::new(inner),
            call_timeout: SyncMutex::new(call_timeout),
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
    fn transport_is_tcps(connect_string: &str, opts: &OracleConnectOptions) -> bool {
        let compact: String = connect_string
            .chars()
            .filter(|c| !c.is_whitespace())
            .map(|c| c.to_ascii_lowercase())
            .collect();
        compact.starts_with("tcps://")
            || compact.contains("protocol=tcps")
            || opts.wallet_location.is_some()
            || opts.ssl_server_cert_dn.is_some()
    }

    /// The directory whose `tnsnames.ora` resolves a bare connect alias: the
    /// `TNS_ADMIN` environment variable when set, else the profile's wallet
    /// directory (an OCI wallet ships its `tnsnames.ora` alongside `cwallet.sso`).
    ///
    /// Only the *value* of `TNS_ADMIN` is read; the library never mutates it
    /// (that would require `unsafe` `std::env::set_var` under edition 2024, which
    /// is forbidden workspace-wide — see [`OracleConnectOptions::wallet_location`]).
    fn tns_admin_dir(opts: &OracleConnectOptions) -> Option<PathBuf> {
        if let Some(value) = std::env::var_os("TNS_ADMIN") {
            let dir = PathBuf::from(value);
            if !dir.as_os_str().is_empty() {
                return Some(dir);
            }
        }
        opts.wallet_location.clone()
    }

    /// Resolve a bare `tnsnames.ora` alias in `connect_string` to its full
    /// connect descriptor via `TNS_ADMIN` / the wallet directory (B2.3, round-2
    /// OCI-2). A full descriptor, a `scheme://` URL, or any EZConnect form that
    /// carries a `/` service or `:` port is used verbatim. A bare alias resolves
    /// through the profile's TNS directory; a missing/malformed alias yields a
    /// clear, actionable [`DbError::Connect`] rather than a late, opaque driver
    /// failure.
    fn resolve_tns_connect_string(opts: &OracleConnectOptions) -> Result<String, DbError> {
        let raw = opts.connect_string.trim();
        // Descriptors, scheme URLs, and EZConnect host:port/service forms are
        // used as-is — only a bare single-token identifier is an alias candidate.
        if raw.is_empty()
            || raw.starts_with('(')
            || raw.contains("://")
            || raw.contains('/')
            || raw.contains(':')
            || !raw
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        {
            return Ok(opts.connect_string.clone());
        }
        let Some(dir) = tns_admin_dir(opts) else {
            // No TNS directory to resolve against — leave the identifier for the
            // driver (it may still be a valid EZConnect host).
            return Ok(opts.connect_string.clone());
        };
        match crate::tns::resolve_alias(&dir, raw) {
            Ok(Some(descriptor)) => Ok(descriptor),
            // A directory with no tnsnames.ora — nothing to resolve against.
            Ok(None) => Ok(opts.connect_string.clone()),
            Err(err) => Err(DbError::Connect(err.to_string())),
        }
    }

    fn format_transport_connect_timeout(timeout: Duration) -> String {
        if timeout.subsec_millis() == 0 {
            timeout.as_secs().max(1).to_string()
        } else {
            format!("{}ms", timeout.as_millis().max(1))
        }
    }

    fn connect_string_with_transport_timeout(
        connect_string: &str,
        timeout: Option<Duration>,
    ) -> Result<String, DbError> {
        let Some(timeout) = timeout.filter(|timeout| !timeout.is_zero()) else {
            return Ok(connect_string.to_owned());
        };
        if connect_string.trim_start().starts_with('(') {
            return Err(DbError::UnsupportedAuth(
                "connect_timeout_seconds cannot be injected into a full Oracle Net descriptor; \
                 set TRANSPORT_CONNECT_TIMEOUT inside the descriptor instead"
                    .to_owned(),
            ));
        }
        let lower = connect_string.to_ascii_lowercase();
        if lower.contains("transport_connect_timeout=") || lower.contains("tcp_connect_timeout=") {
            return Err(DbError::UnsupportedAuth(
                "connect_timeout_seconds conflicts with an existing transport_connect_timeout \
                 value in connect_string; configure it in only one place"
                    .to_owned(),
            ));
        }
        let separator = if connect_string.contains('?') {
            '&'
        } else {
            '?'
        };
        Ok(format!(
            "{}{}transport_connect_timeout={}",
            connect_string,
            separator,
            format_transport_connect_timeout(timeout)
        ))
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
        // Resolve a bare tnsnames.ora alias to its full descriptor up front
        // (B2.3): the driver treats an unresolved alias as "resolve separately",
        // so a bare alias would otherwise fail late. Doing it here also lets the
        // TCPS transport check below see the resolved (possibly `PROTOCOL=TCPS`)
        // descriptor.
        let resolved_connect_string = resolve_tns_connect_string(opts)?;
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
        if iam_token.is_some() && !transport_is_tcps(&resolved_connect_string, opts) {
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
        let connect_string =
            connect_string_with_transport_timeout(&resolved_connect_string, opts.connect_timeout)?;
        let mut connect_options =
            oracledb::ConnectOptions::new(&connect_string, user, password, identity);
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

    async fn apply_session_identity(
        cx: &Cx,
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
                cx,
                inner,
                "BEGIN DBMS_APPLICATION_INFO.SET_MODULE(:1, :2); END;",
                &[
                    BindValue::Text(module.to_owned()),
                    BindValue::Text(action.to_owned()),
                ],
                opts,
                "session identity",
            )
            .await?;
        } else if let Some(action) = identity.action.as_deref() {
            execute_raw(
                cx,
                inner,
                "BEGIN DBMS_APPLICATION_INFO.SET_ACTION(:1); END;",
                &[BindValue::Text(action.to_owned())],
                opts,
                "session identity",
            )
            .await?;
        }
        if let Some(client_identifier) = identity.client_identifier.as_deref() {
            execute_raw(
                cx,
                inner,
                "BEGIN DBMS_SESSION.SET_IDENTIFIER(:1); END;",
                &[BindValue::Text(client_identifier.to_owned())],
                opts,
                "session identity",
            )
            .await?;
        }
        if let Some(client_info) = identity.client_info.as_deref() {
            execute_raw(
                cx,
                inner,
                "BEGIN DBMS_APPLICATION_INFO.SET_CLIENT_INFO(:1); END;",
                &[BindValue::Text(client_info.to_owned())],
                opts,
                "session identity",
            )
            .await?;
        }
        Ok(())
    }

    fn to_bind(bind: &OracleBind) -> BindValue {
        oracle_bind_to_driver(bind)
    }

    async fn execute_raw(
        cx: &Cx,
        inner: &mut oracledb::Connection,
        sql: &str,
        binds: &[BindValue],
        opts: &OracleConnectOptions,
        context: &'static str,
    ) -> Result<QueryResult, DbError> {
        // oracledb 0.5.x removed the 0.2.2 `execute_query_with_binds` family;
        // `Connection::execute_raw` is the retained low-level entry that returns the
        // same `QueryResult` and composes with the fetch primitives below. `bind_rows`
        // is positional array DML — one inner row applies our binds in a single round
        // trip, and an empty slice runs `sql` once with no binds.
        let bind_rows: Vec<Vec<BindValue>> = if binds.is_empty() {
            Vec::new()
        } else {
            vec![binds.to_vec()]
        };
        inner
            .execute_raw(cx, sql, 0, &bind_rows, ExecuteOptions::default(), None)
            .await
            .map_err(|err| {
                DbError::Execute(format!("{context}: {}", sanitize_driver_error(err, opts)))
            })
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_with_timeout(
        cx: &Cx,
        inner: &mut oracledb::Connection,
        sql: &str,
        prefetch_rows: u32,
        binds: &[BindValue],
        timeout_ms: Option<u32>,
        opts: &OracleConnectOptions,
        context: &'static str,
    ) -> Result<QueryResult, DbError> {
        let bind_rows: Vec<Vec<BindValue>> = if binds.is_empty() {
            Vec::new()
        } else {
            vec![binds.to_vec()]
        };
        inner
            .execute_raw(
                cx,
                sql,
                prefetch_rows,
                &bind_rows,
                ExecuteOptions::default(),
                timeout_ms,
            )
            .await
            .map_err(|err| {
                DbError::Query(format!("{context}: {}", sanitize_driver_error(err, opts)))
            })
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

    fn output_value_entry(result: &QueryResult, bind_index: usize) -> Option<Option<&QueryValue>> {
        result
            .out_values
            .iter()
            .find_map(|(index, value)| (*index == bind_index).then_some(value.as_ref()))
    }

    pub(super) fn ordered_routine_out_values(
        result: &QueryResult,
        args: &[OracleRoutineArg],
    ) -> Result<Vec<Option<QueryValue>>, DbError> {
        args.iter()
            .enumerate()
            .filter_map(|(index, arg)| arg.is_output_bind().then_some(index))
            .map(|index| {
                output_value_entry(result, index)
                    .map(|value| value.cloned())
                    .ok_or_else(|| {
                        DbError::Execute(format!(
                            "routine OUT bind at position {} was not returned by the driver",
                            index + 1
                        ))
                    })
            })
            .collect()
    }

    fn routine_arg_metadata(index: usize, arg: &OracleRoutineArg) -> ColumnMetadata {
        let name = format!("OUT_{}", index + 1);
        match &arg.bind {
            BindValue::Output {
                ora_type_num,
                csfrm,
                buffer_size,
            }
            | BindValue::ReturnOutput {
                ora_type_num,
                csfrm,
                buffer_size,
            } => ColumnMetadata::new(name, *ora_type_num)
                .with_csfrm(*csfrm)
                .with_buffer_size(*buffer_size)
                .with_max_size(*buffer_size),
            BindValue::ObjectOutput {
                schema,
                type_name,
                buffer_size,
                ..
            } => ColumnMetadata::new(name, ORA_TYPE_NUM_OBJECT)
                .with_csfrm(CS_FORM_IMPLICIT)
                .with_buffer_size(*buffer_size)
                .with_max_size(*buffer_size)
                .with_object_schema(Some(schema.clone()))
                .with_object_type_name(Some(type_name.clone())),
            other => unreachable!(
                "OracleRoutineArg must wrap only output bind variants, got {}",
                other.variant_name()
            ),
        }
    }

    async fn routine_out_binds(
        cx: &Cx,
        inner: &mut oracledb::Connection,
        result: &QueryResult,
        args: &[OracleRoutineArg],
        opts: &OracleConnectOptions,
        serialize_opts: &SerializeOptions,
        timeout_ms: Option<u32>,
    ) -> Result<Vec<OracleCell>, DbError> {
        let output_args: Vec<(usize, &OracleRoutineArg)> = args
            .iter()
            .enumerate()
            .filter(|(_, arg)| arg.is_output_bind())
            .collect();
        let ordered = ordered_routine_out_values(result, args)?;
        let mut out = Vec::with_capacity(output_args.len());
        for ((index, arg), value) in output_args.into_iter().zip(ordered) {
            let metadata = routine_arg_metadata(index, arg);
            out.push(
                value_to_cell(
                    cx,
                    inner,
                    &metadata,
                    value,
                    opts,
                    serialize_opts,
                    timeout_ms,
                    0,
                )
                .await?,
            );
        }
        Ok(out)
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

    async fn collect_all_rows(
        cx: &Cx,
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
            let fetch_result = bounded_fetch_batch(
                timeout_ms,
                inner.define_and_fetch_rows_with_columns(
                    cx,
                    cursor_id,
                    FETCH_BATCH_ROWS,
                    &columns,
                    None,
                ),
            )
            .await;
            let fetched = match resolve_fetch_batch(cx, inner, fetch_result, opts).await {
                Ok(fetched) => fetched,
                Err(err) => {
                    inner.release_cursor(cursor_id);
                    return Err(err);
                }
            };
            if !fetched.columns.is_empty() {
                columns = fetched.columns.clone();
            }
            previous_row = fetched.rows.last().cloned();
            rows.extend(fetched.rows);
            result.more_rows = fetched.more_rows;
        }
        while has_parent_result && result.more_rows && cursor_id != 0 {
            let fetch_result = if columns_require_define(&columns) {
                bounded_fetch_batch(
                    timeout_ms,
                    inner.define_and_fetch_rows_with_columns(
                        cx,
                        cursor_id,
                        FETCH_BATCH_ROWS,
                        &columns,
                        previous_row.as_deref(),
                    ),
                )
                .await
            } else {
                bounded_fetch_batch(
                    timeout_ms,
                    inner.fetch_rows_with_columns(
                        cx,
                        cursor_id,
                        FETCH_BATCH_ROWS,
                        &columns,
                        previous_row.as_deref(),
                    ),
                )
                .await
            };
            let fetched = match resolve_fetch_batch(cx, inner, fetch_result, opts).await {
                Ok(fetched) => fetched,
                Err(err) => {
                    inner.release_cursor(cursor_id);
                    return Err(err);
                }
            };
            if !fetched.columns.is_empty() {
                columns = fetched.columns.clone();
            }
            previous_row = fetched.rows.last().cloned();
            rows.extend(fetched.rows);
            result.more_rows = fetched.more_rows;
        }
        let mut converted = rows_to_oracle_rows(
            cx,
            inner,
            &columns,
            rows,
            opts,
            serialize_opts,
            timeout_ms,
            0,
        )
        .await?;
        if let Some(implicit_resultsets) = implicit_resultsets
            && let Some(row) = implicit_resultsets_to_row(
                cx,
                inner,
                implicit_resultsets,
                opts,
                serialize_opts,
                timeout_ms,
            )
            .await?
        {
            converted.push(row);
        }
        if cursor_id != 0 {
            inner.release_cursor(cursor_id);
        }
        Ok(converted)
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum FetchBatchError<E> {
        Driver(E),
        Timeout(u32),
    }

    pub(super) async fn bounded_fetch_batch<T, E, Fut>(
        timeout_ms: Option<u32>,
        future: Fut,
    ) -> Result<T, FetchBatchError<E>>
    where
        Fut: Future<Output = Result<T, E>>,
    {
        let Some(timeout_ms) = timeout_ms.filter(|value| *value > 0) else {
            return future.await.map_err(FetchBatchError::Driver);
        };
        match asupersync::time::timeout(
            asupersync::time::wall_now(),
            Duration::from_millis(u64::from(timeout_ms)),
            future,
        )
        .await
        {
            Ok(result) => result.map_err(FetchBatchError::Driver),
            Err(_) => Err(FetchBatchError::Timeout(timeout_ms)),
        }
    }

    async fn resolve_fetch_batch<T>(
        cx: &Cx,
        inner: &mut oracledb::Connection,
        result: Result<T, FetchBatchError<oracledb::Error>>,
        opts: &OracleConnectOptions,
    ) -> Result<T, DbError> {
        match result {
            Ok(value) => Ok(value),
            Err(FetchBatchError::Driver(err)) => {
                Err(DbError::Query(sanitize_driver_error(err, opts)))
            }
            Err(FetchBatchError::Timeout(timeout_ms)) => match inner.cancel(cx).await {
                Ok(()) => Err(fetch_batch_call_timeout(timeout_ms)),
                // Recovery cancel failed: the session is definitively dirty. Use
                // the structurally-uncertain `Cancelled` variant so quarantine
                // never rides on message-text matching.
                Err(err) => Err(DbError::Cancelled(format!(
                    "fetch loop: call timeout of {timeout_ms} ms exceeded; recovery failed: {}",
                    sanitize_driver_error(err, opts)
                ))),
            },
        }
    }

    /// A per-batch call timeout in the fetch loop. After the timeout we issue an
    /// out-of-band `cancel` to the driver, which leaves the session in an
    /// **uncertain** state (a cursor may be partially drained). Return the
    /// structural [`DbError::Cancelled`] variant — `is_uncertain_session_state`
    /// then flags it fail-closed from the error *kind*, never from the message
    /// wording, so editing this literal can never silently un-quarantine a
    /// mid-timeout session.
    pub(super) fn fetch_batch_call_timeout(timeout_ms: u32) -> DbError {
        DbError::Cancelled(format!(
            "fetch loop: call timeout of {timeout_ms} ms exceeded"
        ))
    }

    fn columns_require_define(columns: &[ColumnMetadata]) -> bool {
        columns.iter().any(|column| {
            matches!(
                column.ora_type_num(),
                ORA_TYPE_NUM_CLOB | ORA_TYPE_NUM_BLOB | ORA_TYPE_NUM_VECTOR | ORA_TYPE_NUM_JSON
            )
        })
    }

    // Async recursion (cursor cells nest result sets) is boxed to keep the
    // future `Sized`.
    #[allow(clippy::too_many_arguments)]
    fn rows_to_oracle_rows<'a>(
        cx: &'a Cx,
        inner: &'a mut oracledb::Connection,
        columns: &'a [ColumnMetadata],
        rows: Vec<Vec<Option<QueryValue>>>,
        opts: &'a OracleConnectOptions,
        serialize_opts: &'a SerializeOptions,
        timeout_ms: Option<u32>,
        depth: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<OracleRow>, DbError>> + 'a>>
    {
        Box::pin(async move {
            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                let mut cells = Vec::with_capacity(columns.len());
                for (idx, meta) in columns.iter().enumerate() {
                    let value = row.get(idx).cloned().flatten();
                    cells.push((
                        meta.name().to_owned(),
                        value_to_cell(
                            cx,
                            inner,
                            meta,
                            value,
                            opts,
                            serialize_opts,
                            timeout_ms,
                            depth,
                        )
                        .await?,
                    ));
                }
                out.push(OracleRow { columns: cells });
            }
            Ok(out)
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn value_to_cell<'a>(
        cx: &'a Cx,
        inner: &'a mut oracledb::Connection,
        meta: &'a ColumnMetadata,
        value: Option<QueryValue>,
        opts: &'a OracleConnectOptions,
        serialize_opts: &'a SerializeOptions,
        timeout_ms: Option<u32>,
        depth: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<OracleCell, DbError>> + 'a>>
    {
        Box::pin(async move {
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
                Some(QueryValue::TimestampTz {
                    year,
                    month,
                    day,
                    hour,
                    minute,
                    second,
                    nanosecond,
                    offset_minutes,
                }) => OracleCell::new(
                    oracle_type,
                    Some(format_timestamp_tz(
                        year,
                        month,
                        day,
                        hour,
                        minute,
                        second,
                        nanosecond,
                        offset_minutes,
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
                        cx,
                        inner,
                        oracle_type,
                        &cursor,
                        opts,
                        serialize_opts,
                        timeout_ms,
                        depth,
                    )
                    .await;
                }
                Some(QueryValue::Object(value)) => {
                    OracleCell::structured(oracle_type, structured_object_marker(&value))
                }
                Some(QueryValue::Lob(value)) => {
                    let limits = LobReadLimits::from(serialize_opts);
                    // The native-async LOB read happens HERE, before the pure
                    // `materialize_lob_cell` runs: `read_lob_plan` computes the one
                    // `(offset, amount)` the materializer would have requested, we
                    // read it on the async driver once, and hand the materializer a
                    // sync closure that just replays the captured bytes. This keeps
                    // `materialize_lob_cell` (and its unit tests) callback-shaped
                    // and pure while the actual round trip is `.await`-ed.
                    let prefetched = match read_lob_plan(&value, limits) {
                        Some((offset, amount)) => inner
                            .read_lob_with_timeout(cx, &value.locator, offset, amount, timeout_ms)
                            .await
                            .map(|result| result.data.unwrap_or_default())
                            .map_err(|err| {
                                DbError::Query(format!(
                                    "LOB locator read failed: {}",
                                    sanitize_driver_error(err, opts)
                                ))
                            })?,
                        None => Vec::new(),
                    };
                    let mut read_lob = |_locator: &[u8], _offset: u64, _amount: u64| {
                        Ok(LobReadData {
                            data: Some(prefetched.clone()),
                        })
                    };
                    return materialize_lob_cell(oracle_type, &value, limits, &mut read_lob);
                }
                Some(QueryValue::Vector(value)) => OracleCell::structured(
                    oracle_type,
                    structured_vector_with_caps(&value, serialize_opts.structured_decode_caps),
                ),
                Some(QueryValue::Json(value)) => OracleCell::structured(
                    oracle_type,
                    structured_json_value(&value, serialize_opts.structured_decode_caps),
                ),
                Some(QueryValue::Array(values)) => OracleCell::structured(
                    oracle_type,
                    structured_array_with_caps(&values, serialize_opts.structured_decode_caps),
                ),
                // `QueryValue` is `#[non_exhaustive]` as of oracledb 0.5.x. Every wire
                // value kind that exists today is handled explicitly above; this arm
                // fails SAFE on any future kind with a clearly-marked, non-silent
                // placeholder — never a silent wrong value (cf. the NUMBER→string
                // invariant). Unreachable against the current driver.
                Some(value) => OracleCell::structured(
                    oracle_type,
                    structured_query_value_with_caps(&value, serialize_opts.structured_decode_caps),
                ),
            };
            Ok(cell)
        })
    }

    #[derive(Clone, Copy, Debug)]
    struct StructuredDecodeBudget {
        caps: StructuredDecodeCaps,
        cells: usize,
    }

    impl StructuredDecodeBudget {
        fn new(caps: StructuredDecodeCaps) -> Self {
            Self { caps, cells: 0 }
        }

        fn enter(&mut self, kind: &str, depth: usize) -> Result<(), Value> {
            if depth > self.caps.max_depth {
                return Err(structured_decode_cap_marker(
                    kind,
                    "depth",
                    self.caps.max_depth,
                ));
            }
            if self.cells >= self.caps.max_cells {
                return Err(structured_decode_cap_marker(
                    kind,
                    "cell",
                    self.caps.max_cells,
                ));
            }
            self.cells += 1;
            Ok(())
        }

        fn reserve_cells(&mut self, kind: &str, additional: usize) -> Result<(), Value> {
            if additional > self.caps.max_cells.saturating_sub(self.cells) {
                return Err(structured_decode_cap_marker(
                    kind,
                    "cell",
                    self.caps.max_cells,
                ));
            }
            self.cells += additional;
            Ok(())
        }

        fn check_rows(&self, kind: &str, rows: usize) -> Result<(), Value> {
            if rows > self.caps.max_rows {
                Err(structured_decode_cap_marker(
                    kind,
                    "row",
                    self.caps.max_rows,
                ))
            } else {
                Ok(())
            }
        }

        fn check_bytes(&self, kind: &str, value: Value) -> Value {
            if json_byte_len(&value) > self.caps.max_bytes {
                structured_decode_cap_marker(kind, "byte", self.caps.max_bytes)
            } else {
                value
            }
        }

        fn check_raw_bytes(&self, kind: &str, byte_len: usize) -> Result<(), Value> {
            if byte_len > self.caps.max_bytes {
                Err(structured_decode_cap_marker(
                    kind,
                    "byte",
                    self.caps.max_bytes,
                ))
            } else {
                Ok(())
            }
        }
    }

    #[cfg(test)]
    fn structured_array(values: &[Option<QueryValue>]) -> Value {
        structured_array_with_caps(values, StructuredDecodeCaps::DEFAULT)
    }

    fn structured_array_with_caps(
        values: &[Option<QueryValue>],
        caps: StructuredDecodeCaps,
    ) -> Value {
        let mut budget = StructuredDecodeBudget::new(caps);
        structured_array_with_budget(values, &mut budget, 0)
    }

    fn structured_array_with_budget(
        values: &[Option<QueryValue>],
        budget: &mut StructuredDecodeBudget,
        depth: usize,
    ) -> Value {
        if let Err(marker) = budget.enter("Array", depth) {
            return marker;
        }
        if let Err(marker) = budget.check_rows("Array", values.len()) {
            return marker;
        }
        let value = json!({
            "kind": "array",
            "items": values
                .iter()
                .map(|value| structured_optional_query_value_with_budget(value.as_ref(), budget, depth + 1))
                .collect::<Vec<_>>()
        });
        budget.check_bytes("Array", value)
    }

    fn structured_optional_query_value_with_budget(
        value: Option<&QueryValue>,
        budget: &mut StructuredDecodeBudget,
        depth: usize,
    ) -> Value {
        value.map_or(Value::Null, |value| {
            structured_query_value_with_budget(value, budget, depth)
        })
    }

    fn structured_query_value_with_caps(value: &QueryValue, caps: StructuredDecodeCaps) -> Value {
        let mut budget = StructuredDecodeBudget::new(caps);
        structured_query_value_with_budget(value, &mut budget, 0)
    }

    fn structured_query_value_with_budget(
        value: &QueryValue,
        budget: &mut StructuredDecodeBudget,
        depth: usize,
    ) -> Value {
        match value {
            QueryValue::Text(text) => {
                if let Err(marker) = budget.enter("Text", depth) {
                    return marker;
                }
                if let Err(marker) = budget.check_raw_bytes("Text", text.len()) {
                    return marker;
                }
                budget.check_bytes("Text", json!({ "kind": "text", "value": text }))
            }
            QueryValue::TextRaw { bytes, csfrm } => {
                if let Err(marker) = budget.enter("TextRaw", depth) {
                    return marker;
                }
                if let Err(marker) = budget.check_raw_bytes("TextRaw", bytes.len()) {
                    return marker;
                }
                budget.check_bytes(
                    "TextRaw",
                    json!({
                        "kind": "text_raw",
                        "encoding": "hex",
                        "data": hex_encode(bytes),
                        "byte_length": bytes.len(),
                        "csfrm": csfrm
                    }),
                )
            }
            QueryValue::Raw(bytes) => {
                if let Err(marker) = budget.enter("Raw", depth) {
                    return marker;
                }
                if let Err(marker) = budget.check_raw_bytes("Raw", bytes.len()) {
                    return marker;
                }
                budget.check_bytes(
                    "Raw",
                    json!({
                        "kind": "raw",
                        "encoding": "hex",
                        "data": hex_encode(bytes),
                        "byte_length": bytes.len()
                    }),
                )
            }
            QueryValue::Rowid(text) => {
                if let Err(marker) = budget.enter("Rowid", depth) {
                    return marker;
                }
                if let Err(marker) = budget.check_raw_bytes("Rowid", text.len()) {
                    return marker;
                }
                budget.check_bytes("Rowid", json!({ "kind": "rowid", "value": text }))
            }
            QueryValue::BinaryDouble(text) => {
                if let Err(marker) = budget.enter("BinaryDouble", depth) {
                    return marker;
                }
                if let Err(marker) = budget.check_raw_bytes("BinaryDouble", text.len()) {
                    return marker;
                }
                budget.check_bytes(
                    "BinaryDouble",
                    json!({ "kind": "binary_double", "value": text }),
                )
            }
            QueryValue::IntervalDS {
                days,
                hours,
                minutes,
                seconds,
                fseconds,
            } => {
                if let Err(marker) = budget.enter("IntervalDS", depth) {
                    return marker;
                }
                budget.check_bytes(
                    "IntervalDS",
                    json!({
                        "kind": "interval_ds",
                        "value": format!("{days} {hours:02}:{minutes:02}:{seconds:02}.{fseconds:09}"),
                        "days": days,
                        "hours": hours,
                        "minutes": minutes,
                        "seconds": seconds,
                        "fseconds": fseconds
                    }),
                )
            }
            QueryValue::IntervalYM { years, months } => {
                if let Err(marker) = budget.enter("IntervalYM", depth) {
                    return marker;
                }
                budget.check_bytes(
                    "IntervalYM",
                    json!({
                        "kind": "interval_ym",
                        "value": format!("{years}-{months}"),
                        "years": years,
                        "months": months
                    }),
                )
            }
            QueryValue::Number(number) => {
                if let Err(marker) = budget.enter("Number", depth) {
                    return marker;
                }
                budget.check_bytes(
                    "Number",
                    json!({ "kind": "number", "value": number.to_canonical_string() }),
                )
            }
            QueryValue::Boolean(value) => {
                if let Err(marker) = budget.enter("Boolean", depth) {
                    return marker;
                }
                budget.check_bytes("Boolean", json!({ "kind": "boolean", "value": value }))
            }
            QueryValue::DateTime {
                year,
                month,
                day,
                hour,
                minute,
                second,
                nanosecond,
            } => {
                if let Err(marker) = budget.enter("DateTime", depth) {
                    return marker;
                }
                budget.check_bytes(
                    "DateTime",
                    json!({
                        "kind": "datetime",
                        "value": format_datetime(
                            *year,
                            *month,
                            *day,
                            *hour,
                            *minute,
                            *second,
                            *nanosecond
                        ),
                        "year": year,
                        "month": month,
                        "day": day,
                        "hour": hour,
                        "minute": minute,
                        "second": second,
                        "nanosecond": nanosecond
                    }),
                )
            }
            QueryValue::TimestampTz {
                year,
                month,
                day,
                hour,
                minute,
                second,
                nanosecond,
                offset_minutes,
            } => {
                if let Err(marker) = budget.enter("TimestampTz", depth) {
                    return marker;
                }
                budget.check_bytes(
                    "TimestampTz",
                    json!({
                        "kind": "timestamp_tz",
                        "value": format_timestamp_tz(
                            *year,
                            *month,
                            *day,
                            *hour,
                            *minute,
                            *second,
                            *nanosecond,
                            *offset_minutes
                        ),
                        "year": year,
                        "month": month,
                        "day": day,
                        "hour": hour,
                        "minute": minute,
                        "second": second,
                        "nanosecond": nanosecond,
                        "offset_minutes": offset_minutes
                    }),
                )
            }
            QueryValue::Vector(vector) => structured_vector_with_budget(vector, budget, depth),
            QueryValue::Json(value) => {
                if let Err(marker) = budget.enter("Json", depth) {
                    return marker;
                }
                let decoded = structured_oson_value_with_budget(value, budget, depth + 1);
                budget.check_bytes("Json", json!({ "kind": "json", "value": decoded }))
            }
            QueryValue::Array(values) => structured_array_with_budget(values, budget, depth),
            QueryValue::Object(value) => {
                if let Err(marker) = budget.enter("Object", depth) {
                    return marker;
                }
                budget.check_bytes("Object", structured_object_marker(value))
            }
            QueryValue::Cursor(_) | QueryValue::Lob(_) => {
                if let Err(marker) = budget.enter(value.variant_name(), depth) {
                    return marker;
                }
                budget.check_bytes(
                    value.variant_name(),
                    structured_unsupported(value.variant_name()),
                )
            }
            _ => {
                if let Err(marker) = budget.enter(value.variant_name(), depth) {
                    return marker;
                }
                budget.check_bytes(
                    value.variant_name(),
                    structured_unsupported(value.variant_name()),
                )
            }
        }
    }

    fn structured_json_value(value: &OsonValue, caps: StructuredDecodeCaps) -> Value {
        let mut budget = StructuredDecodeBudget::new(caps);
        if let Err(marker) = budget.enter("Json", 0) {
            return marker;
        }
        let decoded = structured_oson_value_with_budget(value, &mut budget, 1);
        budget.check_bytes("Json", json!({ "kind": "json", "value": decoded }))
    }

    #[cfg(test)]
    fn structured_oson_value(value: &OsonValue) -> Value {
        structured_oson_value_with_caps(value, StructuredDecodeCaps::DEFAULT)
    }

    #[cfg(test)]
    fn structured_oson_value_with_caps(value: &OsonValue, caps: StructuredDecodeCaps) -> Value {
        let mut budget = StructuredDecodeBudget::new(caps);
        structured_oson_value_with_budget(value, &mut budget, 0)
    }

    fn structured_oson_value_with_budget(
        value: &OsonValue,
        budget: &mut StructuredDecodeBudget,
        depth: usize,
    ) -> Value {
        match value {
            OsonValue::Null => {
                if let Err(marker) = budget.enter("Null", depth) {
                    return marker;
                }
                budget.check_bytes("Null", json!({ "kind": "null" }))
            }
            OsonValue::Bool(value) => {
                if let Err(marker) = budget.enter("Boolean", depth) {
                    return marker;
                }
                budget.check_bytes("Boolean", json!({ "kind": "boolean", "value": value }))
            }
            OsonValue::Number(text) => {
                if let Err(marker) = budget.enter("Number", depth) {
                    return marker;
                }
                if let Err(marker) = budget.check_raw_bytes("Number", text.len()) {
                    return marker;
                }
                budget.check_bytes("Number", json!({ "kind": "number", "value": text }))
            }
            OsonValue::BinaryFloat(value) => {
                if let Err(marker) = budget.enter("BinaryFloat", depth) {
                    return marker;
                }
                budget.check_bytes(
                    "BinaryFloat",
                    json!({ "kind": "binary_float", "value": json_number_or_string(f64::from(*value)) }),
                )
            }
            OsonValue::BinaryDouble(value) => {
                if let Err(marker) = budget.enter("BinaryDouble", depth) {
                    return marker;
                }
                budget.check_bytes(
                    "BinaryDouble",
                    json!({ "kind": "binary_double", "value": json_number_or_string(*value) }),
                )
            }
            OsonValue::String(text) => {
                if let Err(marker) = budget.enter("String", depth) {
                    return marker;
                }
                if let Err(marker) = budget.check_raw_bytes("String", text.len()) {
                    return marker;
                }
                budget.check_bytes("String", json!({ "kind": "string", "value": text }))
            }
            OsonValue::Raw(bytes) => {
                if let Err(marker) = budget.enter("Raw", depth) {
                    return marker;
                }
                if let Err(marker) = budget.check_raw_bytes("Raw", bytes.len()) {
                    return marker;
                }
                budget.check_bytes(
                    "Raw",
                    json!({
                        "kind": "raw",
                        "encoding": "hex",
                        "data": hex_encode(bytes),
                        "byte_length": bytes.len()
                    }),
                )
            }
            OsonValue::DateTime {
                year,
                month,
                day,
                hour,
                minute,
                second,
                nanosecond,
            } => {
                if let Err(marker) = budget.enter("DateTime", depth) {
                    return marker;
                }
                budget.check_bytes(
                    "DateTime",
                    json!({
                        "kind": "datetime",
                        "value": format_datetime(
                            *year,
                            *month,
                            *day,
                            *hour,
                            *minute,
                            *second,
                            *nanosecond
                        ),
                        "year": year,
                        "month": month,
                        "day": day,
                        "hour": hour,
                        "minute": minute,
                        "second": second,
                        "nanosecond": nanosecond
                    }),
                )
            }
            OsonValue::IntervalDS {
                days,
                hours,
                minutes,
                seconds,
                fseconds,
            } => {
                if let Err(marker) = budget.enter("IntervalDS", depth) {
                    return marker;
                }
                budget.check_bytes(
                    "IntervalDS",
                    json!({
                        "kind": "interval_ds",
                        "value": format!("P{days}DT{hours}H{minutes}M{seconds}.{fseconds:09}S"),
                        "days": days,
                        "hours": hours,
                        "minutes": minutes,
                        "seconds": seconds,
                        "fseconds": fseconds
                    }),
                )
            }
            OsonValue::Vector(vector) => structured_vector_with_budget(vector, budget, depth),
            OsonValue::Array(items) => {
                if let Err(marker) = budget.enter("Array", depth) {
                    return marker;
                }
                if let Err(marker) = budget.check_rows("Array", items.len()) {
                    return marker;
                }
                let value = json!({
                    "kind": "array",
                    "items": items
                        .iter()
                        .map(|value| structured_oson_value_with_budget(value, budget, depth + 1))
                        .collect::<Vec<_>>()
                });
                budget.check_bytes("Array", value)
            }
            OsonValue::Object(entries) => {
                if let Err(marker) = budget.enter("Object", depth) {
                    return marker;
                }
                if let Err(marker) = budget.check_rows("Object", entries.len()) {
                    return marker;
                }
                let value = json!({
                    "kind": "object",
                    "entries": entries
                        .iter()
                        .map(|(key, value)| {
                            json!({ "key": key, "value": structured_oson_value_with_budget(value, budget, depth + 1) })
                        })
                        .collect::<Vec<_>>()
                });
                budget.check_bytes("Object", value)
            }
        }
    }

    #[cfg(test)]
    fn structured_vector(vector: &Vector) -> Value {
        let mut budget = StructuredDecodeBudget::new(StructuredDecodeCaps::DEFAULT);
        structured_vector_with_budget(vector, &mut budget, 0)
    }

    fn structured_vector_with_caps(vector: &Vector, caps: StructuredDecodeCaps) -> Value {
        let mut budget = StructuredDecodeBudget::new(caps);
        structured_vector_with_budget(vector, &mut budget, 0)
    }

    fn structured_vector_with_budget(
        vector: &Vector,
        budget: &mut StructuredDecodeBudget,
        depth: usize,
    ) -> Value {
        if let Err(marker) = budget.enter("Vector", depth) {
            return marker;
        }
        if let Err(marker) = budget.reserve_cells("Vector", vector_value_count(vector)) {
            return marker;
        }
        let value = match vector {
            Vector::Dense(values) => {
                let (format, values) = structured_vector_values(values);
                json!({
                    "kind": "vector",
                    "storage": "dense",
                    "format": format,
                    "values": values
                })
            }
            Vector::Sparse {
                num_dimensions,
                indices,
                values,
            } => {
                let (format, values) = structured_vector_values(values);
                json!({
                    "kind": "vector",
                    "storage": "sparse",
                    "format": format,
                    "num_dimensions": num_dimensions,
                    "indices": indices,
                    "values": values
                })
            }
        };
        budget.check_bytes("Vector", value)
    }

    fn vector_value_count(vector: &Vector) -> usize {
        match vector {
            Vector::Dense(values) | Vector::Sparse { values, .. } => match values {
                VectorValues::Float32(values) => values.len(),
                VectorValues::Float64(values) => values.len(),
                VectorValues::Int8(values) => values.len(),
                VectorValues::Binary(values) => values.len(),
            },
        }
    }

    fn structured_decode_cap_marker(kind: &str, cap: &str, limit: usize) -> Value {
        json!({
            "kind": "unsupported",
            "unsupported": "oracle_value",
            "oracle_value_kind": kind,
            "value": null,
            "warning": format!(
                "Oracle value exceeded structured {cap} decode cap ({limit}); set deep_decode=true or lower selectivity to inspect more"
            )
        })
    }

    fn structured_vector_values(values: &VectorValues) -> (&'static str, Value) {
        match values {
            VectorValues::Float32(values) => (
                "float32",
                Value::Array(
                    values
                        .iter()
                        .map(|value| json_number_or_string(f64::from(*value)))
                        .collect(),
                ),
            ),
            VectorValues::Float64(values) => (
                "float64",
                Value::Array(
                    values
                        .iter()
                        .map(|value| json_number_or_string(*value))
                        .collect(),
                ),
            ),
            VectorValues::Int8(values) => (
                "int8",
                Value::Array(values.iter().map(|value| json!(*value)).collect()),
            ),
            VectorValues::Binary(values) => (
                "binary",
                Value::Array(values.iter().map(|value| json!(*value)).collect()),
            ),
        }
    }

    fn structured_unsupported(kind: &str) -> Value {
        json!({
            "kind": "unsupported",
            "unsupported": "oracle_value",
            "oracle_value_kind": kind,
            "value": null,
            "warning": "Oracle value kind is not structurally serialized yet"
        })
    }

    fn structured_object_marker(value: &ObjectValue) -> Value {
        json!({
            "kind": "unsupported",
            "unsupported": "oracle_object",
            "oracle_value_kind": "Object",
            "schema": value.schema.as_deref(),
            "type_name": value.type_name.as_deref(),
            "packed_byte_length": value.packed_data.len(),
            "value": null,
            "warning": "Oracle object/UDT values are not decoded by default"
        })
    }

    fn json_number_or_string(value: f64) -> Value {
        Number::from_f64(value).map_or_else(|| Value::String(value.to_string()), Value::Number)
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    fn implicit_resultsets_to_row<'a>(
        cx: &'a Cx,
        inner: &'a mut oracledb::Connection,
        values: Vec<QueryValue>,
        opts: &'a OracleConnectOptions,
        serialize_opts: &'a SerializeOptions,
        timeout_ms: Option<u32>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Option<OracleRow>, DbError>> + 'a>>
    {
        Box::pin(async move {
            let mut columns = Vec::with_capacity(values.len());
            for (idx, value) in values.into_iter().enumerate() {
                let name = format!("IMPLICIT_RESULT_{}", idx + 1);
                let cell = match value {
                    QueryValue::Cursor(cursor) => {
                        materialize_cursor_cell(
                            cx,
                            inner,
                            "REF CURSOR".to_owned(),
                            &cursor,
                            opts,
                            serialize_opts,
                            timeout_ms,
                            0,
                        )
                        .await?
                    }
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
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn materialize_cursor_cell<'a>(
        cx: &'a Cx,
        inner: &'a mut oracledb::Connection,
        oracle_type: String,
        cursor: &'a CursorValue,
        opts: &'a OracleConnectOptions,
        serialize_opts: &'a SerializeOptions,
        timeout_ms: Option<u32>,
        depth: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<OracleCell, DbError>> + 'a>>
    {
        Box::pin(async move {
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
            let result = match inner.fetch_cursor(cx, cursor, fetch_limit).await {
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
                cx,
                inner,
                &columns,
                rows,
                opts,
                serialize_opts,
                timeout_ms,
                depth + 1,
            )
            .await?;
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
        })
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
        columns
            .iter()
            .map(|column| column.name().to_owned())
            .collect()
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

    /// The single `(offset, amount)` the `materialize_lob_cell` family would
    /// request for `lob` under `limits`, or `None` when no read is needed
    /// (amount `0` — an empty LOB). Mirrors the amount logic of
    /// `materialize_text_lob` (CLOB) and `materialize_binary_lob` (BLOB/BFILE)
    /// so the native-async read can be hoisted ahead of the pure materializer.
    fn read_lob_plan(lob: &LobValue, limits: LobReadLimits) -> Option<(u64, u64)> {
        let amount = match lob.ora_type_num {
            ORA_TYPE_NUM_CLOB => known_lob_read_amount(lob.size, limits.max_lob_chars),
            ORA_TYPE_NUM_BLOB => known_lob_read_amount(lob.size, limits.max_blob_bytes),
            ORA_TYPE_NUM_BFILE => unknown_lob_read_amount(limits.max_blob_bytes),
            // Unsupported subtypes never read; `materialize_lob_cell` errors.
            _ => 0,
        };
        (amount != 0).then_some((1, amount))
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
        use oracledb::protocol::{
            oson::OsonValue,
            thin::{CS_FORM_IMPLICIT, ORA_TYPE_NUM_RAW, image_begin, image_finalize},
            vector::{Vector, VectorValues},
        };
        use oracledb::{CollectionElement, ObjectAttribute, ObjectType, decode_object};
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
                    .map(|idx| ColumnMetadata::new(format!("C{idx}"), 0))
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

        #[test]
        fn structured_array_round_trips_nested_values_without_lossy_text() {
            let value = structured_array(&[
                None,
                Some(QueryValue::number_from_text(
                    "99999999999999999999999999999999999999",
                    true,
                )),
                Some(QueryValue::TimestampTz {
                    year: 2026,
                    month: 6,
                    day: 29,
                    hour: 12,
                    minute: 34,
                    second: 56,
                    nanosecond: 987_654_321,
                    offset_minutes: -330,
                }),
                Some(QueryValue::Array(vec![Some(QueryValue::Boolean(true))])),
            ]);
            let expected = json!({
                "kind": "array",
                "items": [
                    null,
                    {
                        "kind": "number",
                        "value": "99999999999999999999999999999999999999"
                    },
                    {
                        "kind": "timestamp_tz",
                        "value": "2026-06-29 12:34:56.987654321 -05:30",
                        "year": 2026,
                        "month": 6,
                        "day": 29,
                        "hour": 12,
                        "minute": 34,
                        "second": 56,
                        "nanosecond": 987654321,
                        "offset_minutes": -330
                    },
                    {
                        "kind": "array",
                        "items": [{ "kind": "boolean", "value": true }]
                    }
                ]
            });

            assert_eq!(value, expected);
            let encoded = serde_json::to_string(&value).expect("structured array serializes");
            let decoded: serde_json::Value =
                serde_json::from_str(&encoded).expect("structured array parses");
            assert_eq!(decoded, expected);
            assert_eq!(
                structured_array(&[]),
                json!({ "kind": "array", "items": [] })
            );
        }

        fn assert_structured_cap_marker(
            value: &Value,
            oracle_value_kind: &str,
            cap: &str,
            limit: usize,
        ) {
            assert_eq!(value["kind"], json!("unsupported"));
            assert_eq!(value["unsupported"], json!("oracle_value"));
            assert_eq!(value["oracle_value_kind"], json!(oracle_value_kind));
            assert_eq!(value["value"], Value::Null);
            let warning = value["warning"]
                .as_str()
                .expect("cap marker warning is text");
            assert!(
                warning.contains(&format!("structured {cap} decode cap ({limit})")),
                "unexpected cap warning: {warning}"
            );
        }

        #[test]
        fn structured_decode_caps_enforce_rows_and_cells_at_boundary() {
            let values = [
                Some(QueryValue::Boolean(true)),
                Some(QueryValue::Boolean(false)),
            ];

            let row_capped =
                structured_array_with_caps(&values, StructuredDecodeCaps::new(1, 10, 1_000, 8));
            assert_structured_cap_marker(&row_capped, "Array", "row", 1);

            let row_exact =
                structured_array_with_caps(&values, StructuredDecodeCaps::new(2, 10, 1_000, 8));
            assert_eq!(row_exact["items"].as_array().expect("array items").len(), 2);

            let cell_capped =
                structured_array_with_caps(&values, StructuredDecodeCaps::new(2, 2, 1_000, 8));
            assert_eq!(
                cell_capped["items"][0],
                json!({ "kind": "boolean", "value": true })
            );
            assert_structured_cap_marker(&cell_capped["items"][1], "Boolean", "cell", 2);

            let cell_exact =
                structured_array_with_caps(&values, StructuredDecodeCaps::new(2, 3, 1_000, 8));
            assert_eq!(
                cell_exact,
                json!({
                    "kind": "array",
                    "items": [
                        { "kind": "boolean", "value": true },
                        { "kind": "boolean", "value": false }
                    ]
                })
            );
        }

        #[test]
        fn structured_decode_caps_enforce_depth_and_bytes_at_boundary() {
            let nested = [Some(QueryValue::Array(vec![Some(QueryValue::Boolean(
                true,
            ))]))];

            let depth_capped =
                structured_array_with_caps(&nested, StructuredDecodeCaps::new(10, 10, 1_000, 1));
            assert_structured_cap_marker(
                &depth_capped["items"][0]["items"][0],
                "Boolean",
                "depth",
                1,
            );

            let depth_exact =
                structured_array_with_caps(&nested, StructuredDecodeCaps::new(10, 10, 1_000, 2));
            assert_eq!(
                depth_exact["items"][0]["items"][0],
                json!({ "kind": "boolean", "value": true })
            );

            let text = OsonValue::String("abcdef".to_owned());
            let full = structured_oson_value_with_caps(
                &text,
                StructuredDecodeCaps::new(10, 10, usize::MAX, 8),
            );
            let full_len = crate::serialize::json_byte_len(&full);
            let byte_capped = structured_oson_value_with_caps(
                &text,
                StructuredDecodeCaps::new(10, 10, full_len - 1, 8),
            );
            assert_structured_cap_marker(&byte_capped, "String", "byte", full_len - 1);

            let byte_exact = structured_oson_value_with_caps(
                &text,
                StructuredDecodeCaps::new(10, 10, full_len, 8),
            );
            assert_eq!(byte_exact, full);
        }

        #[test]
        fn structured_oson_keeps_non_json_scalars_typed() {
            let value = structured_oson_value(&OsonValue::Object(vec![
                (
                    "wide_number".to_owned(),
                    OsonValue::Number("1.234567890123456789".to_owned()),
                ),
                ("raw".to_owned(), OsonValue::Raw(vec![0xde, 0xad])),
                (
                    "when".to_owned(),
                    OsonValue::DateTime {
                        year: 2026,
                        month: 6,
                        day: 30,
                        hour: 21,
                        minute: 24,
                        second: 5,
                        nanosecond: 123_456_789,
                    },
                ),
                (
                    "embedded_vector".to_owned(),
                    OsonValue::Vector(Vector::Dense(VectorValues::Int8(vec![-1, 0, 127]))),
                ),
            ]));

            assert_eq!(
                value,
                json!({
                    "kind": "object",
                    "entries": [
                        {
                            "key": "wide_number",
                            "value": {
                                "kind": "number",
                                "value": "1.234567890123456789"
                            }
                        },
                        {
                            "key": "raw",
                            "value": {
                                "kind": "raw",
                                "encoding": "hex",
                                "data": "dead",
                                "byte_length": 2
                            }
                        },
                        {
                            "key": "when",
                            "value": {
                                "kind": "datetime",
                                "value": "2026-06-30 21:24:05.123456789",
                                "year": 2026,
                                "month": 6,
                                "day": 30,
                                "hour": 21,
                                "minute": 24,
                                "second": 5,
                                "nanosecond": 123456789
                            }
                        },
                        {
                            "key": "embedded_vector",
                            "value": {
                                "kind": "vector",
                                "storage": "dense",
                                "format": "int8",
                                "values": [-1, 0, 127]
                            }
                        }
                    ]
                })
            );
        }

        #[test]
        fn structured_vector_covers_dense_sparse_and_binary_formats() {
            assert_eq!(
                structured_vector(&Vector::Dense(VectorValues::Float32(vec![1.25, -2.5]))),
                json!({
                    "kind": "vector",
                    "storage": "dense",
                    "format": "float32",
                    "values": [1.25, -2.5]
                })
            );
            assert_eq!(
                structured_vector(&Vector::Dense(VectorValues::Float64(vec![3.5, 4.25]))),
                json!({
                    "kind": "vector",
                    "storage": "dense",
                    "format": "float64",
                    "values": [3.5, 4.25]
                })
            );
            assert_eq!(
                structured_vector(&Vector::Dense(VectorValues::Binary(vec![0xaa, 0x55]))),
                json!({
                    "kind": "vector",
                    "storage": "dense",
                    "format": "binary",
                    "values": [170, 85]
                })
            );
            assert_eq!(
                structured_vector(&Vector::Sparse {
                    num_dimensions: 4,
                    indices: vec![0, 3],
                    values: VectorValues::Float64(vec![1.0, -1.5]),
                }),
                json!({
                    "kind": "vector",
                    "storage": "sparse",
                    "format": "float64",
                    "num_dimensions": 4,
                    "indices": [0, 3],
                    "values": [1.0, -1.5]
                })
            );
        }

        #[test]
        fn object_value_marker_preserves_identity_without_packed_bytes() {
            let object = ObjectValue {
                schema: Some("HR".to_owned()),
                type_name: Some("ADDRESS_T".to_owned()),
                packed_data: vec![0xde, 0xad, 0xbe, 0xef],
            };
            let marker = structured_object_marker(&object);
            let expected = json!({
                "kind": "unsupported",
                "unsupported": "oracle_object",
                "oracle_value_kind": "Object",
                "schema": "HR",
                "type_name": "ADDRESS_T",
                "packed_byte_length": 4,
                "value": null,
                "warning": "Oracle object/UDT values are not decoded by default"
            });
            assert_eq!(marker, expected);
            assert!(
                !marker.to_string().contains("deadbeef"),
                "packed object bytes must not be dumped into the public marker"
            );

            let nested = structured_array(&[Some(QueryValue::Object(Box::new(object)))]);
            assert_eq!(nested["items"][0], expected);
        }

        #[test]
        fn decode_object_reports_nested_shapes_as_unsupported_feature() {
            let mut image = image_begin(false);
            image_finalize(&mut image).expect("object image finalizes");
            let value = ObjectValue {
                schema: Some("HR".to_owned()),
                type_name: Some("OUTER_T".to_owned()),
                packed_data: image,
            };
            let object_type = ObjectType {
                schema: "HR".to_owned(),
                name: "OUTER_T".to_owned(),
                attributes: vec![ObjectAttribute {
                    name: "CHILD".to_owned(),
                    type_name: "CHILD_T".to_owned(),
                    type_owner: Some("HR".to_owned()),
                }],
                collection_element: None,
            };
            let err = decode_object(&value, &object_type)
                .expect_err("nested object attributes are intentionally unsupported");
            assert!(
                err.to_string()
                    .contains("nested object/collection attribute is not decodable yet"),
                "unexpected error: {err}"
            );

            let mut image = image_begin(true);
            image_finalize(&mut image).expect("collection image finalizes");
            let value = ObjectValue {
                schema: Some("HR".to_owned()),
                type_name: Some("CHILD_TAB".to_owned()),
                packed_data: image,
            };
            let collection_type = ObjectType {
                schema: "HR".to_owned(),
                name: "CHILD_TAB".to_owned(),
                attributes: Vec::new(),
                collection_element: Some(CollectionElement {
                    type_name: "CHILD_T".to_owned(),
                    type_owner: Some("HR".to_owned()),
                }),
            };
            let err = decode_object(&value, &collection_type)
                .expect_err("nested collection elements are intentionally unsupported");
            assert!(
                err.to_string().contains(
                    "collection of nested object/collection elements is not decodable yet"
                ),
                "unexpected error: {err}"
            );
        }

        #[cfg(feature = "live-xe")]
        #[test]
        fn cursor_fetch_failure_leaves_connection_usable() {
            use asupersync::runtime::RuntimeBuilder;
            let Some(opts) = live_opts_from_env() else {
                eprintln!(
                    "[live-xe] SKIP cursor_fetch_failure_leaves_connection_usable: set ORACLEMCP_TEST_*"
                );
                return;
            };
            // Live test does real socket I/O, so the runtime needs a reactor (release-gre.16).
            let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
            let runtime = RuntimeBuilder::current_thread()
                .with_reactor(reactor)
                .build()
                .expect("current-thread runtime");
            runtime.block_on(async {
                let cx = asupersync::Cx::current().expect("block_on installs a current Cx");
                let mut inner = match oracledb::Connection::connect(
                    &cx,
                    to_connect_options(&opts).expect("connect options"),
                )
                .await
                {
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
                    &cx,
                    &mut inner,
                    "REF CURSOR".to_owned(),
                    &invalid_cursor,
                    &opts,
                    &SerializeOptions::default(),
                    None,
                    0,
                )
                .await
                .expect_err("invalid cursor id should fail");

                assert!(
                    err.to_string().contains("REF CURSOR fetch failed"),
                    "unexpected error: {err}"
                );
                let probe = inner
                    .execute_raw(&cx, "SELECT 1 AS n FROM dual", 1, &[], ExecuteOptions::default(), None)
                    .await
                    .expect("connection remains usable after cursor fetch failure");
                let n = probe.rows[0][0]
                    .as_ref()
                    .and_then(QueryValue::as_i64)
                    .expect("numeric probe cell");
                assert_eq!(n, 1);
            });
        }

        #[cfg(feature = "live-xe")]
        #[test]
        fn live_fetch_loop_is_bounded_per_batch() {
            use asupersync::runtime::RuntimeBuilder;
            let Some(opts) = live_opts_from_env() else {
                eprintln!(
                    "[live-xe] SKIP live_fetch_loop_is_bounded_per_batch: set ORACLEMCP_TEST_*"
                );
                return;
            };
            let reactor = asupersync::runtime::reactor::create_reactor().expect("native reactor");
            let runtime = RuntimeBuilder::current_thread()
                .with_reactor(reactor)
                .build()
                .expect("current-thread runtime");
            runtime.block_on(async {
                let cx = asupersync::Cx::current().expect("block_on installs a current Cx");
                let mut inner = match oracledb::Connection::connect(
                    &cx,
                    to_connect_options(&opts).expect("connect options"),
                )
                .await
                {
                    Ok(conn) => conn,
                    Err(err) => {
                        eprintln!(
                            "[live-xe] SKIP live_fetch_loop_is_bounded_per_batch: no reachable Oracle ({})",
                            sanitize_driver_error(err, &opts)
                        );
                        return;
                    }
                };
                let pipe = format!(
                    "ORACLEMCP_FETCH_TIMEOUT_{}_{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |duration| duration.as_nanos())
                );
                let sql = format!(
                    "SELECT CASE WHEN level = 1 THEN 0 ELSE DBMS_PIPE.RECEIVE_MESSAGE('{pipe}', 2) END AS status \
                     FROM dual CONNECT BY level <= 2"
                );
                let result = match inner
                    .execute_raw(&cx, &sql, 1, &[], ExecuteOptions::default(), None)
                    .await
                {
                    Ok(result) => result,
                    Err(err) => {
                        eprintln!(
                            "[live-xe] SKIP live_fetch_loop_is_bounded_per_batch: DBMS_PIPE unavailable or query rejected ({})",
                            sanitize_driver_error(err, &opts)
                        );
                        return;
                    }
                };
                if !result.more_rows || result.cursor_id == 0 {
                    eprintln!(
                        "[live-xe] SKIP live_fetch_loop_is_bounded_per_batch: fixture query did not produce a continuation fetch"
                    );
                    return;
                }

                let err = collect_all_rows(
                    &cx,
                    &mut inner,
                    result,
                    &opts,
                    &SerializeOptions::default(),
                    Some(10),
                )
                .await
                .expect_err("slow continuation fetch must time out");
                assert!(
                    err.to_string().contains("call timeout"),
                    "unexpected fetch-loop error: {err}"
                );

                let probe = inner
                    .execute_raw(
                        &cx,
                        "SELECT 1 AS n FROM dual",
                        1,
                        &[],
                        ExecuteOptions::default(),
                        None,
                    )
                    .await
                    .expect("connection remains usable after fetch timeout recovery");
                let n = probe.rows[0][0]
                    .as_ref()
                    .and_then(QueryValue::as_i64)
                    .expect("numeric probe cell");
                assert_eq!(n, 1);
            });
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
            let mut attempted_read = false;
            let mut read_lob = |_locator: &[u8], _offset: u64, _amount: u64| {
                attempted_read = true;
                Err(DbError::Query(
                    "unsupported subtype test closure invoked".to_owned(),
                ))
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
            assert!(
                !attempted_read,
                "unsupported LOB subtype must fail before reading locator data"
            );
        }

        #[test]
        fn timestamp_tz_formatter_preserves_numeric_offset() {
            assert_eq!(
                super::format_timestamp_tz(2026, 6, 29, 12, 34, 56, 987_654_321, -330),
                "2026-06-29 12:34:56.987654321 -05:30"
            );
            assert_eq!(
                super::format_timestamp_tz(2026, 6, 29, 12, 34, 56, 0, 345),
                "2026-06-29 12:34:56 +05:45"
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

    #[allow(clippy::too_many_arguments)]
    fn format_timestamp_tz(
        year: i32,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        nanosecond: u32,
        offset_minutes: i32,
    ) -> String {
        let sign = if offset_minutes < 0 { '-' } else { '+' };
        let offset_abs = i64::from(offset_minutes).abs();
        let offset_hours = offset_abs / 60;
        let offset_mins = offset_abs % 60;
        format!(
            "{} {sign}{offset_hours:02}:{offset_mins:02}",
            format_datetime(year, month, day, hour, minute, second, nanosecond)
        )
    }

    fn oracle_type_name(meta: &ColumnMetadata) -> String {
        let base = match meta.ora_type_num() {
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
        if meta.is_json() && base != "JSON" {
            "JSON".to_owned()
        } else {
            base.to_owned()
        }
    }

    const REDACTED: &str = "<redacted>";

    /// Minimum length for the case-insensitive, token-boundary identifier pass.
    /// Anything shorter is redacted only by exact (case-sensitive) substring so a
    /// 1-2 char token can never scrub swathes of unrelated prose.
    const CI_MIN_IDENTIFIER_LEN: usize = 3;

    /// An ASCII byte that can appear inside an Oracle/SQL identifier or a
    /// hostname label. Used as the token boundary for [`redact_identifier_ci`]:
    /// a match only counts when neither neighbour is one of these, so redacting
    /// `SYS` never touches `SYSDATE` and redacting `1521` never touches `215210`.
    fn is_identifier_byte(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b == b'#'
    }

    /// Case-insensitively remove every **token-boundary** occurrence of `needle`
    /// from `haystack`. Oracle upper-cases unquoted identifiers, so a lower-case
    /// schema/service/host in the profile re-appears upper-cased in an `ORA-`
    /// server message; matching ASCII-case-insensitively closes that leak. The
    /// boundary check keeps the pass from over-redacting unrelated text.
    fn redact_identifier_ci(haystack: &str, needle: &str) -> String {
        // Too short to fold casing safely: fall back to an exact (casing-precise)
        // substring pass, which cannot over-match on a short common word.
        if needle.len() < CI_MIN_IDENTIFIER_LEN {
            return haystack.replace(needle, REDACTED);
        }
        // `to_ascii_lowercase` preserves byte length (only ASCII A-Z change), so
        // byte indices computed on the lower-cased copies align with `haystack`.
        let hay_lower = haystack.to_ascii_lowercase();
        let needle_lower = needle.to_ascii_lowercase();
        let hay_bytes = hay_lower.as_bytes();
        let mut out = String::with_capacity(haystack.len());
        let mut last = 0usize;
        let mut search = 0usize;
        while let Some(rel) = hay_lower[search..].find(&needle_lower) {
            let start = search + rel;
            let end = start + needle_lower.len();
            let before_boundary = start == 0 || !is_identifier_byte(hay_bytes[start - 1]);
            let after_boundary = end == hay_bytes.len() || !is_identifier_byte(hay_bytes[end]);
            if before_boundary && after_boundary {
                out.push_str(&haystack[last..start]);
                out.push_str(REDACTED);
                last = end;
                search = end;
            } else {
                // Overlapping/embedded occurrence: advance one byte and retry.
                search = start + 1;
            }
        }
        out.push_str(&haystack[last..]);
        out
    }

    /// Redact every operator-facing rendering of a driver error.
    ///
    /// Two passes, each fail-closed:
    ///  1. **Exact secrets** — high-entropy or free-form material (passwords,
    ///     tokens, wallet paths/passwords, the full connect string, cert DN,
    ///     app-context + session-identity values) removed verbatim. Longest
    ///     first, so a superstring is scrubbed before any of its substrings.
    ///  2. **Topology identifiers** — the host, port, service name (decomposed
    ///     from the connect string) and the username/schema, removed
    ///     case-insensitively on token boundaries. This closes the two leaks the
    ///     verbatim pass alone misses: a *decomposed* connect string (an `ORA-`
    ///     message that names only the host, or only the service) and an
    ///     Oracle-**upper-cased** identifier that no longer byte-matches the
    ///     lower-case profile value.
    pub(super) fn sanitize_driver_error(err: impl Display, opts: &OracleConnectOptions) -> String {
        let mut message = err.to_string();

        // --- Pass 1: exact, case-sensitive secrets -------------------------
        let mut exact_secrets = vec![opts.connect_string.clone()];
        if let Some(password) = &opts.password {
            exact_secrets.push(password.clone());
        }
        if let Some(token) = &opts.iam_token {
            exact_secrets.push(token.clone());
        }
        if let Some(wallet) = &opts.wallet_location {
            exact_secrets.push(wallet.display().to_string());
        }
        if let Some(wallet_password) = &opts.wallet_password {
            exact_secrets.push(wallet_password.clone());
        }
        if let Some(dn) = &opts.ssl_server_cert_dn {
            exact_secrets.push(dn.clone());
        }
        for (namespace, key, value) in &opts.app_context {
            exact_secrets.push(namespace.clone());
            exact_secrets.push(key.clone());
            exact_secrets.push(value.clone());
        }
        exact_secrets.extend(
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
                exact_secrets.push(value.clone());
            }
        }
        exact_secrets.sort_by_key(|value| std::cmp::Reverse(value.len()));
        for secret in exact_secrets.iter().filter(|value| !value.is_empty()) {
            message = message.replace(secret.as_str(), REDACTED);
        }

        // --- Pass 2: decomposed / upper-cased topology identifiers ---------
        let mut identifiers: Vec<String> = Vec::new();
        if let Some(username) = &opts.username {
            identifiers.push(username.clone());
        }
        let hints = crate::tns::extract_hints(&opts.connect_string);
        if let Some(host) = hints.host {
            identifiers.push(host);
        }
        if let Some(service) = hints.service_name {
            identifiers.push(service);
        }
        if let Some(port) = hints.port {
            identifiers.push(port.to_string());
        }
        identifiers.sort_by_key(|value| std::cmp::Reverse(value.len()));
        for identifier in identifiers.iter().filter(|value| !value.is_empty()) {
            message = redact_identifier_ci(&message, identifier);
        }
        message
    }

    /// Extract the `ERR=` code from a TNS listener refuse payload, e.g.
    /// `(DESCRIPTION=(TMP=)(VSNNUM=...)(ERR=12514)(ERROR_STACK=...))`.
    pub(super) fn parse_listener_refuse_code(payload: &str) -> Option<u32> {
        let start = payload.find("(ERR=")? + "(ERR=".len();
        let digits: String = payload[start..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse().ok()
    }

    /// Classify a driver connect/handshake failure into the driver-agnostic
    /// [`ConnectFailureKind`]. This function is the **only** place that reads
    /// `oracledb::Error` connect variants — everything downstream (envelope
    /// rendering, doctor guidance) works from the structured kind. `None`
    /// means "no handshake-specific classification" and the caller keeps the
    /// plain `DbError::Connect` path (wallet errors deliberately stay there:
    /// their existing diagnostics are already precise).
    pub(super) fn classify_connect_failure(err: &oracledb::Error) -> Option<ConnectFailureKind> {
        match err {
            oracledb::Error::UnexpectedPacket(packet_type) => {
                Some(ConnectFailureKind::UnexpectedTnsPacket {
                    packet_type: *packet_type,
                })
            }
            oracledb::Error::ConnectResendLoop(rounds) => {
                Some(ConnectFailureKind::ConnectResendLoop { rounds: *rounds })
            }
            oracledb::Error::FastAuthRequired => Some(ConnectFailureKind::FastAuthNotAdvertised),
            oracledb::Error::RedirectUnsupported => {
                Some(ConnectFailureKind::ListenerRedirectUnsupported)
            }
            oracledb::Error::ListenerRefused(payload) => {
                Some(ConnectFailureKind::ListenerRefused {
                    err_code: parse_listener_refuse_code(payload),
                })
            }
            oracledb::Error::Protocol(protocol) => match protocol {
                oracledb::protocol::ProtocolError::UnsupportedVersion {
                    version,
                    minimum: _,
                } => Some(ConnectFailureKind::ServerGenerationUnsupported {
                    tns_version: Some(*version),
                }),
                oracledb::protocol::ProtocolError::UnsupportedFeature(feature) => {
                    Some(ConnectFailureKind::UnsupportedWireFeature {
                        feature: (*feature).to_owned(),
                    })
                }
                // Any other protocol-layer failure during connect is, by
                // construction, a handshake-phase framing/decode problem —
                // name the phase honestly instead of leaking a bare driver
                // string (the field bug: "unknown TTC message type 11" was a
                // network-layer TNS packet misread as application-layer TTC).
                oracledb::protocol::ProtocolError::TruncatedHeader { .. }
                | oracledb::protocol::ProtocolError::InvalidPacketLength { .. }
                | oracledb::protocol::ProtocolError::IncompletePacket { .. }
                | oracledb::protocol::ProtocolError::PacketTooLarge { .. }
                | oracledb::protocol::ProtocolError::UnknownMessageType { .. }
                | oracledb::protocol::ProtocolError::TtcDecode(_)
                | oracledb::protocol::ProtocolError::InvalidServerResponse => {
                    Some(ConnectFailureKind::HandshakeProtocol)
                }
                _ => None,
            },
            _ => None,
        }
    }

    /// Map a driver connect failure to a [`DbError`]: structured
    /// [`DbError::ConnectHandshake`] when the failure classifies, the plain
    /// sanitized [`DbError::Connect`] otherwise (both fail closed; the
    /// envelope layer guarantees `next_steps` either way).
    pub(super) fn connect_error_to_db_error(
        err: &oracledb::Error,
        opts: &OracleConnectOptions,
    ) -> DbError {
        let message = sanitize_driver_error(err, opts);
        match classify_connect_failure(err) {
            Some(kind) => DbError::ConnectHandshake { kind, message },
            None => DbError::Connect(message),
        }
    }

    #[async_trait::async_trait(?Send)]
    impl super::OracleConnection for RustOracleConnection {
        fn backend(&self) -> crate::types::OracleBackend {
            crate::types::OracleBackend::RustOracle
        }

        async fn ping(&self, cx: &Cx) -> Result<(), DbError> {
            super::db_checkpoint(cx, "oracle_db.ping.before")?;
            let timeout = self.timeout_ms()?;
            let mut inner = self.lock_inner(cx).await?;
            let result = match timeout {
                Some(timeout) => inner.ping_with_timeout(cx, timeout).await,
                None => inner.ping(cx).await,
            }
            .map_err(|err| DbError::Query(sanitize_driver_error(err, &self.opts)));
            drop(inner);
            super::db_checkpoint(cx, "oracle_db.ping.after")?;
            result
        }

        async fn describe(&self, cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            super::db_checkpoint(cx, "oracle_db.describe.before")?;
            let mut info = OracleConnectionInfo {
                backend: Some(crate::types::OracleBackend::RustOracle),
                connection_strategy: Some("single_session".to_owned()),
                ..Default::default()
            };
            if let Some(r) = self
                .query_first_row(
                    cx,
                    "SELECT version_full FROM product_component_version WHERE rownum = 1",
                )
                .await
            {
                info.server_version = r.text("VERSION_FULL").map(str::to_owned);
            }
            if let Some(r) = self
                .query_first_row(
                    cx,
                    "SELECT database_role, open_mode, db_unique_name FROM v$database",
                )
                .await
            {
                info.database_role = r.text("DATABASE_ROLE").map(str::to_owned);
                info.open_mode = r.text("OPEN_MODE").map(str::to_owned);
                info.db_unique_name = r.text("DB_UNIQUE_NAME").map(str::to_owned);
            }
            if let Some(r) = self
                .query_first_row(cx, "SELECT instance_name FROM v$instance")
                .await
            {
                info.instance_name = r.text("INSTANCE_NAME").map(str::to_owned);
            }
            if let Some(r) = self
                .query_first_row(
                    cx,
                    "SELECT \
                    SYS_CONTEXT('USERENV','CURRENT_SCHEMA') AS current_schema, \
                    SYS_CONTEXT('USERENV','CURRENT_EDITION_NAME') AS current_edition, \
                    SYS_CONTEXT('USERENV','SESSION_USER') AS session_user, \
                    SYS_CONTEXT('USERENV','CURRENT_USER') AS current_user, \
                    SYS_CONTEXT('USERENV','PROXY_USER') AS proxy_user, \
                    SYS_CONTEXT('USERENV','SID') AS sid, \
                    SYS_CONTEXT('USERENV','SERVICE_NAME') AS service_name, \
                    SYS_CONTEXT('USERENV','MODULE') AS module, \
                    SYS_CONTEXT('USERENV','ACTION') AS session_action, \
                    SYS_CONTEXT('USERENV','CLIENT_IDENTIFIER') AS client_identifier, \
                    SYS_CONTEXT('USERENV','CLIENT_INFO') AS client_info, \
                    SYS_CONTEXT('USERENV','OS_USER') AS os_user, \
                    SYS_CONTEXT('USERENV','HOST') AS host, \
                    SYS_CONTEXT('USERENV','TERMINAL') AS terminal \
                 FROM dual",
                )
                .await
            {
                info.current_schema = r.text("CURRENT_SCHEMA").map(str::to_owned);
                info.current_edition = r.text("CURRENT_EDITION").map(str::to_owned);
                info.session_user = r.text("SESSION_USER").map(str::to_owned);
                info.current_user = r.text("CURRENT_USER").map(str::to_owned);
                info.proxy_user = r.text("PROXY_USER").map(str::to_owned);
                info.sid = r.text("SID").map(str::to_owned);
                info.service_name = r.text("SERVICE_NAME").map(str::to_owned);
                info.module = r.text("MODULE").map(str::to_owned);
                info.action = r.text("SESSION_ACTION").map(str::to_owned);
                info.client_identifier = r.text("CLIENT_IDENTIFIER").map(str::to_owned);
                info.client_info = r.text("CLIENT_INFO").map(str::to_owned);
                info.os_user = r.text("OS_USER").map(str::to_owned);
                info.host = r.text("HOST").map(str::to_owned);
                info.terminal = r.text("TERMINAL").map(str::to_owned);
            }
            if let Some(r) = self
                .query_first_row(
                    cx,
                    "SELECT sid, serial# AS serial_number, service_name, osuser, machine, terminal, program \
                 FROM v$session \
                 WHERE sid = TO_NUMBER(SYS_CONTEXT('USERENV','SID')) \
                 FETCH FIRST 1 ROWS ONLY",
                )
                .await
            {
                info.sid = r.text("SID").map(str::to_owned).or_else(|| info.sid.take());
                info.serial_number = r.text("SERIAL_NUMBER").map(str::to_owned);
                info.service_name = r
                    .text("SERVICE_NAME")
                    .map(str::to_owned)
                    .or_else(|| info.service_name.take());
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
            if let Some(r) = self
                .query_first_row(
                    cx,
                    "SELECT client_driver \
                 FROM v$session_connect_info \
                 WHERE sid = TO_NUMBER(SYS_CONTEXT('USERENV','SID')) \
                   AND client_driver IS NOT NULL \
                 FETCH FIRST 1 ROWS ONLY",
                )
                .await
            {
                info.client_driver = r.text("CLIENT_DRIVER").map(str::to_owned);
            }
            super::db_checkpoint(cx, "oracle_db.describe.after")?;
            Ok(info.with_read_only_status())
        }

        async fn query_rows(
            &self,
            cx: &Cx,
            sql: &str,
            binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.query_rows_with_serialize_options(cx, sql, binds, &SerializeOptions::default())
                .await
        }

        async fn query_rows_with_serialize_options(
            &self,
            cx: &Cx,
            sql: &str,
            binds: &[OracleBind],
            serialize_opts: &SerializeOptions,
        ) -> Result<Vec<OracleRow>, DbError> {
            super::db_checkpoint(cx, "oracle_db.query_rows.before")?;
            let binds: Vec<BindValue> = binds.iter().map(to_bind).collect();
            let timeout = self.timeout_ms()?;
            let mut inner = self.lock_inner(cx).await?;
            let result = if binds.is_empty() && timeout.is_none() {
                inner
                    .execute_raw(
                        cx,
                        sql,
                        prefetch_rows_for_statement(sql),
                        &[],
                        ExecuteOptions::default(),
                        None,
                    )
                    .await
                    .map_err(|err| DbError::Query(sanitize_driver_error(err, &self.opts)))?
            } else {
                execute_with_timeout(
                    cx,
                    &mut inner,
                    sql,
                    prefetch_rows_for_statement(sql),
                    &binds,
                    timeout,
                    &self.opts,
                    "query",
                )
                .await?
            };
            let rows =
                collect_all_rows(cx, &mut inner, result, &self.opts, serialize_opts, timeout)
                    .await?;
            drop(inner);
            super::db_checkpoint(cx, "oracle_db.query_rows.after")?;
            Ok(rows)
        }

        async fn query_rows_named(
            &self,
            cx: &Cx,
            sql: &str,
            binds: &[(String, OracleBind)],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.query_rows_named_with_serialize_options(
                cx,
                sql,
                binds,
                &SerializeOptions::default(),
            )
            .await
        }

        async fn query_rows_named_with_serialize_options(
            &self,
            cx: &Cx,
            sql: &str,
            binds: &[(String, OracleBind)],
            serialize_opts: &SerializeOptions,
        ) -> Result<Vec<OracleRow>, DbError> {
            super::db_checkpoint(cx, "oracle_db.query_rows_named.before")?;
            let binds: Vec<(String, BindValue)> = binds
                .iter()
                .map(|(name, bind)| (name.clone(), to_bind(bind)))
                .collect();
            let timeout = self.timeout_ms()?;
            let mut inner = self.lock_inner(cx).await?;
            let result = if binds.is_empty() {
                if timeout.is_none() {
                    inner
                        .execute_raw(
                            cx,
                            sql,
                            prefetch_rows_for_statement(sql),
                            &[],
                            ExecuteOptions::default(),
                            None,
                        )
                        .await
                        .map_err(|err| DbError::Query(sanitize_driver_error(err, &self.opts)))?
                } else {
                    execute_with_timeout(
                        cx,
                        &mut inner,
                        sql,
                        prefetch_rows_for_statement(sql),
                        &[],
                        timeout,
                        &self.opts,
                        "query named",
                    )
                    .await?
                }
            } else {
                let ordered_binds = order_named_binds_for_driver(sql, binds);
                execute_with_timeout(
                    cx,
                    &mut inner,
                    sql,
                    prefetch_rows_for_statement(sql),
                    &ordered_binds,
                    timeout,
                    &self.opts,
                    "query named",
                )
                .await?
            };
            let rows =
                collect_all_rows(cx, &mut inner, result, &self.opts, serialize_opts, timeout)
                    .await?;
            drop(inner);
            super::db_checkpoint(cx, "oracle_db.query_rows_named.after")?;
            Ok(rows)
        }

        async fn execute(&self, cx: &Cx, sql: &str, binds: &[OracleBind]) -> Result<u64, DbError> {
            super::db_checkpoint(cx, "oracle_db.execute.before")?;
            let binds: Vec<BindValue> = binds.iter().map(to_bind).collect();
            let timeout = self.timeout_ms()?;
            let mut inner = self.lock_inner(cx).await?;
            let result = execute_with_timeout(
                cx, &mut inner, sql, 0, &binds, timeout, &self.opts, "execute",
            )
            .await
            .map_err(|err| match err {
                DbError::Query(msg) => DbError::Execute(msg),
                other => other,
            })?;
            drop(inner);
            super::db_checkpoint(cx, "oracle_db.execute.after")?;
            Ok(result.row_count)
        }

        async fn call_routine(
            &self,
            cx: &Cx,
            plsql_block: &str,
            args: &[OracleRoutineArg],
        ) -> Result<ExecuteOutcome, DbError> {
            super::db_checkpoint(cx, "oracle_db.call_routine.before")?;
            let binds: Vec<BindValue> = args
                .iter()
                .cloned()
                .map(OracleRoutineArg::into_driver_bind)
                .collect();
            let timeout = self.timeout_ms()?;
            let serialize_opts = SerializeOptions::default();
            let mut inner = self.lock_inner(cx).await?;
            let result = execute_with_timeout(
                cx,
                &mut inner,
                plsql_block,
                0,
                &binds,
                timeout,
                &self.opts,
                "routine",
            )
            .await
            .map_err(|err| match err {
                DbError::Query(msg) => DbError::Execute(msg),
                other => other,
            })?;
            let rows_affected = result.row_count;
            let out_binds = routine_out_binds(
                cx,
                &mut inner,
                &result,
                args,
                &self.opts,
                &serialize_opts,
                timeout,
            )
            .await?;
            drop(inner);
            super::db_checkpoint(cx, "oracle_db.call_routine.after")?;
            Ok(ExecuteOutcome::new(rows_affected, out_binds))
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

        async fn read_dbms_output(
            &self,
            cx: &Cx,
            max_lines: usize,
            max_chars: usize,
        ) -> Result<DbmsOutput, DbError> {
            super::db_checkpoint(cx, "oracle_db.read_dbms_output.before")?;
            let timeout = self.timeout_ms()?;
            let mut lines = Vec::new();
            let mut char_count = 0usize;
            let mut truncated = false;
            let mut inner = self.lock_inner(cx).await?;
            for _ in 0..max_lines {
                let result = inner
                    .execute_raw(
                        cx,
                        "BEGIN DBMS_OUTPUT.GET_LINE(:1, :2); END;",
                        0,
                        &[vec![
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
                        ]],
                        ExecuteOptions::default(),
                        timeout,
                    )
                    .await
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
            drop(inner);
            super::db_checkpoint(cx, "oracle_db.read_dbms_output.after")?;
            Ok(DbmsOutput {
                line_count: lines.len(),
                lines,
                char_count,
                truncated,
            })
        }

        async fn commit(&self, cx: &Cx) -> Result<(), DbError> {
            // No post-commit checkpoint: once Oracle commits, cancellation
            // cannot undo it.
            super::db_checkpoint(cx, "oracle_db.commit.before")?;
            let mut inner = self.lock_inner(cx).await?;
            inner
                .commit(cx)
                .await
                .map_err(|err| DbError::Execute(sanitize_driver_error(err, &self.opts)))
        }

        async fn rollback(&self, cx: &Cx) -> Result<(), DbError> {
            // Rollback is cleanup. Do not add an adapter-level pre-checkpoint
            // here: a cancellation observed after DML must not make this layer
            // skip cleanup before the driver even sees the rollback request.
            // The wire round trip remains bounded by the connection's
            // configured Oracle call timeout.
            let mut inner = self.lock_inner(cx).await?;
            inner
                .rollback(cx)
                .await
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
        use asupersync::runtime::RuntimeBuilder;
        let opts = crate::types::OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            external_auth: true,
            ..Default::default()
        };
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        let result = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            RustOracleConnection::connect(&cx, opts).await
        });
        assert!(matches!(result, Err(DbError::UnsupportedAuth(_))));
    }

    #[test]
    fn duration_to_millis_saturates() {
        assert_eq!(duration_to_millis(Duration::from_millis(42)), 42);
        assert_eq!(duration_to_millis(Duration::from_secs(u64::MAX)), u32::MAX);
    }

    #[test]
    fn routine_arg_wraps_driver_output_variants() {
        match OracleRoutineArg::output(1, 2, 3).into_driver_bind() {
            oracledb::protocol::thin::BindValue::Output {
                ora_type_num,
                csfrm,
                buffer_size,
            } => {
                assert_eq!((ora_type_num, csfrm, buffer_size), (1, 2, 3));
            }
            other => panic!("expected Output bind, got {}", other.variant_name()),
        }

        match OracleRoutineArg::return_output(4, 5, 6).into_driver_bind() {
            oracledb::protocol::thin::BindValue::Output {
                ora_type_num,
                csfrm,
                buffer_size,
            } => {
                assert_eq!((ora_type_num, csfrm, buffer_size), (4, 5, 6));
            }
            other => panic!("expected Output bind, got {}", other.variant_name()),
        }

        match OracleRoutineArg::object_output(
            "APP".to_owned(),
            "OBJ_T".to_owned(),
            vec![1, 2, 3],
            7,
            8,
        )
        .into_driver_bind()
        {
            oracledb::protocol::thin::BindValue::ObjectOutput {
                schema,
                type_name,
                oid,
                version,
                buffer_size,
                is_return,
            } => {
                assert_eq!(schema, "APP");
                assert_eq!(type_name, "OBJ_T");
                assert_eq!(oid, vec![1, 2, 3]);
                assert_eq!((version, buffer_size, is_return), (7, 8, false));
            }
            other => panic!("expected ObjectOutput bind, got {}", other.variant_name()),
        }

        match OracleRoutineArg::object_return_output(
            "APP".to_owned(),
            "OBJ_T".to_owned(),
            vec![4, 5, 6],
            9,
            10,
        )
        .into_driver_bind()
        {
            oracledb::protocol::thin::BindValue::ObjectOutput {
                schema,
                type_name,
                oid,
                version,
                buffer_size,
                is_return,
            } => {
                assert_eq!(schema, "APP");
                assert_eq!(type_name, "OBJ_T");
                assert_eq!(oid, vec![4, 5, 6]);
                assert_eq!((version, buffer_size, is_return), (9, 10, true));
            }
            other => panic!("expected ObjectOutput bind, got {}", other.variant_name()),
        }
    }

    #[test]
    fn routine_out_values_follow_declared_order() {
        let result = oracledb::protocol::thin::QueryResult {
            out_values: vec![
                (
                    0,
                    Some(oracledb::protocol::thin::QueryValue::number_from_text(
                        "42", true,
                    )),
                ),
                (
                    2,
                    Some(oracledb::protocol::thin::QueryValue::Text(
                        "first".to_owned(),
                    )),
                ),
            ],
            ..Default::default()
        };

        let args = [
            OracleRoutineArg::return_output(1, 1, 32_767),
            OracleRoutineArg::input(OracleBind::String("ignored input".to_owned())),
            OracleRoutineArg::output(2, 1, 22),
        ];

        let ordered = driver::ordered_routine_out_values(&result, &args).expect("ordered values");
        assert_eq!(
            ordered,
            vec![
                Some(oracledb::protocol::thin::QueryValue::number_from_text(
                    "42", true
                )),
                Some(oracledb::protocol::thin::QueryValue::Text(
                    "first".to_owned()
                )),
            ]
        );

        let missing = oracledb::protocol::thin::QueryResult {
            out_values: vec![(0, None)],
            ..Default::default()
        };
        let err = driver::ordered_routine_out_values(
            &missing,
            &[
                OracleRoutineArg::input(OracleBind::String("ignored input".to_owned())),
                OracleRoutineArg::output(1, 1, 32_767),
            ],
        )
        .expect_err("missing declared out bind is an adapter error");
        assert!(
            matches!(err, DbError::Execute(ref msg) if msg.contains("position 2")),
            "{err:?}"
        );
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
    fn fetch_loop_is_bounded_per_batch() {
        fn block_on_without_runtime<F: std::future::Future>(future: F) -> F::Output {
            let waker = std::task::Waker::noop().clone();
            let mut cx = std::task::Context::from_waker(&waker);
            let mut future = std::pin::pin!(future);
            loop {
                match future.as_mut().poll(&mut cx) {
                    std::task::Poll::Ready(output) => return output,
                    std::task::Poll::Pending => std::thread::sleep(Duration::from_millis(1)),
                }
            }
        }

        let err = block_on_without_runtime(driver::bounded_fetch_batch(
            Some(1),
            std::future::pending::<Result<(), ()>>(),
        ));

        assert_eq!(err, Err(driver::FetchBatchError::Timeout(1)));
    }

    #[test]
    fn fetch_loop_timeout_is_uncertain_session_state() {
        let err = driver::fetch_batch_call_timeout(25);

        assert!(err.is_uncertain_session_state(), "{err}");
        assert!(err.to_string().contains("call timeout of 25 ms exceeded"));
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

        assert_eq!(connect.identity().program, "profile-program");
        assert_eq!(connect.identity().machine, "profile-machine");
        assert_eq!(connect.identity().osuser, "profile-os-user");
        assert_eq!(connect.identity().terminal, "profile-terminal");
        assert_eq!(connect.identity().driver_name, "profile-driver");
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

        assert_eq!(connect.identity().program, "legacy-module-program");
        assert_eq!(connect.identity().terminal, "legacy-client-terminal");
        assert_eq!(connect.identity().driver_name, "oraclemcp-thin");
        assert!(!connect.identity().machine.is_empty());
        assert!(!connect.identity().osuser.is_empty());
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

        assert_eq!(connect.wallet_location(), Some("/wallets/private"));
        assert_eq!(connect.wallet_password(), Some("wallet-secret"));
        assert!(!connect.ssl_server_dn_match());
        assert_eq!(
            connect.ssl_server_cert_dn(),
            Some("CN=db.example.com,O=Example,C=US")
        );
        assert!(!connect.use_sni());
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

        assert_eq!(connect.wallet_location(), Some("/wallets/private"));
        assert!(
            connect.use_sni(),
            "existing wallet profiles default to SNI on"
        );
        assert!(connect.ssl_server_dn_match());
        assert_eq!(connect.wallet_password(), None);
        assert_eq!(connect.ssl_server_cert_dn(), None);
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

        assert_eq!(connect.user(), "MCP_PROXY");
        assert_eq!(connect.proxy_user(), Some("APP_OWNER"));
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

        assert_eq!(connect.app_context(), opts.app_context.as_slice());
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

        assert_eq!(connect.sdu(), 32_768u16);
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

        assert_eq!(connect.sdu(), 8192u16);
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

        assert_eq!(connect.statement_cache_size(), 128);
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

        assert_eq!(connect.statement_cache_size(), 20);
    }

    #[test]
    fn thin_connect_options_apply_transport_connect_timeout() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            connect_timeout: Some(Duration::from_secs(7)),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(
            connect.connect_string(),
            "localhost:1521/FREEPDB1?transport_connect_timeout=7"
        );
    }

    #[test]
    fn thin_connect_options_append_transport_connect_timeout_to_existing_query() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1?expire_time=5".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            connect_timeout: Some(Duration::from_secs(9)),
            ..Default::default()
        };

        let connect = driver::to_connect_options(&opts).expect("connect options");

        assert_eq!(
            connect.connect_string(),
            "localhost:1521/FREEPDB1?expire_time=5&transport_connect_timeout=9"
        );
    }

    #[test]
    fn thin_connect_options_reject_ambiguous_connect_timeout_sources() {
        let opts = OracleConnectOptions {
            connect_string: "localhost:1521/FREEPDB1?transport_connect_timeout=3".to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            connect_timeout: Some(Duration::from_secs(9)),
            ..Default::default()
        };

        let err = driver::to_connect_options(&opts).expect_err("conflicting timeout sources");
        assert!(matches!(err, DbError::UnsupportedAuth(_)));
        assert!(err.to_string().contains("conflicts"), "{err}");
    }

    #[test]
    fn thin_connect_options_reject_descriptor_connect_timeout_injection() {
        let opts = OracleConnectOptions {
            connect_string: "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=svc)))"
                .to_owned(),
            username: Some("APP".to_owned()),
            password: Some("secret".to_owned()),
            connect_timeout: Some(Duration::from_secs(9)),
            ..Default::default()
        };

        let err = driver::to_connect_options(&opts).expect_err("descriptor injection refused");
        assert!(matches!(err, DbError::UnsupportedAuth(_)));
        assert!(err.to_string().contains("descriptor"), "{err}");
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

        assert_eq!(connect.edition(), Some("E_TEST"));
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
            connect.access_token().is_some(),
            "the IAM token must be wired through with_access_token"
        );
        // The token must never leak through Debug.
        let rendered = format!("{:?}", connect.access_token());
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
        assert!(connect.access_token().is_some());
    }

    /// The committed `tnsnames.ora` fixture tree (design spec §F), used here to
    /// exercise server-side alias resolution (B2.3).
    fn tns_fixtures_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("tests")
            .join("fixtures")
            .join("tns")
    }

    #[test]
    fn bare_alias_resolves_to_descriptor_via_wallet_tnsnames() {
        // Skip if the ambient environment sets TNS_ADMIN (it would take priority
        // over the wallet dir and make the assertion env-dependent).
        if std::env::var_os("TNS_ADMIN").is_some() {
            return;
        }
        // A bare alias (round-2 OCI-2: this previously failed to resolve) is
        // expanded to its full descriptor from the wallet directory's
        // tnsnames.ora before the string reaches the driver.
        let opts = OracleConnectOptions {
            connect_string: "primary_tcps".to_owned(),
            username: Some("APP_USER".to_owned()),
            password: Some("pw".to_owned()),
            wallet_location: Some(tns_fixtures_dir()),
            ..Default::default()
        };
        let connect = driver::to_connect_options(&opts).expect("alias resolves");
        let cs = connect.connect_string();
        assert!(
            cs.contains("tcps.example.com") && cs.contains("2484"),
            "the bare alias resolved to the PRIMARY_TCPS descriptor, got: {cs}"
        );
    }

    #[test]
    fn full_descriptor_connect_string_is_used_verbatim() {
        // A full descriptor must still work unchanged even with a wallet set.
        let descriptor = "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=db.example)(PORT=1521))\
             (CONNECT_DATA=(SERVICE_NAME=svc)))";
        let opts = OracleConnectOptions {
            connect_string: descriptor.to_owned(),
            username: Some("APP_USER".to_owned()),
            password: Some("pw".to_owned()),
            wallet_location: Some(tns_fixtures_dir()),
            ..Default::default()
        };
        let connect = driver::to_connect_options(&opts).expect("descriptor options");
        assert_eq!(connect.connect_string(), descriptor);
    }

    #[test]
    fn missing_alias_fails_with_actionable_error() {
        if std::env::var_os("TNS_ADMIN").is_some() {
            return;
        }
        let opts = OracleConnectOptions {
            connect_string: "does_not_exist".to_owned(),
            username: Some("APP_USER".to_owned()),
            password: Some("pw".to_owned()),
            wallet_location: Some(tns_fixtures_dir()),
            ..Default::default()
        };
        let err = driver::to_connect_options(&opts).expect_err("missing alias is refused");
        assert!(matches!(err, DbError::Connect(_)), "{err}");
        let msg = err.to_string();
        assert!(msg.contains("does_not_exist"), "names the alias: {msg}");
        assert!(
            msg.contains("available aliases") && msg.contains("PRIMARY_TCPS"),
            "lists what IS available: {msg}"
        );
    }

    #[test]
    fn malformed_alias_source_fails_without_panic() {
        if std::env::var_os("TNS_ADMIN").is_some() {
            return;
        }
        // A bare alias against a directory whose tnsnames.ora has an IFILE cycle
        // surfaces a clear connect error, never a panic.
        let opts = OracleConnectOptions {
            connect_string: "anything".to_owned(),
            username: Some("APP_USER".to_owned()),
            password: Some("pw".to_owned()),
            wallet_location: Some(tns_fixtures_dir().join("cycle")),
            ..Default::default()
        };
        let err = driver::to_connect_options(&opts).expect_err("malformed source is refused");
        assert!(matches!(err, DbError::Connect(_)), "{err}");
    }

    #[test]
    fn ez_connect_with_wallet_is_not_treated_as_alias() {
        // A host:port/service EZConnect string carries a `/` and `:`, so it is
        // never mistaken for a bare alias even when a wallet dir is present.
        let opts = OracleConnectOptions {
            connect_string: "db.example:1521/svc".to_owned(),
            username: Some("APP_USER".to_owned()),
            password: Some("pw".to_owned()),
            wallet_location: Some(tns_fixtures_dir()),
            ..Default::default()
        };
        let connect = driver::to_connect_options(&opts).expect("ezconnect options");
        assert_eq!(connect.connect_string(), "db.example:1521/svc");
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

    // --- structured / decomposed / upper-cased redaction (bead p0sd) ------
    //
    // Exact-substring redaction alone leaks a *decomposed* connect string (an
    // `ORA-` message naming only the host, or only the service) and an
    // Oracle-**upper-cased** identifier. These pin the structured pass.

    fn ezconnect_opts() -> OracleConnectOptions {
        OracleConnectOptions {
            connect_string: "db.internal.example:1599/appsvc".to_owned(),
            username: Some("appschema".to_owned()),
            password: Some("hunter2pw".to_owned()),
            ..Default::default()
        }
    }

    #[test]
    fn redaction_scrubs_decomposed_host_alone() {
        let out = driver::sanitize_driver_error(
            "ORA-12545: Connect failed because host db.internal.example is unreachable",
            &ezconnect_opts(),
        );
        assert!(!out.contains("db.internal.example"), "{out}");
        assert!(out.contains("<redacted>"), "{out}");
    }

    #[test]
    fn redaction_scrubs_decomposed_port_alone() {
        let out = driver::sanitize_driver_error(
            "TNS listener on port 1599 refused the request",
            &ezconnect_opts(),
        );
        assert!(!out.contains("1599"), "{out}");
        assert!(out.contains("<redacted>"), "{out}");
    }

    #[test]
    fn redaction_scrubs_decomposed_service_alone() {
        let out = driver::sanitize_driver_error(
            "ORA-12514: listener does not currently know of service appsvc",
            &ezconnect_opts(),
        );
        assert!(!out.contains("appsvc"), "{out}");
        assert!(out.contains("<redacted>"), "{out}");
    }

    #[test]
    fn redaction_scrubs_oracle_uppercased_service_and_schema() {
        // Oracle upper-cases unquoted identifiers, so the lower-case profile
        // values re-appear as APPSVC / APPSCHEMA in the server message.
        let out = driver::sanitize_driver_error(
            "ORA-12514: TNS:listener does not currently know of service APPSVC \
             requested for schema APPSCHEMA",
            &ezconnect_opts(),
        );
        assert!(!out.contains("APPSVC"), "{out}");
        assert!(!out.contains("APPSCHEMA"), "{out}");
        assert!(out.contains("<redacted>"), "{out}");
    }

    #[test]
    fn redaction_scrubs_full_connect_string_verbatim() {
        let out = driver::sanitize_driver_error(
            "failed to connect to db.internal.example:1599/appsvc as appschema",
            &ezconnect_opts(),
        );
        for leak in [
            "db.internal.example",
            "1599",
            "appsvc",
            "appschema",
            "db.internal.example:1599/appsvc",
        ] {
            assert!(!out.contains(leak), "leaked {leak}: {out}");
        }
    }

    #[test]
    fn redaction_does_not_over_scrub_a_benign_message() {
        // No secret component appears here — the message must pass through
        // byte-for-byte, and the short-identifier boundary rule must not fire.
        let benign = "ORA-00942: table or view does not exist";
        let out = driver::sanitize_driver_error(benign, &ezconnect_opts());
        assert_eq!(out, benign, "benign message was altered: {out}");
    }

    #[test]
    fn redaction_boundary_rule_spares_embedded_lookalikes() {
        // Service "appsvc" / port "1599" as *substrings* of longer tokens must
        // survive; only whole-token matches are topology leaks.
        let opts = ezconnect_opts();
        let out =
            driver::sanitize_driver_error("note: myappsvcx and 15990 are unrelated tokens", &opts);
        assert!(
            out.contains("myappsvcx"),
            "over-redacted a superstring: {out}"
        );
        assert!(out.contains("15990"), "over-redacted a superstring: {out}");
        assert!(!out.contains("<redacted>"), "{out}");
    }

    #[test]
    fn redaction_handles_tns_descriptor_connect_string() {
        let opts = OracleConnectOptions {
            connect_string:
                "(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=vault-db.example)(PORT=2484))\
                 (CONNECT_DATA=(SERVICE_NAME=vaultsvc)))"
                    .to_owned(),
            username: Some("vaultuser".to_owned()),
            ..Default::default()
        };
        let out = driver::sanitize_driver_error(
            "ORA-12514 for VAULTSVC on VAULT-DB.EXAMPLE:2484 user VAULTUSER",
            &opts,
        );
        for leak in ["VAULTSVC", "VAULT-DB.EXAMPLE", "2484", "VAULTUSER"] {
            assert!(!out.contains(leak), "leaked {leak}: {out}");
        }
    }

    #[test]
    fn fetch_call_timeout_is_structurally_uncertain_not_marker_dependent() {
        // Regression guard for the marker-fragility half of bead p0sd: the
        // in-house call-timeout path must flag uncertain session state from the
        // error *kind*, independent of the message wording.
        let err = driver::fetch_batch_call_timeout(25);
        assert!(matches!(err, DbError::Cancelled(_)), "{err:?}");
        assert!(err.is_uncertain_session_state(), "{err}");
    }

    // --- connect/handshake failure classification (bead bhw6.2) -----------
    //
    // These construct real `oracledb::Error` connect variants and assert the
    // seam maps each to the driver-agnostic `ConnectFailureKind`, so an
    // opaque driver string can never again ship as the whole diagnosis.

    use crate::error::ConnectFailureKind;

    #[test]
    fn classify_unexpected_packet_maps_to_unexpected_tns_packet() {
        let kind = driver::classify_connect_failure(&oracledb::Error::UnexpectedPacket(11));
        assert_eq!(
            kind,
            Some(ConnectFailureKind::UnexpectedTnsPacket { packet_type: 11 })
        );
    }

    #[test]
    fn classify_connect_resend_loop_carries_rounds() {
        let kind = driver::classify_connect_failure(&oracledb::Error::ConnectResendLoop(5));
        assert_eq!(
            kind,
            Some(ConnectFailureKind::ConnectResendLoop { rounds: 5 })
        );
    }

    #[test]
    fn classify_fast_auth_required_maps_to_token_auth_on_old_server() {
        let kind = driver::classify_connect_failure(&oracledb::Error::FastAuthRequired);
        assert_eq!(kind, Some(ConnectFailureKind::FastAuthNotAdvertised));
    }

    #[test]
    fn classify_redirect_unsupported_maps_to_listener_redirect() {
        let kind = driver::classify_connect_failure(&oracledb::Error::RedirectUnsupported);
        assert_eq!(kind, Some(ConnectFailureKind::ListenerRedirectUnsupported));
    }

    #[test]
    fn classify_listener_refused_extracts_the_err_code() {
        let payload = "(DESCRIPTION=(TMP=)(VSNNUM=301989888)(ERR=12514)(ERROR_STACK=(ERROR=(CODE=12514)(EMFI=4))))";
        let kind =
            driver::classify_connect_failure(&oracledb::Error::ListenerRefused(payload.to_owned()));
        assert_eq!(
            kind,
            Some(ConnectFailureKind::ListenerRefused {
                err_code: Some(12514),
            })
        );
    }

    #[test]
    fn classify_listener_refused_without_code_still_classifies() {
        let kind = driver::classify_connect_failure(&oracledb::Error::ListenerRefused(
            "connection refused".to_owned(),
        ));
        assert_eq!(
            kind,
            Some(ConnectFailureKind::ListenerRefused { err_code: None })
        );
    }

    #[test]
    fn classify_unsupported_tns_version_maps_to_server_generation() {
        let kind = driver::classify_connect_failure(&oracledb::Error::Protocol(
            oracledb::protocol::ProtocolError::UnsupportedVersion {
                version: 298,
                minimum: 315,
            },
        ));
        assert_eq!(
            kind,
            Some(ConnectFailureKind::ServerGenerationUnsupported {
                tns_version: Some(298),
            })
        );
    }

    #[test]
    fn classify_unsupported_feature_names_the_feature() {
        let kind = driver::classify_connect_failure(&oracledb::Error::Protocol(
            oracledb::protocol::ProtocolError::UnsupportedFeature(
                "Native Network Encryption and Data Integrity",
            ),
        ));
        assert_eq!(
            kind,
            Some(ConnectFailureKind::UnsupportedWireFeature {
                feature: "Native Network Encryption and Data Integrity".to_owned(),
            })
        );
    }

    #[test]
    fn classify_unknown_ttc_message_type_is_a_handshake_protocol_error() {
        // The field bug: this exact driver error surfaced raw, naming the TTC
        // application layer while the failing byte was a network-layer TNS
        // packet. It must classify as a handshake-phase protocol error.
        let kind = driver::classify_connect_failure(&oracledb::Error::Protocol(
            oracledb::protocol::ProtocolError::UnknownMessageType {
                message_type: 11,
                position: 4,
            },
        ));
        assert_eq!(kind, Some(ConnectFailureKind::HandshakeProtocol));
    }

    #[test]
    fn classify_wallet_error_keeps_the_plain_connect_path() {
        // Wallet diagnostics are already precise; they stay on DbError::Connect.
        let err =
            oracledb::Error::Wallet(oracledb::protocol::tls::wallet::WalletError::NoCertificates);
        assert_eq!(driver::classify_connect_failure(&err), None);
    }

    #[test]
    fn parse_listener_refuse_code_handles_absent_and_malformed_codes() {
        assert_eq!(
            driver::parse_listener_refuse_code("(ERR=12505)"),
            Some(12505)
        );
        assert_eq!(driver::parse_listener_refuse_code("(ERR=)"), None);
        assert_eq!(driver::parse_listener_refuse_code("no code here"), None);
    }

    #[test]
    fn connect_error_to_db_error_sanitizes_and_classifies() {
        let opts = crate::types::OracleConnectOptions {
            connect_string: "dbhost:1521/private_service".to_owned(),
            ..Default::default()
        };
        let err = oracledb::Error::ListenerRefused(
            "(ERR=12514) for dbhost:1521/private_service".to_owned(),
        );
        let mapped = driver::connect_error_to_db_error(&err, &opts);
        match mapped {
            DbError::ConnectHandshake { kind, message } => {
                assert_eq!(
                    kind,
                    ConnectFailureKind::ListenerRefused {
                        err_code: Some(12514),
                    }
                );
                assert!(!message.contains("private_service"), "{message}");
                assert!(message.contains("<redacted>"), "{message}");
            }
            other => panic!("expected ConnectHandshake, got {other:?}"),
        }
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
        let entries = std::fs::read_dir(dir).expect("read source directory for seam lint");
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

    fn string_field(line: &str, field: &str) -> Option<String> {
        let trimmed = line.trim();
        let rest = trimmed.strip_prefix(field)?.trim_start();
        let value = rest.strip_prefix('=')?.trim_start();
        let value = value.strip_prefix('"')?;
        let (value, _) = value.split_once('"')?;
        Some(value.to_owned())
    }

    fn lock_package_versions(lock: &str, package: &str) -> Vec<String> {
        let mut versions = Vec::new();
        let mut current_name: Option<String> = None;
        let mut current_version: Option<String> = None;

        for line in lock.lines().chain(std::iter::once("[[package]]")) {
            if line.trim() == "[[package]]" {
                if current_name.as_deref() == Some(package)
                    && let Some(version) = current_version.take()
                {
                    versions.push(version);
                }
                current_name = None;
                current_version = None;
                continue;
            }
            if current_name.is_none() {
                current_name = string_field(line, "name");
            }
            if current_version.is_none() {
                current_version = string_field(line, "version");
            }
        }

        versions
    }

    #[test]
    fn pin_is_0_7_4_and_seam_intact() {
        let root = workspace_root();
        let manifest =
            std::fs::read_to_string(root.join("Cargo.toml")).expect("read workspace Cargo.toml");
        assert!(
            manifest.contains(r#"oracledb = { version = "=0.7.4", default-features = false }"#),
            "workspace Cargo.toml must keep the oracledb dependency exactly pinned at =0.7.4"
        );

        let lock = std::fs::read_to_string(root.join("Cargo.lock")).expect("read Cargo.lock");
        assert_eq!(
            lock_package_versions(&lock, "oracledb"),
            vec!["0.7.4".to_owned()],
            "Cargo.lock must resolve exactly one oracledb package at 0.7.4"
        );
        assert_eq!(
            lock_package_versions(&lock, "oracledb-protocol"),
            vec!["0.7.4".to_owned()],
            "Cargo.lock must resolve the matching oracledb-protocol 0.7.4 package"
        );

        assert_eq!(
            ADAPTER_ALLOWLIST,
            ["crates/oraclemcp-db/src/connection.rs"],
            "the driver adapter seam must remain a single source file"
        );
    }

    #[test]
    fn upstream_expire_time_gap_is_parse_visible() {
        let descriptor = oracledb::protocol::net::EasyConnect::parse_descriptor(
            "dbhost:1521/FREEPDB1?expire_time=7&transport_connect_timeout=2.5",
        )
        .expect("extended Easy Connect string should parse");
        let desc = descriptor.first_description();

        assert_eq!(
            desc.expire_time, 7,
            "rust-oracledb#14 remains an upstream runtime keepalive wiring issue, not a parser loss"
        );
        assert!((desc.tcp_connect_timeout - 2.5).abs() < 1e-9);
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
            let contents = std::fs::read_to_string(file).expect("read Rust source for seam lint");
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

    /// True iff `line` is a real `block_on(` CALL (not a doc-comment mention).
    fn names_block_on_call(line: &str) -> bool {
        let trimmed = line.trim_start();
        // Skip doc/line comments — they may legitimately mention `block_on`.
        if trimmed.starts_with("//") {
            return false;
        }
        line.contains("block_on(")
    }

    /// B1 cancel-correctness invariant: NO `block_on` anywhere in the per-call
    /// DB path. The async migration removed the per-call `block_on` (the old
    /// `BlockingConnection` facade); every DB round trip now runs on the one
    /// ambient Asupersync runtime via `.await`. The only legitimate `block_on`s
    /// in these sources are inside `#[cfg(test)]` modules (test harness bridges
    /// that drive an async body on a one-shot runtime). This test fails if a
    /// `block_on(` call appears in PRODUCTION code under the DB-path source
    /// trees, so a regression can never silently reintroduce the per-call
    /// blocking bridge.
    #[test]
    fn no_block_on_in_db_path() {
        let root = workspace_root();
        // The per-call DB path: the canonical DB crate and the dispatcher (which
        // threads `cx` into every DB round trip). Connection ESTABLISHMENT lives
        // in `crates/oraclemcp/src/main.rs` (a one-shot startup `block_on`,
        // explicitly NOT the per-call path) and is intentionally not scanned.
        let db_path_dirs = [
            root.join("crates/oraclemcp-db/src"),
            root.join("crates/oraclemcp/src/dispatch"),
        ];
        let mut files = Vec::new();
        for dir in &db_path_dirs {
            collect_rs_files(dir, &mut files);
        }
        files.sort();
        assert!(!files.is_empty(), "no DB-path sources found");

        let mut violations: Vec<String> = Vec::new();
        for file in &files {
            let rel = file
                .strip_prefix(&root)
                .expect("file under workspace root")
                .to_string_lossy()
                .replace('\\', "/");
            // Whole `*/tests.rs` files (and `*/tests/*.rs`) are `#[cfg(test)]`
            // modules wired in by `mod tests;` — test-only by construction.
            if rel.ends_with("/tests.rs") || rel.contains("/tests/") {
                continue;
            }
            let contents = std::fs::read_to_string(file).expect("read Rust source for seam lint");

            // Track whether the current line is inside a `#[cfg(test)]` module by
            // brace depth: when a `mod ... {` follows a `#[cfg(test)]` attribute,
            // everything until its matching close brace is test-only.
            let mut depth: i32 = 0;
            let mut test_mod_depth: Option<i32> = None;
            let mut pending_cfg_test = false;
            for (n, line) in contents.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("#[cfg(test)]") {
                    pending_cfg_test = true;
                }
                let opens = line.matches('{').count() as i32;
                let closes = line.matches('}').count() as i32;
                // A `mod NAME {` opening right after a `#[cfg(test)]` attribute
                // starts the test region at the depth just before this brace.
                if pending_cfg_test && trimmed.starts_with("mod ") && opens > 0 {
                    test_mod_depth = Some(depth);
                    pending_cfg_test = false;
                } else if !trimmed.is_empty() && !trimmed.starts_with("#[") {
                    // Any other non-attribute line clears a dangling cfg(test).
                    pending_cfg_test = false;
                }
                let in_test = test_mod_depth.is_some_and(|d| depth > d);
                // A `// block-on-boundary:` marker (on the line or within the few
                // lines above, e.g. above the `RuntimeBuilder` chain) exempts the
                // sync→async dispatch ENTRY shims (driven on a one-shot runtime
                // once per tool call for non-server/test callers) — these are NOT
                // the per-call DB round-trip path the invariant targets.
                let all_lines: Vec<&str> = contents.lines().collect();
                let lookback_start = n.saturating_sub(8);
                let boundary_marker = all_lines[lookback_start..=n]
                    .iter()
                    .any(|l| l.contains("block-on-boundary:"));
                if !in_test && !boundary_marker && names_block_on_call(line) {
                    violations.push(format!("{rel}:{}: {}", n + 1, line.trim()));
                }
                depth += opens - closes;
                if let Some(d) = test_mod_depth
                    && depth <= d
                {
                    test_mod_depth = None;
                }
            }
        }

        assert!(
            violations.is_empty(),
            "B1: `block_on` found in the production DB path — the async migration \
             removed the per-call blocking bridge; every DB round trip must run \
             on the ambient runtime via `.await`. Offending sites:\n{}",
            violations.join("\n"),
        );
    }
}
