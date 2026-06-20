//! The synchronous tool dispatcher wiring the advertised read-only tool surface
//! ([`crate::registry`]) to the engine-free `oraclemcp-db` dictionary ops.
//!
//! [`OracleDispatcher`] implements [`oraclemcp_core::ToolDispatch`]: the server
//! passes an explicit Asupersync [`Cx`](asupersync::Cx) at the dispatch boundary.
//! The DB-facing work remains synchronous for this slice and guards the single
//! connection with a `std::sync::Mutex`. Every arm deserializes a small args
//! struct, runs the matching `oraclemcp_db` op against the connection, and maps
//! the result to JSON; a [`oraclemcp_db::DbError`] becomes the agent-facing
//! [`ErrorEnvelope`] via `DbError::into_envelope`. The `oracle_capabilities`
//! discovery tool is answered by the server itself and never reaches here.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use asupersync::Cx;
use asupersync::sync::Mutex as AsyncMutex;
use oraclemcp_audit::{AuditDecision, AuditEntryDraft, AuditOutcome, Auditor};
use oraclemcp_auth::apply_oauth_scopes;
use oraclemcp_config::OracleMcpConfig;
use oraclemcp_core::{
    CustomToolCatalog, CustomToolExecutor, DispatchContext, DispatchFuture, ToolBody, ToolDispatch,
    execute_custom_tool, narrow_to_read_path,
};
use oraclemcp_db::{
    DbError, DbmsOutput, OracleBind, OracleConnection, OracleConnectionInfo, QueryCaps,
    SerializeOptions, compile_errors, compile_object_statements, describe_columns,
    describe_constraints, describe_index, describe_trigger, describe_view, execute_immediate_audit,
    explain_plan, find_unused_declarations, get_ddl, get_source, get_sources_by_name, list_objects,
    list_schemas, plscope_identifiers, plscope_statements, read_lob, read_query, read_query_named,
    sample_rows, search_source, serialize_row,
};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use oraclemcp_guard::{
    Classifier, ClassifierConfig, EscalationError, GuardDecision, LevelDecision, OperatingLevel,
    SessionLevelState, StageA, stage_a,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Default cap on `oracle_search_source` result rows when the caller omits it.
const DEFAULT_SEARCH_MAX_ROWS: usize = 200;
/// Hard cap on `oracle_search_source` for a single call.
const MAX_SEARCH_MAX_ROWS: usize = 5_000;
/// Default cap on `oracle_get_source` source text when the caller omits it.
const DEFAULT_SOURCE_MAX_CHARS: usize = 1_000_000;
/// Cap on before/after snippets in `oracle_patch_source` previews.
const DEFAULT_PATCH_PREVIEW_CHARS: usize = 1_000;
/// Default cap on `oracle_schema_inspect` result rows when the caller omits it.
const DEFAULT_SCHEMA_INSPECT_MAX_ROWS: usize = 500;
/// Hard cap on `oracle_schema_inspect` for a single call.
const MAX_SCHEMA_INSPECT_MAX_ROWS: usize = 5_000;
/// Default cap on `oracle_list_schemas` result rows when the caller omits it.
const DEFAULT_SCHEMA_LIST_MAX_ROWS: usize = 200;
/// Hard cap on `oracle_list_schemas` for a single call.
const MAX_SCHEMA_LIST_MAX_ROWS: usize = 5_000;
/// Default cap on `oracle_sample_rows` when the caller omits it.
const DEFAULT_SAMPLE_MAX_ROWS: usize = 50;
/// Hard cap on `oracle_sample_rows` for a single call.
const MAX_SAMPLE_MAX_ROWS: usize = 1_000;
/// Default cap on `oracle_read_clob` text when the caller omits it.
const DEFAULT_LOB_MAX_CHARS: usize = 1_000_000;
/// Hard cap on `oracle_query` rows per page when a caller supplies max_rows/limit.
const MAX_QUERY_MAX_ROWS: usize = 5_000;
/// Hard cap on serialized bytes per `oracle_query` page.
const MAX_QUERY_RESULT_BYTES: usize = 25 * 1024 * 1024;
/// Hard cap on rows materialized into a single `oracle_query` export resource
/// (E3/E3b). Bounds the work + memory of one export independent of the inline
/// page cap; rows beyond this are dropped and the export is marked truncated.
const MAX_QUERY_EXPORT_ROWS: usize = 100_000;
/// Hard cap on text/CLOB characters materialized by a single query cell.
const MAX_QUERY_TEXT_CHARS: usize = 1_000_000;
/// Hard cap on BLOB bytes materialized by a single query cell.
const MAX_QUERY_BLOB_BYTES: usize = 5 * 1024 * 1024;
/// Default temporary session elevation window for `oracle_set_session_level`.
const DEFAULT_SESSION_LEVEL_TTL_SECONDS: u64 = 900;
/// Hard cap for one temporary session elevation window.
const MAX_SESSION_LEVEL_TTL_SECONDS: u64 = 3_600;
/// Default cap on DBMS_OUTPUT lines captured by `oracle_execute`.
const DEFAULT_DBMS_OUTPUT_MAX_LINES: usize = 200;
/// Hard cap on DBMS_OUTPUT lines captured by `oracle_execute`.
const MAX_DBMS_OUTPUT_MAX_LINES: usize = 5_000;
/// Default cap on DBMS_OUTPUT characters captured by `oracle_execute`.
const DEFAULT_DBMS_OUTPUT_MAX_CHARS: usize = 200_000;
/// Hard cap on DBMS_OUTPUT characters captured by `oracle_execute`.
const MAX_DBMS_OUTPUT_MAX_CHARS: usize = 1_000_000;
/// Hard cap on the Oracle-side DBMS_OUTPUT buffer requested for a capture.
const MAX_DBMS_OUTPUT_BUFFER_BYTES: usize = 1_000_000;
/// Compatibility TTL for `preview_sql` -> `execute_approved` cached grants.
const EXECUTE_APPROVED_TOKEN_TTL_SECONDS: u64 = 300;
/// Hard cap on remembered compatibility grants in one server process.
const MAX_EXECUTE_APPROVED_TOKENS: usize = 128;
/// Hard cap on remembered source patch previews in one server process.
const MAX_PATCH_PREVIEWS: usize = 128;
/// Hard cap on per-call Oracle round-trip timeout overrides.
const MAX_CALL_TIMEOUT_SECONDS: u64 = 3_600;

/// Reconnect callback used by `oracle_switch_profile`. Async + `Cx`-first (B1):
/// opening a connection is a native-async DB round trip, so the connector
/// returns a boxed future awaited on the dispatch runtime.
pub type ProfileConnector = dyn for<'a> Fn(
        &'a Cx,
        &'a str,
    )
        -> Pin<Box<dyn Future<Output = Result<Box<dyn OracleConnection>, DbError>> + 'a>>
    + Send
    + Sync
    + 'static;

/// Optional stateless metadata-read connector used when a profile configures a
/// local client-side pool. Async + `Cx`-first (B1).
pub type ProfileStatelessConnector = dyn for<'a> Fn(
        &'a Cx,
        &'a str,
    ) -> Pin<
        Box<dyn Future<Output = Result<Option<Box<dyn OracleConnection>>, DbError>> + 'a>,
    > + Send
    + Sync
    + 'static;

/// Profile-scoped custom-tool loader used by `oracle_switch_profile`.
pub type CustomToolLoader = dyn Fn(Option<&str>, &SessionLevelState) -> Result<CustomToolCatalog, ErrorEnvelope>
    + Send
    + Sync
    + 'static;

/// Initial connection and profile-switch connector for the optional stateless
/// metadata-read pool.
pub struct StatelessReadStrategy {
    conn: Option<Box<dyn OracleConnection>>,
    connector: Option<Arc<ProfileStatelessConnector>>,
}

impl StatelessReadStrategy {
    /// Disable the stateless metadata-read path.
    #[must_use]
    pub fn none() -> Self {
        Self {
            conn: None,
            connector: None,
        }
    }

    /// Configure the initial stateless connection and profile-switch connector.
    #[must_use]
    pub fn new(
        conn: Option<Box<dyn OracleConnection>>,
        connector: Option<Arc<ProfileStatelessConnector>>,
    ) -> Self {
        Self { conn, connector }
    }
}

fn default_read_only_level() -> SessionLevelState {
    SessionLevelState::new(OperatingLevel::ReadOnly, false)
}

fn profile_level(profile: &str) -> SessionLevelState {
    OracleMcpConfig::load(None)
        .ok()
        .and_then(|cfg| {
            cfg.profile(profile)
                .map(|profile| oraclemcp_core::session_level_state(profile, false))
        })
        .unwrap_or_else(default_read_only_level)
}

struct DispatcherState {
    conn: Box<dyn OracleConnection>,
    stateless_conn: Option<Box<dyn OracleConnection>>,
    active_profile: Option<String>,
    level: SessionLevelState,
    custom_catalog: CustomToolCatalog,
    execute_approved_tokens: HashMap<String, ExecuteApprovedGrant>,
    patch_previews: HashMap<String, PatchPreviewEntry>,
}

struct ExecuteApprovedGrant {
    sql: String,
    required_level: OperatingLevel,
    active_profile: Option<String>,
    expires_at: Instant,
}

#[derive(Clone, Debug)]
struct PatchPreviewEntry {
    active_profile: Option<String>,
    owner: String,
    name: String,
    object_type: String,
    patched_ddl: String,
    tool_name: String,
    created_at: Instant,
}

/// The dispatcher: owns the live connection behind an Asupersync [`AsyncMutex`]
/// so the now-async dispatch can hold the guard across a native-async DB round
/// trip (cancellation-safe; a `std::sync::Mutex` would be a deadlock/cancel
/// hazard across `.await`). The connection is still single-owner per dispatch
/// and never shared across threads without serialization.
pub struct OracleDispatcher {
    state: AsyncMutex<DispatcherState>,
    connector: Option<Arc<ProfileConnector>>,
    stateless_connector: Option<Arc<ProfileStatelessConnector>>,
    custom_loader: Option<Arc<CustomToolLoader>>,
    /// Out-of-band, hash-chained, keyed-MAC auditor. Constructed once in server
    /// wiring; `None` only when no operating level above ReadOnly is reachable
    /// (so no write/escalation can ever occur). Every Guarded/Destructive write
    /// (`oracle_execute`/`execute_approved`) and every `oracle_set_session_level`
    /// escalation appends a record here.
    auditor: Option<Arc<Auditor>>,
    /// Shared store for materialized large-result exports (E3). When set,
    /// oversized `oracle_query` results are exported to `oracle-export://{id}`
    /// and a `resource_link` is returned instead of inlining (E3b). `None`
    /// disables the export arm (results are inlined / row-capped as before).
    exports: Option<Arc<oraclemcp_core::ExportRegistry>>,
}

impl OracleDispatcher {
    /// Build a dispatcher over an open (or stub) connection.
    pub fn new(conn: Box<dyn OracleConnection>) -> Self {
        Self::new_with_profile(conn, None)
    }

    /// Build a dispatcher with a known active profile name.
    pub fn new_with_profile(
        conn: Box<dyn OracleConnection>,
        active_profile: Option<String>,
    ) -> Self {
        Self::new_with_profile_level(conn, active_profile, default_read_only_level())
    }

    /// Build a dispatcher with a known active profile and policy level.
    pub fn new_with_profile_level(
        conn: Box<dyn OracleConnection>,
        active_profile: Option<String>,
        level: SessionLevelState,
    ) -> Self {
        OracleDispatcher {
            state: AsyncMutex::new(DispatcherState {
                conn,
                stateless_conn: None,
                active_profile,
                level,
                custom_catalog: CustomToolCatalog::default(),
                execute_approved_tokens: HashMap::new(),
                patch_previews: HashMap::new(),
            }),
            connector: None,
            stateless_connector: None,
            custom_loader: None,
            auditor: None,
            exports: None,
        }
    }

    /// Build a dispatcher that can reconnect to other configured profiles.
    pub fn new_switchable(
        conn: Box<dyn OracleConnection>,
        active_profile: Option<String>,
        level: SessionLevelState,
        connector: Arc<ProfileConnector>,
    ) -> Self {
        Self::new_switchable_with_custom_tools(
            conn,
            active_profile,
            level,
            connector,
            CustomToolCatalog::default(),
            None,
        )
    }

    /// Build a switchable dispatcher with a profile-scoped custom-tool catalog.
    pub fn new_switchable_with_custom_tools(
        conn: Box<dyn OracleConnection>,
        active_profile: Option<String>,
        level: SessionLevelState,
        connector: Arc<ProfileConnector>,
        custom_catalog: CustomToolCatalog,
        custom_loader: Option<Arc<CustomToolLoader>>,
    ) -> Self {
        Self::new_switchable_with_custom_tools_and_stateless(
            conn,
            active_profile,
            level,
            connector,
            StatelessReadStrategy::none(),
            custom_catalog,
            custom_loader,
        )
    }

    /// Build a switchable dispatcher with a separate stateless metadata-read
    /// connection path for profile-backed pools.
    pub fn new_switchable_with_custom_tools_and_stateless(
        conn: Box<dyn OracleConnection>,
        active_profile: Option<String>,
        level: SessionLevelState,
        connector: Arc<ProfileConnector>,
        stateless: StatelessReadStrategy,
        custom_catalog: CustomToolCatalog,
        custom_loader: Option<Arc<CustomToolLoader>>,
    ) -> Self {
        OracleDispatcher {
            state: AsyncMutex::new(DispatcherState {
                conn,
                stateless_conn: stateless.conn,
                active_profile,
                level,
                custom_catalog,
                execute_approved_tokens: HashMap::new(),
                patch_previews: HashMap::new(),
            }),
            connector: Some(connector),
            stateless_connector: stateless.connector,
            custom_loader,
            auditor: None,
            exports: None,
        }
    }

    /// Attach the out-of-band auditor (builder; consumes and returns `self`).
    /// The server wiring constructs the auditor once and attaches it here so
    /// every served write/escalation is recorded on the hash-chained, signed
    /// log.
    #[must_use]
    pub fn with_auditor(mut self, auditor: Arc<Auditor>) -> Self {
        self.auditor = Some(auditor);
        self
    }

    /// Attach the shared export registry (E3/E3b; builder). When set, oversized
    /// `oracle_query` results are materialized as an `oracle-export://{id}`
    /// resource and returned as a `resource_link` instead of being inlined.
    #[must_use]
    pub fn with_exports(mut self, exports: Arc<oraclemcp_core::ExportRegistry>) -> Self {
        self.exports = Some(exports);
        self
    }
}

/// Serialize a slice of rows to a JSON array via the canonical row serializer.
fn rows_to_json(rows: &[oraclemcp_db::OracleRow]) -> Value {
    let opts = SerializeOptions::default();
    Value::Array(rows.iter().map(|r| serialize_row(r, &opts)).collect())
}

fn profiles_response(cfg: &OracleMcpConfig) -> Value {
    json!({ "profiles": cfg.list_profiles() })
}

fn optional_row_to_json(row: Option<&oraclemcp_db::OracleRow>) -> Value {
    let opts = SerializeOptions::default();
    row.map(|r| serialize_row(r, &opts)).unwrap_or(Value::Null)
}

fn query_caps_from_args(args: &QueryArgs) -> QueryCaps {
    let defaults = QueryCaps::default();
    QueryCaps {
        max_rows: args
            .max_rows
            .unwrap_or(defaults.max_rows)
            .clamp(1, MAX_QUERY_MAX_ROWS),
        max_result_bytes: args
            .max_result_bytes
            .unwrap_or(defaults.max_result_bytes)
            .clamp(1, MAX_QUERY_RESULT_BYTES),
    }
}

fn query_serialize_options_from_args(args: &QueryArgs) -> SerializeOptions {
    let defaults = SerializeOptions::default();
    SerializeOptions {
        numbers_as_float: args.numbers_as_float.unwrap_or(defaults.numbers_as_float),
        max_text_chars: args.max_col_width.map(|n| n.clamp(1, MAX_QUERY_TEXT_CHARS)),
        max_lob_chars: args
            .max_lob_chars
            .unwrap_or(defaults.max_lob_chars)
            .clamp(1, MAX_QUERY_TEXT_CHARS),
        max_blob_bytes: args
            .max_blob_bytes
            .unwrap_or(defaults.max_blob_bytes)
            .clamp(1, MAX_QUERY_BLOB_BYTES),
        ..defaults
    }
}

/// Tamper-token scope for `oracle_query` pagination cursors (E2).
const QUERY_CURSOR_SCOPE: &str = "cursor:query";

/// Stable per-query binding for an `oracle_query` pagination cursor: the SHA-256
/// of the EXACT executed SQL plus the active profile. A cursor minted for one
/// statement/profile must not let a client page a *different* statement, so the
/// offset is signed against this context (E2). The bind values are deliberately
/// NOT part of the binding — a cursor is bound to the statement shape, and the
/// caller resupplies binds with the next page exactly as MCP cursor pagination
/// expects.
fn query_cursor_binding(sql: &str, active_profile: Option<&str>) -> String {
    let sql_hash = oraclemcp_audit::sha256_hex(sql.as_bytes());
    format!("{sql_hash}|{}", active_profile.unwrap_or(""))
}

/// Decode a client-supplied opaque `oracle_query` cursor to a raw offset for
/// this exact statement/profile. Absent cursor starts at offset 0; a present
/// cursor that is forged, edited, or minted for a different statement/profile
/// is a hard `InvalidArguments` error (fail closed), never a silent reset.
fn decode_query_cursor(
    cursor: Option<&str>,
    sql: &str,
    active_profile: Option<&str>,
) -> Result<usize, ErrorEnvelope> {
    let Some(cursor) = non_empty_arg(cursor.map(str::to_owned)) else {
        return Ok(0);
    };
    let binding = query_cursor_binding(sql, active_profile);
    let payload = oraclemcp_core::verify_token(QUERY_CURSOR_SCOPE, &cursor, &[&binding])
        .ok_or_else(|| {
            invalid_args(
                "invalid or tampered oracle_query pagination cursor (it does not match this statement)",
            )
            .with_next_step("re-run oracle_query without a cursor to restart from the first page")
        })?;
    payload
        .parse::<usize>()
        .map_err(|_| invalid_args("invalid oracle_query pagination cursor payload"))
}

/// Re-sign a raw next-page offset from [`read_query`] as an opaque,
/// tamper-evident cursor bound to this statement/profile. Replaces the raw
/// `next_cursor` offset in the serialized response (E2).
fn reseal_query_cursor(mut response: Value, sql: &str, active_profile: Option<&str>) -> Value {
    let Some(offset) = response
        .get("next_cursor")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return response;
    };
    let binding = query_cursor_binding(sql, active_profile);
    let sealed = oraclemcp_core::sign_token(QUERY_CURSOR_SCOPE, &offset, &[&binding]);
    if let Value::Object(map) = &mut response {
        map.insert("next_cursor".to_owned(), Value::String(sealed));
    }
    response
}

/// Stringify one serialized query cell for an export. NUMBER/text cells are
/// already strings; everything else (booleans, the truncated-LOB object, nested
/// arrays) renders to its compact JSON so the export is lossless and unambiguous.
fn export_cell_string(cell: &Value) -> String {
    match cell {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Convert a [`oraclemcp_db::QueryResponse`]-shaped JSON value into
/// `(columns, string-cell rows)` for export materialization. Rows are objects
/// keyed by column name; cells are pulled in `columns` order.
fn query_value_to_export_rows(response: &Value) -> (Vec<String>, Vec<Vec<String>>) {
    let columns: Vec<String> = response
        .get("columns")
        .and_then(Value::as_array)
        .map(|cols| {
            cols.iter()
                .filter_map(|c| c.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let rows: Vec<Vec<String>> = response
        .get("rows")
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|row| {
                    columns
                        .iter()
                        .map(|col| row.get(col).map(export_cell_string).unwrap_or_default())
                        .collect()
                })
                .collect()
        })
        .unwrap_or_default();
    (columns, rows)
}

/// E3/E3b: materialize the bounded full result of a read query as an
/// `oracle-export://{id}` resource and return a `resource_link` result (no
/// inlined rows). Fetches up to [`MAX_QUERY_EXPORT_ROWS`] at `offset`; rows
/// beyond that are dropped and the export is flagged truncated with a next hint.
#[allow(clippy::too_many_arguments)]
async fn export_query_to_resource(
    cx: &Cx,
    conn: &dyn OracleConnection,
    executed_sql: &str,
    a: &QueryArgs,
    binds: &[OracleBind],
    offset: usize,
    active_profile: Option<&str>,
    export_scopes: Option<&[String]>,
    exports: Option<&oraclemcp_core::ExportRegistry>,
) -> Result<Value, ErrorEnvelope> {
    let format = oraclemcp_core::ExportFormat::parse(a.export_format.as_deref())
        .ok_or_else(|| invalid_args("export_format must be \"csv\" or \"json\""))?;
    let Some(exports) = exports else {
        return Err(ErrorEnvelope::new(
            ErrorClass::RuntimeStateRequired,
            "result export is not enabled in this server instance",
        )
        .with_next_step("retry without export=true to page the result inline"));
    };

    // Fetch up to the export ceiling in one window. The byte cap is raised to
    // the export ceiling so the row cap (not the inline byte cap) governs.
    let caps = QueryCaps {
        max_rows: MAX_QUERY_EXPORT_ROWS,
        max_result_bytes: oraclemcp_core::export::MAX_EXPORT_BYTES,
    };
    let response = read_query(
        cx,
        conn,
        executed_sql,
        binds,
        caps,
        offset,
        &query_serialize_options_from_args(a),
    )
    .await
    .map_err(DbError::into_envelope)?;
    let response_value = serde_json::to_value(&response).unwrap_or(Value::Null);
    let more_rows = response.truncated;
    let next_cursor = response.next_cursor.as_deref().map(|offset| {
        let binding = query_cursor_binding(&a.sql, active_profile);
        oraclemcp_core::sign_token(QUERY_CURSOR_SCOPE, offset, &[&binding])
    });

    let (columns, rows) = query_value_to_export_rows(&response_value);
    let access = oraclemcp_core::ExportAccess::new(active_profile, export_scopes);
    let handle = exports.create(
        &columns,
        &rows,
        format,
        access,
        oraclemcp_core::export::DEFAULT_EXPORT_TTL,
    );

    tracing::info!(
        export_uri = %handle.uri,
        format = ?handle.format,
        rows = handle.row_count,
        bytes = handle.byte_size,
        truncated = handle.truncated || more_rows,
        profile = active_profile.unwrap_or(""),
        "oracle_query materialized a large result as an export resource"
    );

    Ok(json!({
        "export": {
            "uri": handle.uri,
            "mime_type": handle.mime_type,
            "format": match handle.format {
                oraclemcp_core::ExportFormat::Csv => "csv",
                oraclemcp_core::ExportFormat::Json => "json",
            },
            "byte_size": handle.byte_size,
            "row_count": handle.row_count,
            "truncated": handle.truncated || more_rows,
        },
        "resource_link": {
            "type": "resource_link",
            "uri": handle.uri,
            "name": "oracle_query export",
            "mimeType": handle.mime_type,
            "description": "Materialized query result. Fetch with resources/read; access-controlled to this session and expires.",
        },
        "columns": columns,
        "row_count": handle.row_count,
        "inlined": false,
        "next_cursor": next_cursor,
        "next_step": if handle.truncated || more_rows {
            "The export was capped; re-run with the returned next_cursor to export the next window."
        } else {
            "Fetch the full result via resources/read on the export uri."
        },
    }))
}

fn call_timeout_duration(seconds: Option<u64>) -> Result<Option<Duration>, ErrorEnvelope> {
    let Some(seconds) = seconds else {
        return Ok(None);
    };
    if seconds == 0 {
        return Err(invalid_args(
            "timeout_seconds must be at least 1 when provided",
        ));
    }
    Ok(Some(Duration::from_secs(
        seconds.min(MAX_CALL_TIMEOUT_SECONDS),
    )))
}

/// Apply the per-call Oracle round-trip timeout around an async DB body.
///
/// `set_call_timeout` / `call_timeout` are synchronous interior-mutability
/// accessors (no `.await`), so the timeout is set, the future `f` is awaited,
/// and the previous value is restored — even on error/cancel.
async fn with_call_timeout<T, Fut>(
    cx: &Cx,
    conn: &dyn OracleConnection,
    timeout_seconds: Option<u64>,
    f: impl FnOnce() -> Fut,
) -> Result<T, ErrorEnvelope>
where
    Fut: Future<Output = Result<T, ErrorEnvelope>>,
{
    dispatch_checkpoint(cx, "oraclemcp.dispatch.call_timeout.before")?;
    let Some(timeout) = call_timeout_duration(timeout_seconds)? else {
        return f().await;
    };
    let previous = conn.call_timeout().map_err(DbError::into_envelope)?;
    conn.set_call_timeout(Some(timeout))
        .map_err(DbError::into_envelope)?;
    let result = f().await;
    let restore = conn
        .set_call_timeout(previous)
        .map_err(DbError::into_envelope);
    match (result, restore) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(err), Ok(())) => Err(err),
        (Ok(_), Err(err)) => Err(err),
        (Err(err), Err(_)) => Err(err),
    }
}

fn dispatch_checkpoint(cx: &Cx, phase: &'static str) -> Result<(), ErrorEnvelope> {
    cx.checkpoint_with(phase).map_err(|err| {
        ErrorEnvelope::new(ErrorClass::Timeout, format!("tool call cancelled: {err}"))
    })
}

async fn describe_conn(
    cx: &Cx,
    conn: &dyn OracleConnection,
) -> Result<OracleConnectionInfo, DbError> {
    conn.describe(cx).await
}

async fn execute_conn(
    cx: &Cx,
    conn: &dyn OracleConnection,
    sql: &str,
    binds: &[OracleBind],
) -> Result<u64, DbError> {
    conn.execute(cx, sql, binds).await
}

async fn commit_conn(cx: &Cx, conn: &dyn OracleConnection) -> Result<(), DbError> {
    conn.commit(cx).await
}

async fn enable_dbms_output_conn(
    cx: &Cx,
    conn: &dyn OracleConnection,
    buffer_bytes: Option<u32>,
) -> Result<(), DbError> {
    conn.enable_dbms_output(cx, buffer_bytes).await
}

async fn read_dbms_output_conn(
    cx: &Cx,
    conn: &dyn OracleConnection,
    max_lines: usize,
    max_chars: usize,
) -> Result<DbmsOutput, DbError> {
    conn.read_dbms_output(cx, max_lines, max_chars).await
}

mod args;
use args::*;

mod audit_marker;
use audit_marker::with_audit_marker;

/// Map a JSON value to an [`OracleBind`]. Agent argument values are always
/// bound, never interpolated. Unsupported JSON (arrays/objects) is an
/// `InvalidArguments` error rather than a silent coercion.
fn json_to_bind(v: &Value) -> Result<OracleBind, ErrorEnvelope> {
    match v {
        Value::Null => Ok(OracleBind::Null),
        Value::Bool(b) => Ok(OracleBind::Bool(*b)),
        Value::String(s) => Ok(OracleBind::String(s.clone())),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(OracleBind::I64(i))
            } else if let Some(f) = n.as_f64() {
                Ok(OracleBind::F64(f))
            } else {
                Err(invalid_args(format!("unsupported numeric bind: {n}")))
            }
        }
        other => Err(invalid_args(format!(
            "bind values must be string/number/bool/null, got: {other}"
        ))),
    }
}

/// Build an `InvalidArguments` envelope (malformed args / unknown tool).
fn invalid_args(message: impl Into<String>) -> ErrorEnvelope {
    ErrorEnvelope::new(ErrorClass::InvalidArguments, message)
}

/// Deserialize a tool's args struct, mapping a serde error to a structured
/// `InvalidArguments` envelope (never a panic).
fn parse_args<T: for<'de> Deserialize<'de>>(tool: &str, args: Value) -> Result<T, ErrorEnvelope> {
    // An MCP client may legally omit `arguments`; the transport maps that to
    // `Value::Null`, which `from_value` rejects even for all-optional structs.
    let args = match args {
        Value::Null => Value::Object(serde_json::Map::new()),
        other => other,
    };
    serde_json::from_value(args)
        .map_err(|e| invalid_args(format!("invalid arguments for {tool}: {e}")))
}

fn ensure_no_args(tool: &str, args: Value) -> Result<(), ErrorEnvelope> {
    match args {
        Value::Object(map) if map.is_empty() => Ok(()),
        Value::Null => Ok(()),
        other => Err(invalid_args(format!(
            "invalid arguments for {tool}: expected an empty object, got {other}"
        ))),
    }
}

fn non_empty_arg(value: Option<String>) -> Option<String> {
    value.and_then(|v| {
        let trimmed = v.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

async fn owner_or_current_cx(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<String>,
) -> Result<String, DbError> {
    match non_empty_arg(owner) {
        Some(owner) => Ok(owner.to_ascii_uppercase()),
        None => {
            let info = describe_conn(cx, conn).await?;
            info.current_schema
                .map(|owner| owner.to_ascii_uppercase())
                .ok_or_else(|| {
                    DbError::Query(
                        "owner is required because current_schema could not be detected".to_owned(),
                    )
                })
        }
    }
}

fn required_non_empty_arg(
    tool: &str,
    field: &str,
    value: Option<String>,
) -> Result<String, ErrorEnvelope> {
    non_empty_arg(value).ok_or_else(|| {
        invalid_args(format!(
            "invalid arguments for {tool}: missing required `{field}`"
        ))
    })
}

fn required_switch_profile_arg(tool: &str, value: Option<String>) -> Result<String, ErrorEnvelope> {
    non_empty_arg(value).ok_or_else(|| {
        invalid_args(format!(
            "invalid arguments for {tool}: provide `profile` or compatibility alias `db`"
        ))
        .with_suggested_tool("oracle_list_profiles")
        .with_next_step("call oracle_list_profiles to inspect configured profile names")
        .with_next_step(
            "call oracle_switch_profile with {\"profile\":\"<name>\"} or {\"db\":\"<name>\"}",
        )
    })
}

fn split_qualified_name(
    value: &str,
    label: &str,
) -> Result<(Option<String>, String), ErrorEnvelope> {
    let value = value.trim();
    if value.is_empty() {
        return Err(invalid_args(format!("{label} must not be empty")));
    }
    let parts: Vec<&str> = value.split('.').collect();
    match parts.as_slice() {
        [name] if !name.trim().is_empty() => Ok((None, name.trim().to_owned())),
        [owner, name] if !owner.trim().is_empty() && !name.trim().is_empty() => {
            Ok((Some(owner.trim().to_owned()), name.trim().to_owned()))
        }
        _ => Err(invalid_args(format!(
            "{label} must be an unquoted name or OWNER.NAME"
        ))),
    }
}

async fn owner_and_name_arg(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<String>,
    name: String,
    label: &str,
) -> Result<(String, String), ErrorEnvelope> {
    let explicit_owner = non_empty_arg(owner);
    let (qualified_owner, object_name) = split_qualified_name(&name, label)?;
    let owner = match (explicit_owner, qualified_owner) {
        (Some(explicit), Some(qualified)) if !explicit.eq_ignore_ascii_case(&qualified) => {
            return Err(invalid_args(format!(
                "conflicting owner arguments: owner={explicit:?}, {label}={name:?}"
            )));
        }
        (Some(explicit), _) => explicit,
        (None, Some(qualified)) => qualified,
        (None, None) => owner_or_current_cx(cx, conn, None)
            .await
            .map_err(DbError::into_envelope)?,
    };
    Ok((owner.to_ascii_uppercase(), object_name.to_ascii_uppercase()))
}

/// The fail-closed read-only gate for tools that accept a raw caller SQL
/// statement (`oracle_query`, plus the inner SQL of `oracle_explain_plan`).
/// Every such statement is run through the `oraclemcp-guard` classifier and
/// refused — *before* it can reach Oracle — unless the guard proves it needs no
/// more than `READ_ONLY`. Writes, DDL/DCL, and any `Forbidden` construct
/// (multi-statement batch, string-concat dynamic SQL, an unproven function call
/// in a SELECT, …) are rejected with a structured envelope. Proven read-only
/// `SELECT`/`WITH` and dictionary introspection pass.
///
/// The dictionary/profile tools build their own parameterized SQL or reconnect
/// from configured profiles and never execute caller-supplied statements, so
/// they need no raw-SQL gate.
fn ensure_read_only(sql: &str) -> Result<(), ErrorEnvelope> {
    let decision = Classifier::new(ClassifierConfig::new()).classify(sql);
    // A session whose ceiling is READ_ONLY: `gate` returns `Allow` only for
    // statements the guard proved read-only; everything else is `Blocked` or
    // `RequireStepUp`, both of which this (step-up-less) server rejects.
    let session = SessionLevelState::new(OperatingLevel::ReadOnly, false);
    if matches!(decision.gate(&session), LevelDecision::Allow) {
        return Ok(());
    }
    // `Forbidden` (never dispatchable at any level) vs. merely needs-a-higher-
    // level — surfaced as distinct, machine-stable error classes.
    let class = if decision.required_level.is_none() {
        ErrorClass::ForbiddenStatement
    } else {
        ErrorClass::OperatingLevelTooLow
    };
    Err(ErrorEnvelope::new(
        class,
        format!(
            "read-only server refused this statement: {}",
            decision.reason
        ),
    )
    .with_next_step(decision.safe_alternative.unwrap_or_else(|| {
        "this server accepts only read-only statements — SELECT/WITH plus the \
         dictionary tools (oracle_schema_inspect, oracle_describe, oracle_get_ddl, \
         oracle_get_source, oracle_describe_index, oracle_describe_trigger, \
         oracle_describe_view, oracle_sample_rows, oracle_read_clob, \
         oracle_compile_errors, oracle_search_source, oracle_plscope_inspect)"
            .to_owned()
    })))
}

fn explain_plan_gate_error(gate: LevelDecision, session: &SessionLevelState) -> ErrorEnvelope {
    gate_error(
        gate,
        session,
        &GateErrorLabels {
            subject: "oracle_explain_plan PLAN_TABLE diagnostic write",
            step_up_tool: "oracle_set_session_level",
            step_up_inspect_step: "call oracle_set_session_level without execute=true to preview a READ_WRITE elevation",
            step_up_elevation_step: "retry oracle_explain_plan with allow_plan_table_write=true only after the session is at READ_WRITE",
            ceiling_step: "choose a profile whose max_level permits READ_WRITE, or use DBMS_XPLAN.DISPLAY_CURSOR against an existing cursor",
            policy_denied_message: "oracle_explain_plan PLAN_TABLE diagnostic write is blocked by policy",
            internal_message: "oracle_explain_plan gate produced an unexpected decision",
        },
        None,
    )
}

fn ensure_explain_plan_write_allowed(
    args: &ExplainPlanArgs,
    session: &SessionLevelState,
) -> Result<(), ErrorEnvelope> {
    if args.read_only_standby {
        return Err(ErrorEnvelope::new(
            ErrorClass::PolicyDenied,
            "oracle_explain_plan writes PLAN_TABLE and is disabled on a read-only standby",
        )
        .with_next_step("use DBMS_XPLAN.DISPLAY_CURSOR against an existing cursor instead"));
    }

    if !args.allow_plan_table_write {
        return Err(ErrorEnvelope::new(
            ErrorClass::PolicyDenied,
            "oracle_explain_plan writes PLAN_TABLE; pass allow_plan_table_write=true only when a diagnostic write is acceptable",
        )
        .with_suggested_tool("oracle_set_session_level")
        .with_next_step("call oracle_preview_sql first if you only need to verify the inner SQL is read-only")
        .with_next_step("for primary databases where PLAN_TABLE writes are acceptable, elevate to READ_WRITE and retry with allow_plan_table_write=true"));
    }

    let gate = session.evaluate(Some(OperatingLevel::ReadWrite));
    if matches!(gate, LevelDecision::Allow) {
        Ok(())
    } else {
        Err(explain_plan_gate_error(gate, session))
    }
}

fn normalized_sql_for_confirmation(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches(';')
        .to_ascii_lowercase()
}

fn confirmation_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).expect("OS random source required for confirmation tokens");
        key
    })
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

fn confirmation_mac(parts: &[&[u8]]) -> String {
    let mut message = Vec::new();
    for part in parts {
        message.extend_from_slice(&(part.len() as u64).to_le_bytes());
        message.extend_from_slice(part);
    }
    let digest = hmac_sha256(confirmation_key(), &message);
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn execute_confirmation_token(
    sql: &str,
    required_level: OperatingLevel,
    active_profile: Option<&str>,
) -> Option<String> {
    if required_level <= OperatingLevel::ReadOnly {
        return None;
    }
    let normalized = normalized_sql_for_confirmation(sql);
    Some(confirmation_mac(&[
        b"oraclemcp:execute-confirmation:v2",
        active_profile.unwrap_or("").as_bytes(),
        required_level.as_str().as_bytes(),
        normalized.as_bytes(),
    ]))
}

fn session_level_view(session: &SessionLevelState) -> Value {
    json!({
        "current_level": session.effective_level(),
        "profile_ceiling": session.effective_ceiling(),
        "max_level": session.max_level(),
        "protected": session.is_protected(),
        "has_active_elevation": session.has_active_elevation(),
    })
}

fn parse_session_level(tool: &str, raw: &str) -> Result<OperatingLevel, ErrorEnvelope> {
    OperatingLevel::parse(raw).ok_or_else(|| {
        invalid_args(format!(
            "invalid arguments for {tool}: unknown operating level {:?}; use READ_ONLY, READ_WRITE, DDL, or ADMIN",
            raw.trim()
        ))
        .with_next_step("call oracle_set_session_level with level=\"READ_WRITE\", \"DDL\", \"ADMIN\", or \"READ_ONLY\"")
    })
}

fn ttl_from_session_level_args(args: &SetSessionLevelArgs) -> Result<u64, ErrorEnvelope> {
    let ttl = args
        .ttl_seconds
        .unwrap_or(DEFAULT_SESSION_LEVEL_TTL_SECONDS);
    if ttl == 0 || ttl > MAX_SESSION_LEVEL_TTL_SECONDS {
        return Err(invalid_args(format!(
            "ttl_seconds must be between 1 and {MAX_SESSION_LEVEL_TTL_SECONDS}"
        )));
    }
    Ok(ttl)
}

fn normalized_session_level_action(invoked_as: &str, args: &SetSessionLevelArgs) -> String {
    if invoked_as == "disable_writes" {
        return "drop".to_owned();
    }
    args.action
        .as_deref()
        .unwrap_or(if args.execute { "apply" } else { "preview" })
        .trim()
        .to_ascii_lowercase()
}

fn session_level_confirmation_token(
    active_profile: Option<&str>,
    target: OperatingLevel,
    ttl_seconds: u64,
) -> String {
    let ttl = ttl_seconds.to_string();
    confirmation_mac(&[
        b"oraclemcp:session-level-confirmation:v2",
        active_profile.unwrap_or("").as_bytes(),
        target.as_str().as_bytes(),
        ttl.as_bytes(),
    ])
}

fn session_level_gate_json(session: &SessionLevelState, target: OperatingLevel) -> Value {
    match session.evaluate(Some(target)) {
        LevelDecision::Allow => json!({
            "decision": "allow",
        }),
        LevelDecision::RequireStepUp { target } => json!({
            "decision": "require_step_up",
            "target": target,
        }),
        LevelDecision::Blocked { reason } => match reason {
            oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling } => json!({
                "decision": "blocked",
                "reason": {
                    "type": "exceeds_ceiling",
                    "required": required,
                    "ceiling": ceiling,
                },
            }),
            oraclemcp_guard::BlockReason::Forbidden => json!({
                "decision": "blocked",
                "reason": { "type": "forbidden" },
            }),
            _ => json!({
                "decision": "blocked",
                "reason": { "type": "unknown" },
            }),
        },
        _ => json!({
            "decision": "unknown",
        }),
    }
}

fn session_level_gate_error(session: &SessionLevelState, target: OperatingLevel) -> ErrorEnvelope {
    match session.evaluate(Some(target)) {
        LevelDecision::Blocked {
            reason: oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling },
        } => ErrorEnvelope::new(
            ErrorClass::OperatingLevelTooLow,
            format!(
                "session level {} exceeds the active profile ceiling {}",
                required.as_str(),
                ceiling.as_str()
            ),
        )
        .with_suggested_tool("oracle_list_profiles")
        .with_next_step("choose a profile whose max_level permits the requested operation"),
        LevelDecision::Blocked { .. } => {
            ErrorEnvelope::new(ErrorClass::PolicyDenied, "session level change is blocked")
        }
        LevelDecision::RequireStepUp { target } => ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            format!(
                "session level elevation to {} requires the confirmation token returned by oracle_set_session_level preview",
                target.as_str()
            ),
        )
        .with_suggested_tool("oracle_set_session_level")
        .with_next_step("call oracle_set_session_level without execute=true, then pass confirmation.confirm as confirm"),
        LevelDecision::Allow => ErrorEnvelope::new(
            ErrorClass::Internal,
            "session level gate unexpectedly allowed a failed request",
        ),
        _ => ErrorEnvelope::new(
            ErrorClass::Internal,
            "session level gate produced an unexpected decision",
        ),
    }
}

fn escalation_error_to_envelope(e: EscalationError) -> ErrorEnvelope {
    match e {
        EscalationError::ExceedsCeiling { requested, ceiling } => ErrorEnvelope::new(
            ErrorClass::OperatingLevelTooLow,
            format!(
                "cannot elevate to {} because the active profile ceiling is {}",
                requested.as_str(),
                ceiling.as_str()
            ),
        )
        .with_suggested_tool("oracle_list_profiles")
        .with_next_step("choose a profile whose max_level permits the requested operation"),
        _ => ErrorEnvelope::new(ErrorClass::PolicyDenied, "session level elevation rejected"),
    }
}

fn scoped_session_level(
    session: &SessionLevelState,
    context: DispatchContext<'_>,
) -> SessionLevelState {
    let mut scoped = session.clone();
    if let Some(grant) = context.scope_grant() {
        let scopes = grant.0.iter().map(String::as_str).collect::<Vec<_>>();
        apply_oauth_scopes(&mut scoped, &scopes);
    }
    scoped
}

fn session_level_response_changed(response: &Value) -> bool {
    response
        .get("changed")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && !response
            .get("preview")
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

fn set_session_level_with_scope(
    stored_session: &mut SessionLevelState,
    scoped_session: &SessionLevelState,
    active_profile: Option<&str>,
    invoked_as: &str,
    args: SetSessionLevelArgs,
    scoped: bool,
) -> Result<Value, ErrorEnvelope> {
    if !scoped {
        return set_session_level(stored_session, active_profile, invoked_as, args);
    }
    let mut request_session = scoped_session.clone();
    let response = set_session_level(
        &mut request_session,
        active_profile,
        invoked_as,
        args.clone(),
    )?;
    if session_level_response_changed(&response) {
        set_session_level(stored_session, active_profile, invoked_as, args)?;
    }
    Ok(response)
}

fn set_session_level(
    session: &mut SessionLevelState,
    active_profile: Option<&str>,
    invoked_as: &str,
    args: SetSessionLevelArgs,
) -> Result<Value, ErrorEnvelope> {
    let action = normalized_session_level_action(invoked_as, &args);
    if matches!(
        action.as_str(),
        "status" | "get" | "show" | "inspect" | "current"
    ) {
        return Ok(json!({
            "changed": false,
            "preview": false,
            "action": "status",
            "session": session_level_view(session),
        }));
    }
    if matches!(
        action.as_str(),
        "drop" | "de_escalate" | "de-escalate" | "disable" | "read_only"
    ) {
        session.drop_elevation();
        session
            .set_current_level(OperatingLevel::ReadOnly)
            .map_err(escalation_error_to_envelope)?;
        return Ok(json!({
            "changed": true,
            "preview": false,
            "action": "drop",
            "target_level": OperatingLevel::ReadOnly,
            "session": session_level_view(session),
            "next_actions": [
                {
                    "intent": "run_reads_only",
                    "tool": "oracle_query",
                    "args": { "sql": "SELECT 1 FROM dual" }
                }
            ],
        }));
    }
    if !matches!(action.as_str(), "preview" | "apply" | "execute") {
        return Err(invalid_args(format!(
            "invalid arguments for {invoked_as}: action must be preview, apply, drop, or status"
        )));
    }

    let ttl_seconds = ttl_from_session_level_args(&args)?;
    let target = if invoked_as == "enable_writes" {
        OperatingLevel::ReadWrite
    } else {
        let raw = required_non_empty_arg(invoked_as, "level", args.level)?;
        parse_session_level(invoked_as, &raw)?
    };
    if target == OperatingLevel::ReadOnly {
        session.drop_elevation();
        session
            .set_current_level(OperatingLevel::ReadOnly)
            .map_err(escalation_error_to_envelope)?;
        return Ok(json!({
            "changed": true,
            "preview": false,
            "action": "drop",
            "target_level": OperatingLevel::ReadOnly,
            "session": session_level_view(session),
        }));
    }

    let current = session.effective_level();
    if target < current {
        if action == "preview" {
            return Ok(json!({
                "changed": false,
                "preview": true,
                "action": "preview",
                "target_level": target,
                "session": session_level_view(session),
                "gate": {
                    "decision": "allow_lowering",
                    "from": current,
                    "to": target,
                },
                "confirmation": Value::Null,
                "next_actions": [
                    {
                        "intent": "apply_session_level_lowering",
                        "tool": "oracle_set_session_level",
                        "args": { "level": target, "action": "apply" }
                    }
                ],
            }));
        }
        session.drop_elevation();
        session
            .set_current_level(target)
            .map_err(escalation_error_to_envelope)?;
        return Ok(json!({
            "changed": true,
            "preview": false,
            "action": "apply",
            "target_level": target,
            "session": session_level_view(session),
            "next_actions": [
                {
                    "intent": "drop_session_level",
                    "tool": "oracle_set_session_level",
                    "args": { "action": "drop" }
                }
            ],
        }));
    }

    let gate = session.evaluate(Some(target));
    let confirm = session_level_confirmation_token(active_profile, target, ttl_seconds);
    let next_actions = match gate {
        LevelDecision::Allow => json!([
            {
                "intent": "continue",
                "message": "The active session already permits this level."
            }
        ]),
        LevelDecision::RequireStepUp { .. } => json!([
            {
                "intent": "apply_session_level",
                "tool": invoked_as,
                "args": {
                    "level": target,
                    "ttl_seconds": ttl_seconds,
                    "execute": true,
                    "confirm": confirm
                }
            },
            {
                "intent": "drop_session_level",
                "tool": "oracle_set_session_level",
                "args": { "action": "drop" }
            }
        ]),
        LevelDecision::Blocked { .. } => json!([
            {
                "intent": "choose_different_profile",
                "tool": "oracle_list_profiles",
                "args": {},
                "required_level": target,
                "current_ceiling": session.effective_ceiling()
            }
        ]),
        _ => Value::Array(Vec::new()),
    };

    if action == "preview" {
        return Ok(json!({
            "changed": false,
            "preview": true,
            "action": "preview",
            "target_level": target,
            "ttl_seconds": ttl_seconds,
            "session": session_level_view(session),
            "gate": session_level_gate_json(session, target),
            "confirmation": if matches!(gate, LevelDecision::RequireStepUp { .. }) {
                json!({
                    "tool": invoked_as,
                    "confirm": confirm,
                    "execute": true,
                    "ttl_seconds": ttl_seconds,
                    "target_level": target,
                    "note": "Pass confirm only when you intend to temporarily elevate this active session within the profile ceiling."
                })
            } else {
                Value::Null
            },
            "next_actions": next_actions,
        }));
    }

    match gate {
        LevelDecision::Allow => Ok(json!({
            "changed": false,
            "preview": false,
            "action": "apply",
            "target_level": target,
            "ttl_seconds": ttl_seconds,
            "session": session_level_view(session),
            "message": "The active session already permits this level.",
        })),
        LevelDecision::RequireStepUp { .. } => {
            if args.confirm.as_deref() != Some(confirm.as_str()) {
                return Err(session_level_gate_error(session, target));
            }
            session
                .escalate_window(target, Duration::from_secs(ttl_seconds))
                .map_err(escalation_error_to_envelope)?;
            Ok(json!({
                "changed": true,
                "preview": false,
                "action": "apply",
                "target_level": target,
                "ttl_seconds": ttl_seconds,
                "session": session_level_view(session),
                "next_actions": [
                    {
                        "intent": "drop_session_level",
                        "tool": "oracle_set_session_level",
                        "args": { "action": "drop" }
                    }
                ],
            }))
        }
        LevelDecision::Blocked { .. } => Err(session_level_gate_error(session, target)),
        _ => Err(ErrorEnvelope::new(
            ErrorClass::Internal,
            "session level gate produced an unexpected decision",
        )),
    }
}

fn execute_confirmation_json(
    sql: &str,
    decision: &GuardDecision,
    gate: &LevelDecision,
    active_profile: Option<&str>,
) -> Value {
    let Some(required_level) = decision.required_level else {
        return Value::Null;
    };
    if required_level <= OperatingLevel::ReadOnly || !matches!(gate, LevelDecision::Allow) {
        return Value::Null;
    }
    let Some(confirm) = execute_confirmation_token(sql, required_level, active_profile) else {
        return Value::Null;
    };
    json!({
        "tool": "oracle_execute",
        "confirm": confirm,
        "commit": true,
        "required_level": required_level,
        "note": "Pass confirm only when you intend to commit this exact statement on this active profile.",
    })
}

// The RequireStepUp and ExceedsCeiling next_actions arms are identical across
// every builder (preview/compile/create-or-replace/patch); only the Allow arm
// and the Forbidden message vary per tool.
fn push_step_up_actions(actions: &mut Vec<Value>, target: &OperatingLevel) {
    actions.push(json!({
        "intent": "preview_session_level_step_up",
        "tool": "oracle_set_session_level",
        "args": { "level": target, "ttl_seconds": DEFAULT_SESSION_LEVEL_TTL_SECONDS },
        "required_level": target,
    }));
    actions.push(json!({
        "intent": "choose_different_profile",
        "tool": "oracle_list_profiles",
        "args": {},
        "required_level": target,
    }));
}

fn push_exceeds_ceiling_action(
    actions: &mut Vec<Value>,
    required: &OperatingLevel,
    ceiling: &OperatingLevel,
) {
    actions.push(json!({
        "intent": "choose_different_profile",
        "tool": "oracle_list_profiles",
        "args": {},
        "required_level": required,
        "current_ceiling": ceiling,
    }));
}

fn preview_next_actions(
    sql: &str,
    decision: &GuardDecision,
    gate: &LevelDecision,
    active_profile: Option<&str>,
) -> Value {
    let mut actions: Vec<Value> = Vec::new();
    match gate {
        LevelDecision::Allow => match decision.required_level {
            Some(level) if level <= OperatingLevel::ReadOnly => {
                actions.push(json!({
                    "intent": "run_read",
                    "tool": "oracle_query",
                    "args": { "sql": sql, "binds": [] },
                }));
            }
            Some(level) if level < OperatingLevel::Ddl => {
                actions.push(json!({
                    "intent": "rollback_preview",
                    "tool": "oracle_execute",
                    "args": { "sql": sql, "binds": [], "commit": false },
                }));
                if let Some(confirm) = execute_confirmation_token(sql, level, active_profile) {
                    actions.push(json!({
                        "intent": "commit",
                        "tool": "oracle_execute",
                        "args": { "sql": sql, "binds": [], "commit": true, "confirm": confirm },
                    }));
                }
            }
            Some(level) => {
                if let Some(confirm) = execute_confirmation_token(sql, level, active_profile) {
                    actions.push(json!({
                        "intent": "commit_ddl_or_admin",
                        "tool": "oracle_execute",
                        "args": { "sql": sql, "binds": [], "commit": true, "confirm": confirm },
                    }));
                }
            }
            None => {}
        },
        LevelDecision::RequireStepUp { target } => push_step_up_actions(&mut actions, target),
        LevelDecision::Blocked { reason } => match reason {
            oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling } => {
                push_exceeds_ceiling_action(&mut actions, required, ceiling);
            }
            oraclemcp_guard::BlockReason::Forbidden => {
                actions.push(json!({
                    "intent": "rewrite_sql",
                    "message": decision.safe_alternative.clone().unwrap_or_else(|| {
                        "rewrite as a simpler single statement or use a dedicated safe tool".to_owned()
                    }),
                }));
            }
            _ => {}
        },
        _ => {}
    }
    Value::Array(actions)
}

// Per-tool copy for the shared gate-error builder. The execute and compile tools
// share the gate-decision dispatch but differ in subject noun and remediation text.
struct GateErrorLabels {
    subject: &'static str,
    step_up_tool: &'static str,
    step_up_inspect_step: &'static str,
    step_up_elevation_step: &'static str,
    ceiling_step: &'static str,
    policy_denied_message: &'static str,
    internal_message: &'static str,
}

// `decision` is Some only on the execute path, where a Forbidden gate carries a
// classifier reason and safe-alternative; the compile path never produces a
// Forbidden gate, so it passes None and Forbidden falls through to PolicyDenied.
fn gate_error(
    gate: LevelDecision,
    session: &SessionLevelState,
    labels: &GateErrorLabels,
    decision: Option<&GuardDecision>,
) -> ErrorEnvelope {
    match gate {
        LevelDecision::RequireStepUp { target } => ErrorEnvelope::new(
            ErrorClass::OperatingLevelTooLow,
            format!(
                "{} requires {} but the active session level is {}",
                labels.subject,
                target.as_str(),
                session.effective_level().as_str()
            ),
        )
        .with_suggested_tool(labels.step_up_tool)
        .with_next_step(labels.step_up_inspect_step)
        .with_next_step(labels.step_up_elevation_step),
        LevelDecision::Blocked { reason } => match reason {
            oraclemcp_guard::BlockReason::Forbidden if decision.is_some() => {
                let decision = decision.expect("decision is Some in this arm");
                ErrorEnvelope::new(
                    ErrorClass::ForbiddenStatement,
                    format!(
                        "{} is forbidden by the SQL classifier: {}",
                        labels.subject, decision.reason
                    ),
                )
                .with_next_step(decision.safe_alternative.clone().unwrap_or_else(
                    || "rewrite the statement as a simpler, single SQL statement".to_owned(),
                ))
            }
            oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling } => {
                ErrorEnvelope::new(
                    ErrorClass::OperatingLevelTooLow,
                    format!(
                        "{} requires {} but the active profile ceiling is {}",
                        labels.subject,
                        required.as_str(),
                        ceiling.as_str()
                    ),
                )
                .with_suggested_tool("oracle_list_profiles")
                .with_next_step(labels.ceiling_step)
            }
            _ => ErrorEnvelope::new(ErrorClass::PolicyDenied, labels.policy_denied_message),
        },
        _ => ErrorEnvelope::new(ErrorClass::Internal, labels.internal_message),
    }
}

fn execute_gate_error(
    decision: &GuardDecision,
    gate: LevelDecision,
    session: &SessionLevelState,
) -> ErrorEnvelope {
    gate_error(
        gate,
        session,
        &GateErrorLabels {
            subject: "statement",
            step_up_tool: "oracle_preview_sql",
            step_up_inspect_step: "call oracle_preview_sql to inspect the required level and profile ceiling",
            step_up_elevation_step: "call oracle_set_session_level to preview a temporary elevation, or keep the profile read-only",
            ceiling_step: "choose a profile whose max_level permits the statement",
            policy_denied_message: "statement is blocked by policy",
            internal_message: "execute gate produced an unexpected decision",
        },
        Some(decision),
    )
}

fn verify_commit_confirmation(
    sql: &str,
    required_level: OperatingLevel,
    active_profile: Option<&str>,
    confirm: Option<&str>,
) -> Result<(), ErrorEnvelope> {
    let expected =
        execute_confirmation_token(sql, required_level, active_profile).ok_or_else(|| {
            ErrorEnvelope::new(
                ErrorClass::InvalidArguments,
                "read-only statements do not use oracle_execute commit confirmation",
            )
        })?;
    if confirm == Some(expected.as_str()) {
        return Ok(());
    }
    Err(ErrorEnvelope::new(
        ErrorClass::ChallengeRequired,
        "commit requires the confirmation token from oracle_preview_sql for this exact statement and active profile",
    )
    .with_suggested_tool("oracle_preview_sql")
    .with_next_step("call oracle_preview_sql with the exact sql, then pass execute_confirmation.confirm as confirm"))
}

fn dbms_output_limits(args: &ExecuteArgs) -> (usize, usize, u32) {
    let max_lines = args
        .dbms_output_max_lines
        .unwrap_or(DEFAULT_DBMS_OUTPUT_MAX_LINES)
        .clamp(1, MAX_DBMS_OUTPUT_MAX_LINES);
    let max_chars = args
        .dbms_output_max_chars
        .unwrap_or(DEFAULT_DBMS_OUTPUT_MAX_CHARS)
        .clamp(1, MAX_DBMS_OUTPUT_MAX_CHARS);
    let buffer_bytes = max_chars
        .saturating_mul(4)
        .clamp(2_000, MAX_DBMS_OUTPUT_BUFFER_BYTES) as u32;
    (max_lines, max_chars, buffer_bytes)
}

fn dbms_output_json(out: &DbmsOutput, max_lines: usize, max_chars: usize) -> Value {
    json!({
        "enabled": true,
        "lines": out.lines.clone(),
        "line_count": out.line_count,
        "char_count": out.char_count,
        "max_lines": max_lines,
        "max_chars": max_chars,
        "truncated": out.truncated,
    })
}

fn prune_execute_approved_tokens(state: &mut DispatcherState) {
    let now = Instant::now();
    state
        .execute_approved_tokens
        .retain(|_, grant| grant.expires_at > now);
    while state.execute_approved_tokens.len() >= MAX_EXECUTE_APPROVED_TOKENS {
        let Some(key) = state.execute_approved_tokens.keys().next().cloned() else {
            break;
        };
        state.execute_approved_tokens.remove(&key);
    }
}

fn remember_execute_approved_token(state: &mut DispatcherState, sql: &str, preview: &Value) {
    let Some(confirm) = preview
        .pointer("/execute_confirmation/confirm")
        .and_then(Value::as_str)
    else {
        return;
    };
    let Some(required_level) = preview
        .pointer("/execute_confirmation/required_level")
        .and_then(Value::as_str)
        .and_then(OperatingLevel::parse)
    else {
        return;
    };
    prune_execute_approved_tokens(state);
    state.execute_approved_tokens.insert(
        confirm.to_owned(),
        ExecuteApprovedGrant {
            sql: sql.to_owned(),
            required_level,
            active_profile: state.active_profile.clone(),
            expires_at: Instant::now() + Duration::from_secs(EXECUTE_APPROVED_TOKEN_TTL_SECONDS),
        },
    );
}

fn execute_approved_args(
    state: &mut DispatcherState,
    session: &SessionLevelState,
    args: ExecuteApprovedArgs,
) -> Result<ExecuteArgs, ErrorEnvelope> {
    let timeout_seconds = args.timeout_seconds;
    if args.save_output.is_some() {
        return Err(invalid_args(
            "execute_approved does not write DBMS_OUTPUT to files; set capture_dbms_output=true and read dbms_output.lines from the tool result",
        )
        .with_suggested_tool("oracle_execute"));
    }

    let token = args.token.filter(|s| !s.trim().is_empty()).ok_or_else(|| {
        invalid_args("execute_approved requires token from preview_sql")
            .with_suggested_tool("preview_sql")
            .with_next_step("call preview_sql with the SQL statement, then pass execute_confirmation.confirm as token")
    })?;
    if let Some(sql) = args.sql.filter(|s| !s.trim().is_empty()) {
        return Ok(ExecuteArgs {
            sql,
            binds: Vec::new(),
            commit: args.commit.unwrap_or(true),
            confirm: Some(token),
            capture_dbms_output: args.capture_dbms_output,
            dbms_output_max_lines: args.dbms_output_max_lines,
            dbms_output_max_chars: args.dbms_output_max_chars,
            timeout_seconds,
        });
    }

    prune_execute_approved_tokens(state);
    let Some(grant) = state.execute_approved_tokens.remove(&token) else {
        return Err(ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            "execute_approved token is unknown or expired in this server process",
        )
        .with_suggested_tool("preview_sql")
        .with_next_step("call preview_sql again, then call execute_approved with the returned token within five minutes")
        .with_next_step("or call oracle_execute with sql, commit=true, and confirm"));
    };

    if grant.active_profile != state.active_profile {
        return Err(ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            "execute_approved token belongs to a different active profile",
        )
        .with_suggested_tool("preview_sql")
        .with_next_step(
            "switch back to the previewed profile or preview the SQL again on the active profile",
        ));
    }
    if session.evaluate(Some(grant.required_level)) != LevelDecision::Allow {
        return Err(execute_gate_error(
            &Classifier::new(ClassifierConfig::new()).classify(&grant.sql),
            session.evaluate(Some(grant.required_level)),
            session,
        ));
    }

    Ok(ExecuteArgs {
        sql: grant.sql,
        binds: Vec::new(),
        commit: args.commit.unwrap_or(true),
        confirm: Some(token),
        capture_dbms_output: args.capture_dbms_output,
        dbms_output_max_lines: args.dbms_output_max_lines,
        dbms_output_max_chars: args.dbms_output_max_chars,
        timeout_seconds,
    })
}

/// An RFC-3339-ish UTC timestamp for audit records (display/forensics only; the
/// monotonic seq is the chain's order key, so a coarse clock string suffices and
/// we avoid a date-formatting dependency).
fn audit_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{secs}")
}

/// Map an `oraclemcp-audit` error to an agent-facing envelope. A failed audit
/// append is fail-closed: the served call errors and the statement does NOT run.
fn audit_error_to_envelope(e: oraclemcp_audit::AuditError) -> ErrorEnvelope {
    ErrorEnvelope::new(ErrorClass::Internal, format!("audit append failed: {e}"))
}

/// The server-controlled principal recorded as the audit `agent_identity`: the
/// active profile name (a low-cardinality, server-controlled value), or the
/// binary name when no profile is bound.
fn audit_agent_identity(active_profile: Option<&str>) -> String {
    active_profile
        .map(|p| format!("profile:{p}"))
        .unwrap_or_else(|| "oraclemcp".to_owned())
}

/// Build an audit draft for an execute call at a known danger level.
fn execute_audit_draft(
    agent_identity: &str,
    sql: &str,
    danger_level: &str,
    rows_affected: Option<u64>,
    outcome: AuditOutcome,
) -> AuditEntryDraft {
    AuditEntryDraft {
        agent_identity: agent_identity.to_owned(),
        tool: "oracle_execute".to_owned(),
        sql: sql.to_owned(),
        danger_level: danger_level.to_owned(),
        decision: AuditDecision::Allowed,
        rows_affected,
        outcome,
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_sql(
    cx: &Cx,
    conn: &dyn OracleConnection,
    active_profile: Option<&str>,
    session: &SessionLevelState,
    auditor: Option<&Auditor>,
    agent_identity: &str,
    args: ExecuteArgs,
) -> Result<Value, ErrorEnvelope> {
    let timeout_seconds = args.timeout_seconds;
    with_call_timeout(cx, conn, timeout_seconds, || {
        execute_sql_inner(
            cx,
            conn,
            active_profile,
            session,
            auditor,
            agent_identity,
            args,
        )
    })
    .await
}

#[allow(clippy::too_many_arguments)]
async fn execute_sql_inner(
    cx: &Cx,
    conn: &dyn OracleConnection,
    active_profile: Option<&str>,
    session: &SessionLevelState,
    auditor: Option<&Auditor>,
    agent_identity: &str,
    args: ExecuteArgs,
) -> Result<Value, ErrorEnvelope> {
    let decision = Classifier::new(ClassifierConfig::new()).classify(&args.sql);
    let gate = decision.gate(session);
    if !matches!(gate, LevelDecision::Allow) {
        return Err(execute_gate_error(&decision, gate, session));
    }

    let required_level = decision.required_level.ok_or_else(|| {
        ErrorEnvelope::new(
            ErrorClass::ForbiddenStatement,
            format!(
                "statement is forbidden by the SQL classifier: {}",
                decision.reason
            ),
        )
    })?;
    if required_level <= OperatingLevel::ReadOnly {
        return Err(invalid_args(
            "oracle_execute is for non-read statements; use oracle_query for SELECT/WITH",
        )
        .with_suggested_tool("oracle_query"));
    }
    if required_level >= OperatingLevel::Ddl && !args.commit {
        return Err(ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            "DDL/Admin statements cannot be rollback-previewed by Oracle; commit=true and confirm are required",
        )
        .with_suggested_tool("oracle_preview_sql")
        .with_next_step("call oracle_preview_sql and pass execute_confirmation.confirm to oracle_execute with commit=true"));
    }
    if args.commit {
        verify_commit_confirmation(
            &args.sql,
            required_level,
            active_profile,
            args.confirm.as_deref(),
        )?;
    }

    let binds = args
        .binds
        .iter()
        .map(json_to_bind)
        .collect::<Result<Vec<_>, _>>()?;

    // A3: prepend the per-statement audit marker. The gate/confirmation above ran
    // on the bare SQL (the text the agent previewed/confirmed); `with_audit_marker`
    // re-classifies the marked text and adopts it ONLY when its verdict is
    // identical to the bare verdict (else it returns the bare SQL), so the text we
    // are about to execute carries the SAME, already-gated classification. We
    // additionally assert that here — defense in depth — and fail closed on any
    // divergence so a marker can never change what runs. The marked text is what
    // we execute AND what the audit log records (A8 digest covers the real text).
    let executed_sql = with_audit_marker(&args.sql, active_profile, "oracle_execute");
    if Classifier::new(ClassifierConfig::new()).classify(&executed_sql) != decision {
        return Err(ErrorEnvelope::new(
            ErrorClass::Internal,
            "audit marker changed the classifier verdict; refusing to execute",
        ));
    }

    // The audited danger tier (SAFE/GUARDED/DESTRUCTIVE) as a string; reads were
    // rejected above, so this is always a Guarded/Destructive write/DDL/Admin.
    let danger_str = serde_json::to_value(decision.danger)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "UNKNOWN".to_owned());

    // fsync-before-execute (§5.13): durably log the approved statement BEFORE it
    // runs so a crash between here and the execute leaves the log written and the
    // database untouched. A failed durable append fails the call closed.
    if let Some(auditor) = auditor {
        let pre = execute_audit_draft(
            agent_identity,
            &executed_sql,
            &danger_str,
            None,
            AuditOutcome::Pending,
        );
        auditor
            .append(&pre, audit_timestamp(), true)
            .map_err(audit_error_to_envelope)?;
    }

    let dbms_output_limits = if args.capture_dbms_output {
        let (max_lines, max_chars, buffer_bytes) = dbms_output_limits(&args);
        enable_dbms_output_conn(cx, conn, Some(buffer_bytes))
            .await
            .map_err(DbError::into_envelope)?;
        Some((max_lines, max_chars))
    } else {
        None
    };
    let rows_affected = match execute_conn(cx, conn, &executed_sql, &binds).await {
        Ok(rows) => rows,
        Err(e) => {
            let _ = conn.rollback(cx).await;
            // Durably log the failed outcome before propagating.
            if let Some(auditor) = auditor {
                let post = execute_audit_draft(
                    agent_identity,
                    &executed_sql,
                    &danger_str,
                    None,
                    AuditOutcome::Failed,
                );
                auditor
                    .append(&post, audit_timestamp(), true)
                    .map_err(audit_error_to_envelope)?;
            }
            return Err(DbError::into_envelope(e));
        }
    };
    if args.commit {
        if let Err(e) = commit_conn(cx, conn).await {
            let _ = conn.rollback(cx).await;
            if let Some(auditor) = auditor {
                let post = execute_audit_draft(
                    agent_identity,
                    &executed_sql,
                    &danger_str,
                    Some(rows_affected),
                    AuditOutcome::Failed,
                );
                auditor
                    .append(&post, audit_timestamp(), true)
                    .map_err(audit_error_to_envelope)?;
            }
            return Err(DbError::into_envelope(e));
        }
    } else {
        conn.rollback(cx).await.map_err(DbError::into_envelope)?;
    }

    // Durably log the successful (committed or rolled-back-preview) outcome.
    if let Some(auditor) = auditor {
        let post = execute_audit_draft(
            agent_identity,
            &executed_sql,
            &danger_str,
            Some(rows_affected),
            AuditOutcome::Succeeded,
        );
        auditor
            .append(&post, audit_timestamp(), true)
            .map_err(audit_error_to_envelope)?;
    }
    let dbms_output = match dbms_output_limits {
        Some((max_lines, max_chars)) => Some(
            read_dbms_output_conn(cx, conn, max_lines, max_chars)
                .await
                .map_err(DbError::into_envelope)
                .map(|out| dbms_output_json(&out, max_lines, max_chars))?,
        ),
        None => None,
    };

    let mut response = json!({
        "executed": true,
        "committed": args.commit,
        "rolled_back": !args.commit,
        "rows_affected": rows_affected,
        "required_level": required_level,
        "danger": decision.danger,
        "objects_affected": decision.objects_affected,
        "reason": decision.reason,
    });
    if let Some(dbms_output) = dbms_output {
        response["dbms_output"] = dbms_output;
    }
    Ok(response)
}

fn normalize_compile_type_for_wire(object_type: &str) -> String {
    object_type.trim().replace('_', " ").to_ascii_uppercase()
}

fn compile_confirmation_token(
    statements: &[String],
    active_profile: Option<&str>,
    owner: &str,
    name: &str,
    object_type: &str,
    plscope: bool,
) -> String {
    let plscope_part: &[u8] = if plscope { b"plscope=1" } else { b"plscope=0" };
    let mut parts = vec![
        b"oraclemcp:compile-confirmation:v2".as_slice(),
        active_profile.unwrap_or("").as_bytes(),
        owner.as_bytes(),
        name.as_bytes(),
        object_type.as_bytes(),
        plscope_part,
    ];
    for stmt in statements {
        parts.push(stmt.as_bytes());
    }
    confirmation_mac(&parts)
}

// Shared gate-and-confirm verification for the execute-path tools that mint their
// own confirmation token in a preview and re-check it on execute (compile, patch).
// Callers gate first; this enforces the token round-trip with tool-specific copy.
fn verify_token_confirmation(
    confirm: Option<String>,
    supplied: Option<&str>,
    missing_token_message: &'static str,
    challenge_message: &'static str,
    suggested_tool: &str,
    next_step: &'static str,
) -> Result<(), ErrorEnvelope> {
    let Some(expected) = confirm else {
        return Err(ErrorEnvelope::new(
            ErrorClass::Internal,
            missing_token_message,
        ));
    };
    if supplied != Some(expected.as_str()) {
        return Err(
            ErrorEnvelope::new(ErrorClass::ChallengeRequired, challenge_message)
                .with_suggested_tool(suggested_tool)
                .with_next_step(next_step),
        );
    }
    Ok(())
}

fn gate_decision_json(gate: &LevelDecision) -> (&'static str, Value, Value) {
    match gate {
        LevelDecision::Allow => ("allow", Value::Null, Value::Null),
        LevelDecision::RequireStepUp { target } => ("require_step_up", Value::Null, json!(target)),
        LevelDecision::Blocked { reason } => {
            let reason = match reason {
                oraclemcp_guard::BlockReason::Forbidden => json!({ "type": "forbidden" }),
                oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling } => {
                    json!({
                        "type": "exceeds_ceiling",
                        "required": required,
                        "ceiling": ceiling,
                    })
                }
                _ => json!({ "type": "unknown" }),
            };
            ("blocked", reason, Value::Null)
        }
        _ => ("unknown", Value::Null, Value::Null),
    }
}

fn compile_gate_error(gate: LevelDecision, session: &SessionLevelState) -> ErrorEnvelope {
    gate_error(
        gate,
        session,
        &GateErrorLabels {
            subject: "compile",
            step_up_tool: "oracle_compile_object",
            step_up_inspect_step: "call oracle_compile_object without execute=true to inspect the required level and confirmation token",
            step_up_elevation_step: "call oracle_set_session_level with level=\"DDL\" to preview a temporary elevation, or keep the profile read-only",
            ceiling_step: "choose a profile whose max_level permits DDL",
            policy_denied_message: "compile is blocked by policy",
            internal_message: "compile gate produced an unexpected decision",
        },
        None,
    )
}

fn compile_next_actions(
    gate: &LevelDecision,
    owner: &str,
    name: &str,
    object_type: &str,
    plscope: bool,
    warnings: bool,
    confirm: Option<&str>,
) -> Value {
    let mut actions = Vec::new();
    match gate {
        LevelDecision::Allow => {
            if let Some(confirm) = confirm {
                actions.push(json!({
                    "intent": "compile",
                    "tool": "oracle_compile_object",
                    "args": {
                        "owner": owner,
                        "name": name,
                        "object_type": object_type,
                        "plscope": plscope,
                        "warnings": warnings,
                        "execute": true,
                        "confirm": confirm,
                    },
                }));
            }
        }
        LevelDecision::RequireStepUp { target } => push_step_up_actions(&mut actions, target),
        LevelDecision::Blocked {
            reason: oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling },
        } => push_exceeds_ceiling_action(&mut actions, required, ceiling),
        LevelDecision::Blocked { .. } => {}
        _ => {}
    }
    Value::Array(actions)
}

fn compile_diagnostic_counts(errors: &[oraclemcp_db::OracleRow]) -> (usize, usize) {
    let error_count = errors
        .iter()
        .filter(|row| {
            row.text("ATTRIBUTE")
                .is_some_and(|attr| attr.eq_ignore_ascii_case("ERROR"))
        })
        .count();
    let warning_count = errors.len().saturating_sub(error_count);
    (error_count, warning_count)
}

async fn compile_object(
    cx: &Cx,
    conn: &dyn OracleConnection,
    active_profile: Option<&str>,
    session: &SessionLevelState,
    tool_name: &str,
    args: CompileObjectArgs,
) -> Result<Value, ErrorEnvelope> {
    let timeout_seconds = args.timeout_seconds;
    with_call_timeout(cx, conn, timeout_seconds, || {
        compile_object_inner(cx, conn, active_profile, session, tool_name, args)
    })
    .await
}

async fn compile_object_inner(
    cx: &Cx,
    conn: &dyn OracleConnection,
    active_profile: Option<&str>,
    session: &SessionLevelState,
    tool_name: &str,
    args: CompileObjectArgs,
) -> Result<Value, ErrorEnvelope> {
    let object_name = required_non_empty_arg(tool_name, "name", args.name)?;
    let (owner, object_name) =
        owner_and_name_arg(cx, conn, args.owner, object_name, "name").await?;
    let object_type = normalize_compile_type_for_wire(&args.object_type);
    let warnings = args.warnings || tool_name == "compile_with_warnings";
    let mut statements =
        compile_object_statements(&object_type, &owner, &object_name, args.plscope)
            .map_err(DbError::into_envelope)?;
    if warnings {
        statements.insert(
            0,
            "ALTER SESSION SET PLSQL_WARNINGS = 'ENABLE:ALL'".to_owned(),
        );
    }
    let gate = session.evaluate(Some(OperatingLevel::Ddl));
    let (gate_decision, blocked_reason, step_up_target) = gate_decision_json(&gate);
    let confirm = matches!(gate, LevelDecision::Allow).then(|| {
        compile_confirmation_token(
            &statements,
            active_profile,
            &owner,
            &object_name,
            &object_type,
            args.plscope,
        )
    });

    let preview = || {
        json!({
            "compiled": false,
            "preview": true,
            "owner": owner,
            "name": object_name,
            "object_type": object_type,
            "plscope": args.plscope,
            "warnings": warnings,
            "required_level": OperatingLevel::Ddl,
            "session_level": session.effective_level(),
            "profile_ceiling": session.effective_ceiling(),
            "gate_decision": gate_decision,
            "blocked_reason": blocked_reason,
            "step_up_target": step_up_target,
            "statements": statements,
            "confirmation": confirmation_block(tool_name, confirm.as_deref(), None),
            "next_actions": compile_next_actions(
                &gate,
                &owner,
                &object_name,
                &object_type,
                args.plscope,
                warnings,
                confirm.as_deref(),
            ),
        })
    };

    if !args.execute {
        return Ok(preview());
    }
    if !matches!(gate, LevelDecision::Allow) {
        return Err(compile_gate_error(gate, session));
    }
    verify_token_confirmation(
        confirm,
        args.confirm.as_deref(),
        "compile confirmation could not be generated",
        "compile requires the confirmation token from a preview of this exact object/profile/options",
        "oracle_compile_object",
        "call oracle_compile_object without execute=true, then pass confirmation.confirm with execute=true",
    )?;

    let mut rows_affected = Vec::with_capacity(statements.len());
    for stmt in &statements {
        rows_affected.push(
            execute_conn(cx, conn, stmt, &[])
                .await
                .map_err(DbError::into_envelope)?,
        );
    }
    dispatch_checkpoint(cx, "oraclemcp.dispatch.compile_errors.before")?;
    let errors = compile_errors(cx, conn, &owner, Some(&object_name))
        .await
        .map_err(DbError::into_envelope)?;
    dispatch_checkpoint(cx, "oraclemcp.dispatch.compile_errors.after")?;
    let (error_count, warning_count) = compile_diagnostic_counts(&errors);
    Ok(json!({
        "compiled": true,
        "preview": false,
        "owner": owner,
        "name": object_name,
        "object_type": object_type,
        "plscope": args.plscope,
        "warnings": warnings,
        "required_level": OperatingLevel::Ddl,
        "statements_executed": statements,
        "rows_affected": rows_affected,
        "errors": rows_to_json(&errors),
        "diagnostic_count": errors.len(),
        "error_count": error_count,
        "warning_count": warning_count,
    }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceObjectHint {
    owner: String,
    name: String,
    object_type: String,
}

fn is_simple_source_name(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(first) = parts.next() else {
        return false;
    };
    let second = parts.next();
    if parts.next().is_some() {
        return false;
    }
    let valid_part = |part: &str| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '#'))
    };
    valid_part(first) && second.is_none_or(valid_part)
}

fn clean_source_name_token(raw: &str) -> Option<String> {
    let token = raw
        .split('(')
        .next()
        .unwrap_or(raw)
        .trim()
        .trim_end_matches(';')
        .trim_matches('"');
    if is_simple_source_name(token) {
        Some(token.to_owned())
    } else {
        None
    }
}

async fn detect_create_or_replace_object(
    cx: &Cx,
    conn: &dyn OracleConnection,
    source: &str,
) -> Option<SourceObjectHint> {
    let words: Vec<&str> = source.split_whitespace().collect();
    if words.len() < 4
        || !words[0].eq_ignore_ascii_case("CREATE")
        || !words[1].eq_ignore_ascii_case("OR")
        || !words[2].eq_ignore_ascii_case("REPLACE")
    {
        return None;
    }

    let mut idx = 3;
    while matches!(
        words.get(idx).map(|w| w.to_ascii_uppercase()).as_deref(),
        Some("EDITIONABLE" | "NONEDITIONABLE" | "FORCE" | "NOFORCE")
    ) {
        idx += 1;
    }

    let first = words.get(idx)?.to_ascii_uppercase();
    let (object_type, name_idx) = match first.as_str() {
        "PACKAGE"
            if words
                .get(idx + 1)
                .is_some_and(|w| w.eq_ignore_ascii_case("BODY")) =>
        {
            ("PACKAGE BODY".to_owned(), idx + 2)
        }
        "TYPE"
            if words
                .get(idx + 1)
                .is_some_and(|w| w.eq_ignore_ascii_case("BODY")) =>
        {
            ("TYPE BODY".to_owned(), idx + 2)
        }
        "PACKAGE" | "PROCEDURE" | "FUNCTION" | "TRIGGER" | "TYPE" | "VIEW" => (first, idx + 1),
        _ => return None,
    };
    let name = clean_source_name_token(words.get(name_idx)?)?;
    let (owner, name) = owner_and_name_arg(cx, conn, None, name, "name")
        .await
        .ok()?;
    Some(SourceObjectHint {
        owner,
        name,
        object_type,
    })
}

// Preview-side confirmation block shared by the create-or-replace and patch
// previews; `note` is omitted (compile preview) or carried verbatim.
fn confirmation_block(tool: &str, confirm: Option<&str>, note: Option<&str>) -> Value {
    confirm.map_or(Value::Null, |confirm| {
        let mut block = json!({
            "tool": tool,
            "execute": true,
            "confirm": confirm,
        });
        if let (Value::Object(map), Some(note)) = (&mut block, note) {
            map.insert("note".to_owned(), json!(note));
        }
        block
    })
}

fn source_preview_json(source: &str, max_chars: usize) -> Value {
    let mut preview = String::new();
    let mut truncated = false;
    for (idx, ch) in source.chars().enumerate() {
        if idx >= max_chars {
            truncated = true;
            break;
        }
        preview.push(ch);
    }
    json!({
        "text": preview,
        "truncated": truncated,
        "max_chars": max_chars,
    })
}

fn detected_object_json(hint: Option<&SourceObjectHint>) -> Value {
    hint.map(|hint| {
        json!({
            "owner": hint.owner,
            "name": hint.name,
            "object_type": hint.object_type,
        })
    })
    .unwrap_or(Value::Null)
}

fn create_or_replace_next_actions(
    gate: &LevelDecision,
    source: &str,
    required_level: Option<OperatingLevel>,
    confirm: Option<&str>,
) -> Value {
    let mut actions = Vec::new();
    match gate {
        LevelDecision::Allow => {
            if let Some(confirm) = confirm {
                actions.push(json!({
                    "intent": "apply_create_or_replace",
                    "tool": "oracle_create_or_replace",
                    "args": {
                        "source_code": source,
                        "execute": true,
                        "confirm": confirm,
                    },
                }));
            }
        }
        LevelDecision::RequireStepUp { target } => push_step_up_actions(&mut actions, target),
        LevelDecision::Blocked { reason } => match reason {
            oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling } => {
                push_exceeds_ceiling_action(&mut actions, required, ceiling);
            }
            oraclemcp_guard::BlockReason::Forbidden => {
                actions.push(json!({
                    "intent": "rewrite_source",
                    "message": "submit one plain CREATE OR REPLACE statement without dynamic SQL or extra statements",
                }));
            }
            _ => {}
        },
        _ => {}
    }
    if matches!(gate, LevelDecision::Allow)
        && required_level.is_some_and(|l| l < OperatingLevel::Ddl)
    {
        actions.push(json!({
            "intent": "use_general_execute",
            "tool": "oracle_preview_sql",
            "args": { "sql": source },
        }));
    }
    Value::Array(actions)
}

fn create_or_replace_source_arg(
    tool_name: &str,
    value: Option<String>,
) -> Result<String, ErrorEnvelope> {
    let source = required_non_empty_arg(tool_name, "source_code", value)?;
    let normalized = source.trim_start();
    let upper = normalized.to_ascii_uppercase();
    if !upper.starts_with("CREATE OR REPLACE ") {
        return Err(invalid_args(format!(
            "invalid arguments for {tool_name}: source_code must start with CREATE OR REPLACE"
        ))
        .with_next_step("pass one full CREATE OR REPLACE statement, or use oracle_preview_sql/oracle_execute for other SQL"));
    }
    Ok(source)
}

#[derive(Clone, Debug)]
struct PatchSourceDocument {
    text: String,
    source_kind: &'static str,
    line_count: Option<usize>,
    char_count: usize,
}

fn normalize_patch_object_type(
    tool_name: &str,
    value: Option<String>,
) -> Result<String, ErrorEnvelope> {
    let value = non_empty_arg(value).or_else(|| match tool_name {
        "patch_package" => Some("PACKAGE BODY".to_owned()),
        "patch_view" => Some("VIEW".to_owned()),
        _ => None,
    });
    let Some(value) = value else {
        return Err(invalid_args(format!(
            "invalid arguments for {tool_name}: missing required `object_type`"
        ))
        .with_next_step(
            "use PACKAGE, PACKAGE_BODY, PROCEDURE, FUNCTION, TRIGGER, TYPE, TYPE_BODY, or VIEW",
        ));
    };
    let normalized = value.trim().to_ascii_uppercase().replace('_', " ");
    match normalized.as_str() {
        "PACKAGE" | "PROCEDURE" | "FUNCTION" | "TRIGGER" | "TYPE" | "VIEW" => Ok(normalized),
        "PACKAGE BODY" | "TYPE BODY" => Ok(normalized),
        _ => Err(invalid_args(format!(
            "invalid arguments for {tool_name}: unsupported object_type {value:?}"
        ))
        .with_next_step(
            "use PACKAGE, PACKAGE_BODY, PROCEDURE, FUNCTION, TRIGGER, TYPE, TYPE_BODY, or VIEW",
        )),
    }
}

fn required_patch_old_text(
    tool_name: &str,
    value: Option<String>,
) -> Result<String, ErrorEnvelope> {
    match value {
        Some(value) if !value.is_empty() => Ok(value),
        _ => Err(invalid_args(format!(
            "invalid arguments for {tool_name}: missing required non-empty `old_text`"
        ))),
    }
}

fn required_patch_new_text(
    tool_name: &str,
    value: Option<String>,
) -> Result<String, ErrorEnvelope> {
    value.ok_or_else(|| {
        invalid_args(format!(
            "invalid arguments for {tool_name}: missing required `new_text`"
        ))
    })
}

async fn fetch_patch_source_document(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
    object_type: &str,
    max_chars: usize,
) -> Result<PatchSourceDocument, ErrorEnvelope> {
    if object_type == "VIEW" {
        dispatch_checkpoint(cx, "oraclemcp.dispatch.patch.get_ddl.before")?;
        let ddl = get_ddl(cx, conn, "VIEW", owner, name)
            .await
            .map_err(DbError::into_envelope)?
            .ok_or_else(|| {
                ErrorEnvelope::new(
                    ErrorClass::ObjectNotFound,
                    format!("VIEW {owner}.{name} is not visible to this session"),
                )
                .with_suggested_tool("oracle_get_ddl")
            })?;
        dispatch_checkpoint(cx, "oraclemcp.dispatch.patch.get_ddl.after")?;
        return Ok(PatchSourceDocument {
            char_count: ddl.chars().count(),
            text: ddl,
            source_kind: "dbms_metadata",
            line_count: None,
        });
    }

    dispatch_checkpoint(cx, "oraclemcp.dispatch.patch.get_source.before")?;
    let source = get_source(cx, conn, owner, name, object_type, max_chars)
        .await
        .map_err(DbError::into_envelope)?;
    dispatch_checkpoint(cx, "oraclemcp.dispatch.patch.get_source.after")?;
    if source.line_count == 0 {
        return Err(ErrorEnvelope::new(
            ErrorClass::ObjectNotFound,
            format!("{object_type} {owner}.{name} source is not visible to this session"),
        )
        .with_suggested_tool("oracle_get_source"));
    }
    if source.truncated {
        return Err(invalid_args(format!(
            "source for {owner}.{name} was truncated at {max_chars} characters; refusing to patch partial source"
        ))
        .with_suggested_tool("oracle_get_source")
        .with_next_step("raise max_chars and preview the patch again"));
    }
    Ok(PatchSourceDocument {
        text: source.source,
        source_kind: "all_source",
        line_count: Some(source.line_count),
        char_count: source.char_count,
    })
}

fn find_unique_patch_match(
    source: &str,
    old_text: &str,
    tool_name: &str,
) -> Result<usize, ErrorEnvelope> {
    let mut matches = source.match_indices(old_text);
    let Some((first_idx, _)) = matches.next() else {
        return Err(ErrorEnvelope::new(
            ErrorClass::ObjectNotFound,
            "old_text was not found exactly in the current source",
        )
        .with_suggested_tool("oracle_get_source")
        .with_next_step("fetch the current source and pass an exact old_text slice"));
    };
    if matches.next().is_some() {
        return Err(invalid_args(format!(
            "invalid arguments for {tool_name}: old_text matches more than once; include more surrounding context"
        ))
        .with_suggested_tool("oracle_get_source"));
    }
    Ok(first_idx)
}

fn create_or_replace_ddl_from_source(source: &str) -> String {
    if source
        .trim_start()
        .to_ascii_uppercase()
        .starts_with("CREATE OR REPLACE ")
    {
        source.to_owned()
    } else {
        format!("CREATE OR REPLACE {source}")
    }
}

fn line_number_at(source: &str, byte_idx: usize) -> usize {
    source[..byte_idx].bytes().filter(|b| *b == b'\n').count() + 1
}

fn logical_line_count(value: &str) -> usize {
    if value.is_empty() {
        0
    } else {
        value.lines().count().max(1)
    }
}

fn patch_diff_json(source: &str, match_idx: usize, old_text: &str, new_text: &str) -> Value {
    json!({
        "format": "exact-replacement",
        "start_line": line_number_at(source, match_idx),
        "old_line_count": logical_line_count(old_text),
        "new_line_count": logical_line_count(new_text),
        "old_preview": source_preview_json(old_text, DEFAULT_PATCH_PREVIEW_CHARS),
        "new_preview": source_preview_json(new_text, DEFAULT_PATCH_PREVIEW_CHARS),
    })
}

fn patch_next_actions(
    tool_name: &str,
    gate: &LevelDecision,
    identity: (&str, &str, &str),
    patch: (&str, &str),
    max_chars: usize,
    confirm: Option<&str>,
) -> Value {
    let (owner, name, object_type) = identity;
    let (old_text, new_text) = patch;
    let mut actions = Vec::new();
    match gate {
        LevelDecision::Allow => {
            if let Some(confirm) = confirm {
                actions.push(json!({
                    "intent": "apply_source_patch",
                    "tool": tool_name,
                    "args": {
                        "owner": owner,
                        "name": name,
                        "object_type": object_type,
                        "old_text": old_text,
                        "new_text": new_text,
                        "max_chars": max_chars,
                        "execute": true,
                        "confirm": confirm,
                    },
                }));
            }
        }
        LevelDecision::RequireStepUp { target } => push_step_up_actions(&mut actions, target),
        LevelDecision::Blocked { reason } => match reason {
            oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling } => {
                push_exceeds_ceiling_action(&mut actions, required, ceiling);
            }
            oraclemcp_guard::BlockReason::Forbidden => {
                actions.push(json!({
                    "intent": "adjust_patch",
                    "message": "patch result must be one plain CREATE OR REPLACE statement without dynamic SQL or extra statements",
                }));
            }
            _ => {}
        },
        _ => {}
    }
    Value::Array(actions)
}

fn is_patch_body_object_type(object_type: &str) -> bool {
    matches!(object_type, "PACKAGE BODY" | "TYPE BODY")
}

fn contains_patch_side_effect_marker(source: &str) -> bool {
    // Reuse the guard's comment-stripping, token-aware Stage-A scan instead of a
    // hand-rolled substring match: a comment wedged between the two keywords of a
    // multi-word marker (`EXECUTE/**/IMMEDIATE`) defeats a plain `.contains`, but
    // not the canonicalized scan. Avoids drifting from the guard's marker set.
    matches!(
        stage_a(source, &ClassifierConfig::new()),
        StageA::PlSqlBlock { dangerous: true } | StageA::BlockListed(_)
    )
}

fn patch_preview_key(active_profile: Option<&str>, owner: &str, name: &str) -> String {
    format!(
        "{}\0{}\0{}",
        active_profile.unwrap_or(""),
        owner.to_ascii_uppercase(),
        name.to_ascii_uppercase()
    )
}

fn remember_patch_preview(state: &mut DispatcherState, entry: PatchPreviewEntry) {
    if state.patch_previews.len() >= MAX_PATCH_PREVIEWS
        && let Some(oldest_key) = state
            .patch_previews
            .iter()
            .min_by_key(|(_, entry)| entry.created_at)
            .map(|(key, _)| key.clone())
    {
        state.patch_previews.remove(&oldest_key);
    }
    let key = patch_preview_key(entry.active_profile.as_deref(), &entry.owner, &entry.name);
    state.patch_previews.insert(key, entry);
}

fn read_patch_preview(
    state: &DispatcherState,
    tool_name: &str,
    args: ReadPatchPreviewArgs,
) -> Result<Value, ErrorEnvelope> {
    let max_chars = args.max_chars.unwrap_or(100_000).clamp(1, 10_000_000);
    let active_profile = state.active_profile.as_deref();
    if let Some(name) = non_empty_arg(args.name) {
        let (_owner, name) = split_qualified_name(&name, "name")?;
        let wanted_name = name.to_ascii_uppercase();
        let mut matches = state
            .patch_previews
            .values()
            .filter(|entry| {
                entry.active_profile.as_deref() == active_profile && entry.name == wanted_name
            })
            .cloned()
            .collect::<Vec<_>>();
        matches.sort_by_key(|entry| entry.created_at);
        let Some(entry) = matches.pop() else {
            return Err(ErrorEnvelope::new(
                ErrorClass::ObjectNotFound,
                "no source patch preview is remembered for that object in the active profile",
            )
            .with_suggested_tool("oracle_patch_source")
            .with_next_step(
                "rerun oracle_patch_source, patch_package, or patch_view without execute=true",
            ));
        };
        return Ok(json!({
            "preview_available": true,
            "compatibility_tool": tool_name,
            "source": "in_memory_patch_preview",
            "active_profile": active_profile,
            "owner": entry.owner,
            "name": entry.name,
            "object_type": entry.object_type,
            "patch_tool": entry.tool_name,
            "ddl_char_count": entry.patched_ddl.chars().count(),
            "ddl_preview": source_preview_json(&entry.patched_ddl, max_chars),
            "next_actions": [
                {
                    "intent": "apply_source_patch",
                    "tool": entry.tool_name,
                    "message": "rerun the same patch tool with execute=true and the confirmation token from its preview"
                }
            ],
        }));
    }

    let mut entries = state
        .patch_previews
        .values()
        .filter(|entry| entry.active_profile.as_deref() == active_profile)
        .map(|entry| {
            json!({
                "owner": entry.owner,
                "name": entry.name,
                "object_type": entry.object_type,
                "patch_tool": entry.tool_name,
                "ddl_char_count": entry.patched_ddl.chars().count(),
            })
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| {
        a["name"]
            .as_str()
            .unwrap_or_default()
            .cmp(b["name"].as_str().unwrap_or_default())
    });
    Ok(json!({
        "preview_available": !entries.is_empty(),
        "compatibility_tool": tool_name,
        "source": "in_memory_patch_preview",
        "active_profile": active_profile,
        "preview_count": entries.len(),
        "previews": entries,
        "next_actions": if entries.is_empty() {
            json!([
                {
                    "intent": "create_source_patch_preview",
                    "tool": "oracle_patch_source",
                    "message": "run oracle_patch_source, patch_package, or patch_view without execute=true"
                }
            ])
        } else {
            json!([
                {
                    "intent": "read_one_preview",
                    "tool": "read_patch_preview",
                    "args": { "name": "<object_name>" }
                }
            ])
        },
    }))
}

async fn patch_source(
    cx: &Cx,
    conn: &dyn OracleConnection,
    active_profile: Option<&str>,
    session: &SessionLevelState,
    tool_name: &str,
    args: PatchSourceArgs,
) -> Result<(Value, Option<PatchPreviewEntry>), ErrorEnvelope> {
    let timeout_seconds = args.timeout_seconds;
    with_call_timeout(cx, conn, timeout_seconds, || {
        patch_source_inner(cx, conn, active_profile, session, tool_name, args)
    })
    .await
}

async fn patch_source_inner(
    cx: &Cx,
    conn: &dyn OracleConnection,
    active_profile: Option<&str>,
    session: &SessionLevelState,
    tool_name: &str,
    args: PatchSourceArgs,
) -> Result<(Value, Option<PatchPreviewEntry>), ErrorEnvelope> {
    let object_name = required_non_empty_arg(tool_name, "name", args.name)?;
    let object_type = normalize_patch_object_type(tool_name, args.object_type)?;
    let old_text = required_patch_old_text(tool_name, args.old_text)?;
    let new_text = required_patch_new_text(tool_name, args.new_text)?;
    let max_chars = args.max_chars.unwrap_or(DEFAULT_SOURCE_MAX_CHARS).max(1);
    let (owner, object_name) =
        owner_and_name_arg(cx, conn, args.owner, object_name, "name").await?;
    let document =
        fetch_patch_source_document(cx, conn, &owner, &object_name, &object_type, max_chars)
            .await?;
    let match_idx = find_unique_patch_match(&document.text, &old_text, tool_name)?;
    let mut patched_source = document.text.clone();
    patched_source.replace_range(match_idx..match_idx + old_text.len(), &new_text);
    let patched_ddl = if object_type == "VIEW" {
        patched_source.clone()
    } else {
        create_or_replace_ddl_from_source(&patched_source)
    };
    let patched_ddl = create_or_replace_source_arg(tool_name, Some(patched_ddl))?;
    let decision = Classifier::new(ClassifierConfig::new()).classify(&patched_ddl);
    let classifier_gate = decision.gate(session);
    let classifier_forbidden = matches!(
        &classifier_gate,
        LevelDecision::Blocked {
            reason: oraclemcp_guard::BlockReason::Forbidden
        }
    );
    let body_balance_override = classifier_forbidden
        && is_patch_body_object_type(&object_type)
        && !contains_patch_side_effect_marker(&patched_ddl);
    let patch_required_level = if decision.required_level.is_some() || body_balance_override {
        Some(OperatingLevel::Ddl)
    } else {
        None
    };
    let patch_guard_note = body_balance_override.then_some(
        "generic classifier could not balance a stored package/type body; patch path enforced DDL gate and side-effect marker scan",
    );
    let gate = if classifier_forbidden && !body_balance_override {
        classifier_gate
    } else {
        session.evaluate(patch_required_level)
    };
    let (gate_decision, blocked_reason, step_up_target) = gate_decision_json(&gate);
    let confirm = match (patch_required_level, &gate) {
        (Some(level), LevelDecision::Allow) => {
            execute_confirmation_token(&patched_ddl, level, active_profile)
        }
        _ => None,
    };

    if !args.execute {
        let preview_entry = confirm.as_ref().map(|_| PatchPreviewEntry {
            active_profile: active_profile.map(str::to_owned),
            owner: owner.clone(),
            name: object_name.clone(),
            object_type: object_type.clone(),
            patched_ddl: patched_ddl.clone(),
            tool_name: tool_name.to_owned(),
            created_at: Instant::now(),
        });
        return Ok((
            json!({
                "applied": false,
                "preview": true,
                "owner": owner,
                "name": object_name,
                "object_type": object_type,
                "source_kind": document.source_kind,
                "line_count": document.line_count,
                "char_count": document.char_count,
                "match_count": 1,
                "diff": patch_diff_json(&document.text, match_idx, &old_text, &new_text),
                "patched_source_preview": source_preview_json(&patched_source, DEFAULT_PATCH_PREVIEW_CHARS),
                "patched_ddl_preview": source_preview_json(&patched_ddl, DEFAULT_PATCH_PREVIEW_CHARS),
                "danger": decision.danger,
                "required_level": patch_required_level,
                "session_level": session.effective_level(),
                "profile_ceiling": session.effective_ceiling(),
                "gate_decision": gate_decision,
                "blocked_reason": blocked_reason,
                "step_up_target": step_up_target,
                "reason": decision.reason,
                "patch_guard_note": patch_guard_note,
                "confirmation": confirmation_block(
                    tool_name,
                    confirm.as_deref(),
                    Some("Pass confirm only when you intend to apply this exact source patch on this active profile."),
                ),
                "next_actions": patch_next_actions(
                    tool_name,
                    &gate,
                    (&owner, &object_name, &object_type),
                    (&old_text, &new_text),
                    max_chars,
                    confirm.as_deref(),
                ),
            }),
            preview_entry,
        ));
    }

    if !matches!(gate, LevelDecision::Allow) {
        return Err(execute_gate_error(&decision, gate, session));
    }
    verify_token_confirmation(
        confirm,
        args.confirm.as_deref(),
        "patch confirmation could not be generated",
        "source patch requires the confirmation token from a preview of this exact object/profile/patch",
        tool_name,
        "call the patch tool without execute=true, then pass confirmation.confirm with execute=true",
    )?;

    let rows_affected = match execute_conn(cx, conn, &patched_ddl, &[]).await {
        Ok(rows) => rows,
        Err(e) => {
            let _ = conn.rollback(cx).await;
            return Err(DbError::into_envelope(e));
        }
    };
    if let Err(e) = commit_conn(cx, conn).await {
        let _ = conn.rollback(cx).await;
        return Err(DbError::into_envelope(e));
    }
    let include_errors = args.include_errors.unwrap_or(true);
    let errors = if include_errors {
        dispatch_checkpoint(cx, "oraclemcp.dispatch.patch.compile_errors.before")?;
        Some(
            compile_errors(cx, conn, &owner, Some(&object_name))
                .await
                .map_err(DbError::into_envelope)?,
        )
    } else {
        None
    };
    if include_errors {
        dispatch_checkpoint(cx, "oraclemcp.dispatch.patch.compile_errors.after")?;
    }
    Ok((
        json!({
            "applied": true,
            "preview": false,
            "executed": true,
            "committed": true,
            "rows_affected": rows_affected,
            "patch_tool": tool_name,
            "owner": owner,
            "name": object_name,
            "object_type": object_type,
            "source_kind": document.source_kind,
            "required_level": OperatingLevel::Ddl,
            "danger": decision.danger,
            "objects_affected": decision.objects_affected,
            "reason": decision.reason,
            "patch_guard_note": patch_guard_note,
            "diff": patch_diff_json(&document.text, match_idx, &old_text, &new_text),
            "errors": errors.as_ref().map(|rows| rows_to_json(rows)),
            "error_count": errors.as_ref().map(Vec::len),
        }),
        None,
    ))
}

// Audit context (auditor + agent_identity) is threaded through the DDL path so
// every CREATE OR REPLACE is hash-chained (A8). TODO(simplify): bundle the audit
// context into an `AuditCtx` to drop back under the arg-count lint.
#[allow(clippy::too_many_arguments)]
async fn create_or_replace(
    cx: &Cx,
    conn: &dyn OracleConnection,
    active_profile: Option<&str>,
    session: &SessionLevelState,
    auditor: Option<&Auditor>,
    agent_identity: &str,
    tool_name: &str,
    args: CreateOrReplaceArgs,
) -> Result<Value, ErrorEnvelope> {
    let timeout_seconds = args.timeout_seconds;
    with_call_timeout(cx, conn, timeout_seconds, || {
        create_or_replace_inner(
            cx,
            conn,
            active_profile,
            session,
            auditor,
            agent_identity,
            tool_name,
            args,
        )
    })
    .await
}

#[allow(clippy::too_many_arguments)]
async fn create_or_replace_inner(
    cx: &Cx,
    conn: &dyn OracleConnection,
    active_profile: Option<&str>,
    session: &SessionLevelState,
    auditor: Option<&Auditor>,
    agent_identity: &str,
    tool_name: &str,
    args: CreateOrReplaceArgs,
) -> Result<Value, ErrorEnvelope> {
    let source = create_or_replace_source_arg(tool_name, args.source_code)?;
    let decision = Classifier::new(ClassifierConfig::new()).classify(&source);
    let gate = decision.gate(session);
    let (gate_decision, blocked_reason, step_up_target) = gate_decision_json(&gate);
    let detected = detect_create_or_replace_object(cx, conn, &source).await;
    let confirm = match (decision.required_level, &gate) {
        (Some(level), LevelDecision::Allow) if level >= OperatingLevel::Ddl => {
            execute_confirmation_token(&source, level, active_profile)
        }
        _ => None,
    };

    if !args.execute {
        return Ok(json!({
            "applied": false,
            "preview": true,
            "source_preview": source_preview_json(&source, 500),
            "detected_object": detected_object_json(detected.as_ref()),
            "danger": decision.danger,
            "required_level": decision.required_level,
            "session_level": session.effective_level(),
            "profile_ceiling": session.effective_ceiling(),
            "gate_decision": gate_decision,
            "blocked_reason": blocked_reason,
            "step_up_target": step_up_target,
            "reason": decision.reason,
            "confirmation": confirmation_block(
                "oracle_create_or_replace",
                confirm.as_deref(),
                Some("Pass confirm only when you intend to apply this exact CREATE OR REPLACE statement on this active profile."),
            ),
            "next_actions": create_or_replace_next_actions(
                &gate,
                &source,
                decision.required_level,
                confirm.as_deref(),
            ),
        }));
    }

    if !matches!(gate, LevelDecision::Allow) {
        return Err(execute_gate_error(&decision, gate, session));
    }
    let mut executed = execute_sql(
        cx,
        conn,
        active_profile,
        session,
        auditor,
        agent_identity,
        ExecuteArgs {
            sql: source.clone(),
            binds: Vec::new(),
            commit: true,
            confirm: args.confirm,
            capture_dbms_output: false,
            dbms_output_max_lines: None,
            dbms_output_max_chars: None,
            timeout_seconds: args.timeout_seconds,
        },
    )
    .await?;
    let include_errors = args.include_errors.unwrap_or(true);
    if let Value::Object(map) = &mut executed {
        map.insert("applied".to_owned(), json!(true));
        map.insert("preview".to_owned(), json!(false));
        map.insert(
            "detected_object".to_owned(),
            detected_object_json(detected.as_ref()),
        );
        if include_errors {
            if let Some(hint) = detected.as_ref() {
                dispatch_checkpoint(
                    cx,
                    "oraclemcp.dispatch.create_or_replace.compile_errors.before",
                )?;
                let errors = compile_errors(cx, conn, &hint.owner, Some(&hint.name))
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(
                    cx,
                    "oraclemcp.dispatch.create_or_replace.compile_errors.after",
                )?;
                map.insert("errors".to_owned(), rows_to_json(&errors));
                map.insert("error_count".to_owned(), json!(errors.len()));
            } else {
                map.insert("errors".to_owned(), Value::Null);
                map.insert("error_count".to_owned(), Value::Null);
                map.insert(
                    "error_lookup_note".to_owned(),
                    json!("object name could not be inferred from the source"),
                );
            }
        }
    }
    Ok(executed)
}

#[allow(clippy::too_many_arguments)]
async fn deploy_ddl(
    cx: &Cx,
    conn: &dyn OracleConnection,
    active_profile: Option<&str>,
    session: &SessionLevelState,
    auditor: Option<&Auditor>,
    agent_identity: &str,
    args: DeployDdlArgs,
) -> Result<Value, ErrorEnvelope> {
    let timeout_seconds = args.timeout_seconds;
    with_call_timeout(cx, conn, timeout_seconds, || {
        deploy_ddl_inner(
            cx,
            conn,
            active_profile,
            session,
            auditor,
            agent_identity,
            args,
        )
    })
    .await
}

#[allow(clippy::too_many_arguments)]
async fn deploy_ddl_inner(
    cx: &Cx,
    conn: &dyn OracleConnection,
    active_profile: Option<&str>,
    session: &SessionLevelState,
    auditor: Option<&Auditor>,
    agent_identity: &str,
    args: DeployDdlArgs,
) -> Result<Value, ErrorEnvelope> {
    let ddl = required_non_empty_arg("deploy_ddl", "ddl", args.ddl)?;
    let deploy_name = non_empty_arg(args.name);
    let wait_seconds = args.wait_seconds.unwrap_or(0);
    if ddl
        .trim_start()
        .to_ascii_uppercase()
        .starts_with("CREATE OR REPLACE ")
    {
        let mut out = create_or_replace(
            cx,
            conn,
            active_profile,
            session,
            auditor,
            agent_identity,
            "deploy_ddl",
            CreateOrReplaceArgs {
                source_code: Some(ddl),
                execute: args.execute,
                confirm: args.confirm,
                include_errors: args.include_errors,
                timeout_seconds: args.timeout_seconds,
            },
        )
        .await?;
        if let Value::Object(map) = &mut out {
            map.insert("deploy_name".to_owned(), json!(deploy_name));
            map.insert("wait_seconds".to_owned(), json!(wait_seconds));
            map.insert("compatibility_tool".to_owned(), json!("deploy_ddl"));
        }
        return Ok(out);
    }

    let decision = Classifier::new(ClassifierConfig::new()).classify(&ddl);
    let required_level = decision.required_level.ok_or_else(|| {
        ErrorEnvelope::new(
            ErrorClass::ForbiddenStatement,
            format!(
                "statement is forbidden by the SQL classifier: {}",
                decision.reason
            ),
        )
    })?;
    if required_level < OperatingLevel::Ddl {
        return Err(invalid_args(
            "deploy_ddl is for DDL statements; use oracle_preview_sql/oracle_execute for DML",
        )
        .with_suggested_tool("oracle_preview_sql"));
    }

    if !args.execute {
        let mut preview = preview_sql(&ddl, session, active_profile);
        if let Value::Object(map) = &mut preview {
            map.insert("preview".to_owned(), json!(true));
            map.insert("applied".to_owned(), json!(false));
            map.insert("deploy_name".to_owned(), json!(deploy_name));
            map.insert("wait_seconds".to_owned(), json!(wait_seconds));
            map.insert("source_preview".to_owned(), source_preview_json(&ddl, 500));
            map.insert("compatibility_tool".to_owned(), json!("deploy_ddl"));
            if let Some(confirm) = map
                .get("execute_confirmation")
                .and_then(|v| v.get("confirm"))
                .and_then(Value::as_str)
                .map(str::to_owned)
            {
                map.insert(
                    "confirmation".to_owned(),
                    json!({
                        "tool": "deploy_ddl",
                        "execute": true,
                        "confirm": confirm,
                        "note": "Pass confirm only when you intend to apply this exact DDL statement on this active profile."
                    }),
                );
            }
        }
        return Ok(preview);
    }

    let mut out = execute_sql(
        cx,
        conn,
        active_profile,
        session,
        auditor,
        agent_identity,
        ExecuteArgs {
            sql: ddl,
            binds: Vec::new(),
            commit: true,
            confirm: args.confirm,
            capture_dbms_output: false,
            dbms_output_max_lines: None,
            dbms_output_max_chars: None,
            timeout_seconds: args.timeout_seconds,
        },
    )
    .await?;
    if let Value::Object(map) = &mut out {
        map.insert("applied".to_owned(), json!(true));
        map.insert("preview".to_owned(), json!(false));
        map.insert("deploy_name".to_owned(), json!(deploy_name));
        map.insert("wait_seconds".to_owned(), json!(wait_seconds));
        map.insert("compatibility_tool".to_owned(), json!("deploy_ddl"));
    }
    Ok(out)
}

struct ReadOnlyCustomToolExecutor<'a> {
    cx: &'a Cx,
    conn: &'a dyn OracleConnection,
}

#[async_trait::async_trait(?Send)]
impl CustomToolExecutor for ReadOnlyCustomToolExecutor<'_> {
    async fn run(
        &self,
        body: ToolBody<'_>,
        level: OperatingLevel,
        binds: &[(String, OracleBind)],
    ) -> Result<Value, ErrorEnvelope> {
        if level > OperatingLevel::ReadOnly {
            return Err(ErrorEnvelope::new(
                ErrorClass::OperatingLevelTooLow,
                format!(
                    "custom tool requires {} but this server executes only READ_ONLY custom tools",
                    level.as_str()
                ),
            )
            .with_next_step(
                "move write or DDL workflows behind a separate guarded execution service",
            ));
        }

        let sql = match body {
            ToolBody::InlineSql(sql) => sql.to_owned(),
            ToolBody::PackageCall(call) => format!("SELECT {call} AS VALUE FROM dual"),
        };
        ensure_read_only(&sql)?;
        // A9: operator-defined read tools also narrow the handler context to the
        // read-path capability row (the DB round trip itself takes the full
        // `cx`, like the oracle_query arm).
        let _read_cx = narrow_to_read_path(self.cx);
        read_query_named(
            self.cx,
            self.conn,
            &sql,
            binds,
            QueryCaps::default(),
            0,
            &SerializeOptions::default(),
        )
        .await
        .map(|resp| serde_json::to_value(resp).unwrap_or(Value::Null))
        .map_err(DbError::into_envelope)
    }
}

fn preview_sql(sql: &str, session: &SessionLevelState, active_profile: Option<&str>) -> Value {
    let decision = Classifier::new(ClassifierConfig::new()).classify(sql);
    let gate = decision.gate(session);
    let (gate_decision, blocked_reason, step_up_target) = match gate {
        LevelDecision::Allow => ("allow", Value::Null, Value::Null),
        LevelDecision::RequireStepUp { target } => ("require_step_up", Value::Null, json!(target)),
        LevelDecision::Blocked { reason } => {
            let reason = match reason {
                oraclemcp_guard::BlockReason::Forbidden => {
                    json!({ "type": "forbidden" })
                }
                oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling } => {
                    json!({
                        "type": "exceeds_ceiling",
                        "required": required,
                        "ceiling": ceiling,
                    })
                }
                _ => json!({ "type": "unknown" }),
            };
            ("blocked", reason, Value::Null)
        }
        _ => ("unknown", Value::Null, Value::Null),
    };

    json!({
        "danger": decision.danger,
        "required_level": decision.required_level,
        "allowed_on_read_only": matches!(
            decision.gate(&SessionLevelState::new(OperatingLevel::ReadOnly, false)),
            LevelDecision::Allow
        ),
        "session_level": session.effective_level(),
        "profile_ceiling": session.effective_ceiling(),
        "protected": session.is_protected(),
        "gate_decision": gate_decision,
        "blocked_reason": blocked_reason,
        "step_up_target": step_up_target,
        "objects_affected": decision.objects_affected,
        "reason": decision.reason,
        "safe_alternative": decision.safe_alternative,
        "execute_confirmation": execute_confirmation_json(sql, &decision, &gate, active_profile),
        "next_actions": preview_next_actions(sql, &decision, &gate, active_profile),
    })
}

fn connection_info_json(
    active_profile: Option<String>,
    info: Result<OracleConnectionInfo, DbError>,
) -> Value {
    match info {
        Ok(info) => json!({
            "active_profile": active_profile,
            "connected": true,
            "connection": info,
        }),
        Err(err) => {
            let mut next_actions = vec![json!({
                "intent": "inspect_profiles",
                "tool": "oracle_list_profiles",
                "args": {},
            })];
            let doctor_args = match active_profile.as_deref() {
                Some(profile) => json!(["--json", "doctor", "--profile", profile]),
                None => json!(["--json", "doctor"]),
            };
            next_actions.push(json!({
                "intent": "run_cli_doctor",
                "command": "oraclemcp",
                "args": doctor_args,
            }));

            json!({
                "active_profile": active_profile,
                "connected": false,
                "connection": Value::Null,
                "connection_error": err
                    .into_envelope()
                    .with_suggested_tool("oracle_list_profiles")
                    .to_json(),
                "next_actions": next_actions,
            })
        }
    }
}

async fn connection_strategy_json(cx: &Cx, conn: &dyn OracleConnection) -> Value {
    match describe_conn(cx, conn).await {
        Ok(info) => json!({
            "connected": true,
            "strategy": info.connection_strategy,
            "pool_open_connections": info.pool_open_connections,
        }),
        Err(err) => json!({
            "connected": false,
            "connection_error": err.into_envelope(),
        }),
    }
}

fn canonical_tool_name(name: &str) -> &str {
    match name {
        "current_database" => "oracle_connection_info",
        "switch_database" => "oracle_switch_profile",
        "enable_writes" | "disable_writes" => "oracle_set_session_level",
        "query" => "oracle_query",
        "list_objects" => "oracle_schema_inspect",
        "list_schemas" => "oracle_list_schemas",
        "get_schema" => "oracle_schema_inspect",
        "compile_object" | "compile_with_warnings" => "oracle_compile_object",
        "create_or_replace" => "oracle_create_or_replace",
        "patch_package" | "patch_view" => "oracle_patch_source",
        "execute_approved" => "execute_approved",
        "deploy_ddl" => "deploy_ddl",
        "describe_table" => "oracle_describe",
        "describe_index" => "oracle_describe_index",
        "describe_trigger" => "oracle_describe_trigger",
        "describe_view" => "oracle_describe_view",
        "get_ddl" => "oracle_get_ddl",
        "get_object_source" => "oracle_get_source",
        "get_errors" => "oracle_compile_errors",
        "get_clob" => "oracle_read_clob",
        "preview_sql" => "oracle_preview_sql",
        other => other,
    }
}

impl ToolDispatch for OracleDispatcher {
    fn dispatch<'a>(
        &'a self,
        cx: &'a Cx,
        context: DispatchContext<'a>,
        name: &'a str,
        args: Value,
    ) -> DispatchFuture<'a> {
        Box::pin(async move { self.dispatch_with_cx_inner(cx, context, name, args).await })
    }
}

impl OracleDispatcher {
    /// Synchronous concrete dispatch used by focused dispatcher tests and the
    /// non-Cx convenience callers. Builds a one-shot current-thread Asupersync
    /// runtime to drive the now-async dispatch and obtain a request `Cx`.
    pub fn dispatch(&self, name: &str, args: Value) -> Result<Value, ErrorEnvelope> {
        self.dispatch_blocking(DispatchContext::default(), name, args)
    }

    /// Synchronous concrete dispatch with an explicit Asupersync cancellation
    /// context. DB-backed tool arms classify/gate input before calling Cx-aware
    /// DB methods.
    pub fn dispatch_with_cx(
        &self,
        cx: &Cx,
        name: &str,
        args: Value,
    ) -> Result<Value, ErrorEnvelope> {
        // Drive the async body to completion on a one-shot current-thread
        // runtime, but thread the CALLER's `cx` (clone) through — its
        // cancellation/budget state is the contract the dispatch must honor (a
        // fresh runtime's ambient Cx would lose a pre-cancelled request).
        let caller_cx = cx.clone();
        // block-on-boundary: sync->async dispatch ENTRY shim (not the per-call
        // DB round-trip path). The server's real entry is the async
        // `ToolDispatch::dispatch` which is `.await`-ed on the dispatch runtime;
        // this sync wrapper exists only for non-server/test callers.
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime")
            .block_on(async move {
                self.dispatch_with_cx_inner(&caller_cx, DispatchContext::default(), name, args)
                    .await
            })
    }

    /// Synchronous concrete dispatch with a transport authorization context.
    pub fn dispatch_with_context(
        &self,
        name: &str,
        args: Value,
        context: DispatchContext<'_>,
    ) -> Result<Value, ErrorEnvelope> {
        self.dispatch_blocking(context, name, args)
    }

    /// Drive the async dispatch to completion on a one-shot current-thread
    /// runtime, supplying the installed request `Cx`.
    fn dispatch_blocking(
        &self,
        context: DispatchContext<'_>,
        name: &str,
        args: Value,
    ) -> Result<Value, ErrorEnvelope> {
        // block-on-boundary: sync->async dispatch ENTRY shim (not the per-call
        // DB round-trip path); see `dispatch_with_cx`.
        asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime")
            .block_on(async move {
                let cx = Cx::current().expect("block_on installs a request Cx");
                self.dispatch_with_cx_inner(&cx, context, name, args).await
            })
    }

    async fn dispatch_with_cx_inner(
        &self,
        cx: &Cx,
        context: DispatchContext<'_>,
        name: &str,
        args: Value,
    ) -> Result<Value, ErrorEnvelope> {
        dispatch_checkpoint(cx, "oraclemcp.dispatch.start")?;
        let tool = canonical_tool_name(name);
        if tool == "oracle_switch_profile" {
            let a: SwitchProfileArgs = parse_args(name, args)?;
            let profile = required_switch_profile_arg(name, a.profile)?;
            let Some(connector) = &self.connector else {
                return Err(ErrorEnvelope::new(
                    ErrorClass::RuntimeStateRequired,
                    "profile switching is unavailable in this server instance",
                )
                .with_next_step("restart the server with `oraclemcp serve --profile <name>`"));
            };

            let new_conn = connector(cx, &profile)
                .await
                .map_err(DbError::into_envelope)?;
            let new_stateless_conn = match &self.stateless_connector {
                Some(connector) => connector(cx, &profile)
                    .await
                    .map_err(DbError::into_envelope)?,
                None => None,
            };
            let mut response = connection_info_json(
                Some(profile.clone()),
                describe_conn(cx, new_conn.as_ref()).await,
            );
            if let Value::Object(map) = &mut response
                && let Some(stateless_conn) = new_stateless_conn.as_ref()
            {
                map.insert(
                    "stateless_read_connection".to_owned(),
                    connection_strategy_json(cx, stateless_conn.as_ref()).await,
                );
            }
            let new_level = profile_level(&profile);
            let new_custom_catalog = match &self.custom_loader {
                Some(loader) => loader(Some(&profile), &new_level)?,
                None => CustomToolCatalog::default(),
            };
            let mut state = self.state.lock(cx).await.map_err(|_| {
                ErrorEnvelope::new(ErrorClass::Internal, "connection mutex lock failed")
            })?;
            state.conn = new_conn;
            state.stateless_conn = new_stateless_conn;
            state.active_profile = Some(profile.clone());
            state.level = new_level;
            state.custom_catalog = new_custom_catalog;
            state.execute_approved_tokens.clear();
            state.patch_previews.clear();
            if let Value::Object(map) = &mut response {
                map.insert(
                    "custom_tool_count".to_owned(),
                    json!(state.custom_catalog.len()),
                );
            }
            return Ok(response);
        }

        // The async mutex serializes dispatch over the single connection and is
        // safe to hold across the DB `.await`s below (the dispatch future is
        // `!Send` and never spawned cross-thread). A lock failure surfaces as an
        // Internal error rather than a panic.
        let mut state = self.state.lock(cx).await.map_err(|_| {
            ErrorEnvelope::new(ErrorClass::Internal, "connection mutex lock failed")
        })?;
        let scoped_level = scoped_session_level(&state.level, context);
        let scoped = context.scope_grant().is_some();
        if tool == "oracle_set_session_level" {
            let a: SetSessionLevelArgs = parse_args(name, args)?;
            let active_profile = state.active_profile.clone();
            let before = state.level.effective_level();
            let result = set_session_level_with_scope(
                &mut state.level,
                &scoped_level,
                active_profile.as_deref(),
                name,
                a,
                scoped,
            );
            // Audit a successful level INCREASE (step-up approval). De-escalation
            // and status reads are not escalations and are not chained.
            if let (Ok(value), Some(auditor)) = (&result, self.auditor.as_deref()) {
                let after = state.level.effective_level();
                let changed = value.get("changed").and_then(Value::as_bool) == Some(true);
                if changed && after > before {
                    let agent_identity = audit_agent_identity(active_profile.as_deref());
                    let draft = AuditEntryDraft {
                        agent_identity,
                        tool: "oracle_set_session_level".to_owned(),
                        sql: format!("ESCALATE {} -> {}", before.as_str(), after.as_str()),
                        danger_level: after.as_str().to_owned(),
                        decision: AuditDecision::StepUpRequired,
                        rows_affected: None,
                        outcome: AuditOutcome::Succeeded,
                    };
                    auditor
                        .append(&draft, audit_timestamp(), true)
                        .map_err(audit_error_to_envelope)?;
                }
            }
            return result;
        }
        if tool == "oracle_preview_sql" {
            let a: PreviewSqlArgs = parse_args(name, args)?;
            let preview = preview_sql(&a.sql, &scoped_level, state.active_profile.as_deref());
            remember_execute_approved_token(&mut state, &a.sql, &preview);
            return Ok(preview);
        }
        if tool == "execute_approved" {
            let a: ExecuteApprovedArgs = parse_args(name, args)?;
            let execute_args = execute_approved_args(&mut state, &scoped_level, a)?;
            let active_profile = state.active_profile.clone();
            let agent_identity = audit_agent_identity(active_profile.as_deref());
            let conn: &dyn OracleConnection = state.conn.as_ref();
            return execute_sql(
                cx,
                conn,
                active_profile.as_deref(),
                &scoped_level,
                self.auditor.as_deref(),
                &agent_identity,
                execute_args,
            )
            .await;
        }
        if tool == "deploy_ddl" {
            let a: DeployDdlArgs = parse_args(name, args)?;
            let active_profile = state.active_profile.clone();
            let agent_identity = audit_agent_identity(active_profile.as_deref());
            let conn: &dyn OracleConnection = state.conn.as_ref();
            return deploy_ddl(
                cx,
                conn,
                active_profile.as_deref(),
                &scoped_level,
                self.auditor.as_deref(),
                &agent_identity,
                a,
            )
            .await;
        }
        if tool == "read_patch_preview" {
            let a: ReadPatchPreviewArgs = parse_args(name, args)?;
            return read_patch_preview(&state, name, a);
        }
        let conn: &dyn OracleConnection = state.conn.as_ref();
        let metadata_conn: &dyn OracleConnection = state
            .stateless_conn
            .as_deref()
            .unwrap_or_else(|| state.conn.as_ref());

        let result: Result<Value, ErrorEnvelope> = match tool {
            "oracle_execute" => {
                let a: ExecuteArgs = parse_args(name, args)?;
                let agent_identity = audit_agent_identity(state.active_profile.as_deref());
                return execute_sql(
                    cx,
                    conn,
                    state.active_profile.as_deref(),
                    &scoped_level,
                    self.auditor.as_deref(),
                    &agent_identity,
                    a,
                )
                .await;
            }
            "oracle_compile_object" => {
                let a: CompileObjectArgs = parse_args(name, args)?;
                return compile_object(
                    cx,
                    conn,
                    state.active_profile.as_deref(),
                    &scoped_level,
                    name,
                    a,
                )
                .await;
            }
            "oracle_create_or_replace" => {
                let a: CreateOrReplaceArgs = parse_args(name, args)?;
                let agent_identity = audit_agent_identity(state.active_profile.as_deref());
                return create_or_replace(
                    cx,
                    conn,
                    state.active_profile.as_deref(),
                    &scoped_level,
                    self.auditor.as_deref(),
                    &agent_identity,
                    name,
                    a,
                )
                .await;
            }
            "oracle_patch_source" => {
                let a: PatchSourceArgs = parse_args(name, args)?;
                let (value, preview_entry) = patch_source(
                    cx,
                    conn,
                    state.active_profile.as_deref(),
                    &scoped_level,
                    name,
                    a,
                )
                .await?;
                if let Some(preview_entry) = preview_entry {
                    remember_patch_preview(&mut state, preview_entry);
                }
                return Ok(value);
            }
            "oracle_list_profiles" => {
                ensure_no_args(name, args)?;
                OracleMcpConfig::load(None)
                    .map(|cfg| profiles_response(&cfg))
                    .map_err(|e| {
                        DbError::UnsupportedAuth(format!("config load failed: {e}")).into_envelope()
                    })
            }
            "oracle_connection_info" => {
                ensure_no_args(name, args)?;
                let mut value = connection_info_json(
                    state.active_profile.clone(),
                    describe_conn(cx, conn).await,
                );
                if let Value::Object(map) = &mut value
                    && let Some(stateless_conn) = state.stateless_conn.as_ref()
                {
                    map.insert(
                        "stateless_read_connection".to_owned(),
                        connection_strategy_json(cx, stateless_conn.as_ref()).await,
                    );
                }
                Ok(value)
            }
            "oracle_query" => {
                let a: QueryArgs = parse_args(name, args)?;
                // A3: mark first, then gate and read the EXACT marked text. The
                // marker is verdict-preserving (verified inside with_audit_marker),
                // so ensure_read_only on the marked text behaves identically to the
                // bare SELECT, and the text classified is the text executed.
                let active_profile = state.active_profile.clone();
                let timeout_seconds = a.timeout_seconds;
                // E3/E3b: resolve the export access context (scope fingerprint)
                // and the shared registry before entering the read closure.
                let export_scopes = context.scope_grant().map(|grant| grant.0.clone());
                let exports = self.exports.clone();
                // A9: narrowing the handler context to the read-path capability
                // row (TIME + IO; no SPAWN / REMOTE / RANDOM) is still applied as
                // the structural guarantee, even though the DB round trip itself
                // takes the full `cx` (the native driver needs `IO`).
                let _read_cx = narrow_to_read_path(cx);
                return with_call_timeout(cx, conn, timeout_seconds, || async {
                    let executed_sql =
                        with_audit_marker(&a.sql, active_profile.as_deref(), "oracle_query");
                    ensure_read_only(&executed_sql)?;
                    let binds = a
                        .binds
                        .iter()
                        .map(json_to_bind)
                        .collect::<Result<Vec<_>, _>>()?;
                    // E2: the page cursor is an opaque, tamper-evident token
                    // bound to THIS statement + active profile, decoded to a raw
                    // offset here (a forged/cross-statement cursor fails closed).
                    let offset = decode_query_cursor(
                        a.cursor.as_deref(),
                        &a.sql,
                        active_profile.as_deref(),
                    )?;
                    // E3b: when the caller opts into export, materialize the
                    // bounded full result as an oracle-export://{id} resource and
                    // return a resource_link instead of inlining the rows.
                    if a.export {
                        return export_query_to_resource(
                            cx,
                            conn,
                            &executed_sql,
                            &a,
                            &binds,
                            offset,
                            active_profile.as_deref(),
                            export_scopes.as_deref(),
                            exports.as_deref(),
                        )
                        .await;
                    }
                    read_query(
                        cx,
                        conn,
                        &executed_sql,
                        &binds,
                        query_caps_from_args(&a),
                        offset,
                        &query_serialize_options_from_args(&a),
                    )
                    .await
                    .map(|resp| serde_json::to_value(resp).unwrap_or(Value::Null))
                    .map(|resp| reseal_query_cursor(resp, &a.sql, active_profile.as_deref()))
                    .map_err(DbError::into_envelope)
                })
                .await;
            }
            "oracle_schema_inspect" => {
                let a: SchemaInspectArgs = parse_args(name, args)?;
                let owner_arg = non_empty_arg(a.owner);
                let object_type = non_empty_arg(a.object_type);
                let name_like = non_empty_arg(a.name_like);
                let max_rows = a
                    .max_rows
                    .unwrap_or(DEFAULT_SCHEMA_INSPECT_MAX_ROWS)
                    .clamp(1, MAX_SCHEMA_INSPECT_MAX_ROWS);
                let owner_filter: Option<String> = match owner_arg.as_deref() {
                    Some("*") => None,
                    Some(owner) => Some(owner.to_owned()),
                    None => {
                        let info = describe_conn(cx, metadata_conn)
                            .await
                            .map_err(DbError::into_envelope)?;
                        Some(
                            info.current_schema
                                .ok_or_else(|| {
                                    DbError::Query(
                                        "owner is required because current_schema could not be detected"
                                            .to_owned(),
                                    )
                                })
                                .map_err(DbError::into_envelope)?,
                        )
                    }
                };
                dispatch_checkpoint(cx, "oraclemcp.dispatch.schema_inspect.before")?;
                let rows = list_objects(
                    cx,
                    metadata_conn,
                    owner_filter.as_deref(),
                    object_type.as_deref(),
                    name_like.as_deref(),
                    max_rows,
                )
                .await
                .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.schema_inspect.after")?;
                Ok(json!({
                    "objects": rows_to_json(&rows),
                    "owner": owner_filter.as_deref().unwrap_or("*"),
                    "object_type": object_type,
                    "name_like": name_like,
                    "max_rows": max_rows,
                    "truncated": rows.len() == max_rows,
                }))
            }
            "oracle_list_schemas" => {
                let a: ListSchemasArgs = parse_args(name, args)?;
                let name_like = non_empty_arg(a.name_like);
                let max_rows = a
                    .max_rows
                    .unwrap_or(DEFAULT_SCHEMA_LIST_MAX_ROWS)
                    .clamp(1, MAX_SCHEMA_LIST_MAX_ROWS);
                dispatch_checkpoint(cx, "oraclemcp.dispatch.list_schemas.before")?;
                let rows = list_schemas(cx, metadata_conn, name_like.as_deref(), max_rows)
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.list_schemas.after")?;
                Ok(json!({
                    "schemas": rows_to_json(&rows),
                    "name_like": name_like,
                    "max_rows": max_rows,
                    "truncated": rows.len() == max_rows,
                }))
            }
            "oracle_describe" => {
                let a: DescribeArgs = parse_args(name, args)?;
                let table = required_non_empty_arg(name, "table", a.table)?;
                let (owner, table) =
                    owner_and_name_arg(cx, metadata_conn, a.owner, table, "table").await?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.describe_columns.before")?;
                let columns = describe_columns(cx, metadata_conn, &owner, &table)
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.describe_constraints.before")?;
                let constraints = describe_constraints(cx, metadata_conn, &owner, &table)
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.describe_constraints.after")?;
                Ok(json!({
                    "owner": owner,
                    "table": table,
                    "columns": rows_to_json(&columns),
                    "constraints": rows_to_json(&constraints),
                }))
            }
            "oracle_describe_index" => {
                let a: DescribeIndexArgs = parse_args(name, args)?;
                let (owner, object_name) =
                    owner_and_name_arg(cx, metadata_conn, a.owner, a.name, "index").await?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.describe_index.before")?;
                let desc = describe_index(cx, metadata_conn, &owner, &object_name)
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.describe_index.after")?;
                Ok(json!({
                    "owner": owner,
                    "name": object_name,
                    "index": optional_row_to_json(desc.metadata.as_ref()),
                    "columns": rows_to_json(&desc.columns),
                    "expressions": rows_to_json(&desc.expressions),
                }))
            }
            "oracle_describe_trigger" => {
                let a: DescribeTriggerArgs = parse_args(name, args)?;
                let (owner, object_name) =
                    owner_and_name_arg(cx, metadata_conn, a.owner, a.name, "trigger").await?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.describe_trigger.before")?;
                let desc = describe_trigger(cx, metadata_conn, &owner, &object_name)
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.describe_trigger.after")?;
                Ok(json!({
                    "owner": owner,
                    "name": object_name,
                    "trigger": optional_row_to_json(desc.metadata.as_ref()),
                }))
            }
            "oracle_describe_view" => {
                let a: DescribeViewArgs = parse_args(name, args)?;
                let (owner, object_name) =
                    owner_and_name_arg(cx, metadata_conn, a.owner, a.name, "view").await?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.describe_view.before")?;
                let desc = describe_view(cx, metadata_conn, &owner, &object_name)
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.describe_view.after")?;
                Ok(json!({
                    "owner": owner,
                    "name": object_name,
                    "view": optional_row_to_json(desc.metadata.as_ref()),
                    "columns": rows_to_json(&desc.columns),
                }))
            }
            "oracle_get_ddl" => {
                let a: GetDdlArgs = parse_args(name, args)?;
                let (owner, object_name) =
                    owner_and_name_arg(cx, metadata_conn, a.owner, a.name, "name").await?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.get_ddl.before")?;
                let ddl = get_ddl(cx, metadata_conn, &a.object_type, &owner, &object_name)
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.get_ddl.after")?;
                Ok(json!({ "owner": owner, "name": object_name, "ddl": ddl }))
            }
            "oracle_get_source" => {
                let a: GetSourceArgs = parse_args(name, args)?;
                let max_chars = a.max_chars.unwrap_or(DEFAULT_SOURCE_MAX_CHARS);
                let (owner, object_name) =
                    owner_and_name_arg(cx, metadata_conn, a.owner, a.name, "name").await?;
                match a.object_type.as_deref().filter(|s| !s.trim().is_empty()) {
                    Some(object_type) => {
                        dispatch_checkpoint(cx, "oraclemcp.dispatch.get_source.before")?;
                        let source = get_source(
                            cx,
                            metadata_conn,
                            &owner,
                            &object_name,
                            object_type,
                            max_chars,
                        )
                        .await
                        .map_err(DbError::into_envelope)?;
                        dispatch_checkpoint(cx, "oraclemcp.dispatch.get_source.after")?;
                        Ok(json!({ "source": source }))
                    }
                    None => {
                        dispatch_checkpoint(cx, "oraclemcp.dispatch.get_sources_by_name.before")?;
                        let sources =
                            get_sources_by_name(cx, metadata_conn, &owner, &object_name, max_chars)
                                .await
                                .map_err(DbError::into_envelope)?;
                        dispatch_checkpoint(cx, "oraclemcp.dispatch.get_sources_by_name.after")?;
                        Ok(json!({
                            "owner": owner,
                            "name": object_name,
                            "source_count": sources.len(),
                            "sources": sources,
                        }))
                    }
                }
            }
            "oracle_sample_rows" => {
                let a: SampleRowsArgs = parse_args(name, args)?;
                let max_rows = a
                    .max_rows
                    .unwrap_or(DEFAULT_SAMPLE_MAX_ROWS)
                    .clamp(1, MAX_SAMPLE_MAX_ROWS);
                let (owner, table) =
                    owner_and_name_arg(cx, conn, a.owner, a.table, "table").await?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.sample_rows.before")?;
                let rows = sample_rows(cx, conn, &owner, &table, max_rows)
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.sample_rows.after")?;
                Ok(
                    json!({ "owner": owner, "table": table, "rows": rows_to_json(&rows), "row_count": rows.len() }),
                )
            }
            "oracle_top_queries" => {
                let a: TopQueriesArgs = parse_args(name, args)?;
                let metric = match a.metric.as_deref() {
                    None => oraclemcp_db::TopSqlMetric::Elapsed,
                    Some(raw) => oraclemcp_db::TopSqlMetric::parse(raw).ok_or_else(|| {
                        invalid_args(format!(
                            "unknown metric '{raw}': use elapsed, cpu, buffer_gets, or disk_reads"
                        ))
                    })?,
                };
                let top_n = a.top_n.unwrap_or(20);
                let min_pct = a.min_pct_of_total;
                let historical = a.historical;
                let timeout_seconds = a.timeout_seconds;
                // Read-only diagnostic: resolve the source (free live cursor cache
                // by default; AWR only when the Diagnostics Pack is licensed, else
                // Statspack, else a structured-unavailable error), build the ranked
                // SQL, and run it as a bounded read.
                return with_call_timeout(cx, conn, timeout_seconds, || async {
                    let source = oraclemcp_db::resolve_top_sql_source(cx, conn, historical).await;
                    let sql = oraclemcp_db::top_sql_query(source, metric, top_n, min_pct)?;
                    let rows = conn
                        .query_rows(cx, &sql, &[])
                        .await
                        .map_err(DbError::into_envelope)?;
                    Ok(json!({
                        "source": serde_json::to_value(source).unwrap_or(Value::Null),
                        "metric": serde_json::to_value(metric).unwrap_or(Value::Null),
                        "rows": rows_to_json(&rows),
                        "row_count": rows.len(),
                    }))
                })
                .await;
            }
            "oracle_db_health" => {
                let a: DbHealthArgs = parse_args(name, args)?;
                let request =
                    oraclemcp_db::parse_health_request(a.health_type.as_deref().unwrap_or("all"));
                let timeout_seconds = a.timeout_seconds;
                // Read-only DBA health suite: each requested subcheck runs a pure
                // V$/DBA_*/ALL_* read with DBA_*->ALL_* privilege degradation, and
                // any per-subcheck failure becomes a structured `skipped` finding
                // rather than failing the whole call. Unknown subcheck names are
                // reported, never fatal.
                return with_call_timeout(cx, conn, timeout_seconds, || async {
                    let findings = oraclemcp_db::run_health(cx, conn, &request.subchecks).await;
                    let checks_run: Vec<&str> = findings
                        .iter()
                        .filter(|f| {
                            f.detail.get("status").and_then(Value::as_str) != Some("skipped")
                        })
                        .map(|f| f.subcheck.name())
                        .collect();
                    let checks_skipped: Vec<&str> = findings
                        .iter()
                        .filter(|f| {
                            f.detail.get("status").and_then(Value::as_str) == Some("skipped")
                        })
                        .map(|f| f.subcheck.name())
                        .collect();
                    Ok(json!({
                        "findings": serde_json::to_value(&findings).unwrap_or(Value::Null),
                        "checks_run": checks_run,
                        "checks_skipped": checks_skipped,
                        "unknown_checks": request.unknown,
                    }))
                })
                .await;
            }
            "oracle_read_clob" => {
                let a: ReadClobArgs = parse_args(name, args)?;
                let max_chars = a.max_chars.unwrap_or(DEFAULT_LOB_MAX_CHARS);
                let (owner, table) =
                    owner_and_name_arg(cx, conn, a.owner, a.table, "table").await?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.read_lob.before")?;
                let clob = read_lob(
                    cx,
                    conn,
                    &owner,
                    &table,
                    &a.clob_column,
                    &a.pk_column,
                    &a.pk_value,
                    max_chars,
                )
                .await
                .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.read_lob.after")?;
                Ok(json!({ "clob": clob }))
            }
            "oracle_compile_errors" => {
                let a: CompileErrorsArgs = parse_args(name, args)?;
                let object_name = non_empty_arg(a.name);
                match object_name {
                    Some(object_name) => {
                        let (owner, object_name) =
                            owner_and_name_arg(cx, metadata_conn, a.owner, object_name, "name")
                                .await?;
                        dispatch_checkpoint(cx, "oraclemcp.dispatch.compile_errors.before")?;
                        let rows = compile_errors(cx, metadata_conn, &owner, Some(&object_name))
                            .await
                            .map_err(DbError::into_envelope)?;
                        dispatch_checkpoint(cx, "oraclemcp.dispatch.compile_errors.after")?;
                        Ok(
                            json!({ "owner": owner, "name": object_name, "errors": rows_to_json(&rows) }),
                        )
                    }
                    None => {
                        let owner = owner_or_current_cx(cx, metadata_conn, a.owner)
                            .await
                            .map_err(DbError::into_envelope)?;
                        dispatch_checkpoint(cx, "oraclemcp.dispatch.compile_errors.before")?;
                        let rows = compile_errors(cx, metadata_conn, &owner, None)
                            .await
                            .map_err(DbError::into_envelope)?;
                        dispatch_checkpoint(cx, "oraclemcp.dispatch.compile_errors.after")?;
                        Ok(json!({ "owner": owner, "errors": rows_to_json(&rows) }))
                    }
                }
            }
            "oracle_search_source" => {
                let a: SearchSourceArgs = parse_args(name, args)?;
                let max_rows = a
                    .max_rows
                    .unwrap_or(DEFAULT_SEARCH_MAX_ROWS)
                    .clamp(1, MAX_SEARCH_MAX_ROWS);
                let requested_owner = non_empty_arg(a.owner);
                let owner = match requested_owner.as_deref() {
                    Some("*") => None,
                    Some(owner) => Some(owner.to_ascii_uppercase()),
                    None => Some(
                        owner_or_current_cx(cx, metadata_conn, None)
                            .await
                            .map_err(DbError::into_envelope)?,
                    ),
                };
                let object_type = non_empty_arg(a.object_type);
                let name_like = non_empty_arg(a.name_like);
                dispatch_checkpoint(cx, "oraclemcp.dispatch.search_source.before")?;
                let rows = search_source(
                    cx,
                    metadata_conn,
                    owner.as_deref(),
                    &a.needle,
                    object_type.as_deref(),
                    name_like.as_deref(),
                    max_rows,
                )
                .await
                .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.search_source.after")?;
                Ok(json!({
                    "owner": owner.as_deref().unwrap_or("*"),
                    "object_type": object_type,
                    "name_like": name_like,
                    "max_rows": max_rows,
                    "matches": rows_to_json(&rows),
                }))
            }
            "oracle_plscope_inspect" => {
                let a: PlscopeInspectArgs = parse_args(name, args)?;
                let object_name = required_non_empty_arg(name, "name", a.name)?;
                let (owner, object_name) =
                    owner_and_name_arg(cx, metadata_conn, a.owner, object_name, "name").await?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.plscope_identifiers.before")?;
                let identifiers = plscope_identifiers(cx, metadata_conn, &owner, &object_name)
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.plscope_identifiers.after")?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.plscope_statements.before")?;
                let statements = plscope_statements(cx, metadata_conn, &owner, &object_name)
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.plscope_statements.after")?;
                let unused_declarations = find_unused_declarations(&identifiers);
                let dynamic_sql_lines = execute_immediate_audit(&statements);
                Ok(json!({
                    "owner": owner,
                    "name": object_name,
                    "identifier_count": identifiers.len(),
                    "statement_count": statements.len(),
                    "unused_declarations": unused_declarations,
                    "dynamic_sql_lines": dynamic_sql_lines,
                    "identifiers": identifiers,
                    "statements": statements,
                }))
            }
            "oracle_explain_plan" => {
                let a: ExplainPlanArgs = parse_args(name, args)?;
                ensure_read_only(&a.sql)?;
                ensure_explain_plan_write_allowed(&a, &scoped_level)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.explain_plan.before")?;
                let rows = explain_plan(cx, conn, &a.sql, a.read_only_standby)
                    .await
                    .map_err(DbError::into_envelope)?;
                dispatch_checkpoint(cx, "oraclemcp.dispatch.explain_plan.after")?;
                Ok(json!({
                    "plan": rows_to_json(&rows),
                    "diagnostic_write": {
                        "statement": "EXPLAIN PLAN",
                        "writes": "PLAN_TABLE",
                        "required_level": OperatingLevel::ReadWrite,
                        "explicitly_allowed": a.allow_plan_table_write,
                    },
                }))
            }
            other => {
                if let Some(loaded) = state.custom_catalog.get(other) {
                    let executor = ReadOnlyCustomToolExecutor { cx, conn };
                    return execute_custom_tool(loaded, &args, &executor).await;
                }
                return Err(invalid_args(format!(
                    "unknown tool: {other:?} (call oracle_capabilities for the tool surface)"
                )));
            }
        };

        result
    }
}

#[cfg(test)]
mod tests;
