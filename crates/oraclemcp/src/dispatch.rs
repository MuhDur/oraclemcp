//! The synchronous tool dispatcher wiring the advertised read-only tool surface
//! ([`crate::registry`]) to the engine-free `oraclemcp-db` dictionary ops.
//!
//! [`OracleDispatcher`] implements [`oraclemcp_core::ToolDispatch`]: the server
//! calls [`dispatch`](OracleDispatcher::dispatch) on a `spawn_blocking` worker
//! (never across an `.await`), so this stays FULLY synchronous and guards the
//! single connection with a `std::sync::Mutex`. Every arm deserializes a small
//! args struct, runs the matching `oraclemcp_db` op against the connection, and
//! maps the result to JSON; a [`oraclemcp_db::DbError`] becomes the agent-facing
//! [`ErrorEnvelope`] via `DbError::into_envelope`. The `oracle_capabilities`
//! discovery tool is answered by the server itself and never reaches here.

use std::sync::{Arc, Mutex};

use oraclemcp_config::OracleMcpConfig;
use oraclemcp_core::ToolDispatch;
use oraclemcp_db::{
    DbError, OracleBind, OracleConnection, QueryCaps, SerializeOptions, compile_errors,
    describe_columns, describe_index, describe_trigger, describe_view, explain_plan, get_ddl,
    get_source, list_objects, read_lob, read_query, sample_rows, search_source, serialize_row,
};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use oraclemcp_guard::{
    Classifier, ClassifierConfig, LevelDecision, OperatingLevel, SessionLevelState,
};
use serde::Deserialize;
use serde_json::{Value, json};

/// Default cap on `oracle_search_source` result rows when the caller omits it.
const DEFAULT_SEARCH_MAX_ROWS: usize = 200;
/// Default cap on `oracle_get_source` source text when the caller omits it.
const DEFAULT_SOURCE_MAX_CHARS: usize = 1_000_000;
/// Default cap on `oracle_schema_inspect` result rows when the caller omits it.
const DEFAULT_SCHEMA_INSPECT_MAX_ROWS: usize = 500;
/// Hard cap on `oracle_schema_inspect` for a single call.
const MAX_SCHEMA_INSPECT_MAX_ROWS: usize = 5_000;
/// Default cap on `oracle_sample_rows` when the caller omits it.
const DEFAULT_SAMPLE_MAX_ROWS: usize = 50;
/// Hard cap on `oracle_sample_rows` for a single call.
const MAX_SAMPLE_MAX_ROWS: usize = 1_000;
/// Default cap on `oracle_read_clob` text when the caller omits it.
const DEFAULT_LOB_MAX_CHARS: usize = 1_000_000;

/// Reconnect callback used by `oracle_switch_profile`.
pub type ProfileConnector =
    dyn Fn(&str) -> Result<Box<dyn OracleConnection>, DbError> + Send + Sync + 'static;

struct DispatcherState {
    conn: Box<dyn OracleConnection>,
    active_profile: Option<String>,
}

/// The dispatcher: owns the live connection behind a `std::sync::Mutex` so
/// dispatch stays sync and the connection is never shared across threads
/// without serialization.
pub struct OracleDispatcher {
    state: Mutex<DispatcherState>,
    connector: Option<Arc<ProfileConnector>>,
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
        OracleDispatcher {
            state: Mutex::new(DispatcherState {
                conn,
                active_profile,
            }),
            connector: None,
        }
    }

    /// Build a dispatcher that can reconnect to other configured profiles.
    pub fn new_switchable(
        conn: Box<dyn OracleConnection>,
        active_profile: Option<String>,
        connector: Arc<ProfileConnector>,
    ) -> Self {
        OracleDispatcher {
            state: Mutex::new(DispatcherState {
                conn,
                active_profile,
            }),
            connector: Some(connector),
        }
    }
}

/// Serialize a slice of rows to a JSON array via the canonical row serializer.
fn rows_to_json(rows: &[oraclemcp_db::OracleRow]) -> Value {
    let opts = SerializeOptions::default();
    Value::Array(rows.iter().map(|r| serialize_row(r, &opts)).collect())
}

fn optional_row_to_json(row: Option<&oraclemcp_db::OracleRow>) -> Value {
    let opts = SerializeOptions::default();
    row.map(|r| serialize_row(r, &opts)).unwrap_or(Value::Null)
}

#[derive(Deserialize)]
struct QueryArgs {
    sql: String,
    #[serde(default)]
    binds: Vec<Value>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Deserialize)]
struct SchemaInspectArgs {
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    object_type: Option<String>,
    #[serde(default)]
    name_like: Option<String>,
    #[serde(default, alias = "limit")]
    max_rows: Option<usize>,
}

#[derive(Deserialize)]
struct DescribeArgs {
    #[serde(default)]
    owner: Option<String>,
    #[serde(default, alias = "table_name", alias = "name")]
    table: Option<String>,
}

#[derive(Deserialize)]
struct DescribeIndexArgs {
    #[serde(default)]
    owner: Option<String>,
    #[serde(alias = "index_name")]
    name: String,
}

#[derive(Deserialize)]
struct DescribeTriggerArgs {
    #[serde(default)]
    owner: Option<String>,
    #[serde(alias = "trigger_name")]
    name: String,
}

#[derive(Deserialize)]
struct DescribeViewArgs {
    #[serde(default)]
    owner: Option<String>,
    #[serde(alias = "view_name")]
    name: String,
}

#[derive(Deserialize)]
struct GetDdlArgs {
    object_type: String,
    #[serde(default)]
    owner: Option<String>,
    #[serde(alias = "object_name")]
    name: String,
}

#[derive(Deserialize)]
struct GetSourceArgs {
    #[serde(default)]
    owner: Option<String>,
    #[serde(alias = "object_name")]
    name: String,
    object_type: String,
    #[serde(default)]
    max_chars: Option<usize>,
}

#[derive(Deserialize)]
struct SampleRowsArgs {
    #[serde(default)]
    owner: Option<String>,
    #[serde(alias = "table_name")]
    table: String,
    #[serde(default)]
    max_rows: Option<usize>,
}

#[derive(Deserialize)]
struct ReadClobArgs {
    #[serde(default)]
    owner: Option<String>,
    #[serde(alias = "table_name")]
    table: String,
    #[serde(alias = "clob_col")]
    clob_column: String,
    #[serde(alias = "pk_col")]
    pk_column: String,
    #[serde(alias = "pk_val")]
    pk_value: String,
    #[serde(default)]
    max_chars: Option<usize>,
}

#[derive(Deserialize)]
struct SwitchProfileArgs {
    #[serde(alias = "db")]
    profile: String,
}

#[derive(Deserialize)]
struct CompileErrorsArgs {
    #[serde(default)]
    owner: Option<String>,
    #[serde(default, alias = "object_name")]
    name: Option<String>,
}

#[derive(Deserialize)]
struct SearchSourceArgs {
    #[serde(default)]
    owner: Option<String>,
    needle: String,
    #[serde(default)]
    max_rows: Option<usize>,
}

#[derive(Deserialize)]
struct ExplainPlanArgs {
    sql: String,
    #[serde(default)]
    read_only_standby: bool,
}

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

fn owner_or_current(conn: &dyn OracleConnection, owner: Option<String>) -> Result<String, DbError> {
    match non_empty_arg(owner) {
        Some(owner) => Ok(owner.to_ascii_uppercase()),
        None => conn.describe().and_then(|info| {
            info.current_schema
                .map(|owner| owner.to_ascii_uppercase())
                .ok_or_else(|| {
                    DbError::Query(
                        "owner is required because current_schema could not be detected".to_owned(),
                    )
                })
        }),
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

fn owner_and_name_arg(
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
        (None, None) => owner_or_current(conn, None).map_err(DbError::into_envelope)?,
    };
    Ok((owner.to_ascii_uppercase(), object_name.to_ascii_uppercase()))
}

/// The fail-closed read-only gate for the two tools that accept a raw SQL
/// statement (`oracle_query`, `oracle_explain_plan`). This binary is read-only
/// by construction: every such statement is run through the `oraclemcp-guard`
/// classifier and refused — *before* it can reach Oracle — unless the guard
/// proves it needs no more than `READ_ONLY`. Writes, DDL/DCL, and any
/// `Forbidden` construct (multi-statement batch, string-concat dynamic SQL, an
/// unproven function call in a SELECT, …) are rejected with a structured
/// envelope. Proven read-only `SELECT`/`WITH` and dictionary introspection pass.
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
         oracle_compile_errors, oracle_search_source)"
            .to_owned()
    })))
}

fn canonical_tool_name(name: &str) -> &str {
    match name {
        "current_database" => "oracle_connection_info",
        "switch_database" => "oracle_switch_profile",
        "query" => "oracle_query",
        "list_objects" => "oracle_schema_inspect",
        "describe_table" => "oracle_describe",
        "describe_index" => "oracle_describe_index",
        "describe_trigger" => "oracle_describe_trigger",
        "describe_view" => "oracle_describe_view",
        "get_ddl" => "oracle_get_ddl",
        "get_object_source" => "oracle_get_source",
        "get_errors" => "oracle_compile_errors",
        "get_clob" => "oracle_read_clob",
        other => other,
    }
}

impl ToolDispatch for OracleDispatcher {
    fn dispatch(&self, name: &str, args: Value) -> Result<Value, ErrorEnvelope> {
        let tool = canonical_tool_name(name);
        if tool == "oracle_switch_profile" {
            let a: SwitchProfileArgs = parse_args(name, args)?;
            let Some(connector) = &self.connector else {
                return Err(ErrorEnvelope::new(
                    ErrorClass::RuntimeStateRequired,
                    "profile switching is unavailable in this server instance",
                )
                .with_next_step("restart the server with `oraclemcp serve --profile <name>`"));
            };

            let new_conn = connector(&a.profile).map_err(DbError::into_envelope)?;
            let connection_info = new_conn.describe().ok();
            let mut state = self.state.lock().map_err(|_| {
                ErrorEnvelope::new(ErrorClass::Internal, "connection mutex poisoned")
            })?;
            state.conn = new_conn;
            state.active_profile = Some(a.profile.clone());
            return Ok(json!({
                "active_profile": a.profile,
                "connection": connection_info,
            }));
        }

        // A poisoned mutex means a prior dispatch panicked while holding the
        // connection; surface it as an Internal error rather than re-panicking.
        let state = self
            .state
            .lock()
            .map_err(|_| ErrorEnvelope::new(ErrorClass::Internal, "connection mutex poisoned"))?;
        let conn: &dyn OracleConnection = state.conn.as_ref();

        let result: Result<Value, DbError> = match tool {
            "oracle_list_profiles" => {
                ensure_no_args(name, args)?;
                OracleMcpConfig::load(None)
                    .map(|cfg| json!({ "profiles": cfg.list_profiles() }))
                    .map_err(|e| DbError::UnsupportedAuth(format!("config load failed: {e}")))
            }
            "oracle_connection_info" => {
                ensure_no_args(name, args)?;
                conn.describe().map(|info| {
                    json!({
                        "active_profile": state.active_profile.clone(),
                        "connection": info,
                    })
                })
            }
            "oracle_query" => {
                let a: QueryArgs = parse_args(name, args)?;
                ensure_read_only(&a.sql)?;
                let binds = a
                    .binds
                    .iter()
                    .map(json_to_bind)
                    .collect::<Result<Vec<_>, _>>()?;
                let offset = oraclemcp_db::cursor_to_offset(a.cursor.as_deref());
                read_query(
                    conn,
                    &a.sql,
                    &binds,
                    QueryCaps::default(),
                    offset,
                    &SerializeOptions::default(),
                )
                .map(|resp| serde_json::to_value(resp).unwrap_or(Value::Null))
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
                let owner_result: Result<Option<String>, DbError> = match owner_arg.as_deref() {
                    Some("*") => Ok(None),
                    Some(owner) => Ok(Some(owner.to_owned())),
                    None => conn.describe().and_then(|info| {
                        info.current_schema.map(Some).ok_or_else(|| {
                            DbError::Query(
                                "owner is required because current_schema could not be detected"
                                    .to_owned(),
                            )
                        })
                    }),
                };
                owner_result.and_then(|owner_filter| {
                    list_objects(
                        conn,
                        owner_filter.as_deref(),
                        object_type.as_deref(),
                        name_like.as_deref(),
                        max_rows,
                    )
                    .map(|rows| {
                        json!({
                            "objects": rows_to_json(&rows),
                            "owner": owner_filter.as_deref().unwrap_or("*"),
                            "object_type": object_type,
                            "name_like": name_like,
                            "max_rows": max_rows,
                            "truncated": rows.len() == max_rows,
                        })
                    })
                })
            }
            "oracle_describe" => {
                let a: DescribeArgs = parse_args(name, args)?;
                let table = required_non_empty_arg(name, "table", a.table)?;
                let (owner, table) = owner_and_name_arg(conn, a.owner, table, "table")?;
                describe_columns(conn, &owner, &table)
                    .map(|rows| json!({ "owner": owner, "table": table, "columns": rows_to_json(&rows) }))
            }
            "oracle_describe_index" => {
                let a: DescribeIndexArgs = parse_args(name, args)?;
                let (owner, object_name) = owner_and_name_arg(conn, a.owner, a.name, "index")?;
                describe_index(conn, &owner, &object_name).map(|desc| {
                    json!({
                        "owner": owner,
                        "name": object_name,
                        "index": optional_row_to_json(desc.metadata.as_ref()),
                        "columns": rows_to_json(&desc.columns),
                        "expressions": rows_to_json(&desc.expressions),
                    })
                })
            }
            "oracle_describe_trigger" => {
                let a: DescribeTriggerArgs = parse_args(name, args)?;
                let (owner, object_name) = owner_and_name_arg(conn, a.owner, a.name, "trigger")?;
                describe_trigger(conn, &owner, &object_name).map(|desc| {
                    json!({
                        "owner": owner,
                        "name": object_name,
                        "trigger": optional_row_to_json(desc.metadata.as_ref()),
                    })
                })
            }
            "oracle_describe_view" => {
                let a: DescribeViewArgs = parse_args(name, args)?;
                let (owner, object_name) = owner_and_name_arg(conn, a.owner, a.name, "view")?;
                describe_view(conn, &owner, &object_name).map(|desc| {
                    json!({
                        "owner": owner,
                        "name": object_name,
                        "view": optional_row_to_json(desc.metadata.as_ref()),
                        "columns": rows_to_json(&desc.columns),
                    })
                })
            }
            "oracle_get_ddl" => {
                let a: GetDdlArgs = parse_args(name, args)?;
                let (owner, object_name) = owner_and_name_arg(conn, a.owner, a.name, "name")?;
                get_ddl(conn, &a.object_type, &owner, &object_name)
                    .map(|ddl| json!({ "owner": owner, "name": object_name, "ddl": ddl }))
            }
            "oracle_get_source" => {
                let a: GetSourceArgs = parse_args(name, args)?;
                let max_chars = a.max_chars.unwrap_or(DEFAULT_SOURCE_MAX_CHARS);
                let (owner, object_name) = owner_and_name_arg(conn, a.owner, a.name, "name")?;
                get_source(conn, &owner, &object_name, &a.object_type, max_chars)
                    .map(|source| json!({ "source": source }))
            }
            "oracle_sample_rows" => {
                let a: SampleRowsArgs = parse_args(name, args)?;
                let max_rows = a
                    .max_rows
                    .unwrap_or(DEFAULT_SAMPLE_MAX_ROWS)
                    .clamp(1, MAX_SAMPLE_MAX_ROWS);
                let (owner, table) = owner_and_name_arg(conn, a.owner, a.table, "table")?;
                sample_rows(conn, &owner, &table, max_rows)
                    .map(|rows| json!({ "owner": owner, "table": table, "rows": rows_to_json(&rows), "row_count": rows.len() }))
            }
            "oracle_read_clob" => {
                let a: ReadClobArgs = parse_args(name, args)?;
                let max_chars = a.max_chars.unwrap_or(DEFAULT_LOB_MAX_CHARS);
                let (owner, table) = owner_and_name_arg(conn, a.owner, a.table, "table")?;
                read_lob(
                    conn,
                    &owner,
                    &table,
                    &a.clob_column,
                    &a.pk_column,
                    &a.pk_value,
                    max_chars,
                )
                .map(|clob| json!({ "clob": clob }))
            }
            "oracle_compile_errors" => {
                let a: CompileErrorsArgs = parse_args(name, args)?;
                let object_name = non_empty_arg(a.name);
                match object_name {
                    Some(object_name) => {
                        let (owner, object_name) =
                            owner_and_name_arg(conn, a.owner, object_name, "name")?;
                        compile_errors(conn, &owner, Some(&object_name))
                            .map(|rows| json!({ "owner": owner, "name": object_name, "errors": rows_to_json(&rows) }))
                    }
                    None => owner_or_current(conn, a.owner).and_then(|owner| {
                        compile_errors(conn, &owner, None)
                            .map(|rows| json!({ "owner": owner, "errors": rows_to_json(&rows) }))
                    }),
                }
            }
            "oracle_search_source" => {
                let a: SearchSourceArgs = parse_args(name, args)?;
                let max_rows = a.max_rows.unwrap_or(DEFAULT_SEARCH_MAX_ROWS);
                owner_or_current(conn, a.owner).and_then(|owner| {
                    search_source(conn, &owner, &a.needle, max_rows)
                        .map(|rows| json!({ "owner": owner, "matches": rows_to_json(&rows) }))
                })
            }
            "oracle_explain_plan" => {
                let a: ExplainPlanArgs = parse_args(name, args)?;
                ensure_read_only(&a.sql)?;
                explain_plan(conn, &a.sql, a.read_only_standby)
                    .map(|rows| json!({ "plan": rows_to_json(&rows) }))
            }
            other => {
                return Err(invalid_args(format!(
                    "unknown tool: {other:?} (call oracle_capabilities for the tool surface)"
                )));
            }
        };

        result.map_err(DbError::into_envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::TOOL_NAMES;
    use oraclemcp_db::{OracleBackend, OracleCell, OracleConnectionInfo, OracleRow};

    /// A driver-free mock that returns one synthetic row for any query — mirrors
    /// `oraclemcp_db::query`'s `NRowMock` so the dispatch arms exercise offline.
    struct OneRowMock;
    impl OracleConnection for OneRowMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        fn ping(&self) -> Result<(), DbError> {
            Ok(())
        }
        fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo {
                backend: Some(OracleBackend::RustOracle),
                server_version: Some("23.0.0".to_owned()),
                database_role: Some("PRIMARY".to_owned()),
                open_mode: Some("READ WRITE".to_owned()),
                current_schema: Some("APP".to_owned()),
            })
        }
        fn query_rows(&self, _sql: &str, _b: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
            Ok(vec![OracleRow {
                columns: vec![
                    (
                        "OBJECT_NAME".to_owned(),
                        OracleCell::new("VARCHAR2", Some("EMPLOYEES".to_owned())),
                    ),
                    (
                        "DDL".to_owned(),
                        OracleCell::new("CLOB", Some("CREATE TABLE ...".to_owned())),
                    ),
                    (
                        "LOB_VALUE".to_owned(),
                        OracleCell::new("CLOB", Some("large text".to_owned())),
                    ),
                ],
            }])
        }
        fn execute(&self, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
            Ok(0)
        }
        fn commit(&self) -> Result<(), DbError> {
            Ok(())
        }
        fn rollback(&self) -> Result<(), DbError> {
            Ok(())
        }
    }

    /// A mock whose every query fails with a classifiable ORA- error, so we can
    /// assert DbError -> ErrorEnvelope mapping end to end.
    struct FailingMock;
    impl OracleConnection for FailingMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        fn ping(&self) -> Result<(), DbError> {
            Ok(())
        }
        fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }
        fn query_rows(&self, _sql: &str, _b: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
            Err(DbError::Query(
                "ORA-00942: table or view does not exist".to_owned(),
            ))
        }
        fn execute(&self, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
            Err(DbError::Execute(
                "ORA-00942: table or view does not exist".to_owned(),
            ))
        }
        fn commit(&self) -> Result<(), DbError> {
            Ok(())
        }
        fn rollback(&self) -> Result<(), DbError> {
            Ok(())
        }
    }

    /// Minimal valid args for a given tool name (matches the registry schemas).
    fn args_for(name: &str) -> Value {
        match name {
            "oracle_list_profiles" => json!({}),
            "oracle_connection_info" => json!({}),
            "oracle_switch_profile" => json!({ "profile": "other" }),
            "oracle_query" => json!({ "sql": "SELECT 1 FROM dual" }),
            "oracle_schema_inspect" => json!({ "owner": "HR" }),
            "oracle_describe" => json!({ "owner": "HR", "table": "EMPLOYEES" }),
            "oracle_describe_index" => json!({ "owner": "HR", "name": "EMP_NAME_IX" }),
            "oracle_describe_trigger" => json!({ "owner": "HR", "name": "EMP_BIU" }),
            "oracle_describe_view" => json!({ "owner": "HR", "name": "EMP_DETAILS_VIEW" }),
            "oracle_get_ddl" => {
                json!({ "object_type": "TABLE", "owner": "HR", "name": "EMPLOYEES" })
            }
            "oracle_get_source" => {
                json!({ "object_type": "PACKAGE", "owner": "HR", "name": "EMP_API" })
            }
            "oracle_sample_rows" => json!({ "owner": "HR", "table": "EMPLOYEES" }),
            "oracle_read_clob" => {
                json!({ "owner": "HR", "table": "DOCS", "clob_column": "BODY", "pk_column": "ID", "pk_value": "42" })
            }
            "oracle_compile_errors" => json!({ "owner": "HR", "name": "PKG" }),
            "oracle_search_source" => json!({ "owner": "HR", "needle": "commit" }),
            "oracle_explain_plan" => json!({ "sql": "SELECT 1 FROM dual" }),
            "current_database" => json!({}),
            "switch_database" => json!({ "db": "other" }),
            "query" => json!({ "sql": "SELECT 1 FROM dual" }),
            "list_objects" => json!({ "owner": "HR" }),
            "describe_table" => json!({ "owner": "HR", "table_name": "EMPLOYEES" }),
            "describe_index" => json!({ "owner": "HR", "index_name": "EMP_NAME_IX" }),
            "describe_trigger" => json!({ "owner": "HR", "trigger_name": "EMP_BIU" }),
            "describe_view" => json!({ "owner": "HR", "view_name": "EMP_DETAILS_VIEW" }),
            "get_ddl" => {
                json!({ "object_type": "TABLE", "owner": "HR", "object_name": "EMPLOYEES" })
            }
            "get_object_source" => {
                json!({ "object_type": "PACKAGE", "owner": "HR", "object_name": "EMP_API" })
            }
            "get_errors" => json!({ "owner": "HR", "object_name": "PKG" }),
            "get_clob" => {
                json!({ "owner": "HR", "table": "DOCS", "clob_col": "BODY", "pk_col": "ID", "pk_val": "42" })
            }
            other => panic!("no test args for {other}"),
        }
    }

    #[test]
    fn every_registry_tool_routes_and_deserializes_offline() {
        let dispatcher = OracleDispatcher::new_switchable(
            Box::new(OneRowMock),
            Some("dev".to_owned()),
            Arc::new(|_| Ok(Box::new(OneRowMock))),
        );
        for name in TOOL_NAMES {
            let out = dispatcher
                .dispatch(name, args_for(name))
                .unwrap_or_else(|e| panic!("{name} should route + succeed offline: {e:?}"));
            assert!(out.is_object(), "{name} returns a JSON object");
        }
    }

    #[test]
    fn compatibility_aliases_route_to_prefixed_tools() {
        let dispatcher = OracleDispatcher::new_switchable(
            Box::new(OneRowMock),
            Some("dev".to_owned()),
            Arc::new(|_| Ok(Box::new(OneRowMock))),
        );
        for name in [
            "current_database",
            "switch_database",
            "query",
            "list_objects",
            "describe_table",
            "describe_index",
            "describe_trigger",
            "describe_view",
            "get_ddl",
            "get_object_source",
            "get_errors",
            "get_clob",
        ] {
            let out = dispatcher
                .dispatch(name, args_for(name))
                .unwrap_or_else(|e| panic!("{name} alias should route: {e:?}"));
            assert!(out.is_object(), "{name} returns a JSON object");
        }
    }

    #[test]
    fn connection_info_reports_the_active_profile() {
        let dispatcher =
            OracleDispatcher::new_with_profile(Box::new(OneRowMock), Some("dev".to_owned()));
        let out = dispatcher
            .dispatch("oracle_connection_info", json!({}))
            .expect("connection info");
        assert_eq!(out["active_profile"], json!("dev"));
    }

    #[test]
    fn failed_profile_switch_does_not_replace_the_current_connection() {
        let dispatcher = OracleDispatcher::new_switchable(
            Box::new(OneRowMock),
            Some("dev".to_owned()),
            Arc::new(|_| Err(DbError::Connect("connect failed".to_owned()))),
        );

        let err = dispatcher
            .dispatch("oracle_switch_profile", json!({ "profile": "broken" }))
            .expect_err("switch errors");
        assert_eq!(err.error_class, ErrorClass::ConnectionFailed);

        let out = dispatcher
            .dispatch("oracle_connection_info", json!({}))
            .expect("current connection still usable");
        assert_eq!(out["active_profile"], json!("dev"));
    }

    #[test]
    fn compile_errors_can_default_to_current_schema() {
        let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
        let out = dispatcher
            .dispatch("oracle_compile_errors", json!({}))
            .expect("compile errors defaults owner");
        assert!(out["errors"].is_array());
    }

    #[test]
    fn schema_inspect_can_default_to_current_schema() {
        let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
        let out = dispatcher
            .dispatch("oracle_schema_inspect", json!({}))
            .expect("schema inspect defaults owner");
        assert_eq!(out["owner"], json!("APP"));
        assert_eq!(out["max_rows"], json!(DEFAULT_SCHEMA_INSPECT_MAX_ROWS));
        assert!(out["objects"].is_array());
    }

    #[test]
    fn schema_inspect_accepts_all_owners_and_limit_alias() {
        let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
        let out = dispatcher
            .dispatch(
                "oracle_schema_inspect",
                json!({ "owner": "*", "object_type": "package", "name_like": "emp%", "limit": 5 }),
            )
            .expect("schema inspect accepts all-owner filters");
        assert_eq!(out["owner"], json!("*"));
        assert_eq!(out["object_type"], json!("package"));
        assert_eq!(out["name_like"], json!("emp%"));
        assert_eq!(out["max_rows"], json!(5));
    }

    #[test]
    fn describe_object_helpers_default_owner_and_accept_legacy_aliases() {
        let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
        let index = dispatcher
            .dispatch("oracle_describe_index", json!({ "index_name": "EMP_IX" }))
            .expect("index description defaults owner");
        assert_eq!(index["owner"], json!("APP"));
        assert!(index["index"].is_object());
        assert!(index["columns"].is_array());
        assert!(index["expressions"].is_array());

        let trigger = dispatcher
            .dispatch(
                "oracle_describe_trigger",
                json!({ "trigger_name": "EMP_BIU" }),
            )
            .expect("trigger description defaults owner");
        assert_eq!(trigger["owner"], json!("APP"));
        assert!(trigger["trigger"].is_object());

        let view = dispatcher
            .dispatch("oracle_describe_view", json!({ "view_name": "EMP_V" }))
            .expect("view description defaults owner");
        assert_eq!(view["owner"], json!("APP"));
        assert!(view["view"].is_object());
        assert!(view["columns"].is_array());
    }

    #[test]
    fn dictionary_tools_accept_default_owner_qualified_names_and_aliases() {
        let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));

        let described = dispatcher
            .dispatch("oracle_describe", json!({ "table_name": "APP.EMPLOYEES" }))
            .expect("describe accepts table_name alias and qualified table");
        assert_eq!(described["owner"], json!("APP"));
        assert_eq!(described["table"], json!("EMPLOYEES"));
        assert!(described["columns"].is_array());

        let ddl = dispatcher
            .dispatch(
                "oracle_get_ddl",
                json!({ "object_type": "TABLE", "object_name": "APP.EMPLOYEES" }),
            )
            .expect("ddl accepts object_name alias and qualified name");
        assert_eq!(ddl["owner"], json!("APP"));
        assert_eq!(ddl["name"], json!("EMPLOYEES"));
        assert_eq!(ddl["ddl"], json!("CREATE TABLE ..."));

        let source = dispatcher
            .dispatch(
                "oracle_get_source",
                json!({ "object_type": "PACKAGE", "object_name": "APP.EMP_API" }),
            )
            .expect("source accepts object_name alias and qualified name");
        assert_eq!(source["source"]["owner"], json!("APP"));
        assert_eq!(source["source"]["name"], json!("EMP_API"));

        let sample = dispatcher
            .dispatch(
                "oracle_sample_rows",
                json!({ "table_name": "APP.EMPLOYEES", "max_rows": 2 }),
            )
            .expect("sample accepts table_name alias and qualified table");
        assert_eq!(sample["owner"], json!("APP"));
        assert_eq!(sample["table"], json!("EMPLOYEES"));
        assert_eq!(sample["row_count"], json!(1));

        let clob = dispatcher
            .dispatch(
                "oracle_read_clob",
                json!({ "table": "APP.DOCS", "clob_col": "BODY", "pk_col": "ID", "pk_val": "42" }),
            )
            .expect("read_clob accepts old argument aliases");
        assert_eq!(clob["clob"]["owner"], json!("APP"));
        assert_eq!(clob["clob"]["table"], json!("DOCS"));

        let errors = dispatcher
            .dispatch("oracle_compile_errors", json!({ "object_name": "APP.PKG" }))
            .expect("compile errors accepts object_name alias and qualified name");
        assert_eq!(errors["owner"], json!("APP"));
        assert_eq!(errors["name"], json!("PKG"));
        assert!(errors["errors"].is_array());

        let matches = dispatcher
            .dispatch("oracle_search_source", json!({ "needle": "commit" }))
            .expect("search source defaults owner");
        assert_eq!(matches["owner"], json!("APP"));
        assert!(matches["matches"].is_array());
    }

    #[test]
    fn conflicting_owner_and_qualified_name_is_invalid_arguments() {
        let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
        let err = dispatcher
            .dispatch(
                "oracle_get_ddl",
                json!({ "object_type": "TABLE", "owner": "HR", "name": "APP.EMPLOYEES" }),
            )
            .expect_err("conflicting owners rejected");
        assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    }

    #[test]
    fn unknown_tool_is_invalid_arguments() {
        let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
        let err = dispatcher
            .dispatch("oracle_nonexistent", json!({}))
            .expect_err("unknown tool errors");
        assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    }

    #[test]
    fn malformed_args_are_invalid_arguments_not_a_panic() {
        let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
        // Missing required `table`.
        let err = dispatcher
            .dispatch("oracle_describe", json!({ "owner": "HR" }))
            .expect_err("missing required arg errors");
        assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    }

    #[test]
    fn db_error_maps_to_a_classified_envelope() {
        let dispatcher = OracleDispatcher::new(Box::new(FailingMock));
        let err = dispatcher
            .dispatch("oracle_schema_inspect", json!({ "owner": "HR" }))
            .expect_err("ORA-00942 propagates as an envelope");
        assert_eq!(err.error_class, ErrorClass::ObjectNotFound);
        assert_eq!(err.ora_code, Some(942));
    }

    #[test]
    fn query_binds_are_accepted_and_typed() {
        let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
        let out = dispatcher
            .dispatch(
                "oracle_query",
                json!({ "sql": "SELECT * FROM t WHERE id = :1 AND active = :2", "binds": [42, true] }),
            )
            .expect("binds accepted");
        assert!(out["columns"].is_array() || out.is_object());
    }

    #[test]
    fn invalid_bind_type_is_invalid_arguments() {
        let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
        let err = dispatcher
            .dispatch(
                "oracle_query",
                json!({ "sql": "SELECT 1", "binds": [ {"nested": "object"} ] }),
            )
            .expect_err("object bind rejected");
        assert_eq!(err.error_class, ErrorClass::InvalidArguments);
    }

    /// A connection that MUST never be touched: any query/execute panics. Proves
    /// the read-only gate refuses a statement *before* it can reach Oracle.
    struct NoExecMock;
    impl OracleConnection for NoExecMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        fn ping(&self) -> Result<(), DbError> {
            Ok(())
        }
        fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }
        fn query_rows(&self, _sql: &str, _b: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
            panic!("a refused statement must never reach the database (query_rows)")
        }
        fn execute(&self, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
            panic!("a refused statement must never reach the database (execute)")
        }
        fn commit(&self) -> Result<(), DbError> {
            Ok(())
        }
        fn rollback(&self) -> Result<(), DbError> {
            Ok(())
        }
    }

    #[test]
    fn writes_ddl_and_dcl_are_refused_before_touching_the_db() {
        let dispatcher = OracleDispatcher::new(Box::new(NoExecMock));
        // Each must be refused fail-closed — and NoExecMock panics if any of
        // them reaches the connection, so a pass here also proves non-execution.
        for sql in [
            "INSERT INTO hr.employees (id) VALUES (1)",
            "UPDATE hr.employees SET salary = 0",
            "DELETE FROM hr.employees",
            "DROP TABLE hr.employees",
            "TRUNCATE TABLE hr.employees",
            "CREATE OR REPLACE PROCEDURE p AS BEGIN NULL; END;",
            "GRANT DBA TO scott",
            "ALTER SYSTEM FLUSH SHARED_POOL",
        ] {
            let err = dispatcher
                .dispatch("oracle_query", json!({ "sql": sql }))
                .expect_err(&format!("expected a fail-closed refusal for: {sql}"));
            assert!(
                matches!(
                    err.error_class,
                    ErrorClass::OperatingLevelTooLow | ErrorClass::ForbiddenStatement
                ),
                "{sql} -> unexpected class {:?}",
                err.error_class
            );
        }
    }

    #[test]
    fn read_only_select_passes_the_gate() {
        // A plain SELECT (no unproven function call) is proven read-only and runs.
        let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
        let out = dispatcher
            .dispatch(
                "oracle_query",
                json!({ "sql": "SELECT object_name FROM all_objects WHERE owner = :1", "binds": ["HR"] }),
            )
            .expect("a read-only SELECT must pass the gate");
        assert!(out.is_object());
    }

    #[test]
    fn explain_plan_refuses_a_non_read_only_statement() {
        let dispatcher = OracleDispatcher::new(Box::new(NoExecMock));
        let err = dispatcher
            .dispatch(
                "oracle_explain_plan",
                json!({ "sql": "DELETE FROM hr.employees" }),
            )
            .expect_err("explain of a write is refused fail-closed");
        assert!(matches!(
            err.error_class,
            ErrorClass::OperatingLevelTooLow | ErrorClass::ForbiddenStatement
        ));
    }

    #[test]
    fn multi_statement_batch_with_a_write_is_refused() {
        // A `;`-joined batch carrying a DROP is refused fail-closed (its danger
        // is the max over statements; a desynced batch would be ForbiddenStatement).
        let dispatcher = OracleDispatcher::new(Box::new(NoExecMock));
        let err = dispatcher
            .dispatch(
                "oracle_query",
                json!({ "sql": "SELECT 1 FROM dual; DROP TABLE hr.employees" }),
            )
            .expect_err("a multi-statement batch containing a write is refused");
        assert!(matches!(
            err.error_class,
            ErrorClass::ForbiddenStatement | ErrorClass::OperatingLevelTooLow
        ));
    }
}
