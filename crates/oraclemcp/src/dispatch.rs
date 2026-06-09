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
use std::time::Duration;

use oraclemcp_config::OracleMcpConfig;
use oraclemcp_core::{
    CustomToolCatalog, CustomToolExecutor, ToolBody, ToolDispatch, execute_custom_tool,
};
use oraclemcp_db::{
    DbError, OracleBind, OracleConnection, QueryCaps, SerializeOptions, compile_errors,
    compile_object_statements, describe_columns, describe_constraints, describe_index,
    describe_trigger, describe_view, execute_immediate_audit, explain_plan,
    find_unused_declarations, get_ddl, get_source, get_sources_by_name, list_objects, list_schemas,
    plscope_identifiers, plscope_statements, read_lob, read_query, read_query_named, sample_rows,
    search_source, serialize_row,
};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use oraclemcp_guard::{
    Classifier, ClassifierConfig, EscalationError, GuardDecision, LevelDecision, OperatingLevel,
    SessionLevelState,
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
/// Hard cap on text/CLOB characters materialized by a single query cell.
const MAX_QUERY_TEXT_CHARS: usize = 1_000_000;
/// Hard cap on BLOB bytes materialized by a single query cell.
const MAX_QUERY_BLOB_BYTES: usize = 5 * 1024 * 1024;
/// Default temporary session elevation window for `oracle_set_session_level`.
const DEFAULT_SESSION_LEVEL_TTL_SECONDS: u64 = 900;
/// Hard cap for one temporary session elevation window.
const MAX_SESSION_LEVEL_TTL_SECONDS: u64 = 3_600;

/// Reconnect callback used by `oracle_switch_profile`.
pub type ProfileConnector =
    dyn Fn(&str) -> Result<Box<dyn OracleConnection>, DbError> + Send + Sync + 'static;

/// Profile-scoped custom-tool loader used by `oracle_switch_profile`.
pub type CustomToolLoader =
    dyn Fn(&SessionLevelState) -> Result<CustomToolCatalog, ErrorEnvelope> + Send + Sync + 'static;

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
    active_profile: Option<String>,
    level: SessionLevelState,
    custom_catalog: CustomToolCatalog,
}

/// The dispatcher: owns the live connection behind a `std::sync::Mutex` so
/// dispatch stays sync and the connection is never shared across threads
/// without serialization.
pub struct OracleDispatcher {
    state: Mutex<DispatcherState>,
    connector: Option<Arc<ProfileConnector>>,
    custom_loader: Option<Arc<CustomToolLoader>>,
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
            state: Mutex::new(DispatcherState {
                conn,
                active_profile,
                level,
                custom_catalog: CustomToolCatalog::default(),
            }),
            connector: None,
            custom_loader: None,
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
        OracleDispatcher {
            state: Mutex::new(DispatcherState {
                conn,
                active_profile,
                level,
                custom_catalog,
            }),
            connector: Some(connector),
            custom_loader,
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
    }
}

#[derive(Deserialize)]
struct QueryArgs {
    sql: String,
    #[serde(default)]
    binds: Vec<Value>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default, alias = "limit")]
    max_rows: Option<usize>,
    #[serde(default)]
    max_result_bytes: Option<usize>,
    #[serde(default)]
    max_lob_chars: Option<usize>,
    #[serde(default)]
    max_blob_bytes: Option<usize>,
    #[serde(default)]
    max_col_width: Option<usize>,
    #[serde(default)]
    numbers_as_float: Option<bool>,
}

#[derive(Deserialize)]
struct PreviewSqlArgs {
    sql: String,
}

#[derive(Deserialize)]
struct ExecuteArgs {
    sql: String,
    #[serde(default)]
    binds: Vec<Value>,
    #[serde(default)]
    commit: bool,
    #[serde(default, alias = "token", alias = "confirmation_token")]
    confirm: Option<String>,
}

#[derive(Deserialize)]
struct SetSessionLevelArgs {
    #[serde(default, alias = "target_level")]
    level: Option<String>,
    #[serde(default)]
    ttl_seconds: Option<u64>,
    #[serde(default)]
    execute: bool,
    #[serde(default, alias = "token", alias = "confirmation_token")]
    confirm: Option<String>,
    #[serde(default)]
    action: Option<String>,
}

#[derive(Deserialize)]
struct CompileObjectArgs {
    object_type: String,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default, alias = "object_name")]
    name: Option<String>,
    #[serde(default)]
    plscope: bool,
    #[serde(default)]
    execute: bool,
    #[serde(default, alias = "token", alias = "confirmation_token")]
    confirm: Option<String>,
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
struct ListSchemasArgs {
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
    #[serde(default)]
    object_type: Option<String>,
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
    object_type: Option<String>,
    #[serde(default)]
    name_like: Option<String>,
    #[serde(default)]
    max_rows: Option<usize>,
}

#[derive(Deserialize)]
struct PlscopeInspectArgs {
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    #[serde(alias = "object_name")]
    name: Option<String>,
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
         oracle_compile_errors, oracle_search_source, oracle_plscope_inspect)"
            .to_owned()
    })))
}

fn normalized_sql_for_confirmation(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches(';')
        .to_ascii_lowercase()
}

fn execute_confirmation_token(
    sql: &str,
    required_level: OperatingLevel,
    active_profile: Option<&str>,
) -> Option<String> {
    if required_level <= OperatingLevel::ReadOnly {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(b"oraclemcp:execute-confirmation:v1\0");
    hasher.update(active_profile.unwrap_or("").as_bytes());
    hasher.update(b"\0");
    hasher.update(required_level.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(normalized_sql_for_confirmation(sql).as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        out.push_str(&format!("{byte:02x}"));
    }
    Some(out)
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
    let mut hasher = Sha256::new();
    hasher.update(b"oraclemcp:session-level-confirmation:v1\0");
    hasher.update(active_profile.unwrap_or("").as_bytes());
    hasher.update(b"\0");
    hasher.update(target.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(ttl_seconds.to_string().as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
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
        LevelDecision::RequireStepUp { target } => {
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
        LevelDecision::Blocked { reason } => match reason {
            oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling } => {
                actions.push(json!({
                    "intent": "choose_different_profile",
                    "tool": "oracle_list_profiles",
                    "args": {},
                    "required_level": required,
                    "current_ceiling": ceiling,
                }));
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

fn execute_gate_error(
    decision: &GuardDecision,
    gate: LevelDecision,
    session: &SessionLevelState,
) -> ErrorEnvelope {
    match gate {
        LevelDecision::RequireStepUp { target } => ErrorEnvelope::new(
            ErrorClass::OperatingLevelTooLow,
            format!(
                "statement requires {} but the active session level is {}",
                target.as_str(),
                session.effective_level().as_str()
            ),
        )
        .with_suggested_tool("oracle_preview_sql")
        .with_next_step("call oracle_preview_sql to inspect the required level and profile ceiling")
        .with_next_step("call oracle_set_session_level to preview a temporary elevation, or keep the profile read-only"),
        LevelDecision::Blocked { reason } => match reason {
            oraclemcp_guard::BlockReason::Forbidden => ErrorEnvelope::new(
                ErrorClass::ForbiddenStatement,
                format!("statement is forbidden by the SQL classifier: {}", decision.reason),
            )
            .with_next_step(decision.safe_alternative.clone().unwrap_or_else(|| {
                "rewrite the statement as a simpler, single SQL statement".to_owned()
            })),
            oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling } => {
                ErrorEnvelope::new(
                    ErrorClass::OperatingLevelTooLow,
                    format!(
                        "statement requires {} but the active profile ceiling is {}",
                        required.as_str(),
                        ceiling.as_str()
                    ),
                )
                .with_suggested_tool("oracle_list_profiles")
                .with_next_step("choose a profile whose max_level permits the statement")
            }
            _ => ErrorEnvelope::new(ErrorClass::PolicyDenied, "statement is blocked by policy"),
        },
        _ => ErrorEnvelope::new(
            ErrorClass::Internal,
            "execute gate produced an unexpected decision",
        ),
    }
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

fn execute_sql(
    conn: &dyn OracleConnection,
    active_profile: Option<&str>,
    session: &SessionLevelState,
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
    let rows_affected = match conn.execute(&args.sql, &binds) {
        Ok(rows) => rows,
        Err(e) => {
            let _ = conn.rollback();
            return Err(DbError::into_envelope(e));
        }
    };
    if args.commit {
        conn.commit().map_err(DbError::into_envelope)?;
    } else {
        conn.rollback().map_err(DbError::into_envelope)?;
    }

    Ok(json!({
        "executed": true,
        "committed": args.commit,
        "rolled_back": !args.commit,
        "rows_affected": rows_affected,
        "required_level": required_level,
        "danger": decision.danger,
        "objects_affected": decision.objects_affected,
        "reason": decision.reason,
    }))
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
    let mut hasher = Sha256::new();
    hasher.update(b"oraclemcp:compile-confirmation:v1\0");
    hasher.update(active_profile.unwrap_or("").as_bytes());
    hasher.update(b"\0");
    hasher.update(owner.as_bytes());
    hasher.update(b"\0");
    hasher.update(name.as_bytes());
    hasher.update(b"\0");
    hasher.update(object_type.as_bytes());
    hasher.update(b"\0");
    hasher.update(if plscope { b"plscope=1" } else { b"plscope=0" });
    for stmt in statements {
        hasher.update(b"\0");
        hasher.update(stmt.as_bytes());
    }
    let digest = hasher.finalize();
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
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
    match gate {
        LevelDecision::RequireStepUp { target } => ErrorEnvelope::new(
            ErrorClass::OperatingLevelTooLow,
            format!(
                "compile requires {} but the active session level is {}",
                target.as_str(),
                session.effective_level().as_str()
            ),
        )
        .with_suggested_tool("oracle_compile_object")
        .with_next_step("call oracle_compile_object without execute=true to inspect the required level and confirmation token")
        .with_next_step("call oracle_set_session_level with level=\"DDL\" to preview a temporary elevation, or keep the profile read-only"),
        LevelDecision::Blocked { reason } => match reason {
            oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling } => {
                ErrorEnvelope::new(
                    ErrorClass::OperatingLevelTooLow,
                    format!(
                        "compile requires {} but the active profile ceiling is {}",
                        required.as_str(),
                        ceiling.as_str()
                    ),
                )
                .with_suggested_tool("oracle_list_profiles")
                .with_next_step("choose a profile whose max_level permits DDL")
            }
            _ => ErrorEnvelope::new(ErrorClass::PolicyDenied, "compile is blocked by policy"),
        },
        _ => ErrorEnvelope::new(
            ErrorClass::Internal,
            "compile gate produced an unexpected decision",
        ),
    }
}

fn compile_next_actions(
    gate: &LevelDecision,
    owner: &str,
    name: &str,
    object_type: &str,
    plscope: bool,
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
                        "execute": true,
                        "confirm": confirm,
                    },
                }));
            }
        }
        LevelDecision::RequireStepUp { target } => {
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
        LevelDecision::Blocked { reason } => {
            if let oraclemcp_guard::BlockReason::ExceedsCeiling { required, ceiling } = reason {
                actions.push(json!({
                    "intent": "choose_different_profile",
                    "tool": "oracle_list_profiles",
                    "args": {},
                    "required_level": required,
                    "current_ceiling": ceiling,
                }));
            }
        }
        _ => {}
    }
    Value::Array(actions)
}

fn compile_object(
    conn: &dyn OracleConnection,
    active_profile: Option<&str>,
    session: &SessionLevelState,
    tool_name: &str,
    args: CompileObjectArgs,
) -> Result<Value, ErrorEnvelope> {
    let object_name = required_non_empty_arg(tool_name, "name", args.name)?;
    let (owner, object_name) = owner_and_name_arg(conn, args.owner, object_name, "name")?;
    let object_type = normalize_compile_type_for_wire(&args.object_type);
    let statements = compile_object_statements(&object_type, &owner, &object_name, args.plscope)
        .map_err(DbError::into_envelope)?;
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
            "required_level": OperatingLevel::Ddl,
            "session_level": session.effective_level(),
            "profile_ceiling": session.effective_ceiling(),
            "gate_decision": gate_decision,
            "blocked_reason": blocked_reason,
            "step_up_target": step_up_target,
            "statements": statements,
            "confirmation": confirm.as_ref().map(|confirm| json!({
                "tool": "oracle_compile_object",
                "execute": true,
                "confirm": confirm,
            })),
            "next_actions": compile_next_actions(
                &gate,
                &owner,
                &object_name,
                &object_type,
                args.plscope,
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
    let Some(expected) = confirm else {
        return Err(ErrorEnvelope::new(
            ErrorClass::Internal,
            "compile confirmation could not be generated",
        ));
    };
    if args.confirm.as_deref() != Some(expected.as_str()) {
        return Err(ErrorEnvelope::new(
            ErrorClass::ChallengeRequired,
            "compile requires the confirmation token from a preview of this exact object/profile/options",
        )
        .with_suggested_tool("oracle_compile_object")
        .with_next_step("call oracle_compile_object without execute=true, then pass confirmation.confirm with execute=true"));
    }

    let mut rows_affected = Vec::with_capacity(statements.len());
    for stmt in &statements {
        rows_affected.push(conn.execute(stmt, &[]).map_err(DbError::into_envelope)?);
    }
    let errors =
        compile_errors(conn, &owner, Some(&object_name)).map_err(DbError::into_envelope)?;
    Ok(json!({
        "compiled": true,
        "preview": false,
        "owner": owner,
        "name": object_name,
        "object_type": object_type,
        "plscope": args.plscope,
        "required_level": OperatingLevel::Ddl,
        "statements_executed": statements,
        "rows_affected": rows_affected,
        "errors": rows_to_json(&errors),
        "error_count": errors.len(),
    }))
}

struct ReadOnlyCustomToolExecutor<'a> {
    conn: &'a dyn OracleConnection,
}

impl CustomToolExecutor for ReadOnlyCustomToolExecutor<'_> {
    fn run(
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
        read_query_named(
            self.conn,
            &sql,
            binds,
            QueryCaps::default(),
            0,
            &SerializeOptions::default(),
        )
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

fn canonical_tool_name(name: &str) -> &str {
    match name {
        "current_database" => "oracle_connection_info",
        "switch_database" => "oracle_switch_profile",
        "enable_writes" | "disable_writes" => "oracle_set_session_level",
        "query" => "oracle_query",
        "list_objects" => "oracle_schema_inspect",
        "list_schemas" => "oracle_list_schemas",
        "get_schema" => "oracle_schema_inspect",
        "compile_object" => "oracle_compile_object",
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
            let new_level = profile_level(&a.profile);
            let new_custom_catalog = match &self.custom_loader {
                Some(loader) => loader(&new_level)?,
                None => CustomToolCatalog::default(),
            };
            let mut state = self.state.lock().map_err(|_| {
                ErrorEnvelope::new(ErrorClass::Internal, "connection mutex poisoned")
            })?;
            state.conn = new_conn;
            state.active_profile = Some(a.profile.clone());
            state.level = new_level;
            state.custom_catalog = new_custom_catalog;
            return Ok(json!({
                "active_profile": a.profile,
                "connection": connection_info,
                "custom_tool_count": state.custom_catalog.len(),
            }));
        }

        // A poisoned mutex means a prior dispatch panicked while holding the
        // connection; surface it as an Internal error rather than re-panicking.
        let mut state = self
            .state
            .lock()
            .map_err(|_| ErrorEnvelope::new(ErrorClass::Internal, "connection mutex poisoned"))?;
        if tool == "oracle_set_session_level" {
            let a: SetSessionLevelArgs = parse_args(name, args)?;
            let active_profile = state.active_profile.clone();
            return set_session_level(&mut state.level, active_profile.as_deref(), name, a);
        }
        let conn: &dyn OracleConnection = state.conn.as_ref();

        let result: Result<Value, DbError> = match tool {
            "oracle_preview_sql" => {
                let a: PreviewSqlArgs = parse_args(name, args)?;
                Ok(preview_sql(
                    &a.sql,
                    &state.level,
                    state.active_profile.as_deref(),
                ))
            }
            "oracle_execute" => {
                let a: ExecuteArgs = parse_args(name, args)?;
                return execute_sql(conn, state.active_profile.as_deref(), &state.level, a);
            }
            "oracle_compile_object" => {
                let a: CompileObjectArgs = parse_args(name, args)?;
                return compile_object(
                    conn,
                    state.active_profile.as_deref(),
                    &state.level,
                    name,
                    a,
                );
            }
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
                    query_caps_from_args(&a),
                    offset,
                    &query_serialize_options_from_args(&a),
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
            "oracle_list_schemas" => {
                let a: ListSchemasArgs = parse_args(name, args)?;
                let name_like = non_empty_arg(a.name_like);
                let max_rows = a
                    .max_rows
                    .unwrap_or(DEFAULT_SCHEMA_LIST_MAX_ROWS)
                    .clamp(1, MAX_SCHEMA_LIST_MAX_ROWS);
                list_schemas(conn, name_like.as_deref(), max_rows).map(|rows| {
                    json!({
                        "schemas": rows_to_json(&rows),
                        "name_like": name_like,
                        "max_rows": max_rows,
                        "truncated": rows.len() == max_rows,
                    })
                })
            }
            "oracle_describe" => {
                let a: DescribeArgs = parse_args(name, args)?;
                let table = required_non_empty_arg(name, "table", a.table)?;
                let (owner, table) = owner_and_name_arg(conn, a.owner, table, "table")?;
                describe_columns(conn, &owner, &table).and_then(|columns| {
                    describe_constraints(conn, &owner, &table).map(|constraints| {
                        json!({
                            "owner": owner,
                            "table": table,
                            "columns": rows_to_json(&columns),
                            "constraints": rows_to_json(&constraints),
                        })
                    })
                })
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
                match a.object_type.as_deref().filter(|s| !s.trim().is_empty()) {
                    Some(object_type) => {
                        get_source(conn, &owner, &object_name, object_type, max_chars)
                            .map(|source| json!({ "source": source }))
                    }
                    None => {
                        get_sources_by_name(conn, &owner, &object_name, max_chars).map(|sources| {
                            json!({
                                "owner": owner,
                                "name": object_name,
                                "source_count": sources.len(),
                                "sources": sources,
                            })
                        })
                    }
                }
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
                let max_rows = a
                    .max_rows
                    .unwrap_or(DEFAULT_SEARCH_MAX_ROWS)
                    .clamp(1, MAX_SEARCH_MAX_ROWS);
                let requested_owner = non_empty_arg(a.owner);
                let owner = match requested_owner.as_deref() {
                    Some("*") => None,
                    Some(owner) => Some(owner.to_ascii_uppercase()),
                    None => Some(owner_or_current(conn, None).map_err(DbError::into_envelope)?),
                };
                let object_type = non_empty_arg(a.object_type);
                let name_like = non_empty_arg(a.name_like);
                search_source(
                    conn,
                    owner.as_deref(),
                    &a.needle,
                    object_type.as_deref(),
                    name_like.as_deref(),
                    max_rows,
                )
                .map(|rows| {
                    json!({
                        "owner": owner.as_deref().unwrap_or("*"),
                        "object_type": object_type,
                        "name_like": name_like,
                        "max_rows": max_rows,
                        "matches": rows_to_json(&rows),
                    })
                })
            }
            "oracle_plscope_inspect" => {
                let a: PlscopeInspectArgs = parse_args(name, args)?;
                let object_name = required_non_empty_arg(name, "name", a.name)?;
                let (owner, object_name) = owner_and_name_arg(conn, a.owner, object_name, "name")?;
                let identifiers = plscope_identifiers(conn, &owner, &object_name)
                    .map_err(DbError::into_envelope)?;
                let statements = plscope_statements(conn, &owner, &object_name)
                    .map_err(DbError::into_envelope)?;
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
                explain_plan(conn, &a.sql, a.read_only_standby)
                    .map(|rows| json!({ "plan": rows_to_json(&rows) }))
            }
            other => {
                if let Some(loaded) = state.custom_catalog.get(other) {
                    let executor = ReadOnlyCustomToolExecutor { conn };
                    return execute_custom_tool(loaded, &args, &executor);
                }
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn read_write_level() -> SessionLevelState {
        let mut level = SessionLevelState::new(OperatingLevel::ReadWrite, false);
        level
            .set_current_level(OperatingLevel::ReadWrite)
            .expect("read/write is within ceiling");
        level
    }

    fn ddl_level() -> SessionLevelState {
        let mut level = SessionLevelState::new(OperatingLevel::Ddl, false);
        level
            .set_current_level(OperatingLevel::Ddl)
            .expect("ddl is within ceiling");
        level
    }

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
                read_only: false,
                read_only_reason: None,
                current_schema: Some("APP".to_owned()),
                current_edition: Some("ORA$BASE".to_owned()),
                session_user: Some("APP".to_owned()),
                current_user: Some("APP".to_owned()),
                module: Some("oraclemcp-test".to_owned()),
                action: None,
                client_identifier: Some("agent".to_owned()),
                client_info: None,
                os_user: Some("operator".to_owned()),
                host: Some("workstation".to_owned()),
                machine: Some("workstation".to_owned()),
                terminal: None,
                program: Some("oraclemcp".to_owned()),
                client_driver: Some("oraclemcp-driver".to_owned()),
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
                        "SCHEMA_NAME".to_owned(),
                        OracleCell::new("VARCHAR2", Some("APP".to_owned())),
                    ),
                    (
                        "OBJECT_COUNT".to_owned(),
                        OracleCell::new("NUMBER", Some("42".to_owned())),
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
        fn query_rows_named(
            &self,
            sql: &str,
            b: &[(String, OracleBind)],
        ) -> Result<Vec<OracleRow>, DbError> {
            assert!(
                sql.contains(":id"),
                "custom SQL should preserve named bind references: {sql}"
            );
            assert_eq!(b, &[("id".to_owned(), OracleBind::I64(7))]);
            self.query_rows(sql, &[])
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

    struct SourceLookupMock;
    impl OracleConnection for SourceLookupMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        fn ping(&self) -> Result<(), DbError> {
            Ok(())
        }
        fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo {
                backend: Some(OracleBackend::RustOracle),
                current_schema: Some("APP".to_owned()),
                ..Default::default()
            })
        }
        fn query_rows(&self, sql: &str, _b: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
            if sql.contains("SELECT type") {
                return Ok(vec![
                    OracleRow {
                        columns: vec![(
                            "TYPE".to_owned(),
                            OracleCell::new("VARCHAR2", Some("PACKAGE".to_owned())),
                        )],
                    },
                    OracleRow {
                        columns: vec![(
                            "TYPE".to_owned(),
                            OracleCell::new("VARCHAR2", Some("PACKAGE BODY".to_owned())),
                        )],
                    },
                ]);
            }

            Ok(vec![OracleRow {
                columns: vec![(
                    "TEXT".to_owned(),
                    OracleCell::new("VARCHAR2", Some("BEGIN NULL; END;\n".to_owned())),
                )],
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

    #[derive(Default)]
    struct ExecState {
        executed: Mutex<Vec<(String, Vec<OracleBind>)>>,
        commits: AtomicUsize,
        rollbacks: AtomicUsize,
    }

    struct ExecRecordingMock {
        state: Arc<ExecState>,
        rows_affected: u64,
    }

    impl ExecRecordingMock {
        fn new(state: Arc<ExecState>) -> Self {
            Self {
                state,
                rows_affected: 3,
            }
        }
    }

    impl OracleConnection for ExecRecordingMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        fn ping(&self) -> Result<(), DbError> {
            Ok(())
        }

        fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo {
                backend: Some(OracleBackend::RustOracle),
                current_schema: Some("APP".to_owned()),
                ..Default::default()
            })
        }

        fn query_rows(&self, _sql: &str, _b: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
            Ok(Vec::new())
        }

        fn execute(&self, sql: &str, b: &[OracleBind]) -> Result<u64, DbError> {
            self.state
                .executed
                .lock()
                .expect("exec mutex")
                .push((sql.to_owned(), b.to_vec()));
            Ok(self.rows_affected)
        }

        fn commit(&self) -> Result<(), DbError> {
            self.state.commits.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn rollback(&self) -> Result<(), DbError> {
            self.state.rollbacks.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Minimal valid args for a given tool name (matches the registry schemas).
    fn args_for(name: &str) -> Value {
        match name {
            "oracle_list_profiles" => json!({}),
            "oracle_connection_info" => json!({}),
            "oracle_switch_profile" => json!({ "profile": "other" }),
            "oracle_set_session_level" => json!({ "action": "status" }),
            "oracle_query" => json!({ "sql": "SELECT 1 FROM dual" }),
            "oracle_list_schemas" => json!({ "name_like": "APP%", "limit": 10 }),
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
            "oracle_plscope_inspect" => json!({ "owner": "HR", "name": "PKG" }),
            "oracle_explain_plan" => json!({ "sql": "SELECT 1 FROM dual" }),
            "oracle_preview_sql" => json!({ "sql": "SELECT 1 FROM dual" }),
            "oracle_execute" => {
                json!({ "sql": "UPDATE employees SET name = name WHERE employee_id = 100" })
            }
            "oracle_compile_object" => json!({ "object_type": "PACKAGE", "name": "EMP_API" }),
            "current_database" => json!({}),
            "switch_database" => json!({ "db": "other" }),
            "enable_writes" => json!({ "ttl_seconds": 60 }),
            "disable_writes" => json!({}),
            "query" => json!({ "sql": "SELECT 1 FROM dual" }),
            "compile_object" => json!({ "object_type": "PACKAGE", "object_name": "EMP_API" }),
            "list_objects" => json!({ "owner": "HR" }),
            "list_schemas" => json!({ "name_like": "APP%" }),
            "get_schema" => json!({ "owner": "HR" }),
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
            "preview_sql" => json!({ "sql": "SELECT 1 FROM dual" }),
            other => panic!("no test args for {other}"),
        }
    }

    #[test]
    fn every_registry_tool_routes_and_deserializes_offline() {
        for name in TOOL_NAMES {
            let dispatcher = OracleDispatcher::new_switchable(
                Box::new(OneRowMock),
                Some("dev".to_owned()),
                ddl_level(),
                Arc::new(|_| Ok(Box::new(OneRowMock))),
            );
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
            default_read_only_level(),
            Arc::new(|_| Ok(Box::new(OneRowMock))),
        );
        for name in [
            "current_database",
            "switch_database",
            "query",
            "compile_object",
            "list_objects",
            "list_schemas",
            "get_schema",
            "describe_table",
            "describe_index",
            "describe_trigger",
            "describe_view",
            "get_ddl",
            "get_object_source",
            "get_errors",
            "get_clob",
            "preview_sql",
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
        assert_eq!(out["connection"]["module"], json!("oraclemcp-test"));
        assert_eq!(out["connection"]["client_identifier"], json!("agent"));
        assert_eq!(out["connection"]["program"], json!("oraclemcp"));
        assert_eq!(
            out["connection"]["client_driver"],
            json!("oraclemcp-driver")
        );
        assert_eq!(out["connection"]["read_only"], json!(false));
    }

    #[test]
    fn failed_profile_switch_does_not_replace_the_current_connection() {
        let dispatcher = OracleDispatcher::new_switchable(
            Box::new(OneRowMock),
            Some("dev".to_owned()),
            default_read_only_level(),
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
    fn list_schemas_accepts_filter_and_limit_alias() {
        let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
        let out = dispatcher
            .dispatch("list_schemas", json!({ "name_like": "app%", "limit": 10 }))
            .expect("schema listing accepts filter and limit alias");
        assert_eq!(out["name_like"], json!("app%"));
        assert_eq!(out["max_rows"], json!(10));
        assert!(out["schemas"].is_array());
        assert_eq!(out["schemas"][0]["SCHEMA_NAME"], json!("APP"));
        assert_eq!(out["schemas"][0]["OBJECT_COUNT"], json!("42"));
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
        assert!(described["constraints"].is_array());

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

        let all_matches = dispatcher
            .dispatch(
                "oracle_search_source",
                json!({
                    "owner": "*",
                    "needle": "commit",
                    "object_type": "package_body",
                    "name_like": "emp%",
                    "max_rows": 999999
                }),
            )
            .expect("search source accepts all-owner and scope filters");
        assert_eq!(all_matches["owner"], json!("*"));
        assert_eq!(all_matches["object_type"], json!("package_body"));
        assert_eq!(all_matches["name_like"], json!("emp%"));
        assert_eq!(all_matches["max_rows"], json!(5000));

        let plscope = dispatcher
            .dispatch(
                "oracle_plscope_inspect",
                json!({ "object_name": "APP.PKG" }),
            )
            .expect("plscope inspect accepts object_name alias and qualified name");
        assert_eq!(plscope["owner"], json!("APP"));
        assert_eq!(plscope["name"], json!("PKG"));
        assert!(plscope["identifiers"].is_array());
        assert!(plscope["statements"].is_array());
    }

    #[test]
    fn get_source_without_object_type_returns_all_visible_sources() {
        let dispatcher = OracleDispatcher::new(Box::new(SourceLookupMock));
        let out = dispatcher
            .dispatch("oracle_get_source", json!({ "name": "EMP_API" }))
            .expect("source lookup can infer visible source types");
        assert_eq!(out["owner"], json!("APP"));
        assert_eq!(out["name"], json!("EMP_API"));
        assert_eq!(out["source_count"], json!(2));
        assert_eq!(out["sources"][0]["object_type"], json!("PACKAGE"));
        assert_eq!(out["sources"][1]["object_type"], json!("PACKAGE BODY"));
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
    fn custom_read_only_tool_dispatches_with_named_binds() {
        let defs = oraclemcp_core::parse_tools_file(
            r#"
            [[tool]]
            name = "app_customer_lookup"
            description = "Lookup a customer row by id"
            sql = "SELECT id, name FROM app_customers WHERE id = :id"
            output_mode = "rows"

            [[tool.params]]
            name = "id"
            type = "integer"
            required = true
            description = "Customer id"
            "#,
        )
        .expect("custom tool parses");
        let loaded = oraclemcp_core::load_tools(
            &defs,
            &Classifier::new(ClassifierConfig::new()),
            OperatingLevel::ReadOnly,
        )
        .expect("custom tool loads");
        let dispatcher = OracleDispatcher::new_switchable_with_custom_tools(
            Box::new(OneRowMock),
            Some("dev".to_owned()),
            default_read_only_level(),
            Arc::new(|_| Ok(Box::new(OneRowMock))),
            CustomToolCatalog::new(loaded),
            None,
        );

        let out = dispatcher
            .dispatch("app_customer_lookup", json!({ "id": 7 }))
            .expect("custom tool dispatches");
        assert_eq!(out["row_count"], json!(1));
        assert_eq!(out["rows"][0]["OBJECT_NAME"], json!("EMPLOYEES"));
    }

    #[test]
    fn malformed_args_are_invalid_arguments_not_a_panic() {
        let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
        // Missing required `table`.
        let err = dispatcher
            .dispatch("oracle_describe", json!({ "owner": "HR" }))
            .expect_err("missing required arg errors");
        assert_eq!(err.error_class, ErrorClass::InvalidArguments);

        let err = dispatcher
            .dispatch("oracle_plscope_inspect", json!({ "owner": "HR" }))
            .expect_err("missing PL/Scope object name errors");
        assert_eq!(err.error_class, ErrorClass::InvalidArguments);
        assert!(err.message.contains("missing required `name`"));
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
    fn query_accepts_page_and_width_compatibility_args() {
        let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
        let out = dispatcher
            .dispatch(
                "query",
                json!({
                    "sql": "SELECT object_name, lob_value FROM user_objects",
                    "limit": 25,
                    "max_col_width": 3,
                    "max_lob_chars": 4,
                    "max_result_bytes": 4096,
                    "numbers_as_float": false
                }),
            )
            .expect("query args accepted");
        assert_eq!(out["row_count"], json!(1));
        assert_eq!(out["rows"][0]["OBJECT_NAME"]["value"], json!("EMP"));
        assert_eq!(out["rows"][0]["OBJECT_NAME"]["truncated"], json!(true));
        assert_eq!(out["rows"][0]["LOB_VALUE"]["value"], json!("larg"));
        assert_eq!(out["rows"][0]["LOB_VALUE"]["truncated"], json!(true));
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
    fn preview_sql_reports_read_only_gate_decision_without_running_sql() {
        let dispatcher = OracleDispatcher::new(Box::new(NoExecMock));
        let select = dispatcher
            .dispatch("oracle_preview_sql", json!({ "sql": "SELECT 1 FROM dual" }))
            .expect("preview select");
        assert_eq!(select["allowed_on_read_only"], json!(true));
        assert_eq!(select["gate_decision"], json!("allow"));
        assert_eq!(select["required_level"], json!("READ_ONLY"));
        assert_eq!(select["session_level"], json!("READ_ONLY"));
        assert_eq!(select["profile_ceiling"], json!("READ_ONLY"));
        assert_eq!(select["next_actions"][0]["tool"], json!("oracle_query"));
        assert_eq!(select["next_actions"][0]["intent"], json!("run_read"));

        let write = dispatcher
            .dispatch("preview_sql", json!({ "sql": "DELETE FROM t" }))
            .expect("preview write alias");
        assert_eq!(write["allowed_on_read_only"], json!(false));
        assert_ne!(write["gate_decision"], json!("allow"));
        assert_eq!(
            write["next_actions"][0]["tool"],
            json!("oracle_list_profiles")
        );
    }

    #[test]
    fn preview_sql_uses_configured_profile_ceiling() {
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(NoExecMock),
            Some("dev".to_owned()),
            SessionLevelState::new(OperatingLevel::Ddl, false),
        );

        let write = dispatcher
            .dispatch(
                "oracle_preview_sql",
                json!({ "sql": "DELETE FROM t WHERE id = 1" }),
            )
            .expect("preview write");
        assert_eq!(write["allowed_on_read_only"], json!(false));
        assert_eq!(write["gate_decision"], json!("require_step_up"));
        assert_eq!(write["step_up_target"], json!("READ_WRITE"));
        assert_eq!(write["profile_ceiling"], json!("DDL"));
        assert_eq!(write["protected"], json!(false));
        assert_eq!(
            write["next_actions"][0]["tool"],
            json!("oracle_set_session_level")
        );

        let ddl = dispatcher
            .dispatch(
                "oracle_preview_sql",
                json!({ "sql": "CREATE TABLE t (id NUMBER)" }),
            )
            .expect("preview ddl");
        assert_eq!(ddl["gate_decision"], json!("require_step_up"));
        assert_eq!(ddl["step_up_target"], json!("DDL"));
    }

    #[test]
    fn set_session_level_previews_before_elevating() {
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(NoExecMock),
            Some("dev".to_owned()),
            SessionLevelState::new(OperatingLevel::ReadWrite, false),
        );

        let out = dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({ "level": "READ_WRITE", "ttl_seconds": 60 }),
            )
            .expect("session level preview");
        assert_eq!(out["preview"], json!(true));
        assert_eq!(out["changed"], json!(false));
        assert_eq!(out["target_level"], json!("READ_WRITE"));
        assert_eq!(out["session"]["current_level"], json!("READ_ONLY"));
        assert_eq!(out["session"]["profile_ceiling"], json!("READ_WRITE"));
        assert_eq!(out["gate"]["decision"], json!("require_step_up"));
        assert_eq!(
            out["confirmation"]["tool"],
            json!("oracle_set_session_level")
        );
        assert!(out["confirmation"]["confirm"].as_str().is_some());

        let write = dispatcher
            .dispatch(
                "oracle_preview_sql",
                json!({ "sql": "DELETE FROM t WHERE id = 1" }),
            )
            .expect("preview write after level preview only");
        assert_eq!(write["gate_decision"], json!("require_step_up"));
    }

    #[test]
    fn set_session_level_requires_confirmation_to_apply() {
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(NoExecMock),
            Some("dev".to_owned()),
            SessionLevelState::new(OperatingLevel::ReadWrite, false),
        );

        let err = dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({ "level": "READ_WRITE", "ttl_seconds": 60, "execute": true }),
            )
            .expect_err("elevation requires preview token");
        assert_eq!(err.error_class, ErrorClass::ChallengeRequired);

        let preview = dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({ "level": "READ_WRITE", "ttl_seconds": 60 }),
            )
            .expect("preview supplies token");
        let confirm = preview["confirmation"]["confirm"]
            .as_str()
            .expect("confirm token");
        let applied = dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({ "level": "READ_WRITE", "ttl_seconds": 60, "execute": true, "confirm": confirm }),
            )
            .expect("confirmed elevation applies");
        assert_eq!(applied["changed"], json!(true));
        assert_eq!(applied["session"]["current_level"], json!("READ_WRITE"));
        assert_eq!(applied["session"]["has_active_elevation"], json!(true));

        let write = dispatcher
            .dispatch(
                "oracle_preview_sql",
                json!({ "sql": "DELETE FROM t WHERE id = 1" }),
            )
            .expect("write is now within current session level");
        assert_eq!(write["gate_decision"], json!("allow"));
        assert!(write["execute_confirmation"]["confirm"].as_str().is_some());
    }

    #[test]
    fn set_session_level_can_lower_without_confirmation() {
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(NoExecMock),
            Some("dev".to_owned()),
            ddl_level(),
        );

        let preview = dispatcher
            .dispatch("oracle_set_session_level", json!({ "level": "READ_WRITE" }))
            .expect("lowering preview");
        assert_eq!(preview["preview"], json!(true));
        assert_eq!(preview["gate"]["decision"], json!("allow_lowering"));
        assert_eq!(preview["confirmation"], Value::Null);

        let lowered = dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({ "level": "READ_WRITE", "action": "apply" }),
            )
            .expect("lowering applies without confirmation");
        assert_eq!(lowered["changed"], json!(true));
        assert_eq!(lowered["session"]["current_level"], json!("READ_WRITE"));

        let ddl = dispatcher
            .dispatch(
                "oracle_preview_sql",
                json!({ "sql": "CREATE TABLE t (id NUMBER)" }),
            )
            .expect("ddl now requires step-up again");
        assert_eq!(ddl["gate_decision"], json!("require_step_up"));
    }

    #[test]
    fn set_session_level_cannot_exceed_profile_ceiling() {
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(NoExecMock),
            Some("ro".to_owned()),
            SessionLevelState::new(OperatingLevel::ReadOnly, true),
        );

        let preview = dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({ "level": "READ_WRITE", "ttl_seconds": 60 }),
            )
            .expect("blocked preview is still inspectable");
        assert_eq!(preview["preview"], json!(true));
        assert_eq!(preview["gate"]["decision"], json!("blocked"));
        assert_eq!(preview["confirmation"], Value::Null);
        assert_eq!(
            preview["next_actions"][0]["tool"],
            json!("oracle_list_profiles")
        );

        let err = dispatcher
            .dispatch(
                "oracle_set_session_level",
                json!({ "level": "READ_WRITE", "ttl_seconds": 60, "execute": true, "confirm": "wrong" }),
            )
            .expect_err("ceiling blocks even with execute=true");
        assert_eq!(err.error_class, ErrorClass::OperatingLevelTooLow);
    }

    #[test]
    fn write_compatibility_aliases_share_session_level_gate() {
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(NoExecMock),
            Some("dev".to_owned()),
            SessionLevelState::new(OperatingLevel::ReadWrite, false),
        );

        let preview = dispatcher
            .dispatch(
                "enable_writes",
                json!({ "ttl_seconds": 60, "db": "ignored" }),
            )
            .expect("enable_writes previews READ_WRITE elevation");
        assert_eq!(preview["preview"], json!(true));
        assert_eq!(preview["target_level"], json!("READ_WRITE"));
        assert_eq!(preview["confirmation"]["tool"], json!("enable_writes"));
        let confirm = preview["confirmation"]["confirm"]
            .as_str()
            .expect("confirm token");

        let applied = dispatcher
            .dispatch(
                "enable_writes",
                json!({ "ttl_seconds": 60, "execute": true, "confirm": confirm }),
            )
            .expect("enable_writes applies with confirmation");
        assert_eq!(applied["session"]["current_level"], json!("READ_WRITE"));

        let dropped = dispatcher
            .dispatch("disable_writes", json!({}))
            .expect("disable_writes drops immediately");
        assert_eq!(dropped["changed"], json!(true));
        assert_eq!(dropped["session"]["current_level"], json!("READ_ONLY"));

        let write = dispatcher
            .dispatch(
                "oracle_preview_sql",
                json!({ "sql": "DELETE FROM t WHERE id = 1" }),
            )
            .expect("write requires step-up again");
        assert_eq!(write["gate_decision"], json!("require_step_up"));
    }

    #[test]
    fn preview_sql_includes_execute_confirmation_for_allowed_write() {
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(NoExecMock),
            Some("dev".to_owned()),
            read_write_level(),
        );

        let preview = dispatcher
            .dispatch(
                "oracle_preview_sql",
                json!({ "sql": "UPDATE employees SET name = name WHERE employee_id = 100" }),
            )
            .expect("preview write");
        assert_eq!(preview["gate_decision"], json!("allow"));
        assert_eq!(
            preview["execute_confirmation"]["tool"],
            json!("oracle_execute")
        );
        assert_eq!(preview["execute_confirmation"]["commit"], json!(true));
        assert_eq!(
            preview["execute_confirmation"]["required_level"],
            json!("READ_WRITE")
        );
        assert_eq!(
            preview["execute_confirmation"]["confirm"]
                .as_str()
                .expect("token")
                .len(),
            16
        );
        assert_eq!(
            preview["next_actions"][0]["intent"],
            json!("rollback_preview")
        );
        assert_eq!(preview["next_actions"][0]["tool"], json!("oracle_execute"));
        assert_eq!(preview["next_actions"][0]["args"]["commit"], json!(false));
        assert_eq!(preview["next_actions"][1]["intent"], json!("commit"));
        assert_eq!(
            preview["next_actions"][1]["args"]["confirm"],
            preview["execute_confirmation"]["confirm"]
        );
    }

    #[test]
    fn execute_rolls_back_dml_by_default() {
        let state = Arc::new(ExecState::default());
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(state.clone())),
            Some("dev".to_owned()),
            read_write_level(),
        );

        let out = dispatcher
            .dispatch(
                "oracle_execute",
                json!({
                    "sql": "UPDATE employees SET name = name WHERE employee_id = :1",
                    "binds": [100]
                }),
            )
            .expect("execute rollback");
        assert_eq!(out["executed"], json!(true));
        assert_eq!(out["committed"], json!(false));
        assert_eq!(out["rolled_back"], json!(true));
        assert_eq!(out["rows_affected"], json!(3));
        assert_eq!(state.commits.load(Ordering::SeqCst), 0);
        assert_eq!(state.rollbacks.load(Ordering::SeqCst), 1);
        let executed = state.executed.lock().expect("exec mutex");
        assert_eq!(executed.len(), 1);
        assert_eq!(executed[0].1, vec![OracleBind::I64(100)]);
    }

    #[test]
    fn execute_commit_requires_preview_confirmation_without_executing() {
        let state = Arc::new(ExecState::default());
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(state.clone())),
            Some("dev".to_owned()),
            read_write_level(),
        );

        let err = dispatcher
            .dispatch(
                "oracle_execute",
                json!({
                    "sql": "UPDATE employees SET name = name WHERE employee_id = 100",
                    "commit": true
                }),
            )
            .expect_err("commit needs confirmation");
        assert_eq!(err.error_class, ErrorClass::ChallengeRequired);
        assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
        assert_eq!(state.commits.load(Ordering::SeqCst), 0);
        assert_eq!(state.rollbacks.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn execute_commit_with_preview_confirmation_commits() {
        let state = Arc::new(ExecState::default());
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(state.clone())),
            Some("dev".to_owned()),
            read_write_level(),
        );
        let sql = "UPDATE employees SET name = name WHERE employee_id = 100";
        let preview = dispatcher
            .dispatch("oracle_preview_sql", json!({ "sql": sql }))
            .expect("preview");
        let confirm = preview["execute_confirmation"]["confirm"]
            .as_str()
            .expect("confirm");

        let out = dispatcher
            .dispatch(
                "oracle_execute",
                json!({ "sql": sql, "commit": true, "confirm": confirm }),
            )
            .expect("execute commit");
        assert_eq!(out["committed"], json!(true));
        assert_eq!(out["rolled_back"], json!(false));
        assert_eq!(state.commits.load(Ordering::SeqCst), 1);
        assert_eq!(state.rollbacks.load(Ordering::SeqCst), 0);
        assert_eq!(state.executed.lock().expect("exec mutex").len(), 1);
    }

    #[test]
    fn execute_rejects_write_below_current_level_without_executing() {
        let state = Arc::new(ExecState::default());
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(state.clone())),
            Some("dev".to_owned()),
            SessionLevelState::new(OperatingLevel::ReadWrite, false),
        );

        let err = dispatcher
            .dispatch(
                "oracle_execute",
                json!({ "sql": "UPDATE employees SET name = name WHERE employee_id = 100" }),
            )
            .expect_err("write needs elevated/default read-write level");
        assert_eq!(err.error_class, ErrorClass::OperatingLevelTooLow);
        assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
    }

    #[test]
    fn execute_requires_commit_confirmation_for_ddl_without_executing() {
        let state = Arc::new(ExecState::default());
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(state.clone())),
            Some("dev".to_owned()),
            ddl_level(),
        );

        let err = dispatcher
            .dispatch(
                "oracle_execute",
                json!({ "sql": "CREATE TABLE app_smoke_execute (id NUMBER)" }),
            )
            .expect_err("ddl cannot rollback-preview");
        assert_eq!(err.error_class, ErrorClass::ChallengeRequired);
        assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
    }

    #[test]
    fn compile_object_preview_is_default_and_does_not_execute() {
        let state = Arc::new(ExecState::default());
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(state.clone())),
            Some("dev".to_owned()),
            ddl_level(),
        );

        let preview = dispatcher
            .dispatch(
                "oracle_compile_object",
                json!({ "object_type": "PACKAGE_BODY", "owner": "APP", "name": "EMP_API", "plscope": true }),
            )
            .expect("compile preview");
        assert_eq!(preview["compiled"], json!(false));
        assert_eq!(preview["preview"], json!(true));
        assert_eq!(preview["required_level"], json!("DDL"));
        assert_eq!(preview["gate_decision"], json!("allow"));
        assert_eq!(
            preview["statements"][0],
            json!("ALTER SESSION SET PLSCOPE_SETTINGS = 'IDENTIFIERS:ALL, STATEMENTS:ALL'")
        );
        assert_eq!(
            preview["statements"][1],
            json!("ALTER PACKAGE APP.EMP_API COMPILE BODY")
        );
        assert_eq!(
            preview["confirmation"]["tool"],
            json!("oracle_compile_object")
        );
        assert_eq!(preview["next_actions"][0]["intent"], json!("compile"));
        assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
    }

    #[test]
    fn compile_object_requires_ddl_level_without_executing() {
        let state = Arc::new(ExecState::default());
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(state.clone())),
            Some("dev".to_owned()),
            read_write_level(),
        );

        let err = dispatcher
            .dispatch(
                "oracle_compile_object",
                json!({
                    "object_type": "PACKAGE",
                    "name": "EMP_API",
                    "execute": true,
                    "confirm": "bad"
                }),
            )
            .expect_err("read/write is not enough for compile");
        assert_eq!(err.error_class, ErrorClass::OperatingLevelTooLow);
        assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
    }

    #[test]
    fn compile_object_execute_requires_preview_confirmation() {
        let state = Arc::new(ExecState::default());
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(state.clone())),
            Some("dev".to_owned()),
            ddl_level(),
        );

        let err = dispatcher
            .dispatch(
                "compile_object",
                json!({
                    "object_type": "PACKAGE",
                    "object_name": "EMP_API",
                    "execute": true
                }),
            )
            .expect_err("confirmation required");
        assert_eq!(err.error_class, ErrorClass::ChallengeRequired);
        assert_eq!(state.executed.lock().expect("exec mutex").len(), 0);
    }

    #[test]
    fn compile_object_execute_runs_statements_and_returns_compile_errors() {
        let state = Arc::new(ExecState::default());
        let dispatcher = OracleDispatcher::new_with_profile_level(
            Box::new(ExecRecordingMock::new(state.clone())),
            Some("dev".to_owned()),
            ddl_level(),
        );
        let preview = dispatcher
            .dispatch(
                "oracle_compile_object",
                json!({ "object_type": "PACKAGE", "name": "EMP_API" }),
            )
            .expect("preview");
        let confirm = preview["confirmation"]["confirm"]
            .as_str()
            .expect("confirm");

        let out = dispatcher
            .dispatch(
                "oracle_compile_object",
                json!({
                    "object_type": "PACKAGE",
                    "name": "EMP_API",
                    "execute": true,
                    "confirm": confirm
                }),
            )
            .expect("compile executes");
        assert_eq!(out["compiled"], json!(true));
        assert_eq!(out["object_type"], json!("PACKAGE"));
        assert_eq!(
            out["statements_executed"][0],
            json!("ALTER PACKAGE APP.EMP_API COMPILE")
        );
        assert!(out["errors"].is_array());
        let executed = state.executed.lock().expect("exec mutex");
        assert_eq!(executed.len(), 1);
        assert_eq!(executed[0].0, "ALTER PACKAGE APP.EMP_API COMPILE");
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
