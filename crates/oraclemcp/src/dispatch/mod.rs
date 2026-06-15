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
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use asupersync::Cx;
use oraclemcp_config::OracleMcpConfig;
use oraclemcp_core::{
    CustomToolCatalog, CustomToolExecutor, DispatchFuture, ToolBody, ToolDispatch,
    execute_custom_tool,
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

/// Reconnect callback used by `oracle_switch_profile`.
pub type ProfileConnector =
    dyn Fn(&str) -> Result<Box<dyn OracleConnection>, DbError> + Send + Sync + 'static;

/// Profile-scoped custom-tool loader used by `oracle_switch_profile`.
pub type CustomToolLoader = dyn Fn(Option<&str>, &SessionLevelState) -> Result<CustomToolCatalog, ErrorEnvelope>
    + Send
    + Sync
    + 'static;

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
                execute_approved_tokens: HashMap::new(),
                patch_previews: HashMap::new(),
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
                execute_approved_tokens: HashMap::new(),
                patch_previews: HashMap::new(),
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
    }
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

fn with_call_timeout<T>(
    conn: &dyn OracleConnection,
    timeout_seconds: Option<u64>,
    f: impl FnOnce() -> Result<T, ErrorEnvelope>,
) -> Result<T, ErrorEnvelope> {
    let Some(timeout) = call_timeout_duration(timeout_seconds)? else {
        return f();
    };
    let previous = conn.call_timeout().map_err(DbError::into_envelope)?;
    conn.set_call_timeout(Some(timeout))
        .map_err(DbError::into_envelope)?;
    let result = f();
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

mod args;
use args::*;

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
    if state.level.evaluate(Some(grant.required_level)) != LevelDecision::Allow {
        return Err(execute_gate_error(
            &Classifier::new(ClassifierConfig::new()).classify(&grant.sql),
            state.level.evaluate(Some(grant.required_level)),
            &state.level,
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

fn execute_sql(
    conn: &dyn OracleConnection,
    active_profile: Option<&str>,
    session: &SessionLevelState,
    args: ExecuteArgs,
) -> Result<Value, ErrorEnvelope> {
    with_call_timeout(conn, args.timeout_seconds, || {
        execute_sql_inner(conn, active_profile, session, args)
    })
}

fn execute_sql_inner(
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
    let dbms_output_limits = if args.capture_dbms_output {
        let (max_lines, max_chars, buffer_bytes) = dbms_output_limits(&args);
        conn.enable_dbms_output(Some(buffer_bytes))
            .map_err(DbError::into_envelope)?;
        Some((max_lines, max_chars))
    } else {
        None
    };
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
    let dbms_output = match dbms_output_limits {
        Some((max_lines, max_chars)) => Some(
            conn.read_dbms_output(max_lines, max_chars)
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

fn compile_object(
    conn: &dyn OracleConnection,
    active_profile: Option<&str>,
    session: &SessionLevelState,
    tool_name: &str,
    args: CompileObjectArgs,
) -> Result<Value, ErrorEnvelope> {
    with_call_timeout(conn, args.timeout_seconds, || {
        compile_object_inner(conn, active_profile, session, tool_name, args)
    })
}

fn compile_object_inner(
    conn: &dyn OracleConnection,
    active_profile: Option<&str>,
    session: &SessionLevelState,
    tool_name: &str,
    args: CompileObjectArgs,
) -> Result<Value, ErrorEnvelope> {
    let object_name = required_non_empty_arg(tool_name, "name", args.name)?;
    let (owner, object_name) = owner_and_name_arg(conn, args.owner, object_name, "name")?;
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
        rows_affected.push(conn.execute(stmt, &[]).map_err(DbError::into_envelope)?);
    }
    let errors =
        compile_errors(conn, &owner, Some(&object_name)).map_err(DbError::into_envelope)?;
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

fn detect_create_or_replace_object(
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
    let (owner, name) = owner_and_name_arg(conn, None, name, "name").ok()?;
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

fn fetch_patch_source_document(
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
    object_type: &str,
    max_chars: usize,
) -> Result<PatchSourceDocument, ErrorEnvelope> {
    if object_type == "VIEW" {
        let ddl = get_ddl(conn, "VIEW", owner, name)
            .map_err(DbError::into_envelope)?
            .ok_or_else(|| {
                ErrorEnvelope::new(
                    ErrorClass::ObjectNotFound,
                    format!("VIEW {owner}.{name} is not visible to this session"),
                )
                .with_suggested_tool("oracle_get_ddl")
            })?;
        return Ok(PatchSourceDocument {
            char_count: ddl.chars().count(),
            text: ddl,
            source_kind: "dbms_metadata",
            line_count: None,
        });
    }

    let source =
        get_source(conn, owner, name, object_type, max_chars).map_err(DbError::into_envelope)?;
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

fn patch_source(
    conn: &dyn OracleConnection,
    active_profile: Option<&str>,
    session: &SessionLevelState,
    tool_name: &str,
    args: PatchSourceArgs,
) -> Result<(Value, Option<PatchPreviewEntry>), ErrorEnvelope> {
    with_call_timeout(conn, args.timeout_seconds, || {
        patch_source_inner(conn, active_profile, session, tool_name, args)
    })
}

fn patch_source_inner(
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
    let (owner, object_name) = owner_and_name_arg(conn, args.owner, object_name, "name")?;
    let document =
        fetch_patch_source_document(conn, &owner, &object_name, &object_type, max_chars)?;
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

    let rows_affected = match conn.execute(&patched_ddl, &[]) {
        Ok(rows) => rows,
        Err(e) => {
            let _ = conn.rollback();
            return Err(DbError::into_envelope(e));
        }
    };
    conn.commit().map_err(DbError::into_envelope)?;
    let include_errors = args.include_errors.unwrap_or(true);
    let errors = if include_errors {
        Some(compile_errors(conn, &owner, Some(&object_name)).map_err(DbError::into_envelope)?)
    } else {
        None
    };
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

fn create_or_replace(
    conn: &dyn OracleConnection,
    active_profile: Option<&str>,
    session: &SessionLevelState,
    tool_name: &str,
    args: CreateOrReplaceArgs,
) -> Result<Value, ErrorEnvelope> {
    with_call_timeout(conn, args.timeout_seconds, || {
        create_or_replace_inner(conn, active_profile, session, tool_name, args)
    })
}

fn create_or_replace_inner(
    conn: &dyn OracleConnection,
    active_profile: Option<&str>,
    session: &SessionLevelState,
    tool_name: &str,
    args: CreateOrReplaceArgs,
) -> Result<Value, ErrorEnvelope> {
    let source = create_or_replace_source_arg(tool_name, args.source_code)?;
    let decision = Classifier::new(ClassifierConfig::new()).classify(&source);
    let gate = decision.gate(session);
    let (gate_decision, blocked_reason, step_up_target) = gate_decision_json(&gate);
    let detected = detect_create_or_replace_object(conn, &source);
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
        conn,
        active_profile,
        session,
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
    )?;
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
                let errors = compile_errors(conn, &hint.owner, Some(&hint.name))
                    .map_err(DbError::into_envelope)?;
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

fn deploy_ddl(
    conn: &dyn OracleConnection,
    active_profile: Option<&str>,
    session: &SessionLevelState,
    args: DeployDdlArgs,
) -> Result<Value, ErrorEnvelope> {
    with_call_timeout(conn, args.timeout_seconds, || {
        deploy_ddl_inner(conn, active_profile, session, args)
    })
}

fn deploy_ddl_inner(
    conn: &dyn OracleConnection,
    active_profile: Option<&str>,
    session: &SessionLevelState,
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
            conn,
            active_profile,
            session,
            "deploy_ddl",
            CreateOrReplaceArgs {
                source_code: Some(ddl),
                execute: args.execute,
                confirm: args.confirm,
                include_errors: args.include_errors,
                timeout_seconds: args.timeout_seconds,
            },
        )?;
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
        conn,
        active_profile,
        session,
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
    )?;
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
    fn dispatch<'a>(&'a self, cx: &'a Cx, name: &'a str, args: Value) -> DispatchFuture<'a> {
        Box::pin(async move {
            cx.checkpoint().map_err(|e| {
                ErrorEnvelope::new(
                    ErrorClass::Internal,
                    format!("dispatch context checkpoint failed: {e}"),
                )
            })?;
            OracleDispatcher::dispatch(self, name, args)
        })
    }
}

impl OracleDispatcher {
    /// Synchronous concrete dispatch used by the current DB adapter and focused
    /// dispatcher tests. The server-facing trait method wraps this behind an
    /// explicit Asupersync context.
    pub fn dispatch(&self, name: &str, args: Value) -> Result<Value, ErrorEnvelope> {
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

            let new_conn = connector(&profile).map_err(DbError::into_envelope)?;
            let mut response = connection_info_json(Some(profile.clone()), new_conn.describe());
            let new_level = profile_level(&profile);
            let new_custom_catalog = match &self.custom_loader {
                Some(loader) => loader(Some(&profile), &new_level)?,
                None => CustomToolCatalog::default(),
            };
            let mut state = self.state.lock().map_err(|_| {
                ErrorEnvelope::new(ErrorClass::Internal, "connection mutex poisoned")
            })?;
            state.conn = new_conn;
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
        if tool == "oracle_preview_sql" {
            let a: PreviewSqlArgs = parse_args(name, args)?;
            let preview = preview_sql(&a.sql, &state.level, state.active_profile.as_deref());
            remember_execute_approved_token(&mut state, &a.sql, &preview);
            return Ok(preview);
        }
        if tool == "execute_approved" {
            let a: ExecuteApprovedArgs = parse_args(name, args)?;
            let execute_args = execute_approved_args(&mut state, a)?;
            let active_profile = state.active_profile.clone();
            let conn: &dyn OracleConnection = state.conn.as_ref();
            return execute_sql(conn, active_profile.as_deref(), &state.level, execute_args);
        }
        if tool == "deploy_ddl" {
            let a: DeployDdlArgs = parse_args(name, args)?;
            let active_profile = state.active_profile.clone();
            let conn: &dyn OracleConnection = state.conn.as_ref();
            return deploy_ddl(conn, active_profile.as_deref(), &state.level, a);
        }
        if tool == "read_patch_preview" {
            let a: ReadPatchPreviewArgs = parse_args(name, args)?;
            return read_patch_preview(&state, name, a);
        }
        let conn: &dyn OracleConnection = state.conn.as_ref();

        let result: Result<Value, DbError> = match tool {
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
            "oracle_create_or_replace" => {
                let a: CreateOrReplaceArgs = parse_args(name, args)?;
                return create_or_replace(
                    conn,
                    state.active_profile.as_deref(),
                    &state.level,
                    name,
                    a,
                );
            }
            "oracle_patch_source" => {
                let a: PatchSourceArgs = parse_args(name, args)?;
                let (value, preview_entry) =
                    patch_source(conn, state.active_profile.as_deref(), &state.level, name, a)?;
                if let Some(preview_entry) = preview_entry {
                    remember_patch_preview(&mut state, preview_entry);
                }
                return Ok(value);
            }
            "oracle_list_profiles" => {
                ensure_no_args(name, args)?;
                OracleMcpConfig::load(None)
                    .map(|cfg| profiles_response(&cfg))
                    .map_err(|e| DbError::UnsupportedAuth(format!("config load failed: {e}")))
            }
            "oracle_connection_info" => {
                ensure_no_args(name, args)?;
                Ok(connection_info_json(
                    state.active_profile.clone(),
                    conn.describe(),
                ))
            }
            "oracle_query" => {
                let a: QueryArgs = parse_args(name, args)?;
                return with_call_timeout(conn, a.timeout_seconds, || {
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
                    .map_err(DbError::into_envelope)
                });
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
                ensure_explain_plan_write_allowed(&a, &state.level)?;
                explain_plan(conn, &a.sql, a.read_only_standby).map(|rows| {
                    json!({
                        "plan": rows_to_json(&rows),
                        "diagnostic_write": {
                            "statement": "EXPLAIN PLAN",
                            "writes": "PLAN_TABLE",
                            "required_level": OperatingLevel::ReadWrite,
                            "explicitly_allowed": a.allow_plan_table_write,
                        },
                    })
                })
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
mod tests;
