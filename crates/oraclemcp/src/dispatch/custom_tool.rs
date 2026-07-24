//! Custom (operator-defined) tool execution family, extracted isomorphically
//! from `dispatch/mod.rs` (C6 de-monolith). Every item the parent module
//! references is `pub(super)` and re-imported with `use custom_tool::*;`, so the
//! effective visibility inside the `dispatch` module is unchanged and no call
//! site, tool surface, or behavior moves.

use std::collections::HashMap;

use asupersync::Cx;
use oraclemcp_core::{CustomToolExecutor, ToolBody, narrow_to_read_path};
use oraclemcp_db::{
    DbError, OracleBind, OracleCatalogResolverCache, OracleConnection, QueryCaps, SerializeOptions,
    read_query_named,
};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use oraclemcp_guard::{OperatingLevel, named_bind_placeholders};
use serde_json::{Value, json};

use super::{ExecuteArgs, dispatch_checkpoint, ensure_resolved_read_only, invalid_args};

pub(super) struct ReadOnlyCustomToolExecutor<'a> {
    pub(super) cx: &'a Cx,
    pub(super) conn: &'a dyn OracleConnection,
    pub(super) catalog_cache: &'a OracleCatalogResolverCache,
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

        // Only Form A reaches execution; Form B (`call = ...`) is rejected at
        // catalog load, so the body is always inline SQL (QA100 .65).
        let ToolBody::InlineSql(sql) = body;
        let sql = sql.to_owned();
        ensure_resolved_read_only(self.cx, self.conn, self.catalog_cache, &sql).await?;
        // A9: operator-defined read tools also narrow the handler context to the
        // read-path capability row. The cancellation checkpoint runs under the
        // narrowed `read_cx`; only the locked, object-safe `OracleConnection`
        // round trip takes the full `cx` (the one documented IO exception).
        let read_cx = narrow_to_read_path(self.cx);
        dispatch_checkpoint(&read_cx, "oraclemcp.dispatch.custom_read.before")?;
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

fn consume_custom_tool_control_string(
    args: &mut serde_json::Map<String, Value>,
    canonical: &str,
    keys: &[&str],
) -> Result<Option<String>, ErrorEnvelope> {
    let mut raw = None;
    for key in keys {
        if let Some(value) = args.remove(*key) {
            if raw.is_some() {
                return Err(invalid_args(format!(
                    "invalid arguments for {canonical}: {key} and its aliases are mutually exclusive"
                )));
            }
            let Some(value) = value.as_str().map(str::to_owned) else {
                return Err(invalid_args(format!(
                    "invalid arguments for {canonical}: {key} must be a string"
                )));
            };
            raw = Some(value);
        }
    }
    Ok(raw)
}

fn consume_custom_tool_control_bool(
    args: &mut serde_json::Map<String, Value>,
    canonical: &str,
    keys: &[&str],
) -> Result<bool, ErrorEnvelope> {
    let mut value = None;
    for key in keys {
        if let Some(raw) = args.remove(*key) {
            if value.is_some() {
                return Err(invalid_args(format!(
                    "invalid arguments for {canonical}: {key} and its aliases are mutually exclusive"
                )));
            }
            let Some(raw) = raw.as_bool() else {
                return Err(invalid_args(format!(
                    "invalid arguments for {canonical}: {key} must be true/false"
                )));
            };
            value = Some(raw);
        }
    }
    Ok(value.unwrap_or(false))
}

fn consume_custom_tool_control_usize(
    args: &mut serde_json::Map<String, Value>,
    canonical: &str,
    keys: &[&str],
) -> Result<Option<usize>, ErrorEnvelope> {
    let mut value = None;
    for key in keys {
        if let Some(raw) = args.remove(*key) {
            if value.is_some() {
                return Err(invalid_args(format!(
                    "invalid arguments for {canonical}: {key} and its aliases are mutually exclusive"
                )));
            }
            let Some(raw) = raw.as_u64() else {
                return Err(invalid_args(format!(
                    "invalid arguments for {canonical}: {key} must be a non-negative integer"
                )));
            };
            let converted = usize::try_from(raw).map_err(|_| {
                invalid_args(format!(
                    "invalid arguments for {canonical}: {key} exceeds supported range"
                ))
            })?;
            value = Some(converted);
        }
    }
    Ok(value)
}

fn consume_custom_tool_control_u64(
    args: &mut serde_json::Map<String, Value>,
    canonical: &str,
    keys: &[&str],
) -> Result<Option<u64>, ErrorEnvelope> {
    let mut value = None;
    for key in keys {
        if let Some(raw) = args.remove(*key) {
            if value.is_some() {
                return Err(invalid_args(format!(
                    "invalid arguments for {canonical}: {key} and its aliases are mutually exclusive"
                )));
            }
            let Some(raw) = raw.as_u64() else {
                return Err(invalid_args(format!(
                    "invalid arguments for {canonical}: {key} must be a non-negative integer"
                )));
            };
            value = Some(raw);
        }
    }
    Ok(value)
}

fn ordered_custom_tool_binds(
    sql: &str,
    bind_values: Vec<(String, OracleBind)>,
) -> Result<Vec<Value>, ErrorEnvelope> {
    let mut values = HashMap::new();
    for (name, value) in bind_values {
        values.insert(name.to_ascii_uppercase(), value);
    }
    named_bind_placeholders(sql)
        .into_iter()
        .map(|name| {
            values.remove(&name).map(bind_to_json).ok_or_else(|| {
                invalid_args(format!("custom tool body references missing bind :{name}"))
            })
        })
        .collect()
}

fn bind_to_json(bind: OracleBind) -> Value {
    match bind {
        OracleBind::Null => Value::Null,
        OracleBind::String(v) => Value::String(v),
        OracleBind::I64(v) => Value::Number(v.into()),
        OracleBind::F64(v) => serde_json::Number::from_f64(v).map_or(Value::Null, Value::Number),
        OracleBind::Bool(v) => Value::Bool(v),
        OracleBind::TimestampTz {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanosecond,
            offset_minutes,
        } => json!({
            "year": year,
            "month": month,
            "day": day,
            "hour": hour,
            "minute": minute,
            "second": second,
            "nanosecond": nanosecond,
            "offset_minutes": offset_minutes
        }),
    }
}

pub(super) fn custom_tool_execute_args(
    canonical: &str,
    tool: &oraclemcp_core::LoadedTool,
    args: &Value,
) -> Result<ExecuteArgs, ErrorEnvelope> {
    let Some(args) = args.as_object() else {
        return Err(invalid_args(format!(
            "invalid arguments for {canonical}: expected an object"
        )));
    };
    let mut args = args.clone();

    let commit = consume_custom_tool_control_bool(&mut args, canonical, &["commit"])?;
    let hold = consume_custom_tool_control_bool(&mut args, canonical, &["hold"])?;
    let capture_dbms_output = consume_custom_tool_control_bool(
        &mut args,
        canonical,
        &["capture_dbms_output", "dbms_output"],
    )?;
    let dbms_output_max_lines =
        consume_custom_tool_control_usize(&mut args, canonical, &["max_dbms_output_lines"])?;
    let dbms_output_max_chars =
        consume_custom_tool_control_usize(&mut args, canonical, &["max_dbms_output_chars"])?;
    let timeout_seconds =
        consume_custom_tool_control_u64(&mut args, canonical, &["timeout_seconds"])?;
    let confirm = consume_custom_tool_control_string(
        &mut args,
        canonical,
        &["confirm", "token", "confirmation_token"],
    )?;
    let ToolBody::InlineSql(sql) = tool.def.body().map_err(|error| {
        ErrorEnvelope::new(
            ErrorClass::InvalidArguments,
            format!("invalid tool body: {error}"),
        )
    })?;
    let binds = oraclemcp_core::bind_params(&tool.def, &Value::Object(args))?;
    let ordered_binds = ordered_custom_tool_binds(sql, binds)?;
    Ok(ExecuteArgs {
        sql: sql.to_owned(),
        binds: ordered_binds,
        commit,
        hold,
        confirm,
        capture_dbms_output,
        dbms_output_max_lines,
        dbms_output_max_chars,
        timeout_seconds,
    })
}
