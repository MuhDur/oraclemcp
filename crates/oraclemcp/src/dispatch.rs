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

use std::sync::Mutex;

use oraclemcp_core::ToolDispatch;
use oraclemcp_db::{
    DbError, OracleBind, OracleConnection, QueryCaps, SerializeOptions, compile_errors,
    describe_columns, explain_plan, get_ddl, list_objects, read_query, search_source,
    serialize_row,
};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use serde::Deserialize;
use serde_json::{Value, json};

/// Default cap on `oracle_search_source` result rows when the caller omits it.
const DEFAULT_SEARCH_MAX_ROWS: usize = 200;

/// The dispatcher: owns the (single) live connection behind a `std::sync::Mutex`
/// so dispatch stays sync and the connection is never shared across threads
/// without serialization.
pub struct OracleDispatcher {
    conn: Mutex<Box<dyn OracleConnection>>,
}

impl OracleDispatcher {
    /// Build a dispatcher over an open (or stub) connection.
    pub fn new(conn: Box<dyn OracleConnection>) -> Self {
        OracleDispatcher {
            conn: Mutex::new(conn),
        }
    }
}

/// Serialize a slice of rows to a JSON array via the canonical row serializer.
fn rows_to_json(rows: &[oraclemcp_db::OracleRow]) -> Value {
    let opts = SerializeOptions::default();
    Value::Array(rows.iter().map(|r| serialize_row(r, &opts)).collect())
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
    owner: String,
    #[serde(default)]
    object_type: Option<String>,
}

#[derive(Deserialize)]
struct DescribeArgs {
    owner: String,
    table: String,
}

#[derive(Deserialize)]
struct GetDdlArgs {
    object_type: String,
    owner: String,
    name: String,
}

#[derive(Deserialize)]
struct CompileErrorsArgs {
    owner: String,
    name: String,
}

#[derive(Deserialize)]
struct SearchSourceArgs {
    owner: String,
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

impl ToolDispatch for OracleDispatcher {
    fn dispatch(&self, name: &str, args: Value) -> Result<Value, ErrorEnvelope> {
        // A poisoned mutex means a prior dispatch panicked while holding the
        // connection; surface it as an Internal error rather than re-panicking.
        let conn_guard = self
            .conn
            .lock()
            .map_err(|_| ErrorEnvelope::new(ErrorClass::Internal, "connection mutex poisoned"))?;
        let conn: &dyn OracleConnection = conn_guard.as_ref();

        let result: Result<Value, DbError> = match name {
            "oracle_query" => {
                let a: QueryArgs = parse_args(name, args)?;
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
                list_objects(conn, &a.owner, a.object_type.as_deref())
                    .map(|rows| json!({ "objects": rows_to_json(&rows) }))
            }
            "oracle_describe" => {
                let a: DescribeArgs = parse_args(name, args)?;
                describe_columns(conn, &a.owner, &a.table)
                    .map(|rows| json!({ "columns": rows_to_json(&rows) }))
            }
            "oracle_get_ddl" => {
                let a: GetDdlArgs = parse_args(name, args)?;
                get_ddl(conn, &a.object_type, &a.owner, &a.name).map(|ddl| json!({ "ddl": ddl }))
            }
            "oracle_compile_errors" => {
                let a: CompileErrorsArgs = parse_args(name, args)?;
                compile_errors(conn, &a.owner, &a.name)
                    .map(|rows| json!({ "errors": rows_to_json(&rows) }))
            }
            "oracle_search_source" => {
                let a: SearchSourceArgs = parse_args(name, args)?;
                let max_rows = a.max_rows.unwrap_or(DEFAULT_SEARCH_MAX_ROWS);
                search_source(conn, &a.owner, &a.needle, max_rows)
                    .map(|rows| json!({ "matches": rows_to_json(&rows) }))
            }
            "oracle_explain_plan" => {
                let a: ExplainPlanArgs = parse_args(name, args)?;
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
            Ok(OracleConnectionInfo::default())
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
            "oracle_query" => json!({ "sql": "SELECT 1 FROM dual" }),
            "oracle_schema_inspect" => json!({ "owner": "HR" }),
            "oracle_describe" => json!({ "owner": "HR", "table": "EMPLOYEES" }),
            "oracle_get_ddl" => {
                json!({ "object_type": "TABLE", "owner": "HR", "name": "EMPLOYEES" })
            }
            "oracle_compile_errors" => json!({ "owner": "HR", "name": "PKG" }),
            "oracle_search_source" => json!({ "owner": "HR", "needle": "commit" }),
            "oracle_explain_plan" => json!({ "sql": "SELECT 1 FROM dual" }),
            other => panic!("no test args for {other}"),
        }
    }

    #[test]
    fn every_registry_tool_routes_and_deserializes_offline() {
        let dispatcher = OracleDispatcher::new(Box::new(OneRowMock));
        for name in TOOL_NAMES {
            let out = dispatcher
                .dispatch(name, args_for(name))
                .unwrap_or_else(|e| panic!("{name} should route + succeed offline: {e:?}"));
            assert!(out.is_object(), "{name} returns a JSON object");
        }
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
        // Missing required `owner`.
        let err = dispatcher
            .dispatch("oracle_schema_inspect", json!({ "wrong": 1 }))
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
}
