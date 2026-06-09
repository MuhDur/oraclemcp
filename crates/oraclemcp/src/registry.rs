//! The advertised tool surface for the engine-free `oraclemcp` server.
//!
//! Pure data — no database access. [`tool_registry`] builds the
//! safe-by-default config-inspection, read, and guarded execute tools the server dispatches (see
//! [`crate::dispatch`]); [`capabilities`] assembles the zero-arg
//! `oracle_capabilities` report from that surface plus the build's feature
//! tiers. The `oracle_capabilities` discovery tool itself is answered by
//! `oraclemcp-core` directly (it is added to the wire `tools/list` by the
//! server, never dispatched), so it is NOT registered here.

use oraclemcp_core::capabilities::{CapabilitiesReport, FeatureTiers};
use oraclemcp_core::tools::{ToolDescriptor, ToolRegistry, ToolTier};
use oraclemcp_guard::OperatingLevel;
use serde_json::{Value, json};

/// The tool names this server dispatches, in registration order.
/// Kept as a constant so the dispatcher and the unit tests pin the exact set.
pub const TOOL_NAMES: [&str; 45] = [
    "oracle_list_profiles",
    "oracle_connection_info",
    "oracle_switch_profile",
    "oracle_set_session_level",
    "oracle_query",
    "oracle_preview_sql",
    "oracle_execute",
    "oracle_compile_object",
    "oracle_create_or_replace",
    "oracle_list_schemas",
    "oracle_schema_inspect",
    "oracle_describe",
    "oracle_describe_index",
    "oracle_describe_trigger",
    "oracle_describe_view",
    "oracle_get_ddl",
    "oracle_get_source",
    "oracle_sample_rows",
    "oracle_read_clob",
    "oracle_compile_errors",
    "oracle_search_source",
    "oracle_plscope_inspect",
    "oracle_explain_plan",
    // Compatibility aliases for agents migrating from shorter Oracle MCP tool
    // names. These route to the prefixed tools in dispatch and share the same
    // guardrails.
    "current_database",
    "switch_database",
    "enable_writes",
    "disable_writes",
    "query",
    "preview_sql",
    "execute_approved",
    "compile_object",
    "compile_with_warnings",
    "create_or_replace",
    "deploy_ddl",
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
];

/// A JSON-Schema `object` with the given required string properties (plus any
/// extra property fragments), `additionalProperties: false`.
fn object_schema(props: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": props,
        "required": required,
        "additionalProperties": false,
    })
}

/// Build the public tool registry. Each descriptor carries a hand-written
/// argument JSON-Schema mirroring the matching `dispatch` arg struct so an
/// agent can construct a call first-try.
pub fn tool_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();

    registry.register(
        ToolDescriptor::new(
            "oracle_list_profiles",
            ToolTier::FoundationStatic,
            "List configured connection profiles without exposing connect strings, usernames, or credential references.",
        )
        .with_input_schema(object_schema(json!({}), &[])),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_connection_info",
            ToolTier::FoundationLiveDb,
            "Describe the active profile and Oracle connection. When live connection metadata is unavailable, returns connected=false with a structured connection_error and next_actions.",
        )
        .with_input_schema(object_schema(json!({}), &[])),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_switch_profile",
            ToolTier::FoundationLiveDb,
            "Reconnect this MCP server to another configured profile by name.",
        )
        .with_input_schema(object_schema(
            json!({
                "profile": { "type": "string", "description": "Configured profile name from oracle_list_profiles." }
            }),
            &["profile"],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_set_session_level",
            ToolTier::FoundationStatic,
            "Preview or apply a temporary session operating-level elevation within the active profile ceiling, or drop back to READ_ONLY.",
        )
        .with_input_schema(object_schema(
            json!({
                "level": { "type": "string", "description": "Target level: READ_WRITE, DDL, or ADMIN. READ_ONLY drops any active elevation." },
                "target_level": { "type": "string", "description": "Alias for level." },
                "ttl_seconds": { "type": "integer", "minimum": 1, "maximum": 3600, "description": "Temporary elevation window in seconds (default 900, hard cap 3600)." },
                "execute": { "type": "boolean", "description": "Default false previews the level change and returns a confirmation token. Set true with confirm to apply elevation." },
                "confirm": { "type": "string", "description": "Confirmation token returned by preview. Required when execute=true raises the level." },
                "action": { "type": "string", "description": "Optional action: preview, apply, drop, or status. Omit for preview/apply based on execute." }
            }),
            &[],
        ))
        .destructive(),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_query",
            ToolTier::FoundationLiveDb,
            "Run a read-only SELECT with positional binds; paginated and row/byte capped.",
        )
        .with_input_schema(object_schema(
            json!({
                "sql": { "type": "string", "description": "A single read-only SELECT. Use :1, :2 … for binds." },
                "binds": {
                    "type": "array",
                    "description": "Positional bind values (string | number | bool | null) for :1, :2 …",
                    "items": {}
                },
                "cursor": { "type": "string", "description": "Opaque pagination cursor from a prior truncated page." },
                "max_rows": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Maximum rows in this page (default 200, hard cap 5000)." },
                "limit": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Alias for max_rows for compatibility with older clients. Prefer max_rows." },
                "max_result_bytes": { "type": "integer", "minimum": 1, "maximum": 26214400, "description": "Maximum serialized JSON bytes in this page (default 10485760, hard cap 26214400)." },
                "max_col_width": { "type": "integer", "minimum": 1, "maximum": 1000000, "description": "Compatibility text cap for ordinary text/raw columns. Truncated values are returned as { value, truncated, char_length }." },
                "max_lob_chars": { "type": "integer", "minimum": 1, "maximum": 1000000, "description": "Maximum CLOB characters to inline per cell (default 32768)." },
                "max_blob_bytes": { "type": "integer", "minimum": 1, "maximum": 5242880, "description": "Maximum BLOB bytes to inline per cell as base64 (default 1048576)." },
                "numbers_as_float": { "type": "boolean", "description": "Emit numeric values as JSON numbers where possible. Default false preserves Oracle NUMBER losslessly as strings." },
                "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 3600, "description": "Temporary Oracle per-round-trip call timeout for this tool call. Overrides the profile default only for this call." }
            }),
            &["sql"],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_preview_sql",
            ToolTier::FoundationStatic,
            "Classify a SQL statement and report whether it would pass the active profile/session gate without executing it.",
        )
        .with_input_schema(object_schema(
            json!({
                "sql": { "type": "string", "description": "SQL statement to classify. It is never executed." }
            }),
            &["sql"],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_execute",
            ToolTier::FoundationLiveDb,
            "Execute one non-read SQL statement through the classifier and active profile gate; DML rolls back by default and commits require the confirmation token from oracle_preview_sql.",
        )
        .with_input_schema(object_schema(
            json!({
                "sql": { "type": "string", "description": "A single non-read SQL statement. Use :1, :2 … for binds." },
                "binds": {
                    "type": "array",
                    "description": "Positional bind values (string | number | bool | null) for :1, :2 …",
                    "items": {}
                },
                "commit": { "type": "boolean", "description": "Default false rolls back after DML. Set true only with confirm from oracle_preview_sql. DDL/Admin statements require true because Oracle cannot rollback them." },
                "confirm": { "type": "string", "description": "Commit confirmation token from oracle_preview_sql.execute_confirmation.confirm. Required when commit=true." },
                "capture_dbms_output": { "type": "boolean", "description": "Default false. When true, enables DBMS_OUTPUT before execution and returns bounded captured lines after commit/rollback." },
                "dbms_output_max_lines": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Maximum DBMS_OUTPUT lines to return when capture_dbms_output=true (default 200)." },
                "dbms_output_max_chars": { "type": "integer", "minimum": 1, "maximum": 1000000, "description": "Maximum DBMS_OUTPUT characters to return when capture_dbms_output=true (default 200000)." },
                "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 3600, "description": "Temporary Oracle per-round-trip call timeout for this tool call. Overrides the profile default only for this call." }
            }),
            &["sql"],
        ))
        .destructive(),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_compile_object",
            ToolTier::FoundationLiveDb,
            "Preview or compile one PL/SQL/view object through the active DDL profile gate; preview is the default and execution requires the returned confirmation token.",
        )
        .with_input_schema(object_schema(
            json!({
                "object_type": { "type": "string", "description": "PACKAGE, PACKAGE_BODY, PROCEDURE, FUNCTION, TRIGGER, TYPE, TYPE_BODY, or VIEW." },
                "owner": { "type": "string", "description": "Optional schema owner. Defaults to the current schema when available." },
                "name": { "type": "string", "description": "Object name. May be OWNER.NAME. Required unless object_name is supplied." },
                "object_name": { "type": "string", "description": "Alias for name for compatibility with older clients. Prefer name." },
                "plscope": { "type": "boolean", "description": "Enable PL/Scope identifier and statement collection before compiling. Default false." },
                "warnings": { "type": "boolean", "description": "Enable PLSQL_WARNINGS='ENABLE:ALL' before compiling. Default false." },
                "execute": { "type": "boolean", "description": "Default false returns a preview and confirmation token. Set true only with confirm to run the compile statements." },
                "confirm": { "type": "string", "description": "Confirmation token returned by the preview for this exact object/profile/options. Required when execute=true." },
                "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 3600, "description": "Temporary Oracle per-round-trip call timeout for this tool call. Overrides the profile default only for this call." }
            }),
            &["object_type"],
        ))
        .destructive(),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_create_or_replace",
            ToolTier::FoundationLiveDb,
            "Preview or apply one CREATE OR REPLACE statement through the classifier and active DDL profile gate.",
        )
        .with_input_schema(object_schema(
            json!({
                "source_code": { "type": "string", "description": "Full CREATE OR REPLACE statement. Required unless sql or ddl is supplied." },
                "sql": { "type": "string", "description": "Alias for source_code." },
                "ddl": { "type": "string", "description": "Alias for source_code." },
                "execute": { "type": "boolean", "description": "Default false previews only. Set true with confirm to apply." },
                "confirm": { "type": "string", "description": "Confirmation token returned by preview. Required when execute=true." },
                "include_errors": { "type": "boolean", "description": "After execute, include current compile errors for the detected object when possible. Default true." },
                "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 3600, "description": "Temporary Oracle per-round-trip call timeout for this tool call. Overrides the profile default only for this call." }
            }),
            &[],
        ))
        .destructive(),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_list_schemas",
            ToolTier::FoundationLiveDb,
            "List schemas that own objects visible to this session, optionally filtered by name.",
        )
        .with_input_schema(object_schema(
            json!({
                "name_like": { "type": "string", "description": "Optional SQL LIKE pattern for schema names (case-insensitive), e.g. APP%." },
                "max_rows": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Maximum schemas to return (default 200, hard cap 5000)." },
                "limit": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Alias for max_rows for compatibility with older clients. Prefer max_rows." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_schema_inspect",
            ToolTier::FoundationLiveDb,
            "List objects in the current schema, one owner, or all accessible schemas, with optional type/name filters.",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Optional schema owner (case-insensitive). Omit for current schema; use * for all accessible schemas." },
                "object_type": { "type": "string", "description": "Optional object type filter, e.g. TABLE, VIEW, PACKAGE." },
                "name_like": { "type": "string", "description": "Optional SQL LIKE pattern for object_name, e.g. EMP%." },
                "max_rows": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Maximum objects to return (default 500, hard cap 5000)." },
                "limit": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Alias for max_rows for compatibility with older clients. Prefer max_rows." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_describe",
            ToolTier::FoundationLiveDb,
            "Describe a table/view's columns and constraint metadata.",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Optional schema owner (case-insensitive). Defaults to current schema when available." },
                "table": { "type": "string", "description": "Table or view name. May be OWNER.TABLE. Required unless table_name or name is supplied." },
                "table_name": { "type": "string", "description": "Alias for table for compatibility with older clients. Prefer table." },
                "name": { "type": "string", "description": "Alias for table. Prefer table." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_describe_index",
            ToolTier::FoundationLiveDb,
            "Describe one index's metadata, indexed columns, and function-based expressions.",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Optional schema owner (case-insensitive). Defaults to current schema when available." },
                "name": { "type": "string", "description": "Index name (case-insensitive). Required unless index_name is supplied." },
                "index_name": { "type": "string", "description": "Alias for name for compatibility with older clients. Prefer name." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_describe_trigger",
            ToolTier::FoundationLiveDb,
            "Describe one trigger's timing, event, target table, status, and body.",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Optional schema owner (case-insensitive). Defaults to current schema when available." },
                "name": { "type": "string", "description": "Trigger name (case-insensitive). Required unless trigger_name is supplied." },
                "trigger_name": { "type": "string", "description": "Alias for name for compatibility with older clients. Prefer name." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_describe_view",
            ToolTier::FoundationLiveDb,
            "Describe one view's definition metadata and columns.",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Optional schema owner (case-insensitive). Defaults to current schema when available." },
                "name": { "type": "string", "description": "View name (case-insensitive). Required unless view_name is supplied." },
                "view_name": { "type": "string", "description": "Alias for name for compatibility with older clients. Prefer name." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_get_ddl",
            ToolTier::FoundationLiveDb,
            "Fetch an object's DDL via DBMS_METADATA.GET_DDL (allowlisted object types).",
        )
        .with_input_schema(object_schema(
            json!({
                "object_type": { "type": "string", "description": "Allowlisted type, e.g. TABLE, VIEW, PACKAGE, PACKAGE_BODY, PROCEDURE, FUNCTION, TRIGGER, TYPE, SEQUENCE, INDEX, SYNONYM." },
                "owner": { "type": "string", "description": "Optional schema owner (case-insensitive). Defaults to current schema when available." },
                "name": { "type": "string", "description": "Object name. May be OWNER.NAME. Required unless object_name is supplied." },
                "object_name": { "type": "string", "description": "Alias for name for compatibility with older clients. Prefer name." }
            }),
            &["object_type"],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_get_source",
            ToolTier::FoundationLiveDb,
            "Fetch an object's full source text from ALL_SOURCE with a character cap. Omit object_type to return every visible source variant for the object name.",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Optional schema owner (case-insensitive). Defaults to current schema when available." },
                "name": { "type": "string", "description": "Object name. May be OWNER.NAME. Required unless object_name is supplied." },
                "object_name": { "type": "string", "description": "Alias for name for compatibility with older clients. Prefer name." },
                "object_type": { "type": "string", "description": "Optional supported source type: PACKAGE, PACKAGE_BODY, PROCEDURE, FUNCTION, TRIGGER, TYPE, TYPE_BODY. When omitted, all visible source types for this name are returned." },
                "max_chars": { "type": "integer", "minimum": 1, "description": "Maximum source characters to return (default 1000000)." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_sample_rows",
            ToolTier::FoundationLiveDb,
            "Read the first rows of a table or view with a hard row cap.",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Optional schema owner (case-insensitive). Defaults to current schema when available." },
                "table": { "type": "string", "description": "Table or view name. May be OWNER.TABLE. Required unless table_name is supplied." },
                "table_name": { "type": "string", "description": "Alias for table for compatibility with older clients. Prefer table." },
                "max_rows": { "type": "integer", "minimum": 1, "maximum": 1000, "description": "Maximum rows to return (default 50, hard cap 1000)." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_read_clob",
            ToolTier::FoundationLiveDb,
            "Read one CLOB/NCLOB/text value by key with a character cap.",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Optional schema owner (case-insensitive). Defaults to current schema when available." },
                "table": { "type": "string", "description": "Table or view name. May be OWNER.TABLE. Required unless table_name is supplied." },
                "table_name": { "type": "string", "description": "Alias for table for compatibility with older clients. Prefer table." },
                "clob_column": { "type": "string", "description": "CLOB/NCLOB/text column name (case-insensitive). Required unless clob_col is supplied." },
                "clob_col": { "type": "string", "description": "Alias for clob_column. Prefer clob_column." },
                "pk_column": { "type": "string", "description": "Key column name (case-insensitive). Required unless pk_col is supplied." },
                "pk_col": { "type": "string", "description": "Alias for pk_column. Prefer pk_column." },
                "pk_value": { "type": "string", "description": "Key value bound as :1. Required unless pk_val is supplied." },
                "pk_val": { "type": "string", "description": "Alias for pk_value. Prefer pk_value." },
                "max_chars": { "type": "integer", "minimum": 1, "description": "Maximum characters to return (default 1000000)." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_compile_errors",
            ToolTier::FoundationLiveDb,
            "Retrieve compile errors for the current schema, an owner, or one object (ALL_ERRORS).",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Optional schema owner (case-insensitive). Defaults to current schema when available." },
                "name": { "type": "string", "description": "Optional object name. May be OWNER.NAME. Omit to list all compile errors for the owner/current schema." },
                "object_name": { "type": "string", "description": "Alias for name for compatibility with older clients. Prefer name." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_search_source",
            ToolTier::FoundationLiveDb,
            "Full-text search across ALL_SOURCE for a needle (row-capped).",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Optional schema owner (case-insensitive). Defaults to current schema; use * for all visible source." },
                "needle": { "type": "string", "description": "Case-insensitive substring to find in source text." },
                "object_type": { "type": "string", "description": "Optional source type filter: PACKAGE, PACKAGE_BODY, PROCEDURE, FUNCTION, TRIGGER, TYPE, TYPE_BODY." },
                "name_like": { "type": "string", "description": "Optional SQL LIKE pattern for source object names, e.g. EMP%." },
                "max_rows": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Maximum matching source lines to return (default 200, hard cap 5000)." }
            }),
            &["needle"],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_plscope_inspect",
            ToolTier::FoundationLiveDb,
            "Inspect PL/Scope identifier and SQL statement metadata for one PL/SQL object when ALL_IDENTIFIERS/ALL_STATEMENTS are populated.",
        )
        .with_input_schema(json!({
            "type": "object",
            "properties": {
                "owner": { "type": "string", "description": "Optional schema owner (case-insensitive). Defaults to current schema when available." },
                "name": { "type": "string", "description": "Object name. May be OWNER.NAME. Required unless object_name is supplied." },
                "object_name": { "type": "string", "description": "Alias for name for compatibility. Prefer name." }
            },
            "anyOf": [
                { "required": ["name"] },
                { "required": ["object_name"] }
            ],
            "required": [],
            "additionalProperties": false,
        })),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_explain_plan",
            ToolTier::FoundationLiveDb,
            "EXPLAIN PLAN for a vetted SELECT, then DBMS_XPLAN.DISPLAY (disabled on a read-only standby).",
        )
        .with_input_schema(object_schema(
            json!({
                "sql": { "type": "string", "description": "A read-only SELECT to explain." },
                "read_only_standby": { "type": "boolean", "description": "If true, refuse (EXPLAIN PLAN writes PLAN_TABLE). Defaults false." }
            }),
            &["sql"],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "current_database",
            ToolTier::FoundationLiveDb,
            "Compatibility alias for oracle_connection_info; returns connected=false with recovery hints when live connection metadata is unavailable.",
        )
        .with_input_schema(object_schema(json!({}), &[])),
    );

    registry.register(
        ToolDescriptor::new(
            "switch_database",
            ToolTier::FoundationLiveDb,
            "Compatibility alias for oracle_switch_profile; pass a configured profile name as db or profile.",
        )
        .with_input_schema(object_schema(
            json!({
                "db": { "type": "string", "description": "Configured profile name. Alias for profile." },
                "profile": { "type": "string", "description": "Configured profile name from oracle_list_profiles." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "enable_writes",
            ToolTier::FoundationStatic,
            "Compatibility alias for oracle_set_session_level with level=READ_WRITE; preview is still the default.",
        )
        .with_input_schema(object_schema(
            json!({
                "ttl_seconds": { "type": "integer", "minimum": 1, "maximum": 3600, "description": "Temporary READ_WRITE elevation window in seconds (default 900)." },
                "execute": { "type": "boolean", "description": "Default false previews and returns a confirmation token. Set true with confirm to apply." },
                "confirm": { "type": "string", "description": "Confirmation token returned by preview. Required when execute=true raises the level." },
                "db": { "type": "string", "description": "Ignored compatibility argument from older clients; use switch_database/oracle_switch_profile to change profiles." },
                "profile": { "type": "string", "description": "Ignored compatibility argument from older clients; use switch_database/oracle_switch_profile to change profiles." }
            }),
            &[],
        ))
        .destructive(),
    );

    registry.register(
        ToolDescriptor::new(
            "disable_writes",
            ToolTier::FoundationStatic,
            "Compatibility alias for oracle_set_session_level action=drop; immediately returns the session to READ_ONLY.",
        )
        .with_input_schema(object_schema(
            json!({
                "db": { "type": "string", "description": "Ignored compatibility argument from older clients." },
                "profile": { "type": "string", "description": "Ignored compatibility argument from older clients." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "query",
            ToolTier::FoundationLiveDb,
            "Compatibility alias for oracle_query.",
        )
        .with_input_schema(object_schema(
            json!({
                "sql": { "type": "string", "description": "A single read-only SELECT. Use :1, :2 ... for binds." },
                "binds": { "type": "array", "description": "Positional bind values for :1, :2 ...", "items": {} },
                "cursor": { "type": "string", "description": "Opaque pagination cursor from a prior truncated page." },
                "max_rows": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Maximum rows in this page (default 200, hard cap 5000)." },
                "limit": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Alias for max_rows for compatibility with older clients. Prefer max_rows." },
                "max_result_bytes": { "type": "integer", "minimum": 1, "maximum": 26214400, "description": "Maximum serialized JSON bytes in this page." },
                "max_col_width": { "type": "integer", "minimum": 1, "maximum": 1000000, "description": "Compatibility text cap for ordinary text/raw columns." },
                "max_lob_chars": { "type": "integer", "minimum": 1, "maximum": 1000000, "description": "Maximum CLOB characters to inline per cell." },
                "max_blob_bytes": { "type": "integer", "minimum": 1, "maximum": 5242880, "description": "Maximum BLOB bytes to inline per cell as base64." },
                "numbers_as_float": { "type": "boolean", "description": "Emit numeric values as JSON numbers where possible." },
                "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 3600, "description": "Temporary Oracle per-round-trip call timeout for this tool call. Overrides the profile default only for this call." }
            }),
            &["sql"],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "preview_sql",
            ToolTier::FoundationStatic,
            "Compatibility alias for oracle_preview_sql.",
        )
        .with_input_schema(object_schema(
            json!({
                "sql": { "type": "string", "description": "SQL statement to classify. It is never executed." }
            }),
            &["sql"],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "execute_approved",
            ToolTier::FoundationLiveDb,
            "Compatibility alias for executing a statement previously previewed with preview_sql; token-only calls work for five minutes in the same server process.",
        )
        .with_input_schema(object_schema(
            json!({
                "token": { "type": "string", "description": "Confirmation token from preview_sql.execute_confirmation.confirm." },
                "confirm": { "type": "string", "description": "Alias for token." },
                "confirmation_token": { "type": "string", "description": "Alias for token." },
                "sql": { "type": "string", "description": "Optional SQL statement. If omitted, the token must still be cached from preview_sql in this server process." },
                "commit": { "type": "boolean", "description": "Default true for this compatibility tool. Set false to rollback-preview DML." },
                "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 3600, "description": "Temporary Oracle per-round-trip call timeout for this tool call. Overrides the profile default only for this call." },
                "save_output": { "type": "string", "description": "Unsupported in the generic core. Use capture_dbms_output=true and read dbms_output.lines instead." },
                "capture_dbms_output": { "type": "boolean", "description": "Default false. When true, returns bounded DBMS_OUTPUT lines." },
                "dbms_output_max_lines": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Maximum DBMS_OUTPUT lines to return when capture_dbms_output=true (default 200)." },
                "dbms_output_max_chars": { "type": "integer", "minimum": 1, "maximum": 1000000, "description": "Maximum DBMS_OUTPUT characters to return when capture_dbms_output=true (default 200000)." }
            }),
            &[],
        ))
        .destructive(),
    );

    registry.register(
        ToolDescriptor::new(
            "compile_object",
            ToolTier::FoundationLiveDb,
            "Compatibility alias for oracle_compile_object.",
        )
        .with_input_schema(object_schema(
            json!({
                "object_type": { "type": "string", "description": "PACKAGE, PACKAGE_BODY, PROCEDURE, FUNCTION, TRIGGER, TYPE, TYPE_BODY, or VIEW." },
                "owner": { "type": "string", "description": "Optional schema owner. Defaults to current schema." },
                "name": { "type": "string", "description": "Object name. May be OWNER.NAME. Required unless object_name is supplied." },
                "object_name": { "type": "string", "description": "Alias for name." },
                "plscope": { "type": "boolean", "description": "Enable PL/Scope identifier and statement collection before compiling. Default false." },
                "warnings": { "type": "boolean", "description": "Enable PLSQL_WARNINGS='ENABLE:ALL' before compiling. Default false." },
                "execute": { "type": "boolean", "description": "Default false previews only. Set true with confirm to compile." },
                "confirm": { "type": "string", "description": "Confirmation token returned by preview. Required when execute=true." },
                "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 3600, "description": "Temporary Oracle per-round-trip call timeout for this tool call. Overrides the profile default only for this call." }
            }),
            &["object_type"],
        ))
        .destructive(),
    );

    registry.register(
        ToolDescriptor::new(
            "compile_with_warnings",
            ToolTier::FoundationLiveDb,
            "Compatibility alias for oracle_compile_object with warnings=true.",
        )
        .with_input_schema(object_schema(
            json!({
                "object_type": { "type": "string", "description": "PACKAGE, PACKAGE_BODY, PROCEDURE, FUNCTION, TRIGGER, TYPE, TYPE_BODY, or VIEW." },
                "owner": { "type": "string", "description": "Optional schema owner. Defaults to current schema." },
                "name": { "type": "string", "description": "Object name. May be OWNER.NAME. Required unless object_name is supplied." },
                "object_name": { "type": "string", "description": "Alias for name." },
                "plscope": { "type": "boolean", "description": "Enable PL/Scope identifier and statement collection before compiling. Default false." },
                "execute": { "type": "boolean", "description": "Default false previews only. Set true with confirm to compile." },
                "confirm": { "type": "string", "description": "Confirmation token returned by preview. Required when execute=true." },
                "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 3600, "description": "Temporary Oracle per-round-trip call timeout for this tool call. Overrides the profile default only for this call." }
            }),
            &["object_type"],
        ))
        .destructive(),
    );

    registry.register(
        ToolDescriptor::new(
            "create_or_replace",
            ToolTier::FoundationLiveDb,
            "Compatibility alias for oracle_create_or_replace.",
        )
        .with_input_schema(object_schema(
            json!({
                "source_code": { "type": "string", "description": "Full CREATE OR REPLACE statement. Required unless sql or ddl is supplied." },
                "sql": { "type": "string", "description": "Alias for source_code." },
                "ddl": { "type": "string", "description": "Alias for source_code." },
                "execute": { "type": "boolean", "description": "Default false previews only. Set true with confirm to apply." },
                "confirm": { "type": "string", "description": "Confirmation token returned by preview. Required when execute=true." },
                "include_errors": { "type": "boolean", "description": "After execute, include current compile errors for the detected object when possible. Default true." },
                "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 3600, "description": "Temporary Oracle per-round-trip call timeout for this tool call. Overrides the profile default only for this call." }
            }),
            &[],
        ))
        .destructive(),
    );

    registry.register(
        ToolDescriptor::new(
            "deploy_ddl",
            ToolTier::FoundationLiveDb,
            "Compatibility wrapper for one DDL statement. Preview is the default; execution reuses the same DDL profile gate and confirmation as oracle_execute/oracle_create_or_replace.",
        )
        .with_input_schema(object_schema(
            json!({
                "name": { "type": "string", "description": "Optional deployment tag returned in the response." },
                "ddl": { "type": "string", "description": "One DDL statement. CREATE OR REPLACE uses the structured create_or_replace path." },
                "sql": { "type": "string", "description": "Alias for ddl." },
                "source_code": { "type": "string", "description": "Alias for ddl." },
                "execute": { "type": "boolean", "description": "Default false previews only. Set true with confirm to apply." },
                "confirm": { "type": "string", "description": "Confirmation token returned by preview. Required when execute=true." },
                "wait_seconds": { "type": "integer", "minimum": 0, "maximum": 3600, "description": "Accepted for compatibility and returned in the response; generic core executes synchronously." },
                "include_errors": { "type": "boolean", "description": "For CREATE OR REPLACE, include current compile errors for the detected object after execute. Default true." },
                "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 3600, "description": "Temporary Oracle per-round-trip call timeout for this tool call. Overrides the profile default only for this call." }
            }),
            &[],
        ))
        .destructive(),
    );

    registry.register(
        ToolDescriptor::new(
            "list_objects",
            ToolTier::FoundationLiveDb,
            "Compatibility alias for oracle_schema_inspect.",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Optional schema owner; omit for current schema, or use * for all accessible schemas." },
                "object_type": { "type": "string", "description": "Optional object type filter." },
                "name_like": { "type": "string", "description": "Optional SQL LIKE pattern for object_name." },
                "limit": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Maximum objects to return." },
                "max_rows": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Alias for limit." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "list_schemas",
            ToolTier::FoundationLiveDb,
            "Compatibility alias for oracle_list_schemas.",
        )
        .with_input_schema(object_schema(
            json!({
                "name_like": { "type": "string", "description": "Optional SQL LIKE pattern for schema names." },
                "max_rows": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Maximum schemas to return." },
                "limit": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Alias for max_rows." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "get_schema",
            ToolTier::FoundationLiveDb,
            "Compatibility alias for oracle_schema_inspect; omit arguments to inspect the current schema.",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Optional schema owner; omit for current schema, or use * for all accessible schemas." },
                "object_type": { "type": "string", "description": "Optional object type filter." },
                "name_like": { "type": "string", "description": "Optional SQL LIKE pattern for object_name." },
                "limit": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Maximum objects to return." },
                "max_rows": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Alias for limit." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "describe_table",
            ToolTier::FoundationLiveDb,
            "Compatibility alias for oracle_describe; returns columns and constraints.",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Optional schema owner; defaults to current schema." },
                "table_name": { "type": "string", "description": "Table or view name. May be OWNER.TABLE." },
                "table": { "type": "string", "description": "Alias for table_name." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "describe_index",
            ToolTier::FoundationLiveDb,
            "Compatibility alias for oracle_describe_index.",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Optional schema owner; defaults to current schema." },
                "index_name": { "type": "string", "description": "Index name. May be OWNER.INDEX_NAME." },
                "name": { "type": "string", "description": "Alias for index_name." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "describe_trigger",
            ToolTier::FoundationLiveDb,
            "Compatibility alias for oracle_describe_trigger.",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Optional schema owner; defaults to current schema." },
                "trigger_name": { "type": "string", "description": "Trigger name. May be OWNER.TRIGGER_NAME." },
                "name": { "type": "string", "description": "Alias for trigger_name." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "describe_view",
            ToolTier::FoundationLiveDb,
            "Compatibility alias for oracle_describe_view.",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Optional schema owner; defaults to current schema." },
                "view_name": { "type": "string", "description": "View name. May be OWNER.VIEW_NAME." },
                "name": { "type": "string", "description": "Alias for view_name." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "get_ddl",
            ToolTier::FoundationLiveDb,
            "Compatibility alias for oracle_get_ddl.",
        )
        .with_input_schema(object_schema(
            json!({
                "object_type": { "type": "string", "description": "Allowlisted object type." },
                "owner": { "type": "string", "description": "Optional schema owner; defaults to current schema." },
                "object_name": { "type": "string", "description": "Object name. May be OWNER.NAME." },
                "name": { "type": "string", "description": "Alias for object_name." }
            }),
            &["object_type"],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "get_object_source",
            ToolTier::FoundationLiveDb,
            "Compatibility alias for oracle_get_source. Omit object_type to return every visible source variant for the object name.",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Optional schema owner; defaults to current schema." },
                "object_name": { "type": "string", "description": "Object name. May be OWNER.NAME." },
                "name": { "type": "string", "description": "Alias for object_name." },
                "object_type": { "type": "string", "description": "Optional source type: PACKAGE, PACKAGE_BODY, PROCEDURE, FUNCTION, TRIGGER, TYPE, or TYPE_BODY. When omitted, all visible source types for this name are returned." },
                "max_chars": { "type": "integer", "minimum": 1, "description": "Maximum source characters to return." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "get_errors",
            ToolTier::FoundationLiveDb,
            "Compatibility alias for oracle_compile_errors.",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Optional schema owner; defaults to current schema." },
                "object_name": { "type": "string", "description": "Optional object name. May be OWNER.NAME." },
                "name": { "type": "string", "description": "Alias for object_name." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "get_clob",
            ToolTier::FoundationLiveDb,
            "Compatibility alias for oracle_read_clob.",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Optional schema owner; defaults to current schema." },
                "table": { "type": "string", "description": "Table or view name. May be OWNER.TABLE." },
                "table_name": { "type": "string", "description": "Alias for table." },
                "clob_col": { "type": "string", "description": "CLOB/NCLOB/text column name." },
                "clob_column": { "type": "string", "description": "Alias for clob_col." },
                "pk_col": { "type": "string", "description": "Key column name." },
                "pk_column": { "type": "string", "description": "Alias for pk_col." },
                "pk_val": { "type": "string", "description": "Key value bound as :1." },
                "pk_value": { "type": "string", "description": "Alias for pk_val." },
                "max_chars": { "type": "integer", "minimum": 1, "description": "Maximum characters to return." }
            }),
            &[],
        )),
    );

    registry
}

/// Assemble the `oracle_capabilities` report for this build. `live_db` reflects
/// whether the Oracle driver is compiled in (the `live-db` feature); `http`
/// reflects whether the Streamable HTTP transport is exposed by `serve`. The
/// engine tier is always `false` — this is the engine-free server.
pub fn capabilities(version: impl Into<String>, live_db: bool, http: bool) -> CapabilitiesReport {
    let registry = tool_registry();
    CapabilitiesReport::new(
        version,
        registry.tools,
        OperatingLevel::ReadOnly,
        FeatureTiers {
            live_db,
            engine: false,
            http_transport: http,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_lists_exactly_the_registered_tools() {
        let registry = tool_registry();
        assert_eq!(registry.len(), TOOL_NAMES.len(), "exact tool surface");
        let names: Vec<&str> = registry.tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, TOOL_NAMES.to_vec());
        let destructive: Vec<&str> = registry
            .tools
            .iter()
            .filter(|t| t.destructive)
            .map(|t| t.name.as_str())
            .collect();
        assert_eq!(
            destructive,
            vec![
                "oracle_set_session_level",
                "oracle_execute",
                "oracle_compile_object",
                "oracle_create_or_replace",
                "enable_writes",
                "execute_approved",
                "compile_object",
                "compile_with_warnings",
                "create_or_replace",
                "deploy_ddl"
            ],
            "only guarded session elevation/execution/deploy/compile tools are destructive"
        );
        // oracle_capabilities is NOT in the registry (the server adds it to
        // tools/list itself).
        assert!(
            !names.contains(&oraclemcp_core::CAPABILITIES_TOOL),
            "oracle_capabilities is server-answered, never registered"
        );
    }

    #[test]
    fn every_tool_advertises_an_input_schema() {
        for tool in tool_registry().tools {
            let schema = tool
                .input_schema
                .unwrap_or_else(|| panic!("{} must advertise an input schema", tool.name));
            assert_eq!(schema["type"], json!("object"), "{}", tool.name);
            assert!(
                schema.get("required").is_some(),
                "{} schema declares required args",
                tool.name
            );
        }
    }

    #[test]
    fn capabilities_reflects_feature_tiers_and_the_tool_surface() {
        let caps = capabilities("0.1.0", true, false);
        assert!(caps.features.live_db);
        assert!(!caps.features.engine, "engine-free server");
        assert!(!caps.features.http_transport);
        assert_eq!(caps.tools.len(), TOOL_NAMES.len());
        // Offline build: live_db false, http true.
        let caps = capabilities("0.1.0", false, true);
        assert!(!caps.features.live_db);
        assert!(caps.features.http_transport);
        assert!(caps.transports.iter().any(|t| t == "http"));
    }
}
