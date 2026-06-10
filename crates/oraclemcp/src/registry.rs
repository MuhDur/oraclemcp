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
pub const TOOL_NAMES: [&str; 49] = [
    "oracle_list_profiles",
    "oracle_connection_info",
    "oracle_switch_profile",
    "oracle_set_session_level",
    "oracle_query",
    "oracle_preview_sql",
    "oracle_execute",
    "oracle_compile_object",
    "oracle_create_or_replace",
    "oracle_patch_source",
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
    "patch_package",
    "patch_view",
    "read_patch_preview",
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

/// Merge property fragments into a base `properties` object. Keys serialize
/// sorted (serde_json is built without preserve_order here), so merge order is
/// wire-irrelevant; this only de-duplicates the recurring fragment literals.
fn props_with(base: Value, fragments: &[Value]) -> Value {
    let mut base = base;
    if let Value::Object(map) = &mut base {
        for fragment in fragments {
            if let Value::Object(extra) = fragment {
                for (k, v) in extra {
                    map.insert(k.clone(), v.clone());
                }
            }
        }
    }
    base
}

/// The standard per-call `timeout_seconds` override property, repeated across
/// every live-DB tool schema.
fn timeout_seconds_prop() -> Value {
    json!({
        "timeout_seconds": { "type": "integer", "minimum": 1, "maximum": 3600, "description": "Temporary Oracle per-round-trip call timeout for this tool call. Overrides the profile default only for this call." }
    })
}

/// The `confirm` token property plus its two fixed aliases. Only the `confirm`
/// description varies per tool; `token`/`confirmation_token` are always aliases.
fn confirm_trio(confirm_description: &str) -> Value {
    json!({
        "confirm": { "type": "string", "description": confirm_description },
        "token": { "type": "string", "description": "Alias for confirm." },
        "confirmation_token": { "type": "string", "description": "Alias for confirm." }
    })
}

/// The DBMS_OUTPUT capture cluster shared by oracle_execute and execute_approved.
/// Only the `capture_dbms_output` description differs between the two tools.
fn dbms_output_props(capture_description: &str) -> Value {
    json!({
        "capture_dbms_output": { "type": "boolean", "description": capture_description },
        "dbms_output": { "type": "boolean", "description": "Alias for capture_dbms_output." },
        "dbms_output_max_lines": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Maximum DBMS_OUTPUT lines to return when capture_dbms_output=true (default 200)." },
        "max_dbms_output_lines": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Alias for dbms_output_max_lines." },
        "dbms_output_max_chars": { "type": "integer", "minimum": 1, "maximum": 1000000, "description": "Maximum DBMS_OUTPUT characters to return when capture_dbms_output=true (default 200000)." },
        "max_dbms_output_chars": { "type": "integer", "minimum": 1, "maximum": 1000000, "description": "Alias for dbms_output_max_chars." }
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
                "profile": { "type": "string", "description": "Configured profile name from oracle_list_profiles." },
                "db": { "type": "string", "description": "Alias for profile for compatibility with older clients. Prefer profile." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_set_session_level",
            ToolTier::FoundationStatic,
            "Preview or apply a temporary session operating-level elevation within the active profile ceiling, or drop back to READ_ONLY.",
        )
        .with_input_schema(object_schema(
            props_with(
                json!({
                    "level": { "type": "string", "description": "Target level: READ_WRITE, DDL, or ADMIN. READ_ONLY drops any active elevation." },
                    "target_level": { "type": "string", "description": "Alias for level." },
                    "ttl_seconds": { "type": "integer", "minimum": 1, "maximum": 3600, "description": "Temporary elevation window in seconds (default 900, hard cap 3600)." },
                    "execute": { "type": "boolean", "description": "Default false previews the level change and returns a confirmation token. Set true with confirm to apply elevation." },
                    "action": { "type": "string", "description": "Optional action: preview, apply, drop, or status. Omit for preview/apply based on execute." }
                }),
                &[confirm_trio("Confirmation token returned by preview. Required when execute=true raises the level.")],
            ),
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
            props_with(
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
                    "numbers_as_float": { "type": "boolean", "description": "Emit numeric values as JSON numbers where possible. Default false preserves Oracle NUMBER losslessly as strings." }
                }),
                &[timeout_seconds_prop()],
            ),
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
            props_with(
                json!({
                    "sql": { "type": "string", "description": "A single non-read SQL statement. Use :1, :2 … for binds." },
                    "binds": {
                        "type": "array",
                        "description": "Positional bind values (string | number | bool | null) for :1, :2 …",
                        "items": {}
                    },
                    "commit": { "type": "boolean", "description": "Default false rolls back after DML. Set true only with confirm from oracle_preview_sql. DDL/Admin statements require true because Oracle cannot rollback them." }
                }),
                &[
                    confirm_trio("Commit confirmation token from oracle_preview_sql.execute_confirmation.confirm. Required when commit=true."),
                    dbms_output_props("Default false. When true, enables DBMS_OUTPUT before execution and returns bounded captured lines after commit/rollback."),
                    timeout_seconds_prop(),
                ],
            ),
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
            props_with(
                json!({
                    "object_type": { "type": "string", "description": "PACKAGE, PACKAGE_BODY, PROCEDURE, FUNCTION, TRIGGER, TYPE, TYPE_BODY, or VIEW." },
                    "owner": { "type": "string", "description": "Optional schema owner. Defaults to the current schema when available." },
                    "name": { "type": "string", "description": "Object name. May be OWNER.NAME. Required unless object_name is supplied." },
                    "object_name": { "type": "string", "description": "Alias for name for compatibility with older clients. Prefer name." },
                    "plscope": { "type": "boolean", "description": "Enable PL/Scope identifier and statement collection before compiling. Default false." },
                    "warnings": { "type": "boolean", "description": "Enable PLSQL_WARNINGS='ENABLE:ALL' before compiling. Default false." },
                    "enable_warnings": { "type": "boolean", "description": "Alias for warnings." },
                    "execute": { "type": "boolean", "description": "Default false returns a preview and confirmation token. Set true only with confirm to run the compile statements." }
                }),
                &[
                    confirm_trio("Confirmation token returned by the preview for this exact object/profile/options. Required when execute=true."),
                    timeout_seconds_prop(),
                ],
            ),
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
            props_with(
                json!({
                    "source_code": { "type": "string", "description": "Full CREATE OR REPLACE statement. Required unless sql or ddl is supplied." },
                    "sql": { "type": "string", "description": "Alias for source_code." },
                    "ddl": { "type": "string", "description": "Alias for source_code." },
                    "execute": { "type": "boolean", "description": "Default false previews only. Set true with confirm to apply." },
                    "include_errors": { "type": "boolean", "description": "After execute, include current compile errors for the detected object when possible. Default true." }
                }),
                &[
                    confirm_trio("Confirmation token returned by preview. Required when execute=true."),
                    timeout_seconds_prop(),
                ],
            ),
            &[],
        ))
        .destructive(),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_patch_source",
            ToolTier::FoundationLiveDb,
            "Preview or apply an exact old_text to new_text replacement against one stored source object; preview refetches the current source and execute uses the existing DDL confirmation gate.",
        )
        .with_input_schema(object_schema(
            props_with(
                json!({
                    "owner": { "type": "string", "description": "Optional schema owner. Defaults to the current schema when available." },
                    "name": { "type": "string", "description": "Object name. May be OWNER.NAME. Required unless object_name is supplied." },
                    "object_name": { "type": "string", "description": "Alias for name." },
                    "object_type": { "type": "string", "description": "PACKAGE, PACKAGE_BODY, PROCEDURE, FUNCTION, TRIGGER, TYPE, TYPE_BODY, or VIEW." },
                    "old_text": { "type": "string", "description": "Exact non-empty text to replace. It must match the current source exactly once." },
                    "search_text": { "type": "string", "description": "Alias for old_text." },
                    "new_text": { "type": "string", "description": "Replacement text. May be empty to delete the matched text." },
                    "replacement": { "type": "string", "description": "Alias for new_text." },
                    "max_chars": { "type": "integer", "minimum": 1, "maximum": 10000000, "description": "Maximum source characters to fetch before patching (default 1000000)." },
                    "execute": { "type": "boolean", "description": "Default false previews only. Set true with confirm to apply." },
                    "include_errors": { "type": "boolean", "description": "After execute, include current compile errors for the patched object when possible. Default true." }
                }),
                &[
                    confirm_trio("Confirmation token returned by preview. Required when execute=true."),
                    timeout_seconds_prop(),
                ],
            ),
            &["object_type"],
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
                "max_rows": { "type": "integer", "minimum": 1, "maximum": 1000, "description": "Maximum rows to return (default 50, hard cap 1000)." },
                "limit": { "type": "integer", "minimum": 1, "maximum": 1000, "description": "Alias for max_rows for compatibility with older clients. Prefer max_rows." }
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
                "max_rows": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Maximum matching source lines to return (default 200, hard cap 5000)." },
                "limit": { "type": "integer", "minimum": 1, "maximum": 5000, "description": "Alias for max_rows for compatibility with older clients. Prefer max_rows." }
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
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Optional schema owner (case-insensitive). Defaults to current schema when available." },
                "name": { "type": "string", "description": "Object name. May be OWNER.NAME. Required unless object_name is supplied." },
                "object_name": { "type": "string", "description": "Alias for name for compatibility. Prefer name." }
            }),
            &[],
        )),
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
            props_with(
                json!({
                    "ttl_seconds": { "type": "integer", "minimum": 1, "maximum": 3600, "description": "Temporary READ_WRITE elevation window in seconds (default 900)." },
                    "execute": { "type": "boolean", "description": "Default false previews and returns a confirmation token. Set true with confirm to apply." },
                    "db": { "type": "string", "description": "Ignored compatibility argument from older clients; use switch_database/oracle_switch_profile to change profiles." },
                    "profile": { "type": "string", "description": "Ignored compatibility argument from older clients; use switch_database/oracle_switch_profile to change profiles." }
                }),
                &[confirm_trio("Confirmation token returned by preview. Required when execute=true raises the level.")],
            ),
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
            props_with(
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
                    "numbers_as_float": { "type": "boolean", "description": "Emit numeric values as JSON numbers where possible." }
                }),
                &[timeout_seconds_prop()],
            ),
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
            props_with(
                json!({
                    "token": { "type": "string", "description": "Confirmation token from preview_sql.execute_confirmation.confirm." },
                    "confirm": { "type": "string", "description": "Alias for token." },
                    "confirmation_token": { "type": "string", "description": "Alias for token." },
                    "sql": { "type": "string", "description": "Optional SQL statement. If omitted, the token must still be cached from preview_sql in this server process." },
                    "commit": { "type": "boolean", "description": "Default true for this compatibility tool. Set false to rollback-preview DML." },
                    "save_output": { "type": "string", "description": "Unsupported in the generic core. Use capture_dbms_output=true and read dbms_output.lines instead." }
                }),
                &[
                    timeout_seconds_prop(),
                    dbms_output_props("Default false. When true, returns bounded DBMS_OUTPUT lines."),
                ],
            ),
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
            props_with(
                json!({
                    "object_type": { "type": "string", "description": "PACKAGE, PACKAGE_BODY, PROCEDURE, FUNCTION, TRIGGER, TYPE, TYPE_BODY, or VIEW." },
                    "owner": { "type": "string", "description": "Optional schema owner. Defaults to current schema." },
                    "name": { "type": "string", "description": "Object name. May be OWNER.NAME. Required unless object_name is supplied." },
                    "object_name": { "type": "string", "description": "Alias for name." },
                    "plscope": { "type": "boolean", "description": "Enable PL/Scope identifier and statement collection before compiling. Default false." },
                    "warnings": { "type": "boolean", "description": "Enable PLSQL_WARNINGS='ENABLE:ALL' before compiling. Default false." },
                    "enable_warnings": { "type": "boolean", "description": "Alias for warnings." },
                    "execute": { "type": "boolean", "description": "Default false previews only. Set true with confirm to compile." }
                }),
                &[
                    confirm_trio("Confirmation token returned by preview. Required when execute=true."),
                    timeout_seconds_prop(),
                ],
            ),
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
            props_with(
                json!({
                    "object_type": { "type": "string", "description": "PACKAGE, PACKAGE_BODY, PROCEDURE, FUNCTION, TRIGGER, TYPE, TYPE_BODY, or VIEW." },
                    "owner": { "type": "string", "description": "Optional schema owner. Defaults to current schema." },
                    "name": { "type": "string", "description": "Object name. May be OWNER.NAME. Required unless object_name is supplied." },
                    "object_name": { "type": "string", "description": "Alias for name." },
                    "plscope": { "type": "boolean", "description": "Enable PL/Scope identifier and statement collection before compiling. Default false." },
                    "execute": { "type": "boolean", "description": "Default false previews only. Set true with confirm to compile." }
                }),
                &[
                    confirm_trio("Confirmation token returned by preview. Required when execute=true."),
                    timeout_seconds_prop(),
                ],
            ),
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
            props_with(
                json!({
                    "source_code": { "type": "string", "description": "Full CREATE OR REPLACE statement. Required unless sql or ddl is supplied." },
                    "sql": { "type": "string", "description": "Alias for source_code." },
                    "ddl": { "type": "string", "description": "Alias for source_code." },
                    "execute": { "type": "boolean", "description": "Default false previews only. Set true with confirm to apply." },
                    "include_errors": { "type": "boolean", "description": "After execute, include current compile errors for the detected object when possible. Default true." }
                }),
                &[
                    confirm_trio("Confirmation token returned by preview. Required when execute=true."),
                    timeout_seconds_prop(),
                ],
            ),
            &[],
        ))
        .destructive(),
    );

    registry.register(
        ToolDescriptor::new(
            "patch_package",
            ToolTier::FoundationLiveDb,
            "Compatibility alias for oracle_patch_source; defaults object_type to PACKAGE_BODY when omitted.",
        )
        .with_input_schema(object_schema(
            props_with(
                json!({
                    "owner": { "type": "string", "description": "Optional schema owner. Defaults to current schema." },
                    "name": { "type": "string", "description": "Package name. May be OWNER.NAME. Required unless object_name is supplied." },
                    "object_name": { "type": "string", "description": "Alias for name." },
                    "object_type": { "type": "string", "description": "Optional override, usually PACKAGE or PACKAGE_BODY. Defaults to PACKAGE_BODY." },
                    "old_text": { "type": "string", "description": "Exact non-empty text to replace. It must match the current source exactly once." },
                    "search_text": { "type": "string", "description": "Alias for old_text." },
                    "new_text": { "type": "string", "description": "Replacement text. May be empty to delete the matched text." },
                    "replacement": { "type": "string", "description": "Alias for new_text." },
                    "max_chars": { "type": "integer", "minimum": 1, "maximum": 10000000, "description": "Maximum source characters to fetch before patching (default 1000000)." },
                    "execute": { "type": "boolean", "description": "Default false previews only. Set true with confirm to apply." },
                    "include_errors": { "type": "boolean", "description": "After execute, include current compile errors for the patched object when possible. Default true." }
                }),
                &[
                    confirm_trio("Confirmation token returned by preview. Required when execute=true."),
                    timeout_seconds_prop(),
                ],
            ),
            &[],
        ))
        .destructive(),
    );

    registry.register(
        ToolDescriptor::new(
            "patch_view",
            ToolTier::FoundationLiveDb,
            "Compatibility alias for oracle_patch_source; defaults object_type to VIEW when omitted.",
        )
        .with_input_schema(object_schema(
            props_with(
                json!({
                    "owner": { "type": "string", "description": "Optional schema owner. Defaults to current schema." },
                    "name": { "type": "string", "description": "View name. May be OWNER.NAME. Required unless object_name is supplied." },
                    "object_name": { "type": "string", "description": "Alias for name." },
                    "old_text": { "type": "string", "description": "Exact non-empty text to replace. It must match the current view DDL exactly once." },
                    "search_text": { "type": "string", "description": "Alias for old_text." },
                    "new_text": { "type": "string", "description": "Replacement text. May be empty to delete the matched text." },
                    "replacement": { "type": "string", "description": "Alias for new_text." },
                    "max_chars": { "type": "integer", "minimum": 1, "maximum": 10000000, "description": "Accepted for symmetry with source patching." },
                    "execute": { "type": "boolean", "description": "Default false previews only. Set true with confirm to apply." },
                    "include_errors": { "type": "boolean", "description": "After execute, include current compile errors for the patched view when possible. Default true." }
                }),
                &[
                    confirm_trio("Confirmation token returned by preview. Required when execute=true."),
                    timeout_seconds_prop(),
                ],
            ),
            &[],
        ))
        .destructive(),
    );

    registry.register(
        ToolDescriptor::new(
            "read_patch_preview",
            ToolTier::FoundationStatic,
            "Compatibility helper for reading the last in-memory source patch preview returned by oracle_patch_source, patch_package, or patch_view.",
        )
        .with_input_schema(object_schema(
            json!({
                "name": { "type": "string", "description": "Optional object name to inspect. If omitted, lists remembered patch previews for the active profile." },
                "object_name": { "type": "string", "description": "Alias for name." },
                "max_chars": { "type": "integer", "minimum": 1, "maximum": 10000000, "description": "Maximum DDL preview characters to return for one object (default 100000)." }
            }),
            &[],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "deploy_ddl",
            ToolTier::FoundationLiveDb,
            "Compatibility wrapper for one DDL statement. Preview is the default; execution reuses the same DDL profile gate and confirmation as oracle_execute/oracle_create_or_replace.",
        )
        .with_input_schema(object_schema(
            props_with(
                json!({
                    "name": { "type": "string", "description": "Optional deployment tag returned in the response." },
                    "ddl": { "type": "string", "description": "One DDL statement. CREATE OR REPLACE uses the structured create_or_replace path." },
                    "sql": { "type": "string", "description": "Alias for ddl." },
                    "source_code": { "type": "string", "description": "Alias for ddl." },
                    "execute": { "type": "boolean", "description": "Default false previews only. Set true with confirm to apply." },
                    "wait_seconds": { "type": "integer", "minimum": 0, "maximum": 3600, "description": "Accepted for compatibility and returned in the response; generic core executes synchronously." },
                    "include_errors": { "type": "boolean", "description": "For CREATE OR REPLACE, include current compile errors for the detected object after execute. Default true." }
                }),
                &[
                    confirm_trio("Confirmation token returned by preview. Required when execute=true."),
                    timeout_seconds_prop(),
                ],
            ),
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
                "table": { "type": "string", "description": "Alias for table_name." },
                "name": { "type": "string", "description": "Alias for table_name." }
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
                "oracle_patch_source",
                "enable_writes",
                "execute_approved",
                "compile_object",
                "compile_with_warnings",
                "create_or_replace",
                "patch_package",
                "patch_view",
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
        let top_level_keywords_rejected_by_function_adapters =
            ["oneOf", "anyOf", "allOf", "enum", "not"];
        for tool in tool_registry().tools {
            let schema = tool
                .input_schema
                .unwrap_or_else(|| panic!("{} must advertise an input schema", tool.name));
            assert_eq!(schema["type"], json!("object"), "{}", tool.name);
            for keyword in top_level_keywords_rejected_by_function_adapters {
                assert!(
                    schema.get(keyword).is_none(),
                    "{} schema must not advertise top-level {keyword}; keep MCP tool parameters function-adapter compatible",
                    tool.name
                );
            }
            assert!(
                schema.get("required").is_some(),
                "{} schema declares required args",
                tool.name
            );
        }
    }

    #[test]
    fn row_capped_read_tools_advertise_limit_aliases() {
        let registry = tool_registry();
        for name in ["oracle_sample_rows", "oracle_search_source"] {
            let tool = registry
                .tools
                .iter()
                .find(|tool| tool.name == name)
                .unwrap_or_else(|| panic!("{name} must be registered"));
            let schema = tool
                .input_schema
                .as_ref()
                .unwrap_or_else(|| panic!("{name} must advertise an input schema"));
            let properties = schema
                .get("properties")
                .and_then(Value::as_object)
                .unwrap_or_else(|| panic!("{name} must advertise object properties"));
            assert!(properties.contains_key("max_rows"), "{name}");
            assert!(
                properties.contains_key("limit"),
                "{name} must advertise the accepted limit alias"
            );
        }
    }

    #[test]
    fn switch_profile_advertises_db_alias_without_false_required_key() {
        let registry = tool_registry();
        let tool = registry
            .tools
            .iter()
            .find(|tool| tool.name == "oracle_switch_profile")
            .expect("oracle_switch_profile must be registered");
        let schema = tool
            .input_schema
            .as_ref()
            .expect("oracle_switch_profile must advertise an input schema");
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("oracle_switch_profile must advertise object properties");
        assert!(properties.contains_key("profile"));
        assert!(properties.contains_key("db"));
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .expect("oracle_switch_profile schema must declare required args");
        assert!(
            required.is_empty(),
            "profile and db are alternative spellings, so neither key is individually required"
        );
    }

    #[test]
    fn confirmation_tools_advertise_all_accepted_token_spellings() {
        let registry = tool_registry();
        for name in [
            "oracle_set_session_level",
            "oracle_execute",
            "oracle_compile_object",
            "oracle_create_or_replace",
            "enable_writes",
            "execute_approved",
            "compile_object",
            "compile_with_warnings",
            "create_or_replace",
            "deploy_ddl",
        ] {
            let tool = registry
                .tools
                .iter()
                .find(|tool| tool.name == name)
                .unwrap_or_else(|| panic!("{name} must be registered"));
            let schema = tool
                .input_schema
                .as_ref()
                .unwrap_or_else(|| panic!("{name} must advertise an input schema"));
            let properties = schema
                .get("properties")
                .and_then(Value::as_object)
                .unwrap_or_else(|| panic!("{name} must advertise object properties"));
            for key in ["confirm", "token", "confirmation_token"] {
                assert!(
                    properties.contains_key(key),
                    "{name} must advertise accepted {key} spelling"
                );
            }
        }
    }

    #[test]
    fn dbms_output_tools_advertise_compatibility_aliases() {
        let registry = tool_registry();
        for name in ["oracle_execute", "execute_approved"] {
            let tool = registry
                .tools
                .iter()
                .find(|tool| tool.name == name)
                .unwrap_or_else(|| panic!("{name} must be registered"));
            let schema = tool
                .input_schema
                .as_ref()
                .unwrap_or_else(|| panic!("{name} must advertise an input schema"));
            let properties = schema
                .get("properties")
                .and_then(Value::as_object)
                .unwrap_or_else(|| panic!("{name} must advertise object properties"));
            for key in [
                "capture_dbms_output",
                "dbms_output",
                "dbms_output_max_lines",
                "max_dbms_output_lines",
                "dbms_output_max_chars",
                "max_dbms_output_chars",
            ] {
                assert!(
                    properties.contains_key(key),
                    "{name} must advertise accepted {key} spelling"
                );
            }
        }
    }

    #[test]
    fn compile_tools_advertise_warning_aliases() {
        let registry = tool_registry();
        for name in ["oracle_compile_object", "compile_object"] {
            let tool = registry
                .tools
                .iter()
                .find(|tool| tool.name == name)
                .unwrap_or_else(|| panic!("{name} must be registered"));
            let schema = tool
                .input_schema
                .as_ref()
                .unwrap_or_else(|| panic!("{name} must advertise an input schema"));
            let properties = schema
                .get("properties")
                .and_then(Value::as_object)
                .unwrap_or_else(|| panic!("{name} must advertise object properties"));
            assert!(properties.contains_key("warnings"), "{name}");
            assert!(
                properties.contains_key("enable_warnings"),
                "{name} must advertise accepted enable_warnings spelling"
            );
        }
    }

    #[test]
    fn accepted_argument_spellings_stay_advertised() {
        let registry = tool_registry();
        let cases: &[(&str, &[&str])] = &[
            ("oracle_switch_profile", &["profile", "db"]),
            (
                "oracle_set_session_level",
                &[
                    "level",
                    "target_level",
                    "ttl_seconds",
                    "execute",
                    "confirm",
                    "token",
                    "confirmation_token",
                    "action",
                ],
            ),
            (
                "oracle_query",
                &[
                    "sql",
                    "binds",
                    "cursor",
                    "max_rows",
                    "limit",
                    "max_result_bytes",
                    "max_lob_chars",
                    "max_blob_bytes",
                    "max_col_width",
                    "numbers_as_float",
                    "timeout_seconds",
                ],
            ),
            (
                "oracle_execute",
                &[
                    "sql",
                    "binds",
                    "commit",
                    "confirm",
                    "token",
                    "confirmation_token",
                    "capture_dbms_output",
                    "dbms_output",
                    "dbms_output_max_lines",
                    "max_dbms_output_lines",
                    "dbms_output_max_chars",
                    "max_dbms_output_chars",
                    "timeout_seconds",
                ],
            ),
            (
                "execute_approved",
                &[
                    "token",
                    "confirm",
                    "confirmation_token",
                    "sql",
                    "commit",
                    "timeout_seconds",
                    "save_output",
                    "capture_dbms_output",
                    "dbms_output",
                    "dbms_output_max_lines",
                    "max_dbms_output_lines",
                    "dbms_output_max_chars",
                    "max_dbms_output_chars",
                ],
            ),
            (
                "oracle_compile_object",
                &[
                    "object_type",
                    "owner",
                    "name",
                    "object_name",
                    "plscope",
                    "warnings",
                    "enable_warnings",
                    "execute",
                    "confirm",
                    "token",
                    "confirmation_token",
                    "timeout_seconds",
                ],
            ),
            (
                "oracle_create_or_replace",
                &[
                    "source_code",
                    "sql",
                    "ddl",
                    "execute",
                    "confirm",
                    "token",
                    "confirmation_token",
                    "include_errors",
                    "timeout_seconds",
                ],
            ),
            (
                "oracle_patch_source",
                &[
                    "owner",
                    "name",
                    "object_name",
                    "object_type",
                    "old_text",
                    "search_text",
                    "new_text",
                    "replacement",
                    "max_chars",
                    "execute",
                    "confirm",
                    "token",
                    "confirmation_token",
                    "include_errors",
                    "timeout_seconds",
                ],
            ),
            ("read_patch_preview", &["name", "object_name", "max_chars"]),
            (
                "deploy_ddl",
                &[
                    "name",
                    "ddl",
                    "sql",
                    "source_code",
                    "execute",
                    "confirm",
                    "token",
                    "confirmation_token",
                    "wait_seconds",
                    "include_errors",
                    "timeout_seconds",
                ],
            ),
            (
                "oracle_schema_inspect",
                &["owner", "object_type", "name_like", "max_rows", "limit"],
            ),
            ("oracle_list_schemas", &["name_like", "max_rows", "limit"]),
            ("oracle_describe", &["owner", "table", "table_name", "name"]),
            ("describe_table", &["owner", "table", "table_name", "name"]),
            ("oracle_describe_index", &["owner", "name", "index_name"]),
            ("describe_index", &["owner", "name", "index_name"]),
            (
                "oracle_describe_trigger",
                &["owner", "name", "trigger_name"],
            ),
            ("describe_trigger", &["owner", "name", "trigger_name"]),
            ("oracle_describe_view", &["owner", "name", "view_name"]),
            ("describe_view", &["owner", "name", "view_name"]),
            (
                "oracle_get_ddl",
                &["object_type", "owner", "name", "object_name"],
            ),
            ("get_ddl", &["object_type", "owner", "name", "object_name"]),
            (
                "oracle_get_source",
                &["owner", "name", "object_name", "object_type", "max_chars"],
            ),
            (
                "get_object_source",
                &["owner", "name", "object_name", "object_type", "max_chars"],
            ),
            (
                "oracle_sample_rows",
                &["owner", "table", "table_name", "max_rows", "limit"],
            ),
            (
                "oracle_read_clob",
                &[
                    "owner",
                    "table",
                    "table_name",
                    "clob_column",
                    "clob_col",
                    "pk_column",
                    "pk_col",
                    "pk_value",
                    "pk_val",
                    "max_chars",
                ],
            ),
            (
                "get_clob",
                &[
                    "owner",
                    "table",
                    "table_name",
                    "clob_column",
                    "clob_col",
                    "pk_column",
                    "pk_col",
                    "pk_value",
                    "pk_val",
                    "max_chars",
                ],
            ),
            ("oracle_compile_errors", &["owner", "name", "object_name"]),
            ("get_errors", &["owner", "name", "object_name"]),
            (
                "oracle_search_source",
                &[
                    "owner",
                    "needle",
                    "object_type",
                    "name_like",
                    "max_rows",
                    "limit",
                ],
            ),
            ("oracle_plscope_inspect", &["owner", "name", "object_name"]),
            ("oracle_explain_plan", &["sql", "read_only_standby"]),
        ];

        for (tool_name, spellings) in cases {
            let tool = registry
                .tools
                .iter()
                .find(|tool| tool.name == *tool_name)
                .unwrap_or_else(|| panic!("{tool_name} must be registered"));
            let properties = tool
                .input_schema
                .as_ref()
                .and_then(|schema| schema.get("properties"))
                .and_then(Value::as_object)
                .unwrap_or_else(|| panic!("{tool_name} must advertise object properties"));
            for spelling in *spellings {
                assert!(
                    properties.contains_key(*spelling),
                    "{tool_name} must advertise accepted argument spelling {spelling}"
                );
            }
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
