//! The advertised tool surface for the engine-free `oraclemcp` server.
//!
//! Pure data — no database access. [`tool_registry`] builds the
//! read-only/config-inspection tools the server dispatches (see
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
pub const TOOL_NAMES: [&str; 10] = [
    "oracle_list_profiles",
    "oracle_connection_info",
    "oracle_query",
    "oracle_schema_inspect",
    "oracle_describe",
    "oracle_get_ddl",
    "oracle_get_source",
    "oracle_compile_errors",
    "oracle_search_source",
    "oracle_explain_plan",
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

/// Build the read-only tool registry. Each descriptor carries a hand-written
/// argument JSON-Schema mirroring the matching `dispatch` arg struct so an
/// agent can construct a call first-try.
pub fn tool_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();

    registry.register(
        ToolDescriptor::new(
            "oracle_list_profiles",
            ToolTier::FoundationStatic,
            "List configured connection profiles without exposing usernames or credential references.",
        )
        .with_input_schema(object_schema(json!({}), &[])),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_connection_info",
            ToolTier::FoundationLiveDb,
            "Describe the active Oracle connection: backend, version, role, open mode, and current schema.",
        )
        .with_input_schema(object_schema(json!({}), &[])),
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
                "cursor": { "type": "string", "description": "Opaque pagination cursor from a prior truncated page." }
            }),
            &["sql"],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_schema_inspect",
            ToolTier::FoundationLiveDb,
            "List objects in a schema (ALL_OBJECTS), optionally filtered by object type.",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Schema owner (case-insensitive)." },
                "object_type": { "type": "string", "description": "Optional filter, e.g. TABLE, VIEW, PACKAGE." }
            }),
            &["owner"],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_describe",
            ToolTier::FoundationLiveDb,
            "Describe a table/view's columns (ALL_TAB_COLUMNS).",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Schema owner (case-insensitive)." },
                "table": { "type": "string", "description": "Table or view name (case-insensitive)." }
            }),
            &["owner", "table"],
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
                "owner": { "type": "string", "description": "Schema owner (case-insensitive)." },
                "name": { "type": "string", "description": "Object name (case-insensitive)." }
            }),
            &["object_type", "owner", "name"],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_get_source",
            ToolTier::FoundationLiveDb,
            "Fetch an object's full source text from ALL_SOURCE with a character cap.",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Schema owner (case-insensitive)." },
                "name": { "type": "string", "description": "Object name (case-insensitive)." },
                "object_type": { "type": "string", "description": "Supported source type: PACKAGE, PACKAGE_BODY, PROCEDURE, FUNCTION, TRIGGER, TYPE, TYPE_BODY." },
                "max_chars": { "type": "integer", "minimum": 1, "description": "Maximum source characters to return (default 1000000)." }
            }),
            &["owner", "name", "object_type"],
        )),
    );

    registry.register(
        ToolDescriptor::new(
            "oracle_compile_errors",
            ToolTier::FoundationLiveDb,
            "Retrieve an object's compile errors (ALL_ERRORS).",
        )
        .with_input_schema(object_schema(
            json!({
                "owner": { "type": "string", "description": "Schema owner (case-insensitive)." },
                "name": { "type": "string", "description": "Object name (case-insensitive)." }
            }),
            &["owner", "name"],
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
                "owner": { "type": "string", "description": "Schema owner (case-insensitive)." },
                "needle": { "type": "string", "description": "Case-insensitive substring to find in source text." },
                "max_rows": { "type": "integer", "minimum": 1, "description": "Maximum matching source lines to return (default 200)." }
            }),
            &["owner", "needle"],
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
    fn registry_lists_exactly_the_registered_read_only_tools() {
        let registry = tool_registry();
        assert_eq!(registry.len(), TOOL_NAMES.len(), "exact tool surface");
        let names: Vec<&str> = registry.tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, TOOL_NAMES.to_vec());
        // None of the read tools is destructive, and oracle_capabilities is NOT
        // in the registry (the server adds it to tools/list itself).
        assert!(registry.tools.iter().all(|t| !t.destructive));
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
