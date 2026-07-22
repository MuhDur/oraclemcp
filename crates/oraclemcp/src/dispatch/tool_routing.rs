//! Pure tool-name routing metadata for the dispatch boundary.
//!
//! Compatibility aliases must keep reaching the same guarded implementation
//! arms as their `oracle_*` targets. This module intentionally carries only
//! name normalization and response-shape classification; argument parsing,
//! profile handling, classifier gates, and execution stay in `dispatch::mod`.

use serde_json::Value;

pub(super) fn canonical_tool_name(name: &str) -> &str {
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

/// Decide from the actual successful response, not just the tool name. The
/// same mutation tools also serve previews, and those must remain cancellable.
pub(super) fn response_reports_terminal_effect(name: &str, value: &Value) -> bool {
    let bool_field = |field| value.get(field).and_then(Value::as_bool) == Some(true);
    match canonical_tool_name(name) {
        "oracle_switch_profile" => true,
        "oracle_set_session_level" => bool_field("changed"),
        "oracle_compile_object" => bool_field("compiled"),
        "oracle_patch_source" | "oracle_create_or_replace" | "deploy_ddl" => bool_field("applied"),
        // F-DI6: a checkpoint or an undo that returned Ok has ALREADY changed
        // transaction state on the pinned session: the SAVEPOINT exists, or the
        // ROLLBACK has been taken. A late cancellation must not report retryable
        // cancellation for work that already happened.
        "oracle_checkpoint" => value.get("checkpoint").is_some_and(Value::is_string),
        "oracle_undo_to" => value.get("statement").is_some_and(Value::is_string),
        "oracle_execute" | "execute_approved" => {
            // F-DI1: a held statement already ran inside the open workspace
            // transaction and its effect persists there. It is pending, but
            // real, just like a committed or non-transactional effect.
            bool_field("executed")
                && (bool_field("committed")
                    || bool_field("non_transactional_effect")
                    || bool_field("held"))
        }
        _ => false,
    }
}
