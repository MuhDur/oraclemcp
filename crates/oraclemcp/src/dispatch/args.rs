//! Tool-call argument DTOs deserialized from the inbound MCP `arguments`
//! object, relocated from the former single-file `dispatch.rs`. Fields are
//! `pub(super)` so the dispatcher handlers in the parent module read them.

use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
pub(super) struct QueryArgs {
    pub(super) sql: String,
    #[serde(default)]
    pub(super) binds: Vec<Value>,
    #[serde(default)]
    pub(super) cursor: Option<String>,
    #[serde(default, alias = "limit")]
    pub(super) max_rows: Option<usize>,
    #[serde(default)]
    pub(super) max_result_bytes: Option<usize>,
    #[serde(default)]
    pub(super) max_lob_chars: Option<usize>,
    #[serde(default)]
    pub(super) max_blob_bytes: Option<usize>,
    #[serde(default)]
    pub(super) max_col_width: Option<usize>,
    #[serde(default)]
    pub(super) numbers_as_float: Option<bool>,
    #[serde(default)]
    pub(super) deep_decode: bool,
    #[serde(default)]
    pub(super) max_structured_rows: Option<usize>,
    #[serde(default)]
    pub(super) max_structured_cells: Option<usize>,
    #[serde(default)]
    pub(super) max_structured_bytes: Option<usize>,
    #[serde(default)]
    pub(super) max_structured_depth: Option<usize>,
    #[serde(default)]
    pub(super) timeout_seconds: Option<u64>,
    /// E3/E3b: when true, materialize the (bounded) full result as an
    /// `oracle-export://{id}` resource and return a `resource_link` instead of
    /// inlining rows. Default false preserves the inline, paginated behavior.
    #[serde(default, alias = "export_to_resource")]
    pub(super) export: bool,
    /// Export serialization format: `csv` (default) or `json`. Only meaningful
    /// with `export=true`.
    #[serde(default, alias = "format")]
    pub(super) export_format: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct PreviewSqlArgs {
    pub(super) sql: String,
}

#[derive(Deserialize)]
pub(super) struct ExecuteArgs {
    pub(super) sql: String,
    #[serde(default)]
    pub(super) binds: Vec<Value>,
    #[serde(default)]
    pub(super) commit: bool,
    #[serde(default, alias = "token", alias = "confirmation_token")]
    pub(super) confirm: Option<String>,
    #[serde(default, alias = "dbms_output")]
    pub(super) capture_dbms_output: bool,
    #[serde(default, alias = "max_dbms_output_lines")]
    pub(super) dbms_output_max_lines: Option<usize>,
    #[serde(default, alias = "max_dbms_output_chars")]
    pub(super) dbms_output_max_chars: Option<usize>,
    #[serde(default)]
    pub(super) timeout_seconds: Option<u64>,
}

#[derive(Deserialize)]
pub(super) struct ExecuteApprovedArgs {
    #[serde(default, alias = "confirm", alias = "confirmation_token")]
    pub(super) token: Option<String>,
    #[serde(default)]
    pub(super) sql: Option<String>,
    #[serde(default)]
    pub(super) commit: Option<bool>,
    #[serde(default)]
    pub(super) timeout_seconds: Option<u64>,
    #[serde(default)]
    pub(super) save_output: Option<String>,
    #[serde(default, alias = "dbms_output")]
    pub(super) capture_dbms_output: bool,
    #[serde(default, alias = "max_dbms_output_lines")]
    pub(super) dbms_output_max_lines: Option<usize>,
    #[serde(default, alias = "max_dbms_output_chars")]
    pub(super) dbms_output_max_chars: Option<usize>,
}

#[derive(Clone, Deserialize)]
pub(super) struct SetSessionLevelArgs {
    #[serde(default, alias = "target_level")]
    pub(super) level: Option<String>,
    #[serde(default)]
    pub(super) ttl_seconds: Option<u64>,
    #[serde(default)]
    pub(super) execute: bool,
    #[serde(default, alias = "token", alias = "confirmation_token")]
    pub(super) confirm: Option<String>,
    #[serde(default)]
    pub(super) action: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct CompileObjectArgs {
    pub(super) object_type: String,
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(default, alias = "object_name")]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) plscope: bool,
    #[serde(default, alias = "enable_warnings")]
    pub(super) warnings: bool,
    #[serde(default)]
    pub(super) execute: bool,
    #[serde(default, alias = "token", alias = "confirmation_token")]
    pub(super) confirm: Option<String>,
    #[serde(default)]
    pub(super) timeout_seconds: Option<u64>,
}

#[derive(Deserialize)]
pub(super) struct CreateOrReplaceArgs {
    #[serde(default, alias = "sql", alias = "ddl")]
    pub(super) source_code: Option<String>,
    #[serde(default)]
    pub(super) execute: bool,
    #[serde(default, alias = "token", alias = "confirmation_token")]
    pub(super) confirm: Option<String>,
    #[serde(default)]
    pub(super) include_errors: Option<bool>,
    #[serde(default)]
    pub(super) timeout_seconds: Option<u64>,
}

#[derive(Deserialize)]
pub(super) struct PatchSourceArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(default, alias = "object_name")]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) object_type: Option<String>,
    #[serde(default, alias = "search_text")]
    pub(super) old_text: Option<String>,
    #[serde(default, alias = "replacement")]
    pub(super) new_text: Option<String>,
    #[serde(default)]
    pub(super) execute: bool,
    #[serde(default, alias = "token", alias = "confirmation_token")]
    pub(super) confirm: Option<String>,
    #[serde(default)]
    pub(super) include_errors: Option<bool>,
    #[serde(default)]
    pub(super) max_chars: Option<usize>,
    #[serde(default)]
    pub(super) timeout_seconds: Option<u64>,
}

#[derive(Deserialize)]
pub(super) struct ReadPatchPreviewArgs {
    #[serde(default, alias = "object_name")]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) max_chars: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct DeployDdlArgs {
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default, alias = "sql", alias = "source_code")]
    pub(super) ddl: Option<String>,
    #[serde(default)]
    pub(super) execute: bool,
    #[serde(default, alias = "token", alias = "confirmation_token")]
    pub(super) confirm: Option<String>,
    #[serde(default)]
    pub(super) include_errors: Option<bool>,
    #[serde(default)]
    pub(super) wait_seconds: Option<u64>,
    #[serde(default)]
    pub(super) timeout_seconds: Option<u64>,
}

#[derive(Deserialize)]
pub(super) struct SchemaInspectArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(default)]
    pub(super) object_type: Option<String>,
    #[serde(default)]
    pub(super) name_like: Option<String>,
    #[serde(default, alias = "limit")]
    pub(super) max_rows: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct SearchObjectsArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(default)]
    pub(super) object_type: Option<String>,
    #[serde(default)]
    pub(super) name_like: Option<String>,
    #[serde(default, alias = "detail")]
    pub(super) detail_level: Option<String>,
    #[serde(default, alias = "limit")]
    pub(super) max_rows: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct ListSchemasArgs {
    #[serde(default)]
    pub(super) name_like: Option<String>,
    #[serde(default, alias = "limit")]
    pub(super) max_rows: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct DescribeArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(default, alias = "table_name", alias = "name")]
    pub(super) table: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct DescribeIndexArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(alias = "index_name")]
    pub(super) name: String,
}

#[derive(Deserialize)]
pub(super) struct DescribeTriggerArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(alias = "trigger_name")]
    pub(super) name: String,
}

#[derive(Deserialize)]
pub(super) struct DescribeViewArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(alias = "view_name")]
    pub(super) name: String,
}

#[derive(Deserialize)]
pub(super) struct GetDdlArgs {
    pub(super) object_type: String,
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(alias = "object_name")]
    pub(super) name: String,
}

#[derive(Deserialize)]
pub(super) struct GetSourceArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(alias = "object_name")]
    pub(super) name: String,
    #[serde(default)]
    pub(super) object_type: Option<String>,
    #[serde(default)]
    pub(super) max_chars: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct SampleRowsArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(alias = "table_name")]
    pub(super) table: String,
    #[serde(default, alias = "limit")]
    pub(super) max_rows: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct TopQueriesArgs {
    /// Ranking metric (`elapsed`/`cpu`/`buffer_gets`/`disk_reads`); defaults to elapsed.
    #[serde(default)]
    pub(super) metric: Option<String>,
    /// How many statements to return (clamped 1..=100 in awr.rs).
    #[serde(default)]
    pub(super) top_n: Option<u32>,
    /// Opt into historical AWR/Statspack instead of the free live cursor cache.
    #[serde(default)]
    pub(super) historical: bool,
    /// Live source only: keep only statements at or above this percent of the
    /// total selected metric (the "5%-of-total" view).
    #[serde(default)]
    pub(super) min_pct_of_total: Option<u8>,
    #[serde(default)]
    pub(super) timeout_seconds: Option<u64>,
}

#[derive(Deserialize)]
pub(super) struct DbHealthArgs {
    /// `"all"` (default) or a comma-separated list of subcheck names
    /// (`invalid_objects`, `unusable_indexes`, `tablespace_undo`,
    /// `sequence_ceiling`, `disabled_constraints`, `buffer_cache_hit_ratio`).
    #[serde(default, alias = "checks", alias = "check")]
    pub(super) health_type: Option<String>,
    #[serde(default)]
    pub(super) timeout_seconds: Option<u64>,
}

#[derive(Deserialize)]
pub(super) struct ReadClobArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(alias = "table_name")]
    pub(super) table: String,
    #[serde(alias = "clob_col")]
    pub(super) clob_column: String,
    #[serde(alias = "pk_col")]
    pub(super) pk_column: String,
    #[serde(alias = "pk_val")]
    pub(super) pk_value: String,
    #[serde(default)]
    pub(super) max_chars: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct SwitchProfileArgs {
    #[serde(default, alias = "db")]
    pub(super) profile: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct CompileErrorsArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(default, alias = "object_name")]
    pub(super) name: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct SearchSourceArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    pub(super) needle: String,
    #[serde(default)]
    pub(super) object_type: Option<String>,
    #[serde(default)]
    pub(super) name_like: Option<String>,
    #[serde(default, alias = "limit")]
    pub(super) max_rows: Option<usize>,
}

#[derive(Deserialize)]
pub(super) struct PlscopeInspectArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(default)]
    #[serde(alias = "object_name")]
    pub(super) name: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct ExplainPlanArgs {
    pub(super) sql: String,
    #[serde(default)]
    pub(super) read_only_standby: bool,
    #[serde(default)]
    pub(super) allow_plan_table_write: bool,
}
