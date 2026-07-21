//! Tool-call argument DTOs deserialized from the inbound MCP `arguments`
//! object, relocated from the former single-file `dispatch.rs`. Fields are
//! `pub(super)` so the dispatcher handlers in the parent module read them.

use serde::Deserialize;
use serde_json::Value;

/// Inline representation for an `oracle_query` result page.
///
/// `Arrow` never changes query execution or egress policy: it only encodes the
/// already-serialized, already-masked result page after audit binding.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(super) enum QueryFormat {
    #[default]
    Json,
    Arrow,
}

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
    /// Optional per-call cost ceiling. This may only lower the active profile's
    /// `max_query_cost`; it can never raise it.
    #[serde(default)]
    pub(super) max_query_cost: Option<u64>,
    /// If true, refuse the cost-estimation `EXPLAIN PLAN` path because it writes
    /// `PLAN_TABLE`. Only meaningful when an effective `max_query_cost` is set.
    #[serde(default)]
    pub(super) read_only_standby: bool,
    /// Explicit opt-in for the cost-estimation `EXPLAIN PLAN` path. Only
    /// meaningful when an effective `max_query_cost` is set.
    #[serde(default)]
    pub(super) allow_plan_table_write: bool,
    /// E3/E3b: when true, materialize the (bounded) full result as an
    /// `oracle-export://{id}` resource and return a `resource_link` instead of
    /// inlining rows. Default false preserves the inline, paginated behavior.
    #[serde(default, alias = "export_to_resource")]
    pub(super) export: bool,
    /// Inline result representation. JSON is the compatibility-preserving
    /// default; Arrow encodes the already-governed page as base64 IPC.
    #[serde(default)]
    pub(super) format: QueryFormat,
    /// Export serialization format: `csv` (default) or `json`. Only meaningful
    /// with `export=true`.
    #[serde(default)]
    pub(super) export_format: Option<String>,
    /// K10: when true, deliver the (bounded) result as an ordered sequence of
    /// resumable page `chunks` instead of a single inline page — "incremental
    /// fetch" made first-class. The server drives successive cursor pages
    /// (byte-identical to a manual cursor resume) and, over the HTTP/SSE
    /// transport, emits each chunk as its own `event: chunk` frame. Default
    /// false preserves the single-page behavior. Mutually exclusive with
    /// `export` and `as_of` (a typed refusal). Streaming never touches the
    /// fail-closed classifier — it only changes DELIVERY of an already-proven
    /// read.
    #[serde(default, alias = "stream")]
    pub(super) streaming: bool,
    /// K9: STRUCTURED flashback / AS-OF read target. The agent passes a NORMAL
    /// `SELECT` here plus an `as_of` value — never hand-written `AS OF` SQL. The
    /// base SELECT is proven read-only by the unchanged classifier FIRST; the
    /// server then bounds the proven query in a `DBMS_FLASHBACK` session window
    /// (the SCN/timestamp is BOUND, never interpolated). Exactly one of `scn` /
    /// `timestamp` may be set.
    #[serde(default)]
    pub(super) as_of: Option<AsOfArg>,
}

/// Arguments for the governed 23ai vector-semantic search surface.
#[derive(Deserialize)]
pub(super) struct SemanticSearchArgs {
    pub(super) over: SemanticSearchOverArgs,
    #[serde(default)]
    pub(super) query_text: Option<String>,
    #[serde(default)]
    pub(super) query_vector: Option<Vec<f64>>,
    #[serde(default)]
    pub(super) k: Option<usize>,
    #[serde(default)]
    pub(super) metric: Option<String>,
    /// One governed equality filter for hybrid retrieval. The dispatcher owns
    /// the predicate grammar and binds `value`; it never accepts raw filter
    /// SQL from an MCP caller.
    #[serde(default)]
    pub(super) filter: Option<SemanticSearchFilterArgs>,
    #[serde(default)]
    pub(super) timeout_seconds: Option<u64>,
}

/// The only caller-controlled shape admitted into a hybrid vector predicate.
/// Both fields are data: `column` is validated as a simple identifier and
/// `value` is bound as a scalar. Unknown fields (including `or`/`sql`) are
/// rejected during deserialization so they cannot widen the generated read.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SemanticSearchFilterArgs {
    pub(super) column: String,
    pub(super) value: Value,
}

#[derive(Deserialize)]
pub(super) struct SemanticSearchOverArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    pub(super) table: String,
    pub(super) column: String,
}

/// K9: the STRUCTURED flashback target for `oracle_query`. Exactly one of `scn`
/// or `timestamp` must be set (both-set / neither-set is a typed refusal in the
/// dispatcher, before any flashback is applied).
#[derive(Deserialize)]
pub(super) struct AsOfArg {
    /// Read as of this system change number (the deterministic form).
    #[serde(default)]
    pub(super) scn: Option<u64>,
    /// Read as of this wall-clock timestamp, `YYYY-MM-DD HH24:MI:SS` (a `T`
    /// date/time separator is also accepted). Oracle resolves it to the nearest
    /// SCN (~3s granularity).
    #[serde(default)]
    pub(super) timestamp: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct DiffArgs {
    /// A normal SELECT/WITH statement. It is classified as a read against each
    /// database it runs on, before any read runs; SCNs are bound through
    /// DBMS_FLASHBACK, not interpolated into this SQL.
    pub(super) sql: String,
    #[serde(default)]
    pub(super) binds: Vec<Value>,
    /// System change number for side A. Required in the single-database
    /// (time) mode; optional in the cross-database (fleet) mode, where it pins
    /// side A to a flashback read instead of the current committed state.
    #[serde(default)]
    pub(super) scn_a: Option<u64>,
    /// System change number for side B. See [`DiffArgs::scn_a`].
    #[serde(default)]
    pub(super) scn_b: Option<u64>,
    /// Connection profile for side A. Supplying both `profile_a` and
    /// `profile_b` selects the cross-database mode: the same proven read runs
    /// against two databases in the fleet, each classified and masked under its
    /// own profile.
    #[serde(default, alias = "db_a")]
    pub(super) profile_a: Option<String>,
    /// Connection profile for side B. See [`DiffArgs::profile_a`].
    #[serde(default, alias = "db_b")]
    pub(super) profile_b: Option<String>,
    /// Optional key columns used to align rows and report `changed`. When empty,
    /// the dispatcher attempts primary-key inference for one simple local table;
    /// otherwise it falls back to keyless multiset add/remove.
    #[serde(default, alias = "keys", alias = "key_columns")]
    pub(super) key: Vec<String>,
    #[serde(default)]
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
    pub(super) timeout_seconds: Option<u64>,
}

#[derive(Deserialize)]
pub(super) struct PreviewSqlArgs {
    pub(super) sql: String,
}

/// Arc I: `oracle_checkpoint` — establish a named savepoint on the pinned
/// session, opening (or extending) the reversible workspace.
#[derive(Deserialize)]
pub(super) struct CheckpointArgs {
    pub(super) name: String,
}

/// Arc I: `oracle_undo_to` — `ROLLBACK TO SAVEPOINT <name>`, or a full rollback
/// that discards the whole workspace when `name` is omitted.
#[derive(Deserialize)]
pub(super) struct UndoToArgs {
    #[serde(default, alias = "checkpoint")]
    pub(super) name: Option<String>,
}

/// Arc I: `oracle_preview_dml` — run the DML inside a savepoint sandbox, capture
/// what it did, roll it back, and present the result.
#[derive(Deserialize)]
pub(super) struct PreviewDmlArgs {
    /// The DML to dry-run. Classified and gated exactly like `oracle_execute`'s.
    pub(super) sql: String,
    #[serde(default)]
    pub(super) binds: Vec<Value>,
    /// An optional read the server runs *inside the sandbox*, once before the DML
    /// and once after, to show the rows it changed. It is proven read-only by the
    /// unchanged classifier, like any other read.
    #[serde(default, alias = "witness_sql")]
    pub(super) witness: Option<String>,
    #[serde(default)]
    pub(super) witness_binds: Vec<Value>,
    #[serde(default, alias = "limit")]
    pub(super) max_rows: Option<usize>,
    #[serde(default)]
    pub(super) timeout_seconds: Option<u64>,
}

#[derive(Deserialize)]
pub(super) struct ExecuteArgs {
    pub(super) sql: String,
    #[serde(default)]
    pub(super) binds: Vec<Value>,
    #[serde(default)]
    pub(super) commit: bool,
    /// Arc I: leave this statement's effect *pending* inside the open reversible
    /// workspace instead of rolling it back, so a later `oracle_undo_to` can
    /// walk it back to a checkpoint. Requires a live checkpoint; mutually
    /// exclusive with `commit`.
    #[serde(default)]
    pub(super) hold: bool,
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
    /// H3: search the egress-filtered names-only object index across every
    /// MCP-visible profile. The dispatcher rejects richer detail levels in
    /// fleet mode so no nested field can bypass the source profile's policy.
    #[serde(default)]
    pub(super) fleet: bool,
}

/// C2/H1: select stable sections of the bounded `oracle_orient` snapshot and,
/// when requested, lift it across every MCP-visible profile.
#[derive(Deserialize)]
pub(super) struct OrientArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(default)]
    pub(super) include: Vec<String>,
    #[serde(default)]
    pub(super) fleet: bool,
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
    #[serde(default)]
    pub(super) from_line: Option<usize>,
    #[serde(default)]
    pub(super) to_line: Option<usize>,
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
pub(super) struct PlanTimelineArgs {
    /// The 13-character Oracle SQL ID whose AWR plan history is requested.
    pub(super) sql_id: String,
    /// Bounded number of chronologically ordered AWR observations to return.
    #[serde(default)]
    pub(super) max_points: Option<u32>,
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
    #[serde(default)]
    pub(super) max_line_chars: Option<usize>,
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
