//! Tool-call argument DTOs deserialized from the inbound MCP `arguments`
//! object, relocated from the former single-file `dispatch.rs`. Fields are
//! `pub(super)` so the dispatcher handlers in the parent module read them.

use serde::{Deserialize, Deserializer};
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub(super) struct PreviewSqlArgs {
    pub(super) sql: String,
}

/// Arc I: `oracle_checkpoint` — establish a named savepoint on the pinned
/// session, opening (or extending) the reversible workspace.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CheckpointArgs {
    pub(super) name: String,
}

/// Arc I: `oracle_undo_to` — `ROLLBACK TO SAVEPOINT <name>`, or a full rollback
/// that discards the whole workspace when `name` is omitted.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UndoToArgs {
    #[serde(default, alias = "checkpoint")]
    pub(super) name: Option<String>,
}

/// Arc I: `oracle_preview_dml` — run the DML inside a savepoint sandbox, capture
/// what it did, roll it back, and present the result.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Missing means no grant; an explicit JSON null is malformed, not permission
/// to fall back to session authority.
fn explicit_grant_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Explicit signed scoped-grant reference; never inferred from active grants.
    #[serde(default, deserialize_with = "explicit_grant_string")]
    pub(super) scoped_grant: Option<String>,
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
#[serde(deny_unknown_fields)]
pub(super) struct ExecuteApprovedArgs {
    #[serde(default, alias = "confirm", alias = "confirmation_token")]
    pub(super) token: Option<String>,
    #[serde(default, deserialize_with = "explicit_grant_string")]
    pub(super) scoped_grant: Option<String>,
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
#[serde(deny_unknown_fields)]
pub(super) struct SetSessionLevelArgs {
    /// Historical alias inputs were accepted and ignored; retain that
    /// documented contract until T3.3 replaces the alias decoder.
    #[serde(default, rename = "db")]
    pub(super) _db: Option<String>,
    #[serde(default, rename = "profile")]
    pub(super) _profile: Option<String>,
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub(super) struct ReadPatchPreviewArgs {
    #[serde(default, alias = "object_name")]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) max_chars: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub(super) struct SchemaInspectArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(default)]
    pub(super) object_type: Option<String>,
    #[serde(default)]
    pub(super) name_like: Option<String>,
    #[serde(default, alias = "limit")]
    pub(super) max_rows: Option<usize>,
    #[serde(default)]
    pub(super) cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub(super) struct OrientArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(default)]
    pub(super) include: Vec<String>,
    #[serde(default)]
    pub(super) fleet: bool,
    #[serde(default, alias = "limit")]
    pub(super) max_rows: Option<usize>,
    #[serde(default)]
    pub(super) cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ListSchemasArgs {
    #[serde(default)]
    pub(super) name_like: Option<String>,
    #[serde(default, alias = "limit")]
    pub(super) max_rows: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DescribeArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(default, alias = "table_name", alias = "name")]
    pub(super) table: Option<String>,
    #[serde(default, alias = "limit")]
    pub(super) max_rows: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DescribeIndexArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(alias = "index_name")]
    pub(super) name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DescribeTriggerArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(alias = "trigger_name")]
    pub(super) name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DescribeViewArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(alias = "view_name")]
    pub(super) name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GetDdlArgs {
    pub(super) object_type: String,
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(alias = "object_name")]
    pub(super) name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub(super) struct SampleRowsArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(alias = "table_name")]
    pub(super) table: String,
    #[serde(default, alias = "limit")]
    pub(super) max_rows: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub(super) struct SwitchProfileArgs {
    #[serde(default, alias = "db")]
    pub(super) profile: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompileErrorsArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(default, alias = "object_name")]
    pub(super) name: Option<String>,
    #[serde(default, alias = "limit")]
    pub(super) max_rows: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub(super) struct PlscopeInspectArgs {
    #[serde(default)]
    pub(super) owner: Option<String>,
    #[serde(default)]
    #[serde(alias = "object_name")]
    pub(super) name: Option<String>,
    #[serde(default, alias = "limit")]
    pub(super) max_rows: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ExplainPlanArgs {
    pub(super) sql: String,
    #[serde(default)]
    pub(super) read_only_standby: bool,
    #[serde(default)]
    pub(super) allow_plan_table_write: bool,
}

#[cfg(test)]
mod strict_contract_tests {
    use super::*;
    use crate::dispatch::{canonical_tool_name, ensure_no_args, parse_args};
    use oraclemcp_error::ErrorEnvelope;
    use serde::de::DeserializeOwned;
    use serde_json::{Map, Value, json};
    use std::collections::{BTreeMap, BTreeSet};

    // Use the dispatcher's actual typed decoder, including each compatibility
    // wrapper's distinct DTO, without opening a database lane.
    fn decode(name: &str, args: Value) -> Result<(), ErrorEnvelope> {
        macro_rules! typed {
            ($ty:ty) => {
                parse_args::<$ty>(name, args).map(|_| ())
            };
        }
        match canonical_tool_name(name) {
            "oracle_list_profiles" | "oracle_connection_info" => ensure_no_args(name, args),
            "oracle_switch_profile" => typed!(SwitchProfileArgs),
            "oracle_set_session_level" => typed!(SetSessionLevelArgs),
            "oracle_query" => typed!(QueryArgs),
            "oracle_semantic_search" => typed!(SemanticSearchArgs),
            "oracle_diff" => typed!(DiffArgs),
            "oracle_preview_sql" => typed!(PreviewSqlArgs),
            "oracle_execute" => typed!(ExecuteArgs),
            "oracle_checkpoint" => typed!(CheckpointArgs),
            "oracle_undo_to" => typed!(UndoToArgs),
            "oracle_preview_dml" => typed!(PreviewDmlArgs),
            "oracle_compile_object" => typed!(CompileObjectArgs),
            "oracle_create_or_replace" => typed!(CreateOrReplaceArgs),
            "oracle_patch_source" => typed!(PatchSourceArgs),
            "oracle_list_schemas" => typed!(ListSchemasArgs),
            "oracle_schema_inspect" => typed!(SchemaInspectArgs),
            "oracle_search_objects" => typed!(SearchObjectsArgs),
            "oracle_orient" => typed!(OrientArgs),
            "oracle_describe" => typed!(DescribeArgs),
            "oracle_describe_index" => typed!(DescribeIndexArgs),
            "oracle_describe_trigger" => typed!(DescribeTriggerArgs),
            "oracle_describe_view" => typed!(DescribeViewArgs),
            "oracle_get_ddl" => typed!(GetDdlArgs),
            "oracle_get_source" => typed!(GetSourceArgs),
            "oracle_sample_rows" => typed!(SampleRowsArgs),
            "oracle_read_clob" => typed!(ReadClobArgs),
            "oracle_compile_errors" => typed!(CompileErrorsArgs),
            "oracle_search_source" => typed!(SearchSourceArgs),
            "oracle_plscope_inspect" => typed!(PlscopeInspectArgs),
            "oracle_explain_plan" => typed!(ExplainPlanArgs),
            "oracle_top_queries" => typed!(TopQueriesArgs),
            "oracle_plan_timeline" => typed!(PlanTimelineArgs),
            "oracle_db_health" => typed!(DbHealthArgs),
            "execute_approved" => typed!(ExecuteApprovedArgs),
            "deploy_ddl" => typed!(DeployDdlArgs),
            "read_patch_preview" => typed!(ReadPatchPreviewArgs),
            #[cfg(feature = "plsql-intelligence")]
            name if crate::plsql_tools::TOOL_NAMES.contains(&name) => {
                crate::plsql_tools::decode_args_for_contract(name, args)
            }
            other => panic!("registered tool {other} has no decoder contract"),
        }
    }

    // Serde's derived struct decoder reports its complete accepted field set
    // (including aliases) for a deliberately unknown key. This observes the
    // runtime decoder itself, rather than maintaining a second hand-written
    // property inventory beside the schema.
    fn serde_fields<T: DeserializeOwned>() -> Vec<String> {
        let error = serde_json::from_value::<T>(json!({"__bogus__": 1}))
            .err()
            .expect("deny_unknown_fields must reject the probe");
        let message = error.to_string();
        assert!(message.contains("unknown field `__bogus__`"), "{message}");
        message
            .split('`')
            .skip(3)
            .step_by(2)
            .map(str::to_owned)
            .collect()
    }

    fn runtime_fields(name: &str) -> Vec<String> {
        macro_rules! fields {
            ($ty:ty) => {
                serde_fields::<$ty>()
            };
        }
        match canonical_tool_name(name) {
            "oracle_list_profiles" | "oracle_connection_info" => Vec::new(),
            "oracle_switch_profile" => fields!(SwitchProfileArgs),
            "oracle_set_session_level" => fields!(SetSessionLevelArgs),
            "oracle_query" => fields!(QueryArgs),
            "oracle_semantic_search" => fields!(SemanticSearchArgs),
            "oracle_diff" => fields!(DiffArgs),
            "oracle_preview_sql" => fields!(PreviewSqlArgs),
            "oracle_execute" => fields!(ExecuteArgs),
            "oracle_checkpoint" => fields!(CheckpointArgs),
            "oracle_undo_to" => fields!(UndoToArgs),
            "oracle_preview_dml" => fields!(PreviewDmlArgs),
            "oracle_compile_object" => fields!(CompileObjectArgs),
            "oracle_create_or_replace" => fields!(CreateOrReplaceArgs),
            "oracle_patch_source" => fields!(PatchSourceArgs),
            "oracle_list_schemas" => fields!(ListSchemasArgs),
            "oracle_schema_inspect" => fields!(SchemaInspectArgs),
            "oracle_search_objects" => fields!(SearchObjectsArgs),
            "oracle_orient" => fields!(OrientArgs),
            "oracle_describe" => fields!(DescribeArgs),
            "oracle_describe_index" => fields!(DescribeIndexArgs),
            "oracle_describe_trigger" => fields!(DescribeTriggerArgs),
            "oracle_describe_view" => fields!(DescribeViewArgs),
            "oracle_get_ddl" => fields!(GetDdlArgs),
            "oracle_get_source" => fields!(GetSourceArgs),
            "oracle_sample_rows" => fields!(SampleRowsArgs),
            "oracle_read_clob" => fields!(ReadClobArgs),
            "oracle_compile_errors" => fields!(CompileErrorsArgs),
            "oracle_search_source" => fields!(SearchSourceArgs),
            "oracle_plscope_inspect" => fields!(PlscopeInspectArgs),
            "oracle_explain_plan" => fields!(ExplainPlanArgs),
            "oracle_top_queries" => fields!(TopQueriesArgs),
            "oracle_plan_timeline" => fields!(PlanTimelineArgs),
            "oracle_db_health" => fields!(DbHealthArgs),
            "execute_approved" => fields!(ExecuteApprovedArgs),
            "deploy_ddl" => fields!(DeployDdlArgs),
            "read_patch_preview" => fields!(ReadPatchPreviewArgs),
            #[cfg(feature = "plsql-intelligence")]
            name if crate::plsql_tools::TOOL_NAMES.contains(&name) => {
                crate::plsql_tools::runtime_fields_for_contract(name)
            }
            other => panic!("registered tool {other} has no runtime field contract"),
        }
    }

    fn placeholder(schema: &Value) -> Value {
        if let Some(choice) = schema
            .get("enum")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
        {
            return choice.clone();
        }
        match schema.get("type").and_then(Value::as_str) {
            Some("string") => json!("X"),
            Some("integer" | "number") => json!(1),
            Some("boolean") => json!(false),
            Some("array") => json!([]),
            Some("object") => {
                let mut object = Map::new();
                if let Some(required) = schema.get("required").and_then(Value::as_array) {
                    for name in required.iter().filter_map(Value::as_str) {
                        object.insert(name.to_owned(), placeholder(&schema["properties"][name]));
                    }
                }
                Value::Object(object)
            }
            _ => Value::Null,
        }
    }

    fn minimal(schema: &Value) -> Value {
        placeholder(schema)
    }

    fn minimal_for_tool(name: &str, schema: &Value) -> Value {
        let mut value = minimal(schema);
        let args = value.as_object_mut().expect("object schema");
        // Function adapters reject a top-level anyOf. These schemas describe
        // "name or old alias" in property text, so choose the canonical arm
        // to construct an actually valid minimal request for the DTO test.
        match canonical_tool_name(name) {
            "oracle_describe_index"
            | "oracle_describe_trigger"
            | "oracle_describe_view"
            | "oracle_get_ddl"
            | "oracle_get_source" => {
                args.insert("name".to_owned(), json!("X"));
            }
            "oracle_sample_rows" | "oracle_read_clob" => {
                args.insert("table".to_owned(), json!("X"));
            }
            _ => {}
        }
        if canonical_tool_name(name) == "oracle_read_clob" {
            for field in ["clob_column", "pk_column", "pk_value"] {
                args.insert(field.to_owned(), json!("X"));
            }
        }
        value
    }

    fn log_case(case_id: &str, tool: &str, expected: &Value, actual: &Value) {
        use std::io::Write;
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<bool>> = OnceLock::new();
        let mut started = LOCK
            .get_or_init(|| Mutex::new(false))
            .lock()
            .expect("test log lock");
        let target = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_owned());
        let path = std::path::Path::new(&target).join("test-logs/w3_strict_decode.jsonl");
        std::fs::create_dir_all(path.parent().expect("test log parent")).expect("test log dir");
        if !*started {
            std::fs::write(&path, b"").expect("test log reset");
            *started = true;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("test log open");
        writeln!(file, "{}", json!({"case_id": case_id, "tool": tool, "expected": expected, "actual": actual, "verdict": expected == actual})).expect("test log write");
    }

    #[test]
    fn every_registered_tool_rejects_unknown_argument() {
        for tool in crate::registry::tool_registry().tools {
            let schema = tool.input_schema.as_ref().expect("input schema");
            let mut args = minimal_for_tool(&tool.name, schema);
            args.as_object_mut()
                .expect("object schema")
                .insert("__bogus__".to_owned(), json!(1));
            let result = decode(&tool.name, args);
            let actual = json!({"invalid_arguments": result.as_ref().is_err_and(|e| e.error_class == oraclemcp_error::ErrorClass::InvalidArguments), "names_bogus": result.as_ref().err().is_some_and(|e| e.message.contains("__bogus__"))});
            let expected = json!({"invalid_arguments": true, "names_bogus": true});
            log_case("unknown_argument", &tool.name, &expected, &actual);
            assert_eq!(actual, expected, "{} must reject __bogus__", tool.name);
        }
    }

    #[test]
    fn existing_argument_aliases_still_decode() {
        for (tool, args) in [
            ("oracle_describe_index", json!({"index_name": "I"})),
            ("oracle_describe_trigger", json!({"trigger_name": "T"})),
            ("oracle_describe_view", json!({"view_name": "V"})),
            (
                "oracle_get_ddl",
                json!({"object_type": "TABLE", "object_name": "T"}),
            ),
            ("oracle_get_source", json!({"object_name": "P"})),
            ("oracle_sample_rows", json!({"table_name": "T", "limit": 1})),
            (
                "oracle_read_clob",
                json!({"table_name": "T", "clob_col": "C", "pk_col": "ID", "pk_val": "1"}),
            ),
            ("enable_writes", json!({"db": "old", "profile": "old"})),
            ("disable_writes", json!({"db": "old", "profile": "old"})),
        ] {
            let result = decode(tool, args);
            assert!(result.is_ok(), "{tool} old alias must decode: {result:?}");
        }
    }

    #[test]
    fn nested_argument_object_rejects_unknown_fields() {
        let error = decode(
            "oracle_query",
            json!({"sql": "SELECT 1 FROM dual", "as_of": {"scn": 1, "typo": 2}}),
        )
        .expect_err("unknown nested as_of field must be rejected");
        assert_eq!(
            error.error_class,
            oraclemcp_error::ErrorClass::InvalidArguments
        );
        assert!(error.message.contains("typo"), "{error:?}");
    }

    #[test]
    fn schema_runtime_differential_every_tool() {
        let mut mismatches = Vec::new();
        let registry = crate::registry::tool_registry();
        let mut advertised_by_route: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for tool in &registry.tools {
            let fields = advertised_by_route
                .entry(canonical_tool_name(&tool.name).to_owned())
                .or_default();
            fields.extend(
                tool.input_schema.as_ref().expect("input schema")["properties"]
                    .as_object()
                    .expect("properties")
                    .keys()
                    .cloned(),
            );
        }
        for tool in registry.tools {
            let schema = tool.input_schema.as_ref().expect("input schema");
            let minimal = minimal_for_tool(&tool.name, schema);
            let base = decode(&tool.name, minimal.clone());
            let accepted = schema["properties"].as_object().expect("properties");
            let mut missing_runtime_fields = Vec::new();
            for field in runtime_fields(&tool.name) {
                // One DTO may serve canonical and compatibility tool names.
                // Each name has a narrower pre-decode schema gate, while the
                // union covers every field that the shared DTO can decode.
                if !advertised_by_route[canonical_tool_name(&tool.name)].contains(&field) {
                    missing_runtime_fields.push(format!(
                        "{} DTO accepts {field} but no schema on its route advertises it",
                        tool.name
                    ));
                }
            }
            let minimal_decodes = base.is_ok();
            if !minimal_decodes {
                mismatches.push(format!(
                    "{} minimal schema args disagree with DTO: {base:?}",
                    tool.name
                ));
            }
            let mut rejected_properties = Vec::new();
            for (property, property_schema) in accepted {
                let mut args = minimal.clone();
                let fields = args.as_object_mut().expect("object schema");
                // Test a legacy alias in place of its canonical field. Sending
                // both is a duplicate-field conflict, which T3.3 handles.
                let canonical = match property.as_str() {
                    "index_name" | "trigger_name" | "view_name" | "object_name" => Some("name"),
                    "table_name" => Some("table"),
                    "clob_col" => Some("clob_column"),
                    "pk_col" => Some("pk_column"),
                    "pk_val" => Some("pk_value"),
                    _ => None,
                };
                if let Some(canonical) = canonical {
                    fields.remove(canonical);
                }
                fields.insert(property.clone(), placeholder(property_schema));
                let result = decode(&tool.name, args);
                if let Err(error) = result {
                    rejected_properties.push(format!(
                        "{} advertises {property} but DTO rejects it: {error:?}",
                        tool.name
                    ));
                }
            }
            let actual = json!({"minimal_decodes": minimal_decodes, "declared_properties_accepted": rejected_properties.is_empty(), "runtime_fields_advertised": missing_runtime_fields.is_empty()});
            let expected = json!({"minimal_decodes": true, "declared_properties_accepted": true, "runtime_fields_advertised": true});
            log_case(
                "schema_runtime_differential",
                &tool.name,
                &expected,
                &actual,
            );
            mismatches.extend(rejected_properties);
            mismatches.extend(missing_runtime_fields);
        }
        assert!(
            mismatches.is_empty(),
            "schema/runtime mismatches:\n{}",
            mismatches.join("\n")
        );
    }
}
