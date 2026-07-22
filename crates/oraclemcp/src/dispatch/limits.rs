use oraclemcp_db::StructuredDecodeCaps;

/// Default cap on `oracle_search_source` result rows when the caller omits it.
pub(super) const DEFAULT_SEARCH_MAX_ROWS: usize = 200;
/// Hard cap on `oracle_search_source` for a single call.
pub(super) const MAX_SEARCH_MAX_ROWS: usize = 5_000;
/// Default cap on each `oracle_search_source` source line.
pub(super) const DEFAULT_SEARCH_MAX_LINE_CHARS: usize = 500;
/// Smallest cap that still leaves an explicit truncation marker in the result.
pub(super) const MIN_SEARCH_MAX_LINE_CHARS: usize = 16;
/// Oracle source text rows are at most 4,000 characters in the dictionary.
pub(super) const MAX_SEARCH_MAX_LINE_CHARS: usize = 4_000;
pub(super) const SOURCE_SEARCH_LINE_TRUNCATION_MARKER: &str = "… [truncated]";
/// Default cap on `oracle_get_source` source text when the caller omits it.
pub(super) const DEFAULT_SOURCE_MAX_CHARS: usize = 1_000_000;
/// Default cap for dictionary metadata arrays that are not cursor-paginated.
pub(super) const DEFAULT_METADATA_MAX_ROWS: usize = 200;
/// Hard cap for dictionary metadata arrays that are not cursor-paginated.
pub(super) const MAX_METADATA_MAX_ROWS: usize = 5_000;
/// Cap on before/after snippets in `oracle_patch_source` previews.
pub(super) const DEFAULT_PATCH_PREVIEW_CHARS: usize = 1_000;
/// Cap on direct dependents listed in a DDL preview's blast-radius block. The
/// probe is observational enrichment, so it is bounded rather than paginated.
pub(super) const DEFAULT_DEPENDENTS_PREVIEW_MAX: usize = 200;
/// Default cap on `oracle_schema_inspect` result rows when the caller omits it.
pub(super) const DEFAULT_SCHEMA_INSPECT_MAX_ROWS: usize = 500;
/// Hard cap on `oracle_schema_inspect` for a single call.
pub(super) const MAX_SCHEMA_INSPECT_MAX_ROWS: usize = 5_000;
/// Compact default for the `get_schema` orientation alias.
pub(super) const DEFAULT_GET_SCHEMA_MAX_ROWS: usize = 100;
/// Hard ceiling for a `get_schema` page. Client arguments can only lower this.
pub(super) const MAX_GET_SCHEMA_MAX_ROWS: usize = 250;
/// Bound cursor depth so a continuation cannot turn one dictionary read into an
/// arbitrarily expensive offset scan.
pub(super) const MAX_GET_SCHEMA_CURSOR_OFFSET: usize = 10_000;
/// Default cap on `oracle_search_objects` result rows when the caller omits it.
/// Lower than schema_inspect because each result is enriched per detail level.
pub(super) const DEFAULT_SEARCH_OBJECTS_MAX_ROWS: usize = 100;
/// Hard cap on `oracle_search_objects` for a single call.
pub(super) const MAX_SEARCH_OBJECTS_MAX_ROWS: usize = 5_000;
/// Audit description for the synthetic, merged rows emitted by the fleet
/// catalog. The underlying dictionary reads remain parameterized `ALL_*`
/// reads in `search_objects`; this label binds the egress certificate to the
/// aggregate surface without recording caller filters as faux SQL.
pub(super) const FLEET_CATALOG_AUDIT_SQL: &str = "GENERATED FLEET CATALOG SEARCH";
/// Default cap on `oracle_list_schemas` result rows when the caller omits it.
pub(super) const DEFAULT_SCHEMA_LIST_MAX_ROWS: usize = 200;
/// Hard cap on `oracle_list_schemas` for a single call.
pub(super) const MAX_SCHEMA_LIST_MAX_ROWS: usize = 5_000;
/// Default cap on `oracle_sample_rows` when the caller omits it.
pub(super) const DEFAULT_SAMPLE_MAX_ROWS: usize = 50;
/// Hard cap on `oracle_sample_rows` for a single call.
pub(super) const MAX_SAMPLE_MAX_ROWS: usize = 1_000;
/// Default cap on `oracle_read_clob` text when the caller omits it.
pub(super) const DEFAULT_LOB_MAX_CHARS: usize = 1_000_000;
/// Hard cap on `oracle_query` rows per page when a caller supplies max_rows/limit.
pub(super) const MAX_QUERY_MAX_ROWS: usize = 5_000;
/// Hard cap on serialized bytes per `oracle_query` page.
pub(super) const MAX_QUERY_RESULT_BYTES: usize = 25 * 1024 * 1024;
/// Arrow cells use compact JSON literals so the IPC stream preserves the exact
/// governed JSON value contract (including lossless NUMBER strings, truncated
/// LOB objects, and nested structured cells) without a type-coercion escape.
pub(super) const ARROW_CELL_ENCODING: &str = "json_utf8_literal_v1";
/// Hard cap on rows materialized into a single `oracle_query` export resource
/// (E3/E3b). Bounds the work + memory of one export independent of the inline
/// page cap; rows beyond this are dropped and the export is marked truncated.
pub(super) const MAX_QUERY_EXPORT_ROWS: usize = 100_000;
/// K10: hard cap on total rows a single streaming (`streaming=true`)
/// `oracle_query` walks the cursor for. Bounds the work + memory of one
/// streamed response; beyond it the final chunk carries a resume cursor and the
/// response is flagged `truncated` so the caller can continue with the cursor.
pub(super) const MAX_QUERY_STREAM_ROWS: usize = 50_000;
/// Hard cap on text/CLOB characters materialized by a single query cell.
pub(super) const MAX_QUERY_TEXT_CHARS: usize = 1_000_000;
/// Hard cap on BLOB bytes materialized by a single query cell.
pub(super) const MAX_QUERY_BLOB_BYTES: usize = 5 * 1024 * 1024;
/// Hard cap on direct entries decoded from one structured ARRAY/JSON node.
pub(super) const MAX_QUERY_STRUCTURED_ROWS: usize = StructuredDecodeCaps::DEEP.max_rows;
/// Hard cap on structured nodes decoded from one structured cell.
pub(super) const MAX_QUERY_STRUCTURED_CELLS: usize = StructuredDecodeCaps::DEEP.max_cells;
/// Hard cap on compact JSON bytes decoded from one structured node.
pub(super) const MAX_QUERY_STRUCTURED_BYTES: usize = StructuredDecodeCaps::DEEP.max_bytes;
/// Hard cap on structured ARRAY/JSON recursion depth.
pub(super) const MAX_QUERY_STRUCTURED_DEPTH: usize = StructuredDecodeCaps::DEEP.max_depth;
/// Default result count for `oracle_semantic_search` when the caller omits k.
pub(super) const DEFAULT_SEMANTIC_SEARCH_K: usize = 10;
/// Hard result cap for one semantic-search request.
pub(super) const MAX_SEMANTIC_SEARCH_K: usize = 1_000;
/// Hard dimension cap for a caller-provided semantic vector before it reaches
/// either the driver or Oracle. Covers current embedding dimensions generously
/// while keeping one request bounded.
pub(super) const MAX_SEMANTIC_SEARCH_VECTOR_DIMENSIONS: usize = 16_384;
/// Hard cap on query text accepted by the in-database embedding expression.
/// This bounds one request before it reaches either the driver or the model.
pub(super) const MAX_SEMANTIC_SEARCH_TEXT_CHARS: usize = 32_768;
/// Fixed capability probe. `COMPATIBLE`, not the marketing/server banner, is
/// the governing contract for the SQL vector-embedding grammar.
pub(super) const SEMANTIC_SEARCH_COMPATIBLE_SQL: &str =
    "SELECT value AS compatible FROM v$parameter WHERE name = 'compatible'";
/// Read at most two candidates: zero proves no local model, two proves the
/// unconfigured server-side selection would be ambiguous. The tool never
/// accepts a model name from a caller.
pub(super) const SEMANTIC_SEARCH_ONNX_MODEL_SQL: &str = "SELECT model_name FROM user_mining_models \
     WHERE mining_function = 'EMBEDDING' AND algorithm = 'ONNX' \
     ORDER BY model_name FETCH FIRST 2 ROWS ONLY";
/// Default temporary session elevation window for `oracle_set_session_level`.
pub(super) const DEFAULT_SESSION_LEVEL_TTL_SECONDS: u64 = 900;
/// Hard cap for one temporary session elevation window.
pub(super) const MAX_SESSION_LEVEL_TTL_SECONDS: u64 = 3_600;
/// Default cap on DBMS_OUTPUT lines captured by `oracle_execute`.
pub(super) const DEFAULT_DBMS_OUTPUT_MAX_LINES: usize = 200;
/// Hard cap on DBMS_OUTPUT lines captured by `oracle_execute`.
pub(super) const MAX_DBMS_OUTPUT_MAX_LINES: usize = 5_000;
/// Default cap on DBMS_OUTPUT characters captured by `oracle_execute`.
pub(super) const DEFAULT_DBMS_OUTPUT_MAX_CHARS: usize = 200_000;
/// Hard cap on DBMS_OUTPUT characters captured by `oracle_execute`.
pub(super) const MAX_DBMS_OUTPUT_MAX_CHARS: usize = 1_000_000;
/// Hard cap on the Oracle-side DBMS_OUTPUT buffer requested for a capture.
pub(super) const MAX_DBMS_OUTPUT_BUFFER_BYTES: usize = 1_000_000;
/// Compatibility TTL for `preview_sql` -> `execute_approved` cached grants.
pub(super) const EXECUTE_APPROVED_TOKEN_TTL_SECONDS: u64 = 300;
/// Hard cap on remembered compatibility grants in one server process.
pub(super) const MAX_EXECUTE_APPROVED_TOKENS: usize = 128;
/// Tamper-token scope for signed execution grant references.
pub(super) const EXECUTE_GRANT_TOKEN_SCOPE: &str = "grant:execute";
/// Bound dictionary preflight for Oracle's one-child edition rule. The parent
/// name is positional-bind-only; caller text is never interpolated into this
/// generated SQL.
pub(super) const EDITION_CHILDREN_SQL: &str =
    "SELECT edition_name FROM all_editions WHERE parent_edition_name = :1";

/// Hard cap on remembered source patch previews in one server process.
pub(super) const MAX_PATCH_PREVIEWS: usize = 128;
/// Each orient snapshot is four bounded dictionary reads; cap retained profiles,
/// catalog revisions, and owner scopes so an agent cannot turn selector caching
/// into an unbounded in-process store.
pub(super) const MAX_ORIENT_SNAPSHOT_CACHE_ENTRIES: usize = 32;
/// Each component of an orient snapshot is independently bounded in the DB
/// layer. This fixed tool-level cap makes a cache entry stable across callers.
pub(super) const DEFAULT_ORIENT_MAX_ROWS: usize = 100;
pub(super) const MAX_ORIENT_MAX_ROWS: usize = 250;
/// Bound cursor depth for each independently capped orient component.
pub(super) const MAX_ORIENT_CURSOR_OFFSET: usize = 10_000;
/// Hard cap on per-call Oracle round-trip timeout overrides.
pub(super) const MAX_CALL_TIMEOUT_SECONDS: u64 = 3_600;
