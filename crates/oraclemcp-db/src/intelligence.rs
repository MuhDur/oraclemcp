//! Tier-1 PL/SQL intelligence — the live-dictionary tools (plan §9.3; bead
//! P1-5): `schema_inspect`, `get_ddl`, compile-error retrieval, source search,
//! `explain_plan`, and safe sampling. These are pure Oracle **dictionary**
//! queries (`ALL_*` / `DBMS_METADATA` / `DBMS_XPLAN`) — engine-free, so they
//! live here. The offline dep-graph cross-check and the `CatalogSnapshot`
//! capture that feed the analysis engine are the engine-side wiring (they use
//! `plsql-catalog` / `plsql-engine` from the consumer side).
//!
//! Values are **bound** wherever Oracle allows it; the few unavoidable
//! identifier positions (schema/table/type in `DBMS_METADATA`, the sampled
//! table) are validated as simple identifiers, never interpolated raw.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use asupersync::Cx;

use crate::connection::OracleConnection;
use crate::error::DbError;
use crate::query::QueryResponse;
use crate::types::{OracleBind, OracleCell, OracleRow};
use serde::{Deserialize, Serialize};

/// A simple unquoted Oracle identifier (≤ 30 chars). Rejects injection.
#[must_use]
pub fn is_simple_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '#'))
        && !s.is_empty()
        && s.len() <= 30
}

/// The `DBMS_METADATA` object types we expose (validated allowlist).
const DDL_OBJECT_TYPES: &[&str] = &[
    "TABLE",
    "VIEW",
    "PACKAGE",
    "PACKAGE_BODY",
    "PROCEDURE",
    "FUNCTION",
    "TRIGGER",
    "TYPE",
    "TYPE_BODY",
    "SEQUENCE",
    "INDEX",
    "SYNONYM",
];

/// The `ALL_SOURCE.TYPE` values we expose for source retrieval.
const SOURCE_OBJECT_TYPES: &[(&str, &str)] = &[
    ("PACKAGE", "PACKAGE"),
    ("PACKAGE_BODY", "PACKAGE BODY"),
    ("PACKAGE BODY", "PACKAGE BODY"),
    ("PROCEDURE", "PROCEDURE"),
    ("FUNCTION", "FUNCTION"),
    ("TRIGGER", "TRIGGER"),
    ("TYPE", "TYPE"),
    ("TYPE_BODY", "TYPE BODY"),
    ("TYPE BODY", "TYPE BODY"),
];

/// Full source text plus truncation metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceText {
    /// Schema owner.
    pub owner: String,
    /// Object name.
    pub name: String,
    /// Normalized `ALL_SOURCE.TYPE`.
    pub object_type: String,
    /// Concatenated source text.
    pub source: String,
    /// Number of source rows read.
    pub line_count: usize,
    /// Characters in the untruncated source.
    pub char_count: usize,
    /// Whether `source` was truncated to the requested cap.
    pub truncated: bool,
}

/// A single CLOB/NCLOB/text value read by key, with truncation metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LobText {
    /// Schema owner.
    pub owner: String,
    /// Table or view name.
    pub table: String,
    /// CLOB/NCLOB/text column name.
    pub column: String,
    /// Key column used to locate the row.
    pub pk_column: String,
    /// The text value, or `None` when the matched column is SQL NULL.
    pub value: Option<String>,
    /// Characters in the untruncated value. Zero for SQL NULL.
    pub char_count: usize,
    /// Whether `value` was truncated to the requested cap.
    pub truncated: bool,
}

/// Metadata and column/expression details for one index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexDescription {
    /// The `ALL_INDEXES` metadata row, or `None` when the index is not visible.
    pub metadata: Option<OracleRow>,
    /// `ALL_IND_COLUMNS` rows in column position order.
    pub columns: Vec<OracleRow>,
    /// `ALL_IND_EXPRESSIONS` rows for function-based index expressions.
    pub expressions: Vec<OracleRow>,
}

/// Metadata and body for one trigger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TriggerDescription {
    /// The `ALL_TRIGGERS` metadata row, or `None` when the trigger is not visible.
    pub metadata: Option<OracleRow>,
}

/// Metadata/definition and column details for one view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewDescription {
    /// The `ALL_VIEWS` metadata row, or `None` when the view is not visible.
    pub metadata: Option<OracleRow>,
    /// View columns from `ALL_TAB_COLUMNS`.
    pub columns: Vec<OracleRow>,
}

/// Whether `t` is an allowlisted `DBMS_METADATA` object type.
#[must_use]
pub fn is_ddl_object_type(t: &str) -> bool {
    DDL_OBJECT_TYPES.contains(&t.to_ascii_uppercase().as_str())
}

/// Normalize a supported source object type to `ALL_SOURCE.TYPE`.
#[must_use]
pub fn normalize_source_object_type(t: &str) -> Option<&'static str> {
    let ty = t.trim().to_ascii_uppercase();
    SOURCE_OBJECT_TYPES
        .iter()
        .find_map(|(input, normalized)| (*input == ty).then_some(*normalized))
}

/// The detail level for [`search_objects`] (E4). Higher levels add bounded,
/// read-only dictionary detail per object. `summary` deliberately uses the
/// optimizer's `ALL_TABLES.NUM_ROWS` estimate (NOT `COUNT(*)`) so the tool never
/// triggers a full table scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchDetailLevel {
    /// Identifier + object metadata only (owner, name, type, status). The
    /// cheapest level: one `ALL_OBJECTS` query.
    Names,
    /// `names` plus, for tables, the optimizer row-count estimate
    /// (`ALL_TABLES.NUM_ROWS`), column count, last-analyzed/staleness, and the
    /// table/column comments (`ALL_TAB_COMMENTS`). No `COUNT(*)`.
    Summary,
    /// `summary` plus the column list (name/type/nullable) for tables and views.
    Standard,
    /// `standard` plus the object's indexes (name/uniqueness/columns).
    Full,
}

impl SearchDetailLevel {
    /// Parse a caller-supplied detail level, case-insensitively. `None`/empty
    /// defaults to [`SearchDetailLevel::Standard`].
    #[must_use]
    pub fn parse(raw: Option<&str>) -> Option<Self> {
        match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
            None | Some("") | Some("standard") => Some(SearchDetailLevel::Standard),
            Some("names") => Some(SearchDetailLevel::Names),
            Some("summary") => Some(SearchDetailLevel::Summary),
            Some("full") => Some(SearchDetailLevel::Full),
            Some(_) => None,
        }
    }

    /// The wire/string form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SearchDetailLevel::Names => "names",
            SearchDetailLevel::Summary => "summary",
            SearchDetailLevel::Standard => "standard",
            SearchDetailLevel::Full => "full",
        }
    }

    fn at_least_summary(self) -> bool {
        !matches!(self, SearchDetailLevel::Names)
    }

    fn at_least_standard(self) -> bool {
        matches!(self, SearchDetailLevel::Standard | SearchDetailLevel::Full)
    }

    fn is_full(self) -> bool {
        matches!(self, SearchDetailLevel::Full)
    }
}

/// One object returned by [`search_objects`] (E4). The optional fields are
/// populated according to the requested [`SearchDetailLevel`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchObject {
    /// Schema owner (always upper-cased by the dictionary).
    pub owner: String,
    /// Object name, exactly as stored — quoted/case-sensitive identifiers are
    /// preserved verbatim (the dictionary stores the unquoted upper-case name
    /// for ordinary identifiers and the exact case for quoted ones).
    pub object_name: String,
    /// `ALL_OBJECTS.OBJECT_TYPE` (e.g. `TABLE`, `VIEW`, `PACKAGE`).
    pub object_type: String,
    /// `ALL_OBJECTS.STATUS` (`VALID`/`INVALID`).
    pub status: Option<String>,
    /// Summary+ : the optimizer row-count estimate from `ALL_TABLES.NUM_ROWS`.
    /// This is the gathered-statistics estimate, **not** a live `COUNT(*)`, so
    /// it may be stale or `None` (no stats gathered / not a table). See
    /// `row_count_is_estimate` and `stats_stale`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_rows: Option<i64>,
    /// Summary+ : always `true` when `num_rows` is present — the row count is the
    /// optimizer estimate, never an exact live count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub row_count_is_estimate: Option<bool>,
    /// Summary+ : `ALL_TABLES.LAST_ANALYZED`, when stats were last gathered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_analyzed: Option<String>,
    /// Summary+ : `true` when the optimizer marks the table's stats stale
    /// (`ALL_TAB_STATISTICS.STALE_STATS = 'YES'`), so `num_rows` should not be
    /// trusted as current.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats_stale: Option<bool>,
    /// Summary+ : number of columns (`COUNT(*)` over `ALL_TAB_COLUMNS`, a cheap
    /// dictionary count — NOT a data scan).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column_count: Option<i64>,
    /// Summary+ : the object comment from `ALL_TAB_COMMENTS`, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Standard+ : columns (name/type/nullable/comment) for tables and views.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub columns: Option<Vec<SearchColumn>>,
    /// Full : indexes on the object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indexes: Option<Vec<SearchIndex>>,
}

/// One column in a [`SearchObject`] (standard+ detail).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchColumn {
    /// Column name.
    pub name: String,
    /// Oracle data type.
    pub data_type: Option<String>,
    /// `Y`/`N` nullable flag.
    pub nullable: Option<String>,
    /// The column comment from `ALL_COL_COMMENTS`, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// One index in a [`SearchObject`] (full detail).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchIndex {
    /// Index name.
    pub name: String,
    /// `UNIQUE`/`NONUNIQUE`.
    pub uniqueness: Option<String>,
    /// Indexed columns in position order.
    pub columns: Vec<String>,
}

/// E4 unified object search/inspection. Returns objects matching the
/// owner/type/name filters, enriched per `detail` level:
///
/// - **names**: one `ALL_OBJECTS` query, identifiers + metadata only.
/// - **summary**: + the optimizer `ALL_TABLES.NUM_ROWS` estimate (never
///   `COUNT(*)`), column count, last-analyzed + stale-stats, and comments.
/// - **standard**: + the column list.
/// - **full**: + the indexes.
///
/// Owner/type/name filters are all bound. `owner = None` searches every visible
/// schema; a `name_like` is a SQL `LIKE` pattern. Identifier inputs are bound,
/// never interpolated; the per-object enrichment queries also bind owner/name,
/// so quoted/case-sensitive identifiers (which the dictionary stores verbatim)
/// are matched exactly.
pub async fn search_objects(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    object_type: Option<&str>,
    name_like: Option<&str>,
    detail: SearchDetailLevel,
    max_rows: usize,
) -> Result<Vec<SearchObject>, DbError> {
    // The base listing is the same cheap ALL_OBJECTS query schema_inspect uses
    // (owner/type/name bound, row-capped). Quoted identifiers are stored
    // verbatim in the dictionary, so binding the exact owner/name matches them.
    let base = list_objects(cx, conn, owner, object_type, name_like, max_rows).await?;

    let mut results = Vec::with_capacity(base.len());
    for row in &base {
        let owner = row.text("OWNER").unwrap_or_default().to_owned();
        let object_name = row.text("OBJECT_NAME").unwrap_or_default().to_owned();
        let object_type = row.text("OBJECT_TYPE").unwrap_or_default().to_owned();
        let status = row.text("STATUS").map(str::to_owned);

        let mut object = SearchObject {
            owner: owner.clone(),
            object_name: object_name.clone(),
            object_type: object_type.clone(),
            status,
            num_rows: None,
            row_count_is_estimate: None,
            last_analyzed: None,
            stats_stale: None,
            column_count: None,
            comment: None,
            columns: None,
            indexes: None,
        };

        let is_relation = matches!(object_type.as_str(), "TABLE" | "VIEW");

        if detail.at_least_summary() {
            // The object comment (cheap dictionary read for any object type).
            object.comment = object_comment(cx, conn, &owner, &object_name).await?;
            if is_relation {
                // Column count is a dictionary COUNT over ALL_TAB_COLUMNS — a
                // metadata count, never a data scan.
                object.column_count = Some(column_count(cx, conn, &owner, &object_name).await?);
            }
            if object_type == "TABLE" {
                // The row count is the OPTIMIZER estimate from ALL_TABLES.NUM_ROWS
                // (gathered statistics), NOT COUNT(*). It may be NULL (no stats)
                // or stale; we surface both so the estimate is never mistaken for
                // a live count.
                if let Some(stats) = table_stats(cx, conn, &owner, &object_name).await? {
                    object.num_rows = stats.num_rows;
                    object.row_count_is_estimate = stats.num_rows.map(|_| true);
                    object.last_analyzed = stats.last_analyzed;
                }
                object.stats_stale = Some(table_stats_stale(cx, conn, &owner, &object_name).await?);
            }
        }

        if detail.at_least_standard() && is_relation {
            object.columns = Some(search_columns(cx, conn, &owner, &object_name).await?);
        }

        if detail.is_full() && is_relation {
            object.indexes = Some(search_indexes(cx, conn, &owner, &object_name).await?);
        }

        results.push(object);
    }

    Ok(results)
}

/// The optimizer table statistics for one table (E4 summary). Pulls
/// `ALL_TABLES.NUM_ROWS` (the gathered estimate, NOT a live count) and
/// `LAST_ANALYZED`. Returns `None` when the name is not a table in `ALL_TABLES`.
struct TableStats {
    num_rows: Option<i64>,
    last_analyzed: Option<String>,
}

async fn table_stats(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    table: &str,
) -> Result<Option<TableStats>, DbError> {
    // NUM_ROWS is the optimizer's gathered-statistics estimate. We deliberately
    // read it from ALL_TABLES instead of running COUNT(*) so a search never
    // triggers a full table scan on a large table.
    let row = conn
        .query_optional_row(
            cx,
            "SELECT num_rows, TO_CHAR(last_analyzed, 'YYYY-MM-DD\"T\"HH24:MI:SS') AS last_analyzed \
             FROM all_tables WHERE owner = :1 AND table_name = :2",
            &[OracleBind::from(owner), OracleBind::from(table)],
        )
        .await?;
    Ok(row.map(|row| TableStats {
        num_rows: row.parse_i64("NUM_ROWS"),
        last_analyzed: row.text("LAST_ANALYZED").map(str::to_owned),
    }))
}

/// Whether the optimizer marks this table's statistics stale (E4 summary). Reads
/// `ALL_TAB_STATISTICS.STALE_STATS`; absent/unknown is treated as not stale.
async fn table_stats_stale(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    table: &str,
) -> Result<bool, DbError> {
    let row = conn
        .query_optional_row(
            cx,
            "SELECT stale_stats FROM all_tab_statistics \
             WHERE owner = :1 AND table_name = :2 AND object_type = 'TABLE' \
               AND partition_name IS NULL",
            &[OracleBind::from(owner), OracleBind::from(table)],
        )
        .await?;
    Ok(row
        .and_then(|row| {
            row.text("STALE_STATS")
                .map(|s| s.eq_ignore_ascii_case("YES"))
        })
        .unwrap_or(false))
}

/// Cheap dictionary column count (`COUNT(*)` over `ALL_TAB_COLUMNS`). This is a
/// metadata count over the dictionary, not a scan of the table's data.
async fn column_count(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    table: &str,
) -> Result<i64, DbError> {
    let row = conn
        .query_optional_row(
            cx,
            "SELECT COUNT(*) AS column_count FROM all_tab_columns \
             WHERE owner = :1 AND table_name = :2",
            &[OracleBind::from(owner), OracleBind::from(table)],
        )
        .await?;
    Ok(row
        .and_then(|row| row.parse_i64("COLUMN_COUNT"))
        .unwrap_or(0))
}

/// The object comment from `ALL_TAB_COMMENTS` (tables/views), when present.
async fn object_comment(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    object_name: &str,
) -> Result<Option<String>, DbError> {
    let row = conn
        .query_optional_row(
            cx,
            "SELECT comments FROM all_tab_comments \
             WHERE owner = :1 AND table_name = :2",
            &[OracleBind::from(owner), OracleBind::from(object_name)],
        )
        .await?;
    Ok(row.and_then(|row| row.text("COMMENTS").map(str::to_owned)))
}

/// Columns with comments for E4 standard+ detail (`ALL_TAB_COLUMNS` left-joined
/// to `ALL_COL_COMMENTS`).
async fn search_columns(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    table: &str,
) -> Result<Vec<SearchColumn>, DbError> {
    let rows = conn
        .query_rows(
            cx,
            "SELECT c.column_name, c.data_type, c.nullable, cc.comments \
             FROM all_tab_columns c \
             LEFT JOIN all_col_comments cc \
               ON cc.owner = c.owner AND cc.table_name = c.table_name \
              AND cc.column_name = c.column_name \
             WHERE c.owner = :1 AND c.table_name = :2 \
             ORDER BY c.column_id",
            &[OracleBind::from(owner), OracleBind::from(table)],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|row| SearchColumn {
            name: row.text("COLUMN_NAME").unwrap_or_default().to_owned(),
            data_type: row.text("DATA_TYPE").map(str::to_owned),
            nullable: row.text("NULLABLE").map(str::to_owned),
            comment: row.text("COMMENTS").map(str::to_owned),
        })
        .collect())
}

/// Indexes on the object for E4 full detail (`ALL_INDEXES` + `ALL_IND_COLUMNS`).
async fn search_indexes(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    table: &str,
) -> Result<Vec<SearchIndex>, DbError> {
    let index_rows = conn
        .query_rows(
            cx,
            "SELECT index_name, uniqueness FROM all_indexes \
             WHERE table_owner = :1 AND table_name = :2 \
             ORDER BY index_name",
            &[OracleBind::from(owner), OracleBind::from(table)],
        )
        .await?;
    let mut indexes = Vec::with_capacity(index_rows.len());
    for row in &index_rows {
        let name = row.text("INDEX_NAME").unwrap_or_default().to_owned();
        let uniqueness = row.text("UNIQUENESS").map(str::to_owned);
        let column_rows = conn
            .query_rows(
                cx,
                "SELECT column_name FROM all_ind_columns \
                 WHERE index_owner = :1 AND index_name = :2 \
                 ORDER BY column_position",
                &[OracleBind::from(owner), OracleBind::from(name.as_str())],
            )
            .await?;
        let columns = column_rows
            .iter()
            .filter_map(|row| row.text("COLUMN_NAME").map(str::to_owned))
            .collect();
        indexes.push(SearchIndex {
            name,
            uniqueness,
            columns,
        });
    }
    Ok(indexes)
}

/// `schema_inspect`: objects in one schema or all accessible schemas, with
/// optional type/name filters. Owner, type, and name pattern are all bound; a
/// NULL owner means "all accessible schemas".
pub async fn list_objects(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    object_type: Option<&str>,
    name_like: Option<&str>,
    max_rows: usize,
) -> Result<Vec<OracleRow>, DbError> {
    let sql = "SELECT * FROM ( \
                   WITH args AS ( \
                       SELECT :1 owner_filter, :2 type_filter, :3 name_filter FROM dual \
                   ) \
                   SELECT o.owner, o.object_name, o.object_type, o.status, o.last_ddl_time \
                   FROM all_objects o CROSS JOIN args \
                   WHERE (args.owner_filter IS NULL OR o.owner = args.owner_filter) \
                     AND (args.type_filter IS NULL OR o.object_type = args.type_filter) \
                     AND (args.name_filter IS NULL OR o.object_name LIKE args.name_filter) \
                   ORDER BY o.owner, o.object_type, o.object_name \
               ) WHERE ROWNUM <= :4";
    let owner_bind = owner.map_or(OracleBind::Null, |o| {
        OracleBind::from(o.to_ascii_uppercase())
    });
    let type_bind = object_type.map_or(OracleBind::Null, |t| {
        OracleBind::from(t.to_ascii_uppercase())
    });
    let name_like_bind = name_like.map_or(OracleBind::Null, |n| {
        OracleBind::from(n.to_ascii_uppercase())
    });
    conn.query_rows(
        cx,
        sql,
        &[
            owner_bind,
            type_bind,
            name_like_bind,
            OracleBind::from(max_rows as i64),
        ],
    )
    .await
}

/// One object in the bounded `oracle_orient` schema map.
///
/// This intentionally carries only the stable identity triplet from
/// `ALL_OBJECTS`; object-specific detail belongs to the focused dictionary
/// tools rather than the shared orient snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrientSchemaObject {
    /// Schema owner as stored in `ALL_OBJECTS`.
    pub owner: String,
    /// Object name as stored in `ALL_OBJECTS`.
    pub object_name: String,
    /// Oracle object kind from `ALL_OBJECTS.OBJECT_TYPE`.
    pub object_type: String,
}

/// One positional child-to-parent column pairing in an [`OrientForeignKey`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrientForeignKeyColumn {
    /// One-based key-column position in both the child and parent constraints.
    pub position: usize,
    /// Child table column at [`Self::position`].
    pub child_column: String,
    /// Parent key column at [`Self::position`].
    pub parent_column: String,
}

/// One directed foreign-key edge in the bounded `oracle_orient` topology.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrientForeignKey {
    /// Foreign-key constraint name, unique together with [`Self::child_owner`].
    pub constraint_name: String,
    /// Schema that owns the referencing table.
    pub child_owner: String,
    /// Referencing table name.
    pub child_table: String,
    /// Schema that owns the referenced key.
    pub parent_owner: String,
    /// Referenced table name.
    pub parent_table: String,
    /// Child-to-parent column pairings in constraint-position order.
    pub columns: Vec<OrientForeignKeyColumn>,
}

/// Read the bounded schema/type map for `oracle_orient` from `ALL_OBJECTS`.
///
/// The optional owner is normalized to upper case and bound positionally; when
/// it is absent, the map covers all objects visible to the session. Results are
/// deterministically ordered and capped with `ROWNUM`, so callers can safely
/// assemble them into a cacheable snapshot without ever interpolating an
/// identifier.
pub async fn orient_schema(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    max_rows: usize,
) -> Result<Vec<OrientSchemaObject>, DbError> {
    let sql = "SELECT * FROM ( \
                   WITH args AS ( \
                       SELECT :1 owner_filter FROM dual \
                   ) \
                   SELECT o.owner, o.object_name, o.object_type \
                   FROM all_objects o CROSS JOIN args \
                   WHERE args.owner_filter IS NULL OR o.owner = args.owner_filter \
                   ORDER BY o.owner, o.object_type, o.object_name \
               ) WHERE ROWNUM <= :2";
    let owner_bind = owner.map_or(OracleBind::Null, |value| {
        OracleBind::from(value.to_ascii_uppercase())
    });
    let rows = conn
        .query_rows(cx, sql, &[owner_bind, OracleBind::from(max_rows as i64)])
        .await?;

    Ok(rows
        .into_iter()
        .map(|row| OrientSchemaObject {
            owner: row.text("OWNER").unwrap_or_default().to_owned(),
            object_name: row.text("OBJECT_NAME").unwrap_or_default().to_owned(),
            object_type: row.text("OBJECT_TYPE").unwrap_or_default().to_owned(),
        })
        .collect())
}

/// Read bounded child-to-parent foreign-key topology for `oracle_orient`.
///
/// This joins the child `R` constraint to its referenced key and then joins
/// both `ALL_CONS_COLUMNS` projections on their one-based positions. The cap
/// is deliberately applied to foreign-key *constraints* before those column
/// joins, preventing a composite key from being returned with only a prefix of
/// its column pairings. The optional owner is a positional, upper-cased bind;
/// `None` covers every foreign key visible to the session.
pub async fn orient_fks(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    max_rows: usize,
) -> Result<Vec<OrientForeignKey>, DbError> {
    // Keep the outermost statement a SELECT. Besides matching the generated
    // read-path contract, the thin driver recognizes this shape consistently
    // when the dictionary query contains a CTE.
    let sql = "SELECT * FROM ( \
               WITH args AS ( \
                   SELECT :1 owner_filter FROM dual \
               ), selected_foreign_keys AS ( \
                   SELECT * FROM ( \
                       SELECT child.owner AS child_owner, \
                              child.table_name AS child_table, \
                              child.constraint_name, \
                              child.r_owner AS parent_owner, \
                              child.r_constraint_name AS parent_constraint_name \
                       FROM all_constraints child CROSS JOIN args \
                       WHERE child.constraint_type = 'R' \
                         AND (args.owner_filter IS NULL OR child.owner = args.owner_filter) \
                       ORDER BY child.owner, child.table_name, child.constraint_name \
                   ) WHERE ROWNUM <= :2 \
               ) \
               SELECT foreign_key.child_owner, foreign_key.child_table, \
                      foreign_key.constraint_name, foreign_key.parent_owner, \
                      parent.table_name AS parent_table, \
                      child_columns.column_name AS child_column, \
                      parent_columns.column_name AS parent_column, \
                      child_columns.position AS column_position \
               FROM selected_foreign_keys foreign_key \
               JOIN all_constraints parent \
                 ON parent.owner = foreign_key.parent_owner \
                AND parent.constraint_name = foreign_key.parent_constraint_name \
               JOIN all_cons_columns child_columns \
                 ON child_columns.owner = foreign_key.child_owner \
                AND child_columns.constraint_name = foreign_key.constraint_name \
               JOIN all_cons_columns parent_columns \
                 ON parent_columns.owner = parent.owner \
                AND parent_columns.constraint_name = parent.constraint_name \
                AND parent_columns.position = child_columns.position \
               ORDER BY foreign_key.child_owner, foreign_key.child_table, \
                        foreign_key.constraint_name, child_columns.position \
               )";
    let owner_bind = owner.map_or(OracleBind::Null, |value| {
        OracleBind::from(value.to_ascii_uppercase())
    });
    let rows = conn
        .query_rows(cx, sql, &[owner_bind, OracleBind::from(max_rows as i64)])
        .await?;

    let mut foreign_keys: Vec<OrientForeignKey> = Vec::new();
    for row in rows {
        let constraint_name = row.text("CONSTRAINT_NAME").unwrap_or_default().to_owned();
        let child_owner = row.text("CHILD_OWNER").unwrap_or_default().to_owned();
        let child_table = row.text("CHILD_TABLE").unwrap_or_default().to_owned();
        let parent_owner = row.text("PARENT_OWNER").unwrap_or_default().to_owned();
        let parent_table = row.text("PARENT_TABLE").unwrap_or_default().to_owned();
        let column = OrientForeignKeyColumn {
            position: row
                .parse_i64("COLUMN_POSITION")
                .and_then(|position| usize::try_from(position).ok())
                .unwrap_or_default(),
            child_column: row.text("CHILD_COLUMN").unwrap_or_default().to_owned(),
            parent_column: row.text("PARENT_COLUMN").unwrap_or_default().to_owned(),
        };

        if let Some(existing) = foreign_keys.last_mut()
            && existing.constraint_name == constraint_name
            && existing.child_owner == child_owner
        {
            existing.columns.push(column);
            continue;
        }

        foreign_keys.push(OrientForeignKey {
            constraint_name,
            child_owner,
            child_table,
            parent_owner,
            parent_table,
            columns: vec![column],
        });
    }

    Ok(foreign_keys)
}

/// List schemas that own objects visible to this session, optionally filtered
/// by a SQL `LIKE` pattern.
pub async fn list_schemas(
    cx: &Cx,
    conn: &dyn OracleConnection,
    name_like: Option<&str>,
    max_rows: usize,
) -> Result<Vec<OracleRow>, DbError> {
    let sql = "SELECT * FROM ( \
                   WITH args AS ( \
                       SELECT :1 name_filter FROM dual \
                   ) \
                   SELECT o.owner AS schema_name, COUNT(*) AS object_count \
                   FROM all_objects o CROSS JOIN args \
                   WHERE args.name_filter IS NULL OR o.owner LIKE args.name_filter \
                   GROUP BY o.owner \
                   ORDER BY o.owner \
               ) WHERE ROWNUM <= :2";
    let name_like_bind = name_like.map_or(OracleBind::Null, |n| {
        OracleBind::from(n.to_ascii_uppercase())
    });
    conn.query_rows(
        cx,
        sql,
        &[name_like_bind, OracleBind::from(max_rows as i64)],
    )
    .await
}

/// One direct dependent of a target object, read from `ALL_DEPENDENCIES`.
///
/// A dependent is an object that *references* the target (the target is its
/// `REFERENCED_*`). This is the "blast radius" shape used by the DDL previews:
/// who a CREATE OR REPLACE of the target might touch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DependentObject {
    /// Owner (schema) of the dependent object.
    pub owner: String,
    /// Name of the dependent object.
    pub name: String,
    /// `ALL_DEPENDENCIES.TYPE` of the dependent (e.g. `VIEW`, `PROCEDURE`).
    pub object_type: String,
}

impl DependentObject {
    /// Whether replacing the referenced object typically marks this dependent
    /// `INVALID`. Best-effort static heuristic: PL/SQL stored code (procedures,
    /// functions, packages and their bodies, types and their bodies, triggers),
    /// views, and materialized views are recompilation-dependent on their
    /// referenced objects; tables, sequences, and synonyms are not invalidated
    /// by a source replace. This is a preview estimate, not a guarantee — Oracle
    /// may fine-grain-invalidate differently at apply time.
    #[must_use]
    pub fn is_invalidatable(&self) -> bool {
        matches!(
            self.object_type.to_ascii_uppercase().as_str(),
            "VIEW"
                | "PROCEDURE"
                | "FUNCTION"
                | "PACKAGE"
                | "PACKAGE BODY"
                | "TYPE"
                | "TYPE BODY"
                | "TRIGGER"
                | "MATERIALIZED VIEW"
        )
    }
}

/// Outcome of a direct-dependents (blast-radius) probe over `ALL_DEPENDENCIES`.
///
/// The probe never surfaces an error to its caller: the dependents block is a
/// purely additive, observational enrichment of a DDL preview, so a privilege
/// gap or dictionary error degrades to [`DependentsProbe::Unavailable`] rather
/// than failing the preview.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DependentsProbe {
    /// The dictionary query ran. `direct` holds the one-hop dependents visible
    /// to this session (possibly empty).
    Available {
        /// Direct (one-hop) dependents referencing the target object.
        direct: Vec<DependentObject>,
    },
    /// `ALL_DEPENDENCIES` was not accessible (privilege gap or dictionary
    /// error); the preview proceeds without the dependents block.
    Unavailable {
        /// Sanitized reason the probe degraded.
        reason: String,
    },
}

/// Build a [`DependentObject`] from one `ALL_DEPENDENCIES` row, skipping rows
/// missing the owner/name/type triple. Pure — factored out for offline tests.
#[must_use]
pub fn dependent_from_row(row: &OracleRow) -> Option<DependentObject> {
    let owner = row.text("OWNER")?.trim();
    let name = row.text("NAME")?.trim();
    let object_type = row.text("TYPE")?.trim();
    if owner.is_empty() || name.is_empty() || object_type.is_empty() {
        return None;
    }
    Some(DependentObject {
        owner: owner.to_owned(),
        name: name.to_owned(),
        object_type: object_type.to_owned(),
    })
}

/// Probe the *direct* (one-hop) dependents of a target object via
/// `ALL_DEPENDENCIES` — the objects that reference `owner.name` and would be
/// candidates for invalidation if it were replaced.
///
/// This is a **read-only** dictionary query, gated by nothing new: it never
/// touches the SQL classifier, the DDL gate, or the operating-level ladder. It
/// binds owner/name (never interpolates) and self-excludes the target. Only
/// direct dependents are returned; the transitive closure and dynamic-SQL
/// (`EXECUTE IMMEDIATE`) references are intentionally out of scope, and objects
/// outside this session's dictionary visibility are not shown. On any driver /
/// privilege error the probe degrades to [`DependentsProbe::Unavailable`] so a
/// preview is never failed by a missing-privilege dependents lookup.
pub async fn probe_dependents(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
    max_rows: usize,
) -> DependentsProbe {
    // Mirror the `list_objects` idiom: bind each value once through a `WITH
    // args` CTE and reference it by alias, so a repeated predicate does not
    // depend on repeating a positional placeholder.
    let sql = "SELECT * FROM ( \
                   WITH args AS ( \
                       SELECT :1 owner_filter, :2 name_filter FROM dual \
                   ) \
                   SELECT DISTINCT d.owner, d.name, d.type \
                   FROM all_dependencies d CROSS JOIN args \
                   WHERE d.referenced_owner = args.owner_filter \
                     AND d.referenced_name = args.name_filter \
                     AND NOT (d.owner = args.owner_filter AND d.name = args.name_filter) \
                   ORDER BY d.owner, d.type, d.name \
               ) WHERE ROWNUM <= :3";
    let binds = [
        OracleBind::from(owner.to_ascii_uppercase()),
        OracleBind::from(name.to_ascii_uppercase()),
        OracleBind::from(max_rows as i64),
    ];
    match conn.query_rows(cx, sql, &binds).await {
        Ok(rows) => DependentsProbe::Available {
            direct: rows.iter().filter_map(dependent_from_row).collect(),
        },
        Err(err) => DependentsProbe::Unavailable {
            reason: format!("ALL_DEPENDENCIES not accessible: {err}"),
        },
    }
}

/// Describe one index's metadata, indexed columns, and function-based
/// expressions. Owner + index name are bound.
pub async fn describe_index(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    index_name: &str,
) -> Result<IndexDescription, DbError> {
    let owner = owner.to_ascii_uppercase();
    let index_name = index_name.to_ascii_uppercase();
    let binds = [
        OracleBind::from(owner.clone()),
        OracleBind::from(index_name.clone()),
    ];

    let metadata = conn
        .query_optional_row(
            cx,
            "SELECT owner, index_name, index_type, table_owner, table_name, \
                uniqueness, status, partitioned, temporary, generated, degree \
         FROM all_indexes \
         WHERE owner = :1 AND index_name = :2",
            &binds,
        )
        .await?;
    let columns = conn
        .query_rows(
            cx,
            "SELECT column_position, column_name, descend, column_length, char_length \
         FROM all_ind_columns \
         WHERE index_owner = :1 AND index_name = :2 \
         ORDER BY column_position",
            &binds,
        )
        .await?;
    let expressions = conn
        .query_rows(
            cx,
            "SELECT column_position, column_expression \
         FROM all_ind_expressions \
         WHERE index_owner = :1 AND index_name = :2 \
         ORDER BY column_position",
            &binds,
        )
        .await?;

    Ok(IndexDescription {
        metadata,
        columns,
        expressions,
    })
}

/// Describe one trigger's timing/event/status and body. Owner + trigger name
/// are bound.
pub async fn describe_trigger(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    trigger_name: &str,
) -> Result<TriggerDescription, DbError> {
    let metadata = conn
        .query_optional_row(
            cx,
            "SELECT owner, trigger_name, trigger_type, triggering_event, \
                table_owner, table_name, status, when_clause, description, trigger_body \
         FROM all_triggers \
         WHERE owner = :1 AND trigger_name = :2",
            &[
                OracleBind::from(owner.to_ascii_uppercase()),
                OracleBind::from(trigger_name.to_ascii_uppercase()),
            ],
        )
        .await?;
    Ok(TriggerDescription { metadata })
}

/// Describe one view's definition metadata and columns. Owner + view name are
/// bound.
pub async fn describe_view(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    view_name: &str,
) -> Result<ViewDescription, DbError> {
    let owner = owner.to_ascii_uppercase();
    let view_name = view_name.to_ascii_uppercase();
    let binds = [
        OracleBind::from(owner.clone()),
        OracleBind::from(view_name.clone()),
    ];

    let metadata = conn
        .query_optional_row(
            cx,
            "SELECT owner, view_name, text_length, text \
         FROM all_views \
         WHERE owner = :1 AND view_name = :2",
            &binds,
        )
        .await?;
    let columns = describe_columns(cx, conn, &owner, &view_name).await?;
    Ok(ViewDescription { metadata, columns })
}

/// Columns of a table/view (owner + name bound).
pub async fn describe_columns(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    table: &str,
) -> Result<Vec<OracleRow>, DbError> {
    let sql = "SELECT column_name, data_type, data_length, nullable, data_default \
               FROM all_tab_columns WHERE owner = :1 AND table_name = :2 \
               ORDER BY column_id";
    conn.query_rows(
        cx,
        sql,
        &[
            OracleBind::from(owner.to_ascii_uppercase()),
            OracleBind::from(table.to_ascii_uppercase()),
        ],
    )
    .await
}

/// Constraint metadata for a table/view (owner + name bound).
pub async fn describe_constraints(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    table: &str,
) -> Result<Vec<OracleRow>, DbError> {
    let sql = "SELECT c.constraint_name, c.constraint_type, c.status, \
                      c.deferrable, c.deferred, c.validated, c.generated, \
                      c.r_owner, c.r_constraint_name, cc.column_name, cc.position \
               FROM all_constraints c \
               LEFT JOIN all_cons_columns cc \
                 ON cc.owner = c.owner \
                AND cc.constraint_name = c.constraint_name \
                AND cc.table_name = c.table_name \
               WHERE c.owner = :1 AND c.table_name = :2 \
               ORDER BY c.constraint_name, cc.position";
    conn.query_rows(
        cx,
        sql,
        &[
            OracleBind::from(owner.to_ascii_uppercase()),
            OracleBind::from(table.to_ascii_uppercase()),
        ],
    )
    .await
}

/// `get_ddl`: `DBMS_METADATA.GET_DDL` for an object. `object_type` is validated
/// against the allowlist (it cannot be bound); name + owner are bound.
pub async fn get_ddl(
    cx: &Cx,
    conn: &dyn OracleConnection,
    object_type: &str,
    owner: &str,
    name: &str,
) -> Result<Option<String>, DbError> {
    if !is_ddl_object_type(object_type) {
        return Err(DbError::Query(format!(
            "unsupported DDL object type: {object_type:?}"
        )));
    }
    // DBMS_METADATA returns a CLOB. Request a VARCHAR2 slice until the thin
    // driver exposes the LOB APIs needed for streaming full metadata text.
    let sql = format!(
        "SELECT DBMS_LOB.SUBSTR(DBMS_METADATA.GET_DDL('{}', :1, :2), 4000, 1) AS ddl FROM dual",
        object_type.to_ascii_uppercase()
    );
    let rows = conn
        .query_rows(
            cx,
            &sql,
            &[
                OracleBind::from(name.to_ascii_uppercase()),
                OracleBind::from(owner.to_ascii_uppercase()),
            ],
        )
        .await?;
    Ok(rows.first().and_then(|r| r.text("DDL").map(str::to_owned)))
}

/// Compile errors for an owner, optionally narrowed to one object (`ALL_ERRORS`;
/// owner + name bound).
pub async fn compile_errors(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: Option<&str>,
) -> Result<Vec<OracleRow>, DbError> {
    let sql = "SELECT name, type, line, position, text, attribute \
               FROM all_errors \
               WHERE owner = :1 AND (:2 IS NULL OR name = :2) \
               ORDER BY name, type, sequence";
    let name_bind = name.map_or(OracleBind::Null, |n| {
        OracleBind::from(n.to_ascii_uppercase())
    });
    conn.query_rows(
        cx,
        sql,
        &[OracleBind::from(owner.to_ascii_uppercase()), name_bind],
    )
    .await
}

/// Full-text search across `ALL_SOURCE`, optionally owner/type/name-filtered
/// and row-capped. NULL owner means all visible schemas.
pub async fn search_source(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    needle: &str,
    object_type: Option<&str>,
    name_like: Option<&str>,
    max_rows: usize,
) -> Result<Vec<OracleRow>, DbError> {
    let source_type = match object_type {
        Some(t) => Some(
            normalize_source_object_type(t)
                .ok_or_else(|| DbError::Query(format!("unsupported source object type: {t:?}")))?,
        ),
        None => None,
    };
    let sql = "SELECT * FROM ( \
                   WITH args AS ( \
                       SELECT :1 owner_filter, :2 type_filter, :3 name_filter, :4 needle FROM dual \
                   ) \
                   SELECT s.owner, s.name, s.type, s.line, s.text \
                   FROM all_source s CROSS JOIN args \
                   WHERE (args.owner_filter IS NULL OR s.owner = args.owner_filter) \
                     AND (args.type_filter IS NULL OR s.type = args.type_filter) \
                     AND (args.name_filter IS NULL OR s.name LIKE args.name_filter) \
                     AND UPPER(s.text) LIKE UPPER('%' || args.needle || '%') \
                   ORDER BY s.owner, s.name, s.type, s.line \
               ) WHERE ROWNUM <= :5";
    let owner_bind = owner.map_or(OracleBind::Null, |o| {
        OracleBind::from(o.to_ascii_uppercase())
    });
    let type_bind = source_type.map_or(OracleBind::Null, OracleBind::from);
    let name_like_bind = name_like.map_or(OracleBind::Null, |n| {
        OracleBind::from(n.to_ascii_uppercase())
    });
    conn.query_rows(
        cx,
        sql,
        &[
            owner_bind,
            type_bind,
            name_like_bind,
            OracleBind::from(needle),
            OracleBind::from(max_rows as i64),
        ],
    )
    .await
}

/// Full source text for one object from `ALL_SOURCE`, capped by characters.
pub async fn get_source(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
    object_type: &str,
    max_chars: usize,
) -> Result<SourceText, DbError> {
    let Some(source_type) = normalize_source_object_type(object_type) else {
        return Err(DbError::Query(format!(
            "unsupported source object type: {object_type:?}"
        )));
    };
    let sql = "SELECT line, text FROM all_source \
               WHERE owner = :1 AND name = :2 AND type = :3 \
               ORDER BY line";
    let rows = conn
        .query_rows(
            cx,
            sql,
            &[
                OracleBind::from(owner.to_ascii_uppercase()),
                OracleBind::from(name.to_ascii_uppercase()),
                OracleBind::from(source_type),
            ],
        )
        .await?;

    let cap = max_chars.max(1);
    let mut source = String::new();
    let mut char_count = 0usize;
    let mut truncated = false;
    for row in &rows {
        let text = row.text("TEXT").unwrap_or_default();
        let text_chars = text.chars().count();
        if !truncated && char_count.saturating_add(text_chars) <= cap {
            source.push_str(text);
        } else if !truncated {
            let remaining = cap.saturating_sub(char_count);
            source.extend(text.chars().take(remaining));
            truncated = true;
        }
        char_count = char_count.saturating_add(text_chars);
    }

    Ok(SourceText {
        owner: owner.to_ascii_uppercase(),
        name: name.to_ascii_uppercase(),
        object_type: source_type.to_owned(),
        source,
        line_count: rows.len(),
        char_count,
        truncated,
    })
}

/// List visible `ALL_SOURCE.TYPE` variants for one object name.
pub async fn list_source_types(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
) -> Result<Vec<String>, DbError> {
    let sql = "SELECT type \
               FROM ( \
                   SELECT DISTINCT type, \
                          CASE type \
                              WHEN 'PACKAGE' THEN 1 \
                              WHEN 'PACKAGE BODY' THEN 2 \
                              WHEN 'TYPE' THEN 3 \
                              WHEN 'TYPE BODY' THEN 4 \
                              WHEN 'PROCEDURE' THEN 5 \
                              WHEN 'FUNCTION' THEN 6 \
                              WHEN 'TRIGGER' THEN 7 \
                              ELSE 99 \
                          END sort_key \
                   FROM all_source \
                   WHERE owner = :1 AND name = :2 \
               ) \
               ORDER BY sort_key, type";
    let rows = conn
        .query_rows(
            cx,
            sql,
            &[
                OracleBind::from(owner.to_ascii_uppercase()),
                OracleBind::from(name.to_ascii_uppercase()),
            ],
        )
        .await?;
    let mut types = Vec::new();
    for row in rows {
        if let Some(source_type) = row.text("TYPE").and_then(normalize_source_object_type)
            && !types.iter().any(|t| t == source_type)
        {
            types.push(source_type.to_owned());
        }
    }
    Ok(types)
}

/// Full source text for every visible source type for one object name.
pub async fn get_sources_by_name(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
    max_chars: usize,
) -> Result<Vec<SourceText>, DbError> {
    let mut out = Vec::new();
    for source_type in list_source_types(cx, conn, owner, name).await? {
        out.push(get_source(cx, conn, owner, name, &source_type, max_chars).await?);
    }
    Ok(out)
}

/// Safe data sampling: the first `n` rows of a table. Schema/table are validated
/// identifiers (they cannot be bound); `n` is bound.
pub async fn sample_rows(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    table: &str,
    n: usize,
) -> Result<Vec<OracleRow>, DbError> {
    if !is_simple_identifier(owner) || !is_simple_identifier(table) {
        return Err(DbError::Query(format!(
            "invalid object name: {owner}.{table}"
        )));
    }
    let sql = format!(
        "SELECT * FROM (SELECT * FROM {}.{}) WHERE ROWNUM <= :1",
        owner.to_ascii_uppercase(),
        table.to_ascii_uppercase()
    );
    conn.query_rows(cx, &sql, &[OracleBind::from(n as i64)])
        .await
}

/// Ordered primary-key column names for one visible table, or an empty list
/// when the relation has no primary key visible to the current user. This is a
/// dictionary read only; owner/table are bound and normalized before lookup.
pub async fn primary_key_columns(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    table: &str,
) -> Result<Vec<String>, DbError> {
    let rows = conn
        .query_rows(
            cx,
            "SELECT cc.column_name \
             FROM all_constraints c \
             JOIN all_cons_columns cc \
               ON cc.owner = c.owner \
              AND cc.constraint_name = c.constraint_name \
              AND cc.table_name = c.table_name \
             WHERE c.owner = :1 \
               AND c.table_name = :2 \
               AND c.constraint_type = 'P' \
             ORDER BY cc.position",
            &[
                OracleBind::String(owner.to_ascii_uppercase()),
                OracleBind::String(table.to_ascii_uppercase()),
            ],
        )
        .await?;
    Ok(rows
        .iter()
        .filter_map(|row| row.text("COLUMN_NAME").map(str::to_owned))
        .collect())
}

/// Semantic diff between two serialized query pages. With key columns, rows are
/// aligned by that key and value changes are reported as `changed`; without key
/// columns, rows are treated as a multiset and only add/remove can be proven.
///
/// A *side* is one page of the same proven read. The two sides may differ in
/// time (the same database at two SCNs) or in space (two databases in the
/// fleet); the alignment maths is identical either way, so this type carries the
/// side provenance in [`QueryDiff::source_a`] / [`QueryDiff::source_b`] rather
/// than assuming an SCN pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryDiff {
    /// Column names in the compared query shape.
    pub columns: Vec<String>,
    /// Whether `changed` was computed by row key.
    pub keyed: bool,
    /// Key columns used for row alignment, in caller/primary-key order.
    pub key_columns: Vec<String>,
    /// Rows present on side B but not on side A.
    pub added: Vec<serde_json::Value>,
    /// Rows present on side A but not on side B.
    pub removed: Vec<serde_json::Value>,
    /// Key-aligned rows whose non-key payload differs between the two sides.
    pub changed: Vec<QueryDiffChange>,
    /// Rows compared from the first page.
    pub row_count_a: usize,
    /// Rows compared from the second page.
    pub row_count_b: usize,
    /// True when either input page was truncated before all rows were compared.
    pub truncated: bool,
    /// Where side A was read from. Empty unless the caller attaches it with
    /// [`QueryDiff::with_sources`].
    #[serde(default, skip_serializing_if = "QueryDiffSource::is_empty")]
    pub source_a: QueryDiffSource,
    /// Where side B was read from.
    #[serde(default, skip_serializing_if = "QueryDiffSource::is_empty")]
    pub source_b: QueryDiffSource,
}

impl QueryDiff {
    /// Attach the provenance of each compared side. The diff maths never needs
    /// this, but a cross-database delta is not interpretable without it.
    #[must_use]
    pub fn with_sources(mut self, source_a: QueryDiffSource, source_b: QueryDiffSource) -> Self {
        self.source_a = source_a;
        self.source_b = source_b;
        self
    }
}

/// Where one compared side of a [`QueryDiff`] was read from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryDiffSource {
    /// Connection profile the side was read from, for a cross-database diff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// System change number the side was read as of, when it was a flashback
    /// read rather than a read of the current committed state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scn: Option<u64>,
}

impl QueryDiffSource {
    /// A side read from `profile` at its current committed state.
    #[must_use]
    pub fn profile(profile: impl Into<String>) -> Self {
        Self {
            profile: Some(profile.into()),
            scn: None,
        }
    }

    /// A side read as of `scn`.
    #[must_use]
    pub fn scn(scn: u64) -> Self {
        Self {
            profile: None,
            scn: Some(scn),
        }
    }

    /// Pin this side to an SCN as well as a profile.
    #[must_use]
    pub fn at_scn(mut self, scn: Option<u64>) -> Self {
        self.scn = scn;
        self
    }

    #[must_use]
    fn is_empty(&self) -> bool {
        self.profile.is_none() && self.scn.is_none()
    }
}

/// One key-aligned row whose payload differs between the two compared sides.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryDiffChange {
    /// The key object that aligned the two rows.
    pub key: serde_json::Value,
    /// Row on side A.
    pub before: serde_json::Value,
    /// Row on side B.
    pub after: serde_json::Value,
}

/// Why a serialized-row diff could not be computed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum QueryDiffError {
    /// A caller-supplied or inferred key column was not present in every row.
    MissingKeyColumn {
        /// Missing result-column name.
        column: String,
    },
}

impl fmt::Display for QueryDiffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueryDiffError::MissingKeyColumn { column } => {
                write!(f, "diff key column `{column}` is not present in every row")
            }
        }
    }
}

impl std::error::Error for QueryDiffError {}

#[must_use]
fn response_columns(a: &QueryResponse, b: &QueryResponse) -> Vec<String> {
    if !b.columns.is_empty() {
        b.columns.clone()
    } else {
        a.columns.clone()
    }
}

fn row_cell<'a>(row: &'a serde_json::Value, column: &str) -> Option<&'a serde_json::Value> {
    let object = row.as_object()?;
    object.get(column).or_else(|| {
        object
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(column))
            .map(|(_, v)| v)
    })
}

fn stable_json(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_owned())
}

fn row_signature(row: &serde_json::Value, columns: &[String]) -> String {
    let projection = serde_json::Value::Array(
        columns
            .iter()
            .map(|column| {
                serde_json::json!([
                    column,
                    row_cell(row, column)
                        .cloned()
                        .unwrap_or(serde_json::Value::Null)
                ])
            })
            .collect(),
    );
    stable_json(&projection)
}

fn key_value(
    row: &serde_json::Value,
    key_columns: &[String],
) -> Result<serde_json::Value, QueryDiffError> {
    let mut key = serde_json::Map::new();
    for column in key_columns {
        let value = row
            .as_object()
            .and_then(|_| row_cell(row, column))
            .cloned()
            .ok_or_else(|| QueryDiffError::MissingKeyColumn {
                column: column.clone(),
            })?;
        key.insert(column.clone(), value);
    }
    Ok(serde_json::Value::Object(key))
}

fn push_multiset_row(
    rows: &mut BTreeMap<String, VecDeque<serde_json::Value>>,
    row: &serde_json::Value,
    columns: &[String],
) {
    rows.entry(row_signature(row, columns))
        .or_default()
        .push_back(row.clone());
}

fn push_keyed_row(
    rows: &mut BTreeMap<String, VecDeque<(serde_json::Value, serde_json::Value)>>,
    row: &serde_json::Value,
    key_columns: &[String],
) -> Result<(), QueryDiffError> {
    let key = key_value(row, key_columns)?;
    rows.entry(stable_json(&key))
        .or_default()
        .push_back((key, row.clone()));
    Ok(())
}

/// Diff two serialized query responses. Keyed mode aligns by `key_columns` and
/// emits row-level changes; keyless mode treats each side as a multiset of full
/// rows and emits add/remove only.
pub fn diff_query_responses(
    a: &QueryResponse,
    b: &QueryResponse,
    key_columns: &[String],
) -> Result<QueryDiff, QueryDiffError> {
    let columns = response_columns(a, b);
    let keyed = !key_columns.is_empty();
    if !keyed {
        let mut after = BTreeMap::<String, VecDeque<serde_json::Value>>::new();
        for row in &b.rows {
            push_multiset_row(&mut after, row, &columns);
        }

        let mut removed = Vec::new();
        for row in &a.rows {
            let signature = row_signature(row, &columns);
            match after.get_mut(&signature).and_then(VecDeque::pop_front) {
                Some(_) => {}
                None => removed.push(row.clone()),
            }
        }
        let added = after.into_values().flat_map(VecDeque::into_iter).collect();
        return Ok(QueryDiff {
            columns,
            keyed: false,
            key_columns: Vec::new(),
            added,
            removed,
            changed: Vec::new(),
            row_count_a: a.row_count,
            row_count_b: b.row_count,
            truncated: a.truncated || b.truncated,
            source_a: QueryDiffSource::default(),
            source_b: QueryDiffSource::default(),
        });
    }

    let mut after = BTreeMap::<String, VecDeque<(serde_json::Value, serde_json::Value)>>::new();
    for row in &b.rows {
        push_keyed_row(&mut after, row, key_columns)?;
    }

    let mut removed = Vec::new();
    let mut changed = Vec::new();
    for before in &a.rows {
        let key = key_value(before, key_columns)?;
        match after
            .get_mut(&stable_json(&key))
            .and_then(VecDeque::pop_front)
        {
            Some((_, after_row))
                if row_signature(before, &columns) != row_signature(&after_row, &columns) =>
            {
                changed.push(QueryDiffChange {
                    key,
                    before: before.clone(),
                    after: after_row,
                });
            }
            Some(_) => {}
            None => removed.push(before.clone()),
        }
    }
    let added = after
        .into_values()
        .flat_map(VecDeque::into_iter)
        .map(|(_, row)| row)
        .collect();

    Ok(QueryDiff {
        columns,
        keyed: true,
        key_columns: key_columns.to_vec(),
        added,
        removed,
        changed,
        row_count_a: a.row_count,
        row_count_b: b.row_count,
        truncated: a.truncated || b.truncated,
        source_a: QueryDiffSource::default(),
        source_b: QueryDiffSource::default(),
    })
}

/// Read one CLOB/NCLOB/text value by an equality key, capped by characters.
///
/// The identifiers cannot be bound in Oracle SQL, so each identifier is
/// restricted to a simple unquoted Oracle identifier before interpolation. The
/// key value is always bound.
#[allow(clippy::too_many_arguments)]
pub async fn read_lob(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    table: &str,
    clob_column: &str,
    pk_column: &str,
    pk_value: &str,
    max_chars: usize,
) -> Result<Option<LobText>, DbError> {
    for (label, value) in [
        ("owner", owner),
        ("table", table),
        ("clob_column", clob_column),
        ("pk_column", pk_column),
    ] {
        if !is_simple_identifier(value) {
            return Err(DbError::Query(format!(
                "invalid {label} identifier: {value:?}"
            )));
        }
    }

    let owner = owner.to_ascii_uppercase();
    let table = table.to_ascii_uppercase();
    let clob_column = clob_column.to_ascii_uppercase();
    let pk_column = pk_column.to_ascii_uppercase();
    let sql = format!(
        "SELECT {clob_column} AS LOB_VALUE \
         FROM {owner}.{table} \
         WHERE {pk_column} = :1 \
         FETCH FIRST 1 ROW ONLY"
    );
    let rows = conn
        .query_rows(cx, &sql, &[OracleBind::from(pk_value)])
        .await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };

    let cap = max_chars.max(1);
    let full_value = row.text("LOB_VALUE");
    let char_count = full_value.map(|s| s.chars().count()).unwrap_or(0);
    let truncated = char_count > cap;
    let value = full_value.map(|s| {
        if truncated {
            s.chars().take(cap).collect()
        } else {
            s.to_owned()
        }
    });

    Ok(Some(LobText {
        owner,
        table,
        column: clob_column,
        pk_column,
        value,
        char_count,
        truncated,
    }))
}

/// `explain_plan`: on a primary, `EXPLAIN PLAN FOR <sql>` writes `PLAN_TABLE`
/// and then reads `DBMS_XPLAN.DISPLAY`; on a read-only standby it is refused
/// (route to `DISPLAY_CURSOR`). `sql` must already have passed the classifier
/// as a vetted SELECT, and callers must separately gate the diagnostic
/// `PLAN_TABLE` write.
pub async fn explain_plan(
    cx: &Cx,
    conn: &dyn OracleConnection,
    sql: &str,
    read_only_standby: bool,
) -> Result<Vec<OracleRow>, DbError> {
    if read_only_standby {
        return Err(DbError::Query(
            "EXPLAIN PLAN writes PLAN_TABLE and is disabled on a read-only standby; \
             use DBMS_XPLAN.DISPLAY_CURSOR against an existing cursor"
                .to_owned(),
        ));
    }
    // The inner SQL is appended (not bindable in EXPLAIN PLAN FOR); the caller
    // guarantees it is a classifier-vetted SELECT.
    conn.execute(cx, &format!("EXPLAIN PLAN FOR {sql}"), &[])
        .await?;
    conn.query_rows(
        cx,
        "SELECT plan_table_output FROM TABLE(DBMS_XPLAN.DISPLAY)",
        &[],
    )
    .await
}

/// Reminder folded into every [`PlanCostEstimate`]: these numbers are the
/// Oracle optimizer's **relative** estimates used to rank candidate plans, not
/// wall-clock timings and not a runtime guarantee.
pub const PLAN_COST_ESTIMATE_NOTE: &str = "cost and cardinality are the Oracle \
optimizer's RELATIVE estimates for ranking candidate plans (derived from the \
current statistics), not wall-clock time and not a guarantee of runtime; any of \
cost/cardinality/bytes may be null when statistics are absent or under RULE-mode \
optimization";

/// The optimizer's estimates for a single `PLAN_TABLE` line.
///
/// `cost`, `cardinality`, and `bytes` are `NUMBER` columns that are `NULL` when
/// the optimizer produced no estimate (missing statistics, or a RULE-mode plan
/// on an ancient database). They are surfaced as `None` — never an error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanCostRow {
    /// The `PLAN_TABLE.ID` plan-line number (`0` is the plan root).
    pub id: i64,
    /// Plan operation (`SELECT STATEMENT`, `TABLE ACCESS`, …), when available.
    pub operation: Option<String>,
    /// Operation options (`FULL`, `BY INDEX ROWID`, …), when available.
    pub options: Option<String>,
    /// Referenced object owner, when available.
    pub object_owner: Option<String>,
    /// Referenced object name, when available.
    pub object_name: Option<String>,
    /// Relative optimizer cost for this operation, or `None` when unavailable.
    pub cost: Option<i64>,
    /// Estimated rows this operation produces, or `None` when unavailable.
    pub cardinality: Option<i64>,
    /// Estimated bytes this operation produces, or `None` when unavailable.
    pub bytes: Option<i64>,
    /// Access predicate text reported by Oracle for this plan line, when
    /// available. Callers must sanitize before exposing it to untrusted clients.
    pub access_predicates: Option<String>,
    /// Filter predicate text reported by Oracle for this plan line, when
    /// available. Callers must sanitize before exposing it to untrusted clients.
    pub filter_predicates: Option<String>,
}

/// The plan root (`ID = 0`) totals: the optimizer's estimate for the whole plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanCostSummary {
    /// Total relative optimizer cost of the whole plan (root line; nullable).
    pub total_cost: Option<i64>,
    /// Estimated total rows the plan returns (root line; nullable).
    pub total_cardinality: Option<i64>,
    /// Estimated total bytes the plan returns (root line; nullable).
    pub total_bytes: Option<i64>,
}

/// A structured optimizer cost/cardinality block that accompanies an
/// `EXPLAIN PLAN`, additive to the human-readable `DBMS_XPLAN.DISPLAY` output.
///
/// See [`PLAN_COST_ESTIMATE_NOTE`]: the figures are relative optimizer
/// estimates, not measured runtime.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanCostEstimate {
    /// Per-line estimates, ordered by `PLAN_TABLE.ID`.
    pub rows: Vec<PlanCostRow>,
    /// The plan-root (`ID = 0`) totals.
    pub summary: PlanCostSummary,
    /// Reminder that these are relative optimizer estimates (see
    /// [`PLAN_COST_ESTIMATE_NOTE`]).
    pub note: String,
}

/// The scoped `PLAN_TABLE` read that surfaces per-line optimizer estimates for
/// the plan the most recent `EXPLAIN PLAN` wrote. It is scoped to the latest
/// `plan_id`, mirroring how `DBMS_XPLAN.DISPLAY` (with no explicit
/// `statement_id`) selects the most recently explained statement — so the cost
/// block describes exactly the plan the `DISPLAY` output above shows.
const PLAN_COST_SQL: &str = "SELECT id, operation, options, object_owner, object_name, \
cost, cardinality, bytes, access_predicates, filter_predicates \
FROM plan_table \
WHERE plan_id = (SELECT MAX(plan_id) FROM plan_table) \
ORDER BY id";

/// Parse an optional `PLAN_TABLE` numeric cell into `Option<i64>`. A SQL `NULL`
/// (or an empty/blank rendering) becomes `None`; a non-integer `NUMBER` is
/// truncated toward zero. Never panics, never errors.
fn plan_cell_i64(cell: Option<&OracleCell>) -> Option<i64> {
    let text = cell.and_then(OracleCell::text)?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed
        .parse::<i64>()
        .ok()
        .or_else(|| trimmed.parse::<f64>().ok().map(|value| value as i64))
}

fn plan_cell_text(cell: Option<&OracleCell>) -> Option<String> {
    let trimmed = cell.and_then(OracleCell::text)?.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Assemble a [`PlanCostEstimate`] from `PLAN_TABLE` rows shaped as
/// `id, cost, cardinality, bytes` (case-insensitive column lookup).
///
/// Pure: no I/O, no classifier interaction. `NULL` estimate columns become
/// `None`. Rows whose `ID` cannot be parsed are skipped (defensive; `ID` is
/// `NOT NULL` in a real `PLAN_TABLE`). Returns `None` when no plan-root line
/// (`ID = 0`) is present, so the caller omits the block rather than emitting a
/// summary it cannot ground on the root.
#[must_use]
pub fn assemble_cost_estimate(rows: &[OracleRow]) -> Option<PlanCostEstimate> {
    let mut cost_rows: Vec<PlanCostRow> = Vec::with_capacity(rows.len());
    for row in rows {
        let Some(id) = plan_cell_i64(row.cell("ID")) else {
            continue;
        };
        cost_rows.push(PlanCostRow {
            id,
            operation: plan_cell_text(row.cell("OPERATION")),
            options: plan_cell_text(row.cell("OPTIONS")),
            object_owner: plan_cell_text(row.cell("OBJECT_OWNER")),
            object_name: plan_cell_text(row.cell("OBJECT_NAME")),
            cost: plan_cell_i64(row.cell("COST")),
            cardinality: plan_cell_i64(row.cell("CARDINALITY")),
            bytes: plan_cell_i64(row.cell("BYTES")),
            access_predicates: plan_cell_text(row.cell("ACCESS_PREDICATES")),
            filter_predicates: plan_cell_text(row.cell("FILTER_PREDICATES")),
        });
    }
    let root = cost_rows.iter().find(|row| row.id == 0)?;
    let summary = PlanCostSummary {
        total_cost: root.cost,
        total_cardinality: root.cardinality,
        total_bytes: root.bytes,
    };
    Some(PlanCostEstimate {
        rows: cost_rows,
        summary,
        note: PLAN_COST_ESTIMATE_NOTE.to_owned(),
    })
}

/// Read the optimizer cost/cardinality estimates for the plan the most recent
/// [`explain_plan`] just wrote (scoped to the latest `plan_id`, matching
/// `DBMS_XPLAN.DISPLAY`). This is additive/observational — a plain read of
/// `PLAN_TABLE`, gated by the same diagnostic-write permission as the
/// `EXPLAIN PLAN` that produced the rows; it never re-runs the statement and
/// never touches the classifier.
///
/// 11g-safe / graceful degradation: on databases whose `PLAN_TABLE` lacks a
/// cost column (or the table/`plan_id` entirely) the `SELECT` fails; that error
/// is returned so the caller can *omit* the block and note why — the surrounding
/// `EXPLAIN PLAN` output must never be failed by a missing cost estimate.
/// `Ok(None)` means the query ran but produced no scoped plan-root line.
pub async fn plan_cost_estimate(
    cx: &Cx,
    conn: &dyn OracleConnection,
) -> Result<Option<PlanCostEstimate>, DbError> {
    let rows = conn.query_rows(cx, PLAN_COST_SQL, &[]).await?;
    Ok(assemble_cost_estimate(&rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OracleBackend, OracleCell, OracleConnectionInfo};
    use asupersync::runtime::RuntimeBuilder;

    fn run_with_cx<F, Fut, T>(body: F) -> T
    where
        F: FnOnce(Cx) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        runtime.block_on(async move {
            let cx = Cx::current().expect("block_on installs a current Cx");
            body(cx).await
        })
    }

    #[derive(Default)]
    struct CaptureMock {
        calls: std::sync::Mutex<Vec<(String, Vec<OracleBind>)>>,
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for CaptureMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            sql: &str,
            binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.calls
                .lock()
                .expect("capture lock")
                .push((sql.to_owned(), binds.to_vec()));
            Ok(vec![])
        }

        async fn execute(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            Ok(0)
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    fn query_response(rows: Vec<serde_json::Value>) -> QueryResponse {
        QueryResponse {
            columns: vec!["ID".to_owned(), "NAME".to_owned(), "QTY".to_owned()],
            row_count: rows.len(),
            rows,
            truncated: false,
            next_cursor: None,
            total_bytes: 0,
            mask_certificate: None,
        }
    }

    #[test]
    fn diff_query_responses_aligns_by_key_and_reports_changes() {
        let before = query_response(vec![
            serde_json::json!({ "ID": "1", "NAME": "old", "QTY": "10" }),
            serde_json::json!({ "ID": "2", "NAME": "gone", "QTY": "20" }),
        ]);
        let after = query_response(vec![
            serde_json::json!({ "ID": "1", "NAME": "new", "QTY": "10" }),
            serde_json::json!({ "ID": "3", "NAME": "added", "QTY": "30" }),
        ]);

        let diff = diff_query_responses(&before, &after, &["ID".to_owned()]).expect("diff");

        assert!(diff.keyed);
        assert_eq!(diff.key_columns, vec!["ID"]);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].key, serde_json::json!({ "ID": "1" }));
        assert_eq!(
            diff.removed,
            vec![serde_json::json!({ "ID": "2", "NAME": "gone", "QTY": "20" })]
        );
        assert_eq!(
            diff.added,
            vec![serde_json::json!({ "ID": "3", "NAME": "added", "QTY": "30" })]
        );
    }

    #[test]
    fn diff_query_responses_without_key_reports_multiset_add_remove_only() {
        let before = query_response(vec![
            serde_json::json!({ "ID": "1", "NAME": "same", "QTY": "10" }),
            serde_json::json!({ "ID": "2", "NAME": "old", "QTY": "20" }),
        ]);
        let after = query_response(vec![
            serde_json::json!({ "ID": "1", "NAME": "same", "QTY": "10" }),
            serde_json::json!({ "ID": "2", "NAME": "new", "QTY": "20" }),
        ]);

        let diff = diff_query_responses(&before, &after, &[]).expect("diff");

        assert!(!diff.keyed);
        assert!(diff.changed.is_empty());
        assert_eq!(
            diff.removed,
            vec![serde_json::json!({ "ID": "2", "NAME": "old", "QTY": "20" })]
        );
        assert_eq!(
            diff.added,
            vec![serde_json::json!({ "ID": "2", "NAME": "new", "QTY": "20" })]
        );
    }

    #[test]
    fn diff_query_responses_refuses_missing_key_column() {
        let before = query_response(vec![serde_json::json!({ "ID": "1" })]);
        let after = query_response(vec![serde_json::json!({ "ID": "1" })]);

        let err = diff_query_responses(&before, &after, &["MISSING".to_owned()])
            .expect_err("missing key");

        assert_eq!(
            err,
            QueryDiffError::MissingKeyColumn {
                column: "MISSING".to_owned(),
            }
        );
    }

    #[test]
    fn primary_key_columns_binds_owner_and_table() {
        let conn = CaptureMock::default();
        let conn_ref = &conn;
        run_with_cx(|cx| async move {
            primary_key_columns(&cx, conn_ref, "app", "orders")
                .await
                .expect("pk lookup")
        });
        let (sql, binds) = conn
            .calls
            .lock()
            .expect("calls")
            .first()
            .cloned()
            .expect("one call");

        assert!(sql.contains("all_constraints"));
        assert!(sql.contains("all_cons_columns"));
        assert_eq!(
            binds,
            vec![
                OracleBind::String("APP".to_owned()),
                OracleBind::String("ORDERS".to_owned()),
            ]
        );
    }

    struct SourceMock;

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for SourceMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            Ok(vec![
                OracleRow {
                    columns: vec![(
                        "TEXT".to_owned(),
                        OracleCell::new("VARCHAR2", Some("BEGIN\n".to_owned())),
                    )],
                },
                OracleRow {
                    columns: vec![(
                        "TEXT".to_owned(),
                        OracleCell::new("VARCHAR2", Some("  NULL;\nEND;\n".to_owned())),
                    )],
                },
            ])
        }

        async fn execute(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            Ok(0)
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    struct MultiSourceMock;

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for MultiSourceMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            sql: &str,
            binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            if sql.contains("SELECT type") {
                assert_eq!(
                    binds,
                    &[
                        OracleBind::String("HR".to_owned()),
                        OracleBind::String("EMP_API".to_owned()),
                    ]
                );
                return Ok(vec![
                    OracleRow {
                        columns: vec![(
                            "TYPE".to_owned(),
                            OracleCell::new("VARCHAR2", Some("PACKAGE".to_owned())),
                        )],
                    },
                    OracleRow {
                        columns: vec![(
                            "TYPE".to_owned(),
                            OracleCell::new("VARCHAR2", Some("PACKAGE BODY".to_owned())),
                        )],
                    },
                ]);
            }

            Ok(vec![OracleRow {
                columns: vec![(
                    "TEXT".to_owned(),
                    OracleCell::new("VARCHAR2", Some("BEGIN NULL; END;\n".to_owned())),
                )],
            }])
        }

        async fn execute(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            Ok(0)
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    struct LobMock;

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for LobMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            Ok(vec![OracleRow {
                columns: vec![(
                    "LOB_VALUE".to_owned(),
                    OracleCell::new("CLOB", Some("abcdefgh".to_owned())),
                )],
            }])
        }

        async fn execute(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            Ok(0)
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    #[test]
    fn identifier_and_type_validation() {
        assert!(is_simple_identifier("HR"));
        assert!(!is_simple_identifier("HR; DROP TABLE t"));
        assert!(is_ddl_object_type("table"));
        assert!(is_ddl_object_type("PACKAGE_BODY"));
        assert!(!is_ddl_object_type("ANYTHING_ELSE"));
        assert_eq!(
            normalize_source_object_type("package_body"),
            Some("PACKAGE BODY")
        );
        assert_eq!(normalize_source_object_type("TYPE BODY"), Some("TYPE BODY"));
        assert_eq!(normalize_source_object_type("TABLE"), None);
    }

    #[test]
    fn list_objects_binds_filters_and_limit() {
        let mock = CaptureMock::default();
        let m = &mock;
        run_with_cx(|cx| async move {
            list_objects(&cx, m, None, Some("package"), Some("emp%"), 25)
                .await
                .unwrap();
        });

        let calls = mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0].0.contains("SELECT o.owner, o.object_name"),
            "query should include OWNER for cross-schema results"
        );
        assert!(calls[0].0.contains("ROWNUM <= :4"));
        assert!(!calls[0].0.contains("FETCH FIRST :4"));
        assert_eq!(
            calls[0].1,
            vec![
                OracleBind::Null,
                OracleBind::String("PACKAGE".to_owned()),
                OracleBind::String("EMP%".to_owned()),
                OracleBind::I64(25),
            ]
        );
    }

    #[test]
    fn list_schemas_binds_filter_and_limit() {
        let mock = CaptureMock::default();
        let m = &mock;
        run_with_cx(|cx| async move {
            list_schemas(&cx, m, Some("app%"), 100).await.unwrap();
        });

        let calls = mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 1);
        assert!(calls[0].0.contains("SELECT o.owner AS schema_name"));
        assert!(calls[0].0.contains("COUNT(*) AS object_count"));
        assert!(calls[0].0.contains("ROWNUM <= :2"));
        assert!(!calls[0].0.contains("FETCH FIRST :2"));
        assert_eq!(
            calls[0].1,
            vec![OracleBind::String("APP%".to_owned()), OracleBind::I64(100),]
        );
    }

    #[test]
    fn search_source_binds_optional_scope_filters() {
        let mock = CaptureMock::default();
        let m = &mock;
        run_with_cx(|cx| async move {
            search_source(
                &cx,
                m,
                None,
                "commit",
                Some("package_body"),
                Some("emp%"),
                25,
            )
            .await
            .unwrap();
        });

        let calls = mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 1);
        assert!(calls[0].0.contains("SELECT s.owner, s.name"));
        assert!(calls[0].0.contains("args.owner_filter IS NULL"));
        assert!(calls[0].0.contains("ROWNUM <= :5"));
        assert!(!calls[0].0.contains("FETCH FIRST :5"));
        assert_eq!(
            calls[0].1,
            vec![
                OracleBind::Null,
                OracleBind::String("PACKAGE BODY".to_owned()),
                OracleBind::String("EMP%".to_owned()),
                OracleBind::String("commit".to_owned()),
                OracleBind::I64(25),
            ]
        );
    }

    #[test]
    fn search_source_rejects_unknown_source_type() {
        let mock = CaptureMock::default();
        let err = run_with_cx(|cx| async move {
            search_source(&cx, &mock, Some("hr"), "commit", Some("table"), None, 25)
                .await
                .expect_err("TABLE is not an ALL_SOURCE type")
        });
        assert!(err.to_string().contains("unsupported source object type"));
    }

    #[test]
    fn get_ddl_uses_text_slice_not_raw_metadata_lob() {
        let mock = CaptureMock::default();
        let m = &mock;
        run_with_cx(|cx| async move {
            get_ddl(&cx, m, "package", "hr", "pkg_demo").await.unwrap();
        });

        let calls = mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 1);
        assert!(calls[0].0.contains("DBMS_LOB.SUBSTR(DBMS_METADATA.GET_DDL"));
        assert_eq!(
            calls[0].1,
            vec![
                OracleBind::String("PKG_DEMO".to_owned()),
                OracleBind::String("HR".to_owned()),
            ]
        );
    }

    #[test]
    fn describe_index_trigger_and_view_bind_names() {
        let index_mock = CaptureMock::default();
        let im = &index_mock;
        let index =
            run_with_cx(|cx| async move { describe_index(&cx, im, "hr", "emp_ix").await.unwrap() });
        assert!(index.metadata.is_none());
        assert!(index.columns.is_empty());
        assert!(index.expressions.is_empty());
        let calls = index_mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 3);
        assert!(calls[0].0.contains("FROM all_indexes"));
        assert!(calls[1].0.contains("FROM all_ind_columns"));
        assert!(calls[2].0.contains("FROM all_ind_expressions"));
        assert_eq!(
            calls[0].1,
            vec![
                OracleBind::String("HR".to_owned()),
                OracleBind::String("EMP_IX".to_owned()),
            ]
        );
        drop(calls);

        let trigger_mock = CaptureMock::default();
        let tm = &trigger_mock;
        let trigger =
            run_with_cx(
                |cx| async move { describe_trigger(&cx, tm, "hr", "emp_biu").await.unwrap() },
            );
        assert!(trigger.metadata.is_none());
        let calls = trigger_mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 1);
        assert!(calls[0].0.contains("FROM all_triggers"));
        assert_eq!(
            calls[0].1,
            vec![
                OracleBind::String("HR".to_owned()),
                OracleBind::String("EMP_BIU".to_owned()),
            ]
        );
        drop(calls);

        let view_mock = CaptureMock::default();
        let vm = &view_mock;
        let view =
            run_with_cx(|cx| async move { describe_view(&cx, vm, "hr", "emp_v").await.unwrap() });
        assert!(view.metadata.is_none());
        assert!(view.columns.is_empty());
        let calls = view_mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 2);
        assert!(calls[0].0.contains("FROM all_views"));
        assert!(calls[1].0.contains("FROM all_tab_columns"));
        assert_eq!(
            calls[0].1,
            vec![
                OracleBind::String("HR".to_owned()),
                OracleBind::String("EMP_V".to_owned()),
            ]
        );
    }

    #[test]
    fn describe_constraints_binds_owner_and_table() {
        let mock = CaptureMock::default();
        let m = &mock;
        let constraints = run_with_cx(|cx| async move {
            describe_constraints(&cx, m, "hr", "employees")
                .await
                .unwrap()
        });
        assert!(constraints.is_empty());
        let calls = mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 1);
        assert!(calls[0].0.contains("FROM all_constraints"));
        assert!(calls[0].0.contains("LEFT JOIN all_cons_columns"));
        assert_eq!(
            calls[0].1,
            vec![
                OracleBind::String("HR".to_owned()),
                OracleBind::String("EMPLOYEES".to_owned()),
            ]
        );
    }

    #[test]
    fn get_source_caps_text_and_reports_metadata() {
        let source = run_with_cx(|cx| async move {
            get_source(&cx, &SourceMock, "hr", "emp_api", "package_body", 8)
                .await
                .unwrap()
        });
        assert_eq!(source.owner, "HR");
        assert_eq!(source.name, "EMP_API");
        assert_eq!(source.object_type, "PACKAGE BODY");
        assert_eq!(source.line_count, 2);
        assert_eq!(source.char_count, "BEGIN\n  NULL;\nEND;\n".chars().count());
        assert_eq!(source.source, "BEGIN\n  ");
        assert!(source.truncated);
    }

    #[test]
    fn get_sources_by_name_lists_source_types_and_fetches_each() {
        let sources = run_with_cx(|cx| async move {
            get_sources_by_name(&cx, &MultiSourceMock, "hr", "emp_api", 64)
                .await
                .unwrap()
        });
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].object_type, "PACKAGE");
        assert_eq!(sources[1].object_type, "PACKAGE BODY");
        assert_eq!(sources[0].owner, "HR");
        assert_eq!(sources[0].name, "EMP_API");
        assert_eq!(sources[0].source, "BEGIN NULL; END;\n");
    }

    #[test]
    fn read_lob_caps_text_and_validates_identifiers() {
        let lob = run_with_cx(|cx| async move {
            read_lob(&cx, &LobMock, "hr", "docs", "body", "id", "42", 4)
                .await
                .unwrap()
                .expect("matched row")
        });
        assert_eq!(lob.owner, "HR");
        assert_eq!(lob.table, "DOCS");
        assert_eq!(lob.column, "BODY");
        assert_eq!(lob.pk_column, "ID");
        assert_eq!(lob.value.as_deref(), Some("abcd"));
        assert_eq!(lob.char_count, 8);
        assert!(lob.truncated);

        let err = run_with_cx(|cx| async move {
            read_lob(&cx, &LobMock, "hr", "docs;drop", "body", "id", "42", 4)
                .await
                .expect_err("bad identifier refused")
        });
        assert!(matches!(err, DbError::Query(_)));
    }

    // The query-builder shapes are exercised by the live tests; the validation
    // above is the injection-safety gate for the few interpolated positions.

    /// A scripted mock for [`search_objects`] (E4): returns SQL-shape-dependent
    /// rows and records every SQL it sees, so the test can prove the summary
    /// uses ALL_TABLES.NUM_ROWS and never COUNT(*) over the table's data.
    struct SearchObjectsMock {
        seen_sql: std::sync::Mutex<Vec<String>>,
        /// Optional STALE_STATS value returned by all_tab_statistics.
        stale: Option<&'static str>,
    }

    impl SearchObjectsMock {
        fn new(stale: Option<&'static str>) -> Self {
            Self {
                seen_sql: std::sync::Mutex::new(Vec::new()),
                stale,
            }
        }
    }

    fn cell_row(pairs: &[(&str, &str)]) -> OracleRow {
        OracleRow {
            columns: pairs
                .iter()
                .map(|(name, value)| {
                    (
                        (*name).to_owned(),
                        OracleCell::new("VARCHAR2", Some((*value).to_owned())),
                    )
                })
                .collect(),
        }
    }

    /// Synthetic `ALL_OBJECTS` and FK-topology rows for the C2.1 orient
    /// contract. It also retains the generated SQL and positional binds so the
    /// test proves the dictionary reads stay bounded and parameterized.
    #[derive(Default)]
    struct OrientMock {
        calls: std::sync::Mutex<Vec<(String, Vec<OracleBind>)>>,
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for OrientMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            sql: &str,
            binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.calls
                .lock()
                .expect("orient mock lock")
                .push((sql.to_owned(), binds.to_vec()));

            if sql.contains("FROM all_objects") {
                return Ok(vec![
                    cell_row(&[
                        ("OWNER", "HR"),
                        ("OBJECT_NAME", "CUSTOMERS"),
                        ("OBJECT_TYPE", "TABLE"),
                    ]),
                    cell_row(&[
                        ("OWNER", "HR"),
                        ("OBJECT_NAME", "ORDERS"),
                        ("OBJECT_TYPE", "TABLE"),
                    ]),
                    cell_row(&[
                        ("OWNER", "HR"),
                        ("OBJECT_NAME", "ORDER_REPORT"),
                        ("OBJECT_TYPE", "VIEW"),
                    ]),
                ]);
            }

            assert!(sql.contains("FROM all_constraints child"));
            Ok(vec![
                cell_row(&[
                    ("CHILD_OWNER", "HR"),
                    ("CHILD_TABLE", "ORDER_LINES"),
                    ("CONSTRAINT_NAME", "ORDER_LINES_ORDER_FK"),
                    ("PARENT_OWNER", "HR"),
                    ("PARENT_TABLE", "ORDERS"),
                    ("CHILD_COLUMN", "ORDER_ID"),
                    ("PARENT_COLUMN", "ID"),
                    ("COLUMN_POSITION", "1"),
                ]),
                cell_row(&[
                    ("CHILD_OWNER", "HR"),
                    ("CHILD_TABLE", "ORDER_LINES"),
                    ("CONSTRAINT_NAME", "ORDER_LINES_ORDER_FK"),
                    ("PARENT_OWNER", "HR"),
                    ("PARENT_TABLE", "ORDERS"),
                    ("CHILD_COLUMN", "ORDER_REGION"),
                    ("PARENT_COLUMN", "REGION"),
                    ("COLUMN_POSITION", "2"),
                ]),
            ])
        }

        async fn execute(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            Ok(0)
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    #[test]
    fn orient_schema_and_fks_return_bounded_synthetic_topology() {
        let mock = OrientMock::default();
        let conn = &mock;
        let (schema, foreign_keys) = run_with_cx(|cx| async move {
            let schema = orient_schema(&cx, conn, Some("hr"), 25)
                .await
                .expect("schema map");
            let foreign_keys = orient_fks(&cx, conn, Some("hr"), 1)
                .await
                .expect("foreign-key topology");
            (schema, foreign_keys)
        });

        assert_eq!(
            schema,
            vec![
                OrientSchemaObject {
                    owner: "HR".to_owned(),
                    object_name: "CUSTOMERS".to_owned(),
                    object_type: "TABLE".to_owned(),
                },
                OrientSchemaObject {
                    owner: "HR".to_owned(),
                    object_name: "ORDERS".to_owned(),
                    object_type: "TABLE".to_owned(),
                },
                OrientSchemaObject {
                    owner: "HR".to_owned(),
                    object_name: "ORDER_REPORT".to_owned(),
                    object_type: "VIEW".to_owned(),
                },
            ]
        );
        assert_eq!(foreign_keys.len(), 1, "one capped FK edge");
        assert_eq!(foreign_keys[0].constraint_name, "ORDER_LINES_ORDER_FK");
        assert_eq!(foreign_keys[0].child_owner, "HR");
        assert_eq!(foreign_keys[0].child_table, "ORDER_LINES");
        assert_eq!(foreign_keys[0].parent_owner, "HR");
        assert_eq!(foreign_keys[0].parent_table, "ORDERS");
        assert_eq!(
            foreign_keys[0].columns,
            vec![
                OrientForeignKeyColumn {
                    position: 1,
                    child_column: "ORDER_ID".to_owned(),
                    parent_column: "ID".to_owned(),
                },
                OrientForeignKeyColumn {
                    position: 2,
                    child_column: "ORDER_REGION".to_owned(),
                    parent_column: "REGION".to_owned(),
                },
            ],
            "the cap is on constraints, so a composite FK remains complete"
        );

        let calls = mock.calls.lock().expect("orient mock lock");
        assert_eq!(
            calls.len(),
            2,
            "schema map and FK topology are separate reads"
        );
        let schema_call = calls
            .iter()
            .find(|(sql, _)| sql.contains("FROM all_objects"))
            .expect("ALL_OBJECTS schema-map read");
        assert!(schema_call.0.contains("ROWNUM <= :2"));
        assert_eq!(
            schema_call.1,
            vec![OracleBind::String("HR".to_owned()), OracleBind::I64(25)],
            "schema owner is upper-cased and bound positionally"
        );

        let fk_call = calls
            .iter()
            .find(|(sql, _)| sql.contains("FROM all_constraints child"))
            .expect("ALL_CONSTRAINTS FK read");
        assert!(fk_call.0.contains("JOIN all_constraints parent"));
        assert!(fk_call.0.contains("JOIN all_cons_columns child_columns"));
        assert!(fk_call.0.contains("JOIN all_cons_columns parent_columns"));
        assert!(
            fk_call
                .0
                .contains("parent_columns.position = child_columns.position"),
            "child and parent columns must be joined by their key position"
        );
        assert!(fk_call.0.contains("ROWNUM <= :2"));
        assert_eq!(
            fk_call.1,
            vec![OracleBind::String("HR".to_owned()), OracleBind::I64(1)],
            "FK owner and cap are positional binds"
        );
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for SearchObjectsMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }
        async fn query_rows(
            &self,
            _cx: &Cx,
            sql: &str,
            _binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.seen_sql.lock().unwrap().push(sql.to_owned());
            if sql.contains("FROM all_objects") {
                // Two objects: a table and a view. (Quoted-identifier case: the
                // dictionary stores the exact case, so "MixedCase" round-trips.)
                return Ok(vec![
                    cell_row(&[
                        ("OWNER", "HR"),
                        ("OBJECT_NAME", "EMPLOYEES"),
                        ("OBJECT_TYPE", "TABLE"),
                        ("STATUS", "VALID"),
                    ]),
                    cell_row(&[
                        ("OWNER", "HR"),
                        ("OBJECT_NAME", "MixedCase"),
                        ("OBJECT_TYPE", "VIEW"),
                        ("STATUS", "VALID"),
                    ]),
                ]);
            }
            if sql.contains("all_col_comments") {
                return Ok(vec![cell_row(&[
                    ("COLUMN_NAME", "ID"),
                    ("DATA_TYPE", "NUMBER"),
                    ("NULLABLE", "N"),
                    ("COMMENTS", "primary key"),
                ])]);
            }
            if sql.contains("FROM all_tab_columns") {
                // Column count query.
                return Ok(vec![cell_row(&[("COLUMN_COUNT", "3")])]);
            }
            if sql.contains("all_tab_comments") {
                return Ok(vec![cell_row(&[("COMMENTS", "the employees table")])]);
            }
            if sql.contains("all_ind_columns") {
                return Ok(vec![cell_row(&[("COLUMN_NAME", "ID")])]);
            }
            if sql.contains("FROM all_indexes") {
                return Ok(vec![cell_row(&[
                    ("INDEX_NAME", "EMP_PK"),
                    ("UNIQUENESS", "UNIQUE"),
                ])]);
            }
            Ok(Vec::new())
        }
        async fn query_optional_row(
            &self,
            _cx: &Cx,
            sql: &str,
            _binds: &[OracleBind],
        ) -> Result<Option<OracleRow>, DbError> {
            self.seen_sql.lock().unwrap().push(sql.to_owned());
            if sql.contains("FROM all_tables") {
                return Ok(Some(cell_row(&[
                    ("NUM_ROWS", "1234"),
                    ("LAST_ANALYZED", "2026-01-01T00:00:00"),
                ])));
            }
            if sql.contains("all_tab_statistics") {
                return Ok(self.stale.map(|value| cell_row(&[("STALE_STATS", value)])));
            }
            if sql.contains("all_tab_comments") {
                return Ok(Some(cell_row(&[("COMMENTS", "the employees table")])));
            }
            if sql.contains("COUNT(*) AS column_count") {
                return Ok(Some(cell_row(&[("COLUMN_COUNT", "3")])));
            }
            Ok(None)
        }
        async fn execute(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            Ok(0)
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    #[test]
    fn search_detail_level_parses_and_defaults_to_standard() {
        assert_eq!(
            SearchDetailLevel::parse(None),
            Some(SearchDetailLevel::Standard)
        );
        assert_eq!(
            SearchDetailLevel::parse(Some("")),
            Some(SearchDetailLevel::Standard)
        );
        assert_eq!(
            SearchDetailLevel::parse(Some("Summary")),
            Some(SearchDetailLevel::Summary)
        );
        assert_eq!(
            SearchDetailLevel::parse(Some(" NAMES ")),
            Some(SearchDetailLevel::Names)
        );
        assert_eq!(
            SearchDetailLevel::parse(Some("full")),
            Some(SearchDetailLevel::Full)
        );
        assert_eq!(SearchDetailLevel::parse(Some("bogus")), None);
    }

    #[test]
    fn search_objects_summary_uses_all_tables_num_rows_not_count_star() {
        let mock = SearchObjectsMock::new(None);
        let m = &mock;
        let results = run_with_cx(|cx| async move {
            search_objects(
                &cx,
                m,
                Some("HR"),
                None,
                None,
                SearchDetailLevel::Summary,
                100,
            )
            .await
            .unwrap()
        });

        // Two objects (table + view). The TABLE carries the optimizer estimate;
        // the VIEW does not (no ALL_TABLES row).
        assert_eq!(results.len(), 2);
        let table = &results[0];
        assert_eq!(table.object_name, "EMPLOYEES");
        assert_eq!(table.num_rows, Some(1234));
        assert_eq!(table.row_count_is_estimate, Some(true));
        assert_eq!(table.last_analyzed.as_deref(), Some("2026-01-01T00:00:00"));
        assert_eq!(table.column_count, Some(3));
        assert_eq!(table.comment.as_deref(), Some("the employees table"));
        // Summary stops before the column list / indexes.
        assert!(table.columns.is_none());
        assert!(table.indexes.is_none());

        // Quoted/case-sensitive identifier is preserved verbatim.
        assert_eq!(results[1].object_name, "MixedCase");

        // The load-bearing AC: the row count came from ALL_TABLES.NUM_ROWS, and
        // we NEVER issued a COUNT(*) over the table's data.
        let seen = mock.seen_sql.lock().unwrap();
        assert!(
            seen.iter()
                .any(|sql| sql.contains("num_rows") && sql.contains("all_tables")),
            "summary must read ALL_TABLES.NUM_ROWS: {seen:?}"
        );
        assert!(
            !seen.iter().any(|sql| {
                let lower = sql.to_ascii_lowercase();
                lower.contains("count(*) from hr")
                    || lower.contains("count(*) from \"hr\"")
                    || (lower.contains("count(*)") && lower.contains("employees"))
            }),
            "summary must NOT COUNT(*) the table's data: {seen:?}"
        );
    }

    #[test]
    fn search_objects_summary_flags_stale_stats() {
        // Stale-stats case: ALL_TAB_STATISTICS.STALE_STATS = 'YES' so the
        // optimizer estimate must be flagged untrustworthy.
        let mock = SearchObjectsMock::new(Some("YES"));
        let m = &mock;
        let results = run_with_cx(|cx| async move {
            search_objects(
                &cx,
                m,
                Some("HR"),
                Some("TABLE"),
                None,
                SearchDetailLevel::Summary,
                100,
            )
            .await
            .unwrap()
        });
        let table = results.iter().find(|o| o.object_type == "TABLE").unwrap();
        assert_eq!(table.num_rows, Some(1234));
        assert_eq!(
            table.stats_stale,
            Some(true),
            "STALE_STATS=YES must surface stats_stale=true so the estimate is not trusted"
        );
    }

    #[test]
    fn search_objects_names_level_is_identifiers_only() {
        let mock = SearchObjectsMock::new(None);
        let m = &mock;
        let results = run_with_cx(|cx| async move {
            search_objects(
                &cx,
                m,
                Some("HR"),
                None,
                None,
                SearchDetailLevel::Names,
                100,
            )
            .await
            .unwrap()
        });
        assert_eq!(results.len(), 2);
        let table = &results[0];
        assert!(table.num_rows.is_none());
        assert!(table.column_count.is_none());
        assert!(table.comment.is_none());
        assert!(table.columns.is_none());
        assert!(table.indexes.is_none());
        // Names level only touches ALL_OBJECTS — no ALL_TABLES read at all.
        let seen = mock.seen_sql.lock().unwrap();
        assert!(
            !seen.iter().any(|sql| sql.contains("all_tables")),
            "names level must not read optimizer stats: {seen:?}"
        );
    }

    #[test]
    fn search_objects_full_level_adds_columns_and_indexes() {
        let mock = SearchObjectsMock::new(None);
        let m = &mock;
        let results = run_with_cx(|cx| async move {
            search_objects(
                &cx,
                m,
                Some("HR"),
                Some("TABLE"),
                None,
                SearchDetailLevel::Full,
                100,
            )
            .await
            .unwrap()
        });
        let table = results.iter().find(|o| o.object_type == "TABLE").unwrap();
        let columns = table.columns.as_ref().expect("full includes columns");
        assert_eq!(columns[0].name, "ID");
        assert_eq!(columns[0].comment.as_deref(), Some("primary key"));
        let indexes = table.indexes.as_ref().expect("full includes indexes");
        assert_eq!(indexes[0].name, "EMP_PK");
        assert_eq!(indexes[0].uniqueness.as_deref(), Some("UNIQUE"));
        assert_eq!(indexes[0].columns, vec!["ID".to_owned()]);
    }

    /// Build a `PLAN_TABLE` row with the four cost columns; a `None` value
    /// models a SQL `NULL` (no-stats / RULE-mode) for that column.
    fn plan_row(
        id: Option<&str>,
        cost: Option<&str>,
        cardinality: Option<&str>,
        bytes: Option<&str>,
    ) -> OracleRow {
        OracleRow {
            columns: vec![
                (
                    "ID".to_owned(),
                    OracleCell::new("NUMBER", id.map(str::to_owned)),
                ),
                (
                    "COST".to_owned(),
                    OracleCell::new("NUMBER", cost.map(str::to_owned)),
                ),
                (
                    "CARDINALITY".to_owned(),
                    OracleCell::new("NUMBER", cardinality.map(str::to_owned)),
                ),
                (
                    "BYTES".to_owned(),
                    OracleCell::new("NUMBER", bytes.map(str::to_owned)),
                ),
            ],
        }
    }

    #[test]
    fn cost_estimate_assembles_rows_and_root_summary() {
        // A tiny two-line plan: root (id=0) then a full-scan child (id=1).
        let rows = vec![
            plan_row(Some("0"), Some("842"), Some("100000"), Some("2400000")),
            plan_row(Some("1"), Some("842"), Some("100000"), Some("2400000")),
        ];
        let estimate = assemble_cost_estimate(&rows).expect("root line present");
        assert_eq!(estimate.rows.len(), 2);
        assert_eq!(estimate.rows[0].id, 0);
        assert_eq!(estimate.rows[0].cost, Some(842));
        assert_eq!(estimate.rows[0].cardinality, Some(100_000));
        assert_eq!(estimate.rows[0].bytes, Some(2_400_000));
        // Summary mirrors the id=0 root line.
        assert_eq!(estimate.summary.total_cost, Some(842));
        assert_eq!(estimate.summary.total_cardinality, Some(100_000));
        assert_eq!(estimate.summary.total_bytes, Some(2_400_000));
        assert_eq!(estimate.note, PLAN_COST_ESTIMATE_NOTE);
    }

    #[test]
    fn cost_estimate_carries_plan_metadata_and_predicates() {
        let rows = vec![
            plan_row(Some("0"), Some("842"), Some("100000"), Some("2400000")),
            OracleRow {
                columns: vec![
                    (
                        "ID".to_owned(),
                        OracleCell::new("NUMBER", Some("1".to_owned())),
                    ),
                    (
                        "OPERATION".to_owned(),
                        OracleCell::new("VARCHAR2", Some("TABLE ACCESS".to_owned())),
                    ),
                    (
                        "OPTIONS".to_owned(),
                        OracleCell::new("VARCHAR2", Some("FULL".to_owned())),
                    ),
                    (
                        "OBJECT_OWNER".to_owned(),
                        OracleCell::new("VARCHAR2", Some("APP".to_owned())),
                    ),
                    (
                        "OBJECT_NAME".to_owned(),
                        OracleCell::new("VARCHAR2", Some("ORDERS".to_owned())),
                    ),
                    (
                        "COST".to_owned(),
                        OracleCell::new("NUMBER", Some("842".to_owned())),
                    ),
                    (
                        "CARDINALITY".to_owned(),
                        OracleCell::new("NUMBER", Some("100000".to_owned())),
                    ),
                    (
                        "BYTES".to_owned(),
                        OracleCell::new("NUMBER", Some("2400000".to_owned())),
                    ),
                    (
                        "ACCESS_PREDICATES".to_owned(),
                        OracleCell::new("VARCHAR2", Some("\"ID\"=:B1".to_owned())),
                    ),
                    (
                        "FILTER_PREDICATES".to_owned(),
                        OracleCell::new("VARCHAR2", Some("\"STATUS\"='OPEN'".to_owned())),
                    ),
                ],
            },
        ];

        let estimate = assemble_cost_estimate(&rows).expect("root line present");
        assert_eq!(estimate.rows[1].operation.as_deref(), Some("TABLE ACCESS"));
        assert_eq!(estimate.rows[1].options.as_deref(), Some("FULL"));
        assert_eq!(estimate.rows[1].object_owner.as_deref(), Some("APP"));
        assert_eq!(estimate.rows[1].object_name.as_deref(), Some("ORDERS"));
        assert_eq!(
            estimate.rows[1].access_predicates.as_deref(),
            Some("\"ID\"=:B1")
        );
        assert_eq!(
            estimate.rows[1].filter_predicates.as_deref(),
            Some("\"STATUS\"='OPEN'")
        );
    }

    #[test]
    fn cost_estimate_emits_null_for_missing_estimates() {
        // 11g / RULE-mode / no-stats: cost, cardinality, bytes come back NULL.
        // They must surface as None (never an error), and the summary stays
        // grounded on the id=0 root even when its estimates are null.
        let rows = vec![
            plan_row(Some("0"), None, None, None),
            plan_row(Some("1"), None, Some("14"), None),
        ];
        let estimate = assemble_cost_estimate(&rows).expect("root line present");
        assert_eq!(estimate.rows[0].cost, None);
        assert_eq!(estimate.rows[0].cardinality, None);
        assert_eq!(estimate.rows[0].bytes, None);
        assert_eq!(estimate.rows[1].cardinality, Some(14));
        assert_eq!(estimate.summary.total_cost, None);
        assert_eq!(estimate.summary.total_cardinality, None);
        assert_eq!(estimate.summary.total_bytes, None);
    }

    #[test]
    fn cost_estimate_handles_blank_and_non_integer_cells() {
        // A blank rendering is treated as NULL; a non-integer NUMBER truncates.
        let rows = vec![plan_row(Some("0"), Some("   "), Some("12.9"), Some("500"))];
        let estimate = assemble_cost_estimate(&rows).expect("root line present");
        assert_eq!(estimate.rows[0].cost, None);
        assert_eq!(estimate.rows[0].cardinality, Some(12));
        assert_eq!(estimate.rows[0].bytes, Some(500));
    }

    #[test]
    fn cost_estimate_omitted_when_no_root_line() {
        // Rows without an id=0 root (degenerate) yield no block, so the caller
        // omits cost_estimate rather than fabricate a summary.
        let rows = vec![plan_row(Some("2"), Some("5"), Some("1"), Some("10"))];
        assert!(assemble_cost_estimate(&rows).is_none());
        // Empty PLAN_TABLE read → no block.
        assert!(assemble_cost_estimate(&[]).is_none());
    }

    fn dependency_row(owner: &str, name: &str, object_type: &str) -> OracleRow {
        OracleRow {
            columns: vec![
                (
                    "OWNER".to_owned(),
                    OracleCell::new("VARCHAR2", Some(owner.to_owned())),
                ),
                (
                    "NAME".to_owned(),
                    OracleCell::new("VARCHAR2", Some(name.to_owned())),
                ),
                (
                    "TYPE".to_owned(),
                    OracleCell::new("VARCHAR2", Some(object_type.to_owned())),
                ),
            ],
        }
    }

    struct DependentsMock {
        rows: Vec<OracleRow>,
        fail: bool,
        calls: std::sync::Mutex<Vec<(String, Vec<OracleBind>)>>,
    }

    impl DependentsMock {
        fn returning(rows: Vec<OracleRow>) -> Self {
            Self {
                rows,
                fail: false,
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn failing() -> Self {
            Self {
                rows: Vec::new(),
                fail: true,
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for DependentsMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }

        async fn query_rows(
            &self,
            _cx: &Cx,
            sql: &str,
            binds: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            self.calls
                .lock()
                .expect("call log")
                .push((sql.to_owned(), binds.to_vec()));
            if self.fail {
                return Err(DbError::Query(
                    "ORA-00942: table or view does not exist".to_owned(),
                ));
            }
            Ok(self.rows.clone())
        }

        async fn execute(
            &self,
            _cx: &Cx,
            _sql: &str,
            _binds: &[OracleBind],
        ) -> Result<u64, DbError> {
            Ok(0)
        }

        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }

        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Ok(())
        }
    }

    #[test]
    fn dependent_object_invalidatable_classification() {
        for kind in [
            "VIEW",
            "PROCEDURE",
            "FUNCTION",
            "PACKAGE",
            "PACKAGE BODY",
            "TYPE",
            "TYPE BODY",
            "TRIGGER",
            "MATERIALIZED VIEW",
            // case-insensitive
            "view",
        ] {
            let dep = DependentObject {
                owner: "APP".to_owned(),
                name: "X".to_owned(),
                object_type: kind.to_owned(),
            };
            assert!(dep.is_invalidatable(), "{kind} should be invalidatable");
        }
        for kind in ["TABLE", "SEQUENCE", "SYNONYM", "INDEX"] {
            let dep = DependentObject {
                owner: "APP".to_owned(),
                name: "X".to_owned(),
                object_type: kind.to_owned(),
            };
            assert!(
                !dep.is_invalidatable(),
                "{kind} should not be invalidatable"
            );
        }
    }

    #[test]
    fn dependent_from_row_skips_incomplete_rows() {
        assert_eq!(
            dependent_from_row(&dependency_row("APP", "V_ORDERS", "VIEW")),
            Some(DependentObject {
                owner: "APP".to_owned(),
                name: "V_ORDERS".to_owned(),
                object_type: "VIEW".to_owned(),
            })
        );
        // Missing NAME column → skipped.
        let partial = OracleRow {
            columns: vec![(
                "OWNER".to_owned(),
                OracleCell::new("VARCHAR2", Some("APP".to_owned())),
            )],
        };
        assert_eq!(dependent_from_row(&partial), None);
        // Blank TYPE → skipped.
        assert_eq!(dependent_from_row(&dependency_row("APP", "X", "  ")), None);
    }

    #[test]
    fn probe_dependents_binds_uppercased_and_self_excludes() {
        let conn = DependentsMock::returning(vec![
            dependency_row("APP", "V_DEP", "VIEW"),
            dependency_row("APP", "P_DEP", "PROCEDURE"),
        ]);
        let conn_ref = &conn;
        let probe = run_with_cx(|cx| async move {
            probe_dependents(&cx, conn_ref, "app", "pkg_target", 100).await
        });
        let (sql, binds) = conn
            .calls
            .lock()
            .expect("calls")
            .first()
            .cloned()
            .expect("one call");
        // Owner/name are bound (never interpolated) and normalized to uppercase.
        assert_eq!(
            binds,
            vec![
                OracleBind::String("APP".to_owned()),
                OracleBind::String("PKG_TARGET".to_owned()),
                OracleBind::I64(100),
            ]
        );
        assert!(sql.contains("all_dependencies"), "queries ALL_DEPENDENCIES");
        assert!(
            sql.contains("referenced_owner") && sql.contains("referenced_name"),
            "filters on the referenced object"
        );
        assert!(sql.contains("NOT (d.owner"), "self-excludes the target");
        match probe {
            DependentsProbe::Available { direct } => {
                assert_eq!(direct.len(), 2);
                assert_eq!(direct[0].name, "V_DEP");
                assert!(direct.iter().all(DependentObject::is_invalidatable));
            }
            DependentsProbe::Unavailable { reason } => panic!("expected Available, got {reason}"),
        }
    }

    #[test]
    fn probe_dependents_degrades_on_dictionary_error() {
        let conn = DependentsMock::failing();
        let conn_ref = &conn;
        let probe = run_with_cx(|cx| async move {
            probe_dependents(&cx, conn_ref, "APP", "PKG_TARGET", 100).await
        });
        match probe {
            DependentsProbe::Unavailable { reason } => {
                assert!(
                    reason.contains("ALL_DEPENDENCIES not accessible"),
                    "reason: {reason}"
                );
            }
            DependentsProbe::Available { .. } => panic!("expected Unavailable on error"),
        }
    }
}
