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

use asupersync::Cx;

use crate::connection::OracleConnection;
use crate::error::DbError;
use crate::types::{OracleBind, OracleRow};
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
}
