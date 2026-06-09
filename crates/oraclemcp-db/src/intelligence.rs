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
pub fn list_objects(
    conn: &dyn OracleConnection,
    owner: Option<&str>,
    object_type: Option<&str>,
    name_like: Option<&str>,
    max_rows: usize,
) -> Result<Vec<OracleRow>, DbError> {
    let sql = "WITH args AS ( \
                   SELECT :1 owner_filter, :2 type_filter, :3 name_filter FROM dual \
               ) \
               SELECT o.owner, o.object_name, o.object_type, o.status, o.last_ddl_time \
               FROM all_objects o CROSS JOIN args \
               WHERE (args.owner_filter IS NULL OR o.owner = args.owner_filter) \
                 AND (args.type_filter IS NULL OR o.object_type = args.type_filter) \
                 AND (args.name_filter IS NULL OR o.object_name LIKE args.name_filter) \
               ORDER BY o.owner, o.object_type, o.object_name \
               FETCH FIRST :4 ROWS ONLY";
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
        sql,
        &[
            owner_bind,
            type_bind,
            name_like_bind,
            OracleBind::from(max_rows as i64),
        ],
    )
}

/// Describe one index's metadata, indexed columns, and function-based
/// expressions. Owner + index name are bound.
pub fn describe_index(
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

    let metadata = conn.query_optional_row(
        "SELECT owner, index_name, index_type, table_owner, table_name, \
                uniqueness, status, partitioned, temporary, generated, degree \
         FROM all_indexes \
         WHERE owner = :1 AND index_name = :2",
        &binds,
    )?;
    let columns = conn.query_rows(
        "SELECT column_position, column_name, descend, column_length, char_length \
         FROM all_ind_columns \
         WHERE index_owner = :1 AND index_name = :2 \
         ORDER BY column_position",
        &binds,
    )?;
    let expressions = conn.query_rows(
        "SELECT column_position, column_expression \
         FROM all_ind_expressions \
         WHERE index_owner = :1 AND index_name = :2 \
         ORDER BY column_position",
        &binds,
    )?;

    Ok(IndexDescription {
        metadata,
        columns,
        expressions,
    })
}

/// Describe one trigger's timing/event/status and body. Owner + trigger name
/// are bound.
pub fn describe_trigger(
    conn: &dyn OracleConnection,
    owner: &str,
    trigger_name: &str,
) -> Result<TriggerDescription, DbError> {
    let metadata = conn.query_optional_row(
        "SELECT owner, trigger_name, trigger_type, triggering_event, \
                table_owner, table_name, status, when_clause, description, trigger_body \
         FROM all_triggers \
         WHERE owner = :1 AND trigger_name = :2",
        &[
            OracleBind::from(owner.to_ascii_uppercase()),
            OracleBind::from(trigger_name.to_ascii_uppercase()),
        ],
    )?;
    Ok(TriggerDescription { metadata })
}

/// Describe one view's definition metadata and columns. Owner + view name are
/// bound.
pub fn describe_view(
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

    let metadata = conn.query_optional_row(
        "SELECT owner, view_name, text_length, text \
         FROM all_views \
         WHERE owner = :1 AND view_name = :2",
        &binds,
    )?;
    let columns = describe_columns(conn, &owner, &view_name)?;
    Ok(ViewDescription { metadata, columns })
}

/// Columns of a table/view (owner + name bound).
pub fn describe_columns(
    conn: &dyn OracleConnection,
    owner: &str,
    table: &str,
) -> Result<Vec<OracleRow>, DbError> {
    let sql = "SELECT column_name, data_type, data_length, nullable, data_default \
               FROM all_tab_columns WHERE owner = :1 AND table_name = :2 \
               ORDER BY column_id";
    conn.query_rows(
        sql,
        &[
            OracleBind::from(owner.to_ascii_uppercase()),
            OracleBind::from(table.to_ascii_uppercase()),
        ],
    )
}

/// Constraint metadata for a table/view (owner + name bound).
pub fn describe_constraints(
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
        sql,
        &[
            OracleBind::from(owner.to_ascii_uppercase()),
            OracleBind::from(table.to_ascii_uppercase()),
        ],
    )
}

/// `get_ddl`: `DBMS_METADATA.GET_DDL` for an object. `object_type` is validated
/// against the allowlist (it cannot be bound); name + owner are bound.
pub fn get_ddl(
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
    // Storage/tablespace stripped for diff-friendliness.
    let sql = format!(
        "SELECT DBMS_METADATA.GET_DDL('{}', :1, :2) AS ddl FROM dual",
        object_type.to_ascii_uppercase()
    );
    let rows = conn.query_rows(
        &sql,
        &[
            OracleBind::from(name.to_ascii_uppercase()),
            OracleBind::from(owner.to_ascii_uppercase()),
        ],
    )?;
    Ok(rows.first().and_then(|r| r.text("DDL").map(str::to_owned)))
}

/// Compile errors for an owner, optionally narrowed to one object (`ALL_ERRORS`;
/// owner + name bound).
pub fn compile_errors(
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
        sql,
        &[OracleBind::from(owner.to_ascii_uppercase()), name_bind],
    )
}

/// Full-text search across `ALL_SOURCE` (owner + needle bound; row-capped).
pub fn search_source(
    conn: &dyn OracleConnection,
    owner: &str,
    needle: &str,
    max_rows: usize,
) -> Result<Vec<OracleRow>, DbError> {
    let sql = "SELECT name, type, line, text FROM all_source \
               WHERE owner = :1 AND UPPER(text) LIKE UPPER('%' || :2 || '%') \
               ORDER BY name, type, line \
               FETCH FIRST :3 ROWS ONLY";
    conn.query_rows(
        sql,
        &[
            OracleBind::from(owner.to_ascii_uppercase()),
            OracleBind::from(needle),
            OracleBind::from(max_rows as i64),
        ],
    )
}

/// Full source text for one object from `ALL_SOURCE`, capped by characters.
pub fn get_source(
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
    let rows = conn.query_rows(
        sql,
        &[
            OracleBind::from(owner.to_ascii_uppercase()),
            OracleBind::from(name.to_ascii_uppercase()),
            OracleBind::from(source_type),
        ],
    )?;

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
pub fn list_source_types(
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
    let rows = conn.query_rows(
        sql,
        &[
            OracleBind::from(owner.to_ascii_uppercase()),
            OracleBind::from(name.to_ascii_uppercase()),
        ],
    )?;
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
pub fn get_sources_by_name(
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
    max_chars: usize,
) -> Result<Vec<SourceText>, DbError> {
    list_source_types(conn, owner, name)?
        .into_iter()
        .map(|source_type| get_source(conn, owner, name, &source_type, max_chars))
        .collect()
}

/// Safe data sampling: the first `n` rows of a table. Schema/table are validated
/// identifiers (they cannot be bound); `n` is bound.
pub fn sample_rows(
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
        "SELECT * FROM {}.{} FETCH FIRST :1 ROWS ONLY",
        owner.to_ascii_uppercase(),
        table.to_ascii_uppercase()
    );
    conn.query_rows(&sql, &[OracleBind::from(n as i64)])
}

/// Read one CLOB/NCLOB/text value by an equality key, capped by characters.
///
/// The identifiers cannot be bound in Oracle SQL, so each identifier is
/// restricted to a simple unquoted Oracle identifier before interpolation. The
/// key value is always bound.
pub fn read_lob(
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
    let rows = conn.query_rows(&sql, &[OracleBind::from(pk_value)])?;
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

/// `explain_plan`: on a primary, `EXPLAIN PLAN FOR <sql>` then
/// `DBMS_XPLAN.DISPLAY`; on a read-only standby, `EXPLAIN PLAN` would write
/// `PLAN_TABLE` (§5.8), so it is refused there (route to `DISPLAY_CURSOR`).
/// `sql` must already have passed the classifier (a vetted SELECT).
pub fn explain_plan(
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
    conn.execute(&format!("EXPLAIN PLAN FOR {sql}"), &[])?;
    conn.query_rows(
        "SELECT plan_table_output FROM TABLE(DBMS_XPLAN.DISPLAY)",
        &[],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OracleBackend, OracleCell, OracleConnectionInfo};

    #[derive(Default)]
    struct CaptureMock {
        calls: std::sync::Mutex<Vec<(String, Vec<OracleBind>)>>,
    }

    impl OracleConnection for CaptureMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        fn ping(&self) -> Result<(), DbError> {
            Ok(())
        }

        fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }

        fn query_rows(&self, sql: &str, binds: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
            self.calls
                .lock()
                .expect("capture lock")
                .push((sql.to_owned(), binds.to_vec()));
            Ok(vec![])
        }

        fn execute(&self, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
            Ok(0)
        }

        fn commit(&self) -> Result<(), DbError> {
            Ok(())
        }

        fn rollback(&self) -> Result<(), DbError> {
            Ok(())
        }
    }

    struct SourceMock;

    impl OracleConnection for SourceMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        fn ping(&self) -> Result<(), DbError> {
            Ok(())
        }

        fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }

        fn query_rows(&self, _sql: &str, _binds: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
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

        fn execute(&self, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
            Ok(0)
        }

        fn commit(&self) -> Result<(), DbError> {
            Ok(())
        }

        fn rollback(&self) -> Result<(), DbError> {
            Ok(())
        }
    }

    struct MultiSourceMock;

    impl OracleConnection for MultiSourceMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        fn ping(&self) -> Result<(), DbError> {
            Ok(())
        }

        fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }

        fn query_rows(&self, sql: &str, binds: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
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

        fn execute(&self, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
            Ok(0)
        }

        fn commit(&self) -> Result<(), DbError> {
            Ok(())
        }

        fn rollback(&self) -> Result<(), DbError> {
            Ok(())
        }
    }

    struct LobMock;

    impl OracleConnection for LobMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }

        fn ping(&self) -> Result<(), DbError> {
            Ok(())
        }

        fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }

        fn query_rows(&self, _sql: &str, _binds: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
            Ok(vec![OracleRow {
                columns: vec![(
                    "LOB_VALUE".to_owned(),
                    OracleCell::new("CLOB", Some("abcdefgh".to_owned())),
                )],
            }])
        }

        fn execute(&self, _sql: &str, _binds: &[OracleBind]) -> Result<u64, DbError> {
            Ok(0)
        }

        fn commit(&self) -> Result<(), DbError> {
            Ok(())
        }

        fn rollback(&self) -> Result<(), DbError> {
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
        list_objects(&mock, None, Some("package"), Some("emp%"), 25).unwrap();

        let calls = mock.calls.lock().expect("capture lock");
        assert_eq!(calls.len(), 1);
        assert!(
            calls[0].0.contains("SELECT o.owner, o.object_name"),
            "query should include OWNER for cross-schema results"
        );
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
    fn describe_index_trigger_and_view_bind_names() {
        let index_mock = CaptureMock::default();
        let index = describe_index(&index_mock, "hr", "emp_ix").unwrap();
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
        let trigger = describe_trigger(&trigger_mock, "hr", "emp_biu").unwrap();
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
        let view = describe_view(&view_mock, "hr", "emp_v").unwrap();
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
        let constraints = describe_constraints(&mock, "hr", "employees").unwrap();
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
        let source = get_source(&SourceMock, "hr", "emp_api", "package_body", 8).unwrap();
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
        let sources = get_sources_by_name(&MultiSourceMock, "hr", "emp_api", 64).unwrap();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].object_type, "PACKAGE");
        assert_eq!(sources[1].object_type, "PACKAGE BODY");
        assert_eq!(sources[0].owner, "HR");
        assert_eq!(sources[0].name, "EMP_API");
        assert_eq!(sources[0].source, "BEGIN NULL; END;\n");
    }

    #[test]
    fn read_lob_caps_text_and_validates_identifiers() {
        let lob = read_lob(&LobMock, "hr", "docs", "body", "id", "42", 4)
            .unwrap()
            .expect("matched row");
        assert_eq!(lob.owner, "HR");
        assert_eq!(lob.table, "DOCS");
        assert_eq!(lob.column, "BODY");
        assert_eq!(lob.pk_column, "ID");
        assert_eq!(lob.value.as_deref(), Some("abcd"));
        assert_eq!(lob.char_count, 8);
        assert!(lob.truncated);

        let err = read_lob(&LobMock, "hr", "docs;drop", "body", "id", "42", 4)
            .expect_err("bad identifier refused");
        assert!(matches!(err, DbError::Query(_)));
    }

    // The query-builder shapes are exercised by the live tests; the validation
    // above is the injection-safety gate for the few interpolated positions.
}
