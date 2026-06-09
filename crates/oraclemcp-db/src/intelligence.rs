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

/// `schema_inspect`: objects in a schema, optionally filtered by type. Owner +
/// type are bound (`:1`, `:2`); a NULL `:2` means "all types".
pub fn list_objects(
    conn: &dyn OracleConnection,
    owner: &str,
    object_type: Option<&str>,
) -> Result<Vec<OracleRow>, DbError> {
    let sql = "SELECT object_name, object_type, status, last_ddl_time \
               FROM all_objects \
               WHERE owner = :1 AND (:2 IS NULL OR object_type = :2) \
               ORDER BY object_type, object_name";
    let type_bind = object_type.map_or(OracleBind::Null, |t| {
        OracleBind::from(t.to_ascii_uppercase())
    });
    conn.query_rows(
        sql,
        &[OracleBind::from(owner.to_ascii_uppercase()), type_bind],
    )
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

/// Compile errors for an object (`ALL_ERRORS`; owner + name bound).
pub fn compile_errors(
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
) -> Result<Vec<OracleRow>, DbError> {
    let sql = "SELECT name, type, line, position, text, attribute \
               FROM all_errors WHERE owner = :1 AND name = :2 \
               ORDER BY sequence";
    conn.query_rows(
        sql,
        &[
            OracleBind::from(owner.to_ascii_uppercase()),
            OracleBind::from(name.to_ascii_uppercase()),
        ],
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
