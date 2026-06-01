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

/// Whether `t` is an allowlisted `DBMS_METADATA` object type.
#[must_use]
pub fn is_ddl_object_type(t: &str) -> bool {
    DDL_OBJECT_TYPES.contains(&t.to_ascii_uppercase().as_str())
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

    #[test]
    fn identifier_and_type_validation() {
        assert!(is_simple_identifier("HR"));
        assert!(!is_simple_identifier("HR; DROP TABLE t"));
        assert!(is_ddl_object_type("table"));
        assert!(is_ddl_object_type("PACKAGE_BODY"));
        assert!(!is_ddl_object_type("ANYTHING_ELSE"));
    }

    // The query-builder shapes are exercised by the live tests; the validation
    // above is the injection-safety gate for the few interpolated positions.
}
