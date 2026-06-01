//! Tier-2 PL/Scope intelligence (plan §11.2; bead P2-7 / oracle-qmwz.3.7).
//! Opt-in deeper static intelligence from Oracle's **PL/Scope**: precise
//! compile-time identifier cross-references (`ALL_IDENTIFIERS`), the SQL
//! statement map (`ALL_STATEMENTS`), and lint (unused declarations, dead code,
//! `EXECUTE IMMEDIATE` audit). Requires recompiling the object with
//! `PLSCOPE_SETTINGS` on — the [`recompile_with_plscope_statements`] helper
//! emits that DDL (DDL-level, step-up-gated); the cross-reference queries are
//! read-only.
//!
//! Pure DB (no engine): deepens the Tier-1 offline calls/refs ([P1-5]) when
//! PL/Scope is available on the target.

use crate::connection::OracleConnection;
use crate::error::DbError;
use crate::types::OracleBind;

/// A PL/Scope identifier cross-reference row (`ALL_IDENTIFIERS`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PlscopeIdentifier {
    /// Identifier name.
    pub name: String,
    /// Identifier type (`VARIABLE`, `PROCEDURE`, `FUNCTION`, …).
    pub object_type: String,
    /// Usage (`DECLARATION`, `REFERENCE`, `CALL`, `ASSIGNMENT`, …).
    pub usage: String,
    /// Source line.
    pub line: i64,
    /// Source column.
    pub col: i64,
    /// PL/Scope signature (uniquely identifies a declaration).
    pub signature: Option<String>,
}

/// A PL/Scope SQL statement-map row (`ALL_STATEMENTS`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PlscopeStatement {
    /// Statement type (`SELECT`, `INSERT`, `EXECUTE IMMEDIATE`, …).
    pub statement_type: String,
    /// Source line.
    pub line: i64,
    /// `sql_id`, if assigned.
    pub sql_id: Option<String>,
}

/// A simple unquoted identifier (DDL object names cannot be bound — validated
/// to prevent injection in the recompile DDL).
fn is_simple_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$' || c == '#')
}

/// The DDL to recompile `owner.name` with PL/Scope identifier + statement
/// collection enabled. `object_type` is `PACKAGE`/`PACKAGE BODY`/`PROCEDURE`/
/// `FUNCTION`/`TRIGGER`/`TYPE`/`TYPE BODY`. DDL-level (step-up-gated). Returns an
/// error if any name is not a simple identifier (injection defense — object
/// names are not bindable).
pub fn recompile_with_plscope_statements(
    object_type: &str,
    owner: &str,
    name: &str,
) -> Result<Vec<String>, DbError> {
    if !is_simple_ident(owner) || !is_simple_ident(name) {
        return Err(DbError::Execute(format!(
            "invalid object identifier(s): {owner:?}.{name:?}"
        )));
    }
    let ty = object_type.trim().to_ascii_uppercase();
    let compile = match ty.as_str() {
        "PACKAGE BODY" => format!("ALTER PACKAGE {owner}.{name} COMPILE BODY"),
        "TYPE BODY" => format!("ALTER TYPE {owner}.{name} COMPILE BODY"),
        "PACKAGE" | "PROCEDURE" | "FUNCTION" | "TRIGGER" | "TYPE" | "VIEW" => {
            format!("ALTER {ty} {owner}.{name} COMPILE")
        }
        other => {
            return Err(DbError::Execute(format!(
                "unsupported object type for PL/Scope recompile: {other}"
            )));
        }
    };
    Ok(vec![
        "ALTER SESSION SET PLSCOPE_SETTINGS = 'IDENTIFIERS:ALL, STATEMENTS:ALL'".to_owned(),
        compile,
    ])
}

fn row_i64(row: &crate::types::OracleRow, col: &str) -> i64 {
    row.parse_i64(col).unwrap_or(0)
}

/// Query the PL/Scope identifier cross-reference for `owner.name`
/// (`ALL_IDENTIFIERS`). Read-only.
pub fn plscope_identifiers(
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
) -> Result<Vec<PlscopeIdentifier>, DbError> {
    let rows = conn.query_rows(
        "SELECT name, type, usage, line, col, signature FROM all_identifiers \
         WHERE owner = :1 AND object_name = :2 ORDER BY line, col",
        &[OracleBind::from(owner), OracleBind::from(name)],
    )?;
    Ok(rows
        .iter()
        .map(|r| PlscopeIdentifier {
            name: r.text("NAME").unwrap_or_default().to_owned(),
            object_type: r.text("TYPE").unwrap_or_default().to_owned(),
            usage: r.text("USAGE").unwrap_or_default().to_owned(),
            line: row_i64(r, "LINE"),
            col: row_i64(r, "COL"),
            signature: r.text("SIGNATURE").map(str::to_owned),
        })
        .collect())
}

/// Query the PL/Scope SQL statement map for `owner.name` (`ALL_STATEMENTS`).
/// Read-only.
pub fn plscope_statements(
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
) -> Result<Vec<PlscopeStatement>, DbError> {
    let rows = conn.query_rows(
        "SELECT type, line, sql_id FROM all_statements \
         WHERE owner = :1 AND object_name = :2 ORDER BY line",
        &[OracleBind::from(owner), OracleBind::from(name)],
    )?;
    Ok(rows
        .iter()
        .map(|r| PlscopeStatement {
            statement_type: r.text("TYPE").unwrap_or_default().to_owned(),
            line: row_i64(r, "LINE"),
            sql_id: r.text("SQL_ID").map(str::to_owned),
        })
        .collect())
}

fn is_use_site(usage: &str) -> bool {
    matches!(usage, "REFERENCE" | "CALL" | "ASSIGNMENT")
}

/// Lint: declared identifiers whose PL/Scope signature is never used
/// (referenced/called/assigned) — **unused declarations / dead code**. A
/// declaration without a signature is not flagged (can't prove it unused).
#[must_use]
pub fn find_unused_declarations(ids: &[PlscopeIdentifier]) -> Vec<String> {
    use std::collections::HashSet;
    let used: HashSet<&str> = ids
        .iter()
        .filter(|i| is_use_site(&i.usage))
        .filter_map(|i| i.signature.as_deref())
        .collect();
    ids.iter()
        .filter(|i| i.usage == "DECLARATION")
        .filter(|i| i.signature.as_deref().is_some_and(|s| !used.contains(s)))
        .map(|i| i.name.clone())
        .collect()
}

/// Lint: lines containing a dynamic-SQL `EXECUTE IMMEDIATE` (the dynamic-SQL
/// audit — these are the highest-risk statements for review).
#[must_use]
pub fn execute_immediate_audit(statements: &[PlscopeStatement]) -> Vec<i64> {
    statements
        .iter()
        .filter(|s| s.statement_type.eq_ignore_ascii_case("EXECUTE IMMEDIATE"))
        .map(|s| s.line)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{OracleBackend, OracleCell, OracleConnectionInfo, OracleRow};

    #[test]
    fn recompile_emits_plscope_settings_and_compile() {
        let s = recompile_with_plscope_statements("PACKAGE", "HR", "EMP_API").unwrap();
        assert_eq!(s.len(), 2);
        assert!(s[0].contains("PLSCOPE_SETTINGS") && s[0].contains("IDENTIFIERS:ALL"));
        assert_eq!(s[1], "ALTER PACKAGE HR.EMP_API COMPILE");
    }

    #[test]
    fn recompile_handles_package_body_and_validates_idents() {
        assert_eq!(
            recompile_with_plscope_statements("PACKAGE BODY", "HR", "EMP_API").unwrap()[1],
            "ALTER PACKAGE HR.EMP_API COMPILE BODY"
        );
        // Injection attempt in the (non-bindable) object name is rejected.
        assert!(recompile_with_plscope_statements("PACKAGE", "HR", "X; DROP TABLE T").is_err());
        assert!(recompile_with_plscope_statements("PACKAGE", "HR", "").is_err());
    }

    #[test]
    fn unused_declaration_lint_flags_only_unreferenced_signatures() {
        let ids = vec![
            // v_used: declared + referenced -> not flagged.
            PlscopeIdentifier {
                name: "V_USED".into(),
                object_type: "VARIABLE".into(),
                usage: "DECLARATION".into(),
                line: 1,
                col: 1,
                signature: Some("sigA".into()),
            },
            PlscopeIdentifier {
                name: "V_USED".into(),
                object_type: "VARIABLE".into(),
                usage: "REFERENCE".into(),
                line: 5,
                col: 1,
                signature: Some("sigA".into()),
            },
            // v_dead: declared, never used -> flagged.
            PlscopeIdentifier {
                name: "V_DEAD".into(),
                object_type: "VARIABLE".into(),
                usage: "DECLARATION".into(),
                line: 2,
                col: 1,
                signature: Some("sigB".into()),
            },
            // no signature -> not flagged (can't prove unused).
            PlscopeIdentifier {
                name: "V_UNK".into(),
                object_type: "VARIABLE".into(),
                usage: "DECLARATION".into(),
                line: 3,
                col: 1,
                signature: None,
            },
        ];
        let unused = find_unused_declarations(&ids);
        assert_eq!(unused, vec!["V_DEAD".to_owned()]);
    }

    #[test]
    fn execute_immediate_audit_finds_dynamic_sql() {
        let stmts = vec![
            PlscopeStatement {
                statement_type: "SELECT".into(),
                line: 3,
                sql_id: None,
            },
            PlscopeStatement {
                statement_type: "EXECUTE IMMEDIATE".into(),
                line: 10,
                sql_id: None,
            },
        ];
        assert_eq!(execute_immediate_audit(&stmts), vec![10]);
    }

    /// Mock returning one ALL_IDENTIFIERS row.
    struct IdentMock;
    impl OracleConnection for IdentMock {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        fn ping(&self) -> Result<(), DbError> {
            Ok(())
        }
        fn describe(&self) -> Result<OracleConnectionInfo, DbError> {
            Ok(OracleConnectionInfo::default())
        }
        fn query_rows(&self, sql: &str, _b: &[OracleBind]) -> Result<Vec<OracleRow>, DbError> {
            assert!(sql.to_ascii_lowercase().contains("all_identifiers"));
            Ok(vec![OracleRow {
                columns: vec![
                    (
                        "NAME".into(),
                        OracleCell::new("VARCHAR2", Some("CALC".into())),
                    ),
                    (
                        "TYPE".into(),
                        OracleCell::new("VARCHAR2", Some("FUNCTION".into())),
                    ),
                    (
                        "USAGE".into(),
                        OracleCell::new("VARCHAR2", Some("DECLARATION".into())),
                    ),
                    ("LINE".into(), OracleCell::new("NUMBER", Some("12".into()))),
                    ("COL".into(), OracleCell::new("NUMBER", Some("3".into()))),
                    (
                        "SIGNATURE".into(),
                        OracleCell::new("VARCHAR2", Some("abc123".into())),
                    ),
                ],
            }])
        }
        fn execute(&self, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
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
    fn plscope_identifiers_parses_rows() {
        let ids = plscope_identifiers(&IdentMock, "HR", "EMP_API").expect("query");
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].name, "CALC");
        assert_eq!(ids[0].object_type, "FUNCTION");
        assert_eq!(ids[0].usage, "DECLARATION");
        assert_eq!(ids[0].line, 12);
        assert_eq!(ids[0].signature.as_deref(), Some("abc123"));
    }
}
