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

use asupersync::Cx;

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

fn normalize_compile_object_type(object_type: &str) -> String {
    object_type.trim().replace('_', " ").to_ascii_uppercase()
}

/// The DDL statement to compile `owner.name`. `object_type` is
/// `PACKAGE`/`PACKAGE BODY`/`PROCEDURE`/`FUNCTION`/`TRIGGER`/`TYPE`/`TYPE BODY`/
/// `VIEW`; underscores are accepted for MCP-friendly spellings such as
/// `PACKAGE_BODY`. PL/Scope and warning options are applied as compiler
/// parameters to this unit only; they never mutate the surrounding Oracle
/// session. Both options are invalid for views, which are not PL/SQL units.
/// DDL-level (step-up-gated). Returns an error if any name is not a simple
/// identifier (injection defense — object names are not bindable).
pub fn compile_object_statements(
    object_type: &str,
    owner: &str,
    name: &str,
    plscope: bool,
    warnings: bool,
) -> Result<Vec<String>, DbError> {
    if !is_simple_ident(owner) || !is_simple_ident(name) {
        return Err(DbError::Execute(format!(
            "invalid object identifier(s): {owner:?}.{name:?}"
        )));
    }
    let ty = normalize_compile_object_type(object_type);
    if ty == "VIEW" && (plscope || warnings) {
        return Err(DbError::UnsupportedFeature(
            "PL/Scope and PL/SQL warning compiler options apply only to PL/SQL units, not VIEW"
                .to_owned(),
        ));
    }
    let mut compile = match ty.as_str() {
        "PACKAGE BODY" => format!("ALTER PACKAGE {owner}.{name} COMPILE BODY"),
        "TYPE BODY" => format!("ALTER TYPE {owner}.{name} COMPILE BODY"),
        "PACKAGE" | "PROCEDURE" | "FUNCTION" | "TRIGGER" | "TYPE" | "VIEW" => {
            format!("ALTER {ty} {owner}.{name} COMPILE")
        }
        other => {
            return Err(DbError::Execute(format!(
                "unsupported object type for compile: {other}"
            )));
        }
    };
    if warnings {
        compile.push_str(" PLSQL_WARNINGS = 'ENABLE:ALL'");
    }
    if plscope {
        compile.push_str(" PLSCOPE_SETTINGS = 'IDENTIFIERS:ALL, STATEMENTS:ALL'");
    }
    if warnings || plscope {
        // Preserve every stored compiler setting the caller did not explicitly
        // request instead of reacquiring unrelated values from the session.
        compile.push_str(" REUSE SETTINGS");
    }
    Ok(vec![compile])
}

/// The DDL to recompile `owner.name` with PL/Scope identifier + statement
/// collection enabled. Retained for callers that only need the PL/Scope path.
pub fn recompile_with_plscope_statements(
    object_type: &str,
    owner: &str,
    name: &str,
) -> Result<Vec<String>, DbError> {
    compile_object_statements(object_type, owner, name, true, false)
}

fn row_i64(row: &crate::types::OracleRow, col: &str) -> i64 {
    row.parse_i64(col).unwrap_or(0)
}

/// Query the PL/Scope identifier cross-reference for `owner.name`
/// (`ALL_IDENTIFIERS`). Read-only.
pub async fn plscope_identifiers(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
    max_rows: usize,
) -> Result<Vec<PlscopeIdentifier>, DbError> {
    let rows = conn
        .query_rows(
            cx,
            "SELECT * FROM ( \
                 SELECT name, type, usage, line, col, signature FROM all_identifiers \
                 WHERE owner = :1 AND object_name = :2 ORDER BY line, col \
             ) WHERE ROWNUM <= :3",
            &[
                OracleBind::from(owner),
                OracleBind::from(name),
                OracleBind::from(max_rows.max(1) as i64),
            ],
        )
        .await?;
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
pub async fn plscope_statements(
    cx: &Cx,
    conn: &dyn OracleConnection,
    owner: &str,
    name: &str,
    max_rows: usize,
) -> Result<Vec<PlscopeStatement>, DbError> {
    let rows = conn
        .query_rows(
            cx,
            "SELECT * FROM ( \
                 SELECT type, line, sql_id FROM all_statements \
                 WHERE owner = :1 AND object_name = :2 ORDER BY line \
             ) WHERE ROWNUM <= :3",
            &[
                OracleBind::from(owner),
                OracleBind::from(name),
                OracleBind::from(max_rows.max(1) as i64),
            ],
        )
        .await?;
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
    fn recompile_embeds_plscope_in_one_unit_local_compile() {
        let s = recompile_with_plscope_statements("PACKAGE", "HR", "EMP_API").unwrap();
        assert_eq!(
            s,
            vec![
                "ALTER PACKAGE HR.EMP_API COMPILE PLSCOPE_SETTINGS = 'IDENTIFIERS:ALL, STATEMENTS:ALL' REUSE SETTINGS"
            ]
        );
        assert!(!s[0].contains("ALTER SESSION"));
    }

    #[test]
    fn compile_object_can_emit_plain_compile_only() {
        let s = compile_object_statements("PACKAGE", "HR", "EMP_API", false, false).unwrap();
        assert_eq!(s, vec!["ALTER PACKAGE HR.EMP_API COMPILE"]);
    }

    #[test]
    fn compile_options_are_unit_local_across_supported_shapes() {
        assert_eq!(
            compile_object_statements("PACKAGE BODY", "HR", "EMP_API", true, true).unwrap(),
            vec![
                "ALTER PACKAGE HR.EMP_API COMPILE BODY PLSQL_WARNINGS = 'ENABLE:ALL' PLSCOPE_SETTINGS = 'IDENTIFIERS:ALL, STATEMENTS:ALL' REUSE SETTINGS"
            ]
        );
        assert_eq!(
            compile_object_statements("TYPE_BODY", "HR", "EMP_T", false, true).unwrap(),
            vec!["ALTER TYPE HR.EMP_T COMPILE BODY PLSQL_WARNINGS = 'ENABLE:ALL' REUSE SETTINGS"]
        );
        assert_eq!(
            compile_object_statements("TRIGGER", "HR", "EMP_BIU", true, false).unwrap(),
            vec![
                "ALTER TRIGGER HR.EMP_BIU COMPILE PLSCOPE_SETTINGS = 'IDENTIFIERS:ALL, STATEMENTS:ALL' REUSE SETTINGS"
            ]
        );
    }

    #[test]
    fn view_rejects_plsql_only_options_but_plain_compile_remains_valid() {
        assert_eq!(
            compile_object_statements("VIEW", "HR", "EMP_V", false, false).unwrap(),
            vec!["ALTER VIEW HR.EMP_V COMPILE"]
        );
        for (plscope, warnings) in [(true, false), (false, true), (true, true)] {
            assert!(matches!(
                compile_object_statements("VIEW", "HR", "EMP_V", plscope, warnings),
                Err(DbError::UnsupportedFeature(_))
            ));
        }
    }

    #[test]
    fn compile_builder_validates_non_bindable_identifiers() {
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

    /// Mock returning one ALL_IDENTIFIERS row.
    struct IdentMock;
    #[async_trait::async_trait(?Send)]
    impl OracleConnection for IdentMock {
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
            _b: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
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
        async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
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
    fn plscope_identifiers_parses_rows() {
        let ids = run_with_cx(|cx| async move {
            plscope_identifiers(&cx, &IdentMock, "HR", "EMP_API", 25)
                .await
                .expect("query")
        });
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].name, "CALC");
        assert_eq!(ids[0].object_type, "FUNCTION");
        assert_eq!(ids[0].usage, "DECLARATION");
        assert_eq!(ids[0].line, 12);
        assert_eq!(ids[0].signature.as_deref(), Some("abc123"));
    }
}
