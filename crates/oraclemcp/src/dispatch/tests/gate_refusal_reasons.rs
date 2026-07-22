//! Read-only gate refusal-shape tests, relocated verbatim from
//! `dispatch/tests.rs` (C6 de-monolith, bead `oraclemcp-z3oit`): the
//! parameterization-hint, paren-less qualified-callable, and structured-reason
//! families. `super` resolves to the `tests` module, so every reference is
//! unchanged; no assertion or fixture was edited.

use super::*;

/// K7: the read-only gate attaches a "parameterize inline literals" next step
/// when a refused statement carries bind-safe literals, and omits it when there
/// is nothing to suggest. Purely additive — the class and refusal are unchanged.
mod parameterization_hint {
    use super::*;

    #[test]
    fn refused_write_with_inline_literal_gets_a_parameterization_hint() {
        let err = ensure_read_only("UPDATE orders SET status = 'X' WHERE id = 42")
            .expect_err("a write is refused by the read-only gate");
        assert_eq!(err.error_class, ErrorClass::OperatingLevelTooLow);
        let hint = err
            .next_steps
            .iter()
            .find(|s| s.contains("parameterize inline literals"))
            .expect("a parameterization hint is attached");
        assert!(
            hint.contains(":id"),
            "the hint suggests binding the literal named after its column: {hint}"
        );
    }

    #[test]
    fn refused_statement_without_bindable_literal_has_no_hint() {
        // A DDL refusal with no bind-safe literal must not fabricate a hint.
        let err = ensure_read_only("DROP TABLE orders")
            .expect_err("DDL is refused by the read-only gate");
        assert!(
            !err.next_steps.iter().any(|s| s.contains("parameterize")),
            "no parameterization hint when there is nothing bind-safe to suggest"
        );
    }
}

/// Bead .102: the served read-only gate refuses a **paren-less** qualified
/// function invocation. Oracle runs a zero-arg function with no `()`, so
/// `SELECT app_admin.run_ddl FROM dual` *calls* `run_ddl` — the classifier's
/// `ident(`-only UDF scan used to read it as a column reference and clear it to
/// Safe. The `DEFAULT_CLASSIFIER` opts into the qualified-callable guard so the
/// gate now fails closed, while genuine in-scope column references still pass.
mod parenless_qualified_callable_gate {
    use super::*;

    #[test]
    fn served_gate_refuses_parenless_qualified_callable() {
        for sql in [
            "SELECT app_admin.run_ddl FROM dual",
            "SELECT id, app_admin.run_ddl FROM orders",
            "SELECT s.nextval FROM dual",
            "SELECT hr.dangerous_fn FROM hr.employees",
            "SELECT app_admin.run_ddl FROM dual WHERE EXISTS (SELECT 1 FROM audit_log app_admin)",
            "SELECT employees.dangerous_fn FROM hr.employees e",
            "WITH c AS (SELECT dbms_random.value v FROM dual) SELECT c.v FROM dual dbms_random, c",
            "SELECT dbms_random.v FROM (SELECT dbms_random.value v FROM dual) dbms_random",
            "SELECT 1 FROM dual d JOIN dual x ON dbms_random.value > 0 JOIN dual dbms_random ON 1=1",
            "SELECT emp.dummy FROM dual \"emp\"",
            "SELECT run_ddl@oraclemcp_missing_link FROM dual",
            "SELECT dbms_random.value@oraclemcp_missing_link FROM dual dbms_random",
            "SELECT sys.dbms_random.value@oraclemcp_missing_link FROM dual sys",
            "SELECT dbms_random.value@prod.example.com FROM dual dbms_random",
        ] {
            let err = ensure_read_only(sql)
                .expect_err("a paren-less qualified callable must be refused by the served gate");
            assert!(
                matches!(
                    err.error_class,
                    ErrorClass::ForbiddenStatement | ErrorClass::OperatingLevelTooLow
                ),
                "refusal should be a guard block, got {:?} for {sql:?}",
                err.error_class
            );
        }
    }

    #[test]
    fn served_gate_still_admits_genuine_qualified_column_reads() {
        for sql in [
            "SELECT e.id, e.name FROM employees e WHERE e.id = 42",
            "SELECT hr.employees.salary FROM hr.employees",
            "SELECT id, name FROM employees WHERE dept = 10",
            "SELECT c.id FROM customers c WHERE EXISTS (SELECT 1 FROM orders o WHERE o.customer_id = c.id)",
            "SELECT \"Emp\".\"Name\" FROM employees \"Emp\"",
            "SELECT EMP.dummy FROM dual \"EMP\"",
            "SELECT \"EMP\".dummy FROM dual EMP",
            "SELECT d.dummy, q.v FROM dual d, LATERAL (SELECT d.dummy v FROM dual) q",
            "SELECT d.dummy, q.v FROM dual d CROSS APPLY (SELECT d.dummy v FROM dual) q",
            "SELECT j.doc.a FROM (SELECT json_col doc FROM json_docs) j",
            "SELECT e.address.city.name FROM employees e",
            "SELECT t.x FROM nested_docs d, TABLE(d.vals) t",
            "SELECT jt.a FROM json_docs d, JSON_TABLE(d.doc, '$' COLUMNS(a NUMBER PATH '$.a')) jt",
            "SELECT xt.a FROM xml_docs d, XMLTABLE('/r' PASSING d.doc COLUMNS a NUMBER PATH '.') xt",
            "SELECT employees.name FROM hr.employees@prod",
            "SELECT employees.name FROM employees@prod",
            "SELECT employees.name FROM hr.employees@prod.example.com",
            "SELECT employees.name FROM employees@prod.example.com",
            "SELECT \"run@ddl\" FROM (SELECT 1 \"run@ddl\" FROM dual)",
        ] {
            ensure_read_only(sql).unwrap_or_else(|e| {
                panic!("a genuine in-scope read must pass the gate: {sql:?} -> {e:?}")
            });
        }
    }
}

/// K8: the read-only gate attaches a structured "why blocked + minimal safe
/// rewrite" reason. Each refusal class returns a valid category, and a minimal
/// rewrite where one exists (or none, deferring to `suggested_tool`).
mod structured_reason {
    use super::*;
    use oraclemcp_error::ReasonCategory;

    fn reason_for(sql: &str) -> oraclemcp_error::StructuredReason {
        ensure_read_only(sql)
            .expect_err("statement is refused")
            .structured_reason
            .expect("a structured reason is attached to a guard refusal")
    }

    #[test]
    fn write_needs_higher_level_with_minimal_rewrite() {
        let reason = reason_for("UPDATE orders SET status = 'X' WHERE id = 42");
        assert_eq!(reason.category, ReasonCategory::RequiresHigherLevel);
        assert_eq!(reason.required_level.as_deref(), Some("READ_WRITE"));
        assert!(
            reason
                .minimal_rewrite
                .as_deref()
                .is_some_and(|r| r.contains("READ_WRITE")),
            "a level-gated write suggests running at the required level"
        );
    }

    #[test]
    fn multi_statement_batch_suggests_splitting() {
        // Trailing top-level SQL after a PL/SQL block rebalances the depth
        // counter — a stacking evasion the guard refuses fail-closed.
        let reason = reason_for("BEGIN NULL; END; DROP TABLE orders");
        assert_eq!(reason.category, ReasonCategory::MultiStatementBatch);
        assert!(
            reason
                .minimal_rewrite
                .as_deref()
                .is_some_and(|r| r.contains("its own")),
            "a stacked batch suggests submitting statements separately"
        );
    }

    #[test]
    fn dynamic_sql_has_category_but_no_minimal_rewrite() {
        let reason = reason_for("BEGIN EXECUTE IMMEDIATE 'DROP TABLE orders'; END;");
        assert_eq!(reason.category, ReasonCategory::DynamicSql);
        assert!(
            reason.minimal_rewrite.is_none(),
            "dynamic SQL has no single safe rewrite; defer to suggested_tool"
        );
        assert!(reason.offending_construct.is_some());
    }
}
