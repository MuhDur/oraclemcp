use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use oraclemcp_guard::resolver::{
    CatalogGeneration, CatalogObjectKind, RawName, RawNamePart, SyntacticRole,
};
use oraclemcp_guard::scoped_grant::matcher::{GrantMismatch, ResolvedDmlTarget, match_sql};
use oraclemcp_guard::scoped_grant::rewrite::{
    GrantRewriteError, render_grant_delete, render_grant_update,
};
use oraclemcp_guard::{
    ClosureFingerprints, ColumnIdent, EffectiveCeiling, ExecGrantBinding, GrantComparison,
    GrantContainer, GrantLimits, GrantOp, GrantOperand, GrantPredicateV1, GrantTargetIdentity,
    GrantValue, LastDdlTime, OperatingLevel, ScopedGrant, ScopedGrantRequest,
};
use proptest::prelude::*;
use sqlparser::ast::{BinaryOperator, Expr, Statement, Value};
use sqlparser::dialect::OracleDialect;
use sqlparser::parser::Parser;

fn col(value: &str) -> ColumnIdent {
    ColumnIdent::new(value).unwrap()
}

fn identity() -> GrantTargetIdentity {
    GrantTargetIdentity {
        owner: "APP".into(),
        object_name: "ORDERS".into(),
        object_id: 42,
        data_object_id: Some(43),
        container: GrantContainer {
            con_id: 3,
            con_uid: 99001,
        },
        edition: Some("ORA$BASE".into()),
        catalog_generation: CatalogGeneration(8),
        resolved_via: None,
    }
}

fn predicate(column: &str, value: &str) -> GrantPredicateV1 {
    GrantPredicateV1::new(vec![GrantComparison {
        column: col(column),
        op: GrantOp::Eq,
        operand: GrantOperand::Single(GrantValue::number(value).unwrap()),
    }])
}

fn grant(verb: &str) -> ScopedGrant {
    grant_for(verb, predicate("ID", "11"))
}

fn grant_for(verb: &str, row_predicate: GrantPredicateV1) -> ScopedGrant {
    let columns = if verb == "UPDATE" {
        BTreeSet::from([col("STATUS")])
    } else {
        BTreeSet::new()
    };
    ScopedGrant::new(
        ScopedGrantRequest {
            profile: "test-profile".into(),
            binding: ExecGrantBinding::new("session", "lane", "subject", 3),
            verbs: vec![verb.into()],
            target: identity(),
            columns,
            row_predicate,
            limits: GrantLimits {
                max_rows_per_statement: 5,
                max_statements: 20,
                max_total_rows: 20,
            },
            ttl: Duration::from_secs(600),
            commit_allowed: false,
            closure: ClosureFingerprints::new(),
            last_ddl_time: LastDdlTime::new("2026-09-01T00:00:00").unwrap(),
        },
        EffectiveCeiling {
            profile_max_level: OperatingLevel::ReadWrite,
            oauth_ceiling: None,
        },
        false,
        &[7; 32],
    )
    .unwrap()
}

fn resolved() -> ResolvedDmlTarget {
    ResolvedDmlTarget {
        raw_name: RawName::new(
            [
                RawNamePart::unquoted("APP"),
                RawNamePart::unquoted("ORDERS"),
            ],
            SyntacticRole::FromFactor,
        ),
        identity: identity(),
        object_kind: CatalogObjectKind::Table,
        bind_types: BTreeMap::new(),
    }
}

fn matched(sql: &str, verb: &str) -> oraclemcp_guard::scoped_grant::GrantMatch {
    match_sql(&grant(verb), sql, &resolved()).unwrap()
}

fn parse_one(sql: &str) -> Statement {
    let mut statements = Parser::parse_sql(&OracleDialect {}, sql).unwrap();
    assert_eq!(statements.len(), 1);
    statements.remove(0)
}

fn number(expr: &Expr, binds: &BTreeMap<String, i64>) -> i64 {
    match expr {
        Expr::Nested(inner) => number(inner, binds),
        Expr::Value(value) => match &value.value {
            Value::Number(text, _) => text.parse().unwrap(),
            Value::Placeholder(name) => binds[name.trim_start_matches(':')],
            _ => panic!("expected number literal"),
        },
        _ => panic!("expected number literal"),
    }
}

fn evaluate(expr: &Expr, row: &BTreeMap<&str, i64>, binds: &BTreeMap<String, i64>) -> bool {
    match expr {
        Expr::Nested(inner) => evaluate(inner, row, binds),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => evaluate(left, row, binds) && evaluate(right, row, binds),
        Expr::BinaryOp { left, op, right } => {
            let Expr::Identifier(identifier) = left.as_ref() else {
                if let Expr::Identifier(identifier) = right.as_ref() {
                    let value = number(left, binds);
                    return compare(value, op.clone(), row[identifier.value.as_str()]);
                }
                panic!("expected row identifier in comparison")
            };
            compare(
                row[identifier.value.as_str()],
                op.clone(),
                number(right, binds),
            )
        }
        _ => panic!("unsupported property expression: {expr}"),
    }
}

fn compare(left: i64, op: BinaryOperator, right: i64) -> bool {
    match op {
        BinaryOperator::Eq => left == right,
        BinaryOperator::NotEq => left != right,
        BinaryOperator::Lt => left < right,
        BinaryOperator::LtEq => left <= right,
        BinaryOperator::Gt => left > right,
        BinaryOperator::GtEq => left >= right,
        _ => panic!("unsupported property operator"),
    }
}

#[test]
fn sqlparser_rejects_update_inline_view_check_option() {
    let sql = "UPDATE (SELECT * FROM \"APP\".\"ORDERS\" WHERE \"ID\" = :omcp_g1 WITH CHECK OPTION) SET \"STATUS\" = 'ready' WHERE \"ID\" = 2";
    assert!(Parser::parse_sql(&OracleDialect {}, sql).is_err());
}

#[test]
fn grant_rewrite_update_template_parts_round_trip_and_reclassify() {
    let matched = matched(
        "UPDATE APP.ORDERS SET STATUS = 'ready' WHERE TENANT_ID = 7",
        "UPDATE",
    );
    let policy_q = Expr::BinaryOp {
        left: Box::new(Expr::Identifier(sqlparser::ast::Ident::new("TENANT_ID"))),
        op: BinaryOperator::Eq,
        right: Box::new(Expr::Value(Value::Number("7".into(), false).into())),
    };
    let rewrite = render_grant_update(&matched, &predicate("ID", "11"), Some(&policy_q), 5)
        .expect("validated server template");
    assert_eq!(
        rewrite.executable_sql(),
        "UPDATE (SELECT * FROM \"APP\".\"ORDERS\" WHERE \"ID\" = :omcp_g1 WITH CHECK OPTION) SET \"STATUS\" = 'ready' WHERE ((TENANT_ID = 7) AND (TENANT_ID = 7)) AND (ROWNUM <= 5)"
    );
    assert_eq!(rewrite.binds().len(), 1);
    assert_eq!(rewrite.binds()[0].name(), "omcp_g1");
    assert!(rewrite.reclass_form().contains("AND (\"ID\" = :omcp_g1)"));
    assert!(Parser::parse_sql(&OracleDialect {}, rewrite.executable_sql()).is_err());
    assert!(Parser::parse_sql(&OracleDialect {}, rewrite.reclass_form()).is_ok());
}

#[test]
fn grant_rewrite_delete_conjunct_is_parenthesized_and_reclassifies() {
    let matched = matched("DELETE FROM APP.ORDERS WHERE ID >= 1", "DELETE");
    let q = Expr::BinaryOp {
        left: Box::new(Expr::Identifier(sqlparser::ast::Ident::new("TENANT_ID"))),
        op: BinaryOperator::Eq,
        right: Box::new(Expr::Value(Value::Number("7".into(), false).into())),
    };
    let rewrite = render_grant_delete(&matched, &predicate("ID", "11"), Some(&q), 5).unwrap();
    assert!(
        rewrite
            .executable_sql()
            .contains("(ID >= 1) AND (TENANT_ID = 7)")
    );
    assert!(rewrite.executable_sql().contains("AND (ROWNUM <= 5)"));
    assert!(rewrite.executable_sql().contains("AND (\"ID\" = :omcp_g1)"));
    assert_eq!(rewrite.reclass_form(), rewrite.executable_sql());
    let Statement::Delete(delete) = parse_one(rewrite.executable_sql()) else {
        panic!("expected DELETE")
    };
    let selection = delete.selection.unwrap().to_string();
    assert!(selection.contains("ID >= 1"));
    assert!(selection.contains("TENANT_ID = 7"));
    assert!(selection.contains("ROWNUM <= 5"));
    assert!(selection.contains(":omcp_g1"));
}

#[test]
fn grant_rewrite_no_caller_text_concatenation() {
    let injection = matched(
        "DELETE FROM APP.ORDERS WHERE STATUS = ') OR (1=1'",
        "DELETE",
    );
    let safe = render_grant_delete(&injection, &predicate("ID", "11"), None, 5).unwrap();
    assert!(safe.executable_sql().contains("STATUS = ') OR (1=1'"));
    assert!(safe.executable_sql().contains("AND (\"ID\" = :omcp_g1)"));
    assert_eq!(
        Parser::parse_sql(&OracleDialect {}, safe.executable_sql())
            .unwrap()
            .len(),
        1
    );

    let boolean_injection = matched("DELETE FROM APP.ORDERS WHERE ID = 1 OR (1 = 1)", "DELETE");
    assert_eq!(
        render_grant_delete(&boolean_injection, &predicate("ID", "11"), None, 5).unwrap_err(),
        GrantRewriteError::UnsupportedExpression
    );
}

#[test]
fn grant_rewrite_requires_caller_where_and_validates_positive_integer_cap() {
    let no_where = matched("DELETE FROM APP.ORDERS", "DELETE");
    assert_eq!(
        render_grant_delete(&no_where, &predicate("ID", "11"), None, 5).unwrap_err(),
        GrantRewriteError::MissingCallerWhere
    );
    let update = matched("UPDATE APP.ORDERS SET STATUS = 'x' WHERE ID = 11", "UPDATE");
    assert_eq!(
        render_grant_update(&update, &predicate("ID", "11"), None, 0).unwrap_err(),
        GrantRewriteError::InvalidCap
    );
    assert_eq!(
        render_grant_update(&update, &predicate("ID", "11"), None, 6).unwrap_err(),
        GrantRewriteError::InvalidCap
    );
}

#[test]
fn grant_rewrite_refuses_set_predicate_column_before_rendering() {
    assert_eq!(
        match_sql(
            &grant("UPDATE"),
            "UPDATE APP.ORDERS SET ID = 12 WHERE ID = 11",
            &resolved()
        )
        .unwrap_err(),
        GrantMismatch::SetPredicateColumn {
            column: "ID".into()
        }
    );
}

#[test]
fn grant_rewrite_refuses_a_predicate_that_differs_from_the_matched_grant() {
    let update = matched("UPDATE APP.ORDERS SET STATUS = 'x' WHERE ID = 11", "UPDATE");
    assert_eq!(
        render_grant_update(&update, &predicate("ID", "10"), None, 5).unwrap_err(),
        GrantRewriteError::GrantPredicateMismatch
    );
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 10_000, .. ProptestConfig::default() })]

    #[test]
    fn prop_rewrite_never_widens_row_set(caller_floor in 0i64..12, p_id in 0i64..12, tenant in 0i64..9) {
        let sql = format!("DELETE FROM APP.ORDERS WHERE ID >= {caller_floor}");
        let p = predicate("ID", &p_id.to_string());
        let matched = match_sql(&grant_for("DELETE", p.clone()), &sql, &resolved()).unwrap();
        let q = Expr::BinaryOp {
            left: Box::new(Expr::Identifier(sqlparser::ast::Ident::new("TENANT_ID"))),
            op: BinaryOperator::Eq,
            right: Box::new(Expr::Value(Value::Number(tenant.to_string(), false).into())),
        };
        let rewrite = render_grant_delete(&matched, &p, Some(&q), 5).unwrap();
        let binds = BTreeMap::from([(
            rewrite.binds()[0].name().to_owned(),
            rewrite.binds()[0]
                .value()
                .expose_canonical()
                .parse::<i64>()
                .unwrap(),
        )]);
        let Statement::Delete(delete) = parse_one(rewrite.executable_sql()) else { panic!("expected DELETE") };
        let selection = delete.selection.unwrap();
        for id in 0..12i64 {
            for tenant_id in 0..9i64 {
                let row = BTreeMap::from([("ID", id), ("TENANT_ID", tenant_id), ("ROWNUM", 1)]);
                let selected = evaluate(&selection, &row, &binds);
                let expected = id >= caller_floor && id == p_id && tenant_id == tenant;
                prop_assert_eq!(selected, expected);
            }
        }
    }
}
