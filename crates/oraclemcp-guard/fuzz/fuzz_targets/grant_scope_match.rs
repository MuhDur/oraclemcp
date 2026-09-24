#![no_main]
//! Fuzz the scoped-grant matcher against independent AST shape assertions.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use oraclemcp_guard::action_envelope::OracleBindType;
use oraclemcp_guard::resolver::{
    CatalogGeneration, CatalogObjectKind, QuoteSemantics, RawName, RawNamePart, SyntacticRole,
};
use oraclemcp_guard::scoped_grant::{GrantMatch, ResolvedDmlTarget, match_sql};
use oraclemcp_guard::{
    ClosureFingerprints, ColumnIdent, EffectiveCeiling, ExecGrantBinding, GrantComparison,
    GrantContainer, GrantLimits, GrantOp, GrantOperand, GrantPredicateV1, GrantTargetIdentity,
    GrantValue, GrantVerb, LastDdlTime, OperatingLevel, ScopedGrant, ScopedGrantRequest,
    SynonymIdentity,
};
use sqlparser::ast::{AssignmentTarget, DataType, Expr, SetExpr, Statement, TableFactor, Value};
use sqlparser::dialect::OracleDialect;
use sqlparser::parser::Parser;

const VALID: &str = "UPDATE APP.ORDERS SET STATUS = :s WHERE ID = :id";

fn target() -> GrantTargetIdentity {
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

fn grant_for(target: GrantTargetIdentity) -> ScopedGrant {
    ScopedGrant::new(
        ScopedGrantRequest {
            profile: "dev".into(),
            binding: ExecGrantBinding::new("session", "lane", "subject", 1),
            verbs: vec!["UPDATE".into()],
            target,
            columns: BTreeSet::from([ColumnIdent::new("STATUS").unwrap()]),
            row_predicate: GrantPredicateV1::new(vec![GrantComparison {
                column: ColumnIdent::new("TENANT_ID").unwrap(),
                op: GrantOp::Eq,
                operand: GrantOperand::Single(GrantValue::number("7").unwrap()),
            }]),
            limits: GrantLimits {
                max_rows_per_statement: 5,
                max_statements: 10,
                max_total_rows: 20,
            },
            ttl: Duration::from_secs(300),
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

fn grant() -> &'static ScopedGrant {
    static GRANT: OnceLock<ScopedGrant> = OnceLock::new();
    GRANT.get_or_init(|| grant_for(target()))
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
        identity: target(),
        object_kind: CatalogObjectKind::Table,
        bind_types: BTreeMap::from([
            ("S".into(), OracleBindType::String),
            ("ID".into(), OracleBindType::I64),
        ]),
    }
}

fn semantic_name(name: &sqlparser::ast::ObjectName) -> Vec<String> {
    name.0
        .iter()
        .map(|part| {
            let ident = part
                .as_ident()
                .expect("admitted target has identifier parts");
            if ident.quote_style.is_some() {
                ident.value.clone()
            } else {
                ident.value.to_ascii_uppercase()
            }
        })
        .collect()
}

fn scalar_rhs(expr: &Expr) -> bool {
    let mut expr = expr;
    let mut depth = 0;
    while let Expr::Nested(inner) = expr {
        depth += 1;
        if depth > 32 {
            return false;
        }
        expr = inner;
    }
    match expr {
        Expr::Value(value) => matches!(
            value.value,
            Value::Placeholder(_)
                | Value::Number(..)
                | Value::SingleQuotedString(_)
                | Value::NationalStringLiteral(_)
                | Value::Null
        ),
        Expr::TypedString(value) => value.data_type == DataType::Date,
        Expr::UnaryOp { op, expr } => {
            *op == sqlparser::ast::UnaryOperator::Minus
                && matches!(expr.as_ref(), Expr::Value(value) if matches!(value.value, Value::Number(..)))
        }
        _ => false,
    }
}

/// Independent structural assertions over the original AST and match output.
/// This does not reuse the matcher's helper functions.
fn admitted_shape_oracle(sql: &str, matched: &GrantMatch, resolved: &ResolvedDmlTarget) {
    let parsed = Parser::parse_sql(&OracleDialect {}, sql).expect("matched SQL must parse");
    assert_eq!(parsed.len(), 1);
    let statement = match &parsed[0] {
        Statement::Query(query) => {
            assert!(matched.cte().is_some());
            assert!(!query.with.as_ref().unwrap().recursive);
            assert!(query.order_by.is_none());
            assert!(query.limit_clause.is_none());
            assert!(query.fetch.is_none());
            assert!(query.locks.is_empty());
            assert!(query.for_clause.is_none());
            assert!(query.settings.is_none());
            assert!(query.format_clause.is_none());
            assert!(query.pipe_operators.is_empty());
            match query.body.as_ref() {
                SetExpr::Update(statement) => statement,
                _ => panic!("matched non-UPDATE CTE"),
            }
        }
        statement => statement,
    };
    let Statement::Update(update) = statement else {
        panic!("grant carried only UPDATE but matched another verb");
    };
    assert_eq!(matched.verb(), GrantVerb::Update);
    assert_eq!(matched.target(), &resolved.identity);
    assert_eq!(resolved.object_kind, CatalogObjectKind::Table);
    assert!(update.returning.is_none());
    assert!(update.output.is_none());
    assert!(update.from.is_none());
    assert!(update.table.joins.is_empty());
    assert!(update.optimizer_hints.is_empty());
    assert!(update.or.is_none());
    assert!(update.order_by.is_empty());
    assert!(update.limit.is_none());
    let TableFactor::Table {
        name,
        alias,
        args,
        with_hints,
        version,
        with_ordinality,
        partitions,
        json_path,
        sample,
        index_hints,
    } = &update.table.relation
    else {
        panic!("matched a non-table target");
    };
    assert!(alias.is_none() && args.is_none() && partitions.is_empty());
    assert!(with_hints.is_empty() && index_hints.is_empty());
    assert!(version.is_none() && json_path.is_none() && sample.is_none());
    assert!(!with_ordinality);
    let expected_name = resolved
        .raw_name
        .parts
        .iter()
        .map(|part| match part.quoting {
            QuoteSemantics::Unquoted => part.text.to_ascii_uppercase(),
            QuoteSemantics::Quoted => part.text.clone(),
        })
        .collect::<Vec<_>>();
    assert_eq!(semantic_name(name), expected_name);
    assert_eq!(matched.set_assignments().len(), update.assignments.len());
    for (source, (column, value)) in update.assignments.iter().zip(matched.set_assignments()) {
        let AssignmentTarget::ColumnName(name) = &source.target else {
            panic!("matched a tuple assignment");
        };
        assert_eq!(semantic_name(name), ["STATUS"]);
        assert_eq!(column.as_str(), "STATUS");
        assert!(
            scalar_rhs(&source.value),
            "matched a non-scalar SET expression"
        );
        assert_eq!(value.expression(), &source.value);
    }
    assert_eq!(matched.caller_where(), update.selection.as_ref());
}

fuzz_target!(|data: &[u8]| {
    if let Ok(sql) = std::str::from_utf8(data) {
        let resolved = resolved();
        if let Ok(matched) = match_sql(grant(), sql, &resolved) {
            admitted_shape_oracle(sql, &matched, &resolved);
        }
    }

    // Every input also selects a known one-axis mutation, so the harness
    // exercises actual scope refusals even when random bytes are not SQL.
    let mut mutated_target = resolved();
    let sql = match data.first().copied().unwrap_or_default() % 12 {
        0 => {
            mutated_target.identity.object_id += 1;
            VALID
        }
        1 => {
            mutated_target.identity.container.con_uid += 1;
            VALID
        }
        2 => {
            mutated_target.identity.resolved_via = Some(SynonymIdentity {
                owner: "APP".into(),
                name: "ORDERS".into(),
                object_id: 99,
            });
            VALID
        }
        3 => {
            mutated_target.object_kind = CatalogObjectKind::View;
            VALID
        }
        4 => {
            mutated_target.raw_name = mutated_target
                .raw_name
                .clone()
                .with_db_link(RawNamePart::unquoted("LINK"));
            VALID
        }
        5 => "UPDATE APP.ORDERS SET TENANT_ID = 8 WHERE ID = :id",
        6 => "UPDATE APP.ORDERS SET NOTE = :s WHERE ID = :id",
        7 => "UPDATE APP.ORDERS SET STATUS = UPPER(:s) WHERE ID = :id",
        8 => "UPDATE APP.ORDERS SET STATUS = :s + 1 WHERE ID = :id",
        9 => "DELETE FROM APP.ORDERS WHERE ID = :id",
        10 => "INSERT INTO APP.ORDERS (ID) VALUES (1)",
        _ => {
            mutated_target
                .bind_types
                .insert("EXTRA".into(), OracleBindType::I64);
            VALID
        }
    };
    assert!(match_sql(grant(), sql, &mutated_target).is_err());

    // Exercise successful case-folding, exact quoted spelling, and approved
    // synonym paths. The oracle checks the parsed target spelling independently.
    let mut resolved = resolved();
    let sql = match data.get(1).copied().unwrap_or_default() % 5 {
        0 => {
            resolved.raw_name = RawName::new(
                [
                    RawNamePart::unquoted("app"),
                    RawNamePart::unquoted("orders"),
                ],
                SyntacticRole::FromFactor,
            );
            "update app.orders set status = :s where id = :id"
        }
        1 => {
            resolved.raw_name = RawName::new(
                [RawNamePart::quoted("APP"), RawNamePart::quoted("ORDERS")],
                SyntacticRole::FromFactor,
            );
            "UPDATE \"APP\".\"ORDERS\" SET STATUS = :s WHERE ID = :id"
        }
        2 => {
            resolved.raw_name =
                RawName::new([RawNamePart::unquoted("ORDERS")], SyntacticRole::FromFactor);
            resolved.identity.resolved_via = Some(SynonymIdentity {
                owner: "APP".into(),
                name: "ORDERS".into(),
                object_id: 99,
            });
            "UPDATE orders SET STATUS = :s WHERE ID = :id"
        }
        3 => {
            resolved.raw_name =
                RawName::new([RawNamePart::quoted("orders")], SyntacticRole::FromFactor);
            resolved.identity.object_name = "orders".into();
            resolved.identity.object_id += 1;
            "UPDATE \"orders\" SET status = :s WHERE ID = :id"
        }
        _ => {
            resolved.raw_name =
                RawName::new([RawNamePart::unquoted("orders")], SyntacticRole::FromFactor);
            "UPDATE orders SET \"STATUS\" = :s WHERE ID = :id"
        }
    };
    let grant = grant_for(resolved.identity.clone());
    let matched = match_sql(&grant, sql, &resolved).expect("approved identifier variant");
    admitted_shape_oracle(sql, &matched, &resolved);
});
