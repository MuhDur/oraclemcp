use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use oraclemcp_guard::action_envelope::OracleBindType;
use oraclemcp_guard::resolver::{
    CatalogGeneration, CatalogObjectKind, RawName, RawNamePart, SyntacticRole,
};
use oraclemcp_guard::scoped_grant::matcher::{
    GrantMismatch, ResolvedDmlTarget, SetExpressionKind, match_sql, match_statement,
};
use oraclemcp_guard::{
    ClosureFingerprints, ColumnIdent, EffectiveCeiling, ExecGrantBinding, GrantComparison,
    GrantContainer, GrantLimits, GrantOp, GrantOperand, GrantPredicateV1, GrantTargetIdentity,
    GrantValue, LastDdlTime, OperatingLevel, ScopedGrant, ScopedGrantRequest, SynonymIdentity,
};
use proptest::prelude::*;
use sqlparser::ast::{Expr, MultiTableInsertType, SelectItem, Statement, TableFactor};
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

fn grant_with_verbs(target: GrantTargetIdentity, verbs: Vec<String>) -> ScopedGrant {
    let columns = if verbs.iter().any(|verb| verb == "DELETE") {
        BTreeSet::new()
    } else {
        BTreeSet::from([col("STATUS")])
    };
    ScopedGrant::new(
        ScopedGrantRequest {
            profile: "dev".into(),
            binding: ExecGrantBinding::new("session", "lane", "subject", 1),
            verbs,
            target,
            columns,
            row_predicate: GrantPredicateV1::new(vec![GrantComparison {
                column: col("TENANT_ID"),
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

fn grant_with(target: GrantTargetIdentity) -> ScopedGrant {
    grant_with_verbs(target, vec!["UPDATE".into()])
}

fn grant() -> ScopedGrant {
    grant_with(identity())
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
        bind_types: BTreeMap::from([
            ("S".into(), OracleBindType::String),
            ("ID".into(), OracleBindType::I64),
        ]),
    }
}

fn parse(sql: &str) -> Statement {
    let statements = Parser::parse_sql(&OracleDialect {}, sql).unwrap();
    assert_eq!(statements.len(), 1, "{sql}");
    statements.into_iter().next().unwrap()
}

fn check(
    sql: &str,
    resolved: &ResolvedDmlTarget,
) -> Result<oraclemcp_guard::scoped_grant::GrantMatch, GrantMismatch> {
    match_statement(&grant(), &parse(sql), resolved)
}

const VALID: &str = "UPDATE APP.ORDERS SET STATUS = :s WHERE ID = :id";

#[test]
fn scope_match_exact_update_admitted() {
    let matched = check(VALID, &resolved()).unwrap();
    assert_eq!(matched.verb().as_str(), "UPDATE");
    assert_eq!(matched.target(), &identity());
    assert_eq!(matched.set_assignments().len(), 1);
    assert_eq!(matched.set_assignments()[0].0, col("STATUS"));
    assert_eq!(
        matched.set_assignments()[0].1.bind_type(),
        Some(OracleBindType::String)
    );
    assert!(matched.caller_where().is_some());
    assert!(!format!("{matched:?}").contains("APP"));
}

#[test]
fn scope_match_exact_delete_admitted_only_with_delete_verb() {
    let sql = "DELETE FROM APP.ORDERS WHERE ID = :id";
    let mut target = resolved();
    target.bind_types.remove("S");
    assert_eq!(
        check(sql, &target).unwrap_err(),
        GrantMismatch::VerbNotGranted
    );
    let delete_grant = grant_with_verbs(identity(), vec!["DELETE".into()]);
    let matched = match_statement(&delete_grant, &parse(sql), &target).unwrap();
    assert_eq!(matched.verb().as_str(), "DELETE");
    assert!(matched.set_assignments().is_empty());
    assert!(matched.caller_where().is_some());
}

#[test]
fn scope_match_quoted_case_distinct() {
    let mut target = resolved();
    target.raw_name = RawName::new(
        [RawNamePart::unquoted("APP"), RawNamePart::quoted("orders")],
        SyntacticRole::FromFactor,
    );
    target.identity.object_name = "orders".into();
    target.identity.object_id += 1;
    assert_eq!(
        check(
            "UPDATE APP.\"orders\" SET STATUS = :s WHERE ID = :id",
            &target
        )
        .unwrap_err(),
        GrantMismatch::TargetIdentityMismatch
    );
    target.raw_name.parts[1] = RawNamePart::quoted("ORDERS");
    target.identity = identity();
    check(
        "UPDATE APP.\"ORDERS\" SET STATUS = :s WHERE ID = :id",
        &target,
    )
    .unwrap();
}

#[test]
fn scope_match_unqualified_resolves_current_schema() {
    let mut target = resolved();
    target.raw_name = RawName::new([RawNamePart::unquoted("ORDERS")], SyntacticRole::FromFactor);
    check("UPDATE orders SET status = :s WHERE id = :id", &target).unwrap();
}

#[test]
fn scope_match_private_synonym_to_other_owner_refused() {
    let mut target = resolved();
    target.raw_name = RawName::new([RawNamePart::unquoted("ORDERS")], SyntacticRole::FromFactor);
    target.identity.owner = "APP2".into();
    target.identity.object_id += 1;
    target.identity.resolved_via = Some(SynonymIdentity {
        owner: "APP".into(),
        name: "ORDERS".into(),
        object_id: 99,
    });
    assert_eq!(
        check("UPDATE ORDERS SET STATUS = :s WHERE ID = :id", &target).unwrap_err(),
        GrantMismatch::TargetIdentityMismatch
    );
}

#[test]
fn scope_match_synonym_path_change_refused() {
    let mut target = resolved();
    target.raw_name = RawName::new([RawNamePart::unquoted("ORDERS")], SyntacticRole::FromFactor);
    target.identity.resolved_via = Some(SynonymIdentity {
        owner: "APP".into(),
        name: "ORDERS".into(),
        object_id: 99,
    });
    let sql = "UPDATE ORDERS SET STATUS = :s WHERE ID = :id";
    assert_eq!(
        check(sql, &target).unwrap_err(),
        GrantMismatch::SynonymPathMismatch
    );
    let approved = grant_with(target.identity.clone());
    match_statement(&approved, &parse(sql), &target).unwrap();
    target.identity.resolved_via.as_mut().unwrap().object_id += 1;
    assert_eq!(
        match_statement(&approved, &parse(sql), &target).unwrap_err(),
        GrantMismatch::SynonymPathMismatch
    );
}

#[test]
fn scope_match_view_and_synonym_to_view_refused() {
    let mut target = resolved();
    target.object_kind = CatalogObjectKind::View;
    assert_eq!(
        check(VALID, &target).unwrap_err(),
        GrantMismatch::ViewTarget
    );
    target.identity.resolved_via = Some(SynonymIdentity {
        owner: "APP".into(),
        name: "ORDERS".into(),
        object_id: 99,
    });
    assert_eq!(
        check(VALID, &target).unwrap_err(),
        GrantMismatch::ViewTarget
    );
}

#[test]
fn scope_match_dblink_refused() {
    let mut target = resolved();
    target.raw_name = target
        .raw_name
        .clone()
        .with_db_link(RawNamePart::unquoted("LINK"));
    assert_eq!(
        check(VALID, &target).unwrap_err(),
        GrantMismatch::RemoteObject
    );
    let sql = "UPDATE APP.ORDERS@LINK SET STATUS = :s WHERE ID = :id";
    assert_eq!(
        check(sql, &resolved()).unwrap_err(),
        GrantMismatch::RemoteObject
    );
}

#[test]
fn scope_match_partition_extended_refused() {
    let mut statement = parse(VALID);
    let Statement::Update(update) = &mut statement else {
        unreachable!()
    };
    let TableFactor::Table { partitions, .. } = &mut update.table.relation else {
        unreachable!()
    };
    partitions.push(sqlparser::ast::Ident::new("P1"));
    assert_eq!(
        match_statement(&grant(), &statement, &resolved()).unwrap_err(),
        GrantMismatch::PartitionExtended
    );
}

#[test]
fn scope_match_table_collection_refused() {
    let mut statement = parse(VALID);
    let Statement::Update(update) = &mut statement else {
        unreachable!()
    };
    update.table.relation = TableFactor::TableFunction {
        expr: Expr::Identifier(sqlparser::ast::Ident::new("COLLECTION")),
        alias: None,
    };
    assert_eq!(
        match_statement(&grant(), &statement, &resolved()).unwrap_err(),
        GrantMismatch::CollectionExpression
    );
}

#[test]
fn scope_match_multi_table_refused() {
    let sql = "UPDATE APP.ORDERS SET STATUS = :s FROM APP.OTHER WHERE ID = :id";
    assert_eq!(
        check(sql, &resolved()).unwrap_err(),
        GrantMismatch::MultiTarget
    );
    let sql = "DELETE FROM APP.ORDERS USING APP.OTHER WHERE ID = :id";
    assert_eq!(
        check(sql, &resolved()).unwrap_err(),
        GrantMismatch::MultiTarget
    );
}

#[test]
fn scope_match_insert_refused_typed() {
    assert_eq!(
        check("INSERT INTO APP.ORDERS (ID) VALUES (1)", &resolved()).unwrap_err(),
        GrantMismatch::InsertRefused
    );
}

#[test]
fn scope_match_merge_refused_typed() {
    assert_eq!(check("MERGE INTO APP.ORDERS USING APP.OTHER ON (APP.ORDERS.ID = APP.OTHER.ID) WHEN MATCHED THEN UPDATE SET STATUS = 'x'", &resolved()).unwrap_err(), GrantMismatch::MergeRefused);
}

#[test]
fn scope_match_insert_all_first_refused() {
    for sql in [
        "INSERT ALL INTO APP.ORDERS (ID) VALUES (1) INTO APP.OTHER (ID) VALUES (1) SELECT 1 FROM DUAL",
        "INSERT FIRST WHEN 1 = 1 THEN INTO APP.ORDERS (ID) VALUES (1) SELECT 1 FROM DUAL",
    ] {
        assert_eq!(
            match_sql(&grant(), sql, &resolved()).unwrap_err(),
            GrantMismatch::MultiTableInsertRefused
        );
    }
    for multi in [MultiTableInsertType::All, MultiTableInsertType::First] {
        let mut stmt = parse("INSERT INTO APP.ORDERS (ID) VALUES (1)");
        let Statement::Insert(insert) = &mut stmt else {
            unreachable!()
        };
        insert.multi_table_insert_type = Some(multi);
        assert_eq!(
            match_statement(&grant(), &stmt, &resolved()).unwrap_err(),
            GrantMismatch::MultiTableInsertRefused
        );
    }
}

#[test]
fn scope_match_cte_dml_refused_unless_single_target() {
    let sql =
        "WITH X AS (SELECT 1 AS ID FROM DUAL) UPDATE APP.ORDERS SET STATUS = :s WHERE ID = :id";
    let matched = check(sql, &resolved()).unwrap();
    assert!(matched.cte().is_some());
    let sql =
        "WITH ORDERS AS (SELECT 1 AS ID FROM DUAL) UPDATE ORDERS SET STATUS = :s WHERE ID = :id";
    let mut target = resolved();
    target.raw_name = RawName::new([RawNamePart::unquoted("ORDERS")], SyntacticRole::FromFactor);
    assert_eq!(
        check(sql, &target).unwrap_err(),
        GrantMismatch::CteDmlUnresolved
    );
}

fn set_error(sql: &str) -> GrantMismatch {
    check(sql, &resolved()).unwrap_err()
}

#[test]
fn scope_match_set_subquery_refused() {
    assert_eq!(
        set_error("UPDATE APP.ORDERS SET STATUS = (SELECT 'x' FROM DUAL) WHERE ID = :id"),
        GrantMismatch::SetExpressionRefused {
            kind: SetExpressionKind::Subquery
        }
    );
}

#[test]
fn scope_match_set_returning_refused() {
    assert_eq!(
        match_sql(
            &grant(),
            "UPDATE APP.ORDERS SET STATUS = :s WHERE ID = :id RETURNING ID INTO :x",
            &resolved()
        )
        .unwrap_err(),
        GrantMismatch::ReturningRefused
    );
    let mut stmt = parse(VALID);
    let Statement::Update(update) = &mut stmt else {
        unreachable!()
    };
    update.returning = Some(vec![SelectItem::UnnamedExpr(Expr::Identifier(
        sqlparser::ast::Ident::new("ID"),
    ))]);
    assert_eq!(
        match_statement(&grant(), &stmt, &resolved()).unwrap_err(),
        GrantMismatch::ReturningRefused
    );
}

#[test]
fn scope_match_set_nextval_refused() {
    assert_eq!(
        set_error("UPDATE APP.ORDERS SET STATUS = s.NEXTVAL WHERE ID = :id"),
        GrantMismatch::SetExpressionRefused {
            kind: SetExpressionKind::Sequence
        }
    );
    assert_eq!(
        set_error("UPDATE APP.ORDERS SET ID = s.NEXTVAL WHERE ID = :id"),
        GrantMismatch::SetExpressionRefused {
            kind: SetExpressionKind::Sequence
        }
    );
}

#[test]
fn scope_match_set_function_refused() {
    assert_eq!(
        set_error("UPDATE APP.ORDERS SET STATUS = UPPER(:s) WHERE ID = :id"),
        GrantMismatch::SetExpressionRefused {
            kind: SetExpressionKind::Function
        }
    );
}

#[test]
fn scope_match_set_arithmetic_refused() {
    assert_eq!(
        set_error("UPDATE APP.ORDERS SET STATUS = :s + 1 WHERE ID = :id"),
        GrantMismatch::SetExpressionRefused {
            kind: SetExpressionKind::Arithmetic
        }
    );
}

#[test]
fn scope_match_set_predicate_column_refused() {
    assert_eq!(
        set_error("UPDATE APP.ORDERS SET TENANT_ID = 8 WHERE ID = :id"),
        GrantMismatch::SetPredicateColumn {
            column: "TENANT_ID".into()
        }
    );
}

#[test]
fn scope_match_ungranted_column_refused() {
    assert_eq!(
        set_error("UPDATE APP.ORDERS SET NOTE = :s WHERE ID = :id"),
        GrantMismatch::ColumnNotGranted {
            column: "NOTE".into()
        }
    );
    assert_eq!(
        set_error("UPDATE APP.ORDERS SET \"status\" = :s WHERE ID = :id"),
        GrantMismatch::ColumnNotGranted {
            column: "status".into()
        }
    );
}

#[test]
fn scope_match_default_and_tuple_refused() {
    assert_eq!(
        set_error("UPDATE APP.ORDERS SET STATUS = DEFAULT WHERE ID = :id"),
        GrantMismatch::SetExpressionRefused {
            kind: SetExpressionKind::Default
        }
    );
    let mut statement = parse(VALID);
    let Statement::Update(update) = &mut statement else {
        unreachable!()
    };
    update.assignments[0].target = sqlparser::ast::AssignmentTarget::Tuple(vec![
        sqlparser::ast::ObjectName::from(vec![sqlparser::ast::Ident::new("STATUS")]),
    ]);
    assert_eq!(
        match_statement(&grant(), &statement, &resolved()).unwrap_err(),
        GrantMismatch::SetExpressionRefused {
            kind: SetExpressionKind::MultiColumnTuple
        }
    );
}

#[test]
fn scope_match_reserved_bind_prefix_refused() {
    let mut target = resolved();
    target.bind_types.remove("ID");
    target
        .bind_types
        .insert("OMCP_G1".into(), OracleBindType::I64);
    assert_eq!(
        check(
            "UPDATE APP.ORDERS SET STATUS = :s WHERE ID = :omcp_g1",
            &target
        )
        .unwrap_err(),
        GrantMismatch::ReservedBindName
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]
    #[test]
    fn prop_out_of_scope_mutation_never_admitted(field in 0u8..13, change in 1u8..=255) {
        let mut target = resolved();
        let sql = match field {
            0 => {
                target.identity.object_id += u64::from(change);
                VALID
            }
            1 => {
                target.identity.container.con_uid += u64::from(change);
                VALID
            }
            2 => {
                target.identity.resolved_via = Some(SynonymIdentity {
                    owner: "APP".into(), name: "ORDERS".into(), object_id: u64::from(change),
                });
                VALID
            }
            3 => {
                target.object_kind = CatalogObjectKind::View;
                VALID
            }
            4 => {
                target.raw_name = target.raw_name.clone().with_db_link(RawNamePart::unquoted("LINK"));
                VALID
            }
            5 => "UPDATE APP.ORDERS SET TENANT_ID = 8 WHERE ID = :id",
            6 => "UPDATE APP.ORDERS SET NOTE = :s WHERE ID = :id",
            7 => "UPDATE APP.ORDERS SET STATUS = UPPER(:s) WHERE ID = :id",
            8 => "UPDATE APP.ORDERS SET STATUS = :s + 1 WHERE ID = :id",
            9 => "DELETE FROM APP.ORDERS WHERE ID = :id",
            10 => "INSERT INTO APP.ORDERS (ID) VALUES (1)",
            11 => {
                target.bind_types.insert(format!("EXTRA_{change}"), OracleBindType::I64);
                VALID
            }
            12 => {
                target.raw_name.parts[1] = RawNamePart::quoted("orders");
                target.identity.object_name = "orders".into();
                target.identity.object_id += u64::from(change);
                "UPDATE APP.\"orders\" SET STATUS = :s WHERE ID = :id"
            }
            _ => unreachable!(),
        };
        prop_assert!(check(sql, &target).is_err(), "admitted field={field} change={change}");
    }
}
