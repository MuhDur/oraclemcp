#![no_main]

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use oraclemcp_guard::resolver::{
    CatalogGeneration, CatalogObjectKind, RawName, RawNamePart, SyntacticRole,
};
use oraclemcp_guard::scoped_grant::matcher::{ResolvedDmlTarget, match_sql};
use oraclemcp_guard::scoped_grant::rewrite::{render_grant_delete, render_grant_update};
use oraclemcp_guard::{
    ClosureFingerprints, ColumnIdent, EffectiveCeiling, ExecGrantBinding, GrantComparison,
    GrantContainer, GrantLimits, GrantOp, GrantOperand, GrantPredicateV1, GrantTargetIdentity,
    GrantValue, LastDdlTime, OperatingLevel, ScopedGrant, ScopedGrantRequest,
};
use sqlparser::ast::Statement;
use sqlparser::dialect::OracleDialect;
use sqlparser::parser::Parser;

fn col(text: &str) -> ColumnIdent {
    ColumnIdent::new(text).expect("static identifier")
}

fn make_grant(target: GrantTargetIdentity, verb: &str) -> ScopedGrant {
    ScopedGrant::new(
        ScopedGrantRequest {
            profile: "fuzz".into(),
            binding: ExecGrantBinding::new("s", "l", "p", 1),
            verbs: vec![verb.into()],
            target,
            columns: if verb == "UPDATE" {
                BTreeSet::from([col("STATUS")])
            } else {
                BTreeSet::new()
            },
            row_predicate: GrantPredicateV1::new(vec![GrantComparison {
                column: col("ID"),
                op: GrantOp::Eq,
                operand: GrantOperand::Single(GrantValue::number("1").unwrap()),
            }]),
            limits: GrantLimits {
                max_rows_per_statement: 5,
                max_statements: 20,
                max_total_rows: 20,
            },
            ttl: Duration::from_secs(10),
            commit_allowed: false,
            closure: ClosureFingerprints::new(),
            last_ddl_time: LastDdlTime::new("2026-09-01T00:00:00").unwrap(),
        },
        EffectiveCeiling {
            profile_max_level: OperatingLevel::ReadWrite,
            oauth_ceiling: None,
        },
        false,
        &[9; 32],
    )
    .expect("fixed fuzz grant is valid")
}

fn raw_owner(quoted: bool) -> RawNamePart {
    if quoted {
        RawNamePart::quoted("APP")
    } else {
        RawNamePart::unquoted("APP")
    }
}

fn raw_table(quoted: bool, lower: bool) -> RawNamePart {
    if lower {
        RawNamePart::quoted("orders")
    } else if quoted {
        RawNamePart::quoted("ORDERS")
    } else {
        RawNamePart::unquoted("ORDERS")
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let selector = data[0];
    let verb = if selector & 1 == 0 {
        "UPDATE"
    } else {
        "DELETE"
    };
    let sql_verb = if selector & 0x10 != 0 {
        verb.to_ascii_lowercase()
    } else {
        verb.to_owned()
    };
    let quote_owner = selector & 2 != 0;
    let quote_table = selector & 4 != 0;
    let lower_table = selector & 8 != 0;
    let owner = "APP".to_owned();
    let object_name = if lower_table { "orders" } else { "ORDERS" }.to_owned();
    let target = GrantTargetIdentity {
        owner: owner.clone(),
        object_name: object_name.clone(),
        object_id: 73,
        data_object_id: Some(73),
        container: GrantContainer {
            con_id: 3,
            con_uid: 9001,
        },
        edition: None,
        catalog_generation: CatalogGeneration(2),
        resolved_via: None,
    };
    let grant = make_grant(target.clone(), verb);
    let resolved = ResolvedDmlTarget {
        raw_name: RawName::new(
            [raw_owner(quote_owner), raw_table(quote_table, lower_table)],
            SyntacticRole::FromFactor,
        ),
        identity: target,
        object_kind: CatalogObjectKind::Table,
        bind_types: BTreeMap::new(),
    };

    // Keep generated SQL valid often enough to exercise rendering; arbitrary
    // bytes still select quoting, keyword case, and parenthesis variants.
    let bound = u16::from_le_bytes([selector, *data.get(1).unwrap_or(&0)]) % 100;
    let owner_part = if quote_owner { "\"APP\"" } else { "APP" };
    let table_part = if lower_table {
        "\"orders\""
    } else if quote_table {
        "\"ORDERS\""
    } else {
        "ORDERS"
    };
    let table = format!("{owner_part}.{table_part}");
    let id_column = if selector & 0x20 != 0 {
        "\"ID\""
    } else if selector & 0x40 != 0 {
        "id"
    } else {
        "ID"
    };
    let where_kw = if selector & 0x80 != 0 {
        "where"
    } else {
        "WHERE"
    };
    let where_sql = match (selector >> 4) & 3 {
        0 if selector & 0x80 != 0 => format!("{id_column} != {bound}"),
        0 => format!("{id_column} <> {bound}"),
        1 => format!("({id_column} >= {bound}) AND (TENANT_ID = 7)"),
        2 => format!("{id_column} IN ({bound}, {})", bound.saturating_add(1)),
        _ => format!(
            "{id_column} BETWEEN {bound} AND {}",
            bound.saturating_add(2)
        ),
    };
    let sql = if verb == "UPDATE" {
        let set_kw = if selector & 0x08 != 0 { "set" } else { "SET" };
        format!("{sql_verb} {table} {set_kw} STATUS = 'x' {where_kw} {where_sql}")
    } else {
        let from_kw = if selector & 0x08 != 0 { "from" } else { "FROM" };
        format!("{sql_verb} {from_kw} {table} {where_kw} {where_sql}")
    };
    if let Ok(matched) = match_sql(&grant, &sql, &resolved) {
        let p = GrantPredicateV1::new(vec![GrantComparison {
            column: col("ID"),
            op: GrantOp::Eq,
            operand: GrantOperand::Single(GrantValue::number("1").unwrap()),
        }]);
        let result = if verb == "UPDATE" {
            render_grant_update(&matched, &p, None, 5)
        } else {
            render_grant_delete(&matched, &p, None, 5)
        };
        if let Ok(rewrite) = result {
            assert_eq!(
                rewrite.parts().target().to_string(),
                format!("\"{owner}\".\"{object_name}\"")
            );
            assert_eq!(rewrite.binds().len(), 1);
            assert_eq!(rewrite.binds()[0].name(), "omcp_g1");
            assert!(Parser::parse_sql(&OracleDialect {}, rewrite.reclass_form()).is_ok());
            if verb == "UPDATE" {
                assert!(rewrite.executable_sql().contains("WITH CHECK OPTION"));
                assert!(Parser::parse_sql(&OracleDialect {}, rewrite.executable_sql()).is_err());
            } else {
                let parsed =
                    Parser::parse_sql(&OracleDialect {}, rewrite.executable_sql()).unwrap();
                assert!(matches!(parsed.as_slice(), [Statement::Delete(_)]));
            }
            assert!(rewrite.executable_sql().contains(":omcp_g1"));
            assert!(!rewrite.executable_sql().contains("UPDATE APP.\"orders\""));
        }
    }
});
