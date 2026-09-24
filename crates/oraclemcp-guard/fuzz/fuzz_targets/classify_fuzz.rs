#![no_main]
//! Fuzz the fail-closed classifier (bead T-CORPUS / 6.2): arbitrary input must
//! never panic, and the fail-closed invariants must hold for every input.
//!
//! Run: `cargo +nightly fuzz run classify_fuzz` (from crates/oraclemcp-guard).

use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;
use std::ops::ControlFlow;

use oraclemcp_guard::resolver::QuoteSemantics;
use oraclemcp_guard::{Classifier, DangerLevel, semantic_read_plan_checked};
use sqlparser::ast::{Query, Statement, TableFactor, Visit, Visitor};
use sqlparser::dialect::OracleDialect;
use sqlparser::parser::Parser;

#[derive(Default)]
struct AstBaseObjects {
    objects: BTreeSet<String>,
    cte_scopes: Vec<BTreeSet<String>>,
}

impl Visitor for AstBaseObjects {
    type Break = ();

    fn pre_visit_query(&mut self, query: &Query) -> ControlFlow<Self::Break> {
        let mut scope = self.cte_scopes.last().cloned().unwrap_or_default();
        if let Some(with) = &query.with {
            scope.extend(
                with.cte_tables
                    .iter()
                    .map(|cte| cte.alias.name.value.to_ascii_uppercase()),
            );
        }
        self.cte_scopes.push(scope);
        ControlFlow::Continue(())
    }

    fn post_visit_query(&mut self, _query: &Query) -> ControlFlow<Self::Break> {
        self.cte_scopes.pop();
        ControlFlow::Continue(())
    }

    fn pre_visit_table_factor(&mut self, factor: &TableFactor) -> ControlFlow<Self::Break> {
        if let TableFactor::Table {
            name, args: None, ..
        } = factor
        {
            let parts: Vec<_> = name.0.iter().filter_map(|part| part.as_ident()).collect();
            if parts.len() == 1
                && self
                    .cte_scopes
                    .last()
                    .is_some_and(|scope| scope.contains(&parts[0].value.to_ascii_uppercase()))
            {
                return ControlFlow::Continue(());
            }
            if !parts.is_empty() {
                self.objects.insert(
                    parts
                        .iter()
                        .map(|part| {
                            if part.quote_style.is_some() {
                                part.value.clone()
                            } else {
                                part.value.to_ascii_uppercase()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join("."),
                );
            }
        }
        ControlFlow::Continue(())
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(sql) = std::str::from_utf8(data) else {
        return;
    };
    let decision = Classifier::default().classify(sql);
    // Invariant 1: Forbidden carries no runnable level.
    if decision.danger == DangerLevel::Forbidden {
        assert!(
            decision.required_level.is_none(),
            "Forbidden must have no required_level"
        );
    } else {
        assert!(
            decision.required_level.is_some(),
            "non-Forbidden must have a required_level"
        );
    }
    // Invariant 2: re-classifying the same input is deterministic.
    let again = Classifier::default().classify(sql);
    assert_eq!(
        decision.danger, again.danger,
        "classification must be deterministic"
    );

    // The production planner independently cross-checks its relations against
    // query_base_objects. This second AST visitor makes that equality visible
    // to fuzzing, including sources in subqueries, CTEs and set branches.
    if let Ok(plan) = semantic_read_plan_checked(sql) {
        let parsed = Parser::parse_sql(&OracleDialect {}, sql)
            .expect("a planned query must parse as Oracle SQL");
        let [Statement::Query(query)] = parsed.as_slice() else {
            panic!("semantic plan exists for a non-query");
        };
        let mut ast = AstBaseObjects::default();
        let _ = query.visit(&mut ast);
        let planned: BTreeSet<String> = plan
            .relations
            .iter()
            .map(|relation| {
                relation
                    .parts
                    .iter()
                    .map(|part| match part.quoting {
                        QuoteSemantics::Quoted => part.text.clone(),
                        QuoteSemantics::Unquoted => part.text.to_ascii_uppercase(),
                    })
                    .collect::<Vec<_>>()
                    .join(".")
            })
            .collect();
        assert_eq!(
            planned, ast.objects,
            "semantic plan and independent AST base objects diverged for {sql:?}"
        );
    }
});
