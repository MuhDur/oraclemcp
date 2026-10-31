//! Engine-free rendering of read shapes into analysis SQL (pvlqq.10.18).

use oraclemcp_guard::shape_oracle::{
    NoShapeOracle, ReadShape, ShapeBranch, ShapeExpr, ShapeFromItem, ShapeIdent, ShapeJoin,
    ShapeJoinKind, ShapePartition, ShapeQuery, ShapeSelect, ShapeSelectItem, ShapeSetOp,
    ShapeSource, ShapeSubqueryKind, ShapeTableRef, StatementShapeOracle, analysis_sql,
    fallback_read_statement,
};
use sqlparser::ast::Statement;

fn ident(text: &str) -> ShapeIdent {
    ShapeIdent {
        text: text.into(),
        quoted: false,
    }
}

fn name(parts: &[&str]) -> ShapeExpr {
    ShapeExpr::Name(parts.iter().map(|part| ident(part)).collect())
}

fn table(name: &[&str], alias: Option<&str>) -> ShapeTableRef {
    ShapeTableRef {
        source: ShapeSource::Table {
            name: name.iter().map(|part| ident(part)).collect(),
            db_link: None,
            partition: None,
        },
        alias: alias.map(ident),
        flashback: Vec::new(),
    }
}

fn select(items: Vec<ShapeSelectItem>, from: Vec<ShapeFromItem>) -> ShapeSelect {
    ShapeSelect {
        distinct: false,
        items,
        from,
        where_clause: None,
        hierarchy: None,
        group_by: Vec::new(),
        having: None,
        order_by: Vec::new(),
        row_limit: Vec::new(),
    }
}

fn query(select: ShapeSelect) -> ShapeQuery {
    ShapeQuery {
        ctes: Vec::new(),
        first: ShapeBranch::Select(Box::new(select)),
        rest: Vec::new(),
        order_by: Vec::new(),
        row_limit: Vec::new(),
    }
}

fn from(table: ShapeTableRef) -> ShapeFromItem {
    ShapeFromItem {
        source: table,
        joins: Vec::new(),
    }
}

fn item(expr: ShapeExpr) -> ShapeSelectItem {
    ShapeSelectItem::Expr { expr, alias: None }
}

fn render(query: ShapeQuery) -> Option<String> {
    analysis_sql(&ReadShape { query })
}

struct Fixed(Option<ReadShape>);

impl StatementShapeOracle for Fixed {
    fn read_shape(&self, _sql: &str) -> Option<ReadShape> {
        self.0.clone()
    }
}

#[test]
fn no_shape_oracle_keeps_parse_failures_refused() {
    assert!(
        NoShapeOracle
            .read_shape("SELECT * FROM t AS OF SCN 1")
            .is_none()
    );
    assert!(fallback_read_statement("SELECT * FROM t AS OF SCN 1", &NoShapeOracle).is_none());
}

#[test]
fn flashback_and_partition_values_join_the_block_predicate() {
    let mut flashback = table(&["APP", "ORDERS"], Some("o"));
    flashback.flashback = vec![name(&["SYSTIMESTAMP"])];
    let sql = render(query(select(
        vec![item(name(&["o", "ID"]))],
        vec![from(flashback)],
    )))
    .unwrap();
    assert_eq!(
        sql,
        "SELECT o.ID FROM APP.ORDERS o WHERE COALESCE(SYSTIMESTAMP) IS NOT NULL"
    );

    let mut named = table(&["APP", "ORDERS"], None);
    if let ShapeSource::Table { partition, .. } = &mut named.source {
        *partition = Some(ShapePartition::Named(vec![ident("P1")]));
    }
    let sql = render(query(select(
        vec![ShapeSelectItem::Wildcard],
        vec![from(named)],
    )))
    .unwrap();
    assert_eq!(
        sql, "SELECT * FROM APP.ORDERS",
        "a partition name is not a value"
    );

    let mut keyed = table(&["APP", "ORDERS"], None);
    if let ShapeSource::Table { partition, .. } = &mut keyed.source {
        *partition = Some(ShapePartition::For(vec![name(&["STATUS"])]));
    }
    let sql = render(query(select(
        vec![ShapeSelectItem::Wildcard],
        vec![from(keyed)],
    )))
    .unwrap();
    assert_eq!(
        sql,
        "SELECT * FROM APP.ORDERS WHERE COALESCE(STATUS) IS NOT NULL"
    );
}

#[test]
fn join_partition_values_and_subquery_kinds_keep_their_block() {
    let join = ShapeJoin {
        kind: ShapeJoinKind::Right,
        natural: false,
        table: table(&["APP", "ITEMS"], Some("i")),
        on: Some(ShapeExpr::Group(vec![
            name(&["i", "ORDER_ID"]),
            name(&["o", "ID"]),
        ])),
        using: Vec::new(),
        partition_by: vec![name(&["o", "STATUS"])],
    };
    let mut block = select(
        vec![item(name(&["o", "ID"]))],
        vec![ShapeFromItem {
            source: table(&["APP", "ORDERS"], Some("o")),
            joins: vec![join],
        }],
    );
    let inner = query(select(
        vec![item(ShapeExpr::Literal)],
        vec![from(table(&["APP", "ITEMS"], None))],
    ));
    block.where_clause = Some(ShapeExpr::Group(vec![
        ShapeExpr::Subquery {
            kind: ShapeSubqueryKind::Exists,
            query: Box::new(inner.clone()),
        },
        ShapeExpr::Subquery {
            kind: ShapeSubqueryKind::In,
            query: Box::new(inner),
        },
    ]));
    let sql = render(query(block)).unwrap();
    assert_eq!(
        sql,
        "SELECT o.ID FROM APP.ORDERS o RIGHT JOIN APP.ITEMS i \
         ON COALESCE(COALESCE(i.ORDER_ID, o.ID)) IS NOT NULL AND COALESCE(o.STATUS) IS NOT NULL \
         WHERE COALESCE(COALESCE(CASE WHEN EXISTS (SELECT 0 FROM APP.ITEMS) THEN 1 END, \
         CASE WHEN 1 IN (SELECT 0 FROM APP.ITEMS) THEN 1 END)) IS NOT NULL"
    );
    let statement = fallback_read_statement(
        "unparsed",
        &Fixed(Some(ReadShape {
            query: query(select(
                vec![item(ShapeExpr::Call {
                    name: vec![ident("COUNT")],
                    builtin: true,
                    args: vec![ShapeExpr::Star],
                })],
                vec![from(table(&["APP", "ORDERS"], None))],
            )),
        })),
    );
    assert!(matches!(statement, Some(Statement::Query(_))));
}

#[test]
fn unrepresentable_shapes_render_nothing() {
    // DB link.
    let mut remote = table(&["ORDERS"], None);
    if let ShapeSource::Table { db_link, .. } = &mut remote.source {
        *db_link = Some(vec![ident("REMOTE")]);
    }
    assert!(
        render(query(select(
            vec![ShapeSelectItem::Wildcard],
            vec![from(remote)]
        )))
        .is_none()
    );

    // ORDER BY inside a set branch.
    let mut branch = select(vec![item(name(&["ID"]))], vec![from(table(&["B"], None))]);
    branch.order_by = vec![name(&["ID"])];
    let mut set = query(select(
        vec![item(name(&["ID"]))],
        vec![from(table(&["A"], None))],
    ));
    set.rest = vec![(ShapeSetOp::Union, ShapeBranch::Select(Box::new(branch)))];
    assert!(render(set).is_none());

    // `*` outside a call, and a name inside a row limit.
    assert!(
        render(query(select(
            vec![item(ShapeExpr::Star)],
            vec![from(table(&["A"], None))]
        )))
        .is_none()
    );
    let mut limited = query(select(
        vec![item(name(&["ID"]))],
        vec![from(table(&["A"], None))],
    ));
    limited.row_limit = vec![name(&["N"])];
    assert!(render(limited).is_none());

    // NATURAL with ON.
    let join = ShapeJoin {
        kind: ShapeJoinKind::Inner,
        natural: true,
        table: table(&["B"], None),
        on: Some(name(&["X"])),
        using: Vec::new(),
        partition_by: Vec::new(),
    };
    let block = select(
        vec![item(name(&["ID"]))],
        vec![ShapeFromItem {
            source: table(&["A"], None),
            joins: vec![join],
        }],
    );
    assert!(render(query(block)).is_none());

    // A quoted identifier containing a quote cannot be rendered exactly.
    let quoted = ShapeExpr::Name(vec![ShapeIdent {
        text: "a\"b".into(),
        quoted: true,
    }]);
    assert!(
        render(query(select(
            vec![item(quoted)],
            vec![from(table(&["A"], None))]
        )))
        .is_none()
    );
}

#[derive(Default)]
struct Counting(std::sync::atomic::AtomicUsize);

impl StatementShapeOracle for Counting {
    fn read_shape(&self, _sql: &str) -> Option<ReadShape> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        None
    }
}

#[test]
fn deep_or_large_statements_never_reach_the_oracle() {
    use oraclemcp_guard::shape_oracle::{MAX_FALLBACK_NESTING, MAX_FALLBACK_SQL_BYTES};
    let nested = |depth: usize| {
        format!(
            "SELECT {}1{} FROM t AS OF SCN 1",
            "(".repeat(depth),
            ")".repeat(depth)
        )
    };
    let oracle = Counting::default();
    let _ = fallback_read_statement(&nested(MAX_FALLBACK_NESTING), &oracle);
    assert_eq!(oracle.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    for sql in [
        nested(MAX_FALLBACK_NESTING + 1),
        nested(10_000),
        format!(
            "SELECT 1 FROM t AS OF SCN 1 WHERE 'x' = '{}'",
            "x".repeat(MAX_FALLBACK_SQL_BYTES)
        ),
    ] {
        assert!(fallback_read_statement(&sql, &oracle).is_none());
    }
    assert_eq!(
        oracle.0.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the oracle must not be consulted past the budget"
    );
    // Parentheses inside a literal are not nesting.
    let literal = format!("SELECT '{}' FROM t AS OF SCN 1", "(".repeat(100));
    let _ = fallback_read_statement(&literal, &oracle);
    assert_eq!(oracle.0.load(std::sync::atomic::Ordering::SeqCst), 2);
}
