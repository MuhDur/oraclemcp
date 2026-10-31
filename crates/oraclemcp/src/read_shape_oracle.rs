//! Engine-backed [`StatementShapeOracle`] (pvlqq.10.18): the served PL/SQL
//! engine's rule-whitelisted ANTLR read shape, converted into the guard's
//! engine-free mirror. The conversion is structural only; every refusal of
//! the engine stays a refusal here.

use oraclemcp_guard::shape_oracle as guard;
use oraclemcp_guard::shape_oracle::StatementShapeOracle;
use plsql_parser_antlr::read_shape as engine;

/// Read shapes from `plsql_parser_antlr::read_shape::read_query_shape`.
#[derive(Debug, Clone, Copy, Default)]
pub struct EngineReadShapeOracle;

/// The grammar parses by recursive descent; its frames are large, so it runs
/// on its own stack, sized for [`guard::MAX_FALLBACK_NESTING`] with margin.
const SHAPE_STACK_BYTES: usize = 32 * 1024 * 1024;

impl StatementShapeOracle for EngineReadShapeOracle {
    fn read_shape(&self, sql: &str) -> Option<guard::ReadShape> {
        // The guard checks this budget before consulting any oracle; checking
        // it here too keeps a direct call from overflowing the parse stack.
        if !guard::within_fallback_budget(sql) {
            return None;
        }
        crate::plsql_tools::validate_engine_source(sql).ok()?;
        let shape = std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("omcp-read-shape".to_owned())
                .stack_size(SHAPE_STACK_BYTES)
                .spawn_scoped(scope, || engine::read_query_shape(sql).ok())
                .ok()?
                .join()
                .ok()?
        })?;
        Some(guard::ReadShape {
            query: query(shape.query),
        })
    }
}

fn ident(part: engine::ShapeIdent) -> guard::ShapeIdent {
    guard::ShapeIdent {
        text: part.text,
        quoted: part.quoted,
    }
}

fn idents(parts: Vec<engine::ShapeIdent>) -> Vec<guard::ShapeIdent> {
    parts.into_iter().map(ident).collect()
}

fn exprs(items: Vec<engine::ShapeExpr>) -> Vec<guard::ShapeExpr> {
    items.into_iter().map(expr).collect()
}

fn query(query: engine::ShapeQuery) -> guard::ShapeQuery {
    guard::ShapeQuery {
        ctes: query
            .ctes
            .into_iter()
            .map(|cte| guard::ShapeCte {
                name: ident(cte.name),
                columns: idents(cte.columns),
                query: self::query(cte.query),
            })
            .collect(),
        first: branch(query.first),
        rest: query
            .rest
            .into_iter()
            .map(|(op, next)| (set_op(op), branch(next)))
            .collect(),
        order_by: exprs(query.order_by),
        row_limit: exprs(query.row_limit),
    }
}

fn set_op(op: engine::ShapeSetOp) -> guard::ShapeSetOp {
    match op {
        engine::ShapeSetOp::Union => guard::ShapeSetOp::Union,
        engine::ShapeSetOp::UnionAll => guard::ShapeSetOp::UnionAll,
        engine::ShapeSetOp::Intersect => guard::ShapeSetOp::Intersect,
        engine::ShapeSetOp::Minus => guard::ShapeSetOp::Minus,
    }
}

fn branch(branch: engine::ShapeBranch) -> guard::ShapeBranch {
    match branch {
        engine::ShapeBranch::Select(select) => {
            guard::ShapeBranch::Select(Box::new(self::select(*select)))
        }
        engine::ShapeBranch::Query(inner) => guard::ShapeBranch::Query(Box::new(query(*inner))),
    }
}

fn select(select: engine::ShapeSelect) -> guard::ShapeSelect {
    guard::ShapeSelect {
        distinct: select.distinct,
        items: select.items.into_iter().map(item).collect(),
        from: select
            .from
            .into_iter()
            .map(|from| guard::ShapeFromItem {
                source: table_ref(from.source),
                joins: from.joins.into_iter().map(join).collect(),
            })
            .collect(),
        where_clause: select.where_clause.map(expr),
        hierarchy: select.hierarchy.map(|hierarchy| guard::ShapeHierarchy {
            start_with: hierarchy.start_with.map(expr),
            connect_by: expr(hierarchy.connect_by),
            nocycle: hierarchy.nocycle,
        }),
        group_by: exprs(select.group_by),
        having: select.having.map(expr),
        order_by: exprs(select.order_by),
        row_limit: exprs(select.row_limit),
    }
}

fn item(item: engine::ShapeSelectItem) -> guard::ShapeSelectItem {
    match item {
        engine::ShapeSelectItem::Wildcard => guard::ShapeSelectItem::Wildcard,
        engine::ShapeSelectItem::QualifiedWildcard(parts) => {
            guard::ShapeSelectItem::QualifiedWildcard(idents(parts))
        }
        engine::ShapeSelectItem::Expr { expr: value, alias } => guard::ShapeSelectItem::Expr {
            expr: expr(value),
            alias: alias.map(ident),
        },
    }
}

fn table_ref(table: engine::ShapeTableRef) -> guard::ShapeTableRef {
    guard::ShapeTableRef {
        source: match table.source {
            engine::ShapeSource::Table {
                name,
                db_link,
                partition,
            } => guard::ShapeSource::Table {
                name: idents(name),
                db_link: db_link.map(idents),
                partition: partition.map(|partition| match partition {
                    engine::ShapePartition::Named(names) => {
                        guard::ShapePartition::Named(idents(names))
                    }
                    engine::ShapePartition::For(keys) => guard::ShapePartition::For(exprs(keys)),
                }),
            },
            engine::ShapeSource::Derived(inner) => {
                guard::ShapeSource::Derived(Box::new(query(*inner)))
            }
        },
        alias: table.alias.map(ident),
        flashback: exprs(table.flashback),
    }
}

fn join(join: engine::ShapeJoin) -> guard::ShapeJoin {
    guard::ShapeJoin {
        kind: match join.kind {
            engine::ShapeJoinKind::Inner => guard::ShapeJoinKind::Inner,
            engine::ShapeJoinKind::Left => guard::ShapeJoinKind::Left,
            engine::ShapeJoinKind::Right => guard::ShapeJoinKind::Right,
            engine::ShapeJoinKind::Full => guard::ShapeJoinKind::Full,
            engine::ShapeJoinKind::Cross => guard::ShapeJoinKind::Cross,
            engine::ShapeJoinKind::CrossApply => guard::ShapeJoinKind::CrossApply,
            engine::ShapeJoinKind::OuterApply => guard::ShapeJoinKind::OuterApply,
        },
        natural: join.natural,
        table: table_ref(join.table),
        on: join.on.map(expr),
        using: idents(join.using),
        partition_by: exprs(join.partition_by),
    }
}

fn expr(value: engine::ShapeExpr) -> guard::ShapeExpr {
    match value {
        engine::ShapeExpr::Literal => guard::ShapeExpr::Literal,
        engine::ShapeExpr::Star => guard::ShapeExpr::Star,
        engine::ShapeExpr::Name(parts) => guard::ShapeExpr::Name(idents(parts)),
        engine::ShapeExpr::Call {
            name,
            builtin,
            args,
        } => guard::ShapeExpr::Call {
            name: idents(name),
            builtin,
            args: exprs(args),
        },
        engine::ShapeExpr::Subquery { kind, query: inner } => guard::ShapeExpr::Subquery {
            kind: match kind {
                engine::ShapeSubqueryKind::Scalar => guard::ShapeSubqueryKind::Scalar,
                engine::ShapeSubqueryKind::Exists => guard::ShapeSubqueryKind::Exists,
                engine::ShapeSubqueryKind::In => guard::ShapeSubqueryKind::In,
                engine::ShapeSubqueryKind::Quantified => guard::ShapeSubqueryKind::Quantified,
            },
            query: Box::new(query(*inner)),
        },
        engine::ShapeExpr::Group(parts) => guard::ShapeExpr::Group(exprs(parts)),
    }
}
