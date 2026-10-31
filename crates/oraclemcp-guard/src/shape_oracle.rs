//! Read-shape fallback port for statements sqlparser cannot parse
//! (pvlqq.10.18).
//!
//! The classifier is sqlparser-based, and sqlparser rejects real Oracle read
//! syntax (flashback `AS OF`, `KEEP (DENSE_RANK …)`, partition extensions,
//! `… DEFAULT … ON ERROR`). Such statements are refused today. A
//! [`StatementShapeOracle`] supplies the syntactic [`ReadShape`] of a
//! statement from a grammar that does accept it; the engine-free core never
//! parses it itself.
//!
//! [`fallback_read_statement`] renders that shape as canonical *analysis
//! SQL* and parses it with the same sqlparser dialect. Every relation,
//! alias, value-position name, call and subquery keeps its exact text and
//! block, so the unchanged classifier, query-block plan and catalog proof
//! run on it. Operators reduce to `COALESCE(…)`, which keeps each value in
//! its block, and Oracle-only modifiers move their values into the same
//! block's predicate. The analysis SQL is never executed; the original
//! statement is. Anything the renderer cannot represent exactly returns
//! `None`, which refuses.

use std::fmt::Write as _;

use sqlparser::ast::Statement;
use sqlparser::dialect::OracleDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer};

/// Deepest parenthesis nesting a statement may have before any shape oracle
/// is consulted. A grammar-backed oracle parses by recursive descent, so its
/// stack use grows with nesting; measured on the served engine (debug build,
/// 32 MiB stack) 96 levels parse safely, so 32 keeps a 3x margin.
pub const MAX_FALLBACK_NESTING: usize = 32;
/// Largest statement, in bytes, any shape oracle is consulted for.
pub const MAX_FALLBACK_SQL_BYTES: usize = 64 * 1024;

/// `true` when `sql` is small and shallow enough to hand to a shape oracle.
/// Parentheses inside literals, quoted identifiers and comments do not count;
/// text the tokenizer rejects is outside the budget.
#[must_use]
pub fn within_fallback_budget(sql: &str) -> bool {
    if sql.len() > MAX_FALLBACK_SQL_BYTES {
        return false;
    }
    let Ok(tokens) = Tokenizer::new(&OracleDialect {}, sql).tokenize() else {
        return false;
    };
    let mut depth = 0usize;
    for token in &tokens {
        match token {
            Token::LParen | Token::LBracket => {
                depth += 1;
                if depth > MAX_FALLBACK_NESTING {
                    return false;
                }
            }
            Token::RParen | Token::RBracket => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    true
}

/// Supplies the read shape of a statement sqlparser could not parse.
pub trait StatementShapeOracle: Send + Sync {
    /// The complete read shape of `sql`, or `None` when the statement is not
    /// exactly one representable read. `None` refuses.
    fn read_shape(&self, sql: &str) -> Option<ReadShape>;
}

/// The engine-free default: no fallback, so a parse failure stays refused.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoShapeOracle;

impl StatementShapeOracle for NoShapeOracle {
    fn read_shape(&self, _sql: &str) -> Option<ReadShape> {
        None
    }
}

/// One identifier exactly as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeIdent {
    pub text: String,
    pub quoted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadShape {
    pub query: ShapeQuery,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeQuery {
    pub ctes: Vec<ShapeCte>,
    pub first: ShapeBranch,
    pub rest: Vec<(ShapeSetOp, ShapeBranch)>,
    pub order_by: Vec<ShapeExpr>,
    pub row_limit: Vec<ShapeExpr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeCte {
    pub name: ShapeIdent,
    pub columns: Vec<ShapeIdent>,
    pub query: ShapeQuery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapeSetOp {
    Union,
    UnionAll,
    Intersect,
    Minus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShapeBranch {
    Select(Box<ShapeSelect>),
    Query(Box<ShapeQuery>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeSelect {
    pub distinct: bool,
    pub items: Vec<ShapeSelectItem>,
    pub from: Vec<ShapeFromItem>,
    pub where_clause: Option<ShapeExpr>,
    pub hierarchy: Option<ShapeHierarchy>,
    pub group_by: Vec<ShapeExpr>,
    pub having: Option<ShapeExpr>,
    pub order_by: Vec<ShapeExpr>,
    pub row_limit: Vec<ShapeExpr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShapeSelectItem {
    Wildcard,
    QualifiedWildcard(Vec<ShapeIdent>),
    Expr {
        expr: ShapeExpr,
        alias: Option<ShapeIdent>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeHierarchy {
    pub start_with: Option<ShapeExpr>,
    pub connect_by: ShapeExpr,
    pub nocycle: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeFromItem {
    pub source: ShapeTableRef,
    pub joins: Vec<ShapeJoin>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeTableRef {
    pub source: ShapeSource,
    pub alias: Option<ShapeIdent>,
    pub flashback: Vec<ShapeExpr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShapeSource {
    Table {
        name: Vec<ShapeIdent>,
        db_link: Option<Vec<ShapeIdent>>,
        partition: Option<ShapePartition>,
    },
    Derived(Box<ShapeQuery>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShapePartition {
    Named(Vec<ShapeIdent>),
    For(Vec<ShapeExpr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapeJoinKind {
    Inner,
    Left,
    Right,
    Full,
    Cross,
    CrossApply,
    OuterApply,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeJoin {
    pub kind: ShapeJoinKind,
    pub natural: bool,
    pub table: ShapeTableRef,
    pub on: Option<ShapeExpr>,
    pub using: Vec<ShapeIdent>,
    pub partition_by: Vec<ShapeExpr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapeSubqueryKind {
    Scalar,
    Exists,
    In,
    Quantified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShapeExpr {
    Literal,
    Star,
    Name(Vec<ShapeIdent>),
    Call {
        name: Vec<ShapeIdent>,
        builtin: bool,
        args: Vec<ShapeExpr>,
    },
    Subquery {
        kind: ShapeSubqueryKind,
        query: Box<ShapeQuery>,
    },
    Group(Vec<ShapeExpr>),
}

/// Ask `oracle` for the shape of `sql` and return the parsed analysis
/// statement: exactly one `Statement::Query`, or `None` (refuse).
#[must_use]
pub fn fallback_read_statement(sql: &str, oracle: &dyn StatementShapeOracle) -> Option<Statement> {
    fallback_read_analysis(sql, oracle).map(|(_, statement)| statement)
}

/// [`fallback_read_statement`] together with the analysis SQL text it was
/// parsed from. Text-level scans that look for calls must read this text: the
/// original Oracle text has `word (` clauses (`KEEP (…)`) that are not calls.
#[must_use]
pub fn fallback_read_analysis(
    sql: &str,
    oracle: &dyn StatementShapeOracle,
) -> Option<(String, Statement)> {
    if !within_fallback_budget(sql) {
        return None;
    }
    let shape = oracle.read_shape(sql)?;
    let analysis = analysis_sql(&shape)?;
    let mut statements = Parser::parse_sql(&OracleDialect {}, &analysis).ok()?;
    match (statements.pop(), statements.is_empty()) {
        (Some(statement @ Statement::Query(_)), true) => Some((analysis, statement)),
        _ => None,
    }
}

/// The canonical analysis SQL of `shape`, or `None` when some part cannot be
/// rendered with the same names, calls and blocks.
#[must_use]
pub fn analysis_sql(shape: &ReadShape) -> Option<String> {
    let mut out = String::new();
    render_query(&shape.query, &mut out)?;
    Some(out)
}

fn ident(part: &ShapeIdent, out: &mut String) -> Option<()> {
    if part.text.is_empty() {
        return None;
    }
    if part.quoted {
        if part.text.contains('"') {
            return None;
        }
        write!(out, "\"{}\"", part.text).ok()
    } else {
        if !part
            .text
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '$' | '#'))
        {
            return None;
        }
        out.push_str(&part.text);
        Some(())
    }
}

fn dotted(parts: &[ShapeIdent], out: &mut String) -> Option<()> {
    if parts.is_empty() {
        return None;
    }
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            out.push('.');
        }
        ident(part, out)?;
    }
    Some(())
}

fn render_query(query: &ShapeQuery, out: &mut String) -> Option<()> {
    if !query.ctes.is_empty() {
        out.push_str("WITH ");
        for (index, cte) in query.ctes.iter().enumerate() {
            if index > 0 {
                out.push_str(", ");
            }
            ident(&cte.name, out)?;
            if !cte.columns.is_empty() {
                out.push_str(" (");
                list(&cte.columns, out, ident)?;
                out.push(')');
            }
            out.push_str(" AS (");
            render_query(&cte.query, out)?;
            out.push(')');
        }
        out.push(' ');
    }
    // A query-block ORDER BY is the query's ORDER BY when the query has one
    // branch; inside a set branch it cannot be represented.
    let mut order_by = query.order_by.clone();
    if let ShapeBranch::Select(select) = &query.first
        && !select.order_by.is_empty()
    {
        if !query.rest.is_empty() {
            return None;
        }
        order_by.extend(select.order_by.iter().cloned());
    }
    render_branch(&query.first, out)?;
    for (op, branch) in &query.rest {
        if let ShapeBranch::Select(select) = branch
            && !select.order_by.is_empty()
        {
            return None;
        }
        out.push_str(match op {
            ShapeSetOp::Union => " UNION ",
            ShapeSetOp::UnionAll => " UNION ALL ",
            ShapeSetOp::Intersect => " INTERSECT ",
            ShapeSetOp::Minus => " MINUS ",
        });
        render_branch(branch, out)?;
    }
    if !order_by.is_empty() {
        out.push_str(" ORDER BY ");
        list(&order_by, out, render_expr)?;
    }
    // Row limits carry no names or subqueries in the supported subset; one
    // that did could not be placed in its block.
    let mut row_limit = query.row_limit.clone();
    if let ShapeBranch::Select(select) = &query.first {
        row_limit.extend(select.row_limit.iter().cloned());
    }
    if row_limit.iter().any(|expr| !is_name_free(expr)) {
        return None;
    }
    Some(())
}

fn render_branch(branch: &ShapeBranch, out: &mut String) -> Option<()> {
    match branch {
        ShapeBranch::Select(select) => render_select(select, out),
        ShapeBranch::Query(query) => {
            out.push('(');
            render_query(query, out)?;
            out.push(')');
            Some(())
        }
    }
}

fn render_select(select: &ShapeSelect, out: &mut String) -> Option<()> {
    if select.items.is_empty() || select.from.is_empty() {
        return None;
    }
    out.push_str("SELECT ");
    if select.distinct {
        out.push_str("DISTINCT ");
    }
    list(&select.items, out, render_item)?;
    out.push_str(" FROM ");
    // Values of Oracle-only table modifiers (flashback, PARTITION FOR, join
    // PARTITION BY without ON) join the block's predicate.
    let mut extra = Vec::new();
    for (index, item) in select.from.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        render_table_ref(&item.source, out, &mut extra)?;
        for join in &item.joins {
            render_join(join, out, &mut extra)?;
        }
    }
    let mut predicates = Vec::new();
    if let Some(condition) = &select.where_clause {
        predicates.push(condition.clone());
    }
    predicates.extend(extra);
    if !predicates.is_empty() {
        out.push_str(" WHERE ");
        for (index, predicate) in predicates.iter().enumerate() {
            if index > 0 {
                out.push_str(" AND ");
            }
            render_bool(predicate, out)?;
        }
    }
    if let Some(hierarchy) = &select.hierarchy {
        if let Some(start) = &hierarchy.start_with {
            out.push_str(" START WITH ");
            render_bool(start, out)?;
        }
        out.push_str(" CONNECT BY ");
        if hierarchy.nocycle {
            out.push_str("NOCYCLE ");
        }
        render_bool(&hierarchy.connect_by, out)?;
    }
    if !select.group_by.is_empty() {
        out.push_str(" GROUP BY ");
        list(&select.group_by, out, render_expr)?;
    }
    if let Some(having) = &select.having {
        out.push_str(" HAVING ");
        render_bool(having, out)?;
    }
    Some(())
}

fn render_item(item: &ShapeSelectItem, out: &mut String) -> Option<()> {
    match item {
        ShapeSelectItem::Wildcard => out.push('*'),
        ShapeSelectItem::QualifiedWildcard(parts) => {
            dotted(parts, out)?;
            out.push_str(".*");
        }
        ShapeSelectItem::Expr { expr, alias } => {
            render_expr(expr, out)?;
            if let Some(alias) = alias {
                out.push_str(" AS ");
                ident(alias, out)?;
            }
        }
    }
    Some(())
}

fn render_table_ref(
    table: &ShapeTableRef,
    out: &mut String,
    extra: &mut Vec<ShapeExpr>,
) -> Option<()> {
    match &table.source {
        ShapeSource::Table {
            name,
            db_link,
            partition,
        } => {
            if db_link.is_some() || name.len() > 2 {
                return None;
            }
            dotted(name, out)?;
            match partition {
                // A partition name is not a value; the relation is the table.
                None | Some(ShapePartition::Named(_)) => {}
                Some(ShapePartition::For(keys)) => extra.extend(keys.iter().cloned()),
            }
        }
        ShapeSource::Derived(query) => {
            out.push('(');
            render_query(query, out)?;
            out.push(')');
        }
    }
    extra.extend(table.flashback.iter().cloned());
    if let Some(alias) = &table.alias {
        out.push(' ');
        ident(alias, out)?;
    }
    Some(())
}

fn render_join(join: &ShapeJoin, out: &mut String, extra: &mut Vec<ShapeExpr>) -> Option<()> {
    let natural = if join.natural { "NATURAL " } else { "" };
    let keyword = match join.kind {
        ShapeJoinKind::Inner => "JOIN",
        ShapeJoinKind::Left => "LEFT JOIN",
        ShapeJoinKind::Right => "RIGHT JOIN",
        ShapeJoinKind::Full => "FULL JOIN",
        ShapeJoinKind::Cross => "CROSS JOIN",
        ShapeJoinKind::CrossApply => "CROSS APPLY",
        ShapeJoinKind::OuterApply => "OUTER APPLY",
    };
    let applies = matches!(
        join.kind,
        ShapeJoinKind::CrossApply | ShapeJoinKind::OuterApply
    );
    if (join.natural || applies || join.kind == ShapeJoinKind::Cross)
        && (join.on.is_some() || !join.using.is_empty())
    {
        return None;
    }
    write!(out, " {natural}{keyword} ").ok()?;
    let mut join_extra = Vec::new();
    render_table_ref(&join.table, out, &mut join_extra)?;
    join_extra.extend(join.partition_by.iter().cloned());
    if let Some(on) = &join.on {
        out.push_str(" ON ");
        render_bool(on, out)?;
        for value in &join_extra {
            out.push_str(" AND ");
            render_bool(value, out)?;
        }
    } else {
        if !join.using.is_empty() {
            out.push_str(" USING (");
            list(&join.using, out, ident)?;
            out.push(')');
        }
        extra.extend(join_extra);
    }
    Some(())
}

/// An expression in value position.
fn render_expr(expr: &ShapeExpr, out: &mut String) -> Option<()> {
    match expr {
        ShapeExpr::Literal => out.push('0'),
        ShapeExpr::Star => return None,
        ShapeExpr::Name(parts) => dotted(parts, out)?,
        ShapeExpr::Call { name, args, .. } => {
            dotted(name, out)?;
            out.push('(');
            for (index, arg) in args.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                if *arg == ShapeExpr::Star {
                    if args.len() != 1 {
                        return None;
                    }
                    out.push('*');
                } else {
                    render_expr(arg, out)?;
                }
            }
            out.push(')');
        }
        ShapeExpr::Subquery {
            kind: ShapeSubqueryKind::Scalar,
            query,
        } => {
            out.push('(');
            render_query(query, out)?;
            out.push(')');
        }
        ShapeExpr::Subquery { .. } => {
            out.push_str("CASE WHEN ");
            render_bool(expr, out)?;
            out.push_str(" THEN 1 END");
        }
        ShapeExpr::Group(parts) => match parts.as_slice() {
            [] => out.push('0'),
            [only] => render_expr(only, out)?,
            _ => {
                out.push_str("COALESCE(");
                list(parts, out, render_expr)?;
                out.push(')');
            }
        },
    }
    Some(())
}

/// An expression in predicate position.
fn render_bool(expr: &ShapeExpr, out: &mut String) -> Option<()> {
    match expr {
        ShapeExpr::Subquery { kind, query } => {
            match kind {
                ShapeSubqueryKind::Exists => out.push_str("EXISTS ("),
                ShapeSubqueryKind::In => out.push_str("1 IN ("),
                ShapeSubqueryKind::Quantified => out.push_str("1 = ANY ("),
                ShapeSubqueryKind::Scalar => out.push_str("1 = ("),
            }
            render_query(query, out)?;
            out.push(')');
        }
        _ => {
            out.push_str("COALESCE(");
            render_expr(expr, out)?;
            out.push_str(") IS NOT NULL");
        }
    }
    Some(())
}

fn list<T>(
    items: &[T],
    out: &mut String,
    render: impl Fn(&T, &mut String) -> Option<()>,
) -> Option<()> {
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        render(item, out)?;
    }
    Some(())
}

fn is_name_free(expr: &ShapeExpr) -> bool {
    match expr {
        ShapeExpr::Literal | ShapeExpr::Star => true,
        ShapeExpr::Group(parts) => parts.iter().all(is_name_free),
        ShapeExpr::Name(_) | ShapeExpr::Call { .. } | ShapeExpr::Subquery { .. } => false,
    }
}
