//! Server-owned AST templates for scoped-grant UPDATE and DELETE.
//!
//! sqlparser 0.62 cannot represent Oracle's UPDATE inline-view CHECK OPTION
//! form. UPDATE therefore uses a deliberately server-rendered envelope; all
//! embedded expressions and assignments remain validated AST nodes. DELETE
//! uses an ordinary parsed statement with the grant predicate as a separate
//! parenthesized conjunct.

use std::collections::BTreeSet;
use std::fmt;

use sqlparser::ast::{Assignment, BinaryOperator, Expr, Ident, Statement, Value};
use sqlparser::dialect::OracleDialect;
use sqlparser::parser::Parser;

use crate::classifier::Classifier;
use crate::levels::DangerLevel;

use super::matcher::GrantMatch;
use super::predicate::{GrantBind, parse_rendered_ast, render_ast};
use super::{GrantPredicateV1, GrantVerb};

/// Typed refusal from the scoped-grant rewrite builder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantRewriteError {
    UnsupportedVerb,
    MissingCallerWhere,
    CteUnsupported,
    GrantPredicateMismatch,
    InvalidTarget,
    SetPredicateColumn,
    InvalidCap,
    UnsupportedExpression,
    RoundTrip,
    Reclassification,
}

impl GrantRewriteError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedVerb => "GRANT_REWRITE_VERB_UNSUPPORTED",
            Self::MissingCallerWhere => "GRANT_REWRITE_WHERE_REQUIRED",
            Self::CteUnsupported => "GRANT_REWRITE_CTE_UNSUPPORTED",
            Self::GrantPredicateMismatch => "GRANT_REWRITE_PREDICATE_MISMATCH",
            Self::InvalidTarget => "GRANT_REWRITE_TARGET_INVALID",
            Self::SetPredicateColumn => "GRANT_REWRITE_SET_PREDICATE_COLUMN",
            Self::InvalidCap => "GRANT_REWRITE_CAP_INVALID",
            Self::UnsupportedExpression => "GRANT_REWRITE_EXPRESSION_UNSUPPORTED",
            Self::RoundTrip => "GRANT_REWRITE_ROUND_TRIP",
            Self::Reclassification => "GRANT_REWRITE_RECLASSIFICATION",
        }
    }
}

impl fmt::Display for GrantRewriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for GrantRewriteError {}

/// Exact quoted catalog identity used by the server-owned template.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotedIdent {
    owner: Ident,
    object: Ident,
}

impl QuotedIdent {
    fn from_match(matched: &GrantMatch) -> Result<Self, GrantRewriteError> {
        let target = matched.target();
        for part in [&target.owner, &target.object_name] {
            if part.is_empty() || part.len() > 128 || part.contains('\0') {
                return Err(GrantRewriteError::InvalidTarget);
            }
        }
        Ok(Self {
            owner: Ident::with_quote('"', &target.owner),
            object: Ident::with_quote('"', &target.object_name),
        })
    }
}

impl fmt::Display for QuotedIdent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.owner, self.object)
    }
}

/// AST parts captured before server template rendering.
#[derive(Clone)]
pub struct GrantRewriteParts {
    target: QuotedIdent,
    p: Expr,
    set: Vec<Assignment>,
    where_: Expr,
    cap: u32,
}

impl GrantRewriteParts {
    #[must_use]
    pub fn target(&self) -> &QuotedIdent {
        &self.target
    }

    #[must_use]
    pub fn predicate(&self) -> &Expr {
        &self.p
    }

    #[must_use]
    pub fn assignments(&self) -> &[Assignment] {
        &self.set
    }

    #[must_use]
    pub fn where_expression(&self) -> &Expr {
        &self.where_
    }

    #[must_use]
    pub fn cap(&self) -> u32 {
        self.cap
    }
}

impl fmt::Debug for GrantRewriteParts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrantRewriteParts")
            .field("target", &self.target)
            .field("assignment_count", &self.set.len())
            .field("where_present", &true)
            .field("cap", &self.cap)
            .finish_non_exhaustive()
    }
}

/// Complete grant rewrite. `reclass_form` is the parseable equivalent used by
/// the classifier; `executable_sql` is the server-owned Oracle UPDATE template
/// (or parsed DELETE statement).
#[derive(Clone)]
pub struct GrantRewriteV1 {
    executable_sql: String,
    parts: GrantRewriteParts,
    binds: Vec<GrantBind>,
    reclass_form: String,
}

impl GrantRewriteV1 {
    #[must_use]
    pub fn executable_sql(&self) -> &str {
        &self.executable_sql
    }

    #[must_use]
    pub fn parts(&self) -> &GrantRewriteParts {
        &self.parts
    }

    #[must_use]
    pub fn binds(&self) -> &[GrantBind] {
        &self.binds
    }

    #[must_use]
    pub fn reclass_form(&self) -> &str {
        &self.reclass_form
    }
}

impl fmt::Debug for GrantRewriteV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrantRewriteV1")
            .field("sql_bytes", &self.executable_sql.len())
            .field("bind_count", &self.binds.len())
            .field("cap", &self.parts.cap)
            .finish_non_exhaustive()
    }
}

/// Build the CHECK OPTION UPDATE envelope from the matched target and ASTs.
pub fn render_grant_update(
    matched: &GrantMatch,
    p: &GrantPredicateV1,
    q: Option<&Expr>,
    cap: u32,
) -> Result<GrantRewriteV1, GrantRewriteError> {
    render(matched, p, q, cap, GrantVerb::Update)
}

/// Build a DELETE whose selection is the caller WHERE, policy Q, grant P and
/// the server-validated row-cap conjunct.
pub fn render_grant_delete(
    matched: &GrantMatch,
    p: &GrantPredicateV1,
    q: Option<&Expr>,
    cap: u32,
) -> Result<GrantRewriteV1, GrantRewriteError> {
    render(matched, p, q, cap, GrantVerb::Delete)
}

fn render(
    matched: &GrantMatch,
    grant_predicate: &GrantPredicateV1,
    policy_q: Option<&Expr>,
    cap: u32,
    expected: GrantVerb,
) -> Result<GrantRewriteV1, GrantRewriteError> {
    if matched.verb() != expected {
        return Err(GrantRewriteError::UnsupportedVerb);
    }
    if matched.cte().is_some() {
        return Err(GrantRewriteError::CteUnsupported);
    }
    if !matched.grant_predicate_matches(grant_predicate) {
        return Err(GrantRewriteError::GrantPredicateMismatch);
    }
    if cap == 0 || u64::from(cap) > matched.max_rows_per_statement() {
        return Err(GrantRewriteError::InvalidCap);
    }
    let caller_where = matched
        .caller_where()
        .cloned()
        .ok_or(GrantRewriteError::MissingCallerWhere)?;
    validate_filter(&caller_where)?;
    if let Some(q) = policy_q {
        validate_filter(q)?;
        if has_placeholder(q) {
            return Err(GrantRewriteError::UnsupportedExpression);
        }
    }

    if matched
        .set_assignments()
        .iter()
        .any(|(column, _)| grant_predicate.columns().contains(column))
    {
        return Err(GrantRewriteError::SetPredicateColumn);
    }
    let (p_ast, binds) = render_ast(grant_predicate);
    validate_filter(&p_ast)?;
    let p_columns: BTreeSet<String> = grant_predicate
        .columns()
        .into_iter()
        .map(|column| column.as_str().to_owned())
        .collect();
    let set = matched
        .set_assignments()
        .iter()
        .map(|(column, value)| {
            if p_columns.contains(column.as_str()) {
                return Err(GrantRewriteError::SetPredicateColumn);
            }
            let target =
                sqlparser::ast::AssignmentTarget::ColumnName(sqlparser::ast::ObjectName(vec![
                    sqlparser::ast::ObjectNamePart::Identifier(Ident::with_quote(
                        '"',
                        column.as_str(),
                    )),
                ]));
            Ok(Assignment {
                target,
                value: value.expression().clone(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if expected == GrantVerb::Update && set.is_empty() {
        return Err(GrantRewriteError::UnsupportedExpression);
    }
    if expected == GrantVerb::Delete && !set.is_empty() {
        return Err(GrantRewriteError::UnsupportedExpression);
    }
    for assignment in &set {
        validate_value(&assignment.value)?;
    }

    let target = QuotedIdent::from_match(matched)?;
    let cap_expr = cap_expression(cap);
    let outer_where = and(vec![
        Some(caller_where.clone()),
        policy_q.cloned(),
        Some(cap_expr.clone()),
    ]);
    let reclass_selection = and(vec![Some(outer_where.clone()), Some(p_ast.clone())]);
    let reclass_form = statement(expected, &target, &set, reclass_selection.clone())?.to_string();
    let original_form = statement(expected, &target, &set, caller_where)?.to_string();
    let classifier = Classifier::default();
    let original_verdict = classifier.classify(&original_form);
    let rewritten_verdict = classifier.classify(&reclass_form);
    if original_verdict.danger == DangerLevel::Forbidden
        || rewritten_verdict.danger == DangerLevel::Forbidden
        || original_verdict != rewritten_verdict
    {
        return Err(GrantRewriteError::Reclassification);
    }

    let executable_sql = match expected {
        GrantVerb::Update => {
            let inline_select = format!("SELECT * FROM {target} WHERE {} WITH CHECK OPTION", p_ast);
            let assignments = assignment_list(&set);
            let sql = format!("UPDATE ({inline_select}) SET {assignments} WHERE {outer_where}");
            round_trip_template_parts(&target, &p_ast, &set, &outer_where, cap)?;
            sql
        }
        GrantVerb::Delete => {
            let statement = statement(expected, &target, &set, reclass_selection.clone())?;
            let sql = statement.to_string();
            round_trip_statement(&sql, &statement)?;
            sql
        }
    };
    Ok(GrantRewriteV1 {
        executable_sql,
        parts: GrantRewriteParts {
            target,
            p: p_ast,
            set,
            where_: outer_where,
            cap,
        },
        binds,
        reclass_form,
    })
}

fn cap_expression(cap: u32) -> Expr {
    Expr::BinaryOp {
        left: Box::new(Expr::Identifier(Ident::new("ROWNUM"))),
        op: BinaryOperator::LtEq,
        right: Box::new(Expr::Value(Value::Number(cap.to_string(), false).into())),
    }
}

fn and(parts: Vec<Option<Expr>>) -> Expr {
    let mut parts = parts.into_iter().flatten();
    let first = parts
        .next()
        .unwrap_or_else(|| Expr::Value(Value::Boolean(false).into()));
    parts.fold(first, |left, right| Expr::BinaryOp {
        left: Box::new(Expr::Nested(Box::new(left))),
        op: BinaryOperator::And,
        right: Box::new(Expr::Nested(Box::new(right))),
    })
}

fn statement(
    verb: GrantVerb,
    target: &QuotedIdent,
    set: &[Assignment],
    selection: Expr,
) -> Result<Statement, GrantRewriteError> {
    let sql = match verb {
        GrantVerb::Update => format!(
            "UPDATE {target} SET {} WHERE {selection}",
            assignment_list(set)
        ),
        GrantVerb::Delete => format!("DELETE FROM {target} WHERE {selection}"),
    };
    let mut statements =
        Parser::parse_sql(&OracleDialect {}, &sql).map_err(|_| GrantRewriteError::RoundTrip)?;
    if statements.len() != 1 {
        return Err(GrantRewriteError::RoundTrip);
    }
    Ok(statements.remove(0))
}

fn assignment_list(assignments: &[Assignment]) -> String {
    assignments
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn round_trip_template_parts(
    target: &QuotedIdent,
    p: &Expr,
    set: &[Assignment],
    where_: &Expr,
    cap: u32,
) -> Result<(), GrantRewriteError> {
    for expr in [p, where_] {
        if parse_rendered_ast(expr).map_err(|_| GrantRewriteError::RoundTrip)? != *expr {
            return Err(GrantRewriteError::RoundTrip);
        }
    }
    let sql = format!("UPDATE {} SET {} WHERE 1 = 1", target, assignment_list(set));
    let parsed_statements =
        Parser::parse_sql(&OracleDialect {}, &sql).map_err(|_| GrantRewriteError::RoundTrip)?;
    let [Statement::Update(parsed)] = parsed_statements.as_slice() else {
        return Err(GrantRewriteError::RoundTrip);
    };
    if parsed.table.relation.to_string() != target.to_string() || parsed.assignments != set {
        return Err(GrantRewriteError::RoundTrip);
    }
    let cap_sql = format!("ROWNUM <= {cap}");
    let parsed_cap = parse_expr(&cap_sql)?;
    if parsed_cap != cap_expression(cap) {
        return Err(GrantRewriteError::RoundTrip);
    }
    Ok(())
}

fn round_trip_statement(sql: &str, expected: &Statement) -> Result<(), GrantRewriteError> {
    let [parsed] = Parser::parse_sql(&OracleDialect {}, sql)
        .map_err(|_| GrantRewriteError::RoundTrip)?
        .try_into()
        .map_err(|_| GrantRewriteError::RoundTrip)?;
    if parsed != *expected {
        return Err(GrantRewriteError::RoundTrip);
    }
    Ok(())
}

fn parse_expr(sql: &str) -> Result<Expr, GrantRewriteError> {
    let mut parser = Parser::new(&OracleDialect {})
        .try_with_sql(sql)
        .map_err(|_| GrantRewriteError::RoundTrip)?;
    let expr = parser
        .parse_expr()
        .map_err(|_| GrantRewriteError::RoundTrip)?;
    parser
        .expect_token(&sqlparser::tokenizer::Token::EOF)
        .map_err(|_| GrantRewriteError::RoundTrip)?;
    Ok(expr)
}

fn validate_filter(expr: &Expr) -> Result<(), GrantRewriteError> {
    match expr {
        Expr::Nested(inner) => validate_filter(inner),
        Expr::BinaryOp { left, op, right } if *op == BinaryOperator::And => {
            validate_filter(left)?;
            validate_filter(right)
        }
        Expr::BinaryOp {
            left,
            op:
                BinaryOperator::Eq
                | BinaryOperator::NotEq
                | BinaryOperator::Lt
                | BinaryOperator::LtEq
                | BinaryOperator::Gt
                | BinaryOperator::GtEq,
            right,
        } => {
            if !matches!(left.as_ref(), Expr::Identifier(_)) {
                return Err(GrantRewriteError::UnsupportedExpression);
            }
            validate_value(right)
        }
        Expr::InList {
            expr,
            list,
            negated: false,
        } if matches!(expr.as_ref(), Expr::Identifier(_)) && !list.is_empty() => {
            list.iter().try_for_each(validate_value)
        }
        Expr::Between {
            expr,
            negated: false,
            low,
            high,
        } if matches!(expr.as_ref(), Expr::Identifier(_)) => {
            validate_value(low)?;
            validate_value(high)
        }
        Expr::IsNull(expr) | Expr::IsNotNull(expr)
            if matches!(expr.as_ref(), Expr::Identifier(_)) =>
        {
            Ok(())
        }
        _ => Err(GrantRewriteError::UnsupportedExpression),
    }
}

fn validate_value(expr: &Expr) -> Result<(), GrantRewriteError> {
    match expr {
        Expr::Nested(inner) => validate_value(inner),
        Expr::Value(_) => Ok(()),
        Expr::UnaryOp {
            op: sqlparser::ast::UnaryOperator::Minus,
            expr,
        } if matches!(expr.as_ref(), Expr::Value(value) if matches!(value.value, Value::Number(..))) => {
            Ok(())
        }
        Expr::TypedString(typed)
            if typed.data_type == sqlparser::ast::DataType::Date
                && matches!(typed.value.value, Value::SingleQuotedString(_)) =>
        {
            Ok(())
        }
        _ => Err(GrantRewriteError::UnsupportedExpression),
    }
}

fn has_placeholder(expr: &Expr) -> bool {
    use sqlparser::ast::Visit;
    use sqlparser::ast::Visitor;
    struct PlaceholderFinder(bool);
    impl Visitor for PlaceholderFinder {
        type Break = ();
        fn pre_visit_expr(&mut self, expr: &Expr) -> std::ops::ControlFlow<Self::Break> {
            if matches!(expr, Expr::Value(value) if matches!(value.value, Value::Placeholder(_))) {
                self.0 = true;
                std::ops::ControlFlow::Break(())
            } else {
                std::ops::ControlFlow::Continue(())
            }
        }
    }
    let mut finder = PlaceholderFinder(false);
    let _ = expr.visit(&mut finder);
    finder.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlparser_rejects_update_inline_view_check_option() {
        let sql = "UPDATE (SELECT * FROM \"APP\".\"T\" WHERE \"ID\" = :omcp_g1 WITH CHECK OPTION) SET \"V\" = 1 WHERE \"ID\" = 2";
        assert!(Parser::parse_sql(&OracleDialect {}, sql).is_err());
    }
}
