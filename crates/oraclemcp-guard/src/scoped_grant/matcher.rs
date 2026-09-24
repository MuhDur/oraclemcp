//! Exact, fail-closed statement-shape match for one scoped DML grant.
//!
//! The database-facing caller supplies the catalog result for the parsed
//! target. This module cross-checks its lexical source before comparing the
//! complete grant identity. It does not resolve names or authorize execution.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::ControlFlow;

use sqlparser::ast::{
    AssignmentTarget, DataType, Expr, FromTable, ObjectName, SetExpr, Statement, TableFactor,
    TableWithJoins, Value, Visit, Visitor, With,
};
use sqlparser::dialect::OracleDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer};

use crate::action_envelope::OracleBindType;
use crate::resolver::{CatalogObjectKind, QuoteSemantics, RawName, SyntacticRole};

use super::{ColumnIdent, GrantTargetIdentity, GrantVerb, ScopedGrant};

/// A catalog answer for exactly the lexical DML target in the parsed AST.
/// The DB-facing consumer must derive this from the live resolver; creating a
/// value here is not a catalog proof by itself.
#[derive(Clone, Debug)]
pub struct ResolvedDmlTarget {
    pub raw_name: RawName,
    pub identity: GrantTargetIdentity,
    pub object_kind: CatalogObjectKind,
    /// Transport-decoded type of every caller bind, keyed by name without `:`.
    pub bind_types: BTreeMap<String, OracleBindType>,
}

/// Why a SET expression cannot be carried by a scoped grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetExpressionKind {
    Function,
    Subquery,
    Sequence,
    Arithmetic,
    MultiColumnTuple,
    Default,
    UntypedBind,
    UnsupportedLiteral,
}

/// Closed refusal vocabulary. Values and SQL text are never copied into it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GrantMismatch {
    VerbNotGranted,
    InsertRefused,
    MergeRefused,
    MultiTableInsertRefused,
    MultiTarget,
    TargetIdentityMismatch,
    SynonymPathMismatch,
    ViewTarget,
    NonTableTarget,
    RemoteObject,
    CollectionExpression,
    PartitionExtended,
    ColumnNotGranted { column: String },
    SetExpressionRefused { kind: SetExpressionKind },
    ReturningRefused,
    SetPredicateColumn { column: String },
    CteDmlUnresolved,
    ReservedBindName,
    BindCountMismatch,
    UnsupportedStatement,
}

impl GrantMismatch {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::VerbNotGranted => "GRANT_VERB_NOT_GRANTED",
            Self::InsertRefused => "GRANT_INSERT_REFUSED",
            Self::MergeRefused => "GRANT_MERGE_REFUSED",
            Self::MultiTableInsertRefused => "GRANT_MULTI_TABLE_INSERT_REFUSED",
            Self::MultiTarget => "GRANT_MULTI_TARGET",
            Self::TargetIdentityMismatch => "GRANT_TARGET_IDENTITY_MISMATCH",
            Self::SynonymPathMismatch => "GRANT_SYNONYM_PATH_MISMATCH",
            Self::ViewTarget => "GRANT_VIEW_TARGET",
            Self::NonTableTarget => "GRANT_NON_TABLE_TARGET",
            Self::RemoteObject => "GRANT_REMOTE_OBJECT",
            Self::CollectionExpression => "GRANT_COLLECTION_EXPRESSION",
            Self::PartitionExtended => "GRANT_PARTITION_EXTENDED",
            Self::ColumnNotGranted { .. } => "GRANT_COLUMN_NOT_GRANTED",
            Self::SetExpressionRefused { .. } => "GRANT_SET_EXPRESSION_REFUSED",
            Self::ReturningRefused => "GRANT_RETURNING_REFUSED",
            Self::SetPredicateColumn { .. } => "GRANT_SET_PREDICATE_COLUMN",
            Self::CteDmlUnresolved => "GRANT_CTE_DML_UNRESOLVED",
            Self::ReservedBindName => "GRANT_RESERVED_BIND_NAME",
            Self::BindCountMismatch => "GRANT_BIND_COUNT_MISMATCH",
            Self::UnsupportedStatement => "GRANT_STATEMENT_UNSUPPORTED",
        }
    }
}

impl fmt::Display for GrantMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for GrantMismatch {}

/// One checked scalar RHS. Debug never includes bind or literal content.
#[derive(Clone)]
pub struct AssignedValue {
    expression: Expr,
    bind_type: Option<OracleBindType>,
}

impl fmt::Debug for AssignedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AssignedValue")
            .field("is_bind", &self.bind_type.is_some())
            .finish_non_exhaustive()
    }
}

impl AssignedValue {
    #[must_use]
    pub fn expression(&self) -> &Expr {
        &self.expression
    }

    #[must_use]
    pub fn bind_type(&self) -> Option<OracleBindType> {
        self.bind_type
    }
}

/// A scoped shape match. It remains insufficient for execution: the caller
/// WHERE, policy, effect closure, final rewrite and row cap still need proof.
#[derive(Clone)]
pub struct GrantMatch {
    verb: GrantVerb,
    target: GrantTargetIdentity,
    set_assignments: Vec<(ColumnIdent, AssignedValue)>,
    caller_where: Option<Expr>,
    cte: Option<With>,
}

impl fmt::Debug for GrantMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrantMatch")
            .field("verb", &self.verb)
            .field("assignment_count", &self.set_assignments.len())
            .field("has_where", &self.caller_where.is_some())
            .field("has_cte", &self.cte.is_some())
            .finish_non_exhaustive()
    }
}

impl GrantMatch {
    #[must_use]
    pub fn verb(&self) -> GrantVerb {
        self.verb
    }

    #[must_use]
    pub fn target(&self) -> &GrantTargetIdentity {
        &self.target
    }

    #[must_use]
    pub fn set_assignments(&self) -> &[(ColumnIdent, AssignedValue)] {
        &self.set_assignments
    }

    #[must_use]
    pub fn caller_where(&self) -> Option<&Expr> {
        self.caller_where.as_ref()
    }

    #[must_use]
    pub fn cte(&self) -> Option<&With> {
        self.cte.as_ref()
    }
}

/// Match one parsed UPDATE/DELETE to one explicitly supplied grant.
/// Every unchecked target or expression form is a typed refusal.
pub fn match_statement(
    grant: &ScopedGrant,
    stmt: &Statement,
    resolved: &ResolvedDmlTarget,
) -> Result<GrantMatch, GrantMismatch> {
    let whole_statement = stmt;
    let (stmt, cte) = unwrap_cte(stmt)?;
    let (verb, table, assignments, selection) = match stmt {
        Statement::Update(update) => {
            if update.returning.is_some() || update.output.is_some() {
                return Err(GrantMismatch::ReturningRefused);
            }
            if update.from.is_some()
                || !update.table.joins.is_empty()
                || !update.optimizer_hints.is_empty()
                || update.or.is_some()
                || !update.order_by.is_empty()
                || update.limit.is_some()
                || update.assignments.is_empty()
            {
                return Err(GrantMismatch::MultiTarget);
            }
            (
                GrantVerb::Update,
                &update.table.relation,
                Some(update.assignments.as_slice()),
                update.selection.as_ref(),
            )
        }
        Statement::Delete(delete) => {
            if delete.returning.is_some() || delete.output.is_some() {
                return Err(GrantMismatch::ReturningRefused);
            }
            if !delete.tables.is_empty()
                || delete.using.is_some()
                || !delete.optimizer_hints.is_empty()
                || !delete.order_by.is_empty()
                || delete.limit.is_some()
            {
                return Err(GrantMismatch::MultiTarget);
            }
            let FromTable::WithFromKeyword(tables) = &delete.from else {
                return Err(GrantMismatch::MultiTarget);
            };
            let [TableWithJoins { relation, joins }] = tables.as_slice() else {
                return Err(GrantMismatch::MultiTarget);
            };
            if !joins.is_empty() {
                return Err(GrantMismatch::MultiTarget);
            }
            (GrantVerb::Delete, relation, None, delete.selection.as_ref())
        }
        Statement::Insert(insert) => {
            return if insert.multi_table_insert_type.is_some()
                || !insert.multi_table_into_clauses.is_empty()
                || !insert.multi_table_when_clauses.is_empty()
                || insert.multi_table_else_clause.is_some()
            {
                Err(GrantMismatch::MultiTableInsertRefused)
            } else {
                Err(GrantMismatch::InsertRefused)
            };
        }
        Statement::Merge(_) => return Err(GrantMismatch::MergeRefused),
        _ => return Err(GrantMismatch::UnsupportedStatement),
    };
    if !grant.verbs().contains(verb) {
        return Err(GrantMismatch::VerbNotGranted);
    }
    check_table(table, resolved)?;
    if let Some(with) = cte {
        let TableFactor::Table { name, .. } = table else {
            return Err(GrantMismatch::CteDmlUnresolved);
        };
        if let [target_name] = name.0.as_slice()
            && let Some(target_ident) = target_name.as_ident()
            && with
                .cte_tables
                .iter()
                .any(|entry| canonical_ident(&entry.alias.name) == canonical_ident(target_ident))
        {
            return Err(GrantMismatch::CteDmlUnresolved);
        }
    }
    check_identity(grant.target(), resolved)?;

    let mut set_assignments = Vec::new();
    let mut seen = BTreeSet::new();
    if let Some(assignments) = assignments {
        for assignment in assignments {
            let AssignmentTarget::ColumnName(name) = &assignment.target else {
                return Err(GrantMismatch::SetExpressionRefused {
                    kind: SetExpressionKind::MultiColumnTuple,
                });
            };
            let column = column_name(name)?;
            let assigned = check_assigned_value(&assignment.value, &resolved.bind_types)?;
            if grant.row_predicate().columns().contains(&column) {
                return Err(GrantMismatch::SetPredicateColumn {
                    column: column.as_str().to_owned(),
                });
            }
            if !grant.columns().contains(&column) || !seen.insert(column.clone()) {
                return Err(GrantMismatch::ColumnNotGranted {
                    column: column.as_str().to_owned(),
                });
            }
            set_assignments.push((column, assigned));
        }
    }
    check_binds(whole_statement, &resolved.bind_types)?;
    Ok(GrantMatch {
        verb,
        target: resolved.identity.clone(),
        set_assignments,
        caller_where: selection.cloned(),
        cte: cte.cloned(),
    })
}

/// Parse then match a single caller statement. The Oracle parser does not
/// currently represent Oracle `INSERT ALL/FIRST` or `RETURNING ... INTO`; the
/// tokenizer recognizes only those refusal shapes on parse failure. It never
/// turns an unparseable statement into a match.
pub fn match_sql(
    grant: &ScopedGrant,
    sql: &str,
    resolved: &ResolvedDmlTarget,
) -> Result<GrantMatch, GrantMismatch> {
    let parsed = match Parser::parse_sql(&OracleDialect {}, sql) {
        Ok(parsed) => parsed,
        Err(_) => return Err(parse_failure_reason(sql)),
    };
    let [statement] = parsed.as_slice() else {
        return Err(GrantMismatch::UnsupportedStatement);
    };
    match_statement(grant, statement, resolved)
}

fn parse_failure_reason(sql: &str) -> GrantMismatch {
    let Ok(tokens) = Tokenizer::new(&OracleDialect {}, sql).tokenize() else {
        return GrantMismatch::UnsupportedStatement;
    };
    let words = tokens.iter().filter_map(|token| match token {
        Token::Word(word) if word.quote_style.is_none() => Some(word.value.to_ascii_uppercase()),
        _ => None,
    });
    let words: Vec<_> = words.collect();
    if words.first().is_some_and(|word| word == "INSERT")
        && words
            .get(1)
            .is_some_and(|word| word == "ALL" || word == "FIRST")
    {
        return GrantMismatch::MultiTableInsertRefused;
    }
    if words.iter().any(|word| word == "RETURNING") {
        return GrantMismatch::ReturningRefused;
    }
    GrantMismatch::UnsupportedStatement
}

fn unwrap_cte(stmt: &Statement) -> Result<(&Statement, Option<&With>), GrantMismatch> {
    let Statement::Query(query) = stmt else {
        return Ok((stmt, None));
    };
    let Some(with) = &query.with else {
        return Err(GrantMismatch::UnsupportedStatement);
    };
    if with.recursive
        || query.order_by.is_some()
        || query.limit_clause.is_some()
        || query.fetch.is_some()
        || !query.locks.is_empty()
        || query.for_clause.is_some()
        || query.settings.is_some()
        || query.format_clause.is_some()
        || !query.pipe_operators.is_empty()
    {
        return Err(GrantMismatch::CteDmlUnresolved);
    }
    let inner = match query.body.as_ref() {
        SetExpr::Update(inner) | SetExpr::Delete(inner) => inner,
        _ => return Err(GrantMismatch::CteDmlUnresolved),
    };
    Ok((inner, Some(with)))
}

fn check_table(table: &TableFactor, resolved: &ResolvedDmlTarget) -> Result<(), GrantMismatch> {
    let TableFactor::Table {
        name,
        alias: None,
        args: None,
        with_hints,
        version: None,
        with_ordinality: false,
        partitions,
        json_path: None,
        sample: None,
        index_hints,
    } = table
    else {
        return Err(match table {
            TableFactor::TableFunction { .. } | TableFactor::Function { .. } => {
                GrantMismatch::CollectionExpression
            }
            _ => GrantMismatch::MultiTarget,
        });
    };
    if !partitions.is_empty() {
        return Err(GrantMismatch::PartitionExtended);
    }
    if !with_hints.is_empty() || !index_hints.is_empty() {
        return Err(GrantMismatch::MultiTarget);
    }
    if resolved.raw_name.db_link.is_some() || name_has_dblink(name) {
        return Err(GrantMismatch::RemoteObject);
    }
    if !same_lexical_name(name, &resolved.raw_name) {
        return Err(GrantMismatch::TargetIdentityMismatch);
    }
    Ok(())
}

fn name_has_dblink(name: &ObjectName) -> bool {
    name.0.iter().any(|part| {
        part.as_ident()
            .is_some_and(|ident| ident.quote_style.is_none() && ident.value.contains('@'))
    })
}

fn same_lexical_name(name: &ObjectName, raw: &RawName) -> bool {
    raw.role == SyntacticRole::FromFactor
        && name.0.len() == raw.parts.len()
        && name.0.iter().zip(&raw.parts).all(|(ast, source)| {
            let Some(ast) = ast.as_ident() else {
                return false;
            };
            let ast = canonical_ident(ast);
            let source = match source.quoting {
                QuoteSemantics::Unquoted => source.text.to_ascii_uppercase(),
                QuoteSemantics::Quoted => source.text.clone(),
            };
            ast == source
        })
}

fn check_identity(
    granted: &GrantTargetIdentity,
    resolved: &ResolvedDmlTarget,
) -> Result<(), GrantMismatch> {
    match resolved.object_kind {
        CatalogObjectKind::Table => {}
        CatalogObjectKind::View | CatalogObjectKind::MaterializedView => {
            return Err(GrantMismatch::ViewTarget);
        }
        _ => return Err(GrantMismatch::NonTableTarget),
    }
    let actual = &resolved.identity;
    if granted.owner != actual.owner
        || granted.object_name != actual.object_name
        || granted.object_id != actual.object_id
        || granted.data_object_id != actual.data_object_id
        || granted.container != actual.container
        || granted.edition != actual.edition
        || granted.catalog_generation != actual.catalog_generation
    {
        return Err(GrantMismatch::TargetIdentityMismatch);
    }
    if granted.resolved_via != actual.resolved_via {
        return Err(GrantMismatch::SynonymPathMismatch);
    }
    Ok(())
}

fn canonical_ident(ident: &sqlparser::ast::Ident) -> String {
    if ident.quote_style.is_some() {
        ident.value.clone()
    } else {
        ident.value.to_ascii_uppercase()
    }
}

fn column_name(name: &ObjectName) -> Result<ColumnIdent, GrantMismatch> {
    let [part] = name.0.as_slice() else {
        return Err(GrantMismatch::ColumnNotGranted {
            column: "<qualified>".into(),
        });
    };
    let ident = part.as_ident().ok_or(GrantMismatch::ColumnNotGranted {
        column: "<unresolved>".into(),
    })?;
    ColumnIdent::new(canonical_ident(ident)).map_err(|_| GrantMismatch::ColumnNotGranted {
        column: "<invalid>".into(),
    })
}

fn canonical_bind(raw: &str) -> Option<String> {
    let name = raw.strip_prefix(':')?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'$' | b'#'))
    {
        return None;
    }
    Some(name.to_ascii_uppercase())
}

fn check_binds(
    stmt: &Statement,
    declared: &BTreeMap<String, OracleBindType>,
) -> Result<(), GrantMismatch> {
    struct BindVisitor<'a> {
        declared: &'a BTreeMap<String, OracleBindType>,
        used: BTreeSet<String>,
    }
    impl Visitor for BindVisitor<'_> {
        type Break = GrantMismatch;

        fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
            if let Expr::Value(value) = expr
                && let Value::Placeholder(raw) = &value.value
            {
                let Some(name) = canonical_bind(raw) else {
                    return ControlFlow::Break(GrantMismatch::BindCountMismatch);
                };
                if name.starts_with("OMCP_G") {
                    return ControlFlow::Break(GrantMismatch::ReservedBindName);
                }
                let Some(bind_type) = self.declared.get(&name) else {
                    return ControlFlow::Break(GrantMismatch::BindCountMismatch);
                };
                if *bind_type == OracleBindType::Bool {
                    return ControlFlow::Break(GrantMismatch::SetExpressionRefused {
                        kind: SetExpressionKind::UntypedBind,
                    });
                }
                self.used.insert(name);
            }
            ControlFlow::Continue(())
        }
    }
    let mut visitor = BindVisitor {
        declared,
        used: BTreeSet::new(),
    };
    if let ControlFlow::Break(reason) = stmt.visit(&mut visitor) {
        return Err(reason);
    }
    if visitor.used.len() != declared.len()
        || declared
            .keys()
            .any(|key| !visitor.used.contains(&key.to_ascii_uppercase()))
    {
        return Err(GrantMismatch::BindCountMismatch);
    }
    Ok(())
}

fn check_assigned_value(
    expr: &Expr,
    bind_types: &BTreeMap<String, OracleBindType>,
) -> Result<AssignedValue, GrantMismatch> {
    let mut value = expr;
    for _ in 0..32 {
        if let Expr::Nested(inner) = value {
            value = inner;
        } else {
            break;
        }
    }
    if matches!(value, Expr::Nested(_)) {
        return Err(GrantMismatch::SetExpressionRefused {
            kind: SetExpressionKind::Arithmetic,
        });
    }
    let bind_type = match value {
        Expr::Value(v) => {
            match &v.value {
                Value::Placeholder(raw) => {
                    let name = canonical_bind(raw).ok_or(GrantMismatch::SetExpressionRefused {
                        kind: SetExpressionKind::UntypedBind,
                    })?;
                    let bind_type = bind_types.get(&name).copied().ok_or(
                        GrantMismatch::SetExpressionRefused {
                            kind: SetExpressionKind::UntypedBind,
                        },
                    )?;
                    if bind_type == OracleBindType::Bool {
                        return Err(GrantMismatch::SetExpressionRefused {
                            kind: SetExpressionKind::UntypedBind,
                        });
                    }
                    Some(bind_type)
                }
                Value::Number(..)
                | Value::SingleQuotedString(_)
                | Value::NationalStringLiteral(_)
                | Value::Null => None,
                _ => {
                    return Err(GrantMismatch::SetExpressionRefused {
                        kind: SetExpressionKind::UnsupportedLiteral,
                    });
                }
            }
        }
        Expr::TypedString(typed)
            if typed.data_type == DataType::Date
                && matches!(typed.value.value, Value::SingleQuotedString(_)) =>
        {
            None
        }
        Expr::UnaryOp { op, expr }
            if *op == sqlparser::ast::UnaryOperator::Minus
                && matches!(expr.as_ref(), Expr::Value(v) if matches!(v.value, Value::Number(..))) =>
        {
            None
        }
        Expr::Function(_) => return set_refusal(SetExpressionKind::Function),
        Expr::Subquery(_) => return set_refusal(SetExpressionKind::Subquery),
        Expr::CompoundIdentifier(parts)
            if parts.last().is_some_and(|p| {
                p.value.eq_ignore_ascii_case("NEXTVAL") || p.value.eq_ignore_ascii_case("CURRVAL")
            }) =>
        {
            return set_refusal(SetExpressionKind::Sequence);
        }
        Expr::Identifier(ident) if ident.value.eq_ignore_ascii_case("DEFAULT") => {
            return set_refusal(SetExpressionKind::Default);
        }
        Expr::BinaryOp { .. } => return set_refusal(SetExpressionKind::Arithmetic),
        _ => return set_refusal(SetExpressionKind::UnsupportedLiteral),
    };
    Ok(AssignedValue {
        expression: expr.clone(),
        bind_type,
    })
}

fn set_refusal<T>(kind: SetExpressionKind) -> Result<T, GrantMismatch> {
    Err(GrantMismatch::SetExpressionRefused { kind })
}
