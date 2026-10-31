//! Closed caller-DML grammar and the immutable input to the W13 rewrite.
//!
//! This module accepts only one local UPDATE/DELETE against a catalog-resolved
//! target. The WHERE is an AND-list of comparisons between resolved target
//! columns and typed literals or positional binds. Every other expression is
//! refused before a scoped grant can use it. `EffectiveDmlPlanV1` builds both
//! execution SQL and impact-count SQL from the same validated ASTs. Current
//! dispatch still refuses scoped-grant execution until the runtime consumer is
//! wired; this plan does not itself authorize or execute DML.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use sha2::{Digest, Sha256};
use sqlparser::ast::{
    AssignmentTarget, BinaryOperator, DataType, Expr, FromTable, ObjectName, SetExpr, Statement,
    TableFactor, Value,
};
use sqlparser::dialect::OracleDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::{Token, Tokenizer};

use crate::action_envelope::{ActionEnvelopeV1, ActionKind, BindEnvelope, OracleBindType};
use crate::resolver::{CatalogObjectKind, RawName, RawNamePart, SyntacticRole};
use crate::scoped_grant::matcher::{ResolvedDmlTarget, match_statement};
use crate::scoped_grant::rewrite::{GrantRewriteV1, build_rewrite};
use crate::scoped_grant::{
    ColumnIdent, GrantBind, GrantPredicateV1, GrantTargetIdentity, GrantVerb, MAX_IN_LIST_VALUES,
    ScopedGrant,
};

const PLAN_DOMAIN: &[u8] = b"omcp/effective-dml-plan/v1";
/// Every change to the W13 SQL template must change this version.
pub const DML_REWRITE_ALGORITHM_VERSION: u16 = 2;
const MAX_CONJUNCTS: usize = 64;
const MAX_PREDICATE_DEPTH: usize = 32;

/// A refusal from the closed DML grammar. It never includes SQL or bind values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmlPlanError {
    Parse,
    UnsupportedStatement,
    TargetMismatch,
    UnresolvedColumn,
    UnsupportedAssignment,
    UnsupportedPredicate,
    PredicateTooComplex,
    InvalidBind,
    ReservedBindName,
    BindCountMismatch,
    GrantMismatch,
    PolicyPredicateInvalid,
    InvalidEffectivePlan,
}

impl DmlPlanError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Parse => "DML_PLAN_PARSE",
            Self::UnsupportedStatement => "DML_PLAN_STATEMENT_UNSUPPORTED",
            Self::TargetMismatch => "DML_PLAN_TARGET_MISMATCH",
            Self::UnresolvedColumn => "DML_PLAN_COLUMN_UNRESOLVED",
            Self::UnsupportedAssignment => "DML_PLAN_ASSIGNMENT_UNSUPPORTED",
            Self::UnsupportedPredicate => "DML_PLAN_PREDICATE_UNSUPPORTED",
            Self::PredicateTooComplex => "DML_PLAN_PREDICATE_TOO_COMPLEX",
            Self::InvalidBind => "DML_PLAN_BIND_INVALID",
            Self::ReservedBindName => "DML_PLAN_BIND_RESERVED",
            Self::BindCountMismatch => "DML_PLAN_BIND_COUNT_MISMATCH",
            Self::GrantMismatch => "DML_PLAN_GRANT_MISMATCH",
            Self::PolicyPredicateInvalid => "DML_PLAN_POLICY_PREDICATE_INVALID",
            Self::InvalidEffectivePlan => "DML_PLAN_EFFECTIVE_INVALID",
        }
    }
}

impl fmt::Display for DmlPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for DmlPlanError {}

/// A WHERE expression whose complete AST was checked against the allow-list.
/// The expression remains private so callers cannot replace it after checking.
#[derive(Clone)]
pub struct DmlCallerPredicateV1 {
    expression: Expr,
    columns: BTreeSet<ColumnIdent>,
    bind_positions: BTreeSet<usize>,
}

impl fmt::Debug for DmlCallerPredicateV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DmlCallerPredicateV1")
            .field("column_count", &self.columns.len())
            .field("bind_count", &self.bind_positions.len())
            .finish_non_exhaustive()
    }
}

impl DmlCallerPredicateV1 {
    /// The validated AST, for the server-owned rewrite renderer only.
    #[must_use]
    pub fn expression(&self) -> &Expr {
        &self.expression
    }

    #[must_use]
    pub fn columns(&self) -> &BTreeSet<ColumnIdent> {
        &self.columns
    }

    #[must_use]
    pub fn bind_positions(&self) -> &BTreeSet<usize> {
        &self.bind_positions
    }
}

/// The validated caller statement. This does not authorize execution: catalog
/// identity, policy, grant scope, effect closure and rewrite remain separate
/// mandatory checks.
#[derive(Clone)]
pub struct DmlCallerStatementV1 {
    statement: Statement,
    verb: GrantVerb,
    target: GrantTargetIdentity,
    resolved_columns: BTreeSet<ColumnIdent>,
    assignments: BTreeSet<ColumnIdent>,
    predicate: DmlCallerPredicateV1,
    statement_digest: [u8; 32],
    binds: BindEnvelope,
}

impl fmt::Debug for DmlCallerStatementV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DmlCallerStatementV1")
            .field("verb", &self.verb)
            .field("assignment_count", &self.assignments.len())
            .finish_non_exhaustive()
    }
}

impl DmlCallerStatementV1 {
    /// Parse and validate the exact SQL the caller submitted. `columns` must be
    /// the catalog-resolved columns of `target`, not a caller-supplied list.
    pub fn parse(
        sql: &str,
        target: GrantTargetIdentity,
        current_schema: &str,
        columns: &BTreeSet<ColumnIdent>,
        binds: &BindEnvelope,
    ) -> Result<Self, DmlPlanError> {
        if binds.arity != binds.types.len() {
            return Err(DmlPlanError::BindCountMismatch);
        }
        let [statement] = Parser::parse_sql(&OracleDialect {}, sql)
            .map_err(|_| DmlPlanError::Parse)?
            .try_into()
            .map_err(|_| DmlPlanError::UnsupportedStatement)?;
        let mut bind_positions = BTreeSet::new();
        let mut predicate_binds = BTreeSet::new();
        let mut predicate_columns = BTreeSet::new();
        let mut assignments = BTreeSet::new();
        let (verb, selection) = match &statement {
            Statement::Update(update) => {
                if update.from.is_some()
                    || !update.table.joins.is_empty()
                    || !update.optimizer_hints.is_empty()
                    || update.returning.is_some()
                    || update.output.is_some()
                    || update.or.is_some()
                    || !update.order_by.is_empty()
                    || update.limit.is_some()
                    || update.assignments.is_empty()
                {
                    return Err(DmlPlanError::UnsupportedStatement);
                }
                check_target(&update.table.relation, &target, current_schema)?;
                for assignment in &update.assignments {
                    let AssignmentTarget::ColumnName(name) = &assignment.target else {
                        return Err(DmlPlanError::UnsupportedAssignment);
                    };
                    let column = resolve_object_column(name, columns)
                        .map_err(|_| DmlPlanError::UnsupportedAssignment)?;
                    if !assignments.insert(column) {
                        return Err(DmlPlanError::UnsupportedAssignment);
                    }
                    check_value(
                        &assignment.value,
                        PredicateBinds::Positional(binds),
                        &mut bind_positions,
                    )
                    .map_err(|_| DmlPlanError::UnsupportedAssignment)?;
                }
                (GrantVerb::Update, update.selection.as_ref())
            }
            Statement::Delete(delete) => {
                if !delete.tables.is_empty()
                    || delete.using.is_some()
                    || !delete.optimizer_hints.is_empty()
                    || delete.returning.is_some()
                    || delete.output.is_some()
                    || !delete.order_by.is_empty()
                    || delete.limit.is_some()
                {
                    return Err(DmlPlanError::UnsupportedStatement);
                }
                let FromTable::WithFromKeyword(tables) = &delete.from else {
                    return Err(DmlPlanError::UnsupportedStatement);
                };
                if tables.len() != 1 || !tables[0].joins.is_empty() {
                    return Err(DmlPlanError::UnsupportedStatement);
                }
                check_target(&tables[0].relation, &target, current_schema)?;
                (GrantVerb::Delete, delete.selection.as_ref())
            }
            _ => return Err(DmlPlanError::UnsupportedStatement),
        };
        let selection = selection.ok_or(DmlPlanError::UnsupportedPredicate)?;
        let mut conjuncts = 0;
        check_predicate(
            selection,
            columns,
            PredicateBinds::Positional(binds),
            &mut predicate_binds,
            &mut predicate_columns,
            &mut conjuncts,
            0,
        )?;
        let assignment_bind_count = bind_positions.len();
        bind_positions.extend(predicate_binds.iter().copied());
        if bind_positions.len() != assignment_bind_count + predicate_binds.len()
            || bind_positions.len() != binds.arity
            || bind_positions.iter().copied().ne(1..=binds.arity)
        {
            return Err(DmlPlanError::BindCountMismatch);
        }
        let selection = selection.clone();
        Ok(Self {
            statement,
            verb,
            target,
            resolved_columns: columns.clone(),
            assignments,
            predicate: DmlCallerPredicateV1 {
                expression: selection,
                columns: predicate_columns,
                bind_positions: predicate_binds,
            },
            statement_digest: ActionEnvelopeV1::statement_digest(sql),
            binds: binds.clone(),
        })
    }

    #[must_use]
    pub fn verb(&self) -> GrantVerb {
        self.verb
    }

    #[must_use]
    pub fn target(&self) -> &GrantTargetIdentity {
        &self.target
    }

    #[must_use]
    pub fn assignments(&self) -> &BTreeSet<ColumnIdent> {
        &self.assignments
    }

    #[must_use]
    pub fn predicate(&self) -> &DmlCallerPredicateV1 {
        &self.predicate
    }

    #[must_use]
    pub fn statement(&self) -> &Statement {
        &self.statement
    }

    #[must_use]
    pub fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }
}

fn normalized_identifier(ident: &sqlparser::ast::Ident) -> String {
    if ident.quote_style.is_some() {
        ident.value.clone()
    } else {
        ident.value.to_ascii_uppercase()
    }
}

fn name_parts(name: &ObjectName) -> Result<Vec<String>, DmlPlanError> {
    name.0
        .iter()
        .map(|part| {
            part.as_ident()
                .map(normalized_identifier)
                .ok_or(DmlPlanError::TargetMismatch)
        })
        .collect()
}

fn check_target(
    relation: &TableFactor,
    target: &GrantTargetIdentity,
    current_schema: &str,
) -> Result<(), DmlPlanError> {
    check_table_target(relation, &target.owner, &target.object_name, current_schema)
}

fn check_table_target(
    relation: &TableFactor,
    owner: &str,
    object_name: &str,
    current_schema: &str,
) -> Result<(), DmlPlanError> {
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
    } = relation
    else {
        return Err(DmlPlanError::UnsupportedStatement);
    };
    if !with_hints.is_empty() || !partitions.is_empty() || !index_hints.is_empty() {
        return Err(DmlPlanError::UnsupportedStatement);
    }
    let parts = name_parts(name)?;
    let matches = match parts.as_slice() {
        [table] => table == object_name && current_schema == owner,
        [schema, table] => schema == owner && table == object_name,
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(DmlPlanError::TargetMismatch)
    }
}

fn resolve_object_column(
    name: &ObjectName,
    columns: &BTreeSet<ColumnIdent>,
) -> Result<ColumnIdent, DmlPlanError> {
    let [part] = name.0.as_slice() else {
        return Err(DmlPlanError::UnresolvedColumn);
    };
    let ident = part.as_ident().ok_or(DmlPlanError::UnresolvedColumn)?;
    let name = normalized_identifier(ident);
    columns
        .iter()
        .find(|column| column.as_str() == name)
        .cloned()
        .ok_or(DmlPlanError::UnresolvedColumn)
}

fn resolve_expr_column(
    expr: &Expr,
    columns: &BTreeSet<ColumnIdent>,
) -> Result<ColumnIdent, DmlPlanError> {
    let Expr::Identifier(ident) = expr else {
        return Err(DmlPlanError::UnresolvedColumn);
    };
    let name = normalized_identifier(ident);
    columns
        .iter()
        .find(|column| column.as_str() == name)
        .cloned()
        .ok_or(DmlPlanError::UnresolvedColumn)
}

/// Binding modes are explicit: a named matcher input never acquires a
/// positional order from iteration over a map.
#[derive(Clone, Copy)]
enum PredicateBinds<'a> {
    Positional(&'a BindEnvelope),
    Named(&'a BTreeMap<String, OracleBindType>),
    None,
}

pub(crate) fn validate_named_filter(
    expr: &Expr,
    columns: &BTreeSet<ColumnIdent>,
    binds: &BTreeMap<String, OracleBindType>,
) -> Result<(), DmlPlanError> {
    validate_filter(expr, columns, PredicateBinds::Named(binds))
}

pub(crate) fn validate_policy_filter(
    expr: &Expr,
    columns: &BTreeSet<ColumnIdent>,
) -> Result<(), DmlPlanError> {
    validate_filter(expr, columns, PredicateBinds::None)
}

fn validate_filter(
    expr: &Expr,
    columns: &BTreeSet<ColumnIdent>,
    binds: PredicateBinds<'_>,
) -> Result<(), DmlPlanError> {
    check_predicate(
        expr,
        columns,
        binds,
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
        &mut 0,
        0,
    )
}

fn check_value(
    expr: &Expr,
    binds: PredicateBinds<'_>,
    positions: &mut BTreeSet<usize>,
) -> Result<(), DmlPlanError> {
    let mut expr = expr;
    let mut depth = 0;
    while let Expr::Nested(inner) = expr {
        depth += 1;
        if depth > MAX_PREDICATE_DEPTH {
            return Err(DmlPlanError::PredicateTooComplex);
        }
        expr = inner;
    }
    match expr {
        Expr::Value(value) => match &value.value {
            Value::Number(..) | Value::SingleQuotedString(_) | Value::NationalStringLiteral(_) => {
                Ok(())
            }
            Value::Placeholder(raw) => {
                let name = raw.strip_prefix(':').ok_or(DmlPlanError::InvalidBind)?;
                let (bind_type, position) = match binds {
                    PredicateBinds::Positional(envelope) => {
                        let index = name
                            .parse::<usize>()
                            .ok()
                            .filter(|index| *index > 0 && *index <= envelope.arity)
                            .ok_or(DmlPlanError::InvalidBind)?;
                        (
                            *envelope
                                .types
                                .get(index - 1)
                                .ok_or(DmlPlanError::InvalidBind)?,
                            Some(index),
                        )
                    }
                    PredicateBinds::Named(types) => {
                        if name.is_empty()
                            || !name.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$' | b'#')
                            })
                        {
                            return Err(DmlPlanError::InvalidBind);
                        }
                        let name = name.to_ascii_uppercase();
                        if name.starts_with("OMCP_G") {
                            return Err(DmlPlanError::ReservedBindName);
                        }
                        (*types.get(&name).ok_or(DmlPlanError::InvalidBind)?, None)
                    }
                    PredicateBinds::None => return Err(DmlPlanError::InvalidBind),
                };
                match bind_type {
                    OracleBindType::String
                    | OracleBindType::I64
                    | OracleBindType::F64
                    | OracleBindType::TimestampTz => {
                        if position.is_none_or(|index| positions.insert(index)) {
                            Ok(())
                        } else {
                            Err(DmlPlanError::BindCountMismatch)
                        }
                    }
                    OracleBindType::Null | OracleBindType::Bool => Err(DmlPlanError::InvalidBind),
                }
            }
            _ => Err(DmlPlanError::UnsupportedPredicate),
        },
        Expr::TypedString(typed)
            if typed.data_type == DataType::Date
                && matches!(typed.value.value, Value::SingleQuotedString(_)) =>
        {
            Ok(())
        }
        Expr::UnaryOp { op, expr }
            if *op == sqlparser::ast::UnaryOperator::Minus
                && matches!(expr.as_ref(), Expr::Value(value) if matches!(value.value, Value::Number(..))) =>
        {
            Ok(())
        }
        _ => Err(DmlPlanError::UnsupportedPredicate),
    }
}

#[allow(clippy::too_many_arguments)]
fn check_predicate(
    expr: &Expr,
    columns: &BTreeSet<ColumnIdent>,
    binds: PredicateBinds<'_>,
    positions: &mut BTreeSet<usize>,
    referenced: &mut BTreeSet<ColumnIdent>,
    conjuncts: &mut usize,
    depth: usize,
) -> Result<(), DmlPlanError> {
    if depth > MAX_PREDICATE_DEPTH {
        return Err(DmlPlanError::PredicateTooComplex);
    }
    match expr {
        Expr::Nested(inner) => check_predicate(
            inner,
            columns,
            binds,
            positions,
            referenced,
            conjuncts,
            depth + 1,
        ),
        Expr::BinaryOp {
            left,
            op: BinaryOperator::And,
            right,
        } => {
            check_predicate(
                left,
                columns,
                binds,
                positions,
                referenced,
                conjuncts,
                depth + 1,
            )?;
            check_predicate(
                right,
                columns,
                binds,
                positions,
                referenced,
                conjuncts,
                depth + 1,
            )
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
            checked_comparison(left, columns, referenced, conjuncts)?;
            check_value(right, binds, positions)
        }
        Expr::InList {
            expr,
            list,
            negated: false,
        } if !list.is_empty() && list.len() <= MAX_IN_LIST_VALUES => {
            checked_comparison(expr, columns, referenced, conjuncts)?;
            for value in list {
                check_value(value, binds, positions)?;
            }
            Ok(())
        }
        Expr::Between {
            expr,
            negated: false,
            low,
            high,
        } => {
            checked_comparison(expr, columns, referenced, conjuncts)?;
            check_value(low, binds, positions)?;
            check_value(high, binds, positions)
        }
        Expr::IsNull(expr) | Expr::IsNotNull(expr) => {
            checked_comparison(expr, columns, referenced, conjuncts)
        }
        _ => Err(DmlPlanError::UnsupportedPredicate),
    }
}

fn checked_comparison(
    expr: &Expr,
    columns: &BTreeSet<ColumnIdent>,
    referenced: &mut BTreeSet<ColumnIdent>,
    conjuncts: &mut usize,
) -> Result<(), DmlPlanError> {
    *conjuncts += 1;
    if *conjuncts > MAX_CONJUNCTS {
        return Err(DmlPlanError::PredicateTooComplex);
    }
    referenced.insert(resolve_expr_column(expr, columns)?);
    Ok(())
}

/// A bind source in the physical SQL's occurrence order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DmlPlanBindV1 {
    /// One-based position in the original ActionEnvelope bind vector.
    Caller { position: usize },
    /// Zero-based index into the server-owned grant bind vector.
    Grant { index: usize },
}

/// Bound components of one executable DML rewrite and its impact-count query.
/// Construction validates and renders the plan but does not authorize or
/// execute DML.
pub struct EffectiveDmlPlanV1 {
    caller: DmlCallerStatementV1,
    envelope_digest: [u8; 32],
    policy_schema_digest: [u8; 32],
    policy_ruleset_digest: [u8; 32],
    matched_rule_ids: Vec<String>,
    policy_predicate_digest: [u8; 32],
    policy_predicate: Option<Expr>,
    grant_predicate: GrantPredicateV1,
    grant_scope_digest: [u8; 32],
    bind_hmac: [u8; 32],
    row_cap: u64,
    rewrite: GrantRewriteV1,
    impact_count_template: String,
    execution_bind_layout: Vec<DmlPlanBindV1>,
    impact_bind_layout: Vec<DmlPlanBindV1>,
}

impl fmt::Debug for EffectiveDmlPlanV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EffectiveDmlPlanV1")
            .field("verb", &self.caller.verb())
            .field("row_cap", &self.row_cap)
            .field("matched_rule_count", &self.matched_rule_ids.len())
            .finish_non_exhaustive()
    }
}

impl EffectiveDmlPlanV1 {
    /// Build the executable and impact-count SQL from the same validated
    /// caller AST, policy predicate, and immutable grant. No caller-supplied
    /// rewrite string is accepted. The final SQL still requires classifier,
    /// closure, authorization, count, and apply-time digest checks.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_rewrite(
        caller: DmlCallerStatementV1,
        envelope: &ActionEnvelopeV1,
        policy_schema_digest: [u8; 32],
        policy_ruleset_digest: [u8; 32],
        matched_rule_ids: Vec<String>,
        policy_predicate_digest: [u8; 32],
        policy_predicate: Option<Expr>,
        grant: &ScopedGrant,
        row_cap: u64,
    ) -> Result<Self, DmlPlanError> {
        if row_cap == 0
            || envelope.version != 1
            || envelope.action_kind != ActionKind::ExecuteDml
            || envelope.statement_digest != caller.statement_digest
            || envelope.binds != caller.binds
            || envelope.scoped_grant_ref.is_none()
        {
            return Err(DmlPlanError::InvalidEffectivePlan);
        }
        if grant.target() != caller.target()
            || !grant.verbs().contains(caller.verb())
            || row_cap > grant.limits().max_rows_per_statement
            || grant
                .row_predicate()
                .columns()
                .iter()
                .any(|column| !caller.resolved_columns.contains(*column))
            || caller
                .assignments()
                .iter()
                .any(|column| !grant.columns().contains(column))
        {
            return Err(DmlPlanError::GrantMismatch);
        }
        if matched_rule_ids.iter().any(String::is_empty)
            || matched_rule_ids.iter().collect::<BTreeSet<_>>().len() != matched_rule_ids.len()
        {
            return Err(DmlPlanError::InvalidEffectivePlan);
        }

        if let Some(predicate) = &policy_predicate {
            validate_policy_filter(predicate, &caller.resolved_columns)
                .map_err(|_| DmlPlanError::PolicyPredicateInvalid)?;
        }

        let matched = match_caller_grant(&caller, grant)?;
        let cap = u32::try_from(row_cap).map_err(|_| DmlPlanError::InvalidEffectivePlan)?;
        let rewrite = build_rewrite(
            &matched,
            grant.row_predicate(),
            policy_predicate.as_ref(),
            cap,
        )
        .map_err(|_| DmlPlanError::InvalidEffectivePlan)?;
        let impact_count_template = impact_count_template(
            rewrite.parts().target(),
            rewrite.effective_selection().clone(),
        )?;
        let execution_bind_layout = bind_layout(
            rewrite.executable_sql(),
            caller.binds.arity,
            rewrite.binds(),
        )?;
        let impact_bind_layout =
            bind_layout(&impact_count_template, caller.binds.arity, rewrite.binds())?;

        Ok(Self {
            caller,
            envelope_digest: envelope.digest(),
            policy_schema_digest,
            policy_ruleset_digest,
            matched_rule_ids,
            policy_predicate_digest,
            policy_predicate,
            grant_predicate: grant.row_predicate().clone(),
            grant_scope_digest: grant.scope_digest(),
            bind_hmac: envelope.binds.value_hmac,
            row_cap,
            rewrite,
            impact_count_template,
            execution_bind_layout,
            impact_bind_layout,
        })
    }

    #[must_use]
    pub fn effective_sql(&self) -> &str {
        self.rewrite.executable_sql()
    }

    /// The immutable physical SQL template used by both grant renderers.
    #[must_use]
    pub fn rewrite(&self) -> &GrantRewriteV1 {
        &self.rewrite
    }

    /// Values must be selected in this rendered occurrence order. This is
    /// deliberately independent of a named-bind map's iteration order.
    #[must_use]
    pub fn execution_bind_layout(&self) -> &[DmlPlanBindV1] {
        &self.execution_bind_layout
    }

    /// Count inputs omit SET-only caller values and preserve each remaining
    /// original caller position alongside distinct server-owned grant slots.
    #[must_use]
    pub fn impact_bind_layout(&self) -> &[DmlPlanBindV1] {
        &self.impact_bind_layout
    }

    #[must_use]
    pub fn caller(&self) -> &DmlCallerStatementV1 {
        &self.caller
    }

    #[must_use]
    pub fn row_cap(&self) -> u64 {
        self.row_cap
    }

    #[must_use]
    pub fn matched_rule_ids(&self) -> &[String] {
        &self.matched_rule_ids
    }

    #[must_use]
    pub fn grant_binds(&self) -> &[GrantBind] {
        self.rewrite.binds()
    }

    /// COUNT query template derived from the exact selection in
    /// [`Self::effective_sql`]. Caller binds stay in the original envelope;
    /// server-owned grant binds are returned by [`Self::grant_binds`].
    /// Select and order those values using [`Self::impact_bind_layout`], which
    /// omits SET-only binds rather than passing the execution bind vector.
    #[must_use]
    pub fn impact_count_sql(&self) -> &str {
        &self.impact_count_template
    }

    #[must_use]
    pub fn effective_selection(&self) -> &Expr {
        self.rewrite.effective_selection()
    }

    #[must_use]
    pub fn policy_predicate(&self) -> Option<&Expr> {
        self.policy_predicate.as_ref()
    }

    #[must_use]
    pub fn grant_predicate(&self) -> &GrantPredicateV1 {
        &self.grant_predicate
    }

    #[must_use]
    pub fn policy_schema_digest(&self) -> [u8; 32] {
        self.policy_schema_digest
    }

    #[must_use]
    pub fn policy_ruleset_digest(&self) -> [u8; 32] {
        self.policy_ruleset_digest
    }

    #[must_use]
    pub fn grant_scope_digest(&self) -> [u8; 32] {
        self.grant_scope_digest
    }

    /// Length-prefixed commitments keep policy order, bind values, target
    /// identity, rewrite version and final executable bytes decisive.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut bytes = Vec::new();
        put(&mut bytes, PLAN_DOMAIN);
        bytes.extend_from_slice(&DML_REWRITE_ALGORITHM_VERSION.to_be_bytes());
        put(&mut bytes, &self.caller.statement_digest);
        put(&mut bytes, self.caller.target.owner.as_bytes());
        put(&mut bytes, self.caller.target.object_name.as_bytes());
        bytes.extend_from_slice(&self.caller.target.object_id.to_be_bytes());
        match self.caller.target.data_object_id {
            Some(id) => {
                bytes.push(1);
                bytes.extend_from_slice(&id.to_be_bytes());
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(&self.caller.target.container.con_id.to_be_bytes());
        bytes.extend_from_slice(&self.caller.target.container.con_uid.to_be_bytes());
        match &self.caller.target.edition {
            Some(edition) => {
                bytes.push(1);
                put(&mut bytes, edition.as_bytes());
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(&self.caller.target.catalog_generation.0.to_be_bytes());
        match &self.caller.target.resolved_via {
            Some(synonym) => {
                bytes.push(1);
                put(&mut bytes, synonym.owner.as_bytes());
                put(&mut bytes, synonym.name.as_bytes());
                bytes.extend_from_slice(&synonym.object_id.to_be_bytes());
            }
            None => bytes.push(0),
        }
        put(&mut bytes, &self.envelope_digest);
        put(&mut bytes, &self.policy_schema_digest);
        put(&mut bytes, &self.policy_ruleset_digest);
        bytes.extend_from_slice(&(self.matched_rule_ids.len() as u64).to_be_bytes());
        for rule_id in &self.matched_rule_ids {
            put(&mut bytes, rule_id.as_bytes());
        }
        put(&mut bytes, &self.policy_predicate_digest);
        put(&mut bytes, &self.grant_scope_digest);
        put(&mut bytes, &self.bind_hmac);
        bytes.extend_from_slice(&self.row_cap.to_be_bytes());
        put(&mut bytes, self.effective_sql().as_bytes());
        put(&mut bytes, self.impact_count_template.as_bytes());
        for layout in [&self.execution_bind_layout, &self.impact_bind_layout] {
            bytes.extend_from_slice(&(layout.len() as u64).to_be_bytes());
            for slot in layout {
                match slot {
                    DmlPlanBindV1::Caller { position } => {
                        bytes.push(0);
                        bytes.extend_from_slice(&(*position as u64).to_be_bytes());
                    }
                    DmlPlanBindV1::Grant { index } => {
                        bytes.push(1);
                        bytes.extend_from_slice(&(*index as u64).to_be_bytes());
                    }
                }
            }
        }
        Sha256::digest(bytes).into()
    }
}

fn match_caller_grant(
    caller: &DmlCallerStatementV1,
    grant: &ScopedGrant,
) -> Result<crate::scoped_grant::GrantMatch, DmlPlanError> {
    let relation = match &caller.statement {
        Statement::Update(update) => &update.table.relation,
        Statement::Delete(delete) => {
            let FromTable::WithFromKeyword(tables) = &delete.from else {
                return Err(DmlPlanError::InvalidEffectivePlan);
            };
            &tables
                .first()
                .ok_or(DmlPlanError::InvalidEffectivePlan)?
                .relation
        }
        _ => return Err(DmlPlanError::InvalidEffectivePlan),
    };
    let TableFactor::Table { name, .. } = relation else {
        return Err(DmlPlanError::InvalidEffectivePlan);
    };
    let parts = name
        .0
        .iter()
        .map(|part| {
            let ident = part.as_ident().ok_or(DmlPlanError::InvalidEffectivePlan)?;
            Ok(if ident.quote_style.is_some() {
                RawNamePart::quoted(&ident.value)
            } else {
                RawNamePart::unquoted(&ident.value)
            })
        })
        .collect::<Result<Vec<_>, DmlPlanError>>()?;
    let resolved = ResolvedDmlTarget {
        raw_name: RawName::new(parts, SyntacticRole::FromFactor),
        identity: caller.target.clone(),
        object_kind: CatalogObjectKind::Table,
        columns: caller.resolved_columns.clone(),
        bind_types: caller
            .binds
            .types
            .iter()
            .enumerate()
            .map(|(index, kind)| ((index + 1).to_string(), *kind))
            .collect(),
    };
    match_statement(grant, &caller.statement, &resolved).map_err(|_| DmlPlanError::GrantMismatch)
}

fn bind_layout(
    sql: &str,
    caller_arity: usize,
    grants: &[GrantBind],
) -> Result<Vec<DmlPlanBindV1>, DmlPlanError> {
    let tokens = Tokenizer::new(&OracleDialect {}, sql)
        .tokenize()
        .map_err(|_| DmlPlanError::InvalidEffectivePlan)?;
    let mut tokens = tokens
        .into_iter()
        .filter(|token| !matches!(token, Token::Whitespace(_)));
    let mut names = Vec::new();
    while let Some(token) = tokens.next() {
        let name = match token {
            Token::Colon => match tokens.next() {
                Some(Token::Word(word)) if word.quote_style.is_none() => word.value,
                Some(Token::Number(number, false))
                    if number.bytes().all(|byte| byte.is_ascii_digit()) =>
                {
                    number
                }
                _ => return Err(DmlPlanError::InvalidEffectivePlan),
            },
            Token::Placeholder(raw) => raw
                .strip_prefix(':')
                .ok_or(DmlPlanError::InvalidEffectivePlan)?
                .to_owned(),
            _ => continue,
        };
        names.push(name);
    }
    names
        .into_iter()
        .map(|name| {
            if let Some(index) = grants
                .iter()
                .position(|bind| bind.name().eq_ignore_ascii_case(&name))
            {
                return Ok(DmlPlanBindV1::Grant { index });
            }
            let position = name
                .parse::<usize>()
                .ok()
                .filter(|position| *position > 0 && *position <= caller_arity)
                .ok_or(DmlPlanError::InvalidEffectivePlan)?;
            Ok(DmlPlanBindV1::Caller { position })
        })
        .collect()
}

fn put(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

/// A shape refusal never substitutes a zero row count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedDmlShape;

impl fmt::Display for UnsupportedDmlShape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unsupported_dml_shape")
    }
}

impl std::error::Error for UnsupportedDmlShape {}

/// Server-owned count SQL and its original bind provenance. Construction is
/// private: a count must come from the proven shape or the effective DML plan.
#[derive(Clone, Debug)]
pub struct CountQueryPlan {
    sql: String,
    binds: Vec<DmlPlanBindV1>,
}

impl CountQueryPlan {
    /// Preserve the exact W13 policy/grant predicate and bind layout. Do not
    /// reconstruct a caller-only count after a scoped rewrite has happened.
    #[must_use]
    pub fn from_effective_plan(plan: &EffectiveDmlPlanV1) -> Self {
        Self {
            sql: plan.impact_count_sql().to_owned(),
            binds: plan.impact_bind_layout().to_vec(),
        }
    }

    #[must_use]
    pub fn sql(&self) -> &str {
        &self.sql
    }

    #[must_use]
    pub fn binds(&self) -> &[DmlPlanBindV1] {
        &self.binds
    }

    /// Render positional slots in occurrence order for the database adapter.
    /// The provenance layout still names the original caller/grant values:
    /// dropping SET must never bind its value to a retained WHERE placeholder.
    pub fn positional_sql(&self) -> Result<String, UnsupportedDmlShape> {
        let mut statements =
            Parser::parse_sql(&OracleDialect {}, &self.sql).map_err(|_| UnsupportedDmlShape)?;
        let mut position = 0;
        let _: std::ops::ControlFlow<()> =
            sqlparser::ast::visit_expressions_mut(&mut statements, |expression| {
                if let Expr::Value(value) = expression
                    && matches!(value.value, Value::Placeholder(_))
                {
                    position += 1;
                    value.value = Value::Placeholder(format!(":{position}"));
                }
                std::ops::ControlFlow::Continue(())
            });
        if position != self.binds.len() || statements.len() != 1 {
            return Err(UnsupportedDmlShape);
        }
        Ok(statements[0].to_string())
    }
}

/// Equivalent row-selection proof for the ordinary session DML path. The
/// supplied statement must already include the server's policy predicate.
/// This is syntax/identity proof, not a second mutation-effect analyzer.
pub struct DmlImpactShapeV1;

impl DmlImpactShapeV1 {
    pub fn prove(
        statement: &Statement,
        resolved: &crate::resolver::ResolvedObject,
    ) -> Result<CountQueryPlan, UnsupportedDmlShape> {
        if resolved.kind != CatalogObjectKind::Table
            || resolved.db_link.is_some()
            || !resolved.synonym_chain.is_empty()
            || resolved.member.is_some()
            || resolved.identity.object_id == 0
        {
            return Err(UnsupportedDmlShape);
        }
        let (relation, selection) = match statement {
            Statement::Update(update)
                if update.from.is_none()
                    && update.table.joins.is_empty()
                    && update.optimizer_hints.is_empty()
                    && update.returning.is_none()
                    && update.output.is_none()
                    && update.or.is_none()
                    && update.order_by.is_empty()
                    && update.limit.is_none()
                    && !update.assignments.is_empty() =>
            {
                (&update.table.relation, update.selection.as_ref())
            }
            Statement::Delete(delete)
                if delete.tables.is_empty()
                    && delete.using.is_none()
                    && delete.optimizer_hints.is_empty()
                    && delete.returning.is_none()
                    && delete.output.is_none()
                    && delete.order_by.is_empty()
                    && delete.limit.is_none() =>
            {
                let FromTable::WithFromKeyword(tables) = &delete.from else {
                    return Err(UnsupportedDmlShape);
                };
                let [table] = tables.as_slice() else {
                    return Err(UnsupportedDmlShape);
                };
                if !table.joins.is_empty() {
                    return Err(UnsupportedDmlShape);
                }
                (&table.relation, delete.selection.as_ref())
            }
            _ => return Err(UnsupportedDmlShape),
        };
        check_table_target(relation, &resolved.owner, &resolved.name, &resolved.owner)
            .map_err(|_| UnsupportedDmlShape)?;
        let target = format!(
            "\"{}\".\"{}\"",
            resolved.owner.replace('"', "\"\""),
            resolved.name.replace('"', "\"\"")
        );
        let selection = selection.cloned().ok_or(UnsupportedDmlShape)?;
        let sql = impact_count_template(&target, selection).map_err(|_| UnsupportedDmlShape)?;
        crate::semantic_read_plan_checked(&sql).map_err(|_| UnsupportedDmlShape)?;
        let binds = bind_layout(&sql, usize::MAX, &[]).map_err(|_| UnsupportedDmlShape)?;
        Ok(CountQueryPlan { sql, binds })
    }
}

fn impact_count_template(
    target: &impl fmt::Display,
    selection: Expr,
) -> Result<String, DmlPlanError> {
    let sql = format!("SELECT COUNT(*) FROM {target}");
    let mut statements = Parser::parse_sql(&OracleDialect {}, &sql)
        .map_err(|_| DmlPlanError::InvalidEffectivePlan)?;
    let [Statement::Query(query)] = statements.as_mut_slice() else {
        return Err(DmlPlanError::InvalidEffectivePlan);
    };
    let SetExpr::Select(select) = query.body.as_mut() else {
        return Err(DmlPlanError::InvalidEffectivePlan);
    };
    select.selection = Some(selection);
    Ok(statements[0].to_string())
}
