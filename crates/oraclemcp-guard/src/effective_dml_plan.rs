//! Closed caller-DML grammar and the immutable input to the W13 rewrite.
//!
//! This module accepts only one local UPDATE/DELETE against a catalog-resolved
//! target. The WHERE is an AND-list of comparisons between resolved target
//! columns and typed literals or positional binds. Every other expression is
//! refused before a scoped grant can use it. The executable rewrite is built
//! by the later grant-rewrite consumer, never from caller-supplied SQL text.
//! This module defines that consumer's binding contract; current dispatch
//! still refuses scoped-grant execution until the rewrite is wired.

use std::collections::BTreeSet;
use std::fmt;

use sha2::{Digest, Sha256};
use sqlparser::ast::{
    AssignmentTarget, BinaryOperator, DataType, Expr, FromTable, ObjectName, Statement,
    TableFactor, Value,
};
use sqlparser::dialect::OracleDialect;
use sqlparser::parser::Parser;

use crate::action_envelope::{ActionEnvelopeV1, ActionKind, BindEnvelope, OracleBindType};
use crate::scoped_grant::{ColumnIdent, GrantTargetIdentity, GrantVerb, MAX_IN_LIST_VALUES};

const PLAN_DOMAIN: &[u8] = b"omcp/effective-dml-plan/v1";
/// Every change to the W13 SQL template must change this version.
pub const DML_REWRITE_ALGORITHM_VERSION: u16 = 1;
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
    BindCountMismatch,
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
            Self::BindCountMismatch => "DML_PLAN_BIND_COUNT_MISMATCH",
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
                    check_value(&assignment.value, binds, &mut bind_positions)
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
            binds,
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
        [table] => table == &target.object_name && current_schema == target.owner,
        [owner, table] => owner == &target.owner && table == &target.object_name,
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

fn check_value(
    expr: &Expr,
    binds: &BindEnvelope,
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
                let index = raw
                    .strip_prefix(':')
                    .and_then(|number| number.parse::<usize>().ok())
                    .filter(|index| *index > 0 && *index <= binds.arity)
                    .ok_or(DmlPlanError::InvalidBind)?;
                match binds.types[index - 1] {
                    OracleBindType::String
                    | OracleBindType::I64
                    | OracleBindType::F64
                    | OracleBindType::TimestampTz => {
                        if positions.insert(index) {
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
    binds: &BindEnvelope,
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

/// Bound components of one executable DML rewrite. The server-owned renderer
/// must supply its exact final SQL; construction binds it but does not prove
/// rewrite correctness or authorize execution.
pub struct EffectiveDmlPlanV1 {
    caller: DmlCallerStatementV1,
    envelope_digest: [u8; 32],
    policy_schema_digest: [u8; 32],
    policy_ruleset_digest: [u8; 32],
    matched_rule_ids: Vec<String>,
    policy_predicate_digest: [u8; 32],
    grant_scope_digest: [u8; 32],
    bind_hmac: [u8; 32],
    row_cap: u64,
    executable_template: String,
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
    /// Assemble a binding after the server-owned rewriter has checked the
    /// template. This function verifies envelope identity, not rewrite
    /// semantics. The consumer must classify final SQL and compare the plan
    /// digest at apply; it must never use caller-supplied template text.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_rewrite(
        caller: DmlCallerStatementV1,
        envelope: &ActionEnvelopeV1,
        policy_schema_digest: [u8; 32],
        policy_ruleset_digest: [u8; 32],
        matched_rule_ids: Vec<String>,
        policy_predicate_digest: [u8; 32],
        grant_scope_digest: [u8; 32],
        row_cap: u64,
        executable_template: String,
    ) -> Result<Self, DmlPlanError> {
        if row_cap == 0
            || executable_template.is_empty()
            || executable_template.contains('\0')
            || envelope.version != 1
            || envelope.action_kind != ActionKind::ExecuteDml
            || envelope.statement_digest != caller.statement_digest
            || envelope.binds != caller.binds
        {
            return Err(DmlPlanError::InvalidEffectivePlan);
        }
        Ok(Self {
            caller,
            envelope_digest: envelope.digest(),
            policy_schema_digest,
            policy_ruleset_digest,
            matched_rule_ids,
            policy_predicate_digest,
            grant_scope_digest,
            bind_hmac: envelope.binds.value_hmac,
            row_cap,
            executable_template,
        })
    }

    #[must_use]
    pub fn effective_sql(&self) -> &str {
        &self.executable_template
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
        put(&mut bytes, self.executable_template.as_bytes());
        Sha256::digest(bytes).into()
    }
}

fn put(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}
