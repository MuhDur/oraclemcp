//! Per-schema scoping & allow/deny policy (plan §6.2; bead P1-POLICY).
//!
//! A policy can only ever **further restrict** the classifier's verdict — never
//! loosen it. `SYSTEM`/`SYS`/`SYSAUX` are deny-all by default and cannot be
//! unlocked by an allow-once token. Schema is resolved by the caller from the
//! parsed `ObjectName` (or `SYS_CONTEXT('USERENV','CURRENT_SCHEMA')`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use sqlparser::ast::{
    BinaryOperator, Expr, FromTable, ObjectName, SetExpr, Statement, TableFactor, TableWithJoins,
};
use sqlparser::dialect::OracleDialect;
use sqlparser::parser::Parser;
use sqlparser::tokenizer::Token;

use crate::classifier::{Classifier, GuardDecision};
use crate::levels::{DangerLevel, OperatingLevel};

/// The only SQL-policy grammar version accepted by this build.
pub const SQL_POLICY_VERSION: u32 = 1;

/// A versioned, profile-scoped Arc N policy configuration.
///
/// This is deliberately only the parsed and validated grammar. The evaluator
/// arrives in N2; keeping the grammar in the guard crate gives the loader and
/// evaluator one tightening-only contract to share.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqlPolicyConfig {
    /// Version of the declarative policy grammar.
    pub version: u32,
    /// Ordered policy rules. Matching rules compose; this order is retained for
    /// later audit and predicate rendering, never allow/else precedence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<SqlPolicyRuleConfig>,
}

impl SqlPolicyConfig {
    /// Validate the version-one grammar before a policy can enter the runtime.
    ///
    /// The return type identifies the exact policy-relative field so the
    /// profile loader can report an actionable, profile-scoped configuration
    /// error without accepting a malformed restriction as a silent no-op.
    pub fn validate(&self) -> Result<(), SqlPolicyValidationError> {
        if self.version != SQL_POLICY_VERSION {
            return Err(SqlPolicyValidationError::new(
                "version",
                format!(
                    "must be {SQL_POLICY_VERSION}; unknown policy grammar versions are refused"
                ),
            ));
        }

        let mut ids = BTreeSet::new();
        for (index, rule) in self.rules.iter().enumerate() {
            rule.validate(index)?;
            if !ids.insert(rule.id.as_str()) {
                return Err(SqlPolicyValidationError::new(
                    format!("rules[{index}].id"),
                    "must be unique within one sql_policy",
                ));
            }
        }
        Ok(())
    }
}

/// One declarative Arc N rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SqlPolicyRuleConfig {
    /// Non-secret stable rule identifier, retained by later audit/certificates.
    pub id: String,
    /// Conjunctive semantic selectors.
    #[serde(rename = "match")]
    pub match_clause: SqlPolicyMatchConfig,
    /// The only structurally tightening effects the grammar can express.
    pub effect: SqlPolicyEffectConfig,
}

impl SqlPolicyRuleConfig {
    fn validate(&self, index: usize) -> Result<(), SqlPolicyValidationError> {
        let prefix = format!("rules[{index}]");
        if !valid_rule_id(&self.id) {
            return Err(SqlPolicyValidationError::new(
                format!("{prefix}.id"),
                "must be 1..=128 ASCII letters, digits, `_`, `-`, or `.`, beginning with a letter or digit",
            ));
        }
        self.match_clause.validate(&prefix)?;
        if let SqlPolicyEffectConfig::RequirePredicate { sql_fragment } = &self.effect {
            self.match_clause.validate_predicate_target(&prefix)?;
            if !valid_policy_predicate(sql_fragment) {
                return Err(SqlPolicyValidationError::new(
                    format!("{prefix}.effect.sql_fragment"),
                    "must be a comment-free, semicolon-free conjunction of simple row-filter atoms; functions, subqueries, binds, and OR are not permitted",
                ));
            }
        }
        Ok(())
    }
}

/// Semantic selectors for one Arc N rule. Omitted selectors match every value
/// for that dimension; an empty table is therefore a deliberate global
/// tightening rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SqlPolicyMatchConfig {
    /// Optional resolved Oracle owner/schema selector.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// Optional resolved object selector, valid only together with `schema`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    /// Optional top-level verb supplied by the classifier, never by a tool arg.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verb: Option<SqlPolicyVerb>,
    /// Optional exact server-derived stable principal key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<String>,
}

impl SqlPolicyMatchConfig {
    fn validate(&self, prefix: &str) -> Result<(), SqlPolicyValidationError> {
        for (field, value) in [("schema", &self.schema), ("object", &self.object)] {
            if let Some(value) = value
                && !valid_oracle_identifier(value)
            {
                return Err(SqlPolicyValidationError::new(
                    format!("{prefix}.match.{field}"),
                    "must be one Oracle identifier; dots, globs, regexes, and empty values are not permitted",
                ));
            }
        }
        if self.object.is_some() && self.schema.is_none() {
            return Err(SqlPolicyValidationError::new(
                format!("{prefix}.match.object"),
                "requires match.schema so the target relation is exact",
            ));
        }
        if let Some(principal) = &self.principal
            && !valid_principal_key(principal)
        {
            return Err(SqlPolicyValidationError::new(
                format!("{prefix}.match.principal"),
                "must be an exact server-derived key such as oauth:<stable-id> or mtls:<fingerprint>",
            ));
        }
        Ok(())
    }

    fn validate_predicate_target(&self, prefix: &str) -> Result<(), SqlPolicyValidationError> {
        if self.schema.is_none() || self.object.is_none() {
            return Err(SqlPolicyValidationError::new(
                format!("{prefix}.match"),
                "RequirePredicate requires exact match.schema and match.object selectors",
            ));
        }
        if !matches!(
            self.verb,
            Some(SqlPolicyVerb::Select | SqlPolicyVerb::Update | SqlPolicyVerb::Delete)
        ) {
            return Err(SqlPolicyValidationError::new(
                format!("{prefix}.match.verb"),
                "RequirePredicate requires verb = select, update, or delete",
            ));
        }
        Ok(())
    }
}

/// Top-level statement verbs that Arc N may match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlPolicyVerb {
    /// A query-shaped SELECT or WITH statement.
    Select,
    /// An INSERT statement.
    Insert,
    /// An UPDATE statement.
    Update,
    /// A DELETE statement.
    Delete,
    /// A MERGE statement.
    Merge,
    /// A DDL statement.
    Ddl,
    /// An ADMIN/DCL statement.
    Admin,
    /// A PL/SQL block or stored-program invocation.
    Plsql,
    /// An ALTER SESSION statement.
    AlterSession,
}

/// The complete set of policy effects. There is deliberately no `Allow`,
/// override, or classifier-configuration variant, making a loosening effect
/// unrepresentable in a successfully loaded policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SqlPolicyEffectConfig {
    /// Refuse the matched statement.
    Deny,
    /// Add an operating-level floor; N2 will compose it with the base level by
    /// taking the maximum, never by replacement.
    RequireLevel {
        /// Minimum operating level imposed by this rule.
        level: OperatingLevel,
    },
    /// Add a static conjunctive row filter after AST placement and mandatory
    /// reclassification in N3.
    RequirePredicate {
        /// Restricted Oracle boolean predicate defined by ADR 0009.
        sql_fragment: String,
    },
}

/// Server-derived semantic facts to which a loaded Arc N policy is applied.
///
/// `schema` and `object` must be resolved Oracle identities, not tool-supplied
/// string hints. An absent value simply cannot satisfy a rule that selects that
/// dimension. `principal` is likewise a stable server-derived identity key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqlPolicyEvaluationContext {
    /// Resolved owning schema, when the statement has one exact target.
    pub schema: Option<String>,
    /// Resolved object name, when the statement has one exact target.
    pub object: Option<String>,
    /// Top-level verb established by classification, never a caller assertion.
    pub verb: SqlPolicyVerb,
    /// Stable server-derived principal key, if authentication supplied one.
    pub principal: Option<String>,
}

impl SqlPolicyEvaluationContext {
    /// Construct a context from already-resolved, server-derived facts.
    #[must_use]
    pub fn new(
        schema: Option<String>,
        object: Option<String>,
        verb: SqlPolicyVerb,
        principal: Option<String>,
    ) -> Self {
        Self {
            schema,
            object,
            verb,
            principal,
        }
    }
}

/// The one exact relation to which a policy predicate may be attached in N3.
///
/// Keeping the target in the proof makes it impossible for the rewrite stage
/// to guess which relation a static row filter was meant to narrow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlPolicyPredicateTarget {
    /// Canonical policy schema selector.
    pub schema: String,
    /// Canonical policy object selector.
    pub object: String,
    /// The only statement verb to which the predicate applies.
    pub verb: SqlPolicyVerb,
}

/// One proof-carrying static predicate narrowing retained for N3 rewrite and
/// later verdict/audit certificates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SqlPolicyPredicate {
    /// Stable identifier of the rule that introduced this predicate.
    pub rule_id: String,
    /// Exact relation and verb the predicate is allowed to constrain.
    pub target: SqlPolicyPredicateTarget,
    /// Validated static conjunction from the loaded policy.
    pub sql_fragment: String,
}

/// Why policy composition refused a base statement.
///
/// This is intentionally a closed, redacted vocabulary: neither a raw SQL
/// string nor an operator-provided free-form reason becomes an authorization
/// proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDenialReason {
    /// The base classifier already returned `Forbidden`.
    BaseClassifierRefused,
    /// The supplied base decision lacked a required operating level.
    IncompleteBaseDecision,
    /// The policy was not a successfully loadable tightening-only grammar.
    InvalidPolicy,
    /// One or more matching declarative rules explicitly deny the statement.
    MatchingDenyRule,
    /// Matching predicates did not name one identical exact target relation.
    PredicateTargetConflict,
}

/// A proof-carrying Arc N denial.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDenial {
    /// Stable failure category for audit/certification consumers.
    pub reason: PolicyDenialReason,
    /// Every matching rule considered before this denial was returned.
    pub matched_rule_ids: Vec<String>,
}

/// A proof-carrying monotone narrowing of a non-forbidden base decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyNarrowing {
    /// The classifier's already-required level; policy never lowers it.
    pub base_required_level: OperatingLevel,
    /// The final floor after taking the maximum of all matched level rules.
    pub required_level: OperatingLevel,
    /// Static predicate constraints, in declaration order, for N3 to rewrite
    /// and re-classify before any execution.
    pub predicates: Vec<SqlPolicyPredicate>,
    /// Stable identifiers of all matched narrowing rules, in declaration order.
    pub matched_rule_ids: Vec<String>,
}

impl PolicyNarrowing {
    /// The policy identity: it adds no restriction and grants no authority.
    #[must_use]
    pub fn identity(base_required_level: OperatingLevel) -> Self {
        Self {
            base_required_level,
            required_level: base_required_level,
            predicates: Vec::new(),
            matched_rule_ids: Vec::new(),
        }
    }

    /// Whether this result added no policy constraint to the base decision.
    #[must_use]
    pub fn is_identity(&self) -> bool {
        self.required_level == self.base_required_level
            && self.predicates.is_empty()
            && self.matched_rule_ids.is_empty()
    }
}

/// The complete Arc N policy outcome.
///
/// There is deliberately no `Allow` outcome. A [`PolicyNarrowing`] only
/// describes restrictions applied to a base classifier decision; dispatch must
/// still apply that decision's level gate and all later safety checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyTightening {
    /// Refuse the operation before dispatch.
    Deny(PolicyDenial),
    /// Preserve the base decision while adding zero or more restrictions.
    Narrow(PolicyNarrowing),
}

impl SqlPolicyConfig {
    /// Compose this loaded policy with a classifier decision as `base AND
    /// policy`.
    ///
    /// The base classifier is checked first, so no declarative rule can turn a
    /// refused statement into a dispatchable one. Every successful result
    /// carries the base level plus the exact matched rule identifiers and
    /// predicates needed by later certificate and rewrite stages.
    #[must_use]
    pub fn evaluate(
        &self,
        base: &GuardDecision,
        context: &SqlPolicyEvaluationContext,
    ) -> PolicyTightening {
        if base.danger == DangerLevel::Forbidden {
            return policy_deny(PolicyDenialReason::BaseClassifierRefused, Vec::new());
        }
        let Some(base_required_level) = base.required_level else {
            return policy_deny(PolicyDenialReason::IncompleteBaseDecision, Vec::new());
        };
        if self.validate().is_err() {
            return policy_deny(PolicyDenialReason::InvalidPolicy, Vec::new());
        }

        let mut narrowing = PolicyNarrowing::identity(base_required_level);
        let mut deny_matched = false;
        let mut predicate_target = None;

        for rule in &self.rules {
            if !rule_matches_context(rule, context) {
                continue;
            }
            narrowing.matched_rule_ids.push(rule.id.clone());
            match &rule.effect {
                SqlPolicyEffectConfig::Deny => deny_matched = true,
                SqlPolicyEffectConfig::RequireLevel { level } => {
                    narrowing.required_level = narrowing.required_level.max(*level);
                }
                SqlPolicyEffectConfig::RequirePredicate { sql_fragment } => {
                    let Some(target) = SqlPolicyPredicateTarget::from_rule(rule) else {
                        return policy_deny(
                            PolicyDenialReason::InvalidPolicy,
                            narrowing.matched_rule_ids,
                        );
                    };
                    if let Some(expected) = &predicate_target
                        && expected != &target
                    {
                        return policy_deny(
                            PolicyDenialReason::PredicateTargetConflict,
                            narrowing.matched_rule_ids,
                        );
                    }
                    predicate_target = Some(target.clone());
                    narrowing.predicates.push(SqlPolicyPredicate {
                        rule_id: rule.id.clone(),
                        target,
                        sql_fragment: sql_fragment.clone(),
                    });
                }
            }
        }

        if deny_matched {
            return policy_deny(
                PolicyDenialReason::MatchingDenyRule,
                narrowing.matched_rule_ids,
            );
        }
        PolicyTightening::Narrow(narrowing)
    }
}

impl SqlPolicyPredicateTarget {
    fn from_rule(rule: &SqlPolicyRuleConfig) -> Option<Self> {
        let SqlPolicyEffectConfig::RequirePredicate { .. } = rule.effect else {
            return None;
        };
        Some(Self {
            schema: canonical_policy_identifier(rule.match_clause.schema.as_deref()?),
            object: canonical_policy_identifier(rule.match_clause.object.as_deref()?),
            verb: rule.match_clause.verb?,
        })
    }
}

fn policy_deny(reason: PolicyDenialReason, matched_rule_ids: Vec<String>) -> PolicyTightening {
    PolicyTightening::Deny(PolicyDenial {
        reason,
        matched_rule_ids,
    })
}

fn rule_matches_context(rule: &SqlPolicyRuleConfig, context: &SqlPolicyEvaluationContext) -> bool {
    let matcher = &rule.match_clause;
    optional_identifier_matches(matcher.schema.as_deref(), context.schema.as_deref())
        && optional_identifier_matches(matcher.object.as_deref(), context.object.as_deref())
        && matcher.verb.is_none_or(|verb| verb == context.verb)
        && matcher
            .principal
            .as_deref()
            .is_none_or(|principal| context.principal.as_deref() == Some(principal))
}

fn optional_identifier_matches(selector: Option<&str>, actual: Option<&str>) -> bool {
    selector.is_none_or(|selector| {
        actual.is_some_and(|actual| policy_identifier_matches(selector, actual))
    })
}

fn policy_identifier_matches(selector: &str, actual: &str) -> bool {
    if selector.starts_with('"') {
        unquote_policy_identifier(selector).is_some_and(|quoted| quoted == actual)
    } else {
        selector.eq_ignore_ascii_case(actual)
    }
}

fn canonical_policy_identifier(selector: &str) -> String {
    unquote_policy_identifier(selector).unwrap_or_else(|| selector.to_ascii_uppercase())
}

fn unquote_policy_identifier(selector: &str) -> Option<String> {
    selector
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .map(|inner| inner.replace("\"\"", "\""))
}

/// Why an attempted `RequirePredicate` AST rewrite was refused.
///
/// Every variant is fail-closed. In particular, an unsupported statement shape
/// is a denial rather than a best-effort textual rewrite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyRewriteDenialReason {
    /// The caller tried to rewrite a base statement the classifier refused.
    BaseClassifierRefused,
    /// The narrowing did not carry the same base level as the supplied verdict.
    InconsistentBaseDecision,
    /// No predicate exists to place in the candidate AST.
    NoPredicates,
    /// Predicate rules did not retain one common exact target.
    PredicateTargetConflict,
    /// The server-derived context disagreed with the predicate target.
    TargetContextMismatch,
    /// The original statement could not be parsed as exactly one statement.
    OriginalParseFailed,
    /// The statement was not the deliberately small rewritable v1 subset.
    UnsupportedStatementShape,
    /// A configured predicate could not be parsed as exactly one expression.
    PredicateParseFailed,
    /// The rendered candidate classifier returned `Forbidden`.
    CandidateClassifierRefused,
    /// A read-only base became a non-read-only candidate after rendering.
    CandidateNotReadOnly,
    /// A non-forbidden candidate lacked an operating-level requirement.
    IncompleteCandidateDecision,
}

/// Proof retained when the mandatory rewrite/reclassification stage denies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRewriteDenial {
    /// Stable reason category; no raw SQL or operator text is retained here.
    pub reason: PolicyRewriteDenialReason,
    /// The narrowing rule ids that led to this attempted rewrite.
    pub matched_rule_ids: Vec<String>,
}

/// A rendered policy candidate that has passed mandatory reclassification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyReclassifiedStatement {
    /// AST-rendered candidate SQL. It is a new statement, not an authorization
    /// for the original bytes.
    pub sql: String,
    /// Decision produced by classifying the rendered candidate with the same
    /// classifier configuration as the original statement.
    pub candidate: GuardDecision,
    /// Maximum danger of the original and rendered statements.
    pub final_danger: DangerLevel,
    /// Maximum of base, policy-floor, and candidate required levels.
    pub final_required_level: OperatingLevel,
}

/// Outcome of applying `RequirePredicate` rules after a successful N2 narrow.
///
/// There is no success-by-default or `Allow` form: callers can either receive
/// a reclassified candidate or a typed refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyPredicateRewrite {
    /// Rewriting or candidate classification failed closed.
    Deny(PolicyRewriteDenial),
    /// A newly rendered candidate passed mandatory reclassification.
    Reclassified(Box<PolicyReclassifiedStatement>),
}

/// Add the policy predicates to a parsed AST and immediately re-classify the
/// rendered candidate (SEC-1).
///
/// Version one intentionally accepts only one exact, unaliased target relation
/// in a plain `SELECT`, `UPDATE`, or `DELETE`. Joins, CTEs, derived relations,
/// aliases, and every unrecognised shape are denied rather than rewritten by
/// text manipulation. The returned final level is the maximum of the original
/// classification, N2's policy floor, and the candidate classification.
#[must_use]
pub fn rewrite_predicates_and_reclassify(
    classifier: &Classifier,
    base: &GuardDecision,
    original_sql: &str,
    context: &SqlPolicyEvaluationContext,
    narrowing: &PolicyNarrowing,
) -> PolicyPredicateRewrite {
    if base.danger == DangerLevel::Forbidden {
        return rewrite_deny(PolicyRewriteDenialReason::BaseClassifierRefused, narrowing);
    }
    let Some(base_required_level) = base.required_level else {
        return rewrite_deny(
            PolicyRewriteDenialReason::InconsistentBaseDecision,
            narrowing,
        );
    };
    if base_required_level != narrowing.base_required_level
        || narrowing.required_level < narrowing.base_required_level
    {
        return rewrite_deny(
            PolicyRewriteDenialReason::InconsistentBaseDecision,
            narrowing,
        );
    }

    let Some(first_predicate) = narrowing.predicates.first() else {
        return rewrite_deny(PolicyRewriteDenialReason::NoPredicates, narrowing);
    };
    let target = &first_predicate.target;
    if !predicate_target_matches_context(target, context) {
        return rewrite_deny(PolicyRewriteDenialReason::TargetContextMismatch, narrowing);
    }
    if narrowing
        .predicates
        .iter()
        .any(|predicate| predicate.target != *target)
    {
        return rewrite_deny(
            PolicyRewriteDenialReason::PredicateTargetConflict,
            narrowing,
        );
    }

    let predicate = match combined_policy_predicate(&narrowing.predicates) {
        Ok(predicate) => predicate,
        Err(reason) => return rewrite_deny(reason, narrowing),
    };
    let dialect = OracleDialect {};
    let mut statements = match Parser::parse_sql(&dialect, original_sql) {
        Ok(statements) if statements.len() == 1 => statements,
        _ => return rewrite_deny(PolicyRewriteDenialReason::OriginalParseFailed, narrowing),
    };
    let Some(statement) = statements.pop() else {
        return rewrite_deny(PolicyRewriteDenialReason::OriginalParseFailed, narrowing);
    };
    let mut statement = statement;
    if rewrite_statement_ast(&mut statement, target, predicate).is_err() {
        return rewrite_deny(
            PolicyRewriteDenialReason::UnsupportedStatementShape,
            narrowing,
        );
    }

    let sql = statement.to_string();
    let candidate = classifier.classify(&sql);
    finalize_reclassified_candidate(base, narrowing, sql, candidate)
}

fn rewrite_deny(
    reason: PolicyRewriteDenialReason,
    narrowing: &PolicyNarrowing,
) -> PolicyPredicateRewrite {
    PolicyPredicateRewrite::Deny(PolicyRewriteDenial {
        reason,
        matched_rule_ids: narrowing.matched_rule_ids.clone(),
    })
}

fn predicate_target_matches_context(
    target: &SqlPolicyPredicateTarget,
    context: &SqlPolicyEvaluationContext,
) -> bool {
    target.verb == context.verb
        && context.schema.as_deref() == Some(target.schema.as_str())
        && context.object.as_deref() == Some(target.object.as_str())
}

fn combined_policy_predicate(
    predicates: &[SqlPolicyPredicate],
) -> Result<Expr, PolicyRewriteDenialReason> {
    let mut expressions = predicates
        .iter()
        .map(|predicate| parse_policy_predicate(&predicate.sql_fragment));
    let Some(first) = expressions.next() else {
        return Err(PolicyRewriteDenialReason::NoPredicates);
    };
    expressions.try_fold(first?, |current, next| {
        Ok(Expr::BinaryOp {
            left: Box::new(Expr::Nested(Box::new(current))),
            op: BinaryOperator::And,
            right: Box::new(Expr::Nested(Box::new(next?))),
        })
    })
}

fn parse_policy_predicate(sql_fragment: &str) -> Result<Expr, PolicyRewriteDenialReason> {
    let dialect = OracleDialect {};
    let mut parser = Parser::new(&dialect)
        .try_with_sql(sql_fragment)
        .map_err(|_| PolicyRewriteDenialReason::PredicateParseFailed)?;
    let expression = parser
        .parse_expr()
        .map_err(|_| PolicyRewriteDenialReason::PredicateParseFailed)?;
    parser
        .expect_token(&Token::EOF)
        .map_err(|_| PolicyRewriteDenialReason::PredicateParseFailed)?;
    Ok(expression)
}

fn rewrite_statement_ast(
    statement: &mut Statement,
    target: &SqlPolicyPredicateTarget,
    predicate: Expr,
) -> Result<(), ()> {
    match statement {
        Statement::Query(query) if target.verb == SqlPolicyVerb::Select => {
            if query.with.is_some()
                || !query.locks.is_empty()
                || !matches!(query.body.as_ref(), SetExpr::Select(_))
            {
                return Err(());
            }
            let SetExpr::Select(select) = query.body.as_mut() else {
                return Err(());
            };
            if select.from.len() != 1 || !exact_target_table(&select.from[0], target) {
                return Err(());
            }
            append_policy_predicate(&mut select.selection, predicate);
            Ok(())
        }
        Statement::Update(update) if target.verb == SqlPolicyVerb::Update => {
            if update.from.is_some() || !exact_target_table(&update.table, target) {
                return Err(());
            }
            append_policy_predicate(&mut update.selection, predicate);
            Ok(())
        }
        Statement::Delete(delete) if target.verb == SqlPolicyVerb::Delete => {
            if delete.using.is_some() || !delete.tables.is_empty() {
                return Err(());
            }
            let tables = match &delete.from {
                FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables) => tables,
            };
            if tables.len() != 1 || !exact_target_table(&tables[0], target) {
                return Err(());
            }
            append_policy_predicate(&mut delete.selection, predicate);
            Ok(())
        }
        _ => Err(()),
    }
}

fn exact_target_table(table: &TableWithJoins, target: &SqlPolicyPredicateTarget) -> bool {
    if !table.joins.is_empty() {
        return false;
    }
    let TableFactor::Table {
        name,
        alias,
        args,
        with_hints,
        version,
        with_ordinality,
        partitions,
        json_path,
        sample,
        index_hints,
    } = &table.relation
    else {
        return false;
    };
    alias.is_none()
        && args.is_none()
        && with_hints.is_empty()
        && version.is_none()
        && !with_ordinality
        && partitions.is_empty()
        && json_path.is_none()
        && sample.is_none()
        && index_hints.is_empty()
        && exact_target_name(name, target)
}

fn exact_target_name(name: &ObjectName, target: &SqlPolicyPredicateTarget) -> bool {
    let parts = &name.0;
    let Some(object) = parts
        .last()
        .and_then(sqlparser::ast::ObjectNamePart::as_ident)
    else {
        return false;
    };
    if !oracle_identifier_matches_target(object.value.as_str(), object.quote_style, &target.object)
    {
        return false;
    }
    match parts.len() {
        // The caller's semantic context already proved the current schema; an
        // unqualified direct table name is therefore exact enough for v1.
        1 => true,
        2 => parts[0].as_ident().is_some_and(|schema| {
            oracle_identifier_matches_target(
                schema.value.as_str(),
                schema.quote_style,
                &target.schema,
            )
        }),
        _ => false,
    }
}

fn oracle_identifier_matches_target(actual: &str, quote_style: Option<char>, target: &str) -> bool {
    if quote_style.is_some() {
        actual == target
    } else {
        actual.eq_ignore_ascii_case(target)
    }
}

fn append_policy_predicate(selection: &mut Option<Expr>, predicate: Expr) {
    let predicate = Expr::Nested(Box::new(predicate));
    *selection = Some(match selection.take() {
        Some(existing) => Expr::BinaryOp {
            left: Box::new(Expr::Nested(Box::new(existing))),
            op: BinaryOperator::And,
            right: Box::new(predicate),
        },
        None => predicate,
    });
}

fn finalize_reclassified_candidate(
    base: &GuardDecision,
    narrowing: &PolicyNarrowing,
    sql: String,
    candidate: GuardDecision,
) -> PolicyPredicateRewrite {
    if candidate.danger == DangerLevel::Forbidden {
        return rewrite_deny(
            PolicyRewriteDenialReason::CandidateClassifierRefused,
            narrowing,
        );
    }
    let Some(candidate_required_level) = candidate.required_level else {
        return rewrite_deny(
            PolicyRewriteDenialReason::IncompleteCandidateDecision,
            narrowing,
        );
    };
    if base.required_level == Some(OperatingLevel::ReadOnly)
        && (candidate.danger != DangerLevel::Safe
            || candidate_required_level != OperatingLevel::ReadOnly)
    {
        return rewrite_deny(PolicyRewriteDenialReason::CandidateNotReadOnly, narrowing);
    }

    PolicyPredicateRewrite::Reclassified(Box::new(PolicyReclassifiedStatement {
        sql,
        final_danger: base.danger.max(candidate.danger),
        final_required_level: narrowing.required_level.max(candidate_required_level),
        candidate,
    }))
}

/// A load-time SQL-policy grammar failure with the policy-relative field and a
/// non-secret, actionable reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqlPolicyValidationError {
    /// Policy-relative field, such as `rules[0].match.object`.
    pub field: String,
    /// Why the field is rejected.
    pub reason: String,
}

impl SqlPolicyValidationError {
    fn new(field: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for SqlPolicyValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid sql_policy.{}: {}", self.field, self.reason)
    }
}

impl std::error::Error for SqlPolicyValidationError {}

fn valid_rule_id(value: &str) -> bool {
    let mut chars = value.bytes();
    matches!(chars.next(), Some(byte) if byte.is_ascii_alphanumeric())
        && value.len() <= 128
        && chars.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_oracle_identifier(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 {
        return false;
    }
    if value.starts_with('"') || value.ends_with('"') {
        if !value.starts_with('"') || !value.ends_with('"') || value.len() == 2 {
            return false;
        }
        let inner = &value[1..value.len() - 1];
        let mut chars = inner.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch.is_control() {
                return false;
            }
            if ch == '"' && chars.next_if_eq(&'"').is_none() {
                return false;
            }
        }
        return true;
    }
    let mut chars = value.bytes();
    matches!(chars.next(), Some(byte) if byte.is_ascii_alphabetic())
        && chars.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$' | b'#'))
}

fn valid_principal_key(value: &str) -> bool {
    let Some((kind, stable_id)) = value.split_once(':') else {
        return false;
    };
    !kind.is_empty()
        && !stable_id.is_empty()
        && kind
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && value.bytes().all(|byte| {
            byte.is_ascii_graphic() && !matches!(byte, b'*' | b'?' | b'[' | b']' | b'\\')
        })
}

fn valid_policy_predicate(value: &str) -> bool {
    let value = value.trim();
    if value.is_empty()
        || value.contains([';', '\n', '\r'])
        || value.contains("--")
        || value.contains("/*")
        || value.contains("*/")
    {
        return false;
    }
    policy_predicate_pattern().is_match(value)
}

fn policy_predicate_pattern() -> &'static Regex {
    static PATTERN: OnceLock<Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        let identifier = r#"(?:[A-Za-z][A-Za-z0-9_$#]*|\"(?:[^\"]|\"\")+\")"#;
        let column = format!(r"(?:{identifier}\.)?{identifier}");
        let value = r"(?:[+-]?(?:\d+(?:\.\d*)?|\.\d+)|'(?:[^']|'')*'|NULL)";
        let atom = format!(
            r"(?:{column}\s*(?:=|<>|!=|<=|>=|<|>|LIKE)\s*{value}|{column}\s+IS\s+(?:NOT\s+)?NULL)"
        );
        Regex::new(&format!(r"(?i)^(?:{atom})(?:\s+AND\s+(?:{atom}))*$"))
            .expect("policy predicate grammar regex is valid")
    })
}

/// The default posture for a schema with no explicit rule.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultMode {
    /// Reads only (DML/DDL denied).
    #[default]
    ReadOnly,
    /// Reads + preview/approve flows; direct writes still gated elsewhere.
    Guarded,
    /// No per-schema restriction (the classifier + level gate still apply).
    Permissive,
}

/// Schemas that are deny-all regardless of config (cannot be unlocked).
const ALWAYS_DENY_ALL: &[&str] = &["SYS", "SYSTEM", "SYSAUX", "AUDSYS", "DBSNMP"];

/// Per-schema policy (one entry; raw form from TOML).
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaPolicyRaw {
    /// Posture for statements not otherwise matched.
    #[serde(default)]
    pub default_mode: DefaultMode,
    /// Permit DML (INSERT/UPDATE/DELETE/MERGE) in this schema.
    #[serde(default)]
    pub allow_dml: bool,
    /// Deny DDL in this schema.
    #[serde(default)]
    pub deny_ddl: bool,
    /// Deny everything in this schema.
    #[serde(default)]
    pub deny_all: bool,
    /// Regex patterns that, if matched against the SQL, deny the call.
    #[serde(default)]
    pub deny_patterns: Vec<String>,
}

/// A compiled per-schema policy.
#[derive(Clone, Debug, Default)]
pub struct SchemaPolicy {
    mode: DefaultMode,
    allow_dml: bool,
    deny_ddl: bool,
    deny_all: bool,
    deny_patterns: Vec<Regex>,
}

impl SchemaPolicy {
    /// Compile from the raw (TOML) form; invalid regexes are dropped.
    #[must_use]
    pub fn compile(raw: &SchemaPolicyRaw) -> Self {
        SchemaPolicy {
            mode: raw.default_mode,
            allow_dml: raw.allow_dml,
            deny_ddl: raw.deny_ddl,
            deny_all: raw.deny_all,
            deny_patterns: raw
                .deny_patterns
                .iter()
                .filter_map(|p| Regex::new(p).ok())
                .collect(),
        }
    }
}

/// The whole-server schema policy set.
#[derive(Clone, Debug, Default)]
pub struct SchemaPolicySet {
    per_schema: BTreeMap<String, SchemaPolicy>,
}

/// A per-schema policy decision (it can only deny, never loosen the classifier).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The policy permits the call (subject to the classifier + level gate).
    Allow,
    /// The policy denies the call.
    Deny {
        /// The schema that triggered the denial.
        schema: String,
        /// Why.
        reason: String,
    },
}

impl SchemaPolicySet {
    /// An empty policy set (only the built-in `ALWAYS_DENY_ALL` applies).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a compiled per-schema policy (schema name is upper-cased).
    #[must_use]
    pub fn with_schema(mut self, schema: &str, policy: SchemaPolicy) -> Self {
        self.per_schema.insert(schema.to_ascii_uppercase(), policy);
        self
    }

    /// Evaluate the policy for a statement of `danger` touching `schemas`,
    /// matching `sql` against deny patterns. Denies on the first offending
    /// schema; otherwise `Allow`.
    #[must_use]
    pub fn evaluate(&self, schemas: &[&str], danger: DangerLevel, sql: &str) -> PolicyDecision {
        for schema in schemas {
            let upper = schema.to_ascii_uppercase();
            if ALWAYS_DENY_ALL.contains(&upper.as_str()) {
                return PolicyDecision::Deny {
                    schema: upper,
                    reason: "system schema is deny-all (cannot be unlocked)".to_owned(),
                };
            }
            let Some(p) = self.per_schema.get(&upper) else {
                // No explicit rule: default-deny writes/DDL to unknown schemas
                // only if the statement is mutating; reads pass.
                if danger >= DangerLevel::Guarded {
                    // Unknown schema + mutating: deny unless a permissive default
                    // exists for it (none here) — conservative.
                    return PolicyDecision::Deny {
                        schema: upper,
                        reason: "no policy for schema; mutating statements denied by default"
                            .to_owned(),
                    };
                }
                continue;
            };
            if p.deny_all {
                return deny(&upper, "schema policy: deny_all");
            }
            for re in &p.deny_patterns {
                if re.is_match(sql) {
                    return deny(
                        &upper,
                        &format!("schema policy: matched deny pattern {}", re.as_str()),
                    );
                }
            }
            // DDL family (Destructive level via CREATE/ALTER/DROP/TRUNCATE).
            if p.deny_ddl && danger == DangerLevel::Destructive {
                return deny(&upper, "schema policy: deny_ddl");
            }
            match p.mode {
                DefaultMode::ReadOnly if danger >= DangerLevel::Guarded && !p.allow_dml => {
                    return deny(&upper, "schema policy: read_only (DML/DDL not allowed)");
                }
                DefaultMode::Guarded if danger == DangerLevel::Destructive && !p.allow_dml => {
                    return deny(&upper, "schema policy: guarded (destructive not allowed)");
                }
                _ => {}
            }
        }
        PolicyDecision::Allow
    }
}

fn deny(schema: &str, reason: &str) -> PolicyDecision {
    PolicyDecision::Deny {
        schema: schema.to_owned(),
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::Classifier;

    fn permissive(schema: &str) -> SchemaPolicySet {
        SchemaPolicySet::new().with_schema(
            schema,
            SchemaPolicy::compile(&SchemaPolicyRaw {
                default_mode: DefaultMode::Permissive,
                allow_dml: true,
                ..Default::default()
            }),
        )
    }

    fn deny_rule(id: &str) -> SqlPolicyRuleConfig {
        SqlPolicyRuleConfig {
            id: id.to_owned(),
            match_clause: SqlPolicyMatchConfig {
                schema: Some("HR".to_owned()),
                object: Some("PAYROLL".to_owned()),
                verb: Some(SqlPolicyVerb::Select),
                principal: None,
            },
            effect: SqlPolicyEffectConfig::Deny,
        }
    }

    #[test]
    fn sql_policy_validation_requires_versioned_unique_tightening_rules() {
        let duplicate = SqlPolicyConfig {
            version: SQL_POLICY_VERSION,
            rules: vec![deny_rule("deny-payroll"), deny_rule("deny-payroll")],
        };
        assert!(matches!(
            duplicate.validate(),
            Err(SqlPolicyValidationError { field, reason })
                if field == "rules[1].id" && reason.contains("unique")
        ));

        let unknown_version = SqlPolicyConfig {
            version: SQL_POLICY_VERSION + 1,
            rules: vec![deny_rule("deny-payroll")],
        };
        assert!(matches!(
            unknown_version.validate(),
            Err(SqlPolicyValidationError { field, reason })
                if field == "version" && reason.contains("unknown policy grammar")
        ));
    }

    #[test]
    fn sql_policy_predicates_need_an_exact_safe_target() {
        let policy = SqlPolicyConfig {
            version: SQL_POLICY_VERSION,
            rules: vec![SqlPolicyRuleConfig {
                id: "tenant-filter".to_owned(),
                match_clause: SqlPolicyMatchConfig {
                    schema: Some("APP".to_owned()),
                    object: Some("ORDERS".to_owned()),
                    verb: Some(SqlPolicyVerb::Merge),
                    principal: None,
                },
                effect: SqlPolicyEffectConfig::RequirePredicate {
                    sql_fragment: "tenant_id = 42".to_owned(),
                },
            }],
        };
        assert!(matches!(
            policy.validate(),
            Err(SqlPolicyValidationError { field, reason })
                if field == "rules[0].match.verb" && reason.contains("select, update, or delete")
        ));
    }

    fn operator_policy() -> SqlPolicyConfig {
        SqlPolicyConfig {
            version: SQL_POLICY_VERSION,
            rules: vec![
                SqlPolicyRuleConfig {
                    id: "operator-level-floor".to_owned(),
                    match_clause: SqlPolicyMatchConfig {
                        schema: Some("APP".to_owned()),
                        object: Some("ORDERS".to_owned()),
                        verb: Some(SqlPolicyVerb::Select),
                        principal: Some("oauth:operator-7".to_owned()),
                    },
                    effect: SqlPolicyEffectConfig::RequireLevel {
                        level: OperatingLevel::ReadWrite,
                    },
                },
                SqlPolicyRuleConfig {
                    id: "operator-tenant-filter".to_owned(),
                    match_clause: SqlPolicyMatchConfig {
                        schema: Some("APP".to_owned()),
                        object: Some("ORDERS".to_owned()),
                        verb: Some(SqlPolicyVerb::Select),
                        principal: Some("oauth:operator-7".to_owned()),
                    },
                    effect: SqlPolicyEffectConfig::RequirePredicate {
                        sql_fragment: "tenant_id = 7".to_owned(),
                    },
                },
            ],
        }
    }

    fn operator_context() -> SqlPolicyEvaluationContext {
        SqlPolicyEvaluationContext::new(
            Some("APP".to_owned()),
            Some("ORDERS".to_owned()),
            SqlPolicyVerb::Select,
            Some("oauth:operator-7".to_owned()),
        )
    }

    #[test]
    fn sql_policy_composes_as_base_and_policy_without_allowing() {
        let base = Classifier::default().classify("SELECT * FROM app.orders");
        assert_eq!(base.required_level, Some(OperatingLevel::ReadOnly));

        let result = operator_policy().evaluate(&base, &operator_context());
        let PolicyTightening::Narrow(narrowing) = result else {
            panic!("a valid narrowing policy must not deny the admitted base read");
        };
        assert_eq!(narrowing.base_required_level, OperatingLevel::ReadOnly);
        assert_eq!(narrowing.required_level, OperatingLevel::ReadWrite);
        assert_eq!(
            narrowing.matched_rule_ids,
            vec!["operator-level-floor", "operator-tenant-filter"]
        );
        assert_eq!(narrowing.predicates.len(), 1);
        assert_eq!(
            narrowing.predicates[0].target,
            SqlPolicyPredicateTarget {
                schema: "APP".to_owned(),
                object: "ORDERS".to_owned(),
                verb: SqlPolicyVerb::Select,
            }
        );
        assert_eq!(narrowing.predicates[0].sql_fragment, "tenant_id = 7");
    }

    #[test]
    fn sql_policy_never_admits_a_base_classifier_refusal() {
        let base =
            Classifier::default().classify("BEGIN EXECUTE IMMEDIATE 'DROP TABLE app.orders'; END;");
        assert_eq!(base.danger, DangerLevel::Forbidden);

        assert_eq!(
            operator_policy().evaluate(&base, &operator_context()),
            PolicyTightening::Deny(PolicyDenial {
                reason: PolicyDenialReason::BaseClassifierRefused,
                matched_rule_ids: Vec::new(),
            })
        );
    }

    #[test]
    fn matching_deny_wins_over_other_tightening_rules() {
        let mut policy = operator_policy();
        policy.rules.push(SqlPolicyRuleConfig {
            id: "operator-deny".to_owned(),
            match_clause: SqlPolicyMatchConfig {
                schema: Some("APP".to_owned()),
                object: Some("ORDERS".to_owned()),
                verb: Some(SqlPolicyVerb::Select),
                principal: Some("oauth:operator-7".to_owned()),
            },
            effect: SqlPolicyEffectConfig::Deny,
        });
        let base = Classifier::default().classify("SELECT * FROM app.orders");
        assert!(matches!(
            policy.evaluate(&base, &operator_context()),
            PolicyTightening::Deny(PolicyDenial {
                reason: PolicyDenialReason::MatchingDenyRule,
                matched_rule_ids,
            }) if matched_rule_ids == vec![
                "operator-level-floor",
                "operator-tenant-filter",
                "operator-deny",
            ]
        ));
    }

    fn predicate_narrowing(sql_fragment: &str) -> PolicyNarrowing {
        PolicyNarrowing {
            base_required_level: OperatingLevel::ReadOnly,
            required_level: OperatingLevel::ReadOnly,
            predicates: vec![SqlPolicyPredicate {
                rule_id: "tenant-filter".to_owned(),
                target: SqlPolicyPredicateTarget {
                    schema: "APP".to_owned(),
                    object: "ORDERS".to_owned(),
                    verb: SqlPolicyVerb::Select,
                },
                sql_fragment: sql_fragment.to_owned(),
            }],
            matched_rule_ids: vec!["tenant-filter".to_owned()],
        }
    }

    #[test]
    fn policy_predicate_rewrite_uses_ast_placement_then_reclassifies() {
        let classifier = Classifier::default();
        let original = "SELECT id FROM app.orders WHERE status = 'OPEN'";
        let base = classifier.classify(original);
        let rewritten = rewrite_predicates_and_reclassify(
            &classifier,
            &base,
            original,
            &operator_context(),
            &predicate_narrowing("tenant_id = 7"),
        );

        let PolicyPredicateRewrite::Reclassified(rewritten) = rewritten else {
            panic!("a simple one-table SELECT predicate must be rewritable");
        };
        assert!(
            rewritten
                .sql
                .contains("WHERE (status = 'OPEN') AND (tenant_id = 7)")
        );
        assert_eq!(rewritten.candidate.danger, DangerLevel::Safe);
        assert_eq!(rewritten.final_required_level, OperatingLevel::ReadOnly);
    }

    #[test]
    fn policy_predicate_rewrite_refuses_a_candidate_that_becomes_non_read_only() {
        // N1 rejects this fragment at load time. Constructing the narrowing
        // directly exercises the SEC-1 recovery check: even an implementation
        // discrepancy that got this far cannot upgrade a safe base read.
        let classifier = Classifier::default();
        let original = "SELECT id FROM app.orders";
        let base = classifier.classify(original);
        assert!(matches!(
            rewrite_predicates_and_reclassify(
                &classifier,
                &base,
                original,
                &operator_context(),
                &predicate_narrowing("billing.side_effect() = 1"),
            ),
            PolicyPredicateRewrite::Deny(PolicyRewriteDenial {
                reason: PolicyRewriteDenialReason::CandidateNotReadOnly,
                ..
            })
        ));
    }

    #[test]
    fn policy_predicate_rewrite_refuses_aliases_instead_of_guessing_target_placement() {
        let classifier = Classifier::default();
        let original = "SELECT id FROM app.orders o";
        let base = classifier.classify(original);
        assert!(matches!(
            rewrite_predicates_and_reclassify(
                &classifier,
                &base,
                original,
                &operator_context(),
                &predicate_narrowing("tenant_id = 7"),
            ),
            PolicyPredicateRewrite::Deny(PolicyRewriteDenial {
                reason: PolicyRewriteDenialReason::UnsupportedStatementShape,
                ..
            })
        ));
    }

    #[test]
    fn system_schemas_are_always_deny_all() {
        let set = SchemaPolicySet::new();
        for sys in ["SYS", "SYSTEM", "sysaux"] {
            assert!(matches!(
                set.evaluate(&[sys], DangerLevel::Safe, "SELECT 1 FROM dual"),
                PolicyDecision::Deny { .. }
            ));
        }
    }

    #[test]
    fn unknown_schema_allows_reads_denies_writes() {
        let set = SchemaPolicySet::new();
        assert_eq!(
            set.evaluate(&["HR"], DangerLevel::Safe, "SELECT * FROM hr.emp"),
            PolicyDecision::Allow
        );
        assert!(matches!(
            set.evaluate(
                &["HR"],
                DangerLevel::Guarded,
                "UPDATE hr.emp SET x=1 WHERE id=2"
            ),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn permissive_schema_allows_dml() {
        let set = permissive("APP");
        assert_eq!(
            set.evaluate(
                &["APP"],
                DangerLevel::Guarded,
                "INSERT INTO app.t VALUES (1)"
            ),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn read_only_schema_denies_dml() {
        let set = SchemaPolicySet::new().with_schema(
            "REPORTS",
            SchemaPolicy::compile(&SchemaPolicyRaw {
                default_mode: DefaultMode::ReadOnly,
                ..Default::default()
            }),
        );
        assert!(matches!(
            set.evaluate(
                &["REPORTS"],
                DangerLevel::Guarded,
                "INSERT INTO reports.t VALUES (1)"
            ),
            PolicyDecision::Deny { .. }
        ));
        assert_eq!(
            set.evaluate(&["REPORTS"], DangerLevel::Safe, "SELECT * FROM reports.t"),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn deny_ddl_blocks_destructive() {
        let set = SchemaPolicySet::new().with_schema(
            "APP",
            SchemaPolicy::compile(&SchemaPolicyRaw {
                default_mode: DefaultMode::Permissive,
                allow_dml: true,
                deny_ddl: true,
                ..Default::default()
            }),
        );
        assert!(matches!(
            set.evaluate(&["APP"], DangerLevel::Destructive, "DROP TABLE app.t"),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn deny_pattern_matches() {
        let set = SchemaPolicySet::new().with_schema(
            "APP",
            SchemaPolicy::compile(&SchemaPolicyRaw {
                default_mode: DefaultMode::Permissive,
                allow_dml: true,
                deny_patterns: vec!["(?i)salaries".to_owned()],
                ..Default::default()
            }),
        );
        assert!(matches!(
            set.evaluate(&["APP"], DangerLevel::Safe, "SELECT * FROM app.salaries"),
            PolicyDecision::Deny { .. }
        ));
    }
}
