//! The one place a loaded Arc N policy is *enforced* (bead `oraclemcp-uhyc`).
//!
//! [`policy.rs`](crate::policy) built the monotone evaluator and the N3 rewrite;
//! nothing called them. A configured `sql_policy` was neither applied to a
//! statement nor reported on a response — a silent policy-not-enforced
//! condition, which is a safety gap and not a display bug. This module is the
//! seam that closes it: dispatch hands it the classifier's verdict and the
//! server-derived facts, and gets back either a typed refusal or the exact SQL,
//! level, and proof it must use.
//!
//! ## Tighten-only, by construction
//!
//! There is no `Allow` outcome here, and none can be added: the grammar cannot
//! express one ([`SqlPolicyEffectConfig`] has only Deny / RequireLevel /
//! RequirePredicate), the evaluator returns only [`PolicyTightening::Deny`] or
//! [`PolicyTightening::Narrow`], and [`PolicyGate::Admitted`] is deliberately
//! *not* an authorization — it says "policy added these restrictions", and the
//! caller must still apply the base level gate and every later safety check.
//!
//! Three properties hold on every path, and each is tested:
//!
//! 1. **A policy can never make a refused statement dispatchable.** A
//!    `Forbidden` base decision is refused before a single rule is consulted.
//! 2. **A policy can never lower a required level.** The admitted level is
//!    `max(base, policy floor, re-classified candidate)`. The maximum is taken,
//!    never a replacement; the gate additionally re-checks the result against the
//!    base and refuses if it ever came out lower, so a future edit that broke the
//!    monotonicity would fail closed rather than silently grant.
//! 3. **A predicate narrowing re-enters the classifier (SEC-1).** Predicates are
//!    placed in the AST and the *rendered candidate* is classified afresh by
//!    [`rewrite_predicates_and_reclassify`]; the previewed verdict is never
//!    carried over. The candidate's SQL — not the original bytes — is what runs.
//!
//! ## Fail-closed on unprovable policy facts
//!
//! A rule that selects a schema/object needs one relation the gate can prove.
//! If that target is absent, the gate evaluates the still-known verb/principal
//! facts for target-free rules, then refuses before a target-selecting policy
//! could silently fail to match. If even the policy verb cannot be derived, the
//! active policy is refused outright. Denying is the tightening direction;
//! guessing or skipping a rule is not.
//!
//! ## The response proof
//!
//! [`PolicyGate::attachment`] is the ADR-0009 outcome, serialized in exactly the
//! shape the operator console already parses (`{"Narrow": {…}}` /
//! `{"Deny": {…}}`) — so the policy badge lights up with no client change. When
//! no policy is configured there is no attachment, and the console reports
//! "not reported", which is honest: it is not the claim that no policy applied.

use serde_json::{Value, json};
use sqlparser::ast::{FromTable, ObjectName, SetExpr, Statement, TableFactor};
use sqlparser::dialect::OracleDialect;
use sqlparser::parser::Parser;

use crate::classifier::{Classifier, GuardDecision};
use crate::levels::{DangerLevel, OperatingLevel};
use crate::policy::{
    PolicyDenialReason, PolicyPredicateRewrite, PolicyRewriteDenialReason, PolicyTightening,
    SqlPolicyConfig, SqlPolicyEvaluationContext, SqlPolicyVerb, rewrite_predicates_and_reclassify,
};

/// Everything the gate needs, all of it server-derived.
///
/// `current_schema` and `principal` come from the authenticated session, never
/// from a tool argument: a caller that could assert its own schema or principal
/// could dodge the very rule that names it.
pub struct PolicyGateRequest<'a> {
    /// The classifier that produced `base`, reused to re-classify any candidate.
    pub classifier: &'a Classifier,
    /// The active profile's loaded policy, if it has one.
    pub policy: Option<&'a SqlPolicyConfig>,
    /// The classifier's verdict on the original statement.
    pub base: &'a GuardDecision,
    /// The original statement text.
    pub sql: &'a str,
    /// The session's resolved `CURRENT_SCHEMA`, used to qualify an unqualified
    /// target. Absent means an unqualified target cannot be resolved.
    pub current_schema: Option<&'a str>,
    /// The stable server-derived principal key, when authentication supplied one.
    pub principal: Option<&'a str>,
}

/// Why the gate refused. A closed vocabulary: no raw SQL and no operator free
/// text ever becomes part of an authorization proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyGateDenialReason {
    /// The classifier already refused the statement; no rule was consulted.
    BaseClassifierRefused,
    /// The base decision carried no required level.
    IncompleteBaseDecision,
    /// The loaded policy is not a valid tightening-only grammar.
    InvalidPolicy,
    /// A matching rule denies the statement.
    MatchingDenyRule,
    /// Matching predicate rules did not name one identical target relation.
    PredicateTargetConflict,
    /// Required policy facts could not be proven. This includes a
    /// schema/object selector without one exact target relation and any
    /// statement whose policy verb is unknown.
    UnresolvedPolicyTarget,
    /// The mandatory predicate rewrite or its re-classification failed closed.
    PredicateRewriteRefused,
    /// The composed level came out below the classifier's — impossible by
    /// construction, refused rather than trusted.
    NonMonotonicComposition,
}

impl PolicyGateDenialReason {
    /// The machine-stable snake_case token carried on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BaseClassifierRefused => "base_classifier_refused",
            Self::IncompleteBaseDecision => "incomplete_base_decision",
            Self::InvalidPolicy => "invalid_policy",
            Self::MatchingDenyRule => "matching_deny_rule",
            Self::PredicateTargetConflict => "predicate_target_conflict",
            Self::UnresolvedPolicyTarget => "unresolved_policy_target",
            Self::PredicateRewriteRefused => "predicate_rewrite_refused",
            Self::NonMonotonicComposition => "non_monotonic_composition",
        }
    }

    fn from_policy(reason: PolicyDenialReason) -> Self {
        match reason {
            PolicyDenialReason::BaseClassifierRefused => Self::BaseClassifierRefused,
            PolicyDenialReason::IncompleteBaseDecision => Self::IncompleteBaseDecision,
            PolicyDenialReason::InvalidPolicy => Self::InvalidPolicy,
            PolicyDenialReason::MatchingDenyRule => Self::MatchingDenyRule,
            PolicyDenialReason::PredicateTargetConflict => Self::PredicateTargetConflict,
        }
    }
}

/// A policy refusal, with the proof the response must carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyGateDenial {
    /// Stable refusal category.
    pub reason: PolicyGateDenialReason,
    /// Every rule that matched before the refusal was returned.
    pub matched_rule_ids: Vec<String>,
}

impl PolicyGateDenial {
    /// The ADR-0009 `{"Deny": …}` proof, in the console's parse shape.
    #[must_use]
    pub fn attachment(&self) -> Value {
        json!({
            "Deny": {
                "reason": self.reason.as_str(),
                "matched_rule_ids": self.matched_rule_ids,
            }
        })
    }
}

/// What dispatch must execute after the policy has been applied.
///
/// This is **not** an allow. The base level gate, the confirmation gate, and
/// every later check still run; this only reports what the policy *added*.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyGateAdmission {
    /// The SQL to execute. `Some` only when a predicate rewrite produced a new,
    /// re-classified candidate — and then it is the candidate that must run, not
    /// the original bytes.
    pub effective_sql: Option<String>,
    /// The decision for the statement that will actually run: the re-classified
    /// candidate when the SQL was rewritten, else the base decision.
    pub effective_decision: GuardDecision,
    /// `max(base, policy floor, candidate)`. Never below the classifier's level.
    pub required_level: OperatingLevel,
    /// `max(base, candidate)`.
    pub danger: DangerLevel,
    /// The ADR-0009 `{"Narrow": …}` proof, or `None` when no policy is
    /// configured (there is nothing to report, and silence is not a clean bill
    /// of health — the console says "not reported").
    pub attachment: Option<Value>,
}

/// The gate's outcome. Deliberately two-valued: refuse, or admit-with-restrictions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyGate {
    /// The policy refused the statement.
    Denied(PolicyGateDenial),
    /// The policy added zero or more restrictions to a base decision.
    Admitted(Box<PolicyGateAdmission>),
}

impl PolicyGate {
    /// The proof to attach to the response, whichever way the gate went.
    #[must_use]
    pub fn attachment(&self) -> Option<Value> {
        match self {
            Self::Denied(denial) => Some(denial.attachment()),
            Self::Admitted(admission) => admission.attachment.clone(),
        }
    }
}

/// Apply the active profile's policy to a classified statement.
///
/// The single enforcement entry point. See the module docs for the three
/// invariants this upholds on every path.
#[must_use]
pub fn enforce_sql_policy(request: &PolicyGateRequest<'_>) -> PolicyGate {
    let base = request.base;

    // (1) A refused statement is refused, before any rule is read. A policy is a
    //     restriction; it has no power to admit.
    if base.danger == DangerLevel::Forbidden {
        return deny(PolicyGateDenialReason::BaseClassifierRefused, Vec::new());
    }
    let Some(base_required_level) = base.required_level else {
        return deny(PolicyGateDenialReason::IncompleteBaseDecision, Vec::new());
    };

    // No policy configured: nothing to enforce and nothing to claim.
    let Some(policy) = request.policy else {
        return PolicyGate::Admitted(Box::new(PolicyGateAdmission {
            effective_sql: None,
            effective_decision: base.clone(),
            required_level: base_required_level,
            danger: base.danger,
            attachment: None,
        }));
    };

    // A malformed policy is a policy that did not load. Refuse; never run
    // unpoliced because the operator's restriction failed to parse.
    if policy.validate().is_err() {
        return deny(PolicyGateDenialReason::InvalidPolicy, Vec::new());
    }

    // (2) Build the evaluation context from server-derived facts only. A
    //     statement without a policy verb cannot be evaluated safely, so an
    //     active policy refuses rather than silently not applying. Query shapes
    //     such as WITH/CTE and JOIN still provide a proven SELECT verb even
    //     when they do not have one exact target relation; that lets global,
    //     verb-only, and principal-only tightening rules apply normally.
    let Some(facts) = StatementPolicyFacts::derive(request.sql, request.current_schema) else {
        return deny(PolicyGateDenialReason::UnresolvedPolicyTarget, Vec::new());
    };
    let target_is_unresolved =
        policy_selects_a_target(policy) && (facts.schema.is_none() || facts.object.is_none());
    let context = SqlPolicyEvaluationContext::new(
        facts.schema.clone(),
        facts.object.clone(),
        facts.verb,
        request.principal.map(str::to_owned),
    );

    let narrowing = match policy.evaluate(base, &context) {
        PolicyTightening::Deny(denial) => {
            return deny(
                PolicyGateDenialReason::from_policy(denial.reason),
                denial.matched_rule_ids,
            );
        }
        PolicyTightening::Narrow(narrowing) => narrowing,
    };

    // Preserve an explicit global/verb/principal deny above, but never admit a
    // statement when any schema/object rule could have been skipped solely
    // because this version cannot prove one exact target relation.
    if target_is_unresolved {
        return deny(PolicyGateDenialReason::UnresolvedPolicyTarget, Vec::new());
    }

    // (3) Predicates re-enter the classifier (SEC-1): the rendered candidate is
    //     classified afresh, and the candidate — not the original — is what runs.
    let (effective_sql, effective_decision, required_level, danger) =
        if narrowing.predicates.is_empty() {
            (None, base.clone(), narrowing.required_level, base.danger)
        } else {
            match rewrite_predicates_and_reclassify(
                request.classifier,
                base,
                request.sql,
                &context,
                &narrowing,
            ) {
                PolicyPredicateRewrite::Deny(refusal) => {
                    return deny(rewrite_reason(refusal.reason), refusal.matched_rule_ids);
                }
                PolicyPredicateRewrite::Reclassified(candidate) => (
                    Some(candidate.sql.clone()),
                    candidate.candidate.clone(),
                    candidate.final_required_level,
                    candidate.final_danger,
                ),
            }
        };

    // The composition is a maximum, so it cannot come out below the classifier's
    // level. Re-check anyway: if it ever did, that is a broken invariant, and a
    // broken invariant must refuse rather than grant.
    if required_level < base_required_level {
        return deny(
            PolicyGateDenialReason::NonMonotonicComposition,
            narrowing.matched_rule_ids,
        );
    }

    let attachment = serde_json::to_value(PolicyTightening::Narrow(narrowing))
        .unwrap_or_else(|_| identity_attachment(base_required_level));
    PolicyGate::Admitted(Box::new(PolicyGateAdmission {
        effective_sql,
        effective_decision,
        required_level,
        danger,
        attachment: Some(attachment),
    }))
}

fn deny(reason: PolicyGateDenialReason, matched_rule_ids: Vec<String>) -> PolicyGate {
    PolicyGate::Denied(PolicyGateDenial {
        reason,
        matched_rule_ids,
    })
}

fn rewrite_reason(reason: PolicyRewriteDenialReason) -> PolicyGateDenialReason {
    match reason {
        PolicyRewriteDenialReason::BaseClassifierRefused => {
            PolicyGateDenialReason::BaseClassifierRefused
        }
        PolicyRewriteDenialReason::PredicateTargetConflict => {
            PolicyGateDenialReason::PredicateTargetConflict
        }
        _ => PolicyGateDenialReason::PredicateRewriteRefused,
    }
}

/// The `{"Narrow": …}` proof for a policy that matched nothing: it reports that a
/// policy WAS evaluated and took nothing away, which is a different claim from
/// silence.
fn identity_attachment(base_required_level: OperatingLevel) -> Value {
    serde_json::to_value(PolicyTightening::Narrow(
        crate::policy::PolicyNarrowing::identity(base_required_level),
    ))
    .unwrap_or(Value::Null)
}

/// Whether any rule selects a schema or object, i.e. whether an unprovable target
/// could cause a rule to silently not match.
fn policy_selects_a_target(policy: &SqlPolicyConfig) -> bool {
    policy
        .rules
        .iter()
        .any(|rule| rule.match_clause.schema.is_some() || rule.match_clause.object.is_some())
}

/// The server-derived facts a policy is matched against.
///
/// Derived from the parsed statement — never from a tool argument. A query's
/// `SELECT` verb remains a usable policy fact for every parsed query shape. The
/// schema/object pair is present only for the deliberately small v1 shape (one
/// exact, unaliased target relation in a plain SELECT / UPDATE / DELETE). A
/// statement whose policy verb cannot be derived yields `None`, and an active
/// policy refuses rather than evaluating against a guess.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementPolicyFacts {
    /// The top-level verb, established by parsing.
    pub verb: SqlPolicyVerb,
    /// The resolved owning schema, qualified by the session's `CURRENT_SCHEMA`
    /// when the statement did not name one.
    pub schema: Option<String>,
    /// The resolved object name.
    pub object: Option<String>,
}

impl StatementPolicyFacts {
    /// Derive the facts from the statement text, or `None` when the shape is not
    /// one this version can prove.
    #[must_use]
    pub fn derive(sql: &str, current_schema: Option<&str>) -> Option<Self> {
        let dialect = OracleDialect {};
        let mut statements = Parser::parse_sql(&dialect, sql).ok()?;
        if statements.len() != 1 {
            return None;
        }
        let statement = statements.pop()?;
        let (verb, name) = match statement {
            Statement::Query(query) => (SqlPolicyVerb::Select, exact_query_target(&query)),
            Statement::Update(update) => {
                if update.from.is_some() || !update.table.joins.is_empty() {
                    return None;
                }
                let TableFactor::Table { name, alias, .. } = &update.table.relation else {
                    return None;
                };
                if alias.is_some() {
                    return None;
                }
                (SqlPolicyVerb::Update, Some(name.clone()))
            }
            Statement::Delete(delete) => {
                if delete.using.is_some() || !delete.tables.is_empty() {
                    return None;
                }
                let (FromTable::WithFromKeyword(tables) | FromTable::WithoutKeyword(tables)) =
                    &delete.from;
                if tables.len() != 1 || !tables[0].joins.is_empty() {
                    return None;
                }
                let TableFactor::Table { name, alias, .. } = &tables[0].relation else {
                    return None;
                };
                if alias.is_some() {
                    return None;
                }
                (SqlPolicyVerb::Delete, Some(name.clone()))
            }
            _ => return None,
        };
        let (schema, object) = name
            .as_ref()
            .and_then(|name| split_qualified(name, current_schema))
            .unwrap_or((None, None));
        Some(Self {
            verb,
            schema,
            object,
        })
    }
}

/// Return the one exact target that v1 may use for a schema/object policy
/// selector. Query shapes outside this narrow subset still retain their
/// `SELECT` verb in [`StatementPolicyFacts::derive`]; they never acquire a
/// guessed target relation.
fn exact_query_target(query: &sqlparser::ast::Query) -> Option<ObjectName> {
    if query.with.is_some() {
        return None;
    }
    let SetExpr::Select(select) = query.body.as_ref() else {
        return None;
    };
    if select.from.len() != 1 || !select.from[0].joins.is_empty() {
        return None;
    }
    let TableFactor::Table { name, alias, .. } = &select.from[0].relation else {
        return None;
    };
    alias.is_none().then(|| name.clone())
}

/// Split `owner.object` (or qualify a bare `object` with the session schema).
/// More than two parts is a shape this version does not prove.
fn split_qualified(
    name: &ObjectName,
    current_schema: Option<&str>,
) -> Option<(Option<String>, Option<String>)> {
    // A quoted identifier keeps its case; an unquoted one folds, exactly as
    // Oracle resolves it. Anything that is not a plain identifier part is a shape
    // this version does not claim to have resolved.
    let mut parts: Vec<String> = Vec::with_capacity(name.0.len());
    for part in &name.0 {
        let ident = sqlparser::ast::ObjectNamePart::as_ident(part)?;
        parts.push(if ident.quote_style.is_some() {
            ident.value.clone()
        } else {
            ident.value.to_ascii_uppercase()
        });
    }
    match parts.as_slice() {
        [object] => Some((
            current_schema.map(|schema| schema.to_ascii_uppercase()),
            Some(object.clone()),
        )),
        [schema, object] => Some((Some(schema.clone()), Some(object.clone()))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{SqlPolicyEffectConfig, SqlPolicyMatchConfig, SqlPolicyRuleConfig};

    fn classifier() -> Classifier {
        Classifier::default()
    }

    fn rule(
        id: &str,
        match_clause: SqlPolicyMatchConfig,
        effect: SqlPolicyEffectConfig,
    ) -> SqlPolicyRuleConfig {
        SqlPolicyRuleConfig {
            id: id.to_owned(),
            match_clause,
            effect,
        }
    }

    fn hr_employees(verb: SqlPolicyVerb) -> SqlPolicyMatchConfig {
        SqlPolicyMatchConfig {
            schema: Some("HR".to_owned()),
            object: Some("EMPLOYEES".to_owned()),
            verb: Some(verb),
            principal: None,
        }
    }

    fn policy(rules: Vec<SqlPolicyRuleConfig>) -> SqlPolicyConfig {
        SqlPolicyConfig { version: 1, rules }
    }

    fn gate<'a>(
        classifier: &'a Classifier,
        policy: Option<&'a SqlPolicyConfig>,
        base: &'a GuardDecision,
        sql: &'a str,
    ) -> PolicyGate {
        enforce_sql_policy(&PolicyGateRequest {
            classifier,
            policy,
            base,
            sql,
            current_schema: Some("HR"),
            principal: Some("oauth:subject-1"),
        })
    }

    /// THE invariant. A policy is a restriction, so it can never turn a statement
    /// the classifier refused into one that dispatches — no matter what its rules
    /// say, including a rule that matches nothing at all.
    #[test]
    fn a_policy_can_never_admit_a_statement_the_classifier_refused() {
        let classifier = classifier();
        let forbidden = classifier.classify("BEGIN EXECUTE IMMEDIATE 'DROP TABLE t'; END;");
        assert_eq!(forbidden.danger, DangerLevel::Forbidden);

        for configured in [
            None,
            Some(policy(Vec::new())),
            Some(policy(vec![rule(
                "everything",
                SqlPolicyMatchConfig::default(),
                SqlPolicyEffectConfig::RequireLevel {
                    level: OperatingLevel::ReadOnly,
                },
            )])),
        ] {
            let outcome = gate(
                &classifier,
                configured.as_ref(),
                &forbidden,
                "BEGIN EXECUTE IMMEDIATE 'DROP TABLE t'; END;",
            );
            assert_eq!(
                outcome,
                PolicyGate::Denied(PolicyGateDenial {
                    reason: PolicyGateDenialReason::BaseClassifierRefused,
                    matched_rule_ids: Vec::new(),
                }),
                "a refused statement stays refused"
            );
        }
    }

    /// THE other invariant, over the whole level lattice: policy composes with
    /// max(), so the admitted level is never below the classifier's — for any
    /// base and any rule floor.
    #[test]
    fn a_policy_can_never_lower_a_required_level() {
        let classifier = classifier();
        let levels = [
            OperatingLevel::ReadOnly,
            OperatingLevel::ReadWrite,
            OperatingLevel::Ddl,
            OperatingLevel::Admin,
        ];
        // One statement per base level, so the base verdict is the classifier's.
        let statements = [
            ("SELECT id FROM hr.employees", OperatingLevel::ReadOnly),
            (
                "UPDATE hr.employees SET id = 1 WHERE id = 2",
                OperatingLevel::ReadWrite,
            ),
        ];
        for (sql, expected_base) in statements {
            let base = classifier.classify(sql);
            assert_eq!(base.required_level, Some(expected_base), "{sql}");
            for floor in levels {
                let configured = policy(vec![rule(
                    "floor",
                    SqlPolicyMatchConfig::default(),
                    SqlPolicyEffectConfig::RequireLevel { level: floor },
                )]);
                let PolicyGate::Admitted(admission) =
                    gate(&classifier, Some(&configured), &base, sql)
                else {
                    panic!("a RequireLevel rule narrows, it does not deny");
                };
                assert!(
                    admission.required_level >= expected_base,
                    "policy lowered {expected_base:?} to {:?} with floor {floor:?}",
                    admission.required_level
                );
                assert_eq!(
                    admission.required_level,
                    expected_base.max(floor),
                    "the floor composes as a maximum, never a replacement"
                );
            }
        }
    }

    /// A deny rule refuses, and says which rule did it.
    #[test]
    fn a_matching_deny_rule_refuses_with_its_rule_ids() {
        let classifier = classifier();
        let sql = "DELETE FROM hr.employees WHERE id = 1";
        let base = classifier.classify(sql);
        let configured = policy(vec![rule(
            "no-prod-deletes",
            hr_employees(SqlPolicyVerb::Delete),
            SqlPolicyEffectConfig::Deny,
        )]);
        let PolicyGate::Denied(denial) = gate(&classifier, Some(&configured), &base, sql) else {
            panic!("a matching deny rule must refuse");
        };
        assert_eq!(denial.reason, PolicyGateDenialReason::MatchingDenyRule);
        assert_eq!(denial.matched_rule_ids, vec!["no-prod-deletes".to_owned()]);
    }

    #[test]
    fn principal_and_verb_deny_cannot_be_bypassed_by_a_cte_read() {
        let classifier = classifier();
        let sql = "WITH x AS (SELECT 1 FROM dual) SELECT * FROM x";
        let base = classifier.classify(sql);
        assert_eq!(base.danger, DangerLevel::Safe, "the base read is admitted");
        let configured = policy(vec![rule(
            "deny-principal-reads",
            SqlPolicyMatchConfig {
                schema: None,
                object: None,
                verb: Some(SqlPolicyVerb::Select),
                principal: Some("oauth:subject-1".to_owned()),
            },
            SqlPolicyEffectConfig::Deny,
        )]);
        let PolicyGate::Denied(denial) = gate(&classifier, Some(&configured), &base, sql) else {
            panic!("a principal+verb deny must apply to a CTE-led SELECT");
        };
        assert_eq!(denial.reason, PolicyGateDenialReason::MatchingDenyRule);
        assert_eq!(denial.matched_rule_ids, vec!["deny-principal-reads"]);
    }

    /// A rule with no target selector must apply to every read shape the base
    /// classifier admits. Target resolution is deliberately narrower than
    /// classification, so it is not an authorization escape hatch.
    #[test]
    fn global_deny_applies_to_each_classifier_admitted_read_shape() {
        let classifier = classifier();
        let configured = policy(vec![rule(
            "deny-all-reads",
            SqlPolicyMatchConfig {
                schema: None,
                object: None,
                verb: Some(SqlPolicyVerb::Select),
                principal: None,
            },
            SqlPolicyEffectConfig::Deny,
        )]);
        let reads = [
            "SELECT 1 FROM dual",
            "WITH x AS (SELECT 1 FROM dual) SELECT * FROM x",
            "SELECT e.id FROM hr.employees e JOIN hr.departments d ON e.id = d.id",
            "SELECT * FROM (SELECT 1 FROM dual)",
            "SELECT 1 FROM dual UNION ALL SELECT 2 FROM dual",
        ];

        for sql in reads {
            let base = classifier.classify(sql);
            assert_eq!(
                base.danger,
                DangerLevel::Safe,
                "base classifier accepts: {sql}"
            );
            let PolicyGate::Denied(denial) = gate(&classifier, Some(&configured), &base, sql)
            else {
                panic!("a global SELECT deny must apply: {sql}");
            };
            assert_eq!(
                denial.reason,
                PolicyGateDenialReason::MatchingDenyRule,
                "{sql}"
            );
            assert_eq!(denial.matched_rule_ids, vec!["deny-all-reads"], "{sql}");
        }
    }

    #[test]
    fn global_deny_keeps_its_proof_when_another_rule_has_an_unresolved_target() {
        let classifier = classifier();
        let sql = "WITH x AS (SELECT 1 FROM dual) SELECT * FROM x";
        let base = classifier.classify(sql);
        let configured = policy(vec![
            rule(
                "deny-all-reads",
                SqlPolicyMatchConfig {
                    schema: None,
                    object: None,
                    verb: Some(SqlPolicyVerb::Select),
                    principal: None,
                },
                SqlPolicyEffectConfig::Deny,
            ),
            rule(
                "targeted-level-floor",
                hr_employees(SqlPolicyVerb::Select),
                SqlPolicyEffectConfig::RequireLevel {
                    level: OperatingLevel::ReadWrite,
                },
            ),
        ]);
        let PolicyGate::Denied(denial) = gate(&classifier, Some(&configured), &base, sql) else {
            panic!("the known global deny must win over an unresolved target");
        };
        assert_eq!(denial.reason, PolicyGateDenialReason::MatchingDenyRule);
        assert_eq!(denial.matched_rule_ids, vec!["deny-all-reads"]);
    }

    /// Unknown targets must not discard the proven SELECT fact. Non-denying
    /// global rules still tighten CTE-led reads exactly as they tighten plain
    /// reads.
    #[test]
    fn verb_and_principal_level_rule_applies_to_a_cte_read_without_a_target() {
        let classifier = classifier();
        let sql = "WITH x AS (SELECT 1 FROM dual) SELECT * FROM x";
        let base = classifier.classify(sql);
        let configured = policy(vec![rule(
            "elevate-subject-reads",
            SqlPolicyMatchConfig {
                schema: None,
                object: None,
                verb: Some(SqlPolicyVerb::Select),
                principal: Some("oauth:subject-1".to_owned()),
            },
            SqlPolicyEffectConfig::RequireLevel {
                level: OperatingLevel::ReadWrite,
            },
        )]);
        let PolicyGate::Admitted(admission) = gate(&classifier, Some(&configured), &base, sql)
        else {
            panic!("a target-free level rule must evaluate against the CTE SELECT verb");
        };
        assert_eq!(admission.required_level, OperatingLevel::ReadWrite);
        assert_eq!(
            admission
                .attachment
                .as_ref()
                .expect("the narrowing is proved")["Narrow"]["matched_rule_ids"],
            json!(["elevate-subject-reads"])
        );
    }

    /// A predicate rule rewrites the statement and RE-CLASSIFIES the candidate
    /// (SEC-1). What runs is the candidate, not the original bytes.
    #[test]
    fn a_predicate_rule_rewrites_and_re_enters_the_classifier() {
        let classifier = classifier();
        let sql = "SELECT id FROM hr.employees";
        let base = classifier.classify(sql);
        let configured = policy(vec![rule(
            "tenant-scope",
            hr_employees(SqlPolicyVerb::Select),
            SqlPolicyEffectConfig::RequirePredicate {
                sql_fragment: "tenant_id = 42".to_owned(),
            },
        )]);
        let PolicyGate::Admitted(admission) = gate(&classifier, Some(&configured), &base, sql)
        else {
            panic!("a predicate rule narrows");
        };
        let effective = admission.effective_sql.expect("the candidate SQL runs");
        assert!(
            effective.to_ascii_uppercase().contains("WHERE"),
            "the predicate was placed in the AST: {effective}"
        );
        assert!(effective.contains("tenant_id = 42"), "{effective}");
        assert_eq!(
            admission.effective_decision,
            classifier.classify(&effective),
            "the decision carried forward is the CANDIDATE's, freshly classified — \
             never the previewed verdict for the original statement"
        );
        assert!(admission.required_level >= OperatingLevel::ReadOnly);
    }

    #[test]
    fn one_part_select_table_is_rewritable_when_current_schema_resolves_target() {
        let classifier = classifier();
        let sql = "SELECT id FROM orders";
        let base = classifier.classify(sql);
        let configured = policy(vec![rule(
            "tenant-scope",
            SqlPolicyMatchConfig {
                schema: Some("APP".to_owned()),
                object: Some("ORDERS".to_owned()),
                verb: Some(SqlPolicyVerb::Select),
                principal: None,
            },
            SqlPolicyEffectConfig::RequirePredicate {
                sql_fragment: "id > 0".to_owned(),
            },
        )]);

        let outcome = enforce_sql_policy(&PolicyGateRequest {
            classifier: &classifier,
            policy: Some(&configured),
            base: &base,
            sql,
            current_schema: Some("APP"),
            principal: Some("oauth:subject-1"),
        });
        let PolicyGate::Admitted(admission) = outcome else {
            panic!("an unqualified target should rewrite through the production path");
        };
        let effective = admission
            .effective_sql
            .expect("the rewrites must run through a fresh candidate SQL");
        assert!(effective.contains("id > 0"));
        assert!(
            effective.contains("WHERE"),
            "policy rewrite must materialize a predicate in AST output: {effective}"
        );
    }

    /// A policy that selects a schema/object cannot be proven against a statement
    /// whose target is not provable — so the statement is refused, not admitted
    /// against a guess. A deny rule that silently fails to match is a policy that
    /// silently did not apply.
    #[test]
    fn an_unprovable_target_is_refused_rather_than_evaluated_against_a_guess() {
        let classifier = classifier();
        // A join: outside the shape this version can resolve to one exact target.
        let sql = "SELECT e.id FROM hr.employees e JOIN hr.departments d ON e.id = d.id";
        let base = classifier.classify(sql);
        assert_ne!(base.danger, DangerLevel::Forbidden, "the base read is fine");
        let configured = policy(vec![rule(
            "no-prod-reads",
            hr_employees(SqlPolicyVerb::Select),
            SqlPolicyEffectConfig::Deny,
        )]);
        let PolicyGate::Denied(denial) = gate(&classifier, Some(&configured), &base, sql) else {
            panic!("an unprovable target must fail closed, not fall open");
        };
        assert_eq!(
            denial.reason,
            PolicyGateDenialReason::UnresolvedPolicyTarget
        );
    }

    /// A policy that failed to load is not a policy that does not apply.
    #[test]
    fn an_invalid_policy_refuses_rather_than_running_unpoliced() {
        let classifier = classifier();
        let sql = "SELECT id FROM hr.employees";
        let base = classifier.classify(sql);
        let bad = SqlPolicyConfig {
            version: 99,
            rules: Vec::new(),
        };
        let PolicyGate::Denied(denial) = gate(&classifier, Some(&bad), &base, sql) else {
            panic!("an unloadable policy must refuse");
        };
        assert_eq!(denial.reason, PolicyGateDenialReason::InvalidPolicy);
    }

    /// With no policy configured there is nothing to enforce and nothing to
    /// claim: no attachment, and the console will say "not reported" rather than
    /// pretending a policy passed.
    #[test]
    fn no_policy_configured_reports_nothing_and_changes_nothing() {
        let classifier = classifier();
        let sql = "SELECT id FROM hr.employees";
        let base = classifier.classify(sql);
        let PolicyGate::Admitted(admission) = gate(&classifier, None, &base, sql) else {
            panic!("no policy cannot deny");
        };
        assert_eq!(admission.effective_sql, None);
        assert_eq!(admission.required_level, base.required_level.unwrap());
        assert_eq!(admission.attachment, None);
    }

    /// The proof on the wire is exactly the shape the operator console already
    /// parses (`presentation-model.ts` / `operator-client.ts::parsePolicyTightening`),
    /// so the badge lights up with NO client change. This test IS that contract.
    #[test]
    fn the_attachment_is_exactly_the_shape_the_console_already_parses() {
        let classifier = classifier();
        let sql = "SELECT id FROM hr.employees";
        let base = classifier.classify(sql);
        let configured = policy(vec![
            rule(
                "hr-salary-guard",
                hr_employees(SqlPolicyVerb::Select),
                SqlPolicyEffectConfig::RequireLevel {
                    level: OperatingLevel::ReadWrite,
                },
            ),
            rule(
                "tenant-scope",
                hr_employees(SqlPolicyVerb::Select),
                SqlPolicyEffectConfig::RequirePredicate {
                    sql_fragment: "tenant_id = 42".to_owned(),
                },
            ),
        ]);
        let outcome = gate(&classifier, Some(&configured), &base, sql);
        let attachment = outcome.attachment().expect("a narrowing is reported");
        let narrow = &attachment["Narrow"];
        assert_eq!(narrow["base_required_level"], json!("READ_ONLY"));
        assert_eq!(narrow["required_level"], json!("READ_WRITE"));
        assert_eq!(
            narrow["matched_rule_ids"],
            json!(["hr-salary-guard", "tenant-scope"])
        );
        let predicate = &narrow["predicates"][0];
        assert_eq!(predicate["rule_id"], json!("tenant-scope"));
        assert_eq!(predicate["sql_fragment"], json!("tenant_id = 42"));
        assert_eq!(predicate["target"]["schema"], json!("HR"));
        assert_eq!(predicate["target"]["object"], json!("EMPLOYEES"));

        // …and the denial shape, which the console reads off the refusal envelope.
        let denied = PolicyGateDenial {
            reason: PolicyGateDenialReason::MatchingDenyRule,
            matched_rule_ids: vec!["no-prod-deletes".to_owned()],
        }
        .attachment();
        assert_eq!(denied["Deny"]["reason"], json!("matching_deny_rule"));
        assert_eq!(
            denied["Deny"]["matched_rule_ids"],
            json!(["no-prod-deletes"])
        );
    }

    /// The facts a rule is matched against come from parsing the statement, and
    /// an unqualified target is qualified by the session's schema — never by a
    /// caller-supplied hint.
    #[test]
    fn statement_facts_are_derived_from_the_parse_and_the_session_schema() {
        let facts = StatementPolicyFacts::derive("select id from employees", Some("hr"))
            .expect("a plain single-target select is provable");
        assert_eq!(facts.verb, SqlPolicyVerb::Select);
        assert_eq!(facts.schema.as_deref(), Some("HR"));
        assert_eq!(facts.object.as_deref(), Some("EMPLOYEES"));

        let qualified =
            StatementPolicyFacts::derive("UPDATE app.orders SET n = 1 WHERE id = 2", Some("HR"))
                .expect("an explicitly qualified update is provable");
        assert_eq!(qualified.verb, SqlPolicyVerb::Update);
        assert_eq!(qualified.schema.as_deref(), Some("APP"));
        assert_eq!(qualified.object.as_deref(), Some("ORDERS"));

        // These query shapes retain their proven SELECT verb but never claim a
        // schema/object target. A target-free rule can evaluate against them;
        // a target-selecting policy will fail closed in `enforce_sql_policy`.
        for query_without_exact_target in [
            "SELECT a.id FROM hr.employees a",
            "SELECT id FROM hr.employees JOIN x ON 1 = 1",
            "WITH c AS (SELECT 1 AS n FROM dual) SELECT n FROM c",
        ] {
            let facts = StatementPolicyFacts::derive(query_without_exact_target, Some("HR"))
                .expect("a parsed query always has a SELECT policy verb");
            assert_eq!(
                facts.verb,
                SqlPolicyVerb::Select,
                "{query_without_exact_target}"
            );
            assert_eq!(facts.schema, None, "{query_without_exact_target}");
            assert_eq!(facts.object, None, "{query_without_exact_target}");
        }

        assert!(
            StatementPolicyFacts::derive(
            "MERGE INTO hr.employees t USING x s ON (t.id = s.id) WHEN MATCHED THEN UPDATE SET t.n = 1",
                Some("HR"),
            )
            .is_none(),
            "a non-query statement without a policy verb remains unprovable"
        );
    }

    #[test]
    fn statement_facts_do_not_assume_aliased_updates_are_exactly_targeted() {
        assert_eq!(
            StatementPolicyFacts::derive("UPDATE hr.emp e SET id = 1 WHERE e.id = 2", Some("HR")),
            None
        );
    }

    #[test]
    fn statement_facts_do_not_assume_aliased_deletes_are_exactly_targeted() {
        assert_eq!(
            StatementPolicyFacts::derive("DELETE FROM hr.emp e WHERE e.id = 2", Some("HR")),
            None
        );
    }

    #[test]
    fn statement_facts_deny_update_with_from_clause_shaping() {
        assert_eq!(
            StatementPolicyFacts::derive(
                "UPDATE hr.emp SET id = id + 1 FROM hr.orders o WHERE hr.emp.id = o.id",
                Some("HR")
            ),
            None
        );
    }

    #[test]
    fn statement_facts_deny_delete_using_clause_shaping() {
        assert_eq!(
            StatementPolicyFacts::derive(
                "DELETE FROM hr.emp e USING hr.orders o WHERE e.id = o.id",
                Some("HR")
            ),
            None
        );
    }

    #[test]
    fn statement_facts_do_not_assume_delete_targets_with_joins() {
        assert_eq!(
            StatementPolicyFacts::derive(
                "DELETE FROM hr.emp e JOIN hr.orders o ON e.id = o.id",
                Some("HR")
            ),
            None
        );
    }

    fn gate_with_schema(
        classifier: &Classifier,
        policy: Option<&SqlPolicyConfig>,
        base: &GuardDecision,
        sql: &str,
        current_schema: Option<&str>,
    ) -> PolicyGate {
        enforce_sql_policy(&PolicyGateRequest {
            classifier,
            policy,
            base,
            sql,
            current_schema,
            principal: Some("oauth:subject-1"),
        })
    }

    #[test]
    fn schema_only_targeting_policies_refuse_unresolvable_schema_if_context_is_unknown() {
        let classifier = classifier();
        let sql = "SELECT * FROM employees";
        let base = classifier.classify(sql);
        let configured = policy(vec![rule(
            "hr-schema-floor",
            SqlPolicyMatchConfig {
                schema: Some("HR".to_owned()),
                object: None,
                verb: Some(SqlPolicyVerb::Select),
                principal: None,
            },
            SqlPolicyEffectConfig::RequireLevel {
                level: OperatingLevel::ReadWrite,
            },
        )]);

        let PolicyGate::Denied(denial) =
            gate_with_schema(&classifier, Some(&configured), &base, sql, None)
        else {
            panic!("a schema-only target selector cannot resolve without CURRENT_SCHEMA")
        };

        assert_eq!(
            denial.reason,
            PolicyGateDenialReason::UnresolvedPolicyTarget,
            "missing schema should fail closed"
        );
        assert_eq!(denial.matched_rule_ids, Vec::<String>::new());
    }

    #[test]
    fn policy_selects_a_target_when_only_schema_is_declared() {
        let classifier = classifier();
        let sql = "SELECT * FROM hr.employees";
        let base = classifier.classify(sql);
        let configured = policy(vec![rule(
            "hr-schema-floor",
            SqlPolicyMatchConfig {
                schema: Some("HR".to_owned()),
                object: None,
                verb: Some(SqlPolicyVerb::Select),
                principal: None,
            },
            SqlPolicyEffectConfig::RequireLevel {
                level: OperatingLevel::ReadWrite,
            },
        )]);

        // With CURRENT_SCHEMA known, the same policy can resolve the target and
        // therefore still narrow the base decision.
        let PolicyGate::Admitted(admission) =
            gate_with_schema(&classifier, Some(&configured), &base, sql, Some("HR"))
        else {
            panic!("schema-only selection is a valid schema-level policy target");
        };
        assert_eq!(admission.required_level, OperatingLevel::ReadWrite);
        assert_eq!(
            admission.required_level,
            admission.required_level.max(OperatingLevel::ReadOnly)
        );
    }

    #[test]
    fn rewrite_reason_preserves_predicate_conflict_denial() {
        assert_eq!(
            rewrite_reason(PolicyRewriteDenialReason::BaseClassifierRefused),
            PolicyGateDenialReason::BaseClassifierRefused
        );
        assert_eq!(
            rewrite_reason(PolicyRewriteDenialReason::PredicateTargetConflict),
            PolicyGateDenialReason::PredicateTargetConflict
        );
    }

    /// The remaining nine [`PolicyRewriteDenialReason`] variants all fall
    /// through `rewrite_reason`'s catch-all arm to
    /// [`PolicyGateDenialReason::PredicateRewriteRefused`] — the one arm the
    /// test above did not reach. Before this, `PredicateRewriteRefused` had
    /// zero coverage anywhere: it is otherwise only constructed at its call
    /// site inside `enforce_sql_policy`, which no test drove into this branch
    /// (every existing predicate-rewrite test either succeeds or hits
    /// `BaseClassifierRefused`/`PredicateTargetConflict` specifically).
    #[test]
    fn rewrite_reason_collapses_every_other_rewrite_denial_to_predicate_rewrite_refused() {
        for reason in [
            PolicyRewriteDenialReason::InconsistentBaseDecision,
            PolicyRewriteDenialReason::NoPredicates,
            PolicyRewriteDenialReason::TargetContextMismatch,
            PolicyRewriteDenialReason::OriginalParseFailed,
            PolicyRewriteDenialReason::UnsupportedStatementShape,
            PolicyRewriteDenialReason::PredicateParseFailed,
            PolicyRewriteDenialReason::CandidateClassifierRefused,
            PolicyRewriteDenialReason::CandidateNotReadOnly,
            PolicyRewriteDenialReason::IncompleteCandidateDecision,
        ] {
            assert_eq!(
                rewrite_reason(reason),
                PolicyGateDenialReason::PredicateRewriteRefused,
                "{reason:?} must collapse to PredicateRewriteRefused, not silently \
                 fall back to a different (or no) denial reason"
            );
        }
    }

    /// The wire label is the ADR-0009 proof the operator console parses
    /// (`{"Deny": {"reason": "...", ...}}`); a rename here is a silent
    /// contract break the console cannot recover from. Only one of the eight
    /// variants (`matching_deny_rule`) was pinned before this test — the other
    /// seven wire strings had no golden coverage at all.
    #[test]
    fn policy_gate_denial_reason_wire_labels_are_pinned() {
        let cases = [
            (
                PolicyGateDenialReason::BaseClassifierRefused,
                "base_classifier_refused",
            ),
            (
                PolicyGateDenialReason::IncompleteBaseDecision,
                "incomplete_base_decision",
            ),
            (PolicyGateDenialReason::InvalidPolicy, "invalid_policy"),
            (
                PolicyGateDenialReason::MatchingDenyRule,
                "matching_deny_rule",
            ),
            (
                PolicyGateDenialReason::PredicateTargetConflict,
                "predicate_target_conflict",
            ),
            (
                PolicyGateDenialReason::UnresolvedPolicyTarget,
                "unresolved_policy_target",
            ),
            (
                PolicyGateDenialReason::PredicateRewriteRefused,
                "predicate_rewrite_refused",
            ),
            (
                PolicyGateDenialReason::NonMonotonicComposition,
                "non_monotonic_composition",
            ),
        ];
        for (reason, wire) in cases {
            assert_eq!(reason.as_str(), wire);
            // The label also flows through `.attachment()` verbatim.
            let denial = PolicyGateDenial {
                reason,
                matched_rule_ids: Vec::new(),
            };
            assert_eq!(denial.attachment()["Deny"]["reason"], json!(wire));
        }
    }

    #[test]
    fn select_joins_do_not_infer_exact_targets() {
        let facts = StatementPolicyFacts::derive(
            "SELECT e.id FROM hr.employees JOIN hr.departments ON e.department_id = hr.departments.id",
            Some("HR"),
        )
        .expect("join statements parse");

        assert_eq!(facts.verb, SqlPolicyVerb::Select);
        assert_eq!(facts.schema, None);
        assert_eq!(facts.object, None);
    }
}
