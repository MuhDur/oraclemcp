//! Property-based invariants for the fail-closed guard (proptest). Two security
//! invariants the unit corpus checks only by example are asserted here over
//! thousands of generated inputs:
//!
//! 1. **ALTER SESSION allowlist fail-closed law.** [`is_allowed_alter_session`]
//!    must NEVER accept a statement that assigns any parameter outside the §6.5
//!    allowlist, regardless of quoting / whitespace / case (oracle-ajm2.4 — a
//!    single allowlisted prefix must not smuggle a trailing `SQL_TRACE = TRUE`
//!    / `EVENTS = '…'` past the gate).
//!
//! 2. **Comment-wedge metamorphic relation.** Inserting a `/* … */` or `--`
//!    comment anywhere between the tokens of a dangerous statement must never
//!    LOWER its [`DangerLevel`] (oracle-rwjl.1 — a comment wedged between
//!    `EXECUTE`/`IMMEDIATE` must keep the block Forbidden, not silently downgrade
//!    it). Danger is monotone non-decreasing under comment insertion.
//!
//! 3. **Opaque-call wrapping monotonicity.** Generated package/member calls stay
//!    Forbidden when wrapped in anonymous-block control flow, declarations,
//!    labels, comments, case changes, or no-argument procedure syntax.
//!
//! 4. **Arc N policy monotonicity (bead …6sj8.5.5).** Six laws over generated
//!    (statement, policy) pairs establish that a policy is a *restriction* and
//!    nothing else: composition never loosens the classifier's verdict; adding
//!    rules only ever tightens the result; rule order carries no authority (no
//!    first-match/else precedence to shadow a rule with); an empty policy is the
//!    identity rather than a grant; no policy can unlock a Forbidden statement;
//!    and the N3 predicate rewrite cannot launder a statement into a weaker
//!    verdict (SEC-1). The grammar has no `Allow` effect, so any counterexample
//!    here is a real widening of the guard, not a generator artefact.
//!
//! Small case counts keep CI fast; the standing adversarial corpus + cargo-fuzz
//! target cover the example-level and never-panic dimensions.

use oraclemcp_guard::policy::{
    PolicyDenialReason, PolicyNarrowing, PolicyPredicateRewrite, PolicyTightening,
    SQL_POLICY_VERSION, SqlPolicyConfig, SqlPolicyEffectConfig, SqlPolicyEvaluationContext,
    SqlPolicyMatchConfig, SqlPolicyRuleConfig, SqlPolicyVerb, rewrite_predicates_and_reclassify,
};
use oraclemcp_guard::{Classifier, DangerLevel, OperatingLevel, is_allowed_alter_session};
use proptest::prelude::*;

const ALLOWLISTED_PARAMS: &[&str] = &[
    "CURRENT_SCHEMA",
    "NLS_DATE_FORMAT",
    "NLS_TIMESTAMP_FORMAT",
    "NLS_TIMESTAMP_TZ_FORMAT",
    "NLS_NUMERIC_CHARACTERS",
    "NLS_LANGUAGE",
    "NLS_TERRITORY",
    "NLS_SORT",
    "NLS_COMP",
    "TIME_ZONE",
    "OPTIMIZER_MODE",
    "STATISTICS_LEVEL",
    "OPTIMIZER_DYNAMIC_SAMPLING",
    "PLSQL_WARNINGS",
    "EDITION",
    "PLSCOPE_SETTINGS",
];

const NON_ALLOWLISTED_PARAMS: &[&str] = &[
    "SQL_TRACE",
    "EVENTS",
    "CONTAINER",
    "TRACEFILE_IDENTIFIER",
    "PLSQL_OPTIMIZE_LEVEL",
    "PLSQL_CODE_TYPE",
    "PLSQL_DEBUG",
    "RESUMABLE_TIMEOUT",
    "CONSTRAINTS",
    "ISOLATION_LEVEL",
    "FLASHBACK_QUERY",
    "PARALLEL_DML",
    "SKIP_UNUSABLE_INDEXES",
    "MAX_DUMP_FILE_SIZE",
    "DB_FILE_MULTIBLOCK_READ_COUNT",
    "CELL_OFFLOAD_PROCESSING",
];

fn param_assignment() -> impl Strategy<Value = (String, bool)> {
    prop_oneof![
        (0..ALLOWLISTED_PARAMS.len()).prop_map(|i| (ALLOWLISTED_PARAMS[i].to_owned(), true)),
        (0..NON_ALLOWLISTED_PARAMS.len())
            .prop_map(|i| (NON_ALLOWLISTED_PARAMS[i].to_owned(), false)),
    ]
}

fn render_param(name: &str, quoted_value: bool, lowercase: bool, spaces: usize) -> String {
    let value = if quoted_value {
        "'10046 trace name context forever, level 12'".to_owned()
    } else {
        "SOME_VALUE".to_owned()
    };
    let pad = " ".repeat(spaces.max(1));
    let clause = format!("{name}{pad}={pad}{value}");
    if lowercase {
        clause.to_ascii_lowercase()
    } else {
        clause
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Invariant #1 (fail-closed): a statement that assigns ANY non-allowlisted
    /// parameter must never be accepted, no matter how the allowlisted clauses
    /// around it are quoted, cased, or spaced.
    #[test]
    fn alter_session_never_accepts_non_allowlisted_param(
        clauses in prop::collection::vec(
            (param_assignment(), any::<bool>(), any::<bool>(), 1usize..4),
            1..6,
        ),
        leading_ws in 0usize..4,
        trailing_ws in 0usize..4,
    ) {
        let mut any_disallowed = false;
        let rendered: Vec<String> = clauses
            .iter()
            .map(|((name, allowed), quoted, lower, spaces)| {
                if !*allowed {
                    any_disallowed = true;
                }
                render_param(name, *quoted, *lower, *spaces)
            })
            .collect();

        let stmt = format!(
            "{}ALTER SESSION SET {}{}",
            " ".repeat(leading_ws),
            rendered.join(" "),
            " ".repeat(trailing_ws),
        );

        let accepted = is_allowed_alter_session(&stmt);

        if any_disallowed {
            prop_assert!(
                !accepted,
                "FAIL-CLOSED VIOLATION: is_allowed_alter_session accepted a statement \
                 assigning a non-allowlisted parameter: {stmt:?}"
            );
        }
    }

    /// Invariant #1, mirror: a statement assigning ONLY allowlisted parameters
    /// (well-formed `param = value` clauses) is accepted. This guards against a
    /// trivially-fail-closed validator that rejects everything (which would
    /// satisfy the security half while being useless), and pins the positive
    /// direction so a regression that breaks legitimate use is also caught.
    #[test]
    fn alter_session_accepts_all_allowlisted_params(
        idxs in prop::collection::vec(0..ALLOWLISTED_PARAMS.len(), 1..6),
        quoteds in prop::collection::vec(any::<bool>(), 1..6),
        lowers in prop::collection::vec(any::<bool>(), 1..6),
    ) {
        let rendered: Vec<String> = idxs
            .iter()
            .enumerate()
            .map(|(i, &pi)| {
                let quoted = *quoteds.get(i % quoteds.len()).unwrap_or(&false);
                let lower = *lowers.get(i % lowers.len()).unwrap_or(&false);
                let value = if quoted { "'YYYY-MM-DD'" } else { "SOME_VALUE" };
                let clause = format!("{} = {value}", ALLOWLISTED_PARAMS[pi]);
                if lower { clause.to_ascii_lowercase() } else { clause }
            })
            .collect();

        let stmt = format!("ALTER SESSION SET {}", rendered.join(" "));
        prop_assert!(
            is_allowed_alter_session(&stmt),
            "all-allowlisted statement was rejected: {stmt:?}"
        );
    }
}

/// Dangerous PL/SQL block templates. Each is split into the token gaps where a
/// comment may legally be wedged (`{}` placeholders). The base form (no comment)
/// is classified once to capture the reference danger; every comment-injected
/// variant must classify at a danger ≥ that reference.
const DANGEROUS_TEMPLATES: &[&[&str]] = &[
    &["BEGIN", "EXECUTE", "IMMEDIATE", "'DROP TABLE t'", "; END;"],
    &[
        "BEGIN",
        "EXECUTE",
        "IMMEDIATE",
        "'GRANT DBA TO scott'",
        "; END;",
    ],
    &[
        "DECLARE",
        "x NUMBER; BEGIN",
        "DBMS_SQL",
        ".PARSE(c, s, 1); END;",
    ],
    &["BEGIN", "UTL_FILE", ".FOPEN('D', 'f', 'w'); END;"],
    &["BEGIN", "UTL_HTTP", ".REQUEST('http://x'); END;"],
    &["BEGIN", "DBMS_SCHEDULER", ".CREATE_JOB('j'); END;"],
    &[
        "DECLARE PRAGMA",
        "AUTONOMOUS_TRANSACTION",
        "; BEGIN NULL; END;",
    ],
    &["CREATE OR REPLACE", "PROCEDURE", "p AS BEGIN NULL; END;"],
    &["BEGIN NULL; END;", "GRANT DBA TO scott"],
];

fn comment_kinds() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("/**/".to_owned()),
        Just("/* x */".to_owned()),
        Just("/*EXECUTE IMMEDIATE*/".to_owned()),
        Just("--c\n".to_owned()),
        Just("-- inline comment\n".to_owned()),
    ]
}

fn join_with_comments(parts: &[&str], comments: &[Option<String>]) -> String {
    let mut out = String::new();
    for (i, part) in parts.iter().enumerate() {
        out.push_str(part);
        if i + 1 < parts.len() {
            match comments.get(i).and_then(Option::as_ref) {
                Some(c) => {
                    out.push(' ');
                    out.push_str(c);
                    out.push(' ');
                }
                None => out.push(' '),
            }
        }
    }
    out
}

fn canonical_whitespace(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

/// Schemas, objects and principals the Arc N generators draw from. Keeping the
/// alphabets small and shared means a generated rule selector has a real chance
/// of both matching and missing a generated statement, instead of the policy
/// being vacuous.
static POLICY_SCHEMAS: [&str; 2] = ["APP", "HR"];
static POLICY_OBJECTS: [&str; 2] = ["ORDERS", "EMPLOYEES"];
static POLICY_PRINCIPALS: [&str; 2] = ["oauth:analyst-7", "mtls:9f2c4a"];
/// Row filters accepted by the ADR 0009 restricted predicate grammar.
static POLICY_PREDICATES: [&str; 3] = ["tenant_id = 7", "region = 'EU'", "deleted = 0"];
static POLICY_LEVELS: [OperatingLevel; 4] = [
    OperatingLevel::ReadOnly,
    OperatingLevel::ReadWrite,
    OperatingLevel::Ddl,
    OperatingLevel::Admin,
];
static POLICY_VERBS: [SqlPolicyVerb; 9] = [
    SqlPolicyVerb::Select,
    SqlPolicyVerb::Insert,
    SqlPolicyVerb::Update,
    SqlPolicyVerb::Delete,
    SqlPolicyVerb::Merge,
    SqlPolicyVerb::Ddl,
    SqlPolicyVerb::Admin,
    SqlPolicyVerb::Plsql,
    SqlPolicyVerb::AlterSession,
];
/// The verbs a `RequirePredicate` rule may constrain, and therefore the only
/// statement kinds the N3 rewrite can be exercised over.
static ROW_FILTER_VERBS: [SqlPolicyVerb; 3] = [
    SqlPolicyVerb::Select,
    SqlPolicyVerb::Update,
    SqlPolicyVerb::Delete,
];
static ROW_FILTER_KINDS: [u8; 3] = [0, 2, 3];
/// Statements the classifier refuses outright, used to prove no policy can
/// reopen a refusal.
static FORBIDDEN_STATEMENTS: [&str; 3] = [
    "BEGIN EXECUTE IMMEDIATE 'DROP TABLE app.orders'; END;",
    "BEGIN DBMS_SCHEDULER.CREATE_JOB(job_name => 'j'); END;",
    "BEGIN SYS.DBMS_SYS_SQL.PARSE_AS_USER(1, 'x', 1); END;",
];

/// One generated statement together with the server-derived facts Arc N is
/// allowed to match on. Both halves are generated as a pair so a rule can only
/// ever match through the classifier's own view of the statement.
#[derive(Clone, Debug)]
struct PolicyScenario {
    sql: String,
    context: SqlPolicyEvaluationContext,
}

/// The effect of one generated rule. This mirrors the whole v1 effect grammar:
/// there is no loosening effect to generate, so a generated policy that admits
/// something the classifier refused is a real defect, not a generator artefact.
#[derive(Clone, Debug)]
enum EffectSeed {
    Deny,
    RequireLevel(OperatingLevel),
    RequirePredicate(&'static str),
}

/// One generated rule before an id is stamped on it.
#[derive(Clone, Debug)]
struct RuleSeed {
    schema: Option<&'static str>,
    object: Option<&'static str>,
    verb: Option<SqlPolicyVerb>,
    principal: Option<&'static str>,
    effect: EffectSeed,
}

fn policy_scenario(
    schema: &'static str,
    object: &'static str,
    kind: u8,
    principal: Option<&'static str>,
) -> PolicyScenario {
    let owner = schema.to_ascii_lowercase();
    let table = object.to_ascii_lowercase();
    // `targeted` statements resolve to exactly one owner.object; the rest have no
    // single exact target, so a schema-scoped rule must not match them at all.
    let (sql, verb, targeted) = match kind % 9 {
        0 => (
            format!("SELECT id FROM {owner}.{table} WHERE status = 'OPEN'"),
            SqlPolicyVerb::Select,
            true,
        ),
        1 => (
            format!("INSERT INTO {owner}.{table} (id) VALUES (7)"),
            SqlPolicyVerb::Insert,
            true,
        ),
        2 => (
            format!("UPDATE {owner}.{table} SET status = 'OPEN' WHERE id = 7"),
            SqlPolicyVerb::Update,
            true,
        ),
        3 => (
            format!("DELETE FROM {owner}.{table} WHERE id = 7"),
            SqlPolicyVerb::Delete,
            true,
        ),
        4 => (
            format!(
                "MERGE INTO {owner}.{table} t USING dual d ON (t.id = d.dummy) WHEN MATCHED THEN UPDATE SET t.status = 'OPEN'"
            ),
            SqlPolicyVerb::Merge,
            true,
        ),
        5 => (
            format!("DROP TABLE {owner}.{table}"),
            SqlPolicyVerb::Ddl,
            true,
        ),
        6 => ("GRANT DBA TO app".to_owned(), SqlPolicyVerb::Admin, false),
        7 => (
            format!("BEGIN EXECUTE IMMEDIATE 'DROP TABLE {owner}.{table}'; END;"),
            SqlPolicyVerb::Plsql,
            false,
        ),
        _ => (
            format!("ALTER SESSION SET CURRENT_SCHEMA = {schema}"),
            SqlPolicyVerb::AlterSession,
            false,
        ),
    };
    let context = SqlPolicyEvaluationContext::new(
        targeted.then(|| schema.to_owned()),
        targeted.then(|| object.to_owned()),
        verb,
        principal.map(str::to_owned),
    );
    PolicyScenario { sql, context }
}

/// Stamp ids onto generated seeds. Ids are prefixed and indexed so two
/// independently generated rule lists can be concatenated and still load.
fn rules_from_seeds(seeds: &[RuleSeed], prefix: &str) -> Vec<SqlPolicyRuleConfig> {
    seeds
        .iter()
        .enumerate()
        .map(|(index, seed)| SqlPolicyRuleConfig {
            id: format!("{prefix}-{index}"),
            match_clause: SqlPolicyMatchConfig {
                schema: seed.schema.map(str::to_owned),
                object: seed.object.map(str::to_owned),
                verb: seed.verb,
                principal: seed.principal.map(str::to_owned),
            },
            effect: match seed.effect {
                EffectSeed::Deny => SqlPolicyEffectConfig::Deny,
                EffectSeed::RequireLevel(level) => SqlPolicyEffectConfig::RequireLevel { level },
                EffectSeed::RequirePredicate(sql_fragment) => {
                    SqlPolicyEffectConfig::RequirePredicate {
                        sql_fragment: sql_fragment.to_owned(),
                    }
                }
            },
        })
        .collect()
}

fn policy_of(rules: Vec<SqlPolicyRuleConfig>) -> SqlPolicyConfig {
    SqlPolicyConfig {
        version: SQL_POLICY_VERSION,
        rules,
    }
}

fn scenario_strategy() -> impl Strategy<Value = PolicyScenario> {
    (
        prop::sample::select(&POLICY_SCHEMAS[..]),
        prop::sample::select(&POLICY_OBJECTS[..]),
        0u8..9,
        prop::option::of(prop::sample::select(&POLICY_PRINCIPALS[..])),
    )
        .prop_map(|(schema, object, kind, principal)| {
            policy_scenario(schema, object, kind, principal)
        })
}

fn verb_strategy() -> impl Strategy<Value = SqlPolicyVerb> {
    prop::sample::select(&POLICY_VERBS[..])
}

/// A rule seed that always loads: `object` never appears without `schema`, and a
/// `RequirePredicate` always carries the exact target the grammar demands.
fn rule_seed_strategy() -> impl Strategy<Value = RuleSeed> {
    let selectors = (
        prop::option::of(prop::sample::select(&POLICY_SCHEMAS[..])),
        prop::option::of(prop::sample::select(&POLICY_OBJECTS[..])),
        prop::option::of(verb_strategy()),
        prop::option::of(prop::sample::select(&POLICY_PRINCIPALS[..])),
    );
    let level_or_deny = prop_oneof![
        Just(EffectSeed::Deny),
        prop::sample::select(&POLICY_LEVELS[..]).prop_map(EffectSeed::RequireLevel),
    ];
    let deny_or_level_rule =
        (selectors, level_or_deny).prop_map(|((schema, object, verb, principal), effect)| {
            RuleSeed {
                // The grammar refuses a bare object selector, so anchor it or drop it.
                object: schema.and(object),
                schema,
                verb,
                principal,
                effect,
            }
        });

    // RequirePredicate is only loadable with an exact schema+object and a
    // row-filterable verb, so it is generated as its own well-formed shape.
    let predicate_rule = (
        prop::sample::select(&POLICY_SCHEMAS[..]),
        prop::sample::select(&POLICY_OBJECTS[..]),
        prop::sample::select(&ROW_FILTER_VERBS[..]),
        prop::option::of(prop::sample::select(&POLICY_PRINCIPALS[..])),
        prop::sample::select(&POLICY_PREDICATES[..]),
    )
        .prop_map(|(schema, object, verb, principal, fragment)| RuleSeed {
            schema: Some(schema),
            object: Some(object),
            verb: Some(verb),
            principal,
            effect: EffectSeed::RequirePredicate(fragment),
        });

    prop_oneof![2 => deny_or_level_rule, 1 => predicate_rule]
}

fn rule_seeds_strategy(max: usize) -> impl Strategy<Value = Vec<RuleSeed>> {
    prop::collection::vec(rule_seed_strategy(), 0..max)
}

/// Sorted (rule id, fragment) pairs — a policy's predicate set independent of
/// the order the rules happened to be declared in.
fn predicate_fingerprint(narrowing: &PolicyNarrowing) -> Vec<(String, String)> {
    let mut fingerprint: Vec<(String, String)> = narrowing
        .predicates
        .iter()
        .map(|predicate| (predicate.rule_id.clone(), predicate.sql_fragment.clone()))
        .collect();
    fingerprint.sort();
    fingerprint
}

fn sorted_ids(narrowing: &PolicyNarrowing) -> Vec<String> {
    let mut ids = narrowing.matched_rule_ids.clone();
    ids.sort();
    ids
}

#[test]
fn danger_adding_transforms_never_lower_classifier_danger() {
    let classifier = Classifier::default();
    let cases = [
        (
            "SELECT * FROM employees",
            &[
                ("append FOR UPDATE", "SELECT * FROM employees FOR UPDATE"),
                (
                    "append DROP",
                    "SELECT * FROM employees; DROP TABLE employees",
                ),
                ("wrap block", "BEGIN SELECT * FROM employees; END;"),
                (
                    "writing CTE",
                    "INSERT INTO audit_log WITH c AS (SELECT * FROM employees) SELECT * FROM c",
                ),
            ][..],
        ),
        (
            "UPDATE orders SET status = 'X' WHERE id = 1",
            &[
                (
                    "append DROP",
                    "UPDATE orders SET status = 'X' WHERE id = 1; DROP TABLE orders",
                ),
                (
                    "wrap block",
                    "BEGIN UPDATE orders SET status = 'X' WHERE id = 1; END;",
                ),
            ][..],
        ),
        (
            "SELECT app.recalc(id) FROM orders",
            &[
                (
                    "append DROP",
                    "SELECT app.recalc(id) FROM orders; DROP TABLE orders",
                ),
                (
                    "append FOR UPDATE",
                    "SELECT app.recalc(id) FROM orders FOR UPDATE",
                ),
            ][..],
        ),
    ];

    for (base_sql, transforms) in cases {
        let base_danger = classifier.classify(base_sql).danger;
        for (label, transformed_sql) in transforms {
            let transformed = classifier.classify(transformed_sql).danger;
            assert!(
                transformed >= base_danger,
                "danger-adding transform {label} lowered danger {base_danger:?} -> {transformed:?}\n  base: {base_sql:?}\n  transformed: {transformed_sql:?}"
            );
        }
    }
}

#[test]
fn classification_is_idempotent_under_canonical_whitespace() {
    let classifier = Classifier::default();
    for sql in [
        "  SELECT   id,  name   FROM   employees   WHERE dept = 10  ",
        "SELECT   app.recalc(id)   FROM   orders",
        "UPDATE   orders   SET status = 'X'   WHERE id = 1",
        "BEGIN   EXECUTE   IMMEDIATE   'DROP TABLE x';   END;",
        "SELECT   *   FROM   t   FOR   UPDATE",
        "INSERT   INTO t WITH c AS (SELECT 1 FROM dual) SELECT * FROM c",
    ] {
        let once = canonical_whitespace(sql);
        let twice = canonical_whitespace(&once);
        assert_eq!(once, twice, "test canonicalizer must be idempotent");

        let original = classifier.classify(sql);
        let normalized = classifier.classify(&once);
        assert_eq!(
            (original.danger, original.required_level),
            (normalized.danger, normalized.required_level),
            "canonical whitespace reclassification changed the decision\n  original: {sql:?} -> {original:?}\n  normalized: {once:?} -> {normalized:?}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    /// Invariant #2 (metamorphic): inserting comments between the tokens of a
    /// dangerous statement must never LOWER its danger classification. The
    /// comment-wedged variant's danger is `>=` the comment-free reference. A
    /// FAIL here means a comment downgraded a dangerous statement — the exact
    /// patch-tool comment-wedge security finding (oracle-rwjl.1).
    #[test]
    fn comment_insertion_never_lowers_danger(
        tmpl_idx in 0..DANGEROUS_TEMPLATES.len(),
        comments in prop::collection::vec(
            prop::option::weighted(0.7, comment_kinds()),
            DANGEROUS_TEMPLATES.iter().map(|t| t.len()).max().unwrap_or(1),
        ),
    ) {
        let classifier = Classifier::default();
        let parts = DANGEROUS_TEMPLATES[tmpl_idx];

        let base_sql = join_with_comments(parts, &vec![None; parts.len()]);
        let base_danger = classifier.classify(&base_sql).danger;

        let wedged_sql = join_with_comments(parts, &comments);
        let wedged_danger = classifier.classify(&wedged_sql).danger;

        prop_assert!(
            wedged_danger >= base_danger,
            "METAMORPHIC VIOLATION: comment insertion LOWERED danger \
             {base_danger:?} -> {wedged_danger:?}\n  base:   {base_sql:?}\n  wedged: {wedged_sql:?}"
        );
    }

    /// Invariant #2, sharpened to the headline marker: a dangerous PL/SQL block
    /// (with a side-effect marker) must stay strictly above `Guarded` — i.e.
    /// `Destructive`/`Forbidden` — no matter how comments are wedged between its
    /// tokens. This is the concrete anti-downgrade assertion behind the
    /// `canonical_marker_scan` fix: a comment-split `EXECUTE/**/IMMEDIATE` must
    /// not slip to `Guarded`.
    #[test]
    fn dangerous_marker_block_stays_high_under_comment_wedge(
        tmpl_idx in 0..DANGEROUS_TEMPLATES.len(),
        comments in prop::collection::vec(
            prop::option::weighted(0.8, comment_kinds()),
            DANGEROUS_TEMPLATES.iter().map(|t| t.len()).max().unwrap_or(1),
        ),
    ) {
        let classifier = Classifier::default();
        let parts = DANGEROUS_TEMPLATES[tmpl_idx];

        let base_danger = classifier
            .classify(&join_with_comments(parts, &vec![None; parts.len()]))
            .danger;
        prop_assume!(base_danger >= DangerLevel::Destructive);

        let wedged_sql = join_with_comments(parts, &comments);
        let wedged_danger = classifier.classify(&wedged_sql).danger;

        prop_assert!(
            wedged_danger >= DangerLevel::Destructive,
            "COMMENT-WEDGE DOWNGRADE: a dangerous-marker block dropped below \
             Destructive to {wedged_danger:?}\n  wedged: {wedged_sql:?}"
        );
    }

    /// Invariant #3: an unproven package/member call is already Forbidden as an
    /// explicit CALL, and adding PL/SQL wrappers/noise must never lower that
    /// authority. This is generated rather than a fixed wrapper table so new
    /// identifier spellings, comments, labels, and wrapper combinations keep
    /// exercising the proof boundary.
    #[test]
    fn opaque_call_wrapping_never_lowers_authority(
        package in "[a-z][a-z0-9_]{0,12}",
        member in "[a-z][a-z0-9_]{0,12}",
        wrapper in 0u8..5,
        comment in prop_oneof![Just("/**/"), Just("/* proof gap */"), Just("-- gap\n")],
        uppercase in any::<bool>(),
        noarg in any::<bool>(),
    ) {
        let classifier = Classifier::default();
        let base = format!("CALL {package}.{member}(:value)");
        let base_decision = classifier.classify(&base);
        prop_assert_eq!(
            base_decision.danger,
            DangerLevel::Forbidden,
            "base {:?}",
            base
        );

        let qualified = format!("{package} {comment} . {comment} {member}");
        let invocation = if noarg {
            qualified
        } else {
            format!("{qualified}(:value)")
        };
        let mut wrapped = match wrapper {
            0 => format!("BEGIN {invocation}; END;"),
            1 => format!(
                "DECLARE n PLS_INTEGER := 1; BEGIN {invocation}; END;"
            ),
            2 => format!(
                "BEGIN IF :enabled = 1 THEN {invocation}; END IF; END;"
            ),
            3 => format!("BEGIN LOOP {invocation}; EXIT; END LOOP; END;"),
            _ => format!(
                "<<outer_label>> BEGIN <<call_label>> {invocation}; END;"
            ),
        };
        if uppercase {
            wrapped = wrapped.to_ascii_uppercase();
        }

        let wrapped_decision = classifier.classify(&wrapped);
        prop_assert!(
            wrapped_decision.danger >= base_decision.danger,
            "OPAQUE-CALL DOWNGRADE: {base:?} -> {wrapped:?}: {wrapped_decision:?}"
        );
        prop_assert_eq!(
            wrapped_decision.required_level,
            None,
            "wrapped {:?}",
            wrapped
        );
    }

    /// N4 law 1 — **tightening-only.** For any generated (statement, policy)
    /// pair the composed result is either a refusal, or it preserves the
    /// classifier's own verdict and adds to it: the base level is carried
    /// through unchanged and the final floor never sits below it. A policy is a
    /// restriction, so there is no outcome in which it hands back more authority
    /// than the classifier already granted.
    #[test]
    fn policy_composition_never_loosens_the_base_verdict(
        scenario in scenario_strategy(),
        seeds in rule_seeds_strategy(6),
    ) {
        let policy = policy_of(rules_from_seeds(&seeds, "r"));
        prop_assert!(policy.validate().is_ok(), "generator emitted an unloadable policy: {policy:?}");
        let base = Classifier::default().classify(&scenario.sql);

        match policy.evaluate(&base, &scenario.context) {
            // A refusal is the tightest possible outcome; nothing to prove.
            PolicyTightening::Deny(_) => {}
            PolicyTightening::Narrow(narrowing) => {
                let base_level = base.required_level.expect(
                    "a narrowed decision must carry the base classifier's level",
                );
                prop_assert_ne!(
                    base.danger, DangerLevel::Forbidden,
                    "POLICY ADMITTED A FORBIDDEN STATEMENT: {:?}", narrowing,
                );
                prop_assert_eq!(
                    narrowing.base_required_level, base_level,
                    "POLICY REWROTE THE BASE LEVEL: narrowing={:?}, base={:?}", narrowing, base,
                );
                prop_assert!(
                    narrowing.required_level >= base_level,
                    "POLICY LOOSENING: base={base:?}, narrowing={narrowing:?}, policy={policy:?}",
                );
                // Every predicate must be attributable to a rule that actually
                // matched: an unattributed filter is authority from nowhere.
                for predicate in &narrowing.predicates {
                    prop_assert!(
                        narrowing.matched_rule_ids.contains(&predicate.rule_id),
                        "UNATTRIBUTED PREDICATE: {predicate:?} not in {:?}", narrowing.matched_rule_ids,
                    );
                }
            }
        }
    }

    /// N4 law 2 — **composition is monotone.** Adding rules to a policy can only
    /// ever tighten its result. A denial can never be reopened by a later rule,
    /// a level floor can only rise, and predicates only accumulate. This is the
    /// law that makes an operator's policy file safe to extend: no added rule
    /// can, by matching, undo a restriction another rule already imposed.
    #[test]
    fn adding_policy_rules_never_loosens_the_result(
        scenario in scenario_strategy(),
        base_seeds in rule_seeds_strategy(5),
        extra_seeds in rule_seeds_strategy(4),
        position in 0usize..8,
    ) {
        let base_rules = rules_from_seeds(&base_seeds, "a");
        let extra_rules = rules_from_seeds(&extra_seeds, "b");
        let smaller = policy_of(base_rules.clone());

        // Splice the extra rules in at a generated position, so this proves more
        // than "appending is safe" — no insertion point can loosen the result.
        let mut combined_rules = base_rules;
        let at = position % (combined_rules.len() + 1);
        combined_rules.splice(at..at, extra_rules);
        let larger = policy_of(combined_rules);
        prop_assert!(smaller.validate().is_ok() && larger.validate().is_ok());

        let base = Classifier::default().classify(&scenario.sql);
        let small_result = smaller.evaluate(&base, &scenario.context);
        let large_result = larger.evaluate(&base, &scenario.context);

        match (small_result, large_result) {
            // Denied stays denied; adding rules cannot unlock a statement.
            (PolicyTightening::Deny(_), PolicyTightening::Deny(_)) => {}
            (PolicyTightening::Deny(denial), PolicyTightening::Narrow(narrowing)) => {
                prop_assert!(
                    false,
                    "ADDED RULES UNLOCKED A DENIED STATEMENT: denial={denial:?}, narrowing={narrowing:?}",
                );
            }
            // Narrow -> Deny is strictly tighter, which is always permitted.
            (PolicyTightening::Narrow(_), PolicyTightening::Deny(_)) => {}
            (PolicyTightening::Narrow(small), PolicyTightening::Narrow(large)) => {
                prop_assert!(
                    large.required_level >= small.required_level,
                    "ADDED RULES LOWERED THE FLOOR: small={small:?}, large={large:?}",
                );
                prop_assert_eq!(
                    large.base_required_level, small.base_required_level,
                    "ADDED RULES MOVED THE BASE LEVEL: small={:?}, large={:?}", small, large,
                );
                for predicate in &small.predicates {
                    prop_assert!(
                        large.predicates.contains(predicate),
                        "ADDED RULES DROPPED A PREDICATE: {predicate:?} missing from {:?}", large.predicates,
                    );
                }
                for id in &small.matched_rule_ids {
                    prop_assert!(
                        large.matched_rule_ids.contains(id),
                        "ADDED RULES UNMATCHED RULE {id}: {:?}", large.matched_rule_ids,
                    );
                }
            }
        }
    }

    /// N4 law 3 — **rule order carries no authority.** Rules compose as a
    /// conjunction, so a rotation of the rule list must produce the same outcome
    /// with the same floor and the same predicate set. If order mattered, a
    /// policy would have first-match/else precedence, and a rule placed late
    /// could be shadowed — the classic way an allow-list turns into a bypass.
    #[test]
    fn policy_rule_order_never_changes_the_outcome(
        scenario in scenario_strategy(),
        seeds in prop::collection::vec(rule_seed_strategy(), 1..6),
        rotation in 0usize..6,
    ) {
        let rules = rules_from_seeds(&seeds, "r");
        let mut rotated = rules.clone();
        let len = rotated.len();
        rotated.rotate_left(rotation % len);

        let base = Classifier::default().classify(&scenario.sql);
        let declared = policy_of(rules).evaluate(&base, &scenario.context);
        let permuted = policy_of(rotated).evaluate(&base, &scenario.context);

        match (declared, permuted) {
            (PolicyTightening::Deny(_), PolicyTightening::Deny(_)) => {}
            (PolicyTightening::Narrow(declared), PolicyTightening::Narrow(permuted)) => {
                prop_assert_eq!(
                    declared.required_level, permuted.required_level,
                    "RULE ORDER CHANGED THE FLOOR: {:?} vs {:?}", declared, permuted,
                );
                prop_assert_eq!(
                    predicate_fingerprint(&declared), predicate_fingerprint(&permuted),
                    "RULE ORDER CHANGED THE PREDICATE SET",
                );
                prop_assert_eq!(
                    sorted_ids(&declared), sorted_ids(&permuted),
                    "RULE ORDER CHANGED WHICH RULES MATCHED",
                );
            }
            (declared, permuted) => {
                prop_assert!(
                    false,
                    "RULE ORDER FLIPPED DENY/NARROW: declared={declared:?}, permuted={permuted:?}",
                );
            }
        }
    }

    /// N4 law 4 — **a policy is never a grant.** With no rules at all the result
    /// is the identity narrowing: the base level, no predicates, no matched
    /// rules. Composition therefore has no "allow" element, and an operator
    /// cannot widen the classifier by writing a policy file.
    #[test]
    fn empty_policy_is_the_identity_and_grants_nothing(scenario in scenario_strategy()) {
        let base = Classifier::default().classify(&scenario.sql);

        match policy_of(Vec::new()).evaluate(&base, &scenario.context) {
            PolicyTightening::Deny(_) => {
                prop_assert!(
                    base.danger == DangerLevel::Forbidden || base.required_level.is_none(),
                    "AN EMPTY POLICY DENIED AN ADMITTED STATEMENT: {base:?}",
                );
            }
            PolicyTightening::Narrow(narrowing) => {
                let base_level = base.required_level.expect("a narrowed base carries a level");
                prop_assert!(
                    narrowing.is_identity(),
                    "AN EMPTY POLICY ADDED A CONSTRAINT: {narrowing:?}",
                );
                prop_assert_eq!(narrowing.required_level, base_level);
            }
        }
    }

    /// N4 law 5 — **no policy can unlock a refusal.** Whatever the rules say, a
    /// statement the classifier forbade stays refused, and the refusal is
    /// attributed to the classifier rather than to a rule. The policy engine sits
    /// behind the guard, never in front of it.
    #[test]
    fn no_policy_can_unlock_a_forbidden_statement(
        sql in prop::sample::select(&FORBIDDEN_STATEMENTS[..]),
        seeds in rule_seeds_strategy(6),
        verb in verb_strategy(),
        principal in prop::option::of(prop::sample::select(&POLICY_PRINCIPALS[..])),
    ) {
        let base = Classifier::default().classify(sql);
        prop_assert_eq!(
            base.danger, DangerLevel::Forbidden,
            "corpus statement must stay forbidden for this law to mean anything: {}", sql,
        );

        let policy = policy_of(rules_from_seeds(&seeds, "r"));
        let context = SqlPolicyEvaluationContext::new(
            Some("APP".to_owned()),
            Some("ORDERS".to_owned()),
            verb,
            principal.map(str::to_owned),
        );

        match policy.evaluate(&base, &context) {
            PolicyTightening::Deny(denial) => prop_assert_eq!(
                denial.reason, PolicyDenialReason::BaseClassifierRefused,
                "a forbidden base must be refused by the classifier, not by a rule",
            ),
            PolicyTightening::Narrow(narrowing) => prop_assert!(
                false,
                "POLICY UNLOCKED A FORBIDDEN STATEMENT: {narrowing:?}, policy={policy:?}",
            ),
        }
    }

    /// N4 law 6 — **the predicate rewrite never loosens either (SEC-1).** The
    /// N3 stage rewrites the AST and re-classifies the candidate. A surviving
    /// candidate must be at least as dangerous and at least as privileged as the
    /// original, must still carry the filter it was rewritten to add, and a
    /// read-only base must stay read-only. Anything else is denied, so a policy
    /// predicate can never launder a statement into a weaker verdict.
    #[test]
    fn predicate_rewrite_never_loosens_the_reclassified_candidate(
        schema in prop::sample::select(&POLICY_SCHEMAS[..]),
        object in prop::sample::select(&POLICY_OBJECTS[..]),
        kind in prop::sample::select(&ROW_FILTER_KINDS[..]),
        fragment in prop::sample::select(&POLICY_PREDICATES[..]),
        floor in prop::option::of(prop::sample::select(&POLICY_LEVELS[..])),
    ) {
        let classifier = Classifier::default();
        let scenario = policy_scenario(schema, object, kind, Some(POLICY_PRINCIPALS[0]));
        let verb = scenario.context.verb;

        let mut rules = vec![SqlPolicyRuleConfig {
            id: "predicate".to_owned(),
            match_clause: SqlPolicyMatchConfig {
                schema: Some(schema.to_owned()),
                object: Some(object.to_owned()),
                verb: Some(verb),
                principal: None,
            },
            effect: SqlPolicyEffectConfig::RequirePredicate { sql_fragment: fragment.to_owned() },
        }];
        if let Some(level) = floor {
            rules.push(SqlPolicyRuleConfig {
                id: "floor".to_owned(),
                match_clause: SqlPolicyMatchConfig::default(),
                effect: SqlPolicyEffectConfig::RequireLevel { level },
            });
        }
        let policy = policy_of(rules);
        prop_assert!(policy.validate().is_ok(), "generator emitted an unloadable policy: {policy:?}");

        let base = classifier.classify(&scenario.sql);
        let PolicyTightening::Narrow(narrowing) = policy.evaluate(&base, &scenario.context) else {
            // A refusal is tighter than any rewrite; there is nothing to rewrite.
            return Ok(());
        };
        let base_level = base.required_level.expect("a narrowed base carries a level");

        match rewrite_predicates_and_reclassify(
            &classifier,
            &base,
            &scenario.sql,
            &scenario.context,
            &narrowing,
        ) {
            // Fail-closed: an unrewritable shape is refused, never passed through.
            PolicyPredicateRewrite::Deny(_) => {}
            PolicyPredicateRewrite::Reclassified(statement) => {
                prop_assert!(
                    statement.final_danger >= base.danger,
                    "REWRITE LOWERED DANGER: base={base:?}, statement={statement:?}",
                );
                prop_assert_ne!(
                    statement.candidate.danger, DangerLevel::Forbidden,
                    "a forbidden candidate must be denied, not returned",
                );
                prop_assert!(
                    statement.final_required_level >= base_level
                        && statement.final_required_level >= narrowing.required_level,
                    "REWRITE LOWERED THE LEVEL: base={base_level:?}, floor={:?}, statement={statement:?}",
                    narrowing.required_level,
                );
                if base_level == OperatingLevel::ReadOnly {
                    prop_assert_eq!(
                        statement.candidate.required_level, Some(OperatingLevel::ReadOnly),
                        "a read-only base must never be rewritten into a writing candidate: {:?}", statement,
                    );
                }
                // The whole point of the rewrite is the added filter. If it were
                // silently dropped, the candidate would be wider than the policy.
                let column = fragment
                    .split_whitespace()
                    .next()
                    .expect("a predicate fragment starts with a column");
                prop_assert!(
                    statement.sql.to_ascii_lowercase().contains(column),
                    "REWRITE DROPPED THE POLICY FILTER `{column}`: {}", statement.sql,
                );
            }
        }
    }
}
