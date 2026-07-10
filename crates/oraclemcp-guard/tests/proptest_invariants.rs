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
//! Small case counts keep CI fast; the standing adversarial corpus + cargo-fuzz
//! target cover the example-level and never-panic dimensions.

use oraclemcp_guard::{Classifier, DangerLevel, is_allowed_alter_session};
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
}
