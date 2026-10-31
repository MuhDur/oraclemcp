//! Read-shape fallback (pvlqq.10.18): the served engine's ANTLR read shape,
//! rendered as analysis SQL, must describe a statement exactly as sqlparser
//! does wherever sqlparser can parse it (differential parity), must give the
//! Oracle reads sqlparser rejects a complete read plan, and must refuse
//! every non-read or unrepresentable statement.
#![cfg(feature = "plsql-intelligence")]

use std::sync::Arc;

use oraclemcp::read_shape_oracle::EngineReadShapeOracle;
use oraclemcp_guard::classifier::{Classifier, ClassifierConfig, semantic_read_plan_checked};
use oraclemcp_guard::levels::OperatingLevel;
use oraclemcp_guard::semantic_read_plan_checked_with_shape;
use oraclemcp_guard::shape_oracle::{StatementShapeOracle, analysis_sql, fallback_read_statement};

/// Ordinary reads sqlparser parses: the parity corpus beside the W1 bypass
/// corpus.
const PARITY_READS: &[&str] = &[
    "SELECT ID, NAME FROM APP.ORDERS",
    "SELECT o.ID, o.NAME AS N FROM APP.ORDERS o WHERE o.ID = 1 ORDER BY N",
    "SELECT ID FROM APP.ORDERS o JOIN APP.ITEMS i ON i.ORDER_ID = o.ID",
    "SELECT o.ID FROM APP.ORDERS o LEFT JOIN APP.ITEMS i ON i.ORDER_ID = o.ID WHERE i.ID IS NULL",
    "SELECT ID FROM APP.ORDERS o JOIN APP.ORDERS p USING (ID)",
    "SELECT ID FROM APP.ORDERS o NATURAL JOIN APP.ORDERS p",
    "SELECT COUNT(*) FROM APP.ORDERS",
    "SELECT STATUS, COUNT(*) AS C FROM APP.ORDERS GROUP BY STATUS HAVING COUNT(*) > 1",
    "SELECT ID FROM APP.ORDERS WHERE ID IN (SELECT ORDER_ID FROM APP.ITEMS)",
    "SELECT ID FROM APP.ORDERS o WHERE EXISTS (SELECT 1 FROM APP.ITEMS i WHERE i.ORDER_ID = o.ID)",
    "SELECT ID, (SELECT MAX(QTY) FROM APP.ITEMS i WHERE i.ORDER_ID = o.ID) AS M FROM APP.ORDERS o",
    "WITH c AS (SELECT ID FROM APP.ORDERS) SELECT c.ID FROM c",
    "SELECT ID FROM APP.ORDERS UNION ALL SELECT ORDER_ID FROM APP.ITEMS",
    "SELECT x.ID FROM (SELECT ID FROM APP.ORDERS) x",
    "SELECT SUM(QTY) OVER (PARTITION BY ORDER_ID ORDER BY ID) AS S FROM APP.ITEMS",
    "SELECT UPPER(NAME), NVL(NAME, 'x'), SYSDATE FROM APP.ORDERS",
    "SELECT ID FROM APP.ORDERS WHERE NAME LIKE 'A%' AND ID BETWEEN 1 AND 9",
    "SELECT CASE WHEN ID > 1 THEN 'x' ELSE 'y' END AS K FROM APP.ORDERS",
    "SELECT ID, LEVEL FROM APP.ORDERS START WITH PARENT_ID IS NULL CONNECT BY PRIOR ID = PARENT_ID",
    "SELECT APP.PRICE_OF(ID) FROM APP.ORDERS",
    "SELECT o.* FROM APP.ORDERS o",
    "SELECT DISTINCT STATUS FROM APP.ORDERS",
    "SELECT ID FROM APP.ORDERS e, APP.ITEMS d WHERE e.ID = d.ORDER_ID(+)",
    "SELECT ID FROM APP.ORDERS ORDER BY ID FETCH FIRST 5 ROWS ONLY",
    "SELECT \"Mixed\".ID FROM APP.\"Mixed\"",
];

/// Oracle reads sqlparser 0.63 rejects, with the base relation each must
/// plan.
const FALLBACK_READS: &[(&str, &str)] = &[
    ("SELECT * FROM APP.ORDERS AS OF SCN 12345", "ORDERS"),
    (
        "SELECT ID FROM APP.ORDERS AS OF TIMESTAMP SYSTIMESTAMP - INTERVAL '1' HOUR o",
        "ORDERS",
    ),
    (
        "SELECT ID FROM APP.ORDERS VERSIONS BETWEEN SCN MINVALUE AND MAXVALUE",
        "ORDERS",
    ),
    (
        "SELECT MAX(QTY) KEEP (DENSE_RANK FIRST ORDER BY ID) FROM APP.ITEMS",
        "ITEMS",
    ),
    (
        "SELECT JSON_VALUE(NAME, '$.a' RETURNING NUMBER DEFAULT 0 ON ERROR) FROM APP.ORDERS",
        "ORDERS",
    ),
    (
        "SELECT TO_NUMBER(NAME DEFAULT 0 ON CONVERSION ERROR) FROM APP.ORDERS",
        "ORDERS",
    ),
    (
        "SELECT VALIDATE_CONVERSION(NAME AS NUMBER) FROM APP.ORDERS",
        "ORDERS",
    ),
    ("SELECT * FROM APP.ORDERS PARTITION (P1)", "ORDERS"),
    (
        "SELECT * FROM APP.ORDERS PARTITION FOR (DATE '2024-01-01')",
        "ORDERS",
    ),
    (
        "SELECT o.ID FROM APP.ORDERS o PARTITION BY (o.STATUS) RIGHT OUTER JOIN APP.ITEMS i ON i.ORDER_ID = o.ID",
        "ITEMS",
    ),
];

/// Statements the fallback must never admit.
const FALLBACK_REFUSED: &[&str] = &[
    "SELECT * FROM APP.ORDERS FOR UPDATE",
    "SELECT * FROM APP.ORDERS AS OF SCN 1 FOR UPDATE",
    "SELECT ID INTO v FROM APP.ORDERS",
    "WITH FUNCTION f RETURN NUMBER IS BEGIN RETURN 1; END; SELECT f FROM dual",
    "SELECT CURSOR(SELECT * FROM APP.ITEMS) FROM dual",
    "SELECT * FROM APP.ORDERS MODEL DIMENSION BY (ID) MEASURES (QTY) RULES (QTY[1] = 0)",
    "SELECT * FROM APP.ORDERS@remote",
    "INSERT INTO APP.ORDERS VALUES (1)",
    "UPDATE APP.ORDERS SET NAME = 'x'",
    "DELETE FROM APP.ORDERS",
    "MERGE INTO APP.ORDERS o USING APP.ITEMS i ON (o.ID = i.ID) WHEN MATCHED THEN UPDATE SET NAME = 'x'",
    "BEGIN NULL; END;",
    "CALL APP.P()",
    "SELECT 1 FROM dual; DELETE FROM APP.ORDERS",
    "SELECT * FROM APP.ORDERS AS OF SCN",
    "garbage ((",
];

fn bypass_corpus() -> Vec<String> {
    include_str!("../../../tests/golden/guard/bypass_corpus.jsonl")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let case: serde_json::Value = serde_json::from_str(line).expect("corpus JSON");
            case["sql"].as_str().expect("corpus sql").to_string()
        })
        .collect()
}

#[test]
fn read_shape_fallback_matches_sqlparser_wherever_sqlparser_parses() {
    let oracle = EngineReadShapeOracle;
    // The served classification policy, and the engine-free baseline where a
    // plain read classifies ReadOnly, so a verdict-changing rendering shows.
    let classifiers = [
        Classifier::new(ClassifierConfig::served_strict()),
        Classifier::engine_free_baseline(ClassifierConfig::new()),
    ];
    let mut corpus: Vec<String> = PARITY_READS.iter().map(ToString::to_string).collect();
    corpus.extend(bypass_corpus());
    let (mut compared, mut engine_refused, mut planned_equal) = (0usize, 0usize, 0usize);
    let mut over_refused = Vec::new();
    for sql in &corpus {
        let original_plan = semantic_read_plan_checked(sql);
        let Some(shape) = oracle.read_shape(sql) else {
            engine_refused += 1;
            continue;
        };
        let Some(analysis) = analysis_sql(&shape) else {
            engine_refused += 1;
            continue;
        };
        compared += 1;
        let analysis_plan = semantic_read_plan_checked(&analysis);
        match (&original_plan, &analysis_plan) {
            (Ok(original), Ok(rendered)) => {
                assert_eq!(
                    rendered, original,
                    "plan parity\n  sql: {sql}\n  analysis: {analysis}"
                );
                planned_equal += 1;
            }
            (Err(_), Ok(_)) => panic!(
                "fallback planned what sqlparser refuses\n  sql: {sql}\n  analysis: {analysis}"
            ),
            (Ok(_), Err(error)) => over_refused.push(format!("{sql} -> {error:?}")),
            (Err(_), Err(_)) => {}
        }
        for classifier in &classifiers {
            let original_decision = classifier.classify(sql);
            let analysis_decision = classifier.classify(&analysis);
            assert_eq!(
                (
                    analysis_decision.danger,
                    analysis_decision.required_level,
                    &analysis_decision.objects_affected
                ),
                (
                    original_decision.danger,
                    original_decision.required_level,
                    &original_decision.objects_affected
                ),
                "decision parity\n  sql: {sql}\n  analysis: {analysis}"
            );
        }
    }
    eprintln!(
        "read-shape parity: corpus={} compared={compared} plans_equal={planned_equal} \
         engine_refused={engine_refused} over_refused={}",
        corpus.len(),
        over_refused.len()
    );
    assert!(
        over_refused.is_empty(),
        "the analysis SQL lost a plan sqlparser had:\n{}",
        over_refused.join("\n")
    );
    // Denominator: every ordinary read must be compared, not skipped.
    assert!(
        compared >= PARITY_READS.len(),
        "only {compared} statements compared"
    );
}

#[test]
fn read_shape_fallback_plans_oracle_reads_sqlparser_rejects() {
    let oracle = EngineReadShapeOracle;
    for (sql, relation) in FALLBACK_READS {
        assert!(
            semantic_read_plan_checked(sql).is_err(),
            "sqlparser must not already plan {sql}"
        );
        let shape = oracle
            .read_shape(sql)
            .unwrap_or_else(|| panic!("no read shape for {sql}"));
        let analysis = analysis_sql(&shape).unwrap_or_else(|| panic!("no analysis SQL for {sql}"));
        let plan = semantic_read_plan_checked(&analysis)
            .unwrap_or_else(|error| panic!("{sql}\n  analysis: {analysis}\n  {error:?}"));
        assert!(
            plan.relations.iter().any(|name| name
                .parts
                .last()
                .is_some_and(|part| part.text.eq_ignore_ascii_case(relation))),
            "{sql}: relations {:?}",
            plan.relations
        );
        assert!(fallback_read_statement(sql, &oracle).is_some(), "{sql}");
        // The read path's entry point plans the statement itself through the
        // oracle, and refuses it without one.
        assert_eq!(
            semantic_read_plan_checked_with_shape(sql, Some(&oracle)).as_ref(),
            Ok(&plan),
            "{sql}"
        );
        assert!(
            semantic_read_plan_checked_with_shape(sql, None).is_err(),
            "{sql}"
        );
    }
}

#[test]
fn read_shape_fallback_refuses_non_reads_and_unrepresentable_shapes() {
    let oracle = EngineReadShapeOracle;
    for sql in FALLBACK_REFUSED {
        assert!(
            fallback_read_statement(sql, &oracle).is_none(),
            "fallback must refuse {sql}"
        );
    }
}

#[test]
fn read_shape_fallback_classifier_hook_admits_only_with_the_oracle() {
    let with_shape = Classifier::engine_free_baseline(ClassifierConfig::new())
        .with_shape_oracle(Arc::new(EngineReadShapeOracle));
    let without_shape = Classifier::engine_free_baseline(ClassifierConfig::new());
    let mut read_only = Vec::new();
    for (sql, _) in FALLBACK_READS {
        let analysis = analysis_sql(&EngineReadShapeOracle.read_shape(sql).expect("shape"))
            .expect("analysis SQL");
        let hooked = with_shape.classify(sql);
        let direct = without_shape.classify(&analysis);
        // The hook classifies exactly what the analysis SQL is.
        assert_eq!(
            (
                hooked.danger,
                hooked.required_level,
                &hooked.objects_affected
            ),
            (
                direct.danger,
                direct.required_level,
                &direct.objects_affected
            ),
            "hook fidelity\n  sql: {sql}\n  analysis: {analysis}"
        );
        assert_eq!(
            without_shape.classify(sql).required_level,
            Some(OperatingLevel::ReadWrite),
            "without the oracle the parse failure keeps today's refusal: {sql}"
        );
        if hooked.required_level == Some(OperatingLevel::ReadOnly) {
            read_only.push(*sql);
        }
    }
    // Reads that call only the classifier's listed built-ins classify ReadOnly.
    // JSON_VALUE and VALIDATE_CONVERSION are not on that list, so they stay
    // Guarded here exactly as they would if sqlparser had parsed them.
    let expected: Vec<&str> = FALLBACK_READS
        .iter()
        .map(|(sql, _)| *sql)
        .filter(|sql| !sql.contains("JSON_VALUE") && !sql.contains("VALIDATE_CONVERSION"))
        .collect();
    assert_eq!(read_only, expected);
    // Tighten-only: binding the oracle never changes the verdict of a
    // statement the fallback must refuse.
    for sql in FALLBACK_REFUSED {
        let hooked = with_shape.classify(sql);
        let unhooked = without_shape.classify(sql);
        assert_eq!(
            (
                hooked.danger,
                hooked.required_level,
                &hooked.objects_affected
            ),
            (
                unhooked.danger,
                unhooked.required_level,
                &unhooked.objects_affected
            ),
            "{sql}"
        );
    }
}

#[test]
fn read_shape_fallback_survives_adversarial_nesting() {
    // Without the nesting budget and dedicated stack this aborts the whole
    // test process with a stack overflow.
    let deep = format!(
        "SELECT {}1{} FROM APP.ORDERS AS OF SCN 1",
        "(".repeat(10_000),
        ")".repeat(10_000)
    );
    assert!(EngineReadShapeOracle.read_shape(&deep).is_none());
    let classifier = Classifier::engine_free_baseline(ClassifierConfig::new())
        .with_shape_oracle(Arc::new(EngineReadShapeOracle));
    assert_ne!(
        classifier.classify(&deep).required_level,
        Some(OperatingLevel::ReadOnly)
    );
    // Within the budget, a nested fallback read still shapes on the
    // oracle's own stack, from a caller on a small thread stack.
    let nested = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(|| {
            let mut sql = "SELECT ID FROM APP.ORDERS AS OF SCN 1".to_string();
            for _ in 0..8 {
                sql = format!("SELECT x.ID FROM ({sql}) x");
            }
            EngineReadShapeOracle.read_shape(&sql).is_some()
        })
        .unwrap()
        .join()
        .unwrap();
    assert!(nested);
}
