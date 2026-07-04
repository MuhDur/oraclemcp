//! Adversarial corpus for CTE-smuggled DML and related write-under-read shapes
//! (Pass-1 bug-hunt over `set_expr_carries_dml`, 2026-07). Every entry carries a
//! top-level write; the fail-closed classifier MUST NOT tier any of them
//! `Safe`/`ReadOnly`. A survivor that classifies `Safe` is a P0 (a READ_ONLY
//! session would be `allow`ed to run a write). The `min_danger` is the *minimum*
//! the classifier must assign — over-classification is acceptable, under is not.
//!
//! Pairs with `adversarial_corpus.rs`; this file concentrates the CTE-DML body
//! nesting that sqlparser 0.62 folds into `Statement::Query { body: SetExpr::… }`.

use oraclemcp_guard::{Classifier, DangerLevel};

/// `(sql, minimum danger the classifier must assign)`.
const CTE_DML_CORPUS: &[(&str, DangerLevel)] = &[
    // --- Controls: genuine reads that must stay Safe (no false positives) ---
    (
        "WITH a AS (SELECT 1 FROM dual) SELECT * FROM a",
        DangerLevel::Safe,
    ),
    (
        "WITH a AS (WITH b AS (SELECT 1 FROM dual) SELECT * FROM b) SELECT * FROM a",
        DangerLevel::Safe,
    ),
    (
        "WITH a AS (SELECT 1 FROM dual) SELECT * FROM dual UNION ALL SELECT * FROM a",
        DangerLevel::Safe,
    ),
    // --- CTE + DML body (the headline smuggle): must be a write ---
    (
        "WITH a AS (SELECT 1 FROM dual) UPDATE t SET x = 1 WHERE id = 2",
        DangerLevel::Guarded,
    ),
    (
        "WITH a AS (SELECT 1 FROM dual) DELETE FROM t WHERE id = 2",
        DangerLevel::Guarded,
    ),
    (
        "WITH a AS (SELECT 1 FROM dual) INSERT INTO t VALUES (1)",
        DangerLevel::Guarded,
    ),
    (
        "WITH a AS (SELECT 1 FROM dual) MERGE INTO t USING s ON (t.id = s.id) \
         WHEN MATCHED THEN UPDATE SET t.v = s.v",
        DangerLevel::Guarded,
    ),
    // --- WITH inside WITH, then a DML body (nested CTE) ---
    (
        "WITH a AS (WITH b AS (SELECT 1 FROM dual) SELECT * FROM b) \
         UPDATE t SET x = 1 WHERE id = 2",
        DangerLevel::Guarded,
    ),
    (
        "WITH a AS (WITH b AS (SELECT 1 FROM dual) SELECT * FROM b) \
         DELETE FROM t WHERE id = 2",
        DangerLevel::Guarded,
    ),
    // --- No-WHERE DML smuggled under a CTE: whole-table blast radius ---
    (
        "WITH a AS (SELECT 1 FROM dual) DELETE FROM t",
        DangerLevel::Guarded,
    ),
    (
        "WITH a AS (SELECT 1 FROM dual) UPDATE t SET x = 1",
        DangerLevel::Guarded,
    ),
    // --- INSERT ALL (multi-table conditional insert) ---
    (
        "INSERT ALL INTO t1 VALUES (1) INTO t2 VALUES (2) SELECT * FROM dual",
        DangerLevel::Guarded,
    ),
    (
        "INSERT FIRST WHEN x > 0 THEN INTO t1 VALUES (x) ELSE INTO t2 VALUES (x) \
         SELECT x FROM src",
        DangerLevel::Guarded,
    ),
    // --- DELETE / UPDATE against an inline view (subquery target) ---
    (
        "DELETE FROM (SELECT * FROM t) WHERE id = 1",
        DangerLevel::Guarded,
    ),
    (
        "UPDATE (SELECT x FROM t WHERE id = 1) SET x = 2",
        DangerLevel::Guarded,
    ),
    // --- CTE feeding an INSERT source (leading keyword governs) ---
    (
        "INSERT INTO t WITH c AS (SELECT 1 FROM dual) SELECT * FROM c",
        DangerLevel::Guarded,
    ),
    // --- Set operation whose one arm is a DML body ---
    (
        "WITH a AS (SELECT 1 FROM dual) SELECT * FROM a UNION ALL UPDATE t SET x = 1",
        DangerLevel::Guarded,
    ),
];

#[test]
fn cte_dml_bodies_are_never_cleared_to_safe() {
    let classifier = Classifier::default();
    let mut failures = Vec::new();
    for (sql, min_danger) in CTE_DML_CORPUS {
        let decision = classifier.classify(sql);
        // Fail-closed direction: a write smuggled under a CTE must never
        // under-classify to `Safe`/`ReadOnly`.
        if decision.danger < *min_danger {
            failures.push(format!(
                "UNDER-CLASSIFIED: {sql:?} got {:?}, expected >= {min_danger:?}",
                decision.danger
            ));
        }
        // No-false-positive direction: a genuine read control (min == Safe) must
        // stay exactly Safe so the tightening does not block legitimate reads.
        if *min_danger == DangerLevel::Safe && decision.danger != DangerLevel::Safe {
            failures.push(format!(
                "OVER-CLASSIFIED read control: {sql:?} got {:?}, expected Safe",
                decision.danger
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "CTE-DML classifier violations:\n{}",
        failures.join("\n")
    );
}
