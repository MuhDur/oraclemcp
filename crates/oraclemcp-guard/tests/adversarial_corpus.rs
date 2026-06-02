//! The classifier differential adversarial corpus (plan §5.3, §12; bead
//! T-CORPUS / oracle-qmwz.6.2). A standing artifact: every entry is a statement
//! the fail-closed classifier MUST classify at least as strictly as its
//! `min_danger`. The corpus encodes the documented attack vectors —
//! comment-hidden DML, CTE-wrapped reads, MERGE, side-effecting function calls
//! in a SELECT, `q'[…]'` / literal `;` desync, EXPLAIN PLAN, multi-statement
//! batches — and asserts the classifier never *under*-classifies them.
//!
//! Pairs with the `fuzz/` cargo-fuzz target (never-panic + fail-closed on
//! arbitrary input) and the never-panic test below (runs in stable CI).

use oraclemcp_guard::{Classifier, DangerLevel};

/// `(sql, minimum danger the classifier must assign)`.
const CORPUS: &[(&str, DangerLevel)] = &[
    // --- Reads that must stay Safe (no false positives that would block work) ---
    (
        "SELECT id, name FROM employees WHERE dept = 10",
        DangerLevel::Safe,
    ),
    (
        "WITH d AS (SELECT * FROM dept) SELECT * FROM d",
        DangerLevel::Safe,
    ),
    ("SELECT COUNT(*), MAX(sal) FROM emp", DangerLevel::Safe),
    // A q-quoted literal containing DROP/;/END is data, not a statement: stays a
    // single Safe SELECT — the splitter must not invent a phantom boundary.
    (
        "SELECT q'{ ; DROP TABLE t; END; }' AS payload FROM dual",
        DangerLevel::Safe,
    ),
    ("SELECT 'a;b;c' FROM dual", DangerLevel::Safe),
    // --- The headline fail-open: a UDF in a SELECT may DML -> must be Guarded ---
    (
        "SELECT billing.purge_old_rows() FROM dual",
        DangerLevel::Guarded,
    ),
    (
        "SELECT id, app.recalc(id) FROM orders",
        DangerLevel::Guarded,
    ),
    // A UDF whose name collides with a non-reserved keyword (oracle-ajm2.1) must
    // not fail-open: it is still a side-effect-capable routine call -> Guarded.
    ("SELECT billing.purge() FROM dual", DangerLevel::Guarded),
    ("SELECT app.merge(x) FROM dual", DangerLevel::Guarded),
    ("SELECT app.comment() FROM dual", DangerLevel::Guarded),
    ("SELECT app.refresh() FROM dual", DangerLevel::Guarded),
    // SELECT ... FOR UPDATE locks rows + holds a txn open (oracle-ajm2.6).
    ("SELECT * FROM t FOR UPDATE", DangerLevel::Guarded),
    (
        "SELECT * FROM t WHERE id = 1 FOR UPDATE OF status NOWAIT",
        DangerLevel::Guarded,
    ),
    // --- DML ---
    (
        "INSERT INTO audit_log (msg) VALUES ('x')",
        DangerLevel::Guarded,
    ),
    (
        "UPDATE orders SET status = 'X' WHERE id = 1",
        DangerLevel::Guarded,
    ),
    (
        "MERGE INTO t USING s ON (t.id = s.id) WHEN MATCHED THEN UPDATE SET t.v = s.v",
        DangerLevel::Guarded,
    ),
    // No-WHERE DML is Destructive (whole-table blast radius).
    ("DELETE FROM orders", DangerLevel::Destructive),
    ("UPDATE orders SET status = 'X'", DangerLevel::Destructive),
    // --- DDL / DCL ---
    ("DROP TABLE orders", DangerLevel::Destructive),
    ("TRUNCATE TABLE orders", DangerLevel::Destructive),
    ("GRANT SELECT ON orders TO scott", DangerLevel::Destructive),
    // --- EXPLAIN PLAN writes PLAN_TABLE: Guarded, never Safe ---
    (
        "EXPLAIN PLAN FOR SELECT * FROM employees",
        DangerLevel::Guarded,
    ),
    // --- PL/SQL blocks: at least Guarded; dynamic/file/network -> Forbidden ---
    (
        "BEGIN UPDATE t SET x = 1 WHERE id = 2; END;",
        DangerLevel::Guarded,
    ),
    ("DECLARE n NUMBER; BEGIN n := 1; END;", DangerLevel::Guarded),
    (
        "BEGIN EXECUTE IMMEDIATE 'DELETE FROM orders'; END;",
        DangerLevel::Forbidden,
    ),
    (
        "BEGIN UTL_FILE.FOPEN('D','f','w'); END;",
        DangerLevel::Forbidden,
    ),
    (
        "DECLARE PRAGMA AUTONOMOUS_TRANSACTION; BEGIN COMMIT; END;",
        DangerLevel::Forbidden,
    ),
    // oracle-rwjl.1: a comment / extra space / tab / newline wedged between the
    // two keywords of a multi-word marker must NOT split it and downgrade the
    // Forbidden block to Guarded — the Stage A scan canonicalizes first.
    (
        "BEGIN EXECUTE/**/IMMEDIATE 'DELETE FROM orders'; END;",
        DangerLevel::Forbidden,
    ),
    (
        "BEGIN EXECUTE  IMMEDIATE 'DELETE FROM orders'; END;",
        DangerLevel::Forbidden,
    ),
    (
        "BEGIN EXECUTE\tIMMEDIATE 'DELETE FROM orders'; END;",
        DangerLevel::Forbidden,
    ),
    (
        "BEGIN EXECUTE\nIMMEDIATE 'DELETE FROM orders'; END;",
        DangerLevel::Forbidden,
    ),
    (
        "DECLARE PRAGMA/**/AUTONOMOUS_TRANSACTION; BEGIN COMMIT; END;",
        DangerLevel::Forbidden,
    ),
    (
        "DECLARE PRAGMA\tAUTONOMOUS_TRANSACTION; BEGIN COMMIT; END;",
        DangerLevel::Forbidden,
    ),
    // --- Multi-statement: the batch takes the max danger ---
    (
        "SELECT 1 FROM dual; DROP TABLE orders",
        DangerLevel::Destructive,
    ),
    (
        "SELECT 1 FROM dual; UPDATE t SET x = 1",
        DangerLevel::Destructive,
    ),
    // --- Desync: an unterminated block must be Forbidden, never best-effort ---
    ("DECLARE x NUMBER; BEGIN x := 1;", DangerLevel::Forbidden),
];

#[test]
fn corpus_is_never_underclassified() {
    let classifier = Classifier::default();
    let mut failures = Vec::new();
    for (sql, min_danger) in CORPUS {
        let decision = classifier.classify(sql);
        if decision.danger < *min_danger {
            failures.push(format!(
                "UNDER-CLASSIFIED: {sql:?} got {:?}, expected >= {min_danger:?}",
                decision.danger
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "fail-closed violations:\n{}",
        failures.join("\n")
    );
}

#[test]
fn classifier_never_panics_on_arbitrary_input() {
    // A stable-CI stand-in for the cargo-fuzz target: feed adversarial / garbage
    // inputs and assert the classifier returns a decision rather than panicking,
    // and that nothing garbage is ever cleared to Safe incorrectly.
    let classifier = Classifier::default();
    let garbage = [
        "",
        " ",
        ";",
        ";;;;",
        "'unterminated",
        "q'[unterminated",
        "BEGIN BEGIN BEGIN",
        "END END END",
        "SELECT \0 FROM \u{1}",
        "ＳＥＬＥＣＴ", // fullwidth
        "/* comment only */",
        "SELECT * FROM t WHERE x = q'!a;b!'",
        &"(".repeat(500),
        &"BEGIN ".repeat(200),
        "DROP/**/TABLE/**/t",
        "sElEcT pkg.f() FrOm DuAl",
    ];
    for input in garbage {
        // Must not panic.
        let decision = classifier.classify(input);
        // Anything non-trivial that survived to here must not be wrongly Safe
        // unless it is genuinely an empty/whitespace/pure-read input.
        let trivially_safe = input.trim().is_empty()
            || input.trim() == "/* comment only */"
            || input
                .trim_start()
                .to_ascii_uppercase()
                .starts_with("SELECT");
        if decision.danger == DangerLevel::Safe {
            assert!(
                trivially_safe,
                "garbage cleared to Safe: {input:?} -> {decision:?}"
            );
        }
    }
}

#[test]
fn dangerous_markers_are_forbidden_anywhere_in_a_block() {
    let classifier = Classifier::default();
    for marker in [
        "EXECUTE IMMEDIATE 'x'",
        "DBMS_SQL.PARSE(c, s, 1)",
        "UTL_HTTP.REQUEST('http://x')",
        "DBMS_SCHEDULER.CREATE_JOB('j')",
    ] {
        let sql = format!("BEGIN {marker}; END;");
        assert_eq!(
            classifier.classify(&sql).danger,
            DangerLevel::Forbidden,
            "marker not Forbidden: {sql:?}"
        );
    }
}
