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

use oraclemcp_guard::{Classifier, ClassifierConfig, DangerLevel};

/// Served/strict-mode corpus (beads .82 + .102). Each entry is a statement the
/// **served/strict** classifier — the fail-closed posture of the raw-query gate
/// — MUST classify at least as strictly as `min_danger`. These are the live
/// fail-opens the default (permissive) classifier still admits as `Safe`:
///
/// - **.102** a paren-less function invocation — Oracle runs a zero-arg function
///   with no `()`, so `SELECT app_admin.run_ddl FROM dual` *calls* `run_ddl`, but
///   the `ident(`-only UDF scan reads it as a column reference.
/// - **.82**  a read whose base object hides side effects (a view/policy function
///   doing autonomous committed writes) — unprovable without a live catalog, so
///   the strict posture refuses every unproven base-object read.
const STRICT_CORPUS: &[(&str, DangerLevel)] = &[
    // .102 — paren-less qualified callables (value position, root not in scope).
    ("SELECT app_admin.run_ddl FROM dual", DangerLevel::Guarded),
    (
        "SELECT id, app_admin.run_ddl FROM orders",
        DangerLevel::Guarded,
    ),
    ("SELECT app.pkg.side_effect FROM dual", DangerLevel::Guarded),
    ("SELECT s.nextval FROM dual", DangerLevel::Guarded),
    (
        "SELECT id FROM orders WHERE audit_pkg.record = 1",
        DangerLevel::Guarded,
    ),
    // .82 — an unproven base-object read (the default UnknownOracle proves
    // nothing, so the strict posture cannot clear it to Safe).
    ("SELECT * FROM reporting_view", DangerLevel::Guarded),
    (
        "SELECT id, name FROM some_schema.some_view",
        DangerLevel::Guarded,
    ),
];

/// Reads that MUST stay `Safe` even under served/strict `.102` guarding — a
/// genuine in-scope column reference is not a callable. (These use the `.102`
/// guard alone, without the aggressive `.82` statement-Unknown tightening, so
/// legitimate reads stay usable.) Prevents the tightening from destroying normal
/// qualified column references.
const STRICT_FALSE_POSITIVE_GUARD: &[&str] = &[
    "SELECT e.name, e.id FROM employees e",
    "SELECT e.name FROM employees e JOIN dept d ON e.dept = d.id",
    "SELECT hr.employees.salary FROM hr.employees",
    "WITH x AS (SELECT id FROM orders) SELECT x.id FROM x",
    "SELECT (SELECT o.amt FROM orders o WHERE o.id = c.id) FROM customers c",
    "SELECT id FROM employees WHERE id IN (SELECT m.id FROM managers m)",
    "SELECT t.* FROM t",
    "SELECT id, name FROM employees WHERE dept = 10",
];

#[test]
fn strict_corpus_is_never_underclassified() {
    // The served/strict posture: full fail-closed (`.82` + `.102`).
    let strict = Classifier::default().served_strict();
    for (sql, min_danger) in STRICT_CORPUS {
        let decision = strict.classify(sql);
        assert!(
            decision.danger >= *min_danger,
            "STRICT UNDER-CLASSIFIED: {sql:?} got {:?}, expected >= {min_danger:?}",
            decision.danger
        );
        assert_ne!(
            decision.required_level,
            Some(oraclemcp_guard::OperatingLevel::ReadOnly),
            "strict posture must never admit {sql:?} at READ_ONLY"
        );
    }
    // Mutation-killing counterpart: the DEFAULT (permissive) classifier still
    // admits every `.102` entry as Safe — proving it is the guard, not some
    // unrelated rule, that closes the hole under strict mode.
    let permissive = Classifier::default();
    assert_eq!(
        permissive
            .classify("SELECT app_admin.run_ddl FROM dual")
            .danger,
        DangerLevel::Safe,
        "the default classifier documents the .102 fail-open (closed only under strict mode)"
    );
}

#[test]
fn strict_102_guard_spares_genuine_column_references() {
    // The `.102` guard in isolation (no `.82` statement-Unknown tightening) must
    // keep ordinary in-scope qualified column references Safe.
    let guard_102 =
        Classifier::new(ClassifierConfig::new().with_unresolved_qualified_calls_guarded());
    for sql in STRICT_FALSE_POSITIVE_GUARD {
        let d = guard_102.classify(sql);
        assert_eq!(
            d.danger,
            DangerLevel::Safe,
            "a genuine in-scope column reference must stay Safe under the .102 guard: {sql:?}"
        );
    }
}

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
    ("SELECT /*+ index(emp) */ * FROM emp", DangerLevel::Safe),
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
    // bead QA100 .84: COMMENT ON and CREATE SEQUENCE parse cleanly under the
    // OracleDialect but used to fall through the classify_statement catch-all to
    // Guarded/READ_WRITE. Oracle DDL implicit-commits and cannot be rolled back,
    // so they must sit at the DDL floor — Destructive, never below. ANALYZE joins
    // them as object DDL that formerly under-classified the same way.
    (
        "COMMENT ON TABLE orders IS 'processed'",
        DangerLevel::Destructive,
    ),
    (
        "CREATE SEQUENCE order_seq START WITH 1",
        DangerLevel::Destructive,
    ),
    (
        "ANALYZE TABLE orders COMPUTE STATISTICS",
        DangerLevel::Destructive,
    ),
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
    // --- Audit gap: Oracle 12c WITH FUNCTION (inline PL/SQL in a SELECT) ---
    // A 12c `WITH FUNCTION` defines a full PL/SQL function body inside what
    // syntactically opens like a CTE. It does NOT start with BEGIN/DECLARE, so
    // Stage A returns PureSql; the inline `BEGIN … END;` then either trips the
    // dynamic-SQL marker scan (EXECUTE IMMEDIATE) or the buried-`;`-inside-block
    // desync. Either way the statement MUST NOT be cleared as a benign read just
    // because it lexes as a SELECT shell. (Observed: Forbidden — fail-closed.)
    (
        "WITH FUNCTION f RETURN NUMBER IS BEGIN EXECUTE IMMEDIATE 'DROP TABLE x'; RETURN 1; END; SELECT f FROM dual",
        DangerLevel::Guarded,
    ),
    // The same shape with no dangerous marker — a plain DML in the inline body —
    // still must not read as Safe (the buried `;` inside the function block is a
    // desync the pure-SQL caller fails closed on). (Observed: Forbidden.)
    (
        "WITH FUNCTION f RETURN NUMBER IS BEGIN DELETE FROM orders; RETURN 1; END; SELECT f FROM dual",
        DangerLevel::Guarded,
    ),
    // Even a side-effect-free inline body (RETURN only) must not be cleared to
    // Safe — the classifier cannot prove the inline routine pure here, and the
    // buried `;` desync fails it closed regardless. (Observed: Forbidden.)
    (
        "WITH FUNCTION f RETURN NUMBER IS BEGIN RETURN 1; END; SELECT f FROM dual",
        DangerLevel::Guarded,
    ),
    // --- Audit gap: INSERT … WITH (a CTE feeding a write) ---
    // `INSERT INTO t WITH c AS (…) SELECT * FROM c` is a write that leads with a
    // CTE on its source side. It must classify as a write (Guarded), never a
    // read — the leading `INSERT` keyword governs, not the embedded `WITH`/SELECT.
    (
        "INSERT INTO t WITH c AS (SELECT 1 FROM dual) SELECT * FROM c",
        DangerLevel::Guarded,
    ),
    (
        "INSERT INTO t\nWITH c AS (SELECT 1 FROM dual)\nSELECT * FROM c",
        DangerLevel::Guarded,
    ),
    // A line comment eats the apparent terminator/dangerous text until newline.
    ("SELECT 1 FROM dual -- ; DROP TABLE t", DangerLevel::Safe),
    // Once the newline ends the comment, the following DROP is real top-level
    // SQL and must govern the batch danger.
    (
        "SELECT 1 FROM dual -- comment\n; DROP TABLE t",
        DangerLevel::Destructive,
    ),
    // Nested comment-looking text is not a license to clear the statement. If
    // the parser cannot prove the shape, the classifier must fail closed.
    (
        "SELECT 1 FROM dual /* outer /* inner */ dangling */",
        DangerLevel::Guarded,
    ),
    // --- Derived-subquery-smuggled DML (oracle-derived-dml-body, 2026-07) ---
    // sqlparser 0.62 accepts a DML `SetExpr` wrapped in a FROM/JOIN derived
    // subquery, a UNION branch's `FROM (…)`, or a WHERE/scalar Expr subquery. The
    // top-level-only CTE-DML check missed all of these and cleared them to Safe.
    // Every read shell that carries a reachable write MUST fail closed to >= a
    // write classification (Guarded), never ReadOnly.
    ("SELECT * FROM (UPDATE t SET x=1)", DangerLevel::Guarded),
    ("SELECT * FROM (DELETE FROM t)", DangerLevel::Guarded),
    (
        "SELECT * FROM (INSERT INTO t VALUES (1))",
        DangerLevel::Guarded,
    ),
    (
        "SELECT * FROM (MERGE INTO t USING s ON (t.id=s.id) WHEN MATCHED THEN UPDATE SET t.v=s.v)",
        DangerLevel::Guarded,
    ),
    (
        "SELECT * FROM (SELECT * FROM (UPDATE t SET x=1))",
        DangerLevel::Guarded,
    ),
    (
        "SELECT 1 FROM dual UNION SELECT * FROM (DELETE FROM t)",
        DangerLevel::Guarded,
    ),
    (
        "SELECT * FROM a JOIN (UPDATE t SET x=1) b ON a.id=b.id",
        DangerLevel::Guarded,
    ),
    (
        "SELECT * FROM a WHERE id IN (UPDATE t SET x=1)",
        DangerLevel::Guarded,
    ),
    (
        "SELECT * FROM a WHERE EXISTS (INSERT INTO t VALUES (1))",
        DangerLevel::Guarded,
    ),
    (
        "WITH a AS (SELECT 1 x FROM dual) SELECT * FROM (WITH b AS (SELECT 1 y FROM dual) UPDATE t SET v=1)",
        DangerLevel::Guarded,
    ),
    // --- QA100 .83: raw non-allowlisted ALTER SESSION must be Forbidden before
    // the operator allow-list, never fall through parse-failure to READ_WRITE.
    // Session state (container, trace, events, hidden params) persists across
    // DML rollback, so it must be governed by the shared session-setting policy. ---
    ("ALTER SESSION SET SQL_TRACE = TRUE", DangerLevel::Forbidden),
    (
        "ALTER SESSION SET CONTAINER = CDB$ROOT",
        DangerLevel::Forbidden,
    ),
    (
        "ALTER SESSION SET EVENTS = '10046 trace name context forever, level 12'",
        DangerLevel::Forbidden,
    ),
    ("ALTER SESSION DISABLE GUARD", DangerLevel::Forbidden),
    // A comment wedge smuggling a denied param after an allowlisted one must not
    // downgrade to Guarded — the shared session policy canonicalizes first.
    (
        "ALTER/**/SESSION SET CURRENT_SCHEMA=HR/**/SQL_TRACE=TRUE",
        DangerLevel::Forbidden,
    ),
    (
        "/* audit */ ALTER SESSION SET CONTAINER = CDB$ROOT",
        DangerLevel::Forbidden,
    ),
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
fn derived_subquery_smuggled_dml_is_never_read_only() {
    // The fail-closed-net hole (oracle-derived-dml-body): a DML SetExpr hidden in
    // a derived / JOIN / UNION-branch / Expr subquery escaped the top-level-only
    // CTE-DML check and cleared to Safe. Assert the write is caught AND that
    // legitimate nested reads (incl. columns/tables whose names merely contain a
    // DML verb, and literals carrying DML words) stay Safe — no false positives.
    let c = Classifier::default();
    let writes = [
        "SELECT * FROM (UPDATE t SET x=1)",
        "SELECT * FROM (DELETE FROM t)",
        "SELECT * FROM (INSERT INTO t VALUES (1))",
        "SELECT * FROM (SELECT * FROM (DELETE FROM t))",
        "SELECT 1 FROM dual UNION SELECT * FROM (UPDATE t SET x=1)",
        "SELECT * FROM a JOIN (DELETE FROM t) b ON a.id=b.id",
        "SELECT * FROM a WHERE id IN (UPDATE t SET x=1)",
    ];
    for w in writes {
        let d = c.classify(w);
        assert!(
            d.danger >= DangerLevel::Guarded
                && d.required_level != Some(oraclemcp_guard::OperatingLevel::ReadOnly),
            "smuggled DML must never be ReadOnly/Safe: {w:?} -> {d:?}"
        );
    }
    let reads = [
        "SELECT * FROM (SELECT 1 FROM dual)",
        "SELECT * FROM (SELECT * FROM (SELECT 1 FROM dual))",
        "SELECT * FROM a JOIN (SELECT id FROM b) x ON a.id=x.id",
        "SELECT 1 FROM dual UNION SELECT 2 FROM dual",
        "SELECT updated_at, inserted_by, deleted_flag FROM audit_view",
        "SELECT COUNT(*) FROM merge_staging",
        "SELECT 'insert update delete' FROM dual",
        "SELECT q'{ UPDATE x; DELETE y; }' AS payload FROM dual",
    ];
    for r in reads {
        let d = c.classify(r);
        assert_eq!(
            d.danger,
            DangerLevel::Safe,
            "legitimate read must stay Safe (no false positive): {r:?} -> {d:?}"
        );
    }
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
fn multibyte_literal_contents_are_data_not_statements() {
    // Audit gap: a multibyte / unicode string literal carrying an embedded `;`
    // plus dangerous keywords (DROP/END/EXECUTE IMMEDIATE) is DATA inside one
    // SELECT, never a phantom statement boundary. The classifier must read the
    // literal as a single token regardless of non-ASCII bytes around the `;`,
    // and the whole thing stays exactly one Safe SELECT. (No false split, no
    // false danger — a false positive here would block legitimate reads.)
    let classifier = Classifier::default();
    for sql in [
        "SELECT 'café; DROP TABLE Ω; END; EXECUTE IMMEDIATE x' AS p FROM dual",
        "SELECT N'你好; DROP TABLE 世界; END;' AS p FROM dual",
        "SELECT q'{café; DROP TABLE Ω; END;}' AS p FROM dual",
        "SELECT 'Ω;Ω;Ω' AS p FROM dual",
    ] {
        let d = classifier.classify(sql);
        assert_eq!(
            d.danger,
            DangerLevel::Safe,
            "multibyte-literal contents must be treated as data (Safe SELECT): {sql:?} -> {d:?}"
        );
    }
}

#[test]
fn qquote_keyword_is_data_but_real_execute_immediate_is_forbidden() {
    // Audit gap: a `q'[…]'` literal whose CONTENTS spell a dangerous marker
    // (`EXECUTE IMMEDIATE`) is data, not a statement — it must NOT trip the
    // PL/SQL dynamic-SQL marker scan. The literal is a single token, so the
    // SELECT stays Safe.
    let classifier = Classifier::default();
    for benign in [
        "SELECT q'[EXECUTE IMMEDIATE]' AS p FROM dual",
        "SELECT q'<EXECUTE IMMEDIATE 'DROP TABLE t'>' AS p FROM dual",
        "SELECT q'{ EXECUTE IMMEDIATE 'x' }' AS p FROM dual",
    ] {
        let d = classifier.classify(benign);
        assert_eq!(
            d.danger,
            DangerLevel::Safe,
            "q-quoted EXECUTE IMMEDIATE is data, must stay Safe: {benign:?} -> {d:?}"
        );
    }
    // But a REAL EXECUTE IMMEDIATE outside any literal must be Forbidden — the
    // marker scan over the canonicalized token stream catches it. This is the
    // other half of the symmetry: data is inert, code is caught.
    for dangerous in [
        "BEGIN EXECUTE IMMEDIATE 'DROP TABLE x'; END;",
        // q-quoted decoy first, then a genuine dynamic-SQL call in the same block:
        // the real marker must still force Forbidden, the decoy must not mask it.
        "BEGIN x := q'[EXECUTE IMMEDIATE]'; EXECUTE IMMEDIATE 'DROP TABLE x'; END;",
    ] {
        let d = classifier.classify(dangerous);
        assert_eq!(
            d.danger,
            DangerLevel::Forbidden,
            "a real EXECUTE IMMEDIATE outside a literal must be Forbidden: {dangerous:?} -> {d:?}"
        );
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

#[test]
fn unicode_literal_forms_remain_data_but_confusable_keywords_do_not_parse_safe() {
    let classifier = Classifier::default();

    for sql in [
        r"SELECT U&'\0045\0058\0045\0043\0055\0054\0045\0020\0049\004D\004D\0045\0044\0049\0041\0054\0045; DROP TABLE t' AS p FROM dual",
        "SELECT N'EXECUTE IMMEDIATE; DROP TABLE t' AS p FROM dual",
    ] {
        let d = classifier.classify(sql);
        assert_eq!(
            d.danger,
            DangerLevel::Safe,
            "Oracle national/Unicode literal contents are data, not executable SQL: {sql:?} -> {d:?}"
        );
    }

    for sql in [
        "ＳＥＬＥＣＴ * FROM dual",
        "SEL\u{200d}ECT * FROM dual",
        "DR\u{200d}OP TABLE t",
        "\u{202e}DROP TABLE t",
    ] {
        let d = classifier.classify(sql);
        assert!(
            d.danger > DangerLevel::Safe,
            "confusable or directional-control keywords must not classify as Safe: {sql:?} -> {d:?}"
        );
    }
}

#[test]
fn unbalanced_quote_or_comment_is_forbidden_desync() {
    let classifier = Classifier::default();
    for sql in [
        "'unterminated",
        "SELECT 'unterminated FROM dual",
        "/* unterminated",
        "SELECT /* unterminated FROM dual",
        "SELECT q'[unterminated FROM dual",
    ] {
        let d = classifier.classify(sql);
        assert_eq!(
            d.danger,
            DangerLevel::Forbidden,
            "unbalanced quote/comment input must fail closed as Forbidden: {sql:?} -> {d:?}"
        );
    }
}
