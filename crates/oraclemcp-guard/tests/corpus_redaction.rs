//! Corpus record schema + redaction (bead oraclemcp-epic-09x-alien-6sj8.14.1).
//!
//! The Arc J corpus is meant to SHIP PUBLICLY, so these are disclosure tests, not
//! formatting tests. The bar: a record must never persist a secret, a credential,
//! a bind value, or a customer identifier — and a record that carries one must be
//! rejected or scrubbed, never quietly written.
//!
//! The suite is built around one adversarial fixture set (`SECRETS`) that is
//! swept across every path a record can take: construction, serialization,
//! reload, dedup, and even the error messages. If any of those ever renders one
//! of those strings, the test fails and names it.

use oraclemcp_guard::corpus::{
    CORPUS_RECORD_VERSION, CorpusRecord, CorpusRedactionError, MAX_WHY_CHARS, ReasonCategory,
    classifier_proves_rewrite, dedup_by_content, reclassify_rewrite_at_apply, redact_sql, safe_why,
    validate_redacted_sql,
};
use oraclemcp_guard::{Classifier, ClassifierConfig, DangerLevel};

/// Every string that must never reach the corpus, whatever field it entered by.
/// Synthetic throughout — no real identifiers (see the repo's confidentiality
/// rule); these stand in for the credential/PII/customer-name shapes we refuse.
const SECRETS: &[&str] = &[
    "hunter2",
    "s3cr3t-token",
    "alice@example.test",
    "111-22-3333",
    "ACME_CORP",
    "CUSTOMERS",
    "PRODDB",
    "4111111111111111",
];

/// Statements that carry a secret in every way a statement can carry one: a
/// string literal, a comment, a bind name, a quoted identifier, a db link, a
/// password clause, and a number.
fn secret_bearing_statements() -> Vec<String> {
    vec![
        "SELECT * FROM acme_corp.customers WHERE email = 'alice@example.test'".to_owned(),
        "SELECT * FROM t WHERE ssn = '111-22-3333' -- hunter2".to_owned(),
        "SELECT /* s3cr3t-token */ card FROM payments WHERE pan = 4111111111111111".to_owned(),
        "UPDATE acme_corp.accounts SET token = :s3cr3t WHERE id = :1".to_owned(),
        "ALTER USER app IDENTIFIED BY hunter2".to_owned(),
        "SELECT * FROM \"ACME_CORP\".\"CUSTOMERS\"@PRODDB".to_owned(),
        "BEGIN EXECUTE IMMEDIATE 'GRANT DBA TO acme_corp'; END;".to_owned(),
        "INSERT INTO customers (email) VALUES ('alice@example.test')".to_owned(),
    ]
}

fn assert_carries_no_secret(haystack: &str, context: &str) {
    for secret in SECRETS {
        assert!(
            !haystack
                .to_ascii_uppercase()
                .contains(&secret.to_ascii_uppercase()),
            "SECRET LEAKED via {context}: {secret:?} is present in {haystack:?}"
        );
    }
}

#[test]
fn redaction_scrubs_every_secret_shape_a_statement_can_carry() {
    for sql in secret_bearing_statements() {
        let redacted = redact_sql(&sql).unwrap_or_else(|error| {
            panic!("a lexable statement must redact rather than error ({error:?}): {sql:?}")
        });
        assert_carries_no_secret(&redacted, "redact_sql");
        // The postcondition must independently agree the output is clean.
        validate_redacted_sql(&redacted).unwrap_or_else(|error| {
            panic!("redacted output failed its own postcondition ({error:?}): {redacted:?}")
        });
    }
}

#[test]
fn redaction_keeps_the_lesson_while_dropping_the_identifiers() {
    // The corpus exists to teach what unsafe SQL looks like. The Oracle-shipped
    // names that make a statement dangerous are public and must SURVIVE, or the
    // dataset is worthless; the customer's table name must not.
    let redacted = redact_sql(
        "BEGIN EXECUTE IMMEDIATE 'DROP TABLE acme_corp.customers'; DBMS_SQL.PARSE(c, s, 1); END;",
    )
    .expect("redacts");
    assert!(
        redacted.contains("EXECUTE") && redacted.contains("IMMEDIATE"),
        "the dangerous construct must survive redaction: {redacted}"
    );
    assert!(
        redacted.contains("DBMS_SQL"),
        "an Oracle-shipped package name is public and must survive: {redacted}"
    );
    assert_carries_no_secret(&redacted, "skeleton");

    // A customer identifier becomes a positional placeholder, and the SAME name
    // maps to the SAME placeholder so joins stay legible.
    let joined =
        redact_sql("SELECT a.id FROM acme_corp.orders a JOIN acme_corp.orders b ON a.id = b.id")
            .expect("redacts");
    assert_carries_no_secret(&joined, "join skeleton");
    assert!(
        joined.contains("id_1") && joined.contains("JOIN"),
        "structure must survive: {joined}"
    );
}

#[test]
fn a_record_round_trips_through_jsonl() {
    let record = CorpusRecord::new(
        "SELECT * FROM acme_corp.customers WHERE email = 'alice@example.test'",
        ReasonCategory::RequiresHigherLevel,
        Some("SELECT id FROM acme_corp.customers WHERE email = :bind"),
        "the statement needs a higher operating level than the session permits",
    )
    .expect("a lexable refusal becomes a record");

    let line = record.to_jsonl_line();
    assert!(
        !line.contains('\n'),
        "a JSONL record must be exactly one line"
    );
    assert_carries_no_secret(&line, "serialized record");

    let parsed = CorpusRecord::from_jsonl_line(&line).expect("round-trips");
    assert_eq!(parsed, record, "the record must survive a JSONL round trip");
    assert_eq!(parsed.refusal_class, ReasonCategory::RequiresHigherLevel);
    assert!(parsed.id.starts_with("sha256:"));
    assert!(parsed.suggested_rewrite_redacted.is_some());
}

#[test]
fn no_field_of_a_serialized_record_ever_carries_a_secret() {
    // The sweep: every adversarial statement, in BOTH sql fields, serialized.
    for sql in secret_bearing_statements() {
        let record = CorpusRecord::new(
            &sql,
            ReasonCategory::DynamicSql,
            Some(&sql),
            "dynamic SQL the guard cannot prove safe",
        )
        .expect("a lexable refusal becomes a record");
        assert_carries_no_secret(&record.to_jsonl_line(), "full record");
        assert_carries_no_secret(&record.id, "content id");
    }
}

#[test]
fn a_stored_corpus_record_never_replays_a_verdict_at_apply_time() {
    let default_classifier = Classifier::default();
    let raw_rewrite = "UPDATE acme_corp.customers SET status = :status WHERE id = :id";
    assert!(
        classifier_proves_rewrite(&default_classifier, raw_rewrite),
        "a level-gated rewrite is classifier-proven advice, not an execution grant"
    );

    let record = CorpusRecord::new(
        "UPDATE acme_corp.customers SET status = 'closed' WHERE id = 42",
        ReasonCategory::RequiresHigherLevel,
        Some(raw_rewrite),
        "the statement needs a higher operating level",
    )
    .expect("redacted corpus record");
    let serialized = record.to_jsonl_line();
    assert!(
        !serialized.contains("verdict")
            && !serialized.contains("danger")
            && !serialized.contains("required_level"),
        "stored corpus data contains no reusable classifier outcome"
    );

    let tightened = Classifier::new(ClassifierConfig::new().with_block_pattern("(?i)UPDATE"));
    assert_eq!(
        reclassify_rewrite_at_apply(&tightened, raw_rewrite).danger,
        DangerLevel::Forbidden,
        "a later tighter policy decides from raw SQL, not from the old corpus record"
    );
    assert!(
        !classifier_proves_rewrite(
            &default_classifier,
            "BEGIN EXECUTE IMMEDIATE 'DROP TABLE acme_corp.customers'; END;"
        ),
        "a forbidden candidate cannot be offered or recorded"
    );
}

#[test]
fn a_why_carrying_a_secret_is_rejected() {
    // `why` is the one free-text field, so it is the obvious smuggling route. It
    // is held to a plain-prose alphabet: no digits, quotes, binds, hosts, or
    // identifier punctuation — which is everything a credential needs.
    for hostile in [
        "password is hunter2",
        "connect as scott/tiger@PRODDB",
        "the bind was :ssn",
        "leaked 'alice@example.test'",
        "card 4111111111111111 refused",
        "see acme_corp.customers",
    ] {
        assert_eq!(
            safe_why(hostile),
            Err(CorpusRedactionError::UnsafeWhy),
            "a `why` carrying a secret must be refused: {hostile:?}"
        );
        assert_eq!(
            CorpusRecord::new("SELECT * FROM t", ReasonCategory::DynamicSql, None, hostile),
            Err(CorpusRedactionError::UnsafeWhy),
            "and the record must not be constructible either: {hostile:?}"
        );
    }
    // The mirror: ordinary prose is accepted, so the rule is not vacuously strict.
    assert!(safe_why("dynamic SQL the guard cannot prove safe").is_ok());
}

#[test]
fn an_unlexable_statement_is_refused_rather_than_shipped_unredacted() {
    // Fail-closed: if the redactor cannot lex the text, it cannot prove what is in
    // it, so there is no record. The alternative — emitting a best-effort scrub —
    // is how an unterminated literal ships a secret.
    let unterminated = "SELECT * FROM t WHERE x = 'hunter2";
    assert_eq!(
        redact_sql(unterminated),
        Err(CorpusRedactionError::NotLexable)
    );
    assert_eq!(
        CorpusRecord::new(
            unterminated,
            ReasonCategory::UnbalancedBlock,
            None,
            "does not lex"
        ),
        Err(CorpusRedactionError::NotLexable),
        "an unlexable refusal must produce NO record"
    );
    assert_eq!(redact_sql("   "), Err(CorpusRedactionError::Empty));
}

#[test]
fn a_tampered_record_is_refused_at_load() {
    // SEC-1 applied to the corpus: text on disk is not trusted just because it is
    // on disk. Someone hand-edits a shipped corpus file to put the plaintext back
    // (or a buggy writer does) — the loader must refuse it.
    let record = CorpusRecord::new(
        "SELECT * FROM acme_corp.customers WHERE email = 'alice@example.test'",
        ReasonCategory::RequiresHigherLevel,
        None,
        "needs a higher operating level",
    )
    .expect("record");

    let tampered = record.to_jsonl_line().replace(
        &record.refused_sql_redacted,
        "SELECT * FROM acme_corp.customers WHERE email = 'alice@example.test'",
    );
    let error = CorpusRecord::from_jsonl_line(&tampered)
        .expect_err("a record whose text carries plaintext again must be refused at load");
    assert!(
        matches!(
            error,
            CorpusRedactionError::ResidualLiteral | CorpusRedactionError::ResidualIdentifier
        ),
        "the residue must be named, got {error:?}"
    );

    // And a record whose text is clean but whose id was edited is refused too, so
    // the dedup key cannot be forged.
    let forged = record.to_jsonl_line().replace(&record.id, "sha256:0000");
    assert_eq!(
        CorpusRecord::from_jsonl_line(&forged),
        Err(CorpusRedactionError::IdMismatch)
    );
}

#[test]
fn a_non_json_corpus_line_is_refused_as_malformed() {
    // The corpus is an operator-visible JSONL file on disk (bead A8 territory):
    // truncated writes, a torn append after a crash, or a hand-edit that broke
    // the JSON entirely must fail closed as `Malformed`, not panic and not be
    // silently skipped. This was the one `CorpusRedactionError` variant with no
    // discriminating test anywhere in the crate before this.
    for garbage in ["", "not json at all", "{", "[1, 2, 3]", "\"just a string\""] {
        assert_eq!(
            CorpusRecord::from_jsonl_line(garbage),
            Err(CorpusRedactionError::Malformed),
            "line {garbage:?} must be refused as Malformed"
        );
    }

    // Valid JSON that simply is not a corpus record (wrong shape) is Malformed
    // too, not a panic or a different variant.
    let wrong_shape = r#"{"unrelated":"json","not":"a corpus record"}"#;
    assert_eq!(
        CorpusRecord::from_jsonl_line(wrong_shape),
        Err(CorpusRedactionError::Malformed)
    );
}

#[test]
fn an_error_never_echoes_the_secret_it_rejected() {
    // A rejection that quotes the offending text just moves the leak into the log.
    for hostile in ["password is hunter2", "leaked 'alice@example.test'"] {
        let error = safe_why(hostile).expect_err("rejected");
        assert_carries_no_secret(&format!("{error}"), "error Display");
        assert_carries_no_secret(&format!("{error:?}"), "error Debug");
    }
    let error = redact_sql("SELECT * FROM t WHERE x = 'hunter2").expect_err("rejected");
    assert_carries_no_secret(&format!("{error} {error:?}"), "unlexable error");
}

#[test]
fn dedup_collapses_statements_that_differ_only_in_names_and_values() {
    // Content hash is taken over the REDACTED skeleton, so two refusals that are
    // the same lesson dressed in different customer names collapse into one
    // public record — which is both the dedup story and a second proof that no
    // identifier survives into the id.
    let first = CorpusRecord::new(
        "SELECT * FROM acme_corp.customers WHERE email = 'alice@example.test'",
        ReasonCategory::RequiresHigherLevel,
        None,
        "needs a higher operating level",
    )
    .expect("record");
    let second = CorpusRecord::new(
        "SELECT * FROM other_corp.people WHERE email = 'bob@example.test'",
        ReasonCategory::RequiresHigherLevel,
        None,
        "needs a higher operating level",
    )
    .expect("record");
    assert_eq!(
        first.id, second.id,
        "the same skeleton is the same corpus lesson"
    );

    let different_class = CorpusRecord::new(
        "SELECT * FROM acme_corp.customers WHERE email = 'alice@example.test'",
        ReasonCategory::DynamicSql,
        None,
        "needs a higher operating level",
    )
    .expect("record");
    assert_ne!(
        first.id, different_class.id,
        "a different refusal class is a different lesson"
    );

    let deduped = dedup_by_content(vec![first.clone(), second, different_class, first.clone()]);
    assert_eq!(deduped.len(), 2, "dedup keeps one record per content hash");
    assert_eq!(deduped[0], first, "dedup keeps the first occurrence");
}

#[test]
fn the_schema_version_is_bound_into_the_content_hash() {
    // A schema change must not silently collide with records written by an older
    // build, so the version is hashed in. Pinning it here makes a bump deliberate.
    assert_eq!(CORPUS_RECORD_VERSION, 1);
}

#[test]
fn every_token_class_collapses_to_its_own_fixed_placeholder() {
    // The tests above prove the output carries no secret. That is necessary but
    // not sufficient: the redactor's catch-all (`_ => '?'`) means DELETING any
    // one token arm still yields secret-free output, just a different shape — so
    // "no secret leaked" cannot tell a working arm from a deleted one, and the
    // arms were in fact unpinned.
    //
    // The contract is stronger than "no secret": each token class collapses to a
    // SPECIFIC placeholder, and the same name always collapses to the same one.
    // That is what keeps the corpus legible (`a.x = b.x` still reads as a join)
    // and what makes dedup_by_content stable across records. Pin the exact
    // skeleton, so a lost arm is a failing test rather than a silent format drift.
    let sql = "SELECT a.x, ? FROM orders a JOIN orders b ON a.x = b.x \
               WHERE a.y = :name AND a.z = :1 AND a.n = 5 AND a.s = 'sec'";
    let redacted = redact_sql(sql).expect("a lexable statement redacts");
    assert_eq!(
        redacted,
        "SELECT id_1 . id_2 , :? FROM id_3 id_1 JOIN id_3 id_4 ON id_1 . id_2 = id_4 . id_2 \
         WHERE id_1 . id_5 = :? AND id_1 . id_6 = :? AND id_1 . id_7 = ? AND id_1 . id_8 = '?'",
        "the redaction contract: a bind (`?`, `:name`, `:1`) becomes `:?` and its \
         NAME is dropped; a number becomes `?`; a literal becomes `'?'`; structure \
         punctuation survives; EOF adds nothing; and a repeated identifier reuses \
         its placeholder (`orders` is id_3 both times, `a` is id_1 throughout)"
    );
}

#[test]
fn the_postcondition_refuses_every_residual_shape_in_text_read_back_from_disk() {
    // validate_redacted_sql is applied to text READ BACK (a shipped corpus file a
    // third party may have hand-edited), not only to text we just wrote. On that
    // path it is the whole defence, so it must reject each residual shape on its
    // own terms — and name it, because the variant is what tells an operator which
    // scrub broke.
    for (residual, expected, why) in [
        (
            "SELECT id_1 FROM id_2 WHERE id_3 = $1",
            CorpusRedactionError::ResidualBind,
            "a surviving bind placeholder is an unredacted value slot",
        ),
        (
            "SELECT id_1 FROM id_2 WHERE id_3 = 5",
            CorpusRedactionError::ResidualNumber,
            "a surviving number is an unredacted value (an account number, a PAN)",
        ),
        (
            "SELECT id_1 FROM id_customer",
            CorpusRedactionError::ResidualIdentifier,
            "`id_customer` is a REAL table that merely looks like a placeholder: a \
             generated placeholder is `id_` + digits and nothing else",
        ),
        (
            "SELECT id_1 FROM id_",
            CorpusRedactionError::ResidualIdentifier,
            "`id_` with an empty suffix is not a generated placeholder either",
        ),
        (
            "SELECT '--' FROM id_2",
            CorpusRedactionError::ResidualComment,
            "a comment marker is refused on sight, before the tokenizer gets a say \
             about whether it happens to sit inside a literal",
        ),
        (
            "SELECT '/*' FROM id_2",
            CorpusRedactionError::ResidualComment,
            "and the block-comment marker likewise",
        ),
        (
            "SELECT 'x' FROM id_2",
            CorpusRedactionError::ResidualLiteral,
            "a string literal that is not the redacted `'?'` is a surviving value",
        ),
    ] {
        assert_eq!(
            validate_redacted_sql(residual),
            Err(expected),
            "the postcondition must refuse {residual:?} as {expected:?}: {why}"
        );
    }

    // The mirror: a properly redacted skeleton passes, so the gate is not
    // vacuously strict (a postcondition that refuses everything proves nothing).
    for clean in [
        "SELECT id_1 FROM id_2",
        "SELECT id_1 FROM id_2 WHERE id_3 = :?",
        "SELECT id_1 FROM id_2 WHERE id_3 = ?",
        "SELECT '?' FROM id_2",
    ] {
        assert_eq!(
            validate_redacted_sql(clean),
            Ok(()),
            "a redacted skeleton must pass its own postcondition: {clean:?}"
        );
    }
}

#[test]
fn the_why_field_is_bounded_as_well_as_alphabet_checked() {
    // The alphabet check above stops a credential being spelled out in `why`. The
    // LENGTH bound is the other half: `why` is the one free-text field that ships,
    // so an unbounded one is an unbounded disclosure channel — prose alone can
    // still describe a customer. Pin both edges of the bound, not just the middle.
    assert_eq!(
        safe_why(""),
        Err(CorpusRedactionError::UnsafeWhy),
        "an empty `why` carries no lesson and must be refused"
    );
    assert_eq!(
        safe_why("   "),
        Err(CorpusRedactionError::UnsafeWhy),
        "whitespace is empty once trimmed"
    );
    assert!(
        safe_why(&"a".repeat(MAX_WHY_CHARS)).is_ok(),
        "exactly MAX_WHY_CHARS is the longest admissible `why`"
    );
    assert_eq!(
        safe_why(&"a".repeat(MAX_WHY_CHARS + 1)),
        Err(CorpusRedactionError::UnsafeWhy),
        "one character past the bound must be refused: the bound is the point"
    );
}
