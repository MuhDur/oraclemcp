use std::collections::BTreeSet;

const CERTIFICATE_SCHEMA: &str =
    include_str!("../../../docs/adr/0010-verdict-certificate-schema.md");
const CLASSIFIER_SOURCE: &str = include_str!("../src/classifier.rs");

fn is_rule_id(token: &str) -> bool {
    token.strip_prefix('R').is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn explicit_rule_ids(text: &str) -> BTreeSet<&str> {
    text.split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| is_rule_id(token))
        .collect()
}

fn documented_rule_ids(note: &str) -> BTreeSet<&str> {
    note.lines()
        .filter_map(|line| {
            line.split('|')
                .nth(1)
                .map(|cell| cell.trim().trim_matches('`'))
        })
        .filter(|cell| is_rule_id(cell))
        .collect()
}

#[test]
fn certificate_schema_is_complete_and_registry_matches_classifier() {
    for field in [
        "stmt_digest",
        "level",
        "verdict",
        "derivation",
        "classifier_version",
        "observed_scn",
        "bound_audit_hash",
    ] {
        assert!(
            CERTIFICATE_SCHEMA.contains(field),
            "certificate schema must define `{field}`"
        );
    }
    assert!(
        CERTIFICATE_SCHEMA.contains("certificate_core_hash"),
        "schema must define the non-circular core hash used to bind the certificate"
    );
    assert!(
        CERTIFICATE_SCHEMA.contains("AuditRecord::entry_hash"),
        "schema must bind a certificate to the exact audit record entry hash"
    );

    assert_eq!(
        documented_rule_ids(CERTIFICATE_SCHEMA),
        explicit_rule_ids(CLASSIFIER_SOURCE),
        "the certificate registry must enumerate every explicit R-numbered classifier rule"
    );
}
