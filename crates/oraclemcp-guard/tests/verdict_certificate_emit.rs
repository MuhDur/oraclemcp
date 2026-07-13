use oraclemcp_audit::{
    AuditDecision, AuditEntryDraft, AuditOutcome, AuditSubject, Auditor, MemoryAuditSink,
    SigningKey, sha256_hex,
};
use std::sync::Arc;

use oraclemcp_guard::{
    Classifier, DangerLevel, ObjectRef, OperatingLevel, Purity, SideEffectOracle,
    VERDICT_CERTIFICATE_CLASSIFIER_VERSION, VerdictCertificate, VerdictCertificateBindingError,
};

fn assert_no_secret_material(certificate: &VerdictCertificate, forbidden: &[&str]) {
    let wire = serde_json::to_string(certificate).expect("certificate must serialize");
    for value in forbidden {
        assert!(
            !wire.contains(value),
            "certificate must not disclose SQL, bind, or identifier material: {value:?}"
        );
    }
}

#[test]
fn certificate_is_emitted_from_the_same_safe_classification_call() {
    let sql = "SELECT payroll.secret_bonus FROM payroll WHERE employee_id = :secret_employee";
    let decision = Classifier::default().classify(sql);
    let certificate = decision.verdict_certificate();

    assert_eq!(decision.danger, DangerLevel::Safe);
    assert_eq!(certificate.stmt_digest, sha256_hex(sql.as_bytes()));
    assert_eq!(certificate.level, Some(OperatingLevel::ReadOnly));
    assert_eq!(certificate.verdict, decision.danger);
    assert_eq!(certificate.bound_audit_hash, None);
    assert_eq!(certificate.observed_scn, None);
    assert_eq!(certificate.derivation.len(), 1);
    assert_eq!(certificate.derivation[0].rule_id, "R16");
    assert_eq!(certificate.derivation[0].construct, "final_verdict:SAFE");
    assert_no_secret_material(
        certificate,
        &[
            "SELECT",
            "payroll",
            "secret_bonus",
            "secret_employee",
            ":secret_employee",
        ],
    );
}

#[test]
fn forbidden_classification_still_has_a_redacted_certificate() {
    let sql = "BEGIN EXECUTE IMMEDIATE 'DROP TABLE payroll'; END;";
    let decision = Classifier::default().classify(sql);
    let certificate = decision.verdict_certificate();

    assert_eq!(decision.danger, DangerLevel::Forbidden);
    assert_eq!(certificate.level, None);
    assert_eq!(certificate.verdict, DangerLevel::Forbidden);
    assert_eq!(
        certificate.derivation[0].construct,
        "final_verdict:FORBIDDEN"
    );
    assert_no_secret_material(certificate, &["EXECUTE", "DROP", "payroll"]);
}

#[test]
fn routine_purity_consult_emits_r15_without_the_routine_identifier() {
    let sql = "SELECT payroll.recalculate_bonus(:employee_secret) FROM dual";
    let decision = Classifier::default().classify(sql);
    let certificate = decision.verdict_certificate();

    assert_eq!(decision.danger, DangerLevel::Guarded);
    assert_eq!(
        certificate.derivation,
        vec![
            oraclemcp_guard::VerdictDerivationStep {
                construct: "routine_purity:unproven_present".to_owned(),
                rule_id: "R15".to_owned(),
            },
            oraclemcp_guard::VerdictDerivationStep {
                construct: "final_verdict:GUARDED".to_owned(),
                rule_id: "R16".to_owned(),
            },
        ]
    );
    assert_no_secret_material(
        certificate,
        &["payroll", "recalculate_bonus", "employee_secret"],
    );
}

#[test]
fn certificate_core_hash_binds_every_core_field_but_not_response_audit_hash() {
    let certificate = Classifier::default()
        .classify("SELECT 1 FROM dual")
        .verdict_certificate()
        .clone();
    let baseline = certificate.core_hash();

    let core_hash = certificate.core_hash();
    let audit_entry_hash = sha256_hex(b"durable audit entry");
    let bound = certificate
        .clone()
        .bind_to_persisted_audit(
            &certificate.stmt_digest,
            Some(&core_hash),
            &audit_entry_hash,
        )
        .expect("matching persisted audit evidence must bind the response certificate");
    assert_eq!(
        bound.bound_audit_hash.as_deref(),
        Some(audit_entry_hash.as_str())
    );
    assert_eq!(
        bound.core_hash(),
        baseline,
        "response-only audit binding must not create a self-referential core hash"
    );
    assert_ne!(
        certificate.with_observed_scn(Some(42_000_001)).core_hash(),
        baseline,
        "an observed SCN is part of the audit-bound certificate core"
    );
}

#[test]
fn certificate_refuses_a_mismatched_or_malformed_audit_binding() {
    let certificate = Classifier::default()
        .classify("SELECT 1 FROM dual")
        .verdict_certificate()
        .clone();
    let statement_digest = certificate.stmt_digest.clone();
    let core_hash = certificate.core_hash();
    let entry_hash = sha256_hex(b"durable audit entry");

    assert_eq!(
        certificate.clone().bind_to_persisted_audit(
            "sha256:different-statement",
            Some(&core_hash),
            &entry_hash,
        ),
        Err(VerdictCertificateBindingError::SqlDigestMismatch)
    );
    assert_eq!(
        certificate.clone().bind_to_persisted_audit(
            &statement_digest,
            Some("sha256:different-certificate"),
            &entry_hash,
        ),
        Err(VerdictCertificateBindingError::CoreHashMismatch)
    );
    assert_eq!(
        certificate.bind_to_persisted_audit(
            &statement_digest,
            Some(&core_hash),
            "not-an-audit-entry-hash",
        ),
        Err(VerdictCertificateBindingError::InvalidAuditEntryHash)
    );
}

#[test]
fn the_bound_audit_hash_must_be_a_canonical_sha256_and_not_merely_sha256_shaped() {
    // The case above is rejected before the hash is ever examined: it has no
    // `sha256:` prefix, so the check short-circuits and the RULE — exactly 64
    // lowercase hex digits — is never exercised. That left the rule unpinned.
    //
    // This binding is what ties a verdict certificate to the durable audit entry
    // that proves the decision happened. A hash we accept without proving its
    // shape is a hash an attacker (or a truncating bug) can choose: a 63-digit
    // stub, an uppercase spelling that hashes differently downstream, or a
    // non-hex string that is not a digest at all. Each must be refused.
    let certificate = Classifier::default()
        .classify("SELECT 1 FROM dual")
        .verdict_certificate()
        .clone();
    let statement_digest = certificate.stmt_digest.clone();
    let core_hash = certificate.core_hash();

    for (entry_hash, why) in [
        (
            format!("sha256:{}", "a".repeat(63)),
            "one digit short is not a SHA-256",
        ),
        (
            format!("sha256:{}", "a".repeat(65)),
            "one digit long is not a SHA-256 either",
        ),
        (
            format!("sha256:{}", "z".repeat(64)),
            "64 characters of non-hex is not a digest, it is just the right length",
        ),
        (
            format!("sha256:{}", "A".repeat(64)),
            "uppercase hex is not the canonical spelling: the same digest written \
             two ways breaks hash equality for every downstream comparison",
        ),
        (format!("sha256:{}", "").to_string(), "an empty digest body"),
    ] {
        assert_eq!(
            certificate.clone().bind_to_persisted_audit(
                &statement_digest,
                Some(&core_hash),
                &entry_hash,
            ),
            Err(VerdictCertificateBindingError::InvalidAuditEntryHash),
            "a certificate must refuse to bind to a non-canonical audit hash: {why}"
        );
    }

    // The mirror: a genuine canonical digest binds, so the rule is not vacuous.
    let genuine = sha256_hex(b"durable audit entry");
    assert!(
        certificate
            .bind_to_persisted_audit(&statement_digest, Some(&core_hash), &genuine)
            .is_ok(),
        "a canonical lowercase sha256 must still bind"
    );
}

#[test]
fn certificate_core_hash_uses_the_jcs_key_order_for_fixed_certificate_values() {
    let certificate = Classifier::default()
        .classify("SELECT 1 FROM dual")
        .verdict_certificate()
        .clone();
    let canonical_core = format!(
        r#"{{"classifier_version":"{VERDICT_CERTIFICATE_CLASSIFIER_VERSION}","derivation":[{{"construct":"final_verdict:SAFE","rule_id":"R16"}}],"level":"READ_ONLY","observed_scn":null,"stmt_digest":"{}","verdict":"SAFE"}}"#,
        certificate.stmt_digest
    );
    let expected =
        sha256_hex(format!("oraclemcp:verdict-certificate-core:v1\n{canonical_core}").as_bytes());

    assert_eq!(certificate.core_hash(), expected);
}

#[test]
fn audit_projection_preserves_the_core_hash_and_only_registered_labels() {
    let certificate = Classifier::default()
        .classify("SELECT payroll.recalculate_bonus(:employee_secret) FROM dual")
        .verdict_certificate()
        .clone()
        .with_observed_scn(Some(42_000_001));

    let audit_certificate = certificate
        .audit_certificate()
        .expect("a guard-produced certificate must fit the closed audit grammar");
    assert_eq!(audit_certificate.core_hash(), certificate.core_hash());

    let wire = serde_json::to_string(&audit_certificate).expect("audit certificate serializes");
    assert!(wire.contains("routine_purity:unproven_present"));
    assert!(wire.contains("final_verdict:GUARDED"));
    for forbidden in ["payroll", "recalculate_bonus", "employee_secret", "SELECT"] {
        assert!(
            !wire.contains(forbidden),
            "audit projection must retain only registry labels: {forbidden}"
        );
    }
}

#[test]
fn same_classification_certificate_binds_to_the_durable_audit_record() {
    let sql = "SELECT 1 FROM dual";
    let certificate = Classifier::default()
        .classify(sql)
        .verdict_certificate()
        .clone()
        .with_observed_scn(Some(42_000_001));
    let certificate_core_hash = certificate.core_hash();
    let auditor = Auditor::new(
        Box::new(MemoryAuditSink::new()),
        SigningKey::new("test", b"0123456789abcdef0123456789abcdef".to_vec())
            .expect("test signing key is valid"),
    );
    let draft = AuditEntryDraft {
        subject: AuditSubject::new("test", "verdict-certificate"),
        db_evidence: None,
        cancel: None,
        result_masking: None,
        tool: "oracle_query".to_owned(),
        sql: sql.to_owned(),
        danger_level: "SAFE".to_owned(),
        decision: AuditDecision::Allowed,
        rows_affected: None,
        outcome: AuditOutcome::Pending,
    };

    let record = auditor
        .append_correlated_with_observed_scn_and_certificate_core_hash(
            &draft,
            "2026-07-13T00:00:00Z".to_owned(),
            true,
            None,
            Some(42_000_001),
            Some(&certificate_core_hash),
        )
        .expect("canonical certificate evidence must be durably appended");
    let bound = certificate
        .bind_to_persisted_audit(
            &record.sql_sha256,
            record.verdict_certificate_core_hash.as_deref(),
            &record.entry_hash,
        )
        .expect("matching durable record must bind the response certificate");

    assert_eq!(record.observed_scn, Some(42_000_001));
    assert_eq!(
        record.verdict_certificate_core_hash.as_deref(),
        Some(certificate_core_hash.as_str())
    );
    assert_eq!(
        bound.bound_audit_hash.as_deref(),
        Some(record.entry_hash.as_str())
    );
}

/// An oracle that PROVES every routine read-only — the engine binding that lets a
/// routine call be admitted rather than merely guarded. It is the only way to
/// reach the `all_proven_read_only` derivation, which the engine-free default
/// classifier can never emit (it has nothing to prove purity with).
struct ProvenReadOnlyOracle;
impl SideEffectOracle for ProvenReadOnlyOracle {
    fn routine_purity(&self, _routine: &ObjectRef) -> Purity {
        Purity::ProvenReadOnly
    }
    fn statement_purity(&self, _base: &[ObjectRef]) -> Purity {
        Purity::ProvenReadOnly
    }
}

#[test]
fn every_verdict_class_projects_into_the_closed_audit_grammar() {
    // `audit_certificate()` maps the certificate's derivation onto the audit
    // crate's CLOSED label vocabulary — an unregistered construct is refused
    // rather than written. That projection is what the audit hash-chain actually
    // records, so a verdict class whose label is missing from the mapping cannot
    // be audited at all.
    //
    // The suite above only ever projected ONE classification (the guarded routine
    // call), so the SAFE / DESTRUCTIVE / FORBIDDEN labels were registered but
    // never exercised: the mapping could lose them and nothing would notice. Walk
    // every verdict class through the projection.
    for (sql, label) in [
        ("SELECT 1 FROM dual", "final_verdict:SAFE"),
        (
            "SELECT payroll.recalculate_bonus(:employee_secret) FROM dual",
            "final_verdict:GUARDED",
        ),
        ("DELETE FROM orders", "final_verdict:DESTRUCTIVE"),
        (
            "BEGIN EXECUTE IMMEDIATE 'DROP TABLE payroll'; END;",
            "final_verdict:FORBIDDEN",
        ),
    ] {
        let certificate = Classifier::default()
            .classify(sql)
            .verdict_certificate()
            .clone();
        let audit_certificate = certificate.audit_certificate().unwrap_or_else(|error| {
            panic!("every guard verdict must fit the closed audit grammar ({error:?}): {sql:?}")
        });
        assert_eq!(
            audit_certificate.core_hash(),
            certificate.core_hash(),
            "projection must not disturb the core hash: {sql:?}"
        );
        let wire = serde_json::to_string(&audit_certificate).expect("audit certificate serializes");
        assert!(
            wire.contains(label),
            "the audited certificate must carry {label:?} for {sql:?}, got {wire}"
        );
    }

    // The R15 purity derivation has a second spelling the default classifier can
    // never produce, so it needs the engine binding to be reached at all.
    let certificate = Classifier::default()
        .with_oracle(Arc::new(ProvenReadOnlyOracle))
        .classify("SELECT payroll.recalculate_bonus(:employee_secret) FROM dual")
        .verdict_certificate()
        .clone();
    let wire = serde_json::to_string(
        &certificate
            .audit_certificate()
            .expect("a proven-pure routine call must also fit the audit grammar"),
    )
    .expect("audit certificate serializes");
    assert!(
        wire.contains("routine_purity:all_proven_read_only"),
        "a routine the engine PROVES read-only must be audited as such, not as \
         unproven: {wire}"
    );
}
