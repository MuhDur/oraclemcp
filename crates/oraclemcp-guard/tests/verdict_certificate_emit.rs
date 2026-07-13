use oraclemcp_audit::{
    AuditDecision, AuditEntryDraft, AuditOutcome, AuditSubject, Auditor, MemoryAuditSink,
    SigningKey, sha256_hex,
};
use oraclemcp_guard::{
    Classifier, DangerLevel, OperatingLevel, VERDICT_CERTIFICATE_CLASSIFIER_VERSION,
    VerdictCertificate, VerdictCertificateBindingError,
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
