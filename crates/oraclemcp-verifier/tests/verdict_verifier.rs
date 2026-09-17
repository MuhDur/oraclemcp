use oraclemcp_audit::{
    AuditDecision, AuditEntryDraft, AuditOutcome, AuditRecord, AuditSubject, GENESIS_HASH,
    SigningKey,
};
use std::sync::Arc;

use oraclemcp_guard::{
    Classifier, ClassifierConfig, DangerLevel, ObjectRef, OperatingLevel, Purity, SideEffectOracle,
    VerdictCertificate,
};
use oraclemcp_verifier::{VerdictEvidence, VerdictVerificationError, verify_verdict};

fn test_key() -> SigningKey {
    SigningKey::new(
        "external-test",
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .expect("test key must be valid")
}

fn evidence_for_certificate(
    sql: &str,
    certificate: VerdictCertificate,
) -> (VerdictCertificate, AuditRecord, SigningKey) {
    let certificate = certificate.clone().with_observed_scn(Some(42_000_001));
    let key = test_key();
    let audit_record =
        AuditRecord::chained_signed_correlated_with_observed_scn_and_certificate_core_hash(
            &AuditEntryDraft {
                subject: AuditSubject::new("external", "verifier-test"),
                db_evidence: None,
                cancel: None,
                result_masking: None,
                tool: "oracle_query".to_owned(),
                sql: sql.to_owned(),
                danger_level: "SAFE".to_owned(),
                decision: AuditDecision::Allowed,
                rows_affected: None,
                outcome: AuditOutcome::Succeeded,
            },
            1,
            GENESIS_HASH,
            "2026-07-13T00:00:00Z".to_owned(),
            &key,
            None,
            Some(42_000_001),
            Some(certificate.core_hash()),
        );
    let certificate = certificate
        .bind_to_persisted_audit(
            &audit_record.sql_sha256,
            audit_record.verdict_certificate_core_hash.as_deref(),
            &audit_record.entry_hash,
        )
        .expect("matching signed audit evidence must bind");
    (certificate, audit_record, key)
}

fn evidence_for(sql: &str) -> (VerdictCertificate, AuditRecord, SigningKey) {
    let certificate = Classifier::engine_free_baseline(ClassifierConfig::new())
        .classify(sql)
        .verdict_certificate()
        .clone();
    evidence_for_certificate(sql, certificate)
}

struct ProvenReadOnlyStatement;

impl SideEffectOracle for ProvenReadOnlyStatement {
    fn statement_purity(&self, _base_objects: &[ObjectRef]) -> Purity {
        Purity::ProvenReadOnly
    }
}

#[test]
fn externally_rederives_a_sample_verdict_and_confirms_its_bound_audit_hash() {
    let sql = "SELECT 1 FROM dual";
    let (certificate, audit_record, key) = evidence_for(sql);

    let verified = verify_verdict(VerdictEvidence {
        sql,
        certificate: &certificate,
        audit_record: &audit_record,
        audit_keys: std::slice::from_ref(&key),
    })
    .expect("independent verifier must accept matching evidence");

    assert_eq!(verified.danger, DangerLevel::Safe);
    assert_eq!(verified.required_level, Some(OperatingLevel::ReadOnly));
    assert_eq!(verified.audit_entry_hash, audit_record.entry_hash);
    assert_eq!(verified.observed_scn, Some(42_000_001));
}

#[test]
fn externally_rederives_a_live_proven_base_read_without_weakening_admission() {
    let sql = "SELECT id FROM app.orders";
    let certificate = Classifier::default()
        .with_oracle(Arc::new(ProvenReadOnlyStatement))
        .classify(sql)
        .verdict_certificate()
        .clone();
    assert_eq!(certificate.verdict, DangerLevel::Safe);
    let (certificate, audit_record, key) = evidence_for_certificate(sql, certificate);

    let verified = verify_verdict(VerdictEvidence {
        sql,
        certificate: &certificate,
        audit_record: &audit_record,
        audit_keys: std::slice::from_ref(&key),
    })
    .expect("offline verification must reproduce a dispatch certificate after live proof");

    assert_eq!(verified.danger, DangerLevel::Safe);
    assert_eq!(verified.required_level, Some(OperatingLevel::ReadOnly));
}

#[test]
fn rejects_a_tampered_certificate_without_trusting_the_server() {
    let sql = "SELECT 1 FROM dual";
    let (mut certificate, audit_record, key) = evidence_for(sql);
    certificate.derivation[0].construct = "final_verdict:FORBIDDEN".to_owned();

    let result = verify_verdict(VerdictEvidence {
        sql,
        certificate: &certificate,
        audit_record: &audit_record,
        audit_keys: std::slice::from_ref(&key),
    });

    assert_eq!(result, Err(VerdictVerificationError::DerivationMismatch));
}

#[test]
fn rejects_a_legacy_audit_schema_that_does_not_hash_certificate_evidence() {
    let sql = "SELECT 1 FROM dual";
    let (certificate, mut audit_record, key) = evidence_for(sql);
    audit_record.schema_version = 9;

    let result = verify_verdict(VerdictEvidence {
        sql,
        certificate: &certificate,
        audit_record: &audit_record,
        audit_keys: std::slice::from_ref(&key),
    });

    assert_eq!(
        result,
        Err(VerdictVerificationError::UnsupportedAuditSchema)
    );
}
