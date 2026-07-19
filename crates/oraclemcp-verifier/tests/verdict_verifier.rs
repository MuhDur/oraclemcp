use oraclemcp_audit::{
    AuditDecision, AuditEntryDraft, AuditOutcome, AuditRecord, AuditSubject, GENESIS_HASH,
    SigningKey,
};
use oraclemcp_guard::{Classifier, DangerLevel, OperatingLevel, VerdictCertificate};
use oraclemcp_verifier::{VerdictEvidence, VerdictVerificationError, verify_verdict};

fn test_key() -> SigningKey {
    SigningKey::new(
        "external-test",
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .expect("test key must be valid")
}

fn evidence_for(sql: &str) -> (VerdictCertificate, AuditRecord, SigningKey) {
    let certificate = Classifier::default()
        .classify(sql)
        .verdict_certificate()
        .clone()
        .with_observed_scn(Some(42_000_001));
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

#[derive(Clone, Copy, Debug)]
enum VerdictTamper {
    FlippedVerdict,
    WrongStatementSha,
    ForgedAuditMac,
    Derivation,
}

#[test]
fn verifier_tamper_matrix_rejects_each_mutation_with_the_exact_error() {
    let rows = [
        (
            "flipped_verdict",
            VerdictTamper::FlippedVerdict,
            VerdictVerificationError::VerdictMismatch,
        ),
        (
            "wrong_statement_sha",
            VerdictTamper::WrongStatementSha,
            VerdictVerificationError::StatementDigestMismatch,
        ),
        (
            "forged_audit_mac",
            VerdictTamper::ForgedAuditMac,
            VerdictVerificationError::AuditSignatureInvalid,
        ),
        (
            "changed_derivation",
            VerdictTamper::Derivation,
            VerdictVerificationError::DerivationMismatch,
        ),
    ];
    let sql = "SELECT 1 FROM dual";

    for (name, tamper, expected) in rows {
        // Reuse the same real classifier -> certificate -> signed audit fixture
        // as the acceptance test. Only the named evidence field is changed.
        let (mut certificate, mut audit_record, key) = evidence_for(sql);
        match tamper {
            VerdictTamper::FlippedVerdict => certificate.verdict = DangerLevel::Forbidden,
            VerdictTamper::WrongStatementSha => {
                certificate.stmt_digest = format!("sha256:{}", "0".repeat(64));
            }
            VerdictTamper::ForgedAuditMac => {
                audit_record.signature = Some(format!("hmac-sha256:{}", "0".repeat(64)));
            }
            VerdictTamper::Derivation => {
                certificate.derivation[0].construct = "final_verdict:FORBIDDEN".to_owned();
            }
        }

        let result = verify_verdict(VerdictEvidence {
            sql,
            certificate: &certificate,
            audit_record: &audit_record,
            audit_keys: std::slice::from_ref(&key),
        });

        assert_eq!(result, Err(expected), "tamper row {name}");
    }
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
