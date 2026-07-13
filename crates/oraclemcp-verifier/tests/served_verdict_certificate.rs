#![forbid(unsafe_code)]

//! External verification bridge for the served Arc-B E2E scenario.
//!
//! The scenario starts a real `oraclemcp serve` process and writes a private,
//! ephemeral evidence bundle from its HTTP audit-tail response. This test is
//! deliberately in the standalone verifier crate: it consumes the redacted
//! certificate plus the exact server-marked statement it authenticated, rather
//! than reaching into the server dispatcher.

use std::env;
use std::fs;
use std::path::PathBuf;

use oraclemcp_audit::{AuditRecord, SigningKey};
use oraclemcp_guard::VerdictCertificate;
use oraclemcp_verifier::{VerdictEvidence, VerdictVerificationError, verify_verdict};
use serde_json::Value;

const EVIDENCE_ENV: &str = "E2E_VERDICT_CERTIFICATE_EVIDENCE";
const AUDIT_KEY_ENV: &str = "E2E_VERDICT_CERTIFICATE_AUDIT_KEY";

struct ServedEvidence {
    sql: String,
    certificate: VerdictCertificate,
    audit_record: AuditRecord,
    audit_key: SigningKey,
}

fn load_served_evidence() -> Option<ServedEvidence> {
    let path = PathBuf::from(env::var_os(EVIDENCE_ENV)?);
    let key_material = env::var(AUDIT_KEY_ENV)
        .expect("served verdict E2E must provide its private audit key through the environment");
    let raw = fs::read_to_string(&path)
        .expect("served verdict E2E must provide a readable private evidence bundle");
    let bundle: Value =
        serde_json::from_str(&raw).expect("served verdict E2E evidence bundle must be valid JSON");

    let sql = bundle
        .get("sql")
        .and_then(Value::as_str)
        .expect("served verdict E2E evidence must name the exact server-classified SQL")
        .to_owned();
    let certificate = serde_json::from_value(
        bundle
            .get("certificate")
            .cloned()
            .expect("served verdict E2E evidence must contain the wire certificate"),
    )
    .expect("wire certificate must match the standalone verifier schema");
    let audit_record = serde_json::from_value(
        bundle
            .get("audit_record")
            .cloned()
            .expect("served verdict E2E evidence must contain the signed audit record"),
    )
    .expect("persisted signed audit record must match the verifier schema");
    let key_id = bundle
        .get("audit_key_id")
        .and_then(Value::as_str)
        .expect("served verdict E2E evidence must name its audit key");
    let audit_key = SigningKey::new(key_id, key_material.into_bytes())
        .expect("served verdict E2E audit key must be accepted by the verifier");

    Some(ServedEvidence {
        sql,
        certificate,
        audit_record,
        audit_key,
    })
}

#[test]
fn served_wire_certificate_verifies_against_its_signed_audit_record() {
    let Some(evidence) = load_served_evidence() else {
        return;
    };

    assert_eq!(
        evidence.certificate.bound_audit_hash.as_deref(),
        Some(evidence.audit_record.entry_hash.as_str()),
        "the certificate received from the served audit-tail must name this signed record"
    );
    verify_verdict(VerdictEvidence {
        sql: &evidence.sql,
        certificate: &evidence.certificate,
        audit_record: &evidence.audit_record,
        audit_keys: std::slice::from_ref(&evidence.audit_key),
    })
    .expect("the standalone verifier must accept the real served certificate evidence");
}

#[test]
fn standalone_verifier_rejects_a_tampered_served_wire_certificate() {
    let Some(mut evidence) = load_served_evidence() else {
        return;
    };
    let terminal = evidence
        .certificate
        .derivation
        .last_mut()
        .expect("served certificate must have a terminal derivation step");
    terminal.construct = "final_verdict:FORBIDDEN".to_owned();

    let result = verify_verdict(VerdictEvidence {
        sql: &evidence.sql,
        certificate: &evidence.certificate,
        audit_record: &evidence.audit_record,
        audit_keys: std::slice::from_ref(&evidence.audit_key),
    });
    assert_eq!(
        result,
        Err(VerdictVerificationError::DerivationMismatch),
        "a modified wire certificate must never become trusted evidence"
    );
}
