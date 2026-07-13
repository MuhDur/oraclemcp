#![forbid(unsafe_code)]

//! Standalone verification for a redacted guard verdict certificate.
//!
//! This crate intentionally has no dependency on the `oraclemcp` server, its
//! dispatcher, a database connection, or server configuration. An independent
//! verifier supplies the exact SQL, certificate, signed audit record, and its
//! own trusted audit keys. The verifier reruns the self-contained classifier
//! rules, recomputes the certificate core, and rejects every disagreement.
//!
//! Certificates whose verdict depends on a server-only live purity oracle are
//! deliberately rejected when this self-contained re-derivation differs. A
//! false positive is safer than treating an unverifiable server claim as proof.

use oraclemcp_audit::{AUDIT_SCHEMA_VERSION, AuditRecord, SigningKey, sha256_hex};
use oraclemcp_guard::{
    Classifier, DangerLevel, OperatingLevel, VERDICT_CERTIFICATE_CLASSIFIER_VERSION,
    VerdictCertificate,
};
use thiserror::Error;

/// All evidence an independent verifier needs to check one certificate.
pub struct VerdictEvidence<'a> {
    /// Exact statement bytes to re-classify. They never enter the output.
    pub sql: &'a str,
    /// Agent-visible certificate to verify.
    pub certificate: &'a VerdictCertificate,
    /// The audit record named by the certificate's `bound_audit_hash`.
    pub audit_record: &'a AuditRecord,
    /// Independently obtained, trusted audit signing keys.
    pub audit_keys: &'a [SigningKey],
}

/// The independently re-derived verdict after all certificate and audit checks pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedVerdict {
    /// Re-derived risk verdict.
    pub danger: DangerLevel,
    /// Re-derived required operating level.
    pub required_level: Option<OperatingLevel>,
    /// The authenticated audit record that bound the certificate.
    pub audit_entry_hash: String,
    /// Snapshot SCN, when the certificate and audit record both attest to one.
    pub observed_scn: Option<u64>,
}

/// A certificate or audit fact failed independent verification.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerdictVerificationError {
    /// The certificate was produced by an unknown classifier/registry version.
    #[error("certificate classifier version is not supported by this verifier")]
    UnsupportedClassifierVersion,
    /// The exact SQL bytes do not match the certificate's digest.
    #[error("certificate statement digest does not match supplied SQL")]
    StatementDigestMismatch,
    /// Re-running the classifier produced a different verdict or level.
    #[error("certificate verdict does not match independent classification")]
    VerdictMismatch,
    /// Re-running the classifier produced different redacted derivation facts.
    #[error("certificate derivation does not match independent classification")]
    DerivationMismatch,
    /// The certificate's SCN is not the audit record's observed SCN.
    #[error("certificate SCN does not match the audit record")]
    ObservedScnMismatch,
    /// The audit record does not describe the exact SQL named by the certificate.
    #[error("audit record SQL digest does not match the certificate")]
    AuditSqlDigestMismatch,
    /// The certificate does not name this audit record.
    #[error("certificate bound audit hash does not match the audit record")]
    BoundAuditHashMismatch,
    /// The audit record does not contain this certificate's core hash.
    #[error("audit record certificate core hash does not match the certificate")]
    AuditCertificateCoreHashMismatch,
    /// The audit record predates (or postdates) the certificate-aware hash schema.
    #[error("audit record schema does not authenticate certificate evidence")]
    UnsupportedAuditSchema,
    /// The audit record's unkeyed chain hash cannot be recomputed.
    #[error("audit record hash is invalid")]
    AuditRecordHashInvalid,
    /// The audit record is unsigned or does not identify its signing key.
    #[error("audit record is missing its signing-key identity")]
    MissingAuditKeyIdentity,
    /// No externally trusted key matches the record's claimed key identity.
    #[error("audit record key is not in the verifier's trusted key set")]
    UntrustedAuditKey,
    /// The selected trusted audit key cannot verify the record's MAC.
    #[error("audit record signature is invalid")]
    AuditSignatureInvalid,
}

/// Independently re-run the classifier and authenticate the certificate binding.
///
/// The return value is deliberately small and contains no SQL, bind, or object
/// identifier material. On every mismatch this function returns an error; it
/// never falls back to the server's asserted certificate verdict.
pub fn verify_verdict(
    evidence: VerdictEvidence<'_>,
) -> Result<VerifiedVerdict, VerdictVerificationError> {
    let VerdictEvidence {
        sql,
        certificate,
        audit_record,
        audit_keys,
    } = evidence;

    if certificate.classifier_version != VERDICT_CERTIFICATE_CLASSIFIER_VERSION {
        return Err(VerdictVerificationError::UnsupportedClassifierVersion);
    }
    if certificate.stmt_digest != sha256_hex(sql.as_bytes()) {
        return Err(VerdictVerificationError::StatementDigestMismatch);
    }

    let expected = Classifier::default().classify(sql);
    let expected_certificate = expected.verdict_certificate();
    if certificate.level != expected_certificate.level
        || certificate.verdict != expected_certificate.verdict
    {
        return Err(VerdictVerificationError::VerdictMismatch);
    }
    if certificate.derivation != expected_certificate.derivation {
        return Err(VerdictVerificationError::DerivationMismatch);
    }

    let expected_observed_scn = audit_record.observed_scn.map(|scn| scn.to_string());
    if certificate.observed_scn != expected_observed_scn {
        return Err(VerdictVerificationError::ObservedScnMismatch);
    }
    if audit_record.sql_sha256 != certificate.stmt_digest {
        return Err(VerdictVerificationError::AuditSqlDigestMismatch);
    }
    if certificate.bound_audit_hash.as_deref() != Some(audit_record.entry_hash.as_str()) {
        return Err(VerdictVerificationError::BoundAuditHashMismatch);
    }
    if audit_record.schema_version != AUDIT_SCHEMA_VERSION {
        return Err(VerdictVerificationError::UnsupportedAuditSchema);
    }
    let certificate_core_hash = certificate.core_hash();
    if audit_record.verdict_certificate_core_hash.as_deref() != Some(certificate_core_hash.as_str())
    {
        return Err(VerdictVerificationError::AuditCertificateCoreHashMismatch);
    }
    if !audit_record.hash_is_valid() {
        return Err(VerdictVerificationError::AuditRecordHashInvalid);
    }

    let key_id = audit_record
        .key_id
        .as_deref()
        .ok_or(VerdictVerificationError::MissingAuditKeyIdentity)?;
    let key = audit_keys
        .iter()
        .find(|key| key.key_id() == key_id)
        .ok_or(VerdictVerificationError::UntrustedAuditKey)?;
    if !audit_record.signature_is_valid(key) {
        return Err(VerdictVerificationError::AuditSignatureInvalid);
    }

    Ok(VerifiedVerdict {
        danger: expected.danger,
        required_level: expected.required_level,
        audit_entry_hash: audit_record.entry_hash.clone(),
        observed_scn: audit_record.observed_scn,
    })
}
