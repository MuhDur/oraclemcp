//! Hash-only impact binding at the two approval revalidation checkpoints.
use super::*;

/// Checkpoint immediately preceding the named irreversible step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditRevalidationStage {
    /// Current facts matched before the single-use grant was removed.
    BeforeConsume,
    /// Current facts matched immediately before the candidate database call.
    BeforeExecute,
}

/// Redaction-safe approval fingerprints. Never contains SQL or bind values.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditImpactBinding {
    /// Exact caller statement digest, before any audit marker is inserted.
    pub statement_digest: String,
    /// Canonical decisive impact digest.
    pub decisive_digest: String,
    /// The completed fact checkpoint.
    pub revalidated_at: AuditRevalidationStage,
}

pub(super) fn bind_impact_v14(
    content_hash: &str,
    statement_digest: Option<&str>,
    decisive_digest: Option<&str>,
    revalidated_at: Option<AuditRevalidationStage>,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"oraclemcp:audit-entry-hash:v14\n");
    hash_str(&mut hash, content_hash);
    hash_opt_str(&mut hash, statement_digest);
    hash_opt_str(&mut hash, decisive_digest);
    hash.update([match revalidated_at {
        None => 0,
        Some(AuditRevalidationStage::BeforeConsume) => 1,
        Some(AuditRevalidationStage::BeforeExecute) => 2,
    }]);
    let mut out = String::from("sha256:");
    for byte in hash.finalize() {
        push_hex_byte(&mut out, byte);
    }
    out
}

impl AuditRecord {
    pub(crate) fn bind_impact(mut self, impact: AuditImpactBinding, key: &SigningKey) -> Self {
        self.statement_digest = Some(impact.statement_digest);
        self.decisive_digest = Some(impact.decisive_digest);
        self.revalidated_at = Some(impact.revalidated_at);
        let content_hash = compute_entry_hash_v12(
            self.seq,
            &self.timestamp,
            &self.agent_identity,
            &self.subject,
            self.db_evidence.as_ref(),
            self.cancel.as_ref(),
            self.correlation.as_ref(),
            self.result_masking.as_ref(),
            self.observed_scn,
            self.verdict_certificate_core_hash.as_deref(),
            &self.tool,
            &self.sql_sha256,
            &self.sql_normalized_sha256,
            &self.sql_preview,
            &self.danger_level,
            self.decision,
            self.rows_affected,
            self.outcome,
            &self.prev_hash,
            self.failure.as_ref(),
        );
        let content_hash = bind_view_proofs_v13(&content_hash, self.db_evidence.as_ref());
        self.entry_hash = bind_impact_v14(
            &content_hash,
            self.statement_digest.as_deref(),
            self.decisive_digest.as_deref(),
            self.revalidated_at,
        );
        self.signature = Some(key.sign(&self.entry_hash));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn impact_digest_validation_refuses_raw_values_before_append() {
        let key = SigningKey::new("impact", vec![7; 32]).unwrap();
        let auditor = crate::Auditor::new(Box::new(crate::MemoryAuditSink::new()), key.clone());
        let draft = AuditEntryDraft {
            subject: AuditSubject::new("test", "subject"),
            db_evidence: None,
            cancel: None,
            result_masking: None,
            tool: "oracle_execute".into(),
            sql: "UPDATE app.t SET n=1 WHERE id=2".into(),
            danger_level: "GUARDED".into(),
            decision: AuditDecision::Allowed,
            rows_affected: None,
            outcome: AuditOutcome::Pending,
        };
        let impact = AuditImpactBinding {
            statement_digest: sha256_hex(draft.sql.as_bytes()),
            decisive_digest: sha256_hex(b"decisive facts"),
            revalidated_at: AuditRevalidationStage::BeforeExecute,
        };
        let mut invalid = impact.clone();
        invalid.decisive_digest = "synthetic-raw-bind-canary".into();
        assert!(matches!(
            auditor.append_with_impact(&draft, "t0".into(), true, invalid, None, None),
            Err(crate::AuditError::InvalidImpactBinding)
        ));
        let record = auditor
            .append_with_impact(&draft, "t1".into(), true, impact, None, None)
            .unwrap();
        assert_eq!(record.seq, 1);
        assert_eq!(record.schema_version, 14);
        assert!(record.hash_is_valid());
        assert!(record.signature_is_valid(&key));
        let mut changed = record.clone();
        changed.statement_digest = None;
        assert!(!changed.hash_is_valid());
        let mut changed = record.clone();
        changed.decisive_digest = None;
        assert!(!changed.hash_is_valid());
        let mut changed = record.clone();
        changed.revalidated_at = Some(AuditRevalidationStage::BeforeConsume);
        assert!(!changed.hash_is_valid());
        let mut changed = record;
        changed.schema_version = 13;
        assert!(!changed.hash_is_valid());
    }
}
