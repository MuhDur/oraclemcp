//! Audit `db_evidence` correlation summary for `oracle audit verify`.
//!
//! Pure data-shaping helpers (no I/O), relocated verbatim from `main.rs` so the
//! CLI flow there stays small. Summarizes DB-evidence capture/correlation across
//! already-signed `AuditRecord`s; it reports, it does not enforce. The three
//! `pub(crate)` entry points (`audit_db_evidence_summary` / `_payload` / `_text`)
//! are re-exported at the crate root and consumed by `run_audit_verify`.

use oraclemcp_audit::{AuditRecord, DbEvidence};

const DB_EVIDENCE_UNAVAILABLE_PREFIX: &str = "db_evidence_unavailable:";
const AUDIT_DB_EVIDENCE_SAMPLE_LIMIT: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuditDbEvidenceCorrelation {
    seq: u64,
    sid: Option<String>,
    serial_number: Option<String>,
    client_identifier: Option<String>,
    module: Option<String>,
    action: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuditDbEvidenceSummary {
    pub(crate) status: &'static str,
    pub(crate) degraded_reason: Option<&'static str>,
    pub(crate) records: usize,
    pub(crate) with_db_evidence: usize,
    pub(crate) captured: usize,
    pub(crate) unavailable: usize,
    pub(crate) missing: usize,
    pub(crate) correlated: usize,
    pub(crate) with_session_tags: usize,
    pub(crate) unavailable_reasons: Vec<String>,
    sample_correlations: Vec<AuditDbEvidenceCorrelation>,
    sample_limit: usize,
    sample_truncated: bool,
}

fn non_empty(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(|v| !v.trim().is_empty())
}

fn db_evidence_unavailable_reason(evidence: &DbEvidence) -> Option<&str> {
    evidence
        .availability
        .as_deref()
        .and_then(|availability| availability.strip_prefix(DB_EVIDENCE_UNAVAILABLE_PREFIX))
        .filter(|reason| !reason.is_empty())
}

fn db_evidence_has_captured_field(evidence: &DbEvidence) -> bool {
    [
        &evidence.db_unique_name,
        &evidence.service_name,
        &evidence.instance_name,
        &evidence.session_user,
        &evidence.current_user,
        &evidence.proxy_user,
        &evidence.current_schema,
        &evidence.sid,
        &evidence.serial_number,
        &evidence.client_identifier,
        &evidence.module,
        &evidence.action,
        &evidence.database_role,
        &evidence.open_mode,
    ]
    .iter()
    .any(|value| non_empty(value))
}

fn db_evidence_is_captured(evidence: &DbEvidence) -> bool {
    evidence.availability.as_deref() == Some("captured") || db_evidence_has_captured_field(evidence)
}

fn db_evidence_has_session_correlation(evidence: &DbEvidence) -> bool {
    let has_sid_serial = non_empty(&evidence.sid) && non_empty(&evidence.serial_number);
    let has_session_tag = non_empty(&evidence.client_identifier)
        || non_empty(&evidence.module)
        || non_empty(&evidence.action);
    has_sid_serial || has_session_tag
}

fn db_evidence_has_session_tag(evidence: &DbEvidence) -> bool {
    non_empty(&evidence.client_identifier)
        || non_empty(&evidence.module)
        || non_empty(&evidence.action)
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_owned());
    }
}

pub(crate) fn audit_db_evidence_summary(records: &[AuditRecord]) -> AuditDbEvidenceSummary {
    let mut summary = AuditDbEvidenceSummary {
        status: "degraded",
        degraded_reason: None,
        records: records.len(),
        with_db_evidence: 0,
        captured: 0,
        unavailable: 0,
        missing: 0,
        correlated: 0,
        with_session_tags: 0,
        unavailable_reasons: Vec::new(),
        sample_correlations: Vec::new(),
        sample_limit: AUDIT_DB_EVIDENCE_SAMPLE_LIMIT,
        sample_truncated: false,
    };

    for record in records {
        let Some(evidence) = record.db_evidence.as_ref() else {
            summary.missing += 1;
            continue;
        };
        summary.with_db_evidence += 1;
        if let Some(reason) = db_evidence_unavailable_reason(evidence) {
            summary.unavailable += 1;
            push_unique(&mut summary.unavailable_reasons, reason);
            continue;
        }
        if db_evidence_is_captured(evidence) {
            summary.captured += 1;
        }
        if db_evidence_has_session_tag(evidence) {
            summary.with_session_tags += 1;
        }
        if db_evidence_has_session_correlation(evidence) {
            summary.correlated += 1;
            if summary.sample_correlations.len() < AUDIT_DB_EVIDENCE_SAMPLE_LIMIT {
                summary
                    .sample_correlations
                    .push(AuditDbEvidenceCorrelation {
                        seq: record.seq,
                        sid: evidence.sid.clone(),
                        serial_number: evidence.serial_number.clone(),
                        client_identifier: evidence.client_identifier.clone(),
                        module: evidence.module.clone(),
                        action: evidence.action.clone(),
                    });
            } else {
                summary.sample_truncated = true;
            }
        }
    }

    if summary.correlated > 0 {
        summary.status = "correlated";
    } else {
        summary.degraded_reason = Some(if summary.records == 0 {
            "no_records"
        } else if summary.with_db_evidence == 0 {
            "no_db_evidence"
        } else if summary.captured == 0 && summary.unavailable > 0 {
            "db_evidence_unavailable"
        } else {
            "db_evidence_missing_session_tags"
        });
    }
    summary
}

pub(crate) fn audit_db_evidence_payload(summary: &AuditDbEvidenceSummary) -> serde_json::Value {
    let sample_correlations: Vec<_> = summary
        .sample_correlations
        .iter()
        .map(|correlation| {
            serde_json::json!({
                "seq": correlation.seq,
                "sid": correlation.sid,
                "serial_number": correlation.serial_number,
                "client_identifier": correlation.client_identifier,
                "module": correlation.module,
                "action": correlation.action,
            })
        })
        .collect();
    serde_json::json!({
        "status": summary.status,
        "degraded_reason": summary.degraded_reason,
        "source": "signed_audit_records",
        "live_database_query": false,
        "records": summary.records,
        "with_db_evidence": summary.with_db_evidence,
        "captured": summary.captured,
        "unavailable": summary.unavailable,
        "missing": summary.missing,
        "correlated": summary.correlated,
        "with_session_tags": summary.with_session_tags,
        "unavailable_reasons": summary.unavailable_reasons,
        "sample_limit": summary.sample_limit,
        "sample_truncated": summary.sample_truncated,
        "sample_correlations": sample_correlations,
    })
}

pub(crate) fn audit_db_evidence_text(summary: &AuditDbEvidenceSummary) -> String {
    let reason = summary
        .degraded_reason
        .map(|reason| format!(" reason={reason}"))
        .unwrap_or_default();
    format!(
        "DB evidence {}:{} correlated={}/{} captured={} unavailable={} missing={} session_tags={}",
        summary.status.to_ascii_uppercase(),
        reason,
        summary.correlated,
        summary.records,
        summary.captured,
        summary.unavailable,
        summary.missing,
        summary.with_session_tags
    )
}
