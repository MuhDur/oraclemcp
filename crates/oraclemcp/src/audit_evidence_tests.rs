//! Focused bounded-streaming tests for audit DB-evidence correlation.

use super::*;
use std::io::{Cursor, Read};

use oraclemcp_audit::{
    AuditDecision, AuditEntryDraft, AuditOutcome, AuditSubject, GENESIS_HASH, JsonlError,
    MAX_AUDIT_LINE_LEN, SigningKey,
};

fn key() -> SigningKey {
    SigningKey::new("test-key", b"db-evidence-streaming-key-123456789".to_vec())
        .expect("valid test key")
}

fn record(seq: u64, db_evidence: Option<DbEvidence>) -> AuditRecord {
    record_with_previous(seq, GENESIS_HASH, db_evidence)
}

fn record_with_previous(
    seq: u64,
    previous_hash: &str,
    db_evidence: Option<DbEvidence>,
) -> AuditRecord {
    let key = key();
    AuditRecord::chained_signed(
        &AuditEntryDraft {
            subject: AuditSubject::new("test", "subject-hash"),
            db_evidence,
            cancel: None,
            result_masking: None,
            tool: "oracle_execute".to_owned(),
            sql: "SELECT 1 FROM dual".to_owned(),
            danger_level: "READ_ONLY".to_owned(),
            decision: AuditDecision::Allowed,
            rows_affected: Some(0),
            outcome: AuditOutcome::Succeeded,
        },
        seq,
        previous_hash,
        format!("2026-09-17T00:00:{seq:02}Z"),
        &key,
    )
}

fn jsonl(records: &[AuditRecord]) -> Vec<u8> {
    let mut body = Vec::new();
    for record in records {
        serde_json::to_writer(&mut body, record).expect("record serializes");
        body.push(b'\n');
    }
    body
}

#[test]
fn streamed_summary_matches_slice_summary_and_caps_correlation_samples() {
    let mut previous_hash = GENESIS_HASH.to_owned();
    let records: Vec<_> = (1..=AUDIT_DB_EVIDENCE_SAMPLE_LIMIT as u64 + 8)
        .map(|seq| {
            let record = record_with_previous(
                seq,
                &previous_hash,
                Some(DbEvidence {
                    availability: Some("captured".to_owned()),
                    sid: Some(seq.to_string()),
                    serial_number: Some((seq + 10_000).to_string()),
                    client_identifier: Some(format!("operator-{seq}")),
                    ..DbEvidence::default()
                }),
            );
            previous_hash.clone_from(&record.entry_hash);
            record
        })
        .collect();

    let mut accumulator = AuditDbEvidenceSummaryAccumulator::new();
    let outcome =
        oraclemcp_audit::verify_reader_with(Cursor::new(jsonl(&records)), &[key()], |record| {
            accumulator.observe(record);
        })
        .expect("streamed signed records parse");
    assert!(matches!(outcome, oraclemcp_audit::VerifyOutcome::Ok { .. }));
    let streamed = accumulator.finish();
    let from_slice = audit_db_evidence_summary(&records);

    assert_eq!(streamed, from_slice);
    assert_eq!(streamed.records, records.len());
    assert_eq!(
        streamed.sample_correlations.len(),
        AUDIT_DB_EVIDENCE_SAMPLE_LIMIT
    );
    assert!(streamed.sample_truncated);
}

#[test]
fn verified_stream_rejects_an_oversized_line_without_retaining_it() {
    let oversized = vec![b'x'; MAX_AUDIT_LINE_LEN + 1];
    let error = oraclemcp_audit::verify_reader_with(Cursor::new(oversized), &[key()], |_| {})
        .expect_err("oversized JSONL line is refused");

    assert!(matches!(error, JsonlError::Malformed(_)));
}

#[test]
fn verified_stream_does_not_expose_tampered_db_evidence_to_the_summary() {
    let mut tampered = record(
        1,
        Some(DbEvidence {
            availability: Some("captured".to_owned()),
            sid: Some("trusted-session".to_owned()),
            serial_number: Some("42".to_owned()),
            ..DbEvidence::default()
        }),
    );
    tampered
        .db_evidence
        .as_mut()
        .expect("fixture has evidence")
        .sid = Some("forged-session".to_owned());
    let mut accumulator = AuditDbEvidenceSummaryAccumulator::new();

    let outcome =
        oraclemcp_audit::verify_reader_with(Cursor::new(jsonl(&[tampered])), &[key()], |record| {
            accumulator.observe(record)
        })
        .expect("tampering produces a verification verdict");

    assert!(matches!(
        outcome,
        oraclemcp_audit::VerifyOutcome::Broken {
            seq: 1,
            reason: oraclemcp_audit::BrokenReason::HashMismatch,
            ..
        }
    ));
    assert_eq!(accumulator.finish().records, 0);
}

#[test]
fn unavailable_reason_samples_are_bounded_and_truthfully_marked() {
    let records: Vec<_> = (1..=AUDIT_DB_EVIDENCE_UNAVAILABLE_REASON_LIMIT as u64 + 1)
        .map(|seq| record(seq, Some(DbEvidence::unavailable(format!("reason-{seq}")))))
        .collect();

    let summary = audit_db_evidence_summary(&records);
    assert_eq!(summary.unavailable, records.len());
    assert_eq!(
        summary.unavailable_reasons.len(),
        AUDIT_DB_EVIDENCE_UNAVAILABLE_REASON_LIMIT
    );
    assert!(summary.unavailable_reasons_truncated);
    assert_eq!(
        audit_db_evidence_payload(&summary)["unavailable_reasons_truncated"],
        serde_json::json!(true)
    );
    assert!(audit_db_evidence_text(&summary).contains("unavailable_reasons_truncated=true"));
}

#[cfg(unix)]
#[test]
fn audit_verification_input_rejects_links_and_fifos_and_keeps_one_opened_ledger() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("test directory");
    let audit = directory.path().join("audit.jsonl");
    let replacement = directory.path().join("replacement.jsonl");
    let moved = directory.path().join("moved-audit.jsonl");
    std::fs::write(&audit, b"original signed ledger\n").expect("seed ledger");

    let mut held = crate::open_audit_verification_file(&audit).expect("open regular ledger");
    std::fs::rename(&audit, &moved).expect("replace ledger path");
    std::fs::write(&replacement, b"replacement ledger\n").expect("seed replacement");
    std::fs::rename(&replacement, &audit).expect("install replacement ledger");
    let mut observed = Vec::new();
    held.read_to_end(&mut observed).expect("read held ledger");
    assert_eq!(observed, b"original signed ledger\n");

    let linked = directory.path().join("linked-audit.jsonl");
    symlink(&moved, &linked).expect("plant symlink");
    assert!(
        crate::open_audit_verification_file(&linked).is_err(),
        "audit verification must refuse a final-component symlink"
    );

    let fifo = directory.path().join("audit.fifo");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if made {
        assert!(
            crate::open_audit_verification_file(&fifo).is_err(),
            "audit verification must reject a FIFO without waiting for a writer"
        );
    }
}

#[cfg(unix)]
#[test]
fn audit_verify_anchor_check_refuses_a_parent_removed_after_primary_open() {
    let root = tempfile::tempdir().expect("test root");
    let audit_parent = root.path().join("audit-parent");
    let parked_parent = root.path().join("parked-audit-parent");
    std::fs::create_dir(&audit_parent).expect("create audit parent");
    let audit_path = audit_parent.join("audit.jsonl");
    let anchor_path = oraclemcp_audit::anchor_path_for(&audit_path);
    std::fs::write(&audit_path, b"signed ledger bytes\n").expect("seed regular primary");
    oraclemcp_audit::AnchorFile::new(&anchor_path, key())
        .record_head(1, "sha256:anchored-head")
        .expect("seed existing head anchor");

    let _opened_primary =
        crate::open_audit_verification_file(&audit_path).expect("open exact primary ledger");
    std::fs::rename(&audit_parent, &parked_parent)
        .expect("remove anchor parent after primary open");

    let error = oraclemcp_audit::load_anchor_for_open_audit_ledger(&anchor_path).expect_err(
        "audit verify must not turn an existing head anchor into a legacy absence after primary open",
    );
    assert!(
        error.to_string().contains("anchor parent is missing"),
        "unexpected error: {error}"
    );
    assert!(
        parked_parent.join("audit.jsonl.anchor").is_file(),
        "the refused configured path had a real anchored head before its parent was removed"
    );
}
