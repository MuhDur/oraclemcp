//! E3 — audit hash-chain end to end, treated as a SECURITY property.
//!
//! The chain is what makes a privileged action non-repudiable. If it can be
//! truncated, reordered, or have an entry silently dropped without detection,
//! then the audit trail is decorative and every "we can prove what happened"
//! claim built on it is false.
//!
//! So these are adversarial tests, not logging tests. Appending three records
//! and verifying the chain would prove none of the properties below: a chain
//! walker that returned `Ok` unconditionally passes that test.
//!
//! Everything here runs against REAL FILES — the JSONL log written by
//! `FileAuditSink` and the `.anchor` sidecar — because that is the layer an
//! attacker (or a bad flush) actually touches. The in-crate unit tests already
//! cover the in-memory `Vec<AuditRecord>` shapes; truncating a file is not the
//! same operation as popping a vector, and only one of them is the threat.
//!
//! The central pair is [`tail_truncation_is_invisible_to_the_chain_and_caught_by_the_anchor`]:
//! a truncated chain is still a VALID chain, so hash-linking alone reports `Ok`.
//! That is not a bug — it is why the anchor exists — but it means any claim of
//! truncation detection that cites only `verify_records` is wrong.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};

use oraclemcp_audit::{
    AnchorStatus, AnchorViolation, AuditDecision, AuditEntryDraft, AuditOutcome, AuditSubject,
    Auditor, BrokenReason, FileAuditSink, SigningKey, VerifyOutcome, anchor_path_for, check_anchor,
    load_anchor, parse_jsonl, verify_records,
};

fn key() -> SigningKey {
    SigningKey::new("k1", b"0123456789abcdef0123456789abcdef".to_vec()).expect("valid test key")
}

fn draft(sql: &str) -> AuditEntryDraft {
    AuditEntryDraft {
        subject: AuditSubject::new("agent", "agent"),
        db_evidence: None,
        cancel: None,
        result_masking: None,
        tool: "oracle_execute".to_owned(),
        sql: sql.to_owned(),
        danger_level: "GUARDED".to_owned(),
        decision: AuditDecision::Allowed,
        rows_affected: None,
        outcome: AuditOutcome::Pending,
    }
}

/// Write `n` durable privileged records through the real file sink and its
/// anchor sidecar, then drop the auditor so the writer lock is released and the
/// bytes on disk are all that remain — the state a verifier actually inspects.
fn write_chain(dir: &Path, n: usize) -> (PathBuf, PathBuf) {
    let audit_path = dir.join("audit.jsonl");
    let anchor_path = anchor_path_for(&audit_path);
    {
        let sink = FileAuditSink::open(&audit_path).expect("open audit log");
        let auditor = Auditor::new(Box::new(sink), key()).with_head_anchor(anchor_path.clone());
        for i in 0..n {
            auditor
                .append(
                    &draft(&format!("DELETE FROM t WHERE id={i}")),
                    format!("2026-07-21T00:00:{i:02}Z"),
                    true, // durable: a privileged action is logged before it runs
                )
                .expect("append");
        }
    }
    (audit_path, anchor_path)
}

fn read_records(audit_path: &Path) -> Vec<oraclemcp_audit::AuditRecord> {
    parse_jsonl(&fs::read_to_string(audit_path).expect("read audit log")).expect("parse jsonl")
}

/// Rewrite the log from raw lines, which is how every tamper below is applied:
/// an attacker edits bytes, they do not call our API.
fn write_lines(audit_path: &Path, lines: &[String]) {
    let mut body = lines.join("\n");
    body.push('\n');
    fs::write(audit_path, body).expect("rewrite audit log");
}

fn lines_of(audit_path: &Path) -> Vec<String> {
    fs::read_to_string(audit_path)
        .expect("read audit log")
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The control for every test below. If an intact chain did not verify, each
/// "tamper is detected" assertion would pass for the wrong reason.
#[test]
fn an_intact_chain_verifies_and_matches_its_anchor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (audit_path, anchor_path) = write_chain(dir.path(), 4);

    let records = read_records(&audit_path);
    assert_eq!(
        verify_records(&records, &[key()]),
        VerifyOutcome::Ok { records: 4 }
    );

    let anchor = load_anchor(&anchor_path)
        .expect("load anchor")
        .expect("anchor sidecar present after durable appends");
    assert_eq!(
        check_anchor(&records, &anchor, &[key()]),
        Ok(AnchorStatus::Match)
    );
}

/// ACCEPTANCE: the anchor sidecar round-trips. It must name the durable head and
/// carry a MAC that verifies under the signing key — an anchor that did not
/// authenticate could simply be rewritten for the shortened chain.
#[test]
fn the_anchor_sidecar_round_trips_and_names_the_durable_head() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (audit_path, anchor_path) = write_chain(dir.path(), 3);

    let records = read_records(&audit_path);
    let head = records.last().expect("head record");
    let anchor = load_anchor(&anchor_path)
        .expect("load anchor")
        .expect("anchor present");

    assert_eq!(anchor.seq, head.seq, "anchor names the durable head seq");
    assert_eq!(
        anchor.entry_hash, head.entry_hash,
        "anchor names the durable head hash"
    );
    assert!(
        anchor.mac_is_valid(&key()),
        "an anchor whose MAC does not verify could be forged for a shorter chain"
    );
}

/// TAMPER MID-CHAIN. Verification must fail AND say where: an operator holding a
/// broken chain needs the offending record, not a boolean.
#[test]
fn an_edited_record_mid_chain_is_detected_and_located() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (audit_path, _) = write_chain(dir.path(), 5);

    let mut lines = lines_of(&audit_path);
    assert_eq!(lines.len(), 5);
    // Rewrite history: make the third record claim a different tool while
    // leaving its recorded hash untouched.
    //
    // NOT the SQL text — a v6+ record stores `sql_sha256` and a REDACTED
    // `sql_preview`, never the statement, so editing the statement text edits
    // nothing. That first attempt silently changed no bytes and the chain
    // verified Ok, which is how a tamper test can pass while proving nothing.
    // Hence the assertion below: the tamper must be observable in the file
    // before its detection means anything.
    let before = lines[2].clone();
    lines[2] = lines[2].replace("oracle_execute", "oracle_drop_table");
    assert_ne!(
        lines[2], before,
        "the tamper changed no bytes — this test would pass without the chain \
         detecting anything at all"
    );
    write_lines(&audit_path, &lines);

    let records = read_records(&audit_path);
    match verify_records(&records, &[key()]) {
        VerifyOutcome::Broken { seq, index, reason } => {
            assert_eq!(index, 2, "the report must name the edited record's index");
            assert_eq!(seq, 3, "the report must name the edited record's seq");
            assert_eq!(
                reason,
                BrokenReason::HashMismatch,
                "an in-place edit breaks the record's own hash first"
            );
        }
        other => panic!("an edited record must not verify: {other:?}"),
    }
}

/// AN ENTRY SILENTLY DROPPED from the middle. The remaining records are each
/// individually intact, so only the LINK between them can reveal the deletion.
#[test]
fn a_dropped_record_mid_chain_is_detected_and_located() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (audit_path, _) = write_chain(dir.path(), 5);

    let mut lines = lines_of(&audit_path);
    lines.remove(2); // the seq=3 record never happened, as far as the file says
    write_lines(&audit_path, &lines);

    let records = read_records(&audit_path);
    match verify_records(&records, &[key()]) {
        VerifyOutcome::Broken { index, reason, .. } => {
            assert_eq!(
                index, 2,
                "detection must land at the gap, not at the end of the file"
            );
            assert!(
                matches!(
                    reason,
                    BrokenReason::PrevHashMismatch | BrokenReason::SeqNotMonotonic { .. }
                ),
                "a removed record must break the link or the sequence, got {reason:?}"
            );
        }
        other => panic!("a dropped record must not verify: {other:?}"),
    }
}

/// REORDERING. Both records are authentic and signed; only their ORDER is a lie.
#[test]
fn reordered_records_are_detected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (audit_path, _) = write_chain(dir.path(), 5);

    let mut lines = lines_of(&audit_path);
    lines.swap(1, 3);
    write_lines(&audit_path, &lines);

    let records = read_records(&audit_path);
    assert!(
        !matches!(verify_records(&records, &[key()]), VerifyOutcome::Ok { .. }),
        "reordering authentic records must not verify: the chain asserts an order"
    );
}

/// THE CENTRAL PAIR — tail truncation.
///
/// A prefix of a valid hash chain is itself a valid hash chain, so the chain
/// walker alone CANNOT tell "nothing happened after seq=2" from "the evidence of
/// what happened after seq=2 was deleted". This test asserts both halves: that
/// `verify_records` reports Ok on the truncated file (so nobody cites it as
/// truncation detection), and that the anchor catches it and says how much is
/// missing.
#[test]
fn tail_truncation_is_invisible_to_the_chain_and_caught_by_the_anchor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (audit_path, anchor_path) = write_chain(dir.path(), 5);

    let anchor = load_anchor(&anchor_path)
        .expect("load anchor")
        .expect("anchor present");

    let mut lines = lines_of(&audit_path);
    lines.truncate(2); // delete the last three records
    write_lines(&audit_path, &lines);

    let records = read_records(&audit_path);

    // Half one: the chain itself is satisfied. This is the gap being closed.
    assert_eq!(
        verify_records(&records, &[key()]),
        VerifyOutcome::Ok { records: 2 },
        "a truncated chain is still a valid chain — if this ever fails, the \
         anchor's reason for existing has changed and the docs must follow"
    );

    // Half two: the anchor refuses, and quantifies the loss.
    assert_eq!(
        check_anchor(&records, &anchor, &[key()]),
        Err(AnchorViolation::Truncated {
            anchor_seq: 5,
            chain_records: 2,
        }),
        "the anchor must detect trailing records being removed"
    );
}

/// Truncation to nothing at all — the "delete the whole file" case, which must
/// not read as "this system never did anything privileged".
#[test]
fn truncation_to_an_empty_log_is_detected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (audit_path, anchor_path) = write_chain(dir.path(), 3);
    let anchor = load_anchor(&anchor_path)
        .expect("load anchor")
        .expect("anchor present");

    fs::write(&audit_path, "").expect("truncate to empty");

    let records = read_records(&audit_path);
    assert!(records.is_empty());
    assert_eq!(
        check_anchor(&records, &anchor, &[key()]),
        Err(AnchorViolation::Truncated {
            anchor_seq: 3,
            chain_records: 0,
        })
    );
}

/// Re-signing the anchor for the shortened chain is the obvious next move once
/// truncation is caught, so the anchor MAC must not verify under a key the
/// attacker does not hold.
#[test]
fn an_anchor_forged_with_the_wrong_key_does_not_verify() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (audit_path, anchor_path) = write_chain(dir.path(), 3);

    let forged_key =
        SigningKey::new("k1", b"ffffffffffffffffffffffffffffffff".to_vec()).expect("key");
    let records = read_records(&audit_path);
    let truncated = &records[..1];

    // The attacker rewrites the anchor to name the shortened head, using a key
    // they control but that the verifier does not trust.
    let forged = oraclemcp_audit::ChainAnchor::signed(
        truncated[0].seq,
        &truncated[0].entry_hash,
        &forged_key,
    );
    assert!(
        !forged.mac_is_valid(&key()),
        "an anchor signed with another key must not verify under the real key"
    );
    assert_eq!(
        check_anchor(truncated, &forged, &[key()]),
        Err(AnchorViolation::MacMismatch),
        "a forged anchor must be refused, not accepted as a shorter history"
    );

    // And the real anchor still names the full chain.
    let real = load_anchor(&anchor_path).expect("load").expect("present");
    assert_eq!(real.seq, 3);
}

/// ACCEPTANCE: privileged-action inventory cross-checked against chain entries.
///
/// "Record everything" is not proven by appending N records and verifying the
/// chain — a sink that silently dropped every other record would still produce
/// a valid chain from what remained. The property under test is that an
/// INDEPENDENT inventory of what the operator did (built outside the audit path)
/// reconciles one-to-one with what the chain contains: every action is present,
/// none is missing, none is extra, and the sequence is gap-free.
#[test]
fn privileged_action_inventory_reconciles_against_chain_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.jsonl");
    let anchor_path = anchor_path_for(&audit_path);

    // Build an independent inventory of privileged actions BEFORE they enter the
    // audit path — this is the operator's record of what they did.
    let inventory: Vec<(&str, &str)> = vec![
        ("oracle_execute", "DELETE FROM employees WHERE dept_id = 42"),
        (
            "oracle_compile_object",
            "ALTER PACKAGE hr.emp_pkg COMPILE BODY",
        ),
        (
            "oracle_create_or_replace",
            "CREATE OR REPLACE VIEW v AS SELECT 1 FROM dual",
        ),
        (
            "oracle_execute",
            "UPDATE payroll SET amount = 0 WHERE emp_id = 7",
        ),
        (
            "oracle_set_session_level",
            "ALTER SESSION SET optimizer_mode = ALL_ROWS",
        ),
    ];

    {
        let sink = FileAuditSink::open(&audit_path).expect("open audit log");
        let auditor = Auditor::new(Box::new(sink), key()).with_head_anchor(anchor_path.clone());
        for (i, (tool, sql)) in inventory.iter().enumerate() {
            let mut d = draft(sql);
            d.tool = tool.to_string();
            auditor
                .append(&d, format!("2026-07-22T00:00:{i:02}Z"), true)
                .expect("append");
        }
    }

    // Read back the chain from disk — the state a verifier inspects.
    let records = read_records(&audit_path);

    // 1. Chain length matches inventory exactly: nothing dropped, nothing extra.
    assert_eq!(
        records.len(),
        inventory.len(),
        "every privileged action must produce exactly one chain entry; \
         a silent drop or a phantom entry both break the audit guarantee"
    );

    // 2. Gap-free monotonic sequence: 1..=N with no holes.
    for (i, rec) in records.iter().enumerate() {
        assert_eq!(
            rec.seq,
            (i + 1) as u64,
            "seq must be gap-free: a skipped seq means a record was lost \
             without the chain noticing"
        );
    }

    // 3. Every inventory item reconciles against exactly one chain entry by
    //    tool + sql_sha256. The inventory was built outside the audit path, so
    //    a mismatch means the audit path lost or corrupted an action.
    for (tool, sql) in &inventory {
        let expected_hash = oraclemcp_audit::sha256_hex(sql.as_bytes());
        let matches: Vec<_> = records
            .iter()
            .filter(|r| r.tool == *tool && r.sql_sha256 == expected_hash)
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "inventory item ({tool}, sha256={expected_hash}) must appear \
             exactly once in the chain; found {} entries",
            matches.len()
        );
    }

    // 4. The chain itself verifies — the inventory match is meaningless if the
    //    entries could have been tampered with after writing.
    assert_eq!(
        verify_records(&records, &[key()]),
        VerifyOutcome::Ok {
            records: inventory.len()
        },
        "the reconciled chain must also be cryptographically intact"
    );

    // 5. The anchor names the full head — truncation would break reconciliation
    //    above, but the anchor is the independent witness.
    let anchor = load_anchor(&anchor_path)
        .expect("load anchor")
        .expect("anchor present");
    assert_eq!(
        check_anchor(&records, &anchor, &[key()]),
        Ok(AnchorStatus::Match),
        "anchor must confirm the full chain head after inventory reconciliation"
    );
}

/// SEC-3: an audit write that cannot succeed must fail CLOSED. Opening the sink
/// is the first place this is decidable, and it must refuse rather than hand
/// back a writer that silently discards records — a "best effort" audit sink is
/// indistinguishable from no audit at all once the disk is unwritable.
#[cfg(unix)]
#[test]
fn an_unwritable_audit_destination_fails_closed_at_open() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let locked = dir.path().join("locked");
    fs::create_dir(&locked).expect("mkdir");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).expect("chmod read-only");

    let result = FileAuditSink::open(locked.join("audit.jsonl"));

    // Restore permissions first so the tempdir can always clean up, even if the
    // assertion below fails.
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).expect("restore");

    assert!(
        result.is_err(),
        "an unwritable audit destination must refuse to open; a sink that \
         succeeds here would drop privileged-action records silently"
    );
}
