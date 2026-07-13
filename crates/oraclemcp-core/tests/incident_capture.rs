//! Arc E1: `om incident capture` assembles a bundle that cannot leak.
//!
//! The acceptance test is the first one: a capture whose inputs are *stuffed*
//! with the exact material an incident carries — the customer's schema and table
//! names, their bind values, their literals, their username, their service and
//! database names, their connect string, their wallet path, a password — and the
//! assertion that not one of those bytes appears anywhere in the written bundle.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use oraclemcp_audit::{AuditDecision, AuditOutcome, AuditRecord, AuditSubject, DbEvidence};
use oraclemcp_config::OracleMcpConfig;
use oraclemcp_core::incident::{
    Cassette, CassetteFrame, IncidentCaptureError, IncidentCaptureRequest, capture_bundle,
    read_cassette, read_redacted_audit_tail, verify_bundle,
};
use oraclemcp_guard::incident::{BuildIdentity, CapturedLane, CapturedVerdict, IncidentTrigger};
use oraclemcp_guard::levels::{DangerLevel, OperatingLevel};

// The customer's world. None of this may ever reach a bundle.
const RAW_SQL: &str =
    "UPDATE hr.employees SET salary = 90000 WHERE email = 'alice@acme.example' AND id = :emp_id";
const CONNECT_STRING: &str = "prod-db.acme.example:1521/ORCLPDB1";
const WALLET_PATH: &str = "/etc/oracle/wallet/cwallet.sso";
const DB_USERNAME: &str = "HR_APP_PROD";
const SERVICE_NAME: &str = "ORCLPDB1_HIGH";
const DB_UNIQUE_NAME: &str = "ACMEPROD";
const PASSWORD: &str = "hunter2-Sup3rSecret";

fn sensitive() -> Vec<String> {
    vec![
        RAW_SQL.to_owned(),
        "hr.employees".to_owned(),
        "employees".to_owned(),
        "salary".to_owned(),
        "alice@acme.example".to_owned(),
        "emp_id".to_owned(),
        "90000".to_owned(),
        CONNECT_STRING.to_owned(),
        WALLET_PATH.to_owned(),
        DB_USERNAME.to_owned(),
        SERVICE_NAME.to_owned(),
        DB_UNIQUE_NAME.to_owned(),
        PASSWORD.to_owned(),
        "acme".to_owned(),
    ]
}

fn config() -> OracleMcpConfig {
    // A real config carries the connect string, the username and the wallet path.
    // The redacted projection must carry none of them.
    let toml = format!(
        r#"
schema_version = 2
default_profile = "prod"

[[profiles]]
name = "prod"
connect_string = "{CONNECT_STRING}"
username = "{DB_USERNAME}"
credential_ref = "env:ORACLE_PASSWORD"
description = "production reader"
max_level = "READ_ONLY"

[[profiles]]
name = "staging"
connect_string = "stg-db.acme.example:1521/STG"
username = "STG_APP"
credential_ref = "file:/etc/oracle/wallet/cwallet.sso"
max_level = "READ_WRITE"
"#
    );
    OracleMcpConfig::from_toml_str(&toml).expect("the fixture config parses")
}

fn audit_records() -> Vec<AuditRecord> {
    // A record with every dangerous field populated: the legacy username, the
    // structured subject, the db evidence, and a pre-v6 RAW sql_preview.
    vec![AuditRecord {
        schema_version: 10,
        seq: 41,
        timestamp: "2026-07-13T09:00:00Z".to_owned(),
        agent_identity: format!("oracle:{DB_USERNAME}"),
        subject: AuditSubject {
            kind: "oauth".to_owned(),
            stable_id: format!("{DB_USERNAME}@acme"),
            authn_method: None,
            client_id: None,
            thumbprint: None,
        },
        db_evidence: Some(DbEvidence {
            availability: Some("available".to_owned()),
            db_unique_name: Some(DB_UNIQUE_NAME.to_owned()),
            service_name: Some(SERVICE_NAME.to_owned()),
            session_user: Some(DB_USERNAME.to_owned()),
            current_schema: Some("HR".to_owned()),
            ..DbEvidence::default()
        }),
        cancel: None,
        correlation: None,
        result_masking: None,
        observed_scn: Some(42_000_001),
        verdict_certificate_core_hash: None,
        tool: "oracle_execute".to_owned(),
        sql_sha256: oraclemcp_audit::sha256_hex(RAW_SQL.as_bytes()),
        sql_normalized_sha256: String::new(),
        sql_preview: RAW_SQL.to_owned(),
        danger_level: "DESTRUCTIVE".to_owned(),
        decision: AuditDecision::Blocked,
        rows_affected: None,
        outcome: AuditOutcome::Failed,
        prev_hash: "genesis".to_owned(),
        entry_hash: oraclemcp_audit::sha256_hex(b"entry"),
        key_id: Some("k1".to_owned()),
        signature: Some("sig".to_owned()),
    }]
}

fn lanes() -> Vec<CapturedLane> {
    vec![CapturedLane {
        lane_id: "lane-a".to_owned(),
        subject_id_hash: oraclemcp_audit::sha256_hex(DB_USERNAME.as_bytes()),
    }]
}

fn build() -> BuildIdentity {
    BuildIdentity {
        server: "oraclemcp/0.9.0".to_owned(),
        classifier: "oraclemcp-guard/0.9.0;registry=1".to_owned(),
        driver: "oracledb/0.8.2".to_owned(),
    }
}

fn request<'a>(
    config: &'a OracleMcpConfig,
    records: &'a [AuditRecord],
    lanes: &'a [CapturedLane],
    cassettes: &'a [Cassette<'a>],
    sensitive: &'a [String],
) -> IncidentCaptureRequest<'a> {
    IncidentCaptureRequest {
        trigger: IncidentTrigger::Refusal,
        seed: 0x5eed_0000_0000_0001,
        statement: Some(RAW_SQL),
        captured_verdict: Some(CapturedVerdict {
            danger: DangerLevel::Destructive,
            required_level: Some(OperatingLevel::ReadWrite),
            reason_class: None,
        }),
        why: "the guard refused a destructive statement at read only",
        lanes,
        build: build(),
        audit_records: records,
        cassettes,
        config,
        sensitive,
    }
}

fn bundle_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("omcp-incident-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

/// Every byte of every file in the bundle, so an assertion cannot miss a file.
fn bundle_bytes(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(&path).expect("read bundle dir") {
            let entry = entry.expect("dir entry").path();
            if entry.is_dir() {
                stack.push(entry);
            } else {
                let text = fs::read_to_string(&entry).expect("bundle files are text");
                out.push((entry, text));
            }
        }
    }
    out
}

// ── The acceptance test ──────────────────────────────────────────────────────

#[test]
fn a_captured_bundle_contains_no_raw_identifier_bind_secret_or_connect_string() {
    let dir = bundle_dir("clean");
    let config = config();
    let records = audit_records();
    let lanes = lanes();
    let frames = vec![CassetteFrame {
        seq: 1,
        tool: "oracle_execute",
        statement: Some(RAW_SQL),
        sql_sha256: Some("sha256:abc"),
        outcome: "refused",
    }];
    let cassettes = vec![Cassette {
        lane_id: "lane-a",
        frames: &frames,
    }];
    let sensitive = sensitive();

    let manifest = capture_bundle(
        &dir,
        &request(&config, &records, &lanes, &cassettes, &sensitive),
    )
    .expect("a capture whose material is fully redactable produces a bundle");

    let files = bundle_bytes(&dir);
    assert_eq!(
        files.len(),
        4,
        "manifest + config + audit tail + one cassette"
    );

    // THE assertion: not one byte of the customer's world survived, anywhere.
    for (path, text) in &files {
        let haystack = text.to_ascii_lowercase();
        for secret in &sensitive {
            assert!(
                !haystack.contains(&secret.to_ascii_lowercase()),
                "{} leaked {secret:?}:\n{text}",
                path.display()
            );
        }
        // And the shapes no bundle may ever carry.
        for shape in [
            "cwallet.sso",
            "password=",
            "credential_ref",
            "(description=",
        ] {
            assert!(
                !haystack.contains(shape),
                "{} leaked {shape:?}",
                path.display()
            );
        }
    }

    // The skeleton still says what happened — the bundle is useful, not empty.
    let statement = manifest.statement_redacted.expect("a redacted statement");
    assert!(
        statement.contains("UPDATE"),
        "the shape is gone too: {statement}"
    );

    // The audit tail kept its correlation handles and dropped the identities.
    let tail = read_redacted_audit_tail(&dir).expect("the audit tail parses");
    assert_eq!(tail.len(), 1);
    assert_eq!(tail[0]["seq"], 41);
    assert!(
        tail[0]["sql_sha256"]
            .as_str()
            .expect("digest")
            .starts_with("sha256:")
    );
    assert!(
        tail[0]["subject_id_hash"]
            .as_str()
            .expect("hash")
            .starts_with("sha256:")
    );
    assert!(tail[0].get("db_evidence").is_none(), "db_evidence survived");
    assert!(
        tail[0].get("sql_preview").is_none(),
        "the raw sql_preview survived"
    );
    assert!(
        tail[0].get("agent_identity").is_none(),
        "the username survived"
    );

    // The cassette kept the skeleton and the digest, not the SQL.
    let cassette = read_cassette(&dir, "lane-a").expect("the cassette parses");
    assert_eq!(cassette.len(), 1);
    assert!(
        cassette[0]
            .statement_redacted
            .as_deref()
            .expect("a redacted frame statement")
            .contains("UPDATE")
    );

    fs::remove_dir_all(&dir).expect("cleanup");
}

// ── The gate is not a formality ──────────────────────────────────────────────

#[test]
fn a_bundle_that_would_leak_is_never_written_at_all() {
    let dir = bundle_dir("leak");
    let config = config();
    let records = audit_records();
    let lanes = lanes();
    let cassettes: Vec<Cassette<'_>> = Vec::new();

    // Simulate a projection that was loosened later: the capture site declares
    // "oracle_execute" — a string the bundle legitimately contains — sensitive.
    // The gate must refuse, because it does not know why a token is sensitive,
    // only that it must not appear.
    let mut sensitive = sensitive();
    sensitive.push("oracle_execute".to_owned());

    let refused = capture_bundle(
        &dir,
        &request(&config, &records, &lanes, &cassettes, &sensitive),
    );
    assert!(
        matches!(refused, Err(IncidentCaptureError::WouldLeak)),
        "the gate admitted a leaking bundle: {refused:?}"
    );

    // Fail-closed means NOTHING on disk: not even a partial directory an operator
    // might attach to a bug report.
    assert!(
        !dir.exists(),
        "a refused capture left a bundle directory behind"
    );
}

#[test]
fn a_statement_the_redactor_cannot_prove_safe_refuses_the_whole_capture() {
    let dir = bundle_dir("unlexable");
    let config = config();
    let records = audit_records();
    let lanes = lanes();
    let cassettes: Vec<Cassette<'_>> = Vec::new();
    let sensitive = sensitive();

    let mut req = request(&config, &records, &lanes, &cassettes, &sensitive);
    req.statement = Some("SELECT 'unterminated");
    let refused = capture_bundle(&dir, &req);
    // The refusal arrives through the manifest, which owns the statement's trip
    // through the Arc J redactor. Either way it is the SAME seam refusing, and
    // the property that matters holds: no bundle, and nothing on disk.
    assert!(
        matches!(
            refused,
            Err(IncidentCaptureError::Manifest(_)) | Err(IncidentCaptureError::Redaction(_))
        ),
        "an unlexable statement produced {refused:?}"
    );
    assert!(
        !dir.exists(),
        "a refused capture left a bundle directory behind"
    );
}

#[test]
fn a_cassette_frame_cannot_smuggle_raw_sql_past_the_redactor() {
    let dir = bundle_dir("cassette");
    let config = config();
    let records = audit_records();
    let lanes = lanes();
    // The frame carries the RAW statement; the cassette writer redacts it, so the
    // gate has nothing left to catch — but the skeleton is all that reaches disk.
    let frames = vec![CassetteFrame {
        seq: 1,
        tool: "oracle_query",
        statement: Some("SELECT ssn FROM hr.employees WHERE email = 'alice@acme.example'"),
        sql_sha256: None,
        outcome: "refused",
    }];
    let cassettes = vec![Cassette {
        lane_id: "lane-a",
        frames: &frames,
    }];
    let mut sensitive = sensitive();
    sensitive.push("ssn".to_owned());

    let refused = capture_bundle(
        &dir,
        &request(&config, &records, &lanes, &cassettes, &sensitive),
    );
    // "ssn" is 3 chars — below the gate's minimum token length — so it is the
    // REDACTOR, not the gate, that has to have removed it. If the redactor ever
    // stops replacing customer identifiers, this test fails.
    let manifest = refused.expect("the frame is redactable");
    let _ = manifest;
    let files = bundle_bytes(&dir);
    for (path, text) in &files {
        let haystack = text.to_ascii_lowercase();
        assert!(
            !haystack.contains("ssn"),
            "{} leaked a column name",
            path.display()
        );
        assert!(
            !haystack.contains("alice"),
            "{} leaked a literal",
            path.display()
        );
    }
    fs::remove_dir_all(&dir).expect("cleanup");
}

// ── Self-describing and reproducible ─────────────────────────────────────────

#[test]
fn the_bundle_is_self_describing_and_verifies_against_its_own_manifest() {
    let dir = bundle_dir("verify");
    let config = config();
    let records = audit_records();
    let lanes = lanes();
    let frames = vec![CassetteFrame {
        seq: 1,
        tool: "oracle_execute",
        statement: Some(RAW_SQL),
        sql_sha256: None,
        outcome: "refused",
    }];
    let cassettes = vec![Cassette {
        lane_id: "lane-a",
        frames: &frames,
    }];
    let sensitive = sensitive();
    let written = capture_bundle(
        &dir,
        &request(&config, &records, &lanes, &cassettes, &sensitive),
    )
    .expect("bundle");

    // Every entry hash matches the bytes on disk, and the manifest id matches
    // its own content.
    let verified = verify_bundle(&dir).expect("the bundle verifies");
    assert_eq!(verified, written);
    assert_eq!(
        verified.entries.len(),
        3,
        "config + audit tail + one cassette are all described"
    );
    let described: BTreeSet<&str> = verified
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    assert!(described.contains("config.redacted.toml"));
    assert!(described.contains("audit-tail.redacted.jsonl"));
    assert!(described.contains("cassettes/lane-a.jsonl"));

    // Swap a file for a different one: the manifest catches it.
    fs::write(dir.join("config.redacted.toml"), b"schema_version = 1\n").expect("tamper");
    assert!(verify_bundle(&dir).is_err(), "a swapped file verified");

    fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn capturing_the_same_incident_twice_yields_byte_identical_bundles() {
    let config = config();
    let records = audit_records();
    let lanes = lanes();
    let frames = vec![CassetteFrame {
        seq: 1,
        tool: "oracle_execute",
        statement: Some(RAW_SQL),
        sql_sha256: None,
        outcome: "refused",
    }];
    let cassettes = vec![Cassette {
        lane_id: "lane-a",
        frames: &frames,
    }];
    let sensitive = sensitive();

    let first_dir = bundle_dir("determinism-1");
    let second_dir = bundle_dir("determinism-2");
    let first = capture_bundle(
        &first_dir,
        &request(&config, &records, &lanes, &cassettes, &sensitive),
    )
    .expect("first");
    let second = capture_bundle(
        &second_dir,
        &request(&config, &records, &lanes, &cassettes, &sensitive),
    )
    .expect("second");

    assert_eq!(first.id, second.id, "the same incident produced two ids");
    let read_all = |dir: &Path| -> Vec<(String, String)> {
        let mut files: Vec<(String, String)> = bundle_bytes(dir)
            .into_iter()
            .map(|(path, text)| {
                (
                    path.strip_prefix(dir)
                        .expect("relative")
                        .to_string_lossy()
                        .into_owned(),
                    text,
                )
            })
            .collect();
        files.sort();
        files
    };
    assert_eq!(
        read_all(&first_dir),
        read_all(&second_dir),
        "two captures of one incident differ on disk"
    );

    fs::remove_dir_all(&first_dir).expect("cleanup");
    fs::remove_dir_all(&second_dir).expect("cleanup");
}
