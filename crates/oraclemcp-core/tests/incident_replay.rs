//! Arc E2 replay proof: the stored verdict is evidence, not authority, and a
//! fixed seed produces the same fresh classifications and audit-tail digest.

use std::fs;
use std::path::{Path, PathBuf};

use oraclemcp_config::OracleMcpConfig;
use oraclemcp_core::incident::{
    Cassette, CassetteFrame, IncidentCaptureRequest, capture_bundle, replay_bundle,
};
use oraclemcp_guard::{
    BuildIdentity, CapturedLane, CapturedVerdict, DangerLevel, IncidentTrigger, OperatingLevel,
};

const RAW_DDL: &str = "DROP TABLE tenant_sensitive_records";

fn bundle_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "omcp-incident-replay-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    dir
}

fn capture_fixture(dir: &Path) {
    let config = OracleMcpConfig::default();
    let lanes = [CapturedLane {
        lane_id: "local-capture".to_owned(),
        subject_id_hash: oraclemcp_audit::sha256_hex(b"local-capture"),
    }];
    let frames = [CassetteFrame {
        seq: 7,
        tool: "oracle_execute",
        statement: Some(RAW_DDL),
        sql_sha256: Some("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
        outcome: "refused",
    }];
    let cassettes = [Cassette {
        lane_id: "local-capture",
        frames: &frames,
    }];
    let sensitive = [RAW_DDL.to_owned(), "tenant_sensitive_records".to_owned()];

    capture_bundle(
        dir,
        &IncidentCaptureRequest {
            trigger: IncidentTrigger::Refusal,
            seed: 0x5eed_0000_0000_0001,
            statement: Some(RAW_DDL),
            // Deliberately false evidence. If replay ever trusted it, the
            // destructive DDL below would become a read-only verdict.
            captured_verdict: Some(CapturedVerdict {
                danger: DangerLevel::Safe,
                required_level: Some(OperatingLevel::ReadOnly),
                reason_class: None,
            }),
            why: "the guard refused a destructive statement at read only",
            lanes: &lanes,
            build: BuildIdentity {
                server: "oraclemcp/0.9.0".to_owned(),
                classifier: "oraclemcp-guard/0.9.0;registry=1".to_owned(),
                driver: "oracledb/0.8.2".to_owned(),
            },
            audit_records: &[],
            cassettes: &cassettes,
            config: &config,
            sensitive: &sensitive,
        },
    )
    .expect("fixture capture succeeds");
}

#[test]
fn replay_reclassifies_from_the_redacted_statement_not_the_captured_verdict() {
    let dir = bundle_dir("sec1");
    capture_fixture(&dir);

    let report = replay_bundle(&dir).expect("replay succeeds");
    assert_eq!(report.replayed_steps, 1);
    assert_eq!(report.verdicts[0].lane_id, "local-capture");
    assert_eq!(report.verdicts[0].seq, 7);
    assert_ne!(report.verdicts[0].danger, "Safe");
    assert_ne!(
        report.verdicts[0].required_level.as_deref(),
        Some("ReadOnly")
    );
    assert!(report.audit_tail_sha256.starts_with("sha256:"));

    fs::remove_dir_all(&dir).expect("cleanup fixture");
}

#[test]
fn replay_is_byte_stable_for_one_verified_bundle_and_seed() {
    let dir = bundle_dir("deterministic");
    capture_fixture(&dir);

    let first = replay_bundle(&dir).expect("first replay succeeds");
    let second = replay_bundle(&dir).expect("second replay succeeds");
    assert_eq!(first, second, "same seed and bundle replay differently");
    assert_eq!(
        serde_json::to_vec(&first).expect("report serializes"),
        serde_json::to_vec(&second).expect("report serializes"),
        "same report has unstable wire bytes"
    );

    fs::remove_dir_all(&dir).expect("cleanup fixture");
}
