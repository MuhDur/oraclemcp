//! K3 producer contract: the CI emitter consumes its secret only from the
//! environment, hashes named artifacts, emits a K1 document, and fails closed.

use oraclemcp_audit::SigningKey;
use oraclemcp_verifier::{TestOutcome, verify_test_attestation};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const SECRET_HEX: &str = "3031323334353637383961626364656630313233343536373839616263646566";

fn fixture_directory() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let root = workspace_root();
    let relative = PathBuf::from(format!(
        "target/test-attest-cli/{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(root.join(&relative)).expect("create ignored test fixture directory");
    relative
}

fn run_emitter(directory: &std::path::Path, output_name: &str, secret: Option<&str>) -> Output {
    let root = workspace_root();
    let artifact = portable_relative_path(&directory.join("lane.log"));
    let output = portable_relative_path(&directory.join(output_name));
    let mut command = Command::new(env!("CARGO_BIN_EXE_oraclemcp-test-attest"));
    command
        .current_dir(root)
        .env_remove("ORACLEMCP_TEST_ATTESTATION_KEY")
        .env("ORACLEMCP_TEST_ATTESTATION_KEY_ID", "ci-test-key")
        .args([
            "--lane",
            "coverage-ratchet",
            "--repo",
            "oraclemcp",
            "--git-sha",
            "4b46e87bb874427f1f117b38bbeec39a1c2f790f",
            "--toolchain",
            "nightly-2026-05-11",
            "--command",
            "bash scripts/coverage_ratchet.sh run --base deadbeef",
            "--created-at",
            "2026-07-20T00:00:00Z",
            "--test",
            "coverage-ratchet:changed-line-floor=PASS",
            "--test",
            "coverage-ratchet:mutation-floor=PASS",
            "--artifact",
            &artifact,
            "--output",
            &output,
        ]);
    if let Some(secret) = secret {
        command.env("ORACLEMCP_TEST_ATTESTATION_KEY", secret);
    }
    command.output().expect("run test-attest emitter")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_owned()
}

fn fixture_path(directory: &std::path::Path, name: &str) -> PathBuf {
    workspace_root().join(directory).join(name)
}

fn portable_relative_path(path: &std::path::Path) -> String {
    path.to_str()
        .expect("UTF-8 fixture path")
        .replace('\\', "/")
}

#[test]
fn emitter_writes_a_verifiable_artifact_bound_document() {
    let directory = fixture_directory();
    fs::write(
        fixture_path(&directory, "lane.log"),
        b"changed-line floor: PASS\n",
    )
    .expect("write ignored evidence fixture");
    let result = run_emitter(&directory, "attestation.jsonl", Some(SECRET_HEX));
    assert!(
        result.status.success(),
        "emitter failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let document = fs::read_to_string(fixture_path(&directory, "attestation.jsonl"))
        .expect("read emitted attestation");
    let key = SigningKey::new("ci-test-key", b"0123456789abcdef0123456789abcdef".to_vec())
        .expect("trusted test key");
    let verified = verify_test_attestation(&document, &[key]).expect("emitted document verifies");
    assert!(verified.attestation.all_tests_passed());
    assert_eq!(verified.attestation.tests().len(), 2);
    assert_eq!(verified.attestation.tests()[0].outcome, TestOutcome::Pass);
    assert_eq!(verified.attestation.artifacts().len(), 1);
    assert_eq!(
        verified.attestation.artifacts()[0].path,
        portable_relative_path(&directory.join("lane.log"))
    );
}

#[test]
fn missing_or_malformed_secret_fails_without_creating_an_attestation() {
    let directory = fixture_directory();
    fs::write(fixture_path(&directory, "lane.log"), b"lane result\n")
        .expect("write ignored fixture");

    let missing = run_emitter(&directory, "missing.jsonl", None);
    assert!(!missing.status.success());
    assert!(!fixture_path(&directory, "missing.jsonl").exists());
    let missing_error = String::from_utf8_lossy(&missing.stderr);
    assert!(missing_error.contains("ORACLEMCP_TEST_ATTESTATION_KEY is not set"));

    let malformed = run_emitter(&directory, "malformed.jsonl", Some("not-a-secret"));
    assert!(!malformed.status.success());
    assert!(!fixture_path(&directory, "malformed.jsonl").exists());
    let malformed_error = String::from_utf8_lossy(&malformed.stderr);
    assert!(malformed_error.contains("must be 64..1024 lowercase hexadecimal characters"));
    assert!(!malformed_error.contains("not-a-secret"));
}

#[test]
fn emitter_refuses_to_overwrite_existing_output() {
    let directory = fixture_directory();
    fs::write(fixture_path(&directory, "lane.log"), b"lane result\n")
        .expect("write ignored fixture");
    fs::write(fixture_path(&directory, "existing.jsonl"), b"preserve-me\n")
        .expect("write existing output fixture");

    let result = run_emitter(&directory, "existing.jsonl", Some(SECRET_HEX));
    assert!(!result.status.success());
    assert_eq!(
        fs::read(fixture_path(&directory, "existing.jsonl")).expect("read preserved output"),
        b"preserve-me\n"
    );
}
