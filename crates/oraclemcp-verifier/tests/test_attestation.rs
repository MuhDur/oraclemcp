//! `test-attestation/v1` contract tests (Cluster K1, plan §32.3, ADR-0012):
//! sign→verify round-trip, tamper rejection, wrong-key rejection, malformed
//! rejection, over-claiming-frame rejection, and a byte-exact golden document.

use oraclemcp_audit::SigningKey;
use oraclemcp_verifier::{
    AttestedArtifact, AttestedTest, TEST_ATTESTATION_FRAME, TestAttestation, TestAttestationDraft,
    TestAttestationFormatError, TestAttestationVerificationError, TestOutcome,
    sign_test_attestation, verify_test_attestation,
};

fn signing_key() -> SigningKey {
    SigningKey::new(
        "test-attestation-key",
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .expect("test key must be valid")
}

fn draft() -> TestAttestationDraft {
    TestAttestationDraft {
        lane: "mutation-safety".to_owned(),
        repo: "oraclemcp".to_owned(),
        git_sha: "4b46e87bb874427f1f117b38bbeec39a1c2f790f".to_owned(),
        toolchain: "nightly-2026-05-11".to_owned(),
        command: "bash scripts/mutation_safety_gate.sh run".to_owned(),
        created_at: "2026-07-20T00:00:00Z".to_owned(),
        tests: vec![
            AttestedTest {
                detail: Some("kill=92.6% threshold=90".to_owned()),
                name: "mutation-gate:oraclemcp-guard:kill-rate-floor".to_owned(),
                outcome: TestOutcome::Pass,
            },
            AttestedTest {
                detail: Some("kill=96.9% threshold=90".to_owned()),
                name: "mutation-gate:oraclemcp-audit:kill-rate-floor".to_owned(),
                outcome: TestOutcome::Pass,
            },
        ],
        artifacts: vec![AttestedArtifact {
            path: "target/mutants/summary.txt".to_owned(),
            sha256: format!("sha256:{}", "a".repeat(64)),
        }],
    }
}

fn signed_document() -> String {
    let attestation = TestAttestation::from_draft(draft()).expect("valid draft");
    sign_test_attestation(&attestation, &signing_key())
}

#[test]
fn sign_then_verify_round_trips_and_binds_names_to_outcomes() {
    let document = signed_document();
    let keys = [signing_key()];

    let verified = verify_test_attestation(&document, &keys).expect("authentic document verifies");
    assert_eq!(verified.key_id, "test-attestation-key");
    assert!(verified.payload_sha256.starts_with("sha256:"));
    assert_eq!(verified.attestation.lane(), "mutation-safety");
    assert_eq!(
        verified.attestation.git_sha(),
        "4b46e87bb874427f1f117b38bbeec39a1c2f790f"
    );
    assert_eq!(verified.attestation.tests().len(), 2);
    assert_eq!(
        verified.attestation.tests()[0].name,
        "mutation-gate:oraclemcp-guard:kill-rate-floor"
    );
    assert_eq!(verified.attestation.tests()[0].outcome, TestOutcome::Pass);
    assert!(verified.attestation.all_tests_passed());
    assert_eq!(verified.attestation.frame(), TEST_ATTESTATION_FRAME);
}

#[test]
fn a_recorded_skip_or_fail_verifies_but_is_never_counted_as_passed() {
    let mut with_skip = draft();
    with_skip.tests[1].outcome = TestOutcome::Skip;
    let attestation = TestAttestation::from_draft(with_skip).expect("valid draft");
    let document = sign_test_attestation(&attestation, &signing_key());
    let verified =
        verify_test_attestation(&document, &[signing_key()]).expect("honest SKIP verifies");
    assert!(
        !verified.attestation.all_tests_passed(),
        "a SKIP must not be treated as evidence of passing"
    );

    let mut with_fail = draft();
    with_fail.tests[0].outcome = TestOutcome::Fail;
    let attestation = TestAttestation::from_draft(with_fail).expect("valid draft");
    let document = sign_test_attestation(&attestation, &signing_key());
    let verified =
        verify_test_attestation(&document, &[signing_key()]).expect("honest FAIL verifies");
    assert!(!verified.attestation.all_tests_passed());
}

#[test]
fn payload_tamper_is_rejected_via_digest_mismatch() {
    let document = signed_document();
    let tampered = document.replacen("\"PASS\"", "\"FAIL\"", 1);
    assert_ne!(document, tampered, "tamper must have changed the payload");
    assert_eq!(
        verify_test_attestation(&tampered, &[signing_key()]),
        Err(TestAttestationVerificationError::PayloadDigestMismatch)
    );
}

#[test]
fn recomputed_digest_forgery_without_the_key_is_rejected_by_the_mac() {
    // A forger who edits the payload AND recomputes payload_sha256 (the
    // recompute-from-genesis analogue) still cannot reproduce the keyed MAC.
    let document = signed_document();
    let (payload_line, signature_line) = document
        .trim_end_matches('\n')
        .split_once('\n')
        .expect("two lines");
    let forged_payload = payload_line.replacen("\"PASS\"", "\"FAIL\"", 1);
    let forged_digest = oraclemcp_audit::sha256_hex(forged_payload.as_bytes());
    let mut signature: serde_json::Value =
        serde_json::from_str(signature_line).expect("signature JSON");
    signature["payload_sha256"] = serde_json::Value::String(forged_digest);
    let forged = format!("{forged_payload}\n{signature}\n");
    assert_eq!(
        verify_test_attestation(&forged, &[signing_key()]),
        Err(TestAttestationVerificationError::SignatureInvalid)
    );
}

#[test]
fn wrong_key_material_and_unknown_key_id_are_rejected() {
    let document = signed_document();

    let wrong_material = SigningKey::new(
        "test-attestation-key",
        b"ffffffffffffffffffffffffffffffff".to_vec(),
    )
    .expect("valid key");
    assert_eq!(
        verify_test_attestation(&document, &[wrong_material]),
        Err(TestAttestationVerificationError::SignatureInvalid)
    );

    let different_identity = SigningKey::new(
        "some-other-key",
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .expect("valid key");
    assert_eq!(
        verify_test_attestation(&document, &[different_identity]),
        Err(TestAttestationVerificationError::UntrustedKey)
    );

    assert_eq!(
        verify_test_attestation(&document, &[]),
        Err(TestAttestationVerificationError::UntrustedKey)
    );
}

#[test]
fn malformed_documents_are_rejected_not_defaulted() {
    let keys = [signing_key()];
    let document = signed_document();
    let (payload_line, signature_line) = document
        .trim_end_matches('\n')
        .split_once('\n')
        .expect("two lines");

    for (case, mangled) in [
        ("empty", String::new()),
        ("payload only", format!("{payload_line}\n")),
        ("signature only", format!("{signature_line}\n")),
        ("third line", format!("{document}extra\n")),
        ("crlf", document.replace('\n', "\r\n")),
        ("blank payload", format!("\n{signature_line}\n")),
        (
            "missing final newline",
            format!("{payload_line}\n{signature_line}"),
        ),
    ] {
        assert_eq!(
            verify_test_attestation(&mangled, &keys),
            Err(TestAttestationVerificationError::MalformedDocument),
            "case: {case}"
        );
    }

    assert_eq!(
        verify_test_attestation(&format!("not-json\n{signature_line}\n"), &keys),
        Err(TestAttestationVerificationError::MalformedPayload)
    );
    assert_eq!(
        verify_test_attestation(&format!("{payload_line}\nnot-json\n"), &keys),
        Err(TestAttestationVerificationError::MalformedSignature)
    );

    // An unknown payload field must be rejected, never ignored.
    let mut payload: serde_json::Value = serde_json::from_str(payload_line).expect("payload JSON");
    payload["smuggled"] = serde_json::Value::String("field".to_owned());
    assert_eq!(
        verify_test_attestation(&format!("{payload}\n{signature_line}\n"), &keys),
        Err(TestAttestationVerificationError::MalformedPayload)
    );

    // An unknown outcome value is malformed, not an implicit pass.
    let bad_outcome = payload_line.replacen("\"PASS\"", "\"GREENISH\"", 1);
    assert_eq!(
        verify_test_attestation(&format!("{bad_outcome}\n{signature_line}\n"), &keys),
        Err(TestAttestationVerificationError::MalformedPayload)
    );

    // A wrong signature schema is unsupported, not tolerated.
    let bad_schema = signature_line.replace(
        "test-attestation-signature/v1",
        "test-attestation-signature/v9",
    );
    assert_eq!(
        verify_test_attestation(&format!("{payload_line}\n{bad_schema}\n"), &keys),
        Err(TestAttestationVerificationError::UnsupportedSignatureSchema)
    );
}

#[test]
fn an_altered_frame_is_rejected_as_over_claiming() {
    let document = signed_document();
    let over_claiming = document.replace(
        "Evidence of testing, not a proof of correctness",
        "Proof that this binary is correct",
    );
    assert_ne!(document, over_claiming);
    // The tamper is caught by the digest first; a re-hashed forgery is then
    // caught by the MAC — either way, the reworded claim never verifies.
    assert!(verify_test_attestation(&over_claiming, &[signing_key()]).is_err());
}

#[test]
fn producer_refuses_to_construct_an_over_claiming_or_malformed_payload() {
    let cases: Vec<(TestAttestationDraft, TestAttestationFormatError)> = vec![
        (
            TestAttestationDraft {
                tests: vec![],
                ..draft()
            },
            TestAttestationFormatError::InvalidTestCount,
        ),
        (
            TestAttestationDraft {
                lane: "Mutation_Safety".to_owned(),
                ..draft()
            },
            TestAttestationFormatError::InvalidLane,
        ),
        (
            TestAttestationDraft {
                git_sha: "deadbeef".to_owned(),
                ..draft()
            },
            TestAttestationFormatError::InvalidGitSha,
        ),
        (
            TestAttestationDraft {
                created_at: "2026-07-20 00:00:00".to_owned(),
                ..draft()
            },
            TestAttestationFormatError::InvalidCreatedAt,
        ),
        (
            TestAttestationDraft {
                created_at: "2026-13-20T00:00:00Z".to_owned(),
                ..draft()
            },
            TestAttestationFormatError::InvalidCreatedAt,
        ),
        (
            TestAttestationDraft {
                created_at: "2026-02-29T00:00:00Z".to_owned(),
                ..draft()
            },
            TestAttestationFormatError::InvalidCreatedAt,
        ),
        (
            TestAttestationDraft {
                command: "line one\nline two".to_owned(),
                ..draft()
            },
            TestAttestationFormatError::InvalidCommand,
        ),
        (
            TestAttestationDraft {
                artifacts: vec![AttestedArtifact {
                    path: "summary.txt".to_owned(),
                    sha256: "sha256:short".to_owned(),
                }],
                ..draft()
            },
            TestAttestationFormatError::InvalidArtifactDigest,
        ),
        (
            TestAttestationDraft {
                tests: vec![AttestedTest {
                    detail: None,
                    name: "name\nwith-newline".to_owned(),
                    outcome: TestOutcome::Pass,
                }],
                ..draft()
            },
            TestAttestationFormatError::InvalidTestName,
        ),
        (
            TestAttestationDraft {
                tests: vec![draft().tests[0].clone(), draft().tests[0].clone()],
                ..draft()
            },
            TestAttestationFormatError::DuplicateTestName,
        ),
        (
            TestAttestationDraft {
                artifacts: vec![AttestedArtifact {
                    path: "../summary.txt".to_owned(),
                    sha256: format!("sha256:{}", "a".repeat(64)),
                }],
                ..draft()
            },
            TestAttestationFormatError::InvalidArtifactPath,
        ),
        (
            TestAttestationDraft {
                artifacts: vec![draft().artifacts[0].clone(), draft().artifacts[0].clone()],
                ..draft()
            },
            TestAttestationFormatError::DuplicateArtifactPath,
        ),
    ];
    for (bad_draft, expected) in cases {
        assert_eq!(
            TestAttestation::from_draft(bad_draft.clone()).expect_err("draft must be refused"),
            expected,
            "draft: {bad_draft:?}"
        );
    }
}

#[test]
fn ambiguous_trusted_key_identity_is_rejected() {
    let document = signed_document();
    let keys = [signing_key(), signing_key()];
    assert_eq!(
        verify_test_attestation(&document, &keys),
        Err(TestAttestationVerificationError::AmbiguousKey)
    );
}

/// The committed golden document pins the wire format byte-for-byte (payload
/// field order, signature rendering, trailing newline) so the browser
/// re-verifier (Cluster K2) and any external tooling can rely on it. Rebless
/// with `UPDATE_GOLDENS=1 cargo test -p oraclemcp-verifier --test
/// test_attestation` after a reviewed, deliberate format change.
#[test]
fn golden_document_is_byte_stable_and_verifies() {
    let document = signed_document();
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/test-attestation-v1.golden.jsonl"
    );
    if std::env::var_os("UPDATE_GOLDENS").is_some_and(|v| v == "1") {
        std::fs::write(path, &document).expect("write golden");
    }
    let golden = std::fs::read_to_string(path).expect("committed golden fixture");
    assert_eq!(
        document, golden,
        "test-attestation/v1 wire format drifted from the committed golden"
    );
    verify_test_attestation(&golden, &[signing_key()]).expect("golden verifies");
}
