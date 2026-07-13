//! Arc E0: the incident-artifact manifest contract.
//!
//! Three properties, pinned here so a later bead cannot quietly weaken them:
//!
//! 1. the manifest cannot carry a secret, a bind value, a wallet path, a connect
//!    string or a customer identifier out of the process (negative tests);
//! 2. a captured verdict is EVIDENCE, never an authorization input — replay
//!    re-classifies from scratch and disagrees with a lying bundle (SEC-1);
//! 3. the same incident yields the same artifact, byte for byte (golden).

use oraclemcp_guard::classifier::{Classifier, ClassifierConfig};
use oraclemcp_guard::incident::{
    BuildIdentity, BundleEntry, BundleEntryKind, CapturedLane, CapturedVerdict,
    INCIDENT_MANIFEST_VERSION, IncidentCapture, IncidentManifest, IncidentManifestError,
    IncidentTrigger, reclassify_at_replay,
};
use oraclemcp_guard::levels::{DangerLevel, OperatingLevel};

const SUBJECT: &str = "sha256:4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a";
const DIGEST: &str = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

fn lanes() -> Vec<CapturedLane> {
    vec![
        CapturedLane {
            lane_id: "lane-b".to_owned(),
            subject_id_hash: SUBJECT.to_owned(),
        },
        CapturedLane {
            lane_id: "lane-a".to_owned(),
            subject_id_hash: SUBJECT.to_owned(),
        },
    ]
}

fn entries() -> Vec<BundleEntry> {
    vec![
        BundleEntry {
            kind: BundleEntryKind::RedactedAuditTail,
            path: "audit-tail.redacted.jsonl".to_owned(),
            sha256: DIGEST.to_owned(),
            bytes: 4_096,
        },
        BundleEntry {
            kind: BundleEntryKind::Cassette,
            path: "cassettes/lane-a.jsonl".to_owned(),
            sha256: DIGEST.to_owned(),
            bytes: 128,
        },
        BundleEntry {
            kind: BundleEntryKind::RedactedConfig,
            path: "config.redacted.toml".to_owned(),
            sha256: DIGEST.to_owned(),
            bytes: 512,
        },
    ]
}

fn build() -> BuildIdentity {
    BuildIdentity {
        server: "oraclemcp/0.9.0".to_owned(),
        classifier: "oraclemcp-guard/0.9.0;registry=1".to_owned(),
        driver: "oracledb/0.8.2".to_owned(),
    }
}

fn capture_of<'a>(statement: Option<&'a str>, why: &'a str) -> IncidentCapture<'a> {
    IncidentCapture {
        trigger: IncidentTrigger::Refusal,
        seed: 0x5eed_0000_0000_0001,
        statement,
        captured_verdict: Some(CapturedVerdict {
            danger: DangerLevel::Destructive,
            required_level: Some(OperatingLevel::Ddl),
            reason_class: None,
        }),
        why,
        lanes: &[],
        build: build(),
        entries: &[],
    }
}

fn manifest_of<'a>(
    statement: Option<&'a str>,
    why: &'a str,
    lanes: &'a [CapturedLane],
    entries: &'a [BundleEntry],
) -> Result<IncidentManifest, IncidentManifestError> {
    IncidentManifest::capture(IncidentCapture {
        lanes,
        entries,
        ..capture_of(statement, why)
    })
}

fn valid_manifest() -> IncidentManifest {
    manifest_of(
        Some("DROP TABLE hr.employees WHERE id = :bind AND name = 'alice'"),
        "the guard refused a destructive statement at read only",
        &lanes(),
        &entries(),
    )
    .expect("a well formed capture yields a manifest")
}

// ── 1. The manifest is not an exfiltration channel ───────────────────────────

#[test]
fn the_statement_is_stored_only_as_a_redacted_skeleton() {
    let manifest = valid_manifest();
    let statement = manifest
        .statement_redacted
        .as_deref()
        .expect("the incident had a statement");

    // The shape survives — that is what makes the incident diagnosable.
    assert!(statement.contains("DROP"));
    // Nothing else does. A bind value, a literal, a number and the customer's
    // table name are all gone; the Arc J redactor is the only path in.
    assert!(
        !statement.contains(":bind"),
        "a bind name survived: {statement}"
    );
    assert!(
        !statement.contains("alice"),
        "a literal survived: {statement}"
    );
    assert!(
        !statement.to_ascii_uppercase().contains("EMPLOYEES"),
        "a customer identifier survived: {statement}"
    );
    assert!(
        !statement.to_ascii_uppercase().contains("HR."),
        "a customer schema survived: {statement}"
    );

    // And the whole serialized artifact carries none of it either.
    let json = manifest.to_json();
    for secret in [":bind", "alice", "EMPLOYEES", "employees", "hr."] {
        assert!(
            !json.contains(secret),
            "the manifest leaked {secret:?}:\n{json}"
        );
    }
}

#[test]
fn a_comment_is_stripped_and_its_secret_never_reaches_the_artifact() {
    // A comment is where a secret hides. The Arc J redactor removes it outright,
    // so the manifest is still made — but the payload is gone.
    let manifest = manifest_of(
        Some("SELECT /* password=hunter2 */ 1 FROM dual"),
        "note",
        &lanes(),
        &entries(),
    )
    .expect("a comment is redacted away, not a reason to refuse the capture");
    let json = manifest.to_json();
    for secret in ["password", "hunter2", "/*"] {
        assert!(
            !json.contains(secret),
            "the manifest leaked {secret:?}: {json}"
        );
    }
}

#[test]
fn a_statement_that_cannot_be_proven_safe_is_refused_and_no_manifest_is_made() {
    // The redactor can only vouch for what it can lex. When it cannot, the
    // capture fails closed: an incident that cannot be captured safely is not
    // captured at all, and NO manifest is returned to write to disk.
    let refused = manifest_of(Some("SELECT 'unterminated"), "note", &lanes(), &entries());
    assert!(
        matches!(refused, Err(IncidentManifestError::Statement(_))),
        "an unlexable statement produced {refused:?}"
    );
}

#[test]
fn the_incident_note_must_be_safe_prose() {
    let refused = manifest_of(
        Some("SELECT 1 FROM dual"),
        "connect as system/hunter2@prod-db:1521/orcl",
        &lanes(),
        &entries(),
    );
    assert_eq!(refused.unwrap_err(), IncidentManifestError::UnsafeWhy);
}

#[test]
fn a_wallet_path_or_connect_string_cannot_ride_in_on_an_entry_path() {
    // The path field is the classic exfiltration seam: it is the one field that
    // is *supposed* to look like a filesystem path.
    for hostile in [
        "/etc/oracle/wallet/cwallet.sso",
        "../../../home/operator/.oci/config",
        "cassettes/../../wallet.sso",
        "cassettes/tnsnames.ora",
        "C:\\oracle\\wallet\\cwallet.sso",
        "prod-db.example.com:1521/ORCL",
    ] {
        let hostile_entries = vec![BundleEntry {
            kind: BundleEntryKind::Cassette,
            path: hostile.to_owned(),
            sha256: DIGEST.to_owned(),
            bytes: 1,
        }];
        let refused = manifest_of(None, "note", &lanes(), &hostile_entries);
        assert_eq!(
            refused.unwrap_err(),
            IncidentManifestError::PathNotAllowed,
            "path {hostile:?} was admitted into a bundle"
        );
    }
}

#[test]
fn an_entry_path_must_match_the_kind_it_claims() {
    let mismatched = vec![BundleEntry {
        kind: BundleEntryKind::RedactedConfig,
        path: "audit-tail.redacted.jsonl".to_owned(),
        sha256: DIGEST.to_owned(),
        bytes: 1,
    }];
    assert_eq!(
        manifest_of(None, "note", &lanes(), &mismatched).unwrap_err(),
        IncidentManifestError::PathKindMismatch
    );
}

#[test]
fn a_lane_is_identified_by_a_bare_id_and_a_hashed_subject_only() {
    // A username, a connect string, or a path is not a lane id.
    for hostile_lane in ["hr_app@prod-db:1521/orcl", "../etc/passwd", "lane id"] {
        let hostile = vec![CapturedLane {
            lane_id: hostile_lane.to_owned(),
            subject_id_hash: SUBJECT.to_owned(),
        }];
        assert_eq!(
            manifest_of(None, "note", &hostile, &entries()).unwrap_err(),
            IncidentManifestError::UnsafeLaneId,
            "lane id {hostile_lane:?} was admitted"
        );
    }
    // A raw subject (a username) is not a subject id: only the hash form is.
    for hostile_subject in ["HR_APP", "system", "subject-sha256:not-hex", "sha256:abc"] {
        let hostile = vec![CapturedLane {
            lane_id: "lane-a".to_owned(),
            subject_id_hash: hostile_subject.to_owned(),
        }];
        assert_eq!(
            manifest_of(None, "note", &hostile, &entries()).unwrap_err(),
            IncidentManifestError::UnsafeSubjectId,
            "subject {hostile_subject:?} was admitted"
        );
    }
}

#[test]
fn a_version_field_cannot_smuggle_a_path_or_a_connect_string() {
    for hostile in [
        "/etc/oracle/wallet/cwallet.sso",
        "prod-db.example.com:1521/ORCL",
        "(DESCRIPTION=(ADDRESS=(HOST=prod-db)))",
        // A credential pair is `name/name` — exactly the shape of `pkg/version`
        // unless the version part is required to start with a digit.
        "system/hunter2",
        "hr_app/Passw0rd",
        "",
    ] {
        let mut build = build();
        build.driver = hostile.to_owned();
        let refused = IncidentManifest::capture(IncidentCapture {
            lanes: &lanes(),
            entries: &entries(),
            build,
            ..capture_of(None, "note")
        });
        assert_eq!(
            refused.unwrap_err(),
            IncidentManifestError::UnsafeVersion,
            "version {hostile:?} was admitted"
        );
    }
    // The real version strings still pass — the gate is a shape, not a denylist.
    assert!(manifest_of(None, "note", &lanes(), &entries()).is_ok());
}

#[test]
fn an_entry_digest_must_be_a_sha256() {
    let bad = vec![BundleEntry {
        kind: BundleEntryKind::RedactedConfig,
        path: "config.redacted.toml".to_owned(),
        sha256: "md5:deadbeef".to_owned(),
        bytes: 1,
    }];
    assert_eq!(
        manifest_of(None, "note", &lanes(), &bad).unwrap_err(),
        IncidentManifestError::InvalidDigest
    );
}

#[test]
fn a_manifest_edited_on_disk_to_smuggle_a_secret_back_in_is_refused_at_load() {
    let manifest = valid_manifest();
    let json = manifest.to_json();

    // Round-trips clean.
    assert_eq!(
        IncidentManifest::from_json(&json).expect("round trip"),
        manifest
    );

    // An attacker puts the customer's SQL back into the skeleton field. The
    // redaction POSTCONDITION catches it at load, before the id is even
    // considered: the stored text is re-lexed, not believed because it is on disk.
    let tampered = json.replace(
        manifest.statement_redacted.as_deref().expect("statement"),
        "DROP TABLE hr.employees",
    );
    assert_ne!(tampered, json);
    assert!(
        matches!(
            IncidentManifest::from_json(&tampered),
            Err(IncidentManifestError::Statement(_))
        ),
        "a smuggled customer identifier survived a re-load"
    );

    // And an edit the field validators cannot see — a byte count silently changed
    // so a swapped-in file passes as the captured one — is caught by the id.
    let resized = json.replace("\"bytes\": 4096", "\"bytes\": 4097");
    assert_ne!(resized, json);
    assert_eq!(
        IncidentManifest::from_json(&resized).unwrap_err(),
        IncidentManifestError::IdMismatch
    );

    // And if they recompute nothing but simply hand-write a lane with a username
    // in it, the field validation refuses it before the id is even considered.
    let hostile = json.replace("\"lane-a\"", "\"hr_app@prod\"");
    assert_eq!(
        IncidentManifest::from_json(&hostile).unwrap_err(),
        IncidentManifestError::UnsafeLaneId
    );
}

// ── 2. SEC-1: a captured verdict is evidence, never authorization ────────────

#[test]
fn replay_reclassifies_from_scratch_and_a_lying_bundle_changes_nothing() {
    // A bundle that CLAIMS the statement was safe...
    let lying = IncidentManifest::capture(IncidentCapture {
        captured_verdict: Some(CapturedVerdict {
            danger: DangerLevel::Safe,
            required_level: Some(OperatingLevel::ReadOnly),
            reason_class: None,
        }),
        lanes: &lanes(),
        entries: &entries(),
        ..capture_of(
            Some("DROP TABLE hr.employees"),
            "an operator edited this bundle",
        )
    })
    .expect("the manifest is well formed — it is merely wrong");
    assert_eq!(
        lying.captured_verdict.expect("verdict").danger,
        DangerLevel::Safe
    );

    // ...does not make it safe. Replay re-runs the live classifier over the
    // statement and reaches its own verdict, which is the only one that governs.
    let classifier = Classifier::new(ClassifierConfig::default());
    let decision = reclassify_at_replay(
        &classifier,
        lying.statement_redacted.as_deref().expect("statement"),
    );
    assert_ne!(
        decision.danger,
        DangerLevel::Safe,
        "the stored verdict was believed — SEC-1 is broken"
    );
    assert!(matches!(
        decision.danger,
        DangerLevel::Destructive | DangerLevel::Forbidden
    ));
    assert_ne!(decision.required_level, Some(OperatingLevel::ReadOnly));
}

#[test]
fn the_manifest_offers_no_path_from_a_stored_verdict_to_a_decision() {
    // A structural assertion, not a behavioral one: the ONLY way to obtain a
    // GuardDecision from this module is reclassify_at_replay, which takes the
    // statement and a live classifier. CapturedVerdict is inert data — it has no
    // method, no Into<GuardDecision>, and nothing here reads it back.
    let manifest = valid_manifest();
    let verdict = manifest.captured_verdict.expect("verdict");
    // It can be read and shown to an operator...
    assert_eq!(verdict.danger, DangerLevel::Destructive);
    // ...and re-classification is independent of it: the same statement yields
    // the same decision whether or not the bundle carried a verdict at all.
    let classifier = Classifier::new(ClassifierConfig::default());
    let with_verdict = reclassify_at_replay(
        &classifier,
        manifest.statement_redacted.as_deref().expect("statement"),
    );
    let without_verdict = IncidentManifest::capture(IncidentCapture {
        captured_verdict: None,
        lanes: &lanes(),
        entries: &entries(),
        ..capture_of(
            Some("DROP TABLE hr.employees WHERE id = :bind AND name = 'alice'"),
            "the guard refused a destructive statement at read only",
        )
    })
    .expect("capture without a verdict");
    let replayed = reclassify_at_replay(
        &classifier,
        without_verdict
            .statement_redacted
            .as_deref()
            .expect("statement"),
    );
    assert_eq!(with_verdict.danger, replayed.danger);
    assert_eq!(with_verdict.required_level, replayed.required_level);
}

// ── 3. The same incident yields the same artifact ────────────────────────────

#[test]
fn capturing_the_same_incident_twice_is_byte_identical() {
    let first = valid_manifest();
    let second = valid_manifest();
    assert_eq!(first.id, second.id);
    assert_eq!(first.to_json(), second.to_json());

    // No wall clock and no random id: the manifest is a pure function of the
    // capture. (If either sneaks in, this is the test that fails.)
    assert!(!first.to_json().contains("captured_at"));
    assert!(first.id.starts_with("sha256:"));
    assert_eq!(first.id.len(), "sha256:".len() + 64);
}

#[test]
fn lanes_and_entries_are_canonically_ordered_so_capture_order_cannot_change_the_bytes() {
    let forward = manifest_of(None, "note", &lanes(), &entries()).expect("manifest");
    let mut shuffled_lanes = lanes();
    shuffled_lanes.reverse();
    let mut shuffled_entries = entries();
    shuffled_entries.reverse();
    let backward = manifest_of(None, "note", &shuffled_lanes, &shuffled_entries).expect("manifest");

    assert_eq!(forward.to_json(), backward.to_json());
    assert_eq!(forward.id, backward.id);
    assert_eq!(
        forward
            .lanes
            .iter()
            .map(|lane| lane.lane_id.as_str())
            .collect::<Vec<_>>(),
        ["lane-a", "lane-b"]
    );
}

#[test]
fn a_different_incident_yields_a_different_id() {
    let base = valid_manifest();
    let other_seed = IncidentManifest::capture(IncidentCapture {
        seed: 0x5eed_0000_0000_0002,
        lanes: &lanes(),
        entries: &entries(),
        ..capture_of(
            Some("DROP TABLE hr.employees WHERE id = :bind AND name = 'alice'"),
            "the guard refused a destructive statement at read only",
        )
    })
    .expect("manifest");
    assert_ne!(base.id, other_seed.id, "the seed is not bound into the id");

    let other_trigger = IncidentManifest::capture(IncidentCapture {
        trigger: IncidentTrigger::Quarantine,
        lanes: &lanes(),
        entries: &entries(),
        ..capture_of(
            Some("DROP TABLE hr.employees WHERE id = :bind AND name = 'alice'"),
            "the guard refused a destructive statement at read only",
        )
    })
    .expect("manifest");
    assert_ne!(
        base.id, other_trigger.id,
        "the trigger is not bound into the id"
    );
}

// ── The schema itself ────────────────────────────────────────────────────────

#[test]
fn the_manifest_json_pins_the_documented_bundle_layout() {
    let manifest = valid_manifest();
    let json: serde_json::Value =
        serde_json::from_str(&manifest.to_json()).expect("the manifest is JSON");

    assert_eq!(json["schema_version"], INCIDENT_MANIFEST_VERSION);
    assert_eq!(json["trigger"], "REFUSAL");
    assert_eq!(json["seed"], 0x5eed_0000_0000_0001_u64);
    assert_eq!(
        json["build"]["classifier"],
        "oraclemcp-guard/0.9.0;registry=1"
    );
    assert_eq!(json["captured_verdict"]["danger"], "DESTRUCTIVE");
    assert_eq!(json["captured_verdict"]["required_level"], "DDL");

    // The three bundle files, canonically ordered by (kind, path).
    let entries = json["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0]["kind"], "cassette");
    assert_eq!(entries[0]["path"], "cassettes/lane-a.jsonl");
    assert_eq!(entries[1]["kind"], "redacted_config");
    assert_eq!(entries[1]["path"], "config.redacted.toml");
    assert_eq!(entries[2]["kind"], "redacted_audit_tail");
    assert_eq!(entries[2]["path"], "audit-tail.redacted.jsonl");

    // An unknown field is not silently accepted: the schema is closed.
    let with_extra = manifest.to_json().replace(
        "\"schema_version\": 1,",
        "\"schema_version\": 1,\n  \"connect_string\": \"prod-db:1521/orcl\",",
    );
    assert_eq!(
        IncidentManifest::from_json(&with_extra).unwrap_err(),
        IncidentManifestError::Malformed
    );
}

#[test]
fn a_bundle_must_carry_at_least_one_file_and_never_the_same_path_twice() {
    assert_eq!(
        manifest_of(None, "note", &lanes(), &[]).unwrap_err(),
        IncidentManifestError::InvalidBundle
    );
    let duplicated = vec![entries()[2].clone(), entries()[2].clone()];
    assert_eq!(
        manifest_of(None, "note", &lanes(), &duplicated).unwrap_err(),
        IncidentManifestError::InvalidBundle
    );
}
