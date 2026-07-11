//! Verify-before-mutate for the discovery add-only merge (TNS-onboarding bead
//! `.11`; design spec §E, `docs/tns-discovery-onboarding.md`).
//!
//! `oraclemcp setup --discover` reads the current target, computes an add-only
//! merge from those exact bytes, then applies through config-ops passing the
//! hash of the bytes it merged from. This test reproduces that contract via the
//! public config-ops API: a concurrent external edit landing between the base
//! read and the apply must be **rejected** (`ConfigOpsError::CurrentChanged`),
//! never silently clobbered — so a racing edit is never lost.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use oraclemcp_core::config_ops::{ConfigOpsBackend, ConfigOpsError, ConfigOpsService};

fn unique_temp_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "oraclemcp-discover-merge-{}-{stamp}-{label}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn profile_block(name: &str) -> String {
    format!(
        "\n[[profiles]]\nname = \"{name}\"\nconnect_string = \"h.example.com:1521/S\"\ncredential_ref = \"env:ORACLE_{}_PASSWORD\"\nmax_level = \"READ_ONLY\"\ndefault_level = \"READ_ONLY\"\n",
        name.to_ascii_uppercase()
    )
}

#[test]
fn concurrent_edit_between_base_read_and_apply_is_rejected() {
    let store_root = unique_temp_dir("store");
    let backend = ConfigOpsBackend::open(&store_root).expect("open config ops");
    let target_dir = unique_temp_dir("target");
    let target = target_dir.join("profiles.toml");

    // The base config the merge is computed from.
    let base = format!("schema_version = 2\n{}", profile_block("a"));
    std::fs::write(&target, &base).expect("write base");
    let base_hash = oraclemcp_audit::sha256_hex(base.as_bytes());

    // A concurrent external edit lands before the apply (the operator, another
    // agent, or the dashboard added a profile).
    let edited = format!("{base}{}", profile_block("b"));
    std::fs::write(&target, &edited).expect("concurrent edit");

    // The merged draft the discovery flow computed from `base` (base + a new
    // add-only block), applied with the STALE base hash, must be rejected.
    let merged = format!("{base}{}", profile_block("c"));
    let service = ConfigOpsService::new(backend, target.clone(), None);
    let err = service
        .apply(&merged, Some(&base_hash))
        .expect_err("a stale base hash must be rejected as CurrentChanged");
    assert!(
        matches!(err, ConfigOpsError::CurrentChanged { .. }),
        "verify-before-mutate rejects a racing edit rather than clobbering it: {err:?}"
    );

    // The concurrent edit is intact — nothing was written.
    assert_eq!(
        std::fs::read_to_string(&target).expect("target readable"),
        edited,
        "the racing edit is preserved verbatim"
    );

    std::fs::remove_dir_all(&store_root).ok();
    std::fs::remove_dir_all(&target_dir).ok();
}

#[test]
fn matching_base_hash_applies_cleanly() {
    // The companion happy path: when no concurrent edit occurred, the same
    // apply with the matching base hash succeeds and leaves a backup.
    let store_root = unique_temp_dir("store-ok");
    let backend = ConfigOpsBackend::open(&store_root).expect("open config ops");
    let target_dir = unique_temp_dir("target-ok");
    let target = target_dir.join("profiles.toml");

    let base = format!("schema_version = 2\n{}", profile_block("a"));
    std::fs::write(&target, &base).expect("write base");
    let base_hash = oraclemcp_audit::sha256_hex(base.as_bytes());

    let merged = format!("{base}{}", profile_block("c"));
    let service = ConfigOpsService::new(backend, target.clone(), None);
    let outcome = service
        .apply(&merged, Some(&base_hash))
        .expect("matching base hash applies");
    assert!(outcome.apply.backup_path.exists(), "a backup is written");
    let installed = std::fs::read_to_string(&target).expect("target readable");
    assert!(installed.contains("name = \"a\""));
    assert!(installed.contains("name = \"c\""));

    std::fs::remove_dir_all(&store_root).ok();
    std::fs::remove_dir_all(&target_dir).ok();
}
