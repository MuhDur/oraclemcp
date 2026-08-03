#[test]
fn build_auditor_installs_when_writable_profile_has_a_key() {
    // With a signing key configured, a writable reachable profile installs
    // an auditor (so the writable profile, after a switch, is audited).
    // Startup hardens this pre-existing parent to its exact owner-only policy.
    let dir = tempfile::tempdir().expect("private audit tempdir");
    let audit = AuditConfig {
        path: Some(dir.path().join("audit.jsonl")),
        key_ref: Some("literal:0123456789abcdef0123456789abcdef".to_owned()),
        ..AuditConfig::default()
    };
    let active = SessionLevelState::new(OperatingLevel::ReadOnly, false);
    match build_auditor(&audit, &active, OperatingLevel::Ddl, &SystemSecretResolver) {
        Ok(auditor) => assert!(
            auditor.is_some(),
            "an auditor must be installed when a write level is reachable"
        ),
        Err((code, msg)) => panic!("auditor should build with a key: {code}: {msg}"),
    }
}

#[cfg(windows)]
#[test]
fn build_auditor_hardens_a_new_worm_parent_before_opening_the_mirror() {
    let root = tempfile::tempdir().expect("audit tempdir");
    let audit = AuditConfig {
        path: Some(root.path().join("primary/audit.jsonl")),
        key_ref: Some("literal:0123456789abcdef0123456789abcdef".to_owned()),
        shipping: Some(oraclemcp_config::AuditShippingConfig {
            worm_path: Some(root.path().join("worm/audit.jsonl")),
            ..oraclemcp_config::AuditShippingConfig::default()
        }),
        ..AuditConfig::default()
    };
    let active = SessionLevelState::new(OperatingLevel::ReadOnly, false);

    match build_auditor(&audit, &active, OperatingLevel::Ddl, &SystemSecretResolver) {
        Ok(Some(_)) => {}
        Ok(None) => panic!("a writable profile with a signing key must install an auditor"),
        Err((code, message)) => {
            panic!(
                "WORM startup must harden its parent before opening the mirror: {code}: {message}"
            )
        }
    }
}
