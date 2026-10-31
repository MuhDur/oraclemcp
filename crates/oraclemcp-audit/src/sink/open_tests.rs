use super::*;

#[test]
fn system_link_requires_root_ownership_and_a_protected_parent() {
    assert!(trusted_audit_root_link(0, 0, 0o755));
    assert!(!trusted_audit_root_link(1000, 0, 0o755));
    assert!(!trusted_audit_root_link(0, 1000, 0o700));
    assert!(!trusted_audit_root_link(0, 0, 0o775));
    assert!(!trusted_audit_root_link(0, 0, 0o1777));
}

#[test]
fn system_link_target_requires_root_and_private_or_sticky_permissions() {
    assert!(trusted_audit_root_target(0, 0o755, true));
    assert!(trusted_audit_root_target(0, 0o1777, true));
    assert!(!trusted_audit_root_target(0, 0o777, true));
    assert!(!trusted_audit_root_target(0, 0o775, true));
    assert!(!trusted_audit_root_target(1000, 0o700, true));
    assert!(!trusted_audit_root_target(1000, 0o1777, true));
    assert!(!trusted_audit_root_target(0, 0o1777, false));
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn root_link_audit_fixture() -> (tempfile::TempDir, PathBuf) {
    use std::os::unix::fs::MetadataExt;
    #[cfg(target_os = "linux")]
    let alias = Path::new("/var/lock");
    #[cfg(target_os = "macos")]
    let alias = Path::new("/tmp");
    let link = std::fs::symlink_metadata(alias).expect("system temporary-directory link");
    assert!(link.file_type().is_symlink());
    assert_eq!(link.uid(), 0);
    let directory = tempfile::Builder::new()
        .prefix("oraclemcp-audit-")
        .tempdir_in(alias.canonicalize().unwrap())
        .expect("private fixture beneath the system link target");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let configured = alias.join(directory.path().file_name().unwrap());
    (directory, configured)
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn root_owned_system_link_supports_audit_anchor_recovery_and_mirror() {
    use crate::record::{AuditDecision, AuditOutcome, AuditSubject};
    let (directory, configured) = root_link_audit_fixture();
    let log = configured.join("audit.jsonl");
    let anchor = crate::anchor_path_for(&log);
    let key = SigningKey::new("root-link-test", vec![7; 32]).unwrap();
    let primary = FileAuditSink::open(&log).expect("trusted root link admits the audit sink");
    let mirror = crate::WormFileForwarder::open_distinct(
        configured.join("mirror.jsonl"),
        &primary,
        std::slice::from_ref(&key),
    )
    .expect("trusted root link admits a distinct mirror");
    drop(mirror);
    let draft = AuditEntryDraft {
        subject: AuditSubject::new("test", "root-link"),
        db_evidence: None,
        cancel: None,
        result_masking: None,
        tool: "oracle_query".to_owned(),
        sql: "SELECT 1 FROM SYS.DUAL".to_owned(),
        danger_level: "SAFE".to_owned(),
        decision: AuditDecision::Allowed,
        rows_affected: None,
        outcome: AuditOutcome::Pending,
    };
    let auditor = Auditor::new(Box::new(primary), key.clone()).with_head_anchor(&anchor);
    let first = auditor.append(&draft, "t0".to_owned(), true).unwrap();
    let loaded = crate::load_anchor(&anchor).unwrap().unwrap();
    assert_eq!(loaded.seq, first.seq);
    assert_eq!(loaded.entry_hash, first.entry_hash);
    assert!(directory.path().join("audit.jsonl").is_file());
    assert!(directory.path().join("audit.jsonl.lock").is_file());
    assert!(directory.path().join("mirror.jsonl").is_file());
    drop(auditor);
    let reopened = FileAuditSink::open(&log).unwrap();
    let recovered = Auditor::new(Box::new(reopened), key)
        .with_head_anchor(&anchor)
        .resume_from(&log)
        .expect("recovery binds ledger and anchor under the root link");
    let second = recovered.append(&draft, "t1".to_owned(), true).unwrap();
    assert_eq!(second.seq, first.seq + 1);
    assert_eq!(
        crate::load_anchor(&anchor).unwrap().unwrap().seq,
        second.seq
    );
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn root_owned_nonsticky_system_target_supports_audit_open() {
    #[cfg(target_os = "linux")]
    let alias = Path::new("/var/run/lock");
    #[cfg(target_os = "macos")]
    let alias = Path::new("/var/tmp");
    let directory = tempfile::tempdir_in(alias.canonicalize().unwrap()).unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let configured = alias.join(directory.path().file_name().unwrap());
    let (held, resolved) = open_existing_audit_directory(&configured).unwrap();
    assert_eq!(resolved, directory.path().canonicalize().unwrap());
    authenticate_held_audit_directory(&held, &resolved).unwrap();
    FileAuditSink::open(configured.join("audit.jsonl")).unwrap();
    assert!(directory.path().join("audit.jsonl").is_file());
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn sticky_system_target_requires_an_owned_private_immediate_child() {
    let (directory, configured) = root_link_audit_fixture();
    let uid = rustix::process::geteuid().as_raw();
    walk_audit_directory(&configured, AuditDirectoryWalk::Configured, uid).unwrap();
    assert!(walk_audit_directory(&configured, AuditDirectoryWalk::Configured, uid ^ 1).is_err());
    for mode in [0o755, 0o777] {
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(walk_audit_directory(&configured, AuditDirectoryWalk::Configured, uid).is_err());
    }
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    #[cfg(target_os = "linux")]
    let alias = Path::new("/var/lock");
    #[cfg(target_os = "macos")]
    let alias = Path::new("/tmp");
    assert!(open_existing_audit_directory(alias).is_err());
}

#[test]
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn admitted_system_link_returns_a_physical_path_for_strict_revalidation() {
    let (directory, configured) = root_link_audit_fixture();
    let (held, resolved) = open_existing_audit_directory(&configured).unwrap();
    assert_eq!(resolved, directory.path().canonicalize().unwrap());
    authenticate_held_audit_directory(&held, &resolved).unwrap();
    assert!(open_existing_audit_directory_nofollow(&configured).is_err());
    #[cfg(target_os = "linux")]
    let nested_target = Path::new("/var/run");
    #[cfg(target_os = "macos")]
    let nested_target = Path::new("/tmp");
    assert!(
        walk_audit_directory(
            nested_target,
            AuditDirectoryWalk::RootLinkTarget,
            rustix::process::geteuid().as_raw(),
        )
        .is_err()
    );
    #[cfg(target_os = "linux")]
    let concealed_link = Path::new("/var/run/../..");
    #[cfg(target_os = "macos")]
    let concealed_link = Path::new("/tmp/..");
    walk_audit_directory(
        Path::new("/"),
        AuditDirectoryWalk::RootLinkTarget,
        rustix::process::geteuid().as_raw(),
    )
    .unwrap();
    assert!(
        walk_audit_directory(
            concealed_link,
            AuditDirectoryWalk::RootLinkTarget,
            rustix::process::geteuid().as_raw(),
        )
        .is_err()
    );
    #[cfg(target_os = "linux")]
    let relative_target = Path::new("/var/../run/lock");
    #[cfg(target_os = "macos")]
    let relative_target = Path::new("/private/../private/tmp");
    let (_, physical) = walk_audit_directory(
        relative_target,
        AuditDirectoryWalk::RootLinkTarget,
        rustix::process::geteuid().as_raw(),
    )
    .unwrap();
    assert_eq!(physical, relative_target.canonicalize().unwrap());
}

#[test]
fn recreated_audit_and_lock_entries_fsync_the_parent_from_actual_open_outcomes() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().expect("temporary audit directory");
    let audit_path = directory.path().join("audit.jsonl");
    let lock_path = lock_path_for(&audit_path);
    std::fs::write(&audit_path, b"stale audit entry").expect("seed an existing audit entry");
    std::fs::write(&lock_path, b"stale lock entry").expect("seed an existing lock entry");
    let stale_audit_path = directory.path().join("audit.jsonl.stale");
    let stale_lock_path = directory.path().join("audit.jsonl.lock.stale");
    let audit_for_hook = audit_path.clone();
    let lock_for_hook = lock_path.clone();
    set_file_audit_open_hook(move || {
        // Preserve both pre-existing objects under distinct names. This models
        // an operator/attacker removal after historical existence probes
        // without deleting any test artifact.
        std::fs::rename(&audit_for_hook, &stale_audit_path)
            .expect("move stale audit entry out of the secure-open path");
        std::fs::rename(&lock_for_hook, &stale_lock_path)
            .expect("move stale lock entry out of the secure-open path");
    });

    let before = PARENT_DIR_FSYNCS.with(std::cell::Cell::get);
    let sink = FileAuditSink::open(&audit_path).expect("secure open recreates both entries");
    let after = PARENT_DIR_FSYNCS.with(std::cell::Cell::get);

    assert_eq!(
        after,
        before + 1,
        "the actual audit/lock creations, not stale exists checks, require one parent fsync"
    );
    assert_eq!(
        std::fs::metadata(&audit_path)
            .expect("new audit entry metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600,
        "recreated audit entry remains owner-private"
    );
    assert_eq!(
        std::fs::metadata(&lock_path)
            .expect("new lock entry metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600,
        "recreated lock entry remains owner-private"
    );
    drop(sink);
}
