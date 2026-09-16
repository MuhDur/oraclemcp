use super::*;

#[cfg(unix)]
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
