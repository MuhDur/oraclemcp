use super::*;
use asupersync::runtime::RuntimeBuilder;

fn doctor(ctx: &DoctorContext<'_>) -> DoctorReport {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("current-thread runtime");
    runtime.block_on(async {
        let cx = Cx::current().expect("block_on installs a current Cx");
        run_doctor(&cx, ctx).await
    })
}

fn doctor_tmp_dir(name: &str) -> std::path::PathBuf {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest
        .parent()
        .and_then(std::path::Path::parent)
        .expect("crates/<crate> lives two levels below the workspace root");
    let mut path = workspace.join("target/tmp/oraclemcp-core-doctor-tests");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_nanos();
    path.push(format!("{}-{}-{name}", std::process::id(), nanos));
    std::fs::create_dir_all(&path).expect("test temp dir exists");
    std::fs::canonicalize(path).expect("test temp dir canonicalizes")
}

fn check_by_id(report: &DoctorReport, id: u8) -> &CheckResult {
    report
        .checks
        .iter()
        .find(|check| check.id == id)
        .expect("check present")
}

fn legacy_layout(root: &std::path::Path) -> DoctorStateLayout {
    DoctorStateLayout {
        legacy_audit_path: root.join("config").join("audit.jsonl"),
        current_audit_path: root.join("state").join("audit").join("audit.jsonl"),
        migration_backup_dir: root.join("state").join("doctor-migrations").join("backups"),
        audit_path_configured: false,
    }
}

fn write_patterned_audit(path: &std::path::Path, length: usize) {
    use std::io::Write as _;

    std::fs::create_dir_all(path.parent().expect("audit parent")).expect("audit parent exists");
    let mut file = std::fs::File::create(path).expect("create audit fixture");
    let pattern = *b"audit-jsonl-streaming-pattern\n";
    let mut remaining = length;
    while remaining >= pattern.len() {
        file.write_all(&pattern).expect("write full audit pattern");
        remaining -= pattern.len();
    }
    file.write_all(&pattern[..remaining])
        .expect("write audit tail");
    file.sync_all().expect("sync audit fixture");
}

#[test]
fn legacy_state_layout_detects_and_migrates_audit_jsonl_once() {
    let root = doctor_tmp_dir("legacy-state-migration");
    let layout = legacy_layout(&root);
    std::fs::create_dir_all(layout.legacy_audit_path.parent().expect("legacy parent"))
        .expect("legacy parent exists");
    let audit_jsonl = br#"{"schema_version":1,"seq":1}
"#;
    std::fs::write(&layout.legacy_audit_path, audit_jsonl).expect("seed legacy audit");

    let report = doctor(&DoctorContext {
        state_layout: Some(layout.clone()),
        audit_posture: Some(DoctorAuditPosture::SigningKeyConfigured {
            path: layout.current_audit_path.clone(),
        }),
        ..DoctorContext::default()
    });
    let check = check_by_id(&report, 13);
    assert_eq!(check.status, CheckStatus::Warn);
    assert!(
        check
            .fix
            .as_deref()
            .is_some_and(|fix| fix.contains("doctor --fix"))
    );

    let mutation = apply_legacy_state_migration(Some(&layout))
        .expect("migration succeeds")
        .expect("migration applied");
    assert_eq!(mutation.id, "legacy_state_audit_jsonl_migration");
    assert_eq!(
        std::fs::read(&layout.legacy_audit_path).expect("read legacy"),
        audit_jsonl
    );
    assert_eq!(
        std::fs::read(&layout.current_audit_path).expect("read current"),
        audit_jsonl
    );
    assert_eq!(
        std::fs::read(&mutation.backup).expect("read backup"),
        audit_jsonl
    );

    let rerun = doctor(&DoctorContext {
        state_layout: Some(layout.clone()),
        audit_posture: Some(DoctorAuditPosture::SigningKeyConfigured {
            path: layout.current_audit_path.clone(),
        }),
        ..DoctorContext::default()
    })
    .with_fix_report_mutations(vec![mutation]);
    assert_eq!(check_by_id(&rerun, 13).status, CheckStatus::Pass);
    let fix = rerun.fix.as_ref().expect("fix report");
    assert_eq!(fix.outcome, DoctorFixOutcome::Applied);
    assert_eq!(fix.exit_code, 0);
    assert_eq!(fix.mutations.len(), 1);
    assert!(
        apply_legacy_state_migration(Some(&layout))
            .expect("second migration is noop")
            .is_none(),
        "migration must be idempotent after the byte-identical copy exists"
    );
}

#[test]
fn legacy_migration_streams_a_large_audit_to_byte_identical_outputs() {
    let root = doctor_tmp_dir("legacy-state-streaming-migration");
    let layout = legacy_layout(&root);
    let length = LEGACY_AUDIT_MIGRATION_BUFFER_BYTES * 4 + 137;
    write_patterned_audit(&layout.legacy_audit_path, length);

    let mutation = apply_legacy_state_migration(Some(&layout))
        .expect("large migration succeeds")
        .expect("large migration applies");
    assert_eq!(
        std::fs::metadata(&layout.current_audit_path)
            .expect("current metadata")
            .len(),
        length as u64
    );
    assert_eq!(
        std::fs::metadata(&mutation.backup)
            .expect("backup metadata")
            .len(),
        length as u64
    );
    assert!(
        audit_files_match(&layout.legacy_audit_path, &layout.current_audit_path)
            .expect("current matches legacy through the streaming comparer")
    );
    assert!(
        audit_files_match(
            &layout.legacy_audit_path,
            std::path::Path::new(&mutation.backup)
        )
        .expect("backup matches legacy through the streaming comparer")
    );
}

#[test]
fn equal_large_legacy_and_current_audits_remain_a_noop() {
    let root = doctor_tmp_dir("legacy-state-streaming-equality");
    let layout = legacy_layout(&root);
    let length = LEGACY_AUDIT_MIGRATION_BUFFER_BYTES * 3 + 19;
    write_patterned_audit(&layout.legacy_audit_path, length);
    write_patterned_audit(&layout.current_audit_path, length);

    assert!(
        apply_legacy_state_migration(Some(&layout))
            .expect("large equal audit pair is inspected safely")
            .is_none(),
        "equal large ledgers must not create a duplicate migration"
    );
}

#[test]
fn legacy_migration_copy_failure_never_publishes_the_current_target() {
    let root = doctor_tmp_dir("legacy-state-streaming-copy-failure");
    let layout = legacy_layout(&root);
    write_patterned_audit(
        &layout.legacy_audit_path,
        LEGACY_AUDIT_MIGRATION_BUFFER_BYTES + 1,
    );
    set_doctor_legacy_audit_copy_hook(|| Err("injected interrupted copy".to_owned()));

    let error = apply_legacy_state_migration(Some(&layout))
        .expect_err("an interrupted copy must stop migration");
    assert_eq!(error, "injected interrupted copy");
    assert!(
        !layout.current_audit_path.exists(),
        "a partially copied staging file must never become the current audit target"
    );
}

#[cfg(unix)]
#[test]
fn legacy_migration_refuses_source_swap_before_any_copy() {
    let root = doctor_tmp_dir("legacy-state-source-symlink-race");
    let layout = legacy_layout(&root);
    std::fs::create_dir_all(layout.legacy_audit_path.parent().expect("legacy parent"))
        .expect("legacy parent exists");
    std::fs::write(&layout.legacy_audit_path, b"audit source").expect("seed legacy audit");
    let moved_source = root.join("moved-audit.jsonl");
    let attacker_target = root.join("attacker-audit.jsonl");
    let source_for_hook = layout.legacy_audit_path.clone();
    set_doctor_legacy_audit_open_hook(move || {
        std::fs::rename(&source_for_hook, &moved_source).expect("move observed source aside");
        std::os::unix::fs::symlink(&attacker_target, &source_for_hook)
            .expect("replace source with symlink");
    });

    let error = apply_legacy_state_migration(Some(&layout))
        .expect_err("source replacement must refuse before migration writes");
    assert!(
        error.contains("failed to open legacy audit JSONL")
            || error.contains("changed while opening"),
        "source swap error stays specific: {error}"
    );
    assert!(
        !layout.current_audit_path.exists(),
        "a swapped source cannot publish a current audit target"
    );
    assert!(
        !layout
            .migration_backup_dir
            .join("legacy-audit-jsonl.backup")
            .exists(),
        "a swapped source cannot publish a backup"
    );
}

#[cfg(unix)]
#[test]
fn legacy_migration_refuses_symlink_swaps_at_atomic_install() {
    let audit_jsonl = br#"{"schema_version":1,"seq":1}
"#;

    let parent_swap_root = doctor_tmp_dir("legacy-state-parent-symlink-race");
    let parent_swap = legacy_layout(&parent_swap_root);
    std::fs::create_dir_all(
        parent_swap
            .legacy_audit_path
            .parent()
            .expect("legacy parent"),
    )
    .expect("legacy parent exists");
    std::fs::write(&parent_swap.legacy_audit_path, audit_jsonl).expect("seed legacy audit");
    let verified_parent = parent_swap
        .current_audit_path
        .parent()
        .expect("current parent")
        .to_owned();
    let moved_parent = parent_swap_root.join("state").join("audit-verified");
    let attacker_parent = parent_swap_root.join("attacker-parent");
    std::fs::create_dir_all(&attacker_parent).expect("attacker parent exists");
    let attacker_parent_for_hook = attacker_parent.clone();
    set_doctor_atomic_install_hook(move || {
        std::fs::rename(&verified_parent, &moved_parent).expect("move verified parent");
        std::os::unix::fs::symlink(&attacker_parent_for_hook, &verified_parent)
            .expect("replace visible parent with symlink");
    });
    let parent_error = apply_legacy_state_migration(Some(&parent_swap))
        .expect_err("replaced destination parent must refuse");
    assert!(
        parent_error.contains("not a safe directory"),
        "{parent_error}"
    );
    assert!(
        !attacker_parent.join("audit.jsonl").exists(),
        "the held parent must prevent writes through the replacement symlink"
    );

    let destination_swap_root = doctor_tmp_dir("legacy-state-destination-symlink-race");
    let destination_swap = legacy_layout(&destination_swap_root);
    std::fs::create_dir_all(
        destination_swap
            .legacy_audit_path
            .parent()
            .expect("legacy parent"),
    )
    .expect("legacy parent exists");
    std::fs::write(&destination_swap.legacy_audit_path, audit_jsonl).expect("seed legacy audit");
    let attacker_target = destination_swap_root.join("attacker-target");
    set_doctor_atomic_install_hook({
        let destination = destination_swap.current_audit_path.clone();
        let attacker_target = attacker_target.clone();
        move || {
            std::os::unix::fs::symlink(&attacker_target, &destination)
                .expect("replace destination with symlink");
        }
    });
    let destination_error = apply_legacy_state_migration(Some(&destination_swap))
        .expect_err("replacement destination must preserve create-new semantics");
    assert!(
        destination_error.contains("failed to install"),
        "{destination_error}"
    );
    assert!(
        !attacker_target.exists(),
        "the destination symlink must never receive the migration write"
    );
}
