#[test]
fn build_auditor_installs_when_writable_profile_has_a_key() {
    // With a signing key configured, a writable reachable profile installs
    // an auditor (so the writable profile, after a switch, is audited).
    // Startup hardens this pre-existing parent to its exact owner-only policy.
    let dir = tempfile::tempdir().expect("private audit tempdir");
    let audit = AuditConfig {
        path: Some(dir.path().join("private/audit.jsonl")),
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

// Bead .12.2: native-Windows proof of the WORM shipping parent and the startup
// audit parent. A missing parent is created private, a broad user-owned parent
// is tightened, and a foreign-owned parent is refused; `fs::create_dir_all`
// would have accepted both pre-existing parents. The owner/DACL fixtures mirror
// the oraclemcp-audit sink tests, which are private to that crate.

fn audit_startup_config(primary: &Path, worm: Option<&Path>) -> AuditConfig {
    AuditConfig {
        path: Some(primary.to_path_buf()),
        key_ref: Some("literal:0123456789abcdef0123456789abcdef".to_owned()),
        shipping: worm.map(|worm| oraclemcp_config::AuditShippingConfig {
            worm_path: Some(worm.to_path_buf()),
            ..oraclemcp_config::AuditShippingConfig::default()
        }),
        ..AuditConfig::default()
    }
}

fn start_audit(audit: &AuditConfig) -> Result<(), (&'static str, String)> {
    let active = SessionLevelState::new(OperatingLevel::ReadOnly, false);
    build_auditor(audit, &active, OperatingLevel::Ddl, &SystemSecretResolver).map(|auditor| {
        assert!(
            auditor.is_some(),
            "a writable profile with a key installs an auditor"
        );
    })
}

fn log_audit_parent_case(
    case_id: &str,
    path_kind: &str,
    expected: &str,
    actual: &str,
    error_code: Option<&str>,
) {
    eprintln!(
        "{}",
        serde_json::json!({
            "case_id": case_id,
            "path_kind": path_kind,
            "expected": expected,
            "actual": actual,
            "error_code": error_code,
        })
    );
}

/// Owner is TokenUser, and the DACL rendered with the TokenUser SID redacted.
#[cfg(windows)]
fn windows_owner_and_dacl(path: &Path) -> (bool, String) {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};

    let descriptor = windows_permissions::wrappers::GetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Dacl,
    )
    .expect("read owner and DACL");
    let current =
        windows_permissions::utilities::current_process_sid().expect("resolve TokenUser SID");
    let rendered =
        windows_permissions::wrappers::ConvertSecurityDescriptorToStringSecurityDescriptor(
            &descriptor,
            SecurityInformation::Dacl,
        )
        .expect("render DACL");
    (
        descriptor.owner() == Some(&*current),
        rendered
            .to_string_lossy()
            .replace(&current.to_string(), "TokenUser"),
    )
}

#[cfg(windows)]
const PRIVATE_DIRECTORY_DACL: &str = "D:P(A;OICI;FA;;;TokenUser)";

#[cfg(windows)]
fn assert_private_directory(path: &Path) {
    let (owner_is_user, dacl) = windows_owner_and_dacl(path);
    assert!(
        owner_is_user,
        "{} must be owned by TokenUser",
        path.display()
    );
    assert_eq!(dacl, PRIVATE_DIRECTORY_DACL, "{} DACL", path.display());
}

/// An unprotected DACL granting Everyone and the user full access, owned by the user.
#[cfg(windows)]
fn install_broad_directory_dacl(path: &Path) {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::{LocalBox, SecurityDescriptor};

    let current =
        windows_permissions::utilities::current_process_sid().expect("resolve TokenUser SID");
    let descriptor: LocalBox<SecurityDescriptor> =
        format!("D:(A;OICI;FA;;;WD)(A;OICI;FA;;;{current})")
            .parse()
            .expect("parse broad DACL");
    windows_permissions::wrappers::SetNamedSecurityInfo(
        path.as_os_str(),
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::UnprotectedDacl,
        None,
        None,
        descriptor.dacl(),
        None,
    )
    .expect("install broad DACL");
    let (owner_is_user, dacl) = windows_owner_and_dacl(path);
    assert!(owner_is_user, "broad fixture stays user-owned");
    assert!(
        dacl.contains(";;;WD)"),
        "fixture must grant Everyone: {dacl}"
    );
}

#[cfg(windows)]
fn plant_system_owner(path: &Path) {
    let status = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/setowner", "*S-1-5-18"])
        .status()
        .expect("run icacls /setowner");
    assert!(status.success(), "icacls must plant the SYSTEM owner");
    let (owner_is_user, _) = windows_owner_and_dacl(path);
    assert!(!owner_is_user, "fixture owner must differ from TokenUser");
}

#[cfg(windows)]
#[test]
fn build_auditor_hardens_a_new_worm_parent_before_opening_the_mirror() {
    let root = tempfile::tempdir().expect("audit tempdir");
    let worm_parent = root.path().join("worm");
    let audit = audit_startup_config(
        &root.path().join("primary/audit.jsonl"),
        Some(&worm_parent.join("audit.jsonl")),
    );
    start_audit(&audit).unwrap_or_else(|(code, message)| panic!("{code}: {message}"));
    // The mirror opens with the private append-file primitive, which refuses a
    // parent without this exact DACL, so a successful start means the parent was
    // private before the file opened.
    assert_private_directory(&worm_parent);
    assert!(
        worm_parent.join("audit.jsonl").is_file(),
        "the WORM mirror opened"
    );
    log_audit_parent_case(
        "build_auditor_hardens_a_new_worm_parent_before_opening_the_mirror",
        "worm_parent_missing",
        "created_private",
        "created_private",
        None,
    );
}

#[cfg(windows)]
#[test]
fn worm_parent_existing_broad_user_owned_dacl_is_tightened() {
    let root = tempfile::tempdir().expect("audit tempdir");
    let worm_parent = root.path().join("worm");
    std::fs::create_dir(&worm_parent).expect("pre-create WORM parent");
    install_broad_directory_dacl(&worm_parent);
    let audit = audit_startup_config(
        &root.path().join("primary/audit.jsonl"),
        Some(&worm_parent.join("audit.jsonl")),
    );
    start_audit(&audit).unwrap_or_else(|(code, message)| panic!("{code}: {message}"));
    assert_private_directory(&worm_parent);
    log_audit_parent_case(
        "worm_parent_existing_broad_user_owned_dacl_is_tightened",
        "worm_parent_broad_user_owned",
        "tightened",
        "tightened",
        None,
    );
}

#[cfg(windows)]
#[test]
fn worm_parent_foreign_owned_is_refused_shipping_invalid() {
    let root = tempfile::tempdir().expect("audit tempdir");
    let worm_parent = root.path().join("worm");
    std::fs::create_dir(&worm_parent).expect("pre-create WORM parent");
    plant_system_owner(&worm_parent);
    // The plain directory path this replaced accepts the foreign-owned parent.
    std::fs::create_dir_all(&worm_parent).expect("create_dir_all accepts an existing parent");
    let audit = audit_startup_config(
        &root.path().join("primary/audit.jsonl"),
        Some(&worm_parent.join("audit.jsonl")),
    );
    let (code, message) = start_audit(&audit).expect_err("a SYSTEM-owned WORM parent is refused");
    assert_eq!(code, "ORACLEMCP_AUDIT_SHIPPING_INVALID", "{message}");
    assert!(
        !worm_parent.join("audit.jsonl").exists(),
        "no mirror file may open beneath it"
    );
    log_audit_parent_case(
        "worm_parent_foreign_owned_is_refused_shipping_invalid",
        "worm_parent_system_owned",
        "refused",
        "refused",
        Some(code),
    );
}

#[cfg(windows)]
#[test]
fn startup_audit_parent_missing_is_created_private() {
    let root = tempfile::tempdir().expect("audit tempdir");
    let parent = root.path().join("fresh");
    let audit = audit_startup_config(&parent.join("audit.jsonl"), None);
    start_audit(&audit).unwrap_or_else(|(code, message)| panic!("{code}: {message}"));
    assert_private_directory(&parent);
    log_audit_parent_case(
        "startup_audit_parent_missing_is_created_private",
        "audit_parent_missing",
        "created_private",
        "created_private",
        None,
    );
}

#[cfg(windows)]
#[test]
fn startup_audit_parent_broad_dacl_negative_case() {
    // The retained broad-parent negative case: a user-owned parent that grants
    // Everyone full access must not stay broad. Policy tightens it to the exact
    // private DACL before the audit log opens beneath it.
    let root = tempfile::tempdir().expect("audit tempdir");
    let parent = root.path().join("broad");
    std::fs::create_dir(&parent).expect("pre-create audit parent");
    install_broad_directory_dacl(&parent);
    let audit = audit_startup_config(&parent.join("audit.jsonl"), None);
    start_audit(&audit).unwrap_or_else(|(code, message)| panic!("{code}: {message}"));
    assert_private_directory(&parent);
    log_audit_parent_case(
        "startup_audit_parent_broad_dacl_negative_case",
        "audit_parent_broad_user_owned",
        "tightened",
        "tightened",
        None,
    );
}

#[cfg(windows)]
#[test]
fn startup_audit_parent_foreign_owned_is_refused() {
    let root = tempfile::tempdir().expect("audit tempdir");
    let parent = root.path().join("foreign");
    std::fs::create_dir(&parent).expect("pre-create audit parent");
    plant_system_owner(&parent);
    std::fs::create_dir_all(&parent).expect("create_dir_all accepts an existing parent");
    let audit = audit_startup_config(&parent.join("audit.jsonl"), None);
    let (code, message) = start_audit(&audit).expect_err("a SYSTEM-owned audit parent is refused");
    assert_eq!(code, "ORACLEMCP_AUDIT_PATH_INVALID", "{message}");
    assert!(
        !parent.join("audit.jsonl").exists(),
        "no audit file may open beneath it"
    );
    log_audit_parent_case(
        "startup_audit_parent_foreign_owned_is_refused",
        "audit_parent_system_owned",
        "refused",
        "refused",
        Some(code),
    );
}

#[cfg(unix)]
#[test]
fn worm_parent_unix_create_dir_all_unchanged() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().expect("audit tempdir");
    let primary_parent = root.path().join("primary");
    let worm_parent = root.path().join("worm");
    let audit = audit_startup_config(
        &primary_parent.join("audit.jsonl"),
        Some(&worm_parent.join("audit.jsonl")),
    );
    start_audit(&audit).unwrap_or_else(|(code, message)| panic!("{code}: {message}"));
    let mode = |path: &Path| {
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    };
    // The primary audit directory keeps the private 0700 semantics.
    assert_eq!(mode(&primary_parent), 0o700);
    // The WORM parent is still a plain create_dir_all directory: the same mode a
    // control directory created the same way gets under this process's umask.
    let control = root.path().join("control");
    std::fs::create_dir_all(&control).expect("control directory");
    assert!(worm_parent.is_dir());
    assert_eq!(mode(&worm_parent), mode(&control));
    log_audit_parent_case(
        "worm_parent_unix_create_dir_all_unchanged",
        "worm_parent_missing_unix",
        "create_dir_all",
        "create_dir_all",
        None,
    );
}
