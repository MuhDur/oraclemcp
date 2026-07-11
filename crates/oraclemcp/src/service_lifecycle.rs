use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use cap_fs_ext::{DirExt as _, FollowSymlinks, MetadataExt as _, OpenOptionsFollowExt as _};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, DirBuilder as CapDirBuilder, OpenOptions as CapOpenOptions};
use oraclemcp_audit::{SigningKey, VerifyOutcome, ct_eq, parse_jsonl, sha256_hex, verify_records};
use oraclemcp_core::{DoctorServiceUnitCaps, DoctorServiceUnitLimitCaps, FileStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const SERVICE_LIMIT_NOFILE: u64 = 65_536;
const SERVICE_TASKS_MAX: u64 = 512;
const SERVICE_MEMORY_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const SERVICE_MEMORY_MAX_SYSTEMD: &str = "2G";
const SERVICE_OOM_SCORE_ADJUST: i16 = 100;
const SERVICE_INSTANCE_LOCK_FILE: &str = "service-instance.json";
const SERVICE_INSTANCE_SCHEMA_VERSION: u8 = 1;
const SERVICE_STATE_LOCK_FILE: &str = ".service.lock";
const BACKUP_MANIFEST_FILE: &str = "manifest.json";
const BACKUP_SCHEMA_VERSION: u32 = 2;
const BACKUP_KIND: &str = "oraclemcp_service_backup";
const BACKUP_MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"oraclemcp:service-backup-manifest:v2\0";

#[derive(Debug, Clone)]
pub(crate) struct ServiceError {
    pub(crate) code: &'static str,
    pub(crate) message: String,
    pub(crate) exit_code: u8,
}

impl ServiceError {
    fn new(code: &'static str, message: impl Into<String>, exit_code: u8) -> Self {
        Self {
            code,
            message: message.into(),
            exit_code,
        }
    }

    fn confirm_required(action: &str) -> Self {
        Self::new(
            "ORACLEMCP_SERVICE_CONFIRM_REQUIRED",
            format!(
                "`oraclemcp service {action}` changes local service-manager state; rerun with \
                 `--dry-run` to inspect the plan or `--yes` to execute it"
            ),
            2,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ServiceManager {
    SystemdUser,
    LaunchdUser,
    WindowsService,
}

impl ServiceManager {
    pub(crate) fn detect() -> Result<Self, ServiceError> {
        if cfg!(target_os = "linux") {
            Ok(ServiceManager::SystemdUser)
        } else if cfg!(target_os = "macos") {
            Ok(ServiceManager::LaunchdUser)
        } else if cfg!(target_os = "windows") {
            Ok(ServiceManager::WindowsService)
        } else {
            Err(ServiceError::new(
                "ORACLEMCP_SERVICE_UNSUPPORTED_PLATFORM",
                "service lifecycle is supported on Linux systemd --user, macOS launchd, and Windows services",
                2,
            ))
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            ServiceManager::SystemdUser => "systemd_user",
            ServiceManager::LaunchdUser => "launchd_user",
            ServiceManager::WindowsService => "windows_service",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ServiceInstallOptions {
    pub(crate) name: String,
    pub(crate) listen: String,
    pub(crate) profile: Option<String>,
    pub(crate) allow_no_auth: bool,
    pub(crate) client_credentials: bool,
    pub(crate) skip_linger: bool,
    pub(crate) yes: bool,
    pub(crate) dry_run: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ServiceMutationOptions {
    pub(crate) name: String,
    pub(crate) yes: bool,
    pub(crate) dry_run: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ServiceReadOptions {
    pub(crate) name: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ServiceLogsOptions {
    pub(crate) name: String,
    pub(crate) lines: u16,
}

#[derive(Debug, Clone)]
pub(crate) struct ServiceBackupOptions {
    pub(crate) name: String,
    pub(crate) state_dir: PathBuf,
    pub(crate) config_path: PathBuf,
    pub(crate) audit_path: PathBuf,
    pub(crate) manifest_signing_key: SigningKey,
    pub(crate) output: Option<PathBuf>,
    pub(crate) yes: bool,
    pub(crate) dry_run: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ServiceRestoreOptions {
    pub(crate) name: String,
    pub(crate) state_dir: PathBuf,
    pub(crate) config_path: PathBuf,
    pub(crate) audit_path: PathBuf,
    pub(crate) backup: PathBuf,
    pub(crate) audit_keys: Vec<SigningKey>,
    pub(crate) yes: bool,
    pub(crate) dry_run: bool,
}

#[derive(Debug, Clone)]
pub(crate) enum ServiceCommand {
    Install(ServiceInstallOptions),
    Uninstall(ServiceMutationOptions),
    Restart(ServiceMutationOptions),
    Status(ServiceReadOptions),
    Logs(ServiceLogsOptions),
    Backup(ServiceBackupOptions),
    Restore(ServiceRestoreOptions),
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ServiceResult {
    pub(crate) exit_code: u8,
    pub(crate) payload: serde_json::Value,
    pub(crate) text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupFileManifest {
    present: bool,
    source_path: String,
    backup_path: Option<String>,
    sha256: Option<String>,
    bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupTreeFileManifest {
    path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupTreeManifest {
    source_path: String,
    backup_path: String,
    file_count: usize,
    bytes: u64,
    files: Vec<BackupTreeFileManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupManifest {
    schema_version: u32,
    kind: String,
    service_name: String,
    created_unix_ms: u64,
    state: BackupTreeManifest,
    config: BackupFileManifest,
    audit: BackupFileManifest,
    audit_anchor: BackupFileManifest,
    service_lock_held: bool,
    transient_files_skipped: Vec<String>,
    manifest_key_id: String,
    manifest_signature: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum RestoreAuditVerification {
    Verified { records: usize, file: String },
    NoAuditLog,
}

#[derive(Debug)]
struct PreparedBackupFile {
    bytes: u64,
    snapshot: File,
}

#[derive(Debug)]
struct PreparedStateFile {
    relative_path: PathBuf,
    source: PreparedBackupFile,
}

#[derive(Debug)]
struct PreparedTarget {
    root: Dir,
    relative_path: PathBuf,
    display_path: PathBuf,
}

#[derive(Debug)]
struct PreparedRestore {
    state_files: Vec<PreparedStateFile>,
    config: Option<PreparedBackupFile>,
    audit: Option<PreparedBackupFile>,
    audit_anchor: Option<PreparedBackupFile>,
    state_target: PreparedTarget,
    config_target: PreparedTarget,
    audit_target: PreparedTarget,
    audit_anchor_target: PreparedTarget,
    audit_verification: RestoreAuditVerification,
}

#[derive(Debug)]
pub(crate) struct ServiceInstanceGuard {
    path: PathBuf,
    token: String,
}

impl Drop for ServiceInstanceGuard {
    fn drop(&mut self) {
        let owned = fs::read_to_string(&self.path)
            .ok()
            .and_then(|body| serde_json::from_str::<ServiceInstanceMetadata>(&body).ok())
            .is_some_and(|metadata| metadata.token == self.token);
        if owned && fs::remove_file(&self.path).is_ok() {
            let _ = sync_parent_dir(&self.path);
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ServiceInstanceMetadata {
    schema_version: u8,
    pid: u32,
    listen: String,
    started_unix_ms: u64,
    token: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum ServiceInstanceDiscovery {
    Missing {
        lock_path: String,
    },
    Present {
        lock_path: String,
        pid: u32,
        listen: String,
        started_unix_ms: u64,
    },
    Unreadable {
        lock_path: String,
        error: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ServicePlan {
    pub(crate) ok: bool,
    pub(crate) kind: &'static str,
    pub(crate) action: &'static str,
    pub(crate) manager: ServiceManager,
    pub(crate) service_name: String,
    pub(crate) dry_run: bool,
    pub(crate) executable: String,
    pub(crate) serve_args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) service_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) hardening: Option<ServiceHardening>,
    pub(crate) steps: Vec<ServiceStep>,
    pub(crate) next_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ServiceHardening {
    pub(crate) manager: ServiceManager,
    pub(crate) configured: DoctorServiceUnitLimitCaps,
    pub(crate) notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ServiceStep {
    WriteFile {
        path: String,
        content: String,
    },
    RemoveFile {
        path: String,
        if_exists: bool,
    },
    Run {
        program: String,
        args: Vec<String>,
        optional: bool,
    },
}

pub(crate) fn run_service_command(command: ServiceCommand) -> Result<ServiceResult, ServiceError> {
    let manager = ServiceManager::detect()?;
    let exe = env::current_exe().map_err(|e| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_EXE_UNAVAILABLE",
            format!("failed to resolve current executable path: {e}"),
            2,
        )
    })?;
    run_service_command_with(command, manager, &exe)
}

pub(crate) fn run_service_command_with(
    command: ServiceCommand,
    manager: ServiceManager,
    exe: &Path,
) -> Result<ServiceResult, ServiceError> {
    match command {
        ServiceCommand::Install(options) => {
            require_confirmed("install", options.dry_run, options.yes)?;
            let plan = install_plan(manager, exe, options)?;
            execute_or_describe_plan(plan)
        }
        ServiceCommand::Uninstall(options) => {
            require_confirmed("uninstall", options.dry_run, options.yes)?;
            let plan = uninstall_plan(manager, exe, options)?;
            execute_or_describe_plan(plan)
        }
        ServiceCommand::Restart(options) => {
            require_confirmed("restart", options.dry_run, options.yes)?;
            let plan = restart_plan(manager, exe, options)?;
            execute_or_describe_plan(plan)
        }
        ServiceCommand::Status(options) => run_status(manager, &options.name),
        ServiceCommand::Logs(options) => run_logs(manager, &options.name, options.lines),
        ServiceCommand::Backup(options) => {
            require_confirmed("backup", options.dry_run, options.yes)?;
            run_backup(manager, options)
        }
        ServiceCommand::Restore(options) => {
            require_confirmed("restore", options.dry_run, options.yes)?;
            run_restore(manager, exe, options)
        }
    }
}

pub(crate) fn doctor_service_unit_caps() -> Option<DoctorServiceUnitCaps> {
    let manager = ServiceManager::detect().ok()?;
    Some(DoctorServiceUnitCaps {
        manager: manager.as_str().to_owned(),
        configured: configured_service_unit_caps(manager),
        effective: effective_service_unit_caps(),
        notes: service_hardening_notes(manager),
    })
}

pub(crate) fn acquire_service_instance_guard(
    listen: &str,
) -> Result<ServiceInstanceGuard, ServiceError> {
    acquire_service_instance_guard_at(&default_service_instance_lock_path(), listen)
}

fn require_confirmed(action: &str, dry_run: bool, yes: bool) -> Result<(), ServiceError> {
    if dry_run || yes {
        Ok(())
    } else {
        Err(ServiceError::confirm_required(action))
    }
}

fn execute_or_describe_plan(plan: ServicePlan) -> Result<ServiceResult, ServiceError> {
    if !plan.dry_run {
        execute_steps(&plan.steps)?;
    }
    Ok(ServiceResult {
        exit_code: 0,
        text: render_plan_text(&plan),
        payload: serde_json::to_value(&plan).expect("service plan serializes"),
    })
}

fn install_plan(
    manager: ServiceManager,
    exe: &Path,
    options: ServiceInstallOptions,
) -> Result<ServicePlan, ServiceError> {
    validate_service_name(&options.name)?;
    let serve_args = serve_args(&options);
    let exe_display = exe.display().to_string();
    let mut steps = Vec::new();
    let (service_file, next_actions) = match manager {
        ServiceManager::SystemdUser => {
            let unit = systemd_unit_name(&options.name);
            let unit_path = systemd_user_unit_path(&unit)?;
            steps.push(ServiceStep::WriteFile {
                path: unit_path.display().to_string(),
                content: systemd_unit(&exe_display, &serve_args),
            });
            steps.push(ServiceStep::Run {
                program: "systemctl".to_owned(),
                args: vec!["--user".into(), "daemon-reload".into()],
                optional: false,
            });
            steps.push(ServiceStep::Run {
                program: "systemctl".to_owned(),
                args: vec!["--user".into(), "enable".into(), "--now".into(), unit],
                optional: false,
            });
            if !options.skip_linger
                && let Some(user) = current_user()
            {
                steps.push(ServiceStep::Run {
                    program: "loginctl".to_owned(),
                    args: vec!["enable-linger".into(), user],
                    optional: true,
                });
            }
            (
                Some(unit_path.display().to_string()),
                vec![
                    "check service state with `oraclemcp service status --json`".to_owned(),
                    "inspect logs with `oraclemcp service logs --json`".to_owned(),
                    "configure OAuth or mTLS before exposing the listener off loopback".to_owned(),
                ],
            )
        }
        ServiceManager::LaunchdUser => {
            let label = launchd_label(&options.name);
            let plist_path = launchd_plist_path(&label)?;
            steps.push(ServiceStep::WriteFile {
                path: plist_path.display().to_string(),
                content: launchd_plist(&label, &exe_display, &serve_args),
            });
            steps.push(ServiceStep::Run {
                program: "launchctl".to_owned(),
                args: vec![
                    "bootstrap".into(),
                    launchd_domain()?,
                    plist_path.display().to_string(),
                ],
                optional: false,
            });
            steps.push(ServiceStep::Run {
                program: "launchctl".to_owned(),
                args: vec![
                    "kickstart".into(),
                    "-k".into(),
                    launchd_service_target(&label)?,
                ],
                optional: false,
            });
            (
                Some(plist_path.display().to_string()),
                vec![
                    "check service state with `oraclemcp service status --json`".to_owned(),
                    "inspect launchd logs with `oraclemcp service logs --json`".to_owned(),
                ],
            )
        }
        ServiceManager::WindowsService => {
            let bin_path = windows_bin_path(&exe_display, &serve_args);
            steps.push(ServiceStep::Run {
                program: "sc.exe".to_owned(),
                args: vec![
                    "create".into(),
                    options.name.clone(),
                    "start=".into(),
                    "auto".into(),
                    "binPath=".into(),
                    bin_path,
                ],
                optional: false,
            });
            steps.push(ServiceStep::Run {
                program: "sc.exe".to_owned(),
                args: vec![
                    "failure".into(),
                    options.name.clone(),
                    "reset=".into(),
                    "86400".into(),
                    "actions=".into(),
                    "restart/5000".into(),
                ],
                optional: false,
            });
            steps.push(ServiceStep::Run {
                program: "sc.exe".to_owned(),
                args: vec!["start".into(), options.name.clone()],
                optional: false,
            });
            (
                None,
                vec![
                    "check service state with `oraclemcp service status --json`".to_owned(),
                    "inspect Windows service events with `oraclemcp service logs --json`"
                        .to_owned(),
                ],
            )
        }
    };

    Ok(ServicePlan {
        ok: true,
        kind: "oraclemcp_service_plan",
        action: "install",
        manager,
        service_name: options.name,
        dry_run: options.dry_run,
        executable: exe_display,
        serve_args,
        service_file,
        hardening: Some(service_hardening(manager)),
        steps,
        next_actions,
    })
}

fn uninstall_plan(
    manager: ServiceManager,
    exe: &Path,
    options: ServiceMutationOptions,
) -> Result<ServicePlan, ServiceError> {
    validate_service_name(&options.name)?;
    let exe_display = exe.display().to_string();
    let mut steps = Vec::new();
    let service_file = match manager {
        ServiceManager::SystemdUser => {
            let unit = systemd_unit_name(&options.name);
            let unit_path = systemd_user_unit_path(&unit)?;
            steps.push(ServiceStep::Run {
                program: "systemctl".to_owned(),
                args: vec![
                    "--user".into(),
                    "disable".into(),
                    "--now".into(),
                    unit.clone(),
                ],
                optional: true,
            });
            steps.push(ServiceStep::RemoveFile {
                path: unit_path.display().to_string(),
                if_exists: true,
            });
            steps.push(ServiceStep::Run {
                program: "systemctl".to_owned(),
                args: vec!["--user".into(), "daemon-reload".into()],
                optional: false,
            });
            Some(unit_path.display().to_string())
        }
        ServiceManager::LaunchdUser => {
            let label = launchd_label(&options.name);
            let plist_path = launchd_plist_path(&label)?;
            steps.push(ServiceStep::Run {
                program: "launchctl".to_owned(),
                args: vec!["bootout".into(), launchd_service_target(&label)?],
                optional: true,
            });
            steps.push(ServiceStep::RemoveFile {
                path: plist_path.display().to_string(),
                if_exists: true,
            });
            Some(plist_path.display().to_string())
        }
        ServiceManager::WindowsService => {
            steps.push(ServiceStep::Run {
                program: "sc.exe".to_owned(),
                args: vec!["stop".into(), options.name.clone()],
                optional: true,
            });
            steps.push(ServiceStep::Run {
                program: "sc.exe".to_owned(),
                args: vec!["delete".into(), options.name.clone()],
                optional: false,
            });
            None
        }
    };

    Ok(ServicePlan {
        ok: true,
        kind: "oraclemcp_service_plan",
        action: "uninstall",
        manager,
        service_name: options.name,
        dry_run: options.dry_run,
        executable: exe_display,
        serve_args: Vec::new(),
        service_file,
        hardening: None,
        steps,
        next_actions: vec![
            "re-run `oraclemcp service status --json` to confirm the service is gone".to_owned(),
        ],
    })
}

fn restart_plan(
    manager: ServiceManager,
    exe: &Path,
    options: ServiceMutationOptions,
) -> Result<ServicePlan, ServiceError> {
    validate_service_name(&options.name)?;
    let exe_display = exe.display().to_string();
    let steps = match manager {
        ServiceManager::SystemdUser => vec![ServiceStep::Run {
            program: "systemctl".to_owned(),
            args: vec![
                "--user".into(),
                "restart".into(),
                systemd_unit_name(&options.name),
            ],
            optional: false,
        }],
        ServiceManager::LaunchdUser => {
            let label = launchd_label(&options.name);
            vec![ServiceStep::Run {
                program: "launchctl".to_owned(),
                args: vec![
                    "kickstart".into(),
                    "-k".into(),
                    launchd_service_target(&label)?,
                ],
                optional: false,
            }]
        }
        ServiceManager::WindowsService => vec![
            ServiceStep::Run {
                program: "sc.exe".to_owned(),
                args: vec!["stop".into(), options.name.clone()],
                optional: true,
            },
            ServiceStep::Run {
                program: "sc.exe".to_owned(),
                args: vec!["start".into(), options.name.clone()],
                optional: false,
            },
        ],
    };

    Ok(ServicePlan {
        ok: true,
        kind: "oraclemcp_service_plan",
        action: "restart",
        manager,
        service_name: options.name,
        dry_run: options.dry_run,
        executable: exe_display,
        serve_args: Vec::new(),
        service_file: None,
        hardening: None,
        steps,
        next_actions: vec!["check service state with `oraclemcp service status --json`".to_owned()],
    })
}

fn run_status(manager: ServiceManager, name: &str) -> Result<ServiceResult, ServiceError> {
    validate_service_name(name)?;
    let (program, args) = status_command(manager, name)?;
    let output = run_capture(&program, &args, false)?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let runtime_instance = discover_service_instance();
    let active = match manager {
        ServiceManager::SystemdUser => stdout == "active",
        ServiceManager::LaunchdUser => output.status.success(),
        ServiceManager::WindowsService => stdout.contains("RUNNING"),
    };
    let exit_code = if active { 0 } else { 3 };
    let payload = serde_json::json!({
        "ok": active,
        "kind": "oraclemcp_service_status",
        "manager": manager.as_str(),
        "service_name": name,
        "active": active,
        "status": stdout,
        "stderr": stderr,
        "runtime_instance": runtime_instance,
        "exit_code": exit_code,
    });
    let text = if active {
        format!(
            "oraclemcp service `{name}` is active; {}",
            render_instance_discovery(&runtime_instance)
        )
    } else {
        format!(
            "oraclemcp service `{name}` is not active; {}; run `oraclemcp service logs` or `oraclemcp service install --dry-run`",
            render_instance_discovery(&runtime_instance)
        )
    };
    Ok(ServiceResult {
        exit_code,
        payload,
        text,
    })
}

fn run_logs(
    manager: ServiceManager,
    name: &str,
    lines: u16,
) -> Result<ServiceResult, ServiceError> {
    validate_service_name(name)?;
    let (program, args) = logs_command(manager, name, lines)?;
    let output = run_capture(&program, &args, false)?;
    let exit_code = if output.status.success() { 0 } else { 3 };
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let payload = serde_json::json!({
        "ok": output.status.success(),
        "kind": "oraclemcp_service_logs",
        "manager": manager.as_str(),
        "service_name": name,
        "lines": lines,
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
    });
    let text = if output.status.success() {
        stdout
    } else {
        format!(
            "failed to read service logs for `{name}`; stderr:\n{stderr}\ntry `oraclemcp service status --json`"
        )
    };
    Ok(ServiceResult {
        exit_code,
        payload,
        text,
    })
}

fn run_backup(
    manager: ServiceManager,
    options: ServiceBackupOptions,
) -> Result<ServiceResult, ServiceError> {
    validate_service_name(&options.name)?;
    let output = options
        .output
        .clone()
        .unwrap_or_else(|| default_backup_path(&options.state_dir));
    validate_backup_output_path(&output, &options.state_dir)?;

    let manifest = if options.dry_run {
        build_backup_manifest(&options, &output, false, false)?
    } else {
        let store = FileStore::open(&options.state_dir).map_err(service_store_error)?;
        // Backup is deliberately offline-only. A live service owns this lock
        // for its full lifetime, so refusing here prevents a state snapshot
        // from racing client/config/proposal/source/audit mutations.
        let owner = store
            .acquire_service_owner("service-backup")
            .map_err(service_backup_store_error)?;
        create_new_private_dir(&output)?;
        let state_target = output.join("state");
        let mut state = copy_dir_snapshot(store.root(), &state_target)?;
        state.backup_path = "state".to_owned();
        let mut config = copy_optional_file(
            &options.config_path,
            &output.join("config").join("profiles.toml"),
        )?;
        relativize_file_manifest(&mut config, &output);
        let (mut audit, mut audit_anchor) = copy_audit_for_backup(&options.audit_path, &output)?;
        relativize_file_manifest(&mut audit, &output);
        relativize_file_manifest(&mut audit_anchor, &output);
        let mut manifest = BackupManifest {
            schema_version: BACKUP_SCHEMA_VERSION,
            kind: BACKUP_KIND.to_owned(),
            service_name: options.name.clone(),
            created_unix_ms: current_unix_millis(),
            state,
            config,
            audit,
            audit_anchor,
            service_lock_held: true,
            transient_files_skipped: vec![SERVICE_STATE_LOCK_FILE.to_owned()],
            manifest_key_id: options.manifest_signing_key.key_id().to_owned(),
            manifest_signature: String::new(),
        };
        sign_backup_manifest(&mut manifest, &options.manifest_signing_key)?;
        write_manifest(&output, &manifest)?;
        drop(owner);
        manifest
    };

    let payload = serde_json::json!({
        "ok": true,
        "kind": "oraclemcp_service_backup",
        "manager": manager.as_str(),
        "service_name": options.name,
        "dry_run": options.dry_run,
        "backup_dir": output.display().to_string(),
        "manifest": manifest,
        "next_actions": [
            "restore with `oraclemcp --json service restore <backup-dir> --dry-run` first",
            "run `oraclemcp audit verify` or service restore with the audit signing key before trusting recovered state"
        ],
    });
    let text = if options.dry_run {
        format!(
            "oraclemcp service backup\nmanager: {}\nservice: {}\nmode: dry-run (no changes made)\nbackup dir: {}\nstate: {}\nconfig: {}\naudit: {}\n",
            manager.as_str(),
            options.name,
            output.display(),
            options.state_dir.display(),
            options.config_path.display(),
            options.audit_path.display()
        )
    } else {
        format!(
            "oraclemcp service backup completed\nbackup dir: {}\nstate files: {}\naudit: {}\n",
            output.display(),
            manifest.state.file_count,
            if manifest.audit.present {
                "included"
            } else {
                "not present"
            }
        )
    };
    Ok(ServiceResult {
        exit_code: 0,
        payload,
        text,
    })
}

fn run_restore(
    manager: ServiceManager,
    _exe: &Path,
    options: ServiceRestoreOptions,
) -> Result<ServiceResult, ServiceError> {
    validate_service_name(&options.name)?;
    // Preflight and snapshot every byte through a capability rooted at the
    // selected backup before stopping the service. The returned files are
    // anonymous private snapshots, so path replacement, hard-link mutation,
    // and rename swaps after this point cannot change what gets restored.
    let mut prepared = prepare_restore(&options)?;
    let audit_verification = prepared.audit_verification.clone();
    let stop = stop_step(manager, &options.name)?;
    let start = start_step(manager, &options.name)?;

    if !options.dry_run {
        execute_steps(std::slice::from_ref(&stop))?;
        prepared.apply()?;
        execute_steps(std::slice::from_ref(&start))?;
    }

    let payload = serde_json::json!({
        "ok": true,
        "kind": "oraclemcp_service_restore",
        "manager": manager.as_str(),
        "service_name": options.name,
        "dry_run": options.dry_run,
        "backup_dir": options.backup.display().to_string(),
        "target_state_dir": options.state_dir.display().to_string(),
        "target_config_path": options.config_path.display().to_string(),
        "target_audit_path": options.audit_path.display().to_string(),
        "audit_verification": audit_verification,
        "steps": [stop, start],
    });
    let audit_text = match audit_verification {
        RestoreAuditVerification::Verified { .. } => "verified signed chain and head anchor",
        RestoreAuditVerification::NoAuditLog => "no audit log present in backup",
    };
    let text = if options.dry_run {
        format!(
            "oraclemcp service restore\nmanager: {}\nservice: {}\nmode: dry-run (no changes made)\nbackup dir: {}\naudit: {audit_text}\n",
            manager.as_str(),
            options.name,
            options.backup.display()
        )
    } else {
        format!(
            "oraclemcp service restore completed\nbackup dir: {}\nstate: {}\nconfig: {}\n",
            options.backup.display(),
            options.state_dir.display(),
            options.config_path.display()
        )
    };
    Ok(ServiceResult {
        exit_code: 0,
        payload,
        text,
    })
}

fn build_backup_manifest(
    options: &ServiceBackupOptions,
    output: &Path,
    service_lock_held: bool,
    include_existing_stats: bool,
) -> Result<BackupManifest, ServiceError> {
    let state = if include_existing_stats {
        let mut state = tree_manifest_for(&options.state_dir, &output.join("state"))?;
        state.backup_path = "state".to_owned();
        state
    } else {
        BackupTreeManifest {
            source_path: options.state_dir.display().to_string(),
            backup_path: "state".to_owned(),
            file_count: 0,
            bytes: 0,
            files: Vec::new(),
        }
    };
    let mut config = file_manifest_for(&options.config_path, &output.join("config/profiles.toml"))?;
    relativize_file_manifest(&mut config, output);
    let mut audit = file_manifest_for(&options.audit_path, &output.join("audit/audit.jsonl"))?;
    relativize_file_manifest(&mut audit, output);
    let audit_anchor_path = oraclemcp_audit::anchor_path_for(&options.audit_path);
    let mut audit_anchor =
        file_manifest_for(&audit_anchor_path, &output.join("audit/audit.jsonl.anchor"))?;
    relativize_file_manifest(&mut audit_anchor, output);
    require_audit_anchor_pair(&audit, &audit_anchor, "backup")?;
    let mut manifest = BackupManifest {
        schema_version: BACKUP_SCHEMA_VERSION,
        kind: BACKUP_KIND.to_owned(),
        service_name: options.name.clone(),
        created_unix_ms: current_unix_millis(),
        state,
        config,
        audit,
        audit_anchor,
        service_lock_held,
        transient_files_skipped: vec![SERVICE_STATE_LOCK_FILE.to_owned()],
        manifest_key_id: options.manifest_signing_key.key_id().to_owned(),
        manifest_signature: String::new(),
    };
    sign_backup_manifest(&mut manifest, &options.manifest_signing_key)?;
    Ok(manifest)
}

fn relativize_file_manifest(manifest: &mut BackupFileManifest, backup_root: &Path) {
    if let Some(path) = manifest.backup_path.as_deref() {
        let path = Path::new(path);
        if let Ok(relative) = path.strip_prefix(backup_root) {
            manifest.backup_path = Some(relative.display().to_string());
        }
    }
}

fn default_backup_path(state_dir: &Path) -> PathBuf {
    let parent = state_dir
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    parent
        .join("oraclemcp-backups")
        .join(format!("backup-{}", timestamp_suffix()))
}

fn validate_backup_output_path(output: &Path, state_dir: &Path) -> Result<(), ServiceError> {
    if output.as_os_str().is_empty() {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_BACKUP_INVALID_TARGET",
            "backup output path must not be empty",
            2,
        ));
    }
    if path_is_under(output, state_dir) {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_BACKUP_INVALID_TARGET",
            format!(
                "backup output {} must not be inside the state directory {}",
                output.display(),
                state_dir.display()
            ),
            2,
        ));
    }
    if output.exists() {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_BACKUP_TARGET_EXISTS",
            format!(
                "backup output {} already exists; choose a new directory so no backup is overwritten",
                output.display()
            ),
            2,
        ));
    }
    Ok(())
}

fn path_is_under(candidate: &Path, root: &Path) -> bool {
    let candidate_abs = absoluteish(candidate);
    let root_abs = absoluteish(root);
    candidate_abs == root_abs || candidate_abs.starts_with(root_abs)
}

fn absoluteish(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

fn service_store_error(error: oraclemcp_core::FileStoreError) -> ServiceError {
    ServiceError::new(
        "ORACLEMCP_SERVICE_STORE_UNAVAILABLE",
        format!("service file-store operation failed: {error}"),
        3,
    )
}

fn service_backup_store_error(error: oraclemcp_core::FileStoreError) -> ServiceError {
    if matches!(error, oraclemcp_core::FileStoreError::Locked) {
        return ServiceError::new(
            "ORACLEMCP_SERVICE_BACKUP_ACTIVE_OWNER",
            "refusing an incoherent online backup while the service owns the state root; stop the service and retry the backup",
            3,
        );
    }
    service_store_error(error)
}

fn copy_audit_for_backup(
    audit_path: &Path,
    output: &Path,
) -> Result<(BackupFileManifest, BackupFileManifest), ServiceError> {
    // Keep the audit payload independent from the state-tree snapshot even when
    // its live path happens to sit below the state directory. Restore targets
    // are current, explicit operator configuration; source_path is provenance
    // only and is never a write authority.
    let anchor_source = oraclemcp_audit::anchor_path_for(audit_path);
    let audit = copy_optional_file(audit_path, &output.join("audit").join("audit.jsonl"))?;
    let anchor = copy_optional_file(
        &anchor_source,
        &output.join("audit").join("audit.jsonl.anchor"),
    )?;
    require_audit_anchor_pair(&audit, &anchor, "backup")?;
    Ok((audit, anchor))
}

fn require_audit_anchor_pair(
    audit: &BackupFileManifest,
    anchor: &BackupFileManifest,
    action: &str,
) -> Result<(), ServiceError> {
    if audit.present == anchor.present {
        return Ok(());
    }
    Err(ServiceError::new(
        if action == "backup" {
            "ORACLEMCP_SERVICE_BACKUP_AUDIT_ANCHOR_REQUIRED"
        } else {
            "ORACLEMCP_SERVICE_RESTORE_AUDIT_UNVERIFIABLE"
        },
        format!(
            "service {action} requires an audit payload and its signed head anchor to either both be present or both be absent"
        ),
        2,
    ))
}

fn copy_dir_snapshot(source: &Path, target: &Path) -> Result<BackupTreeManifest, ServiceError> {
    let mut manifest = BackupTreeManifest {
        source_path: source.display().to_string(),
        backup_path: target.display().to_string(),
        file_count: 0,
        bytes: 0,
        files: Vec::new(),
    };
    copy_dir_snapshot_inner(source, source, target, &mut manifest)?;
    manifest
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
    Ok(manifest)
}

fn copy_dir_snapshot_inner(
    source_root: &Path,
    source: &Path,
    target: &Path,
    manifest: &mut BackupTreeManifest,
) -> Result<(), ServiceError> {
    ensure_source_dir_safe(source)?;
    create_private_dir_all(target)?;
    let mut entries = fs::read_dir(source)
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_BACKUP_READ_FAILED", source, e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_BACKUP_READ_FAILED", source, e))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let file_name = entry.file_name();
        if file_name == SERVICE_STATE_LOCK_FILE {
            continue;
        }
        let source_path = entry.path();
        let target_path = target.join(&file_name);
        let metadata = fs::symlink_metadata(&source_path).map_err(|e| {
            service_io_error("ORACLEMCP_SERVICE_BACKUP_READ_FAILED", &source_path, e)
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ServiceError::new(
                "ORACLEMCP_SERVICE_BACKUP_UNSAFE_PATH",
                format!("refusing to follow symlink {}", source_path.display()),
                2,
            ));
        }
        if metadata.is_dir() {
            copy_dir_snapshot_inner(source_root, &source_path, &target_path, manifest)?;
        } else if metadata.is_file() {
            copy_regular_file(&source_path, &target_path)?;
            let copied = fs::metadata(&target_path).map_err(|e| {
                service_io_error("ORACLEMCP_SERVICE_BACKUP_READ_FAILED", &target_path, e)
            })?;
            let relative = source_path.strip_prefix(source_root).map_err(|e| {
                ServiceError::new(
                    "ORACLEMCP_SERVICE_BACKUP_UNSAFE_PATH",
                    format!("failed to inventory {}: {e}", source_path.display()),
                    2,
                )
            })?;
            let relative = portable_relative_path(relative)?;
            let bytes = copied.len();
            manifest.file_count += 1;
            manifest.bytes += bytes;
            manifest.files.push(BackupTreeFileManifest {
                path: relative,
                sha256: sha256_file(&target_path)?,
                bytes,
            });
        }
    }
    sync_dir(target)
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_BACKUP_SYNC_FAILED", target, e))
}

impl PreparedRestore {
    fn apply(&mut self) -> Result<(), ServiceError> {
        let state_dir = open_or_create_dir_chain(
            &self.state_target.root,
            &self.state_target.relative_path,
            &self.state_target.display_path,
        )?;
        let mut expected_inventory = self
            .state_files
            .iter()
            .map(|file| portable_relative_path(&file.relative_path))
            .collect::<Result<Vec<_>, _>>()?;
        for target in [
            self.config.as_ref().map(|_| &self.config_target),
            self.audit.as_ref().map(|_| &self.audit_target),
            self.audit_anchor
                .as_ref()
                .map(|_| &self.audit_anchor_target),
        ]
        .into_iter()
        .flatten()
        {
            if let Ok(relative) = target
                .display_path
                .strip_prefix(&self.state_target.display_path)
                && !relative.as_os_str().is_empty()
            {
                expected_inventory.push(portable_relative_path(relative)?);
            }
        }
        expected_inventory.sort();
        expected_inventory.dedup();
        let existing_inventory = inventory_target_tree(&state_dir)?;
        if existing_inventory
            .iter()
            .any(|path| expected_inventory.binary_search(path).is_err())
        {
            return Err(ServiceError::new(
                "ORACLEMCP_SERVICE_RESTORE_TARGET_INVALID",
                format!(
                    "target state directory contains files outside the authenticated backup inventory: {existing_inventory:?}"
                ),
                2,
            ));
        }
        for file in &mut self.state_files {
            let target = PreparedTarget {
                root: state_dir.try_clone().map_err(|e| {
                    service_io_error(
                        "ORACLEMCP_SERVICE_RESTORE_TARGET_INVALID",
                        &self.state_target.display_path,
                        e,
                    )
                })?,
                relative_path: file.relative_path.clone(),
                display_path: self.state_target.display_path.join(&file.relative_path),
            };
            write_prepared_file(&mut file.source, &target)?;
        }
        if let Some(config) = self.config.as_mut() {
            write_prepared_file(config, &self.config_target)?;
        }
        if let Some(audit) = self.audit.as_mut() {
            write_prepared_file(audit, &self.audit_target)?;
        }
        if let Some(anchor) = self.audit_anchor.as_mut() {
            write_prepared_file(anchor, &self.audit_anchor_target)?;
        }
        let restored_inventory = inventory_target_tree(&state_dir)?;
        if restored_inventory != expected_inventory {
            return Err(ServiceError::new(
                "ORACLEMCP_SERVICE_RESTORE_TARGET_INVALID",
                format!(
                    "target state inventory changed during restore (expected {expected_inventory:?}, found {restored_inventory:?})"
                ),
                2,
            ));
        }
        let current_state_dir =
            open_dir_chain_nofollow(&self.state_target.root, &self.state_target.relative_path)
                .map_err(|e| {
                    service_io_error(
                        "ORACLEMCP_SERVICE_RESTORE_UNSAFE_PATH",
                        &self.state_target.display_path,
                        e,
                    )
                })?;
        if !same_capability_identity(&state_dir, &current_state_dir)? {
            return Err(ServiceError::new(
                "ORACLEMCP_SERVICE_RESTORE_UNSAFE_PATH",
                format!(
                    "target state directory {} was replaced during restore",
                    self.state_target.display_path.display()
                ),
                2,
            ));
        }
        Ok(())
    }
}

fn copy_optional_file(source: &Path, target: &Path) -> Result<BackupFileManifest, ServiceError> {
    if !source.exists() {
        return Ok(BackupFileManifest {
            present: false,
            source_path: source.display().to_string(),
            backup_path: None,
            sha256: None,
            bytes: None,
        });
    }
    copy_regular_file(source, target)?;
    file_manifest_for(source, target)
}

fn file_manifest_for(source: &Path, target: &Path) -> Result<BackupFileManifest, ServiceError> {
    match fs::symlink_metadata(source) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(ServiceError::new(
            "ORACLEMCP_SERVICE_BACKUP_UNSAFE_PATH",
            format!("refusing to follow symlink {}", source.display()),
            2,
        )),
        Ok(metadata) if metadata.is_file() => Ok(BackupFileManifest {
            present: true,
            source_path: source.display().to_string(),
            backup_path: Some(target.display().to_string()),
            sha256: Some(sha256_file(source)?),
            bytes: Some(metadata.len()),
        }),
        Ok(_) => Err(ServiceError::new(
            "ORACLEMCP_SERVICE_BACKUP_UNSAFE_PATH",
            format!("{} is not a regular file", source.display()),
            2,
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BackupFileManifest {
            present: false,
            source_path: source.display().to_string(),
            backup_path: None,
            sha256: None,
            bytes: None,
        }),
        Err(e) => Err(service_io_error(
            "ORACLEMCP_SERVICE_BACKUP_READ_FAILED",
            source,
            e,
        )),
    }
}

fn tree_manifest_for(source: &Path, target: &Path) -> Result<BackupTreeManifest, ServiceError> {
    let mut manifest = BackupTreeManifest {
        source_path: source.display().to_string(),
        backup_path: target.display().to_string(),
        file_count: 0,
        bytes: 0,
        files: Vec::new(),
    };
    if !source.exists() {
        return Ok(manifest);
    }
    accumulate_tree_manifest(source, source, &mut manifest)?;
    manifest
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
    Ok(manifest)
}

fn accumulate_tree_manifest(
    source_root: &Path,
    source: &Path,
    manifest: &mut BackupTreeManifest,
) -> Result<(), ServiceError> {
    ensure_source_dir_safe(source)?;
    let mut entries = fs::read_dir(source)
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_BACKUP_READ_FAILED", source, e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_BACKUP_READ_FAILED", source, e))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        if entry.file_name() == SERVICE_STATE_LOCK_FILE {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|e| service_io_error("ORACLEMCP_SERVICE_BACKUP_READ_FAILED", &path, e))?;
        if metadata.file_type().is_symlink() {
            return Err(ServiceError::new(
                "ORACLEMCP_SERVICE_BACKUP_UNSAFE_PATH",
                format!("refusing to follow symlink {}", path.display()),
                2,
            ));
        }
        if metadata.is_dir() {
            accumulate_tree_manifest(source_root, &path, manifest)?;
        } else if metadata.is_file() {
            manifest.file_count += 1;
            manifest.bytes += metadata.len();
            manifest.files.push(BackupTreeFileManifest {
                path: portable_relative_path(path.strip_prefix(source_root).map_err(|e| {
                    ServiceError::new(
                        "ORACLEMCP_SERVICE_BACKUP_UNSAFE_PATH",
                        format!("failed to inventory {}: {e}", path.display()),
                        2,
                    )
                })?)?,
                sha256: sha256_file(&path)?,
                bytes: metadata.len(),
            });
        }
    }
    Ok(())
}

fn ensure_source_dir_safe(path: &Path) -> Result<(), ServiceError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_BACKUP_READ_FAILED", path, e))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_BACKUP_UNSAFE_PATH",
            format!("{} is not a safe directory", path.display()),
            2,
        ));
    }
    Ok(())
}

fn copy_regular_file(source: &Path, target: &Path) -> Result<(), ServiceError> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_BACKUP_READ_FAILED", source, e))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_BACKUP_UNSAFE_PATH",
            format!("{} is not a regular file", source.display()),
            2,
        ));
    }
    if let Some(parent) = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        create_private_dir_all(parent)?;
    }
    let mut bytes = Vec::new();
    File::open(source)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_BACKUP_READ_FAILED", source, e))?;
    write_private_file_atomic(target, &bytes)
}

fn create_new_private_dir(path: &Path) -> Result<(), ServiceError> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|e| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_BACKUP_WRITE_FAILED",
            format!("failed to create backup directory {}: {e}", path.display()),
            3,
        )
    })
}

fn create_private_dir_all(path: &Path) -> Result<(), ServiceError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ServiceError::new(
                "ORACLEMCP_SERVICE_BACKUP_UNSAFE_PATH",
                format!("{} is not a safe directory", path.display()),
                2,
            ));
        }
        harden_private_runtime_dir(path, &metadata)
            .map_err(|e| service_io_error("ORACLEMCP_SERVICE_BACKUP_WRITE_FAILED", path, e))?;
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_BACKUP_WRITE_FAILED", path, e))
}

fn write_private_file_atomic(path: &Path, bytes: &[u8]) -> Result<(), ServiceError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        create_private_dir_all(parent)?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            ServiceError::new(
                "ORACLEMCP_SERVICE_BACKUP_WRITE_FAILED",
                format!("invalid file target {}", path.display()),
                2,
            )
        })?;
    let tmp = parent.join(format!(
        ".{file_name}.tmp.{}.{}",
        std::process::id(),
        timestamp_suffix()
    ));
    let mut file = create_new_private_file(&tmp)
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_BACKUP_WRITE_FAILED", &tmp, e))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_BACKUP_WRITE_FAILED", &tmp, e))?;
    drop(file);
    fs::rename(&tmp, path)
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_BACKUP_WRITE_FAILED", path, e))?;
    sync_dir(parent)
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_BACKUP_SYNC_FAILED", parent, e))
}

fn write_manifest(output: &Path, manifest: &BackupManifest) -> Result<(), ServiceError> {
    let mut bytes = serde_json::to_vec_pretty(manifest).map_err(|e| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_BACKUP_MANIFEST_FAILED",
            format!("failed to serialize backup manifest: {e}"),
            3,
        )
    })?;
    bytes.push(b'\n');
    write_private_file_atomic(&output.join(BACKUP_MANIFEST_FILE), &bytes)
}

fn sign_backup_manifest(
    manifest: &mut BackupManifest,
    key: &SigningKey,
) -> Result<(), ServiceError> {
    manifest.manifest_key_id = key.key_id().to_owned();
    manifest.manifest_signature.clear();
    let digest = backup_manifest_digest(manifest)?;
    manifest.manifest_signature = key.sign(&digest);
    Ok(())
}

fn backup_manifest_digest(manifest: &BackupManifest) -> Result<String, ServiceError> {
    let mut unsigned = manifest.clone();
    unsigned.manifest_signature.clear();
    let canonical = serde_json::to_vec(&unsigned).map_err(|e| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_BACKUP_MANIFEST_FAILED",
            format!("failed to canonicalize backup manifest: {e}"),
            3,
        )
    })?;
    let mut signed = Vec::with_capacity(BACKUP_MANIFEST_SIGNATURE_DOMAIN.len() + canonical.len());
    signed.extend_from_slice(BACKUP_MANIFEST_SIGNATURE_DOMAIN);
    signed.extend_from_slice(&canonical);
    Ok(sha256_hex(&signed))
}

fn verify_manifest_signature(
    manifest: &BackupManifest,
    keys: &[SigningKey],
) -> Result<(), ServiceError> {
    let key = keys
        .iter()
        .find(|key| key.key_id() == manifest.manifest_key_id)
        .ok_or_else(|| {
            ServiceError::new(
                "ORACLEMCP_SERVICE_RESTORE_MANIFEST_UNVERIFIABLE",
                format!(
                    "backup manifest names unknown signing key id {:?}",
                    manifest.manifest_key_id
                ),
                2,
            )
        })?;
    let digest = backup_manifest_digest(manifest)?;
    let expected = key.sign(&digest);
    if !ct_eq(expected.as_bytes(), manifest.manifest_signature.as_bytes()) {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_MANIFEST_BROKEN",
            "backup manifest signature does not verify; refusing every payload path and byte",
            2,
        ));
    }
    Ok(())
}

fn prepare_restore(options: &ServiceRestoreOptions) -> Result<PreparedRestore, ServiceError> {
    let backup_root = open_backup_root(&options.backup)?;
    let manifest = read_manifest_from_root(&backup_root, &options.backup)?;
    validate_manifest_header(&manifest, options)?;
    verify_manifest_signature(&manifest, &options.audit_keys)?;
    validate_manifest_shape(&manifest)?;

    let state_dir = backup_root
        .open_dir_nofollow(&manifest.state.backup_path)
        .map_err(|e| restore_source_error(&options.backup, &manifest.state.backup_path, e))?;
    let actual_inventory = inventory_capability_tree(&state_dir)?;
    let expected_inventory = manifest
        .state
        .files
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<Vec<_>>();
    if actual_inventory != expected_inventory {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_INVENTORY_MISMATCH",
            format!(
                "backup state inventory differs from the authenticated manifest (expected {expected_inventory:?}, found {actual_inventory:?})"
            ),
            2,
        ));
    }

    let mut state_files = Vec::with_capacity(manifest.state.files.len());
    for entry in &manifest.state.files {
        let relative_path = parse_portable_relative_path(&entry.path, "state inventory path")?;
        let source = stage_verified_cap_file(
            &state_dir,
            &relative_path,
            entry.bytes,
            &entry.sha256,
            &format!("state/{}", entry.path),
        )?;
        state_files.push(PreparedStateFile {
            relative_path,
            source,
        });
    }

    let config = stage_manifest_file(&backup_root, &manifest.config, "config/profiles.toml")?;
    let mut audit = stage_manifest_file(&backup_root, &manifest.audit, "audit/audit.jsonl")?;
    let mut audit_anchor = stage_manifest_file(
        &backup_root,
        &manifest.audit_anchor,
        "audit/audit.jsonl.anchor",
    )?;
    let audit_verification =
        verify_prepared_audit(audit.as_mut(), audit_anchor.as_mut(), &options.audit_keys)?;

    Ok(PreparedRestore {
        state_files,
        config,
        audit,
        audit_anchor,
        state_target: prepare_target(&options.state_dir, true)?,
        config_target: prepare_target(&options.config_path, false)?,
        audit_target: prepare_target(&options.audit_path, false)?,
        audit_anchor_target: prepare_target(
            &oraclemcp_audit::anchor_path_for(&options.audit_path),
            false,
        )?,
        audit_verification,
    })
}

fn validate_manifest_header(
    manifest: &BackupManifest,
    options: &ServiceRestoreOptions,
) -> Result<(), ServiceError> {
    if manifest.kind != BACKUP_KIND || manifest.schema_version != BACKUP_SCHEMA_VERSION {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
            format!(
                "{} is not an oraclemcp service backup this binary understands",
                options.backup.display()
            ),
            2,
        ));
    }
    if manifest.service_name != options.name {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
            format!(
                "backup belongs to service {:?}, not requested service {:?}",
                manifest.service_name, options.name
            ),
            2,
        ));
    }
    if !manifest.service_lock_held {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
            "backup was not captured while holding the service state lock",
            2,
        ));
    }
    Ok(())
}

fn validate_manifest_shape(manifest: &BackupManifest) -> Result<(), ServiceError> {
    if manifest.state.backup_path != "state" {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
            "authenticated state backup_path must be exactly `state`",
            2,
        ));
    }
    if manifest.transient_files_skipped != [SERVICE_STATE_LOCK_FILE] {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
            "backup transient-file policy does not match this binary",
            2,
        ));
    }

    let mut prior: Option<&str> = None;
    let mut total_bytes = 0_u64;
    for entry in &manifest.state.files {
        parse_portable_relative_path(&entry.path, "state inventory path")?;
        validate_sha256(&entry.sha256, &entry.path)?;
        if prior.is_some_and(|previous| previous >= entry.path.as_str()) {
            return Err(ServiceError::new(
                "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
                "state inventory paths must be unique and strictly sorted",
                2,
            ));
        }
        prior = Some(&entry.path);
        total_bytes = total_bytes.checked_add(entry.bytes).ok_or_else(|| {
            ServiceError::new(
                "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
                "state inventory byte total overflows u64",
                2,
            )
        })?;
    }
    if manifest.state.file_count != manifest.state.files.len()
        || manifest.state.bytes != total_bytes
    {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_INVENTORY_MISMATCH",
            "state file_count/bytes do not match the authenticated per-file inventory",
            2,
        ));
    }
    validate_file_manifest(&manifest.config, "config/profiles.toml")?;
    validate_file_manifest(&manifest.audit, "audit/audit.jsonl")?;
    validate_file_manifest(&manifest.audit_anchor, "audit/audit.jsonl.anchor")?;
    require_audit_anchor_pair(&manifest.audit, &manifest.audit_anchor, "restore")?;
    Ok(())
}

fn validate_file_manifest(
    manifest: &BackupFileManifest,
    expected_path: &str,
) -> Result<(), ServiceError> {
    match (
        manifest.present,
        manifest.backup_path.as_deref(),
        manifest.sha256.as_deref(),
        manifest.bytes,
    ) {
        (false, None, None, None) => Ok(()),
        (true, Some(path), Some(hash), Some(_)) if path == expected_path => {
            validate_sha256(hash, expected_path)
        }
        _ => Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
            format!("manifest entry {expected_path:?} is internally inconsistent"),
            2,
        )),
    }
}

fn validate_sha256(hash: &str, label: &str) -> Result<(), ServiceError> {
    let Some(hex) = hash.strip_prefix("sha256:") else {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
            format!("manifest SHA-256 for {label:?} lacks the `sha256:` algorithm prefix"),
            2,
        ));
    };
    if hex.len() != 64
        || !hex
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
            format!("manifest SHA-256 for {label:?} is not 64 lowercase hex digits"),
            2,
        ));
    }
    Ok(())
}

fn open_backup_root(backup: &Path) -> Result<Dir, ServiceError> {
    let absolute = absoluteish(backup);
    let name = absolute.file_name().ok_or_else(|| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
            format!("backup path {} has no directory name", backup.display()),
            2,
        )
    })?;
    let parent = absolute.parent().ok_or_else(|| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
            format!("backup path {} has no parent directory", backup.display()),
            2,
        )
    })?;
    let parent_dir = Dir::open_ambient_dir(parent, ambient_authority())
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP", parent, e))?;
    parent_dir
        .open_dir_nofollow(name)
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP", &absolute, e))
}

fn read_manifest_from_root(root: &Dir, backup: &Path) -> Result<BackupManifest, ServiceError> {
    let mut file = open_cap_file_nofollow(root, Path::new(BACKUP_MANIFEST_FILE))
        .map_err(|e| restore_source_error(backup, BACKUP_MANIFEST_FILE, e))?;
    let metadata = file
        .metadata()
        .map_err(|e| restore_source_error(backup, BACKUP_MANIFEST_FILE, e))?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
            "backup manifest must be a regular file no larger than 1 MiB",
            2,
        ));
    }
    let mut body = String::new();
    file.read_to_string(&mut body)
        .map_err(|e| restore_source_error(backup, BACKUP_MANIFEST_FILE, e))?;
    serde_json::from_str(&body).map_err(|e| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
            format!(
                "backup manifest {}/{} is invalid: {e}",
                backup.display(),
                BACKUP_MANIFEST_FILE
            ),
            2,
        )
    })
}

fn stage_manifest_file(
    root: &Dir,
    manifest: &BackupFileManifest,
    expected_path: &str,
) -> Result<Option<PreparedBackupFile>, ServiceError> {
    if !manifest.present {
        return Ok(None);
    }
    let bytes = manifest.bytes.ok_or_else(|| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
            format!("manifest entry {expected_path:?} lacks a byte count"),
            2,
        )
    })?;
    let hash = manifest.sha256.as_deref().ok_or_else(|| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
            format!("manifest entry {expected_path:?} lacks a SHA-256"),
            2,
        )
    })?;
    stage_verified_cap_file(root, Path::new(expected_path), bytes, hash, expected_path).map(Some)
}

fn stage_verified_cap_file(
    root: &Dir,
    path: &Path,
    expected_bytes: u64,
    expected_sha256: &str,
    label: &str,
) -> Result<PreparedBackupFile, ServiceError> {
    validate_normal_relative_path(path, label)?;
    let mut source = open_cap_file_nofollow(root, path)
        .map_err(|e| restore_source_error(Path::new("backup"), label, e))?;
    let metadata = source
        .metadata()
        .map_err(|e| restore_source_error(Path::new("backup"), label, e))?;
    if !metadata.is_file() || metadata.len() != expected_bytes {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_PAYLOAD_MISMATCH",
            format!(
                "backup payload {label:?} is not a regular file with authenticated length {expected_bytes}"
            ),
            2,
        ));
    }

    let mut snapshot = tempfile::tempfile().map_err(|e| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_PREFLIGHT_FAILED",
            format!("failed to create private restore staging file: {e}"),
            3,
        )
    })?;
    let mut digest = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|e| restore_source_error(Path::new("backup"), label, e))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        snapshot.write_all(&buffer[..read]).map_err(|e| {
            ServiceError::new(
                "ORACLEMCP_SERVICE_RESTORE_PREFLIGHT_FAILED",
                format!("failed to stage backup payload {label:?}: {e}"),
                3,
            )
        })?;
        copied = copied.checked_add(read as u64).ok_or_else(|| {
            ServiceError::new(
                "ORACLEMCP_SERVICE_RESTORE_PAYLOAD_MISMATCH",
                format!("backup payload {label:?} byte count overflowed"),
                2,
            )
        })?;
    }
    let digest = digest.finalize();
    let mut actual_sha256 = String::with_capacity(7 + digest.len() * 2);
    actual_sha256.push_str("sha256:");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        actual_sha256.push(HEX[(byte >> 4) as usize] as char);
        actual_sha256.push(HEX[(byte & 0x0f) as usize] as char);
    }
    if copied != expected_bytes || actual_sha256 != expected_sha256 {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_PAYLOAD_MISMATCH",
            format!("backup payload {label:?} failed authenticated length/SHA-256 validation"),
            2,
        ));
    }
    snapshot
        .sync_all()
        .and_then(|()| snapshot.seek(SeekFrom::Start(0)).map(drop))
        .map_err(|e| {
            ServiceError::new(
                "ORACLEMCP_SERVICE_RESTORE_PREFLIGHT_FAILED",
                format!("failed to finalize staged backup payload {label:?}: {e}"),
                3,
            )
        })?;
    Ok(PreparedBackupFile {
        bytes: copied,
        snapshot,
    })
}

fn open_cap_file_nofollow(root: &Dir, path: &Path) -> io::Result<cap_std::fs::File> {
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file path has no name"))?;
    let mut parent = root.try_clone()?;
    if let Some(parent_path) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        for component in parent_path.components() {
            let Component::Normal(name) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "file path contains a non-normal parent component",
                ));
            };
            parent = parent.open_dir_nofollow(name)?;
        }
    }
    let mut options = CapOpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    parent.open_with(file_name, &options)
}

fn verify_prepared_audit(
    audit: Option<&mut PreparedBackupFile>,
    anchor: Option<&mut PreparedBackupFile>,
    keys: &[SigningKey],
) -> Result<RestoreAuditVerification, ServiceError> {
    let Some(audit) = audit else {
        return Ok(RestoreAuditVerification::NoAuditLog);
    };
    let Some(anchor) = anchor else {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_AUDIT_UNVERIFIABLE",
            "backup audit log has no authenticated head anchor",
            2,
        ));
    };
    let body = read_prepared_string(audit, "audit log")?;
    let records = parse_jsonl(&body).map_err(|e| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_AUDIT_MALFORMED",
            format!("backup audit log is malformed: {e}"),
            2,
        )
    })?;
    if records.is_empty() {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_AUDIT_UNVERIFIABLE",
            "an empty audit log is not authenticated restore evidence",
            2,
        ));
    }
    let record_count = match verify_records(&records, keys) {
        VerifyOutcome::Ok { records } => records,
        VerifyOutcome::Broken { seq, index, reason } => {
            return Err(ServiceError::new(
                "ORACLEMCP_SERVICE_RESTORE_AUDIT_BROKEN",
                format!("backup audit chain failed at seq {seq} record #{index}: {reason}"),
                2,
            ));
        }
        _ => {
            return Err(ServiceError::new(
                "ORACLEMCP_SERVICE_RESTORE_AUDIT_UNVERIFIABLE",
                "unrecognized audit verification outcome",
                2,
            ));
        }
    };
    let anchor_body = read_prepared_string(anchor, "audit head anchor")?;
    let chain_anchor: oraclemcp_audit::ChainAnchor =
        serde_json::from_str(&anchor_body).map_err(|e| {
            ServiceError::new(
                "ORACLEMCP_SERVICE_RESTORE_AUDIT_BROKEN",
                format!("backup audit head anchor is malformed: {e}"),
                2,
            )
        })?;
    if let Err(violation) = oraclemcp_audit::check_anchor(&records, &chain_anchor, keys) {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_AUDIT_BROKEN",
            format!("backup audit chain failed the head-anchor check: {violation}"),
            2,
        ));
    }
    Ok(RestoreAuditVerification::Verified {
        records: record_count,
        file: "audit/audit.jsonl".to_owned(),
    })
}

fn read_prepared_string(
    prepared: &mut PreparedBackupFile,
    label: &str,
) -> Result<String, ServiceError> {
    prepared.snapshot.seek(SeekFrom::Start(0)).map_err(|e| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_PREFLIGHT_FAILED",
            format!("failed to rewind staged {label}: {e}"),
            3,
        )
    })?;
    let mut body = String::new();
    prepared.snapshot.read_to_string(&mut body).map_err(|e| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_AUDIT_MALFORMED",
            format!("staged {label} is not UTF-8: {e}"),
            2,
        )
    })?;
    prepared.snapshot.seek(SeekFrom::Start(0)).map_err(|e| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_PREFLIGHT_FAILED",
            format!("failed to rewind staged {label}: {e}"),
            3,
        )
    })?;
    Ok(body)
}

fn inventory_capability_tree(root: &Dir) -> Result<Vec<String>, ServiceError> {
    let mut inventory = Vec::new();
    inventory_capability_tree_inner(root, Path::new(""), &mut inventory, false)?;
    inventory.sort();
    Ok(inventory)
}

fn inventory_target_tree(root: &Dir) -> Result<Vec<String>, ServiceError> {
    let mut inventory = Vec::new();
    inventory_capability_tree_inner(root, Path::new(""), &mut inventory, true)?;
    inventory.sort();
    Ok(inventory)
}

fn inventory_capability_tree_inner(
    dir: &Dir,
    prefix: &Path,
    inventory: &mut Vec<String>,
    allow_service_lock: bool,
) -> Result<(), ServiceError> {
    let entries = dir.read_dir(".").map_err(|e| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
            format!("failed to enumerate backup state directory: {e}"),
            2,
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| {
            ServiceError::new(
                "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
                format!("failed to enumerate backup state entry: {e}"),
                2,
            )
        })?;
        let name = entry.file_name();
        if name == OsStr::new(SERVICE_STATE_LOCK_FILE) {
            if allow_service_lock {
                continue;
            }
            return Err(ServiceError::new(
                "ORACLEMCP_SERVICE_RESTORE_INVENTORY_MISMATCH",
                "backup state unexpectedly contains the transient service lock",
                2,
            ));
        }
        let relative = prefix.join(&name);
        let file_type = entry.file_type().map_err(|e| {
            ServiceError::new(
                "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
                format!("failed to inspect backup state entry {:?}: {e}", relative),
                2,
            )
        })?;
        if file_type.is_dir() {
            let child = dir.open_dir_nofollow(&name).map_err(|e| {
                ServiceError::new(
                    "ORACLEMCP_SERVICE_RESTORE_UNSAFE_PATH",
                    format!("refusing unsafe backup state directory {:?}: {e}", relative),
                    2,
                )
            })?;
            inventory_capability_tree_inner(&child, &relative, inventory, allow_service_lock)?;
        } else if file_type.is_file() {
            inventory.push(portable_relative_path(&relative)?);
        } else {
            return Err(ServiceError::new(
                "ORACLEMCP_SERVICE_RESTORE_UNSAFE_PATH",
                format!("refusing non-regular backup state entry {:?}", relative),
                2,
            ));
        }
    }
    Ok(())
}

fn restore_source_error(
    backup: &Path,
    relative: impl AsRef<Path>,
    error: io::Error,
) -> ServiceError {
    ServiceError::new(
        "ORACLEMCP_SERVICE_RESTORE_UNSAFE_PATH",
        format!(
            "failed to open backup payload {}/{} without following links: {error}",
            backup.display(),
            relative.as_ref().display()
        ),
        2,
    )
}

fn portable_relative_path(path: &Path) -> Result<String, ServiceError> {
    validate_normal_relative_path(path, "backup inventory path")?;
    let mut components = Vec::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(ServiceError::new(
                "ORACLEMCP_SERVICE_BACKUP_UNSAFE_PATH",
                format!(
                    "backup inventory path {:?} is not relative and normalized",
                    path
                ),
                2,
            ));
        };
        let component = component.to_str().ok_or_else(|| {
            ServiceError::new(
                "ORACLEMCP_SERVICE_BACKUP_UNSAFE_PATH",
                format!("backup inventory path {:?} is not valid UTF-8", path),
                2,
            )
        })?;
        if component.contains('/') || component.contains('\\') {
            return Err(ServiceError::new(
                "ORACLEMCP_SERVICE_BACKUP_UNSAFE_PATH",
                format!("backup inventory component {component:?} contains a separator"),
                2,
            ));
        }
        components.push(component);
    }
    Ok(components.join("/"))
}

fn parse_portable_relative_path(path: &str, label: &str) -> Result<PathBuf, ServiceError> {
    if path.is_empty() || path.contains('\\') {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_UNSAFE_PATH",
            format!("{label} {path:?} is not a portable relative path"),
            2,
        ));
    }
    let parsed = PathBuf::from(path);
    validate_normal_relative_path(&parsed, label)?;
    if portable_relative_path(&parsed)? != path {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_UNSAFE_PATH",
            format!("{label} {path:?} is not canonically encoded"),
            2,
        ));
    }
    Ok(parsed)
}

fn validate_normal_relative_path(path: &Path, label: &str) -> Result<(), ServiceError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_UNSAFE_PATH",
            format!(
                "{label} {:?} must contain only normal relative components",
                path
            ),
            2,
        ));
    }
    Ok(())
}

fn prepare_target(path: &Path, directory: bool) -> Result<PreparedTarget, ServiceError> {
    let absolute = absoluteish(path);
    if absolute.file_name().is_none() {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_TARGET_INVALID",
            format!(
                "restore target {} may not be a filesystem root",
                path.display()
            ),
            2,
        ));
    }
    let root_path = filesystem_root(&absolute)?;
    let relative_path = absolute.strip_prefix(&root_path).map_err(|e| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_TARGET_INVALID",
            format!("failed to anchor restore target {}: {e}", path.display()),
            2,
        )
    })?;
    validate_normal_relative_path(relative_path, "restore target")?;
    if !directory && relative_path.file_name().is_none() {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_TARGET_INVALID",
            format!("restore file target {} has no file name", path.display()),
            2,
        ));
    }
    let root = Dir::open_ambient_dir(&root_path, ambient_authority())
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_RESTORE_TARGET_INVALID", &root_path, e))?;
    Ok(PreparedTarget {
        root,
        relative_path: relative_path.to_path_buf(),
        display_path: absolute,
    })
}

fn filesystem_root(path: &Path) -> Result<PathBuf, ServiceError> {
    let mut root = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => root.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir | Component::Normal(_) => break,
        }
    }
    if root.as_os_str().is_empty() {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_TARGET_INVALID",
            format!("restore target {} is not absolute", path.display()),
            2,
        ));
    }
    Ok(root)
}

fn write_prepared_file(
    source: &mut PreparedBackupFile,
    target: &PreparedTarget,
) -> Result<(), ServiceError> {
    let file_name = target.relative_path.file_name().ok_or_else(|| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_TARGET_INVALID",
            format!(
                "restore target {} has no file name",
                target.display_path.display()
            ),
            2,
        )
    })?;
    let parent_path = target
        .relative_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = open_or_create_dir_chain(&target.root, parent_path, &target.display_path)?;
    let temp_name = OsString::from(format!(
        ".{}.restore.{}.{}",
        file_name.to_string_lossy(),
        std::process::id(),
        timestamp_suffix()
    ));
    let mut options = CapOpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut output = parent.open_with(&temp_name, &options).map_err(|e| {
        service_io_error(
            "ORACLEMCP_SERVICE_RESTORE_WRITE_FAILED",
            &target.display_path,
            e,
        )
    })?;
    source.snapshot.seek(SeekFrom::Start(0)).map_err(|e| {
        service_io_error(
            "ORACLEMCP_SERVICE_RESTORE_WRITE_FAILED",
            &target.display_path,
            e,
        )
    })?;
    let copied = io::copy(&mut source.snapshot, &mut output).map_err(|e| {
        service_io_error(
            "ORACLEMCP_SERVICE_RESTORE_WRITE_FAILED",
            &target.display_path,
            e,
        )
    })?;
    if copied != source.bytes {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_WRITE_FAILED",
            format!(
                "private restore snapshot for {} changed length unexpectedly",
                target.display_path.display()
            ),
            3,
        ));
    }
    output.sync_all().map_err(|e| {
        service_io_error(
            "ORACLEMCP_SERVICE_RESTORE_WRITE_FAILED",
            &target.display_path,
            e,
        )
    })?;
    parent.rename(&temp_name, &parent, file_name).map_err(|e| {
        service_io_error(
            "ORACLEMCP_SERVICE_RESTORE_WRITE_FAILED",
            &target.display_path,
            e,
        )
    })?;
    let current_parent = open_dir_chain_nofollow(&target.root, parent_path).map_err(|e| {
        service_io_error(
            "ORACLEMCP_SERVICE_RESTORE_UNSAFE_PATH",
            &target.display_path,
            e,
        )
    })?;
    if !same_capability_identity(&parent, &current_parent)? {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_UNSAFE_PATH",
            format!(
                "restore target parent for {} was replaced during write",
                target.display_path.display()
            ),
            2,
        ));
    }
    let current_file =
        open_cap_file_nofollow(&current_parent, Path::new(file_name)).map_err(|e| {
            service_io_error(
                "ORACLEMCP_SERVICE_RESTORE_UNSAFE_PATH",
                &target.display_path,
                e,
            )
        })?;
    let written_metadata = output.metadata().map_err(|e| {
        service_io_error(
            "ORACLEMCP_SERVICE_RESTORE_WRITE_FAILED",
            &target.display_path,
            e,
        )
    })?;
    let current_metadata = current_file.metadata().map_err(|e| {
        service_io_error(
            "ORACLEMCP_SERVICE_RESTORE_UNSAFE_PATH",
            &target.display_path,
            e,
        )
    })?;
    if written_metadata.dev() != current_metadata.dev()
        || written_metadata.ino() != current_metadata.ino()
    {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_UNSAFE_PATH",
            format!(
                "restore target {} was replaced after its atomic write",
                target.display_path.display()
            ),
            2,
        ));
    }
    drop(current_file);
    drop(output);
    #[cfg(windows)]
    {
        Ok(())
    }
    #[cfg(not(windows))]
    {
        parent
            .open(".")
            .and_then(|dir| dir.sync_all())
            .map_err(|e| {
                service_io_error(
                    "ORACLEMCP_SERVICE_RESTORE_WRITE_FAILED",
                    &target.display_path,
                    e,
                )
            })
    }
}

fn same_capability_identity(left: &Dir, right: &Dir) -> Result<bool, ServiceError> {
    let left = left.dir_metadata().map_err(|e| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_TARGET_INVALID",
            format!("failed to inspect held restore directory: {e}"),
            3,
        )
    })?;
    let right = right.dir_metadata().map_err(|e| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_TARGET_INVALID",
            format!("failed to inspect current restore directory: {e}"),
            3,
        )
    })?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

fn open_dir_chain_nofollow(root: &Dir, relative: &Path) -> io::Result<Dir> {
    let mut current = root.try_clone()?;
    if relative == Path::new(".") {
        return Ok(current);
    }
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory path contains a non-normal component",
            ));
        };
        current = current.open_dir_nofollow(name)?;
    }
    Ok(current)
}

fn open_or_create_dir_chain(
    root: &Dir,
    relative: &Path,
    display_target: &Path,
) -> Result<Dir, ServiceError> {
    let mut current = root.try_clone().map_err(|e| {
        service_io_error(
            "ORACLEMCP_SERVICE_RESTORE_TARGET_INVALID",
            display_target,
            e,
        )
    })?;
    if relative == Path::new(".") {
        return Ok(current);
    }
    validate_normal_relative_path(relative, "restore target parent")?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            unreachable!("validated normal relative path")
        };
        match current.open_dir_nofollow(name) {
            Ok(next) => current = next,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut builder = CapDirBuilder::new();
                #[cfg(unix)]
                {
                    use cap_std::fs::DirBuilderExt as _;
                    builder.mode(0o700);
                }
                match current.create_dir_with(name, &builder) {
                    Ok(()) => {}
                    Err(race) if race.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(service_io_error(
                            "ORACLEMCP_SERVICE_RESTORE_WRITE_FAILED",
                            display_target,
                            error,
                        ));
                    }
                }
                current = current.open_dir_nofollow(name).map_err(|e| {
                    service_io_error("ORACLEMCP_SERVICE_RESTORE_UNSAFE_PATH", display_target, e)
                })?;
            }
            Err(error) => {
                return Err(service_io_error(
                    "ORACLEMCP_SERVICE_RESTORE_UNSAFE_PATH",
                    display_target,
                    error,
                ));
            }
        }
    }
    Ok(current)
}

fn sha256_file(path: &Path) -> Result<String, ServiceError> {
    let bytes = fs::read(path)
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_BACKUP_READ_FAILED", path, e))?;
    Ok(sha256_hex(&bytes))
}

fn service_io_error(code: &'static str, path: &Path, error: io::Error) -> ServiceError {
    ServiceError::new(code, format!("{}: {error}", path.display()), 3)
}

fn timestamp_suffix() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}-{:09}", now.as_secs(), now.subsec_nanos())
}

fn stop_step(manager: ServiceManager, name: &str) -> Result<ServiceStep, ServiceError> {
    Ok(match manager {
        ServiceManager::SystemdUser => ServiceStep::Run {
            program: "systemctl".to_owned(),
            args: vec!["--user".into(), "stop".into(), systemd_unit_name(name)],
            optional: true,
        },
        ServiceManager::LaunchdUser => {
            let label = launchd_label(name);
            ServiceStep::Run {
                program: "launchctl".to_owned(),
                args: vec![
                    "kill".into(),
                    "TERM".into(),
                    launchd_service_target(&label)?,
                ],
                optional: true,
            }
        }
        ServiceManager::WindowsService => ServiceStep::Run {
            program: "sc.exe".to_owned(),
            args: vec!["stop".into(), name.to_owned()],
            optional: true,
        },
    })
}

fn start_step(manager: ServiceManager, name: &str) -> Result<ServiceStep, ServiceError> {
    Ok(match manager {
        ServiceManager::SystemdUser => ServiceStep::Run {
            program: "systemctl".to_owned(),
            args: vec!["--user".into(), "start".into(), systemd_unit_name(name)],
            optional: false,
        },
        ServiceManager::LaunchdUser => {
            let label = launchd_label(name);
            ServiceStep::Run {
                program: "launchctl".to_owned(),
                args: vec![
                    "kickstart".into(),
                    "-k".into(),
                    launchd_service_target(&label)?,
                ],
                optional: false,
            }
        }
        ServiceManager::WindowsService => ServiceStep::Run {
            program: "sc.exe".to_owned(),
            args: vec!["start".into(), name.to_owned()],
            optional: false,
        },
    })
}

fn execute_steps(steps: &[ServiceStep]) -> Result<(), ServiceError> {
    for step in steps {
        match step {
            ServiceStep::WriteFile { path, content } => {
                let path = PathBuf::from(path);
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(|e| {
                        ServiceError::new(
                            "ORACLEMCP_SERVICE_WRITE_FAILED",
                            format!(
                                "failed to create service directory {}: {e}",
                                parent.display()
                            ),
                            3,
                        )
                    })?;
                }
                fs::write(&path, content).map_err(|e| {
                    ServiceError::new(
                        "ORACLEMCP_SERVICE_WRITE_FAILED",
                        format!("failed to write service file {}: {e}", path.display()),
                        3,
                    )
                })?;
            }
            ServiceStep::RemoveFile { path, if_exists } => {
                let path = PathBuf::from(path);
                if *if_exists && !path.exists() {
                    continue;
                }
                fs::remove_file(&path).map_err(|e| {
                    ServiceError::new(
                        "ORACLEMCP_SERVICE_REMOVE_FAILED",
                        format!("failed to remove service file {}: {e}", path.display()),
                        3,
                    )
                })?;
            }
            ServiceStep::Run {
                program,
                args,
                optional,
            } => {
                let output = match run_capture(program, args, *optional) {
                    Ok(output) => output,
                    Err(err) if *optional => {
                        eprintln!(
                            "oraclemcp service: skipped optional command: {}",
                            err.message
                        );
                        continue;
                    }
                    Err(err) => return Err(err),
                };
                if !output.status.success() && *optional {
                    eprintln!(
                        "oraclemcp service: optional command failed: {} {}",
                        program,
                        args.join(" ")
                    );
                } else if !output.status.success() {
                    return Err(ServiceError::new(
                        "ORACLEMCP_SERVICE_COMMAND_FAILED",
                        format!(
                            "service-manager command failed: {} {}\n{}",
                            program,
                            args.join(" "),
                            String::from_utf8_lossy(&output.stderr).trim()
                        ),
                        3,
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Returns whether `pid` still refers to a live process on this host.
///
/// Used to distinguish a stale instance lock left by a crashed or killed service
/// from a lock held by a running peer.
fn service_instance_pid_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    if pid == std::process::id() {
        return true;
    }
    service_instance_pid_is_alive_platform(pid)
}

#[cfg(unix)]
fn service_instance_pid_is_alive_platform(pid: u32) -> bool {
    use std::process::Command;
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(windows)]
fn service_instance_pid_is_alive_platform(pid: u32) -> bool {
    use std::process::Command;
    Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .output()
        .map(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .any(|line| line.contains(&pid.to_string()))
        })
        .unwrap_or(false)
}

/// If `path` exists and records a dead pid, remove the stale lock file.
fn try_clear_stale_service_instance_lock_at(path: &Path) -> bool {
    let ServiceInstanceDiscovery::Present { pid, .. } = discover_service_instance_at(path) else {
        return false;
    };
    if service_instance_pid_is_alive(pid) {
        return false;
    }
    if fs::remove_file(path).is_ok() {
        let _ = sync_parent_dir(path);
        return true;
    }
    false
}

fn service_instance_already_running_error(path: &Path) -> ServiceError {
    ServiceError::new(
        "ORACLEMCP_SERVICE_ALREADY_RUNNING",
        format!(
            "another oraclemcp service instance is already registered; refusing to \
             start a second instance ({}). This prevents silent takeover of a different \
             port or socket; inspect service status/logs before clearing a stale lock.",
            render_instance_discovery(&discover_service_instance_at(path))
        ),
        3,
    )
}

fn create_service_instance_lock_file(
    path: &Path,
    _body: &[u8],
) -> Result<std::fs::File, ServiceError> {
    match create_new_private_file(path) {
        Ok(file) => Ok(file),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            if try_clear_stale_service_instance_lock_at(path) {
                create_new_private_file(path).map_err(|retry| {
                    if retry.kind() == io::ErrorKind::AlreadyExists {
                        service_instance_already_running_error(path)
                    } else {
                        ServiceError::new(
                            "ORACLEMCP_SERVICE_LOCK_UNAVAILABLE",
                            format!(
                                "failed to create service instance lock at {} after clearing stale lock: {retry}",
                                path.display()
                            ),
                            3,
                        )
                    }
                })
            } else {
                Err(service_instance_already_running_error(path))
            }
        }
        Err(e) => Err(ServiceError::new(
            "ORACLEMCP_SERVICE_LOCK_UNAVAILABLE",
            format!(
                "failed to create service instance lock at {}: {e}",
                path.display()
            ),
            3,
        )),
    }
}

fn acquire_service_instance_guard_at(
    path: &Path,
    listen: &str,
) -> Result<ServiceInstanceGuard, ServiceError> {
    let token = new_service_instance_token()?;
    let metadata = ServiceInstanceMetadata {
        schema_version: SERVICE_INSTANCE_SCHEMA_VERSION,
        pid: std::process::id(),
        listen: listen.to_owned(),
        started_unix_ms: current_unix_millis(),
        token: token.clone(),
    };
    let mut body = serde_json::to_vec_pretty(&metadata).map_err(|e| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_LOCK_UNAVAILABLE",
            format!("failed to serialize service instance lock metadata: {e}"),
            3,
        )
    })?;
    body.push(b'\n');

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        ensure_private_runtime_dir(parent).map_err(|e| {
            ServiceError::new(
                "ORACLEMCP_SERVICE_LOCK_UNAVAILABLE",
                format!(
                    "failed to prepare service runtime directory {}: {e}",
                    parent.display()
                ),
                3,
            )
        })?;
    }

    let mut file = create_service_instance_lock_file(path, &body)?;

    let write_result = file.write_all(&body).and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = write_result {
        let _ = fs::remove_file(path);
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_LOCK_UNAVAILABLE",
            format!(
                "failed to write service instance lock {}: {e}",
                path.display()
            ),
            3,
        ));
    }
    if let Err(e) = sync_parent_dir(path) {
        let _ = fs::remove_file(path);
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_LOCK_UNAVAILABLE",
            format!(
                "failed to sync service instance lock directory for {}: {e}",
                path.display()
            ),
            3,
        ));
    }

    Ok(ServiceInstanceGuard {
        path: path.to_path_buf(),
        token,
    })
}

fn default_service_instance_lock_path() -> PathBuf {
    default_service_runtime_dir().join(SERVICE_INSTANCE_LOCK_FILE)
}

fn default_service_runtime_dir() -> PathBuf {
    if let Some(runtime) = env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("oraclemcp");
    }
    let user = env::var("USER")
        .or_else(|_| env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_owned());
    env::temp_dir().join(format!("oraclemcp-service-{user}"))
}

fn discover_service_instance() -> ServiceInstanceDiscovery {
    discover_service_instance_at(&default_service_instance_lock_path())
}

fn discover_service_instance_at(path: &Path) -> ServiceInstanceDiscovery {
    let lock_path = path.display().to_string();
    let body = match fs::read_to_string(path) {
        Ok(body) => body,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return ServiceInstanceDiscovery::Missing { lock_path };
        }
        Err(e) => {
            return ServiceInstanceDiscovery::Unreadable {
                lock_path,
                error: e.to_string(),
            };
        }
    };
    match serde_json::from_str::<ServiceInstanceMetadata>(&body) {
        Ok(metadata) if metadata.schema_version == SERVICE_INSTANCE_SCHEMA_VERSION => {
            ServiceInstanceDiscovery::Present {
                lock_path,
                pid: metadata.pid,
                listen: metadata.listen,
                started_unix_ms: metadata.started_unix_ms,
            }
        }
        Ok(metadata) => ServiceInstanceDiscovery::Unreadable {
            lock_path,
            error: format!("unsupported schema_version {}", metadata.schema_version),
        },
        Err(e) => ServiceInstanceDiscovery::Unreadable {
            lock_path,
            error: e.to_string(),
        },
    }
}

fn render_instance_discovery(discovery: &ServiceInstanceDiscovery) -> String {
    match discovery {
        ServiceInstanceDiscovery::Missing { lock_path } => {
            format!("no service instance lock at {lock_path}")
        }
        ServiceInstanceDiscovery::Present {
            lock_path,
            pid,
            listen,
            started_unix_ms,
        } => format!(
            "service instance lock at {lock_path}: pid={pid} listen={listen:?} started_unix_ms={started_unix_ms}"
        ),
        ServiceInstanceDiscovery::Unreadable { lock_path, error } => {
            format!("service instance lock at {lock_path} is unreadable: {error}")
        }
    }
}

fn ensure_private_runtime_dir(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "service runtime path is not a regular directory",
                ));
            }
            harden_private_runtime_dir(path, &metadata)
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            builder.create(path)
        }
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn harden_private_runtime_dir(path: &Path, metadata: &fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = metadata.permissions().mode() & 0o777;
    if mode == 0o700 {
        return Ok(());
    }
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)
}

#[cfg(not(unix))]
fn harden_private_runtime_dir(_path: &Path, _metadata: &fs::Metadata) -> io::Result<()> {
    Ok(())
}

fn create_new_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

fn new_service_instance_token() -> Result<String, ServiceError> {
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).map_err(|e| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_LOCK_UNAVAILABLE",
            format!("failed to create service instance token: {e}"),
            3,
        )
    })?;
    Ok(hex_lower(&raw))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn current_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn sync_parent_dir(path: &Path) -> io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        sync_dir(parent)?;
    }
    Ok(())
}

#[cfg(windows)]
fn sync_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
fn sync_dir(path: &Path) -> io::Result<()> {
    File::open(path).and_then(|file| file.sync_all())
}

fn run_capture(
    program: &str,
    args: &[String],
    optional: bool,
) -> Result<std::process::Output, ServiceError> {
    Command::new(program).args(args).output().map_err(|e| {
        ServiceError::new(
            if optional {
                "ORACLEMCP_SERVICE_OPTIONAL_COMMAND_UNAVAILABLE"
            } else {
                "ORACLEMCP_SERVICE_COMMAND_UNAVAILABLE"
            },
            format!("failed to run service-manager command `{program}`: {e}"),
            if optional { 0 } else { 3 },
        )
    })
}

fn serve_args(options: &ServiceInstallOptions) -> Vec<String> {
    let mut args = vec![
        "serve".to_owned(),
        "--listen".to_owned(),
        options.listen.clone(),
    ];
    if options.allow_no_auth {
        args.push("--allow-no-auth".to_owned());
    }
    if options.client_credentials {
        args.push("--client-credentials".to_owned());
    }
    if let Some(profile) = options.profile.as_ref() {
        args.push("--profile".to_owned());
        args.push(profile.clone());
    }
    args
}

fn validate_service_name(name: &str) -> Result<(), ServiceError> {
    let valid = !name.is_empty()
        && name.len() <= 80
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(ServiceError::new(
            "ORACLEMCP_SERVICE_INVALID_NAME",
            "service name must be 1..=80 ASCII letters, digits, '.', '_' or '-' with no path separators",
            2,
        ))
    }
}

fn systemd_unit_name(name: &str) -> String {
    if name.ends_with(".service") {
        name.to_owned()
    } else {
        format!("{name}.service")
    }
}

fn systemd_user_unit_path(unit: &str) -> Result<PathBuf, ServiceError> {
    let config_home = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| home_dir().map(|home| home.join(".config")))
        .ok_or_else(|| {
            ServiceError::new(
                "ORACLEMCP_SERVICE_HOME_UNAVAILABLE",
                "cannot determine home directory for systemd user unit path",
                2,
            )
        })?;
    Ok(config_home.join("systemd/user").join(unit))
}

fn launchd_label(name: &str) -> String {
    if name.contains('.') {
        name.to_owned()
    } else {
        format!("io.github.MuhDur.{name}")
    }
}

fn launchd_plist_path(label: &str) -> Result<PathBuf, ServiceError> {
    let home = home_dir().ok_or_else(|| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_HOME_UNAVAILABLE",
            "cannot determine home directory for launchd agent path",
            2,
        )
    })?;
    Ok(home
        .join("Library/LaunchAgents")
        .join(format!("{label}.plist")))
}

fn launchd_domain() -> Result<String, ServiceError> {
    let uid = current_uid().ok_or_else(|| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_UID_UNAVAILABLE",
            "cannot determine UID for launchd gui/<uid> domain",
            2,
        )
    })?;
    Ok(format!("gui/{uid}"))
}

fn launchd_service_target(label: &str) -> Result<String, ServiceError> {
    Ok(format!("{}/{}", launchd_domain()?, label))
}

fn home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn current_user() -> Option<String> {
    env::var("USER")
        .or_else(|_| env::var("LOGNAME"))
        .or_else(|_| env::var("USERNAME"))
        .ok()
        .filter(|s| !s.is_empty())
}

fn current_uid() -> Option<String> {
    if let Ok(uid) = env::var("UID")
        && !uid.is_empty()
        && uid.bytes().all(|b| b.is_ascii_digit())
    {
        return Some(uid);
    }
    #[cfg(target_os = "windows")]
    {
        Some("0".to_owned())
    }
    #[cfg(not(target_os = "windows"))]
    {
        Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|uid| uid.trim().to_owned())
            .filter(|uid| !uid.is_empty() && uid.bytes().all(|b| b.is_ascii_digit()))
    }
}

fn systemd_unit(exe: &str, serve_args: &[String]) -> String {
    let exec = std::iter::once(systemd_quote(exe))
        .chain(serve_args.iter().map(|arg| systemd_quote(arg)))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "[Unit]\n\
         Description=oraclemcp always-on MCP service\n\
         After=network-online.target\n\
         Wants=network-online.target\n\n\
         [Service]\n\
         Type=notify\n\
         NotifyAccess=main\n\
         ExecStart={exec}\n\
         Restart=on-failure\n\
         RestartSec=3\n\
         LimitNOFILE={SERVICE_LIMIT_NOFILE}\n\
         TasksMax={SERVICE_TASKS_MAX}\n\
         MemoryMax={SERVICE_MEMORY_MAX_SYSTEMD}\n\
         OOMScoreAdjust={SERVICE_OOM_SCORE_ADJUST}\n\
         Environment=ORACLEMCP_SERVICE=1\n\n\
         [Install]\n\
         WantedBy=default.target\n"
    )
}

fn launchd_plist(label: &str, exe: &str, serve_args: &[String]) -> String {
    let args = std::iter::once(exe.to_owned())
        .chain(serve_args.iter().cloned())
        .map(|arg| format!("        <string>{}</string>", xml_escape(&arg)))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
             <key>Label</key>\n\
             <string>{}</string>\n\
             <key>ProgramArguments</key>\n\
             <array>\n{}\n\
             </array>\n\
             <key>RunAtLoad</key>\n\
             <true/>\n\
             <key>KeepAlive</key>\n\
             <true/>\n\
             <key>SoftResourceLimits</key>\n\
             <dict>\n\
                 <key>NumberOfFiles</key>\n\
                 <integer>{}</integer>\n\
                 <key>NumberOfProcesses</key>\n\
                 <integer>{}</integer>\n\
             </dict>\n\
         </dict>\n\
         </plist>\n",
        xml_escape(label),
        args,
        SERVICE_LIMIT_NOFILE,
        SERVICE_TASKS_MAX
    )
}

fn windows_bin_path(exe: &str, serve_args: &[String]) -> String {
    std::iter::once(windows_quote(exe))
        .chain(serve_args.iter().map(|arg| windows_quote(arg)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn status_command(
    manager: ServiceManager,
    name: &str,
) -> Result<(String, Vec<String>), ServiceError> {
    Ok(match manager {
        ServiceManager::SystemdUser => (
            "systemctl".to_owned(),
            vec!["--user".into(), "is-active".into(), systemd_unit_name(name)],
        ),
        ServiceManager::LaunchdUser => {
            let label = launchd_label(name);
            (
                "launchctl".to_owned(),
                vec!["print".into(), launchd_service_target(&label)?],
            )
        }
        ServiceManager::WindowsService => {
            ("sc.exe".to_owned(), vec!["query".into(), name.to_owned()])
        }
    })
}

fn logs_command(
    manager: ServiceManager,
    name: &str,
    lines: u16,
) -> Result<(String, Vec<String>), ServiceError> {
    Ok(match manager {
        ServiceManager::SystemdUser => (
            "journalctl".to_owned(),
            vec![
                "--user-unit".into(),
                systemd_unit_name(name),
                "-n".into(),
                lines.to_string(),
                "--no-pager".into(),
            ],
        ),
        ServiceManager::LaunchdUser => (
            "log".to_owned(),
            vec![
                "show".into(),
                "--style".into(),
                "compact".into(),
                "--last".into(),
                "1h".into(),
                "--predicate".into(),
                format!("process == \"{}\"", name),
            ],
        ),
        ServiceManager::WindowsService => (
            "powershell.exe".to_owned(),
            vec![
                "-NoProfile".into(),
                "-Command".into(),
                format!(
                    "Get-EventLog -LogName Application -Source '{}' -Newest {}",
                    name.replace('\'', "''"),
                    lines
                ),
            ],
        ),
    })
}

fn systemd_quote(input: &str) -> String {
    if input
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b':' | b'-'))
    {
        input.to_owned()
    } else {
        format!("\"{}\"", input.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

fn windows_quote(input: &str) -> String {
    format!("\"{}\"", input.replace('"', "\\\""))
}

fn xml_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn render_plan_text(plan: &ServicePlan) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "oraclemcp service {}\nmanager: {}\nservice: {}\n",
        plan.action,
        plan.manager.as_str(),
        plan.service_name
    ));
    if plan.dry_run {
        out.push_str("mode: dry-run (no changes made)\n");
    } else {
        out.push_str("mode: executed\n");
    }
    if !plan.serve_args.is_empty() {
        out.push_str(&format!(
            "serve command: {} {}\n",
            plan.executable,
            plan.serve_args.join(" ")
        ));
    }
    if let Some(hardening) = &plan.hardening {
        out.push_str(&format!(
            "hardening: restart={:?} notify={:?} nofile={:?} tasks={:?} memory={:?} oom={:?}\n",
            hardening.configured.restart_policy,
            hardening.configured.notify,
            hardening.configured.limit_nofile,
            hardening.configured.tasks_max,
            hardening.configured.memory_max_bytes,
            hardening.configured.oom_score_adjust,
        ));
    }
    for (index, step) in plan.steps.iter().enumerate() {
        out.push_str(&format!("{}. {}\n", index + 1, render_step(step)));
    }
    if !plan.next_actions.is_empty() {
        out.push_str("next actions:\n");
        for action in &plan.next_actions {
            out.push_str(&format!("  - {action}\n"));
        }
    }
    out
}

fn render_step(step: &ServiceStep) -> String {
    match step {
        ServiceStep::WriteFile { path, .. } => format!("write service file {path}"),
        ServiceStep::RemoveFile { path, if_exists } => {
            if *if_exists {
                format!("remove service file {path} if it exists")
            } else {
                format!("remove service file {path}")
            }
        }
        ServiceStep::Run {
            program,
            args,
            optional,
        } => {
            let optional = if *optional { " (optional)" } else { "" };
            format!("run {program} {}{optional}", args.join(" "))
        }
    }
}

fn service_hardening(manager: ServiceManager) -> ServiceHardening {
    ServiceHardening {
        manager,
        configured: configured_service_unit_caps(manager),
        notes: service_hardening_notes(manager),
    }
}

fn configured_service_unit_caps(manager: ServiceManager) -> DoctorServiceUnitLimitCaps {
    match manager {
        ServiceManager::SystemdUser => DoctorServiceUnitLimitCaps {
            notify: Some("type=notify notify_access=main".to_owned()),
            restart_policy: Some("on-failure".to_owned()),
            limit_nofile: Some(SERVICE_LIMIT_NOFILE),
            tasks_max: Some(SERVICE_TASKS_MAX),
            memory_max_bytes: Some(SERVICE_MEMORY_MAX_BYTES),
            oom_score_adjust: Some(SERVICE_OOM_SCORE_ADJUST),
        },
        ServiceManager::LaunchdUser => DoctorServiceUnitLimitCaps {
            notify: None,
            restart_policy: Some("KeepAlive=true".to_owned()),
            limit_nofile: Some(SERVICE_LIMIT_NOFILE),
            tasks_max: Some(SERVICE_TASKS_MAX),
            memory_max_bytes: None,
            oom_score_adjust: None,
        },
        ServiceManager::WindowsService => DoctorServiceUnitLimitCaps {
            notify: None,
            restart_policy: Some("sc.exe failure actions=restart/5000".to_owned()),
            limit_nofile: None,
            tasks_max: None,
            memory_max_bytes: None,
            oom_score_adjust: None,
        },
    }
}

fn effective_service_unit_caps() -> DoctorServiceUnitLimitCaps {
    DoctorServiceUnitLimitCaps {
        notify: env::var_os("NOTIFY_SOCKET").map(|_| "notify_socket_present".to_owned()),
        restart_policy: None,
        limit_nofile: proc_limit_soft("Max open files"),
        tasks_max: finite_min([
            proc_limit_soft("Max processes"),
            read_cgroup_limit("/sys/fs/cgroup/pids.max"),
        ]),
        memory_max_bytes: read_cgroup_limit("/sys/fs/cgroup/memory.max"),
        oom_score_adjust: read_i16("/proc/self/oom_score_adj"),
    }
}

fn service_hardening_notes(manager: ServiceManager) -> Vec<String> {
    match manager {
        ServiceManager::SystemdUser => vec![
            "effective values are read from the current process and cgroup; run doctor under the service to inspect inherited unit caps".to_owned(),
            "OOMScoreAdjust is positive so an unprivileged user service can apply it without elevated capabilities".to_owned(),
        ],
        ServiceManager::LaunchdUser => vec![
            "launchd agent uses KeepAlive plus SoftResourceLimits for file and process caps; memory and OOM controls are platform-specific".to_owned(),
        ],
        ServiceManager::WindowsService => vec![
            "Windows service install configures automatic start plus restart-on-failure; file, task, and memory caps require external service wrapper or job-object policy".to_owned(),
        ],
    }
}

fn proc_limit_soft(label: &str) -> Option<u64> {
    let limits = fs::read_to_string("/proc/self/limits").ok()?;
    for line in limits.lines() {
        if let Some(rest) = line.strip_prefix(label) {
            return parse_limit_value(rest.split_whitespace().next()?);
        }
    }
    None
}

fn read_cgroup_limit(path: &str) -> Option<u64> {
    let raw = fs::read_to_string(path).ok()?;
    parse_limit_value(raw.trim())
}

fn parse_limit_value(raw: &str) -> Option<u64> {
    if raw.eq_ignore_ascii_case("unlimited") || raw == "max" {
        None
    } else {
        raw.parse().ok()
    }
}

fn read_i16(path: &str) -> Option<i16> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn finite_min(values: impl IntoIterator<Item = Option<u64>>) -> Option<u64> {
    values.into_iter().flatten().min()
}

#[cfg(test)]
mod tests {
    use super::*;
    use oraclemcp_audit::{
        AuditDecision, AuditEntryDraft, AuditOutcome, AuditRecord, AuditSubject, GENESIS_HASH,
    };

    fn exe() -> PathBuf {
        PathBuf::from("/opt/oraclemcp/bin/oraclemcp")
    }

    fn test_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root")
            .join("target/service-lifecycle-tests")
            .join(format!("{name}-{}-{stamp}", std::process::id()))
    }

    fn signed_audit_jsonl(key: &SigningKey) -> String {
        let draft = AuditEntryDraft {
            subject: AuditSubject::new("operator", "restore-test").with_authn_method("loopback"),
            db_evidence: None,
            cancel: None,
            tool: "oracle_execute".to_owned(),
            sql: "update app.t set c = 1 where id = :id".to_owned(),
            danger_level: "READ_WRITE".to_owned(),
            decision: AuditDecision::Allowed,
            rows_affected: Some(1),
            outcome: AuditOutcome::Succeeded,
        };
        let record = AuditRecord::chained_signed(
            &draft,
            1,
            GENESIS_HASH,
            "2026-07-01T00:00:00Z".to_owned(),
            key,
        );
        format!("{}\n", serde_json::to_string(&record).expect("audit json"))
    }

    #[derive(Debug)]
    struct RestoreFixture {
        root: PathBuf,
        backup: PathBuf,
        state_target: PathBuf,
        config_target: PathBuf,
        audit_target: PathBuf,
        key: SigningKey,
    }

    impl RestoreFixture {
        fn options(&self) -> ServiceRestoreOptions {
            ServiceRestoreOptions {
                name: "oraclemcp".to_owned(),
                state_dir: self.state_target.clone(),
                config_path: self.config_target.clone(),
                audit_path: self.audit_target.clone(),
                backup: self.backup.clone(),
                audit_keys: vec![self.key.clone()],
                yes: false,
                dry_run: true,
            }
        }

        fn manifest(&self) -> BackupManifest {
            let body = fs::read_to_string(self.backup.join(BACKUP_MANIFEST_FILE))
                .expect("read test manifest");
            serde_json::from_str(&body).expect("parse test manifest")
        }

        fn write_signed_manifest(&self, mut manifest: BackupManifest) {
            sign_backup_manifest(&mut manifest, &self.key).expect("sign test manifest");
            write_manifest(&self.backup, &manifest).expect("write test manifest");
        }
    }

    fn restore_fixture(name: &str) -> RestoreFixture {
        let root = test_root(name);
        let source_state = root.join("live").join("state");
        let source_config = root.join("live").join("config").join("profiles.toml");
        let source_audit = root.join("live").join("audit").join("audit.jsonl");
        let backup = root.join("backup");
        let key = SigningKey::new(
            "default",
            format!("qa4-restore-fixture-key-{name}-0123456789").into_bytes(),
        )
        .expect("valid fixture key");
        fs::create_dir_all(source_state.join("metrics")).expect("source state dir");
        fs::create_dir_all(source_config.parent().expect("source config parent"))
            .expect("source config dir");
        fs::create_dir_all(source_audit.parent().expect("source audit parent"))
            .expect("source audit dir");
        fs::write(
            source_state.join("metrics/snapshot.json"),
            b"fixture-state\n",
        )
        .expect("source state");
        fs::write(&source_config, b"schema_version = 2\nfixture = true\n").expect("source config");
        let audit_jsonl = signed_audit_jsonl(&key);
        fs::write(&source_audit, &audit_jsonl).expect("source audit");
        let record: AuditRecord =
            serde_json::from_str(audit_jsonl.trim()).expect("source audit record");
        fs::write(
            oraclemcp_audit::anchor_path_for(&source_audit),
            format!(
                "{}\n",
                serde_json::to_string(&oraclemcp_audit::ChainAnchor::signed(
                    record.seq,
                    &record.entry_hash,
                    &key,
                ))
                .expect("source anchor json")
            ),
        )
        .expect("source anchor");
        run_service_command_with(
            ServiceCommand::Backup(ServiceBackupOptions {
                name: "oraclemcp".to_owned(),
                state_dir: source_state,
                config_path: source_config,
                audit_path: source_audit,
                manifest_signing_key: key.clone(),
                output: Some(backup.clone()),
                yes: true,
                dry_run: false,
            }),
            ServiceManager::SystemdUser,
            &exe(),
        )
        .expect("create fixture backup");
        RestoreFixture {
            state_target: root.join("restore").join("state"),
            config_target: root.join("restore").join("config/profiles.toml"),
            audit_target: root.join("restore").join("audit/audit.jsonl"),
            root,
            backup,
            key,
        }
    }

    #[test]
    fn install_requires_yes_or_dry_run() {
        let err = run_service_command_with(
            ServiceCommand::Install(ServiceInstallOptions {
                name: "oraclemcp".to_owned(),
                listen: "127.0.0.1:7070".to_owned(),
                profile: None,
                allow_no_auth: false,
                client_credentials: false,
                skip_linger: false,
                yes: false,
                dry_run: false,
            }),
            ServiceManager::SystemdUser,
            &exe(),
        )
        .expect_err("mutating install requires confirmation");
        assert_eq!(err.code, "ORACLEMCP_SERVICE_CONFIRM_REQUIRED");
        assert!(err.message.contains("--dry-run"));
        assert!(err.message.contains("--yes"));
    }

    #[test]
    fn systemd_install_dry_run_plans_user_unit_and_linger() {
        let result = run_service_command_with(
            ServiceCommand::Install(ServiceInstallOptions {
                name: "oraclemcp".to_owned(),
                listen: "127.0.0.1:7070".to_owned(),
                profile: Some("dev_ro".to_owned()),
                allow_no_auth: false,
                client_credentials: true,
                skip_linger: false,
                yes: false,
                dry_run: true,
            }),
            ServiceManager::SystemdUser,
            &exe(),
        )
        .expect("dry-run plan");
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.payload["action"], serde_json::json!("install"));
        assert_eq!(result.payload["manager"], serde_json::json!("systemd_user"));
        assert_eq!(
            result.payload["hardening"]["configured"]["limit_nofile"],
            serde_json::json!(SERVICE_LIMIT_NOFILE)
        );
        assert_eq!(
            result.payload["hardening"]["configured"]["tasks_max"],
            serde_json::json!(SERVICE_TASKS_MAX)
        );
        let steps = result.payload["steps"].as_array().expect("steps array");
        let unit = steps
            .iter()
            .find_map(|step| step["content"].as_str())
            .expect("systemd unit content");
        assert!(unit.contains("Type=notify"));
        assert!(unit.contains("NotifyAccess=main"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("LimitNOFILE=65536"));
        assert!(unit.contains("TasksMax=512"));
        assert!(unit.contains("MemoryMax=2G"));
        assert!(unit.contains("OOMScoreAdjust=100"));
        assert!(steps.iter().any(|step| {
            step["program"] == "systemctl"
                && step["args"]
                    == serde_json::json!(["--user", "enable", "--now", "oraclemcp.service"])
        }));
        assert!(steps.iter().any(|step| step["program"] == "loginctl"));
        assert!(
            result
                .text
                .contains("serve --listen 127.0.0.1:7070 --client-credentials --profile dev_ro"),
            "{}",
            result.text
        );
    }

    #[test]
    fn systemd_unit_quotes_paths_with_spaces() {
        let unit = systemd_unit(
            "/opt/oracle mcp/oraclemcp",
            &["serve".into(), "--listen".into(), "127.0.0.1:7070".into()],
        );
        assert!(
            unit.contains("ExecStart=\"/opt/oracle mcp/oraclemcp\" serve --listen 127.0.0.1:7070")
        );
    }

    #[test]
    fn uninstall_dry_run_plans_disable_and_remove() {
        let result = run_service_command_with(
            ServiceCommand::Uninstall(ServiceMutationOptions {
                name: "oraclemcp".to_owned(),
                yes: false,
                dry_run: true,
            }),
            ServiceManager::SystemdUser,
            &exe(),
        )
        .expect("dry-run plan");
        let payload = result.payload.to_string();
        assert!(payload.contains("disable"));
        assert!(payload.contains("remove_file"));
        assert_eq!(result.payload["action"], serde_json::json!("uninstall"));
    }

    #[test]
    fn restart_dry_run_plans_manager_restart() {
        let result = run_service_command_with(
            ServiceCommand::Restart(ServiceMutationOptions {
                name: "oraclemcp".to_owned(),
                yes: false,
                dry_run: true,
            }),
            ServiceManager::SystemdUser,
            &exe(),
        )
        .expect("dry-run plan");
        let payload = result.payload.to_string();
        assert!(payload.contains("restart"));
        assert!(payload.contains("oraclemcp.service"));
    }

    #[test]
    fn backup_restore_verifies_audit_chain() {
        let root = test_root("backup-restore");
        let state_dir = root.join("state").join("oraclemcp");
        let config_path = root.join("config").join("profiles.toml");
        let audit_path = state_dir.join("audit").join("audit.jsonl");
        let backup_dir = root.join("backup");
        let key = SigningKey::new("default", b"backup-restore-test-key-123456789".to_vec())
            .expect("valid test key");

        fs::create_dir_all(audit_path.parent().expect("audit parent")).expect("audit dir");
        fs::create_dir_all(config_path.parent().expect("config parent")).expect("config dir");
        fs::create_dir_all(state_dir.join("metrics")).expect("metrics dir");
        let audit_jsonl = signed_audit_jsonl(&key);
        fs::write(&audit_path, &audit_jsonl).expect("seed audit chain");
        let audit_record: AuditRecord =
            serde_json::from_str(audit_jsonl.trim()).expect("seed audit record");
        fs::write(
            oraclemcp_audit::anchor_path_for(&audit_path),
            format!(
                "{}\n",
                serde_json::to_string(&oraclemcp_audit::ChainAnchor::signed(
                    audit_record.seq,
                    &audit_record.entry_hash,
                    &key,
                ))
                .expect("anchor json")
            ),
        )
        .expect("seed audit anchor");
        fs::write(
            state_dir.join("metrics").join("snapshot.json"),
            b"{\"ok\":true}\n",
        )
        .expect("seed state file");
        fs::write(
            &config_path,
            b"schema_version = 2\n\n[[profiles]]\nname = \"prod\"\nconnect_string = \"db\"\n",
        )
        .expect("seed config");

        let backup = run_service_command_with(
            ServiceCommand::Backup(ServiceBackupOptions {
                name: "oraclemcp".to_owned(),
                state_dir: state_dir.clone(),
                config_path: config_path.clone(),
                audit_path: audit_path.clone(),
                manifest_signing_key: key.clone(),
                output: Some(backup_dir.clone()),
                yes: true,
                dry_run: false,
            }),
            ServiceManager::SystemdUser,
            &exe(),
        )
        .expect("backup succeeds");
        assert_eq!(
            backup.payload["kind"],
            serde_json::json!("oraclemcp_service_backup")
        );
        assert_eq!(
            backup.payload["manifest"]["service_lock_held"],
            serde_json::json!(true)
        );

        let restore_plan = run_service_command_with(
            ServiceCommand::Restore(ServiceRestoreOptions {
                name: "oraclemcp".to_owned(),
                state_dir: state_dir.clone(),
                config_path: config_path.clone(),
                audit_path: audit_path.clone(),
                backup: backup_dir.clone(),
                audit_keys: vec![key.clone()],
                yes: false,
                dry_run: true,
            }),
            ServiceManager::SystemdUser,
            &exe(),
        )
        .expect("dry-run restore verifies audit");
        assert_eq!(
            restore_plan.payload["audit_verification"]["status"],
            serde_json::json!("verified")
        );
        assert_eq!(
            restore_plan.payload["audit_verification"]["records"],
            serde_json::json!(1)
        );

        fs::write(
            state_dir.join("metrics").join("snapshot.json"),
            b"{\"ok\":false}\n",
        )
        .expect("mutate state file");
        fs::write(&config_path, b"schema_version = 2\n").expect("mutate config");

        let restore_options = ServiceRestoreOptions {
            name: "oraclemcp".to_owned(),
            state_dir: state_dir.clone(),
            config_path: config_path.clone(),
            audit_path: audit_path.clone(),
            backup: backup_dir.clone(),
            audit_keys: vec![key.clone()],
            yes: true,
            dry_run: false,
        };
        let mut prepared = prepare_restore(&restore_options).expect("prepare restore");
        // A post-preflight source replacement cannot change the anonymous
        // payload snapshot that is applied.
        fs::write(
            backup_dir
                .join("state")
                .join("metrics")
                .join("snapshot.json"),
            b"attacker rename-swap bytes\n",
        )
        .expect("replace source after prepare");
        prepared.apply().expect("restore copies staged files");
        assert_eq!(
            fs::read(state_dir.join("metrics").join("snapshot.json")).expect("restored state"),
            b"{\"ok\":true}\n"
        );
        assert!(
            fs::read_to_string(&config_path)
                .expect("restored config")
                .contains("name = \"prod\"")
        );

        let backup_audit = backup_dir.join("audit").join("audit.jsonl");
        let mut tampered: serde_json::Value = serde_json::from_str(
            fs::read_to_string(&backup_audit)
                .expect("read backup audit")
                .trim(),
        )
        .expect("backup audit json");
        tampered["signature"] = serde_json::json!("hmac-sha256:00");
        fs::write(
            &backup_audit,
            format!(
                "{}\n",
                serde_json::to_string(&tampered).expect("tampered json")
            ),
        )
        .expect("tamper backup audit");
        let err = run_service_command_with(
            ServiceCommand::Restore(ServiceRestoreOptions {
                name: "oraclemcp".to_owned(),
                state_dir,
                config_path,
                audit_path,
                backup: backup_dir,
                audit_keys: vec![key],
                yes: false,
                dry_run: true,
            }),
            ServiceManager::SystemdUser,
            &exe(),
        )
        .expect_err("tampered payload refuses restore");
        assert_eq!(err.code, "ORACLEMCP_SERVICE_RESTORE_PAYLOAD_MISMATCH");
    }

    #[test]
    fn restore_rejects_authenticated_absolute_parent_empty_and_prefixed_paths() {
        let fixture = restore_fixture("unsafe-manifest-paths");
        let baseline = fixture.manifest();
        let unsafe_file_paths = [
            "/tmp/outside-profiles.toml",
            "../outside-profiles.toml",
            "",
            ".",
            "C:\\outside\\profiles.toml",
        ];
        for unsafe_path in unsafe_file_paths {
            let mut manifest = baseline.clone();
            manifest.config.backup_path = Some(unsafe_path.to_owned());
            fixture.write_signed_manifest(manifest);
            let err = prepare_restore(&fixture.options()).expect_err("unsafe file path rejected");
            assert!(
                matches!(
                    err.code,
                    "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP"
                        | "ORACLEMCP_SERVICE_RESTORE_UNSAFE_PATH"
                ),
                "unexpected error for {unsafe_path:?}: {err:?}"
            );
        }

        for unsafe_path in [
            "/tmp/outside-state",
            "../outside-state",
            "",
            ".",
            "C:\\outside\\state",
        ] {
            let mut manifest = baseline.clone();
            manifest.state.backup_path = unsafe_path.to_owned();
            fixture.write_signed_manifest(manifest);
            let err = prepare_restore(&fixture.options()).expect_err("unsafe tree path rejected");
            assert_eq!(err.code, "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP");
        }

        for unsafe_path in [
            "/tmp/outside-state.json",
            "../outside-state.json",
            "",
            ".",
            "C:\\outside\\state.json",
        ] {
            let mut manifest = baseline.clone();
            manifest.state.files[0].path = unsafe_path.to_owned();
            fixture.write_signed_manifest(manifest);
            let err = prepare_restore(&fixture.options()).expect_err("unsafe inventory rejected");
            assert_eq!(err.code, "ORACLEMCP_SERVICE_RESTORE_UNSAFE_PATH");
        }
    }

    #[test]
    fn restore_ignores_manifest_source_paths_and_writes_only_explicit_targets() {
        let fixture = restore_fixture("explicit-destinations");
        let victim = fixture.root.join("victim-do-not-touch.log");
        fs::write(&victim, b"sentinel\n").expect("victim sentinel");
        let mut manifest = fixture.manifest();
        manifest.state.source_path = victim.display().to_string();
        manifest.config.source_path = victim.display().to_string();
        manifest.audit.source_path = victim.display().to_string();
        manifest.audit_anchor.source_path = victim.display().to_string();
        fixture.write_signed_manifest(manifest);

        let mut prepared = prepare_restore(&fixture.options()).expect("safe explicit restore");
        prepared.apply().expect("apply explicit restore");
        assert_eq!(fs::read(&victim).expect("victim remains"), b"sentinel\n");
        assert_eq!(
            fs::read(fixture.state_target.join("metrics/snapshot.json"))
                .expect("explicit state target"),
            b"fixture-state\n"
        );
        assert_eq!(
            fs::read(&fixture.config_target).expect("explicit config target"),
            b"schema_version = 2\nfixture = true\n"
        );
        assert!(
            fs::read_to_string(&fixture.audit_target)
                .expect("explicit audit target")
                .contains("oracle_execute")
        );
        assert!(oraclemcp_audit::anchor_path_for(&fixture.audit_target).is_file());
    }

    #[test]
    fn restore_rejects_manifest_payload_and_inventory_tampering_before_any_write() {
        for (name, relative) in [
            ("tampered-state", "state/metrics/snapshot.json"),
            ("tampered-config", "config/profiles.toml"),
            ("tampered-audit", "audit/audit.jsonl"),
            ("tampered-anchor", "audit/audit.jsonl.anchor"),
        ] {
            let fixture = restore_fixture(name);
            fs::write(fixture.backup.join(relative), b"tampered\n").expect("tamper payload");
            let err = prepare_restore(&fixture.options()).expect_err("tampered payload rejected");
            assert_eq!(err.code, "ORACLEMCP_SERVICE_RESTORE_PAYLOAD_MISMATCH");
            assert!(!fixture.state_target.exists());
            assert!(!fixture.config_target.exists());
            assert!(!fixture.audit_target.exists());
        }

        let count_fixture = restore_fixture("tampered-counts");
        let mut manifest = count_fixture.manifest();
        manifest.state.file_count += 1;
        manifest.state.bytes += 1;
        count_fixture.write_signed_manifest(manifest);
        let err = prepare_restore(&count_fixture.options()).expect_err("bad counts rejected");
        assert_eq!(err.code, "ORACLEMCP_SERVICE_RESTORE_INVENTORY_MISMATCH");
        assert!(!count_fixture.state_target.exists());

        let extra_fixture = restore_fixture("unexpected-state-file");
        fs::write(
            extra_fixture.backup.join("state/unexpected.json"),
            b"unexpected\n",
        )
        .expect("unexpected state file");
        let err = prepare_restore(&extra_fixture.options()).expect_err("extra file rejected");
        assert_eq!(err.code, "ORACLEMCP_SERVICE_RESTORE_INVENTORY_MISMATCH");
        assert!(!extra_fixture.state_target.exists());

        let missing_fixture = restore_fixture("missing-state-file");
        fs::rename(
            missing_fixture.backup.join("state/metrics/snapshot.json"),
            missing_fixture.backup.join("missing-snapshot.saved"),
        )
        .expect("move expected state file out of inventory");
        let err = prepare_restore(&missing_fixture.options()).expect_err("missing file rejected");
        assert_eq!(err.code, "ORACLEMCP_SERVICE_RESTORE_INVENTORY_MISMATCH");
        assert!(!missing_fixture.state_target.exists());
    }

    #[test]
    fn restore_rejects_unsigned_manifest_edits_and_empty_unanchored_audit() {
        let signature_fixture = restore_fixture("manifest-signature");
        let manifest_path = signature_fixture.backup.join(BACKUP_MANIFEST_FILE);
        let mut manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&manifest_path).expect("manifest body"))
                .expect("manifest json");
        manifest["created_unix_ms"] = serde_json::json!(0);
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).expect("edited manifest json"),
        )
        .expect("edit without signing");
        let err = prepare_restore(&signature_fixture.options())
            .expect_err("unauthenticated manifest edit rejected");
        assert_eq!(err.code, "ORACLEMCP_SERVICE_RESTORE_MANIFEST_BROKEN");

        let empty_fixture = restore_fixture("empty-unanchored-audit");
        fs::write(empty_fixture.backup.join("audit/audit.jsonl"), b"")
            .expect("empty audit payload");
        let mut manifest = empty_fixture.manifest();
        manifest.audit.bytes = Some(0);
        manifest.audit.sha256 = Some(sha256_hex(b""));
        manifest.audit_anchor = BackupFileManifest {
            present: false,
            source_path: "attacker-omitted-anchor".to_owned(),
            backup_path: None,
            sha256: None,
            bytes: None,
        };
        empty_fixture.write_signed_manifest(manifest);
        let err = prepare_restore(&empty_fixture.options())
            .expect_err("empty audit without anchor rejected");
        assert_eq!(err.code, "ORACLEMCP_SERVICE_RESTORE_AUDIT_UNVERIFIABLE");
        assert!(!empty_fixture.audit_target.exists());

        let empty_anchored_fixture = restore_fixture("empty-anchored-audit");
        fs::write(empty_anchored_fixture.backup.join("audit/audit.jsonl"), b"")
            .expect("empty anchored audit payload");
        let mut manifest = empty_anchored_fixture.manifest();
        manifest.audit.bytes = Some(0);
        manifest.audit.sha256 = Some(sha256_hex(b""));
        empty_anchored_fixture.write_signed_manifest(manifest);
        let err = prepare_restore(&empty_anchored_fixture.options())
            .expect_err("even an anchored empty log is not authenticated evidence");
        assert_eq!(err.code, "ORACLEMCP_SERVICE_RESTORE_AUDIT_UNVERIFIABLE");
    }

    #[test]
    fn backup_refuses_live_service_owner_without_creating_partial_output() {
        let root = test_root("backup-live-owner");
        let state = root.join("state");
        let output = root.join("backup");
        let store = FileStore::open(&state).expect("state store");
        let _owner = store
            .acquire_service_owner("serve")
            .expect("live service owner");
        let key = SigningKey::new("default", b"qa1-offline-backup-key-0123456789".to_vec())
            .expect("valid key");

        let error = run_service_command_with(
            ServiceCommand::Backup(ServiceBackupOptions {
                name: "oraclemcp".to_owned(),
                state_dir: state,
                config_path: root.join("config/profiles.toml"),
                audit_path: root.join("audit/audit.jsonl"),
                manifest_signing_key: key,
                output: Some(output.clone()),
                yes: true,
                dry_run: false,
            }),
            ServiceManager::SystemdUser,
            &exe(),
        )
        .expect_err("online backup must fail closed");

        assert_eq!(error.code, "ORACLEMCP_SERVICE_BACKUP_ACTIVE_OWNER");
        assert!(error.message.contains("stop the service"));
        assert!(!output.exists(), "refusal must precede output creation");
    }

    #[test]
    fn backup_refuses_an_audit_log_without_its_signed_head_anchor() {
        let root = test_root("backup-unanchored-audit");
        let state = root.join("state");
        let config = root.join("config/profiles.toml");
        let audit = root.join("audit/audit.jsonl");
        fs::create_dir_all(&state).expect("state dir");
        fs::create_dir_all(config.parent().expect("config parent")).expect("config dir");
        fs::create_dir_all(audit.parent().expect("audit parent")).expect("audit dir");
        fs::write(&config, b"schema_version = 2\n").expect("config");
        fs::write(&audit, b"present but deliberately unanchored\n").expect("audit");
        let key = SigningKey::new("default", b"qa4-unanchored-backup-key-0123456789".to_vec())
            .expect("valid key");
        let err = run_service_command_with(
            ServiceCommand::Backup(ServiceBackupOptions {
                name: "oraclemcp".to_owned(),
                state_dir: state,
                config_path: config,
                audit_path: audit,
                manifest_signing_key: key,
                output: Some(root.join("backup")),
                yes: true,
                dry_run: false,
            }),
            ServiceManager::SystemdUser,
            &exe(),
        )
        .expect_err("unanchored audit backup rejected");
        assert_eq!(err.code, "ORACLEMCP_SERVICE_BACKUP_AUDIT_ANCHOR_REQUIRED");
    }

    #[cfg(unix)]
    #[test]
    fn restore_capabilities_reject_symlinks_and_freeze_hardlink_and_rename_swaps() {
        use std::os::unix::fs::symlink;

        let symlink_fixture = restore_fixture("source-symlink");
        let config_source = symlink_fixture.backup.join("config/profiles.toml");
        let saved_config = symlink_fixture.root.join("saved-config.toml");
        fs::rename(&config_source, &saved_config).expect("move config before symlink");
        symlink(&saved_config, &config_source).expect("source symlink");
        let err = prepare_restore(&symlink_fixture.options()).expect_err("symlink rejected");
        assert_eq!(err.code, "ORACLEMCP_SERVICE_RESTORE_UNSAFE_PATH");

        let root_symlink_fixture = restore_fixture("source-root-symlink");
        let backup_alias = root_symlink_fixture.root.join("backup-alias");
        symlink(&root_symlink_fixture.backup, &backup_alias).expect("backup root symlink");
        let mut aliased_options = root_symlink_fixture.options();
        aliased_options.backup = backup_alias;
        let err = prepare_restore(&aliased_options).expect_err("backup root symlink rejected");
        assert_eq!(err.code, "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP");

        let hardlink_fixture = restore_fixture("source-hardlink");
        let config_source = hardlink_fixture.backup.join("config/profiles.toml");
        let outside_link = hardlink_fixture.root.join("outside-hardlink.toml");
        fs::rename(&config_source, &outside_link).expect("move config to outside name");
        fs::hard_link(&outside_link, &config_source).expect("hard-link config into bundle");
        let mut prepared = prepare_restore(&hardlink_fixture.options())
            .expect("hard link is staged by value through its capability");
        fs::write(&outside_link, b"mutated through external hard link\n")
            .expect("mutate hard-linked inode after preflight");
        prepared.apply().expect("apply frozen hard-link snapshot");
        assert_eq!(
            fs::read(&hardlink_fixture.config_target).expect("restored config"),
            b"schema_version = 2\nfixture = true\n"
        );

        let rename_fixture = restore_fixture("source-rename-swap");
        let mut prepared = prepare_restore(&rename_fixture.options()).expect("prepare snapshot");
        let config_source = rename_fixture.backup.join("config/profiles.toml");
        fs::rename(
            &config_source,
            rename_fixture.root.join("authenticated-config.saved"),
        )
        .expect("move authenticated source");
        fs::write(&config_source, b"attacker replacement\n").expect("rename-swap replacement");
        prepared.apply().expect("apply frozen rename-swap snapshot");
        assert_eq!(
            fs::read(&rename_fixture.config_target).expect("restored config"),
            b"schema_version = 2\nfixture = true\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn restore_destination_traversal_rejects_symlink_swap_without_touching_victim() {
        use std::os::unix::fs::symlink;

        let fixture = restore_fixture("destination-symlink-swap");
        let mut prepared = prepare_restore(&fixture.options()).expect("prepare restore");
        let victim = fixture.root.join("victim-directory");
        fs::create_dir_all(&victim).expect("victim directory");
        fs::write(victim.join("snapshot.json"), b"victim-sentinel\n").expect("victim sentinel");
        fs::create_dir_all(fixture.state_target.parent().expect("state target parent"))
            .expect("restore parent");
        symlink(&victim, &fixture.state_target).expect("destination symlink swap");
        let err = prepared.apply().expect_err("destination symlink rejected");
        assert_eq!(err.code, "ORACLEMCP_SERVICE_RESTORE_UNSAFE_PATH");
        assert_eq!(
            fs::read(victim.join("snapshot.json")).expect("victim unchanged"),
            b"victim-sentinel\n"
        );

        let rename_fixture = restore_fixture("destination-rename-swap");
        let target = prepare_target(&rename_fixture.state_target, true).expect("target capability");
        let held =
            open_or_create_dir_chain(&target.root, &target.relative_path, &target.display_path)
                .expect("held target directory");
        fs::rename(
            &rename_fixture.state_target,
            rename_fixture.root.join("renamed-state-target"),
        )
        .expect("rename held destination");
        fs::create_dir_all(&rename_fixture.state_target).expect("replacement destination");
        let current = open_dir_chain_nofollow(&target.root, &target.relative_path)
            .expect("current replacement capability");
        assert!(
            !same_capability_identity(&held, &current).expect("compare directory identity"),
            "post-write identity check must detect a renamed-and-replaced destination"
        );
    }

    #[test]
    fn invalid_service_name_rejects_path_traversal() {
        let err = run_service_command_with(
            ServiceCommand::Restart(ServiceMutationOptions {
                name: "../oraclemcp".to_owned(),
                yes: false,
                dry_run: true,
            }),
            ServiceManager::SystemdUser,
            &exe(),
        )
        .expect_err("path traversal rejected");
        assert_eq!(err.code, "ORACLEMCP_SERVICE_INVALID_NAME");
    }

    #[test]
    fn service_instance_guard_refuses_second_instance_and_reports_discovery() {
        let path = test_root("service-instance").join("service-instance.json");
        let first =
            acquire_service_instance_guard_at(&path, "127.0.0.1:7070").expect("first guard");

        let discovery = discover_service_instance_at(&path);
        let ServiceInstanceDiscovery::Present { pid, listen, .. } = discovery else {
            panic!("expected present discovery");
        };
        assert_eq!(pid, std::process::id());
        assert_eq!(listen, "127.0.0.1:7070");

        let err = acquire_service_instance_guard_at(&path, "127.0.0.1:7071")
            .expect_err("second guard is refused");
        assert_eq!(err.code, "ORACLEMCP_SERVICE_ALREADY_RUNNING");
        assert_eq!(err.exit_code, 3);
        assert!(err.message.contains("refusing to start a second instance"));
        assert!(err.message.contains("pid="));
        assert!(err.message.contains("127.0.0.1:7070"));

        drop(first);
        assert!(matches!(
            discover_service_instance_at(&path),
            ServiceInstanceDiscovery::Missing { .. }
        ));
    }

    #[test]
    fn service_instance_guard_drop_does_not_clear_replaced_lock() {
        let path = test_root("service-instance-replaced").join("service-instance.json");
        let first =
            acquire_service_instance_guard_at(&path, "127.0.0.1:7070").expect("first guard");
        fs::remove_file(&path).expect("simulate operator-cleared stale lock");
        let second =
            acquire_service_instance_guard_at(&path, "127.0.0.1:7071").expect("second guard");

        drop(first);
        let discovery = discover_service_instance_at(&path);
        let ServiceInstanceDiscovery::Present { listen, .. } = discovery else {
            panic!("replacement lock must remain present");
        };
        assert_eq!(listen, "127.0.0.1:7071");

        drop(second);
    }

    #[test]
    fn service_instance_guard_clears_stale_lock_when_recorded_pid_is_dead() {
        let path = test_root("service-instance-stale-dead-pid").join("service-instance.json");
        let stale_pid = 4_194_304_u32;
        assert!(
            !service_instance_pid_is_alive(stale_pid),
            "test requires a non-running pid for stale-lock simulation"
        );
        let stale = ServiceInstanceMetadata {
            schema_version: SERVICE_INSTANCE_SCHEMA_VERSION,
            pid: stale_pid,
            listen: "127.0.0.1:7070".to_owned(),
            started_unix_ms: 1,
            token: "stale-token".to_owned(),
        };
        fs::create_dir_all(path.parent().expect("lock parent")).expect("runtime dir");
        fs::write(
            &path,
            serde_json::to_vec(&stale).expect("serialize stale lock"),
        )
        .expect("write stale lock");

        let guard = acquire_service_instance_guard_at(&path, "127.0.0.1:7071")
            .expect("stale lock should be cleared and replaced");
        let discovery = discover_service_instance_at(&path);
        let ServiceInstanceDiscovery::Present { pid, listen, .. } = discovery else {
            panic!("replacement lock must be present after stale clear");
        };
        assert_eq!(listen, "127.0.0.1:7071");
        assert_eq!(pid, std::process::id());
        drop(guard);
    }

    #[test]
    fn launchd_plan_uses_plist_and_bootstrap() {
        let result = run_service_command_with(
            ServiceCommand::Install(ServiceInstallOptions {
                name: "oraclemcp".to_owned(),
                listen: "127.0.0.1:7070".to_owned(),
                profile: None,
                allow_no_auth: false,
                client_credentials: false,
                skip_linger: true,
                yes: false,
                dry_run: true,
            }),
            ServiceManager::LaunchdUser,
            &exe(),
        )
        .expect("dry-run plan");
        let payload = result.payload.to_string();
        assert!(payload.contains("io.github.MuhDur.oraclemcp.plist"));
        assert!(payload.contains("bootstrap"));
        let steps = result.payload["steps"].as_array().expect("steps array");
        let plist = steps
            .iter()
            .find_map(|step| step["content"].as_str())
            .expect("launchd plist content");
        assert!(plist.contains("<key>SoftResourceLimits</key>"));
        assert!(plist.contains("<key>NumberOfFiles</key>"));
        assert!(plist.contains("<integer>65536</integer>"));
        assert!(plist.contains("<key>NumberOfProcesses</key>"));
        assert!(
            result.payload["hardening"]["configured"]["restart_policy"]
                .as_str()
                .unwrap()
                .contains("KeepAlive")
        );
    }

    #[test]
    fn windows_plan_uses_sc_create_without_postinstall_side_effects_in_dry_run() {
        let result = run_service_command_with(
            ServiceCommand::Install(ServiceInstallOptions {
                name: "oraclemcp".to_owned(),
                listen: "127.0.0.1:7070".to_owned(),
                profile: None,
                allow_no_auth: false,
                client_credentials: false,
                skip_linger: true,
                yes: false,
                dry_run: true,
            }),
            ServiceManager::WindowsService,
            &exe(),
        )
        .expect("dry-run plan");
        let payload = result.payload.to_string();
        assert!(payload.contains("sc.exe"));
        assert!(payload.contains("create"));
        assert!(payload.contains("binPath="));
        assert!(payload.contains("failure"));
        assert!(payload.contains("restart/5000"));
        assert!(
            result.payload["hardening"]["configured"]["restart_policy"]
                .as_str()
                .unwrap()
                .contains("restart/5000")
        );
    }

    #[test]
    fn doctor_service_unit_caps_reports_configured_and_effective_limits() {
        let caps = doctor_service_unit_caps().expect("supported service manager");
        assert!(matches!(
            caps.manager.as_str(),
            "systemd_user" | "launchd_user" | "windows_service"
        ));
        match caps.manager.as_str() {
            "systemd_user" => {
                assert_eq!(
                    caps.configured.notify.as_deref(),
                    Some("type=notify notify_access=main")
                );
                assert_eq!(caps.configured.limit_nofile, Some(SERVICE_LIMIT_NOFILE));
                assert_eq!(caps.configured.tasks_max, Some(SERVICE_TASKS_MAX));
                assert_eq!(
                    caps.configured.memory_max_bytes,
                    Some(SERVICE_MEMORY_MAX_BYTES)
                );
                assert_eq!(
                    caps.configured.oom_score_adjust,
                    Some(SERVICE_OOM_SCORE_ADJUST)
                );
            }
            "launchd_user" => {
                assert_eq!(caps.configured.limit_nofile, Some(SERVICE_LIMIT_NOFILE));
                assert_eq!(caps.configured.tasks_max, Some(SERVICE_TASKS_MAX));
            }
            "windows_service" => {
                assert!(
                    caps.configured
                        .restart_policy
                        .as_deref()
                        .unwrap_or_default()
                        .contains("restart/5000")
                );
            }
            _ => unreachable!(),
        }
        #[cfg(target_os = "linux")]
        assert!(
            caps.effective.limit_nofile.is_some()
                || caps.effective.tasks_max.is_some()
                || caps.effective.memory_max_bytes.is_some()
                || caps.effective.oom_score_adjust.is_some()
        );
    }
}
