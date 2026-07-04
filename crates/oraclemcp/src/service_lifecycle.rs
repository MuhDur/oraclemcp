use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use oraclemcp_audit::{SigningKey, VerifyOutcome, parse_jsonl, sha256_hex, verify_records};
use oraclemcp_core::{DoctorServiceUnitCaps, DoctorServiceUnitLimitCaps, FileStore};
use serde::{Deserialize, Serialize};

const SERVICE_LIMIT_NOFILE: u64 = 65_536;
const SERVICE_TASKS_MAX: u64 = 512;
const SERVICE_MEMORY_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const SERVICE_MEMORY_MAX_SYSTEMD: &str = "2G";
const SERVICE_OOM_SCORE_ADJUST: i16 = 100;
const SERVICE_INSTANCE_LOCK_FILE: &str = "service-instance.json";
const SERVICE_INSTANCE_SCHEMA_VERSION: u8 = 1;
const SERVICE_STATE_LOCK_FILE: &str = ".service.lock";
const BACKUP_MANIFEST_FILE: &str = "manifest.json";
const BACKUP_SCHEMA_VERSION: u32 = 1;
const BACKUP_KIND: &str = "oraclemcp_service_backup";

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
    pub(crate) output: Option<PathBuf>,
    pub(crate) yes: bool,
    pub(crate) dry_run: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ServiceRestoreOptions {
    pub(crate) name: String,
    pub(crate) state_dir: PathBuf,
    pub(crate) config_path: PathBuf,
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
struct BackupFileManifest {
    present: bool,
    source_path: String,
    backup_path: Option<String>,
    sha256: Option<String>,
    bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupTreeManifest {
    source_path: String,
    backup_path: String,
    file_count: usize,
    bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupManifest {
    schema_version: u32,
    kind: String,
    service_name: String,
    created_unix_ms: u64,
    state: BackupTreeManifest,
    config: BackupFileManifest,
    audit: BackupFileManifest,
    service_lock_held: bool,
    transient_files_skipped: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum RestoreAuditVerification {
    Verified { records: usize, file: String },
    NoAuditLog,
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
        let lock = store
            .acquire_service_lock("service-backup")
            .map_err(service_store_error)?;
        create_new_private_dir(&output)?;
        let state_target = output.join("state");
        let mut state = copy_dir_snapshot(store.root(), &state_target)?;
        state.backup_path = "state".to_owned();
        let mut config = copy_optional_file(
            &options.config_path,
            &output.join("config").join("profiles.toml"),
        )?;
        relativize_file_manifest(&mut config, &output);
        let mut audit = copy_audit_for_backup(&options.audit_path, store.root(), &output)?;
        relativize_file_manifest(&mut audit, &output);
        let manifest = BackupManifest {
            schema_version: BACKUP_SCHEMA_VERSION,
            kind: BACKUP_KIND.to_owned(),
            service_name: options.name.clone(),
            created_unix_ms: current_unix_millis(),
            state,
            config,
            audit,
            service_lock_held: true,
            transient_files_skipped: vec![SERVICE_STATE_LOCK_FILE.to_owned()],
        };
        write_manifest(&output, &manifest)?;
        drop(lock);
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
    let manifest = read_manifest(&options.backup)?;
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

    let audit_verification = verify_backup_audit(&options.backup, &manifest, &options.audit_keys)?;
    let stop = stop_step(manager, &options.name)?;
    let start = start_step(manager, &options.name)?;

    if !options.dry_run {
        execute_steps(std::slice::from_ref(&stop))?;
        restore_from_manifest(&options.backup, &options, &manifest)?;
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
        "audit_verification": audit_verification,
        "steps": [stop, start],
    });
    let text = if options.dry_run {
        format!(
            "oraclemcp service restore\nmanager: {}\nservice: {}\nmode: dry-run (no changes made)\nbackup dir: {}\naudit: verified before restore\n",
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
        }
    };
    let mut config = file_manifest_for(&options.config_path, &output.join("config/profiles.toml"))?;
    relativize_file_manifest(&mut config, output);
    let mut audit = file_manifest_for(&options.audit_path, &output.join("audit/audit.jsonl"))?;
    relativize_file_manifest(&mut audit, output);
    Ok(BackupManifest {
        schema_version: BACKUP_SCHEMA_VERSION,
        kind: BACKUP_KIND.to_owned(),
        service_name: options.name.clone(),
        created_unix_ms: current_unix_millis(),
        state,
        config,
        audit,
        service_lock_held,
        transient_files_skipped: vec![SERVICE_STATE_LOCK_FILE.to_owned()],
    })
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

fn copy_audit_for_backup(
    audit_path: &Path,
    state_root: &Path,
    output: &Path,
) -> Result<BackupFileManifest, ServiceError> {
    let audit_compare = audit_path
        .canonicalize()
        .unwrap_or_else(|_| audit_path.to_path_buf());
    let state_compare = state_root
        .canonicalize()
        .unwrap_or_else(|_| state_root.to_path_buf());
    if audit_compare.starts_with(&state_compare) {
        let relative = audit_compare.strip_prefix(&state_compare).map_err(|e| {
            ServiceError::new(
                "ORACLEMCP_SERVICE_BACKUP_AUDIT_PATH_INVALID",
                format!(
                    "failed to relativize audit path {}: {e}",
                    audit_path.display()
                ),
                2,
            )
        })?;
        return file_manifest_for(audit_path, &output.join("state").join(relative));
    }
    // Outside the state dir the audit log is copied explicitly; bring the head
    // anchor sidecar (bead oraclemcp-xb51) along so a restored log still
    // carries its tail-truncation evidence. (Inside the state dir the whole-dir
    // snapshot already copies the sidecar.)
    let anchor_source = oraclemcp_audit::anchor_path_for(audit_path);
    if anchor_source.exists() {
        copy_regular_file(
            &anchor_source,
            &output.join("audit").join("audit.jsonl.anchor"),
        )?;
    }
    copy_optional_file(audit_path, &output.join("audit").join("audit.jsonl"))
}

fn copy_dir_snapshot(source: &Path, target: &Path) -> Result<BackupTreeManifest, ServiceError> {
    let mut manifest = BackupTreeManifest {
        source_path: source.display().to_string(),
        backup_path: target.display().to_string(),
        file_count: 0,
        bytes: 0,
    };
    copy_dir_snapshot_inner(source, target, &mut manifest)?;
    Ok(manifest)
}

fn copy_dir_snapshot_inner(
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
            copy_dir_snapshot_inner(&source_path, &target_path, manifest)?;
        } else if metadata.is_file() {
            copy_regular_file(&source_path, &target_path)?;
            manifest.file_count += 1;
            manifest.bytes += metadata.len();
        }
    }
    sync_dir(target)
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_BACKUP_SYNC_FAILED", target, e))
}

fn restore_from_manifest(
    backup: &Path,
    options: &ServiceRestoreOptions,
    manifest: &BackupManifest,
) -> Result<(), ServiceError> {
    let state_source = backup.join("state");
    if !state_source.exists() {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
            format!(
                "backup state directory is missing: {}",
                state_source.display()
            ),
            2,
        ));
    }
    copy_dir_restore(&state_source, &options.state_dir)?;

    if manifest.config.present {
        let source = manifest_backup_path(backup, &manifest.config)?;
        copy_regular_file(&source, &options.config_path)?;
    }
    if manifest.audit.present
        && !Path::new(&manifest.audit.source_path).starts_with(&options.state_dir)
    {
        let source = manifest_backup_path(backup, &manifest.audit)?;
        copy_regular_file(&source, Path::new(&manifest.audit.source_path))?;
        // Restore the head anchor sidecar next to the audit log when the
        // backup carried one (bead oraclemcp-xb51).
        let anchor_source = oraclemcp_audit::anchor_path_for(&source);
        if anchor_source.exists() {
            copy_regular_file(
                &anchor_source,
                &oraclemcp_audit::anchor_path_for(Path::new(&manifest.audit.source_path)),
            )?;
        }
    }
    Ok(())
}

fn copy_dir_restore(source: &Path, target: &Path) -> Result<(), ServiceError> {
    let mut ignored = BackupTreeManifest {
        source_path: source.display().to_string(),
        backup_path: target.display().to_string(),
        file_count: 0,
        bytes: 0,
    };
    copy_dir_snapshot_inner(source, target, &mut ignored)
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
    };
    if !source.exists() {
        return Ok(manifest);
    }
    accumulate_tree_manifest(source, &mut manifest)?;
    Ok(manifest)
}

fn accumulate_tree_manifest(
    source: &Path,
    manifest: &mut BackupTreeManifest,
) -> Result<(), ServiceError> {
    ensure_source_dir_safe(source)?;
    for entry in fs::read_dir(source)
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_BACKUP_READ_FAILED", source, e))?
    {
        let entry = entry
            .map_err(|e| service_io_error("ORACLEMCP_SERVICE_BACKUP_READ_FAILED", source, e))?;
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
            accumulate_tree_manifest(&path, manifest)?;
        } else if metadata.is_file() {
            manifest.file_count += 1;
            manifest.bytes += metadata.len();
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

fn read_manifest(backup: &Path) -> Result<BackupManifest, ServiceError> {
    let path = backup.join(BACKUP_MANIFEST_FILE);
    let body = fs::read_to_string(&path)
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP", &path, e))?;
    serde_json::from_str(&body).map_err(|e| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
            format!("backup manifest {} is invalid: {e}", path.display()),
            2,
        )
    })
}

fn verify_backup_audit(
    backup: &Path,
    manifest: &BackupManifest,
    keys: &[SigningKey],
) -> Result<RestoreAuditVerification, ServiceError> {
    if !manifest.audit.present {
        return Ok(RestoreAuditVerification::NoAuditLog);
    }
    let path = manifest_backup_path(backup, &manifest.audit)?;
    let body = fs::read_to_string(&path)
        .map_err(|e| service_io_error("ORACLEMCP_SERVICE_RESTORE_AUDIT_READ_FAILED", &path, e))?;
    let records = parse_jsonl(&body).map_err(|e| {
        ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_AUDIT_MALFORMED",
            format!("backup audit log {} is malformed: {e}", path.display()),
            2,
        )
    })?;
    match verify_records(&records, keys) {
        VerifyOutcome::Ok {
            records: record_count,
        } => {
            // Cross-check the head anchor sidecar when the backup carries one
            // (bead oraclemcp-xb51): a truncated backup must not restore as
            // "verified". Absent sidecar keeps the legacy behavior.
            let anchor_path = oraclemcp_audit::anchor_path_for(&path);
            match oraclemcp_audit::load_anchor(&anchor_path) {
                Ok(None) => {}
                Ok(Some(anchor)) => {
                    if let Err(violation) = oraclemcp_audit::check_anchor(&records, &anchor, keys) {
                        return Err(ServiceError::new(
                            "ORACLEMCP_SERVICE_RESTORE_AUDIT_BROKEN",
                            format!(
                                "backup audit chain {} failed the head-anchor check: {violation}",
                                path.display()
                            ),
                            2,
                        ));
                    }
                }
                Err(e) => {
                    return Err(ServiceError::new(
                        "ORACLEMCP_SERVICE_RESTORE_AUDIT_BROKEN",
                        format!("backup audit head anchor is unreadable: {e}"),
                        2,
                    ));
                }
            }
            Ok(RestoreAuditVerification::Verified {
                records: record_count,
                file: path.display().to_string(),
            })
        }
        VerifyOutcome::Broken { seq, index, reason } => Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_AUDIT_BROKEN",
            format!(
                "backup audit chain {} failed at seq {seq} record #{index}: {reason}",
                path.display()
            ),
            2,
        )),
        _ => Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_AUDIT_UNVERIFIABLE",
            "unrecognized audit verification outcome",
            2,
        )),
    }
}

fn manifest_backup_path(backup: &Path, file: &BackupFileManifest) -> Result<PathBuf, ServiceError> {
    let Some(path) = file.backup_path.as_deref() else {
        return Err(ServiceError::new(
            "ORACLEMCP_SERVICE_RESTORE_INVALID_BACKUP",
            "backup manifest file entry is present but has no backup path",
            2,
        ));
    };
    let path = PathBuf::from(path);
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(backup.join(path))
    }
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

    let mut file = match create_new_private_file(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(ServiceError::new(
                "ORACLEMCP_SERVICE_ALREADY_RUNNING",
                format!(
                    "another oraclemcp service instance is already registered; refusing to \
                     start a second instance ({}). This prevents silent takeover of a different \
                     port or socket; inspect service status/logs before clearing a stale lock.",
                    render_instance_discovery(&discover_service_instance_at(path))
                ),
                3,
            ));
        }
        Err(e) => {
            return Err(ServiceError::new(
                "ORACLEMCP_SERVICE_LOCK_UNAVAILABLE",
                format!(
                    "failed to create service instance lock {}: {e}",
                    path.display()
                ),
                3,
            ));
        }
    };

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
            .join("../../target/service-lifecycle-tests")
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
        let key = SigningKey::new("default", b"backup-restore-test-key".to_vec());

        fs::create_dir_all(audit_path.parent().expect("audit parent")).expect("audit dir");
        fs::create_dir_all(config_path.parent().expect("config parent")).expect("config dir");
        fs::create_dir_all(state_dir.join("metrics")).expect("metrics dir");
        fs::write(&audit_path, signed_audit_jsonl(&key)).expect("seed audit chain");
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

        let manifest = read_manifest(&backup_dir).expect("manifest");
        restore_from_manifest(
            &backup_dir,
            &ServiceRestoreOptions {
                name: "oraclemcp".to_owned(),
                state_dir: state_dir.clone(),
                config_path: config_path.clone(),
                backup: backup_dir.clone(),
                audit_keys: vec![key.clone()],
                yes: true,
                dry_run: false,
            },
            &manifest,
        )
        .expect("restore copies manifest files");
        assert_eq!(
            fs::read(state_dir.join("metrics").join("snapshot.json")).expect("restored state"),
            b"{\"ok\":true}\n"
        );
        assert!(
            fs::read_to_string(&config_path)
                .expect("restored config")
                .contains("name = \"prod\"")
        );

        let backup_audit = backup_dir.join("state").join("audit").join("audit.jsonl");
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
                backup: backup_dir,
                audit_keys: vec![key],
                yes: false,
                dry_run: true,
            }),
            ServiceManager::SystemdUser,
            &exe(),
        )
        .expect_err("tampered audit refuses restore");
        assert_eq!(err.code, "ORACLEMCP_SERVICE_RESTORE_AUDIT_BROKEN");
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
