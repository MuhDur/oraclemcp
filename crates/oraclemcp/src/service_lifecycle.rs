use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use oraclemcp_core::{DoctorServiceUnitCaps, DoctorServiceUnitLimitCaps};
use serde::{Deserialize, Serialize};

const SERVICE_LIMIT_NOFILE: u64 = 65_536;
const SERVICE_TASKS_MAX: u64 = 512;
const SERVICE_MEMORY_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const SERVICE_MEMORY_MAX_SYSTEMD: &str = "2G";
const SERVICE_OOM_SCORE_ADJUST: i16 = 100;
const SERVICE_INSTANCE_LOCK_FILE: &str = "service-instance.json";
const SERVICE_INSTANCE_SCHEMA_VERSION: u8 = 1;

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
pub(crate) enum ServiceCommand {
    Install(ServiceInstallOptions),
    Uninstall(ServiceMutationOptions),
    Restart(ServiceMutationOptions),
    Status(ServiceReadOptions),
    Logs(ServiceLogsOptions),
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ServiceResult {
    pub(crate) exit_code: u8,
    pub(crate) payload: serde_json::Value,
    pub(crate) text: String,
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
