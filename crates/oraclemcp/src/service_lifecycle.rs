use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

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
    pub(crate) steps: Vec<ServiceStep>,
    pub(crate) next_actions: Vec<String>,
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
        "exit_code": exit_code,
    });
    let text = if active {
        format!("oraclemcp service `{name}` is active")
    } else {
        format!(
            "oraclemcp service `{name}` is not active; run `oraclemcp service logs` or `oraclemcp service install --dry-run`"
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
         Type=simple\n\
         ExecStart={exec}\n\
         Restart=on-failure\n\
         RestartSec=3\n\
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
         </dict>\n\
         </plist>\n",
        xml_escape(label),
        args
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

#[cfg(test)]
mod tests {
    use super::*;

    fn exe() -> PathBuf {
        PathBuf::from("/opt/oraclemcp/bin/oraclemcp")
    }

    #[test]
    fn install_requires_yes_or_dry_run() {
        let err = run_service_command_with(
            ServiceCommand::Install(ServiceInstallOptions {
                name: "oraclemcp".to_owned(),
                listen: "127.0.0.1:7070".to_owned(),
                profile: None,
                allow_no_auth: false,
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
                allow_no_auth: true,
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
        let steps = result.payload["steps"].as_array().expect("steps array");
        assert!(steps.iter().any(|step| {
            step["program"] == "systemctl"
                && step["args"]
                    == serde_json::json!(["--user", "enable", "--now", "oraclemcp.service"])
        }));
        assert!(steps.iter().any(|step| step["program"] == "loginctl"));
        assert!(
            result
                .text
                .contains("serve --listen 127.0.0.1:7070 --allow-no-auth --profile dev_ro"),
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
    fn launchd_plan_uses_plist_and_bootstrap() {
        let result = run_service_command_with(
            ServiceCommand::Install(ServiceInstallOptions {
                name: "oraclemcp".to_owned(),
                listen: "127.0.0.1:7070".to_owned(),
                profile: None,
                allow_no_auth: false,
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
    }

    #[test]
    fn windows_plan_uses_sc_create_without_postinstall_side_effects_in_dry_run() {
        let result = run_service_command_with(
            ServiceCommand::Install(ServiceInstallOptions {
                name: "oraclemcp".to_owned(),
                listen: "127.0.0.1:7070".to_owned(),
                profile: None,
                allow_no_auth: false,
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
    }
}
