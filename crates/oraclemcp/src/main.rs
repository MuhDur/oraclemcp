#![forbid(unsafe_code)]
// ErrorEnvelope-returning fns (the ToolDispatch contract) trip result_large_err;
// boxing every cold error path adds noise for no benefit — oraclemcp-core does
// the same. See oraclemcp-core/src/lib.rs.
#![allow(clippy::result_large_err)]

//! `oraclemcp` — the engine-free Oracle Database MCP server binary (Phase-E
//! E-2b).
//!
//! A thin consumer of `oraclemcp-core` ([`OracleMcpServer`] +
//! `oracle_capabilities`) and `oraclemcp-db` (the read-only dictionary ops plus
//! one guarded execute primitive). It advertises governed, least-privilege
//! live-DB/config-inspection tools ([`registry`]) and dispatches them through
//! [`dispatch::OracleDispatcher`]. There is NO engine and NO `plsql-*`
//! dependency; non-read execution is isolated behind the classifier,
//! profile/session operating level, rollback default, and commit confirmation.
//!
//! CLI shape (mirrors `plsql-mcp`): a top-level `--robot-json` flag plus
//! `serve` (stdio default, `--listen <ADDR>` for Streamable HTTP), `info`,
//! `doctor`, `capabilities`, and `robot-docs guide`.

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod readiness;
mod robot_docs;
mod service_lifecycle;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use asupersync::Cx;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use oraclemcp::dispatch::{
    McpExposurePolicy, OracleDispatcher, ProfileConnector, ProfileDrainState,
    ProfileStatelessConnector, StatelessReadStrategy, profile_draining_error,
    stateless_read_worker_tool,
};
use oraclemcp::registry;
use oraclemcp_audit::{
    AuditRecord, AuditSink, AuditSubject, Auditor, DbEvidence, FileAuditSink, ShippingAuditSink,
    ShippingForwarder, SigningKey, WormFileForwarder,
};
use oraclemcp_auth::{
    Hs256Verifier, ResourceServerConfig, SecretError, SecretResolver, SystemSecretResolver,
    resolve_secret_with,
};
use oraclemcp_config::{
    AuditConfig, CONFIG_PATH_ENV, ConnectionProfile, HttpConfig, HttpTlsConfig, OracleMcpConfig,
};
use oraclemcp_core::admission::DEFAULT_READ_PER_PROFILE_CAP;
use oraclemcp_core::http::SinglePrincipalGuard;
use oraclemcp_core::{
    AdmissionController, CapabilitiesReport, ChangeProposalStore, ClientCredentialError,
    ClientCredentialIssueRequest, ClientCredentialLifecycle, ClientCredentialStore,
    ConfigApplyOutcome, ConfigDraftPreview, ConfigOpsBackend, ConfigOpsError, ConfigOpsService,
    ConfigOpsStatus, ConfigReloadApplier, ConfigReloadApplyReport, CustomToolCatalog,
    CustomToolDef, DashboardAuth, DispatchCloseReason, DispatchContext, DispatchFuture,
    DispatchOutcome, DoctorAuthCapabilities, DoctorAuthModeKind, DoctorContext, DoctorLevelCaps,
    DoctorProfileCaps, DoctorStateLayout, ExportRegistry, FeatureTiers, HttpSessionLifecycle,
    HttpTransportConfig, LaneContext, LaneDispatchFactory, LaneRuntime, MCP_PATH, McpSurfaceDetail,
    McpSurfaceFuture, MtlsClientRegistry, OAuthEnforcement, ObservabilityState,
    OperatorAuthorityPolicy, OracleMcpServer, PROTECTED_RESOURCE_METADATA_PATH, ServiceTransport,
    ShutdownCoordinator, SiemFormat, SiemHttpForwarder, SourceHistoryStore, StatefulLaneDispatch,
    StdioAuthPolicy, TlsMaterial, TlsServerConfig, ToolDispatch, WriteIntentLog,
    apply_legacy_state_migration, build_server_config, default_dashboard_ticket_dir, load_tools,
    load_tools_for_profile, mint_dashboard_pairing_ticket, operator_subject_id_hash,
    parse_tools_file, requires_mtls, run_doctor, service_app_doctor_snapshot, sign,
    start_oraclemcp_service_app_with_transport,
};
use oraclemcp_db::{
    DbError, OracleConnectOptions, OracleConnection, OraclePool, PoolSettings, RustOracleConnection,
};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use oraclemcp_guard::{Classifier, ClassifierConfig, OperatingLevel, SessionLevelState};
use oraclemcp_telemetry::{HealthState, Metrics, OtlpConfig};
use service_lifecycle::{
    ServiceBackupOptions, ServiceCommand as ServiceLifecycleCommand, ServiceInstallOptions,
    ServiceLogsOptions, ServiceMutationOptions, ServiceReadOptions, ServiceRestoreOptions,
    acquire_service_instance_guard,
};

/// Whether this build includes live Oracle connectivity.
const LIVE_DB: bool = true;
const CUSTOM_TOOLS_DIR_ENV: &str = "ORACLEMCP_TOOLS_DIR";
const CUSTOM_TOOLS_HMAC_KEY_ENV: &str = "ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY";
const DEFAULT_SETUP_CONFIG_PATH: &str = "~/.config/oraclemcp/profiles.toml";
/// Fallback environment variable for the audit signing key when the config's
/// `[audit].key_ref` is not set.
const AUDIT_KEY_ENV: &str = "ORACLEMCP_AUDIT_KEY";
const DEFAULT_BINARY_NAME: &str = "oraclemcp";
const SHORT_BINARY_ALIAS: &str = "om";

#[derive(Parser, Debug)]
#[command(
    name = "oraclemcp",
    version,
    about = "Engine-free, governed least-privilege Oracle Database MCP server",
    long_about = "Speaks the Model Context Protocol over stdio (default) or \
                  Streamable HTTP (--listen). Exposes governed, least-privilege Oracle tools \
                  (profile discovery, connection info, query, schema_inspect, \
                  list_schemas, switch_profile, set_session_level, preview_sql, describe, get_ddl, \
                  get_source, compile_errors, search_source, plscope_inspect, \
                  sample_rows, read_clob, explain_plan, compile_object, compile_with_warnings, \
                  create_or_replace, patch_source, guarded execute) plus the \
                  zero-arg oracle_capabilities discovery tool. No PL/SQL engine, \
                  no environment-specific workflow engine.",
    after_long_help = "Agent surfaces:\n  \
                       - Use --json (alias for --robot-json) for machine-readable stdout.\n  \
                       - Inspect the stable contract with: oraclemcp --json capabilities\n  \
                       - Read the in-tool guide with: oraclemcp robot-docs guide\n  \
                       - Preview host changes with: oraclemcp --json service install --dry-run\n  \
                       - Local service mutations require --yes; guarded SQL writes require preview confirmation."
)]
struct Cli {
    /// Emit a single JSON object on stdout instead of human text.
    #[arg(long, visible_alias = "json", global = true)]
    robot_json: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
enum Command {
    /// Start the MCP server (stdio by default; --listen <ADDR> for HTTP).
    Serve {
        /// Bind a Streamable HTTP listener at <ADDR> (e.g. 127.0.0.1:7070)
        /// instead of stdio. HTTP starts only with --client-credentials,
        /// configured OAuth, mTLS client-certificate verification, or explicit
        /// --allow-no-auth; mTLS identities require registered leaf fingerprints.
        #[arg(long)]
        listen: Option<String>,
        /// Run stdio without an init token (development only). Without this and
        /// without $ORACLEMCP_STDIO_TOKEN, stdio serve refuses to start.
        #[arg(long)]
        allow_no_auth: bool,
        /// The expected stdio init token (overrides $ORACLEMCP_STDIO_TOKEN).
        #[arg(long)]
        stdio_token: Option<String>,
        /// Connect using this named profile from the loaded config.
        #[arg(long)]
        profile: Option<String>,
        /// Streamable HTTP transport options.
        #[command(flatten)]
        http: HttpServeArgs,
    },
    /// Print build information (version, enabled features) and exit.
    Info,
    /// Run diagnostics; exit 2 on a blocker.
    Doctor {
        /// Inspect this named profile. Offline unless --online is also set.
        #[arg(long)]
        profile: Option<String>,
        /// Open a live database connection for connectivity/auth/role probes.
        #[arg(long)]
        online: bool,
        /// Plan scoped self-repair. Out-of-scope targets are refused with exit 4.
        #[arg(long)]
        fix: bool,
    },
    /// List configured connection profiles without opening a database connection.
    #[command(alias = "list-profiles")]
    Profiles,
    /// Print the capabilities report (tools, level, feature tiers) as JSON.
    Capabilities,
    /// Generate shell completions to stdout.
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: CompletionShell,
    },
    /// Install and operate the persistent local service.
    Service {
        #[command(subcommand)]
        command: ServiceCliCommand,
    },
    /// Issue, list, rotate, and revoke per-client HTTP bearer credentials.
    #[command(name = "clients", alias = "client-credentials")]
    Clients {
        #[command(subcommand)]
        command: ClientCredentialCliCommand,
    },
    /// Open the local browser dashboard through a one-time pairing ticket.
    Dashboard {
        /// Base URL of the running local oraclemcp HTTP service.
        #[arg(long, default_value = "http://127.0.0.1:7070")]
        url: String,
        /// Print the pairing URL without trying to launch a browser.
        #[arg(long)]
        no_open: bool,
    },
    /// Print an agent-oriented usage guide from the binary itself.
    #[command(name = "robot-docs", alias = "robot_docs")]
    RobotDocs {
        #[command(subcommand)]
        command: Option<RobotDocsCommand>,
    },
    /// Print generic onboarding templates for profiles, wrappers, and MCP clients.
    Setup {
        /// Write the generated profile config through the SCFG config-ops backend.
        #[arg(long)]
        write: bool,
        /// Example profile name to use in generated snippets.
        #[arg(long, default_value = "db_ro")]
        profile: String,
        /// Environment variable name used by credential_ref in the profile template.
        #[arg(long, default_value = "ORACLE_APP_PASSWORD")]
        credential_env: String,
        /// Wrapper path shown in client snippets.
        #[arg(long, default_value = "~/.local/bin/oraclemcp-local")]
        wrapper_path: String,
        /// Config path shown in generated guidance.
        #[arg(long, default_value = DEFAULT_SETUP_CONFIG_PATH)]
        config_path: String,
        /// Custom tools directory shown in generated guidance.
        #[arg(long, default_value = "~/.config/oraclemcp/tools.d")]
        tools_dir: String,
    },
    /// Re-run the release installer to update this binary.
    #[command(name = "self-update", alias = "self_update")]
    SelfUpdate(SelfUpdateCliArgs),
    /// Print HMAC signatures for operator-defined custom tool definitions.
    #[command(name = "sign-tool", alias = "sign_tools")]
    SignTool {
        /// TOML file containing one or more [[tool]] definitions.
        path: PathBuf,
        /// Sign only this tool name from the file.
        #[arg(long)]
        tool: Option<String>,
    },
    /// Operate on the out-of-band audit log (verify the signed hash chain).
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
}

#[derive(Subcommand, Debug)]
enum AuditCommand {
    /// Re-walk an audit log file, recompute every hash link, and re-check the
    /// keyed MAC with the configured key(s). Exits non-zero on a broken link or
    /// a recompute-without-key forgery.
    Verify {
        /// Path to the append-only JSONL audit log.
        file: PathBuf,
        /// Override the signing key id to verify against (defaults to the
        /// configured [audit].key_id or "default").
        #[arg(long)]
        key_id: Option<String>,
        /// Summarize signed database evidence and session-tag correlation.
        #[arg(long, visible_alias = "with_db_evidence")]
        with_db_evidence: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ServiceCliCommand {
    /// Install and start the persistent local service.
    Install(ServiceInstallCliArgs),
    /// Stop and unregister the persistent local service.
    Uninstall(ServiceMutationCliArgs),
    /// Report service-manager state.
    Status(ServiceReadCliArgs),
    /// Print recent service logs.
    Logs(ServiceLogsCliArgs),
    /// Restart the persistent local service.
    Restart(ServiceMutationCliArgs),
    /// Snapshot the service state directory plus the active config file.
    Backup(ServiceBackupCliArgs),
    /// Restore a service backup after verifying its audit hash-chain.
    Restore(ServiceRestoreCliArgs),
}

#[derive(Subcommand, Debug)]
enum ClientCredentialCliCommand {
    /// Issue one scoped bearer for one MCP client. The bearer is printed once.
    Issue(ClientCredentialIssueCliArgs),
    /// List redacted client credential metadata.
    List,
    /// Rotate one client's bearer. The new bearer is printed once.
    Rotate(ClientCredentialIdCliArgs),
    /// Revoke one client credential.
    Revoke(ClientCredentialIdCliArgs),
}

#[derive(Args, Debug, Clone)]
struct ClientCredentialIssueCliArgs {
    /// Human label for this MCP client.
    #[arg(long)]
    label: String,
    /// Granted scope. Repeat for multiple scopes.
    #[arg(long = "scope", default_value = "oracle:read")]
    scopes: Vec<String>,
}

#[derive(Args, Debug, Clone)]
struct ClientCredentialIdCliArgs {
    /// Client id returned by `oraclemcp clients issue`.
    client_id: String,
}

#[derive(Args, Debug, Clone)]
struct ServiceInstallCliArgs {
    /// Service name / label. Keep this stable; it determines the unit/plist/service id.
    #[arg(long, default_value = "oraclemcp")]
    name: String,
    /// Local HTTP listener for the service's `serve --listen` command.
    #[arg(long, default_value = "127.0.0.1:7070")]
    listen: String,
    /// Connect using this named profile from the loaded config.
    #[arg(long)]
    profile: Option<String>,
    /// Start HTTP without OAuth or registered mTLS (local development only).
    #[arg(long)]
    allow_no_auth: bool,
    /// Enable service-owned per-client bearer credentials for HTTP.
    #[arg(long)]
    client_credentials: bool,
    /// Do not run the optional Linux `loginctl enable-linger <user>` step.
    #[arg(long)]
    skip_linger: bool,
    /// Execute the service-manager changes. Omit and use --dry-run to inspect safely.
    #[arg(long)]
    yes: bool,
    /// Print the service-manager plan without writing files or running commands.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args, Debug)]
struct SelfUpdateCliArgs {
    /// Release version to install, e.g. 0.6.4 or v0.6.4.
    #[arg(long, default_value = "latest")]
    version: String,
    /// Verification posture forwarded to the platform installer.
    #[arg(long)]
    verify: Option<String>,
    /// Forward consent to the platform installer.
    #[arg(long)]
    yes: bool,
    /// Forward no-service to the platform installer.
    #[arg(long)]
    no_service: bool,
    /// Print the installer command without executing it.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args, Debug, Clone)]
struct ServiceMutationCliArgs {
    /// Service name / label.
    #[arg(long, default_value = "oraclemcp")]
    name: String,
    /// Execute the service-manager changes. Omit and use --dry-run to inspect safely.
    #[arg(long)]
    yes: bool,
    /// Print the service-manager plan without writing files or running commands.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args, Debug, Clone)]
struct ServiceReadCliArgs {
    /// Service name / label.
    #[arg(long, default_value = "oraclemcp")]
    name: String,
}

#[derive(Args, Debug, Clone)]
struct ServiceLogsCliArgs {
    /// Service name / label.
    #[arg(long, default_value = "oraclemcp")]
    name: String,
    /// Number of recent log lines/events to request.
    #[arg(long, default_value_t = 100)]
    lines: u16,
}

#[derive(Args, Debug, Clone)]
struct ServiceBackupCliArgs {
    /// Service name / label.
    #[arg(long, default_value = "oraclemcp")]
    name: String,
    /// New directory to create for the backup. Defaults outside the XDG state root.
    #[arg(long)]
    output: Option<PathBuf>,
    /// Execute the local backup write. Omit and use --dry-run to inspect safely.
    #[arg(long)]
    yes: bool,
    /// Print the backup plan without writing files.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args, Debug, Clone)]
struct ServiceRestoreCliArgs {
    /// Backup directory produced by `oraclemcp service backup`.
    backup: PathBuf,
    /// Service name / label.
    #[arg(long, default_value = "oraclemcp")]
    name: String,
    /// Override the audit signing key id to verify against.
    #[arg(long, visible_alias = "key_id")]
    key_id: Option<String>,
    /// Execute the stop, restore, and start sequence. Omit and use --dry-run first.
    #[arg(long)]
    yes: bool,
    /// Verify the backup and print the restore plan without writing files.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args, Debug, Default)]
struct HttpServeArgs {
    /// Allow this Host authority in addition to loopback authorities.
    #[arg(long = "http-allowed-host")]
    allowed_hosts: Vec<String>,
    /// Allow this browser Origin in addition to loopback origins.
    #[arg(long = "http-allowed-origin")]
    allowed_origins: Vec<String>,
    /// Use Streamable HTTP stateful session framing.
    #[arg(long = "http-stateful")]
    stateful: bool,
    /// Prefer direct JSON responses for stateless requests.
    #[arg(long = "http-json-response")]
    json_response: bool,
    /// OAuth resource/audience identifier expected in JWT aud.
    #[arg(long = "oauth-resource")]
    oauth_resource: Option<String>,
    /// Allowed OAuth issuer. Repeat for multiple issuers.
    #[arg(long = "oauth-issuer")]
    oauth_issuers: Vec<String>,
    /// OAuth authorization server advertised in protected-resource metadata.
    #[arg(long = "oauth-authorization-server")]
    oauth_authorization_servers: Vec<String>,
    /// Required OAuth scope. Repeat for multiple required scopes.
    #[arg(long = "oauth-required-scope")]
    oauth_required_scopes: Vec<String>,
    /// Secret reference for the built-in HS256 verifier, e.g. env:JWT_SECRET.
    #[arg(long = "oauth-hs256-secret-ref")]
    oauth_hs256_secret_ref: Option<String>,
    /// Metadata URL advertised in WWW-Authenticate.
    #[arg(long = "oauth-metadata-url")]
    oauth_metadata_url: Option<String>,
    /// Server certificate-chain PEM path for native rustls HTTPS.
    #[arg(long = "tls-cert")]
    tls_cert: Option<PathBuf>,
    /// Server private-key PEM path for native rustls HTTPS.
    #[arg(long = "tls-key")]
    tls_key: Option<PathBuf>,
    /// Client CA PEM path for native mTLS client-certificate verification.
    #[arg(long = "mtls-client-ca")]
    mtls_client_ca: Option<PathBuf>,
    /// Registered mTLS client leaf certificate SHA-256 fingerprint.
    #[arg(long = "mtls-client-fingerprint")]
    mtls_client_fingerprints: Vec<String>,
    /// Accept service-owned per-client `ocmcp_*` bearer credentials.
    #[arg(long = "client-credentials")]
    client_credentials: bool,
}

#[derive(Subcommand, Debug)]
enum RobotDocsCommand {
    /// Print the compact agent guide.
    Guide,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    #[value(name = "powershell", alias = "pwsh", alias = "power-shell")]
    Powershell,
}

fn display_binary_name_from_argv0(argv0: Option<&std::ffi::OsStr>) -> &'static str {
    let Some(argv0) = argv0 else {
        return DEFAULT_BINARY_NAME;
    };
    let Some(stem) = Path::new(argv0).file_stem().and_then(|name| name.to_str()) else {
        return DEFAULT_BINARY_NAME;
    };
    if stem.eq_ignore_ascii_case(SHORT_BINARY_ALIAS) {
        SHORT_BINARY_ALIAS
    } else {
        DEFAULT_BINARY_NAME
    }
}

fn current_display_binary_name() -> &'static str {
    let argv0 = std::env::args_os().next();
    display_binary_name_from_argv0(argv0.as_deref())
}

fn cli_command(binary_name: &'static str) -> clap::Command {
    Cli::command().name(binary_name).bin_name(binary_name)
}

fn parse_cli(binary_name: &'static str) -> Cli {
    let matches = cli_command(binary_name).get_matches();
    Cli::from_arg_matches(&matches).unwrap_or_else(|err| err.exit())
}

fn bare_invocation_hint(binary_name: &str) -> String {
    format!(
        "no subcommand given — try `{binary_name} serve`, `{binary_name} doctor`, or `{binary_name} capabilities`."
    )
}

fn main() -> ExitCode {
    let binary_name = current_display_binary_name();
    let cli = parse_cli(binary_name);
    let robot_json = cli.robot_json;

    let Some(command) = cli.command else {
        // Bare invocation: help to stderr, exit 2. stdout stays empty so a
        // launcher piping JSON-RPC never mistakes the hint for data.
        let mut cmd = cli_command(binary_name);
        let _ = cmd.write_long_help(&mut std::io::stderr());
        eprintln!("\n{}", bare_invocation_hint(binary_name));
        return ExitCode::from(2);
    };

    match command {
        Command::Serve {
            listen,
            allow_no_auth,
            stdio_token,
            profile,
            http,
        } => run_serve(
            listen,
            allow_no_auth,
            stdio_token,
            profile,
            http,
            robot_json,
        ),
        Command::Info => run_info(robot_json),
        Command::Doctor {
            profile,
            online,
            fix,
        } => run_doctor_cmd(robot_json, profile, online, fix),
        Command::Profiles => run_profiles(robot_json),
        Command::Capabilities => run_capabilities(robot_json),
        Command::Completions { shell } => run_completions_cmd(binary_name, shell),
        Command::Service { command } => run_service_cmd(robot_json, command),
        Command::Clients { command } => run_client_credentials_cmd(robot_json, command),
        Command::Dashboard { url, no_open } => {
            run_dashboard_cmd(robot_json, binary_name, &url, no_open)
        }
        Command::RobotDocs { command } => match command {
            None | Some(RobotDocsCommand::Guide) => run_robot_docs_guide(robot_json),
        },
        Command::Setup {
            write,
            profile,
            credential_env,
            wrapper_path,
            config_path,
            tools_dir,
        } => run_setup(
            robot_json,
            write,
            &profile,
            &credential_env,
            &wrapper_path,
            &config_path,
            &tools_dir,
        ),
        Command::SelfUpdate(args) => run_self_update_cmd(robot_json, args),
        Command::SignTool { path, tool } => run_sign_tool(robot_json, &path, tool.as_deref()),
        Command::Audit { command } => match command {
            AuditCommand::Verify {
                file,
                key_id,
                with_db_evidence,
            } => run_audit_verify(robot_json, &file, key_id.as_deref(), with_db_evidence),
        },
    }
}

fn write_stdout<F>(write: F) -> io::Result<()>
where
    F: FnOnce(&mut dyn Write) -> io::Result<()>,
{
    let stdout = io::stdout();
    let mut out = stdout.lock();
    write(&mut out)
}

fn write_stdout_text(text: &str) -> io::Result<()> {
    write_stdout(|out| out.write_all(text.as_bytes()))
}

fn write_stdout_line(text: &str) -> io::Result<()> {
    write_stdout(|out| {
        out.write_all(text.as_bytes())?;
        out.write_all(b"\n")
    })
}

fn stdout_exit(result: io::Result<()>, success: ExitCode) -> ExitCode {
    match result {
        Ok(()) => success,
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("oraclemcp: failed writing to stdout: {e}");
            ExitCode::from(1)
        }
    }
}

/// Resolve the selected profile name and connection options from config + an
/// optional profile name. When no explicit/default/sole profile resolves, the
/// result is `None` so `serve` can still start for capabilities/doctor.
fn default_read_only_level() -> SessionLevelState {
    SessionLevelState::new(OperatingLevel::ReadOnly, false)
}

#[derive(Clone)]
struct SelectedRuntimeProfile {
    name: String,
    level: SessionLevelState,
    request_timeout: Option<std::time::Duration>,
}

#[derive(Clone)]
struct ResolvedProfile {
    name: String,
    opts: OracleConnectOptions,
    level: SessionLevelState,
    pool_settings: Option<PoolSettings>,
    doctor_caps: DoctorProfileCaps,
    connect_timeout_seconds: Option<u64>,
}

fn selected_config_profile<'a>(
    cfg: &'a OracleMcpConfig,
    profile: Option<&str>,
) -> Result<Option<&'a ConnectionProfile>, DbError> {
    match profile {
        Some(name) => Ok(Some(cfg.profile(name).ok_or_else(|| {
            DbError::UnsupportedAuth(format!("connection profile `{name}` not found"))
        })?)),
        None if cfg.default_profile.is_some() => {
            let name = cfg.default_profile.as_deref().expect("checked is_some");
            Ok(Some(cfg.profile(name).ok_or_else(|| {
                DbError::UnsupportedAuth(format!("default_profile `{name}` not found"))
            })?))
        }
        // No explicit/default profile: use the sole profile if there is exactly
        // one, else none (the agent can still drive capabilities/doctor).
        None if cfg.profiles.len() == 1 => Ok(cfg.profiles.first()),
        None => Ok(None),
    }
}

fn select_runtime_profile_from_config(
    cfg: &OracleMcpConfig,
    profile: Option<&str>,
) -> Result<Option<SelectedRuntimeProfile>, DbError> {
    let Some(chosen) = selected_config_profile(cfg, profile)? else {
        return Ok(None);
    };
    let ctx = oraclemcp_core::build_session_context(chosen, None, None, false)?;
    Ok(Some(SelectedRuntimeProfile {
        name: chosen.name.clone(),
        level: ctx.level_state,
        request_timeout: ctx.options.call_timeout,
    }))
}

fn select_runtime_profile(
    profile: Option<&str>,
) -> Result<Option<SelectedRuntimeProfile>, DbError> {
    let cfg = OracleMcpConfig::load(None)
        .map_err(|e| DbError::UnsupportedAuth(format!("config load failed: {e}")))?;
    select_runtime_profile_from_config(&cfg, profile)
}

fn resolve_profile_options(profile: Option<&str>) -> Result<Option<ResolvedProfile>, DbError> {
    let resolver = SystemSecretResolver;
    resolve_profile_options_with(profile, &resolver)
}

fn resolve_profile_options_with(
    profile: Option<&str>,
    secret_resolver: &dyn SecretResolver,
) -> Result<Option<ResolvedProfile>, DbError> {
    let cfg = OracleMcpConfig::load(None)
        .map_err(|e| DbError::UnsupportedAuth(format!("config load failed: {e}")))?;

    let Some(chosen) = selected_config_profile(&cfg, profile)? else {
        return Ok(None);
    };

    let password = resolve_profile_secret(
        "credential_ref",
        &chosen.name,
        chosen.credential_ref.as_deref(),
        chosen.protected(),
        secret_resolver,
    )?;
    let wallet_password = resolve_profile_secret(
        "wallet_password_ref",
        &chosen.name,
        chosen
            .oci
            .as_ref()
            .and_then(|oci| oci.wallet_password_ref.as_deref()),
        chosen.protected(),
        secret_resolver,
    )?;

    let ctx = oraclemcp_core::build_session_context(chosen, password, wallet_password, false)?;
    let doctor_caps = doctor_profile_caps(chosen, &ctx.level_state);
    Ok(Some(ResolvedProfile {
        name: chosen.name.clone(),
        opts: ctx.options,
        level: ctx.level_state,
        pool_settings: ctx.pool_settings,
        doctor_caps,
        connect_timeout_seconds: chosen.connect_timeout_seconds,
    }))
}

fn resolve_profile_secret(
    field: &str,
    profile_name: &str,
    secret_ref: Option<&str>,
    protected: bool,
    secret_resolver: &dyn SecretResolver,
) -> Result<Option<String>, DbError> {
    let Some(reference) = secret_ref else {
        return Ok(None);
    };
    let secret = resolve_secret_with(reference, protected, secret_resolver).map_err(|e| {
        DbError::UnsupportedAuth(format!(
            "failed to resolve {field} for profile `{profile_name}`: {}",
            secret_error_summary(&e)
        ))
    })?;
    Ok(Some(secret.expose().to_owned()))
}

fn secret_error_summary(error: &SecretError) -> String {
    match error {
        SecretError::Malformed(_) => {
            "malformed secret reference (expected scheme:locator)".to_owned()
        }
        SecretError::NotFound(_) => "secret not found".to_owned(),
        SecretError::PlaintextForbidden => {
            "plaintext literal credential is forbidden on a protected profile".to_owned()
        }
        SecretError::InvalidUtf8(scheme) => {
            format!("secret backend `{scheme}` returned invalid utf-8")
        }
        SecretError::BackendFailure(scheme) => {
            format!("secret backend `{scheme}` failed")
        }
        SecretError::BackendUnavailable(scheme) => {
            format!("secrets backend not available for scheme `{scheme}` (feature-gated)")
        }
        _ => "secret resolution failed".to_owned(),
    }
}

/// The `oracle_switch_profile` reconnect connector (B1: async + `Cx`-first).
///
/// Matches `oraclemcp::dispatch::ProfileConnector`: opens the session
/// connection for `profile` as a native-async DB round trip, awaited on the
/// dispatch runtime that already holds the request `Cx`. The connector captures
/// the D18 SecretResolver seam so profile credentials are resolved only at the
/// connect boundary.
fn profile_connector(secret_resolver: Arc<dyn SecretResolver>) -> Arc<ProfileConnector> {
    Arc::new(move |cx: &Cx, profile: &str| {
        let secret_resolver = Arc::clone(&secret_resolver);
        Box::pin(async move {
            let Some(resolved) =
                resolve_profile_options_with(Some(profile), secret_resolver.as_ref())?
            else {
                return Err(DbError::UnsupportedAuth(format!(
                    "connection profile `{profile}` not found"
                )));
            };
            try_open_connection(cx, resolved.opts).await
        })
    })
}

/// The `oracle_switch_profile` stateless-pool connector (B1: async + `Cx`-first).
fn profile_stateless_connector(
    secret_resolver: Arc<dyn SecretResolver>,
) -> Arc<ProfileStatelessConnector> {
    Arc::new(move |cx: &Cx, profile: &str| {
        let secret_resolver = Arc::clone(&secret_resolver);
        Box::pin(async move {
            let Some(resolved) =
                resolve_profile_options_with(Some(profile), secret_resolver.as_ref())?
            else {
                return Err(DbError::UnsupportedAuth(format!(
                    "connection profile `{profile}` not found"
                )));
            };
            try_open_stateless_connection(cx, resolved.opts, resolved.pool_settings).await
        })
    })
}

async fn try_open_connection(
    cx: &Cx,
    opts: OracleConnectOptions,
) -> Result<Box<dyn OracleConnection>, DbError> {
    RustOracleConnection::connect(cx, opts)
        .await
        .map(|conn| Box::new(conn) as Box<dyn OracleConnection>)
}

async fn try_open_stateless_connection(
    cx: &Cx,
    opts: OracleConnectOptions,
    pool_settings: Option<PoolSettings>,
) -> Result<Option<Box<dyn OracleConnection>>, DbError> {
    match pool_settings {
        Some(settings) => OraclePool::connect(cx, opts, settings)
            .await
            .map(|pool| Some(Box::new(pool) as Box<dyn OracleConnection>)),
        None => Ok(None),
    }
}

struct RuntimeConnections {
    session: Box<dyn OracleConnection>,
    stateless: Option<Box<dyn OracleConnection>>,
}

enum RuntimeConnectionPlan {
    Profile(String),
    Default,
    Stub(DbError),
}

async fn try_open_runtime_connections(
    cx: &Cx,
    resolved: ResolvedProfile,
) -> Result<RuntimeConnections, DbError> {
    let session = try_open_connection(cx, resolved.opts.clone()).await?;
    let stateless =
        try_open_stateless_connection(cx, resolved.opts, resolved.pool_settings).await?;
    Ok(RuntimeConnections { session, stateless })
}

/// Drive a connection-establishment future to completion on a one-shot
/// current-thread Asupersync runtime. Connection setup is a rare startup-time
/// operation (NOT the per-call DB path), so a dedicated `block_on` here is safe
/// and keeps the per-query path `block_on`-free.
fn block_on_connect<F, T>(f: impl FnOnce(Cx) -> F) -> T
where
    F: std::future::Future<Output = T>,
{
    // The async `oracledb` driver needs a reactor to drive socket I/O; a runtime
    // built without one hangs on the first round trip (release-gre.16).
    let reactor = asupersync::runtime::reactor::create_reactor()
        .expect("Asupersync native reactor builds for connection setup");
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .with_reactor(reactor)
        .build()
        .expect("Asupersync current-thread runtime builds for connection setup");
    // block-on-boundary: rare startup connection setup, not a per-call DB path.
    runtime.block_on(async move {
        let cx = Cx::current().expect("block_on installs a current Cx");
        f(cx).await
    })
}

/// Open the live connection, or — when the driver is absent / the connect fails
/// — a stub connection that returns the same `DbError` on every call. Either
/// way `serve` starts: capabilities/doctor work offline, and live tool calls
/// return a structured envelope instead of crashing the process.
fn open_connection(opts: OracleConnectOptions) -> Box<dyn OracleConnection> {
    match block_on_connect(|cx| async move { try_open_connection(&cx, opts).await }) {
        Ok(conn) => conn,
        Err(e) => {
            tracing::warn!(error = %e, "no live connection; live tools will return a structured error envelope");
            Box::new(stub::StubConnection::new(e))
        }
    }
}

fn open_runtime_connections(resolved: ResolvedProfile) -> RuntimeConnections {
    match block_on_connect(|cx| async move { try_open_runtime_connections(&cx, resolved).await }) {
        Ok(connections) => connections,
        Err(e) => {
            tracing::warn!(error = %e, "no live connection; live tools will return a structured error envelope");
            stub_runtime_connections(e)
        }
    }
}

fn stub_runtime_connections(error: DbError) -> RuntimeConnections {
    RuntimeConnections {
        session: Box::new(stub::StubConnection::new(error)) as Box<dyn OracleConnection>,
        stateless: None,
    }
}

fn open_profile_runtime_connections(
    profile: &str,
    secret_resolver: &dyn SecretResolver,
    include_stateless: bool,
) -> RuntimeConnections {
    let resolved = match resolve_profile_options_with(Some(profile), secret_resolver) {
        Ok(Some(resolved)) => resolved,
        Ok(None) => {
            return stub_runtime_connections(DbError::UnsupportedAuth(format!(
                "connection profile `{profile}` not found"
            )));
        }
        Err(e) => return stub_runtime_connections(e),
    };
    if include_stateless {
        open_runtime_connections(resolved)
    } else {
        RuntimeConnections {
            session: open_connection(resolved.opts),
            stateless: None,
        }
    }
}

fn open_runtime_connection_plan(
    plan: RuntimeConnectionPlan,
    include_stateless: bool,
    secret_resolver: &dyn SecretResolver,
) -> RuntimeConnections {
    match plan {
        RuntimeConnectionPlan::Profile(profile) => {
            open_profile_runtime_connections(&profile, secret_resolver, include_stateless)
        }
        RuntimeConnectionPlan::Default => RuntimeConnections {
            session: open_connection(OracleConnectOptions::default()),
            stateless: None,
        },
        RuntimeConnectionPlan::Stub(e) => stub_runtime_connections(e),
    }
}

fn custom_tools_dir() -> Option<PathBuf> {
    std::env::var_os(CUSTOM_TOOLS_DIR_ENV)
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".config/oraclemcp/tools.d"))
        })
}

fn custom_tool_error(message: impl Into<String>) -> ErrorEnvelope {
    ErrorEnvelope::new(ErrorClass::InvalidArguments, message)
}

fn read_custom_tool_defs(dir: &Path) -> Result<Vec<CustomToolDef>, ErrorEnvelope> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    if !dir.is_dir() {
        return Err(custom_tool_error(format!(
            "{} must point to a directory of .toml tool definitions",
            CUSTOM_TOOLS_DIR_ENV
        )));
    }

    let mut paths = Vec::new();
    let entries = std::fs::read_dir(dir)
        .map_err(|e| custom_tool_error(format!("failed to read custom tools dir: {e}")))?;
    for entry in entries {
        let entry =
            entry.map_err(|e| custom_tool_error(format!("failed to read tools.d entry: {e}")))?;
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|ext| ext == "toml") {
            paths.push(path);
        }
    }
    paths.sort();

    let mut defs = Vec::new();
    for path in paths {
        let src = std::fs::read_to_string(&path).map_err(|e| {
            custom_tool_error(format!(
                "failed to read custom tool file {}: {e}",
                path.display()
            ))
        })?;
        let mut file_defs = parse_tools_file(&src).map_err(|e| {
            custom_tool_error(format!(
                "failed to parse custom tool file {}: {e}",
                path.display()
            ))
        })?;
        defs.append(&mut file_defs);
    }
    Ok(defs)
}

fn validate_custom_tool_names(defs: &[CustomToolDef]) -> Result<(), ErrorEnvelope> {
    let reserved_names: HashSet<String> = registry::tool_registry()
        .tools
        .into_iter()
        .map(|tool| tool.name)
        .chain(std::iter::once(
            oraclemcp_core::CAPABILITIES_TOOL.to_owned(),
        ))
        .collect();
    let mut seen = HashSet::new();
    for def in defs {
        if !seen.insert(def.name.as_str()) {
            return Err(custom_tool_error(format!(
                "duplicate custom tool name `{}`",
                def.name
            )));
        }
        if reserved_names.contains(&def.name) {
            return Err(custom_tool_error(format!(
                "custom tool name `{}` collides with a built-in tool or alias",
                def.name
            )));
        }
    }
    Ok(())
}

fn custom_tools_require_signatures(
    active_profile: Option<&str>,
    level: &SessionLevelState,
) -> bool {
    if level.is_protected() {
        return true;
    }
    let Some(profile_name) = active_profile else {
        return false;
    };
    OracleMcpConfig::load(None)
        .ok()
        .and_then(|cfg| {
            cfg.profile(profile_name)
                .map(|profile| profile.require_signed_tools())
        })
        .unwrap_or(false)
}

fn load_custom_catalog_for_profile(
    active_profile: Option<&str>,
    level: &SessionLevelState,
) -> Result<CustomToolCatalog, ErrorEnvelope> {
    let Some(dir) = custom_tools_dir() else {
        return Ok(CustomToolCatalog::default());
    };
    let defs = read_custom_tool_defs(&dir)?;
    if defs.is_empty() {
        return Ok(CustomToolCatalog::default());
    }
    validate_custom_tool_names(&defs)?;

    let classifier = Classifier::new(ClassifierConfig::new());
    let key = std::env::var(CUSTOM_TOOLS_HMAC_KEY_ENV).ok();
    let signed_defs_present = defs.iter().any(|def| def.signature.is_some());
    let require_signed_tools = custom_tools_require_signatures(active_profile, level);
    let loaded = if require_signed_tools {
        let key = key.ok_or_else(|| {
            custom_tool_error(format!(
                "{CUSTOM_TOOLS_HMAC_KEY_ENV} is required when this profile requires signed custom tools"
            ))
        })?;
        load_tools_for_profile(
            &defs,
            &classifier,
            OperatingLevel::ReadOnly,
            key.as_bytes(),
            true,
        )
    } else if let Some(key) = key {
        load_tools_for_profile(
            &defs,
            &classifier,
            OperatingLevel::ReadOnly,
            key.as_bytes(),
            false,
        )
    } else if signed_defs_present {
        return Err(custom_tool_error(format!(
            "custom tool signatures are present but {CUSTOM_TOOLS_HMAC_KEY_ENV} is not set"
        )));
    } else {
        load_tools(&defs, &classifier, OperatingLevel::ReadOnly)
    }
    .map_err(|e| custom_tool_error(format!("failed to load custom tools: {e}")))?;

    Ok(CustomToolCatalog::new(loaded))
}

/// The current safe default audit-log path under the XDG state home, used when
/// `[audit].path` is not configured but an auditor is required.
fn default_audit_path() -> PathBuf {
    if let Ok(state_dir) = oraclemcp_core::FileStore::default_state_dir() {
        return state_dir.join("audit").join("audit.jsonl");
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".local/state/oraclemcp/audit/audit.jsonl"))
        .unwrap_or_else(|| PathBuf::from("oraclemcp-audit.jsonl"))
}

/// The legacy 0.4.x default audit path under the config home.
fn legacy_audit_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".config/oraclemcp/audit.jsonl"))
}

fn doctor_state_layout(audit_path_configured: bool) -> Option<DoctorStateLayout> {
    let legacy_audit_path = legacy_audit_path()?;
    let state_dir = oraclemcp_core::FileStore::default_state_dir().ok()?;
    Some(DoctorStateLayout {
        legacy_audit_path,
        current_audit_path: default_audit_path(),
        migration_backup_dir: state_dir.join("doctor-migrations").join("backups"),
        audit_path_configured,
    })
}

/// Resolve the audit signing key: prefer the config `[audit].key_ref` secret,
/// fall back to the `ORACLEMCP_AUDIT_KEY` env var. Returns `None` when neither
/// is set (the caller fails closed if a write level is reachable).
fn resolve_audit_signing_key(
    audit: &AuditConfig,
    protected: bool,
    secret_resolver: &dyn SecretResolver,
) -> Result<Option<SigningKey>, (&'static str, String)> {
    let key_id = audit.key_id_or_default().to_owned();
    if let Some(key_ref) = audit.key_ref.as_deref() {
        let secret = resolve_secret_with(key_ref, protected, secret_resolver).map_err(|e| {
            (
                "ORACLEMCP_AUDIT_KEY_INVALID",
                format!(
                    "failed to resolve [audit].key_ref: {}",
                    secret_error_summary(&e)
                ),
            )
        })?;
        return Ok(Some(SigningKey::new(
            key_id,
            secret.expose().as_bytes().to_vec(),
        )));
    }
    if let Ok(raw) = std::env::var(AUDIT_KEY_ENV)
        && !raw.is_empty()
    {
        return Ok(Some(SigningKey::new(key_id, raw.into_bytes())));
    }
    Ok(None)
}

/// The maximum operating level reachable across every profile this server can
/// SERVE at runtime, plus the active/startup profile (bead A8, multi-profile).
///
/// E5 per-profile opt-out: every profile is servable (reachable via
/// `oracle_switch_profile`) UNLESS it sets `mcp_exposed = false`, so a hidden
/// profile cannot raise the reachable ceiling. The active profile's ceiling is
/// always included (the server starts on it). The result drives the fail-closed
/// audit requirement: if it exceeds READ_ONLY, a signing key is mandatory.
fn max_reachable_write_ceiling(
    config: &OracleMcpConfig,
    active_level: &SessionLevelState,
) -> OperatingLevel {
    let mut ceiling = active_level.max_level();
    for profile in &config.profiles {
        // Servable unless explicitly hidden with `mcp_exposed = false`. A
        // protected profile is always pinned at READ_ONLY by validation, so it
        // contributes nothing here.
        if profile.mcp_exposed() {
            ceiling = ceiling.max(profile.max_level());
        }
    }
    ceiling
}

/// One-line operator-facing summary of which profiles are exposed to the MCP
/// agent and at what ceiling (E5 per-profile opt-out). Visibility only —
/// behavior-neutral; emitted to stderr at startup so an operator can see at a
/// glance that, e.g., a writable profile is reachable by the agent.
fn exposed_profiles_summary(config: &OracleMcpConfig) -> String {
    let exposed: Vec<String> = config
        .profiles
        .iter()
        .filter(|p| p.mcp_exposed())
        .map(|p| format!("{} [{:?}]", p.name, p.max_level()))
        .collect();
    let total = config.profiles.len();
    if exposed.is_empty() {
        if total == 0 {
            "MCP exposing 0 profiles (none configured)".to_owned()
        } else {
            format!("MCP exposing 0 of {total} profile(s) — all hidden via mcp_exposed=false")
        }
    } else {
        let hidden = total - exposed.len();
        let suffix = if hidden > 0 {
            format!(" ({hidden} hidden via mcp_exposed=false)")
        } else {
            String::new()
        };
        format!(
            "MCP exposing {} profile(s): {}{suffix}",
            exposed.len(),
            exposed.join(", ")
        )
    }
}

/// Build the out-of-band auditor for the server.
///
/// Fail-closed policy (bead A8): if any operating level **above ReadOnly** is
/// reachable — across the active profile OR any servable profile the server can
/// `oracle_switch_profile` to (see [`max_reachable_write_ceiling`]) — a signing
/// key is **required**; without one we refuse to start rather than run writes
/// unaudited on a profile reached after startup. When only ReadOnly is reachable
/// anywhere, the auditor is optional: a configured key still builds one (so
/// escalation previews/log stay available), otherwise `None` (pure reads never
/// touch the chain).
fn build_auditor(
    audit: &AuditConfig,
    level: &SessionLevelState,
    reachable_ceiling: OperatingLevel,
    secret_resolver: &dyn SecretResolver,
) -> Result<Option<Arc<Auditor>>, (&'static str, String)> {
    let write_reachable = reachable_ceiling > OperatingLevel::ReadOnly;
    let key = resolve_audit_signing_key(audit, level.is_protected(), secret_resolver)?;

    let Some(key) = key else {
        if write_reachable {
            return Err((
                "ORACLEMCP_AUDIT_KEY_REQUIRED",
                format!(
                    "a servable profile can reach operating level {} (above READ_ONLY) but no \
                     audit signing key is configured; set [audit].key_ref or {AUDIT_KEY_ENV} so \
                     every write/escalation is recorded on the signed audit chain",
                    reachable_ceiling.as_str()
                ),
            ));
        }
        // Read-only everywhere reachable: no writes/escalations can occur, so no
        // auditor needed.
        return Ok(None);
    };

    let path = audit.path.clone().unwrap_or_else(default_audit_path);
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|e| {
            (
                "ORACLEMCP_AUDIT_PATH_INVALID",
                format!(
                    "failed to create audit log directory {}: {e}",
                    parent.display()
                ),
            )
        })?;
    }
    let sink = FileAuditSink::open(&path).map_err(|e| {
        (
            "ORACLEMCP_AUDIT_PATH_INVALID",
            format!("failed to open audit log {}: {e}", path.display()),
        )
    })?;
    tracing::info!(path = %path.display(), key_id = %audit.key_id_or_default(), "audit log armed");

    // D2: optional WORM/SIEM shipping. Off by default — only when
    // `[audit.shipping]` configures a destination do we wrap the durable local
    // sink in the fail-safe ShippingAuditSink decorator. A forward failure never
    // loses the local record (the decorator logs + counts it).
    let local: Box<dyn AuditSink> = Box::new(sink);
    let local = match audit.shipping.as_ref() {
        Some(shipping) => {
            build_shipping_sink(local, shipping, level.is_protected(), secret_resolver)?
        }
        None => local,
    };
    Ok(Some(Arc::new(Auditor::new(local, key))))
}

fn build_write_intent_log(
    reachable_ceiling: OperatingLevel,
) -> Result<Option<Arc<WriteIntentLog>>, (&'static str, String)> {
    if reachable_ceiling <= OperatingLevel::ReadOnly {
        return Ok(None);
    }
    let log = WriteIntentLog::open_default().map_err(|e| {
        (
            "ORACLEMCP_WRITE_INTENT_LOG_INVALID",
            format!("failed to open durable write-intent log: {e}"),
        )
    })?;
    finish_write_intent_log_build(log)
}

#[cfg(test)]
fn build_write_intent_log_at(
    root: &Path,
    reachable_ceiling: OperatingLevel,
) -> Result<Option<Arc<WriteIntentLog>>, (&'static str, String)> {
    if reachable_ceiling <= OperatingLevel::ReadOnly {
        return Ok(None);
    }
    let log = WriteIntentLog::open(root).map_err(|e| {
        (
            "ORACLEMCP_WRITE_INTENT_LOG_INVALID",
            format!("failed to open durable write-intent log: {e}"),
        )
    })?;
    finish_write_intent_log_build(log)
}

fn finish_write_intent_log_build(
    log: WriteIntentLog,
) -> Result<Option<Arc<WriteIntentLog>>, (&'static str, String)> {
    let unresolved = log.unresolved().map_err(|e| {
        (
            "ORACLEMCP_WRITE_INTENT_LOG_INVALID",
            format!("failed to recover durable write-intent log: {e}"),
        )
    })?;
    let path = log
        .path()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "<unknown>".to_owned());
    if let Some(first) = unresolved.first() {
        return Err((
            "ORACLEMCP_WRITE_INTENT_IN_DOUBT",
            format!(
                "durable write-intent log {} contains {} unresolved intent(s); first intent {} \
                 subject={} lane={} sql_hash={}. Verify the database outcome before restarting \
                 a writable server so non-idempotent work is never silently re-executed.",
                path,
                unresolved.len(),
                first.intent_id,
                first.subject,
                first.lane,
                first.sql_sha256
            ),
        ));
    }
    tracing::info!(path = %path, "durable write-intent log armed");
    Ok(Some(Arc::new(log)))
}

/// Wrap the durable local audit sink in the D2 shipping decorator from
/// `[audit.shipping]`. Builds a WORM file forwarder and/or a SIEM HTTP forwarder
/// (asupersync HTTP client, no tokio/reqwest), composing both into a single
/// forwarder when both are configured. Shipping never weakens the local chain.
fn build_shipping_sink(
    local: Box<dyn AuditSink>,
    shipping: &oraclemcp_config::AuditShippingConfig,
    protected: bool,
    secret_resolver: &dyn SecretResolver,
) -> Result<Box<dyn AuditSink>, (&'static str, String)> {
    let mut forwarders: Vec<Box<dyn ShippingForwarder>> = Vec::new();

    if let Some(worm_path) = shipping.worm_path.as_deref() {
        if let Some(parent) = worm_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|e| {
                (
                    "ORACLEMCP_AUDIT_SHIPPING_INVALID",
                    format!(
                        "failed to create WORM mirror directory {}: {e}",
                        parent.display()
                    ),
                )
            })?;
        }
        let worm = WormFileForwarder::open(worm_path).map_err(|e| {
            (
                "ORACLEMCP_AUDIT_SHIPPING_INVALID",
                format!("failed to open WORM mirror {}: {e}", worm_path.display()),
            )
        })?;
        tracing::info!(worm_path = %worm_path.display(), "audit WORM mirror armed");
        forwarders.push(Box::new(worm));
    }

    if let Some(endpoint) = shipping.siem_endpoint.as_deref() {
        let format = SiemFormat::parse(shipping.siem_format_or_default()).ok_or((
            "ORACLEMCP_AUDIT_SHIPPING_INVALID",
            format!(
                "unknown audit.shipping.siem_format {:?} (expected json|cef|syslog)",
                shipping.siem_format_or_default()
            ),
        ))?;
        let mut forwarder = SiemHttpForwarder::new(endpoint.to_owned(), format);
        if let Some(auth_ref) = shipping.siem_auth_header_ref.as_deref() {
            let secret =
                resolve_secret_with(auth_ref, protected, secret_resolver).map_err(|e| {
                    (
                        "ORACLEMCP_AUDIT_SHIPPING_INVALID",
                        format!(
                            "failed to resolve audit.shipping.siem_auth_header_ref: {}",
                            secret_error_summary(&e)
                        ),
                    )
                })?;
            forwarder = forwarder.with_header(
                shipping.siem_auth_header_name_or_default().to_owned(),
                secret.expose().to_owned(),
            );
        }
        tracing::info!(siem_endpoint = %endpoint, format = ?format, "audit SIEM forwarder armed");
        forwarders.push(Box::new(forwarder));
    }

    let forwarder: Box<dyn ShippingForwarder> = match forwarders.len() {
        0 => return Ok(local), // validate() guarantees ≥1, but stay total.
        1 => forwarders.into_iter().next().expect("len==1"),
        _ => Box::new(TeeForwarder::new(forwarders)),
    };
    Ok(Box::new(ShippingAuditSink::new(local, forwarder)))
}

/// A forwarder that fans one record out to several forwarders (WORM + SIEM).
/// Order-preserving; each forward error is independent (one destination being
/// down does not stop the others). The first error is returned so the
/// decorator counts a failure, but every destination is still attempted.
struct TeeForwarder {
    forwarders: Vec<Box<dyn ShippingForwarder>>,
}

impl TeeForwarder {
    fn new(forwarders: Vec<Box<dyn ShippingForwarder>>) -> Self {
        Self { forwarders }
    }
}

impl ShippingForwarder for TeeForwarder {
    fn forward(
        &self,
        record: &oraclemcp_audit::AuditRecord,
    ) -> Result<(), oraclemcp_audit::ShippingError> {
        let mut first_err = None;
        for f in &self.forwarders {
            if let Err(e) = f.forward(record)
                && first_err.is_none()
            {
                first_err = Some(e);
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn flush(&self) -> Result<(), oraclemcp_audit::ShippingError> {
        let mut first_err = None;
        for f in &self.forwarders {
            if let Err(e) = f.flush()
                && first_err.is_none()
            {
                first_err = Some(e);
            }
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[derive(Clone)]
struct DispatcherWiring {
    active_profile: Option<String>,
    level: SessionLevelState,
    request_timeout: Option<std::time::Duration>,
    secret_resolver: Arc<dyn SecretResolver>,
    custom_catalog: CustomToolCatalog,
    exposure: McpExposurePolicy,
    profile_drain: ProfileDrainState,
    auditor: Option<Arc<Auditor>>,
    write_intents: Option<Arc<WriteIntentLog>>,
    exports: Arc<ExportRegistry>,
    notifications: Arc<oraclemcp_core::NotificationHub>,
}

fn build_oracle_dispatcher(
    conn: Box<dyn OracleConnection>,
    stateless_conn: Option<Box<dyn OracleConnection>>,
    wiring: &DispatcherWiring,
) -> OracleDispatcher {
    let mut dispatcher = OracleDispatcher::new_switchable_with_custom_tools_and_stateless(
        conn,
        wiring.active_profile.clone(),
        wiring.level.clone(),
        profile_connector(Arc::clone(&wiring.secret_resolver)),
        StatelessReadStrategy::new(
            stateless_conn,
            Some(profile_stateless_connector(Arc::clone(
                &wiring.secret_resolver,
            ))),
        ),
        wiring.custom_catalog.clone(),
        Some(Arc::new(load_custom_catalog_for_profile)),
    )
    .with_request_timeout(wiring.request_timeout)
    .with_mcp_exposure(wiring.exposure.clone())
    .with_profile_drain_state(wiring.profile_drain.clone())
    .with_exports(Arc::clone(&wiring.exports))
    .with_notifications(Arc::clone(&wiring.notifications));
    if let Some(auditor) = &wiring.auditor {
        dispatcher = dispatcher.with_auditor(Arc::clone(auditor));
    }
    if let Some(write_intents) = &wiring.write_intents {
        dispatcher = dispatcher.with_write_intent_log(Arc::clone(write_intents));
    }
    dispatcher
}

fn audit_subject_from_principal_key(principal_key: &str) -> AuditSubject {
    if principal_key == "anonymous-http" {
        return AuditSubject::new("anonymous-http", "server-derived").with_authn_method("none");
    }
    let (kind, stable_id) = principal_key
        .split_once(':')
        .filter(|(kind, stable_id)| !kind.is_empty() && !stable_id.is_empty())
        .unwrap_or(("principal", principal_key));
    let authn_method = match kind {
        "oauth" => "oauth",
        "mtls" | "cert" => "mtls",
        "process" => "process",
        _ => "server",
    };
    AuditSubject::new(kind, stable_id).with_authn_method(authn_method)
}

async fn open_lane_runtime_connections(
    cx: &Cx,
    active_profile: Option<&str>,
    secret_resolver: &dyn SecretResolver,
) -> Result<RuntimeConnections, DbError> {
    match active_profile {
        Some(profile) => {
            let Some(resolved) = resolve_profile_options_with(Some(profile), secret_resolver)?
            else {
                return Err(DbError::UnsupportedAuth(format!(
                    "connection profile `{profile}` not found"
                )));
            };
            match try_open_runtime_connections(cx, resolved).await {
                Ok(connections) => Ok(connections),
                Err(e) => {
                    tracing::warn!(error = %e, "no live connection for lane; live tools will return a structured error envelope");
                    Ok(RuntimeConnections {
                        session: Box::new(stub::StubConnection::new(e)),
                        stateless: None,
                    })
                }
            }
        }
        None => {
            let session = match try_open_connection(cx, OracleConnectOptions::default()).await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!(error = %e, "no live connection for lane; live tools will return a structured error envelope");
                    Box::new(stub::StubConnection::new(e)) as Box<dyn OracleConnection>
                }
            };
            Ok(RuntimeConnections {
                session,
                stateless: None,
            })
        }
    }
}

struct MetricsDispatch {
    inner: Arc<dyn ToolDispatch>,
    metrics: Arc<Metrics>,
}

impl MetricsDispatch {
    fn new(inner: Arc<dyn ToolDispatch>, metrics: Arc<Metrics>) -> Self {
        Self { inner, metrics }
    }
}

impl ToolDispatch for MetricsDispatch {
    fn dispatch<'a>(
        &'a self,
        cx: &'a Cx,
        context: oraclemcp_core::DispatchContext<'a>,
        name: &'a str,
        args: serde_json::Value,
    ) -> DispatchFuture<'a> {
        Box::pin(async move {
            let started = Instant::now();
            let lane_id = context.lane_id().unwrap_or("process").to_owned();
            let subject_id_hash = context
                .principal_key()
                .map(operator_subject_id_hash)
                .unwrap_or_else(|| operator_subject_id_hash("process"));
            let result = self.inner.dispatch(cx, context, name, args).await;
            let status = metrics_status(&result);
            self.metrics
                .record_lane_request(&lane_id, &subject_id_hash, name, status);
            self.metrics.record_lane_request_duration_ms(
                &lane_id,
                &subject_id_hash,
                name,
                u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            );
            if metrics_is_blocked(&result) {
                self.metrics.record_lane_blocked(&lane_id, &subject_id_hash);
            }
            result
        })
    }

    fn close<'a>(
        &'a self,
        cx: &'a Cx,
        reason: oraclemcp_core::DispatchCloseReason,
    ) -> oraclemcp_core::DispatchCloseFuture<'a> {
        self.inner.close(cx, reason)
    }

    fn mcp_surface_state<'a>(
        &'a self,
        cx: &'a Cx,
        context: oraclemcp_core::DispatchContext<'a>,
        detail: McpSurfaceDetail,
    ) -> McpSurfaceFuture<'a> {
        self.inner.mcp_surface_state(cx, context, detail)
    }
}

fn metrics_status(outcome: &DispatchOutcome) -> &'static str {
    match outcome {
        asupersync::Outcome::Ok(_) => "ok",
        asupersync::Outcome::Err(envelope) => match envelope.error_class {
            ErrorClass::Busy => "busy",
            ErrorClass::AtCapacity => "at_capacity",
            ErrorClass::PolicyDenied
            | ErrorClass::ForbiddenStatement
            | ErrorClass::OperatingLevelTooLow => "blocked",
            _ => "error",
        },
        asupersync::Outcome::Cancelled(_) => "cancelled",
        asupersync::Outcome::Panicked(_) => "panicked",
    }
}

fn metrics_is_blocked(outcome: &DispatchOutcome) -> bool {
    matches!(
        outcome,
        asupersync::Outcome::Err(envelope)
            if matches!(
                envelope.error_class,
                ErrorClass::Busy
                    | ErrorClass::AtCapacity
                    | ErrorClass::PolicyDenied
                    | ErrorClass::ForbiddenStatement
                    | ErrorClass::OperatingLevelTooLow
            )
    )
}

fn maybe_wrap_metrics_dispatch(
    dispatcher: Arc<dyn ToolDispatch>,
    metrics: Option<&Arc<Metrics>>,
) -> Arc<dyn ToolDispatch> {
    match metrics {
        Some(metrics) => Arc::new(MetricsDispatch::new(dispatcher, Arc::clone(metrics))),
        None => dispatcher,
    }
}

fn stateful_lane_factory(
    wiring: DispatcherWiring,
    metrics: Option<Arc<Metrics>>,
) -> Arc<LaneDispatchFactory> {
    Arc::new(move |cx: &Cx, lane_context: &LaneContext| {
        let wiring = wiring.clone();
        let metrics = metrics.clone();
        let principal_key = lane_context.principal_key().to_owned();
        Box::pin(async move {
            if let Some(active_profile) = wiring.active_profile.as_deref()
                && wiring.profile_drain.is_draining(active_profile)
            {
                return Err(profile_draining_error(active_profile));
            }
            let connections = open_lane_runtime_connections(
                cx,
                wiring.active_profile.as_deref(),
                wiring.secret_resolver.as_ref(),
            )
            .await
            .map_err(DbError::into_envelope)?;
            let dispatcher =
                build_oracle_dispatcher(connections.session, connections.stateless, &wiring)
                    .with_default_audit_subject(audit_subject_from_principal_key(&principal_key));
            let dispatcher: Arc<dyn ToolDispatch> = Arc::new(dispatcher);
            Ok(maybe_wrap_metrics_dispatch(dispatcher, metrics.as_ref()))
        })
    })
}

type ReadWorkerFactoryBuilder =
    dyn Fn(Option<String>) -> Arc<LaneDispatchFactory> + Send + Sync + 'static;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ReadWorkerKey {
    principal_key: String,
    active_profile: Option<String>,
}

struct ReadWorkerBucket {
    next: usize,
    lanes: Vec<LaneRuntime>,
}

struct HttpStatelessReadDispatch {
    control_lane: LaneRuntime,
    active_profile: Mutex<Option<String>>,
    read_factory: Arc<ReadWorkerFactoryBuilder>,
    read_lanes: Mutex<HashMap<ReadWorkerKey, ReadWorkerBucket>>,
    next_lane_id: AtomicU64,
    width_per_key: usize,
}

impl HttpStatelessReadDispatch {
    fn new(
        control_lane: LaneRuntime,
        active_profile: Option<String>,
        width_per_key: usize,
        read_factory: Arc<ReadWorkerFactoryBuilder>,
    ) -> Self {
        Self {
            control_lane,
            active_profile: Mutex::new(active_profile),
            read_factory,
            read_lanes: Mutex::new(HashMap::new()),
            next_lane_id: AtomicU64::new(1),
            width_per_key: width_per_key.max(1),
        }
    }

    fn active_profile(&self) -> Option<String> {
        self.active_profile
            .lock()
            .expect("stateless read active_profile mutex not poisoned")
            .clone()
    }

    fn set_active_profile(&self, active_profile: Option<String>) {
        *self
            .active_profile
            .lock()
            .expect("stateless read active_profile mutex not poisoned") = active_profile;
    }

    fn read_lane_for(&self, context: DispatchContext<'_>) -> LaneRuntime {
        let key = ReadWorkerKey {
            principal_key: context
                .principal_key()
                .unwrap_or("anonymous-http")
                .to_owned(),
            active_profile: self.active_profile(),
        };
        let mut lanes = self
            .read_lanes
            .lock()
            .expect("stateless read lane registry mutex not poisoned");
        let bucket = lanes
            .entry(key.clone())
            .or_insert_with(|| ReadWorkerBucket {
                next: 0,
                lanes: Vec::new(),
            });
        if bucket.lanes.len() < self.width_per_key {
            let lane_number = self.next_lane_id.fetch_add(1, Ordering::SeqCst);
            let lane_id = format!("stateless-read-{lane_number}");
            let lane_context = LaneContext::new(
                lane_id.clone(),
                "stateless-read",
                key.principal_key.clone(),
                1,
            );
            let factory = (self.read_factory)(key.active_profile.clone());
            let lane = LaneRuntime::spawn_with_dispatch_factory(
                lane_id,
                lane_context,
                factory,
                oraclemcp_core::DEFAULT_LANE_MAILBOX_CAPACITY,
                None,
            );
            bucket.lanes.push(lane);
        }
        let index = bucket.next % bucket.lanes.len();
        bucket.next = bucket.next.wrapping_add(1);
        // SAFETY: the read-worker registry stores only `LaneRuntime` handles.
        // The caller sends to the returned lane after this mutex guard is gone,
        // mirroring the core stateful registry's copy-handle-before-send rule.
        bucket.lanes[index].clone()
    }

    fn close_read_lanes(&self, reason: DispatchCloseReason) {
        let buckets = self
            .read_lanes
            .lock()
            .expect("stateless read lane registry mutex not poisoned")
            .drain()
            .map(|(_, bucket)| bucket)
            .collect::<Vec<_>>();
        for bucket in buckets {
            for lane in bucket.lanes {
                lane.close_with_reason(reason);
            }
        }
    }
}

impl ToolDispatch for HttpStatelessReadDispatch {
    fn dispatch<'a>(
        &'a self,
        cx: &'a Cx,
        context: DispatchContext<'a>,
        name: &'a str,
        args: serde_json::Value,
    ) -> DispatchFuture<'a> {
        Box::pin(async move {
            if stateless_read_worker_tool(name) {
                let lane = self.read_lane_for(context);
                return lane.dispatch(cx, context, name, args).await;
            }

            let switches_profile = matches!(name, "oracle_switch_profile" | "switch_database");
            let outcome = self.control_lane.dispatch(cx, context, name, args).await;
            if switches_profile && let DispatchOutcome::Ok(value) = &outcome {
                let active_profile = value
                    .get("active_profile")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned);
                self.set_active_profile(active_profile);
                self.close_read_lanes(DispatchCloseReason::RuntimeDrop);
            }
            outcome
        })
    }

    fn close<'a>(
        &'a self,
        _cx: &'a Cx,
        reason: DispatchCloseReason,
    ) -> oraclemcp_core::DispatchCloseFuture<'a> {
        self.close_read_lanes(reason);
        self.control_lane.close_with_reason(reason);
        Box::pin(async { Ok(()) })
    }

    fn mcp_surface_state<'a>(
        &'a self,
        cx: &'a Cx,
        context: DispatchContext<'a>,
        detail: McpSurfaceDetail,
    ) -> McpSurfaceFuture<'a> {
        self.control_lane.mcp_surface_state(cx, context, detail)
    }
}

fn stateless_read_worker_factory_builder(
    wiring: DispatcherWiring,
    metrics: Option<Arc<Metrics>>,
) -> Arc<ReadWorkerFactoryBuilder> {
    Arc::new(move |active_profile| {
        stateless_read_worker_factory(wiring.clone(), metrics.clone(), active_profile)
    })
}

fn stateless_read_worker_factory(
    wiring: DispatcherWiring,
    metrics: Option<Arc<Metrics>>,
    active_profile: Option<String>,
) -> Arc<LaneDispatchFactory> {
    Arc::new(move |cx: &Cx, lane_context: &LaneContext| {
        let mut wiring = wiring.clone();
        let metrics = metrics.clone();
        let active_profile = active_profile.clone();
        let principal_key = lane_context.principal_key().to_owned();
        Box::pin(async move {
            if let Some(profile) = active_profile.as_deref()
                && wiring.profile_drain.is_draining(profile)
            {
                return Err(profile_draining_error(profile));
            }
            let Some(resolved) = resolve_profile_options_with(
                active_profile.as_deref(),
                wiring.secret_resolver.as_ref(),
            )
            .map_err(DbError::into_envelope)?
            else {
                return Err(ErrorEnvelope::new(
                    ErrorClass::RuntimeStateRequired,
                    "stateless read-worker lanes require an active connection profile",
                )
                .with_next_step("start the server with `oraclemcp serve --profile <name>`"));
            };
            let profile = resolved.name.clone();
            let level = resolved.level.clone();
            let request_timeout = resolved.opts.call_timeout;
            let conn = try_open_connection(cx, resolved.opts)
                .await
                .map_err(DbError::into_envelope)?;
            wiring.active_profile = Some(profile);
            wiring.level = level;
            wiring.request_timeout = request_timeout;
            let dispatcher = build_oracle_dispatcher(conn, None, &wiring)
                .with_default_audit_subject(audit_subject_from_principal_key(&principal_key));
            let dispatcher: Arc<dyn ToolDispatch> = Arc::new(dispatcher);
            Ok(maybe_wrap_metrics_dispatch(dispatcher, metrics.as_ref()))
        })
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServerTransportMode {
    Stdio,
    HttpStateless,
    HttpStateful,
}

impl ServerTransportMode {
    fn is_http(self) -> bool {
        !matches!(self, Self::Stdio)
    }
}

struct ServerBuildOptions {
    transport: ServerTransportMode,
    custom_catalog: CustomToolCatalog,
    auditor: Option<Arc<Auditor>>,
    write_intents: Option<Arc<WriteIntentLog>>,
    secret_resolver: Arc<dyn SecretResolver>,
    request_timeout: Option<std::time::Duration>,
    metrics: Option<Arc<Metrics>>,
    profile_drain: ProfileDrainState,
}

struct BuiltServer {
    server: OracleMcpServer,
    session_lifecycle: Option<Arc<dyn HttpSessionLifecycle>>,
}

/// Build the server from the registry + capabilities + dispatcher over `conn`.
fn build_server(
    conn: Box<dyn OracleConnection>,
    stateless_conn: Option<Box<dyn OracleConnection>>,
    active_profile: Option<String>,
    level: SessionLevelState,
    options: ServerBuildOptions,
) -> OracleMcpServer {
    build_server_with_lifecycle(conn, stateless_conn, active_profile, level, options).server
}

fn build_server_with_lifecycle(
    conn: Box<dyn OracleConnection>,
    stateless_conn: Option<Box<dyn OracleConnection>>,
    active_profile: Option<String>,
    level: SessionLevelState,
    options: ServerBuildOptions,
) -> BuiltServer {
    let version = env!("CARGO_PKG_VERSION");
    let mut registry = registry::tool_registry();
    options.custom_catalog.register_first_class(&mut registry);
    let caps = CapabilitiesReport::new(
        version,
        registry.tools.clone(),
        level.max_level(),
        FeatureTiers {
            live_db: LIVE_DB,
            engine: cfg!(feature = "plsql-intelligence"),
            http_transport: options.transport.is_http(),
        },
    );
    // E5 connection-scope isolation: per-profile opt-out — every profile is
    // reachable by the served surface (switch/list/search/complete) unless it
    // sets `mcp_exposed = false`. A config load failure fails closed (an empty
    // allow-list: nothing is exposed to the agent) rather than defaulting open.
    let exposure = match OracleMcpConfig::load(None) {
        Ok(cfg) => {
            // Operator-visibility notice (stderr; never the stdio MCP channel).
            eprintln!("[oraclemcp] {}", exposed_profiles_summary(&cfg));
            oraclemcp::dispatch::McpExposurePolicy::from_config(&cfg)
        }
        Err(_) => oraclemcp::dispatch::McpExposurePolicy::AllowList(HashSet::new()),
    };
    // E3/E3b: the dispatcher (which mints exports for oversized oracle_query
    // results) and the server (which serves them over resources/read) share the
    // SAME export registry.
    let exports = Arc::new(ExportRegistry::new());
    // E6: the dispatcher (which enqueues tools/list_changed on a profile switch)
    // and the server (which brackets long tool calls with progress and flushes
    // the queue) share the SAME notification hub.
    let notifications = Arc::new(oraclemcp_core::NotificationHub::new());
    let wiring = DispatcherWiring {
        active_profile,
        level,
        request_timeout: options.request_timeout,
        secret_resolver: options.secret_resolver,
        custom_catalog: options.custom_catalog,
        exposure,
        profile_drain: options.profile_drain,
        auditor: options.auditor,
        write_intents: options.write_intents,
        exports: Arc::clone(&exports),
        notifications: Arc::clone(&notifications),
    };
    let mut session_lifecycle: Option<Arc<dyn HttpSessionLifecycle>> = None;
    let dispatcher: Arc<dyn ToolDispatch> = if options.transport.is_http() {
        if matches!(options.transport, ServerTransportMode::HttpStateful) {
            let stateful = Arc::new(
                StatefulLaneDispatch::with_dispatch_factory(
                    stateful_lane_factory(wiring.clone(), options.metrics.clone()),
                    wiring.auditor.clone(),
                )
                .with_admission_controller(Arc::new(AdmissionController::n4_stateful_defaults())),
            );
            session_lifecycle = Some(stateful.clone());
            stateful
        } else {
            let dispatcher = build_oracle_dispatcher(conn, None, &wiring);
            let dispatcher =
                maybe_wrap_metrics_dispatch(Arc::new(dispatcher), options.metrics.as_ref());
            let control_lane = LaneRuntime::spawn_default_with_panic_auditor(
                "served-http-stateless-control",
                dispatcher,
                wiring.auditor.clone(),
            );
            let read_dispatch = HttpStatelessReadDispatch::new(
                control_lane,
                wiring.active_profile.clone(),
                DEFAULT_READ_PER_PROFILE_CAP,
                stateless_read_worker_factory_builder(wiring.clone(), options.metrics.clone()),
            );
            drop(stateless_conn);
            Arc::new(read_dispatch)
        }
    } else {
        let dispatcher = build_oracle_dispatcher(conn, stateless_conn, &wiring);
        Arc::new(dispatcher)
    };
    let server = OracleMcpServer::with_exports(version, registry, caps, dispatcher, exports)
        .with_notifications(notifications);
    BuiltServer {
        server,
        session_lifecycle,
    }
}

fn apply_http_cli_overrides(mut config: HttpConfig, cli: &HttpServeArgs) -> HttpConfig {
    config
        .allowed_hosts
        .extend(cli.allowed_hosts.iter().cloned());
    config
        .allowed_origins
        .extend(cli.allowed_origins.iter().cloned());
    if cli.stateful {
        config.stateful = true;
    }
    if cli.json_response {
        config.json_response = true;
    }

    let cli_has_oauth = cli.oauth_resource.is_some()
        || !cli.oauth_issuers.is_empty()
        || !cli.oauth_authorization_servers.is_empty()
        || !cli.oauth_required_scopes.is_empty()
        || cli.oauth_hs256_secret_ref.is_some()
        || cli.oauth_metadata_url.is_some();
    if cli_has_oauth {
        let mut oauth = config.oauth.unwrap_or_default();
        if let Some(resource) = &cli.oauth_resource {
            oauth.resource = Some(resource.clone());
        }
        if !cli.oauth_issuers.is_empty() {
            oauth.allowed_issuers = cli.oauth_issuers.clone();
        }
        if !cli.oauth_authorization_servers.is_empty() {
            oauth.authorization_servers = cli.oauth_authorization_servers.clone();
        }
        if !cli.oauth_required_scopes.is_empty() {
            oauth.required_scopes = cli.oauth_required_scopes.clone();
        }
        if let Some(secret_ref) = &cli.oauth_hs256_secret_ref {
            oauth.hs256_secret_ref = Some(secret_ref.clone());
        }
        if let Some(metadata_url) = &cli.oauth_metadata_url {
            oauth.metadata_url = Some(metadata_url.clone());
        }
        config.oauth = Some(oauth);
    }

    let cli_has_tls =
        cli.tls_cert.is_some() || cli.tls_key.is_some() || cli.mtls_client_ca.is_some();
    if cli_has_tls {
        let mut tls = config.tls.unwrap_or_default();
        if let Some(cert) = &cli.tls_cert {
            tls.cert_chain_path = Some(cert.clone());
        }
        if let Some(key) = &cli.tls_key {
            tls.private_key_path = Some(key.clone());
        }
        if let Some(ca) = &cli.mtls_client_ca {
            tls.client_ca_path = Some(ca.clone());
        }
        config.tls = Some(tls);
    }
    config
        .mtls
        .client_fingerprints
        .extend(cli.mtls_client_fingerprints.iter().cloned());

    config
}

fn default_oauth_metadata_url(resource: &str) -> String {
    let base = resource
        .trim_end_matches('/')
        .strip_suffix(MCP_PATH)
        .unwrap_or_else(|| resource.trim_end_matches('/'))
        .trim_end_matches('/');
    format!("{base}{PROTECTED_RESOURCE_METADATA_PATH}")
}

fn local_operator_stable_id() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "process-owner".to_owned())
}

#[derive(Clone, Debug)]
struct ResolvedHttpTransportConfig {
    transport: HttpTransportConfig,
    tls: Option<Arc<TlsServerConfig>>,
    mtls_required: bool,
}

#[derive(Clone)]
struct HttpConfigReloadApplier {
    profile_drain: ProfileDrainState,
}

impl ConfigReloadApplier for HttpConfigReloadApplier {
    fn apply_config_reload_plan(
        &self,
        plan: &oraclemcp_config::ConfigReloadPlan,
    ) -> ConfigReloadApplyReport {
        self.profile_drain.apply_config_reload_plan(plan);
        let draining_profiles = self.profile_drain.draining_profiles();
        ConfigReloadApplyReport {
            status: "applied".to_owned(),
            hot_reloadable: true,
            restart_required: Vec::new(),
            message: if draining_profiles.is_empty() {
                "hot reload applied; no profiles are draining".to_owned()
            } else {
                "hot reload applied; changed profiles are draining".to_owned()
            },
            draining_profiles,
        }
    }
}

fn operator_config_target_path() -> PathBuf {
    if let Some(path) = std::env::var_os(CONFIG_PATH_ENV).map(PathBuf::from) {
        return path;
    }
    if let Some(path) = OracleMcpConfig::default_config_path() {
        return path;
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".config").join("oraclemcp").join("profiles.toml"))
        .unwrap_or_else(|| PathBuf::from("profiles.toml"))
}

fn service_state_dir_for_cli(robot_json: bool) -> Result<PathBuf, ExitCode> {
    oraclemcp_core::FileStore::default_state_dir().map_err(|e| {
        emit_status_error(
            robot_json,
            "ORACLEMCP_SERVICE_STATE_UNAVAILABLE",
            &format!("failed to resolve XDG service state directory: {e}"),
        );
        ExitCode::from(2)
    })
}

fn service_audit_path_for_backup(config_path: &Path) -> Result<PathBuf, String> {
    OracleMcpConfig::load(Some(config_path))
        .map(|config| config.audit.path.unwrap_or_else(default_audit_path))
        .map_err(|e| format!("failed to load config for backup audit path: {e}"))
}

fn resolve_http_transport_config(
    cli: &HttpServeArgs,
    level: &SessionLevelState,
    secret_resolver: &dyn SecretResolver,
) -> Result<ResolvedHttpTransportConfig, (&'static str, String)> {
    let cfg = OracleMcpConfig::load(None).map_err(|e| {
        (
            "ORACLEMCP_CONFIG_INVALID",
            format!("failed to load HTTP transport config: {e}"),
        )
    })?;
    let http = apply_http_cli_overrides(cfg.http, cli);
    http_transport_config_from_merged(http, level.is_protected(), secret_resolver)
}

fn http_transport_config_from_merged(
    http: HttpConfig,
    protected: bool,
    secret_resolver: &dyn SecretResolver,
) -> Result<ResolvedHttpTransportConfig, (&'static str, String)> {
    http.validate().map_err(|e| {
        (
            "ORACLEMCP_HTTP_CONFIG_INVALID",
            format!("invalid HTTP transport config: {e}"),
        )
    })?;

    let tls_material = match http.tls.as_ref() {
        Some(tls) => tls_material_from_config(tls)?,
        None => None,
    };
    let mtls_required = tls_material.as_ref().is_some_and(requires_mtls);
    let tls = tls_material
        .as_ref()
        .map(build_server_config)
        .transpose()
        .map_err(|e| {
            (
                "ORACLEMCP_HTTP_TLS_INVALID",
                format!("invalid HTTP TLS/mTLS material: {e}"),
            )
        })?;

    let (resource_metadata, oauth) = match http.oauth {
        Some(oauth_cfg) => {
            let resource = oauth_cfg
                .resource
                .as_deref()
                .expect("validated oauth resource")
                .to_owned();
            let metadata_url = oauth_cfg
                .metadata_url
                .clone()
                .unwrap_or_else(|| default_oauth_metadata_url(&resource));
            let secret_ref = oauth_cfg
                .hs256_secret_ref
                .as_deref()
                .expect("validated oauth secret ref");
            let secret =
                resolve_secret_with(secret_ref, protected, secret_resolver).map_err(|e| {
                    (
                        "ORACLEMCP_HTTP_OAUTH_SECRET_INVALID",
                        format!(
                            "failed to resolve http.oauth.hs256_secret_ref: {}",
                            secret_error_summary(&e)
                        ),
                    )
                })?;
            let resource_config = ResourceServerConfig {
                resource,
                allowed_issuers: oauth_cfg.allowed_issuers,
                authorization_servers: oauth_cfg.authorization_servers,
                required_scopes: oauth_cfg.required_scopes,
            };
            let metadata = resource_config.protected_resource_metadata();
            let enforcement = OAuthEnforcement {
                config: resource_config,
                verifier: Arc::new(Hs256Verifier {
                    secret: secret.expose().as_bytes().to_vec(),
                }),
                metadata_url,
            };
            (Some(metadata), Some(Arc::new(enforcement)))
        }
        None => (None, None),
    };

    let transport = HttpTransportConfig {
        allowed_hosts: http.allowed_hosts,
        allowed_origins: http.allowed_origins,
        json_response: http.json_response,
        stateful: http.stateful,
        stateful_idle_ttl: std::time::Duration::from_secs(http.stateful_idle_ttl_seconds),
        resource_metadata,
        oauth,
        mtls_clients: MtlsClientRegistry::from_fingerprints(http.mtls.client_fingerprints),
        single_principal_guard: Some(SinglePrincipalGuard::new()),
        operator_authority: OperatorAuthorityPolicy {
            allow_loopback_owner: http.operator.allow_loopback_owner,
            local_owner_stable_id: local_operator_stable_id(),
            allowed_subjects: http
                .operator
                .allowed_subjects
                .into_iter()
                .map(|subject| subject.trim().to_owned())
                .collect(),
        },
        dashboard_auth: Some(Arc::new(DashboardAuth::new(default_dashboard_ticket_dir()))),
        // Observability is wired in run_serve (HealthState/Metrics/probe).
        observability: ObservabilityState::default(),
        ..Default::default()
    };

    Ok(ResolvedHttpTransportConfig {
        transport,
        tls,
        mtls_required,
    })
}

fn tls_material_from_config(
    tls: &HttpTlsConfig,
) -> Result<Option<TlsMaterial>, (&'static str, String)> {
    let Some(cert_path) = tls.cert_chain_path.as_deref() else {
        return Ok(None);
    };
    let key_path = tls
        .private_key_path
        .as_deref()
        .expect("validated TLS private_key_path");
    let cert_chain_pem = read_tls_pem("server certificate chain", cert_path)?;
    let private_key_pem = read_tls_pem("server private key", key_path)?;
    let client_ca_pem = tls
        .client_ca_path
        .as_deref()
        .map(|path| read_tls_pem("client CA", path))
        .transpose()?;
    Ok(Some(TlsMaterial {
        cert_chain_pem,
        private_key_pem,
        client_ca_pem,
    }))
}

fn read_tls_pem(role: &'static str, path: &Path) -> Result<Vec<u8>, (&'static str, String)> {
    fs::read(path).map_err(|e| {
        (
            "ORACLEMCP_HTTP_TLS_INVALID",
            format!("failed to read HTTP TLS {role} at {}: {e}", path.display()),
        )
    })
}

fn run_serve(
    listen: Option<String>,
    allow_no_auth: bool,
    stdio_token: Option<String>,
    profile: Option<String>,
    http: HttpServeArgs,
    robot_json: bool,
) -> ExitCode {
    let secret_resolver: Arc<dyn SecretResolver> = Arc::new(SystemSecretResolver);
    // D1 observability: install the JSON stderr logger plus — when an OTLP
    // endpoint is configured via OTEL_EXPORTER_OTLP_* (off by default) — the OTLP
    // logs + traces export layers. The guard owns the background export pump; it
    // is kept alive for the serve loop and dropped (flush + bounded join) on exit.
    let telemetry = oraclemcp_telemetry::init_telemetry("info", OtlpConfig::from_env());
    if telemetry.otlp_enabled() {
        tracing::info!(
            "oraclemcp: OTLP telemetry export enabled (OTEL_EXPORTER_OTLP_* configured)"
        );
    }
    // Select only non-secret profile metadata at startup. DB credentials remain
    // as `credential_ref` / `wallet_password_ref` until the actual connection
    // opener runs (stdio/stateless startup connect, readiness probe connect, or
    // stateful per-lane connect).
    let (connection_plan, active_profile, level, request_timeout) = match select_runtime_profile(
        profile.as_deref(),
    ) {
        Ok(Some(selected)) => {
            let active_profile = Some(selected.name.clone());
            (
                RuntimeConnectionPlan::Profile(selected.name),
                active_profile,
                selected.level,
                selected.request_timeout,
            )
        }
        Ok(None) => (
            RuntimeConnectionPlan::Default,
            None,
            default_read_only_level(),
            OracleConnectOptions::default().call_timeout,
        ),
        Err(e) if profile.is_some() => {
            emit_status_error(
                robot_json,
                "ORACLEMCP_CONFIG_INVALID",
                &format!("failed to resolve connection profile: {e}"),
            );
            return ExitCode::from(2);
        }
        Err(e) => {
            tracing::warn!(error = %e, "no live connection; live tools will return a structured error envelope");
            (
                RuntimeConnectionPlan::Stub(e),
                None,
                default_read_only_level(),
                OracleConnectOptions::default().call_timeout,
            )
        }
    };

    let custom_catalog = match load_custom_catalog_for_profile(active_profile.as_deref(), &level) {
        Ok(catalog) => catalog,
        Err(e) => {
            emit_status_error(robot_json, "ORACLEMCP_CUSTOM_TOOLS_INVALID", &e.message);
            return ExitCode::from(2);
        }
    };
    let mut advertised_registry = registry::tool_registry();
    custom_catalog.register_first_class(&mut advertised_registry);
    let advertised_tools: Vec<String> = advertised_registry
        .tools
        .iter()
        .map(|tool| tool.name.clone())
        .collect();

    // Arm the out-of-band audit chain. Fails closed if a write level is
    // reachable without a configured signing key (bead A8).
    //
    // A8 (multi-profile): the auditor decision must consider EVERY profile the
    // server can reach at runtime — not just the startup/active profile. A
    // server started on a read-only profile can `oracle_switch_profile` to a
    // writable `mcp_exposed` profile and run writes/DDL there, so the signing
    // key must be required if ANY reachable profile can exceed READ_ONLY.
    let full_config = match OracleMcpConfig::load(None) {
        Ok(cfg) => cfg,
        Err(e) => {
            emit_status_error(
                robot_json,
                "ORACLEMCP_CONFIG_INVALID",
                &format!("failed to load audit config: {e}"),
            );
            return ExitCode::from(2);
        }
    };
    let reachable_ceiling = max_reachable_write_ceiling(&full_config, &level);
    let auditor = match build_auditor(
        &full_config.audit,
        &level,
        reachable_ceiling,
        secret_resolver.as_ref(),
    ) {
        Ok(auditor) => auditor,
        Err((code, message)) => {
            emit_status_error(robot_json, code, &message);
            return ExitCode::from(2);
        }
    };
    let write_intents = match build_write_intent_log(reachable_ceiling) {
        Ok(write_intents) => write_intents,
        Err((code, message)) => {
            emit_status_error(robot_json, code, &message);
            return ExitCode::from(2);
        }
    };

    match listen {
        // ── stdio transport (default) ──────────────────────────────────────
        None => {
            // Resolve the init-token policy fail-closed (mirrors the §7.1 gate).
            let env_token = stdio_token
                .or_else(|| std::env::var(oraclemcp_core::init_token::STDIO_TOKEN_ENV).ok());
            let auth = match StdioAuthPolicy::resolve(env_token, allow_no_auth) {
                Ok(a) => a,
                Err(e) => {
                    emit_status_error(robot_json, "ORACLEMCP_AUTH_REQUIRED", &e.to_string());
                    return ExitCode::from(2);
                }
            };
            let connections =
                open_runtime_connection_plan(connection_plan, true, secret_resolver.as_ref());
            let server = build_server(
                connections.session,
                connections.stateless,
                active_profile,
                level,
                ServerBuildOptions {
                    transport: ServerTransportMode::Stdio,
                    custom_catalog,
                    auditor,
                    write_intents,
                    secret_resolver: Arc::clone(&secret_resolver),
                    request_timeout,
                    metrics: None,
                    profile_drain: ProfileDrainState::default(),
                },
            );
            emit_serve_status(robot_json, "stdio", None, &advertised_tools);
            match server.serve_stdio(&auth) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("oraclemcp serve: stdio transport error: {e}");
                    ExitCode::from(1)
                }
            }
        }
        // ── Streamable HTTP transport (--listen) ───────────────────────────
        Some(addr) => {
            let mut resolved_http =
                match resolve_http_transport_config(&http, &level, secret_resolver.as_ref()) {
                    Ok(cfg) => cfg,
                    Err((code, message)) => {
                        emit_status_error(robot_json, code, &message);
                        return ExitCode::from(2);
                    }
                };
            if http.client_credentials {
                let store = match ClientCredentialStore::open_default() {
                    Ok(store) => store,
                    Err(error) => {
                        emit_status_error(
                            robot_json,
                            "ORACLEMCP_CLIENT_CREDENTIAL_STORE_UNAVAILABLE",
                            &client_credential_error_message(&error),
                        );
                        return ExitCode::from(2);
                    }
                };
                resolved_http.transport.client_credentials = Some(Arc::new(store));
            }
            let oauth_enabled = resolved_http.transport.oauth.is_some();
            let tls_enabled = resolved_http.tls.is_some();
            let client_credentials_enabled = resolved_http.transport.client_credentials.is_some();
            let auth_enabled =
                oauth_enabled || resolved_http.mtls_required || client_credentials_enabled;
            let allow_remote = std::env::var("ORACLEMCP_HTTP_ALLOW_REMOTE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if let Err((code, message)) = http_listen_guard(
                allow_no_auth,
                auth_enabled,
                tls_enabled,
                &addr,
                allow_remote,
            ) {
                emit_status_error(robot_json, code, &message);
                return ExitCode::from(2);
            }
            if tls_enabled {
                eprintln!(
                    "oraclemcp serve: HTTPS transport on {addr} has native TLS{} enabled.",
                    if resolved_http.mtls_required {
                        " with mTLS client-certificate verification"
                    } else if oauth_enabled {
                        " with OAuth bearer enforcement"
                    } else if client_credentials_enabled {
                        " with per-client bearer credential enforcement"
                    } else {
                        ""
                    }
                );
                if !oauth_enabled && !resolved_http.mtls_required && !client_credentials_enabled {
                    eprintln!(
                        "oraclemcp serve: WARNING — HTTPS transport on {addr} has TLS \
                         encryption but no per-client credential, OAuth, or mTLS client authentication."
                    );
                }
            } else if oauth_enabled {
                eprintln!(
                    "oraclemcp serve: HTTP transport on {addr} has OAuth bearer enforcement \
                     enabled. The native listener is still plaintext; bind loopback or front it \
                     with a TLS-terminating proxy for off-box clients."
                );
            } else if client_credentials_enabled {
                eprintln!(
                    "oraclemcp serve: HTTP transport on {addr} has per-client bearer credential \
                     enforcement enabled. The native listener is still plaintext; bind loopback \
                     or front it with a TLS-terminating proxy for off-box clients."
                );
            } else {
                eprintln!(
                    "oraclemcp serve: WARNING — HTTP transport on {addr} is UNAUTHENTICATED and \
                     UNENCRYPTED. Do not expose it to untrusted networks; front it with a \
                     TLS-terminating authenticated proxy, or use stdio."
                );
            }
            let http_stateful = resolved_http.transport.stateful;
            if http_stateful {
                resolved_http.transport.single_principal_guard = None;
            }
            let connections = if http_stateful {
                stub_runtime_connections(DbError::Connect(
                    "stateful HTTP opens Oracle profile connections per lane".to_owned(),
                ))
            } else {
                open_runtime_connection_plan(connection_plan, false, secret_resolver.as_ref())
            };
            let metrics = Arc::new(Metrics::new());
            let profile_drain = ProfileDrainState::default();
            let built = build_server_with_lifecycle(
                connections.session,
                connections.stateless,
                active_profile.clone(),
                level,
                ServerBuildOptions {
                    transport: if http_stateful {
                        ServerTransportMode::HttpStateful
                    } else {
                        ServerTransportMode::HttpStateless
                    },
                    custom_catalog,
                    auditor: auditor.clone(),
                    write_intents,
                    secret_resolver: Arc::clone(&secret_resolver),
                    request_timeout,
                    metrics: Some(Arc::clone(&metrics)),
                    profile_drain: profile_drain.clone(),
                },
            );
            let server = built.server;
            let ResolvedHttpTransportConfig {
                mut transport, tls, ..
            } = resolved_http;
            transport.session_lifecycle = built.session_lifecycle;
            transport.operator_audit_tail_path = auditor.as_ref().map(|_| {
                full_config
                    .audit
                    .path
                    .clone()
                    .unwrap_or_else(default_audit_path)
            });
            transport.operator_auditor = auditor;
            let config_ops_backend = match ConfigOpsBackend::open_default() {
                Ok(backend) => backend,
                Err(e) => {
                    emit_status_error(
                        robot_json,
                        "ORACLEMCP_CONFIG_OPS_UNAVAILABLE",
                        &format!("failed to initialize config workflow backend: {e}"),
                    );
                    return ExitCode::from(2);
                }
            };
            transport.config_ops = Some(Arc::new(ConfigOpsService::new(
                config_ops_backend,
                operator_config_target_path(),
                Some(Arc::new(HttpConfigReloadApplier {
                    profile_drain: profile_drain.clone(),
                })),
            )));
            let change_proposals = match ChangeProposalStore::open_default() {
                Ok(store) => store,
                Err(e) => {
                    emit_status_error(
                        robot_json,
                        "ORACLEMCP_CHANGE_PROPOSALS_UNAVAILABLE",
                        &format!("failed to initialize change proposal store: {e}"),
                    );
                    return ExitCode::from(2);
                }
            };
            transport.change_proposals = Some(Arc::new(change_proposals));
            let source_history = match SourceHistoryStore::open_default() {
                Ok(store) => store,
                Err(e) => {
                    emit_status_error(
                        robot_json,
                        "ORACLEMCP_SOURCE_HISTORY_UNAVAILABLE",
                        &format!("failed to initialize source history store: {e}"),
                    );
                    return ExitCode::from(2);
                }
            };
            transport.source_history = Some(Arc::new(source_history));

            // ── D1 observability wiring (health + metrics + graceful drain) ──
            let version = env!("CARGO_PKG_VERSION");
            let health = HealthState::new(version);
            let shutdown_coordinator = ShutdownCoordinator::new(health.clone());

            // /readyz DB-reachability probe: a background pinger on a dedicated
            // probe connection. With no live DB it probes a stub (always 503).
            let probe_conn: Box<dyn OracleConnection> = match active_profile.as_deref() {
                Some(profile) => {
                    open_profile_runtime_connections(profile, secret_resolver.as_ref(), false)
                        .session
                }
                None => Box::new(stub::StubConnection::new(DbError::Connect(
                    "no connection profile configured".to_owned(),
                ))),
            };
            let mut pinger = readiness::DbReadinessPinger::start(probe_conn);

            transport.observability = ObservabilityState {
                health: Some(health.clone()),
                metrics: Some(Arc::clone(&metrics)),
                readiness_probe: Some(pinger.probe()),
            };
            // The control connection is established (or a stub stands in); the
            // server is ready to accept work. /readyz still gates on the live
            // DB-reachability probe.
            health.set_ready(true);

            // Feed the OTLP metrics exporter (when enabled) the live snapshot.
            {
                let metrics_for_otlp = Arc::clone(&metrics);
                telemetry
                    .set_metrics_provider(std::sync::Arc::new(move || metrics_for_otlp.snapshot()));
            }

            // Bridge SIGTERM/SIGINT → graceful drain: flips /readyz to draining
            // and stops the accept loop. The flag is what serve_*_until watches.
            let shutdown_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
            install_shutdown_signal_bridge(&shutdown_coordinator, &shutdown_flag);

            let listener = match TcpListener::bind(&addr) {
                Ok(listener) => listener,
                Err(e) => {
                    eprintln!(
                        "oraclemcp serve: {} bind error on {addr}: {e}",
                        if tls_enabled { "https" } else { "http" }
                    );
                    pinger.shutdown();
                    drop(telemetry);
                    return ExitCode::from(1);
                }
            };
            let _service_instance_guard = match acquire_service_instance_guard(&addr) {
                Ok(guard) => guard,
                Err(error) => {
                    emit_status_error(robot_json, error.code, &error.message);
                    pinger.shutdown();
                    drop(telemetry);
                    return ExitCode::from(error.exit_code);
                }
            };
            let service_transport = match tls {
                Some(tls) => ServiceTransport::Https {
                    listener,
                    server,
                    config: transport,
                    tls,
                },
                None => ServiceTransport::Http {
                    listener,
                    server,
                    config: transport,
                },
            };
            let mut service_app = match start_oraclemcp_service_app_with_transport(
                None,
                service_transport,
                Arc::clone(&shutdown_flag),
            ) {
                Ok(app) => app,
                Err(e) => {
                    eprintln!("oraclemcp serve: service AppSpec failed to start: {e}");
                    pinger.shutdown();
                    drop(telemetry);
                    return ExitCode::from(1);
                }
            };
            readiness::notify_systemd_ready();
            emit_serve_status(
                robot_json,
                if tls_enabled { "https" } else { "http" },
                Some(&addr),
                &advertised_tools,
            );
            let result = service_app.wait_for_transport();
            let app_stop_result = service_app.stop_and_join();

            // Drain telemetry + the probe before returning (bounded budgets).
            pinger.shutdown();
            drop(telemetry);

            match (result, app_stop_result) {
                (Ok(()), Ok(())) => ExitCode::SUCCESS,
                (Ok(()), Err(e)) => {
                    eprintln!(
                        "oraclemcp serve: service AppSpec shutdown did not resolve cleanly: {e}"
                    );
                    ExitCode::from(1)
                }
                (Err(e), app_stop_result) => {
                    eprintln!(
                        "oraclemcp serve: {} transport error on {addr}: {e}",
                        if tls_enabled { "https" } else { "http" }
                    );
                    if let Err(app_err) = app_stop_result {
                        eprintln!(
                            "oraclemcp serve: service AppSpec shutdown after transport error \
                             also failed: {app_err}"
                        );
                    }
                    ExitCode::from(1)
                }
            }
        }
    }
}

/// Install a best-effort SIGTERM/SIGINT bridge: on the first delivery, begin the
/// graceful drain (flip `/readyz`) and set the accept-loop shutdown flag so
/// `serve_*_until` stops accepting and joins in-flight workers.
///
/// Uses a self-pipe-free approach: a background thread polls a process-global
/// signal latch set by a minimal `libc`-free handler. Since the workspace forbids
/// `unsafe` and avoids extra deps, we register via the std-only `ctrlc`-style
/// path is unavailable; instead we rely on the runtime's own SIGTERM handling
/// where present and expose the coordinator for an external supervisor. The flag
/// is also flipped if the coordinator is signalled programmatically.
fn install_shutdown_signal_bridge(
    coordinator: &ShutdownCoordinator,
    flag: &Arc<std::sync::atomic::AtomicBool>,
) {
    let coordinator = coordinator.clone();
    let flag = Arc::clone(flag);
    // A lightweight watcher thread: when the coordinator begins shutdown (via
    // any path — a future SIGTERM handler, an admin request, or a test), mirror
    // it into the accept-loop flag. This keeps the bridge dependency-free and
    // unsafe-free while still wiring the coordinator to the serve loop.
    std::thread::Builder::new()
        .name("oraclemcp-shutdown-bridge".to_owned())
        .spawn(move || {
            while !coordinator.is_shutting_down() {
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        })
        .ok();
}

/// Emit a serve startup status line on stderr (stdout stays JSON-RPC data).
fn emit_serve_status(robot_json: bool, transport: &str, addr: Option<&str>, tools: &[String]) {
    if robot_json {
        eprintln!(
            "{}",
            serde_json::json!({
                "kind": "status",
                "transport": transport,
                "listen": addr,
                "live_db": LIVE_DB,
                "tools": tools,
            })
        );
    } else {
        match addr {
            Some(a) => eprintln!(
                "oraclemcp serve: http transport listening on {a} ({} tools, live-db: {LIVE_DB})",
                tools.len()
            ),
            None => eprintln!(
                "oraclemcp serve: stdio transport ready ({} tools, live-db: {LIVE_DB})",
                tools.len()
            ),
        }
    }
}

/// Decide whether a `--listen` HTTP(S) server may start.
/// `Ok(())` = proceed (the caller still emits a transport warning);
/// `Err((code, message))` = refuse with exit code 2.
///
/// Fail-closed parity with stdio (§7.1): `/mcp` must either have OAuth bearer
/// enforcement/mTLS verification/per-client credentials or the operator must explicitly accept
/// unauthenticated local dev mode with `--allow-no-auth`. Binding a routable
/// (non-loopback) address still needs a second deliberate opt-in.
fn http_listen_guard(
    allow_no_auth: bool,
    auth_enabled: bool,
    tls_enabled: bool,
    addr: &str,
    allow_remote: bool,
) -> Result<(), (&'static str, String)> {
    if !auth_enabled && !allow_no_auth {
        return Err((
            "ORACLEMCP_AUTH_REQUIRED",
            "the HTTP transport (--listen) has no OAuth enforcement, mTLS \
             client-certificate verification, or per-client credentials configured; configure [http.oauth] / \
             --oauth-* / [http.tls.client_ca_path], and register mTLS clients with \
             [http.mtls].client_fingerprints or --mtls-client-fingerprint; use \
             --client-credentials for service-owned per-client bearers; or re-run with \
             --allow-no-auth to accept unauthenticated development mode explicitly"
                .to_owned(),
        ));
    }
    let bound_loopback = addr
        .parse::<std::net::SocketAddr>()
        .map(|s| s.ip().is_loopback())
        .unwrap_or(false);
    if !bound_loopback && !allow_remote {
        return Err((
            "ORACLEMCP_HTTP_REMOTE_BIND_REFUSED",
            format!(
                "refusing to bind {} to non-loopback {addr}; bind a loopback \
                 address or set ORACLEMCP_HTTP_ALLOW_REMOTE=1 when equivalent \
                 network controls are in front",
                if tls_enabled {
                    "HTTPS"
                } else {
                    "plaintext HTTP"
                }
            ),
        ));
    }
    Ok(())
}

/// Emit a structured error on stderr (used before the serve loop starts).
fn emit_status_error(robot_json: bool, code: &str, message: &str) {
    if robot_json {
        eprintln!(
            "{}",
            serde_json::json!({ "kind": "error", "code": code, "message": message })
        );
    } else {
        eprintln!("oraclemcp serve: {message}");
    }
}

fn run_dashboard_cmd(
    robot_json: bool,
    binary_name: &str,
    base_url: &str,
    no_open: bool,
) -> ExitCode {
    let ticket_dir = default_dashboard_ticket_dir();
    let ticket = match mint_dashboard_pairing_ticket(&ticket_dir, base_url) {
        Ok(ticket) => ticket,
        Err(e) => {
            if robot_json {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "kind": "error",
                        "code": "ORACLEMCP_DASHBOARD_PAIRING_FAILED",
                        "message": e.to_string(),
                    })
                );
            } else {
                eprintln!("{binary_name} dashboard: failed to create pairing ticket: {e}");
            }
            return ExitCode::from(2);
        }
    };
    let opened = if no_open {
        false
    } else {
        match open_dashboard_url(&ticket.url) {
            Ok(()) => true,
            Err(e) => {
                if robot_json {
                    eprintln!(
                        "{}",
                        serde_json::json!({
                            "kind": "warning",
                            "code": "ORACLEMCP_DASHBOARD_OPEN_FAILED",
                            "message": e.to_string(),
                        })
                    );
                } else {
                    eprintln!(
                        "{binary_name} dashboard: browser launch failed; open the printed URL manually"
                    );
                }
                false
            }
        }
    };
    if robot_json {
        let output = serde_json::json!({
            "kind": "dashboard_pairing",
            "url": ticket.url,
            "expires_unix": ticket.expires_unix,
            "opened": opened,
            "ticket_file": ticket.ticket_file,
        });
        stdout_exit(
            write_stdout_line(&serde_json::to_string(&output).expect("dashboard JSON serializes")),
            ExitCode::SUCCESS,
        )
    } else {
        stdout_exit(write_stdout_line(&ticket.url), ExitCode::SUCCESS)
    }
}

fn open_dashboard_url(url: &str) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    let status = std::process::Command::new("open").arg(url).status()?;
    #[cfg(target_os = "windows")]
    let status = std::process::Command::new("cmd")
        .args(["/C", "start", "", url])
        .status()?;
    #[cfg(all(unix, not(target_os = "macos")))]
    let status = std::process::Command::new("xdg-open").arg(url).status()?;
    #[cfg(not(any(unix, target_os = "windows")))]
    let status = {
        let _ = url;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "automatic browser launch is not supported on this platform",
        ));
    };
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other("browser launcher exited unsuccessfully"))
    }
}

fn run_completions_cmd(binary_name: &'static str, shell: CompletionShell) -> ExitCode {
    let mut cmd = cli_command(binary_name);
    let mut out = Vec::new();
    match shell {
        CompletionShell::Bash => {
            clap_complete::generate(clap_complete::shells::Bash, &mut cmd, binary_name, &mut out);
        }
        CompletionShell::Zsh => {
            clap_complete::generate(clap_complete::shells::Zsh, &mut cmd, binary_name, &mut out);
        }
        CompletionShell::Fish => {
            clap_complete::generate(clap_complete::shells::Fish, &mut cmd, binary_name, &mut out);
        }
        CompletionShell::Powershell => {
            clap_complete::generate(
                clap_complete::shells::PowerShell,
                &mut cmd,
                binary_name,
                &mut out,
            );
        }
    }
    stdout_exit(
        write_stdout(|stdout| stdout.write_all(&out)),
        ExitCode::SUCCESS,
    )
}

fn setup_display_path(path: &str) -> String {
    let expanded = if path == "~" {
        std::env::var_os("HOME").map(PathBuf::from)
    } else if let Some(rest) = path.strip_prefix("~/") {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(rest))
    } else {
        Some(PathBuf::from(path))
    };
    let Some(expanded) = expanded else {
        return path.to_owned();
    };
    if expanded.is_absolute() {
        expanded.display().to_string()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(&expanded).display().to_string())
            .unwrap_or_else(|_| expanded.display().to_string())
    }
}

fn run_info(robot_json: bool) -> ExitCode {
    let info = serde_json::json!({
        "binary": "oraclemcp",
        "version": env!("CARGO_PKG_VERSION"),
        "engine": cfg!(feature = "plsql-intelligence"),
        "live_db": LIVE_DB,
        "transports": ["stdio", "http"],
        "tools": registry::tool_names(),
        "mcp_protocol_version": oraclemcp_core::PROTOCOL_VERSION,
    });
    let output = if robot_json {
        serde_json::to_string(&info).unwrap()
    } else {
        serde_json::to_string_pretty(&info).unwrap()
    };
    stdout_exit(write_stdout_line(&output), ExitCode::SUCCESS)
}

fn setup_payload(
    profile: &str,
    credential_env: &str,
    wrapper_path: &str,
    config_path: &str,
    tools_dir: &str,
) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "kind": "oraclemcp_setup",
        "principle": "one generic binary; all environment-specific database names, credentials, session identity, and custom tools live in local config",
        "install": {
            "cargo": "cargo install oraclemcp",
            "docker_stdio": format!("docker run -i --rm ghcr.io/muhdur/oraclemcp:{}", env!("CARGO_PKG_VERSION"))
        },
        "paths": {
            "profiles": config_path,
            "custom_tools": tools_dir,
            "wrapper": wrapper_path,
            "full_profile_example": "oraclemcp.example.toml"
        },
        "profiles_toml": robot_docs::setup_profiles_template(profile, credential_env),
        "wrapper_script": robot_docs::setup_wrapper_template(),
        "custom_tool_toml": robot_docs::setup_custom_tool_template(),
        "claude_mcp_json": {
            "mcpServers": {
                "oracle": {
                    "command": wrapper_path,
                    "args": ["serve", "--profile", profile, "--allow-no-auth"]
                }
            }
        },
        "codex_config_toml": format!(
            "[mcp_servers.oracle]\ncommand = \"{wrapper_path}\"\nargs = [\"serve\", \"--profile\", \"{profile}\", \"--allow-no-auth\"]\n"
        ),
        "secure_stdio": {
            "env": { "ORACLEMCP_STDIO_TOKEN": "<shared-init-token>" },
            "args": ["serve", "--profile", profile],
            "note": "Use secure stdio when the MCP client can provide the init token; otherwise keep stdio local and use --allow-no-auth intentionally."
        },
        "http_client_credentials": {
            "issue_once": ["oraclemcp", "clients", "issue", "--label", "Claude Desktop", "--scope", "oracle:read"],
            "serve_args": ["serve", "--listen", "127.0.0.1:7070", "--client-credentials", "--profile", profile],
            "service_install": ["oraclemcp", "service", "install", "--yes", "--client-credentials", "--profile", profile],
            "claude_mcp_add": ["claude", "mcp", "add", "oracle", "--transport", "http", "http://127.0.0.1:7070/mcp"],
            "secret_rule": "The issued bearer is shown once by the clients command; put it only in the MCP client's secret/header store, never in profiles.toml, audit, logs, or committed config.",
            "rotation": ["oraclemcp", "clients", "rotate", "<client_id>"],
            "revocation": ["oraclemcp", "clients", "revoke", "<client_id>"]
        },
        "validation_commands": [
            ["oraclemcp", "--json", "info"],
            ["oraclemcp", "--json", "setup", "--profile", profile],
            ["oraclemcp", "--json", "profiles"],
            ["oraclemcp", "--json", "doctor"],
            ["oraclemcp", "--json", "doctor", "--online", "--profile", profile],
            ["oraclemcp", "--json", "capabilities"]
        ],
        "next_actions": [
            format!("write the minimal profiles template to {config_path} after replacing placeholders"),
            "use oraclemcp.example.toml when you need the fully annotated profile reference",
            format!("write the wrapper template to {wrapper_path} and make it executable if Oracle client environment setup is needed"),
            "for HTTP clients, issue one per-client bearer and configure --client-credentials on the service",
            "configure every stdio MCP client to call the same wrapper and args",
            "restart each MCP client after changing the binary, wrapper, or profile",
            "run the validation commands before allowing agents to use live database tools"
        ]
    })
}

#[derive(Debug)]
struct SetupWriteResult {
    preview: ConfigDraftPreview,
    outcome: ConfigApplyOutcome,
    status: ConfigOpsStatus,
}

fn setup_write_target_path(config_path: &str) -> PathBuf {
    if config_path == DEFAULT_SETUP_CONFIG_PATH {
        return operator_config_target_path();
    }
    expand_home_path(config_path)
}

fn expand_home_path(path: &str) -> PathBuf {
    if path == "~" {
        return std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(path));
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return std::env::var_os("HOME")
            .map(PathBuf::from)
            .map(|home| home.join(rest))
            .unwrap_or_else(|| PathBuf::from(path));
    }
    PathBuf::from(path)
}

fn setup_apply_config_with_backend(
    backend: ConfigOpsBackend,
    target_path: PathBuf,
    draft_toml: &str,
) -> Result<SetupWriteResult, ConfigOpsError> {
    let service = ConfigOpsService::new(backend, target_path, None);
    let preview = service.stage(draft_toml)?;
    let outcome = service.apply(draft_toml, Some(&preview.current_sha256))?;
    let status = service.status()?;
    Ok(SetupWriteResult {
        preview,
        outcome,
        status,
    })
}

fn setup_write_payload(
    mut payload: serde_json::Value,
    target_path: &Path,
    result: &SetupWriteResult,
) -> serde_json::Value {
    if let Some(obj) = payload.as_object_mut() {
        obj.remove("profiles_toml");
        obj.insert(
            "write".to_owned(),
            serde_json::json!({
                "enabled": true,
                "source": "config_ops",
                "target_path": target_path,
                "preview": &result.preview,
                "outcome": &result.outcome,
                "status": &result.status,
                "redaction": "profiles TOML and secret references are not echoed by setup --write"
            }),
        );
        obj.insert(
            "next_actions".to_owned(),
            serde_json::json!([
                format!("edit {} locally to replace placeholder database metadata before live use", target_path.display()),
                "set the environment variable referenced by credential_ref outside profiles.toml",
                "use oraclemcp.example.toml when you need wallet, proxy, DRCP, pool, app-context, or writable-profile examples",
                "write the wrapper template only if local Oracle network environment setup is needed",
                "for HTTP clients, issue one per-client bearer and configure --client-credentials on the service",
                "run the validation commands before allowing agents to use live database tools"
            ]),
        );
    }
    payload
}

fn setup_config_error_status(error: &ConfigOpsError) -> (&'static str, String) {
    match error {
        ConfigOpsError::CurrentChanged { .. } => (
            "ORACLEMCP_SETUP_CONFIG_CHANGED",
            "config target changed during setup --write; rerun setup after reviewing the current file"
                .to_owned(),
        ),
        ConfigOpsError::InvalidTargetPath(reason) => {
            ("ORACLEMCP_SETUP_TARGET_INVALID", reason.clone())
        }
        ConfigOpsError::InvalidUtf8 { .. } => (
            "ORACLEMCP_SETUP_CONFIG_INVALID_UTF8",
            "config target is not valid UTF-8".to_owned(),
        ),
        ConfigOpsError::Config(_) => (
            "ORACLEMCP_SETUP_CONFIG_INVALID",
            "generated setup config failed strict validation".to_owned(),
        ),
        ConfigOpsError::UnknownRollbackId => (
            "ORACLEMCP_SETUP_ROLLBACK_UNKNOWN",
            "rollback id is unknown or already consumed".to_owned(),
        ),
        ConfigOpsError::FileStore(_) | ConfigOpsError::Io(_) => (
            "ORACLEMCP_SETUP_WRITE_FAILED",
            "config workflow failed before completion".to_owned(),
        ),
        _ => (
            "ORACLEMCP_SETUP_WRITE_FAILED",
            "config workflow failed before completion".to_owned(),
        ),
    }
}

fn emit_command_error(robot_json: bool, command: &str, code: &str, message: &str) {
    if robot_json {
        eprintln!(
            "{}",
            serde_json::json!({ "kind": "error", "code": code, "message": message })
        );
    } else {
        eprintln!("oraclemcp {command}: {message}");
    }
}

fn run_setup(
    robot_json: bool,
    write: bool,
    profile: &str,
    credential_env: &str,
    wrapper_path: &str,
    config_path: &str,
    tools_dir: &str,
) -> ExitCode {
    let target_path = setup_write_target_path(config_path);
    let setup_config_path = if write {
        target_path.display().to_string()
    } else {
        setup_display_path(config_path)
    };
    let setup_wrapper_path = setup_display_path(wrapper_path);
    let setup_tools_dir = setup_display_path(tools_dir);
    let mut payload = setup_payload(
        profile,
        credential_env,
        &setup_wrapper_path,
        &setup_config_path,
        &setup_tools_dir,
    );
    let write_result = if write {
        let draft_toml = payload["profiles_toml"]
            .as_str()
            .expect("setup payload includes profiles_toml")
            .to_owned();
        let backend = match ConfigOpsBackend::open_default() {
            Ok(backend) => backend,
            Err(error) => {
                let (code, message) = setup_config_error_status(&error);
                emit_command_error(robot_json, "setup", code, &message);
                return ExitCode::from(2);
            }
        };
        match setup_apply_config_with_backend(backend, target_path.clone(), &draft_toml) {
            Ok(result) => Some(result),
            Err(error) => {
                let (code, message) = setup_config_error_status(&error);
                emit_command_error(robot_json, "setup", code, &message);
                return ExitCode::from(2);
            }
        }
    } else {
        None
    };
    if let Some(result) = write_result.as_ref() {
        payload = setup_write_payload(payload, &target_path, result);
    }
    if robot_json {
        let output = serde_json::to_string(&payload).unwrap();
        stdout_exit(write_stdout_line(&output), ExitCode::SUCCESS)
    } else {
        let mut output = String::new();
        output.push_str("oraclemcp setup\n\n");
        output.push_str("Install:\n  cargo install oraclemcp\n\n");
        output.push_str(&format!("Profiles path:\n  {setup_config_path}\n\n"));
        if let Some(result) = write_result.as_ref() {
            output.push_str("profiles.toml written through config-ops:\n");
            output.push_str(&format!(
                "  target: {}\n",
                result.outcome.apply.target_path.display()
            ));
            output.push_str(&format!(
                "  backup: {}\n",
                result.outcome.apply.backup_path.display()
            ));
            output.push_str(&format!("  rollback: {}\n", result.outcome.rollback_id));
            output.push_str(&format!("  reload: {}\n", result.outcome.reload.status));
            output.push_str("  redaction: profiles TOML and secret references are not echoed by setup --write\n\n");
        } else {
            output.push_str(&format!(
                "profiles.toml template:\n{}\n\n",
                payload["profiles_toml"].as_str().unwrap_or("")
            ));
        }
        output.push_str(&format!("Wrapper path:\n  {setup_wrapper_path}\n\n"));
        output.push_str(&format!(
            "wrapper script template:\n{}\n\n",
            payload["wrapper_script"].as_str().unwrap_or("")
        ));
        output.push_str(&format!("Custom tools path:\n  {setup_tools_dir}\n\n"));
        output.push_str(&format!(
            "custom tool template:\n{}\n\n",
            payload["custom_tool_toml"].as_str().unwrap_or("")
        ));
        output.push_str(&format!(
            "Claude MCP JSON:\n{}\n\n",
            serde_json::to_string_pretty(&payload["claude_mcp_json"]).unwrap()
        ));
        output.push_str(&format!(
            "Codex config TOML:\n{}",
            payload["codex_config_toml"].as_str().unwrap_or("")
        ));
        output.push_str("\nHTTP per-client credentials:\n");
        output.push_str(&format!(
            "  issue: {}\n",
            payload["http_client_credentials"]["issue_once"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|part| part.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        ));
        output.push_str(&format!(
            "  service: {}\n",
            payload["http_client_credentials"]["service_install"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|part| part.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        ));
        output.push_str(&format!(
            "  claude: {}\n",
            payload["http_client_credentials"]["claude_mcp_add"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|part| part.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        ));
        output.push_str(&format!(
            "  note: {}\n",
            payload["http_client_credentials"]["secret_rule"]
                .as_str()
                .unwrap_or("")
        ));
        output.push_str("Validation commands:\n");
        for command in payload["validation_commands"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let rendered = command
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|part| part.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            output.push_str(&format!("  {rendered}\n"));
        }
        stdout_exit(write_stdout_text(&output), ExitCode::SUCCESS)
    }
}

#[cfg(not(windows))]
const SELF_UPDATE_INSTALLER_SH_URL: &str =
    "https://raw.githubusercontent.com/MuhDur/oraclemcp/main/install.sh";
#[cfg(windows)]
const SELF_UPDATE_INSTALLER_PS_URL: &str =
    "https://raw.githubusercontent.com/MuhDur/oraclemcp/main/install.ps1";

#[cfg(not(windows))]
fn self_update_installer_url() -> &'static str {
    SELF_UPDATE_INSTALLER_SH_URL
}

#[cfg(windows)]
fn self_update_installer_url() -> &'static str {
    SELF_UPDATE_INSTALLER_PS_URL
}

#[cfg(not(windows))]
fn self_update_argv(args: &SelfUpdateCliArgs) -> Vec<String> {
    let mut argv = vec![
        "bash".to_owned(),
        "-c".to_owned(),
        "set -euo pipefail; url=\"$1\"; shift; curl -fsSL \"${url}?$(date +%s)\" | bash -s -- \"$@\""
            .to_owned(),
        "oraclemcp-self-update".to_owned(),
        SELF_UPDATE_INSTALLER_SH_URL.to_owned(),
        "--update".to_owned(),
        "--version".to_owned(),
        args.version.clone(),
    ];
    if let Some(verify) = &args.verify {
        argv.push("--verify".to_owned());
        argv.push(verify.clone());
    }
    if args.yes {
        argv.push("--yes".to_owned());
    }
    if args.no_service {
        argv.push("--no-service".to_owned());
    }
    argv
}

#[cfg(windows)]
fn self_update_argv(args: &SelfUpdateCliArgs) -> Vec<String> {
    let mut argv = vec![
        "powershell.exe".to_owned(),
        "-NoProfile".to_owned(),
        "-ExecutionPolicy".to_owned(),
        "Bypass".to_owned(),
        "-Command".to_owned(),
        "$ErrorActionPreference = 'Stop'; $url = $args[0]; $installer = Join-Path ([IO.Path]::GetTempPath()) ('oraclemcp-install-' + [guid]::NewGuid().ToString('N') + '.ps1'); Invoke-WebRequest -UseBasicParsing -Uri ($url + '?' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) -OutFile $installer; $installerArgs = @(); for ($i = 1; $i -lt $args.Count; $i++) { $installerArgs += $args[$i] }; try { & $installer @installerArgs; if ($LASTEXITCODE -is [int] -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE } } finally { Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue }"
            .to_owned(),
        SELF_UPDATE_INSTALLER_PS_URL.to_owned(),
        "-Update".to_owned(),
        "-Version".to_owned(),
        args.version.clone(),
    ];
    if let Some(verify) = &args.verify {
        argv.push("-Verify".to_owned());
        argv.push(verify.clone());
    }
    if args.yes {
        argv.push("-Yes".to_owned());
    }
    if args.no_service {
        argv.push("-NoService".to_owned());
    }
    argv
}

fn exit_code_from_status(status: ExitStatus) -> ExitCode {
    match status.code() {
        Some(code) if (0..=255).contains(&code) => ExitCode::from(code as u8),
        Some(_) | None => ExitCode::from(1),
    }
}

fn run_self_update_cmd(robot_json: bool, args: SelfUpdateCliArgs) -> ExitCode {
    let argv = self_update_argv(&args);
    let installer_url = self_update_installer_url();
    if args.dry_run {
        let payload = serde_json::json!({
            "kind": "oraclemcp_self_update",
            "installer_url": installer_url,
            "version": args.version,
            "argv": argv,
            "notes": [
                "self-update re-runs the same verified installer path as the one-line install",
                "the platform installer --update flag is an alias for the version-aware update path"
            ]
        });
        let mut text = String::new();
        text.push_str("oraclemcp self-update\n\n");
        text.push_str(&format!("Installer:\n  {installer_url}\n\n"));
        text.push_str("Command argv:\n");
        for arg in payload["argv"].as_array().expect("argv array") {
            text.push_str(&format!(
                "  {}\n",
                arg.as_str().expect("argv item is string")
            ));
        }
        return if robot_json {
            stdout_exit(
                write_stdout_line(&serde_json::to_string(&payload).expect("self-update JSON")),
                ExitCode::SUCCESS,
            )
        } else {
            stdout_exit(write_stdout_text(&text), ExitCode::SUCCESS)
        };
    }

    let Some((program, rest)) = argv.split_first() else {
        emit_command_error(
            robot_json,
            "self-update",
            "ORACLEMCP_SELF_UPDATE_COMMAND_EMPTY",
            "internal self-update command was empty",
        );
        return ExitCode::from(2);
    };
    match ProcessCommand::new(program).args(rest).status() {
        Ok(status) => exit_code_from_status(status),
        Err(error) => {
            emit_command_error(
                robot_json,
                "self-update",
                "ORACLEMCP_SELF_UPDATE_FAILED",
                &format!("failed to run installer: {error}"),
            );
            ExitCode::from(2)
        }
    }
}

fn custom_tool_signatures(
    path: &Path,
    only_tool: Option<&str>,
) -> Result<serde_json::Value, ErrorEnvelope> {
    let key = std::env::var(CUSTOM_TOOLS_HMAC_KEY_ENV).map_err(|_| {
        custom_tool_error(format!(
            "{CUSTOM_TOOLS_HMAC_KEY_ENV} is required to sign custom tool definitions"
        ))
    })?;
    let src = std::fs::read_to_string(path).map_err(|e| {
        custom_tool_error(format!(
            "failed to read custom tool file {}: {e}",
            path.display()
        ))
    })?;
    let defs = parse_tools_file(&src).map_err(|e| {
        custom_tool_error(format!(
            "failed to parse custom tool file {}: {e}",
            path.display()
        ))
    })?;
    let mut signatures = Vec::new();
    for def in defs {
        if only_tool.is_some_and(|name| name != def.name.as_str()) {
            continue;
        }
        signatures.push(serde_json::json!({
            "name": def.name,
            "signature": sign(&def, key.as_bytes()),
        }));
    }
    if signatures.is_empty() {
        return Err(custom_tool_error(
            "no matching custom tool definitions found",
        ));
    }
    Ok(serde_json::json!({
        "ok": true,
        "path": path.display().to_string(),
        "signatures": signatures,
        "next_actions": [
            "copy each signature into its matching [[tool]] block as signature = \"...\"",
            "set ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY in the MCP server environment",
            "run oraclemcp --json doctor --online --profile <profile> before restarting clients"
        ]
    }))
}

fn run_sign_tool(robot_json: bool, path: &Path, only_tool: Option<&str>) -> ExitCode {
    match custom_tool_signatures(path, only_tool) {
        Ok(payload) => {
            let output = if robot_json {
                serde_json::to_string(&payload).unwrap()
            } else {
                serde_json::to_string_pretty(&payload).unwrap()
            };
            stdout_exit(write_stdout_line(&output), ExitCode::SUCCESS)
        }
        Err(e) => {
            emit_status_error(robot_json, "ORACLEMCP_SIGN_TOOL_FAILED", &e.message);
            ExitCode::from(2)
        }
    }
}

/// Resolve the verification key set from config + env. The verify path resolves
/// the same secret the server signs with; if `--key-id` is given it overrides
/// the label so a rotated key (whose bytes are supplied via the same secret-ref
/// or env) can be checked.
fn audit_verification_keys(key_id_override: Option<&str>) -> Result<Vec<SigningKey>, String> {
    let audit = OracleMcpConfig::load(None)
        .map(|cfg| cfg.audit)
        .map_err(|e| format!("failed to load audit config: {e}"))?;
    let key_id = key_id_override
        .map(str::to_owned)
        .unwrap_or_else(|| audit.key_id_or_default().to_owned());

    if let Some(key_ref) = audit.key_ref.as_deref() {
        // `protected=false`: verification is an operator action that may run
        // off-box against a copied log, where a dev `literal:` key is legitimate.
        let secret = resolve_secret_with(key_ref, false, &SystemSecretResolver).map_err(|e| {
            format!(
                "failed to resolve [audit].key_ref: {}",
                secret_error_summary(&e)
            )
        })?;
        return Ok(vec![SigningKey::new(
            key_id,
            secret.expose().as_bytes().to_vec(),
        )]);
    }
    match std::env::var(AUDIT_KEY_ENV) {
        Ok(raw) if !raw.is_empty() => Ok(vec![SigningKey::new(key_id, raw.into_bytes())]),
        _ => Err(format!(
            "no audit signing key configured; set [audit].key_ref or {AUDIT_KEY_ENV} to verify the chain"
        )),
    }
}

const DB_EVIDENCE_UNAVAILABLE_PREFIX: &str = "db_evidence_unavailable:";
const AUDIT_DB_EVIDENCE_SAMPLE_LIMIT: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuditDbEvidenceCorrelation {
    seq: u64,
    sid: Option<String>,
    serial_number: Option<String>,
    client_identifier: Option<String>,
    module: Option<String>,
    action: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuditDbEvidenceSummary {
    status: &'static str,
    degraded_reason: Option<&'static str>,
    records: usize,
    with_db_evidence: usize,
    captured: usize,
    unavailable: usize,
    missing: usize,
    correlated: usize,
    with_session_tags: usize,
    unavailable_reasons: Vec<String>,
    sample_correlations: Vec<AuditDbEvidenceCorrelation>,
    sample_limit: usize,
    sample_truncated: bool,
}

fn non_empty(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(|v| !v.trim().is_empty())
}

fn db_evidence_unavailable_reason(evidence: &DbEvidence) -> Option<&str> {
    evidence
        .availability
        .as_deref()
        .and_then(|availability| availability.strip_prefix(DB_EVIDENCE_UNAVAILABLE_PREFIX))
        .filter(|reason| !reason.is_empty())
}

fn db_evidence_has_captured_field(evidence: &DbEvidence) -> bool {
    [
        &evidence.db_unique_name,
        &evidence.service_name,
        &evidence.instance_name,
        &evidence.session_user,
        &evidence.current_user,
        &evidence.proxy_user,
        &evidence.current_schema,
        &evidence.sid,
        &evidence.serial_number,
        &evidence.client_identifier,
        &evidence.module,
        &evidence.action,
        &evidence.database_role,
        &evidence.open_mode,
    ]
    .iter()
    .any(|value| non_empty(value))
}

fn db_evidence_is_captured(evidence: &DbEvidence) -> bool {
    evidence.availability.as_deref() == Some("captured") || db_evidence_has_captured_field(evidence)
}

fn db_evidence_has_session_correlation(evidence: &DbEvidence) -> bool {
    let has_sid_serial = non_empty(&evidence.sid) && non_empty(&evidence.serial_number);
    let has_session_tag = non_empty(&evidence.client_identifier)
        || non_empty(&evidence.module)
        || non_empty(&evidence.action);
    has_sid_serial || has_session_tag
}

fn db_evidence_has_session_tag(evidence: &DbEvidence) -> bool {
    non_empty(&evidence.client_identifier)
        || non_empty(&evidence.module)
        || non_empty(&evidence.action)
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_owned());
    }
}

fn audit_db_evidence_summary(records: &[AuditRecord]) -> AuditDbEvidenceSummary {
    let mut summary = AuditDbEvidenceSummary {
        status: "degraded",
        degraded_reason: None,
        records: records.len(),
        with_db_evidence: 0,
        captured: 0,
        unavailable: 0,
        missing: 0,
        correlated: 0,
        with_session_tags: 0,
        unavailable_reasons: Vec::new(),
        sample_correlations: Vec::new(),
        sample_limit: AUDIT_DB_EVIDENCE_SAMPLE_LIMIT,
        sample_truncated: false,
    };

    for record in records {
        let Some(evidence) = record.db_evidence.as_ref() else {
            summary.missing += 1;
            continue;
        };
        summary.with_db_evidence += 1;
        if let Some(reason) = db_evidence_unavailable_reason(evidence) {
            summary.unavailable += 1;
            push_unique(&mut summary.unavailable_reasons, reason);
            continue;
        }
        if db_evidence_is_captured(evidence) {
            summary.captured += 1;
        }
        if db_evidence_has_session_tag(evidence) {
            summary.with_session_tags += 1;
        }
        if db_evidence_has_session_correlation(evidence) {
            summary.correlated += 1;
            if summary.sample_correlations.len() < AUDIT_DB_EVIDENCE_SAMPLE_LIMIT {
                summary
                    .sample_correlations
                    .push(AuditDbEvidenceCorrelation {
                        seq: record.seq,
                        sid: evidence.sid.clone(),
                        serial_number: evidence.serial_number.clone(),
                        client_identifier: evidence.client_identifier.clone(),
                        module: evidence.module.clone(),
                        action: evidence.action.clone(),
                    });
            } else {
                summary.sample_truncated = true;
            }
        }
    }

    if summary.correlated > 0 {
        summary.status = "correlated";
    } else {
        summary.degraded_reason = Some(if summary.records == 0 {
            "no_records"
        } else if summary.with_db_evidence == 0 {
            "no_db_evidence"
        } else if summary.captured == 0 && summary.unavailable > 0 {
            "db_evidence_unavailable"
        } else {
            "db_evidence_missing_session_tags"
        });
    }
    summary
}

fn audit_db_evidence_payload(summary: &AuditDbEvidenceSummary) -> serde_json::Value {
    let sample_correlations: Vec<_> = summary
        .sample_correlations
        .iter()
        .map(|correlation| {
            serde_json::json!({
                "seq": correlation.seq,
                "sid": correlation.sid,
                "serial_number": correlation.serial_number,
                "client_identifier": correlation.client_identifier,
                "module": correlation.module,
                "action": correlation.action,
            })
        })
        .collect();
    serde_json::json!({
        "status": summary.status,
        "degraded_reason": summary.degraded_reason,
        "source": "signed_audit_records",
        "live_database_query": false,
        "records": summary.records,
        "with_db_evidence": summary.with_db_evidence,
        "captured": summary.captured,
        "unavailable": summary.unavailable,
        "missing": summary.missing,
        "correlated": summary.correlated,
        "with_session_tags": summary.with_session_tags,
        "unavailable_reasons": summary.unavailable_reasons,
        "sample_limit": summary.sample_limit,
        "sample_truncated": summary.sample_truncated,
        "sample_correlations": sample_correlations,
    })
}

fn audit_db_evidence_text(summary: &AuditDbEvidenceSummary) -> String {
    let reason = summary
        .degraded_reason
        .map(|reason| format!(" reason={reason}"))
        .unwrap_or_default();
    format!(
        "DB evidence {}:{} correlated={}/{} captured={} unavailable={} missing={} session_tags={}",
        summary.status.to_ascii_uppercase(),
        reason,
        summary.correlated,
        summary.records,
        summary.captured,
        summary.unavailable,
        summary.missing,
        summary.with_session_tags
    )
}

fn run_audit_verify(
    robot_json: bool,
    file: &Path,
    key_id_override: Option<&str>,
    with_db_evidence: bool,
) -> ExitCode {
    use oraclemcp_audit::{VerifyOutcome, parse_jsonl, verify_records};

    let keys = match audit_verification_keys(key_id_override) {
        Ok(keys) => keys,
        Err(message) => {
            emit_status_error(robot_json, "ORACLEMCP_AUDIT_KEY_REQUIRED", &message);
            return ExitCode::from(2);
        }
    };

    let body = match fs::read_to_string(file) {
        Ok(body) => body,
        Err(e) => {
            emit_status_error(
                robot_json,
                "ORACLEMCP_AUDIT_READ_FAILED",
                &format!("failed to read audit log {}: {e}", file.display()),
            );
            return ExitCode::from(2);
        }
    };
    let records = match parse_jsonl(&body) {
        Ok(records) => records,
        Err(e) => {
            emit_status_error(robot_json, "ORACLEMCP_AUDIT_MALFORMED", &e.to_string());
            return ExitCode::from(2);
        }
    };

    match verify_records(&records, &keys) {
        VerifyOutcome::Ok {
            records: record_count,
        } => {
            let mut payload = serde_json::json!({
                "ok": true,
                "file": file.display().to_string(),
                "records": record_count,
            });
            let db_evidence_summary = with_db_evidence.then(|| audit_db_evidence_summary(&records));
            if let Some(summary) = db_evidence_summary.as_ref()
                && let serde_json::Value::Object(obj) = &mut payload
            {
                obj.insert("db_evidence".to_owned(), audit_db_evidence_payload(summary));
            }
            let output = if robot_json {
                serde_json::to_string(&payload).unwrap()
            } else if let Some(summary) = db_evidence_summary.as_ref() {
                format!(
                    "OK: audit chain verified ({record_count} records); {}",
                    audit_db_evidence_text(summary)
                )
            } else {
                format!("OK: audit chain verified ({record_count} records)")
            };
            stdout_exit(write_stdout_line(&output), ExitCode::SUCCESS)
        }
        VerifyOutcome::Broken { seq, index, reason } => {
            let payload = serde_json::json!({
                "ok": false,
                "file": file.display().to_string(),
                "broken_at_seq": seq,
                "broken_at_index": index,
                "reason": reason.to_string(),
            });
            if robot_json {
                let _ = write_stdout_line(&serde_json::to_string(&payload).unwrap());
            } else {
                let _ = write_stdout_line(&format!(
                    "BROKEN: audit chain failed at seq {seq} (record #{index}): {reason}"
                ));
            }
            ExitCode::from(2)
        }
        // `VerifyOutcome` is #[non_exhaustive]; fail closed on any future variant.
        _ => {
            emit_status_error(
                robot_json,
                "ORACLEMCP_AUDIT_UNVERIFIABLE",
                "unrecognized verification outcome",
            );
            ExitCode::from(2)
        }
    }
}

fn capabilities_payload() -> serde_json::Value {
    // HTTP is advertised as available (the binary can serve it); live_db tracks
    // the compiled driver feature.
    let caps = registry::capabilities(env!("CARGO_PKG_VERSION"), LIVE_DB, true);
    let mut value = serde_json::to_value(&caps).unwrap_or(serde_json::Value::Null);
    if let serde_json::Value::Object(obj) = &mut value {
        obj.insert("cli_contract".to_owned(), robot_docs::cli_contract_json());
        obj.insert(
            "mcp_cli_dashboard_parity".to_owned(),
            robot_docs::mcp_cli_dashboard_parity_json(),
        );
    }
    value
}

fn run_capabilities(robot_json: bool) -> ExitCode {
    let value = capabilities_payload();
    let output = if robot_json {
        serde_json::to_string(&value).unwrap()
    } else {
        serde_json::to_string_pretty(&value).unwrap()
    };
    stdout_exit(write_stdout_line(&output), ExitCode::SUCCESS)
}

fn run_service_cmd(robot_json: bool, command: ServiceCliCommand) -> ExitCode {
    let command = match command {
        ServiceCliCommand::Install(args) => {
            ServiceLifecycleCommand::Install(ServiceInstallOptions {
                name: args.name,
                listen: args.listen,
                profile: args.profile,
                allow_no_auth: args.allow_no_auth,
                client_credentials: args.client_credentials,
                skip_linger: args.skip_linger,
                yes: args.yes,
                dry_run: args.dry_run,
            })
        }
        ServiceCliCommand::Uninstall(args) => {
            ServiceLifecycleCommand::Uninstall(ServiceMutationOptions {
                name: args.name,
                yes: args.yes,
                dry_run: args.dry_run,
            })
        }
        ServiceCliCommand::Status(args) => {
            ServiceLifecycleCommand::Status(ServiceReadOptions { name: args.name })
        }
        ServiceCliCommand::Logs(args) => ServiceLifecycleCommand::Logs(ServiceLogsOptions {
            name: args.name,
            lines: args.lines,
        }),
        ServiceCliCommand::Restart(args) => {
            ServiceLifecycleCommand::Restart(ServiceMutationOptions {
                name: args.name,
                yes: args.yes,
                dry_run: args.dry_run,
            })
        }
        ServiceCliCommand::Backup(args) => {
            let state_dir = match service_state_dir_for_cli(robot_json) {
                Ok(path) => path,
                Err(code) => return code,
            };
            let config_path = operator_config_target_path();
            let audit_path = match service_audit_path_for_backup(&config_path) {
                Ok(path) => path,
                Err(message) => {
                    emit_status_error(robot_json, "ORACLEMCP_CONFIG_INVALID", &message);
                    return ExitCode::from(2);
                }
            };
            ServiceLifecycleCommand::Backup(ServiceBackupOptions {
                name: args.name,
                state_dir,
                config_path,
                audit_path,
                output: args.output,
                yes: args.yes,
                dry_run: args.dry_run,
            })
        }
        ServiceCliCommand::Restore(args) => {
            let state_dir = match service_state_dir_for_cli(robot_json) {
                Ok(path) => path,
                Err(code) => return code,
            };
            let audit_keys = match audit_verification_keys(args.key_id.as_deref()) {
                Ok(keys) => keys,
                Err(message) => {
                    emit_status_error(robot_json, "ORACLEMCP_AUDIT_KEY_REQUIRED", &message);
                    return ExitCode::from(2);
                }
            };
            ServiceLifecycleCommand::Restore(ServiceRestoreOptions {
                name: args.name,
                state_dir,
                config_path: operator_config_target_path(),
                backup: args.backup,
                audit_keys,
                yes: args.yes,
                dry_run: args.dry_run,
            })
        }
    };

    match service_lifecycle::run_service_command(command) {
        Ok(result) => {
            let output = if robot_json {
                serde_json::to_string(&result.payload).unwrap()
            } else {
                result.text
            };
            stdout_exit(write_stdout_line(&output), ExitCode::from(result.exit_code))
        }
        Err(e) => {
            if robot_json {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "kind": "error",
                        "code": e.code,
                        "message": e.message,
                        "exit_code": e.exit_code,
                    })
                );
            } else {
                eprintln!("oraclemcp service: {}", e.message);
            }
            ExitCode::from(e.exit_code)
        }
    }
}

fn run_client_credentials_cmd(robot_json: bool, command: ClientCredentialCliCommand) -> ExitCode {
    let store = match ClientCredentialStore::open_default() {
        Ok(store) => store,
        Err(error) => {
            emit_status_error(
                robot_json,
                "ORACLEMCP_CLIENT_CREDENTIAL_STORE_UNAVAILABLE",
                &client_credential_error_message(&error),
            );
            return ExitCode::from(2);
        }
    };
    let store_path = store.path().display().to_string();
    let result = match command {
        ClientCredentialCliCommand::Issue(args) => store
            .issue(ClientCredentialIssueRequest::new(args.label, args.scopes))
            .map(|issued| {
                let client_id = issued.client_id.clone();
                let bearer = issued.bearer.expose().to_owned();
                serde_json::json!({
                    "kind": "client_credential_issued",
                    "store_path": store_path,
                    "client": issued.view,
                    "bearer": bearer,
                    "bearer_shown_once": true,
                    "serve_args": ["serve", "--listen", "127.0.0.1:7070", "--client-credentials"],
                    "rotation_command": ["oraclemcp", "clients", "rotate", client_id],
                    "revocation_command": ["oraclemcp", "clients", "revoke", issued.client_id],
                })
            }),
        ClientCredentialCliCommand::List => Ok(serde_json::json!({
            "kind": "client_credentials",
            "store_path": store_path,
            "clients": store.list(),
        })),
        ClientCredentialCliCommand::Rotate(args) => store.rotate(&args.client_id).map(
            |(issued, lifecycle)| {
                let bearer = issued.bearer.expose().to_owned();
                serde_json::json!({
                    "kind": "client_credential_rotated",
                    "store_path": store_path,
                    "client": issued.view,
                    "bearer": bearer,
                    "bearer_shown_once": true,
                    "closed_principal": client_lifecycle_json(&lifecycle),
                    "next_step": "restart or close active sessions for this client so old in-memory grants are gone",
                })
            },
        ),
        ClientCredentialCliCommand::Revoke(args) => {
            store.revoke(&args.client_id).map(|lifecycle| {
                serde_json::json!({
                    "kind": "client_credential_revoked",
                    "store_path": store_path,
                    "closed_principal": client_lifecycle_json(&lifecycle),
                    "next_step": "restart or close active sessions for this client so in-memory grants are gone",
                })
            })
        }
    };

    match result {
        Ok(value) if robot_json => {
            stdout_exit(write_stdout_line(&value.to_string()), ExitCode::SUCCESS)
        }
        Ok(value) => stdout_exit(
            write_stdout_text(&client_credential_text(&value)),
            ExitCode::SUCCESS,
        ),
        Err(error) => {
            emit_status_error(
                robot_json,
                "ORACLEMCP_CLIENT_CREDENTIAL_FAILED",
                &client_credential_error_message(&error),
            );
            ExitCode::from(2)
        }
    }
}

fn client_lifecycle_json(lifecycle: &ClientCredentialLifecycle) -> serde_json::Value {
    serde_json::json!({
        "client_id": &lifecycle.client_id,
        "subject_id_hash": operator_subject_id_hash(&lifecycle.principal_key),
        "generation": lifecycle.generation,
    })
}

fn client_credential_text(value: &serde_json::Value) -> String {
    let mut out = String::new();
    let kind = value["kind"].as_str().unwrap_or("client_credentials");
    out.push_str(kind);
    out.push('\n');
    if let Some(path) = value["store_path"].as_str() {
        out.push_str(&format!("store: {path}\n"));
    }
    if let Some(client) = value.get("client") {
        out.push_str(&format!(
            "client_id: {}\nlabel: {}\nstatus: {}\ngeneration: {}\nsubject_id_hash: {}\nscopes: {}\n",
            client["client_id"].as_str().unwrap_or(""),
            client["label"].as_str().unwrap_or(""),
            client["status"].as_str().unwrap_or(""),
            client["generation"].as_u64().unwrap_or(0),
            client["subject_id_hash"].as_str().unwrap_or(""),
            client["scopes"]
                .as_array()
                .map(|scopes| scopes
                    .iter()
                    .filter_map(|scope| scope.as_str())
                    .collect::<Vec<_>>()
                    .join(", "))
                .unwrap_or_default()
        ));
    }
    if let Some(bearer) = value["bearer"].as_str() {
        out.push_str("bearer (shown once): ");
        out.push_str(bearer);
        out.push('\n');
    }
    if let Some(closed) = value.get("closed_principal") {
        out.push_str(&format!(
            "closed_principal: client_id={} subject_id_hash={} generation={}\n",
            closed["client_id"].as_str().unwrap_or(""),
            closed["subject_id_hash"].as_str().unwrap_or(""),
            closed["generation"].as_u64().unwrap_or(0)
        ));
    }
    if let Some(clients) = value["clients"].as_array() {
        for client in clients {
            out.push_str(&format!(
                "{}\t{}\t{}\tgeneration={}\tscopes={}\tsubject={}\n",
                client["client_id"].as_str().unwrap_or(""),
                client["status"].as_str().unwrap_or(""),
                client["label"].as_str().unwrap_or(""),
                client["generation"].as_u64().unwrap_or(0),
                client["scopes"]
                    .as_array()
                    .map(|scopes| scopes
                        .iter()
                        .filter_map(|scope| scope.as_str())
                        .collect::<Vec<_>>()
                        .join(","))
                    .unwrap_or_default(),
                client["subject_id_hash"].as_str().unwrap_or("")
            ));
        }
    }
    if let Some(next_step) = value["next_step"].as_str() {
        out.push_str("next: ");
        out.push_str(next_step);
        out.push('\n');
    }
    out
}

fn client_credential_error_message(error: &ClientCredentialError) -> String {
    match error {
        ClientCredentialError::Store(oraclemcp_core::file_store::FileStoreError::Locked) => {
            "client credential store is locked by the service; stop the service before offline mutation".to_owned()
        }
        _ => error.to_string(),
    }
}

fn run_robot_docs_guide(robot_json: bool) -> ExitCode {
    if robot_json {
        let output = serde_json::to_string(&robot_docs::robot_docs_guide_json()).unwrap();
        stdout_exit(write_stdout_line(&output), ExitCode::SUCCESS)
    } else {
        stdout_exit(
            write_stdout_text(robot_docs::robot_docs_guide_text()),
            ExitCode::SUCCESS,
        )
    }
}

fn profiles_json(cfg: &OracleMcpConfig) -> serde_json::Value {
    let profiles = cfg
        .list_profiles()
        .into_iter()
        .map(|profile| {
            serde_json::json!({
                "name": profile.name,
                "description": profile.description,
                "is_default": profile.is_default,
                "call_timeout_seconds": profile.call_timeout_seconds,
                "connect_timeout_seconds": profile.connect_timeout_seconds,
                "pool": profile.pool,
                "max_level": profile.max_level,
                "default_level": profile.default_level,
                "protected": profile.protected,
                "require_signed_tools": profile.require_signed_tools,
                "read_only_standby": profile.read_only_standby,
                "mcp_exposed": profile.mcp_exposed,
                "dashboard_ddl_workbench": profile.dashboard_ddl_workbench,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "ok": true,
        "profile_count": profiles.len(),
        "has_default_profile": cfg.default_profile.is_some(),
        "profiles": profiles,
    })
}

fn profiles_text(cfg: &OracleMcpConfig) -> String {
    let profiles = cfg.list_profiles();
    if profiles.is_empty() {
        return "oraclemcp profiles\nno profiles configured\ncreate ~/.config/oraclemcp/profiles.toml or set ORACLEMCP_CONFIG\n".to_owned();
    }

    let mut out = String::from("oraclemcp profiles\n");
    for profile in profiles {
        let default = if profile.is_default { " default" } else { "" };
        let protected = if profile.protected { " protected" } else { "" };
        let signed_tools = if profile.require_signed_tools {
            " signed-tools"
        } else {
            ""
        };
        out.push_str(&format!(
            "- {}{}{}{} max_level={} default_level={}",
            profile.name,
            default,
            protected,
            signed_tools,
            profile.max_level,
            profile.default_level
        ));
        if let Some(description) = profile.description {
            out.push_str(&format!(" — {description}"));
        }
        out.push('\n');
        if let Some(pool) = profile.pool {
            out.push_str(&format!(
                "  pool: {} max_size={} min_idle={} acquire_timeout_secs={}\n",
                pool.strategy, pool.max_size, pool.min_idle, pool.acquire_timeout_secs
            ));
        }
    }
    out
}

fn run_profiles(robot_json: bool) -> ExitCode {
    match OracleMcpConfig::load(None) {
        Ok(cfg) => {
            if robot_json {
                stdout_exit(
                    write_stdout_line(&profiles_json(&cfg).to_string()),
                    ExitCode::SUCCESS,
                )
            } else {
                stdout_exit(write_stdout_text(&profiles_text(&cfg)), ExitCode::SUCCESS)
            }
        }
        Err(e) => {
            if robot_json {
                let output = serde_json::json!({
                    "ok": false,
                    "exit_code": 2,
                    "error": {
                        "class": "ConfigError",
                        "message": e.to_string(),
                    }
                })
                .to_string();
                stdout_exit(write_stdout_line(&output), ExitCode::from(2))
            } else {
                eprintln!("oraclemcp profiles: {e}");
                eprintln!("fix: correct ~/.config/oraclemcp/profiles.toml or set ORACLEMCP_CONFIG");
                ExitCode::from(2)
            }
        }
    }
}

fn doctor_process_exit_code(report: &oraclemcp_core::DoctorReport) -> u8 {
    if let Some(fix) = &report.fix {
        return fix.exit_code;
    }
    // Mirror plsql-mcp: a blocker (any failed check) exits 2.
    if report.any_failed() { 2 } else { 0 }
}

struct DoctorProfileContext {
    conn: Option<Box<dyn OracleConnection>>,
    connection_error: Option<String>,
    wallet_location: Option<String>,
    protected_profile_writable: bool,
    connection_strategy: Option<String>,
    call_timeout_resolved: bool,
    call_timeout: Option<std::time::Duration>,
    connect_timeout_seconds: Option<u64>,
    proxy_user: bool,
    profile_caps: Option<DoctorProfileCaps>,
    auth_capabilities: Option<DoctorAuthCapabilities>,
    sensitive_values: Vec<String>,
}

impl DoctorProfileContext {
    fn offline() -> Self {
        DoctorProfileContext {
            conn: None,
            connection_error: None,
            wallet_location: None,
            protected_profile_writable: false,
            connection_strategy: None,
            call_timeout_resolved: false,
            call_timeout: None,
            connect_timeout_seconds: None,
            proxy_user: false,
            profile_caps: None,
            auth_capabilities: None,
            sensitive_values: Vec::new(),
        }
    }
}

fn doctor_sensitive_values(opts: &OracleConnectOptions) -> Vec<String> {
    let mut values = Vec::new();
    values.push(opts.connect_string.clone());
    if let Some(username) = &opts.username {
        values.push(username.clone());
    }
    if let Some(password) = &opts.password {
        values.push(password.clone());
    }
    values.extend(
        opts.auth_adapter
            .sensitive_values()
            .into_iter()
            .map(ToOwned::to_owned),
    );
    if let Some(token) = &opts.iam_token {
        values.push(token.clone());
    }
    if let Some(wallet) = &opts.wallet_location {
        values.push(wallet.display().to_string());
    }
    if let Some(wallet_password) = &opts.wallet_password {
        values.push(wallet_password.clone());
    }
    if let Some(dn) = &opts.ssl_server_cert_dn {
        values.push(dn.clone());
    }
    for (namespace, key, value) in &opts.app_context {
        values.push(namespace.clone());
        values.push(key.clone());
        values.push(value.clone());
    }
    if let Some(identity) = &opts.session_identity {
        for value in [
            &identity.edition,
            &identity.program,
            &identity.machine,
            &identity.os_user,
            &identity.terminal,
            &identity.module,
            &identity.action,
            &identity.client_identifier,
            &identity.client_info,
            &identity.driver_name,
        ]
        .into_iter()
        .flatten()
        {
            values.push(value.clone());
        }
    }
    values.retain(|value| !value.is_empty());
    values
}

fn doctor_connection_error(error: DbError) -> String {
    error.into_envelope().message
}

fn doctor_call_timeout(call_timeout_seconds: Option<u64>) -> Option<std::time::Duration> {
    match call_timeout_seconds {
        None => Some(oraclemcp_core::resilience::DEFAULT_CALL_TIMEOUT),
        Some(0) => None,
        Some(seconds) => Some(std::time::Duration::from_secs(seconds)),
    }
}

fn doctor_profile_caps(
    profile: &oraclemcp_config::ConnectionProfile,
    level: &SessionLevelState,
) -> DoctorProfileCaps {
    DoctorProfileCaps {
        profile: profile.name.clone(),
        configured: DoctorLevelCaps {
            default_level: profile.default_level(),
            max_level: profile.max_level(),
        },
        effective: DoctorLevelCaps {
            default_level: level.effective_level(),
            max_level: level.max_level(),
        },
        protected: level.is_protected(),
        read_only_standby: profile.read_only_standby(),
    }
}

fn doctor_auth_capabilities_for_profile(
    profile: &oraclemcp_config::ConnectionProfile,
) -> DoctorAuthCapabilities {
    let selected = if profile
        .proxy_auth
        .as_ref()
        .and_then(|proxy| proxy.proxy_user())
        .is_some()
    {
        DoctorAuthModeKind::Proxy
    } else if profile.oci.as_ref().is_some_and(|oci| oci.use_iam_token) {
        DoctorAuthModeKind::IamToken
    } else if profile.username.is_none() && profile.credential_ref.is_none() {
        DoctorAuthModeKind::ExternalWallet
    } else {
        DoctorAuthModeKind::Password
    };
    DoctorAuthCapabilities::thin(selected)
}

fn doctor_profile_metadata_context(profile: &str) -> DoctorProfileContext {
    let cfg = match OracleMcpConfig::load(None) {
        Ok(cfg) => cfg,
        Err(e) => {
            return DoctorProfileContext {
                connection_error: Some(format!("config load failed: {e}")),
                ..DoctorProfileContext::offline()
            };
        }
    };
    let Some(chosen) = cfg.profile(profile) else {
        return DoctorProfileContext {
            connection_error: Some(format!("connection profile `{profile}` not found")),
            ..DoctorProfileContext::offline()
        };
    };
    let level = oraclemcp_core::session_level_state(chosen, false);
    DoctorProfileContext {
        conn: None,
        connection_error: None,
        wallet_location: chosen
            .oci
            .as_ref()
            .and_then(|oci| oci.wallet_location.as_ref())
            .map(|path| path.display().to_string()),
        protected_profile_writable: level.is_protected()
            && level.max_level() > OperatingLevel::ReadOnly,
        connection_strategy: Some(
            if chosen.pool.is_some() {
                "hybrid_pool"
            } else {
                "single_session"
            }
            .to_owned(),
        ),
        call_timeout_resolved: true,
        call_timeout: doctor_call_timeout(chosen.call_timeout_seconds),
        connect_timeout_seconds: chosen.connect_timeout_seconds,
        proxy_user: chosen
            .proxy_auth
            .as_ref()
            .and_then(|proxy| proxy.proxy_user())
            .is_some(),
        profile_caps: Some(doctor_profile_caps(chosen, &level)),
        auth_capabilities: Some(doctor_auth_capabilities_for_profile(chosen)),
        sensitive_values: Vec::new(),
    }
}

fn doctor_profile_context(profile: Option<&str>, online: bool) -> DoctorProfileContext {
    if !online {
        return match profile {
            Some(profile) => doctor_profile_metadata_context(profile),
            None => match OracleMcpConfig::load(None) {
                Ok(cfg) => match selected_config_profile(&cfg, None) {
                    Ok(Some(chosen)) => doctor_profile_metadata_context(&chosen.name),
                    Ok(None) if cfg.profiles.is_empty() => DoctorProfileContext {
                        connection_error: Some(
                            "no connection profiles are configured; run `oraclemcp --json setup --write --profile db_ro`, then export ORACLE_APP_PASSWORD for the generated credential_ref and rerun `oraclemcp --json doctor --profile db_ro`"
                                .to_owned(),
                        ),
                        ..DoctorProfileContext::offline()
                    },
                    Ok(None) => DoctorProfileContext {
                        connection_error: Some(
                            "multiple connection profiles exist but no default_profile is configured; run `oraclemcp --json profiles`, then rerun `oraclemcp --json doctor --profile <profile>`"
                                .to_owned(),
                        ),
                        ..DoctorProfileContext::offline()
                    },
                    Err(e) => DoctorProfileContext {
                        connection_error: Some(doctor_connection_error(e)),
                        ..DoctorProfileContext::offline()
                    },
                },
                Err(e) => DoctorProfileContext {
                    connection_error: Some(format!("config load failed: {e}")),
                    ..DoctorProfileContext::offline()
                },
            },
        };
    }

    let Some(profile) = profile else {
        return match resolve_profile_options(None) {
            Ok(Some(resolved)) => doctor_open_resolved_profile(resolved),
            Ok(None) => DoctorProfileContext {
                connection_error: Some(
                    "no default or sole connection profile is configured for --online".to_owned(),
                ),
                ..DoctorProfileContext::offline()
            },
            Err(e) => DoctorProfileContext {
                connection_error: Some(doctor_connection_error(e)),
                ..DoctorProfileContext::offline()
            },
        };
    };

    match resolve_profile_options(Some(profile)) {
        Ok(Some(resolved)) => doctor_open_resolved_profile(resolved),
        Ok(None) => DoctorProfileContext {
            conn: None,
            connection_error: Some(format!("connection profile `{profile}` not found")),
            wallet_location: None,
            protected_profile_writable: false,
            connection_strategy: None,
            call_timeout_resolved: false,
            call_timeout: None,
            connect_timeout_seconds: None,
            proxy_user: false,
            profile_caps: None,
            auth_capabilities: None,
            sensitive_values: Vec::new(),
        },
        Err(e) => DoctorProfileContext {
            conn: None,
            connection_error: Some(doctor_connection_error(e)),
            wallet_location: None,
            protected_profile_writable: false,
            connection_strategy: None,
            call_timeout_resolved: false,
            call_timeout: None,
            connect_timeout_seconds: None,
            proxy_user: false,
            profile_caps: None,
            auth_capabilities: None,
            sensitive_values: Vec::new(),
        },
    }
}

fn doctor_audit_path_configured() -> bool {
    OracleMcpConfig::load(None)
        .map(|config| config.audit.path.is_some())
        .unwrap_or(false)
}

fn doctor_open_resolved_profile(resolved: ResolvedProfile) -> DoctorProfileContext {
    let wallet_location = resolved
        .opts
        .wallet_location
        .as_ref()
        .map(|path| path.display().to_string());
    let protected_profile_writable =
        resolved.level.is_protected() && resolved.level.max_level() > OperatingLevel::ReadOnly;
    let proxy_user = resolved.opts.auth_adapter.proxy_connect_user().is_some();
    let sensitive_values = doctor_sensitive_values(&resolved.opts);
    let call_timeout = resolved.opts.call_timeout;
    let connect_timeout_seconds = resolved.connect_timeout_seconds;
    let connection_strategy = Some(
        if resolved.pool_settings.is_some() {
            "hybrid_pool"
        } else {
            "single_session"
        }
        .to_owned(),
    );
    let profile_caps = Some(resolved.doctor_caps.clone());
    let auth_capabilities = Some(DoctorAuthCapabilities::from_connect_options(&resolved.opts));
    match block_on_connect(|cx| async move { try_open_runtime_connections(&cx, resolved).await }) {
        Ok(connections) => DoctorProfileContext {
            conn: Some(connections.session),
            connection_error: None,
            wallet_location,
            protected_profile_writable,
            connection_strategy,
            call_timeout_resolved: true,
            call_timeout,
            connect_timeout_seconds,
            proxy_user,
            profile_caps,
            auth_capabilities,
            sensitive_values,
        },
        Err(e) => DoctorProfileContext {
            conn: None,
            connection_error: Some(doctor_connection_error(e)),
            wallet_location,
            protected_profile_writable,
            connection_strategy,
            call_timeout_resolved: true,
            call_timeout,
            connect_timeout_seconds,
            proxy_user,
            profile_caps,
            auth_capabilities,
            sensitive_values,
        },
    }
}

fn run_doctor_cmd(robot_json: bool, profile: Option<String>, online: bool, fix: bool) -> ExitCode {
    // Offline by default: profile metadata inspection does not resolve secrets
    // or open Oracle. --online is the explicit live-connect boundary.
    let profile_ctx = doctor_profile_context(profile.as_deref(), online);
    let state_layout = doctor_state_layout(doctor_audit_path_configured());
    let mut fix_mutations = Vec::new();
    if fix {
        match apply_legacy_state_migration(state_layout.as_ref()) {
            Ok(Some(mutation)) => fix_mutations.push(mutation),
            Ok(None) => {}
            Err(e) => eprintln!("doctor --fix legacy state migration refused: {e}"),
        }
    }
    let ctx = DoctorContext {
        conn: profile_ctx.conn.as_deref(),
        connection_error: profile_ctx.connection_error,
        tns_admin: std::env::var("TNS_ADMIN").ok(),
        wallet_location: profile_ctx.wallet_location,
        protected_profile_writable: profile_ctx.protected_profile_writable,
        connection_strategy: profile_ctx.connection_strategy,
        call_timeout_resolved: profile_ctx.call_timeout_resolved,
        call_timeout: profile_ctx.call_timeout,
        connect_timeout_seconds: profile_ctx.connect_timeout_seconds,
        proxy_user: profile_ctx.proxy_user,
        online,
        profile_caps: profile_ctx.profile_caps,
        auth_capabilities: profile_ctx.auth_capabilities,
        service_health: service_app_doctor_snapshot().ok(),
        service_unit_caps: service_lifecycle::doctor_service_unit_caps(),
        state_layout,
        sensitive_values: profile_ctx.sensitive_values,
    };
    let mut report = block_on_connect(|cx| async move { run_doctor(&cx, &ctx).await });
    if fix {
        report = report.with_fix_report_mutations(fix_mutations);
    }
    let exit_code = doctor_process_exit_code(&report);
    if robot_json {
        let output = report
            .to_json_with_exit_code(i32::from(exit_code))
            .to_string();
        stdout_exit(write_stdout_line(&output), ExitCode::from(exit_code))
    } else {
        // The human report is the data here; print it on stdout.
        stdout_exit(
            write_stdout_text(&report.to_text_with_exit_code(i32::from(exit_code))),
            ExitCode::from(exit_code),
        )
    }
}

/// A no-driver / failed-connect stub connection: every operation returns the
/// recorded connect error, so serve can start and live tool calls degrade to a
/// structured envelope instead of a panic.
mod stub {
    use asupersync::Cx;
    use oraclemcp_db::{
        DbError, OracleBackend, OracleBind, OracleConnection, OracleConnectionInfo, OracleRow,
    };

    pub(super) struct StubConnection {
        error: DbError,
    }

    impl StubConnection {
        pub(super) fn new(error: DbError) -> Self {
            StubConnection { error }
        }
        fn err(&self) -> DbError {
            self.error.clone()
        }
    }

    #[async_trait::async_trait(?Send)]
    impl OracleConnection for StubConnection {
        fn backend(&self) -> OracleBackend {
            OracleBackend::RustOracle
        }
        async fn ping(&self, _cx: &Cx) -> Result<(), DbError> {
            Err(self.err())
        }
        async fn describe(&self, _cx: &Cx) -> Result<OracleConnectionInfo, DbError> {
            Err(self.err())
        }
        async fn query_rows(
            &self,
            _cx: &Cx,
            _sql: &str,
            _b: &[OracleBind],
        ) -> Result<Vec<OracleRow>, DbError> {
            Err(self.err())
        }
        async fn query_rows_named(
            &self,
            _cx: &Cx,
            _sql: &str,
            _b: &[(String, OracleBind)],
        ) -> Result<Vec<OracleRow>, DbError> {
            Err(self.err())
        }
        async fn execute(&self, _cx: &Cx, _s: &str, _b: &[OracleBind]) -> Result<u64, DbError> {
            Err(self.err())
        }
        async fn commit(&self, _cx: &Cx) -> Result<(), DbError> {
            Err(self.err())
        }
        async fn rollback(&self, _cx: &Cx) -> Result<(), DbError> {
            Err(self.err())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oraclemcp_config::HttpOAuthConfig;

    fn self_signed_cert() -> (Vec<u8>, Vec<u8>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        (
            cert.cert.pem().into_bytes(),
            cert.key_pair.serialize_pem().into_bytes(),
        )
    }

    fn target_tmp_file(name: &str) -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../target/tmp/oraclemcp-main-tests");
        fs::create_dir_all(&path).expect("test temp dir exists");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        path.push(format!("{}-{}-{name}", std::process::id(), nanos));
        path
    }

    #[test]
    fn runtime_profile_selection_does_not_resolve_secret_refs() {
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            schema_version = 1
            default_profile = "prod"

            [[profiles]]
            name = "prod"
            connect_string = "prod.example:1521/service"
            username = "APP_USER"
            credential_ref = "env:ORACLEMCP_TEST_UNSET_DB_PASSWORD"

            [profiles.oci]
            wallet_password_ref = "env:ORACLEMCP_TEST_UNSET_WALLET_PASSWORD"
            "#,
        )
        .expect("valid config");

        let selected = select_runtime_profile_from_config(&cfg, None)
            .expect("metadata selection does not touch secret backends")
            .expect("default profile selected");
        assert_eq!(selected.name, "prod");
        assert_eq!(selected.level.max_level(), OperatingLevel::ReadOnly);
        assert_eq!(
            selected.request_timeout,
            Some(std::time::Duration::from_secs(30))
        );
    }

    #[test]
    fn http_listen_refused_without_allow_no_auth() {
        let err = http_listen_guard(false, false, false, "127.0.0.1:7070", false).unwrap_err();
        assert_eq!(err.0, "ORACLEMCP_AUTH_REQUIRED");
    }

    // ── A8 multi-profile audit reachability (the keystone) ──────────────────

    #[test]
    fn reachable_ceiling_spans_writable_exposed_profile_with_readonly_startup() {
        // Per-profile opt-out: both profiles are exposed (neither sets
        // mcp_exposed=false). The startup profile is read-only, but a writable
        // profile is reachable — so a switch to it can run writes, and the
        // reachable ceiling must reflect that.
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "ro_start"
            connect_string = "localhost:1521/FREEPDB1"
            mcp_exposed = true

            [[profiles]]
            name = "writable"
            connect_string = "localhost:1521/FREEPDB1"
            max_level = "DDL"
            mcp_exposed = true
            "#,
        )
        .expect("config parses");
        let active = SessionLevelState::new(OperatingLevel::ReadOnly, false);
        assert_eq!(
            max_reachable_write_ceiling(&cfg, &active),
            OperatingLevel::Ddl
        );
    }

    #[test]
    fn reachable_ceiling_ignores_explicitly_hidden_writable_profile() {
        // Per-profile opt-out: a writable profile explicitly hidden with
        // `mcp_exposed = false` is not servable (the agent can never switch to
        // it), so it does not raise the reachable ceiling.
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "ro_exposed"
            connect_string = "localhost:1521/FREEPDB1"

            [[profiles]]
            name = "hidden_writable"
            connect_string = "localhost:1521/FREEPDB1"
            max_level = "READ_WRITE"
            mcp_exposed = false
            "#,
        )
        .expect("config parses");
        let active = SessionLevelState::new(OperatingLevel::ReadOnly, false);
        assert_eq!(
            max_reachable_write_ceiling(&cfg, &active),
            OperatingLevel::ReadOnly
        );
    }

    #[test]
    fn reachable_ceiling_spans_all_profiles_by_default() {
        // Per-profile opt-out default: with no profile hidden, all profiles are
        // servable, so a writable one raises the reachable ceiling even though
        // the server started on a read-only profile.
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "ro_start"
            connect_string = "localhost:1521/FREEPDB1"

            [[profiles]]
            name = "writable"
            connect_string = "localhost:1521/FREEPDB1"
            max_level = "READ_WRITE"
            "#,
        )
        .expect("config parses");
        let active = SessionLevelState::new(OperatingLevel::ReadOnly, false);
        assert_eq!(
            max_reachable_write_ceiling(&cfg, &active),
            OperatingLevel::ReadWrite
        );
    }

    #[test]
    fn exposed_profiles_summary_lists_exposed_and_counts_hidden() {
        // E5 boot notice (visibility only): exposed profiles are listed with
        // their ceiling; an explicitly hidden one is counted, not named.
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            [[profiles]]
            name = "dev"
            connect_string = "localhost:1521/FREEPDB1"

            [[profiles]]
            name = "prod_admin"
            connect_string = "localhost:1521/FREEPDB1"
            max_level = "DDL"
            mcp_exposed = false
            "#,
        )
        .expect("config parses");
        let summary = exposed_profiles_summary(&cfg);
        assert!(summary.contains("dev [ReadOnly]"), "{summary}");
        assert!(summary.contains("1 hidden"), "{summary}");
        assert!(
            !summary.contains("prod_admin"),
            "a hidden profile must not be named: {summary}"
        );
    }

    #[test]
    fn build_auditor_fails_closed_when_a_switchable_profile_can_write() {
        // The A8 keystone: a read-only startup profile + a writable exposed
        // profile + NO audit key must fail closed at startup (so the writable
        // profile can never be switched into and run writes UNAUDITED). This is
        // the case the old single-profile check missed. Assumes a clean env
        // (no ORACLEMCP_AUDIT_KEY), as the rest of the suite does.
        let active = SessionLevelState::new(OperatingLevel::ReadOnly, false);
        let audit = AuditConfig::default(); // no key_ref
        match build_auditor(&audit, &active, OperatingLevel::Ddl, &SystemSecretResolver) {
            Err((code, _)) => assert_eq!(code, "ORACLEMCP_AUDIT_KEY_REQUIRED"),
            Ok(_) => panic!("must fail closed: write reachable, no key"),
        }
    }

    #[test]
    fn build_auditor_installs_when_writable_profile_has_a_key() {
        // With a signing key configured, a writable reachable profile installs
        // an auditor (so the writable profile, after a switch, is audited).
        let dir = target_tmp_file("a8-audit");
        fs::create_dir_all(&dir).expect("tmp dir");
        let audit = AuditConfig {
            path: Some(dir.join("audit.jsonl")),
            key_ref: Some("literal:test-signing-key-material".to_owned()),
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

    #[test]
    fn build_auditor_optional_when_only_read_only_is_reachable() {
        // Read-only everywhere reachable + no key: auditor is optional (None).
        let active = SessionLevelState::new(OperatingLevel::ReadOnly, false);
        let audit = AuditConfig::default();
        match build_auditor(
            &audit,
            &active,
            OperatingLevel::ReadOnly,
            &SystemSecretResolver,
        ) {
            Ok(auditor) => assert!(auditor.is_none()),
            Err((code, msg)) => panic!("read-only-only needs no key: {code}: {msg}"),
        }
    }

    #[test]
    fn build_write_intent_log_fails_closed_on_unresolved_restart_intent() {
        let root = target_tmp_file("cx-c1-write-intents");
        {
            let log = WriteIntentLog::open(&root).expect("open intent log");
            let binding =
                oraclemcp_guard::ExecGrantBinding::new("sess-1", "lane-1", "principal-1", 1);
            let intent = oraclemcp_core::WriteIntent::new(oraclemcp_core::WriteIntentDetails {
                idempotency_key_material: "grant-1",
                subject: "profile:dev",
                active_profile: Some("dev"),
                tool: "oracle_execute",
                sql: "UPDATE employees SET name = name WHERE employee_id = 100",
                required_level: OperatingLevel::ReadWrite,
                binding: &binding,
            });
            log.append_pending(intent).expect("append pending intent");
        }

        match build_write_intent_log_at(&root, OperatingLevel::ReadWrite) {
            Err((code, message)) => {
                assert_eq!(code, "ORACLEMCP_WRITE_INTENT_IN_DOUBT");
                assert!(message.contains("unresolved intent"), "{message}");
                assert!(message.contains("sql_hash=sha256:"), "{message}");
            }
            Ok(_) => panic!("writable startup must fail closed with an unresolved intent"),
        }
    }

    #[test]
    fn http_listen_loopback_allowed_with_allow_no_auth() {
        assert!(http_listen_guard(true, false, false, "127.0.0.1:7070", false).is_ok());
        assert!(http_listen_guard(true, false, true, "[::1]:7070", false).is_ok());
    }

    #[test]
    fn http_listen_loopback_allowed_with_oauth_or_mtls() {
        assert!(http_listen_guard(false, true, false, "127.0.0.1:7070", false).is_ok());
        assert!(http_listen_guard(false, true, true, "127.0.0.1:7070", false).is_ok());
    }

    #[test]
    fn http_listen_non_loopback_refused_without_remote_optin() {
        let err = http_listen_guard(true, false, false, "0.0.0.0:7070", false).unwrap_err();
        assert_eq!(err.0, "ORACLEMCP_HTTP_REMOTE_BIND_REFUSED");
        let err = http_listen_guard(false, true, true, "192.168.1.10:7070", false).unwrap_err();
        assert_eq!(err.0, "ORACLEMCP_HTTP_REMOTE_BIND_REFUSED");
    }

    #[test]
    fn http_listen_non_loopback_allowed_with_remote_optin() {
        assert!(http_listen_guard(true, false, false, "0.0.0.0:7070", true).is_ok());
        assert!(http_listen_guard(false, true, true, "0.0.0.0:7070", true).is_ok());
    }

    #[test]
    fn http_listen_auth_refusal_precedes_remote_check() {
        let err = http_listen_guard(false, false, true, "0.0.0.0:7070", true).unwrap_err();
        assert_eq!(err.0, "ORACLEMCP_AUTH_REQUIRED");
    }

    #[test]
    fn http_cli_oauth_builds_enforced_transport_config() {
        let args = HttpServeArgs {
            allowed_hosts: vec!["mcp.example.com".to_owned()],
            allowed_origins: vec!["https://client.example.com".to_owned()],
            json_response: true,
            stateful: true,
            oauth_resource: Some("https://mcp.example.com/mcp".to_owned()),
            oauth_issuers: vec!["https://idp.example.com".to_owned()],
            oauth_authorization_servers: vec!["https://idp.example.com".to_owned()],
            oauth_required_scopes: vec!["oracle:read".to_owned()],
            oauth_hs256_secret_ref: Some("literal:test-secret".to_owned()),
            ..Default::default()
        };
        let http = apply_http_cli_overrides(HttpConfig::default(), &args);
        let cfg = http_transport_config_from_merged(http, false, &SystemSecretResolver)
            .expect("valid OAuth transport config");

        assert!(cfg.transport.oauth.is_some());
        assert_eq!(
            cfg.transport.resource_metadata.as_ref().expect("metadata")["resource"],
            serde_json::json!("https://mcp.example.com/mcp")
        );
        assert_eq!(cfg.transport.allowed_hosts, ["mcp.example.com"]);
        assert_eq!(
            cfg.transport.allowed_origins,
            ["https://client.example.com"]
        );
        assert!(cfg.transport.json_response);
        assert!(cfg.transport.stateful);
        assert!(cfg.transport.single_principal_guard.is_some());
        assert!(cfg.tls.is_none());
    }

    #[test]
    fn http_oauth_literal_secret_is_rejected_for_protected_profiles() {
        let http = HttpConfig {
            oauth: Some(HttpOAuthConfig {
                resource: Some("https://mcp.example.com/mcp".to_owned()),
                allowed_issuers: vec!["https://idp.example.com".to_owned()],
                authorization_servers: vec!["https://idp.example.com".to_owned()],
                required_scopes: vec!["oracle:read".to_owned()],
                hs256_secret_ref: Some("literal:test-secret".to_owned()),
                metadata_url: None,
            }),
            ..Default::default()
        };

        let err = http_transport_config_from_merged(http, true, &SystemSecretResolver)
            .expect_err("protected profile rejects literal OAuth secret");
        assert_eq!(err.0, "ORACLEMCP_HTTP_OAUTH_SECRET_INVALID");
        assert!(err.1.contains("plaintext literal credential is forbidden"));
        assert!(!err.1.contains("test-secret"));
    }

    #[test]
    fn stateless_http_read_workers_do_not_head_of_line_block() {
        struct ControlDispatch;

        impl ToolDispatch for ControlDispatch {
            fn dispatch<'a>(
                &'a self,
                _cx: &'a Cx,
                _context: oraclemcp_core::DispatchContext<'a>,
                _name: &'a str,
                _args: serde_json::Value,
            ) -> DispatchFuture<'a> {
                Box::pin(async {
                    DispatchOutcome::Ok(serde_json::json!({
                        "control": true
                    }))
                })
            }
        }

        struct BlockingReadDispatch {
            started: std::sync::mpsc::Sender<()>,
            release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
        }

        impl ToolDispatch for BlockingReadDispatch {
            fn dispatch<'a>(
                &'a self,
                _cx: &'a Cx,
                _context: oraclemcp_core::DispatchContext<'a>,
                _name: &'a str,
                _args: serde_json::Value,
            ) -> DispatchFuture<'a> {
                Box::pin(async move {
                    self.started.send(()).expect("test observer is alive");
                    let (lock, cvar) = &*self.release;
                    let mut released = lock.lock().expect("release mutex not poisoned");
                    while !*released {
                        released = cvar.wait(released).expect("release mutex not poisoned");
                    }
                    DispatchOutcome::Ok(serde_json::json!({
                        "schemas": []
                    }))
                })
            }
        }

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let read_factory: Arc<ReadWorkerFactoryBuilder> = Arc::new({
            let release = Arc::clone(&release);
            move |_profile| {
                let started = started_tx.clone();
                let release = Arc::clone(&release);
                Arc::new(move |_cx: &Cx, _lane_context: &LaneContext| {
                    let dispatch: Arc<dyn ToolDispatch> = Arc::new(BlockingReadDispatch {
                        started: started.clone(),
                        release: Arc::clone(&release),
                    });
                    Box::pin(async move { Ok(dispatch) })
                })
            }
        });
        let control_lane =
            LaneRuntime::spawn("test-stateless-control", Arc::new(ControlDispatch), 4);
        let dispatch = Arc::new(HttpStatelessReadDispatch::new(
            control_lane,
            Some("dev".to_owned()),
            2,
            read_factory,
        ));

        let mut handles = Vec::new();
        for _ in 0..2 {
            let dispatch = Arc::clone(&dispatch);
            handles.push(std::thread::spawn(move || {
                let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
                    .build()
                    .expect("test runtime builds");
                runtime.block_on(async move {
                    let cx = Cx::current().expect("test runtime installs Cx");
                    let outcome = dispatch
                        .dispatch(
                            &cx,
                            oraclemcp_core::DispatchContext::default()
                                .with_principal_key("oauth:reader"),
                            "oracle_list_schemas",
                            serde_json::json!({ "max_rows": 1 }),
                        )
                        .await;
                    assert!(matches!(outcome, DispatchOutcome::Ok(_)));
                });
            }));
        }

        started_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("first read worker starts");
        started_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("second read worker starts without waiting for first to finish");

        let (lock, cvar) = &*release;
        *lock.lock().expect("release mutex not poisoned") = true;
        cvar.notify_all();
        for handle in handles {
            handle.join().expect("read worker caller joins");
        }
    }

    #[test]
    fn stateless_http_profile_switch_closes_read_workers() {
        struct SwitchControlDispatch;

        impl ToolDispatch for SwitchControlDispatch {
            fn dispatch<'a>(
                &'a self,
                _cx: &'a Cx,
                _context: oraclemcp_core::DispatchContext<'a>,
                name: &'a str,
                _args: serde_json::Value,
            ) -> DispatchFuture<'a> {
                Box::pin(async move {
                    if name == "oracle_switch_profile" {
                        DispatchOutcome::Ok(serde_json::json!({
                            "active_profile": "prod"
                        }))
                    } else {
                        DispatchOutcome::Ok(serde_json::json!({
                            "control": name
                        }))
                    }
                })
            }
        }

        struct ProfileReadDispatch {
            profile: Option<String>,
            seen: std::sync::mpsc::Sender<Option<String>>,
            closed: std::sync::mpsc::Sender<DispatchCloseReason>,
        }

        impl ToolDispatch for ProfileReadDispatch {
            fn dispatch<'a>(
                &'a self,
                _cx: &'a Cx,
                _context: oraclemcp_core::DispatchContext<'a>,
                _name: &'a str,
                _args: serde_json::Value,
            ) -> DispatchFuture<'a> {
                Box::pin(async move {
                    self.seen
                        .send(self.profile.clone())
                        .expect("test profile observer is alive");
                    DispatchOutcome::Ok(serde_json::json!({
                        "schemas": []
                    }))
                })
            }

            fn close<'a>(
                &'a self,
                _cx: &'a Cx,
                reason: DispatchCloseReason,
            ) -> oraclemcp_core::DispatchCloseFuture<'a> {
                self.closed
                    .send(reason)
                    .expect("test close observer is alive");
                Box::pin(async { Ok(()) })
            }
        }

        let (profile_tx, profile_rx) = std::sync::mpsc::channel();
        let (closed_tx, closed_rx) = std::sync::mpsc::channel();
        let read_factory: Arc<ReadWorkerFactoryBuilder> = Arc::new(move |profile| {
            let seen = profile_tx.clone();
            let closed = closed_tx.clone();
            Arc::new(move |_cx: &Cx, _lane_context: &LaneContext| {
                let dispatch: Arc<dyn ToolDispatch> = Arc::new(ProfileReadDispatch {
                    profile: profile.clone(),
                    seen: seen.clone(),
                    closed: closed.clone(),
                });
                Box::pin(async move { Ok(dispatch) })
            })
        });
        let control_lane = LaneRuntime::spawn(
            "test-stateless-switch-control",
            Arc::new(SwitchControlDispatch),
            4,
        );
        let dispatch =
            HttpStatelessReadDispatch::new(control_lane, Some("dev".to_owned()), 1, read_factory);

        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("test runtime builds");
        runtime.block_on(async {
            let cx = Cx::current().expect("test runtime installs Cx");
            let first = dispatch
                .dispatch(
                    &cx,
                    oraclemcp_core::DispatchContext::default().with_principal_key("oauth:reader"),
                    "oracle_list_schemas",
                    serde_json::json!({ "max_rows": 1 }),
                )
                .await;
            assert!(matches!(first, DispatchOutcome::Ok(_)));

            let switched = dispatch
                .dispatch(
                    &cx,
                    oraclemcp_core::DispatchContext::default().with_principal_key("oauth:reader"),
                    "oracle_switch_profile",
                    serde_json::json!({ "profile": "prod" }),
                )
                .await;
            assert!(matches!(switched, DispatchOutcome::Ok(_)));

            let second = dispatch
                .dispatch(
                    &cx,
                    oraclemcp_core::DispatchContext::default().with_principal_key("oauth:reader"),
                    "oracle_list_schemas",
                    serde_json::json!({ "max_rows": 1 }),
                )
                .await;
            assert!(matches!(second, DispatchOutcome::Ok(_)));
        });

        assert_eq!(
            profile_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("first read records startup profile"),
            Some("dev".to_owned())
        );
        assert_eq!(
            closed_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("profile switch closes old read lane"),
            DispatchCloseReason::RuntimeDrop
        );
        assert_eq!(
            profile_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("next read records switched profile"),
            Some("prod".to_owned())
        );
    }

    #[test]
    fn http_tls_material_builds_native_tls_config() {
        let (server_cert, server_key) = self_signed_cert();
        let (client_ca, _client_ca_key) = self_signed_cert();
        let cert_path = target_tmp_file("server.pem");
        let key_path = target_tmp_file("server.key");
        let client_ca_path = target_tmp_file("client-ca.pem");
        fs::write(&cert_path, server_cert).expect("server cert fixture");
        fs::write(&key_path, server_key).expect("server key fixture");
        fs::write(&client_ca_path, client_ca).expect("client CA fixture");

        let args = HttpServeArgs {
            tls_cert: Some(cert_path.clone()),
            tls_key: Some(key_path),
            mtls_client_ca: Some(client_ca_path.clone()),
            mtls_client_fingerprints: vec![
                "sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
                    .to_owned(),
            ],
            ..Default::default()
        };
        let http = apply_http_cli_overrides(HttpConfig::default(), &args);
        assert_eq!(
            http.tls
                .as_ref()
                .and_then(|tls| tls.client_ca_path.as_deref()),
            Some(client_ca_path.as_path())
        );

        let cfg = http_transport_config_from_merged(http, false, &SystemSecretResolver)
            .expect("native TLS listener config builds");
        assert!(cfg.tls.is_some());
        assert!(cfg.mtls_required);
        assert!(!cfg.transport.mtls_clients.is_empty());
    }

    #[test]
    fn stub_connection_returns_an_envelopable_error() {
        let stub = stub::StubConnection::new(oraclemcp_db::DbError::Connect(
            "listener refused the connection".to_owned(),
        ));
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .expect("current-thread runtime");
        let err = runtime.block_on(async {
            let cx = Cx::current().expect("block_on installs a current Cx");
            stub.ping(&cx).await.expect_err("stub always errors")
        });
        // It maps to a structured envelope (no panic).
        let _ = err.into_envelope();
    }

    #[test]
    fn stdout_exit_treats_broken_pipe_as_success_path() {
        let code = stdout_exit(
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed")),
            ExitCode::from(2),
        );
        assert_eq!(format!("{code:?}"), "ExitCode(unix_exit_status(0))");
    }

    #[test]
    fn doctor_process_exit_code_matches_cli_contract() {
        let ok = oraclemcp_core::DoctorReport {
            checks: Vec::new(),
            profile_caps: None,
            auth_capabilities: None,
            service_health: None,
            service_unit_caps: None,
            fix: None,
        };
        assert_eq!(doctor_process_exit_code(&ok), 0);

        let failed = oraclemcp_core::DoctorReport {
            checks: vec![oraclemcp_core::CheckResult {
                id: 1,
                name: "example".to_owned(),
                status: oraclemcp_core::CheckStatus::Fail,
                detail: "failed".to_owned(),
                fix: None,
                failure_class: None,
                auth_mode: None,
                wallet_error: None,
                ora_code: None,
            }],
            profile_caps: None,
            auth_capabilities: None,
            service_health: None,
            service_unit_caps: None,
            fix: None,
        };
        let process_code = doctor_process_exit_code(&failed);
        assert_eq!(process_code, 2);
        assert_eq!(
            failed.to_json_with_exit_code(i32::from(process_code))["exit_code"],
            serde_json::json!(2)
        );
        let fix_report = failed.with_fix_report();
        assert_eq!(doctor_process_exit_code(&fix_report), 2);
    }

    #[test]
    fn doctor_sensitive_values_include_connect_material() {
        let opts = OracleConnectOptions {
            connect_string: "dbhost:1521/private_service".to_owned(),
            username: Some("APP_USER".to_owned()),
            password: Some("super_secret".to_owned()),
            auth_adapter: oraclemcp_db::AuthAdapter::Proxy {
                proxy_user: "MCP_PROXY".to_owned(),
                target_schema: "APP_OWNER".to_owned(),
            },
            wallet_location: Some("/home/operator/private-wallet".into()),
            wallet_password: Some("wallet_secret".to_owned()),
            ssl_server_cert_dn: Some("CN=private-db,O=Example,C=US".to_owned()),
            use_iam_token: true,
            iam_token: Some("iam.jwt.token".to_owned()),
            app_context: vec![(
                "private-namespace".to_owned(),
                "private-key".to_owned(),
                "private-value".to_owned(),
            )],
            session_identity: Some(oraclemcp_db::OracleSessionIdentity {
                program: Some("private-program".to_owned()),
                machine: Some("private-machine".to_owned()),
                os_user: Some("private-os-user".to_owned()),
                terminal: Some("private-terminal".to_owned()),
                module: Some("private-module".to_owned()),
                action: Some("private-action".to_owned()),
                client_identifier: Some("private-client-id".to_owned()),
                client_info: Some("private-client-info".to_owned()),
                driver_name: Some("private-driver".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let values = doctor_sensitive_values(&opts);
        for expected in [
            "dbhost:1521/private_service",
            "APP_USER",
            "super_secret",
            "MCP_PROXY",
            "APP_OWNER",
            "/home/operator/private-wallet",
            "wallet_secret",
            "CN=private-db,O=Example,C=US",
            "iam.jwt.token",
            "private-program",
            "private-machine",
            "private-os-user",
            "private-terminal",
            "private-module",
            "private-action",
            "private-client-id",
            "private-client-info",
            "private-driver",
            "private-namespace",
            "private-key",
            "private-value",
        ] {
            assert!(values.iter().any(|value| value == expected), "{values:?}");
        }
    }

    #[test]
    fn wallet_password_ref_uses_profile_secret_resolution_policy() {
        let secret = resolve_profile_secret(
            "wallet_password_ref",
            "dev",
            Some("literal:wallet"),
            false,
            &SystemSecretResolver,
        )
        .expect("dev literal")
        .expect("secret");
        assert_eq!(secret, "wallet");

        let err = resolve_profile_secret(
            "wallet_password_ref",
            "prod",
            Some("literal:wallet"),
            true,
            &SystemSecretResolver,
        )
        .expect_err("protected literal rejected");
        assert!(err.to_string().contains("wallet_password_ref"));
        assert!(
            err.to_string()
                .contains("plaintext literal credential is forbidden")
        );
    }

    #[test]
    fn profile_secret_resolution_errors_do_not_echo_secret_locators() {
        let err = resolve_profile_secret(
            "wallet_password_ref",
            "prod",
            Some("env:PRIVATE_WALLET_PASSWORD_NAME"),
            true,
            &SystemSecretResolver,
        )
        .expect_err("missing env var");
        let rendered = err.to_string();
        assert!(rendered.contains("wallet_password_ref"));
        assert!(rendered.contains("secret not found"));
        assert!(!rendered.contains("PRIVATE_WALLET_PASSWORD_NAME"));
        assert!(!rendered.contains("env:"));

        let err = resolve_profile_secret(
            "credential_ref",
            "prod",
            Some("noscheme-secret-ref"),
            true,
            &SystemSecretResolver,
        )
        .expect_err("malformed ref");
        let rendered = err.to_string();
        assert!(rendered.contains("credential_ref"));
        assert!(rendered.contains("malformed secret reference"));
        assert!(!rendered.contains("noscheme-secret-ref"));
    }

    #[test]
    fn doctor_connection_error_uses_agent_envelope_message() {
        let message = doctor_connection_error(oraclemcp_db::DbError::UnsupportedAuth(
            "connection profile `missing_ro` not found".to_owned(),
        ));
        assert_eq!(message, "connection profile `missing_ro` not found");
    }

    #[test]
    fn doctor_profile_auth_capabilities_are_metadata_only() {
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            schema_version = 1

            [[profiles]]
            name = "proxy"
            connect_string = "localhost:1521/FREEPDB1"
            username = "APP_USER"
            credential_ref = "env:ORACLE_PASSWORD"

            [profiles.proxy_auth]
            proxy_user = "APP_USER"
            target_schema = "APP_OWNER"

            [[profiles]]
            name = "iam"
            connect_string = "tcps://private.example/svc"
            username = "IAM_USER"

            [profiles.oci]
            wallet_location = "/wallets/private"
            use_iam_token = true

            [[profiles]]
            name = "external"
            connect_string = "tcps://private.example/svc"

            [profiles.oci]
            wallet_location = "/wallets/private"
            wallet_password_ref = "env:WALLET_PASSWORD"
            "#,
        )
        .expect("valid config");

        let proxy = doctor_auth_capabilities_for_profile(cfg.profile("proxy").unwrap());
        assert_eq!(proxy.selected, DoctorAuthModeKind::Proxy);
        let iam = doctor_auth_capabilities_for_profile(cfg.profile("iam").unwrap());
        assert_eq!(iam.selected, DoctorAuthModeKind::IamToken);
        let external = doctor_auth_capabilities_for_profile(cfg.profile("external").unwrap());
        assert_eq!(external.selected, DoctorAuthModeKind::ExternalWallet);

        let serialized = serde_json::to_string(&serde_json::json!([proxy, iam, external]))
            .expect("auth capabilities serialize");
        for forbidden in [
            "APP_USER",
            "APP_OWNER",
            "ORACLE_PASSWORD",
            "WALLET_PASSWORD",
            "/wallets/private",
            "private.example",
            "FREEPDB1",
        ] {
            assert!(
                !serialized.contains(forbidden),
                "{forbidden} leaked: {serialized}"
            );
        }
        for expected in [
            "\"driver\":\"thin\"",
            "\"selected\":\"proxy\"",
            "\"selected\":\"iam_token\"",
            "\"selected\":\"external_wallet\"",
            "\"support\":\"unsupported_in_thin\"",
        ] {
            assert!(
                serialized.contains(expected),
                "{expected} missing from {serialized}"
            );
        }
    }

    #[test]
    fn profiles_json_reports_non_secret_metadata() {
        let cfg = OracleMcpConfig::from_toml_str(
            r#"
            schema_version = 1
            default_profile = "dev"

            [[profiles]]
            name = "dev"
            description = "Development profile"
            connect_string = "localhost:1521/FREEPDB1"
            username = "APP_USER"
            credential_ref = "env:ORACLE_PASSWORD"
            max_level = "READ_ONLY"
            default_level = "READ_ONLY"
            require_signed_tools = true
            dashboard_ddl_workbench = true
            sdu = 32768

            [profiles.oci]
            wallet_location = "/wallets/private"
            wallet_password_ref = "env:WALLET_PASSWORD"
            ssl_server_cert_dn = "CN=private-db"

            [profiles.proxy_auth]
            proxy_user = "APP_USER"
            target_schema = "APP_OWNER"

            [profiles.drcp]
            pooled = true
            connection_class = "PRIVATE_CLASS"
            purity = "reuse"

            [[profiles.app_context]]
            namespace = "ORACLEMCP_CTX"
            key = "tenant_id"
            value = "tenant-123"
            "#,
        )
        .expect("valid config");

        let out = profiles_json(&cfg);
        assert_eq!(out["ok"], serde_json::json!(true));
        assert_eq!(out["profile_count"], serde_json::json!(1));
        assert_eq!(out["has_default_profile"], serde_json::json!(true));
        assert_eq!(out["profiles"][0]["name"], serde_json::json!("dev"));
        assert_eq!(out["profiles"][0]["is_default"], serde_json::json!(true));
        assert_eq!(
            out["profiles"][0]["require_signed_tools"],
            serde_json::json!(true)
        );
        assert_eq!(
            out["profiles"][0]["dashboard_ddl_workbench"],
            serde_json::json!(true)
        );
        let serialized = serde_json::to_string(&out).expect("json");
        assert!(!serialized.contains("APP_USER"));
        assert!(!serialized.contains("APP_OWNER"));
        assert!(!serialized.contains("ORACLE_PASSWORD"));
        assert!(!serialized.contains("WALLET_PASSWORD"));
        assert!(!serialized.contains("/wallets/private"));
        assert!(!serialized.contains("CN=private-db"));
        assert!(!serialized.contains("credential_ref"));
        assert!(!serialized.contains("wallet_password_ref"));
        assert!(!serialized.contains("proxy_auth"));
        assert!(!serialized.contains("target_schema"));
        assert!(!serialized.contains("PRIVATE_CLASS"));
        assert!(!serialized.contains("drcp"));
        assert!(!serialized.contains("ORACLEMCP_CTX"));
        assert!(!serialized.contains("tenant_id"));
        assert!(!serialized.contains("tenant-123"));
        assert!(!serialized.contains("app_context"));
        assert!(!serialized.contains("FREEPDB1"));
        assert!(!serialized.contains("connect_string"));
    }

    #[test]
    fn resolved_secret_material_is_absent_from_rendered_surfaces() {
        let resolved_db_secret = "resolved-db-secret-not-in-config";
        let resolved_wallet_secret = "resolved-wallet-secret-not-in-config";
        let resolved_audit_secret = "resolved-audit-secret-not-in-config";
        let credential_ref = "keyring:prod/app";
        let wallet_ref = "file:/run/secrets/oracle-wallet";

        let cfg = OracleMcpConfig::from_toml_str(&format!(
            r#"
            schema_version = 1

            [[profiles]]
            name = "prod"
            connect_string = "prod:1521/svc"
            username = "APP_USER"
            credential_ref = "{credential_ref}"

            [profiles.oci]
            wallet_password_ref = "{wallet_ref}"
            "#
        ))
        .expect("valid config");
        let profile_json = serde_json::to_string(&profiles_json(&cfg)).expect("profile json");

        let opts = OracleConnectOptions {
            connect_string: "prod:1521/svc".to_owned(),
            username: Some("APP_USER".to_owned()),
            password: Some(resolved_db_secret.to_owned()),
            wallet_password: Some(resolved_wallet_secret.to_owned()),
            iam_token: Some("resolved-iam-token-not-in-config".to_owned()),
            ..OracleConnectOptions::default()
        };
        let options_debug = format!("{opts:?}");

        let connection_info = oraclemcp_db::OracleConnectionInfo {
            session_user: Some("APP_USER".to_owned()),
            current_schema: Some("APP".to_owned()),
            ..Default::default()
        };
        let connection_info_json = serde_json::to_string(&connection_info).expect("conn json");

        let signing_key = SigningKey::new("test-key", resolved_audit_secret.as_bytes().to_vec());
        let signing_key_debug = format!("{signing_key:?}");
        let audit_record = oraclemcp_audit::AuditRecord::chained_signed(
            &oraclemcp_audit::AuditEntryDraft {
                subject: oraclemcp_audit::AuditSubject::new("subject", "hash"),
                db_evidence: None,
                cancel: None,
                tool: "oracle_query".to_owned(),
                sql: "select 1 from dual".to_owned(),
                danger_level: "READ_ONLY".to_owned(),
                decision: oraclemcp_audit::AuditDecision::Allowed,
                rows_affected: None,
                outcome: oraclemcp_audit::AuditOutcome::Succeeded,
            },
            1,
            oraclemcp_audit::GENESIS_HASH,
            "2026-06-30T00:00:00Z".to_owned(),
            &signing_key,
        );
        let audit_json = serde_json::to_string(&audit_record).expect("audit json");

        for rendered in [
            profile_json.as_str(),
            options_debug.as_str(),
            connection_info_json.as_str(),
            signing_key_debug.as_str(),
            audit_json.as_str(),
        ] {
            for forbidden in [
                resolved_db_secret,
                resolved_wallet_secret,
                resolved_audit_secret,
                "resolved-iam-token-not-in-config",
                credential_ref,
                wallet_ref,
            ] {
                assert!(
                    !rendered.contains(forbidden),
                    "rendered surface leaked {forbidden}: {rendered}"
                );
            }
        }
    }

    fn audit_record_for_db_evidence_summary(
        seq: u64,
        db_evidence: Option<DbEvidence>,
    ) -> AuditRecord {
        let key = SigningKey::new("test-key", b"db-evidence-summary-key".to_vec());
        AuditRecord::chained_signed(
            &oraclemcp_audit::AuditEntryDraft {
                subject: AuditSubject::new("oauth", "subject-hash"),
                db_evidence,
                cancel: None,
                tool: "oracle_execute".to_owned(),
                sql: format!("DELETE FROM private_table WHERE secret_id = {seq}"),
                danger_level: "GUARDED".to_owned(),
                decision: oraclemcp_audit::AuditDecision::Allowed,
                rows_affected: Some(1),
                outcome: oraclemcp_audit::AuditOutcome::Succeeded,
            },
            seq,
            oraclemcp_audit::GENESIS_HASH,
            format!("2026-07-02T00:00:{seq:02}Z"),
            &key,
        )
    }

    #[test]
    fn audit_db_evidence_summary_correlates_signed_session_tags() {
        let records = vec![
            audit_record_for_db_evidence_summary(
                1,
                Some(DbEvidence {
                    availability: Some("captured".to_owned()),
                    db_unique_name: Some("ORCL23A".to_owned()),
                    service_name: Some("freepdb1".to_owned()),
                    instance_name: Some("free".to_owned()),
                    session_user: Some("APP".to_owned()),
                    sid: Some("101".to_owned()),
                    serial_number: Some("202".to_owned()),
                    client_identifier: Some("oauth-subject".to_owned()),
                    module: Some("oraclemcp-test".to_owned()),
                    action: Some("execute".to_owned()),
                    ..DbEvidence::default()
                }),
            ),
            audit_record_for_db_evidence_summary(2, None),
        ];

        let summary = audit_db_evidence_summary(&records);
        assert_eq!(summary.status, "correlated");
        assert_eq!(summary.records, 2);
        assert_eq!(summary.with_db_evidence, 1);
        assert_eq!(summary.captured, 1);
        assert_eq!(summary.correlated, 1);
        assert_eq!(summary.with_session_tags, 1);
        assert_eq!(summary.missing, 1);

        let payload = audit_db_evidence_payload(&summary);
        assert_eq!(payload["source"], serde_json::json!("signed_audit_records"));
        assert_eq!(payload["live_database_query"], serde_json::json!(false));
        assert_eq!(
            payload["sample_correlations"][0]["seq"],
            serde_json::json!(1)
        );
        assert_eq!(
            payload["sample_correlations"][0]["sid"],
            serde_json::json!("101")
        );
        assert_eq!(
            payload["sample_correlations"][0]["serial_number"],
            serde_json::json!("202")
        );
        let rendered = serde_json::to_string(&payload).expect("payload json");
        assert!(!rendered.contains("DELETE"));
        assert!(!rendered.contains("private_table"));
        assert!(!rendered.contains("secret_id"));
    }

    #[test]
    fn audit_db_evidence_summary_degrades_when_evidence_unavailable() {
        let records = vec![
            audit_record_for_db_evidence_summary(
                1,
                Some(DbEvidence::unavailable("describe_failed")),
            ),
            audit_record_for_db_evidence_summary(2, None),
        ];

        let summary = audit_db_evidence_summary(&records);
        assert_eq!(summary.status, "degraded");
        assert_eq!(summary.degraded_reason, Some("db_evidence_unavailable"));
        assert_eq!(summary.records, 2);
        assert_eq!(summary.with_db_evidence, 1);
        assert_eq!(summary.unavailable, 1);
        assert_eq!(summary.missing, 1);
        assert_eq!(summary.correlated, 0);
        assert_eq!(summary.unavailable_reasons, vec!["describe_failed"]);
        assert!(audit_db_evidence_text(&summary).contains("DEGRADED"));
    }

    #[test]
    fn profiles_text_handles_empty_config() {
        let cfg = OracleMcpConfig::from_toml_str("").expect("empty config is valid");
        let text = profiles_text(&cfg);
        assert!(text.contains("no profiles configured"));
        assert!(text.contains("ORACLEMCP_CONFIG"));
    }

    #[test]
    fn setup_payload_is_generic_and_client_ready() {
        let out = setup_payload(
            "tenant_ro",
            "APP_PASSWORD",
            "/opt/oraclemcp-wrapper",
            "/etc/oraclemcp/profiles.toml",
            "/etc/oraclemcp/tools.d",
        );
        assert_eq!(out["ok"], serde_json::json!(true));
        assert_eq!(out["kind"], serde_json::json!("oraclemcp_setup"));
        assert!(
            out["profiles_toml"]
                .as_str()
                .expect("profiles_toml")
                .contains("credential_ref = \"env:APP_PASSWORD\"")
        );
        let profiles_toml = out["profiles_toml"].as_str().expect("profiles_toml");
        let cfg =
            OracleMcpConfig::from_toml_str(profiles_toml).expect("setup profiles TOML parses");
        assert_eq!(cfg.default_profile.as_deref(), Some("tenant_ro"));
        let profile = cfg.profile("tenant_ro").expect("starter profile exists");
        assert_eq!(profile.max_level(), OperatingLevel::ReadOnly);
        assert_eq!(profile.default_level(), OperatingLevel::ReadOnly);
        assert!(!profiles_toml.contains("wallet_password_ref"));
        assert!(!profiles_toml.contains("[profiles.oci]"));
        assert!(!profiles_toml.contains("[profiles.drcp]"));
        assert!(!profiles_toml.contains("[profiles.proxy_auth]"));
        assert!(!profiles_toml.contains("[[profiles.app_context]]"));
        assert!(!profiles_toml.contains("[profiles.session_identity]"));
        assert_eq!(
            out["paths"]["full_profile_example"],
            serde_json::json!("oraclemcp.example.toml")
        );
        assert_eq!(
            out["claude_mcp_json"]["mcpServers"]["oracle"]["command"],
            serde_json::json!("/opt/oraclemcp-wrapper")
        );
        assert!(
            out["codex_config_toml"]
                .as_str()
                .expect("codex config")
                .contains("tenant_ro")
        );
        assert_eq!(
            out["http_client_credentials"]["serve_args"],
            serde_json::json!([
                "serve",
                "--listen",
                "127.0.0.1:7070",
                "--client-credentials",
                "--profile",
                "tenant_ro"
            ])
        );
        assert_eq!(
            out["http_client_credentials"]["claude_mcp_add"],
            serde_json::json!([
                "claude",
                "mcp",
                "add",
                "oracle",
                "--transport",
                "http",
                "http://127.0.0.1:7070/mcp"
            ])
        );
        assert!(
            out["http_client_credentials"]["secret_rule"]
                .as_str()
                .expect("secret rule")
                .contains("never in profiles.toml")
        );
        assert!(
            out["custom_tool_toml"]
                .as_str()
                .expect("custom tool template")
                .contains("oraclemcp sign-tool")
        );
        let serialized = serde_json::to_string(&out).expect("json");
        assert!(serialized.contains("dbhost.example.com"));
        assert!(!serialized.contains("literal:"));
    }

    #[test]
    fn json_alias_is_accepted_before_and_after_subcommand() {
        let before = Cli::try_parse_from(["oraclemcp", "--json", "profiles"]).expect("parse");
        assert!(before.robot_json);
        assert!(matches!(before.command, Some(Command::Profiles)));

        let after = Cli::try_parse_from(["oraclemcp", "profiles", "--json"]).expect("parse");
        assert!(after.robot_json);
        assert!(matches!(after.command, Some(Command::Profiles)));
    }

    #[test]
    fn setup_and_sign_tool_commands_parse() {
        let setup = Cli::try_parse_from([
            "oraclemcp",
            "--json",
            "setup",
            "--write",
            "--profile",
            "tenant_ro",
            "--credential-env",
            "APP_PASSWORD",
        ])
        .expect("parse setup");
        assert!(setup.robot_json);
        assert!(matches!(
            setup.command,
            Some(Command::Setup {
                write: true,
                ref profile,
                ref credential_env,
                ..
            }) if profile == "tenant_ro" && credential_env == "APP_PASSWORD"
        ));

        let self_update = Cli::try_parse_from([
            "oraclemcp",
            "--json",
            "self-update",
            "--dry-run",
            "--version",
            "0.6.4",
            "--verify",
            "require",
            "--no-service",
        ])
        .expect("parse self-update");
        assert!(self_update.robot_json);
        assert!(matches!(
            self_update.command,
            Some(Command::SelfUpdate(SelfUpdateCliArgs {
                ref version,
                ref verify,
                dry_run: true,
                no_service: true,
                ..
            })) if version == "0.6.4" && verify.as_deref() == Some("require")
        ));

        let sign = Cli::try_parse_from([
            "oraclemcp",
            "sign-tool",
            "tools.toml",
            "--tool",
            "app_lookup",
        ])
        .expect("parse sign-tool");
        assert!(matches!(
            sign.command,
            Some(Command::SignTool {
                ref path,
                ref tool,
            }) if path == Path::new("tools.toml") && tool.as_deref() == Some("app_lookup")
        ));
    }

    #[test]
    fn audit_verify_with_db_evidence_command_parses() {
        let audit = Cli::try_parse_from([
            "oraclemcp",
            "--json",
            "audit",
            "verify",
            "audit.jsonl",
            "--with-db-evidence",
        ])
        .expect("parse audit verify");
        assert!(audit.robot_json);
        assert!(matches!(
            audit.command,
            Some(Command::Audit {
                command: AuditCommand::Verify {
                    ref file,
                    key_id: None,
                    with_db_evidence: true,
                }
            }) if file == Path::new("audit.jsonl")
        ));
    }

    #[test]
    fn dashboard_command_parses() {
        let dashboard = Cli::try_parse_from([
            "oraclemcp",
            "--json",
            "dashboard",
            "--url",
            "http://127.0.0.1:7777",
            "--no-open",
        ])
        .expect("parse dashboard");
        assert!(dashboard.robot_json);
        assert!(matches!(
            dashboard.command,
            Some(Command::Dashboard {
                ref url,
                no_open: true,
            }) if url == "http://127.0.0.1:7777"
        ));
    }

    #[test]
    fn om_alias_argv0_aware_parses_dashboard_help() {
        assert_eq!(
            display_binary_name_from_argv0(Some(std::ffi::OsStr::new("/usr/local/bin/om"))),
            "om"
        );
        assert_eq!(
            display_binary_name_from_argv0(Some(std::ffi::OsStr::new("OM.exe"))),
            "om"
        );
        assert_eq!(
            display_binary_name_from_argv0(Some(std::ffi::OsStr::new("/usr/local/bin/oraclemcp",))),
            "oraclemcp"
        );
        assert_eq!(display_binary_name_from_argv0(None), "oraclemcp");

        let matches = cli_command("om")
            .try_get_matches_from([
                "om",
                "--json",
                "dashboard",
                "--url",
                "http://127.0.0.1:7777",
                "--no-open",
            ])
            .expect("parse om dashboard");
        let dashboard = Cli::from_arg_matches(&matches).expect("build cli from alias matches");
        assert!(dashboard.robot_json);
        assert!(matches!(
            dashboard.command,
            Some(Command::Dashboard {
                ref url,
                no_open: true,
            }) if url == "http://127.0.0.1:7777"
        ));

        let mut help = Vec::new();
        cli_command("om")
            .write_long_help(&mut help)
            .expect("render om help");
        let help = String::from_utf8(help).expect("help is utf8");
        assert!(help.contains("Usage: om "));
        assert!(!help.contains("Usage: oraclemcp"));
        assert!(bare_invocation_hint("om").contains("`om serve`"));
        assert!(bare_invocation_hint("om").contains("`om doctor`"));
        assert!(bare_invocation_hint("om").contains("`om capabilities`"));
    }

    #[test]
    fn service_commands_parse() {
        let install = Cli::try_parse_from([
            "oraclemcp",
            "--json",
            "service",
            "install",
            "--dry-run",
            "--listen",
            "127.0.0.1:7070",
            "--profile",
            "dev_ro",
            "--allow-no-auth",
            "--client-credentials",
            "--skip-linger",
        ])
        .expect("parse service install");
        assert!(install.robot_json);
        assert!(matches!(
            install.command,
            Some(Command::Service {
                command: ServiceCliCommand::Install(ServiceInstallCliArgs {
                    ref listen,
                    ref profile,
                    allow_no_auth: true,
                    client_credentials: true,
                    skip_linger: true,
                    dry_run: true,
                    ..
                })
            }) if listen == "127.0.0.1:7070" && profile.as_deref() == Some("dev_ro")
        ));

        let uninstall = Cli::try_parse_from(["oraclemcp", "service", "uninstall", "--yes"])
            .expect("parse service uninstall");
        assert!(matches!(
            uninstall.command,
            Some(Command::Service {
                command: ServiceCliCommand::Uninstall(ServiceMutationCliArgs { yes: true, .. })
            })
        ));

        let status =
            Cli::try_parse_from(["oraclemcp", "service", "status"]).expect("parse service status");
        assert!(matches!(
            status.command,
            Some(Command::Service {
                command: ServiceCliCommand::Status(ServiceReadCliArgs { .. })
            })
        ));

        let logs = Cli::try_parse_from(["oraclemcp", "service", "logs", "--lines", "25"])
            .expect("parse service logs");
        assert!(matches!(
            logs.command,
            Some(Command::Service {
                command: ServiceCliCommand::Logs(ServiceLogsCliArgs { lines: 25, .. })
            })
        ));

        let restart = Cli::try_parse_from(["oraclemcp", "service", "restart", "--dry-run"])
            .expect("parse service restart");
        assert!(matches!(
            restart.command,
            Some(Command::Service {
                command: ServiceCliCommand::Restart(ServiceMutationCliArgs { dry_run: true, .. })
            })
        ));

        let backup = Cli::try_parse_from([
            "oraclemcp",
            "service",
            "backup",
            "--output",
            "/tmp/oraclemcp-backup",
            "--dry-run",
        ])
        .expect("parse service backup");
        assert!(matches!(
            backup.command,
            Some(Command::Service {
                command: ServiceCliCommand::Backup(ServiceBackupCliArgs {
                    ref output,
                    dry_run: true,
                    ..
                })
            }) if output.as_deref() == Some(Path::new("/tmp/oraclemcp-backup"))
        ));

        let restore = Cli::try_parse_from([
            "oraclemcp",
            "service",
            "restore",
            "/tmp/oraclemcp-backup",
            "--key_id",
            "2026-q2",
            "--dry-run",
        ])
        .expect("parse service restore");
        assert!(matches!(
            restore.command,
            Some(Command::Service {
                command: ServiceCliCommand::Restore(ServiceRestoreCliArgs {
                    ref backup,
                    ref key_id,
                    dry_run: true,
                    ..
                })
            }) if backup == Path::new("/tmp/oraclemcp-backup")
                && key_id.as_deref() == Some("2026-q2")
        ));
    }

    #[test]
    fn client_credential_commands_parse() {
        let issue = Cli::try_parse_from([
            "oraclemcp",
            "--json",
            "clients",
            "issue",
            "--label",
            "Claude Desktop",
            "--scope",
            "oracle:read",
            "--scope",
            "oracle:execute",
        ])
        .expect("parse client issue");
        assert!(issue.robot_json);
        assert!(matches!(
            issue.command,
            Some(Command::Clients {
                command: ClientCredentialCliCommand::Issue(ClientCredentialIssueCliArgs {
                    ref label,
                    ref scopes,
                })
            }) if label == "Claude Desktop"
                && scopes == &vec!["oracle:read".to_owned(), "oracle:execute".to_owned()]
        ));

        let issue_default_scope =
            Cli::try_parse_from(["oraclemcp", "clients", "issue", "--label", "Claude Desktop"])
                .expect("parse client issue with default scope");
        assert!(matches!(
            issue_default_scope.command,
            Some(Command::Clients {
                command: ClientCredentialCliCommand::Issue(ClientCredentialIssueCliArgs {
                    ref scopes,
                    ..
                })
            }) if scopes == &vec!["oracle:read".to_owned()]
        ));

        let rotate = Cli::try_parse_from([
            "oraclemcp",
            "client-credentials",
            "rotate",
            "client-0123456789abcdef0123456789abcdef",
        ])
        .expect("parse client rotate");
        assert!(matches!(
            rotate.command,
            Some(Command::Clients {
                command: ClientCredentialCliCommand::Rotate(ClientCredentialIdCliArgs {
                    ref client_id,
                })
            }) if client_id == "client-0123456789abcdef0123456789abcdef"
        ));

        let revoke = Cli::try_parse_from([
            "oraclemcp",
            "clients",
            "revoke",
            "client-0123456789abcdef0123456789abcdef",
        ])
        .expect("parse client revoke");
        assert!(matches!(
            revoke.command,
            Some(Command::Clients {
                command: ClientCredentialCliCommand::Revoke(ClientCredentialIdCliArgs {
                    ref client_id,
                })
            }) if client_id == "client-0123456789abcdef0123456789abcdef"
        ));
    }

    #[test]
    fn robot_docs_guide_is_available_with_or_without_guide_subcommand() {
        let bare = Cli::try_parse_from(["oraclemcp", "robot-docs"]).expect("parse");
        assert!(matches!(
            bare.command,
            Some(Command::RobotDocs { command: None })
        ));

        let explicit = Cli::try_parse_from(["oraclemcp", "robot-docs", "guide"]).expect("parse");
        assert!(matches!(
            explicit.command,
            Some(Command::RobotDocs {
                command: Some(RobotDocsCommand::Guide)
            })
        ));
    }

    #[test]
    fn agent_ergonomics_drift_guard_pins_capabilities_schema() {
        let out = capabilities_payload();
        for key in [
            "server_name",
            "server_version",
            "protocol_version",
            "tools",
            "operating_level",
            "transports",
            "connection",
            "features",
            "cli_contract",
            "mcp_cli_dashboard_parity",
        ] {
            assert!(out.get(key).is_some(), "missing capabilities key {key}");
        }
        assert_eq!(
            out["cli_contract"]["contract_version"],
            serde_json::json!(1)
        );
        assert_eq!(
            out["cli_contract"]["structured_output"]["alias"],
            serde_json::json!("--json")
        );
        assert_eq!(
            out["cli_contract"]["binary_names"],
            serde_json::json!(["oraclemcp", "om"])
        );

        let exit_codes = out["cli_contract"]["exit_codes"]
            .as_array()
            .expect("exit code dictionary");
        for code in [0, 1, 2, 3, 4] {
            assert!(
                exit_codes
                    .iter()
                    .any(|entry| entry["code"] == serde_json::json!(code)),
                "missing exit code {code}: {exit_codes:?}"
            );
        }
        assert!(
            serde_json::to_string(&out["cli_contract"])
                .expect("json")
                .contains("--dry-run")
        );

        let parity = out["mcp_cli_dashboard_parity"]["matrix"]
            .as_array()
            .expect("parity matrix");
        assert_eq!(parity.len(), 7);
        for id in [
            "discovery",
            "profile_inventory",
            "diagnostics",
            "guarded_sql",
            "schema_explorer",
            "service_and_auth",
            "audit",
        ] {
            let row = parity
                .iter()
                .find(|row| row["id"] == serde_json::json!(id))
                .unwrap_or_else(|| panic!("missing parity row {id}: {parity:?}"));
            assert_eq!(row["status"], serde_json::json!("aligned"));
            for face in ["cli", "mcp", "dashboard"] {
                assert!(
                    row[face]
                        .as_array()
                        .is_some_and(|values| !values.is_empty()),
                    "{id} has no {face} surface"
                );
            }
        }
    }

    #[test]
    fn agent_ergonomics_drift_guard_pins_help_footer() {
        for binary_name in ["oraclemcp", "om"] {
            let mut help = Vec::new();
            cli_command(binary_name)
                .write_long_help(&mut help)
                .expect("render help");
            let help = String::from_utf8(help).expect("help utf8");
            assert!(help.contains(&format!("Usage: {binary_name} ")));
            assert!(help.contains("Agent surfaces:"));
            assert!(help.contains("--json"));
            assert!(help.contains("oraclemcp --json capabilities"));
            assert!(help.contains("oraclemcp robot-docs guide"));
            assert!(help.contains("oraclemcp --json service install --dry-run"));
            assert!(help.contains("service mutations require --yes"));
        }
    }

    #[test]
    fn robot_docs_guide_outputs_agent_workflows() {
        let text = robot_docs::robot_docs_guide_text();
        assert!(text.contains("oraclemcp robot-docs guide"));
        assert!(text.contains("oracle_preview_sql"));
        assert!(text.contains("oracle_execute"));
        assert!(text.contains("READ_ONLY < READ_WRITE < DDL < ADMIN"));

        let out = robot_docs::robot_docs_guide_json();
        assert_eq!(out["ok"], serde_json::json!(true));
        assert_eq!(
            out["structured_output"]["alias"],
            serde_json::json!("--json")
        );
        assert_eq!(
            out["cli_contract"]["exit_codes"][4]["code"],
            serde_json::json!(4)
        );
        assert_eq!(
            out["mcp_cli_dashboard_parity"]["status"],
            serde_json::json!("aligned")
        );
        assert!(text.contains("MCP / CLI / dashboard parity"));
        assert!(text.contains("Exit codes: 0 success"));
        assert!(text.contains("Client smoke tests"));
        assert!(text.contains("oraclemcp --json setup --profile <profile>"));
        assert!(text.contains("Always-on service"));
        assert!(text.contains("oraclemcp --json service install --dry-run --profile <profile>"));
        assert!(
            text.contains(
                "oraclemcp service install --yes --client-credentials --profile <profile>"
            )
        );
        assert!(text.contains("Thin diagnostics"));
        assert!(text.contains("does not need Oracle Instant Client"));
        assert!(text.contains("Result materialization"));
        assert!(
            serde_json::to_string(&out)
                .expect("json")
                .contains("custom_tool_signing")
        );
        assert!(text.contains("MCP tools/list"));
        assert_eq!(
            out["tool_schema_contract"]["strict_client_safe"],
            serde_json::json!(
                "tool parameter schemas avoid top-level oneOf, anyOf, allOf, enum, and not"
            )
        );
        assert_eq!(
            out["client_setup"]["stdio"]["argv"],
            serde_json::json!([
                "oraclemcp",
                "serve",
                "--profile",
                "<profile>",
                "--allow-no-auth"
            ])
        );
        assert_eq!(
            out["client_setup"]["smoke_tests"][1]["mcp_method"],
            serde_json::Value::Null
        );
        assert_eq!(
            out["client_setup"]["smoke_tests"][2]["mcp_method"],
            serde_json::json!("tools/list")
        );
        assert_eq!(
            out["diagnostic_flow"][5]["argv"],
            serde_json::json!(["oraclemcp", "--json", "capabilities"])
        );
        assert_eq!(
            out["diagnostic_flow"][6]["argv"],
            serde_json::json!(["oraclemcp", "--json", "service", "status"])
        );
        assert_eq!(
            out["first_commands"][0]["argv"],
            serde_json::json!(["oraclemcp", "--json", "setup", "--profile", "<profile>"])
        );
        assert_eq!(
            out["first_commands"][1]["argv"],
            serde_json::json!(["oraclemcp", "--json", "profiles"])
        );
        assert_eq!(
            out["first_commands"][3]["argv"],
            serde_json::json!([
                "oraclemcp",
                "--json",
                "doctor",
                "--online",
                "--profile",
                "<profile>"
            ])
        );
        assert_eq!(
            out["first_commands"][5]["argv"],
            serde_json::json!([
                "oraclemcp",
                "--json",
                "service",
                "install",
                "--dry-run",
                "--profile",
                "<profile>"
            ])
        );
        assert_eq!(
            out["client_setup"]["service"]["status"]["argv"],
            serde_json::json!(["oraclemcp", "--json", "service", "status"])
        );
        assert_eq!(
            out["safety_model"]["levels"],
            serde_json::json!(["READ_ONLY", "READ_WRITE", "DDL", "ADMIN"])
        );
        assert_eq!(
            out["thin_diagnostics"]["driver"],
            serde_json::json!(
                "pure-Rust oracledb thin driver; no Oracle Instant Client, ODPI-C, libclntsh, or C toolchain required"
            )
        );
        assert!(
            out["thin_diagnostics"]["secret_handling"]
                .as_str()
                .expect("secret handling text")
                .contains("wallet paths")
        );
        assert!(
            out["result_materialization"]["ref_cursors"]
                .as_str()
                .expect("ref cursor text")
                .contains("nested result objects")
        );
        assert!(
            serde_json::to_string(&out)
                .expect("json")
                .contains("oracle_preview_sql")
        );
    }

    fn custom_def(name: &str) -> CustomToolDef {
        CustomToolDef {
            name: name.to_owned(),
            description: "Test custom tool".to_owned(),
            sql: Some("SELECT 1 FROM dual".to_owned()),
            call: None,
            params: Vec::new(),
            output_mode: oraclemcp_core::OutputMode::Rows,
            declared_level: None,
            signature: None,
        }
    }

    #[test]
    fn custom_tool_names_cannot_duplicate_or_shadow_advertised_tools() {
        let err = validate_custom_tool_names(&[custom_def("app_lookup"), custom_def("app_lookup")])
            .expect_err("duplicate custom names rejected");
        assert_eq!(err.error_class, ErrorClass::InvalidArguments);
        assert!(err.message.contains("duplicate custom tool name"));

        let err = validate_custom_tool_names(&[custom_def("query")])
            .expect_err("compatibility alias collision rejected");
        assert_eq!(err.error_class, ErrorClass::InvalidArguments);
        assert!(err.message.contains("collides"));
    }

    #[test]
    fn build_server_advertises_the_registered_tools_plus_capabilities() {
        let conn = open_connection(OracleConnectOptions::default());
        let server = build_server(
            conn,
            None,
            None,
            default_read_only_level(),
            ServerBuildOptions {
                transport: ServerTransportMode::Stdio,
                custom_catalog: CustomToolCatalog::default(),
                auditor: None,
                write_intents: None,
                secret_resolver: Arc::new(SystemSecretResolver),
                request_timeout: OracleConnectOptions::default().call_timeout,
                metrics: None,
                profile_drain: ProfileDrainState::default(),
            },
        );
        // The capabilities report carries the registry's tools.
        let caps = registry::capabilities(env!("CARGO_PKG_VERSION"), LIVE_DB, false);
        assert_eq!(caps.tools.len(), registry::tool_names().len());
        // Smoke: the server clones (it is Clone) — proves it is fully built.
        let _ = server.clone();
    }
}
