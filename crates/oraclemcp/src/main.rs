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

mod audit_evidence;
mod discover;
mod readiness;
mod robot_docs;
mod service_lifecycle;

use audit_evidence::{
    audit_db_evidence_payload, audit_db_evidence_summary, audit_db_evidence_text,
};

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use asupersync::Cx;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use oraclemcp::cost_budget::QueryCostBudgetStore;
use oraclemcp::dispatch::{
    McpExposurePolicy, OracleDispatcher, ProfileConnectionBundle, ProfileConnector,
    ProfileDrainState, ProfileGenerationAdmission, StatelessReadStrategy, profile_draining_error,
    profile_not_available, result_masking_policy_from_profile, stateless_read_worker_tool,
};
use oraclemcp::registry;
use oraclemcp_audit::{
    AuditError, AuditKeyring, AuditSink, AuditSubject, Auditor, FileAuditSink, HmacSha256Key,
    ShippingAuditSink, ShippingForwarder, SigningKey, WormFileForwarder,
};
use oraclemcp_auth::{
    Hs256Verifier, ResourceServerConfig, SecretError, SecretResolver, SystemSecretResolver,
    resolve_secret_with,
};
use oraclemcp_config::{
    AuditConfig, CONFIG_PATH_ENV, ConnectionProfile, CumulativeQueryCostBudgetConfig, HttpConfig,
    HttpControlConfig, HttpTlsConfig, OracleMcpConfig,
};
use oraclemcp_core::admission::DEFAULT_READ_PER_PROFILE_CAP;
use oraclemcp_core::http::SinglePrincipalGuard;
use oraclemcp_core::incident::{
    Cassette, CassetteFrame, IncidentCaptureError, IncidentCaptureRequest, IncidentReplayError,
    capture_bundle, replay_bundle,
};
use oraclemcp_core::{
    AdmissionController, CapabilitiesReport, ChangeProposalStore, ClientCredentialError,
    ClientCredentialIssueRequest, ClientCredentialLifecycle, ClientCredentialStore,
    ConfigApplyOutcome, ConfigDraftPreview, ConfigOpsBackend, ConfigOpsError, ConfigOpsService,
    ConfigOpsStatus, ConfigReloadApplier, ConfigReloadApplyReport, CustomToolCatalog,
    CustomToolDef, DASHBOARD_PAIRING_TTL_SECONDS, DEFAULT_REQUEST_TIMEOUT, DashboardAuth,
    DashboardAuthError, DispatchCloseReason, DispatchContext, DispatchFuture, DispatchOutcome,
    DoctorAuditPosture, DoctorAuthCapabilities, DoctorAuthModeKind, DoctorContext, DoctorLevelCaps,
    DoctorProfileCaps, DoctorStateLayout, EffectiveHttpScheme, ExportRegistry, FeatureTiers,
    FileStore, HttpSessionLifecycle, HttpTransportConfig, LaneContext, LaneDispatchFactory,
    LaneDispatchFactoryBuilder, LaneRuntime, MCP_PATH, McpSurfaceDetail, McpSurfaceFuture,
    MtlsClientRegistry, OAuthEnforcement, ObservabilityState, OperatorAuthorityPolicy,
    OracleMcpServer, PROTECTED_RESOURCE_METADATA_PATH, PreparedLaneDispatch, ServiceOwner,
    ServiceTransport, ShutdownCoordinator, SiemFormat, SiemHttpForwarder, SourceHistoryStore,
    StatefulLaneDispatch, StdioAuthPolicy, TlsMaterial, TlsServerConfig, ToolDispatch,
    ToolStreamSender, WriteIntentLog, apply_legacy_state_migration, build_server_config,
    default_dashboard_ticket_dir, load_tools, load_tools_for_profile,
    mint_dashboard_pairing_ticket, operator_subject_id_hash, parse_tools_file,
    prepare_dashboard_pairing, probe_dashboard_http_service, requires_mtls, run_doctor,
    service_app_doctor_snapshot, sign, start_oraclemcp_service_app_with_transport,
};
use oraclemcp_db::{
    DbError, OracleConnectOptions, OracleConnection, OraclePool, PoolSettings, ResultMaskingPolicy,
    RustOracleConnection,
};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use oraclemcp_guard::incident::{BuildIdentity, CapturedLane, CapturedVerdict, IncidentTrigger};
use oraclemcp_guard::{
    Classifier, ClassifierConfig, OperatingLevel, SessionLevelState, SqlPolicyConfig,
};
use oraclemcp_telemetry::{HealthState, Metrics, OtlpConfig};
use service_lifecycle::{
    ServiceBackupOptions, ServiceCommand as ServiceLifecycleCommand, ServiceInstallOptions,
    ServiceLogsOptions, ServiceMutationOptions, ServiceReadOptions, ServiceRestoreOptions,
    acquire_service_instance_guard,
};

/// Whether this binary was built with Oracle connectivity support. This is a
/// build capability, not a claim about a currently reachable database.
const BUILT_WITH_LIVE_DB: bool = true;
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
        /// Permit unauthenticated development: disables stdio's init-token
        /// requirement only when no token is configured, and permits HTTP to
        /// start without configured auth. A non-loopback HTTP bind still needs
        /// explicit remote opt-in; never use this for remote exposure.
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
    /// Print a listener-bound one-time dashboard pairing URL.
    Dashboard {
        /// Base URL of the running local oraclemcp HTTP service.
        #[arg(long, default_value = "http://127.0.0.1:7070")]
        url: String,
        /// Suppress the manual-open reminder (pairing URLs are never auto-launched).
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
        /// Discover tnsnames.ora net-services and synthesize read-only profiles.
        /// Interactive on a TTY; a non-TTY caller must add --discover-tns/--yes.
        #[arg(long)]
        discover: bool,
        /// Non-interactive consent to scan for tnsnames.ora and write the
        /// discovered read-only profiles (required by --discover on a non-TTY).
        #[arg(long = "discover-tns")]
        discover_tns: bool,
        /// Grant non-interactive consent (scan and write) for --discover.
        #[arg(long)]
        yes: bool,
        /// With --discover, scan and report the plan without writing any config.
        #[arg(long = "dry-run")]
        dry_run: bool,
        /// Example profile name to use in generated snippets.
        #[arg(long, default_value = "db_ro")]
        profile: String,
        /// Environment variable name used by credential_ref in the profile template.
        #[arg(long, default_value = "ORACLE_APP_PASSWORD")]
        credential_env: String,
        /// Use this wrapper script as the client-snippet command instead of the
        /// resolved oraclemcp binary. Setup only prints a wrapper template; you
        /// must create the wrapper (and make it executable) before the snippets
        /// work.
        #[arg(long)]
        wrapper_path: Option<String>,
        /// Config path shown in generated guidance.
        #[arg(long, default_value = DEFAULT_SETUP_CONFIG_PATH)]
        config_path: String,
        /// Custom tools directory shown in generated guidance.
        #[arg(long, default_value = "~/.config/oraclemcp/tools.d")]
        tools_dir: String,
    },
    /// Run the authenticated installer embedded in this binary to update it.
    #[command(name = "self-update", alias = "self_update")]
    SelfUpdate(SelfUpdateCliArgs),
    /// Print HMAC signatures for operator-defined custom tool definitions.
    ///
    /// ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY must contain at least 32 bytes.
    #[command(name = "sign-tool", alias = "sign_tools")]
    SignTool {
        /// TOML file containing one or more [[tool]] definitions.
        path: PathBuf,
        /// Sign only this tool name from the file.
        #[arg(long)]
        tool: Option<String>,
        /// Write each generated signature into its matching [[tool]] block.
        #[arg(long, alias = "in-place")]
        write: bool,
    },
    /// Operate on the out-of-band audit log (verify the signed hash chain).
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
    /// Capture a redacted, deterministic incident bundle for offline replay.
    Incident {
        #[command(subcommand)]
        command: IncidentCommand,
    },
    /// Export the accumulated redacted refusal corpus as a shippable dataset.
    #[command(name = "refusal-corpus", alias = "refusal_corpus")]
    RefusalCorpus {
        #[command(subcommand)]
        command: RefusalCorpusCommand,
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
        /// Override the active key id for a legacy env-only key. Mixed-key
        /// rotation should use [[audit.verification_keys]] instead.
        #[arg(long)]
        key_id: Option<String>,
        /// Summarize signed database evidence and session-tag correlation.
        #[arg(long, visible_alias = "with_db_evidence")]
        with_db_evidence: bool,
    },
}

#[derive(Subcommand, Debug)]
enum IncidentCommand {
    /// Capture one stdin-supplied statement into a new redacted bundle directory.
    Capture(IncidentCaptureCliArgs),
    /// Re-classify a verified bundle under its recorded LabRuntime seed.
    Replay(IncidentReplayCliArgs),
}

#[derive(Subcommand, Debug)]
enum RefusalCorpusCommand {
    /// Export the corpus as deterministic, deduplicated, re-validated JSONL.
    Export(RefusalCorpusExportCliArgs),
}

#[derive(Args, Debug)]
struct RefusalCorpusExportCliArgs {
    /// Destination file for the exported dataset. It must differ from the source
    /// corpus path; a malformed or tampered corpus aborts the export instead of
    /// shipping a best-effort dataset.
    #[arg(long)]
    out: PathBuf,
    /// Source corpus state file to export. Defaults to the served corpus the
    /// dispatcher appends to ($XDG_STATE_HOME/oraclemcp/corpus/refusals.jsonl).
    #[arg(long)]
    corpus: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct IncidentCaptureCliArgs {
    /// New directory for the redacted incident bundle. It must not already exist.
    bundle: PathBuf,
    /// Deterministic LabRuntime seed recorded for a future replay.
    #[arg(long)]
    seed: u64,
}

#[derive(Args, Debug)]
struct IncidentReplayCliArgs {
    /// Existing self-verifying incident bundle directory.
    bundle: PathBuf,
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
    /// Restore an authenticated service backup after verifying every payload and its audit chain.
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
    /// Permit HTTP without configured auth (local development only). A
    /// non-loopback bind still needs explicit remote opt-in.
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
    /// Release version to install, e.g. 0.6.6 or v0.6.6.
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
    /// Override the active id for a legacy env-only audit key.
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
    /// Secret reference for the built-in HS256 verifier (at least 32 bytes),
    /// e.g. env:JWT_SECRET.
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
    /// Start a separately bounded mandatory-mTLS operator/readiness listener.
    /// Reuses --tls-*, --mtls-client-ca, and registered fingerprint material.
    #[arg(long = "control-listen")]
    control_listen: Option<String>,
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
            discover,
            discover_tns,
            yes,
            dry_run,
            profile,
            credential_env,
            wrapper_path,
            config_path,
            tools_dir,
        } => {
            if discover || discover_tns {
                let flags = discover::DiscoverFlags {
                    interactive: discover::stdin_is_interactive(),
                    discover_tns,
                    yes,
                    dry_run,
                };
                discover::run_setup_discover(
                    robot_json,
                    flags,
                    setup_write_target_path(&config_path),
                )
            } else {
                run_setup(
                    robot_json,
                    write,
                    &profile,
                    &credential_env,
                    wrapper_path.as_deref(),
                    &config_path,
                    &tools_dir,
                )
            }
        }
        Command::SelfUpdate(args) => run_self_update_cmd(robot_json, args),
        Command::SignTool { path, tool, write } => {
            run_sign_tool(robot_json, &path, tool.as_deref(), write)
        }
        Command::Audit { command } => match command {
            AuditCommand::Verify {
                file,
                key_id,
                with_db_evidence,
            } => run_audit_verify(robot_json, &file, key_id.as_deref(), with_db_evidence),
        },
        Command::Incident { command } => match command {
            IncidentCommand::Capture(args) => run_incident_capture(robot_json, args),
            IncidentCommand::Replay(args) => run_incident_replay(robot_json, args),
        },
        Command::RefusalCorpus { command } => match command {
            RefusalCorpusCommand::Export(args) => run_refusal_corpus_export(robot_json, args),
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
    max_query_cost: Option<u64>,
    cumulative_query_cost_budget: Option<CumulativeQueryCostBudgetConfig>,
    result_masking: Option<ResultMaskingPolicy>,
    sql_policy: Option<SqlPolicyConfig>,
    require_signed_tools: bool,
}

#[derive(Clone)]
struct ResolvedProfile {
    name: String,
    opts: OracleConnectOptions,
    level: SessionLevelState,
    require_signed_tools: bool,
    max_query_cost: Option<u64>,
    cumulative_query_cost_budget: Option<CumulativeQueryCostBudgetConfig>,
    pool_settings: Option<PoolSettings>,
    doctor_caps: DoctorProfileCaps,
    connect_timeout_seconds: Option<u64>,
    inactivity_timeout_seconds: Option<u64>,
    keepalive_minutes: Option<u64>,
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
        max_query_cost: chosen.max_query_cost,
        cumulative_query_cost_budget: chosen.cumulative_query_cost_budget.clone(),
        result_masking: result_masking_policy_from_profile(chosen).map_err(|error| {
            DbError::UnsupportedAuth(format!(
                "failed to load result masking policy for profile `{}`: {error}",
                chosen.name
            ))
        })?,
        sql_policy: chosen.sql_policy.clone(),
        require_signed_tools: chosen.require_signed_tools(),
    }))
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

    resolve_profile_options_from_config_with(&cfg, profile, secret_resolver)
}

fn resolve_profile_options_from_config_with(
    cfg: &OracleMcpConfig,
    profile: Option<&str>,
    secret_resolver: &dyn SecretResolver,
) -> Result<Option<ResolvedProfile>, DbError> {
    let Some(chosen) = selected_config_profile(cfg, profile)? else {
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

    let mut ctx = oraclemcp_core::build_session_context(chosen, password, wallet_password, false)?;
    // B2.2a: resolve the server-side OCI IAM database token (env/file source) at
    // connect time and inject it into `options.iam_token`, so the B2 adapter
    // wires it through `with_access_token` (TCPS-enforced). A no-op unless the
    // profile enables `use_iam_token`; fail-closed on a non-TCPS transport or an
    // empty/missing token. The token is never persisted, rendered, or logged.
    oraclemcp_core::inject_iam_token(chosen, &mut ctx.options)
        .map_err(|e| DbError::UnsupportedAuth(e.to_string()))?;
    let doctor_caps = doctor_profile_caps(chosen, &ctx.level_state);
    Ok(Some(ResolvedProfile {
        name: chosen.name.clone(),
        opts: ctx.options,
        level: ctx.level_state,
        require_signed_tools: chosen.require_signed_tools(),
        max_query_cost: chosen.max_query_cost,
        cumulative_query_cost_budget: chosen.cumulative_query_cost_budget.clone(),
        pool_settings: ctx.pool_settings,
        doctor_caps,
        connect_timeout_seconds: chosen.connect_timeout_seconds,
        inactivity_timeout_seconds: chosen.inactivity_timeout_seconds,
        keepalive_minutes: chosen.keepalive_minutes,
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
/// Open the primary and optional stateless connection from one resolved
/// profile. In particular, password, wallet-password, and IAM-token references
/// are resolved exactly once and the resulting options are cloned for both
/// physical connections.
fn profile_connector(secret_resolver: Arc<dyn SecretResolver>) -> Arc<ProfileConnector> {
    Arc::new(move |cx: &Cx, generation| {
        let secret_resolver = Arc::clone(&secret_resolver);
        Box::pin(async move {
            let config = generation.config().ok_or_else(|| {
                DbError::UnsupportedAuth(
                    "profile generation has no accepted config snapshot".to_owned(),
                )
            })?;
            let profile = generation.profile();
            let Some(resolved) = resolve_profile_options_from_config_with(
                config,
                Some(profile),
                secret_resolver.as_ref(),
            )?
            else {
                return Err(DbError::UnsupportedAuth(format!(
                    "connection profile `{profile}` not found"
                )));
            };
            let connections = try_open_runtime_connections(cx, resolved).await?;
            Ok(ProfileConnectionBundle::new(
                connections.session,
                connections.stateless,
            ))
        })
    })
}

fn load_custom_catalog_for_generation(
    generation: &oraclemcp::dispatch::ProfileGenerationLease,
    level: &SessionLevelState,
) -> Result<CustomToolCatalog, ErrorEnvelope> {
    let config = generation
        .config()
        .ok_or_else(|| custom_tool_error("profile generation has no accepted config snapshot"))?;
    load_custom_catalog_for_snapshot(config, Some(generation.profile()), level)
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

impl std::fmt::Debug for RuntimeConnections {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The trait objects are not `Debug`; surface only the shape so tests can
        // `expect_err`/`unwrap` a `Result<RuntimeConnections, _>`.
        f.debug_struct("RuntimeConnections")
            .field("stateless", &self.stateless.is_some())
            .finish_non_exhaustive()
    }
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
    let (session_options, stateless_options, pool_settings) = runtime_connection_options(resolved);
    try_open_runtime_connections_with(
        || try_open_connection(cx, session_options),
        || try_open_stateless_connection(cx, stateless_options, pool_settings),
    )
    .await
}

/// Open the authoritative pinned session before attempting the optional pool.
///
/// The pinned session remains usable when pool bootstrap fails: dispatch already
/// has a guarded fallback for stateless reads, while discarding the proven
/// session would turn an availability-only pool failure into a total outage.
async fn try_open_runtime_connections_with<OpenSession, SessionFuture, OpenPool, PoolFuture>(
    open_session: OpenSession,
    open_pool: OpenPool,
) -> Result<RuntimeConnections, DbError>
where
    OpenSession: FnOnce() -> SessionFuture,
    SessionFuture: std::future::Future<Output = Result<Box<dyn OracleConnection>, DbError>>,
    OpenPool: FnOnce() -> PoolFuture,
    PoolFuture: std::future::Future<Output = Result<Option<Box<dyn OracleConnection>>, DbError>>,
{
    let session = open_session().await?;
    let stateless = match open_pool().await {
        Ok(stateless) => stateless,
        Err(_) => {
            // Never render the driver error here: connection strings and
            // credential-adjacent details can be embedded in connect errors.
            // The stable class is enough for operators and log metrics.
            tracing::warn!(
                failure_class = "optional_pool_bootstrap_failed",
                fallback = "guarded_pinned_session",
                "optional stateless pool unavailable; retaining the live pinned session"
            );
            None
        }
    };
    Ok(RuntimeConnections { session, stateless })
}

fn runtime_connection_strategy(
    pool_configured: bool,
    connections: &RuntimeConnections,
) -> &'static str {
    match (pool_configured, connections.stateless.is_some()) {
        (true, true) => "pinned_plus_stateless",
        (true, false) => "pinned_plus_stateless_degraded",
        (false, _) => "single_session",
    }
}

/// Split one fully-resolved profile into the two physical-connection plans.
/// Secret references have already been resolved at this point, so cloning the
/// options cannot mix credential epochs when the backing secret rotates.
fn runtime_connection_options(
    resolved: ResolvedProfile,
) -> (
    OracleConnectOptions,
    OracleConnectOptions,
    Option<PoolSettings>,
) {
    let ResolvedProfile {
        opts,
        pool_settings,
        ..
    } = resolved;
    (opts.clone(), opts, pool_settings)
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
    config: &OracleMcpConfig,
    profile: &str,
    secret_resolver: &dyn SecretResolver,
    include_stateless: bool,
) -> RuntimeConnections {
    let resolved =
        match resolve_profile_options_from_config_with(config, Some(profile), secret_resolver) {
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
    config: &OracleMcpConfig,
    include_stateless: bool,
    secret_resolver: &dyn SecretResolver,
) -> RuntimeConnections {
    match plan {
        RuntimeConnectionPlan::Profile(profile) => {
            open_profile_runtime_connections(config, &profile, secret_resolver, include_stateless)
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
    config: &OracleMcpConfig,
    active_profile: Option<&str>,
    level: &SessionLevelState,
) -> Result<bool, ErrorEnvelope> {
    if level.is_protected() {
        return Ok(true);
    }
    let Some(profile_name) = active_profile else {
        return Ok(false);
    };
    config
        .profile(profile_name)
        .map(|profile| profile.require_signed_tools())
        .ok_or_else(|| {
            custom_tool_error(format!(
                "accepted config snapshot has no active profile `{profile_name}`"
            ))
        })
}

fn load_custom_catalog_for_snapshot(
    config: &OracleMcpConfig,
    active_profile: Option<&str>,
    level: &SessionLevelState,
) -> Result<CustomToolCatalog, ErrorEnvelope> {
    let require_signed_tools = custom_tools_require_signatures(config, active_profile, level)?;
    load_custom_catalog_with_requirement(require_signed_tools)
}

fn load_custom_catalog_with_requirement(
    require_signed_tools: bool,
) -> Result<CustomToolCatalog, ErrorEnvelope> {
    let dir = custom_tools_dir();
    let key = std::env::var(CUSTOM_TOOLS_HMAC_KEY_ENV).ok();
    load_custom_catalog_from_sources(dir.as_deref(), key.as_deref(), require_signed_tools)
}

fn load_custom_catalog_from_sources(
    dir: Option<&Path>,
    key: Option<&str>,
    require_signed_tools: bool,
) -> Result<CustomToolCatalog, ErrorEnvelope> {
    let Some(dir) = dir else {
        return Ok(CustomToolCatalog::default());
    };
    let defs = read_custom_tool_defs(dir)?;
    if defs.is_empty() {
        return Ok(CustomToolCatalog::default());
    }
    validate_custom_tool_names(&defs)?;

    let key = key
        .map(|key| {
            HmacSha256Key::new(key.as_bytes().to_vec()).map_err(|error| {
                custom_tool_error(format!("{CUSTOM_TOOLS_HMAC_KEY_ENV} is invalid: {error}"))
            })
        })
        .transpose()?;

    let classifier = Classifier::new(ClassifierConfig::new());
    let signed_defs_present = defs.iter().any(|def| def.signature.is_some());
    let loaded = if require_signed_tools {
        let key = key.as_ref().ok_or_else(|| {
            custom_tool_error(format!(
                "{CUSTOM_TOOLS_HMAC_KEY_ENV} is required when this profile requires signed custom tools"
            ))
        })?;
        load_tools_for_profile(
            &defs,
            &classifier,
            OperatingLevel::ReadOnly,
            key,
            true,
        )
    } else if let Some(key) = key.as_ref() {
        load_tools_for_profile(
            &defs,
            &classifier,
            OperatingLevel::ReadOnly,
            key,
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

/// Where the CI-lane background poller and the independent heartbeat notifier
/// (`scripts/ci_heartbeat.sh`) durably write their compatible snapshots for
/// `/operator/v1/ci-lanes` (bead oraclemcp-eng-program-bp8ia.6.8). Resolution
/// mirrors the script's own `OUT_PATH` default exactly: `CI_HEARTBEAT_OUTPUT`
/// when set, else `$XDG_STATE_HOME/oraclemcp/ci-heartbeat.json`. `None` (no
/// resolvable state home) leaves the tile on its honest "unavailable" posture.
fn ci_heartbeat_snapshot_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("CI_HEARTBEAT_OUTPUT").filter(|path| !path.is_empty()) {
        return Some(PathBuf::from(path));
    }
    std::env::var_os("XDG_STATE_HOME")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|path| !path.is_empty())
                .map(|home| PathBuf::from(home).join(".local/state"))
        })
        .map(|state_home| state_home.join("oraclemcp/ci-heartbeat.json"))
}

/// Fill the heartbeat path only when the resolved transport has no explicit
/// source, then enable the production poller only when a durable path exists.
/// Keeping this as a small seam makes the precedence and enablement contracts
/// testable without mutating process-wide environment variables.
fn apply_ci_lane_snapshot_default(
    transport: &mut HttpTransportConfig,
    default_path: impl FnOnce() -> Option<PathBuf>,
) {
    if transport.ci_lane_snapshot_path.is_none() {
        transport.ci_lane_snapshot_path = default_path();
    }
    transport.ci_lane_polling_enabled = transport.ci_lane_snapshot_path.is_some();
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

/// Resolve one active audit signer plus all configured historical verification
/// keys. The legacy environment key is only the active-key fallback.
fn resolve_audit_keyring(
    audit: &AuditConfig,
    protected: bool,
    secret_resolver: &dyn SecretResolver,
) -> Result<Option<AuditKeyring>, (&'static str, String)> {
    let legacy_env_key = std::env::var(AUDIT_KEY_ENV).ok();
    resolve_audit_keyring_from_sources(
        audit,
        None,
        protected,
        secret_resolver,
        legacy_env_key.as_deref(),
    )
    .map_err(|message| ("ORACLEMCP_AUDIT_KEY_INVALID", message))
}

fn resolve_audit_keyring_from_sources(
    audit: &AuditConfig,
    active_key_id_override: Option<&str>,
    protected: bool,
    secret_resolver: &dyn SecretResolver,
    legacy_env_key: Option<&str>,
) -> Result<Option<AuditKeyring>, String> {
    let active_key_id = if audit.key_ref.is_some() {
        audit.key_id_or_default()
    } else {
        active_key_id_override.unwrap_or_else(|| audit.key_id_or_default())
    };
    let active = if let Some(key_ref) = audit.key_ref.as_deref() {
        let secret = resolve_secret_with(key_ref, protected, secret_resolver).map_err(|error| {
            format!(
                "failed to resolve active [audit].key_ref: {}",
                secret_error_summary(&error)
            )
        })?;
        Some(
            SigningKey::new(active_key_id, secret.expose().as_bytes().to_vec())
                .map_err(|error| format!("resolved active audit key is invalid: {error}"))?,
        )
    } else {
        legacy_env_key
            .map(|raw| {
                SigningKey::new(active_key_id, raw.as_bytes().to_vec())
                    .map_err(|error| format!("{AUDIT_KEY_ENV} is invalid: {error}"))
            })
            .transpose()?
    };
    let Some(active) = active else {
        if audit.verification_keys.is_empty() {
            return Ok(None);
        }
        return Err(format!(
            "historical audit verification keys are configured without an active signing key; \
             set [audit].key_ref or {AUDIT_KEY_ENV}"
        ));
    };

    let mut historical = Vec::with_capacity(audit.verification_keys.len());
    for configured in &audit.verification_keys {
        let secret = resolve_secret_with(&configured.key_ref, protected, secret_resolver).map_err(
            |error| {
                format!(
                    "failed to resolve historical audit key_id {:?}: {}",
                    configured.key_id,
                    secret_error_summary(&error)
                )
            },
        )?;
        historical.push(
            SigningKey::new(&configured.key_id, secret.expose().as_bytes().to_vec()).map_err(
                |error| {
                    format!(
                        "resolved historical audit key_id {:?} is invalid: {error}",
                        configured.key_id
                    )
                },
            )?,
        );
    }
    AuditKeyring::new(active, historical)
        .map(Some)
        .map_err(|error| format!("invalid active+historical audit keyring: {error}"))
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
/// Create the audit log's parent directory with private, symlink-safe
/// semantics (bead oraclemcp-qa100 .15): reject a symlink/non-directory at the
/// path, create any new directories `0700` on Unix, and harden an existing
/// directory's mode down to `0700`. Unlike a plain `create_dir_all`, this fails
/// closed on an unsafe filesystem object and never leaves the audit directory
/// group/world-accessible under a permissive umask or a custom layout.
fn create_private_audit_dir(path: &Path) -> std::io::Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "{} is a symlink or non-directory; audit logs require a private directory",
                    path.display()
                ),
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = metadata.permissions().mode() & 0o777;
            if mode != 0o700 {
                let mut permissions = metadata.permissions();
                permissions.set_mode(0o700);
                fs::set_permissions(path, permissions)?;
            }
        }
        return Ok(());
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path)
}

fn build_auditor(
    audit: &AuditConfig,
    level: &SessionLevelState,
    reachable_ceiling: OperatingLevel,
    secret_resolver: &dyn SecretResolver,
) -> Result<Option<Arc<Auditor>>, (&'static str, String)> {
    let write_reachable = reachable_ceiling > OperatingLevel::ReadOnly;
    let keyring = resolve_audit_keyring(audit, level.is_protected(), secret_resolver)?;

    let Some(keyring) = keyring else {
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
    if let Some(worm_path) = audit
        .shipping
        .as_ref()
        .and_then(|shipping| shipping.worm_path.as_deref())
    {
        let primary = normalized_destination_path(&path).map_err(|error| {
            (
                "ORACLEMCP_AUDIT_SHIPPING_INVALID",
                format!("cannot validate primary audit destination identity: {error}"),
            )
        })?;
        let mirror = normalized_destination_path(worm_path).map_err(|error| {
            (
                "ORACLEMCP_AUDIT_SHIPPING_INVALID",
                format!("cannot validate WORM destination identity: {error}"),
            )
        })?;
        if primary == mirror {
            return Err((
                "ORACLEMCP_AUDIT_SHIPPING_INVALID",
                "WORM mirror must be a filesystem object distinct from the primary audit log"
                    .to_owned(),
            ));
        }
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        create_private_audit_dir(parent).map_err(|e| {
            (
                "ORACLEMCP_AUDIT_PATH_INVALID",
                format!(
                    "failed to create private audit log directory {}: {e}",
                    parent.display()
                ),
            )
        })?;
    }
    let sink = FileAuditSink::open(&path).map_err(|e| match e {
        // A concurrent oraclemcp instance already holds the writer lock on this
        // log (bead oraclemcp-mbu1). Fail closed at startup with a distinct,
        // actionable code rather than letting both instances fork the chain.
        AuditError::Locked { .. } => (
            "ORACLEMCP_AUDIT_LOG_LOCKED",
            format!("refusing to start: {e}"),
        ),
        other => (
            "ORACLEMCP_AUDIT_PATH_INVALID",
            format!("failed to open audit log {}: {other}", path.display()),
        ),
    })?;
    tracing::info!(
        path = %path.display(),
        key_id = %keyring.active().key_id(),
        historical_keys = keyring.verification_keys().len().saturating_sub(1),
        "audit log armed"
    );

    // D2: optional WORM/SIEM shipping. Off by default — only when
    // `[audit.shipping]` configures a destination do we wrap the durable local
    // sink in the fail-safe ShippingAuditSink decorator. A forward failure never
    // loses the local record (the decorator logs + counts it).
    let local = match audit.shipping.as_ref() {
        Some(shipping) => {
            build_shipping_sink(sink, shipping, &path, level.is_protected(), secret_resolver)?
        }
        None => Box::new(sink) as Box<dyn AuditSink>,
    };
    // Head anchor sidecar (bead oraclemcp-xb51): `<audit path>.anchor` tracks
    // the durable chain head so `audit verify` detects tail truncation. Record
    // fsync always precedes the anchor update (never anchor-ahead).
    let anchor_path = oraclemcp_audit::anchor_path_for(&path);
    // Chain resume (bead oraclemcp-ow3v): a restart must continue the SAME
    // hash chain, not re-issue seq=1/genesis after the previous run's records
    // (which `audit verify` would report BROKEN at the run boundary). Seed the
    // chain state from the log's last well-formed record; fail closed if that
    // tail is malformed or contradicts the head anchor.
    let auditor = Auditor::new_with_keyring(local, keyring)
        .with_head_anchor(anchor_path)
        .resume_from(&path)
        .map_err(|e| {
            (
                "ORACLEMCP_AUDIT_CHAIN_RESUME_REFUSED",
                format!(
                    "refusing to start: the existing audit log at {} cannot seed a continuing \
                     signed hash chain: {e}",
                    path.display()
                ),
            )
        })?;
    Ok(Some(Arc::new(auditor)))
}

/// Normalize a destination without requiring the final file to exist. Existing
/// paths are canonicalized (resolving symlinks); nonexistent paths are made
/// absolute and lexically collapse `.`/`..`. The open-handle identity check in
/// `WormFileForwarder` remains authoritative for hard links and races.
fn normalized_destination_path(path: &Path) -> std::io::Result<PathBuf> {
    match fs::canonicalize(path) {
        Ok(path) => return Ok(path),
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
        Err(_) => {}
    }

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => normalized.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::Normal(part) => normalized.push(part),
        }
    }
    Ok(normalized)
}

fn build_service_owner(required: bool) -> Result<Option<ServiceOwner>, (&'static str, String)> {
    if !required {
        return Ok(None);
    }
    let store = FileStore::open_default().map_err(|e| {
        (
            "ORACLEMCP_SERVICE_STATE_UNAVAILABLE",
            format!("failed to open service state root: {e}"),
        )
    })?;
    let owner = store.acquire_service_owner("serve").map_err(|e| {
        (
            "ORACLEMCP_SERVICE_STATE_UNAVAILABLE",
            format!("failed to acquire exclusive service state ownership: {e}"),
        )
    })?;
    Ok(Some(owner))
}

#[cfg(test)]
fn build_service_owner_at(
    root: &Path,
    required: bool,
) -> Result<Option<ServiceOwner>, (&'static str, String)> {
    if !required {
        return Ok(None);
    }
    let store = FileStore::open(root).map_err(|e| {
        (
            "ORACLEMCP_SERVICE_STATE_UNAVAILABLE",
            format!("failed to open service state root: {e}"),
        )
    })?;
    let owner = store.acquire_service_owner("serve-test").map_err(|e| {
        (
            "ORACLEMCP_SERVICE_STATE_UNAVAILABLE",
            format!("failed to acquire exclusive service state ownership: {e}"),
        )
    })?;
    Ok(Some(owner))
}

fn build_write_intent_log(
    reachable_ceiling: OperatingLevel,
    owner: Option<&ServiceOwner>,
) -> Result<Option<Arc<WriteIntentLog>>, (&'static str, String)> {
    if reachable_ceiling <= OperatingLevel::ReadOnly {
        return Ok(None);
    }
    let owner = owner.ok_or_else(|| {
        (
            "ORACLEMCP_WRITE_INTENT_LOG_INVALID",
            "writable service state owner was not initialized".to_owned(),
        )
    })?;
    let log = WriteIntentLog::open_with_owner(owner.clone()).map_err(|e| {
        (
            "ORACLEMCP_WRITE_INTENT_LOG_INVALID",
            format!("failed to open durable write-intent log: {e}"),
        )
    })?;
    finish_write_intent_log_build(log)
}

fn has_cumulative_query_cost_budget(config: &OracleMcpConfig) -> bool {
    config
        .profiles
        .iter()
        .any(|profile| profile.cumulative_query_cost_budget.is_some())
}

fn build_query_cost_budget_store(
    enabled: bool,
    owner: Option<&ServiceOwner>,
) -> Result<Option<Arc<QueryCostBudgetStore>>, (&'static str, String)> {
    if !enabled {
        return Ok(None);
    }
    let owner = owner.ok_or_else(|| {
        (
            "ORACLEMCP_QUERY_COST_BUDGET_UNAVAILABLE",
            "durable service state owner was not initialized".to_owned(),
        )
    })?;
    let store = QueryCostBudgetStore::open_with_owner(owner.clone()).map_err(|_| {
        (
            "ORACLEMCP_QUERY_COST_BUDGET_UNAVAILABLE",
            "failed to open durable cumulative query-cost budget state".to_owned(),
        )
    })?;
    Ok(Some(Arc::new(store)))
}

#[cfg(test)]
fn build_write_intent_log_at(
    root: &Path,
    reachable_ceiling: OperatingLevel,
) -> Result<Option<Arc<WriteIntentLog>>, (&'static str, String)> {
    if reachable_ceiling <= OperatingLevel::ReadOnly {
        return Ok(None);
    }
    let store = FileStore::open(root).map_err(|e| {
        (
            "ORACLEMCP_WRITE_INTENT_LOG_INVALID",
            format!("failed to open durable write-intent state: {e}"),
        )
    })?;
    let owner = store.acquire_service_owner("serve-test").map_err(|e| {
        (
            "ORACLEMCP_WRITE_INTENT_LOG_INVALID",
            format!("failed to own durable write-intent state: {e}"),
        )
    })?;
    let log = WriteIntentLog::open_with_owner(owner).map_err(|e| {
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
/// `[audit.shipping]`. Builds a WORM file forwarder and/or a validated SIEM
/// HTTPS/loopback forwarder (asupersync HTTP client, no tokio/reqwest), composing both into a single
/// forwarder when both are configured. Shipping never weakens the local chain.
fn build_shipping_sink(
    local: FileAuditSink,
    shipping: &oraclemcp_config::AuditShippingConfig,
    audit_path: &Path,
    protected: bool,
    secret_resolver: &dyn SecretResolver,
) -> Result<Box<dyn AuditSink>, (&'static str, String)> {
    let mut forwarders: Vec<Box<dyn ShippingForwarder>> = Vec::new();
    let mut spool_name = audit_path.as_os_str().to_os_string();
    spool_name.push(".shipping-spool");
    let spool_root = PathBuf::from(spool_name);

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
        let worm =
            WormFileForwarder::open_distinct(worm_path, &local).map_err(|error| match error {
                oraclemcp_audit::ShippingError::AliasedPrimaryAuditLog => (
                    "ORACLEMCP_AUDIT_SHIPPING_INVALID",
                    "WORM mirror must be a filesystem object distinct from the primary audit log"
                        .to_owned(),
                ),
                other => (
                    "ORACLEMCP_AUDIT_SHIPPING_INVALID",
                    format!(
                        "failed to open WORM mirror {}: {other}",
                        worm_path.display()
                    ),
                ),
            })?;
        let normalized_worm = normalized_destination_path(worm_path).map_err(|error| {
            (
                "ORACLEMCP_AUDIT_SHIPPING_INVALID",
                format!("cannot normalize WORM destination for durable spooling: {error}"),
            )
        })?;
        let destination_id =
            oraclemcp_audit::sha256_hex(normalized_worm.to_string_lossy().as_bytes());
        let destination_slug: String = destination_id
            .strip_prefix("sha256:")
            .unwrap_or(&destination_id)
            .chars()
            .take(16)
            .collect();
        let spool_dir = spool_root.join(format!("worm-{destination_slug}"));
        let worm = oraclemcp_audit::DurableShippingForwarder::open(
            oraclemcp_audit::DurableSpoolConfig::new(&spool_dir, destination_id),
            Box::new(worm),
        )
        .map_err(|error| {
            (
                "ORACLEMCP_AUDIT_SHIPPING_INVALID",
                format!(
                    "failed to open durable WORM spool {}: {error}",
                    spool_dir.display()
                ),
            )
        })?;
        tracing::info!(
            worm_path = %worm_path.display(),
            spool_dir = %spool_dir.display(),
            "durable asynchronous audit WORM mirror armed"
        );
        forwarders.push(Box::new(worm));
    }

    if let Some(endpoint) = shipping.siem_endpoint.as_ref() {
        let format = SiemFormat::parse(shipping.siem_format_or_default()).ok_or((
            "ORACLEMCP_AUDIT_SHIPPING_INVALID",
            format!(
                "unknown audit.shipping.siem_format {:?} (expected json|cef|syslog)",
                shipping.siem_format_or_default()
            ),
        ))?;
        let mut forwarder = SiemHttpForwarder::new(endpoint.clone(), format);
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
            forwarder = forwarder
                .with_header(
                    shipping.siem_auth_header_name_or_default().to_owned(),
                    secret.expose().to_owned(),
                )
                .map_err(|error| {
                    (
                        "ORACLEMCP_AUDIT_SHIPPING_INVALID",
                        format!("refusing SIEM authentication header: {error}"),
                    )
                })?;
        }
        let destination_id =
            oraclemcp_audit::sha256_hex(format!("{}|{format:?}", endpoint.as_str()).as_bytes());
        let destination_slug: String = destination_id
            .strip_prefix("sha256:")
            .unwrap_or(&destination_id)
            .chars()
            .take(16)
            .collect();
        let spool_dir = spool_root.join(format!("siem-{destination_slug}"));
        let forwarder = oraclemcp_audit::DurableShippingForwarder::open(
            oraclemcp_audit::DurableSpoolConfig::new(&spool_dir, destination_id),
            Box::new(forwarder),
        )
        .map_err(|error| {
            (
                "ORACLEMCP_AUDIT_SHIPPING_INVALID",
                format!(
                    "failed to open durable SIEM spool {}: {error}",
                    spool_dir.display()
                ),
            )
        })?;
        tracing::info!(
            siem_origin = %endpoint.diagnostic_origin(),
            format = ?format,
            spool_dir = %spool_dir.display(),
            "durable asynchronous audit SIEM forwarder armed"
        );
        forwarders.push(Box::new(forwarder));
    }

    let forwarder: Box<dyn ShippingForwarder> = match forwarders.len() {
        0 => return Ok(Box::new(local)), // validate() guarantees ≥1, but stay total.
        1 => forwarders.into_iter().next().expect("len==1"),
        _ => Box::new(TeeForwarder::new(forwarders)),
    };
    Ok(Box::new(ShippingAuditSink::new(Box::new(local), forwarder)))
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
    max_query_cost: Option<u64>,
    cumulative_query_cost_budget: Option<CumulativeQueryCostBudgetConfig>,
    query_cost_budgets: Option<Arc<QueryCostBudgetStore>>,
    result_masking: Option<ResultMaskingPolicy>,
    sql_policy: Option<SqlPolicyConfig>,
    secret_resolver: Arc<dyn SecretResolver>,
    custom_catalog: CustomToolCatalog,
    exposure: McpExposurePolicy,
    profile_drain: ProfileDrainState,
    auditor: Option<Arc<Auditor>>,
    write_intents: Option<Arc<WriteIntentLog>>,
    exports: Arc<ExportRegistry>,
    unsigned_refusal_log: bool,
}

fn whole_request_timeout(call_timeout_seconds: Option<u64>) -> std::time::Duration {
    match call_timeout_seconds {
        Some(0) | None => DEFAULT_REQUEST_TIMEOUT,
        Some(seconds) => std::time::Duration::from_secs(seconds),
    }
}

fn apply_selected_profile_to_wiring(
    wiring: &mut DispatcherWiring,
    selected: SelectedRuntimeProfile,
) {
    wiring.active_profile = Some(selected.name);
    wiring.level = selected.level;
    wiring.request_timeout = selected.request_timeout;
    wiring.max_query_cost = selected.max_query_cost;
    wiring.cumulative_query_cost_budget = selected.cumulative_query_cost_budget;
    wiring.result_masking = selected.result_masking;
    wiring.sql_policy = selected.sql_policy;
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
        StatelessReadStrategy::new(stateless_conn),
        wiring.custom_catalog.clone(),
        Some(Arc::new(load_custom_catalog_for_generation)),
    )
    .with_request_timeout(wiring.request_timeout)
    .with_max_query_cost(wiring.max_query_cost)
    .with_cumulative_query_cost_budget(wiring.cumulative_query_cost_budget.clone())
    .with_result_masking_policy(wiring.result_masking.clone())
    // SQL policy is part of the profile's startup snapshot, just like the
    // operating level and response masking. Without this installation, only a
    // later profile switch would govern the lane, which would fail open for the
    // initially served profile.
    .with_sql_policy(wiring.sql_policy.clone())
    .with_mcp_exposure(wiring.exposure.clone())
    .with_profile_drain_state(wiring.profile_drain.clone())
    .with_exports(Arc::clone(&wiring.exports));
    if let Some(query_cost_budgets) = &wiring.query_cost_budgets {
        dispatcher = dispatcher.with_query_cost_budget_store(Arc::clone(query_cost_budgets));
    }
    if let Some(auditor) = &wiring.auditor {
        dispatcher = dispatcher.with_auditor(Arc::clone(auditor));
    }
    if let Some(write_intents) = &wiring.write_intents {
        dispatcher = dispatcher.with_write_intent_log(Arc::clone(write_intents));
    }
    if !wiring.unsigned_refusal_log {
        dispatcher = dispatcher.without_refusal_corpus();
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
    accepted_config: Option<&OracleMcpConfig>,
    secret_resolver: &dyn SecretResolver,
) -> Result<OpenedLaneRuntime, DbError> {
    match active_profile {
        Some(profile) => {
            let config = accepted_config.ok_or_else(|| {
                DbError::UnsupportedAuth(
                    "profile generation has no accepted config snapshot".to_owned(),
                )
            })?;
            let Some(resolved) =
                resolve_profile_options_from_config_with(config, Some(profile), secret_resolver)?
            else {
                return Err(DbError::UnsupportedAuth(format!(
                    "connection profile `{profile}` not found"
                )));
            };
            let selected_profile = SelectedRuntimeProfile {
                name: resolved.name.clone(),
                level: resolved.level.clone(),
                request_timeout: resolved.opts.call_timeout,
                max_query_cost: resolved.max_query_cost,
                cumulative_query_cost_budget: resolved.cumulative_query_cost_budget.clone(),
                result_masking: match config.profile(&resolved.name) {
                    Some(profile) => {
                        result_masking_policy_from_profile(profile).map_err(|error| {
                            DbError::UnsupportedAuth(format!(
                                "failed to load result masking policy for profile `{}`: {error}",
                                resolved.name
                            ))
                        })?
                    }
                    None => None,
                },
                sql_policy: config
                    .profile(&resolved.name)
                    .and_then(|profile| profile.sql_policy.clone()),
                require_signed_tools: resolved.require_signed_tools,
            };
            match try_open_runtime_connections(cx, resolved).await {
                Ok(connections) => Ok(OpenedLaneRuntime {
                    connections,
                    selected_profile: Some(selected_profile),
                }),
                Err(e) => {
                    tracing::warn!(error = %e, "no live connection for lane; live tools will return a structured error envelope");
                    Ok(OpenedLaneRuntime {
                        connections: RuntimeConnections {
                            session: Box::new(stub::StubConnection::new(e)),
                            stateless: None,
                        },
                        selected_profile: Some(selected_profile),
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
            Ok(OpenedLaneRuntime {
                connections: RuntimeConnections {
                    session,
                    stateless: None,
                },
                selected_profile: None,
            })
        }
    }
}

struct OpenedLaneRuntime {
    connections: RuntimeConnections,
    selected_profile: Option<SelectedRuntimeProfile>,
}

struct MetricsDispatch {
    inner: Arc<dyn ToolDispatch>,
    metrics: Arc<Metrics>,
}

impl MetricsDispatch {
    fn new(inner: Arc<dyn ToolDispatch>, metrics: Arc<Metrics>) -> Self {
        Self { inner, metrics }
    }

    fn labels(context: oraclemcp_core::DispatchContext<'_>) -> (String, String) {
        let lane_id = context.lane_id().unwrap_or("process").to_owned();
        let subject_id_hash = context
            .principal_key()
            .map(operator_subject_id_hash)
            .unwrap_or_else(|| operator_subject_id_hash("process"));
        (lane_id, subject_id_hash)
    }

    fn record_outcome(
        &self,
        started: Instant,
        lane_id: &str,
        subject_id_hash: &str,
        name: &str,
        result: &DispatchOutcome,
    ) {
        let status = metrics_status(result);
        self.metrics
            .record_lane_request(lane_id, subject_id_hash, name, status);
        self.metrics.record_lane_request_duration_ms(
            lane_id,
            subject_id_hash,
            name,
            u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        );
        if let Some((reason_class, operating_level)) = blocked_labels(result) {
            self.metrics.record_lane_blocked(
                lane_id,
                subject_id_hash,
                reason_class,
                operating_level,
            );
        }
    }
}

impl ToolDispatch for MetricsDispatch {
    fn request_timeout_ceiling(&self) -> Result<std::time::Duration, ErrorEnvelope> {
        self.inner.request_timeout_ceiling()
    }

    fn dispatch<'a>(
        &'a self,
        cx: &'a Cx,
        context: oraclemcp_core::DispatchContext<'a>,
        name: &'a str,
        args: serde_json::Value,
    ) -> DispatchFuture<'a> {
        Box::pin(async move {
            let started = Instant::now();
            let (lane_id, subject_id_hash) = Self::labels(context);
            let result = self.inner.dispatch(cx, context, name, args).await;
            self.record_outcome(started, &lane_id, &subject_id_hash, name, &result);
            result
        })
    }

    fn dispatch_stream<'a>(
        &'a self,
        cx: &'a Cx,
        context: oraclemcp_core::DispatchContext<'a>,
        name: &'a str,
        args: serde_json::Value,
        frames: ToolStreamSender,
    ) -> DispatchFuture<'a> {
        Box::pin(async move {
            let started = Instant::now();
            let (lane_id, subject_id_hash) = Self::labels(context);
            let result = self
                .inner
                .dispatch_stream(cx, context, name, args, frames)
                .await;
            self.record_outcome(started, &lane_id, &subject_id_hash, name, &result);
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

/// K4: the bounded `(reason_class, operating_level)` labels for a blocked
/// dispatch, or `None` when the outcome was not a pre-DB refusal. `reason_class`
/// buckets the blocking `ErrorClass`; `operating_level` is the required level
/// from the guard's structured reason (K8) when present, else `n/a`. Both stay
/// within fixed sets so the metric's label cardinality is bounded.
fn blocked_labels(outcome: &DispatchOutcome) -> Option<(&'static str, &'static str)> {
    let asupersync::Outcome::Err(envelope) = outcome else {
        return None;
    };
    let reason_class = match envelope.error_class {
        ErrorClass::Busy | ErrorClass::AtCapacity => "capacity",
        ErrorClass::PolicyDenied => "policy",
        ErrorClass::ForbiddenStatement => "classifier",
        ErrorClass::OperatingLevelTooLow => "operating_level",
        _ => return None,
    };
    let operating_level = envelope
        .structured_reason
        .as_ref()
        .and_then(|reason| reason.required_level.as_deref())
        .map_or("n/a", bounded_operating_level);
    Some((reason_class, operating_level))
}

/// Clamp a required-level string to the bounded label set (defends the metric's
/// cardinality even if an unexpected value ever reaches here).
fn bounded_operating_level(level: &str) -> &'static str {
    match level {
        "READ_ONLY" => "READ_ONLY",
        "READ_WRITE" => "READ_WRITE",
        "DDL" => "DDL",
        "ADMIN" => "ADMIN",
        _ => "n/a",
    }
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

fn stateful_lane_factory_builder(
    wiring: DispatcherWiring,
    metrics: Option<Arc<Metrics>>,
) -> Arc<LaneDispatchFactoryBuilder> {
    Arc::new(move |lane_context: &LaneContext| {
        let profile_generation = match wiring.active_profile.as_deref() {
            Some(active_profile) => {
                match wiring.profile_drain.admit_mcp_profile(active_profile, true) {
                    ProfileGenerationAdmission::Ready(lease) => Some(lease),
                    ProfileGenerationAdmission::NotExposed => {
                        return Err(profile_not_available(active_profile));
                    }
                    ProfileGenerationAdmission::Draining => {
                        return Err(profile_draining_error(active_profile));
                    }
                }
            }
            None => None,
        };
        let request_timeout = profile_generation
            .as_ref()
            .and_then(|lease| lease.config()?.profile(lease.profile()))
            .map(|profile| whole_request_timeout(profile.call_timeout_seconds))
            .unwrap_or_else(|| wiring.request_timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT));
        let prepared_generation = Arc::new(Mutex::new(Some(profile_generation)));
        let factory_wiring = wiring.clone();
        let factory_metrics = metrics.clone();
        let principal_key = lane_context.principal_key().to_owned();
        let factory: Arc<LaneDispatchFactory> = Arc::new(move |cx, _lane_context| {
            let prepared_generation = Arc::clone(&prepared_generation);
            let mut wiring = factory_wiring.clone();
            let metrics = factory_metrics.clone();
            let principal_key = principal_key.clone();
            Box::pin(async move {
                // Do not consume the one-shot generation reservation merely by
                // constructing this future. A caller cancelled before its
                // first poll must leave the prepared lane reusable.
                let profile_generation = prepared_generation
                    .lock()
                    .map_err(|error| {
                        ErrorEnvelope::new(
                            ErrorClass::Internal,
                            format!("prepared profile-generation lock failed: {error}"),
                        )
                    })?
                    .take()
                    .ok_or_else(|| {
                        ErrorEnvelope::new(
                            ErrorClass::RuntimeStateRequired,
                            "prepared lane dispatcher factory was already consumed",
                        )
                    })?;
                let opened = open_lane_runtime_connections(
                    cx,
                    wiring.active_profile.as_deref(),
                    profile_generation.as_ref().and_then(|lease| lease.config()),
                    wiring.secret_resolver.as_ref(),
                )
                .await
                .map_err(DbError::into_envelope)?;
                if profile_generation
                    .as_ref()
                    .is_some_and(oraclemcp::dispatch::ProfileGenerationLease::is_draining)
                {
                    return Err(profile_draining_error(
                        wiring.active_profile.as_deref().unwrap_or(""),
                    ));
                }
                if let Some(selected) = opened.selected_profile {
                    wiring.custom_catalog =
                        load_custom_catalog_with_requirement(selected.require_signed_tools)?;
                    apply_selected_profile_to_wiring(&mut wiring, selected);
                }
                let dispatcher = build_oracle_dispatcher(
                    opened.connections.session,
                    opened.connections.stateless,
                    &wiring,
                );
                let dispatcher = match profile_generation {
                    Some(lease) => dispatcher
                        .with_profile_generation_lease(wiring.profile_drain.clone(), lease),
                    None => Ok(dispatcher),
                }?
                .with_default_audit_subject(audit_subject_from_principal_key(&principal_key));
                let dispatcher: Arc<dyn ToolDispatch> = Arc::new(dispatcher);
                Ok(maybe_wrap_metrics_dispatch(dispatcher, metrics.as_ref()))
            })
        });
        Ok(PreparedLaneDispatch::new(factory, request_timeout))
    })
}

type ReadWorkerFactoryBuilder =
    dyn Fn(Option<String>) -> Result<PreparedLaneDispatch, ErrorEnvelope> + Send + Sync + 'static;

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

    fn read_lane_for(
        &self,
        cx: &Cx,
        context: DispatchContext<'_>,
    ) -> Result<LaneRuntime, ErrorEnvelope> {
        cx.checkpoint().map_err(|_| {
            ErrorEnvelope::new(
                ErrorClass::Timeout,
                "stateless read-worker resolution was cancelled before admission",
            )
        })?;
        let key = ReadWorkerKey {
            principal_key: context
                .principal_key()
                .unwrap_or("anonymous-http")
                .to_owned(),
            active_profile: self.active_profile(),
        };
        let (existing, stale_lanes) = {
            let mut lanes = self
                .read_lanes
                .lock()
                .expect("stateless read lane registry mutex not poisoned");
            let mut stale_lanes = Vec::new();
            let existing = if let Some(bucket) = lanes.get_mut(&key) {
                let mut index = 0;
                while index < bucket.lanes.len() {
                    if bucket.lanes[index].accepts_commands() {
                        index += 1;
                    } else {
                        stale_lanes.push(bucket.lanes.swap_remove(index));
                    }
                }
                if bucket.lanes.len() >= self.width_per_key {
                    let index = bucket.next % bucket.lanes.len();
                    bucket.next = bucket.next.wrapping_add(1);
                    Some(bucket.lanes[index].clone())
                } else {
                    None
                }
            } else {
                None
            };
            (existing, stale_lanes)
        };
        // A dead read lane can still own a generation-bound lazy factory.
        // Release it outside the read-worker registry lock.
        drop(stale_lanes);
        if let Some(existing) = existing {
            return Ok(existing);
        }

        // Reserve the exact profile generation and timeout before taking the
        // read-worker registry lock. A concurrent winner may make this
        // preparation unnecessary; dropping it then releases its lease.
        let mut prepared = Some((self.read_factory)(key.active_profile.clone())?);
        if cx.checkpoint().is_err() {
            drop(prepared);
            return Err(ErrorEnvelope::new(
                ErrorClass::Timeout,
                "stateless read-worker preparation exhausted the caller budget",
            ));
        }
        let lane_number = self.next_lane_id.fetch_add(1, Ordering::SeqCst);
        let lane_id = format!("stateless-read-{lane_number}");
        let lane_context = LaneContext::new(
            lane_id.clone(),
            "stateless-read",
            key.principal_key.clone(),
            1,
        );
        let mut lanes = self
            .read_lanes
            .lock()
            .expect("stateless read lane registry mutex not poisoned");
        let bucket = lanes.entry(key).or_insert_with(|| ReadWorkerBucket {
            next: 0,
            lanes: Vec::new(),
        });
        let mut stale_lanes = Vec::new();
        let mut index = 0;
        while index < bucket.lanes.len() {
            if bucket.lanes[index].accepts_commands() {
                index += 1;
            } else {
                stale_lanes.push(bucket.lanes.swap_remove(index));
            }
        }
        if bucket.lanes.len() < self.width_per_key {
            let prepared = prepared
                .take()
                .expect("prepared read worker is consumed once");
            bucket.lanes.push(LaneRuntime::spawn_prepared_dispatch(
                lane_id,
                lane_context,
                prepared,
                oraclemcp_core::DEFAULT_LANE_MAILBOX_CAPACITY,
                None,
            ));
        }
        let index = bucket.next % bucket.lanes.len();
        bucket.next = bucket.next.wrapping_add(1);
        // SAFETY: the read-worker registry stores only `LaneRuntime` handles.
        // The caller sends to the returned lane after this mutex guard is gone,
        // mirroring the core stateful registry's copy-handle-before-send rule.
        let lane = bucket.lanes[index].clone();
        drop(lanes);
        drop(stale_lanes);
        // A concurrent winner may already have filled the bucket. Release this
        // unused generation reservation only after leaving the registry lock.
        drop(prepared);
        Ok(lane)
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

    #[cfg(test)]
    fn read_lane_count(&self) -> usize {
        self.read_lanes
            .lock()
            .expect("stateless read lane registry mutex not poisoned")
            .values()
            .map(|bucket| bucket.lanes.len())
            .sum()
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
            let context = context.with_request_started_at(Instant::now());
            if cx.checkpoint().is_err() {
                return DispatchOutcome::Cancelled(cx.cancel_reason().unwrap_or_else(|| {
                    asupersync::CancelReason::user(
                        "stateless HTTP dispatch cancelled before lane admission",
                    )
                }));
            }
            if stateless_read_worker_tool(name) {
                let lane = match self.read_lane_for(cx, context) {
                    Ok(lane) => lane,
                    Err(error) => return DispatchOutcome::Err(error),
                };
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
        let requested_profile = active_profile.ok_or_else(|| {
            ErrorEnvelope::new(
                ErrorClass::RuntimeStateRequired,
                "stateless read-worker lanes require an active connection profile",
            )
            .with_next_step("start the server with `oraclemcp serve --profile <name>`")
        })?;
        let profile_generation = match wiring
            .profile_drain
            .admit_mcp_profile(&requested_profile, true)
        {
            ProfileGenerationAdmission::Ready(lease) => lease,
            ProfileGenerationAdmission::NotExposed => {
                return Err(profile_not_available(&requested_profile));
            }
            ProfileGenerationAdmission::Draining => {
                return Err(profile_draining_error(&requested_profile));
            }
        };
        let request_timeout = profile_generation
            .config()
            .and_then(|config| config.profile(profile_generation.profile()))
            .map(|profile| whole_request_timeout(profile.call_timeout_seconds))
            .ok_or_else(|| {
                ErrorEnvelope::new(
                    ErrorClass::RuntimeStateRequired,
                    "profile generation has no accepted profile snapshot",
                )
            })?;
        let prepared_generation = Arc::new(Mutex::new(Some(profile_generation)));
        let factory_wiring = wiring.clone();
        let factory_metrics = metrics.clone();
        let factory: Arc<LaneDispatchFactory> =
            Arc::new(move |cx: &Cx, lane_context: &LaneContext| {
                let prepared_generation = Arc::clone(&prepared_generation);
                let mut wiring = factory_wiring.clone();
                let metrics = factory_metrics.clone();
                let requested_profile = requested_profile.clone();
                let principal_key = lane_context.principal_key().to_owned();
                Box::pin(async move {
                    let profile_generation = prepared_generation
                        .lock()
                        .map_err(|error| {
                            ErrorEnvelope::new(
                                ErrorClass::Internal,
                                format!("prepared profile-generation lock failed: {error}"),
                            )
                        })?
                        .take()
                        .ok_or_else(|| {
                            ErrorEnvelope::new(
                                ErrorClass::RuntimeStateRequired,
                                "prepared read-worker dispatcher factory was already consumed",
                            )
                        })?;
                    let config = profile_generation.config().ok_or_else(|| {
                        ErrorEnvelope::new(
                            ErrorClass::RuntimeStateRequired,
                            "profile generation has no accepted config snapshot",
                        )
                    })?;
                    let Some(resolved) = resolve_profile_options_from_config_with(
                        config,
                        Some(&requested_profile),
                        wiring.secret_resolver.as_ref(),
                    )
                    .map_err(DbError::into_envelope)?
                    else {
                        return Err(profile_draining_error(&requested_profile));
                    };
                    let profile = resolved.name.clone();
                    let level = resolved.level.clone();
                    let request_timeout = resolved.opts.call_timeout;
                    let require_signed_tools = resolved.require_signed_tools;
                    let conn = try_open_connection(cx, resolved.opts)
                        .await
                        .map_err(DbError::into_envelope)?;
                    if profile_generation.is_draining() {
                        return Err(profile_draining_error(&requested_profile));
                    }
                    wiring.active_profile = Some(profile);
                    wiring.level = level;
                    wiring.request_timeout = request_timeout;
                    wiring.custom_catalog =
                        load_custom_catalog_with_requirement(require_signed_tools)?;
                    let dispatcher = build_oracle_dispatcher(conn, None, &wiring)
                        .with_profile_generation_lease(
                            wiring.profile_drain.clone(),
                            profile_generation,
                        )?
                        .with_default_audit_subject(audit_subject_from_principal_key(
                            &principal_key,
                        ));
                    let dispatcher: Arc<dyn ToolDispatch> = Arc::new(dispatcher);
                    Ok(maybe_wrap_metrics_dispatch(dispatcher, metrics.as_ref()))
                })
            });
        Ok(PreparedLaneDispatch::new(factory, request_timeout))
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
    max_query_cost: Option<u64>,
    cumulative_query_cost_budget: Option<CumulativeQueryCostBudgetConfig>,
    query_cost_budgets: Option<Arc<QueryCostBudgetStore>>,
    result_masking: Option<ResultMaskingPolicy>,
    sql_policy: Option<SqlPolicyConfig>,
    metrics: Option<Arc<Metrics>>,
    profile_drain: ProfileDrainState,
    unsigned_refusal_log: bool,
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
    // Keep the server registry immutable and built-in-only. Profile-scoped
    // custom descriptors come from the dispatcher's active catalog snapshot,
    // so discovery and execution swap the same lane-local generation.
    let registry = registry::tool_registry();
    let caps = CapabilitiesReport::new(
        version,
        registry.tools.clone(),
        level.max_level(),
        FeatureTiers {
            live_db: BUILT_WITH_LIVE_DB,
            engine: cfg!(feature = "plsql-intelligence"),
            http_transport: options.transport.is_http(),
        },
    );
    // E5 connection-scope isolation: derive the immutable startup policy from
    // the same accepted snapshot used for generation admission. Missing or
    // poisoned lifecycle state fails closed; serving paths never re-read disk.
    let exposure = match options.profile_drain.accepted_config() {
        Some(cfg) => {
            // Operator-visibility notice (stderr; never the stdio MCP channel).
            eprintln!("[oraclemcp] {}", exposed_profiles_summary(&cfg));
            oraclemcp::dispatch::McpExposurePolicy::from_config(&cfg)
        }
        None => oraclemcp::dispatch::McpExposurePolicy::AllowList(HashSet::new()),
    };
    // E3/E3b: the dispatcher (which mints exports for oversized oracle_query
    // results) and the server (which serves them over resources/read) share the
    // SAME export registry.
    let exports = Arc::new(ExportRegistry::new());
    let wiring = DispatcherWiring {
        active_profile,
        level,
        request_timeout: options.request_timeout,
        max_query_cost: options.max_query_cost,
        cumulative_query_cost_budget: options.cumulative_query_cost_budget,
        query_cost_budgets: options.query_cost_budgets,
        result_masking: options.result_masking,
        sql_policy: options.sql_policy,
        secret_resolver: options.secret_resolver,
        custom_catalog: options.custom_catalog,
        exposure,
        profile_drain: options.profile_drain,
        auditor: options.auditor,
        write_intents: options.write_intents,
        exports: Arc::clone(&exports),
        unsigned_refusal_log: options.unsigned_refusal_log,
    };
    let mut session_lifecycle: Option<Arc<dyn HttpSessionLifecycle>> = None;
    let dispatcher: Arc<dyn ToolDispatch> = if options.transport.is_http() {
        if matches!(options.transport, ServerTransportMode::HttpStateful) {
            let stateful = Arc::new(
                StatefulLaneDispatch::with_dispatch_factory_builder(
                    stateful_lane_factory_builder(wiring.clone(), options.metrics.clone()),
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
        let dispatcher: Arc<dyn ToolDispatch> = Arc::new(dispatcher);
        Arc::new(LaneRuntime::spawn_default_with_panic_auditor(
            "served-stdio",
            dispatcher,
            wiring.auditor.clone(),
        ))
    };
    let server = OracleMcpServer::with_exports(version, registry, caps, dispatcher, exports);
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
    if let Some(listen) = &cli.control_listen {
        let mut control = config.control.unwrap_or_default();
        control.listen = listen.clone();
        config.control = Some(control);
    }

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
    allow_remote: bool,
    control: Option<HttpControlConfig>,
}

#[derive(Clone)]
struct HttpConfigReloadApplier {
    profile_drain: ProfileDrainState,
}

impl ConfigReloadApplier for HttpConfigReloadApplier {
    fn apply_config_reload_plan(
        &self,
        plan: &oraclemcp_config::ConfigReloadPlan,
        expected: &OracleMcpConfig,
        next: &OracleMcpConfig,
    ) -> ConfigReloadApplyReport {
        if let Err(reason) = self
            .profile_drain
            .apply_config_reload_plan(plan, expected, next)
        {
            return ConfigReloadApplyReport {
                status: "restart_required".to_owned(),
                hot_reloadable: false,
                restart_required: vec![reason.to_owned()],
                draining_profiles: Vec::new(),
                message: format!(
                    "config file was updated but the live accepted snapshot was not changed: {reason}; restart the service"
                ),
            };
        }
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
    // Fresh write target: the highest-precedence search dir, so an XDG-native
    // box (XDG_CONFIG_HOME set) gets its config created where discovery reads.
    OracleMcpConfig::config_search_dirs()
        .into_iter()
        .next()
        .map(|dir| dir.join("profiles.toml"))
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
    cfg: &OracleMcpConfig,
    cli: &HttpServeArgs,
    level: &SessionLevelState,
    secret_resolver: &dyn SecretResolver,
) -> Result<ResolvedHttpTransportConfig, (&'static str, String)> {
    let http = apply_http_cli_overrides(cfg.http.clone(), cli);
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
            let verifier =
                Hs256Verifier::new(secret.expose().as_bytes().to_vec()).map_err(|error| {
                    (
                        "ORACLEMCP_HTTP_OAUTH_SECRET_INVALID",
                        format!("resolved http.oauth.hs256_secret_ref is invalid: {error}"),
                    )
                })?;
            let enforcement = OAuthEnforcement {
                config: resource_config,
                verifier: Arc::new(verifier),
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
        effective_scheme: if http.trusted_https_termination {
            EffectiveHttpScheme::Https
        } else {
            EffectiveHttpScheme::Http
        },
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
        // Bound to the actual native loopback listener after bind, including a
        // concrete port when the caller requested port zero.
        dashboard_auth: None,
        // Observability is wired in run_serve (HealthState/Metrics/probe).
        observability: ObservabilityState::default(),
        ..Default::default()
    };

    Ok(ResolvedHttpTransportConfig {
        transport,
        tls,
        mtls_required,
        allow_remote: http.allow_remote,
        control: http.control,
    })
}

fn http_allow_remote_from_env() -> bool {
    std::env::var("ORACLEMCP_HTTP_ALLOW_REMOTE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn effective_http_allow_remote(config_allow_remote: bool) -> bool {
    config_allow_remote || http_allow_remote_from_env()
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
    // Load one validated startup snapshot. Every profile connection, level,
    // exposure decision, custom-tool policy, and audit prerequisite below is
    // derived from this exact value; runtime paths never re-read the file.
    let full_config = match OracleMcpConfig::load(None) {
        Ok(cfg) => cfg,
        Err(e) => {
            emit_status_error(
                robot_json,
                "ORACLEMCP_CONFIG_INVALID",
                &format!("failed to load server config: {e}"),
            );
            return ExitCode::from(2);
        }
    };
    // Select only non-secret profile metadata at startup. DB credentials remain
    // as `credential_ref` / `wallet_password_ref` until the actual connection
    // opener runs (stdio/stateless startup connect, readiness probe connect, or
    // stateful per-lane connect).
    let (
        connection_plan,
        active_profile,
        level,
        request_timeout,
        max_query_cost,
        cumulative_query_cost_budget,
        result_masking,
        sql_policy,
    ) = match select_runtime_profile_from_config(&full_config, profile.as_deref()) {
        Ok(Some(selected)) => {
            let active_profile = Some(selected.name.clone());
            (
                RuntimeConnectionPlan::Profile(selected.name),
                active_profile,
                selected.level,
                selected.request_timeout,
                selected.max_query_cost,
                selected.cumulative_query_cost_budget,
                selected.result_masking,
                selected.sql_policy,
            )
        }
        Ok(None) => (
            RuntimeConnectionPlan::Default,
            None,
            default_read_only_level(),
            OracleConnectOptions::default().call_timeout,
            None,
            None,
            None,
            None,
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
                None,
                None,
                None,
                None,
            )
        }
    };

    let custom_catalog =
        match load_custom_catalog_for_snapshot(&full_config, active_profile.as_deref(), &level) {
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
    // The redacted refusal trail is the unsigned floor only when no signed
    // chain is active. An operator may disable that floor explicitly.
    let unsigned_refusal_log =
        unsigned_refusal_trail_enabled(auditor.is_some(), full_config.audit.unsigned_refusal_log);
    let query_cost_budget_enabled = has_cumulative_query_cost_budget(&full_config);
    let service_owner = match build_service_owner(
        listen.is_some()
            || reachable_ceiling > OperatingLevel::ReadOnly
            || query_cost_budget_enabled,
    ) {
        Ok(owner) => owner,
        Err((code, message)) => {
            emit_status_error(robot_json, code, &message);
            return ExitCode::from(2);
        }
    };
    let write_intents = match build_write_intent_log(reachable_ceiling, service_owner.as_ref()) {
        Ok(write_intents) => write_intents,
        Err((code, message)) => {
            emit_status_error(robot_json, code, &message);
            return ExitCode::from(2);
        }
    };
    let query_cost_budgets =
        match build_query_cost_budget_store(query_cost_budget_enabled, service_owner.as_ref()) {
            Ok(store) => store,
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
            let connections = open_runtime_connection_plan(
                connection_plan,
                &full_config,
                true,
                secret_resolver.as_ref(),
            );
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
                    max_query_cost,
                    cumulative_query_cost_budget: cumulative_query_cost_budget.clone(),
                    query_cost_budgets: query_cost_budgets.clone(),
                    result_masking: result_masking.clone(),
                    sql_policy: sql_policy.clone(),
                    metrics: None,
                    profile_drain: ProfileDrainState::from_config(full_config.clone()),
                    unsigned_refusal_log,
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
            let Some(http_service_owner) = service_owner.as_ref() else {
                emit_status_error(
                    robot_json,
                    "ORACLEMCP_SERVICE_STATE_UNAVAILABLE",
                    "HTTP service state owner was not initialized",
                );
                return ExitCode::from(2);
            };
            let mut resolved_http = match resolve_http_transport_config(
                &full_config,
                &http,
                &level,
                secret_resolver.as_ref(),
            ) {
                Ok(cfg) => cfg,
                Err((code, message)) => {
                    emit_status_error(robot_json, code, &message);
                    return ExitCode::from(2);
                }
            };
            if http.client_credentials {
                let store = match ClientCredentialStore::open_with_owner(http_service_owner.clone())
                {
                    Ok(store) => store,
                    Err(error) => {
                        emit_status_error(
                            robot_json,
                            client_credential_error_code(&error),
                            &client_credential_error_message(&error),
                        );
                        return ExitCode::from(2);
                    }
                };
                resolved_http.transport.client_credentials = Some(Arc::new(store));
            }
            let oauth_enabled = resolved_http.transport.oauth.is_some();
            let tls_enabled = resolved_http.tls.is_some();
            let effective_https = tls_enabled
                || resolved_http.transport.effective_scheme == EffectiveHttpScheme::Https;
            let client_credentials_enabled = resolved_http.transport.client_credentials.is_some();
            let auth_enabled =
                oauth_enabled || resolved_http.mtls_required || client_credentials_enabled;
            let allow_remote = effective_http_allow_remote(resolved_http.allow_remote);
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
            } else if effective_https {
                eprintln!(
                    "oraclemcp serve: plaintext HTTP backend on {addr} is configured behind \
                     trusted external HTTPS termination. Forwarded scheme headers are ignored."
                );
                if !oauth_enabled && !client_credentials_enabled {
                    eprintln!(
                        "oraclemcp serve: WARNING — trusted HTTPS termination does not provide \
                         per-client authentication; configure OAuth or client credentials unless \
                         this is intentional local development."
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
                open_runtime_connection_plan(
                    connection_plan,
                    &full_config,
                    false,
                    secret_resolver.as_ref(),
                )
            };
            let metrics = Arc::new(Metrics::new());
            let profile_drain = ProfileDrainState::from_config(full_config.clone());
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
                    max_query_cost,
                    cumulative_query_cost_budget: cumulative_query_cost_budget.clone(),
                    query_cost_budgets: query_cost_budgets.clone(),
                    result_masking: result_masking.clone(),
                    sql_policy: sql_policy.clone(),
                    metrics: Some(Arc::clone(&metrics)),
                    profile_drain: profile_drain.clone(),
                    unsigned_refusal_log,
                },
            );
            let server = built.server;
            let ResolvedHttpTransportConfig {
                mut transport,
                tls,
                control,
                ..
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
            // The CI-lane tile reads a durable snapshot. The ordinary HTTP(S)
            // listener starts one bounded background poller that refreshes it
            // from the fixed public GitHub API; the request path only reads.
            apply_ci_lane_snapshot_default(&mut transport, ci_heartbeat_snapshot_path);
            let config_ops_backend =
                match ConfigOpsBackend::open_with_owner(http_service_owner.clone()) {
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
            let change_proposals =
                match ChangeProposalStore::open_with_owner(http_service_owner.clone()) {
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
            let source_history =
                match SourceHistoryStore::open_with_owner(http_service_owner.clone()) {
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
                    open_profile_runtime_connections(
                        &full_config,
                        profile,
                        secret_resolver.as_ref(),
                        false,
                    )
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
            let listener_addr = match listener.local_addr() {
                Ok(listener_addr) => listener_addr,
                Err(error) => {
                    emit_status_error(
                        robot_json,
                        "ORACLEMCP_DASHBOARD_LISTENER_IDENTITY_UNAVAILABLE",
                        &format!("failed to identify bound HTTP listener: {error}"),
                    );
                    pinger.shutdown();
                    drop(telemetry);
                    return ExitCode::from(1);
                }
            };
            if listener_addr.ip().is_loopback() {
                let host = match listener_addr.ip() {
                    std::net::IpAddr::V4(address) => address.to_string(),
                    std::net::IpAddr::V6(address) => format!("[{address}]"),
                };
                let scheme = if tls_enabled { "https" } else { "http" };
                let audience = format!("{scheme}://{host}:{}", listener_addr.port());
                transport.dashboard_auth =
                    match DashboardAuth::new(default_dashboard_ticket_dir(), &audience) {
                        Ok(auth) => Some(Arc::new(auth)),
                        Err(error) => {
                            emit_status_error(
                                robot_json,
                                "ORACLEMCP_DASHBOARD_LISTENER_IDENTITY_UNAVAILABLE",
                                &error.to_string(),
                            );
                            pinger.shutdown();
                            drop(telemetry);
                            return ExitCode::from(1);
                        }
                    };
            }
            let _service_instance_guard = match acquire_service_instance_guard(&addr) {
                Ok(guard) => guard,
                Err(error) => {
                    emit_status_error(robot_json, error.code, &error.message);
                    pinger.shutdown();
                    drop(telemetry);
                    return ExitCode::from(error.exit_code);
                }
            };
            let control_transport = if let Some(control) = control {
                let control_listener = match TcpListener::bind(&control.listen) {
                    Ok(listener) => listener,
                    Err(error) => {
                        emit_status_error(
                            robot_json,
                            "ORACLEMCP_CONTROL_LISTEN_BIND_FAILED",
                            &format!(
                                "mandatory-mTLS control-listener bind error on {}: {error}",
                                control.listen
                            ),
                        );
                        pinger.shutdown();
                        drop(telemetry);
                        return ExitCode::from(1);
                    }
                };
                let authenticated_workers = control
                    .operator_workers
                    .saturating_add(control.doctor_workers);
                let mut control_config = transport.clone();
                control_config.stateful = false;
                control_config.session_store = None;
                control_config.result_store = None;
                control_config.dashboard_auth = None;
                control_config.transport_admission = Arc::new(AdmissionController::with_reserved(
                    authenticated_workers,
                    authenticated_workers,
                    control.operator_workers,
                    control.doctor_workers,
                ));
                let preauth_admission = Arc::new(AdmissionController::new(
                    control.preauth_workers,
                    control.preauth_workers,
                ));
                eprintln!(
                    "oraclemcp serve: dedicated mandatory-mTLS control transport on {} enabled (preauth={}, operator={}, doctor={}).",
                    control.listen,
                    control.preauth_workers,
                    control.operator_workers,
                    control.doctor_workers,
                );
                Some((control_listener, control_config, preauth_admission))
            } else {
                None
            };
            let service_transport = match (tls, control_transport) {
                (Some(tls), Some((control_listener, control_config, preauth_admission))) => {
                    ServiceTransport::HttpsWithControl {
                        listener,
                        control_listener,
                        server,
                        config: transport,
                        control_config: Box::new(control_config),
                        control_preauth_admission: preauth_admission,
                        tls,
                    }
                }
                (Some(tls), None) => ServiceTransport::Https {
                    listener,
                    server,
                    config: transport,
                    tls,
                },
                (None, None) => ServiceTransport::Http {
                    listener,
                    server,
                    config: transport,
                },
                (None, Some(_)) => unreachable!("validated control ingress requires TLS"),
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
        eprintln!("{}", serve_status_payload(transport, addr, tools));
    } else {
        match addr {
            Some(a) => eprintln!(
                "oraclemcp serve: http transport listening on {a} ({} tools, built-with-live-db: {BUILT_WITH_LIVE_DB})",
                tools.len()
            ),
            None => eprintln!(
                "oraclemcp serve: stdio transport ready ({} tools, built-with-live-db: {BUILT_WITH_LIVE_DB})",
                tools.len()
            ),
        }
    }
}

/// Startup status contains build facts only. Runtime connectivity is observed
/// through `oracle_connection_info`, `oracle_capabilities`, or `doctor --online`.
fn serve_status_payload(
    transport: &str,
    addr: Option<&str>,
    tools: &[String],
) -> serde_json::Value {
    serde_json::json!({
        "kind": "status",
        "transport": transport,
        "listen": addr,
        "built_with_live_db": BUILT_WITH_LIVE_DB,
        "tools": tools,
    })
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
                 address, set [http] allow_remote = true in config, or set \
                 ORACLEMCP_HTTP_ALLOW_REMOTE=1 when equivalent network controls \
                 are in front",
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
    let pairing_request = match prepare_dashboard_pairing(base_url) {
        Ok(request) => request,
        Err(error) => {
            if robot_json {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "kind": "error",
                        "code": "ORACLEMCP_DASHBOARD_URL_INVALID",
                        "message": error.to_string(),
                    })
                );
            } else {
                eprintln!("{binary_name} dashboard: {error}");
            }
            return ExitCode::from(2);
        }
    };
    // Single sanctioned sync->async boundary for the CLI path (same helper used by
    // connect/doctor); the library probe itself is a pure `async fn(&Cx, ...)`.
    let probe_request = &pairing_request;
    let listener_proof = match block_on_connect(|cx| async move {
        probe_dashboard_http_service(&cx, probe_request).await
    }) {
        Ok(proof) => proof,
        Err(e) => {
            let code = if matches!(e, DashboardAuthError::ServiceUnreachable { .. }) {
                "ORACLEMCP_DASHBOARD_SERVICE_UNREACHABLE"
            } else {
                "ORACLEMCP_DASHBOARD_PROBE_FAILED"
            };
            if robot_json {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "kind": "error",
                        "code": code,
                        "message": e.to_string(),
                    })
                );
            } else {
                eprintln!("{binary_name} dashboard: {e}");
            }
            return ExitCode::from(2);
        }
    };
    let ticket = match mint_dashboard_pairing_ticket(&ticket_dir, pairing_request, listener_proof) {
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
    // The URL carries no secret (bead oraclemcp-l6xn), but the browser is still
    // never launched from here: a launcher argv is visible to other local
    // processes, and pairing stays a deliberate operator act.
    let opened = false;
    if !no_open && !robot_json {
        eprintln!(
            "{binary_name} dashboard: automatic browser launch is disabled; open the printed URL manually"
        );
    }
    if robot_json {
        let output = serde_json::json!({
            "kind": "dashboard_pairing",
            "url": ticket.url,
            "pairing_code": ticket.code,
            "expires_unix": ticket.expires_unix,
            "opened": opened,
            "ticket_file": ticket.ticket_file,
        });
        stdout_exit(
            write_stdout_line(&serde_json::to_string(&output).expect("dashboard JSON serializes")),
            ExitCode::SUCCESS,
        )
    } else {
        // stdout stays the machine-readable channel (the URL); the code and its
        // instructions go to stderr so `om dashboard | …` keeps working.
        eprintln!(
            "{binary_name} dashboard: open the URL below, then paste this one-time code (valid {DASHBOARD_PAIRING_TTL_SECONDS}s, single use):\n\n    {}\n",
            ticket.code
        );
        stdout_exit(write_stdout_line(&ticket.url), ExitCode::SUCCESS)
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

fn info_payload() -> serde_json::Value {
    serde_json::json!({
        "binary": "oraclemcp",
        "version": env!("CARGO_PKG_VERSION"),
        "engine": cfg!(feature = "plsql-intelligence"),
        "built_with_live_db": BUILT_WITH_LIVE_DB,
        "transports": ["stdio", "http"],
        "tools": registry::tool_names(),
        "mcp_protocol_version": oraclemcp_core::PROTOCOL_VERSION,
    })
}

fn run_info(robot_json: bool) -> ExitCode {
    let info = info_payload();
    let output = if robot_json {
        serde_json::to_string(&info).unwrap()
    } else {
        serde_json::to_string_pretty(&info).unwrap()
    };
    stdout_exit(write_stdout_line(&output), ExitCode::SUCCESS)
}

/// The command MCP client snippets launch by default: the real, currently
/// running binary — the same resolution the installer's `print_client_snippet`
/// performs — never a wrapper script that nothing creates.
fn setup_snippet_command() -> String {
    std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "oraclemcp".to_owned())
}

/// Encode `value` as a TOML string for the hand-rolled `codex_config_toml`
/// snippet. Prefers a **literal** (single-quoted) string so a Windows path like
/// `C:\Users\alice\oraclemcp.exe` survives verbatim — a basic double-quoted
/// string would treat `\U`/`\a`/… as (invalid) escapes and emit un-parseable
/// TOML. Falls back to a properly-escaped basic string when the value contains a
/// single quote or a control char (which a literal string cannot carry).
fn toml_string_encode(value: &str) -> String {
    if !value.contains('\'') && !value.chars().any(char::is_control) {
        return format!("'{value}'");
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn setup_payload(
    profile: &str,
    credential_env: &str,
    snippet_command: &str,
    explicit_wrapper: Option<&str>,
    config_path: &str,
    tools_dir: &str,
) -> serde_json::Value {
    let one_line_install = format!(
        "curl -fsSL \"https://raw.githubusercontent.com/MuhDur/oraclemcp/main/install.sh?$(date +%s)\" | bash -s -- --version {}",
        env!("CARGO_PKG_VERSION")
    );
    serde_json::json!({
        "ok": true,
        "kind": "oraclemcp_setup",
        "principle": "one generic binary; all environment-specific database names, credentials, session identity, and custom tools live in local config",
        "install": {
            "one_line": one_line_install,
            "self_update": "oraclemcp self-update",
            "cargo_binstall": "cargo binstall oraclemcp",
            "source_build": "cargo +nightly-2026-05-11 install oraclemcp (source-build escape hatch; the workspace is pinned to nightly, plain cargo install fails on stable)",
            "docker_stdio": format!("docker run -i --rm ghcr.io/muhdur/oraclemcp:{}", env!("CARGO_PKG_VERSION"))
        },
        "paths": {
            "profiles": config_path,
            "custom_tools": tools_dir,
            "wrapper": explicit_wrapper,
            "full_profile_example": "oraclemcp.example.toml"
        },
        "snippet_command": {
            "command": snippet_command,
            "source": if explicit_wrapper.is_some() {
                "explicit --wrapper-path; the wrapper must exist before the snippets work (setup only prints a template, it never writes the wrapper)"
            } else {
                "resolved oraclemcp binary"
            }
        },
        "profiles_toml": robot_docs::setup_profiles_template(profile, credential_env),
        "wrapper_script": robot_docs::setup_wrapper_template(),
        "custom_tool_toml": robot_docs::setup_custom_tool_template(),
        "claude_mcp_json": {
            "mcpServers": {
                "oracle": {
                    "command": snippet_command,
                    "args": ["serve", "--profile", profile, "--allow-no-auth"]
                }
            }
        },
        "codex_config_toml": format!(
            "[mcp_servers.oracle]\ncommand = {}\nargs = [\"serve\", \"--profile\", {}, \"--allow-no-auth\"]\n",
            toml_string_encode(snippet_command),
            toml_string_encode(profile),
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
            match explicit_wrapper {
                Some(path) => format!("create the wrapper first: write the wrapper_script template to {path} and make it executable — the client snippets point at it and nothing creates it automatically"),
                None => "optionally re-run setup --wrapper-path <path> after writing the wrapper_script template there, if Oracle Net environment setup (e.g. TNS_ADMIN) is needed".to_owned(),
            },
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

/// Apply a discovered/merged config through config-ops, guarding against a
/// concurrent external edit since the bytes the merge was computed from
/// (`expected_current_sha256`). Used by `setup --discover` (TNS-onboarding beads
/// `.10`–`.12`): the merge in `discover` reads the current target, so the apply
/// must reject a racing write (`ConfigOpsError::CurrentChanged`) rather than
/// clobber it — verify-before-mutate on top of the same backup + atomic-rename +
/// strict-revalidate path `setup --write` uses.
fn setup_apply_discovery_config(
    target_path: PathBuf,
    draft_toml: &str,
    expected_current_sha256: &str,
) -> Result<SetupWriteResult, ConfigOpsError> {
    let backend = ConfigOpsBackend::open_default()?;
    let service = ConfigOpsService::new(backend, target_path, None);
    let preview = service.stage(draft_toml)?;
    let outcome = service.apply(draft_toml, Some(expected_current_sha256))?;
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
        ConfigOpsError::PreviewRequired => (
            "ORACLEMCP_SETUP_PREVIEW_REQUIRED",
            error.to_string(),
        ),
        ConfigOpsError::InvalidPreviewToken => (
            "ORACLEMCP_SETUP_PREVIEW_TOKEN_INVALID",
            error.to_string(),
        ),
        ConfigOpsError::PreviewExpired => ("ORACLEMCP_SETUP_PREVIEW_EXPIRED", error.to_string()),
        ConfigOpsError::PreviewDraftChanged => (
            "ORACLEMCP_SETUP_PREVIEW_DRAFT_CHANGED",
            error.to_string(),
        ),
        ConfigOpsError::PreviewConfirmationRequired => (
            "ORACLEMCP_SETUP_PREVIEW_CONFIRMATION_REQUIRED",
            error.to_string(),
        ),
        ConfigOpsError::FileStore(oraclemcp_core::file_store::FileStoreError::Locked) => (
            "ORACLEMCP_STATE_STORE_LOCKED",
            "the state store is exclusively locked by a running oraclemcp service; stop that service before offline mutation or use its online operator workflow"
                .to_owned(),
        ),
        ConfigOpsError::FileStore(_) => (
            "ORACLEMCP_SETUP_STATE_STORE_FAILED",
            error.to_string(),
        ),
        ConfigOpsError::Io(_) => (
            "ORACLEMCP_SETUP_IO_FAILED",
            error.to_string(),
        ),
        _ => (
            "ORACLEMCP_SETUP_WRITE_FAILED",
            error.to_string(),
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
    wrapper_path: Option<&str>,
    config_path: &str,
    tools_dir: &str,
) -> ExitCode {
    let target_path = setup_write_target_path(config_path);
    let setup_config_path = if write {
        target_path.display().to_string()
    } else {
        setup_display_path(config_path)
    };
    let explicit_wrapper = wrapper_path.map(setup_display_path);
    let snippet_command = explicit_wrapper
        .clone()
        .unwrap_or_else(setup_snippet_command);
    let setup_tools_dir = setup_display_path(tools_dir);
    let mut payload = setup_payload(
        profile,
        credential_env,
        &snippet_command,
        explicit_wrapper.as_deref(),
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
        output.push_str("Install / update:\n");
        output.push_str(&format!(
            "  {}\n",
            payload["install"]["one_line"].as_str().unwrap_or("")
        ));
        output.push_str("  oraclemcp self-update        (existing installs)\n");
        output.push_str("  cargo binstall oraclemcp     (prebuilt via cargo ecosystem)\n");
        output.push_str(
            "  cargo +nightly-2026-05-11 install oraclemcp   (source-build escape hatch; plain cargo install fails on stable)\n\n",
        );
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
        output.push_str(&format!("Snippet command:\n  {snippet_command}\n"));
        if let Some(wrapper) = explicit_wrapper.as_deref() {
            output.push_str(&format!(
                "  (explicit --wrapper-path: create this wrapper first — write the wrapper script template to {wrapper} and make it executable; setup never writes it)\n"
            ));
        }
        output.push('\n');
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

const LATEST_RELEASE_API_URL: &str =
    "https://api.github.com/repos/MuhDur/oraclemcp/releases/latest";
const LATEST_RELEASE_MAX_BYTES: usize = 1024 * 1024;
// Embed the installers from a crate-local copy kept byte-identical to the
// repo-root install.sh/install.ps1 (drift-guarded by the
// `embedded_installers_match_repo_root` test below). The repo-root originals
// are what `curl | bash` fetches; `cargo package` only includes files inside
// the crate, so the self-update embed must read a local copy or the published
// tarball fails to verify (qa93 packaging regression).
#[cfg(any(test, not(windows)))]
const EMBEDDED_INSTALLER_SH: &[u8] = include_bytes!("../install.sh");
#[cfg(any(test, windows))]
const EMBEDDED_INSTALLER_PS1: &[u8] = include_bytes!("../install.ps1");
#[cfg(not(windows))]
const EMBEDDED_SELF_UPDATE_INSTALLER: &[u8] = EMBEDDED_INSTALLER_SH;
#[cfg(windows)]
const EMBEDDED_SELF_UPDATE_INSTALLER: &[u8] = EMBEDDED_INSTALLER_PS1;
#[cfg(not(windows))]
const EMBEDDED_SELF_UPDATE_NAME: &str = "install.sh";
#[cfg(windows)]
const EMBEDDED_SELF_UPDATE_NAME: &str = "install.ps1";

fn self_update_installer_source() -> String {
    format!(
        "embedded:{EMBEDDED_SELF_UPDATE_NAME}@oraclemcp-{}",
        env!("CARGO_PKG_VERSION")
    )
}

fn normalize_self_update_version(value: &str) -> Result<String, String> {
    let value = value.strip_prefix('v').unwrap_or(value);
    let (core, prerelease) = value
        .split_once('-')
        .map_or((value, None), |(core, prerelease)| (core, Some(prerelease)));
    let parts = core.split('.').collect::<Vec<_>>();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty()
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
        })
    {
        return Err(
            "release version must be X.Y.Z or vX.Y.Z with an optional prerelease".to_owned(),
        );
    }
    if prerelease.is_some_and(|value| {
        value.is_empty()
            || value.split('.').any(|part| {
                part.is_empty()
                    || (part.len() > 1
                        && part.starts_with('0')
                        && part.bytes().all(|byte| byte.is_ascii_digit()))
            })
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    }) {
        return Err("release prerelease contains unsupported characters".to_owned());
    }
    Ok(value.to_owned())
}

fn parse_latest_release_version(body: &[u8]) -> Result<String, String> {
    if body.len() > LATEST_RELEASE_MAX_BYTES {
        return Err("latest-release metadata exceeded 1 MiB".to_owned());
    }
    let value: serde_json::Value = serde_json::from_slice(body)
        .map_err(|_| "latest-release metadata was not valid JSON".to_owned())?;
    let tag = value
        .get("tag_name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "latest-release metadata omitted tag_name".to_owned())?;
    normalize_self_update_version(tag)
}

#[cfg(not(windows))]
fn fetch_latest_release_version() -> Result<String, String> {
    let output = ProcessCommand::new("curl")
        .args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--max-time",
            "15",
            "--max-filesize",
            "1048576",
            "--header",
            concat!(
                "user-agent: oraclemcp-self-update/",
                env!("CARGO_PKG_VERSION")
            ),
            LATEST_RELEASE_API_URL,
        ])
        .output()
        .map_err(|error| format!("could not run curl to resolve latest release: {error}"))?;
    if !output.status.success() {
        return Err("GitHub latest-release lookup failed".to_owned());
    }
    parse_latest_release_version(&output.stdout)
}

#[cfg(windows)]
fn fetch_latest_release_version() -> Result<String, String> {
    const SCRIPT: &str = concat!(
        "$ProgressPreference = 'SilentlyContinue'; ",
        "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; ",
        "$response = Invoke-RestMethod -UseBasicParsing -Uri $args[0] ",
        "-Headers @{'User-Agent'='oraclemcp-self-update/",
        env!("CARGO_PKG_VERSION"),
        "'} -MaximumRedirection 3 -TimeoutSec 15; ",
        "[Console]::Out.Write([string]$response.tag_name)"
    );
    let output = ProcessCommand::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            SCRIPT,
            LATEST_RELEASE_API_URL,
        ])
        .output()
        .map_err(|error| format!("could not run PowerShell to resolve latest release: {error}"))?;
    if !output.status.success() {
        return Err("GitHub latest-release lookup failed".to_owned());
    }
    if output.stdout.len() > 256 {
        return Err("latest-release tag exceeded 256 bytes".to_owned());
    }
    let tag = std::str::from_utf8(&output.stdout)
        .map_err(|_| "latest-release tag was not UTF-8".to_owned())?;
    normalize_self_update_version(tag.trim())
}

fn resolve_self_update_version(requested: &str) -> Result<String, String> {
    if requested != "latest" {
        return normalize_self_update_version(requested);
    }
    fetch_latest_release_version()
}

fn embedded_installer_sha256(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    use sha2::Digest;
    let digest = sha2::Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn materialize_verified_installer(
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<tempfile::NamedTempFile, String> {
    let suffix = if cfg!(windows) { ".ps1" } else { ".sh" };
    let mut file = tempfile::Builder::new()
        .prefix("oraclemcp-self-update-")
        .suffix(suffix)
        .tempfile()
        .map_err(|error| format!("could not create private installer file: {error}"))?;
    file.write_all(bytes)
        .and_then(|()| file.as_file().sync_all())
        .map_err(|error| format!("could not write embedded installer: {error}"))?;
    let mut reader = file
        .reopen()
        .map_err(|error| format!("could not reopen embedded installer: {error}"))?;
    let length = reader
        .metadata()
        .map_err(|error| format!("could not inspect embedded installer: {error}"))?
        .len();
    if length != bytes.len() as u64 {
        return Err("embedded installer length changed before execution".to_owned());
    }
    let mut readback = Vec::with_capacity(bytes.len());
    reader
        .read_to_end(&mut readback)
        .map_err(|error| format!("could not verify embedded installer: {error}"))?;
    if embedded_installer_sha256(&readback) != expected_sha256 {
        return Err("embedded installer authentication failed before execution".to_owned());
    }
    Ok(file)
}

#[cfg(not(windows))]
fn self_update_argv(args: &SelfUpdateCliArgs, resolved_version: &str, path: &str) -> Vec<String> {
    let mut argv = vec![
        "bash".to_owned(),
        path.to_owned(),
        "--update".to_owned(),
        "--version".to_owned(),
        resolved_version.to_owned(),
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
fn self_update_argv(args: &SelfUpdateCliArgs, resolved_version: &str, path: &str) -> Vec<String> {
    let mut argv = vec![
        "powershell.exe".to_owned(),
        "-NoProfile".to_owned(),
        "-ExecutionPolicy".to_owned(),
        "Bypass".to_owned(),
        "-File".to_owned(),
        path.to_owned(),
        "-Update".to_owned(),
        "-Version".to_owned(),
        resolved_version.to_owned(),
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
    let resolved_version = match resolve_self_update_version(&args.version) {
        Ok(version) => version,
        Err(error) => {
            emit_command_error(
                robot_json,
                "self-update",
                "ORACLEMCP_SELF_UPDATE_VERSION_RESOLUTION_FAILED",
                &error,
            );
            return ExitCode::from(2);
        }
    };
    let installer_sha256 = embedded_installer_sha256(EMBEDDED_SELF_UPDATE_INSTALLER);
    let installer_source = self_update_installer_source();
    let preview_path = format!("<verified-embedded:{EMBEDDED_SELF_UPDATE_NAME}>");
    let preview_argv = self_update_argv(&args, &resolved_version, &preview_path);
    if args.dry_run {
        let payload = serde_json::json!({
            "kind": "oraclemcp_self_update",
            "installer_source": installer_source,
            "installer_sha256": installer_sha256,
            "requested_version": args.version,
            "resolved_version": resolved_version,
            "release_tag": format!("v{}", resolved_version),
            "argv": preview_argv,
            "notes": [
                "self-update executes installer bytes embedded in this signed binary, never a mutable branch",
                "the platform installer --update flag is an alias for the version-aware update path"
            ]
        });
        let mut text = String::new();
        text.push_str("oraclemcp self-update\n\n");
        text.push_str(&format!(
            "Installer:\n  source: {installer_source}\n  sha256: {installer_sha256}\n  release_tag: v{resolved_version}\n\n"
        ));
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

    let installer =
        match materialize_verified_installer(EMBEDDED_SELF_UPDATE_INSTALLER, &installer_sha256) {
            Ok(installer) => installer,
            Err(error) => {
                emit_command_error(
                    robot_json,
                    "self-update",
                    "ORACLEMCP_SELF_UPDATE_INSTALLER_AUTH_FAILED",
                    &error,
                );
                return ExitCode::from(2);
            }
        };
    let installer_path = installer.path().to_string_lossy().into_owned();
    let argv = self_update_argv(&args, &resolved_version, &installer_path);
    let Some((program, rest)) = argv.split_first() else {
        emit_command_error(
            robot_json,
            "self-update",
            "ORACLEMCP_SELF_UPDATE_COMMAND_EMPTY",
            "internal verified self-update command was empty",
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
    write: bool,
) -> Result<serde_json::Value, ErrorEnvelope> {
    let key = std::env::var(CUSTOM_TOOLS_HMAC_KEY_ENV).map_err(|_| {
        custom_tool_error(format!(
            "{CUSTOM_TOOLS_HMAC_KEY_ENV} is required to sign custom tool definitions"
        ))
    })?;
    custom_tool_signatures_with_key_and_write(path, only_tool, &key, write)
}

#[cfg(test)]
fn custom_tool_signatures_with_key(
    path: &Path,
    only_tool: Option<&str>,
    key: &str,
) -> Result<serde_json::Value, ErrorEnvelope> {
    custom_tool_signatures_with_key_and_write(path, only_tool, key, false)
}

fn custom_tool_signatures_with_key_and_write(
    path: &Path,
    only_tool: Option<&str>,
    key: &str,
    write: bool,
) -> Result<serde_json::Value, ErrorEnvelope> {
    let key = HmacSha256Key::new(key.as_bytes().to_vec()).map_err(|error| {
        custom_tool_error(format!("{CUSTOM_TOOLS_HMAC_KEY_ENV} is invalid: {error}"))
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
        let signature = sign(&def, &key);
        signatures.push((def.name, signature));
    }
    if signatures.is_empty() {
        return Err(custom_tool_error(
            "no matching custom tool definitions found",
        ));
    }
    if write {
        write_custom_tool_signatures(path, &src, &signatures)?;
    }
    Ok(serde_json::json!({
        "ok": true,
        "path": path.display().to_string(),
        "written": write,
        "signatures": signatures.iter().map(|(name, signature)| serde_json::json!({
            "name": name,
            "signature": signature,
        })).collect::<Vec<_>>(),
        "next_actions": [
            if write {
                "signatures were written into their matching [[tool]] blocks"
            } else {
                "copy each signature into its matching [[tool]] block as signature = \"...\", or re-run with --write"
            },
            "set ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY in the MCP server environment",
            "run oraclemcp --json doctor --online --profile <profile> before restarting clients"
        ]
    }))
}

/// Atomically update only the matching top-level `[[tool]]` tables. TOML's
/// nested `[[tool.params]]` tables stay nested, so a signature can never be
/// appended under the final parameter by accident.
fn write_custom_tool_signatures(
    path: &Path,
    src: &str,
    signatures: &[(String, String)],
) -> Result<(), ErrorEnvelope> {
    let mut document = src.parse::<toml_edit::DocumentMut>().map_err(|error| {
        custom_tool_error(format!(
            "failed to edit custom tool file {}: {error}",
            path.display()
        ))
    })?;
    let tools = document
        .get_mut("tool")
        .and_then(toml_edit::Item::as_array_of_tables_mut)
        .ok_or_else(|| custom_tool_error("custom tool file contains no [[tool]] definitions"))?;
    let mut written = 0usize;
    for tool in tools.iter_mut() {
        let Some(name) = tool.get("name").and_then(toml_edit::Item::as_str) else {
            continue;
        };
        let Some((_, signature)) = signatures
            .iter()
            .find(|(candidate, _)| candidate.as_str() == name)
        else {
            continue;
        };
        tool["signature"] = toml_edit::value(signature.clone());
        written += 1;
    }
    if written != signatures.len() {
        return Err(custom_tool_error(
            "could not locate every requested custom tool while writing signatures",
        ));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let mut temporary = tempfile::NamedTempFile::new_in(parent.unwrap_or_else(|| Path::new(".")))
        .map_err(|error| {
        custom_tool_error(format!(
            "failed to create temporary signed tool file beside {}: {error}",
            path.display()
        ))
    })?;
    temporary
        .write_all(document.to_string().as_bytes())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|error| {
            custom_tool_error(format!(
                "failed to write signed custom tool file {}: {error}",
                path.display()
            ))
        })?;
    temporary.persist(path).map_err(|error| {
        custom_tool_error(format!(
            "failed to replace signed custom tool file {}: {}",
            path.display(),
            error.error
        ))
    })?;
    Ok(())
}

fn run_sign_tool(robot_json: bool, path: &Path, only_tool: Option<&str>, write: bool) -> ExitCode {
    match custom_tool_signatures(path, only_tool, write) {
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

/// Resolve the same active+historical keyring used by startup. `--key-id`
/// remains an env-only active-id override; configured historical keys are
/// always included so a mixed chain verifies end to end.
fn audit_verification_keyring(key_id_override: Option<&str>) -> Result<AuditKeyring, String> {
    let audit = OracleMcpConfig::load(None)
        .map(|cfg| cfg.audit)
        .map_err(|e| format!("failed to load audit config: {e}"))?;
    let legacy_env_key = std::env::var(AUDIT_KEY_ENV).ok();
    audit_verification_keyring_from_sources(
        &audit,
        key_id_override,
        &SystemSecretResolver,
        legacy_env_key.as_deref(),
    )
}

fn audit_verification_keyring_from_sources(
    audit: &AuditConfig,
    key_id_override: Option<&str>,
    secret_resolver: &dyn SecretResolver,
    legacy_env_key: Option<&str>,
) -> Result<AuditKeyring, String> {
    // `protected=false`: verification is an operator action that may run
    // off-box against a copied log, where a dev `literal:` key is legitimate.
    resolve_audit_keyring_from_sources(
        audit,
        key_id_override,
        false,
        secret_resolver,
        legacy_env_key,
    )?
    .ok_or_else(|| {
        format!(
            "no audit signing key configured; set [audit].key_ref or {AUDIT_KEY_ENV} to verify \
             the chain"
        )
    })
}

/// Capture an offline-replayable bundle without trusting the artifact as an
/// authorization source. The raw statement remains in process only long enough
/// for the Arc J redactor and the capture gate to prove it cannot reach disk.
fn run_refusal_corpus_export(robot_json: bool, args: RefusalCorpusExportCliArgs) -> ExitCode {
    match oraclemcp::dispatch::export_refusal_corpus(args.corpus.as_deref(), &args.out) {
        Ok(records) => {
            let payload = serde_json::json!({
                "kind": "oraclemcp_refusal_corpus_export",
                "destination": args.out.display().to_string(),
                "records": records,
            });
            let output = if robot_json {
                payload.to_string()
            } else {
                format!(
                    "exported {records} redacted refusal record(s) to {}",
                    args.out.display()
                )
            };
            stdout_exit(write_stdout_line(&output), ExitCode::SUCCESS)
        }
        Err(message) => {
            emit_command_error(
                robot_json,
                "refusal-corpus export",
                "ORACLEMCP_REFUSAL_CORPUS_EXPORT_REFUSED",
                &message,
            );
            ExitCode::from(2)
        }
    }
}

fn incident_capture_error_status(error: &IncidentCaptureError) -> (&'static str, String) {
    match error {
        IncidentCaptureError::Io(_) => ("ORACLEMCP_INCIDENT_CAPTURE_IO_FAILED", error.to_string()),
        IncidentCaptureError::MissingFile { .. } => {
            ("ORACLEMCP_INCIDENT_BUNDLE_MISSING", error.to_string())
        }
        _ => ("ORACLEMCP_INCIDENT_CAPTURE_REFUSED", error.to_string()),
    }
}

fn incident_replay_error_status(error: &IncidentReplayError) -> (&'static str, String) {
    match error {
        IncidentReplayError::Capture(capture_error @ IncidentCaptureError::Io(_)) => (
            "ORACLEMCP_INCIDENT_REPLAY_IO_FAILED",
            capture_error.to_string(),
        ),
        IncidentReplayError::Capture(capture_error @ IncidentCaptureError::MissingFile { .. }) => (
            "ORACLEMCP_INCIDENT_BUNDLE_MISSING",
            capture_error.to_string(),
        ),
        _ => ("ORACLEMCP_INCIDENT_REPLAY_REFUSED", error.to_string()),
    }
}

fn incident_config_load_error_status(error: impl std::fmt::Display) -> (&'static str, String) {
    (
        "ORACLEMCP_INCIDENT_CONFIG_LOAD_FAILED",
        format!("incident capture could not load configuration: {error}"),
    )
}

fn run_incident_capture(robot_json: bool, args: IncidentCaptureCliArgs) -> ExitCode {
    if args.bundle.exists() {
        emit_command_error(
            robot_json,
            "incident capture",
            "ORACLEMCP_INCIDENT_TARGET_EXISTS",
            "incident capture requires a new bundle directory",
        );
        return ExitCode::from(2);
    }

    // A statement can contain a bind value or a literal secret. Accept it only
    // on stdin so it is not left in a shell history or visible in a process
    // listing while the capture gate proves it cannot enter the artifact.
    let mut statement = String::new();
    if io::stdin().read_to_string(&mut statement).is_err() || statement.trim().is_empty() {
        emit_command_error(
            robot_json,
            "incident capture",
            "ORACLEMCP_INCIDENT_STATEMENT_REQUIRED",
            "incident capture requires a non-empty statement on standard input",
        );
        return ExitCode::from(2);
    }

    let config = match OracleMcpConfig::load(None) {
        Ok(config) => config,
        Err(error) => {
            let (code, message) = incident_config_load_error_status(error);
            emit_command_error(robot_json, "incident capture", code, &message);
            return ExitCode::from(2);
        }
    };

    // Capture the guard's verdict as evidence for comparison only. E2 must call
    // `reclassify_at_replay` again; no persisted verdict reaches an admission
    // decision or an execution path.
    let decision = Classifier::new(ClassifierConfig::served_strict()).classify(&statement);
    let captured_verdict = CapturedVerdict {
        danger: decision.danger,
        required_level: decision.required_level,
        reason_class: decision.reason_category,
    };
    let statement_sha256 = oraclemcp_audit::sha256_hex(statement.as_bytes());
    let frames = [CassetteFrame {
        seq: 1,
        // This is a closed, implementation-owned label, never an operator or
        // customer identifier. The statement itself is redacted in core.
        tool: "captured_statement",
        statement: Some(&statement),
        sql_sha256: Some(&statement_sha256),
        outcome: "captured",
    }];
    let cassettes = [Cassette {
        lane_id: "local",
        frames: &frames,
    }];
    let lanes = [CapturedLane {
        lane_id: "local".to_owned(),
        // An implementation-owned stable value, not an operator identity.
        subject_id_hash: oraclemcp_audit::sha256_hex(b"oraclemcp-incident-local"),
    }];
    let sensitive = [statement.clone()];
    let request = IncidentCaptureRequest {
        trigger: IncidentTrigger::Refusal,
        seed: args.seed,
        statement: Some(&statement),
        captured_verdict: Some(captured_verdict),
        why: "operator requested a deterministic incident capture",
        lanes: &lanes,
        build: BuildIdentity {
            server: format!("oraclemcp/{}", env!("CARGO_PKG_VERSION")),
            classifier: format!("oraclemcp-guard/{};registry=1", env!("CARGO_PKG_VERSION")),
            driver: format!("oracledb/{}", oraclemcp_db::DRIVER_VERSION),
        },
        // The live server owns durable audit-tail collection. This standalone
        // command intentionally creates a self-describing empty projection,
        // rather than reading arbitrary operator-selected files into a bundle.
        audit_records: &[],
        cassettes: &cassettes,
        config: &config,
        sensitive: &sensitive,
    };
    let manifest = match capture_bundle(&args.bundle, &request) {
        Ok(manifest) => manifest,
        Err(error) => {
            let (code, message) = incident_capture_error_status(&error);
            emit_command_error(robot_json, "incident capture", code, &message);
            return ExitCode::from(2);
        }
    };

    let payload = serde_json::json!({
        "kind": "oraclemcp_incident_capture",
        "bundle_id": manifest.id,
        "seed": manifest.seed,
        "entries": manifest.entries.len(),
    });
    let output = if robot_json {
        payload.to_string()
    } else {
        format!(
            "captured redacted incident bundle {} (seed {}, {} entries)",
            manifest.id,
            manifest.seed,
            manifest.entries.len()
        )
    };
    stdout_exit(write_stdout_line(&output), ExitCode::SUCCESS)
}

fn run_incident_replay(robot_json: bool, args: IncidentReplayCliArgs) -> ExitCode {
    let report = match replay_bundle(&args.bundle) {
        Ok(report) => report,
        Err(error) => {
            let (code, message) = incident_replay_error_status(&error);
            emit_command_error(robot_json, "incident replay", code, &message);
            return ExitCode::from(2);
        }
    };
    let payload = serde_json::json!({
        "kind": "oraclemcp_incident_replay",
        "bundle_id": report.manifest_id,
        "seed": report.seed,
        "replayed_steps": report.replayed_steps,
        "verdicts": report.verdicts,
        "audit_tail_sha256": report.audit_tail_sha256,
    });
    let output = if robot_json {
        payload.to_string()
    } else {
        serde_json::to_string_pretty(&payload).expect("incident replay payload serializes")
    };
    stdout_exit(write_stdout_line(&output), ExitCode::SUCCESS)
}

fn run_audit_verify(
    robot_json: bool,
    file: &Path,
    key_id_override: Option<&str>,
    with_db_evidence: bool,
) -> ExitCode {
    use oraclemcp_audit::{
        AnchorReaderError, AnchorStatus, AnchorViolation, JsonlError, VerifyOutcome,
        anchor_path_for, check_anchor_reader, load_anchor, parse_jsonl, verify_reader,
    };
    use std::io::BufReader;

    let keyring = match audit_verification_keyring(key_id_override) {
        Ok(keyring) => keyring,
        Err(message) => {
            emit_status_error(robot_json, "ORACLEMCP_AUDIT_KEY_REQUIRED", &message);
            return ExitCode::from(2);
        }
    };

    // Stream verification with BOUNDED MEMORY (bead oraclemcp-qa100 .29): a
    // permanent, never-pruned audit log can be multi-gigabyte, so `audit verify`
    // must not `read_to_string` + parse every record into a `Vec`. The optional
    // `--with-db-evidence` correlation scan below is an explicit operator opt-in
    // and still buffers the full history.
    let open_stream = || std::fs::File::open(file).map(BufReader::new);
    let reader = match open_stream() {
        Ok(reader) => reader,
        Err(e) => {
            emit_status_error(
                robot_json,
                "ORACLEMCP_AUDIT_READ_FAILED",
                &format!("failed to read audit log {}: {e}", file.display()),
            );
            return ExitCode::from(2);
        }
    };
    let outcome = match verify_reader(reader, keyring.verification_keys()) {
        Ok(outcome) => outcome,
        Err(JsonlError::Malformed(e)) => {
            emit_status_error(robot_json, "ORACLEMCP_AUDIT_MALFORMED", &e.to_string());
            return ExitCode::from(2);
        }
        Err(JsonlError::Io(e)) => {
            emit_status_error(
                robot_json,
                "ORACLEMCP_AUDIT_READ_FAILED",
                &format!("failed to read audit log {}: {e}", file.display()),
            );
            return ExitCode::from(2);
        }
    };

    match outcome {
        VerifyOutcome::Ok {
            records: record_count,
        } => {
            // Hash-link/MAC verification passed — a valid PREFIX is a valid
            // chain, so cross-check the sidecar head anchor (bead
            // oraclemcp-xb51) to detect tail truncation. Fail closed on a
            // present-but-invalid anchor; report an explicit advisory when the
            // sidecar is absent (legacy log, or removed with the tail).
            let anchor_path = anchor_path_for(file);
            let anchor = match load_anchor(&anchor_path) {
                Ok(anchor) => anchor,
                Err(e) => {
                    emit_status_error(robot_json, "ORACLEMCP_AUDIT_ANCHOR_INVALID", &e.to_string());
                    return ExitCode::from(2);
                }
            };
            let anchor_payload = match anchor.as_ref() {
                None => serde_json::json!({
                    "status": "absent",
                    "note": "no head anchor sidecar; tail truncation is not locally detectable \
                             for this log (legacy log, or the anchor was removed)",
                }),
                Some(anchor) => {
                    // Bounded streaming anchor cross-check (bead
                    // oraclemcp-qa100 .29): re-open the log and stream it rather
                    // than retaining every record from verification.
                    let anchor_reader = match open_stream() {
                        Ok(reader) => reader,
                        Err(e) => {
                            emit_status_error(
                                robot_json,
                                "ORACLEMCP_AUDIT_READ_FAILED",
                                &format!("failed to re-read audit log {}: {e}", file.display()),
                            );
                            return ExitCode::from(2);
                        }
                    };
                    match check_anchor_reader(anchor_reader, anchor, keyring.verification_keys()) {
                        Ok(AnchorStatus::Match) => serde_json::json!({
                            "status": "match",
                            "seq": anchor.seq,
                        }),
                        Ok(AnchorStatus::Behind { behind_by }) => serde_json::json!({
                            "status": "behind",
                            "seq": anchor.seq,
                            "behind_by": behind_by,
                            "note": "anchor is behind the chain head — explainable (crash between \
                                     record fsync and anchor update, or buffered read records); \
                                     never tamper evidence on its own",
                        }),
                        // `AnchorStatus` is #[non_exhaustive]; fail closed on any
                        // future variant this binary does not understand.
                        Ok(_) => {
                            emit_status_error(
                                robot_json,
                                "ORACLEMCP_AUDIT_UNVERIFIABLE",
                                "unrecognized head-anchor status",
                            );
                            return ExitCode::from(2);
                        }
                        Err(AnchorReaderError::Read(message)) => {
                            emit_status_error(robot_json, "ORACLEMCP_AUDIT_READ_FAILED", &message);
                            return ExitCode::from(2);
                        }
                        Err(AnchorReaderError::Violation(violation)) => {
                            let truncated = matches!(violation, AnchorViolation::Truncated { .. });
                            let payload = serde_json::json!({
                                "ok": false,
                                "file": file.display().to_string(),
                                "records": record_count,
                                "anchor_file": anchor_path.display().to_string(),
                                "anchor_seq": anchor.seq,
                                "reason": violation.to_string(),
                                "truncated": truncated,
                            });
                            if robot_json {
                                let _ =
                                    write_stdout_line(&serde_json::to_string(&payload).unwrap());
                            } else if truncated {
                                let _ = write_stdout_line(&format!(
                                    "TRUNCATED: {violation} (anchor: {})",
                                    anchor_path.display()
                                ));
                            } else {
                                let _ = write_stdout_line(&format!(
                                    "BROKEN: head anchor check failed: {violation} (anchor: {})",
                                    anchor_path.display()
                                ));
                            }
                            return ExitCode::from(2);
                        }
                    }
                }
            };
            let mut payload = serde_json::json!({
                "ok": true,
                "file": file.display().to_string(),
                "records": record_count,
                "anchor": anchor_payload,
            });
            // `--with-db-evidence` is an explicit operator opt-in for a full
            // correlation scan, so it (only) buffers the whole history here; the
            // default verification path above stays bounded (bead qa100 .29).
            let db_evidence_summary = if with_db_evidence {
                match fs::read_to_string(file)
                    .map_err(|e| e.to_string())
                    .and_then(|body| {
                        parse_jsonl(&body)
                            .map(|records| audit_db_evidence_summary(&records))
                            .map_err(|e| e.to_string())
                    }) {
                    Ok(summary) => Some(summary),
                    Err(message) => {
                        emit_status_error(robot_json, "ORACLEMCP_AUDIT_READ_FAILED", &message);
                        return ExitCode::from(2);
                    }
                }
            } else {
                None
            };
            if let Some(summary) = db_evidence_summary.as_ref()
                && let serde_json::Value::Object(obj) = &mut payload
            {
                obj.insert("db_evidence".to_owned(), audit_db_evidence_payload(summary));
            }
            let anchor_text = match payload["anchor"]["status"].as_str() {
                Some("match") => "; anchor: match".to_owned(),
                Some("behind") => format!(
                    "; anchor: behind by {} (explainable crash/buffer window)",
                    payload["anchor"]["behind_by"]
                ),
                _ => "; anchor: absent (tail truncation not locally detectable)".to_owned(),
            };
            let output = if robot_json {
                serde_json::to_string(&payload).unwrap()
            } else if let Some(summary) = db_evidence_summary.as_ref() {
                format!(
                    "OK: audit chain verified ({record_count} records){anchor_text}; {}",
                    audit_db_evidence_text(summary)
                )
            } else {
                format!("OK: audit chain verified ({record_count} records){anchor_text}")
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
    // HTTP and Oracle-driver availability are build capabilities; the
    // `connection` block is the separate runtime observation surface.
    let caps = registry::capabilities(env!("CARGO_PKG_VERSION"), BUILT_WITH_LIVE_DB, true);
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
            let manifest_signing_key = match audit_verification_keyring(None) {
                Ok(keyring) => keyring.active().clone(),
                Err(message) => {
                    emit_status_error(robot_json, "ORACLEMCP_AUDIT_KEY_REQUIRED", &message);
                    return ExitCode::from(2);
                }
            };
            ServiceLifecycleCommand::Backup(ServiceBackupOptions {
                name: args.name,
                state_dir,
                config_path,
                audit_path,
                manifest_signing_key,
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
            let audit_keys = match audit_verification_keyring(args.key_id.as_deref()) {
                Ok(keyring) => keyring.verification_keys().to_vec(),
                Err(message) => {
                    emit_status_error(robot_json, "ORACLEMCP_AUDIT_KEY_REQUIRED", &message);
                    return ExitCode::from(2);
                }
            };
            let config_path = operator_config_target_path();
            let audit_path = match service_audit_path_for_backup(&config_path) {
                Ok(path) => path,
                Err(message) => {
                    emit_status_error(robot_json, "ORACLEMCP_CONFIG_INVALID", &message);
                    return ExitCode::from(2);
                }
            };
            ServiceLifecycleCommand::Restore(ServiceRestoreOptions {
                name: args.name,
                state_dir,
                config_path,
                audit_path,
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
    let online_revocation = online_revocation_for_command(&command);
    let store = match ClientCredentialStore::open_default() {
        Ok(store) => store,
        Err(error) => {
            emit_client_credential_open_error(robot_json, &error, online_revocation.as_ref());
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
                    "durability": issued.durability.as_str(),
                    "durability_warning": issued.durability.warning(),
                    "serve_args": ["serve", "--listen", "127.0.0.1:7070", "--client-credentials"],
                    "client_command": client_credential_client_command(&bearer),
                    "rotation_command": ["oraclemcp", "clients", "rotate", client_id],
                    "revocation_command": ["oraclemcp", "clients", "revoke", issued.client_id],
                    "offline_mutation_notice": "The local rotate and revoke commands require the service to be stopped; a running service keeps clients.json in memory.",
                    "online_revocation_command": online_client_credential_revoke_command(&issued.client_id),
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
                    "durability": issued.durability.as_str(),
                    "durability_warning": issued.durability.warning(),
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
                    "durability": lifecycle.durability.as_str(),
                    "durability_warning": lifecycle.durability.warning(),
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

fn client_credential_client_command(bearer: &str) -> serde_json::Value {
    serde_json::json!([
        "claude",
        "mcp",
        "add",
        "oracle",
        "--transport",
        "http",
        "--header",
        format!("Authorization: Bearer {bearer}"),
        "http://127.0.0.1:7070/mcp",
    ])
}

fn online_client_credential_revoke_command(client_id: &str) -> serde_json::Value {
    serde_json::json!({
        "program": "curl",
        "argv": [
            "curl",
            "--fail-with-body",
            "--request",
            "POST",
            "${ORACLEMCP_CONTROL_URL}/operator/v1/client-credentials/revoke",
            "--cert",
            "${ORACLEMCP_OPERATOR_CERT}",
            "--key",
            "${ORACLEMCP_OPERATOR_KEY}",
            "--cacert",
            "${ORACLEMCP_CONTROL_CA}",
            "--header",
            "content-type: application/json",
            "--data",
            serde_json::json!({ "client_id": client_id }).to_string(),
        ],
        "method": "POST",
        "path": "/operator/v1/client-credentials/revoke",
        "requires": [
            "ORACLEMCP_CONTROL_URL set to the running service's HTTPS control listener",
            "an mTLS client certificate authorized by http.operator.allowed_subjects",
        ],
        "note": "This route mutates the running service's in-memory credential store and closes affected sessions without downtime. Expand or replace the ${...} placeholders before execution."
    })
}

fn online_revocation_for_command(
    command: &ClientCredentialCliCommand,
) -> Option<serde_json::Value> {
    match command {
        ClientCredentialCliCommand::Revoke(args) => {
            Some(online_client_credential_revoke_command(&args.client_id))
        }
        ClientCredentialCliCommand::Issue(_)
        | ClientCredentialCliCommand::List
        | ClientCredentialCliCommand::Rotate(_) => None,
    }
}

fn emit_client_credential_open_error(
    robot_json: bool,
    error: &ClientCredentialError,
    online_revocation: Option<&serde_json::Value>,
) {
    let code = client_credential_error_code(error);
    let message = client_credential_error_message(error);
    let is_locked = matches!(
        error,
        ClientCredentialError::Store(oraclemcp_core::file_store::FileStoreError::Locked)
    );

    if robot_json
        && is_locked
        && let Some(online_revocation) = online_revocation
    {
        eprintln!(
            "{}",
            serde_json::json!({
                "kind": "error",
                "code": code,
                "message": message,
                "online_revocation_command": online_revocation,
                "next_action": "Use the authenticated control-listener request above; do not edit clients.json out of process while the service is running."
            })
        );
    } else {
        emit_status_error(robot_json, code, &message);
    }
}

fn client_lifecycle_json(lifecycle: &ClientCredentialLifecycle) -> serde_json::Value {
    serde_json::json!({
        "client_id": &lifecycle.client_id,
        "subject_id_hash": operator_subject_id_hash(&lifecycle.principal_key),
        "generation": lifecycle.generation,
        "durability": lifecycle.durability.as_str(),
        "durability_warning": lifecycle.durability.warning(),
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
    if let Some(durability) = value["durability"].as_str() {
        out.push_str("durability: ");
        out.push_str(durability);
        out.push('\n');
    }
    if let Some(warning) = value["durability_warning"].as_str() {
        out.push_str("warning: ");
        out.push_str(warning);
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

fn client_credential_error_code(error: &ClientCredentialError) -> &'static str {
    match error {
        ClientCredentialError::Store(oraclemcp_core::file_store::FileStoreError::Locked) => {
            "ORACLEMCP_STATE_STORE_LOCKED"
        }
        _ => "ORACLEMCP_CLIENT_CREDENTIAL_STORE_UNAVAILABLE",
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
    stateless_conn: Option<Box<dyn OracleConnection>>,
    stateless_pool_configured: bool,
    configuration_error: Option<String>,
    connection_error: Option<String>,
    wallet_location: Option<String>,
    protected_profile_writable: bool,
    connection_strategy: Option<String>,
    call_timeout_resolved: bool,
    call_timeout: Option<std::time::Duration>,
    connect_timeout_seconds: Option<u64>,
    inactivity_timeout_seconds: Option<u64>,
    keepalive_minutes: Option<u64>,
    proxy_user: bool,
    profile_caps: Option<DoctorProfileCaps>,
    auth_capabilities: Option<DoctorAuthCapabilities>,
    sensitive_values: Vec<String>,
    credential_env_hint: Option<String>,
    /// Resolved OCI IAM database token (transient; used only for the doctor
    /// near-expiry diagnostic and never rendered). `None` unless the profile uses
    /// IAM-token auth and a token was resolved from its env/file source.
    iam_token: Option<String>,
    /// Resolved wallet password for the online wallet-posture probe only.
    wallet_password: Option<String>,
}

impl DoctorProfileContext {
    fn offline() -> Self {
        DoctorProfileContext {
            conn: None,
            stateless_conn: None,
            stateless_pool_configured: false,
            configuration_error: None,
            connection_error: None,
            wallet_location: None,
            protected_profile_writable: false,
            connection_strategy: None,
            call_timeout_resolved: false,
            call_timeout: None,
            connect_timeout_seconds: None,
            inactivity_timeout_seconds: None,
            keepalive_minutes: None,
            proxy_user: false,
            profile_caps: None,
            auth_capabilities: None,
            sensitive_values: Vec::new(),
            credential_env_hint: None,
            iam_token: None,
            wallet_password: None,
        }
    }
}

/// Build a non-blocking, offline credential-verification hint for a profile
/// whose `env:`-backed credential is still unset (TNS-onboarding bead `.14`).
/// Names the exact env var to export and the `doctor --online` command to
/// verify the profile; returns `None` when the credential is already set, is not
/// an `env:` ref, or is absent. Only the variable NAME is used — never a value.
fn doctor_credential_env_hint(profile: &ConnectionProfile) -> Option<String> {
    let var = profile
        .credential_ref
        .as_deref()?
        .strip_prefix("env:")?
        .trim();
    if var.is_empty() || std::env::var_os(var).is_some() {
        return None;
    }
    Some(format!(
        "export {var}, then run `oraclemcp doctor --online --profile {}` to verify this profile",
        profile.name
    ))
}

fn doctor_sensitive_values(opts: &OracleConnectOptions) -> Vec<String> {
    opts.doctor_redaction_values()
}

fn doctor_connection_error(error: DbError) -> String {
    error.into_envelope().message
}

/// Render a configuration failure with both the configuration file contract and
/// the underlying parser/validation error. `default_config_path` names an
/// existing discovered file; malformed explicit pointers are already named by
/// the underlying `ORACLEMCP_CONFIG` error.
fn doctor_configuration_error(error: impl std::fmt::Display) -> String {
    let source = OracleMcpConfig::default_config_path()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "profiles.toml or ORACLEMCP_CONFIG".to_owned());
    format!("{source}: {error}")
}

fn doctor_resolution_error_context(error: DbError) -> DoctorProfileContext {
    let error = doctor_connection_error(error);
    let mut context = DoctorProfileContext::offline();
    if error.starts_with("config load failed:") {
        context.configuration_error = Some(doctor_configuration_error(error));
    } else {
        context.connection_error = Some(error);
    }
    context
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
                configuration_error: Some(doctor_configuration_error(e)),
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
        stateless_conn: None,
        stateless_pool_configured: chosen.pool.is_some(),
        configuration_error: None,
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
                "pinned_plus_stateless_configured"
            } else {
                "single_session"
            }
            .to_owned(),
        ),
        call_timeout_resolved: true,
        call_timeout: doctor_call_timeout(chosen.call_timeout_seconds),
        connect_timeout_seconds: chosen.connect_timeout_seconds,
        inactivity_timeout_seconds: chosen.inactivity_timeout_seconds,
        keepalive_minutes: chosen.keepalive_minutes,
        proxy_user: chosen
            .proxy_auth
            .as_ref()
            .and_then(|proxy| proxy.proxy_user())
            .is_some(),
        profile_caps: Some(doctor_profile_caps(chosen, &level)),
        auth_capabilities: Some(doctor_auth_capabilities_for_profile(chosen)),
        sensitive_values: Vec::new(),
        credential_env_hint: doctor_credential_env_hint(chosen),
        // Offline metadata inspection never resolves a token (offline-no-secrets
        // invariant); the IAM near-expiry check runs on the --online path.
        iam_token: None,
        wallet_password: None,
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
                            "no connection profiles are configured; run `oraclemcp setup --discover` to auto-discover profiles from tnsnames.ora (the zero-config fast path), or `oraclemcp --json setup --write --profile db_ro` then export ORACLE_APP_PASSWORD for the generated credential_ref and rerun `oraclemcp --json doctor --profile db_ro`"
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
                    configuration_error: Some(doctor_configuration_error(e)),
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
            Err(e) => doctor_resolution_error_context(e),
        };
    };

    match resolve_profile_options(Some(profile)) {
        Ok(Some(resolved)) => doctor_open_resolved_profile(resolved),
        Ok(None) => DoctorProfileContext {
            conn: None,
            stateless_conn: None,
            stateless_pool_configured: false,
            configuration_error: None,
            connection_error: Some(format!("connection profile `{profile}` not found")),
            wallet_location: None,
            protected_profile_writable: false,
            connection_strategy: None,
            call_timeout_resolved: false,
            call_timeout: None,
            connect_timeout_seconds: None,
            inactivity_timeout_seconds: None,
            keepalive_minutes: None,
            proxy_user: false,
            profile_caps: None,
            auth_capabilities: None,
            sensitive_values: Vec::new(),
            credential_env_hint: None,
            iam_token: None,
            wallet_password: None,
        },
        Err(e) => doctor_resolution_error_context(e),
    }
}

fn doctor_audit_path_configured() -> bool {
    OracleMcpConfig::load(None)
        .map(|config| config.audit.path.is_some())
        .unwrap_or(false)
}

/// Default location of the unsigned refusal/security-event trail. It is kept
/// separate from `audit.jsonl` because it has neither signatures nor an anchor.
fn default_unsigned_refusal_trail_path() -> PathBuf {
    if let Ok(state_dir) = FileStore::default_state_dir() {
        return state_dir.join("corpus").join("refusals.jsonl");
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".local/state/oraclemcp/corpus/refusals.jsonl"))
        .unwrap_or_else(|| PathBuf::from("oraclemcp-refusal-corpus.jsonl"))
}

/// The unsigned trail is a floor for keyless read-only serving, never a second
/// audit tier alongside the signed hash chain.
const fn unsigned_refusal_trail_enabled(
    signed_audit_active: bool,
    configured_enabled: bool,
) -> bool {
    !signed_audit_active && configured_enabled
}

/// Derive the same no-key/reachable-write decision that startup uses without
/// resolving an audit secret or opening the audit file. Offline doctor must not
/// turn a diagnostic into a secret read or a filesystem mutation.
fn doctor_audit_posture(profile: Option<&str>) -> DoctorAuditPosture {
    let config = match OracleMcpConfig::load(None) {
        Ok(config) => config,
        Err(_) => {
            return DoctorAuditPosture::Unavailable {
                reason: "configuration could not be loaded".to_owned(),
            };
        }
    };
    let active_level = match selected_config_profile(&config, profile) {
        Ok(Some(profile)) => oraclemcp_core::session_level_state(profile, false),
        Ok(None) => default_read_only_level(),
        Err(_) => {
            return DoctorAuditPosture::Unavailable {
                reason: "the selected profile could not be resolved".to_owned(),
            };
        }
    };
    let signing_key_configured = config.audit.key_ref.is_some()
        || std::env::var_os(AUDIT_KEY_ENV).is_some_and(|value| !value.is_empty());
    doctor_audit_posture_from_config(&config, &active_level, signing_key_configured)
}

/// Pure audit posture decision used by doctor and unit tests.
fn doctor_audit_posture_from_config(
    config: &OracleMcpConfig,
    active_level: &SessionLevelState,
    signing_key_configured: bool,
) -> DoctorAuditPosture {
    let reachable_ceiling = max_reachable_write_ceiling(config, active_level);
    if signing_key_configured {
        return DoctorAuditPosture::SigningKeyConfigured {
            path: config.audit.path.clone().unwrap_or_else(default_audit_path),
        };
    }
    if reachable_ceiling > OperatingLevel::ReadOnly {
        return DoctorAuditPosture::StartupRefused { reachable_ceiling };
    }
    DoctorAuditPosture::DisabledReadOnly {
        unsigned_refusal_trail_path: config
            .audit
            .unsigned_refusal_log
            .then(default_unsigned_refusal_trail_path),
    }
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
    let inactivity_timeout_seconds = resolved.inactivity_timeout_seconds;
    let keepalive_minutes = resolved.keepalive_minutes;
    let pool_configured = resolved.pool_settings.is_some();
    let configured_connection_strategy = Some(
        if pool_configured {
            "pinned_plus_stateless_configured"
        } else {
            "single_session"
        }
        .to_owned(),
    );
    let profile_caps = Some(resolved.doctor_caps.clone());
    let auth_capabilities = Some(DoctorAuthCapabilities::from_connect_options(&resolved.opts));
    // Capture the resolved IAM token BEFORE `resolved` is moved into the connect
    // attempt, so the near-expiry diagnostic works even when the connect fails.
    let iam_token = resolved.opts.iam_token.clone();
    let wallet_password = resolved.opts.wallet_password.clone();
    match block_on_connect(|cx| async move { try_open_runtime_connections(&cx, resolved).await }) {
        Ok(connections) => {
            let connection_strategy =
                Some(runtime_connection_strategy(pool_configured, &connections).to_owned());
            DoctorProfileContext {
                conn: Some(connections.session),
                stateless_conn: connections.stateless,
                stateless_pool_configured: pool_configured,
                configuration_error: None,
                connection_error: None,
                wallet_location,
                protected_profile_writable,
                connection_strategy,
                call_timeout_resolved: true,
                call_timeout,
                connect_timeout_seconds,
                inactivity_timeout_seconds,
                keepalive_minutes,
                proxy_user,
                profile_caps,
                auth_capabilities,
                sensitive_values,
                // Online: a live connection is attempted; the offline credential
                // hint does not apply.
                credential_env_hint: None,
                iam_token,
                wallet_password,
            }
        }
        Err(e) => DoctorProfileContext {
            conn: None,
            stateless_conn: None,
            stateless_pool_configured: pool_configured,
            configuration_error: None,
            connection_error: Some(doctor_connection_error(e)),
            wallet_location,
            protected_profile_writable,
            connection_strategy: configured_connection_strategy,
            call_timeout_resolved: true,
            call_timeout,
            connect_timeout_seconds,
            inactivity_timeout_seconds,
            keepalive_minutes,
            proxy_user,
            profile_caps,
            auth_capabilities,
            sensitive_values,
            credential_env_hint: None,
            iam_token,
            wallet_password,
        },
    }
}

fn run_doctor_cmd(robot_json: bool, profile: Option<String>, online: bool, fix: bool) -> ExitCode {
    // Offline by default: profile metadata inspection does not resolve secrets
    // or open Oracle. --online is the explicit live-connect boundary.
    let audit_posture = doctor_audit_posture(profile.as_deref());
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
        stateless_conn: profile_ctx.stateless_conn.as_deref(),
        stateless_pool_configured: profile_ctx.stateless_pool_configured,
        configuration_error: profile_ctx.configuration_error,
        connection_error: profile_ctx.connection_error,
        tns_admin: std::env::var("TNS_ADMIN").ok(),
        wallet_location: profile_ctx.wallet_location,
        // Offline-by-default invariant: profile metadata inspection never
        // resolves a secret. Online mode carries only the already-resolved
        // wallet password into the transient posture probe.
        wallet_password: if online {
            profile_ctx.wallet_password
        } else {
            None
        },
        // Transient: only the JWT `exp` is read for the near-expiry diagnostic;
        // the token value is never rendered or serialized.
        iam_token: profile_ctx.iam_token,
        protected_profile_writable: profile_ctx.protected_profile_writable,
        connection_strategy: profile_ctx.connection_strategy,
        call_timeout_resolved: profile_ctx.call_timeout_resolved,
        call_timeout: profile_ctx.call_timeout,
        connect_timeout_seconds: profile_ctx.connect_timeout_seconds,
        inactivity_timeout_seconds: profile_ctx.inactivity_timeout_seconds,
        keepalive_minutes: profile_ctx.keepalive_minutes,
        // B5: honest trio-stack provenance — whether the optional
        // plsql-intelligence engine is compiled into this server build.
        plsql_intelligence_detected: cfg!(feature = "plsql-intelligence"),
        proxy_user: profile_ctx.proxy_user,
        online,
        profile_caps: profile_ctx.profile_caps,
        auth_capabilities: profile_ctx.auth_capabilities,
        service_health: service_app_doctor_snapshot().ok(),
        service_unit_caps: service_lifecycle::doctor_service_unit_caps(),
        state_layout,
        audit_posture: Some(audit_posture),
        sensitive_values: profile_ctx.sensitive_values,
        credential_env_hint: profile_ctx.credential_env_hint,
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
#[path = "main_tests.rs"]
mod tests;
