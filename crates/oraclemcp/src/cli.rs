//! CLI surface for the `oraclemcp` binary: the `clap` derive types that define
//! every flag, subcommand, argument, and help string.
//!
//! Extracted isomorphically from `main.rs` (C6 de-monolith, bead
//! `oraclemcp-eng-program-bp8ia.4.6.5`): the command surface is byte-for-byte
//! unchanged — no flag, subcommand, help text, or exit code moved. `main.rs`
//! re-exports these types at the crate root via `pub(crate) use cli::*;`, so
//! every existing reference (including `main_tests.rs`, which reaches the crate
//! root through `use super::*`) resolves exactly as before. Items are
//! `pub(crate)` because `main_tests.rs` constructs the arg structs and reads
//! their fields; visibility is the only change, never behaviour.

use super::DEFAULT_SETUP_CONFIG_PATH;
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

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
pub(crate) struct Cli {
    /// Emit a single JSON object on stdout instead of human text.
    #[arg(long, visible_alias = "json", global = true)]
    pub(crate) robot_json: bool,

    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand, Debug)]
pub(crate) enum Command {
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
        /// Refuse startup when any custom-tool definition is invalid instead of
        /// skipping configuration-quality failures with a warning.
        #[arg(long)]
        strict_custom_tools: bool,
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
        /// Local-only doctor diagnostics.
        #[command(subcommand)]
        command: Option<DoctorCommand>,
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

/// Local-only `doctor` diagnostics. These are never part of an MCP or HTTP
/// request path.
#[derive(Subcommand, Debug)]
pub(crate) enum DoctorCommand {
    /// Validate one supplied OAuth token against the local resource-server config.
    Oauth {
        /// JWT to diagnose. It is never logged, persisted, or rendered.
        #[arg(long, value_name = "JWT")]
        token: String,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum AuditCommand {
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
pub(crate) enum IncidentCommand {
    /// Capture one stdin-supplied statement into a new redacted bundle directory.
    Capture(IncidentCaptureCliArgs),
    /// Re-classify a verified bundle under its recorded LabRuntime seed.
    Replay(IncidentReplayCliArgs),
}

#[derive(Subcommand, Debug)]
pub(crate) enum RefusalCorpusCommand {
    /// Export the corpus as deterministic, deduplicated, re-validated JSONL.
    Export(RefusalCorpusExportCliArgs),
}

#[derive(Args, Debug)]
pub(crate) struct RefusalCorpusExportCliArgs {
    /// Destination file for the exported dataset. It must differ from the source
    /// corpus path; a malformed or tampered corpus aborts the export instead of
    /// shipping a best-effort dataset.
    #[arg(long)]
    pub(crate) out: PathBuf,
    /// Source corpus state file to export. Defaults to the served corpus the
    /// dispatcher appends to ($XDG_STATE_HOME/oraclemcp/corpus/refusals.jsonl).
    #[arg(long)]
    pub(crate) corpus: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(crate) struct IncidentCaptureCliArgs {
    /// New directory for the redacted incident bundle. It must not already exist.
    pub(crate) bundle: PathBuf,
    /// Deterministic LabRuntime seed recorded for a future replay.
    #[arg(long)]
    pub(crate) seed: u64,
}

#[derive(Args, Debug)]
pub(crate) struct IncidentReplayCliArgs {
    /// Existing self-verifying incident bundle directory.
    pub(crate) bundle: PathBuf,
}

#[derive(Subcommand, Debug)]
pub(crate) enum ServiceCliCommand {
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
pub(crate) enum ClientCredentialCliCommand {
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
pub(crate) struct ClientCredentialIssueCliArgs {
    /// Human label for this MCP client.
    #[arg(long)]
    pub(crate) label: String,
    /// Granted scope. Repeat for multiple scopes.
    #[arg(long = "scope", default_value = "oracle:read")]
    pub(crate) scopes: Vec<String>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ClientCredentialIdCliArgs {
    /// Client id returned by `oraclemcp clients issue`.
    pub(crate) client_id: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ServiceInstallCliArgs {
    /// Service name / label. Keep this stable; it determines the unit/plist/service id.
    #[arg(long, default_value = "oraclemcp")]
    pub(crate) name: String,
    /// Local HTTP listener for the service's `serve --listen` command.
    #[arg(long, default_value = "127.0.0.1:7070")]
    pub(crate) listen: String,
    /// Connect using this named profile from the loaded config.
    #[arg(long)]
    pub(crate) profile: Option<String>,
    /// Permit HTTP without configured auth (local development only). A
    /// non-loopback bind still needs explicit remote opt-in.
    #[arg(long)]
    pub(crate) allow_no_auth: bool,
    /// Enable service-owned per-client bearer credentials for HTTP.
    #[arg(long)]
    pub(crate) client_credentials: bool,
    /// Do not run the optional Linux `loginctl enable-linger <user>` step.
    #[arg(long)]
    pub(crate) skip_linger: bool,
    /// Execute the service-manager changes. Omit and use --dry-run to inspect safely.
    #[arg(long)]
    pub(crate) yes: bool,
    /// Print the service-manager plan without writing files or running commands.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

#[derive(Args, Debug)]
pub(crate) struct SelfUpdateCliArgs {
    /// Release version to install, e.g. 0.6.6 or v0.6.6.
    #[arg(long, default_value = "latest")]
    pub(crate) version: String,
    /// Verification posture forwarded to the platform installer.
    #[arg(long)]
    pub(crate) verify: Option<String>,
    /// Forward consent to the platform installer.
    #[arg(long)]
    pub(crate) yes: bool,
    /// Forward no-service to the platform installer.
    #[arg(long)]
    pub(crate) no_service: bool,
    /// Print the installer command without executing it.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ServiceMutationCliArgs {
    /// Service name / label.
    #[arg(long, default_value = "oraclemcp")]
    pub(crate) name: String,
    /// Execute the service-manager changes. Omit and use --dry-run to inspect safely.
    #[arg(long)]
    pub(crate) yes: bool,
    /// Print the service-manager plan without writing files or running commands.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ServiceReadCliArgs {
    /// Service name / label.
    #[arg(long, default_value = "oraclemcp")]
    pub(crate) name: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ServiceLogsCliArgs {
    /// Service name / label.
    #[arg(long, default_value = "oraclemcp")]
    pub(crate) name: String,
    /// Number of recent log lines/events to request.
    #[arg(long, default_value_t = 100)]
    pub(crate) lines: u16,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ServiceBackupCliArgs {
    /// Service name / label.
    #[arg(long, default_value = "oraclemcp")]
    pub(crate) name: String,
    /// New directory to create for the backup. Defaults outside the XDG state root.
    #[arg(long)]
    pub(crate) output: Option<PathBuf>,
    /// Execute the local backup write. Omit and use --dry-run to inspect safely.
    #[arg(long)]
    pub(crate) yes: bool,
    /// Print the backup plan without writing files.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ServiceRestoreCliArgs {
    /// Backup directory produced by `oraclemcp service backup`.
    pub(crate) backup: PathBuf,
    /// Service name / label.
    #[arg(long, default_value = "oraclemcp")]
    pub(crate) name: String,
    /// Override the active id for a legacy env-only audit key.
    #[arg(long, visible_alias = "key_id")]
    pub(crate) key_id: Option<String>,
    /// Execute the stop, restore, and start sequence. Omit and use --dry-run first.
    #[arg(long)]
    pub(crate) yes: bool,
    /// Verify the backup and print the restore plan without writing files.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

#[derive(Args, Debug, Default)]
pub(crate) struct HttpServeArgs {
    /// Allow this Host authority in addition to loopback authorities.
    #[arg(long = "http-allowed-host")]
    pub(crate) allowed_hosts: Vec<String>,
    /// Allow this browser Origin in addition to loopback origins.
    #[arg(long = "http-allowed-origin")]
    pub(crate) allowed_origins: Vec<String>,
    /// Use Streamable HTTP stateful session framing.
    #[arg(long = "http-stateful")]
    pub(crate) stateful: bool,
    /// Prefer direct JSON responses for stateless requests.
    #[arg(long = "http-json-response")]
    pub(crate) json_response: bool,
    /// OAuth resource/audience identifier expected in JWT aud.
    #[arg(long = "oauth-resource")]
    pub(crate) oauth_resource: Option<String>,
    /// Allowed OAuth issuer. Repeat for multiple issuers.
    #[arg(long = "oauth-issuer")]
    pub(crate) oauth_issuers: Vec<String>,
    /// OAuth authorization server advertised in protected-resource metadata.
    #[arg(long = "oauth-authorization-server")]
    pub(crate) oauth_authorization_servers: Vec<String>,
    /// Required OAuth scope. Repeat for multiple required scopes.
    #[arg(long = "oauth-required-scope")]
    pub(crate) oauth_required_scopes: Vec<String>,
    /// Secret reference for the built-in HS256 verifier (at least 32 bytes),
    /// e.g. env:JWT_SECRET.
    #[arg(long = "oauth-hs256-secret-ref")]
    pub(crate) oauth_hs256_secret_ref: Option<String>,
    /// Metadata URL advertised in WWW-Authenticate.
    #[arg(long = "oauth-metadata-url")]
    pub(crate) oauth_metadata_url: Option<String>,
    /// Server certificate-chain PEM path for native rustls HTTPS.
    #[arg(long = "tls-cert")]
    pub(crate) tls_cert: Option<PathBuf>,
    /// Server private-key PEM path for native rustls HTTPS.
    #[arg(long = "tls-key")]
    pub(crate) tls_key: Option<PathBuf>,
    /// Client CA PEM path for native mTLS client-certificate verification.
    #[arg(long = "mtls-client-ca")]
    pub(crate) mtls_client_ca: Option<PathBuf>,
    /// Registered mTLS client leaf certificate SHA-256 fingerprint.
    #[arg(long = "mtls-client-fingerprint")]
    pub(crate) mtls_client_fingerprints: Vec<String>,
    /// Start a separately bounded mandatory-mTLS operator/readiness listener.
    /// Reuses --tls-*, --mtls-client-ca, and registered fingerprint material.
    #[arg(long = "control-listen")]
    pub(crate) control_listen: Option<String>,
    /// Accept service-owned per-client `ocmcp_*` bearer credentials.
    #[arg(long = "client-credentials")]
    pub(crate) client_credentials: bool,
}

#[derive(Subcommand, Debug)]
pub(crate) enum RobotDocsCommand {
    /// Print the compact agent guide.
    Guide,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    #[value(name = "powershell", alias = "pwsh", alias = "power-shell")]
    Powershell,
}
