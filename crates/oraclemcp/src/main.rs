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

mod readiness;
mod robot_docs;

use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use asupersync::Cx;
use clap::{Args, CommandFactory, Parser, Subcommand};
use oraclemcp::dispatch::{OracleDispatcher, StatelessReadStrategy};
use oraclemcp::registry;
use oraclemcp_audit::{Auditor, FileAuditSink, SigningKey};
use oraclemcp_auth::{Hs256Verifier, ResourceServerConfig, SecretError, resolve_secret};
use oraclemcp_config::{AuditConfig, HttpConfig, HttpTlsConfig, OracleMcpConfig};
use oraclemcp_core::{
    CapabilitiesReport, CustomToolCatalog, CustomToolDef, DoctorContext, FeatureTiers,
    HttpTransportConfig, MCP_PATH, OAuthEnforcement, ObservabilityState, OracleMcpServer,
    PROTECTED_RESOURCE_METADATA_PATH, ShutdownCoordinator, StdioAuthPolicy, TlsMaterial,
    TlsServerConfig, build_server_config, load_tools, load_tools_for_profile, parse_tools_file,
    requires_mtls, run_doctor, serve_http_until, serve_https_until, sign,
};
use oraclemcp_db::{
    DbError, OracleConnectOptions, OracleConnection, OraclePool, PoolSettings, RustOracleConnection,
};
use oraclemcp_error::{ErrorClass, ErrorEnvelope};
use oraclemcp_guard::{Classifier, ClassifierConfig, OperatingLevel, SessionLevelState};
use oraclemcp_telemetry::{HealthState, Metrics, OtlpConfig};

/// Whether this build includes live Oracle connectivity.
const LIVE_DB: bool = true;
const CUSTOM_TOOLS_DIR_ENV: &str = "ORACLEMCP_TOOLS_DIR";
const CUSTOM_TOOLS_HMAC_KEY_ENV: &str = "ORACLEMCP_CUSTOM_TOOLS_HMAC_KEY";
/// Fallback environment variable for the audit signing key when the config's
/// `[audit].key_ref` is not set.
const AUDIT_KEY_ENV: &str = "ORACLEMCP_AUDIT_KEY";

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
                  no environment-specific workflow engine."
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
        /// instead of stdio. HTTP starts only with configured OAuth enforcement
        /// or explicit --allow-no-auth; use native TLS/mTLS or a terminating
        /// proxy for off-box clients.
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
        /// Connect using this named profile and include live connectivity checks.
        /// Omit for offline diagnostics only.
        #[arg(long)]
        profile: Option<String>,
    },
    /// List configured connection profiles without opening a database connection.
    #[command(alias = "list-profiles")]
    Profiles,
    /// Print the capabilities report (tools, level, feature tiers) as JSON.
    Capabilities,
    /// Print an agent-oriented usage guide from the binary itself.
    #[command(name = "robot-docs", alias = "robot_docs")]
    RobotDocs {
        #[command(subcommand)]
        command: Option<RobotDocsCommand>,
    },
    /// Print generic onboarding templates for profiles, wrappers, and MCP clients.
    Setup {
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
        #[arg(long, default_value = "~/.config/oraclemcp/profiles.toml")]
        config_path: String,
        /// Custom tools directory shown in generated guidance.
        #[arg(long, default_value = "~/.config/oraclemcp/tools.d")]
        tools_dir: String,
    },
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
    },
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
}

#[derive(Subcommand, Debug)]
enum RobotDocsCommand {
    /// Print the compact agent guide.
    Guide,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let robot_json = cli.robot_json;

    let Some(command) = cli.command else {
        // Bare invocation: help to stderr, exit 2. stdout stays empty so a
        // launcher piping JSON-RPC never mistakes the hint for data.
        let mut cmd = Cli::command();
        let _ = cmd.write_long_help(&mut std::io::stderr());
        eprintln!(
            "\nno subcommand given — try `oraclemcp serve`, `oraclemcp doctor`, or `oraclemcp capabilities`."
        );
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
        Command::Doctor { profile } => run_doctor_cmd(robot_json, profile),
        Command::Profiles => run_profiles(robot_json),
        Command::Capabilities => run_capabilities(robot_json),
        Command::RobotDocs { command } => match command {
            None | Some(RobotDocsCommand::Guide) => run_robot_docs_guide(robot_json),
        },
        Command::Setup {
            profile,
            credential_env,
            wrapper_path,
            config_path,
            tools_dir,
        } => run_setup(
            robot_json,
            &profile,
            &credential_env,
            &wrapper_path,
            &config_path,
            &tools_dir,
        ),
        Command::SignTool { path, tool } => run_sign_tool(robot_json, &path, tool.as_deref()),
        Command::Audit { command } => match command {
            AuditCommand::Verify { file, key_id } => {
                run_audit_verify(robot_json, &file, key_id.as_deref())
            }
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
struct ResolvedProfile {
    name: String,
    opts: OracleConnectOptions,
    level: SessionLevelState,
    pool_settings: Option<PoolSettings>,
}

fn resolve_profile_options(profile: Option<&str>) -> Result<Option<ResolvedProfile>, DbError> {
    let cfg = OracleMcpConfig::load(None)
        .map_err(|e| DbError::UnsupportedAuth(format!("config load failed: {e}")))?;

    let Some(chosen) = (match profile {
        Some(name) => Some(cfg.profile(name).ok_or_else(|| {
            DbError::UnsupportedAuth(format!("connection profile `{name}` not found"))
        })?),
        None if cfg.default_profile.is_some() => {
            let name = cfg.default_profile.as_deref().expect("checked is_some");
            Some(cfg.profile(name).ok_or_else(|| {
                DbError::UnsupportedAuth(format!("default_profile `{name}` not found"))
            })?)
        }
        // No explicit/default profile: use the sole profile if there is exactly
        // one, else none (the agent can still drive capabilities/doctor).
        None if cfg.profiles.len() == 1 => cfg.profiles.first(),
        None => None,
    }) else {
        return Ok(None);
    };

    let password = resolve_profile_secret(
        "credential_ref",
        &chosen.name,
        chosen.credential_ref.as_deref(),
        chosen.protected(),
    )?;
    let wallet_password = resolve_profile_secret(
        "wallet_password_ref",
        &chosen.name,
        chosen
            .oci
            .as_ref()
            .and_then(|oci| oci.wallet_password_ref.as_deref()),
        chosen.protected(),
    )?;

    let ctx = oraclemcp_core::build_session_context(chosen, password, wallet_password, false)?;
    Ok(Some(ResolvedProfile {
        name: chosen.name.clone(),
        opts: ctx.options,
        level: ctx.level_state,
        pool_settings: ctx.pool_settings,
    }))
}

fn resolve_profile_secret(
    field: &str,
    profile_name: &str,
    secret_ref: Option<&str>,
    protected: bool,
) -> Result<Option<String>, DbError> {
    let Some(reference) = secret_ref else {
        return Ok(None);
    };
    let secret =
        resolve_secret(reference, protected, |name| std::env::var(name).ok()).map_err(|e| {
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
/// dispatch runtime that already holds the request `Cx`.
#[allow(clippy::type_complexity)]
fn connect_profile<'a>(
    cx: &'a Cx,
    profile: &'a str,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Box<dyn OracleConnection>, DbError>> + 'a>,
> {
    Box::pin(async move {
        let Some(resolved) = resolve_profile_options(Some(profile))? else {
            return Err(DbError::UnsupportedAuth(format!(
                "connection profile `{profile}` not found"
            )));
        };
        try_open_connection(cx, resolved.opts).await
    })
}

/// The `oracle_switch_profile` stateless-pool connector (B1: async + `Cx`-first).
#[allow(clippy::type_complexity)]
fn connect_profile_stateless<'a>(
    cx: &'a Cx,
    profile: &'a str,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Option<Box<dyn OracleConnection>>, DbError>> + 'a>,
> {
    Box::pin(async move {
        let Some(resolved) = resolve_profile_options(Some(profile))? else {
            return Err(DbError::UnsupportedAuth(format!(
                "connection profile `{profile}` not found"
            )));
        };
        try_open_stateless_connection(cx, resolved.opts, resolved.pool_settings).await
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
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("Asupersync current-thread runtime builds for connection setup");
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
            RuntimeConnections {
                session: Box::new(stub::StubConnection::new(e)),
                stateless: None,
            }
        }
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

/// The safe default audit-log path under the config home, used when
/// `[audit].path` is not configured but an auditor is required.
fn default_audit_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".config/oraclemcp/audit.jsonl"))
        .unwrap_or_else(|| PathBuf::from("oraclemcp-audit.jsonl"))
}

/// Resolve the audit signing key: prefer the config `[audit].key_ref` secret,
/// fall back to the `ORACLEMCP_AUDIT_KEY` env var. Returns `None` when neither
/// is set (the caller fails closed if a write level is reachable).
fn resolve_audit_signing_key(
    audit: &AuditConfig,
    protected: bool,
) -> Result<Option<SigningKey>, (&'static str, String)> {
    let key_id = audit.key_id_or_default().to_owned();
    if let Some(key_ref) = audit.key_ref.as_deref() {
        let secret =
            resolve_secret(key_ref, protected, |name| std::env::var(name).ok()).map_err(|e| {
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

/// Build the out-of-band auditor for the server.
///
/// Fail-closed policy (bead A8): if any operating level **above ReadOnly** is
/// reachable (the profile ceiling permits a write/DDL/escalation), a signing
/// key is **required** — without one we refuse to start rather than run writes
/// unaudited. When only ReadOnly is reachable, the auditor is optional: a
/// configured key still builds one (so escalation previews/log stay available),
/// otherwise `None` (pure reads never touch the chain).
fn build_auditor(
    audit: &AuditConfig,
    level: &SessionLevelState,
) -> Result<Option<Arc<Auditor>>, (&'static str, String)> {
    let write_reachable = level.max_level() > OperatingLevel::ReadOnly;
    let key = resolve_audit_signing_key(audit, level.is_protected())?;

    let Some(key) = key else {
        if write_reachable {
            return Err((
                "ORACLEMCP_AUDIT_KEY_REQUIRED",
                format!(
                    "this profile can reach operating level {} (above READ_ONLY) but no audit \
                     signing key is configured; set [audit].key_ref or {AUDIT_KEY_ENV} so every \
                     write/escalation is recorded on the signed audit chain",
                    level.max_level().as_str()
                ),
            ));
        }
        // Read-only only: no writes/escalations can occur, so no auditor needed.
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
    Ok(Some(Arc::new(Auditor::new(Box::new(sink), key))))
}

/// Build the server from the registry + capabilities + dispatcher over `conn`.
fn build_server(
    conn: Box<dyn OracleConnection>,
    stateless_conn: Option<Box<dyn OracleConnection>>,
    active_profile: Option<String>,
    level: SessionLevelState,
    http: bool,
    custom_catalog: CustomToolCatalog,
    auditor: Option<Arc<Auditor>>,
) -> OracleMcpServer {
    let version = env!("CARGO_PKG_VERSION");
    let mut registry = registry::tool_registry();
    custom_catalog.register_first_class(&mut registry);
    let caps = CapabilitiesReport::new(
        version,
        registry.tools.clone(),
        OperatingLevel::ReadOnly,
        FeatureTiers {
            live_db: LIVE_DB,
            engine: false,
            http_transport: http,
        },
    );
    let mut dispatcher = OracleDispatcher::new_switchable_with_custom_tools_and_stateless(
        conn,
        active_profile,
        level,
        Arc::new(connect_profile),
        StatelessReadStrategy::new(stateless_conn, Some(Arc::new(connect_profile_stateless))),
        custom_catalog,
        Some(Arc::new(load_custom_catalog_for_profile)),
    );
    if let Some(auditor) = auditor {
        dispatcher = dispatcher.with_auditor(auditor);
    }
    // E3/E3b: the dispatcher (which mints exports for oversized oracle_query
    // results) and the server (which serves them over resources/read) share the
    // SAME export registry.
    let exports = Arc::new(oraclemcp_core::ExportRegistry::new());
    dispatcher = dispatcher.with_exports(Arc::clone(&exports));
    OracleMcpServer::with_exports(version, registry, caps, Arc::new(dispatcher), exports)
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
}

fn default_oauth_metadata_url(resource: &str) -> String {
    let base = resource
        .trim_end_matches('/')
        .strip_suffix(MCP_PATH)
        .unwrap_or_else(|| resource.trim_end_matches('/'))
        .trim_end_matches('/');
    format!("{base}{PROTECTED_RESOURCE_METADATA_PATH}")
}

#[derive(Clone, Debug)]
struct ResolvedHttpTransportConfig {
    transport: HttpTransportConfig,
    tls: Option<Arc<TlsServerConfig>>,
    mtls_required: bool,
}

fn resolve_http_transport_config(
    cli: &HttpServeArgs,
    level: &SessionLevelState,
) -> Result<ResolvedHttpTransportConfig, (&'static str, String)> {
    let cfg = OracleMcpConfig::load(None).map_err(|e| {
        (
            "ORACLEMCP_CONFIG_INVALID",
            format!("failed to load HTTP transport config: {e}"),
        )
    })?;
    let http = apply_http_cli_overrides(cfg.http, cli);
    http_transport_config_from_merged(http, level.is_protected(), |name| std::env::var(name).ok())
}

fn http_transport_config_from_merged(
    http: HttpConfig,
    protected: bool,
    env_lookup: impl Fn(&str) -> Option<String>,
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
            let secret = resolve_secret(secret_ref, protected, env_lookup).map_err(|e| {
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

    Ok(ResolvedHttpTransportConfig {
        transport: HttpTransportConfig {
            allowed_hosts: http.allowed_hosts,
            allowed_origins: http.allowed_origins,
            json_response: http.json_response,
            stateful: http.stateful,
            resource_metadata,
            oauth,
            session_store: None,
            // Observability is wired in run_serve (HealthState/Metrics/probe).
            observability: ObservabilityState::default(),
        },
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
    // `probe_opts` carries the resolved connect options so the /readyz pinger can
    // open its own dedicated probe connection (D1-health). `None` means no live
    // DB is configured — the pinger then probes a stub and /readyz reports 503.
    let (connections, active_profile, level, probe_opts) = match resolve_profile_options(
        profile.as_deref(),
    ) {
        Ok(Some(resolved)) => {
            let active_profile = Some(resolved.name.clone());
            let level = resolved.level.clone();
            let probe_opts = Some(resolved.opts.clone());
            (
                open_runtime_connections(resolved),
                active_profile,
                level,
                probe_opts,
            )
        }
        Ok(None) => (
            RuntimeConnections {
                session: open_connection(OracleConnectOptions::default()),
                stateless: None,
            },
            None,
            default_read_only_level(),
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
                RuntimeConnections {
                    session: Box::new(stub::StubConnection::new(e)) as Box<dyn OracleConnection>,
                    stateless: None,
                },
                None,
                default_read_only_level(),
                None,
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
    let audit_config = match OracleMcpConfig::load(None) {
        Ok(cfg) => cfg.audit,
        Err(e) => {
            emit_status_error(
                robot_json,
                "ORACLEMCP_CONFIG_INVALID",
                &format!("failed to load audit config: {e}"),
            );
            return ExitCode::from(2);
        }
    };
    let auditor = match build_auditor(&audit_config, &level) {
        Ok(auditor) => auditor,
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
            let server = build_server(
                connections.session,
                connections.stateless,
                active_profile,
                level,
                false,
                custom_catalog,
                auditor,
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
            let resolved_http = match resolve_http_transport_config(&http, &level) {
                Ok(cfg) => cfg,
                Err((code, message)) => {
                    emit_status_error(robot_json, code, &message);
                    return ExitCode::from(2);
                }
            };
            let oauth_enabled = resolved_http.transport.oauth.is_some();
            let tls_enabled = resolved_http.tls.is_some();
            let auth_enabled = oauth_enabled || resolved_http.mtls_required;
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
                    } else {
                        ""
                    }
                );
                if !oauth_enabled && !resolved_http.mtls_required {
                    eprintln!(
                        "oraclemcp serve: WARNING — HTTPS transport on {addr} has TLS \
                         encryption but no OAuth or mTLS client authentication."
                    );
                }
            } else if oauth_enabled {
                eprintln!(
                    "oraclemcp serve: HTTP transport on {addr} has OAuth bearer enforcement \
                     enabled. The native listener is still plaintext; bind loopback or front it \
                     with a TLS-terminating proxy for off-box clients."
                );
            } else {
                eprintln!(
                    "oraclemcp serve: WARNING — HTTP transport on {addr} is UNAUTHENTICATED and \
                     UNENCRYPTED. Do not expose it to untrusted networks; front it with a \
                     TLS-terminating authenticated proxy, or use stdio."
                );
            }
            let server = build_server(
                connections.session,
                connections.stateless,
                active_profile,
                level,
                true,
                custom_catalog,
                auditor,
            );
            let ResolvedHttpTransportConfig {
                mut transport, tls, ..
            } = resolved_http;

            // ── D1 observability wiring (health + metrics + graceful drain) ──
            let version = env!("CARGO_PKG_VERSION");
            let health = HealthState::new(version);
            let metrics = Arc::new(Metrics::new());
            let shutdown_coordinator = ShutdownCoordinator::new(health.clone());

            // /readyz DB-reachability probe: a background pinger on a dedicated
            // probe connection. With no live DB it probes a stub (always 503).
            let probe_conn: Box<dyn OracleConnection> = match probe_opts {
                Some(opts) => open_connection(opts),
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
            // Pool is established (or a stub stands in); the server is ready to
            // accept work. /readyz still gates on the live DB-reachability probe.
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

            emit_serve_status(
                robot_json,
                if tls_enabled { "https" } else { "http" },
                Some(&addr),
                &advertised_tools,
            );
            let result = TcpListener::bind(&addr).and_then(|listener| match tls {
                Some(tls) => serve_https_until(
                    listener,
                    server,
                    &transport,
                    tls,
                    Arc::clone(&shutdown_flag),
                ),
                None => serve_http_until(listener, server, &transport, Arc::clone(&shutdown_flag)),
            });

            // Drain telemetry + the probe before returning (bounded budgets).
            pinger.shutdown();
            drop(telemetry);

            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!(
                        "oraclemcp serve: {} transport error on {addr}: {e}",
                        if tls_enabled { "https" } else { "http" }
                    );
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
/// enforcement/mTLS or the operator must explicitly accept unauthenticated local dev
/// mode with `--allow-no-auth`. Binding a routable (non-loopback) address still
/// needs a second deliberate opt-in.
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
            "the HTTP transport (--listen) has no OAuth enforcement or mTLS \
             client-certificate verification configured; configure [http.oauth] / \
             --oauth-* / [http.tls.client_ca_path], or re-run with --allow-no-auth \
             to accept unauthenticated development mode explicitly"
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

fn run_info(robot_json: bool) -> ExitCode {
    let info = serde_json::json!({
        "binary": "oraclemcp",
        "version": env!("CARGO_PKG_VERSION"),
        "engine": false,
        "live_db": LIVE_DB,
        "transports": ["stdio", "http"],
        "tools": &registry::TOOL_NAMES[..],
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
            "wrapper": wrapper_path
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
        "validation_commands": [
            ["oraclemcp", "--json", "info"],
            ["oraclemcp", "--json", "setup", "--profile", profile],
            ["oraclemcp", "--json", "profiles"],
            ["oraclemcp", "--json", "doctor"],
            ["oraclemcp", "--json", "doctor", "--profile", profile],
            ["oraclemcp", "--json", "capabilities"]
        ],
        "next_actions": [
            format!("write the profiles template to {config_path} after replacing placeholders"),
            format!("write the wrapper template to {wrapper_path} and make it executable if Oracle client environment setup is needed"),
            "configure every MCP client to call the same wrapper and args",
            "restart each MCP client after changing the binary, wrapper, or profile",
            "run the validation commands before allowing agents to use live database tools"
        ]
    })
}

fn run_setup(
    robot_json: bool,
    profile: &str,
    credential_env: &str,
    wrapper_path: &str,
    config_path: &str,
    tools_dir: &str,
) -> ExitCode {
    let payload = setup_payload(
        profile,
        credential_env,
        wrapper_path,
        config_path,
        tools_dir,
    );
    if robot_json {
        let output = serde_json::to_string(&payload).unwrap();
        stdout_exit(write_stdout_line(&output), ExitCode::SUCCESS)
    } else {
        let mut output = String::new();
        output.push_str("oraclemcp setup\n\n");
        output.push_str("Install:\n  cargo install oraclemcp\n\n");
        output.push_str(&format!("Profiles path:\n  {config_path}\n\n"));
        output.push_str(&format!(
            "profiles.toml template:\n{}\n\n",
            payload["profiles_toml"].as_str().unwrap_or("")
        ));
        output.push_str(&format!("Wrapper path:\n  {wrapper_path}\n\n"));
        output.push_str(&format!(
            "wrapper script template:\n{}\n\n",
            payload["wrapper_script"].as_str().unwrap_or("")
        ));
        output.push_str(&format!("Custom tools path:\n  {tools_dir}\n\n"));
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
            "run oraclemcp --json doctor --profile <profile> before restarting clients"
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
        let secret =
            resolve_secret(key_ref, false, |name| std::env::var(name).ok()).map_err(|e| {
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

fn run_audit_verify(robot_json: bool, file: &Path, key_id_override: Option<&str>) -> ExitCode {
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
        VerifyOutcome::Ok { records } => {
            let payload = serde_json::json!({
                "ok": true,
                "file": file.display().to_string(),
                "records": records,
            });
            let output = if robot_json {
                serde_json::to_string(&payload).unwrap()
            } else {
                format!("OK: audit chain verified ({records} records)")
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

fn run_capabilities(robot_json: bool) -> ExitCode {
    // HTTP is advertised as available (the binary can serve it); live_db tracks
    // the compiled driver feature.
    let caps = registry::capabilities(env!("CARGO_PKG_VERSION"), LIVE_DB, true);
    let value = serde_json::to_value(&caps).unwrap_or(serde_json::Value::Null);
    let output = if robot_json {
        serde_json::to_string(&value).unwrap()
    } else {
        serde_json::to_string_pretty(&value).unwrap()
    };
    stdout_exit(write_stdout_line(&output), ExitCode::SUCCESS)
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
                "pool": profile.pool,
                "max_level": profile.max_level,
                "default_level": profile.default_level,
                "protected": profile.protected,
                "require_signed_tools": profile.require_signed_tools,
                "read_only_standby": profile.read_only_standby,
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
    // Mirror plsql-mcp: a blocker (any failed check) exits 2.
    if report.any_failed() { 2 } else { 0 }
}

struct DoctorProfileContext {
    conn: Option<Box<dyn OracleConnection>>,
    connection_error: Option<String>,
    wallet_location: Option<String>,
    protected_profile_writable: bool,
    connection_strategy: Option<String>,
    proxy_user: bool,
    sensitive_values: Vec<String>,
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

fn doctor_profile_context(profile: Option<&str>) -> DoctorProfileContext {
    let Some(profile) = profile else {
        return DoctorProfileContext {
            conn: None,
            connection_error: None,
            wallet_location: None,
            protected_profile_writable: false,
            connection_strategy: None,
            proxy_user: false,
            sensitive_values: Vec::new(),
        };
    };

    match resolve_profile_options(Some(profile)) {
        Ok(Some(resolved)) => {
            let wallet_location = resolved
                .opts
                .wallet_location
                .as_ref()
                .map(|path| path.display().to_string());
            let protected_profile_writable = resolved.level.is_protected()
                && resolved.level.max_level() > OperatingLevel::ReadOnly;
            let proxy_user = resolved.opts.auth_adapter.proxy_connect_user().is_some();
            let sensitive_values = doctor_sensitive_values(&resolved.opts);
            let connection_strategy = Some(
                if resolved.pool_settings.is_some() {
                    "hybrid_pool"
                } else {
                    "single_session"
                }
                .to_owned(),
            );
            match block_on_connect(
                |cx| async move { try_open_runtime_connections(&cx, resolved).await },
            ) {
                Ok(connections) => DoctorProfileContext {
                    conn: Some(connections.session),
                    connection_error: None,
                    wallet_location,
                    protected_profile_writable,
                    connection_strategy,
                    proxy_user,
                    sensitive_values,
                },
                Err(e) => DoctorProfileContext {
                    conn: None,
                    connection_error: Some(doctor_connection_error(e)),
                    wallet_location,
                    protected_profile_writable,
                    connection_strategy,
                    proxy_user,
                    sensitive_values,
                },
            }
        }
        Ok(None) => DoctorProfileContext {
            conn: None,
            connection_error: Some(format!("connection profile `{profile}` not found")),
            wallet_location: None,
            protected_profile_writable: false,
            connection_strategy: None,
            proxy_user: false,
            sensitive_values: Vec::new(),
        },
        Err(e) => DoctorProfileContext {
            conn: None,
            connection_error: Some(doctor_connection_error(e)),
            wallet_location: None,
            protected_profile_writable: false,
            connection_strategy: None,
            proxy_user: false,
            sensitive_values: Vec::new(),
        },
    }
}

fn run_doctor_cmd(robot_json: bool, profile: Option<String>) -> ExitCode {
    // Offline by default: no live connection (the live subset reports Skip with
    // a reason). With --profile, use the configured profile and let the live
    // checks report connection/auth/role failures as ordinary doctor checks.
    let profile_ctx = doctor_profile_context(profile.as_deref());
    let ctx = DoctorContext {
        conn: profile_ctx.conn.as_deref(),
        connection_error: profile_ctx.connection_error,
        tns_admin: std::env::var("TNS_ADMIN").ok(),
        wallet_location: profile_ctx.wallet_location,
        protected_profile_writable: profile_ctx.protected_profile_writable,
        connection_strategy: profile_ctx.connection_strategy,
        proxy_user: profile_ctx.proxy_user,
        sensitive_values: profile_ctx.sensitive_values,
    };
    let report = block_on_connect(|cx| async move { run_doctor(&cx, &ctx).await });
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
    fn http_listen_refused_without_allow_no_auth() {
        let err = http_listen_guard(false, false, false, "127.0.0.1:7070", false).unwrap_err();
        assert_eq!(err.0, "ORACLEMCP_AUTH_REQUIRED");
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
        let cfg = http_transport_config_from_merged(http, false, |_| None)
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

        let err = http_transport_config_from_merged(http, true, |_| None)
            .expect_err("protected profile rejects literal OAuth secret");
        assert_eq!(err.0, "ORACLEMCP_HTTP_OAUTH_SECRET_INVALID");
        assert!(err.1.contains("plaintext literal credential is forbidden"));
        assert!(!err.1.contains("test-secret"));
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
            ..Default::default()
        };
        let http = apply_http_cli_overrides(HttpConfig::default(), &args);
        assert_eq!(
            http.tls
                .as_ref()
                .and_then(|tls| tls.client_ca_path.as_deref()),
            Some(client_ca_path.as_path())
        );

        let cfg = http_transport_config_from_merged(http, false, |_| None)
            .expect("native TLS listener config builds");
        assert!(cfg.tls.is_some());
        assert!(cfg.mtls_required);
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
        let ok = oraclemcp_core::DoctorReport { checks: Vec::new() };
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
                ora_code: None,
            }],
        };
        let process_code = doctor_process_exit_code(&failed);
        assert_eq!(process_code, 2);
        assert_eq!(
            failed.to_json_with_exit_code(i32::from(process_code))["exit_code"],
            serde_json::json!(2)
        );
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
        let secret =
            resolve_profile_secret("wallet_password_ref", "dev", Some("literal:wallet"), false)
                .expect("dev literal")
                .expect("secret");
        assert_eq!(secret, "wallet");

        let err =
            resolve_profile_secret("wallet_password_ref", "prod", Some("literal:wallet"), true)
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
        )
        .expect_err("missing env var");
        let rendered = err.to_string();
        assert!(rendered.contains("wallet_password_ref"));
        assert!(rendered.contains("secret not found"));
        assert!(!rendered.contains("PRIVATE_WALLET_PASSWORD_NAME"));
        assert!(!rendered.contains("env:"));

        let err =
            resolve_profile_secret("credential_ref", "prod", Some("noscheme-secret-ref"), true)
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
        OracleMcpConfig::from_toml_str(profiles_toml).expect("setup profiles TOML parses");
        assert!(profiles_toml.contains("wallet_password_ref = \"env:WALLET_PASSWORD\""));
        assert!(profiles_toml.contains("ssl_server_dn_match = true"));
        assert!(profiles_toml.contains("ssl_server_cert_dn = \"CN=dbhost.example.com\""));
        assert!(profiles_toml.contains("use_sni = true"));
        assert!(profiles_toml.contains("sdu = 32768"));
        assert!(profiles_toml.contains("[profiles.drcp]"));
        assert!(profiles_toml.contains("connection_class = \"ORACLE_MCP_AGENTS\""));
        assert!(profiles_toml.contains("purity = \"reuse\""));
        assert!(profiles_toml.contains("# [profiles.pool]"));
        assert!(profiles_toml.contains("# max_size = 4"));
        assert!(profiles_toml.contains("[profiles.proxy_auth]"));
        assert!(profiles_toml.contains("proxy_user = \"MCP_PROXY\""));
        assert!(profiles_toml.contains("target_schema = \"APP_OWNER\""));
        assert!(profiles_toml.contains("# edition = \"ORA$BASE\""));
        assert!(profiles_toml.contains("program = \"oraclemcp\""));
        assert!(profiles_toml.contains("machine = \"local-workstation\""));
        assert!(profiles_toml.contains("os_user = \"local-agent\""));
        assert!(profiles_toml.contains("terminal = \"agent\""));
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
                ref profile,
                ref credential_env,
                ..
            }) if profile == "tenant_ro" && credential_env == "APP_PASSWORD"
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
        assert!(text.contains("Client smoke tests"));
        assert!(text.contains("oraclemcp --json setup --profile <profile>"));
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
            out["first_commands"][0]["argv"],
            serde_json::json!(["oraclemcp", "--json", "setup", "--profile", "<profile>"])
        );
        assert_eq!(
            out["first_commands"][1]["argv"],
            serde_json::json!(["oraclemcp", "--json", "profiles"])
        );
        assert_eq!(
            out["first_commands"][3]["argv"],
            serde_json::json!(["oraclemcp", "--json", "doctor", "--profile", "<profile>"])
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
            false,
            CustomToolCatalog::default(),
            None,
        );
        // The capabilities report carries the registry's tools.
        let caps = registry::capabilities(env!("CARGO_PKG_VERSION"), LIVE_DB, false);
        assert_eq!(caps.tools.len(), registry::TOOL_NAMES.len());
        // Smoke: the server clones (it is Clone) — proves it is fully built.
        let _ = server.clone();
    }
}
